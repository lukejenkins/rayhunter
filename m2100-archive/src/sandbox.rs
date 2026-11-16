//! The decoder sandbox: runs the WebAssembly guest (m2100-decoder) on one hostile
//! capture inside an embedded wasmtime, with no capabilities and hard limits, so a
//! malicious capture can at worst produce wrong counts or a reported failure.
//!
//! What the guest gets, and nothing else:
//! - stdin: the capture file, streamed (never read whole into memory);
//! - stdout: a pipe read through `events::read_events`, capped at 64 MiB in total;
//! - stderr: discarded;
//! - argv = ["m2100-decoder"], an empty environment, no preopened directories
//!   (so no file can be named), no sockets, no name lookup;
//! - clocks that always read 0 and a random source that always yields zeros;
//! - `poll_oneoff` that never blocks (the stock one sleeps in the host, where the
//!   epoch deadline cannot reach it);
//! - 512 MiB of linear memory, 120 s of wall-clock time (epoch interruption).
//!
//! The guest binary must hash to the sha256 this add-on was built with
//! (build.rs, Ruling 1); anything else is refused before it is compiled.

#![allow(dead_code)] // wired into the cycle by Task 6

use crate::events::{Tally, read_events};
use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::thread::JoinHandle;
use std::time::Duration;
use wasmtime::{
    Caller, Config, Engine, Linker, Module, ResourceLimiter, Store, StoreLimits,
    StoreLimitsBuilder, Trap,
};
use wasmtime_wasi::cli::{InputFile, IsTerminal, StdoutStream};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::{OutputStream, Pollable, StreamError, StreamResult};
use wasmtime_wasi::{HostMonotonicClock, HostWallClock, I32Exit, WasiCtxBuilder};

/// sha256 of the guest baked in at build time; "" when the build had none
/// (decoding disabled).
pub const GUEST_SHA256: &str = env!("M2100_GUEST_SHA256");
/// Where the add-on image carries the guest (addon/Dockerfile).
pub const GUEST_PATH: &str = "/usr/local/share/m2100-archive/m2100-decoder.wasm";
pub const WASMTIME_VERSION: &str = env!("M2100_WASMTIME_VERSION");

pub const MEMORY_LIMIT: usize = 512 << 20;
pub const OUTPUT_LIMIT: u64 = 64 << 20;
pub const TIMEOUT: Duration = Duration::from_secs(120);
/// Epoch ticks per deadline: the deadline is met to within timeout / TICKS.
const TICKS: u32 = 20;
const ARGV0: &str = "m2100-decoder";
/// Stdout chunks in flight between the guest and the reader.
const PIPE_DEPTH: usize = 16;
/// Longest trap message kept.
const MAX_REASON: usize = 512;

/// How a decode ended. The tally returned with it is always the partial one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEnd {
    /// The guest exited 0 and its output was valid and complete.
    Finished,
    /// The guest trapped, ran out of memory, exited non-zero, or the host could
    /// not start it (e.g. the capture could not be opened).
    Trapped(String),
    /// The wall-clock deadline passed.
    Timeout,
    /// The guest wrote more than `OUTPUT_LIMIT` bytes.
    OutputTooLarge,
    /// The guest's output broke the event schema or limits.
    Malformed(String),
    /// The guest hit one of its caps (`what`: frame / decompressed / events), emitted
    /// `capped` and exited cleanly: the counts are a truncated partial, never a fact.
    Capped(String),
}

/// Runs the decoder on one archived capture.
///
/// `run` blocks for up to the deadline (120 s): call it from
/// `tokio::task::spawn_blocking` or a plain thread, never from an async task
/// (wasmtime-wasi's sync shims `block_on` the current tokio handle).
pub trait Decoder: Send + Sync {
    fn run(&self, capture_gz: &Path) -> (Tally, RunEnd);
}

pub struct Sandbox {
    engine: Engine,
    module: Module,
    linker: Linker<Host>,
    deadline_ticks: u64,
    /// The module came from the compiled-module cache (not recompiled).
    from_cache: bool,
    _ticker: Ticker,
}

impl Sandbox {
    /// `expected_sha256` is the hash this build was made with (`GUEST_SHA256`).
    /// Refuses a guest whose hash differs, and refuses everything when it is "".
    /// Compiles once, caching the compiled module in `cache_dir`.
    pub fn new(guest: &[u8], expected_sha256: &str, cache_dir: &Path) -> anyhow::Result<Sandbox> {
        Self::with_timeout(guest, expected_sha256, cache_dir, TIMEOUT)
    }

    fn with_timeout(
        guest: &[u8],
        expected_sha256: &str,
        cache_dir: &Path,
        timeout: Duration,
    ) -> anyhow::Result<Sandbox> {
        if expected_sha256.is_empty() {
            bail!("decoding disabled: this add-on was built without a decoder guest");
        }
        let actual = hex(&Sha256::digest(guest));
        if !actual.eq_ignore_ascii_case(expected_sha256) {
            bail!(
                "decoder guest sha256 {actual} does not match the one this add-on was built \
                 and tested with ({expected_sha256}); refusing to run it"
            );
        }

        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(anyhow::Error::from)?;
        let (module, from_cache) = load_or_compile(&engine, guest, &actual, cache_dir)?;

        let mut linker: Linker<Host> = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |h: &mut Host| &mut h.wasi)?;
        linker.allow_shadowing(true);
        linker.func_wrap("wasi_snapshot_preview1", "poll_oneoff", poll_oneoff_now)?;
        linker.allow_shadowing(false);
        // Test-only import for the host-panic test: a host function that panics.
        #[cfg(test)]
        linker.func_wrap("m2100_test", "panic", || -> () {
            panic!("test host function panicked")
        })?;

        let tick = (timeout / TICKS).max(Duration::from_millis(1));
        let deadline_ticks = timeout.as_nanos().div_ceil(tick.as_nanos()) as u64;
        Ok(Sandbox {
            _ticker: Ticker::start(engine.clone(), tick),
            engine,
            module,
            linker,
            deadline_ticks,
            from_cache,
        })
    }

    /// Run the guest on `capture`, feeding its stdout to `consume` on this thread.
    /// Returns Err only when the host could not start the run.
    fn execute<R>(
        &self,
        capture: &Path,
        consume: impl FnOnce(&mut dyn BufRead) -> R,
    ) -> Result<(R, GuestRun), String> {
        let file = std::fs::File::open(capture)
            .map_err(|e| format!("host: cannot open capture {}: {e}", capture.display()))?;
        let (tx, rx) = sync_channel(PIPE_DEPTH);
        let pipe = CappedPipe(Arc::new(PipeState {
            tx: Mutex::new(Some(tx)),
            total: AtomicU64::new(0),
            over: AtomicBool::new(false),
            hung_up: AtomicBool::new(false),
        }));

        let wasi = WasiCtxBuilder::new()
            .args(&[ARGV0])
            .stdin(InputFile::new(file))
            .stdout(pipe.clone())
            // stderr: the builder's default sink
            .wall_clock(FixedClock)
            .monotonic_clock(FixedClock)
            .secure_random(ZeroRng)
            .insecure_random(ZeroRng)
            .insecure_random_seed(0)
            .max_random_size(4096)
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .build_p1();
        let limits = StoreLimitsBuilder::new()
            .memory_size(MEMORY_LIMIT)
            .memories(1)
            .tables(4)
            .table_elements(1 << 20)
            .instances(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            &self.engine,
            Host {
                wasi,
                limits: PeakLimiter {
                    inner: limits,
                    peak: 0,
                    denied: 0,
                },
                polls: 0,
            },
        );
        store.limiter(|h| &mut h.limits);
        store.set_epoch_deadline(self.deadline_ticks);

        let state = pipe.0.clone();
        let guest_state = pipe.0.clone();
        drop(pipe);
        let (linker, module) = (&self.linker, &self.module);
        std::thread::scope(|s| {
            let guest = s.spawn(move || {
                // EOF for the reader however this thread ends, panics included
                // (wasmtime re-raises a host function's panic after leaving wasm):
                // otherwise the reader waits forever and the join is never reached.
                let _close = CloseOnDrop(guest_state);
                let end = run_guest(linker, module, &mut store);
                let h = store.data();
                (end, (h.limits.peak, h.limits.denied, h.polls))
            });
            let mut reader = BufReader::new(ChanReader {
                rx,
                chunk: Vec::new(),
                pos: 0,
            });
            let out = consume(&mut reader);
            // hang up: any further guest write fails
            drop(reader);
            let (end, (peak_memory, denied_memory, polls)) = match guest.join() {
                Ok(r) => r,
                Err(payload) => {
                    let what = payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_default();
                    let mut why = format!("host: guest thread panicked: {what}");
                    truncate(&mut why, MAX_REASON);
                    (GuestEnd::Failed(why), (0, 0, 0))
                }
            };
            Ok((
                out,
                GuestRun {
                    end,
                    peak_memory,
                    denied_memory,
                    polls,
                    over: state.over.load(Ordering::SeqCst),
                    hung_up: state.hung_up.load(Ordering::SeqCst),
                },
            ))
        })
    }
}

impl Decoder for Sandbox {
    fn run(&self, capture_gz: &Path) -> (Tally, RunEnd) {
        let ((tally, read), g) = match self.execute(capture_gz, |r| read_events(r)) {
            Ok(x) => x,
            Err(why) => return (Tally::default(), RunEnd::Trapped(why)),
        };
        let end = if g.over {
            RunEnd::OutputTooLarge
        } else if let (true, Err(m)) = (g.hung_up, &read) {
            // the reader refused the output and hung up; whatever the guest did
            // after that is a consequence
            RunEnd::Malformed(m.to_string())
        } else {
            match g.end {
                GuestEnd::Interrupted => RunEnd::Timeout,
                GuestEnd::Exited(0) => match read {
                    Ok(()) => match &tally.capped {
                        Some(what) => RunEnd::Capped(what.clone()),
                        None => RunEnd::Finished,
                    },
                    Err(m) => RunEnd::Malformed(m.to_string()),
                },
                GuestEnd::Exited(code) => {
                    RunEnd::Trapped(format!("guest exited with status {code}"))
                }
                GuestEnd::Failed(why) => RunEnd::Trapped(why),
            }
        };
        (tally, end)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GuestEnd {
    Exited(i32),
    /// The epoch deadline passed.
    Interrupted,
    Failed(String),
}

struct GuestRun {
    end: GuestEnd,
    /// Largest linear memory granted, bytes.
    peak_memory: usize,
    /// Largest linear memory refused, bytes (0 if none).
    denied_memory: usize,
    polls: u64,
    over: bool,
    hung_up: bool,
}

fn run_guest(linker: &Linker<Host>, module: &Module, store: &mut Store<Host>) -> GuestEnd {
    let result = linker
        .instantiate(&mut *store, module)
        .and_then(|instance| {
            instance
                .get_typed_func::<(), ()>(&mut *store, "_start")?
                .call(&mut *store, ())
        });
    match result {
        Ok(()) => GuestEnd::Exited(0),
        Err(e) => {
            if let Some(exit) = e.downcast_ref::<I32Exit>() {
                GuestEnd::Exited(exit.0)
            } else if e.downcast_ref::<Trap>() == Some(&Trap::Interrupt) {
                GuestEnd::Interrupted
            } else {
                let mut why = format!("{e:#}");
                truncate(&mut why, MAX_REASON);
                GuestEnd::Failed(why)
            }
        }
    }
}

fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        let mut at = max;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
    }
}

// ---------- compiled-module cache ----------

/// Load the compiled module from `cache_dir`, or compile and store it. The file is
/// keyed by wasmtime version, engine-compatibility hash and guest hash; its own
/// sha256 sits next to it and is checked on the bytes in memory before they are
/// deserialized (so a truncated or corrupted file is recompiled, never loaded).
fn load_or_compile(
    engine: &Engine,
    guest: &[u8],
    guest_sha: &str,
    cache_dir: &Path,
) -> anyhow::Result<(Module, bool)> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    engine.precompile_compatibility_hash().hash(&mut h);
    let name = format!(
        "m2100-decoder-wasmtime-{WASMTIME_VERSION}-{:016x}-{guest_sha}.cwasm",
        h.finish()
    );
    let path = cache_dir.join(&name);
    let side = cache_dir.join(format!("{name}.sha256"));
    remove_stale_cache(cache_dir, &name);

    if let (Ok(bytes), Ok(want)) = (std::fs::read(&path), std::fs::read_to_string(&side)) {
        if hex(&Sha256::digest(&bytes)) == want.trim() {
            // SAFETY: the bytes are ones this program serialized itself for this
            // engine configuration (name keyed by version, config and guest hash;
            // content checked against the sidecar hash just now, in memory).
            match unsafe { Module::deserialize(engine, &bytes) } {
                Ok(m) => return Ok((m, true)),
                Err(e) => log::warn!("compiled decoder cache {} unusable: {e}", path.display()),
            }
        } else {
            log::warn!(
                "compiled decoder cache {} fails its hash; recompiling",
                path.display()
            );
        }
    }

    // from_binary: the text format is not a guest
    let module = Module::from_binary(engine, guest)
        .map_err(anyhow::Error::from)
        .context("compiling the decoder guest")?;
    match module.serialize() {
        Ok(bytes) => {
            if let Err(e) = store_cache(cache_dir, &path, &side, &bytes) {
                log::warn!(
                    "cannot cache the compiled decoder in {}: {e:#}",
                    cache_dir.display()
                );
            }
        }
        Err(e) => log::warn!("cannot serialize the compiled decoder: {e}"),
    }
    Ok((module, false))
}

/// Delete compiled-module files (`*.cwasm`, their `.sha256` sidecars and leftover
/// temporaries) that are not the current key `keep`: an upgraded guest or wasmtime
/// would otherwise leave a ~MB-sized file behind forever. Best effort.
fn remove_stale_cache(dir: &Path, keep: &str) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let keep_side = format!("{keep}.sha256");
    for e in rd.flatten() {
        let n = e.file_name();
        let Some(n) = n.to_str() else { continue };
        if n.contains(".cwasm") && n != keep && n != keep_side {
            match std::fs::remove_file(e.path()) {
                Ok(()) => log::info!("removed stale compiled decoder {n}"),
                Err(err) => log::warn!("cannot remove stale compiled decoder {n}: {err}"),
            }
        }
    }
}

fn store_cache(dir: &Path, path: &Path, side: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_atomically(path, bytes)?;
    write_atomically(side, hex(&Sha256::digest(bytes)).as_bytes())?;
    Ok(())
}

/// Write to a unique temporary name beside `path`, then rename over it.
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let r = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------- the epoch ticker ----------

struct Ticker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Ticker {
    fn start(engine: Engine, tick: Duration) -> Ticker {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::Builder::new()
            .name("sandbox-epoch".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    std::thread::sleep(tick);
                    engine.increment_epoch();
                }
            })
            .expect("spawn the epoch ticker");
        Ticker {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------- store state: WASI context and limits ----------

struct Host {
    wasi: WasiP1Ctx,
    limits: PeakLimiter,
    polls: u64,
}

/// `StoreLimits`, recording the largest memory granted and refused.
struct PeakLimiter {
    inner: StoreLimits,
    peak: usize,
    denied: usize,
}

impl ResourceLimiter for PeakLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let r = self.inner.memory_growing(current, desired, maximum);
        match r {
            Ok(true) => self.peak = self.peak.max(desired),
            _ => self.denied = self.denied.max(desired),
        }
        r
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.inner.table_growing(current, desired, maximum)
    }
    fn instances(&self) -> usize {
        self.inner.instances()
    }
    fn tables(&self) -> usize {
        self.inner.tables()
    }
    fn memories(&self) -> usize {
        self.inner.memories()
    }
}

/// Wall and monotonic clocks that always read 0.
struct FixedClock;

impl HostWallClock for FixedClock {
    fn resolution(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn now(&self) -> Duration {
        Duration::ZERO
    }
}

impl HostMonotonicClock for FixedClock {
    fn resolution(&self) -> u64 {
        1_000_000_000
    }
    fn now(&self) -> u64 {
        0
    }
}

/// A "random" source of zeros. The guest uses ordered containers, not hashed
/// ones, so nothing it does depends on randomness.
struct ZeroRng;

impl rand_core::TryRng for ZeroRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(0);
        Ok(())
    }
}

// ---------- poll_oneoff that never blocks ----------

const ERRNO_SUCCESS: i32 = 0;
const ERRNO_FAULT: i32 = 21;
const ERRNO_INVAL: i32 = 28;
const SUBSCRIPTION_SIZE: usize = 48;
const EVENT_SIZE: usize = 32;

/// Replaces WASI `poll_oneoff`, which sleeps in the host for clock subscriptions
/// (out of reach of the epoch deadline). Every subscription is reported ready at
/// once: clocks read a constant 0, so every timeout has already passed, and
/// stdin/stdout are a file and a pipe that never wait on the outside world.
fn poll_oneoff_now(
    mut caller: Caller<'_, Host>,
    subs: i32,
    events: i32,
    nsubs: i32,
    nevents: i32,
) -> i32 {
    caller.data_mut().polls += 1;
    let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
        return ERRNO_INVAL;
    };
    let mem = memory.data_mut(&mut caller);
    let n = nsubs as u32 as usize;
    if n == 0 {
        return ERRNO_INVAL;
    }
    let range = |ptr: i32, size: usize| {
        let start = ptr as u32 as usize;
        let end = start.checked_add(n.checked_mul(size)?)?;
        (end <= mem.len()).then_some(start)
    };
    let (Some(subs), Some(events)) = (range(subs, SUBSCRIPTION_SIZE), range(events, EVENT_SIZE))
    else {
        return ERRNO_FAULT;
    };
    let nevents = nevents as u32 as usize;
    if nevents.checked_add(4).is_none_or(|end| end > mem.len()) {
        return ERRNO_FAULT;
    }
    for i in 0..n {
        let s = subs + i * SUBSCRIPTION_SIZE;
        let mut ev = [0u8; EVENT_SIZE];
        ev[0..8].copy_from_slice(&mem[s..s + 8]); // userdata
        let tag = mem[s + 8]; // 0 clock, 1 fd_read, 2 fd_write
        if tag > 2 {
            return ERRNO_INVAL;
        }
        // error = 0 (bytes 8..10), type = tag; fd events: nbytes 0, flags 0
        ev[10] = tag;
        let e = events + i * EVENT_SIZE;
        mem[e..e + EVENT_SIZE].copy_from_slice(&ev);
    }
    mem[nevents..nevents + 4].copy_from_slice(&(n as u32).to_le_bytes());
    ERRNO_SUCCESS
}

// ---------- stdout: a capped pipe to the reader ----------

struct PipeState {
    tx: Mutex<Option<SyncSender<Vec<u8>>>>,
    total: AtomicU64,
    over: AtomicBool,
    hung_up: AtomicBool,
}

impl PipeState {
    fn push(&self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let n = buf.len() as u64;
        if self.total.fetch_add(n, Ordering::SeqCst).saturating_add(n) > OUTPUT_LIMIT {
            self.over.store(true, Ordering::SeqCst);
            return Err(io::Error::other("decoder output limit reached"));
        }
        let tx = self.tx.lock().unwrap().clone();
        let Some(tx) = tx else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        tx.send(buf.to_vec()).map_err(|_| {
            self.hung_up.store(true, Ordering::SeqCst);
            io::Error::from(io::ErrorKind::BrokenPipe)
        })
    }

    fn close(&self) {
        // never panics: it runs during unwinding
        self.tx.lock().unwrap_or_else(|p| p.into_inner()).take();
    }
}

/// Closes the pipe when dropped, so the reader sees EOF even on unwind.
struct CloseOnDrop(Arc<PipeState>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[derive(Clone)]
struct CappedPipe(Arc<PipeState>);

impl IsTerminal for CappedPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CappedPipe {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for CappedPipe {
    async fn ready(&mut self) {}
}

impl OutputStream for CappedPipe {
    fn write(&mut self, bytes: bytes::Bytes) -> StreamResult<()> {
        self.0
            .push(&bytes)
            .map_err(|e| StreamError::LastOperationFailed(wasmtime::format_err!(e)))
    }
    fn flush(&mut self) -> StreamResult<()> {
        Ok(())
    }
    fn check_write(&mut self) -> StreamResult<usize> {
        Ok(64 << 10)
    }
}

impl tokio::io::AsyncWrite for CappedPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.0.push(buf).map(|()| buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The reader's end: EOF once every sender is gone.
struct ChanReader {
    rx: Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    pos: usize,
}

impl Read for ChanReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.chunk.len() {
            match self.rx.recv() {
                Ok(c) => {
                    self.chunk = c;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.chunk.len() - self.pos);
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::Instant;
    use tempfile::TempDir;

    const SUMMARY0: &str =
        r#"{"t":"summary","frames":0,"failures":0,"towers":0,"identity_requests":0}"#;

    /// Escape bytes for a WAT data string.
    fn wat_str(b: &[u8]) -> String {
        b.iter().map(|x| format!("\\{x:02x}")).collect()
    }

    /// A WASI preview1 module with the imports the probes use.
    fn module(data: &str, body: &str) -> String {
        format!(
            r#"(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_get" (func $fd_prestat_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "environ_sizes_get" (func $environ_sizes_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $args_sizes_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_get" (func $args_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get" (func $clock_time_get (param i32 i64 i32) (result i32)))
  (import "wasi_snapshot_preview1" "random_get" (func $random_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "sock_accept" (func $sock_accept (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll_oneoff (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  {data}
  ;; write the `len` bytes at `ptr` to stdout; returns the errno
  (func $out (param $ptr i32) (param $len i32) (result i32)
    (i32.store (i32.const 60000) (local.get $ptr))
    (i32.store (i32.const 60004) (local.get $len))
    (call $fd_write (i32.const 1) (i32.const 60000) (i32.const 1) (i32.const 60008)))
  (func (export "_start") {body}))"#
        )
    }

    fn sha_hex(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    fn wat_sandbox(wat: &str, timeout: Duration) -> (Sandbox, TempDir) {
        let bin = wat::parse_str(wat).unwrap();
        let cache = TempDir::new().unwrap();
        let sb = Sandbox::with_timeout(&bin, &sha_hex(&bin), cache.path(), timeout).unwrap();
        (sb, cache)
    }

    fn some_capture() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not really a capture").unwrap();
        f
    }

    fn summary_body() -> (String, String) {
        let data = format!(
            r#"(data (i32.const 0) "{}")"#,
            wat_str(format!("{SUMMARY0}\n").as_bytes())
        );
        let body = format!(
            "(drop (call $out (i32.const 0) (i32.const {})))",
            SUMMARY0.len() + 1
        );
        (data, body)
    }

    fn real_guest() -> Option<Vec<u8>> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../m2100-decoder/target/wasm32-wasip1/release/m2100-decoder.wasm");
        match std::fs::read(&p) {
            Ok(b) => Some(b),
            Err(_) => {
                eprintln!(
                    "SKIP: no guest at {} (cd m2100-decoder && cargo +1.98.0 build --release --target wasm32-wasip1)",
                    p.display()
                );
                None
            }
        }
    }

    /// One compiled-module cache for every real-guest test (compiling it takes seconds).
    fn real_cache() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-cwasm-cache")
    }

    fn real_sandbox(guest: &[u8]) -> Sandbox {
        Sandbox::new(guest, &sha_hex(guest), &real_cache()).unwrap()
    }

    fn fixtures() -> Option<PathBuf> {
        let dir = std::env::var_os("RH_FIXTURES")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join("Projects/rayhunter-m2100/captures"))
            })?;
        if dir.is_dir() {
            Some(dir)
        } else {
            eprintln!("SKIP: no fixtures at {} (set RH_FIXTURES)", dir.display());
            None
        }
    }

    // ---------- identity of the guest (Review Focus 2) ----------

    #[test]
    fn a_guest_with_a_different_hash_is_refused() {
        let (data, body) = summary_body();
        let tested = wat::parse_str(module(&data, &body)).unwrap();
        let stale = wat::parse_str(module(&data, &format!("{body} (nop)"))).unwrap();
        assert_ne!(sha_hex(&tested), sha_hex(&stale));
        let cache = TempDir::new().unwrap();
        let err = Sandbox::new(&stale, &sha_hex(&tested), cache.path())
            .err()
            .expect("a stale guest must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("does not match"), "{msg}");
        assert!(
            msg.contains(&sha_hex(&stale)) && msg.contains(&sha_hex(&tested)),
            "{msg}"
        );
        // refused before anything was compiled or cached
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
        // the right guest is accepted
        assert!(Sandbox::new(&tested, &sha_hex(&tested), cache.path()).is_ok());
    }

    #[test]
    fn a_build_without_a_guest_disables_decoding() {
        let (data, body) = summary_body();
        let bin = wat::parse_str(module(&data, &body)).unwrap();
        let cache = TempDir::new().unwrap();
        let err = Sandbox::new(&bin, "", cache.path())
            .err()
            .expect("must refuse");
        assert!(format!("{err:#}").contains("disabled"), "{err:#}");
    }

    #[test]
    fn wat_text_is_not_accepted_as_a_guest() {
        let (data, body) = summary_body();
        let text = module(&data, &body);
        let cache = TempDir::new().unwrap();
        assert!(Sandbox::new(text.as_bytes(), &sha_hex(text.as_bytes()), cache.path()).is_err());
    }

    // ---------- compiled-module cache ----------

    #[test]
    fn compiled_module_is_cached_and_a_corrupt_cache_is_recompiled() {
        let (data, body) = summary_body();
        let bin = wat::parse_str(module(&data, &body)).unwrap();
        let sha = sha_hex(&bin);
        let cache = TempDir::new().unwrap();
        let first = Sandbox::new(&bin, &sha, cache.path()).unwrap();
        assert!(!first.from_cache);
        let cwasm: Vec<PathBuf> = std::fs::read_dir(cache.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "cwasm"))
            .collect();
        assert_eq!(cwasm.len(), 1);
        let name = cwasm[0].file_name().unwrap().to_str().unwrap().to_string();
        assert!(
            name.contains(WASMTIME_VERSION) && name.contains(&sha),
            "{name}"
        );

        let second = Sandbox::new(&bin, &sha, cache.path()).unwrap();
        assert!(second.from_cache);

        // garbage in place of the compiled module: never deserialized, recompiled
        std::fs::write(&cwasm[0], b"garbage").unwrap();
        let third = Sandbox::new(&bin, &sha, cache.path()).unwrap();
        assert!(!third.from_cache);
        let fourth = Sandbox::new(&bin, &sha, cache.path()).unwrap();
        assert!(fourth.from_cache);
        let capture = some_capture();
        assert_eq!(fourth.run(capture.path()).1, RunEnd::Finished);
    }

    // ---------- limits ----------

    #[test]
    fn a_guest_that_spins_forever_times_out() {
        let (sb, _c) = wat_sandbox(&module("", "(loop $l (br $l))"), Duration::from_secs(1));
        let capture = some_capture();
        let start = Instant::now();
        let (_, end) = sb.run(capture.path());
        let took = start.elapsed();
        assert_eq!(end, RunEnd::Timeout);
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_secs(3),
            "{took:?}"
        );
    }

    #[test]
    fn a_sleep_in_poll_oneoff_does_not_block_the_host() {
        // a relative 1 h sleep on the monotonic clock, then a summary
        let (data, out) = summary_body();
        let body = format!(
            "(i64.store (i32.const 2048) (i64.const 7))
             (i32.store8 (i32.const 2056) (i32.const 0))
             (i32.store (i32.const 2064) (i32.const 1))
             (i64.store (i32.const 2072) (i64.const 3600000000000))
             (i64.store (i32.const 2080) (i64.const 0))
             (i32.store16 (i32.const 2088) (i32.const 0))
             (if (i32.ne (call $poll_oneoff (i32.const 2048) (i32.const 2200) (i32.const 1) (i32.const 2300)) (i32.const 0))
               (then unreachable))
             (if (i32.ne (i32.load (i32.const 2300)) (i32.const 1)) (then unreachable))
             (if (i64.ne (i64.load (i32.const 2200)) (i64.const 7)) (then unreachable))
             {out}"
        );
        let (sb, _c) = wat_sandbox(&module(&data, &body), Duration::from_secs(30));
        let capture = some_capture();
        let (tx, rx) = std::sync::mpsc::channel();
        let start = Instant::now();
        std::thread::spawn(move || {
            let r = sb.run(capture.path());
            let _ = tx.send(r);
        });
        // a blocking sleep cannot be cut short by the epoch deadline, so a
        // regression would hang here: bound it
        let (_, end) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("poll_oneoff blocked the host");
        assert_eq!(end, RunEnd::Finished);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn stale_compiled_modules_are_removed_at_startup_and_the_current_one_kept() {
        let bin = wat::parse_str(module("", "")).unwrap();
        let sha = sha_hex(&bin);
        let cache = TempDir::new().unwrap();
        Sandbox::new(&bin, &sha, cache.path()).unwrap();
        let keep: Vec<String> = std::fs::read_dir(cache.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(keep.len(), 2, "{keep:?}");
        for stale in [
            "m2100-decoder-wasmtime-0.0.1-00ff-abc.cwasm",
            "m2100-decoder-wasmtime-0.0.1-00ff-abc.cwasm.sha256",
            "m2100-decoder-wasmtime-0.0.1-00ff-abc.cwasm.tmp-1-0",
        ] {
            std::fs::write(cache.path().join(stale), b"old").unwrap();
        }
        std::fs::write(cache.path().join("unrelated.txt"), b"x").unwrap();
        let again = Sandbox::new(&bin, &sha, cache.path()).unwrap();
        assert!(
            again.from_cache,
            "the current module must survive the cleanup"
        );
        let mut left: Vec<String> = std::fs::read_dir(cache.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        let mut want = keep;
        want.push("unrelated.txt".into());
        want.sort();
        assert_eq!(left, want);
    }

    #[test]
    fn a_guest_that_emits_capped_then_exits_zero_ends_as_capped() {
        let line = r#"{"t":"capped","what":"decompressed","at_frame":42}"#;
        let data = format!(
            r#"(data (i32.const 0) "{}")"#,
            wat_str(format!("{line}\n").as_bytes())
        );
        let body = format!(
            "(drop (call $out (i32.const 0) (i32.const {})))",
            line.len() + 1
        );
        let (sb, _c) = wat_sandbox(&module(&data, &body), Duration::from_secs(10));
        let (tally, end) = sb.run(some_capture().path());
        assert_eq!(end, RunEnd::Capped("decompressed".into()));
        assert_eq!(
            (tally.frames, tally.capped.as_deref()),
            (42, Some("decompressed"))
        );
    }

    #[test]
    fn memory_above_the_limit_traps() {
        // grow to 600 MiB (9600 pages of 64 KiB)
        let (sb, _c) = wat_sandbox(
            &module("", "(drop (memory.grow (i32.const 9599)))"),
            Duration::from_secs(10),
        );
        let capture = some_capture();
        let ((), g) = sb.execute(capture.path(), |_| ()).unwrap();
        assert!(matches!(g.end, GuestEnd::Failed(_)), "{:?}", g.end);
        assert!(g.peak_memory <= MEMORY_LIMIT, "peak {}", g.peak_memory);
        assert!(g.denied_memory > MEMORY_LIMIT, "denied {}", g.denied_memory);
        assert!(matches!(sb.run(capture.path()).1, RunEnd::Trapped(_)));

        // a module that declares too much memory up front does not even instantiate
        let big = "(module (memory (export \"memory\") 9000) (func (export \"_start\")))";
        let (sb, _c) = wat_sandbox(big, Duration::from_secs(10));
        assert!(matches!(sb.run(capture.path()).1, RunEnd::Trapped(_)));

        // within the limit is fine
        let (data, out) = summary_body();
        let ok = format!("(drop (memory.grow (i32.const 4000))) {out}");
        let (sb, _c) = wat_sandbox(&module(&data, &ok), Duration::from_secs(10));
        assert_eq!(sb.run(capture.path()).1, RunEnd::Finished);
    }

    #[test]
    fn output_above_64_mib_is_too_large() {
        // 70,000 valid 1,000-byte lines (whitespace-padded JSON), so only the byte
        // cap can stop it: the strict reader accepts every line
        let mut line = r#"{"t":"parse_failures","hour":null,"count":0,"frames":0"#.to_string();
        line.push_str(&" ".repeat(1000 - line.len() - 2));
        line.push_str("}\n");
        assert_eq!(line.len(), 1000);
        let data = format!(r#"(data (i32.const 0) "{}")"#, wat_str(line.as_bytes()));
        let body = "(local $i i32)
            (loop $l
              (br_if 1 (i32.ne (call $out (i32.const 0) (i32.const 1000)) (i32.const 0)))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br_if $l (i32.lt_u (local.get $i) (i32.const 70000))))";
        let (sb, _c) = wat_sandbox(&module(&data, body), Duration::from_secs(30));
        let capture = some_capture();
        let (tally, end) = sb.run(capture.path());
        assert_eq!(end, RunEnd::OutputTooLarge);
        assert_eq!(tally.frames, 0);
    }

    #[test]
    fn junk_output_is_malformed_and_stops_the_guest() {
        // junk forever, stopping only when a write fails
        let data = format!(r#"(data (i32.const 0) "{}")"#, wat_str(b"junk\n"));
        let body = "(loop $l (br_if $l (i32.eqz (call $out (i32.const 0) (i32.const 5)))))";
        let (sb, _c) = wat_sandbox(&module(&data, body), Duration::from_secs(30));
        let capture = some_capture();
        let start = Instant::now();
        let (_, end) = sb.run(capture.path());
        assert!(matches!(end, RunEnd::Malformed(_)), "{end:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_trap_is_reported_with_the_partial_tally() {
        let tower = r#"{"t":"tower","ts":null,"plmn":null,"tac":null,"cell":null,"pci":3,"earfcn":5230,"strength":"pci"}"#;
        let data = format!(
            r#"(data (i32.const 0) "{}")"#,
            wat_str(format!("{tower}\n").as_bytes())
        );
        let body = format!(
            "(drop (call $out (i32.const 0) (i32.const {}))) unreachable",
            tower.len() + 1
        );
        let (sb, _c) = wat_sandbox(&module(&data, &body), Duration::from_secs(10));
        let capture = some_capture();
        let (tally, end) = sb.run(capture.path());
        assert!(matches!(end, RunEnd::Trapped(_)), "{end:?}");
        assert_eq!(tally.towers, 1);
    }

    // ---------- capabilities ----------

    #[test]
    fn the_guest_has_no_files_env_network_clock_or_randomness() {
        // results land at 1024..1280 and are written raw to stdout
        let data = r#"
  (data (i32.const 0) "/etc/passwd")
  (data (i32.const 16) "etc/passwd")
  (data (i32.const 1064) "\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff\ff")
  (data (i32.const 1088) "\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa")"#;
        let body = "
    (i32.store (i32.const 1024) (call $path_open (i32.const 3) (i32.const 0) (i32.const 16) (i32.const 10) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 1500)))
    (i32.store (i32.const 1028) (call $fd_prestat_get (i32.const 3) (i32.const 1500)))
    (i32.store (i32.const 1032) (call $environ_sizes_get (i32.const 1036) (i32.const 1040)))
    (i32.store (i32.const 1044) (call $args_sizes_get (i32.const 1048) (i32.const 1052)))
    (i32.store (i32.const 1056) (call $clock_time_get (i32.const 0) (i64.const 1) (i32.const 1064)))
    (i32.store (i32.const 1060) (call $clock_time_get (i32.const 1) (i64.const 1) (i32.const 1072)))
    (i32.store (i32.const 1080) (call $random_get (i32.const 1088) (i32.const 32)))
    (i32.store (i32.const 1120) (call $path_open (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 11) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 1500)))
    (i32.store (i32.const 1124) (call $sock_accept (i32.const 3) (i32.const 0) (i32.const 1500)))
    (i32.store (i32.const 1128) (call $args_get (i32.const 1136) (i32.const 1152)))
    (i32.store (i32.const 1132) (call $path_open (i32.const 4) (i32.const 0) (i32.const 0) (i32.const 11) (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 1500)))
    (drop (call $out (i32.const 1024) (i32.const 256)))";
        let (sb, _c) = wat_sandbox(&module(data, body), Duration::from_secs(10));
        let capture = some_capture();
        let (out, g) = sb
            .execute(capture.path(), |r| {
                let mut v = Vec::new();
                r.read_to_end(&mut v).unwrap();
                v
            })
            .unwrap();
        assert_eq!(g.end, GuestEnd::Exited(0));
        assert_eq!(out.len(), 256);
        let u32_at = |o: usize| u32::from_le_bytes(out[o - 1024..o - 1020].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(out[o - 1024..o - 1016].try_into().unwrap());
        const EBADF: u32 = 8;
        assert_eq!(u32_at(1024), EBADF, "path_open on fd 3 (no preopens)");
        assert_eq!(u32_at(1028), EBADF, "fd_prestat_get(3): no preopened dir");
        assert_eq!(u32_at(1132), EBADF, "path_open on fd 4");
        assert_ne!(u32_at(1120), 0, "path_open relative to stdin");
        assert_eq!(
            (u32_at(1032), u32_at(1036), u32_at(1040)),
            (0, 0, 0),
            "empty env"
        );
        assert_eq!(
            (u32_at(1044), u32_at(1048), u32_at(1052)),
            (0, 1, 14),
            "argv = [argv0]"
        );
        assert_eq!(u32_at(1128), 0);
        assert_eq!(&out[1152 - 1024..1166 - 1024], b"m2100-decoder\0");
        assert_eq!(
            (u32_at(1056), u64_at(1064)),
            (0, 0),
            "wall clock is constant 0"
        );
        assert_eq!(
            (u32_at(1060), u64_at(1072)),
            (0, 0),
            "monotonic clock is constant 0"
        );
        assert_eq!(u32_at(1080), 0);
        assert_eq!(
            &out[1088 - 1024..1120 - 1024],
            &[0u8; 32],
            "random is zero-filled"
        );
        assert_ne!(
            u32_at(1124),
            0,
            "sock_accept on a socket that does not exist"
        );
    }

    // ---------- the real guest ----------

    #[test]
    fn real_small_capture_matches_the_native_guest() {
        let Some(guest) = real_guest() else { return };
        let Some(dir) = fixtures() else { return };
        let capture = dir.join("unit1-2026-10-09-prune-test/403323-403323.qmdl.gz");
        if !capture.is_file() {
            eprintln!("SKIP: {} absent", capture.display());
            return;
        }
        let native = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../m2100-decoder/target/release/m2100-decoder");
        if !native.is_file() {
            eprintln!(
                "SKIP: no native guest at {} (cargo build --release)",
                native.display()
            );
            return;
        }
        let out = std::process::Command::new(&native)
            .stdin(std::fs::File::open(&capture).unwrap())
            .output()
            .unwrap();
        assert!(out.status.success());
        let (want, ok) = read_events(&out.stdout[..]);
        ok.unwrap();

        let sb = real_sandbox(&guest);
        let (tally, g) = sb
            .execute(&capture, |r| read_events(r))
            .map(|((t, r), g)| {
                r.unwrap();
                (t, g)
            })
            .unwrap();
        eprintln!(
            "403323 in the sandbox: {tally:?}; peak memory {} KiB; poll_oneoff calls {}",
            g.peak_memory >> 10,
            g.polls
        );
        assert_eq!(g.end, GuestEnd::Exited(0));
        assert_eq!(tally, want);
        assert!(tally.towers >= 1 && tally.frames > 0);
        assert_eq!(sb.run(&capture), (want, RunEnd::Finished));
    }

    #[test]
    fn real_guest_gzip_bomb_is_capped_fast_within_memory() {
        let Some(guest) = real_guest() else { return };
        // 2 GiB of zeros, no frame terminator
        let bomb = tempfile::NamedTempFile::new().unwrap();
        {
            let mut gz = flate2::write::GzEncoder::new(
                std::io::BufWriter::new(bomb.reopen().unwrap()),
                flate2::Compression::fast(),
            );
            let zeros = vec![0u8; 1 << 20];
            for _ in 0..2048 {
                gz.write_all(&zeros).unwrap();
            }
            gz.finish().unwrap().flush().unwrap();
        }
        let sb = real_sandbox(&guest);
        let start = Instant::now();
        let ((tally, res), g) = sb.execute(bomb.path(), |r| read_events(r)).unwrap();
        let took = start.elapsed();
        eprintln!(
            "bomb: {:?} {res:?} {tally:?} in {took:?}, peak {} MiB",
            g.end,
            g.peak_memory >> 20
        );
        // The guest skips the endless frame and inflates up to its 1 GiB
        // decompressed cap: ~5 s here in wasm (the decoder's own native bomb test
        // allows 10 s), ~2x that on the Yellow; well inside the 120 s deadline.
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert!(g.peak_memory <= MEMORY_LIMIT);
        let end = sb.run(bomb.path()).1;
        assert!(
            matches!(end, RunEnd::Capped(_)) && tally.capped.is_some(),
            "{end:?} {tally:?}"
        );
    }

    #[test]
    fn real_guest_on_noise_reports_a_summary() {
        let Some(guest) = real_guest() else { return };
        let sb = real_sandbox(&guest);
        let capture = some_capture();
        let (tally, end) = sb.run(capture.path());
        assert_eq!(end, RunEnd::Finished);
        assert_eq!(tally.towers, 0);
    }

    #[test]
    fn a_panic_on_the_guest_thread_ends_the_run() {
        // a host function panicking mid-run (wasmtime re-raises it after leaving
        // wasm): the pipe must still close, so the reader and run return
        let tower = r#"{"t":"tower","ts":null,"plmn":null,"tac":null,"cell":null,"pci":3,"earfcn":5230,"strength":"pci"}"#;
        let data = format!(
            r#"(data (i32.const 0) "{}")"#,
            wat_str(format!("{tower}\n").as_bytes())
        );
        let wat = module(
            &data,
            &format!(
                "(drop (call $out (i32.const 0) (i32.const {}))) (call $panic)",
                tower.len() + 1
            ),
        )
        .replacen(
            "(memory (export",
            "(import \"m2100_test\" \"panic\" (func $panic))\n  (memory (export",
            1,
        );
        let (sb, _c) = wat_sandbox(&wat, Duration::from_secs(30));
        let capture = some_capture();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = sb.run(capture.path());
            let _ = tx.send(r);
        });
        let (tally, end) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a panic on the guest thread wedged the run");
        assert!(
            matches!(end, RunEnd::Trapped(ref m) if m.contains("panicked")),
            "{end:?}"
        );
        assert_eq!(tally.towers, 1, "events before the panic are kept");
    }

    #[test]
    fn a_missing_capture_is_reported_not_panicked() {
        let (data, body) = summary_body();
        let (sb, _c) = wat_sandbox(&module(&data, &body), Duration::from_secs(10));
        let (_, end) = sb.run(Path::new("/nonexistent/capture.qmdl.gz"));
        assert!(
            matches!(end, RunEnd::Trapped(ref m) if m.contains("capture")),
            "{end:?}"
        );
    }
}
