//! Decode one gzipped QMDL capture into events. Everything here treats the
//! input as hostile: memory is bounded by the caps (frame, decompressed size,
//! event count), never by the input.
//!
//! Event accounting: every event line counts toward `max_events`, including
//! the final `summary`/`capped`. Things emitted only at the end (towers seen
//! by PCI alone, `parse_failures` hour buckets) reserve their line as soon as
//! they are first seen, so `written + reserved + 1 <= max_events` holds at all
//! times and the end-of-capture lines always fit. A new event, bucket or
//! PCI-only tower that would break that is the `events` cap.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use flate2::read::GzDecoder;
use rayhunter::DeviceMetadata;
use rayhunter::analysis::analyzer::{AnalyzerConfig, EventType, Harness};
use rayhunter::analysis::observe::{is_identity_request, rrc_cell, sib1_tower};
use rayhunter::diag::Message;
use rayhunter::qmdl::QmdlMessageReader;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use crate::events::{CapKind, Event, LineWriter, Strength};

/// Hard limits. `Default` is the production set (spec section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Longest frame, terminator included. Longer frames are counted as
    /// parse failures and the reader resyncs at the next terminator.
    pub max_frame: usize,
    /// Most bytes gunzip may produce.
    pub max_decompressed: u64,
    /// Most output lines, the final `summary`/`capped` included.
    pub max_events: u64,
    /// Longest output line, its newline included.
    pub max_line: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_frame: 65536,
            max_decompressed: 1 << 30,
            max_events: 200_000,
            max_line: 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Ended with `summary`.
    Summary,
    /// Ended with `capped`.
    Capped(CapKind),
    /// stdout failed; the output so far may end mid-stream.
    OutputError,
}

/// Decode the gzipped capture `input`, writing event lines to `out`.
pub fn run<R: Read, W: Write>(input: R, out: W, caps: Caps) -> Outcome {
    assert!(caps.max_frame > 0, "max_frame 0 would never make progress");
    assert!(caps.max_events >= 1 && caps.max_line >= 256);

    let cap_hit = Rc::new(Cell::new(false));
    let plain = CappedRead {
        inner: GzDecoder::new(input),
        left: caps.max_decompressed,
        hit: cap_hit.clone(),
    };
    let source = Source {
        probe_bytes: PROBE_BYTES,
        inner: plain,
        hit: cap_hit.clone(),
        done: false,
    };
    let mut decoder = Decoder::new(out, caps);

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    rt.block_on(async {
        let mut reader = QmdlMessageReader::new(source)
            .await
            .expect("reader construction does not fail")
            .with_max_frame(caps.max_frame);
        // We gunzip (with a cap) ourselves; the reader must never gunzip again.
        assert!(!reader.is_compressed());
        let result = decoder.decode_all(&mut reader, &cap_hit).await;
        decoder.finish(result)
    })
}

/// Bytes the reader's gzip probe (`read_u16`, then a rewind) consumes.
const PROBE_BYTES: usize = 2;

/// Gunzip output with a hard size limit: reading past `left` bytes sets `hit`
/// and errors (so a capture of exactly the limit is fine).
struct CappedRead<R> {
    inner: R,
    left: u64,
    hit: Rc<Cell<bool>>,
}

impl<R: Read> Read for CappedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => {
                    self.hit.set(true);
                    Err(io::Error::other("decompressed size cap"))
                }
            };
        }
        let n = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let got = self.inner.read(&mut buf[..n])?;
        self.left -= got as u64;
        Ok(got)
    }
}

/// Adapts the blocking reader to the async `QmdlMessageReader` (everything
/// runs on one thread; stdin blocking is fine).
///
/// The reader probes its source for the gzip magic (reads 2 bytes, then
/// rewinds) and would transparently gunzip -- without our cap -- a capture
/// whose decompressed bytes are themselves gzip. So this source is not
/// seekable: the rewind fails, the reader takes the input as plain, and the
/// probe is fed `PROBE_BYTES` throwaway bytes so no capture byte is lost.
///
/// A gunzip error (corrupt or truncated gzip) reads as the end of input, as
/// the library does for truncated gzip; only the size cap is an error.
struct Source<R> {
    probe_bytes: usize,
    inner: R,
    hit: Rc<Cell<bool>>,
    done: bool,
}

// Nothing is ever pinned through a Source: the inner reader is blocking and
// only reached by `&mut`, so any `R` (stdin's lock, a slice...) is fine.
impl<R> Unpin for Source<R> {}

impl<R: Read> AsyncRead for Source<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.probe_bytes > 0 {
            let n = this.probe_bytes.min(buf.remaining());
            buf.put_slice(&[0u8; PROBE_BYTES][..n]);
            this.probe_bytes -= n;
            return Poll::Ready(Ok(()));
        }
        if this.done {
            return Poll::Ready(Ok(()));
        }
        let dst = buf.initialize_unfilled();
        loop {
            match this.inner.read(dst) {
                Ok(n) => {
                    if n == 0 {
                        this.done = true;
                    }
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    this.done = true;
                    return Poll::Ready(if this.hit.get() { Err(e) } else { Ok(()) });
                }
            }
        }
    }
}

impl<R> AsyncSeek for Source<R> {
    fn start_seek(self: Pin<&mut Self>, _: io::SeekFrom) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
    }
}

/// Why decoding stopped early.
enum Stop {
    Cap(CapKind),
    Output,
}

/// A `parse_failures` bucket: the message's time truncated to the hour, as
/// hours since the Unix epoch; `None` for frames with no timestamp (diag-level
/// parse failures, oversized frames, non-log messages).
type Hour = Option<i64>;

#[derive(Default)]
struct Bucket {
    failures: u64,
    frames: u64,
}

struct Decoder<W: Write> {
    out: LineWriter<W>,
    caps: Caps,
    harness: Harness,
    analyzers: Vec<String>,
    frames: u64,
    failures: u64,
    towers: u64,
    identity_requests: u64,
    buckets: BTreeMap<Hour, Bucket>,
    /// (pci, earfcn) seen only by PCI so far -> first time seen. Emitted at
    /// the end unless a SIB1 names the tower first.
    pci_only: BTreeMap<(u16, u32), Option<String>>,
    /// (pci, earfcn) that have a SIB1 tower.
    sib1_cells: BTreeSet<(u16, u32)>,
    /// Emitted SIB1 towers: (plmn, tac, cell, pci, earfcn).
    sib1_towers: BTreeSet<(Option<String>, u64, u64, u16, u32)>,
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn severity(t: EventType) -> &'static str {
    match t {
        EventType::High => "high",
        EventType::Medium => "medium",
        EventType::Low => "low",
        EventType::Informational => "info",
    }
}

impl<W: Write> Decoder<W> {
    fn new(out: W, caps: Caps) -> Self {
        let harness =
            Harness::new_with_config(&AnalyzerConfig::default(), &DeviceMetadata::default());
        let analyzers = harness
            .get_metadata()
            .analyzers
            .iter()
            .map(|m| m.key.to_string())
            .collect();
        Decoder {
            out: LineWriter::new(out, caps.max_line),
            caps,
            harness,
            analyzers,
            frames: 0,
            failures: 0,
            towers: 0,
            identity_requests: 0,
            buckets: BTreeMap::new(),
            pci_only: BTreeMap::new(),
            sib1_cells: BTreeSet::new(),
            sib1_towers: BTreeSet::new(),
        }
    }

    /// Lines already promised: written, plus end-of-capture lines reserved.
    fn committed(&self) -> u64 {
        self.out.written() + self.buckets.len() as u64 + self.pci_only.len() as u64
    }

    /// Can one more line be committed and still leave room for the final one?
    fn room_for_one(&self) -> Result<(), Stop> {
        if self.committed() + 2 <= self.caps.max_events {
            Ok(())
        } else {
            Err(Stop::Cap(CapKind::Events))
        }
    }

    fn emit(&mut self, ev: Event) -> Result<(), Stop> {
        self.room_for_one()?;
        self.out.write(&ev).map_err(|_| Stop::Output)
    }

    fn count_frame(&mut self, hour: Hour, failed: bool) -> Result<(), Stop> {
        if !self.buckets.contains_key(&hour) {
            self.room_for_one()?;
        }
        let b = self.buckets.entry(hour).or_default();
        b.frames += 1;
        self.frames += 1;
        if failed {
            b.failures += 1;
            self.failures += 1;
        }
        Ok(())
    }

    async fn decode_all<T>(
        &mut self,
        reader: &mut QmdlMessageReader<T>,
        cap_hit: &Cell<bool>,
    ) -> Result<(), Stop>
    where
        T: AsyncRead + AsyncSeek + Unpin,
    {
        loop {
            match reader.get_next_message().await {
                Ok(None) => return Ok(()),
                // Diag-level failure: counted only. Its error embeds the raw
                // frame bytes, so it never reaches the harness or the output.
                Ok(Some(Err(_))) => self.count_frame(None, true)?,
                Ok(Some(Ok(msg))) => self.message(msg)?,
                Err(_) if cap_hit.get() => return Err(Stop::Cap(CapKind::Decompressed)),
                // Over max_frame: the reader consumed max_frame bytes and
                // resyncs on the next call; the frame's tail comes back as a
                // (failing) frame of its own.
                Err(e) if e.kind() == io::ErrorKind::InvalidData => self.count_frame(None, true)?,
                // Nothing else is produced by our source; treat as the end.
                Err(_) => return Ok(()),
            }
        }
    }

    fn message(&mut self, msg: Message) -> Result<(), Stop> {
        let time: Option<DateTime<Utc>> = match &msg {
            Message::Log { timestamp, .. } => Some(timestamp.to_datetime().with_timezone(&Utc)),
            _ => None,
        };
        let cell = rrc_cell(&msg);
        let (row, element) = self.harness.analyze_qmdl_message_with_element(Ok(msg));
        let hour = time.map(|t| t.timestamp().div_euclid(3600));
        self.count_frame(hour, row.skipped_message_reason.is_some())?;
        let ts = time.map(rfc3339);

        if let Some(element) = &element {
            match (sib1_tower(element), cell) {
                (Some(t), Some((pci, earfcn))) => {
                    let key = (t.plmn.clone(), t.tac, t.cell, pci, earfcn);
                    if !self.sib1_towers.contains(&key) {
                        // frees its reserved line, if it had one
                        self.pci_only.remove(&(pci, earfcn));
                        self.emit(Event::Tower {
                            ts: ts.clone(),
                            plmn: t.plmn,
                            tac: Some(t.tac),
                            cell: Some(t.cell),
                            pci,
                            earfcn,
                            strength: Strength::Sib1,
                        })?;
                        self.towers += 1;
                        self.sib1_towers.insert(key);
                        self.sib1_cells.insert((pci, earfcn));
                    }
                }
                (None, Some(pc)) => {
                    if !self.sib1_cells.contains(&pc) && !self.pci_only.contains_key(&pc) {
                        self.room_for_one()?;
                        self.pci_only.insert(pc, ts.clone());
                    }
                }
                _ => {}
            }
            if is_identity_request(element) {
                self.identity_requests += 1;
                self.emit(Event::IdentityRequest {
                    ts: ts.clone(),
                    frame: self.frames,
                })?;
            }
        }

        for (i, ev) in row.events.into_iter().enumerate() {
            let Some(ev) = ev else { continue };
            self.emit(Event::Warning {
                ts: ts.clone(),
                severity: severity(ev.event_type),
                analyzer: self.analyzers.get(i).cloned().unwrap_or_default(),
                msg: ev.message,
            })?;
        }
        Ok(())
    }

    /// Write the reserved end-of-capture lines (they always fit), then the
    /// final `summary` or `capped`.
    fn finish(&mut self, result: Result<(), Stop>) -> Outcome {
        let last = match result {
            Ok(()) => None,
            Err(Stop::Cap(what)) => Some(what),
            Err(Stop::Output) => return Outcome::OutputError,
        };
        let mut lines = Vec::new();
        for ((pci, earfcn), ts) in std::mem::take(&mut self.pci_only) {
            self.towers += 1;
            lines.push(Event::Tower {
                ts,
                plmn: None,
                tac: None,
                cell: None,
                pci,
                earfcn,
                strength: Strength::Pci,
            });
        }
        for (hour, b) in std::mem::take(&mut self.buckets) {
            lines.push(Event::ParseFailures {
                hour: hour.map(|h| {
                    Utc.timestamp_opt(h * 3600, 0)
                        .single()
                        .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
                        .unwrap_or_default()
                }),
                count: b.failures,
                frames: b.frames,
            });
        }
        lines.push(match last {
            None => Event::Summary {
                frames: self.frames,
                failures: self.failures,
                towers: self.towers,
                identity_requests: self.identity_requests,
            },
            Some(what) => Event::Capped {
                what,
                at_frame: self.frames,
            },
        });
        for ev in &lines {
            if self.out.write(ev).is_err() {
                return Outcome::OutputError;
            }
        }
        debug_assert!(self.out.written() <= self.caps.max_events);
        match last {
            None => Outcome::Summary,
            Some(what) => Outcome::Capped(what),
        }
    }
}
