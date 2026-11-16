//! One pull cycle: list the unit's finished captures, download each new one, verify it
//! against the device's own hash, archive it, and only then delete it on the device.
//!
//! A capture is `(name, start)`, never the name alone: the unit reuses names across boots
//! (pre-sync recordings are named from seconds since boot), and its delete and hash
//! endpoints only take a name, so a name can point at different bytes from one cycle to
//! the next.
//!
//! The safety rule lives here: `Device::delete` is called from exactly one place,
//! `delete_verified`, which re-reads the index row and the archived file, then asks the
//! unit for a fresh hash of the name. A delete goes out only for a row that is `Archived`
//! with `local_sha256 == device_sha256`, whose archive file decompresses to bytes with
//! that hash, and whose name the unit hashes to that same value right now. Every other
//! path leaves the device's copy alone.
#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::device::{Device, DeviceError, Entry};
use crate::store::{Capture, State, Store};

/// Below this many free bytes on the archive's disk no new captures are pulled.
pub const MIN_FREE_BYTES: u64 = 5_000_000_000;
/// A capture whose download mismatched this many times is flagged and never retried.
pub const MAX_MISMATCH_TRIES: u32 = 2;
/// The device delete also removes the analysis, so it waits while the analysis is
/// missing: one fetch attempt per cycle, this many, then the delete goes out anyway (a
/// broken analysis endpoint must not fill the unit).
pub const MAX_ANALYSIS_TRIES: u32 = 3;
/// SHA-256 of no bytes. A recording that has just started can be empty too, so an empty
/// archived capture is never a reason to delete whatever the unit holds under its name.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub pulled: u32,
    pub deleted: u32,
    pub mismatches: u32,
    pub missing: u32,
    pub backlog: u32,
    pub oldest_backlog: Option<DateTime<Utc>>,
    pub reached_device: bool,
}

/// One pass over the unit's finished captures.
///
/// `backlog` / `oldest_backlog` count listed captures still on the unit after this cycle
/// (anything not `DeletedOnDevice` / `MissingOnDevice`, including flagged mismatches).
/// When `reached_device` is false they are 0 / None: the caller should keep showing the
/// last known backlog.
pub async fn cycle(
    dev: &dyn Device,
    store: &Store,
    device_id: &str,
    archive: &Path,
    now: DateTime<Utc>,
    free_bytes: u64,
) -> Outcome {
    let mut o = Outcome::default();
    let tmp = archive.join(".tmp");
    let mismatch = archive.join("mismatch");
    for d in [archive.to_path_buf(), mismatch.clone()] {
        if let Err(e) = std::fs::create_dir_all(&d) {
            log::warn!("cannot create {}: {e}; skipping this cycle", d.display());
            return o;
        }
    }
    // A temp file is never trusted: it is from a download that did not finish (or an
    // add-on restart mid-cycle). Clear it before anything else, reachable or not.
    clean_tmp(&tmp, &mismatch);
    if let Err(e) = std::fs::create_dir_all(&tmp) {
        log::warn!("cannot create {}: {e}; skipping this cycle", tmp.display());
        return o;
    }

    let entries = match dev.finished().await {
        Ok(e) => e,
        Err(e) => {
            log::warn!("unit unreachable: {e:?}");
            return o;
        }
    };
    o.reached_device = true;
    let p = Puller {
        dev,
        store,
        device_id,
        archive,
        now,
    };

    for e in &entries {
        if !safe_name(&e.name) {
            // Never pulled, so not counted in backlog either.
            log::warn!("ignoring capture with unsafe name {:?}", e.name);
            continue;
        }
        // The row for this (name, start). No row: a new capture, even if the name
        // has been seen before (another boot's recording).
        match p.row(e) {
            Err(err) => log::warn!("index read failed for {}: {err:#}", e.name),
            Ok(row) => match row.as_ref().map(|r| r.state) {
                Some(State::DeletedOnDevice | State::MissingOnDevice) => continue,
                Some(State::Archived) => p.archived(e, row.unwrap(), &mut o).await,
                Some(State::Mismatch)
                    if row.as_ref().unwrap().mismatch_tries >= MAX_MISMATCH_TRIES => {}
                Some(State::Mismatch) | None => {
                    if free_bytes < MIN_FREE_BYTES {
                        log::info!("low disk: not pulling {}", e.name);
                    } else {
                        p.pull(e, row, &mut o).await;
                    }
                }
            },
        }
        // Backlog: what the pipeline still intends to clear from the unit (new, Archived
        // awaiting delete, Mismatch still to be retried). Not flagged mismatches, not
        // missing or deleted ones.
        let pending = match p.row(e) {
            Ok(None) | Err(_) => true,
            Ok(Some(c)) => match c.state {
                State::Archived => true,
                State::Mismatch => c.mismatch_tries < MAX_MISMATCH_TRIES,
                State::DeletedOnDevice | State::MissingOnDevice => false,
            },
        };
        if pending {
            o.backlog += 1;
            o.oldest_backlog = Some(o.oldest_backlog.map_or(e.start, |t| t.min(e.start)));
        }
    }
    o
}

struct Puller<'a> {
    dev: &'a dyn Device,
    store: &'a Store,
    device_id: &'a str,
    archive: &'a Path,
    now: DateTime<Utc>,
}

impl Puller<'_> {
    fn tmp(&self, file: &str) -> PathBuf {
        self.archive.join(".tmp").join(file)
    }

    fn key<'k>(&'k self, e: &'k Entry) -> crate::store::Key<'k> {
        crate::store::Key {
            device: self.device_id,
            name: &e.name,
            start: &e.start,
        }
    }

    fn row(&self, e: &Entry) -> anyhow::Result<Option<Capture>> {
        self.store.get(self.key(e))
    }

    /// `{name}-{start unix seconds}`, the base every file of this capture is named from.
    fn stem(e: &Entry) -> String {
        format!("{}-{}", e.name, e.start.timestamp())
    }

    /// A stem no existing archive file or index row uses: `{stem}`, else `{stem}-2`,
    /// `{stem}-3`... (two captures can share a name and start second). A surviving
    /// index row owns its stem even with no files (restore, manual removal); pruning
    /// that row would delete these files. A failed lookup is an error (the pull is
    /// retried next cycle), never "free".
    fn free_stem(&self, e: &Entry) -> anyhow::Result<String> {
        let base = Self::stem(e);
        for k in 1.. {
            let s = match k {
                1 => base.clone(),
                k => format!("{base}-{k}"),
            };
            if !self.archive.join(format!("{s}.qmdl.gz")).exists()
                && !self.archive.join(format!("{s}.ndjson")).exists()
                && !self.store.stem_in_use(self.device_id, &s)?
            {
                return Ok(s);
            }
        }
        unreachable!()
    }

    /// Download, verify, archive, record, then (only then) delete.
    async fn pull(&self, e: &Entry, prev: Option<Capture>, o: &mut Outcome) {
        let name = &e.name;
        let tmp_gz = self.tmp(&format!("{name}.qmdl.gz"));
        let local = match self.dev.download(name, &tmp_gz).await {
            Ok(h) => h,
            Err(DeviceError::NotFound) => {
                discard(&tmp_gz);
                self.record_missing(e, prev, o);
                return;
            }
            Err(err) => {
                discard(&tmp_gz);
                log::warn!("download {name} failed: {err:?}; retry next cycle");
                return;
            }
        };
        let remote = match self.dev.device_sha256(name).await {
            Ok(h) => Some(h),
            // Garbage from the device is a mismatch, never a match.
            Err(DeviceError::Bad(why)) => {
                log::warn!("device hash for {name} unusable: {why}");
                None
            }
            // The unit lost it between download and hash: our copy is now the only one.
            // Keep it (unverified) and flag the row so the pruner never takes it.
            Err(DeviceError::NotFound) => {
                self.keep_unverified(e, prev, &tmp_gz, o);
                return;
            }
            Err(err) => {
                discard(&tmp_gz);
                log::warn!("device hash for {name} unavailable: {err:?}; retry next cycle");
                return;
            }
        };
        let remote = match remote {
            Some(r) if is_sha256_hex(&local) && local == r => r,
            other => {
                log::warn!("hash mismatch for {name}: local {local}, device {other:?}");
                self.record_mismatch(e, prev, &tmp_gz, o);
                return;
            }
        };

        let stem = match self.free_stem(e) {
            Ok(s) => s,
            Err(err) => {
                log::warn!("cannot pick a stem for {name}: {err}; retry next cycle");
                return;
            }
        };
        let dest = self.archive.join(format!("{stem}.qmdl.gz"));
        if let Err(err) = move_durably(&tmp_gz, &dest) {
            log::warn!("cannot archive {name}: {err}; retry next cycle");
            return;
        }
        // Before the device copy (and its analysis) is deleted.
        let analysis_ok = self.fetch_analysis(e, &stem).await;
        let (tries, kept, flagged, an_tries) = prev.as_ref().map_or((0, false, false, 0), |p| {
            (p.mismatch_tries, p.kept, p.flagged, p.analysis_tries)
        });
        let an_tries = if analysis_ok { an_tries } else { an_tries + 1 };
        let c = Capture {
            device: self.device_id.into(),
            name: name.clone(),
            state: State::Archived,
            local_sha256: Some(local),
            device_sha256: Some(remote),
            size: e.size,
            start: e.start,
            last_message: e.last_message,
            archived_at: Some(self.now),
            mismatch_tries: tries,
            kept,
            flagged,
            file: Some(stem),
            analysis_tries: an_tries,
        };
        if let Err(err) = self.store.record_archived(&c) {
            log::warn!("cannot record {name} as archived: {err:#}; not deleting");
            return;
        }
        o.pulled += 1;
        log::info!(
            "archived {name} as {}",
            c.file.as_deref().unwrap_or_default()
        );
        if analysis_ok || an_tries >= MAX_ANALYSIS_TRIES {
            self.delete_verified(e, o).await;
        } else {
            log::warn!("analysis for {name} missing; device delete deferred (try {an_tries})");
        }
    }

    /// Save the analysis as `{stem}.ndjson` (never replacing a file); true if it is there.
    async fn fetch_analysis(&self, e: &Entry, stem: &str) -> bool {
        let name = &e.name;
        let tmp_an = self.tmp(&format!("{name}.ndjson"));
        match self.dev.analysis(name, &tmp_an).await {
            Ok(()) => match move_durably(&tmp_an, &self.archive.join(format!("{stem}.ndjson"))) {
                Ok(()) => true,
                Err(err) => {
                    log::warn!("cannot archive analysis for {name}: {err}");
                    false
                }
            },
            Err(err) => {
                discard(&tmp_an);
                log::warn!("analysis for {name} not fetched: {err:?}");
                false
            }
        }
    }

    /// An Archived row whose capture is still listed: fetch a missing analysis (one try
    /// per cycle, up to MAX_ANALYSIS_TRIES), then delete.
    async fn archived(&self, e: &Entry, row: Capture, o: &mut Outcome) {
        let name = &e.name;
        let Some(stem) = row.file.as_deref() else {
            log::warn!("not deleting {name}: archived row has no file");
            return;
        };
        let have_analysis = self.archive.join(format!("{stem}.ndjson")).exists();
        if !have_analysis && row.analysis_tries < MAX_ANALYSIS_TRIES {
            // Only while the unit still holds our bytes under this name: a reused name
            // would serve another boot's analysis.
            match self.dev.device_sha256(name).await {
                Ok(h) if row.local_sha256.as_deref() == Some(h.as_str()) => {}
                other => {
                    log::warn!("not fetching analysis for {name}: unit hash is {other:?}");
                    return;
                }
            }
            if !self.fetch_analysis(e, stem).await {
                match self.store.bump_analysis(self.key(e)) {
                    Ok(n) => log::warn!("analysis for {name} missing; delete deferred (try {n})"),
                    Err(err) => log::warn!("cannot count analysis try for {name}: {err:#}"),
                }
                return;
            }
        }
        self.delete_verified(e, o).await;
    }

    fn record_missing(&self, e: &Entry, prev: Option<Capture>, o: &mut Outcome) {
        log::warn!("{} listed but not found on the unit", e.name);
        let mut c = self.unverified(e, prev.as_ref());
        c.state = State::MissingOnDevice;
        match self.store.record_archived(&c) {
            Ok(()) => o.missing += 1,
            Err(err) => log::warn!("cannot record {} missing: {err:#}", e.name),
        }
    }

    /// Device hash NotFound after a good download: our copy is the only one. Keep it as
    /// `mismatch/{stem}.unverified[.k].qmdl.gz` (never overwriting), then record the
    /// capture MissingOnDevice and flag it.
    ///
    /// If the move fails and the file is still in `.tmp`, no row is written (a row would
    /// claim a copy that is not in `mismatch/`); the file is renamed in place to
    /// `.tmp/{stem}.unverified.qmdl.gz`, which the next cycles' clean-up moves into
    /// `mismatch/` instead of wiping.
    fn keep_unverified(&self, e: &Entry, prev: Option<Capture>, tmp_gz: &Path, o: &mut Outcome) {
        let name = &e.name;
        let base = format!("{}.unverified", Self::stem(e));
        let keep = unique(&self.archive.join("mismatch"), &base, "qmdl.gz");
        match move_durably(tmp_gz, &keep) {
            Ok(()) => log::warn!(
                "{name} vanished from the unit before it could be verified; unverified copy kept at {}",
                keep.display()
            ),
            // The rename went through but was not confirmed durable: the copy is there.
            Err(err) if keep.exists() => {
                log::warn!(
                    "unverified copy of {name} at {} (dir sync: {err})",
                    keep.display()
                )
            }
            Err(err) => {
                let parked = unique(&self.archive.join(".tmp"), &base, "qmdl.gz");
                match std::fs::rename(tmp_gz, &parked) {
                    Ok(()) => log::error!(
                        "cannot keep the only copy of {name} in mismatch/ ({err}); parked at {} \
                         for the next cycle to move",
                        parked.display()
                    ),
                    Err(err2) => log::error!(
                        "cannot keep the only copy of {name} ({err}; {err2}); it is at {} and \
                         will be lost when .tmp is cleared",
                        tmp_gz.display()
                    ),
                }
                return;
            }
        }
        self.record_missing(e, prev, o);
        if let Err(err) = self.store.set_flagged(self.key(e), true) {
            log::warn!("cannot flag {name}: {err:#}");
        }
    }

    fn record_mismatch(&self, e: &Entry, prev: Option<Capture>, tmp_gz: &Path, o: &mut Outcome) {
        let name = &e.name;
        o.mismatches += 1;
        let n = prev.as_ref().map_or(0, |p| p.mismatch_tries) + 1;
        let stem = Self::stem(e);
        let dir = self.archive.join("mismatch");
        let keep = (1..)
            .map(|k| match k {
                1 => dir.join(format!("{stem}.{n}.qmdl.gz")),
                k => dir.join(format!("{stem}.{n}.{k}.qmdl.gz")),
            })
            .find(|p| !p.exists())
            .unwrap();
        if let Err(err) = move_durably(tmp_gz, &keep) {
            log::warn!("cannot keep mismatched copy of {name}: {err}");
        }
        let r = match prev {
            None => {
                let mut c = self.unverified(e, None);
                c.state = State::Mismatch;
                c.mismatch_tries = 1;
                self.store.record_archived(&c).map(|_| 1)
            }
            Some(_) => self.store.bump_mismatch(self.key(e)),
        };
        match r {
            Ok(tries) if tries >= MAX_MISMATCH_TRIES => {
                log::warn!("{name} mismatched {tries} times; flagged, not retrying");
                if let Err(err) = self.store.set_flagged(self.key(e), true) {
                    log::warn!("cannot flag {name}: {err:#}");
                }
            }
            Ok(_) => {}
            Err(err) => log::warn!("cannot record mismatch for {name}: {err:#}"),
        }
    }

    /// A row with no verified hash (Mismatch / MissingOnDevice), keeping what `prev` had.
    fn unverified(&self, e: &Entry, prev: Option<&Capture>) -> Capture {
        Capture {
            device: self.device_id.into(),
            name: e.name.clone(),
            state: State::Mismatch,
            local_sha256: None,
            device_sha256: None,
            size: e.size,
            start: e.start,
            last_message: e.last_message,
            archived_at: None,
            mismatch_tries: prev.map_or(0, |p| p.mismatch_tries),
            kept: prev.is_some_and(|p| p.kept),
            flagged: prev.is_some_and(|p| p.flagged),
            file: None,
            analysis_tries: prev.map_or(0, |p| p.analysis_tries),
        }
    }

    /// The only caller of `Device::delete`. Re-reads the index row for this
    /// `(name, start)`, re-hashes the archived file, then asks the unit to hash the name
    /// again: the delete goes out only if the row is Archived with equal hashes, the file
    /// holds exactly those bytes, and the unit still holds exactly those bytes under the
    /// name (the name may have been reused by a later boot, possibly for the recording
    /// in progress, which answers 409).
    async fn delete_verified(&self, e: &Entry, o: &mut Outcome) {
        let name = &e.name;
        let (h, stem) = match self.row(e) {
            Ok(Some(Capture {
                state: State::Archived,
                local_sha256: Some(l),
                device_sha256: Some(d),
                file: Some(f),
                ..
            })) if l == d => (l, f),
            other => {
                log::warn!("not deleting {name}: index row is {other:?}");
                return;
            }
        };
        if h == EMPTY_SHA256 {
            log::warn!("not deleting {name}: the archived copy is empty");
            return;
        }
        let file = self.archive.join(format!("{stem}.qmdl.gz"));
        let got = tokio::task::spawn_blocking({
            let file = file.clone();
            move || gz_sha256(&file)
        })
        .await;
        match got {
            Ok(Ok(f)) if f == h => {}
            other => {
                log::warn!(
                    "not deleting {name}: {} is missing or not the verified bytes ({other:?})",
                    file.display()
                );
                return;
            }
        }
        // Immediately before the delete: what does the unit hold under this name now?
        match self.dev.device_sha256(name).await {
            Ok(now) if now == h => {}
            Ok(now) => {
                log::warn!(
                    "not deleting {name}: the unit now holds other bytes under that name \
                     ({now}, archived {h}); the name was reused"
                );
                return;
            }
            Err(err) => {
                log::warn!("not deleting {name}: fresh device hash unavailable ({err:?})");
                return;
            }
        }
        match self.dev.delete(name).await {
            // Ruling 1: NotFound on delete means the unit no longer has it.
            Ok(()) | Err(DeviceError::NotFound) => {
                o.deleted += 1;
                log::info!("deleted {name} on the unit");
                if let Err(err) = self.store.set_state(self.key(e), State::DeletedOnDevice) {
                    // Row stays Archived: next cycle retries the delete and gets NotFound.
                    log::warn!("cannot record {name} deleted: {err:#}");
                }
            }
            Err(err) => log::warn!("delete {name} failed: {err:?}; retry next cycle"),
        }
    }
}

/// `dir/{base}.{ext}`, else `dir/{base}.2.{ext}`, `.3`, ...: the first that does not exist.
fn unique(dir: &Path, base: &str, ext: &str) -> PathBuf {
    (1..)
        .map(|k| match k {
            1 => dir.join(format!("{base}.{ext}")),
            k => dir.join(format!("{base}.{k}.{ext}")),
        })
        .find(|p| !p.exists())
        .unwrap()
}

/// Empty `.tmp`, except for `*.unverified.qmdl.gz` files: those are the only copy of a
/// capture that vanished from the unit (parked by `keep_unverified` when its move
/// failed). They are moved into `mismatch/` (never overwriting), or left where they
/// are if that fails again; never deleted.
fn clean_tmp(tmp: &Path, mismatch: &Path) {
    let rd = match std::fs::read_dir(tmp) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            log::warn!("cannot read {}: {e}", tmp.display());
            return;
        }
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let fname = ent.file_name().to_string_lossy().into_owned();
        if let Some(base) = fname
            .strip_suffix(".qmdl.gz")
            .filter(|b| b.ends_with(".unverified"))
        {
            let to = unique(mismatch, base, "qmdl.gz");
            match move_durably(&p, &to) {
                Ok(()) => log::warn!("unverified copy moved to {}", to.display()),
                Err(e) if to.exists() => {
                    log::warn!("unverified copy at {} (dir sync: {e})", to.display())
                }
                Err(e) => log::error!("cannot move {} to mismatch/: {e}; kept", p.display()),
            }
            continue;
        }
        let r = if ent.file_type().is_ok_and(|t| t.is_dir()) {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
        if let Err(e) = r {
            log::warn!("cannot clear {}: {e}", p.display());
        }
    }
}

/// Capture names become file names: allow only plain names (the unit uses digits).
pub(crate) fn safe_name(n: &str) -> bool {
    !n.is_empty()
        && !n.starts_with('.')
        && n.len() <= 128
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn discard(p: &Path) {
    let _ = std::fs::remove_file(p);
}

/// fsync `from`, move it to `to` without ever replacing an existing file (hard link,
/// then unlink `from`), fsync `to`'s directory. `to` existing is an `AlreadyExists` error.
fn move_durably(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::File::open(from)?.sync_all()?;
    match std::fs::hard_link(from, to) {
        Ok(()) => {
            if let Err(e) = std::fs::remove_file(from) {
                // Harmless: both names are the same file; .tmp is cleared next cycle.
                log::warn!("cannot unlink {}: {e}", from.display());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(e),
        // A filesystem without hard links: cycles never overlap, so check-then-rename
        // cannot race.
        Err(_) if to.exists() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists", to.display()),
            ));
        }
        Err(_) => std::fs::rename(from, to)?,
    }
    if let Some(dir) = to.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// SHA-256 (lowercase hex) of a gzip file's decompressed contents.
pub(crate) fn gz_sha256(p: &Path) -> std::io::Result<String> {
    let mut r = flate2::read::GzDecoder::new(std::fs::File::open(p)?);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceError, Entry, Fake};
    use crate::store::{Capture, State};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::Mutex;

    const DEV: &str = "m2100";
    const PLENTY: u64 = 100_000_000_000;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn sha(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }
    fn gz(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }
    fn gunzip(p: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(p).unwrap())
            .read_to_end(&mut out)
            .unwrap();
        out
    }
    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 9, 12, 0, 0).unwrap()
    }
    fn bytes(name: &str) -> Vec<u8> {
        format!("qmdl bytes of {name}").repeat(500).into_bytes()
    }
    /// Valid-shaped (64 lowercase hex) but wrong.
    const WRONG: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    /// What the index said (every row under the name, and what each row's archive file
    /// hashed to), and what the unit really held, when a delete went out.
    #[derive(Debug)]
    struct AtDelete {
        name: String,
        rows: Vec<(Capture, Option<String>)>,
        device_true: Option<String>,
    }

    /// Wraps the Fake: records every download/device_sha256 result and, at each delete,
    /// snapshots the index row (through its own connection) and the archive file.
    struct Checked {
        fake: Fake,
        index: Mutex<Store>,
        archive: PathBuf,
        /// ("download a" | "device_sha256 a" | "delete a", result) in call order.
        results: Mutex<Vec<(String, Result<String, DeviceError>)>>,
        deletes: Mutex<Vec<AtDelete>>,
        /// Downloads that fail after leaving junk at `to` and a stray `.part`.
        partial: Mutex<HashSet<String>>,
        /// Captures the unit loses right after a successful download.
        vanish: Mutex<HashSet<String>>,
    }

    #[async_trait]
    impl Device for Checked {
        async fn finished(&self) -> Result<Vec<Entry>, DeviceError> {
            self.fake.finished().await
        }
        async fn download(&self, name: &str, to: &Path) -> Result<String, DeviceError> {
            let r = self.fake.download(name, to).await;
            if r.is_ok() && self.vanish.lock().unwrap().remove(name) {
                self.fake.remove(name);
            }
            if r.is_err() && self.partial.lock().unwrap().remove(name) {
                std::fs::write(to, b"half a gzip").unwrap();
                std::fs::write(to.with_extension("gz.part"), b"half").unwrap();
            }
            self.results
                .lock()
                .unwrap()
                .push((format!("download {name}"), r.clone()));
            r
        }
        async fn analysis(&self, name: &str, to: &Path) -> Result<(), DeviceError> {
            self.fake.analysis(name, to).await
        }
        async fn device_sha256(&self, name: &str) -> Result<String, DeviceError> {
            let r = self.fake.device_sha256(name).await;
            self.results
                .lock()
                .unwrap()
                .push((format!("device_sha256 {name}"), r.clone()));
            r
        }
        async fn delete(&self, name: &str) -> Result<(), DeviceError> {
            let rows = self.index.lock().unwrap().by_name(DEV, name).unwrap();
            let rows = rows
                .into_iter()
                .map(|c| {
                    let f = c
                        .file
                        .as_ref()
                        .map(|f| self.archive.join(format!("{f}.qmdl.gz")));
                    let file_sha = f.filter(|f| f.exists()).map(|f| sha(&gunzip(&f)));
                    (c, file_sha)
                })
                .collect();
            self.deletes.lock().unwrap().push(AtDelete {
                name: name.into(),
                rows,
                device_true: self.fake.true_sha256(name),
            });
            let r = self.fake.delete(name).await;
            self.results
                .lock()
                .unwrap()
                .push((format!("delete {name}"), r.clone().map(|_| String::new())));
            r
        }
        async fn fixed(&self, token: &str) -> Result<bool, DeviceError> {
            self.fake.fixed(token).await
        }
        async fn live(&self, token: &str) -> Result<crate::live::Snapshot, DeviceError> {
            self.fake.live(token).await
        }
        async fn capture_profiles(
            &self,
        ) -> Result<std::collections::HashMap<String, String>, DeviceError> {
            self.fake.capture_profiles().await
        }
        async fn current(&self) -> Result<Option<String>, DeviceError> {
            self.fake.current().await
        }
        async fn disk_used_percent(&self) -> Result<u32, DeviceError> {
            self.fake.disk_used_percent().await
        }
        async fn stop_recording(&self) -> Result<(), DeviceError> {
            self.fake.stop_recording().await
        }
        async fn start_recording(&self) -> Result<(), DeviceError> {
            self.fake.start_recording().await
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        store: Store,
        dev: Checked,
        archive: PathBuf,
        /// Names whose Archived row was put in the index before the first cycle
        /// ("recorded in an earlier one").
        seeded: Vec<String>,
    }

    impl Rig {
        fn new() -> Rig {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("index.sqlite");
            let archive = dir.path().join("archive");
            let store = Store::open(&db).unwrap();
            let dev = Checked {
                fake: Fake::new(),
                index: Mutex::new(Store::open(&db).unwrap()),
                archive: archive.clone(),
                results: Mutex::default(),
                deletes: Mutex::default(),
                partial: Mutex::default(),
                vanish: Mutex::default(),
            };
            Rig {
                _dir: dir,
                store,
                dev,
                archive,
                seeded: Vec::new(),
            }
        }
        fn fake(&self) -> &Fake {
            &self.dev.fake
        }
        async fn run(&self, free: u64) -> Outcome {
            cycle(&self.dev, &self.store, DEV, &self.archive, now(), free).await
        }
        /// The one row under `name` (tests that reuse names use `store.by_name`).
        fn row(&self, name: &str) -> Option<Capture> {
            let mut v = self.store.by_name(DEV, name).unwrap();
            assert!(v.len() <= 1, "{name} has {} rows", v.len());
            v.pop()
        }
        /// The archive file of a capture added with `Fake::add` (start 1_700_000_000).
        fn file(&self, name: &str) -> PathBuf {
            self.archive.join(format!("{name}-1700000000.qmdl.gz"))
        }
        fn tmp(&self) -> PathBuf {
            self.archive.join(".tmp")
        }
        fn tmp_is_empty(&self) -> bool {
            std::fs::read_dir(self.tmp()).unwrap().next().is_none()
        }
        /// An earlier cycle archived `name` (verified) but its delete never went out.
        fn seed_archived(&mut self, name: &str) {
            let b = bytes(name);
            self.fake().add(name, &b);
            std::fs::create_dir_all(&self.archive).unwrap();
            std::fs::write(self.file(name), gz(&b)).unwrap();
            std::fs::write(
                self.archive.join(format!("{name}-1700000000.ndjson")),
                b"{}\n",
            )
            .unwrap();
            let h = sha(&b);
            let start = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
            self.store
                .record_archived(&Capture {
                    device: DEV.into(),
                    name: name.into(),
                    state: State::Archived,
                    local_sha256: Some(h.clone()),
                    device_sha256: Some(h),
                    size: b.len() as u64,
                    start,
                    last_message: None,
                    archived_at: Some(now()),
                    mismatch_tries: 0,
                    kept: false,
                    flagged: false,
                    file: Some(format!("{name}-1700000000")),
                    analysis_tries: 0,
                })
                .unwrap();
            self.seeded.push(name.into());
        }
        /// Log lines added since `from`.
        fn log_since(&self, from: usize) -> Vec<String> {
            self.fake().log()[from..].to_vec()
        }
        fn deleted(&self) -> Vec<String> {
            self.dev
                .deletes
                .lock()
                .unwrap()
                .iter()
                .map(|d| d.name.clone())
                .collect()
        }

        /// THE SAFETY RULE, checked over everything this rig's device has seen so far.
        ///
        /// Every `delete X` sent to the device must have, at the moment it went out:
        /// - as the call immediately before it, `device_sha256 X` returning Ok(h): a fresh
        ///   check that the unit holds, under the name, the bytes we archived,
        /// - the unit really holding bytes with hash h under X (not just claiming to),
        /// - an index row under X in state Archived with local_sha256 == device_sha256 == h,
        /// - that row's archive file decompressing to bytes with exactly that hash,
        /// - and either X was archived in an earlier run (seeded), or earlier in the call
        ///   sequence `download X` returned Ok(h) and a later `device_sha256 X` returned
        ///   Ok(h).
        fn assert_safe(&self) {
            let log = self.fake().log();
            let deletes = self.dev.deletes.lock().unwrap();
            let results = self.dev.results.lock().unwrap();
            let n_log = log.iter().filter(|l| l.starts_with("delete ")).count();
            assert_eq!(n_log, deletes.len(), "a delete bypassed the check: {log:?}");

            let mut seen_deletes = 0;
            for (i, (key, _)) in results.iter().enumerate() {
                let Some(name) = key.strip_prefix("delete ") else {
                    continue;
                };
                let d = &deletes[seen_deletes];
                seen_deletes += 1;
                assert_eq!(d.name, name);

                let h = match results[..i].last() {
                    Some((k, Ok(h))) if *k == format!("device_sha256 {name}") => h.clone(),
                    other => panic!("delete {name} not immediately after a good hash: {other:?}"),
                };
                assert_eq!(
                    d.device_true.as_deref(),
                    Some(h.as_str()),
                    "delete {name}: the unit held other bytes than the hash said"
                );
                let ok_row = d.rows.iter().any(|(row, file_sha)| {
                    row.state == State::Archived
                        && row.local_sha256.as_deref() == Some(h.as_str())
                        && row.device_sha256.as_deref() == Some(h.as_str())
                        && file_sha.as_deref() == Some(h.as_str())
                });
                assert!(
                    ok_row,
                    "delete {name}: no Archived row with a verified file for {h}: {:?}",
                    d.rows
                );

                if self.seeded.iter().any(|s| s == name) {
                    continue;
                }
                let before = &results[..i];
                let dl = before
                    .iter()
                    .rposition(|(k, r)| {
                        *k == format!("download {name}") && r.as_ref().ok() == Some(&h)
                    })
                    .unwrap_or_else(|| panic!("delete {name} without a good download first"));
                let verified = before[dl + 1..i - 1].iter().any(|(k, r)| {
                    *k == format!("device_sha256 {name}") && r.as_ref().ok() == Some(&h)
                });
                assert!(
                    verified,
                    "delete {name}: device hash never matched the download"
                );
            }
        }
    }

    #[tokio::test]
    async fn happy_path_archives_then_deletes() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().set_analysis("a", b"{\"analysis\":1}\n");
        let o = r.run(PLENTY).await;

        assert_eq!(
            r.fake().log(),
            [
                "finished",
                "download a",
                "device_sha256 a",
                "analysis a",
                "device_sha256 a",
                "delete a"
            ]
        );
        assert_eq!(gunzip(&r.file("a")), bytes("a"));
        assert_eq!(
            std::fs::read(r.archive.join("a-1700000000.ndjson")).unwrap(),
            b"{\"analysis\":1}\n"
        );
        let c = r.row("a").unwrap();
        assert_eq!(c.state, State::DeletedOnDevice);
        assert_eq!(c.local_sha256, Some(sha(&bytes("a"))));
        assert_eq!(c.local_sha256, c.device_sha256);
        assert_eq!(c.archived_at, Some(now()));
        assert!(!r.fake().has("a"));
        assert!(r.tmp_is_empty());
        assert_eq!(
            o,
            Outcome {
                pulled: 1,
                deleted: 1,
                reached_device: true,
                ..Default::default()
            }
        );
        r.assert_safe();
    }

    #[tokio::test]
    async fn analysis_that_fails_once_defers_the_delete_one_cycle() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().fail_once("analysis a", DeviceError::Unreachable);
        let o = r.run(PLENTY).await;
        let c = r.row("a").unwrap();
        assert_eq!((c.state, c.analysis_tries), (State::Archived, 1));
        assert!(
            r.deleted().is_empty(),
            "deleted before the analysis was saved"
        );
        assert!(r.fake().has("a"));
        assert_eq!((o.pulled, o.deleted, o.backlog), (1, 0, 1));

        let from = r.fake().log().len();
        let o = r.run(PLENTY).await;
        assert_eq!(
            r.log_since(from),
            [
                "finished",
                "device_sha256 a",
                "analysis a",
                "device_sha256 a",
                "delete a"
            ]
        );
        assert_eq!(
            std::fs::read(r.archive.join("a-1700000000.ndjson")).unwrap(),
            b"analysis of a\n"
        );
        assert_eq!(r.row("a").unwrap().state, State::DeletedOnDevice);
        assert_eq!((o.pulled, o.deleted, o.backlog), (0, 1, 0));
        r.assert_safe();
    }

    /// A broken analysis endpoint must not fill the unit: three tries (one per cycle,
    /// counted in the index so restarts don't reset them), then the delete goes out.
    #[tokio::test]
    async fn analysis_that_keeps_failing_delays_the_delete_three_cycles_only() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().fail("analysis a", DeviceError::NotFound);
        for n in 1..=3 {
            r.run(PLENTY).await;
            let c = r.row("a").unwrap();
            assert_eq!(
                (c.state, c.analysis_tries),
                (State::Archived, n),
                "cycle {n}"
            );
            assert!(r.deleted().is_empty(), "cycle {n}");
        }
        let from = r.fake().log().len();
        let o = r.run(PLENTY).await;
        assert_eq!(
            r.log_since(from),
            ["finished", "device_sha256 a", "delete a"]
        );
        assert_eq!(r.row("a").unwrap().state, State::DeletedOnDevice);
        assert!(!r.archive.join("a-1700000000.ndjson").exists());
        assert_eq!(o.deleted, 1);
        r.assert_safe();
    }

    /// The analysis retry for an old row must not save another boot's analysis: it is
    /// only fetched while the unit still holds the archived bytes under the name.
    #[tokio::test]
    async fn analysis_retry_needs_the_unit_to_still_hold_the_same_bytes() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().fail_once("analysis a", DeviceError::Unreachable);
        r.run(PLENTY).await;
        r.fake().add_current("a", b"another boot");
        let from = r.fake().log().len();
        r.run(PLENTY).await;
        assert_eq!(r.log_since(from), ["finished", "device_sha256 a"]);
        assert!(!r.archive.join("a-1700000000.ndjson").exists());
        assert!(r.deleted().is_empty());
        r.assert_safe();
    }

    #[tokio::test]
    async fn unreachable_changes_nothing() {
        let mut r = Rig::new();
        r.seed_archived("old");
        r.fake().add("a", &bytes("a"));
        r.fake().fail("finished", DeviceError::Unreachable);
        let o = r.run(PLENTY).await;
        assert_eq!(r.fake().log(), ["finished"]);
        assert!(!o.reached_device);
        assert_eq!(r.row("a"), None);
        assert_eq!(r.row("old").unwrap().state, State::Archived);
        assert!(r.fake().has("a") && r.fake().has("old"));
        r.assert_safe();
    }

    #[tokio::test]
    async fn interrupted_download_leaves_no_row_no_delete_and_temp_is_cleared() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().fail_once("download a", DeviceError::Unreachable);
        r.dev.partial.lock().unwrap().insert("a".into());
        let o = r.run(PLENTY).await;
        assert_eq!(r.row("a"), None);
        assert!(r.deleted().is_empty());
        assert!(r.fake().has("a"));
        assert!(!r.file("a").exists());
        assert_eq!((o.pulled, o.backlog), (0, 1));
        r.assert_safe();

        // Next cycle: the device is unreachable, but the temp dir is still cleared.
        r.fake().fail_once("finished", DeviceError::Unreachable);
        r.run(PLENTY).await;
        assert!(r.tmp_is_empty());

        // And the one after pulls it properly.
        let o = r.run(PLENTY).await;
        assert_eq!(r.row("a").unwrap().state, State::DeletedOnDevice);
        assert_eq!(gunzip(&r.file("a")), bytes("a"));
        assert_eq!((o.pulled, o.deleted, o.backlog), (1, 1, 0));
        r.assert_safe();
    }

    #[tokio::test]
    async fn mismatch_never_deletes_retries_once_then_flags() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().set_device_hash("a", WRONG);

        let o = r.run(PLENTY).await;
        let c = r.row("a").unwrap();
        assert_eq!(
            (c.state, c.mismatch_tries, c.flagged),
            (State::Mismatch, 1, false)
        );
        assert_eq!(c.local_sha256, None);
        assert_eq!(
            gunzip(&r.archive.join("mismatch/a-1700000000.1.qmdl.gz")),
            bytes("a")
        );
        assert!(!r.file("a").exists());
        assert_eq!((o.mismatches, o.pulled, o.deleted, o.backlog), (1, 0, 0, 1));

        let from = r.fake().log().len();
        let o = r.run(PLENTY).await;
        assert_eq!(
            r.log_since(from),
            ["finished", "download a", "device_sha256 a"]
        );
        let c = r.row("a").unwrap();
        assert_eq!(
            (c.state, c.mismatch_tries, c.flagged),
            (State::Mismatch, 2, true)
        );
        assert!(r.archive.join("mismatch/a-1700000000.2.qmdl.gz").exists());
        assert_eq!((o.mismatches, o.backlog), (1, 0)); // flagged: no longer backlog

        let from = r.fake().log().len();
        let o = r.run(PLENTY).await;
        assert_eq!(r.log_since(from), ["finished"]);
        assert_eq!(o.mismatches, 0);
        assert_eq!(r.row("a").unwrap().mismatch_tries, 2);

        assert!(r.deleted().is_empty());
        assert!(r.fake().has("a"));
        assert_eq!(r.store.mismatch_total(DEV).unwrap(), 2);
        r.assert_safe();
    }

    #[tokio::test]
    async fn mismatch_then_match_upgrades_and_deletes() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().set_device_hash("a", WRONG);
        r.run(PLENTY).await;
        r.fake().set_device_hash("a", &sha(&bytes("a")));
        let o = r.run(PLENTY).await;
        let c = r.row("a").unwrap();
        assert_eq!((c.state, c.mismatch_tries), (State::DeletedOnDevice, 1));
        assert_eq!(gunzip(&r.file("a")), bytes("a"));
        assert_eq!((o.pulled, o.deleted), (1, 1));
        r.assert_safe();
    }

    #[tokio::test]
    async fn garbage_device_hash_is_a_mismatch() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake()
            .fail("device_sha256 a", DeviceError::Bad("not hex".into()));
        let o = r.run(PLENTY).await;
        assert_eq!(r.row("a").unwrap().state, State::Mismatch);
        assert_eq!(o.mismatches, 1);
        assert!(r.deleted().is_empty());
        r.assert_safe();
    }

    #[tokio::test]
    async fn hash_unavailable_is_retried_not_counted() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake()
            .fail_once("device_sha256 a", DeviceError::Unreachable);
        let o = r.run(PLENTY).await;
        assert_eq!(r.row("a"), None);
        assert_eq!((o.mismatches, o.backlog), (0, 1));
        assert!(r.deleted().is_empty());
        let o = r.run(PLENTY).await;
        assert_eq!(r.row("a").unwrap().state, State::DeletedOnDevice);
        assert_eq!(o.deleted, 1);
        r.assert_safe();
    }

    #[tokio::test]
    async fn failed_delete_stays_archived_and_only_the_delete_is_retried() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().fail_once("delete a", DeviceError::Unreachable);
        let o = r.run(PLENTY).await;
        assert_eq!(r.row("a").unwrap().state, State::Archived);
        assert!(r.fake().has("a"));
        assert_eq!((o.pulled, o.deleted, o.backlog), (1, 0, 1));

        let from = r.fake().log().len();
        let o = r.run(PLENTY).await;
        assert_eq!(
            r.log_since(from),
            ["finished", "device_sha256 a", "delete a"]
        );
        assert_eq!(r.row("a").unwrap().state, State::DeletedOnDevice);
        assert_eq!((o.pulled, o.deleted, o.backlog), (0, 1, 0));
        r.assert_safe();
    }

    #[tokio::test]
    async fn delete_not_found_means_gone() {
        let mut r = Rig::new();
        r.seed_archived("a");
        r.fake().fail("delete a", DeviceError::NotFound);
        let o = r.run(PLENTY).await;
        assert_eq!(r.row("a").unwrap().state, State::DeletedOnDevice);
        assert_eq!(o.backlog, 0);
        r.assert_safe();
    }

    #[tokio::test]
    async fn not_found_is_missing_and_never_retried() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().fail("download a", DeviceError::NotFound);
        let o = r.run(PLENTY).await;
        let c = r.row("a").unwrap();
        assert_eq!(c.state, State::MissingOnDevice);
        assert_eq!(c.local_sha256, None);
        assert_eq!((o.missing, o.backlog), (1, 0));
        let from = r.fake().log().len();
        let o = r.run(PLENTY).await;
        assert_eq!(r.log_since(from), ["finished"]);
        assert_eq!(o.missing, 0);
        assert!(r.deleted().is_empty());
        r.assert_safe();
    }

    #[tokio::test]
    async fn low_disk_pulls_nothing_but_pending_delete_goes_out() {
        let mut r = Rig::new();
        r.seed_archived("old");
        r.fake().add("new", &bytes("new"));
        let o = r.run(MIN_FREE_BYTES - 1).await;
        assert_eq!(
            r.fake().log(),
            ["finished", "device_sha256 old", "delete old"]
        );
        assert_eq!(r.row("old").unwrap().state, State::DeletedOnDevice);
        assert_eq!(r.row("new"), None);
        assert!(r.fake().has("new"));
        assert_eq!((o.pulled, o.deleted, o.backlog), (0, 1, 1));
        assert_eq!(
            o.oldest_backlog,
            Some(DateTime::from_timestamp(1_700_000_000, 0).unwrap())
        );
        r.assert_safe();
    }

    #[tokio::test]
    async fn low_disk_does_not_retry_mismatches_either() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().set_device_hash("a", WRONG);
        r.run(PLENTY).await;
        let from = r.fake().log().len();
        r.run(MIN_FREE_BYTES - 1).await;
        assert_eq!(r.log_since(from), ["finished"]);
        assert_eq!(r.row("a").unwrap().mismatch_tries, 1);
        r.assert_safe();
    }

    #[tokio::test]
    async fn current_recording_is_never_touched() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.fake().add_current("cur", &bytes("cur"));
        r.run(PLENTY).await;
        r.run(PLENTY).await;
        assert!(r.fake().log().iter().all(|l| !l.contains("cur")));
        assert!(r.fake().has("cur"));
        assert_eq!(r.row("cur"), None);
        r.assert_safe();
    }

    #[tokio::test]
    async fn restart_mid_cycle_clears_temp_and_retries_only_the_delete() {
        let mut r = Rig::new();
        r.seed_archived("a");
        std::fs::create_dir_all(r.tmp()).unwrap();
        std::fs::write(r.tmp().join("a.qmdl.gz.part"), b"half").unwrap();
        std::fs::write(r.tmp().join("b.qmdl.gz"), b"half").unwrap();
        let o = r.run(PLENTY).await;
        assert!(r.tmp_is_empty());
        assert_eq!(r.fake().log(), ["finished", "device_sha256 a", "delete a"]);
        assert_eq!(r.row("a").unwrap().state, State::DeletedOnDevice);
        assert_eq!((o.pulled, o.deleted), (0, 1));
        r.assert_safe();
    }

    #[tokio::test]
    async fn archived_row_without_its_file_is_never_deleted() {
        // e.g. the index came back from an HA backup but /data/archive (excluded) did not.
        let mut r = Rig::new();
        r.seed_archived("a");
        r.seed_archived("b");
        std::fs::remove_file(r.file("a")).unwrap();
        std::fs::write(r.file("b"), gz(b"other bytes")).unwrap();
        let o = r.run(PLENTY).await;
        assert!(r.deleted().is_empty());
        assert!(r.fake().has("a") && r.fake().has("b"));
        assert_eq!(r.row("a").unwrap().state, State::Archived);
        assert_eq!(r.row("b").unwrap().state, State::Archived);
        assert_eq!((o.deleted, o.backlog), (0, 2));
        r.assert_safe();
    }

    #[tokio::test]
    async fn unsafe_names_are_not_touched() {
        let r = Rig::new();
        r.fake().add("../escape", &bytes("x"));
        r.fake().add(".hidden", &bytes("y"));
        let o = r.run(PLENTY).await;
        assert_eq!(r.fake().log(), ["finished"]);
        assert_eq!(o.backlog, 0);
        r.assert_safe();
    }

    /// The only copy of a capture that vanished from the unit must survive a failed
    /// move into mismatch/: no row is written for a file that isn't there, and the
    /// next cycles' .tmp clean-up moves it into mismatch/ instead of wiping it.
    #[tokio::test]
    async fn unverified_copy_survives_a_failed_move() {
        use std::os::unix::fs::PermissionsExt;
        let r = Rig::new();
        let mm = r.archive.join("mismatch");
        std::fs::create_dir_all(&mm).unwrap();
        std::fs::set_permissions(&mm, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::write(mm.join("probe"), b"x").is_ok() {
            return; // running as root: permissions not enforced
        }
        r.fake().add("a", &bytes("a"));
        r.dev.vanish.lock().unwrap().insert("a".into());
        let o = r.run(PLENTY).await;
        assert_eq!(
            r.row("a"),
            None,
            "a row for a copy that is not in mismatch/"
        );
        assert_eq!(o.missing, 0);
        let in_tmp = r.tmp().join("a-1700000000.unverified.qmdl.gz");
        assert_eq!(gunzip(&in_tmp), bytes("a"));

        // mismatch/ still unwritable: the clean-up must not wipe it.
        r.run(PLENTY).await;
        assert_eq!(gunzip(&in_tmp), bytes("a"));

        std::fs::set_permissions(&mm, std::fs::Permissions::from_mode(0o700)).unwrap();
        r.run(PLENTY).await;
        assert_eq!(
            gunzip(&mm.join("a-1700000000.unverified.qmdl.gz")),
            bytes("a")
        );
        assert!(r.tmp_is_empty());
        assert!(r.deleted().is_empty());
        r.assert_safe();
    }

    #[test]
    fn tmp_cleanup_rescues_unverified_files_without_overwriting() {
        let d = tempfile::tempdir().unwrap();
        let (tmp, mm) = (d.path().join(".tmp"), d.path().join("mismatch"));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(&mm).unwrap();
        std::fs::write(tmp.join("x-1.unverified.qmdl.gz"), b"rescued").unwrap();
        std::fs::write(tmp.join("x.qmdl.gz"), b"junk").unwrap();
        std::fs::write(tmp.join("x.qmdl.gz.part"), b"junk").unwrap();
        std::fs::write(mm.join("x-1.unverified.qmdl.gz"), b"earlier").unwrap();
        clean_tmp(&tmp, &mm);
        assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
        assert_eq!(
            std::fs::read(mm.join("x-1.unverified.qmdl.gz")).unwrap(),
            b"earlier"
        );
        assert_eq!(
            std::fs::read(mm.join("x-1.unverified.2.qmdl.gz")).unwrap(),
            b"rescued"
        );
    }

    #[tokio::test]
    async fn capture_vanishing_before_its_hash_keeps_the_unverified_copy() {
        let r = Rig::new();
        r.fake().add("a", &bytes("a"));
        r.dev.vanish.lock().unwrap().insert("a".into());
        // A file from an earlier vanish must not be overwritten.
        std::fs::create_dir_all(r.archive.join("mismatch")).unwrap();
        let earlier = r.archive.join("mismatch/a-1700000000.unverified.qmdl.gz");
        std::fs::write(&earlier, b"earlier").unwrap();
        let o = r.run(PLENTY).await;
        assert_eq!(
            r.fake().log(),
            ["finished", "download a", "device_sha256 a"]
        );
        assert_eq!(std::fs::read(&earlier).unwrap(), b"earlier");
        let kept = r.archive.join("mismatch/a-1700000000.unverified.2.qmdl.gz");
        assert_eq!(gunzip(&kept), bytes("a"));
        let c = r.row("a").unwrap();
        assert_eq!(c.state, State::MissingOnDevice);
        assert!(c.flagged);
        assert_eq!(c.local_sha256, None);
        assert_eq!((o.missing, o.backlog, o.deleted), (1, 0, 0));
        assert!(r.deleted().is_empty());
        assert!(r.tmp_is_empty());
        r.assert_safe();
    }

    #[tokio::test]
    async fn backlog_counts_new_but_not_flagged_mismatches() {
        let r = Rig::new();
        r.fake().add("bad", &bytes("bad"));
        r.fake().set_device_hash("bad", WRONG);
        r.run(PLENTY).await;
        r.run(PLENTY).await; // bad: tries 2, flagged
        r.fake().add("new", &bytes("new"));
        let o = r.run(MIN_FREE_BYTES - 1).await; // low disk: "new" stays new
        assert!(r.row("bad").unwrap().flagged);
        assert_eq!(r.row("new"), None);
        assert_eq!(o.backlog, 1);
        assert!(o.oldest_backlog.is_some());
        r.assert_safe();
    }

    #[tokio::test]
    async fn already_done_rows_are_skipped() {
        let mut r = Rig::new();
        r.seed_archived("gone");
        let gone = r.row("gone").unwrap();
        r.store
            .set_state(gone.key(), State::DeletedOnDevice)
            .unwrap();
        r.fake().add("miss", &bytes("miss"));
        r.fake().fail_once("download miss", DeviceError::NotFound);
        r.run(PLENTY).await;
        let from = r.fake().log().len();
        let o = r.run(PLENTY).await;
        assert_eq!(r.log_since(from), ["finished"]);
        assert_eq!(o.backlog, 0);
        r.assert_safe();
    }

    /// Gunzipped contents of every archived capture file (archive root only).
    fn archived_payloads(r: &Rig) -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = std::fs::read_dir(&r.archive)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".qmdl.gz"))
            .map(|e| gunzip(&e.path()))
            .collect();
        v.sort();
        v
    }

    /// Pre-sync captures: named from seconds since boot, stamped 1970. Same second.
    fn boot(n: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(31, 0).unwrap() + chrono::Duration::milliseconds(100 * n)
    }

    /// C1: "31" archived, its delete fails; the unit reboots and records a new "31"
    /// (the files under that name are now the new recording). The old row must never
    /// be used to delete it, while it records or after; the new one is its own capture.
    #[tokio::test]
    async fn a_name_reused_after_a_failed_delete_is_never_deleted_by_the_old_row() {
        let r = Rig::new();
        let old = b"first boot".repeat(100);
        let new = b"second boot".repeat(100);
        r.fake().add_at("31", &old, boot(1));
        r.fake().fail_once("delete 31", DeviceError::Unreachable);
        r.run(PLENTY).await;
        assert!(r.deleted().len() == 1 && r.fake().has("31"));

        // Reboot: "31" is now the recording in progress (not listed as finished),
        // but the old manifest entry is still listed.
        r.fake().add_current("31", &new);
        r.run(PLENTY).await;
        r.run(PLENTY).await;
        assert_eq!(
            r.deleted().len(),
            1,
            "the old row deleted the new recording"
        );
        assert_eq!(r.fake().true_sha256("31"), Some(sha(&new)));
        r.assert_safe();

        // It finishes: listed with its own start (same second). Archived as a new
        // capture, beside (never over) the old file, then deleted.
        r.fake().add_at("31", &new, boot(2));
        r.run(PLENTY).await;
        let mut want = vec![old.clone(), new.clone()];
        want.sort();
        assert_eq!(archived_payloads(&r), want);
        assert!(!r.fake().has("31"));
        r.assert_safe();
        // Named {name}-{start seconds}; the second capture in the same second gets a
        // suffix instead of replacing the first file.
        let rows = r.store.by_name(DEV, "31").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].start, boot(1));
        assert_eq!(rows[0].file.as_deref(), Some("31-31"));
        assert_eq!(rows[0].state, State::Archived); // its delete never went out
        assert_eq!(rows[1].file.as_deref(), Some("31-31-2"));
        assert_eq!(rows[1].state, State::DeletedOnDevice);
        assert_eq!(gunzip(&r.archive.join("31-31.qmdl.gz")), old);
        assert_eq!(gunzip(&r.archive.join("31-31-2.qmdl.gz")), new);
    }

    /// After an HA restore the index survives but the archive does not: an old
    /// DeletedOnDevice row still owns stem `31-31` with no files on disk. A new "31"
    /// pulled in the same second must not reuse that stem, or pruning the old row
    /// would delete the new capture's only copy.
    #[tokio::test]
    async fn a_stem_owned_by_a_surviving_row_is_never_reused() {
        let r = Rig::new();
        let new = b"second boot".repeat(100);
        let mut old = Capture {
            device: DEV.into(),
            name: "31".into(),
            state: State::Archived,
            local_sha256: Some(sha(b"gone")),
            device_sha256: Some(sha(b"gone")),
            size: 4,
            start: boot(0),
            last_message: None,
            archived_at: Some(now() - chrono::Duration::days(1)),
            mismatch_tries: 0,
            kept: false,
            flagged: false,
            file: Some("31-31".into()),
            analysis_tries: 0,
        };
        r.store.record_archived(&old).unwrap();
        r.store
            .set_state(old.key(), State::DeletedOnDevice)
            .unwrap();
        old.state = State::DeletedOnDevice;
        assert!(!r.archive.join("31-31.qmdl.gz").exists());

        r.fake().add_at("31", &new, boot(1));
        let o = r.run(PLENTY).await;
        assert_eq!((o.pulled, o.deleted), (1, 1));
        let fresh = r.store.by_name(DEV, "31").unwrap();
        let fresh = fresh.iter().find(|c| c.start == boot(1)).unwrap();
        assert_eq!(fresh.file.as_deref(), Some("31-31-2"));
        assert_eq!(gunzip(&r.archive.join("31-31-2.qmdl.gz")), new);

        // 91 days later the old row expires; the new capture's files stay.
        let later = now() + chrono::Duration::days(90); // old row: 91 days, new: 90
        let n = crate::pruner::prune(&r.store, &r.archive, DEV, later);
        assert_eq!(n, 1);
        assert_eq!(gunzip(&r.archive.join("31-31-2.qmdl.gz")), new);
        assert!(r.archive.join("31-31-2.ndjson").exists());
    }

    #[test]
    fn move_durably_never_replaces_a_file() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::write(&a, b"new").unwrap();
        std::fs::write(&b, b"old").unwrap();
        let e = move_durably(&a, &b).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&b).unwrap(), b"old");
        assert_eq!(std::fs::read(&a).unwrap(), b"new");
        std::fs::remove_file(&b).unwrap();
        move_durably(&a, &b).unwrap();
        assert!(!a.exists());
        assert_eq!(std::fs::read(&b).unwrap(), b"new");
    }

    /// C1: once "31" is DeletedOnDevice, a later "31" (new boot) must still be pulled.
    #[tokio::test]
    async fn a_name_reused_after_its_row_was_deleted_is_pulled() {
        let r = Rig::new();
        let old = b"first boot".repeat(100);
        let new = b"second boot".repeat(100);
        r.fake().add_at("31", &old, boot(1));
        r.run(PLENTY).await;
        assert!(!r.fake().has("31"));
        r.fake().add_at("31", &new, boot(2));
        let o = r.run(PLENTY).await;
        assert_eq!((o.pulled, o.deleted), (1, 1));
        let mut want = vec![old, new];
        want.sort();
        assert_eq!(archived_payloads(&r), want);
        assert!(!r.fake().has("31"));
        r.assert_safe();
    }

    /// C1(d): the unit answers 409 for the recording in progress; no delete.
    #[tokio::test]
    async fn busy_hash_before_delete_means_no_delete() {
        let mut r = Rig::new();
        r.seed_archived("a");
        r.fake().fail("device_sha256 a", DeviceError::Busy);
        let o = r.run(PLENTY).await;
        assert!(r.deleted().is_empty());
        assert!(r.fake().has("a"));
        assert_eq!((o.deleted, o.backlog), (0, 1));
        r.assert_safe();
    }

    /// C1(d): any hash error, or a different hash, right before the delete -> no delete.
    #[tokio::test]
    async fn fresh_hash_error_or_difference_before_delete_means_no_delete() {
        let mut r = Rig::new();
        r.seed_archived("a");
        r.seed_archived("b");
        r.fake()
            .fail_once("device_sha256 a", DeviceError::Unreachable);
        r.fake().set_device_hash("b", WRONG);
        r.run(PLENTY).await;
        assert!(r.deleted().is_empty());
        r.assert_safe();
        // a's error was transient: it goes out next cycle; b never does.
        r.run(PLENTY).await;
        assert_eq!(r.deleted(), ["a"]);
        assert!(r.fake().has("b"));
        r.assert_safe();
    }

    /// Several captures, several faults, several cycles: the rule holds throughout.
    #[tokio::test]
    async fn mixed_cycles_keep_the_safety_rule() {
        let mut r = Rig::new();
        r.seed_archived("s");
        for n in ["a", "b", "c", "d", "e", "f"] {
            r.fake().add(n, &bytes(n));
        }
        r.fake().add_current("cur", &bytes("cur"));
        r.fake().set_device_hash("b", WRONG);
        r.fake().fail_once("download c", DeviceError::Unreachable);
        r.dev.partial.lock().unwrap().insert("c".into());
        r.fake().fail_once("delete d", DeviceError::Busy);
        r.fake().fail("download e", DeviceError::NotFound);
        r.fake()
            .fail_once("device_sha256 f", DeviceError::Bad("junk".into()));
        r.fake().fail_once("delete s", DeviceError::Unreachable);
        for free in [PLENTY, MIN_FREE_BYTES - 1, PLENTY, PLENTY, PLENTY] {
            r.run(free).await;
            r.assert_safe();
        }
        let st = |n| r.row(n).unwrap().state;
        assert_eq!(st("a"), State::DeletedOnDevice);
        assert_eq!(st("b"), State::Mismatch);
        assert_eq!(st("c"), State::DeletedOnDevice);
        assert_eq!(st("d"), State::DeletedOnDevice);
        assert_eq!(st("e"), State::MissingOnDevice);
        assert_eq!(st("f"), State::DeletedOnDevice);
        assert_eq!(st("s"), State::DeletedOnDevice);
        assert!(r.fake().has("b") && r.fake().has("cur"));
        let dels = r.deleted();
        assert_eq!(dels.len(), 7, "{dels:?}"); // s,a,d (s,d failed) | s,d | c,f
    }
}
