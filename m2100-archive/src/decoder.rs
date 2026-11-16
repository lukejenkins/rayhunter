//! Decoding and judging in the cycle: each archived capture is decoded once, after the
//! cycle's pulls, deletes and prune, judged against its profile's baseline, and the
//! counts, findings and learning stored in the index together. Never blocks Phase 1:
//! at most `MAX_PER_CYCLE` captures per cycle, and nothing here can fail the cycle.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};

use crate::checks::{self, Judgement, Level, Profile};
use crate::device::Device;
use crate::events::{Observations, Tally, printable};
use crate::puller::gz_sha256;
use crate::sandbox::{Decoder, GUEST_SHA256, RunEnd};
use crate::store::{Decode, DecodeStatus, Store};

/// Captures decoded per cycle: a backlog clears in a few hours, a cycle stays bounded
/// (each decode may take up to the sandbox's 120 s).
pub const MAX_PER_CYCLE: usize = 3;
/// Cycles a capture is left pending while the profile lookup fails; after this many
/// retries it is decoded as `mobile`.
pub const PROFILE_RETRIES: u32 = 4;
/// Longest `detail` stored.
const DETAIL_MAX: usize = 256;

/// In-memory decode bookkeeping, lost on restart:
/// - how many times each capture has been deferred for want of a profile (a restart
///   only grants a few more tries);
/// - captures whose final verdict could not be stored (`record_judgement` failed): they
///   are not run again until restart, so a bomb cannot cost 3 x 120 s every cycle.
#[derive(Default)]
pub struct ProfileRetries {
    counts: RefCell<HashMap<(String, i64), u32>>,
    unstored: RefCell<HashSet<(String, i64)>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DecodeOutcome {
    pub ok: u32,
    pub failed: u32,
    pub archive_corrupt: u32,
    pub archive_missing: u32,
    /// Left pending for the next cycle (profile lookup down).
    pub deferred: u32,
    /// 2a failure rows judged from their stored status (no sandbox run).
    pub judged_from_status: u32,
    /// Findings at `notify` level this cycle, suppressed (backfill) ones included.
    pub notify: u32,
    /// Each capture whose verdict was stored this cycle, in judging order (for Cribl).
    pub judged: Vec<Judged>,
}

impl DecodeOutcome {
    /// The counters, for the log line (not the per-capture rows).
    pub fn summary(&self) -> String {
        format!(
            "ok {}, failed {}, archive_corrupt {}, archive_missing {}, deferred {}, \
             judged_from_status {}, notify {}",
            self.ok, self.failed, self.archive_corrupt, self.archive_missing, self.deferred,
            self.judged_from_status, self.notify
        )
    }
}

/// One stored verdict as the Cribl output sees it: counts, check ids and levels only.
/// Never a `detail` (it can hold cell identities) and never a tower key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    /// Capture name (untrusted text).
    pub name: String,
    pub status: DecodeStatus,
    pub profile: Profile,
    pub spans_switch: bool,
    pub suppressed: bool,
    pub towers_known: Option<bool>,
    pub frames: u64,
    pub failures: u64,
    /// A count: how many distinct towers, never which.
    pub towers: u64,
    pub identity_requests: u64,
    pub warnings_high: u64,
    pub warnings_other: u64,
    /// (check id, level), in stored order.
    pub findings: Vec<(&'static str, Level)>,
}

impl Judged {
    pub fn new(d: &Decode, j: &Judgement) -> Judged {
        Judged {
            name: d.name.clone(),
            status: d.status,
            profile: j.profile,
            spans_switch: j.spans_switch,
            suppressed: j.suppressed,
            towers_known: j.towers_known,
            frames: d.frames,
            failures: d.failures,
            towers: d.towers,
            identity_requests: d.identity_requests,
            warnings_high: d.warnings_high,
            warnings_other: d.warnings_other,
            findings: j.findings.iter().map(|f| (f.check, f.level)).collect(),
        }
    }
}

/// Guest-controlled text made safe to store: printable ASCII only, at most 256 chars.
pub fn sanitize_detail(s: &str) -> String {
    printable(s, DETAIL_MAX)
}

fn run_end_detail(end: &RunEnd) -> Option<String> {
    match end {
        RunEnd::Finished => None,
        RunEnd::Trapped(s) => Some(format!("guest trapped: {s}")),
        RunEnd::Timeout => Some("guest timed out".into()),
        RunEnd::OutputTooLarge => Some("guest output too large".into()),
        RunEnd::Malformed(s) => Some(format!("malformed output: {s}")),
        RunEnd::Capped(w) => Some(format!("capped: {w}")),
    }
}

/// Judge one capture against what the baselines hold right now (so a capture judged
/// earlier in this cycle has already taught them) and store it all in one transaction.
#[allow(clippy::too_many_arguments)]
fn judge_one(
    store: &Store,
    d: &Decode,
    profile: Profile,
    spans_switch: bool,
    seen: &Observations,
    suppressed: bool,
    now: DateTime<Utc>,
    settings: &checks::Settings,
) -> anyhow::Result<Judgement> {
    // Each step names itself in the error, so the log says which read failed.
    let baseline = store.baseline(profile.as_str(), now).context("baseline")?;
    let prev_identity = store
        .previous_identity(&d.device, profile.as_str(), &d.start)
        .context("previous_identity")?;
    // Spike history: the week before this capture's first synced hour, up to its last.
    let hours: Vec<DateTime<Utc>> = seen
        .failure_hours
        .iter()
        .filter_map(|(h, _, _)| h.as_deref().and_then(checks::parse_ts))
        .filter(|h| checks::synced(*h, now))
        .collect();
    let history = match (hours.iter().min(), hours.iter().max()) {
        (Some(lo), Some(hi)) => store
            .failure_history(
                *lo - Duration::days(checks::SPIKE_WINDOW_DAYS),
                *hi + Duration::hours(1),
            )
            .context("failure_history")?,
        _ => Vec::new(),
    };
    let (findings, learn) = checks::judge(&checks::Input {
        profile,
        status: d.status,
        seen,
        baseline: &baseline,
        prev_identity,
        failure_history: &history,
        now,
        settings,
    });
    let j = Judgement {
        profile,
        findings,
        learn,
        spans_switch,
        suppressed,
        // Against the baseline as it was before this capture teaches it.
        towers_known: checks::towers_known(seen, &baseline),
    };
    // The only production write: `record_decode` would reset `judged` and let the
    // capture learn twice.
    store
        .record_judgement(d, &j, now)
        .context("record_judgement")?;
    Ok(j)
}

/// The `notify` findings of one capture as (check id, how many), in first-seen order:
/// what gets logged, one line per check id however many findings it has.
fn notify_by_check(findings: &[checks::Finding]) -> Vec<(&'static str, usize)> {
    let mut out: Vec<(&'static str, usize)> = Vec::new();
    for f in findings.iter().filter(|f| f.level == Level::Notify) {
        match out.iter_mut().find(|(c, _)| *c == f.check) {
            Some((_, n)) => *n += 1,
            None => out.push((f.check, 1)),
        }
    }
    out
}

/// Decode (if needed) and judge up to `max_per_cycle` unjudged captures, oldest first:
/// new ones, and the 2a backlog (D7: as backfill, `suppressed`).
#[allow(clippy::too_many_arguments)]
pub async fn judge_pending(
    store: &Store,
    decoder: Option<&Arc<dyn Decoder>>,
    dev: &dyn Device,
    device_id: &str,
    archive: &Path,
    max_per_cycle: usize,
    retries: &ProfileRetries,
    now: DateTime<Utc>,
    settings: &checks::Settings,
) -> DecodeOutcome {
    let mut out = DecodeOutcome::default();
    let judged = RefCell::new(Vec::new());
    let Some(decoder) = decoder else {
        log::debug!("no decoder available; nothing judged");
        return out;
    };
    // Ask for enough to see past the captures whose verdict could not be stored.
    let skip = retries.unstored.borrow().len();
    let pending = match store.unjudged(device_id, max_per_cycle + skip) {
        Ok(p) => p
            .into_iter()
            .filter(|(c, _)| {
                !retries
                    .unstored
                    .borrow()
                    .contains(&(c.name.clone(), c.start.timestamp()))
            })
            .take(max_per_cycle)
            .collect::<Vec<_>>(),
        Err(e) => {
            log::error!("unjudged: {e}");
            return out;
        }
    };
    if pending.is_empty() {
        return out;
    }
    // D7: what was archived before judging began is backfill; its findings are kept
    // but must never be notified.
    let epoch = match store.judge_epoch(now) {
        Ok(e) => e,
        Err(e) => {
            log::error!("judge_epoch: {e}");
            return out;
        }
    };
    // Once per cycle; only a failure to ask is an error (a missing name is `mobile`).
    let mut profiles: Option<Result<HashMap<String, String>, ()>> = None;

    for (c, prior) in pending {
        let suppressed = c.archived_at < Some(epoch);
        let decode = |status, profile: Profile, t: &Tally, hash: &str, detail| Decode {
            device: c.device.clone(),
            name: c.name.clone(),
            start: c.start,
            status,
            profile: profile.as_str().to_string(),
            frames: t.frames,
            failures: t.failures,
            towers: t.towers,
            identity_requests: t.identity_requests,
            warnings_high: t.warnings_high,
            warnings_other: t.warnings_other,
            decoder_hash: hash.to_string(),
            decoded_at: now,
            detail,
        };
        // Returns how many `notify` findings it stored.
        let judge = |d: &Decode, profile, spans_switch, seen: &Observations| -> u32 {
            match judge_one(
                store,
                d,
                profile,
                spans_switch,
                seen,
                suppressed,
                now,
                settings,
            ) {
                Ok(j) => {
                    judged.borrow_mut().push(Judged::new(d, &j));
                    let mut total = 0;
                    for (check, n) in notify_by_check(&j.findings) {
                        // The check id only: `detail` can hold cell identities.
                        log::info!(
                            "finding {check} (notify) x{n} in {}{}",
                            c.name,
                            if suppressed { " [backfill]" } else { "" }
                        );
                        total += n as u32;
                    }
                    total
                }
                Err(e) => {
                    // Not stored, so it stays "unjudged": remember it here, or the next
                    // cycle runs the same (possibly hostile) capture again.
                    let first = retries
                        .unstored
                        .borrow_mut()
                        .insert((c.name.clone(), c.start.timestamp()));
                    if first {
                        // `{e:#}` leads with the failed step (baseline, previous_identity,
                        // failure_history or record_judgement).
                        log::error!(
                            "judging {}: {e:#}; not judging it again until restart",
                            c.name
                        );
                    }
                    0
                }
            }
        };
        let none = Tally::default();
        let stored_profile = prior.as_ref().map(|p| Profile::from_stored(&p.profile));

        // A 2a verdict other than `ok` is final: judge it from its status, as stored.
        if let Some(p) = prior.as_ref().filter(|p| p.status != DecodeStatus::Ok) {
            let profile = Profile::from_stored(&p.profile);
            out.notify += judge(p, profile, false, &Observations::default());
            out.judged_from_status += 1;
            continue;
        }

        // (1)+(2): the archive copy must exist and still be the verified bytes.
        let Some(stem) = c.file.clone() else { continue };
        let file = archive.join(format!("{stem}.qmdl.gz"));
        let hashed = tokio::task::spawn_blocking({
            let file = file.clone();
            move || gz_sha256(&file)
        })
        .await;
        let lost = stored_profile.unwrap_or(Profile::Mobile);
        match hashed {
            Ok(Ok(h)) if Some(&h) == c.local_sha256.as_ref() => {}
            // Transient trouble (not NotFound, not a corrupt stream, or the task
            // itself failed) decides nothing: no row, no `unstored` entry; the
            // capture is retried next cycle.
            Ok(Err(e))
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::InvalidData
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::InvalidInput
                ) =>
            {
                log::warn!("decode {}: cannot re-hash the archive copy: {e}", c.name);
                continue;
            }
            Err(e) => {
                log::warn!("decode {}: re-hash task failed: {e}", c.name);
                continue;
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                log::warn!(
                    "decode {}: archive copy {} is missing",
                    c.name,
                    file.display()
                );
                let d = decode(
                    DecodeStatus::ArchiveMissing,
                    lost,
                    &none,
                    "",
                    Some("archive copy missing".into()),
                );
                out.notify += judge(&d, lost, false, &Observations::default());
                out.archive_missing += 1;
                continue;
            }
            other => {
                log::warn!(
                    "decode {}: archive copy is not the verified bytes ({other:?})",
                    c.name
                );
                let d = decode(
                    DecodeStatus::ArchiveCorrupt,
                    lost,
                    &none,
                    "",
                    Some("archive copy does not match its recorded hash".into()),
                );
                out.notify += judge(&d, lost, false, &Observations::default());
                out.archive_corrupt += 1;
                continue;
            }
        }

        // (3): the profile it was recorded in. A 2a `ok` row already says; otherwise
        // ask the unit. `mixed` is judged as mobile and marked (D5).
        let (profile, spans_switch) = if let Some(p) = stored_profile {
            (p, false)
        } else {
            if profiles.is_none() {
                profiles = Some(match dev.capture_profiles().await {
                    Ok(m) => Ok(m),
                    Err(e) => {
                        log::warn!("capture profiles unavailable: {e:?}");
                        Err(())
                    }
                });
            }
            match profiles.as_ref().unwrap() {
                Ok(m) => match m.get(&c.name).map(String::as_str) {
                    Some("fixed") => (Profile::Fixed, false),
                    Some("mixed") => (Profile::Mobile, true),
                    _ => (Profile::Mobile, false),
                },
                Err(()) => {
                    let key = (c.name.clone(), c.start.timestamp());
                    let n = {
                        let mut r = retries.counts.borrow_mut();
                        let n = r.entry(key.clone()).or_insert(0);
                        *n += 1;
                        *n
                    };
                    if n <= PROFILE_RETRIES {
                        out.deferred += 1;
                        continue; // stays pending
                    }
                    retries.counts.borrow_mut().remove(&key);
                    (Profile::Mobile, false)
                }
            }
        };

        // (4): the sandbox, off the async thread (it blocks for up to 120 s).
        let ran = tokio::task::spawn_blocking({
            let (d, file) = (decoder.clone(), file.clone());
            move || d.run(&file)
        })
        .await;
        let (tally, end) = match ran {
            Ok(r) => r,
            Err(e) => (
                Tally::default(),
                RunEnd::Trapped(format!("host: decoder panicked: {e}")),
            ),
        };
        match run_end_detail(&end) {
            None => {
                let d = decode(DecodeStatus::Ok, profile, &tally, GUEST_SHA256, None);
                out.notify += judge(&d, profile, spans_switch, &tally.seen);
                out.ok += 1;
            }
            Some(detail) => {
                log::warn!("decode {}: {}", c.name, sanitize_detail(&detail));
                let d = decode(
                    DecodeStatus::DecoderFailure,
                    profile,
                    &tally,
                    GUEST_SHA256,
                    Some(sanitize_detail(&detail)),
                );
                out.notify += judge(&d, profile, spans_switch, &tally.seen);
                out.failed += 1;
            }
        }
    }
    out.judged = judged.into_inner();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceError, Fake};
    use crate::store::{Capture, State};
    use chrono::DateTime;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::sync::Mutex;

    const DEV: &str = "unit1";

    struct FakeDecoder {
        calls: Mutex<Vec<String>>,
        result: Mutex<(Tally, RunEnd)>,
        panic: bool,
    }
    impl FakeDecoder {
        fn new(t: Tally, e: RunEnd) -> Arc<Self> {
            Arc::new(FakeDecoder {
                calls: Default::default(),
                result: Mutex::new((t, e)),
                panic: false,
            })
        }
        fn ok() -> Arc<Self> {
            Self::new(
                Tally {
                    frames: 100,
                    failures: 2,
                    towers: 3,
                    identity_requests: 1,
                    warnings_high: 1,
                    warnings_other: 4,
                    capped: None,
                    ..Default::default()
                },
                RunEnd::Finished,
            )
        }
        fn calls(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }
    impl Decoder for FakeDecoder {
        fn run(&self, p: &Path) -> (Tally, RunEnd) {
            self.calls.lock().unwrap().push(p.display().to_string());
            if self.panic {
                panic!("sandbox exploded");
            }
            self.result.lock().unwrap().clone()
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        archive: std::path::PathBuf,
        store: Store,
        dev: Fake,
        retries: ProfileRetries,
        settings: checks::Settings,
    }
    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive");
        std::fs::create_dir_all(&archive).unwrap();
        let store = Store::open(&dir.path().join("i.sqlite")).unwrap();
        Rig {
            _dir: dir,
            archive,
            store,
            dev: Fake::new(),
            retries: Default::default(),
            settings: Default::default(),
        }
    }
    fn sha(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    }
    impl Rig {
        /// An archived capture `name` with a real gz file (unless `write` is false).
        fn seed(&self, name: &str, age: i64, write: bool) {
            let body = format!("capture {name}").into_bytes();
            let stem = format!("{name}-1700000000");
            if write {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                e.write_all(&body).unwrap();
                std::fs::write(
                    self.archive.join(format!("{stem}.qmdl.gz")),
                    e.finish().unwrap(),
                )
                .unwrap();
            }
            let h = sha(&body);
            self.store
                .record_archived(&Capture {
                    device: DEV.into(),
                    name: name.into(),
                    state: State::Archived,
                    local_sha256: Some(h.clone()),
                    device_sha256: Some(h),
                    size: body.len() as u64,
                    start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                    last_message: None,
                    archived_at: Some(DateTime::from_timestamp(1_700_000_000 + age, 0).unwrap()),
                    mismatch_tries: 0,
                    kept: false,
                    flagged: false,
                    file: Some(stem),
                    analysis_tries: 0,
                })
                .unwrap();
        }
        fn decode_of(&self, name: &str) -> Option<Decode> {
            let c = self.store.by_name(DEV, name).unwrap().remove(0);
            self.store.get_decode(c.key()).unwrap()
        }
        async fn run(&self, d: Option<&Arc<dyn Decoder>>, max: usize) -> DecodeOutcome {
            judge_pending(
                &self.store,
                d,
                &self.dev,
                DEV,
                &self.archive,
                max,
                &self.retries,
                now(),
                &self.settings,
            )
            .await
        }
    }
    fn dynd(d: &Arc<FakeDecoder>) -> Arc<dyn Decoder> {
        d.clone()
    }
    /// The cycle's clock: long after the rig's captures were archived (2023).
    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[tokio::test]
    async fn happy_path_stores_ok_counts_and_the_devices_profile() {
        let r = rig();
        r.seed("a", 0, true);
        r.dev.set_profile("a", "fixed");
        let d = FakeDecoder::ok();
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.ok, 1);
        let x = r.decode_of("a").unwrap();
        assert_eq!(x.status, DecodeStatus::Ok);
        assert_eq!(x.profile, "fixed");
        assert_eq!(
            (x.frames, x.failures, x.towers, x.identity_requests),
            (100, 2, 3, 1)
        );
        assert_eq!((x.warnings_high, x.warnings_other), (1, 4));
        assert_eq!(x.decoder_hash, GUEST_SHA256);
        assert_eq!(x.detail, None);
        // decoded once: a second cycle does nothing
        r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(d.calls(), 1);
    }

    #[tokio::test]
    async fn mixed_and_missing_profiles_are_stored_as_mobile() {
        let r = rig();
        r.seed("a", 0, true);
        r.seed("b", 1, true);
        r.dev.set_profile("a", "mixed");
        let d = FakeDecoder::ok();
        r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(r.decode_of("a").unwrap().profile, "mobile");
        assert_eq!(r.decode_of("b").unwrap().profile, "mobile");
    }

    #[tokio::test]
    async fn missing_archive_file_is_archive_missing_once() {
        let r = rig();
        r.seed("a", 0, false);
        let d = FakeDecoder::ok();
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.archive_missing, 1);
        let x = r.decode_of("a").unwrap();
        assert_eq!(x.status, DecodeStatus::ArchiveMissing);
        assert_eq!(d.calls(), 0);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o, DecodeOutcome::default(), "no retry storm");
    }

    #[tokio::test]
    async fn corrupt_copy_is_archive_corrupt_and_never_reaches_the_sandbox() {
        let r = rig();
        r.seed("a", 0, true);
        // flip the copy to other (valid gzip) bytes
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(b"tampered").unwrap();
        std::fs::write(r.archive.join("a-1700000000.qmdl.gz"), e.finish().unwrap()).unwrap();
        r.seed("b", 1, true);
        std::fs::write(r.archive.join("b-1700000000.qmdl.gz"), b"not gzip at all").unwrap();
        let d = FakeDecoder::ok();
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.archive_corrupt, 2);
        assert_eq!(
            r.decode_of("a").unwrap().status,
            DecodeStatus::ArchiveCorrupt
        );
        assert_eq!(
            r.decode_of("b").unwrap().status,
            DecodeStatus::ArchiveCorrupt
        );
        assert_eq!(d.calls(), 0);
    }

    #[tokio::test]
    async fn guest_failure_is_recorded_once_with_partial_counts_and_not_retried() {
        let r = rig();
        r.seed("a", 0, true);
        let d = FakeDecoder::new(
            Tally {
                frames: 7,
                towers: 2,
                ..Default::default()
            },
            RunEnd::Trapped("unreachable \u{1b}[31m\u{e9}".into()),
        );
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.failed, 1);
        let x = r.decode_of("a").unwrap();
        assert_eq!(x.status, DecodeStatus::DecoderFailure);
        assert_eq!((x.frames, x.towers), (7, 2));
        let detail = x.detail.unwrap();
        assert!(detail.contains("unreachable"));
        assert!(
            detail.chars().all(|c| (' '..='~').contains(&c)),
            "{detail:?}"
        );
        for _ in 0..3 {
            r.run(Some(&dynd(&d)), 3).await;
        }
        assert_eq!(d.calls(), 1, "a failing capture must not be retried");
    }

    #[test]
    fn detail_is_truncated_and_ascii_printable() {
        let s = sanitize_detail(&format!("{}\n\0\u{202e}x", "a".repeat(400)));
        assert_eq!(s.len(), 256);
        assert!(
            sanitize_detail("a\nb\u{202e}c")
                .chars()
                .all(|c| (' '..='~').contains(&c))
        );
        assert_eq!(sanitize_detail("ok"), "ok");
    }

    #[tokio::test]
    async fn profile_endpoint_down_defers_then_decodes_as_mobile_after_the_retries() {
        let r = rig();
        r.seed("a", 0, true);
        r.dev.fail("capture_profiles", DeviceError::Unreachable);
        let d = FakeDecoder::ok();
        for cycle in 1..=PROFILE_RETRIES {
            let o = r.run(Some(&dynd(&d)), 3).await;
            assert_eq!(o.deferred, 1, "cycle {cycle}");
            assert!(
                r.decode_of("a").is_none(),
                "cycle {cycle} must leave it pending"
            );
        }
        assert_eq!(d.calls(), 0);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.ok, 1);
        let x = r.decode_of("a").unwrap();
        assert_eq!((x.status, x.profile.as_str()), (DecodeStatus::Ok, "mobile"));
        assert_eq!(d.calls(), 1);
    }

    #[tokio::test]
    async fn profile_endpoint_recovering_uses_the_real_profile() {
        let r = rig();
        r.seed("a", 0, true);
        r.dev.set_profile("a", "fixed");
        r.dev
            .fail_once("capture_profiles", DeviceError::Unreachable);
        let d = FakeDecoder::ok();
        assert_eq!(r.run(Some(&dynd(&d)), 3).await.deferred, 1);
        assert_eq!(r.run(Some(&dynd(&d)), 3).await.ok, 1);
        assert_eq!(r.decode_of("a").unwrap().profile, "fixed");
    }

    #[tokio::test]
    async fn at_most_max_per_cycle_oldest_first_and_profiles_fetched_once() {
        let r = rig();
        for (i, n) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            r.seed(n, i as i64, true);
        }
        let d = FakeDecoder::ok();
        assert_eq!(r.run(Some(&dynd(&d)), 3).await.ok, 3);
        assert_eq!(d.calls(), 3);
        assert!(r.decode_of("c").is_some() && r.decode_of("d").is_none());
        assert_eq!(
            r.dev
                .log()
                .iter()
                .filter(|l| *l == "capture_profiles")
                .count(),
            1
        );
        assert_eq!(r.run(Some(&dynd(&d)), 3).await.ok, 2);
    }

    #[tokio::test]
    async fn no_decoder_decodes_nothing_and_does_not_touch_the_device() {
        let r = rig();
        r.seed("a", 0, true);
        let o = r.run(None, 3).await;
        assert_eq!(o, DecodeOutcome::default());
        assert!(r.decode_of("a").is_none());
        assert!(r.dev.log().is_empty());
    }

    #[tokio::test]
    async fn a_panicking_sandbox_is_one_decoder_failure_and_the_next_capture_still_runs() {
        let r = rig();
        r.seed("a", 0, true);
        let d = Arc::new(FakeDecoder {
            calls: Default::default(),
            result: Mutex::new((Tally::default(), RunEnd::Finished)),
            panic: true,
        });
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.failed, 1);
        assert_eq!(
            r.decode_of("a").unwrap().status,
            DecodeStatus::DecoderFailure
        );
    }

    #[tokio::test]
    async fn a_capped_capture_is_one_decoder_failure_with_partial_counts_never_retried() {
        let r = rig();
        r.seed("a", 0, true);
        let d = FakeDecoder::new(
            Tally {
                frames: 5000,
                towers: 4,
                capped: Some("events".into()),
                ..Default::default()
            },
            RunEnd::Capped("events".into()),
        );
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!((o.ok, o.failed), (0, 1));
        let x = r.decode_of("a").unwrap();
        assert_eq!(x.status, DecodeStatus::DecoderFailure);
        assert_eq!((x.frames, x.towers), (5000, 4));
        assert_eq!(x.detail.as_deref(), Some("capped: events"));
        for _ in 0..3 {
            r.run(Some(&dynd(&d)), 3).await;
        }
        assert_eq!(d.calls(), 1, "a capped capture must not be retried");
    }

    /// Make every insert into `decodes` fail, as a full disk or a locked file would.
    fn break_record_decode(r: &Rig) {
        let c = rusqlite::Connection::open(r._dir.path().join("i.sqlite")).unwrap();
        c.execute_batch(
            "CREATE TRIGGER no_decodes BEFORE INSERT ON decodes
             BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn a_verdict_that_cannot_be_stored_is_not_rerun_every_cycle() {
        let r = rig();
        r.seed("a", 0, true);
        break_record_decode(&r);
        let d = FakeDecoder::new(Tally::default(), RunEnd::Trapped("bomb".into()));
        r.run(Some(&dynd(&d)), 3).await;
        r.run(Some(&dynd(&d)), 3).await;
        r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(d.calls(), 1, "re-run despite an unstorable verdict");
        assert!(r.decode_of("a").is_none());
    }

    #[tokio::test]
    async fn an_unstored_capture_does_not_starve_the_ones_behind_it() {
        let r = rig();
        r.seed("a", 0, true);
        r.seed("b", 1, true);
        break_record_decode(&r);
        let d = FakeDecoder::ok();
        // max 1 per cycle: cycle 1 runs a (unstorable), cycle 2 must reach b
        r.run(Some(&dynd(&d)), 1).await;
        r.run(Some(&dynd(&d)), 1).await;
        assert_eq!(d.calls(), 2);
    }

    #[tokio::test]
    async fn a_transient_rehash_error_leaves_the_capture_pending_and_retried() {
        let r = rig();
        r.seed("a", 0, false);
        // a directory where the file should be: opens, then fails to read (EISDIR)
        let p = r.archive.join("a-1700000000.qmdl.gz");
        std::fs::create_dir(&p).unwrap();
        let d = FakeDecoder::ok();
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o, DecodeOutcome::default());
        assert!(
            r.decode_of("a").is_none(),
            "no verdict from a transient error"
        );
        assert_eq!(d.calls(), 0);
        // it clears: the capture is then decoded, not blocked by any memory
        std::fs::remove_dir(&p).unwrap();
        std::fs::copy(
            {
                r.seed("tmp", 99, true);
                r.archive.join("tmp-1700000000.qmdl.gz")
            },
            &p,
        )
        .unwrap();
        // the copy holds "capture tmp", not "capture a": hash mismatch is a verdict
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.archive_corrupt, 1);
    }

    #[tokio::test]
    async fn a_truncated_gzip_is_archive_corrupt() {
        let r = rig();
        r.seed("a", 0, true);
        let p = r.archive.join("a-1700000000.qmdl.gz");
        let b = std::fs::read(&p).unwrap();
        std::fs::write(&p, &b[..b.len() - 12]).unwrap();
        let d = FakeDecoder::ok();
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.archive_corrupt, 1);
        assert_eq!(d.calls(), 0);
    }

    // ---- judging (2b) ----

    use crate::events::{Observations, Severity, Strength, TowerSeen, WarningSeen};

    fn tower(key: &str) -> TowerSeen {
        TowerSeen {
            key: key.into(),
            strength: Strength::Sib1,
            ts: None,
        }
    }
    fn high() -> WarningSeen {
        WarningSeen {
            severity: Severity::High,
            analyzer: "An".into(),
            msg: "m".into(),
            ts: None,
        }
    }
    fn seen(towers: &[&str], warnings: Vec<WarningSeen>) -> Tally {
        Tally {
            frames: 100,
            towers: towers.len() as u64,
            seen: Observations {
                towers: towers.iter().map(|k| tower(k)).collect(),
                warnings,
                ..Default::default()
            },
            ..Default::default()
        }
    }
    impl Rig {
        fn findings_of(&self, name: &str) -> Vec<(String, String, bool, bool, String)> {
            let c = self.store.by_name(DEV, name).unwrap().remove(0);
            self.store.findings(c.key()).unwrap()
        }
        fn checks_of(&self, name: &str) -> Vec<String> {
            self.findings_of(name).into_iter().map(|f| f.0).collect()
        }
        fn capture(&self, name: &str) -> Capture {
            self.store.by_name(DEV, name).unwrap().remove(0)
        }
        /// A 2a row: decoded, never judged (`judged` = 0).
        fn decode_2a(&self, name: &str, status: DecodeStatus, profile: &str) {
            let c = self.capture(name);
            self.store
                .record_decode(&Decode {
                    device: c.device.clone(),
                    name: c.name.clone(),
                    start: c.start,
                    status,
                    profile: profile.into(),
                    frames: 9,
                    failures: 0,
                    towers: 0,
                    identity_requests: 0,
                    warnings_high: 0,
                    warnings_other: 0,
                    decoder_hash: GUEST_SHA256.into(),
                    decoded_at: now(),
                    detail: Some("2a said so".into()),
                })
                .unwrap();
        }
        fn towers_learned(&self) -> usize {
            self.store.baseline("fixed", now()).unwrap().towers.len()
                + self.store.baseline("mobile", now()).unwrap().towers.len()
        }
    }

    /// Review Focus 1: a 2a `ok` row is decoded again (2a kept no observations), once,
    /// with its stored profile, and judged as backfill.
    #[tokio::test]
    async fn a_2a_ok_row_is_redecoded_once_judged_and_suppressed() {
        let r = rig();
        r.seed("a", 0, true);
        r.decode_2a("a", DecodeStatus::Ok, "fixed");
        let d = FakeDecoder::new(seen(&["sib1:1:2:3"], vec![high()]), RunEnd::Finished);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!((o.ok, o.notify, o.judged_from_status), (1, 1, 0));
        assert_eq!(d.calls(), 1);
        assert!(
            !r.dev.log().iter().any(|l| l == "capture_profiles"),
            "the stored profile is reused"
        );
        let f = r.findings_of("a");
        assert!(!f.is_empty());
        assert!(f.iter().all(|x| x.3), "archived before the epoch: {f:?}");
        assert!(r.checks_of("a").contains(&"analyser_high".to_string()));
        assert_eq!(r.decode_of("a").unwrap().profile, "fixed");
        assert_eq!(r.store.baseline("fixed", now()).unwrap().towers.len(), 1);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o, DecodeOutcome::default(), "a second cycle judges nothing");
        assert_eq!(d.calls(), 1);
    }

    /// Review Focus 1: a 2a failure row is judged from its status: no sandbox, no
    /// re-hash (its file is gone here, which a re-hash would call archive_missing),
    /// no device call.
    #[tokio::test]
    async fn a_2a_failure_row_is_judged_from_status_without_the_sandbox() {
        let r = rig();
        r.seed("a", 0, false);
        r.decode_2a("a", DecodeStatus::DecoderFailure, "fixed");
        let d = FakeDecoder::ok();
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!((o.judged_from_status, o.notify), (1, 1));
        assert_eq!((o.ok, o.failed, o.archive_missing), (0, 0, 0));
        assert_eq!(d.calls(), 0, "the sandbox must not run");
        assert!(r.dev.log().is_empty(), "no device call");
        assert_eq!(
            r.findings_of("a"),
            [(
                "decoder_failure".to_string(),
                "notify".to_string(),
                false,
                true,
                "the decoder failed; checks cover what arrived".to_string()
            )]
        );
        let x = r.decode_of("a").unwrap();
        assert_eq!(x.status, DecodeStatus::DecoderFailure);
        assert_eq!(x.detail.as_deref(), Some("2a said so"), "stored row reused");
        assert!(r.capture("a").flagged);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o, DecodeOutcome::default());
    }

    #[tokio::test]
    async fn the_second_fixed_capture_in_a_cycle_has_learned_from_the_first() {
        let r = rig();
        r.seed("a", 0, true);
        r.seed("b", 1, true);
        r.dev.set_profile("a", "fixed");
        r.dev.set_profile("b", "fixed");
        let d = FakeDecoder::new(
            seen(&["sib1:1:2:3", "sib1:1:2:4"], vec![]),
            RunEnd::Finished,
        );
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.ok, 2);
        assert_eq!(r.checks_of("a"), ["new_tower"]);
        assert!(r.checks_of("b").is_empty(), "{:?}", r.findings_of("b"));
    }

    #[tokio::test]
    async fn a_decoder_failure_with_a_high_warning_is_judged_and_teaches_nothing() {
        let r = rig();
        r.seed("a", 0, true);
        r.dev.set_profile("a", "fixed");
        let d = FakeDecoder::new(
            seen(&["sib1:1:2:3"], vec![high()]),
            RunEnd::Trapped("boom".into()),
        );
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!((o.failed, o.notify), (1, 2));
        let c = r.checks_of("a");
        assert!(c.contains(&"analyser_high".to_string()), "{c:?}");
        assert!(c.contains(&"decoder_failure".to_string()), "{c:?}");
        assert_eq!(r.towers_learned(), 0);
    }

    #[tokio::test]
    async fn a_mixed_capture_is_judged_mobile_with_spans_switch() {
        let r = rig();
        r.seed("a", 0, true);
        r.dev.set_profile("a", "mixed");
        let d = FakeDecoder::new(seen(&["sib1:1:2:3"], vec![high()]), RunEnd::Finished);
        r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(r.decode_of("a").unwrap().profile, "mobile");
        let f = r.findings_of("a");
        assert!(!f.is_empty());
        assert!(f.iter().all(|x| x.2), "spans_switch: {f:?}");
        assert_eq!(r.store.baseline("mobile", now()).unwrap().towers.len(), 1);
    }

    #[tokio::test]
    async fn a_capture_archived_after_the_epoch_is_not_suppressed() {
        let r = rig();
        // judging began when the rig's captures were archived (2023-11-14T22:13:20Z)
        r.store
            .judge_epoch(DateTime::from_timestamp(1_700_000_000, 0).unwrap())
            .unwrap();
        r.seed("new", 10, true);
        r.seed("old", -10, true);
        let d = FakeDecoder::new(seen(&[], vec![high()]), RunEnd::Finished);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!(o.notify, 2);
        assert!(r.findings_of("new").iter().all(|x| !x.3));
        assert!(r.findings_of("old").iter().all(|x| x.3));
        assert!(!r.findings_of("new").is_empty() && !r.findings_of("old").is_empty());
    }

    /// Ruling P3: only `DeletedOnDevice` rows are pruned, so both are seeded that way,
    /// and the unflagged twin is the control that IS pruned.
    #[tokio::test]
    async fn a_notify_finding_flags_the_capture_and_the_pruner_keeps_it() {
        let r = rig();
        r.seed("a", 0, true);
        r.seed("b", 1, true);
        for n in ["a", "b"] {
            let c = r.capture(n);
            r.store.set_state(c.key(), State::DeletedOnDevice).unwrap();
        }
        let notify = FakeDecoder::new(seen(&[], vec![high()]), RunEnd::Finished);
        r.run(Some(&dynd(&notify)), 1).await;
        let quiet = FakeDecoder::new(seen(&["sib1:1:2:3"], vec![]), RunEnd::Finished);
        r.run(Some(&dynd(&quiet)), 1).await;
        assert!(r.capture("a").flagged);
        assert!(!r.capture("b").flagged);
        assert_eq!(r.checks_of("b"), ["new_tower"], "a count finding only");
        let later =
            DateTime::from_timestamp(1_700_000_000, 0).unwrap() + chrono::Duration::days(100);
        assert_eq!(crate::pruner::prune(&r.store, &r.archive, DEV, later), 1);
        assert!(
            r.store.by_name(DEV, "b").unwrap().is_empty(),
            "control pruned"
        );
        assert_eq!(r.store.by_name(DEV, "a").unwrap().len(), 1, "flagged kept");
    }

    /// Review Focus 5: a flood is reported and never reaches the baseline.
    #[tokio::test]
    async fn a_tower_flood_is_a_finding_and_teaches_no_tower() {
        let r = rig();
        r.seed("a", 0, true);
        r.dev.set_profile("a", "fixed");
        let keys: Vec<String> = (0..300).map(|i| format!("sib1:1:2:{i}")).collect();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let d = FakeDecoder::new(seen(&refs, vec![]), RunEnd::Finished);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!((o.ok, o.notify), (1, 1));
        assert_eq!(r.checks_of("a"), ["tower_flood"]);
        assert_eq!(r.towers_learned(), 0);
    }

    /// I2: a hostile capture's 10,000 High warnings are one finding, one notify.
    #[tokio::test]
    async fn ten_thousand_high_warnings_are_one_finding() {
        let r = rig();
        r.seed("a", 0, true);
        let d = FakeDecoder::new(seen(&[], vec![high(); 10_000]), RunEnd::Finished);
        let o = r.run(Some(&dynd(&d)), 3).await;
        assert_eq!((o.ok, o.notify), (1, 1));
        let f = r.findings_of("a");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].4, "An: 10000 high warning(s); first: m");
    }

    /// The alert says whether the capture's towers were known, judged before it teaches them.
    #[tokio::test]
    async fn the_alert_knows_whether_its_towers_were_known() {
        let r = rig();
        // Judging began long ago: these captures are live, not backfill.
        r.store.judge_epoch(DateTime::from_timestamp(1_600_000_000, 0).unwrap()).unwrap();
        r.seed("a", 0, true);
        let d = FakeDecoder::new(seen(&["310-260-1-1"], vec![high()]), RunEnd::Finished);
        r.run(Some(&dynd(&d)), 3).await;
        r.seed("b", 1, true);
        let d = FakeDecoder::new(seen(&["310-260-1-1"], vec![high()]), RunEnd::Finished);
        r.run(Some(&dynd(&d)), 3).await;
        let dev = r.capture("a").device;
        let (p, _) = r.store.pending_notifications(&dev, now(), 10).unwrap();
        let got: Vec<(&str, &str, Option<bool>)> = p
            .iter()
            .map(|x| (x.name.as_str(), x.check.as_str(), x.towers_known))
            .collect();
        assert_eq!(
            got,
            [
                ("a", checks::ANALYSER_HIGH, Some(false)),
                ("b", checks::ANALYSER_HIGH, Some(true))
            ]
        );
    }

    #[test]
    fn notify_logging_is_one_line_per_check_id() {
        let f = |check, level| checks::Finding {
            check,
            level,
            detail: "secret cell id".into(),
        };
        let findings = [
            f(checks::ANALYSER_HIGH, Level::Notify),
            f(checks::DECODER_FAILURE, Level::Notify),
            f(checks::ANALYSER_HIGH, Level::Notify),
            f(checks::NEW_TOWER_WEAK, Level::Count),
            f(checks::ANALYSER_HIGH, Level::Notify),
        ];
        assert_eq!(
            notify_by_check(&findings),
            [(checks::ANALYSER_HIGH, 3), (checks::DECODER_FAILURE, 1)]
        );
    }

    /// M6: a failed read names its own step, not `record_judgement`.
    #[test]
    fn a_failed_read_while_judging_names_its_step() {
        let r = rig();
        r.seed("a", 0, true);
        let c = r.capture("a");
        let d = Decode {
            device: c.device.clone(),
            name: c.name.clone(),
            start: c.start,
            status: DecodeStatus::Ok,
            profile: "fixed".into(),
            frames: 0,
            failures: 0,
            towers: 0,
            identity_requests: 0,
            warnings_high: 0,
            warnings_other: 0,
            decoder_hash: GUEST_SHA256.into(),
            decoded_at: now(),
            detail: None,
        };
        let obs = Observations {
            failure_hours: vec![(Some("2026-10-11T00:00:00Z".into()), 1, 200)],
            ..Default::default()
        };
        let step = |table: &str| {
            let conn = rusqlite::Connection::open(r._dir.path().join("i.sqlite")).unwrap();
            conn.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_gone"))
                .unwrap();
            let e = judge_one(
                &r.store,
                &d,
                Profile::Fixed,
                false,
                &obs,
                false,
                now(),
                &checks::Settings::default(),
            )
            .unwrap_err();
            conn.execute_batch(&format!("ALTER TABLE {table}_gone RENAME TO {table}"))
                .unwrap();
            e.to_string()
        };
        assert_eq!(step("towers"), "baseline");
        assert_eq!(step("captures"), "previous_identity");
        assert_eq!(step("failure_hours"), "failure_history");
        assert_eq!(step("findings"), "record_judgement");
    }
}
