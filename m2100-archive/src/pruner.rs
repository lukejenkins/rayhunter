//! Retention: delete archived captures 90 days after they were archived, unless kept
//! or flagged.
//!
//! Age is measured from `archived_at` (this machine's clock), never from the capture's
//! own times: the unit stamps recordings started before its clock syncs in 1970, so a
//! capture-time age would prune them the day they arrive.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};

use crate::store::{State, Store};

pub const RETENTION_DAYS: i64 = 90;

/// Remove expired captures (files, then rows); returns how many were pruned.
///
/// Only `DeletedOnDevice` rows are eligible: `Archived` rows are still on the
/// unit, `Mismatch` rows are retrying, and `MissingOnDevice` rows may hold the
/// only (unverified) copy. `kept` and `flagged` rows are never pruned. Files
/// are removed before the row, so a crash leaves a row pointing at nothing
/// rather than an orphan file nobody indexes. Never touches `mismatch/` or
/// `.tmp/`: only `{name}.qmdl.gz` and `{name}.ndjson` directly in `archive`.
pub fn prune(store: &Store, archive: &Path, device_id: &str, now: DateTime<Utc>) -> u32 {
    // Bookkeeping for the mesh sensors; a failure here never stops the capture pruning below.
    if let Err(e) = store.prune_mesh_log(now) {
        log::error!("prune: cannot prune mesh log: {e:#}");
    }
    let rows = match store.all(device_id) {
        Ok(r) => r,
        Err(e) => {
            log::error!("prune: cannot read index: {e}");
            return 0;
        }
    };
    let mut n = 0;
    for c in rows {
        if c.state != State::DeletedOnDevice || c.kept || c.flagged {
            continue;
        }
        let Some(archived_at) = c.archived_at else {
            continue; // no known archive time: never pruned
        };
        if !(now - archived_at > Duration::days(RETENTION_DAYS)) {
            continue;
        }
        // A file name that could escape the archive directory is never trusted.
        let Some(file) = c.file.as_deref() else {
            log::error!("prune: {} has no archive file recorded", c.name);
            continue;
        };
        if file.is_empty() || file.contains(['/', '\\']) || file == ".." || file == "." {
            log::error!("prune: refusing suspicious file name {file:?}");
            continue;
        }
        // Defence in depth (the unique index should make this impossible): another
        // row owning this stem means the files are not this row's alone.
        let shared = match store.stem_shared(c.key(), file) {
            Ok(b) => b,
            Err(e) => {
                log::error!("prune: cannot check stem {file} for sharing: {e}; skipping");
                continue;
            }
        };
        if shared {
            log::warn!(
                "prune: another row owns stem {file}; removing only the row for {}",
                c.name
            );
            match store.remove(c.key()) {
                Ok(()) => n += 1,
                Err(e) => log::error!("prune: cannot remove row {}: {e}", c.name),
            }
            continue;
        }
        let mut ok = true;
        for ext in ["qmdl.gz", "ndjson"] {
            let p = archive.join(format!("{file}.{ext}"));
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    log::error!("prune: cannot remove {}: {e}", p.display());
                    ok = false;
                }
            }
        }
        if !ok {
            continue; // keep the row; retry tomorrow
        }
        match store.remove(c.key()) {
            Ok(()) => n += 1,
            Err(e) => log::error!("prune: cannot remove row {}: {e}", c.name),
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Capture;
    use chrono::TimeZone;

    const DEV: &str = "m2100";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 9, 12, 0, 0).unwrap()
    }

    fn setup(
        name: &str,
        age_days: i64,
        state: State,
        kept: bool,
        flagged: bool,
    ) -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        add(&s, d.path(), name, age_days, state, kept, flagged);
        (d, s)
    }

    fn add(s: &Store, dir: &Path, name: &str, age_days: i64, st: State, kept: bool, flagged: bool) {
        let end = now() - Duration::days(age_days);
        add_at(
            s,
            dir,
            name,
            end - Duration::hours(1),
            end,
            end,
            st,
            kept,
            flagged,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn add_at(
        s: &Store,
        dir: &Path,
        name: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        archived_at: DateTime<Utc>,
        st: State,
        kept: bool,
        flagged: bool,
    ) {
        let h = Some("a".repeat(64));
        let c = Capture {
            device: DEV.into(),
            name: name.into(),
            state: State::Archived,
            local_sha256: h.clone(),
            device_sha256: h,
            size: 10,
            start,
            last_message: Some(end),
            archived_at: Some(archived_at),
            mismatch_tries: 0,
            kept: false,
            flagged: false,
            file: Some(name.into()),
            analysis_tries: 0,
        };
        s.record_archived(&c).unwrap();
        if st != State::Archived {
            s.set_state(c.key(), st).unwrap();
        }
        s.set_kept(c.key(), kept).unwrap();
        s.set_flagged(c.key(), flagged).unwrap();
        std::fs::write(dir.join(format!("{name}.qmdl.gz")), b"q").unwrap();
        std::fs::write(dir.join(format!("{name}.ndjson")), b"n").unwrap();
    }

    fn exists(d: &tempfile::TempDir, name: &str) -> (bool, bool) {
        (
            d.path().join(format!("{name}.qmdl.gz")).exists(),
            d.path().join(format!("{name}.ndjson")).exists(),
        )
    }

    #[test]
    fn prune_also_trims_the_mesh_log() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        s.log_mesh(&["alert"], now() - Duration::days(8)).unwrap();
        s.log_mesh(&["quiet"], now() - Duration::days(1)).unwrap();
        assert_eq!(prune(&s, d.path(), DEV, now()), 0);
        assert_eq!(s.mesh_log_rows(), 1);
    }

    /// Two rows owning one stem can only exist if the unique index is gone; the pruner
    /// must still leave the files alone and drop just the expired row.
    #[test]
    fn a_stem_shared_with_another_row_keeps_its_files() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        add(
            &s,
            d.path(),
            "old",
            100,
            State::DeletedOnDevice,
            false,
            false,
        );
        s.drop_stem_index_for_test();
        // A newer capture whose row points at the same stem.
        let mut other = s.by_name(DEV, "old").unwrap().remove(0);
        other.name = "new".into();
        other.start = now();
        other.state = State::DeletedOnDevice;
        other.archived_at = Some(now());
        other.file = Some("old".into());
        s.record_archived(&Capture {
            state: State::Archived,
            ..other.clone()
        })
        .unwrap();
        s.set_state(other.key(), State::DeletedOnDevice).unwrap();
        assert_eq!(prune(&s, d.path(), DEV, now()), 1);
        assert_eq!(exists(&d, "old"), (true, true));
        assert!(s.by_name(DEV, "old").unwrap().is_empty());
        assert_eq!(s.by_name(DEV, "new").unwrap().len(), 1);
    }

    #[test]
    fn prunes_91_days_files_and_row() {
        let (d, s) = setup("old", 91, State::DeletedOnDevice, false, false);
        assert_eq!(prune(&s, d.path(), DEV, now()), 1);
        assert_eq!(exists(&d, "old"), (false, false));
        assert!(s.by_name(DEV, "old").unwrap().is_empty());
    }

    #[test]
    fn keeps_89_days() {
        let (d, s) = setup("recent", 89, State::DeletedOnDevice, false, false);
        assert_eq!(prune(&s, d.path(), DEV, now()), 0);
        assert_eq!(exists(&d, "recent"), (true, true));
        assert!(!s.by_name(DEV, "recent").unwrap().is_empty());
    }

    #[test]
    fn kept_and_flagged_never_pruned() {
        for (k, f) in [(true, false), (false, true), (true, true)] {
            let (d, s) = setup("x", 1000, State::DeletedOnDevice, k, f);
            assert_eq!(prune(&s, d.path(), DEV, now()), 0);
            assert_eq!(exists(&d, "x"), (true, true));
            assert!(!s.by_name(DEV, "x").unwrap().is_empty());
        }
    }

    #[test]
    fn other_states_never_pruned() {
        for st in [State::Archived, State::Mismatch, State::MissingOnDevice] {
            let (d, s) = setup("x", 1000, st, false, false);
            assert_eq!(prune(&s, d.path(), DEV, now()), 0, "{st:?}");
            assert_eq!(exists(&d, "x"), (true, true));
            assert!(!s.by_name(DEV, "x").unwrap().is_empty());
        }
    }

    #[test]
    fn missing_ndjson_is_fine_and_mismatch_dir_untouched() {
        let (d, s) = setup("old", 100, State::DeletedOnDevice, false, false);
        std::fs::remove_file(d.path().join("old.ndjson")).unwrap();
        std::fs::create_dir(d.path().join("mismatch")).unwrap();
        std::fs::create_dir(d.path().join(".tmp")).unwrap();
        for p in ["mismatch/old.qmdl.gz", ".tmp/old.qmdl.gz"] {
            std::fs::write(d.path().join(p), b"keep").unwrap();
        }
        assert_eq!(prune(&s, d.path(), DEV, now()), 1);
        assert!(d.path().join("mismatch/old.qmdl.gz").exists());
        assert!(d.path().join(".tmp/old.qmdl.gz").exists());
    }

    #[test]
    fn age_is_time_since_archiving_not_the_capture_times() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        // Recorded 100 days ago, archived only 10 days ago: kept.
        let t = now() - Duration::days(100);
        add_at(
            &s,
            d.path(),
            "late",
            t,
            t,
            now() - Duration::days(10),
            State::DeletedOnDevice,
            false,
            false,
        );
        assert_eq!(prune(&s, d.path(), DEV, now()), 0);
        assert_eq!(exists(&d, "late"), (true, true));
    }

    /// C2: a pre-sync capture is stamped 1970 by the unit's clock. Archived today it
    /// must not be pruned (that would lose both copies within a day).
    #[test]
    fn a_1970_capture_archived_today_is_not_pruned() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        let t = DateTime::from_timestamp(31, 0).unwrap();
        add_at(
            &s,
            d.path(),
            "31",
            t,
            t,
            now() - Duration::hours(1),
            State::DeletedOnDevice,
            false,
            false,
        );
        assert_eq!(prune(&s, d.path(), DEV, now()), 0);
        assert_eq!(exists(&d, "31"), (true, true));
        assert_eq!(s.by_name(DEV, "31").unwrap().len(), 1);
    }

    #[test]
    fn a_1970_capture_archived_91_days_ago_is_pruned() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        let t = DateTime::from_timestamp(31, 0).unwrap();
        add_at(
            &s,
            d.path(),
            "31",
            t,
            t,
            now() - Duration::days(91),
            State::DeletedOnDevice,
            false,
            false,
        );
        assert_eq!(prune(&s, d.path(), DEV, now()), 1);
        assert_eq!(exists(&d, "31"), (false, false));
        assert!(s.by_name(DEV, "31").unwrap().is_empty());
    }
}
