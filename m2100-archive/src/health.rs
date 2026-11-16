use std::path::Path;

use chrono::{DateTime, Duration, Utc};

use crate::puller::MIN_FREE_BYTES;
use crate::store::{State, Store};

/// The pipeline numbers published to Home Assistant.
pub struct Health {
    pub archive_bytes: u64,
    pub free_bytes: u64,
    pub days_covered: f64,
    pub gap_24h: Duration,
    pub longest_gap_24h: Duration,
    pub paused: bool,
}

/// Uncovered stretches of `[from, to]`, given coverage `spans` (any order,
/// overlapping or touching spans merge). Spans are clipped to the window.
pub fn gaps(
    spans: &[(DateTime<Utc>, DateTime<Utc>)],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let mut sorted: Vec<_> = spans.iter().filter(|(s, e)| e >= s).copied().collect();
    sorted.sort();
    let mut out = Vec::new();
    let mut cursor = from;
    for (s, e) in sorted {
        if s > cursor {
            let gap_end = s.min(to);
            if gap_end > cursor {
                out.push((cursor, gap_end));
            }
        }
        cursor = cursor.max(e);
        if cursor >= to {
            return out;
        }
    }
    if to > cursor {
        out.push((cursor, to));
    }
    out
}

fn dir_bytes(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Captures the unit stamped before this have no known time: it names and stamps
/// recordings started before its clock syncs from seconds since boot (1970).
pub fn time_known_from() -> DateTime<Utc> {
    DateTime::from_timestamp(1_577_836_800, 0).unwrap() // 2020-01-01T00:00:00Z
}

/// Compute the pipeline numbers.
///
/// Coverage spans come from rows that have a file (`DeletedOnDevice` and
/// `Archived`), as `start ..= last_message` (or `start`). Spans starting before
/// 2020 ("time unknown") count towards neither days covered nor gaps. A capture still
/// recording on the unit is not in the index yet, so the most recent stretch
/// up to `now` will normally show as a gap; that is accepted for now.
pub fn health(
    store: &Store,
    device_id: &str,
    archive: &Path,
    free_bytes: u64,
    now: DateTime<Utc>,
) -> Health {
    let archive_bytes = dir_bytes(archive) + dir_bytes(&archive.join("mismatch"));
    let spans: Vec<_> = store
        .all(device_id)
        .unwrap_or_else(|e| {
            log::error!("health: cannot read index: {e}");
            Vec::new()
        })
        .into_iter()
        .filter(|c| matches!(c.state, State::DeletedOnDevice | State::Archived))
        .filter(|c| c.start >= time_known_from())
        // Normalise once: a bad device clock can put last_message before start.
        .map(|c| (c.start, c.last_message.map_or(c.start, |l| l.max(c.start))))
        .collect();

    let days_covered = match (
        spans.iter().map(|s| s.0).min(),
        spans.iter().map(|s| s.1).max(),
    ) {
        (Some(a), Some(b)) => ((b - a).num_milliseconds() as f64 / 86_400_000.0).max(0.0),
        _ => 0.0,
    };

    let g = gaps(&spans, now - Duration::hours(24), now);
    let gap_24h = g.iter().fold(Duration::zero(), |a, (s, e)| a + (*e - *s));
    let longest_gap_24h = g
        .iter()
        .map(|(s, e)| *e - *s)
        .max()
        .unwrap_or_else(Duration::zero);

    Health {
        archive_bytes,
        free_bytes,
        days_covered,
        gap_24h,
        longest_gap_24h,
        paused: free_bytes < MIN_FREE_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Capture, State};
    use chrono::TimeZone;

    fn t(h: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap() + Duration::hours(h)
    }

    #[test]
    fn gaps_none_when_covered() {
        assert!(gaps(&[(t(0), t(10))], t(2), t(8)).is_empty());
        assert!(gaps(&[(t(0), t(5)), (t(5), t(10))], t(0), t(10)).is_empty());
    }

    #[test]
    fn gaps_whole_window_when_no_spans() {
        assert_eq!(gaps(&[], t(0), t(10)), vec![(t(0), t(10))]);
    }

    #[test]
    fn gaps_one_in_the_middle() {
        assert_eq!(
            gaps(&[(t(0), t(4)), (t(6), t(10))], t(0), t(10)),
            vec![(t(4), t(6))]
        );
    }

    #[test]
    fn gaps_overlapping_touching_out_of_order() {
        let spans = [(t(7), t(9)), (t(0), t(3)), (t(2), t(4)), (t(4), t(5))];
        assert_eq!(gaps(&spans, t(0), t(10)), vec![(t(5), t(7)), (t(9), t(10))]);
    }

    #[test]
    fn gaps_clip_at_window_edges() {
        let spans = [(t(-5), t(2)), (t(8), t(20))];
        assert_eq!(gaps(&spans, t(0), t(10)), vec![(t(2), t(8))]);
    }

    #[test]
    fn gaps_ignore_spans_outside_window() {
        assert_eq!(gaps(&[(t(20), t(30)), (t(-9), t(-1))], t(0), t(10)), vec![(t(0), t(10))]);
    }

    fn add(s: &Store, name: &str, st: State, start: DateTime<Utc>, last: Option<DateTime<Utc>>) {
        let h = Some("a".repeat(64));
        let c = Capture {
            device: "m2100".into(),
            name: name.into(),
            state: State::Archived,
            local_sha256: h.clone(),
            device_sha256: h,
            size: 1,
            start,
            last_message: last,
            archived_at: None,
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
    }

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        (d, s)
    }

    #[test]
    fn days_covered_oldest_to_newest() {
        let (d, s) = store();
        let now = t(24 * 20);
        add(&s, "a", State::DeletedOnDevice, t(0), Some(t(2)));
        add(&s, "b", State::Archived, t(24 * 9), Some(t(24 * 10)));
        // Rows without a file do not count.
        add(&s, "c", State::MissingOnDevice, t(-24 * 100), None);
        let h = health(&s, "m2100", d.path(), 100_000_000_000, now);
        assert!((h.days_covered - 10.0).abs() < 1e-9, "{}", h.days_covered);
    }

    /// C2: spans the unit stamped before 2020 (pre-sync, 1970) have no known time.
    #[test]
    fn spans_before_2020_are_time_unknown() {
        let (d, s) = store();
        let now = t(24 * 20);
        let epoch = DateTime::from_timestamp(31, 0).unwrap();
        add(&s, "31", State::DeletedOnDevice, epoch, Some(epoch + Duration::hours(30)));
        add(&s, "a", State::DeletedOnDevice, t(24 * 9), Some(t(24 * 10)));
        let h = health(&s, "m2100", d.path(), 100_000_000_000, now);
        assert!((h.days_covered - 1.0).abs() < 1e-9, "{}", h.days_covered);
        // A 1970 span can never cover the last 24 h either: the gap is the whole window
        // except what "b" covers.
        add(&s, "b", State::Archived, now - Duration::hours(4), Some(now));
        let h = health(&s, "m2100", d.path(), 100_000_000_000, now);
        assert_eq!(h.gap_24h, Duration::hours(20));
        // Only 1970 spans: nothing covered.
        let (d, s) = store();
        add(&s, "31", State::DeletedOnDevice, epoch, Some(epoch + Duration::hours(30)));
        let h = health(&s, "m2100", d.path(), 100_000_000_000, now);
        assert_eq!(h.days_covered, 0.0);
    }

    #[test]
    fn last_message_before_start_is_a_point_at_start() {
        let (d, s) = store();
        add(&s, "skew", State::Archived, t(24 * 10), Some(t(24 * 5)));
        let h = health(&s, "m2100", d.path(), 1, t(24 * 10) + Duration::hours(12));
        assert_eq!(h.days_covered, 0.0);
        let (d, s) = store();
        add(&s, "skew", State::Archived, t(24 * 10), Some(t(24 * 5)));
        add(&s, "ok", State::Archived, t(0), Some(t(24 * 2)));
        let h = health(&s, "m2100", d.path(), 1, t(24 * 11));
        assert!((h.days_covered - 10.0).abs() < 1e-9, "{}", h.days_covered);
    }

    #[test]
    fn days_covered_zero_when_empty() {
        let (d, s) = store();
        let h = health(&s, "m2100", d.path(), 1, t(0));
        assert_eq!(h.days_covered, 0.0);
        assert_eq!(h.gap_24h, Duration::hours(24));
    }

    #[test]
    fn start_only_row_counts_as_a_point() {
        let (d, s) = store();
        add(&s, "a", State::Archived, t(5), None);
        let h = health(&s, "m2100", d.path(), 1, t(0) + Duration::hours(30));
        assert_eq!(h.days_covered, 0.0);
    }

    #[test]
    fn gap_numbers_over_24h_window() {
        let (d, s) = store();
        let now = t(100);
        // window = [t(76), t(100)]; covered 80..90 and 92..96
        add(&s, "a", State::Archived, t(80), Some(t(90)));
        add(&s, "b", State::DeletedOnDevice, t(92), Some(t(96)));
        let h = health(&s, "m2100", d.path(), 1, now);
        // gaps: 76-80 (4h), 90-92 (2h), 96-100 (4h)
        assert_eq!(h.gap_24h, Duration::hours(10));
        assert_eq!(h.longest_gap_24h, Duration::hours(4));
    }

    #[test]
    fn archive_bytes_counts_root_and_mismatch_not_tmp() {
        let (d, s) = store();
        let a = d.path().join("arch");
        std::fs::create_dir_all(a.join("mismatch")).unwrap();
        std::fs::create_dir_all(a.join(".tmp")).unwrap();
        std::fs::write(a.join("x.qmdl.gz"), vec![0; 100]).unwrap();
        std::fs::write(a.join("x.ndjson"), vec![0; 20]).unwrap();
        std::fs::write(a.join("mismatch/y.qmdl.gz"), vec![0; 3]).unwrap();
        std::fs::write(a.join(".tmp/z"), vec![0; 1000]).unwrap();
        let h = health(&s, "m2100", &a, 1, t(0));
        assert_eq!(h.archive_bytes, 123);
    }

    #[test]
    fn paused_below_five_gb() {
        let (d, s) = store();
        let f = |b| health(&s, "m2100", d.path(), b, t(0)).paused;
        assert!(f(4_999_999_999));
        assert!(!f(5_000_000_000));
        assert!(!f(100_000_000_000));
        let h = health(&s, "m2100", d.path(), 42, t(0));
        assert_eq!(h.free_bytes, 42);
    }
}
