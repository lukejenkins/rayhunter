//! The most recent detection, shared between the analysis path and the M2100 panel.
//!
//! Before this, a warning produced one notification -- "Rayhunter has detected a High
//! severity event" -- and a red outline on the panel. When, which analyzer, and which
//! cell were in the recording, but nowhere you could see them without pulling it.
//! This keeps the latest alert where both the notification text and the panel's banner
//! can read it, and remembers whether it has been acknowledged on the device.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Datelike, Local, Utc};
use rayhunter::analysis::analyzer::EventType;

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub at: DateTime<Local>,
    pub severity: EventType,
    /// The analyzer's display name, e.g. "IMSI Requested".
    pub analyzer: String,
    /// The analyzer's own explanation of what it saw.
    pub message: String,
    /// The serving cell when it fired, if the device can say -- "eNB 12345 c1 PCI 101 TAC 4242".
    pub cell: Option<String>,
    /// That cell's identity (ECI). Lets the cell log mark the right row even when
    /// `at` is wrong -- an alert at boot is stamped before the clock syncs.
    pub eci: Option<u32>,
}

/// Before the network sets the clock, the device believes it is January 1970. Any
/// year before this is a clock that hasn't synced, not a real time.
const FIRST_PLAUSIBLE_YEAR: i32 = 2020;

/// When it fired, for people: UTC and labelled, because the firmware's timezone is
/// Eastern European while the person is not; or an honest "unknown" before sync.
/// (2026-10-02: a boot-time test alert went out reading "22:39:37" -- 1970 clock,
/// EEST zone -- which was wrong twice over.)
pub fn time_label(at: DateTime<Local>, with_seconds: bool) -> String {
    if at.year() < FIRST_PLAUSIBLE_YEAR {
        return "time unknown (clock not synced)".to_string();
    }
    let fmt = if with_seconds { "%H:%M:%S UTC" } else { "%H:%MZ" };
    at.with_timezone(&Utc).format(fmt).to_string()
}

static LAST: Mutex<Option<Alert>> = Mutex::new(None);
static ACKED: AtomicBool = AtomicBool::new(true);

/// Remember a new alert. It stays unacknowledged until someone sees it on the panel.
pub fn record(a: Alert) {
    *LAST.lock().unwrap() = Some(a);
    ACKED.store(false, Ordering::Relaxed);
}

/// The latest alert, acknowledged or not -- the cell log marks where it happened.
pub fn last() -> Option<Alert> {
    LAST.lock().unwrap().clone()
}

/// The latest alert, only while nobody has acknowledged it -- what the banner shows.
pub fn unacknowledged() -> Option<Alert> {
    if ACKED.load(Ordering::Relaxed) {
        None
    } else {
        last()
    }
}

/// Mark the current alert seen. `how` goes to the log, so a banner that disappears
/// can always be accounted for (2026-10-02: one was dismissed as instructed, and the
/// absence of a record cost a debugging detour).
pub fn acknowledge(how: &str) {
    if !ACKED.swap(true, Ordering::Relaxed) {
        log::info!("alert acknowledged: {how}");
    }
}

/// The notification body.
///
/// Deliberately carries NO location: the notification goes to ntfy.sh, which is
/// third-party infrastructure. Coordinates, when there are any, stay in the recording.
pub fn notification_text(a: &Alert) -> String {
    // Deliberately no cell. This text leaves the device for the notification
    // server (ntfy.sh unless self-hosted), and a cell identity plus a timestamp
    // is a location at the moment something was detected -- the worst moment
    // to leak one. The cell stays on the panel and in the recording.
    format!(
        "Rayhunter {:?} alert: {}, {}. {}",
        a.severity,
        a.analyzer,
        time_label(a.at, true),
        a.message
    )
}

/// One line for the panel banner: 30 characters, leaving room for the "tap left"
/// hint on a 40-character panel.
pub fn banner_text(a: &Alert) -> String {
    let when = if a.at.year() < FIRST_PLAUSIBLE_YEAR {
        "--:--".to_string()
    } else {
        time_label(a.at, false)
    };
    let s = format!("! {when} {}", a.analyzer);
    s.chars().take(30).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample() -> Alert {
        Alert {
            at: Local.with_ymd_and_hms(2026, 10, 2, 14, 3, 7).unwrap(),
            severity: EventType::High,
            analyzer: "IMSI Requested".into(),
            message: "Identity request without attach (packet 1234)".into(),
            cell: Some("eNB 12345 c1 PCI 101 TAC 4242".into()),
            eci: Some(12345 << 8 | 1),
        }
    }

    #[test]
    fn the_notification_names_the_analyzer_and_the_time_but_not_the_cell() {
        let t = notification_text(&sample());
        assert!(t.contains("IMSI Requested"), "{t}");
        assert!(!t.contains("eNB"), "a cell identity must never leave the device: {t}");
        assert!(!t.contains("TAC"), "{t}");
        let utc = sample().at.with_timezone(&Utc).format("%H:%M:%S UTC").to_string();
        assert!(t.contains(&utc), "times are UTC and labelled: {t}");
        assert!(t.contains("Identity request"), "{t}");
        assert!(t.contains("High"), "{t}");
    }

    #[test]
    fn a_missing_cell_still_reads_cleanly() {
        let mut a = sample();
        a.cell = None;
        let t = notification_text(&a);
        assert!(!t.contains(" on "), "{t}");
    }

    #[test]
    fn the_banner_fits_the_panel() {
        let mut a = sample();
        a.analyzer = "A Very Long Analyzer Name That Would Overflow The Panel".into();
        assert!(banner_text(&a).chars().count() <= 30);
        assert!(banner_text(&sample()).starts_with("! "));
        assert!(banner_text(&sample()).contains("Z IMSI"), "{}", banner_text(&sample()));
    }

    #[test]
    fn an_alert_shows_until_acknowledged_but_is_still_remembered() {
        record(sample());
        assert!(unacknowledged().is_some());
        acknowledge("test");
        assert!(unacknowledged().is_none(), "acknowledged alerts leave the banner");
        assert!(last().is_some(), "but the cell log can still mark where it happened");
    }

    #[test]
    fn an_unsynced_clock_says_so_instead_of_lying() {
        let mut a = sample();
        a.at = Local.with_ymd_and_hms(1970, 1, 9, 22, 39, 37).unwrap();
        let t = notification_text(&a);
        assert!(t.contains("time unknown"), "{t}");
        assert!(!t.contains("22:39"), "{t}");
        assert!(banner_text(&a).starts_with("! --:-- "), "{}", banner_text(&a));
    }
}
