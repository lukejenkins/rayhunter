pub mod wire;
pub mod link;

use crate::checks::{
    ANALYSER_HIGH, ANALYSER_OTHER, ANALYSER_OVERFLOW, FAILURE_SPIKE, IDENTITY_OFF_RHYTHM,
    NEW_TOWER, NEW_TOWER_IDENTITY, NEW_TOWER_RECUR, NEW_TOWER_SECTOR, NEW_TOWER_WEAK, TOWER_FLOOD,
};
use chrono::{DateTime, Duration, Local, Timelike, Utc};
use std::io::Read;

pub const QUIET_TEXT: &str = "Home sentinel: all quiet";
pub const TEST_TEXT: &str = "Home sentinel: test message";
/// ASCII BEL. Receivers mute the channel and turn on "alert on bell", so only texts that
/// carry it make a sound; the quiet ping arrives silently. Invisible on the screens tried.
pub const BELL: char = '\u{7}';
/// What a text may hold before `on_air` adds the bell: the radio's limit less one byte.
pub const TEXT_MAX: usize = wire::MAX_TEXT - 1;
pub const MAX_PER_CYCLE: usize = 3;
pub const QUIET_MAX_STALE_MIN: i64 = 120;
/// A quiet ping built longer ago than this is not sent: its all-clear is out of date.
pub const QUIET_MAX_BATCH_AGE_MIN: i64 = 5;

const PORT_PREFIX: &str = "/dev/serial/by-id/";

/// A text as it goes on air: every text but the quiet ping ends in the bell, once. New
/// kinds of text buzz unless someone decides otherwise.
pub fn on_air(text: &str) -> String {
    if text == QUIET_TEXT || text.ends_with(BELL) {
        text.to_string()
    } else {
        format!("{text}{BELL}")
    }
}

/// What became of one radio text, or of a due quiet ping that was never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    Failed,
    Skipped,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Sent => "sent",
            Outcome::Failed => "failed",
            Outcome::Skipped => "skipped",
        }
    }
}

// Why a due quiet ping did not go out.
pub const SKIP_ALERT_OPEN: &str = "alert_open";
pub const SKIP_NOT_WATCHING: &str = "not_watching";
pub const SKIP_QUIET_HOURS: &str = "quiet_hours";
/// Other texts went out that cycle instead.
pub const SKIP_BUSY: &str = "busy";
/// Another stage held the radio when the cycle came to send.
pub const SKIP_RADIO_BUSY: &str = "radio_busy";
/// The batch was too old by the time the radio was free (`QUIET_MAX_BATCH_AGE_MIN`).
pub const SKIP_STALE: &str = "stale";
pub const SKIP_STORE_ERROR: &str = "store_error";

/// One line of the transmission log: what kind of text, what became of it, never the
/// text itself. `hash` (first 12 hex of the text's sha256, without the bell) matches a
/// sent-list entry without carrying its words.
#[derive(Debug, Clone, PartialEq)]
pub struct RadioEvent {
    pub at: DateTime<Utc>,
    pub kind: &'static str,
    pub outcome: Outcome,
    pub reason: Option<&'static str>,
    pub alert_id: Option<i64>,
    pub bell: bool,
    pub hash: String,
}

pub fn text_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let t = text.strip_suffix(BELL).unwrap_or(text);
    Sha256::digest(t.as_bytes()).iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// The reason a failed send is booked under: the same classes as the "Mesh status" sensor.
pub fn fail_reason(e: &anyhow::Error) -> &'static str {
    if e.downcast_ref::<link::NoRadio>().is_some() {
        "no_radio"
    } else if e.downcast_ref::<link::HandshakeTimeout>().is_some() {
        "no_answer"
    } else {
        "error"
    }
}

/// The log lines for one send of `items` (kind, alert, text) in order: on `Ok(n)` the first
/// `n` went out and the rest did not; on `Err` none is booked as sent.
pub fn send_events(
    items: &[(&'static str, Option<i64>, &str)],
    sent: &anyhow::Result<usize>,
    now: DateTime<Utc>,
) -> Vec<RadioEvent> {
    items
        .iter()
        .enumerate()
        .map(|(i, (kind, alert_id, text))| {
            let (outcome, reason) = match sent {
                Ok(n) if i < *n => (Outcome::Sent, None),
                Ok(_) => (Outcome::Failed, Some("not_sent")),
                Err(e) => (Outcome::Failed, Some(fail_reason(e))),
            };
            RadioEvent {
                at: now,
                kind,
                outcome,
                reason,
                alert_id: *alert_id,
                bell: on_air(text).ends_with(BELL),
                hash: text_hash(text),
            }
        })
        .collect()
}

/// A due quiet ping that did not go out, and why.
pub fn skipped_ping(reason: &'static str, now: DateTime<Utc>) -> RadioEvent {
    RadioEvent {
        at: now,
        kind: "quiet",
        outcome: Outcome::Skipped,
        reason: Some(reason),
        alert_id: None,
        bell: false,
        hash: text_hash(QUIET_TEXT),
    }
}

/// How long without any quiet-ping record before the page warns: the longest gap the
/// schedule allows (1.5 x the even spacing, see `next_quiet`) plus 30 minutes. `None` when
/// pings are off.
pub fn quiet_overdue_after(per_day: u32) -> Option<Duration> {
    if per_day == 0 {
        return None;
    }
    Some(Duration::minutes(i64::from(24 * 60 * 3 / 2 / per_day) + 30))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Level {
    Strong,
    All,
}

/// How the sentinel's own sending is going, for the "Mesh status" sensor.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum MeshStatus {
    Off,
    Ok,
    NoRadio,
    NoAnswer,
    Error,
}

impl MeshStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            MeshStatus::Off => "off",
            MeshStatus::Ok => "ok",
            MeshStatus::NoRadio => "radio missing",
            MeshStatus::NoAnswer => "no answer",
            MeshStatus::Error => "error",
        }
    }
}

/// The status a send attempt leaves behind.
pub fn status_of(sent: &anyhow::Result<usize>) -> MeshStatus {
    match sent {
        Ok(_) => MeshStatus::Ok,
        Err(e) if e.downcast_ref::<link::NoRadio>().is_some() => MeshStatus::NoRadio,
        Err(e) if e.downcast_ref::<link::HandshakeTimeout>().is_some() => MeshStatus::NoAnswer,
        Err(_) => MeshStatus::Error,
    }
}

/// A change in whether the radio's port exists, for one log line per change.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RadioChange {
    Gone,
    Back,
}

/// One presence check (the port path exists; the radio is never opened for it). Returns the
/// status to publish and the change since the last check: while the port is gone the status
/// is NoRadio, otherwise it is the outcome of the last real send attempt. An attempt that
/// failed with NoRadio was about presence, which this check owns, so once the port is back it
/// reads as Ok until the next attempt says otherwise.
pub fn radio_check(
    was_present: bool,
    present: bool,
    last_attempt: MeshStatus,
) -> (MeshStatus, Option<RadioChange>) {
    let change = match (was_present, present) {
        (true, false) => Some(RadioChange::Gone),
        (false, true) => Some(RadioChange::Back),
        _ => None,
    };
    let status = match (present, last_attempt) {
        (false, _) => MeshStatus::NoRadio,
        (true, MeshStatus::NoRadio) => MeshStatus::Ok,
        (true, s) => s,
    };
    (status, change)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub port: String,
    pub level: Level,
    pub quiet_per_day: u32,
    pub send_test: bool,
    /// Local hours with no "all quiet" pings, as (start, end), end exclusive, may wrap past
    /// midnight. Alerts ignore it.
    pub quiet_hours: Option<(u32, u32)>,
}

fn port_ok(port: &str) -> bool {
    use std::path::{Component, Path};
    let Some(rest) = port.strip_prefix(PORT_PREFIX) else {
        return false;
    };
    !rest.is_empty()
        && Path::new(rest).file_name().is_some()
        && Path::new(rest).components().all(|c| matches!(c, Component::Normal(_)))
}

pub fn config(
    port: Option<&str>,
    level: Option<&str>,
    quiet_per_day: Option<i64>,
    send_test: Option<bool>,
) -> Option<Config> {
    let port = match port.map(str::trim) {
        None => return None,
        Some("") => {
            log::warn!("mesh_port is blank; mesh alerts off");
            return None;
        }
        Some(p) => p,
    };
    if !port_ok(port) {
        log::warn!("mesh_port {port:?} is not a plain path under {PORT_PREFIX}; mesh alerts off");
        return None;
    }
    let level = match level.map(str::trim) {
        None | Some("strong") => Level::Strong,
        Some("all") => Level::All,
        Some(other) => {
            log::warn!("mesh_level {other:?} is not strong or all; using strong");
            Level::Strong
        }
    };
    let asked = quiet_per_day.unwrap_or(3);
    let quiet = asked.clamp(0, 6);
    if quiet != asked {
        log::warn!("mesh_quiet_per_day {asked} is outside 0..=6; using {quiet}");
    }
    Some(Config {
        port: port.to_string(),
        level,
        quiet_per_day: quiet as u32,
        send_test: send_test.unwrap_or(false),
        quiet_hours: None,
    })
}

/// `mesh_quiet_hours`, e.g. "22-7": two whole local hours 0..=23, different. Anything else is
/// off, with a warning.
pub fn quiet_hours(s: Option<&str>) -> Option<(u32, u32)> {
    let s = s?.trim();
    let parsed = s.split_once('-').and_then(|(a, b)| {
        let ok = |x: &str| x.len() <= 2 && x.bytes().all(|c| c.is_ascii_digit()) && !x.is_empty();
        if !ok(a) || !ok(b) {
            return None;
        }
        let (a, b) = (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?);
        (a <= 23 && b <= 23 && a != b).then_some((a, b))
    });
    if parsed.is_none() {
        log::warn!("mesh_quiet_hours {s:?} is not like 22-7; no quiet hours");
    }
    parsed
}

/// Whether local `hour` falls in the quiet hours (start inclusive, end exclusive, wrapping).
pub fn in_quiet_hours(hour: u32, q: Option<(u32, u32)>) -> bool {
    match q {
        None => false,
        Some((a, b)) if a < b => (a..b).contains(&hour),
        Some((a, b)) => hour >= a || hour < b,
    }
}

/// The hour on the Yellow's local clock (the add-on gets TZ from the Supervisor).
/// The start of `t`'s local day (the earlier one if midnight repeats; `t` itself if
/// midnight does not exist that day).
pub fn local_midnight(t: DateTime<Utc>) -> DateTime<Utc> {
    t.with_timezone(&Local)
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|m| m.and_local_timezone(Local).earliest())
        .map_or(t, |m| m.with_timezone(&Utc))
}

pub fn local_hour(t: DateTime<Utc>) -> u32 {
    t.with_timezone(&Local).hour()
}

pub fn checks_for(level: Level) -> &'static [&'static str] {
    match level {
        Level::Strong => &[
            ANALYSER_HIGH,
            ANALYSER_OVERFLOW,
            TOWER_FLOOD,
            NEW_TOWER_IDENTITY,
            NEW_TOWER_RECUR,
        ],
        Level::All => &[
            ANALYSER_HIGH,
            ANALYSER_OVERFLOW,
            TOWER_FLOOD,
            NEW_TOWER_IDENTITY,
            NEW_TOWER_RECUR,
            NEW_TOWER,
            NEW_TOWER_WEAK,
            NEW_TOWER_SECTOR,
            IDENTITY_OFF_RHYTHM,
            FAILURE_SPIKE,
            ANALYSER_OTHER,
        ],
    }
}

pub fn text_for(check: &str) -> Option<&'static str> {
    Some(match check {
        ANALYSER_HIGH => "Home alert (strong): suspicious cell activity near home",
        ANALYSER_OVERFLOW => "Home alert (strong): many suspicious cell warnings near home",
        TOWER_FLOOD => "Home alert (strong): many new cell towers at once near home",
        NEW_TOWER_IDENTITY => "Home alert (strong): new cell tower asked phones for ID",
        NEW_TOWER_RECUR => "Home alert (strong): new cell tower is back near home",
        NEW_TOWER =>"Home notice: new cell tower near home",
        NEW_TOWER_WEAK => "Home notice: new cell tower near home (weak signal)",
        NEW_TOWER_SECTOR => "Home notice: new antenna on a known tower near home",
        IDENTITY_OFF_RHYTHM => "Home notice: phones asked for ID at an unusual time",
        FAILURE_SPIKE => "Home notice: unusual cell errors near home",
        ANALYSER_OTHER => "Home notice: minor cell warning near home",
        _ => return None,
    })
}

/// Appended to a strong check's text for the first live (stage 1) radio message.
pub const STAGE1_TAIL: &str = " Stay calm, avoid sensitive calls, wait for an update.";

/// Stage 1 radio text: the check's fixed sentence plus the calm-down tail.
pub fn stage1_text(check: &str) -> Option<String> {
    text_for(check).map(|t| format!("{t}{STAGE1_TAIL}"))
}

/// Just before a send: keep the rows in `live` (still not meshed) and a quiet ping only if
/// its batch was `built` at most `QUIET_MAX_BATCH_AGE_MIN` before `now`. Order is kept.
pub fn sendable(
    batch: Vec<(Option<i64>, String)>,
    live: &[i64],
    built: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Vec<(Option<i64>, String)> {
    let fresh = now - built <= Duration::minutes(QUIET_MAX_BATCH_AGE_MIN);
    batch
        .into_iter()
        .filter(|(id, _)| match id {
            Some(id) => live.contains(id),
            None => fresh,
        })
        .collect()
}

/// Next quiet ping: now + a gap uniform in [0.5, 1.5] x (a day / per_day), from `r`.
pub fn next_quiet(now: DateTime<Utc>, per_day: u32, r: u32) -> Option<DateTime<Utc>> {
    if per_day == 0 {
        return None;
    }
    let frac = r as f64 / u32::MAX as f64;
    let secs = (86_400.0 / per_day as f64) * (0.5 + frac);
    Some(now + Duration::milliseconds((secs * 1000.0).round() as i64))
}

pub fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)) {
        Ok(()) => u32::from_le_bytes(b),
        Err(e) => {
            log::warn!("/dev/urandom unavailable ({e}); using hasher randomness");
            use std::hash::{BuildHasher, Hasher};
            std::collections::hash_map::RandomState::new().build_hasher().finish() as u32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{
        ANALYSER_HIGH, ANALYSER_OTHER, ANALYSER_OVERFLOW, FAILURE_SPIKE, IDENTITY_OFF_RHYTHM,
        NEW_TOWER, NEW_TOWER_IDENTITY, NEW_TOWER_RECUR, NEW_TOWER_SECTOR, NEW_TOWER_WEAK, TOWER_FLOOD,
    };

    const P: &str = "/dev/serial/by-id/usb-x";

    #[test]
    fn config_off_without_port_or_with_bad_path() {
        assert!(config(None, None, None, None).is_none());
        assert!(config(Some("/dev/ttyACM0"), None, None, None).is_none());
        assert!(config(Some("  "), None, None, None).is_none());
        assert!(config(Some("/dev/serial/by-id/"), None, None, None).is_none());
        assert!(config(Some("/dev/serial/by-id/../../ttyACM0"), None, None, None).is_none());
        assert!(config(Some("/dev/serial/by-id/./x"), None, None, None).is_none());
    }

    #[test]
    fn quiet_hours_parse() {
        assert_eq!(quiet_hours(Some("22-7")), Some((22, 7)));
        assert_eq!(quiet_hours(Some(" 1-5 ")), Some((1, 5)));
        assert_eq!(quiet_hours(Some("0-23")), Some((0, 23)));
        assert_eq!(quiet_hours(None), None);
        for bad in ["", "22", "22-24", "7-7", "a-b", "22-7-1", "-1-5", "22 - 7"] {
            assert_eq!(quiet_hours(Some(bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn quiet_hours_wrap_past_midnight() {
        let night = Some((22, 7));
        for h in [22, 23, 0, 3, 6] {
            assert!(in_quiet_hours(h, night), "{h}");
        }
        for h in [7, 12, 21] {
            assert!(!in_quiet_hours(h, night), "{h}");
        }
        let early = Some((1, 5));
        assert!(!in_quiet_hours(0, early));
        assert!(in_quiet_hours(1, early));
        assert!(in_quiet_hours(4, early));
        assert!(!in_quiet_hours(5, early));
        for h in 0..24 {
            assert!(!in_quiet_hours(h, None), "{h}");
        }
    }

    #[test]
    fn config_defaults() {
        let c = config(Some(P), None, None, None).unwrap();
        assert_eq!(
            c,
            Config {
                port: P.into(),
                level: Level::Strong,
                quiet_per_day: 3,
                send_test: false,
                quiet_hours: None,
            }
        );
    }

    #[test]
    fn quiet_per_day_is_clamped() {
        assert_eq!(config(Some(P), None, Some(9), None).unwrap().quiet_per_day, 6);
        assert_eq!(config(Some(P), None, Some(-1), None).unwrap().quiet_per_day, 0);
    }

    #[test]
    fn strong_level_sends_only_strong_checks() {
        let mut s = checks_for(Level::Strong).to_vec();
        s.sort();
        let mut want = vec![
            ANALYSER_HIGH,
            ANALYSER_OVERFLOW,
            TOWER_FLOOD,
            NEW_TOWER_IDENTITY,
            NEW_TOWER_RECUR,
        ];
        want.sort();
        assert_eq!(s, want);
        let a = checks_for(Level::All);
        assert_eq!(a.len(), 11);
        assert!(a.contains(&NEW_TOWER));
    }

    #[test]
    fn copy_is_exact_and_short() {
        let table = [
            (ANALYSER_HIGH, "Home alert (strong): suspicious cell activity near home"),
            (ANALYSER_OVERFLOW, "Home alert (strong): many suspicious cell warnings near home"),
            (TOWER_FLOOD, "Home alert (strong): many new cell towers at once near home"),
            (NEW_TOWER_IDENTITY, "Home alert (strong): new cell tower asked phones for ID"),
            (NEW_TOWER_RECUR, "Home alert (strong): new cell tower is back near home"),
            (NEW_TOWER, "Home notice: new cell tower near home"),
            (NEW_TOWER_WEAK, "Home notice: new cell tower near home (weak signal)"),
            (NEW_TOWER_SECTOR, "Home notice: new antenna on a known tower near home"),
            (IDENTITY_OFF_RHYTHM, "Home notice: phones asked for ID at an unusual time"),
            (FAILURE_SPIKE, "Home notice: unusual cell errors near home"),
            (ANALYSER_OTHER, "Home notice: minor cell warning near home"),
        ];
        for (c, t) in table {
            assert_eq!(text_for(c), Some(t));
            assert!(t.len() <= TEXT_MAX);
        }
        assert_eq!(QUIET_TEXT, "Home sentinel: all quiet");
        assert_eq!(TEST_TEXT, "Home sentinel: test message");
        assert!(text_for("decoder_failure").is_none());
        assert!(text_for("anything").is_none());
    }

    #[test]
    fn quiet_gap_bounds() {
        let now = Utc::now();
        let h = |d: DateTime<Utc>| (d - now).num_milliseconds() as f64 / 3_600_000.0;
        assert!((h(next_quiet(now, 3, 0).unwrap()) - 4.0).abs() < 1e-6);
        assert!((h(next_quiet(now, 3, u32::MAX).unwrap()) - 12.0).abs() < 1e-6);
        assert!((h(next_quiet(now, 3, u32::MAX / 2).unwrap()) - 8.0).abs() < 1.0 / 3600.0);
        assert!(next_quiet(now, 0, 5).is_none());
    }
    #[test]
    fn mesh_status_maps_errors() {
        use anyhow::anyhow;
        let open_err = anyhow::Error::new(std::io::Error::other("no such port")).context(link::NoRadio);
        assert_eq!(status_of(&Err(open_err)), MeshStatus::NoRadio);
        assert_eq!(status_of(&Err(link::HandshakeTimeout.into())), MeshStatus::NoAnswer);
        assert_eq!(status_of(&Err(anyhow!("write failed"))), MeshStatus::Error);
        assert_eq!(status_of(&Ok(2)), MeshStatus::Ok);
        let names: Vec<&str> =
            [MeshStatus::Off, MeshStatus::Ok, MeshStatus::NoRadio, MeshStatus::NoAnswer, MeshStatus::Error]
                .iter().map(|m| m.as_str()).collect();
        assert_eq!(names, ["off", "ok", "radio missing", "no answer", "error"]);
    }

    /// I1: the presence check publishes NoRadio while the port is gone, reports a change
    /// only when presence flips, and hands back the last real attempt when it returns.
    #[test]
    fn radio_presence_transitions() {
        use MeshStatus::*;
        // Missing (from present): NoRadio, one Gone.
        assert_eq!(radio_check(true, false, Ok), (NoRadio, Some(RadioChange::Gone)));
        // Still missing: NoRadio, no new change (so no second warning).
        assert_eq!(radio_check(false, false, Ok), (NoRadio, None));
        assert_eq!(radio_check(false, false, NoAnswer), (NoRadio, None));
        // Back: the last real attempt's status, one Back.
        assert_eq!(radio_check(false, true, NoAnswer), (NoAnswer, Some(RadioChange::Back)));
        assert_eq!(radio_check(false, true, Ok), (Ok, Some(RadioChange::Back)));
        // Back after a send was tried while it was gone: that NoRadio was about presence,
        // which this check now owns, so it must not outlive the replug.
        assert_eq!(radio_check(false, true, NoRadio), (Ok, Some(RadioChange::Back)));
        assert_eq!(radio_check(true, true, NoRadio), (Ok, None));
        // Present all along: the last attempt, quietly.
        assert_eq!(radio_check(true, true, Error), (Error, None));
        assert_eq!(radio_check(true, true, Ok), (Ok, None));
    }

    /// M1: just before sending, rows another stage meshed meanwhile are dropped, and a quiet
    /// ping built more than 5 minutes ago is dropped (its all-clear is stale).
    #[test]
    fn sendable_drops_meshed_rows_and_stale_pings() {
        let built = Utc::now();
        let batch = vec![
            (Some(1), "a".to_string()),
            (Some(2), "b".to_string()),
            (None, QUIET_TEXT.to_string()),
        ];
        let at = |min| built + Duration::minutes(min);
        assert_eq!(sendable(batch.clone(), &[1, 2], built, at(5)), batch, "all live, 5 min: kept");
        assert_eq!(
            sendable(batch.clone(), &[2], built, at(1)),
            [(Some(2), "b".to_string()), (None, QUIET_TEXT.to_string())]
        );
        assert_eq!(
            sendable(batch.clone(), &[1, 2], built, at(5) + Duration::seconds(1)),
            [(Some(1), "a".to_string()), (Some(2), "b".to_string())],
            "a ping built over 5 min ago is dropped; rows are not"
        );
        assert!(sendable(batch, &[], built, at(6)).is_empty());
    }

    #[test]
    fn opening_a_missing_port_is_no_radio() {
        let e = link::open("/dev/serial/by-id/does-not-exist").err().unwrap();
        assert_eq!(status_of(&Err(e)), MeshStatus::NoRadio);
    }


    #[test]
    fn every_strong_check_has_stage1_text() {
        for c in checks_for(Level::Strong) {
            let t = stage1_text(c).unwrap();
            assert!(t.starts_with(text_for(c).unwrap()) && t.ends_with(STAGE1_TAIL), "{c}");
        }
        assert!(stage1_text("nope").is_none());
    }

    #[test]
    fn stage1_texts_leave_room_for_the_bell() {
        for c in checks_for(Level::All) {
            assert!(stage1_text(c).unwrap().len() <= TEXT_MAX, "{c}");
        }
    }

    fn at(m: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap() + Duration::minutes(m)
    }

    #[test]
    fn text_hash_is_short_stable_and_ignores_the_bell() {
        let h = text_hash("Home alert");
        assert_eq!(h.len(), 12);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(h, text_hash("Home alert\u{7}"));
        assert_ne!(h, text_hash("Home alert!"));
        // sha256("Home alert"), first 12 hex digits: matches what the sent list holds.
        assert_eq!(h, &hex_sha256("Home alert")[..12]);
    }

    fn hex_sha256(t: &str) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(t.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn send_events_book_what_went_out_and_what_did_not() {
        let items = [
            ("stage1", Some(4), "Home alert"),
            ("quiet", None, QUIET_TEXT),
            ("notice", None, "Home notice"),
        ];
        let ev = send_events(&items, &Ok(2), at(0));
        let got: Vec<_> = ev.iter().map(|e| (e.kind, e.outcome, e.reason)).collect();
        assert_eq!(
            got,
            vec![
                ("stage1", Outcome::Sent, None),
                ("quiet", Outcome::Sent, None),
                ("notice", Outcome::Failed, Some("not_sent")),
            ]
        );
        assert_eq!(ev[0].alert_id, Some(4));
        assert!(ev[0].bell && !ev[1].bell, "the ping carries no bell");
        assert_eq!(ev[0].hash, text_hash("Home alert"));
        assert!(ev.iter().all(|e| e.at == at(0)));

        let none = send_events(&items, &Err(link::HandshakeTimeout.into()), at(1));
        assert!(none.iter().all(|e| e.outcome == Outcome::Failed && e.reason == Some("no_answer")));
        let no_port = anyhow::Error::new(std::io::Error::other("gone")).context(link::NoRadio);
        let gone = send_events(&items[..1], &Err(no_port), at(1));
        assert_eq!(gone[0].reason, Some("no_radio"));
        let other = send_events(&items[..1], &Err(anyhow::anyhow!("io")), at(1));
        assert_eq!(other[0].reason, Some("error"));
    }

    #[test]
    fn a_skipped_ping_is_a_record_without_text() {
        let e = skipped_ping(SKIP_ALERT_OPEN, at(3));
        assert_eq!((e.kind, e.outcome, e.reason, e.alert_id, e.bell), ("quiet", Outcome::Skipped, Some("alert_open"), None, false));
        assert_eq!(e.hash, text_hash(QUIET_TEXT));
        for r in [SKIP_ALERT_OPEN, SKIP_NOT_WATCHING, SKIP_QUIET_HOURS, SKIP_BUSY, SKIP_RADIO_BUSY, SKIP_STALE, SKIP_STORE_ERROR] {
            assert!(r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{r}");
        }
    }

    /// The longest gap the schedule allows (1.5 x the even spacing), plus 30 minutes.
    #[test]
    fn overdue_after_scales_with_pings_per_day() {
        assert_eq!(quiet_overdue_after(3), Some(Duration::minutes(12 * 60 + 30)));
        assert_eq!(quiet_overdue_after(1), Some(Duration::minutes(36 * 60 + 30)));
        assert_eq!(quiet_overdue_after(6), Some(Duration::minutes(6 * 60 + 30)));
        assert_eq!(quiet_overdue_after(0), None);
    }

    #[test]
    fn on_air_rings_the_bell_except_for_the_quiet_ping() {
        assert_eq!(on_air(QUIET_TEXT), QUIET_TEXT);
        assert_eq!(on_air("Home alert"), "Home alert\u{7}");
        assert_eq!(on_air(TEST_TEXT), format!("{TEST_TEXT}\u{7}"));
        assert_eq!(on_air("TEST: Update: x"), "TEST: Update: x\u{7}");
        // Never twice.
        assert_eq!(on_air("x\u{7}"), "x\u{7}");
        assert_eq!(TEXT_MAX + 1, wire::MAX_TEXT);
    }

    #[test]
    fn stage1_never_says_phones_off() {
        for c in checks_for(Level::All) {
            let t = stage1_text(c).unwrap().to_lowercase();
            for w in ["airplane", "phones off", "turn off"] {
                assert!(!t.contains(w), "{w} in {t}");
            }
        }
    }

    #[test]
    fn stage1_has_no_digits_runs() {
        for c in checks_for(Level::All) {
            let t = stage1_text(c).unwrap();
            let mut run = 0;
            for ch in t.chars() {
                run = if ch.is_ascii_digit() { run + 1 } else { 0 };
                assert!(run < 5, "{t}");
            }
        }
    }
}
