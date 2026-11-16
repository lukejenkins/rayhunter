//! Owner-page follow-up rules and the page model: pure logic, no I/O.

use crate::app::LiveState;
use crate::mqtt;
use crate::privacy;
use crate::store::{AdminItem, Alert, AlertEvent, CloseBy, RadioEntry};
use chrono::{DateTime, Duration, Local, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A TEST alert closed by `test` stays the page's target this long, so the flow can be
/// tried on hardware (a TEST alert closes itself at stage 1).
pub const TEST_PRACTICE_MIN: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    FalseAlarm,
    Watching,
    PhonesOff,
    AllClear,
}

fn hhmm(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%H:%M").to_string()
}

impl Kind {
    /// The preset text for this follow-up (HH:MM on the Yellow's local clock).
    pub fn preset(&self, alert: &Alert, now: DateTime<Utc>) -> String {
        match self {
            Kind::FalseAlarm => "Update: false alarm. Carry on as normal.".to_string(),
            Kind::Watching => format!(
                "Update: looking into it. Keep avoiding sensitive calls. Next update by {}.",
                hhmm(now + Duration::hours(1))
            ),
            Kind::PhonesOff => "Update: confirmed. Turn on airplane mode now (Wi-Fi is OK). Wait for the all clear."
                .to_string(),
            Kind::AllClear => format!(
                "All clear: no sign of it since {}. Phones back to normal.",
                hhmm(alert.last_seen_at)
            ),
        }
    }

    /// The radio-log name (same as the serde name).
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::FalseAlarm => "false_alarm",
            Kind::Watching => "watching",
            Kind::PhonesOff => "phones_off",
            Kind::AllClear => "all_clear",
        }
    }

    /// What sending this follow-up does to the alert. Nothing else ever changes.
    pub fn closes(&self) -> Option<CloseBy> {
        match self {
            Kind::FalseAlarm => Some(CloseBy::FalseAlarm),
            Kind::AllClear => Some(CloseBy::AllClear),
            Kind::Watching | Kind::PhonesOff => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub unlocked: bool,
    pub unlocks_at: Option<DateTime<Utc>>,
}

/// All clear unlocks once the live view is working and has seen nothing for `hours`.
/// A live view that cannot see (unplugged unit) never unlocks it.
pub fn all_clear_gate(alert: &Alert, live: LiveState, now: DateTime<Utc>, hours: i64) -> Gate {
    match live {
        LiveState::Ok { .. } => {
            let at = alert.last_seen_at + Duration::hours(hours);
            Gate {
                unlocked: now >= at,
                unlocks_at: Some(at),
            }
        }
        _ => Gate {
            unlocked: false,
            unlocks_at: None,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sighting {
    Now,
    NoSignSince(DateTime<Utc>),
    Unknown,
}

pub fn still_happening(
    alert: &Alert,
    live: LiveState,
    now: DateTime<Utc>,
    poll_secs: u64,
) -> Sighting {
    match live {
        LiveState::Ok { .. } => {
            if now - alert.last_seen_at <= Duration::seconds(3 * poll_secs as i64) {
                Sighting::Now
            } else {
                Sighting::NoSignSince(alert.last_seen_at)
            }
        }
        _ => Sighting::Unknown,
    }
}

/// The alert the page acts on, and whether it is a practice TEST: the open alert, else
/// a TEST alert closed by `test` less than `TEST_PRACTICE_MIN` minutes ago.
pub fn target(
    open: Option<Alert>,
    last: Option<Alert>,
    now: DateTime<Utc>,
) -> Option<(Alert, bool)> {
    if let Some(a) = open {
        return Some((a, false));
    }
    let a = last?;
    let fresh = a
        .closed_at
        .is_some_and(|c| now - c < Duration::minutes(TEST_PRACTICE_MIN) && now >= c);
    if a.closed_by.as_deref() == Some("test") && fresh {
        Some((a, true))
    } else {
        None
    }
}

/// A practice target's follow-up as it goes on air: trimmed and marked "TEST: ", unless
/// it already starts with "TEST" (any case). An empty text stays empty.
pub fn practice_text(text: &str) -> String {
    let t = text.trim();
    let marked = t.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("test"));
    if t.is_empty() || marked {
        t.to_string()
    } else {
        format!("TEST: {t}")
    }
}

/// What the page needs to know about the optional summary. Never the key or the model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SummaryInfo {
    pub enabled: bool,
    pub tokens_in: u64,
    pub tokens_out: u64,
}

pub struct PageInput {
    pub open: Option<Alert>,
    /// The target alert's events.
    pub events: Vec<AlertEvent>,
    pub last: Option<Alert>,
    /// The radio log, last 50.
    pub radio: Vec<RadioEntry>,
    /// Admin items, last 24 h.
    pub admin: Vec<AdminItem>,
    pub live: LiveState,
    pub now: DateTime<Utc>,
    pub poll_secs: u64,
    pub all_clear_hours: i64,
    pub mesh_on: bool,
    pub summary: SummaryInfo,
    /// `None`: quiet pings are off.
    pub quiet: Option<QuietInfo>,
}

/// The all-quiet ping line's inputs.
pub struct QuietInfo {
    pub per_day: u32,
    /// When the mesh output started (the add-on's start).
    pub started: DateTime<Utc>,
    /// `sent_since` counted from local midnight.
    pub status: crate::store::QuietStatus,
}

/// The ping line: the last sent ping, how many today, the newest record if it was not a
/// send, and whether no record at all has appeared for longer than the schedule allows.
fn quiet_json(q: &QuietInfo, now: DateTime<Utc>) -> Value {
    let s = &q.status;
    let missed = match &s.last {
        Some((at, outcome, reason)) if outcome != "sent" => {
            json!({"at": rfc(*at), "outcome": outcome, "reason": reason})
        }
        _ => Value::Null,
    };
    let since = s.last.as_ref().map_or(q.started, |l| l.0.max(q.started));
    let overdue = crate::mesh::quiet_overdue_after(q.per_day).is_some_and(|d| now - since > d);
    json!({
        "last_sent": s.last_sent.map(rfc),
        "sent_today": s.sent_since,
        "missed": missed,
        "overdue": overdue,
        "counted_from": rfc(since),
    })
}

fn rfc(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) fn is_strong(check: &str) -> bool {
    check == "test_alert" || crate::mesh::checks_for(crate::mesh::Level::Strong).contains(&check)
}

/// The JSON the owner page renders. Labels only: no event detail, tower key, recording
/// name or ID ever goes in.
pub fn page_state(i: &PageInput) -> Value {
    let tgt = target(i.open.clone(), i.last.clone(), i.now);
    let timeline: Vec<Value> = i
        .events
        .iter()
        .map(|e| json!({"at": rfc(e.at), "label": mqtt::label(&e.check_id), "timeline_only": e.timeline_only}))
        .collect();
    let sent: Vec<Value> = i
        .radio
        .iter()
        .map(|r| json!({"at": rfc(r.at), "kind": r.kind, "text": r.text}))
        .collect();
    let admin: Vec<Value> = i
        .admin
        .iter()
        .map(|a| json!({"at": rfc(a.at), "label": mqtt::label(&a.kind)}))
        .collect();

    let (status, gate, alert_id) = match &tgt {
        Some((a, practice)) => {
            let strong = *practice || i.events.iter().any(|e| is_strong(&e.check_id));
            let label = if *practice {
                "TEST"
            } else {
                i.events
                    .iter()
                    .rev()
                    .find(|e| !e.timeline_only)
                    .map_or("Alert", |e| mqtt::label(&e.check_id))
            };
            let sighting = match still_happening(a, i.live, i.now, i.poll_secs) {
                Sighting::Now => json!({"state": "now"}),
                Sighting::NoSignSince(t) => json!({"state": "no_sign_since", "since": rfc(t)}),
                Sighting::Unknown => json!({"state": "unknown"}),
            };
            let g = all_clear_gate(a, i.live, i.now, i.all_clear_hours);
            (
                json!({
                    "active": true, "test": practice, "label": label,
                    "strength": if strong { "strong" } else { "notice" },
                    "radio_sent": a.stage1_at.is_some(),
                    "first_seen": rfc(a.opened_at), "last_seen": rfc(a.last_seen_at),
                    "sighting": sighting,
                }),
                g,
                json!(a.id),
            )
        }
        None => (
            json!({
                "active": false, "test": false, "label": "All quiet", "strength": null,
                "radio_sent": false, "first_seen": null, "last_seen": null, "sighting": null,
            }),
            Gate {
                unlocked: false,
                unlocks_at: None,
            },
            Value::Null,
        ),
    };

    let presets = match &tgt {
        Some((a, practice)) => {
            let p = |k: Kind| {
                let t = k.preset(a, i.now);
                if *practice { practice_text(&t) } else { t }
            };
            json!({
                "false_alarm": p(Kind::FalseAlarm), "watching": p(Kind::Watching),
                "phones_off": p(Kind::PhonesOff), "all_clear": p(Kind::AllClear),
            })
        }
        None => Value::Null,
    };
    let quiet_since = match (&tgt, &i.last) {
        (None, Some(l)) => json!(rfc(l.last_finding_at)),
        _ => Value::Null,
    };
    json!({
        "status": status,
        "timeline": timeline,
        "sent": sent,
        "admin": admin,
        "gate": {"unlocked": gate.unlocked, "unlocks_at": gate.unlocks_at.map(rfc)},
        "presets": presets,
        "reminder": privacy::REMINDER,
        "mesh_on": i.mesh_on,
        "quiet_since": quiet_since,
        "quiet": i.quiet.as_ref().map(|q| quiet_json(q, i.now)),
        "alert_id": alert_id,
        "summary": {
            "enabled": i.summary.enabled,
            "tokens_in": i.summary.tokens_in,
            "tokens_out": i.summary.tokens_out,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::TEXT_MAX as MAX_TEXT;

    fn t(s: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + s, 0).unwrap()
    }
    fn alert(last_seen: DateTime<Utc>) -> Alert {
        Alert {
            id: 7,
            opened_at: last_seen - Duration::minutes(5),
            last_seen_at: last_seen,
            last_finding_at: last_seen,
            closed_at: None,
            closed_by: None,
            stage1_at: Some(last_seen),
        }
    }
    fn hhmm(x: DateTime<Utc>) -> String {
        x.with_timezone(&Local).format("%H:%M").to_string()
    }
    fn input(
        open: Option<Alert>,
        last: Option<Alert>,
        live: LiveState,
        now: DateTime<Utc>,
    ) -> PageInput {
        PageInput {
            open,
            events: vec![],
            last,
            radio: vec![],
            admin: vec![],
            live,
            now,
            poll_secs: 60,
            all_clear_hours: 3,
            mesh_on: true,
            summary: SummaryInfo::default(),
            quiet: None,
        }
    }

    fn quiet_input(now: DateTime<Utc>, started: DateTime<Utc>, status: crate::store::QuietStatus) -> PageInput {
        let mut i = input(None, None, LiveState::Off, now);
        i.quiet = Some(QuietInfo { per_day: 3, started, status });
        i
    }

    fn st(last: Option<(DateTime<Utc>, &str, Option<&str>)>, last_sent: Option<DateTime<Utc>>, n: u32) -> crate::store::QuietStatus {
        crate::store::QuietStatus {
            last: last.map(|(a, o, r)| (a, o.to_string(), r.map(str::to_string))),
            last_sent,
            sent_since: n,
        }
    }

    #[test]
    fn quiet_line_is_absent_when_pings_are_off() {
        let p = page_state(&input(None, None, LiveState::Off, Utc::now()));
        assert_eq!(p["quiet"], Value::Null);
    }

    #[test]
    fn quiet_line_shows_the_last_sent_and_a_later_miss() {
        let t0 = Utc::now();
        let h = |n: i64| t0 + chrono::Duration::hours(n);
        let p = page_state(&quiet_input(h(10), h(0), st(Some((h(9), "skipped", Some("alert_open"))), Some(h(5)), 2)));
        let q = &p["quiet"];
        assert_eq!(q["last_sent"], rfc(h(5)));
        assert_eq!(q["sent_today"], 2);
        assert_eq!(q["missed"], json!({"at": rfc(h(9)), "outcome": "skipped", "reason": "alert_open"}));
        assert_eq!(q["overdue"], false);
        // The newest record is a send: no miss to show.
        let p = page_state(&quiet_input(h(10), h(0), st(Some((h(9), "sent", None)), Some(h(9)), 1)));
        assert_eq!(p["quiet"]["missed"], Value::Null);
    }

    /// 3 a day: 12 h 30 m without any record (since it, or since the add-on started).
    #[test]
    fn quiet_line_warns_only_past_the_longest_allowed_gap() {
        let t0 = Utc::now();
        let m = |n: i64| t0 + chrono::Duration::minutes(n);
        let limit = 12 * 60 + 30;
        let rec = st(Some((m(0), "sent", None)), Some(m(0)), 0);
        assert_eq!(page_state(&quiet_input(m(limit), m(-60), rec.clone()))["quiet"]["overdue"], false);
        let p = page_state(&quiet_input(m(limit + 1), m(-60), rec.clone()));
        assert_eq!(p["quiet"]["overdue"], true);
        assert_eq!(p["quiet"]["counted_from"], rfc(m(0)));
        // A restart after the last record resets the clock.
        assert_eq!(page_state(&quiet_input(m(limit + 1), m(30), rec))["quiet"]["overdue"], false);
        // Never a record: counted from the start.
        let none = st(None, None, 0);
        assert_eq!(page_state(&quiet_input(m(limit), m(0), none.clone()))["quiet"]["overdue"], false);
        let p = page_state(&quiet_input(m(limit + 1), m(0), none));
        assert_eq!((p["quiet"]["overdue"].clone(), p["quiet"]["counted_from"].clone()), (json!(true), json!(rfc(m(0)))));
    }

    #[test]
    fn all_clear_locked_then_unlocks() {
        let now = t(0);
        let live = LiveState::Ok { at: now };
        let seen = now - Duration::hours(3) + Duration::minutes(1);
        let g = all_clear_gate(&alert(seen), live, now, 3);
        assert!(!g.unlocked);
        assert_eq!(g.unlocks_at, Some(seen + Duration::hours(3)));
        let g = all_clear_gate(&alert(now - Duration::hours(3)), live, now, 3);
        assert!(g.unlocked);
    }

    #[test]
    fn unknown_live_never_unlocks_all_clear() {
        let now = t(0);
        let live = LiveState::Unknown {
            since: now - Duration::hours(1),
        };
        let a = alert(now - Duration::hours(10));
        let g = all_clear_gate(&a, live, now, 3);
        assert!(!g.unlocked);
        assert_eq!(g.unlocks_at, None);
        assert_eq!(still_happening(&a, live, now, 60), Sighting::Unknown);
    }

    #[test]
    fn still_happening_window() {
        let now = t(0);
        let live = LiveState::Ok { at: now };
        let a = alert(now - Duration::seconds(170));
        assert_eq!(still_happening(&a, live, now, 60), Sighting::Now);
        let a = alert(now - Duration::seconds(190));
        assert_eq!(
            still_happening(&a, live, now, 60),
            Sighting::NoSignSince(now - Duration::seconds(190))
        );
    }

    #[test]
    fn presets_fill_times() {
        let now = t(0);
        let a = alert(now - Duration::hours(4));
        let w = Kind::Watching.preset(&a, now);
        assert!(w.contains(&hhmm(now + Duration::hours(1))), "{w}");
        let c = Kind::AllClear.preset(&a, now);
        assert!(c.contains(&hhmm(a.last_seen_at)), "{c}");
        assert_eq!(
            Kind::FalseAlarm.preset(&a, now),
            "Update: false alarm. Carry on as normal."
        );
        assert_eq!(
            Kind::PhonesOff.preset(&a, now),
            "Update: confirmed. Turn on airplane mode now (Wi-Fi is OK). Wait for the all clear."
        );
        for k in [
            Kind::FalseAlarm,
            Kind::Watching,
            Kind::PhonesOff,
            Kind::AllClear,
        ] {
            let p = k.preset(&a, now);
            assert!(privacy::check(&p).is_ok(), "{p}");
            assert!(p.len() <= MAX_TEXT);
        }
    }

    #[test]
    fn closes() {
        assert_eq!(Kind::FalseAlarm.closes(), Some(CloseBy::FalseAlarm));
        assert_eq!(Kind::AllClear.closes(), Some(CloseBy::AllClear));
        assert_eq!(Kind::Watching.closes(), None);
        assert_eq!(Kind::PhonesOff.closes(), None);
    }

    #[test]
    fn page_state_has_no_identifiers() {
        let now = t(0);
        let mut i = input(Some(alert(now)), None, LiveState::Ok { at: now }, now);
        i.events = vec![AlertEvent {
            at: now,
            check_id: "new_tower_identity".into(),
            detail: "ECI 87654321 PCI 77 EARFCN 55555".into(),
            towers: vec!["310-260-12345-87654321".into()],
            source: crate::store::Source::Live,
            recording: Some("1799999999-rec".into()),
            subject: "310-260-12345-87654321".into(),
            timeline_only: false,
        }];
        i.radio = vec![RadioEntry {
            at: now,
            kind: "followup".into(),
            text: "Update: looking into it.".into(),
            alert_id: Some(7),
        }];
        let v = page_state(&i);
        assert_eq!(v["sent"][0]["kind"], "followup");
        assert_eq!(v["sent"][0]["text"], "Update: looking into it.");
        let s = v.to_string();
        for bad in ["87654321", "55555", "310-260", "PCI", "1799999999-rec"] {
            assert!(!s.contains(bad), "{bad} leaked: {s}");
        }
        assert!(s.contains("New tower with identity request"));
    }

    #[test]
    fn page_state_practice_test() {
        let now = t(0);
        let mut last = alert(now - Duration::minutes(10));
        last.closed_at = Some(now - Duration::minutes(10));
        last.closed_by = Some("test".into());
        let v = page_state(&input(
            None,
            Some(last.clone()),
            LiveState::Ok { at: now },
            now,
        ));
        assert_eq!(v["status"]["active"], true);
        assert_eq!(v["status"]["test"], true);
        assert_eq!(v["alert_id"], 7);
        // The real gate: a TEST alert was last seen when it opened, so All clear stays
        // locked through the practice window and the override gets rehearsed.
        assert_eq!(v["gate"]["unlocked"], false);
        assert_eq!(
            v["gate"]["unlocks_at"],
            (last.last_seen_at + Duration::hours(3)).to_rfc3339_opts(SecondsFormat::Secs, true)
        );
        // Practice presets carry the TEST marker that goes on air.
        for k in ["false_alarm", "watching", "phones_off", "all_clear"] {
            let p = v["presets"][k].as_str().unwrap();
            assert!(p.starts_with("TEST: "), "{k}: {p}");
            assert!(p.len() <= MAX_TEXT);
        }
        let now = t(31 * 60);
        let v = page_state(&input(None, Some(last), LiveState::Ok { at: now }, now));
        assert_eq!(v["status"]["active"], false);
        assert_eq!(v["status"]["test"], false);
    }

    #[test]
    fn target_prefers_open() {
        let now = t(0);
        let mut last = alert(now - Duration::minutes(10));
        last.closed_at = Some(now - Duration::minutes(10));
        last.closed_by = Some("test".into());
        let open = alert(now);
        let (a, practice) = target(Some(open.clone()), Some(last), now).unwrap();
        assert_eq!(a, open);
        assert!(!practice);
        assert!(target(None, None, now).is_none());
    }

    #[test]
    fn target_practice_table() {
        let now = t(0);
        let case = |by: &str, closed: DateTime<Utc>| {
            let mut a = alert(closed);
            a.closed_at = Some(closed);
            a.closed_by = Some(by.into());
            target(None, Some(a), now).map(|(_, p)| p)
        };
        let s = Duration::seconds;
        assert_eq!(case("test", now - s(29 * 60 + 59)), Some(true));
        assert_eq!(case("test", now - s(30 * 60)), None);
        assert_eq!(case("test", now - s(30 * 60 + 1)), None);
        assert_eq!(case("false_alarm", now - s(120)), None);
        assert_eq!(case("all_clear", now - s(120)), None);
        assert_eq!(case("expired", now - s(120)), None);
        assert_eq!(case("test", now + s(60)), None);
    }

    #[test]
    fn page_state_unknown_live_open_alert() {
        let now = t(0);
        let live = LiveState::Unknown {
            since: now - Duration::hours(1),
        };
        let v = page_state(&input(
            Some(alert(now - Duration::hours(10))),
            None,
            live,
            now,
        ));
        assert_eq!(v["status"]["active"], true);
        assert_eq!(v["status"]["sighting"]["state"], "unknown");
        assert_eq!(v["gate"]["unlocked"], false);
        assert!(!v["presets"]["watching"].as_str().unwrap().starts_with("TEST"));
    }

    #[test]
    fn page_state_all_quiet() {
        let now = t(0);
        let mut last = alert(now - Duration::hours(5));
        last.closed_at = Some(now - Duration::hours(4));
        last.closed_by = Some("all_clear".into());
        let v = page_state(&input(
            None,
            Some(last.clone()),
            LiveState::Ok { at: now },
            now,
        ));
        assert_eq!(v["status"]["active"], false);
        assert_eq!(
            v["quiet_since"],
            last.last_finding_at
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        );
        assert_eq!(v["reminder"], privacy::REMINDER);
    }
}
