//! The scrubbed record behind the optional Claude summary (plan 4).
//!
//! This is the privacy boundary for the add-on's only call to an outside service. The
//! record is built from typed fields only, and **no type in it holds a `String`**: every
//! word is a `&'static str` out of a fixed table, so a detail text, tower key, recording
//! name or cell ID cannot reach it however the store's strings are filled. Times are whole
//! minutes relative to the alert's opening, never a clock time or date.

use crate::app::LiveState;
use crate::checks;
use crate::store::{Alert, AlertEvent, RadioEntry, Source};
use chrono::{DateTime, Utc};
use serde::Serialize;

/// The add-on watches one unit (`app::DEVICE_ID`).
const UNITS: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventRec {
    pub check: &'static str,
    /// `alert` for a check that can raise an alert, `admin` for a health check.
    pub class: &'static str,
    /// Whole minutes after the alert opened (never negative).
    pub minute: i64,
    pub source: &'static str,
    pub timeline_only: bool,
}

/// The numbers an alert is judged against. `profile` is passed in by the caller: the
/// store knows the learning start but not the configured learning days.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Baseline {
    pub identity_24h: u32,
    /// Mean per day over the 7 days before the last 24 h.
    pub identity_per_day_7d: f64,
    pub strong_alerts_30d: u32,
    /// `fixed`, `mobile` or `learning`.
    pub profile: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Record {
    /// A practice TEST target: the model must not treat a drill as real.
    pub practice: bool,
    pub age_min: i64,
    pub last_seen_min: i64,
    /// `ok`, `unknown`, `not_recording` or `off`.
    pub live: &'static str,
    pub event_count: u32,
    pub events: Vec<EventRec>,
    /// Follow-ups already sent, by kind name only.
    pub sent: Vec<&'static str>,
    pub baseline: Baseline,
    pub units: u32,
}

/// Known check ids map to their `checks::` constant; anything else is `"other"`.
pub fn known_check(id: &str) -> &'static str {
    const KNOWN: [&str; 15] = [
        checks::ANALYSER_OVERFLOW,
        checks::ANALYSER_HIGH,
        checks::ANALYSER_OTHER,
        checks::NEW_TOWER,
        checks::NEW_TOWER_IDENTITY,
        checks::NEW_TOWER_RECUR,
        checks::NEW_TOWER_WEAK,
        checks::NEW_TOWER_SECTOR,
        checks::IDENTITY_OFF_RHYTHM,
        checks::FAILURE_SPIKE,
        checks::DECODER_FAILURE,
        checks::ARCHIVE_CORRUPT,
        checks::ARCHIVE_MISSING,
        checks::TOWER_FLOOD,
        TEST_ALERT,
    ];
    KNOWN.iter().copied().find(|k| *k == id).unwrap_or("other")
}

/// The check id of the one-shot TEST alert.
const TEST_ALERT: &str = "test_alert";

fn class_of(id: &'static str) -> &'static str {
    // One rule with the owner page: strong checks (and the TEST alert) are alerts.
    if crate::followup::is_strong(id) {
        "alert"
    } else {
        "admin"
    }
}

fn live_word(l: LiveState) -> &'static str {
    match l {
        LiveState::Off => "off",
        LiveState::Ok { .. } => "ok",
        LiveState::Unknown { .. } => "unknown",
        LiveState::NotRecording => "not_recording",
    }
}

/// The radio log's kind, through a fixed table (Ruling 2); never the text.
fn sent_kind(kind: &str) -> &'static str {
    match kind {
        "false_alarm" => "false_alarm",
        "watching" => "watching",
        "phones_off" => "phones_off",
        "all_clear" => "all_clear",
        "all_clear_override" => "all_clear_override",
        "stage1" => "stage1",
        "test" => "test",
        _ => "other",
    }
}

/// The profile word for a baseline: `learning` while Fixed is still learning.
pub fn profile_word(profile: &str, learning: bool) -> &'static str {
    match (profile, learning) {
        ("fixed", true) => "learning",
        ("fixed", false) => "fixed",
        _ => "mobile",
    }
}

pub fn record(
    alert: &Alert,
    events: &[AlertEvent],
    sent: &[RadioEntry],
    live: LiveState,
    base: &Baseline,
    practice: bool,
    now: DateTime<Utc>,
) -> Record {
    let mins = |d: chrono::Duration| d.num_minutes().max(0);
    let events: Vec<EventRec> = events
        .iter()
        .map(|e| {
            let check = known_check(&e.check_id);
            EventRec {
                check,
                class: class_of(check),
                minute: mins(e.at - alert.opened_at),
                source: match e.source {
                    Source::Live => "live",
                    Source::Closed => "closed",
                },
                timeline_only: e.timeline_only,
            }
        })
        .collect();
    Record {
        practice,
        age_min: mins(now - alert.opened_at),
        last_seen_min: mins(now - alert.last_seen_at),
        live: live_word(live),
        event_count: events.len() as u32,
        events,
        sent: sent.iter().map(|r| sent_kind(&r.kind)).collect(),
        baseline: base.clone(),
        units: UNITS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use chrono::{Duration, TimeZone};
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap()
    }

    fn alert() -> Alert {
        Alert {
            id: 7,
            opened_at: t0(),
            last_seen_at: t0() + Duration::minutes(3),
            last_finding_at: t0(),
            closed_at: None,
            closed_by: None,
            stage1_at: None,
        }
    }

    fn ev(check: &str, secs: i64, detail: &str) -> AlertEvent {
        AlertEvent {
            at: t0() + Duration::seconds(secs),
            check_id: check.to_string(),
            detail: detail.to_string(),
            towers: vec!["310-260-12345-87654321".into()],
            source: Source::Live,
            recording: Some("1792943418".into()),
            subject: "310-260-12345-87654321".into(),
            timeline_only: false,
        }
    }

    fn rfc(t: DateTime<Utc>) -> String {
        t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    }

    fn base() -> Baseline {
        Baseline {
            identity_24h: 3,
            identity_per_day_7d: 1.5,
            strong_alerts_30d: 2,
            profile: "fixed",
        }
    }

    fn radio(kind: &str, text: &str) -> RadioEntry {
        RadioEntry {
            at: t0(),
            kind: kind.into(),
            text: text.into(),
            alert_id: Some(7),
        }
    }

    fn rec(events: &[AlertEvent], sent: &[RadioEntry]) -> Record {
        record(
            &alert(),
            events,
            sent,
            LiveState::Ok { at: t0() },
            &base(),
            false,
            t0() + Duration::minutes(10),
        )
    }

    fn keys(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    out.insert(k.clone());
                    keys(v, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|v| keys(v, out)),
            _ => {}
        }
    }

    #[test]
    fn record_has_only_allowlisted_fields() {
        let detail = "IMSI 310260123456789 IMEI 35123456789012 ECI 87654321 PCI 77 EARFCN 55555 TAC 12345 PLMN 310-260 at 12.34,-123.45";
        let events = [
            ev("new_tower_identity", 0, detail),
            ev("zzz_unknown", 30, detail),
        ];
        let sent = [radio("all_clear", "All clear 310260123456789")];
        let r = rec(&events, &sent);
        let json = serde_json::to_string(&r).unwrap();
        for bad in [
            "310260",
            "356938",
            "87654321",
            "55555",
            "12345",
            "310-260",
            "12.34",
            "1792943418",
            "IMSI",
            "PCI",
        ] {
            assert!(!json.contains(bad), "{bad} leaked: {json}");
        }
        let v: Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["events"][0]["check"], "new_tower_identity");
        assert_eq!(v["events"][1]["check"], "other");
        let mut got = BTreeSet::new();
        keys(&v, &mut got);
        let want: BTreeSet<String> = [
            "practice",
            "age_min",
            "last_seen_min",
            "live",
            "event_count",
            "events",
            "check",
            "class",
            "minute",
            "source",
            "timeline_only",
            "sent",
            "baseline",
            "identity_24h",
            "identity_per_day_7d",
            "strong_alerts_30d",
            "profile",
            "units",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn record_times_are_relative_minutes() {
        let events = [
            ev("new_tower", 0, "a"),
            ev("new_tower", 90, "b"),
            ev("new_tower", 3600, "c"),
        ];
        let r = rec(&events, &[]);
        let m: Vec<i64> = r.events.iter().map(|e| e.minute).collect();
        assert_eq!(m, [0, 1, 60]);
        assert_eq!((r.age_min, r.last_seen_min), (10, 7));
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("2026") && !json.contains('T'), "{json}");
        assert!(
            !json
                .as_bytes()
                .windows(3)
                .any(|w| w[0].is_ascii_digit() && w[1] == b':' && w[2].is_ascii_digit()),
            "{json}"
        );
    }

    #[test]
    fn sent_follow_ups_are_kinds_only() {
        let sent = [
            radio("all_clear", "All clear: no sign of it since 02:07..."),
            radio("stage1", "Home sentinel TEST"),
            radio("test", "x"),
            radio("weird_new_kind", "y"),
        ];
        let r = rec(&[], &sent);
        assert_eq!(r.sent, ["all_clear", "stage1", "test", "other"]);
        assert!(!serde_json::to_string(&r).unwrap().contains("02:07"));
    }

    #[test]
    fn practice_flag_and_classes() {
        let events = [
            ev("test_alert", 0, ""),
            ev("decoder_failure", 0, ""),
            ev("tower_flood", 0, ""),
        ];
        let r = record(&alert(), &events, &[], LiveState::Off, &base(), true, t0());
        assert!(r.practice);
        assert_eq!(r.live, "off");
        let c: Vec<&str> = r.events.iter().map(|e| e.class).collect();
        assert_eq!(c, ["alert", "admin", "alert"]);
        let class = |id: &str| rec(&[ev(id, 0, "")], &[]).events[0].class;
        for id in [
            "identity_off_rhythm",
            "failure_spike",
            "new_tower",
            "new_tower_weak",
            "new_tower_sector",
            "analyser_other",
        ] {
            assert_eq!(class(id), "admin", "{id}");
        }
        for id in [
            "analyser_high",
            "analyser_overflow",
            "tower_flood",
            "new_tower_identity",
            "new_tower_recur",
            "test_alert",
        ] {
            assert_eq!(class(id), "alert", "{id}");
        }
    }

    #[test]
    fn baseline_counts() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        let now = t0();
        let ident = |dev: &str, n: i64, ago: Duration| {
            s.test_exec(
                "INSERT INTO identity_requests (device, name, start, seq, ts, profile) VALUES (?1, 'r', 's', ?2, ?3, 'fixed')",
                &[dev, &n.to_string(), &rfc(now - ago)],
            );
        };
        // 2 in the last 24 h; 14 over the 7 days before (2/day); 5 older; unit2 ignored.
        ident("m2100", 1, Duration::hours(1));
        ident("m2100", 2, Duration::hours(23));
        for i in 0..14 {
            ident("m2100", 10 + i, Duration::hours(25 + i * 11));
        }
        for i in 0..5 {
            ident("m2100", 100 + i, Duration::days(20 + i));
        }
        // Boundaries: exactly 24 h old is the last 24 h (not also the week); exactly 8 d old
        // is the week's oldest instant; a second older is out.
        ident("m2100", 300, Duration::hours(24));
        ident("m2100", 301, Duration::days(8));
        ident("m2100", 302, Duration::days(8) + Duration::seconds(1));
        ident("unit2", 200, Duration::hours(2));
        let alert_row = |dev: &str, id: i64, ago: Duration, check: &str| {
            let at = rfc(now - ago);
            s.test_exec(
                "INSERT INTO alerts (id, device, opened_at, last_seen_at, last_finding_at) VALUES (?1, ?2, ?3, ?3, ?3)",
                &[&id.to_string(), dev, &at],
            );
            s.test_exec(
                "INSERT INTO alert_events (alert_id, at, check_id, detail, towers, source) VALUES (?1, ?2, ?3, '', '[]', 'live')",
                &[&id.to_string(), &at, check],
            );
        };
        alert_row("m2100", 1, Duration::days(2), "new_tower_identity");
        alert_row("m2100", 2, Duration::days(29), "tower_flood");
        alert_row("m2100", 3, Duration::days(35), "new_tower_identity"); // too old
        alert_row("m2100", 4, Duration::days(3), "new_tower"); // not strong
        alert_row("m2100", 5, Duration::days(1), "test_alert"); // a drill
        alert_row("m2100", 7, Duration::days(30), "new_tower_identity"); // exactly 30 d: in
        alert_row(
            "m2100",
            8,
            Duration::days(30) + Duration::seconds(1),
            "tower_flood",
        ); // out
        alert_row("m2100", 9, Duration::zero(), "new_tower_recur"); // opened now: in
        alert_row("unit2", 6, Duration::days(1), "new_tower_identity");
        let b = s.summary_baseline("m2100", now, "learning").unwrap();
        assert_eq!(b.identity_24h, 3);
        assert!(
            (b.identity_per_day_7d - 15.0 / 7.0).abs() < 1e-9,
            "{}",
            b.identity_per_day_7d
        );
        assert_eq!(b.strong_alerts_30d, 4);
        assert_eq!(b.profile, "learning");
    }

    #[test]
    fn profile_words() {
        assert_eq!(profile_word("fixed", true), "learning");
        assert_eq!(profile_word("fixed", false), "fixed");
        assert_eq!(profile_word("mobile", false), "mobile");
    }
}
