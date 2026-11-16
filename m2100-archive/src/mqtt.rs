//! Home Assistant MQTT layer: discovery payloads, state messages and the "go to Fixed"
//! button handler. Pure data in, data out; the client connection lives elsewhere.
//!
//! Nothing here may carry a cell, PCI, EARFCN, band, PLMN or signal field.
#![allow(dead_code)]

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};

use crate::device::{Device, DeviceError};
use crate::health::Health;
use crate::puller::Outcome;
use crate::store::{Pending, Report};

const HA_NAME: &str = "Rayhunter archive (unit 1)";
/// Published for a timestamp sensor that has no value yet. HA's MQTT sensor treats the
/// literal "None" as "unknown" (an empty string or "unknown" fails timestamp parsing).
const NO_VALUE: &str = "None";

fn base(device_id: &str) -> String {
    format!("rayhunter_archive/{device_id}")
}

pub fn fixed_press_topic(device_id: &str) -> String {
    format!("{}/fixed/press", base(device_id))
}

/// The state message for the "last Fixed request" sensor (one of `press_fixed`'s strings).
pub fn fixed_state(device_id: &str, result: &str) -> (String, String) {
    (format!("{}/fixed/last", base(device_id)), result.to_string())
}

/// The event types the "Rayhunter finding" entity declares: every check that can notify.
pub const EVENT_TYPES: [&str; 15] = [
    "analyser_high", "analyser_overflow", "new_tower_identity", "new_tower_recur",
    "identity_off_rhythm", "failure_spike", "decoder_failure", "archive_corrupt", "tower_flood",
    "live_unknown", "not_recording", "low_disk", "decoding_off", "live_unconfirmed",
    "test_alert",
];

/// Admin event kinds: notices about the sentinel itself, not about a capture.
const ADMIN_KINDS: [&str; 6] = [
    "live_unknown", "not_recording", "low_disk", "decoding_off", "live_unconfirmed",
    "test_alert",
];

/// An admin notice on the finding topic, with the same fields as `finding_event`.
/// `admin: true` (absent on findings) makes the HA package render it as
/// "{label} · HH:MM", without capture text. `None` for a kind that is not an admin type.
pub fn admin_event(
    device_id: &str,
    kind: &str,
    profile: &str,
    now: DateTime<Utc>,
) -> Option<(String, String)> {
    if !ADMIN_KINDS.contains(&kind) {
        return None;
    }
    let v = json!({
        "event_type": kind,
        "label": label(kind),
        "capture": "",
        "profile": profile,
        "admin": true,
        "switched": false,
        "count": 1,
        "found": now.to_rfc3339_opts(SecondsFormat::Secs, true),
        "towers": Value::Null,
    });
    Some((finding_topic(device_id), v.to_string()))
}

pub fn finding_topic(device_id: &str) -> String {
    format!("{}/finding", base(device_id))
}

/// Capture names come from the unit (untrusted): rayhunter names them by number, so
/// anything but 1 to 12 ASCII digits is not shown. A name that is a cell identity with
/// its separators (310-260-…) or text is refused; digits alone can still carry data.
pub fn safe_name(name: &str) -> &str {
    let ok = (1..=12).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_digit());
    if ok { name } else { "?" }
}

pub fn label(check: &str) -> &'static str {
    match check {
        "analyser_high" => "Analyser High warning",
        "analyser_overflow" => "Too many analysers (decoder suspect)",
        "new_tower" => "New tower",
        "new_tower_identity" => "New tower with identity request",
        "new_tower_recur" => "New tower seen again",
        "identity_off_rhythm" => "Identity request off rhythm",
        "failure_spike" => "Decode failure spike",
        "decoder_failure" => "Decoder failure",
        "archive_corrupt" => "Archive corrupt",
        "tower_flood" => "Tower flood",
        "live_unknown" => "Live view unavailable",
        "not_recording" => "Unit not recording",
        "low_disk" => "Unit storage nearly full",
        "decoding_off" => "Decoding paused",
        "live_unconfirmed" => "Live alert not confirmed by full capture",
        "test_alert" => "Home sentinel TEST alert",
        _ => "Finding",
    }
}

/// "known" / "unknown" for the capture's towers, left out (null) where it says nothing:
/// a new tower or a flood is unknown by definition, and a capture with no fully
/// identified tower cannot be matched.
fn towers_word(check: &str, known: Option<bool>) -> Option<&'static str> {
    match (check, known) {
        ("new_tower" | "new_tower_identity" | "new_tower_recur" | "tower_flood", _) => None,
        (_, Some(true)) => Some("known"),
        (_, Some(false)) => Some("unknown"),
        (_, None) => None,
    }
}

/// One finding event. Built from the outbox row only: the stored detail never gets here.
/// `None` for a check HA was not told about (it would reject the event type).
pub fn finding_event(device_id: &str, p: &Pending) -> Option<(String, String)> {
    if !EVENT_TYPES.contains(&p.check.as_str()) {
        return None;
    }
    let v = json!({
        "event_type": p.check,
        "label": label(&p.check),
        "capture": safe_name(&p.name),
        "profile": p.profile,
        "switched": p.spans_switch,
        "count": p.count,
        "found": p.found_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        "towers": towers_word(&p.check, p.towers_known),
    });
    Some((finding_topic(device_id), v.to_string()))
}

struct Sensor {
    key: &'static str,
    name: &'static str,
    component: &'static str,
    device_class: Option<&'static str>,
    state_class: Option<&'static str>,
    unit: Option<&'static str>,
}

const fn s(
    key: &'static str,
    name: &'static str,
    device_class: Option<&'static str>,
    state_class: Option<&'static str>,
    unit: Option<&'static str>,
) -> Sensor {
    Sensor { key, name, component: "sensor", device_class, state_class, unit }
}

const fn b(key: &'static str, name: &'static str, device_class: Option<&'static str>) -> Sensor {
    Sensor { key, name, component: "binary_sensor", device_class, state_class: None, unit: None }
}

/// Only when the mesh output is configured: the sentinel's own sending, nothing heard.
fn mesh_sensors() -> Vec<Sensor> {
    vec![
        s("mesh_status", "Mesh status", None, None, None),
        s("mesh_last_sent", "Mesh last sent", Some("timestamp"), None, None),
        s("mesh_sent_24h", "Mesh messages (24 h)", None, Some("measurement"), None),
    ]
}

fn sensors() -> Vec<Sensor> {
    let m = Some("measurement");
    vec![
        s("backlog", "Backlog", None, m, None),
        s("oldest_backlog", "Oldest backlog", Some("timestamp"), None, None),
        s("last_pull", "Last successful pull", Some("timestamp"), None, None),
        s("last_rotation", "Last rotation", Some("timestamp"), None, None),
        s("mismatches", "Hash mismatches", None, Some("total_increasing"), None),
        s("gap_24h", "Recording gap (24 h)", Some("duration"), m, Some("min")),
        s("longest_gap_24h", "Longest recording gap (24 h)", Some("duration"), m, Some("min")),
        s("archive_mb", "Archive size", Some("data_size"), m, Some("MB")),
        s("free_gb", "Yellow free", Some("data_size"), m, Some("GB")),
        s("days_covered", "Days covered", None, m, Some("d")),
        b("paused", "Pulling paused", Some("problem")),
        s("fixed/last", "Last Fixed request", None, None, None),
        s("findings/analyser_high_24h", "Analyser High warnings (24 h)", None, m, None),
        s("findings/analyser_other_24h", "Analyser other warnings (24 h)", None, m, None),
        s("findings/new_towers_24h", "New towers (24 h)", None, m, None),
        s("findings/off_rhythm_24h", "Identity requests off rhythm (24 h)", None, m, None),
        s("findings/failure_spikes_24h", "Decode failure spikes (24 h)", None, m, None),
        s("findings/decoder_failures_24h", "Decoder failures (24 h)", None, m, None),
        s("findings/archive_corrupt_24h", "Archive corrupt (24 h)", None, m, None),
        s("findings/towers_seen_24h", "Towers seen (24 h)", None, m, None),
        b("decoder_unavailable", "Decoder unavailable", Some("problem")),
        b("baseline_learning", "Fixed baseline learning", None),
    ]
}

/// Retained HA discovery messages: `(topic, json)`.
pub fn discovery(device_id: &str, mesh: bool) -> Vec<(String, String)> {
    let b = base(device_id);
    let dev = json!({"identifiers": [format!("rh_archive_{device_id}")], "name": HA_NAME});
    let mut out = Vec::new();
    for x in sensors().into_iter().chain(if mesh { mesh_sensors() } else { Vec::new() }) {
        let obj = x.key.replace('/', "_");
        let mut p = json!({
            "name": x.name,
            "unique_id": format!("rh_archive_{device_id}_{obj}"),
            "state_topic": format!("{b}/{}", x.key),
            "device": dev,
        });
        let m = p.as_object_mut().unwrap();
        if let Some(v) = x.device_class {
            m.insert("device_class".into(), v.into());
        }
        if let Some(v) = x.state_class {
            m.insert("state_class".into(), v.into());
        }
        if let Some(v) = x.unit {
            m.insert("unit_of_measurement".into(), v.into());
        }
        if x.component == "binary_sensor" {
            m.insert("payload_on".into(), "ON".into());
            m.insert("payload_off".into(), "OFF".into());
        }
        out.push((
            format!("homeassistant/{}/rh_archive_{device_id}/{obj}/config", x.component),
            p.to_string(),
        ));
    }
    let event: Value = json!({
        "name": "Rayhunter finding",
        "unique_id": format!("rh_archive_{device_id}_finding"),
        "state_topic": finding_topic(device_id),
        "event_types": EVENT_TYPES,
        "device": dev,
    });
    out.push((
        format!("homeassistant/event/rh_archive_{device_id}/finding/config"),
        event.to_string(),
    ));
    let button: Value = json!({
        "name": "Rayhunter: go to Fixed",
        "unique_id": format!("rh_archive_{device_id}_fixed_button"),
        "command_topic": fixed_press_topic(device_id),
        "device": dev,
    });
    out.push((
        format!("homeassistant/button/rh_archive_{device_id}/fixed_button/config"),
        button.to_string(),
    ));
    out
}

fn ts(t: Option<DateTime<Utc>>) -> String {
    t.map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| NO_VALUE.to_string())
}

/// State messages for the sensors above, except "last Fixed request" (see `fixed_state`).
pub fn states(
    device_id: &str,
    o: &Outcome,
    h: &Health,
    mismatches_total: u32,
    last_pull: Option<DateTime<Utc>>,
) -> Vec<(String, String)> {
    let b = base(device_id);
    let mins = |d: chrono::Duration| ((d.num_seconds() as f64 / 60.0).round() as i64).to_string();
    let t = |k: &str, v: String| (format!("{b}/{k}"), v);
    vec![
        t("backlog", o.backlog.to_string()),
        t("oldest_backlog", ts(o.oldest_backlog)),
        t("last_pull", ts(last_pull)),
        t("mismatches", mismatches_total.to_string()),
        t("gap_24h", mins(h.gap_24h)),
        t("longest_gap_24h", mins(h.longest_gap_24h)),
        t("archive_mb", format!("{:.0}", h.archive_bytes as f64 / 1e6)),
        t("free_gb", format!("{:.1}", h.free_bytes as f64 / 1e9)),
        t("days_covered", format!("{:.1}", h.days_covered)),
        t("paused", if h.paused { "ON" } else { "OFF" }.to_string()),
    ]
}

/// The "Last rotation" sensor: the last successful capture rotation, Yellow clock.
pub fn rotation_state(device_id: &str, last: Option<DateTime<Utc>>) -> (String, String) {
    (format!("{}/last_rotation", base(device_id)), ts(last))
}

/// The three mesh sensors: status, newest send, sends in the last 24 h.
pub fn mesh_states(
    device_id: &str,
    status: crate::mesh::MeshStatus,
    sent_24h: u32,
    last_sent: Option<DateTime<Utc>>,
) -> Vec<(String, String)> {
    let b = base(device_id);
    vec![
        (format!("{b}/mesh_status"), status.as_str().to_string()),
        (format!("{b}/mesh_last_sent"), ts(last_sent)),
        (format!("{b}/mesh_sent_24h"), sent_24h.to_string()),
    ]
}

/// The decoder flag: kept apart from `report_states` so a failed report cannot hide it.
pub fn decoder_state(device_id: &str, unavailable: bool) -> (String, String) {
    let v = if unavailable { "ON" } else { "OFF" };
    (format!("{}/decoder_unavailable", base(device_id)), v.to_string())
}

/// State messages for the findings sensors and the baseline flag.
pub fn report_states(device_id: &str, r: &Report) -> Vec<(String, String)> {
    let b = base(device_id);
    let t = |k: &str, v: String| (format!("{b}/{k}"), v);
    let onoff = |on: bool| if on { "ON" } else { "OFF" }.to_string();
    vec![
        t("findings/analyser_high_24h", r.analyser_high.to_string()),
        t("findings/analyser_other_24h", r.analyser_other.to_string()),
        t("findings/new_towers_24h", r.new_towers.to_string()),
        t("findings/off_rhythm_24h", r.off_rhythm.to_string()),
        t("findings/failure_spikes_24h", r.failure_spikes.to_string()),
        t("findings/decoder_failures_24h", r.decoder_failures.to_string()),
        t("findings/archive_corrupt_24h", r.archive_corrupt.to_string()),
        t("findings/towers_seen_24h", r.towers_seen.to_string()),
        t("baseline_learning", onoff(r.learning)),
    ]
}

/// Handle the button press. Returns one of "ok", "failed", "refused", "busy",
/// "not paired", "unreachable". `NotFound` and `Bad(_)` both map to "failed".
pub async fn press_fixed(dev: &dyn Device, token: Option<&str>) -> &'static str {
    let token = match token.map(str::trim) {
        Some(t) if !t.is_empty() => t,
        _ => return "not paired",
    };
    match dev.fixed(token).await {
        Ok(true) => "ok",
        Ok(false) => "failed",
        Err(DeviceError::Refused) => "refused",
        Err(DeviceError::Busy) => "busy",
        Err(DeviceError::Unreachable) => "unreachable",
        Err(DeviceError::NotFound) | Err(DeviceError::Bad(_)) => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Fake;
    use chrono::Duration;

    fn health() -> Health {
        Health {
            archive_bytes: 1_234_567_890,
            free_bytes: 52_340_000_000,
            days_covered: 3.456,
            gap_24h: Duration::seconds(95),
            longest_gap_24h: Duration::minutes(40),
            paused: true,
        }
    }

    fn all_states() -> Vec<(String, String)> {
        let o = Outcome {
            backlog: 4,
            oldest_backlog: DateTime::from_timestamp(1_700_000_000, 0),
            ..Default::default()
        };
        let mut v = states("u1", &o, &health(), 2, None);
        v.push(fixed_state("u1", "ok"));
        v.extend(report_states("u1", &report()));
        v.push(decoder_state("u1", false));
        v.push(rotation_state("u1", DateTime::from_timestamp(1_791_958_000, 0)));
        v.extend(mesh_states("u1", crate::mesh::MeshStatus::NoAnswer, 3, DateTime::from_timestamp(1_791_958_000, 0)));
        v
    }

    fn report() -> crate::store::Report {
        crate::store::Report {
            analyser_high: 1, analyser_other: 2, off_rhythm: 3, failure_spikes: 4,
            decoder_failures: 5, archive_corrupt: 6, new_towers: 7, towers_seen: 8, learning: true,
        }
    }

    fn pending(name: &str, check: &str) -> crate::store::Pending {
        crate::store::Pending {
            id: 1, name: name.into(), check: check.into(), count: 2, profile: "fixed".into(),
            spans_switch: true, found_at: DateTime::from_timestamp(1_791_778_437, 0).unwrap(),
            towers_known: Some(true),
        }
    }

    #[test]
    fn discovery_is_consistent_with_states() {
        let d = discovery("u1", true);
        let st = all_states();
        let mut ids = std::collections::HashSet::new();
        let mut buttons = 0;
        let mut events = 0;
        for (topic, body) in &d {
            let v: Value = serde_json::from_str(body).unwrap();
            assert!(topic.starts_with("homeassistant/") && topic.ends_with("/config"));
            let id = v["unique_id"].as_str().unwrap();
            assert!(id.starts_with("rh_archive_u1_"));
            assert!(ids.insert(id.to_string()), "duplicate {id}");
            assert_eq!(v["device"]["name"], "Rayhunter archive (unit 1)");
            if topic.contains("/button/") {
                buttons += 1;
                assert_eq!(v["command_topic"], "rayhunter_archive/u1/fixed/press");
            } else if topic.contains("/event/") {
                events += 1;
                assert_eq!(v["state_topic"], finding_topic("u1"));
                assert_eq!(v["event_types"], json!(EVENT_TYPES));
            } else {
                let t = v["state_topic"].as_str().unwrap();
                assert!(st.iter().any(|(k, _)| k == t), "no state for {t}");
            }
        }
        assert_eq!(buttons, 1);
        assert_eq!(events, 1);
        assert_eq!(d.len(), 13 + 10 + 1 + 3);
        for (k, _) in &st {
            assert!(
                d.iter().any(|(_, b)| b.contains(&format!("\"{k}\""))),
                "undiscovered {k}"
            );
        }
    }

    #[test]
    fn mesh_sensors_only_when_mesh_is_on() {
        let on = discovery("u1", true);
        let off = discovery("u1", false);
        assert_eq!(on.len(), off.len() + 3);
        assert!(off.iter().all(|(t, _)| !t.contains("mesh_")));
        let find = |k: &str| {
            let (_, b) = on.iter().find(|(t, _)| t.ends_with(&format!("/{k}/config"))).unwrap();
            serde_json::from_str::<Value>(b).unwrap()
        };
        let (st, ls, n) = (find("mesh_status"), find("mesh_last_sent"), find("mesh_sent_24h"));
        assert_eq!(st["name"], "Mesh status");
        assert!(st.get("device_class").is_none());
        assert_eq!((ls["name"].as_str(), ls["device_class"].as_str()), (Some("Mesh last sent"), Some("timestamp")));
        assert_eq!((n["name"].as_str(), n["state_class"].as_str()), (Some("Mesh messages (24 h)"), Some("measurement")));
        assert!(n.get("device_class").is_none());
        let v: std::collections::HashMap<_, _> = mesh_states("u1", crate::mesh::MeshStatus::NoRadio, 4, None).into_iter().collect();
        assert_eq!(v["rayhunter_archive/u1/mesh_status"], "radio missing");
        assert_eq!(v["rayhunter_archive/u1/mesh_last_sent"], "None");
        assert_eq!(v["rayhunter_archive/u1/mesh_sent_24h"], "4");
    }

    #[test]
    fn no_radio_fields_anywhere() {
        let mut texts: Vec<String> =
            discovery("u1", true).into_iter().flat_map(|(t, b)| [t, b]).collect();
        texts.extend(all_states().into_iter().flat_map(|(t, b)| [t, b]));
        for c in EVENT_TYPES {
            let (t, b) = finding_event("u1", &pending("1791778208", c)).unwrap();
            texts.extend([t, b, label(c).to_string()]);
        }
        texts.push(label("other").to_string());
        for t in texts {
            let l = t.to_lowercase();
            for w in ["cell", "pci", "earfcn", "band", "plmn", "signal", "rsrp", "rsrq"] {
                assert!(!l.contains(w), "{w} in {t}");
            }
        }
    }

    #[test]
    fn state_values() {
        let st: std::collections::HashMap<_, _> = all_states().into_iter().collect();
        let g = |k: &str| st[&format!("rayhunter_archive/u1/{k}")].clone();
        assert_eq!(g("backlog"), "4");
        assert_eq!(g("oldest_backlog"), "2023-11-14T22:13:20Z");
        assert_eq!(g("last_pull"), "None");
        assert_eq!(g("mismatches"), "2");
        assert_eq!(g("gap_24h"), "2");
        assert_eq!(g("longest_gap_24h"), "40");
        assert_eq!(g("archive_mb"), "1235");
        assert_eq!(g("free_gb"), "52.3");
        assert_eq!(g("days_covered"), "3.5");
        assert_eq!(g("paused"), "ON");
        assert_eq!(g("fixed/last"), "ok");
        assert_eq!(g("last_rotation"), "2026-10-14T06:06:40Z");
        assert_eq!(rotation_state("u1", None).1, "None", "unknown until the first rotation");
        let d = discovery("u1", true);
        let (_, body) = d.iter().find(|(t, _)| t.ends_with("/last_rotation/config")).unwrap();
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!((v["name"].as_str(), v["device_class"].as_str()), (Some("Last rotation"), Some("timestamp")));
    }

    #[tokio::test]
    async fn unpaired_never_calls_the_device() {
        for tok in [None, Some(""), Some("   ")] {
            let f = Fake::new();
            assert_eq!(press_fixed(&f, tok).await, "not paired");
            assert!(!f.log().iter().any(|l| l.starts_with("fixed")), "{:?}", f.log());
        }
    }

    #[tokio::test]
    async fn device_results_map_to_strings() {
        let cases = [
            (Ok(true), "ok"),
            (Ok(false), "failed"),
            (Err(DeviceError::Refused), "refused"),
            (Err(DeviceError::Busy), "busy"),
            (Err(DeviceError::Unreachable), "unreachable"),
            (Err(DeviceError::NotFound), "failed"),
            (Err(DeviceError::Bad("x".into())), "failed"),
        ];
        for (r, want) in cases {
            let f = Fake::new();
            f.set_fixed(r);
            assert_eq!(press_fixed(&f, Some("tok")).await, want);
            assert!(f.log().iter().any(|l| l.starts_with("fixed")));
        }
    }

    #[test]
    fn report_states_values() {
        let mut st: std::collections::HashMap<_, _> = report_states("u1", &report()).into_iter().collect();
        assert_eq!(st.len(), 9, "the decoder flag is not part of the report");
        st.extend([decoder_state("u1", false)]);
        let g = |k: &str| st[&format!("rayhunter_archive/u1/{k}")].clone();
        assert_eq!(g("findings/analyser_high_24h"), "1");
        assert_eq!(g("findings/towers_seen_24h"), "8");
        assert_eq!(g("decoder_unavailable"), "OFF");
        assert_eq!(g("baseline_learning"), "ON");
        assert_eq!(decoder_state("u1", true).1, "ON");
    }

    #[test]
    fn finding_event_payload() {
        let (t, body) = finding_event("u1", &pending("1791778208", "new_tower_recur")).unwrap();
        assert_eq!(t, "rayhunter_archive/u1/finding");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["event_type"], "new_tower_recur");
        assert_eq!(v["label"], "New tower seen again");
        assert_eq!(v["capture"], "1791778208");
        assert_eq!(v["profile"], "fixed");
        assert_eq!(v["switched"], true);
        assert_eq!(v["count"], 2);
        assert_eq!(v["found"], "2026-10-12T04:13:57Z");
        assert_eq!(v["towers"], Value::Null, "a new tower is unknown by definition");
        assert_eq!(v.as_object().unwrap().len(), 8, "nothing else, never the detail");
    }

    #[test]
    fn the_tower_word_only_where_it_adds_something() {
        let towers = |check: &str, known: Option<bool>| {
            let mut p = pending("1", check);
            p.towers_known = known;
            let (_, body) = finding_event("u1", &p).unwrap();
            serde_json::from_str::<Value>(&body).unwrap()["towers"].clone()
        };
        assert_eq!(towers("analyser_high", Some(true)), "known");
        assert_eq!(towers("identity_off_rhythm", Some(false)), "unknown");
        assert_eq!(towers("decoder_failure", None), Value::Null);
        for c in ["new_tower_identity", "new_tower_recur", "tower_flood"] {
            assert_eq!(towers(c, Some(false)), Value::Null, "{c}");
        }
    }

    #[test]
    fn hostile_capture_names_are_replaced() {
        for bad in [
            "", "a b", "310-260-0x1a2b;tac 4321", "x".repeat(33).as_str(), "ünicode", "1791778208\n",
            "310-260-21891-1234", "a_b-C", "1234567890123", "-1", "١٢٣",
        ] {
            assert_eq!(safe_name(bad), "?", "{bad:?}");
        }
        for good in ["1791778208", "532174", "0", "123456789012"] {
            assert_eq!(safe_name(good), good);
        }
        let (_, body) = finding_event("u1", &pending("310 260 cell 99", "new_tower_recur")).unwrap();
        assert!(body.contains("\"capture\":\"?\""), "{body}");
    }

    #[test]
    fn an_unknown_check_is_not_sent() {
        assert!(finding_event("u1", &pending("1", "analyser_other")).is_none());
        assert!(finding_event("u1", &pending("1", "made_up")).is_none());
    }

    #[test]
    fn every_notify_capable_check_is_an_event_type() {
        use crate::checks::{self, Level, Profile};
        for c in [
            checks::ANALYSER_HIGH, checks::ANALYSER_OTHER, checks::ANALYSER_OVERFLOW, checks::NEW_TOWER,
            checks::NEW_TOWER_IDENTITY, checks::NEW_TOWER_RECUR, checks::NEW_TOWER_WEAK, checks::NEW_TOWER_SECTOR, checks::IDENTITY_OFF_RHYTHM, checks::FAILURE_SPIKE,
            checks::DECODER_FAILURE, checks::ARCHIVE_CORRUPT, checks::ARCHIVE_MISSING, checks::TOWER_FLOOD,
        ] {
            let can_notify = [Profile::Fixed, Profile::Mobile]
                .iter()
                .any(|p| checks::level(c, *p, false) == Level::Notify);
            assert_eq!(can_notify, EVENT_TYPES.contains(&c), "{c}");
            if can_notify {
                assert_ne!(label(c), "Finding", "{c} needs a label");
            }
        }
    }

    const ADMIN: [(&str, &str); 6] = [
        ("live_unknown", "Live view unavailable"),
        ("not_recording", "Unit not recording"),
        ("low_disk", "Unit storage nearly full"),
        ("decoding_off", "Decoding paused"),
        ("live_unconfirmed", "Live alert not confirmed by full capture"),
        ("test_alert", "Home sentinel TEST alert"),
    ];

    #[test]
    fn event_types_has_15() {
        assert_eq!(EVENT_TYPES.len(), 15);
        for (k, _) in ADMIN {
            assert!(EVENT_TYPES.contains(&k), "{k}");
        }
    }

    #[test]
    fn every_event_type_has_a_label() {
        for c in EVENT_TYPES {
            assert_ne!(label(c), "Finding", "{c} needs a label");
        }
        for (k, l) in ADMIN {
            assert_eq!(label(k), l);
        }
    }

    #[test]
    fn admin_event_payload_has_label_and_type() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        for (k, l) in ADMIN {
            let (topic, body) = admin_event("u1", k, "mobile", now).unwrap();
            assert_eq!(topic, finding_topic("u1"));
            let v: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["event_type"], k);
            assert_eq!(v["label"], l);
            assert_eq!(v["capture"], "");
            assert_eq!(v["count"], 1);
            assert_eq!(v["switched"], false);
            assert_eq!(v["found"], "2023-11-14T22:13:20Z");
            assert!(v["towers"].is_null());
            assert_eq!(v["profile"], "mobile");
            assert_eq!(v["admin"], true);
        }
        let f = finding_event("u1", &pending("1791778208", "analyser_high")).unwrap().1;
        assert!(serde_json::from_str::<Value>(&f).unwrap().get("admin").is_none());
        assert!(admin_event("u1", "analyser_high", "fixed", now).is_none());
        assert!(admin_event("u1", "bogus", "fixed", now).is_none());
    }
}
