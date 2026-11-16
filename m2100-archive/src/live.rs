//! The unit's live view (`GET /api/m2100/live`): what the recording in progress has
//! seen so far. The unit's data is hostile, so it is parsed against a fixed schema
//! with every count and string bounded.

use crate::checks::{self, Level, Profile};
use crate::events::{
    MAX_WARNING_MSG, Observations, Severity, Strength, TowerSeen, WarningSeen, printable, tower_key,
};
use crate::mesh;
use crate::store::{Baseline, DecodeStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};

/// Largest body believed.
pub const LIVE_MAX_BODY: usize = 256 * 1024;
const MAX_TOWERS: usize = 512;
const MAX_IDENTITY: usize = 128;
const MAX_WARNINGS: usize = 64;
const MAX_TS: usize = 64;
const MAX_PLMN: usize = 32;
const MAX_ANALYZER: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub recording: Option<String>,
    pub towers: Vec<LiveTower>,
    pub towers_capped: bool,
    pub identity: Vec<Option<String>>,
    pub identity_total: u64,
    pub warnings: Vec<WarningSeen>,
    pub warnings_total: u64,
    pub warnings_high_total: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LiveTower {
    /// `events::tower_key(..)`: the same key the decoder path uses.
    pub key: String,
    pub first: Option<String>,
    pub last: Option<String>,
    pub hits: u64,
}

fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(d)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnapshot {
    version: u32,
    #[serde(deserialize_with = "present")]
    recording: Option<String>,
    towers: Vec<RawTower>,
    towers_capped: bool,
    identity: Vec<Option<String>>,
    identity_total: u64,
    warnings: Vec<RawWarning>,
    warnings_total: u64,
    warnings_high_total: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTower {
    #[serde(deserialize_with = "present")]
    plmn: Option<String>,
    tac: u64,
    cell: u64,
    #[allow(dead_code)]
    pci: u16,
    #[allow(dead_code)]
    earfcn: u32,
    #[serde(deserialize_with = "present")]
    first: Option<String>,
    #[serde(deserialize_with = "present")]
    last: Option<String>,
    hits: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWarning {
    severity: Severity,
    analyzer: String,
    msg: String,
    #[serde(deserialize_with = "present")]
    ts: Option<String>,
}

fn bounded(what: &str, s: &Option<String>, max: usize) -> Result<(), String> {
    match s {
        Some(s) if s.len() > max => Err(format!("{what} longer than {max} bytes")),
        _ => Ok(()),
    }
}

pub fn parse(body: &[u8]) -> Result<Snapshot, String> {
    if body.len() > LIVE_MAX_BODY {
        return Err(format!("body over {LIVE_MAX_BODY} bytes"));
    }
    let raw: RawSnapshot = serde_json::from_slice(body).map_err(|e| format!("live: {e}"))?;
    if raw.version != 1 {
        return Err(format!("live: unsupported version {}", raw.version));
    }
    if raw.towers.len() > MAX_TOWERS {
        return Err(format!("live: more than {MAX_TOWERS} towers"));
    }
    if raw.identity.len() > MAX_IDENTITY {
        return Err(format!("live: more than {MAX_IDENTITY} identity entries"));
    }
    if raw.warnings.len() > MAX_WARNINGS {
        return Err(format!("live: more than {MAX_WARNINGS} warnings"));
    }
    if raw
        .recording
        .as_deref()
        .is_some_and(|r| !crate::puller::safe_name(r))
    {
        return Err("live: unsafe recording name".into());
    }
    for ts in &raw.identity {
        bounded("identity ts", ts, MAX_TS)?;
    }
    let mut towers = Vec::with_capacity(raw.towers.len());
    for t in raw.towers {
        bounded("plmn", &t.plmn, MAX_PLMN)?;
        bounded("tower ts", &t.first, MAX_TS)?;
        bounded("tower ts", &t.last, MAX_TS)?;
        towers.push(LiveTower {
            key: tower_key(t.plmn.as_deref(), t.tac, t.cell),
            first: t.first,
            last: t.last,
            hits: t.hits,
        });
    }
    let mut warnings = Vec::with_capacity(raw.warnings.len());
    for w in raw.warnings {
        if w.analyzer.len() > MAX_ANALYZER {
            return Err(format!("live: analyzer longer than {MAX_ANALYZER} bytes"));
        }
        bounded("warning ts", &w.ts, MAX_TS)?;
        if w.msg.chars().any(|c| !c.is_ascii() || c.is_ascii_control()) {
            return Err("live: warning message not printable".into());
        }
        warnings.push(WarningSeen {
            severity: w.severity,
            analyzer: printable(&w.analyzer, MAX_ANALYZER),
            msg: printable(&w.msg, MAX_WARNING_MSG),
            ts: w.ts,
        });
    }
    Ok(Snapshot {
        recording: raw.recording,
        towers,
        towers_capped: raw.towers_capped,
        identity: raw.identity,
        identity_total: raw.identity_total,
        warnings,
        warnings_total: raw.warnings_total,
        warnings_high_total: raw.warnings_high_total,
    })
}

/// What the last poll showed, so a repeat poll raises and reports nothing new.
#[derive(Default)]
pub struct LiveMemory {
    recording: Option<String>,
    /// (check, detail) already raised for this recording.
    raised: HashSet<(String, String)>,
    hits: HashMap<String, u64>,
    identity_total: u64,
    warnings_total: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LiveFinding {
    pub check: &'static str,
    pub detail: String,
    /// Tower keys named in `detail`.
    pub towers: Vec<String>,
    /// For `analyser_high` the analyzer key; empty for every other check.
    pub subject: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Activity {
    /// Keys whose hits rose or that are new.
    pub towers: Vec<String>,
    pub identity: bool,
    pub warning_checks: Vec<&'static str>,
}

/// `analyser_high` details read "{analyzer}: {count} high warning(s); ...", so the
/// subject is the text before the first ": ". Other checks have none.
pub fn subject_of(check: &str, detail: &str) -> String {
    if check != checks::ANALYSER_HIGH {
        return String::new();
    }
    detail.split(": ").next().unwrap_or("").to_string()
}

/// Every `sib1:...` / `pci:...` token in a detail string.
pub fn towers_in(detail: &str) -> Vec<String> {
    detail
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| w.starts_with("sib1:") || w.starts_with("pci:"))
        .map(str::to_string)
        .collect()
}

/// Judge the live snapshot as a Fixed capture and keep only new, strong, notifying
/// findings. Never learns: the baseline is read-only and the `Learn` is dropped. A
/// finding counts as raised only once the caller `mark_raised`s it (after a successful
/// ingest): until then every poll offers it again.
pub fn evaluate(
    mem: &mut LiveMemory,
    snap: &Snapshot,
    baseline: &Baseline,
    settings: &checks::Settings,
    learning: bool,
    now: DateTime<Utc>,
) -> (Vec<LiveFinding>, Activity) {
    if snap.recording != mem.recording {
        *mem = LiveMemory {
            recording: snap.recording.clone(),
            ..LiveMemory::default()
        };
    }
    let seen = Observations {
        towers: snap
            .towers
            .iter()
            .map(|t| TowerSeen {
                key: t.key.clone(),
                strength: Strength::Sib1,
                ts: t.first.clone(),
            })
            .collect(),
        identity_ts: snap.identity.clone(),
        warnings: snap.warnings.clone(),
        failure_hours: Vec::new(),
    };
    let (found, _learn) = checks::judge(&checks::Input {
        profile: Profile::Fixed,
        status: DecodeStatus::Ok,
        seen: &seen,
        baseline,
        prev_identity: None,
        failure_history: &[],
        now,
        settings,
    });
    let strong = mesh::checks_for(mesh::Level::Strong);
    let mut out = Vec::new();
    for f in found {
        if !strong.contains(&f.check)
            || f.level != Level::Notify
            || checks::level(f.check, Profile::Fixed, learning) != Level::Notify
        {
            continue;
        }
        let key = (f.check.to_string(), f.detail.clone());
        let listed = out
            .iter()
            .any(|o: &LiveFinding| o.check == f.check && o.detail == f.detail);
        if !mem.raised.contains(&key) && !listed {
            out.push(LiveFinding {
                check: f.check,
                towers: towers_in(&f.detail),
                subject: subject_of(f.check, &f.detail),
                detail: f.detail,
            });
        }
    }

    let mut act = Activity::default();
    // One key can be listed under several (pci, earfcn) entries: sum them, first-listed order.
    let mut keys: Vec<&str> = Vec::new();
    let mut hits: HashMap<&str, u64> = HashMap::new();
    for t in &snap.towers {
        let h = hits.entry(&t.key).or_insert_with(|| {
            keys.push(&t.key);
            0
        });
        *h = h.saturating_add(t.hits);
    }
    for k in keys {
        let h = hits[k];
        if mem.hits.get(k).is_none_or(|was| h > *was) {
            act.towers.push(k.to_string());
        }
        mem.hits.insert(k.to_string(), h);
    }
    act.identity = snap.identity_total > mem.identity_total;
    mem.identity_total = snap.identity_total;
    if snap.warnings_total > mem.warnings_total {
        // The list is oldest first; the newest are at its tail.
        let fresh = (snap.warnings_total - mem.warnings_total) as usize;
        let from = snap.warnings.len().saturating_sub(fresh);
        for w in &snap.warnings[from..] {
            let c = match w.severity {
                Severity::High => checks::ANALYSER_HIGH,
                Severity::Medium | Severity::Low => checks::ANALYSER_OTHER,
                Severity::Info => continue,
            };
            if !act.warning_checks.contains(&c) {
                act.warning_checks.push(c);
            }
        }
    }
    mem.warnings_total = snap.warnings_total;
    (out, act)
}

/// `f` went into the alerts (opened, joined or a duplicate): not offered again this recording.
pub fn mark_raised(mem: &mut LiveMemory, f: &LiveFinding) {
    mem.raised.insert((f.check.to_string(), f.detail.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn example() -> Value {
        json!({
            "version": 1,
            "recording": "1800000001",
            "towers": [
                {"plmn":"310-260","tac":11111,"cell":87654321,"pci":12,"earfcn":5230,
                 "first":"2026-10-24T01:02:03.000Z","last":"2026-10-24T01:05:03.000Z","hits":7},
                {"plmn":null,"tac":1,"cell":2,"pci":3,"earfcn":4,"first":null,"last":null,"hits":1}
            ],
            "towers_capped": false,
            "identity": ["2026-10-24T01:03:00.000Z", null],
            "identity_total": 9,
            "warnings": [
                {"severity":"high","analyzer":"imsi_requested","msg":"IMSI requested","ts":"2026-10-24T01:03:00.000Z"},
                {"severity":"low","analyzer":"x","msg":"m","ts":null}
            ],
            "warnings_total": 12,
            "warnings_high_total": 4
        })
    }

    fn bytes(v: &Value) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn parses_plan1_example() {
        let s = parse(&bytes(&example())).unwrap();
        assert_eq!(s.recording.as_deref(), Some("1800000001"));
        assert_eq!(s.towers.len(), 2);
        assert_eq!(s.towers[0].key, "sib1:310-260:11111:87654321");
        assert_eq!(s.towers[0].hits, 7);
        assert_eq!(s.towers[1].key, "sib1:-:1:2");
        assert_eq!(s.towers[1].first, None);
        assert!(!s.towers_capped);
        assert_eq!(
            s.identity,
            vec![Some("2026-10-24T01:03:00.000Z".into()), None]
        );
        assert_eq!(s.identity_total, 9);
        assert_eq!(s.warnings.len(), 2);
        assert_eq!(s.warnings[0].severity, Severity::High);
        assert_eq!(s.warnings[0].analyzer, "imsi_requested");
        assert_eq!(s.warnings[1].ts, None);
        assert_eq!(s.warnings_total, 12);
        assert_eq!(s.warnings_high_total, 4);
        let mut v = example();
        v["recording"] = Value::Null;
        assert_eq!(parse(&bytes(&v)).unwrap().recording, None);
    }

    #[test]
    fn tower_key_matches_decoder_format() {
        assert_eq!(
            tower_key(Some("310-260"), 11111, 87654321),
            "sib1:310-260:11111:87654321"
        );
        assert_eq!(tower_key(None, 1, 2), "sib1:-:1:2");
    }

    #[test]
    fn refuses_oversized_and_malformed() {
        let mut v = example();
        v["version"] = json!(2);
        assert!(parse(&bytes(&v)).is_err());

        let mut v = example();
        let t = v["towers"][0].clone();
        v["towers"] = Value::Array(vec![t; 513]);
        assert!(parse(&bytes(&v)).is_err());

        let mut v = example();
        v["warnings"][0]["msg"] = json!("bad\u{7}msg");
        assert!(parse(&bytes(&v)).is_err());
        let mut v = example();
        v["warnings"][0]["msg"] = json!("caf\u{e9}");
        assert!(parse(&bytes(&v)).is_err());

        for bad in ["../x", "a/b", ".hidden", ""] {
            let mut v = example();
            v["recording"] = json!(bad);
            assert!(parse(&bytes(&v)).is_err(), "{bad:?}");
        }

        let mut v = example();
        v["identity"] = Value::Array(vec![Value::Null; 129]);
        assert!(parse(&bytes(&v)).is_err());
        let mut v = example();
        let w = v["warnings"][0].clone();
        v["warnings"] = Value::Array(vec![w; 65]);
        assert!(parse(&bytes(&v)).is_err());

        let mut v = example();
        v["warnings"][0]["severity"] = json!("catastrophic");
        assert!(parse(&bytes(&v)).is_err());
        let mut v = example();
        v.as_object_mut().unwrap().remove("warnings_high_total");
        assert!(parse(&bytes(&v)).is_err());

        assert!(parse(b"not json").is_err());
        assert!(parse(&vec![b' '; LIVE_MAX_BODY + 1]).is_err());
    }

    #[test]
    fn long_warning_msg_is_cut() {
        let mut v = example();
        v["warnings"][0]["msg"] = json!("a".repeat(200));
        let s = parse(&bytes(&v)).unwrap();
        assert_eq!(s.warnings[0].msg.len(), MAX_WARNING_MSG);
    }

    mod eval {
        use super::super::*;
        use chrono::Duration;

        fn now() -> DateTime<Utc> {
            "2026-10-24T02:00:00Z".parse().unwrap()
        }
        fn past() -> Baseline {
            Baseline {
                fixed_since: Some(now() - Duration::days(20)),
                ..Baseline::default()
            }
        }
        fn tower(key: &str, hits: u64) -> LiveTower {
            LiveTower {
                key: key.into(),
                first: Some("2026-10-24T01:02:00Z".into()),
                last: None,
                hits,
            }
        }
        fn snap() -> Snapshot {
            Snapshot {
                recording: Some("100".into()),
                towers: vec![],
                towers_capped: false,
                identity: vec![],
                identity_total: 0,
                warnings: vec![],
                warnings_total: 0,
                warnings_high_total: 0,
            }
        }
        fn high(analyzer: &str) -> WarningSeen {
            WarningSeen {
                severity: Severity::High,
                analyzer: analyzer.into(),
                msg: "bad".into(),
                ts: None,
            }
        }
        fn with_identity() -> Snapshot {
            let mut s = snap();
            s.towers = vec![tower("sib1:310-260:1:2", 3)];
            s.identity = vec![Some("2026-10-24T01:05:00Z".into())];
            s.identity_total = 1;
            s
        }
        /// Evaluate, then mark every finding raised (as a successful ingest does).
        fn run(m: &mut LiveMemory, s: &Snapshot, b: &Baseline, learning: bool) -> (Vec<LiveFinding>, Activity) {
            let (f, a) = evaluate(m, s, b, &checks::Settings::default(), learning, now());
            for x in &f {
                mark_raised(m, x);
            }
            (f, a)
        }

        /// M6: a finding the caller did not mark (its ingest failed) is offered again.
        #[test]
        fn unmarked_finding_is_offered_again() {
            let mut m = LiveMemory::default();
            let s = with_identity();
            let st = checks::Settings::default();
            let (f, _) = evaluate(&mut m, &s, &past(), &st, false, now());
            assert_eq!(f.len(), 1);
            let (again, _) = evaluate(&mut m, &s, &past(), &st, false, now());
            assert_eq!(again, f, "not marked: offered again");
            mark_raised(&mut m, &again[0]);
            assert!(evaluate(&mut m, &s, &past(), &st, false, now()).0.is_empty());
        }

        #[test]
        fn unknown_tower_then_identity_within_10_min_raises_identity_check() {
            let mut m = LiveMemory::default();
            let (f, _) = run(&mut m, &with_identity(), &past(), false);
            assert_eq!(f.len(), 1, "{f:?}");
            assert_eq!(f[0].check, checks::NEW_TOWER_IDENTITY);
            assert_eq!(f[0].towers, vec!["sib1:310-260:1:2".to_string()]);
            assert_eq!(f[0].subject, "");
        }

        #[test]
        fn repeat_poll_raises_nothing_new() {
            let mut m = LiveMemory::default();
            let s = with_identity();
            assert_eq!(run(&mut m, &s, &past(), false).0.len(), 1);
            assert!(run(&mut m, &s, &past(), false).0.is_empty());
        }

        #[test]
        fn new_high_warning_raises_analyser_high_once() {
            let mut m = LiveMemory::default();
            let mut s = snap();
            s.warnings = vec![high("imsi_requested")];
            s.warnings_total = 1;
            s.warnings_high_total = 1;
            let (f, a) = run(&mut m, &s, &past(), false);
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].check, checks::ANALYSER_HIGH);
            assert_eq!(f[0].subject, "imsi_requested");
            assert_eq!(a.warning_checks, vec![checks::ANALYSER_HIGH]);
            let (f, a) = run(&mut m, &s, &past(), false);
            assert!(f.is_empty());
            assert!(a.warning_checks.is_empty());
        }

        #[test]
        fn learning_or_known_tower_raises_nothing() {
            let mut m = LiveMemory::default();
            assert!(run(&mut m, &with_identity(), &past(), true).0.is_empty());
            let mut known = past();
            known.towers.insert("sib1:310-260:1:2".into());
            let mut m = LiveMemory::default();
            assert!(run(&mut m, &with_identity(), &known, false).0.is_empty());
            let mut still = Baseline {
                fixed_since: Some(now() - Duration::days(2)),
                ..Baseline::default()
            };
            still.towers.clear();
            let mut m = LiveMemory::default();
            assert!(run(&mut m, &with_identity(), &still, false).0.is_empty());
        }

        #[test]
        fn new_recording_resets_memory() {
            let mut m = LiveMemory::default();
            let mut s = with_identity();
            assert_eq!(run(&mut m, &s, &past(), false).0.len(), 1);
            s.recording = Some("101".into());
            assert_eq!(run(&mut m, &s, &past(), false).0.len(), 1, "raised again");
            s.recording = None;
            let (_, a) = run(&mut m, &s, &past(), false);
            assert_eq!(a.towers, vec!["sib1:310-260:1:2".to_string()], "hits reset");
            assert!(a.identity, "totals reset");
        }

        #[test]
        fn activity_reports_rising_hits_only() {
            let mut m = LiveMemory::default();
            let mut s = snap();
            s.towers = vec![tower("sib1:a:1:1", 2), tower("sib1:a:1:2", 5)];
            let (_, a) = run(&mut m, &s, &past(), true);
            assert_eq!(a.towers.len(), 2, "new towers count");
            assert!(!a.identity);
            s.towers[0].hits = 3;
            s.identity_total = 1;
            let (_, a) = run(&mut m, &s, &past(), true);
            assert_eq!(a.towers, vec!["sib1:a:1:1".to_string()]);
            assert!(a.identity);
            let (_, a) = run(&mut m, &s, &past(), true);
            assert!(a.towers.is_empty() && !a.identity);
        }

        /// I2: one archive key under two (pci, earfcn) entries: their hits are summed, so
        /// an identical poll is not "rising" and a new key is reported once.
        #[test]
        fn two_entries_one_key_not_rising_on_identical_poll() {
            let mut m = LiveMemory::default();
            let mut s = snap();
            s.towers = vec![tower("sib1:a:1:1", 5), tower("sib1:a:1:1", 2)];
            let (_, a) = run(&mut m, &s, &past(), true);
            assert_eq!(a.towers, vec!["sib1:a:1:1".to_string()], "new, once");
            let (_, a) = run(&mut m, &s, &past(), true);
            assert!(a.towers.is_empty(), "identical poll: {:?}", a.towers);
            // Either entry rising is the key rising.
            s.towers[1].hits = 3;
            let (_, a) = run(&mut m, &s, &past(), true);
            assert_eq!(a.towers, vec!["sib1:a:1:1".to_string()]);
        }

        #[test]
        fn learn_is_never_applied() {
            let b = past();
            let before = (b.towers.clone(), b.held.clone(), b.fixed_since);
            let mut m = LiveMemory::default();
            run(&mut m, &with_identity(), &b, false);
            assert_eq!((b.towers.clone(), b.held.clone(), b.fixed_since), before);
            assert!(b.towers.is_empty());
        }

        #[test]
        fn towers_in_extracts_keys() {
            assert_eq!(
                towers_in("identity request after: sib1:310-260:1:2, pci:7:5230, ... +3 more"),
                vec!["sib1:310-260:1:2".to_string(), "pci:7:5230".to_string()]
            );
            assert!(towers_in("nothing here").is_empty());
        }

        #[test]
        fn subject_of_analyser_high_is_analyzer_key() {
            assert_eq!(
                subject_of("analyser_high", "imsi_requested: 2 high warning(s); first: a: b"),
                "imsi_requested"
            );
        }

        #[test]
        fn subject_of_other_checks_is_empty() {
            assert_eq!(subject_of("new_tower_identity", "identity request after: sib1:a:1:1"), "");
            assert_eq!(subject_of("tower_flood", "x: y"), "");
        }
    }
}
