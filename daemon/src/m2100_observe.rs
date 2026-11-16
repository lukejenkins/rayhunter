//! In-memory view of the current recording (towers, identity requests,
//! warnings), served at `/api/m2100/live`. Pure: no I/O, no clock.

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, SecondsFormat, Utc};
use rayhunter::analysis::analyzer::{Event, EventType};
use rayhunter::analysis::information_element::InformationElement;
use rayhunter::analysis::observe::{Sib1Tower, is_identity_request, sib1_tower};
use serde::Serialize;

pub const TOWER_CAP: usize = 512;
pub const IDENTITY_KEEP: usize = 128;
/// High-severity warnings get their own ring so a burst of Low/Medium cannot
/// evict them.
pub const HIGH_KEEP: usize = 32;
pub const OTHER_KEEP: usize = 32;
/// Most warnings ever listed: `HIGH_KEEP + OTHER_KEEP`.
#[cfg_attr(not(test), allow(dead_code))]
pub const WARNING_KEEP: usize = HIGH_KEEP + OTHER_KEEP;
pub const MSG_MAX: usize = 200;

type TowerKey = (Option<String>, u64, u64, u16, u32);

struct Tower {
    plmn: Option<String>,
    tac: u64,
    cell: u64,
    pci: u16,
    earfcn: u32,
    first: Option<String>,
    last: Option<String>,
    hits: u64,
}

#[derive(Default)]
pub struct LiveObservations {
    recording: Option<String>,
    towers: Vec<Tower>,
    index: HashMap<TowerKey, usize>,
    current: HashMap<(u16, u32), usize>,
    towers_capped: bool,
    identity: VecDeque<Option<String>>,
    identity_total: u64,
    /// (arrival sequence, warning); high and other severities kept apart.
    warnings_high: VecDeque<(u64, LiveWarning)>,
    warnings_other: VecDeque<(u64, LiveWarning)>,
    warnings_total: u64,
    warnings_high_total: u64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct LiveSnapshot {
    pub version: u32,
    pub recording: Option<String>,
    pub towers: Vec<LiveTower>,
    pub towers_capped: bool,
    pub identity: Vec<Option<String>>,
    pub identity_total: u64,
    pub warnings: Vec<LiveWarning>,
    pub warnings_total: u64,
    /// All High warnings this recording, including evicted ones.
    pub warnings_high_total: u64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct LiveTower {
    pub plmn: Option<String>,
    pub tac: u64,
    pub cell: u64,
    pub pci: u16,
    pub earfcn: u32,
    pub first: Option<String>,
    pub last: Option<String>,
    pub hits: u64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct LiveWarning {
    pub severity: String,
    pub analyzer: String,
    pub msg: String,
    pub ts: Option<String>,
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn severity(t: EventType) -> Option<&'static str> {
    match t {
        EventType::High => Some("high"),
        EventType::Medium => Some("medium"),
        EventType::Low => Some("low"),
        EventType::Informational => None,
    }
}

impl LiveObservations {
    pub fn reset(&mut self, recording: Option<String>) {
        *self = Self {
            recording,
            ..Self::default()
        };
    }

    pub fn observe(
        &mut self,
        ts: Option<DateTime<Utc>>,
        cell: Option<(u16, u32)>,
        element: Option<&InformationElement>,
    ) {
        self.observe_parts(
            ts,
            cell,
            element.and_then(sib1_tower),
            element.is_some_and(is_identity_request),
        );
    }

    pub(crate) fn observe_parts(
        &mut self,
        ts: Option<DateTime<Utc>>,
        cell: Option<(u16, u32)>,
        sib1: Option<Sib1Tower>,
        identity: bool,
    ) {
        let ts = ts.map(rfc3339);
        if identity {
            if self.identity.len() >= IDENTITY_KEEP {
                self.identity.pop_front();
            }
            self.identity.push_back(ts.clone());
            self.identity_total += 1;
        }
        let Some((pci, earfcn)) = cell else { return };
        if let Some(t) = sib1 {
            let key = (t.plmn.clone(), t.tac, t.cell, pci, earfcn);
            let idx = match self.index.get(&key) {
                Some(&i) => {
                    self.bump(i, &ts);
                    Some(i)
                }
                None if self.towers.len() >= TOWER_CAP => {
                    self.towers_capped = true;
                    // Don't let later RRC traffic on this pair credit an older tower.
                    self.current.remove(&(pci, earfcn));
                    None
                }
                None => {
                    let i = self.towers.len();
                    self.towers.push(Tower {
                        plmn: t.plmn,
                        tac: t.tac,
                        cell: t.cell,
                        pci,
                        earfcn,
                        first: ts.clone(),
                        last: ts,
                        hits: 1,
                    });
                    self.index.insert(key, i);
                    Some(i)
                }
            };
            if let Some(i) = idx {
                self.current.insert((pci, earfcn), i);
            }
        } else if let Some(&i) = self.current.get(&(pci, earfcn)) {
            self.bump(i, &ts);
        }
    }

    fn bump(&mut self, i: usize, ts: &Option<String>) {
        let t = &mut self.towers[i];
        t.last = ts.clone();
        t.hits += 1;
    }

    pub fn warning(&mut self, ts: Option<DateTime<Utc>>, analyzer: &str, event: &Event) {
        let Some(sev) = severity(event.event_type) else {
            return;
        };
        let msg: String = event
            .message
            .chars()
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '?'
                }
            })
            .take(MSG_MAX)
            .collect();
        let w = LiveWarning {
            severity: sev.to_string(),
            analyzer: analyzer.to_string(),
            msg,
            ts: ts.map(rfc3339),
        };
        let seq = self.warnings_total;
        let (ring, keep) = if event.event_type == EventType::High {
            self.warnings_high_total += 1;
            (&mut self.warnings_high, HIGH_KEEP)
        } else {
            (&mut self.warnings_other, OTHER_KEEP)
        };
        if ring.len() >= keep {
            ring.pop_front();
        }
        ring.push_back((seq, w));
        self.warnings_total += 1;
    }

    pub fn snapshot(&self) -> LiveSnapshot {
        LiveSnapshot {
            version: 1,
            recording: self.recording.clone(),
            towers: self
                .towers
                .iter()
                .map(|t| LiveTower {
                    plmn: t.plmn.clone(),
                    tac: t.tac,
                    cell: t.cell,
                    pci: t.pci,
                    earfcn: t.earfcn,
                    first: t.first.clone(),
                    last: t.last.clone(),
                    hits: t.hits,
                })
                .collect(),
            towers_capped: self.towers_capped,
            identity: self.identity.iter().cloned().collect(),
            identity_total: self.identity_total,
            warnings: {
                let mut all: Vec<&(u64, LiveWarning)> = self
                    .warnings_high
                    .iter()
                    .chain(self.warnings_other.iter())
                    .collect();
                all.sort_by_key(|(seq, _)| *seq);
                all.into_iter().map(|(_, w)| w.clone()).collect()
            },
            warnings_total: self.warnings_total,
            warnings_high_total: self.warnings_high_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(s: u32) -> Option<DateTime<Utc>> {
        Some(
            Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, s % 60).unwrap()
                + chrono::Duration::minutes((s / 60) as i64),
        )
    }

    fn sib(cell: u64) -> Option<Sib1Tower> {
        Some(Sib1Tower {
            plmn: Some("310-260".into()),
            tac: 7,
            cell,
        })
    }

    #[test]
    fn new_sib1_tower_has_first_last_and_one_hit() {
        let mut o = LiveObservations::default();
        o.observe_parts(at(1), Some((10, 5230)), sib(1), false);
        let s = o.snapshot();
        assert_eq!(s.version, 1);
        assert_eq!(s.towers.len(), 1);
        let t = &s.towers[0];
        assert_eq!(t.first, Some("2026-10-24T12:00:01.000Z".into()));
        assert_eq!(t.first, t.last);
        assert_eq!(
            (t.hits, t.pci, t.earfcn, t.cell, t.tac),
            (1, 10, 5230, 1, 7)
        );
    }

    #[test]
    fn same_sib1_again_bumps_last_and_hits_not_first() {
        let mut o = LiveObservations::default();
        o.observe_parts(at(1), Some((10, 5230)), sib(1), false);
        o.observe_parts(at(9), Some((10, 5230)), sib(1), false);
        let s = o.snapshot();
        assert_eq!(s.towers.len(), 1);
        assert_eq!(s.towers[0].hits, 2);
        assert_eq!(s.towers[0].first, Some("2026-10-24T12:00:01.000Z".into()));
        assert_eq!(s.towers[0].last, Some("2026-10-24T12:00:09.000Z".into()));
    }

    #[test]
    fn rrc_hits_go_to_latest_sib1_on_that_pci() {
        let mut o = LiveObservations::default();
        o.observe_parts(at(1), Some((10, 5230)), sib(1), false);
        o.observe_parts(at(2), Some((10, 5230)), sib(2), false);
        o.observe_parts(at(3), Some((10, 5230)), None, false);
        let s = o.snapshot();
        assert_eq!(s.towers[0].hits, 1);
        assert_eq!(s.towers[1].hits, 2);
        assert_eq!(s.towers[1].last, Some("2026-10-24T12:00:03.000Z".into()));
        assert_eq!(s.towers[0].last, Some("2026-10-24T12:00:01.000Z".into()));
    }

    #[test]
    fn rrc_on_unknown_pci_changes_nothing() {
        let mut o = LiveObservations::default();
        o.observe_parts(at(1), Some((10, 5230)), sib(1), false);
        let before = o.snapshot();
        o.observe_parts(at(2), Some((11, 5230)), None, false);
        o.observe_parts(at(3), Some((10, 66)), None, false);
        o.observe_parts(at(4), None, None, false);
        assert_eq!(o.snapshot(), before);
    }

    #[test]
    fn identity_keeps_last_128_and_counts_all() {
        let mut o = LiveObservations::default();
        for i in 0..130 {
            o.observe_parts(at(i), None, None, true);
        }
        let s = o.snapshot();
        assert_eq!(s.identity.len(), IDENTITY_KEEP);
        assert_eq!(s.identity_total, 130);
        assert_eq!(s.identity[0], at(2).map(rfc3339));
        assert_eq!(s.identity[127], at(129).map(rfc3339));
    }

    fn ev(t: EventType, m: &str) -> Event {
        Event {
            event_type: t,
            message: m.to_string(),
        }
    }

    #[test]
    fn warnings_keep_last_32_high_cut_msg_and_skip_informational() {
        let mut o = LiveObservations::default();
        o.warning(at(0), "a", &ev(EventType::Informational, "ignored"));
        assert_eq!(o.snapshot().warnings_total, 0);
        for i in 0..34 {
            o.warning(at(i), "a", &ev(EventType::High, &format!("m{i}")));
        }
        o.warning(at(70), "b", &ev(EventType::Low, &"x".repeat(500)));
        o.warning(at(71), "b", &ev(EventType::Medium, "caf\u{e9}\n"));
        let s = o.snapshot();
        assert_eq!(s.warnings.len(), HIGH_KEEP + 2);
        assert_eq!(s.warnings_total, 36);
        assert_eq!(s.warnings_high_total, 34);
        assert_eq!(s.warnings[0].msg, "m2");
        let n = s.warnings.len();
        assert_eq!(s.warnings[n - 2].msg.len(), MSG_MAX);
        assert_eq!(s.warnings[n - 2].severity, "low");
        assert_eq!(s.warnings[n - 1].msg, "caf??");
        assert_eq!(s.warnings[n - 1].severity, "medium");
        assert_eq!(s.warnings[0].severity, "high");
    }

    #[test]
    fn warnings_never_exceed_keep_and_merge_in_arrival_order() {
        let mut o = LiveObservations::default();
        for i in 0..100 {
            let t = if i % 2 == 0 {
                EventType::High
            } else {
                EventType::Low
            };
            o.warning(at(i), "a", &ev(t, &format!("m{i}")));
        }
        let s = o.snapshot();
        assert_eq!(s.warnings.len(), WARNING_KEEP);
        assert_eq!(s.warnings_total, 100);
        assert_eq!(s.warnings_high_total, 50);
        let nums: Vec<u32> = s
            .warnings
            .iter()
            .map(|w| w.msg[1..].parse().unwrap())
            .collect();
        assert!(nums.windows(2).all(|w| w[0] < w[1]), "{nums:?}");
        assert_eq!(*nums.last().unwrap(), 99);
    }

    #[test]
    fn high_survives_burst_of_low() {
        let mut o = LiveObservations::default();
        o.warning(at(0), "a", &ev(EventType::High, "the high one"));
        for i in 0..100 {
            o.warning(at(1), "a", &ev(EventType::Low, &format!("l{i}")));
        }
        let s = o.snapshot();
        assert!(s.warnings.iter().any(|w| w.msg == "the high one"));
        assert_eq!(s.warnings[0].msg, "the high one");
        assert_eq!(s.warnings.len(), 1 + OTHER_KEEP);
        assert_eq!(s.warnings_total, 101);
        assert_eq!(s.warnings_high_total, 1);
    }

    #[test]
    fn tower_cap_holds_and_flags() {
        let mut o = LiveObservations::default();
        for c in 0..=TOWER_CAP as u64 {
            o.observe_parts(at(1), Some((10, 5230)), sib(c), false);
        }
        let s = o.snapshot();
        assert_eq!(s.towers.len(), TOWER_CAP);
        assert!(s.towers_capped);
        o.observe_parts(at(5), Some((10, 5230)), sib(0), false);
        let s = o.snapshot();
        assert_eq!(s.towers[0].hits, 2);
        assert_eq!(s.towers[0].last, Some("2026-10-24T12:00:05.000Z".into()));
    }

    #[test]
    fn capped_new_sib1_clears_current_for_its_pci() {
        let mut o = LiveObservations::default();
        // Fill the table; the last one admitted sits on (10, 5230).
        for c in 0..TOWER_CAP as u64 {
            o.observe_parts(at(1), Some((10, 5230)), sib(c), false);
        }
        // A new tower on the same pci/earfcn is dropped by the cap...
        o.observe_parts(at(2), Some((10, 5230)), sib(9999), false);
        // ...so later RRC traffic on it must not be credited to an older tower.
        o.observe_parts(at(3), Some((10, 5230)), None, false);
        let s = o.snapshot();
        assert!(s.towers_capped);
        assert_eq!(s.towers[TOWER_CAP - 1].hits, 1);
        assert_eq!(
            s.towers[TOWER_CAP - 1].last,
            Some("2026-10-24T12:00:01.000Z".into())
        );
    }

    #[test]
    fn reset_clears_everything_and_sets_recording() {
        let mut o = LiveObservations::default();
        o.observe_parts(at(1), Some((10, 5230)), sib(1), true);
        o.warning(
            at(1),
            "a",
            &Event {
                event_type: EventType::High,
                message: "x".into(),
            },
        );
        o.reset(Some("rec1".into()));
        let s = o.snapshot();
        assert_eq!(s.recording, Some("rec1".into()));
        assert!(s.towers.is_empty() && s.identity.is_empty() && s.warnings.is_empty());
        assert_eq!(
            (s.identity_total, s.warnings_total, s.warnings_high_total),
            (0, 0, 0)
        );
        assert!(!s.towers_capped);
        o.observe_parts(at(2), Some((10, 5230)), None, false);
        assert!(o.snapshot().towers.is_empty());
    }

    #[test]
    fn observe_with_no_element_is_safe() {
        let mut o = LiveObservations::default();
        o.observe(at(1), Some((1, 2)), None);
        assert_eq!(o.snapshot().identity_total, 0);
    }
}
