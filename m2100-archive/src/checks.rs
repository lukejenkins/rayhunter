//! The checks: what a capture's observations say against the profile's baseline,
//! and what the capture may teach that baseline. Pure; the store applies the result.

use crate::events::{Observations, Severity, Strength, TowerSeen, printable};
use crate::store::{Baseline, DecodeStatus};
use chrono::{DateTime, Duration, TimeZone, Utc};
use std::collections::{HashMap, HashSet};

/// Default length of Fixed's learning period, days (the add-on option `fixed_learning_days`).
pub const LEARN_DAYS: i64 = 14;
pub const DEFAULT_GAP_MIN: i64 = 108;
pub const CLUSTER_MIN: i64 = 30;
pub const MIN_GAPS_FOR_MEDIAN: usize = 10;
pub const BACK_TO_BACK_MIN: i64 = 5;
pub const SPIKE_FACTOR: f64 = 10.0;
pub const SPIKE_WINDOW_DAYS: i64 = 7;
pub const SPIKE_HISTORY_HOURS: usize = 48;
pub const SPIKE_MIN_FRAMES: u64 = 100;
pub const SPIKE_MIN_FAILURES: u64 = 50;
/// More distinct SIB1 towers than this in one capture is a flood, not a drive.
pub const TOWER_FLOOD_MAX: usize = 200;
/// Longest finding `detail` stored: lists are cut short with "... +N more".
pub const DETAIL_MAX: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Fixed,
    Mobile,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Fixed => "fixed",
            Profile::Mobile => "mobile",
        }
    }

    /// `mixed` and anything unrecognised are judged as mobile, the stricter baseline.
    pub fn from_stored(s: &str) -> Profile {
        match s {
            "fixed" => Profile::Fixed,
            _ => Profile::Mobile,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Worth telling the owner about.
    Notify,
    /// Only counted.
    Count,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Notify => "notify",
            Level::Count => "count",
        }
    }
}

/// Distinct analysers that each get their own High finding in one capture; the rest
/// fold into one `analyser_overflow` (Rayhunter ships fewer, so only a compromised
/// decoder gets here).
pub const MAX_HIGH_ANALYSERS: usize = 16;
pub const ANALYSER_OVERFLOW: &str = "analyser_overflow";
pub const ANALYSER_HIGH: &str = "analyser_high";
pub const ANALYSER_OTHER: &str = "analyser_other";
pub const NEW_TOWER: &str = "new_tower";
/// A new tower with an identity request on its heels: what a catcher does to get the IMSI.
pub const NEW_TOWER_IDENTITY: &str = "new_tower_identity";
/// A held (unlearned) new tower seen again.
pub const NEW_TOWER_RECUR: &str = "new_tower_recur";
pub const NEW_TOWER_WEAK: &str = "new_tower_weak";
/// Fixed after learning: a new sector of a site (network, area, eNodeB) already in the
/// baseline. Learned, not held: another antenna face of a known tower showing through.
pub const NEW_TOWER_SECTOR: &str = "new_tower_sector";
/// An identity request this long after a new tower's first sighting corroborates it.
pub const IDENTITY_AFTER_TOWER_MIN: i64 = 10;
/// How long a held tower waits for a second sighting before it is forgotten.
pub const HOLD_DAYS: i64 = 7;
pub const IDENTITY_OFF_RHYTHM: &str = "identity_off_rhythm";
pub const FAILURE_SPIKE: &str = "failure_spike";
pub const DECODER_FAILURE: &str = "decoder_failure";
pub const ARCHIVE_CORRUPT: &str = "archive_corrupt";
pub const ARCHIVE_MISSING: &str = "archive_missing";
pub const TOWER_FLOOD: &str = "tower_flood";
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub check: &'static str,
    pub level: Level,
    pub detail: String,
}

/// What a capture adds to the baselines, applied once and only with its findings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Learn {
    pub towers: Vec<(String, Strength)>,
    /// New SIB1 towers to hold rather than learn (Fixed, after learning).
    pub hold: Vec<String>,
    pub identity_ts: Vec<DateTime<Utc>>,
    /// (hour, failures, frames)
    pub failure_hours: Vec<(DateTime<Utc>, u64, u64)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Judgement {
    pub profile: Profile,
    pub findings: Vec<Finding>,
    pub learn: Option<Learn>,
    pub spans_switch: bool,
    pub suppressed: bool,
    /// Were the capture's towers already known here? (see `towers_known`)
    pub towers_known: Option<bool>,
}

pub struct Settings {
    pub tolerance_min: i64,
    /// How long Fixed learns before its comparisons notify.
    pub learn_days: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            tolerance_min: 15,
            learn_days: LEARN_DAYS,
        }
    }
}

pub struct Input<'a> {
    pub profile: Profile,
    pub status: DecodeStatus,
    pub seen: &'a Observations,
    pub baseline: &'a Baseline,
    pub prev_identity: Option<DateTime<Utc>>,
    pub failure_history: &'a [(DateTime<Utc>, u64, u64)],
    pub now: DateTime<Utc>,
    pub settings: &'a Settings,
}

/// Whether every fully identified (SIB1) tower in a capture is already in the profile's
/// baseline. `None` when it has none: a channel-only sighting cannot be matched.
/// Known means seen here before, not legitimate: a fake cell can copy a real one's IDs.
pub fn towers_known(seen: &Observations, baseline: &Baseline) -> Option<bool> {
    let mut any = false;
    for t in seen.towers.iter().filter(|t| t.strength == Strength::Sib1) {
        any = true;
        if !baseline.towers.contains(&t.key) {
            return Some(false);
        }
    }
    any.then_some(true)
}

/// The site of a SIB1 key: network, area and eNodeB (the 28-bit cell id less its 8-bit
/// sector). `None` for PCI-only keys and an unknown network.
pub fn site_of(key: &str) -> Option<(&str, &str, u64)> {
    let mut p = key.split(':');
    if p.next()? != "sib1" {
        return None;
    }
    let (plmn, tac, cell) = (p.next()?, p.next()?, p.next()?.parse::<u64>().ok()?);
    (plmn != "-" && p.next().is_none()).then_some((plmn, tac, cell >> 8))
}

/// Whether a sector of `key`'s site is in `towers`.
pub fn site_known(key: &str, towers: &HashSet<String>) -> bool {
    let Some(site) = site_of(key) else { return false };
    towers.iter().any(|k| site_of(k) == Some(site))
}

/// Times before this come from a unit whose clock never synced.
fn synced_from() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap()
}

/// A stamp further past `now` than this is not a real time: the unit's clock follows
/// NITZ (two-digit year), so a fake base station can set it anywhere up to 2099.
const FUTURE_SLACK_DAYS: i64 = 1;

fn future(t: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    t > now + Duration::days(FUTURE_SLACK_DAYS)
}

/// A real wall-clock time: from 2020 up to a day past `now` (the add-on's clock).
pub fn synced(t: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    t >= synced_from() && !future(t, now)
}

/// RFC 3339 only; the guest's strings are hostile, so anything else is `None`.
pub fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// The spec's level table. `learning` softens only the checks that compare against
/// a baseline; analyser warnings, decoder failure and archive corruption never learn.
pub fn level(check: &str, profile: Profile, learning: bool) -> Level {
    let fixed = profile == Profile::Fixed;
    match check {
        ANALYSER_HIGH | ANALYSER_OVERFLOW | DECODER_FAILURE | ARCHIVE_CORRUPT | TOWER_FLOOD => {
            Level::Notify
        }
        NEW_TOWER_IDENTITY | NEW_TOWER_RECUR | IDENTITY_OFF_RHYTHM | FAILURE_SPIKE
            if fixed && !learning =>
        {
            Level::Notify
        }
        _ => Level::Count,
    }
}

/// Every detail is printable and at most `DETAIL_MAX` bytes, whatever went into it.
fn finding(check: &'static str, profile: Profile, learning: bool, detail: String) -> Finding {
    Finding {
        check,
        level: level(check, profile, learning),
        detail: printable(&detail, DETAIL_MAX),
    }
}

/// `prefix` and as many items as fit in `DETAIL_MAX`, then "... +N more".
fn listed(prefix: &str, items: &[String]) -> String {
    // Room for ", ... +200000 more" and then some.
    const TAIL: usize = 32;
    let mut s = prefix.to_string();
    for (n, item) in items.iter().enumerate() {
        let sep = if n == 0 { "" } else { ", " };
        let last = n + 1 == items.len();
        let room = if last { DETAIL_MAX } else { DETAIL_MAX - TAIL };
        if s.len() + sep.len() + item.len() > room {
            s.push_str(&format!("{sep}... +{} more", items.len() - n));
            break;
        }
        s.push_str(sep);
        s.push_str(item);
    }
    s
}

/// Upper median for an even count; the spec only needs a stable middle.
fn median<T: Copy + PartialOrd>(v: &mut [T]) -> Option<T> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(v[v.len() / 2])
}

/// Gaps (seconds) between consecutive identity requests. A gap that is negative
/// (the guest clock stepped back) is not measurable and is skipped, never judged.
/// Inside one capture a pair is measured only if both stamps are unsynced or both
/// synced (an unsynced-to-synced pair spans a clock step, e.g. NITZ after attach);
/// a far-future stamp is in no pair. Across captures only a synced pair counts.
fn gaps(stamps: &[DateTime<Utc>], prev: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Vec<i64> {
    let mut out = Vec::new();
    if let (Some(p), Some(f)) = (prev, stamps.first()) {
        if synced(p, now) && synced(*f, now) {
            out.push((*f - p).num_seconds());
        }
    }
    out.extend(
        stamps
            .windows(2)
            .filter(|w| !future(w[0], now) && !future(w[1], now))
            .filter(|w| synced(w[0], now) == synced(w[1], now))
            .map(|w| (w[1] - w[0]).num_seconds()),
    );
    out.retain(|g| *g >= 0);
    out
}

pub fn judge(i: &Input) -> (Vec<Finding>, Option<Learn>) {
    let mut out = Vec::new();
    match i.status {
        DecodeStatus::ArchiveCorrupt => {
            let d = "archive copy no longer matches its recorded hash".to_string();
            return (vec![finding(ARCHIVE_CORRUPT, i.profile, false, d)], None);
        }
        DecodeStatus::ArchiveMissing => {
            let d = "archive copy is gone".to_string();
            return (vec![finding(ARCHIVE_MISSING, i.profile, false, d)], None);
        }
        DecodeStatus::DecoderFailure => {
            let d = "the decoder failed; checks cover what arrived".to_string();
            out.push(finding(DECODER_FAILURE, i.profile, false, d));
        }
        DecodeStatus::Ok => {}
    }
    let seen = i.seen;
    let fixed = i.profile == Profile::Fixed;
    // D2: Fixed learns for 14 days from its first clean capture.
    let learning = fixed
        && i.baseline
            .fixed_since
            .is_none_or(|s| i.now - s < Duration::days(i.settings.learn_days));

    // Analyser warnings: one High finding per analyser, in order of first warning.
    let mut other = 0;
    let mut high: Vec<(&str, u64, &str)> = Vec::new();
    let mut slot: HashMap<&str, usize> = HashMap::new();
    for w in &seen.warnings {
        match w.severity {
            Severity::High => {
                let at = *slot.entry(w.analyzer.as_str()).or_insert_with(|| {
                    high.push((w.analyzer.as_str(), 0, w.msg.as_str()));
                    high.len() - 1
                });
                high[at].1 += 1;
            }
            Severity::Medium | Severity::Low => other += 1,
            Severity::Info => {}
        }
    }
    let extra = high.len().saturating_sub(MAX_HIGH_ANALYSERS);
    for (analyzer, count, first) in high.into_iter().take(MAX_HIGH_ANALYSERS) {
        let d = format!("{analyzer}: {count} high warning(s); first: {first}");
        out.push(finding(ANALYSER_HIGH, i.profile, learning, d));
    }
    if extra > 0 {
        let d = format!("{extra} more analysers with high warnings");
        out.push(finding(ANALYSER_OVERFLOW, i.profile, learning, d));
    }
    if other > 0 {
        let d = format!("{other} medium/low warnings");
        out.push(finding(ANALYSER_OTHER, i.profile, learning, d));
    }

    // Towers. A flood teaches nothing (D6) and hides the per-tower findings. Only
    // SIB1 keys count: PCI-only keys never notify, and a long drive can pass 200.
    let distinct: HashSet<&str> = seen
        .towers
        .iter()
        .filter(|t| t.strength == Strength::Sib1)
        .map(|t| t.key.as_str())
        .collect();
    let flood = distinct.len() > TOWER_FLOOD_MAX;
    // After learning, Fixed holds a new SIB1 tower instead of learning it; it notifies
    // only when corroborated by an identity request or seen again while held.
    let hold = fixed && !learning;
    let is_new = |t: &TowerSeen| !i.baseline.towers.contains(&t.key);
    // A new sector of a known site is learned at once, even if it was held before.
    let sector = |t: &TowerSeen| hold && t.strength == Strength::Sib1 && site_known(&t.key, &i.baseline.towers);
    let recurs = |t: &TowerSeen| {
        hold && t.strength == Strength::Sib1 && i.baseline.held.contains(&t.key) && !sector(t)
    };
    let mut held_new: Vec<String> = Vec::new();
    if flood {
        let d = format!("{} distinct SIB1 towers in one capture", distinct.len());
        out.push(finding(TOWER_FLOOD, i.profile, learning, d));
    } else {
        let recurring: Vec<String> = seen
            .towers
            .iter()
            .filter(|t| is_new(t) && recurs(t))
            .map(|t| t.key.clone())
            .collect();
        if !recurring.is_empty() {
            let d = listed("seen again: ", &recurring);
            out.push(finding(NEW_TOWER_RECUR, i.profile, learning, d));
        }
        let sectors: Vec<String> = seen
            .towers
            .iter()
            .filter(|t| is_new(t) && sector(t))
            .map(|t| t.key.clone())
            .collect();
        if !sectors.is_empty() {
            let d = listed("new sector of a known site: ", &sectors);
            out.push(finding(NEW_TOWER_SECTOR, i.profile, learning, d));
        }
        for (strength, check) in [(Strength::Sib1, NEW_TOWER), (Strength::Pci, NEW_TOWER_WEAK)] {
            let new: Vec<String> = seen
                .towers
                .iter()
                .filter(|t| t.strength == strength && is_new(t) && !recurs(t) && !sector(t))
                .map(|t| t.key.clone())
                .collect();
            if !new.is_empty() {
                let d = listed("new: ", &new);
                out.push(finding(check, i.profile, learning, d));
            }
        }
        if hold {
            let ids: Vec<DateTime<Utc>> = seen
                .identity_ts
                .iter()
                .filter_map(|s| s.as_deref().and_then(parse_ts))
                .collect();
            let window = Duration::minutes(IDENTITY_AFTER_TOWER_MIN);
            let mut asked = Vec::new();
            for t in seen.towers.iter().filter(|t| t.strength == Strength::Sib1 && is_new(t) && !recurs(t)) {
                if !sector(t) {
                    held_new.push(t.key.clone());
                }
                let Some(t0) = t.ts.as_deref().and_then(parse_ts) else { continue };
                if ids.iter().any(|id| *id >= t0 && *id - t0 <= window) {
                    asked.push(t.key.clone());
                }
            }
            if !asked.is_empty() {
                let d = listed("identity request after: ", &asked);
                out.push(finding(NEW_TOWER_IDENTITY, i.profile, learning, d));
            }
        }
    }

    // Identity rhythm.
    let stamps: Vec<DateTime<Utc>> = seen
        .identity_ts
        .iter()
        .filter_map(|s| s.as_deref().and_then(parse_ts))
        .collect();
    let mut expected = DEFAULT_GAP_MIN * 60;
    if fixed && !learning && i.baseline.fixed_gaps_secs.len() >= MIN_GAPS_FOR_MEDIAN {
        let mut g = i.baseline.fixed_gaps_secs.clone();
        expected = median(&mut g).unwrap_or(expected);
    }
    let tol = i.settings.tolerance_min * 60;
    let off: Vec<i64> = gaps(&stamps, i.prev_identity, i.now)
        .into_iter()
        .filter(|g| *g < CLUSTER_MIN * 60 || (g - expected).abs() > tol)
        .collect();
    if !off.is_empty() {
        let mins: Vec<String> = off.iter().map(|g| format!("{} min", g / 60)).collect();
        let d = listed("off-rhythm gaps: ", &mins);
        out.push(finding(IDENTITY_OFF_RHYTHM, i.profile, learning, d));
    }

    // Decode-failure spikes (D3: the rate, not the count).
    let mut spikes = Vec::new();
    let mut spike_learning = false;
    for (h, failures, frames) in &seen.failure_hours {
        let Some(h) = h
            .as_deref()
            .and_then(parse_ts)
            .filter(|h| synced(*h, i.now))
        else {
            continue;
        };
        if *frames < SPIKE_MIN_FRAMES || *failures < SPIKE_MIN_FAILURES {
            continue;
        }
        let mut rates: Vec<f64> = i
            .failure_history
            .iter()
            .filter(|(t, _, f)| {
                *t >= h - Duration::days(SPIKE_WINDOW_DAYS) && *t < h && *f >= SPIKE_MIN_FRAMES
            })
            .map(|(_, n, f)| *n as f64 / *f as f64)
            .collect();
        let history_hours = rates.len();
        let Some(base) = median(&mut rates) else {
            continue;
        };
        let rate = *failures as f64 / *frames as f64;
        if rate > SPIKE_FACTOR * base {
            spike_learning |= history_hours < SPIKE_HISTORY_HOURS;
            spikes.push(format!(
                "{} {:.2}%",
                h.format("%Y-%m-%dT%H:%MZ"),
                rate * 100.0
            ));
        }
    }
    if !spikes.is_empty() {
        let d = listed("failure rate spike: ", &spikes);
        out.push(finding(
            FAILURE_SPIKE,
            i.profile,
            spike_learning || learning,
            d,
        ));
    }

    // D3: a capture teaches the rhythm only if every request has a real stamp; dropping
    // one would join its neighbours into a gap the checks never measured.
    let all_real = seen.identity_ts.iter().all(|s| {
        s.as_deref()
            .and_then(parse_ts)
            .is_some_and(|t| !future(t, i.now))
    });

    // Learning: only a clean decode teaches, and never a flood. Identity stamps keep
    // unsynced ones (in-capture gaps are valid) but never far-future ones (they would
    // pin the baseline's window); failure hours must be synced.
    let learn = (i.status == DecodeStatus::Ok && !flood).then(|| Learn {
        towers: seen
            .towers
            .iter()
            .filter(|t| !held_new.contains(&t.key))
            .map(|t| (t.key.clone(), t.strength))
            .collect(),
        hold: held_new.clone(),
        identity_ts: if all_real { stamps } else { Vec::new() },
        failure_hours: seen
            .failure_hours
            .iter()
            .filter_map(|(h, n, f)| {
                let h = h
                    .as_deref()
                    .and_then(parse_ts)
                    .filter(|h| synced(*h, i.now))?;
                Some((h, *n, *f))
            })
            .collect(),
    });
    (out, learn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{TowerSeen, WarningSeen};

    fn t(s: &str) -> DateTime<Utc> {
        parse_ts(s).unwrap()
    }
    fn now() -> DateTime<Utc> {
        t("2026-10-11T12:00:00Z")
    }
    /// A Fixed baseline that finished learning 6 days ago.
    fn past() -> Baseline {
        Baseline {
            fixed_since: Some(now() - Duration::days(20)),
            ..Baseline::default()
        }
    }
    fn run(
        profile: Profile,
        status: DecodeStatus,
        seen: &Observations,
        baseline: &Baseline,
    ) -> (Vec<Finding>, Option<Learn>) {
        run_full(profile, status, seen, baseline, None, &[], 15)
    }
    fn run_full(
        profile: Profile,
        status: DecodeStatus,
        seen: &Observations,
        baseline: &Baseline,
        prev: Option<DateTime<Utc>>,
        hist: &[(DateTime<Utc>, u64, u64)],
        tol: i64,
    ) -> (Vec<Finding>, Option<Learn>) {
        judge(&Input {
            profile,
            status,
            seen,
            baseline,
            prev_identity: prev,
            failure_history: hist,
            now: now(),
            settings: &Settings {
                tolerance_min: tol,
                ..Settings::default()
            },
        })
    }
    fn ok(p: Profile, seen: &Observations, b: &Baseline) -> Vec<Finding> {
        run(p, DecodeStatus::Ok, seen, b).0
    }
    fn find<'a>(f: &'a [Finding], check: &str) -> Vec<&'a Finding> {
        f.iter().filter(|x| x.check == check).collect()
    }
    fn tower(key: &str, strength: Strength) -> TowerSeen {
        TowerSeen {
            key: key.into(),
            strength,
            ts: None,
        }
    }
    #[test]
    fn towers_known_only_counts_fully_identified_towers() {
        let base = Baseline {
            towers: ["310-260-1-1".to_string()].into_iter().collect(),
            ..Baseline::default()
        };
        let seen = |ts: Vec<TowerSeen>| Observations {
            towers: ts,
            ..Observations::default()
        };
        assert_eq!(towers_known(&seen(vec![]), &base), None, "no towers");
        assert_eq!(
            towers_known(&seen(vec![tower("pci:7:5230", Strength::Pci)]), &base),
            None,
            "channel-only towers cannot be matched"
        );
        assert_eq!(
            towers_known(&seen(vec![tower("310-260-1-1", Strength::Sib1)]), &base),
            Some(true)
        );
        assert_eq!(
            towers_known(
                &seen(vec![
                    tower("310-260-1-1", Strength::Sib1),
                    tower("310-260-1-2", Strength::Sib1),
                    tower("pci:7:5230", Strength::Pci)
                ]),
                &base
            ),
            Some(false)
        );
    }

    /// The learning period is a setting: 8 days of Fixed is done at 7, still learning at 14.
    #[test]
    fn the_learning_period_is_a_setting() {
        let b = Baseline {
            fixed_since: Some(now() - Duration::days(8)),
            held: ["310-260-77-1".to_string()].into_iter().collect(),
            ..Baseline::default()
        };
        let seen = Observations {
            towers: vec![tower("310-260-77-1", Strength::Sib1)],
            ..Observations::default()
        };
        let level_with = |days: i64| {
            let f = judge(&Input {
                profile: Profile::Fixed,
                status: DecodeStatus::Ok,
                seen: &seen,
                baseline: &b,
                prev_identity: None,
                failure_history: &[],
                now: now(),
                settings: &Settings {
                    tolerance_min: 15,
                    learn_days: days,
                },
            })
            .0;
            (f[0].check, f[0].level)
        };
        assert_eq!(level_with(7), (NEW_TOWER_RECUR, Level::Notify));
        assert_eq!(level_with(14), (NEW_TOWER, Level::Count));
        assert_eq!(Settings::default().learn_days, LEARN_DAYS);
    }
    fn warn(severity: Severity, msg: &str) -> WarningSeen {
        WarningSeen {
            severity,
            analyzer: "An".into(),
            msg: msg.into(),
            ts: None,
        }
    }
    /// Identity stamps `mins` minutes after a synced base.
    fn ids(mins: &[i64]) -> Observations {
        let base = t("2026-10-11T00:00:00Z");
        Observations {
            identity_ts: mins
                .iter()
                .map(|m| Some((base + Duration::minutes(*m)).to_rfc3339()))
                .collect(),
            ..Observations::default()
        }
    }
    fn rhythm(f: &[Finding]) -> Vec<&Finding> {
        find(f, IDENTITY_OFF_RHYTHM)
    }
    fn hour(n: i64) -> DateTime<Utc> {
        t("2026-10-01T00:00:00Z") + Duration::hours(n)
    }
    /// n history hours, each at 16/128 = 0.125.
    fn hist(n: i64) -> Vec<(DateTime<Utc>, u64, u64)> {
        (0..n).map(|i| (hour(i), 16, 128)).collect()
    }
    /// n history hours, each at 2/10_000 = 0.0002 (a 10x spike clears the 50-failure floor).
    fn hist_quiet(n: i64) -> Vec<(DateTime<Utc>, u64, u64)> {
        (0..n).map(|i| (hour(i), 2, 10_000)).collect()
    }
    fn spike_obs(h: &str, failures: u64, frames: u64) -> Observations {
        Observations {
            failure_hours: vec![(Some(h.into()), failures, frames)],
            ..Observations::default()
        }
    }
    fn spike(seen: &Observations, hist: &[(DateTime<Utc>, u64, u64)]) -> Vec<Finding> {
        let f = run_full(
            Profile::Fixed,
            DecodeStatus::Ok,
            seen,
            &past(),
            None,
            hist,
            15,
        )
        .0;
        f.into_iter().filter(|x| x.check == FAILURE_SPIKE).collect()
    }

    /// `hours` consecutive history hours ending just before 2026-10-08T00, each at
    /// `failures`/`frames`.
    fn hist_rate(hours: i64, failures: u64, frames: u64) -> Vec<(DateTime<Utc>, u64, u64)> {
        let spike_hour = t("2026-10-08T00:00:00Z");
        (1..=hours)
            .map(|i| (spike_hour - Duration::hours(i), failures, frames))
            .collect()
    }
    /// Like `spike`, but Fixed has been learning for `learned_days` (None: not started).
    fn spike_fixed(
        seen: &Observations,
        hist: &[(DateTime<Utc>, u64, u64)],
        learned_days: Option<i64>,
    ) -> Vec<Finding> {
        let b = Baseline {
            fixed_since: learned_days.map(|d| now() - Duration::days(d)),
            ..Baseline::default()
        };
        let f = run_full(Profile::Fixed, DecodeStatus::Ok, seen, &b, None, hist, 15).0;
        f.into_iter().filter(|x| x.check == FAILURE_SPIKE).collect()
    }
    /// Mobile, decoded fine, these identity stamps, at 2026-10-12T00:00:00Z.
    fn judge_identity(stamps: &[Option<&str>]) -> (Vec<Finding>, Option<Learn>) {
        let seen = Observations {
            identity_ts: stamps.iter().map(|s| s.map(String::from)).collect(),
            ..Observations::default()
        };
        judge(&Input {
            profile: Profile::Mobile,
            status: DecodeStatus::Ok,
            seen: &seen,
            baseline: &Baseline::default(),
            prev_identity: None,
            failure_history: &[],
            now: t("2026-10-12T00:00:00Z"),
            settings: &Settings::default(),
        })
    }
    fn findings_for_warnings(warnings: Vec<WarningSeen>) -> Vec<Finding> {
        let seen = Observations {
            warnings,
            ..Observations::default()
        };
        ok(Profile::Mobile, &seen, &Baseline::default())
    }
    fn high_warnings(n: usize) -> Vec<WarningSeen> {
        (0..n)
            .map(|n| WarningSeen {
                severity: Severity::High,
                analyzer: format!("a{n}"),
                msg: "m".into(),
                ts: None,
            })
            .collect()
    }

    #[test]
    fn level_table() {
        use Level::*;
        use Profile::*;
        // (check, fixed, mobile, learnable)
        let rows = [
            (ANALYSER_HIGH, Notify, Notify, false),
            (ANALYSER_OTHER, Count, Count, false),
            (NEW_TOWER, Count, Count, true),
            (NEW_TOWER_IDENTITY, Notify, Count, true),
            (NEW_TOWER_RECUR, Notify, Count, true),
            (NEW_TOWER_WEAK, Count, Count, true),
            (IDENTITY_OFF_RHYTHM, Notify, Count, true),
            (FAILURE_SPIKE, Notify, Count, true),
            (DECODER_FAILURE, Notify, Notify, false),
            (ARCHIVE_CORRUPT, Notify, Notify, false),
            (ARCHIVE_MISSING, Count, Count, false),
            (TOWER_FLOOD, Notify, Notify, false),
        ];
        for (c, f, m, learnable) in rows {
            assert_eq!(level(c, Fixed, false), f, "{c} fixed");
            assert_eq!(level(c, Mobile, false), m, "{c} mobile");
            // Learning only softens the learned checks.
            assert_eq!(
                level(c, Fixed, true),
                if learnable { Count } else { f },
                "{c} fixed learning"
            );
            assert_eq!(
                level(c, Mobile, true),
                if learnable { Count } else { m },
                "{c} mobile learning"
            );
        }
    }

    #[test]
    fn level_strings() {
        assert_eq!(Level::Notify.as_str(), "notify");
        assert_eq!(Level::Count.as_str(), "count");
    }

    #[test]
    fn empty_fixed_baseline_is_learning_so_new_tower_counts() {
        let seen = Observations {
            towers: vec![tower("sib1:1:2:3", Strength::Sib1)],
            ..Observations::default()
        };
        let f = ok(Profile::Fixed, &seen, &Baseline::default());
        assert_eq!(find(&f, NEW_TOWER)[0].level, Level::Count);
    }

    #[test]
    fn new_tower_learning_ends_at_14_days() {
        let seen = Observations {
            towers: vec![
                tower("sib1:1:2:3", Strength::Sib1),
                tower("sib1:1:2:4", Strength::Sib1),
            ],
            ..Observations::default()
        };
        let mut b = Baseline::default();
        b.fixed_since = Some(now() - Duration::days(13) - Duration::hours(23));
        let f = ok(Profile::Fixed, &seen, &b);
        assert_eq!(f.len(), 1, "one finding listing both keys");
        assert_eq!(f[0].level, Level::Count);
        assert!(f[0].detail.contains("sib1:1:2:3") && f[0].detail.contains("sib1:1:2:4"));
        b.fixed_since = Some(now() - Duration::days(14));
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &seen, &b);
        assert_eq!((f.len(), f[0].check, f[0].level), (1, NEW_TOWER, Level::Count));
        let learn = learn.unwrap();
        assert!(learn.towers.is_empty(), "after learning, a lone new tower is held, not learned");
        assert_eq!(learn.hold, ["sib1:1:2:3", "sib1:1:2:4"]);
    }

    fn tower_at(key: &str, ts: &str) -> TowerSeen {
        TowerSeen {
            key: key.into(),
            strength: Strength::Sib1,
            ts: Some(ts.into()),
        }
    }

    /// The 2026-10-24 case: a 34 s reselection to a never-seen cell, nothing asked of the phone.
    #[test]
    fn a_lone_new_tower_after_learning_counts_and_is_held() {
        let seen = Observations {
            towers: vec![tower_at("sib1:310-260:11111:87654321", "2026-10-11T11:27:59Z")],
            identity_ts: vec![Some("2026-10-11T10:40:00Z".into())],
            ..Observations::default()
        };
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &seen, &past());
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].check, f[0].level), (NEW_TOWER, Level::Count));
        let learn = learn.unwrap();
        assert!(learn.towers.is_empty());
        assert_eq!(learn.hold, ["sib1:310-260:11111:87654321"]);
    }

    #[test]
    fn an_identity_request_within_10_min_of_a_new_tower_notifies() {
        let at = |id: &str| Observations {
            towers: vec![tower_at("sib1:9:9:9", "2026-10-11T11:00:00Z")],
            identity_ts: vec![Some(id.into())],
            ..Observations::default()
        };
        let corroborated = |id: &str| find(&ok(Profile::Fixed, &at(id), &past()), NEW_TOWER_IDENTITY).len();
        assert_eq!(corroborated("2026-10-11T11:00:00Z"), 1, "same second");
        assert_eq!(corroborated("2026-10-11T11:10:00Z"), 1, "10 min is inside");
        assert_eq!(corroborated("2026-10-11T11:10:01Z"), 0, "just past 10 min");
        assert_eq!(corroborated("2026-10-11T10:59:59Z"), 0, "before the tower appeared");
        let f = ok(Profile::Fixed, &at("2026-10-11T11:00:30Z"), &past());
        let hit = find(&f, NEW_TOWER_IDENTITY);
        assert_eq!(hit[0].level, Level::Notify);
        assert!(hit[0].detail.contains("sib1:9:9:9"));
    }

    #[test]
    fn a_new_tower_without_a_time_is_never_corroborated() {
        let seen = Observations {
            towers: vec![tower("sib1:9:9:9", Strength::Sib1)],
            identity_ts: vec![Some("2026-10-11T11:00:00Z".into())],
            ..Observations::default()
        };
        assert!(find(&ok(Profile::Fixed, &seen, &past()), NEW_TOWER_IDENTITY).is_empty());
    }

    #[test]
    fn a_held_tower_seen_again_notifies_and_is_learned() {
        let seen = Observations {
            towers: vec![tower("sib1:9:9:9", Strength::Sib1), tower("sib1:9:9:8", Strength::Sib1)],
            ..Observations::default()
        };
        let mut b = past();
        b.held.insert("sib1:9:9:9".into());
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &seen, &b);
        let recur = find(&f, NEW_TOWER_RECUR);
        assert_eq!((recur.len(), recur[0].level), (1, Level::Notify));
        assert!(recur[0].detail.contains("sib1:9:9:9") && !recur[0].detail.contains("sib1:9:9:8"));
        let new = find(&f, NEW_TOWER);
        assert!(new[0].detail.contains("sib1:9:9:8") && !new[0].detail.contains("sib1:9:9:9"));
        let learn = learn.unwrap();
        assert_eq!(learn.towers, [("sib1:9:9:9".to_string(), Strength::Sib1)]);
        assert_eq!(learn.hold, ["sib1:9:9:8"]);
    }

    /// The 2026-11-11 case: sectors 12 and 22 of a site whose sector 2 Fixed already knows.
    #[test]
    fn a_new_sector_of_a_known_site_counts_and_is_learned_not_held() {
        let seen = Observations {
            towers: vec![
                tower("sib1:001-01:100:256022", Strength::Sib1),
                tower("sib1:001-01:100:256012", Strength::Sib1),
                tower("sib1:001-01:100:255750", Strength::Sib1),
            ],
            ..Observations::default()
        };
        let mut b = past();
        b.towers.insert("sib1:001-01:100:256002".into());
        b.held.insert("sib1:001-01:100:256022".into());
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &seen, &b);
        assert!(find(&f, NEW_TOWER_RECUR).is_empty(), "a held sibling seen again stays quiet");
        let sector = find(&f, NEW_TOWER_SECTOR);
        assert_eq!((sector.len(), sector[0].level), (1, Level::Count));
        assert!(sector[0].detail.contains("256022") && sector[0].detail.contains("256012"));
        let new = find(&f, NEW_TOWER);
        assert!(new[0].detail.contains("255750") && !new[0].detail.contains("256012"));
        let learn = learn.unwrap();
        assert_eq!(learn.hold, ["sib1:001-01:100:255750"]);
        let learned: Vec<&str> = learn.towers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(learned, ["sib1:001-01:100:256022", "sib1:001-01:100:256012"]);
    }

    #[test]
    fn a_new_sector_is_still_corroborated_by_an_identity_request() {
        let seen = Observations {
            towers: vec![tower_at("sib1:001-01:100:256022", "2026-10-11T11:00:00Z")],
            identity_ts: vec![Some("2026-10-11T11:02:00Z".into())],
            ..Observations::default()
        };
        let mut b = past();
        b.towers.insert("sib1:001-01:100:256002".into());
        let f = ok(Profile::Fixed, &seen, &b);
        let hit = find(&f, NEW_TOWER_IDENTITY);
        assert_eq!((hit.len(), hit[0].level), (1, Level::Notify));
    }

    #[test]
    fn a_site_is_its_network_area_and_enodeb() {
        assert_eq!(site_of("sib1:001-01:100:256022"), Some(("001-01", "100", 1000)));
        assert_eq!(site_of("sib1:-:100:256022"), None, "an unknown network matches nothing");
        assert_eq!(site_of("pci:101:1000"), None);
        assert_eq!(site_of("sib1:001-01:100:x"), None);
        let mut b = past();
        b.towers.insert("sib1:001-01:100:256002".into());
        let known = |k: &str| site_known(k, &b.towers);
        assert!(known("sib1:001-01:100:256022"));
        assert!(!known("sib1:001-01:101:256022"), "another area");
        assert!(!known("sib1:001-02:100:256022"), "another network");
        assert!(!known("sib1:001-01:100:256278"), "the next site");
    }

    #[test]
    fn while_learning_and_in_mobile_new_towers_are_learned_not_held() {
        let seen = Observations {
            towers: vec![tower("sib1:9:9:9", Strength::Sib1)],
            ..Observations::default()
        };
        let mut b = past();
        b.held.insert("sib1:9:9:9".into());
        let learning = Baseline { held: b.held.clone(), ..Baseline::default() };
        for (p, base) in [(Profile::Mobile, &b), (Profile::Fixed, &learning)] {
            let (f, learn) = run(p, DecodeStatus::Ok, &seen, base);
            assert!(find(&f, NEW_TOWER_RECUR).is_empty(), "{p:?}");
            let learn = learn.unwrap();
            assert_eq!(learn.towers.len(), 1, "{p:?}");
            assert!(learn.hold.is_empty(), "{p:?}");
        }
    }

    #[test]
    fn known_towers_are_quiet_and_mobile_new_tower_counts() {
        let seen = Observations {
            towers: vec![tower("sib1:1:2:3", Strength::Sib1)],
            ..Observations::default()
        };
        let mut b = past();
        b.towers.insert("sib1:1:2:3".into());
        assert!(ok(Profile::Fixed, &seen, &b).is_empty());
        assert_eq!(ok(Profile::Mobile, &seen, &past())[0].level, Level::Count);
    }

    #[test]
    fn weak_towers_never_notify() {
        let seen = Observations {
            towers: vec![
                tower("pci:1:2", Strength::Pci),
                tower("pci:3:4", Strength::Pci),
            ],
            ..Observations::default()
        };
        for p in [Profile::Fixed, Profile::Mobile] {
            let f = ok(p, &seen, &past());
            assert_eq!(f.len(), 1);
            assert_eq!((f[0].check, f[0].level), (NEW_TOWER_WEAK, Level::Count));
        }
    }

    fn flood(n: usize) -> Observations {
        Observations {
            towers: (0..n)
                .map(|i| tower(&format!("sib1:1:2:{i}"), Strength::Sib1))
                .collect(),
            ..Observations::default()
        }
    }

    #[test]
    fn flood_at_200_is_not_one_at_201_is() {
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &flood(200), &past());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check, NEW_TOWER);
        assert_eq!(learn.unwrap().hold.len(), 200);

        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &flood(201), &past());
        assert_eq!(f.len(), 1, "no tower findings besides the flood");
        assert_eq!((f[0].check, f[0].level), (TOWER_FLOOD, Level::Notify));
        assert!(learn.is_none());
    }

    #[test]
    fn rhythm_boundaries() {
        // Fixed, past learning, no median (too few gaps): expected 108, tol 15.
        for (m, off) in [
            (108, false),
            (93, false),
            (123, false),
            (92, true),
            (124, true),
        ] {
            let f = ok(Profile::Fixed, &ids(&[0, m]), &past());
            assert_eq!(!rhythm(&f).is_empty(), off, "gap {m}");
        }
    }

    #[test]
    fn rhythm_reports_all_off_gaps_in_one_finding() {
        let f = ok(Profile::Fixed, &ids(&[0, 10, 118, 128]), &past());
        assert_eq!(rhythm(&f).len(), 1);
        assert_eq!(rhythm(&f)[0].level, Level::Notify);
    }

    #[test]
    fn tolerance_is_a_setting() {
        let seen = ids(&[0, 140]);
        let b = past();
        let f = run_full(Profile::Fixed, DecodeStatus::Ok, &seen, &b, None, &[], 15).0;
        assert_eq!(rhythm(&f).len(), 1);
        let f = run_full(Profile::Fixed, DecodeStatus::Ok, &seen, &b, None, &[], 40).0;
        assert!(rhythm(&f).is_empty());
    }

    fn with_gaps(n: usize, mins: i64) -> Baseline {
        Baseline {
            fixed_gaps_secs: vec![mins * 60; n],
            ..past()
        }
    }

    #[test]
    fn cluster_29_is_off_30_is_not() {
        // Median 35 min makes 29 and 30 both within tolerance, so only the cluster rule decides.
        let b = with_gaps(10, 35);
        assert_eq!(rhythm(&ok(Profile::Fixed, &ids(&[0, 29]), &b)).len(), 1);
        assert!(rhythm(&ok(Profile::Fixed, &ids(&[0, 30]), &b)).is_empty());
    }

    #[test]
    fn median_needs_ten_gaps_and_a_finished_learning_period() {
        // 9 gaps: still 108, so a 50 min gap is off.
        let f = ok(Profile::Fixed, &ids(&[0, 50]), &with_gaps(9, 50));
        assert_eq!(rhythm(&f).len(), 1);
        // 10 gaps: the median (50) is expected; 50 is on, 108 is off.
        assert!(rhythm(&ok(Profile::Fixed, &ids(&[0, 50]), &with_gaps(10, 50))).is_empty());
        assert_eq!(
            rhythm(&ok(Profile::Fixed, &ids(&[0, 108]), &with_gaps(10, 50))).len(),
            1
        );
        // Still learning: 108 is expected whatever the gaps say.
        let mut b = with_gaps(10, 50);
        b.fixed_since = Some(now() - Duration::days(3));
        assert_eq!(rhythm(&ok(Profile::Fixed, &ids(&[0, 50]), &b)).len(), 1);
        assert!(rhythm(&ok(Profile::Fixed, &ids(&[0, 108]), &b)).is_empty());
    }

    #[test]
    fn rhythm_while_learning_counts_and_mobile_counts() {
        let off = ids(&[0, 10]);
        let mut b = Baseline::default();
        assert_eq!(rhythm(&ok(Profile::Fixed, &off, &b))[0].level, Level::Count);
        b = past();
        assert_eq!(
            rhythm(&ok(Profile::Fixed, &off, &b))[0].level,
            Level::Notify
        );
        assert_eq!(
            rhythm(&ok(Profile::Mobile, &off, &b))[0].level,
            Level::Count
        );
    }

    #[test]
    fn prev_identity_counts_only_when_synced() {
        let first = t("2026-10-11T00:00:00Z");
        let seen = ids(&[0]);
        let b = past();
        let run_prev =
            |prev| run_full(Profile::Fixed, DecodeStatus::Ok, &seen, &b, prev, &[], 15).0;
        // 10 min before: a cluster.
        assert_eq!(
            rhythm(&run_prev(Some(first - Duration::minutes(10)))).len(),
            1
        );
        // 108 min before: on rhythm.
        assert!(rhythm(&run_prev(Some(first - Duration::minutes(108)))).is_empty());
        // An unsynced previous stamp is never compared.
        assert!(rhythm(&run_prev(Some(t("1970-01-01T00:00:10Z")))).is_empty());
        // Nor is an unsynced first stamp compared with a synced previous one.
        let unsynced = Observations {
            identity_ts: vec![Some("1970-01-01T00:00:10Z".into())],
            ..Observations::default()
        };
        let f = run_full(
            Profile::Fixed,
            DecodeStatus::Ok,
            &unsynced,
            &b,
            Some(first),
            &[],
            15,
        )
        .0;
        assert!(rhythm(&f).is_empty());
    }

    #[test]
    fn unsynced_pairs_inside_one_capture_are_still_measured() {
        let seen = Observations {
            identity_ts: vec![
                Some("1970-01-01T00:00:00Z".into()),
                Some("1970-01-01T00:10:00Z".into()),
            ],
            ..Observations::default()
        };
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &seen, &past());
        assert_eq!(rhythm(&f).len(), 1);
        assert_eq!(learn.unwrap().identity_ts.len(), 2);
    }

    #[test]
    fn clock_sync_step_inside_a_capture_is_not_measured() {
        // Attach at boot (1970), then NITZ syncs: the pair spans a clock step.
        let seen = Observations {
            identity_ts: vec![
                Some("1970-01-01T00:00:30Z".into()),
                Some("2026-10-11T00:00:00Z".into()),
                Some("2026-10-11T01:48:00Z".into()),
            ],
            ..Observations::default()
        };
        let f = ok(Profile::Fixed, &seen, &past());
        assert!(rhythm(&f).is_empty(), "{f:?}");
    }

    #[test]
    fn negative_and_zero_gaps() {
        // A clock that steps back is not measurable, never off rhythm.
        let f = ok(Profile::Fixed, &ids(&[200, 100]), &past());
        assert!(rhythm(&f).is_empty());
        // Two at the same instant are inside the 30 min cluster.
        let f = ok(Profile::Fixed, &ids(&[100, 100]), &past());
        assert_eq!(rhythm(&f).len(), 1);
    }

    #[test]
    fn hostile_timestamps_do_not_panic() {
        assert_eq!(parse_ts("+13129-07-01T00:00:00.000Z"), None);
        assert_eq!(parse_ts("garbage"), None);
        assert_eq!(parse_ts(""), None);
        assert!(parse_ts("2026-10-11T00:00:00.000Z").is_some());
        let seen = Observations {
            identity_ts: vec![
                None,
                Some("+13129-07-01T00:00:00.000Z".into()),
                Some("garbage".into()),
                Some(String::new()),
                Some("1970-01-01T00:00:00Z".into()),
            ],
            failure_hours: vec![
                (None, 50, 500),
                (Some("garbage".into()), 50, 500),
                (Some("+13129-07-01T00:00:00.000Z".into()), 50, 500),
                (Some("1970-01-01T00:00:00Z".into()), 50, 500),
            ],
            ..Observations::default()
        };
        let (f, learn) = run_full(
            Profile::Fixed,
            DecodeStatus::Ok,
            &seen,
            &past(),
            None,
            &hist(60),
            15,
        );
        assert!(f.is_empty(), "{f:?}");
        let l = learn.unwrap();
        assert!(l.identity_ts.is_empty(), "a bad stamp teaches no rhythm");
        assert!(
            l.failure_hours.is_empty(),
            "store failure_hours never gets a 1970 hour"
        );
    }

    #[test]
    fn spike_history_floor_47_vs_48() {
        // 0.5 against a 0.0002 median is far past 10x.
        let seen = spike_obs("2026-10-08T00:00:00Z", 64, 128);
        let f = spike(&seen, &hist_quiet(47));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].level, Level::Count, "47 hours is still learning");
        assert!(f[0].detail.contains("2026-10-08"));
        let f = spike(&seen, &hist_quiet(48));
        assert_eq!(f[0].level, Level::Notify);
    }

    #[test]
    fn spike_threshold_is_strictly_above_10x() {
        // History 1/2048 per hour; 50/10_240 = 5/1024 = exactly 10 x 1/2048 (all exact in f64).
        let h: Vec<_> = (0..48).map(|i| (hour(i), 1, 2048)).collect();
        assert!(spike(&spike_obs("2026-10-08T00:00:00Z", 50, 10_240), &h).is_empty());
        assert_eq!(
            spike(&spike_obs("2026-10-08T00:00:00Z", 51, 10_240), &h).len(),
            1
        );
    }

    #[test]
    fn spike_floors() {
        let h = hist_quiet(48);
        // 99 frames: too quiet to judge. 100 frames: judged.
        assert!(spike(&spike_obs("2026-10-08T00:00:00Z", 90, 99), &h).is_empty());
        assert_eq!(
            spike(&spike_obs("2026-10-08T00:00:00Z", 90, 100), &h).len(),
            1
        );
        // 49 failures: too few. 50: judged.
        assert!(spike(&spike_obs("2026-10-08T00:00:00Z", 49, 100), &h).is_empty());
        assert_eq!(
            spike(&spike_obs("2026-10-08T00:00:00Z", 50, 100), &h).len(),
            1
        );
    }

    #[test]
    fn spike_history_window_and_frames() {
        // Hours at or after h, older than 7 days, or too quiet are not history.
        let h = t("2026-10-08T00:00:00Z");
        let mut old = vec![(h - Duration::days(7) - Duration::hours(1), 2, 10_000); 48];
        old.extend(vec![(h, 2, 10_000); 48]);
        old.extend((0..48).map(|i| (h - Duration::hours(i + 1), 1, 99)));
        // No usable history: nothing to compare against, so no finding.
        assert!(spike(&spike_obs("2026-10-08T00:00:00Z", 64, 128), &old).is_empty());
        // Exactly 7 days back is inside the window.
        let edge = vec![(h - Duration::days(7), 2, 10_000); 48];
        assert_eq!(
            spike(&spike_obs("2026-10-08T00:00:00Z", 64, 128), &edge)[0].level,
            Level::Notify
        );
    }

    #[test]
    fn no_spike_from_unsynced_hours() {
        let seen = spike_obs("1970-01-01T00:00:00Z", 500, 500);
        let history: Vec<_> = (0..48)
            .map(|i| (t("1970-01-01T00:00:00Z") + Duration::hours(i), 1, 1000))
            .collect();
        assert!(spike(&seen, &history).is_empty());
    }

    #[test]
    fn decoder_failure_still_checks_but_learns_nothing() {
        let seen = Observations {
            warnings: vec![warn(Severity::High, "bad")],
            ..Observations::default()
        };
        let (f, learn) = run(Profile::Fixed, DecodeStatus::DecoderFailure, &seen, &past());
        assert_eq!(f[0].check, DECODER_FAILURE);
        assert_eq!(f[0].level, Level::Notify);
        assert_eq!(find(&f, ANALYSER_HIGH).len(), 1);
        assert!(learn.is_none());
    }

    #[test]
    fn archive_problems_stop_at_one_finding() {
        let seen = Observations {
            warnings: vec![warn(Severity::High, "bad")],
            ..Observations::default()
        };
        let (f, l) = run(Profile::Fixed, DecodeStatus::ArchiveCorrupt, &seen, &past());
        assert_eq!(
            (f.len(), f[0].check, f[0].level),
            (1, ARCHIVE_CORRUPT, Level::Notify)
        );
        assert!(l.is_none());
        let (f, l) = run(Profile::Fixed, DecodeStatus::ArchiveMissing, &seen, &past());
        assert_eq!(
            (f.len(), f[0].check, f[0].level),
            (1, ARCHIVE_MISSING, Level::Count)
        );
        assert!(l.is_none());
    }

    #[test]
    fn warnings_one_high_per_analyser_one_other_total_info_nothing() {
        let seen = Observations {
            warnings: vec![
                warn(Severity::High, "a"),
                warn(Severity::High, "b"),
                warn(Severity::Medium, "c"),
                warn(Severity::Low, "d"),
                warn(Severity::Info, "e"),
            ],
            ..Observations::default()
        };
        let f = ok(Profile::Mobile, &seen, &past());
        let high = find(&f, ANALYSER_HIGH);
        assert_eq!(high.len(), 1, "one per analyser");
        assert_eq!(high[0].detail, "An: 2 high warning(s); first: a");
        let other = find(&f, ANALYSER_OTHER);
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].level, Level::Count);
        assert!(other[0].detail.contains('2'));
        assert_eq!(f.len(), 2);

        let info = Observations {
            warnings: vec![warn(Severity::Info, "e")],
            ..Observations::default()
        };
        assert!(ok(Profile::Fixed, &info, &past()).is_empty());
    }

    #[test]
    fn ok_learns_everything_synced_and_parseable() {
        let seen = Observations {
            towers: vec![
                tower("sib1:1:2:3", Strength::Sib1),
                tower("pci:1:2", Strength::Pci),
            ],
            failure_hours: vec![
                (Some("2026-10-10T05:00:00Z".into()), 3, 400),
                (Some("1970-01-01T00:00:00Z".into()), 1, 5),
            ],
            ..ids(&[0, 108])
        };
        let l = run(Profile::Mobile, DecodeStatus::Ok, &seen, &past())
            .1
            .unwrap();
        assert_eq!(l.towers.len(), 2);
        assert_eq!(l.identity_ts.len(), 2);
        assert_eq!(l.failure_hours, vec![(t("2026-10-10T05:00:00Z"), 3, 400)]);
    }

    #[test]
    fn ten_thousand_high_warnings_are_one_finding_per_analyser() {
        let mut seen = Observations {
            warnings: (0..10_000)
                .map(|i| warn(Severity::High, &format!("m{i}")))
                .collect(),
            ..Observations::default()
        };
        let f = ok(Profile::Mobile, &seen, &past());
        let high = find(&f, ANALYSER_HIGH);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].detail, "An: 10000 high warning(s); first: m0");
        assert_eq!(high[0].level, Level::Notify);
        seen.warnings.push(WarningSeen {
            analyzer: "Other".into(),
            ..warn(Severity::High, "x")
        });
        let f = ok(Profile::Mobile, &seen, &past());
        let high = find(&f, ANALYSER_HIGH);
        assert_eq!(high.len(), 2);
        assert_eq!(high[1].detail, "Other: 1 high warning(s); first: x");
    }

    #[test]
    fn every_detail_is_at_most_1_kib_and_lists_say_how_many_more() {
        // 500 off-rhythm gaps, 150 long new SIB1 keys, 150 long new PCI keys, 300 spike hours.
        let mut seen = ids(&(0..500).map(|i| i * 10).collect::<Vec<_>>());
        let long = "x".repeat(50);
        seen.towers = (0..150)
            .map(|i| tower(&format!("sib1:{long}:{i}"), Strength::Sib1))
            .chain((0..150).map(|i| tower(&format!("pci:{long}:{i}"), Strength::Pci)))
            .collect();
        seen.failure_hours = (0..300)
            .map(|i| {
                (
                    Some((hour(200) + Duration::hours(i)).to_rfc3339()),
                    500,
                    500,
                )
            })
            .collect();
        let (f, _) = run_full(
            Profile::Fixed,
            DecodeStatus::Ok,
            &seen,
            &past(),
            None,
            &hist_quiet(200),
            15,
        );
        for check in [
            IDENTITY_OFF_RHYTHM,
            NEW_TOWER,
            NEW_TOWER_WEAK,
            FAILURE_SPIKE,
        ] {
            let d = &find(&f, check)[0].detail;
            assert!(d.len() <= DETAIL_MAX, "{check}: {} bytes", d.len());
            assert!(d.ends_with(" more"), "{check}: {d}");
            assert!(d.chars().all(|c| (' '..='~').contains(&c)), "{check}: {d}");
        }
        // A short list is untouched.
        let f = ok(Profile::Fixed, &ids(&[0, 10]), &past());
        assert_eq!(rhythm(&f)[0].detail, "off-rhythm gaps: 10 min");
    }

    #[test]
    fn only_sib1_keys_count_toward_a_flood() {
        let pci = |n: usize| -> Vec<TowerSeen> {
            (0..n)
                .map(|i| tower(&format!("pci:{i}:1"), Strength::Pci))
                .collect()
        };
        let seen = Observations {
            towers: pci(300),
            ..Observations::default()
        };
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &seen, &past());
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].check, NEW_TOWER_WEAK);
        assert_eq!(learn.unwrap().towers.len(), 300);
        // 200 SIB1 plus 100 PCI: still not a flood.
        let mut seen = flood(200);
        seen.towers.extend(pci(100));
        let (f, learn) = run(Profile::Fixed, DecodeStatus::Ok, &seen, &past());
        assert!(find(&f, TOWER_FLOOD).is_empty());
        let learn = learn.unwrap();
        assert_eq!((learn.towers.len(), learn.hold.len()), (100, 200), "PCI learned, SIB1 held");
    }

    #[test]
    fn synced_is_2020_to_a_day_past_now() {
        let n = now();
        assert!(synced(t("2020-01-01T00:00:00Z"), n));
        assert!(!synced(t("2019-12-31T23:59:59Z"), n));
        assert!(synced(n + Duration::days(1), n));
        assert!(!synced(n + Duration::days(1) + Duration::seconds(1), n));
    }

    #[test]
    fn far_future_stamps_are_neither_measured_nor_learned() {
        // A fake base station sets the unit's clock by NITZ (two-digit year): 2099 parses.
        let seen = Observations {
            identity_ts: vec![
                Some("2026-10-11T00:00:00Z".into()),
                Some("2099-01-01T00:00:00Z".into()),
                Some("2099-01-01T00:10:00Z".into()),
            ],
            failure_hours: vec![(Some("2099-01-01T00:00:00Z".into()), 64, 128)],
            ..Observations::default()
        };
        let future_hist: Vec<_> = (1..=48)
            .map(|i| (t("2099-01-01T00:00:00Z") - Duration::hours(i), 16, 128))
            .collect();
        let (f, learn) = run_full(
            Profile::Fixed,
            DecodeStatus::Ok,
            &seen,
            &past(),
            None,
            &future_hist,
            15,
        );
        // Neither 2026 -> 2099 nor the 10 min 2099 pair is measured; no 2099 spike.
        assert!(f.is_empty(), "{f:?}");
        let l = learn.unwrap();
        assert!(l.identity_ts.is_empty(), "a future stamp teaches no rhythm");
        assert!(l.failure_hours.is_empty());
        // Nor is a far-future previous stamp compared across captures.
        let soon = Observations {
            identity_ts: vec![Some((now() + Duration::days(2)).to_rfc3339())],
            ..Observations::default()
        };
        let prev = now() + Duration::days(2) - Duration::minutes(10);
        let f = run_full(
            Profile::Fixed,
            DecodeStatus::Ok,
            &soon,
            &past(),
            Some(prev),
            &[],
            15,
        )
        .0;
        assert!(rhythm(&f).is_empty(), "{f:?}");
    }

    #[test]
    fn analysers_past_sixteen_fold_into_one_overflow_finding() {
        let f = findings_for_warnings(high_warnings(20));
        let high = f.iter().filter(|x| x.check == ANALYSER_HIGH).count();
        let over: Vec<_> = f.iter().filter(|x| x.check == ANALYSER_OVERFLOW).collect();
        assert_eq!(high, MAX_HIGH_ANALYSERS);
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].level, Level::Notify);
        assert_eq!(over[0].detail, "4 more analysers with high warnings");
    }

    #[test]
    fn sixteen_analysers_make_no_overflow() {
        let f = findings_for_warnings(high_warnings(16));
        assert!(f.iter().all(|x| x.check != ANALYSER_OVERFLOW));
        assert_eq!(f.iter().filter(|x| x.check == ANALYSER_HIGH).count(), 16);
    }

    #[test]
    fn level_table_overflow_always_notifies() {
        for p in [Profile::Fixed, Profile::Mobile] {
            for learning in [true, false] {
                assert_eq!(level(ANALYSER_OVERFLOW, p, learning), Level::Notify);
            }
        }
    }

    #[test]
    fn spike_needs_ten_times_and_fifty_failures() {
        // History: 48 hours at 2/10_000 (0.02 %).
        // 49 failures at 10_000 frames (24.5x) -> floor; 50 at 10_000 (25x) -> spike;
        // 50 at 30_000 (8.3x) -> factor.
        for (failures, frames, want) in
            [(49, 10_000, false), (50, 10_000, true), (50, 30_000, false)]
        {
            let f = spike(
                &spike_obs("2026-10-08T00:00:00Z", failures, frames),
                &hist_rate(48, 2, 10_000),
            );
            assert_eq!(!f.is_empty(), want, "{failures}/{frames}");
        }
    }

    #[test]
    fn fixed_spike_waits_for_the_fourteen_day_learning() {
        // Enough history (48 h) but Fixed has learned for only 3 days: Count, not Notify.
        let seen = spike_obs("2026-10-08T00:00:00Z", 500, 10_000);
        let f = spike_fixed(&seen, &hist_rate(48, 2, 10_000), Some(3));
        assert_eq!(f[0].level, Level::Count);
        let f = spike_fixed(&seen, &hist_rate(48, 2, 10_000), Some(15));
        assert_eq!(f[0].level, Level::Notify);
    }

    #[test]
    fn spike_detail_shows_two_decimals() {
        let f = spike(
            &spike_obs("2026-10-08T00:00:00Z", 60, 10_000),
            &hist_rate(48, 2, 10_000),
        );
        assert!(f[0].detail.contains(" 0.60%"), "{}", f[0].detail);
    }

    #[test]
    fn a_bad_identity_stamp_teaches_no_rhythm() {
        // 2026a, 2099 (future), 2026b: nothing learned (renumbering would fake a 2x gap).
        let (_, learn) = judge_identity(&[
            Some("2026-10-08T08:00:00Z"),
            Some("2099-01-01T00:00:00Z"),
            Some("2026-10-08T09:48:00Z"),
        ]);
        assert!(learn.unwrap().identity_ts.is_empty());
        // An unparseable or missing stamp: same.
        let (_, learn) = judge_identity(&[
            Some("2026-10-08T08:00:00Z"),
            Some("garbage"),
            Some("2026-10-08T09:48:00Z"),
        ]);
        assert!(learn.unwrap().identity_ts.is_empty());
        let (_, learn) = judge_identity(&[
            Some("2026-10-08T08:00:00Z"),
            None,
            Some("2026-10-08T09:48:00Z"),
        ]);
        assert!(learn.unwrap().identity_ts.is_empty());
        // All good: all three learned.
        let (_, learn) = judge_identity(&[
            Some("2026-10-08T08:00:00Z"),
            Some("2026-10-08T09:48:00Z"),
            Some("2026-10-08T11:36:00Z"),
        ]);
        assert_eq!(learn.unwrap().identity_ts.len(), 3);
    }
}
