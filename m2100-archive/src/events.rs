//! Reads the decoder guest's output. The guest runs on hostile input and may be
//! compromised, so every line is parsed as hostile: bounded in size, count and
//! value, against a fixed schema (spec section 4). The first violation stops the
//! read; the tally up to that point is still returned, so a failed decode keeps
//! its partial counts.

use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::fmt;
use std::io::{BufRead, Read};

/// Longest line accepted, newline included (the guest's own limit).
pub const MAX_LINE: usize = 1024;
/// Most lines accepted (the guest's own event cap).
pub const MAX_LINES: u64 = 200_000;
/// Largest count or frame number believed (a 1 GiB capture holds far fewer frames).
pub const MAX_COUNT: u64 = 100_000_000;
const MAX_TS: usize = 64;
const MAX_PLMN: usize = 32;
const MAX_ANALYZER: usize = 64;
/// Longest warning message kept (the guest's line limit already bounds the rest).
pub const MAX_WARNING_MSG: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    Sib1,
    Pci,
}

impl Strength {
    pub fn as_str(self) -> &'static str {
        match self {
            Strength::Sib1 => "sib1",
            Strength::Pci => "pci",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapKind {
    Frame,
    Decompressed,
    Events,
}

impl CapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CapKind::Frame => "frame",
            CapKind::Decompressed => "decompressed",
            CapKind::Events => "events",
        }
    }
}

/// A key that must be present but may be null (an absent key is malformed, which
/// serde's default for `Option` would not say).
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(d)
}

/// One decoded line. Timestamps and hours are opaque bounded strings: a hostile
/// capture can make the guest print any year, and that is not malformed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Tower {
        #[serde(deserialize_with = "present")]
        ts: Option<String>,
        #[serde(deserialize_with = "present")]
        plmn: Option<String>,
        #[serde(deserialize_with = "present")]
        tac: Option<u64>,
        #[serde(deserialize_with = "present")]
        cell: Option<u64>,
        pci: u16,
        earfcn: u32,
        strength: Strength,
    },
    IdentityRequest {
        #[serde(deserialize_with = "present")]
        ts: Option<String>,
        frame: u64,
    },
    Warning {
        #[serde(deserialize_with = "present")]
        ts: Option<String>,
        severity: Severity,
        analyzer: String,
        msg: String,
    },
    ParseFailures {
        #[serde(deserialize_with = "present")]
        hour: Option<String>,
        count: u64,
        frames: u64,
    },
    Capped {
        what: CapKind,
        at_frame: u64,
    },
    Summary {
        frames: u64,
        failures: u64,
        towers: u64,
        identity_requests: u64,
    },
}

/// Guest-controlled text made safe to store: printable ASCII only (anything else
/// becomes `?`), at most `max` chars.
pub fn printable(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                '?'
            }
        })
        .take(max)
        .collect()
}

/// The key of a SIB1 tower: PLMN (`-` when unknown), TAC and cell.
pub fn tower_key(plmn: Option<&str>, tac: u64, cell: u64) -> String {
    format!("sib1:{}:{tac}:{cell}", plmn.unwrap_or("-"))
}

/// A tower as the later judging sees it. The key is what makes two sightings the
/// same tower: a SIB1 tower is its PLMN, TAC and cell (PCI and EARFCN are radio
/// settings that vary for one tower); a PCI-only tower is its PCI and EARFCN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TowerSeen {
    pub key: String,
    pub strength: Strength,
    /// The first sighting's timestamp.
    pub ts: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarningSeen {
    pub severity: Severity,
    pub analyzer: String,
    /// Printable ASCII, at most `MAX_WARNING_MSG` chars.
    pub msg: String,
    pub ts: Option<String>,
}

/// What the guest reported, kept in arrival order. Bounded by `MAX_LINES`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observations {
    /// Distinct towers, first sighting kept.
    pub towers: Vec<TowerSeen>,
    /// The timestamp of every identity request.
    pub identity_ts: Vec<Option<String>>,
    pub warnings: Vec<WarningSeen>,
    /// Per `parse_failures` line: (hour, failures, frames).
    pub failure_hours: Vec<(Option<String>, u64, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    /// From the `summary` (0 if the stream had none).
    pub frames: u64,
    pub failures: u64,
    /// Distinct towers among the `tower` lines, not trusted from the summary.
    pub towers: u64,
    pub identity_requests: u64,
    pub warnings_high: u64,
    pub warnings_other: u64,
    /// `Some(what)` when the guest hit a cap and ended with `capped`.
    pub capped: Option<String>,
    pub seen: Observations,
}

/// Why the guest's output was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    /// 1-based line of the violation (the last line read for an incomplete stream).
    pub line: u64,
    pub reason: String,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decoder output line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for Malformed {}

/// Read the guest's stdout. Stops at the first violation, returning the tally so
/// far with the error. Exactly one terminal event (`summary` or `capped`) must be
/// last; a stream that ends without one is an error (the guest died).
pub fn read_events<R: BufRead>(mut r: R) -> (Tally, Result<(), Malformed>) {
    let mut t = Tally::default();
    let mut line_no = 0u64;
    // Sum of `parse_failures` counts, for the cross-check against the summary.
    let mut pf_count = 0u64;
    let mut tower_keys: HashSet<String> = HashSet::new();
    let mut terminal = false;
    let mut buf = Vec::with_capacity(MAX_LINE + 1);
    macro_rules! stop {
        ($($arg:tt)*) => {
            return (t, Err(Malformed { line: line_no, reason: format!($($arg)*) }))
        };
    }
    loop {
        buf.clear();
        // Never buffer more than one byte past the limit, whatever the guest prints.
        match r
            .by_ref()
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
        {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                line_no += 1;
                stop!("read error: {e}")
            }
        }
        line_no += 1;
        if terminal {
            stop!("output after the terminal event");
        }
        if line_no > MAX_LINES {
            stop!("more than {MAX_LINES} lines");
        }
        if buf.len() > MAX_LINE {
            stop!("line longer than {MAX_LINE} bytes");
        }
        if buf.pop() != Some(b'\n') {
            stop!("last line has no newline");
        }
        let ev: Event = match serde_json::from_slice(&buf) {
            Ok(ev) => ev,
            Err(e) => stop!("not an accepted event: {e}"),
        };
        if let Err(why) = sane(&ev) {
            stop!("{why}");
        }
        match ev {
            Event::Tower {
                ts,
                plmn,
                tac,
                cell,
                pci,
                earfcn,
                strength,
            } => {
                // `sane` guarantees a sib1 tower has its tac and cell
                let key = match (strength, tac, cell) {
                    (Strength::Sib1, Some(tac), Some(cell)) => {
                        tower_key(plmn.as_deref(), tac, cell)
                    }
                    _ => format!("pci:{pci}:{earfcn}"),
                };
                if tower_keys.insert(key.clone()) {
                    t.towers += 1;
                    t.seen.towers.push(TowerSeen { key, strength, ts });
                }
            }
            Event::IdentityRequest { ts, .. } => {
                t.identity_requests += 1;
                t.seen.identity_ts.push(ts);
            }
            Event::Warning {
                ts,
                severity,
                analyzer,
                msg,
            } => {
                if severity == Severity::High {
                    t.warnings_high += 1;
                } else {
                    t.warnings_other += 1;
                }
                t.seen.warnings.push(WarningSeen {
                    severity,
                    analyzer,
                    msg: printable(&msg, MAX_WARNING_MSG),
                    ts,
                });
            }
            Event::ParseFailures {
                hour,
                count,
                frames,
            } => {
                pf_count += count;
                t.seen.failure_hours.push((hour, count, frames));
            }
            Event::Capped { what, at_frame } => {
                t.capped = Some(what.as_str().to_string());
                // no summary follows a cap: the frames reached are the partial count
                t.frames = at_frame;
                terminal = true;
            }
            Event::Summary {
                frames,
                failures,
                towers,
                identity_requests,
            } => {
                if frames < pf_count || failures < pf_count {
                    stop!("summary counts fewer than the {pf_count} parse failures reported");
                }
                if frames == 0 && (towers > 0 || identity_requests > 0 || failures > 0) {
                    stop!("summary reports events but no frames");
                }
                t.frames = frames;
                t.failures = failures;
                terminal = true;
            }
        }
    }
    if !terminal {
        return (
            t,
            Err(Malformed {
                line: line_no,
                reason: "incomplete: no summary or capped event".into(),
            }),
        );
    }
    (t, Ok(()))
}

/// Value bounds the types alone do not give.
fn sane(ev: &Event) -> Result<(), String> {
    let count = |name: &str, n: u64| {
        if n > MAX_COUNT {
            Err(format!("{name} {n} is above {MAX_COUNT}"))
        } else {
            Ok(())
        }
    };
    let text = |name: &str, s: &Option<String>, max: usize| match s {
        Some(s) if s.len() > max => Err(format!("{name} longer than {max} bytes")),
        _ => Ok(()),
    };
    match ev {
        Event::Tower {
            ts,
            plmn,
            tac,
            cell,
            strength,
            ..
        } => {
            text("ts", ts, MAX_TS)?;
            text("plmn", plmn, MAX_PLMN)?;
            if *strength == Strength::Sib1 && (tac.is_none() || cell.is_none()) {
                return Err("sib1 tower without a tac or cell".into());
            }
            Ok(())
        }
        Event::IdentityRequest { ts, frame } => {
            text("ts", ts, MAX_TS)?;
            count("frame", *frame)
        }
        Event::Warning { ts, analyzer, .. } => {
            text("ts", ts, MAX_TS)?;
            if analyzer.len() > MAX_ANALYZER {
                return Err(format!("analyzer longer than {MAX_ANALYZER} bytes"));
            }
            Ok(())
        }
        Event::ParseFailures {
            hour,
            count: c,
            frames,
        } => {
            text("hour", hour, MAX_TS)?;
            count("count", *c)?;
            count("frames", *frames)?;
            if c > frames {
                return Err("more parse failures than frames".into());
            }
            Ok(())
        }
        Event::Capped { at_frame, .. } => count("at_frame", *at_frame),
        Event::Summary {
            frames,
            failures,
            towers,
            identity_requests,
        } => {
            count("frames", *frames)?;
            count("failures", *failures)?;
            count("towers", *towers)?;
            count("identity_requests", *identity_requests)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOWER: &str = r#"{"t":"tower","ts":"2026-10-08T12:00:00.000Z","plmn":"310-260","tac":7,"cell":9,"pci":3,"earfcn":5230,"strength":"sib1"}"#;
    const TOWER_NULLS: &str = r#"{"t":"tower","ts":null,"plmn":null,"tac":null,"cell":null,"pci":3,"earfcn":5230,"strength":"pci"}"#;
    const IDREQ: &str = r#"{"t":"identity_request","ts":null,"frame":9}"#;
    const WARN_HIGH: &str =
        r#"{"t":"warning","ts":null,"severity":"high","analyzer":"imsi_requested","msg":"x"}"#;
    const WARN_LOW: &str =
        r#"{"t":"warning","ts":null,"severity":"info","analyzer":"a","msg":"x"}"#;
    const PF: &str =
        r#"{"t":"parse_failures","hour":"2026-10-08T12:00:00Z","count":2,"frames":50}"#;
    const SUMMARY: &str =
        r#"{"t":"summary","frames":100,"failures":3,"towers":2,"identity_requests":1}"#;

    fn run(lines: &[&str]) -> (Tally, Result<(), Malformed>) {
        let mut s = lines.join("\n");
        s.push('\n');
        read_events(s.as_bytes())
    }

    fn bad(lines: &[&str]) -> (Tally, Malformed) {
        let (t, r) = run(lines);
        (t, r.expect_err("must be malformed"))
    }

    #[test]
    fn valid_stream_tallies() {
        let (t, r) = run(&[
            TOWER,
            TOWER_NULLS,
            IDREQ,
            WARN_HIGH,
            WARN_LOW,
            WARN_LOW,
            PF,
            SUMMARY,
        ]);
        r.unwrap();
        assert_eq!(
            t,
            Tally {
                frames: 100,
                failures: 3,
                towers: 2,
                identity_requests: 1,
                warnings_high: 1,
                warnings_other: 2,
                capped: None,
                seen: t.seen.clone(),
            }
        );
        assert_eq!(t.seen.towers.len(), 2);
    }

    #[test]
    fn same_sib1_tower_is_one_whatever_its_radio_settings() {
        let a = r#"{"t":"tower","ts":"A","plmn":"310-260","tac":7,"cell":9,"pci":3,"earfcn":5230,"strength":"sib1"}"#;
        let b = r#"{"t":"tower","ts":"B","plmn":"310-260","tac":7,"cell":9,"pci":4,"earfcn":66600,"strength":"sib1"}"#;
        let (t, r) = run(&[a, b, SUMMARY]);
        r.unwrap();
        assert_eq!(t.towers, 1);
        assert_eq!(t.seen.towers.len(), 1);
        assert_eq!(
            t.seen.towers[0].ts.as_deref(),
            Some("A"),
            "first sighting wins"
        );
    }

    #[test]
    fn tower_keys_by_strength() {
        let nop = r#"{"t":"tower","ts":null,"plmn":null,"tac":7,"cell":9,"pci":3,"earfcn":5230,"strength":"sib1"}"#;
        let (t, r) = run(&[TOWER, TOWER_NULLS, nop, SUMMARY]);
        r.unwrap();
        let keys: Vec<_> = t.seen.towers.iter().map(|x| x.key.as_str()).collect();
        assert_eq!(keys, ["sib1:310-260:7:9", "pci:3:5230", "sib1:-:7:9"]);
        assert_eq!(t.seen.towers[1].strength, Strength::Pci);
        assert_eq!(t.towers, 3);
    }

    #[test]
    fn sib1_tower_without_tac_or_cell_is_malformed() {
        let no_tac = r#"{"t":"tower","ts":null,"plmn":"1","tac":null,"cell":9,"pci":3,"earfcn":1,"strength":"sib1"}"#;
        let no_cell = r#"{"t":"tower","ts":null,"plmn":"1","tac":7,"cell":null,"pci":3,"earfcn":1,"strength":"sib1"}"#;
        bad(&[no_tac, SUMMARY]);
        bad(&[no_cell, SUMMARY]);
    }

    #[test]
    fn identity_timestamps_and_failure_hours_keep_order() {
        let i1 = r#"{"t":"identity_request","ts":"T1","frame":1}"#;
        let pf0 = r#"{"t":"parse_failures","hour":null,"count":1,"frames":4}"#;
        let (t, r) = run(&[i1, IDREQ, i1, PF, pf0, SUMMARY]);
        r.unwrap();
        assert_eq!(
            t.seen.identity_ts,
            [Some("T1".to_string()), None, Some("T1".to_string())]
        );
        assert_eq!(
            t.seen.failure_hours,
            [
                (Some("2026-10-08T12:00:00Z".to_string()), 2, 50),
                (None, 1, 4)
            ]
        );
    }

    #[test]
    fn warning_msg_is_printable_and_bounded() {
        let w = |msg: &str| {
            format!(r#"{{"t":"warning","ts":"W","severity":"high","analyzer":"an","msg":"{msg}"}}"#)
        };
        let long = "a".repeat(500);
        let (t, r) = run(&[&w(r"x\u0000\n\u202ey"), &w(&long), SUMMARY]);
        r.unwrap();
        let [ctl, big] = &t.seen.warnings[..] else {
            panic!("two warnings")
        };
        assert_eq!(ctl.msg, "x???y");
        assert_eq!(big.msg.len(), MAX_WARNING_MSG);
        assert_eq!(
            (ctl.severity, ctl.analyzer.as_str(), ctl.ts.as_deref()),
            (Severity::High, "an", Some("W"))
        );
    }

    #[test]
    fn empty_capture_summary_alone_is_valid() {
        let s = r#"{"t":"summary","frames":0,"failures":0,"towers":0,"identity_requests":0}"#;
        let (t, r) = run(&[s]);
        r.unwrap();
        assert_eq!(t, Tally::default());
    }

    #[test]
    fn far_future_year_is_not_malformed() {
        let ts = r#"{"t":"identity_request","ts":"+13129-07-01T00:00:00.000Z","frame":1}"#;
        let h = r#"{"t":"parse_failures","hour":"+13129-07-01T00:00:00Z","count":1,"frames":1}"#;
        let (t, r) = run(&[ts, h, SUMMARY]);
        r.unwrap();
        assert_eq!(t.identity_requests, 1);
    }

    #[test]
    fn capped_is_a_valid_terminal() {
        for what in ["frame", "decompressed", "events"] {
            let c = format!(r#"{{"t":"capped","what":"{what}","at_frame":10}}"#);
            let (t, r) = run(&[TOWER, &c]);
            r.unwrap();
            assert_eq!(t.capped.as_deref(), Some(what));
            assert_eq!(t.towers, 1);
            assert_eq!(t.frames, 10, "a cap carries the frames reached");
        }
    }

    #[test]
    fn no_terminal_is_incomplete_with_partial_tally() {
        let (t, e) = bad(&[TOWER, WARN_HIGH]);
        assert_eq!((t.towers, t.warnings_high), (1, 1));
        assert_eq!((t.seen.towers.len(), t.seen.warnings.len()), (1, 1));
        assert!(e.reason.contains("incomplete"), "{e}");
        let (_, r) = read_events(&b""[..]);
        assert!(r.unwrap_err().reason.contains("incomplete"));
    }

    #[test]
    fn unterminated_last_line_is_malformed() {
        let s = format!("{TOWER}\n{SUMMARY}");
        let (t, r) = read_events(s.as_bytes());
        assert!(r.is_err());
        assert_eq!(t.towers, 1);
        assert_eq!(t.frames, 0);
    }

    #[test]
    fn negative_count_is_malformed() {
        let neg = r#"{"t":"summary","frames":-1,"failures":0,"towers":0,"identity_requests":0}"#;
        let (t, _) = bad(&[TOWER, neg]);
        assert_eq!((t.towers, t.frames), (1, 0));
        let neg = r#"{"t":"parse_failures","hour":null,"count":-2,"frames":1}"#;
        bad(&[neg, SUMMARY]);
    }

    #[test]
    fn absurd_frame_count_is_malformed() {
        let big =
            r#"{"t":"summary","frames":1000000000,"failures":0,"towers":0,"identity_requests":0}"#;
        let (t, _) = bad(&[TOWER, big]);
        assert_eq!((t.towers, t.frames), (1, 0));
        let ok =
            r#"{"t":"summary","frames":100000000,"failures":0,"towers":0,"identity_requests":0}"#;
        run(&[ok]).1.unwrap();
        bad(&[
            r#"{"t":"identity_request","ts":null,"frame":1000000000}"#,
            SUMMARY,
        ]);
    }

    #[test]
    fn summary_first_then_more_is_malformed() {
        let (t, e) = bad(&[SUMMARY, TOWER]);
        assert_eq!(e.line, 2);
        assert_eq!((t.frames, t.towers), (100, 0));
    }

    #[test]
    fn two_summaries_are_malformed() {
        let (t, e) = bad(&[TOWER, SUMMARY, SUMMARY]);
        assert_eq!(e.line, 3);
        assert_eq!(t.towers, 1);
    }

    #[test]
    fn nothing_after_capped() {
        let c = r#"{"t":"capped","what":"events","at_frame":1}"#;
        bad(&[c, SUMMARY]);
        bad(&[c, c]);
        bad(&[SUMMARY, c]);
    }

    #[test]
    fn summary_that_contradicts_the_lines_is_malformed() {
        // 2 failures were reported per hour but the summary says 1
        let s = r#"{"t":"summary","frames":100,"failures":1,"towers":0,"identity_requests":0}"#;
        bad(&[PF, s]);
        let s = r#"{"t":"summary","frames":1,"failures":5,"towers":0,"identity_requests":0}"#;
        let pf = r#"{"t":"parse_failures","hour":null,"count":2,"frames":1}"#;
        bad(&[pf, pf, s]);
        // towers seen in a capture with no frames
        let s = r#"{"t":"summary","frames":0,"failures":0,"towers":1,"identity_requests":0}"#;
        bad(&[s]);
    }

    #[test]
    fn unknown_type_field_and_shape_are_malformed() {
        bad(&[TOWER, r#"{"t":"exec","cmd":"x"}"#, SUMMARY]);
        bad(&[
            r#"{"t":"identity_request","ts":null,"frame":1,"extra":1}"#,
            SUMMARY,
        ]);
        bad(&[r#"{"t":"identity_request","frame":1}"#, SUMMARY]); // ts absent
        bad(&[
            r#"{"t":"identity_request","ts":null,"frame":1,"frame":2}"#,
            SUMMARY,
        ]);
        bad(&[r#"{"ts":null,"frame":1}"#, SUMMARY]);
        bad(&[r#"["tower"]"#, SUMMARY]);
        bad(&["not json", SUMMARY]);
        bad(&["", SUMMARY]);
        bad(&[
            r#"{"t":"warning","ts":null,"severity":"loud","analyzer":"a","msg":"x"}"#,
            SUMMARY,
        ]);
        bad(&[
            r#"{"t":"tower","ts":null,"plmn":null,"tac":null,"cell":null,"pci":70000,"earfcn":1,"strength":"pci"}"#,
            SUMMARY,
        ]);
    }

    #[test]
    fn invalid_utf8_is_malformed() {
        let mut v = b"{\"t\":\"warning\",\"ts\":null,\"severity\":\"high\",\"analyzer\":\"\xff\",\"msg\":\"\"}\n".to_vec();
        v.extend_from_slice(SUMMARY.as_bytes());
        v.push(b'\n');
        let (t, r) = read_events(&v[..]);
        assert!(r.is_err());
        assert_eq!(t.warnings_high, 0);
    }

    #[test]
    fn overlong_strings_are_malformed() {
        let ts = "9".repeat(65);
        bad(&[
            &format!(r#"{{"t":"identity_request","ts":"{ts}","frame":1}}"#),
            SUMMARY,
        ]);
        let hour = "9".repeat(65);
        bad(&[
            &format!(r#"{{"t":"parse_failures","hour":"{hour}","count":1,"frames":1}}"#),
            SUMMARY,
        ]);
        let an = "a".repeat(65);
        bad(&[
            &format!(r#"{{"t":"warning","ts":null,"severity":"low","analyzer":"{an}","msg":""}}"#),
            SUMMARY,
        ]);
        let p = "1".repeat(33);
        bad(&[
            &format!(
                r#"{{"t":"tower","ts":null,"plmn":"{p}","tac":null,"cell":null,"pci":1,"earfcn":1,"strength":"pci"}}"#
            ),
            SUMMARY,
        ]);
        // exactly at the bound is fine
        let ts = "9".repeat(64);
        run(&[
            &format!(r#"{{"t":"identity_request","ts":"{ts}","frame":1}}"#),
            SUMMARY,
        ])
        .1
        .unwrap();
    }

    #[test]
    fn line_length_limit() {
        let pad = |n: usize| {
            // a warning line of exactly n bytes including the newline
            let base =
                r#"{"t":"warning","ts":null,"severity":"low","analyzer":"a","msg":""}"#.len() + 1;
            format!(
                r#"{{"t":"warning","ts":null,"severity":"low","analyzer":"a","msg":"{}"}}"#,
                "m".repeat(n - base)
            )
        };
        let (t, r) = run(&[&pad(1024), SUMMARY]);
        r.unwrap();
        assert_eq!(t.warnings_other, 1);
        let (t, e) = bad(&[TOWER, &pad(1025), SUMMARY]);
        assert_eq!(e.line, 2);
        assert_eq!((t.towers, t.warnings_other), (1, 0));
        // a huge line with no newline at all is refused without being buffered whole
        let huge = "x".repeat(10_000_000);
        let (_, r) = read_events(huge.as_bytes());
        assert!(r.is_err());
    }

    #[test]
    fn line_count_limit() {
        let mut s = String::new();
        for _ in 0..200_001 {
            s.push_str(IDREQ);
            s.push('\n');
        }
        s.push_str(SUMMARY);
        s.push('\n');
        let (t, r) = read_events(s.as_bytes());
        assert_eq!(r.unwrap_err().line, 200_001);
        assert_eq!(t.identity_requests, 200_000);
        // 199,999 events + the summary is exactly at the limit
        let mut s = String::new();
        for _ in 0..199_999 {
            s.push_str(IDREQ);
            s.push('\n');
        }
        s.push_str(
            r#"{"t":"summary","frames":200000,"failures":0,"towers":0,"identity_requests":199999}"#,
        );
        s.push('\n');
        read_events(s.as_bytes()).1.unwrap();
    }
}
