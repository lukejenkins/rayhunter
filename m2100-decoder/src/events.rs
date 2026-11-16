//! The guest's output: one JSON object per line (spec section 4), each line
//! at most `max_line` bytes including its newline.

use std::io::{self, Write};

use serde::Serialize;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    /// PLMN/TAC/cell ID read from the tower's own SIB1.
    Sib1,
    /// Only the physical cell ID and EARFCN (from the diag log header) are known.
    Pci,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CapKind {
    /// In the schema, but never emitted: an oversized frame is counted as a
    /// parse failure and the reader resyncs at the next terminator
    /// (QmdlMessageReader::with_max_frame), so it does not stop decoding.
    #[allow(dead_code)]
    Frame,
    Decompressed,
    Events,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Event {
    Tower {
        ts: Option<String>,
        plmn: Option<String>,
        tac: Option<u64>,
        cell: Option<u64>,
        pci: u16,
        earfcn: u32,
        strength: Strength,
    },
    IdentityRequest {
        ts: Option<String>,
        frame: u64,
    },
    Warning {
        ts: Option<String>,
        severity: &'static str,
        analyzer: String,
        msg: String,
    },
    ParseFailures {
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

/// Longest an analyser key may be on the wire (escaped bytes).
const MAX_ANALYZER: usize = 64;
/// Longest a PLMN string may be on the wire (escaped bytes).
const MAX_PLMN: usize = 32;

/// Bytes `c` takes inside a JSON string as serde_json writes it.
fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// Longest prefix of `s` (on a char boundary) whose escaped form fits `max`.
pub fn truncate_escaped(s: &str, max: usize) -> &str {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        used += escaped_len(c);
        if used > max {
            return &s[..i];
        }
    }
    s
}

fn serialize(ev: &Event) -> Vec<u8> {
    // Serialising these plain structs cannot fail.
    let mut line = serde_json::to_vec(ev).expect("event serialises");
    line.push(b'\n');
    line
}

/// Serialise `ev` as one line (with its newline) of at most `max_line` bytes,
/// truncating its free-text strings as needed.
pub fn fit_line(ev: &Event, max_line: usize) -> Vec<u8> {
    let mut ev = ev.clone();
    match &mut ev {
        Event::Warning {
            ts,
            severity,
            analyzer,
            msg,
        } => {
            let fixed = serialize(&Event::Warning {
                ts: ts.clone(),
                severity,
                analyzer: String::new(),
                msg: String::new(),
            })
            .len();
            let budget = max_line.saturating_sub(fixed);
            let a = truncate_escaped(analyzer, budget.min(MAX_ANALYZER)).to_string();
            let a_len: usize = a.chars().map(escaped_len).sum();
            let m = truncate_escaped(msg, budget - a_len).to_string();
            *analyzer = a;
            *msg = m;
        }
        Event::Tower { plmn: Some(p), .. } => {
            *p = truncate_escaped(p, MAX_PLMN).to_string();
        }
        _ => {}
    }
    let line = serialize(&ev);
    assert!(
        line.len() <= max_line,
        "event line of {} bytes exceeds {max_line}",
        line.len()
    );
    line
}

/// Writes events as lines, flushing each, and counts them.
pub struct LineWriter<W: Write> {
    out: W,
    max_line: usize,
    written: u64,
}

impl<W: Write> LineWriter<W> {
    pub fn new(out: W, max_line: usize) -> Self {
        Self {
            out,
            max_line,
            written: 0,
        }
    }

    pub fn write(&mut self, ev: &Event) -> io::Result<()> {
        let line = fit_line(ev, self.max_line);
        self.out.write_all(&line)?;
        self.out.flush()?;
        self.written += 1;
        Ok(())
    }

    pub fn written(&self) -> u64 {
        self.written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warning(analyzer: &str, msg: &str) -> Event {
        Event::Warning {
            ts: Some("2026-10-08T12:34:56.789Z".into()),
            severity: "high",
            analyzer: analyzer.into(),
            msg: msg.into(),
        }
    }

    fn check(line: &[u8], max: usize) -> serde_json::Value {
        assert!(line.len() <= max, "{} > {max}", line.len());
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
        serde_json::from_slice(line).expect("valid JSON")
    }

    #[test]
    fn short_warning_unchanged() {
        let v = check(&fit_line(&warning("imsi_requested", "hello"), 1024), 1024);
        assert_eq!(v["t"], "warning");
        assert_eq!(v["severity"], "high");
        assert_eq!(v["analyzer"], "imsi_requested");
        assert_eq!(v["msg"], "hello");
    }

    #[test]
    fn long_warning_truncated_to_line_limit() {
        let msg = "x".repeat(5000);
        let line = fit_line(&warning("a", &msg), 1024);
        let v = check(&line, 1024);
        let got = v["msg"].as_str().unwrap();
        assert!(got.len() > 800 && msg.starts_with(got));
    }

    #[test]
    fn escaping_heavy_strings_still_fit() {
        // control chars escape to 6 bytes, quotes to 2; multi-byte chars must
        // not be split
        for msg in [
            "\u{01}".repeat(3000),
            "\"".repeat(3000),
            "é€😀".repeat(1000),
            "\n\\".repeat(1000),
        ] {
            let an = "\u{02}".repeat(500);
            for max in [1024, 300, 120] {
                check(&fit_line(&warning(&an, &msg), max), max);
            }
        }
    }

    #[test]
    fn every_event_type_serialises_as_spec() {
        let evs = [
            Event::Tower {
                ts: None,
                plmn: Some("310-260".into()),
                tac: Some(1),
                cell: Some(2),
                pci: 3,
                earfcn: 4,
                strength: Strength::Sib1,
            },
            Event::IdentityRequest { ts: None, frame: 9 },
            Event::ParseFailures {
                hour: None,
                count: 1,
                frames: 2,
            },
            Event::Capped {
                what: CapKind::Decompressed,
                at_frame: 5,
            },
            Event::Summary {
                frames: 1,
                failures: 0,
                towers: 0,
                identity_requests: 0,
            },
        ];
        let want = [
            r#"{"t":"tower","ts":null,"plmn":"310-260","tac":1,"cell":2,"pci":3,"earfcn":4,"strength":"sib1"}"#,
            r#"{"t":"identity_request","ts":null,"frame":9}"#,
            r#"{"t":"parse_failures","hour":null,"count":1,"frames":2}"#,
            r#"{"t":"capped","what":"decompressed","at_frame":5}"#,
            r#"{"t":"summary","frames":1,"failures":0,"towers":0,"identity_requests":0}"#,
        ];
        for (ev, w) in evs.iter().zip(want) {
            let line = fit_line(ev, 1024);
            assert_eq!(std::str::from_utf8(&line).unwrap(), format!("{w}\n"));
        }
    }
}
