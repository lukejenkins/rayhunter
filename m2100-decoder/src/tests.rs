//! Native tests of the whole decoder: synthetic captures, hostile generated
//! inputs, and (when present) the real captures under $RH_FIXTURES.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use deku::DekuContainerWrite;
use flate2::Compression;
use flate2::read::GzEncoder as ReadGzEncoder;
use flate2::write::GzEncoder;
use rayhunter::diag::diaglog::rrc::LteRrcOtaPacket;
use rayhunter::diag::diaglog::{LogBody, Nas4GMessageDirection, Timestamp};
use rayhunter::diag::{CRC_CCITT, Message};
use rayhunter::hdlc::hdlc_encapsulate;
use serde_json::Value;

use crate::decode::{Caps, Outcome, run};
use crate::events::CapKind;

// ---------- synthetic frames ----------

/// Seconds since the diag epoch (1980-01-06) -> diag timestamp (1/800 s ticks
/// in the upper 48 bits).
fn diag_ts(secs: u64) -> u64 {
    (secs * 800) << 16
}

/// 2026-10-08T00:00:00Z in seconds since 1980-01-06T00:00:00Z.
const T0: u64 = 1_475_452_800;

fn encapsulate(message: Message) -> Vec<u8> {
    let bytes = message.to_bytes().expect("serialise test message");
    let frame = hdlc_encapsulate(&bytes, &CRC_CCITT);
    assert_eq!(Message::from_hdlc(&frame).as_ref(), Ok(&message));
    frame
}

fn rrc_frame(pci: u16, earfcn: u32, pdu_num: u8, payload: &[u8], secs: u64) -> Vec<u8> {
    let len = 31 + payload.len() as u16;
    encapsulate(Message::Log {
        pending_msgs: 0,
        outer_length: len,
        inner_length: len,
        log_type: 0xb0c0,
        timestamp: Timestamp { ts: diag_ts(secs) },
        body: LogBody::LteRrcOtaMessage {
            ext_header_version: 20,
            packet: LteRrcOtaPacket::V8 {
                rrc_rel_maj: 14,
                rrc_rel_min: 48,
                bearer_id: 0,
                phy_cell_id: pci,
                earfcn,
                sfn_subfn: 4057,
                pdu_num,
                sib_mask: 0,
                len: payload.len() as u16,
                packet: payload.to_vec(),
            },
        },
    })
}

/// A paging message (PCCH; pdu 5 at ext header 20) that decodes.
fn pcch(pci: u16, earfcn: u32, secs: u64) -> Vec<u8> {
    rrc_frame(
        pci,
        earfcn,
        5,
        &[0x40, 0x01, 0xee, 0xad, 0xd5, 0x4d, 0xd0],
        secs,
    )
}

/// A SIB1 (BCCH-DL-SCH; pdu 2 at ext header 20), from telcom-parser's test.
fn sib1(pci: u16, earfcn: u32, secs: u64) -> Vec<u8> {
    let hex = "484c469010600018fd1a9207e22103108ac21bdc09802292cdd20000";
    let payload: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    rrc_frame(pci, earfcn, 2, &payload, secs)
}

/// A plain downlink EMM Identity Request (IMSI). Built by hand: deku writes
/// the Nas4GMessage variant's skipped log_type field.
fn identity_request(secs: u64) -> Vec<u8> {
    let msg = vec![0x07, 0x55, 0x01];
    let len = 12 + 4 + msg.len() as u16;
    let mut bytes = vec![0x10, 0x00];
    bytes.extend(len.to_le_bytes());
    bytes.extend(len.to_le_bytes());
    bytes.extend(0xb0ecu16.to_le_bytes());
    bytes.extend(diag_ts(secs).to_le_bytes());
    bytes.extend([1, 9, 5, 9]);
    bytes.extend(&msg);
    let frame = hdlc_encapsulate(&bytes, &CRC_CCITT);
    let want = Message::Log {
        pending_msgs: 0,
        outer_length: len,
        inner_length: len,
        log_type: 0xb0ec,
        timestamp: Timestamp { ts: diag_ts(secs) },
        body: LogBody::Nas4GMessage {
            log_type: 0xb0ec,
            direction: Nas4GMessageDirection::Downlink,
            ext_header_version: 1,
            rrc_rel: 9,
            rrc_version_minor: 5,
            rrc_version_major: 9,
            msg,
        },
    };
    assert_eq!(Message::from_hdlc(&frame), Ok(want));
    frame
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Deterministic pseudo-random bytes.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// An endless repetition of `pattern`.
struct Cycle {
    pattern: Vec<u8>,
    pos: usize,
}

impl Read for Cycle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for b in buf.iter_mut() {
            *b = self.pattern[self.pos];
            self.pos = (self.pos + 1) % self.pattern.len();
        }
        Ok(buf.len())
    }
}

// ---------- running and checking ----------

struct Decoded {
    outcome: Outcome,
    events: Vec<Value>,
}

impl Decoded {
    fn of(&self, t: &str) -> Vec<&Value> {
        self.events.iter().filter(|e| e["t"] == t).collect()
    }
    fn last(&self) -> &Value {
        self.events.last().expect("at least one event")
    }
    fn summary(&self) -> &Value {
        assert_eq!(self.outcome, Outcome::Summary, "{:?}", self.last());
        self.last()
    }
}

/// Runs the decoder and checks the output contract on every run: each line
/// <= max_line bytes (newline included) and valid JSON, at most max_events
/// lines, exactly one terminal event (`summary` or `capped`) and it is last,
/// and a summary agrees with the events before it.
fn decode(input: impl Read, caps: Caps) -> Decoded {
    let mut out = Vec::new();
    let outcome = run(input, &mut out, caps);
    assert_eq!(out.last(), Some(&b'\n'), "output ends with a full line");
    let mut events = Vec::new();
    for line in out.split_inclusive(|b| *b == b'\n') {
        assert!(
            line.len() <= caps.max_line,
            "line of {} bytes: {}",
            line.len(),
            String::from_utf8_lossy(line)
        );
        events.push(serde_json::from_slice::<Value>(line).expect("line is JSON"));
    }
    assert!(
        events.len() as u64 <= caps.max_events,
        "{} events",
        events.len()
    );
    let terminal = |e: &Value| e["t"] == "summary" || e["t"] == "capped";
    assert_eq!(events.iter().filter(|e| terminal(e)).count(), 1);
    let last = events.last().unwrap();
    assert!(terminal(last));
    match outcome {
        Outcome::Summary => {
            assert_eq!(last["t"], "summary");
            let count = |t: &str| events.iter().filter(|e| e["t"] == t).count() as u64;
            let sum = |f: &str| -> u64 {
                events
                    .iter()
                    .filter(|e| e["t"] == "parse_failures")
                    .map(|e| e[f].as_u64().unwrap())
                    .sum()
            };
            assert_eq!(last["towers"].as_u64().unwrap(), count("tower"));
            assert_eq!(
                last["identity_requests"].as_u64().unwrap(),
                count("identity_request")
            );
            assert_eq!(last["failures"].as_u64().unwrap(), sum("count"));
            assert_eq!(last["frames"].as_u64().unwrap(), sum("frames"));
            assert!(last["failures"].as_u64() <= last["frames"].as_u64());
        }
        Outcome::Capped(what) => {
            assert_eq!(last["t"], "capped");
            assert_eq!(last["what"], serde_json::to_value(what).unwrap());
        }
        Outcome::OutputError => panic!("output error writing to a Vec"),
    }
    Decoded { outcome, events }
}

fn small_caps() -> Caps {
    Caps {
        max_frame: 64,
        ..Caps::default()
    }
}

// ---------- synthetic captures ----------

#[test]
fn synthetic_capture_towers_identity_requests_failures() {
    let frames = [
        pcch(1, 100, T0),
        pcch(1, 100, T0 + 10),
        pcch(3, 300, T0 + 20), // seen by PCI before its SIB1...
        pcch(2, 200, T0 + 3600),
        sib1(3, 300, T0 + 3601),
        pcch(3, 300, T0 + 3602), // ...and after: still one tower
        identity_request(T0 + 7200),
        vec![0x01, 0x02, 0x7e], // diag-level failure: no timestamp
    ]
    .concat();
    let d = decode(&gz(&frames)[..], Caps::default());
    let s = d.summary();
    assert_eq!(s["frames"], 8);
    assert_eq!(s["failures"], 1);
    assert_eq!(s["towers"], 3);
    assert_eq!(s["identity_requests"], 1);

    let towers = d.of("tower");
    let by_pci = |p: u64| *towers.iter().find(|t| t["pci"] == p).unwrap();
    assert_eq!(by_pci(1)["strength"], "pci");
    assert_eq!(by_pci(1)["earfcn"], 100);
    assert_eq!(by_pci(1)["plmn"], Value::Null);
    assert_eq!(by_pci(1)["ts"], "2026-10-08T00:00:00.000Z");
    assert_eq!(by_pci(2)["strength"], "pci");
    let t3 = by_pci(3);
    assert_eq!(t3["strength"], "sib1");
    assert_eq!(t3["earfcn"], 300);
    assert!(t3["plmn"].as_str().unwrap().contains('-'));
    assert!(t3["tac"].is_u64() && t3["cell"].is_u64());
    assert_eq!(t3["ts"], "2026-10-08T01:00:01.000Z");

    let ir = d.of("identity_request");
    assert_eq!(ir[0]["frame"], 7);
    assert_eq!(ir[0]["ts"], "2026-10-08T02:00:00.000Z");

    let warnings = d.of("warning");
    assert!(
        !warnings.is_empty(),
        "the analysers flag an identity request"
    );
    for w in &warnings {
        assert!(["high", "medium", "low", "info"].contains(&w["severity"].as_str().unwrap()));
        assert!(!w["analyzer"].as_str().unwrap().is_empty());
    }

    let pf = d.of("parse_failures");
    let hour = |h: Value| *pf.iter().find(|e| e["hour"] == h).unwrap();
    assert_eq!(hour(Value::Null)["count"], 1);
    assert_eq!(hour(Value::Null)["frames"], 1);
    assert_eq!(hour("2026-10-08T00:00:00Z".into())["frames"], 3);
    assert_eq!(hour("2026-10-08T01:00:00Z".into())["frames"], 3);
    assert_eq!(hour("2026-10-08T02:00:00Z".into())["frames"], 1);
    assert_eq!(hour("2026-10-08T02:00:00Z".into())["count"], 0);
}

#[test]
fn oversized_frame_is_a_failure_and_the_reader_resyncs() {
    let valid = pcch(1, 100, T0);
    assert!(valid.len() < 64);
    let mut oversized = vec![0x41; 100];
    oversized.push(0x7e);
    let input = [valid.clone(), oversized, pcch(2, 200, T0 + 1)].concat();
    let d = decode(&gz(&input)[..], small_caps());
    let s = d.summary();
    let (frames, failures) = (
        s["frames"].as_u64().unwrap(),
        s["failures"].as_u64().unwrap(),
    );
    assert!(failures >= 1, "the oversized frame counts as failure(s)");
    assert_eq!(frames - failures, 2, "both valid frames decode");
    assert_eq!(s["towers"], 2, "the frame after the oversized one decodes");
}

#[test]
fn events_cap_stops_with_capped_events() {
    let frames: Vec<u8> = (0..50).flat_map(|p| pcch(p, 100, T0)).collect();
    let caps = Caps {
        max_events: 10,
        ..Caps::default()
    };
    let d = decode(&gz(&frames)[..], caps);
    assert_eq!(d.outcome, Outcome::Capped(CapKind::Events));
    assert_eq!(d.last()["what"], "events");
    assert!(d.last()["at_frame"].as_u64().unwrap() <= 50);
}

#[test]
fn output_error_stops_cleanly() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let input = gz(&pcch(1, 100, T0));
    assert_eq!(
        run(&input[..], Broken, Caps::default()),
        Outcome::OutputError
    );
}

// ---------- hostile inputs ----------

#[test]
fn gzip_bomb_of_zeros_hits_a_cap_quickly() {
    // 2 GiB of 0x00 (no frame terminator), gzipped as it is read
    let bomb = ReadGzEncoder::new(io::repeat(0).take(2 << 30), Compression::fast());
    let start = Instant::now();
    let d = decode(bomb, Caps::default());
    let took = start.elapsed();
    eprintln!("zero bomb: {:?} in {took:?}", d.last());
    assert!(matches!(
        d.outcome,
        Outcome::Capped(CapKind::Decompressed) | Outcome::Capped(CapKind::Frame)
    ));
    assert!(took < Duration::from_secs(10), "took {took:?}");
}

#[test]
fn stream_of_three_byte_frames_hits_a_cap() {
    let caps = Caps {
        max_decompressed: 4 << 20,
        ..Caps::default()
    };
    let input = ReadGzEncoder::new(
        Cycle {
            pattern: vec![0x00, 0x01, 0x7e],
            pos: 0,
        },
        Compression::fast(),
    );
    let d = decode(input, caps);
    assert!(matches!(
        d.outcome,
        Outcome::Capped(CapKind::Decompressed) | Outcome::Capped(CapKind::Events)
    ));
    // the failures seen before the cap are still reported
    let pf = d.of("parse_failures");
    assert!(pf.iter().map(|e| e["count"].as_u64().unwrap()).sum::<u64>() > 1_000_000);
}

#[test]
fn decompressed_cap_is_exact() {
    let frames = [pcch(1, 100, T0), pcch(2, 100, T0)].concat();
    let exact = Caps {
        max_decompressed: frames.len() as u64,
        ..Caps::default()
    };
    assert_eq!(decode(&gz(&frames)[..], exact).summary()["frames"], 2);
    let short = Caps {
        max_decompressed: frames.len() as u64 - 1,
        ..Caps::default()
    };
    let d = decode(&gz(&frames)[..], short);
    assert_eq!(d.outcome, Outcome::Capped(CapKind::Decompressed));
    assert_eq!(d.last()["at_frame"], 1);
}

#[test]
fn garbage_inputs_end_with_a_summary() {
    let capture = [
        pcch(1, 100, T0),
        identity_request(T0 + 1),
        sib1(3, 300, T0 + 2),
    ]
    .concat()
    .repeat(200);
    let gzipped = gz(&capture);
    let mut with_terminators = noise(1 << 20, 7);
    for (i, b) in with_terminators.iter_mut().enumerate() {
        if i % 37 == 0 {
            *b = 0x7e;
        }
    }
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("raw noise, not gzip", noise(1 << 20, 1)),
        ("gzipped noise", gz(&noise(4 << 20, 2))),
        ("gzipped noise with terminators", gz(&with_terminators)),
        ("truncated gzip", gzipped[..gzipped.len() / 2].to_vec()),
        ("gzip header only", gzipped[..10].to_vec()),
        ("truncated mid-frame", gz(&capture[..capture.len() - 5])),
    ];
    for (name, input) in inputs {
        let d = decode(&input[..], Caps::default());
        eprintln!("{name}: {}", d.last());
        d.summary();
    }
    // bit flips through a real-shaped capture
    let mut flipped = capture.clone();
    for (i, b) in noise(flipped.len(), 3).iter().enumerate() {
        if *b < 3 {
            flipped[i] ^= 1 << (b % 8);
        }
    }
    decode(&gz(&flipped)[..], Caps::default()).summary();
}

#[test]
fn nested_gzip_is_not_decompressed_twice() {
    // the decompressed capture is itself a gzip of a valid capture; the
    // library reader would gunzip it again (uncapped) if it saw the magic
    let inner = gz(&[pcch(7, 100, T0), pcch(8, 100, T0)].concat());
    let d = decode(&gz(&inner)[..], Caps::default());
    assert_eq!(d.summary()["towers"], 0);
}

// ---------- real captures ----------

fn fixtures() -> Option<PathBuf> {
    let dir = std::env::var_os("RH_FIXTURES")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join("Projects/rayhunter-m2100/captures"))
        })?;
    if dir.is_dir() {
        Some(dir)
    } else {
        eprintln!("SKIP: no fixtures at {} (set RH_FIXTURES)", dir.display());
        None
    }
}

fn gzip_file(path: &std::path::Path) -> Vec<u8> {
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    gz(&raw)
}

#[test]
fn real_big_capture_1791247177() {
    let Some(dir) = fixtures() else { return };
    let zip = dir.join("unit1-2026-10-08/1791247177.zip");
    if !zip.is_file() {
        eprintln!("SKIP: {} absent", zip.display());
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("unzip")
        .arg("-q")
        .arg(&zip)
        .arg("1791247177.qmdl")
        .arg("-d")
        .arg(tmp.path())
        .status()
        .expect("run unzip");
    assert!(status.success());
    let qmdl = tmp.path().join("1791247177.qmdl");
    // the zip stores the member with no permission bits
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&qmdl, std::fs::Permissions::from_mode(0o600)).unwrap();
    let input = gzip_file(&qmdl);
    let start = Instant::now();
    let d = decode(&input[..], Caps::default());
    let s = d.summary().clone();
    let warn = |sev: &str| {
        d.of("warning")
            .iter()
            .filter(|w| w["severity"] == sev)
            .count()
    };
    eprintln!(
        "1791247177: {s} in {:?}; warnings high={} medium={} low={} info={}; parse_failures buckets={}",
        start.elapsed(),
        warn("high"),
        warn("medium"),
        warn("low"),
        warn("info"),
        d.of("parse_failures").len()
    );
    for e in d.of("parse_failures") {
        eprintln!("  {e}");
    }
    assert_eq!(s["identity_requests"], 14);
    // failures = diag-level parse errors + rows the harness skipped +
    // oversized frames. The spike's harness_skipped (which, like the device,
    // fed diag errors to the harness) was 168, matching the device's ndjson;
    // this capture has no oversized frames, so the two agree exactly.
    assert_eq!(s["failures"], 168);
    assert_eq!(s["frames"], 433_594);
}

#[test]
fn real_small_capture_403323() {
    let Some(dir) = fixtures() else { return };
    let path = dir.join("unit1-2026-10-09-prune-test/403323-403323.qmdl.gz");
    if !path.is_file() {
        eprintln!("SKIP: {} absent", path.display());
        return;
    }
    let input = std::fs::read(&path).unwrap();
    let d = decode(&input[..], Caps::default());
    let s = d.summary();
    eprintln!("403323: {s}");
    for t in d.of("tower") {
        eprintln!(
            "  tower strength={} pci={} earfcn={}",
            t["strength"], t["pci"], t["earfcn"]
        );
    }
    assert!(s["towers"].as_u64().unwrap() >= 1);
    assert_eq!(s["identity_requests"], 0);
}
