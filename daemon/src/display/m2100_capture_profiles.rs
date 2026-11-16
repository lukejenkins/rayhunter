//! Which deployment profile each capture was recorded in (Fixed = home
//! cabinet, Mobile = everything else), so the archive add-on can judge a
//! capture against the right baseline later. One line per fact:
//! `<capture> <profile>`; a capture that saw a switch has lines for both.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::Mutex;

use crate::display::m2100_profile::{PROFILE_PATH, Profile, load};
use crate::display::m2100_secret::write_atomic;

pub const CAPTURE_PROFILES_PATH: &str = "/data/rayhunter/capture-profiles";
pub const MAX_LINES: usize = 1000;

/// The recording in progress, so a profile switch knows which capture to tag.
pub static CURRENT_CAPTURE: Mutex<Option<String>> = Mutex::new(None);

/// Appends `<capture> <profile>`, keeping the last `MAX_LINES` lines. Capture
/// names are digits; anything else is refused rather than corrupt the file.
pub fn record(path: &Path, capture: &str, profile: Profile) -> io::Result<()> {
    if capture.is_empty() || !capture.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capture name must be digits",
        ));
    }
    // One writer at a time: read-modify-write plus a shared temp file.
    static WRITE_LOCK: Mutex<()> = Mutex::new(());
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let old = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<&str> = old.lines().collect();
    // The capture's latest line already says this (boot re-apply repeats).
    let prefix = format!("{capture} ");
    if let Some(last) = lines.iter().rev().find(|l| l.starts_with(&prefix))
        && *last == format!("{capture} {}", profile.as_str())
    {
        return Ok(());
    }
    let new = format!("{capture} {}", profile.as_str());
    lines.push(&new);
    let keep = lines.len().saturating_sub(MAX_LINES);
    let mut body = lines[keep..].join("\n");
    body.push('\n');
    write_atomic(path, &body)
}

/// Each capture -> "fixed" / "mobile", or "mixed" if it has both. Malformed
/// lines are ignored.
pub fn summarise(text: &str) -> BTreeMap<String, &'static str> {
    let mut out: BTreeMap<String, &'static str> = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split(' ');
        let (Some(name), Some(p), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let p = match p {
            "fixed" => "fixed",
            "mobile" => "mobile",
            _ => continue,
        };
        let e = out.entry(name.to_string()).or_insert(p);
        if *e != p {
            *e = "mixed";
        }
    }
    out
}

/// Logs `capture` under `profile`; a write failure is a warning, never an
/// error for the caller (recording must not be affected).
fn record_or_warn(path: &Path, capture: &str, profile: Profile) {
    if let Err(e) = record(path, capture, profile) {
        log::warn!("m2100: capture profile log failed: {e}");
    }
}

fn started_at(log: &Path, profile_file: &Path, name: &str) {
    if let Ok(mut cur) = CURRENT_CAPTURE.lock() {
        *cur = Some(name.to_string());
    }
    record_or_warn(log, name, load(profile_file));
}

fn applied_at(log: &Path, profile: Profile) {
    let cur = CURRENT_CAPTURE.lock().ok().and_then(|c| c.clone());
    if let Some(name) = cur {
        record_or_warn(log, &name, profile);
    }
}

/// A recording started: remember it and log it under the saved profile.
/// Callers gate this on the M2100.
pub fn note_started(name: Option<&str>) {
    if let Some(name) = name {
        started_at(
            Path::new(CAPTURE_PROFILES_PATH),
            Path::new(PROFILE_PATH),
            name,
        );
    }
}

/// The recording ended: later switches belong to no capture.
pub fn note_stopped() {
    if let Ok(mut cur) = CURRENT_CAPTURE.lock() {
        *cur = None;
    }
}

/// A profile was successfully applied: tag the current capture with it.
pub fn note_applied(profile: Profile) {
    applied_at(Path::new(CAPTURE_PROFILES_PATH), profile);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("capprof-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("capture-profiles")
    }

    #[test]
    fn different_profiles_for_one_capture_are_mixed() {
        let p = scratch("mixed");
        record(&p, "100", Profile::Fixed).unwrap();
        record(&p, "100", Profile::Mobile).unwrap();
        let s = summarise(&std::fs::read_to_string(&p).unwrap());
        assert_eq!(s["100"], "mixed");
    }

    #[test]
    fn same_profile_twice_stays_that_profile() {
        let p = scratch("same");
        record(&p, "100", Profile::Fixed).unwrap();
        record(&p, "100", Profile::Fixed).unwrap();
        record(&p, "200", Profile::Mobile).unwrap();
        let s = summarise(&std::fs::read_to_string(&p).unwrap());
        assert_eq!(s["100"], "fixed");
        assert_eq!(s["200"], "mobile");
    }

    #[test]
    fn keeps_only_the_last_thousand_lines() {
        let p = scratch("cap");
        for i in 0..1005 {
            record(&p, &i.to_string(), Profile::Mobile).unwrap();
        }
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), MAX_LINES);
        assert_eq!(text.lines().next().unwrap(), "5 mobile");
        assert_eq!(text.lines().last().unwrap(), "1004 mobile");
    }

    #[test]
    fn malformed_lines_are_ignored() {
        let s = summarise("x\n31 moving\n\n abc fixed\n7 fixed extra\n42 fixed\n");
        assert_eq!(s.len(), 1);
        assert_eq!(s["42"], "fixed");
    }

    #[test]
    fn odd_names_are_refused_and_nothing_is_written() {
        let p = scratch("names");
        for bad in ["a b", "1\n2", "", "12 ", "x"] {
            assert!(record(&p, bad, Profile::Fixed).is_err(), "{bad:?}");
        }
        assert!(!p.exists());
    }

    #[test]
    fn a_switch_after_the_recording_stopped_does_not_tag_it() {
        let d = scratch("stop");
        let prof = d.with_file_name("profile");
        crate::display::m2100_profile::store(&prof, Profile::Fixed).unwrap();
        started_at(&d, &prof, "300");
        note_stopped();
        applied_at(&d, Profile::Mobile);
        let s = summarise(&std::fs::read_to_string(&d).unwrap());
        assert_eq!(s["300"], "fixed");
        // while recording, a switch does tag it
        started_at(&d, &prof, "301");
        applied_at(&d, Profile::Mobile);
        note_stopped();
        let s = summarise(&std::fs::read_to_string(&d).unwrap());
        assert_eq!(s["301"], "mixed");
    }

    #[test]
    fn concurrent_records_lose_nothing() {
        let p = scratch("conc");
        let (a, b) = (p.clone(), p.clone());
        let n = 200;
        let t1 = std::thread::spawn(move || {
            for i in 0..n {
                record(&a, &format!("1{i}"), Profile::Fixed).unwrap();
            }
        });
        let t2 = std::thread::spawn(move || {
            for i in 0..n {
                record(&b, &format!("2{i}"), Profile::Mobile).unwrap();
            }
        });
        t1.join().unwrap();
        t2.join().unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap().lines().count(), 2 * n);
    }

    #[test]
    fn repeating_the_latest_profile_adds_no_line() {
        let p = scratch("dup");
        record(&p, "5", Profile::Fixed).unwrap();
        record(&p, "5", Profile::Fixed).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap().lines().count(), 1);
        record(&p, "5", Profile::Mobile).unwrap();
        record(&p, "5", Profile::Fixed).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap().lines().count(), 3);
    }

    #[test]
    fn hooks_are_wired_where_the_recording_starts_and_stops() {
        let diag = include_str!("../diag.rs");
        let stop = &diag[diag.find("fn stop_current_recording").unwrap()..];
        assert!(stop[..300].contains("note_stopped()"));
        let start = diag.find("note_started(").unwrap();
        assert!(diag[start - 200..start].contains("Device::M2100"));
    }

    #[test]
    fn route_is_get_only() {
        let main = include_str!("../main.rs");
        let lines: Vec<&str> = main
            .lines()
            .filter(|l| l.contains("m2100/capture-profiles"))
            .collect();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("get("), "{}", lines[0]);
        assert!(!lines[0].contains("post(") && !lines[0].contains("put("));
    }
}
