//! SPIKE (2026-10-16, throwaway): a serving-cell signal log for the "is this
//! transmitter moving?" question.
//!
//! Every [`EVERY`] telemetry polls the panel's poller appends one CSV line:
//! the unit's clock, seconds since the daemon started, the serving cell and
//! its signal. The question is whether a fixed unit's per-cell RSRP spread is
//! narrow enough for a moving or newly parked transmitter to stand out.
//!
//! The file stays on the unit (read by adb, never served over the web API) and
//! is capped: past [`CAP_BYTES`] it is moved to `siglog.csv.1`, replacing the
//! previous one, so at most about two caps are ever on disk.

use std::io::Write;
use std::path::Path;

use super::m2100_signal::{CellInfo, SignalInfo};

pub const PATH: &str = "/data/rayhunter/siglog.csv";
/// One line every 15 polls of 2 s = every 30 s.
pub const EVERY: u32 = 15;
pub const CAP_BYTES: u64 = 1024 * 1024;

pub const HEADER: &str =
    "unit_time,uptime_s,plmn,tac,eci,pci,earfcn,cell_rsrp,cell_rsrq,rsrp,rsrq,rssi,snr\n";

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

/// One CSV line. Missing readings leave their fields empty; a line is written
/// even when both are missing, so gaps show up as gaps.
pub fn format_line(
    unit_time: &str,
    uptime_s: u64,
    cell: Option<&CellInfo>,
    sig: Option<&SignalInfo>,
) -> String {
    let c = |f: fn(&CellInfo) -> String| cell.map(f).unwrap_or_default();
    format!(
        "{unit_time},{uptime_s},{},{},{},{},{},{},{},{},{},{},{}\n",
        c(|c| c.plmn.clone()),
        c(|c| c.tac.to_string()),
        c(|c| c.global_cell_id.to_string()),
        c(|c| c.pci.to_string()),
        c(|c| c.earfcn.to_string()),
        c(|c| format!("{:.1}", c.rsrp_dbm10 as f32 / 10.0)),
        c(|c| format!("{:.1}", c.rsrq_db10 as f32 / 10.0)),
        opt(sig.map(|s| s.rsrp_dbm)),
        opt(sig.map(|s| s.rsrq_db)),
        opt(sig.map(|s| s.rssi_dbm)),
        opt(sig.map(|s| format!("{:.1}", s.snr_db()))),
    )
}

/// Append `line`, rotating to `<path>.1` first if the file is already at the
/// cap, and writing the header into a new file.
pub fn append(path: &Path, line: &str, cap: u64) -> std::io::Result<()> {
    let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if len >= cap {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        std::fs::rename(path, &old)?;
    }
    let fresh = !path.exists();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if fresh {
        f.write_all(HEADER.as_bytes())?;
    }
    f.write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell() -> CellInfo {
        CellInfo {
            plmn: "310-260".into(),
            tac: 11111,
            global_cell_id: 3_160_321,
            earfcn: 1050,
            pci: 101,
            rsrq_db10: -118,
            rsrp_dbm10: -1038,
        }
    }

    fn sig() -> SignalInfo {
        SignalInfo {
            rssi_dbm: -75,
            rsrq_db: -11,
            rsrp_dbm: -104,
            snr_db10: 87,
        }
    }

    #[test]
    fn line_has_every_field() {
        let l = format_line("2026-10-16T10:00:00-07:00", 42, Some(&cell()), Some(&sig()));
        assert_eq!(
            l,
            "2026-10-16T10:00:00-07:00,42,310-260,11111,3160321,101,1050,-103.8,-11.8,-104,-11,-75,8.7\n"
        );
        assert_eq!(l.matches(',').count(), HEADER.matches(',').count());
    }

    #[test]
    fn missing_readings_leave_empty_fields() {
        let l = format_line("t", 1, None, None);
        assert_eq!(l, "t,1,,,,,,,,,,,\n");
        assert_eq!(l.matches(',').count(), HEADER.matches(',').count());
    }

    #[test]
    fn new_file_gets_a_header_then_lines() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("siglog.csv");
        append(&p, "a\n", 1000).unwrap();
        append(&p, "b\n", 1000).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            format!("{HEADER}a\nb\n")
        );
    }

    #[test]
    fn rotates_at_the_cap_and_keeps_one_old_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("siglog.csv");
        let cap = (HEADER.len() + 2) as u64;
        append(&p, "a\n", cap).unwrap(); // header + a = exactly the cap
        append(&p, "b\n", cap).unwrap(); // rotates first
        append(&p, "c\n", cap).unwrap(); // at cap again: rotates, replacing .1
        let old = d.path().join("siglog.csv.1");
        assert_eq!(
            std::fs::read_to_string(&old).unwrap(),
            format!("{HEADER}b\n")
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), format!("{HEADER}c\n"));
    }
}
