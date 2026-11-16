//! Live status panel for the Inseego M2100's 320x240 colour display.
//!
//! Rather than showing a fixed image, this renders the things you actually want
//! to glance at on a mounted sensor: the serving cell, signal, carrier, how much
//! data the plan has burned, and Rayhunter's own recording/warning state.
//!
//! Cell and radio data come from the vendor's own web API on the loopback
//! interface, `http://127.0.0.1/srv/status`, which needs no authentication and
//! is the same endpoint the vendor UI itself reads. It carries the serving
//! cell's band and PCI, the PLMN, technology, signal bars, SINR, battery, byte
//! counters and connected client count.
//!
//! Text is drawn with a small embedded bitmap font (see [`super::m2100_font`])
//! so there is no font dependency at runtime.

use super::m2100_font::{FONT, GLYPH_H, GLYPH_W};
use super::m2100_signal::{ActiveBand, CellInfo, SignalInfo};
use crate::display::DisplayState;
use crate::display::generic_framebuffer::Color;
use rayhunter::analysis::analyzer::EventType;
use std::time::Duration;

const WIDTH: u32 = 320;
const HEIGHT: u32 = 240;

const STATUS_URL: &str = "http://127.0.0.1/srv/status";

/// How many RSRP samples the sparkline keeps. At one sample per [`REFRESH`]
/// that is a few minutes of history across the width of the panel.
pub const HISTORY: usize = 76;

/// Fixed dBm window for the sparkline. Fixed rather than auto-scaled so the
/// trace means the same thing from one glance to the next -- an auto-scaled
/// plot of a flat signal looks identical to one of a collapsing signal.
const RSRP_FLOOR: i16 = -125;
const RSRP_CEIL: i16 = -70;

/// The START/STOP control inside the status panel.
///
/// Placed centrally on purpose: the four mode-switch corners occupy
/// `x < 80 || x >= 240` crossed with `y < 60 || y >= 180`, so a button between
/// x=100 and x=220 cannot be hit by a corner gesture and vice versa.
// Beside the DATA/CONN/BATT block, which leaves its right half empty. It used
// to sit at the bottom, across the RSRP trace, so the trace was only visible
// either side of it -- and the history in the middle, the most recent minutes,
// was the part hidden.
pub const BTN_X: u32 = 184;
pub const BTN_W: u32 = 120;
pub const BTN_Y: u32 = 120;
pub const BTN_H: u32 = 32;

/// The magenta that first proved this panel was alive.
///
/// Eleven approaches had failed and the panel had been written off as closed
/// before `strace` on the vendor's own `/opt/nvtl/bin/tests/lcdfbtest` gave up
/// ioctl `0x9999`. This was the first thing that ever reached the glass.
pub fn render_egg() -> Vec<(u8, u8, u8)> {
    let mut c = Canvas::new();
    let magenta = (252, 0, 252);
    for px in c.px.iter_mut() {
        *px = magenta;
    }

    let lines = [("0x9999", 3u32), ("lcdfbtest", 2)];
    let mut y = 78;
    for (text, scale) in lines {
        let tw = text.len() as u32 * GLYPH_W * scale;
        let x = (WIDTH - tw) / 2;
        for (i, ch) in text.chars().enumerate() {
            let idx = match ch as u32 {
                v @ 0x20..=0x7e => (v - 0x20) as usize,
                _ => 0,
            };
            for (row, bits) in FONT[idx].iter().enumerate().take(GLYPH_H as usize) {
                for col in 0..GLYPH_W {
                    if bits >> (7 - col) & 1 != 1 {
                        continue;
                    }
                    let bx = x + (i as u32 * GLYPH_W + col) * scale;
                    let by = y + row as u32 * scale;
                    for dy in 0..scale {
                        for dx in 0..scale {
                            c.set(bx + dx, by + dy, (0, 0, 0));
                        }
                    }
                }
            }
        }
        y += GLYPH_H * scale + 16;
    }
    c.px
}

/// Overlay a bare `ON` / `OFF` in the middle of whatever is on screen.
///
/// Deliberately says nothing about what it refers to. Someone who presses the
/// gesture without knowing what it is learns only that something toggled, not
/// that the device has a web interface, or that it has just been closed. The
/// operator knows what it means; a bystander gets nothing.
pub fn flash_overlay(buf: &mut [(u8, u8, u8)], on: bool) {
    let label = if on { "ON" } else { "OFF" };
    let col = if on {
        Color::Green.rgb()
    } else {
        Color::Red.rgb()
    };

    // Scale the glyphs up so it reads at a glance and at arm's length.
    const S: u32 = 4;
    let tw = label.len() as u32 * GLYPH_W * S;
    let th = GLYPH_H * S;
    let ox = (WIDTH - tw) / 2;
    let oy = (HEIGHT - th) / 2;

    let pad = 10;
    for y in oy.saturating_sub(pad)..(oy + th + pad).min(HEIGHT) {
        for x in ox.saturating_sub(pad)..(ox + tw + pad).min(WIDTH) {
            if let Some(px) = buf.get_mut((y * WIDTH + x) as usize) {
                *px = (0, 0, 0);
            }
        }
    }

    for (i, ch) in label.chars().enumerate() {
        let idx = match ch as u32 {
            v @ 0x20..=0x7e => (v - 0x20) as usize,
            _ => 0,
        };
        let glyph = &FONT[idx];
        for (row, bits) in glyph.iter().enumerate().take(GLYPH_H as usize) {
            for c in 0..GLYPH_W {
                if bits >> (7 - c) & 1 != 1 {
                    continue;
                }
                let bx = ox + (i as u32 * GLYPH_W + c) * S;
                let by = oy + row as u32 * S;
                for dy in 0..S {
                    for dx in 0..S {
                        if let Some(px) = buf.get_mut(((by + dy) * WIDTH + bx + dx) as usize) {
                            *px = col;
                        }
                    }
                }
            }
        }
    }
}

/// True if a touch at these coordinates is on the control button.
pub fn hits_control(x: i32, y: i32) -> bool {
    x >= BTN_X as i32
        && x < (BTN_X + BTN_W) as i32
        && y >= BTN_Y as i32
        && y < (BTN_Y + BTN_H) as i32
}

/// How many cell changes the log keeps. It was 8 -- what fits on one screen --
/// and the header showed how many were KEPT, so a 40-mile drive with 92 changes
/// read "8" and looked like 8 towers (2026-10-02). It now scrolls, keeps enough
/// for a day's driving, and the header shows kept / total. The captures are
/// still the audit trail; this is the glanceable one.
pub const LOG_LEN: usize = 100;

/// Where towers already seen are remembered, so a never-seen-before eNodeB can be
/// marked. An unfamiliar tower is weak evidence on its own, but it is the first
/// thing a fake cell looks like.
pub const KNOWN_TOWERS_PATH: &str = "/data/rayhunter/known_towers.txt";

/// eNodeB IDs already seen, one per line on disk. `path: None` keeps it in
/// memory only (tests, and a device without the file).
#[derive(Debug, Default)]
pub struct KnownTowers {
    seen: std::collections::HashSet<u32>,
    path: Option<std::path::PathBuf>,
}

impl KnownTowers {
    /// Load from `path`; a missing or unreadable file starts empty. Lines that are
    /// not numbers are skipped, so a hand edit can't take the panel down.
    pub fn load(path: &str) -> Self {
        let seen = std::fs::read_to_string(path)
            .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
            .unwrap_or_default();
        KnownTowers {
            seen,
            path: Some(path.into()),
        }
    }

    /// Record a sighting; true if this tower had never been seen before.
    /// Appends to the file so the memory survives reboots.
    pub fn sighted(&mut self, enodeb: u32) -> bool {
        if !self.seen.insert(enodeb) {
            return false;
        }
        if let Some(p) = &self.path {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
            {
                let _ = writeln!(f, "{enodeb}");
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

/// The identity of a serving cell, as far as this device can see it.
///
/// A change in any of these is what the log records. Band and channel come from
/// QMI and are authoritative; PCI comes from the vendor, which is the only
/// source for it here.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CellId {
    pub plmn: Option<String>,
    pub band: Option<String>,
    pub channel: Option<u16>,
    pub pci: Option<u16>,
    /// E-UTRAN Cell Identity. This is what a change is really keyed on: PCI is
    /// only locally unique and heavily reused, while the ECI names one cell on
    /// one eNodeB.
    pub eci: Option<u32>,
    /// Tracking area. Worth recording on its own -- a TAC change forces a
    /// location update, which is one way to make a device identify itself.
    pub tac: Option<u16>,
}

impl CellId {
    fn label(&self) -> String {
        let band = self.band.clone().unwrap_or_else(|| "?".into());
        let chan = self.channel.map(|c| format!(" E{c}")).unwrap_or_default();
        let pci = self.pci.map(|p| format!(" P{p}")).unwrap_or_default();
        format!("{band}{chan}{pci}")
    }

    /// Second line for the log: the identity that actually pins the cell down.
    fn detail(&self) -> String {
        match (self.eci, self.tac) {
            (Some(e), Some(t)) => format!("eNB {} c{}  TAC {t}", e >> 8, e & 0xff),
            (Some(e), None) => format!("eNB {} c{}", e >> 8, e & 0xff),
            (None, Some(t)) => format!("TAC {t}"),
            _ => String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CellChange {
    pub at: chrono::DateTime<chrono::Local>,
    pub cell: CellId,
    /// RSRP at the moment of the change, when known.
    pub rsrp_dbm: Option<i16>,
    /// This cell's eNodeB had never been seen before.
    pub new_tower: bool,
}

/// Everything the panels draw from, polled on its own cadence so the history
/// and the cell log keep accumulating no matter which mode is on screen.
#[derive(Default)]
pub struct Telemetry {
    pub status: VendorStatus,
    pub cell: Option<CellInfo>,
    pub sig: Option<SignalInfo>,
    pub bands: Vec<ActiveBand>,
    pub hist: Vec<i16>,
    pub log: Vec<CellChange>,
    /// Every serving-cell change since start, including those the log dropped.
    pub total_changes: u64,
    pub known: KnownTowers,
    current: CellId,
}

impl Telemetry {
    /// Current serving-cell identity, preferring QMI for band and channel.
    fn cell_id(&self) -> CellId {
        let (band, channel) = match self.bands.first() {
            Some(b) => (Some(b.label()), Some(b.channel)),
            None => (self.status.band.clone().map(|b| format!("B{b}")), None),
        };
        // Everything identifying comes from QMI. The vendor's statusBarPCI was
        // observed reading 0 while the modem was on a nonzero PCI, and reading 0
        // across three different cells, so it is not used at all.
        CellId {
            plmn: self
                .cell
                .as_ref()
                .map(|c| c.plmn.clone())
                .or_else(|| self.status.plmn.clone()),
            band,
            channel: self.cell.as_ref().map(|c| c.earfcn).or(channel),
            pci: self.cell.as_ref().map(|c| c.pci),
            eci: self.cell.as_ref().map(|c| c.global_cell_id),
            tac: self.cell.as_ref().map(|c| c.tac),
        }
    }

    /// Fold one poll's worth of readings in, appending to the log if the
    /// serving cell changed.
    pub fn observe(&mut self) {
        let now = self.cell_id();
        // Ignore an all-empty reading: a failed poll is not a cell change.
        if now == CellId::default() {
            return;
        }
        if now != self.current {
            self.current = now.clone();
            self.total_changes += 1;
            let new_tower = now.eci.map(|e| self.known.sighted(e >> 8)).unwrap_or(false);
            if self.log.len() == LOG_LEN {
                self.log.remove(0);
            }
            self.log.push(CellChange {
                at: chrono::Local::now(),
                cell: now,
                rsrp_dbm: self.sig.map(|s| s.rsrp_dbm),
                new_tower,
            });
        }
    }
}

/// A screen's worth of pixels, written top-left to bottom-right.
struct Canvas {
    px: Vec<(u8, u8, u8)>,
}

impl Canvas {
    fn new() -> Self {
        Canvas {
            px: vec![(0, 0, 0); (WIDTH * HEIGHT) as usize],
        }
    }

    fn set(&mut self, x: u32, y: u32, c: (u8, u8, u8)) {
        if x < WIDTH && y < HEIGHT {
            self.px[(y * WIDTH + x) as usize] = c;
        }
    }

    fn hline(&mut self, x: u32, y: u32, len: u32, c: (u8, u8, u8)) {
        for i in 0..len {
            self.set(x + i, y, c);
        }
    }

    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, c: (u8, u8, u8)) {
        for dy in 0..h {
            self.hline(x, y + dy, w, c);
        }
    }

    /// Draw one line of text. Characters outside the font fall back to a space.
    fn text(&mut self, x: u32, y: u32, s: &str, c: (u8, u8, u8)) {
        for (i, ch) in s.chars().enumerate() {
            let idx = match ch as u32 {
                v @ 0x20..=0x7e => (v - 0x20) as usize,
                _ => 0,
            };
            let glyph = &FONT[idx];
            let gx = x + i as u32 * GLYPH_W;
            for (row, bits) in glyph.iter().enumerate().take(GLYPH_H as usize) {
                for col in 0..GLYPH_W {
                    if bits >> (7 - col) & 1 == 1 {
                        self.set(gx + col, y + row as u32, c);
                    }
                }
            }
        }
    }
}

/// The subset of the vendor status API this panel shows.
///
/// Every field is optional: the endpoint is the vendor's, not ours, and a
/// missing or renamed key should blank one line rather than break the panel.
#[derive(Default, Clone)]
pub struct VendorStatus {
    pub network: Option<String>,
    pub plmn: Option<String>,
    pub technology: Option<String>,
    pub band: Option<String>,
    pub bars: Option<u32>,
    pub battery: Option<String>,
    pub charging_source: Option<String>,
    pub bytes_total: Option<u64>,
    pub connection_secs: Option<u64>,
    pub clients: Option<String>,
    pub connection_state: Option<String>,
}

fn str_field(v: &serde_json::Value, key: &str) -> Option<String> {
    let f = v.get(key)?;
    // The vendor mixes quoted and unquoted values for the same shape of data.
    match f {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn num_field(v: &serde_json::Value, key: &str) -> Option<u64> {
    str_field(v, key)?.parse().ok()
}

pub async fn fetch_status(client: &reqwest::Client) -> Option<VendorStatus> {
    let body = client
        .get(STATUS_URL)
        .timeout(Duration::from_secs(4))
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let root: serde_json::Value = serde_json::from_str(&body).ok()?;
    let d = root.get("statusData")?;
    Some(VendorStatus {
        network: str_field(d, "statusBarNetwork"),
        plmn: str_field(d, "statusBarNetworkID"),
        technology: str_field(d, "statusBarTechnology"),
        band: str_field(d, "statusBarBand"),
        bars: num_field(d, "statusBarSignalBars").map(|v| v as u32),
        battery: str_field(d, "statusBarBatteryPercent"),
        charging_source: str_field(d, "statusBarBatteryChargingSource"),
        bytes_total: num_field(d, "statusBarBytesTotal"),
        connection_secs: num_field(d, "statusBarConnectionDuration"),
        clients: str_field(d, "statusBarClientListSize"),
        connection_state: str_field(d, "statusBarConnectionState"),
    })
}

fn human_bytes(b: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = MB * 1024.0;
    let f = b as f64;
    if f >= GB {
        format!("{:.2} GB", f / GB)
    } else {
        format!("{:.1} MB", f / MB)
    }
}

fn human_secs(s: u64) -> String {
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// Free space on the partition holding the captures.
fn disk_free() -> Option<u64> {
    let path = std::ffi::CString::new("/data").ok()?;
    // SAFETY: `stat` is fully initialised by statvfs on success, and `path` is
    // a valid NUL-terminated string that outlives the call.
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        Some(stat.f_bavail as u64 * stat.f_frsize as u64)
    }
}

fn state_label(state: DisplayState) -> (&'static str, Color) {
    match state {
        DisplayState::Paused => ("PAUSED", Color::White),
        DisplayState::Recording => ("RECORDING", Color::Green),
        DisplayState::WarningDetected { event_type } => match event_type {
            EventType::Informational => ("INFO", Color::Green),
            EventType::Low => ("WARNING: LOW", Color::Yellow),
            EventType::Medium => ("WARNING: MED", Color::Orange),
            EventType::High => ("WARNING: HIGH", Color::Red),
        },
    }
}

/// Draw the RSRP trace. Oldest sample left, newest right, with the newest
/// value picked out so the current reading is findable at a glance.
/// Width reserved for the RSRP scale down the left of the trace: "-125" plus
/// a gap.
const SCALE_W: u32 = 4 * GLYPH_W + 4;

/// Rows for the two scale labels: the top of the plot and its bottom.
///
/// They used to sit either side of the HOLD button, one at each end of the
/// row, which reads as a horizontal axis running -125 -> -70. It is a vertical
/// scale, and time is what runs left to right, so the labels now stack down the
/// left margin against the trace they describe.
///
/// The font is 8x14, so two rows need 28px: at the original plot height of 24
/// they overlapped, which is why the plot grew by 4.
fn scale_rows(plot_y: u32, plot_h: u32) -> (u32, u32) {
    (plot_y, plot_y + plot_h.saturating_sub(GLYPH_H))
}

/// Left edge and width of column `i` of `n`, spread across `w` with no
/// cumulative rounding loss.
///
/// The obvious `w / n` truncates, and the error compounds: once the scale took
/// its left margin the plot was 276 wide, 276/76 rounds 3.63 down to 3, and 76
/// columns then covered 228px -- the trace visibly stopped short of the right
/// edge. Deriving each edge from the full width instead keeps the last column
/// against the right edge whatever the divisor does.
fn plot_column(x: u32, w: u32, n: u32, i: u32) -> (u32, u32) {
    let bx = x + (i * w) / n;
    let end = x + ((i + 1) * w) / n;
    (bx, end.saturating_sub(bx).saturating_sub(1).max(1))
}

fn sparkline(c: &mut Canvas, x: u32, y: u32, w: u32, h: u32, hist: &[i16], accent: (u8, u8, u8)) {
    let grid = (55, 55, 55);
    // Baseline and top rule, so an empty or flat trace still reads as a plot.
    c.hline(x, y + h, w, grid);
    c.hline(x, y, w, grid);

    if hist.is_empty() {
        return;
    }
    for (i, v) in hist.iter().enumerate() {
        let clamped = (*v).clamp(RSRP_FLOOR, RSRP_CEIL);
        let frac = (clamped - RSRP_FLOOR) as f32 / (RSRP_CEIL - RSRP_FLOOR) as f32;
        let bar = (frac * h as f32).round() as u32;
        let (bx, cw) = plot_column(x, w, HISTORY as u32, i as u32);
        if bx >= x + w {
            break;
        }
        let bar = bar.max(2);
        let newest = i + 1 == hist.len();
        // Dimmed fill below the trace gives the magnitude at a glance without
        // the solid block a full-height bar chart produces.
        let fill = (
            (accent.0 as u16 * 45 / 255) as u8,
            (accent.1 as u16 * 45 / 255) as u8,
            (accent.2 as u16 * 45 / 255) as u8,
        );
        c.fill_rect(bx, y + h - bar, cw, bar, fill);
        // The trace itself: the top two rows of each column.
        let col = if newest { (255, 255, 255) } else { accent };
        c.fill_rect(bx, y + h - bar, cw, 2, col);
    }
}

/// Render the whole panel. Returns a full-screen buffer ready for the
/// framebuffer, with the status bar already composited into the top rows.
pub fn render_status(state: DisplayState, t: &Telemetry, colorblind: bool) -> Vec<(u8, u8, u8)> {
    let s = &t.status;
    let sig = t.sig;
    let bands = &t.bands[..];
    let hist = &t.hist[..];
    let mut c = Canvas::new();

    let (label, mut accent) = state_label(state);
    if colorblind && matches!(state, DisplayState::Recording) {
        accent = Color::Blue;
    }
    let accent = accent.rgb();
    let dim = (140, 140, 140);
    let white = (255, 255, 255);

    // Status bar, same two rows and meaning as every other UI level.
    c.fill_rect(0, 0, WIDTH, 2, accent);

    let mut y = 6;
    c.text(4, y, "RAYHUNTER", white);
    // Right-align the state label.
    let lx = WIDTH - 4 - label.len() as u32 * GLYPH_W;
    c.text(lx, y, label, accent);
    y += GLYPH_H + 2;
    c.hline(4, y, WIDTH - 8, dim);
    y += 4;

    let row = |c: &mut Canvas, y: &mut u32, key: &str, val: String| {
        c.text(4, *y, key, dim);
        c.text(4 + 6 * GLYPH_W, *y, &val, white);
        *y += GLYPH_H;
    };

    // Carrier name from the vendor, but the RAT from QMI. The vendor reports
    // "5G" whenever EN-DC is merely advertised, which is not the same as being
    // connected to it -- observed showing 5G/n8 while QMI had a single LTE leg.
    let rat = if bands.iter().any(|b| b.is_nr()) {
        "5G".to_string()
    } else if bands.is_empty() {
        s.technology.clone().unwrap_or_else(|| "--".into())
    } else {
        "LTE".to_string()
    };
    let net = match &s.network {
        Some(n) => format!("{n}  {rat}"),
        None => rat,
    };
    row(&mut c, &mut y, "NET", net);
    row(
        &mut c,
        &mut y,
        "PLMN",
        s.plmn.clone().unwrap_or_else(|| "--".into()),
    );
    // Band and channel from QMI (authoritative), PCI from the vendor since QMI
    // does not carry it here. In EN-DC both legs are listed.
    let cell = if bands.is_empty() {
        match &s.band {
            Some(b) => format!("B{b}  (vendor)"),
            None => "--".into(),
        }
    } else {
        let legs: Vec<String> = bands
            .iter()
            .map(|b| format!("{} E{}", b.label(), b.channel))
            .collect();
        match t.cell.as_ref() {
            Some(ci) => format!("{}  PCI {}", legs.join(" + "), ci.pci),
            None => legs.join(" + "),
        }
    };
    row(&mut c, &mut y, "CELL", cell);
    row(
        &mut c,
        &mut y,
        "ID",
        match t.cell.as_ref() {
            Some(ci) => format!("eNB {} c{}  TAC {}", ci.enodeb(), ci.cell(), ci.tac),
            None => "--".into(),
        },
    );

    // Signal: vendor bar count, then the real measurements from QMI. The
    // vendor's own SINR field is not shown because it is hardwired to 0.
    let bars = s.bars.unwrap_or(0).min(5);
    c.text(4, y, "SIG", dim);
    let bx = 4 + 6 * GLYPH_W;
    for i in 0..5u32 {
        let bh = 4 + i * 2;
        let col = if i < bars { accent } else { (60, 60, 60) };
        c.fill_rect(bx + i * 7, y + (GLYPH_H - bh), 5, bh, col);
    }
    if let Some(sig) = sig {
        c.text(
            bx + 42,
            y,
            &format!("{} dBm  SNR {:.0}", sig.rsrp_dbm, sig.snr_db()),
            white,
        );
    }
    y += GLYPH_H + 2;

    c.hline(4, y, WIDTH - 8, dim);
    y += 4;

    row(
        &mut c,
        &mut y,
        "DATA",
        s.bytes_total
            .map(human_bytes)
            .unwrap_or_else(|| "--".into()),
    );
    row(
        &mut c,
        &mut y,
        "CONN",
        match (&s.connection_secs, &s.connection_state) {
            (Some(t), Some(st)) if st == "Connected" => human_secs(*t),
            (_, Some(st)) => st.clone(),
            _ => "--".into(),
        },
    );
    row(
        &mut c,
        &mut y,
        "BATT",
        match (&s.battery, &s.charging_source) {
            // "ChargingSourceUSB" -> "USB"
            (Some(b), Some(src)) => format!("{b}%  {}", src.trim_start_matches("ChargingSource")),
            (Some(b), None) => format!("{b}%"),
            _ => "--".into(),
        },
    );
    row(
        &mut c,
        &mut y,
        "DISK",
        disk_free()
            .map(|b| format!("{} free", human_bytes(b)))
            .unwrap_or_else(|| "--".into()),
    );
    row(
        &mut c,
        &mut y,
        "WIFI",
        s.clients
            .clone()
            .map(|n| format!("{n} clients"))
            .unwrap_or_else(|| "--".into()),
    );

    // RSRP trace. A sudden step here is one of the classic tells -- a cell
    // appearing far stronger than its neighbours.
    y += 2;
    c.text(4, y, "RSRP", dim);
    if let Some(sig) = sig {
        c.text(
            4 + 6 * GLYPH_W,
            y,
            &format!(
                "{} dBm  RSSI {}  RSRQ {}",
                sig.rsrp_dbm, sig.rssi_dbm, sig.rsrq_db
            ),
            white,
        );
    }
    y += GLYPH_H;
    // Fills what is left below the RSRP line now that the button has moved off
    // it, rather than a fixed height chosen to fit around the button.
    let plot_h = HEIGHT.saturating_sub(y + 6);
    let (row_hi, row_lo) = scale_rows(y, plot_h);
    c.text(4, row_hi, &format!("{RSRP_CEIL}"), dim);
    c.text(4, row_lo, &format!("{RSRP_FLOOR}"), dim);
    sparkline(
        &mut c,
        4 + SCALE_W,
        y,
        WIDTH - 8 - SCALE_W,
        plot_h,
        hist,
        accent,
    );

    // Control. Shows the action the touch will perform, not the current state,
    // so there is no ambiguity about what pressing it does.
    let recording = !matches!(state, DisplayState::Paused);
    let (btn_label, btn_col) = if recording {
        ("HOLD STOP", Color::Red.rgb())
    } else {
        ("HOLD START", Color::Green.rgb())
    };
    c.fill_rect(BTN_X, BTN_Y, BTN_W, BTN_H, (28, 28, 28));
    // Border, so it reads as a target rather than a label.
    c.hline(BTN_X, BTN_Y, BTN_W, btn_col);
    c.hline(BTN_X, BTN_Y + BTN_H - 1, BTN_W, btn_col);
    for dy in 0..BTN_H {
        c.set(BTN_X, BTN_Y + dy, btn_col);
        c.set(BTN_X + BTN_W - 1, BTN_Y + dy, btn_col);
    }
    let tw = btn_label.len() as u32 * GLYPH_W;
    c.text(
        BTN_X + (BTN_W - tw) / 2,
        BTN_Y + (BTN_H - GLYPH_H) / 2,
        btn_label,
        btn_col,
    );
    c.px
}

/// The cell-change log: when the serving cell last changed, and to what.
///
/// A single signal reading says little. A band or PCI change you did not cause
/// -- especially with a large signal step -- is the thing worth noticing, and
/// only a history shows it.
/// Which log entry was serving when an alert fired.
///
/// By cell identity first: the newest row for the alert's cell. That is immune to
/// the clock -- an alert at boot is stamped 1970 and would otherwise match nothing
/// (2026-10-02). Falls back to time: the last change at or before the alert.
pub fn alert_row(
    log: &[CellChange],
    eci: Option<u32>,
    at: chrono::DateTime<chrono::Local>,
) -> Option<usize> {
    if let Some(e) = eci {
        if let Some(i) = log.iter().rposition(|c| c.cell.eci == Some(e)) {
            return Some(i);
        }
    }
    log.iter().rposition(|e| e.at <= at)
}

/// How many entries fit below the header, for scrolling. Two text rows each.
pub const LOG_VISIBLE: usize = 7;

/// Clamp a scroll offset so the last page is never past the end.
pub fn clamp_scroll(scroll: usize, len: usize) -> usize {
    scroll.min(len.saturating_sub(LOG_VISIBLE))
}

pub fn render_log(
    state: DisplayState,
    t: &Telemetry,
    colorblind: bool,
    scroll: usize,
    alert: Option<(Option<u32>, chrono::DateTime<chrono::Local>)>,
) -> Vec<(u8, u8, u8)> {
    let mut c = Canvas::new();
    let (_, mut accent) = state_label(state);
    if colorblind && matches!(state, DisplayState::Recording) {
        accent = Color::Blue;
    }
    let accent = accent.rgb();
    let dim = (140, 140, 140);
    let white = (255, 255, 255);
    let red = Color::Red.rgb();
    let yellow = (232, 195, 65);

    c.fill_rect(0, 0, WIDTH, 2, accent);

    let mut y = 6;
    c.text(4, y, "CELLS", white);
    // kept / total, then distinct towers ever seen: the number people mean.
    let n = format!("{}/{} {}twr", t.log.len(), t.total_changes, t.known.len());
    c.text(WIDTH - 4 - n.len() as u32 * GLYPH_W, y, &n, accent);
    y += GLYPH_H + 2;
    c.hline(4, y, WIDTH - 8, dim);
    y += 4;

    if t.log.is_empty() {
        c.text(4, y, "no changes seen yet", dim);
        return c.px;
    }

    let scroll = clamp_scroll(scroll, t.log.len());
    let alerted = alert.and_then(|(eci, at)| alert_row(&t.log, eci, at));
    // Newest first: the most recent change is the one being reacted to.
    let shown = t
        .log
        .iter()
        .enumerate()
        .rev()
        .skip(scroll)
        .take(LOG_VISIBLE);
    for (k, (idx, e)) in shown.enumerate() {
        let newest = scroll == 0 && k == 0;
        let col = if newest { white } else { dim };
        // Marker column: '!' where an alert fired, '*' a never-seen tower.
        if alerted == Some(idx) {
            c.text(4, y, "!", red);
        } else if e.new_tower {
            c.text(4, y, "*", yellow);
        }
        let x0 = 4 + 2 * GLYPH_W;
        c.text(x0, y, &e.at.format("%H:%M").to_string(), col);
        c.text(x0 + 6 * GLYPH_W, y, &e.cell.label(), col);
        if let Some(r) = e.rsrp_dbm {
            let s = format!("{r}");
            c.text(WIDTH - 4 - s.len() as u32 * GLYPH_W, y, &s, col);
        }
        y += GLYPH_H;
        let detail = e.cell.detail();
        if !detail.is_empty() {
            c.text(x0 + 6 * GLYPH_W, y, &detail, (90, 90, 90));
        }
        y += GLYPH_H;
    }

    // Where you are in the list, and how to move: taps on the right edge.
    let older = t.log.len().saturating_sub(scroll + LOG_VISIBLE);
    let hint = match (scroll > 0, older > 0) {
        (true, true) => format!("^{scroll} newer  v{older} older"),
        (true, false) => format!("^{scroll} newer"),
        (false, true) => format!("v{older} older  tap right edge"),
        (false, false) => String::new(),
    };
    if !hint.is_empty() {
        c.text(
            WIDTH - 4 - hint.len() as u32 * GLYPH_W,
            HEIGHT - GLYPH_H - 2,
            &hint,
            dim,
        );
    }

    c.px
}

/// A red bar across the bottom while an alert is unacknowledged. Drawn on top of
/// whatever the screen shows, so it can't be missed by being on another mode.
pub fn alert_banner(buf: &mut Vec<(u8, u8, u8)>, text: &str) {
    let mut c = Canvas {
        px: std::mem::take(buf),
    };
    let h = GLYPH_H + 6;
    let y = HEIGHT - h;
    c.fill_rect(0, y, WIDTH, h, Color::Red.rgb());
    c.text(4, y + 3, text, (255, 255, 255));
    // Dismissed by a short tap on the LEFT edge (see m2100_ui::edge_tap).
    let hint = "tap left";
    c.text(
        WIDTH - 4 - hint.len() as u32 * GLYPH_W,
        y + 3,
        hint,
        (255, 255, 255),
    );
    *buf = c.px;
}

/// Sanity checks on the parts that are easy to get subtly wrong.
use crate::display::m2100_enrol::{Fail, Stage, Target};
use crate::display::m2100_profile::Profile;

pub fn render_enrol(target: Target, stage: &Stage, progress: usize) -> Vec<(u8, u8, u8)> {
    let mut c = Canvas::new();
    let white = (255, 255, 255);
    let what = match target {
        Target::Gesture => "reveal gesture",
        Target::Pin => "panic PIN",
    };
    c.text(8, 8, &format!("Set {what}"), white);
    let (line1, line2) = match stage {
        Stage::Verify => ("Perform your CURRENT", "one first"),
        Stage::First => ("Perform it now", "then pause"),
        Stage::Confirm => ("Again, to confirm", "then pause"),
        Stage::Done(_) => ("Saved", ""),
        Stage::Failed(Fail::TooShort) => ("Too short", "tap to try again"),
        Stage::Failed(Fail::TooLong) => ("Too long", "tap to try again"),
        Stage::Failed(Fail::TooSimple) => ("Too simple: vary it", "tap to try again"),
        Stage::Failed(Fail::Mismatch) => ("Didn't match", "tap to try again"),
        Stage::Failed(Fail::WrongCurrent) => ("Current one didn't match", "tap to try again"),
        Stage::Failed(Fail::TimedOut) => ("Timed out", ""),
    };
    c.text(8, 80, line1, white);
    c.text(8, 100, line2, white);
    // Progress as a row of dots: how many, never which.
    for i in 0..progress.min(12) as u32 {
        c.fill_rect(8 + i * 20, 150, 12, 12, white);
    }
    c.px
}

/// The buzzer row's text. The state is spelled out, not shown by colour alone.
pub fn buzzer_row_label(on: bool) -> &'static str {
    if on {
        "Tap: buzzer is ON"
    } else {
        "Tap: buzzer is OFF"
    }
}

pub fn profile_row_label(p: Profile) -> String {
    format!("Profile: {}", p.label())
}

/// Four rows drawn exactly where `m2100_ui::settings_choice` hears them
/// (y 0-47, 64-111, 128-175, 192-239); the bands between them choose nothing.
/// The rows that change a secret stay at the ends.
pub fn render_settings(buzzer_on: bool, profile: Profile) -> Vec<(u8, u8, u8)> {
    let mut c = Canvas::new();
    let white = (255, 255, 255);
    let grey = (90, 90, 90);
    let rows = [
        "Tap: set reveal gesture".to_string(),
        buzzer_row_label(buzzer_on).to_string(),
        profile_row_label(profile),
        "Tap: set panic PIN".to_string(),
    ];
    for (i, label) in rows.iter().enumerate() {
        let y = i as u32 * 64;
        c.fill_rect(0, y, WIDTH, 48, grey);
        c.text(8, y + 17, label, white);
    }
    c.px
}

/// The one-line note between the two profiles. "hold 2 s" on either: the
/// other switches, the current one re-applies.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ProfileNote {
    Hold,
    Switching,
    Failed,
}

impl ProfileNote {
    pub fn text(self) -> &'static str {
        match self {
            ProfileNote::Hold => "hold 2 s to switch",
            ProfileNote::Switching => "switching...",
            ProfileNote::Failed => "switch failed",
        }
    }
}

/// FIXED over y 0-103, the note in 104-135, MOBILE over 136-239: drawn where
/// `m2100_ui::profile_target` hears them. The current profile is lit and says
/// so in words, not by colour alone.
pub fn render_profile(current: Profile, note: ProfileNote) -> Vec<(u8, u8, u8)> {
    let mut c = Canvas::new();
    let white = (255, 255, 255);
    let grey = (90, 90, 90);
    let lit = (0, 110, 60);
    for (p, y) in [(Profile::Fixed, 0u32), (Profile::Mobile, 136)] {
        let on = p == current;
        c.fill_rect(0, y, WIDTH, 104, if on { lit } else { grey });
        let label = if on {
            format!("{} (current)", p.label())
        } else {
            p.label().to_string()
        };
        c.text(8, y + 44, &label, white);
    }
    c.text(8, 112, note.text(), white);
    c.px
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Columns must span the whole plot. `w / HISTORY` truncates -- at the
    /// width left after the scale took its margin, 276/76 is 3.63 rounded to
    /// 3, so 76 columns covered 228px of 276 and the trace stopped well short
    /// of the right edge.
    #[test]
    fn the_settings_screen_says_whether_the_buzzer_is_on() {
        assert_eq!(buzzer_row_label(true), "Tap: buzzer is ON");
        assert_eq!(buzzer_row_label(false), "Tap: buzzer is OFF");
        assert_ne!(
            render_settings(true, Profile::Fixed),
            render_settings(false, Profile::Fixed)
        );
    }

    #[test]
    fn the_settings_screen_names_the_current_profile() {
        assert_eq!(profile_row_label(Profile::Fixed), "Profile: FIXED");
        assert_eq!(profile_row_label(Profile::Mobile), "Profile: MOBILE");
        assert_ne!(
            render_settings(true, Profile::Fixed),
            render_settings(true, Profile::Mobile)
        );
    }

    #[test]
    fn the_profile_screen_shows_which_is_current_and_the_note() {
        assert_eq!(ProfileNote::Hold.text(), "hold 2 s to switch");
        assert_eq!(ProfileNote::Switching.text(), "switching...");
        assert_eq!(ProfileNote::Failed.text(), "switch failed");
        assert_ne!(
            render_profile(Profile::Fixed, ProfileNote::Hold),
            render_profile(Profile::Mobile, ProfileNote::Hold)
        );
        assert_ne!(
            render_profile(Profile::Fixed, ProfileNote::Hold),
            render_profile(Profile::Fixed, ProfileNote::Failed)
        );
    }

    #[test]
    fn columns_span_the_full_plot_width() {
        let (x, w, n) = (40u32, 276u32, HISTORY as u32);
        let (first, _) = plot_column(x, w, n, 0);
        let (last, last_w) = plot_column(x, w, n, n - 1);
        assert_eq!(
            first, x,
            "first column should start at the plot's left edge"
        );
        assert_eq!(
            last + last_w + 1,
            x + w,
            "last column should reach the right edge"
        );
    }

    #[test]
    fn columns_leave_no_gaps() {
        let (x, w, n) = (40u32, 276u32, HISTORY as u32);
        for i in 0..n - 1 {
            let (bx, cw) = plot_column(x, w, n, i);
            let (next, _) = plot_column(x, w, n, i + 1);
            assert_eq!(bx + cw + 1, next, "gap or overlap before column {}", i + 1);
        }
    }

    /// The old truncating step, kept as a regression marker.
    #[test]
    fn a_truncated_step_would_not_reach_the_edge() {
        let (w, n) = (276u32, HISTORY as u32);
        assert_eq!(w / n, 3, "the truncation this replaced");
        assert!(n * (w / n) < w, "76 x 3 = 228, short of 276");
    }

    /// The two RSRP bounds label a VERTICAL scale, so they have to stack
    /// without touching. This is the constraint that forced the plot from 24
    /// to 28: the font is 8x14 and two rows need 28.
    #[test]
    fn the_scale_labels_stack_without_overlapping() {
        let plot_y = 190;
        let (hi, lo) = scale_rows(plot_y, 28);
        assert!(lo >= hi + GLYPH_H, "labels overlap: {hi} and {lo}");
        assert!(lo + GLYPH_H <= plot_y + 28, "bottom label leaves the plot");
        assert_eq!(hi, plot_y, "top label should sit at the top of the plot");
    }

    #[test]
    fn the_old_plot_height_could_not_have_fitted_them() {
        // Documents why the plot grew rather than the labels shrinking.
        let (hi, lo) = scale_rows(190, 24);
        assert!(lo < hi + GLYPH_H);
    }

    /// The scale sits in the left margin, clear of the HOLD button, which the
    /// trace is drawn underneath.
    #[test]
    fn the_scale_does_not_reach_the_button() {
        assert!(4 + SCALE_W <= BTN_X, "scale would run under the button");
    }
    fn sample() -> Telemetry {
        Telemetry {
            status: VendorStatus {
                network: Some("Mint".into()),
                plmn: Some("310260".into()),
                technology: Some("5G".into()),
                band: Some("n8".into()),
                bars: Some(3),
                battery: Some("100".into()),
                charging_source: Some("ChargingSourceUSB".into()),
                bytes_total: Some(143_500_000),
                connection_secs: Some(6776),
                clients: Some("0".into()),
                connection_state: Some("Connected".into()),
            },
            sig: Some(SignalInfo {
                rssi_dbm: -81,
                rsrq_db: -11,
                rsrp_dbm: -109,
                snr_db10: 66,
            }),
            bands: vec![ActiveBand {
                radio_if: 0x08,
                band: 121,
                channel: 650,
            }],
            cell: Some(CellInfo {
                plmn: "310260".into(),
                tac: 11111,
                global_cell_id: 3_160_327,
                earfcn: 1000,
                pci: 101,
                rsrq_db10: -118,
                rsrp_dbm10: -1038,
            }),
            hist: (0..HISTORY)
                .map(|i| -95 - ((i as f32 / 6.0).sin() * 12.0) as i16)
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn renders_a_full_screen_buffer() {
        let buf = render_status(DisplayState::Recording, &Telemetry::default(), false);
        assert_eq!(buf.len(), (WIDTH * HEIGHT) as usize);
        let buf = render_log(
            DisplayState::Recording,
            &Telemetry::default(),
            false,
            0,
            None,
        );
        assert_eq!(buf.len(), (WIDTH * HEIGHT) as usize);
    }

    #[test]
    fn status_bar_takes_the_accent_colour() {
        let buf = render_status(
            DisplayState::WarningDetected {
                event_type: EventType::High,
            },
            &Telemetry::default(),
            false,
        );
        for i in 0..(WIDTH * 2) as usize {
            assert_eq!(buf[i], Color::Red.rgb());
        }
    }

    #[test]
    fn missing_vendor_fields_do_not_panic() {
        let empty: serde_json::Value = serde_json::json!({});
        assert_eq!(str_field(&empty, "nope"), None);
        assert_eq!(num_field(&empty, "nope"), None);
    }

    #[test]
    fn formats_sizes_and_durations() {
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(human_secs(3661), "01:01:01");
    }

    /// The log must record a change only when the cell actually changes, and
    /// must not treat a failed poll (everything absent) as a change.
    #[test]
    fn log_records_only_real_cell_changes() {
        let mut t = sample();
        t.observe();
        assert_eq!(t.log.len(), 1, "first sighting is a change");
        t.observe();
        assert_eq!(t.log.len(), 1, "unchanged cell must not re-log");

        // Identity now comes from QMI, so a change has to be driven there --
        // the vendor's PCI field is not consulted at all.
        if let Some(c) = t.cell.as_mut() {
            c.pci = 214;
        }
        t.observe();
        assert_eq!(t.log.len(), 2, "a PCI change is a change");

        if let Some(c) = t.cell.as_mut() {
            c.global_cell_id = 9_000_000;
        }
        t.observe();
        assert_eq!(t.log.len(), 3, "an ECI change is a change");

        if let Some(c) = t.cell.as_mut() {
            c.tac = 22222;
        }
        t.observe();
        assert_eq!(t.log.len(), 4, "a TAC change is a change");

        t.bands = vec![ActiveBand {
            radio_if: 0x08,
            band: 131,
            channel: 1050,
        }];
        t.observe();
        assert_eq!(t.log.len(), 5, "a band change is a change");
        assert_eq!(t.log.last().unwrap().cell.band.as_deref(), Some("LTE B12"));
        assert_eq!(t.log.last().unwrap().rsrp_dbm, Some(-109));
    }

    #[test]
    fn empty_readings_are_not_a_cell_change() {
        let mut t = Telemetry::default();
        t.observe();
        t.observe();
        assert!(t.log.is_empty(), "a failed poll is not a cell change");
    }

    #[test]
    fn log_is_bounded() {
        let mut t = sample();
        for i in 0..(LOG_LEN * 3) {
            if let Some(c) = t.cell.as_mut() {
                c.pci = i as u16;
            }
            t.observe();
        }
        assert_eq!(t.log.len(), LOG_LEN);
    }

    /// The band shown must come from QMI, not the vendor badge. The sample has
    /// the vendor claiming 5G/n8 while QMI reports LTE band 2.
    #[test]
    fn cell_id_prefers_qmi_over_the_vendor_badge() {
        let t = sample();
        let id = t.cell_id();
        assert_eq!(id.band.as_deref(), Some("LTE B2"));
    }

    /// The vendor reported PCI 0 while the modem was on a nonzero PCI. Identity must come
    /// from QMI and the vendor field must not be able to influence it.
    #[test]
    fn vendor_pci_is_ignored_entirely() {
        let t = sample();
        let id = t.cell_id();
        assert_eq!(id.pci, Some(101), "PCI must come from QMI, not the vendor");
        assert_eq!(id.eci, Some(3_160_327));
        assert_eq!(id.tac, Some(11111));
        assert_eq!(
            id.channel,
            Some(1000),
            "EARFCN must come from the cell info"
        );

        // The label must carry QMI's channel and PCI, not the vendor's.
        assert_eq!(id.label(), "LTE B2 E1000 P101");
    }

    #[test]
    fn egg_is_magenta_with_dark_text() {
        let buf = render_egg();
        assert_eq!(buf.len(), (WIDTH * HEIGHT) as usize);
        let magenta = buf.iter().filter(|p| **p == (252, 0, 252)).count();
        let dark = buf.iter().filter(|p| **p == (0, 0, 0)).count();
        assert!(magenta > 60_000, "should be mostly magenta, got {magenta}");
        assert!(dark > 500, "text should be legible, got {dark} dark px");
    }

    /// Render a populated panel to a PNG so the layout can be eyeballed without
    /// flashing a device. Ignored by default; run with
    /// `cargo test -p rayhunter-daemon dump_panel_preview -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_panel_preview() {
        let mut t = sample();
        for (i, pci) in [252u16, 214, 41, 88].iter().enumerate() {
            if let Some(c) = t.cell.as_mut() {
                c.pci = *pci;
                c.global_cell_id = 3_160_327 + i as u32 * 256;
            }
            t.sig = t.sig.map(|mut s| {
                s.rsrp_dbm = -96 - (i as i16 * 7);
                s
            });
            t.observe();
        }
        let save = |buf: Vec<(u8, u8, u8)>, name: &str| {
            let mut img = image::RgbImage::new(WIDTH, HEIGHT);
            for (i, (r, g, b)) in buf.iter().enumerate() {
                img.put_pixel(i as u32 % WIDTH, i as u32 / WIDTH, image::Rgb([*r, *g, *b]));
            }
            let path = std::env::temp_dir().join(name);
            img.save(&path).unwrap();
            println!("wrote {}", path.display());
        };
        save(
            render_status(DisplayState::Recording, &t, false),
            "m2100-panel-preview.png",
        );
        save(
            render_log(DisplayState::Recording, &t, false, 0, None),
            "m2100-log-preview.png",
        );
        save(render_egg(), "m2100-egg-preview.png");
    }

    // ---- 2026-10-02: scrollable log, known towers, alert marking ----------

    fn change(min: u32, eci: u32, new_tower: bool) -> CellChange {
        use chrono::TimeZone;
        CellChange {
            at: chrono::Local
                .with_ymd_and_hms(2026, 10, 2, 14, min, 0)
                .unwrap(),
            cell: CellId {
                eci: Some(eci),
                ..CellId::default()
            },
            rsrp_dbm: None,
            new_tower,
        }
    }

    #[test]
    fn an_alert_marks_the_cell_that_was_serving_when_it_fired() {
        use chrono::TimeZone;
        let log = vec![
            change(0, 1 << 8, false),
            change(10, 2 << 8, false),
            change(20, 3 << 8, false),
        ];
        let at = |m| {
            chrono::Local
                .with_ymd_and_hms(2026, 10, 2, 14, m, 30)
                .unwrap()
        };
        assert_eq!(
            alert_row(&log, None, at(12)),
            Some(1),
            "fired while the 14:10 cell served"
        );
        assert_eq!(
            alert_row(&log, None, at(25)),
            Some(2),
            "after the last change: the current cell"
        );
        let before = chrono::Local
            .with_ymd_and_hms(2026, 10, 2, 13, 0, 0)
            .unwrap();
        assert_eq!(
            alert_row(&log, None, before),
            None,
            "older than anything kept"
        );
    }

    #[test]
    fn a_boot_alert_stamped_1970_still_marks_its_cell() {
        use chrono::TimeZone;
        let log = vec![
            change(0, 1 << 8, false),
            change(10, 2 << 8, false),
            change(20, 1 << 8, false),
        ];
        let unsynced = chrono::Local
            .with_ymd_and_hms(1970, 1, 9, 22, 39, 37)
            .unwrap();
        assert_eq!(
            alert_row(&log, Some(1 << 8), unsynced),
            Some(2),
            "newest row for that cell"
        );
        assert_eq!(
            alert_row(&log, Some(9 << 8), unsynced),
            None,
            "unknown cell, no plausible time"
        );
    }

    #[test]
    fn scrolling_never_runs_past_the_last_page() {
        assert_eq!(clamp_scroll(0, 3), 0, "a short log never scrolls");
        assert_eq!(clamp_scroll(50, 3), 0);
        assert_eq!(clamp_scroll(5, 100), 5);
        assert_eq!(clamp_scroll(500, 100), 100 - LOG_VISIBLE);
    }

    #[test]
    fn a_tower_is_new_once_and_remembered_across_restarts() {
        let path = std::env::temp_dir().join(format!("known-towers-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().unwrap();
        let mut k = KnownTowers::load(p);
        assert!(k.sighted(10001), "first sighting is new");
        assert!(!k.sighted(10001), "second is not");
        assert!(k.sighted(10002));
        let mut again = KnownTowers::load(p);
        assert_eq!(again.len(), 2, "persisted to disk");
        assert!(!again.sighted(10001), "still known after a reload");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn junk_in_the_known_towers_file_is_ignored() {
        let path = std::env::temp_dir().join(format!("known-junk-{}.txt", std::process::id()));
        std::fs::write(&path, "10001\nnot a number\n\n 10002 \n").unwrap();
        assert_eq!(KnownTowers::load(path.to_str().unwrap()).len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_header_counts_every_change_not_just_the_kept_ones() {
        let mut t = Telemetry::default();
        for i in 0..(LOG_LEN as u32 + 20) {
            t.cell = Some(CellInfo {
                plmn: "310260".into(),
                tac: 1,
                global_cell_id: (i + 1) << 8,
                earfcn: 650,
                pci: 1,
                rsrq_db10: 0,
                rsrp_dbm10: 0,
            });
            t.observe();
        }
        assert_eq!(t.log.len(), LOG_LEN, "the log is capped");
        assert_eq!(t.total_changes, LOG_LEN as u64 + 20, "the total is not");
        assert!(
            t.log.iter().all(|e| e.new_tower),
            "every eNodeB here is distinct"
        );
    }

    use crate::display::m2100_enrol::{Fail, Stage, Target};

    #[test]
    fn the_enrolment_screen_shows_a_count_and_never_the_moves() {
        let a = render_enrol(Target::Gesture, &Stage::First, 3);
        let b = render_enrol(Target::Gesture, &Stage::First, 3);
        assert_eq!(a, b, "same count, same pixels: nothing about which moves");
        let c = render_enrol(Target::Gesture, &Stage::First, 4);
        assert_ne!(a, c, "the count is shown");
        assert_eq!(a.len(), (WIDTH * HEIGHT) as usize);
    }

    #[test]
    fn every_failure_has_its_own_screen() {
        let shots: Vec<_> = [
            Fail::TooShort,
            Fail::TooLong,
            Fail::TooSimple,
            Fail::Mismatch,
            Fail::WrongCurrent,
            Fail::TimedOut,
        ]
        .iter()
        .map(|f| render_enrol(Target::Gesture, &Stage::Failed(*f), 0))
        .collect();
        for i in 0..shots.len() {
            for j in i + 1..shots.len() {
                assert_ne!(shots[i], shots[j], "failures {i} and {j} look identical");
            }
        }
    }
}
