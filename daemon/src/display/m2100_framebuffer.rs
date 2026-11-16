//! Framebuffer backend for the Inseego M2100's 320x240 colour panel.
//!
//! This panel is **not** on the stock MSM display pipeline. It is driven by a
//! vendor kernel driver (`nvtl_lcd`, `/sys/devices/platform/1b22000.lcd`), and
//! `/dev/fb0` is only a staging buffer: writing to it changes memory and
//! nothing reaches the glass until a transfer is triggered.
//!
//! The trigger is a vendor-private ioctl that appears in no public header:
//!
//! ```text
//! _IOC(dir = _IOC_NONE, type = 0x99, nr = 0x99, size = 0) == 0x9999
//! ```
//!
//! Despite encoding size 0 it takes the update rectangle as its argument;
//! passing a zeroed or null argument returns EINVAL. Found by stracing the
//! vendor's own panel test tool, `/opt/nvtl/bin/tests/lcdfbtest`. Every
//! *documented* commit ioctl (MSMFB_DISPLAY_COMMIT, FBIORECT_DISPLAY,
//! FBIOPAN_DISPLAY, FBIO_WAITFORVSYNC) is either accepted and inert here, or
//! rejected outright.
//!
//! Pixel format, from FBIOGET_VSCREENINFO: 18 bpp RGB666, stride 960,
//! `red.offset = 12, green.offset = 6, blue.offset = 0`, packed big-endian
//! across three bytes. 320 * 240 * 3 = 230,400 bytes.
//!
//! Panel power is `/opt/nvtl/devices/lcd/on` (writing 1 lights it). Note that
//! the fbdev route, `/sys/class/graphics/fb0/blank`, returns EINVAL for every
//! value and is not usable.

use async_trait::async_trait;
use image::{DynamicImage, imageops::FilterType};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::config::UiLevel;
use crate::display::DisplayState;
use crate::display::generic_framebuffer::{self, Dimensions, GenericFramebuffer};

use tokio::sync::mpsc::Receiver;
use tokio_util::task::TaskTracker;

const FB_PATH: &str = "/dev/fb0";
const LCD_ON: &str = "/opt/nvtl/devices/lcd/on";

const WIDTH: u32 = 320;
const HEIGHT: u32 = 240;

/// Vendor-private "transfer framebuffer to panel" ioctl. See module docs.
/// NOTE: `libc::ioctl`'s request argument is `c_ulong` on glibc but `c_int` on
/// musl/ARM, so this is cast with `as _` at the call site rather than typed here.
const NVTL_LCD_COMMIT: u32 = 0x9999;

/// The vendor UI's SysV init script, which supports start/stop/restart/status.
const DEVUI_INIT: &str = "/etc/rc3.d/S50devui3";

#[repr(C)]
struct NvtlLcdRect {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

pub struct Framebuffer {
    /// False = the vendor UI owns the panel and we do not draw at all.
    /// Always starts false, so a device that is power-cycled comes up stock.
    visible: Arc<AtomicBool>,
    /// Whether we drew on the previous tick, so transitions can be detected.
    painting: bool,
}

/// Hand the panel back by restarting the vendor's Qt UI.
///
/// `devuiappd` is a Qt5 application on the `linuxfb` platform plugin, and Qt
/// only repaints regions it considers dirty. Once Rayhunter has drawn over it,
/// it never repaints that area again: measured on hardware, it does not redraw
/// on a power-button wake, on a touch, or on any other event, even though it
/// holds all three input devices open. The panel simply keeps Rayhunter's frame.
///
/// Replaying a captured vendor frame was tried first and is worse. It restores a
/// still image with stale signal bars and battery, and because the capture is
/// taken when Rayhunter takes the panel, a daemon restart while Rayhunter was
/// showing captures *Rayhunter's own output* as the supposed stock frame --
/// which then gets faithfully replayed as the "vendor" UI. Restarting the
/// process makes Qt redraw the whole UI, live.
///
/// `setsid` is required: the init script backgrounds the app with a bare `&`, so
/// without a fresh session it takes SIGHUP when the spawning shell exits and
/// dies part-drawn, leaving a frozen splash on the panel.
/// Longest the display path may block on a helper process.
const VENDOR_CMD_TIMEOUT: Duration = Duration::from_secs(6);

/// Run `setsid <args>` with a hard ceiling on how long it may block.
///
/// These run on the display path, so an unbounded wait freezes the panel.
/// Observed on hardware: a restart issued moments after `adbd` was killed never
/// returned, and the display loop sat in it until the device was power-cycled.
/// The screen stopped updating and gestures looked dead, because the watcher
/// was still firing but nothing was left to act on them.
async fn run_bounded(args: &[&str]) -> Result<std::process::ExitStatus, std::io::Error> {
    let child = tokio::process::Command::new("setsid")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match tokio::time::timeout(VENDOR_CMD_TIMEOUT, child).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("setsid {args:?} exceeded {VENDOR_CMD_TIMEOUT:?}"),
        )),
    }
}

/// Stop the vendor UI while Rayhunter owns the panel.
///
/// `devuiappd` reads the same digitiser we do, and its own controls sit under
/// our reveal corner -- the stock home screen puts `Help` at the bottom right,
/// exactly where the gesture lands. Left running, it reacts to that touch,
/// navigates, and repaints over whatever Rayhunter has drawn. Since the panel
/// is handed back by restarting it anyway, stopping it here costs nothing.
async fn stop_vendor_ui() {
    let result = run_bounded(&[DEVUI_INIT, "stop"]).await;

    match result {
        Ok(s) if s.success() => log::info!("m2100 display: vendor UI stopped"),
        Ok(s) => log::warn!("m2100 display: vendor UI stop exited with {s}"),
        Err(e) => log::warn!("m2100 display: couldn't stop the vendor UI: {e}"),
    }
}

async fn restore_vendor_ui() {
    let result = run_bounded(&[DEVUI_INIT, "restart"]).await;

    match result {
        Ok(s) if s.success() => {
            log::info!("m2100 display: handed the panel back to the vendor UI")
        }
        Ok(s) => log::warn!("m2100 display: vendor UI restart exited with {s}"),
        Err(e) => log::warn!("m2100 display: couldn't restart the vendor UI: {e}"),
    }
}

/// Transfer `rows` of the staging buffer to the panel. Nothing is visible until
/// this runs; see the module docs for how the ioctl was found.
fn commit(f: &tokio::fs::File, rows: u32) {
    let mut rect = NvtlLcdRect {
        x: 0,
        y: 0,
        w: WIDTH,
        h: rows,
    };
    let res = unsafe { libc::ioctl(f.as_raw_fd(), NVTL_LCD_COMMIT as _, &mut rect as *mut _) };
    if res < 0 {
        log::warn!(
            "m2100 framebuffer: commit ioctl 0x{NVTL_LCD_COMMIT:04x} failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[async_trait]
impl GenericFramebuffer for Framebuffer {
    fn dimensions(&self) -> Dimensions {
        Dimensions {
            height: HEIGHT,
            width: WIDTH,
        }
    }

    /// Scale an image to the panel and centre it on a full-screen black canvas.
    ///
    /// The generic implementation only ever *shrinks*: an asset already smaller
    /// than the display is passed through at its native size. Because every
    /// `write_buffer` here is a linear write at a fixed 320px stride, a 128px-wide
    /// image then wraps 2.5 times per row and smears into the top 51 rows.
    /// (`eff.png` is 128x128, so this hits the stock EFF-logo UI level.)
    ///
    /// Scaling up as well as down, then padding to the full frame, also clears
    /// whatever was on the panel before instead of leaving it around the edges.
    fn prepare_image(&self, img: DynamicImage) -> Vec<(u8, u8, u8)> {
        // `resize` preserves aspect ratio and fits within the bounds, scaling
        // in either direction.
        let scaled = img.resize(WIDTH, HEIGHT, FilterType::CatmullRom);
        let (iw, ih) = (scaled.width(), scaled.height());
        let rgba = scaled.to_rgba8();

        let ox = (WIDTH - iw) / 2;
        let oy = (HEIGHT - ih) / 2;

        let mut buf = vec![(0u8, 0u8, 0u8); (WIDTH * HEIGHT) as usize];
        for y in 0..ih {
            for x in 0..iw {
                let px = rgba.get_pixel(x, y);
                buf[((y + oy) * WIDTH + (x + ox)) as usize] = (px[0], px[1], px[2]);
            }
        }
        buf
    }

    async fn write_buffer(&mut self, buffer: Vec<(u8, u8, u8)>) {
        // Stealth gate. While the vendor UI owns the panel we draw nothing at
        // all, so the device is visually indistinguishable from stock.
        if !self.visible.load(Ordering::Relaxed) {
            if self.painting {
                self.painting = false;
                restore_vendor_ui().await;
            }
            return;
        }
        if !self.painting {
            self.painting = true;
            stop_vendor_ui().await;
            log::info!("m2100 display: Rayhunter UI has the panel");
        }

        // Make sure the panel is powered before we bother transferring.
        // Best-effort: this node is vendor-specific and absent on other devices.
        let _ = tokio::fs::write(LCD_ON, b"1").await;

        let buffer_px = buffer.len();
        let mut raw = Vec::with_capacity(buffer_px * 3);
        for (r, g, b) in buffer {
            // 8 bits per channel down to 6, packed red<<12 | green<<6 | blue.
            let v: u32 = ((r as u32 >> 2) << 12) | ((g as u32 >> 2) << 6) | (b as u32 >> 2);
            // 18 bits written big-endian across three bytes.
            raw.push(((v >> 16) & 0xff) as u8);
            raw.push(((v >> 8) & 0xff) as u8);
            raw.push((v & 0xff) as u8);
        }

        let mut f = match OpenOptions::new().write(true).open(FB_PATH).await {
            Ok(f) => f,
            Err(e) => {
                log::warn!("m2100 framebuffer: couldn't open {FB_PATH}: {e}");
                return;
            }
        };

        if let Err(e) = f.write_all(&raw).await {
            log::warn!("m2100 framebuffer: write failed: {e}");
            return;
        }

        // Callers may hand us a partial frame drawn from the top-left -- the
        // status bar is `width x 2`. Commit only the rows we actually wrote so
        // we don't re-transfer (and re-latch) stale pixels below them.
        let rows = ((buffer_px as u32).div_ceil(WIDTH)).min(HEIGHT);
        if rows == 0 {
            return;
        }

        commit(&f, rows);
    }
}

pub fn update_ui(
    task_tracker: &TaskTracker,
    config: &config::Config,
    shutdown_token: CancellationToken,
    ui_update_rx: Receiver<DisplayState>,
) {
    // Always boot showing the vendor UI: a device that is seized and power
    // cycled must come up looking factory-stock.
    let visible = Arc::new(AtomicBool::new(false));

    // On shutdown, hand the panel back. Without this, stopping the daemon while
    // Rayhunter owned the panel strands Rayhunter's last frame on the glass --
    // and restarting does not clear it, because stock mode deliberately never
    // draws. Only gated on `visible` so a shutdown in stock mode does not
    // needlessly restart a vendor UI that is already fine.
    let was_visible = visible.clone();
    let shutdown_for_restore = shutdown_token.clone();
    task_tracker.spawn(async move {
        shutdown_for_restore.cancelled().await;
        if was_visible.load(Ordering::Relaxed) {
            restore_vendor_ui().await;
        }
    });

    let fb = Framebuffer {
        visible: visible.clone(),
        painting: false,
    };

    // LiveStatus hands the device its own display loop: touch-selected modes,
    // live data and an on-screen control, none of which the shared loop models.
    // It still writes through this `Framebuffer`, so the stealth gate and the
    // vendor hand-back apply to it unchanged.
    if config.ui_level == UiLevel::LiveStatus {
        // m2100_ui owns the gesture watcher in this mode, because its gestures
        // select a mode as well as toggling visibility. It must drive the *same*
        // `visible` flag this Framebuffer gates on -- two flags means a corner
        // can switch mode while the gate stays shut and nothing is drawn.
        return crate::display::m2100_ui::update_ui(
            task_tracker,
            config,
            fb,
            visible,
            shutdown_token,
            ui_update_rx,
        );
    }

    // Nothing reveals the panel in these display modes: it stays stock. The
    // per-device reveal gesture lives in m2100_ui (LiveStatus).
    generic_framebuffer::update_ui(task_tracker, config, fb, shutdown_token, ui_update_rx)
}
