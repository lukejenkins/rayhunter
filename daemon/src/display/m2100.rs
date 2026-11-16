//! Display support for the Inseego MiFi M2100 5G UW.
//!
//! The M2100 has a 320x240 framebuffer at `/dev/fb0`, but writes to it never
//! reach the panel: `write()` and `mmap` + `msync` both change the buffer with
//! no visible effect, `FBIOPAN_DISPLAY` fails with EINVAL (`yres_virtual ==
//! yres`, so there is no back buffer to flip), and tracing the vendor Qt UI
//! shows it issuing no ioctl at all -- it writes to its mmap, so there is no
//! commit path to replicate. See FINDINGS.md.
//!
//! So this signals through the two indicators the device does expose: a single
//! LED and a PWM buzzer.
//!
//!   Recording        one brief LED blink every 3s, silent
//!   Paused           dark, silent
//!   WarningDetected  LED double-blink, repeating; buzzer only if enabled
//!
//! ## Why the buzzer is off by default
//!
//! An audible alert in public tells everyone nearby that something was
//! detected -- including, potentially, whoever is operating the thing you just
//! detected. It also points at you. The quiet channels are the LED (a blinking
//! light on a hotspot is unremarkable) and `ntfy_url`, which reaches a phone
//! silently. The buzzer is for when you are somewhere private.
//!
//! Nothing here uses Morse. SOS is the one pattern a bystander might actually
//! recognise, and you already know what your own device means, so it costs
//! deniability and buys nothing.
//!
//! Double-tapping the power button toggles the buzzer at runtime; the state
//! persists via a flag file so it survives a restart.
//!
//! ## Buzzer quirks, both confirmed on hardware
//!
//!   * Writing 1 to `control` returns EIO but *does* take effect -- the buzzer
//!     sounds and `control` subsequently reads 1. The error is spurious.
//!   * Writing 0 to `control` returns EIO and does *not* take effect. Writing 0
//!     to `period` is the only reliable way to silence it.
//!   * The transducer is a piezo with a resonant peak near **4.4 kHz**. Pitch is
//!     freely settable (`period` is the raw PWM period in ns, so
//!     `freq = 1e9 / period`), but loudness is not: tones far from resonance are
//!     much quieter, and there is no `duty_cycle` attribute, so there is no
//!     volume control at all. Keep alert tones in roughly 3.8-4.6 kHz.
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use log::{info, warn};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use rayhunter::analysis::analyzer::EventType;

use crate::config::{self, UiLevel};
use crate::display::DisplayState;

const LED: &str = "/sys/class/leds/blue-led";
const ON: &str = "255";
const OFF: &str = "0";

const BUZZER: &str = "/sys/devices/platform/soc:pwm_buzzer";
/// Set when the buzzer is enabled, so the choice survives a restart.
const BUZZER_FLAG: &str = "/data/rayhunter/buzzer_enabled";

const INPUT_DEV: &str = "/dev/input/event0";
/// Two 16-byte `input_event` structs per read on 32-bit ARM (the key event and
/// its EV_SYN); the first event's value lands at offset 12.
const INPUT_EVENT_SIZE: usize = 32;

static BUZZER_ON: AtomicBool = AtomicBool::new(false);

/// PWM period in nanoseconds, by severity, so an alert is identifiable by ear:
/// higher pitch = more urgent.
///
/// All three sit inside the transducer's resonant band. Measured by sweeping
/// 100 Hz - 10 kHz and listening: output peaks around **4.4 kHz** and falls off
/// audibly above 5 kHz and below about 4 kHz -- an ordinary piezo response.
/// An earlier octave-spaced scheme (1 / 2 / 4 kHz) put only the High tone on
/// resonance, so the *least* urgent alert was also the quietest and easiest to
/// sleep through. 3.8 / 4.2 / 4.6 kHz are all near peak loudness and were
/// confirmed by ear to still be distinguishable from each other, including
/// which direction the sequence moves.
///
/// 263_158 ns = 3.8 kHz, 238_095 = 4.2 kHz, 217_391 = 4.6 kHz.
fn buzzer_period_ns(event_type: EventType) -> &'static str {
    match event_type {
        EventType::Informational | EventType::Low => "263158",
        EventType::Medium => "238095",
        EventType::High => "217391",
    }
}

async fn write_led(file: &str, value: &str) {
    let path = format!("{LED}/{file}");
    if let Err(e) = tokio::fs::write(&path, value).await {
        warn!("failed writing {path}: {e}");
    }
}

/// Writes to the buzzer, tolerating the driver's spurious EIO on `control`.
async fn write_buzzer(file: &str, value: &str) {
    let path = format!("{BUZZER}/{file}");
    if let Err(e) = tokio::fs::write(&path, value).await {
        if e.raw_os_error() != Some(5) {
            warn!("failed writing {path}: {e}");
        }
    }
}

/// Play (sounding, ms) steps if the user has the buzzer enabled. Enrolment
/// feedback. Reads the setting's file, not `BUZZER_ON`: that flag is only loaded
/// on the invisible-UI path, so in LiveStatus it would always read "off".
pub async fn play_chirps(steps: &[(bool, u64)]) {
    if !buzzer_enabled() {
        return;
    }
    for (on, ms) in steps {
        // 4.2 kHz: the middle of the transducer's measured resonance band.
        buzzer(*on, "238095").await;
        tokio::time::sleep(Duration::from_millis(*ms)).await;
    }
    buzzer(false, "0").await;
}

/// Whether the buzzer is on. The file is the setting, shared by every display
/// mode: the double-tap toggle here and the settings row in LiveStatus.
pub fn buzzer_enabled() -> bool {
    std::path::Path::new(BUZZER_FLAG).exists()
}

/// Turn the buzzer on or off, persisted so it survives a restart. Turning it on
/// confirms with one short chirp; turning it off is silent by definition.
pub async fn set_buzzer_enabled(on: bool) {
    BUZZER_ON.store(on, Ordering::Relaxed);
    if on {
        let _ = tokio::fs::write(BUZZER_FLAG, b"1").await;
        info!("buzzer enabled");
        buzzer(true, "238095").await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        buzzer(false, "0").await;
    } else {
        let _ = tokio::fs::remove_file(BUZZER_FLAG).await;
        info!("buzzer disabled");
    }
}

/// Three short pulses at the severity's pitch, for a new detection in
/// LiveStatus, if the buzzer is on. Rhythm carries through a bag better than
/// pitch does; the pitch still says how serious (see `buzzer_period_ns`).
pub async fn play_alert(event_type: EventType) {
    if !buzzer_enabled() {
        return;
    }
    let period = buzzer_period_ns(event_type);
    for _ in 0..3 {
        buzzer(true, period).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        buzzer(false, "0").await;
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

async fn buzzer(on: bool, period_ns: &str) {
    if on {
        write_buzzer("period", period_ns).await;
        write_buzzer("control", "1").await;
    } else {
        // control=0 returns EIO and leaves it sounding; period=0 works.
        write_buzzer("period", "0").await;
    }
}

/// A pattern is a list of (lit, duration_ms) steps, played in a loop.
/// The warning pattern is a double-blink: distinguishable at a glance from the
/// recording heartbeat, but not conspicuous to anyone else.
fn pattern_for(state: &DisplayState) -> Vec<(bool, u64)> {
    match state {
        DisplayState::Paused => vec![(false, 1000)],
        DisplayState::Recording => vec![(true, 60), (false, 3000)],
        DisplayState::WarningDetected { .. } => {
            vec![(true, 120), (false, 140), (true, 120), (false, 1200)]
        }
    }
}

/// Watches the power button and toggles the buzzer on a double tap.
/// evdev broadcasts, so reading here does not take the button away from the
/// vendor UI or from rayhunter's own key_input service.
fn spawn_buzzer_toggle(task_tracker: &TaskTracker, shutdown_token: CancellationToken) {
    task_tracker.spawn(async move {
        let mut file = match tokio::fs::File::open(INPUT_DEV).await {
            Ok(f) => f,
            Err(e) => {
                warn!("buzzer toggle disabled, cannot open {INPUT_DEV}: {e}");
                return;
            }
        };

        let mut buf = [0u8; INPUT_EVENT_SIZE];
        let mut last_keyup: Option<Instant> = None;
        let mut last_event: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => return,
                r = file.read_exact(&mut buf) => {
                    if r.is_err() {
                        return;
                    }
                }
            }

            let now = Instant::now();
            // The power button can emit bursts of events; ignore the repeats.
            if let Some(prev) = last_event
                && now.duration_since(prev) < Duration::from_millis(50)
            {
                last_event = Some(now);
                continue;
            }
            last_event = Some(now);

            // value == 0 is key-up
            if buf[12] != 0 {
                continue;
            }

            if let Some(prev) = last_keyup {
                let gap = now.duration_since(prev);
                if gap >= Duration::from_millis(100) && gap <= Duration::from_millis(800) {
                    // Turning it off is silent by definition, so the LED is the
                    // only feedback there.
                    info!("buzzer toggled (double tap)");
                    set_buzzer_enabled(!BUZZER_ON.load(Ordering::Relaxed)).await;
                    last_keyup = None;
                    continue;
                }
            }
            last_keyup = Some(now);
        }
    });
}

pub fn update_ui(
    task_tracker: &TaskTracker,
    config: &config::Config,
    shutdown_token: CancellationToken,
    mut ui_update_rx: Receiver<DisplayState>,
) {
    if config.ui_level == UiLevel::Invisible {
        info!("Invisible mode, not spawning LED UI.");
        task_tracker.spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => break,
                    _ = ui_update_rx.recv() => {}
                }
            }
        });
        return;
    }

    let buzzer_enabled = std::path::Path::new(BUZZER_FLAG).exists();
    BUZZER_ON.store(buzzer_enabled, Ordering::Relaxed);
    info!(
        "Starting M2100 LED UI on {LED} (buzzer {}; double-tap power to toggle)",
        if buzzer_enabled { "enabled" } else { "off" }
    );

    spawn_buzzer_toggle(task_tracker, shutdown_token.clone());

    task_tracker.spawn(async move {
        // Take the LED away from whatever trigger owns it (normally "timer").
        write_led("trigger", "none").await;

        let mut state = DisplayState::Recording;
        'outer: loop {
            let tone = match state {
                DisplayState::WarningDetected { event_type } => Some(buzzer_period_ns(event_type)),
                _ => None,
            };
            for (lit, ms) in pattern_for(&state) {
                write_led("brightness", if lit { ON } else { OFF }).await;
                if let Some(period) = tone
                    && BUZZER_ON.load(Ordering::Relaxed)
                {
                    buzzer(lit, period).await;
                }
                tokio::select! {
                    _ = shutdown_token.cancelled() => break 'outer,
                    next = ui_update_rx.recv() => {
                        match next {
                            Some(s) => { state = s; continue 'outer; }
                            None => break 'outer,
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(ms)) => {}
                }
            }
        }

        buzzer(false, "0").await;
        write_led("brightness", OFF).await;
        write_led("trigger", "timer").await;
    });
}
