//! The M2100's display loop.
//!
//! This replaces `generic_framebuffer::update_ui` for this device, because the
//! M2100's display behaves differently in three ways that do not generalise:
//! it is stealth-gated (the vendor UI owns the panel until revealed), its mode
//! is chosen at runtime by touch rather than fixed by config, and one of its
//! modes renders live data rather than an image.
//!
//! # Gestures
//!
//! The stock screen is revealed only by this device's own gesture (see
//! `m2100_gesture` and SPEC-configurable-reveal-gesture.md), matched on release.
//! There is no default: with no stored gesture, nothing on the panel reveals.
//! Inside Rayhunter's UI, gestures are distinguished by duration:
//!
//! * **Hold a corner for 3 s** — switch to that corner's mode. Holding the
//!   corner of the mode already showing hides it again and hands the panel back
//!   to the vendor UI.
//! * **Hold the on-screen control for 1 s** — perform that mode's action
//!   (currently start/stop recording on the status panel).
//!
//! The control sits between x=100 and x=220, and corner regions are
//! `x < 80 || x >= 240`, so the two can never overlap.
//!
//! Destructive actions are deliberately absent. `delete-all-recordings` exists
//! in the daemon's API but a mis-tap on a 2.4" panel would irreversibly destroy
//! every capture on a device whose purpose is collecting them; that belongs
//! behind a keyboard.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::m2100_cli;
use super::m2100_live::{self, ProfileNote, Telemetry};
use super::m2100_panic::{self, PanicConfig};
use super::m2100_profile::{self, Profile};
use super::m2100_profile_io;
use super::m2100_siglog;
use super::m2100_signal;
use crate::config;
use crate::display::DisplayState;
use crate::display::generic_framebuffer::{Color, GenericFramebuffer, LinePattern};
use crate::display::m2100_enrol::{self, Paths};
use crate::display::m2100_gesture::{self, Matcher, Touch};
use crate::display::m2100_secret::Secret;
use rayhunter::analysis::analyzer::EventType;

const WIDTH: u32 = 320;
const HEIGHT: u32 = 240;

/// Corner hot-zone size. Generous, because it is reached by feel.
const CORNER_W: i32 = 80;
const CORNER_H: i32 = 60;

const MODE_HOLD: Duration = Duration::from_secs(3);
const ACTION_HOLD: Duration = Duration::from_secs(1);
/// Longer than the others: this one can cut off remote access to the device.
const LOCKDOWN_HOLD: Duration = Duration::from_secs(5);
/// Keep holding the EFF corner past the switch it already gave you.
const EGG_HOLD: Duration = Duration::from_secs(10);
/// Long enough to read, short enough that nobody thinks it has crashed.
const EGG_SHOW: Duration = Duration::from_secs(4);
/// How long the unlabelled state flash stays on screen.
const FLASH: Duration = Duration::from_millis(1600);
/// Hold the left edge (between the corners) this long to open settings.
const SETTINGS_HOLD: Duration = Duration::from_secs(3);
/// The settings screen closes if left untouched this long.
const SETTINGS_IDLE: Duration = Duration::from_secs(30);
/// Hold the other profile this long to switch to it.
const PROFILE_HOLD: Duration = Duration::from_secs(2);

/// A lockdown reverts itself after this long unless it is re-confirmed.
///
/// The lockdown disables ADB and the web API -- everything that could undo it
/// remotely -- leaving the touchscreen as the only way back. On hardware that
/// proved too thin a thread: the display loop blocked on a helper process and
/// the panel stopped responding, which left no route back at all short of
/// pulling the battery. A feature whose sole recovery path is the thing it
/// disables needs a floor under it.
///
/// Re-confirming (another lockdown gesture while already closed) restarts the
/// window, so a deliberately long lockdown is still possible -- it just has to
/// be intentional rather than accidental.
const LOCKDOWN_LEASE: Duration = Duration::from_secs(600);

/// Panic sequence: this many power-button presses inside [`PANIC_WINDOW`].
///
/// The power button is the right control for this. The digitiser sleeps and
/// needs waking before it reports at all, whereas `event0` is always live; and
/// using it requires no Rayhunter screen to be showing, which matters because
/// revealing the UI is the opposite of what you want in the moment you would
/// reach for this. To anyone watching it looks like someone prodding a hotspot
/// that will not wake up.
const PANIC_CLICKS: usize = 5;
const PANIC_WINDOW: Duration = Duration::from_secs(3);

/// The power button, via the PMIC's `qpnp_pon` input device.
const POWER_INPUT: &str = "/dev/input/event0";
const KEY_POWER: u16 = 116;

/// Confirmation for the panic sequence: one long LED flash, plus the vendor's
/// own startup chime when the owner's sound settings allow (`panic_chime`).
///
/// Not a Rayhunter beep: a sound of our own would announce the action to
/// everyone within earshot. The chime is a stock sound the device makes anyway,
/// so to anyone else it is the hotspot behaving normally (2026-10-08).
const LED_BRIGHTNESS: &str = "/sys/class/leds/blue-led/brightness";
const LED_TRIGGER: &str = "/sys/class/leds/blue-led/trigger";
/// Wait this long after the panic fires before glowing: the five presses toggle
/// the screen on and off, and a light that starts during that flicker is missed.
const PANIC_SETTLE: Duration = Duration::from_secs(1);
/// Then fast blinking for this long. A 3 s steady glow (2026-10-08) read like a
/// long heartbeat flash (the heartbeat is 1 s on every 5 s); fast blinks are the
/// opposite of anything the heartbeat does, and an ordinary "activity" pattern
/// for a hotspot to anyone else.
const PANIC_BLINKING: Duration = Duration::from_secs(2);
/// 5 Hz, driven by the kernel's timer trigger so the rhythm stays even while
/// the daemon is busy with the panic itself.
const PANIC_BLINK_ON: &str = "100";
const PANIC_BLINK_OFF: &str = "100";

const LED_DELAY_ON: &str = "/sys/class/leds/blue-led/delay_on";
const LED_DELAY_OFF: &str = "/sys/class/leds/blue-led/delay_off";

/// Everything needed to put the LED back exactly as it was.
#[derive(Clone, Debug, PartialEq)]
struct LedState {
    trigger: String,
    /// The vendor runs at about 75%, so restoring the trigger and delays alone
    /// gives it back at the wrong level.
    brightness: Option<String>,
    /// Only present while a trigger that blinks owns the LED. Writing the
    /// trigger file **recreates these at the kernel defaults**, so restoring
    /// the trigger name alone is not enough.
    delay_on: Option<String>,
    delay_off: Option<String>,
}

/// The LED state to hand back as "the vendor's". If what was saved is actually
/// Rayhunter's own heartbeat -- a daemon restarted without a reboot finds the LED
/// still in it -- use dark instead, which is how the vendor leaves it (measured
/// 2026-10-08). Replaying the heartbeat while locked would blink Rayhunter's 5 s
/// rhythm, the one thing that tells it apart from the vendor's.
fn vendor_from_saved(s: LedState) -> LedState {
    let ours = s.trigger == "timer"
        && s.delay_on.as_deref() == Some(LED_HB_ON)
        && s.delay_off.as_deref() == Some(LED_HB_OFF);
    if ours {
        LedState {
            trigger: "none".to_string(),
            brightness: Some("0".to_string()),
            delay_on: None,
            delay_off: None,
        }
    } else {
        s
    }
}

async fn save_led() -> Option<LedState> {
    let raw = tokio::fs::read_to_string(LED_TRIGGER).await.ok()?;
    let trigger = raw
        .split_whitespace()
        .find(|t| t.starts_with('['))
        .map(|t| t.trim_matches(['[', ']']).to_string())?;
    let read = |p: &'static str| async move {
        tokio::fs::read_to_string(p)
            .await
            .ok()
            .map(|v| v.trim().to_string())
    };
    Some(LedState {
        trigger,
        brightness: read(LED_BRIGHTNESS).await,
        delay_on: read(LED_DELAY_ON).await,
        delay_off: read(LED_DELAY_OFF).await,
    })
}

async fn restore_led(s: LedState) {
    if s.trigger == "none" {
        // It was under direct control; leave it dark rather than invent a blink.
        let _ = tokio::fs::write(LED_BRIGHTNESS, b"0").await;
        return;
    }
    let _ = tokio::fs::write(LED_TRIGGER, s.trigger.as_bytes()).await;
    // Order matters: the trigger write is what creates these files, and it
    // creates them at the kernel defaults.
    if let Some(v) = s.delay_on {
        let _ = tokio::fs::write(LED_DELAY_ON, v.as_bytes()).await;
    }
    if let Some(v) = s.delay_off {
        let _ = tokio::fs::write(LED_DELAY_OFF, v.as_bytes()).await;
    }
    if let Some(v) = s.brightness {
        let _ = tokio::fs::write(LED_BRIGHTNESS, v.as_bytes()).await;
    }
}

/// Whether a short tap should flip the orca between the swimming pod and the
/// spinning mascot.
///
/// Restricted to the SAME corner that reaches the screen, rather than anywhere
/// on it. Tap-anywhere overlapped the short centre tap that peeks at the
/// lockdown state, so one tap in the middle both swapped the orca and popped
/// the ON/OFF overlay -- two correct behaviours that read as one bug.
/// What a press at (x, y) will do if held, and for how long.
///
/// The ORDER is the safety property: a corner beats the control, and the
/// control beats the centre band. Without that, one touch could arm two things
/// -- a mode switch and an action, or an action and a lockdown. Geometry is
/// free to move as long as this order holds, so this is what the tests pin
/// rather than where the button happens to sit.
fn classify_touch(showing: bool, mode: Mode, x: i32, y: i32) -> Option<(Hold, Duration)> {
    if !showing {
        // The stock screen has no hold gestures at all. Revealing is done by
        // the per-device gesture, matched on release (see `stock_release`).
        return None;
    }
    if let Some(m) = Mode::from_corner(x, y) {
        return Some((Hold::Switch(m), MODE_HOLD));
    }
    if x < CORNER_W {
        // Left edge between the corners: a tap acknowledges an alert (edge_tap,
        // on release); a 3 s hold opens settings.
        return Some((Hold::Settings, SETTINGS_HOLD));
    }
    if mode == Mode::Status && m2100_live::hits_control(x, y) {
        return Some((Hold::Control, ACTION_HOLD));
    }
    if is_centre(x) {
        return Some((Hold::Lockdown, LOCKDOWN_HOLD));
    }
    None
}

/// A short tap on a side edge, between the corner zones.
///
/// These are the only places a quick tap means nothing else: the corners switch
/// mode on a hold, and the centre band arms the lockdown on a hold and peeks its
/// state on a tap. The edges at mid-height belong to neither, so a tap there can
/// never be half of another gesture.
#[derive(Clone, Copy, PartialEq, Debug)]
enum EdgeTap {
    /// Acknowledge the alert banner (any mode).
    Left,
    /// Cell log: scroll toward the newest.
    RightUpper,
    /// Cell log: scroll toward older entries.
    RightLower,
}

fn edge_tap(x: i32, y: i32) -> Option<EdgeTap> {
    if Mode::from_corner(x, y).is_some() || is_centre(x) {
        return None;
    }
    if x < CORNER_W {
        return Some(EdgeTap::Left);
    }
    if y < HEIGHT as i32 / 2 {
        Some(EdgeTap::RightUpper)
    } else {
        Some(EdgeTap::RightLower)
    }
}

/// Entries moved per scroll tap: most of a screen, so a day's log is a few taps.
const SCROLL_STEP: usize = m2100_live::LOG_VISIBLE - 1;

fn taps_orca_toggle(mode: Mode, x: i32, y: i32) -> bool {
    mode == Mode::Orca && Mode::from_corner(x, y) == Some(Mode::Orca)
}

/// Rayhunter's heartbeat: full brightness on a 5s cycle.
///
/// The interval is the whole signal. The vendor flashes on 6s, so the two are
/// told apart by counting rather than by remembering a colour or a shape --
/// which is the only comparison available on a device with one LED.
const LED_HB_ON: &str = "1000";
const LED_HB_OFF: &str = "4000";
const LED_HB_BRIGHTNESS: &str = "255";

/// Which pattern the LED should be showing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Led {
    Vendor,
    Heartbeat,
}

/// The LED answers exactly one question at a glance: is Rayhunter running?
///
/// It deliberately ignores the screen. The vendor's pattern honours screen
/// state and so vanishes while the panel sleeps, which is precisely when a
/// status light earns its keep. This one runs regardless.
///
/// A panic lockdown hands the LED back: the point of panic is that the device
/// gives nothing away, and a light still announcing "recording" would undo it.
fn led_for(locked: bool, state: DisplayState) -> Led {
    if locked || matches!(state, DisplayState::Paused) {
        Led::Vendor
    } else {
        Led::Heartbeat
    }
}

/// Drive the LED to `want`, writing only what actually differs.
///
/// `devuid` owns this LED too and reasserts its own pattern whenever the screen
/// changes, so this is called every tick to win that argument. Reading first
/// keeps it from becoming a write storm: in the steady state nothing is
/// written at all.
async fn ensure_led(want: Led, vendor: &Option<LedState>) {
    let set = |p: &'static str, v: String| async move {
        if read_back(p).await.as_deref() != Some(v.as_str()) {
            let _ = tokio::fs::write(p, v.as_bytes()).await;
        }
    };
    match want {
        Led::Heartbeat => {
            // Order matters: writing `trigger` recreates delay_on/delay_off at
            // the kernel defaults, so it has to come first.
            if read_back(LED_TRIGGER)
                .await
                .as_deref()
                .map(|t| t.contains("[timer]"))
                != Some(true)
            {
                let _ = tokio::fs::write(LED_TRIGGER, b"timer").await;
            }
            set(LED_DELAY_ON, LED_HB_ON.to_string()).await;
            set(LED_DELAY_OFF, LED_HB_OFF.to_string()).await;
            set(LED_BRIGHTNESS, LED_HB_BRIGHTNESS.to_string()).await;
        }
        Led::Vendor => {
            if let Some(v) = vendor {
                restore_led(v.clone()).await;
            }
        }
    }
}

/// Current value of a sysfs LED attribute, trimmed.
async fn read_back(path: &'static str) -> Option<String> {
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .map(|v| v.trim().to_string())
}

/// One long flash to confirm, then put the LED back exactly as it was found.
///
/// Two wrong versions preceded this, both from assuming the LED has a fixed
/// stock state. It does not. `devuiappd` owns it and drives it dynamically:
/// observed at `none`/0 immediately after a vendor-UI restart and at
/// `timer`/255 a while later on the same unmodified device.
///
/// So there is nothing correct to write. The first version handed the LED to
/// the kernel `timer` trigger and produced a 500 ms blink that was noticed on
/// hardware as "a sequence I hadn't seen before" -- the feature meant to remove
/// tells being the only thing producing one. The second left it dark, which is
/// equally wrong whenever the vendor had it blinking.
///
/// Saving and restoring whatever was there is the only version that cannot
/// introduce an anomaly, whatever state the vendor happens to be in.
///
/// Measured on this device, the vendor runs `timer` with `delay_on = 1000` and
/// `delay_off = 5000` -- one one-second flash every six seconds. Cycling the
/// trigger resets those to 500/500, which is the rapid blink that was spotted
/// on hardware as an unfamiliar pattern. The delays, not the trigger name, were
/// the real casualty.
async fn panic_led_blink() {
    // Hold the LED for the whole signal: the render loop leaves it alone while a
    // cue plays, so it can't take it back halfway through.
    CUE_PLAYING.store(true, Ordering::Release);
    tokio::time::sleep(PANIC_SETTLE).await;
    // Order matters: writing the trigger recreates delay_on/delay_off at the
    // kernel defaults, so set the delays after it.
    if tokio::fs::write(LED_TRIGGER, b"timer").await.is_ok() {
        let _ = tokio::fs::write(LED_DELAY_ON, PANIC_BLINK_ON).await;
        let _ = tokio::fs::write(LED_DELAY_OFF, PANIC_BLINK_OFF).await;
        let _ = tokio::fs::write(LED_BRIGHTNESS, b"255").await;
        tokio::time::sleep(PANIC_BLINKING).await;
        let _ = tokio::fs::write(LED_TRIGGER, b"none").await;
        let _ = tokio::fs::write(LED_BRIGHTNESS, b"0").await;
    }
    // The render loop now hands the LED to the vendor (locked => Led::Vendor).
    CUE_PLAYING.store(false, Ordering::Release);
}

/// How often QMI is re-read. Cheap: a socket, a datagram, a reply.
const POLL: Duration = Duration::from_secs(2);

/// How often the *vendor's* web API is re-read.
///
/// Far less often than QMI, and not for performance. `sysser.fcgi` allocates a
/// session slot per request from a fixed pool, and polling it every two seconds
/// exhausted that pool within hours — after which the device's own owner could
/// not log in to the vendor UI, with the log showing
/// `AuthSession::GetSessionSlot: no open slots available`. Locking the user out
/// of their own settings page is a conspicuous fault on a device that is
/// supposed to look untouched.
///
/// Nothing taken from the vendor API changes quickly. Serving cell, band,
/// channel and signal all come from QMI now, and battery comes from sysfs. What
/// is left is the carrier name, connection uptime, byte counters and client
/// count, none of which need second-level resolution.
const VENDOR_POLL: Duration = Duration::from_secs(60);

/// Redraw cadence for the static modes. The animated mode paces itself.
const REDRAW: Duration = Duration::from_millis(900);

/// A revealed screen hands itself back to the vendor UI after this long with no
/// touch; any touch resets the countdown. Our screens do not honour the vendor
/// screen-sleep setting -- we drive the panel directly and it would otherwise
/// stay lit forever -- and a device revealed then set down should look stock
/// again for whoever picks it up next.
const IDLE_REVERT: Duration = Duration::from_secs(300);

/// The screen fades down over the final [`DIM_WARN`] before an idle revert, so
/// the revert is never a surprise -- a visibly dimming panel says "touch me or
/// I am going". A touch resets it to full.
const DIM_WARN: Duration = Duration::from_secs(30);

/// Darkest the fade reaches, out of 256. Low enough to be unmistakable, not
/// zero -- a black panel reads as broken rather than as a countdown.
const DIM_FLOOR: u16 = 32;

/// Brightness for the current idle time, as a 0..=256 fixed-point multiplier.
///
/// Full until the warning window, then a **quadratic** fade to [`DIM_FLOOR`].
/// Quadratic on purpose: perceived brightness is roughly logarithmic, so a
/// linear fade spends its first half in a range the eye barely registers. The
/// square keeps the panel near full early in the window, then drops hard as the
/// revert approaches -- an accelerating dim reads as a countdown, which is the
/// point.
fn dim_factor(idle: Duration) -> u16 {
    let fade_start = IDLE_REVERT.saturating_sub(DIM_WARN);
    if idle < fade_start {
        return 256;
    }
    let remaining = IDLE_REVERT.saturating_sub(idle).as_millis() as u64;
    let span = DIM_WARN.as_millis() as u64;
    // frac = remaining/span in [0,1]; brightness = floor + (256-floor)*frac^2
    let num = remaining.saturating_mul(remaining);
    let den = span.saturating_mul(span).max(1);
    (DIM_FLOOR as u64 + (256 - DIM_FLOOR as u64) * num / den).min(256) as u16
}

/// Scale a frame's brightness in place. A no-op at full.
fn apply_dim(buf: &mut [(u8, u8, u8)], factor: u16) {
    if factor >= 256 {
        return;
    }
    for px in buf.iter_mut() {
        px.0 = ((px.0 as u16 * factor) >> 8) as u8;
        px.1 = ((px.1 as u16 * factor) >> 8) as u8;
        px.2 = ((px.2 as u16 * factor) >> 8) as u8;
    }
}

const API_START: &str = "http://127.0.0.1:8080/api/start-recording";
const API_STOP: &str = "http://127.0.0.1:8080/api/stop-recording";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Status,
    CellLog,
    Orca,
    EffLogo,
}

impl Mode {
    fn from_u8(v: u8) -> Mode {
        match v {
            1 => Mode::CellLog,
            2 => Mode::Orca,
            3 => Mode::EffLogo,
            _ => Mode::Status,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Mode::Status => 0,
            Mode::CellLog => 1,
            Mode::Orca => 2,
            Mode::EffLogo => 3,
        }
    }

    /// Which corner selects this mode.
    fn from_corner(x: i32, y: i32) -> Option<Mode> {
        let left = x < CORNER_W;
        let right = x >= WIDTH as i32 - CORNER_W;
        let top = y < CORNER_H;
        let bottom = y >= HEIGHT as i32 - CORNER_H;
        match (left, right, top, bottom) {
            (true, _, true, _) => Some(Mode::CellLog),
            (_, true, true, _) => Some(Mode::Orca),
            (true, _, _, true) => Some(Mode::EffLogo),
            (_, true, _, true) => Some(Mode::Status),
            _ => None,
        }
    }
}

/// Is a touch clear of every corner zone?
///
/// A corner requires an edge in *both* axes, so anything in the middle
/// horizontal band is safe at any height -- `y` does not need checking.
fn is_centre(x: i32) -> bool {
    x >= CORNER_W && x < WIDTH as i32 - CORNER_W
}

/// What a completed hold should do.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Hold {
    Switch(Mode),
    Control,
    /// Close or reopen everything reachable from outside the device.
    Lockdown,
    Egg,
    /// Open the settings screen (change gesture or PIN).
    Settings,
    /// Switch to this profile, if it is not the current one.
    Profile(Profile),
}

/// Shared between the gesture watcher and the render loop.
struct Ui {
    /// Shared with the `Framebuffer` that gates writes to the panel.
    visible: Arc<AtomicBool>,
    mode: AtomicU8,
    /// Set by the watcher when the control is held; cleared by the render loop.
    action: AtomicBool,
    /// Set when the lockdown gesture completes; cleared by the render loop.
    toggle_lockdown: AtomicBool,
    /// Set by a short centre tap: show current state without changing it.
    peek: AtomicBool,
    /// True while the web UI and ADB are reachable.
    services_open: AtomicBool,
    /// Set by the power-button watcher; a deliberate, silent lockdown that
    /// does not take a lease.
    panic: AtomicBool,
    /// True while a persisted panic lockdown is in force. Every ordinary
    /// gesture is suppressed in this state -- revealing Rayhunter's UI on a
    /// device that has been locked down would undo the point of locking it.
    locked: AtomicBool,
    /// Set when the correct PIN has been entered.
    unlock: AtomicBool,
    egg: AtomicBool,
    /// Which orca is showing: false = swimming pod, true = spinning mascot.
    /// Flipped by a short tap while in Orca mode.
    orca_variant: AtomicBool,
    /// How many entries the cell log is scrolled back from the newest.
    log_scroll: AtomicUsize,
    /// When the panel was last touched, for the idle revert. Read by the render
    /// loop, written by the gesture watcher on every touch-down. A plain mutex:
    /// touches are rare and the render loop reads it about once a second, so
    /// there is no meaningful contention, and it is never held across an await.
    last_touch: Mutex<tokio::time::Instant>,
    /// This device's reveal gesture. `None`: nothing on the panel reveals.
    reveal: Mutex<Option<Secret>>,
    /// An enrolment in progress. Owns every touch while `Some`.
    enrol: Mutex<Option<m2100_enrol::Enrolment>>,
    /// The armed panic PIN, reloadable after on-panel enrolment.
    pin: Mutex<Option<Arc<PanicConfig>>>,
    /// The settings screen is showing.
    settings: AtomicBool,
    /// The profile screen is showing.
    profile_screen: AtomicBool,
    profile_note: Mutex<ProfileNote>,
    /// Where the Mobile confirmation goes; `None`: no confirmation.
    ntfy_url: Option<String>,
}

/// What a tap on the settings screen changes.
#[derive(Clone, Copy, PartialEq, Debug)]
enum SettingsChoice {
    /// Set the reveal gesture or the panic PIN (after performing the current one).
    Enrol(m2100_enrol::Target),
    /// Toggle Rayhunter's own sounds: detection beeps and enrolment chirps.
    Buzzer,
    /// Open the profile screen.
    Profile,
}

/// Four 48 px rows with 16 px dead bands between them, so a sloppy tap between
/// two rows chooses neither. `m2100_live::render_settings` draws the same rows.
fn settings_choice(y: i32) -> Option<SettingsChoice> {
    match y {
        0..=47 => Some(SettingsChoice::Enrol(m2100_enrol::Target::Gesture)),
        64..=111 => Some(SettingsChoice::Buzzer),
        128..=175 => Some(SettingsChoice::Profile),
        192..=239 => Some(SettingsChoice::Enrol(m2100_enrol::Target::Pin)),
        _ => None,
    }
}

/// FIXED on the top part, MOBILE on the bottom, and the note band between
/// them chooses nothing. `m2100_live::render_profile` draws the same parts.
/// The corners are left to their usual job, so there is always a way out.
fn profile_target(x: i32, y: i32) -> Option<Profile> {
    if Mode::from_corner(x, y).is_some() {
        return None;
    }
    match y {
        0..=103 => Some(Profile::Fixed),
        136..=239 => Some(Profile::Mobile),
        _ => None,
    }
}

/// A hold on the other profile switches to it; a hold on the current one
/// re-applies it, so a unit that drifted can be put back from the panel
/// (changed 2026-10-09; the spec first had it do nothing). Never while a
/// switch is still running.
fn hold_switches(_target: Profile, _current: Profile, switching: bool) -> bool {
    !switching
}

/// What the profile screen says when it opens: a switch still running, else a
/// boot re-apply that failed (until a switch succeeds), else the hint.
fn opening_note(switching: bool, boot_failed: bool) -> ProfileNote {
    if switching {
        ProfileNote::Switching
    } else if boot_failed {
        ProfileNote::Failed
    } else {
        ProfileNote::Hold
    }
}

/// What a completed corner hold shows: `Some(mode)`, or `None` for the stock
/// screen. Holding the corner of the mode already on screen hides it -- except
/// when leaving settings or the profile screen, where it means "take me there".
fn after_corner_hold(showing: bool, current: Mode, m: Mode, leaving: bool) -> Option<Mode> {
    if showing && current == m && !leaving {
        None
    } else {
        Some(m)
    }
}

fn saved_profile() -> Profile {
    m2100_profile::load(std::path::Path::new(m2100_profile::PROFILE_PATH))
}

/// A completed hold on the profile screen. The switch runs in the background
/// and the note line shows how it went; on a switch to Mobile, one ntfy
/// confirms it once the data call is up.
fn start_switch(ui: &Arc<Ui>, target: Profile) {
    if !hold_switches(
        target,
        saved_profile(),
        m2100_profile_io::SWITCHING.load(Ordering::Relaxed),
    ) || m2100_profile_io::SWITCHING.swap(true, Ordering::Relaxed)
    {
        return;
    }
    *ui.profile_note.lock().unwrap() = ProfileNote::Switching;
    log::info!("m2100 display: switching to {}", target.as_str());
    let ui = ui.clone();
    tokio::spawn(async move {
        let runner = m2100_cli::System::new();
        let path = std::path::Path::new(m2100_profile::PROFILE_PATH);
        let ok = m2100_profile_io::switch_to(&runner, path, target).await;
        *ui.profile_note.lock().unwrap() = if ok {
            ProfileNote::Hold
        } else {
            ProfileNote::Failed
        };
        if ok {
            m2100_profile_io::BOOT_FAILED.store(false, Ordering::Relaxed);
        }
        m2100_profile_io::SWITCHING.store(false, Ordering::Relaxed);
        log::info!(
            "m2100 display: switch to {} {}",
            target.as_str(),
            if ok { "done" } else { "FAILED" }
        );
        if !ok || target != Profile::Mobile {
            return;
        }
        let Some(url) = ui.ntfy_url.clone() else {
            return;
        };
        if m2100_profile_io::wait_connected(&runner, Duration::from_secs(5), 12).await {
            let client = reqwest::Client::new();
            let sent = m2100_profile_io::retry_send(path, Duration::from_secs(10), 6, || async {
                let msg = "Rayhunter: mobile profile active".to_string();
                match crate::notifications::send_notification(&client, &url, msg, 10).await {
                    Ok(()) => true,
                    Err(e) => {
                        log::info!("m2100 display: mobile confirmation not sent yet: {e}");
                        false
                    }
                }
            })
            .await;
            if !sent {
                log::warn!("m2100 display: mobile confirmation not sent");
            }
        } else {
            log::warn!("m2100 display: data call not up 60 s after switching to mobile");
        }
    });
}

/// The severity to beep for when the display state changes, if any: a new
/// warning, or one more severe than the last. The same warning is re-sent with
/// every analysed batch, and must not beep each time. Informational never beeps.
fn alert_beep_for(prev: DisplayState, new: DisplayState) -> Option<EventType> {
    let DisplayState::WarningDetected { event_type: t } = new else {
        return None;
    };
    if t == EventType::Informational {
        return None;
    }
    match prev {
        DisplayState::WarningDetected { event_type: p } if p >= t => None,
        _ => Some(t),
    }
}

/// Changing a secret from the panel requires performing the current one first.
fn start_from_settings(ui: &Ui, target: m2100_enrol::Target, now: std::time::Instant) {
    let verify = match target {
        m2100_enrol::Target::Gesture => ui.reveal.lock().unwrap().clone(),
        m2100_enrol::Target::Pin => ui.pin.lock().unwrap().as_ref().map(|c| c.secret().clone()),
    };
    ui.settings.store(false, Ordering::Relaxed);
    *ui.enrol.lock().unwrap() = Some(m2100_enrol::Enrolment::new(target, verify, now));
    // The gesture is enrolled on the stock screen; the PIN keeps its own screen.
    ui.visible
        .store(target == m2100_enrol::Target::Pin, Ordering::Relaxed);
}

/// Advance any enrolment, returning the cue its stage change calls for. A
/// failed gesture enrolment restarts itself: on the stock screen a tap to retry
/// would land on the vendor UI. A timeout is final.
fn enrolment_tick(ui: &Ui, now: std::time::Instant) -> Option<m2100_enrol::Cue> {
    let mut slot = ui.enrol.lock().unwrap();
    let e = slot.as_mut()?;
    let before = e.stage().clone();
    e.tick(now);
    let cue = m2100_enrol::cue_for(&before, e.stage());
    if e.target == m2100_enrol::Target::Gesture
        && matches!(e.stage(), m2100_enrol::Stage::Failed(f) if *f != m2100_enrol::Fail::TimedOut)
    {
        e.restart(now);
    }
    cue
}

/// Set while a cue is playing; a cue arriving meanwhile is dropped, not queued,
/// so blinks never pile up on the LED.
static CUE_PLAYING: AtomicBool = AtomicBool::new(false);

/// Blink (and chirp) a cue, then hand the LED back exactly as it was.
async fn play_cue(c: m2100_enrol::Cue) {
    if CUE_PLAYING.swap(true, Ordering::AcqRel) {
        return;
    }
    let previous = save_led().await;
    if tokio::fs::write(LED_TRIGGER, b"none").await.is_ok() {
        for (on, ms) in m2100_enrol::led_steps(c) {
            let _ = tokio::fs::write(
                LED_BRIGHTNESS,
                if *on {
                    b"255".as_slice()
                } else {
                    b"0".as_slice()
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(*ms)).await;
        }
    }
    match previous {
        Some(state) => restore_led(state).await,
        None => {
            let _ = tokio::fs::write(LED_BRIGHTNESS, b"0").await;
        }
    }
    crate::display::m2100::play_chirps(m2100_enrol::chirps(c)).await;
    CUE_PLAYING.store(false, Ordering::Release);
}

/// A touch released while the stock screen shows. Returns true when it
/// completed this device's gesture and revealed Rayhunter.
fn stock_release(ui: &Ui, matcher: &mut Matcher, t: &Touch, now: std::time::Instant) -> bool {
    if ui.locked.load(Ordering::Relaxed) {
        return false;
    }
    let guard = ui.reveal.lock().unwrap();
    let Some(secret) = guard.as_ref() else {
        return false;
    };
    let Some(mv) = m2100_gesture::classify(t) else {
        matcher.reset();
        return false;
    };
    if matcher.len() != secret.len {
        *matcher = Matcher::new(secret.len);
    }
    let pressed = now.checked_sub(t.held).unwrap_or(now);
    let Some(window) = matcher.push(mv.code(), pressed, now) else {
        return false;
    };
    if !secret.matches(&window) {
        return false;
    }
    matcher.reset();
    ui.mode.store(Mode::Status.as_u8(), Ordering::Relaxed);
    ui.visible.store(true, Ordering::Relaxed);
    log::info!("m2100 display: reveal gesture matched");
    true
}

/// Watch the digitiser for the two gestures.
///
/// Timer-driven rather than event-driven: this controller does not report while
/// a finger is held still (the input core suppresses unchanged absolute values),
/// so a hold must arm a deadline on touch-down rather than measure elapsed time
/// when events arrive. See `m2100_framebuffer` for the full note.
async fn watch_gestures(ui: Arc<Ui>, shutdown: CancellationToken) {
    use tokio::io::AsyncReadExt;

    const EV_SYN: u16 = 0x00;
    const EV_KEY: u16 = 0x01;
    const EV_ABS: u16 = 0x03;
    const BTN_TOUCH: u16 = 0x14a;
    const ABS_X: u16 = 0x00;
    const ABS_Y: u16 = 0x01;

    let mut f = match tokio::fs::File::open("/dev/input/event2").await {
        Ok(f) => f,
        Err(e) => {
            log::warn!("m2100 display: no touch input ({e}); gestures disabled");
            return;
        }
    };

    let mut buf = [0u8; 16];
    let (mut x, mut y) = (0i32, 0i32);
    let mut pressed = false;
    let mut fired = false;
    let mut deadline: Option<tokio::time::Instant> = None;
    let mut pending: Option<Hold> = None;
    let mut press_started = tokio::time::Instant::now();
    let mut touch_start: Option<(i32, i32)> = None;
    let mut matcher = Matcher::new(m2100_gesture::MIN_LEN);

    // Rolling window of entered digits, only used while locked.
    let mut entry: Vec<u8> = Vec::new();
    let mut last_digit = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            _ = async {
                match deadline {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                deadline = None;
                fired = true;

                if ui.locked.load(Ordering::Relaxed) {
                    // Read the live PIN: one set on the panel takes effect
                    // without restarting the daemon.
                    let pin = ui.pin.lock().unwrap().clone();
                    let Some(cfg) = pin.as_ref() else { continue };
                    let pin_len = cfg.len;
                    let Some(d) = m2100_panic::digit_at(x, y, WIDTH, HEIGHT) else {
                        continue;
                    };
                    // Discard a stale partial entry rather than let someone
                    // else finish it.
                    if last_digit.elapsed() > m2100_panic::ENTRY_IDLE {
                        entry.clear();
                    }
                    last_digit = tokio::time::Instant::now();
                    entry.push(d);
                    if entry.len() > pin_len {
                        entry.remove(0);
                    }
                    // Silent on failure: no feedback at all, so there is no
                    // sign a pad exists, and no oracle to probe.
                    if entry.len() == pin_len && cfg.matches(&entry) {
                        entry.clear();
                        ui.unlock.store(true, Ordering::Relaxed);
                    }
                    continue;
                }

                match pending {
                    Some(Hold::Switch(m)) => {
                        let current = Mode::from_u8(ui.mode.load(Ordering::Relaxed));
                        let showing = ui.visible.load(Ordering::Relaxed);
                        let leaving = ui.settings.swap(false, Ordering::Relaxed)
                            | ui.profile_screen.swap(false, Ordering::Relaxed);
                        if after_corner_hold(showing, current, m, leaving).is_none() {
                            // Same corner as the mode on screen: hide.
                            ui.visible.store(false, Ordering::Relaxed);
                            log::info!("m2100 display: {m:?} corner held -> stock UI");
                        } else {
                            ui.mode.store(m.as_u8(), Ordering::Relaxed);
                            ui.visible.store(true, Ordering::Relaxed);
                            log::info!("m2100 display: {m:?} corner held -> {m:?}");
                            // Still holding the EFF corner well past the switch
                            // it already gave you? Arm the egg.
                            if m == Mode::EffLogo {
                                pending = Some(Hold::Egg);
                                deadline = Some(press_started + EGG_HOLD);
                                fired = false;
                            }
                        }
                    }
                    Some(Hold::Control) => {
                        ui.action.store(true, Ordering::Relaxed);
                        log::info!("m2100 display: control held at ({x},{y})");
                    }
                    Some(Hold::Lockdown) => {
                        ui.toggle_lockdown.store(true, Ordering::Relaxed);
                    }
                    Some(Hold::Egg) => {
                        ui.egg.store(true, Ordering::Relaxed);
                    }
                    Some(Hold::Settings) => {
                        ui.settings.store(true, Ordering::Relaxed);
                        log::info!("m2100 display: settings opened");
                    }
                    Some(Hold::Profile(t)) => start_switch(&ui, t),
                    None => {}
                }
            }

            r = f.read_exact(&mut buf) => {
                if let Err(e) = r {
                    log::warn!("m2100 display: touch read failed: {e}; gestures disabled");
                    return;
                }
                let ev_type = u16::from_le_bytes([buf[8], buf[9]]);
                let code = u16::from_le_bytes([buf[10], buf[11]]);
                let value = i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);

                match (ev_type, code) {
                    (EV_ABS, ABS_X) => x = value,
                    (EV_ABS, ABS_Y) => y = value,
                    (EV_KEY, BTN_TOUCH) => {
                        pressed = value == 1;
                        if pressed {
                            touch_start = None;
                            press_started = tokio::time::Instant::now();
                            // Any touch keeps a revealed screen awake.
                            *ui.last_touch.lock().unwrap() = press_started;
                            // An enrolment must not decide the performance is over
                            // while this finger is down.
                            if let Some(e) = ui.enrol.lock().unwrap().as_mut() {
                                e.touch_down(press_started.into_std());
                            }
                        }
                        if !pressed {
                            if ui.profile_screen.load(Ordering::Relaxed) {
                                // Taps do nothing here; a hold did its work at
                                // the deadline.
                                deadline = None;
                                fired = false;
                                pending = None;
                                continue;
                            }
                            if ui.settings.load(Ordering::Relaxed) && !fired {
                                match settings_choice(y) {
                                    Some(SettingsChoice::Enrol(target)) => start_from_settings(
                                        &ui,
                                        target,
                                        tokio::time::Instant::now().into_std(),
                                    ),
                                    // Reversible and harmless, so no secret is
                                    // asked for; settings stays open to show it.
                                    Some(SettingsChoice::Buzzer) => {
                                        let on = !crate::display::m2100::buzzer_enabled();
                                        tokio::spawn(crate::display::m2100::set_buzzer_enabled(on));
                                    }
                                    Some(SettingsChoice::Profile) => {
                                        *ui.profile_note.lock().unwrap() = opening_note(
                                            m2100_profile_io::SWITCHING.load(Ordering::Relaxed),
                                            m2100_profile_io::BOOT_FAILED.load(Ordering::Relaxed),
                                        );
                                        ui.settings.store(false, Ordering::Relaxed);
                                        ui.profile_screen.store(true, Ordering::Relaxed);
                                    }
                                    None => {}
                                }
                                deadline = None;
                                pending = None;
                                continue;
                            }
                            {
                                let mut slot = ui.enrol.lock().unwrap();
                                if let Some(e) = slot.as_mut() {
                                    let now = tokio::time::Instant::now().into_std();
                                    e.touch_up(now);
                                    let t = Touch {
                                        start: touch_start.unwrap_or((x, y)),
                                        end: (x, y),
                                        held: press_started.elapsed(),
                                    };
                                    if e.target == m2100_enrol::Target::Pin
                                        && matches!(e.stage(), m2100_enrol::Stage::Failed(_))
                                    {
                                        // On the PIN screen, "tap to try again". A gesture
                                        // enrolment restarts itself (enrolment_tick).
                                        e.restart(now);
                                    } else {
                                        let code = match e.target {
                                            m2100_enrol::Target::Gesture => {
                                                m2100_gesture::classify(&t).map(|m| m.code())
                                            }
                                            m2100_enrol::Target::Pin => (t.held
                                                >= m2100_panic::DIGIT_HOLD)
                                                .then(|| {
                                                    m2100_panic::digit_at(
                                                        t.start.0, t.start.1, WIDTH, HEIGHT,
                                                    )
                                                })
                                                .flatten(),
                                        };
                                        if let Some(c) = code {
                                            e.push(c, now);
                                            if e.target == m2100_enrol::Target::Gesture {
                                                tokio::spawn(play_cue(m2100_enrol::Cue::Move));
                                            }
                                        }
                                    }
                                    drop(slot);
                                    deadline = None;
                                    fired = false;
                                    pending = None;
                                    continue;
                                }
                            }
                            if !ui.visible.load(Ordering::Relaxed) {
                                let t = Touch {
                                    start: touch_start.unwrap_or((x, y)),
                                    end: (x, y),
                                    held: press_started.elapsed(),
                                };
                                stock_release(&ui, &mut matcher, &t, tokio::time::Instant::now().into_std());
                            }
                            // A short centre tap shows the current state
                            // without changing it, so state can be checked as
                            // deniably as it is toggled.
                            if !fired
                                && matches!(pending, Some(Hold::Lockdown))
                                && ui.visible.load(Ordering::Relaxed)
                            {
                                ui.peek.store(true, Ordering::Relaxed);
                            }
                            // A short tap in the orca's own corner swaps the
                            // two variants.
                            if !fired
                                && ui.visible.load(Ordering::Relaxed)
                                && taps_orca_toggle(
                                    Mode::from_u8(ui.mode.load(Ordering::Relaxed)),
                                    x,
                                    y,
                                )
                            {
                                ui.orca_variant.fetch_xor(true, Ordering::Relaxed);
                            }
                            // Short edge taps: acknowledge an alert, scroll the log.
                            // Never while locked -- the PIN pad owns every touch then.
                            if !fired
                                && ui.visible.load(Ordering::Relaxed)
                                && !ui.locked.load(Ordering::Relaxed)
                            {
                                let mode = Mode::from_u8(ui.mode.load(Ordering::Relaxed));
                                match edge_tap(x, y) {
                                    Some(EdgeTap::Left) => crate::alerts::acknowledge(
                                        &format!("left-edge tap at {x},{y}"),
                                    ),
                                    Some(EdgeTap::RightUpper) if mode == Mode::CellLog => {
                                        let s = ui.log_scroll.load(Ordering::Relaxed);
                                        ui.log_scroll
                                            .store(s.saturating_sub(SCROLL_STEP), Ordering::Relaxed);
                                    }
                                    Some(EdgeTap::RightLower) if mode == Mode::CellLog => {
                                        let s = ui.log_scroll.load(Ordering::Relaxed);
                                        // Capped here, clamped exactly at render time.
                                        ui.log_scroll.store(
                                            (s + SCROLL_STEP).min(m2100_live::LOG_LEN),
                                            Ordering::Relaxed,
                                        );
                                    }
                                    _ => {}
                                }
                            }
                            deadline = None;
                            fired = false;
                            pending = None;
                        }
                    }
                    // Coordinates arrive after BTN_TOUCH within the same packet,
                    // so the position is only trustworthy at the closing SYN.
                    (EV_SYN, _) => {
                        if pressed && touch_start.is_none() {
                            // First SYN of this press. Use the current x,y even
                            // if no ABS event arrived: the input core drops
                            // unchanged values, so a press at the same spot as
                            // the last one reports no coordinates at all.
                            touch_start = Some((x, y));
                        }
                        // An enrolment owns every touch; no hold may arm.
                        if ui.enrol.lock().unwrap().is_some() {
                            continue;
                        }
                        // Once the egg is armed it stays armed until the finger
                        // lifts. A held finger still jitters, and each jitter
                        // produces a SYN: without this the handler re-evaluates,
                        // overwrites the pending egg with another mode switch,
                        // and the long hold ends up *hiding* the screen it just
                        // brought up.
                        if !pressed || fired || matches!(pending, Some(Hold::Egg)) {
                            continue;
                        }
                        let showing = ui.visible.load(Ordering::Relaxed);
                        let mode = Mode::from_u8(ui.mode.load(Ordering::Relaxed));

                        // Order matters: a service button and the centre hold
                        // occupy the same band, so the button wins where they
                        // overlap, and only bare centre opens/closes the screen.
                        // Locked: the invisible PIN pad replaces every other
                        // gesture. Nothing may reveal the UI in this state.
                        if ui.locked.load(Ordering::Relaxed) {
                            if ui.pin.lock().unwrap().is_some()
                                && m2100_panic::digit_at(x, y, WIDTH, HEIGHT).is_some()
                            {
                                pending = None;
                                deadline.get_or_insert_with(|| {
                                    tokio::time::Instant::now() + m2100_panic::DIGIT_HOLD
                                });
                            }
                            continue;
                        }

                        // On the profile screen only a hold on FIXED or MOBILE
                        // arms, and start_switch decides then whether it
                        // switches; sliding to the other part restarts the
                        // hold. A corner falls through to the usual corner
                        // hold, which leaves the screen.
                        if ui.profile_screen.load(Ordering::Relaxed)
                            && Mode::from_corner(x, y).is_none()
                        {
                            match profile_target(x, y) {
                                Some(t) if pending == Some(Hold::Profile(t)) => {}
                                Some(t) => {
                                    pending = Some(Hold::Profile(t));
                                    deadline = Some(tokio::time::Instant::now() + PROFILE_HOLD);
                                }
                                None => {
                                    deadline = None;
                                    pending = None;
                                }
                            }
                            continue;
                        }

                        let (what, hold) = match classify_touch(showing, mode, x, y) {
                            Some((p, h)) => (Some(p), h),
                            None => (None, MODE_HOLD),
                        };

                        match what {
                            Some(p) => {
                                pending = Some(p);
                                deadline.get_or_insert_with(|| {
                                    tokio::time::Instant::now() + hold
                                });
                            }
                            None => {
                                deadline = None;
                                pending = None;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Watch the power button for the panic sequence.
///
/// Counts presses in a sliding window and fires once when the threshold is
/// reached. Normal use of the button -- one press to wake, one to blank -- is
/// well clear of five in three seconds.
async fn watch_panic_sequence(ui: Arc<Ui>, shutdown: CancellationToken) {
    use tokio::io::AsyncReadExt;

    let mut f = match tokio::fs::File::open(POWER_INPUT).await {
        Ok(f) => f,
        Err(e) => {
            log::warn!("m2100 display: no power input at {POWER_INPUT} ({e}); panic disabled");
            return;
        }
    };

    let mut buf = [0u8; 16];
    let mut presses: Vec<tokio::time::Instant> = Vec::new();

    loop {
        let read = tokio::select! {
            _ = shutdown.cancelled() => break,
            r = f.read_exact(&mut buf) => r,
        };
        if let Err(e) = read {
            log::warn!("m2100 display: power input read failed: {e}; panic disabled");
            return;
        }

        let ev_type = u16::from_le_bytes([buf[8], buf[9]]);
        let code = u16::from_le_bytes([buf[10], buf[11]]);
        let value = i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);

        // Key down only; a press and release would otherwise count twice.
        if ev_type != 1 || code != KEY_POWER || value != 1 {
            continue;
        }

        let now = tokio::time::Instant::now();
        presses.retain(|t| now.duration_since(*t) <= PANIC_WINDOW);
        presses.push(now);

        if presses.len() >= PANIC_CLICKS {
            presses.clear();
            ui.panic.store(true, Ordering::Relaxed);
            log::info!("m2100 display: panic sequence");
        }
    }
}

/// Poll the vendor API and QMI on a fixed cadence, independent of what is on
/// screen, so the RSRP history and the cell log keep accumulating even while a
/// different mode is showing -- or while nothing is.
async fn poll_telemetry(tel: Arc<tokio::sync::Mutex<Telemetry>>, shutdown: CancellationToken) {
    let client = reqwest::Client::new();
    let mut last_vendor: Option<tokio::time::Instant> = None;
    // SPIKE 2026-10-16: serving-cell signal log, see m2100_siglog.
    let started = std::time::Instant::now();
    let mut polls: u32 = 0;
    let mut siglog_failed = false;
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        // Only re-read the vendor API occasionally; see VENDOR_POLL.
        let status = if last_vendor.is_none_or(|t: tokio::time::Instant| t.elapsed() >= VENDOR_POLL)
        {
            last_vendor = Some(tokio::time::Instant::now());
            m2100_live::fetch_status(&client).await
        } else {
            None
        };
        // Both QMI calls are blocking socket round-trips.
        let sig = tokio::task::spawn_blocking(m2100_signal::read_signal)
            .await
            .ok()
            .flatten();
        let bands = tokio::task::spawn_blocking(m2100_signal::read_active_bands)
            .await
            .unwrap_or_default();
        let cell = tokio::task::spawn_blocking(m2100_signal::read_cell_info)
            .await
            .ok()
            .flatten();

        polls = polls.wrapping_add(1);
        let siglog = (polls % m2100_siglog::EVERY == 0).then(|| {
            m2100_siglog::format_line(
                &chrono::Local::now().to_rfc3339(),
                started.elapsed().as_secs(),
                cell.as_ref(),
                sig.as_ref(),
            )
        });

        {
            let mut t = tel.lock().await;
            if let Some(s) = status {
                t.status = s;
            }
            if let Some(s) = sig {
                t.sig = Some(s);
                if t.hist.len() == m2100_live::HISTORY {
                    t.hist.remove(0);
                }
                t.hist.push(s.rsrp_dbm);
            }
            if !bands.is_empty() {
                t.bands = bands;
            }
            if cell.is_some() {
                t.cell = cell;
            }
            t.observe();
        }

        if let Some(line) = siglog {
            let res = tokio::task::spawn_blocking(move || {
                m2100_siglog::append(
                    std::path::Path::new(m2100_siglog::PATH),
                    &line,
                    m2100_siglog::CAP_BYTES,
                )
            })
            .await;
            // Log a failure once, not every 30 s: a full disk must not fill it further.
            if let Ok(Err(e)) = res {
                if !siglog_failed {
                    log::warn!("m2100 siglog: {e}");
                    siglog_failed = true;
                }
            }
        }

        tokio::time::sleep(POLL).await;
    }
}

/// Close or reopen the device's externally reachable services.
///
/// Two things are reachable from outside, and they are different in kind:
///
/// * the daemon's web API, bound to `0.0.0.0` with no authentication, so anyone
///   on the device's WiFi can read captures, stop recording, or delete
///   everything;
/// * ADB, which is USB-only and so needs physical possession and a cable.
///
/// The web UI is blocked with a firewall rule on the LAN bridge rather than by
/// stopping the server, which keeps loopback working -- the panel's own
/// start/stop control talks to `127.0.0.1`, and the vendor's rules already
/// carry `-A INPUT -i lo -j ACCEPT`. ADB is closed by stopping `adbd`; the
/// functionfs mount persists, so it can be started again.
///
/// Neither change is persisted. A power cycle restores both, which is the
/// recovery path if the panel ever stops responding while locked down.
async fn set_services_open(open: bool, port: u16) -> bool {
    let rule = [
        "INPUT",
        "-i",
        "bridge0",
        "-p",
        "tcp",
        "--dport",
        &port.to_string(),
        "-j",
        "DROP",
    ]
    .map(String::from);

    let mut ok = true;

    // Firewall: insert the DROP at the head of INPUT so it precedes the
    // vendor's blanket `-i bridge0 -j ACCEPT`, or delete it to reopen.
    let mut args: Vec<String> = Vec::new();
    if open {
        args.push("-D".into());
    } else {
        args.push("-I".into());
    }
    args.extend(rule.iter().cloned());
    if open {
        // A delete of a rule that is not present is an error, not a problem.
        let _ = run("iptables", &args).await;
    } else {
        // Insert at position 1.
        let mut ins = vec!["-I".to_string(), "INPUT".to_string(), "1".to_string()];
        ins.extend(rule.iter().skip(1).cloned());
        ok &= run("iptables", &ins).await;
    }

    // ADB. Starting it must not wait for it to exit -- adbd is a daemon and
    // runs until killed, so awaiting its status blocks until the timeout fires.
    if open {
        ok &= spawn_detached("setsid", &["/sbin/adbd".to_string()]);
    } else {
        // killall returns non-zero when nothing matched, which is fine.
        let _ = run("killall", &["adbd".to_string()]).await;
    }

    log::info!(
        "m2100 display: external services now {}",
        if open { "open" } else { "closed" }
    );
    ok
}

/// Launch a long-running process without waiting for it to finish.
///
/// [`run`] waits for the child to exit, which is right for one-shot helpers and
/// wrong for daemons: `adbd` runs until it is killed, so awaiting it blocked the
/// display loop until the timeout expired every single time ADB was re-enabled.
/// Returns whether the spawn itself succeeded, which is all that can be known
/// at this point.
fn spawn_detached(cmd: &str, args: &[String]) -> bool {
    match tokio::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            // Nothing will await this handle; let the runtime reap it so it
            // does not linger as a zombie.
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            true
        }
        Err(e) => {
            log::warn!("m2100 display: couldn't spawn {cmd}: {e}");
            false
        }
    }
}

/// Detect whether the services are currently reachable, so state is read from
/// the system rather than assumed after a daemon restart.
async fn services_are_open(port: u16) -> bool {
    let blocked = run(
        "iptables",
        &[
            "-C".to_string(),
            "INPUT".to_string(),
            "-i".to_string(),
            "bridge0".to_string(),
            "-p".to_string(),
            "tcp".to_string(),
            "--dport".to_string(),
            port.to_string(),
            "-j".to_string(),
            "DROP".to_string(),
        ],
    )
    .await;
    !blocked
}

/// Apply a services change, then record what the system actually ended up in
/// rather than what was asked for.
///
/// [`set_services_open`] can partly fail -- an `iptables` insert can be
/// refused, `adbd` can fail to spawn -- and it returns whether it succeeded.
/// Every call site used to discard that and store the INTENT, so a lockdown
/// that did not take would display OFF while the web interface stayed
/// reachable. That is the wrong way round for an indicator whose entire job is
/// to say whether this device is exposed: it should fail towards "still open",
/// never towards a false sense of being shut.
///
/// Reading the firewall back costs one `iptables -C` on an action a person
/// performs by hand, which is not a rate worth optimising.
///
/// NOTE: the read-back checks the firewall only. `adbd` failing to start while
/// the firewall opens will still report open.
async fn apply_services_open(ui: &Ui, open: bool, port: u16) {
    if !set_services_open(open, port).await {
        log::warn!(
            "m2100 display: services change to {} did not fully succeed; \
             reporting the measured state instead",
            if open { "open" } else { "closed" }
        );
    }
    ui.services_open
        .store(services_are_open(port).await, Ordering::Relaxed);
}

/// Longest any helper process may block the caller.
const CMD_TIMEOUT: Duration = Duration::from_secs(5);

/// Run a helper process, and never wait on it indefinitely.
///
/// The display loop calls into this, so an unbounded wait freezes the panel:
/// the screen stops updating and gestures appear dead because nothing acts on
/// them. That happened on hardware -- a vendor-UI restart issued moments after
/// `adbd` was killed never returned, and the loop sat in it until the device
/// was power-cycled. A hung helper now costs a few seconds and a log line.
/// Confirm a panic by ear with the vendor's own startup chime, but only when the
/// device would beep for its own events (see `m2100_panic::chime_wanted`).
/// Spawned, never awaited by the panic: the lock must not wait on a sound.
async fn panic_chime() {
    use crate::display::m2100_cli::{Out, Runner, System};
    let r = System::new();
    let enabled = |o: Option<Out>| o.and_then(|o| m2100_panic::parse_enabled(&o.stdout));
    let audio = enabled(r.run("ans_cli", &["get_audio_alerts_enabled"], "").await);
    let stealth = enabled(r.run("ans_cli", &["get_stealth_mode_enabled"], "").await);
    if !m2100_panic::chime_wanted(audio, stealth) {
        return;
    }
    let _ = r
        .run("ans_cli", &["trigger_notification"], m2100_panic::CHIME_ADD)
        .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let _ = r
        .run(
            "ans_cli",
            &["trigger_notification"],
            m2100_panic::CHIME_REMOVE,
        )
        .await;
}

async fn run(cmd: &str, args: &[String]) -> bool {
    let child = tokio::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match tokio::time::timeout(CMD_TIMEOUT, child).await {
        Ok(Ok(s)) => s.success(),
        Ok(Err(e)) => {
            log::warn!("m2100 display: {cmd} failed: {e}");
            false
        }
        Err(_) => {
            log::warn!("m2100 display: {cmd} timed out after {CMD_TIMEOUT:?}");
            false
        }
    }
}

/// Start or stop recording through the daemon's own HTTP API.
async fn toggle_recording(client: &reqwest::Client, recording: bool) {
    let url = if recording { API_STOP } else { API_START };
    match client.post(url).timeout(CMD_TIMEOUT).send().await {
        Ok(r) if r.status().is_success() => {
            log::info!(
                "m2100 display: {} recording via control",
                if recording { "stopped" } else { "started" }
            )
        }
        Ok(r) => log::warn!("m2100 display: recording control returned {}", r.status()),
        Err(e) => log::warn!("m2100 display: recording control failed: {e}"),
    }
}

/// Stop recording outright, whatever state it is in.
///
/// Panic and lockdown historically closed only the *interfaces* and left the
/// capture running, so a device that had been panicked was still writing to
/// disk. Hiding the UI while continuing to collect is the wrong trade when the
/// reason for panicking is that someone may be about to hold the device.
///
/// [`toggle_recording`] takes "is currently recording", so `true` means stop.
async fn stop_recording(client: &reqwest::Client) {
    toggle_recording(client, true).await;
}

/// `visible` is the framebuffer's own stealth gate, passed in rather than
/// created here: the gesture watcher and the thing that decides whether a write
/// reaches the panel have to be looking at one flag, not two.
pub fn update_ui(
    task_tracker: &TaskTracker,
    config: &config::Config,
    mut fb: impl GenericFramebuffer,
    visible: Arc<AtomicBool>,
    shutdown_token: CancellationToken,
    mut ui_update_rx: Receiver<DisplayState>,
) {
    // Always starts hidden: a device that is power-cycled comes up stock.
    let ui = Arc::new(Ui {
        visible,
        mode: AtomicU8::new(Mode::Status.as_u8()),
        action: AtomicBool::new(false),
        panic: AtomicBool::new(false),
        locked: AtomicBool::new(false),
        unlock: AtomicBool::new(false),
        egg: AtomicBool::new(false),
        orca_variant: AtomicBool::new(false),
        log_scroll: AtomicUsize::new(0),
        toggle_lockdown: AtomicBool::new(false),
        peek: AtomicBool::new(false),
        services_open: AtomicBool::new(true),
        last_touch: Mutex::new(tokio::time::Instant::now()),
        reveal: Mutex::new(m2100_enrol::load_reveal(&Paths::device())),
        enrol: Mutex::new(None),
        pin: Mutex::new(PanicConfig::load().map(Arc::new)),
        settings: AtomicBool::new(false),
        profile_screen: AtomicBool::new(false),
        profile_note: Mutex::new(ProfileNote::Hold),
        ntfy_url: config.ntfy_url.clone().filter(|u| !u.is_empty()),
    });
    let mut initial = Telemetry::default();
    initial.known = m2100_live::KnownTowers::load(m2100_live::KNOWN_TOWERS_PATH);
    let tel = Arc::new(tokio::sync::Mutex::new(initial));
    let colorblind = config.colorblind_mode;

    // Absent config means the feature is not armed on this device, which is
    // the default: it can brick the device, so its presence is opt-in and
    // deliberately leaves no trace in any screen or setting.
    if ui.pin.lock().unwrap().is_some() {
        log::info!("m2100 display: panic lockdown armed");
    }

    task_tracker.spawn(watch_gestures(ui.clone(), shutdown_token.clone()));
    task_tracker.spawn(watch_panic_sequence(ui.clone(), shutdown_token.clone()));
    task_tracker.spawn(poll_telemetry(tel.clone(), shutdown_token.clone()));

    let port = config.port;

    task_tracker.spawn(async move {
        let client = reqwest::Client::new();
        let mut state = DisplayState::Recording;
        let mut flash_until: Option<tokio::time::Instant> = None;
        let mut egg_until: Option<tokio::time::Instant> = None;
        // When the current lockdown lapses on its own.
        let mut lease_until: Option<tokio::time::Instant> = None;

        // Re-apply a panic lockdown that survived a reboot, before anything
        // else happens. Takes no lease: it was a deliberate act and stays until
        // it is deliberately undone.
        if ui.pin.lock().unwrap().is_some() && m2100_panic::flag_set() {
            log::info!("m2100 display: panic lockdown in force, awaiting PIN");
            ui.locked.store(true, Ordering::Relaxed);
            ui.visible.store(false, Ordering::Relaxed);
            apply_services_open(&ui, false, port).await;
            // The flag survived a reboot, so the daemon has just come up and
            // may have started recording again. A panic that reboots into a
            // recording device has not held.
            stop_recording(&client).await;
        } else {
            // Read the real state rather than assuming: a daemon restart while
            // locked down must not claim the services are open.
            ui.services_open
                .store(services_are_open(port).await, Ordering::Relaxed);
        }

        // The Orca mode has two variants, toggled by a short tap: the swimming
        // pod and the spinning mascot. Both prepared once.
        let orca_spin: Vec<(Vec<(u8, u8, u8)>, u64)> = load_gif(&fb, "orca_spin.gif");
        // Same spin with a red outline, shown while a warning is active so the
        // mascot's outline tracks the status bar instead of staying green.
        let orca_spin_red: Vec<(Vec<(u8, u8, u8)>, u64)> = load_gif(&fb, "orca_spin_red.gif");
        // Prepared once: the orca frames and the EFF logo never change, and
        // rescaling them per frame dominated CPU when they did.
        let orca: Vec<(Vec<(u8, u8, u8)>, u64)> = load_gif(&fb, "orca.gif");
        let eff: Option<Vec<(u8, u8, u8)>> = load_eff(&fb);

        // The vendor's own LED pattern, captured before we ever touch it, so
        // "not running" can be handed back exactly as found rather than as a
        // guess at 75% and 6s.
        let vendor_led = save_led().await.map(vendor_from_saved);

        loop {
            if shutdown_token.is_cancelled() {
                log::info!("received UI shutdown");
                // Leave the LED as the vendor's, so a stopped daemon does not
                // keep flashing "running".
                ensure_led(Led::Vendor, &vendor_led).await;
                break;
            }
            match ui_update_rx.try_recv() {
                Ok(s) => {
                    if let Some(t) = alert_beep_for(state, s) {
                        tokio::spawn(crate::display::m2100::play_alert(t));
                    }
                    state = s;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                Err(e) => log::error!("error receiving framebuffer update message: {e}"),
            }

            // Independent of the panel: the screen sleeps, the question of
            // whether Rayhunter is running does not.
            // Not while a cue or the panic glow is playing: this runs every
            // cycle and would switch it off partway through (it did, 2026-10-08).
            if !CUE_PLAYING.load(Ordering::Acquire) {
                ensure_led(
                    led_for(ui.locked.load(Ordering::Relaxed), state),
                    &vendor_led,
                )
                .await;
            }

            // Panic sequence. Confirmed only by things the device does anyway:
            // fast LED blinks once the presses settle (panic_led_blink), and
            // the vendor's own startup chime if the owner's sound settings allow
            // it (panic_chime). Never a Rayhunter-specific signal, which would be
            // a tell at the one moment it matters. It takes no lease: this is an explicit act, and having it quietly
            // reopen while the situation that prompted it is still unfolding
            // would defeat it. It also hides the Rayhunter UI, since leaving
            // that on screen undoes the point of closing everything else.
            let pin = ui.pin.lock().unwrap().clone();
            if ui.panic.swap(false, Ordering::Relaxed) && pin.is_some() {
                let dev = pin.as_ref().map(|c| c.dev_mode).unwrap_or(false);
                ui.visible.store(false, Ordering::Relaxed);
                // Before anything else, and in dev mode too: stopping capture
                // is reversible and risks no lockout, so a rehearsal that
                // skipped it would not be rehearsing the thing that matters.
                stop_recording(&client).await;
                if dev {
                    // Dev mode still enters the locked UI state, so the PIN pad
                    // and the suppression of every other gesture can be
                    // rehearsed -- that is the recovery path, and it is the part
                    // worth testing before arming for real. What it does not do
                    // is close anything, so ADB stays up and a failed rehearsal
                    // costs a daemon restart rather than the device.
                    ui.locked.store(true, Ordering::Relaxed);
                    log::info!(
                        "m2100 display: panic (dev mode) -- UI locked, recording \
                         stopped, no services closed"
                    );
                } else {
                    if ui.services_open.load(Ordering::Relaxed) {
                        apply_services_open(&ui, false, port).await;
                    }
                    m2100_panic::set_flag(true);
                    ui.locked.store(true, Ordering::Relaxed);
                }
                lease_until = None;
                // Confirm on the LED, not the screen and not the buzzer.
                // Spawned rather than awaited: the confirmation must not delay
                // the thing it is confirming.
                tokio::spawn(panic_led_blink());
                // And by ear, if the owner's sound settings allow (see panic_chime).
                tokio::spawn(panic_chime());
                log::info!("m2100 display: panic lockdown, no lease");
            }

            if ui.unlock.swap(false, Ordering::Relaxed) {
                let dev = pin.as_ref().map(|c| c.dev_mode).unwrap_or(false);
                log::info!(
                    "m2100 display: PIN accepted{}",
                    if dev { " (dev mode)" } else { ", reopening" }
                );
                ui.locked.store(false, Ordering::Relaxed);
                if !dev {
                    m2100_panic::set_flag(false);
                    apply_services_open(&ui, true, port).await;
                }
                // Bring the panel back so the confirmation is actually visible;
                // the panic hid it.
                ui.visible.store(true, Ordering::Relaxed);
                flash_until = Some(tokio::time::Instant::now() + FLASH);
            }

            // Dead-man's timer, checked before the visibility gate on purpose:
            // the panel is usually hidden while locked down, and a lease that
            // only ticks while something is on screen would never lapse in the
            // exact situation it exists for.
            if let Some(t) = lease_until {
                if tokio::time::Instant::now() >= t {
                    lease_until = None;
                    if !ui.services_open.load(Ordering::Relaxed)
                        && !ui.locked.load(Ordering::Relaxed)
                    {
                        log::info!("m2100 display: lockdown lease expired, reopening");
                        apply_services_open(&ui, true, port).await;
                        flash_until = Some(tokio::time::Instant::now() + FLASH);
                    }
                }
            }

            // Enrolment: requests from the helper script, and the enrolment
            // screen while one runs. Before the idle revert, so an enrolment is
            // never cut short by the idle timer.
            let paths = Paths::device();
            handle_request(&ui, &paths, tokio::time::Instant::now().into_std());
            if let Some(cue) = enrolment_tick(&ui, tokio::time::Instant::now().into_std()) {
                tokio::spawn(play_cue(cue));
            }
            let pin_screen = {
                let slot = ui.enrol.lock().unwrap();
                slot.as_ref()
                    .filter(|e| e.target == m2100_enrol::Target::Pin)
                    .map(|e| m2100_live::render_enrol(e.target, e.stage(), e.progress()))
            };
            let finished = finish_enrolment(&ui, &paths).is_some();
            if let Some(buf) = pin_screen {
                fb.write_buffer(buf).await;
                if finished {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                }
                tokio::time::sleep(REDRAW).await;
                continue;
            }

            if ui.profile_screen.load(Ordering::Relaxed) {
                if ui.last_touch.lock().unwrap().elapsed() >= SETTINGS_IDLE {
                    ui.profile_screen.store(false, Ordering::Relaxed);
                } else {
                    let note = *ui.profile_note.lock().unwrap();
                    fb.write_buffer(m2100_live::render_profile(saved_profile(), note))
                        .await;
                    tokio::time::sleep(REDRAW).await;
                    continue;
                }
            }

            if ui.settings.load(Ordering::Relaxed) {
                if ui.last_touch.lock().unwrap().elapsed() >= SETTINGS_IDLE {
                    ui.settings.store(false, Ordering::Relaxed);
                } else {
                    fb.write_buffer(m2100_live::render_settings(
                        crate::display::m2100::buzzer_enabled(),
                        saved_profile(),
                    ))
                    .await;
                    tokio::time::sleep(REDRAW).await;
                    continue;
                }
            }

            // Idle revert. Our screens do not time out on their own, so a
            // revealed panel left untouched hands itself back here. Gated on
            // !locked: a panic lockdown is a security state, not an idle
            // screen, and must never lapse into the vendor UI on a timer.
            let idle = ui.last_touch.lock().unwrap().elapsed();
            if ui.visible.load(Ordering::Relaxed)
                && !ui.locked.load(Ordering::Relaxed)
                && idle >= IDLE_REVERT
            {
                ui.visible.store(false, Ordering::Relaxed);
                log::info!("m2100 display: idle for {IDLE_REVERT:?}, handing panel back");
            }
            // Fades over the last DIM_WARN before that revert.
            let dim = dim_factor(idle);

            if !ui.visible.load(Ordering::Relaxed) {
                // An empty write still drives the hand-back on the transition.
                fb.write_buffer(Vec::new()).await;
                tokio::time::sleep(REDRAW).await;
                continue;
            }

            if ui.action.swap(false, Ordering::Relaxed) {
                let recording = !matches!(state, DisplayState::Paused);
                toggle_recording(&client, recording).await;
            }

            if ui.toggle_lockdown.swap(false, Ordering::Relaxed) {
                let want_open = !ui.services_open.load(Ordering::Relaxed);
                apply_services_open(&ui, want_open, port).await;
                // Key the lease off what actually happened, not the request: a
                // lockdown that failed must not start a lease that will later
                // "reopen" something never closed.
                let now_open = ui.services_open.load(Ordering::Relaxed);
                // Closing starts the lease; re-closing while already closed
                // renews it; opening clears it.
                lease_until = if now_open {
                    None
                } else {
                    Some(tokio::time::Instant::now() + LOCKDOWN_LEASE)
                };
                flash_until = Some(tokio::time::Instant::now() + FLASH);
            }

            if ui.peek.swap(false, Ordering::Relaxed) {
                flash_until = Some(tokio::time::Instant::now() + FLASH);
            }

            if ui.egg.swap(false, Ordering::Relaxed) {
                egg_until = Some(tokio::time::Instant::now() + EGG_SHOW);
            }
            // Always reverts: a screen that stays magenta looks broken.
            if let Some(t) = egg_until {
                if tokio::time::Instant::now() >= t {
                    egg_until = None;
                }
            }

            let flashing = match flash_until {
                Some(t) if tokio::time::Instant::now() < t => true,
                Some(_) => {
                    flash_until = None;
                    false
                }
                None => false,
            };
            let services_open = ui.services_open.load(Ordering::Relaxed);

            let (color, pattern) = status_style(state, colorblind);
            match Mode::from_u8(ui.mode.load(Ordering::Relaxed)) {
                Mode::Status => {
                    let t = tel.lock().await;
                    let mut buf = m2100_live::render_status(state, &t, colorblind);
                    drop(t);
                    if let Some(a) = crate::alerts::unacknowledged() {
                        m2100_live::alert_banner(&mut buf, &crate::alerts::banner_text(&a));
                    }
                    if flashing {
                        m2100_live::flash_overlay(&mut buf, services_open);
                    }
                    apply_dim(&mut buf, dim);
                    fb.write_buffer(buf).await;
                    tokio::time::sleep(REDRAW).await;
                }
                Mode::CellLog => {
                    let t = tel.lock().await;
                    let scroll = ui.log_scroll.load(Ordering::Relaxed);
                    let alert = crate::alerts::last().map(|a| (a.eci, a.at));
                    let mut buf = m2100_live::render_log(state, &t, colorblind, scroll, alert);
                    drop(t);
                    if let Some(a) = crate::alerts::unacknowledged() {
                        m2100_live::alert_banner(&mut buf, &crate::alerts::banner_text(&a));
                    }
                    if flashing {
                        m2100_live::flash_overlay(&mut buf, services_open);
                    }
                    apply_dim(&mut buf, dim);
                    fb.write_buffer(buf).await;
                    tokio::time::sleep(REDRAW).await;
                }
                Mode::Orca => {
                    // The spinning mascot's outline follows the status: red while
                    // a warning is active, green otherwise. The swimming pod has
                    // no status-coloured outline, so it is shown as-is.
                    let warning = matches!(
                        state,
                        DisplayState::WarningDetected { event_type }
                            if matches!(
                                event_type,
                                EventType::Low | EventType::Medium | EventType::High
                            )
                    );
                    let frames = if ui.orca_variant.load(Ordering::Relaxed) {
                        if warning && !orca_spin_red.is_empty() {
                            &orca_spin_red
                        } else {
                            &orca_spin
                        }
                    } else {
                        &orca
                    };
                    if frames.is_empty() {
                        tokio::time::sleep(REDRAW).await;
                        continue;
                    }
                    for (frame, delay_ms) in frames {
                        if !ui.visible.load(Ordering::Relaxed) {
                            break;
                        }
                        let mut buf = frame.clone();
                        paint_bar(&mut buf, color, pattern);
                        if flashing {
                            m2100_live::flash_overlay(&mut buf, services_open);
                        }
                        apply_dim(&mut buf, dim);
                        fb.write_buffer(buf).await;
                        tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
                    }
                }
                Mode::EffLogo if egg_until.is_some() => {
                    fb.write_buffer(m2100_live::render_egg()).await;
                    tokio::time::sleep(REDRAW).await;
                }
                Mode::EffLogo => {
                    if let Some(img) = &eff {
                        let mut buf = img.clone();
                        paint_bar(&mut buf, color, pattern);
                        if flashing {
                            m2100_live::flash_overlay(&mut buf, services_open);
                        }
                        apply_dim(&mut buf, dim);
                        fb.write_buffer(buf).await;
                    }
                    tokio::time::sleep(REDRAW).await;
                }
            }
        }
    });
}

fn status_style(state: DisplayState, colorblind: bool) -> (Color, LinePattern) {
    match state {
        DisplayState::Paused => (Color::White, LinePattern::Solid),
        DisplayState::Recording => {
            if colorblind {
                (Color::Blue, LinePattern::Solid)
            } else {
                (Color::Green, LinePattern::Solid)
            }
        }
        DisplayState::WarningDetected { event_type } => match event_type {
            EventType::Informational if colorblind => (Color::Blue, LinePattern::Solid),
            EventType::Informational => (Color::Green, LinePattern::Solid),
            EventType::Low => (Color::Yellow, LinePattern::Dotted),
            EventType::Medium => (Color::Orange, LinePattern::Dashed),
            EventType::High => (Color::Red, LinePattern::Solid),
        },
    }
}

/// Composite the two-row status bar into a frame, rather than writing it
/// separately: a second write per frame leaves the panel holding a bar-less
/// image for part of every frame, which reads as a flicker.
fn paint_bar(buf: &mut [(u8, u8, u8)], color: Color, pattern: LinePattern) {
    let rgb = color.rgb();
    for row in 0..2u32 {
        for col in 0..WIDTH {
            let Some(px) = buf.get_mut((row * WIDTH + col) as usize) else {
                return;
            };
            let on = match pattern {
                LinePattern::Solid => true,
                LinePattern::Dashed => (col / 4) % 2 == 0,
                LinePattern::Dotted => col % 4 == 0,
            };
            *px = if on { rgb } else { (0, 0, 0) };
        }
    }
}

fn load_gif(fb: &impl GenericFramebuffer, name: &str) -> Vec<(Vec<(u8, u8, u8)>, u64)> {
    use image::{AnimationDecoder, DynamicImage, codecs::gif::GifDecoder};
    let Some(bytes) = super::generic_framebuffer::image_asset(name) else {
        return Vec::new();
    };
    match GifDecoder::new(std::io::Cursor::new(bytes)) {
        Ok(d) => d
            .into_frames()
            .filter_map(|f| f.ok())
            .map(|frame| {
                let (num, _) = frame.delay().numer_denom_ms();
                (
                    fb.prepare_image(DynamicImage::from(frame.into_buffer())),
                    num as u64,
                )
            })
            .collect(),
        Err(e) => {
            log::warn!("m2100 display: couldn't decode {name}: {e}");
            Vec::new()
        }
    }
}

fn load_eff(fb: &impl GenericFramebuffer) -> Option<Vec<(u8, u8, u8)>> {
    let bytes = super::generic_framebuffer::image_asset("eff.png")?;
    match image::load_from_memory(bytes) {
        Ok(img) => Some(fb.prepare_image(img)),
        Err(e) => {
            log::warn!("m2100 display: couldn't decode eff.png: {e}");
            None
        }
    }
}

fn handle_request(ui: &Ui, p: &Paths, now: std::time::Instant) {
    let Some(req) = m2100_enrol::take_request(p) else {
        return;
    };
    if ui.locked.load(Ordering::Relaxed) {
        m2100_enrol::write_result(p, "ignored locked");
        return;
    }
    match req {
        m2100_enrol::Request::Reload => {
            *ui.reveal.lock().unwrap() = m2100_enrol::load_reveal(p);
            *ui.pin.lock().unwrap() = PanicConfig::load_from(&p.panic()).map(Arc::new);
            m2100_enrol::write_result(p, "ok reload");
        }
        m2100_enrol::Request::Pin => {
            // The PIN pad covers the whole panel, so on the stock screen its holds
            // would open vendor menus. It is set from settings only (spec 3a).
            m2100_enrol::write_result(p, "ignored pin-on-panel-only");
        }
        m2100_enrol::Request::Gesture => {
            // From the laptop: whoever can reach ADB already has root, so no
            // verification of the current secret is asked for here. The stock
            // screen stays up: taking the panel over while the screen is asleep
            // leaves touch input dead (measured 2026-10-07), and every move in
            // the vocabulary is one the vendor UI ignores anyway.
            *ui.enrol.lock().unwrap() = Some(m2100_enrol::Enrolment::new(
                m2100_enrol::Target::Gesture,
                None,
                now,
            ));
        }
    }
}

/// Store a finished enrolment and leave the screen. Returns the result line
/// written, or `None` while the enrolment is still in progress.
fn finish_enrolment(ui: &Ui, p: &Paths) -> Option<&'static str> {
    let mut slot = ui.enrol.lock().unwrap();
    let e = slot.as_ref()?;
    let target = e.target;
    let result = match (e.stage(), e.target) {
        (m2100_enrol::Stage::Done(codes), m2100_enrol::Target::Gesture) => {
            match m2100_enrol::save_reveal(p, codes) {
                Ok(()) => {
                    *ui.reveal.lock().unwrap() = m2100_enrol::load_reveal(p);
                    log::info!("m2100 display: reveal gesture set");
                    "ok gesture"
                }
                Err(e) => {
                    log::warn!("m2100 display: couldn't store gesture: {e}");
                    "failed write"
                }
            }
        }
        (m2100_enrol::Stage::Done(codes), m2100_enrol::Target::Pin) => {
            let dev = ui.pin.lock().unwrap().as_ref().is_some_and(|c| c.dev_mode);
            match PanicConfig::store(&p.panic(), codes, dev) {
                Ok(()) => {
                    *ui.pin.lock().unwrap() = PanicConfig::load_from(&p.panic()).map(Arc::new);
                    log::info!("m2100 display: panic PIN set");
                    "ok pin"
                }
                Err(e) => {
                    log::warn!("m2100 display: couldn't store PIN: {e}");
                    "failed write"
                }
            }
        }
        (m2100_enrol::Stage::Failed(m2100_enrol::Fail::TimedOut), _) => "failed timed-out",
        _ => return None,
    };
    *slot = None;
    drop(slot);
    ui.settings.store(false, Ordering::Relaxed);
    if target == m2100_enrol::Target::Pin {
        // The PIN screen had the panel (via settings); hand it back. A gesture
        // enrolment never took it.
        ui.visible.store(false, Ordering::Relaxed);
    }
    m2100_enrol::write_result(p, result);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The orca variant flips on a tap in the SAME corner that reaches the
    /// screen. It used to flip on a tap anywhere, which overlapped the short
    /// centre tap that peeks at the lockdown state: one tap in the middle both
    /// swapped the orca and popped the ON/OFF overlay.
    #[test]
    fn orca_toggles_from_its_own_corner() {
        assert!(taps_orca_toggle(Mode::Orca, 300, 10));
        // The real calibrated top-right tap, not just a synthetic one.
        assert!(taps_orca_toggle(Mode::Orca, 304, 20));
    }

    #[test]
    fn a_centre_tap_does_not_flip_the_orca() {
        // This is the reported bug: the centre belongs to the lockdown peek.
        assert!(!taps_orca_toggle(Mode::Orca, 160, 120));
        assert!(!taps_orca_toggle(Mode::Orca, 150, 210));
    }

    #[test]
    fn other_corners_do_not_flip_the_orca() {
        assert!(!taps_orca_toggle(Mode::Orca, 10, 10));
        assert!(!taps_orca_toggle(Mode::Orca, 10, 220));
        assert!(!taps_orca_toggle(Mode::Orca, 300, 220));
    }

    #[test]
    fn orca_corner_only_flips_while_the_orca_is_showing() {
        assert!(!taps_orca_toggle(Mode::Status, 300, 10));
        assert!(!taps_orca_toggle(Mode::CellLog, 300, 10));
    }

    /// The LED was Rayhunter's only status channel before the panel worked, and
    /// the LiveStatus backend never inherited it. It reports whether Rayhunter
    /// is RUNNING -- independent of whether its screens happen to be up, since
    /// the screen sleeps and the question does not.
    #[test]
    fn led_shows_the_heartbeat_whenever_rayhunter_is_recording() {
        assert_eq!(led_for(false, DisplayState::Recording), Led::Heartbeat);
    }

    #[test]
    fn led_shows_the_heartbeat_during_a_warning_too() {
        // A warning still means running; the panel carries the severity.
        assert_eq!(
            led_for(
                false,
                DisplayState::WarningDetected {
                    event_type: EventType::Low
                }
            ),
            Led::Heartbeat
        );
    }

    #[test]
    fn led_falls_back_to_the_vendor_when_paused() {
        assert_eq!(led_for(false, DisplayState::Paused), Led::Vendor);
    }

    #[test]
    fn a_panic_lockdown_looks_exactly_like_stock() {
        // The whole point of panic is that the device gives nothing away, so
        // the LED must not keep announcing that Rayhunter is alive.
        assert_eq!(led_for(true, DisplayState::Recording), Led::Vendor);
        assert_eq!(
            led_for(
                true,
                DisplayState::WarningDetected {
                    event_type: EventType::High
                }
            ),
            Led::Vendor
        );
    }

    #[test]
    fn corners_map_to_modes() {
        assert_eq!(Mode::from_corner(10, 10), Some(Mode::CellLog));
        assert_eq!(Mode::from_corner(300, 10), Some(Mode::Orca));
        assert_eq!(Mode::from_corner(10, 220), Some(Mode::EffLogo));
        assert_eq!(Mode::from_corner(300, 220), Some(Mode::Status));
        // Calibrated real taps: top-left (31,33), bottom-right (304,205).
        assert_eq!(Mode::from_corner(31, 33), Some(Mode::CellLog));
        assert_eq!(Mode::from_corner(304, 205), Some(Mode::Status));
    }

    #[test]
    fn centre_is_not_a_corner() {
        assert_eq!(Mode::from_corner(160, 120), None);
        assert_eq!(Mode::from_corner(150, 210), None);
    }

    /// The control must be unreachable by a corner gesture, and vice versa,
    /// or a mode switch and an action could fire from the same touch.
    #[test]
    fn control_never_overlaps_a_corner() {
        for x in m2100_live::BTN_X..(m2100_live::BTN_X + m2100_live::BTN_W) {
            for y in m2100_live::BTN_Y..(m2100_live::BTN_Y + m2100_live::BTN_H) {
                assert_eq!(
                    Mode::from_corner(x as i32, y as i32),
                    None,
                    "control pixel ({x},{y}) lies in a corner zone"
                );
            }
        }
    }

    /// The lockdown gesture must be unreachable from any corner, or a mode
    /// switch and a lockdown could arm from the same touch.
    #[test]
    fn centre_band_never_overlaps_a_corner() {
        for x in 0..WIDTH as i32 {
            if !is_centre(x) {
                continue;
            }
            for y in (0..HEIGHT as i32).step_by(7) {
                assert_eq!(
                    Mode::from_corner(x, y),
                    None,
                    "centre x={x} y={y} lies in a corner zone"
                );
            }
        }
    }

    /// Wherever the control is drawn, every pixel of it must arm the recording
    /// action -- never a lockdown, never a mode switch. This replaced a test
    /// that asserted the control sat inside the centre band, which described
    /// where the button happened to be rather than what has to be true: the
    /// button has since moved off the RSRP trace and out of that band, and the
    /// guarantee is unchanged because it comes from the order of the checks.
    #[test]
    fn every_pixel_of_the_control_arms_the_action() {
        for x in m2100_live::BTN_X..(m2100_live::BTN_X + m2100_live::BTN_W) {
            for y in m2100_live::BTN_Y..(m2100_live::BTN_Y + m2100_live::BTN_H) {
                assert_eq!(
                    classify_touch(true, Mode::Status, x as i32, y as i32),
                    Some((Hold::Control, ACTION_HOLD)),
                    "control pixel ({x},{y}) does not arm the action"
                );
            }
        }
    }

    /// The other two rungs of the precedence ladder, so removing either is
    /// caught. Without these, deleting the corner branch broke nothing that
    /// any test noticed.
    #[test]
    fn a_corner_arms_a_mode_switch() {
        assert_eq!(
            classify_touch(true, Mode::Status, 300, 10),
            Some((Hold::Switch(Mode::Orca), MODE_HOLD))
        );
        assert_eq!(
            classify_touch(true, Mode::Status, 10, 220),
            Some((Hold::Switch(Mode::EffLogo), MODE_HOLD))
        );
    }

    #[test]
    fn the_centre_away_from_the_control_arms_a_lockdown() {
        // Mid-screen, clear of both the corners and the button.
        assert_eq!(
            classify_touch(true, Mode::Status, 150, 170),
            Some((Hold::Lockdown, LOCKDOWN_HOLD))
        );
    }

    /// And the control only exists on the Status screen.
    #[test]
    fn the_control_is_inert_on_other_screens() {
        let x = (m2100_live::BTN_X + 5) as i32;
        let y = (m2100_live::BTN_Y + 5) as i32;
        assert_ne!(
            classify_touch(true, Mode::Orca, x, y),
            Some((Hold::Control, ACTION_HOLD))
        );
    }

    #[test]
    fn dim_is_full_until_the_warning_window() {
        assert_eq!(dim_factor(Duration::from_secs(0)), 256);
        assert_eq!(
            dim_factor(IDLE_REVERT - DIM_WARN - Duration::from_secs(1)),
            256
        );
    }

    #[test]
    fn dim_fades_but_never_to_black() {
        // Entering the window: full.
        assert_eq!(dim_factor(IDLE_REVERT - DIM_WARN), 256);
        // Right before revert: at the floor, never 0.
        let end = dim_factor(IDLE_REVERT - Duration::from_millis(1));
        assert!(
            (DIM_FLOOR..=DIM_FLOOR + 8).contains(&end),
            "should floor, got {end}"
        );
        // Quadratic: still bright at the halfway point (frac^2 = 0.25), then
        // drops -- and monotonic throughout.
        let mid = dim_factor(IDLE_REVERT - DIM_WARN / 2);
        let entering = dim_factor(IDLE_REVERT - DIM_WARN);
        assert!(
            end < mid && mid < entering,
            "monotonic: {end} {mid} {entering}"
        );
        assert!(
            mid < 128,
            "past halfway it should be visibly dim, got {mid}"
        );
    }

    #[test]
    fn apply_dim_scales_and_full_is_noop() {
        let mut buf = vec![(200u8, 100, 40)];
        apply_dim(&mut buf, 256);
        assert_eq!(buf[0], (200, 100, 40), "256 is a no-op");
        apply_dim(&mut buf, 128);
        assert_eq!(buf[0], (100, 50, 20), "half brightness");
    }

    #[test]
    fn mode_round_trips_through_u8() {
        for m in [Mode::Status, Mode::CellLog, Mode::Orca, Mode::EffLogo] {
            assert_eq!(Mode::from_u8(m.as_u8()), m);
        }
    }

    // ---- 2026-10-02: edge taps ----------------------------------------------

    /// The safety property: an edge tap can never land on a corner (mode switch)
    /// or the centre band (lockdown), so it cannot be half of another gesture.
    #[test]
    fn edge_taps_never_overlap_a_corner_or_the_centre() {
        for x in (0..WIDTH as i32).step_by(4) {
            for y in (0..HEIGHT as i32).step_by(4) {
                if edge_tap(x, y).is_some() {
                    assert!(Mode::from_corner(x, y).is_none(), "corner at {x},{y}");
                    assert!(!is_centre(x), "centre band at {x},{y}");
                }
            }
        }
    }

    #[test]
    fn the_edges_map_to_their_actions() {
        assert_eq!(edge_tap(10, 120), Some(EdgeTap::Left));
        assert_eq!(edge_tap(300, 80), Some(EdgeTap::RightUpper));
        assert_eq!(edge_tap(300, 160), Some(EdgeTap::RightLower));
        assert_eq!(edge_tap(10, 10), None, "top-left corner switches modes");
        assert_eq!(edge_tap(160, 120), None, "the centre is the lockdown band");
    }

    use crate::display::m2100_gesture::{Matcher, Touch};
    use crate::display::m2100_secret::Secret;
    use std::time::Instant;

    fn test_ui() -> Ui {
        Ui {
            visible: Arc::new(AtomicBool::new(false)),
            mode: AtomicU8::new(Mode::CellLog.as_u8()),
            action: AtomicBool::new(false),
            toggle_lockdown: AtomicBool::new(false),
            peek: AtomicBool::new(false),
            services_open: AtomicBool::new(true),
            panic: AtomicBool::new(false),
            locked: AtomicBool::new(false),
            unlock: AtomicBool::new(false),
            egg: AtomicBool::new(false),
            orca_variant: AtomicBool::new(false),
            log_scroll: AtomicUsize::new(0),
            last_touch: Mutex::new(tokio::time::Instant::now()),
            reveal: Mutex::new(None),
            enrol: Mutex::new(None),
            pin: Mutex::new(None),
            settings: AtomicBool::new(false),
            profile_screen: AtomicBool::new(false),
            profile_note: Mutex::new(ProfileNote::Hold),
            ntfy_url: None,
        }
    }

    fn swipe(dx: i32) -> Touch {
        Touch {
            start: (160, 120),
            end: (160 + dx, 120),
            held: std::time::Duration::from_millis(400),
        }
    }
    fn bar_tap(x: i32) -> Touch {
        Touch {
            start: (x, 20),
            end: (x, 20),
            held: std::time::Duration::from_millis(100),
        }
    }

    #[test]
    fn the_stock_screen_has_no_corner_reveal_any_more() {
        for (x, y) in [(10, 10), (310, 10), (10, 230), (310, 230)] {
            assert_eq!(
                classify_touch(false, Mode::Status, x, y),
                None,
                "corner {x},{y}"
            );
        }
        // Inside Rayhunter's UI the corners still switch modes.
        assert!(matches!(
            classify_touch(true, Mode::Status, 10, 10),
            Some((Hold::Switch(_), _))
        ));
    }

    #[test]
    fn the_stored_gesture_reveals_the_status_screen() {
        let ui = test_ui();
        // swipe right, swipe left, bar left, bar middle, bar right
        *ui.reveal.lock().unwrap() = Some(Secret::create(&[3, 2, 4, 5, 6]));
        let mut m = Matcher::new(5);
        let t = Instant::now();
        assert!(!stock_release(&ui, &mut m, &swipe(200), t));
        assert!(!stock_release(&ui, &mut m, &swipe(-200), t));
        assert!(!stock_release(&ui, &mut m, &bar_tap(40), t));
        assert!(!stock_release(&ui, &mut m, &bar_tap(160), t));
        assert!(stock_release(&ui, &mut m, &bar_tap(300), t));
        assert!(ui.visible.load(Ordering::Relaxed));
        assert_eq!(Mode::from_u8(ui.mode.load(Ordering::Relaxed)), Mode::Status);
    }

    #[test]
    fn with_no_gesture_stored_nothing_reveals() {
        let ui = test_ui();
        let mut m = Matcher::new(4);
        let t = Instant::now();
        for tch in [swipe(200), swipe(-200), bar_tap(40), bar_tap(300)] {
            assert!(!stock_release(&ui, &mut m, &tch, t));
        }
        assert!(!ui.visible.load(Ordering::Relaxed));
    }

    #[test]
    fn a_vendor_area_touch_breaks_the_sequence() {
        let ui = test_ui();
        *ui.reveal.lock().unwrap() = Some(Secret::create(&[3, 2, 4, 8]));
        let mut m = Matcher::new(4);
        let t = Instant::now();
        stock_release(&ui, &mut m, &swipe(200), t);
        stock_release(&ui, &mut m, &swipe(-200), t);
        // A plain tap on the vendor's tiles: not a move, so it resets the entry.
        stock_release(
            &ui,
            &mut m,
            &Touch {
                start: (160, 140),
                end: (160, 140),
                held: std::time::Duration::from_millis(100),
            },
            t,
        );
        stock_release(&ui, &mut m, &bar_tap(40), t);
        assert!(!stock_release(&ui, &mut m, &bar_tap(300), t));
    }

    #[test]
    fn nothing_reveals_while_locked() {
        // Review focus 4.
        let ui = test_ui();
        ui.locked.store(true, Ordering::Relaxed);
        *ui.reveal.lock().unwrap() = Some(Secret::create(&[3, 2, 4, 8]));
        let mut m = Matcher::new(4);
        let t = Instant::now();
        for tch in [swipe(200), swipe(-200), bar_tap(40), bar_tap(300)] {
            assert!(!stock_release(&ui, &mut m, &tch, t));
        }
        assert!(!ui.visible.load(Ordering::Relaxed));
    }

    fn scratch_paths(name: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("rh-ui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Paths { dir }
    }

    #[test]
    fn a_gesture_request_enrols_on_the_stock_screen() {
        let ui = test_ui();
        let p = scratch_paths("req");
        std::fs::write(p.request(), "gesture").unwrap();
        handle_request(&ui, &p, Instant::now());
        assert!(ui.enrol.lock().unwrap().is_some());
        assert!(
            !ui.visible.load(Ordering::Relaxed),
            "the vendor UI keeps the panel"
        );
    }

    #[test]
    fn a_request_while_locked_is_answered_ignored() {
        // Review focus 4.
        let ui = test_ui();
        ui.locked.store(true, Ordering::Relaxed);
        let p = scratch_paths("locked");
        std::fs::write(p.request(), "gesture").unwrap();
        handle_request(&ui, &p, Instant::now());
        assert!(ui.enrol.lock().unwrap().is_none());
        assert_eq!(
            std::fs::read_to_string(p.result()).unwrap().trim(),
            "ignored locked"
        );
    }

    #[test]
    fn a_completed_enrolment_is_stored_and_the_panel_goes_back_to_stock() {
        let ui = test_ui();
        let p = scratch_paths("done");
        let mut t = Instant::now();
        let mut e = m2100_enrol::Enrolment::new(m2100_enrol::Target::Gesture, None, t);
        for _ in 0..2 {
            for c in [0u8, 5, 6, 3, 1] {
                t += std::time::Duration::from_millis(400);
                e.push(c, t);
            }
            t += m2100_enrol::PERFORM_END + std::time::Duration::from_millis(1);
            e.tick(t);
        }
        *ui.enrol.lock().unwrap() = Some(e);
        ui.visible.store(true, Ordering::Relaxed);
        assert_eq!(finish_enrolment(&ui, &p), Some("ok gesture"));
        assert!(
            ui.reveal
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .matches(&[0, 5, 6, 3, 1])
        );
        assert!(
            m2100_enrol::load_reveal(&p)
                .unwrap()
                .matches(&[0, 5, 6, 3, 1])
        );
        assert!(ui.enrol.lock().unwrap().is_none());
    }

    #[test]
    fn an_unfinished_enrolment_stores_nothing() {
        // Review focus 2: only Done writes; a restart mid-enrolment loses only the attempt.
        let ui = test_ui();
        let p = scratch_paths("partial");
        m2100_enrol::save_reveal(&p, &[1, 2, 3, 4]).unwrap();
        let t = Instant::now();
        let mut e = m2100_enrol::Enrolment::new(m2100_enrol::Target::Gesture, None, t);
        e.push(7, t);
        *ui.enrol.lock().unwrap() = Some(e);
        assert_eq!(finish_enrolment(&ui, &p), None);
        assert!(
            m2100_enrol::load_reveal(&p).unwrap().matches(&[1, 2, 3, 4]),
            "old gesture intact"
        );
    }

    #[test]
    fn a_pin_enrolled_on_the_panel_arms_panic() {
        let ui = test_ui();
        let p = scratch_paths("pin");
        let mut t = Instant::now();
        let mut e = m2100_enrol::Enrolment::new(m2100_enrol::Target::Pin, None, t);
        for _ in 0..2 {
            for d in [3u8, 1, 4, 1, 5, 9] {
                t += std::time::Duration::from_millis(700);
                e.push(d, t);
            }
            t += m2100_enrol::PERFORM_END + std::time::Duration::from_millis(1);
            e.tick(t);
        }
        *ui.enrol.lock().unwrap() = Some(e);
        assert_eq!(finish_enrolment(&ui, &p), Some("ok pin"));
        let armed = ui.pin.lock().unwrap().clone().expect("armed");
        assert!(armed.matches(&[3, 1, 4, 1, 5, 9]));
    }

    #[test]
    fn holding_the_left_edge_opens_settings_and_corners_still_win() {
        assert!(
            matches!(classify_touch(true, Mode::Status, 20, 120), Some((Hold::Settings, d)) if d == SETTINGS_HOLD)
        );
        assert!(matches!(
            classify_touch(true, Mode::Status, 20, 20),
            Some((Hold::Switch(_), _))
        ));
        assert!(matches!(
            classify_touch(true, Mode::Status, 20, 220),
            Some((Hold::Switch(_), _))
        ));
        assert_eq!(
            classify_touch(false, Mode::Status, 20, 120),
            None,
            "never from the stock screen"
        );
    }

    #[test]
    fn the_settings_rows_choose_what_to_change() {
        // Four 48 px rows with 16 px dead bands between them: a tap that lands
        // between two rows must choose neither.
        use m2100_enrol::Target;
        for y in 0..HEIGHT as i32 {
            let want = match y {
                0..=47 => Some(SettingsChoice::Enrol(Target::Gesture)),
                64..=111 => Some(SettingsChoice::Buzzer),
                128..=175 => Some(SettingsChoice::Profile),
                192..=239 => Some(SettingsChoice::Enrol(Target::Pin)),
                _ => None,
            };
            assert_eq!(settings_choice(y), want, "y={y}");
        }
    }

    #[test]
    fn the_profile_screen_has_fixed_on_top_and_mobile_below() {
        // The corners stay corners, so a hold there leaves the screen instead
        // of switching the profile (unit 1, 2026-10-09: trying to get back to
        // the status screen switched to Mobile and back).
        for x in 0..WIDTH as i32 {
            for y in 0..HEIGHT as i32 {
                let want = match y {
                    _ if Mode::from_corner(x, y).is_some() => None,
                    0..=103 => Some(Profile::Fixed),
                    136..=239 => Some(Profile::Mobile),
                    _ => None, // the note band
                };
                assert_eq!(profile_target(x, y), want, "x={x} y={y}");
            }
        }
    }

    #[test]
    fn a_corner_hold_leaves_settings_for_that_screen_never_for_stock() {
        // Leaving: always show the corner's screen, even the current mode.
        assert_eq!(after_corner_hold(true, Mode::Status, Mode::Status, true), Some(Mode::Status));
        assert_eq!(after_corner_hold(true, Mode::Status, Mode::Orca, true), Some(Mode::Orca));
        // Not leaving: the corner of the mode on screen hides, as before.
        assert_eq!(after_corner_hold(true, Mode::Status, Mode::Status, false), None);
        assert_eq!(after_corner_hold(true, Mode::Status, Mode::Orca, false), Some(Mode::Orca));
        assert_eq!(after_corner_hold(false, Mode::Status, Mode::Status, false), Some(Mode::Status));
    }

    #[test]
    fn a_failed_boot_re_apply_shows_when_the_profile_screen_opens() {
        assert_eq!(opening_note(false, false), ProfileNote::Hold);
        assert_eq!(opening_note(false, true), ProfileNote::Failed);
        assert_eq!(opening_note(true, true), ProfileNote::Switching);
    }

    #[test]
    fn the_boot_re_apply_does_not_depend_on_the_ui_level() {
        // It must run for Invisible and Subtle too, so it is started from
        // main.rs, outside the display choice, never from this module.
        let main = include_str!("../main.rs");
        let call = main
            .find("m2100_profile_io::spawn_boot_reapply(")
            .expect("called");
        let branch = main.find("UiLevel::Invisible").unwrap();
        assert!(
            call > main[branch..].find("};").unwrap() + branch,
            "after the display choice"
        );
        assert!(!include_str!("m2100_ui.rs").contains(&["m2100_profile_io::", "apply("].concat()));
    }

    #[test]
    fn a_hold_switches_or_re_applies_but_never_mid_switch() {
        // Holding the current profile re-applies it, so a unit that drifted
        // (data turned on by something else) can be put back from the panel.
        use Profile::*;
        assert!(hold_switches(Mobile, Fixed, false));
        assert!(hold_switches(Fixed, Mobile, false));
        assert!(hold_switches(Fixed, Fixed, false), "re-apply");
        assert!(hold_switches(Mobile, Mobile, false), "re-apply");
        assert!(!hold_switches(Mobile, Fixed, true), "mid-switch");
        assert!(!hold_switches(Fixed, Fixed, true), "mid-switch");
    }

    #[test]
    fn rayhunters_own_heartbeat_is_never_mistaken_for_the_vendors_led() {
        // 2026-10-08: after a daemon restart (not a reboot) the LED was still in
        // our heartbeat when it was saved as "the vendor's", so a panic lock
        // replayed Rayhunter's 5 s rhythm -- the one thing that tells it apart.
        let st = |trigger: &str, on: Option<&str>, off: Option<&str>| LedState {
            trigger: trigger.to_string(),
            brightness: Some("255".to_string()),
            delay_on: on.map(str::to_string),
            delay_off: off.map(str::to_string),
        };
        let ours = st("timer", Some(LED_HB_ON), Some(LED_HB_OFF));
        let got = vendor_from_saved(ours);
        assert_eq!(
            got.trigger, "none",
            "fall back to dark, as the vendor leaves it"
        );
        assert_eq!(got.brightness.as_deref(), Some("0"));
        // A genuine vendor state is kept exactly.
        let vendor = st("timer", Some("500"), Some("5500"));
        assert_eq!(vendor_from_saved(vendor.clone()), vendor);
        let dark = st("none", None, None);
        assert_eq!(vendor_from_saved(dark.clone()), dark);
    }

    #[test]
    fn the_panic_signal_is_fast_blinks_unlike_the_heartbeat() {
        // 2026-10-08: a 3 s steady glow read like a long heartbeat (1 s on every
        // 5 s). Fast blinking is the opposite of anything the heartbeat does.
        assert!(PANIC_SETTLE >= Duration::from_secs(1));
        assert!(PANIC_BLINKING >= Duration::from_secs(2));
        let (on, off): (u64, u64) = (
            PANIC_BLINK_ON.parse().unwrap(),
            PANIC_BLINK_OFF.parse().unwrap(),
        );
        assert!(
            on <= 150 && off <= 150,
            "fast: at least ~3 flashes a second"
        );
        assert!(
            on * 4 <= LED_HB_ON.parse::<u64>().unwrap(),
            "far shorter than a heartbeat flash"
        );
    }

    #[test]
    fn a_new_alert_beeps_once_and_a_worse_one_beeps_again() {
        use DisplayState::*;
        let w = |t| WarningDetected { event_type: t };
        assert_eq!(
            alert_beep_for(Recording, w(EventType::Low)),
            Some(EventType::Low)
        );
        assert_eq!(
            alert_beep_for(Paused, w(EventType::Medium)),
            Some(EventType::Medium)
        );
        // The same alert re-sent with every analysed batch must not beep again.
        assert_eq!(alert_beep_for(w(EventType::Low), w(EventType::Low)), None);
        assert_eq!(alert_beep_for(w(EventType::High), w(EventType::Low)), None);
        // Escalation is news.
        assert_eq!(
            alert_beep_for(w(EventType::Low), w(EventType::High)),
            Some(EventType::High)
        );
        // Informational never beeps, and nothing beeps for a non-warning.
        assert_eq!(alert_beep_for(Recording, w(EventType::Informational)), None);
        assert_eq!(alert_beep_for(w(EventType::High), Recording), None);
    }

    #[test]
    fn changing_from_settings_requires_the_current_secret() {
        let ui = test_ui();
        *ui.reveal.lock().unwrap() = Some(Secret::create(&[3, 2, 4, 8]));
        start_from_settings(&ui, m2100_enrol::Target::Gesture, Instant::now());
        let slot = ui.enrol.lock().unwrap();
        assert_eq!(slot.as_ref().unwrap().stage(), &m2100_enrol::Stage::Verify);
    }

    #[test]
    fn a_pin_request_from_the_laptop_is_refused() {
        // PIN enrolment needs its own screen; it starts only from settings.
        let ui = test_ui();
        let p = scratch_paths("pinreq");
        std::fs::write(p.request(), "pin").unwrap();
        handle_request(&ui, &p, Instant::now());
        assert!(ui.enrol.lock().unwrap().is_none());
        assert_eq!(
            std::fs::read_to_string(p.result()).unwrap().trim(),
            "ignored pin-on-panel-only"
        );
    }

    #[test]
    fn a_failed_gesture_enrolment_restarts_by_itself() {
        // Review focus 3: a tap to retry would land on the vendor UI.
        let ui = test_ui();
        let mut t = Instant::now();
        let mut e = m2100_enrol::Enrolment::new(m2100_enrol::Target::Gesture, None, t);
        e.push(1, t);
        *ui.enrol.lock().unwrap() = Some(e);
        t += m2100_enrol::PERFORM_END + std::time::Duration::from_millis(1);
        assert_eq!(enrolment_tick(&ui, t), Some(m2100_enrol::Cue::Failed));
        assert_eq!(
            ui.enrol.lock().unwrap().as_ref().unwrap().stage(),
            &m2100_enrol::Stage::First
        );
    }

    #[test]
    fn a_saved_gesture_leaves_the_panel_stock() {
        let ui = test_ui();
        let p = scratch_paths("stock-done");
        let mut t = Instant::now();
        let mut e = m2100_enrol::Enrolment::new(m2100_enrol::Target::Gesture, None, t);
        for _ in 0..2 {
            for c in [0u8, 5, 6, 3, 1] {
                t += std::time::Duration::from_millis(400);
                e.push(c, t);
            }
            t += m2100_enrol::PERFORM_END + std::time::Duration::from_millis(1);
            e.tick(t);
        }
        *ui.enrol.lock().unwrap() = Some(e);
        assert_eq!(finish_enrolment(&ui, &p), Some("ok gesture"));
        assert!(!ui.visible.load(Ordering::Relaxed));
    }

    #[test]
    fn choosing_the_gesture_in_settings_hands_the_panel_back_to_stock() {
        let ui = test_ui();
        ui.visible.store(true, Ordering::Relaxed);
        start_from_settings(&ui, m2100_enrol::Target::Gesture, Instant::now());
        assert!(!ui.visible.load(Ordering::Relaxed));
        start_from_settings(&ui, m2100_enrol::Target::Pin, Instant::now());
        assert!(
            ui.visible.load(Ordering::Relaxed),
            "the PIN keeps its own screen"
        );
    }

    #[test]
    fn a_reload_during_an_enrolment_leaves_it_running() {
        // Review focus 5.
        let ui = test_ui();
        let p = scratch_paths("reload-mid");
        *ui.enrol.lock().unwrap() = Some(m2100_enrol::Enrolment::new(
            m2100_enrol::Target::Gesture,
            None,
            Instant::now(),
        ));
        std::fs::write(p.request(), "reload").unwrap();
        handle_request(&ui, &p, Instant::now());
        assert!(ui.enrol.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn overlapping_cues_are_dropped_not_queued() {
        // Overlapping cues are dropped, never queued: the flag is clear afterwards.
        assert!(!CUE_PLAYING.load(Ordering::Relaxed));
        CUE_PLAYING.store(true, Ordering::Relaxed);
        play_cue(m2100_enrol::Cue::Move).await; // returns at once: one is "playing"
        assert!(
            CUE_PLAYING.load(Ordering::Relaxed),
            "the second cue didn't take over"
        );
        CUE_PLAYING.store(false, Ordering::Relaxed);
    }
}
