//! Panic lockdown: arming, PIN storage, and silent PIN entry.
//!
//! # Off unless armed
//!
//! Every part of this is disabled unless [`PANIC_CONF`] exists. There is no
//! config option and nothing in any screen that hints at it, because the
//! feature can brick the device: forget the PIN or lose the digitiser and there
//! is no ADB, no web UI and no gesture, only a reflash. Its existence on a given
//! device is the arming, and is meant to travel by word of mouth rather than by
//! being discoverable on the device.
//!
//! # What it protects
//!
//! It defeats *inspection*: someone who takes the device, power-cycles it and
//! plugs in a cable finds a MiFi with no ADB and no web interface. It does not
//! defeat *forensics*: the captures are unencrypted on flash, and anyone who
//! reads the flash directly has them regardless. Protecting against that is a
//! different and much larger piece of work.
//!
//! # The PIN pad
//!
//! While locked, the screen is divided into an invisible 3x3 grid numbered 1-9
//! left-to-right, top-to-bottom. Each digit is a two-second hold. Nothing is
//! drawn, nothing is acknowledged, and a wrong entry produces no response at
//! all -- there is no indication that a pad exists.
//!
//! Entry is matched against a rolling window of the last `len` digits rather
//! than a fixed-length buffer with a submit action. That supports a PIN of any
//! length and lets a fumbled start slide harmlessly out of the window, but it
//! means an attacker gets a fresh candidate every digit rather than every
//! `len` digits. At one second a digit that is about 1.8 hours to exhaust a
//! four-digit PIN, six days for six digits and over a year for eight — so six
//! is the practical floor and eight is cheap insurance, since entry cost grows
//! only a couple of seconds.

use crate::display::m2100_secret::{self, Secret};
use std::path::Path;
use std::time::Duration;

/// Presence of this file arms the feature. Absent, none of this exists.
const PANIC_CONF: &str = "/data/rayhunter/.panic";
/// Written when a panic lockdown is engaged, so it survives a reboot.
const PANIC_FLAG: &str = "/data/rayhunter/.panic_engaged";

/// How long a digit must be held.
///
/// Set from measurement rather than intuition. Twenty-two touches captured on
/// this hardware split cleanly in two: twelve deliberate "about a second"
/// holds ran 1.068-1.674 s, and nine ordinary taps ran 0.032-0.151 s. Nothing
/// landed between. Half a second sits in the middle of a sevenfold gap, so it
/// separates the two with enormous margin in both directions and removes any
/// need to judge an interval -- "press deliberately" rather than "hold for one
/// second", which is a far easier instruction to follow under pressure.
///
/// A tap would be quicker but is the wrong trade. The same capture showed the
/// hold is really an *aiming* gate: every deliberate hold landed at least 33 px
/// from a cell boundary, while six of the nine quick taps landed within 15 px
/// of one and two were within a single pixel of registering as a different
/// digit. Pressing slowly makes people aim; tapping makes them sloppy.
///
/// The hold also separates deliberate entry from innocent use of the vendor UI,
/// which stays live and fully usable while locked -- `devuiappd` reads the same
/// digitiser and neither process grabs it exclusively, so both see every touch.
///
/// Brute force at half a second a digit is about three days for six digits and
/// eight months for eight; neither is reachable by hand.
pub const DIGIT_HOLD: Duration = Duration::from_millis(500);

/// Touches landing this close to a cell boundary are discarded rather than
/// resolved to a guess.
///
/// Without this, a press one pixel over an edge silently enters the *wrong*
/// digit, which shifts the rolling window and means the whole PIN has to be
/// re-entered -- with no feedback to say why. An ignored touch leaves the
/// window untouched, so simply pressing again continues the sequence. Given
/// there is no feedback at all, ignored is strictly better than wrong.
const EDGE_MARGIN: u32 = 10;

/// Partial entry is discarded after this long without a digit, so a half-typed
/// PIN does not sit in memory waiting to be completed by someone else.
pub const ENTRY_IDLE: Duration = Duration::from_secs(30);

pub struct PanicConfig {
    secret: Secret,
    /// Number of digits in the PIN. Stored because the rolling window needs it.
    pub len: usize,
    /// Go through the motions and report the outcome, but do not actually close
    /// anything. For testing on a device you cannot afford to lock out.
    pub dev_mode: bool,
}

impl PanicConfig {
    /// Load the armed configuration.
    ///
    /// Returns `None` when the feature is not armed on this device, which is
    /// the default and must stay the default.
    pub fn load() -> Option<PanicConfig> {
        Self::load_from(Path::new(PANIC_CONF))
    }

    pub fn load_from(path: &Path) -> Option<PanicConfig> {
        let body = std::fs::read_to_string(path).ok()?;
        let secret = Secret::from_lines(&body)?;
        let dev_mode = body.lines().any(|l| {
            l.split_once('=')
                .is_some_and(|(k, v)| k.trim() == "dev" && matches!(v.trim(), "true" | "1"))
        });
        Some(PanicConfig {
            len: secret.len,
            secret,
            dev_mode,
        })
    }

    /// Arm (or re-arm) with these digits. The PIN is set by entering it on the
    /// panel (or `rayhunter-m2100 enroll pin`), never from a plaintext file.
    pub fn store(path: &Path, digits: &[u8], dev: bool) -> std::io::Result<()> {
        let s = Secret::create(digits);
        m2100_secret::write_atomic(path, &format!("{}dev = {dev}\n", s.to_lines()))
    }

    pub fn matches(&self, digits: &[u8]) -> bool {
        self.secret.matches(digits)
    }

    pub fn secret(&self) -> &Secret {
        &self.secret
    }
}

/// Which grid cell a touch falls in, as a digit 1-9.
///
/// The grid is invisible and covers the whole panel, so while locked it
/// replaces every other gesture rather than sharing the screen with them.
///
/// Returns `None` for a touch too close to a boundary to be sure about. See
/// [`EDGE_MARGIN`]: guessing would enter a wrong digit that the person cannot
/// detect, whereas discarding costs them one repeated press.
pub fn digit_at(x: i32, y: i32, width: u32, height: u32) -> Option<u8> {
    if x < 0 || y < 0 || x >= width as i32 || y >= height as i32 {
        return None;
    }
    // Measure against the two interior boundaries on each axis directly. Doing
    // this with `x % cell_width` is wrong when the panel does not divide evenly
    // by three: at 320 px the cells are 106 wide, so x=319 lands in a nominal
    // fourth column and its remainder makes the panel's own edge look like an
    // interior boundary.
    let (x, y) = (x as i64, y as i64);
    let (w, h) = (width as i64, height as i64);
    let (bx1, bx2) = (w / 3, 2 * w / 3);
    let (by1, by2) = (h / 3, 2 * h / 3);
    let margin = EDGE_MARGIN as i64;

    // Only interior boundaries are ambiguous. The outer edges of the panel are
    // not, so a press in the far corner always registers.
    if (x - bx1).abs() < margin
        || (x - bx2).abs() < margin
        || (y - by1).abs() < margin
        || (y - by2).abs() < margin
    {
        return None;
    }

    let col = if x < bx1 {
        0
    } else if x < bx2 {
        1
    } else {
        2
    };
    let row = if y < by1 {
        0
    } else if y < by2 {
        1
    } else {
        2
    };

    Some((row * 3 + col + 1) as u8)
}

pub fn flag_set() -> bool {
    std::path::Path::new(PANIC_FLAG).exists()
}

pub fn set_flag(engaged: bool) {
    if engaged {
        if let Err(e) = std::fs::write(PANIC_FLAG, b"1") {
            log::warn!("panic: couldn't persist flag: {e}");
        }
    } else {
        let _ = std::fs::remove_file(PANIC_FLAG);
    }
}

/// The confirmation a panic gives by ear. Not a sound of our own: the vendor's
/// "startup" notification, raised through its own alert service (`ansd`), so it
/// is genuinely a stock sound -- 2 beeps, no screen wake (measured 2026-10-08;
/// "batteryCharging" is 3 beeps but wakes the screen and could claim a charger
/// that isn't there). At boot the device plays exactly this. It is added, then
/// removed, so nothing lingers in the vendor's notification list.
pub const CHIME_ADD: &str = "startup\n1\n";
pub const CHIME_REMOVE: &str = "startup\n0\n";

/// `enabled:[0|1]` from `ans_cli get_audio_alerts_enabled` and friends.
pub fn parse_enabled(out: &str) -> Option<bool> {
    let i = out.find("enabled:[")? + "enabled:[".len();
    match out.get(i..i + 2)? {
        "1]" => Some(true),
        "0]" => Some(false),
        _ => None,
    }
}

/// Chime only when the device would beep for its own events: the vendor's
/// audio alerts on and its stealth mode off. Whoever silenced the device gets
/// silence. A setting that can't be read also means silence -- an unexpected
/// beep is the one outcome a panic must not risk.
pub fn chime_wanted(audio_alerts: Option<bool>, vendor_stealth: Option<bool>) -> bool {
    audio_alerts == Some(true) && vendor_stealth == Some(false)
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_stored_pin_loads_and_matches() {
        let dir = std::env::temp_dir().join(format!("rh-panic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(".panic");
        PanicConfig::store(&p, &[1, 5, 9, 2, 6, 8], true).unwrap();
        let cfg = PanicConfig::load_from(&p).expect("loads");
        assert!(cfg.matches(&[1, 5, 9, 2, 6, 8]));
        assert!(!cfg.matches(&[1, 5, 9, 2, 6, 7]));
        assert_eq!(cfg.len, 6);
        assert!(cfg.dev_mode);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    use super::*;
    use crate::display::m2100_secret::{derive, hex, unhex};

    fn cfg(pin: &[u8]) -> PanicConfig {
        let salt = b"testsalt".to_vec();
        PanicConfig {
            secret: Secret {
                hash: derive(&salt, pin),
                salt,
                len: pin.len(),
            },
            len: pin.len(),
            dev_mode: false,
        }
    }

    #[test]
    fn grid_maps_corners_and_centre() {
        let (w, h) = (320, 240);
        assert_eq!(digit_at(5, 5, w, h), Some(1));
        assert_eq!(digit_at(160, 5, w, h), Some(2));
        assert_eq!(digit_at(315, 5, w, h), Some(3));
        assert_eq!(digit_at(5, 120, w, h), Some(4));
        assert_eq!(digit_at(160, 120, w, h), Some(5));
        assert_eq!(digit_at(315, 120, w, h), Some(6));
        assert_eq!(digit_at(5, 235, w, h), Some(7));
        assert_eq!(digit_at(160, 235, w, h), Some(8));
        assert_eq!(digit_at(315, 235, w, h), Some(9));
        // Calibrated real taps from this hardware.
        assert_eq!(digit_at(31, 33, w, h), Some(1));
        assert_eq!(digit_at(304, 205, w, h), Some(9));
    }

    /// Touches near an interior boundary must be discarded, not guessed.
    /// These coordinates are from the hardware capture that motivated this:
    /// two taps landed 0.7 px from a vertical edge and one 4 px from both.
    #[test]
    fn grid_discards_ambiguous_touches() {
        let (w, h) = (320u32, 240u32);
        // cell edges fall at x = 106, 212 and y = 80, 160 for integer cells
        assert_eq!(digit_at(106, 180, w, h), None, "0.7px from a vertical edge");
        assert_eq!(digit_at(218, 156, w, h), None, "near both edges");
        assert_eq!(digit_at(206, 152, w, h), None, "near both edges");
        // but the deliberate holds from the same capture must all still land
        for (x, y, want) in [
            (169, 51, 2u8),
            (63, 116, 4),
            (65, 195, 7),
            (61, 49, 1),
            (289, 41, 3),
            (173, 111, 5),
            (280, 114, 6),
            (278, 206, 9),
            (180, 208, 8),
        ] {
            assert_eq!(
                digit_at(x, y, w, h),
                Some(want),
                "deliberate hold ({x},{y})"
            );
        }
    }

    /// The outer edge of the panel is not ambiguous -- only interior
    /// boundaries are -- so corner presses must still register.
    #[test]
    fn grid_accepts_the_panel_edges() {
        assert_eq!(digit_at(0, 0, 320, 240), Some(1));
        assert_eq!(digit_at(319, 239, 320, 240), Some(9));
        assert_eq!(digit_at(2, 238, 320, 240), Some(7));
    }

    #[test]
    fn grid_rejects_out_of_range() {
        assert_eq!(digit_at(-1, 10, 320, 240), None);
        assert_eq!(digit_at(10, -1, 320, 240), None);
        assert_eq!(digit_at(320, 10, 320, 240), None);
        assert_eq!(digit_at(10, 240, 320, 240), None);
    }

    #[test]
    fn correct_pin_matches() {
        let c = cfg(&[1, 2, 3, 4, 5, 6]);
        assert!(c.matches(&[1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn wrong_pin_does_not_match() {
        let c = cfg(&[1, 2, 3, 4, 5, 6]);
        assert!(!c.matches(&[1, 2, 3, 4, 5, 7]));
        assert!(!c.matches(&[6, 5, 4, 3, 2, 1]));
    }

    /// A rolling window hands over exactly `len` digits, so anything else is a
    /// bug in the caller rather than a near-miss to be tolerated.
    #[test]
    fn wrong_length_does_not_match() {
        let c = cfg(&[1, 2, 3, 4, 5, 6]);
        assert!(!c.matches(&[1, 2, 3, 4, 5]));
        assert!(!c.matches(&[1, 2, 3, 4, 5, 6, 7]));
        assert!(!c.matches(&[]));
    }

    /// Two devices with the same PIN must not share a hash.
    #[test]
    fn salt_changes_the_hash() {
        let pin = [1, 2, 3, 4, 5, 6];
        assert_ne!(derive(b"salt-a", &pin), derive(b"salt-b", &pin));
    }

    #[test]
    fn hex_round_trips() {
        let b = vec![0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(unhex(&hex(&b)), Some(b));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }

    // ---- panic confirmation chime (2026-10-08) ----------------------------
    use super::{CHIME_ADD, CHIME_REMOVE, chime_wanted, parse_enabled};

    #[test]
    fn the_vendor_tools_enabled_line_is_read() {
        let on = "ans_get_audio_alerts_enabled returned 0 (ANS: success.)\nenabled:[1]\n";
        let off = "ans_get_stealth_mode_enabled returned 0 (ANS: success.)\nenabled:[0]\n";
        assert_eq!(parse_enabled(on), Some(true));
        assert_eq!(parse_enabled(off), Some(false));
        assert_eq!(
            parse_enabled("returned 2 (ANS: one or more bad parameters)"),
            None
        );
        assert_eq!(parse_enabled("enabled:[7]"), None);
    }

    #[test]
    fn the_chime_follows_the_vendors_own_sound_settings() {
        // Sounds on and the vendor's stealth mode off: the device would beep for
        // its own events, so it may beep for this one.
        assert!(chime_wanted(Some(true), Some(false)));
        // The owner silenced the device, or put it in the vendor's stealth mode.
        assert!(!chime_wanted(Some(false), Some(false)));
        assert!(!chime_wanted(Some(true), Some(true)));
    }

    #[test]
    fn a_setting_that_cannot_be_read_means_silence() {
        // Fail quiet, not loud: an unexpected beep is the one outcome a panic
        // must not risk.
        assert!(!chime_wanted(None, Some(false)));
        assert!(!chime_wanted(Some(true), None));
        assert!(!chime_wanted(None, None));
    }

    #[test]
    fn the_chime_is_the_vendors_startup_notification_added_then_removed() {
        assert_eq!(CHIME_ADD, "startup\n1\n");
        assert_eq!(CHIME_REMOVE, "startup\n0\n");
    }
}
