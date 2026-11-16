//! Deployment profiles (SPEC-deployment-profiles.md): Fixed for the cabinet,
//! Mobile for standalone use. Pure: the profile file, each profile's commands,
//! and parsing what the vendor tools print. Running them is m2100_profile_io.rs.

use std::path::Path;

use crate::display::m2100_cli::Out;

pub const PROFILE_PATH: &str = "/data/rayhunter/profile";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Profile {
    Fixed,
    Mobile,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Fixed => "fixed",
            Profile::Mobile => "mobile",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Profile::Fixed => "FIXED",
            Profile::Mobile => "MOBILE",
        }
    }
}

/// The saved profile, or `None` if the file is missing, unreadable or
/// unrecognised (an empty file after a power cut mid-write, say).
pub fn read(path: &Path) -> Option<Profile> {
    match std::fs::read_to_string(path).ok()?.trim() {
        "fixed" => Some(Profile::Fixed),
        "mobile" => Some(Profile::Mobile),
        _ => None,
    }
}

/// Missing, unreadable or unrecognised means Mobile: stock behaviour. Never a
/// guess at Fixed.
pub fn load(path: &Path) -> Profile {
    read(path).unwrap_or(Profile::Mobile)
}

pub fn store(path: &Path, p: Profile) -> std::io::Result<()> {
    super::m2100_secret::write_atomic(path, &format!("{}\n", p.as_str()))
}

/// One step of a profile. The firewall steps need a little logic (check before
/// inserting, delete until gone), so they are named; the rest are plain
/// commands: (program, arguments, what to type at its prompts).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// `iptables` and `ip6tables -I OUTPUT/FORWARD -o rmnet+ -j DROP`, each
    /// only if missing.
    FirewallOn,
    /// The same four rules deleted, repeatedly, in case of duplicates.
    FirewallOff,
    /// `wifi_cli set_ap_enable 0`, only if `get_ap_enable` doesn't already say
    /// off: on this firmware, switching off a hotspot that is already off
    /// returns "general error" (unit 1, 2026-10-09).
    HotspotOff,
    Run(&'static str, &'static [&'static str], &'static str),
}

/// T-Mobile here is IPv6-native, and there is no ip6tables on the device, so
/// IPv6 is switched off on the cellular interfaces themselves. The vendor keeps
/// rmnet_data1..5 off already; Mobile restores only rmnet_data0.
const V6_OFF: &str = "for i in 0 1 2 3 4 5; do echo 1 > /proc/sys/net/ipv6/conf/rmnet_data$i/disable_ipv6 || exit 1; done";
const V6_ON: &str = "echo 0 > /proc/sys/net/ipv6/conf/rmnet_data0/disable_ipv6";

/// The commands for each profile, in order (spec section 2). Fixed puts the
/// backstop up first, so a vendor command that hangs can never leave data
/// flowing. Autoconnect is never 1 ("when clients are connected"): the Yellow
/// on USB counts as a client.
pub fn steps(p: Profile) -> Vec<Step> {
    match p {
        Profile::Fixed => vec![
            Step::FirewallOn,
            Step::Run("sh", &["-c", V6_OFF], ""),
            Step::Run("ccm2_cli", &["set_wwan_ac"], "0\n"),
            Step::Run("modem2_cli", &["enable_data_call"], "0\n"),
            Step::HotspotOff,
        ],
        Profile::Mobile => vec![
            Step::Run("sh", &["-c", V6_ON], ""),
            Step::Run("ccm2_cli", &["set_wwan_ac"], "2\n"),
            Step::Run("modem2_cli", &["enable_data_call"], "1\n"),
            Step::HotspotOff,
            Step::FirewallOff,
        ],
    }
}

/// The boot re-apply (spec section 3). Mobile leaves the hotspot alone: it goes
/// off once, at switch time, and is the vendor UI's to change after that.
pub fn steps_at_boot(p: Profile) -> Vec<Step> {
    let mut s = steps(p);
    if p == Profile::Mobile {
        s.retain(|s| *s != Step::HotspotOff);
    }
    s
}

/// The vendor tools print "<call> returned <n> (...)"; anything but 0 is a
/// failure even when the process itself exits 0. Plain commands print nothing.
pub fn succeeded(o: &Out) -> bool {
    o.ok && (!o.stdout.contains(" returned ") || o.stdout.contains(" returned 0 "))
}

fn bracketed(out: &str, key: &str) -> Option<u8> {
    let i = out.find(key)? + key.len();
    let rest = &out[i..];
    rest[..rest.find(']')?].trim().parse().ok()
}

/// `ccm2_cli get_wwan_ac`: 0 manual, 1 when clients connect, 2 when service is
/// available (stock), 3 when not roaming.
pub fn parse_autoconnect(out: &str) -> Option<u8> {
    bracketed(out, "Autoconnect Type:[")
}

/// `wifi_cli get_ap_enable`: 0 off, 1 on.
pub fn parse_ap_enable(out: &str) -> Option<u8> {
    bracketed(out, "Wifi AP mode is :[")
}

/// `modem2_cli call_get_status`: 3 Idle, 5 Connected.
pub fn parse_wwan_state(out: &str) -> Option<u8> {
    bracketed(out, "WWAN State:[")
}

/// In Fixed there is no path out, so sending would only fail and retry; the
/// alert is still on the panel and in Home Assistant.
pub fn ntfy_allowed(p: Profile) -> bool {
    p != Profile::Fixed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_garbled_profile_file_means_mobile() {
        let dir = std::env::temp_dir().join(format!("rh-prof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("profile");
        assert_eq!(load(&p), Profile::Mobile, "missing");
        std::fs::write(&p, "fixd\n").unwrap();
        assert_eq!(load(&p), Profile::Mobile, "garbled");
        store(&p, Profile::Fixed).unwrap();
        assert_eq!(load(&p), Profile::Fixed);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "fixed\n");
        store(&p, Profile::Mobile).unwrap();
        assert_eq!(load(&p), Profile::Mobile);
    }

    #[test]
    fn fixed_puts_the_backstop_up_before_any_vendor_command() {
        let s = steps(Profile::Fixed);
        assert_eq!(s[0], Step::FirewallOn);
        assert!(matches!(s[1], Step::Run("sh", _, _)), "IPv6 off second");
        assert_eq!(
            &s[2..],
            &[
                Step::Run("ccm2_cli", &["set_wwan_ac"], "0\n"),
                Step::Run("modem2_cli", &["enable_data_call"], "0\n"),
                Step::HotspotOff,
            ]
        );
    }

    #[test]
    fn mobile_brings_data_back_and_takes_the_backstop_down_last() {
        let s = steps(Profile::Mobile);
        assert!(matches!(s[0], Step::Run("sh", _, _)), "IPv6 back first");
        assert_eq!(
            &s[1..],
            &[
                Step::Run("ccm2_cli", &["set_wwan_ac"], "2\n"),
                Step::Run("modem2_cli", &["enable_data_call"], "1\n"),
                Step::HotspotOff,
                Step::FirewallOff,
            ]
        );
    }

    #[test]
    fn neither_profile_ever_uses_autoconnect_when_clients_connect() {
        // Mode 1 counts the Yellow on USB as a client, so Fixed would connect.
        for p in [Profile::Fixed, Profile::Mobile] {
            assert!(!steps(p).contains(&Step::Run("ccm2_cli", &["set_wwan_ac"], "1\n")));
        }
    }

    #[test]
    fn ipv6_is_switched_on_every_cellular_interface_but_restored_only_on_the_first() {
        let Step::Run(_, off, _) = steps(Profile::Fixed)[1] else {
            panic!()
        };
        for i in 0..6 {
            assert!(off[1].contains("disable_ipv6"));
            assert!(off[1].contains(&format!("{i}")), "rmnet_data{i}");
        }
        // Every write must count, not only the last one in the loop.
        assert!(off[1].contains("disable_ipv6 || exit 1;"), "{}", off[1]);
        let Step::Run(_, on, _) = steps(Profile::Mobile)[0] else {
            panic!()
        };
        assert!(on[1].contains("echo 0 > /proc/sys/net/ipv6/conf/rmnet_data0/disable_ipv6"));
    }

    #[test]
    fn real_vendor_output_parses() {
        let ac = "ccm_get_wwan_ac returned 0 (CCM: success.)\nAutoconnect Type:[2] Autoconnect when service is available\n";
        assert_eq!(parse_autoconnect(ac), Some(2));
        assert_eq!(
            parse_autoconnect("Autoconnect Type:[0] Manual connect, autoconnect disabled"),
            Some(0)
        );
        // The set_wwan_ac menu lists choices; it is not a reading.
        assert_eq!(
            parse_autoconnect("Autoconnect Index: 0 Type:[Manual connect]"),
            None
        );
        let st = "IP Family:[2] (IPV6)\nWWAN State:[3] (Idle)\nInterface:[rmnet_data0]\n";
        assert_eq!(parse_wwan_state(st), Some(3));
        assert_eq!(parse_wwan_state("WWAN State:[5] (Connected)"), Some(5));
        assert_eq!(
            parse_wwan_state("returned 2 (MDM_MAIN: one or more bad parameters"),
            None
        );
    }

    #[test]
    fn the_hotspot_reading_parses() {
        let off = "wifi_get_ap_enabled returned 0 (WIFI: success.)\nWifi AP mode is :[0] \n";
        assert_eq!(parse_ap_enable(off), Some(0));
        assert_eq!(parse_ap_enable("Wifi AP mode is :[1] "), Some(1));
        assert_eq!(
            parse_ap_enable("wifi_get_ap_enabled returned 1 (WIFI: general error.)"),
            None
        );
    }

    #[test]
    fn a_vendor_command_succeeded_only_if_it_says_so() {
        let o = |s: &str| crate::display::m2100_cli::Out {
            ok: true,
            code: Some(0),
            stdout: s.to_string(),
        };
        assert!(succeeded(&o("ccm_set_wwan_ac returned 0 (CCM: success.)")));
        assert!(!succeeded(&o(
            "ans_trigger_notification returned 2 (ANS: one or more bad parameters"
        )));
        assert!(succeeded(&o(""))); // sh commands print nothing
        assert!(!succeeded(&crate::display::m2100_cli::Out {
            ok: false,
            code: Some(1),
            stdout: String::new()
        }));
    }

    #[test]
    fn ntfy_goes_out_except_in_fixed() {
        assert!(!ntfy_allowed(Profile::Fixed));
        assert!(ntfy_allowed(Profile::Mobile));
    }

    #[test]
    fn read_tells_a_garbled_file_from_a_missing_one() {
        let dir = std::env::temp_dir().join(format!("rh-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("profile");
        let _ = std::fs::remove_file(&p);
        assert_eq!(read(&p), None);
        std::fs::write(&p, "").unwrap(); // a power cut mid-write
        assert_eq!(read(&p), None);
        assert_eq!(load(&p), Profile::Mobile);
        store(&p, Profile::Fixed).unwrap();
        assert_eq!(read(&p), Some(Profile::Fixed));
    }

    #[test]
    fn the_boot_re_apply_leaves_the_mobile_hotspot_alone() {
        // Spec section 2: the hotspot goes off once, at switch time, and is the
        // vendor UI's to change after that.
        let boot = steps_at_boot(Profile::Mobile);
        assert!(!boot.iter().any(|s| *s == Step::HotspotOff));
        let mut want = steps(Profile::Mobile);
        want.retain(|s| *s != Step::HotspotOff);
        assert_eq!(boot, want);
        assert_eq!(steps_at_boot(Profile::Fixed), steps(Profile::Fixed));
    }
}
