//! Running a profile's steps on the device, and switching. The device switches
//! and reports; it never enforces (spec: Home Assistant watches Fixed).

use std::path::Path;

use std::sync::atomic::{AtomicBool, Ordering};

use crate::display::m2100_cli::{Runner, System};
use serde::Serialize;

use crate::display::m2100_profile::{
    PROFILE_PATH, Profile, Step, load, parse_ap_enable, parse_autoconnect, parse_wwan_state, read,
    steps, steps_at_boot, store, succeeded,
};

/// The backstop: both directions out of the cellular interfaces, for IPv4 and
/// IPv6. The vendor turns IPv6 back on when data comes up (unit 1,
/// 2026-10-09), so disable_ipv6 alone isn't one.
const RULES: [(&str, &str); 4] = [
    ("iptables", "OUTPUT"),
    ("iptables", "FORWARD"),
    ("ip6tables", "OUTPUT"),
    ("ip6tables", "FORWARD"),
];

/// More copies of a rule than this means something else keeps adding them.
const MAX_DELETES: usize = 8;

/// A run of a profile (a switch or the boot re-apply) is in progress. Shared
/// by the boot task in main.rs and the panel.
pub static SWITCHING: AtomicBool = AtomicBool::new(false);
/// The boot re-apply failed and no switch has succeeded since.
pub static BOOT_FAILED: AtomicBool = AtomicBool::new(false);

/// `-w` waits for the xtables lock: the vendor stack runs iptables itself when
/// a data call comes up, and without it a busy lock fails at once.
fn rule<'a>(op: &'a str, chain: &'a str) -> [&'a str; 7] {
    ["-w", op, chain, "-o", "rmnet+", "-j", "DROP"]
}

/// `Some(true)` present, `Some(false)` absent (`iptables -C` exits 1), `None`
/// for anything else: a lock error or a timeout is "don't know", never
/// "absent".
async fn rule_state(r: &dyn Runner, bin: &str, chain: &str) -> Option<bool> {
    match r.run(bin, &rule("-C", chain), "").await {
        Some(o) if o.ok => Some(true),
        Some(o) if o.code == Some(1) => Some(false),
        _ => None,
    }
}

async fn step(r: &dyn Runner, s: Step) -> bool {
    match s {
        Step::FirewallOn => {
            for (bin, chain) in RULES {
                match rule_state(r, bin, chain).await {
                    Some(true) => continue,
                    Some(false) => {}
                    None => return false,
                }
                match r.run(bin, &rule("-I", chain), "").await {
                    Some(o) if o.ok => {}
                    _ => return false,
                }
            }
            true
        }
        Step::FirewallOff => {
            for (bin, chain) in RULES {
                for _ in 0..MAX_DELETES {
                    match r.run(bin, &rule("-D", chain), "").await {
                        Some(o) if o.ok => {}
                        _ => break,
                    }
                }
                // A failed delete is the expected end; make sure it meant "gone".
                if rule_state(r, bin, chain).await != Some(false) {
                    return false;
                }
            }
            true
        }
        Step::HotspotOff => {
            let now = match r.run("wifi_cli", &["get_ap_enable"], "").await {
                Some(o) => parse_ap_enable(&o.stdout),
                None => None,
            };
            if now == Some(0) {
                return true;
            }
            match r.run("wifi_cli", &["set_ap_enable"], "0\n").await {
                Some(o) => succeeded(&o),
                None => false,
            }
        }
        Step::Run(cmd, args, stdin) => match r.run(cmd, args, stdin).await {
            Some(o) => succeeded(&o),
            None => false,
        },
    }
}

/// Runs the profile's steps in order and stops at the first that fails or
/// times out. Used by a switch and (with `at_boot`) by the boot re-apply.
pub async fn apply(r: &dyn Runner, p: Profile, at_boot: bool) -> bool {
    let list = if at_boot { steps_at_boot(p) } else { steps(p) };
    for s in list {
        if !step(r, s).await {
            log::warn!("m2100: applying {} stopped at {s:?}", p.as_str());
            return false;
        }
    }
    true
}

/// A switch: the profile is saved only if every step succeeded, so a failed
/// switch leaves the saved profile as it was and the owner can retry.
pub async fn switch_to(r: &dyn Runner, path: &Path, p: Profile) -> bool {
    if !apply(r, p, false).await {
        return false;
    }
    match store(path, p) {
        Ok(()) => {
            super::m2100_capture_profiles::note_applied(p);
            true
        }
        Err(e) => {
            log::warn!("m2100: saving profile failed: {e}");
            false
        }
    }
}

/// After a switch to Mobile: poll the data call every `every` for at most
/// `tries` polls (5 s x 12 on the device) and report whether it connected.
pub async fn wait_connected(r: &dyn Runner, every: std::time::Duration, tries: u32) -> bool {
    for i in 0..tries {
        if i > 0 {
            tokio::time::sleep(every).await;
        }
        if let Some(o) = r.run("modem2_cli", &["call_get_status"], "1\n2\n").await
            && parse_wwan_state(&o.stdout) == Some(5)
        {
            return true;
        }
    }
    false
}

/// The Mobile confirmation: "Connected" is reported before the route out is
/// usable (unit 1, 2026-10-09: the first send failed, one a minute later went
/// through), so try `tries` times, `every` apart. Each try first checks the
/// saved profile is still Mobile, so a quick switch back never sends it.
pub async fn retry_send<F, Fut>(
    path: &Path,
    every: std::time::Duration,
    tries: u32,
    send: F,
) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for i in 0..tries {
        if i > 0 {
            tokio::time::sleep(every).await;
        }
        if read(path) != Some(Profile::Mobile) {
            return false;
        }
        if send().await {
            return true;
        }
    }
    false
}

/// How hard the boot re-apply tries. Rayhunter starts at S74, before the
/// modem (S75) and ccm2 (S76), so the first attempts can be refused; and
/// router2d rebuilds OUTPUT when the network comes up, which can wipe a rule
/// put in early (both seen on unit 1, 2026-10-09).
pub struct BootTiming {
    pub retry: std::time::Duration,
    /// After a success, wait this long and check the firewall is still there.
    pub settle: std::time::Duration,
    pub tries: u32,
}

pub const BOOT_TIMING: BootTiming = BootTiming {
    retry: std::time::Duration::from_secs(30),
    settle: std::time::Duration::from_secs(90),
    tries: 10,
};

async fn firewall_up(r: &dyn Runner) -> bool {
    for (bin, chain) in RULES {
        if rule_state(r, bin, chain).await != Some(true) {
            return false;
        }
    }
    true
}

/// Spec section 3, made to survive this firmware's boot order: apply until it
/// takes, then once more if the router wiped the firewall. Bounded to the boot
/// window -- after it, the device only reports (Home Assistant watches). Stops
/// as soon as the saved profile is no longer `p` (the owner switched), and
/// skips any attempt that would run alongside a switch.
pub async fn boot_reapply(
    r: &dyn Runner,
    path: &Path,
    p: Profile,
    switching: &AtomicBool,
    t: BootTiming,
) -> bool {
    for i in 0..t.tries {
        if i > 0 {
            tokio::time::sleep(t.retry).await;
        }
        if read(path) != Some(p) {
            log::info!("m2100: profile changed during boot; boot re-apply stops");
            return true;
        }
        if switching.swap(true, Ordering::Relaxed) {
            continue;
        }
        let ok = apply(r, p, true).await;
        switching.store(false, Ordering::Relaxed);
        if !ok {
            log::info!(
                "m2100: boot re-apply attempt {} of {} refused",
                i + 1,
                t.tries
            );
            continue;
        }
        super::m2100_capture_profiles::note_applied(p);
        if p == Profile::Mobile {
            return true;
        }
        tokio::time::sleep(t.settle).await;
        if read(path) != Some(p) || firewall_up(r).await {
            return true;
        }
        log::warn!("m2100: firewall gone after the boot re-apply; again");
    }
    false
}

/// Spec section 3: a reboot wipes the firewall rules and the IPv6 switch, so
/// the saved profile is re-applied, whatever the display's ui_level. Nothing
/// saved: the device stays stock. A file that exists but can't be read is left
/// alone too, rather than guessed at either way (the endpoint says "unrecognised").
pub fn spawn_boot_reapply(task_tracker: &tokio_util::task::TaskTracker) {
    let path = Path::new(PROFILE_PATH);
    let Some(p) = read(path) else {
        if path.exists() {
            log::warn!("m2100: profile file unrecognised; not re-applied at boot");
            BOOT_FAILED.store(true, Ordering::Relaxed);
        }
        return;
    };
    task_tracker.spawn(async move {
        let path = Path::new(PROFILE_PATH);
        if boot_reapply(&System::new(), path, p, &SWITCHING, BOOT_TIMING).await {
            log::info!("m2100: {} profile re-applied at boot", p.as_str());
        } else {
            log::warn!("m2100: re-applying {} at boot FAILED", p.as_str());
            BOOT_FAILED.store(true, Ordering::Relaxed);
        }
    });
}

/// What `GET /api/m2100/profile` reports (spec section 4): the saved profile
/// and live readings. A reading that could not be taken is `null`, which Home
/// Assistant treats as "not in Fixed state", never as fine.
#[derive(Serialize, Debug)]
pub struct Readings {
    pub profile: &'static str,
    pub autoconnect: Option<u8>,
    /// "idle", "connected", or the raw WWAN state number.
    pub data_call: Option<serde_json::Value>,
    pub hotspot: Option<bool>,
    pub firewall: Option<bool>,
    pub ipv6_off: Option<bool>,
}

/// `root` is "/" on the device; tests point it at a scratch directory.
pub async fn readings(r: &dyn Runner, root: &Path) -> Readings {
    let autoconnect = match r.run("ccm2_cli", &["get_wwan_ac"], "").await {
        Some(o) => parse_autoconnect(&o.stdout),
        None => None,
    };
    let data_call = match r.run("modem2_cli", &["call_get_status"], "1\n2\n").await {
        Some(o) => parse_wwan_state(&o.stdout).map(|n| match n {
            3 => serde_json::json!("idle"),
            5 => serde_json::json!("connected"),
            n => serde_json::json!(n),
        }),
        None => None,
    };
    // Not hostapd, which lingers after the access point is off.
    let hotspot = std::fs::read_dir(root.join("sys/class/net")).ok().map(|d| {
        d.flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with("wlan"))
    });
    let mut firewall = Some(true);
    for (bin, chain) in RULES {
        match rule_state(r, bin, chain).await {
            None => firewall = None,
            Some(false) => firewall = firewall.map(|_| false),
            Some(true) => {}
        }
    }
    let ipv6_off =
        std::fs::read_to_string(root.join("proc/sys/net/ipv6/conf/rmnet_data0/disable_ipv6"))
            .ok()
            .map(|v| v.trim() == "1");
    // A file that exists but says neither is reported, not read as Mobile:
    // Home Assistant must see a cabinet unit whose profile file was garbled.
    let path = root.join(PROFILE_PATH.trim_start_matches('/'));
    let profile = match read(&path) {
        Some(p) => p.as_str(),
        None if path.exists() => "unrecognised",
        None => load(&path).as_str(),
    };
    Readings {
        profile,
        autoconnect,
        data_call,
        hotspot,
        firewall,
        ipv6_off,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::m2100_cli::{Fake, Out};

    /// An iptables OR ip6tables call whose arguments start with `rest`.
    fn fw(l: &str, rest: &str) -> bool {
        l.strip_prefix("ip6tables")
            .or_else(|| l.strip_prefix("iptables"))
            .is_some_and(|a| a.starts_with(rest))
    }

    fn ok(s: &str) -> Option<Out> {
        Some(Out {
            ok: true,
            code: Some(0),
            stdout: s.to_string(),
        })
    }
    fn fails() -> Option<Out> {
        Some(Out {
            ok: false,
            code: Some(1),
            stdout: String::new(),
        })
    }

    /// Rules start absent; every other command succeeds.
    fn device() -> Fake {
        Fake::new(|l| {
            if fw(l, " -w -C") || fw(l, " -w -D") {
                fails()
            } else {
                ok("x returned 0 (success.)")
            }
        })
    }

    fn scratch(name: &str, start: Profile) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rh-pio-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("profile");
        store(&p, start).unwrap();
        p
    }

    fn first(calls: &[String], prefix: &str) -> usize {
        calls
            .iter()
            .position(|c| c.starts_with(prefix))
            .unwrap_or(usize::MAX)
    }

    #[tokio::test]
    async fn fixed_puts_the_backstop_up_before_any_vendor_command() {
        let f = device();
        assert!(apply(&f, Profile::Fixed, false).await);
        let c = f.calls();
        let last_fw = c
            .iter()
            .rposition(|c| c.starts_with("iptables -w -I"))
            .unwrap();
        assert_eq!(
            c.iter().filter(|c| c.starts_with("iptables -w -I")).count(),
            2
        );
        assert!(last_fw < first(&c, "sh -c"), "{c:?}");
        assert!(last_fw < first(&c, "ccm2_cli"), "{c:?}");
        assert!(first(&c, "ccm2_cli") < usize::MAX, "{c:?}");
    }

    #[tokio::test]
    async fn a_hung_command_fails_the_switch_and_keeps_the_saved_profile() {
        let path = scratch("hung", Profile::Mobile);
        let f = Fake::new(|l| {
            if l.starts_with("modem2_cli") {
                None // never answered; the runner timed it out
            } else if fw(l, " -w -C") {
                fails()
            } else {
                ok("x returned 0 (success.)")
            }
        });
        assert!(!switch_to(&f, &path, Profile::Fixed).await);
        assert_eq!(load(&path), Profile::Mobile);
        let c = f.calls();
        // The backstop was already up when it hung, and nothing ran after it.
        assert!(
            first(&c, "iptables -w -I") < first(&c, "modem2_cli"),
            "{c:?}"
        );
        assert_eq!(first(&c, "wifi_cli"), usize::MAX, "{c:?}");
    }

    #[tokio::test]
    async fn a_vendor_error_fails_the_switch_too() {
        let path = scratch("vendor-err", Profile::Fixed);
        let f = Fake::new(|l| {
            if l.starts_with("ccm2_cli") {
                ok("ccm_set_wwan_ac returned 2 (CCM: bad parameters)")
            } else if fw(l, "") {
                fails()
            } else {
                ok("")
            }
        });
        assert!(!switch_to(&f, &path, Profile::Mobile).await);
        assert_eq!(load(&path), Profile::Fixed);
    }

    #[tokio::test]
    async fn a_successful_switch_saves_the_new_profile() {
        let path = scratch("ok", Profile::Mobile);
        assert!(switch_to(&device(), &path, Profile::Fixed).await);
        assert_eq!(load(&path), Profile::Fixed);
        assert!(switch_to(&device(), &path, Profile::Mobile).await);
        assert_eq!(load(&path), Profile::Mobile);
    }

    #[tokio::test]
    async fn a_rule_already_present_is_not_inserted_twice() {
        let f = Fake::new(|l| {
            if fw(l, " -w -C OUTPUT") {
                ok("")
            } else if fw(l, " -w -C") {
                fails()
            } else {
                ok("x returned 0 (success.)")
            }
        });
        assert!(apply(&f, Profile::Fixed, false).await);
        let c = f.calls();
        assert!(
            !c.iter().any(|c| c.starts_with("iptables -w -I OUTPUT")),
            "{c:?}"
        );
        assert!(
            c.iter().any(|c| c.starts_with("iptables -w -I FORWARD")),
            "{c:?}"
        );
    }

    #[tokio::test]
    async fn mobile_deletes_duplicate_rules_until_gone() {
        // Two copies in OUTPUT, one in FORWARD.
        let left = std::sync::Mutex::new([2usize, 1, 2, 1]);
        let f = Fake::new(move |l| {
            let i = l.starts_with("ip6") as usize * 2 + if l.contains(" OUTPUT ") { 0 } else { 1 };
            let mut n = left.lock().unwrap();
            if fw(l, " -w -D") {
                if n[i] > 0 {
                    n[i] -= 1;
                    ok("")
                } else {
                    fails()
                }
            } else if fw(l, " -w -C") {
                if n[i] > 0 { ok("") } else { fails() }
            } else {
                ok("x returned 0 (success.)")
            }
        });
        assert!(apply(&f, Profile::Mobile, false).await);
        let c = f.calls();
        assert_eq!(
            c.iter()
                .filter(|c| c.starts_with("iptables -w -D OUTPUT"))
                .count(),
            3
        );
        assert_eq!(
            c.iter()
                .filter(|c| c.starts_with("iptables -w -D FORWARD"))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn a_rule_that_will_not_go_fails_mobile() {
        let f = Fake::new(|l| {
            if fw(l, " -w -D") {
                fails()
            } else {
                ok("x returned 0 (success.)") // -C keeps finding it
            }
        });
        assert!(!apply(&f, Profile::Mobile, false).await);
    }
    /// A scratch root with /sys/class/net, the IPv6 switch and a profile file.
    fn root(name: &str, nets: &[&str], v6: Option<&str>, p: Option<Profile>) -> std::path::PathBuf {
        let r = std::env::temp_dir().join(format!("rh-rd-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        for n in nets {
            std::fs::create_dir_all(r.join("sys/class/net").join(n)).unwrap();
        }
        std::fs::create_dir_all(r.join("sys/class/net")).unwrap();
        if let Some(v) = v6 {
            let d = r.join("proc/sys/net/ipv6/conf/rmnet_data0");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("disable_ipv6"), v).unwrap();
        }
        if let Some(p) = p {
            std::fs::create_dir_all(r.join("data/rayhunter")).unwrap();
            store(&r.join("data/rayhunter/profile"), p).unwrap();
        }
        r
    }

    fn fixed_device() -> Fake {
        Fake::new(|l| {
            if l.starts_with("ccm2_cli get_wwan_ac") {
                ok(
                    "ccm_get_wwan_ac returned 0 (CCM: success.)\nAutoconnect Type:[0] Manual connect\n",
                )
            } else if l.starts_with("modem2_cli call_get_status <1,2,") {
                ok("WWAN State:[3] (Idle)\n")
            } else if fw(l, " -w -C") {
                ok("")
            } else {
                None
            }
        })
    }

    #[tokio::test]
    async fn a_fixed_device_reports_fixed_readings() {
        let r = root(
            "fixed",
            &["lo", "rmnet_data0", "bridge0"],
            Some("1\n"),
            Some(Profile::Fixed),
        );
        let v = serde_json::to_value(readings(&fixed_device(), &r).await).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "profile": "fixed", "autoconnect": 0, "data_call": "idle",
                "hotspot": false, "firewall": true, "ipv6_off": true
            })
        );
    }

    #[tokio::test]
    async fn a_mobile_device_reports_mobile_readings() {
        let f = Fake::new(|l| {
            if l.starts_with("ccm2_cli") {
                ok("Autoconnect Type:[2] Autoconnect when service is available\n")
            } else if l.starts_with("modem2_cli") {
                ok("WWAN State:[5] (Connected)\n")
            } else {
                fails() // iptables -C: no rule
            }
        });
        let r = root("mobile", &["wlan0"], Some("0\n"), None);
        let v = serde_json::to_value(readings(&f, &r).await).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "profile": "mobile", "autoconnect": 2, "data_call": "connected",
                "hotspot": true, "firewall": false, "ipv6_off": false
            })
        );
    }

    #[tokio::test]
    async fn an_unreadable_reading_is_null_never_fine() {
        // Every command times out and the IPv6 switch is missing.
        let r = root("null", &[], None, Some(Profile::Fixed));
        let v = serde_json::to_value(readings(&Fake::new(|_| None), &r).await).unwrap();
        for k in ["autoconnect", "data_call", "firewall", "ipv6_off"] {
            assert!(v[k].is_null(), "{k}: {v}");
        }
        // One rule there and the other unreadable is still not "firewall on".
        let half = Fake::new(|l| if fw(l, " -w -C OUTPUT") { ok("") } else { None });
        let v = serde_json::to_value(readings(&half, &r).await).unwrap();
        assert!(v["firewall"].is_null(), "{v}");
    }

    #[tokio::test]
    async fn an_odd_data_call_state_is_reported_raw() {
        let f = Fake::new(|l| {
            if l.starts_with("modem2_cli") {
                ok("WWAN State:[4] (Connecting)\n")
            } else {
                None
            }
        });
        let r = root("raw", &[], None, None);
        let v = serde_json::to_value(readings(&f, &r).await).unwrap();
        assert_eq!(v["data_call"], serde_json::json!(4));
    }

    #[test]
    fn no_write_route_touches_the_profile_endpoint() {
        let main = include_str!("../main.rs");
        assert!(main.contains("\"/api/m2100/profile\", get("));
        for line in main.lines().filter(|l| l.contains("m2100/profile")) {
            assert!(
                !line.contains("post(") && !line.contains("put(") && !line.contains("delete("),
                "{line}"
            );
        }
    }

    #[tokio::test]
    async fn the_mobile_confirmation_waits_for_connected() {
        let n = std::sync::Mutex::new(0);
        let f = Fake::new(move |_| {
            let mut n = n.lock().unwrap();
            *n += 1;
            ok(if *n < 3 {
                "WWAN State:[3] (Idle)"
            } else {
                "WWAN State:[5] (Connected)"
            })
        });
        let tick = std::time::Duration::from_millis(1);
        assert!(wait_connected(&f, tick, 10).await);
        assert_eq!(f.calls().len(), 3);
        assert!(f.calls()[0].starts_with("modem2_cli call_get_status <1,2,"));
        let never = Fake::new(|_| ok("WWAN State:[3] (Idle)"));
        assert!(!wait_connected(&never, tick, 4).await);
        assert_eq!(never.calls().len(), 4);
    }

    /// iptables exits 4 when another process holds the xtables lock (or -w
    /// gives up). That is "don't know", never "rule absent".
    fn locked() -> Option<Out> {
        Some(Out {
            ok: false,
            code: Some(4),
            stdout: String::new(),
        })
    }

    #[tokio::test]
    async fn a_lock_error_never_counts_as_the_rule_being_gone() {
        let f = Fake::new(|l| {
            if fw(l, "") {
                locked()
            } else {
                ok("x returned 0 (success.)")
            }
        });
        assert!(!apply(&f, Profile::Mobile, false).await, "Mobile");
        assert!(!apply(&f, Profile::Fixed, false).await, "Fixed");
        let r = root("locked", &[], Some("1\n"), Some(Profile::Fixed));
        let v = serde_json::to_value(readings(&f, &r).await).unwrap();
        assert!(v["firewall"].is_null(), "{v}");
    }

    #[tokio::test]
    async fn every_iptables_call_waits_for_the_lock() {
        let f = device();
        assert!(apply(&f, Profile::Fixed, false).await);
        assert!(apply(&f, Profile::Mobile, false).await);
        let c = f.calls();
        let fwc = |c: &&String| c.starts_with("iptables") || c.starts_with("ip6tables");
        assert_eq!(
            c.iter()
                .filter(fwc)
                .filter(|c| c.starts_with("ip6"))
                .count()
                > 0,
            true
        );
        for c in c.iter().filter(fwc) {
            assert!(c.contains("tables -w "), "{c}");
        }
    }

    #[tokio::test]
    async fn the_boot_re_apply_skips_the_mobile_hotspot_step() {
        let f = device();
        assert!(apply(&f, Profile::Mobile, true).await);
        assert_eq!(first(&f.calls(), "wifi_cli"), usize::MAX);
    }

    #[tokio::test]
    async fn a_garbled_profile_is_reported_as_unknown() {
        let r = root("garbled", &[], None, None);
        std::fs::create_dir_all(r.join("data/rayhunter")).unwrap();
        std::fs::write(r.join("data/rayhunter/profile"), "").unwrap();
        let v = serde_json::to_value(readings(&Fake::new(|_| None), &r).await).unwrap();
        assert_eq!(v["profile"], "unrecognised");
    }

    /// Unit 1, 2026-10-09: `set_ap_enable 0` on a hotspot that is already
    /// off returns "general error", which failed the first Fixed switch.
    fn wifi(state: &'static str) -> Fake {
        Fake::new(move |l| {
            if l.starts_with("wifi_cli get_ap_enable") {
                ok(state)
            } else if l.starts_with("wifi_cli set_ap_enable") {
                ok("wifi_set_ap_enabled returned 1 (WIFI: general error.)")
            } else if fw(l, " -w -C") || fw(l, " -w -D") {
                fails()
            } else {
                ok("x returned 0 (success.)")
            }
        })
    }

    #[tokio::test]
    async fn a_hotspot_already_off_is_left_alone() {
        let f = wifi("wifi_get_ap_enabled returned 0 (WIFI: success.)\nWifi AP mode is :[0] \n");
        assert!(apply(&f, Profile::Fixed, false).await);
        assert_eq!(first(&f.calls(), "wifi_cli set_ap_enable"), usize::MAX);
    }

    #[tokio::test]
    async fn a_hotspot_that_is_on_must_go_off() {
        // On, and the set fails: the step fails.
        let f = wifi("Wifi AP mode is :[1] ");
        assert!(!apply(&f, Profile::Fixed, false).await);
        assert!(first(&f.calls(), "wifi_cli set_ap_enable <0,") < usize::MAX);
        // Unreadable: try the set; it must succeed.
        let f = wifi("wifi_get_ap_enabled returned 1 (WIFI: general error.)");
        assert!(!apply(&f, Profile::Fixed, false).await);
        assert!(first(&f.calls(), "wifi_cli set_ap_enable <0,") < usize::MAX);
    }

    fn quick(tries: u32) -> BootTiming {
        BootTiming {
            retry: std::time::Duration::from_millis(1),
            settle: std::time::Duration::from_millis(1),
            tries,
        }
    }

    /// A device whose rules are real state: -I adds, -C reads. The first
    /// `ccm_down` set_wwan_ac calls fail (ccm2 not started yet at S74).
    fn booting(ccm_down: usize) -> Fake {
        let st = std::sync::Mutex::new((ccm_down, [0usize; 4]));
        Fake::new(move |l| {
            let mut st = st.lock().unwrap();
            let i = l.starts_with("ip6") as usize * 2 + if l.contains(" OUTPUT ") { 0 } else { 1 };
            if l.starts_with("ccm2_cli set_wwan_ac") && st.0 > 0 {
                st.0 -= 1;
                return ok("ccm_set_wwan_ac returned 6 (CCM: not ready)");
            }
            if fw(l, " -w -I") {
                st.1[i] += 1;
                return ok("");
            }
            if fw(l, " -w -C") {
                return if st.1[i] > 0 { ok("") } else { fails() };
            }
            if l.starts_with("wifi_cli get_ap_enable") {
                return ok("Wifi AP mode is :[0] ");
            }
            ok("x returned 0 (success.)")
        })
    }

    #[tokio::test]
    async fn the_boot_re_apply_waits_for_the_vendor_stack() {
        let path = scratch("boot-wait", Profile::Fixed);
        let f = booting(2);
        let sw = AtomicBool::new(false);
        assert!(boot_reapply(&f, &path, Profile::Fixed, &sw, quick(10)).await);
        let n = f
            .calls()
            .iter()
            .filter(|c| c.starts_with("ccm2_cli set_wwan_ac"))
            .count();
        assert_eq!(n, 3, "two refusals, then it took");
        assert!(!sw.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn the_boot_re_apply_puts_back_a_rule_the_router_wiped() {
        let path = scratch("boot-flush", Profile::Fixed);
        // OUTPUT is wiped once, between the first apply and the settle check:
        // the first insert never sticks, the second does.
        let inserts = std::sync::Mutex::new(0usize);
        let f = Fake::new(move |l| {
            let mut n = inserts.lock().unwrap();
            if l.starts_with("iptables -w -I OUTPUT") {
                *n += 1;
                return ok("");
            }
            if l.starts_with("iptables -w -C OUTPUT") {
                return if *n >= 2 { ok("") } else { fails() };
            }
            if l.starts_with("iptables -w -C FORWARD") {
                return ok("");
            }
            if l.starts_with("wifi_cli get_ap_enable") {
                return ok("Wifi AP mode is :[0] ");
            }
            ok("x returned 0 (success.)")
        });
        let sw = AtomicBool::new(false);
        assert!(boot_reapply(&f, &path, Profile::Fixed, &sw, quick(10)).await);
        let n = f
            .calls()
            .iter()
            .filter(|c| c.starts_with("iptables -w -I OUTPUT"))
            .count();
        assert_eq!(n, 2, "{:?}", f.calls());
    }

    #[tokio::test]
    async fn the_boot_re_apply_gives_up_after_its_tries() {
        let path = scratch("boot-never", Profile::Fixed);
        let f = booting(usize::MAX);
        let sw = AtomicBool::new(false);
        assert!(!boot_reapply(&f, &path, Profile::Fixed, &sw, quick(4)).await);
        let n = f
            .calls()
            .iter()
            .filter(|c| c.starts_with("ccm2_cli set_wwan_ac"))
            .count();
        assert_eq!(n, 4);
    }

    #[tokio::test]
    async fn the_boot_re_apply_yields_to_the_owner() {
        // The owner switched to Mobile while boot was still retrying Fixed.
        let path = scratch("boot-owner", Profile::Mobile);
        let f = booting(0);
        let sw = AtomicBool::new(false);
        assert!(boot_reapply(&f, &path, Profile::Fixed, &sw, quick(4)).await);
        assert!(f.calls().is_empty(), "{:?}", f.calls());
        // A switch in progress: that attempt is skipped, not run alongside it.
        let path = scratch("boot-busy", Profile::Fixed);
        let sw = AtomicBool::new(true);
        assert!(!boot_reapply(&f, &path, Profile::Fixed, &sw, quick(2)).await);
        assert!(f.calls().is_empty(), "{:?}", f.calls());
    }

    #[tokio::test]
    async fn the_mobile_confirmation_retries_until_the_network_carries_it() {
        // Unit 1: "Connected" came 15 s after the switch, but the first send
        // failed; the same send a minute later went through.
        let path = scratch("confirm", Profile::Mobile);
        let tries = std::sync::Mutex::new(0);
        let tick = std::time::Duration::from_millis(1);
        let sent = retry_send(&path, tick, 6, || {
            let n = {
                let mut t = tries.lock().unwrap();
                *t += 1;
                *t
            };
            async move { n >= 3 }
        })
        .await;
        assert!(sent);
        assert_eq!(*tries.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn the_mobile_confirmation_gives_up_and_never_sends_after_a_switch_back() {
        let path = scratch("confirm-never", Profile::Mobile);
        let tick = std::time::Duration::from_millis(1);
        let n = std::sync::Mutex::new(0);
        assert!(
            !retry_send(&path, tick, 4, || {
                *n.lock().unwrap() += 1;
                async { false }
            })
            .await
        );
        assert_eq!(*n.lock().unwrap(), 4);
        // Switched back to Fixed: nothing goes out.
        let path = scratch("confirm-fixed", Profile::Fixed);
        let n = std::sync::Mutex::new(0);
        assert!(
            !retry_send(&path, tick, 4, || {
                *n.lock().unwrap() += 1;
                async { true }
            })
            .await
        );
        assert_eq!(*n.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn fixed_blocks_ipv6_too_before_any_vendor_command() {
        // The vendor turns IPv6 back on when data comes up (unit 1,
        // 2026-10-09), so disable_ipv6 alone is not a backstop.
        let f = device();
        assert!(apply(&f, Profile::Fixed, false).await);
        let c = f.calls();
        for chain in ["OUTPUT", "FORWARD"] {
            let at = first(&c, &format!("ip6tables -w -I {chain} -o rmnet+ -j DROP"));
            assert!(at < first(&c, "sh -c"), "{chain}: {c:?}");
        }
        // Mobile takes them down again.
        let f = device();
        assert!(apply(&f, Profile::Mobile, false).await);
        let c = f.calls();
        assert!(first(&c, "ip6tables -w -D OUTPUT") < usize::MAX, "{c:?}");
        assert!(first(&c, "ip6tables -w -D FORWARD") < usize::MAX, "{c:?}");
    }

    #[tokio::test]
    async fn the_firewall_reads_on_only_with_the_ipv6_rules_too() {
        let f = Fake::new(|l| {
            if l.starts_with("iptables -w -C") {
                ok("")
            } else {
                fails()
            }
        });
        let r = root("v4-only", &[], Some("1\n"), Some(Profile::Fixed));
        let v = serde_json::to_value(readings(&f, &r).await).unwrap();
        assert_eq!(v["firewall"], false, "{v}");
    }
}
