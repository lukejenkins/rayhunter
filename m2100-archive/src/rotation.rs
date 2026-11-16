//! Capture rotation: Rayhunter only starts a new capture when recording restarts, so one
//! capture can grow for days and nothing reaches the archive. Each cycle, before the pull,
//! the current capture is stopped and a new one started once it is `hours` old, or early
//! once the unit's capture storage is `disk_pct` full and the capture is at least an hour
//! old. If the storage stays that full after a disk rotation (and its pull) had their
//! chance, it is not captures filling it: disk rotations pause until it drops below.
//!
//! The unit is untrusted and its clock is attacker-influenced (a fake base station can set
//! it to 2099 by NITZ; unsynced it reads 1970). A capture's age is therefore measured on the
//! add-on's own clock: the time this add-on first saw that capture name as current, kept in
//! the index's `meta` table so it survives restarts. The unit's `start_time` is never read.
//!
//! The unit is never left stopped on purpose: a start that fails (or opens no new capture)
//! is retried at once, and then every cycle, whatever the thresholds, until a capture runs.
//! The intent is written before the stop, so an add-on that dies mid-rotation restarts the
//! unit on its next cycle.

use chrono::{DateTime, Duration, Utc};

use crate::device::{Device, DeviceError};
use crate::store::Store;

/// No rotation within this many minutes of the last one (Yellow clock).
pub const FLOOR_MIN: i64 = 10;
/// The disk rule needs the current capture at least this old (Yellow clock).
pub const DISK_MIN_AGE_MIN: i64 = 60;
/// After the unit refuses stop/start (debug mode, busy), no attempt for this long.
pub const BACKOFF_MIN: i64 = 60;
/// Between stop and start.
pub const PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Settings {
    /// Rotate a capture this many hours old; 0 = rotation off (the disk rule too).
    pub hours: i64,
    /// Also rotate once the unit's storage `used_percent` is at least this.
    pub disk_pct: u32,
    pub pause: std::time::Duration,
}

impl Default for Settings {
    /// Off: only `with_rotation` (from the add-on options) turns it on.
    fn default() -> Self {
        Settings { hours: 0, disk_pct: 70, pause: PAUSE }
    }
}

/// One rotation attempt, for the log and the Cribl output.
#[derive(Debug, Clone, PartialEq)]
pub struct Rotation {
    /// "age" / "disk" / "retry".
    pub reason: &'static str,
    pub ok: bool,
    /// The capture that was stopped (the unit's text, untrusted).
    pub previous: Option<String>,
    /// The new current capture; `None` if none was started.
    pub current: Option<String>,
    pub used_percent: Option<u32>,
    /// Age of `previous` on the add-on's clock, hours to one decimal.
    pub age_hours: Option<f64>,
}

// Kept in the index's `meta` table, all times on the Yellow's clock.
/// The current capture's name as last seen, and when this add-on first saw it current.
const K_NAME: &str = "rotation_current";
const K_FIRST_SEEN: &str = "rotation_first_seen";
/// The last attempt (the floor) and the last success (the sensor).
const K_LAST_TRY: &str = "rotation_last_try";
const K_LAST_OK: &str = "rotation_last_ok";
/// Set (to the reason) from just before a stop until a new capture is confirmed: while
/// set and nothing records, the start is retried every cycle.
const K_RETRY: &str = "rotation_retry";
/// A disk rotation succeeded: the next disk reading says whether it freed anything.
const K_DISK_CHECK: &str = "rotation_disk_check";
/// Storage stayed full after a disk rotation: disk rotations pause until it drops.
const K_DISK_FULL: &str = "rotation_disk_full";
/// No attempt before this time (the unit refused stop/start).
const K_BACKOFF_UNTIL: &str = "rotation_backoff_until";
/// A capture name is the unit's text: kept printable and bounded.
const NAME_MAX: usize = 128;

/// When the last successful rotation happened (Yellow clock), for the HA sensor.
/// `Err`: the index could not be read (the state is then not published).
pub fn last_rotation(store: &Store) -> anyhow::Result<Option<DateTime<Utc>>> {
    store.meta_time(K_LAST_OK)
}

/// Run before the pull. `None`: nothing was attempted. `pulls_paused`: the Yellow is too
/// full to pull, so a disk rotation would free nothing (the disk rule is off).
pub async fn run(
    dev: &dyn Device,
    store: &Store,
    s: &Settings,
    now: DateTime<Utc>,
    pulls_paused: bool,
) -> Option<Rotation> {
    match step(dev, store, s, now, pulls_paused).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("rotation skipped: index: {e:#}");
            None
        }
    }
}

async fn step(
    dev: &dyn Device,
    store: &Store,
    s: &Settings,
    now: DateTime<Utc>,
    pulls_paused: bool,
) -> anyhow::Result<Option<Rotation>> {
    let retry = store.meta(K_RETRY)?.is_some();
    if s.hours <= 0 && !retry {
        return Ok(None);
    }
    let current = match dev.current().await {
        Ok(c) => c,
        Err(DeviceError::Bad(e)) => {
            log::warn!("rotation skipped: the unit's manifest is unreadable ({e})");
            return Ok(None);
        }
        Err(e) => {
            log::info!("rotation skipped: unit not reached ({e:?})");
            return Ok(None);
        }
    };
    let tracked = store.meta(K_NAME)?;
    if retry {
        if current.is_none() {
            // A rotation of ours stopped the unit and no capture runs: start it, whatever
            // the thresholds, the floor and the back-off.
            store.set_meta_time(K_LAST_TRY, now)?;
            let a = start(dev, None, false).await;
            return Ok(Some(finish(store, "retry", tracked, a, None, None, now)));
        }
        // Something is recording again (started by hand, or a slow start): done.
        store.del_meta(K_RETRY)?;
        log::info!("rotation: a capture is recording again");
    }
    let Some(name) = current else {
        // Nothing recording and not because of us: not ours to start.
        return Ok(None);
    };
    if s.hours <= 0 {
        return Ok(None);
    }
    // Age on the Yellow's clock: from when this add-on first saw the name current.
    let key = crate::events::printable(&name, NAME_MAX);
    let first_seen = match store.meta_time(K_FIRST_SEEN)? {
        Some(t) if tracked.as_deref() == Some(key.as_str()) && t <= now => t,
        // New name (or the Yellow's clock went back): its age starts now.
        _ => {
            store.set_meta(K_NAME, &key)?;
            store.set_meta_time(K_FIRST_SEEN, now)?;
            now
        }
    };
    let age = now - first_seen;
    // Unknown storage use: only the age rule applies this cycle.
    let used = dev.disk_used_percent().await.ok();
    let disk_full = disk_episode(store, s, used)?;
    let reason = if age >= Duration::hours(s.hours) {
        "age"
    } else if !pulls_paused
        && !disk_full
        && age >= Duration::minutes(DISK_MIN_AGE_MIN)
        && used.is_some_and(|u| u >= s.disk_pct)
    {
        "disk"
    } else {
        return Ok(None);
    };
    if let Some(until) = store.meta_time(K_BACKOFF_UNTIL)? {
        // (Far in the future means the Yellow's clock went back: ignore it.)
        if now < until && until - now <= Duration::minutes(BACKOFF_MIN) {
            log::debug!("rotation due ({reason}) but backing off");
            return Ok(None);
        }
        store.del_meta(K_BACKOFF_UNTIL)?;
    }
    if let Some(last) = store.meta_time(K_LAST_TRY)? {
        // (A last attempt in the future means the Yellow's clock went back: no floor.)
        if last <= now && now - last < Duration::minutes(FLOOR_MIN) {
            log::debug!("rotation due ({reason}) but inside the {FLOOR_MIN} min floor");
            return Ok(None);
        }
    }
    store.set_meta_time(K_LAST_TRY, now)?;
    // Before the stop: if the add-on dies before the start, the next cycle starts the unit.
    store.set_meta(K_RETRY, reason)?;
    let mut refused = false;
    if let Err(e) = dev.stop_recording().await {
        // A start closes the open capture anyway, so carry on.
        log::warn!("rotation: stop-recording failed ({e:?}); starting anyway");
        refused = matches!(e, DeviceError::Refused | DeviceError::Busy);
    }
    tokio::time::sleep(s.pause).await;
    let a = start(dev, Some(&name), refused).await;
    let hours = age.num_seconds() as f64 / 3600.0;
    Ok(Some(finish(store, reason, Some(name), a, used, Some(hours), now)))
}

/// Updates the "storage stays full" episode from this cycle's reading; true while it lasts.
fn disk_episode(store: &Store, s: &Settings, used: Option<u32>) -> anyhow::Result<bool> {
    if let Some(u) = used {
        let full = u >= s.disk_pct;
        // The first reading after a disk rotation, whose pull and delete have run since.
        if store.meta(K_DISK_CHECK)?.is_some() {
            store.del_meta(K_DISK_CHECK)?;
            if full && store.meta(K_DISK_FULL)?.is_none() {
                store.set_meta(K_DISK_FULL, "1")?;
                log::warn!(
                    "rotation: unit storage stays full ({u}%) after a disk rotation: not \
                     captures; disk rotations paused until it drops below {}%",
                    s.disk_pct
                );
            }
        }
        if !full && store.meta(K_DISK_FULL)?.is_some() {
            store.del_meta(K_DISK_FULL)?;
            log::info!("rotation: unit storage below {}% again; disk rotations resume", s.disk_pct);
        }
    }
    Ok(store.meta(K_DISK_FULL)?.is_some())
}

/// What a start attempt left running.
struct Attempt {
    /// The new current capture.
    new: Option<String>,
    /// The old capture is still recording (stop and start had no effect).
    still_old: bool,
    /// The unit refused (403 debug mode) or was busy.
    refused: bool,
}

/// Start recording and confirm a new capture runs (a current name other than
/// `previous`); one immediate retry.
async fn start(dev: &dyn Device, previous: Option<&str>, refused: bool) -> Attempt {
    let mut a = Attempt { new: None, still_old: false, refused };
    for _ in 0..2 {
        if let Err(e) = dev.start_recording().await {
            log::warn!("rotation: start-recording failed ({e:?})");
            a.refused |= matches!(e, DeviceError::Refused | DeviceError::Busy);
        }
        match dev.current().await {
            Ok(Some(n)) if Some(n.as_str()) != previous => {
                a.new = Some(n);
                return a;
            }
            Ok(Some(_)) => a.still_old = true,
            Ok(None) => a.still_old = false,
            Err(e) => {
                // Unknown: assume nothing records, so a retry stays armed.
                a.still_old = false;
                log::warn!("rotation: cannot read the manifest ({e:?})");
            }
        }
    }
    a
}

/// Record the attempt's result. Index errors are logged, never lose the event.
fn finish(
    store: &Store,
    reason: &'static str,
    previous: Option<String>,
    a: Attempt,
    used_percent: Option<u32>,
    age_hours: Option<f64>,
    now: DateTime<Utc>,
) -> Rotation {
    let ok = a.new.is_some();
    let saved = (|| -> anyhow::Result<()> {
        if let Some(n) = &a.new {
            store.set_meta_time(K_LAST_OK, now)?;
            store.set_meta(K_NAME, &crate::events::printable(n, NAME_MAX))?;
            store.set_meta_time(K_FIRST_SEEN, now)?;
            if reason == "disk" {
                store.set_meta(K_DISK_CHECK, "1")?;
            }
            // Last: until here a crash leaves the retry armed (harmless: something runs).
            store.del_meta(K_RETRY)?;
        } else if a.still_old {
            // Still recording: nothing to retry.
            store.del_meta(K_RETRY)?;
            if a.refused {
                store.set_meta_time(K_BACKOFF_UNTIL, now + Duration::minutes(BACKOFF_MIN))?;
            }
        } else {
            store.set_meta(K_RETRY, reason)?;
        }
        Ok(())
    })();
    if let Err(e) = saved {
        log::error!("rotation: cannot record the result: {e:#}");
    }
    if !ok && a.still_old {
        if a.refused {
            log::warn!(
                "capture rotation ({reason}): the unit refused stop/start (debug mode or \
                 busy?) and keeps recording the old capture; no rotation for {BACKOFF_MIN} min"
            );
        } else {
            log::warn!("capture rotation ({reason}): the old capture is still recording");
        }
    } else if !ok {
        log::error!(
            "capture rotation ({reason}) failed: no capture is recording on the unit; \
             start retried every cycle"
        );
    }
    log::info!("capture rotation: reason {reason}, ok {ok}");
    Rotation { reason, ok, previous, current: a.new, used_percent, age_hours }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Cycle, Runner};
    use crate::device::Fake;
    use serde_json::Value;
    use std::path::Path;
    use std::sync::Arc;

    /// The Yellow's clock: `m` minutes after 2026-10-15 00:00 UTC.
    fn t(m: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_792_022_400 + m * 60, 0).unwrap()
    }

    fn unit_time(rfc: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc).unwrap().with_timezone(&Utc)
    }

    fn runner(fake: Arc<Fake>, dir: &Path, hours: i64, disk_pct: u32) -> Runner {
        runner_free(fake, dir, hours, disk_pct, 100_000_000_000)
    }

    /// `free`: bytes free on the Yellow (under 5 GB pauses the pulls).
    fn runner_free(fake: Arc<Fake>, dir: &Path, hours: i64, disk_pct: u32, free: u64) -> Runner {
        let store = Store::open(&dir.join("i.sqlite")).unwrap();
        Runner::new(fake, store, &dir.join("archive"), Box::new(move || free))
            .with_rotation(Settings { hours, disk_pct, pause: std::time::Duration::ZERO })
    }

    /// A second connection to the runner's index, as a restart would open it.
    fn index(dir: &Path) -> Store {
        Store::open(&dir.join("i.sqlite")).unwrap()
    }

    fn calls(f: &Fake, key: &str) -> usize {
        f.log().iter().filter(|l| *l == key).count()
    }

    fn rotations(c: &Cycle) -> Vec<&Value> {
        c.cribl.iter().filter(|e| e["type"] == "rotation").collect()
    }

    fn last_rotation_state(c: &Cycle) -> String {
        c.states
            .iter()
            .find(|(k, _)| k.ends_with("/last_rotation"))
            .expect("a last_rotation state")
            .1
            .clone()
    }

    fn rfc(t: DateTime<Utc>) -> String {
        t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    /// 1: six hours on the Yellow's clock -> stop + start, a new capture, and the finished
    /// one pulled in the same cycle.
    #[tokio::test]
    async fn rotates_by_age_and_pulls_the_finished_capture_in_the_same_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"old capture", t(0));
        let r = runner(fake.clone(), dir.path(), 6, 70);
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(rotations(&c).is_empty());
        assert_eq!(last_rotation_state(&c), "None");
        let c = r.on_tick(t(6 * 60 - 1)).await.unwrap();
        assert!(rotations(&c).is_empty(), "5 h 59 min: not yet");
        assert_eq!(calls(&fake, "stop_recording"), 0);

        let c = r.on_tick(t(6 * 60)).await.unwrap();
        assert_eq!((calls(&fake, "stop_recording"), calls(&fake, "start_recording")), (1, 1));
        assert_eq!(fake.current_name().as_deref(), Some("1800000001"));
        let log = fake.log();
        let pos = |k: &str| log.iter().position(|l| l == k).unwrap();
        assert!(pos("stop_recording") < pos("start_recording"));
        assert!(pos("start_recording") < pos("download 100"), "pulled after the rotation");
        assert!(!fake.has("100"), "archived, verified and deleted from the unit");
        let ev = rotations(&c);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["reason"], "age");
        assert_eq!(ev[0]["ok"], true);
        assert_eq!(ev[0]["previous"], "100");
        assert_eq!(ev[0]["current"], "1800000001");
        assert_eq!(ev[0]["age_hours"], 6.0);
        assert_eq!(ev[0]["used_percent"], 0);
        assert_eq!(last_rotation_state(&c), rfc(t(6 * 60)));
        assert_eq!(c.cribl[0]["type"], "cycle", "the cycle event still leads");

        // The new capture's age starts now.
        let c = r.on_tick(t(6 * 60 + 15)).await.unwrap();
        assert!(rotations(&c).is_empty());
        assert_eq!(calls(&fake, "stop_recording"), 1);
        assert_eq!(last_rotation_state(&c), rfc(t(6 * 60)));
    }

    /// A different current name (restarted by hand) resets the age.
    #[tokio::test]
    async fn a_new_current_name_resets_the_age() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        fake.set_current("200", b"b", t(300));
        r.on_tick(t(300)).await.unwrap();
        r.on_tick(t(6 * 60)).await.unwrap();
        assert_eq!(calls(&fake, "stop_recording"), 0, "200 is one hour old");
        r.on_tick(t(300 + 6 * 60)).await.unwrap();
        assert_eq!(calls(&fake, "stop_recording"), 1);
    }

    /// 2: storage at the threshold rotates a capture at least an hour old (Yellow clock);
    /// a younger one, or storage just below, does not.
    #[tokio::test]
    async fn rotates_by_disk_once_an_hour_old() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.set_disk(69);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        let c = r.on_tick(t(60)).await.unwrap();
        assert!(rotations(&c).is_empty(), "69 %");
        fake.set_disk(70);
        let c = r.on_tick(t(59)).await.unwrap();
        assert!(rotations(&c).is_empty(), "70 % but 59 min old");
        let c = r.on_tick(t(75)).await.unwrap();
        assert_eq!(calls(&fake, "stop_recording"), 1);
        let ev = rotations(&c);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("disk"), Some(true)));
        assert_eq!(ev[0]["used_percent"], 70);
        assert_eq!(ev[0]["age_hours"], 1.3);
    }

    /// The next disk reading after a disk rotation (that rotation's pull and delete had
    /// their chance) still at the threshold: storage is not full of captures, so disk
    /// rotations stop until it drops below. The age rule carries on.
    #[tokio::test]
    async fn disk_rotations_pause_while_storage_stays_full() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.set_disk(80);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        r.on_tick(t(60)).await.unwrap();
        assert_eq!(calls(&fake, "stop_recording"), 1, "disk rotation");
        // Still 80 % at the next reading: the episode starts.
        for m in [75, 120, 180, 240] {
            let c = r.on_tick(t(m)).await.unwrap();
            assert!(rotations(&c).is_empty(), "minute {m}");
        }
        assert_eq!(index(dir.path()).meta(K_DISK_FULL).unwrap().as_deref(), Some("1"));
        // The age rule is not affected.
        let c = r.on_tick(t(60 + 360)).await.unwrap();
        assert_eq!(rotations(&c)[0]["reason"], "age");
        assert_eq!(calls(&fake, "stop_recording"), 2);
        // Below the threshold: the episode ends; above again later, disk rotations resume.
        fake.set_disk(60);
        r.on_tick(t(60 + 375)).await.unwrap();
        assert_eq!(index(dir.path()).meta(K_DISK_FULL).unwrap(), None);
        fake.set_disk(75);
        let c = r.on_tick(t(60 + 360 + 60)).await.unwrap();
        assert_eq!(rotations(&c)[0]["reason"], "disk");
    }

    /// A disk rotation that did free the unit: no episode.
    #[tokio::test]
    async fn a_disk_rotation_that_frees_space_starts_no_episode() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.set_disk(80);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        r.on_tick(t(60)).await.unwrap();
        fake.set_disk(40);
        r.on_tick(t(75)).await.unwrap();
        fake.set_disk(80);
        r.on_tick(t(120)).await.unwrap();
        assert_eq!(calls(&fake, "stop_recording"), 2, "rotated again an hour later");
    }

    /// Pulls paused (Yellow under 5 GB free): the disk rule is off (nothing would be pulled
    /// or deleted, and the unit may refuse to start again); the age rule still runs.
    #[tokio::test]
    async fn no_disk_rotation_while_pulls_are_paused() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.set_disk(99);
        let r = runner_free(fake.clone(), dir.path(), 6, 70, 1_000_000_000);
        for m in [0, 60, 120, 359] {
            let c = r.on_tick(t(m)).await.unwrap();
            assert!(rotations(&c).is_empty(), "minute {m}");
        }
        let c = r.on_tick(t(360)).await.unwrap();
        assert_eq!(rotations(&c)[0]["reason"], "age");
    }

    /// 3: never two rotations within 10 minutes (Yellow clock), whatever is due.
    #[tokio::test]
    async fn ten_minute_floor() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        // An attempt 1 min before the capture is due (e.g. one whose result was lost).
        index(dir.path()).set_meta_time(K_LAST_TRY, t(359)).unwrap();
        let c = r.on_tick(t(360)).await.unwrap();
        assert!(rotations(&c).is_empty(), "1 min after the last attempt");
        r.on_tick(t(368)).await.unwrap();
        assert_eq!(calls(&fake, "stop_recording"), 0, "9 min after");
        r.on_tick(t(369)).await.unwrap();
        assert_eq!(calls(&fake, "stop_recording"), 1, "10 min after");
    }

    /// 4: rotate_hours = 0 turns rotation off, the disk rule too; rotation never asks the unit.
    #[tokio::test]
    async fn zero_hours_never_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.set_disk(99);
        let r = runner(fake.clone(), dir.path(), 0, 70);
        for m in [0, 15, 48 * 60, 30 * 24 * 60] {
            let c = r.on_tick(t(m)).await.unwrap();
            assert!(rotations(&c).is_empty());
            assert_eq!(last_rotation_state(&c), "None");
        }
        for k in ["current", "stop_recording", "start_recording"] {
            assert_eq!(calls(&fake, k), 0, "{k}");
        }
        // Once a cycle for the low-disk notice (app.rs); rotation itself never asks.
        assert_eq!(calls(&fake, "disk"), 4, "disk");
        assert_eq!(fake.current_name().as_deref(), Some("100"));
    }

    /// 5: a start that fails is retried at once; still failing, the cycle reports it and
    /// the next cycles retry the start alone, whatever the thresholds, until one runs.
    #[tokio::test]
    async fn a_failed_start_is_retried_until_a_capture_runs() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.fail("start_recording", DeviceError::Bad("507".into()));
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        let c = r.on_tick(t(360)).await.unwrap();
        assert_eq!((calls(&fake, "stop_recording"), calls(&fake, "start_recording")), (1, 2));
        let ev = rotations(&c);
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("age"), Some(false)));
        assert_eq!(ev[0]["previous"], "100");
        assert_eq!(ev[0]["current"], Value::Null);
        assert_eq!(last_rotation_state(&c), "None", "nothing rotated yet");
        assert_eq!(fake.current_name(), None, "the unit is stopped");

        // Next cycle: below every threshold, the start is retried (no stop).
        let c = r.on_tick(t(375)).await.unwrap();
        assert_eq!((calls(&fake, "stop_recording"), calls(&fake, "start_recording")), (1, 4));
        let ev = rotations(&c);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("retry"), Some(false)));

        fake.unfail("start_recording");
        let c = r.on_tick(t(390)).await.unwrap();
        assert_eq!((calls(&fake, "stop_recording"), calls(&fake, "start_recording")), (1, 5));
        let ev = rotations(&c);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("retry"), Some(true)));
        assert_eq!(ev[0]["current"], "1800000001");
        assert_eq!(fake.current_name().as_deref(), Some("1800000001"));
        assert_eq!(last_rotation_state(&c), rfc(t(390)));

        // Running again: nothing more, and the new capture's age starts at the retry.
        let c = r.on_tick(t(405)).await.unwrap();
        assert!(rotations(&c).is_empty());
        assert_eq!(calls(&fake, "start_recording"), 5);
    }

    /// 5b: a start that answers Ok but opens no new capture counts as failed.
    #[tokio::test]
    async fn a_start_that_opens_nothing_is_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.set_start_noop(true);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        let c = r.on_tick(t(360)).await.unwrap();
        assert_eq!(calls(&fake, "start_recording"), 2);
        let ev = rotations(&c);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("age"), Some(false)));
        fake.set_start_noop(false);
        let c = r.on_tick(t(375)).await.unwrap();
        let ev = rotations(&c);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("retry"), Some(true)));
    }

    /// 6: the unit's own timestamps are never used: a current capture stamped 1970 or 2099
    /// (and new ones stamped the same) rotate exactly when a sane one would.
    #[tokio::test]
    async fn the_units_clock_is_never_used() {
        for clock in ["1970-01-01T00:00:05Z", "2099-06-01T00:00:00Z"] {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_current("100", b"a", unit_time(clock));
            fake.set_unit_clock(unit_time(clock));
            let r = runner(fake.clone(), dir.path(), 6, 70);
            for m in [0, 60, 6 * 60 - 1] {
                let c = r.on_tick(t(m)).await.unwrap();
                assert!(rotations(&c).is_empty(), "{clock}: rotated at minute {m}");
            }
            let c = r.on_tick(t(6 * 60)).await.unwrap();
            let ev = rotations(&c);
            assert_eq!(ev.len(), 1, "{clock}: no rotation at 6 h");
            assert_eq!(ev[0]["age_hours"], 6.0, "{clock}");
            // The new capture (stamped by the same clock) also waits its 6 h.
            for m in [6 * 60 + 15, 12 * 60 - 1] {
                let c = r.on_tick(t(m)).await.unwrap();
                assert!(rotations(&c).is_empty(), "{clock}: rotated at minute {m}");
            }
            r.on_tick(t(12 * 60)).await.unwrap();
            assert_eq!(calls(&fake, "stop_recording"), 2, "{clock}");
        }
    }

    /// 7: an unreachable unit gets no rotation calls, not even the retry of a failed start.
    #[tokio::test]
    async fn an_unreachable_unit_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.set_disk(99);
        fake.fail("current", DeviceError::Unreachable);
        fake.fail("finished", DeviceError::Unreachable);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        for m in [0, 6 * 60, 24 * 60] {
            let c = r.on_tick(t(m)).await.unwrap();
            assert!(rotations(&c).is_empty());
        }
        assert_eq!((calls(&fake, "stop_recording"), calls(&fake, "start_recording")), (0, 0));

        // A pending retry waits for the unit too.
        fake.unfail("current");
        fake.unfail("finished");
        fake.fail("start_recording", DeviceError::Unreachable);
        r.on_tick(t(25 * 60)).await.unwrap(); // first seen now
        r.on_tick(t(26 * 60)).await.unwrap();
        let starts = calls(&fake, "start_recording");
        assert_eq!(starts, 2, "rotated (disk, 1 h old), start failed twice");
        fake.fail("current", DeviceError::Unreachable);
        let c = r.on_tick(t(26 * 60 + 15)).await.unwrap();
        assert!(rotations(&c).is_empty());
        assert_eq!(calls(&fake, "start_recording"), starts);
    }

    /// 8: first_seen survives an add-on restart (the index is reopened).
    #[tokio::test]
    async fn first_seen_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        {
            let r = runner(fake.clone(), dir.path(), 6, 70);
            r.on_tick(t(0)).await.unwrap();
        }
        let r = runner(fake.clone(), dir.path(), 6, 70);
        let c = r.on_tick(t(6 * 60)).await.unwrap();
        assert_eq!(rotations(&c).len(), 1, "6 h since it was first seen, before the restart");
        assert_eq!(calls(&fake, "stop_recording"), 1);
        // And the last rotation (the sensor, the floor) survives too.
        let r = runner(fake.clone(), dir.path(), 6, 70);
        fake.set_disk(99);
        let c = r.on_tick(t(6 * 60 + 5)).await.unwrap();
        assert!(rotations(&c).is_empty(), "inside the floor");
        assert_eq!(last_rotation_state(&c), rfc(t(6 * 60)));
    }

    /// The add-on dies between stop and start (an update mid-rotation): the next cycle,
    /// from the reopened index, starts the unit.
    #[tokio::test]
    async fn a_crash_between_stop_and_start_still_restarts_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.gate("start_recording");
        {
            let r = runner(fake.clone(), dir.path(), 6, 70);
            r.on_tick(t(0)).await.unwrap();
            let wait = std::time::Duration::from_millis(300);
            let cut = tokio::time::timeout(wait, r.on_tick(t(360))).await;
            assert!(cut.is_err(), "the cycle is stuck inside start-recording");
        } // the runner (and its index connection) is gone mid-rotation
        assert_eq!(calls(&fake, "stop_recording"), 1);
        assert_eq!(fake.current_name(), None, "stopped");
        fake.release("start_recording", 100);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        let c = r.on_tick(t(375)).await.unwrap();
        let ev = rotations(&c);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("retry"), Some(true)));
        assert_eq!(fake.current_name().as_deref(), Some("1800000001"));
    }

    /// A failed stop does not hold the start back (the daemon's start closes the capture).
    #[tokio::test]
    async fn a_failed_stop_still_sends_start() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.fail("stop_recording", DeviceError::Unreachable);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        let c = r.on_tick(t(360)).await.unwrap();
        assert_eq!((calls(&fake, "stop_recording"), calls(&fake, "start_recording")), (1, 1));
        let ev = rotations(&c);
        assert_eq!((ev[0]["ok"].as_bool(), ev[0]["current"].as_str()), (Some(true), Some("1800000001")));
        assert!(fake.log().iter().any(|l| l == "download 100"), "finished and pulled");
    }

    /// No storage reading: only the age rule applies, and the event says unknown.
    #[tokio::test]
    async fn an_unreadable_disk_leaves_only_the_age_rule() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.fail("disk", DeviceError::Bad("no used_percent".into()));
        let r = runner(fake.clone(), dir.path(), 6, 70);
        for m in [0, 60, 120, 359] {
            assert!(rotations(&r.on_tick(t(m)).await.unwrap()).is_empty());
        }
        let c = r.on_tick(t(360)).await.unwrap();
        let ev = rotations(&c);
        assert_eq!(ev[0]["reason"], "age");
        assert_eq!(ev[0]["used_percent"], Value::Null);
    }

    /// A hostile name (long, control characters) is kept truncated and printable, and the
    /// raw name the unit keeps sending still matches it: its age is not reset every cycle.
    #[tokio::test]
    async fn a_hostile_name_is_tracked_by_its_truncated_key() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        let hostile = format!("{}\u{1b}[31m{}", "9".repeat(150), "x".repeat(50));
        fake.set_current(&hostile, b"a", t(0));
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        let kept = index(dir.path()).meta(K_NAME).unwrap().unwrap();
        assert_eq!(kept, "9".repeat(NAME_MAX));
        for m in [60, 359] {
            assert!(rotations(&r.on_tick(t(m)).await.unwrap()).is_empty());
        }
        let c = r.on_tick(t(360)).await.unwrap();
        let ev = rotations(&c);
        assert_eq!(ev.len(), 1, "6 h after it was first seen");
        assert_eq!(ev[0]["previous"].as_str().unwrap(), "9".repeat(64));
    }

    /// A unit that refuses stop/start (403 in debug mode, 409 busy) keeps recording the old
    /// capture: no retry, no ERROR every cycle; one warning, then an hour's back-off.
    #[tokio::test]
    async fn a_refusing_unit_backs_off_for_an_hour() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        fake.fail("stop_recording", DeviceError::Refused);
        fake.fail("start_recording", DeviceError::Refused);
        let r = runner(fake.clone(), dir.path(), 6, 70);
        r.on_tick(t(0)).await.unwrap();
        let c = r.on_tick(t(360)).await.unwrap();
        let ev = rotations(&c);
        assert_eq!((ev[0]["reason"].as_str(), ev[0]["ok"].as_bool()), (Some("age"), Some(false)));
        assert_eq!(fake.current_name().as_deref(), Some("100"), "still recording");
        assert_eq!(index(dir.path()).meta(K_RETRY).unwrap(), None, "nothing to retry");
        let starts = calls(&fake, "start_recording");
        for m in [375, 390, 360 + 59] {
            let c = r.on_tick(t(m)).await.unwrap();
            assert!(rotations(&c).is_empty(), "minute {m}: backing off");
        }
        assert_eq!(calls(&fake, "start_recording"), starts);
        fake.unfail("stop_recording");
        fake.unfail("start_recording");
        let c = r.on_tick(t(420)).await.unwrap();
        assert_eq!(rotations(&c)[0]["ok"], true, "an hour later it tries again");
    }

    /// An unreadable index: the "Last rotation" state is left out, not published as "None".
    #[tokio::test]
    async fn an_unreadable_index_publishes_no_last_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_current("100", b"a", t(0));
        let r = runner(fake.clone(), dir.path(), 6, 70);
        index(dir.path()).drop_meta_for_test();
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(c.states.iter().all(|(k, _)| !k.ends_with("/last_rotation")));
        assert_eq!(calls(&fake, "stop_recording"), 0);
    }
}
