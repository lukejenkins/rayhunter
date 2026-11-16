//! The running program's logic, kept free of sockets so it can be tested: options,
//! Supervisor MQTT credentials and the single-flight cycle runner.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::device::Device;
use crate::sandbox::Decoder;
use crate::followup::{self, Kind};
use crate::privacy;
use crate::store::Store;
use crate::{checks, decoder, health, mqtt, pruner, puller, rotation};

/// One unit for now.
pub const DEVICE_ID: &str = "unit1";

/// At most this many finding events leave per cycle; the rest wait in the outbox.
pub const MAX_EVENTS_PER_CYCLE: usize = 10;

/// Whether a finished cycle may publish now. While the broker is down rumqttc never drains
/// its request queue, so publishing would block and stack tasks; and two publish stages
/// at once would send the same unmarked events twice. Skipping loses nothing: states are
/// republished next cycle and events stay in the outbox.
pub fn may_publish(connected: bool, already_publishing: bool) -> bool {
    connected && !already_publishing
}

/// Whether finding events may go out: states need only the broker, but an event sent while
/// HA is restarting reaches no automation and is marked sent all the same.
pub fn may_send_events(connected: bool, ha_online: bool) -> bool {
    connected && ha_online
}

/// Live events held while they may not be sent, at most this many.
pub const LIVE_HELD_MAX: usize = 32;
/// Transmission-log events waiting for Cribl; past this the oldest go (the database keeps
/// them all for 7 days).
pub const RADIO_EVENTS_MAX: usize = 500;

/// The live view's events (alerts' phone notices, admin notices) waiting for MQTT and HA.
/// Live events have no outbox row, so without this one raised before the broker is up
/// (the first tick runs at start-up) is lost while its radio text still goes.
#[derive(Debug, Default)]
pub struct HeldEvents(Vec<(String, String)>);

impl HeldEvents {
    /// Holds `events` behind any already held; returns how many were dropped at the cap
    /// (the newest go: an alert's opening notice outranks what follows it).
    pub fn hold(&mut self, events: Vec<(String, String)>) -> usize {
        let room = LIVE_HELD_MAX.saturating_sub(self.0.len());
        let dropped = events.len().saturating_sub(room);
        self.0.extend(events.into_iter().take(room));
        dropped
    }

    /// This tick's events: all held ones and `new`, in order, if they may be sent now;
    /// otherwise nothing, and they are held. Also returns how many the cap dropped.
    pub fn take(&mut self, new: Vec<(String, String)>, may_send: bool) -> (Vec<(String, String)>, usize) {
        let dropped = self.hold(new);
        if may_send { (std::mem::take(&mut self.0), dropped) } else { (Vec::new(), dropped) }
    }
}

/// What the MQTT event loop saw that bears on whether HA is listening.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HaSignal {
    /// (Re)connected to the broker.
    ConnAck,
    /// `homeassistant/status` = `online` (HA's birth message).
    StatusOnline,
    /// `homeassistant/status` = `offline` (HA's last will).
    StatusOffline,
}

/// The HA-online flag after `signal`. A (re)connect resets it to true: HA's birth message
/// is not retained, so one sent while we were reconnecting (HA and the broker restarting
/// together) would otherwise leave every event held until it expired.
pub fn ha_online_after(current: bool, signal: HaSignal) -> bool {
    let _ = current;
    signal != HaSignal::StatusOffline
}

/// Health checks that alert at most once per `HEALTH_COOLDOWN_MIN` each: a decoder that
/// fails on every capture (3 decodes per 15-minute cycle) would otherwise page the phone
/// up to about 12 times an hour, forever.
/// The 24 h sensors count findings, so they still see every one.
pub const COOLDOWN_CHECKS: [&str; 2] = [checks::DECODER_FAILURE, checks::ARCHIVE_CORRUPT];
pub const HEALTH_COOLDOWN_MIN: i64 = 60;

/// Strong outbox rows ingested into the alerts per cycle at most (no radio cost; the
/// rest wait for the next cycle).
const CLOSED_ALERTS_PER_CYCLE: usize = 50;

/// The unit's storage use (percent) at which a `low_disk` notice goes out.
pub const LOW_DISK_PCT: u32 = 90;

/// One cycle's outbox rows, sorted for the publisher.
#[derive(Debug, Default, PartialEq)]
pub struct Batch {
    /// (outbox id, topic, payload).
    pub events: Vec<(i64, String, String)>,
    /// Health alerts inside the cooldown: retired as 'merged', never sent.
    pub merged: Vec<i64>,
    /// (outbox id, check id): HA declares no such event type; retired, never retried.
    pub unsendable: Vec<(i64, String)>,
}

/// Sort pending rows into events, cooled-down health alerts and rows HA cannot take.
/// `last_sent(check)`: when that check last actually went out.
pub fn sort_outbox(
    pending: Vec<crate::store::Pending>,
    last_sent: impl Fn(&str) -> Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Batch {
    let mut b = Batch::default();
    let mut in_batch: Vec<String> = Vec::new();
    for p in pending {
        if COOLDOWN_CHECKS.contains(&p.check.as_str()) {
            let cooling = in_batch.contains(&p.check)
                || last_sent(&p.check)
                    .is_some_and(|t| now - t < Duration::minutes(HEALTH_COOLDOWN_MIN));
            if cooling {
                b.merged.push(p.id);
                continue;
            }
            in_batch.push(p.check.clone());
        }
        match mqtt::finding_event(DEVICE_ID, &p) {
            Some((topic, body)) => b.events.push((p.id, topic, body)),
            None => b.unsendable.push((p.id, p.check)),
        }
    }
    b
}

/// What one cycle hands to the publisher.
pub struct Cycle {
    /// Retained: sensor states.
    pub states: Vec<(String, String)>,
    /// Not retained: (outbox id, topic, payload).
    pub events: Vec<(i64, String, String)>,
    /// For the optional Cribl output: this cycle's events (sent only if it is on).
    pub cribl: Vec<serde_json::Value>,
    /// The outbox rows in `events`, for the "sent" notification events.
    pub notes: Vec<crate::cribl::Note>,
    /// The mesh messages: (outbox rowid, or `None` for a quiet ping, text). Empty = mesh off.
    pub mesh: Vec<(Option<i64>, String)>,
    /// Stage 1 radio texts owed: (alert id, text), sent ahead of `mesh` in the same send.
    pub stage1: Vec<(i64, String)>,
    /// Not retained: admin notices (low disk, decoding off, live unconfirmed) as (topic, payload).
    pub admin: Vec<(String, String)>,
}

/// What the live view looks like right now (plan 3's owner page reads it).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LiveState {
    /// No `device_token`: the live view is never polled.
    Off,
    /// The last poll answered, with a recording in progress.
    Ok { at: DateTime<Utc> },
    /// `LIVE_FAILURES_UNKNOWN` polls in a row failed, the first at `since` (also the
    /// state from start-up until the first answer).
    Unknown { since: DateTime<Utc> },
    /// The unit answered but is not recording.
    NotRecording,
}

/// What one live tick hands to the publisher.
#[derive(Debug)]
pub struct LiveCycle {
    /// Not retained: phone pushes (live findings, admin notices) as (topic, payload).
    pub events: Vec<(String, String)>,
    /// Stage 1 radio texts owed: (alert id, text). Empty when the mesh is off.
    pub mesh: Vec<(i64, String)>,
    #[allow(dead_code)] // read by plan 3's owner page
    pub state: LiveState,
}

/// The stage 1 text of the one-shot TEST alert (`live_test_alert`).
pub const LIVE_TEST_TEXT: &str =
    "Home sentinel TEST alert. Stay calm, avoid sensitive calls, wait for an update.";
/// The TEST alert's detail starts with this; nothing the checks write does.
const LIVE_TEST_PREFIX: &str = "test ";
/// Consecutive failed polls before the live view counts as unknown.
const LIVE_FAILURES_UNKNOWN: u32 = 3;
/// Successful polls in a row with no recording before the unit is "not recording".
const LIVE_NO_RECORDING_POLLS: u32 = 2;

/// Clears a single-flight flag when a tick ends, even on a panic.
struct Release<'a>(&'a std::cell::Cell<bool>);
impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

pub const INDEX_PATH: &str = "/data/index.sqlite";
pub const ARCHIVE_DIR: &str = "/data/archive";
pub const OPTIONS_PATH: &str = "/data/options.json";
pub const CYCLE_EVERY: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const PRUNE_EVERY_HOURS: i64 = 24;

/// A secret option value. Debug never shows it.
#[derive(PartialEq, Clone)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

pub const DEFAULT_SUMMARY_MODEL: &str = "claude-opus-5-5";

#[derive(Debug, PartialEq)]
pub struct Options {
    pub device_url: String,
    pub device_token: Option<String>,
    /// Off-rhythm tolerance for identity requests, minutes.
    pub rhythm_tolerance_min: i64,
    /// How long Fixed learns before its comparisons notify, days.
    pub fixed_learning_days: i64,
    /// The optional Cribl output; `None` = off.
    pub cribl: Option<crate::cribl::Config>,
    /// Rotate the unit's capture after this many hours; 0 = rotation off.
    pub rotate_hours: i64,
    /// Also rotate once the unit's storage is this full, percent.
    pub rotate_disk_pct: u32,
    /// The optional household mesh output; `None` = off.
    pub mesh: Option<crate::mesh::Config>,
    /// How often the unit's live view is polled, seconds (30..=600).
    pub live_poll_secs: u64,
    /// Once per start: open a TEST alert and send its stage 1 over the mesh.
    pub live_test_alert: bool,
    /// The owner page's All clear unlocks after this many hours without a sign (1..=24).
    pub all_clear_hours: i64,
    /// The optional alert summary's API key; `None` = the summary is off.
    pub summary_api_key: Option<Secret>,
    pub summary_model: String,
}

pub fn parse_options(json: &str) -> anyhow::Result<Options> {
    #[derive(Deserialize)]
    struct Raw {
        device_url: String,
        #[serde(default)]
        device_token: Option<String>,
        #[serde(default)]
        rhythm_tolerance_min: Option<i64>,
        #[serde(default)]
        fixed_learning_days: Option<i64>,
        #[serde(default)]
        cribl_url: Option<String>,
        #[serde(default)]
        cribl_token: Option<String>,
        #[serde(default)]
        cribl_ca: Option<String>,
        #[serde(default)]
        rotate_hours: Option<i64>,
        #[serde(default)]
        rotate_disk_pct: Option<i64>,
        #[serde(default)]
        mesh_port: Option<String>,
        #[serde(default)]
        mesh_level: Option<String>,
        #[serde(default)]
        mesh_quiet_per_day: Option<i64>,
        #[serde(default)]
        mesh_send_test: Option<bool>,
        #[serde(default)]
        mesh_quiet_hours: Option<String>,
        #[serde(default)]
        live_poll_secs: Option<i64>,
        #[serde(default)]
        live_test_alert: Option<bool>,
        #[serde(default)]
        all_clear_hours: Option<i64>,
        #[serde(default)]
        summary_api_key: Option<String>,
        #[serde(default)]
        summary_model: Option<String>,
    }
    let r: Raw = serde_json::from_str(json)?;
    let asked = r.rhythm_tolerance_min.unwrap_or(15);
    // The Supervisor's schema bounds it too; a hand-edited options.json is not trusted.
    let tolerance = asked.clamp(5, 60);
    if tolerance != asked {
        log::warn!("rhythm_tolerance_min {asked} is outside 5..=60; using {tolerance}");
    }
    let asked = r.fixed_learning_days.unwrap_or(checks::LEARN_DAYS);
    let days = asked.clamp(7, 60);
    if days != asked {
        log::warn!("fixed_learning_days {asked} is outside 7..=60; using {days}");
    }
    let asked = r.rotate_hours.unwrap_or(6);
    let rotate_hours = asked.clamp(0, 48);
    if rotate_hours != asked {
        log::warn!("rotate_hours {asked} is outside 0..=48; using {rotate_hours}");
    }
    let asked = r.rotate_disk_pct.unwrap_or(70);
    let rotate_disk_pct = asked.clamp(50, 95);
    if rotate_disk_pct != asked {
        log::warn!("rotate_disk_pct {asked} is outside 50..=95; using {rotate_disk_pct}");
    }
    let asked = r.live_poll_secs.unwrap_or(60);
    let live_poll_secs = asked.clamp(30, 600);
    if live_poll_secs != asked {
        log::warn!("live_poll_secs {asked} is outside 30..=600; using {live_poll_secs}");
    }
    let asked = r.all_clear_hours.unwrap_or(3);
    let all_clear_hours = asked.clamp(1, 24);
    if all_clear_hours != asked {
        log::warn!("all_clear_hours {asked} is outside 1..=24; using {all_clear_hours}");
    }
    Ok(Options {
        device_url: r.device_url.trim().to_string(),
        device_token: r
            .device_token
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty()),
        rhythm_tolerance_min: tolerance,
        fixed_learning_days: days,
        cribl: crate::cribl::config(
            r.cribl_url.as_deref(),
            r.cribl_token.as_deref(),
            r.cribl_ca.as_deref(),
        ),
        rotate_hours,
        rotate_disk_pct: rotate_disk_pct as u32,
        mesh: crate::mesh::config(
            r.mesh_port.as_deref(),
            r.mesh_level.as_deref(),
            r.mesh_quiet_per_day,
            r.mesh_send_test,
        )
        .map(|c| crate::mesh::Config {
            quiet_hours: crate::mesh::quiet_hours(r.mesh_quiet_hours.as_deref()),
            ..c
        }),
        live_poll_secs: live_poll_secs as u64,
        live_test_alert: r.live_test_alert.unwrap_or(false),
        all_clear_hours,
        summary_api_key: r
            .summary_api_key
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .map(Secret),
        summary_model: r
            .summary_model
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| DEFAULT_SUMMARY_MODEL.to_string()),
    })
}

#[derive(Debug, PartialEq)]
pub struct MqttCreds {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ssl: bool,
}

/// The Supervisor's `GET /services/mqtt` response.
pub fn parse_mqtt_service(json: &str) -> anyhow::Result<MqttCreds> {
    #[derive(Deserialize)]
    struct Data {
        host: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        ssl: bool,
    }
    #[derive(Deserialize)]
    struct Resp {
        data: Data,
    }
    let r: Resp = serde_json::from_str(json)?;
    Ok(MqttCreds {
        host: r.data.host,
        port: r.data.port,
        username: r.data.username,
        password: r.data.password,
        ssl: r.data.ssl,
    })
}

/// The same follow-up text for the same alert within this many seconds goes on air once.
const FOLLOW_UP_DUP_SECS: i64 = 60;

/// A follow-up the owner asked for.
#[derive(Debug, Clone, Deserialize)]
pub struct FollowUp {
    pub alert_id: i64,
    pub kind: Kind,
    pub text: String,
    #[serde(rename = "override", default)]
    pub override_gate: bool,
}

/// A follow-up that passed `follow_up_prepare`; only this module can build one.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepared {
    text: String,
    alert_id: i64,
    kind: Kind,
    overrode: bool,
    practice: bool,
}

impl Prepared {
    /// The exact text to put on air.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Why a follow-up was not sent.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    NoRadio,
    AlertClosed,
    Privacy(String),
    Locked { unlocks_at: Option<DateTime<Utc>> },
    Duplicate,
    RadioBusy,
    SendFailed(String),
}

impl Refusal {
    pub fn status(&self) -> u16 {
        match self {
            Refusal::SendFailed(_) => 502,
            Refusal::RadioBusy => 503,
            _ => 409,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Refusal::NoRadio => "The radio is not set up (no mesh_port).".into(),
            Refusal::AlertClosed => "Alert already closed.".into(),
            Refusal::Privacy(why) => why.clone(),
            Refusal::Locked { unlocks_at: Some(t) } => format!(
                "All clear is locked until {}. Send with override to go sooner.",
                t.with_timezone(&chrono::Local).format("%H:%M")
            ),
            Refusal::Locked { unlocks_at: None } => {
                "All clear is locked: the live view cannot see the unit right now. Send with override to go anyway."
                    .into()
            }
            Refusal::Duplicate => "That exact message just went out.".into(),
            Refusal::RadioBusy => "Radio busy, try again.".into(),
            Refusal::SendFailed(e) => format!("Not sent: {e}"),
        }
    }
}

pub struct Runner {
    dev: std::sync::Arc<dyn Device>,
    store: Store,
    archive: PathBuf,
    free: Box<dyn Fn() -> u64>,
    busy: std::cell::Cell<bool>,
    cycles: std::cell::Cell<u32>,
    last_pull: std::cell::Cell<Option<DateTime<Utc>>>,
    last_prune: std::cell::Cell<Option<DateTime<Utc>>>,
    /// Backlog / oldest backlog from the last cycle that reached the unit.
    last_backlog: std::cell::Cell<(u32, Option<DateTime<Utc>>)>,
    /// `None`: decoding is off (no guest, or it failed to load); Phase 1 is unaffected.
    decoder: Option<std::sync::Arc<dyn Decoder>>,
    profile_retries: decoder::ProfileRetries,
    settings: checks::Settings,
    rotation: rotation::Settings,
    /// `None`: the mesh output is off.
    mesh: Option<crate::mesh::Config>,
    /// When the next "all quiet" ping is due; `None` = pings off.
    next_quiet: std::cell::Cell<Option<DateTime<Utc>>>,
    /// The outcome of the last mesh attempt (`Off` until the mesh is turned on).
    mesh_status: std::cell::Cell<crate::mesh::MeshStatus>,
    /// When the mesh output was turned on (the add-on's start): the quiet line's clock
    /// before any ping record.
    mesh_since: std::cell::Cell<Option<DateTime<Utc>>>,
    /// Transmission-log events not yet handed to Cribl (`take_radio_events`).
    radio_events: std::cell::RefCell<std::collections::VecDeque<crate::mesh::RadioEvent>>,
    /// Whether the radio's port existed at the last presence check (assumed at start, so
    /// a radio missing from the start is warned about once).
    radio_present: std::cell::Cell<bool>,
    /// The live view's bearer token; `None` = the live view is off.
    live_token: Option<String>,
    /// What the live view already raised for the recording in progress.
    live_mem: std::cell::RefCell<crate::live::LiveMemory>,
    /// Single flight for live ticks (independent of the cycle's `busy`).
    live_busy: std::cell::Cell<bool>,
    /// Consecutive failed polls, and when the first of them happened.
    live_failures: std::cell::Cell<u32>,
    live_failing_since: std::cell::Cell<Option<DateTime<Utc>>>,
    live_state: std::cell::Cell<LiveState>,
    /// Consecutive successful polls with no recording (rotation's stop/start gives one).
    live_no_recording: std::cell::Cell<u32>,
    /// "token refused" / "profiles unavailable" are logged once per streak, not every poll.
    live_refused_logged: std::cell::Cell<bool>,
    live_profiles_logged: std::cell::Cell<bool>,
    /// A failed live stage 1 send was logged (until a send goes out).
    live_stage1_fail_logged: std::cell::Cell<bool>,
    /// The open alert a waiting TEST alert was last logged for.
    live_test_wait_logged: std::cell::Cell<Option<i64>>,
    /// When each admin notice last left (the health alerts' 60 min cooldown).
    live_pushed: std::cell::RefCell<std::collections::HashMap<&'static str, DateTime<Utc>>>,
    /// The unit's profile as last seen ("fixed" | "mobile"), for admin notices.
    live_profile: std::cell::Cell<&'static str>,
    /// The last answered poll's recording is in Fixed (the live view judged it). The
    /// owner page treats a live view in any other profile as unknown.
    live_fixed: std::cell::Cell<bool>,
    /// `live_test_alert`, until its TEST alert has been opened.
    live_test: std::cell::Cell<bool>,
    /// The owner page: how often the live view is polled (for "happening now").
    live_poll_secs: u64,
    /// The owner page: hours without a sign before All clear unlocks.
    all_clear_hours: i64,
    /// The optional alert summary (plan 4). The key lives only here and in `claude::call`'s
    /// header; `None` = off, and nothing ever calls the API.
    summary_key: Option<String>,
    summary_model: String,
    summary_base: String,
    /// Built on the first call, so a build failure is an answer, never a panic.
    summary_client: std::cell::RefCell<Option<reqwest::Client>>,
    /// When the last call that counts toward the gap ended (the DB row may fail to write).
    summary_last: std::cell::Cell<Option<DateTime<Utc>>>,
    /// The main runtime, where the API call runs; `None` = the current one.
    summary_rt: Option<tokio::runtime::Handle>,
    /// One summary per (alert id, number of timeline events).
    summary_cache: std::cell::RefCell<std::collections::HashMap<(i64, usize), String>>,
    /// A call is out (single flight).
    summary_busy: std::cell::Cell<bool>,
}

/// At most one new API call per this many minutes overall.
pub const SUMMARY_MIN_GAP_MIN: i64 = 5;

/// What a tap on Summary leads to.
pub enum SummaryStep {
    Cached(String),
    Call {
        body: serde_json::Value,
        key: String,
        model: String,
        /// The alert's event count when the record was built (the cache key).
        events: usize,
    },
}

// Not derived: the key must never reach a Debug print.
impl std::fmt::Debug for SummaryStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SummaryStep::Cached(_) => f.write_str("Cached"),
            SummaryStep::Call { .. } => f.write_str("Call(<redacted>)"),
        }
    }
}

impl Runner {
    pub fn new(
        dev: std::sync::Arc<dyn Device>,
        store: Store,
        archive: &Path,
        free: Box<dyn Fn() -> u64>,
    ) -> Self {
        Runner {
            dev,
            store,
            archive: archive.to_path_buf(),
            free,
            busy: Default::default(),
            cycles: Default::default(),
            last_pull: Default::default(),
            last_prune: Default::default(),
            last_backlog: Default::default(),
            decoder: None,
            profile_retries: Default::default(),
            settings: Default::default(),
            rotation: Default::default(),
            mesh: None,
            next_quiet: Default::default(),
            mesh_status: std::cell::Cell::new(crate::mesh::MeshStatus::Off),
            radio_events: Default::default(),
            mesh_since: Default::default(),
            radio_present: std::cell::Cell::new(true),
            live_token: None,
            live_mem: Default::default(),
            live_busy: Default::default(),
            live_failures: Default::default(),
            live_failing_since: Default::default(),
            live_state: std::cell::Cell::new(LiveState::Off),
            live_no_recording: Default::default(),
            live_refused_logged: Default::default(),
            live_profiles_logged: Default::default(),
            live_stage1_fail_logged: Default::default(),
            live_test_wait_logged: Default::default(),
            live_pushed: Default::default(),
            live_profile: std::cell::Cell::new("fixed"),
            live_fixed: Default::default(),
            live_test: Default::default(),
            live_poll_secs: 60,
            all_clear_hours: 3,
            summary_key: None,
            summary_model: DEFAULT_SUMMARY_MODEL.to_string(),
            summary_base: crate::claude::DEFAULT_BASE_URL.to_string(),
            summary_client: Default::default(),
            summary_last: Default::default(),
            summary_rt: None,
            summary_cache: Default::default(),
            summary_busy: Default::default(),
        }
    }

    /// Turn the optional alert summary on (`key` set). Off otherwise.
    pub fn with_summary(mut self, key: Option<String>, model: String) -> Self {
        self.summary_key = key;
        self.summary_model = model;
        self
    }

    /// Where the API lives (tests point it at a local fake).
    #[cfg(test)]
    pub fn with_summary_base_url(mut self, url: &str) -> Self {
        self.summary_base = url.to_string();
        self
    }

    /// Run the API call on this runtime rather than the cycle thread's.
    pub fn with_summary_runtime(mut self, h: tokio::runtime::Handle) -> Self {
        self.summary_rt = Some(h);
        self
    }

    /// What the spawned call needs. Only reached after `summary_prepare` gave a `Call`.
    pub fn summary_transport(
        &self,
    ) -> Result<(reqwest::Client, String, tokio::runtime::Handle), crate::claude::ApiError> {
        let cached = self.summary_client.borrow().clone();
        let client = match cached {
            Some(c) => c,
            None => {
                let c = crate::claude::client()?;
                *self.summary_client.borrow_mut() = Some(c.clone());
                c
            }
        };
        Ok((
            client,
            self.summary_base.clone(),
            self.summary_rt.clone().unwrap_or_else(tokio::runtime::Handle::current),
        ))
    }

    /// A tap on Summary for `alert_id`: the cached text, a refusal in the page's words, or
    /// the call to make. The target rule is the page's and the follow-ups': the id must be
    /// `followup::target`'s.
    pub fn summary_prepare(&self, alert_id: i64, now: DateTime<Utc>) -> Result<SummaryStep, String> {
        const GONE: &str = "That alert is no longer active.";
        const READ: &str = "Could not read the alert.";
        let Some(key) = &self.summary_key else {
            return Err("Summary is off.".into());
        };
        let open = self.store.open_alert(DEVICE_ID).map_err(|_| READ.to_string())?;
        let last = self.store.last_alert(DEVICE_ID).map_err(|_| READ.to_string())?;
        let (alert, practice) = match followup::target(open, last, now) {
            Some((a, p)) if a.id == alert_id => (a, p),
            _ => return Err(GONE.into()),
        };
        let events = self.store.alert_events(alert.id).map_err(|_| READ.to_string())?;
        if let Some(text) = self.summary_cache.borrow().get(&(alert.id, events.len())) {
            return Ok(SummaryStep::Cached(text.clone()));
        }
        if self.summary_busy.get() {
            return Err("A summary is already on its way.".into());
        }
        let db_last = self.store.summary_last_call(DEVICE_ID).map_err(|_| READ.to_string())?;
        if let Some(last) = db_last.max(self.summary_last.get()) {
            let next = last + Duration::minutes(SUMMARY_MIN_GAP_MIN);
            if now < next {
                return Err(format!(
                    "One summary per {SUMMARY_MIN_GAP_MIN} minutes; try again at {}",
                    next.with_timezone(&chrono::Local).format("%H:%M")
                ));
            }
        }
        let learning = self
            .store
            .baseline(checks::Profile::Fixed.as_str(), now)
            .map_err(|_| READ.to_string())?
            .fixed_since
            .is_none_or(|s| now - s < Duration::days(self.settings.learn_days));
        let word = crate::summary::profile_word(self.live_profile.get(), learning);
        let base = self
            .store
            .summary_baseline(DEVICE_ID, now, word)
            .map_err(|_| READ.to_string())?;
        let sent = self
            .store
            .radio_log_for_alert(DEVICE_ID, alert.id, 50)
            .map_err(|_| READ.to_string())?;
        let rec = crate::summary::record(&alert, &events, &sent, self.page_live(), &base, practice, now);
        self.summary_busy.set(true);
        Ok(SummaryStep::Call {
            body: crate::claude::request_body(&self.summary_model, &rec),
            key: key.clone(),
            model: self.summary_model.clone(),
            events: events.len(),
        })
    }

    /// The call is over: log its usage, cache a good answer, and return what the page shows.
    pub fn summary_done(
        &self,
        alert_id: i64,
        events: usize,
        result: &Result<crate::claude::Reply, crate::claude::ApiError>,
        now: DateTime<Utc>,
    ) -> Result<String, String> {
        use crate::claude::{ApiError, Reply};
        self.summary_busy.set(false);
        let (outcome, tin, tout, shown): (&str, u64, u64, Result<String, String>) = match result {
            Ok(Reply::Text { text, cut_short, input_tokens, output_tokens }) => {
                let shown = if *cut_short { format!("{text} (cut short)") } else { text.clone() };
                ("ok", *input_tokens, *output_tokens, Ok(shown))
            }
            Ok(Reply::Refused { input_tokens, output_tokens }) => (
                "refused",
                *input_tokens,
                *output_tokens,
                Ok("The model declined to summarise this alert.".to_string()),
            ),
            Err(e) => {
                let word = match e {
                    ApiError::KeyRefused => "key_refused",
                    ApiError::NoCredit => "no_credit",
                    ApiError::Busy => "busy",
                    ApiError::NoInternet => "no_internet",
                    ApiError::KeyUnusable => "key_unusable",
                    ApiError::Bad(_) => "bad",
                };
                (word, 0, 0, Err(e.message().to_string()))
            }
        };
        if outcome != "no_internet" {
            self.summary_last.set(Some(now));
        }
        if let Err(e) = self.store.summary_log_add(
            DEVICE_ID, now, alert_id, &self.summary_model, tin, tout, outcome,
        ) {
            log::error!("summary: log: {e:#}");
        }
        match &shown {
            Ok(text) => {
                self.summary_cache.borrow_mut().insert((alert_id, events), text.clone());
            }
            Err(_) => log::warn!("summary: {outcome}"),
        }
        shown
    }

    /// The owner page's settings (`live_poll_secs`, `all_clear_hours`).
    pub fn with_owner_page(mut self, live_poll_secs: u64, all_clear_hours: i64) -> Self {
        self.live_poll_secs = live_poll_secs;
        self.all_clear_hours = all_clear_hours;
        self
    }

    /// Turn the live view on (`token` set) and arm the one-shot TEST alert. Until the
    /// first answer the live view is `Unknown` since `now`.
    pub fn with_live(mut self, token: Option<String>, test_alert: bool, now: DateTime<Utc>) -> Self {
        let on = token.is_some();
        self.live_token = token;
        self.live_state
            .set(if on { LiveState::Unknown { since: now } } else { LiveState::Off });
        self.live_test.set(on && test_alert);
        self
    }

    pub fn live_state(&self) -> LiveState {
        self.live_state.get()
    }

    /// The live view as the owner page judges it: it only checks anything in Fixed, so a
    /// live view answering in another profile (or whose profile is not known) is Unknown.
    fn page_live(&self) -> LiveState {
        match self.live_state.get() {
            LiveState::Ok { at } if !self.live_fixed.get() => LiveState::Unknown { since: at },
            s => s,
        }
    }

    /// The JSON the owner page renders. Reads only; the target alert is `followup::target`.
    pub fn page(&self, now: DateTime<Utc>) -> serde_json::Value {
        let open = self.store.open_alert(DEVICE_ID).unwrap_or_else(|e| {
            log::error!("page: open_alert: {e:#}");
            None
        });
        let last = self.store.last_alert(DEVICE_ID).unwrap_or_else(|e| {
            log::error!("page: last_alert: {e:#}");
            None
        });
        let events = match followup::target(open.clone(), last.clone(), now) {
            Some((a, _)) => self.store.alert_events(a.id).unwrap_or_else(|e| {
                log::error!("page: alert_events: {e:#}");
                Vec::new()
            }),
            None => Vec::new(),
        };
        let radio = self.store.radio_log(DEVICE_ID, 50).unwrap_or_else(|e| {
            log::error!("page: radio_log: {e:#}");
            Vec::new()
        });
        let admin = self
            .store
            .admin_items(DEVICE_ID, now - Duration::hours(24))
            .unwrap_or_else(|e| {
                log::error!("page: admin_items: {e:#}");
                Vec::new()
            });
        followup::page_state(&followup::PageInput {
            open,
            events,
            last,
            radio,
            admin,
            live: self.page_live(),
            now,
            poll_secs: self.live_poll_secs,
            all_clear_hours: self.all_clear_hours,
            mesh_on: self.mesh.is_some(),
            quiet: self.quiet_info(now),
            summary: {
                let (tokens_in, tokens_out) = self.store.summary_totals(DEVICE_ID).unwrap_or_else(|e| {
                    log::error!("page: summary_totals: {e:#}");
                    (0, 0)
                });
                followup::SummaryInfo { enabled: self.summary_key.is_some(), tokens_in, tokens_out }
            },
        })
    }

    /// Every check that must pass before a follow-up goes on air. The token carries the
    /// trimmed text the privacy check validated and every decision made here.
    pub fn follow_up_prepare(&self, req: &FollowUp, now: DateTime<Utc>) -> Result<Prepared, Refusal> {
        if self.mesh.is_none() {
            return Err(Refusal::NoRadio);
        }
        let open = self.store.open_alert(DEVICE_ID).map_err(|e| Refusal::SendFailed(format!("{e:#}")))?;
        let last = self.store.last_alert(DEVICE_ID).map_err(|e| Refusal::SendFailed(format!("{e:#}")))?;
        let (alert, practice) = match followup::target(open, last, now) {
            Some((a, p)) if a.id == req.alert_id => (a, p),
            _ => return Err(Refusal::AlertClosed),
        };
        // A practice follow-up goes on air marked TEST; every check below sees that text.
        let text = if practice { followup::practice_text(&req.text) } else { req.text.trim().to_string() };
        let text = text.as_str();
        privacy::check(text).map_err(|b| Refusal::Privacy(privacy::reason(&b)))?;
        let mut overrode = false;
        if req.kind == Kind::AllClear {
            let gate = followup::all_clear_gate(&alert, self.page_live(), now, self.all_clear_hours);
            if !gate.unlocked {
                if !req.override_gate {
                    return Err(Refusal::Locked { unlocks_at: gate.unlocks_at });
                }
                overrode = true;
            }
        }
        // Rows are newest first and the window is 60 s; 20 rows cover far more than the
        // owner can send in that time (one radio, one message at a time).
        let recent = self
            .store
            .radio_log(DEVICE_ID, 20)
            .map_err(|e| Refusal::SendFailed(format!("{e:#}")))?;
        let dup = recent.iter().any(|e| {
            e.alert_id == Some(alert.id)
                && e.text == text
                && e.at <= now
                && now - e.at < Duration::seconds(FOLLOW_UP_DUP_SECS)
        });
        if dup {
            return Err(Refusal::Duplicate);
        }
        Ok(Prepared {
            text: text.to_string(),
            alert_id: alert.id,
            kind: req.kind,
            overrode,
            practice,
        })
    }

    /// The ping line's inputs; `None` when pings are off or the log cannot be read.
    fn quiet_info(&self, now: DateTime<Utc>) -> Option<followup::QuietInfo> {
        let cfg = self.mesh.as_ref().filter(|c| c.quiet_per_day > 0)?;
        let status = self
            .store
            .quiet_status(crate::mesh::local_midnight(now))
            .map_err(|e| log::error!("page: quiet_status: {e:#}"))
            .ok()?;
        Some(followup::QuietInfo { per_day: cfg.quiet_per_day, started: self.mesh_since.get()?, status })
    }

    /// The radio refused a prepared follow-up: only the transmission log hears of it.
    pub fn follow_up_failed(&self, p: &Prepared, e: anyhow::Error, now: DateTime<Utc>) {
        self.record_follow_up(p, &Err(e), now);
    }

    fn record_follow_up(&self, p: &Prepared, sent: &anyhow::Result<usize>, now: DateTime<Utc>) {
        let mut ev = crate::mesh::send_events(&[(p.kind.as_str(), Some(p.alert_id), p.text.as_str())], sent, now);
        if p.overrode
            && let Some(e) = ev.first_mut()
            && e.reason.is_none()
        {
            e.reason = Some("override");
        }
        self.record_radio(ev);
    }

    /// The follow-up went on air: log it (and an override, if prepare decided on one), then
    /// close the alert for false alarm / all clear if it is still open. Nothing else
    /// changes: no tower is learned, no check muted. A practice TEST stays as it is.
    /// Uses only the token; the gate is not looked at again.
    pub fn follow_up_sent(&self, p: &Prepared, now: DateTime<Utc>) {
        self.record_follow_up(p, &Ok(1), now);
        if p.overrode {
            log::warn!(
                "owner page: all clear for alert {} sent by override before the gate unlocked",
                p.alert_id
            );
            if let Err(e) = self.store.log_radio(
                DEVICE_ID,
                "all_clear_override",
                "sent before the all-clear gate unlocked",
                Some(p.alert_id),
                now,
            ) {
                log::error!("follow-up: log_radio: {e:#}");
            }
        }
        if let Err(e) = self.store.log_radio(DEVICE_ID, p.kind.as_str(), &p.text, Some(p.alert_id), now) {
            log::error!("follow-up: log_radio: {e:#}");
        }
        if p.practice {
            return;
        }
        if let Some(by) = p.kind.closes() {
            match self.store.open_alert(DEVICE_ID) {
                Ok(Some(a)) if a.id == p.alert_id => {
                    if let Err(e) = self.store.close_alert(a.id, by, now) {
                        log::error!("follow-up: close_alert: {e:#}");
                    }
                }
                Ok(_) => {}
                Err(e) => log::error!("follow-up: open_alert (alert {} not closed): {e:#}", p.alert_id),
            }
        }
    }

    /// Turn the mesh output on; the first quiet ping is scheduled from `now`.
    pub fn with_mesh(
        mut self,
        cfg: crate::mesh::Config,
        now: DateTime<Utc>,
        rand: &mut dyn FnMut() -> u32,
    ) -> Self {
        self.next_quiet
            .set(crate::mesh::next_quiet(now, cfg.quiet_per_day, rand()));
        self.mesh = Some(cfg);
        self.mesh_since.set(Some(now));
        self.mesh_status.set(crate::mesh::MeshStatus::Ok);
        self
    }

    /// What to send over the mesh this cycle: unsent household alerts (oldest first, at most
    /// `MAX_PER_CYCLE`), else a quiet ping if one is due and the detector is fully watching
    /// (fresh pull, decoder loaded, pulls not `paused` for disk).
    pub fn mesh_outbox(
        &self,
        now: DateTime<Utc>,
        paused: bool,
        rand: &mut dyn FnMut() -> u32,
    ) -> Vec<(Option<i64>, String)> {
        use crate::mesh;
        let Some(cfg) = &self.mesh else {
            return Vec::new();
        };
        // Strong rows are alerts (`closed_alerts`); their stage 1 is owed by the alert (see
        // `stage1_outbox`). Only `mesh_level: all` notice rows go out as their own text.
        let strong = mesh::checks_for(mesh::Level::Strong);
        let notices: Vec<&str> = mesh::checks_for(cfg.level)
            .iter()
            .copied()
            .filter(|c| !strong.contains(c))
            .collect();
        let rows = self.store.mesh_pending(DEVICE_ID, &notices, now, mesh::MAX_PER_CYCLE);
        let mut out: Vec<(Option<i64>, String)> = match rows {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|(id, check)| mesh::text_for(&check).map(|t| (Some(id), t.to_string())))
                .collect(),
            Err(e) => {
                // Unreadable is not empty: no ping either, or it would be a false all-clear.
                log::error!("mesh_pending: {e:#}");
                if self.next_quiet.get().is_some_and(|due| due <= now) {
                    self.record_radio(vec![mesh::skipped_ping(mesh::SKIP_STORE_ERROR, now)]);
                    self.next_quiet
                        .set(mesh::next_quiet(now, cfg.quiet_per_day, rand()));
                }
                return Vec::new();
            }
        };
        if self.next_quiet.get().is_some_and(|due| due <= now) {
            // A detector that is not fully watching stays silent: silence is the signal.
            // Watching = a recent pull, a decoder to judge it, and pulls not paused for disk.
            let fresh = self
                .last_pull
                .get()
                .is_some_and(|t| now - t <= Duration::minutes(mesh::QUIET_MAX_STALE_MIN));
            let watching = fresh && self.decoder.is_some() && !paused;
            // Quiet hours: skip, don't save it up (a ping always at the end of the night
            // would be a fixed beat). Alerts above are never held.
            let night = mesh::in_quiet_hours(mesh::local_hour(now), cfg.quiet_hours);
            // No "all quiet" while any alert is open, its stage 1 sent or not (an unreadable
            // store counts as open): fresh evidence may be joining it.
            let open = self.store.open_alert(DEVICE_ID).map_or(true, |a| a.is_some());
            // Every due ping leaves a record; the most telling reason wins.
            let skip = if !watching {
                Some(mesh::SKIP_NOT_WATCHING)
            } else if open {
                Some(mesh::SKIP_ALERT_OPEN)
            } else if !out.is_empty() {
                Some(mesh::SKIP_BUSY)
            } else if night {
                Some(mesh::SKIP_QUIET_HOURS)
            } else {
                None
            };
            match skip {
                None => out.push((None, mesh::QUIET_TEXT.to_string())),
                Some(why) => self.record_radio(vec![mesh::skipped_ping(why, now)]),
            }
            self.next_quiet
                .set(mesh::next_quiet(now, cfg.quiet_per_day, rand()));
        }
        out
    }

    /// Every strong, Fixed, switch-free outbox row not yet ingested goes through the
    /// alerts, whether or not a radio is configured.
    fn closed_alerts(&self, now: DateTime<Utc>) {
        let strong = crate::mesh::checks_for(crate::mesh::Level::Strong);
        match self.store.alert_pending(DEVICE_ID, strong, CLOSED_ALERTS_PER_CYCLE) {
            Ok(rows) => {
                for (id, check) in rows {
                    if let Some(c) = strong.iter().find(|c| **c == check) {
                        self.closed_ingest(id, c, now);
                    }
                }
            }
            Err(e) => log::error!("alert_pending: {e:#}"),
        }
    }

    /// Pass a strong outbox row's findings through the alerts (`Source::Closed`, the
    /// capture as the recording), then mark the row (`alert_at`) whatever the outcome, so
    /// it is ingested exactly once. An opened alert owes its stage 1 (`stage1_outbox`); a row
    /// an alert already covers goes out on no radio. A store error leaves the row for
    /// the next cycle.
    fn closed_ingest(&self, row: i64, check: &'static str, now: DateTime<Utc>) {
        use crate::store::{Ingested, Source};
        let (name, details) = match self.store.row_findings(row) {
            Ok(Some(x)) => x,
            Ok(None) => return,
            Err(e) => {
                log::error!("mesh: row_findings: {e:#}");
                return;
            }
        };
        // No stored finding: still one, so the row is never silently lost.
        let details = if details.is_empty() { vec![String::new()] } else { details };
        // A TEST alert still waiting for the radio must not take in a real finding.
        if let Some(id) = self.open_test_alert() {
            log::warn!("mesh: unsent TEST alert {id} closed for a real finding");
            if let Err(e) = self.store.close_alert(id, crate::store::CloseBy::Test, now) {
                log::error!("mesh: close_alert: {e:#}");
            }
        }
        let (mut opened, mut joined) = (None, None);
        for detail in details {
            let f = crate::live::LiveFinding {
                check,
                towers: crate::live::towers_in(&detail),
                subject: crate::live::subject_of(check, &detail),
                detail,
            };
            match self.store.ingest(DEVICE_ID, &f, Source::Closed, Some(&name), now) {
                Ok(Ingested::Opened(id)) => _ = opened.get_or_insert(id),
                Ok(Ingested::Joined(id)) => _ = joined.get_or_insert(id),
                Ok(Ingested::Duplicate) => {}
                Err(e) => {
                    log::error!("mesh: ingest: {e:#}");
                    return;
                }
            }
        }
        match (opened, joined) {
            (Some(id), _) => log::warn!("mesh: alert {id} opened by the closed pass ({check})"),
            (None, Some(id)) => log::debug!("mesh: already covered by alert {id}"),
            (None, None) => match self.store.open_alert(DEVICE_ID) {
                Ok(Some(a)) => log::debug!("mesh: already covered by alert {}", a.id),
                _ => log::debug!("mesh: already covered by an earlier alert"),
            },
        }
        if let Err(e) = self.store.mark_alerted(row, now) {
            log::error!("mark_alerted: {e:#}");
        }
    }

    /// After captures are judged: a live finding raised during one of them that the
    /// closed pass did not repeat (same check sharing a tower, or the same check when it
    /// named none) gives one `live_unconfirmed` notice for that capture.
    fn live_unconfirmed(&self, judged: &[decoder::Judged], now: DateTime<Utc>) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for j in judged {
            let live = match self.store.live_events_in(DEVICE_ID, &j.name) {
                Ok(v) if v.is_empty() => continue,
                Ok(v) => v,
                Err(e) => {
                    log::error!("live_events_in: {e:#}");
                    continue;
                }
            };
            let closed = match self.store.findings_named(DEVICE_ID, &j.name) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("findings_named: {e:#}");
                    continue;
                }
            };
            let missing = live.iter().filter(|e| !confirmed_by(e, &closed)).count();
            if missing > 0 {
                log::warn!("live: {missing} live finding(s) not confirmed by the closed pass");
                out.extend(self.admin_push("live_unconfirmed", now));
            }
        }
        out
    }

    /// Capture rotation (off unless set; see `rotation`).
    pub fn with_rotation(mut self, s: rotation::Settings) -> Self {
        self.rotation = s;
        self
    }

    pub fn with_rhythm_tolerance(mut self, minutes: i64) -> Self {
        self.settings.tolerance_min = minutes;
        self
    }

    pub fn with_learning_days(mut self, days: i64) -> Self {
        self.settings.learn_days = days;
        self
    }

    pub fn with_decoder(mut self, d: Option<std::sync::Arc<dyn Decoder>>) -> Self {
        self.decoder = d;
        self
    }

    /// Number of cycles that have started.
    pub fn cycles(&self) -> u32 {
        self.cycles.get()
    }

    /// Mark outbox rows as sent. A store error is logged and swallowed: the rows come
    /// round again next cycle (at-least-once from the add-on's side).
    pub fn mark_sent(&self, ids: &[i64], now: DateTime<Utc>) {
        if let Err(e) = self.store.mark_sent(ids, now) {
            log::error!("mark_sent: {e}");
        }
    }

    /// The mesh status to publish this cycle, from whether the radio's port exists now
    /// (checked every cycle, so a missing radio shows without a send being due). Logs once
    /// when the radio goes missing and once when it comes back.
    pub fn check_radio(&self, present: bool) -> crate::mesh::MeshStatus {
        use crate::mesh::RadioChange;
        let (status, change) =
            crate::mesh::radio_check(self.radio_present.replace(present), present, self.mesh_status.get());
        match change {
            Some(RadioChange::Gone) => log::warn!("mesh: radio port is missing; mesh alerts wait for it"),
            Some(RadioChange::Back) => log::info!("mesh: radio port is back"),
            None => {}
        }
        status
    }

    /// After a mesh send: see `after_mesh_send`.
    pub fn mesh_sent(
        &self,
        sent: &anyhow::Result<usize>,
        batch: &[(Option<i64>, String)],
        now: DateTime<Utc>,
    ) {
        self.mesh_status.set(after_mesh_send(&self.store, sent, batch, now));
        let items: Vec<_> = batch.iter().map(|(id, t)| (batch_kind(*id, t), *id, t.as_str())).collect();
        self.record_radio(crate::mesh::send_events(&items, sent, now));
    }

    /// The cycle found another stage holding the radio: a quiet ping in its batch is lost
    /// (rows stay unsent and come round again).
    pub fn mesh_stage_skipped(&self, batch: &[(Option<i64>, String)], now: DateTime<Utc>) {
        if batch.iter().any(|(id, t)| id.is_none() && t == crate::mesh::QUIET_TEXT) {
            self.record_radio(vec![crate::mesh::skipped_ping(crate::mesh::SKIP_RADIO_BUSY, now)]);
        }
    }

    /// Book transmission-log events: the database for the page and 7 days of history, and
    /// the buffer Cribl drains. A store error is logged; Cribl still gets them.
    pub fn record_radio(&self, evs: Vec<crate::mesh::RadioEvent>) {
        if evs.is_empty() {
            return;
        }
        if let Err(e) = self.store.log_radio_events(&evs) {
            log::error!("log_radio_events: {e:#}");
        }
        let mut q = self.radio_events.borrow_mut();
        q.extend(evs);
        while q.len() > RADIO_EVENTS_MAX {
            q.pop_front();
        }
    }

    /// The transmission-log events Cribl has not had yet, oldest first.
    pub fn take_radio_events(&self) -> Vec<crate::mesh::RadioEvent> {
        self.radio_events.borrow_mut().drain(..).collect()
    }

    /// After the cycle's one radio send of `stage1` then `batch` (in that order): the
    /// first `n` texts went out; each part is booked as its own path books it.
    pub fn cycle_mesh_sent(
        &self,
        sent: &anyhow::Result<usize>,
        stage1: &[(i64, String)],
        batch: &[(Option<i64>, String)],
        now: DateTime<Utc>,
    ) {
        match sent {
            Ok(n) => {
                let k = (*n).min(stage1.len());
                self.live_mesh_sent(&Ok(k), stage1, now);
                self.mesh_sent(&Ok(n - k), batch, now);
            }
            Err(_) => {
                self.mesh_status.set(crate::mesh::status_of(sent));
                let items: Vec<_> = stage1
                    .iter()
                    .map(|(id, t)| (stage1_kind(t), Some(*id), t.as_str()))
                    .chain(batch.iter().map(|(id, t)| (batch_kind(*id, t), *id, t.as_str())))
                    .collect();
                self.record_radio(crate::mesh::send_events(&items, sent, now));
            }
        }
    }

    /// A mesh batch as it should go out now: built at `built`, re-checked just before the
    /// send (another mesh stage may have sent its rows; a quiet ping goes stale; see
    /// `mesh::sendable`). A store error sends nothing this time; the rows come round again.
    pub fn mesh_sendable(
        &self,
        batch: Vec<(Option<i64>, String)>,
        built: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Vec<(Option<i64>, String)> {
        let ids: Vec<i64> = batch.iter().filter_map(|b| b.0).collect();
        let is_ping = |b: &(Option<i64>, String)| b.0.is_none() && b.1 == crate::mesh::QUIET_TEXT;
        let had_ping = batch.iter().any(is_ping);
        match self.store.mesh_still_pending(&ids) {
            Ok(live) => {
                let out = crate::mesh::sendable(batch, &live, built, now);
                if had_ping && !out.iter().any(is_ping) {
                    self.record_radio(vec![crate::mesh::skipped_ping(crate::mesh::SKIP_STALE, now)]);
                }
                out
            }
            Err(e) => {
                log::error!("mesh_still_pending: {e:#}");
                Vec::new()
            }
        }
    }

    /// The ids whose rows are still unsent, checked just before publishing: another publish
    /// stage may have sent this batch meanwhile. A store error sends nothing this time.
    pub fn still_pending(&self, ids: &[i64]) -> Vec<i64> {
        self.store.still_pending(ids).unwrap_or_else(|e| {
            log::error!("still_pending: {e}");
            Vec::new()
        })
    }

    /// One timer tick. `None`: a cycle was already running, so this tick is dropped.
    /// `Some(cycle)`: the retained states and the one-shot events to publish after it.
    pub async fn on_tick(&self, now: DateTime<Utc>) -> Option<Cycle> {
        // Single flight: the puller wipes `archive/.tmp` when it starts, so cycles must
        // never overlap. A tick that finds one running is dropped, never queued.
        if self.busy.replace(true) {
            log::warn!("previous cycle still running; tick dropped");
            return None;
        }
        let _release = Release(&self.busy);
        self.cycles.set(self.cycles.get() + 1);
        let started = std::time::Instant::now();

        // Before the pull, so a capture it finishes is archived and judged this cycle.
        let free = (self.free)();
        // Pulls paused: a disk-triggered stop would free nothing on the unit.
        let paused = free < puller::MIN_FREE_BYTES;
        let rotated = rotation::run(&*self.dev, &self.store, &self.rotation, now, paused).await;
        let mut outcome =
            puller::cycle(&*self.dev, &self.store, DEVICE_ID, &self.archive, now, free).await;
        if outcome.reached_device {
            self.last_pull.set(Some(now));
            self.last_backlog
                .set((outcome.backlog, outcome.oldest_backlog));
        } else {
            // The unit was not reached: its backlog is unknown, not 0.
            (outcome.backlog, outcome.oldest_backlog) = self.last_backlog.get();
        }
        let due = self
            .last_prune
            .get()
            .is_none_or(|t| now - t >= Duration::hours(PRUNE_EVERY_HOURS));
        if due {
            let n = pruner::prune(&self.store, &self.archive, DEVICE_ID, now);
            log::info!("pruned {n} captures");
            self.last_prune.set(Some(now));
        }
        // Last, and bounded: a decode problem never stops the pulls above.
        let d = decoder::judge_pending(
            &self.store,
            self.decoder.as_ref(),
            &*self.dev,
            DEVICE_ID,
            &self.archive,
            decoder::MAX_PER_CYCLE,
            &self.profile_retries,
            now,
            &self.settings,
        )
        .await;
        if d != decoder::DecodeOutcome::default() {
            log::info!("judged: {}", d.summary());
        }
        // For the optional Cribl output; built from what this cycle has in hand.
        let mut cribl = Vec::new();
        if let Some(rot) = &rotated {
            cribl.push(crate::cribl::rotation_event(rot, now));
        }
        for j in &d.judged {
            cribl.push(crate::cribl::decode_event(j, now));
            cribl.extend(crate::cribl::finding_events(j, now));
        }
        // Radio or not: the alerts are the record of every strong closed finding.
        self.closed_alerts(now);
        let mut admin = self.live_unconfirmed(&d.judged, now);
        let h = health::health(&self.store, DEVICE_ID, &self.archive, free, now);
        // Unknown storage use: no notice this cycle.
        if self.dev.disk_used_percent().await.is_ok_and(|u| u >= LOW_DISK_PCT) {
            admin.extend(self.admin_push("low_disk", now));
        }
        if h.paused {
            admin.extend(self.admin_push("decoding_off", now));
        }
        let mismatches = self.store.mismatch_total(DEVICE_ID).unwrap_or_else(|e| {
            log::error!("mismatch_total: {e}");
            0
        });
        let mut states = mqtt::states(DEVICE_ID, &outcome, &h, mismatches, self.last_pull.get());
        // Not part of the report: a failed report must not hide a missing decoder.
        states.push(mqtt::decoder_state(DEVICE_ID, self.decoder.is_none()));
        // Unreadable: left out this cycle rather than published as "never".
        match rotation::last_rotation(&self.store) {
            Ok(t) => states.push(mqtt::rotation_state(DEVICE_ID, t)),
            Err(e) => log::error!("last rotation: {e:#}"),
        }
        // Only the sentinel's own sending; unreadable: left out this cycle.
        if let Some(cfg) = &self.mesh {
            // Never opens the radio: only whether its by-id path exists.
            let status = self.check_radio(Path::new(&cfg.port).exists());
            match self.store.mesh_stats(now) {
                Ok((n, last)) => {
                    states.extend(mqtt::mesh_states(DEVICE_ID, status, n, last));
                }
                Err(e) => log::error!("mesh_stats: {e:#}"),
            }
        }
        let report = self.store.report(DEVICE_ID, now, self.settings.learn_days);
        match &report {
            Ok(r) => states.extend(mqtt::report_states(DEVICE_ID, r)),
            Err(e) => log::error!("report: {e}"),
        }
        cribl.push(crate::cribl::health_event(
            &h,
            report.as_ref().ok(),
            self.decoder.is_none(),
            outcome.backlog,
            mismatches,
            now,
        ));
        let mut events = Vec::new();
        let mut notes = Vec::new();
        match self
            .store
            .pending_notifications(DEVICE_ID, now, MAX_EVENTS_PER_CYCLE)
        {
            Ok((pending, expired)) => {
                if expired > 0 {
                    log::warn!("{expired} notification(s) older than 24 h dropped unsent");
                    // Read-only: which rows that was, for the Cribl output.
                    match self.store.retired_at(DEVICE_ID, "expired", now) {
                        Ok(rows) => cribl.extend(rows.into_iter().map(|(capture, check, count)| {
                            let n = crate::cribl::Note { id: 0, capture, check, count };
                            crate::cribl::notification_event(&n, "expired", now)
                        })),
                        Err(e) => log::error!("retired_at: {e}"),
                    }
                }
                let all: Vec<crate::cribl::Note> = pending
                    .iter()
                    .map(|p| crate::cribl::Note {
                        id: p.id,
                        capture: p.name.clone(),
                        check: p.check.clone(),
                        count: p.count,
                    })
                    .collect();
                let last_sent = |check: &str| {
                    // Unknown: send rather than risk swallowing a health alert.
                    self.store.last_sent(DEVICE_ID, check).unwrap_or_else(|e| {
                        log::error!("last_sent: {e}");
                        None
                    })
                };
                let b = sort_outbox(pending, last_sent, now);
                // Never blocks the queue: a row we cannot express is retired, not retried.
                for (_, check) in &b.unsendable {
                    log::warn!("outbox row for check {check} has no event type; retired unsent");
                }
                let unsendable: Vec<i64> = b.unsendable.iter().map(|u| u.0).collect();
                self.mark_sent(&unsendable, now);
                if !b.merged.is_empty() {
                    let n = b.merged.len();
                    log::info!("{n} health alert(s) inside the 1 h cooldown; not sent");
                    if let Err(e) = self.store.mark(&b.merged, "merged", now) {
                        log::error!("mark merged: {e}");
                    }
                }
                use crate::cribl::notifications;
                cribl.extend(notifications(&all, &b.merged, "merged", now));
                cribl.extend(notifications(&all, &unsendable, "unsendable", now));
                let ids: Vec<i64> = b.events.iter().map(|e| e.0).collect();
                notes = all.into_iter().filter(|n| ids.contains(&n.id)).collect();
                events = b.events;
            }
            Err(e) => log::error!("pending_notifications: {e}"),
        }
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // First: the cycle's own summary leads its events.
        cribl.insert(0, crate::cribl::cycle_event(&outcome, free, ms, now));
        let mesh = self.mesh_outbox(now, paused, &mut crate::mesh::random_u32);
        let stage1 = self.stage1_outbox(now);
        Some(Cycle { states, events, cribl, notes, mesh, stage1, admin })
    }

    /// One live tick: poll the unit's live view, judge it as Fixed, group the strong
    /// findings into alerts and say which stage 1 texts are owed. `None`: the previous
    /// live tick is still running. Never learns: nothing here writes a baseline.
    pub async fn on_live_tick(&self, now: DateTime<Utc>) -> Option<LiveCycle> {
        let Some(token) = &self.live_token else {
            return Some(LiveCycle { events: Vec::new(), mesh: Vec::new(), state: LiveState::Off });
        };
        if self.live_busy.replace(true) {
            log::debug!("live: previous tick still running; tick dropped");
            return None;
        }
        let _release = Release(&self.live_busy);
        let mut events = Vec::new();
        match self.dev.live(token).await {
            Err(e) => {
                if e == crate::device::DeviceError::Refused {
                    if !self.live_refused_logged.replace(true) {
                        log::warn!("live: token refused");
                    }
                } else {
                    log::debug!("live: poll failed ({})", live_err(&e));
                }
                let n = self.live_failures.get() + 1;
                self.live_failures.set(n);
                if n == 1 {
                    self.live_failing_since.set(Some(now));
                }
                if n >= LIVE_FAILURES_UNKNOWN {
                    let since = self.live_failing_since.get().unwrap_or(now);
                    self.set_live_state(LiveState::Unknown { since });
                    events.extend(self.admin_push("live_unknown", now));
                }
            }
            Ok(snap) => {
                self.live_failures.set(0);
                self.live_failing_since.set(None);
                self.live_refused_logged.set(false);
                match snap.recording.clone() {
                    // One poll can land in rotation's 2 s stop/start: only a second in a
                    // row (failed polls in between say nothing either way) is "not recording".
                    None => {
                        let n = self.live_no_recording.get().saturating_add(1);
                        self.live_no_recording.set(n);
                        if n >= LIVE_NO_RECORDING_POLLS {
                            self.set_live_state(LiveState::NotRecording);
                            events.extend(self.admin_push("not_recording", now));
                        }
                    }
                    Some(rec) => {
                        self.live_no_recording.set(0);
                        self.set_live_state(LiveState::Ok { at: now });
                        // No tower, cell or token in this line.
                        log::debug!("live: ok");
                        let fixed = self.live_profile_of(&rec).await == Some(checks::Profile::Fixed);
                        self.live_fixed.set(fixed);
                        if fixed {
                            events.extend(self.live_judge(&snap, &rec, now));
                        }
                    }
                }
            }
        }
        events.extend(self.live_test_alert(now));
        let mesh = self.stage1_outbox(now);
        Some(LiveCycle { events, mesh, state: self.live_state.get() })
    }

    fn set_live_state(&self, s: LiveState) {
        let was = self.live_state.replace(s);
        let kind = |s: LiveState| std::mem::discriminant(&s);
        if kind(was) != kind(s) {
            match s {
                LiveState::Ok { .. } => log::info!("live: ok"),
                LiveState::Unknown { .. } => log::warn!("live: unknown ({LIVE_FAILURES_UNKNOWN} polls failed)"),
                LiveState::NotRecording => log::warn!("live: the unit is not recording"),
                LiveState::Off => {}
            }
        }
    }

    /// An admin notice, at most once per `HEALTH_COOLDOWN_MIN` per kind (as health alerts).
    fn admin_push(&self, kind: &'static str, now: DateTime<Utc>) -> Option<(String, String)> {
        let mut pushed = self.live_pushed.borrow_mut();
        let cooling = pushed
            .get(kind)
            .is_some_and(|t| now - *t < Duration::minutes(HEALTH_COOLDOWN_MIN));
        if cooling {
            return None;
        }
        let ev = mqtt::admin_event(DEVICE_ID, kind, self.live_profile.get(), now)?;
        pushed.insert(kind, now);
        if let Err(e) = self.store.log_admin(DEVICE_ID, kind, now) {
            log::error!("log_admin: {e:#}");
        }
        Some(ev)
    }

    /// The profile the recording in progress is in, from the unit's capture profiles
    /// (as the closed pass reads them): `mixed` or a missing name is Mobile. `None`:
    /// the unit did not say, so nothing is judged this tick.
    async fn live_profile_of(&self, rec: &str) -> Option<checks::Profile> {
        match self.dev.capture_profiles().await {
            Ok(m) => {
                self.live_profiles_logged.set(false);
                let fixed = m.get(rec).map(String::as_str) == Some("fixed");
                self.live_profile.set(if fixed { "fixed" } else { "mobile" });
                Some(if fixed { checks::Profile::Fixed } else { checks::Profile::Mobile })
            }
            Err(e) => {
                if !self.live_profiles_logged.replace(true) {
                    log::warn!("live: capture profiles unavailable ({}); nothing judged", live_err(&e));
                }
                None
            }
        }
    }

    /// Judge `snap` against the Fixed baseline, exactly as the closed pass loads it, and
    /// ingest the new strong findings; returns the phone pushes for alerts it opened.
    fn live_judge(
        &self,
        snap: &crate::live::Snapshot,
        rec: &str,
        now: DateTime<Utc>,
    ) -> Vec<(String, String)> {
        use crate::store::{Ingested, Source};
        let baseline = match self.store.baseline(checks::Profile::Fixed.as_str(), now) {
            Ok(b) => b,
            Err(e) => {
                log::error!("live: baseline: {e:#}");
                return Vec::new();
            }
        };
        let learning = baseline
            .fixed_since
            .is_none_or(|s| now - s < Duration::days(self.settings.learn_days));
        let (found, act) = crate::live::evaluate(
            &mut self.live_mem.borrow_mut(),
            snap,
            &baseline,
            &self.settings,
            learning,
            now,
        );
        if !found.is_empty() {
            // A TEST alert still waiting for the radio must not take in a real finding.
            if let Some(id) = self.open_test_alert() {
                log::warn!("live: unsent TEST alert {id} closed for a real finding");
                if let Err(e) = self.store.close_alert(id, crate::store::CloseBy::Test, now) {
                    log::error!("live: close_alert: {e:#}");
                }
            }
        }
        let mut events = Vec::new();
        for f in &found {
            let r = self.store.ingest(DEVICE_ID, f, Source::Live, Some(rec), now);
            match &r {
                Ok(Ingested::Opened(id)) => {
                    log::warn!("live: alert {id} opened ({})", f.check);
                    events.extend(live_finding_event(f.check, rec, now));
                }
                Ok(Ingested::Joined(id)) => log::info!("live: {} joined alert {id}", f.check),
                Ok(Ingested::Duplicate) => {}
                // Not marked raised: the next poll offers it again.
                Err(e) => log::error!("live: ingest: {e:#}"),
            }
            if r.is_ok() {
                crate::live::mark_raised(&mut self.live_mem.borrow_mut(), f);
            }
        }
        if let Err(e) = self.store.touch(DEVICE_ID, &act, now) {
            log::error!("live: touch: {e:#}");
        }
        events
    }

    /// The open alert, if it is the TEST alert.
    fn open_test_alert(&self) -> Option<i64> {
        let a = self.store.open_alert(DEVICE_ID).ok().flatten()?;
        let ev = self.store.alert_events(a.id).ok()?;
        ev.first()
            .is_some_and(|e| e.detail.starts_with(LIVE_TEST_PREFIX))
            .then_some(a.id)
    }

    /// `live_test_alert`: once per start, when the mesh is on and no alert is open (so it
    /// never joins a real one), open a TEST alert; its stage 1 goes out with this tick.
    /// Returns its phone push (`test_alert`, no cooldown: it is one-shot).
    fn live_test_alert(&self, now: DateTime<Utc>) -> Option<(String, String)> {
        if !self.live_test.get() {
            return None;
        }
        if self.mesh.is_none() {
            log::warn!("live_test_alert needs the mesh (mesh_port); no TEST alert");
            self.live_test.set(false);
            return None;
        }
        match self.store.open_alert(DEVICE_ID) {
            Ok(None) => self.live_test_wait_logged.set(None),
            Ok(Some(a)) => {
                // Once per open alert, not every tick.
                if self.live_test_wait_logged.replace(Some(a.id)) != Some(a.id) {
                    log::info!("live: TEST alert waits: alert {} is open", a.id);
                }
                return None;
            }
            Err(e) => {
                log::error!("live: open_alert: {e:#}");
                return None;
            }
        }
        let detail = format!(
            "{LIVE_TEST_PREFIX}{}",
            now.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        );
        let f = crate::live::LiveFinding {
            check: checks::ANALYSER_HIGH,
            subject: crate::live::subject_of(checks::ANALYSER_HIGH, &detail),
            towers: Vec::new(),
            detail,
        };
        match self.store.ingest(DEVICE_ID, &f, crate::store::Source::Live, None, now) {
            Ok(crate::store::Ingested::Opened(id)) => {
                log::info!("live: TEST alert {id} opened");
                self.live_test.set(false);
                mqtt::admin_event(DEVICE_ID, "test_alert", self.live_profile.get(), now)
            }
            Ok(other) => {
                log::warn!("live: TEST alert not opened ({other:?})");
                None
            }
            Err(e) => {
                log::error!("live: ingest TEST alert: {e:#}");
                None
            }
        }
    }

    /// Give up alerts past the stage 1 window (each logged once), then expire stale
    /// alerts, then the stage 1 texts still owed (nothing if the mesh is off).
    fn stage1_outbox(&self, now: DateTime<Utc>) -> Vec<(i64, String)> {
        match self.store.stage1_give_up(now) {
            Ok(ids) => {
                for id in ids {
                    if self.mesh.is_some() {
                        log::warn!("live: stage 1 for alert {id} never went out; given up");
                    }
                    // A TEST alert that never went out is just closed.
                    if self.store.alert_events(id).is_ok_and(|ev| {
                        ev.first().is_some_and(|e| e.detail.starts_with(LIVE_TEST_PREFIX))
                    }) && let Err(e) = self.store.close_alert(id, crate::store::CloseBy::Test, now)
                    {
                        log::error!("live: close_alert: {e:#}");
                    }
                }
            }
            Err(e) => log::error!("live: stage1_give_up: {e:#}"),
        }
        // After the give-up: an alert past both windows is given up (and logged) first.
        match self.store.expire_alerts(DEVICE_ID, now) {
            Ok(ids) if !ids.is_empty() => log::info!("live: {} alert(s) expired", ids.len()),
            Ok(_) => {}
            Err(e) => log::error!("live: expire_alerts: {e:#}"),
        }
        let mut out = Vec::new();
        if self.mesh.is_some() {
            match self.store.stage1_pending(DEVICE_ID, now) {
                Ok(rows) => {
                    for (id, check, detail) in rows {
                        let text = if detail.starts_with(LIVE_TEST_PREFIX) {
                            Some(LIVE_TEST_TEXT.to_string())
                        } else {
                            crate::mesh::stage1_text(&check)
                        };
                        match text {
                            Some(t) => out.push((id, t)),
                            None => log::warn!("live: alert {id} ({check}) has no stage 1 text"),
                        }
                    }
                }
                Err(e) => log::error!("live: stage1_pending: {e:#}"),
            }
        }
        out
    }

    /// After stage 1 texts went out: mark them, log each in the radio log, and close a
    /// TEST alert as `test` (so it never takes in a real finding). A store error is
    /// logged; the alert is then offered again (a repeat beats a silent loss).
    pub fn stage1_sent(&self, sent: &[(i64, String)], now: DateTime<Utc>) {
        let ids: Vec<i64> = sent.iter().map(|s| s.0).collect();
        if let Err(e) = self.store.stage1_sent(&ids, now) {
            log::error!("live: stage1_sent: {e:#}");
            return;
        }
        for (id, text) in sent {
            let test = text == LIVE_TEST_TEXT;
            let kind = if test { "test" } else { "stage1" };
            if let Err(e) = self.store.log_radio(DEVICE_ID, kind, text, Some(*id), now) {
                log::error!("live: log_radio: {e:#}");
            }
            if test && let Err(e) = self.store.close_alert(*id, crate::store::CloseBy::Test, now) {
                log::error!("live: close_alert: {e:#}");
            }
        }
    }

    /// Log a live stage 1 send's outcome. A failure (a radio unplugged for hours fails
    /// every poll) warns once per streak; a send that goes out ends the streak.
    pub fn live_stage1_result(&self, sent: &anyhow::Result<usize>, total: usize) {
        match sent {
            Ok(n) => {
                self.live_stage1_fail_logged.set(false);
                log::info!("live: stage 1 sent {n} of {total} message(s)");
            }
            Err(e) => {
                if !self.live_stage1_fail_logged.replace(true) {
                    log::warn!(
                        "live: stage 1 not sent ({e:#}); retried every tick, logged again once one goes out"
                    );
                }
            }
        }
    }

    /// After a live mesh send: the mesh status, and on `Ok(n)` the first `n` texts are
    /// marked sent and counted in the mesh sensors. On `Err` nothing is marked.
    pub fn live_mesh_sent(
        &self,
        sent: &anyhow::Result<usize>,
        batch: &[(i64, String)],
        now: DateTime<Utc>,
    ) {
        self.mesh_status.set(crate::mesh::status_of(sent));
        let items: Vec<_> = batch.iter().map(|(id, t)| (stage1_kind(t), Some(*id), t.as_str())).collect();
        self.record_radio(crate::mesh::send_events(&items, sent, now));
        let Ok(n) = sent else { return };
        let went = &batch[..(*n).min(batch.len())];
        let kinds: Vec<&str> = went
            .iter()
            .map(|(_, t)| if t == LIVE_TEST_TEXT { "test" } else { "alert" })
            .collect();
        if let Err(e) = self.store.log_mesh(&kinds, now) {
            log::error!("log_mesh: {e:#}");
        }
        self.stage1_sent(went, now);
    }

    /// A live mesh batch as it should go out now: only alerts still owed stage 1 (an
    /// earlier live send may have finished meanwhile). A store error sends nothing.
    pub fn stage1_still_pending(&self, batch: Vec<(i64, String)>, now: DateTime<Utc>) -> Vec<(i64, String)> {
        match self.store.stage1_pending(DEVICE_ID, now) {
            Ok(rows) => batch
                .into_iter()
                .filter(|(id, _)| rows.iter().any(|r| r.0 == *id))
                .collect(),
            Err(e) => {
                log::error!("live: stage1_pending: {e:#}");
                Vec::new()
            }
        }
    }
}

/// Whether the closed findings `(check, detail)` repeat live event `e`: the same check
/// sharing a tower, or, when `e` named no tower, the same check.
fn confirmed_by(e: &crate::store::AlertEvent, closed: &[(String, String)]) -> bool {
    closed.iter().any(|(check, detail)| {
        *check == e.check_id
            && (e.towers.is_empty()
                || crate::live::towers_in(detail).iter().any(|t| e.towers.contains(t)))
    })
}

/// The transmission-log kind of a stage 1 text.
fn stage1_kind(text: &str) -> &'static str {
    if text == LIVE_TEST_TEXT { "test" } else { "stage1" }
}

/// The transmission-log kind of a cycle batch entry: an outbox row is a notice.
fn batch_kind(id: Option<i64>, text: &str) -> &'static str {
    match (id, text) {
        (Some(_), _) => "notice",
        (None, crate::mesh::QUIET_TEXT) => "quiet",
        (None, crate::mesh::TEST_TEXT) => "test",
        (None, _) => "other",
    }
}

/// A device error for the live log lines: `Bad` carries parser text that can echo the
/// unit's (hostile) body, so only its kind is logged.
fn live_err(e: &crate::device::DeviceError) -> &'static str {
    use crate::device::DeviceError as E;
    match e {
        E::Unreachable => "unreachable",
        E::NotFound => "not found",
        E::Busy => "busy",
        E::Refused => "refused",
        E::Bad(_) => "bad answer",
    }
}

/// The phone push for a live alert: `finding_event`'s payload for this check, with the
/// recording as its capture, plus `"live": true`. The detail never leaves.
fn live_finding_event(check: &str, rec: &str, now: DateTime<Utc>) -> Option<(String, String)> {
    let p = crate::store::Pending {
        id: 0,
        name: rec.to_string(),
        check: check.to_string(),
        count: 1,
        profile: checks::Profile::Fixed.as_str().to_string(),
        spans_switch: false,
        found_at: now,
        towers_known: None,
    };
    let (topic, body) = mqtt::finding_event(DEVICE_ID, &p)?;
    let mut v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v["live"] = serde_json::Value::Bool(true);
    Some((topic, v.to_string()))
}

/// Bookkeeping after a mesh send; returns the status it leaves behind. On `Ok(n)` the rows
/// among the first `n` messages are marked sent and the `n` messages are logged by kind
/// (outbox row = alert, quiet ping = quiet, start-up message = test); on `Err` nothing is,
/// even if some texts went out first: a repeat beats a silent loss. A store error is logged
/// and swallowed (the rows come round again).
pub fn after_mesh_send(
    store: &Store,
    sent: &anyhow::Result<usize>,
    batch: &[(Option<i64>, String)],
    now: DateTime<Utc>,
) -> crate::mesh::MeshStatus {
    let status = crate::mesh::status_of(sent);
    let Ok(n) = sent else { return status };
    let kinds: Vec<&str> = batch
        .iter()
        .take(*n)
        .filter_map(|(id, text)| match (id, text.as_str()) {
            (Some(_), _) => Some("alert"),
            (None, crate::mesh::QUIET_TEXT) => Some("quiet"),
            (None, crate::mesh::TEST_TEXT) => Some("test"),
            (None, _) => None,
        })
        .collect();
    if let Err(e) = store.log_mesh(&kinds, now) {
        log::error!("log_mesh: {e:#}");
    }
    let ids: Vec<i64> = batch.iter().take(*n).filter_map(|(id, _)| *id).collect();
    if !ids.is_empty()
        && let Err(e) = store.mark_mesh(&ids, now)
    {
        log::error!("mark_mesh: {e:#}");
    }
    status
}

/// Install rustls's ring provider (once). Without a process-wide default, building a
/// ClientConfig panics when more than one provider is compiled in.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn tls_config_from(roots: rustls::RootCertStore) -> anyhow::Result<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// TLS config trusting the platform CA store. No CA store is an error, not a panic.
pub fn tls_config() -> anyhow::Result<rustls::ClientConfig> {
    let loaded = rustls_native_certs::load_native_certs();
    for e in &loaded.errors {
        log::warn!("CA store: {e}");
    }
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(loaded.certs);
    anyhow::ensure!(added > 0, "no CA certificates available for TLS");
    tls_config_from(roots)
}

/// Free bytes on the filesystem holding `path`.
pub fn free_bytes(path: &str) -> u64 {
    match nix::sys::statvfs::statvfs(path) {
        Ok(s) => s.blocks_available() as u64 * s.fragment_size() as u64,
        Err(e) => {
            log::error!("statvfs {path}: {e}");
            // Unknown: report plenty rather than pausing pulls on a failed probe? No:
            // refusing to fill a disk we cannot measure is the safe side.
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Fake;
    use std::sync::Arc;

    #[test]
    fn options_missing_token_is_none() {
        let o = parse_options(r#"{"device_url":"http://x:1"}"#).unwrap();
        assert_eq!(o.device_token, None);
        assert_eq!(o.device_url, "http://x:1");
    }

    #[test]
    fn options_token_is_trimmed_and_blank_is_none() {
        let o = parse_options(r#"{"device_url":"u","device_token":"  abc\n"}"#).unwrap();
        assert_eq!(o.device_token.as_deref(), Some("abc"));
        let o = parse_options(r#"{"device_url":"u","device_token":"   "}"#).unwrap();
        assert_eq!(o.device_token, None);
        let o = parse_options(r#"{"device_url":"u","device_token":null}"#).unwrap();
        assert_eq!(o.device_token, None);
    }

    #[test]
    fn options_rhythm_tolerance_defaults_to_15_and_is_clamped_to_5_60() {
        let tol = |j: &str| parse_options(j).unwrap().rhythm_tolerance_min;
        assert_eq!(tol(r#"{"device_url":"u"}"#), 15);
        assert_eq!(tol(r#"{"device_url":"u","rhythm_tolerance_min":2}"#), 5);
        assert_eq!(tol(r#"{"device_url":"u","rhythm_tolerance_min":99}"#), 60);
        assert_eq!(tol(r#"{"device_url":"u","rhythm_tolerance_min":20}"#), 20);
        assert_eq!(tol(r#"{"device_url":"u","rhythm_tolerance_min":null}"#), 15);
    }

    #[test]
    fn options_fixed_learning_days_defaults_to_14_and_is_clamped_to_7_60() {
        let days = |j: &str| parse_options(j).unwrap().fixed_learning_days;
        assert_eq!(days(r#"{"device_url":"u"}"#), 14);
        assert_eq!(days(r#"{"device_url":"u","fixed_learning_days":3}"#), 7);
        assert_eq!(days(r#"{"device_url":"u","fixed_learning_days":90}"#), 60);
        assert_eq!(days(r#"{"device_url":"u","fixed_learning_days":7}"#), 7);
        assert_eq!(days(r#"{"device_url":"u","fixed_learning_days":null}"#), 14);
    }

    #[test]
    fn options_rotation_defaults_to_6_h_and_70_pct_and_is_clamped() {
        let rot = |j: &str| {
            let o = parse_options(j).unwrap();
            (o.rotate_hours, o.rotate_disk_pct)
        };
        assert_eq!(rot(r#"{"device_url":"u"}"#), (6, 70));
        assert_eq!(rot(r#"{"device_url":"u","rotate_hours":null,"rotate_disk_pct":null}"#), (6, 70));
        assert_eq!(rot(r#"{"device_url":"u","rotate_hours":0}"#), (0, 70));
        assert_eq!(rot(r#"{"device_url":"u","rotate_hours":-1,"rotate_disk_pct":10}"#), (0, 50));
        assert_eq!(rot(r#"{"device_url":"u","rotate_hours":99,"rotate_disk_pct":100}"#), (48, 95));
        assert_eq!(rot(r#"{"device_url":"u","rotate_hours":12,"rotate_disk_pct":80}"#), (12, 80));
    }

    #[test]
    fn options_garbage_is_an_error() {
        assert!(parse_options("not json").is_err());
    }

    #[test]
    fn supervisor_response_parses() {
        let j = r#"{"result":"ok","data":{"addon":"core_mosquitto","host":"core-mosquitto",
            "port":1883,"ssl":false,"protocol":"3.1.1","username":"u","password":"p"}}"#;
        let c = parse_mqtt_service(j).unwrap();
        assert_eq!(
            c,
            MqttCreds {
                host: "core-mosquitto".into(),
                port: 1883,
                username: Some("u".into()),
                password: Some("p".into()),
                ssl: false
            }
        );
    }

    #[test]
    fn supervisor_error_response_is_an_error() {
        assert!(parse_mqtt_service(r#"{"result":"error","message":"nope"}"#).is_err());
        assert!(parse_mqtt_service(r#"{"result":"ok","data":{}}"#).is_err());
    }

    /// Emulates Python's PurePath.match, which the Supervisor uses for `backup_exclude`:
    /// a relative pattern is matched right-anchored against the path's last N components.
    fn purepath_match(path: &str, pattern: &str) -> bool {
        let pat: Vec<&str> = pattern.split('/').collect();
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if pattern.starts_with('/') || pat.len() > comps.len() {
            return false; // absolute patterns must match the whole path; ours never does
        }
        let tail = &comps[comps.len() - pat.len()..];
        pat.iter().zip(tail).all(|(p, c)| {
            glob::Pattern::new(p).unwrap().matches_with(
                c,
                glob::MatchOptions {
                    require_literal_separator: true,
                    ..Default::default()
                },
            )
        })
    }

    #[test]
    fn config_yaml_source_check() {
        let y: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../addon/config.yaml")).unwrap();
        let excl: Vec<&str> = y["backup_exclude"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(excl, ["archive/*", "archive/*/*", "cwasm-cache/*"]);
        let host = "/data/addons/data/local_rayhunter_archive";
        for f in [
            "archive/x.qmdl.gz",
            "archive/x.ndjson",
            "archive/mismatch/y.qmdl.gz",
            "archive/.tmp/z",
            "cwasm-cache/x.cwasm",
            "cwasm-cache/x.cwasm.sha256",
        ] {
            let path = format!("{host}/{f}");
            assert!(
                excl.iter().any(|p| purepath_match(&path, p)),
                "{path} must be excluded"
            );
        }
        let idx = format!("{host}/index.sqlite");
        assert!(
            !excl.iter().any(|p| purepath_match(&idx, p)),
            "index must be backed up"
        );
        for k in ["ports", "privileged", "host_network"] {
            assert!(y.get(k).is_none(), "{k} must not be set");
        }
        // The owner page (web.rs) is reached only through Ingress.
        assert_eq!(y["ingress"].as_bool(), Some(true));
        assert_eq!(y["slug"].as_str(), Some("rayhunter_archive"));
        assert_eq!(y["arch"][0].as_str(), Some("aarch64"));
        assert_eq!(y["services"][0].as_str(), Some("mqtt:need"));
        assert_eq!(y["options"]["rhythm_tolerance_min"].as_i64(), Some(15));
        assert_eq!(
            y["schema"]["rhythm_tolerance_min"].as_str(),
            Some("int(5,60)?")
        );
        assert_eq!(y["options"]["fixed_learning_days"].as_i64(), Some(14));
        assert_eq!(
            y["schema"]["fixed_learning_days"].as_str(),
            Some("int(7,60)?")
        );
        // Capture rotation: on by default, shown in the UI with its defaults.
        assert_eq!(y["options"]["rotate_hours"].as_i64(), Some(6));
        assert_eq!(y["schema"]["rotate_hours"].as_str(), Some("int(0,48)?"));
        assert_eq!(y["options"]["rotate_disk_pct"].as_i64(), Some(70));
        assert_eq!(y["schema"]["rotate_disk_pct"].as_str(), Some("int(50,95)?"));
        // The Cribl output: optional, off by default, the token a password field.
        assert_eq!(y["schema"]["cribl_url"].as_str(), Some("url?"));
        assert_eq!(y["schema"]["cribl_token"].as_str(), Some("password?"));
        assert_eq!(y["schema"]["cribl_ca"].as_str(), Some("str?"));
        for k in ["cribl_url", "cribl_token", "cribl_ca"] {
            let v = &y["options"][k];
            assert!(v.is_null() || v.as_str() == Some(""), "{k} must default to blank");
        }
        // The live view: polled every minute by default; the test alert off.
        assert_eq!(y["options"]["live_poll_secs"].as_i64(), Some(60));
        assert_eq!(y["schema"]["live_poll_secs"].as_str(), Some("int(30,600)?"));
        assert_eq!(y["options"]["live_test_alert"].as_bool(), Some(false));
        assert_eq!(y["schema"]["live_test_alert"].as_str(), Some("bool?"));
        // The owner page's All clear gate: three quiet hours by default.
        assert_eq!(y["options"]["all_clear_hours"].as_i64(), Some(3));
        assert_eq!(y["schema"]["all_clear_hours"].as_str(), Some("int(1,24)?"));
        // The add-on's version is the one its events report.
        assert_eq!(y["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.8.4");
    }

    #[test]
    fn config_yaml_has_mesh_options() {
        let y: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../addon/config.yaml")).unwrap();
        assert_eq!(y["uart"].as_bool(), Some(true));
        assert!(y.get("devices").is_none(), "a listed device would block start-up");
        assert_eq!(y["schema"]["mesh_port"].as_str(), Some("str?"));
        assert_eq!(y["schema"]["mesh_level"].as_str(), Some("list(strong|all)?"));
        assert_eq!(y["schema"]["mesh_quiet_per_day"].as_str(), Some("int(0,6)?"));
        assert_eq!(y["schema"]["mesh_send_test"].as_str(), Some("bool?"));
        assert_eq!(
            y["schema"]["mesh_quiet_hours"].as_str(),
            Some("match(^([01]?[0-9]|2[0-3])-([01]?[0-9]|2[0-3])$)?")
        );
        assert!(y["options"]["mesh_port"].is_null() || y["options"]["mesh_port"].as_str() == Some(""));
        assert_eq!(y["version"].as_str(), Some("0.8.4"));
        assert_eq!(y["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn parse_options_reads_mesh() {
        let o = parse_options(
            r#"{"device_url":"u","mesh_port":"/dev/serial/by-id/usb-x","mesh_level":"all","mesh_quiet_per_day":2,"mesh_send_test":true,"mesh_quiet_hours":"22-7"}"#,
        )
        .unwrap();
        assert_eq!(
            o.mesh,
            Some(crate::mesh::Config {
                port: "/dev/serial/by-id/usb-x".into(),
                level: crate::mesh::Level::All,
                quiet_per_day: 2,
                send_test: true,
                quiet_hours: Some((22, 7)),
            })
        );
    }

    #[test]
    fn parse_options_mesh_off_by_default() {
        assert_eq!(parse_options(r#"{"device_url":"u"}"#).unwrap().mesh, None);
        let o = parse_options(r#"{"device_url":"u","mesh_level":"all","mesh_send_test":true}"#)
            .unwrap();
        assert_eq!(o.mesh, None, "no port, no mesh");
    }

    fn mesh_cfg(level: crate::mesh::Level, per_day: u32) -> crate::mesh::Config {
        crate::mesh::Config {
            port: "/dev/serial/by-id/usb-x".into(),
            level,
            quiet_per_day: per_day,
            send_test: false,
            quiet_hours: None,
        }
    }

    fn insert_row(dir: &Path, check: &str, found: DateTime<Utc>) -> i64 {
        let c = rusqlite::Connection::open(dir.join("i.sqlite")).unwrap();
        let f = found.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        c.execute(
            "INSERT INTO notifications
             (device, name, start, check_id, count, profile, spans_switch, found_at)
             VALUES (?1, 'n', ?2, ?3, 1, 'fixed', 0, ?2)",
            rusqlite::params![DEVICE_ID, f, check],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    #[test]
    fn mesh_outbox_sends_strong_rows_and_skips_quiet_ping() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 3), t(0), &mut || 0);
        let id = insert_row(dir.path(), checks::ANALYSER_HIGH, t(-60));
        insert_row(dir.path(), checks::NEW_TOWER, t(-50)); // not strong
        r.last_pull.set(Some(t(0)));
        r.next_quiet.set(Some(t(-1)));
        r.closed_alerts(t(0));
        let got = r.mesh_outbox(t(0), false, &mut || 0);
        // The strong row went through alerts: no row text and no quiet ping beside it.
        assert!(got.is_empty(), "{got:?}");
        let s1 = r.stage1_outbox(t(0));
        assert_eq!(s1.len(), 1, "{s1:?}");
        assert_eq!(
            s1[0].1,
            "Home alert (strong): suspicious cell activity near home".to_string() + crate::mesh::STAGE1_TAIL
        );
        assert!(alerted(&r, id));
    }

    /// A runner whose detector is fully up: a decoder, so a quiet ping may go out.
    fn mesh_runner(fake: Arc<Fake>, dir: &Path, per_day: u32) -> Runner {
        runner(fake, dir)
            .with_decoder(Some(Arc::new(Boom(Default::default()))))
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, per_day), t(0), &mut || 0)
    }

    fn rows(r: &Runner) -> Vec<(String, String, Option<String>)> {
        r.store.radio_event_rows()
    }

    fn row(kind: &str, outcome: &str, reason: Option<&str>) -> (String, String, Option<String>) {
        (kind.to_string(), outcome.to_string(), reason.map(str::to_string))
    }

    #[test]
    fn a_due_ping_skipped_for_not_watching_is_recorded_and_a_not_due_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 3), t(0), &mut || 0);
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || 0).is_empty());
        assert_eq!(rows(&r), [row("quiet", "skipped", Some("not_watching"))]);
        // Rescheduled into the future: the next cycle is not due and books nothing.
        assert!(r.mesh_outbox(t(1), false, &mut || 0).is_empty());
        assert_eq!(rows(&r).len(), 1);
        // Taken for Cribl in order, once.
        let taken = r.take_radio_events();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].reason, Some("not_watching"));
        assert!(r.take_radio_events().is_empty());
    }

    #[test]
    fn a_due_ping_in_quiet_hours_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let h = crate::mesh::local_hour(t(0));
        let mut cfg = mesh_cfg(crate::mesh::Level::Strong, 3);
        cfg.quiet_hours = Some((h, (h + 1) % 24));
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_decoder(Some(Arc::new(Boom(Default::default()))))
            .with_mesh(cfg, t(0), &mut || 0);
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || 0).is_empty());
        assert_eq!(rows(&r), [row("quiet", "skipped", Some("quiet_hours"))]);
    }

    #[test]
    fn a_due_ping_while_an_alert_is_open_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        insert_row(dir.path(), checks::ANALYSER_HIGH, t(-60));
        r.last_pull.set(Some(t(-600)));
        r.closed_alerts(t(0));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || 0).is_empty());
        assert_eq!(rows(&r), [row("quiet", "skipped", Some("alert_open"))]);
    }

    #[test]
    fn a_due_ping_beside_notices_is_recorded_as_busy() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_decoder(Some(Arc::new(Boom(Default::default()))))
            .with_mesh(mesh_cfg(crate::mesh::Level::All, 3), t(0), &mut || 0);
        insert_row(dir.path(), checks::NEW_TOWER, t(-60));
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert_eq!(r.mesh_outbox(t(0), false, &mut || 0).len(), 1, "the notice");
        assert_eq!(rows(&r), [row("quiet", "skipped", Some("busy"))]);
    }

    #[test]
    fn a_due_ping_on_an_unreadable_outbox_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        rusqlite::Connection::open(dir.path().join("i.sqlite"))
            .unwrap()
            .execute("ALTER TABLE notifications RENAME TO notifications_gone", [])
            .unwrap();
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || 0).is_empty());
        assert_eq!(rows(&r), [row("quiet", "skipped", Some("store_error"))]);
    }

    #[test]
    fn sends_book_their_kind_and_outcome() {
        use crate::mesh::{QUIET_TEXT, TEST_TEXT};
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        // The cycle's ping, the start-up test, a notice row.
        r.mesh_sent(&Ok(3), &[(None, QUIET_TEXT.into()), (None, TEST_TEXT.into()), (Some(9), "Home notice".into())], t(0));
        // A cycle that failed books both of its parts.
        r.cycle_mesh_sent(
            &Err(crate::mesh::link::HandshakeTimeout.into()),
            &[(5, "Home alert".into())],
            &[(None, QUIET_TEXT.into())],
            t(1),
        );
        // The live path: stage 1 and the live TEST.
        r.live_mesh_sent(&Ok(2), &[(5, "Home alert".into()), (6, LIVE_TEST_TEXT.into())], t(2));
        assert_eq!(
            rows(&r),
            [
                row("quiet", "sent", None),
                row("test", "sent", None),
                row("notice", "sent", None),
                row("stage1", "failed", Some("no_answer")),
                row("quiet", "failed", Some("no_answer")),
                row("stage1", "sent", None),
                row("test", "sent", None),
            ]
        );
        let ev = r.take_radio_events();
        assert_eq!(ev[3].alert_id, Some(5));
        assert!(!ev[0].bell && ev[1].bell, "only the ping goes without the bell");
    }

    #[test]
    fn a_ping_dropped_before_the_send_is_recorded() {
        use crate::mesh::QUIET_TEXT;
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        // Stale: built more than 5 minutes before the radio was free.
        assert!(r.mesh_sendable(vec![(None, QUIET_TEXT.into())], t(-400), t(0)).is_empty());
        // Fresh: kept, nothing booked.
        assert_eq!(r.mesh_sendable(vec![(None, QUIET_TEXT.into())], t(-10), t(0)).len(), 1);
        // Another stage held the radio.
        r.mesh_stage_skipped(&[(None, QUIET_TEXT.into())], t(1));
        r.mesh_stage_skipped(&[(Some(3), "Home notice".into())], t(2));
        assert_eq!(rows(&r), [row("quiet", "skipped", Some("stale")), row("quiet", "skipped", Some("radio_busy"))]);
    }

    #[test]
    fn the_page_shows_the_ping_line_only_when_pings_are_on() {
        use crate::mesh::QUIET_TEXT;
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        // Just after local midnight, so "today" is unambiguous.
        let now = crate::mesh::local_midnight(t(0)) + Duration::hours(30);
        r.mesh_sent(&Ok(1), &[(None, QUIET_TEXT.into())], now - Duration::hours(26)); // yesterday
        r.mesh_sent(&Ok(1), &[(None, QUIET_TEXT.into())], now - Duration::hours(2));
        let q = &r.page(now)["quiet"];
        assert_eq!(q["sent_today"], 1);
        assert_eq!(q["overdue"], false);
        let off = tempfile::tempdir().unwrap();
        let r0 = mesh_runner(Arc::new(Fake::new()), off.path(), 0);
        assert_eq!(r0.page(now)["quiet"], serde_json::Value::Null);
        let none = tempfile::tempdir().unwrap();
        assert_eq!(runner(Arc::new(Fake::new()), none.path()).page(now)["quiet"], serde_json::Value::Null);
    }

    #[test]
    fn the_cribl_buffer_keeps_the_newest_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        for i in 0..(RADIO_EVENTS_MAX as i64 + 5) {
            r.record_radio(vec![crate::mesh::skipped_ping("busy", t(i))]);
        }
        let ev = r.take_radio_events();
        assert_eq!(ev.len(), RADIO_EVENTS_MAX);
        assert_eq!(ev.last().unwrap().at, t(RADIO_EVENTS_MAX as i64 + 4));
        assert_eq!(ev[0].at, t(5), "the oldest went");
    }

    #[test]
    fn quiet_ping_when_due_and_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_decoder(Some(Arc::new(Boom(Default::default()))))
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 3), t(0), &mut || 0);
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        let got = r.mesh_outbox(t(0), false, &mut || u32::MAX / 2);
        assert_eq!(got, [(None, crate::mesh::QUIET_TEXT.to_string())]);
        let n = r.next_quiet.get().unwrap();
        assert!(n >= t(4 * 3600) && n <= t(12 * 3600), "{n}");
    }

    /// Quiet hours: a due ping inside them is skipped and rescheduled, never saved up.
    #[test]
    fn no_quiet_ping_during_quiet_hours() {
        let dir = tempfile::tempdir().unwrap();
        let h = crate::mesh::local_hour(t(0));
        let mut cfg = mesh_cfg(crate::mesh::Level::Strong, 3);
        cfg.quiet_hours = Some((h, (h + 1) % 24));
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_decoder(Some(Arc::new(Boom(Default::default()))))
            .with_mesh(cfg, t(0), &mut || 0);
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || u32::MAX / 2).is_empty());
        assert!(r.next_quiet.get().unwrap() > t(0), "rescheduled, not held for the morning");
    }

    /// Quiet hours never hold back a real alert.
    #[test]
    fn alerts_go_out_during_quiet_hours() {
        let dir = tempfile::tempdir().unwrap();
        let h = crate::mesh::local_hour(t(0));
        let mut cfg = mesh_cfg(crate::mesh::Level::Strong, 3);
        cfg.quiet_hours = Some((h, (h + 1) % 24));
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_decoder(Some(Arc::new(Boom(Default::default()))))
            .with_mesh(cfg, t(0), &mut || 0);
        insert_row(dir.path(), crate::checks::ANALYSER_HIGH, t(-60));
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        r.closed_alerts(t(0));
        let got = r.mesh_outbox(t(0), false, &mut || 0);
        assert!(got.is_empty(), "no quiet ping beside an alert: {got:?}");
        assert_eq!(r.stage1_outbox(t(0)).len(), 1, "the alert's stage 1");
    }

    #[test]
    fn no_quiet_ping_when_detector_stale() {
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        r.last_pull.set(Some(t(-3 * 3600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || u32::MAX / 2).is_empty());
        assert!(r.next_quiet.get().unwrap() > t(0), "rescheduled even though silent");
        // and never pulled at all
        r.last_pull.set(None);
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || 0).is_empty());
    }

    /// I2: without a decoder nothing is judged, so "all quiet" would be a false all-clear.
    #[test]
    fn no_quiet_ping_without_a_decoder() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 3), t(0), &mut || 0);
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || u32::MAX / 2).is_empty());
        assert!(r.next_quiet.get().unwrap() > t(0), "rescheduled even though silent");
    }

    /// I2: pulls paused for disk means new captures are not being fetched or judged.
    #[test]
    fn no_quiet_ping_while_pulls_are_paused() {
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), true, &mut || u32::MAX / 2).is_empty());
        assert!(r.next_quiet.get().unwrap() > t(0), "rescheduled even though silent");
        // The same runner, not paused, does ping: the pause was the only reason.
        r.next_quiet.set(Some(t(-1)));
        assert_eq!(
            r.mesh_outbox(t(0), false, &mut || u32::MAX / 2),
            [(None, crate::mesh::QUIET_TEXT.to_string())]
        );
    }

    /// I2 through the cycle: a paused disk reaches the mesh decision.
    #[tokio::test]
    async fn a_cycle_with_pulls_paused_sends_no_quiet_ping() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("i.sqlite")).unwrap();
        let r = Runner::new(Arc::new(Fake::new()), store, &dir.path().join("archive"), Box::new(|| 0))
            .with_decoder(Some(Arc::new(Boom(Default::default()))))
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 3), t(0), &mut || 0);
        r.next_quiet.set(Some(t(-1)));
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(c.mesh.is_empty(), "{:?}", c.mesh);
        let dir2 = tempfile::tempdir().unwrap();
        let ok = mesh_runner(Arc::new(Fake::new()), dir2.path(), 3);
        ok.next_quiet.set(Some(t(-1)));
        assert_eq!(ok.on_tick(t(0)).await.unwrap().mesh.len(), 1, "control: free disk pings");
    }

    #[test]
    fn unreadable_outbox_sends_no_quiet_ping() {
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        rusqlite::Connection::open(dir.path().join("i.sqlite"))
            .unwrap()
            .execute("ALTER TABLE notifications RENAME TO notifications_gone", [])
            .unwrap();
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || u32::MAX / 2).is_empty());
        assert!(r.next_quiet.get().unwrap() > t(0));
    }

    #[test]
    fn mesh_outbox_caps_at_three_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::All, 0), t(0), &mut || 0);
        let ids: Vec<i64> = (0..5)
            .map(|i| insert_row(dir.path(), checks::NEW_TOWER, t(-100 + i)))
            .collect();
        let got: Vec<Option<i64>> = r.mesh_outbox(t(0), false, &mut || 0).into_iter().map(|x| x.0).collect();
        assert_eq!(got, [Some(ids[0]), Some(ids[1]), Some(ids[2])]);
    }

    #[test]
    fn mesh_failure_leaves_rows_unsent() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path());
        let id = insert_row(dir.path(), checks::ANALYSER_HIGH, t(-60));
        let batch = vec![(Some(id), "x".to_string()), (None, "y".to_string())];
        let offered = |r: &Runner| {
            r.store
                .mesh_pending(DEVICE_ID, &[checks::ANALYSER_HIGH], t(0), 10)
                .unwrap()
                .len()
        };
        after_mesh_send(&r.store, &Err(anyhow::anyhow!("no radio")), &batch, t(0));
        assert_eq!(offered(&r), 1, "an error marks nothing");
        after_mesh_send(&r.store, &Ok(1), &batch, t(0));
        assert_eq!(offered(&r), 0);
    }

    #[test]
    fn after_mesh_send_logs_kinds_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path());
        let batch = vec![
            (Some(1), "alert text".to_string()),
            (None, crate::mesh::QUIET_TEXT.to_string()),
            (None, crate::mesh::TEST_TEXT.to_string()),
        ];
        let got = after_mesh_send(&r.store, &Ok(2), &batch, t(0));
        assert_eq!(got, crate::mesh::MeshStatus::Ok);
        assert_eq!(r.store.mesh_stats(t(0)).unwrap().0, 2, "only what went out is logged");
        let got = after_mesh_send(&r.store, &Err(crate::mesh::link::HandshakeTimeout.into()), &batch, t(0));
        assert_eq!(got, crate::mesh::MeshStatus::NoAnswer);
        assert_eq!(r.store.mesh_stats(t(0)).unwrap().0, 2, "a failure logs nothing");
    }

    /// M1: a batch built by one cycle, re-checked after another cycle meshed its row.
    #[test]
    fn mesh_sendable_drops_rows_another_stage_meshed() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::All, 3), t(0), &mut || 0);
        insert_row(dir.path(), checks::NEW_TOWER, t(-60));
        let b = insert_row(dir.path(), checks::NEW_TOWER, t(-50));
        let batch = r.mesh_outbox(t(0), false, &mut || 0);
        assert_eq!(batch.len(), 2);
        after_mesh_send(&r.store, &Ok(1), &batch[..1], t(1)); // the other stage sent `a`
        let left: Vec<Option<i64>> =
            r.mesh_sendable(batch, t(0), t(2)).into_iter().map(|x| x.0).collect();
        assert_eq!(left, [Some(b)]);
    }

    #[test]
    fn after_mesh_send_marks_only_what_went_out() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path());
        let a = insert_row(dir.path(), checks::ANALYSER_HIGH, t(-60));
        let b = insert_row(dir.path(), checks::ANALYSER_HIGH, t(-50));
        let batch = vec![(None, "p".to_string()), (Some(a), "a".to_string()), (Some(b), "b".to_string())];
        after_mesh_send(&r.store, &Ok(2), &batch, t(0));
        let left = r.store.mesh_pending(DEVICE_ID, &[checks::ANALYSER_HIGH], t(0), 10).unwrap();
        assert_eq!(left.into_iter().map(|x| x.0).collect::<Vec<_>>(), [b]);
    }

    /// A closed-pass strong row with its finding: notifications and findings rows for
    /// capture `name`, as `record_judgement` writes them.
    fn insert_closed(dir: &Path, name: &str, check: &str, detail: &str, found: DateTime<Utc>) -> i64 {
        let c = rusqlite::Connection::open(dir.join("i.sqlite")).unwrap();
        let f = found.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        c.execute(
            "INSERT INTO findings (device, name, start, check_id, level, profile, spans_switch,
                 suppressed, detail, found_at)
             VALUES (?1, ?2, ?3, ?4, 'notify', 'fixed', 0, 0, ?5, ?3)",
            rusqlite::params![DEVICE_ID, name, f, check, detail],
        )
        .unwrap();
        c.execute(
            "INSERT INTO notifications
             (device, name, start, check_id, count, profile, spans_switch, found_at)
             VALUES (?1, ?2, ?3, ?4, 1, 'fixed', 0, ?3)",
            rusqlite::params![DEVICE_ID, name, f, check],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    const TOWER: &str = "sib1:310-260:1:2";

    /// Whether the closed pass has ingested outbox row `id` (it is no longer pending).
    fn alerted(r: &Runner, id: i64) -> bool {
        let strong = crate::mesh::checks_for(crate::mesh::Level::Strong);
        !r.store.alert_pending(DEVICE_ID, strong, 100).unwrap().iter().any(|x| x.0 == id)
    }

    fn live_alert(r: &Runner, check: &'static str, detail: &str, rec: &str, now: DateTime<Utc>) -> i64 {
        let f = crate::live::LiveFinding {
            check,
            detail: detail.to_string(),
            towers: crate::live::towers_in(detail),
            subject: crate::live::subject_of(check, detail),
        };
        match r.store.ingest(DEVICE_ID, &f, crate::store::Source::Live, Some(rec), now).unwrap() {
            crate::store::Ingested::Opened(id) | crate::store::Ingested::Joined(id) => id,
            other => panic!("{other:?}"),
        }
    }

    /// Live already raised it and its stage 1 went out: the closed pass adds nothing.
    #[test]
    fn closed_strong_after_live_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0);
        let id = live_alert(&r, checks::NEW_TOWER_IDENTITY, &format!("new tower {TOWER} asked for ID"), "100", t(-600));
        r.stage1_sent(&[(id, "s".into())], t(-590));
        let row = insert_closed(
            dir.path(),
            "100",
            checks::NEW_TOWER_IDENTITY,
            &format!("{TOWER} identity request"),
            t(-60),
        );
        r.closed_alerts(t(0));
        assert!(r.mesh_outbox(t(0), false, &mut || 0).is_empty());
        assert!(r.stage1_outbox(t(0)).is_empty());
        assert!(alerted(&r, row), "ingested, nothing on the radio");
        assert_eq!(r.store.open_alert(DEVICE_ID).unwrap().unwrap().id, id, "no second alert");
    }

    /// No live alert: the closed pass opens one; its stage 1 copy goes out and is recorded.
    #[tokio::test]
    async fn closed_strong_without_live_sends_stage1_text() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0);
        let row = insert_closed(dir.path(), "100", checks::TOWER_FLOOD, &format!("towers {TOWER}"), t(-60));
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(c.mesh.is_empty(), "{:?}", c.mesh);
        let alert = r.store.open_alert(DEVICE_ID).unwrap().expect("opened");
        let want = crate::mesh::stage1_text(checks::TOWER_FLOOD).unwrap();
        assert_eq!(c.stage1, [(alert.id, want.clone())]);
        let ev = r.store.alert_events(alert.id).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].source, crate::store::Source::Closed);
        assert_eq!(ev[0].recording.as_deref(), Some("100"));
        assert_eq!(ev[0].towers, [TOWER]);
        assert!(alerted(&r, row));
        r.cycle_mesh_sent(&Ok(1), &c.stage1, &c.mesh, t(1));
        assert!(r.store.open_alert(DEVICE_ID).unwrap().unwrap().stage1_at.is_some());
        let log = r.store.radio_log(DEVICE_ID, 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!((log[0].kind.as_str(), log[0].text.as_str(), log[0].alert_id), ("stage1", want.as_str(), Some(alert.id)));
        assert_eq!(r.store.mesh_stats(t(1)).unwrap().0, 1);
        assert!(r.on_tick(t(900)).await.unwrap().stage1.is_empty(), "sent once");
    }

    /// A send failure leaves the stage 1 owed by the alert, never re-ingests the row.
    #[tokio::test]
    async fn closed_row_ingested_once_even_if_cycle_repeats() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0);
        let row = insert_closed(dir.path(), "100", checks::ANALYSER_HIGH, "imsi_requested: 1 high warning(s)", t(-60));
        let c1 = r.on_tick(t(0)).await.unwrap();
        assert_eq!(c1.stage1.len(), 1);
        assert!(alerted(&r, row), "the row is spent at ingest");
        r.cycle_mesh_sent(&Err(anyhow::anyhow!("no radio")), &c1.stage1, &c1.mesh, t(1));
        let c2 = r.on_tick(t(900)).await.unwrap();
        assert_eq!(c2.stage1, c1.stage1, "still owed, the same alert");
        let a = r.store.open_alert(DEVICE_ID).unwrap().unwrap();
        assert_eq!(r.store.alert_events(a.id).unwrap().len(), 1, "ingested once");
    }

    /// M5: the closed pass also stamps the row's `mesh_at`, as 0.5.3 would have after
    /// sending it, so a rollback to 0.5.3 on this database does not re-send strong rows.
    /// 0.6.0 itself never reads `mesh_at` of a strong row: the alert's stage 1 is still owed.
    #[test]
    fn closed_ingest_stamps_mesh_at_for_rollback() {
        let strong = crate::mesh::checks_for(crate::mesh::Level::Strong);
        for with_mesh in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let mut r = runner(Arc::new(Fake::new()), dir.path());
            if with_mesh {
                r = r.with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0);
            }
            let row = insert_closed(dir.path(), "100", checks::TOWER_FLOOD, &format!("towers {TOWER}"), t(-60));
            assert_eq!(r.store.mesh_pending(DEVICE_ID, strong, t(0), 10).unwrap().len(), 1);
            r.closed_alerts(t(0));
            assert!(alerted(&r, row));
            // What 0.5.3 would send after a rollback: nothing.
            assert!(r.store.mesh_pending(DEVICE_ID, strong, t(0), 10).unwrap().is_empty(), "mesh {with_mesh}");
            assert!(r.store.mesh_still_pending(&[row]).unwrap().is_empty());
            if with_mesh {
                let alert = r.store.open_alert(DEVICE_ID).unwrap().unwrap();
                let want = crate::mesh::stage1_text(checks::TOWER_FLOOD).unwrap();
                assert_eq!(r.stage1_outbox(t(0)), [(alert.id, want)], "stage 1 still owed");
            }
        }
    }

    /// `mesh_level: all`: notice rows still go out as today, untouched by alerts.
    #[test]
    fn mesh_level_all_nonstrong_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::All, 0), t(0), &mut || 0);
        let a = insert_closed(dir.path(), "100", checks::NEW_TOWER, &format!("new {TOWER}"), t(-60));
        let b = insert_row(dir.path(), checks::ANALYSER_OTHER, t(-50));
        let got = r.mesh_outbox(t(0), false, &mut || 0);
        assert_eq!(
            got,
            [
                (Some(a), crate::mesh::text_for(checks::NEW_TOWER).unwrap().to_string()),
                (Some(b), crate::mesh::text_for(checks::ANALYSER_OTHER).unwrap().to_string()),
            ]
        );
        assert!(r.store.open_alert(DEVICE_ID).unwrap().is_none());
        assert_eq!(r.store.mesh_still_pending(&[a, b]).unwrap(), [a, b], "marked only once sent");
        assert!(r.stage1_outbox(t(0)).is_empty());
    }

    /// No radio configured: the closed pass still records the alert (the owner page's
    /// record); nothing is owed to a radio that is not there.
    #[tokio::test]
    async fn closed_strong_opens_alert_without_radio() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path());
        let row = insert_closed(dir.path(), "100", checks::NEW_TOWER_RECUR, &format!("back {TOWER}"), t(-60));
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(c.mesh.is_empty() && c.stage1.is_empty());
        let a = r.store.open_alert(DEVICE_ID).unwrap().expect("opened without a radio");
        let ev = r.store.alert_events(a.id).unwrap();
        assert_eq!((ev.len(), ev[0].check_id.as_str(), ev[0].source), (1, checks::NEW_TOWER_RECUR, crate::store::Source::Closed));
        assert!(alerted(&r, row));
        r.on_tick(t(900)).await.unwrap();
        assert_eq!(r.store.alert_events(a.id).unwrap().len(), 1, "not ingested again");
    }

    #[test]
    fn confirmed_by_matches_a_shared_tower() {
        let e = crate::store::AlertEvent {
            at: t(0),
            check_id: checks::NEW_TOWER_IDENTITY.into(),
            detail: format!("new {TOWER}"),
            towers: vec![TOWER.into()],
            source: crate::store::Source::Live,
            recording: Some("a".into()),
            subject: String::new(),
            timeline_only: false,
        };
        let id = checks::NEW_TOWER_IDENTITY.to_string();
        let named = format!("identity request after: {TOWER}, 3 min");
        assert!(confirmed_by(&e, &[(id.clone(), named.clone())]));
        assert!(!confirmed_by(&e, &[(id.clone(), "identity request after: sib1:310-260:9:9, 3 min".into())]));
        assert!(!confirmed_by(&e, &[(checks::NEW_TOWER.into(), named)]), "another check");
        assert!(!confirmed_by(&e, &[]));
    }

    /// Stage 1 already out, a closed strong row joins the open alert, a ping is due: no
    /// "all quiet" while any alert is open. Control: the alert closed, the ping goes.
    #[test]
    fn no_quiet_ping_while_an_alert_is_open() {
        let dir = tempfile::tempdir().unwrap();
        let r = mesh_runner(Arc::new(Fake::new()), dir.path(), 3);
        let id = live_alert(&r, checks::NEW_TOWER_IDENTITY, &format!("new {TOWER}"), "100", t(-600));
        r.stage1_sent(&[(id, "s".into())], t(-590));
        insert_closed(dir.path(), "100", checks::ANALYSER_HIGH, "imsi_requested: 1 high warning(s)", t(-60));
        r.closed_alerts(t(0));
        assert_eq!(r.store.alert_events(id).unwrap().len(), 2, "joined");
        r.last_pull.set(Some(t(-600)));
        r.next_quiet.set(Some(t(-1)));
        assert!(r.mesh_outbox(t(0), false, &mut || u32::MAX / 2).is_empty(), "no false all clear");
        r.store.close_alert(id, crate::store::CloseBy::AllClear, t(1)).unwrap();
        r.next_quiet.set(Some(t(-1)));
        assert_eq!(
            r.mesh_outbox(t(2), false, &mut || u32::MAX / 2),
            [(None, crate::mesh::QUIET_TEXT.to_string())]
        );
    }

    fn gave_up_and_closed_by(dir: &Path, id: i64) -> (i64, Option<String>) {
        rusqlite::Connection::open(dir.join("i.sqlite"))
            .unwrap()
            .query_row("SELECT stage1_gave_up, closed_by FROM alerts WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
    }

    /// An alert unseen and unsent for 24 h is given up (and logged) before it expires;
    /// an unsent TEST alert closes as `test`, not silently as `expired`.
    #[test]
    fn stage1_given_up_before_the_alert_expires() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0);
        let id = live_alert(&r, checks::NEW_TOWER_IDENTITY, &format!("new {TOWER}"), "100", t(0));
        let later = t(24 * 3600 + 60);
        assert!(r.stage1_outbox(later).is_empty());
        assert_eq!(gave_up_and_closed_by(dir.path(), id), (1, Some("expired".into())));

        let dir2 = tempfile::tempdir().unwrap();
        let r2 = runner(Arc::new(Fake::new()), dir2.path())
            .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0);
        let detail = format!("{LIVE_TEST_PREFIX}x");
        let f = crate::live::LiveFinding {
            check: checks::ANALYSER_HIGH,
            subject: crate::live::subject_of(checks::ANALYSER_HIGH, &detail),
            towers: Vec::new(),
            detail,
        };
        let crate::store::Ingested::Opened(test) =
            r2.store.ingest(DEVICE_ID, &f, crate::store::Source::Live, None, t(0)).unwrap()
        else {
            panic!()
        };
        assert!(r2.stage1_outbox(later).is_empty());
        assert_eq!(gave_up_and_closed_by(dir2.path(), test), (1, Some("test".into())));
    }

    fn admin_kinds(c: &Cycle) -> Vec<String> {
        c.admin
            .iter()
            .map(|(_, b)| {
                let v: serde_json::Value = serde_json::from_str(b).unwrap();
                assert_eq!(v["admin"], true);
                v["event_type"].as_str().unwrap().to_string()
            })
            .collect()
    }

    /// A live alert the closed pass did not confirm: one notice for the capture.
    #[tokio::test]
    async fn unconfirmed_live_alert_pushes_once() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        // Boom: the capture is judged with a decoder_failure finding only.
        let r = runner(fake.clone(), dir.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        live_alert(&r, checks::NEW_TOWER_IDENTITY, &format!("new {TOWER}"), "a", t(-600));
        live_alert(&r, checks::ANALYSER_HIGH, "imsi_requested: 1 high warning(s)", "a", t(-500));
        live_alert(&r, checks::NEW_TOWER_IDENTITY, "new sib1:310-260:9:9", "other", t(-400));
        let c = r.on_tick(t(0)).await.unwrap();
        assert_eq!(admin_kinds(&c), ["live_unconfirmed"]);
        // Judged once: later cycles say nothing more, even past the cooldown.
        let later = t(2 * HEALTH_COOLDOWN_MIN * 60);
        assert!(!admin_kinds(&r.on_tick(later).await.unwrap()).contains(&"live_unconfirmed".to_string()));

        // Control: the closed pass found the same check (no towers): nothing.
        let dir2 = tempfile::tempdir().unwrap();
        let fake2 = Arc::new(Fake::new());
        fake2.add("a", b"hello");
        let r2 = runner(fake2, dir2.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        live_alert(&r2, checks::DECODER_FAILURE, "sandbox", "a", t(-600));
        assert!(admin_kinds(&r2.on_tick(t(0)).await.unwrap()).is_empty());
    }

    #[tokio::test]
    async fn low_disk_at_90_pushes_with_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.set_disk(89);
        let r = runner(fake.clone(), dir.path());
        assert!(admin_kinds(&r.on_tick(t(0)).await.unwrap()).is_empty(), "89 %");
        fake.set_disk(90);
        assert_eq!(admin_kinds(&r.on_tick(t(900)).await.unwrap()), ["low_disk"]);
        assert!(admin_kinds(&r.on_tick(t(1800)).await.unwrap()).is_empty(), "cooldown");
        let after = t(900 + HEALTH_COOLDOWN_MIN * 60);
        assert_eq!(admin_kinds(&r.on_tick(after).await.unwrap()), ["low_disk"]);
    }

    #[tokio::test]
    async fn paused_archive_pushes_decoding_off() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("i.sqlite")).unwrap();
        let r = Runner::new(Arc::new(Fake::new()), store, &dir.path().join("archive"), Box::new(|| 0));
        assert_eq!(admin_kinds(&r.on_tick(t(0)).await.unwrap()), ["decoding_off"]);
        assert!(admin_kinds(&r.on_tick(t(900)).await.unwrap()).is_empty(), "cooldown");
        // Control: free space, no notice.
        let dir2 = tempfile::tempdir().unwrap();
        let ok = runner(Arc::new(Fake::new()), dir2.path());
        assert!(admin_kinds(&ok.on_tick(t(0)).await.unwrap()).is_empty());
    }

    #[test]
    fn tls_config_builds_without_panicking() {
        install_crypto_provider();
        install_crypto_provider(); // idempotent
        assert!(tls_config_from(rustls::RootCertStore::empty()).is_ok());
        // whatever the CA store state here, it must return, never panic
        let _ = tls_config();
    }

    fn runner(fake: Arc<Fake>, dir: &Path) -> Runner {
        let store = Store::open(&dir.join("i.sqlite")).unwrap();
        Runner::new(
            fake,
            store,
            &dir.join("archive"),
            Box::new(|| 100_000_000_000),
        )
    }

    fn t(n: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + n, 0).unwrap()
    }

    #[test]
    fn a_tick_during_a_cycle_is_dropped_not_queued() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        fake.gate("download");
        let r = Rc::new(runner(fake.clone(), dir.path()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let r1 = r.clone();
            let first = tokio::task::spawn_local(async move { r1.on_tick(t(0)).await });
            // wait until the first cycle is inside the (blocked) download
            while !fake.log().iter().any(|l| l == "download a") {
                tokio::task::yield_now().await;
            }
            // two more ticks arrive while it is stuck
            // (a queueing implementation would block here; fail instead of hanging)
            let wait = std::time::Duration::from_secs(2);
            let d1 = tokio::time::timeout(wait, r.on_tick(t(900))).await;
            let d2 = tokio::time::timeout(wait, r.on_tick(t(1800))).await;
            assert!(
                matches!(d1, Ok(None)),
                "tick during a cycle must be dropped"
            );
            assert!(
                matches!(d2, Ok(None)),
                "tick during a cycle must be dropped"
            );
            fake.release("download", 100);
            let msgs = first.await.unwrap();
            assert!(msgs.is_some());
            assert_eq!(r.cycles(), 1, "dropped ticks must not run or queue a cycle");
            // and it is free again afterwards
            assert!(r.on_tick(t(2700)).await.is_some());
            assert_eq!(r.cycles(), 2);
        });
        assert_eq!(fake.log().iter().filter(|l| *l == "download a").count(), 1);
    }

    /// I4: an unreachable unit must keep showing the last known backlog, not 0.
    #[tokio::test]
    async fn unreachable_unit_keeps_the_last_known_backlog() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        fake.fail("download a", crate::device::DeviceError::Unreachable);
        let r = runner(fake.clone(), dir.path());
        let get = |m: &[(String, String)], k: &str| {
            m.iter()
                .find(|(t, _)| t.ends_with(&format!("/{k}")))
                .unwrap()
                .1
                .clone()
        };
        let m = r.on_tick(t(0)).await.unwrap().states;
        assert_eq!(get(&m, "backlog"), "1");
        let oldest = get(&m, "oldest_backlog");
        assert_eq!(oldest, "2023-11-14T22:13:20Z");

        fake.fail("finished", crate::device::DeviceError::Unreachable);
        let m = r.on_tick(t(900)).await.unwrap().states;
        assert_eq!(get(&m, "backlog"), "1");
        assert_eq!(get(&m, "oldest_backlog"), oldest);
    }

    #[tokio::test]
    async fn mesh_sensors_are_published_only_when_mesh_is_on() {
        let has = |c: &Cycle| c.states.iter().any(|(k, _)| k.contains("/mesh_"));
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path());
        assert!(!has(&r.on_tick(t(0)).await.unwrap()), "mesh off: no mesh states");
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = mesh_cfg(crate::mesh::Level::Strong, 0);
        cfg.port = dir.path().join("radio").to_string_lossy().into_owned();
        std::fs::write(&cfg.port, b"").unwrap(); // the radio is plugged in
        let r = runner(Arc::new(Fake::new()), dir.path()).with_mesh(cfg, t(0), &mut || 0);
        let st = |c: &Cycle, k: &str| {
            c.states.iter().find(|(t, _)| t.ends_with(&format!("/mesh_{k}"))).unwrap().1.clone()
        };
        let c = r.on_tick(t(0)).await.unwrap();
        assert_eq!((st(&c, "status").as_str(), st(&c, "sent_24h").as_str()), ("ok", "0"));
        r.mesh_sent(&Err(crate::mesh::link::HandshakeTimeout.into()), &[], t(1));
        r.mesh_sent(&Ok(1), &[(None, crate::mesh::QUIET_TEXT.to_string())], t(2));
        r.mesh_sent(&Err(anyhow::anyhow!("x")), &[], t(3));
        let c = r.on_tick(t(900)).await.unwrap();
        assert_eq!(st(&c, "status"), "error");
        assert_eq!(st(&c, "sent_24h"), "1");
        assert_eq!(st(&c, "last_sent"), "2023-11-14T22:13:22Z");
    }

    /// I1: a missing radio shows as "radio missing" every cycle without any send being due,
    /// and its return restores the status of the last real attempt.
    #[tokio::test]
    async fn a_missing_radio_is_reported_without_a_send() {
        let dir = tempfile::tempdir().unwrap();
        let port = dir.path().join("radio");
        let mut cfg = mesh_cfg(crate::mesh::Level::Strong, 0);
        cfg.port = port.to_string_lossy().into_owned();
        let r = runner(Arc::new(Fake::new()), dir.path()).with_mesh(cfg, t(0), &mut || 0);
        let st = |c: &Cycle| {
            c.states.iter().find(|(t, _)| t.ends_with("/mesh_status")).unwrap().1.clone()
        };
        assert!(r.mesh_outbox(t(0), false, &mut || 0).is_empty(), "nothing due to send");
        assert_eq!(st(&r.on_tick(t(0)).await.unwrap()), "radio missing");
        assert_eq!(st(&r.on_tick(t(900)).await.unwrap()), "radio missing");
        std::fs::write(&port, b"").unwrap();
        assert_eq!(st(&r.on_tick(t(1800)).await.unwrap()), "ok", "no attempt yet: ok");
        r.mesh_sent(&Err(crate::mesh::link::HandshakeTimeout.into()), &[], t(1801));
        std::fs::remove_file(&port).unwrap();
        assert_eq!(st(&r.on_tick(t(2700)).await.unwrap()), "radio missing");
        std::fs::write(&port, b"").unwrap();
        assert_eq!(st(&r.on_tick(t(3600)).await.unwrap()), "no answer", "the last attempt");
    }

    use std::rc::Rc;

    #[test]
    fn publishing_needs_a_connection_and_no_other_publisher() {
        assert!(may_publish(true, false));
        assert!(!may_publish(false, false), "broker down: nothing is queued");
        assert!(!may_publish(true, true), "a publish stage is already running");
        assert!(!may_publish(false, true));
    }

    /// I-3: HA restarting drops events on the floor, so they wait for it; states do not.
    #[test]
    fn events_also_need_home_assistant_online() {
        assert!(may_send_events(true, true));
        assert!(!may_send_events(true, false), "HA offline: events stay in the outbox");
        assert!(!may_send_events(false, true));
        assert!(!may_send_events(false, false));
    }

    fn ev(n: usize) -> (String, String) {
        ("t".to_string(), n.to_string())
    }

    /// The live view's first tick runs before MQTT is up: its events must wait, not vanish
    /// (a TEST alert once reached the radio but never the phone).
    #[test]
    fn live_events_wait_until_they_may_be_sent() {
        let mut h = HeldEvents::default();
        assert_eq!(h.take(vec![ev(1)], false), (vec![], 0));
        assert_eq!(h.take(vec![ev(2)], false), (vec![], 0));
        assert_eq!(h.take(vec![], true), (vec![ev(1), ev(2)], 0), "held first, in order");
        assert_eq!(h.take(vec![], true), (vec![], 0), "sent once only");
    }

    #[test]
    fn held_live_events_go_ahead_of_new_ones() {
        let mut h = HeldEvents::default();
        h.take(vec![ev(1)], false);
        assert_eq!(h.take(vec![ev(2)], true), (vec![ev(1), ev(2)], 0));
    }

    /// A failed publish is held for the next tick, ahead of anything newer.
    #[test]
    fn a_failed_publish_is_held_again() {
        let mut h = HeldEvents::default();
        assert_eq!(h.hold(vec![ev(1)]), 0);
        assert_eq!(h.take(vec![ev(2)], true), (vec![ev(1), ev(2)], 0));
    }

    /// A long broker outage must not grow memory without bound. The oldest are kept: an
    /// alert's opening notice matters more than the admin notices after it.
    #[test]
    fn held_live_events_are_capped_keeping_the_oldest() {
        let mut h = HeldEvents::default();
        let many: Vec<_> = (0..LIVE_HELD_MAX + 3).map(ev).collect();
        assert_eq!(h.take(many, false), (vec![], 3));
        let (sent, dropped) = h.take(vec![ev(999)], true);
        assert_eq!(dropped, 1);
        assert_eq!(sent.len(), LIVE_HELD_MAX);
        assert_eq!(sent.first(), Some(&ev(0)));
        assert_eq!(sent.last(), Some(&ev(LIVE_HELD_MAX - 1)));
    }

    /// A missed birth message (HA and the broker restarting together) must not hold events
    /// for good: every broker (re)connect assumes HA is listening again.
    #[test]
    fn ha_online_resets_on_every_broker_connect() {
        use HaSignal::*;
        assert!(!ha_online_after(true, StatusOffline));
        assert!(ha_online_after(false, StatusOnline));
        assert!(ha_online_after(false, ConnAck), "offline, then reconnect without a birth");
        assert!(ha_online_after(true, ConnAck));
        let after = [StatusOffline, ConnAck].iter().fold(true, |f, s| ha_online_after(f, *s));
        assert!(after);
    }

    fn pend(id: i64, check: &str) -> crate::store::Pending {
        crate::store::Pending {
            id, name: format!("{id}"), check: check.into(), count: 1, profile: "fixed".into(),
            spans_switch: false, found_at: t(0), towers_known: None,
        }
    }

    fn ids(b: &Batch) -> (Vec<i64>, Vec<i64>, Vec<(i64, String)>) {
        (b.events.iter().map(|e| e.0).collect(), b.merged.clone(), b.unsendable.clone())
    }

    /// I-2: health alerts at most once an hour per check; catcher signals unaffected.
    #[test]
    fn health_alerts_cool_down_for_an_hour() {
        let never = |_: &str| None;
        // Two decoder failures and an archive corrupt in one batch, plus a new tower.
        let b = sort_outbox(
            vec![
                pend(1, "decoder_failure"), pend(2, "new_tower_recur"), pend(3, "decoder_failure"),
                pend(4, "archive_corrupt"), pend(5, "archive_corrupt"), pend(6, "new_tower_recur"),
            ],
            never,
            t(0),
        );
        assert_eq!(ids(&b), (vec![1, 2, 4, 6], vec![3, 5], vec![]));
        // One sent 30 min ago: this one merges. The tower is never held back.
        let recent = |c: &str| (c == "decoder_failure").then(|| t(-1800));
        let b = sort_outbox(vec![pend(1, "decoder_failure"), pend(2, "new_tower_recur")], recent, t(0));
        assert_eq!(ids(&b), (vec![2], vec![1], vec![]));
        let any_recent = |_: &str| Some(t(-60));
        let b = sort_outbox(vec![pend(2, "new_tower_recur"), pend(4, "archive_corrupt")], any_recent, t(0));
        assert_eq!(ids(&b), (vec![2], vec![4], vec![]));
        // 61 min later it goes out.
        let old = |_: &str| Some(t(-61 * 60));
        let b = sort_outbox(vec![pend(1, "decoder_failure"), pend(3, "decoder_failure")], old, t(0));
        assert_eq!(ids(&b), (vec![1], vec![3], vec![]));
    }

    /// T4: a row HA cannot take is retired and reported by check id only.
    #[test]
    fn an_unsendable_row_is_reported_by_check_id() {
        let b = sort_outbox(vec![pend(7, "analyser_other"), pend(8, "new_tower_recur")], |_| None, t(0));
        assert_eq!(ids(&b), (vec![8], vec![], vec![(7, "analyser_other".to_string())]));
    }

    /// I-2 through the runner: a decoder failing on every capture alerts once an hour.
    #[tokio::test]
    async fn a_failing_decoder_alerts_once_an_hour() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        fake.add("b", b"world");
        let r =
            runner(fake.clone(), dir.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        let c = r.on_tick(t(0)).await.unwrap();
        assert_eq!(c.events.len(), 1, "two failures in one cycle: one alert");
        r.mark_sent(&[c.events[0].0], t(0));
        // The merged row never comes back.
        assert!(r.on_tick(t(900)).await.unwrap().events.is_empty());
        fake.add("c", b"again");
        assert!(r.on_tick(t(1800)).await.unwrap().events.is_empty(), "30 min after: merged");
        fake.add("d", b"later");
        let c = r.on_tick(t(61 * 60)).await.unwrap();
        assert_eq!(c.events.len(), 1, "61 min after the last alert: sent");
        assert!(c.events[0].2.contains("\"event_type\":\"decoder_failure\""));
    }

    /// M1: a batch that another publish stage already marked is not sent again.
    #[tokio::test]
    async fn still_pending_drops_events_marked_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        let r =
            runner(fake.clone(), dir.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        let c1 = r.on_tick(t(0)).await.unwrap();
        let c2 = r.on_tick(t(900)).await.unwrap(); // same row, still unmarked
        let id = c1.events[0].0;
        assert_eq!(c2.events[0].0, id);
        assert_eq!(r.still_pending(&[id]), vec![id]);
        r.mark_sent(&[id], t(901)); // the first stage got there first
        assert!(r.still_pending(&[id]).is_empty());
    }

    /// M3: the decoder flag does not depend on the findings report succeeding.
    #[tokio::test]
    async fn decoder_unavailable_survives_a_report_failure() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path());
        r.store.drop_findings_for_test();
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(c.states.iter().all(|(t, _)| !t.contains("/findings/")), "report did fail");
        assert!(c
            .states
            .iter()
            .any(|(t, v)| t.ends_with("/decoder_unavailable") && v == "ON"));
    }

    fn of_type<'a>(c: &'a Cycle, t: &str) -> Vec<&'a serde_json::Value> {
        c.cribl.iter().filter(|e| e["type"] == t).collect()
    }

    /// The cycle's Cribl events come from what the cycle already had in hand.
    #[tokio::test]
    async fn a_cycle_carries_its_cribl_events() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        fake.add("b", b"world");
        let r =
            runner(fake.clone(), dir.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        let c = r.on_tick(t(0)).await.unwrap();
        let cy = of_type(&c, "cycle");
        assert_eq!(cy.len(), 1);
        assert_eq!((cy[0]["pulled"].as_u64(), cy[0]["reached_device"].as_bool()), (Some(2), Some(true)));
        assert!(cy[0]["cycle_ms"].is_u64());
        let d = of_type(&c, "decode");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0]["status"], "decoder_failure");
        let f = of_type(&c, "finding");
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|e| e["check"] == "decoder_failure" && e["level"] == "notify"));
        let h = of_type(&c, "health");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0]["decoder_failures_24h"], 2);
        assert_eq!(h[0]["decoder_unavailable"], false);
        assert!(c.cribl.iter().all(|e| e["time"] == "2023-11-14T22:13:20Z"));
        // Two failures, one alert: the second row merged, and said so.
        let n = of_type(&c, "notification");
        assert_eq!(n.len(), 1);
        assert_eq!((n[0]["capture"].as_str(), n[0]["outcome"].as_str()), (Some("b"), Some("merged")));
        // The row to be published is kept as a note for the publish stage.
        assert_eq!(c.notes.len(), 1);
        assert_eq!(c.notes[0].id, c.events[0].0);
        assert_eq!((c.notes[0].capture.as_str(), c.notes[0].check.as_str()), ("a", "decoder_failure"));
        let sent = crate::cribl::notifications(&c.notes, &[c.events[0].0], "sent", t(1));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["outcome"], "sent");
    }

    /// A row left unsent for a day expires, and the Cribl output names it.
    #[tokio::test]
    async fn expired_and_unsendable_rows_become_notification_events() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        let r =
            runner(fake.clone(), dir.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        assert_eq!(r.on_tick(t(0)).await.unwrap().events.len(), 1);
        let c = r.on_tick(t(25 * 3600)).await.unwrap();
        assert!(c.events.is_empty());
        let n = of_type(&c, "notification");
        assert_eq!(n.len(), 1);
        assert_eq!((n[0]["capture"].as_str(), n[0]["outcome"].as_str()), (Some("a"), Some("expired")));
        // analyser_other has no HA event type: retired as unsendable.
        let b = sort_outbox(vec![pend(7, "analyser_other")], |_| None, t(0));
        assert_eq!(b.unsendable.len(), 1);
    }

    /// Test 5: an unreachable or hanging Cribl changes nothing in the cycle, and a send
    /// stuck on it does not hold up the next cycle.
    ///
    /// main.rs has no harness, so this reproduces its wiring: the cycle thread's
    /// current-thread runtime + LocalSet, `on_tick`, then `cribl::after_cycle` in its own
    /// `spawn_local` task while the next tick runs. Margins: the next cycle must finish
    /// within 1 s while the stuck send only times out after 6 s.
    #[test]
    fn the_cycle_is_unaffected_by_an_unreachable_cribl() {
        use crate::cribl;
        let pem = include_str!("testdata/cribl/leaf.crt");
        // Accepts connections and never answers.
        let hang = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://127.0.0.1:{}/cribl/_bulk", hang.local_addr().unwrap().port());
        let cfg = cribl::config(Some(&url), Some("t"), Some(pem)).unwrap();
        let sender = Rc::new(cribl::Sender::new(&cfg, std::time::Duration::from_secs(6)).unwrap());
        let buf: cribl::Shared = Default::default();

        let run = |with_cribl: bool| {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.add("a", b"hello");
            let r = Rc::new(
                runner(fake.clone(), dir.path())
                    .with_decoder(Some(Arc::new(Boom(Default::default())))),
            );
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let local = tokio::task::LocalSet::new();
            let (sender, buf) = (sender.clone(), buf.clone());
            local.block_on(&rt, async move {
                let c1 = r.on_tick(t(0)).await.unwrap();
                let send = with_cribl.then(|| {
                    let (s, b, ev) = (sender.clone(), buf.clone(), c1.cribl.clone());
                    tokio::task::spawn_local(async move { cribl::after_cycle(&s, &b, ev).await })
                });
                fake.add("b", b"again");
                let quick = std::time::Duration::from_secs(1);
                let c2 = tokio::time::timeout(quick, r.on_tick(t(900))).await;
                let c2 = c2.expect("the next cycle must not wait for Cribl").unwrap();
                if let Some(h) = send {
                    assert!(!h.is_finished(), "the send is still stuck");
                    assert_eq!(h.await.unwrap(), cribl::Flushed::Kept(c1.cribl.len()));
                }
                let strip = |c: &Cycle| (c.states.clone(), c.events.clone());
                (strip(&c1), strip(&c2))
            })
        };
        let with = run(true);
        let without = run(false);
        assert_eq!(with, without, "states and events are the same with or without Cribl");
        assert!(!with.0.1.is_empty(), "the alert is still there");
        assert!(buf.lock().unwrap().len() > 0, "kept for the next cycle");
        drop(hang);
    }

    /// A sandbox that panics (counting its calls).
    struct Boom(std::sync::atomic::AtomicU32);
    impl Decoder for Boom {
        fn run(&self, _: &Path) -> (crate::events::Tally, crate::sandbox::RunEnd) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("sandbox exploded");
        }
    }

    /// A Notify finding reaches the cycle's events, once; marking it sent empties the queue.
    #[tokio::test]
    async fn a_notify_finding_becomes_one_event_until_marked_sent() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        // decoder_failure is notify-level in both profiles.
        let r =
            runner(fake.clone(), dir.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        let c1 = r.on_tick(t(0)).await.unwrap();
        // Archived in this same cycle, so archived_at == judge_epoch: live, not backfill.
        assert_eq!(c1.events.len(), 1, "{:?}", c1.events);
        let (id, topic, body) = &c1.events[0];
        assert_eq!(topic, "rayhunter_archive/unit1/finding");
        assert!(body.contains("\"event_type\":\"decoder_failure\""));
        // Not marked: it comes again next cycle (MQTT was down).
        let c2 = r.on_tick(t(900)).await.unwrap();
        assert_eq!(c2.events.len(), 1);
        r.mark_sent(&[*id], t(901));
        let c3 = r.on_tick(t(1800)).await.unwrap();
        assert!(c3.events.is_empty());
    }

    #[tokio::test]
    async fn events_are_not_in_the_retained_set() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        let r =
            runner(fake.clone(), dir.path()).with_decoder(Some(Arc::new(Boom(Default::default()))));
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(!c.events.is_empty());
        assert!(c.states.iter().all(|(t, _)| !t.ends_with("/finding")));
        assert!(c
            .states
            .iter()
            .any(|(t, v)| t.ends_with("/decoder_unavailable") && v == "OFF"));
    }

    #[tokio::test]
    async fn no_decoder_reports_decoder_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let r = runner(Arc::new(Fake::new()), dir.path());
        let c = r.on_tick(t(0)).await.unwrap();
        assert!(c
            .states
            .iter()
            .any(|(t, v)| t.ends_with("/decoder_unavailable") && v == "ON"));
    }

    /// A sandbox that panics must not stop the pull in the same cycle, and the capture
    /// is decoded (as a failure) exactly once.
    #[tokio::test]
    async fn a_panicking_decoder_does_not_affect_the_pull() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::new());
        fake.add("a", b"hello");
        let boom = Arc::new(Boom(Default::default()));
        let r = runner(fake.clone(), dir.path()).with_decoder(Some(boom.clone()));
        assert!(r.on_tick(t(0)).await.is_some());
        assert!(fake.log().iter().any(|l| l == "download a"));
        let c = r.store.by_name(DEVICE_ID, "a").unwrap().remove(0);
        assert_eq!(c.state, crate::store::State::DeletedOnDevice);
        assert_eq!(
            r.store.get_decode(c.key()).unwrap().unwrap().status,
            crate::store::DecodeStatus::DecoderFailure
        );
        assert!(r.on_tick(t(900)).await.is_some());
        assert_eq!(boom.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn all_clear_hours_option() {
        let h = |j: &str| parse_options(j).unwrap().all_clear_hours;
        assert_eq!(h(r#"{"device_url":"u"}"#), 3);
        assert_eq!(h(r#"{"device_url":"u","all_clear_hours":null}"#), 3);
        assert_eq!(h(r#"{"device_url":"u","all_clear_hours":0}"#), 1);
        assert_eq!(h(r#"{"device_url":"u","all_clear_hours":99}"#), 24);
        assert_eq!(h(r#"{"device_url":"u","all_clear_hours":6}"#), 6);
    }

    #[test]
    fn options_live_poll_secs_clamped() {
        let live = |j: &str| {
            let o = parse_options(j).unwrap();
            (o.live_poll_secs, o.live_test_alert)
        };
        assert_eq!(live(r#"{"device_url":"u"}"#), (60, false));
        assert_eq!(live(r#"{"device_url":"u","live_poll_secs":null,"live_test_alert":null}"#), (60, false));
        assert_eq!(live(r#"{"device_url":"u","live_poll_secs":10}"#), (30, false));
        assert_eq!(live(r#"{"device_url":"u","live_poll_secs":-5}"#), (30, false));
        assert_eq!(live(r#"{"device_url":"u","live_poll_secs":9999}"#), (600, false));
        assert_eq!(live(r#"{"device_url":"u","live_poll_secs":120,"live_test_alert":true}"#), (120, true));
    }

    mod live_tick {
        use super::*;
        use crate::live::{LiveTower, Snapshot};

        fn rfc(n: i64) -> String {
            t(n).to_rfc3339()
        }

        /// A runner with the live view on (token set) and the mesh on.
        fn live_runner(fake: Arc<Fake>, dir: &Path, test_alert: bool) -> Runner {
            runner(fake, dir)
                .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0)
                .with_live(Some("tok".into()), test_alert, t(0))
        }

        /// Fixed finished learning a month ago.
        fn fixed_learned(dir: &Path) {
            let since = (t(0) - Duration::days(30))
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
            Store::open(&dir.join("i.sqlite")).unwrap(); // the schema
            rusqlite::Connection::open(dir.join("i.sqlite"))
                .unwrap()
                .execute(
                    "INSERT INTO meta (key, value) VALUES ('fixed_since', ?1)",
                    [since],
                )
                .unwrap();
        }

        fn snap(rec: Option<&str>) -> Snapshot {
            Snapshot {
                recording: rec.map(str::to_string),
                towers: vec![],
                towers_capped: false,
                identity: vec![],
                identity_total: 0,
                warnings: vec![],
                warnings_total: 0,
                warnings_high_total: 0,
            }
        }

        /// An unknown tower, then an identity request a minute later.
        fn identity_snap() -> Snapshot {
            let mut s = snap(Some("100"));
            s.towers = vec![LiveTower {
                key: "sib1:310-260:1:2".into(),
                first: Some(rfc(-120)),
                last: Some(rfc(-60)),
                hits: 3,
            }];
            s.identity = vec![Some(rfc(-60))];
            s.identity_total = 1;
            s
        }

        fn high_snap() -> Snapshot {
            let mut s = snap(Some("100"));
            s.warnings = vec![crate::events::WarningSeen {
                severity: crate::events::Severity::High,
                analyzer: "imsi_requested".into(),
                msg: "IMSI requested".into(),
                ts: Some(rfc(-30)),
            }];
            s.warnings_total = 1;
            s.warnings_high_total = 1;
            s
        }

        fn json(e: &(String, String)) -> serde_json::Value {
            serde_json::from_str(&e.1).unwrap()
        }

        /// Final review minor 5: the live view only checks anything in Fixed, so a live
        /// view in Mobile says nothing about the alert: "unknown", and All clear locked.
        #[tokio::test]
        async fn live_in_mobile_is_unknown_to_the_page() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "mobile");
            fake.set_live(Ok(snap(Some("100"))));
            fixed_learned(dir.path());
            let r = live_runner(fake.clone(), dir.path(), false);
            let id = live_alert(&r, checks::NEW_TOWER_IDENTITY, "identity request after: 310-260-1-2", "100", t(0));
            let now = t(4 * 3600);
            assert_eq!(r.on_live_tick(now).await.unwrap().state, LiveState::Ok { at: now });
            let v = r.page(now);
            assert_eq!(v["status"]["sighting"]["state"], "unknown");
            assert_eq!(v["gate"]["unlocked"], false);
            assert_eq!(v["gate"]["unlocks_at"], serde_json::Value::Null);
            let q = FollowUp {
                alert_id: id,
                kind: crate::followup::Kind::AllClear,
                text: "All clear: nothing since.".into(),
                override_gate: false,
            };
            assert_eq!(r.follow_up_prepare(&q, now), Err(Refusal::Locked { unlocks_at: None }));
            // The same unit in Fixed: the live view counts.
            fake.set_profile("100", "fixed");
            let now = t(4 * 3600 + 60);
            r.on_live_tick(now).await.unwrap();
            let v = r.page(now);
            assert_eq!(v["status"]["sighting"]["state"], "no_sign_since");
            assert_eq!(v["gate"]["unlocked"], true);
        }

        #[tokio::test]
        async fn live_new_tower_and_identity_gives_one_stage1() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = live_runner(fake, dir.path(), false);
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert_eq!(c.state, LiveState::Ok { at: t(0) });
            assert_eq!(c.mesh.len(), 1, "{:?}", c.mesh);
            assert_eq!(
                Some(c.mesh[0].1.clone()),
                crate::mesh::stage1_text(checks::NEW_TOWER_IDENTITY)
            );
            assert_eq!(c.events.len(), 1, "{:?}", c.events);
            let v = json(&c.events[0]);
            assert_eq!(v["event_type"], checks::NEW_TOWER_IDENTITY);
            assert_eq!(v["capture"], "100");
            assert_eq!(v["live"], true);
            assert_eq!(c.events[0].0, mqtt::finding_topic(DEVICE_ID));
            assert_eq!(r.live_state(), LiveState::Ok { at: t(0) });
        }

        #[tokio::test]
        async fn second_identical_poll_gives_no_mesh() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = live_runner(fake, dir.path(), false);
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert_eq!(c.mesh.len(), 1);
            r.stage1_sent(&c.mesh, t(5));
            let log = r.store.radio_log(DEVICE_ID, 10).unwrap();
            assert_eq!(log.len(), 1);
            assert_eq!(log[0].kind, "stage1");
            assert_eq!(log[0].alert_id, Some(c.mesh[0].0));
            assert_eq!(log[0].text, c.mesh[0].1);
            let c = r.on_live_tick(t(60)).await.unwrap();
            assert!(c.mesh.is_empty(), "{:?}", c.mesh);
            assert!(c.events.is_empty(), "{:?}", c.events);
        }

        #[tokio::test]
        async fn stage1_retried_until_sent() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = live_runner(fake, dir.path(), false);
            let first = r.on_live_tick(t(0)).await.unwrap().mesh;
            assert_eq!(first.len(), 1);
            // The send failed: nothing was marked, so the next tick offers it again.
            let again = r.on_live_tick(t(60)).await.unwrap().mesh;
            assert_eq!(again, first);
            r.stage1_sent(&again, t(65));
            assert!(r.on_live_tick(t(120)).await.unwrap().mesh.is_empty());
        }

        #[tokio::test]
        async fn three_failures_push_live_unknown_once() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new()); // no live set: Unreachable
            let r = live_runner(fake.clone(), dir.path(), false);
            for n in 0..2 {
                let c = r.on_live_tick(t(n * 60)).await.unwrap();
                assert!(c.events.is_empty(), "failure {n}: {:?}", c.events);
            }
            let c = r.on_live_tick(t(120)).await.unwrap();
            assert_eq!(c.events.len(), 1, "{:?}", c.events);
            let v = json(&c.events[0]);
            assert_eq!(v["event_type"], "live_unknown");
            assert_eq!(v["admin"], true);
            assert_eq!(c.state, LiveState::Unknown { since: t(0) });
            for n in 3..10 {
                assert!(r.on_live_tick(t(n * 60)).await.unwrap().events.is_empty(), "{n}");
            }
            // The 60 min cooldown, as for health alerts.
            let c = r.on_live_tick(t(120 + HEALTH_COOLDOWN_MIN * 60)).await.unwrap();
            assert_eq!(c.events.len(), 1);
            // A success resets the count: two more failures push nothing.
            fake.set_live(Ok(snap(Some("100"))));
            assert_eq!(r.on_live_tick(t(9000)).await.unwrap().state, LiveState::Ok { at: t(9000) });
            fake.set_live(Err(crate::device::DeviceError::Unreachable));
            assert!(r.on_live_tick(t(9060)).await.unwrap().events.is_empty());
            let c = r.on_live_tick(t(9120)).await.unwrap();
            assert!(c.events.is_empty());
            assert_eq!(c.state, LiveState::Ok { at: t(9000) }, "two failures: still the last Ok");
        }

        #[tokio::test]
        async fn not_recording_pushes_admin() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_live(Ok(snap(None)));
            let r = live_runner(fake, dir.path(), false);
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert!(c.events.is_empty(), "one poll is not enough: {:?}", c.events);
            let c = r.on_live_tick(t(30)).await.unwrap();
            assert_eq!(c.state, LiveState::NotRecording);
            assert_eq!(c.events.len(), 1, "{:?}", c.events);
            let v = json(&c.events[0]);
            assert_eq!(v["event_type"], "not_recording");
            assert_eq!(v["admin"], true);
            assert!(r.on_live_tick(t(60)).await.unwrap().events.is_empty(), "cooldown");
        }

        /// M1: a poll landing in rotation's stop/start gap (one poll with no recording)
        /// is not "not recording"; two in a row are.
        #[tokio::test]
        async fn one_poll_in_the_rotation_gap_is_not_not_recording() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_live(Ok(snap(Some("100"))));
            let r = live_runner(fake.clone(), dir.path(), false);
            r.on_live_tick(t(0)).await.unwrap();
            fake.set_live(Ok(snap(None)));
            let c = r.on_live_tick(t(60)).await.unwrap();
            assert!(c.events.is_empty(), "{:?}", c.events);
            assert_eq!(c.state, LiveState::Ok { at: t(0) }, "still the last Ok");
            fake.set_live(Ok(snap(Some("101"))));
            r.on_live_tick(t(120)).await.unwrap();
            fake.set_live(Ok(snap(None)));
            assert!(r.on_live_tick(t(180)).await.unwrap().events.is_empty(), "streak reset");
            let c = r.on_live_tick(t(240)).await.unwrap();
            assert_eq!(c.state, LiveState::NotRecording);
            assert_eq!(c.events.len(), 1, "{:?}", c.events);
            assert_eq!(json(&c.events[0])["event_type"], "not_recording");
        }

        #[tokio::test]
        async fn mobile_gives_nothing_and_learning_holds_tower_checks() {
            for profile in ["mobile", "mixed"] {
                let dir = tempfile::tempdir().unwrap();
                let fake = Arc::new(Fake::new());
                fake.set_profile("100", profile);
                fake.set_live(Ok(identity_snap()));
                fixed_learned(dir.path());
                let r = live_runner(fake.clone(), dir.path(), false);
                let c = r.on_live_tick(t(0)).await.unwrap();
                assert!(c.mesh.is_empty() && c.events.is_empty(), "{profile}: {:?}", c.mesh);
                assert_eq!(c.state, LiveState::Ok { at: t(0) }, "still polled for health");
                assert!(fake.log().iter().any(|l| l == "live"));
                assert!(r.store.open_alert(DEVICE_ID).unwrap().is_none());
            }
            // Fixed but still learning: the tower checks hold.
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            let r = live_runner(fake, dir.path(), false);
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert!(c.mesh.is_empty() && c.events.is_empty(), "{:?}", c.mesh);
            assert!(r.store.open_alert(DEVICE_ID).unwrap().is_none());
        }

        /// Controller ruling: analyser_high (and overflow / flood) still raise while learning.
        #[tokio::test]
        async fn learning_still_raises_analyser_high() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(high_snap()));
            let r = live_runner(fake, dir.path(), false); // no fixed_since: learning
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert_eq!(c.mesh.len(), 1, "{:?}", c.mesh);
            assert_eq!(
                Some(c.mesh[0].1.clone()),
                crate::mesh::stage1_text(checks::ANALYSER_HIGH)
            );
            assert_eq!(c.events.len(), 1);
        }

        #[tokio::test]
        async fn no_token_means_live_off() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_live(Ok(identity_snap()));
            let r = runner(fake.clone(), dir.path()).with_live(None, true, t(0));
            assert_eq!(r.live_state(), LiveState::Off);
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert_eq!(c.state, LiveState::Off);
            assert!(c.mesh.is_empty() && c.events.is_empty());
            assert!(!fake.log().iter().any(|l| l == "live"), "never polled");
            // Never configured at all reads the same.
            let dir = tempfile::tempdir().unwrap();
            assert_eq!(runner(fake, dir.path()).live_state(), LiveState::Off);
        }

        #[tokio::test]
        async fn test_alert_once_then_closed() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(snap(Some("100"))));
            fixed_learned(dir.path());
            let r = live_runner(fake.clone(), dir.path(), true);
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert_eq!(c.mesh.len(), 1, "{:?}", c.mesh);
            assert_eq!(c.mesh[0].1, LIVE_TEST_TEXT);
            assert_eq!(c.events.len(), 1, "the test alert's own push");
            let test_id = c.mesh[0].0;
            let ev = r.store.alert_events(test_id).unwrap();
            assert!(ev[0].detail.starts_with("test "), "{}", ev[0].detail);
            r.stage1_sent(&c.mesh, t(5));
            let log = r.store.radio_log(DEVICE_ID, 10).unwrap();
            assert_eq!(log[0].kind, "test");
            assert_eq!(log[0].alert_id, Some(test_id));
            assert!(r.store.open_alert(DEVICE_ID).unwrap().is_none(), "closed");
            // One-shot: no second test; a real finding opens its own alert.
            fake.set_live(Ok(identity_snap()));
            let c = r.on_live_tick(t(60)).await.unwrap();
            assert_eq!(c.mesh.len(), 1, "{:?}", c.mesh);
            assert_ne!(c.mesh[0].0, test_id);
            assert_eq!(
                Some(c.mesh[0].1.clone()),
                crate::mesh::stage1_text(checks::NEW_TOWER_IDENTITY)
            );
            assert_eq!(c.events.len(), 1);
        }

        #[tokio::test]
        async fn test_alert_pushes_phone_event_once() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(snap(Some("100"))));
            let r = live_runner(fake, dir.path(), true);
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert_eq!(c.events.len(), 1, "{:?}", c.events);
            let v = json(&c.events[0]);
            assert_eq!(v["event_type"], "test_alert");
            assert_eq!(v["admin"], true);
            assert_eq!(v["label"], "Home sentinel TEST alert");
            assert_eq!(c.events[0].0, mqtt::finding_topic(DEVICE_ID));
            // Unsent, then sent: no second push either way.
            assert!(r.on_live_tick(t(60)).await.unwrap().events.is_empty());
            let mesh = r.on_live_tick(t(120)).await.unwrap().mesh;
            r.stage1_sent(&mesh, t(125));
            assert!(r.on_live_tick(t(180)).await.unwrap().events.is_empty());
        }

        /// An unsent test alert never swallows a real finding.
        #[tokio::test]
        async fn a_real_finding_replaces_an_unsent_test_alert() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(snap(Some("100"))));
            fixed_learned(dir.path());
            let r = live_runner(fake.clone(), dir.path(), true);
            let test_id = r.on_live_tick(t(0)).await.unwrap().mesh[0].0;
            fake.set_live(Ok(identity_snap()));
            let c = r.on_live_tick(t(60)).await.unwrap();
            assert_eq!(c.mesh.len(), 1, "{:?}", c.mesh);
            assert_ne!(c.mesh[0].0, test_id);
            assert_eq!(
                Some(c.mesh[0].1.clone()),
                crate::mesh::stage1_text(checks::NEW_TOWER_IDENTITY)
            );
        }

        /// Without the mesh the alert is still opened and the phone paged; nothing to send.
        #[tokio::test]
        async fn mesh_off_still_pages_the_phone() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = runner(fake, dir.path()).with_live(Some("tok".into()), true, t(0));
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert!(c.mesh.is_empty());
            assert_eq!(c.events.len(), 1);
            let ev = r.store.alert_events(r.store.open_alert(DEVICE_ID).unwrap().unwrap().id).unwrap();
            assert!(ev.iter().all(|e| !e.detail.starts_with("test ")), "no test alert without a radio");
        }

        /// Live never learns: towers, held towers and fixed_since are untouched.
        #[tokio::test]
        async fn the_live_tick_writes_no_baseline() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = live_runner(fake, dir.path(), false);
            let before = r.store.baseline("fixed", t(0)).unwrap();
            r.on_live_tick(t(0)).await.unwrap();
            let after = r.store.baseline("fixed", t(0)).unwrap();
            assert_eq!(
                (before.towers, before.held, before.fixed_since),
                (after.towers, after.held, after.fixed_since)
            );
        }

        /// Log lines of this test's thread (tokio tests run on it), to count repeats.
        mod logcap {
            use std::cell::RefCell;
            thread_local! { static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) }; }
            struct Cap;
            impl log::Log for Cap {
                fn enabled(&self, _: &log::Metadata) -> bool {
                    true
                }
                fn log(&self, r: &log::Record) {
                    LINES.with(|l| l.borrow_mut().push(r.args().to_string()));
                }
                fn flush(&self) {}
            }
            static CAP: Cap = Cap;
            pub fn start() {
                let _ = log::set_logger(&CAP);
                log::set_max_level(log::LevelFilter::Trace);
                LINES.with(|l| l.borrow_mut().clear());
            }
            pub fn count(needle: &str) -> usize {
                LINES.with(|l| l.borrow().iter().filter(|s| s.contains(needle)).count())
            }
        }

        /// M3: a radio unplugged for many polls warns once per failure streak.
        #[tokio::test]
        async fn stage1_not_sent_is_logged_once_per_streak() {
            logcap::start();
            let dir = tempfile::tempdir().unwrap();
            let r = live_runner(Arc::new(Fake::new()), dir.path(), false);
            for _ in 0..5 {
                r.live_stage1_result(&Err(anyhow::anyhow!("no radio")), 1);
            }
            assert_eq!(logcap::count("stage 1 not sent"), 1);
            r.live_stage1_result(&Ok(1), 1);
            assert_eq!(logcap::count("stage 1 sent 1 of 1"), 1);
            r.live_stage1_result(&Err(anyhow::anyhow!("no radio")), 1);
            r.live_stage1_result(&Err(anyhow::anyhow!("no radio")), 1);
            assert_eq!(logcap::count("stage 1 not sent"), 2, "a new streak after a success");
        }

        /// M3: "TEST alert waits" once per open alert, not every tick.
        #[tokio::test]
        async fn test_alert_waits_logged_once_per_open_alert() {
            logcap::start();
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = live_runner(fake.clone(), dir.path(), true);
            let first = r.on_live_tick(t(0)).await.unwrap();
            assert_eq!(first.mesh.len(), 1, "the real alert, no TEST yet");
            for n in 1..5 {
                r.on_live_tick(t(n * 60)).await.unwrap();
            }
            assert_eq!(logcap::count("TEST alert waits"), 1);
            // Another alert opens after that one closes: one more line.
            let a = r.store.open_alert(DEVICE_ID).unwrap().unwrap().id;
            r.store.close_alert(a, crate::store::CloseBy::FalseAlarm, t(300)).unwrap();
            let f = crate::live::LiveFinding {
                check: checks::ANALYSER_HIGH,
                detail: "x: 1 high warning(s); first: y".into(),
                towers: vec![],
                subject: "x".into(),
            };
            r.store.ingest(DEVICE_ID, &f, crate::store::Source::Live, Some("100"), t(300)).unwrap();
            r.on_live_tick(t(360)).await.unwrap();
            r.on_live_tick(t(420)).await.unwrap();
            assert_eq!(logcap::count("TEST alert waits"), 2);
        }

        /// M6: an ingest error does not lose the finding for the recording.
        #[tokio::test]
        async fn ingest_error_then_retry_next_poll() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = live_runner(fake, dir.path(), false);
            let db = rusqlite::Connection::open(dir.path().join("i.sqlite")).unwrap();
            db.execute_batch("ALTER TABLE alert_events RENAME TO gone").unwrap();
            let c = r.on_live_tick(t(0)).await.unwrap();
            assert!(c.mesh.is_empty() && c.events.is_empty(), "{:?}", c.mesh);
            db.execute_batch("ALTER TABLE gone RENAME TO alert_events").unwrap();
            let c = r.on_live_tick(t(60)).await.unwrap();
            assert_eq!(c.mesh.len(), 1, "retried: {:?}", c.mesh);
            assert_eq!(c.events.len(), 1);
            assert!(r.store.open_alert(DEVICE_ID).unwrap().is_some());
        }

        #[tokio::test]
        async fn live_mesh_send_marks_only_what_went_out() {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(Fake::new());
            fake.set_profile("100", "fixed");
            fake.set_live(Ok(identity_snap()));
            fixed_learned(dir.path());
            let r = live_runner(fake, dir.path(), false);
            let batch = r.on_live_tick(t(0)).await.unwrap().mesh;
            r.live_mesh_sent(&Err(anyhow::anyhow!("radio gone")), &batch, t(5));
            assert_eq!(r.stage1_still_pending(batch.clone(), t(6)), batch);
            r.live_mesh_sent(&Ok(1), &batch, t(10));
            assert!(r.stage1_still_pending(batch, t(11)).is_empty());
            assert_eq!(r.store.mesh_stats(t(12)).unwrap().0, 1, "counted in the mesh sensors");
        }
    }

    mod follow_up {
        use super::*;
        use crate::followup::Kind;

        fn fu_runner(dir: &Path) -> Runner {
            runner(Arc::new(Fake::new()), dir)
                .with_mesh(mesh_cfg(crate::mesh::Level::Strong, 0), t(0), &mut || 0)
        }
        fn open(r: &Runner, now: DateTime<Utc>) -> i64 {
            live_alert(
                r,
                crate::checks::NEW_TOWER_IDENTITY,
                "identity request after: 310-260-1-2",
                "rec",
                now,
            )
        }
        fn req(alert_id: i64, kind: Kind, text: &str, ov: bool) -> FollowUp {
            FollowUp { alert_id, kind, text: text.into(), override_gate: ov }
        }
        fn kinds(r: &Runner) -> Vec<String> {
            r.store.radio_log(DEVICE_ID, 50).unwrap().into_iter().map(|e| e.kind).collect()
        }
        fn rows(dir: &Path) -> (i64, i64) {
            let c = rusqlite::Connection::open(dir.join("i.sqlite")).unwrap();
            let n = |tb: &str| c.query_row(&format!("SELECT count(*) FROM {tb}"), [], |r| r.get(0)).unwrap();
            (n("towers"), n("held_towers"))
        }
        fn closed_test(r: &Runner, opened: i64, closed: i64) -> i64 {
            let id = open(r, t(opened));
            r.store.close_alert(id, crate::store::CloseBy::Test, t(closed)).unwrap();
            id
        }

        // The page handler, driven with a fake radio. `n` seconds after t(0).
        async fn drive(
            r: &Runner,
            meshing: &Arc<std::sync::atomic::AtomicBool>,
            cmds: Vec<crate::page::PageCmd>,
            sent: &std::cell::RefCell<Vec<String>>,
            fail: bool,
        ) {
            let (tx, rx) = crate::page::channel();
            for c in cmds {
                tx.send(c).await.unwrap();
            }
            drop(tx);
            let wait = (std::time::Duration::from_millis(20), std::time::Duration::from_millis(5));
            crate::page::serve(rx, r, meshing, wait, || t(100), |text| {
                sent.borrow_mut().push(text);
                async move { if fail { anyhow::bail!("radio gone") } else { Ok(1) } }
            })
            .await;
        }

        #[tokio::test]
        async fn page_state_command_returns_the_runner_page() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            open(&r, t(0));
            let (tx, rx) = tokio::sync::oneshot::channel();
            let sent = Default::default();
            drive(&r, &Default::default(), vec![crate::page::PageCmd::State(tx)], &sent, false).await;
            assert_eq!(rx.await.unwrap(), r.page(t(100)));
            assert!(sent.borrow().is_empty());
        }

        #[tokio::test]
        async fn page_follow_up_sends_once_logs_once_and_replies_text() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let q = req(id, Kind::Watching, " Update: looking into it. ", false);
            let (tx, rx) = tokio::sync::oneshot::channel();
            let (tx2, rx2) = tokio::sync::oneshot::channel();
            let sent = Default::default();
            let meshing: Arc<std::sync::atomic::AtomicBool> = Default::default();
            // The same text twice, queued back to back: serial handling makes the
            // second see the first's log row.
            let cmds = vec![crate::page::PageCmd::FollowUp(q.clone(), tx), crate::page::PageCmd::FollowUp(q, tx2)];
            drive(&r, &meshing, cmds, &sent, false).await;
            assert_eq!(rx.await.unwrap(), Ok("Update: looking into it.".to_string()));
            assert_eq!(rx2.await.unwrap(), Err(Refusal::Duplicate));
            assert_eq!(*sent.borrow(), vec!["Update: looking into it.".to_string()]);
            assert_eq!(kinds(&r), vec!["watching".to_string()]);
            assert!(!meshing.load(std::sync::atomic::Ordering::Relaxed), "radio released");
        }

        fn radio(r: &Runner) -> Vec<crate::mesh::RadioEvent> {
            r.take_radio_events()
        }

        #[tokio::test]
        async fn follow_ups_go_in_the_transmission_log_without_their_text() {
            use crate::mesh::Outcome;
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let meshing: Arc<std::sync::atomic::AtomicBool> = Default::default();
            let sent = Default::default();
            // Sent.
            let (tx, rx) = tokio::sync::oneshot::channel();
            let q = req(id, Kind::Watching, "Update: looking into it.", false);
            drive(&r, &meshing, vec![crate::page::PageCmd::FollowUp(q, tx)], &sent, false).await;
            assert!(rx.await.unwrap().is_ok());
            // Failed on the radio.
            let (tx, rx) = tokio::sync::oneshot::channel();
            let q = req(id, Kind::PhonesOff, "Update: phones off for now.", false);
            drive(&r, &meshing, vec![crate::page::PageCmd::FollowUp(q, tx)], &sent, true).await;
            assert!(rx.await.unwrap().is_err());
            // All clear before the gate, by override.
            let (tx, rx) = tokio::sync::oneshot::channel();
            let q = req(id, Kind::AllClear, "Update: all clear.", true);
            drive(&r, &meshing, vec![crate::page::PageCmd::FollowUp(q, tx)], &sent, false).await;
            assert!(rx.await.unwrap().is_ok());
            let ev = radio(&r);
            let got: Vec<_> = ev.iter().map(|e| (e.kind, e.outcome, e.reason)).collect();
            assert_eq!(
                got,
                vec![
                    ("watching", Outcome::Sent, None),
                    ("phones_off", Outcome::Failed, Some("error")),
                    ("all_clear", Outcome::Sent, Some("override")),
                ]
            );
            assert!(ev.iter().all(|e| e.alert_id == Some(id) && e.bell));
            assert_eq!(ev[0].hash, crate::mesh::text_hash("Update: looking into it."));
            assert_eq!(r.store.radio_event_rows().len(), 3, "and in the database");
        }

        #[tokio::test]
        async fn page_follow_up_send_failure_logs_nothing() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let q = req(id, Kind::FalseAlarm, "Update: false alarm. Carry on as normal.", false);
            let (tx, rx) = tokio::sync::oneshot::channel();
            let sent = Default::default();
            let meshing: Arc<std::sync::atomic::AtomicBool> = Default::default();
            drive(&r, &meshing, vec![crate::page::PageCmd::FollowUp(q, tx)], &sent, true).await;
            assert!(matches!(rx.await.unwrap(), Err(Refusal::SendFailed(m)) if m.contains("radio gone")));
            assert!(kinds(&r).is_empty());
            assert!(r.store.open_alert(DEVICE_ID).unwrap().is_some(), "alert still open");
            assert!(!meshing.load(std::sync::atomic::Ordering::Relaxed));
        }

        #[tokio::test]
        async fn page_follow_up_with_a_busy_radio_is_refused_unsent() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let q = req(id, Kind::Watching, "Update: looking into it.", false);
            let (tx, rx) = tokio::sync::oneshot::channel();
            let sent = Default::default();
            let meshing = Arc::new(std::sync::atomic::AtomicBool::new(true));
            drive(&r, &meshing, vec![crate::page::PageCmd::FollowUp(q, tx)], &sent, false).await;
            assert_eq!(rx.await.unwrap(), Err(Refusal::RadioBusy));
            assert!(sent.borrow().is_empty() && kinds(&r).is_empty());
            assert!(meshing.load(std::sync::atomic::Ordering::Relaxed), "the other stage keeps it");
        }

        #[tokio::test]
        async fn page_follow_up_rechecks_after_waiting_for_the_radio() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let q = req(id, Kind::Watching, "Update: looking into it.", false);
            let (tx, rx) = tokio::sync::oneshot::channel();
            let sent: std::cell::RefCell<Vec<String>> = Default::default();
            let meshing = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let (ctx, crx) = crate::page::channel();
            ctx.send(crate::page::PageCmd::FollowUp(q, tx)).await.unwrap();
            drop(ctx);
            let wait = (std::time::Duration::from_millis(500), std::time::Duration::from_millis(5));
            let serve = crate::page::serve(crx, &r, &meshing, wait, || t(100), |text| {
                sent.borrow_mut().push(text);
                async { Ok(1) }
            });
            let closer = async {
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                r.store.close_alert(id, crate::store::CloseBy::Expired, t(50)).unwrap();
                meshing.store(false, std::sync::atomic::Ordering::Relaxed);
            };
            tokio::join!(serve, closer);
            assert_eq!(rx.await.unwrap(), Err(Refusal::AlertClosed));
            assert!(sent.borrow().is_empty(), "nothing on air");
            assert!(kinds(&r).is_empty());
            assert!(!meshing.load(std::sync::atomic::Ordering::Relaxed), "radio released");
        }

        #[test]
        fn follow_up_for_a_closed_alert_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            r.store.close_alert(id, crate::store::CloseBy::Expired, t(10)).unwrap();
            let q = req(id, Kind::Watching, "Update: looking into it.", false);
            assert_eq!(r.follow_up_prepare(&q, t(20)), Err(Refusal::AlertClosed));
            // A newer alert is open: the old id is still refused.
            let newer = open(&r, t(3 * 3600 * 10));
            assert_ne!(newer, id);
            assert_eq!(r.follow_up_prepare(&q, t(3 * 3600 * 10 + 5)), Err(Refusal::AlertClosed));
            // Nothing open at all.
            let r2 = fu_runner(tempfile::tempdir().unwrap().path());
            assert_eq!(r2.follow_up_prepare(&q, t(0)), Err(Refusal::AlertClosed));
        }

        #[test]
        fn follow_up_on_a_recent_test_alert_is_allowed() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = closed_test(&r, 0, 60);
            let q = req(id, Kind::Watching, " Update: looking into it. ", false);
            let now = t(60 + 600);
            let p = r.follow_up_prepare(&q, now).unwrap();
            assert_eq!(p.text(), "TEST: Update: looking into it.", "trimmed, marked TEST");
            r.follow_up_sent(&p, now);
            let log = r.store.radio_log(DEVICE_ID, 10).unwrap();
            assert_eq!(log[0].kind, "watching");
            assert_eq!(log[0].text, "TEST: Update: looking into it.");
            assert_eq!(log[0].alert_id, Some(id));
            // 31 minutes after the close: gone.
            assert_eq!(r.follow_up_prepare(&q, t(60 + 31 * 60)), Err(Refusal::AlertClosed));
        }

        /// Final review I3: a practice target has the real gate and override logging, so
        /// both can be rehearsed on hardware; a follow-up still never closes it again.
        #[test]
        fn practice_all_clear_needs_the_gate_or_override() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = closed_test(&r, 0, 60);
            r.live_state.set(LiveState::Ok { at: t(700) });
            r.live_fixed.set(true);
            let now = t(60 + 700);
            let q = req(id, Kind::AllClear, "All clear: no sign of it. Phones back to normal.", false);
            match r.follow_up_prepare(&q, now) {
                Err(Refusal::Locked { unlocks_at }) => assert!(unlocks_at.is_some_and(|u| u > now)),
                other => panic!("{other:?}"),
            }
            assert!(kinds(&r).is_empty());
            let q = req(id, Kind::AllClear, "All clear: no sign of it. Phones back to normal.", true);
            let p = r.follow_up_prepare(&q, now).unwrap();
            r.follow_up_sent(&p, now);
            assert_eq!(kinds(&r), vec!["all_clear".to_string(), "all_clear_override".to_string()]);
            let a = r.store.last_alert(DEVICE_ID).unwrap().unwrap();
            assert_eq!(a.id, id);
            assert_eq!(a.closed_by.as_deref(), Some("test"), "not re-closed");
            assert_eq!(a.closed_at, Some(t(60)));
        }

        /// Final review I4: practice follow-ups go on air marked TEST; the checks and the
        /// duplicate guard see the final text.
        #[test]
        fn practice_follow_ups_are_marked_test() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = closed_test(&r, 0, 60);
            let now = t(120);
            let phones = Kind::PhonesOff.preset(&r.store.last_alert(DEVICE_ID).unwrap().unwrap(), now);
            let p = r.follow_up_prepare(&req(id, Kind::PhonesOff, &phones, false), now).unwrap();
            assert!(p.text().starts_with("TEST: "), "{}", p.text());
            assert_eq!(p.text(), format!("TEST: {phones}"));
            // Already marked (any case): not marked twice.
            let p = r.follow_up_prepare(&req(id, Kind::Watching, " test: x ", false), now).unwrap();
            assert_eq!(p.text(), "test: x");
            // 197 bytes + "TEST: " is over the radio limit.
            let long = "a".repeat(197);
            assert!(matches!(
                r.follow_up_prepare(&req(id, Kind::Watching, &long, false), now),
                Err(Refusal::Privacy(m)) if m.contains("203")
            ));
            // An empty box stays empty: the marker does not make it sendable.
            assert!(matches!(
                r.follow_up_prepare(&req(id, Kind::Watching, "   ", false), now),
                Err(Refusal::Privacy(m)) if m.contains("empty")
            ));
            // The privacy check sees the marked text too.
            assert!(matches!(
                r.follow_up_prepare(&req(id, Kind::Watching, "PCI 12", false), now),
                Err(Refusal::Privacy(_))
            ));
            // The duplicate guard compares what went on air.
            let p = r.follow_up_prepare(&req(id, Kind::Watching, "Update: x", false), now).unwrap();
            r.follow_up_sent(&p, now);
            assert_eq!(
                r.follow_up_prepare(&req(id, Kind::Watching, "TEST: Update: x", false), t(130)),
                Err(Refusal::Duplicate)
            );
        }

        #[test]
        fn follow_up_needs_a_radio() {
            let dir = tempfile::tempdir().unwrap();
            let r = runner(Arc::new(Fake::new()), dir.path());
            let id = open(&r, t(0));
            let q = req(id, Kind::Watching, "Update: looking into it.", false);
            assert_eq!(r.follow_up_prepare(&q, t(5)), Err(Refusal::NoRadio));
        }

        #[test]
        fn follow_up_blocked_text_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let q = req(id, Kind::Watching, "PCI 12", false);
            assert!(matches!(r.follow_up_prepare(&q, t(5)), Err(Refusal::Privacy(_))));
            assert!(r.store.radio_log(DEVICE_ID, 10).unwrap().is_empty());
        }

        #[test]
        fn all_clear_needs_the_gate_or_override() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let now = t(600);
            r.live_state.set(LiveState::Ok { at: now });
            r.live_fixed.set(true);
            let q = req(id, Kind::AllClear, "All clear: nothing since.", false);
            match r.follow_up_prepare(&q, now) {
                Err(Refusal::Locked { unlocks_at }) => {
                    assert!(unlocks_at.is_some_and(|u| u > now))
                }
                other => panic!("{other:?}"),
            }
            assert!(r.store.radio_log(DEVICE_ID, 10).unwrap().is_empty());
            let q = req(id, Kind::AllClear, "All clear: nothing since.", true);
            let p = r.follow_up_prepare(&q, now).unwrap();
            r.follow_up_sent(&p, now);
            let k = kinds(&r);
            assert!(k.contains(&"all_clear_override".to_string()), "{k:?}");
            assert!(k.contains(&"all_clear".to_string()), "{k:?}");
            assert_eq!(r.store.last_alert(DEVICE_ID).unwrap().unwrap().closed_by.as_deref(), Some("all_clear"));
        }

        #[test]
        fn all_clear_with_an_unknown_live_view_is_locked_without_a_time() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let now = t(10 * 3600);
            r.live_state.set(LiveState::Unknown { since: t(0) });
            let q = req(id, Kind::AllClear, "All clear: nothing since.", false);
            assert_eq!(
                r.follow_up_prepare(&q, now),
                Err(Refusal::Locked { unlocks_at: None })
            );
        }

        #[test]
        fn follow_up_twice_sends_once() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let q = req(id, Kind::Watching, "Update: looking into it.", false);
            let text = r.follow_up_prepare(&q, t(100)).unwrap();
            r.follow_up_sent(&text, t(100));
            assert_eq!(r.follow_up_prepare(&q, t(130)), Err(Refusal::Duplicate));
            assert_eq!(r.follow_up_prepare(&q, t(159)), Err(Refusal::Duplicate));
            assert!(r.follow_up_prepare(&q, t(161)).is_ok(), "61 s on");
            // Different text is not a duplicate.
            let other = req(id, Kind::Watching, "Update: still looking.", false);
            assert!(r.follow_up_prepare(&other, t(130)).is_ok());
        }

        #[test]
        fn false_alarm_closes_and_learns_nothing() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            let before = rows(dir.path());
            let q = req(id, Kind::FalseAlarm, "Update: false alarm. Carry on as normal.", false);
            let text = r.follow_up_prepare(&q, t(50)).unwrap();
            r.follow_up_sent(&text, t(50));
            let a = r.store.last_alert(DEVICE_ID).unwrap().unwrap();
            assert_eq!(a.closed_by.as_deref(), Some("false_alarm"));
            assert_eq!(kinds(&r), vec!["false_alarm".to_string()]);
            assert_eq!(rows(dir.path()), before);
        }

        #[test]
        fn watching_leaves_it_open() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            for k in [Kind::Watching, Kind::PhonesOff] {
                let q = req(id, k, &format!("Update: {k:?}."), false);
                let text = r.follow_up_prepare(&q, t(50)).unwrap();
                r.follow_up_sent(&text, t(50));
            }
            assert_eq!(r.store.open_alert(DEVICE_ID).unwrap().map(|a| a.id), Some(id));
            assert_eq!(kinds(&r), vec!["phones_off".to_string(), "watching".to_string()]);
        }

        #[test]
        fn override_decision_is_prepares() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            // Locked at prepare, override asked; by send time the gate would be open.
            r.live_state.set(LiveState::Ok { at: t(600) });
            r.live_fixed.set(true);
            let q = req(id, Kind::AllClear, "All clear: nothing since.", true);
            let p = r.follow_up_prepare(&q, t(600)).unwrap();
            r.live_state.set(LiveState::Ok { at: t(5 * 3600) });
            r.follow_up_sent(&p, t(5 * 3600));
            assert!(kinds(&r).contains(&"all_clear_override".to_string()), "{:?}", kinds(&r));
        }

        #[test]
        fn no_override_row_when_prepare_found_it_unlocked() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = open(&r, t(0));
            r.live_state.set(LiveState::Ok { at: t(4 * 3600) });
            r.live_fixed.set(true);
            let q = req(id, Kind::AllClear, "All clear: nothing since.", true);
            let p = r.follow_up_prepare(&q, t(4 * 3600)).unwrap();
            r.live_state.set(LiveState::Unknown { since: t(4 * 3600) });
            r.follow_up_sent(&p, t(4 * 3600 + 20));
            assert_eq!(kinds(&r), vec!["all_clear".to_string()]);
        }

        #[test]
        fn page_shows_the_target_alert() {
            let dir = tempfile::tempdir().unwrap();
            let r = fu_runner(dir.path());
            let id = closed_test(&r, 0, 60);
            let v = r.page(t(120));
            assert_eq!(v["alert_id"], id);
            assert_eq!(v["status"]["test"], true);
            assert_eq!(v["mesh_on"], true);
        }
    }

    mod summary_wiring {
        use super::*;
        use crate::claude::{ApiError, Reply};
        use crate::page::PageCmd;

        const MODEL: &str = "claude-opus-5-5";

        fn sr(dir: &Path, key: Option<&str>) -> Runner {
            runner(Arc::new(Fake::new()), dir).with_summary(key.map(String::from), MODEL.into())
        }
        fn open_a(r: &Runner, tower: &str, rec: &str, now: DateTime<Utc>) -> i64 {
            live_alert(
                r,
                crate::checks::NEW_TOWER_IDENTITY,
                &format!("identity request after: {tower}"),
                rec,
                now,
            )
        }
        fn ok(i: u64, o: u64) -> Result<Reply, ApiError> {
            Ok(Reply::Text { text: "Looks odd.".into(), cut_short: false, input_tokens: i, output_tokens: o })
        }
        fn events(r: &Runner, id: i64) -> usize {
            r.store.alert_events(id).unwrap().len()
        }
        fn log_rows(dir: &Path) -> Vec<(i64, i64, String)> {
            let c = rusqlite::Connection::open(dir.join("i.sqlite")).unwrap();
            let mut st = c
                .prepare("SELECT input_tokens, output_tokens, outcome FROM summary_log ORDER BY id")
                .unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        }

        #[test]
        fn summary_off_without_key() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), None);
            let id = open_a(&r, "310-260-1-2", "rec", t(0));
            assert_eq!(r.page(t(10))["summary"]["enabled"], false);
            assert_eq!(r.summary_prepare(id, t(10)).unwrap_err(), "Summary is off.");
            let on = sr(dir.path(), Some("sk-test"));
            assert_eq!(on.page(t(10))["summary"]["enabled"], true);
            assert!(on.page(t(10)).to_string().find("sk-test").is_none());
        }

        #[test]
        fn only_the_page_target_is_accepted() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), Some("k"));
            let id = open_a(&r, "310-260-1-2", "rec", t(0));
            assert_eq!(r.summary_prepare(id + 99, t(10)).unwrap_err(), "That alert is no longer active.");
            r.store.close_alert(id, crate::store::CloseBy::FalseAlarm, t(20)).unwrap();
            assert_eq!(r.summary_prepare(id, t(30)).unwrap_err(), "That alert is no longer active.");
        }

        #[test]
        fn second_tap_inside_the_gap_is_refused_or_cached() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), Some("k"));
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            let n = events(&r, a);
            assert!(matches!(r.summary_prepare(a, t(10)), Ok(SummaryStep::Call { .. })));
            // Two tabs: a second tap while the first call is still out.
            assert!(r.summary_prepare(a, t(11)).is_err());
            let _ = r.summary_done(a, n, &ok(10, 5), t(12));
            match r.summary_prepare(a, t(20)) {
                Ok(SummaryStep::Cached(s)) => assert_eq!(s, "Looks odd."),
                _ => panic!("expected the cache"),
            }
            r.store.close_alert(a, crate::store::CloseBy::FalseAlarm, t(25)).unwrap();
            let b = open_a(&r, "310-260-7-7", "rec2", t(30));
            assert_ne!(a, b);
            let want = format!(
                "One summary per 5 minutes; try again at {}",
                t(12 + 300).with_timezone(&chrono::Local).format("%H:%M")
            );
            assert_eq!(r.summary_prepare(b, t(60)).unwrap_err(), want);
            assert!(matches!(r.summary_prepare(b, t(12 + 300)), Ok(SummaryStep::Call { .. })));
        }

        #[test]
        fn a_failed_log_write_does_not_lift_the_gap() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), Some("k"));
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            let n = events(&r, a);
            r.summary_prepare(a, t(10)).unwrap();
            {
                let c = rusqlite::Connection::open(dir.path().join("i.sqlite")).unwrap();
                c.execute_batch(
                    "CREATE TRIGGER nolog BEFORE INSERT ON summary_log BEGIN SELECT RAISE(ABORT, 'no'); END;",
                )
                .unwrap();
            }
            let _ = r.summary_done(a, n, &ok(10, 5), t(12));
            assert!(log_rows(dir.path()).is_empty(), "the write really failed");
            r.store.close_alert(a, crate::store::CloseBy::FalseAlarm, t(25)).unwrap();
            let b = open_a(&r, "310-260-7-7", "rec2", t(30));
            let err = r.summary_prepare(b, t(60)).unwrap_err();
            assert!(err.starts_with("One summary per 5 minutes"), "{err}");
            assert!(matches!(r.summary_prepare(b, t(12 + 300)), Ok(SummaryStep::Call { .. })));
        }

        #[test]
        fn the_sent_list_survives_many_unrelated_radio_rows() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), Some("k"));
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            r.store.log_radio(DEVICE_ID, "stage1", "x", Some(a), t(5)).unwrap();
            for i in 0..60 {
                r.store.log_radio(DEVICE_ID, "test", "noise", None, t(6 + i)).unwrap();
            }
            let Ok(SummaryStep::Call { body, .. }) = r.summary_prepare(a, t(1000)) else {
                panic!("expected a call")
            };
            let rec: serde_json::Value =
                serde_json::from_str(body["messages"][0]["content"].as_str().unwrap()).unwrap();
            assert!(!rec["sent"].as_array().unwrap().is_empty(), "{rec}");
        }

        #[test]
        fn a_new_event_invalidates_the_cache() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), Some("k"));
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            let n = events(&r, a);
            assert!(matches!(r.summary_prepare(a, t(10)), Ok(SummaryStep::Call { .. })));
            let _ = r.summary_done(a, n, &ok(10, 5), t(10));
            let b = live_alert(&r, crate::checks::ANALYSER_HIGH, "analyser warning", "rec", t(60));
            assert_eq!(a, b, "joined the open alert");
            assert!(events(&r, a) > n);
            assert!(matches!(r.summary_prepare(a, t(10 + 301)), Ok(SummaryStep::Call { .. })));
        }

        #[test]
        fn usage_is_logged() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), Some("k"));
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            let n = events(&r, a);
            r.summary_prepare(a, t(10)).unwrap();
            let _ = r.summary_done(a, n, &ok(900, 150), t(10));
            let s = &r.page(t(11))["summary"];
            assert_eq!((s["tokens_in"].as_u64(), s["tokens_out"].as_u64()), (Some(900), Some(150)));
            assert!(matches!(r.summary_prepare(a, t(10 + 400)), Ok(SummaryStep::Cached(_)))); // no call
            r.store.close_alert(a, crate::store::CloseBy::FalseAlarm, t(420)).unwrap();
            let b = open_a(&r, "310-260-7-7", "rec2", t(430));
            let nb = events(&r, b);
            r.summary_prepare(b, t(500)).unwrap();
            let _ = r.summary_done(b, nb, &Err(ApiError::NoCredit), t(500));
            let rows = log_rows(dir.path());
            assert_eq!(rows[0], (900, 150, "ok".to_string()));
            assert_eq!(rows[1], (0, 0, "no_credit".to_string()));
            let s = &r.page(t(501))["summary"];
            assert_eq!((s["tokens_in"].as_u64(), s["tokens_out"].as_u64()), (Some(900), Some(150)));
            // An error is not cached: the same alert asks again after the gap.
            assert!(matches!(r.summary_prepare(b, t(500 + 301)), Ok(SummaryStep::Call { .. })));
        }

        #[test]
        fn a_refusal_and_a_cut_reply_are_worded() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), Some("k"));
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            let n = events(&r, a);
            r.summary_prepare(a, t(10)).unwrap();
            let cut = Ok(Reply::Text { text: "Half".into(), cut_short: true, input_tokens: 1, output_tokens: 2 });
            assert_eq!(r.summary_done(a, n, &cut, t(10)).unwrap(), "Half (cut short)");
            let refused = Ok(Reply::Refused { input_tokens: 1, output_tokens: 2 });
            assert_eq!(
                r.summary_done(a, n, &refused, t(10 + 301)).unwrap(),
                "The model declined to summarise this alert."
            );
        }

        /// A server that takes `delay` to answer a Messages call.
        async fn slow_api(delay: std::time::Duration) -> String {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move {
                loop {
                    let Ok((mut c, _)) = l.accept().await else { return };
                    tokio::spawn(async move {
                        let mut got = Vec::new();
                        let mut buf = vec![0u8; 16384];
                        loop {
                            let n = c.read(&mut buf).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            got.extend_from_slice(&buf[..n]);
                            let s = String::from_utf8_lossy(&got).to_string();
                            if s.contains("\r\n\r\n") && s.trim_end().ends_with('}') {
                                break;
                            }
                        }
                        tokio::time::sleep(delay).await;
                        let body = r#"{"content":[{"type":"text","text":"Slow but fine."}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}"#;
                        let r = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = c.write_all(r.as_bytes()).await;
                        let _ = c.shutdown().await;
                    });
                }
            });
            url
        }

        #[tokio::test]
        async fn slow_api_does_not_block_the_cycle_thread() {
            let dir = tempfile::tempdir().unwrap();
            let url = slow_api(std::time::Duration::from_secs(2)).await;
            let r = sr(dir.path(), Some("sk-test")).with_summary_base_url(&url);
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            let (tx, rx) = crate::page::channel();
            let meshing: Arc<std::sync::atomic::AtomicBool> = Default::default();
            let wait = (std::time::Duration::from_millis(20), std::time::Duration::from_millis(5));
            let serve = crate::page::serve(rx, &r, &meshing, wait, || t(100), |_| async { Ok(1) });
            let driver = async {
                let (sum_tx, sum_rx) = tokio::sync::oneshot::channel();
                let (st_tx, st_rx) = tokio::sync::oneshot::channel();
                tx.send(PageCmd::Summary(a, sum_tx)).await.unwrap();
                tx.send(PageCmd::State(st_tx)).await.unwrap();
                let start = std::time::Instant::now();
                st_rx.await.unwrap();
                let state_took = start.elapsed();
                let text = sum_rx.await.unwrap();
                let total = start.elapsed();
                drop(tx);
                (state_took, text, total)
            };
            let ((state_took, text, total), ()) = tokio::join!(driver, serve);
            assert!(state_took < std::time::Duration::from_millis(500), "{state_took:?}");
            assert_eq!(text.unwrap(), "Slow but fine.");
            assert!(total >= std::time::Duration::from_secs(2), "the call really was slow");
            assert_eq!(log_rows(dir.path()), vec![(7, 3, "ok".to_string())]);
        }

        #[tokio::test]
        async fn summary_command_without_a_key_makes_no_call() {
            let dir = tempfile::tempdir().unwrap();
            let r = sr(dir.path(), None);
            let a = open_a(&r, "310-260-1-2", "rec", t(0));
            let (tx, rx) = crate::page::channel();
            let (rtx, rrx) = tokio::sync::oneshot::channel();
            tx.send(PageCmd::Summary(a, rtx)).await.unwrap();
            drop(tx);
            let meshing: Arc<std::sync::atomic::AtomicBool> = Default::default();
            let wait = (std::time::Duration::from_millis(20), std::time::Duration::from_millis(5));
            crate::page::serve(rx, &r, &meshing, wait, || t(100), |_| async { Ok(1) }).await;
            assert_eq!(rrx.await.unwrap().unwrap_err(), "Summary is off.");
            assert!(log_rows(dir.path()).is_empty());
        }

        #[test]
        fn options_summary_key_and_model() {
            let o = parse_options(r#"{"device_url":"u"}"#).unwrap();
            assert_eq!((o.summary_api_key.is_none(), o.summary_model.as_str()), (true, MODEL));
            let o = parse_options(r#"{"device_url":"u","summary_api_key":"  ","summary_model":""}"#).unwrap();
            assert_eq!((o.summary_api_key.is_none(), o.summary_model.as_str()), (true, MODEL));
            let o = parse_options(r#"{"device_url":"u","summary_api_key":" sk-x ","summary_model":"m"}"#).unwrap();
            assert_eq!(o.summary_api_key.as_ref().map(|k| k.expose()), Some("sk-x"));
            assert_eq!(o.summary_model, "m");
            assert!(!format!("{o:?}").contains("sk-x"), "Debug must not show the key");
        }

        #[test]
        fn config_yaml_has_summary_options() {
            let y: serde_yaml::Value = serde_yaml::from_str(include_str!("../addon/config.yaml")).unwrap();
            assert_eq!(y["schema"]["summary_api_key"].as_str(), Some("password?"));
            assert_eq!(y["schema"]["summary_model"].as_str(), Some("str?"));
            assert!(y["options"].get("summary_api_key").is_none(), "no default key");
            assert_eq!(y["version"].as_str(), Some("0.8.4"));
        }
    }
}
