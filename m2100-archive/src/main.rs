mod app;
mod checks;
mod claude;
mod cribl;
mod decoder;
mod device;
mod events;
mod followup;
mod health;
mod live;
mod mesh;
mod mqtt;
mod page;
mod privacy;
mod proxy;
mod pruner;
mod puller;
mod rotation;
mod sandbox;
mod store;
mod summary;
mod web;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, Transport};
use tokio::sync::mpsc;

/// One radio session on a blocking thread, so a slow or missing radio never stalls the
/// runtime. Returns how many texts went out.
async fn mesh_send(cfg: &mesh::Config, texts: &[String]) -> anyhow::Result<usize> {
    let (port, texts) = (cfg.port.clone(), texts.to_vec());
    tokio::task::spawn_blocking(move || {
        let mut link = mesh::link::open(&port)?;
        mesh::link::send_texts(&mut link, &texts, &mut mesh::random_u32)
    })
    .await?
}

/// Clears an in-flight flag when a stage ends, even on a panic.
struct Done(Arc<AtomicBool>);

impl Drop for Done {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

use app::{DEVICE_ID, MqttCreds};
use device::{Device, Http};

/// Compiled-module cache for the sandbox: outside the archive (it is not backed up or pruned).
const CWASM_CACHE: &str = "/data/cwasm-cache";

/// Load the decoder guest. Any problem is logged once and means "no decoding"; the
/// archiving above it carries on regardless.
fn load_decoder() -> Option<Arc<dyn sandbox::Decoder>> {
    if sandbox::GUEST_SHA256.is_empty() {
        log::error!("decoding is off: this build has no decoder guest");
        return None;
    }
    let bytes = match std::fs::read(sandbox::GUEST_PATH) {
        Ok(b) => b,
        Err(e) => {
            log::error!("decoding is off: cannot read {}: {e}", sandbox::GUEST_PATH);
            return None;
        }
    };
    match sandbox::Sandbox::new(&bytes, sandbox::GUEST_SHA256, std::path::Path::new(CWASM_CACHE)) {
        Ok(s) => {
            log::info!("decoder ready (guest {})", sandbox::GUEST_SHA256);
            Some(Arc::new(s))
        }
        Err(e) => {
            log::error!("decoding is off: {e:#}");
            None
        }
    }
}

const STATUS_TOPIC: &str = "homeassistant/status";

async fn supervisor_mqtt() -> anyhow::Result<MqttCreds> {
    let token = std::env::var("SUPERVISOR_TOKEN")?;
    let body = reqwest::Client::new()
        .get("http://supervisor/services/mqtt")
        .bearer_auth(token)
        .timeout(Duration::from_secs(30))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    app::parse_mqtt_service(&body)
}

async fn publish_all(client: &AsyncClient, msgs: Vec<(String, String)>, retain: bool) {
    for (topic, payload) in msgs {
        if let Err(e) = client.publish(topic, QoS::AtLeastOnce, retain, payload).await {
            log::warn!("publish failed: {e}");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    app::install_crypto_provider();
    let opts = app::parse_options(&std::fs::read_to_string(app::OPTIONS_PATH)?)?;
    // The optional Cribl output: off when its options are blank or wrong (parse_options
    // warned). Sends only from the cycle thread; this thread's lifecycle events go into
    // the same buffer and leave with the next cycle's POST.
    let cribl_out: Option<(Arc<cribl::Sender>, cribl::Shared)> = opts.cribl.as_ref().and_then(|cfg| {
        match cribl::Sender::new(cfg, cribl::SEND_TIMEOUT) {
            Ok(s) => {
                log::info!("Cribl output on ({})", cfg.url.host_str().unwrap_or("?"));
                Some((Arc::new(s), Default::default()))
            }
            Err(e) => {
                log::warn!("Cribl output off: {e}");
                None
            }
        }
    });
    let cribl_buf: Option<cribl::Shared> = cribl_out.as_ref().map(|o| o.1.clone());
    let lifecycle = |what: &str| {
        cribl::push(cribl_buf.as_ref(), vec![cribl::lifecycle_event(what, chrono::Utc::now())]);
    };
    lifecycle("start");
    let creds = loop {
        match supervisor_mqtt().await {
            Ok(c) => break c,
            Err(e) => {
                log::error!("cannot get MQTT credentials from the Supervisor: {e}");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    };

    let mut mo = MqttOptions::new("rayhunter_archive", creds.host, creds.port);
    mo.set_keep_alive(Duration::from_secs(30));
    if let (Some(u), Some(p)) = (creds.username, creds.password) {
        mo.set_credentials(u, p);
    }
    if creds.ssl {
        // No CA store: log and keep retrying rather than crash.
        let cfg = loop {
            match app::tls_config() {
                Ok(c) => break c,
                Err(e) => {
                    log::error!("cannot set up TLS for MQTT: {e}");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        };
        mo.set_transport(Transport::tls_with_config(cfg.into()));
    }
    let (client, mut eventloop) = AsyncClient::new(mo, 64);

    let dev: Arc<dyn Device> = Arc::new(Http::device(&opts.device_url));
    let press_topic = mqtt::fixed_press_topic(DEVICE_ID);
    let mesh_on = opts.mesh.is_some();
    // Set by the event loop below; findings are only sent (and marked sent) while true.
    let connected = Arc::new(AtomicBool::new(false));
    // HA's own birth/last-will on `homeassistant/status`: events wait while it is offline.
    // Starts true: HA may already be up and only says so again when it restarts.
    let ha_online = Arc::new(AtomicBool::new(true));
    // The last cycle's sensor states, re-sent on every connect (retained, so harmless twice).
    let last_states: Arc<std::sync::Mutex<Vec<(String, String)>>> = Default::default();

    // The owner page's channel into the cycle thread; the sender goes to the web server.
    let (page_tx, page_rx) = page::channel();
    // The owner page, over Ingress. If the port cannot be bound the add-on carries on without it.
    {
        let proxy = match proxy::Proxy::new(&opts.device_url, opts.device_token.clone()) {
            Ok(p) => Some(p),
            Err(e) => {
                log::error!("owner page: Rayhunter view disabled: {e}");
                None
            }
        };
        let router = web::router(page_tx.clone(), proxy);
        tokio::spawn(async move {
            let addr = std::net::SocketAddr::from(([0, 0, 0, 0], web::PORT));
            if let Err(e) = web::serve(router, addr).await {
                log::error!("owner page: cannot serve on {addr}: {e}; the add-on carries on without it");
            }
        });
    }

    // The cycle loop owns the SQLite connection (not Sync), so it gets its own thread with
    // a single-threaded runtime. A long cycle therefore never stalls the MQTT task below.
    {
        let (dev, client, connected) = (dev.clone(), client.clone(), connected.clone());
        let ha_online = ha_online.clone();
        let tolerance = opts.rhythm_tolerance_min;
        let learn_days = opts.fixed_learning_days;
        let rotation = rotation::Settings { hours: opts.rotate_hours, disk_pct: opts.rotate_disk_pct, pause: rotation::PAUSE };
        let last_states = last_states.clone();
        let cribl_out = cribl_out.clone();
        let mesh_cfg = opts.mesh.clone();
        let live_token = opts.device_token.clone();
        let live_test = opts.live_test_alert;
        let live_every = Duration::from_secs(opts.live_poll_secs);
        let summary_key = opts.summary_api_key.as_ref().map(|k| k.expose().to_string());
        let summary_model = opts.summary_model.clone();
        // The API call runs on this (the main) runtime, off the cycle thread.
        let main_rt = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                let store = match store::Store::open(std::path::Path::new(app::INDEX_PATH)) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("cannot open index: {e}");
                        std::process::exit(1);
                    }
                };
                let decoder = load_decoder();
                let what = if decoder.is_some() { "decoder_ready" } else { "decoder_unavailable" };
                cribl::push(cribl_out.as_ref().map(|o| &o.1), vec![cribl::lifecycle_event(what, chrono::Utc::now())]);
                let mut runner =
                    app::Runner::new(
                        dev,
                        store,
                        std::path::Path::new(app::ARCHIVE_DIR),
                        Box::new(|| app::free_bytes("/data")),
                    )
                    .with_decoder(decoder)
                    .with_rhythm_tolerance(tolerance)
                    .with_learning_days(learn_days)
                    .with_rotation(rotation)
                    .with_live(live_token.clone(), live_test, chrono::Utc::now())
                    .with_owner_page(opts.live_poll_secs, opts.all_clear_hours)
                    .with_summary(summary_key, summary_model)
                    .with_summary_runtime(main_rt);
                if live_token.is_none() {
                    log::info!("live: off (no device_token)");
                }
                if let Some(cfg) = &mesh_cfg {
                    runner = runner.with_mesh(cfg.clone(), chrono::Utc::now(), &mut mesh::random_u32);
                    if cfg.send_test {
                        // Once, at start-up: proves the radio path without waiting for an alert.
                        let batch = [(None, mesh::TEST_TEXT.to_string())];
                        let sent = mesh_send(cfg, &[mesh::TEST_TEXT.to_string()]).await;
                        match &sent {
                            Ok(_) => log::info!("mesh: test message sent"),
                            Err(e) => log::warn!("mesh: test message not sent ({e:#})"),
                        }
                        runner.mesh_sent(&sent, &batch, chrono::Utc::now());
                    }
                }
                let runner = std::rc::Rc::new(runner);
                let publishing = Arc::new(AtomicBool::new(false));
                let meshing = Arc::new(AtomicBool::new(false));
                // The owner page's commands, one at a time, on this thread. They take the
                // radio through `meshing` like every other stage.
                {
                    let (runner, meshing, mesh_cfg) = (runner.clone(), meshing.clone(), mesh_cfg.clone());
                    tokio::task::spawn_local(async move {
                        page::serve(
                            page_rx,
                            &runner,
                            &meshing,
                            (page::RADIO_WAIT, page::RADIO_STEP),
                            chrono::Utc::now,
                            |text| {
                                let cfg = mesh_cfg.clone();
                                async move {
                                    match cfg {
                                        Some(cfg) => mesh_send(&cfg, &[text]).await,
                                        None => anyhow::bail!("no mesh radio configured"),
                                    }
                                }
                            },
                        )
                        .await;
                        log::error!("owner page: command loop ended; the page is unavailable until restart");
                    });
                }
                // The live view: its own tick on this thread, sharing the runner, the
                // store and `meshing` (the radio is never opened by two stages at once).
                if live_token.is_some() {
                    let (runner, client, meshing) = (runner.clone(), client.clone(), meshing.clone());
                    let (connected, ha_online) = (connected.clone(), ha_online.clone());
                    let mesh_cfg = mesh_cfg.clone();
                    // Events from ticks that could not send (the first runs before MQTT is up).
                    let held = std::rc::Rc::new(std::cell::RefCell::new(app::HeldEvents::default()));
                    tokio::task::spawn_local(async move {
                        let mut tick = tokio::time::interval(live_every);
                        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        loop {
                            tick.tick().await;
                            let (r, c, meshing) = (runner.clone(), client.clone(), meshing.clone());
                            let (connected, ha_online) = (connected.clone(), ha_online.clone());
                            let mesh_cfg = mesh_cfg.clone();
                            let held = held.clone();
                            tokio::task::spawn_local(async move {
                                let Some(lc) = r.on_live_tick(chrono::Utc::now()).await else { return };
                                let up = connected.load(Ordering::Relaxed);
                                let ha = ha_online.load(Ordering::Relaxed);
                                let new = lc.events.len();
                                let (batch, dropped) = held.borrow_mut().take(lc.events, app::may_send_events(up, ha));
                                if dropped > 0 {
                                    log::warn!("live: {dropped} event(s) dropped, {} already held", app::LIVE_HELD_MAX);
                                }
                                if batch.is_empty() && new > 0 {
                                    log::warn!("live: {new} event(s) held (connected: {up}, HA online: {ha})");
                                }
                                let mut failed = Vec::new();
                                for (topic, body) in batch {
                                    // Never retained: an HA restart must not replay it.
                                    if let Err(e) = c.publish(topic.clone(), QoS::AtLeastOnce, false, body.clone()).await {
                                        log::warn!("live event not sent, held: {e}");
                                        failed.push((topic, body));
                                    }
                                }
                                let lost = held.borrow_mut().hold(failed);
                                if lost > 0 {
                                    log::warn!("live: {lost} event(s) dropped, {} already held", app::LIVE_HELD_MAX);
                                }
                                // Stage 1 never waits for quiet hours. If the 15-minute cycle
                                // holds the radio, it stays owed and the next tick offers it.
                                if let (Some(cfg), false) = (&mesh_cfg, lc.mesh.is_empty()) {
                                    if meshing.swap(true, Ordering::Relaxed) {
                                        log::debug!("live: stage 1 waits: the radio is busy");
                                        return;
                                    }
                                    let _done = Done(meshing.clone());
                                    let batch = r.stage1_still_pending(lc.mesh, chrono::Utc::now());
                                    if batch.is_empty() {
                                        return;
                                    }
                                    let texts: Vec<String> = batch.iter().map(|b| b.1.clone()).collect();
                                    let sent = mesh_send(cfg, &texts).await;
                                    r.live_stage1_result(&sent, texts.len());
                                    r.live_mesh_sent(&sent, &batch, chrono::Utc::now());
                                }
                            });
                        }
                    });
                }
                let mut tick = tokio::time::interval(app::CYCLE_EVERY);
                // Ticks are delivered on time even mid-cycle; the runner drops them.
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
                loop {
                    tick.tick().await;
                    let (r, c) = (runner.clone(), client.clone());
                    let (connected, publishing) = (connected.clone(), publishing.clone());
                    let meshing = meshing.clone();
                    let ha_online = ha_online.clone();
                    let last_states = last_states.clone();
                    let cribl_out = cribl_out.clone();
                    let mesh_cfg = mesh_cfg.clone();
                    tokio::task::spawn_local(async move {
                        if let Some(mut cycle) = r.on_tick(chrono::Utc::now()).await {
                            // When the mesh batch was built; it is re-checked before sending.
                            let mesh_built = chrono::Utc::now();
                            // Kept for the next connect: the first cycle runs before MQTT is up.
                            *last_states.lock().unwrap() = cycle.states.clone();
                            let cribl_events = std::mem::take(&mut cycle.cribl);
                            let notes = std::mem::take(&mut cycle.notes);
                            let mesh_batch = std::mem::take(&mut cycle.mesh);
                            let stage1 = std::mem::take(&mut cycle.stage1);
                            let admin = std::mem::take(&mut cycle.admin);
                            // The publish stage; yields the outbox ids it sent. A `return` in
                            // here ends the stage only: the Cribl step below still runs.
                            let sent: Vec<i64> = async {
                            // Checked first: the broker being down means publish() would block
                            // (rumqttc stops draining its queue), so send nothing at all.
                            // States go out next cycle; events stay in the outbox.
                            let up = connected.load(Ordering::Relaxed);
                            if !app::may_publish(up, publishing.load(Ordering::Relaxed)) {
                                log::debug!("publish skipped (connected: {up})");
                                return Vec::new();
                            }
                            // One publish stage at a time, released even on a panic.
                            if publishing.swap(true, Ordering::Relaxed) {
                                return Vec::new();
                            }
                            let _done = Done(publishing.clone());
                            publish_all(&c, cycle.states, true).await;
                            // HA restarting would take the events and run no automation.
                            let up = connected.load(Ordering::Relaxed);
                            let ha = ha_online.load(Ordering::Relaxed);
                            if !app::may_send_events(up, ha) {
                                log::debug!("events held (connected: {up}, HA online: {ha})");
                                return Vec::new();
                            }
                            // Admin notices: never retained, never retried (they cool down).
                            for (topic, body) in admin {
                                if let Err(e) = c.publish(topic, QoS::AtLeastOnce, false, body).await {
                                    log::warn!("admin event not sent: {e}");
                                }
                            }
                            // Built before this stage began: drop rows another stage sent.
                            let ids: Vec<i64> = cycle.events.iter().map(|e| e.0).collect();
                            let live = r.still_pending(&ids);
                            let mut sent = Vec::new();
                            let events = cycle.events.into_iter().filter(|e| live.contains(&e.0));
                            for (id, topic, body) in events {
                                // Never retained: an HA restart must not replay a finding.
                                match c.publish(topic, QoS::AtLeastOnce, false, body).await {
                                    Ok(()) => sent.push(id),
                                    Err(e) => log::warn!("finding event not sent: {e}"),
                                }
                            }
                            if !sent.is_empty() {
                                log::info!("sent {} finding event(s)", sent.len());
                            }
                            r.mark_sent(&sent, chrono::Utc::now());
                            sent
                            }
                            .await;
                            // Cribl last, best effort: after the alerts went out, in this
                            // cycle's own task (the next tick never waits for it), one send
                            // at a time, 10 s timeout. Unsent events wait in a capped buffer.
                            if let Some((sender, buf)) = &cribl_out {
                                let mut events = cribl_events;
                                let now = chrono::Utc::now();
                                events.extend(cribl::notifications(&notes, &sent, "sent", now));
                                // The transmission log since the last cycle (this cycle's
                                // mesh step comes after, so its lines go next time).
                                events.extend(r.take_radio_events().iter().map(cribl::radio_event));
                                cribl::after_cycle(sender, buf, events).await;
                            }
                            // The household mesh, after everything else; a failure here
                            // leaves the rows unsent for the next cycle and nothing more.
                            // One mesh stage at a time (released even on a panic): a stage
                            // that finds another sending skips; its rows stay unsent.
                            // Stage 1 texts owed by alerts go first, in the same send.
                            let quiet = mesh_batch.is_empty() && stage1.is_empty();
                            if let (Some(cfg), false) = (&mesh_cfg, quiet) {
                                if meshing.swap(true, Ordering::Relaxed) {
                                    log::debug!("mesh stage skipped: another is sending");
                                    r.mesh_stage_skipped(&mesh_batch, chrono::Utc::now());
                                } else {
                                    let _done = Done(meshing.clone());
                                    // Built before the stages above: drop what another stage
                                    // meshed meanwhile, and a quiet ping that has gone stale.
                                    let now = chrono::Utc::now();
                                    let stage1 = r.stage1_still_pending(stage1, now);
                                    let batch = r.mesh_sendable(mesh_batch, mesh_built, now);
                                    if !(batch.is_empty() && stage1.is_empty()) {
                                        let texts: Vec<String> =
                                            stage1.iter().map(|b| b.1.clone()).chain(batch.iter().map(|b| b.1.clone())).collect();
                                        let sent = mesh_send(cfg, &texts).await;
                                        match &sent {
                                            Ok(n) => log::info!("mesh: sent {n} of {} message(s)", texts.len()),
                                            Err(e) => log::warn!(
                                                "mesh: not sent ({e:#}); {} row(s) and {} stage 1 wait for the next cycle",
                                                batch.iter().filter(|b| b.0.is_some()).count(),
                                                stage1.len()
                                            ),
                                        }
                                        r.cycle_mesh_sent(&sent, &stage1, &batch, chrono::Utc::now());
                                    }
                                }
                            }
                        }
                    });
                }
            });
        });
    }

    // Button presses: handled on their own task; never starts a cycle.
    let (press_tx, mut press_rx) = mpsc::channel::<()>(8);
    {
        // Its own HTTP client: connection pools are tied to the runtime that made them.
        let dev: Arc<dyn Device> = Arc::new(Http::device(&opts.device_url));
        let (client, token) = (client.clone(), opts.device_token.clone());
        tokio::spawn(async move {
            while press_rx.recv().await.is_some() {
                let result = mqtt::press_fixed(&*dev, token.as_deref()).await;
                log::info!("Fixed request: {result}");
                publish_all(&client, vec![mqtt::fixed_state(DEVICE_ID, result)], true).await;
            }
        });
    }

    // MQTT event loop: keep-alives, (re)subscribe + discovery on connect, HA restarts.
    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                log::info!("MQTT connected");
                connected.store(true, Ordering::Relaxed);
                lifecycle("mqtt_connected");
                // A birth message missed while reconnecting must not hold events for good.
                let ha = app::ha_online_after(ha_online.load(Ordering::Relaxed), app::HaSignal::ConnAck);
                ha_online.store(ha, Ordering::Relaxed);
                let c = client.clone();
                let topic = press_topic.clone();
                let states = last_states.lock().unwrap().clone();
                tokio::spawn(async move {
                    let _ = c.subscribe(topic, QoS::AtLeastOnce).await;
                    let _ = c.subscribe(STATUS_TOPIC, QoS::AtLeastOnce).await;
                    publish_all(&c, mqtt::discovery(DEVICE_ID, mesh_on), true).await;
                    publish_all(&c, states, true).await;
                });
            }
            Ok(Event::Incoming(Packet::Publish(p))) => {
                if p.topic == press_topic {
                    // Any payload is a press (HA sends "PRESS" by default).
                    let _ = press_tx.try_send(());
                } else if p.topic == STATUS_TOPIC && &p.payload[..] == b"online" {
                    let ha = app::ha_online_after(ha_online.load(Ordering::Relaxed), app::HaSignal::StatusOnline);
                    ha_online.store(ha, Ordering::Relaxed);
                    let c = client.clone();
                    tokio::spawn(async move {
                        publish_all(&c, mqtt::discovery(DEVICE_ID, mesh_on), true).await;
                    });
                } else if p.topic == STATUS_TOPIC && &p.payload[..] == b"offline" {
                    log::info!("Home Assistant offline; finding events wait");
                    let ha = app::ha_online_after(ha_online.load(Ordering::Relaxed), app::HaSignal::StatusOffline);
                    ha_online.store(ha, Ordering::Relaxed);
                }
            }
            Ok(_) => {}
            Err(e) => {
                log::warn!("MQTT: {e}; retrying");
                // Once per outage, not every 5 s retry.
                if connected.swap(false, Ordering::Relaxed) {
                    lifecycle("mqtt_lost");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
