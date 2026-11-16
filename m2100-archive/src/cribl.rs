//! Optional output to a self-hosted Cribl Stream HTTP source: each cycle's events, one JSON
//! object per line, POSTed over TLS that trusts only the pinned Cribl certificate.
//!
//! Best effort and off the safety path: nothing here can delay or fail a pull, a judgement,
//! an MQTT publish or an alert. Off when the options are blank.
//!
//! Nothing here may carry a finding's `detail`, a tower key or identity (PLMN/TAC/cell/PCI/
//! EARFCN), a location, a token, a file path or capture bytes. Event `time` is the Yellow's
//! clock (the cycle's `now`), never one of the unit's timestamps.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};

use crate::app::DEVICE_ID;
use crate::decoder::Judged;
use crate::health::Health;
use crate::puller::Outcome;
use crate::store::Report;

/// Unsent events kept across cycles; past this the oldest are dropped.
pub const BUFFER_MAX: usize = 1000;
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest capture name sent (the unit names them; untrusted text).
const NAME_MAX: usize = 64;

/// Where and how to send. Built only from a complete, valid set of options.
#[derive(Clone, PartialEq)]
pub struct Config {
    pub url: reqwest::Url,
    token: String,
    /// The pinned certificate(s), DER.
    certs: Vec<Vec<u8>>,
}

/// Never prints the token.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Config {{ url: {}, token: <redacted>, certs: {} }}", self.url, self.certs.len())
    }
}

fn blank(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|v| !v.is_empty())
}

/// The output's options, or `None` (off). Blank URL = off, silently; anything else that is
/// missing or wrong = off with one warning that names the option, never its value.
pub fn config(url: Option<&str>, token: Option<&str>, ca: Option<&str>) -> Option<Config> {
    let url = blank(url)?;
    let off = |why: &str| {
        log::warn!("Cribl output off: {why}");
        None
    };
    let url = match reqwest::Url::parse(url) {
        // Userinfo would add a second (basic) Authorization header; Cribl takes no query.
        Ok(u) if u.scheme() == "https" && u.host().is_some()
            && (!u.username().is_empty() || u.password().is_some()) =>
        {
            return off("cribl_url must not hold a user name or password");
        }
        Ok(u) if u.scheme() == "https" && u.host().is_some() && u.query().is_some() => {
            return off("cribl_url must not have a query string");
        }
        Ok(u) if u.scheme() == "https" && u.host().is_some() => u,
        // The token must never cross the LAN in clear.
        Ok(u) if u.scheme() == "http" => return off("cribl_url must be https://, not http://"),
        _ => return off("cribl_url is not an https:// URL"),
    };
    let Some(token) = blank(token) else {
        return off("cribl_url is set but cribl_token is blank");
    };
    let Some(ca) = blank(ca) else {
        return off("cribl_url is set but cribl_ca (the Cribl certificate PEM) is blank");
    };
    let Some(certs) = pem_certs(ca) else {
        return off("cribl_ca holds no certificate that parses");
    };
    Some(Config { url, token: token.to_string(), certs })
}

/// The certificates in a PEM, each checked to parse. Tolerates a PEM pasted into a
/// one-line field (newlines turned into spaces) or with literal `\n`s.
fn pem_certs(pem: &str) -> Option<Vec<Vec<u8>>> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    // Rebuild each block as a well-formed PEM: markers on their own lines, the base64
    // body with all whitespace removed, then let pki-types do the parsing.
    let pem = pem.replace("\\n", "\n");
    let mut clean = String::new();
    let mut rest = pem.as_str();
    while let Some(b) = rest.find(BEGIN) {
        let after = &rest[b + BEGIN.len()..];
        let e = after.find(END)?;
        let body: String = after[..e].chars().filter(|c| !c.is_whitespace()).collect();
        clean.push_str(&format!("{BEGIN}\n{body}\n{END}\n"));
        rest = &after[e + END.len()..];
    }
    let certs: Vec<CertificateDer> =
        CertificateDer::pem_slice_iter(clean.as_bytes()).collect::<Result<_, _>>().ok()?;
    // Each must be a certificate rustls can trust (this parses it).
    let mut roots = rustls::RootCertStore::empty();
    for c in &certs {
        roots.add(c.clone()).ok()?;
    }
    (!certs.is_empty()).then(|| certs.iter().map(|c| c.to_vec()).collect())
}

// ---- events ----

/// A capture name as sent: printable ASCII, at most 64 chars.
fn name(s: &str) -> String {
    crate::events::printable(s, NAME_MAX)
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The common fields, then the type's own (`fields` must be an object), all top level.
fn event(kind: &str, now: DateTime<Utc>, raw: String, fields: Value) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), kind.into());
    m.insert("time".into(), rfc3339(now).into());
    m.insert("device".into(), DEVICE_ID.into());
    m.insert("addon_version".into(), env!("CARGO_PKG_VERSION").into());
    m.insert("_raw".into(), raw.into());
    if let Value::Object(f) = fields {
        m.extend(f);
    }
    Value::Object(m)
}

fn known_word(k: Option<bool>) -> Option<&'static str> {
    k.map(|k| if k { "known" } else { "unknown" })
}

/// One transmission-log line: what kind of text and what became of it, never the text.
pub fn radio_event(e: &crate::mesh::RadioEvent) -> Value {
    let raw = match e.reason {
        Some(r) => format!("radio {} {} ({r})", e.kind, e.outcome.as_str()),
        None => format!("radio {} {}", e.kind, e.outcome.as_str()),
    };
    event(
        "radio",
        e.at,
        raw,
        json!({
            "kind": e.kind,
            "outcome": e.outcome.as_str(),
            "reason": e.reason,
            "alert_id": e.alert_id,
            "bell": e.bell,
            "hash": e.hash,
        }),
    )
}

/// The cycle's pull numbers.
pub fn cycle_event(o: &Outcome, free_bytes: u64, cycle_ms: u64, now: DateTime<Utc>) -> Value {
    let raw = if o.reached_device {
        format!("cycle pulled {} deleted {} backlog {}", o.pulled, o.deleted, o.backlog)
    } else {
        "cycle: unit not reached".to_string()
    };
    event("cycle", now, raw, json!({
        "pulled": o.pulled,
        "deleted": o.deleted,
        "mismatches": o.mismatches,
        "missing": o.missing,
        "backlog": o.backlog,
        "reached_device": o.reached_device,
        "free_bytes": free_bytes,
        "cycle_ms": cycle_ms,
    }))
}

/// One capture's decode: counts only (`towers` is how many, never which).
pub fn decode_event(j: &Judged, now: DateTime<Utc>) -> Value {
    let (capture, status) = (name(&j.name), j.status.as_str());
    let raw = format!("decode {status} in {capture} ({})", j.profile.as_str());
    event("decode", now, raw, json!({
        "capture": capture,
        "status": status,
        "profile": j.profile.as_str(),
        "switched": j.spans_switch,
        "frames": j.frames,
        "failures": j.failures,
        "towers": j.towers,
        "identity_requests": j.identity_requests,
        "warnings_high": j.warnings_high,
        "warnings_other": j.warnings_other,
    }))
}

/// One event per finding of the capture: check id and level, never the detail.
pub fn finding_events(j: &Judged, now: DateTime<Utc>) -> Vec<Value> {
    let capture = name(&j.name);
    j.findings
        .iter()
        .map(|(check, level)| {
            let raw = format!("finding {check} in {capture}");
            event("finding", now, raw, json!({
                "capture": capture,
                "check": check,
                "level": level.as_str(),
                "profile": j.profile.as_str(),
                "switched": j.spans_switch,
                "suppressed": j.suppressed,
                "towers_known": known_word(j.towers_known),
                // Judged now: `found_at` in the index is the judging time too.
                "found": rfc3339(now),
            }))
        })
        .collect()
}

/// An outbox row as the Cribl output needs it, kept from the cycle for the publish stage.
#[derive(Debug, Clone, PartialEq)]
pub struct Note {
    pub id: i64,
    pub capture: String,
    pub check: String,
    pub count: u32,
}

/// `outcome`: "sent" / "expired" / "merged" / "unsendable".
pub fn notification_event(n: &Note, outcome: &str, now: DateTime<Utc>) -> Value {
    let (capture, check) = (name(&n.capture), name(&n.check));
    let raw = format!("notification {check} for {capture} {outcome}");
    event("notification", now, raw, json!({
        "capture": capture,
        "check": check,
        "count": n.count,
        "outcome": outcome,
    }))
}

/// The events for the rows among `notes` whose id is in `ids`.
pub fn notifications(notes: &[Note], ids: &[i64], outcome: &str, now: DateTime<Utc>) -> Vec<Value> {
    notes
        .iter()
        .filter(|n| ids.contains(&n.id))
        .map(|n| notification_event(n, outcome, now))
        .collect()
}

/// The values the HA sensors get this cycle. `report`: `None` if it failed (its fields are
/// left out, as the sensors are not updated then).
pub fn health_event(
    h: &Health,
    report: Option<&Report>,
    decoder_unavailable: bool,
    backlog: u32,
    mismatches_total: u32,
    now: DateTime<Utc>,
) -> Value {
    // Rounded as the sensors are.
    let mins = |d: chrono::Duration| (d.num_seconds() as f64 / 60.0).round() as i64;
    let tenths = |x: f64| (x * 10.0).round() / 10.0;
    let free_gb = tenths(h.free_bytes as f64 / 1e9);
    let mut f = json!({
        "decoder_unavailable": decoder_unavailable,
        "archive_mb": (h.archive_bytes as f64 / 1e6).round() as u64,
        "free_gb": free_gb,
        "days_covered": tenths(h.days_covered),
        "gap_24h_min": mins(h.gap_24h),
        "longest_gap_24h_min": mins(h.longest_gap_24h),
        "backlog": backlog,
        "mismatches_total": mismatches_total,
        "paused": h.paused,
    });
    if let (Some(r), Value::Object(m)) = (report, &mut f) {
        m.extend(
            json!({
                "analyser_high_24h": r.analyser_high,
                "analyser_other_24h": r.analyser_other,
                "new_towers_24h": r.new_towers,
                "off_rhythm_24h": r.off_rhythm,
                "failure_spikes_24h": r.failure_spikes,
                "decoder_failures_24h": r.decoder_failures,
                "archive_corrupt_24h": r.archive_corrupt,
                "towers_seen_24h": r.towers_seen,
                "learning": r.learning,
            })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        );
    }
    let raw = format!("health backlog {backlog} free {free_gb} GB");
    event("health", now, raw, f)
}

/// One rotation attempt (see `rotation`). `age_hours` is on the Yellow's clock.
pub fn rotation_event(r: &crate::rotation::Rotation, now: DateTime<Utc>) -> Value {
    let raw = format!("rotation {} {}", r.reason, if r.ok { "ok" } else { "failed" });
    event("rotation", now, raw, json!({
        "reason": r.reason,
        "ok": r.ok,
        "previous": r.previous.as_deref().map(name),
        "current": r.current.as_deref().map(name),
        "used_percent": r.used_percent,
        "age_hours": r.age_hours.map(|h| (h * 10.0).round() / 10.0),
    }))
}

/// "start" / "decoder_ready" / "decoder_unavailable" / "mqtt_connected" / "mqtt_lost".
pub fn lifecycle_event(what: &str, now: DateTime<Utc>) -> Value {
    event("lifecycle", now, format!("lifecycle {what}"), json!({ "event": what }))
}

// ---- buffer ----

/// Unsent event lines, oldest first, each with a sequence number so a send can clear
/// exactly what it took even if more arrived (or the oldest were dropped) meanwhile.
#[derive(Default)]
pub struct Buffer {
    q: VecDeque<(u64, String)>,
    next: u64,
    dropped: usize,
}

pub type Shared = Arc<Mutex<Buffer>>;

impl Buffer {
    /// Add events; past `BUFFER_MAX` the oldest go.
    pub fn push(&mut self, events: Vec<Value>) {
        for e in events {
            if self.q.len() >= BUFFER_MAX {
                self.q.pop_front();
                self.dropped += 1;
            }
            self.q.push_back((self.next, e.to_string()));
            self.next += 1;
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// How many were dropped since the last call.
    pub fn take_dropped(&mut self) -> usize {
        std::mem::take(&mut self.dropped)
    }

    /// Everything buffered as one NDJSON body: (last sequence number, body, how many).
    pub fn batch(&self) -> Option<(u64, String, usize)> {
        let last = self.q.back()?.0;
        let mut body = String::new();
        for (_, line) in &self.q {
            body.push_str(line);
            body.push('\n');
        }
        Some((last, body, self.q.len()))
    }

    /// A send of everything up to `last` succeeded.
    pub fn ack(&mut self, last: u64) {
        while self.q.front().is_some_and(|(seq, _)| *seq <= last) {
            self.q.pop_front();
        }
    }
}

/// Queue events if the output is on. Never blocks for long (a short mutex).
pub fn push(buf: Option<&Shared>, events: Vec<Value>) {
    if let Some(b) = buf {
        b.lock().unwrap_or_else(|e| e.into_inner()).push(events);
    }
}

// ---- sending ----

/// What one flush did.
#[derive(Debug, PartialEq)]
pub enum Flushed {
    /// Another send was still running.
    Busy,
    Empty,
    Sent(usize),
    /// Not accepted (error or non-2xx): kept for the next cycle.
    Kept(usize),
}

/// Certificate pinning: the server must present exactly a pinned certificate, byte for byte,
/// and prove it holds its key (the handshake signature is still verified against it).
/// Nothing a pinned certificate signed is accepted. Name, dates and the CA flag are not
/// checked: the pin is the identity. (A plain trust anchor would refuse the CA:TRUE
/// self-signed certificate `openssl req -x509` makes by default, and would accept any
/// certificate signed with its key.)
#[derive(Debug)]
struct Pinned {
    certs: Vec<Vec<u8>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.certs.iter().any(|c| c.as_slice() == end_entity.as_ref()) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("not the pinned Cribl certificate".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub struct Sender {
    client: reqwest::Client,
    url: reqwest::Url,
    /// The token as the `Authorization` value, marked sensitive.
    auth: reqwest::header::HeaderValue,
    sending: AtomicBool,
}

impl Sender {
    /// A client that accepts only the pinned certificate(s) (see `Pinned`): no system or
    /// bundled roots, https only, no redirects.
    pub fn new(cfg: &Config, timeout: Duration) -> anyhow::Result<Sender> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let pinned = Pinned {
            certs: cfg.certs.clone(),
            algs: provider.signature_verification_algorithms,
        };
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(pinned))
            .with_no_client_auth();
        let b = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout);
        let mut auth = reqwest::header::HeaderValue::from_str(&cfg.token)
            .map_err(|_| anyhow::anyhow!("cribl_token has characters a header cannot carry"))?;
        auth.set_sensitive(true);
        Ok(Sender {
            client: b.build()?,
            url: cfg.url.clone(),
            auth,
            sending: AtomicBool::new(false),
        })
    }

    /// One POST of everything buffered, one at a time. 2xx clears what was sent;
    /// anything else keeps it (subject to the cap) and logs one line.
    pub async fn flush(&self, buf: &Mutex<Buffer>) -> Flushed {
        if self.sending.swap(true, Ordering::Relaxed) {
            return Flushed::Busy;
        }
        // Released even if this future is dropped mid-send.
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let _done = Done(&self.sending);
        let lock = || buf.lock().unwrap_or_else(|e| e.into_inner());
        let (dropped, batch) = {
            let mut b = lock();
            (b.take_dropped(), b.batch())
        };
        if dropped > 0 {
            log::warn!("Cribl: buffer full; dropped the {dropped} oldest event(s)");
        }
        let Some((last, body, n)) = batch else {
            return Flushed::Empty;
        };
        let sent = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::AUTHORIZATION, self.auth.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
        // One line, never the token or the events.
        match sent {
            Ok(r) if r.status().is_success() => {
                lock().ack(last);
                log::debug!("Cribl: sent {n} event(s)");
                Flushed::Sent(n)
            }
            Ok(r) => {
                log::warn!("Cribl: HTTP {}; {n} event(s) kept", r.status().as_u16());
                Flushed::Kept(n)
            }
            Err(e) => {
                log::warn!("Cribl: {}; {n} event(s) kept", describe(e));
                Flushed::Kept(n)
            }
        }
    }
}

/// The error and its causes on one line (a TLS refusal is only in the causes).
/// A failed send for the log: no URL (reqwest's Display appends it), so no option value.
fn describe(e: reqwest::Error) -> String {
    error_chain(&e.without_url())
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

/// After a cycle: queue its events and send. Runs on the cycle thread after the publish
/// stage, in its own task, so the next tick never waits for it.
pub async fn after_cycle(sender: &Sender, buf: &Shared, events: Vec<Value>) -> Flushed {
    push(Some(buf), events);
    sender.flush(buf).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{self, Finding, Judgement, Learn, Level, Profile};
    use crate::events::Strength;
    use crate::store::{Decode, DecodeStatus};
    use std::io::{Read, Write};

    const CELL: &str = "310-260-21891-1234";
    const LEAF: &str = include_str!("testdata/cribl/leaf.crt");
    const LEAF_KEY: &str = include_str!("testdata/cribl/leaf.key");
    const OTHER: &str = include_str!("testdata/cribl/other.crt");
    const OTHER_KEY: &str = include_str!("testdata/cribl/other.key");
    const URL: &str = "https://192.0.2.10:9443/cribl/_bulk";

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-15T12:00:00Z").unwrap().with_timezone(&Utc)
    }

    /// A realistic verdict: details and learned towers full of cell identities.
    fn judged() -> Judged {
        let d = Decode {
            device: "unit1".into(),
            name: "532174".into(),
            start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            status: DecodeStatus::Ok,
            profile: "fixed".into(),
            frames: 100,
            failures: 2,
            towers: 3,
            identity_requests: 1,
            warnings_high: 1,
            warnings_other: 4,
            decoder_hash: "abc".into(),
            decoded_at: now(),
            detail: Some(format!("guest said {CELL}")),
        };
        let j = Judgement {
            profile: Profile::Fixed,
            findings: vec![
                Finding {
                    check: checks::ANALYSER_HIGH,
                    level: Level::Notify,
                    detail: format!("An: 1 high warning(s); first: {CELL} PCI 12 EARFCN 5230 PLMN 310260 TAC 21891"),
                },
                Finding {
                    check: checks::NEW_TOWER_WEAK,
                    level: Level::Count,
                    detail: "pci:12:earfcn:5230".into(),
                },
            ],
            learn: Some(Learn {
                towers: vec![(CELL.into(), Strength::Sib1), ("pci:12:5230".into(), Strength::Pci)],
                hold: vec![],
                identity_ts: vec![now()],
                failure_hours: vec![],
            }),
            spans_switch: true,
            suppressed: false,
            towers_known: Some(false),
        };
        Judged::new(&d, &j)
    }

    fn health() -> Health {
        Health {
            archive_bytes: 1_234_567_890,
            free_bytes: 52_340_000_000,
            days_covered: 3.456,
            gap_24h: chrono::Duration::seconds(95),
            longest_gap_24h: chrono::Duration::minutes(40),
            paused: false,
        }
    }

    fn report() -> Report {
        Report {
            analyser_high: 1, analyser_other: 2, off_rhythm: 3, failure_spikes: 4,
            decoder_failures: 5, archive_corrupt: 6, new_towers: 7, towers_seen: 8, learning: true,
        }
    }

    fn note() -> Note {
        Note { id: 7, capture: "532174".into(), check: "analyser_high".into(), count: 2 }
    }

    fn every_event() -> Vec<Value> {
        let o = Outcome {
            pulled: 2, deleted: 2, mismatches: 0, missing: 1, backlog: 3,
            oldest_backlog: DateTime::from_timestamp(1_700_000_000, 0), reached_device: true,
        };
        let j = judged();
        let mut v = vec![cycle_event(&o, 52_340_000_000, 1234, now()), decode_event(&j, now())];
        v.extend(finding_events(&j, now()));
        for outcome in ["sent", "expired", "merged", "unsendable"] {
            v.push(notification_event(&note(), outcome, now()));
        }
        v.push(health_event(&health(), Some(&report()), false, 3, 2, now()));
        v.push(health_event(&health(), None, true, 3, 2, now()));
        for what in ["start", "decoder_ready", "decoder_unavailable", "mqtt_connected", "mqtt_lost"] {
            v.push(lifecycle_event(what, now()));
        }
        v.extend(rotations().iter().map(|r| rotation_event(r, now())));
        v.extend(radios().iter().map(radio_event));
        v
    }

    /// A sent alert, a failed follow-up, a skipped ping.
    fn radios() -> Vec<crate::mesh::RadioEvent> {
        use crate::mesh::*;
        let mut v = send_events(&[("stage1", Some(4), "Home alert (strong): near 310-260 PCI 21891")], &Ok(1), now());
        v.extend(send_events(&[("watching", Some(4), "Update: looking into it.")], &Err(anyhow::anyhow!("x")), now()));
        v.push(skipped_ping(SKIP_ALERT_OPEN, now()));
        v
    }

    #[test]
    fn radio_events_carry_the_outcome_and_hash_never_the_text() {
        let all: Vec<Value> = radios().iter().map(radio_event).collect();
        assert_eq!(all[0]["kind"], "stage1");
        assert_eq!(all[0]["outcome"], "sent");
        assert_eq!(all[0]["reason"], Value::Null);
        assert_eq!(all[0]["alert_id"], 4);
        assert_eq!(all[0]["bell"], true);
        assert_eq!(all[0]["hash"], crate::mesh::text_hash("Home alert (strong): near 310-260 PCI 21891"));
        assert_eq!(all[0]["_raw"], "radio stage1 sent");
        assert_eq!(all[1]["_raw"], "radio watching failed (error)");
        assert_eq!(all[2]["_raw"], "radio quiet skipped (alert_open)");
        assert_eq!((all[2]["alert_id"].clone(), all[2]["bell"].clone()), (Value::Null, Value::Bool(false)));
        for e in &all {
            let s = e.to_string().to_lowercase();
            for bad in ["home alert", "update:", "all quiet", "near"] {
                assert!(!s.contains(bad), "{bad:?} in {s}");
            }
        }
    }

    /// A good one, a failed one, and one whose names are the unit's hostile text.
    fn rotations() -> Vec<crate::rotation::Rotation> {
        use crate::rotation::Rotation;
        vec![
            Rotation {
                reason: "age", ok: true, previous: Some("1791778208".into()),
                current: Some("1791799808".into()), used_percent: Some(41), age_hours: Some(6.0),
            },
            Rotation {
                reason: "retry", ok: false, previous: None, current: None, used_percent: None,
                age_hours: None,
            },
            Rotation {
                reason: "disk", ok: true, previous: Some("ab\ncd".into()),
                current: Some(format!("{}\u{1b}", "9".repeat(80))), used_percent: Some(88),
                age_hours: Some(1.25),
            },
        ]
    }

    fn keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    out.push(k.clone());
                    keys(x, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| keys(x, out)),
            _ => {}
        }
    }

    #[test]
    fn no_forbidden_fields_in_any_event() {
        let all = every_event();
        let types: std::collections::BTreeSet<&str> =
            all.iter().map(|e| e["type"].as_str().unwrap_or("?")).collect();
        assert_eq!(
            types.into_iter().collect::<Vec<_>>(),
            ["cycle", "decode", "finding", "health", "lifecycle", "notification", "radio", "rotation"]
        );
        assert_eq!(all.iter().filter(|e| e["type"] == "finding").count(), 2);
        for e in &all {
            let s = e.to_string().to_lowercase();
            for bad in [CELL, "310-260", "21891", "pci", "earfcn", "plmn", "detail", "token"] {
                assert!(!s.contains(bad), "{bad:?} in {s}");
            }
            let mut ks = Vec::new();
            keys(e, &mut ks);
            assert!(!ks.iter().any(|k| k == "tac"), "{s}");
        }
    }

    /// Exactly the brief's fields per type, plus the common ones; time is the Yellow's.
    #[test]
    fn each_event_has_exactly_its_fields_and_the_yellows_clock() {
        let common = ["type", "time", "device", "addon_version", "_raw"];
        let want: &[(&str, &[&str])] = &[
            ("cycle", &["pulled", "deleted", "mismatches", "missing", "backlog", "reached_device", "free_bytes", "cycle_ms"]),
            ("decode", &["capture", "status", "profile", "switched", "frames", "failures", "towers", "identity_requests", "warnings_high", "warnings_other"]),
            ("finding", &["capture", "check", "level", "profile", "switched", "suppressed", "towers_known", "found"]),
            ("notification", &["capture", "check", "count", "outcome"]),
            ("lifecycle", &["event"]),
            ("radio", &["kind", "outcome", "reason", "alert_id", "bell", "hash"]),
            ("rotation", &["reason", "ok", "previous", "current", "used_percent", "age_hours"]),
        ];
        for e in every_event() {
            assert_eq!(e["time"], "2026-10-15T12:00:00Z");
            assert_eq!(e["device"], "unit1");
            assert_eq!(e["addon_version"], env!("CARGO_PKG_VERSION"));
            assert!(!e["_raw"].as_str().unwrap().is_empty());
            let t = e["type"].as_str().unwrap();
            let mut got: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
            got.retain(|k| !common.contains(k));
            got.sort();
            if t == "health" {
                continue; // checked below
            }
            let mut exp = want.iter().find(|w| w.0 == t).unwrap().1.to_vec();
            exp.sort();
            assert_eq!(got, exp, "{t}");
        }
        let all = every_event();
        let f = all.iter().find(|e| e["type"] == "finding").unwrap();
        assert_eq!(f["capture"], "532174");
        assert_eq!(f["check"], "analyser_high");
        assert_eq!(f["level"], "notify");
        assert_eq!(f["towers_known"], "unknown");
        assert_eq!(f["found"], "2026-10-15T12:00:00Z");
        assert_eq!(f["_raw"], "finding analyser_high in 532174");
        let d = all.iter().find(|e| e["type"] == "decode").unwrap();
        assert_eq!((d["towers"].as_u64(), d["status"].as_str()), (Some(3), Some("ok")));
        let h: Vec<&Value> = all.iter().filter(|e| e["type"] == "health").collect();
        assert_eq!(h[0]["analyser_high_24h"], 1);
        assert_eq!(h[0]["towers_seen_24h"], 8);
        assert_eq!(h[0]["learning"], true);
        assert_eq!(h[0]["archive_mb"], 1235);
        assert_eq!(h[0]["free_gb"], 52.3);
        assert_eq!(h[0]["days_covered"], 3.5);
        assert_eq!((h[0]["gap_24h_min"].as_i64(), h[0]["longest_gap_24h_min"].as_i64()), (Some(2), Some(40)));
        assert_eq!((h[0]["backlog"].as_u64(), h[0]["mismatches_total"].as_u64()), (Some(3), Some(2)));
        assert_eq!((h[0]["paused"].as_bool(), h[0]["decoder_unavailable"].as_bool()), (Some(false), Some(false)));
        assert!(h[1].get("analyser_high_24h").is_none() && h[1].get("learning").is_none());
        assert_eq!(h[1]["decoder_unavailable"], true);
        let r: Vec<&Value> = all.iter().filter(|e| e["type"] == "rotation").collect();
        assert_eq!(r.len(), 3);
        assert_eq!((r[0]["reason"].as_str(), r[0]["ok"].as_bool()), (Some("age"), Some(true)));
        assert_eq!((r[0]["previous"].as_str(), r[0]["current"].as_str()), (Some("1791778208"), Some("1791799808")));
        assert_eq!((r[0]["used_percent"].as_u64(), r[0]["age_hours"].as_f64()), (Some(41), Some(6.0)));
        assert_eq!(r[0]["_raw"], "rotation age ok");
        assert_eq!((r[1]["reason"].as_str(), r[1]["ok"].as_bool()), (Some("retry"), Some(false)));
        for k in ["previous", "current", "used_percent", "age_hours"] {
            assert_eq!(r[1][k], Value::Null, "{k}");
        }
        assert_eq!(r[1]["_raw"], "rotation retry failed");
        assert_eq!(r[2]["current"].as_str().unwrap(), "9".repeat(64), "cut to 64");
        assert_eq!(r[2]["previous"], "ab?cd", "printable only");
        assert_eq!(r[2]["age_hours"], 1.3, "one decimal");
    }

    #[test]
    fn capture_names_are_printable_and_at_most_64_chars() {
        let mut n = note();
        n.capture = format!("{}\u{1b}[31m", "9".repeat(70));
        let e = notification_event(&n, "sent", now());
        assert_eq!(e["capture"].as_str().unwrap(), "9".repeat(64));
        n.capture = "ab\ncd".into();
        assert_eq!(notification_event(&n, "sent", now())["capture"], "ab?cd");
    }

    // ---- options ----

    #[test]
    fn options_decide_on_or_off() {
        let on = |u, t, c| config(u, t, c).is_some();
        assert!(!on(None, None, None), "absent: off");
        assert!(!on(Some("  "), Some(""), Some("")), "blank: off");
        assert!(!on(Some("http://192.0.2.10:9443/cribl/_bulk"), Some("t"), Some(LEAF)), "http: off");
        assert!(!on(Some("not a url"), Some("t"), Some(LEAF)));
        assert!(!on(Some(URL), None, Some(LEAF)), "no token: off");
        assert!(!on(Some(URL), Some("   "), Some(LEAF)), "blank token: off");
        assert!(!on(Some(URL), Some("t"), None), "no PEM: off");
        assert!(!on(Some(URL), Some("t"), Some("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")));
        assert!(!on(Some(URL), Some("t"), Some(LEAF_KEY)), "a key is not a certificate");
        let c = config(Some(URL), Some(" s3cret "), Some(LEAF)).unwrap();
        assert_eq!(c.url.as_str(), URL);
        assert_eq!(c.token, "s3cret");
        assert_eq!(c.certs.len(), 1);
        assert!(!format!("{c:?}").contains("s3cret"), "Debug must not print the token");
    }

    /// Userinfo would make reqwest add a second (basic) Authorization header; a query string
    /// is not part of a Cribl HTTP source URL. Both: off.
    #[test]
    fn a_url_with_userinfo_or_a_query_is_refused() {
        let on = |u: &str| config(Some(u), Some("t"), Some(LEAF)).is_some();
        assert!(!on("https://me:pw@192.0.2.10:9443/cribl/_bulk"));
        assert!(!on("https://me@192.0.2.10:9443/cribl/_bulk"));
        assert!(!on("https://192.0.2.10:9443/cribl/_bulk?token=x"));
        assert!(!on("https://192.0.2.10:9443/cribl/_bulk?"));
        assert!(on(URL));
    }

    /// The token header is marked sensitive (kept out of reqwest's Debug output).
    #[test]
    fn the_token_header_is_sensitive() {
        let cfg = config(Some(URL), Some("s3cret"), Some(LEAF)).unwrap();
        let s = Sender::new(&cfg, SEND_TIMEOUT).unwrap();
        assert!(s.auth.is_sensitive());
        assert_eq!(s.auth.to_str().unwrap(), "s3cret");
        let bad = config(Some(URL), Some("a\u{7f}b"), Some(LEAF)).unwrap();
        assert!(Sender::new(&bad, SEND_TIMEOUT).is_err(), "an unusable token: off");
    }

    /// The HA options form is one line: a pasted PEM arrives with spaces for newlines.
    #[test]
    fn a_pem_flattened_onto_one_line_still_parses() {
        let flat = LEAF.trim().replace('\n', " ");
        let escaped = LEAF.trim().replace('\n', "\\n");
        let want = pem_certs(LEAF).unwrap();
        assert_eq!(want.len(), 1);
        assert_eq!(pem_certs(&flat).unwrap(), want);
        assert_eq!(pem_certs(&escaped).unwrap(), want);
    }

    #[test]
    fn options_json_reaches_the_config() {
        let j = |extra: &str| {
            crate::app::parse_options(&format!(r#"{{"device_url":"u"{extra}}}"#)).unwrap().cribl
        };
        assert!(j("").is_none());
        assert!(j(r#","cribl_url":"","cribl_token":"","cribl_ca":"""#).is_none());
        let pem = serde_json::to_string(LEAF).unwrap();
        let on = j(&format!(r#","cribl_url":"{URL}","cribl_token":"t","cribl_ca":{pem}"#));
        assert!(on.is_some());
    }

    // ---- buffer ----

    fn ev(i: usize) -> Value {
        json!({ "i": i })
    }

    #[test]
    fn the_buffer_keeps_the_newest_1000() {
        let mut b = Buffer::default();
        b.push((0..1005).map(ev).collect());
        assert_eq!(b.len(), BUFFER_MAX);
        assert_eq!(b.take_dropped(), 5);
        assert_eq!(b.take_dropped(), 0, "logged once");
        let (_, body, n) = b.batch().unwrap();
        assert_eq!(n, 1000);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 1000);
        assert_eq!(lines[0], r#"{"i":5}"#, "the oldest went");
        assert_eq!(lines[999], r#"{"i":1004}"#);
    }

    #[test]
    fn a_2xx_clears_only_what_was_sent() {
        let mut b = Buffer::default();
        assert!(b.batch().is_none());
        b.push(vec![ev(1), ev(2)]);
        let (last, _, _) = b.batch().unwrap();
        b.push(vec![ev(3)]); // arrived while sending
        b.ack(last);
        assert_eq!(b.batch().unwrap().1, "{\"i\":3}\n");
        // A failure acks nothing: all of it stays.
        b.push(vec![ev(4)]);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn an_ack_after_the_oldest_were_dropped_clears_only_what_was_sent() {
        let mut b = Buffer::default();
        b.push((0..10).map(ev).collect());
        let (last, _, _) = b.batch().unwrap();
        b.push((10..1005).map(ev).collect()); // 5 of the batch dropped meanwhile
        b.ack(last);
        assert_eq!(b.len(), 995);
        assert!(b.batch().unwrap().1.starts_with("{\"i\":10}\n"));
    }

    // ---- sending, against a local TLS server ----

    struct Got {
        head: String,
        body: String,
    }

    /// A one-thread HTTPS server on 127.0.0.1 with `cert`/`key`, answering `status`.
    fn serve(cert: &str, key: &str, status: u16) -> (u16, std::sync::mpsc::Receiver<Got>) {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        crate::app::install_crypto_provider();
        let certs: Vec<CertificateDer> =
            CertificateDer::pem_slice_iter(cert.as_bytes()).map(|c| c.unwrap()).collect();
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
        // CertifiedKey::new skips the cert/key match check, so a mismatched pair can be served.
        let provider = rustls::crypto::ring::default_provider();
        let signer = provider.key_provider.load_private_key(key).unwrap();
        #[derive(Debug)]
        struct One(Arc<rustls::sign::CertifiedKey>);
        impl rustls::server::ResolvesServerCert for One {
            fn resolve(
                &self,
                _: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                Some(self.0.clone())
            }
        }
        let ck = Arc::new(rustls::sign::CertifiedKey::new(certs, signer));
        let cfg = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(One(ck))),
        );
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { continue };
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(p + 4);
                    }
                };
                let Some(head_end) = head_end else { continue }; // handshake refused
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
                let _ = write!(
                    tls,
                    "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = tls.flush();
                let _ = tx.send(Got { head, body });
            }
        });
        (port, rx)
    }

    fn sender(port: u16, pinned: &str, timeout: Duration) -> Sender {
        let url = format!("https://127.0.0.1:{port}/cribl/_bulk");
        let cfg = config(Some(&url), Some("s3cret-token"), Some(pinned)).unwrap();
        Sender::new(&cfg, timeout).unwrap()
    }

    fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    #[tokio::test]
    async fn the_pinned_cert_is_accepted_and_the_body_is_ndjson() {
        let (port, rx) = serve(LEAF, LEAF_KEY, 200);
        let s = sender(port, LEAF, SEND_TIMEOUT);
        let buf: Shared = Default::default();
        let f = after_cycle(&s, &buf, every_event().into_iter().take(3).collect()).await;
        assert_eq!(f, Flushed::Sent(3));
        assert_eq!(buf.lock().unwrap().len(), 0, "a 2xx clears the buffer");
        let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(got.head.starts_with("POST /cribl/_bulk HTTP/1.1\r\n"), "{}", got.head);
        assert_eq!(header(&got.head, "authorization"), Some("s3cret-token"));
        assert_eq!(header(&got.head, "content-type"), Some("application/json"));
        let lines: Vec<&str> = got.body.lines().collect();
        assert_eq!(lines.len(), 3);
        for l in lines {
            let v: Value = serde_json::from_str(l).unwrap();
            assert!(v["type"].is_string());
        }
        assert_eq!(s.flush(&buf).await, Flushed::Empty);
    }

    /// Made like `openssl req -x509 ...` makes one by default: basicConstraints CA:TRUE.
    const CA_TRUE: &str = include_str!("testdata/cribl/default.crt");
    const CA_TRUE_KEY: &str = include_str!("testdata/cribl/default.key");
    /// A CA:FALSE leaf signed by CA_TRUE's key.
    const SIGNED: &str = include_str!("testdata/cribl/signed.crt");
    const SIGNED_KEY: &str = include_str!("testdata/cribl/signed.key");

    /// webpki refuses a CA:TRUE certificate as a server's (CaUsedAsEndEntity); OpenSSL and
    /// curl accept it, so a cert that passed a curl test can still fail here.
    #[tokio::test]
    async fn an_openssl_default_ca_true_cert_is_accepted_when_pinned() {
        let (port, rx) = serve(CA_TRUE, CA_TRUE_KEY, 200);
        let s = sender(port, CA_TRUE, SEND_TIMEOUT);
        let buf: Shared = Default::default();
        assert_eq!(after_cycle(&s, &buf, vec![ev(1)]).await, Flushed::Sent(1));
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
    }

    /// The pin is the certificate itself, not a trust anchor: a cert its key signed is refused.
    #[tokio::test]
    async fn a_cert_signed_by_the_pinned_one_is_refused() {
        let (port, rx) = serve(SIGNED, SIGNED_KEY, 200);
        let s = sender(port, CA_TRUE, SEND_TIMEOUT);
        let buf: Shared = Default::default();
        assert_eq!(after_cycle(&s, &buf, vec![ev(1)]).await, Flushed::Kept(1));
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    }

    /// The certificate is public: presenting it without its key must fail the handshake.
    #[tokio::test]
    async fn the_pinned_cert_with_another_key_is_refused() {
        let (port, rx) = serve(LEAF, OTHER_KEY, 200);
        let s = sender(port, LEAF, SEND_TIMEOUT);
        let buf: Shared = Default::default();
        assert_eq!(after_cycle(&s, &buf, vec![ev(1)]).await, Flushed::Kept(1));
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    }

    /// Pinning: a server with any other certificate (same name, same IP) is refused.
    #[tokio::test]
    async fn a_different_cert_is_refused_and_the_events_are_kept() {
        let (port, rx) = serve(OTHER, OTHER_KEY, 200);
        let s = sender(port, LEAF, SEND_TIMEOUT);
        let buf: Shared = Default::default();
        let f = after_cycle(&s, &buf, vec![ev(1), ev(2)]).await;
        assert_eq!(f, Flushed::Kept(2));
        assert_eq!(buf.lock().unwrap().len(), 2);
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "no request got through");
    }

    #[tokio::test]
    async fn a_non_2xx_keeps_the_events() {
        let (port, rx) = serve(LEAF, LEAF_KEY, 500);
        let s = sender(port, LEAF, SEND_TIMEOUT);
        let buf: Shared = Default::default();
        assert_eq!(after_cycle(&s, &buf, vec![ev(1)]).await, Flushed::Kept(1));
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
        assert_eq!(buf.lock().unwrap().len(), 1);
    }

    /// The log line for a failed send names no option value: not the host, port or path.
    #[tokio::test]
    async fn a_failed_send_is_described_without_its_url() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l); // nothing listens: connection refused
        let url = format!("https://127.0.0.1:{port}/very-private-path");
        let cfg = config(Some(&url), Some("t"), Some(LEAF)).unwrap();
        let s = Sender::new(&cfg, SEND_TIMEOUT).unwrap();
        let e = s.client.post(s.url.clone()).body("x").send().await.unwrap_err();
        assert!(error_chain(&e).contains("very-private-path"), "control: reqwest does add it");
        let line = describe(e);
        for bad in ["very-private-path", "127.0.0.1", &port.to_string(), "https://"] {
            assert!(!line.contains(bad), "{bad:?} in {line:?}");
        }
        assert!(!line.is_empty());
    }

    /// Single flight: a second flush while one is stuck does nothing.
    #[tokio::test]
    async fn one_send_at_a_time() {
        // Accepts and never answers.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let s = Arc::new(sender(port, LEAF, Duration::from_secs(2)));
        let buf: Shared = Default::default();
        push(Some(&buf), vec![ev(1)]);
        let (s2, b2) = (s.clone(), buf.clone());
        let first = tokio::spawn(async move { s2.flush(&b2).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(s.flush(&buf).await, Flushed::Busy);
        assert_eq!(first.await.unwrap(), Flushed::Kept(1), "timed out, kept");
        drop(l);
    }
}
