//! The add-on's view of the M2100: a trait (so the puller can be tested against a fake),
//! the real HTTP client, and (in tests) a scriptable in-memory fake.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub start: DateTime<Utc>,
    pub last_message: Option<DateTime<Utc>>,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceError {
    Unreachable,
    NotFound,
    Busy,
    Refused,
    Bad(String),
}

#[async_trait]
pub trait Device: Send + Sync {
    /// Finished recordings only (never the current one).
    async fn finished(&self) -> Result<Vec<Entry>, DeviceError>;
    /// Stream the capture to `to` as gzip; returns the SHA-256 (lowercase hex) of the
    /// uncompressed bytes received. Only `Ok(hash)` means a durable copy exists. On an error
    /// before the rename no file is left at `to`; if the rename succeeded but the
    /// directory sync failed, `Err` is returned and `to` is left in place (untrusted).
    async fn download(&self, name: &str, to: &Path) -> Result<String, DeviceError>;
    /// Save the analysis report body as-is (opaque).
    async fn analysis(&self, name: &str, to: &Path) -> Result<(), DeviceError>;
    /// The device's own SHA-256 of the stored capture; anything but 64 lowercase hex is `Bad`.
    async fn device_sha256(&self, name: &str) -> Result<String, DeviceError>;
    async fn delete(&self, name: &str) -> Result<(), DeviceError>;
    async fn fixed(&self, token: &str) -> Result<bool, DeviceError>;
    /// The unit's live view of the recording in progress (`GET /api/m2100/live`).
    /// 401 is `Refused`; a body over `LIVE_MAX_BODY` or one that does not parse is `Bad`.
    async fn live(&self, token: &str) -> Result<crate::live::Snapshot, DeviceError>;
    /// Capture name -> the profile it was recorded in (`fixed` | `mobile` | `mixed`),
    /// from `GET /api/m2100/capture-profiles`. Values are passed through unchecked.
    async fn capture_profiles(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, DeviceError>;
    /// The name of the recording in progress (the manifest's `current_entry`), if any.
    /// Only the name is read: its times are the unit's clock (attacker-influenced), and a
    /// missing or unparsable one must not block rotation.
    async fn current(&self) -> Result<Option<String>, DeviceError>;
    /// The unit's capture storage use, `disk_stats.used_percent` of `/api/system-stats`
    /// (0..=100; anything else is `Bad`).
    async fn disk_used_percent(&self) -> Result<u32, DeviceError>;
    async fn stop_recording(&self) -> Result<(), DeviceError>;
    /// Closes the current capture (if any) and opens a new one.
    async fn start_recording(&self) -> Result<(), DeviceError>;
}

/// No bytes received for this long while downloading -> give up.
pub const DOWNLOAD_IDLE: Duration = Duration::from_secs(60);
/// Hard deadline for one download (or one device-side hash, which is computed before
/// the first byte is sent).
pub const DOWNLOAD_TOTAL: Duration = Duration::from_secs(60 * 60);
/// Every other call.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// The live view is polled every minute; give up well before the next poll.
pub const LIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Http {
    base: String,
    client: reqwest::Client,
    idle: Duration,
    total: Duration,
    timeout: Duration,
}

impl Http {
    pub fn device(base: &str) -> Self {
        Self::new(base, DOWNLOAD_IDLE, DOWNLOAD_TOTAL, TIMEOUT)
    }

    pub fn new(base: &str, idle: Duration, total: Duration, timeout: Duration) -> Self {
        Http {
            base: base.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .connect_timeout(timeout)
                .build()
                .expect("http client"),
            idle,
            total,
            timeout,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        timeout: Duration,
    ) -> Result<reqwest::Response, DeviceError> {
        // A per-request timeout covers the whole exchange, body included.
        req.timeout(timeout).send().await.map_err(net_err)
    }
}

fn net_err(_: reqwest::Error) -> DeviceError {
    DeviceError::Unreachable
}

/// Statuses shared by every call; `Ok(resp)` only for 2xx.
fn check(resp: reqwest::Response) -> Result<reqwest::Response, DeviceError> {
    use reqwest::StatusCode as S;
    match resp.status() {
        s if s.is_success() => Ok(resp),
        S::NOT_FOUND => Err(DeviceError::NotFound),
        S::CONFLICT => Err(DeviceError::Busy),
        S::FORBIDDEN => Err(DeviceError::Refused),
        s => Err(DeviceError::Bad(format!("unexpected status {s}"))),
    }
}

fn io_err(e: std::io::Error) -> DeviceError {
    DeviceError::Bad(format!("local io: {e}"))
}

#[derive(Deserialize)]
struct Manifest {
    entries: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    name: String,
    start_time: DateTime<Utc>,
    last_message_time: Option<DateTime<Utc>>,
    qmdl_size_bytes: u64,
}

/// Stream `resp` into `part` as gzip, hashing the raw bytes; fsyncs. Returns the hash.
async fn stream_gz(
    resp: reqwest::Response,
    part: &Path,
    idle: Duration,
) -> Result<String, DeviceError> {
    use std::io::Write;
    let mut file = tokio::fs::File::create(part).await.map_err(io_err)?;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = tokio::time::timeout(idle, stream.next())
        .await
        .map_err(|_| DeviceError::Unreachable)?
    {
        let chunk = chunk.map_err(net_err)?;
        hasher.update(&chunk);
        enc.write_all(&chunk).map_err(io_err)?;
        if !enc.get_ref().is_empty() {
            file.write_all(enc.get_ref()).await.map_err(io_err)?;
            enc.get_mut().clear();
        }
    }
    let tail = enc.finish().map_err(io_err)?;
    file.write_all(&tail).await.map_err(io_err)?;
    file.flush().await.map_err(io_err)?;
    file.sync_all().await.map_err(io_err)?;
    Ok(hex(&hasher.finalize()))
}

/// fsync a directory so a rename inside it is durable.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

async fn sync_parent(to: &Path) -> std::io::Result<()> {
    let dir = match to.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    tokio::task::spawn_blocking(move || sync_dir(&dir))
        .await
        .map_err(std::io::Error::other)?
}

fn part_path(to: &Path) -> PathBuf {
    let mut s = to.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

#[async_trait]
impl Device for Http {
    async fn finished(&self) -> Result<Vec<Entry>, DeviceError> {
        let resp = self
            .send(
                self.client.get(self.url("/api/qmdl-manifest")),
                self.timeout,
            )
            .await?;
        let m: Manifest = check(resp)?.json().await.map_err(|e| {
            if e.is_decode() {
                DeviceError::Bad(e.to_string())
            } else {
                DeviceError::Unreachable
            }
        })?;
        // `current_entry` is deliberately never read: it is still being written.
        Ok(m.entries
            .into_iter()
            .map(|e| Entry {
                name: e.name,
                start: e.start_time,
                last_message: e.last_message_time,
                size: e.qmdl_size_bytes,
            })
            .collect())
    }

    async fn download(&self, name: &str, to: &Path) -> Result<String, DeviceError> {
        // `total` bounds the whole exchange, body included; `idle` bounds the wait for
        // headers and each gap between chunks.
        let resp = tokio::time::timeout(
            self.idle,
            self.send(
                self.client.get(self.url(&format!("/api/qmdl/{name}"))),
                self.total,
            ),
        )
        .await
        .map_err(|_| DeviceError::Unreachable)??;
        let resp = check(resp)?;
        let part = part_path(to);
        let r = stream_gz(resp, &part, self.idle).await;
        match r {
            Ok(hash) => match tokio::fs::rename(&part, to).await {
                // Err (leaving `to`) if the rename may not be durable: the caller
                // must not delete the device copy on that basis.
                Ok(()) => sync_parent(to).await.map(|()| hash).map_err(io_err),
                Err(e) => {
                    let _ = tokio::fs::remove_file(&part).await;
                    Err(io_err(e))
                }
            },
            Err(e) => {
                let _ = tokio::fs::remove_file(&part).await;
                Err(e)
            }
        }
    }

    async fn analysis(&self, name: &str, to: &Path) -> Result<(), DeviceError> {
        // A report can be as long as its capture: the download's timeouts, not the
        // short one (`total` for the whole exchange, `idle` for headers and each gap).
        let resp = tokio::time::timeout(
            self.idle,
            self.send(
                self.client
                    .get(self.url(&format!("/api/analysis-report/{name}"))),
                self.total,
            ),
        )
        .await
        .map_err(|_| DeviceError::Unreachable)??;
        let resp = check(resp)?;
        let part = part_path(to);
        let w = async {
            let mut f = tokio::fs::File::create(&part).await.map_err(io_err)?;
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = tokio::time::timeout(self.idle, stream.next())
                .await
                .map_err(|_| DeviceError::Unreachable)?
            {
                f.write_all(&chunk.map_err(net_err)?)
                    .await
                    .map_err(io_err)?;
            }
            f.sync_all().await.map_err(io_err)?;
            tokio::fs::rename(&part, to).await.map_err(io_err)
        };
        match w.await {
            Ok(()) => sync_parent(to).await.map_err(io_err),
            Err(e) => {
                let _ = tokio::fs::remove_file(&part).await;
                Err(e)
            }
        }
    }

    async fn device_sha256(&self, name: &str) -> Result<String, DeviceError> {
        let resp = self
            .send(
                self.client
                    .get(self.url(&format!("/api/m2100/sha256/{name}"))),
                self.total,
            )
            .await?;
        // 5xx is the unit failing to read the file: retry later. Only a malformed body
        // (or another unexpected status) is `Bad`, which the puller counts as a mismatch.
        if resp.status().is_server_error() {
            return Err(DeviceError::Unreachable);
        }
        let body = check(resp)?.text().await.map_err(net_err)?;
        let h = body.trim_end_matches('\n');
        if h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(h.to_string())
        } else {
            Err(DeviceError::Bad(
                "device returned a malformed sha256".into(),
            ))
        }
    }

    async fn delete(&self, name: &str) -> Result<(), DeviceError> {
        let resp = self
            .send(
                self.client
                    .post(self.url(&format!("/api/delete-recording/{name}"))),
                self.timeout,
            )
            .await?;
        if resp.status() == reqwest::StatusCode::BAD_REQUEST {
            return Err(DeviceError::NotFound);
        }
        check(resp).map(|_| ())
    }

    async fn fixed(&self, token: &str) -> Result<bool, DeviceError> {
        let req = self
            .client
            .post(self.url("/api/m2100/fixed"))
            .header("Authorization", format!("Bearer {token}"));
        let resp = self.send(req, self.timeout).await?;
        match resp.status() {
            reqwest::StatusCode::UNAUTHORIZED => return Err(DeviceError::Refused),
            reqwest::StatusCode::TOO_MANY_REQUESTS => return Err(DeviceError::Busy),
            _ => {}
        }
        let v: serde_json::Value = check(resp)?
            .json()
            .await
            .map_err(|e| DeviceError::Bad(e.to_string()))?;
        v.get("ok")
            .and_then(|b| b.as_bool())
            .ok_or_else(|| DeviceError::Bad("fixed: missing ok".into()))
    }

    async fn live(&self, token: &str) -> Result<crate::live::Snapshot, DeviceError> {
        let req = self
            .client
            .get(self.url("/api/m2100/live"))
            .header("Authorization", format!("Bearer {token}"));
        let resp = self.send(req, LIVE_TIMEOUT).await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DeviceError::Refused);
        }
        let resp = check(resp)?;
        let max = crate::live::LIVE_MAX_BODY;
        if resp.content_length().is_some_and(|n| n > max as u64) {
            return Err(DeviceError::Bad("live: body too large".into()));
        }
        // Never buffer more than the limit, whatever the unit claims.
        let mut body: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(net_err)?;
            if body.len() + chunk.len() > max {
                return Err(DeviceError::Bad("live: body too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        crate::live::parse(&body).map_err(DeviceError::Bad)
    }

    async fn capture_profiles(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, DeviceError> {
        let resp = self
            .send(
                self.client.get(self.url("/api/m2100/capture-profiles")),
                self.timeout,
            )
            .await?;
        check(resp)?
            .json()
            .await
            .map_err(|e| DeviceError::Bad(e.to_string()))
    }

    async fn current(&self) -> Result<Option<String>, DeviceError> {
        // Its own structs: `finished` must keep ignoring `current_entry` (a malformed one
        // must not stop the pulls), and only the name is read here.
        #[derive(Deserialize)]
        struct Name {
            name: String,
        }
        #[derive(Deserialize)]
        struct Current {
            current_entry: Option<Name>,
        }
        let resp = self
            .send(
                self.client.get(self.url("/api/qmdl-manifest")),
                self.timeout,
            )
            .await?;
        let m: Current = check(resp)?.json().await.map_err(|e| {
            if e.is_decode() {
                DeviceError::Bad(e.to_string())
            } else {
                DeviceError::Unreachable
            }
        })?;
        Ok(m.current_entry.map(|e| e.name))
    }

    async fn disk_used_percent(&self) -> Result<u32, DeviceError> {
        let resp = self
            .send(
                self.client.get(self.url("/api/system-stats")),
                self.timeout,
            )
            .await?;
        let v: serde_json::Value = check(resp)?.json().await.map_err(|e| {
            if e.is_decode() {
                DeviceError::Bad(e.to_string())
            } else {
                DeviceError::Unreachable
            }
        })?;
        // The daemon sends e.g. "86%".
        v.get("disk_stats")
            .and_then(|d| d.get("used_percent"))
            .and_then(|p| p.as_str())
            .and_then(|p| p.trim().strip_suffix('%'))
            .and_then(|p| p.parse::<u32>().ok())
            .filter(|p| *p <= 100)
            .ok_or_else(|| DeviceError::Bad("system-stats: no usable used_percent".into()))
    }

    async fn stop_recording(&self) -> Result<(), DeviceError> {
        let resp = self
            .send(
                self.client.post(self.url("/api/stop-recording")),
                self.timeout,
            )
            .await?;
        check(resp).map(|_| ())
    }

    async fn start_recording(&self) -> Result<(), DeviceError> {
        let resp = self
            .send(
                self.client.post(self.url("/api/start-recording")),
                self.timeout,
            )
            .await?;
        check(resp).map(|_| ())
    }
}

#[cfg(test)]
pub use fake::Fake;

#[cfg(test)]
mod fake {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use tokio::sync::Semaphore;

    #[derive(Default)]
    struct Capture {
        bytes: Vec<u8>,
        hash_override: Option<String>,
        analysis: Option<Vec<u8>>,
    }

    #[derive(Default)]
    struct State {
        entries: Vec<Entry>,
        captures: HashMap<String, Capture>,
        log: Vec<String>,
        once: HashMap<String, VecDeque<DeviceError>>,
        always: HashMap<String, DeviceError>,
        gates: HashMap<String, Arc<Semaphore>>,
        fixed: Option<Result<bool, DeviceError>>,
        live: Option<Result<crate::live::Snapshot, DeviceError>>,
        profiles: HashMap<String, String>,
        /// The recording in progress, as the manifest's `current_entry` shows it.
        current: Option<Entry>,
        /// `disk_stats.used_percent`.
        disk: u32,
        /// The unit's own clock: the start time it gives a new recording.
        unit_clock: Option<DateTime<Utc>>,
        /// `start_recording` answers Ok but starts nothing.
        start_noop: bool,
        /// Names given to new recordings: 1_800_000_001, 1_800_000_002...
        started: u64,
    }

    /// In-memory device. Every call is logged in order as `"<method> <name>"`
    /// (`"finished"` and `"fixed"` have no name). Errors are scripted per log key,
    /// e.g. `fail("download a", DeviceError::Unreachable)`.
    #[derive(Default)]
    pub struct Fake {
        s: Mutex<State>,
    }

    impl Fake {
        pub fn new() -> Self {
            Self::default()
        }
        /// Add a finished capture serving `bytes` (and an analysis report).
        pub fn add(&self, name: &str, bytes: &[u8]) {
            let mut s = self.s.lock().unwrap();
            let start = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
            s.entries.push(Entry {
                name: name.into(),
                start,
                last_message: Some(start),
                size: bytes.len() as u64,
            });
            s.captures.insert(
                name.into(),
                Capture {
                    bytes: bytes.to_vec(),
                    analysis: Some(format!("analysis of {name}\n").into_bytes()),
                    ..Default::default()
                },
            );
        }
        /// Add a finished capture with an explicit start. Like the unit, a name that is
        /// already stored is overwritten (its files now hold `bytes`); entries already
        /// listed under that name stay listed (the unit's manifest keeps them).
        pub fn add_at(&self, name: &str, bytes: &[u8], start: DateTime<Utc>) {
            let mut s = self.s.lock().unwrap();
            s.entries.push(Entry {
                name: name.into(),
                start,
                last_message: Some(start),
                size: bytes.len() as u64,
            });
            s.captures.insert(
                name.into(),
                Capture {
                    bytes: bytes.to_vec(),
                    analysis: Some(format!("analysis of {name}\n").into_bytes()),
                    ..Default::default()
                },
            );
        }
        /// SHA-256 of the bytes the unit holds under `name` right now (ignores any
        /// scripted hash override).
        pub fn true_sha256(&self, name: &str) -> Option<String> {
            let s = self.s.lock().unwrap();
            s.captures.get(name).map(|c| sha256_hex(&c.bytes))
        }
        /// Make the device report this hash instead of the true one.
        pub fn set_device_hash(&self, name: &str, hash: &str) {
            let mut s = self.s.lock().unwrap();
            s.captures.get_mut(name).unwrap().hash_override = Some(hash.into());
        }
        pub fn set_analysis(&self, name: &str, body: &[u8]) {
            let mut s = self.s.lock().unwrap();
            s.captures.get_mut(name).unwrap().analysis = Some(body.to_vec());
        }
        pub fn set_profile(&self, name: &str, profile: &str) {
            self.s
                .lock()
                .unwrap()
                .profiles
                .insert(name.into(), profile.into());
        }
        pub fn set_live(&self, r: Result<crate::live::Snapshot, DeviceError>) {
            self.s.lock().unwrap().live = Some(r);
        }
        pub fn set_fixed(&self, r: Result<bool, DeviceError>) {
            self.s.lock().unwrap().fixed = Some(r);
        }
        /// Fail the next call whose log key is `key`.
        pub fn fail_once(&self, key: &str, e: DeviceError) {
            let mut s = self.s.lock().unwrap();
            s.once.entry(key.into()).or_default().push_back(e);
        }
        /// Fail every call whose log key is `key`.
        pub fn fail(&self, key: &str, e: DeviceError) {
            self.s.lock().unwrap().always.insert(key.into(), e);
        }
        /// Calls to `method` ("download", "analysis", "device_sha256", "delete", "finished",
        /// "fixed") block after being logged until `release(method, n)`.
        pub fn gate(&self, method: &str) {
            self.s
                .lock()
                .unwrap()
                .gates
                .insert(method.into(), Arc::new(Semaphore::new(0)));
        }
        pub fn release(&self, method: &str, n: usize) {
            let g = self.s.lock().unwrap().gates[method].clone();
            g.add_permits(n);
        }
        pub fn log(&self) -> Vec<String> {
            self.s.lock().unwrap().log.clone()
        }
        /// The recording in progress: stored on the device, but never listed by `finished`.
        pub fn add_current(&self, name: &str, bytes: &[u8]) {
            self.s.lock().unwrap().captures.insert(
                name.into(),
                Capture {
                    bytes: bytes.to_vec(),
                    ..Default::default()
                },
            );
        }
        /// A recording in progress that the manifest shows as `current_entry`, stamped
        /// `start` by the unit's clock. `stop_recording`/`start_recording` finish it.
        pub fn set_current(&self, name: &str, bytes: &[u8], start: DateTime<Utc>) {
            self.add_current(name, bytes);
            self.set_analysis(name, format!("analysis of {name}\n").as_bytes());
            self.s.lock().unwrap().current = Some(Entry {
                name: name.into(),
                start,
                last_message: Some(start),
                size: bytes.len() as u64,
            });
        }
        pub fn current_name(&self) -> Option<String> {
            self.s.lock().unwrap().current.as_ref().map(|e| e.name.clone())
        }
        pub fn set_disk(&self, used_percent: u32) {
            self.s.lock().unwrap().disk = used_percent;
        }
        /// The start time the unit stamps on recordings it starts from now on.
        pub fn set_unit_clock(&self, t: DateTime<Utc>) {
            self.s.lock().unwrap().unit_clock = Some(t);
        }
        pub fn set_start_noop(&self, v: bool) {
            self.s.lock().unwrap().start_noop = v;
        }
        /// Undo `fail(key, ..)`.
        pub fn unfail(&self, key: &str) {
            self.s.lock().unwrap().always.remove(key);
        }
        /// The capture disappears from the unit (e.g. deleted by hand in the web UI).
        pub fn remove(&self, name: &str) {
            let mut s = self.s.lock().unwrap();
            s.captures.remove(name);
            s.entries.retain(|e| e.name != name);
        }
        pub fn has(&self, name: &str) -> bool {
            self.s.lock().unwrap().captures.contains_key(name)
        }

        /// Log the call, wait at its gate, then return any scripted error.
        async fn enter(&self, method: &str, name: Option<&str>) -> Result<(), DeviceError> {
            let key = match name {
                Some(n) => format!("{method} {n}"),
                None => method.to_string(),
            };
            let gate = {
                let mut s = self.s.lock().unwrap();
                s.log.push(key.clone());
                s.gates.get(method).cloned()
            };
            if let Some(g) = gate {
                g.acquire().await.unwrap().forget();
            }
            let mut s = self.s.lock().unwrap();
            if let Some(e) = s.once.get_mut(&key).and_then(|q| q.pop_front()) {
                return Err(e);
            }
            if let Some(e) = s.always.get(&key) {
                return Err(e.clone());
            }
            Ok(())
        }
    }

    #[async_trait]
    impl Device for Fake {
        async fn finished(&self) -> Result<Vec<Entry>, DeviceError> {
            self.enter("finished", None).await?;
            Ok(self.s.lock().unwrap().entries.clone())
        }
        async fn download(&self, name: &str, to: &Path) -> Result<String, DeviceError> {
            self.enter("download", Some(name)).await?;
            let bytes = self
                .s
                .lock()
                .unwrap()
                .captures
                .get(name)
                .ok_or(DeviceError::NotFound)?
                .bytes
                .clone();
            std::fs::write(to, gzip(&bytes)).map_err(|e| DeviceError::Bad(e.to_string()))?;
            Ok(sha256_hex(&bytes))
        }
        async fn analysis(&self, name: &str, to: &Path) -> Result<(), DeviceError> {
            self.enter("analysis", Some(name)).await?;
            let body = self
                .s
                .lock()
                .unwrap()
                .captures
                .get(name)
                .and_then(|c| c.analysis.clone())
                .ok_or(DeviceError::NotFound)?;
            std::fs::write(to, body).map_err(|e| DeviceError::Bad(e.to_string()))
        }
        async fn device_sha256(&self, name: &str) -> Result<String, DeviceError> {
            self.enter("device_sha256", Some(name)).await?;
            let s = self.s.lock().unwrap();
            let c = s.captures.get(name).ok_or(DeviceError::NotFound)?;
            Ok(c.hash_override
                .clone()
                .unwrap_or_else(|| sha256_hex(&c.bytes)))
        }
        async fn delete(&self, name: &str) -> Result<(), DeviceError> {
            self.enter("delete", Some(name)).await?;
            let mut s = self.s.lock().unwrap();
            s.captures.remove(name).ok_or(DeviceError::NotFound)?;
            s.entries.retain(|e| e.name != name);
            Ok(())
        }
        async fn fixed(&self, _token: &str) -> Result<bool, DeviceError> {
            self.enter("fixed", None).await?;
            self.s.lock().unwrap().fixed.clone().unwrap_or(Ok(true))
        }
        async fn live(&self, _token: &str) -> Result<crate::live::Snapshot, DeviceError> {
            self.enter("live", None).await?;
            self.s
                .lock()
                .unwrap()
                .live
                .clone()
                .unwrap_or(Err(DeviceError::Unreachable))
        }
        async fn capture_profiles(&self) -> Result<HashMap<String, String>, DeviceError> {
            self.enter("capture_profiles", None).await?;
            Ok(self.s.lock().unwrap().profiles.clone())
        }
        async fn current(&self) -> Result<Option<String>, DeviceError> {
            self.enter("current", None).await?;
            Ok(self.s.lock().unwrap().current.as_ref().map(|e| e.name.clone()))
        }
        async fn disk_used_percent(&self) -> Result<u32, DeviceError> {
            self.enter("disk", None).await?;
            Ok(self.s.lock().unwrap().disk)
        }
        async fn stop_recording(&self) -> Result<(), DeviceError> {
            self.enter("stop_recording", None).await?;
            let mut s = self.s.lock().unwrap();
            if let Some(e) = s.current.take() {
                s.entries.push(e);
            }
            Ok(())
        }
        async fn start_recording(&self) -> Result<(), DeviceError> {
            self.enter("start_recording", None).await?;
            let mut s = self.s.lock().unwrap();
            if s.start_noop {
                return Ok(());
            }
            // Like the daemon: an open recording is closed first.
            if let Some(e) = s.current.take() {
                s.entries.push(e);
            }
            s.started += 1;
            let name = (1_800_000_000 + s.started).to_string();
            let start = s
                .unit_clock
                .unwrap_or_else(|| DateTime::from_timestamp(1_800_000_000, 0).unwrap());
            let bytes = format!("recording {name}").into_bytes();
            s.current = Some(Entry {
                name: name.clone(),
                start,
                last_message: Some(start),
                size: bytes.len() as u64,
            });
            s.captures.insert(
                name.clone(),
                Capture {
                    bytes,
                    analysis: Some(format!("analysis of {name}\n").into_bytes()),
                    ..Default::default()
                },
            );
            Ok(())
        }
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    const T: Duration = Duration::from_secs(5);

    fn http(url: &str) -> Http {
        Http::new(url, T, T, T)
    }

    fn sha(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    #[tokio::test]
    async fn capture_profiles_maps_names_and_old_daemons_are_errors() {
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/m2100/capture-profiles")
            .with_body(r#"{"a":"fixed","b":"mixed"}"#)
            .create_async()
            .await;
        let got = http(&s.url()).capture_profiles().await.unwrap();
        assert_eq!(got["a"], "fixed");
        assert_eq!(got["b"], "mixed");
        // an older daemon: the route does not exist
        let s2 = mockito::Server::new_async().await;
        assert!(http(&s2.url()).capture_profiles().await.is_err());
    }

    #[tokio::test]
    async fn finished_ignores_current_entry_and_maps_times_to_utc() {
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/qmdl-manifest")
            .with_body(r#"{"entries":[{"name":"a","start_time":"2026-10-08T21:02:16.338439102-07:00","last_message_time":null,"qmdl_size_bytes":42,"arch":"x"}],
              "current_entry":{"name":"cur","start_time":"2026-10-08T22:00:00-07:00","last_message_time":null,"qmdl_size_bytes":1}}"#)
            .create_async().await;
        let got = http(&s.url()).finished().await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "a");
        assert_eq!(got[0].size, 42);
        assert_eq!(got[0].last_message, None);
        assert_eq!(
            got[0].start,
            "2026-10-09T04:02:16.338439102Z"
                .parse::<DateTime<Utc>>()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn current_reads_only_current_entry() {
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/qmdl-manifest")
            .with_body(r#"{"entries":[{"name":"a","start_time":"2026-10-08T21:02:16-07:00","last_message_time":null,"qmdl_size_bytes":42}],
              "current_entry":{"name":"cur","start_time":"2099-01-01T00:00:00Z","last_message_time":null,"qmdl_size_bytes":1}}"#)
            .create_async().await;
        assert_eq!(http(&s.url()).current().await, Ok(Some("cur".to_string())));
        // Only the name is read: a missing or unparsable time changes nothing.
        let mut s4 = mockito::Server::new_async().await;
        s4.mock("GET", "/api/qmdl-manifest")
            .with_body(r#"{"entries":[{"broken":true}],"current_entry":{"name":"cur2","start_time":"yesterday"}}"#)
            .create_async().await;
        assert_eq!(http(&s4.url()).current().await, Ok(Some("cur2".to_string())));
        let mut s2 = mockito::Server::new_async().await;
        s2.mock("GET", "/api/qmdl-manifest")
            .with_body(r#"{"entries":[],"current_entry":null}"#)
            .create_async().await;
        assert_eq!(http(&s2.url()).current().await, Ok(None));
        // A malformed current entry is the unit's problem, never "nothing recording".
        let mut s3 = mockito::Server::new_async().await;
        s3.mock("GET", "/api/qmdl-manifest")
            .with_body(r#"{"entries":[],"current_entry":{"name":7}}"#)
            .create_async().await;
        assert!(matches!(http(&s3.url()).current().await, Err(DeviceError::Bad(_))));
    }

    #[tokio::test]
    async fn disk_used_percent_parses_and_bounds_the_units_text() {
        let cases = [
            (r#"{"disk_stats":{"used_percent":"86%"}}"#, Some(86)),
            (r#"{"disk_stats":{"used_percent":"0%"}}"#, Some(0)),
            (r#"{"disk_stats":{"used_percent":"100%"}}"#, Some(100)),
            (r#"{"disk_stats":{"used_percent":"101%"}}"#, None),
            (r#"{"disk_stats":{"used_percent":"-3%"}}"#, None),
            (r#"{"disk_stats":{"used_percent":"lots"}}"#, None),
            (r#"{"disk_stats":{}}"#, None),
            ("not json", None),
        ];
        for (body, want) in cases {
            let mut s = mockito::Server::new_async().await;
            s.mock("GET", "/api/system-stats").with_body(body).create_async().await;
            let r = http(&s.url()).disk_used_percent().await;
            match want {
                Some(p) => assert_eq!(r, Ok(p), "{body}"),
                None => assert!(matches!(r, Err(DeviceError::Bad(_))), "{body}: {r:?}"),
            }
        }
    }

    #[tokio::test]
    async fn stop_and_start_recording_post_and_map_statuses() {
        let mut s = mockito::Server::new_async().await;
        let stop = s.mock("POST", "/api/stop-recording").with_status(202).with_body("ok")
            .expect(1).create_async().await;
        let start = s.mock("POST", "/api/start-recording").with_status(202).with_body("ok")
            .expect(1).create_async().await;
        let h = http(&s.url());
        assert_eq!(h.stop_recording().await, Ok(()));
        assert_eq!(h.start_recording().await, Ok(()));
        stop.assert_async().await;
        start.assert_async().await;
        let mut s2 = mockito::Server::new_async().await;
        s2.mock("POST", "/api/start-recording").with_status(507).create_async().await;
        s2.mock("POST", "/api/stop-recording").with_status(403).create_async().await;
        let h = http(&s2.url());
        assert!(matches!(h.start_recording().await, Err(DeviceError::Bad(_))));
        assert_eq!(h.stop_recording().await, Err(DeviceError::Refused));
    }

    #[tokio::test]
    async fn download_gzips_and_hashes_the_served_bytes() {
        let body: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/qmdl/a")
            .with_body(&body)
            .create_async()
            .await;
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("a.qmdl.gz");
        let h = http(&s.url()).download("a", &to).await.unwrap();
        assert_eq!(h, sha(&body));
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(&to).unwrap())
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, body);
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temp left"
        );
    }

    #[tokio::test]
    async fn download_error_statuses_leave_no_file() {
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/qmdl/gone")
            .with_status(404)
            .create_async()
            .await;
        s.mock("GET", "/api/qmdl/cur")
            .with_status(409)
            .create_async()
            .await;
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("x.gz");
        assert_eq!(
            http(&s.url()).download("gone", &to).await,
            Err(DeviceError::NotFound)
        );
        assert_eq!(
            http(&s.url()).download("cur", &to).await,
            Err(DeviceError::Busy)
        );
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn dropped_connection_mid_body_errs_and_leaves_no_file() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf).await;
            c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100000\r\n\r\n0123456789")
                .await
                .unwrap();
            c.flush().await.unwrap();
            // drop: connection closes short
        });
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("a.gz");
        let r = http(&format!("http://127.0.0.1:{port}"))
            .download("a", &to)
            .await;
        assert!(r.is_err(), "{r:?}");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn analysis_saved_as_is() {
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/analysis-report/a")
            .with_body("{\"x\":1}\n{\"y\":2}\n")
            .create_async()
            .await;
        s.mock("GET", "/api/analysis-report/none")
            .with_status(404)
            .create_async()
            .await;
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("a.ndjson");
        http(&s.url()).analysis("a", &to).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&to).unwrap(),
            "{\"x\":1}\n{\"y\":2}\n"
        );
        let to2 = d.path().join("n.ndjson");
        assert_eq!(
            http(&s.url()).analysis("none", &to2).await,
            Err(DeviceError::NotFound)
        );
        assert!(!to2.exists());
    }

    #[tokio::test]
    async fn device_sha256_validates_shape() {
        let good = "a".repeat(32) + &"0123456789abcdef".repeat(2);
        let cases: Vec<(&str, String, bool)> = vec![
            ("ok", good.clone(), true),
            ("short", good[..63].to_string(), false),
            ("long", format!("{good}0"), false),
            ("upper", good.to_uppercase().replace('0', "A"), false),
            ("nonhex", "g".repeat(64), false),
            ("empty", String::new(), false),
        ];
        let mut s = mockito::Server::new_async().await;
        for (n, body, _) in &cases {
            s.mock("GET", format!("/api/m2100/sha256/{n}").as_str())
                .with_body(body)
                .create_async()
                .await;
        }
        let h = http(&s.url());
        for (n, body, ok) in &cases {
            let r = h.device_sha256(n).await;
            if *ok {
                assert_eq!(r, Ok(body.clone()), "{n}");
            } else {
                assert!(matches!(r, Err(DeviceError::Bad(_))), "{n}: {r:?}");
            }
        }
    }

    #[tokio::test]
    async fn device_sha256_status_mapping() {
        let mut s = mockito::Server::new_async().await;
        for (n, c) in [("nf", 404), ("cur", 409), ("err", 500), ("unavail", 503)] {
            s.mock("GET", format!("/api/m2100/sha256/{n}").as_str())
                .with_status(c)
                .create_async()
                .await;
        }
        let h = http(&s.url());
        assert_eq!(h.device_sha256("nf").await, Err(DeviceError::NotFound));
        assert_eq!(h.device_sha256("cur").await, Err(DeviceError::Busy));
        // A device-side read error is transient, never a mismatch (Bad would count one).
        assert_eq!(h.device_sha256("err").await, Err(DeviceError::Unreachable));
        assert_eq!(
            h.device_sha256("unavail").await,
            Err(DeviceError::Unreachable)
        );
    }

    #[tokio::test]
    async fn delete_maps_statuses() {
        let mut s = mockito::Server::new_async().await;
        for (n, c) in [("a", 202), ("b", 400), ("c", 403), ("d", 500)] {
            s.mock("POST", format!("/api/delete-recording/{n}").as_str())
                .with_status(c)
                .with_body("x")
                .create_async()
                .await;
        }
        let h = http(&s.url());
        assert_eq!(h.delete("a").await, Ok(()));
        assert_eq!(h.delete("b").await, Err(DeviceError::NotFound));
        assert_eq!(h.delete("c").await, Err(DeviceError::Refused));
        assert!(matches!(h.delete("d").await, Err(DeviceError::Bad(_))));
    }

    fn live_body() -> String {
        r#"{"version":1,"recording":"1800000001","towers":[{"plmn":"310-260","tac":1,"cell":2,"pci":3,"earfcn":4,"first":null,"last":null,"hits":1}],"towers_capped":false,"identity":[],"identity_total":0,"warnings":[],"warnings_total":0,"warnings_high_total":0}"#.to_string()
    }

    #[tokio::test]
    async fn live_sends_bearer() {
        let mut s = mockito::Server::new_async().await;
        let m = s
            .mock("GET", "/api/m2100/live")
            .match_header("authorization", "Bearer tok123")
            .with_body(live_body())
            .expect(1)
            .create_async()
            .await;
        let snap = http(&s.url()).live("tok123").await.unwrap();
        m.assert_async().await;
        assert_eq!(snap.towers[0].key, "sib1:310-260:1:2");
    }

    #[tokio::test]
    async fn live_401_is_refused() {
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/m2100/live")
            .with_status(401)
            .create_async()
            .await;
        assert_eq!(http(&s.url()).live("t").await, Err(DeviceError::Refused));
    }

    #[tokio::test]
    async fn live_oversized_and_malformed_are_bad() {
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/m2100/live")
            .with_body(vec![b' '; crate::live::LIVE_MAX_BODY + 1])
            .create_async()
            .await;
        assert!(matches!(http(&s.url()).live("t").await, Err(DeviceError::Bad(_))));
        let mut s2 = mockito::Server::new_async().await;
        s2.mock("GET", "/api/m2100/live")
            .with_body("{}")
            .create_async()
            .await;
        assert!(matches!(http(&s2.url()).live("t").await, Err(DeviceError::Bad(_))));
    }

    #[tokio::test]
    async fn fake_live_logs_and_serves() {
        let f = Fake::new();
        assert!(f.live("t").await.is_err());
        f.set_live(Ok(crate::live::parse(live_body().as_bytes()).unwrap()));
        assert_eq!(f.live("t").await.unwrap().towers.len(), 1);
        assert_eq!(f.log(), vec!["live", "live"]);
    }

    #[tokio::test]
    async fn fixed_sends_bearer_and_maps_statuses() {
        let mut s = mockito::Server::new_async().await;
        let m = s
            .mock("POST", "/api/m2100/fixed")
            .match_header("authorization", "Bearer tok123")
            .with_body(r#"{"ok":true}"#)
            .expect(1)
            .create_async()
            .await;
        assert_eq!(http(&s.url()).fixed("tok123").await, Ok(true));
        m.assert_async().await;

        let mut s2 = mockito::Server::new_async().await;
        s2.mock("POST", "/api/m2100/fixed")
            .with_body(r#"{"ok":false}"#)
            .create_async()
            .await;
        assert_eq!(http(&s2.url()).fixed("t").await, Ok(false));

        for (c, want) in [(401, DeviceError::Refused), (429, DeviceError::Busy)] {
            let mut s3 = mockito::Server::new_async().await;
            s3.mock("POST", "/api/m2100/fixed")
                .with_status(c)
                .create_async()
                .await;
            assert_eq!(http(&s3.url()).fixed("t").await, Err(want));
        }
    }

    #[tokio::test]
    async fn every_call_has_a_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((c, _)) = l.accept().await {
                    held.push(c); // accept, never answer
                }
            }
        });
        let h = Http::new(
            &format!("http://127.0.0.1:{port}"),
            Duration::from_millis(300),
            Duration::from_millis(300),
            Duration::from_millis(300),
        );
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let all = async {
            assert_eq!(h.finished().await, Err(DeviceError::Unreachable));
            assert_eq!(h.download("a", &p).await, Err(DeviceError::Unreachable));
            assert_eq!(h.analysis("a", &p).await, Err(DeviceError::Unreachable));
            assert_eq!(h.device_sha256("a").await, Err(DeviceError::Unreachable));
            assert_eq!(h.delete("a").await, Err(DeviceError::Unreachable));
            assert_eq!(h.fixed("t").await, Err(DeviceError::Unreachable));
            assert_eq!(h.current().await, Err(DeviceError::Unreachable));
            assert_eq!(h.disk_used_percent().await, Err(DeviceError::Unreachable));
            assert_eq!(h.stop_recording().await, Err(DeviceError::Unreachable));
            assert_eq!(h.start_recording().await, Err(DeviceError::Unreachable));
        };
        tokio::time::timeout(Duration::from_secs(10), all)
            .await
            .expect("a call hung past its timeout");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn download_stalling_after_a_chunk_hits_the_idle_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf).await;
            c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100000\r\n\r\n0123456789")
                .await
                .unwrap();
            c.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await; // stall, connection open
        });
        let h = Http::new(
            &format!("http://127.0.0.1:{port}"),
            Duration::from_millis(300),
            Duration::from_secs(60),
            T,
        );
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("a.gz");
        let r = tokio::time::timeout(Duration::from_secs(10), h.download("a", &to))
            .await
            .expect("idle timeout did not fire");
        assert_eq!(r, Err(DeviceError::Unreachable));
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn sync_dir_ok_on_dir_err_on_missing() {
        let d = tempfile::tempdir().unwrap();
        assert!(sync_dir(d.path()).is_ok());
        assert!(sync_dir(&d.path().join("nope")).is_err());
    }

    /// A dir we can write into but not open for reading: the rename succeeds, the
    /// directory fsync cannot, so success must not be reported.
    #[tokio::test]
    async fn download_and_analysis_err_when_parent_dir_cannot_be_synced() {
        use std::os::unix::fs::PermissionsExt;
        let mut s = mockito::Server::new_async().await;
        s.mock("GET", "/api/qmdl/a")
            .with_body("x")
            .create_async()
            .await;
        s.mock("GET", "/api/analysis-report/a")
            .with_body("y")
            .create_async()
            .await;
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o300)).unwrap();
        if std::fs::File::open(&sub).is_ok() {
            return; // running as root: permissions not enforced
        }
        let h = http(&s.url());
        let r1 = h.download("a", &sub.join("a.gz")).await;
        let r2 = h.analysis("a", &sub.join("a.ndjson")).await;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(r1, Err(DeviceError::Bad(_))), "{r1:?}");
        assert!(matches!(r2, Err(DeviceError::Bad(_))), "{r2:?}");
    }

    /// Server that waits `delay` after the request, then sends `body` as a 200.
    async fn slow_server(delay: Duration, body: &'static str) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut c, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = c.read(&mut buf).await;
                    tokio::time::sleep(delay).await;
                    let r = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = c.write_all(r.as_bytes()).await;
                });
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn device_sha256_uses_the_total_deadline_not_the_short_one() {
        let ms = Duration::from_millis;
        let hash: &'static str = Box::leak("ab".repeat(32).into_boxed_str());
        // answers after 700ms: longer than `timeout` (300ms), shorter than `total` (3s)
        let url = slow_server(ms(700), hash).await;
        let h = Http::new(&url, ms(300), ms(3000), ms(300));
        assert_eq!(h.device_sha256("a").await, Ok(hash.to_string()));
        // answers after 1.5s with total=600ms: too slow
        let url = slow_server(ms(1500), hash).await;
        let h = Http::new(&url, ms(300), ms(600), ms(300));
        assert_eq!(h.device_sha256("a").await, Err(DeviceError::Unreachable));
    }

    #[tokio::test]
    async fn finished_uses_the_short_timeout_not_the_total() {
        let ms = Duration::from_millis;
        let url = slow_server(ms(1000), r#"{"entries":[],"current_entry":null}"#).await;
        let h = Http::new(&url, ms(300), Duration::from_secs(60), ms(300));
        assert_eq!(h.finished().await, Err(DeviceError::Unreachable));
        let h = Http::new(&url, ms(300), Duration::from_secs(60), ms(3000));
        assert_eq!(h.finished().await, Ok(vec![]));
    }

    /// Server: headers at once, then `chunks` bodies of 2 bytes `gap` apart, then
    /// (if `stall`) holds the connection open without finishing.
    async fn trickle_server(chunks: usize, gap: Duration, stall: bool) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf).await;
            let len = if stall { chunks * 2 + 100 } else { chunks * 2 };
            let h = format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\n\r\n");
            c.write_all(h.as_bytes()).await.unwrap();
            for _ in 0..chunks {
                tokio::time::sleep(gap).await;
                c.write_all(b"x\n").await.unwrap();
                c.flush().await.unwrap();
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        format!("http://127.0.0.1:{port}")
    }

    /// I5: the analysis gets the download timeouts (idle + total), not the 30 s one.
    #[tokio::test]
    async fn analysis_body_may_outlast_the_short_timeout() {
        let ms = Duration::from_millis;
        let url = trickle_server(5, ms(200), false).await;
        let h = Http::new(&url, ms(600), ms(5000), ms(300));
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("a.ndjson");
        assert_eq!(h.analysis("a", &to).await, Ok(()));
        assert_eq!(std::fs::read(&to).unwrap(), b"x\n".repeat(5));
    }

    #[tokio::test]
    async fn analysis_stalling_hits_the_idle_timeout_and_leaves_no_file() {
        let ms = Duration::from_millis;
        let url = trickle_server(1, ms(10), true).await;
        let h = Http::new(&url, ms(300), Duration::from_secs(60), T);
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("a.ndjson");
        let r = tokio::time::timeout(Duration::from_secs(10), h.analysis("a", &to))
            .await
            .expect("idle timeout did not fire");
        assert_eq!(r, Err(DeviceError::Unreachable));
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn fake_logs_in_order_gates_and_scripts() {
        let f = std::sync::Arc::new(Fake::new());
        f.add("a", b"hello");
        let d = tempfile::tempdir().unwrap();
        let to = d.path().join("a.gz");
        f.gate("download");
        let f2 = f.clone();
        let to2 = to.clone();
        let t = tokio::spawn(async move { f2.download("a", &to2).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!t.is_finished(), "gate holds the download");
        assert_eq!(f.log(), ["download a"]);
        f.release("download", 1);
        assert_eq!(t.await.unwrap().unwrap(), sha(b"hello"));
        f.set_device_hash("a", &"0".repeat(64));
        assert_eq!(f.device_sha256("a").await.unwrap(), "0".repeat(64));
        f.fail_once("delete a", DeviceError::Unreachable);
        assert_eq!(f.delete("a").await, Err(DeviceError::Unreachable));
        assert_eq!(f.delete("a").await, Ok(()));
        assert_eq!(f.delete("a").await, Err(DeviceError::NotFound));
        assert_eq!(
            f.log(),
            [
                "download a",
                "device_sha256 a",
                "delete a",
                "delete a",
                "delete a"
            ]
        );
    }
}
