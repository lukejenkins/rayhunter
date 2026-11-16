use anyhow::{Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, params};
use std::path::Path;

mod alerts;
mod judge;
#[allow(unused_imports)] // consumed by the 2c publisher
pub use judge::OUTBOX_MAX_AGE_HOURS;
pub use alerts::{AdminItem, Alert, AlertEvent, CloseBy, Ingested, QuietStatus, RadioEntry, Source};
pub use judge::{Baseline, Pending, Report};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Archived,
    DeletedOnDevice,
    Mismatch,
    MissingOnDevice,
}

/// One capture, identified by `(device, name, start)`.
///
/// The unit's names are not identities: recordings started before its clock syncs are
/// named from seconds since boot (and stamped 1970), so the same name comes back on
/// every boot. The start time (to the nanosecond) tells them apart.
#[derive(Debug, Clone, PartialEq)]
pub struct Capture {
    pub device: String,
    pub name: String,
    pub state: State,
    pub local_sha256: Option<String>,
    pub device_sha256: Option<String>,
    pub size: u64,
    pub start: DateTime<Utc>,
    pub last_message: Option<DateTime<Utc>>,
    pub archived_at: Option<DateTime<Utc>>,
    pub mismatch_tries: u32,
    pub kept: bool,
    pub flagged: bool,
    /// Archive file stem: the capture is `{file}.qmdl.gz`, its analysis `{file}.ndjson`,
    /// both directly in the archive directory. Required for an Archived row.
    pub file: Option<String>,
    /// Failed attempts to fetch the analysis (the device delete waits for it, up to a limit).
    pub analysis_tries: u32,
}

/// The index key of a capture.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Key<'a> {
    pub device: &'a str,
    pub name: &'a str,
    pub start: &'a DateTime<Utc>,
}

impl Capture {
    pub fn key(&self) -> Key<'_> {
        Key {
            device: &self.device,
            name: &self.name,
            start: &self.start,
        }
    }
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::Archived => "archived",
            State::DeletedOnDevice => "deleted_on_device",
            State::Mismatch => "mismatch",
            State::MissingOnDevice => "missing_on_device",
        }
    }

    fn parse(s: &str) -> Result<State> {
        Ok(match s {
            "archived" => State::Archived,
            "deleted_on_device" => State::DeletedOnDevice,
            "mismatch" => State::Mismatch,
            "missing_on_device" => State::MissingOnDevice,
            other => bail!("unknown capture state in index: {other}"),
        })
    }
}

/// How a decode ended. Only `Ok` rows hold counts that may be treated as fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStatus {
    Ok,
    /// The guest crashed, timed out, hit a cap, or printed output the event reader
    /// refused. The counts are what arrived before that.
    DecoderFailure,
    /// The archive copy no longer matches its recorded hash; nothing was decoded.
    ArchiveCorrupt,
    /// The archive copy is gone; nothing was decoded.
    ArchiveMissing,
}

impl DecodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DecodeStatus::Ok => "ok",
            DecodeStatus::DecoderFailure => "decoder_failure",
            DecodeStatus::ArchiveCorrupt => "archive_corrupt",
            DecodeStatus::ArchiveMissing => "archive_missing",
        }
    }

    fn parse(s: &str) -> Result<DecodeStatus> {
        Ok(match s {
            "ok" => DecodeStatus::Ok,
            "decoder_failure" => DecodeStatus::DecoderFailure,
            "archive_corrupt" => DecodeStatus::ArchiveCorrupt,
            "archive_missing" => DecodeStatus::ArchiveMissing,
            other => bail!("unknown decode status in index: {other}"),
        })
    }
}

/// The result of decoding one capture, keyed like `captures`.
#[derive(Debug, Clone, PartialEq)]
pub struct Decode {
    pub device: String,
    pub name: String,
    pub start: DateTime<Utc>,
    pub status: DecodeStatus,
    /// `fixed` or `mobile` (the capture's profile; `mixed`/unknown are stored as `mobile`).
    pub profile: String,
    pub frames: u64,
    pub failures: u64,
    pub towers: u64,
    pub identity_requests: u64,
    pub warnings_high: u64,
    pub warnings_other: u64,
    /// Hash of the guest that produced this (empty if none ran).
    pub decoder_hash: String,
    pub decoded_at: DateTime<Utc>,
    /// Why it was not `ok` (a short reason; never raw guest output beyond a bounded excerpt).
    pub detail: Option<String>,
}

pub struct Store {
    conn: Connection,
}

const COLS: &str = "device, name, state, local_sha256, device_sha256, size, start, \
                    last_message, archived_at, mismatch_tries, kept, flagged, file, \
                    analysis_tries";

const KEY: &str = "device = ?1 AND name = ?2 AND start = ?3";

/// Always the same text for the same instant, so it can be part of the key.
#[cfg(test)]
impl Store {
    /// Raw SQL with text parameters, for tests that seed rows no public method writes.
    pub(crate) fn test_exec(&self, sql: &str, params: &[&str]) {
        self.conn
            .execute(sql, rusqlite::params_from_iter(params.iter()))
            .unwrap();
    }
}

fn ts(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
}

fn row_to_capture(r: &rusqlite::Row) -> Result<Capture> {
    let opt_ts = |i: usize| -> Result<Option<DateTime<Utc>>> {
        r.get::<_, Option<String>>(i)?
            .map(|s| parse_ts(&s))
            .transpose()
    };
    Ok(Capture {
        device: r.get(0)?,
        name: r.get(1)?,
        state: State::parse(&r.get::<_, String>(2)?)?,
        local_sha256: r.get(3)?,
        device_sha256: r.get(4)?,
        size: r.get::<_, i64>(5)? as u64,
        start: parse_ts(&r.get::<_, String>(6)?)?,
        last_message: opt_ts(7)?,
        archived_at: opt_ts(8)?,
        mismatch_tries: r.get(9)?,
        kept: r.get(10)?,
        flagged: r.get(11)?,
        file: r.get(12)?,
        analysis_tries: r.get(13)?,
    })
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let conn = Connection::open(path)?;
        // journal_mode returns a row, so it must be read, not executed.
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS captures (
                device         TEXT NOT NULL,
                name           TEXT NOT NULL,
                state          TEXT NOT NULL,
                local_sha256   TEXT,
                device_sha256  TEXT,
                size           INTEGER NOT NULL,
                start          TEXT NOT NULL,
                last_message   TEXT,
                archived_at    TEXT,
                mismatch_tries INTEGER NOT NULL DEFAULT 0,
                kept           INTEGER NOT NULL DEFAULT 0,
                flagged        INTEGER NOT NULL DEFAULT 0,
                file           TEXT,
                analysis_tries INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (device, name, start),
                CHECK (state <> 'archived'
                       OR (local_sha256 IS NOT NULL AND local_sha256 = device_sha256
                           AND file IS NOT NULL))
            );
            -- One stem, one owner: pruning deletes files by a row's stem, so two rows
            -- sharing one would let the older delete the newer's only copy. NULLs
            -- (rows without a copy) are distinct in SQLite and never collide.
            CREATE UNIQUE INDEX IF NOT EXISTS captures_device_file
                ON captures (device, file);
            -- One row per capture once decoded (whatever the outcome), keyed like
            -- `captures`. A row here is what stops a capture being retried every cycle.
            CREATE TABLE IF NOT EXISTS decodes (
                device            TEXT NOT NULL,
                name              TEXT NOT NULL,
                start             TEXT NOT NULL,
                status            TEXT NOT NULL,
                profile           TEXT NOT NULL,
                frames            INTEGER NOT NULL,
                failures          INTEGER NOT NULL,
                towers            INTEGER NOT NULL,
                identity_requests INTEGER NOT NULL,
                warnings_high     INTEGER NOT NULL,
                warnings_other    INTEGER NOT NULL,
                decoder_hash      TEXT NOT NULL,
                decoded_at        TEXT NOT NULL,
                detail            TEXT,
                PRIMARY KEY (device, name, start),
                CHECK (status IN ('ok', 'decoder_failure', 'archive_corrupt', 'archive_missing')),
                CHECK (frames >= 0 AND failures >= 0 AND towers >= 0 AND identity_requests >= 0
                       AND warnings_high >= 0 AND warnings_other >= 0)
            );
            CREATE TABLE IF NOT EXISTS findings (
                device       TEXT NOT NULL,
                name         TEXT NOT NULL,
                start        TEXT NOT NULL,
                check_id     TEXT NOT NULL,
                level        TEXT NOT NULL CHECK (level IN ('notify', 'count')),
                profile      TEXT NOT NULL,
                spans_switch INTEGER NOT NULL,
                suppressed   INTEGER NOT NULL,
                detail       TEXT NOT NULL,
                found_at     TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS findings_capture ON findings (device, name, start);
            -- What each profile has seen: a tower is new only against its own profile.
            CREATE TABLE IF NOT EXISTS towers (
                profile       TEXT NOT NULL,
                key           TEXT NOT NULL,
                strength      TEXT NOT NULL,
                first_seen    TEXT NOT NULL,
                first_capture TEXT NOT NULL,
                PRIMARY KEY (profile, key)
            );
            CREATE TABLE IF NOT EXISTS identity_requests (
                device  TEXT NOT NULL,
                name    TEXT NOT NULL,
                start   TEXT NOT NULL,
                seq     INTEGER NOT NULL,
                ts      TEXT NOT NULL,
                profile TEXT NOT NULL,
                PRIMARY KEY (device, name, start, seq)
            );
            CREATE TABLE IF NOT EXISTS failure_hours (
                hour   TEXT PRIMARY KEY,
                count  INTEGER NOT NULL,
                frames INTEGER NOT NULL
            );
            -- 2c outbox: one row per capture per notify check, never for backfill.
            -- outcome: NULL pending; 'merged' = a health alert inside the 1 h cooldown.
            CREATE TABLE IF NOT EXISTS notifications (
                device       TEXT NOT NULL,
                name         TEXT NOT NULL,
                start        TEXT NOT NULL,
                check_id     TEXT NOT NULL,
                count        INTEGER NOT NULL,
                profile      TEXT NOT NULL,
                spans_switch INTEGER NOT NULL,
                found_at     TEXT NOT NULL,
                towers_known INTEGER,
                sent_at      TEXT,
                outcome      TEXT CHECK (outcome IN ('sent', 'expired', 'merged')),
                PRIMARY KEY (device, name, start, check_id)
            );
            -- Towers seen per hour (judge time), kept 48 h: feeds the towers-seen sensor.
            CREATE TABLE IF NOT EXISTS tower_sightings (
                key  TEXT NOT NULL,
                hour TEXT NOT NULL,
                PRIMARY KEY (key, hour)
            );
            -- Fixed towers first seen after learning, held (not learned) for HOLD_DAYS: a second
            -- sighting notifies. Learning a tower releases its hold.
            CREATE TABLE IF NOT EXISTS held_towers (
                profile       TEXT NOT NULL,
                key           TEXT NOT NULL,
                first_seen    TEXT NOT NULL,
                first_capture TEXT NOT NULL,
                PRIMARY KEY (profile, key)
            );
            -- The transmission log (kind and outcome, never text), kept 7 days: one row per radio
            -- text attempted and per due quiet ping that did not go out (outcome 'skipped').
            CREATE TABLE IF NOT EXISTS radio_events (
                at       TEXT NOT NULL,
                kind     TEXT NOT NULL,
                outcome  TEXT NOT NULL CHECK (outcome IN ('sent', 'failed', 'skipped')),
                reason   TEXT,
                alert_id INTEGER,
                bell     INTEGER NOT NULL,
                hash     TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS radio_events_kind_at ON radio_events (kind, at);
            -- What went out over the mesh (kind only, never text), kept 7 days: feeds the mesh sensors.
            CREATE TABLE IF NOT EXISTS mesh_log (
                at   TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('alert', 'quiet', 'test'))
            );
            -- Live alerts (times are the Yellow's clock, stored like the judge's: RFC 3339 text).
            CREATE TABLE IF NOT EXISTS alerts (
                id             INTEGER PRIMARY KEY,
                device         TEXT NOT NULL,
                opened_at      TEXT NOT NULL,
                last_seen_at   TEXT NOT NULL,
                closed_at      TEXT,
                closed_by      TEXT,
                stage1_at      TEXT,
                stage1_gave_up INTEGER NOT NULL DEFAULT 0,
                last_finding_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_events (
                alert_id  INTEGER NOT NULL,
                at        TEXT NOT NULL,
                check_id  TEXT NOT NULL,
                detail    TEXT NOT NULL,
                towers    TEXT NOT NULL,
                source    TEXT NOT NULL,
                recording TEXT,
                subject   TEXT NOT NULL DEFAULT '',
                timeline_only INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS alert_events_alert ON alert_events (alert_id);
            CREATE TABLE IF NOT EXISTS radio_log (
                id       INTEGER PRIMARY KEY,
                device   TEXT NOT NULL,
                at       TEXT NOT NULL,
                kind     TEXT NOT NULL,
                text     TEXT NOT NULL,
                alert_id INTEGER
            );
            -- Admin notices the add-on pushed (kind only): feeds the owner page's admin strip.
            CREATE TABLE IF NOT EXISTS admin_log (
                id     INTEGER PRIMARY KEY,
                device TEXT NOT NULL,
                at     TEXT NOT NULL,
                kind   TEXT NOT NULL
            );
            -- One row per call of the optional alert summary: usage only, never text.
            CREATE TABLE IF NOT EXISTS summary_log (
                id            INTEGER PRIMARY KEY,
                device        TEXT NOT NULL,
                at            TEXT NOT NULL,
                alert_id      INTEGER,
                model         TEXT NOT NULL,
                input_tokens  INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                outcome       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        // 2a databases have no `judged`; their decodes were never judged.
        let has_judged = conn
            .prepare("PRAGMA table_info(decodes)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|c| c == "judged");
        if !has_judged {
            conn.execute_batch("ALTER TABLE decodes ADD COLUMN judged INTEGER NOT NULL DEFAULT 0")?;
        }
        // 0.4.0 outboxes have no `towers_known`; their rows say nothing about towers.
        let has_towers = conn
            .prepare("PRAGMA table_info(notifications)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|c| c == "towers_known");
        if !has_towers {
            conn.execute_batch("ALTER TABLE notifications ADD COLUMN towers_known INTEGER")?;
        }
        // Pre-0.5.0 outboxes have no `mesh_at`; mesh delivery is tracked apart from HA's `outcome`.
        // The rows already there were alerted on through HA: stamp them as meshed, in the same
        // transaction as the column, so the first deploy does not page the family with them.
        let has_mesh = conn
            .prepare("PRAGMA table_info(notifications)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|c| c == "mesh_at");
        if !has_mesh {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch("ALTER TABLE notifications ADD COLUMN mesh_at TEXT")?;
            tx.execute(
                "UPDATE notifications SET mesh_at = ?1",
                params![ts(&Utc::now())],
            )?;
            tx.commit()?;
        }
        // Pre-0.6.0 outboxes have no `alert_at` (when the closed pass passed the row through
        // the alerts). Rows already meshed, or past the 24 h a row was ever retried, are
        // stamped so the first deploy neither reopens nor re-sends them; an unsent recent
        // strong row is ingested, as 0.5 would still have retried it.
        let has_alert = conn
            .prepare("PRAGMA table_info(notifications)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|c| c == "alert_at");
        if !has_alert {
            let now = Utc::now();
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch("ALTER TABLE notifications ADD COLUMN alert_at TEXT")?;
            tx.execute(
                "UPDATE notifications SET alert_at = ?1 WHERE mesh_at IS NOT NULL OR found_at < ?2",
                params![ts(&now), ts(&(now - chrono::Duration::hours(judge::OUTBOX_MAX_AGE_HOURS)))],
            )?;
            tx.commit()?;
        }
        // Early 0.6.0 alerts have no `last_finding_at` (expiry keyed on `last_seen_at`):
        // start it there.
        let has_finding = conn
            .prepare("PRAGMA table_info(alerts)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|c| c == "last_finding_at");
        if !has_finding {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "ALTER TABLE alerts ADD COLUMN last_finding_at TEXT NOT NULL DEFAULT '';
                 UPDATE alerts SET last_finding_at = last_seen_at;",
            )?;
            tx.commit()?;
        }
        // Pre-timeline-only alert events: add the flag (0 = a normal event).
        let has_timeline_only = conn
            .prepare("PRAGMA table_info(alert_events)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|c| c == "timeline_only");
        if !has_timeline_only {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(
                "ALTER TABLE alert_events ADD COLUMN timeline_only INTEGER NOT NULL DEFAULT 0;",
            )?;
            tx.commit()?;
        }
        Ok(Store { conn })
    }

    pub fn get(&self, k: Key) -> Result<Option<Capture>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {COLS} FROM captures WHERE {KEY}"))?;
        let mut rows = st.query(params![k.device, k.name, ts(k.start)])?;
        match rows.next()? {
            Some(r) => Ok(Some(row_to_capture(r)?)),
            None => Ok(None),
        }
    }

    /// Every capture the unit has listed under `name` (one per start time).
    pub fn by_name(&self, device: &str, name: &str) -> Result<Vec<Capture>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM captures WHERE device = ?1 AND name = ?2 ORDER BY start"
        ))?;
        let mut rows = st.query(params![device, name])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_capture(r)?);
        }
        Ok(out)
    }

    /// Insert, or upgrade an existing row (e.g. Mismatch -> Archived). On
    /// conflict the existing `mismatch_tries`, `kept`, `flagged` and
    /// `analysis_tries` are kept.
    ///
    /// Refuses: an Archived record without two equal hashes or without a file, and
    /// any change to an existing Archived or DeletedOnDevice row.
    pub fn record_archived(&self, c: &Capture) -> Result<()> {
        if c.state == State::Archived
            && (!matches!((&c.local_sha256, &c.device_sha256), (Some(a), Some(b)) if a == b)
                || c.file.is_none())
        {
            bail!(
                "refusing to archive {}/{}: hashes missing or unequal, or no file",
                c.device,
                c.name
            );
        }
        if let Some(old) = self.get(c.key())?
            && matches!(old.state, State::Archived | State::DeletedOnDevice)
        {
            bail!(
                "refusing to overwrite {}/{}@{}: already {}",
                c.device,
                c.name,
                ts(&c.start),
                old.state.as_str()
            );
        }
        self.conn.execute(
            &format!(
                "INSERT INTO captures ({COLS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT (device, name, start) DO UPDATE SET
                    state = excluded.state,
                    local_sha256 = excluded.local_sha256,
                    device_sha256 = excluded.device_sha256,
                    size = excluded.size,
                    last_message = excluded.last_message,
                    archived_at = excluded.archived_at,
                    file = excluded.file"
            ),
            params![
                c.device,
                c.name,
                c.state.as_str(),
                c.local_sha256,
                c.device_sha256,
                c.size as i64,
                ts(&c.start),
                c.last_message.as_ref().map(ts),
                c.archived_at.as_ref().map(ts),
                c.mismatch_tries,
                c.kept,
                c.flagged,
                c.file,
                c.analysis_tries,
            ],
        )?;
        Ok(())
    }

    /// Rows only become Archived through `record_archived` (which checks hashes).
    pub fn set_state(&self, k: Key, s: State) -> Result<()> {
        if s == State::Archived {
            bail!("set_state cannot target Archived; use record_archived");
        }
        self.conn.execute(
            &format!("UPDATE captures SET state = ?4 WHERE {KEY}"),
            params![k.device, k.name, ts(k.start), s.as_str()],
        )?;
        Ok(())
    }

    /// Increment a counter column and return the new count (0 rows -> error).
    fn bump(&self, k: Key, col: &str) -> Result<u32> {
        let n = self.conn.execute(
            &format!("UPDATE captures SET {col} = {col} + 1 WHERE {KEY}"),
            params![k.device, k.name, ts(k.start)],
        )?;
        if n == 0 {
            bail!("no such capture: {}/{}@{}", k.device, k.name, ts(k.start));
        }
        Ok(self.conn.query_row(
            &format!("SELECT {col} FROM captures WHERE {KEY}"),
            params![k.device, k.name, ts(k.start)],
            |r| r.get(0),
        )?)
    }

    /// Increment `mismatch_tries` and return the new count (0 rows -> error).
    pub fn bump_mismatch(&self, k: Key) -> Result<u32> {
        self.bump(k, "mismatch_tries")
    }

    /// Increment `analysis_tries` and return the new count (0 rows -> error).
    pub fn bump_analysis(&self, k: Key) -> Result<u32> {
        self.bump(k, "analysis_tries")
    }

    pub fn set_kept(&self, k: Key, v: bool) -> Result<()> {
        self.conn.execute(
            &format!("UPDATE captures SET kept = ?4 WHERE {KEY}"),
            params![k.device, k.name, ts(k.start), v],
        )?;
        Ok(())
    }

    pub fn set_flagged(&self, k: Key, v: bool) -> Result<()> {
        self.conn.execute(
            &format!("UPDATE captures SET flagged = ?4 WHERE {KEY}"),
            params![k.device, k.name, ts(k.start), v],
        )?;
        Ok(())
    }

    pub fn all(&self, device: &str) -> Result<Vec<Capture>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM captures WHERE device = ?1 ORDER BY start, name"
        ))?;
        let mut rows = st.query(params![device])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_capture(r)?);
        }
        Ok(out)
    }

    pub fn remove(&self, k: Key) -> Result<()> {
        self.conn.execute(
            &format!("DELETE FROM captures WHERE {KEY}"),
            params![k.device, k.name, ts(k.start)],
        )?;
        // A later capture with the same key must not inherit this one's result, its
        // findings, or its identity requests. The shared baselines (towers, failure
        // hours) are what the profile learned and stay.
        for table in ["decodes", "findings", "identity_requests", "notifications"] {
            self.conn.execute(
                &format!("DELETE FROM {table} WHERE {KEY}"),
                params![k.device, k.name, ts(k.start)],
            )?;
        }
        Ok(())
    }

    /// Record (or replace) the result of decoding a capture.
    ///
    /// Test-only since 2b: its INSERT OR REPLACE resets `judged` to 0, so a production
    /// write here would let a capture learn twice. The cycle writes `record_judgement`.
    #[cfg(test)]
    pub fn record_decode(&self, d: &Decode) -> Result<()> {
        let n = |v: u64| i64::try_from(v);
        self.conn.execute(
            "INSERT OR REPLACE INTO decodes (device, name, start, status, profile, frames,
                 failures, towers, identity_requests, warnings_high, warnings_other,
                 decoder_hash, decoded_at, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                d.device,
                d.name,
                ts(&d.start),
                d.status.as_str(),
                d.profile,
                n(d.frames)?,
                n(d.failures)?,
                n(d.towers)?,
                n(d.identity_requests)?,
                n(d.warnings_high)?,
                n(d.warnings_other)?,
                d.decoder_hash,
                ts(&d.decoded_at),
                d.detail,
            ],
        )?;
        Ok(())
    }

    pub fn get_decode(&self, k: Key) -> Result<Option<Decode>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT device, name, start, status, profile, frames, failures, towers,
                    identity_requests, warnings_high, warnings_other, decoder_hash,
                    decoded_at, detail
             FROM decodes WHERE {KEY}"
        ))?;
        let mut rows = st.query(params![k.device, k.name, ts(k.start)])?;
        let Some(r) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(Decode {
            device: r.get(0)?,
            name: r.get(1)?,
            start: parse_ts(&r.get::<_, String>(2)?)?,
            status: DecodeStatus::parse(&r.get::<_, String>(3)?)?,
            profile: r.get(4)?,
            frames: r.get::<_, i64>(5)? as u64,
            failures: r.get::<_, i64>(6)? as u64,
            towers: r.get::<_, i64>(7)? as u64,
            identity_requests: r.get::<_, i64>(8)? as u64,
            warnings_high: r.get::<_, i64>(9)? as u64,
            warnings_other: r.get::<_, i64>(10)? as u64,
            decoder_hash: r.get(11)?,
            decoded_at: parse_ts(&r.get::<_, String>(12)?)?,
            detail: r.get(13)?,
        }))
    }

    /// Captures that have an archive copy and no decode row, oldest `archived_at`
    /// first (ties by name, start), at most `limit`.
    ///
    /// 2a's queue, superseded by `unjudged`; kept with its tests for the 2a semantics.
    #[cfg(test)]
    pub fn undecoded(&self, device: &str, limit: usize) -> Result<Vec<Capture>> {
        let cols = COLS
            .split(", ")
            .map(|c| format!("c.{}", c.trim()))
            .collect::<Vec<_>>()
            .join(", ");
        let mut st = self.conn.prepare(&format!(
            "SELECT {cols} FROM captures c
             WHERE c.device = ?1 AND c.file IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM decodes d
                               WHERE d.device = c.device AND d.name = c.name
                                 AND d.start = c.start)
             ORDER BY c.archived_at, c.name, c.start
             LIMIT ?2"
        ))?;
        let mut rows = st.query(params![device, i64::try_from(limit)?])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_capture(r)?);
        }
        Ok(out)
    }

    /// Whether any row of `device` owns archive stem `stem`. A lookup error is the
    /// caller's to treat as "in use".
    pub fn stem_in_use(&self, device: &str, stem: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM captures WHERE device = ?1 AND file = ?2)",
            params![device, stem],
            |r| r.get(0),
        )?)
    }

    /// Whether a row OTHER than `k` of `k.device` owns `stem`.
    pub fn stem_shared(&self, k: Key, stem: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM captures WHERE device = ?1 AND file = ?2
                            AND NOT (name = ?3 AND start = ?4))",
            params![k.device, stem, k.name, ts(k.start)],
            |r| r.get(0),
        )?)
    }

    /// Test only: drop the unique index so a corrupt index can be simulated.
    #[cfg(test)]
    pub fn drop_stem_index_for_test(&self) {
        self.conn
            .execute_batch("DROP INDEX captures_device_file")
            .unwrap();
    }

    /// Test only: drop the meta table so every read of it fails.
    #[cfg(test)]
    pub fn drop_meta_for_test(&self) {
        self.conn.execute_batch("DROP TABLE meta").unwrap();
    }

    /// Test only: drop the findings table so the 24 h report fails.
    #[cfg(test)]
    pub fn drop_findings_for_test(&self) {
        self.conn.execute_batch("DROP TABLE findings").unwrap();
    }

    pub fn mismatch_total(&self, device: &str) -> Result<u32> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(SUM(mismatch_tries), 0) FROM captures WHERE device = ?1",
            params![device],
            |r| r.get(0),
        )?)
    }

    /// A value in `meta`, or `None` if the key is not set.
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        let mut st = self.conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = st.query(params![key])?;
        Ok(match rows.next()? {
            Some(r) => Some(r.get(0)?),
            None => None,
        })
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn del_meta(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM meta WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// A time kept in `meta` (always written by `set_meta_time`, the Yellow's clock).
    pub fn meta_time(&self, key: &str) -> Result<Option<DateTime<Utc>>> {
        self.meta(key)?.map(|v| parse_ts(&v)).transpose()
    }

    pub fn set_meta_time(&self, key: &str, t: DateTime<Utc>) -> Result<()> {
        self.set_meta(key, &ts(&t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    static START: std::sync::LazyLock<DateTime<Utc>> =
        std::sync::LazyLock::new(|| Utc.with_ymd_and_hms(2026, 10, 1, 8, 0, 0).unwrap());

    /// The key of a `cap(device, name)` row.
    fn k<'a>(device: &'a str, name: &'a str) -> Key<'a> {
        Key {
            device,
            name,
            start: &START,
        }
    }

    fn cap(device: &str, name: &str) -> Capture {
        Capture {
            device: device.into(),
            name: name.into(),
            state: State::Archived,
            local_sha256: Some("a".repeat(64)),
            device_sha256: Some("a".repeat(64)),
            size: 12345,
            start: *START,
            last_message: Some(Utc.with_ymd_and_hms(2026, 10, 1, 9, 30, 0).unwrap()),
            archived_at: Some(Utc.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).unwrap()),
            mismatch_tries: 0,
            kept: false,
            flagged: false,
            file: Some(format!("{name}-1759305600")),
            analysis_tries: 0,
        }
    }

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        (d, s)
    }

    #[test]
    fn round_trips_every_field() {
        let (_d, s) = store();
        let mut c = cap("m2100", "one");
        c.kept = true;
        c.flagged = true;
        c.mismatch_tries = 2;
        s.record_archived(&c).unwrap();
        assert_eq!(s.get(k("m2100", "one")).unwrap(), Some(c));
        assert_eq!(s.get(k("m2100", "nope")).unwrap(), None);
    }

    #[test]
    fn states_round_trip() {
        let (_d, s) = store();
        s.record_archived(&cap("m2100", "x")).unwrap();
        for st in [
            State::Mismatch,
            State::MissingOnDevice,
            State::DeletedOnDevice,
        ] {
            s.set_state(k("m2100", "x"), st).unwrap();
            assert_eq!(s.get(k("m2100", "x")).unwrap().unwrap().state, st);
        }
    }

    #[test]
    fn bump_mismatch_counts_up() {
        let (_d, s) = store();
        s.record_archived(&cap("m2100", "x")).unwrap();
        assert_eq!(s.bump_mismatch(k("m2100", "x")).unwrap(), 1);
        assert_eq!(s.bump_mismatch(k("m2100", "x")).unwrap(), 2);
        assert_eq!(s.get(k("m2100", "x")).unwrap().unwrap().mismatch_tries, 2);
    }

    #[test]
    fn mismatch_total_sums() {
        let (_d, s) = store();
        for n in ["a", "b", "c"] {
            s.record_archived(&cap("m2100", n)).unwrap();
        }
        s.record_archived(&cap("other", "a")).unwrap();
        s.bump_mismatch(k("m2100", "a")).unwrap();
        s.bump_mismatch(k("m2100", "a")).unwrap();
        s.bump_mismatch(k("m2100", "b")).unwrap();
        s.bump_mismatch(k("other", "a")).unwrap();
        assert_eq!(s.mismatch_total("m2100").unwrap(), 3);
        assert_eq!(s.mismatch_total("other").unwrap(), 1);
        assert_eq!(s.mismatch_total("none").unwrap(), 0);
    }

    #[test]
    fn reopen_keeps_rows() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        {
            let s = Store::open(&p).unwrap();
            s.record_archived(&cap("m2100", "x")).unwrap();
        }
        let s = Store::open(&p).unwrap();
        assert_eq!(s.get(k("m2100", "x")).unwrap(), Some(cap("m2100", "x")));
    }

    #[test]
    fn all_is_per_device_and_same_name_is_distinct() {
        let (_d, s) = store();
        let mut other = cap("other", "x");
        other.size = 999;
        s.record_archived(&cap("m2100", "x")).unwrap();
        s.record_archived(&other).unwrap();
        s.record_archived(&cap("m2100", "y")).unwrap();
        assert_eq!(s.all("m2100").unwrap().len(), 2);
        assert_eq!(s.all("other").unwrap(), vec![other.clone()]);
        assert_eq!(s.get(k("m2100", "x")).unwrap().unwrap().size, 12345);
        assert_eq!(s.get(k("other", "x")).unwrap().unwrap().size, 999);
        s.remove(k("other", "x")).unwrap();
        assert!(s.all("other").unwrap().is_empty());
        assert_eq!(s.all("m2100").unwrap().len(), 2);
    }

    #[test]
    fn set_state_refuses_archived() {
        let (_d, s) = store();
        let mut m = cap("m2100", "x");
        m.state = State::Mismatch;
        m.local_sha256 = None;
        m.device_sha256 = None;
        s.record_archived(&m).unwrap();
        assert!(s.set_state(k("m2100", "x"), State::Archived).is_err());
        assert_eq!(
            s.get(k("m2100", "x")).unwrap().unwrap().state,
            State::Mismatch
        );
    }

    #[test]
    fn record_archived_requires_equal_hashes() {
        let (_d, s) = store();
        let mut none = cap("m2100", "x");
        none.local_sha256 = None;
        none.device_sha256 = None;
        assert!(s.record_archived(&none).is_err());
        let mut one = cap("m2100", "x");
        one.device_sha256 = None;
        assert!(s.record_archived(&one).is_err());
        let mut diff = cap("m2100", "x");
        diff.device_sha256 = Some("b".repeat(64));
        assert!(s.record_archived(&diff).is_err());
        assert_eq!(s.get(k("m2100", "x")).unwrap(), None);
    }

    #[test]
    fn schema_check_rejects_unverified_archived_row() {
        let (_d, s) = store();
        let sql = |l: &str, d: &str, f: &str| {
            s.conn.execute(
                &format!(
                    "INSERT INTO captures (device, name, state, local_sha256, device_sha256, size, start, file)
                     VALUES ('m', 'x', 'archived', {l}, {d}, 1, '2026-10-01T00:00:00Z', {f})"
                ),
                [],
            )
        };
        assert!(sql("NULL", "NULL", "'x-1'").is_err());
        assert!(sql("'a'", "'b'", "'x-1'").is_err());
        assert!(sql("'a'", "'a'", "NULL").is_err());
        assert!(sql("'a'", "'a'", "'x-1'").is_ok());
    }

    #[test]
    fn fractional_seconds_round_trip() {
        let (_d, s) = store();
        let mut c = cap("m2100", "x");
        c.start = Utc.with_ymd_and_hms(2026, 10, 1, 8, 0, 0).unwrap()
            + chrono::Duration::nanoseconds(123_456_789);
        c.last_message = Some(c.start + chrono::Duration::milliseconds(250));
        s.record_archived(&c).unwrap();
        assert_eq!(s.get(c.key()).unwrap(), Some(c.clone()));
        assert_eq!(s.get(k("m2100", "x")).unwrap(), None);
    }

    #[test]
    fn upsert_never_downgrades_archived_or_deleted() {
        let (_d, s) = store();
        let mut m = cap("m2100", "x");
        m.state = State::Mismatch;
        m.local_sha256 = None;
        m.device_sha256 = None;
        m.archived_at = None;
        m.mismatch_tries = 1;

        s.record_archived(&cap("m2100", "x")).unwrap();
        let before = s.get(k("m2100", "x")).unwrap();
        assert!(s.record_archived(&m).is_err());
        assert!(s.record_archived(&cap("m2100", "x")).is_err());
        assert_eq!(s.get(k("m2100", "x")).unwrap(), before);

        s.set_state(k("m2100", "x"), State::DeletedOnDevice)
            .unwrap();
        let before = s.get(k("m2100", "x")).unwrap();
        assert!(s.record_archived(&m).is_err());
        assert!(s.record_archived(&cap("m2100", "x")).is_err());
        assert_eq!(s.get(k("m2100", "x")).unwrap(), before);
    }

    #[test]
    fn upgrade_preserves_kept_and_flagged() {
        let (_d, s) = store();
        let mut m = cap("m2100", "x");
        m.state = State::Mismatch;
        m.local_sha256 = None;
        m.device_sha256 = None;
        m.archived_at = None;
        m.mismatch_tries = 1;
        m.kept = true;
        m.flagged = true;
        s.record_archived(&m).unwrap();
        s.record_archived(&cap("m2100", "x")).unwrap();
        let c = s.get(k("m2100", "x")).unwrap().unwrap();
        assert_eq!(c.state, State::Archived);
        assert!(c.kept && c.flagged);
        assert_eq!(c.mismatch_tries, 1);
    }

    #[test]
    fn set_kept_and_flagged() {
        let (_d, s) = store();
        s.record_archived(&cap("m2100", "x")).unwrap();
        s.set_kept(k("m2100", "x"), true).unwrap();
        s.set_flagged(k("m2100", "x"), true).unwrap();
        let c = s.get(k("m2100", "x")).unwrap().unwrap();
        assert!(c.kept && c.flagged);
        s.set_kept(k("m2100", "x"), false).unwrap();
        assert!(!s.get(k("m2100", "x")).unwrap().unwrap().kept);
    }

    #[test]
    fn archived_upgrades_a_mismatch_row_keeping_tries() {
        let (_d, s) = store();
        let mut m = cap("m2100", "x");
        m.state = State::Mismatch;
        m.local_sha256 = None;
        m.device_sha256 = None;
        m.archived_at = None;
        m.mismatch_tries = 1;
        s.record_archived(&m).unwrap();
        assert_eq!(s.get(k("m2100", "x")).unwrap(), Some(m));

        s.record_archived(&cap("m2100", "x")).unwrap();
        let c = s.get(k("m2100", "x")).unwrap().unwrap();
        assert_eq!(c.state, State::Archived);
        assert_eq!(c.mismatch_tries, 1);
        assert!(c.local_sha256.is_some() && c.archived_at.is_some());
        assert_eq!(s.all("m2100").unwrap().len(), 1);
    }

    #[test]
    fn same_name_different_start_is_a_different_capture() {
        let (_d, s) = store();
        let a = cap("m2100", "31");
        let mut b = cap("m2100", "31");
        b.start = a.start + chrono::Duration::nanoseconds(1);
        b.size = 7;
        b.file = Some("31-1759305600-2".into());
        s.record_archived(&a).unwrap();
        // a is Archived; b is not a downgrade of a, it is another capture
        s.record_archived(&b).unwrap();
        assert_eq!(
            s.by_name("m2100", "31").unwrap(),
            vec![a.clone(), b.clone()]
        );
        assert_eq!(s.get(a.key()).unwrap(), Some(a.clone()));
        assert_eq!(s.get(b.key()).unwrap(), Some(b.clone()));
        s.set_state(b.key(), State::DeletedOnDevice).unwrap();
        assert_eq!(s.get(a.key()).unwrap().unwrap().state, State::Archived);
        s.remove(b.key()).unwrap();
        assert_eq!(s.by_name("m2100", "31").unwrap(), vec![a]);
    }

    #[test]
    fn two_rows_cannot_own_one_stem_but_null_files_coexist() {
        let (_d, s) = store();
        let a = cap("m2100", "a");
        s.record_archived(&a).unwrap();
        let mut b = cap("m2100", "b");
        b.file = a.file.clone();
        assert!(s.record_archived(&b).is_err());
        // Same stem on another device is fine.
        let mut c = cap("other", "a");
        c.file = a.file.clone();
        s.record_archived(&c).unwrap();
        // Rows without a copy do not collide with each other.
        for n in ["x", "y"] {
            let mut u = cap("m2100", n);
            u.state = State::Mismatch;
            u.local_sha256 = None;
            u.device_sha256 = None;
            u.file = None;
            s.record_archived(&u).unwrap();
        }
        assert_eq!(s.all("m2100").unwrap().len(), 3);
    }

    #[test]
    fn stem_in_use_sees_rows() {
        let (_d, s) = store();
        let a = cap("m2100", "a");
        s.record_archived(&a).unwrap();
        assert!(s.stem_in_use("m2100", a.file.as_deref().unwrap()).unwrap());
        assert!(!s.stem_in_use("m2100", "nope").unwrap());
        assert!(!s.stem_in_use("other", a.file.as_deref().unwrap()).unwrap());
    }

    #[test]
    fn archived_requires_a_file() {
        let (_d, s) = store();
        let mut c = cap("m2100", "x");
        c.file = None;
        assert!(s.record_archived(&c).is_err());
        assert_eq!(s.get(k("m2100", "x")).unwrap(), None);
    }

    #[test]
    fn bump_analysis_counts_up_and_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        {
            let s = Store::open(&p).unwrap();
            s.record_archived(&cap("m2100", "x")).unwrap();
            assert_eq!(s.bump_analysis(k("m2100", "x")).unwrap(), 1);
            assert_eq!(s.bump_analysis(k("m2100", "x")).unwrap(), 2);
            assert!(s.bump_analysis(k("m2100", "nope")).is_err());
        }
        let s = Store::open(&p).unwrap();
        assert_eq!(s.get(k("m2100", "x")).unwrap().unwrap().analysis_tries, 2);
    }

    fn decode_for(c: &Capture) -> Decode {
        Decode {
            device: c.device.clone(),
            name: c.name.clone(),
            start: c.start,
            status: DecodeStatus::Ok,
            profile: "mobile".into(),
            frames: 100,
            failures: 3,
            towers: 4,
            identity_requests: 1,
            warnings_high: 2,
            warnings_other: 5,
            decoder_hash: "f".repeat(64),
            decoded_at: Utc.with_ymd_and_hms(2026, 10, 11, 1, 2, 3).unwrap(),
            detail: None,
        }
    }

    #[test]
    fn decode_round_trips_every_status() {
        let (_d, s) = store();
        let c = cap("m2100", "one");
        s.record_archived(&c).unwrap();
        assert_eq!(s.get_decode(k("m2100", "one")).unwrap(), None);
        for st in [
            DecodeStatus::Ok,
            DecodeStatus::DecoderFailure,
            DecodeStatus::ArchiveCorrupt,
            DecodeStatus::ArchiveMissing,
        ] {
            let mut d = decode_for(&c);
            d.status = st;
            d.detail = Some(format!("why {st:?}"));
            s.record_decode(&d).unwrap();
            assert_eq!(s.get_decode(k("m2100", "one")).unwrap(), Some(d));
        }
    }

    #[test]
    fn decode_survives_reopen_and_replaces() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        let c = cap("m2100", "one");
        {
            let s = Store::open(&p).unwrap();
            s.record_archived(&c).unwrap();
            let mut dec = decode_for(&c);
            dec.status = DecodeStatus::DecoderFailure;
            s.record_decode(&dec).unwrap();
            dec.status = DecodeStatus::Ok;
            s.record_decode(&dec).unwrap();
        }
        let s = Store::open(&p).unwrap();
        assert_eq!(
            s.get_decode(k("m2100", "one")).unwrap().unwrap().status,
            DecodeStatus::Ok
        );
    }

    #[test]
    fn undecoded_is_oldest_archived_first_and_excludes_decoded_and_fileless() {
        let (_d, s) = store();
        let at = |day| Some(Utc.with_ymd_and_hms(2026, 10, day, 0, 0, 0).unwrap());
        let mut newest = cap("m2100", "newest");
        newest.archived_at = at(9);
        let mut oldest = cap("m2100", "oldest");
        oldest.archived_at = at(3);
        let mut middle = cap("m2100", "middle");
        middle.archived_at = at(5);
        let mut done = cap("m2100", "done");
        done.archived_at = at(1);
        let mut nofile = cap("m2100", "nofile");
        nofile.state = State::MissingOnDevice;
        nofile.file = None;
        nofile.archived_at = at(2);
        let mut other = cap("other", "elsewhere");
        other.archived_at = at(1);
        for c in [&newest, &oldest, &middle, &done, &nofile, &other] {
            s.record_archived(c).unwrap();
        }
        s.record_decode(&decode_for(&done)).unwrap();
        let names = |v: Vec<Capture>| v.into_iter().map(|c| c.name).collect::<Vec<_>>();
        assert_eq!(
            names(s.undecoded("m2100", 10).unwrap()),
            ["oldest", "middle", "newest"]
        );
        assert_eq!(
            names(s.undecoded("m2100", 2).unwrap()),
            ["oldest", "middle"]
        );
        assert_eq!(names(s.undecoded("other", 10).unwrap()), ["elsewhere"]);
        // a failed decode is still a decode: not retried
        let mut f = decode_for(&oldest);
        f.status = DecodeStatus::DecoderFailure;
        s.record_decode(&f).unwrap();
        assert_eq!(
            names(s.undecoded("m2100", 10).unwrap()),
            ["middle", "newest"]
        );
    }

    #[test]
    fn decode_is_keyed_by_start_and_removed_with_its_capture() {
        let (_d, s) = store();
        let a = cap("m2100", "boot");
        let mut b = cap("m2100", "boot");
        b.start = Utc.with_ymd_and_hms(2026, 10, 5, 8, 0, 0).unwrap();
        b.file = Some("boot-2".into());
        s.record_archived(&a).unwrap();
        s.record_archived(&b).unwrap();
        s.record_decode(&decode_for(&a)).unwrap();
        let left = s.undecoded("m2100", 10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].start, b.start);
        s.remove(a.key()).unwrap();
        assert_eq!(s.get_decode(a.key()).unwrap(), None);
    }

    #[test]
    fn decodes_table_refuses_a_bad_status() {
        let (_d, s) = store();
        let e = s.conn.execute(
            "INSERT INTO decodes VALUES ('d','n','t','bogus','mobile',0,0,0,0,0,0,'','t',NULL)",
            [],
        );
        assert!(e.is_err());
    }
}
