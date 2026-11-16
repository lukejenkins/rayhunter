//! The judgement side of the index: what each capture was judged to be, and the
//! baselines (towers, identity rhythm, failure hours) later captures are judged against.

use super::{COLS, Capture, Decode, DecodeStatus, KEY, Key, Store, parse_ts, row_to_capture, ts};
use crate::checks::{self, Judgement, Level, Profile};
use anyhow::Result;
use chrono::{DateTime, Duration, DurationRound, TimeZone, Utc};
use rusqlite::{OptionalExtension, params};
use std::collections::HashSet;

/// What a profile has learned so far.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Baseline {
    pub towers: HashSet<String>,
    /// Fixed towers first seen after learning, held for `HOLD_DAYS` instead of learned:
    /// a second sighting in that time notifies (`new_tower_recur`).
    pub held: HashSet<String>,
    pub fixed_since: Option<DateTime<Utc>>,
    /// Gaps between consecutive identity requests of one capture (fixed profile only).
    pub fixed_gaps_secs: Vec<i64>,
}

/// A queued phone notification, as the publisher sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    /// `notifications.rowid`.
    pub id: i64,
    /// Capture name (untrusted text).
    pub name: String,
    pub check: String,
    pub count: u32,
    /// "fixed" | "mobile".
    pub profile: String,
    pub spans_switch: bool,
    pub found_at: DateTime<Utc>,
    /// The capture's towers were all known here (`Some(true)`), one was not, or unknowable.
    pub towers_known: Option<bool>,
}

/// The 24 hour numbers behind the Home Assistant sensors.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub analyser_high: u32,
    pub analyser_other: u32,
    pub off_rhythm: u32,
    pub failure_spikes: u32,
    pub decoder_failures: u32,
    pub archive_corrupt: u32,
    pub new_towers: u32,
    pub towers_seen: u32,
    pub learning: bool,
}

pub const OUTBOX_MAX_AGE_HOURS: i64 = 24;

/// Times before this come from a unit whose clock never synced.
fn synced_floor() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap()
}

impl Store {
    /// When judging began; set on first call so later captures share one origin.
    pub fn judge_epoch(&self, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
        self.conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('judge_epoch', ?1)",
            params![ts(&now)],
        )?;
        let v: String = self.conn.query_row(
            "SELECT value FROM meta WHERE key = 'judge_epoch'",
            [],
            |r| r.get(0),
        )?;
        parse_ts(&v)
    }

    /// Archived captures not yet judged (never decoded, or decoded by 2a), oldest first,
    /// each with its existing decode row if there is one.
    pub fn unjudged(&self, device: &str, limit: usize) -> Result<Vec<(Capture, Option<Decode>)>> {
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
                                 AND d.start = c.start AND d.judged = 1)
             ORDER BY c.archived_at, c.start, c.name
             LIMIT ?2"
        ))?;
        let mut rows = st.query(params![device, i64::try_from(limit)?])?;
        let mut caps = Vec::new();
        while let Some(r) = rows.next()? {
            caps.push(row_to_capture(r)?);
        }
        caps.into_iter()
            .map(|c| {
                let d = self.get_decode(c.key())?;
                Ok((c, d))
            })
            .collect()
    }

    /// Store a capture's verdict, its findings and what it teaches the baselines in
    /// one transaction: either all of it lands or none, so a crash cannot leave a
    /// capture judged but unlearned (or learned twice on the retry).
    ///
    /// Re-judging replaces the findings but never learns again, and only a clean
    /// (`ok`) decode ever learns, whatever the judgement carries.
    pub fn record_judgement(&self, d: &Decode, j: &Judgement, now: DateTime<Utc>) -> Result<()> {
        let key = (d.device.as_str(), d.name.as_str(), ts(&d.start));
        let n = |v: u64| i64::try_from(v);
        let tx = self.conn.unchecked_transaction()?;
        let already: bool = tx
            .query_row(
                &format!("SELECT judged FROM decodes WHERE {KEY}"),
                params![key.0, key.1, key.2],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false);
        tx.execute(
            "INSERT OR REPLACE INTO decodes (device, name, start, status, profile, frames,
                 failures, towers, identity_requests, warnings_high, warnings_other,
                 decoder_hash, decoded_at, detail, judged)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 1)",
            params![
                key.0,
                key.1,
                key.2,
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
        tx.execute(
            &format!("DELETE FROM findings WHERE {KEY}"),
            params![key.0, key.1, key.2],
        )?;
        for f in &j.findings {
            tx.execute(
                "INSERT INTO findings (device, name, start, check_id, level, profile,
                     spans_switch, suppressed, detail, found_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    key.0,
                    key.1,
                    key.2,
                    f.check,
                    f.level.as_str(),
                    j.profile.as_str(),
                    j.spans_switch,
                    j.suppressed,
                    f.detail,
                    ts(&now),
                ],
            )?;
        }
        // 2c outbox: one row per notify check, never for backfill. OR IGNORE: a capture
        // judged again must not be told twice.
        if !j.suppressed {
            let mut per_check: Vec<(&str, i64)> = Vec::new();
            for f in j.findings.iter().filter(|f| f.level == Level::Notify) {
                match per_check.iter_mut().find(|(c, _)| *c == f.check) {
                    Some((_, n)) => *n += 1,
                    None => per_check.push((f.check, 1)),
                }
            }
            for (check, n) in per_check {
                tx.execute(
                    "INSERT OR IGNORE INTO notifications (device, name, start, check_id, count,
                         profile, spans_switch, found_at, towers_known)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![key.0, key.1, key.2, check, n, j.profile.as_str(), j.spans_switch, ts(&now), j.towers_known],
                )?;
            }
        }
        let learns = !already && d.status == DecodeStatus::Ok;
        if let Some(l) = j.learn.as_ref().filter(|_| learns) {
            let profile = j.profile.as_str();
            for (tower, strength) in &l.towers {
                tx.execute(
                    "INSERT OR IGNORE INTO towers (profile, key, strength, first_seen, first_capture)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![profile, tower, strength.as_str(), ts(&now), d.name],
                )?;
                tx.execute(
                    "DELETE FROM held_towers WHERE profile = ?1 AND key = ?2",
                    params![profile, tower],
                )?;
            }
            for tower in &l.hold {
                tx.execute(
                    "INSERT OR IGNORE INTO held_towers (profile, key, first_seen, first_capture)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![profile, tower, ts(&now), d.name],
                )?;
            }
            tx.execute(
                "DELETE FROM held_towers WHERE first_seen < ?1",
                params![ts(&(now - Duration::days(checks::HOLD_DAYS)))],
            )?;
            // Backfill learns towers but is not a sighting: the 24 h sensor excludes it.
            if !j.suppressed {
                let hour = now.duration_trunc(Duration::hours(1))?;
                for tower in l.towers.iter().map(|(t, _)| t).chain(&l.hold) {
                    tx.execute(
                        "INSERT OR IGNORE INTO tower_sightings (key, hour) VALUES (?1, ?2)",
                        params![tower, ts(&hour)],
                    )?;
                }
                tx.execute(
                    "DELETE FROM tower_sightings WHERE hour < ?1",
                    params![ts(&(now - Duration::hours(48)))],
                )?;
            }
            for (seq, t) in l.identity_ts.iter().enumerate() {
                tx.execute(
                    "INSERT OR REPLACE INTO identity_requests (device, name, start, seq, ts, profile)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![key.0, key.1, key.2, seq as i64, ts(t), profile],
                )?;
            }
            for (hour, count, frames) in &l.failure_hours {
                tx.execute(
                    "INSERT INTO failure_hours (hour, count, frames) VALUES (?1, ?2, ?3)
                     ON CONFLICT (hour) DO UPDATE SET
                        count = count + excluded.count, frames = frames + excluded.frames",
                    params![ts(hour), n(*count)?, n(*frames)?],
                )?;
            }
            if j.profile == Profile::Fixed {
                tx.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('fixed_since', ?1)",
                    params![ts(&now)],
                )?;
            }
        }
        if j.findings.iter().any(|f| f.level == Level::Notify) {
            tx.execute(
                &format!("UPDATE captures SET flagged = 1 WHERE {KEY}"),
                params![key.0, key.1, key.2],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Unsent notifications, oldest first, after expiring any older than a day (they
    /// are counted by the sensors but never sent: a day-old alert is noise).
    pub fn pending_notifications(
        &self,
        device: &str,
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<(Vec<Pending>, usize)> {
        let cutoff = ts(&(now - Duration::hours(OUTBOX_MAX_AGE_HOURS)));
        let expired = self.conn.execute(
            "UPDATE notifications SET outcome = 'expired', sent_at = ?1
             WHERE device = ?2 AND outcome IS NULL AND found_at < ?3",
            params![ts(&now), device, cutoff],
        )?;
        let mut st = self.conn.prepare(
            "SELECT rowid, name, check_id, count, profile, spans_switch, found_at, towers_known
             FROM notifications WHERE device = ?1 AND outcome IS NULL
             ORDER BY found_at, rowid LIMIT ?2",
        )?;
        let mut rows = st.query(params![device, i64::try_from(limit)?])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(Pending {
                id: r.get(0)?,
                name: r.get(1)?,
                check: r.get(2)?,
                count: r.get::<_, i64>(3)?.try_into()?,
                profile: r.get(4)?,
                spans_switch: r.get(5)?,
                found_at: parse_ts(&r.get::<_, String>(6)?)?,
            towers_known: r.get(7)?,
            });
        }
        Ok((out, expired))
    }

    pub fn mark_sent(&self, ids: &[i64], now: DateTime<Utc>) -> Result<()> {
        self.mark(ids, "sent", now)
    }

    /// Retire outbox rows with `outcome` ('sent' | 'expired' | 'merged'). A row already
    /// retired keeps its first outcome.
    pub fn mark(&self, ids: &[i64], outcome: &str, now: DateTime<Utc>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for id in ids {
            tx.execute(
                "UPDATE notifications SET outcome = ?1, sent_at = ?2
                 WHERE rowid = ?3 AND outcome IS NULL",
                params![outcome, ts(&now), id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Fixed-profile, switch-free outbox rows not yet sent over the mesh, oldest first, as
    /// (rowid, check id). Younger than a day only; the HA `outcome` is ignored on purpose
    /// so the mesh does not depend on MQTT.
    pub fn mesh_pending(
        &self,
        device: &str,
        checks: &[&str],
        now: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<(i64, String)>> {
        let cutoff = ts(&(now - Duration::hours(OUTBOX_MAX_AGE_HOURS)));
        let mut st = self.conn.prepare(
            "SELECT rowid, check_id FROM notifications
             WHERE device = ?1 AND mesh_at IS NULL AND profile = 'fixed' AND spans_switch = 0
               AND found_at >= ?2
             ORDER BY found_at, rowid",
        )?;
        let mut rows = st.query(params![device, cutoff])?;
        let mut out = Vec::new();
        while out.len() < limit {
            let Some(r) = rows.next()? else { break };
            let check: String = r.get(1)?;
            if checks.contains(&check.as_str()) {
                out.push((r.get(0)?, check));
            }
        }
        Ok(out)
    }

    /// Fixed-profile, switch-free outbox rows of `checks` the closed pass has not yet passed
    /// through the alerts, oldest first, as (rowid, check id). No age limit: a row is never
    /// lost before it is ingested (the 0.6.0 migration stamped the old ones).
    pub fn alert_pending(
        &self,
        device: &str,
        checks: &[&str],
        limit: usize,
    ) -> Result<Vec<(i64, String)>> {
        let mut st = self.conn.prepare(
            "SELECT rowid, check_id FROM notifications
             WHERE device = ?1 AND alert_at IS NULL AND profile = 'fixed' AND spans_switch = 0
             ORDER BY found_at, rowid",
        )?;
        let mut rows = st.query(params![device])?;
        let mut out = Vec::new();
        while out.len() < limit {
            let Some(r) = rows.next()? else { break };
            let check: String = r.get(1)?;
            if checks.contains(&check.as_str()) {
                out.push((r.get(0)?, check));
            }
        }
        Ok(out)
    }

    /// Record that the closed pass ingested this outbox row (first time only). `mesh_at` is
    /// stamped too, as 0.5.3 did after sending a strong row, so a rollback to 0.5.3 on this
    /// database does not send it again; 0.6.0 never reads a strong row's `mesh_at` (its
    /// radio message is the alert's stage 1).
    pub fn mark_alerted(&self, id: i64, now: DateTime<Utc>) -> Result<()> {
        self.conn.execute(
            "UPDATE notifications SET alert_at = COALESCE(alert_at, ?1), mesh_at = COALESCE(mesh_at, ?1)
             WHERE rowid = ?2",
            params![ts(&now), id],
        )?;
        Ok(())
    }

    /// An outbox row's capture name and the details of that capture's findings for the
    /// row's check (in stored order), for the closed pass's alert ingest. `None`: no such row.
    pub fn row_findings(&self, rowid: i64) -> Result<Option<(String, Vec<String>)>> {
        let row: Option<(String, String, String, String)> = self
            .conn
            .query_row(
                "SELECT device, name, start, check_id FROM notifications WHERE rowid = ?1",
                params![rowid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((device, name, start, check)) = row else {
            return Ok(None);
        };
        let mut st = self.conn.prepare(
            "SELECT detail FROM findings
             WHERE device = ?1 AND name = ?2 AND start = ?3 AND check_id = ?4 ORDER BY rowid",
        )?;
        let details = st
            .query_map(params![device, name, start, check], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some((name, details)))
    }

    /// (check, detail) of every finding stored for captures named `name`.
    pub fn findings_named(&self, device: &str, name: &str) -> Result<Vec<(String, String)>> {
        let mut st = self.conn.prepare(
            "SELECT check_id, detail FROM findings WHERE device = ?1 AND name = ?2 ORDER BY rowid",
        )?;
        let rows = st
            .query_map(params![device, name], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Record that these outbox rows went out over the mesh (first time only).
    pub fn mark_mesh(&self, ids: &[i64], now: DateTime<Utc>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for id in ids {
            tx.execute(
                "UPDATE notifications SET mesh_at = ?1 WHERE rowid = ?2 AND mesh_at IS NULL",
                params![ts(&now), id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The ids, in order, whose rows are still not sent over the mesh.
    pub fn mesh_still_pending(&self, ids: &[i64]) -> Result<Vec<i64>> {
        let mut st = self
            .conn
            .prepare("SELECT 1 FROM notifications WHERE rowid = ?1 AND mesh_at IS NULL")?;
        let mut out = Vec::new();
        for id in ids {
            if st.exists(params![id])? {
                out.push(*id);
            }
        }
        Ok(out)
    }

    /// Record messages that went out over the mesh, one row per kind ("alert", "quiet", "test").
    pub fn log_mesh(&self, kinds: &[&str], now: DateTime<Utc>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for k in kinds {
            tx.execute("INSERT INTO mesh_log (at, kind) VALUES (?1, ?2)", params![ts(&now), k])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// (messages sent in the last 24 h, when the newest went out).
    pub fn mesh_stats(&self, now: DateTime<Utc>) -> Result<(u32, Option<DateTime<Utc>>)> {
        let (n, newest): (u32, Option<String>) = self.conn.query_row(
            "SELECT COUNT(*) FILTER (WHERE at > ?1), MAX(at) FROM mesh_log",
            params![ts(&(now - Duration::hours(24)))],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((n, newest.map(|s| parse_ts(&s)).transpose()?))
    }

    /// Drop mesh log and transmission log rows older than 7 days; returns how many mesh
    /// log rows went.
    pub fn prune_mesh_log(&self, now: DateTime<Utc>) -> Result<usize> {
        let cut = ts(&(now - Duration::days(7)));
        self.conn.execute("DELETE FROM radio_events WHERE at < ?1", params![cut])?;
        Ok(self.conn.execute("DELETE FROM mesh_log WHERE at < ?1", params![cut])?)
    }

    #[cfg(test)]
    pub fn mesh_log_rows(&self) -> i64 {
        self.conn.query_row("SELECT COUNT(*) FROM mesh_log", [], |r| r.get(0)).unwrap()
    }

    /// The rows retired with `outcome` at exactly `at`, as (capture name, check id, count):
    /// which ones `pending_notifications` just expired, for the Cribl output. Read-only.
    pub fn retired_at(
        &self,
        device: &str,
        outcome: &str,
        at: DateTime<Utc>,
    ) -> Result<Vec<(String, String, u32)>> {
        let mut st = self.conn.prepare(
            "SELECT name, check_id, count FROM notifications
             WHERE device = ?1 AND outcome = ?2 AND sent_at = ?3 ORDER BY found_at, rowid",
        )?;
        let rows = st.query_map(params![device, outcome, ts(&at)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
        })?;
        rows.map(|r| {
            let (name, check, n) = r?;
            Ok((name, check, u32::try_from(n)?))
        })
        .collect()
    }

    /// When a row of `check` last actually went out (merged and expired rows never did).
    pub fn last_sent(&self, device: &str, check: &str) -> Result<Option<DateTime<Utc>>> {
        let t: Option<String> = self.conn.query_row(
            "SELECT MAX(sent_at) FROM notifications
             WHERE device = ?1 AND check_id = ?2 AND outcome = 'sent'",
            params![device, check],
            |r| r.get(0),
        )?;
        t.map(|t| parse_ts(&t)).transpose()
    }

    /// The ids, in order, whose rows are still unsent.
    pub fn still_pending(&self, ids: &[i64]) -> Result<Vec<i64>> {
        let mut st = self
            .conn
            .prepare("SELECT 1 FROM notifications WHERE rowid = ?1 AND outcome IS NULL")?;
        let mut out = Vec::new();
        for id in ids {
            if st.exists(params![id])? {
                out.push(*id);
            }
        }
        Ok(out)
    }

    /// The 24 h numbers for Home Assistant: findings by judge time, backfill excluded.
    pub fn report(&self, device: &str, now: DateTime<Utc>, learn_days: i64) -> Result<Report> {
        let since = ts(&(now - Duration::hours(24)));
        let mut st = self.conn.prepare(
            "SELECT check_id, COUNT(*) FROM findings
             WHERE device = ?1 AND suppressed = 0 AND found_at >= ?2 GROUP BY check_id",
        )?;
        let mut by: std::collections::HashMap<String, u32> = Default::default();
        for r in st.query_map(params![device, since], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })? {
            let (c, n) = r?;
            by.insert(c, n.try_into()?);
        }
        let g = |c: &str| by.get(c).copied().unwrap_or(0);
        let new_towers: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM (SELECT key FROM towers WHERE first_seen >= ?1
                                   UNION SELECT key FROM held_towers WHERE first_seen >= ?1)",
            params![since],
            |r| r.get(0),
        )?;
        let towers_seen: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT key) FROM tower_sightings WHERE hour >= ?1",
            params![ts(&(now - Duration::hours(24)).duration_trunc(Duration::hours(1))?)],
            |r| r.get(0),
        )?;
        let fixed_since = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'fixed_since'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .map(|s| parse_ts(&s))
            .transpose()?;
        Ok(Report {
            analyser_high: g(checks::ANALYSER_HIGH),
            analyser_other: g(checks::ANALYSER_OTHER),
            off_rhythm: g(checks::IDENTITY_OFF_RHYTHM),
            failure_spikes: g(checks::FAILURE_SPIKE),
            decoder_failures: g(checks::DECODER_FAILURE),
            archive_corrupt: g(checks::ARCHIVE_CORRUPT),
            new_towers: new_towers.try_into()?,
            towers_seen: towers_seen.try_into()?,
            learning: fixed_since.is_none_or(|s| now - s < Duration::days(learn_days)),
        })
    }

    /// One call of the summary, usage only. `outcome` is a fixed word.
    #[allow(clippy::too_many_arguments)]
    pub fn summary_log_add(
        &self,
        device: &str,
        at: DateTime<Utc>,
        alert_id: i64,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        outcome: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO summary_log (device, at, alert_id, model, input_tokens, output_tokens, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![device, ts(&at), alert_id, model, input_tokens as i64, output_tokens as i64, outcome],
        )?;
        Ok(())
    }

    /// When the API was last asked (a call that never left the machine does not count).
    pub fn summary_last_call(&self, device: &str) -> Result<Option<DateTime<Utc>>> {
        let at: Option<String> = self
            .conn
            .query_row(
                "SELECT at FROM summary_log WHERE device = ?1 AND outcome != 'no_internet'
                 ORDER BY at DESC, id DESC LIMIT 1",
                params![device],
                |r| r.get(0),
            )
            .optional()?;
        at.map(|a| parse_ts(&a)).transpose()
    }

    /// Running totals (input, output) over every logged call.
    pub fn summary_totals(&self, device: &str) -> Result<(u64, u64)> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0)
             FROM summary_log WHERE device = ?1",
            params![device],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )?)
    }

    /// The numbers a summary judges an alert against (`summary::Baseline`): identity
    /// requests in the last 24 h, the mean per day over the 7 days before that, and the
    /// strong alerts opened in the last 30 days (TEST drills excluded). Named apart from
    /// `baseline`, which is the judge's. `profile` is the caller's word (`fixed` /
    /// `mobile` / `learning`): the store knows when Fixed began, not the learning days.
    pub fn summary_baseline(
        &self,
        device: &str,
        now: DateTime<Utc>,
        profile: &'static str,
    ) -> Result<crate::summary::Baseline> {
        let ids = |from: DateTime<Utc>, to: DateTime<Utc>| -> Result<i64> {
            Ok(self.conn.query_row(
                "SELECT COUNT(*) FROM identity_requests WHERE device = ?1 AND ts >= ?2 AND ts < ?3",
                params![device, ts(&from), ts(&to)],
                |r| r.get(0),
            )?)
        };
        let day = now - Duration::hours(24);
        // Half-open windows: the last 24 h is [day, now] (the +1 s makes `now` itself count),
        // the week before is [day - 7 d, day), so a row at exactly `day` is counted once.
        let last_24h = ids(day, now + Duration::seconds(1))?;
        let week = ids(day - Duration::days(7), day)?;
        let strong: Vec<&str> = crate::mesh::checks_for(crate::mesh::Level::Strong).to_vec();
        let marks = vec!["?"; strong.len()].join(",");
        let sql = format!(
            "SELECT COUNT(*) FROM alerts a WHERE a.device = ?1 AND a.opened_at >= ?2 AND a.opened_at <= ?3
               AND EXISTS (SELECT 1 FROM alert_events e WHERE e.alert_id = a.id AND e.check_id IN ({marks}))"
        );
        let mut args: Vec<String> = vec![
            device.to_string(),
            ts(&(now - Duration::days(30))),
            ts(&now),
        ];
        args.extend(strong.iter().map(|s| s.to_string()));
        let alerts: i64 = self
            .conn
            .query_row(&sql, rusqlite::params_from_iter(args.iter()), |r| r.get(0))?;
        Ok(crate::summary::Baseline {
            identity_24h: last_24h.try_into()?,
            identity_per_day_7d: week as f64 / 7.0,
            strong_alerts_30d: alerts.try_into()?,
            profile,
        })
    }

    pub fn baseline(&self, profile: &str, now: DateTime<Utc>) -> Result<Baseline> {
        let mut st = self
            .conn
            .prepare("SELECT key FROM towers WHERE profile = ?1")?;
        let towers = st
            .query_map(params![profile], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        let mut st = self
            .conn
            .prepare("SELECT key FROM held_towers WHERE profile = ?1 AND first_seen >= ?2")?;
        let held = st
            .query_map(
                params![profile, ts(&(now - Duration::days(checks::HOLD_DAYS)))],
                |r| r.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        let fixed_since = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'fixed_since'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(|s| parse_ts(&s))
            .transpose()?;
        // Gaps are measured within one capture only: the time between captures is
        // the unit being off, not the network's rhythm. Windowed on the add-on's
        // clock, the 30 days before `now` up to a day past it: a far-future stamp a
        // fake base station planted can neither anchor the window nor fall in it.
        let mut fixed_gaps_secs = Vec::new();
        if profile == "fixed" {
            let lo = ts(&(now - Duration::days(30)));
            let hi = ts(&(now + Duration::days(1)));
            let mut st = self.conn.prepare(
                "SELECT device, name, start, ts FROM identity_requests
                 WHERE profile = 'fixed' AND ts >= ?1 AND ts <= ?2
                 ORDER BY device, name, start, seq",
            )?;
            let mut rows = st.query(params![lo, hi])?;
            let mut prev: Option<(String, DateTime<Utc>)> = None;
            while let Some(r) = rows.next()? {
                let id = format!(
                    "{}\0{}\0{}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?
                );
                let t = parse_ts(&r.get::<_, String>(3)?)?;
                if let Some((pid, pt)) = &prev
                    && *pid == id
                {
                    // A gap of zero or less is a clock step, not a rhythm.
                    let g = (t - *pt).num_seconds();
                    if g > 0 {
                        fixed_gaps_secs.push(g);
                    }
                }
                prev = Some((id, t));
            }
        }
        Ok(Baseline {
            towers,
            held,
            fixed_since,
            fixed_gaps_secs,
        })
    }

    /// Hours in `[from, to)` that have recorded failures, oldest first.
    pub fn failure_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<(DateTime<Utc>, u64, u64)>> {
        let mut st = self.conn.prepare(
            "SELECT hour, count, frames FROM failure_hours
             WHERE hour >= ?1 AND hour < ?2 ORDER BY hour",
        )?;
        let mut rows = st.query(params![ts(&from), ts(&to)])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push((
                parse_ts(&r.get::<_, String>(0)?)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
            ));
        }
        Ok(out)
    }

    /// The last identity request of the capture this one directly follows: judged,
    /// recorded in the same profile, both clocks synced, and ending within five
    /// minutes of this start. Anything further apart is a power cycle, not a
    /// continuous watch; a stamp past `start + 5 min` is not a real time.
    pub fn previous_identity(
        &self,
        device: &str,
        profile: &str,
        start: &DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>> {
        if *start < synced_floor() {
            return Ok(None);
        }
        let near = Duration::minutes(crate::checks::BACK_TO_BACK_MIN);
        let lo = (*start - near).max(synced_floor());
        let hi = *start + near;
        let prev: Option<(String, String, String)> = self
            .conn
            .query_row(
                "SELECT c.device, c.name, c.start FROM captures c
                 JOIN decodes d ON d.device = c.device AND d.name = c.name
                                AND d.start = c.start AND d.judged = 1
                 WHERE c.device = ?1 AND c.start < ?2
                   AND c.last_message >= ?3 AND c.last_message <= ?4
                   AND d.profile = ?5
                 ORDER BY c.start DESC LIMIT 1",
                params![device, ts(start), ts(&lo), ts(&hi), profile],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((dv, name, st)) = prev else {
            return Ok(None);
        };
        let last: Option<String> = self.conn.query_row(
            "SELECT MAX(ts) FROM identity_requests
             WHERE device = ?1 AND name = ?2 AND start = ?3 AND ts >= ?4 AND ts <= ?5",
            params![dv, name, st, ts(&synced_floor()), ts(&hi)],
            |r| r.get(0),
        )?;
        last.map(|s| parse_ts(&s)).transpose()
    }

    /// (check, level, spans_switch, suppressed, detail) of a capture's findings.
    #[allow(dead_code)] // read by 2c's report; in 2b only the tests read it
    pub fn findings(&self, k: Key) -> Result<Vec<(String, String, bool, bool, String)>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT check_id, level, spans_switch, suppressed, detail FROM findings
             WHERE {KEY} ORDER BY rowid"
        ))?;
        let mut rows = st.query(params![k.device, k.name, ts(k.start)])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{self, Finding, Learn, Level};
    use crate::events::Strength;
    use crate::store::{DecodeStatus, State};

    fn at(day: u32, h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, h, m, 0).unwrap()
    }

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        (d, s)
    }

    fn cap(name: &str, start: DateTime<Utc>, last: Option<DateTime<Utc>>) -> Capture {
        Capture {
            device: "m2100".into(),
            name: name.into(),
            state: State::Archived,
            local_sha256: Some("a".repeat(64)),
            device_sha256: Some("a".repeat(64)),
            size: 1,
            start,
            last_message: last,
            archived_at: Some(start),
            mismatch_tries: 0,
            kept: false,
            flagged: false,
            file: Some(format!("{name}-stem")),
            analysis_tries: 0,
        }
    }

    fn dec(c: &Capture) -> Decode {
        Decode {
            device: c.device.clone(),
            name: c.name.clone(),
            start: c.start,
            status: DecodeStatus::Ok,
            profile: "fixed".into(),
            frames: 10,
            failures: 1,
            towers: 1,
            identity_requests: 2,
            warnings_high: 0,
            warnings_other: 0,
            decoder_hash: "f".repeat(64),
            decoded_at: at(11, 0, 0),
            detail: None,
        }
    }

    fn finding(level: Level) -> Finding {
        Finding {
            check: checks::NEW_TOWER,
            level,
            detail: "d".into(),
        }
    }

    fn judgement(findings: Vec<Finding>, learn: Option<Learn>) -> Judgement {
        Judgement {
            profile: Profile::Fixed,
            findings,
            learn,
            spans_switch: false,
            suppressed: false,
            towers_known: None,
        }
    }

    fn learn() -> Learn {
        Learn {
            towers: vec![("310-260-1".into(), Strength::Sib1)],
            hold: vec![],
            identity_ts: vec![at(1, 8, 0), at(1, 8, 10), at(1, 8, 25)],
            failure_hours: vec![(at(1, 8, 0), 3, 100)],
        }
    }

    fn hold(key: &str) -> Learn {
        Learn {
            hold: vec![key.into()],
            ..Learn::default()
        }
    }

    #[test]
    fn a_held_tower_is_kept_seven_days_then_forgotten() {
        let (_d, s) = store();
        let c = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        judged(&s, &c, &judgement(vec![], Some(hold("k"))), at(1, 9, 0));
        let b = s.baseline("fixed", at(8, 8, 59)).unwrap();
        assert_eq!(b.held, HashSet::from(["k".to_string()]));
        assert!(b.towers.is_empty(), "held is not learned");
        assert!(s.baseline("mobile", at(2, 0, 0)).unwrap().held.is_empty());
        assert!(s.baseline("fixed", at(8, 9, 1)).unwrap().held.is_empty(), "past 7 days");
    }

    #[test]
    fn learning_a_held_tower_releases_it() {
        let (_d, s) = store();
        let a = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        judged(&s, &a, &judgement(vec![], Some(hold("310-260-1"))), at(1, 9, 0));
        let b = cap("b", at(2, 8, 0), Some(at(2, 9, 0)));
        judged(&s, &b, &judgement(vec![], Some(learn())), at(2, 9, 0));
        let base = s.baseline("fixed", at(2, 10, 0)).unwrap();
        assert!(base.towers.contains("310-260-1"));
        assert!(base.held.is_empty());
    }

    #[test]
    fn a_held_tower_counts_as_new_and_seen_in_the_24h_sensors() {
        let (_d, s) = store();
        let c = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        judged(&s, &c, &judgement(vec![], Some(hold("k"))), at(1, 9, 0));
        let r = s.report("m2100", at(1, 10, 0), 7).unwrap();
        assert_eq!((r.new_towers, r.towers_seen), (1, 1));
    }

    fn key(c: &Capture) -> Key<'_> {
        c.key()
    }

    fn judged(s: &Store, c: &Capture, j: &Judgement, now: DateTime<Utc>) {
        s.record_archived(c).ok();
        s.record_judgement(&dec(c), j, now).unwrap();
    }

    fn count(s: &Store, sql: &str) -> i64 {
        s.conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn the_outbox_carries_the_tower_status() {
        let (_d, s) = store();
        for (name, status) in [("k1", Some(true)), ("k2", Some(false)), ("k3", None)] {
            let mut j = judgement(vec![notify(checks::ANALYSER_HIGH)], None);
            j.towers_known = status;
            judged(&s, &cap(name, at(1, 8, 0), None), &j, at(1, 9, 0));
        }
        let (p, _) = s.pending_notifications("m2100", at(1, 9, 1), 10).unwrap();
        let got: Vec<(&str, Option<bool>)> = p.iter().map(|x| (x.name.as_str(), x.towers_known)).collect();
        assert_eq!(got, [("k1", Some(true)), ("k2", Some(false)), ("k3", None)]);
    }

    /// Insert an outbox row directly, with a chosen profile, switch flag and found_at.
    fn outbox(s: &Store, name: &str, check: &str, profile: &str, spans: i64, found: DateTime<Utc>) -> i64 {
        s.conn
            .execute(
                "INSERT INTO notifications
                 (device, name, start, check_id, count, profile, spans_switch, found_at)
                 VALUES ('m2100', ?1, ?2, ?3, 1, ?4, ?5, ?6)",
                params![name, ts(&found), check, profile, spans, ts(&found)],
            )
            .unwrap();
        s.conn.last_insert_rowid()
    }

    fn mesh_ids(s: &Store, checks: &[&str], now: DateTime<Utc>, limit: usize) -> Vec<i64> {
        s.mesh_pending("m2100", checks, now, limit)
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    }

    #[test]
    fn mesh_sent_rows_are_not_offered_again() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        let now = at(1, 12, 0);
        let id;
        {
            let s = Store::open(&p).unwrap();
            id = outbox(&s, "m1", checks::ANALYSER_HIGH, "fixed", 0, at(1, 11, 0));
            assert_eq!(
                s.mesh_pending("m2100", &[checks::ANALYSER_HIGH], now, 10).unwrap(),
                [(id, checks::ANALYSER_HIGH.to_string())]
            );
            s.mark_mesh(&[id], now).unwrap();
            assert!(mesh_ids(&s, &[checks::ANALYSER_HIGH], now, 10).is_empty());
            // HA is independent: its outcome is untouched.
            let (pend, _) = s.pending_notifications("m2100", now, 10).unwrap();
            assert_eq!(pend.len(), 1);
            assert_eq!(pend[0].id, id);
        }
        let s = Store::open(&p).unwrap();
        assert!(mesh_ids(&s, &[checks::ANALYSER_HIGH], now, 10).is_empty());
    }

    #[test]
    fn mobile_and_switch_rows_are_never_offered() {
        let (_d, s) = store();
        let now = at(1, 12, 0);
        outbox(&s, "mob", checks::ANALYSER_HIGH, "mobile", 0, at(1, 11, 0));
        outbox(&s, "sw", checks::ANALYSER_HIGH, "fixed", 1, at(1, 11, 0));
        assert!(mesh_ids(&s, &[checks::ANALYSER_HIGH], now, 10).is_empty());
    }

    #[test]
    fn offers_at_most_limit_oldest_first_within_24h() {
        let (_d, s) = store();
        let now = at(2, 12, 0);
        let mut ids = Vec::new();
        for h in 1..=5i64 {
            ids.push(outbox(&s, &format!("f{h}"), checks::TOWER_FLOOD, "fixed", 0, now - Duration::hours(h)));
        }
        outbox(&s, "old", checks::TOWER_FLOOD, "fixed", 0, now - Duration::hours(25));
        // -5h, -4h, -3h
        assert_eq!(mesh_ids(&s, &[checks::TOWER_FLOOD], now, 3), [ids[4], ids[3], ids[2]]);
    }

    #[test]
    fn only_requested_checks_are_offered() {
        let (_d, s) = store();
        let now = at(1, 12, 0);
        outbox(&s, "a", checks::NEW_TOWER, "fixed", 0, at(1, 11, 0));
        let b = outbox(&s, "b", checks::ANALYSER_HIGH, "fixed", 0, at(1, 11, 0));
        assert_eq!(mesh_ids(&s, &[checks::ANALYSER_HIGH], now, 10), [b]);
        assert!(mesh_ids(&s, &[], now, 10).is_empty());
    }

    /// 0.6.0: rows already meshed or past 24 h are stamped as ingested; an unsent recent
    /// strong row (0.5 would still have retried it) goes through the alerts.
    #[test]
    fn migration_adds_alert_at_and_keeps_unsent_recent_rows() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        let now = Utc::now();
        {
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE notifications (
                    device TEXT NOT NULL, name TEXT NOT NULL, start TEXT NOT NULL,
                    check_id TEXT NOT NULL, count INTEGER NOT NULL, profile TEXT NOT NULL,
                    spans_switch INTEGER NOT NULL, found_at TEXT NOT NULL,
                    towers_known INTEGER, sent_at TEXT,
                    outcome TEXT CHECK (outcome IN ('sent', 'expired', 'merged')),
                    mesh_at TEXT,
                    PRIMARY KEY (device, name, start, check_id)
                 );",
            )
            .unwrap();
            let hour_ago = ts(&(now - Duration::hours(1)));
            let two_days = ts(&(now - Duration::hours(48)));
            for (name, found, mesh) in [("meshed", &hour_ago, Some(&hour_ago)), ("unsent", &hour_ago, None), ("old", &two_days, None)] {
                c.execute(
                    "INSERT INTO notifications VALUES
                        ('m2100',?1,?2,'analyser_high',1,'fixed',0,?2,NULL,NULL,NULL,?3)",
                    params![name, found, mesh],
                )
                .unwrap();
            }
        }
        let s = Store::open(&p).unwrap();
        let names: Vec<String> = s
            .alert_pending("m2100", &[checks::ANALYSER_HIGH], 10)
            .unwrap()
            .into_iter()
            .map(|(id, _)| s.row_findings(id).unwrap().unwrap().0)
            .collect();
        assert_eq!(names, ["unsent"]);
        let fresh = outbox(&s, "fresh", checks::ANALYSER_HIGH, "fixed", 0, now);
        let ids: Vec<i64> = s.alert_pending("m2100", &[checks::ANALYSER_HIGH], 10).unwrap().into_iter().map(|x| x.0).collect();
        assert!(ids.contains(&fresh), "a new row is pending");
        s.mark_alerted(fresh, now).unwrap();
        let ids: Vec<i64> = s.alert_pending("m2100", &[checks::ANALYSER_HIGH], 10).unwrap().into_iter().map(|x| x.0).collect();
        assert!(!ids.contains(&fresh), "marked once");
    }

    /// I3: the migration stamps every row it finds as already meshed, so the first deploy
    /// does not page the family with findings HA already alerted on.
    #[test]
    fn migration_adds_mesh_at_to_an_existing_db() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        let now = Utc::now();
        {
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE notifications (
                    device TEXT NOT NULL, name TEXT NOT NULL, start TEXT NOT NULL,
                    check_id TEXT NOT NULL, count INTEGER NOT NULL, profile TEXT NOT NULL,
                    spans_switch INTEGER NOT NULL, found_at TEXT NOT NULL,
                    towers_known INTEGER, sent_at TEXT,
                    outcome TEXT CHECK (outcome IN ('sent', 'expired', 'merged')),
                    PRIMARY KEY (device, name, start, check_id)
                 );
                 INSERT INTO notifications VALUES
                    ('m2100','old','2026-10-01T11:00:00Z','analyser_high',1,'fixed',0,
                     '2026-10-01T11:00:00Z',NULL,NULL,NULL);",
            )
            .unwrap();
            // A strong finding from an hour ago: inside the 24 h window, already alerted on.
            let hour_ago = ts(&(now - Duration::hours(1)));
            c.execute(
                "INSERT INTO notifications VALUES
                    ('m2100','recent',?1,'analyser_high',1,'fixed',0,?1,NULL,NULL,NULL)",
                params![hour_ago],
            )
            .unwrap();
        }
        let s = Store::open(&p).unwrap();
        let cols: Vec<String> = s
            .conn
            .prepare("PRAGMA table_info(notifications)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(cols.iter().any(|c| c == "mesh_at"));
        assert!(mesh_ids(&s, &[checks::ANALYSER_HIGH], at(1, 12, 0), 10).is_empty());
        assert!(
            mesh_ids(&s, &[checks::ANALYSER_HIGH], now, 10).is_empty(),
            "a pre-existing row is not offered to the mesh"
        );
        let fresh = outbox(&s, "fresh", checks::ANALYSER_HIGH, "fixed", 0, now);
        assert_eq!(mesh_ids(&s, &[checks::ANALYSER_HIGH], now, 10), [fresh], "a new row is");
        drop(s);
        let s = Store::open(&p).unwrap(); // idempotent: a reopen stamps nothing new
        assert_eq!(mesh_ids(&s, &[checks::ANALYSER_HIGH], now, 10), [fresh]);
    }

    #[test]
    fn a_040_outbox_gains_the_tower_status_column() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        let c = cap("o40", at(1, 8, 0), None);
        {
            let s = Store::open(&p).unwrap();
            judged(&s, &c, &judgement(vec![notify(checks::NEW_TOWER)], None), at(1, 9, 0));
            // make it look like 0.4.0: no towers_known column
            s.conn
                .execute_batch("ALTER TABLE notifications DROP COLUMN towers_known")
                .unwrap();
        }
        let s = Store::open(&p).unwrap();
        let (p0, _) = s.pending_notifications("m2100", at(1, 9, 1), 10).unwrap();
        assert_eq!(p0.len(), 1, "the 0.4.0 row survives");
        assert_eq!(p0[0].towers_known, None);
        drop(s);
        Store::open(&p).unwrap(); // reopening again is a no-op
    }

    #[test]
    fn a_2a_database_gains_judged_zero_and_keeps_its_row() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        let c = cap("old", at(1, 8, 0), None);
        {
            let s = Store::open(&p).unwrap();
            s.record_archived(&c).unwrap();
            s.record_decode(&dec(&c)).unwrap();
            // make it look like 2a: no judged column
            s.conn
                .execute_batch("ALTER TABLE decodes DROP COLUMN judged")
                .unwrap();
        }
        let s = Store::open(&p).unwrap();
        assert_eq!(
            count(&s, "SELECT judged FROM decodes WHERE name = 'old'"),
            0
        );
        assert!(s.get_decode(key(&c)).unwrap().is_some());
        // reopening again is a no-op
        drop(s);
        Store::open(&p).unwrap();
    }

    #[test]
    fn unjudged_returns_never_decoded_and_unjudged_oldest_first() {
        let (_d, s) = store();
        let newer = cap("newer", at(5, 0, 0), None);
        let older = cap("older", at(3, 0, 0), None);
        let half = cap("half", at(4, 0, 0), None); // a 2a decode, never judged
        let done = cap("done", at(1, 0, 0), None);
        let mut nofile = cap("nofile", at(2, 0, 0), None);
        nofile.state = State::MissingOnDevice;
        nofile.file = None;
        for c in [&newer, &older, &half, &done, &nofile] {
            s.record_archived(c).unwrap();
        }
        s.record_decode(&dec(&half)).unwrap();
        s.record_judgement(&dec(&done), &judgement(vec![], None), at(11, 0, 0))
            .unwrap();
        let got = s.unjudged("m2100", 10).unwrap();
        let names: Vec<_> = got.iter().map(|(c, _)| c.name.as_str()).collect();
        assert_eq!(names, ["older", "half", "newer"]);
        assert!(got[0].1.is_none());
        assert_eq!(got[1].1, Some(dec(&half)));
        assert_eq!(s.unjudged("m2100", 2).unwrap().len(), 2);
        assert!(s.unjudged("other", 10).unwrap().is_empty());
    }

    #[test]
    fn judge_epoch_is_set_once() {
        let (_d, s) = store();
        assert_eq!(s.judge_epoch(at(1, 0, 0)).unwrap(), at(1, 0, 0));
        assert_eq!(s.judge_epoch(at(9, 0, 0)).unwrap(), at(1, 0, 0));
    }

    #[test]
    fn a_notify_finding_flags_the_capture_and_count_does_not() {
        let (_d, s) = store();
        let n = cap("n", at(1, 0, 0), None);
        let c = cap("c", at(2, 0, 0), None);
        judged(
            &s,
            &n,
            &judgement(vec![finding(Level::Notify)], None),
            at(11, 0, 0),
        );
        judged(
            &s,
            &c,
            &judgement(vec![finding(Level::Count)], None),
            at(11, 0, 0),
        );
        assert!(s.get(key(&n)).unwrap().unwrap().flagged);
        assert!(!s.get(key(&c)).unwrap().unwrap().flagged);
        assert_eq!(
            s.findings(key(&n)).unwrap(),
            [(
                "new_tower".into(),
                "notify".into(),
                false,
                false,
                "d".into()
            )]
        );
        assert_eq!(count(&s, "SELECT judged FROM decodes WHERE name = 'n'"), 1);
    }

    #[test]
    fn learning_writes_towers_identity_hours_and_fixed_since() {
        let (_d, s) = store();
        let c = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        judged(&s, &c, &judgement(vec![], Some(learn())), at(11, 0, 0));
        let b = s.baseline("fixed", at(11, 0, 0)).unwrap();
        assert_eq!(b.towers, HashSet::from(["310-260-1".to_string()]));
        assert_eq!(b.fixed_since, Some(at(11, 0, 0)));
        assert_eq!(b.fixed_gaps_secs, [600, 900]);
        assert!(
            s.baseline("mobile", at(11, 0, 0))
                .unwrap()
                .towers
                .is_empty()
        );
        assert_eq!(
            s.failure_history(at(1, 8, 0), at(1, 9, 0)).unwrap(),
            [(at(1, 8, 0), 3, 100)]
        );
        // [from, to) is half open
        assert!(
            s.failure_history(at(1, 7, 0), at(1, 8, 0))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn judging_twice_replaces_findings_and_never_relearns() {
        let (_d, s) = store();
        let c = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        let j = judgement(vec![finding(Level::Count)], Some(learn()));
        judged(&s, &c, &j, at(11, 0, 0));
        judged(&s, &c, &j, at(12, 0, 0));
        assert_eq!(s.findings(key(&c)).unwrap().len(), 1);
        assert_eq!(count(&s, "SELECT count FROM failure_hours"), 3);
        assert_eq!(count(&s, "SELECT frames FROM failure_hours"), 100);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM identity_requests"), 3);
        let first: String = s
            .conn
            .query_row("SELECT first_seen FROM towers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(parse_ts(&first).unwrap(), at(11, 0, 0));
    }

    #[test]
    fn a_failure_mid_transaction_leaves_nothing_behind() {
        let (_d, s) = store();
        let c = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        s.record_archived(&c).unwrap();
        s.conn
            .execute_batch(
                "CREATE TRIGGER no_findings BEFORE INSERT ON findings
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        let j = judgement(vec![finding(Level::Notify)], Some(learn()));
        assert!(s.record_judgement(&dec(&c), &j, at(11, 0, 0)).is_err());
        assert!(s.get_decode(key(&c)).unwrap().is_none());
        assert_eq!(count(&s, "SELECT COUNT(*) FROM towers"), 0);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM identity_requests"), 0);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM failure_hours"), 0);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM meta"), 0);
        assert!(!s.get(key(&c)).unwrap().unwrap().flagged);
    }

    #[test]
    fn previous_identity_needs_a_judged_synced_back_to_back_capture() {
        let (_d, s) = store();
        let prev = cap("prev", at(1, 8, 0), Some(at(1, 9, 0)));
        judged(&s, &prev, &judgement(vec![], Some(learn())), at(11, 0, 0));
        let last = at(1, 8, 25);
        let edge = at(1, 9, 5);
        assert_eq!(
            s.previous_identity("m2100", "fixed", &edge).unwrap(),
            Some(last)
        );
        let late = edge + Duration::seconds(1);
        assert_eq!(s.previous_identity("m2100", "fixed", &late).unwrap(), None);
        // the other side of the boundary: a next capture starting before the previous ended
        let early = at(1, 8, 55);
        assert_eq!(
            s.previous_identity("m2100", "fixed", &early).unwrap(),
            Some(last)
        );
        assert_eq!(s.previous_identity("other", "fixed", &edge).unwrap(), None);
        // not below its own start
        assert_eq!(
            s.previous_identity("m2100", "fixed", &at(1, 8, 0)).unwrap(),
            None
        );
    }

    #[test]
    fn previous_identity_ignores_unjudged_and_unsynced() {
        let (_d, s) = store();
        // decoded but never judged
        let raw = cap("raw", at(1, 8, 0), Some(at(1, 9, 0)));
        s.record_archived(&raw).unwrap();
        s.record_decode(&dec(&raw)).unwrap();
        assert_eq!(
            s.previous_identity("m2100", "fixed", &at(1, 9, 1)).unwrap(),
            None
        );
        // a previous capture from before the clock synced
        let old = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let unsynced = cap("u", old, Some(old + Duration::seconds(60)));
        judged(
            &s,
            &unsynced,
            &judgement(vec![], Some(learn())),
            at(11, 0, 0),
        );
        assert_eq!(
            s.previous_identity("m2100", "fixed", &(old + Duration::seconds(120)))
                .unwrap(),
            None
        );
        // a synced capture right after an unsynced one
        assert_eq!(
            s.previous_identity("m2100", "fixed", &(old + Duration::seconds(60)))
                .unwrap(),
            None
        );
    }

    #[test]
    fn previous_identity_ignores_unsynced_identity_stamps() {
        let (_d, s) = store();
        // clock synced mid-capture: last_message is real, the attach-time request is 1970
        let prev = cap("prev", at(1, 8, 0), Some(at(1, 9, 0)));
        let l = Learn {
            identity_ts: vec![Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 0).unwrap()],
            ..Default::default()
        };
        judged(&s, &prev, &judgement(vec![], Some(l)), at(11, 0, 0));
        assert_eq!(
            s.previous_identity("m2100", "fixed", &at(1, 9, 1)).unwrap(),
            None
        );
    }

    #[test]
    fn fixed_gaps_never_span_captures() {
        let (_d, s) = store();
        let a = cap("a", at(1, 8, 0), None);
        let b = cap("b", at(1, 12, 0), None);
        let la = Learn {
            identity_ts: vec![at(1, 8, 0), at(1, 8, 10)],
            ..Default::default()
        };
        let lb = Learn {
            identity_ts: vec![at(1, 12, 0), at(1, 12, 20)],
            ..Default::default()
        };
        judged(&s, &a, &judgement(vec![], Some(la)), at(11, 0, 0));
        judged(&s, &b, &judgement(vec![], Some(lb)), at(11, 0, 0));
        let mut gaps = s.baseline("fixed", at(11, 0, 0)).unwrap().fixed_gaps_secs;
        gaps.sort();
        assert_eq!(gaps, [600, 1200]);
    }

    fn y2099() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap()
    }

    fn ids(name: &str, start: DateTime<Utc>, stamps: Vec<DateTime<Utc>>) -> (Capture, Judgement) {
        let l = Learn {
            identity_ts: stamps,
            ..Default::default()
        };
        (cap(name, start, None), judgement(vec![], Some(l)))
    }

    #[test]
    fn a_far_future_identity_row_does_not_pin_the_baseline_window() {
        let (_d, s) = store();
        let now = at(11, 12, 0);
        // Rows a pre-fix add-on may already hold: real gaps, then one 2099 stamp.
        let mut stamps: Vec<_> = (0..12)
            .map(|i| at(10, 0, 0) + Duration::minutes(50 * i))
            .collect();
        stamps.push(y2099());
        let (c, j) = ids("a", at(10, 0, 0), stamps);
        judged(&s, &c, &j, now);
        assert_eq!(
            s.baseline("fixed", now).unwrap().fixed_gaps_secs,
            [3000; 11]
        );
    }

    #[test]
    fn the_gap_window_is_the_30_days_before_now() {
        let (_d, s) = store();
        let now = at(11, 12, 0);
        let old = now - Duration::days(31);
        let (c, j) = ids("old", old, vec![old, old + Duration::minutes(10)]);
        judged(&s, &c, &j, now);
        assert!(s.baseline("fixed", now).unwrap().fixed_gaps_secs.is_empty());
        let edge = now - Duration::days(30);
        let (c, j) = ids("edge", edge, vec![edge, edge + Duration::minutes(20)]);
        judged(&s, &c, &j, now);
        assert_eq!(s.baseline("fixed", now).unwrap().fixed_gaps_secs, [1200]);
    }

    #[test]
    fn baseline_gaps_drop_zero_and_negative() {
        let (_d, s) = store();
        let t = at(1, 8, 0);
        let (c, j) = ids(
            "a",
            t,
            vec![
                t,
                t,
                t + Duration::minutes(10),
                t + Duration::minutes(5),
                t + Duration::minutes(25),
            ],
        );
        judged(&s, &c, &j, at(11, 0, 0));
        assert_eq!(
            s.baseline("fixed", at(11, 0, 0)).unwrap().fixed_gaps_secs,
            [600, 1200]
        );
    }

    /// End to end: checks, store, checks again.
    #[test]
    fn a_2099_stamp_teaches_nothing_and_the_next_capture_gets_the_real_median() {
        use crate::events::Observations;
        let (_d, s) = store();
        let now = at(11, 12, 0);
        let mut stamps: Vec<Option<String>> = (0..12)
            .map(|i| Some((at(10, 0, 0) + Duration::minutes(50 * i)).to_rfc3339()))
            .collect();
        stamps.push(Some("2099-01-01T00:00:00Z".into()));
        let judge = |seen: &Observations, b: &Baseline| {
            checks::judge(&checks::Input {
                profile: Profile::Fixed,
                status: DecodeStatus::Ok,
                seen,
                baseline: b,
                prev_identity: None,
                failure_history: &[],
                now,
                settings: &checks::Settings::default(),
            })
        };
        let first = Observations {
            identity_ts: stamps,
            ..Default::default()
        };
        let (findings, learn) = judge(&first, &Baseline::default());
        let c = cap("a", at(10, 0, 0), None);
        judged(&s, &c, &judgement(findings, learn), now);
        assert_eq!(
            count(
                &s,
                "SELECT COUNT(*) FROM identity_requests WHERE ts >= '2099'"
            ),
            0
        );
        // The bad stamp spoils the whole capture's rhythm (2c D3); a clean one teaches it.
        assert!(s.baseline("fixed", now).unwrap().fixed_gaps_secs.is_empty());
        let clean = Observations {
            identity_ts: first.identity_ts[..12].to_vec(),
            ..Default::default()
        };
        let (findings, learn) = judge(&clean, &Baseline::default());
        let c = cap("b", at(10, 0, 0), None);
        judged(&s, &c, &judgement(findings, learn), now);
        let mut b = s.baseline("fixed", now).unwrap();
        assert_eq!(b.fixed_gaps_secs, [3000; 11]);
        // Past learning, a 50 min gap is on rhythm (108 would say off).
        b.fixed_since = Some(now - Duration::days(20));
        let next = Observations {
            identity_ts: vec![
                Some(at(11, 10, 0).to_rfc3339()),
                Some(at(11, 10, 50).to_rfc3339()),
            ],
            ..Default::default()
        };
        let (f, _) = judge(&next, &b);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn previous_identity_ignores_far_future_stamps() {
        let (_d, s) = store();
        let prev = cap("prev", at(1, 8, 0), Some(at(1, 9, 0)));
        let l = Learn {
            identity_ts: vec![at(1, 8, 25), y2099()],
            ..Default::default()
        };
        judged(&s, &prev, &judgement(vec![], Some(l)), at(11, 0, 0));
        assert_eq!(
            s.previous_identity("m2100", "fixed", &at(1, 9, 5)).unwrap(),
            Some(at(1, 8, 25))
        );
    }

    #[test]
    fn previous_identity_comes_only_from_the_same_profile() {
        let (_d, s) = store();
        let prev = cap("prev", at(1, 8, 0), Some(at(1, 9, 0)));
        s.record_archived(&prev).unwrap();
        let mut d = dec(&prev);
        d.profile = "mobile".into();
        let mut j = judgement(vec![], Some(learn()));
        j.profile = Profile::Mobile;
        s.record_judgement(&d, &j, at(11, 0, 0)).unwrap();
        assert_eq!(
            s.previous_identity("m2100", "fixed", &at(1, 9, 5)).unwrap(),
            None
        );
        assert_eq!(
            s.previous_identity("m2100", "mobile", &at(1, 9, 5))
                .unwrap(),
            Some(at(1, 8, 25))
        );
    }

    #[test]
    fn only_an_ok_decode_learns_in_the_store() {
        let (_d, s) = store();
        let c = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        s.record_archived(&c).unwrap();
        let mut d = dec(&c);
        d.status = DecodeStatus::DecoderFailure;
        s.record_judgement(&d, &judgement(vec![], Some(learn())), at(11, 0, 0))
            .unwrap();
        assert_eq!(count(&s, "SELECT COUNT(*) FROM towers"), 0);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM identity_requests"), 0);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM failure_hours"), 0);
        assert_eq!(
            count(&s, "SELECT COUNT(*) FROM meta WHERE key = 'fixed_since'"),
            0
        );
        // the control: the same judgement with an ok decode learns
        let c = cap("b", at(2, 8, 0), Some(at(2, 9, 0)));
        judged(&s, &c, &judgement(vec![], Some(learn())), at(11, 0, 0));
        assert_eq!(count(&s, "SELECT COUNT(*) FROM towers"), 1);
    }

    #[test]
    fn remove_deletes_the_captures_findings_and_identity_rows() {
        let (_d, s) = store();
        let a = cap("a", at(1, 8, 0), Some(at(1, 9, 0)));
        let b = cap("b", at(2, 8, 0), Some(at(2, 9, 0)));
        let j = judgement(vec![finding(Level::Count)], Some(learn()));
        judged(&s, &a, &j, at(11, 0, 0));
        judged(&s, &b, &j, at(11, 0, 0));
        s.remove(key(&a)).unwrap();
        assert!(s.findings(key(&a)).unwrap().is_empty());
        assert_eq!(
            count(
                &s,
                "SELECT COUNT(*) FROM identity_requests WHERE name = 'a'"
            ),
            0
        );
        // b is untouched; the shared baselines (towers, hours) stay
        assert_eq!(s.findings(key(&b)).unwrap().len(), 1);
        assert_eq!(
            count(
                &s,
                "SELECT COUNT(*) FROM identity_requests WHERE name = 'b'"
            ),
            3
        );
        assert_eq!(count(&s, "SELECT COUNT(*) FROM towers"), 1);
    }

    fn notify(check: &'static str) -> Finding {
        Finding {
            check,
            level: Level::Notify,
            detail: "secret cell 310-260-1".into(),
        }
    }

    #[test]
    fn notify_findings_queue_one_row_per_check_with_a_count() {
        let (_d, s) = store();
        let c = cap("n1", at(1, 8, 0), None);
        let j = judgement(
            vec![
                notify(checks::ANALYSER_HIGH),
                notify(checks::ANALYSER_HIGH),
                notify(checks::NEW_TOWER),
                finding(Level::Count),
            ],
            None,
        );
        judged(&s, &c, &j, at(1, 9, 0));
        let (p, expired) = s.pending_notifications("m2100", at(1, 9, 1), 10).unwrap();
        assert_eq!(expired, 0);
        let got: Vec<(String, u32)> = p.iter().map(|x| (x.check.clone(), x.count)).collect();
        assert_eq!(
            got,
            vec![("analyser_high".into(), 2), ("new_tower".into(), 1)]
        );
        assert_eq!(p[0].name, "n1");
        assert_eq!(p[0].profile, "fixed");
        assert_eq!(p[0].found_at, at(1, 9, 0));
    }

    #[test]
    fn backfill_never_queues() {
        let (_d, s) = store();
        let c = cap("b1", at(1, 8, 0), None);
        let mut j = judgement(vec![notify(checks::ANALYSER_HIGH)], None);
        j.suppressed = true;
        judged(&s, &c, &j, at(1, 9, 0));
        assert!(
            s.pending_notifications("m2100", at(1, 9, 1), 10)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn rejudge_never_requeues() {
        let (_d, s) = store();
        let c = cap("r1", at(1, 8, 0), None);
        let j = judgement(vec![notify(checks::NEW_TOWER)], None);
        judged(&s, &c, &j, at(1, 9, 0));
        let (p, _) = s.pending_notifications("m2100", at(1, 9, 1), 10).unwrap();
        s.mark_sent(&[p[0].id], at(1, 9, 2)).unwrap();
        // Judged again (the 2b path that replaces findings): no new row, still sent.
        s.record_judgement(&dec(&c), &j, at(1, 10, 0)).unwrap();
        assert!(
            s.pending_notifications("m2100", at(1, 10, 1), 10)
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(count(&s, "SELECT COUNT(*) FROM notifications"), 1);
    }

    #[test]
    fn outbox_survives_reopen_and_marks_once() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("index.sqlite");
        let c = cap("o1", at(1, 8, 0), None);
        {
            let s = Store::open(&path).unwrap();
            judged(
                &s,
                &c,
                &judgement(vec![notify(checks::DECODER_FAILURE)], None),
                at(1, 9, 0),
            );
        }
        let s = Store::open(&path).unwrap();
        let (p, _) = s.pending_notifications("m2100", at(1, 9, 30), 10).unwrap();
        assert_eq!(p.len(), 1);
        s.mark_sent(&[p[0].id], at(1, 9, 31)).unwrap();
        s.mark_sent(&[p[0].id], at(1, 9, 32)).unwrap(); // idempotent
        assert!(
            s.pending_notifications("m2100", at(1, 9, 33), 10)
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(
            count(
                &s,
                "SELECT COUNT(*) FROM notifications WHERE outcome = 'sent' \
                 AND sent_at = '2026-10-01T09:31:00.000000000Z'"
            ),
            1
        );
    }

    #[test]
    fn pending_is_oldest_first_and_limited() {
        let (_d, s) = store();
        for (i, n) in ["p3", "p1", "p2"].iter().enumerate() {
            let c = cap(n, at(1, 8, i as u32), None);
            judged(
                &s,
                &c,
                &judgement(vec![notify(checks::NEW_TOWER)], None),
                at(1, 9, [3, 1, 2][i]),
            );
        }
        let (p, _) = s.pending_notifications("m2100", at(1, 9, 10), 2).unwrap();
        let names: Vec<_> = p.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["p1", "p2"]);
    }

    #[test]
    fn unsent_rows_expire_after_24h_and_are_never_sent() {
        let (_d, s) = store();
        let c = cap("e1", at(1, 8, 0), None);
        judged(
            &s,
            &c,
            &judgement(vec![notify(checks::NEW_TOWER)], None),
            at(1, 9, 0),
        );
        let (p, expired) = s.pending_notifications("m2100", at(2, 9, 0), 10).unwrap(); // exactly 24 h: still sendable
        assert_eq!((p.len(), expired), (1, 0));
        let (p, expired) = s.pending_notifications("m2100", at(2, 9, 1), 10).unwrap();
        assert_eq!((p.len(), expired), (0, 1));
        assert_eq!(
            count(
                &s,
                "SELECT COUNT(*) FROM notifications WHERE outcome = 'expired'"
            ),
            1
        );
    }

    /// The Cribl output names the rows a cycle expired; other rows and outcomes are not.
    #[test]
    fn retired_at_lists_only_the_rows_retired_then() {
        let (_d, s) = store();
        for (n, h) in [("e1", 8), ("e2", 9), ("k1", 20)] {
            let c = cap(n, at(1, h, 0), None);
            judged(&s, &c, &judgement(vec![notify(checks::NEW_TOWER)], None), at(1, h, 0));
        }
        // e1 and e2 are over 24 h old at 2/9:30; k1 is not, and is sent instead.
        let (p, expired) = s.pending_notifications("m2100", at(2, 9, 30), 10).unwrap();
        assert_eq!((p.len(), expired), (1, 2));
        s.mark_sent(&[p[0].id], at(2, 9, 30)).unwrap();
        let got = s.retired_at("m2100", "expired", at(2, 9, 30)).unwrap();
        assert_eq!(
            got,
            [("e1".to_string(), "new_tower".to_string(), 1), ("e2".into(), "new_tower".into(), 1)]
        );
        assert!(s.retired_at("m2100", "expired", at(2, 9, 31)).unwrap().is_empty());
        assert!(s.retired_at("other", "expired", at(2, 9, 30)).unwrap().is_empty());
        let sent = s.retired_at("m2100", "sent", at(2, 9, 30)).unwrap();
        assert_eq!(sent, [("k1".to_string(), "new_tower".to_string(), 1)]);
    }

    /// I-2: the health cooldown needs the last real send per check and a 'merged' retire.
    #[test]
    fn last_sent_and_merge_for_the_health_cooldown() {
        let (_d, s) = store();
        for (n, m) in [("h1", 0), ("h2", 1), ("h3", 2)] {
            let c = cap(n, at(1, 8, m), None);
            judged(&s, &c, &judgement(vec![notify(checks::DECODER_FAILURE)], None), at(1, 9, m));
        }
        let c = cap("t1", at(1, 8, 5), None);
        judged(&s, &c, &judgement(vec![notify(checks::NEW_TOWER)], None), at(1, 9, 5));
        assert_eq!(s.last_sent("m2100", checks::DECODER_FAILURE).unwrap(), None);
        let (p, _) = s.pending_notifications("m2100", at(1, 9, 10), 10).unwrap();
        let ids: Vec<i64> = p.iter().map(|x| x.id).collect();
        s.mark_sent(&[ids[0]], at(1, 9, 20)).unwrap();
        s.mark(&[ids[1]], "merged", at(1, 9, 30)).unwrap();
        s.mark(&[ids[1]], "sent", at(1, 9, 40)).unwrap(); // already retired: untouched
        s.mark_sent(&[ids[3]], at(1, 9, 50)).unwrap(); // the new_tower row
        // Only a real send of the same check counts; merged rows and other checks do not.
        assert_eq!(
            s.last_sent("m2100", checks::DECODER_FAILURE).unwrap(),
            Some(at(1, 9, 20))
        );
        assert_eq!(s.last_sent("other", checks::DECODER_FAILURE).unwrap(), None);
        assert_eq!(
            count(&s, "SELECT COUNT(*) FROM notifications WHERE outcome = 'merged'"),
            1
        );
        assert!(s.mark(&[ids[2]], "bogus", at(1, 9, 55)).is_err(), "CHECK guards outcome");
    }

    /// M1: a batch built before another stage marked its rows must not send them again.
    #[test]
    fn still_pending_drops_rows_already_retired() {
        let (_d, s) = store();
        for (n, m) in [("s1", 0), ("s2", 1), ("s3", 2)] {
            let c = cap(n, at(1, 8, m), None);
            judged(&s, &c, &judgement(vec![notify(checks::NEW_TOWER)], None), at(1, 9, m));
        }
        let (p, _) = s.pending_notifications("m2100", at(1, 9, 10), 10).unwrap();
        let ids: Vec<i64> = p.iter().map(|x| x.id).collect();
        s.mark_sent(&[ids[1]], at(1, 9, 11)).unwrap();
        assert_eq!(s.still_pending(&ids).unwrap(), vec![ids[0], ids[2]]);
        assert_eq!(s.still_pending(&[]).unwrap(), Vec::<i64>::new());
        assert_eq!(s.still_pending(&[9999]).unwrap(), Vec::<i64>::new());
    }

    /// M1: the mesh re-check before a send keeps only rows not yet meshed.
    #[test]
    fn mesh_still_pending_drops_rows_meshed_meanwhile() {
        let (_d, s) = store();
        let now = at(1, 12, 0);
        let a = outbox(&s, "a", checks::ANALYSER_HIGH, "fixed", 0, at(1, 11, 0));
        let b = outbox(&s, "b", checks::ANALYSER_HIGH, "fixed", 0, at(1, 11, 1));
        s.mark_sent(&[b], now).unwrap(); // HA delivery does not count as meshed
        assert_eq!(s.mesh_still_pending(&[a, b]).unwrap(), vec![a, b]);
        s.mark_mesh(&[a], now).unwrap();
        assert_eq!(s.mesh_still_pending(&[a, b]).unwrap(), vec![b]);
        assert!(s.mesh_still_pending(&[9999]).unwrap().is_empty());
    }

    #[test]
    fn report_counts_the_last_24h_and_excludes_backfill() {
        let (_d, s) = store();
        let now = at(5, 12, 0);
        let mk = |n: &str, checks: Vec<(&'static str, Level)>, when, suppressed| {
            let c = cap(n, at(1, 8, 0), None);
            let mut j = judgement(
                checks
                    .into_iter()
                    .map(|(c, l)| Finding {
                        check: c,
                        level: l,
                        detail: "x".into(),
                    })
                    .collect(),
                None,
            );
            j.suppressed = suppressed;
            judged(&s, &c, &j, when);
        };
        mk(
            "a",
            vec![
                (checks::ANALYSER_HIGH, Level::Notify),
                (checks::FAILURE_SPIKE, Level::Count),
            ],
            now - Duration::hours(2),
            false,
        );
        mk(
            "b",
            vec![(checks::ANALYSER_HIGH, Level::Notify)],
            now - Duration::hours(25),
            false,
        ); // too old
        mk(
            "c",
            vec![(checks::ANALYSER_HIGH, Level::Notify)],
            now - Duration::hours(1),
            true,
        ); // backfill
        mk(
            "d",
            vec![
                (checks::IDENTITY_OFF_RHYTHM, Level::Count),
                (checks::DECODER_FAILURE, Level::Notify),
            ],
            now,
            false,
        );
        let r = s.report("m2100", now, checks::LEARN_DAYS).unwrap();
        assert_eq!(
            (
                r.analyser_high,
                r.failure_spikes,
                r.off_rhythm,
                r.decoder_failures
            ),
            (1, 1, 1, 1)
        );
        assert_eq!((r.analyser_other, r.archive_corrupt), (0, 0));
    }

    #[test]
    fn towers_seen_and_new_towers_over_24h() {
        let (_d, s) = store();
        let now = at(5, 12, 0);
        let mut l = learn();
        l.towers = vec![("t1".into(), Strength::Sib1), ("t2".into(), Strength::Pci)];
        judged(
            &s,
            &cap("s1", at(1, 8, 0), None),
            &judgement(vec![], Some(l.clone())),
            now - Duration::hours(30),
        );
        l.towers = vec![("t2".into(), Strength::Pci), ("t3".into(), Strength::Sib1)];
        judged(
            &s,
            &cap("s2", at(2, 8, 0), None),
            &judgement(vec![], Some(l)),
            now - Duration::hours(3),
        );
        let r = s.report("m2100", now, checks::LEARN_DAYS).unwrap();
        assert_eq!(r.towers_seen, 2, "t2 + t3 seen in the window");
        assert_eq!(r.new_towers, 1, "only t3 is new in the window");
        // Sightings older than 48 h are pruned on the next judgement.
        judged(
            &s,
            &cap("s3", at(3, 8, 0), None),
            &judgement(vec![], Some(learn())),
            now + Duration::hours(20),
        );
        assert_eq!(
            count(
                &s,
                "SELECT COUNT(*) FROM tower_sightings \
                 WHERE hour < '2026-10-04T08:00:00.000000000Z'"
            ),
            0
        );
    }

    #[test]
    fn learning_flag_uses_the_configured_days() {
        let (_d, s) = store();
        judged(
            &s,
            &cap("f7", at(1, 8, 0), None),
            &judgement(vec![], Some(learn())),
            at(1, 9, 0),
        );
        assert!(s.report("m2100", at(8, 8, 59), 7).unwrap().learning);
        assert!(!s.report("m2100", at(8, 9, 0), 7).unwrap().learning, "7 days: done");
        assert!(s.report("m2100", at(8, 9, 0), 14).unwrap().learning);
    }

    #[test]
    fn learning_flag_follows_fixed_since() {
        let (_d, s) = store();
        assert!(
            s.report("m2100", at(1, 0, 0), checks::LEARN_DAYS).unwrap().learning,
            "never Fixed: learning"
        );
        judged(
            &s,
            &cap("f1", at(1, 8, 0), None),
            &judgement(vec![], Some(learn())),
            at(1, 9, 0),
        ); // sets fixed_since
        assert!(s.report("m2100", at(15, 8, 59), checks::LEARN_DAYS).unwrap().learning);
        assert!(
            !s.report("m2100", at(15, 9, 0), checks::LEARN_DAYS).unwrap().learning,
            "14 days: done"
        );
    }

    #[test]
    fn remove_also_clears_the_outbox() {
        let (_d, s) = store();
        let c = cap("x1", at(1, 8, 0), None);
        judged(
            &s,
            &c,
            &judgement(vec![notify(checks::NEW_TOWER)], None),
            at(1, 9, 0),
        );
        s.remove(c.key()).unwrap();
        assert_eq!(count(&s, "SELECT COUNT(*) FROM notifications"), 0);
    }

    #[test]
    fn backfill_adds_no_sightings() {
        let (_d, s) = store();
        let mut j = judgement(vec![], Some(learn()));
        j.suppressed = true;
        judged(&s, &cap("bs", at(1, 8, 0), None), &j, at(5, 11, 0));
        assert_eq!(count(&s, "SELECT COUNT(*) FROM tower_sightings"), 0);
        assert_eq!(count(&s, "SELECT COUNT(*) FROM towers"), 1, "still learned");
        assert_eq!(s.report("m2100", at(5, 12, 0), checks::LEARN_DAYS).unwrap().towers_seen, 0);
    }
    #[test]
    fn mesh_log_counts_last_24h_and_newest() {
        let (_d, s) = store();
        let now = at(10, 12, 0);
        s.log_mesh(&["alert"], now - Duration::hours(30)).unwrap();
        s.log_mesh(&["quiet"], now - Duration::hours(2)).unwrap();
        s.log_mesh(&["test"], now - Duration::hours(1)).unwrap();
        assert_eq!(s.mesh_stats(now).unwrap(), (2, Some(now - Duration::hours(1))));
        let (_d2, empty) = store();
        assert_eq!(empty.mesh_stats(now).unwrap(), (0, None));
    }

    #[test]
    fn mesh_log_pruned_after_7_days() {
        let (_d, s) = store();
        let now = at(20, 12, 0);
        s.log_mesh(&["alert"], now - Duration::days(8)).unwrap();
        s.log_mesh(&["quiet"], now - Duration::days(6)).unwrap();
        assert_eq!(s.prune_mesh_log(now).unwrap(), 1);
        assert_eq!(s.mesh_log_rows(), 1);
        assert!(s.log_mesh(&["bogus"], now).is_err(), "kind is constrained");
    }

}
