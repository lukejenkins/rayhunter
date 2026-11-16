//! Live alert state: one alert at a time collects findings into a timeline, so a
//! second finding joins the open alert instead of raising a second one.

use super::{Store, parse_ts, ts};
use crate::checks;
use crate::live;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{OptionalExtension, params};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Source {
    Live,
    Closed,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Live => "live",
            Source::Closed => "closed",
        }
    }
    fn parse(s: &str) -> Source {
        if s == "closed" {
            Source::Closed
        } else {
            Source::Live
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ingested {
    Opened(i64),
    Joined(i64),
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CloseBy {
    FalseAlarm,
    AllClear,
    Expired,
    Test,
}

impl CloseBy {
    fn as_str(self) -> &'static str {
        match self {
            CloseBy::FalseAlarm => "false_alarm",
            CloseBy::AllClear => "all_clear",
            CloseBy::Expired => "expired",
            CloseBy::Test => "test",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub id: i64,
    pub opened_at: DateTime<Utc>,
    /// Last sign of the alert's towers or checks (`touch`); plan 3's "no sign since".
    pub last_seen_at: DateTime<Utc>,
    /// Last finding that opened or joined it; expiry keys on this.
    pub last_finding_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub closed_by: Option<String>,
    pub stage1_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertEvent {
    pub at: DateTime<Utc>,
    pub check_id: String,
    pub detail: String,
    pub towers: Vec<String>,
    pub source: Source,
    pub recording: Option<String>,
    pub subject: String,
    /// Noted on the timeline only: a duplicate-rule escalation, not a new finding.
    pub timeline_only: bool,
}

/// The quiet-ping line's facts, see `Store::quiet_status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuietStatus {
    /// Newest ping record of any outcome: (at, outcome, reason).
    pub last: Option<(DateTime<Utc>, String, Option<String>)>,
    pub last_sent: Option<DateTime<Utc>>,
    pub sent_since: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RadioEntry {
    pub at: DateTime<Utc>,
    pub kind: String,
    pub text: String,
    pub alert_id: Option<i64>,
}

const DUP_WINDOW_HOURS: i64 = 24;
/// Strong checks that name towers: within one recording, any of them on a tower is the
/// same evidence as any other on it.
const STRONG_TOWER_CHECKS: [&str; 3] = [
    checks::NEW_TOWER_IDENTITY,
    checks::NEW_TOWER_RECUR,
    checks::TOWER_FLOOD,
];
/// How long an alert's stage 1 is retried (from `opened_at`) before it is given up.
const STAGE1_WINDOW_HOURS: i64 = 24;

fn opt_ts(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    s.map(|s| parse_ts(&s)).transpose()
}

fn row_to_alert(r: &rusqlite::Row) -> Result<Alert> {
    Ok(Alert {
        id: r.get(0)?,
        opened_at: parse_ts(&r.get::<_, String>(1)?)?,
        last_seen_at: parse_ts(&r.get::<_, String>(2)?)?,
        closed_at: opt_ts(r.get(3)?)?,
        closed_by: r.get(4)?,
        stage1_at: opt_ts(r.get(5)?)?,
        last_finding_at: parse_ts(&r.get::<_, String>(6)?)?,
    })
}

const ALERT_COLS: &str =
    "id, opened_at, last_seen_at, closed_at, closed_by, stage1_at, last_finding_at";

/// One line of the owner page's admin strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminItem {
    pub at: DateTime<Utc>,
    pub kind: String,
}

impl Store {
    pub fn log_admin(&self, device: &str, kind: &str, now: DateTime<Utc>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO admin_log (device, at, kind) VALUES (?1, ?2, ?3)",
            params![device, ts(&now), kind],
        )?;
        Ok(())
    }

    /// Admin pushes plus admin-class findings since `since`, newest first.
    pub fn admin_items(&self, device: &str, since: DateTime<Utc>) -> Result<Vec<AdminItem>> {
        let mut st = self.conn.prepare(
            "SELECT at, kind FROM admin_log WHERE device = ?1 AND at >= ?2
             UNION ALL
             SELECT found_at, check_id FROM notifications
              WHERE device = ?1 AND found_at >= ?2 AND check_id IN (?3, ?4, ?5, ?6)
             ORDER BY 1 DESC",
        )?;
        let rows = st
            .query_map(
                params![
                    device,
                    ts(&since),
                    checks::IDENTITY_OFF_RHYTHM,
                    checks::FAILURE_SPIKE,
                    checks::DECODER_FAILURE,
                    checks::ARCHIVE_CORRUPT
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(at, kind)| {
                Ok(AdminItem {
                    at: parse_ts(&at)?,
                    kind,
                })
            })
            .collect()
    }

    /// The newest alert, open or closed.
    pub fn last_alert(&self, device: &str) -> Result<Option<Alert>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {ALERT_COLS} FROM alerts WHERE device = ?1 ORDER BY id DESC LIMIT 1"
        ))?;
        let mut rows = st.query(params![device])?;
        match rows.next()? {
            Some(r) => Ok(Some(row_to_alert(r)?)),
            None => Ok(None),
        }
    }

    pub fn ingest(
        &self,
        device: &str,
        f: &live::LiveFinding,
        source: Source,
        recording: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Ingested> {
        let tx = self.conn.unchecked_transaction()?;
        let cutoff = ts(&(now - Duration::hours(DUP_WINDOW_HOURS)));
        // (at, towers, detail, source, recording, subject) of this device's events for this check.
        let mut st = tx.prepare(
            "SELECT e.at, e.towers, e.detail, e.recording, e.subject FROM alert_events e
             JOIN alerts a ON a.id = e.alert_id WHERE a.device = ?1 AND e.check_id = ?2 AND e.timeline_only = 0",
        )?;
        let rows = st
            .query_map(params![device, f.check], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(st);
        let duplicate = rows.iter().any(|(at, towers, detail, rec, subject)| {
            let recent = at.as_str() >= cutoff.as_str();
            if !f.towers.is_empty() {
                return recent && towers.split(' ').any(|t| f.towers.iter().any(|k| k == t));
            }
            match source {
                Source::Live => recent && *detail == f.detail,
                Source::Closed => {
                    recording.is_some() && rec.as_deref() == recording && *subject == f.subject
                }
            }
        });
        if duplicate {
            return Ok(Ingested::Duplicate);
        }
        // Same recording, any age, any alert state: a strong tower check already sharing a
        // tower is the same evidence (the closed pass re-judging what live saw, maybe days
        // later, maybe under another tower check).
        if let (false, Some(rec)) = (f.towers.is_empty(), recording) {
            let mut st = tx.prepare(
                "SELECT e.towers, e.alert_id FROM alert_events e JOIN alerts a ON a.id = e.alert_id
                 WHERE a.device = ?1 AND e.recording = ?2 AND e.check_id IN (?3, ?4, ?5)
                 AND e.timeline_only = 0",
            )?;
            let [c1, c2, c3] = STRONG_TOWER_CHECKS;
            let rows = st
                .query_map(params![device, rec, c1, c2, c3], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(st);
            let matching: Vec<i64> = rows
                .iter()
                .filter(|(ts, _)| ts.split(' ').any(|t| f.towers.iter().any(|k| k == t)))
                .map(|(_, id)| *id)
                .collect();
            if !matching.is_empty() {
                // A different check escalating the same evidence on the open alert still
                // shows on its timeline. It is not a new finding: no `last_finding_at`,
                // no `last_seen_at`, and never the alert's first event (stage 1 reads that).
                let open: Option<i64> = tx
                    .query_row(
                        "SELECT id FROM alerts WHERE device = ?1 AND closed_at IS NULL ORDER BY id DESC LIMIT 1",
                        params![device],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(id) = open.filter(|id| matching.contains(id)) {
                    let seen: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM alert_events WHERE alert_id = ?1 AND check_id = ?2",
                        params![id, f.check],
                        |r| r.get(0),
                    )?;
                    if seen == 0 {
                        tx.execute(
                            "INSERT INTO alert_events (alert_id, at, check_id, detail, towers, source, recording, subject, timeline_only)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
                            params![
                                id,
                                ts(&now),
                                f.check,
                                f.detail,
                                f.towers.join(" "),
                                source.as_str(),
                                recording,
                                f.subject
                            ],
                        )?;
                        tx.commit()?;
                    }
                }
                return Ok(Ingested::Duplicate);
            }
        }
        let open: Option<i64> = tx
            .query_row(
                "SELECT id FROM alerts WHERE device = ?1 AND closed_at IS NULL ORDER BY id DESC LIMIT 1",
                params![device],
                |r| r.get(0),
            )
            .optional()?;
        let (id, joined) = match open {
            Some(id) => {
                tx.execute(
                    "UPDATE alerts SET last_finding_at = ?1 WHERE id = ?2",
                    params![ts(&now), id],
                )?;
                if source == Source::Live {
                    tx.execute(
                        "UPDATE alerts SET last_seen_at = ?1 WHERE id = ?2",
                        params![ts(&now), id],
                    )?;
                }
                (id, true)
            }
            None => {
                tx.execute(
                    "INSERT INTO alerts (device, opened_at, last_seen_at, last_finding_at)
                     VALUES (?1, ?2, ?2, ?2)",
                    params![device, ts(&now)],
                )?;
                (tx.last_insert_rowid(), false)
            }
        };
        tx.execute(
            "INSERT INTO alert_events (alert_id, at, check_id, detail, towers, source, recording, subject)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                ts(&now),
                f.check,
                f.detail,
                f.towers.join(" "),
                source.as_str(),
                recording,
                f.subject
            ],
        )?;
        tx.commit()?;
        Ok(if joined {
            Ingested::Joined(id)
        } else {
            Ingested::Opened(id)
        })
    }

    /// Fresh activity on the open alert's towers or checks: recorded as `last_seen_at`
    /// (plan 3's "no sign since"). It does not keep the alert open (`expire_alerts`).
    pub fn touch(&self, device: &str, act: &live::Activity, now: DateTime<Utc>) -> Result<()> {
        let Some(alert) = self.open_alert(device)? else {
            return Ok(());
        };
        // Timeline-only events match too, on purpose: it keeps the all-clear gate locked longer.
        let hit = self.alert_events(alert.id)?.iter().any(|e| {
            e.towers.iter().any(|t| act.towers.contains(t))
                || act.warning_checks.iter().any(|c| *c == e.check_id)
        });
        if hit {
            self.conn.execute(
                "UPDATE alerts SET last_seen_at = ?1 WHERE id = ?2",
                params![ts(&now), alert.id],
            )?;
        }
        Ok(())
    }

    pub fn open_alert(&self, device: &str) -> Result<Option<Alert>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {ALERT_COLS} FROM alerts WHERE device = ?1 AND closed_at IS NULL ORDER BY id DESC LIMIT 1"
        ))?;
        let mut rows = st.query(params![device])?;
        match rows.next()? {
            Some(r) => Ok(Some(row_to_alert(r)?)),
            None => Ok(None),
        }
    }

    pub fn alert_events(&self, id: i64) -> Result<Vec<AlertEvent>> {
        let mut st = self.conn.prepare(
            "SELECT at, check_id, detail, towers, source, recording, subject, timeline_only FROM alert_events
             WHERE alert_id = ?1 ORDER BY rowid",
        )?;
        let rows = st
            .query_map(params![id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, bool>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(
                |(at, check_id, detail, towers, source, recording, subject, timeline_only)| {
                    Ok(AlertEvent {
                        at: parse_ts(&at)?,
                        check_id,
                        detail,
                        towers: towers
                            .split(' ')
                            .filter(|t| !t.is_empty())
                            .map(str::to_string)
                            .collect(),
                        source: Source::parse(&source),
                        recording,
                        subject,
                        timeline_only,
                    })
                },
            )
            .collect()
    }

    /// Every live event (of any alert) raised during recording `rec`, oldest first.
    pub fn live_events_in(&self, device: &str, rec: &str) -> Result<Vec<AlertEvent>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT e.alert_id FROM alert_events e JOIN alerts a ON a.id = e.alert_id
             WHERE a.device = ?1 AND e.source = 'live' AND e.recording = ?2 AND e.timeline_only = 0
             ORDER BY e.alert_id",
        )?;
        let ids = st
            .query_map(params![device, rec], |r| r.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out = Vec::new();
        for id in ids {
            out.extend(
                self.alert_events(id)?
                    .into_iter()
                    .filter(|e| {
                        !e.timeline_only
                            && e.source == Source::Live
                            && e.recording.as_deref() == Some(rec)
                    }),
            );
        }
        Ok(out)
    }

    pub fn close_alert(&self, id: i64, by: CloseBy, now: DateTime<Utc>) -> Result<()> {
        self.conn.execute(
            "UPDATE alerts SET closed_at = ?1, closed_by = ?2 WHERE id = ?3 AND closed_at IS NULL",
            params![ts(&now), by.as_str(), id],
        )?;
        Ok(())
    }

    /// Open alerts still owed a stage 1 message: (id, first event's check, its detail).
    pub fn stage1_pending(
        &self,
        device: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<(i64, String, String)>> {
        let since = ts(&(now - Duration::hours(STAGE1_WINDOW_HOURS)));
        let mut st = self.conn.prepare(
            "SELECT a.id,
                (SELECT check_id FROM alert_events WHERE alert_id = a.id ORDER BY rowid LIMIT 1),
                (SELECT detail FROM alert_events WHERE alert_id = a.id ORDER BY rowid LIMIT 1)
             FROM alerts a
             WHERE a.device = ?1 AND a.closed_at IS NULL AND a.stage1_at IS NULL
               AND a.stage1_gave_up = 0 AND a.opened_at >= ?2
               AND EXISTS (SELECT 1 FROM alert_events WHERE alert_id = a.id)
             ORDER BY a.id",
        )?;
        let rows = st
            .query_map(params![device, since], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Close every open alert with no new finding for 24 h; returns their ids. Activity
    /// on its towers (`touch`) does not count: a real tower stays visible for ever.
    pub fn expire_alerts(&self, device: &str, now: DateTime<Utc>) -> Result<Vec<i64>> {
        let tx = self.conn.unchecked_transaction()?;
        let cutoff = ts(&(now - Duration::hours(DUP_WINDOW_HOURS)));
        let mut st = tx.prepare(
            "SELECT id FROM alerts WHERE device = ?1 AND closed_at IS NULL AND last_finding_at < ?2",
        )?;
        let ids = st
            .query_map(params![device, cutoff], |r| r.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(st);
        for id in &ids {
            tx.execute(
                "UPDATE alerts SET closed_at = ?1, closed_by = ?2 WHERE id = ?3",
                params![ts(&now), CloseBy::Expired.as_str(), id],
            )?;
        }
        tx.commit()?;
        Ok(ids)
    }

    pub fn stage1_sent(&self, ids: &[i64], now: DateTime<Utc>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for id in ids {
            tx.execute(
                "UPDATE alerts SET stage1_at = ?1 WHERE id = ?2",
                params![ts(&now), id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Stop trying stage 1 for open alerts older than the window; returns their ids.
    pub fn stage1_give_up(&self, now: DateTime<Utc>) -> Result<Vec<i64>> {
        let tx = self.conn.unchecked_transaction()?;
        let since = ts(&(now - Duration::hours(STAGE1_WINDOW_HOURS)));
        let mut st = tx.prepare(
            "SELECT id FROM alerts WHERE closed_at IS NULL AND stage1_at IS NULL
             AND stage1_gave_up = 0 AND opened_at < ?1",
        )?;
        let ids = st
            .query_map(params![since], |r| r.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(st);
        for id in &ids {
            tx.execute(
                "UPDATE alerts SET stage1_gave_up = 1 WHERE id = ?1",
                params![id],
            )?;
        }
        tx.commit()?;
        Ok(ids)
    }

    pub fn log_radio(
        &self,
        device: &str,
        kind: &str,
        text: &str,
        alert_id: Option<i64>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO radio_log (device, at, kind, text, alert_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![device, ts(&now), kind, text, alert_id],
        )?;
        Ok(())
    }

    /// The transmission log: one row per radio text attempted and per due quiet ping that
    /// did not go out. Kind and outcome only, never text.
    pub fn log_radio_events(&self, evs: &[crate::mesh::RadioEvent]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for e in evs {
            tx.execute(
                "INSERT INTO radio_events (at, kind, outcome, reason, alert_id, bell, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![ts(&e.at), e.kind, e.outcome.as_str(), e.reason, e.alert_id, e.bell, e.hash],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The quiet-ping line: the newest ping record of any outcome, the newest sent one, and
    /// how many were sent since `since`.
    pub fn quiet_status(&self, since: DateTime<Utc>) -> Result<QuietStatus> {
        let last: Option<(String, String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT at, outcome, reason FROM radio_events WHERE kind = 'quiet'
                 ORDER BY at DESC, rowid DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (last_sent, sent_since): (Option<String>, u32) = self.conn.query_row(
            "SELECT MAX(at), COUNT(*) FILTER (WHERE at >= ?1) FROM radio_events
             WHERE kind = 'quiet' AND outcome = 'sent'",
            params![ts(&since)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(QuietStatus {
            last: last.map(|(at, o, r)| Ok::<_, anyhow::Error>((parse_ts(&at)?, o, r))).transpose()?,
            last_sent: last_sent.map(|s| parse_ts(&s)).transpose()?,
            sent_since,
        })
    }

    #[cfg(test)]
    pub fn radio_event_rows(&self) -> Vec<(String, String, Option<String>)> {
        let mut st = self.conn.prepare("SELECT kind, outcome, reason FROM radio_events ORDER BY rowid").unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(|r| r.unwrap()).collect()
    }

    /// The newest `limit` rows tied to one alert, newest first.
    pub fn radio_log_for_alert(&self, device: &str, alert_id: i64, limit: usize) -> Result<Vec<RadioEntry>> {
        let mut st = self.conn.prepare(
            "SELECT at, kind, text, alert_id FROM radio_log WHERE device = ?1 AND alert_id = ?2
             ORDER BY at DESC, id DESC LIMIT ?3",
        )?;
        let rows = st
            .query_map(params![device, alert_id, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<(String, String, String, Option<i64>)>>>()?;
        rows.into_iter()
            .map(|(at, kind, text, alert_id)| {
                Ok(RadioEntry { at: parse_ts(&at)?, kind, text, alert_id })
            })
            .collect()
    }

    pub fn radio_log(&self, device: &str, limit: usize) -> Result<Vec<RadioEntry>> {
        let mut st = self.conn.prepare(
            "SELECT at, kind, text, alert_id FROM radio_log WHERE device = ?1
             ORDER BY at DESC, id DESC LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![device, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<(String, String, String, Option<i64>)>>>()?;
        rows.into_iter()
            .map(|(at, kind, text, alert_id)| {
                Ok(RadioEntry {
                    at: parse_ts(&at)?,
                    kind,
                    text,
                    alert_id,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const D: &str = "m2100";

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("index.sqlite")).unwrap();
        (d, s)
    }

    fn t(mins: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap() + Duration::minutes(mins)
    }

    fn ev(kind: &'static str, outcome: crate::mesh::Outcome, reason: Option<&'static str>, at: DateTime<Utc>) -> crate::mesh::RadioEvent {
        crate::mesh::RadioEvent { at, kind, outcome, reason, alert_id: None, bell: kind != "quiet", hash: "0123456789ab".into() }
    }

    #[test]
    fn quiet_status_reads_the_newest_ping_record_and_counts_sent_ones() {
        use crate::mesh::Outcome::*;
        let (_d, s) = store();
        assert_eq!(s.quiet_status(t(0)).unwrap(), QuietStatus { last: None, last_sent: None, sent_since: 0 });
        s.log_radio_events(&[
            ev("quiet", Sent, None, t(10)),
            ev("stage1", Sent, None, t(20)),
            ev("quiet", Sent, None, t(30)),
            ev("quiet", Skipped, Some("alert_open"), t(40)),
            ev("quiet", Failed, Some("no_radio"), t(50)),
        ])
        .unwrap();
        let q = s.quiet_status(t(15)).unwrap();
        // Newest quiet record of any outcome; only sent pings after `since` count.
        assert_eq!(q.last, Some((t(50), "failed".to_string(), Some("no_radio".to_string()))));
        assert_eq!(q.sent_since, 1);
        assert_eq!(s.quiet_status(t(0)).unwrap().sent_since, 2);
        assert_eq!(q.last_sent, Some(t(30)));
    }

    #[test]
    fn radio_events_keep_every_field_and_are_pruned_with_the_mesh_log() {
        use crate::mesh::Outcome::*;
        let (_d, s) = store();
        let mut e = ev("all_clear", Sent, Some("override"), t(0));
        e.alert_id = Some(7);
        s.log_radio_events(&[e, ev("quiet", Sent, None, t(0) + Duration::days(8))]).unwrap();
        let row: (String, String, String, Option<String>, Option<i64>, i64, String) = s
            .conn
            .query_row(
                "SELECT at, kind, outcome, reason, alert_id, bell, hash FROM radio_events ORDER BY at LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .unwrap();
        assert_eq!(row.1, "all_clear");
        assert_eq!((row.2.as_str(), row.3.as_deref(), row.4, row.5, row.6.as_str()), ("sent", Some("override"), Some(7), 1, "0123456789ab"));
        // 7 days, like the mesh log: the old row goes, the new one stays.
        s.prune_mesh_log(t(0) + Duration::days(8)).unwrap();
        let n: i64 = s.conn.query_row("SELECT COUNT(*) FROM radio_events", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    fn tower(key: &str) -> live::LiveFinding {
        live::LiveFinding {
            check: "new_tower",
            detail: format!("new tower {key}"),
            towers: vec![key.to_string()],
            subject: String::new(),
        }
    }

    fn analyser(name: &str, n: u32) -> live::LiveFinding {
        let detail = format!("{name}: {n} high warnings; x");
        live::LiveFinding {
            check: "analyser_high",
            subject: live::subject_of("analyser_high", &detail),
            detail,
            towers: vec![],
        }
    }

    fn live_in(s: &Store, f: &live::LiveFinding, now: DateTime<Utc>) -> Ingested {
        s.ingest(D, f, Source::Live, Some("rec1"), now).unwrap()
    }

    #[test]
    fn first_finding_opens() {
        let (_d, s) = store();
        let r = live_in(&s, &tower("sib1:1"), t(0));
        let a = s.open_alert(D).unwrap().unwrap();
        assert_eq!(r, Ingested::Opened(a.id));
        assert_eq!(a.opened_at, t(0));
        let ev = s.alert_events(a.id).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].towers, vec!["sib1:1"]);
        assert_eq!(ev[0].recording.as_deref(), Some("rec1"));
    }

    #[test]
    fn second_finding_while_open_joins_without_new_alert() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &tower("sib1:1"), t(0)) else {
            panic!()
        };
        assert_eq!(live_in(&s, &tower("sib1:2"), t(5)), Ingested::Joined(id));
        assert_eq!(s.alert_events(id).unwrap().len(), 2);
        assert_eq!(s.open_alert(D).unwrap().unwrap().last_seen_at, t(5));
    }

    #[test]
    fn same_tower_same_check_is_duplicate() {
        let (_d, s) = store();
        live_in(&s, &tower("sib1:1"), t(0));
        assert_eq!(live_in(&s, &tower("sib1:1"), t(5)), Ingested::Duplicate);
        let a = s.open_alert(D).unwrap().unwrap();
        assert_eq!(s.alert_events(a.id).unwrap().len(), 1);
        assert_eq!(a.last_seen_at, t(0));
    }

    #[test]
    fn closed_alert_not_reopened_by_old_evidence() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &tower("sib1:1"), t(0)) else {
            panic!()
        };
        s.close_alert(id, CloseBy::FalseAlarm, t(1)).unwrap();
        assert_eq!(live_in(&s, &tower("sib1:1"), t(2)), Ingested::Duplicate);
        assert!(s.open_alert(D).unwrap().is_none());
    }

    #[test]
    fn new_evidence_after_close_opens_new_alert() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &tower("sib1:1"), t(0)) else {
            panic!()
        };
        s.close_alert(id, CloseBy::AllClear, t(1)).unwrap();
        let r = live_in(&s, &tower("sib1:9"), t(2));
        assert!(matches!(r, Ingested::Opened(n) if n != id));
    }

    #[test]
    fn closed_source_duplicate_does_not_touch_last_seen() {
        let (_d, s) = store();
        live_in(&s, &tower("sib1:1"), t(0));
        let r = s
            .ingest(D, &tower("sib1:1"), Source::Closed, Some("rec0"), t(10))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        assert_eq!(s.open_alert(D).unwrap().unwrap().last_seen_at, t(0));
    }

    #[test]
    fn rotation_keeps_open_alert() {
        let (_d, s) = store();
        live_in(&s, &tower("sib1:1"), t(0));
        let r = s
            .ingest(D, &tower("sib1:1"), Source::Live, Some("rec2"), t(10))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        let act = live::Activity {
            towers: vec!["sib1:1".into()],
            ..Default::default()
        };
        s.touch(D, &act, t(10)).unwrap();
        assert_eq!(s.open_alert(D).unwrap().unwrap().last_seen_at, t(10));
        // Unrelated activity does not.
        let other = live::Activity {
            towers: vec!["sib1:7".into()],
            ..Default::default()
        };
        s.touch(D, &other, t(20)).unwrap();
        assert_eq!(s.open_alert(D).unwrap().unwrap().last_seen_at, t(10));
    }

    #[test]
    fn stage1_pending_until_sent_then_gone() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &tower("sib1:1"), t(0)) else {
            panic!()
        };
        live_in(&s, &tower("sib1:2"), t(1));
        let p = s.stage1_pending(D, t(2)).unwrap();
        assert_eq!(
            p,
            vec![(id, "new_tower".to_string(), "new tower sib1:1".to_string())]
        );
        s.stage1_sent(&[id], t(2)).unwrap();
        assert!(s.stage1_pending(D, t(3)).unwrap().is_empty());
        assert_eq!(s.open_alert(D).unwrap().unwrap().stage1_at, Some(t(2)));
    }

    #[test]
    fn stage1_gives_up_after_24_h() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &tower("sib1:1"), t(0)) else {
            panic!()
        };
        let day = 24 * 60;
        assert!(s.stage1_give_up(t(day - 1)).unwrap().is_empty());
        assert_eq!(s.stage1_pending(D, t(day - 1)).unwrap().len(), 1);
        assert!(s.stage1_pending(D, t(day + 1)).unwrap().is_empty());
        assert_eq!(s.stage1_give_up(t(day + 1)).unwrap(), vec![id]);
        assert!(s.stage1_give_up(t(day + 2)).unwrap().is_empty());
    }

    #[test]
    fn quiet_open_alert_expires_after_24h_then_new_evidence_opens() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &tower("sib1:1"), t(0)) else {
            panic!()
        };
        assert!(s.expire_alerts(D, t(60 * 23)).unwrap().is_empty());
        assert_eq!(s.expire_alerts(D, t(60 * 24 + 1)).unwrap(), vec![id]);
        assert!(s.open_alert(D).unwrap().is_none());
        // Same tower, now outside the 24 h window: a fresh alert.
        let r = live_in(&s, &tower("sib1:1"), t(60 * 24 + 2));
        assert!(matches!(r, Ingested::Opened(n) if n != id));
    }

    fn finding(check: &'static str, key: &str) -> live::LiveFinding {
        live::LiveFinding {
            check,
            detail: format!("identity request after: {key}"),
            towers: vec![key.to_string()],
            subject: String::new(),
        }
    }

    /// C1: a real, persistent tower keeps showing rising hits (every rotation resets the
    /// live memory), so `touch` keeps bumping `last_seen_at`; expiry must not key on it.
    #[test]
    fn constant_tower_activity_does_not_keep_an_alert_open() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let Ingested::Opened(id) = live_in(&s, &finding("new_tower_identity", k), t(0)) else {
            panic!()
        };
        s.stage1_sent(&[id], t(1)).unwrap();
        let act = live::Activity {
            towers: vec![k.into()],
            ..Default::default()
        };
        for h in (6..=72).step_by(6) {
            s.touch(D, &act, t(h * 60)).unwrap();
            s.expire_alerts(D, t(h * 60)).unwrap();
        }
        assert_eq!(s.open_alert(D).unwrap().map(|a| a.id), None, "expired");
        let r = s
            .ingest(D, &analyser("imsi_requested", 1), Source::Live, Some("r9"), t(72 * 60))
            .unwrap();
        let Ingested::Opened(new) = r else {
            panic!("{r:?}")
        };
        assert_ne!(new, id);
        let p = s.stage1_pending(D, t(72 * 60)).unwrap();
        assert_eq!(p.iter().map(|x| x.0).collect::<Vec<_>>(), vec![new], "its own stage 1");
    }

    /// I1 (a): decoding paused over a day, then the closed pass judges the recording the
    /// live loop already alerted on: the same evidence, not a second stage 1.
    #[test]
    fn closed_pass_days_later_same_recording_is_duplicate() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let Ingested::Opened(id) = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap()
        else {
            panic!()
        };
        s.stage1_sent(&[id], t(1)).unwrap();
        assert_eq!(s.expire_alerts(D, t(25 * 60)).unwrap(), vec![id]);
        let r = s
            .ingest(D, &finding("new_tower_identity", k), Source::Closed, Some("r1"), t(72 * 60))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        assert!(s.open_alert(D).unwrap().is_none());
        assert!(s.stage1_pending(D, t(72 * 60)).unwrap().is_empty());
    }

    /// I1 (b): live saw identity-after-new-tower on T; the closed pass of the same
    /// recording calls T a recurring new tower. Different check, same evidence.
    #[test]
    fn closed_recur_after_live_identity_same_recording_is_duplicate() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let Ingested::Opened(id) = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap()
        else {
            panic!()
        };
        s.close_alert(id, CloseBy::AllClear, t(60)).unwrap();
        let r = s
            .ingest(D, &finding("new_tower_recur", k), Source::Closed, Some("r1"), t(120))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        // A flood naming T in the same recording is the same evidence too.
        let r = s
            .ingest(D, &finding("tower_flood", k), Source::Live, Some("r1"), t(130))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        assert!(s.open_alert(D).unwrap().is_none());
    }

    /// Control for I1: the same tower in another recording, past the 24 h window, is new.
    #[test]
    fn same_tower_other_recording_after_window_opens() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let Ingested::Opened(id) = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap()
        else {
            panic!()
        };
        s.expire_alerts(D, t(25 * 60)).unwrap();
        let r = s
            .ingest(D, &finding("new_tower_recur", k), Source::Closed, Some("r2"), t(26 * 60))
            .unwrap();
        assert!(matches!(r, Ingested::Opened(n) if n != id), "{r:?}");
        // And another recording inside the window, other tower check: also new evidence.
        let (_d, s) = store();
        s.ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap();
        let r = s
            .ingest(D, &finding("new_tower_recur", k), Source::Closed, Some("r2"), t(60))
            .unwrap();
        assert!(matches!(r, Ingested::Joined(_)), "{r:?}");
    }

    /// An early 0.6.0 database: `last_finding_at` starts at `last_seen_at`.
    #[test]
    fn migration_adds_last_finding_at_from_last_seen_at() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("index.sqlite");
        {
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY, device TEXT NOT NULL, opened_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL, closed_at TEXT, closed_by TEXT, stage1_at TEXT,
                    stage1_gave_up INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .unwrap();
            c.execute(
                "INSERT INTO alerts (device, opened_at, last_seen_at) VALUES (?1, ?2, ?3)",
                params![D, ts(&t(0)), ts(&t(600))],
            )
            .unwrap();
        }
        let s = Store::open(&p).unwrap();
        let a = s.open_alert(D).unwrap().unwrap();
        assert_eq!(a.last_finding_at, t(600));
        assert!(s.expire_alerts(D, t(600 + 23 * 60)).unwrap().is_empty());
        assert_eq!(s.expire_alerts(D, t(600 + 24 * 60 + 1)).unwrap(), vec![a.id]);
        drop(s);
        Store::open(&p).unwrap(); // idempotent
    }

    /// Opened and Joined findings (either source) keep an alert open; `touch` does not.
    #[test]
    fn findings_not_activity_keep_an_alert_open() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &tower("sib1:1"), t(0)) else {
            panic!()
        };
        let act = live::Activity {
            towers: vec!["sib1:1".into()],
            ..Default::default()
        };
        s.touch(D, &act, t(20 * 60)).unwrap();
        let a = s.open_alert(D).unwrap().unwrap();
        assert_eq!((a.last_seen_at, a.last_finding_at), (t(20 * 60), t(0)));
        // A closed-pass finding joining at 20 h keeps it open past 24 h from opening.
        let r = s
            .ingest(D, &analyser("imsi", 1), Source::Closed, Some("rec0"), t(20 * 60))
            .unwrap();
        assert_eq!(r, Ingested::Joined(id));
        assert!(s.expire_alerts(D, t(30 * 60)).unwrap().is_empty());
        assert_eq!(s.expire_alerts(D, t(44 * 60 + 1)).unwrap(), vec![id]);
    }

    fn note(s: &Store, dev: &str, check: &str, at: DateTime<Utc>) {
        s.conn
            .execute(
                "INSERT INTO notifications (device, name, start, check_id, count, profile, spans_switch, found_at)
                 VALUES (?1, ?2, ?3, ?4, 1, 'mobile', 0, ?3)",
                params![dev, format!("n-{check}"), ts(&at), check],
            )
            .unwrap();
    }

    #[test]
    fn admin_items_merge_admin_log_and_admin_notifications() {
        let (_d, s) = store();
        s.log_admin(D, "live_unknown", t(0)).unwrap();
        s.log_admin(D, "test_alert", t(1)).unwrap();
        note(&s, D, checks::DECODER_FAILURE, t(2));
        note(&s, D, checks::NEW_TOWER_IDENTITY, t(3));
        let kinds: Vec<String> = s.admin_items(D, t(0)).unwrap().into_iter().map(|i| i.kind).collect();
        assert_eq!(kinds, ["decoder_failure", "test_alert", "live_unknown"]);
    }

    #[test]
    fn admin_items_respect_since_and_device() {
        let (_d, s) = store();
        s.log_admin(D, "old", t(-5)).unwrap();
        s.log_admin("unit2", "other", t(1)).unwrap();
        note(&s, "unit2", checks::FAILURE_SPIKE, t(1));
        s.log_admin(D, "kept", t(1)).unwrap();
        let items = s.admin_items(D, t(0)).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, "kept");
    }

    #[test]
    fn last_alert_returns_closed_ones_too() {
        let (_d, s) = store();
        assert!(s.last_alert(D).unwrap().is_none());
        live_in(&s, &tower("a"), t(0));
        let id = s.open_alert(D).unwrap().unwrap().id;
        s.close_alert(id, CloseBy::Test, t(1)).unwrap();
        let a = s.last_alert(D).unwrap().unwrap();
        assert_eq!(a.id, id);
        assert_eq!(a.closed_by.as_deref(), Some("test"));
    }

    #[test]
    fn same_recording_escalation_is_noted_on_the_open_alert() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let r = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap();
        let Ingested::Opened(id) = r else { panic!() };
        let r = s
            .ingest(D, &finding("tower_flood", k), Source::Live, Some("r1"), t(10))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        let ev = s.alert_events(id).unwrap();
        assert_eq!(ev.len(), 2);
        assert!(!ev[0].timeline_only);
        assert!(ev[1].timeline_only);
        assert_eq!(ev[1].check_id, "tower_flood");
        assert_eq!(s.open_alert(D).unwrap().unwrap().last_finding_at, t(0));
        s.stage1_sent(&[id], t(11)).unwrap();
        assert!(s.stage1_pending(D, t(12)).unwrap().is_empty());
    }

    #[test]
    fn same_check_duplicate_adds_nothing() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let Ingested::Opened(id) = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap()
        else {
            panic!()
        };
        let r = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(10))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        assert_eq!(s.alert_events(id).unwrap().len(), 1);
        // The escalation is noted once, not once per repeat.
        for m in [20, 30] {
            s.ingest(D, &finding("tower_flood", k), Source::Live, Some("r1"), t(m)).unwrap();
        }
        assert_eq!(s.alert_events(id).unwrap().len(), 2);
    }

    #[test]
    fn duplicate_of_a_closed_alert_adds_nothing() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let Ingested::Opened(id) = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap()
        else {
            panic!()
        };
        s.close_alert(id, CloseBy::FalseAlarm, t(1)).unwrap();
        let r = s
            .ingest(D, &finding("tower_flood", k), Source::Live, Some("r1"), t(10))
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
        assert_eq!(s.alert_events(id).unwrap().len(), 1);
    }

    fn noted_escalation(s: &Store, k: &str) -> i64 {
        let Ingested::Opened(id) = s
            .ingest(D, &finding("new_tower_identity", k), Source::Live, Some("r1"), t(0))
            .unwrap()
        else {
            panic!()
        };
        s.ingest(D, &finding("tower_flood", k), Source::Live, Some("r1"), t(10)).unwrap();
        id
    }

    #[test]
    fn a_noted_escalation_is_not_duplicate_evidence_in_another_recording() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let id = noted_escalation(&s, k);
        let r = s
            .ingest(D, &finding("tower_flood", k), Source::Live, Some("r2"), t(100))
            .unwrap();
        assert_eq!(r, Ingested::Joined(id));
        assert_eq!(s.open_alert(D).unwrap().unwrap().last_finding_at, t(100));
    }

    #[test]
    fn a_noted_escalation_does_not_suppress_a_new_alert_after_close() {
        let (_d, s) = store();
        let k = "sib1:310-260:1:2";
        let id = noted_escalation(&s, k);
        s.close_alert(id, CloseBy::FalseAlarm, t(20)).unwrap();
        let r = s
            .ingest(D, &finding("tower_flood", k), Source::Live, Some("r2"), t(100))
            .unwrap();
        assert!(matches!(r, Ingested::Opened(n) if n != id));
    }

    /// A flood in recording r1 naming towers A and C, noted timeline-only on the alert
    /// that a new_tower_identity on A opened. Returns that alert's id.
    fn flood_noted_over_a_and_c(s: &Store, a: &str, c: &str) -> i64 {
        let Ingested::Opened(id) = s
            .ingest(D, &finding("new_tower_identity", a), Source::Live, Some("r1"), t(0))
            .unwrap()
        else {
            panic!()
        };
        let flood = live::LiveFinding {
            check: "tower_flood",
            detail: "tower flood".into(),
            towers: vec![a.to_string(), c.to_string()],
            subject: String::new(),
        };
        let r = s.ingest(D, &flood, Source::Live, Some("r1"), t(10)).unwrap();
        assert_eq!(r, Ingested::Duplicate);
        assert!(s.alert_events(id).unwrap()[1].timeline_only);
        id
    }

    /// Final review I2: a tower named only by a noted escalation is not evidence: a real
    /// finding on it in the same recording joins the open alert.
    #[test]
    fn a_tower_named_only_by_a_noted_escalation_joins_the_open_alert() {
        let (_d, s) = store();
        let (a, c) = ("sib1:310-260:1:2", "sib1:310-260:1:9");
        let id = flood_noted_over_a_and_c(&s, a, c);
        let r = s
            .ingest(D, &finding("new_tower_identity", c), Source::Live, Some("r1"), t(20))
            .unwrap();
        assert_eq!(r, Ingested::Joined(id));
        assert_eq!(s.open_alert(D).unwrap().unwrap().last_finding_at, t(20));
    }

    #[test]
    fn a_tower_named_only_by_a_noted_escalation_opens_after_close() {
        let (_d, s) = store();
        let (a, c) = ("sib1:310-260:1:2", "sib1:310-260:1:9");
        let id = flood_noted_over_a_and_c(&s, a, c);
        s.close_alert(id, CloseBy::FalseAlarm, t(15)).unwrap();
        let r = s
            .ingest(D, &finding("new_tower_identity", c), Source::Live, Some("r1"), t(20))
            .unwrap();
        assert!(matches!(r, Ingested::Opened(n) if n != id), "{r:?}");
    }

    #[test]
    fn live_events_in_skips_timeline_only_rows() {
        let (_d, s) = store();
        noted_escalation(&s, "sib1:310-260:1:2");
        let ev = s.live_events_in(D, "r1").unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].check_id, "new_tower_identity");
    }

    #[test]
    fn last_alert_is_the_newest_for_the_device() {
        let (_d, s) = store();
        live_in(&s, &tower("a"), t(0));
        let a = s.open_alert(D).unwrap().unwrap().id;
        s.close_alert(a, CloseBy::FalseAlarm, t(1)).unwrap();
        live_in(&s, &tower("b"), t(2));
        let b = s.open_alert(D).unwrap().unwrap().id;
        s.ingest("unit2", &tower("c"), Source::Live, Some("rec2"), t(3)).unwrap();
        assert_ne!(a, b);
        assert_eq!(s.last_alert(D).unwrap().unwrap().id, b);
    }

    #[test]
    fn admin_items_drop_old_notifications_and_include_all_admin_checks() {
        let (_d, s) = store();
        note(&s, D, checks::DECODER_FAILURE, t(-5));
        assert!(s.admin_items(D, t(0)).unwrap().is_empty());
        for (i, c) in [
            checks::IDENTITY_OFF_RHYTHM,
            checks::FAILURE_SPIKE,
            checks::DECODER_FAILURE,
            checks::ARCHIVE_CORRUPT,
        ]
        .into_iter()
        .enumerate()
        {
            note(&s, D, c, t(1 + i as i64));
        }
        let mut kinds: Vec<String> =
            s.admin_items(D, t(0)).unwrap().into_iter().map(|i| i.kind).collect();
        kinds.sort();
        let mut want = vec![
            checks::IDENTITY_OFF_RHYTHM.to_string(),
            checks::FAILURE_SPIKE.to_string(),
            checks::DECODER_FAILURE.to_string(),
            checks::ARCHIVE_CORRUPT.to_string(),
        ];
        want.sort();
        assert_eq!(kinds, want);
    }

    #[test]
    fn radio_log_roundtrip_newest_first() {
        let (_d, s) = store();
        s.log_radio(D, "stage1", "one", Some(3), t(0)).unwrap();
        s.log_radio(D, "quiet", "two", None, t(5)).unwrap();
        s.log_radio("other", "test", "x", None, t(6)).unwrap();
        let l = s.radio_log(D, 10).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(
            (l[0].kind.as_str(), l[0].text.as_str(), l[0].alert_id),
            ("quiet", "two", None)
        );
        assert_eq!(l[1].alert_id, Some(3));
        assert_eq!(s.radio_log(D, 1).unwrap().len(), 1);
    }

    #[test]
    fn closed_analyser_same_recording_same_subject_is_duplicate_even_if_count_differs() {
        let (_d, s) = store();
        let Ingested::Opened(id) = s
            .ingest(D, &analyser("imsi", 3), Source::Closed, Some("recA"), t(0))
            .unwrap()
        else {
            panic!()
        };
        s.close_alert(id, CloseBy::AllClear, t(1)).unwrap();
        // Days later, same recording, different count: still the same evidence.
        let r = s
            .ingest(
                D,
                &analyser("imsi", 7),
                Source::Closed,
                Some("recA"),
                t(60 * 72),
            )
            .unwrap();
        assert_eq!(r, Ingested::Duplicate);
    }

    #[test]
    fn closed_analyser_other_recording_is_not_duplicate() {
        let (_d, s) = store();
        s.ingest(D, &analyser("imsi", 3), Source::Closed, Some("recA"), t(0))
            .unwrap();
        let r = s
            .ingest(D, &analyser("imsi", 3), Source::Closed, Some("recB"), t(5))
            .unwrap();
        assert!(matches!(r, Ingested::Joined(_)));
    }

    #[test]
    fn live_analyser_new_count_after_close_opens_new_alert() {
        let (_d, s) = store();
        let Ingested::Opened(id) = live_in(&s, &analyser("imsi", 3), t(0)) else {
            panic!()
        };
        s.close_alert(id, CloseBy::AllClear, t(1)).unwrap();
        assert_eq!(live_in(&s, &analyser("imsi", 3), t(2)), Ingested::Duplicate);
        let r = live_in(&s, &analyser("imsi", 4), t(3));
        assert!(matches!(r, Ingested::Opened(n) if n != id));
    }

    #[test]
    fn closed_analyser_same_recording_other_subject_is_not_duplicate() {
        let (_d, s) = store();
        s.ingest(D, &analyser("imsi", 3), Source::Closed, Some("recA"), t(0))
            .unwrap();
        let r = s
            .ingest(
                D,
                &analyser("null_cipher", 3),
                Source::Closed,
                Some("recA"),
                t(5),
            )
            .unwrap();
        assert!(matches!(r, Ingested::Joined(_)));
    }
}
