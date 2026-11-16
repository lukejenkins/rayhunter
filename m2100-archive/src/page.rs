//! The owner page's channel into the cycle thread. The web server (a different thread)
//! sends a `PageCmd`; the cycle thread owns the runner, the store and the radio, so it
//! answers. Commands are handled strictly one at a time: the duplicate guard reads the
//! radio log, so one command's send must be logged before the next is prepared.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};

use crate::app::{FollowUp, Refusal, Runner, SummaryStep};
use crate::claude::{self, ApiError, Reply};

/// How long a send waits for the radio, and how often it looks.
pub const RADIO_WAIT: Duration = Duration::from_secs(30);
pub const RADIO_STEP: Duration = Duration::from_millis(250);

pub enum PageCmd {
    State(oneshot::Sender<serde_json::Value>),
    FollowUp(FollowUp, oneshot::Sender<Result<String, Refusal>>),
    /// The optional alert summary for this alert id: the text, or a message for the page.
    Summary(i64, oneshot::Sender<Result<String, String>>),
}

pub fn channel() -> (mpsc::Sender<PageCmd>, mpsc::Receiver<PageCmd>) {
    mpsc::channel(8)
}

/// True once this call has swapped the flag false -> true (the caller then owns the radio
/// and must clear the flag); false if it stayed held for `wait`.
pub async fn wait_for_radio(flag: &AtomicBool, wait: Duration, step: Duration) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        if !flag.swap(true, Ordering::Relaxed) {
            return true;
        }
        if start.elapsed() >= wait {
            return false;
        }
        tokio::time::sleep(step).await;
    }
}

/// Answer commands until every sender is gone. `send` puts one text on air.
pub async fn serve<F, Fut>(
    mut rx: mpsc::Receiver<PageCmd>,
    runner: &Runner,
    meshing: &Arc<AtomicBool>,
    wait: (Duration, Duration),
    now: impl Fn() -> DateTime<Utc>,
    send: F,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<usize>>,
{
    // A summary's HTTP call runs on the main runtime and reports back here, so this loop
    // (and with it every follow-up and state request) never waits on the API.
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<SummaryDone>();
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    PageCmd::State(reply) => {
                        let _ = reply.send(runner.page(now()));
                    }
                    PageCmd::FollowUp(req, reply) => {
                        let _ = reply.send(follow_up(runner, meshing, wait, &now, &send, &req).await);
                    }
                    PageCmd::Summary(alert_id, reply) => match runner.summary_prepare(alert_id, now()) {
                        Err(msg) => {
                            let _ = reply.send(Err(msg));
                        }
                        Ok(SummaryStep::Cached(text)) => {
                            let _ = reply.send(Ok(text));
                        }
                        Ok(SummaryStep::Call { body, key, model, events }) => {
                            log::info!("summary: asking {model}");
                            let tx = done_tx.clone();
                            let (client, base, handle) = match runner.summary_transport() {
                                Ok(t) => t,
                                Err(e) => {
                                    let _ = tx.send(SummaryDone { alert_id, events, result: Err(e), reply });
                                    continue;
                                }
                            };
                            let call = handle.spawn(async move {
                                claude::call(&client, &base, &key, &body).await
                            });
                            // A panic in the call task still ends in an answer.
                            handle.spawn(async move {
                                let result = call.await.unwrap_or(Err(ApiError::Bad("task".into())));
                                let _ = tx.send(SummaryDone { alert_id, events, result, reply });
                            });
                        }
                    },
                }
            }
            Some(d) = done_rx.recv() => {
                let _ = d.reply.send(runner.summary_done(d.alert_id, d.events, &d.result, now()));
            }
        }
    }
}

struct SummaryDone {
    alert_id: i64,
    events: usize,
    result: Result<Reply, ApiError>,
    reply: oneshot::Sender<Result<String, String>>,
}

async fn follow_up<F, Fut>(
    runner: &Runner,
    meshing: &Arc<AtomicBool>,
    wait: (Duration, Duration),
    now: &impl Fn() -> DateTime<Utc>,
    send: &F,
    req: &FollowUp,
) -> Result<String, Refusal>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<usize>>,
{
    // Refuses with NoRadio when the mesh is off, before the radio is touched.
    runner.follow_up_prepare(req, now())?;
    if !wait_for_radio(meshing, wait.0, wait.1).await {
        return Err(Refusal::RadioBusy);
    }
    // Held until the send is done, even on a panic.
    let _done = crate::Done(meshing.clone());
    // The wait may have been long: the alert can have closed or expired meanwhile. Prepare
    // again with the radio held, and send only what this second check allows.
    let p = runner.follow_up_prepare(req, now())?;
    match send(p.text().to_string()).await {
        Ok(_) => {
            runner.follow_up_sent(&p, now());
            Ok(p.text().to_string())
        }
        Err(e) => {
            log::warn!("owner page: follow-up not sent ({e:#})");
            let msg = format!("{e:#}");
            runner.follow_up_failed(&p, e, now());
            Err(Refusal::SendFailed(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn busy_radio_refuses_after_the_wait() {
        let flag = AtomicBool::new(true);
        let start = Instant::now();
        assert!(!wait_for_radio(&flag, Duration::from_millis(30), Duration::from_millis(5)).await);
        assert!(start.elapsed() >= Duration::from_millis(30));
        assert!(flag.load(Ordering::Relaxed), "still held by its owner");
    }

    #[tokio::test]
    async fn radio_freed_mid_wait_is_taken() {
        let flag = Arc::new(AtomicBool::new(true));
        let f = flag.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            f.store(false, Ordering::Relaxed);
        });
        assert!(wait_for_radio(&flag, Duration::from_millis(500), Duration::from_millis(5)).await);
        assert!(flag.load(Ordering::Relaxed), "taken");
    }
}
