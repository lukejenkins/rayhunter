//! The token for `POST /api/m2100/fixed`, the daemon's only write endpoint for
//! the Home Assistant add-on. It can only move the unit to its locked-down
//! Fixed profile. The token is made on the owner's laptop (`rayhunter-m2100
//! pair`) and never leaves the device except in the owner's own paste.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const TOKEN_PATH: &str = "/data/rayhunter/.api_token";

/// One accepted request per this long.
const WINDOW: Duration = Duration::from_secs(10);

/// True only for `Some("Bearer <t>")` where `t` equals a stored token that is,
/// once trimmed, exactly 64 hex characters.
pub fn bearer_ok(header: Option<&str>, stored: Option<&str>) -> bool {
    let Some(stored) = stored.map(str::trim) else {
        return false;
    };
    if stored.len() != 64
        || !stored
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return false;
    }
    let Some(given) = header.and_then(|h| h.strip_prefix("Bearer ")) else {
        return false;
    };
    constant_time_eq(given.as_bytes(), stored.as_bytes())
}

/// Equal-length inputs are compared without stopping at the first difference.
/// Unequal lengths are refused up front: the length of the token isn't secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct RateLimit {
    last: Mutex<Option<Instant>>,
}

impl RateLimit {
    pub const fn new() -> Self {
        Self {
            last: Mutex::new(None),
        }
    }

    /// Allows the request if none was accepted in the last 10 s. Only an
    /// allowed request starts the window; a refused one does not extend it.
    pub fn allow(&self, now: Instant) -> bool {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = *last
            && now.saturating_duration_since(t) < WINDOW
        {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// Clears the flag when dropped, so a request future that is dropped
/// mid-switch doesn't leave the panel locked out.
struct Clear<'a>(&'a AtomicBool);

impl Drop for Clear<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Runs `switch` only if nobody else is switching (the panel uses the same
/// flag); otherwise false without running it. The flag is cleared afterwards,
/// including when this future is dropped part-way.
pub async fn guarded<F: std::future::Future<Output = bool>>(flag: &AtomicBool, switch: F) -> bool {
    if flag.swap(true, Ordering::Relaxed) {
        return false;
    }
    let _clear = Clear(flag);
    switch.await
}

/// `guarded`, run on its own task: the switch goes to the end even if the caller
/// (an HTTP request whose client hung up) is dropped part-way, so Fixed is never
/// left half-applied. A panicked switch reports false.
pub async fn guarded_detached<F>(flag: &'static AtomicBool, switch: F) -> bool
where
    F: std::future::Future<Output = bool> + Send + 'static,
{
    tokio::spawn(guarded(flag, switch)).await.unwrap_or(false)
}

/// Shared by the one route that uses it.
pub static RATE_LIMIT: RateLimit = RateLimit::new();

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn ok(h: &str, s: &str) -> bool {
        bearer_ok(Some(h), Some(s))
    }

    #[test]
    fn the_right_token_passes() {
        assert!(ok(&format!("Bearer {T}"), T));
        assert!(ok(&format!("Bearer {T}"), &format!("{T}\n")));
    }

    #[test]
    fn a_wrong_token_of_the_same_length_fails() {
        let wrong = format!("{}0", &T[..63]);
        assert_eq!(wrong.len(), 64);
        assert!(!ok(&format!("Bearer {wrong}"), T));
    }

    #[test]
    fn a_prefix_of_the_right_token_fails() {
        assert!(!ok(&format!("Bearer {}", &T[..32]), T));
        assert!(!ok(&format!("Bearer {}", &T[..63]), T));
        assert!(!ok(&format!("Bearer {T}0"), T));
        assert!(!ok("Bearer ", T));
    }

    #[test]
    fn other_schemes_and_a_missing_header_fail() {
        assert!(!ok(&format!("bearer {T}"), T));
        assert!(!ok(&format!("Token {T}"), T));
        assert!(!ok(T, T));
        assert!(!bearer_ok(None, Some(T)));
    }

    #[test]
    fn a_bad_stored_token_never_matches_even_when_the_header_does() {
        assert!(!bearer_ok(Some("Bearer "), Some("")));
        assert!(!bearer_ok(Some("Bearer "), Some("  \n")));
        assert!(!bearer_ok(Some("Bearer x"), None));
        let short = &T[..63];
        assert!(!ok(&format!("Bearer {short}"), short));
        let nonhex = format!("{}g", &T[..63]);
        assert!(!ok(&format!("Bearer {nonhex}"), &nonhex));
        let upper = T.to_uppercase();
        assert!(!ok(&format!("Bearer {upper}"), &upper));
    }

    #[test]
    fn rate_limit_first_allowed_second_refused_later_allowed() {
        let r = RateLimit::new();
        let t0 = Instant::now();
        assert!(r.allow(t0));
        assert!(!r.allow(t0 + Duration::from_secs(5)));
        assert!(r.allow(t0 + Duration::from_secs(10)));
    }

    #[test]
    fn a_refused_request_does_not_extend_the_window() {
        let r = RateLimit::new();
        let t0 = Instant::now();
        assert!(r.allow(t0));
        assert!(!r.allow(t0 + Duration::from_secs(9)));
        assert!(r.allow(t0 + Duration::from_secs(10)));
    }

    #[tokio::test]
    async fn a_switch_already_in_progress_is_refused_without_running() {
        let flag = AtomicBool::new(true);
        let ran = AtomicBool::new(false);
        let r = guarded(&flag, async {
            ran.store(true, Ordering::Relaxed);
            true
        })
        .await;
        assert!(!r);
        assert!(!ran.load(Ordering::Relaxed));
        // someone else's switch is still theirs to clear
        assert!(flag.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn the_flag_is_set_during_the_switch_and_cleared_after() {
        let flag = AtomicBool::new(false);
        let seen = guarded(&flag, async { flag.load(Ordering::Relaxed) }).await;
        assert!(seen);
        assert!(!flag.load(Ordering::Relaxed));
        assert!(!guarded(&flag, async { false }).await);
        assert!(!flag.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_dropped_request_clears_the_flag() {
        use std::future::Future;
        let flag = AtomicBool::new(false);
        {
            let mut f = std::pin::pin!(guarded(&flag, std::future::pending::<bool>()));
            let w = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&w);
            assert!(f.as_mut().poll(&mut cx).is_pending());
            assert!(flag.load(Ordering::Relaxed));
        }
        assert!(!flag.load(Ordering::Relaxed));
    }

    /// I6: the request future being dropped (client gone) must not cancel the
    /// switch part-way: it runs to the end on its own task.
    #[tokio::test]
    async fn a_dropped_request_does_not_cancel_the_detached_switch() {
        static FLAG: AtomicBool = AtomicBool::new(false);
        static DONE: AtomicBool = AtomicBool::new(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let req = tokio::spawn(guarded_detached(&FLAG, async move {
            let _ = started_tx.send(());
            let _ = go_rx.await;
            DONE.store(true, Ordering::Relaxed);
            true
        }));
        started_rx.await.unwrap();
        req.abort(); // the client hangs up mid-switch
        let _ = req.await;
        assert!(FLAG.load(Ordering::Relaxed), "the switch is still running");
        go_tx.send(()).unwrap();
        for _ in 0..200 {
            if DONE.load(Ordering::Relaxed) && !FLAG.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(DONE.load(Ordering::Relaxed), "the switch was cancelled");
        assert!(!FLAG.load(Ordering::Relaxed), "the flag was not cleared");
    }

    #[tokio::test]
    async fn the_detached_switch_returns_its_result_and_respects_the_guard() {
        static FLAG: AtomicBool = AtomicBool::new(false);
        assert!(guarded_detached(&FLAG, async { true }).await);
        assert!(!guarded_detached(&FLAG, async { false }).await);
        FLAG.store(true, Ordering::Relaxed);
        assert!(!guarded_detached(&FLAG, async { true }).await);
        assert!(FLAG.load(Ordering::Relaxed));
    }

    #[test]
    fn only_the_post_route_mentions_the_fixed_endpoint() {
        let main = include_str!("../main.rs");
        let lines: Vec<&str> = main.lines().filter(|l| l.contains("m2100/fixed")).collect();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("post("), "{}", lines[0]);
        assert!(!lines[0].contains("get(") && !lines[0].contains("put("));
        let server = include_str!("../server.rs");
        assert!(!server.contains("m2100/fixed\", get"));
        // the handler goes through the shared switch guard
        let handler = &server[server.find("fn post_m2100_fixed").unwrap()..];
        assert!(handler.contains("guarded_detached(") && handler.contains("&SWITCHING"));
    }
}
