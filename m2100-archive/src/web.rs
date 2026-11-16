//! The owner page, served over Home Assistant Ingress. Only the Supervisor's Ingress peer
//! may connect. The page itself is `web/index.html`; the data comes from the cycle thread
//! through `PageCmd`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};

use crate::app::FollowUp;
use crate::page::PageCmd;
use crate::proxy::Proxy;

/// The Supervisor's Ingress proxy; the only peer let in.
pub const INGRESS_PEER: &str = "172.30.32.2";
/// The port `ingress_port` in config.yaml names.
pub const PORT: u16 = 8099;

/// How long the page waits for the cycle thread. A State request can queue behind a
/// follow-up that waits up to 30 s for the radio.
const STATE_WAIT: Duration = Duration::from_secs(10);
/// A follow-up: the radio wait (30 s) plus the send.
const FOLLOWUP_WAIT: Duration = Duration::from_secs(45);

/// A summary: the API's own 30 s timeout plus the queue behind a follow-up.
const SUMMARY_WAIT: Duration = Duration::from_secs(40);

const INDEX: &str = include_str!("web/index.html");

fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "the add-on is busy"})),
    )
        .into_response()
}

async fn ingress_only(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ingress: IpAddr = IpAddr::V4(INGRESS_PEER.parse::<Ipv4Addr>().expect("constant"));
    if peer.ip().to_canonical() != ingress {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    next.run(req).await
}

async fn index() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        INDEX,
    )
        .into_response()
}

async fn state(State(tx): State<mpsc::Sender<PageCmd>>) -> Response {
    let (reply, rx) = oneshot::channel();
    // A full queue gives a 503 rather than a hang.
    if !matches!(
        tokio::time::timeout(STATE_WAIT, tx.send(PageCmd::State(reply))).await,
        Ok(Ok(()))
    ) {
        return busy();
    }
    match tokio::time::timeout(STATE_WAIT, rx).await {
        Ok(Ok(v)) => ([(header::CACHE_CONTROL, "no-store")], Json(v)).into_response(),
        _ => busy(),
    }
}

async fn followup(State(tx): State<mpsc::Sender<PageCmd>>, Json(req): Json<FollowUp>) -> Response {
    let (reply, rx) = oneshot::channel();
    // The queue is bounded: a full one means the cycle thread is not keeping up.
    let sent = tokio::time::timeout(FOLLOWUP_WAIT, tx.send(PageCmd::FollowUp(req, reply))).await;
    if !matches!(sent, Ok(Ok(()))) {
        return busy();
    }
    match tokio::time::timeout(FOLLOWUP_WAIT, rx).await {
        Ok(Ok(Ok(text))) => Json(json!({"sent": text})).into_response(),
        Ok(Ok(Err(r))) => {
            let code = StatusCode::from_u16(r.status()).unwrap_or(StatusCode::CONFLICT);
            (code, Json(json!({"error": r.message()}))).into_response()
        }
        // No answer in time: the send may still complete, so do not say "busy".
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No answer yet. Check the Sent log before trying again."})),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct SummaryReq {
    alert_id: i64,
}

/// `POST /api/summary`: the optional alert summary, only ever on a tap.
async fn summary(State(tx): State<mpsc::Sender<PageCmd>>, Json(req): Json<SummaryReq>) -> Response {
    let (reply, rx) = oneshot::channel();
    let sent = tokio::time::timeout(SUMMARY_WAIT, tx.send(PageCmd::Summary(req.alert_id, reply))).await;
    if !matches!(sent, Ok(Ok(()))) {
        return busy();
    }
    match tokio::time::timeout(SUMMARY_WAIT, rx).await {
        Ok(Ok(Ok(text))) => Json(json!({"summary": text})).into_response(),
        Ok(Ok(Err(msg))) => (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response(),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No answer from the API yet; try again shortly."})),
        )
            .into_response(),
    }
}

/// `GET /rayhunter/<path>`: the unit's own UI, read-only (see `proxy`). Any other method
/// gets axum's 405 and never reaches the unit.
async fn rayhunter(
    State(p): State<Option<Proxy>>,
    Path(path): Path<String>,
    uri: Uri,
) -> Response {
    let Some(p) = p else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Rayhunter view unavailable").into_response();
    };
    // `Path` has already decoded; the proxy wants the raw form to see `%2e` and friends.
    let raw = uri.path().strip_prefix("/rayhunter/").unwrap_or(&path);
    p.get(raw, uri.query()).await
}

/// `proxy` is `None` when its HTTP client could not be built: the page still works.
pub fn router(tx: mpsc::Sender<PageCmd>, proxy: Option<Proxy>) -> Router {
    let ui = Router::new()
        .route("/", get(index))
        .route("/api/state", get(state))
        .route("/api/followup", post(followup))
        .route("/api/summary", post(summary))
        .with_state(tx);
    let rh = Router::new()
        .route("/rayhunter/{*path}", get(rayhunter))
        .with_state(proxy);
    // The layer goes on the merge, so it covers every route.
    ui.merge(rh).layer(middleware::from_fn(ingress_only))
}

pub async fn serve(router: Router, addr: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Refusal;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const INDEX: &str = include_str!("web/index.html");

    /// A responder standing in for the cycle thread.
    fn app(refusal: Option<Refusal>) -> Router {
        let (tx, mut rx) = crate::page::channel();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    PageCmd::State(r) => {
                        let _ = r.send(serde_json::json!({"status": {"label": "All quiet"}}));
                    }
                    PageCmd::Summary(_, r) => {
                        let _ = r.send(Err("off".into()));
                    }
                    PageCmd::FollowUp(f, r) => {
                        let _ = r.send(match &refusal {
                            Some(x) => Err(x.clone()),
                            None => Ok(f.text),
                        });
                    }
                }
            }
        });
        router(tx, Proxy::new("http://127.0.0.1:1", None).ok())
    }

    fn req(method: &str, uri: &str, peer: &str, body: &str) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let addr: SocketAddr = format!("{peer}:40000").parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        r
    }

    async fn body(r: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let s = r.status();
        let b = r.into_body().collect().await.unwrap().to_bytes();
        (
            s,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }

    const FU: &str = r#"{"alert_id":7,"kind":"watching","text":"Update: ok.","override":false}"#;

    #[tokio::test]
    async fn non_ingress_peer_is_refused() {
        let r = app(None)
            .oneshot(req("GET", "/api/state", "192.0.2.50", ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = app(None)
            .oneshot(req("GET", "/api/state", INGRESS_PEER, ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn every_route_refuses_a_foreign_peer() {
        for (m, u, b) in [("GET", "/", ""), ("POST", "/api/followup", FU)] {
            let r = app(None)
                .oneshot(req(m, u, "192.0.2.50", b))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{m} {u}");
        }
    }

    #[tokio::test]
    async fn v4_mapped_ingress_peer_is_let_in() {
        let mut r = req("GET", "/api/state", INGRESS_PEER, "");
        let addr: SocketAddr = "[::ffff:172.30.32.2]:40000".parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        let r = app(None).oneshot(r).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_follow_up_says_check_the_log() {
        let (tx, _rx) = crate::page::channel();
        let r = router(tx, Proxy::new("http://127.0.0.1:1", None).ok())
            .oneshot(req("POST", "/api/followup", INGRESS_PEER, FU))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            v["error"],
            "No answer yet. Check the Sent log before trying again."
        );
    }

    #[tokio::test(start_paused = true)]
    async fn full_queue_gives_503_not_a_hang() {
        let (tx, _rx) = crate::page::channel();
        for _ in 0..8 {
            tx.send(PageCmd::State(oneshot::channel().0)).await.unwrap();
        }
        let r = router(tx.clone(), Proxy::new("http://127.0.0.1:1", None).ok())
            .oneshot(req("GET", "/api/state", INGRESS_PEER, ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let r = router(tx, Proxy::new("http://127.0.0.1:1", None).ok())
            .oneshot(req("POST", "/api/followup", INGRESS_PEER, FU))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn index_is_served_to_ingress() {
        let r = app(None)
            .oneshot(req("GET", "/", INGRESS_PEER, ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let b = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(b.as_ref(), INDEX.as_bytes());
        assert!(!b.is_empty());
    }

    #[tokio::test]
    async fn no_proxy_still_serves_the_page_and_says_so() {
        let (tx, _rx) = crate::page::channel();
        let r = router(tx.clone(), None)
            .oneshot(req("GET", "/", INGRESS_PEER, ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let r = router(tx, None)
            .oneshot(req("GET", "/rayhunter/api/log", INGRESS_PEER, ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn state_round_trips() {
        let r = app(None)
            .oneshot(req("GET", "/api/state", INGRESS_PEER, ""))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["status"]["label"], "All quiet");
    }

    #[tokio::test]
    async fn follow_up_ok_returns_sent_text() {
        let r = app(None)
            .oneshot(req("POST", "/api/followup", INGRESS_PEER, FU))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["sent"], "Update: ok.");
    }

    #[tokio::test]
    async fn follow_up_refusal_maps_status() {
        let locked = Refusal::Locked { unlocks_at: None };
        let r = app(Some(locked.clone()))
            .oneshot(req("POST", "/api/followup", INGRESS_PEER, FU))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(v["error"], locked.message());
        let r = app(Some(Refusal::RadioBusy))
            .oneshot(req("POST", "/api/followup", INGRESS_PEER, FU))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn bad_follow_up_body_is_a_client_error() {
        let r = app(None)
            .oneshot(req("POST", "/api/followup", INGRESS_PEER, "{}"))
            .await
            .unwrap();
        assert!(r.status().is_client_error());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_cycle_thread_gives_503() {
        // A receiver that never answers.
        let (tx, _rx) = crate::page::channel();
        let r = router(tx, Proxy::new("http://127.0.0.1:1", None).ok())
            .oneshot(req("GET", "/api/state", INGRESS_PEER, ""))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["error"], "the add-on is busy");
    }

    #[test]
    fn page_renders_summary_as_text() {
        assert!(INDEX.contains("api/summary"));
        assert!(INDEX.contains("Advice only. You decide what to send."));
        assert!(INDEX.contains("Tokens used so far"));
        assert!(INDEX.contains("$('summary-text').textContent"));
        for bad in ["innerHTML", "insertAdjacentHTML", "outerHTML", "document.write"] {
            assert!(!INDEX.contains(bad), "{bad}");
        }
        // Shown only when the add-on says it is on.
        assert!(INDEX.contains("s.summary && s.summary.enabled"));
    }

    #[tokio::test]
    async fn summary_round_trips_and_maps_refusals() {
        let (tx, mut rx) = crate::page::channel();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                if let PageCmd::Summary(id, r) = cmd {
                    let _ = r.send(if id == 7 { Ok("Fine.".into()) } else { Err("Summary is off.".into()) });
                }
            }
        });
        let r = router(tx.clone(), None)
            .oneshot(req("POST", "/api/summary", INGRESS_PEER, r#"{"alert_id":7}"#))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!((s, v["summary"].as_str()), (StatusCode::OK, Some("Fine.")));
        let r = router(tx, None)
            .oneshot(req("POST", "/api/summary", INGRESS_PEER, r#"{"alert_id":8}"#))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!((s, v["error"].as_str()), (StatusCode::CONFLICT, Some("Summary is off.")));
    }

    #[tokio::test(start_paused = true)]
    async fn silent_summary_gives_503_after_40s() {
        let (tx, _rx) = crate::page::channel();
        let r = router(tx, None)
            .oneshot(req("POST", "/api/summary", INGRESS_PEER, r#"{"alert_id":7}"#))
            .await
            .unwrap();
        let (s, v) = body(r).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["error"], "No answer from the API yet; try again shortly.");
    }

    #[test]
    fn page_never_uses_inner_html() {
        assert!(!INDEX.contains("innerHTML"));
        assert!(!INDEX.contains("insertAdjacentHTML"));
        assert!(!INDEX.contains("outerHTML"));
        assert!(!INDEX.contains("document.write"));
        assert!(!INDEX.contains("eval("));
    }

    #[test]
    fn page_has_no_external_or_absolute_urls() {
        assert!(!INDEX.is_empty());
        for bad in [
            "http://",
            "https://",
            "src=\"/",
            "href=\"/",
            "fetch('/",
            "fetch(\"/",
            "//cdn",
        ] {
            assert!(!INDEX.contains(bad), "{bad}");
        }
    }

    #[test]
    fn page_gates_send_on_a_chosen_kind() {
        assert!(INDEX.contains("kind: null"));
        assert!(INDEX.contains("c.kind !== null"));
        assert!(INDEX.contains("alert_id: sentCompose.id"));
    }

    /// Final review UX1-UX3, pinned in the source (the DOM is checked in a browser).
    #[test]
    fn page_ux_selected_preset_locked_send_and_log_names() {
        // UX1: no preset is permanently red; red only on the selected Phones off.
        assert!(!INDEX.contains("class=\"danger\""));
        assert!(INDEX.contains("#presets button.sel[data-kind=\"phones_off\"]"));
        // UX2: a locked, unticked All clear cannot be sent.
        assert!(INDEX.contains("if (c.kind === 'all_clear' && !unlocked && !anyway) return false;"));
        // UX3: every radio-log kind has a name; other days carry the weekday.
        for k in ["stage1: 'Alert'", "test: 'TEST'", "all_clear_override: 'All clear (override)'"] {
            assert!(INDEX.contains(k), "{k}");
        }
        assert!(INDEX.contains("LOG_NAMES[r.kind]"));
        assert!(INDEX.contains("DAYS[d.getDay()]"));
    }

    #[test]
    fn page_counts_bytes_and_keeps_the_reminder() {
        assert!(INDEX.contains("new TextEncoder().encode("));
        assert!(INDEX.contains("rayhunter/index.html"));
        // The ping line sits above the Sent list and renders from the page state.
        let (q, sent) = (INDEX.find("id=\"quiet\"").unwrap(), INDEX.find("id=\"sent\"").unwrap());
        assert!(q < sent);
        assert!(INDEX.contains("renderQuiet(s.quiet);"));
        assert!(INDEX.contains("prefers-color-scheme"));
    }

    #[test]
    fn config_yaml_has_ingress() {
        let y: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../addon/config.yaml")).unwrap();
        assert_eq!(y["ingress"], serde_yaml::Value::Bool(true));
        assert_eq!(y["ingress_port"], serde_yaml::Value::from(8099));
    }
}
