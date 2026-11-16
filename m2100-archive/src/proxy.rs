//! A read-only window onto the unit's own Rayhunter UI, for the owner page. GET only, and
//! only paths on an allowlist: no capture downloads, no writes, no location. The device
//! token is added here, on the upstream request, and never reaches the browser.

use std::io::Read;
use std::time::Duration;

use axum::body::Body;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Between reads, not for the whole body, so a long log stream is not cut off.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Keys the owner page never shows: places, notification endpoints, credentials.
const PRIVATE_KEYS: &[&str] = &[
    "webdav",
    "ntfy_url",
    "gps_fixed_latitude",
    "gps_fixed_longitude",
    "wifi_ssid",
    "wifi_password",
];
/// Cap on the unzipped index (the real one is about 1 MB).
const INDEX_MAX: u64 = 16 * 1024 * 1024;
const NOT_AVAILABLE: &str = "not available through the owner page";

const EXACT: &[&str] = &[
    "index.html",
    "api/analysis",
    "api/analyzers",
    "api/config",
    "api/log",
    "api/qmdl-manifest",
    "api/system-stats",
    "api/time",
    "api/update-status",
    "api/wifi-status",
    "api/m2100/profile",
    "api/m2100/capture-profiles",
    "favicon.png",
    "rayhunter_orca_only.png",
    "rayhunter_text.png",
];

/// A path with nothing that could climb out, hide a separator or end a string early.
fn safe(path: &str) -> bool {
    !(path.is_empty()
        || path.starts_with('/')
        || path.contains("..")
        || path.contains('\\')
        || path.contains('\0'))
}

/// Is this (already decoded, no leading slash) path one the owner page may read?
pub fn allowed(path: &str) -> bool {
    if !safe(path) {
        return false;
    }
    if EXACT.contains(&path) {
        return true;
    }
    match path.strip_prefix("api/analysis-report/") {
        Some(name) => {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        }
        None => false,
    }
}

/// Point the bundle's absolute URLs at the page's own directory so they stay under
/// `…/rayhunter/` instead of hitting Home Assistant.
pub fn rewrite_index(html: &str) -> String {
    let mut s = html.to_string();
    for q in ["'", "\"", "`"] {
        s = s.replace(&format!("{q}/api/"), &format!("{q}./api/"));
    }
    for asset in [
        "favicon.png",
        "rayhunter_orca_only.png",
        "rayhunter_text.png",
    ] {
        for q in ["'", "\"", "`"] {
            s = s.replace(&format!("{q}/{asset}"), &format!("{q}./{asset}"));
        }
    }
    s
}

/// Percent-decode; `None` if the result is not valid UTF-8 or an escape is malformed.
fn decode(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[derive(Clone)]
pub struct Proxy {
    base: String,
    token: Option<String>,
    client: reqwest::Client,
}

fn refuse() -> Response {
    (StatusCode::FORBIDDEN, NOT_AVAILABLE).into_response()
}

impl Proxy {
    pub fn new(device_url: &str, token: Option<String>) -> Result<Self, reqwest::Error> {
        Ok(Proxy {
            base: device_url.trim_end_matches('/').to_string(),
            token: token.filter(|t| !t.is_empty()),
            client: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(READ_TIMEOUT)
                // A redirect could carry the token somewhere else.
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    /// `path` is the raw (still percent-encoded) part after `/rayhunter/`.
    pub async fn get(&self, path: &str, query: Option<&str>) -> Response {
        let lower = path.to_ascii_lowercase();
        if lower.contains("%2e") || lower.contains("%2f") || !safe(path) {
            return refuse();
        }
        let Some(path) = decode(path) else {
            return refuse();
        };
        // The page polls this every second and reads 404 as "no GPS"; a 403 would stop
        // the whole page. Still never reaches the unit.
        if path == "api/gps" {
            return (StatusCode::NOT_FOUND, NOT_AVAILABLE).into_response();
        }
        if !allowed(&path) {
            return refuse();
        }
        let mut url = format!("{}/{}", self.base, path);
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            url.push('?');
            url.push_str(q);
        }
        // Only the token and Accept go upstream: none of the browser's headers.
        let mut rq = self.client.get(url).header(header::ACCEPT, "*/*");
        if let Some(t) = &self.token {
            rq = rq.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let Ok(up) = rq.send().await else {
            return unreachable();
        };
        let status = up.status();
        let ctype = up.headers().get(header::CONTENT_TYPE).cloned();
        let clen = up.headers().get(header::CONTENT_LENGTH).cloned();
        let gzipped = up
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
        let mut b = Response::builder()
            .status(status)
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
        let body = if path == "index.html" {
            // Rewritten (and possibly unzipped), so type and length are ours.
            let Ok(raw) = up.bytes().await else {
                return unreachable();
            };
            let raw = if gzipped {
                let mut out = Vec::new();
                if flate2::read::GzDecoder::new(&raw[..])
                    .take(INDEX_MAX)
                    .read_to_end(&mut out)
                    .is_err()
                {
                    return unreachable();
                }
                out
            } else {
                raw.to_vec()
            };
            let text = String::from_utf8_lossy(&raw);
            b = b.header(header::CONTENT_TYPE, "text/html; charset=utf-8");
            Body::from(rewrite_index(&text))
        } else {
            b = b.header(header::CONTENT_SECURITY_POLICY, "sandbox");
            if let Some(c) = ctype {
                b = b.header(header::CONTENT_TYPE, c);
            }
            if path == "api/config" {
                // Filtered, so the length is ours.
                let Ok(raw) = up.bytes().await else {
                    return unreachable();
                };
                let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&raw) else {
                    return unreachable();
                };
                strip_private(&mut v);
                Body::from(serde_json::to_vec(&v).unwrap_or_default())
            } else {
                if let Some(c) = clen {
                    b = b.header(header::CONTENT_LENGTH, c);
                }
                Body::from_stream(up.bytes_stream())
            }
        };
        b.body(body).unwrap_or_else(|_| refuse())
    }
}

fn unreachable() -> Response {
    (StatusCode::BAD_GATEWAY, "unit not reachable").into_response()
}

/// Remove the private keys at any depth.
fn strip_private(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            m.retain(|k, _| !PRIVATE_KEYS.contains(&k.as_str()));
            m.values_mut().for_each(strip_private);
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(strip_private),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::io::Read;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    const BUNDLE: &[u8] = include_bytes!("testdata/rayhunter-index.html.gz");

    fn bundle() -> String {
        let mut s = String::new();
        flate2::read::GzDecoder::new(BUNDLE)
            .read_to_string(&mut s)
            .unwrap();
        s
    }

    /// A fake unit: records each raw request, answers every one with `reply`.
    async fn fake(reply: impl AsRef<[u8]>) -> (String, Arc<Mutex<Vec<String>>>) {
        let reply: Vec<u8> = reply.as_ref().to_vec();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen: Arc<Mutex<Vec<String>>> = Default::default();
        let s2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = l.accept().await else {
                    return;
                };
                let s3 = s2.clone();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    s3.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[..n]).to_string());
                    let _ = c.write_all(&reply).await;
                    let _ = c.shutdown().await;
                });
            }
        });
        (url, seen)
    }

    fn rq(method: &str, uri: &str) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, "ha=session")
            .header(header::AUTHORIZATION, "Bearer ingress")
            .body(Body::empty())
            .unwrap();
        let addr: SocketAddr = "172.30.32.2:40000".parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        r
    }

    const OK_JSON: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: s=1\r\nX-Secret: secret\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

    #[test]
    fn downloads_and_writes_are_refused() {
        for p in [
            "api/pcap/x.pcapng",
            "api/qmdl/x.qmdl",
            "api/zip/x.zip",
            "api/m2100/live",
            "api/m2100/sha256/x",
            "api/stop-recording",
            "api/gps",
            "../etc/passwd",
            "api/analysis/../qmdl/x",
            "/api/config",
            "api/analysis-report/a/b",
            "api/analysis-report/",
            "api/config\0",
            "api\\config",
        ] {
            assert!(!allowed(p), "{p}");
        }
    }

    #[test]
    fn ui_reads_are_allowed() {
        for p in EXACT {
            assert!(allowed(p), "{p}");
        }
        assert!(allowed("api/analysis-report/2026-10-01_a.qmdl"));
    }

    #[tokio::test]
    async fn post_is_refused() {
        let (url, seen) = fake(OK_JSON).await;
        let r = crate::web::router(
            crate::page::channel().0,
            Some(Proxy::new(&url, Some("secret".into())).unwrap()),
        )
        .oneshot(rq("POST", "/rayhunter/api/stop-recording"))
        .await
        .unwrap();
        assert!(matches!(
            r.status(),
            StatusCode::METHOD_NOT_ALLOWED | StatusCode::FORBIDDEN
        ));
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unsafe_and_unlisted_paths_never_reach_the_unit() {
        let (url, seen) = fake(OK_JSON).await;
        let p = Proxy::new(&url, None).unwrap();
        for path in [
            "api/pcap/x",
            "api/%2e%2e/qmdl/x",
            "api/analysis-report/%2F..",
            "api/analysis-report/%2fx",
            "api/analysis-report/%5cx",
            "api/analysis-report/x%00",
            "/api/config",
            "api/%zz",
        ] {
            assert_eq!(
                p.get(path, None).await.status(),
                StatusCode::FORBIDDEN,
                "{path}"
            );
        }
        assert!(seen.lock().unwrap().is_empty());
    }

    /// The Rayhunter page polls api/gps every second and reads 404 as "no GPS"; any
    /// other refusal stops the whole page with a connection error.
    #[tokio::test]
    async fn gps_answers_no_gps_without_reaching_the_unit() {
        let (url, seen) = fake(OK_JSON).await;
        let p = Proxy::new(&url, None).unwrap();
        assert_eq!(p.get("api/gps", None).await.status(), StatusCode::NOT_FOUND);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn foreign_peer_cannot_use_the_proxy() {
        let (url, seen) = fake(OK_JSON).await;
        let mut r = rq("GET", "/rayhunter/api/config");
        let addr: SocketAddr = "192.0.2.50:1".parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        let r = crate::web::router(crate::page::channel().0, Proxy::new(&url, None).ok())
            .oneshot(r)
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn rewrite_covers_the_real_bundle() {
        let out = rewrite_index(&bundle());
        for bad in ["'/api/", "\"/api/", "`/api/", "\"/rayhunter_", "\"/favicon"] {
            assert!(!out.contains(bad), "{bad}");
        }
        assert!(out.contains("./api/qmdl-manifest"));
        assert!(out.contains("./rayhunter_orca_only.png"));
    }

    /// Paths the UI uses that the proxy deliberately refuses.
    fn refused_on_purpose(p: &str) -> bool {
        const POSTS: &[&str] = &[
            "api/start-recording",
            "api/stop-recording",
            "api/delete-recording/",
            "api/delete-all-recordings",
            "api/analysis/",
            "api/test-notification",
            "api/wifi-scan",
            "api/time-offset",
            "api/debug/display-state",
            "api/gps",
        ];
        ["api/pcap/", "api/qmdl/", "api/zip/"]
            .iter()
            .chain(POSTS)
            .any(|x| p == x.trim_end_matches('/') || p.starts_with(x) && x.ends_with('/'))
            || (p.starts_with("api/m2100/")
                && p != "api/m2100/profile"
                && p != "api/m2100/capture-profiles")
    }

    #[test]
    fn every_bundle_get_is_allowed() {
        let text = bundle();
        let re = regex::Regex::new(r"/api/[a-z0-9/-]+").unwrap();
        let mut n = 0;
        for m in re.find_iter(&text) {
            let p = m.as_str().trim_start_matches('/');
            // A trailing slash is a prefix (`/api/x/${name}`).
            let bare = p.trim_end_matches('/');
            n += 1;
            assert!(
                allowed(p) || allowed(bare) || p == "api/analysis-report/" || refused_on_purpose(p),
                "the bundle uses {p}: allow it or refuse it on purpose"
            );
        }
        assert!(n > 10, "found only {n} api paths");
    }

    #[tokio::test]
    async fn token_is_sent_upstream_not_downstream() {
        let (url, seen) = fake(OK_JSON).await;
        let r = crate::web::router(
            crate::page::channel().0,
            Some(Proxy::new(&url, Some("secret".into())).unwrap()),
        )
        .oneshot(rq("GET", "/rayhunter/api/config?x=1"))
        .await
        .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        assert!(r.headers().get(header::SET_COOKIE).is_none());
        assert!(r.headers().get("x-secret").is_none());
        let hdrs = format!("{:?}", r.headers());
        let b = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(b.as_ref(), b"{}");
        assert!(!hdrs.contains("secret"));
        let req = seen.lock().unwrap()[0].to_ascii_lowercase();
        assert!(req.starts_with("get /api/config?x=1 "), "{req}");
        assert!(req.contains("authorization: bearer secret"));
        assert!(!req.contains("cookie"));
        assert!(!req.contains("ingress"));
    }

    fn gzip_reply(body: &[u8]) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        head.extend_from_slice(body);
        head
    }

    #[tokio::test]
    async fn index_is_rewritten_on_the_way_through() {
        // The daemon always serves index.html gzipped, with Content-Encoding: gzip.
        let (url, _) = fake(gzip_reply(BUNDLE)).await;
        let r = Proxy::new(&url, None)
            .unwrap()
            .get("index.html", None)
            .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
        let b = r.into_body().collect().await.unwrap().to_bytes();
        let t = String::from_utf8(b.to_vec()).unwrap();
        assert!(t.contains("./api/qmdl-manifest"));
        assert!(!t.contains("`/api/"));
    }

    const CFG: &str = r#"{"ui_level":2,"ntfy_url":"https://ntfy.example/SECRETTOPIC","webdav":{"url":"https://dav.example/SECRETDAV","password":"SECRETPW"},"gps_fixed_latitude":37.7712345,"gps_fixed_longitude":-122.4198765,"wifi_ssid":"SECRETSSID","wifi_password":"SECRETWIFIPW","nested":{"wifi_ssid":"SECRETSSID2","keep":1}}"#;

    #[tokio::test]
    async fn config_is_filtered_of_private_keys() {
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{CFG}",
            CFG.len()
        );
        let (url, _) = fake(reply).await;
        let r = Proxy::new(&url, None)
            .unwrap()
            .get("api/config", None)
            .await;
        assert_eq!(r.status(), StatusCode::OK);
        let b = r.into_body().collect().await.unwrap().to_bytes();
        let t = String::from_utf8(b.to_vec()).unwrap();
        for v in ["SECRET", "37.77", "122.41", "dav.example"] {
            assert!(!t.contains(v), "{v} leaked: {t}");
        }
        let v: serde_json::Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["ui_level"], 2);
        assert_eq!(v["nested"]["keep"], 1);
    }

    #[tokio::test]
    async fn unparseable_config_is_a_502() {
        let (url, _) = fake("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\nnot json SECRETPW").await;
        let r = Proxy::new(&url, None)
            .unwrap()
            .get("api/config", None)
            .await;
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        let b = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(b.as_ref(), b"unit not reachable");
    }

    #[tokio::test]
    async fn proxied_responses_carry_hardening_headers() {
        let (url, _) = fake(OK_JSON).await;
        let r = Proxy::new(&url, None).unwrap().get("api/log", None).await;
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        assert_eq!(r.headers()[header::CONTENT_SECURITY_POLICY], "sandbox");
        let (url, _) = fake(gzip_reply(BUNDLE)).await;
        let r = Proxy::new(&url, None)
            .unwrap()
            .get("index.html", None)
            .await;
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        assert!(r.headers().get(header::CONTENT_SECURITY_POLICY).is_none());
    }

    #[tokio::test]
    async fn only_get_is_accepted() {
        let (url, seen) = fake(OK_JSON).await;
        for m in ["POST", "PUT", "DELETE", "PATCH"] {
            let r = crate::web::router(crate::page::channel().0, Proxy::new(&url, None).ok())
                .oneshot(rq(m, "/rayhunter/api/config"))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED, "{m}");
        }
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dead_unit_is_a_502() {
        let r = Proxy::new("http://127.0.0.1:1", None)
            .unwrap()
            .get("api/log", None)
            .await;
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        let b = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(b.as_ref(), b"unit not reachable");
    }
}
