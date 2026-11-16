//! The one outbound call of the optional alert summary (plan 4): the Messages API over
//! raw HTTP (there is no official Rust SDK).
//!
//! The API key is only ever handed to `call`, which puts it in a sensitive header. Nothing
//! here derives `Debug` on a type holding it, and reqwest errors are mapped by kind, never
//! by their text (which can carry the URL).

use crate::summary::Record;
use serde_json::{Value, json};

pub const SYSTEM_PROMPT: &str = "You help the owner of a home IMSI-catcher sentinel decide what to tell her household. You get a scrubbed JSON record of one alert: check names, relative times in minutes, counts and baseline rates. It contains no identifiers or places, so do not ask for any. In at most 120 words, plain language, say what the evidence suggests, how unusual it is against the baseline, and which follow-up fits best: false_alarm, watching, phones_off or all_clear. You are advice only; the owner decides and sends.";

pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
pub const TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Text {
        text: String,
        cut_short: bool,
        input_tokens: u64,
        output_tokens: u64,
    },
    Refused {
        input_tokens: u64,
        output_tokens: u64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApiError {
    KeyRefused,
    NoCredit,
    Busy,
    NoInternet,
    /// The key has characters a header cannot carry.
    KeyUnusable,
    /// Carries a fixed internal label only, never the API's text.
    Bad(String),
}

impl ApiError {
    pub fn message(&self) -> &'static str {
        match self {
            ApiError::KeyRefused => "API key refused.",
            ApiError::NoCredit => "Out of API credit.",
            ApiError::Busy => "The API is busy or down; try again later.",
            ApiError::NoInternet => "No internet; the alert flow works without it.",
            ApiError::KeyUnusable => "API key not usable.",
            ApiError::Bad(_) => "Unexpected reply from the API.",
        }
    }
}

/// The client for `call`: a 30 s timeout covers connect, send and reading the reply.
pub fn client() -> Result<reqwest::Client, ApiError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        // reqwest strips Authorization on a cross-origin redirect but not x-api-key.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ApiError::Bad("client".into()))
}

pub fn request_body(model: &str, rec: &Record) -> Value {
    let text = serde_json::to_string(rec).expect("record serializes");
    json!({
        "model": model,
        "max_tokens": 4000,
        "system": SYSTEM_PROMPT,
        "output_config": {"effort": "low"},
        "fallbacks": "default",
        "messages": [{"role": "user", "content": text}],
    })
}

pub fn parse(status: u16, body: &str) -> Result<Reply, ApiError> {
    match status {
        200 => {}
        401 | 403 => return Err(ApiError::KeyRefused),
        402 => return Err(ApiError::NoCredit),
        429 | 500..=599 => return Err(ApiError::Busy),
        _ => return Err(ApiError::Bad(format!("status {status}"))),
    }
    let v: Value = serde_json::from_str(body).map_err(|_| ApiError::Bad("not json".into()))?;
    let tokens = |k: &str| v["usage"][k].as_u64().unwrap_or(0);
    let (input_tokens, output_tokens) = (tokens("input_tokens"), tokens("output_tokens"));
    let stop = v["stop_reason"].as_str().unwrap_or("");
    if stop == "refusal" {
        return Ok(Reply::Refused {
            input_tokens,
            output_tokens,
        });
    }
    let blocks = v["content"]
        .as_array()
        .ok_or_else(|| ApiError::Bad("no content".into()))?;
    let text: String = blocks
        .iter()
        .filter(|b| b["type"] == "text")
        .filter_map(|b| b["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    if text.trim().is_empty() {
        return Err(ApiError::Bad("empty".into()));
    }
    Ok(Reply::Text {
        text,
        cut_short: stop == "max_tokens",
        input_tokens,
        output_tokens,
    })
}

/// One request, no retries. `key` goes only into a sensitive header.
pub async fn call(
    client: &reqwest::Client,
    base_url: &str,
    key: &str,
    body: &Value,
) -> Result<Reply, ApiError> {
    let mut k = reqwest::header::HeaderValue::from_str(key)
        .map_err(|_| ApiError::KeyUnusable)?;
    k.set_sensitive(true);
    let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));
    let sent = client
        .post(url)
        .header("x-api-key", k)
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "server-side-fallback-2026-07-01")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await;
    let resp = sent.map_err(map_err)?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(map_err)?;
    parse(status, &text)
}

/// By kind only: the error's own text can include the URL.
fn map_err(e: reqwest::Error) -> ApiError {
    if e.is_timeout() {
        ApiError::Busy
    } else if e.is_connect() {
        ApiError::NoInternet
    } else {
        ApiError::Bad("transport".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summary::{Baseline, EventRec};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn rec() -> Record {
        Record {
            practice: false,
            age_min: 12,
            last_seen_min: 1,
            live: "ok",
            event_count: 1,
            events: vec![EventRec {
                check: "new_tower",
                class: "alert",
                minute: 0,
                source: "live",
                timeline_only: false,
            }],
            sent: vec!["watching"],
            baseline: Baseline {
                identity_24h: 3,
                identity_per_day_7d: 0.5,
                strong_alerts_30d: 0,
                profile: "fixed",
            },
            units: 1,
        }
    }

    #[test]
    fn request_body_shape() {
        let r = rec();
        let b = request_body("claude-opus-5-5", &r);
        assert_eq!(b["model"], "claude-opus-5-5");
        assert_eq!(b["max_tokens"], 4000);
        assert_eq!(b["output_config"]["effort"], "low");
        assert_eq!(b["fallbacks"], "default");
        assert_eq!(b["system"], SYSTEM_PROMPT);
        assert!(b.get("thinking").is_none());
        assert!(b.get("temperature").is_none());
        let m = b["messages"].as_array().unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["role"], "user");
        let back: Value = serde_json::from_str(m[0]["content"].as_str().unwrap()).unwrap();
        assert_eq!(back, serde_json::to_value(&r).unwrap());
    }

    #[test]
    fn parse_text_reply() {
        let body = r#"{"content":[{"type":"thinking","thinking":"","signature":"x"},
            {"type":"text","text":"One."},{"type":"text","text":"Two."}],
            "stop_reason":"end_turn","usage":{"input_tokens":11,"output_tokens":22}}"#;
        assert_eq!(
            parse(200, body),
            Ok(Reply::Text {
                text: "One.\n\nTwo.".into(),
                cut_short: false,
                input_tokens: 11,
                output_tokens: 22
            })
        );
    }

    #[test]
    fn parse_max_tokens_is_cut_short() {
        let body = r#"{"content":[{"type":"text","text":"Half"}],"stop_reason":"max_tokens",
            "usage":{"input_tokens":1,"output_tokens":4000}}"#;
        match parse(200, body).unwrap() {
            Reply::Text {
                text, cut_short, ..
            } => {
                assert_eq!(text, "Half");
                assert!(cut_short);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parse_refusal() {
        let body = r#"{"content":[],"stop_reason":"refusal",
            "usage":{"input_tokens":5,"output_tokens":0}}"#;
        assert_eq!(
            parse(200, body),
            Ok(Reply::Refused {
                input_tokens: 5,
                output_tokens: 0
            })
        );
    }

    #[test]
    fn parse_errors() {
        let e = r#"{"type":"error","error":{"type":"x","message":"secret words"}}"#;
        assert_eq!(parse(401, e), Err(ApiError::KeyRefused));
        assert_eq!(parse(403, e), Err(ApiError::KeyRefused));
        assert_eq!(parse(402, e), Err(ApiError::NoCredit));
        for s in [429, 529, 500] {
            assert_eq!(parse(s, e), Err(ApiError::Busy));
        }
        assert!(matches!(parse(200, "<html>"), Err(ApiError::Bad(_))));
        assert!(matches!(parse(400, e), Err(ApiError::Bad(_))));
        // The API's own text never reaches a message.
        assert!(!format!("{:?}", parse(400, e)).contains("secret words"));
        assert_eq!(
            ApiError::Bad("x".into()).message(),
            "Unexpected reply from the API."
        );
    }

    /// Records each raw request; answers with `status` and `body`, or never if `status` is 0.
    async fn fake(status: u16, body: &str) -> (String, Arc<Mutex<Vec<String>>>) {
        fake_with(status, "", body).await
    }

    async fn fake_with(status: u16, extra: &str, body: &str) -> (String, Arc<Mutex<Vec<String>>>) {
        let body = body.to_string();
        let extra = extra.to_string();
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
                let body = body.clone();
                let extra = extra.clone();
                tokio::spawn(async move {
                    let mut got: Vec<u8> = Vec::new();
                    let mut buf = vec![0u8; 16384];
                    loop {
                        let n = c.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&got).to_string();
                        if let Some(i) = text.find("\r\n\r\n") {
                            let want = text[..i]
                                .to_lowercase()
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if got.len() >= i + 4 + want {
                                break;
                            }
                        }
                    }
                    s3.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&got).to_string());
                    if status == 0 {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        return;
                    }
                    let r = format!(
                        "HTTP/1.1 {status} X\r\n{extra}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = c.write_all(r.as_bytes()).await;
                    let _ = c.shutdown().await;
                });
            }
        });
        (url, seen)
    }

    const OK: &str = r#"{"content":[{"type":"text","text":"Fine."}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":2}}"#;

    #[tokio::test]
    async fn call_sends_the_headers() {
        let (url, seen) = fake(200, OK).await;
        let b = request_body("m", &rec());
        let r = call(&client().unwrap(), &url, "sk-test-SECRET", &b).await;
        assert!(matches!(r, Ok(Reply::Text { .. })), "{r:?}");
        let reqs = seen.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let head = reqs[0].to_lowercase();
        assert!(head.starts_with("post /v1/messages http/1.1"), "{head}");
        assert!(head.contains("\r\nx-api-key: sk-test-secret\r\n"));
        assert!(head.contains("\r\nanthropic-version: 2023-06-01\r\n"));
        assert!(head.contains("\r\nanthropic-beta: server-side-fallback-2026-07-01\r\n"));
        assert!(head.contains("\r\ncontent-type: application/json\r\n"));
    }

    #[tokio::test]
    async fn errors_never_contain_the_key() {
        let key = "sk-test-SECRET";
        let b = request_body("m", &rec());
        // Connection refused: bind a port, then drop the listener.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let refused = call(&client().unwrap(), &dead, key, &b).await.unwrap_err();
        assert_eq!(refused, ApiError::NoInternet);
        // 401 whose body even echoes the key.
        let (u401, _) = fake(
            401,
            r#"{"type":"error","error":{"message":"bad sk-test-SECRET"}}"#,
        )
        .await;
        let e401 = call(&client().unwrap(), &u401, key, &b).await.unwrap_err();
        assert_eq!(e401, ApiError::KeyRefused);
        // A 400 and a 200 non-JSON whose bodies echo the key.
        let (u400, _) = fake(400, "bad key sk-test-SECRET").await;
        let e400 = call(&client().unwrap(), &u400, key, &b).await.unwrap_err();
        let (unj, _) = fake(200, "<html>sk-test-SECRET</html>").await;
        let enj = call(&client().unwrap(), &unj, key, &b).await.unwrap_err();
        assert!(matches!(e400, ApiError::Bad(_)) && matches!(enj, ApiError::Bad(_)));
        // Timeout.
        let (hang, _) = fake(0, "").await;
        let fast = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let slow = call(&fast, &hang, key, &b).await.unwrap_err();
        assert_eq!(slow, ApiError::Busy);
        for e in [refused, e401, e400, enj, slow] {
            assert!(!e.message().contains("SECRET"));
            assert!(!format!("{e:?}").contains("SECRET"));
        }
        // An unusable key is reported without echoing it.
        let bad = call(&client().unwrap(), &dead, "sk-SECRET\n", &b).await.unwrap_err();
        assert!(!format!("{bad:?}{}", bad.message()).contains("SECRET"));
        assert_eq!(bad.message(), "API key not usable.");
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed_so_the_key_stays_put() {
        let (b_url, b_seen) = fake(200, OK).await;
        let loc = format!("location: {b_url}/v1/messages\r\n");
        let (a_url, a_seen) = fake_with(302, &loc, "").await;
        let r = call(
            &client().unwrap(),
            &a_url,
            "sk-test-SECRET",
            &request_body("m", &rec()),
        )
        .await;
        assert!(matches!(r, Err(ApiError::Bad(_))), "{r:?}");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(a_seen.lock().unwrap().len(), 1);
        assert_eq!(b_seen.lock().unwrap().len(), 0, "the key was sent on");
    }

    #[tokio::test]
    async fn no_retry() {
        let (url, seen) = fake(
            529,
            r#"{"type":"error","error":{"type":"overloaded_error"}}"#,
        )
        .await;
        let r = call(&client().unwrap(), &url, "k", &request_body("m", &rec())).await;
        assert_eq!(r, Err(ApiError::Busy));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
