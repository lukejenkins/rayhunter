use anyhow::Error;
use async_zip::Compression;
use async_zip::ZipEntryBuilder;
use async_zip::tokio::write::ZipFileWriter;
use axum::Json;
use axum::body::Body;
use axum::extract::Path;
use axum::extract::State;
use axum::http::header::{self, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Local};
use futures::TryStreamExt;
use log::{error, warn};
use rayhunter::analysis::analyzer::{AnalyzerMetadata, get_analyzers_metadata};
use rayhunter::qmdl::QmdlMessageReader;
use serde::{Deserialize, Serialize};
use std::pin::pin;
use std::sync::Arc;
use tokio::fs::write;
use tokio::io::copy;
use tokio::io::duplex;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::compat::FuturesAsyncWriteCompatExt;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

use crate::analysis::{AnalysisCtrlMessage, AnalysisStatus};
use crate::config::{Config, GpsMode};
use crate::diag::DiagDeviceCtrlMessage;
use crate::display::DisplayState;
use crate::gps::GpsData;
use crate::notifications::DEFAULT_NOTIFICATION_TIMEOUT;
use crate::pcap::{generate_pcap_data, load_gps_records_for_entry};
use crate::qmdl_store::{FileKind, RecordingStore};
use crate::update::UpdateStatus;

pub struct ServerState {
    pub config_path: String,
    pub config: Config,
    pub qmdl_store_lock: Arc<RwLock<RecordingStore>>,
    pub diag_device_ctrl_sender: Sender<DiagDeviceCtrlMessage>,
    pub analysis_status_lock: Arc<RwLock<AnalysisStatus>>,
    pub analysis_sender: Sender<AnalysisCtrlMessage>,
    pub daemon_restart_token: CancellationToken,
    pub ui_update_sender: Option<Sender<DisplayState>>,
    pub wifi_status: Arc<RwLock<wifi_station::WifiStatus>>,
    pub wifi_scan_lock: tokio::sync::Mutex<()>,
    pub gps_state: Arc<RwLock<Option<GpsData>>>,
    pub live: Arc<std::sync::Mutex<crate::m2100_observe::LiveObservations>>,
    pub update_status_lock: Arc<RwLock<UpdateStatus>>,
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/qmdl/{name}",
    tag = "Recordings",
    responses(
        (status = StatusCode::OK, description = "QMDL download successful", content_type = "application/octet-stream"),
        (status = StatusCode::NOT_FOUND, description = "Could not find file {name}"),
        (status = StatusCode::SERVICE_UNAVAILABLE, description = "QMDL file is empty, or error opening file")
    ),
    params(
        ("name" = String, Path, description = "QMDL filename to convert and download")
    ),
    summary = "Download a QMDL file",
    description = "Stream the QMDL file {name} to the client."
))]
pub async fn get_qmdl(
    State(state): State<Arc<ServerState>>,
    Path(qmdl_name): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let qmdl_idx = qmdl_name.trim_end_matches(".qmdl");
    let qmdl_store = state.qmdl_store_lock.read().await;
    let (entry_index, _) = qmdl_store.entry_for_name(qmdl_idx).ok_or((
        StatusCode::NOT_FOUND,
        format!("couldn't find qmdl file with name {qmdl_idx}"),
    ))?;
    let qmdl_file = qmdl_store
        .open_file(entry_index, FileKind::Qmdl)
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error opening QMDL file: {err}"),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "QMDL file not found".to_string()))?;
    let qmdl_reader = QmdlMessageReader::new(qmdl_file).await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("error reading QMDL file: {err}"),
        )
    })?;

    let headers = [(CONTENT_TYPE, "application/octet-stream")];
    let body = Body::from_stream(qmdl_reader.into_qmdl_stream());
    Ok((headers, body).into_response())
}

pub async fn serve_static(
    State(_): State<Arc<ServerState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let path = path.trim_start_matches('/');

    match path {
        "rayhunter_orca_only.png" => (
            [(header::CONTENT_TYPE, HeaderValue::from_static("image/png"))],
            include_bytes!("../web/build/rayhunter_orca_only.png"),
        )
            .into_response(),
        "rayhunter_text.png" => (
            [(header::CONTENT_TYPE, HeaderValue::from_static("image/png"))],
            include_bytes!("../web/build/rayhunter_text.png"),
        )
            .into_response(),
        "favicon.png" => (
            [(header::CONTENT_TYPE, HeaderValue::from_static("image/png"))],
            include_bytes!("../web/build/favicon.png"),
        )
            .into_response(),
        "index.html" => (
            [
                (header::CONTENT_TYPE, HeaderValue::from_static("text/html")),
                (header::CONTENT_ENCODING, HeaderValue::from_static("gzip")),
            ],
            include_bytes!("../web/build/index.html.gz"),
        )
            .into_response(),
        path => {
            warn!("404 on path: {path}");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/config",
    tag = "Configuration",
    responses(
        (status = StatusCode::OK, description = "Success", body = Config)
    ),
    summary = "Get config",
    description = "Show the running configuration for Rayhunter."
))]
pub async fn get_config(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Config>, (StatusCode, String)> {
    let mut config = state.config.clone();
    config.wifi_password = None;
    Ok(Json(config))
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/analyzers",
    tag = "Configuration",
    responses(
        (status = StatusCode::OK, description = "Success", body = Vec<AnalyzerMetadata>)
    ),
    summary = "List analyzers",
    description = "List the analyzers compiled into Rayhunter, including the config key that enables each of them."
))]
pub async fn get_analyzers() -> Json<Vec<AnalyzerMetadata>> {
    Json(get_analyzers_metadata())
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/config",
    tag = "Configuration",
    request_body(
        content = Option<[Config]>,
        description = "Any or all configuration elements from the valid config schema to be altered may be passed. Invalid keys will be discarded. Invalid values or value types will return an error."
    ),
    responses(
        (status = StatusCode::ACCEPTED, description = "Success"),
        (status = StatusCode::INTERNAL_SERVER_ERROR, description = "Failed to parse or write config file"),
        (status = 422, description = "Failed to deserialize JSON body")
    ),
    summary = "Set config",
    description = "Write a new configuration for Rayhunter and trigger a restart."
))]
pub async fn set_config(
    State(state): State<Arc<ServerState>>,
    Json(mut config): Json<Config>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if config.gps_mode != GpsMode::Fixed {
        config.gps_fixed_latitude = None;
        config.gps_fixed_longitude = None;
    }
    let mut config_to_write = config.clone();
    config_to_write.wifi_ssid = None;
    config_to_write.wifi_password = None;
    config_to_write.wifi_security = None;

    let config_str = toml::to_string_pretty(&config_to_write).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize config as TOML: {err}"),
        )
    })?;

    write(&state.config_path, config_str).await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write config file: {err}"),
        )
    })?;

    wifi_station::update_wpa_conf(&config.wifi_config()).await;

    // Trigger daemon restart after writing config
    state.daemon_restart_token.cancel();
    Ok((
        StatusCode::ACCEPTED,
        "wrote config and triggered restart".to_string(),
    ))
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/test-notification",
    tag = "Configuration",
    responses(
        (status = StatusCode::OK, description = "Success"),
        (status = StatusCode::BAD_REQUEST, description = "No notification URL set"),
        (status = StatusCode::INTERNAL_SERVER_ERROR, description = "Failed to send HTTP request. Ensure your device can reach the internet.")
    ),
    summary = "Test ntfy notification",
    description = "Send a test notification to the ntfy_url in the running configuration for Rayhunter."
))]
pub async fn test_notification(
    State(state): State<Arc<ServerState>>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let url = state.config.ntfy_url.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        "No notification URL configured".to_string(),
    ))?;

    if url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Notification URL is empty".to_string(),
        ));
    }

    let http_client = crate::http_client::client().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create HTTP client: {err}"),
        )
    })?;
    let message = "Test notification from Rayhunter".to_string();

    crate::notifications::send_notification(
        &http_client,
        url,
        message,
        DEFAULT_NOTIFICATION_TIMEOUT,
    )
    .await
    .map(|()| {
        (
            StatusCode::OK,
            "Test notification sent successfully".to_string(),
        )
    })
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to send test notification: {e}"),
        )
    })
}

/// Response for GET /api/time
#[derive(Serialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct TimeResponse {
    /// The raw system time (without clock offset)
    #[cfg_attr(feature = "apidocs", schema(value_type = String))]
    pub system_time: DateTime<Local>,
    /// The adjusted time (system time + offset)
    #[cfg_attr(feature = "apidocs", schema(value_type = String))]
    pub adjusted_time: DateTime<Local>,
    /// The current offset in seconds
    pub offset_seconds: i64,
}

/// Request for POST /api/time-offset
#[derive(Deserialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct SetTimeOffsetRequest {
    /// The offset to set, in seconds
    pub offset_seconds: i64,
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/time",
    tag = "Configuration",
    responses(
        (status = StatusCode::OK, description = "Success", body = TimeResponse)
    ),
    summary = "Get time",
    description = "Get the current time and offset (in seconds) of the device."
))]
pub async fn get_time() -> Json<TimeResponse> {
    let system_time = Local::now();
    let adjusted_time = rayhunter::clock::get_adjusted_now();
    let offset_seconds = adjusted_time
        .signed_duration_since(system_time)
        .num_seconds();
    Json(TimeResponse {
        system_time,
        adjusted_time,
        offset_seconds,
    })
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/time-offset",
    tag = "Configuration",
    request_body(
        content = SetTimeOffsetRequest
    ),
    responses(
        (status = StatusCode::OK, description = "Success", body = TimeResponse)
    ),
    summary = "Set time offset",
    description = "Set the difference (in seconds) between the system time and the adjusted time for Rayhunter."
))]
pub async fn set_time_offset(Json(req): Json<SetTimeOffsetRequest>) -> StatusCode {
    rayhunter::clock::set_offset(chrono::TimeDelta::seconds(req.offset_seconds));
    StatusCode::OK
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/zip/{name}",
    tag = "Recordings",
    responses(
        (status = StatusCode::OK, description = "ZIP download successful. It is possible that if the PCAP fails to convert, the same status will be returned, but the file will contain only the QMDL file.", content_type = "application/zip"),
        (status = StatusCode::NOT_FOUND, description = "Could not find file {name}"),
        (status = StatusCode::SERVICE_UNAVAILABLE, description = "QMDL file is empty, or error opening file")
    ),
    params(
        ("name" = String, Path, description = "QMDL filename to convert and download")
    ),
    summary = "Download a ZIP file",
    description = "Stream a ZIP file to the client which contains the QMDL file {name}, its NDJSON analysis report, its GPS NDJSON file (if present), and a PCAP generated from the QMDL."
))]
pub async fn get_zip(
    State(state): State<Arc<ServerState>>,
    Path(entry_name): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let qmdl_idx = entry_name.trim_end_matches(".zip").to_owned();
    let entry_index = {
        let qmdl_store = state.qmdl_store_lock.read().await;
        let (entry_index, entry) = qmdl_store.entry_for_name(&qmdl_idx).ok_or((
            StatusCode::NOT_FOUND,
            format!("couldn't find entry with name {qmdl_idx}"),
        ))?;

        if entry.qmdl_size_bytes == 0 {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "QMDL file is empty, try again in a bit!".to_string(),
            ));
        }

        entry_index
    };

    let qmdl_store_lock = state.qmdl_store_lock.clone();
    let gps_records = load_gps_records_for_entry(&state, entry_index).await;

    let (reader, writer) = duplex(8192);

    tokio::spawn(async move {
        let result: Result<(), Error> = async {
            let mut zip = ZipFileWriter::with_tokio(writer);

            // Add stored files
            for &file_kind in FileKind::ALL {
                let file_opt = {
                    let qmdl_store = qmdl_store_lock.read().await;
                    qmdl_store.open_file(entry_index, file_kind).await?
                };

                let Some(mut file) = file_opt else {
                    continue;
                };

                /*
                 * `qmdl_compressed` is always false here because even if the
                 * QMDL was already compressed, we decompress it before zipping.
                 * This is for two reasons
                 * 1. If this is the current entry, it's still being written and
                 *    lacks a GZIP footer. If we zipped up this partial .gz
                 *    file, some software might consider it damaged and refuse to
                 *    extract it.
                 * 2. Zipping an already-GZIP'd file is redundant and
                 *    inconvenient for the user.
                 */
                let zip_entry = ZipEntryBuilder::new(
                    file_kind.get_filename(&qmdl_idx, false).into(),
                    Compression::Stored,
                );
                // FuturesAsyncWriteCompatExt::compat_write because async-zip's entrystream does
                // not impl tokio's AsyncWrite, but only future's AsyncWrite. This can be removed
                // once https://github.com/Majored/rs-async-zip/pull/160 is released.
                let mut entry_writer = zip.write_entry_stream(zip_entry).await?.compat_write();

                if file_kind == FileKind::Qmdl {
                    let reader = QmdlMessageReader::new(&mut file).await?;
                    let stream = reader.into_qmdl_stream();
                    let mut reader = pin!(stream.into_async_read().compat());
                    copy(&mut reader, &mut entry_writer).await?;
                } else {
                    copy(&mut file, &mut entry_writer).await?;
                }
                entry_writer.into_inner().close().await?;
            }

            // Add PCAP file
            {
                let entry =
                    ZipEntryBuilder::new(format!("{qmdl_idx}.pcapng").into(), Compression::Stored);
                let mut entry_writer = zip.write_entry_stream(entry).await?.compat_write();

                let qmdl_file_for_pcap = {
                    let qmdl_store = qmdl_store_lock.read().await;
                    qmdl_store
                        .open_file(entry_index, FileKind::Qmdl)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("QMDL file not found"))?
                };
                let qmdl_reader = QmdlMessageReader::new(qmdl_file_for_pcap).await?;

                if let Err(e) =
                    generate_pcap_data(&mut entry_writer, qmdl_reader, gps_records).await
                {
                    // if we fail to generate the PCAP file, we should still continue and give the
                    // user the QMDL.
                    error!("Failed to generate PCAP: {e:?}");
                }

                entry_writer.into_inner().close().await?;
            }

            zip.close().await?;
            Ok(())
        }
        .await;

        if let Err(e) = result {
            error!("Error generating ZIP file: {e:?}");
        }
    });

    let headers = [(CONTENT_TYPE, "application/zip")];
    let body = Body::from_stream(ReaderStream::new(reader));
    Ok((headers, body).into_response())
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/wifi-status",
    tag = "Configuration",
    responses(
        (status = StatusCode::OK, description = "Success", body = wifi_station::WifiStatus)
    ),
    summary = "Get wifi status",
    description = "Show the status of the wifi client."
))]
pub async fn get_wifi_status(
    State(state): State<Arc<ServerState>>,
) -> Json<wifi_station::WifiStatus> {
    let status = state.wifi_status.read().await;
    Json(status.clone())
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/wifi-scan",
    tag = "Configuration",
    responses(
        (status = StatusCode::OK, description = "Scan success", body = inline(Vec<wifi_station::WifiNetwork>), content_type = "application/json"),
        (status = StatusCode::TOO_MANY_REQUESTS, description = "Scan already in progress"),
        (status = StatusCode::INTERNAL_SERVER_ERROR, description = "Scan failed"),
    ),
    summary = "Wifi SSID scan",
    description = "Poll for a list of available wifi networks. Returns an array of WifiNetwork objects."
))]
pub async fn scan_wifi(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<Vec<wifi_station::WifiNetwork>>, (StatusCode, String)> {
    let _guard = state.wifi_scan_lock.try_lock().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "WiFi scan already in progress".to_string(),
        )
    })?;
    let networks = wifi_station::scan_wifi_networks(wifi_station::STA_IFACE)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("WiFi scan failed: {e}"),
            )
        })?;
    Ok(Json(networks))
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/debug/display-state",
    tag = "Configuration",
    request_body(
        content = DisplayState
    ),
    responses(
        (status = StatusCode::OK, description = "Display state updated successfully"),
        (status = StatusCode::INTERNAL_SERVER_ERROR, description = "Error sending update to the display"),
        (status = StatusCode::SERVICE_UNAVAILABLE, description = "Display system not available")
    ),
    summary = "Set display state",
    description = "Change the display state (color bar or otherwise) of the device for debugging purposes."
))]
pub async fn debug_set_display_state(
    State(state): State<Arc<ServerState>>,
    Json(display_state): Json<DisplayState>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if let Some(ui_sender) = &state.ui_update_sender {
        ui_sender.send(display_state).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to send display state update".to_string(),
            )
        })?;
        Ok((
            StatusCode::OK,
            "display state updated successfully".to_string(),
        ))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "display system not available".to_string(),
        ))
    }
}

/// The saved deployment profile and live readings (M2100). Read-only: the
/// profile is switched from the panel, never over the network.
pub async fn get_m2100_profile() -> Json<crate::display::m2100_profile_io::Readings> {
    let runner = crate::display::m2100_cli::System::new();
    Json(crate::display::m2100_profile_io::readings(&runner, std::path::Path::new("/")).await)
}

/// Which profile each capture was recorded in (`{"<capture>": "fixed" |
/// "mobile" | "mixed"}`). A missing log is an empty object.
pub async fn get_m2100_capture_profiles() -> Json<std::collections::BTreeMap<String, &'static str>>
{
    let text =
        tokio::fs::read_to_string(crate::display::m2100_capture_profiles::CAPTURE_PROFILES_PATH)
            .await
            .unwrap_or_default();
    Json(crate::display::m2100_capture_profiles::summarise(&text))
}

/// The only write endpoint for the archive add-on: moves the unit to its
/// locked-down Fixed profile and nothing else. Takes no parameters. A missing,
/// wrong or absent token is the same empty 401; one accepted request per 10 s.
pub async fn post_m2100_fixed(headers: axum::http::HeaderMap) -> Response {
    use crate::display::m2100_token::{RATE_LIMIT, TOKEN_PATH, bearer_ok};
    let stored = tokio::fs::read_to_string(TOKEN_PATH).await.ok();
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !bearer_ok(given, stored.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !RATE_LIMIT.allow(std::time::Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    use crate::display::m2100_profile_io::{BOOT_FAILED, SWITCHING};
    // Detached: if the client hangs up, the switch still runs to the end rather
    // than being cancelled with Fixed half-applied.
    let ok = crate::display::m2100_token::guarded_detached(&SWITCHING, async {
        crate::display::m2100_profile_io::switch_to(
            &crate::display::m2100_cli::System::new(),
            std::path::Path::new(crate::display::m2100_profile::PROFILE_PATH),
            crate::display::m2100_profile::Profile::Fixed,
        )
        .await
    })
    .await;
    if ok {
        BOOT_FAILED.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    Json(serde_json::json!({ "ok": ok })).into_response()
}

/// What the current recording has seen so far (towers, identity requests,
/// warnings) for the archive add-on. Read-only, behind the same device token as
/// `/fixed` but not rate limited: it is polled. Only the live lock is taken, and
/// never across an await; the recorder's store lock is not touched.
#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/m2100/live",
    tag = "M2100",
    responses(
        (status = StatusCode::OK, description = "What the current recording has seen", body = crate::m2100_observe::LiveSnapshot),
        (status = StatusCode::UNAUTHORIZED, description = "Missing or wrong device token")
    ),
    summary = "Live observations (M2100)",
    description = "Towers, identity requests and warnings seen in the current recording. Requires `Authorization: Bearer <device token>`; not rate limited."
))]
pub async fn get_m2100_live(
    State(state): State<Arc<ServerState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<crate::m2100_observe::LiveSnapshot>, (StatusCode, String)> {
    let stored = tokio::fs::read_to_string(crate::display::m2100_token::TOKEN_PATH)
        .await
        .ok();
    live_with_token(&state, &headers, stored.as_deref())
}

fn live_with_token(
    state: &ServerState,
    headers: &axum::http::HeaderMap,
    stored: Option<&str>,
) -> Result<Json<crate::m2100_observe::LiveSnapshot>, (StatusCode, String)> {
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !crate::display::m2100_token::bearer_ok(given, stored) {
        return Err((StatusCode::UNAUTHORIZED, String::new()));
    }
    let snapshot = state
        .live
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .snapshot();
    Ok(Json(snapshot))
}

/// SHA-256 (lowercase hex) of exactly the bytes `GET /api/qmdl/{name}` streams,
/// so the archive add-on can verify its copy before deleting the device's.
/// 404 unknown, 409 for the recording in progress, 500 on any read error.
pub async fn get_m2100_sha256(
    State(state): State<Arc<ServerState>>,
    Path(qmdl_name): Path<String>,
) -> Result<String, (StatusCode, String)> {
    let qmdl_idx = qmdl_name.trim_end_matches(".qmdl");
    // The store guard is held only to find the entry, refuse the current one and
    // open the file. It is dropped before hashing: the recorder takes the write lock
    // for every diag container, so holding the read lock for a whole hash would stall
    // live recording. The open handle keeps reading the right file regardless.
    let qmdl_file = {
        let qmdl_store = state.qmdl_store_lock.read().await;
        let (entry_index, _) = qmdl_store.entry_for_name(qmdl_idx).ok_or((
            StatusCode::NOT_FOUND,
            format!("couldn't find qmdl file with name {qmdl_idx}"),
        ))?;
        if qmdl_store.current_entry == Some(entry_index) {
            return Err((StatusCode::CONFLICT, "recording in progress".to_string()));
        }
        qmdl_store
            .open_file(entry_index, FileKind::Qmdl)
            .await
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("error opening QMDL file: {err}"),
                )
            })?
            .ok_or((StatusCode::NOT_FOUND, "QMDL file not found".to_string()))?
    };
    let qmdl_reader = QmdlMessageReader::new(qmdl_file).await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("error reading QMDL file: {err}"),
        )
    })?;
    crate::display::m2100_hash::sha256_of_stream(qmdl_reader.into_qmdl_stream().into_stream())
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error hashing QMDL file: {err}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::config::GpsMode;
    use async_zip::base::read::mem::ZipFileReader;
    use axum::extract::{Path, State};
    use futures::AsyncReadExt;
    use rayhunter::{
        diag::{DataType, HdlcEncapsulatedMessage, Message, MessagesContainer},
        qmdl::{QmdlMessageReader, QmdlWriter},
    };
    use tempfile::TempDir;

    async fn create_test_qmdl_store() -> (TempDir, Arc<RwLock<crate::qmdl_store::RecordingStore>>) {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().to_path_buf();
        let store = crate::qmdl_store::RecordingStore::create(&store_path)
            .await
            .unwrap();
        (temp_dir, Arc::new(RwLock::new(store)))
    }

    async fn create_test_entry_with_data(
        store_lock: &Arc<RwLock<crate::qmdl_store::RecordingStore>>,
        test_data: &MessagesContainer,
    ) -> String {
        let entry_name = {
            let mut store = store_lock.write().await;
            let (mut qmdl_gz_file, _analysis_file) =
                store.new_entry(GpsMode::Disabled).await.unwrap();

            let mut writer = QmdlWriter::new(&mut qmdl_gz_file);
            writer.write_container(test_data).await.unwrap();
            writer.close().await.unwrap();

            let qmdl_file_size = qmdl_gz_file.metadata().await.unwrap().len() as usize;

            let current_entry = store.current_entry.unwrap();
            let entry = &store.manifest.entries[current_entry];
            let entry_name = entry.name.clone();

            store
                .update_current_entry_qmdl_size(qmdl_file_size)
                .await
                .unwrap();
            entry_name
        };

        let mut store = store_lock.write().await;
        store.close_current_entry().await.unwrap();
        entry_name
    }

    fn create_test_server_state(
        store_lock: Arc<RwLock<crate::qmdl_store::RecordingStore>>,
    ) -> Arc<ServerState> {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let (analysis_tx, _analysis_rx) = tokio::sync::mpsc::channel(1);

        let analysis_status = {
            let store = store_lock.try_read().unwrap();
            crate::analysis::AnalysisStatus::new(&store)
        };

        Arc::new(ServerState {
            config_path: "/tmp/test_config.toml".to_string(),
            config: Config::default(),
            qmdl_store_lock: store_lock,
            diag_device_ctrl_sender: tx,
            analysis_status_lock: Arc::new(RwLock::new(analysis_status)),
            analysis_sender: analysis_tx,
            daemon_restart_token: CancellationToken::new(),
            ui_update_sender: None,
            wifi_status: Arc::new(RwLock::new(wifi_station::WifiStatus::default())),
            wifi_scan_lock: tokio::sync::Mutex::new(()),
            gps_state: Arc::new(RwLock::new(None)),
            live: Arc::default(),
            update_status_lock: Arc::new(RwLock::new(UpdateStatus::default())),
        })
    }

    // valid HDLC encapsulated diag message generated from
    // rayhunter::diag::test::get_test_message
    fn create_test_container() -> MessagesContainer {
        MessagesContainer {
            data_type: DataType::UserSpace,
            num_messages: 1,
            messages: vec![HdlcEncapsulatedMessage {
                len: 39,
                data: vec![
                    16, 0, 32, 0, 32, 0, 192, 176, 26, 165, 245, 135, 118, 35, 2, 1, 20, 14, 48, 0,
                    160, 0, 2, 8, 0, 0, 217, 15, 5, 0, 0, 0, 0, 1, 0, 10, 13, 196, 126,
                ],
            }],
        }
    }

    #[tokio::test]
    async fn test_get_zip_success() {
        let (_temp_dir, store_lock) = create_test_qmdl_store().await;
        let test_qmdl_data = create_test_container();
        let entry_name = create_test_entry_with_data(&store_lock, &test_qmdl_data).await;
        let state = create_test_server_state(store_lock);

        let response = get_zip(State(state), Path(entry_name.clone()))
            .await
            .unwrap();

        let headers = response.headers();
        assert_eq!(headers.get("content-type").unwrap(), "application/zip");

        let body = response.into_body();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();

        let zip_reader = ZipFileReader::new(body_bytes.to_vec()).await.unwrap();
        let zip_reader_file = zip_reader.file();
        let filenames: Vec<String> = zip_reader_file
            .entries()
            .iter()
            .map(|entry| entry.filename().as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            filenames,
            vec![
                format!("{entry_name}.qmdl"),
                format!("{entry_name}.ndjson"),
                format!("{entry_name}-gps.ndjson"),
                format!("{entry_name}.pcapng"),
            ]
        );

        let mut qmdl_body = Vec::with_capacity(128);
        zip_reader
            .reader_without_entry(0)
            .await
            .unwrap()
            .read_to_end(&mut qmdl_body)
            .await
            .unwrap();
        let mut qmdl_reader = QmdlMessageReader::new(Cursor::new(qmdl_body))
            .await
            .unwrap();
        let expected_message = Message::from_hdlc(&test_qmdl_data.messages[0].data).unwrap();
        assert_eq!(
            qmdl_reader.get_next_message().await.unwrap(),
            Some(Ok(expected_message)),
        );
    }

    /// I3: the hash must not hold the store's read lock while it reads the file,
    /// or the recorder (which takes the write lock per diag container) stalls.
    /// The QMDL file is swapped for a FIFO that has a writer but no data yet, so
    /// the hash blocks in its first read; the write lock must still be free.
    #[tokio::test]
    async fn sha256_does_not_hold_the_store_lock_while_hashing() {
        use std::os::unix::ffi::OsStrExt;
        let (_temp_dir, store_lock) = create_test_qmdl_store().await;
        let entry_name = create_test_entry_with_data(&store_lock, &create_test_container()).await;
        let qmdl_path = {
            let store = store_lock.read().await;
            let (i, _) = store.entry_for_name(&entry_name).unwrap();
            store.manifest.entries[i].get_filepath(FileKind::Qmdl, &store.path)
        };
        std::fs::remove_file(&qmdl_path).unwrap();
        let c = std::ffi::CString::new(qmdl_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // O_RDWR on a FIFO opens without waiting and keeps a writer present.
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&qmdl_path)
            .unwrap();
        let state = create_test_server_state(store_lock.clone());
        let hashing = tokio::spawn(get_m2100_sha256(State(state), Path(entry_name)));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let got_write =
            tokio::time::timeout(std::time::Duration::from_secs(2), store_lock.write()).await;
        let free = got_write.is_ok();
        drop(got_write);
        // Let the hash finish whatever the outcome, so no blocking read is left behind.
        use std::io::Write;
        writer.write_all(b"\x10\x00").unwrap();
        drop(writer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), hashing).await;
        assert!(free, "the store lock was held while hashing");
    }

    const LIVE_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn bearer(token: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    async fn live_state() -> (TempDir, Arc<ServerState>) {
        let (dir, store_lock) = create_test_qmdl_store().await;
        (dir, create_test_server_state(store_lock))
    }

    async fn body_json(r: Json<crate::m2100_observe::LiveSnapshot>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(Json(r.0).into_response().into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn live_without_header_is_401() {
        let (_d, state) = live_state().await;
        let r = live_with_token(&state, &axum::http::HeaderMap::new(), Some(LIVE_TOKEN));
        assert_eq!(r.err().unwrap().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn live_with_wrong_token_is_401() {
        let (_d, state) = live_state().await;
        let wrong = "f".repeat(64);
        let r = live_with_token(&state, &bearer(&wrong), Some(LIVE_TOKEN));
        assert_eq!(r.err().unwrap().0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn live_without_token_file_matches_fixed_handler() {
        let (_d, state) = live_state().await;
        // No stored token: refused, with the status the /fixed handler gives.
        let r = live_with_token(&state, &bearer(LIVE_TOKEN), None);
        let live_status = r.err().unwrap().0;
        let fixed = post_m2100_fixed(bearer(LIVE_TOKEN)).await.status();
        assert_eq!(live_status, fixed);
        assert_eq!(live_status, StatusCode::UNAUTHORIZED);
        // The real handler, on a box with no token file, agrees.
        if !std::path::Path::new(crate::display::m2100_token::TOKEN_PATH).exists() {
            let r = get_m2100_live(State(state), bearer(LIVE_TOKEN)).await;
            assert_eq!(r.err().unwrap().0, fixed);
        }
    }

    #[tokio::test]
    async fn live_when_idle_is_empty_200() {
        let (_d, state) = live_state().await;
        let r = live_with_token(&state, &bearer(LIVE_TOKEN), Some(LIVE_TOKEN)).unwrap();
        let v = body_json(r).await;
        assert_eq!(v["version"], 1);
        assert!(v["recording"].is_null());
        assert_eq!(v["towers"], serde_json::json!([]));
        assert_eq!(v["identity"], serde_json::json!([]));
        assert_eq!(v["warnings"], serde_json::json!([]));
        assert_eq!(v["towers_capped"], false);
        assert_eq!(v["identity_total"], 0);
        assert_eq!(v["warnings_total"], 0);
        assert_eq!(v["warnings_high_total"], 0);
    }

    #[tokio::test]
    async fn live_returns_snapshot() {
        use rayhunter::analysis::analyzer::{Event, EventType};
        use rayhunter::analysis::observe::Sib1Tower;
        let (_d, state) = live_state().await;
        {
            let mut live = state.live.lock().unwrap();
            live.reset(Some("1700000000".to_string()));
            let sib1 = Sib1Tower {
                plmn: Some("311-480".to_string()),
                tac: 7,
                cell: 99,
            };
            live.observe_parts(None, Some((270, 1811)), Some(sib1), true);
            live.warning(
                None,
                "IMSI Requested",
                &Event {
                    event_type: EventType::High,
                    message: "boom".to_string(),
                },
            );
        }
        let r = live_with_token(&state, &bearer(LIVE_TOKEN), Some(LIVE_TOKEN)).unwrap();
        let v = body_json(r).await;
        assert_eq!(v["recording"], "1700000000");
        assert_eq!(v["towers"][0]["plmn"], "311-480");
        assert_eq!(v["towers"][0]["tac"], 7);
        assert_eq!(v["towers"][0]["cell"], 99);
        assert_eq!(v["towers"][0]["pci"], 270);
        assert_eq!(v["towers"][0]["earfcn"], 1811);
        assert_eq!(v["towers"][0]["hits"], 1);
        assert_eq!(v["identity_total"], 1);
        assert_eq!(v["identity"].as_array().unwrap().len(), 1);
        assert_eq!(v["warnings"][0]["severity"], "high");
        assert_eq!(v["warnings"][0]["analyzer"], "IMSI Requested");
        assert_eq!(v["warnings"][0]["msg"], "boom");
        assert_eq!(v["warnings_total"], 1);
        assert_eq!(v["warnings_high_total"], 1);
    }

    #[tokio::test]
    async fn live_is_not_rate_limited() {
        let (_d, state) = live_state().await;
        for _ in 0..3 {
            assert!(live_with_token(&state, &bearer(LIVE_TOKEN), Some(LIVE_TOKEN)).is_ok());
        }
    }

    #[test]
    fn live_handler_takes_only_the_live_lock_and_no_rate_limit() {
        let server = include_str!("server.rs");
        let start = server.find("fn live_with_token").unwrap();
        let end = server[start..].find("\n}\n").unwrap();
        let body = &server[start..start + end];
        let handler_start = server.find("pub async fn get_m2100_live").unwrap();
        let handler =
            &server[handler_start..handler_start + server[handler_start..].find("\n}\n").unwrap()];
        let body = format!("{handler}{body}");
        assert!(!body.contains("qmdl_store_lock") && !body.contains("RATE_LIMIT"));
    }
}
