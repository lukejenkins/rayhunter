use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use log::{error, info, warn};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::GpsMode;
use crate::diag::DiagDeviceCtrlMessage;
use crate::server::ServerState;

fn deserialize_latitude<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;
    let v = f64::deserialize(deserializer)?;
    if !(-90.0..=90.0).contains(&v) {
        return Err(de::Error::custom(format!(
            "latitude {v} out of range [-90, 90]"
        )));
    }
    Ok(v)
}

fn deserialize_longitude<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;
    let v = f64::deserialize(deserializer)?;
    if !(-180.0..=180.0).contains(&v) {
        return Err(de::Error::custom(format!(
            "longitude {v} out of range [-180, 180]"
        )));
    }
    Ok(v)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct GpsData {
    #[serde(deserialize_with = "deserialize_latitude")]
    pub latitude: f64,
    #[serde(deserialize_with = "deserialize_longitude")]
    pub longitude: f64,
}

#[derive(Serialize, Deserialize)]
pub struct GpsRecord {
    /// Packet timestamp (modem clock) for correlation with captured packets.
    /// None if no packets have been received yet.
    pub latest_packet_timestamp: Option<i64>,
    /// Drift-corrected system time when this GPS fix was received
    pub system_time: i64,
    pub lat: f64,
    pub lon: f64,
}

/// Reads all GPS records from a storage NDJSON file, logging and skipping malformed lines.
pub async fn load_gps_records(file: tokio::fs::File) -> Vec<GpsRecord> {
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut records = Vec::new();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => match serde_json::from_str::<GpsRecord>(&line) {
                Ok(record) => records.push(record),
                Err(e) => warn!("skipping malformed GPS storage line: {e}"),
            },
            Ok(None) => break,
            Err(e) => {
                error!("error reading GPS storage file: {e}");
                break;
            }
        }
    }
    records.sort_by_key(|r| r.latest_packet_timestamp.unwrap_or(i64::MIN));
    records
}

/// Submit GPS coordinates
#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/gps",
    tag = "Configuration",
    request_body = GpsData,
    responses(
        (status = StatusCode::OK, description = "GPS data accepted"),
        (status = StatusCode::FORBIDDEN, description = "GPS API endpoint is disabled"),
        (status = StatusCode::INTERNAL_SERVER_ERROR, description = "Failed to send GPS update")
    ),
    summary = "Submit GPS coordinates",
    description = "Submit GPS coordinates from an external source (e.g. a phone app). Requires gps_mode to be set to 'Api' in configuration. latitude is in decimal degrees from -90 to 90, longitude is in decimal degrees from -180 to 180. The timestamp is derived from the most recent packet's modem timestamp."
))]
pub async fn post_gps(
    State(state): State<Arc<ServerState>>,
    Json(gps_data): Json<GpsData>,
) -> Result<StatusCode, (StatusCode, String)> {
    if state.config.gps_mode != GpsMode::Api {
        return Err((
            StatusCode::FORBIDDEN,
            "GPS API endpoint is disabled. Set gps_mode to API endpoint in configuration."
                .to_string(),
        ));
    }

    // Update in-memory state for GET /api/gps
    let mut gps = state.gps_state.write().await;
    *gps = Some(gps_data.clone());
    drop(gps);

    // Send to DiagTask to write to storage with packet timestamp
    state
        .diag_device_ctrl_sender
        .send(DiagDeviceCtrlMessage::GpsUpdate {
            lat: gps_data.latitude,
            lon: gps_data.longitude,
        })
        .await
        .map_err(|e| {
            error!("failed to send GPS update: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to send GPS update: {e}"),
            )
        })?;

    Ok(StatusCode::OK)
}

/// Get the current GPS coordinates
#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/gps",
    tag = "Configuration",
    responses(
        (status = StatusCode::OK, description = "Current GPS data", body = GpsData),
        (status = StatusCode::NOT_FOUND, description = "No GPS data available")
    ),
    summary = "Get current GPS coordinates",
    description = "Returns the most recently submitted GPS coordinates. Returns 404 if no coordinates have been submitted yet this session."
))]
pub async fn get_gps(State(state): State<Arc<ServerState>>) -> Result<Json<GpsData>, StatusCode> {
    let gps = state.gps_state.read().await;
    match gps.as_ref() {
        Some(data) => Ok(Json(data.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Converts an NMEA `ddmm.mmmm` / `dddmm.mmmm` value and its hemisphere letter
/// to signed decimal degrees.
fn nmea_degrees(value: &str, hemisphere: &str, degree_digits: usize) -> Option<f64> {
    let degrees: f64 = value.get(..degree_digits)?.parse().ok()?;
    let minutes: f64 = value.get(degree_digits..)?.parse().ok()?;
    if !(0.0..60.0).contains(&minutes) {
        return None;
    }
    let value = degrees + minutes / 60.0;
    match hemisphere {
        "N" | "E" => Some(value),
        "S" | "W" => Some(-value),
        _ => None,
    }
}

/// Reads a position from one NMEA 0183 sentence.
///
/// Only GGA with a non-zero fix quality and RMC with status `A` carry a
/// position. Every other sentence, a sentence without a fix, and a sentence
/// with a missing or wrong checksum return `None`.
pub fn parse_nmea_position(sentence: &str) -> Option<GpsData> {
    let body = sentence.trim().strip_prefix('$')?;
    let (body, checksum) = body.split_once('*')?;
    let expected = u8::from_str_radix(checksum.get(..2)?, 16).ok()?;
    if body.bytes().fold(0, |acc, b| acc ^ b) != expected {
        return None;
    }
    let fields: Vec<&str> = body.split(',').collect();
    // The first two characters are the talker (GP, GN, GL, ...).
    let (lat, lat_hemisphere, lon, lon_hemisphere) = match fields.first()?.get(2..)? {
        "GGA" => {
            let quality: u8 = fields.get(6)?.parse().ok()?;
            if quality == 0 {
                return None;
            }
            (
                fields.get(2)?,
                fields.get(3)?,
                fields.get(4)?,
                fields.get(5)?,
            )
        }
        "RMC" => {
            if *fields.get(2)? != "A" {
                return None;
            }
            (
                fields.get(3)?,
                fields.get(4)?,
                fields.get(5)?,
                fields.get(6)?,
            )
        }
        _ => return None,
    };
    let latitude = nmea_degrees(lat, lat_hemisphere, 2)?;
    let longitude = nmea_degrees(lon, lon_hemisphere, 3)?;
    if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
        return None;
    }
    Some(GpsData {
        latitude,
        longitude,
    })
}

/// Listens for NMEA sentences on a UDP port and records the positions they
/// carry, at most once per `interval`. A datagram may hold one sentence or
/// several, separated by line breaks.
pub fn run_nmea_gps_listener(
    task_tracker: &TaskTracker,
    address: String,
    port: u16,
    interval: Duration,
    diag_device_sender: Sender<DiagDeviceCtrlMessage>,
    gps_state: Arc<RwLock<Option<GpsData>>>,
    shutdown_token: CancellationToken,
) {
    task_tracker.spawn(async move {
        let socket = match UdpSocket::bind((address.as_str(), port)).await {
            Ok(socket) => socket,
            Err(e) => {
                error!("failed to bind NMEA UDP {address}:{port}: {e}");
                return;
            }
        };
        info!("Listening for NMEA sentences on UDP {address}:{port}");
        let mut last_recorded: Option<Instant> = None;
        let mut buf = [0u8; 2048];
        loop {
            let len = select! {
                _ = shutdown_token.cancelled() => break,
                received = socket.recv_from(&mut buf) => match received {
                    Ok((len, _)) => len,
                    Err(e) => {
                        warn!("error receiving NMEA datagram: {e}");
                        continue;
                    }
                },
            };
            let Ok(datagram) = std::str::from_utf8(&buf[..len]) else {
                continue;
            };
            let Some(position) = datagram.lines().rev().find_map(parse_nmea_position) else {
                continue;
            };
            if last_recorded.is_some_and(|t| t.elapsed() < interval) {
                continue;
            }
            last_recorded = Some(Instant::now());
            *gps_state.write().await = Some(position.clone());
            let update = DiagDeviceCtrlMessage::GpsUpdate {
                lat: position.latitude,
                lon: position.longitude,
            };
            if diag_device_sender.send(update).await.is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gga_with_a_fix_gives_a_position() {
        let p = parse_nmea_position(
            "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n",
        )
        .unwrap();
        assert!((p.latitude - 48.1173).abs() < 1e-6);
        assert!((p.longitude - 11.516_666_6).abs() < 1e-6);
    }

    #[test]
    fn rmc_with_status_a_gives_a_position_in_the_southern_and_western_hemispheres() {
        let p = parse_nmea_position("$GNRMC,123519,A,3352.128,S,15112.558,W,0.0,0.0,190126,,,A*63")
            .unwrap();
        assert!((p.latitude + 33.8688).abs() < 1e-6);
        assert!((p.longitude + 151.209_3).abs() < 1e-6);
    }

    #[test]
    fn sentences_without_a_fix_are_ignored() {
        assert!(parse_nmea_position("$GPGGA,123519,,,,,0,00,,,M,,M,,*6B").is_none());
        assert!(parse_nmea_position("$GNRMC,123519,V,,,,,,,190126,,,N*4D").is_none());
    }

    #[test]
    fn a_bad_checksum_is_ignored() {
        assert!(
            parse_nmea_position(
                "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*48"
            )
            .is_none()
        );
    }

    #[test]
    fn a_missing_checksum_is_ignored() {
        assert!(
            parse_nmea_position("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,")
                .is_none()
        );
    }

    #[test]
    fn sentences_without_a_position_are_ignored() {
        assert!(parse_nmea_position("$GPGSV,3,1,11,03,03,111,00,04,15,270,00*7F").is_none());
        assert!(parse_nmea_position("$PQWP1,0,0*37").is_none());
        assert!(parse_nmea_position("not nmea").is_none());
    }
}
