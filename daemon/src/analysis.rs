use std::cmp;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use log::{error, info};
use rayhunter::Device;
use rayhunter::DeviceMetadata;
use rayhunter::analysis::analyzer::{AnalyzerConfig, Event, EventType, Harness};
use rayhunter::analysis::information_element::InformationElement;
use rayhunter::analysis::observe::rrc_cell;
use rayhunter::diag::{DiagParsingError, Message, MessagesContainer};
use rayhunter::qmdl::QmdlMessageReader;
use serde::Serialize;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{RwLock, RwLockWriteGuard};
use tokio_util::task::TaskTracker;

use crate::m2100_observe::LiveObservations;
use crate::qmdl_store::{FileKind, RecordingStore};
use crate::server::ServerState;

pub struct AnalysisWriter {
    writer: BufWriter<File>,
    harness: Harness,
    /// Analyzer display names, in the harness's order -- the order of every
    /// row's `events`, which the harness asserts.
    names: Vec<String>,
    /// Analyzer metadata keys (e.g. "imsi_requested"), same order as `names`.
    /// The live endpoint reports these, matching the add-on's decoder.
    keys: Vec<String>,
    /// Collector for the live endpoint. Only the recording path sets this;
    /// re-analysis of a closed recording must never feed it.
    live: Option<Arc<Mutex<LiveObservations>>>,
}

/// One container's worth of observations, gathered without the collector's
/// lock and applied under a single short lock afterwards.
enum Observed {
    Message(
        Option<chrono::DateTime<chrono::Utc>>,
        Option<(u16, u32)>,
        Option<InformationElement>,
    ),
    Warning(Option<chrono::DateTime<chrono::Utc>>, String, Event),
}

/// What one container produced: the worst severity, and the single most severe
/// event with the name of the analyzer that raised it (the first, on a tie).
pub struct ContainerOutcome {
    pub max_type: EventType,
    pub top: Option<(String, Event)>,
}

// We write our analysis results to a file immediately to minimize the amount of
// state Rayhunter has to keep track of in memory. The analysis file's format is
// Newline Delimited JSON
// (https://docs.mulesoft.com/dataweave/latest/dataweave-formats-ndjson), which
// lets us simply append new rows to the end without parsing the entire JSON
// object beforehand.
impl AnalysisWriter {
    pub async fn new(
        file: File,
        analyzer_config: &AnalyzerConfig,
        device_metadata: &DeviceMetadata,
    ) -> Result<Self, std::io::Error> {
        let harness = Harness::new_with_config(analyzer_config, device_metadata);

        let names = harness
            .get_metadata()
            .analyzers
            .iter()
            .map(|a| a.name.to_string())
            .collect();
        let keys = harness
            .get_metadata()
            .analyzers
            .iter()
            .map(|a| a.key.to_string())
            .collect();
        let mut result = Self {
            writer: BufWriter::new(file),
            harness,
            names,
            keys,
            live: None,
        };
        let metadata = result.harness.get_metadata();
        result.write(&metadata).await?;
        Ok(result)
    }

    /// Feed this writer's analysis to the live collector as it goes.
    pub fn with_live(mut self, live: Arc<Mutex<LiveObservations>>) -> Self {
        self.live = Some(live);
        self
    }

    // Runs the analysis harness on the given container, serializing the results
    // to the analysis file, returning the worst severity and the event behind it
    pub async fn analyze_container(
        &mut self,
        container: MessagesContainer,
    ) -> Result<ContainerOutcome, std::io::Error> {
        let mut max_type = EventType::Informational;
        let mut top: Option<(String, Event)> = None;

        let collect = self.live.is_some();
        let mut observed: Vec<Observed> = Vec::new();
        for maybe_message in container.messages() {
            let (ts, cell) = match &maybe_message {
                Ok(msg) => (
                    match msg {
                        Message::Log { timestamp, .. } => {
                            Some(timestamp.to_datetime().with_timezone(&chrono::Utc))
                        }
                        _ => None,
                    },
                    rrc_cell(msg),
                ),
                Err(_) => (None, None),
            };
            let (row, element) = self
                .harness
                .analyze_qmdl_message_with_element(maybe_message);
            if collect {
                observed.push(Observed::Message(ts, cell, element));
                for (i, ev) in row.events.iter().enumerate() {
                    if let Some(e) = ev
                        && e.event_type != EventType::Informational
                    {
                        let name = self
                            .keys
                            .get(i)
                            .cloned()
                            .unwrap_or_else(|| format!("analyzer {i}"));
                        observed.push(Observed::Warning(ts, name, e.clone()));
                    }
                }
            }
            if !row.is_empty() {
                self.write(&row).await?;
            }
            max_type = cmp::max(max_type, row.get_max_event_type());
            if let Some(found) = most_severe(&self.names, &row.events) {
                let better = top
                    .as_ref()
                    .is_none_or(|(_, e)| found.1.event_type > e.event_type);
                if better {
                    top = Some(found);
                }
            }
        }
        if let Some(live) = &self.live {
            // One short lock per container; never held across an await.
            let mut live = live.lock().unwrap_or_else(|e| e.into_inner());
            for o in observed {
                match o {
                    Observed::Message(ts, cell, element) => {
                        live.observe(ts, cell, element.as_ref())
                    }
                    Observed::Warning(ts, name, e) => live.warning(ts, &name, &e),
                }
            }
        }
        Ok(ContainerOutcome { max_type, top })
    }

    pub async fn analyze_message(
        &mut self,
        maybe_qmdl_msg: Result<Message, DiagParsingError>,
    ) -> Result<EventType, std::io::Error> {
        let row = self.harness.analyze_qmdl_message(maybe_qmdl_msg);
        if !row.is_empty() {
            self.write(&row).await?;
        }
        Ok(row.get_max_event_type())
    }

    async fn write<T: Serialize>(&mut self, value: &T) -> Result<(), std::io::Error> {
        let mut value_str = serde_json::to_string(value).unwrap();
        value_str.push('\n');
        self.writer.write_all(value_str.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    // Flushes any pending I/O to disk before dropping the writer
    pub async fn close(mut self) -> Result<(), std::io::Error> {
        self.writer.flush().await?;
        Ok(())
    }
}

/// The most severe non-informational event in one row, named by its analyzer.
/// `events[i]` belongs to `names[i]`; a missing name reads "analyzer i" rather
/// than panicking, because a mislabelled alert beats a lost one.
fn most_severe(names: &[String], events: &[Option<Event>]) -> Option<(String, Event)> {
    let mut best: Option<(String, Event)> = None;
    for (i, ev) in events.iter().enumerate() {
        let Some(e) = ev else { continue };
        if e.event_type == EventType::Informational {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(_, b)| e.event_type > b.event_type)
        {
            let name = names
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("analyzer {i}"));
            best = Some((name, e.clone()));
        }
    }
    best
}

#[cfg(test)]
mod alert_tests {
    use super::*;

    fn ev(t: EventType, m: &str) -> Option<Event> {
        Some(Event {
            event_type: t,
            message: m.into(),
        })
    }

    #[test]
    fn the_most_severe_event_is_named_by_its_own_analyzer() {
        let names = vec!["IMSI Requested".to_string(), "Null Cipher".to_string()];
        let events = vec![
            ev(EventType::Medium, "id request"),
            ev(EventType::High, "null cipher"),
        ];
        let (n, e) = most_severe(&names, &events).unwrap();
        assert_eq!(n, "Null Cipher");
        assert_eq!(e.message, "null cipher");
    }

    #[test]
    fn informational_events_are_not_alerts() {
        let names = vec!["Diagnostic".to_string()];
        assert!(most_severe(&names, &[ev(EventType::Informational, "fyi")]).is_none());
        assert!(most_severe(&names, &[None]).is_none());
    }

    #[test]
    fn a_tie_keeps_the_first_analyzer() {
        let names = vec!["A".to_string(), "B".to_string()];
        let events = vec![ev(EventType::High, "a"), ev(EventType::High, "b")];
        assert_eq!(most_severe(&names, &events).unwrap().0, "A");
    }

    #[test]
    fn a_missing_name_degrades_instead_of_panicking() {
        let events = vec![None, ev(EventType::Low, "x")];
        assert_eq!(most_severe(&[], &events).unwrap().0, "analyzer 1");
    }
}

#[cfg(test)]
pub(crate) mod live_tests {
    use super::*;
    use crate::m2100_observe::LiveObservations;
    use rayhunter::analysis::analyzer::Harness;
    use rayhunter::diag::{CRC_CCITT, HdlcEncapsulatedMessage};
    use rayhunter::hdlc::hdlc_encapsulate;
    use std::sync::Mutex;

    /// Wrap a raw diag log (header + body) in HDLC. The two length fields
    /// both read "total - 4", as in the lib's captured samples.
    fn frame(mut raw: Vec<u8>) -> HdlcEncapsulatedMessage {
        let l = (raw.len() - 4) as u16;
        raw[2..4].copy_from_slice(&l.to_le_bytes());
        raw[4..6].copy_from_slice(&l.to_le_bytes());
        let data = hdlc_encapsulate(&raw, &CRC_CCITT);
        HdlcEncapsulatedMessage {
            len: data.len() as u32,
            data,
        }
    }

    fn header(log_type: u16, ts: u64) -> Vec<u8> {
        let mut v = vec![0x10, 0, 0, 0, 0, 0];
        v.extend(log_type.to_le_bytes());
        v.extend(ts.to_le_bytes());
        v
    }

    pub(crate) fn sib1_frame() -> HdlcEncapsulatedMessage {
        // SIB1 from telcom-parser's lte_rrc_test.
        let hex = "484c469010600018fd1a9207e22103108ac21bdc09802292cdd20000";
        let payload: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut raw = header(0xb0c0, 1 << 16);
        // v26 LTE RRC OTA: ext header version, rel maj/min x2, bearer, PCI 270,
        // EARFCN 1811, sfn, pdu 3 (BCCH-DL-SCH), sib mask, length.
        raw.extend([26, 15, 64, 15, 64, 1]);
        raw.extend(270u16.to_le_bytes());
        raw.extend(1811u32.to_le_bytes());
        raw.extend([0, 0, 3, 0, 0, 0, 0]);
        raw.extend((payload.len() as u16).to_le_bytes());
        raw.extend(payload);
        frame(raw)
    }

    fn identity_frame() -> HdlcEncapsulatedMessage {
        let mut raw = header(0xb0ec, 2 << 16);
        raw.extend([0, 0, 0, 0, 0x07, 0x55, 0x01]);
        frame(raw)
    }

    // Tracking area update reject: puts the IMSI analyzer in its disconnected
    // state, so the identity request that follows is a High event.
    fn tau_reject_frame() -> HdlcEncapsulatedMessage {
        let mut raw = header(0xb0ec, 1 << 16);
        raw.extend([0, 0, 0, 0, 0x07, 0x4b, 0x0b]);
        frame(raw)
    }

    fn container() -> MessagesContainer {
        MessagesContainer {
            data_type: rayhunter::diag::DataType::UserSpace,
            num_messages: 3,
            messages: vec![sib1_frame(), tau_reject_frame(), identity_frame()],
        }
    }

    #[tokio::test]
    async fn analyze_container_feeds_live_and_rows_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let config = AnalyzerConfig::default();
        let meta = DeviceMetadata::default();

        // What the old path writes.
        let mut harness = Harness::new_with_config(&config, &meta);
        let mut expected = serde_json::to_string(&harness.get_metadata()).unwrap() + "\n";
        for row in harness.analyze_qmdl_messages(container()) {
            if !row.is_empty() {
                expected += &(serde_json::to_string(&row).unwrap() + "\n");
            }
        }

        let live = Arc::new(Mutex::new(LiveObservations::default()));
        let path = dir.path().join("a.ndjson");
        let file = File::create(&path).await.unwrap();
        let mut writer = AnalysisWriter::new(file, &config, &meta)
            .await
            .unwrap()
            .with_live(live.clone());
        writer.analyze_container(container()).await.unwrap();
        writer.close().await.unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
        let s = live.lock().unwrap().snapshot();
        assert_eq!(s.towers.len(), 1, "{s:?}");
        assert_eq!((s.towers[0].pci, s.towers[0].earfcn), (270, 1811));
        assert_eq!(s.identity_total, 1);
        assert_eq!(s.warnings_total, 1, "{s:?}");
        assert_eq!(s.warnings.len(), 1, "{s:?}");
        assert_eq!(s.warnings[0].severity, "high");
        assert_eq!(s.warnings[0].analyzer, "imsi_requested");
        let t = &s.towers[0];
        assert_eq!(t.plmn, Some("311-480".to_string()));
        assert_eq!((t.tac, t.cell), (1536, 1637658));
    }

    #[tokio::test]
    async fn analyze_container_without_live_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("b.ndjson")).await.unwrap();
        let mut writer =
            AnalysisWriter::new(file, &AnalyzerConfig::default(), &DeviceMetadata::default())
                .await
                .unwrap();
        writer.analyze_container(container()).await.unwrap();
    }
}

/// The system status relating to QMDL file analysis
#[derive(Debug, Serialize, Clone)]
#[cfg_attr(feature = "apidocs", derive(utoipa::ToSchema))]
pub struct AnalysisStatus {
    /// The vector array of queued files
    queued: Vec<String>,
    /// The file currently being analyzed
    running: Option<String>,
    /// The vector array of finished files
    finished: Vec<String>,
}

impl AnalysisStatus {
    pub fn new(store: &RecordingStore) -> Self {
        let existing_recordings: Vec<String> = store
            .manifest
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        AnalysisStatus {
            queued: Vec::new(),
            running: None,
            finished: existing_recordings,
        }
    }
}

pub enum AnalysisCtrlMessage {
    NewFilesQueued,
    RecordingFinished(String),
    Exit,
}

async fn queued_len(analysis_status_lock: Arc<RwLock<AnalysisStatus>>) -> usize {
    analysis_status_lock.read().await.queued.len()
}

async fn dequeue_to_running(analysis_status_lock: Arc<RwLock<AnalysisStatus>>) -> String {
    let mut analysis_status = analysis_status_lock.write().await;
    let name = analysis_status.queued.remove(0);
    assert!(analysis_status.running.is_none());
    analysis_status.running = Some(name.clone());
    name
}

async fn finish_running_analysis(analysis_status_lock: Arc<RwLock<AnalysisStatus>>) {
    let mut analysis_status = analysis_status_lock.write().await;
    let finished = analysis_status.running.take().unwrap();
    analysis_status.finished.push(finished);
}

async fn perform_analysis(
    name: &str,
    qmdl_store_lock: Arc<RwLock<RecordingStore>>,
    analyzer_config: &AnalyzerConfig,
    device_metadata: &DeviceMetadata,
) -> Result<(), String> {
    info!("Opening QMDL and analysis file for {name}...");
    let (analysis_file, mut qmdl_reader) = {
        let mut qmdl_store = qmdl_store_lock.write().await;
        let (entry_index, _) = qmdl_store
            .entry_for_name(name)
            .ok_or(format!("failed to find QMDL store entry for {name}"))?;
        let analysis_file = qmdl_store
            .clear_and_open_entry_analysis(entry_index)
            .await
            .map_err(|e| format!("{e:?}"))?;
        let qmdl_file = qmdl_store
            .open_file(entry_index, FileKind::Qmdl)
            .await
            .map_err(|e| format!("{e:?}"))?
            .ok_or("QMDL file not found")?;
        let qmdl_reader = QmdlMessageReader::new(qmdl_file)
            .await
            .map_err(|e| format!("{e:?}"))?;

        (analysis_file, qmdl_reader)
    };

    let mut analysis_writer = AnalysisWriter::new(analysis_file, analyzer_config, device_metadata)
        .await
        .map_err(|e| format!("{e:?}"))?;

    info!("Starting analysis for {name}...");
    while let Some(maybe_message) = qmdl_reader
        .get_next_message()
        .await
        .expect("failed to get message")
    {
        let _ = analysis_writer
            .analyze_message(maybe_message)
            .await
            .map_err(|e| format!("{e:?}"))?;
    }

    analysis_writer
        .close()
        .await
        .map_err(|e| format!("{e:?}"))?;
    info!("Analysis for {name} complete!");

    Ok(())
}

pub fn run_analysis_thread(
    task_tracker: &TaskTracker,
    mut analysis_rx: Receiver<AnalysisCtrlMessage>,
    qmdl_store_lock: Arc<RwLock<RecordingStore>>,
    analysis_status_lock: Arc<RwLock<AnalysisStatus>>,
    analyzer_config: AnalyzerConfig,
    device: Device,
    debug_mode: bool,
) {
    task_tracker.spawn(async move {
        loop {
            match analysis_rx.recv().await {
                Some(AnalysisCtrlMessage::NewFilesQueued) => {
                    let count = queued_len(analysis_status_lock.clone()).await;
                    let mut device_metadata = DeviceMetadata::default();
                    if !debug_mode {
                        device_metadata.home_plmn = rayhunter::sim::home_plmn(&device).await;
                    }
                    for _ in 0..count {
                        let name = dequeue_to_running(analysis_status_lock.clone()).await;
                        if let Err(err) = perform_analysis(
                            &name,
                            qmdl_store_lock.clone(),
                            &analyzer_config,
                            &device_metadata,
                        )
                        .await
                        {
                            error!("failed to analyze {name}: {err}");
                        }
                        finish_running_analysis(analysis_status_lock.clone()).await;
                    }
                }
                Some(AnalysisCtrlMessage::RecordingFinished(name)) => {
                    let mut status = analysis_status_lock.write().await;
                    status.finished.push(name);
                }
                Some(AnalysisCtrlMessage::Exit) | None => return,
            }
        }
    });
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    get,
    path = "/api/analysis",
    tag = "Recordings",
    responses(
        (status = StatusCode::OK, description = "Success", body = AnalysisStatus)
    ),
    summary = "Analysis status",
    description = "Show analysis status for all QMDL files."
))]
pub async fn get_analysis_status(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<AnalysisStatus>, (StatusCode, String)> {
    Ok(Json(state.analysis_status_lock.read().await.clone()))
}

fn queue_qmdl(name: &str, analysis_status: &mut RwLockWriteGuard<AnalysisStatus>) -> bool {
    if analysis_status.queued.iter().any(|n| n == name)
        || analysis_status.running.iter().any(|n| n == name)
    {
        return false;
    }
    analysis_status.queued.push(name.to_string());
    true
}

#[cfg_attr(feature = "apidocs", utoipa::path(
    post,
    path = "/api/analysis/{name}",
    tag = "Recordings",
    responses(
        (status = StatusCode::ACCEPTED, description = "Success"),
        (status = StatusCode::INTERNAL_SERVER_ERROR, description = "Unable to queue analysis file")
    ),
    params(
        ("name" = String, Path, description = "QMDL file to analyze")
    ),
    summary = "Start analysis",
    description = "Begin analysis of QMDL file {name}."
))]
pub async fn start_analysis(
    State(state): State<Arc<ServerState>>,
    Path(qmdl_name): Path<String>,
) -> Result<(StatusCode, Json<AnalysisStatus>), (StatusCode, String)> {
    let mut analysis_status = state.analysis_status_lock.write().await;
    let store = state.qmdl_store_lock.read().await;
    let queued = if qmdl_name.is_empty() {
        let mut entry_names: Vec<&str> = store
            .manifest
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        if let Some(current_entry) = store.current_entry {
            entry_names.remove(current_entry);
        }
        entry_names
            .iter()
            .any(|name| queue_qmdl(name, &mut analysis_status))
    } else {
        queue_qmdl(&qmdl_name, &mut analysis_status)
    };
    if queued {
        state
            .analysis_sender
            .send(AnalysisCtrlMessage::NewFilesQueued)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to queue new analysis files: {e:?}"),
                )
            })?;
    }
    Ok((StatusCode::ACCEPTED, Json(analysis_status.clone())))
}
