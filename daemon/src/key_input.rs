use log::{error, info};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{self, KeyInputMode};
use crate::diag::DiagDeviceCtrlMessage;

#[derive(Debug)]
enum Event {
    KeyDown,
    KeyUp,
}

const INPUT_EVENT_SIZE: usize = 32;
const INPUT_DEVICE: &str = "/dev/input/event0";

/// Opens an input device for non-blocking reads through the runtime's reactor.
///
/// Not `tokio::fs::File`: that runs each read on a blocking-pool thread, and a
/// read parked on an idle button is never interrupted. Cancelling the task left
/// the thread in `evdev_read`, and dropping the runtime waited for it, so the
/// process outlived "see you space cowboy" until someone pressed power (chp
/// #7933, RC400L, once SIGTERM started shutting down gracefully).
fn open_input(path: &Path) -> io::Result<AsyncFd<File>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    AsyncFd::new(file)
}

/// Fills `buf` from `fd`. Waiting for readiness is cancel-safe: dropping this
/// future leaves no thread behind.
async fn read_input(fd: &AsyncFd<File>, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let mut ready = fd.readable().await?;
        match ready.try_io(|inner| {
            let mut file: &File = inner.get_ref();
            file.read(&mut buf[filled..])
        }) {
            Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(Ok(n)) => filled += n,
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

pub fn run_key_input_thread(
    task_tracker: &TaskTracker,
    config: &config::Config,
    diag_tx: Sender<DiagDeviceCtrlMessage>,
    cancellation_token: CancellationToken,
) {
    if config.key_input_mode == KeyInputMode::Disabled {
        return;
    }
    spawn_key_reader(
        task_tracker,
        PathBuf::from(INPUT_DEVICE),
        diag_tx,
        cancellation_token,
    );
}

fn spawn_key_reader(
    task_tracker: &TaskTracker,
    path: PathBuf,
    diag_tx: Sender<DiagDeviceCtrlMessage>,
    cancellation_token: CancellationToken,
) {
    task_tracker.spawn(async move {
        let file = match open_input(&path) {
            Ok(file) => file,
            Err(e) => {
                error!("Failed to open {}: {e}", path.display());
                return;
            }
        };

        let mut buffer = [0u8; INPUT_EVENT_SIZE];
        let mut last_keyup: Option<Instant> = None;
        let mut last_event_time: Option<Instant> = None;

        loop {
            tokio::select! {
               _ = cancellation_token.cancelled() => {
                    info!("received key input shutdown");
                    return;
                }
                result = read_input(&file, &mut buffer) => {
                    if let Err(e) = result {
                        error!("failed to read key input: {e}");
                        return;
                    }
                }
            }

            let event = parse_event(buffer);

            let now = Instant::now();

            // On orbic it was observed that pressing the power button can trigger many successive
            // events. Drop events that are too close together.
            if let Some(last_time) = last_event_time
                && now.duration_since(last_time) < Duration::from_millis(50)
            {
                last_event_time = Some(now);
                continue;
            }
            last_event_time = Some(now);

            match event {
                Event::KeyUp => {
                    if let Some(last_keyup_instant) = last_keyup {
                        let elapsed = now.duration_since(last_keyup_instant);

                        if elapsed >= Duration::from_millis(100)
                            && elapsed <= Duration::from_millis(800)
                        {
                            if let Err(e) = diag_tx.send(DiagDeviceCtrlMessage::StopRecording).await
                            {
                                error!("Failed to send StopRecording: {e}");
                            }
                            if let Err(e) = diag_tx
                                .send(DiagDeviceCtrlMessage::StartRecording { response_tx: None })
                                .await
                            {
                                error!("Failed to send StartRecording: {e}");
                            }
                            last_keyup = None;
                            continue;
                        }
                    }

                    last_keyup = Some(now);
                }
                Event::KeyDown => {}
            }
        }
    });
}

fn parse_event(input: [u8; INPUT_EVENT_SIZE]) -> Event {
    if input[12] == 0 {
        Event::KeyUp
    } else {
        Event::KeyDown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use tokio::sync::mpsc;

    /// A FIFO stands in for /dev/input/event0: a read on it waits for data.
    /// Returns the path and a read-write handle that keeps it open and writable.
    fn fifo(dir: &tempfile::TempDir) -> (PathBuf, File) {
        let path = dir.path().join("event0");
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let peer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (path, peer)
    }

    /// One 32-bit key event plus its SYN, the 32 bytes the reader takes at a time.
    fn key(value: u8) -> [u8; INPUT_EVENT_SIZE] {
        let mut e = [0u8; INPUT_EVENT_SIZE];
        e[8] = 1; // EV_KEY
        e[10] = 116; // KEY_POWER
        e[12] = value;
        e
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// chp #7933: after cancel, the runtime must drop at once. With
    /// tokio::fs::File the read sat on a blocking-pool thread and the drop
    /// waited for a key press that never came.
    #[test]
    fn cancel_leaves_no_parked_read_behind() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _peer) = fifo(&dir);
        let rt = runtime();
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let (tx, _rx) = mpsc::channel(4);
        rt.block_on(async {
            spawn_key_reader(&tracker, path, tx, token.clone());
            tokio::time::sleep(Duration::from_millis(100)).await;
            token.cancel();
            tracker.close();
            tokio::time::timeout(Duration::from_secs(2), tracker.wait())
                .await
                .expect("reader task ended on cancel");
        });
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(rt);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("runtime dropped promptly: no thread left in a blocking read");
    }

    /// The non-blocking path still delivers keys: two key-ups 300 ms apart are
    /// the double tap that starts a new recording.
    #[test]
    fn a_double_tap_read_through_the_reactor_starts_a_new_recording() {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut peer) = fifo(&dir);
        let rt = runtime();
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let (tx, mut rx) = mpsc::channel(4);
        rt.block_on(async {
            spawn_key_reader(&tracker, path, tx, token.clone());
            tokio::time::sleep(Duration::from_millis(100)).await;
            peer.write_all(&key(0)).unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            peer.write_all(&key(0)).unwrap();
            let first = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
            let second = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
            assert!(matches!(
                first,
                Ok(Some(DiagDeviceCtrlMessage::StopRecording))
            ));
            assert!(matches!(
                second,
                Ok(Some(DiagDeviceCtrlMessage::StartRecording { .. }))
            ));
            token.cancel();
        });
        // Bounded, so a regression to a parked read fails the test above by
        // name instead of hanging this one in an implicit drop.
        rt.shutdown_timeout(Duration::from_secs(1));
    }

    #[test]
    fn test_parse_event_keydown_m7350_v5() {
        let input = [
            0x57, 0x6c, 0x09, 0x00, 0x7c, 0xfb, 0x03, 0x00, 0x01, 0x00, 0x74, 0x00, 0x01, 0x00,
            0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(parse_event(input), Event::KeyDown));
    }

    #[test]
    fn test_parse_event_keyup_m7350_v5() {
        let input = [
            0x57, 0x6c, 0x09, 0x00, 0x1b, 0x15, 0x05, 0x00, 0x01, 0x00, 0x74, 0x00, 0x00, 0x00,
            0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(parse_event(input), Event::KeyUp));
    }
}
