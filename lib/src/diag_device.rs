use crate::diag::{
    CRC_CCITT, DataType, DiagParsingError, LogConfigRequest, LogConfigResponse, Message,
    MessagesContainer, Request, RequestContainer, ResponsePayload, build_log_mask_request,
};
use crate::hdlc::hdlc_encapsulate;
use crate::{Device, log_codes};

use deku::prelude::*;
use futures::TryStream;
use log::{debug, error, info};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::time::Duration;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

pub type DiagResult<T> = Result<T, DiagDeviceError>;

#[derive(Error, Debug)]
pub enum DiagDeviceError {
    #[error("Failed to initialize /dev/diag: {0}")]
    InitializationFailed(String),
    #[error("Failed to read diag device: {0}")]
    DeviceReadFailed(std::io::Error),
    #[error("Failed to write diag device: {0}")]
    DeviceWriteFailed(std::io::Error),
    #[error("Nonzero status code {0} for diag request: {1:?}")]
    RequestFailed(u32, Request),
    #[error("Didn't receive response for request: {0:?}")]
    NoResponse(Request),
    #[error("Failed to open QMDL file: {0}")]
    OpenQmdlFileError(std::io::Error),
    #[error("Failed to write to QMDL file: {0}")]
    QmdlFileWriteError(std::io::Error),
    #[error("Failed to open diag device: {0}")]
    OpenDiagDeviceError(std::io::Error),
    #[error("Failed to parse MessagesContainer: {0}")]
    ParseMessagesContainerError(deku::DekuError),
}

pub const LOG_CODES_FOR_RAW_PACKET_LOGGING: [u32; 17] = [
    // Layer 2:
    log_codes::LOG_GPRS_MAC_SIGNALLING_MESSAGE_C,
    // Layer 3:
    log_codes::LOG_GSM_RR_SIGNALING_MESSAGE_C,
    log_codes::WCDMA_SIGNALLING_MESSAGE,
    log_codes::LOG_LTE_RRC_OTA_MSG_LOG_C,
    log_codes::LOG_NR_RRC_OTA_MSG_LOG_C,
    // NAS:
    log_codes::LOG_UMTS_NAS_OTA_MESSAGE_LOG_PACKET_C,
    log_codes::LOG_LTE_NAS_ESM_OTA_IN_MSG_LOG_C,
    log_codes::LOG_LTE_NAS_ESM_OTA_OUT_MSG_LOG_C,
    log_codes::LOG_LTE_NAS_EMM_OTA_IN_MSG_LOG_C,
    log_codes::LOG_LTE_NAS_EMM_OTA_OUT_MSG_LOG_C,
    // User IP traffic:
    log_codes::LOG_DATA_PROTOCOL_LOGGING_C,
    // LTE physical layer serving cell measurements: RSRP, RSRQ, RSSI
    log_codes::LOG_LTE_ML1_SERVING_CELL_MEAS_AND_EVAL_C,
    log_codes::LOG_LTE_ML1_NEIGHBOR_MEAS,
    // LTE MAC Random Access Channel response: contains Timing Advance
    log_codes::LOG_LTE_MAC_RACH_RESPONSE_C,
    log_codes::LOG_LTE_MAC_DL,
    log_codes::LOG_LTE_MAC_UL,
    0xb114, // maybe timing advance related?
];

const BUFFER_LEN: usize = 1024 * 1024 * 10;
const MEMORY_DEVICE_MODE: u32 = 2;

#[cfg(target_env = "musl")]
const DIAG_IOCTL_REMOTE_DEV: i32 = 32;
#[cfg(all(not(target_env = "musl"), target_arch = "arm"))]
const DIAG_IOCTL_REMOTE_DEV: u32 = 32;
#[cfg(all(not(target_env = "musl"), target_arch = "x86_64"))]
const DIAG_IOCTL_REMOTE_DEV: u64 = 32;
#[cfg(all(not(target_env = "musl"), target_arch = "aarch64"))]
const DIAG_IOCTL_REMOTE_DEV: u64 = 32;

#[cfg(target_env = "musl")]
const DIAG_IOCTL_SWITCH_LOGGING: i32 = 7;
#[cfg(all(not(target_env = "musl"), target_arch = "arm"))]
const DIAG_IOCTL_SWITCH_LOGGING: u32 = 7;
#[cfg(all(not(target_env = "musl"), target_arch = "x86_64"))]
const DIAG_IOCTL_SWITCH_LOGGING: u64 = 7;
#[cfg(all(not(target_env = "musl"), target_arch = "aarch64"))]
const DIAG_IOCTL_SWITCH_LOGGING: u64 = 7;

pub struct DiagDevice {
    file: File,
    read_buf: Vec<u8>,
    use_mdm: i32,
}

impl DiagDevice {
    pub async fn new(configured_device: &Device) -> DiagResult<Self> {
        Self::new_with_retries(Duration::from_secs(30), configured_device).await
    }

    pub async fn new_with_retries(
        max_duration: Duration,
        configured_device: &Device,
    ) -> DiagResult<Self> {
        // For some reason the diag device needs a very long time to become available again with in
        // the same process, on TP-Link M7350 v3. While process restart would reset it faster.

        let start_time = std::time::Instant::now();
        let max_delay = Duration::from_secs(5);

        let mut delay = Duration::from_millis(100);
        let mut num_retries = 0;

        loop {
            match Self::try_new(configured_device).await {
                Ok(device) => {
                    info!("Diag device initialization succeeded after {num_retries} retries");
                    return Ok(device);
                }
                Err(e) => {
                    num_retries += 1;
                    if start_time.elapsed() >= max_duration {
                        error!("Failed to initialize diag device after {max_duration:?}: {e}");
                        return Err(e);
                    }

                    info!(
                        "Diag device initialization failed {num_retries} times, retrying in {delay:?}: {e}"
                    );
                    sleep(delay).await;

                    // Exponential backoff
                    delay = std::cmp::min(delay * 2, max_delay);
                }
            }
        }
    }

    async fn try_new(configured_device: &Device) -> DiagResult<Self> {
        let diag_file = File::options()
            .read(true)
            .write(true)
            .open("/dev/diag")
            .await
            .map_err(DiagDeviceError::OpenDiagDeviceError)?;
        let fd = diag_file.as_raw_fd();

        enable_frame_readwrite(fd, MEMORY_DEVICE_MODE, configured_device)?;
        let use_mdm = determine_use_mdm(fd)?;

        Ok(DiagDevice {
            read_buf: vec![0; BUFFER_LEN],
            file: diag_file,
            use_mdm,
        })
    }

    pub fn as_stream(
        &mut self,
    ) -> impl TryStream<Ok = MessagesContainer, Error = DiagDeviceError> + '_ {
        futures::stream::try_unfold(self, |dev| async {
            let container = dev.get_next_messages_container().await?;
            Ok(Some((container, dev)))
        })
    }

    async fn get_next_messages_container(&mut self) -> Result<MessagesContainer, DiagDeviceError> {
        let mut bytes_read = 0;
        // TP-Link M7350 sometimes sends too small messages, we need to be able to deal with short reads.
        while bytes_read <= 8 {
            bytes_read = self
                .file
                .read(&mut self.read_buf)
                .await
                .map_err(DiagDeviceError::DeviceReadFailed)?;
        }

        debug!(
            "Parsing messages container size = {:?} [{:?}]",
            bytes_read,
            &self.read_buf[0..bytes_read]
        );

        match MessagesContainer::from_bytes((&self.read_buf[0..bytes_read], 0)) {
            Ok((_, container)) => Ok(container),
            Err(err) => Err(DiagDeviceError::ParseMessagesContainerError(err)),
        }
    }

    async fn write_request(&mut self, req: &Request) -> DiagResult<()> {
        let req_bytes = &req.to_bytes().expect("Failed to serialize Request");
        let buf = RequestContainer {
            data_type: DataType::UserSpace,
            use_mdm: self.use_mdm > 0,
            mdm_field: -1,
            hdlc_encapsulated_request: hdlc_encapsulate(req_bytes, &CRC_CCITT),
        }
        .to_bytes()
        .expect("Failed to serialize RequestContainer");
        if let Err(err) = self.file.write(&buf).await {
            // For reasons I don't entirely understand, calls to write(2) on
            // /dev/diag always return 0 bytes written, though the written
            // requests end up being interpreted. As such, we're not concerned
            // about WriteZero errors
            if err.kind() != ErrorKind::WriteZero {
                return Err(DiagDeviceError::DeviceWriteFailed(err));
            }
        }
        if let Err(err) = self.file.flush().await
            && err.kind() != ErrorKind::WriteZero
        {
            return Err(DiagDeviceError::DeviceWriteFailed(err));
        }
        Ok(())
    }

    async fn read_response(&mut self) -> DiagResult<Vec<Result<Message, DiagParsingError>>> {
        loop {
            let container = self.get_next_messages_container().await?;
            if container.data_type != DataType::UserSpace {
                continue;
            }
            return Ok(container.messages());
        }
    }

    /// Sends `req` and reads until `pick` recognises its reply. The reply is not always in the
    /// first batch read back: other diag clients (vendor daemons on Android, the modem stack on
    /// the M2100) share the device, so their traffic can come first. Reads are bounded by a
    /// timeout and the request is re-sent a few times before giving up.
    async fn request_reply<T>(
        &mut self,
        req: Request,
        pick: impl Fn(u32, ResponsePayload) -> Option<T>,
    ) -> DiagResult<T> {
        const ATTEMPTS: u32 = 5;
        const WAIT: Duration = Duration::from_secs(3);
        for attempt in 1..=ATTEMPTS {
            self.write_request(&req).await?;
            let deadline = tokio::time::Instant::now() + WAIT;
            let mut batches = 0u32;
            loop {
                let msgs = match tokio::time::timeout_at(deadline, self.read_response()).await {
                    Ok(msgs) => msgs?,
                    Err(_) => break,
                };
                batches += 1;
                for msg in msgs {
                    match msg {
                        Ok(Message::Log { .. }) => debug!("skipping log message while waiting for reply"),
                        Ok(Message::Response { payload, status, .. }) => {
                            if let Some(found) = pick(status, payload) {
                                if attempt > 1 || batches > 1 {
                                    info!("diag reply arrived on attempt {attempt}, batch {batches}");
                                }
                                return Ok(found);
                            }
                            debug!("skipping unrelated response while waiting for reply");
                        }
                        Err(e) => error!("error parsing message: {e:?}"),
                    }
                }
            }
            info!("no diag reply after {batches} batches (attempt {attempt}/{ATTEMPTS}), re-sending");
        }
        Err(DiagDeviceError::NoResponse(req))
    }

    async fn retrieve_id_ranges(&mut self) -> DiagResult<[u32; 16]> {
        let req = Request::LogConfig(LogConfigRequest::RetrieveIdRanges);
        let (status, sizes) = self
            .request_reply(req.clone(), |status, payload| match payload {
                ResponsePayload::LogConfig(LogConfigResponse::RetrieveIdRanges { log_mask_sizes }) => {
                    Some((status, log_mask_sizes))
                }
                _ => None,
            })
            .await?;
        if status != 0 {
            return Err(DiagDeviceError::RequestFailed(status, req));
        }
        Ok(sizes)
    }

    async fn set_log_mask(&mut self, log_type: u32, log_mask_bitsize: u32) -> DiagResult<()> {
        let req = build_log_mask_request(
            log_type,
            log_mask_bitsize,
            &LOG_CODES_FOR_RAW_PACKET_LOGGING,
        );
        let status = self
            .request_reply(req.clone(), |status, payload| match payload {
                ResponsePayload::LogConfig(LogConfigResponse::SetMask) => Some(status),
                _ => None,
            })
            .await?;
        if status != 0 {
            return Err(DiagDeviceError::RequestFailed(status, req));
        }
        Ok(())
    }

    pub async fn config_logs(&mut self) -> DiagResult<()> {
        info!("retrieving diag logging capabilities...");
        let log_mask_sizes = self.retrieve_id_ranges().await?;

        for (log_type, &log_mask_bitsize) in log_mask_sizes.iter().enumerate() {
            if log_mask_bitsize > 0 {
                self.set_log_mask(log_type as u32, log_mask_bitsize).await?;
                info!("enabled logging for log type {log_type}");
            }
        }

        Ok(())
    }
}

// also found in: https://android.googlesource.com/kernel/msm.git/+/android-7.1.0_r0.3/drivers/char/diag/diagchar.h#399
//
// the code on
// https://github.com/P1sec/QCSuper/blob/master/docs/The%20Diag%20protocol.md#the-diag-protocol-over-devdiag
// is misleading, mode_param is only 8 bits. sending the larger [u32; 3] payload will cause the
// IOCTL to be rejected by TPLINK M7350 HW rev 5
//
// TPLINK M7350 v5 source code can be downloaded at https://www.tp-link.com/de/support/gpl-code/?app=omada
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DiagLoggingModeParam {
    req_mode: u32,
    peripheral_mask: u32,
    mode_param: u8,
}

// msm-4.x extended layout (SDX55 / kernel 4.14 and later). The ioctl carries no
// length: the driver always copies its own sizeof (24 bytes on mainline
// msm-4.14) from the pointer. A shorter struct is "rejected" only because of
// what the driver reads past its end; see `padded()`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DiagLoggingModeParamV2 {
    req_mode: u32,
    peripheral_mask: u32,
    pd_mask: u32,
    mode_param: u8,
    diag_id: u8,
    pd_val: u8,
    reserved: u8,
    peripheral: i32,
}

// Same, plus the `device_mask` field present in some vendor trees.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct DiagLoggingModeParamV3 {
    req_mode: u32,
    peripheral_mask: u32,
    pd_mask: u32,
    mode_param: u8,
    diag_id: u8,
    pd_val: u8,
    reserved: u8,
    peripheral: i32,
    device_mask: i32,
}

// Every layout is passed inside a zeroed buffer at least as large as the
// largest one. The driver reads its full struct size whatever we meant to send,
// so an unpadded short struct hands it the stack bytes behind it. On a Pixel 4
// (msm-4.14) junk landing in `pd_mask` made the 12-byte attempt fail with
// EINVAL *and* left driver state behind: the 24-byte attempt that followed
// returned 0 but created no memory-device session, so every later write was
// refused ("request came from invalid md session pid"). Whether it broke
// depended on what was on the stack, which is why it looked like boot timing.
fn padded<T: Copy>(p: &T) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let n = std::mem::size_of::<T>();
    assert!(n <= buf.len());
    // SAFETY: T is plain-old-data (repr(C) param structs) and n fits in buf.
    unsafe { std::ptr::copy_nonoverlapping(p as *const T as *const u8, buf.as_mut_ptr(), n) };
    buf
}

// Triggers the diag device's debug logging mode.
//
// Kernels differ in what this ioctl accepts. Older ones take the mode as a bare
// int; msm-4.x takes a pointer to a struct of its own size and rejects one whose
// fields it cannot accept (a zeroed `device_mask` is -EINVAL there, for
// example). Every attempt is zero-padded (`padded()`). Rather than guess, walk a ladder of
// known shapes and log what each one returns, so a total failure still yields a
// usable bug report.
fn enable_frame_readwrite(fd: i32, mode: u32, configured_device: &Device) -> DiagResult<()> {
    // DIAG_CON_ALL on most trees is the OR of the per-peripheral bits; u32::MAX
    // is what rayhunter historically sent and some drivers reject it.
    const MASKS: [(u32, &str); 3] = [
        (u32::MAX, "u32::MAX"),
        (0x0000_00ff, "0xff (DIAG_CON_ALL, 8 peripherals)"),
        (0x0000_007f, "0x7f (DIAG_CON_ALL, 7 peripherals)"),
    ];

    unsafe {
        // 1. legacy int form
        let r = libc::ioctl(fd, DIAG_IOCTL_SWITCH_LOGGING, mode, 0, 0, 0);
        log::info!(
            "diag probe: int form           -> ret={r} errno={:?}",
            std::io::Error::last_os_error()
        );
        if r == 0 {
            return Ok(());
        }

        // 2. tplink-specific 12-byte variant, tried first on that hardware
        if configured_device == &Device::Tplink {
            let mut p = DiagLoggingModeParam { req_mode: mode, peripheral_mask: 0, mode_param: 1 };
            let r = libc::ioctl(
                fd, DIAG_IOCTL_SWITCH_LOGGING,
                padded(&p).as_mut_ptr(),
                std::mem::size_of::<DiagLoggingModeParam>(), 0, 0, 0, 0,
            );
            log::info!("diag probe: v1 tplink (12B)    -> ret={r} errno={:?}",
                std::io::Error::last_os_error());
            if r == 0 { return Ok(()); }
        }

        for (mask, label) in MASKS {
            // 12-byte original
            let mut p1 = DiagLoggingModeParam { req_mode: mode, peripheral_mask: mask, mode_param: 0 };
            let r = libc::ioctl(
                fd, DIAG_IOCTL_SWITCH_LOGGING,
                padded(&p1).as_mut_ptr(),
                std::mem::size_of::<DiagLoggingModeParam>(), 0, 0, 0, 0,
            );
            log::info!("diag probe: v1 ({:>2}B) mask={label} -> ret={r} errno={:?}",
                std::mem::size_of::<DiagLoggingModeParam>(), std::io::Error::last_os_error());
            if r == 0 { return Ok(()); }

            // 20-byte msm-4.x
            let mut p2 = DiagLoggingModeParamV2 {
                req_mode: mode, peripheral_mask: mask, pd_mask: 0,
                mode_param: 0, diag_id: 0, pd_val: 0, reserved: 0, peripheral: 0,
            };
            let r = libc::ioctl(
                fd, DIAG_IOCTL_SWITCH_LOGGING,
                padded(&p2).as_mut_ptr(),
                std::mem::size_of::<DiagLoggingModeParamV2>(), 0, 0, 0, 0,
            );
            log::info!("diag probe: v2 ({:>2}B) mask={label} -> ret={r} errno={:?}",
                std::mem::size_of::<DiagLoggingModeParamV2>(), std::io::Error::last_os_error());
            if r == 0 { return Ok(()); }

            // 24-byte with device_mask
            let p3 = DiagLoggingModeParamV3 {
                req_mode: mode, peripheral_mask: mask, pd_mask: 0,
                mode_param: 0, diag_id: 0, pd_val: 0, reserved: 0, peripheral: 0, device_mask: 1,
            };
            let r = libc::ioctl(
                fd, DIAG_IOCTL_SWITCH_LOGGING,
                padded(&p3).as_mut_ptr(),
                std::mem::size_of::<DiagLoggingModeParamV3>(), 0, 0, 0, 0,
            );
            log::info!("diag probe: v3 ({:>2}B) mask={label} -> ret={r} errno={:?}",
                std::mem::size_of::<DiagLoggingModeParamV3>(), std::io::Error::last_os_error());
            if r == 0 { return Ok(()); }
        }

        Err(DiagDeviceError::InitializationFailed(
            "DIAG_IOCTL_SWITCH_LOGGING: every known parameter shape was rejected".to_string(),
        ))
    }
}

// Unsure of what MDM actually stands for, but if `use_mdm` is > 0, then
// an additional mask is included in every diag request
fn determine_use_mdm(fd: i32) -> DiagResult<i32> {
    let use_mdm: i32 = 0;
    unsafe {
        if libc::ioctl(fd, DIAG_IOCTL_REMOTE_DEV, &use_mdm as *const i32) < 0 {
            let msg = format!("DIAG_IOCTL_REMOTE_DEV ioctl failed with error code {}", 0);
            return Err(DiagDeviceError::InitializationFailed(msg));
        }
    }
    Ok(use_mdm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_keeps_the_struct_and_zeroes_what_the_driver_reads_past_it() {
        let p = DiagLoggingModeParam { req_mode: 2, peripheral_mask: u32::MAX, mode_param: 7 };
        let buf = padded(&p);
        assert_eq!(&buf[0..4], &2u32.to_ne_bytes());
        assert_eq!(&buf[4..8], &u32::MAX.to_ne_bytes());
        assert_eq!(buf[8], 7);
        let n = std::mem::size_of::<DiagLoggingModeParam>();
        assert!(buf[n..].iter().all(|&b| b == 0), "tail must be zero, not stack bytes");
        assert!(buf.len() >= std::mem::size_of::<DiagLoggingModeParamV3>());
    }
}
