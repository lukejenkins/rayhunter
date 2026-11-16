//! Minimal QMI client for the one thing the vendor API cannot tell us: the
//! actual radio measurements.
//!
//! `http://127.0.0.1/srv/status` exposes only a 0-5 bar count and a `SINR`
//! field that is hardwired to `0` on this device. The real numbers -- RSSI,
//! RSRQ, RSRP and SNR -- come from QMI NAS *Get Signal Info* (`0x004F`), and
//! they move: sampled on hardware, RSRP drifted between -96 and -110 dBm and
//! SNR between 4.0 and 14.8 dB over a few minutes sitting still.
//!
//! QMI here is spoken over QRTR (`AF_QIPCRTR`), the Qualcomm IPC router, as
//! plain datagrams. The NAS service sits at a fixed node/port on this modem,
//! so no service lookup is needed.
//!
//! Note the LTE signal TLV is **`0x14`** on this modem, not the `0x11` that
//! some QMI references list.

use std::time::{Duration, Instant};

const AF_QIPCRTR: libc::c_int = 42;

/// Where the NAS service lives on this modem. Discovered with `qrtr-lookup`
/// and stable across reboots.
const NAS_NODE: u32 = 3;
const NAS_PORT: u32 = 55;

/// QMI NAS Get Signal Info.
const QMI_NAS_GET_SIG_INFO: u16 = 0x004F;
/// QMI NAS Get RF Band Information -- the *active* band per radio interface.
const QMI_NAS_GET_RF_BAND_INFO: u16 = 0x0031;
/// QMI NAS Get Cell Location Info -- serving cell identity and measurements.
const QMI_NAS_GET_CELL_LOCATION_INFO: u16 = 0x0043;
/// TLV carrying LTE intra-frequency serving cell info in that response.
const TLV_LTE_INTRA: u8 = 0x13;
/// TLV carrying LTE RSSI/RSRQ/RSRP/SNR in the response.
const TLV_LTE_SIG_INFO: u8 = 0x14;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SockaddrQrtr {
    family: u16,
    node: u32,
    port: u32,
}

/// One active radio leg: which RAT, which band, which channel.
///
/// This is what the panel should believe about the serving cell. The vendor's
/// own status API will happily report `5G` on band `n8` while this shows a
/// single LTE leg and no NR at all -- it advertises EN-DC capability rather
/// than an established NR connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ActiveBand {
    pub radio_if: u8,
    pub band: u16,
    pub channel: u16,
}

impl ActiveBand {
    pub fn is_nr(&self) -> bool {
        self.radio_if == 0x0a
    }

    /// Human label. QMI's active-band enum places E-UTRA band 1 at 120, so LTE
    /// band numbers have to be un-offset before they mean anything.
    pub fn label(&self) -> String {
        match self.radio_if {
            0x08 if self.band >= 120 => format!("LTE B{}", self.band - 119),
            0x08 => format!("LTE ?{}", self.band),
            0x0a => format!("NR n{}", self.band),
            0x05 => format!("UMTS {}", self.band),
            0x04 => format!("GSM {}", self.band),
            other => format!("RAT 0x{other:02x} b{}", self.band),
        }
    }
}

/// Who we are actually camped on.
///
/// The vendor status API's `statusBarPCI` is not usable for this: observed
/// reporting `0` while the modem was on a nonzero PCI, and reporting `0` across three
/// different serving cells on two bands. Everything here comes from QMI.
///
/// `global_cell_id` is the E-UTRAN Cell Identity and is the field worth keying
/// on. PCI is only locally unique and is reused heavily, whereas the ECI names
/// a specific cell on a specific eNodeB. `tac` matters on its own: a tracking
/// area change forces a location update, which is one way to provoke a device
/// into identifying itself.
#[derive(Debug, Clone, PartialEq)]
pub struct CellInfo {
    pub plmn: String,
    pub tac: u16,
    pub global_cell_id: u32,
    pub earfcn: u16,
    pub pci: u16,
    /// Tenths of a dB/dBm, as the modem reports them.
    pub rsrq_db10: i16,
    pub rsrp_dbm10: i16,
}

impl CellInfo {
    /// eNodeB identity: the ECI's top 20 bits.
    pub fn enodeb(&self) -> u32 {
        self.global_cell_id >> 8
    }

    /// Cell index within that eNodeB.
    pub fn cell(&self) -> u8 {
        (self.global_cell_id & 0xff) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SignalInfo {
    pub rssi_dbm: i8,
    pub rsrq_db: i8,
    pub rsrp_dbm: i16,
    /// SNR in tenths of a dB, as the modem reports it.
    pub snr_db10: i16,
}

impl SignalInfo {
    pub fn snr_db(&self) -> f32 {
        self.snr_db10 as f32 / 10.0
    }
}

/// Build a QMI service request: one-byte control flags, txn id, message id,
/// payload length, then the payload.
fn qmi_request(txn: u16, msg_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(7 + payload.len());
    m.push(0x00); // request
    m.extend(txn.to_le_bytes());
    m.extend(msg_id.to_le_bytes());
    m.extend((payload.len() as u16).to_le_bytes());
    m.extend(payload);
    m
}

/// Split a QMI response body into (type, value) pairs, skipping the header.
fn parse_tlvs(buf: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    if buf.len() < 7 {
        return out;
    }
    let mut i = 7;
    while i + 3 <= buf.len() {
        let ty = buf[i];
        let len = u16::from_le_bytes([buf[i + 1], buf[i + 2]]) as usize;
        let start = i + 3;
        let Some(end) = start.checked_add(len) else { break };
        if end > buf.len() {
            break;
        }
        out.push((ty, buf[start..end].to_vec()));
        i = end;
    }
    out
}

/// Query the modem for current signal info.
pub fn read_signal() -> Option<SignalInfo> {
    decode_sig_info(&query(QMI_NAS_GET_SIG_INFO)?)
}

/// Query the modem for the active band on each radio leg.
///
/// In EN-DC this returns both the LTE anchor and the NR leg, which is the only
/// reliable way to tell a real 5G connection from a 5G badge.
pub fn read_active_bands() -> Vec<ActiveBand> {
    let Some(tlvs) = query(QMI_NAS_GET_RF_BAND_INFO) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ty, v) in tlvs {
        if ty != 0x01 || v.is_empty() {
            continue;
        }
        let n = v[0] as usize;
        for i in 0..n {
            let o = 1 + i * 5;
            if o + 5 > v.len() {
                break;
            }
            out.push(ActiveBand {
                radio_if: v[o],
                band: u16::from_le_bytes([v[o + 1], v[o + 2]]),
                channel: u16::from_le_bytes([v[o + 3], v[o + 4]]),
            });
        }
    }
    out
}

/// Query the serving cell's identity and measurements.
pub fn read_cell_info() -> Option<CellInfo> {
    decode_cell_info(&query(QMI_NAS_GET_CELL_LOCATION_INFO)?)
}

/// Decode a PLMN from the three-byte BCD form QMI uses.
///
/// Nibble order is swapped per byte, and an MNC third digit of 0xf means the
/// MNC is two digits rather than three.
fn decode_plmn(b: &[u8]) -> String {
    let mcc = format!("{}{}{}", b[0] & 0xf, b[0] >> 4, b[1] & 0xf);
    let mnc3 = b[1] >> 4;
    let mut mnc = format!("{}{}", b[2] & 0xf, b[2] >> 4);
    if mnc3 != 0xf {
        mnc.push_str(&mnc3.to_string());
    }
    format!("{mcc}{mnc}")
}

fn decode_cell_info(tlvs: &[(u8, Vec<u8>)]) -> Option<CellInfo> {
    let v = tlvs.iter().find(|(t, _)| *t == TLV_LTE_INTRA).map(|(_, v)| v)?;
    // ue_in_idle(1) plmn(3) tac(2) eci(4) earfcn(2) pci(2) + 4 thresholds + count
    if v.len() < 20 {
        return None;
    }
    let plmn = decode_plmn(&v[1..4]);
    let tac = u16::from_le_bytes([v[4], v[5]]);
    let global_cell_id = u32::from_le_bytes([v[6], v[7], v[8], v[9]]);
    let earfcn = u16::from_le_bytes([v[10], v[11]]);
    let pci = u16::from_le_bytes([v[12], v[13]]);

    // The serving cell repeats in the cell list that follows the four
    // reselection thresholds, and that copy carries the measurements.
    let (mut rsrq_db10, mut rsrp_dbm10) = (0i16, 0i16);
    let count = *v.get(18)? as usize;
    for k in 0..count {
        let o = 19 + k * 10;
        if o + 10 > v.len() {
            break;
        }
        if u16::from_le_bytes([v[o], v[o + 1]]) == pci {
            rsrq_db10 = i16::from_le_bytes([v[o + 2], v[o + 3]]);
            rsrp_dbm10 = i16::from_le_bytes([v[o + 4], v[o + 5]]);
            break;
        }
    }

    Some(CellInfo {
        plmn,
        tac,
        global_cell_id,
        earfcn,
        pci,
        rsrq_db10,
        rsrp_dbm10,
    })
}

/// Send one QMI request to NAS and return the response TLVs.
///
/// Blocking, and short: it polls for a reply for at most a second. Call it from
/// a blocking context rather than directly on the async runtime.
fn query(msg_id: u16) -> Option<Vec<(u8, Vec<u8>)>> {
    // SAFETY: each call below is a plain libc socket operation on a descriptor
    // this function owns; `fd` is closed on every return path.
    unsafe {
        let fd = libc::socket(AF_QIPCRTR, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return None;
        }

        let result = (|| {
            // Bind to our own node with a kernel-assigned port.
            let mut sn = SockaddrQrtr::default();
            let mut sl = std::mem::size_of::<SockaddrQrtr>() as libc::socklen_t;
            if libc::getsockname(fd, &mut sn as *mut _ as *mut libc::sockaddr, &mut sl) < 0 {
                return None;
            }
            let me = SockaddrQrtr {
                family: AF_QIPCRTR as u16,
                node: sn.node,
                port: 0,
            };
            if libc::bind(
                fd,
                &me as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrQrtr>() as libc::socklen_t,
            ) < 0
            {
                return None;
            }

            let dst = SockaddrQrtr {
                family: AF_QIPCRTR as u16,
                node: NAS_NODE,
                port: NAS_PORT,
            };
            let req = qmi_request(1, msg_id, &[]);
            if libc::sendto(
                fd,
                req.as_ptr() as *const libc::c_void,
                req.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrQrtr>() as libc::socklen_t,
            ) < 0
            {
                return None;
            }

            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_millis(1000);
            loop {
                let mut from = SockaddrQrtr::default();
                let mut fl = std::mem::size_of::<SockaddrQrtr>() as libc::socklen_t;
                let n = libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                    &mut from as *mut _ as *mut libc::sockaddr,
                    &mut fl,
                );
                if n > 0 {
                    return Some(parse_tlvs(&buf[..n as usize]));
                }
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })();

        libc::close(fd);
        result
    }
}

fn decode_sig_info(tlvs: &[(u8, Vec<u8>)]) -> Option<SignalInfo> {
    for (ty, v) in tlvs {
        if *ty == TLV_LTE_SIG_INFO && v.len() >= 6 {
            return Some(SignalInfo {
                rssi_dbm: v[0] as i8,
                rsrq_db: v[1] as i8,
                rsrp_dbm: i16::from_le_bytes([v[2], v[3]]),
                snr_db10: i16::from_le_bytes([v[4], v[5]]),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact bytes captured from the device, so the decode stays pinned to
    /// something real rather than to my reading of a spec.
    #[test]
    fn decodes_a_real_capture() {
        // header (7 bytes) + TLV 0x14, len 6: b6 f7 a0 ff 94 00
        let mut buf = vec![0x02, 0x01, 0x00, 0x4f, 0x00, 0x09, 0x00];
        buf.extend([TLV_LTE_SIG_INFO, 0x06, 0x00]);
        buf.extend([0xb6, 0xf7, 0xa0, 0xff, 0x94, 0x00]);
        let s = decode_sig_info(&parse_tlvs(&buf)).expect("should decode");
        assert_eq!(s.rssi_dbm, -74);
        assert_eq!(s.rsrq_db, -9);
        assert_eq!(s.rsrp_dbm, -96);
        assert_eq!(s.snr_db10, 148);
        assert!((s.snr_db() - 14.8).abs() < 0.01);
    }

    #[test]
    fn absent_lte_tlv_is_none() {
        let buf = vec![0x02, 0x01, 0x00, 0x4f, 0x00, 0x04, 0x00, 0x17, 0x01, 0x00, 0x00];
        assert_eq!(decode_sig_info(&parse_tlvs(&buf)), None);
    }

    /// A truncated TLV must not panic or read past the buffer.
    /// The exact RF-band reply seen while the vendor UI claimed "5G / n8":
    /// one LTE leg on band 2, no NR leg at all.
    #[test]
    fn decodes_the_active_band_that_contradicted_the_vendor_badge() {
        let v = vec![0x01u8, 0x08, 0x79, 0x00, 0x8a, 0x02];
        let n = v[0] as usize;
        let mut bands = Vec::new();
        for i in 0..n {
            let o = 1 + i * 5;
            bands.push(ActiveBand {
                radio_if: v[o],
                band: u16::from_le_bytes([v[o + 1], v[o + 2]]),
                channel: u16::from_le_bytes([v[o + 3], v[o + 4]]),
            });
        }
        assert_eq!(bands.len(), 1);
        assert_eq!(bands[0].label(), "LTE B2");
        assert_eq!(bands[0].channel, 650);
        assert!(!bands[0].is_nr());
    }

    /// Pinned to bytes captured from the device, cross-validated three ways:
    /// the PLMN decodes to the SIM's operator, the EARFCN matches what Get RF
    /// Band Information reported independently, and the PCI appears twice --
    /// header field and cell list -- agreeing. The vendor API claimed PCI 0 at
    /// the same moment.
    #[test]
    fn decodes_a_real_serving_cell() {
        let v: Vec<u8> = "01 13 00 62 67 2b 07 39 30 00 e8 03 65 00 02 08 00 2e 01 65 00 8a ff f2 fb f8 fc 14 00"
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect();
        let c = decode_cell_info(&[(TLV_LTE_INTRA, v)]).expect("should decode");
        assert_eq!(c.plmn, "310260");
        assert_eq!(c.tac, 11111);
        assert_eq!(c.global_cell_id, 3_160_327);
        assert_eq!(c.enodeb(), 12345);
        assert_eq!(c.cell(), 7);
        assert_eq!(c.earfcn, 1000);
        assert_eq!(c.pci, 101);
        assert_eq!(c.rsrq_db10, -118);
        assert_eq!(c.rsrp_dbm10, -1038);
    }

    #[test]
    fn plmn_handles_two_and_three_digit_mnc() {
        // 310260, three-digit MNC.
        assert_eq!(decode_plmn(&[0x13, 0x00, 0x62]), "310260");
        // 0xf filler in the MNC third digit means a two-digit MNC.
        assert_eq!(decode_plmn(&[0x13, 0xf0, 0x62]), "31026");
    }

    #[test]
    fn short_cell_tlv_is_rejected() {
        assert_eq!(decode_cell_info(&[(TLV_LTE_INTRA, vec![0u8; 8])]), None);
        assert_eq!(decode_cell_info(&[(0x99, vec![0u8; 40])]), None);
    }

    #[test]
    fn truncated_tlv_is_ignored() {
        let mut buf = vec![0x02, 0x01, 0x00, 0x4f, 0x00, 0x09, 0x00];
        buf.extend([TLV_LTE_SIG_INFO, 0x06, 0x00]);
        buf.extend([0xb6, 0xf7]); // claims 6 bytes, supplies 2
        assert_eq!(decode_sig_info(&parse_tlvs(&buf)), None);
    }
}
