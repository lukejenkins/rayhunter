// SPDX-License-Identifier: Apache-2.0
//! QMI framing and the QMI-LOC messages, with no I/O.
//!
//! Over QRTR a QMI message has no QMUX header: a 7-byte little-endian header
//! (u8 type, u16 transaction id, u16 message id, u16 TLV length), then TLVs of
//! u8 type, u16 length, value.

/// QMI service number of LOC ("LOC v02").
pub const SVC_LOC: u32 = 16;

pub const MSG_REG_EVENTS: u16 = 0x0021;
pub const MSG_START: u16 = 0x0022;
pub const MSG_STOP: u16 = 0x0023;
pub const MSG_EVENT_NMEA_IND: u16 = 0x0026;
pub const MSG_SET_NMEA_TYPES: u16 = 0x003E;

/// REG_EVENTS mask bit for NMEA indications.
pub const EVENT_MASK_NMEA: u64 = 0x04;

/// The session id this crate starts and stops.
pub const SESSION_ID: u8 = 1;

/// SET_NMEA_TYPES default: GGA 0x1 | RMC 0x2 | GSV 0x4 | GSA 0x8 | VTG 0x10 |
/// GLGSV 0x80 | GNGSA 0x100 | GNGNS 0x200. Measured on R500L5 V2.0.4.3:
/// without SET_NMEA_TYPES the engine emits only Qualcomm proprietary sentences
/// (`$PQWP1`-`6`, `$PQWM1`, `$PQMECLK`).
pub const NMEA_TYPES_DEFAULT: u32 = 0x39F;

pub const TYPE_REQUEST: u8 = 0x00;
pub const TYPE_RESPONSE: u8 = 0x02;
pub const TYPE_INDICATION: u8 = 0x04;

/// Header length: u8 type, u16 txn, u16 msg id, u16 TLV length.
pub const HEADER_LEN: usize = 7;

/// The longest NMEA text taken from one indication, matching the C
/// forwarder's 4100-byte buffer (4099 bytes + NUL).
pub const NMEA_TEXT_MAX: usize = 4099;

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// Build a request: header followed by `tlvs` in order.
pub fn request(txn: u16, msg_id: u16, tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let body: usize = tlvs.iter().map(|(_, v)| 3 + v.len()).sum();
    let mut out = Vec::with_capacity(HEADER_LEN + body);
    out.push(TYPE_REQUEST);
    out.extend_from_slice(&txn.to_le_bytes());
    out.extend_from_slice(&msg_id.to_le_bytes());
    out.extend_from_slice(&(body as u16).to_le_bytes());
    for (ty, v) in tlvs {
        out.push(*ty);
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// REG_EVENTS: TLV 0x01 u64 event mask.
pub fn reg_events(txn: u16, mask: u64) -> Vec<u8> {
    request(txn, MSG_REG_EVENTS, &[(0x01, &mask.to_le_bytes())])
}

/// SET_NMEA_TYPES: TLV 0x01 u32 sentence mask.
pub fn set_nmea_types(txn: u16, mask: u32) -> Vec<u8> {
    request(txn, MSG_SET_NMEA_TYPES, &[(0x01, &mask.to_le_bytes())])
}

/// START: TLV 0x01 u8 session id, TLV 0x10 u32 fix recurrence = 1 (periodic).
pub fn start(txn: u16, session: u8) -> Vec<u8> {
    request(txn, MSG_START, &[(0x01, &[session]), (0x10, &1u32.to_le_bytes())])
}

/// STOP: TLV 0x01 u8 session id.
pub fn stop(txn: u16, session: u8) -> Vec<u8> {
    request(txn, MSG_STOP, &[(0x01, &[session])])
}

/// A parsed QMI message borrowing its TLV area from the receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub kind: u8,
    pub txn: u16,
    pub msg_id: u16,
    pub tlvs: &'a [u8],
}

impl<'a> Message<'a> {
    /// Parse a header. `None` when `buf` is shorter than the header or than
    /// the TLV length the header declares. Trailing bytes are ignored.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let len = le16(&buf[5..]) as usize;
        let tlvs = buf.get(HEADER_LEN..HEADER_LEN + len)?;
        Some(Message { kind: buf[0], txn: le16(&buf[1..]), msg_id: le16(&buf[3..]), tlvs })
    }

    /// The value of TLV `ty`; see [`tlv_find`].
    pub fn tlv(&self, ty: u8) -> Option<&'a [u8]> {
        tlv_find(self.tlvs, ty)
    }
}

/// Find TLV `ty`. `None` when it is absent, or when a TLV before or at it
/// runs past the end of `tlvs` (nothing beyond a bad length is trusted).
pub fn tlv_find(tlvs: &[u8], ty: u8) -> Option<&[u8]> {
    let mut p = 0;
    while p + 3 <= tlvs.len() {
        let len = le16(&tlvs[p + 1..]) as usize;
        let val = tlvs.get(p + 3..p + 3 + len)?;
        if tlvs[p] == ty {
            return Some(val);
        }
        p += 3 + len;
    }
    None
}

/// What a request came back with: the standard result TLV 0x02, or why there
/// was none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Result TLV says success.
    Ok,
    /// Result TLV says failure: QMI result and error codes as sent.
    Failed { result: u16, error: u16 },
    /// A response arrived without a well-formed 4-byte result TLV.
    Malformed,
    /// Send failed, or no matching response before the deadline.
    NoResponse,
}

impl Outcome {
    /// Decode the result TLV of a response's TLV area.
    pub fn from_tlvs(tlvs: &[u8]) -> Self {
        match tlv_find(tlvs, 0x02) {
            Some(v) if v.len() == 4 => match (le16(v), le16(&v[2..])) {
                (0, _) => Outcome::Ok,
                (result, error) => Outcome::Failed { result, error },
            },
            _ => Outcome::Malformed,
        }
    }

    pub fn is_ok(&self) -> bool {
        *self == Outcome::Ok
    }

    /// One number in the C forwarder's convention: 0 success, the QMI error
    /// code on failure (1 when the failure carries error 0), -1 when there is
    /// no usable response.
    pub fn code(&self) -> i32 {
        match *self {
            Outcome::Ok => 0,
            Outcome::Failed { error: 0, .. } => 1,
            Outcome::Failed { error, .. } => error as i32,
            Outcome::Malformed | Outcome::NoResponse => -1,
        }
    }
}

/// The NMEA text of an EVENT_NMEA_IND TLV area: TLV 0x01 up to its first NUL,
/// capped at [`NMEA_TEXT_MAX`] bytes. `None` when the TLV is absent,
/// malformed, or its text is empty. It may hold several sentences; see [`sentences`].
pub fn nmea_text(tlvs: &[u8]) -> Option<&[u8]> {
    let v = tlv_find(tlvs, 0x01)?;
    if v.is_empty() {
        return None;
    }
    let v = &v[..v.len().min(NMEA_TEXT_MAX)];
    let text = match v.iter().position(|&b| b == 0) {
        Some(nul) => &v[..nul],
        None => v,
    };
    (!text.is_empty()).then_some(text)
}

/// Split NMEA text into sentences: each starts at `$` or `!` and runs up to
/// the next CR, LF or NUL (not included). Bytes before a start are skipped.
pub fn sentences(text: &[u8]) -> Sentences<'_> {
    Sentences { text, pos: 0 }
}

/// Iterator returned by [`sentences`].
#[derive(Debug, Clone)]
pub struct Sentences<'a> {
    text: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Sentences<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = &self.text[self.pos..];
        let Some(i) = rest.iter().position(|&b| b == b'$' || b == b'!') else {
            self.pos = self.text.len();
            return None;
        };
        let len = rest[i..].iter().position(|&b| matches!(b, b'\r' | b'\n' | 0)).unwrap_or(rest.len() - i);
        self.pos += i + len;
        Some(&rest[i..i + len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte layouts pinned by apps/locnmea/tests/test_locnmea.c.

    #[test]
    fn reg_events_bytes() {
        let want = [
            0x00, 0x34, 0x12, 0x21, 0x00, 0x0B, 0x00, //
            0x01, 0x08, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(reg_events(0x1234, EVENT_MASK_NMEA), want);
    }

    #[test]
    fn start_bytes() {
        let want = [
            0x00, 0x02, 0x00, 0x22, 0x00, 0x0B, 0x00, //
            0x01, 0x01, 0x00, 0x01, // session id 1
            0x10, 0x04, 0x00, 0x01, 0, 0, 0, // periodic
        ];
        assert_eq!(start(2, 1), want);
    }

    #[test]
    fn stop_bytes() {
        let want = [0x00, 0x03, 0x00, 0x23, 0x00, 0x04, 0x00, 0x01, 0x01, 0x00, 0x01];
        assert_eq!(stop(3, 1), want);
    }

    #[test]
    fn set_nmea_types_bytes() {
        let want = [
            0x00, 0x05, 0x00, 0x3E, 0x00, 0x07, 0x00, //
            0x01, 0x04, 0x00, 0x9F, 0x03, 0x00, 0x00,
        ];
        assert_eq!(set_nmea_types(5, NMEA_TYPES_DEFAULT), want);
    }

    #[test]
    fn result_tlv() {
        let ok = [0x02, 0x04, 0x00, 0, 0, 0, 0];
        let bad = [0x02, 0x04, 0x00, 1, 0, 0x2A, 0];
        let nocode = [0x02, 0x04, 0x00, 1, 0, 0, 0];
        assert_eq!(Outcome::from_tlvs(&ok), Outcome::Ok);
        assert_eq!(Outcome::from_tlvs(&bad), Outcome::Failed { result: 1, error: 0x2A });
        assert_eq!(Outcome::from_tlvs(&bad).code(), 0x2A);
        // A failure is never reported as 0.
        assert_eq!(Outcome::from_tlvs(&nocode).code(), 1);
        assert_eq!(Outcome::from_tlvs(&ok[..3]), Outcome::Malformed);
        assert_eq!(Outcome::from_tlvs(&[]).code(), -1);
        assert_eq!(Outcome::NoResponse.code(), -1);
        // A result TLV of the wrong length is not trusted.
        assert_eq!(Outcome::from_tlvs(&[0x02, 0x02, 0x00, 0, 0]), Outcome::Malformed);
    }

    #[test]
    fn tlv_find_is_bounds_safe() {
        let t = [0x10, 0x01, 0x00, 0xAA, 0x01, 0xFF, 0x00, b'x']; // 2nd overruns
        assert_eq!(tlv_find(&t, 0x10), Some(&[0xAA][..]));
        assert_eq!(tlv_find(&t, 0x01), None);
        assert_eq!(tlv_find(&t, 0x33), None);
        assert_eq!(tlv_find(&[], 0x01), None);
        assert_eq!(tlv_find(&[0x01, 0x00], 0x01), None); // short TLV header
    }

    #[test]
    fn parse_rejects_short_and_overlong() {
        let mut m = [0x04, 0x01, 0x00, 0x26, 0x00, 0x05, 0x00, 0x01, 0x02, 0x00, b'$', b'G'];
        let msg = Message::parse(&m).unwrap();
        assert_eq!(msg.kind, TYPE_INDICATION);
        assert_eq!(msg.txn, 1);
        assert_eq!(msg.msg_id, MSG_EVENT_NMEA_IND);
        assert_eq!(msg.tlvs.len(), 5);
        assert_eq!(msg.tlv(0x01), Some(&b"$G"[..]));
        assert_eq!(Message::parse(&m[..6]), None); // short header
        m[5] = 0x40; // declares 64
        assert_eq!(Message::parse(&m), None);
    }

    fn nmea_ind_tlvs(text: &[u8]) -> Vec<u8> {
        let mut v = text.to_vec();
        v.push(0);
        let mut t = vec![0x01];
        t.extend_from_slice(&(v.len() as u16).to_le_bytes());
        t.extend_from_slice(&v);
        t
    }

    #[test]
    fn nmea_text_and_split() {
        let s = b"$GPGGA,,,,,,0,,,,,,,,*66\r\n$GPRMC,,V,,,,,,,,,,N*53\r\n";
        let tlvs = nmea_ind_tlvs(s);
        let text = nmea_text(&tlvs).unwrap();
        assert_eq!(text, s);
        let got: Vec<&[u8]> = sentences(text).collect();
        assert_eq!(got, [&b"$GPGGA,,,,,,0,,,,,,,,*66"[..], &b"$GPRMC,,V,,,,,,,,,,N*53"[..]]);
    }

    #[test]
    fn split_edge_cases() {
        // Leading junk, '!' starts, a bare LF, no trailing terminator.
        let got: Vec<&[u8]> = sentences(b"xx$A*00\n\n!AIVDM,1\r$B").collect();
        assert_eq!(got, [&b"$A*00"[..], &b"!AIVDM,1"[..], &b"$B"[..]]);
        assert_eq!(sentences(b"").count(), 0);
        assert_eq!(sentences(b"\r\n no start").count(), 0);
        // A start with nothing after it is a 1-byte sentence, as in the C.
        assert_eq!(sentences(b"$").collect::<Vec<_>>(), [&b"$"[..]]);
    }

    #[test]
    fn nmea_text_absent_empty_truncated() {
        assert_eq!(nmea_text(&[]), None);
        assert_eq!(nmea_text(&[0x01, 0x00, 0x00]), None); // empty TLV
        assert_eq!(nmea_text(&[0x01, 0x02, 0x00, 0, b'$']), None); // NUL first
        assert_eq!(nmea_text(&[0x01, 0x05, 0x00, b'$', b'G']), None); // overruns
        assert_eq!(nmea_text(&[0x10, 0x01, 0x00, 0x00]), None); // no TLV 0x01
                                                                // No NUL: the whole value is the text.
        assert_eq!(nmea_text(&[0x01, 0x02, 0x00, b'$', b'G']), Some(&b"$G"[..]));
        // Long text is capped at NMEA_TEXT_MAX, like the C 4100-byte buffer.
        let long = vec![b'A'; 5000];
        assert_eq!(nmea_text(&nmea_ind_tlvs(&long)).unwrap().len(), NMEA_TEXT_MAX);
    }
}
