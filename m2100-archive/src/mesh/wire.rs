//! Meshtastic serial wire format: the stream framing and the few protobuf messages we use.
//! Hand-written (no protobuf crate): we send four fixed shapes and read one field back.

pub const START1: u8 = 0x94;
pub const START2: u8 = 0xC3;
/// The firmware's own limit on a frame payload.
pub const MAX_PAYLOAD: usize = 512;
/// Longest alert text we send; keeps the packet well inside one radio frame.
pub const MAX_TEXT: usize = 200;

/// Broadcast destination (all nodes on the channel).
const BROADCAST: u32 = 0xFFFF_FFFF;
/// Meshtastic TEXT_MESSAGE_APP.
const PORTNUM_TEXT: u64 = 1;
const HOP_LIMIT: u64 = 3;

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Wire types: 0 varint, 1 fixed64, 2 length-delimited, 5 fixed32.
fn put_tag(out: &mut Vec<u8>, field: u32, wire: u8) {
    put_varint(out, (u64::from(field) << 3) | u64::from(wire));
}

fn put_varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
    put_tag(out, field, 0);
    put_varint(out, v);
}

fn put_fixed32_field(out: &mut Vec<u8>, field: u32, v: u32) {
    put_tag(out, field, 5);
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes_field(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    put_tag(out, field, 2);
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// Prefix a payload with the serial stream header.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_PAYLOAD, "mesh frame payload too large");
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&[START1, START2]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// ToRadio carrying a broadcast text message on the primary channel (unframed).
pub fn text_packet(text: &str, packet_id: u32) -> Vec<u8> {
    let mut data = Vec::new();
    put_varint_field(&mut data, 1, PORTNUM_TEXT);
    put_bytes_field(&mut data, 2, text.as_bytes());

    // Channel 0 and want_ack=false are proto3 defaults, so they are left out.
    let mut packet = Vec::new();
    put_fixed32_field(&mut packet, 2, BROADCAST);
    put_bytes_field(&mut packet, 4, &data);
    put_fixed32_field(&mut packet, 6, packet_id);
    put_varint_field(&mut packet, 9, HOP_LIMIT);

    let mut out = Vec::new();
    put_bytes_field(&mut out, 1, &packet);
    out
}

/// ToRadio.want_config_id: asks the radio to dump its config, ending with our nonce.
pub fn want_config(nonce: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint_field(&mut out, 3, u64::from(nonce));
    out
}

/// ToRadio.disconnect = true.
pub fn disconnect() -> Vec<u8> {
    let mut out = Vec::new();
    put_varint_field(&mut out, 4, 1);
    out
}

/// Splits the radio's byte stream into frame payloads. The radio interleaves plain-text
/// debug output with frames, so anything outside a frame is skipped.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Feed bytes; returns every payload completed by them. Never panics on any input.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            // Discard everything before a possible frame start.
            match self.buf.iter().position(|&b| b == START1) {
                Some(0) => {}
                Some(n) => {
                    self.buf.drain(..n);
                }
                None => {
                    self.buf.clear();
                    break;
                }
            }
            if self.buf.len() < 2 {
                break;
            }
            if self.buf[1] != START2 {
                self.buf.drain(..1);
                continue;
            }
            if self.buf.len() < 4 {
                break;
            }
            let len = usize::from(u16::from_be_bytes([self.buf[2], self.buf[3]]));
            if len > MAX_PAYLOAD {
                // Not a real header; skip its first byte and look for the next start.
                self.buf.drain(..1);
                continue;
            }
            if self.buf.len() < 4 + len {
                break;
            }
            out.push(self.buf[4..4 + len].to_vec());
            self.buf.drain(..4 + len);
        }
        out
    }
}

fn read_varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    for shift in (0..70).step_by(7) {
        let byte = *b.get(*pos)?;
        *pos += 1;
        if shift < 64 {
            v |= u64::from(byte & 0x7F) << shift;
        }
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// FromRadio.config_complete_id (field 7), the only thing we read from the radio. The
/// bytes are untrusted: other fields are skipped by wire type, and anything malformed
/// is `None`.
pub fn config_complete_id(from_radio: &[u8]) -> Option<u32> {
    let mut pos = 0;
    while pos < from_radio.len() {
        let tag = read_varint(from_radio, &mut pos)?;
        let (field, wire) = (tag >> 3, tag & 7);
        match wire {
            0 => {
                let v = read_varint(from_radio, &mut pos)?;
                if field == 7 {
                    return u32::try_from(v).ok();
                }
            }
            1 => pos = pos.checked_add(8).filter(|&p| p <= from_radio.len())?,
            2 => {
                let len = usize::try_from(read_varint(from_radio, &mut pos)?).ok()?;
                pos = pos.checked_add(len).filter(|&p| p <= from_radio.len())?;
            }
            5 => pos = pos.checked_add(4).filter(|&p| p <= from_radio.len())?,
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test] fn text_packet_matches_official_encoding() {
        assert_eq!(hex(&text_packet("Home: test", 0x0102_0304)),
            "0a1c15ffffffff220e0801120a486f6d653a207465737435040302014803");
    }
    #[test] fn want_config_matches_official_encoding() {
        assert_eq!(hex(&want_config(0x00ab_cdef)), "18ef9baf05");
    }
    #[test] fn disconnect_bytes() { assert_eq!(disconnect(), vec![0x20, 0x01]); }
    #[test] fn frame_header() {
        assert_eq!(frame(&[1, 2, 3]), vec![0x94, 0xC3, 0x00, 0x03, 1, 2, 3]);
    }
    #[test] fn reads_config_complete_from_official_encoding() {
        // FromRadio{ id: 5, config_complete_id: 0x00abcdef }
        assert_eq!(config_complete_id(&unhex("080538ef9baf05")), Some(0x00ab_cdef));
    }
    #[test] fn config_complete_absent_or_malformed_is_none() {
        assert_eq!(config_complete_id(&unhex("0805")), None);
        assert_eq!(config_complete_id(&unhex("38ff")), None);        // truncated varint
        assert_eq!(config_complete_id(&unhex("12ff01")), None);      // length past the end
        assert_eq!(config_complete_id(&[]), None);
    }
    #[test] fn reader_skips_debug_text_and_splits_frames() {
        let mut r = FrameReader::new();
        let mut input = b"INFO | boot\r\n".to_vec();
        input.extend(frame(&[7, 8]));
        input.extend(frame(&[9]));
        assert_eq!(r.push(&input[..5]), Vec::<Vec<u8>>::new());
        assert_eq!(r.push(&input[5..]), vec![vec![7, 8], vec![9]]);
    }
    #[test] fn reader_drops_oversize_header_and_resyncs() {
        let mut r = FrameReader::new();
        let mut input = vec![0x94, 0xC3, 0x02, 0x01]; // 513 announced
        input.extend(frame(&[1]));
        assert_eq!(r.push(&input), vec![vec![1]]);
    }
}
