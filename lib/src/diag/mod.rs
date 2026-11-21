//! Diag protocol serialization/deserialization

use crc::{Algorithm, Crc};
use deku::prelude::*;

use crate::hdlc::{self, hdlc_decapsulate};
use log::warn;
use thiserror::Error;

pub mod diaglog;

use diaglog::{LogBody, Timestamp};

pub const MESSAGE_TERMINATOR: u8 = 0x7e;
pub const MESSAGE_ESCAPE_CHAR: u8 = 0x7d;

pub const ESCAPED_MESSAGE_TERMINATOR: u8 = 0x5e;
pub const ESCAPED_MESSAGE_ESCAPE_CHAR: u8 = 0x5d;

/// Command code of the multi-radio envelope (`DIAG_MULTI_RADIO_CMD_F` in
/// Qualcomm's DIAG command list) that some modems wrap around every message
/// they send. See [`Message::strip_multi_radio_header`].
pub const DIAG_MULTI_RADIO_CMD_F: u8 = 0x98;
/// The only envelope version seen so far.
const MULTI_RADIO_VERSION: u8 = 0x01;
/// Command code, version, two reserved bytes, then a 32-bit field.
const MULTI_RADIO_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, DekuWrite)]
pub struct RequestContainer {
    pub data_type: DataType,
    #[deku(skip)]
    pub use_mdm: bool,
    #[deku(skip, cond = "!*use_mdm")]
    pub mdm_field: i32,
    pub hdlc_encapsulated_request: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DekuWrite)]
#[deku(id_type = "u32")]
pub enum Request {
    #[deku(id = "115")]
    LogConfig(LogConfigRequest),
}

#[derive(Debug, Clone, PartialEq, DekuWrite)]
#[deku(id_type = "u32", endian = "little")]
pub enum LogConfigRequest {
    #[deku(id = "1")]
    RetrieveIdRanges,

    #[deku(id = "3")]
    SetMask {
        log_type: u32,
        log_mask_bitsize: u32,
        log_mask: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u32", endian = "little")]
pub enum DataType {
    #[deku(id = "32")]
    UserSpace,
    #[deku(id_pat = "_")]
    Other(u32),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum DiagParsingError {
    #[error("Failed to parse Message: {0}, data: {1:?}")]
    MessageParsingError(deku::DekuError, Vec<u8>),
    #[error("HDLC decapsulation of message failed: {0}, data: {1:?}")]
    HdlcDecapsulationError(hdlc::HdlcError, Vec<u8>),
}

// this is sorta based on the params qcsuper uses, plus what seems to be used in
// https://github.com/fgsect/scat/blob/f1538b397721df3ab8ba12acd26716abcf21f78b/util.py#L47
pub const CRC_CCITT_ALG: Algorithm<u16> = Algorithm {
    poly: 0x1021,
    init: 0xffff,
    refin: true,
    refout: true,
    width: 16,
    xorout: 0xffff,
    check: 0x2189,
    residue: 0x0000,
};

pub const CRC_CCITT: Crc<u16> = Crc::<u16>::new(&CRC_CCITT_ALG);
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
pub struct MessagesContainer {
    pub data_type: DataType,
    pub num_messages: u32,
    #[deku(count = "num_messages")]
    pub messages: Vec<HdlcEncapsulatedMessage>,
}

impl MessagesContainer {
    pub fn messages(&self) -> Vec<Result<Message, DiagParsingError>> {
        let mut result = Vec::new();
        for msg in &self.messages {
            for sub_msg in msg.data.split_inclusive(|&b| b == MESSAGE_TERMINATOR) {
                result.push(Message::from_hdlc(sub_msg));
            }
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
pub struct HdlcEncapsulatedMessage {
    pub len: u32,
    #[deku(count = "len")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum Message {
    #[deku(id = "16")]
    Log {
        pending_msgs: u8,
        outer_length: u16,
        inner_length: u16,
        log_type: u16,
        timestamp: Timestamp,
        // pass the log type and log length (inner_length - (sizeof(log_type) + sizeof(timestamp)))
        #[deku(ctx = "*log_type, inner_length.saturating_sub(12)")]
        body: LogBody,
    },

    // kinda unpleasant deku hackery here. deku expects an enum's variant to be
    // right before its data, but in this case, a status value comes between the
    // variants and the data. so we need to use deku's context (ctx) feature to
    // pass those opcodes down to their respective parsers.
    #[deku(id_pat = "_")]
    Response {
        opcode1: u8, // the "id" (from deku's POV) gets parsed into this field
        opcode2: u8,
        opcode3: u8,
        opcode4: u8,
        subopcode: u32,
        status: u32,
        #[deku(ctx = "u32::from_le_bytes([*opcode1, *opcode2, *opcode3, *opcode4]), *subopcode")]
        payload: ResponsePayload,
    },
}

impl Message {
    /// Some Qualcomm modems (observed on SDX55 / Inseego MiFi M2100) wrap every
    /// message in an 8-byte multi-radio header before the usual diag payload:
    ///
    /// ```text
    /// 98 01 00 00 | 01 00 00 00 | 10 00 7c 00 7c 00 14 b1 ...
    /// \_ 0x98 tag _/ \_ subscr. _/ \_ ordinary Message (0x10 = Log) ...
    /// ```
    ///
    /// The wrapper sits *inside* the HDLC frame and is covered by its CRC, so
    /// decapsulation succeeds and only the subsequent parse fails -- the leading
    /// 0x98 is read as a Response opcode, yielding
    /// "ID 408 not found on ResponsePayload" (408 == 0x0198).
    ///
    /// 0x98 is [`DIAG_MULTI_RADIO_CMD_F`]. Only version 1 with both reserved
    /// bytes zero is unwrapped, and only when a message follows the header;
    /// anything else is parsed as it is. How many messages arrive wrapped
    /// depends on the firmware image, not only on the chipset: on one SDX55
    /// MiFiOS image about half the log messages were wrapped, on another
    /// nearly all of them.
    fn strip_multi_radio_header(data: &[u8]) -> &[u8] {
        if data.len() > MULTI_RADIO_HEADER_LEN
            && data[0] == DIAG_MULTI_RADIO_CMD_F
            && data[1] == MULTI_RADIO_VERSION
            && data[2] == 0
            && data[3] == 0
        {
            &data[MULTI_RADIO_HEADER_LEN..]
        } else {
            data
        }
    }

    pub fn from_hdlc(data: &[u8]) -> Result<Message, DiagParsingError> {
        match hdlc_decapsulate(data, &CRC_CCITT) {
            Ok(data) => match Message::from_bytes((Message::strip_multi_radio_header(&data), 0)) {
                Ok(((leftover_bytes, _), res)) => {
                    if !leftover_bytes.is_empty() {
                        warn!(
                            "warning: {} leftover bytes when parsing Message",
                            leftover_bytes.len()
                        );
                    }
                    Ok(res)
                }
                Err(e) => Err(DiagParsingError::MessageParsingError(e, data)),
            },
            Err(err) => Err(DiagParsingError::HdlcDecapsulationError(err, data.to_vec())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "opcode: u32, subopcode: u32", id = "opcode")]
pub enum ResponsePayload {
    #[deku(id = "115")]
    LogConfig(#[deku(ctx = "subopcode")] LogConfigResponse),
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "subopcode: u32", id = "subopcode")]
pub enum LogConfigResponse {
    #[deku(id = "1")]
    RetrieveIdRanges { log_mask_sizes: [u32; 16] },

    #[deku(id = "3")]
    SetMask,
}

pub fn build_log_mask_request(
    log_type: u32,
    log_mask_bitsize: u32,
    accepted_log_codes: &[u32],
) -> Request {
    let mut current_byte: u8 = 0;
    let mut num_bits_written: u8 = 0;
    let mut log_mask: Vec<u8> = vec![];
    for i in 0..log_mask_bitsize {
        let log_code: u32 = (log_type << 12) | i;
        if accepted_log_codes.contains(&log_code) {
            current_byte |= 1 << num_bits_written;
        }
        num_bits_written += 1;

        if num_bits_written == 8 || i == log_mask_bitsize - 1 {
            log_mask.push(current_byte);
            current_byte = 0;
            num_bits_written = 0;
        }
    }

    Request::LogConfig(LogConfigRequest::SetMask {
        log_type,
        log_mask_bitsize,
        log_mask,
    })
}

#[cfg(test)]
mod multi_radio_test {
    use super::*;
    use crate::hdlc::hdlc_encapsulate;

    /// A synthetic outgoing EMM NAS log (0xb0ed): the 12-byte log header,
    /// four version bytes, then a three-byte NAS message.
    const NAS_LOG: [u8; 23] = [
        0x10, 0x00, // log command, pending messages
        0x13, 0x00, 0x13, 0x00, // outer and inner length (19)
        0xed, 0xb0, // log type 0xb0ed
        0, 0, 0, 0, 0, 0, 0, 0, // timestamp
        0x01, 0x09, 0x00, 0x05, // ext header version, RRC release, minor, major
        0x07, 0x5d, 0x00, // NAS message bytes
    ];

    fn wrap(header: &[u8], message: &[u8]) -> Vec<u8> {
        let mut data = header.to_vec();
        data.extend_from_slice(message);
        hdlc_encapsulate(&data, &CRC_CCITT)
    }

    fn assert_is_the_nas_log(message: &Message) {
        match message {
            Message::Log {
                log_type: 0xb0ed,
                body: LogBody::Nas4GMessage { msg, .. },
                ..
            } => assert_eq!(msg, &[0x07, 0x5d, 0x00]),
            other => panic!("expected the 0xb0ed NAS log, got {other:?}"),
        }
    }

    #[test]
    fn an_unwrapped_message_parses_as_before() {
        let frame = hdlc_encapsulate(&NAS_LOG, &CRC_CCITT);
        assert_is_the_nas_log(&Message::from_hdlc(&frame).unwrap());
    }

    #[test]
    fn a_wrapped_message_parses_like_the_unwrapped_one() {
        let frame = wrap(&[0x98, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], &NAS_LOG);
        assert_is_the_nas_log(&Message::from_hdlc(&frame).unwrap());
    }

    #[test]
    fn the_32_bit_field_after_the_reserved_bytes_is_not_checked() {
        let frame = wrap(&[0x98, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00], &NAS_LOG);
        assert_is_the_nas_log(&Message::from_hdlc(&frame).unwrap());
    }

    #[test]
    fn an_unknown_envelope_version_is_not_unwrapped() {
        let frame = wrap(&[0x98, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], &NAS_LOG);
        assert!(Message::from_hdlc(&frame).is_err());
    }

    #[test]
    fn nonzero_reserved_bytes_are_not_unwrapped() {
        for reserved in [[0x01, 0x00], [0x00, 0x01]] {
            let header = [0x98, 0x01, reserved[0], reserved[1], 0x01, 0x00, 0x00, 0x00];
            let frame = wrap(&header, &NAS_LOG);
            assert!(Message::from_hdlc(&frame).is_err(), "{reserved:?}");
        }
    }

    #[test]
    fn a_header_with_nothing_after_it_is_an_error() {
        let frame = wrap(&[0x98, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], &[]);
        assert!(Message::from_hdlc(&frame).is_err());
    }

    #[test]
    fn a_frame_shorter_than_the_header_does_not_panic() {
        for len in 1..8 {
            let header = [0x98, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
            let frame = wrap(&header[..len], &[]);
            assert!(Message::from_hdlc(&frame).is_err(), "{len}");
        }
    }
}
