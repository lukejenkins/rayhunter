//! Diag MAC RACH serialization/deserialization. As with most of our diag
//! parsers, these structs were derived from SCAT:
//! https://github.com/fgsect/scat/blob/9763cb5b1dcd5ee980f5b0ead9a8d520c8c51a51/src/scat/parsers/qualcomm/diagltelogparser.py#L853

use deku::prelude::*;

/// Qualcomm emits several incompatible layouts under these MAC log codes and
/// tags them with a leading version byte. Upstream implements version 1 and
/// asserts on it, which turns every other version into a hard parse failure
/// for the whole message.
///
/// The Inseego M2100 (Qualcomm SDX55) emits MAC DL (0xb063) as version **49**
/// (0x31), while MAC UL (0xb064) and RACH (0xb062) on the same device are
/// version 1 and parse normally -- 245 failures in one 16-hour capture. MAC DL
/// now has its own type, [`DlTransportBlock`], because its 0x31 and 0x32
/// layouts are not this subpacket container. For these log codes an
/// unrecognised version is kept as opaque bytes rather than failing.
#[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
#[deku(ctx = "hdr_len: u16")]
pub struct Packet {
    pub version: u8,
    #[deku(ctx = "*version, hdr_len.saturating_sub(1)")]
    pub body: PacketBody,
}

#[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
#[deku(ctx = "version: u8, len: u16", id = "version")]
pub enum PacketBody {
    #[deku(id = "1")]
    V1 {
        num_subpackets: u8,
        #[deku(pad_bytes_before = "2", count = "num_subpackets")]
        subpackets: Vec<Subpacket>,
    },
    /// Unknown layout, not unknown data -- keep the bytes.
    #[deku(id_pat = "_")]
    Unsupported {
        #[deku(count = "len")]
        data: Vec<u8>,
    },
}

impl Packet {
    /// The subpackets, or an empty slice for a version this parser does not
    /// know. Callers that only want the contents need not know the difference.
    pub fn subpackets(&self) -> &[Subpacket] {
        match &self.body {
            PacketBody::V1 { subpackets, .. } => subpackets,
            PacketBody::Unsupported { .. } => &[],
        }
    }
}

/// LTE MAC DL transport block (0xb063), keyed on the version byte.
///
/// - Version 1 is the same subpacket container as [`Packet`].
/// - Version 0x31 (SDX55: Inseego M2100, Orbic R500L5) is a flat layout: an
///   8-byte header (counting the version byte), 532 bytes of per-cell
///   statistics, then `num_entries` transport block entries.
/// - Version 0x32 (SDX65: Inseego M3100) has the same 8-byte header and no
///   per-cell statistics block: the entries start right after the header.
///
/// Entries can carry a variable-length extension (record sizes are not a fixed
/// multiple of `num_entries`), so they are kept as raw bytes rather than framed
/// here. Any other version is kept as opaque bytes.
#[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
#[deku(ctx = "hdr_len: u16")]
pub struct DlTransportBlock {
    pub version: u8,
    #[deku(ctx = "*version, hdr_len.saturating_sub(1)")]
    pub body: DlTransportBlockBody,
}

#[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
#[deku(ctx = "version: u8, len: u16", id = "version")]
pub enum DlTransportBlockBody {
    #[deku(id = "1")]
    V1 {
        num_subpackets: u8,
        #[deku(pad_bytes_before = "2", count = "num_subpackets")]
        subpackets: Vec<Subpacket>,
    },
    #[deku(id = "0x31")]
    V31 {
        unknown1: [u8; 3],
        num_entries: u16,
        unknown2: u16,
        #[deku(count = "532")]
        cell_stats: Vec<u8>,
        #[deku(count = "len.saturating_sub(539)")]
        entries: Vec<u8>,
    },
    #[deku(id = "0x32")]
    V32 {
        unknown1: [u8; 3],
        num_entries: u16,
        unknown2: u16,
        #[deku(count = "len.saturating_sub(7)")]
        entries: Vec<u8>,
    },
    /// Unknown layout, not unknown data -- keep the bytes.
    #[deku(id_pat = "_")]
    Unsupported {
        #[deku(count = "len")]
        data: Vec<u8>,
    },
}

impl DlTransportBlock {
    /// The subpackets of a version 1 block; empty for every other version.
    pub fn subpackets(&self) -> &[Subpacket] {
        match &self.body {
            DlTransportBlockBody::V1 { subpackets, .. } => subpackets,
            _ => &[],
        }
    }

    /// The number of transport block entries, where the layout records it.
    pub fn num_entries(&self) -> Option<u16> {
        match &self.body {
            DlTransportBlockBody::V31 { num_entries, .. }
            | DlTransportBlockBody::V32 { num_entries, .. } => Some(*num_entries),
            _ => None,
        }
    }
}

#[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
pub struct Subpacket {
    pub id: u8,
    pub version: u8,
    pub size: u16,
    // size includes the header length, so subtract that
    #[deku(ctx = "*id, *version, *size - 4")]
    pub body: SubpacketBody,
}

#[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
#[deku(ctx = "id: u8, version: u8, size: u16", id = "id")]
pub enum SubpacketBody {
    #[deku(id = 0x06)]
    RachAttempt(#[deku(ctx = "version")] rach::Attempt),
    #[deku(id_pat = "_")]
    Other {
        #[deku(count = "size")]
        data: Vec<u8>,
    },
}

pub mod rach {
    //! Derived from https://github.com/fgsect/scat/blob/9763cb5b1dcd5ee980f5b0ead9a8d520c8c51a51/src/scat/parsers/qualcomm/diagltelogparser.py#L496
    use super::*;

    #[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
    #[deku(ctx = "version: u8")]
    pub struct Attempt {
        #[deku(ctx = "version")]
        pub header: AttemptHeader,
        // since we may not have meaningful msg fields, they're marked private and the get_msg
        // functions should be used instead
        #[deku(ctx = "version")]
        msg1: Msg1,
        msg2: Msg2,
        #[deku(ctx = "version")]
        msg3: Msg3,
        #[deku(cond = "version == 0x31 || version == 0x32")]
        pub additional_info: Option<AdditionalInfo>,
    }

    impl Attempt {
        pub fn get_msg1(&self) -> Option<&Msg1> {
            if self.header.has_msg1() {
                Some(&self.msg1)
            } else {
                None
            }
        }

        pub fn get_msg2(&self) -> Option<&Msg2> {
            if self.header.has_msg2() {
                Some(&self.msg2)
            } else {
                None
            }
        }

        pub fn get_msg3(&self) -> Option<&Msg3> {
            if self.header.has_msg3() {
                Some(&self.msg3)
            } else {
                None
            }
        }
    }

    #[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
    pub struct AdditionalInfo {
        pub ul_earfcn: u32,
        pub p_max: u8,
        pub scell_id: u8,
        pub unk1: u32,
        pub unk2: u32,
    }

    #[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
    #[deku(ctx = "version: u8", id = "version")]
    pub enum Msg1 {
        #[deku(id = "0x02")]
        V2 {
            preamble_index: u8,
            preamble_index_mask: u8,
            preamble_power_offset: i16,
        },
        #[deku(id_pat = "0x03 | 0x31")]
        V3Or31 {
            preamble_index: u8,
            preamble_index_mask: u8,
            preamble_power_offset: i16,
        },
        #[deku(id = "0x32")]
        V32 {
            preamble_index: u8,
            preamble_index_mask: u8,
            preamble_power_offset: i16,
            unk1: u16,
            group: i8,
        },
    }

    impl Msg1 {
        pub fn get_preamble_index(&self) -> u8 {
            match self {
                Msg1::V2 { preamble_index, .. } => *preamble_index,
                Msg1::V3Or31 { preamble_index, .. } => *preamble_index,
                Msg1::V32 { preamble_index, .. } => *preamble_index,
            }
        }
    }

    #[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
    pub struct Msg2 {
        pub backoff: u16,
        pub result: u8,
        pub tc_rnti: u16,
        pub ta: u16,
    }

    #[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
    #[deku(ctx = "version: u8")]
    pub struct Msg3 {
        #[deku(ctx = "version")]
        pub grant: Msg3Grant,
        pub unk_grant: u16,
        pub harq_id: u8,
        pub mac_pdu: [u8; 10],
    }

    impl Msg3 {
        pub fn get_grant(&self) -> u32 {
            match self.grant {
                Msg3Grant::V1 { grant } => grant,
                Msg3Grant::V32 { grant } => grant,
            }
        }
    }

    #[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
    #[deku(ctx = "version: u8", id = "version")]
    pub enum Msg3Grant {
        #[deku(id_pat = "0..0x32")]
        V1 {
            #[deku(endian = "little", map = "Msg3Grant::map_grant")]
            grant: u32,
        },
        #[deku(id_pat = "0x32..")]
        V32 {
            #[deku(endian = "big", map = "Msg3Grant::map_grant")]
            grant: u32,
        },
    }

    impl Msg3Grant {
        fn map_grant(grant: u32) -> Result<u32, DekuError> {
            Ok(grant & 0xfffff)
        }
    }

    #[derive(DekuRead, DekuWrite, Debug, Clone, PartialEq)]
    #[deku(ctx = "version: u8", id = "version")]
    pub enum AttemptHeader {
        #[deku(id = 0x02)]
        V2 {
            num_attempt: u8,
            rach_result: u8,
            contention: u8,
            msg_bitmask: u8,
        },
        #[deku(id_pat = "0x03 | 0x31 | 0x32")]
        V3 {
            sub_id: u8,
            cell_id: u8,
            num_attempt: u8,
            rach_result: u8,
            contention: u8,
            msg_bitmask: u8,
        },
    }

    impl AttemptHeader {
        fn get_bitmask(&self) -> u8 {
            match self {
                AttemptHeader::V2 { msg_bitmask, .. } => *msg_bitmask,
                AttemptHeader::V3 { msg_bitmask, .. } => *msg_bitmask,
            }
        }

        pub fn has_msg1(&self) -> bool {
            self.get_bitmask() & 0x01 > 0
        }

        pub fn has_msg2(&self) -> bool {
            self.get_bitmask() & 0x02 > 0
        }

        pub fn has_msg3(&self) -> bool {
            self.get_bitmask() & 0x04 > 0
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    //! These tests were adapted from SCAT's MAC RACH parser's unit tests,
    //! and the values were produced by modifying the tests to output the
    //! entire parsed struct rather than the hexlified gsmtap packets. See
    //! the changes in this commit for more info:
    //! https://github.com/wgreenberg/scat/commit/adb21575832b4f3b30c8f2aaca9ee843ef74f38b

    use super::*;
    use crate::diag::diaglog::mac::rach::{AdditionalInfo, AttemptHeader, Msg1, Msg2, Msg3};
    use crate::{diag::diaglog::mac::rach::Msg3Grant, test_util::unhexlify};

    use std::io::Seek;

    pub fn mac_rach_test_packets_from_scat() -> Vec<Packet> {
        // test data from SCAT unit tests: https://github.com/fgsect/scat/blob/9763cb5b1dcd5ee980f5b0ead9a8d520c8c51a51/tests/test_diagltelogparser.py#L129
        vec![
            parse_rach_packet(
                "0101a06906022400010001071BFF98FF000001231A0400181C010007000600465C80BD0648000000",
            ),
            parse_rach_packet(
                "0101a0690603280001000100010718ffa4ff000001c6610b00b4a2000012000120061f423f8d95075800",
            ),
            parse_rach_packet(
                "0101739e063134000100010000033f0098ff0000013c6b070058ac010007000000468f47e2d446000000644b0000180001000000d5040000",
            ),
            parse_rach_packet(
                "01010000063134000100010001070aff98ff0000011c48070018e2000007000000523b7dfd69b6000000f5540000ff0001000000d6040000",
            ),
            parse_rach_packet(
                "01010000063238000100010000032900a4ffeb000000000195b603000000a0b412000420061f425dc9be41b800885e000017000100000065050000",
            ),
            parse_rach_packet(
                "010100000632380001000100010713ffa0ffeb0000000001ad5a0500000146b412000420061f425dc9be41b400665300001800010000001a050000",
            ),
        ]
    }

    fn parse_rach_packet(bytes_str: &str) -> Packet {
        let (total_size, mut reader) = unhexlify(bytes_str);
        let packet = Packet::from_reader_with_ctx(&mut reader, total_size as u16).unwrap();
        let leftover_bits = reader.rest().len();
        let leftover_bytes = total_size - reader.stream_position().unwrap() as usize;
        assert_eq!(leftover_bytes, 0);
        assert_eq!(leftover_bits, 0);
        packet
    }

    fn assert_rach_subpacket(
        packet: &Packet,
        header: AttemptHeader,
        msg1: Option<Msg1>,
        msg2: Option<Msg2>,
        msg3: Option<Msg3>,
        additional_info: Option<AdditionalInfo>,
    ) {
        assert_eq!(packet.version, 0x01);
        assert_eq!(packet.subpackets().len(), 1);
        if let SubpacketBody::RachAttempt(attempt) = &packet.subpackets()[0].body {
            assert_eq!(attempt.header, header);
            assert_eq!(attempt.get_msg1(), msg1.as_ref());
            assert_eq!(attempt.get_msg2(), msg2.as_ref());
            assert_eq!(attempt.get_msg3(), msg3.as_ref());
            assert_eq!(attempt.additional_info, additional_info);
        } else {
            panic!("not rach attempt {:?}", packet.subpackets()[0].body);
        }
    }

    fn parse_dl(hex: &str) -> DlTransportBlock {
        let (total_size, mut reader) = unhexlify(hex);
        let block = DlTransportBlock::from_reader_with_ctx(&mut reader, total_size as u16).unwrap();
        let consumed = reader.stream_position().unwrap() as usize;
        assert_eq!(consumed, total_size, "left bytes unread");
        block
    }

    /// Synthetic 0x31 block: header, 532 bytes of statistics, `entries`.
    fn dl_v31(num_entries: u16, entries: &str) -> String {
        format!(
            "31000000{}0000{}{entries}",
            hex_u16(num_entries),
            "00".repeat(532)
        )
    }

    fn hex_u16(v: u16) -> String {
        v.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn mac_dl_v31_keeps_statistics_and_entries() {
        let block = parse_dl(&dl_v31(2, "0102030405060708"));
        assert_eq!(block.version, 0x31);
        assert_eq!(block.num_entries(), Some(2));
        assert!(block.subpackets().is_empty());
        let DlTransportBlockBody::V31 {
            cell_stats,
            entries,
            ..
        } = block.body
        else {
            panic!("expected V31");
        };
        assert_eq!(cell_stats.len(), 532);
        assert_eq!(entries, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn mac_dl_v32_has_no_statistics_block() {
        let block = parse_dl(&format!("32000000{}0000aabbccdd", hex_u16(3)));
        assert_eq!(block.num_entries(), Some(3));
        let DlTransportBlockBody::V32 { entries, .. } = block.body else {
            panic!("expected V32");
        };
        assert_eq!(entries, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn mac_dl_v1_is_the_subpacket_container() {
        // The first SCAT RACH vector is a version 1 container too.
        let hex =
            "0101a06906022400010001071BFF98FF000001231A0400181C010007000600465C80BD0648000000";
        let block = parse_dl(hex);
        assert_eq!(block.subpackets().len(), 1);
        assert_eq!(block.num_entries(), None);
        assert_eq!(block.subpackets(), parse_rach_packet(hex).subpackets());
    }

    #[test]
    fn mac_dl_unknown_version_is_kept_as_bytes() {
        let block = parse_dl("33010203");
        assert_eq!(
            block.body,
            DlTransportBlockBody::Unsupported {
                data: vec![1, 2, 3]
            }
        );
    }

    #[test]
    fn test_rach_attempt_parsing() {
        let test_packets = mac_rach_test_packets_from_scat();
        assert_rach_subpacket(
            &test_packets[0],
            rach::AttemptHeader::V2 {
                num_attempt: 1,
                rach_result: 0,
                contention: 1,
                msg_bitmask: 7,
            },
            Some(Msg1::V2 {
                preamble_index: 27,
                preamble_index_mask: 255,
                preamble_power_offset: -104,
            }),
            Some(Msg2 {
                backoff: 0,
                result: 1,
                tc_rnti: 6691,
                ta: 4,
            }),
            Some(Msg3 {
                grant: Msg3Grant::V1 { grant: 72728 },
                unk_grant: 7,
                harq_id: 6,
                mac_pdu: [0x00, 0x46, 0x5c, 0x80, 0xbd, 0x06, 0x48, 0x00, 0x00, 0x00],
            }),
            None,
        );

        assert_rach_subpacket(
            &test_packets[1],
            rach::AttemptHeader::V3 {
                sub_id: 1,
                cell_id: 0,
                num_attempt: 1,
                rach_result: 0,
                contention: 1,
                msg_bitmask: 7,
            },
            Some(Msg1::V3Or31 {
                preamble_index: 24,
                preamble_index_mask: 255,
                preamble_power_offset: -92,
            }),
            Some(Msg2 {
                backoff: 0,
                result: 1,
                tc_rnti: 25030,
                ta: 11,
            }),
            Some(Msg3 {
                grant: Msg3Grant::V1 { grant: 41652 },
                unk_grant: 18,
                harq_id: 1,
                mac_pdu: [0x20, 0x06, 0x1f, 0x42, 0x3f, 0x8d, 0x95, 0x07, 0x58, 0x00],
            }),
            None,
        );

        assert_rach_subpacket(
            &test_packets[2],
            rach::AttemptHeader::V3 {
                sub_id: 1,
                cell_id: 0,
                num_attempt: 1,
                rach_result: 0,
                contention: 0,
                msg_bitmask: 3,
            },
            Some(Msg1::V3Or31 {
                preamble_index: 63,
                preamble_index_mask: 0,
                preamble_power_offset: -104,
            }),
            Some(Msg2 {
                backoff: 0,
                result: 1,
                tc_rnti: 27452,
                ta: 7,
            }),
            None,
            Some(AdditionalInfo {
                ul_earfcn: 19300,
                p_max: 24,
                scell_id: 0,
                unk1: 1,
                unk2: 1237,
            }),
        );

        assert_rach_subpacket(
            &test_packets[3],
            AttemptHeader::V3 {
                sub_id: 1,
                cell_id: 0,
                num_attempt: 1,
                rach_result: 0,
                contention: 1,
                msg_bitmask: 7,
            },
            Some(Msg1::V3Or31 {
                preamble_index: 10,
                preamble_index_mask: 255,
                preamble_power_offset: -104,
            }),
            Some(Msg2 {
                backoff: 0,
                result: 1,
                tc_rnti: 18460,
                ta: 7,
            }),
            Some(Msg3 {
                grant: Msg3Grant::V1 { grant: 57880 },
                unk_grant: 7,
                harq_id: 0,
                mac_pdu: [0x00, 0x52, 0x3b, 0x7d, 0xfd, 0x69, 0xb6, 0x00, 0x00, 0x00],
            }),
            Some(AdditionalInfo {
                ul_earfcn: 21749,
                p_max: 255,
                scell_id: 0,
                unk1: 1,
                unk2: 1238,
            }),
        );

        assert_rach_subpacket(
            &test_packets[4],
            AttemptHeader::V3 {
                sub_id: 1,
                cell_id: 0,
                num_attempt: 1,
                rach_result: 0,
                contention: 0,
                msg_bitmask: 3,
            },
            Some(Msg1::V32 {
                preamble_index: 41,
                preamble_index_mask: 0,
                preamble_power_offset: -92,
                unk1: 235,
                group: 0,
            }),
            Some(Msg2 {
                backoff: 0,
                result: 1,
                tc_rnti: 46741,
                ta: 3,
            }),
            None,
            Some(AdditionalInfo {
                ul_earfcn: 24200,
                p_max: 23,
                scell_id: 0,
                unk1: 1,
                unk2: 1381,
            }),
        );

        assert_rach_subpacket(
            &test_packets[5],
            AttemptHeader::V3 {
                sub_id: 1,
                cell_id: 0,
                num_attempt: 1,
                rach_result: 0,
                contention: 1,
                msg_bitmask: 7,
            },
            Some(Msg1::V32 {
                preamble_index: 19,
                preamble_index_mask: 255,
                preamble_power_offset: -96,
                unk1: 235,
                group: 0,
            }),
            Some(Msg2 {
                backoff: 0,
                result: 1,
                tc_rnti: 23213,
                ta: 5,
            }),
            Some(Msg3 {
                grant: Msg3Grant::V32 { grant: 83636 },
                unk_grant: 18,
                harq_id: 4,
                mac_pdu: [0x20, 0x06, 0x1f, 0x42, 0x5d, 0xc9, 0xbe, 0x41, 0xb4, 0x00],
            }),
            Some(AdditionalInfo {
                ul_earfcn: 21350,
                p_max: 24,
                scell_id: 0,
                unk1: 1,
                unk2: 1306,
            }),
        );
    }
}
