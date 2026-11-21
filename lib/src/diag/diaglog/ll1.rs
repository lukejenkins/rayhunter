use deku::prelude::*;

/// Qualcomm emits several incompatible layouts under log code 0xb114, tagged by
/// a leading version byte. Upstream implements version 1 and asserts on it,
/// which turns every other version into a hard parse failure for the whole
/// message.
///
/// The Inseego M2100 (Qualcomm SDX55) emits version 161 (0xa1). In one 16-hour
/// capture that was 29,332 failures -- 98.9% of every skipped message --
/// producing a 186MB error log from a 14.9MB source and filling the device's
/// rootfs. Version 0xa1 is now decoded ([`VA1`]); any other unrecognised
/// version is kept as opaque bytes rather than failing, so it leaves the error
/// path and the payload is retained in case the layout is ever worked out.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "hdr_len: u16")]
pub struct ServingCellTiming {
    pub version: u8,
    #[deku(ctx = "*version, hdr_len.saturating_sub(1)")]
    pub body: ServingCellTimingBody,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "version: u8, len: u16", id = "version")]
pub enum ServingCellTimingBody {
    #[deku(id = "1")]
    V1(V1),
    #[deku(id = "0xa1")]
    VA1(VA1),
    /// Unknown layout, not unknown data -- keep the bytes.
    #[deku(id_pat = "_")]
    Unsupported {
        #[deku(count = "len")]
        data: Vec<u8>,
    },
}

/// Version 1. `num_records` may be 0: some modems (seen on an MDM9207) send
/// a header-only log with the timing fields filled in and no records.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(bit_order = "lsb")]
pub struct V1 {
    #[deku(bits = 5, assert = "(0..=20).contains(num_records)")]
    pub num_records: u8,
    #[deku(bits = 4, assert = "*starting_sub_fn <= 9")]
    pub starting_sub_fn: u8,
    #[deku(
        bits = 10,
        pad_bits_after = "5",
        assert = "*starting_system_fn <= 1023"
    )]
    pub starting_system_fn: u16,
    #[deku(
        bits = 19,
        pad_bits_after = "13",
        assert = "*starting_dl_frame_timing_offs <= 307200"
    )]
    pub starting_dl_frame_timing_offs: u32, // in Ts units
    #[deku(bits = 19, assert = "*starting_ul_frame_timing_offs <= 307200")]
    pub starting_ul_frame_timing_offs: u32, // in Ts units
    #[deku(bits = 11, pad_bits_after = "2")]
    pub starting_ul_timing_advance: u16, // in 16 Ts units
    #[deku(count = "num_records")]
    pub timing_adjustment: Vec<TimingAdjustment>,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(bit_order = "lsb", ctx = "_: deku::ctx::Order")]
pub struct TimingAdjustment {
    #[deku(
        bits = 11,
        assert = "(-512..=511).contains(dl_frame_timing_adjustment)"
    )]
    pub dl_frame_timing_adjustment: i16, // in Ts units
    #[deku(bits = 5, assert = "(-16..=15).contains(ul_frame_timing_adjustment)")]
    pub ul_frame_timing_adjustment: i8, // in Ts units
    #[deku(assert = "(-128..=127).contains(timing_advance)")]
    pub timing_advance: i8, // in 16 Ts units
}

/// Version 0xa1, sent by SDX55-class modems (Inseego M2100, Orbic R500L5): a
/// 16-byte header (counting the version byte) followed by `num_records`
/// 48-byte records. The frame number moved from the header into each record.
///
/// Across consecutive logs, `ul_frame_timing` advances by the sum of the
/// previous log's `ul_frame_timing_adjustment` values in 94% of the pairs
/// where either side is non-zero (62% for the DL pair), so those names follow
/// the version 1 field order. `adjustment2` and the `unknown_*` fields are not
/// pinned down.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(bit_order = "lsb")]
pub struct VA1 {
    #[deku(bits = 5, assert = "(1..=20).contains(num_records)")]
    pub num_records: u8,
    #[deku(bits = 3)]
    pub unknown_flags: u8,
    pub unknown_i16: i16,
    pub dl_frame_timing: u16,
    pub ul_frame_timing: u16,
    pub unknown_counter1: u32,
    pub unknown_counter2: u32,
    #[deku(count = "num_records")]
    pub records: Vec<TimingRecordVA1>,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(bit_order = "lsb", ctx = "_: deku::ctx::Order")]
pub struct TimingRecordVA1 {
    #[deku(bits = 10, assert = "*system_fn <= 1023")]
    pub system_fn: u16,
    #[deku(bits = 4, pad_bits_after = "2", assert = "*sub_fn <= 9")]
    pub sub_fn: u8,
    pub dl_frame_timing_adjustment: i16,
    pub ul_frame_timing_adjustment: i16,
    pub adjustment2: i16,
    pub unknown: [u8; 40],
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::diag::diaglog::LogBody;
    use crate::test_util::unhexlify;
    use std::io::Seek;

    fn parse(hexlified_bytes: &str) -> Result<ServingCellTiming, DekuError> {
        let (total_size, mut reader) = unhexlify(hexlified_bytes);
        match LogBody::from_reader_with_ctx(&mut reader, (0xb114, total_size as u16))? {
            LogBody::LteLl1ServingCellTiming { data } => {
                let consumed = reader.stream_position().unwrap() as usize;
                assert_eq!(consumed, total_size, "left bytes unread");
                Ok(data)
            }
            other => panic!("expected ServingCellTiming, got {other:?}"),
        }
    }

    /// One synthetic 48-byte 0xa1 record: frame number and subframe packed
    /// into the first u16, three i16 adjustments, then 40 opaque bytes.
    fn va1_record(system_fn: u16, sub_fn: u16, dl: i16, ul: i16, adj2: i16) -> String {
        let packed = system_fn | (sub_fn << 10);
        let mut bytes = packed.to_le_bytes().to_vec();
        for v in [dl, ul, adj2] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend(std::iter::repeat_n(0xaa, 40));
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A synthetic 0xa1 log: version, num_records (low 5 bits), unknown_i16,
    /// DL and UL frame timing, two counters, then the records.
    fn va1_log(records: &[String]) -> String {
        let mut hex = format!("a1{:02x}", records.len());
        hex += "1200"; // unknown_i16 = 18
        hex += "0010"; // dl_frame_timing = 0x1000
        hex += "0110"; // ul_frame_timing = 0x1001
        hex += "01000000"; // unknown_counter1 = 1
        hex += "02000000"; // unknown_counter2 = 2
        for r in records {
            hex += r;
        }
        hex
    }

    #[test]
    fn va1_decodes_the_header_and_every_record() {
        let log = va1_log(&[va1_record(100, 3, 1, -1, 0), va1_record(101, 9, -2, 2, 7)]);
        let ServingCellTiming {
            version: 0xa1,
            body: ServingCellTimingBody::VA1(v),
        } = parse(&log).unwrap()
        else {
            panic!("expected VA1");
        };
        assert_eq!(v.num_records, 2);
        assert_eq!(v.unknown_i16, 18);
        assert_eq!((v.dl_frame_timing, v.ul_frame_timing), (0x1000, 0x1001));
        assert_eq!((v.unknown_counter1, v.unknown_counter2), (1, 2));
        let fields: Vec<_> = v
            .records
            .iter()
            .map(|r| {
                (
                    r.system_fn,
                    r.sub_fn,
                    r.dl_frame_timing_adjustment,
                    r.ul_frame_timing_adjustment,
                    r.adjustment2,
                )
            })
            .collect();
        assert_eq!(fields, vec![(100, 3, 1, -1, 0), (101, 9, -2, 2, 7)]);
        assert!(v.records.iter().all(|r| r.unknown == [0xaa; 40]));
    }

    #[test]
    fn va1_with_no_records_is_rejected() {
        assert!(parse(&va1_log(&[])).is_err());
    }

    #[test]
    fn v1_may_be_header_only() {
        // num_records = 0, starting_sub_fn = 5, everything else 0.
        let ServingCellTiming {
            body: ServingCellTimingBody::V1(v),
            ..
        } = parse("01a000000000000000000000").unwrap()
        else {
            panic!("expected V1");
        };
        assert_eq!(v.num_records, 0);
        assert_eq!(v.starting_sub_fn, 5);
        assert!(v.timing_adjustment.is_empty());
    }

    #[test]
    fn v1_claiming_21_records_is_rejected() {
        let mut log = String::from("011500000000000000000000");
        log += &"00".repeat(21 * 3);
        assert!(parse(&log).is_err());
    }

    #[test]
    fn an_unknown_version_is_kept_as_bytes() {
        let ServingCellTiming {
            version: 0xa2,
            body: ServingCellTimingBody::Unsupported { data },
        } = parse("a2010203").unwrap()
        else {
            panic!("expected Unsupported");
        };
        assert_eq!(data, vec![1, 2, 3]);
    }
}
