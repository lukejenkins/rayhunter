use deku::prelude::*;

/// LTE LL1 serving cell frame timing (0xB114), keyed on the version byte.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8", bit_order = "lsb")]
pub enum ServingCellTiming {
    #[deku(id = "0x01")]
    V1 {
        #[deku(bits = 5, assert = "(1..=20).contains(num_records)")]
        num_records: u8,
        #[deku(bits = 4, assert = "*starting_sub_fn <= 9")]
        starting_sub_fn: u8,
        #[deku(
            bits = 10,
            pad_bits_after = "5",
            assert = "*starting_system_fn <= 1023"
        )]
        starting_system_fn: u16,
        #[deku(
            bits = 19,
            pad_bits_after = "13",
            assert = "*starting_dl_frame_timing_offs <= 307200"
        )]
        starting_dl_frame_timing_offs: u32, // in Ts units
        #[deku(bits = 19, assert = "*starting_ul_frame_timing_offs <= 307200")]
        starting_ul_frame_timing_offs: u32, // in Ts units
        #[deku(bits = 11, pad_bits_after = "2")]
        starting_ul_timing_advance: u16, // in 16 Ts units
        #[deku(count = "num_records")]
        timing_adjustment: Vec<TimingAdjustment>,
    },
    /// Sent by SDX55-class modems, e.g. the Orbic R500L5. A 16-byte header
    /// followed by `num_records` 48-byte records; the frame number moved from
    /// the header into each record.
    ///
    /// Field semantics were checked against consecutive logs from an R500L5.
    /// Across adjacent logs, `ul_frame_timing` advances by the sum of the
    /// previous log's `ul_frame_timing_adjustment` values in 94% of the pairs
    /// where either side is non-zero (62% for the DL pair), so those names
    /// follow the V1 field order. `adjustment2` and the unknown header fields
    /// are not pinned down: `unknown_i16` usually moves by twice the sum of
    /// `adjustment2`, which is suggestive of a timing advance but not proof.
    #[deku(id = "0xa1")]
    VA1 {
        #[deku(bits = 5, assert = "(1..=20).contains(num_records)")]
        num_records: u8,
        #[deku(bits = 3)]
        unknown_flags: u8,
        unknown_i16: i16,
        dl_frame_timing: u16,
        ul_frame_timing: u16,
        unknown_counter1: u32,
        unknown_counter2: u32,
        #[deku(count = "num_records")]
        records: Vec<TimingRecordVA1>,
    },
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

    // Orbic RC400L (MDM9207): a 20-record v0x01 log with +-1 adjustments.
    const RC400L_V1_20_RECORDS: &str = "0154d2026fff01006fff0100000000ffff00000000010800ffff00010800ffff0001080000f800000000000000000000000000000000000000010800ffff0001080000f800000000";

    // Orbic R500L5 (SDX55), fw ORB500L5_V2.0.4.3_BVZRT: v0xA1 logs.
    const R500L5_VA1_2_RECORDS: &str = "a10212006f3edc3d6f9e4f05dc1550055d240000000000000f000000fedc9000a880ca40ec18000076ddfeff7d57aaaa5c7a66668080808000000000000000005e000100000000000f000000ff279100c0c0d540ed18000072ddfeff7b57aaaa5c7a6666808080800000000000000000";
    const R500L5_VA1_20_RECORDS: &str = concat!(
        "a13412004164a56341bced14a533ee14",
        "f926000000000000030000006cf32d00fcffff3f40160000b2f8fdff5d59aaaaea796666808000000000000000000000",
        "fa02000000000000030000006c3e2e00fc9f054040160000b2f8fdff5d59aaaaea796666808000000000000000000000",
        "fa06000000000000030000006c892e00fc3f0b4040160000b2f8fdff6359aaaae8796666808000000000000000000000",
        "fa0a000000000000030000006cd42e00fcdf104040160000b2f8fdff6359aaaae8796666000000000000000000000000",
        "fa0e000000000000030000006c1f2f00fc7f164040160000b2f8fdff6f59aaaae6796666000000000000000000000000",
        "fa12000000000000030000006c6a2f00fc1f1c4040160000b2f8fdff6859aaaae6796666000000000000000000000000",
        "fa16000000000000030000006cb52f00fcbf214040160000b2f8fdff6159aaaae8796666000000000000000000000000",
        "fa1a000000000000030000006c003000fc5f274040160000b2f8fdff5c59aaaaea796666000000000000000000000000",
        "fa1e000000000000030000006b4b3000fcff2c4040160000b2f8fdff5b59aaaaea796666808000000000000000000000",
        "1a030c00180000000300000061fe8b000c0000404716000000f8fdff5559aaaaec796666808000000000000000000000",
        "1a07ffffe7ff00000300000061498c0000a005404716000000f8fdff5559aaaaec796666808000000000000000000000",
        "1a0b0000000000000300000061948c0000400b404716000000f8fdff5159aaaaec796666808000000000000000000000",
        "1a0f0000000000000300000061df8c0000e010404716000000f8fdff5159aaaaec796666000000000000000000000000",
        "1a1300000000000003000000612a8d00008016404716000000f8fdff4d59aaaaee796666000000000000000000000000",
        "1a170000000000000300000061758d0000201c404716000000f8fdff5159aaaaec796666000000000000000000000000",
        "1a1b0000000000000300000060c08d0000c021404716000000f8fdff4c59aaaaee796666000000000000000000000000",
        "1a1f00000000000003000000600b8e00006027404716000000f8fdff4f59aaaaec796666000000000000000000000000",
        "1a2300000000ffff0300000060568e0000002d404716000000f8fdff4f59aaaaec796666808000000000000000000000",
        "7927010003000100030000002cf3a400fcffff3f4416000059f8fdff4f59aaaaec796666808000000000000000000000",
        "7a03000000000000030000002c3ea500fc9f05404416000059f8fdff4f59aaaaec796666808000000000000000000000",
    );

    fn parse(hexlified_bytes: &str) -> ServingCellTiming {
        let (total_size, mut reader) = unhexlify(hexlified_bytes);
        match LogBody::from_reader_with_ctx(&mut reader, (0xb114, 0)) {
            Ok(LogBody::LteLl1ServingCellTiming { data }) => {
                if !reader.end() {
                    let leftover_bytes = total_size - reader.stream_position().unwrap() as usize;
                    panic!("failed to read entire buffer ({leftover_bytes} bytes left)");
                }
                data
            }
            Ok(x) => panic!("expected ServingCellTiming, but parsed {:?}", x),
            Err(x) => panic!("failed to parse ServingCellTiming {:?}", x),
        }
    }

    fn va1_record(
        system_fn: u16,
        sub_fn: u8,
        dl: i16,
        ul: i16,
        adjustment2: i16,
        record_hex: &str,
    ) -> (u16, u8, i16, i16, i16, Vec<u8>) {
        let bytes: Vec<u8> = (16..record_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&record_hex[i..i + 2], 16).unwrap())
            .collect();
        (system_fn, sub_fn, dl, ul, adjustment2, bytes)
    }

    #[test]
    fn test_v1_is_unchanged() {
        let ServingCellTiming::V1 {
            num_records,
            starting_sub_fn,
            starting_system_fn,
            starting_dl_frame_timing_offs,
            starting_ul_frame_timing_offs,
            starting_ul_timing_advance,
            timing_adjustment,
        } = parse(RC400L_V1_20_RECORDS)
        else {
            panic!("expected V1");
        };
        assert_eq!(num_records, 20);
        assert_eq!(starting_sub_fn, 2);
        assert_eq!(starting_system_fn, 361);
        assert_eq!(starting_dl_frame_timing_offs, 130927);
        assert_eq!(starting_ul_frame_timing_offs, 130927);
        assert_eq!(starting_ul_timing_advance, 0);
        let adjustments: Vec<(i16, i8, i8)> = timing_adjustment
            .iter()
            .map(|a| {
                (
                    a.dl_frame_timing_adjustment,
                    a.ul_frame_timing_adjustment,
                    a.timing_advance,
                )
            })
            .collect();
        assert_eq!(
            adjustments,
            vec![
                (0, 0, 0),
                (-1, -1, 0),
                (0, 0, 0),
                (1, 1, 0),
                (-1, -1, 0),
                (1, 1, 0),
                (-1, -1, 0),
                (1, 1, 0),
                (0, -1, 0),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
                (1, 1, 0),
                (-1, -1, 0),
                (1, 1, 0),
                (0, -1, 0),
                (0, 0, 0),
            ]
        );
    }

    #[test]
    fn test_va1_two_records() {
        let ServingCellTiming::VA1 {
            num_records,
            unknown_flags,
            unknown_i16,
            dl_frame_timing,
            ul_frame_timing,
            unknown_counter1,
            unknown_counter2,
            records,
        } = parse(R500L5_VA1_2_RECORDS)
        else {
            panic!("expected VA1");
        };
        assert_eq!(num_records, 2);
        assert_eq!(unknown_flags, 0);
        assert_eq!(unknown_i16, 18);
        assert_eq!(dl_frame_timing, 15983);
        assert_eq!(ul_frame_timing, 15836);
        assert_eq!(unknown_counter1, 89103983);
        assert_eq!(unknown_counter2, 89134556);
        let expected = [
            va1_record(
                93,
                9,
                0,
                0,
                0,
                "5d240000000000000f000000fedc9000a880ca40ec18000076ddfeff7d57aaaa5c7a6666808080800000000000000000",
            ),
            va1_record(
                94,
                0,
                1,
                0,
                0,
                "5e000100000000000f000000ff279100c0c0d540ed18000072ddfeff7b57aaaa5c7a6666808080800000000000000000",
            ),
        ];
        assert_eq!(records.len(), expected.len());
        for (record, (system_fn, sub_fn, dl, ul, adjustment2, unknown)) in
            records.iter().zip(expected)
        {
            assert_eq!(record.system_fn, system_fn);
            assert_eq!(record.sub_fn, sub_fn);
            assert_eq!(record.dl_frame_timing_adjustment, dl);
            assert_eq!(record.ul_frame_timing_adjustment, ul);
            assert_eq!(record.adjustment2, adjustment2);
            assert_eq!(record.unknown.to_vec(), unknown);
        }
    }

    #[test]
    fn test_va1_twenty_records_with_flags_and_signed_adjustments() {
        let ServingCellTiming::VA1 {
            num_records,
            unknown_flags,
            dl_frame_timing,
            ul_frame_timing,
            records,
            ..
        } = parse(R500L5_VA1_20_RECORDS)
        else {
            panic!("expected VA1");
        };
        assert_eq!(num_records, 20);
        assert_eq!(unknown_flags, 1);
        assert_eq!(dl_frame_timing, 25665);
        assert_eq!(ul_frame_timing, 25509);
        assert_eq!(records.len(), 20);
        assert_eq!((records[0].system_fn, records[0].sub_fn), (761, 9));
        assert_eq!((records[19].system_fn, records[19].sub_fn), (890, 0));
        let nonzero: Vec<(u16, u8, i16, i16, i16)> = records
            .iter()
            .filter(|r| {
                r.dl_frame_timing_adjustment != 0
                    || r.ul_frame_timing_adjustment != 0
                    || r.adjustment2 != 0
            })
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
        assert_eq!(
            nonzero,
            vec![
                (794, 0, 12, 24, 0),
                (794, 1, -1, -25, 0),
                (794, 8, 0, 0, -1),
                (889, 9, 1, 3, 1),
            ]
        );
    }

    #[test]
    fn test_va1_rejects_a_truncated_record() {
        let truncated = &R500L5_VA1_2_RECORDS[..R500L5_VA1_2_RECORDS.len() - 2];
        let (_, mut reader) = unhexlify(truncated);
        assert!(LogBody::from_reader_with_ctx(&mut reader, (0xb114, 0),).is_err());
    }

    #[test]
    fn test_unknown_version_is_still_rejected() {
        let mut other = String::from("a2");
        other.push_str(&R500L5_VA1_2_RECORDS[2..]);
        let (_, mut reader) = unhexlify(&other);
        assert!(LogBody::from_reader_with_ctx(&mut reader, (0xb114, 0),).is_err());
    }
}
