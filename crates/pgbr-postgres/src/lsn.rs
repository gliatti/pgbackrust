//! Log Sequence Number (LSN) parsing and WAL-segment-name derivation.
//!
//! A `PostgreSQL` LSN is a 64-bit byte position in the write-ahead log,
//! rendered in text as two `/`-separated hex halves: `XXXXXXXX/YYYYYYYY`,
//! where the upper half is the high 32 bits and the lower half the low 32
//! bits (e.g. `0/16B3E40`, `1/0`). `pg_backup_start` / `pg_backup_stop`
//! (and their pre-15 `pg_start_backup` / `pg_stop_backup` predecessors)
//! return such a string; pgBackRest records both the raw LSN and the name
//! of the WAL segment that contains it.
//!
//! A WAL segment file is named with 24 hex digits: the 8-digit timeline id
//! followed by the segment number split into a high half and a low half,
//! each 8 digits. The segment number is `lsn / wal_segment_size`; with the
//! default 16 MiB segment the low half of the name is
//! `(low_32_bits_of_lsn) / wal_segment_size` and the high half is the upper
//! 32 bits of the LSN. C reference: `pgLsnToWalSegment()` in
//! `src/postgres/interface.c` and `walSegmentName()` in
//! `src/command/archive/common.c`.

/// Default WAL segment size, 16 MiB. Used when `pg_control` does not (yet)
/// surface the cluster's configured `wal_segment_size`.
pub const WAL_SEGMENT_SIZE_DEFAULT: u64 = 16 * 1024 * 1024;

/// Parse a textual `PostgreSQL` LSN (`"XXXXXXXX/YYYYYYYY"`) into its 64-bit
/// value.
///
/// Both halves are interpreted as hexadecimal (case-insensitive); the upper
/// half occupies the high 32 bits, the lower half the low 32 bits. Leading /
/// trailing ASCII whitespace is tolerated (libpq returns the value as plain
/// text). Returns `None` when the string is not exactly two `/`-separated hex
/// fields, when either field is empty, or when either overflows 32 bits.
#[must_use]
pub fn parse_lsn(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    let (hi_str, lo_str) = trimmed.split_once('/')?;
    if hi_str.is_empty() || lo_str.is_empty() {
        return None;
    }
    let hi = u32::from_str_radix(hi_str, 16).ok()?;
    let lo = u32::from_str_radix(lo_str, 16).ok()?;
    Some((u64::from(hi) << 32) | u64::from(lo))
}

/// Render a 64-bit LSN back to its canonical `"XXXXXXXX/YYYYYYYY"` text form.
///
/// pgBackRest renders the two halves with no leading zeroes and uppercase hex
/// (matching `PostgreSQL`'s `%X/%X` formatting), e.g. `0/16B3E40`, `1/0`.
#[must_use]
pub fn lsn_to_string(lsn: u64) -> String {
    let hi = (lsn >> 32) & 0xFFFF_FFFF;
    let lo = lsn & 0xFFFF_FFFF;
    format!("{hi:X}/{lo:X}")
}

/// Derive the 24-hex-digit WAL segment file name that contains `lsn` on
/// `timeline`, given the cluster's `wal_segment_size`.
///
/// The name is `TTTTTTTT` (timeline, 8 hex) + `HHHHHHHH` (the high 32 bits of
/// the LSN, 8 hex) + `LLLLLLLL` (the low 32 bits divided by `wal_segment_size`,
/// 8 hex). With the default 16 MiB segment this matches `PostgreSQL`'s
/// `XLogFileName(tli, segno)` where `segno = lsn / wal_segment_size` (the high
/// half of the segment number equals the high 32 bits of the LSN, since a 4 GiB
/// "logical xlog file" holds an exact number of equally-sized segments).
///
/// A `wal_segment_size` of 0 is treated as the 16 MiB default so the function
/// is total (an unconfigured size never panics or divides by zero).
#[must_use]
pub fn lsn_to_wal_segment(timeline: u32, lsn: u64, wal_segment_size: u64) -> String {
    let seg_size = if wal_segment_size == 0 {
        WAL_SEGMENT_SIZE_DEFAULT
    } else {
        wal_segment_size
    };
    let hi = (lsn >> 32) & 0xFFFF_FFFF;
    let lo = lsn & 0xFFFF_FFFF;
    // The low half of the segment number: the byte position within the 4 GiB
    // logical file, divided by the segment size. seg_size divides 4 GiB evenly
    // for every supported size (1 MiB .. 1 GiB, all powers of two), so this is
    // the canonical XLogFileName low component.
    let lo_segment = lo / seg_size;
    format!("{timeline:08X}{hi:08X}{lo_segment:08X}")
}

/// Parse a textual LSN and derive its WAL segment name on `timeline` in one
/// step. Returns `None` when [`parse_lsn`] rejects the text.
#[must_use]
pub fn lsn_text_to_wal_segment(timeline: u32, lsn_text: &str, wal_segment_size: u64) -> Option<String> {
    let lsn = parse_lsn(lsn_text)?;
    Some(lsn_to_wal_segment(timeline, lsn, wal_segment_size))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_lsn_decodes_two_hex_halves() {
        assert_eq!(parse_lsn("0/0"), Some(0));
        assert_eq!(parse_lsn("0/16B3E40"), Some(0x016B_3E40));
        // Upper half occupies the high 32 bits.
        assert_eq!(parse_lsn("1/0"), Some(1 << 32));
        assert_eq!(parse_lsn("2/30"), Some((2 << 32) | 0x30));
        // Case-insensitive and whitespace-tolerant (libpq text).
        assert_eq!(parse_lsn("  A/ff  "), Some((0xA << 32) | 0xFF));
        assert_eq!(parse_lsn("ffffffff/ffffffff"), Some(u64::MAX));
    }

    #[test]
    fn parse_lsn_rejects_malformed() {
        assert_eq!(parse_lsn(""), None);
        assert_eq!(parse_lsn("16B3E40"), None, "no slash");
        assert_eq!(parse_lsn("/40"), None, "empty high half");
        assert_eq!(parse_lsn("16/"), None, "empty low half");
        assert_eq!(parse_lsn("zz/40"), None, "non-hex high half");
        assert_eq!(parse_lsn("0/zz"), None, "non-hex low half");
        assert_eq!(parse_lsn("100000000/0"), None, "high half overflows 32 bits");
        assert_eq!(parse_lsn("0/100000000"), None, "low half overflows 32 bits");
    }

    #[test]
    fn lsn_to_string_round_trips() {
        for raw in ["0/0", "0/16B3E40", "1/0", "2/30", "A/FF", "FFFFFFFF/FFFFFFFF"] {
            let lsn = parse_lsn(raw).expect("parse");
            assert_eq!(lsn_to_string(lsn), raw.to_uppercase());
        }
    }

    #[test]
    fn lsn_to_wal_segment_default_16mib() {
        // 0/16B3E40 on timeline 1, 16 MiB segments. The low half of the LSN is
        // 0x016B3E40 = 23804480, / 16 MiB (0x01000000) = 1, so segment ...00000001.
        assert_eq!(
            lsn_to_wal_segment(1, 0x016B_3E40, WAL_SEGMENT_SIZE_DEFAULT),
            "000000010000000000000001"
        );
        // The very start of timeline 1: 0/0 -> ...000000000.
        assert_eq!(lsn_to_wal_segment(1, 0, WAL_SEGMENT_SIZE_DEFAULT), "000000010000000000000000");
        // An LSN with a non-zero high half: 1/0 -> high component 00000001.
        assert_eq!(
            lsn_to_wal_segment(1, 1 << 32, WAL_SEGMENT_SIZE_DEFAULT),
            "000000010000000100000000"
        );
        // The last segment of logical file 0: 0/FF000000 -> low component 000000FF.
        assert_eq!(
            lsn_to_wal_segment(1, 0xFF00_0000, WAL_SEGMENT_SIZE_DEFAULT),
            "0000000100000000000000FF"
        );
        // A different timeline shows up in the leading 8 digits.
        assert_eq!(
            lsn_to_wal_segment(0x2A, 0, WAL_SEGMENT_SIZE_DEFAULT),
            "0000002A0000000000000000"
        );
    }

    #[test]
    fn lsn_to_wal_segment_zero_size_falls_back_to_default() {
        assert_eq!(
            lsn_to_wal_segment(1, 0x016B_3E40, 0),
            lsn_to_wal_segment(1, 0x016B_3E40, WAL_SEGMENT_SIZE_DEFAULT),
        );
    }

    #[test]
    fn lsn_to_wal_segment_non_default_size() {
        // With 1 GiB segments (0x40000000), 0/0 .. just under 1 GiB is segment 0.
        assert_eq!(lsn_to_wal_segment(1, 0x3FFF_FFFF, 0x4000_0000), "000000010000000000000000");
        // Exactly 1 GiB rolls to segment 1.
        assert_eq!(lsn_to_wal_segment(1, 0x4000_0000, 0x4000_0000), "000000010000000000000001");
    }

    #[test]
    fn lsn_text_to_wal_segment_combines_parse_and_derive() {
        assert_eq!(
            lsn_text_to_wal_segment(1, "0/16B3E40", WAL_SEGMENT_SIZE_DEFAULT),
            Some("000000010000000000000001".to_owned())
        );
        assert_eq!(lsn_text_to_wal_segment(1, "garbage", WAL_SEGMENT_SIZE_DEFAULT), None);
    }
}
