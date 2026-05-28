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

/// Size, in bytes, of a `PostgreSQL` "logical xlog file": the 4 GiB span the
/// low (`LLLLLLLL`) component of a WAL segment name addresses before the high
/// (`HHHHHHHH`) component rolls over.
///
/// A WAL segment number is split across two 32-bit halves of the file name; the
/// low half counts segments within a 4 GiB logical file and the high half counts
/// logical files. Every supported `wal_segment_size` (1 MiB .. 1 GiB, all powers
/// of two) divides this evenly, so the number of segments per logical file is
/// exactly `LOGICAL_XLOG_FILE_SIZE / wal_segment_size` (256 for the 16 MiB
/// default). C reference: `XLogSegmentsPerXLogId` in
/// `src/include/access/xlog_internal.h`.
const LOGICAL_XLOG_FILE_SIZE: u64 = 0x1_0000_0000;

/// Number of WAL segments per logical xlog file for a given `wal_segment_size`.
///
/// `LOGICAL_XLOG_FILE_SIZE / wal_segment_size` (256 for the 16 MiB default),
/// matching `PostgreSQL`'s `XLogSegmentsPerXLogId`. A `wal_segment_size` of 0 is
/// treated as the 16 MiB default so the function never divides by zero.
#[must_use]
pub const fn segments_per_logical_file(wal_segment_size: u64) -> u64 {
    let seg_size = if wal_segment_size == 0 {
        WAL_SEGMENT_SIZE_DEFAULT
    } else {
        wal_segment_size
    };
    LOGICAL_XLOG_FILE_SIZE / seg_size
}

/// Parse a 24-hex-digit WAL segment file name into its `(timeline, high, low)`
/// components.
///
/// The three components are the leading 8 hex digits (timeline), the middle 8
/// (the high half of the segment number) and the trailing 8 (the low half).
/// Returns `None` when the name is not exactly 24 ASCII-hex characters.
#[must_use]
pub fn parse_wal_segment(name: &str) -> Option<(u32, u32, u32)> {
    if name.len() != 24 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let timeline = u32::from_str_radix(&name[0..8], 16).ok()?;
    let high = u32::from_str_radix(&name[8..16], 16).ok()?;
    let low = u32::from_str_radix(&name[16..24], 16).ok()?;
    Some((timeline, high, low))
}

/// Enumerate every WAL segment file name from `start` through `stop` inclusive,
/// on the segment range's timeline, given the cluster's `wal_segment_size`.
///
/// `start` and `stop` are 24-hex-digit segment names (as produced by
/// [`lsn_to_wal_segment`]). The range walks the segment number (the
/// `(high, low)` pair) one segment at a time: the low (`LLLLLLLL`) component
/// counts within a 4 GiB logical file and rolls over to 0, incrementing the high
/// (`HHHHHHHH`) component, once it reaches `segments_per_logical_file - 1`. This
/// is exactly `PostgreSQL`'s `XLByteToSeg` / `XLogFileName` segment ordering, so
/// the enumeration covers every segment a backup needs to be made consistent
/// (`backup-archive-start` .. `backup-archive-stop`), including a roll-over
/// across the high half. C reference: the `walSegmentRange()` loop in
/// `src/command/backup/backup.c`.
///
/// Returns `None` when either name is malformed, when the two names are on
/// different timelines (a range cannot span a timeline switch), when `stop`
/// precedes `start`, or when `wal_segment_size` yields no segments per logical
/// file. The timeline embedded in every returned name is the timeline of `start`.
#[must_use]
pub fn wal_segment_range(start: &str, stop: &str, wal_segment_size: u64) -> Option<Vec<String>> {
    let (start_tli, start_hi, start_lo) = parse_wal_segment(start)?;
    let (stop_tli, stop_hi, stop_lo) = parse_wal_segment(stop)?;
    if start_tli != stop_tli {
        return None;
    }
    let per_file = segments_per_logical_file(wal_segment_size);
    if per_file == 0 {
        return None;
    }

    // Collapse each name into a single 64-bit segment number so the range is a
    // simple inclusive integer walk. The high half counts logical files (each
    // holding `per_file` segments), the low half counts segments within one.
    let start_segno = u64::from(start_hi) * per_file + u64::from(start_lo);
    let stop_segno = u64::from(stop_hi) * per_file + u64::from(stop_lo);
    if stop_segno < start_segno {
        return None;
    }

    let mut out = Vec::new();
    for segno in start_segno..=stop_segno {
        let high = u32::try_from(segno / per_file).ok()?;
        let low = u32::try_from(segno % per_file).ok()?;
        out.push(format!("{start_tli:08X}{high:08X}{low:08X}"));
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// WAL segment header
// ---------------------------------------------------------------------------

/// `XLP_LONG_HEADER` bit of `xlp_info`: set on the first page of every WAL
/// segment, marking that the page carries the long header (with the system id /
/// segment size). Mirrors `XLP_LONG_HEADER` in
/// `src/include/access/xlog_internal.h`.
const XLP_LONG_HEADER: u16 = 0x0002;

/// Byte offset of `xlp_seg_size` (u32 LE) within `XLogLongPageHeaderData`.
///
/// Layout (all little-endian, the struct is MAXALIGN=8 padded so the long
/// header begins at offset 24): `xlp_magic` u16 @0, `xlp_info` u16 @2,
/// `xlp_tli` u32 @4, `xlp_pageaddr` u64 @8, `xlp_rem_len` u32 @16, (4 bytes pad),
/// then `xlp_sysid` u64 @24, `xlp_seg_size` u32 @32, `xlp_xlog_blcksz` u32 @36.
const XLP_SYSID_OFFSET: usize = 24;
/// Byte offset of `xlp_seg_size` (u32 LE).
const XLP_SEG_SIZE_OFFSET: usize = 32;
/// Minimum bytes needed to decode the long page header (through `xlp_seg_size`).
const WAL_LONG_HEADER_LEN: usize = XLP_SEG_SIZE_OFFSET + 4;

/// `(wal_magic, major-version-label)` for every supported `PostgreSQL` release,
/// mirroring `XLOG_PAGE_MAGIC` in each release's
/// `src/include/access/xlog_internal.h`. The magic bumps every major (and
/// occasionally a minor with a WAL-format change), so it identifies the version
/// that wrote a WAL segment. Provenance matches the C tree's per-version
/// `walMagic` in `src/postgres/interface/version.vendor.h`.
const WAL_MAGIC_VERSIONS: &[(u16, &str)] = &[
    (0xD093, "9.6"),
    (0xD097, "10"),
    (0xD098, "11"),
    (0xD101, "12"),
    (0xD106, "13"),
    (0xD10D, "14"),
    (0xD110, "15"),
    (0xD113, "16"),
    (0xD116, "17"),
    (0xD117, "18"),
];

/// Decoded long page header from the first page of a WAL segment.
///
/// pgBackRest reads this on `archive-push` (`archive-header-check`) to confirm a
/// completed WAL segment belongs to the stanza's cluster before storing it. C
/// reference: `pgWalFromBuffer()` in `src/postgres/interface.c`, which decodes a
/// `PgWal { version, systemId, size }` from the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalHeader {
    /// `xlp_magic` — identifies the `PostgreSQL` version that wrote the segment.
    pub magic: u16,
    /// Major-version label the magic maps to (`"14"`, …), or `None` for an
    /// unrecognised magic.
    pub version: Option<&'static str>,
    /// `xlp_tli` — the timeline id the segment belongs to.
    pub timeline: u32,
    /// `xlp_sysid` — the cluster system identifier the segment was written by.
    pub system_id: u64,
    /// `xlp_seg_size` — the cluster's configured WAL segment size, in bytes.
    pub segment_size: u32,
}

/// Map a WAL `xlp_magic` to the `PostgreSQL` major-version label that uses it,
/// or `None` for an unrecognised magic. Mirrors the per-version `XLOG_PAGE_MAGIC`.
#[must_use]
pub fn wal_version_from_magic(magic: u16) -> Option<&'static str> {
    WAL_MAGIC_VERSIONS
        .iter()
        .find_map(|(m, label)| if *m == magic { Some(*label) } else { None })
}

/// Parse the long page header at the start of a WAL segment buffer.
///
/// `buf` must be at least the first page of the segment (the long header lives
/// in the first [`WAL_LONG_HEADER_LEN`] bytes). The first page of every WAL
/// segment carries the long header (its `xlp_info` has [`XLP_LONG_HEADER`] set);
/// this is a hard requirement, so a buffer whose first page is *not* a long
/// header is rejected. C reference: `pgWalFromBuffer()` in
/// `src/postgres/interface.c`.
///
/// Returns `None` when the buffer is too short or its first page is not a WAL
/// long-header page.
#[must_use]
pub fn parse_wal_header(buf: &[u8]) -> Option<WalHeader> {
    if buf.len() < WAL_LONG_HEADER_LEN {
        return None;
    }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    let info = u16::from_le_bytes([buf[2], buf[3]]);
    // The first page of a segment must be a long header.
    if info & XLP_LONG_HEADER == 0 {
        return None;
    }
    let timeline = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let system_id = u64::from_le_bytes([
        buf[XLP_SYSID_OFFSET],
        buf[XLP_SYSID_OFFSET + 1],
        buf[XLP_SYSID_OFFSET + 2],
        buf[XLP_SYSID_OFFSET + 3],
        buf[XLP_SYSID_OFFSET + 4],
        buf[XLP_SYSID_OFFSET + 5],
        buf[XLP_SYSID_OFFSET + 6],
        buf[XLP_SYSID_OFFSET + 7],
    ]);
    let segment_size = u32::from_le_bytes([
        buf[XLP_SEG_SIZE_OFFSET],
        buf[XLP_SEG_SIZE_OFFSET + 1],
        buf[XLP_SEG_SIZE_OFFSET + 2],
        buf[XLP_SEG_SIZE_OFFSET + 3],
    ]);
    Some(WalHeader {
        magic,
        version: wal_version_from_magic(magic),
        timeline,
        system_id,
        segment_size,
    })
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

    #[test]
    fn segments_per_logical_file_matches_postgres() {
        // 4 GiB / segment size: 256 at the 16 MiB default, scaling with the size.
        assert_eq!(segments_per_logical_file(WAL_SEGMENT_SIZE_DEFAULT), 256);
        assert_eq!(segments_per_logical_file(0), 256, "0 falls back to the default");
        assert_eq!(segments_per_logical_file(1024 * 1024), 4096, "1 MiB segments");
        assert_eq!(segments_per_logical_file(0x4000_0000), 4, "1 GiB segments");
    }

    #[test]
    fn parse_wal_segment_splits_three_components() {
        assert_eq!(parse_wal_segment("000000010000000200000003"), Some((1, 2, 3)));
        assert_eq!(parse_wal_segment("0000002A000000FF000000FE"), Some((0x2A, 0xFF, 0xFE)));
        // Wrong length / non-hex are rejected.
        assert_eq!(parse_wal_segment("00000001"), None, "too short");
        assert_eq!(parse_wal_segment("0000000100000002000000030"), None, "too long");
        assert_eq!(parse_wal_segment("00000001000000020000000g"), None, "non-hex");
    }

    #[test]
    fn wal_segment_range_single_segment() {
        // start == stop yields exactly that one segment.
        let seg = "000000010000000000000001";
        assert_eq!(
            wal_segment_range(seg, seg, WAL_SEGMENT_SIZE_DEFAULT),
            Some(vec![seg.to_owned()])
        );
    }

    #[test]
    fn wal_segment_range_consecutive_within_logical_file() {
        // 0x01 .. 0x03 within logical file 0 (16 MiB segments).
        let range = wal_segment_range(
            "000000010000000000000001",
            "000000010000000000000003",
            WAL_SEGMENT_SIZE_DEFAULT,
        )
        .expect("range");
        assert_eq!(
            range,
            vec![
                "000000010000000000000001".to_owned(),
                "000000010000000000000002".to_owned(),
                "000000010000000000000003".to_owned(),
            ]
        );
    }

    #[test]
    fn wal_segment_range_wraps_across_high_half() {
        // The default 16 MiB layout has 256 segments per logical file, so the
        // low component runs 00..FF then rolls over to 00 with the high component
        // incrementing. Walk from the last segment of logical file 0 (..0000 00FF)
        // through the first two of logical file 1 (..0001 0000, ..0001 0001).
        let range = wal_segment_range(
            "0000000100000000000000FF",
            "000000010000000100000001",
            WAL_SEGMENT_SIZE_DEFAULT,
        )
        .expect("range across the high half");
        assert_eq!(
            range,
            vec![
                "0000000100000000000000FF".to_owned(),
                "000000010000000100000000".to_owned(),
                "000000010000000100000001".to_owned(),
            ],
            "low half must roll over and bump the high half"
        );
    }

    #[test]
    fn wal_segment_range_wraps_with_non_default_size() {
        // 1 GiB segments => 4 segments per logical file (low runs 0..3).
        let seg_size = 0x4000_0000;
        let range = wal_segment_range("000000010000000000000003", "000000010000000100000000", seg_size).expect("range");
        assert_eq!(
            range,
            vec!["000000010000000000000003".to_owned(), "000000010000000100000000".to_owned(),],
            "the low half wraps at 4 for 1 GiB segments"
        );
    }

    #[test]
    fn wal_segment_range_rejects_bad_input() {
        // stop before start.
        assert_eq!(
            wal_segment_range(
                "000000010000000000000005",
                "000000010000000000000001",
                WAL_SEGMENT_SIZE_DEFAULT
            ),
            None,
            "stop before start"
        );
        // Different timelines.
        assert_eq!(
            wal_segment_range(
                "000000010000000000000001",
                "000000020000000000000002",
                WAL_SEGMENT_SIZE_DEFAULT
            ),
            None,
            "range cannot span timelines"
        );
        // Malformed name.
        assert_eq!(
            wal_segment_range("not-a-segment", "000000010000000000000001", WAL_SEGMENT_SIZE_DEFAULT),
            None
        );
    }

    /// Build a WAL segment first-page buffer with the given header fields.
    fn wal_header_buf(magic: u16, info: u16, timeline: u32, system_id: u64, segment_size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; WAL_LONG_HEADER_LEN];
        buf[0..2].copy_from_slice(&magic.to_le_bytes());
        buf[2..4].copy_from_slice(&info.to_le_bytes());
        buf[4..8].copy_from_slice(&timeline.to_le_bytes());
        buf[XLP_SYSID_OFFSET..XLP_SYSID_OFFSET + 8].copy_from_slice(&system_id.to_le_bytes());
        buf[XLP_SEG_SIZE_OFFSET..XLP_SEG_SIZE_OFFSET + 4].copy_from_slice(&segment_size.to_le_bytes());
        buf
    }

    #[test]
    fn wal_version_from_magic_maps_known_magics() {
        assert_eq!(wal_version_from_magic(0xD10D), Some("14"));
        assert_eq!(wal_version_from_magic(0xD113), Some("16"));
        assert_eq!(wal_version_from_magic(0xD093), Some("9.6"));
        assert_eq!(wal_version_from_magic(0x0000), None, "unknown magic");
    }

    #[test]
    fn parse_wal_header_decodes_long_header() {
        // PG 14 magic, long-header flag set, timeline 7, a system id and 16 MiB segments.
        let buf = wal_header_buf(0xD10D, XLP_LONG_HEADER, 7, 6_873_049_345_984_568_091, 16 * 1024 * 1024);
        let header = parse_wal_header(&buf).expect("long header parses");
        assert_eq!(header.magic, 0xD10D);
        assert_eq!(header.version, Some("14"));
        assert_eq!(header.timeline, 7);
        assert_eq!(header.system_id, 6_873_049_345_984_568_091);
        assert_eq!(header.segment_size, 16 * 1024 * 1024);
    }

    #[test]
    fn parse_wal_header_rejects_short_buffer() {
        assert_eq!(parse_wal_header(&[0u8; WAL_LONG_HEADER_LEN - 1]), None);
    }

    #[test]
    fn parse_wal_header_rejects_non_long_first_page() {
        // The XLP_LONG_HEADER bit clear means this is not a segment's first page.
        let buf = wal_header_buf(0xD10D, 0, 1, 42, 16 * 1024 * 1024);
        assert_eq!(parse_wal_header(&buf), None, "first page must be a long header");
    }

    #[test]
    fn parse_wal_header_unknown_magic_yields_none_version() {
        let buf = wal_header_buf(0xABCD, XLP_LONG_HEADER, 1, 42, 16 * 1024 * 1024);
        let header = parse_wal_header(&buf).expect("still parses structurally");
        assert_eq!(header.magic, 0xABCD);
        assert_eq!(header.version, None, "unknown magic has no version label");
    }

    #[test]
    fn wal_segment_range_carries_start_timeline() {
        // The timeline of every returned name is the start timeline (post-failover
        // lines are addressed by their own timeline id).
        let range = wal_segment_range(
            "0000000A0000000000000001",
            "0000000A0000000000000002",
            WAL_SEGMENT_SIZE_DEFAULT,
        )
        .expect("range");
        assert!(range.iter().all(|s| s.starts_with("0000000A")), "{range:?}");
    }
}
