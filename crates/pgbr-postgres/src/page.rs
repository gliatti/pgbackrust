//! `PostgreSQL` data-page checksum (`pg_checksum_page`).
//!
//! Ported faithfully from `src/postgres/interface/page.c` (`pgPageChecksum`),
//! which the C tree in turn adapted from `PostgreSQL`'s
//! `src/include/storage/checksum_impl.h`. The algorithm is an FNV-1a-based
//! block checksum computed over the page interpreted as a native-endian
//! `uint32` array, in `PARALLEL_SUM` independent lanes, folded down to a
//! 16-bit value that `PostgreSQL` stores in the page header's `pd_checksum`
//! field.
//!
//! The page's own `pd_checksum` field (offset 8, 2 bytes) is treated as zero
//! during computation, exactly as the C code temporarily zeroes it before the
//! FNV loop and restores it afterwards.

/// Page size this checksum is defined for (`PostgreSQL` `BLCKSZ`, default build).
pub const BLCKSZ: usize = 8192;

/// Byte offset of the `pd_checksum` field in `PageHeaderData` (after the
/// 8-byte `pd_lsn`).
const PD_CHECKSUM_OFFSET: usize = 8;

/// Number of FNV lanes computed in parallel (`PARALLEL_SUM` in the C source,
/// `N_SUMS` upstream).
const PARALLEL_SUM: usize = 32;

/// Prime multiplier of the FNV-1a hash (`FNV_PRIME`).
const FNV_PRIME: u32 = 16_777_619;

/// Initial per-lane seed values, copied verbatim from `pgPageChecksum`.
const SUM_SEEDS: [u32; PARALLEL_SUM] = [
    0x5b1f_36e9,
    0xb852_5960,
    0x02ab_50aa,
    0x1de6_6d2a,
    0x79ff_467a,
    0x9bb9_f8a3,
    0x217e_7cd2,
    0x83e1_3d2c,
    0xf8d4_474f,
    0xe39e_b970,
    0x42c6_ae16,
    0x9932_16fa,
    0x7b09_3b5d,
    0x98da_ff3c,
    0xf718_902a,
    0x0b1c_9cdb,
    0xe58f_764b,
    0x1876_36bc,
    0x5d7b_3bb1,
    0xe73d_e7de,
    0x92be_c979,
    0xcca6_c0b2,
    0x304a_0979,
    0x85aa_43d4,
    0x7831_25bb,
    0x6ca8_eaa2,
    0xe407_eac6,
    0x4b5c_fc3e,
    0x9fbf_8c76,
    0x15ca_20be,
    0xf2ca_9fd3,
    0x959b_d756,
];

/// One FNV-1a round, matching the C `CHECKSUM_ROUND` macro:
/// `tmp = checksum ^ value; checksum = tmp * FNV_PRIME ^ (tmp >> 17)`.
/// Multiplication wraps (C unsigned overflow semantics).
#[inline]
const fn checksum_round(checksum: u32, value: u32) -> u32 {
    let tmp = checksum ^ value;
    tmp.wrapping_mul(FNV_PRIME) ^ (tmp >> 17)
}

/// Number of FNV passes over the page: `BLCKSZ / (4 * PARALLEL_SUM)` = 64.
const ROUNDS: usize = BLCKSZ / (4 * PARALLEL_SUM);

/// Compute the 16-bit data-page checksum.
///
/// This is the value `PostgreSQL` stores in a data page's header
/// (`pd_checksum`, offset 8). `page` must be exactly `BLCKSZ` (8192) bytes;
/// `block_no` is the relation block number. The page's own `pd_checksum`
/// field is treated as zero during computation.
///
/// Returns `None` if `page.len() != 8192`.
#[must_use]
pub fn pg_checksum_page(page: &[u8], block_no: u32) -> Option<u16> {
    if page.len() != BLCKSZ {
        return None;
    }

    // Read the page as native-endian u32s, treating pd_checksum (offset 8) as
    // zero. This mirrors the C code casting the byte array to a uint32 matrix
    // and temporarily storing 0 in pd_checksum before the loop.
    let mut words = [0u32; BLCKSZ / 4];
    for (idx, word) in words.iter_mut().enumerate() {
        let off = idx * 4;
        *word = u32::from_ne_bytes([page[off], page[off + 1], page[off + 2], page[off + 3]]);
    }
    // pd_checksum occupies bytes 8..10 -> the low 16 bits of word index 2.
    // Zero just those two bytes regardless of host endianness.
    let mut zeroed = words[PD_CHECKSUM_OFFSET / 4].to_ne_bytes();
    zeroed[PD_CHECKSUM_OFFSET % 4] = 0;
    zeroed[(PD_CHECKSUM_OFFSET % 4) + 1] = 0;
    words[PD_CHECKSUM_OFFSET / 4] = u32::from_ne_bytes(zeroed);

    let mut sums = SUM_SEEDS;

    // Main checksum calculation: ROUNDS passes, each over PARALLEL_SUM
    // consecutive u32s, one per lane.
    for round in 0..ROUNDS {
        let base = round * PARALLEL_SUM;
        for (lane, sum) in sums.iter_mut().enumerate() {
            *sum = checksum_round(*sum, words[base + lane]);
        }
    }

    // Two rounds of zeroes for additional mixing.
    for _ in 0..2 {
        for sum in &mut sums {
            *sum = checksum_round(*sum, 0);
        }
    }

    // XOR-fold the partial checksums together.
    let mut result = 0u32;
    for sum in sums {
        result ^= sum;
    }

    // Mix in the block number to detect transposed pages.
    result ^= block_no;

    // Reduce to a u16 with an offset of one so the checksum is never zero.
    // result % 65535 is in 0..=65534, so +1 is in 1..=65535 — always fits a
    // u16. The cast cannot truncate given that bound.
    #[allow(clippy::cast_possible_truncation)]
    let checksum = ((result % 65_535) + 1) as u16;
    Some(checksum)
}

/// Read the `pd_checksum` field stored in a page header (offset 8, u16 LE).
///
/// Returns `None` if `page.len() < 10` (the header through `pd_checksum`).
#[must_use]
pub fn stored_checksum(page: &[u8]) -> Option<u16> {
    if page.len() < PD_CHECKSUM_OFFSET + 2 {
        return None;
    }
    Some(u16::from_le_bytes([page[PD_CHECKSUM_OFFSET], page[PD_CHECKSUM_OFFSET + 1]]))
}

/// Whether a page's stored checksum matches its computed checksum.
///
/// Returns `None` if `page.len() != 8192`.
#[must_use]
pub fn page_checksum_valid(page: &[u8], block_no: u32) -> Option<bool> {
    let computed = pg_checksum_page(page, block_no)?;
    let stored = stored_checksum(page)?;
    Some(computed == stored)
}

/// Size of the fixed `PageHeaderData` prefix (`SizeOfPageHeaderData`), the bytes
/// before the per-page item-pointer array. Every data page begins with this
/// 24-byte header.
pub const SIZE_OF_PAGE_HEADER_DATA: usize = 24;

/// Byte offset of `pd_lower` (`LocationIndex`, u16 LE) in `PageHeaderData`:
/// after `pd_lsn` (8), `pd_checksum` (2), `pd_flags` (2).
const PD_LOWER_OFFSET: usize = 12;
/// Byte offset of `pd_upper` (u16 LE) in `PageHeaderData`.
const PD_UPPER_OFFSET: usize = 14;
/// Byte offset of `pd_special` (u16 LE) in `PageHeaderData`.
const PD_SPECIAL_OFFSET: usize = 16;

/// Read the page's `pd_lsn` (the first 8 bytes of the header) as a 64-bit LSN.
///
/// `pd_lsn` is a `PageXLogRecPtr` — `xlogid` (high 32 bits) at offset 0 and
/// `xrecoff` (low 32 bits) at offset 4, both little-endian. Returns `None` when
/// the slice is shorter than 8 bytes.
#[must_use]
pub fn page_lsn(page: &[u8]) -> Option<u64> {
    if page.len() < 8 {
        return None;
    }
    let xlogid = u32::from_le_bytes([page[0], page[1], page[2], page[3]]);
    let xrecoff = u32::from_le_bytes([page[4], page[5], page[6], page[7]]);
    Some((u64::from(xlogid) << 32) | u64::from(xrecoff))
}

/// Whether a data page's *header* is structurally sane, independent of the
/// checksum.
///
/// pgBackRest validates a page's header before (and in addition to) its
/// checksum so a page whose checksum happens to collide can still be rejected
/// when its bookkeeping fields are impossible. C reference: the
/// `PageHeaderData` field checks `PostgreSQL` itself uses in `PageIsVerified`
/// (`src/backend/storage/page/bufpage.c`) — `pd_upper`/`pd_lower`/`pd_special`
/// must describe a consistent free-space layout, and `pd_lsn` must not exceed
/// the highest LSN the cluster has reached.
///
/// A page passes when **all** of the following hold (with `page.len()` being the
/// page size, normally [`BLCKSZ`]):
///
/// - the slice is at least [`SIZE_OF_PAGE_HEADER_DATA`] bytes (it can hold a
///   header at all);
/// - `pd_lower >= SizeOfPageHeaderData` (the line-pointer array starts after the
///   header) **or** `pd_lower == 0` (a never-initialised / empty page);
/// - `pd_lower <= pd_upper` (the free space between the line pointers and the
///   tuples is non-negative);
/// - `pd_upper <= pd_special` (the tuples sit at or before the special space);
/// - `pd_special <= page_size` (the special space ends within the page);
/// - when `max_lsn` is supplied, `pd_lsn <= max_lsn` (the page cannot claim a
///   WAL position the cluster has not reached — a strong corruption signal).
///
/// An all-zero page (a freshly extended, never-written block) trivially passes:
/// every field is zero, `pd_lower == 0`, and `pd_lsn == 0`.
///
/// `max_lsn` is the cluster's current insert/flush LSN (the backup stop LSN is a
/// safe upper bound). Pass `None` to skip the `pd_lsn` ceiling check (e.g. when
/// no LSN is available).
#[must_use]
pub fn page_header_valid(page: &[u8], page_size: usize, max_lsn: Option<u64>) -> bool {
    if page.len() < SIZE_OF_PAGE_HEADER_DATA {
        return false;
    }

    let read_u16 = |off: usize| usize::from(u16::from_le_bytes([page[off], page[off + 1]]));
    let pd_lower = read_u16(PD_LOWER_OFFSET);
    let pd_upper = read_u16(PD_UPPER_OFFSET);
    let pd_special = read_u16(PD_SPECIAL_OFFSET);

    // pd_lower must either start past the header (line-pointer array) or be 0
    // (an empty / never-initialised page).
    if pd_lower != 0 && pd_lower < SIZE_OF_PAGE_HEADER_DATA {
        return false;
    }
    // The three free-space boundaries must be monotonically ordered and fit the
    // page: header <= pd_lower <= pd_upper <= pd_special <= page_size.
    if pd_lower > pd_upper || pd_upper > pd_special || pd_special > page_size {
        return false;
    }

    // pd_lsn must not exceed the highest LSN the cluster has reached.
    if let Some(max_lsn) = max_lsn
        && let Some(lsn) = page_lsn(page)
        && lsn > max_lsn
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fill a `BLCKSZ` page with a deterministic LCG sequence. The exact same
    /// generator (seed and constants) is used by the standalone C program that
    /// produced the known-answer vectors below, so the byte content matches.
    fn synthetic_page() -> Vec<u8> {
        let mut page = vec![0u8; BLCKSZ];
        let mut state: u64 = 0x0123_4567_89ab_cdef;
        for byte in &mut page {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (state >> 56) as u8;
        }
        // Non-zero pd_checksum to exercise the algorithm's zeroing step.
        page[8] = 0xAB;
        page[9] = 0xCD;
        page
    }

    /// Known-answer vectors captured from the vendored C `pgPageChecksum`
    /// (`src/postgres/interface/page.c`), compiled and run in the dev
    /// container on `x86_64` against [`synthetic_page`]. Because that C routine
    /// is the exact algorithm `PostgreSQL` uses, matching it validates the port
    /// against real `PostgreSQL` output rather than mere self-consistency.
    #[test]
    fn matches_vendored_c_known_answers() {
        let page = synthetic_page();
        assert_eq!(pg_checksum_page(&page, 0), Some(0x6f74));
        assert_eq!(pg_checksum_page(&page, 1), Some(0x6f73));
        assert_eq!(pg_checksum_page(&page, 100), Some(0x6f50));
        assert_eq!(pg_checksum_page(&page, u32::MAX), Some(0x908d));

        let zero = vec![0u8; BLCKSZ];
        assert_eq!(pg_checksum_page(&zero, 0), Some(0xc6aa));
    }

    #[test]
    fn wrong_length_returns_none() {
        assert_eq!(pg_checksum_page(&[], 0), None);
        assert_eq!(pg_checksum_page(&[0u8; BLCKSZ - 1], 0), None);
        assert_eq!(pg_checksum_page(&[0u8; BLCKSZ + 1], 0), None);
        assert_eq!(page_checksum_valid(&[0u8; 100], 0), None);
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let page = synthetic_page();
        let first = pg_checksum_page(&page, 42);
        let second = pg_checksum_page(&page, 42);
        assert_eq!(first, second);
        assert!(first.is_some());
    }

    #[test]
    fn pd_checksum_field_is_zeroed() {
        // Two pages identical except for the stored pd_checksum bytes (offset
        // 8..10) must produce the SAME computed checksum, proving the field is
        // ignored (zeroed) during computation.
        let mut a = synthetic_page();
        let mut b = a.clone();
        a[8] = 0x00;
        a[9] = 0x00;
        b[8] = 0xFF;
        b[9] = 0xFF;
        assert_eq!(pg_checksum_page(&a, 7), pg_checksum_page(&b, 7));

        // A byte change anywhere else, however, must affect the checksum.
        let mut c = a.clone();
        c[10] ^= 0x01;
        assert_ne!(pg_checksum_page(&a, 7), pg_checksum_page(&c, 7));
    }

    #[test]
    fn block_number_changes_checksum() {
        let page = synthetic_page();
        let b0 = pg_checksum_page(&page, 0).unwrap();
        let b1 = pg_checksum_page(&page, 1).unwrap();
        let b2 = pg_checksum_page(&page, 2).unwrap();
        assert_ne!(b0, b1);
        assert_ne!(b1, b2);
        assert_ne!(b0, b2);
    }

    #[test]
    fn never_returns_zero() {
        // The +1 offset guarantees the checksum is in 1..=65535.
        let mut page = vec![0u8; BLCKSZ];
        for block_no in 0..2000u32 {
            assert_ne!(pg_checksum_page(&page, block_no), Some(0));
        }
        // And across varied page content too.
        page = synthetic_page();
        for block_no in 0..2000u32 {
            assert_ne!(pg_checksum_page(&page, block_no), Some(0));
        }
    }

    #[test]
    fn stored_checksum_reads_little_endian_field() {
        let mut page = vec![0u8; BLCKSZ];
        page[8] = 0x34;
        page[9] = 0x12;
        assert_eq!(stored_checksum(&page), Some(0x1234));
        assert_eq!(stored_checksum(&[0u8; 9]), None);
    }

    #[test]
    fn page_checksum_valid_round_trips() {
        let mut page = synthetic_page();
        let computed = pg_checksum_page(&page, 5).unwrap();
        // Write the computed checksum into the header (LE) — page is now valid.
        page[8..10].copy_from_slice(&computed.to_le_bytes());
        assert_eq!(page_checksum_valid(&page, 5), Some(true));

        // Corrupt the stored checksum -> invalid.
        page[8] ^= 0x01;
        assert_eq!(page_checksum_valid(&page, 5), Some(false));
    }

    /// Build a page with a structurally-sane header: `pd_lower` past the header,
    /// `pd_upper` / `pd_special` at the page end, and an LSN of `lsn`.
    fn header_page(lsn: u64, pd_lower: u16, pd_upper: u16, pd_special: u16) -> Vec<u8> {
        let mut page = vec![0u8; BLCKSZ];
        let xlogid = u32::try_from(lsn >> 32).unwrap_or(u32::MAX);
        let xrecoff = u32::try_from(lsn & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        page[0..4].copy_from_slice(&xlogid.to_le_bytes());
        page[4..8].copy_from_slice(&xrecoff.to_le_bytes());
        page[PD_LOWER_OFFSET..PD_LOWER_OFFSET + 2].copy_from_slice(&pd_lower.to_le_bytes());
        page[PD_UPPER_OFFSET..PD_UPPER_OFFSET + 2].copy_from_slice(&pd_upper.to_le_bytes());
        page[PD_SPECIAL_OFFSET..PD_SPECIAL_OFFSET + 2].copy_from_slice(&pd_special.to_le_bytes());
        page
    }

    #[test]
    fn page_lsn_reads_xlogid_and_xrecoff() {
        let page = header_page((1 << 32) | 0x0123_4567, 24, 8192, 8192);
        assert_eq!(page_lsn(&page), Some((1 << 32) | 0x0123_4567));
        assert_eq!(page_lsn(&[0u8; 4]), None, "too short");
    }

    #[test]
    fn page_header_valid_accepts_well_formed_page() {
        // header(24) <= pd_lower(40) <= pd_upper(2000) <= pd_special(8192) <= 8192.
        let page = header_page(0x16B_3E40, 40, 2000, 8192);
        assert!(page_header_valid(&page, BLCKSZ, Some(0x0FFF_FFFF_FFFF)));
    }

    #[test]
    fn page_header_valid_accepts_all_zero_page() {
        // A never-written page is all zeroes: pd_lower == 0, every field 0.
        let zero = vec![0u8; BLCKSZ];
        assert!(page_header_valid(&zero, BLCKSZ, Some(123)));
        assert!(page_header_valid(&zero, BLCKSZ, None));
    }

    #[test]
    fn page_header_valid_rejects_pd_lower_inside_header() {
        // A non-zero pd_lower smaller than the header start is impossible.
        let page = header_page(0, 10, 2000, 8192);
        assert!(!page_header_valid(&page, BLCKSZ, None));
    }

    #[test]
    fn page_header_valid_rejects_unordered_boundaries() {
        // pd_lower > pd_upper.
        let page = header_page(0, 3000, 2000, 8192);
        assert!(!page_header_valid(&page, BLCKSZ, None));
        // pd_upper > pd_special.
        let page = header_page(0, 40, 8000, 4000);
        assert!(!page_header_valid(&page, BLCKSZ, None));
        // pd_special > page_size.
        let page = header_page(0, 40, 2000, 8192);
        assert!(!page_header_valid(&page, 4096, None));
    }

    #[test]
    fn page_header_valid_rejects_future_lsn() {
        // A page claiming an LSN past the cluster's max is corrupt.
        let page = header_page(0x1_0000_0000, 40, 2000, 8192);
        assert!(!page_header_valid(&page, BLCKSZ, Some(0xFFFF_FFFF)));
        // The same page passes when no LSN ceiling is enforced.
        assert!(page_header_valid(&page, BLCKSZ, None));
    }

    #[test]
    fn page_header_valid_rejects_too_short() {
        assert!(!page_header_valid(&[0u8; SIZE_OF_PAGE_HEADER_DATA - 1], BLCKSZ, None));
    }
}
