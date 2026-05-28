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
        // Non-zero pd_checksum, matching the C harness, to exercise zeroing.
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
}
