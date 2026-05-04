//! PostgreSQL-specific helpers shared between the C and Rust sides of pgBackRust.
//!
//! For now this crate exposes a single function: [`crc32c_one`], the byte-wise CRC-32C
//! computation used to validate `pg_control` and other `PostgreSQL` on-disk structures. The
//! lookup table is built at compile time from the Castagnoli polynomial (0x1EDC6F41, reflected
//! as 0x82F63B78) so the generated values match the table the upstream `src/postgres/interface/
//! crc32.c` ships verbatim.

#![cfg_attr(not(test), forbid(unsafe_code))]

const CRC32C_POLY_REFLECTED: u32 = 0x82F6_3B78;

/// Generated at compile time from `CRC32C_POLY_REFLECTED`. Each entry holds the CRC-32C value
/// for an 8-bit message, used to advance a 32-bit running checksum byte by byte.
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut byte = 0u32;
    while byte < 256 {
        let mut c = byte;
        let mut i = 0;
        while i < 8 {
            c = if c & 1 == 1 { (c >> 1) ^ CRC32C_POLY_REFLECTED } else { c >> 1 };
            i += 1;
        }
        table[byte as usize] = c;
        byte += 1;
    }
    table
};

/// Compute the CRC-32C checksum (Castagnoli polynomial) of `data`.
///
/// Identical algorithm to the legacy C `crc32cOne(uint8_t *, size_t)`: byte-wise table lookup
/// with the standard `0xffff_ffff` initial value and final XOR.
#[must_use]
pub const fn crc32c_one(data: &[u8]) -> u32 {
    let mut result: u32 = 0xffff_ffff;
    let mut i = 0;
    while i < data.len() {
        let idx = ((result ^ data[i] as u32) & 0xff) as usize;
        result = CRC32C_TABLE[idx] ^ (result >> 8);
        i += 1;
    }
    result ^ 0xffff_ffff
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Reference implementation that does not rely on the precomputed table — recomputes the
    /// CRC bit by bit. Used as a self-check for the table-based fast path.
    fn reference_crc32c(data: &[u8]) -> u32 {
        let mut result: u32 = 0xffff_ffff;
        for &byte in data {
            result ^= u32::from(byte);
            for _ in 0..8 {
                result = if result & 1 == 1 {
                    (result >> 1) ^ CRC32C_POLY_REFLECTED
                } else {
                    result >> 1
                };
            }
        }
        result ^ 0xffff_ffff
    }

    #[test]
    fn empty_input_returns_zero_after_final_xor() {
        // RFC 3720 §A.4 vector — zero-length CRC-32C is 0.
        assert_eq!(crc32c_one(&[]), 0);
    }

    #[test]
    fn known_vectors_match_castagnoli_reference() {
        // Taken from RFC 3720 §A.4 / iSCSI test vectors and the iSCSI checksum design draft.
        // Each is 32 bytes of `data`, with the expected CRC-32C printed in MSB-first hex.
        let cases: &[(&[u8], u32)] = &[
            (&[0x00; 32], 0x8a91_36aa),
            (&[0xff; 32], 0x62a8_ab43),
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
                    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                0x46dd_794e,
            ),
        ];
        for (data, expected) in cases {
            assert_eq!(crc32c_one(data), *expected, "data of length {}", data.len());
        }
    }

    #[test]
    fn ascii_known_vectors() {
        // "123456789" CRC-32C is the canonical test vector for Castagnoli.
        assert_eq!(crc32c_one(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c_one(b"hello"), 0x9a71_bb4c);
    }

    #[test]
    fn round_trip_random_inputs_against_reference() {
        // Deterministic LCG over a fixed seed — 10 000 inputs covering 0..=200 byte lengths.
        let mut state: u64 = 0xc0ff_eeba_bea1_b0b0;
        let mut buf = Vec::with_capacity(257);
        for iter in 0..10_000 {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            let len = if iter < 257 { iter } else { ((state >> 32) as usize) % 257 };
            buf.clear();
            for _ in 0..len {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                buf.push((state >> 56) as u8);
            }
            let table_based = crc32c_one(&buf);
            let bitwise = reference_crc32c(&buf);
            assert_eq!(table_based, bitwise, "iter {iter} len {len}");
        }
    }
}
