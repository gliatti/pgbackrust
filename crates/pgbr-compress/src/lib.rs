//! Compression helpers shared across the pgBackRust workspace.
//!
//! Submodules:
//!
//! - [`gz`] — zlib glue: error-code classification ported from
//!   `src/common/compress/gz/common.c` and the streaming gzip / zlib-wrapped deflate compressor
//!   ported from `src/common/compress/gz/compress.c`. The compressor calls libz directly via
//!   `libz-sys` so its byte output is identical to the legacy C path for any given (level, raw,
//!   memLevel, strategy) tuple.
//! - [`params`] — `compressParamList` / `decompressParamList` ported from
//!   `src/common/compress/common.c`. Produces the exact byte sequence the legacy
//!   `pckWriteI32P` + `pckWriteBoolP` + `pckWriteEndP` chain emits, so the C side can wrap
//!   the bytes in a `Buffer*` (which is what `Pack*` is, structurally) without changing the
//!   public ABI.

pub mod params {
    //! Pack-encoded parameter lists for compress / decompress filters.
    //!
    //! The byte format matches the legacy C `pckWriteI32P` / `pckWriteBoolP` / `pckWriteEndP`
    //! sequence in `src/common/compress/common.c`. Each field is written with `defaultWrite`
    //! left at its default `false`, so a value equal to its default (`0` for I32, `false` for
    //! Bool) is encoded as a NULL — i.e. it does not produce any bytes but still consumes a
    //! field-id slot. The terminator is a single `0x00` byte.
    //!
    //! The encoding logic is a direct port of `pckWriteTag` (see the giant comment at the top
    //! of `src/common/type/pack.c` for the bit layout).

    /// Type-map discriminant for `pckTypeMapBool`. Tag bytes for booleans put this value in
    /// the high four bits.
    const TYPE_MAP_BOOL: u8 = 2;
    /// Type-map discriminant for `pckTypeMapI32`.
    const TYPE_MAP_I32: u8 = 3;

    /// `pckWriteTag`-style writer that tracks the auto-incrementing field ID through optional
    /// NULL gaps, exactly the way `PackTagStack.idLast` / `nullTotal` do on the C side.
    #[derive(Default)]
    struct PackWriter {
        id_last: u32,
        null_total: u32,
        out: Vec<u8>,
    }

    impl PackWriter {
        /// Mirror of `pckWriteDefaultNull(_, false, value == default)` — the field is skipped
        /// (no bytes emitted) but the field-id counter advances on the next non-NULL write.
        const fn skip(&mut self) {
            self.null_total += 1;
        }

        /// Push a base-128 little-endian varint, mirroring `cvtUInt64ToVarInt128`.
        #[allow(clippy::cast_possible_truncation)]
        fn push_varint(&mut self, mut value: u64) {
            while value >= 0x80 {
                self.out.push((value & 0x7F) as u8 | 0x80);
                value >>= 7;
            }
            self.out.push((value & 0x7F) as u8);
        }

        /// Compute the field-id delta (`id - idLast - 1`) for the next write and reset
        /// `null_total`. Returns the delta.
        const fn next_tag_id(&mut self) -> u32 {
            let id = self.id_last + self.null_total + 1;
            let tag_id = id - self.id_last - 1;
            self.null_total = 0;
            self.id_last = id;
            tag_id
        }

        /// `pckWriteTag` for a multi-bit-value type (I32 here; the same code-path covers
        /// I64, U32, U64, `StrId`, Time, Mode in the legacy module).
        fn write_multi_bit_value(&mut self, type_map: u8, value: u64) {
            let mut tag_id = self.next_tag_id();
            let mut tag: u8 = type_map << 4;
            let mut value = value;

            if value < 2 {
                // Value (0 or 1) fits in the tag's "value low order bit" slot.
                tag |= ((value & 0x1) as u8) << 2;
                value >>= 1;
                tag |= (tag_id & 0x1) as u8;
                tag_id >>= 1;
                if tag_id > 0 {
                    tag |= 0x2;
                }
            } else {
                // Multi-byte value follows the tag.
                tag |= 0x8;
                tag |= (tag_id & 0x3) as u8;
                tag_id >>= 2;
                if tag_id > 0 {
                    tag |= 0x4;
                }
            }

            self.out.push(tag);
            if tag_id > 0 {
                self.push_varint(u64::from(tag_id));
            }
            if value > 0 {
                self.push_varint(value);
            }
        }

        /// `pckWriteTag` for a single-bit-value type (Bool here; same shape covers Str, Bin).
        fn write_single_bit_value(&mut self, type_map: u8, value_bit: bool) {
            let mut tag_id = self.next_tag_id();
            let mut tag: u8 = type_map << 4;

            tag |= u8::from(value_bit) << 3;
            tag |= (tag_id & 0x3) as u8;
            tag_id >>= 2;
            if tag_id > 0 {
                tag |= 0x4;
            }

            self.out.push(tag);
            if tag_id > 0 {
                self.push_varint(u64::from(tag_id));
            }
            // For single-bit-value types the value lives entirely in the tag byte; no varint
            // value bytes follow.
        }

        /// Mirror of `pckWriteI32P(value)` with default-value 0.
        fn write_i32(&mut self, value: i32) {
            if value == 0 {
                self.skip();
                return;
            }
            // ZigZag encoding: (value << 1) ^ (value >> 31).
            #[allow(clippy::cast_sign_loss)]
            let zigzag = ((value as u32) << 1) ^ ((value >> 31) as u32);
            self.write_multi_bit_value(TYPE_MAP_I32, u64::from(zigzag));
        }

        /// Mirror of `pckWriteBoolP(value)` with default-value `false`.
        fn write_bool(&mut self, value: bool) {
            if !value {
                self.skip();
                return;
            }
            self.write_single_bit_value(TYPE_MAP_BOOL, true);
        }

        /// Append the terminator byte (`pckWriteEndP` writes a varint zero).
        fn finish(mut self) -> Vec<u8> {
            self.out.push(0);
            self.out
        }
    }

    /// Build the Pack-encoded byte buffer for `compressParamList(level, raw)`.
    ///
    /// Mirrors the legacy body in `src/common/compress/common.c`:
    /// `pckWriteI32P(level) + pckWriteBoolP(raw) + pckWriteEndP`.
    #[must_use]
    pub fn compress_param_list_bytes(level: i32, raw: bool) -> Vec<u8> {
        let mut writer = PackWriter::default();
        writer.write_i32(level);
        writer.write_bool(raw);
        writer.finish()
    }

    /// Build the Pack-encoded byte buffer for `decompressParamList(raw)`.
    #[must_use]
    pub fn decompress_param_list_bytes(raw: bool) -> Vec<u8> {
        let mut writer = PackWriter::default();
        writer.write_bool(raw);
        writer.finish()
    }
}

pub mod bz2;
pub mod gz;
pub mod lz4;
pub mod zst;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod params_tests {
    use super::params::*;

    // Expected byte sequences computed by hand from `pckWriteTag` (see top-of-file pack.c
    // comment) and the `pckWriteI32P` / `pckWriteBoolP` / `pckWriteEndP` defaults in
    // `src/common/compress/common.c`. These act as fixtures the C differential test can
    // double-check.

    #[test]
    fn compress_param_list_level_1_raw_false() {
        // I32 zigzag(1) = 2 → tag 0x38 + varint 0x02. Bool false skipped. End 0x00.
        assert_eq!(compress_param_list_bytes(1, false), vec![0x38, 0x02, 0x00]);
    }

    #[test]
    fn compress_param_list_level_1_raw_true() {
        // I32 zigzag(1) = 2 → 0x38 0x02. Bool true at id=2 with delta 0 → 0x28. End 0x00.
        assert_eq!(compress_param_list_bytes(1, true), vec![0x38, 0x02, 0x28, 0x00]);
    }

    #[test]
    fn compress_param_list_level_0_raw_true() {
        // I32 0 == default → skipped (null_total=1). Bool true at id=2 with delta 1 → 0x29.
        assert_eq!(compress_param_list_bytes(0, true), vec![0x29, 0x00]);
    }

    #[test]
    fn compress_param_list_level_9_raw_false() {
        // I32 zigzag(9) = 18 → multi-byte branch: tag 0x38 + varint 18 = 0x12.
        assert_eq!(compress_param_list_bytes(9, false), vec![0x38, 0x12, 0x00]);
    }

    #[test]
    fn compress_param_list_level_negative() {
        // I32 -1: zigzag(-1) = (-1<<1) ^ (-1>>31) = -2 ^ -1 = 1 → fits in tag value bit:
        //   tag = (3<<4) | ((1&1)<<2) | (tagId 0 & 1) = 0x34. value >>= 1 = 0, no varint.
        assert_eq!(compress_param_list_bytes(-1, false), vec![0x34, 0x00]);
    }

    #[test]
    fn decompress_param_list_raw_false() {
        // Bool false at id=1 == default → skipped. End 0x00.
        assert_eq!(decompress_param_list_bytes(false), vec![0x00]);
    }

    #[test]
    fn decompress_param_list_raw_true() {
        // Bool true at id=1 with delta 0 → tag 0x28.
        assert_eq!(decompress_param_list_bytes(true), vec![0x28, 0x00]);
    }
}
