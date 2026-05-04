//! Compression helpers shared across the pgBackRust workspace.
//!
//! Submodules:
//!
//! - [`gz`] — zlib error-code classification ported from `src/common/compress/gz/common.c`.
//! - [`params`] — `compressParamList` / `decompressParamList` ported from
//!   `src/common/compress/common.c`. Produces the exact byte sequence the legacy
//!   `pckWriteI32P` + `pckWriteBoolP` + `pckWriteEndP` chain emits, so the C side can wrap
//!   the bytes in a `Buffer*` (which is what `Pack*` is, structurally) without changing the
//!   public ABI.

#![cfg_attr(not(test), forbid(unsafe_code))]

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

pub mod gz {
    //! zlib error-code classification.
    //!
    //! Mirrors `gzError` in `src/common/compress/gz/common.c`: takes a raw zlib return code and
    //! decides whether to throw, which pgBackRust [`ErrorKind`] to throw with, and what
    //! human-readable message to attach. The C side keeps the actual `THROW` because it has
    //! to plug into pgBackRust's exception machinery; this module just does the mapping.

    /// zlib `Z_OK` — operation completed successfully (no throw).
    pub const Z_OK: i32 = 0;
    /// zlib `Z_STREAM_END` — end of stream reached (no throw).
    pub const Z_STREAM_END: i32 = 1;

    /// pgBackRust error category the C side should `THROW` with for a given zlib error code.
    ///
    /// Discriminants are stable across the FFI boundary; the C wrapper maps each variant to
    /// the matching `ErrorType *` pointer (`AssertError` / `FormatError` / `MemoryError`).
    #[repr(i32)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ErrorKind {
        /// "Should not happen" / programming-bug class — `Z_NEED_DICT`, `Z_ERRNO`,
        /// `Z_BUF_ERROR`, plus the catch-all unknown code path.
        Assert = 0,
        /// Caller-supplied input was malformed — `Z_STREAM_ERROR`, `Z_DATA_ERROR`,
        /// `Z_VERSION_ERROR`.
        Format = 1,
        /// Allocation failure — `Z_MEM_ERROR`.
        Memory = 2,
    }

    /// Result of [`classify`]: either the input was non-erroneous (`Ok` carrying the original
    /// code) or it was erroneous and needs to be thrown.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Classification {
        /// `Z_OK` or `Z_STREAM_END` — return `code` to the caller, no throw.
        Ok { code: i32 },
        /// Throw `kind` with the given short message and the `code` formatted in.
        Throw { code: i32, kind: ErrorKind, message: &'static str },
    }

    /// Inspect a zlib return code and decide whether it represents an error.
    ///
    /// Mirrors the legacy `gzError` switch — same list of recognized codes, same mapping to
    /// `AssertError` / `FormatError` / `MemoryError`, same human-readable message strings.
    #[must_use]
    pub const fn classify(code: i32) -> Classification {
        if code == Z_OK || code == Z_STREAM_END {
            return Classification::Ok { code };
        }

        // Constants taken straight from `zlib.h`. Hard-coded here so this module does not need
        // a build-script + libz-sys dependency just for a handful of integer constants.
        let z_need_dict: i32 = 2;
        let z_errno: i32 = -1;
        let z_stream_error: i32 = -2;
        let z_data_error: i32 = -3;
        let z_mem_error: i32 = -4;
        let z_buf_error: i32 = -5;
        let z_version_error: i32 = -6;

        let (kind, message) = if code == z_need_dict {
            (ErrorKind::Assert, "need dictionary")
        } else if code == z_errno {
            (ErrorKind::Assert, "file error")
        } else if code == z_stream_error {
            (ErrorKind::Format, "stream error")
        } else if code == z_data_error {
            (ErrorKind::Format, "data error")
        } else if code == z_mem_error {
            (ErrorKind::Memory, "insufficient memory")
        } else if code == z_buf_error {
            (ErrorKind::Assert, "no space in buffer")
        } else if code == z_version_error {
            (ErrorKind::Format, "incompatible version")
        } else {
            (ErrorKind::Assert, "unknown error")
        };

        Classification::Throw { code, kind, message }
    }
}

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::gz::*;

    #[test]
    fn z_ok_and_stream_end_do_not_throw() {
        assert_eq!(classify(Z_OK), Classification::Ok { code: Z_OK });
        assert_eq!(classify(Z_STREAM_END), Classification::Ok { code: Z_STREAM_END });
    }

    #[test]
    fn known_error_codes_map_to_legacy_messages() {
        let cases = [
            (2, ErrorKind::Assert, "need dictionary"),
            (-1, ErrorKind::Assert, "file error"),
            (-2, ErrorKind::Format, "stream error"),
            (-3, ErrorKind::Format, "data error"),
            (-4, ErrorKind::Memory, "insufficient memory"),
            (-5, ErrorKind::Assert, "no space in buffer"),
            (-6, ErrorKind::Format, "incompatible version"),
        ];
        for (code, kind, message) in cases {
            assert_eq!(classify(code), Classification::Throw { code, kind, message });
        }
    }

    #[test]
    fn unknown_codes_become_assert_unknown() {
        for code in [-7, -100, 99, i32::MAX, i32::MIN] {
            assert_eq!(
                classify(code),
                Classification::Throw {
                    code,
                    kind: ErrorKind::Assert,
                    message: "unknown error",
                }
            );
        }
    }
}
