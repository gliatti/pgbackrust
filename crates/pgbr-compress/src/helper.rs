//! Compression-helper lookups — Phase 26.
//!
//! Mirrors the type-id and extension tables in `src/common/compress/helper.c`. The C
//! dispatch table (`compressHelperLocal`) — which holds the `compressNew` /
//! `decompressNew` function pointers — stays on the C side because those constructors
//! return pgBackRust `IoFilter *` values that have not been migrated to Rust yet. This
//! module only handles the parts that are pure data: `compressTypeEnum` (`StringId` →
//! enum) and `compressTypeFromName` (filename → enum by extension).

/// Mirror of the C `CompressType` enum in `src/common/compress/helper.h`. Values must
/// match the C side exactly so the FFI can pass them as `i32` round-trips.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressType {
    /// No compression.
    None = 0,
    /// bzip2 (`.bz2`).
    Bz2 = 1,
    /// gzip (`.gz`).
    Gz = 2,
    /// LZ4 frame (`.lz4`).
    Lz4 = 3,
    /// Zstandard (`.zst`).
    Zst = 4,
    /// xz / lzma (`.xz`) — declared but not implemented.
    Xz = 5,
}

/// Pre-encoded `StringId` values for each compress type. Mirrors the
/// `STRID5("...", 0x...)` literals from `compressHelperLocal[].typeId` in the legacy C
/// code. These are stable across pgBackRust versions; the suffix nibble (`0`) at the
/// low end means an empty 6th character (`StringId5` 5-bit-per-char encoding). `lz4`
/// uses `STRID6` (6-bit-per-char encoding) which is encoded differently — its
/// discriminant is `0x2068c1` per the legacy table.
const TYPE_IDS: &[(CompressType, u64)] = &[
    (CompressType::None, 0x2b_9ee0),
    (CompressType::Bz2, 0x7_3420),
    (CompressType::Gz, 0x3470),
    (CompressType::Lz4, 0x20_68c1),
    (CompressType::Zst, 0x5_27a0),
    (CompressType::Xz, 0x3580),
];

/// Pre-encoded extension strings. Mirrors `compressHelperLocal[].ext` (the period-prefixed
/// form). `compressTypeNone` has no extension.
const EXTENSIONS: &[(CompressType, &str)] = &[
    (CompressType::None, ""),
    (CompressType::Bz2, ".bz2"),
    (CompressType::Gz, ".gz"),
    (CompressType::Lz4, ".lz4"),
    (CompressType::Zst, ".zst"),
    (CompressType::Xz, ".xz"),
];

/// Map a `StringId`-encoded type name to a [`CompressType`].
///
/// Mirrors `compressTypeEnum`. Returns `None` when the type id is not a recognized
/// compression type — the C wrapper translates that into the legacy `AssertError`
/// `"invalid compression type 'XXX'"`.
#[must_use]
pub fn type_enum(type_id: u64) -> Option<CompressType> {
    for (ty, id) in TYPE_IDS {
        if *id == type_id {
            return Some(*ty);
        }
    }
    None
}

/// Map a filename to a [`CompressType`] by checking its extension. Mirrors
/// `compressTypeFromName`. Returns [`CompressType::None`] when no recognized extension
/// matches.
#[must_use]
pub fn type_from_name(name: &str) -> CompressType {
    // Skip the `None` entry (empty extension) — every name "ends with" `""`.
    for (ty, ext) in EXTENSIONS.iter().filter(|(_, e)| !e.is_empty()) {
        if name.ends_with(ext) {
            return *ty;
        }
    }
    CompressType::None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{CompressType, type_enum, type_from_name};

    #[test]
    fn type_enum_round_trip() {
        // Same fixtures the C `compressTypeEnum` test asserts.
        assert_eq!(type_enum(0x2b_9ee0), Some(CompressType::None));
        assert_eq!(type_enum(0x7_3420), Some(CompressType::Bz2));
        assert_eq!(type_enum(0x3470), Some(CompressType::Gz));
        assert_eq!(type_enum(0x20_68c1), Some(CompressType::Lz4));
        assert_eq!(type_enum(0x5_27a0), Some(CompressType::Zst));
        assert_eq!(type_enum(0x3580), Some(CompressType::Xz));
    }

    #[test]
    fn type_enum_unknown_returns_none() {
        // A bogus type id that is not in the table.
        assert_eq!(type_enum(0xDEAD_BEEF), None);
    }

    #[test]
    fn type_from_name_picks_extension() {
        assert_eq!(type_from_name("file"), CompressType::None);
        assert_eq!(type_from_name("file.gz"), CompressType::Gz);
        assert_eq!(type_from_name("file.bz2"), CompressType::Bz2);
        assert_eq!(type_from_name("file.lz4"), CompressType::Lz4);
        assert_eq!(type_from_name("file.zst"), CompressType::Zst);
        assert_eq!(type_from_name("file.xz"), CompressType::Xz);
    }

    #[test]
    fn type_from_name_unrecognized_returns_none() {
        assert_eq!(type_from_name("file.txt"), CompressType::None);
        assert_eq!(type_from_name("file.7z"), CompressType::None);
    }
}
