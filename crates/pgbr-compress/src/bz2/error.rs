//! `bz2Error` classification — Phase 20.
//!
//! Mirrors `bz2Error` in `src/common/compress/bz2/common.c`. Takes a raw libbz2 return
//! code and decides whether to throw, which pgBackRust [`ErrorKind`] to throw with, and
//! what human-readable message to attach. The C side keeps the actual `THROWP` because
//! it has to plug into pgBackRust's exception machinery; this module just does the
//! mapping. No `bzip2-sys` dependency — the codes are just integer constants from
//! `bzlib.h`.

/// pgBackRust error category the C side should `THROWP` with for a given libbz2 error
/// code.
///
/// Discriminants are stable across the FFI boundary; the C wrapper maps each variant to
/// the matching `ErrorType *` pointer (`AssertError` / `FormatError` / `MemoryError`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// "Should not happen" / programming-bug class — `BZ_SEQUENCE_ERROR`,
    /// `BZ_PARAM_ERROR`, `BZ_IO_ERROR`, `BZ_UNEXPECTED_EOF`, `BZ_OUTBUFF_FULL`,
    /// `BZ_CONFIG_ERROR`, plus the catch-all unknown-code path.
    Assert = 0,
    /// Caller-supplied input was malformed — `BZ_DATA_ERROR`, `BZ_DATA_ERROR_MAGIC`.
    Format = 1,
    /// Allocation failure — `BZ_MEM_ERROR`.
    Memory = 2,
}

/// Result of [`classify`]: either the input was non-erroneous (`Ok` carrying the
/// original code) or it was erroneous and needs to be thrown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// `code >= 0` — return `code` to the caller, no throw.
    Ok { code: i32 },
    /// `code < 0` — throw `kind` with the given short message and the `code` formatted
    /// in.
    Throw { code: i32, kind: ErrorKind, message: &'static str },
}

/// Inspect a libbz2 return code and decide whether it represents an error.
///
/// Mirrors the legacy `bz2Error` switch — same list of recognized codes, same mapping
/// to `AssertError` / `FormatError` / `MemoryError`, same human-readable message
/// strings.
#[must_use]
pub const fn classify(code: i32) -> Classification {
    if code >= 0 {
        return Classification::Ok { code };
    }

    // Constants taken straight from `bzlib.h`. Hard-coded so this module does not need
    // a `bzip2-sys` dependency just to expose a handful of integer codes.
    let bz_sequence_error: i32 = -1;
    let bz_param_error: i32 = -2;
    let bz_mem_error: i32 = -3;
    let bz_data_error: i32 = -4;
    let bz_data_error_magic: i32 = -5;
    let bz_io_error: i32 = -6;
    let bz_unexpected_eof: i32 = -7;
    let bz_outbuff_full: i32 = -8;
    let bz_config_error: i32 = -9;

    let (kind, message) = if code == bz_sequence_error {
        (ErrorKind::Assert, "sequence error")
    } else if code == bz_param_error {
        (ErrorKind::Assert, "parameter error")
    } else if code == bz_mem_error {
        (ErrorKind::Memory, "memory error")
    } else if code == bz_data_error {
        (ErrorKind::Format, "data error")
    } else if code == bz_data_error_magic {
        (ErrorKind::Format, "data error magic")
    } else if code == bz_io_error {
        (ErrorKind::Assert, "io error")
    } else if code == bz_unexpected_eof {
        (ErrorKind::Assert, "unexpected eof")
    } else if code == bz_outbuff_full {
        (ErrorKind::Assert, "outbuff full")
    } else if code == bz_config_error {
        (ErrorKind::Assert, "config error")
    } else {
        (ErrorKind::Assert, "unknown error")
    };

    Classification::Throw { code, kind, message }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{Classification, ErrorKind, classify};

    #[test]
    fn non_negative_codes_do_not_throw() {
        for code in [0, 1, 2, 3, 4, 100, i32::MAX] {
            assert_eq!(classify(code), Classification::Ok { code });
        }
    }

    #[test]
    fn known_error_codes_map_to_legacy_messages() {
        let cases = [
            (-1, ErrorKind::Assert, "sequence error"),
            (-2, ErrorKind::Assert, "parameter error"),
            (-3, ErrorKind::Memory, "memory error"),
            (-4, ErrorKind::Format, "data error"),
            (-5, ErrorKind::Format, "data error magic"),
            (-6, ErrorKind::Assert, "io error"),
            (-7, ErrorKind::Assert, "unexpected eof"),
            (-8, ErrorKind::Assert, "outbuff full"),
            (-9, ErrorKind::Assert, "config error"),
        ];
        for (code, kind, message) in cases {
            assert_eq!(classify(code), Classification::Throw { code, kind, message });
        }
    }

    #[test]
    fn unknown_codes_become_assert_unknown() {
        for code in [-10, -100, -999, i32::MIN] {
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
