//! Compression helpers shared across the pgBackRust workspace.
//!
//! Currently exposes a single submodule:
//!
//! - [`gz`] — zlib error-code classification ported from `src/common/compress/gz/common.c`. The
//!   actual compression / decompression streaming will land in later phases of the C→Rust
//!   migration.

#![cfg_attr(not(test), forbid(unsafe_code))]

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
