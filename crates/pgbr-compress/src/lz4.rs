//! liblz4 glue: error-code classification (Phase 17).
//!
//! Mirrors `lz4Error` in `src/common/compress/lz4/common.c`. Takes an `LZ4F_errorCode_t`
//! return code (a `size_t` whose error values are the encoded negative-int range that
//! `LZ4F_isError` recognizes) and decides whether the C side should `THROW` a
//! `FormatError`. The error-name string comes straight from `LZ4F_getErrorName` so the
//! formatted exception text is identical to the legacy path byte-for-byte.

pub mod error {
    //! `lz4Error` classification.

    use core::ffi::CStr;

    /// Outcome of [`classify`].
    ///
    /// Either the input was non-erroneous (return code passes through) or it was
    /// erroneous and the C side must throw a `FormatError` with the formatted message
    /// `lz4 error: [<code>] <name>`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Classification<'a> {
        /// `LZ4F_isError(code) == 0` — return `code` to the caller, no throw.
        Ok { code: usize },
        /// `LZ4F_isError(code) == 1` — throw `FormatError` with the given name string.
        ///
        /// The byte slice is owned by the linked liblz4 (returned by
        /// `LZ4F_getErrorName`), so the lifetime is effectively `'static` from the C
        /// caller's point of view; we tag it with `'a` here only to keep the borrow
        /// checker happy when the slice transitively comes from a stack-allocated `CStr`.
        Throw { code: usize, name: &'a [u8] },
    }

    /// Inspect an `LZ4F_errorCode_t` and decide whether it represents an error.
    ///
    /// Calls `LZ4F_isError` to detect the error encoding; on a hit, fetches the
    /// human-readable name with `LZ4F_getErrorName`.
    #[must_use]
    pub fn classify(code: usize) -> Classification<'static> {
        // SAFETY: both `LZ4F_isError` and `LZ4F_getErrorName` are documented as pure
        // functions of their input — no global state, no side effects. The string returned
        // by `LZ4F_getErrorName` is a static, NUL-terminated, library-owned constant
        // valid for the lifetime of the process.
        #[allow(unsafe_code)]
        let is_err = unsafe { lz4_sys::LZ4F_isError(code) };

        if is_err == 0 {
            return Classification::Ok { code };
        }

        // SAFETY: see above — the returned pointer is a static string.
        #[allow(unsafe_code)]
        let name_ptr = unsafe { lz4_sys::LZ4F_getErrorName(code) };

        // Defensive null check: the lz4 library never returns null for this API in
        // practice (it falls back to a sentinel string for unknown codes), but treat null
        // as "<unknown>" so we never crash inside an FFI shim.
        let name: &'static [u8] = if name_ptr.is_null() {
            b"<unknown>"
        } else {
            // SAFETY: `name_ptr` is a static, NUL-terminated UTF-8 string from liblz4.
            #[allow(unsafe_code)]
            let cstr = unsafe { CStr::from_ptr(name_ptr) };
            cstr.to_bytes()
        };

        Classification::Throw { code, name }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::error::{Classification, classify};

    #[test]
    fn zero_is_ok() {
        assert_eq!(classify(0), Classification::Ok { code: 0 });
    }

    #[test]
    fn small_positive_is_ok() {
        // `LZ4F_isError` only flags the "negative-encoded" sentinels at the top of the
        // size_t range; small positive values are valid byte counts.
        for code in [1_usize, 2, 100, 1024, 1 << 20] {
            assert_eq!(classify(code), Classification::Ok { code });
        }
    }

    #[test]
    fn known_error_codes_match_legacy_messages() {
        // Same fixtures the C compressTest uses (size_t cast of -2 → ERROR_maxBlockSize_invalid).
        #[allow(clippy::cast_sign_loss)]
        let neg2 = -2_isize as usize;
        match classify(neg2) {
            Classification::Throw { code, name } => {
                assert_eq!(code, neg2);
                assert_eq!(name, b"ERROR_maxBlockSize_invalid");
            }
            Classification::Ok { code } => panic!("expected Throw, got Ok({code})"),
        }
    }

    #[test]
    fn negative_one_is_generic_error_text() {
        // -1 is the legacy "GENERIC" error; lz4 returns "ERROR_GENERIC".
        #[allow(clippy::cast_sign_loss)]
        let neg1 = -1_isize as usize;
        match classify(neg1) {
            Classification::Throw { code, name } => {
                assert_eq!(code, neg1);
                assert!(!name.is_empty(), "lz4 must surface a non-empty name");
            }
            Classification::Ok { code } => panic!("expected Throw, got Ok({code})"),
        }
    }
}
