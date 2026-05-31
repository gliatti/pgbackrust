//! `zstError` classification — Phase 23.
//!
//! Mirrors `zstError` in `src/common/compress/zst/common.c`. Takes a libzstd return
//! code (a `size_t` whose error values are the encoded negative-int range that
//! `ZSTD_isError` recognizes) and decides whether the C side should `THROW` a
//! `FormatError`. The error-name string comes straight from `ZSTD_getErrorName` so the
//! formatted exception text is identical to the legacy path byte-for-byte.

use core::ffi::CStr;

/// Outcome of [`classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification<'a> {
    /// `ZSTD_isError(code) == 0` — return `code` to the caller, no throw.
    Ok { code: usize },
    /// `ZSTD_isError(code) != 0` — throw `FormatError` with the given name string.
    Throw { code: usize, name: &'a [u8] },
}

/// Inspect a libzstd return code and decide whether it represents an error.
#[must_use]
pub fn classify(code: usize) -> Classification<'static> {
    // SAFETY: `ZSTD_isError` and `ZSTD_getErrorName` are documented as pure functions
    // of their input. The string returned by `ZSTD_getErrorName` is a static,
    // NUL-terminated, library-owned constant valid for the lifetime of the process.
    #[allow(unsafe_code)]
    let is_err = unsafe { zstd_sys::ZSTD_isError(code) };

    if is_err == 0 {
        return Classification::Ok { code };
    }

    // SAFETY: see above — the returned pointer is a static string.
    #[allow(unsafe_code)]
    let name_ptr = unsafe { zstd_sys::ZSTD_getErrorName(code) };

    let name: &'static [u8] = if name_ptr.is_null() {
        b"<unknown>"
    } else {
        // SAFETY: `name_ptr` is a static, NUL-terminated UTF-8 string from libzstd.
        #[allow(unsafe_code)]
        let cstr = unsafe { CStr::from_ptr(name_ptr) };
        cstr.to_bytes()
    };

    Classification::Throw { code, name }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{Classification, classify};

    #[test]
    fn zero_is_ok() {
        assert_eq!(classify(0), Classification::Ok { code: 0 });
    }

    #[test]
    fn small_positive_is_ok() {
        for code in [1_usize, 100, 1024, 1 << 20] {
            assert_eq!(classify(code), Classification::Ok { code });
        }
    }

    #[test]
    fn known_error_codes_yield_named_errors() {
        // libzstd's error encoding flags `(size_t)-N` for small N as errors. The exact
        // names depend on the linked libzstd version, so just assert the name is
        // non-empty and starts with the expected prefix-friendly pattern.
        #[allow(clippy::cast_sign_loss)]
        let neg1 = -1_isize as usize;
        match classify(neg1) {
            Classification::Throw { code, name } => {
                assert_eq!(code, neg1);
                assert!(!name.is_empty(), "libzstd must surface a non-empty name");
            }
            Classification::Ok { code } => panic!("expected Throw, got Ok({code})"),
        }
    }
}
