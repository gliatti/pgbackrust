//! Foundational types shared across the workspace.
//!
//! For now this crate exposes two read-only borrowed views over C-managed buffers, [`RefStr`]
//! and [`RefBuf`]. They give intermediate migration phases a way to receive UTF-8 strings or
//! byte slices from C without copying or taking ownership, while keeping the lifetime
//! relationship between the borrowed view and the underlying C object explicit in the type
//! system.

#![cfg_attr(not(test), forbid(unsafe_op_in_unsafe_fn))]

pub mod debug;

use core::ffi::{CStr, c_char};
use core::fmt;
use core::marker::PhantomData;

/// Read-only borrowed view of a UTF-8 string owned by the C side.
///
/// `RefStr<'a>` is a zero-cost wrapper over `&'a str`. It cannot be constructed from a raw
/// pointer without asserting (via an `unsafe` constructor) that the underlying bytes are valid
/// UTF-8 and that the lifetime `'a` does not outlive the C object that owns the buffer.
///
/// # Examples
///
/// ```
/// use pgbr_core::RefStr;
/// let owned = String::from("hello");
/// // SAFETY: `owned`'s bytes are valid UTF-8 and outlive the borrow.
/// let view = unsafe { RefStr::from_raw_parts(owned.as_ptr(), owned.len()) };
/// assert_eq!(view.as_str(), "hello");
/// assert_eq!(view.len(), 5);
/// assert!(!view.is_empty());
/// ```
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct RefStr<'a> {
    inner: &'a str,
}

impl<'a> RefStr<'a> {
    /// Borrow a UTF-8 string from a raw pointer/length pair owned by the C side.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and point to at least `len` bytes of readable memory.
    /// - The first `len` bytes at `ptr` must be valid UTF-8.
    /// - The lifetime `'a` must not outlive the C-side ownership of the buffer.
    /// - The buffer must not be mutated for the duration of `'a`.
    #[must_use]
    pub const unsafe fn from_raw_parts(ptr: *const u8, len: usize) -> Self {
        // SAFETY: caller upholds all invariants documented above.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        // SAFETY: caller asserts the bytes are valid UTF-8.
        let inner = unsafe { core::str::from_utf8_unchecked(bytes) };
        Self { inner }
    }

    /// Borrow a UTF-8 string from a NUL-terminated C string.
    ///
    /// Returns `None` if the string is not valid UTF-8. Returns the empty `RefStr` if `ptr` is
    /// null.
    ///
    /// # Safety
    ///
    /// - `ptr`, when non-null, must point to a NUL-terminated C string.
    /// - The lifetime `'a` must not outlive the C-side ownership of the buffer.
    /// - The buffer must not be mutated for the duration of `'a`.
    #[must_use]
    pub unsafe fn from_cstr(ptr: *const c_char) -> Option<Self> {
        if ptr.is_null() {
            return Some(Self::empty());
        }
        // SAFETY: caller asserts `ptr` is NUL-terminated and readable.
        let cstr = unsafe { CStr::from_ptr(ptr) };
        cstr.to_str().ok().map(|inner| Self { inner })
    }

    /// Build a `RefStr<'a>` from a Rust `&'a str` without any unsafe.
    #[must_use]
    pub const fn from_str(s: &'a str) -> Self {
        Self { inner: s }
    }

    /// Build an empty `RefStr` whose lifetime is unbounded by any borrow.
    #[must_use]
    pub const fn empty() -> Self {
        Self { inner: "" }
    }

    /// Borrow the underlying UTF-8 string slice.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.inner
    }

    /// Borrow the underlying byte slice.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.inner.as_bytes()
    }

    /// Length of the borrowed string in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the borrowed string is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<str> for RefStr<'_> {
    fn as_ref(&self) -> &str {
        self.inner
    }
}

impl PartialEq for RefStr<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for RefStr<'_> {}

impl PartialEq<str> for RefStr<'_> {
    fn eq(&self, other: &str) -> bool {
        self.inner == other
    }
}

impl PartialEq<&str> for RefStr<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.inner == *other
    }
}

impl fmt::Debug for RefStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.inner, f)
    }
}

impl fmt::Display for RefStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.inner, f)
    }
}

/// Read-only borrowed view of a byte buffer owned by the C side.
///
/// `RefBuf<'a>` is a zero-cost wrapper over `&'a [u8]`. Unlike [`RefStr`] it makes no UTF-8
/// guarantee — use it for binary data such as compressed blocks, page checksums, or raw manifest
/// entries.
///
/// # Examples
///
/// ```
/// use pgbr_core::RefBuf;
/// let owned = vec![1u8, 2, 3, 4];
/// // SAFETY: `owned` outlives the borrow and is not mutated.
/// let view = unsafe { RefBuf::from_raw_parts(owned.as_ptr(), owned.len()) };
/// assert_eq!(view.as_bytes(), &[1, 2, 3, 4]);
/// assert_eq!(view.len(), 4);
/// ```
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct RefBuf<'a> {
    inner: &'a [u8],
    _phantom: PhantomData<&'a ()>,
}

impl<'a> RefBuf<'a> {
    /// Borrow a byte buffer from a raw pointer/length pair owned by the C side.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and point to at least `len` bytes of readable memory.
    /// - The lifetime `'a` must not outlive the C-side ownership of the buffer.
    /// - The buffer must not be mutated for the duration of `'a`.
    #[must_use]
    pub const unsafe fn from_raw_parts(ptr: *const u8, len: usize) -> Self {
        // SAFETY: caller upholds all invariants documented above.
        let inner = unsafe { core::slice::from_raw_parts(ptr, len) };
        Self {
            inner,
            _phantom: PhantomData,
        }
    }

    /// Build a `RefBuf<'a>` from a Rust slice without any unsafe.
    #[must_use]
    pub const fn from_slice(bytes: &'a [u8]) -> Self {
        Self {
            inner: bytes,
            _phantom: PhantomData,
        }
    }

    /// Build an empty `RefBuf` whose lifetime is unbounded by any borrow.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            inner: &[],
            _phantom: PhantomData,
        }
    }

    /// Borrow the underlying byte slice.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.inner
    }

    /// Length of the borrowed buffer in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the borrowed buffer is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<[u8]> for RefBuf<'_> {
    fn as_ref(&self) -> &[u8] {
        self.inner
    }
}

impl PartialEq for RefBuf<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for RefBuf<'_> {}

impl PartialEq<[u8]> for RefBuf<'_> {
    fn eq(&self, other: &[u8]) -> bool {
        self.inner == other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for RefBuf<'_> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.inner == other.as_slice()
    }
}

impl fmt::Debug for RefBuf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefBuf").field("len", &self.inner.len()).finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn refstr_round_trip_via_raw_parts() {
        let owned = String::from("hello world");
        // SAFETY: `owned` is valid UTF-8 and outlives the borrow.
        let view = unsafe { RefStr::from_raw_parts(owned.as_ptr(), owned.len()) };
        assert_eq!(view.as_str(), "hello world");
        assert_eq!(view.len(), 11);
        assert!(!view.is_empty());
        assert_eq!(view, "hello world");
    }

    #[test]
    fn refstr_from_cstr_handles_null_and_invalid_utf8() {
        // SAFETY: null pointer is allowed by the documented contract.
        let null_view = unsafe { RefStr::from_cstr(core::ptr::null()) };
        assert_eq!(null_view.unwrap().as_str(), "");

        let owned = CString::new("café").unwrap();
        // SAFETY: CString is NUL-terminated and outlives the borrow.
        let view = unsafe { RefStr::from_cstr(owned.as_ptr()) };
        assert_eq!(view.unwrap().as_str(), "café");

        let invalid = [0xFFu8, 0xFFu8, 0u8];
        // SAFETY: `invalid` is NUL-terminated even if not UTF-8.
        let bad = unsafe { RefStr::from_cstr(invalid.as_ptr().cast()) };
        assert!(bad.is_none());
    }

    #[test]
    fn refstr_const_constructors_work_in_const_context() {
        const STATIC_VIEW: RefStr<'static> = RefStr::from_str("hello");
        const EMPTY: RefStr<'static> = RefStr::empty();
        assert_eq!(STATIC_VIEW.len(), 5);
        assert!(EMPTY.is_empty());
    }

    #[test]
    fn refbuf_round_trip_via_raw_parts() {
        let owned: [u8; 5] = [1, 2, 3, 4, 5];
        // SAFETY: `owned` outlives the borrow and is not mutated during the call.
        let view = unsafe { RefBuf::from_raw_parts(owned.as_ptr(), owned.len()) };
        assert_eq!(view.as_bytes(), &owned[..]);
        assert_eq!(view.len(), 5);
        assert_eq!(view, [1u8, 2, 3, 4, 5]);
    }

    #[test]
    fn refbuf_const_constructors_work_in_const_context() {
        const STATIC_VIEW: RefBuf<'static> = RefBuf::from_slice(b"binary data");
        const EMPTY: RefBuf<'static> = RefBuf::empty();
        assert_eq!(STATIC_VIEW.len(), 11);
        assert!(EMPTY.is_empty());
    }

    #[test]
    fn refbuf_debug_does_not_dump_contents() {
        let view = RefBuf::from_slice(&[1, 2, 3]);
        let rendered = format!("{view:?}");
        assert!(rendered.contains("len: 3"));
        assert!(!rendered.contains('1'));
    }
}
