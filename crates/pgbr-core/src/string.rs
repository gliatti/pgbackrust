//! `String` type migrated from `src/common/type/string.c`.
//!
//! Owns the byte-identical mirror of the C `StringPub` (size + extra bitfields packed
//! into a `u64`, then the `char *` buffer) plus every algorithmic body except the
//! variadic / cross-module entry points (which stay on the C side and call back into
//! these helpers). The static name passed to `mem_context_new` is "String" — same
//! token the legacy `OBJ_NEW_BEGIN(String, ...)` macro produced.
//!
//! The layout assumption is GCC + little-endian, which is what every CI VM in
//! `.github/workflows/test.yml` runs on (u22 / d11 / f43 / rh8 — all `x86_64`) and what
//! the `compile_assert_string_layout` C-side test in `typecTest.c` verifies on every
//! build. A `const_assert` here pins the Rust mirror to the same shape.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::ptr_as_ptr
)]

use core::ffi::{c_char, c_void};
use core::ptr;

use crate::mem_context;

/// Maximum size of a `String` in bytes (`STRING_SIZE_MAX` in `src/common/type/string.c`).
pub const STRING_SIZE_MAX: u64 = 1_073_741_824;

/// Minimum extra bytes to allocate for growing strings (`STRING_EXTRA_MIN` in
/// `src/common/type/string.h`).
pub const STRING_EXTRA_MIN: u32 = 64;

/// `MEM_CONTEXT_ALLOC_EXTRA_MAX` from `src/common/memContext.h`.
const MEM_CONTEXT_ALLOC_EXTRA_MAX: usize = u16::MAX as usize;

const NAME: &core::ffi::CStr = c"String";

/// Mirror of the C `StringPub` struct.
///
/// The legacy declaration is:
///
/// ```c
/// typedef struct StringPub {
///     uint64_t size : 32;
///     uint64_t extra : 32;
///     char *buffer;
/// } StringPub;
/// ```
///
/// On GCC + little-endian, `size` lives in the low 32 bits of the packed `u64` word
/// and `extra` in the high 32 bits. We expose the packed word directly and provide
/// accessors that mask / shift the same way the C bitfield does.
#[repr(C)]
pub struct StringPub {
    /// `size` (low 32 bits) and `extra` (high 32 bits) packed into one 64-bit word.
    pub size_extra: u64,
    pub buffer: *mut c_char,
}

// `String` and `StringPub` must be the same size — `struct String { StringPub pub; }`.
const _: () = assert!(core::mem::size_of::<StringPub>() == 2 * core::mem::size_of::<*mut c_char>());

impl StringPub {
    #[must_use]
    pub const fn size(&self) -> u32 {
        (self.size_extra & 0xFFFF_FFFF) as u32
    }

    #[must_use]
    pub const fn extra(&self) -> u32 {
        (self.size_extra >> 32) as u32
    }

    pub const fn set_size(&mut self, value: u32) {
        self.size_extra = (self.size_extra & 0xFFFF_FFFF_0000_0000) | (value as u64);
    }

    pub const fn set_extra(&mut self, value: u32) {
        self.size_extra = (self.size_extra & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
    }
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/// `strNew`: create an empty growable string.
///
/// # Safety
///
/// Single-threaded mem-context invariant. `try_depth` from `errorTryDepth()`.
#[must_use]
pub unsafe fn new(empty_buffer: *const c_char, try_depth: u32) -> *mut StringPub {
    // SAFETY: caller upholds the invariant.
    let mc = unsafe { mem_context::mem_context_new(NAME.as_ptr(), 0, 1, 0, sizeof_string_pub_u16(), try_depth) };
    // SAFETY: same.
    unsafe { mem_context::switch(mc.cast(), try_depth) };
    // SAFETY: alloc-extra slot is sized for StringPub.
    let this: *mut StringPub = unsafe { mem_context::mem_context_alloc_extra(mc).cast::<StringPub>() };
    // SAFETY: this points at writable storage of sizeof(StringPub) inside the new context.
    unsafe {
        ptr::write(
            this,
            StringPub {
                size_extra: 0,
                buffer: empty_buffer.cast_mut(),
            },
        );
    }
    let _ = mem_context::switch_back();
    let _ = mem_context::keep();
    this
}

/// `strNewFixed`: create a fixed-size string of `size` bytes plus the trailing NUL.
///
/// The buffer either lives in the new context's `allocExtra` slot (when the total
/// `sizeof(String) + size + 1` fits in the 64 KiB cap) or in a separate allocation.
///
/// # Safety
///
/// `size <= STRING_SIZE_MAX`. Single-threaded mem-context invariant.
#[must_use]
pub unsafe fn new_fixed(size: usize, try_depth: u32) -> *mut StringPub {
    assert!(size as u64 <= STRING_SIZE_MAX, "string size out of range");

    let alloc_extra_total = core::mem::size_of::<StringPub>() + size + 1;

    if alloc_extra_total > MEM_CONTEXT_ALLOC_EXTRA_MAX {
        // Allocate buffer separately.
        // SAFETY: caller upholds the invariant.
        let mc = unsafe { mem_context::mem_context_new(NAME.as_ptr(), 0, 1, 0, sizeof_string_pub_u16(), try_depth) };
        // SAFETY: same.
        unsafe { mem_context::switch(mc.cast(), try_depth) };
        let this: *mut StringPub = unsafe { mem_context::mem_context_alloc_extra(mc).cast::<StringPub>() };
        let buffer = unsafe { mem_context::mem_new(size + 1).cast::<c_char>() };
        unsafe {
            let mut pub_ = StringPub { size_extra: 0, buffer };
            #[allow(clippy::cast_possible_truncation)]
            pub_.set_size(size as u32);
            ptr::write(this, pub_);
        }
        let _ = mem_context::switch_back();
        let _ = mem_context::keep();
        this
    } else {
        // Fold buffer into the alloc-extra slot, just past the StringPub header.
        // SAFETY: caller upholds the invariant.
        let mc = unsafe {
            mem_context::mem_context_new(
                NAME.as_ptr(),
                0,
                1,
                0,
                #[allow(clippy::cast_possible_truncation)]
                {
                    alloc_extra_total as u16
                },
                try_depth,
            )
        };
        // SAFETY: same.
        unsafe { mem_context::switch(mc.cast(), try_depth) };
        let this: *mut StringPub = unsafe { mem_context::mem_context_alloc_extra(mc).cast::<StringPub>() };
        // The fixed buffer sits immediately after the StringPub bytes inside the alloc-extra slot.
        // SAFETY: alloc-extra slot is `alloc_extra_total` bytes; offset + 1 buffer byte fits.
        let buffer = unsafe { (this as *mut u8).add(core::mem::size_of::<StringPub>()).cast::<c_char>() };
        unsafe {
            let mut pub_ = StringPub { size_extra: 0, buffer };
            #[allow(clippy::cast_possible_truncation)]
            pub_.set_size(size as u32);
            ptr::write(this, pub_);
        }
        let _ = mem_context::switch_back();
        let _ = mem_context::keep();
        this
    }
}

#[allow(clippy::cast_possible_truncation)]
const fn sizeof_string_pub_u16() -> u16 {
    core::mem::size_of::<StringPub>() as u16
}

/// `strNewZ`: copy a NUL-terminated C string.
///
/// # Safety
///
/// `s` must be NUL-terminated and readable.
#[must_use]
pub unsafe fn new_z(s: *const c_char, try_depth: u32) -> *mut StringPub {
    // SAFETY: caller guarantees `s` is NUL-terminated.
    let size = unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes().len();
    // SAFETY: same.
    let this = unsafe { new_fixed(size, try_depth) };
    // SAFETY: `this->buffer` is sized for `size + 1` bytes; we just allocated it.
    unsafe {
        let pub_ = &mut *this;
        ptr::copy_nonoverlapping(s.cast::<u8>(), pub_.buffer.cast::<u8>(), size);
        *pub_.buffer.add(size) = 0;
    }
    this
}

/// `strNewZN`: copy `size` bytes from `s`. The source need not be NUL-terminated.
///
/// # Safety
///
/// `s` must be readable for `size` bytes (when `size > 0`).
#[must_use]
pub unsafe fn new_zn(s: *const c_char, size: usize, try_depth: u32) -> *mut StringPub {
    // SAFETY: caller upholds the invariant.
    let this = unsafe { new_fixed(size, try_depth) };
    // SAFETY: `this->buffer` is sized for `size + 1` bytes.
    unsafe {
        let pub_ = &mut *this;
        if size != 0 {
            ptr::copy_nonoverlapping(s.cast::<u8>(), pub_.buffer.cast::<u8>(), size);
        }
        *pub_.buffer.add(size) = 0;
    }
    this
}

/// `strDup(this)`: deep-copy. Returns null when `this` is null.
///
/// # Safety
///
/// `this` may be null; otherwise must be a live `String *`.
#[must_use]
pub unsafe fn dup(this: *const StringPub, try_depth: u32) -> *mut StringPub {
    if this.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `this` is live.
    let pub_ = unsafe { &*this };
    // SAFETY: `buffer` is the live String's NUL-terminated buffer.
    unsafe { new_z(pub_.buffer, try_depth) }
}

// -----------------------------------------------------------------------------
// Resize / append
// -----------------------------------------------------------------------------

/// `strResize`: grow the string buffer to allow `requested` more bytes.
///
/// # Safety
///
/// `this` must be a live `String *` whose buffer is heap-allocated (not a fixed
/// in-context buffer and not the empty literal); the C side enforces this with an
/// assertion the wrapper still runs.
pub unsafe fn resize(this: *mut StringPub, requested: usize, try_depth: u32, empty_buffer: *const c_char) {
    // SAFETY: caller guarantees `this` is live.
    let pub_ = unsafe { &mut *this };

    if requested as u32 > pub_.extra() {
        let size_total = pub_.size() as u64 + requested as u64;
        assert!(size_total <= STRING_SIZE_MAX, "string size out of range");

        // New extra: requested + (size + requested) / 2, clamped to STRING_EXTRA_MIN.
        let mut new_extra = (requested as u64) + (size_total / 2);
        if new_extra < STRING_EXTRA_MIN as u64 {
            new_extra = STRING_EXTRA_MIN as u64;
        }
        assert!(u32::try_from(new_extra).is_ok(), "extra overflow");
        let new_extra_u32 = new_extra as u32;
        pub_.set_extra(new_extra_u32);

        // Resolve owning context and switch in (mirrors `MEM_CONTEXT_OBJ_BEGIN(this)`).
        // SAFETY: `this` lives in an alloc-extra slot.
        let mc = unsafe { mem_context::mem_context_from_alloc_extra(this.cast::<c_void>()) };
        // SAFETY: live MemContext.
        unsafe { mem_context::switch(mc.cast(), try_depth) };

        let new_size = pub_.size() as usize + new_extra_u32 as usize + 1;

        if pub_.buffer == empty_buffer.cast_mut() {
            // SAFETY: allocate inside the obj's context.
            pub_.buffer = unsafe { mem_context::mem_new(new_size).cast::<c_char>() };
        } else {
            // SAFETY: same — pgbr_mem_resize picks up the same allocator.
            pub_.buffer = unsafe { mem_context::mem_resize(pub_.buffer.cast::<c_void>(), new_size).cast::<c_char>() };
        }

        let _ = mem_context::switch_back();
    }
}

/// `strCatZN(this, cat, size)`: append `size` bytes from `cat`.
///
/// # Safety
///
/// `this` is a live growable `String *`. `cat` is readable for `size` bytes when
/// `size > 0`.
#[must_use]
pub unsafe fn cat_zn(
    this: *mut StringPub,
    cat: *const c_char,
    size: usize,
    try_depth: u32,
    empty_buffer: *const c_char,
) -> *mut StringPub {
    if size != 0 {
        // SAFETY: caller upholds the contract.
        unsafe { resize(this, size, try_depth, empty_buffer) };
        // SAFETY: same.
        let pub_ = unsafe { &mut *this };
        // SAFETY: buffer has room for `size_old + size + 1` bytes after resize.
        unsafe {
            let dst = pub_.buffer.add(pub_.size() as usize);
            ptr::copy_nonoverlapping(cat.cast::<u8>(), dst.cast::<u8>(), size);
            *dst.add(size) = 0;
        }
        #[allow(clippy::cast_possible_truncation)]
        let size_u32 = size as u32;
        pub_.set_size(pub_.size() + size_u32);
        pub_.set_extra(pub_.extra() - size_u32);
    }
    this
}

/// `strCatZ(this, cat)`: append a NUL-terminated C string.
///
/// # Safety
///
/// `this` is a live growable `String *`. `cat` is NUL-terminated.
#[must_use]
pub unsafe fn cat_z(this: *mut StringPub, cat: *const c_char, try_depth: u32, empty_buffer: *const c_char) -> *mut StringPub {
    // SAFETY: caller guarantees `cat` is NUL-terminated.
    let size = unsafe { core::ffi::CStr::from_ptr(cat) }.to_bytes().len();
    // SAFETY: contract upheld.
    unsafe { cat_zn(this, cat, size, try_depth, empty_buffer) }
}

/// `strCatChr(this, c)`: append a single (non-NUL) character.
///
/// # Safety
///
/// `this` is a live growable `String *`. `c != 0`.
#[must_use]
pub unsafe fn cat_chr(this: *mut StringPub, c: c_char, try_depth: u32, empty_buffer: *const c_char) -> *mut StringPub {
    // SAFETY: caller upholds the contract.
    unsafe { resize(this, 1, try_depth, empty_buffer) };
    // SAFETY: same.
    let pub_ = unsafe { &mut *this };
    let pos = pub_.size() as usize;
    // SAFETY: buffer has room.
    unsafe {
        *pub_.buffer.add(pos) = c;
        *pub_.buffer.add(pos + 1) = 0;
    }
    pub_.set_size(pub_.size() + 1);
    pub_.set_extra(pub_.extra() - 1);
    this
}

// -----------------------------------------------------------------------------
// Predicates
// -----------------------------------------------------------------------------

/// `strEmpty(this)`: true if size == 0.
///
/// # Safety
///
/// `this` must be a live `String *`.
#[must_use]
pub const unsafe fn empty(this: *const StringPub) -> bool {
    // SAFETY: caller guarantees liveness.
    unsafe { (*this).size() == 0 }
}

/// `strBeginsWithZ(this, prefix)`.
///
/// # Safety
///
/// `this` is live; `prefix` is NUL-terminated.
#[must_use]
pub unsafe fn begins_with_z(this: *const StringPub, prefix: *const c_char) -> bool {
    // SAFETY: caller guarantees `prefix` is NUL-terminated.
    let prefix_bytes = unsafe { core::ffi::CStr::from_ptr(prefix) }.to_bytes();
    // SAFETY: live String.
    let pub_ = unsafe { &*this };
    if (pub_.size() as usize) < prefix_bytes.len() {
        return false;
    }
    // SAFETY: buffer has at least `size` bytes followed by NUL.
    let this_bytes = unsafe { core::slice::from_raw_parts(pub_.buffer.cast::<u8>(), prefix_bytes.len()) };
    this_bytes == prefix_bytes
}

/// `strEndsWithZ(this, suffix)`.
///
/// # Safety
///
/// `this` is live; `suffix` is NUL-terminated.
#[must_use]
pub unsafe fn ends_with_z(this: *const StringPub, suffix: *const c_char) -> bool {
    // SAFETY: caller guarantees `suffix` is NUL-terminated.
    let suffix_bytes = unsafe { core::ffi::CStr::from_ptr(suffix) }.to_bytes();
    // SAFETY: live String.
    let pub_ = unsafe { &*this };
    if (pub_.size() as usize) < suffix_bytes.len() {
        return false;
    }
    // SAFETY: buffer has at least `size` bytes.
    let tail = unsafe {
        core::slice::from_raw_parts(
            pub_.buffer.cast::<u8>().add(pub_.size() as usize - suffix_bytes.len()),
            suffix_bytes.len(),
        )
    };
    tail == suffix_bytes
}

/// `strEq(a, b)`: NULL-tolerant byte equality.
///
/// # Safety
///
/// Either pointer may be null; otherwise must be a live `String *`.
#[must_use]
pub unsafe fn eq(a: *const StringPub, b: *const StringPub) -> bool {
    if a.is_null() || b.is_null() {
        return a.is_null() && b.is_null();
    }
    // SAFETY: both live by the early-out above.
    let (a_pub, b_pub) = unsafe { (&*a, &*b) };
    if a_pub.size() != b_pub.size() {
        return false;
    }
    // SAFETY: buffers are NUL-terminated and at least `size` bytes long.
    let a_bytes = unsafe { core::slice::from_raw_parts(a_pub.buffer.cast::<u8>(), a_pub.size() as usize) };
    let b_bytes = unsafe { core::slice::from_raw_parts(b_pub.buffer.cast::<u8>(), b_pub.size() as usize) };
    a_bytes == b_bytes
}

/// `strEqZ(this, other_z)`: compare against a C string. Caller asserts both non-null.
///
/// # Safety
///
/// `this` is live; `other` is NUL-terminated.
#[must_use]
pub unsafe fn eq_z(this: *const StringPub, other: *const c_char) -> bool {
    // SAFETY: callers upholds the contract.
    let pub_ = unsafe { &*this };
    let other_bytes = unsafe { core::ffi::CStr::from_ptr(other) }.to_bytes();
    if pub_.size() as usize != other_bytes.len() {
        return false;
    }
    let this_bytes = unsafe { core::slice::from_raw_parts(pub_.buffer.cast::<u8>(), pub_.size() as usize) };
    this_bytes == other_bytes
}

/// `strCmp(a, b)`: NULL-tolerant `strcmp`.
///
/// # Safety
///
/// Either pointer may be null; otherwise must be a live `String *`.
#[must_use]
pub unsafe fn cmp(a: *const StringPub, b: *const StringPub) -> i32 {
    match (a.is_null(), b.is_null()) {
        (true, true) => 0,
        (true, false) => -1,
        (false, true) => 1,
        (false, false) => {
            // SAFETY: both live.
            let (a_pub, b_pub) = unsafe { (&*a, &*b) };
            // SAFETY: buffers are NUL-terminated.
            unsafe { libc_strcmp(a_pub.buffer, b_pub.buffer) }
        }
    }
}

/// # Safety
///
/// Both pointers are NUL-terminated readable C strings.
unsafe fn libc_strcmp(a: *const c_char, b: *const c_char) -> i32 {
    unsafe extern "C" {
        fn strcmp(a: *const c_char, b: *const c_char) -> i32;
    }
    // SAFETY: caller upholds the contract.
    unsafe { strcmp(a, b) }
}

/// `strChr(this, c)`: index of `c` or -1.
///
/// # Safety
///
/// `this` is live.
#[must_use]
pub unsafe fn chr(this: *const StringPub, c: c_char) -> i32 {
    // SAFETY: live.
    let pub_ = unsafe { &*this };
    if pub_.size() == 0 {
        return -1;
    }
    // SAFETY: buffer is NUL-terminated.
    let bytes = unsafe { core::slice::from_raw_parts(pub_.buffer.cast::<u8>(), pub_.size() as usize) };
    bytes
        .iter()
        .position(|&b| b == c as u8)
        .and_then(|p| i32::try_from(p).ok())
        .unwrap_or(-1)
}

// -----------------------------------------------------------------------------
// In-place mutation
// -----------------------------------------------------------------------------

/// `strFirstUpper(this)`: uppercase first char.
///
/// # Safety
///
/// `this` is live.
#[must_use]
pub unsafe fn first_upper(this: *mut StringPub) -> *mut StringPub {
    // SAFETY: live.
    let pub_ = unsafe { &mut *this };
    if pub_.size() > 0 {
        // SAFETY: buffer has at least one byte.
        unsafe {
            let p = pub_.buffer;
            *p = (*p as u8).to_ascii_uppercase() as c_char;
        }
    }
    this
}

/// `strFirstLower(this)`: lowercase first char.
///
/// # Safety
///
/// `this` is live.
#[must_use]
pub unsafe fn first_lower(this: *mut StringPub) -> *mut StringPub {
    // SAFETY: live.
    let pub_ = unsafe { &mut *this };
    if pub_.size() > 0 {
        // SAFETY: buffer has at least one byte.
        unsafe {
            let p = pub_.buffer;
            *p = (*p as u8).to_ascii_lowercase() as c_char;
        }
    }
    this
}

/// `strLower(this)`: lowercase entire string.
///
/// # Safety
///
/// `this` is live.
#[must_use]
pub unsafe fn lower(this: *mut StringPub) -> *mut StringPub {
    // SAFETY: live.
    let pub_ = unsafe { &mut *this };
    let len = pub_.size() as usize;
    // SAFETY: buffer has at least `size` bytes.
    let bytes = unsafe { core::slice::from_raw_parts_mut(pub_.buffer.cast::<u8>(), len) };
    for b in bytes.iter_mut() {
        *b = b.to_ascii_lowercase();
    }
    this
}

/// `strReplaceChr(this, find, replace)`.
///
/// # Safety
///
/// `this` is live.
#[must_use]
pub unsafe fn replace_chr(this: *mut StringPub, find: c_char, replace: c_char) -> *mut StringPub {
    // SAFETY: live.
    let pub_ = unsafe { &mut *this };
    let len = pub_.size() as usize;
    // SAFETY: buffer has at least `size` bytes.
    let bytes = unsafe { core::slice::from_raw_parts_mut(pub_.buffer.cast::<u8>(), len) };
    for b in bytes.iter_mut() {
        if *b == find as u8 {
            *b = replace as u8;
        }
    }
    this
}

/// `strTrim(this)`: trim ASCII whitespace from both ends.
///
/// # Safety
///
/// `this` is live.
#[must_use]
pub unsafe fn trim(this: *mut StringPub) -> *mut StringPub {
    // SAFETY: live.
    let pub_ = unsafe { &mut *this };
    if pub_.size() == 0 {
        return this;
    }
    let len = pub_.size() as usize;
    // SAFETY: buffer has `size + 1` bytes.
    let bytes = unsafe { core::slice::from_raw_parts_mut(pub_.buffer.cast::<u8>(), len) };

    let mut begin = 0;
    while begin < len && matches!(bytes[begin], b' ' | b'\t' | b'\r' | b'\n') {
        begin += 1;
    }

    let mut end = len; // exclusive
    while end > begin && matches!(bytes[end - 1], b' ' | b'\t' | b'\r' | b'\n') {
        end -= 1;
    }

    let new_size = end - begin;
    if begin != 0 || new_size < len {
        if new_size > 0 {
            // SAFETY: source and dest within the same buffer; using copy (overlap-safe).
            unsafe {
                ptr::copy(pub_.buffer.add(begin), pub_.buffer, new_size);
            }
        }
        // SAFETY: position `new_size` is within `len`.
        unsafe {
            *pub_.buffer.add(new_size) = 0;
        }
        #[allow(clippy::cast_possible_truncation)]
        let removed = (len - new_size) as u32;
        pub_.set_size(pub_.size() - removed);
        pub_.set_extra(pub_.extra() + removed);
    }
    this
}

/// `strTruncIdx(this, idx)`.
///
/// # Safety
///
/// `this` is live; `0 <= idx <= size`.
#[must_use]
pub unsafe fn trunc_idx(this: *mut StringPub, idx: i32) -> *mut StringPub {
    // SAFETY: live.
    let pub_ = unsafe { &mut *this };
    debug_assert!(idx >= 0);
    let idx_usize = idx as usize;
    debug_assert!(idx_usize <= pub_.size() as usize);
    if pub_.size() > 0 {
        let removed = pub_.size() - idx as u32;
        pub_.set_extra(pub_.extra() + removed);
        pub_.set_size(idx as u32);
        // SAFETY: buffer has room for at least `idx + 1` bytes.
        unsafe { *pub_.buffer.add(idx_usize) = 0 };
    }
    this
}

/// `strBaseZ(this)`: pointer to the file part of a path-like string.
///
/// # Safety
///
/// `this` is live.
#[must_use]
pub unsafe fn base_z(this: *const StringPub) -> *const c_char {
    // SAFETY: live.
    let pub_ = unsafe { &*this };
    let len = pub_.size() as usize;
    let mut end = len; // index past the end
    while end > 0 {
        // SAFETY: buffer has `size + 1` bytes.
        let prev = unsafe { *pub_.buffer.add(end - 1) };
        if prev == b'/' as c_char {
            break;
        }
        end -= 1;
    }
    // SAFETY: `end` is in [0, len].
    unsafe { pub_.buffer.add(end) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // The end-to-end allocation behaviour requires the C-side mem-context machinery;
    // these pure-Rust tests pin down the layout and the size/extra accessor algebra
    // that the C-side `compile_assert_string_layout` test in `typecTest.c` is the
    // build-time companion to.

    #[test]
    fn string_pub_is_two_words() {
        assert_eq!(core::mem::size_of::<StringPub>(), 2 * core::mem::size_of::<*mut c_char>());
    }

    #[test]
    fn size_extra_packing_matches_c_bitfields() {
        let mut p = StringPub {
            size_extra: 0,
            buffer: core::ptr::null_mut(),
        };
        p.set_size(0x1234_5678);
        p.set_extra(0xDEAD_BEEF);
        assert_eq!(p.size(), 0x1234_5678);
        assert_eq!(p.extra(), 0xDEAD_BEEF);
        // GCC + little-endian: size in low 32 bits, extra in high 32 bits.
        assert_eq!(p.size_extra, 0xDEAD_BEEF_1234_5678);
    }

    #[test]
    fn name_constant_matches_legacy_token() {
        assert_eq!(NAME.to_str().unwrap(), "String");
    }

    #[test]
    fn string_size_max_matches_c_constant() {
        assert_eq!(STRING_SIZE_MAX, 1_073_741_824);
    }

    #[test]
    fn string_extra_min_matches_c_constant() {
        assert_eq!(STRING_EXTRA_MIN, 64);
    }
}
