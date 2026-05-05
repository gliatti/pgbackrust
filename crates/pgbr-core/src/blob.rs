//! Blob handler migrated from `src/common/type/blob.c`.
//!
//! Packs many small allocations onto larger fixed-size blocks. Mirrors the legacy C
//! body byte-for-byte: the `Blob` struct (current write block + position cursor) lives
//! in the new context's `allocExtra` slot; every block is a separate `mem_new`
//! allocation inside that context.

use core::ffi::{c_char, c_void};
use core::ptr;

use crate::mem_context;

// Compile-time assertion that the `Blob` layout fits in the 16-bit `allocExtra` field.
const _: () = assert!(core::mem::size_of::<usize>() * 2 <= u16::MAX as usize);

/// Size of each fixed block allocated for blob data. Mirrors `BLOB_BLOCK_SIZE` in
/// `src/common/type/blob.h` (64 KiB).
pub const BLOB_BLOCK_SIZE: usize = 64 * 1024;

/// Static name passed to the new `MemContext` so backtraces show "Blob" the same way
/// `OBJ_NEW_BEGIN(Blob, ...)` does.
const NAME: &core::ffi::CStr = c"Blob";

/// Mirror of the C `struct Blob` in `src/common/type/blob.c`.
///
/// Hidden behind an opaque `typedef struct Blob Blob;` in the public header, so the
/// layout is private to the module. `#[repr(C)]` keeps the field order in sync with
/// the legacy struct in case any future tooling pokes at the bytes.
#[repr(C)]
pub struct Blob {
    /// Current block for writing (pointer into a fixed `BLOB_BLOCK_SIZE` allocation).
    pub block: *mut c_char,
    /// Bytes already written into `block`.
    pub pos: usize,
}

/// `blbNew()`: allocate the `Blob` header in a fresh `MemContext`'s `allocExtra` slot
/// and the first 64 KiB block as a child allocation inside that context.
///
/// # Safety
///
/// Single-threaded mem-context invariant. `try_depth` must come from the C-side
/// `errorTryDepth()`.
#[must_use]
pub unsafe fn new(try_depth: u32) -> *mut Blob {
    // SAFETY: caller upholds the contract; `NAME` is statically allocated.
    let mc = unsafe {
        mem_context::mem_context_new(
            NAME.as_ptr(),
            0,       // child_qty
            u8::MAX, // alloc_qty = MEM_CONTEXT_QTY_MAX
            0,       // callback_qty
            // `sizeof(Blob) = 2 * usize = 16` on 64-bit, well below u16::MAX. The
            // const_assert at module level locks this in.
            #[allow(clippy::cast_possible_truncation)]
            {
                core::mem::size_of::<Blob>() as u16
            },
            try_depth,
        )
    };

    // SAFETY: `mc` is the freshly-allocated MemContext returned by `mem_context_new`.
    unsafe { mem_context::switch(mc.cast(), try_depth) };

    // The `allocExtra` slot is sized to `sizeof(Blob)` and lives at a stable offset past
    // the `MemContext` header.
    // SAFETY: `mem_context_alloc_extra` returns the start of the extra region we just
    // sized to `sizeof(Blob)`.
    let this: *mut Blob = unsafe { mem_context::mem_context_alloc_extra(mc).cast::<Blob>() };

    // SAFETY: `mem_new` allocates inside the current (= `mc`) context.
    let block = unsafe { mem_context::mem_new(BLOB_BLOCK_SIZE).cast::<c_char>() };

    // SAFETY: `this` points at writable storage of `sizeof(Blob)` bytes inside `mc`.
    unsafe { ptr::write(this, Blob { block, pos: 0 }) };

    // Mirror `MEM_CONTEXT_NEW_END`: switch back to the caller's prior context, then
    // `keep` so the new context (and its `Blob` + first block) survives.
    let _ = mem_context::switch_back();
    let _ = mem_context::keep();

    this
}

/// `blbAdd(this, data, size)`: copy `size` bytes from `data` into the blob.
///
/// Returns a pointer to the stored copy. Allocates a new 64 KiB block (or a one-off
/// oversize allocation when `size >= BLOB_BLOCK_SIZE`) when the current block can't
/// hold the payload.
///
/// # Safety
///
/// `this` must be a valid `Blob *` returned by [`new`]. `data` must point at `size`
/// readable bytes. Single-threaded mem-context invariant.
#[must_use]
pub unsafe fn add(this: *mut Blob, data: *const c_void, size: usize, try_depth: u32) -> *const c_void {
    // Resolve the owning context so we allocate inside it (mirrors
    // `MEM_CONTEXT_OBJ_BEGIN(this)` in C).
    // SAFETY: `this` is a live `Blob` pointer inside an `allocExtra` slot.
    let mc = unsafe { mem_context::mem_context_from_alloc_extra(this.cast::<c_void>()) };

    // SAFETY: `mc` is a live MemContext; `switch` is the standard obj-begin step.
    unsafe { mem_context::switch(mc.cast(), try_depth) };

    let result: *mut c_void = if size >= BLOB_BLOCK_SIZE {
        // Oversize payload — allocate a dedicated buffer just for it. The current
        // block-in-progress is preserved untouched for the next call.
        // SAFETY: `mem_new` allocates inside the obj's context.
        let buffer = unsafe { mem_context::mem_new(size) };
        // SAFETY: caller guarantees `data` is readable for `size` bytes; `buffer` was
        // just allocated with at least `size` writable bytes.
        unsafe { ptr::copy_nonoverlapping(data.cast::<u8>(), buffer.cast::<u8>(), size) };
        buffer
    } else {
        // SAFETY: `this` is the live `Blob` we resolved above.
        let blob = unsafe { &mut *this };
        if BLOB_BLOCK_SIZE - blob.pos >= size {
            // Fits in the current block.
            // SAFETY: `block + pos` is within the 64 KiB allocation we tracked, and
            // `pos + size <= BLOB_BLOCK_SIZE` by the predicate above.
            let dest = unsafe { blob.block.add(blob.pos).cast::<c_void>() };
            // SAFETY: caller guarantees `data` is readable for `size` bytes.
            unsafe { ptr::copy_nonoverlapping(data.cast::<u8>(), dest.cast::<u8>(), size) };
            blob.pos += size;
            dest
        } else {
            // Current block is too full — allocate a fresh one and start there.
            // SAFETY: `mem_new` allocates inside the obj's context.
            let new_block = unsafe { mem_context::mem_new(BLOB_BLOCK_SIZE).cast::<c_char>() };
            blob.block = new_block;
            // SAFETY: caller guarantees `data` is readable for `size` bytes; `new_block`
            // is freshly allocated with `BLOB_BLOCK_SIZE >= size` writable bytes.
            unsafe { ptr::copy_nonoverlapping(data.cast::<u8>(), new_block.cast::<u8>(), size) };
            blob.pos = size;
            new_block.cast::<c_void>()
        }
    };

    // Mirror `MEM_CONTEXT_OBJ_END`.
    let _ = mem_context::switch_back();

    result.cast_const()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // End-to-end behaviour requires the C-side mem-context machinery; the integration
    // is exercised by the C unit test. Pure-Rust tests here pin down the static parts.

    #[test]
    fn block_size_matches_c_header() {
        assert_eq!(BLOB_BLOCK_SIZE, 64 * 1024);
    }

    #[test]
    fn name_constant_matches_legacy_token() {
        assert_eq!(NAME.to_str().unwrap(), "Blob");
    }

    #[test]
    fn struct_layout_is_repr_c_with_pointer_first() {
        // Two-field struct, pointer first then `size_t`. The legacy C definition is
        // `struct Blob { char *block; size_t pos; };` — keep the same layout so any
        // legacy tooling that pokes at the bytes still finds the fields where it
        // expects them.
        assert_eq!(core::mem::size_of::<Blob>(), 2 * core::mem::size_of::<*mut c_char>());
        assert_eq!(core::mem::offset_of!(Blob, block), 0);
        assert_eq!(core::mem::offset_of!(Blob, pos), core::mem::size_of::<*mut c_char>());
    }
}
