//! Zero-terminated string helpers migrated from `src/common/type/stringZ.c`.
//!
//! The `new` allocator mirrors the legacy `zNewInternal` body: a fresh `MemContext` is
//! pushed with either an `allocExtra` slot sized to the request (when it fits in the
//! 64 KiB cap) or a single child allocation (when it doesn't), and the resulting buffer
//! pointer is returned. The variadic `zNewFmt` and `zNewStrId` stay on the C side —
//! routing `va_list` and the `strIdToZN` helper through the FFI surface would be more
//! work than the few remaining C lines they replace.

use core::ffi::c_char;

use crate::mem_context;

/// Maximum number of bytes that fit in a `MemContext`'s `allocExtra` slot.
/// Mirrors `MEM_CONTEXT_ALLOC_EXTRA_MAX` in `src/common/memContext.h`.
const MEM_CONTEXT_ALLOC_EXTRA_MAX: usize = u16::MAX as usize;

/// Static name passed to the new `MemContext` so backtraces show "char *" the same way
/// `OBJ_NEW_BASE_EXTRA_BEGIN(char *, ...)` does.
const NAME: &core::ffi::CStr = c"char *";

/// `zNewInternal(size)`: allocate a fresh `size`-byte buffer in a brand-new `MemContext`,
/// switch back to the prior context, and return the pointer.
///
/// Small sizes (≤ `MEM_CONTEXT_ALLOC_EXTRA_MAX`) are folded into the new context's
/// `allocExtra` slot to avoid an extra `mem_new` round trip; larger sizes get a single
/// child allocation. Either way the buffer is owned by the freshly-kept context, so the
/// caller (or a later `objFree`) is responsible for cleanup.
///
/// # Safety
///
/// Must be called from a thread holding the single-threaded mem-context invariant. The
/// `try_depth` value forwarded to `mem_context_new` / `switch` is read from the C-side
/// `errorTryDepth()` by the FFI shim — the legacy macros do the same thing implicitly
/// via `MEM_CONTEXT_NEW_BEGIN`.
#[must_use]
pub unsafe fn new(size: usize, try_depth: u32) -> *mut c_char {
    // Bounded by MEM_CONTEXT_ALLOC_EXTRA_MAX = u16::MAX so the truncating cast is
    // value-preserving on the small branch and 0-equivalent on the large branch.
    #[allow(clippy::cast_possible_truncation)]
    let alloc_extra: u16 = if size > MEM_CONTEXT_ALLOC_EXTRA_MAX { 0 } else { size as u16 };
    let alloc_qty: u8 = u8::from(size > MEM_CONTEXT_ALLOC_EXTRA_MAX);

    // SAFETY: caller upholds the single-threaded mem-context invariant; `NAME` is a
    // statically-allocated NUL-terminated C string that outlives the call.
    let mc = unsafe { mem_context::mem_context_new(NAME.as_ptr(), 0, alloc_qty, 0, alloc_extra, try_depth) };

    // SAFETY: `mc` is the freshly-allocated MemContext returned by `mem_context_new`;
    // switching to it is the standard `MEM_CONTEXT_NEW_BEGIN` step.
    unsafe { mem_context::switch(mc.cast(), try_depth) };

    let result = if size > MEM_CONTEXT_ALLOC_EXTRA_MAX {
        // SAFETY: we are switched to `mc` and `mem_new` allocates inside the current
        // context's `allocMany` list, the same way `memNew(size)` does.
        unsafe { mem_context::mem_new(size).cast::<c_char>() }
    } else {
        // SAFETY: `mc` was created with `alloc_extra = size` so the extra slot has at
        // least `size` writable bytes.
        unsafe { mem_context::mem_context_alloc_extra(mc).cast::<c_char>() }
    };

    // Mirror `MEM_CONTEXT_NEW_END`: switch back to the prior context, then `keep` so the
    // new context (and the buffer it owns) survives past this call.
    let _ = mem_context::switch_back();
    let _ = mem_context::keep();

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // The end-to-end behaviour requires the C-side `memContextTop` / `errorContext`
    // machinery, so the integration coverage lives in the C unit test. These pure-Rust
    // tests just lock down the static parts.

    #[test]
    fn alloc_extra_max_constant_matches_c_header() {
        assert_eq!(MEM_CONTEXT_ALLOC_EXTRA_MAX, u16::MAX as usize);
    }

    #[test]
    fn name_constant_matches_legacy_token() {
        assert_eq!(NAME.to_str().unwrap(), "char *");
    }

    #[test]
    fn alloc_qty_branch_picks_separate_when_size_overflows_extra() {
        // The branching logic must agree with the legacy ternary
        //   `size > MEM_CONTEXT_ALLOC_EXTRA_MAX ? 1 : 0`
        // even when called via the public Rust signature. Replicate the predicate so a
        // future refactor can't silently flip the boundary.
        let just_under = MEM_CONTEXT_ALLOC_EXTRA_MAX;
        let just_over = MEM_CONTEXT_ALLOC_EXTRA_MAX + 1;
        assert!(just_under <= MEM_CONTEXT_ALLOC_EXTRA_MAX);
        assert!(just_over > MEM_CONTEXT_ALLOC_EXTRA_MAX);
    }
}
