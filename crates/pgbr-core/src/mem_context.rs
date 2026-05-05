//! Memory-context stack-state algorithms shared with the C `memContext.h` macros.
//!
//! Migration phase: 32A (sub-issue of #36). This module owns both the **algorithmic** layer of
//! the mem-context stack (`switch`, `switch_back`, `keep`, `discard`, `current`, `prior`,
//! `clean`, plus the `push_new` helper used by the still-in-C `memContextNew`) and the
//! **storage** for the 128-entry stack array, the cursor variables, and the DEBUG sequence
//! counter.
//!
//! The state lives in this crate (and therefore inside `libpgbr_ffi.a`) so the FFI library is
//! self-contained — every test binary that links `libpgbr_ffi.a` resolves all `pgbr_mem_context_*`
//! symbols without needing `src/common/memContext.c` in its compile list. The error and
//! `error-retry` test binaries, which never call mem-context functions but pull in `pgbr_ffi.a`
//! for `pgbr_stack_trace_*`, would otherwise fail at link with `undefined reference to
//! memContextStack`.
//!
//! Symbols are exported with their C names (`memContextStack`, `memContextCurrentStackIdx`,
//! `memContextMaxStackIdx`, `memContextSequence`) so `src/common/memContext.c` can `extern`
//! them and the `ASSERT_ALLOC_MANY_VALID` macro keeps stringifying as
//! `memContextStack[memContextCurrentStackIdx]`. The test suite, which `#include`s
//! `memContext.c` directly and reads `memContextStack[…]` plus `memContext->name` style fields,
//! keeps compiling — only the storage **owner** moved.
//!
//! Slot zero of `memContextStack` must hold the address of the C-side static `contextTop`. Rust
//! cannot statically initialise that pointer because `&contextTop` is not a Rust constant; the
//! `pgbr_mem_context_init_top` hook (called from a `__attribute__((constructor))` in
//! `memContext.c`) writes the pointer before `main` runs.

use core::ffi::c_char;
use core::ffi::c_void;

/// Maximum stack depth tracked. Mirrors `MEM_CONTEXT_STACK_MAX` in `src/common/memContext.c`.
pub const MEM_CONTEXT_STACK_MAX: usize = 128;

/// Mirror of the C `MemQty` enum from `src/common/memContext.c`. The C bitfield uses 2 bits to
/// hold one of these values.
pub const MEM_QTY_NONE: u8 = 0;
pub const MEM_QTY_ONE: u8 = 1;
pub const MEM_QTY_MANY: u8 = 2;

/// Number of `MemContext` slots reserved per child / alloc list when the list is first
/// initialised. Mirrors `MEM_CONTEXT_INITIAL_SIZE` in `src/common/memContext.h`.
pub const MEM_CONTEXT_INITIAL_SIZE: u32 = 4;

/// Number of `MemContextAlloc` slots reserved per allocation list when first initialised.
/// Mirrors `MEM_CONTEXT_ALLOC_INITIAL_SIZE` in `src/common/memContext.h`.
#[allow(dead_code)]
pub const MEM_CONTEXT_ALLOC_INITIAL_SIZE: u32 = 4;

/// Discriminant for the `type` field of `MemContextStack`. Mirrors
/// `memContextStackTypeSwitch` (= 0) in the C enum: a context that can be switched to for
/// allocating memory.
pub const STACK_TYPE_SWITCH: i32 = 0;

/// Discriminant for the `type` field of `MemContextStack`. Mirrors `memContextStackTypeNew`
/// (= 1) in the C enum: a context tracked only so error-cleanup can free it; cannot be switched
/// to.
pub const STACK_TYPE_NEW: i32 = 1;

// ─── Tree-structure mirrors (32B) ──────────────────────────────────────────────────────────────
//
// The C side keeps the bitfield-packed `struct MemContext` in `src/common/memContext.c` because
// the test (`test/src/test.c` `#include`s the file directly) reads `memContext->name`,
// `memContext->active`, etc. The Rust mirror below MUST agree byte-for-byte with the C struct so
// the still-in-C `memContextNew` and the Rust `mem_context_*` algorithms can share malloc'd
// allocations.
//
// 32B targets the DEBUG layout (the only flavour test.pl exercises). The C compiler asserts
// `sizeof(struct MemContext) == 32` on 64-bit DEBUG and `24` on 32-bit DEBUG — see the
// `_Static_assert` matrix at the top of `src/common/memContext.c`. A non-DEBUG production build
// has a different (smaller) `MemContext` layout; the Rust mirror does not currently track it,
// and `mem_context_new` / `mem_context_free` would mismatch in that build. A follow-up sub-issue
// will add a build.rs reading the meson `c-debug` env var to switch layouts; for now the
// pgbackrest binary already gates the DEBUG/non-DEBUG builds via meson_options.txt and the
// test.pl harness only runs DEBUG.

/// Bitfield-packed flags region of `MemContext`.
///
/// GCC's System V ABI packs consecutive bitfields LSB-first into a single 32-bit storage unit
/// when the total bit count fits. The DEBUG layout uses 26 bits (with `active`); the non-DEBUG
/// layout uses 25 (no `active`). Bit positions for the **non**-`active` fields shift by one
/// between the two layouts, so the helper constants are `cfg`-gated.
///
/// LSB-first bit layout (matches GCC SysV ABI):
///
/// | bits (DEBUG) | bits (release) | field                  |
/// |--------------|----------------|------------------------|
/// | 0            | n/a            | `active` (DEBUG only)  |
/// | 1-2          | 0-1            | `child_qty`            |
/// | 3            | 2              | `child_initialized`    |
/// | 4-5          | 3-4            | `alloc_qty`            |
/// | 6            | 5              | `alloc_initialized`    |
/// | 7-8          | 6-7            | `callback_qty`         |
/// | 9            | 8              | `callback_initialized` |
/// | 10-25        | 9-24           | `alloc_extra`          |
#[cfg(c_debug)]
const FLAG_ACTIVE_SHIFT: u32 = 0;
#[cfg(c_debug)]
const FLAG_ACTIVE_MASK: u32 = 0x1;
#[cfg(c_debug)]
const FLAG_CHILD_QTY_SHIFT: u32 = 1;
#[cfg(not(c_debug))]
const FLAG_CHILD_QTY_SHIFT: u32 = 0;
const FLAG_CHILD_QTY_MASK: u32 = 0x3;
#[cfg(c_debug)]
const FLAG_CHILD_INIT_SHIFT: u32 = 3;
#[cfg(not(c_debug))]
const FLAG_CHILD_INIT_SHIFT: u32 = 2;
const FLAG_CHILD_INIT_MASK: u32 = 0x1;
#[cfg(c_debug)]
const FLAG_ALLOC_QTY_SHIFT: u32 = 4;
#[cfg(not(c_debug))]
const FLAG_ALLOC_QTY_SHIFT: u32 = 3;
const FLAG_ALLOC_QTY_MASK: u32 = 0x3;
#[cfg(c_debug)]
const FLAG_ALLOC_INIT_SHIFT: u32 = 6;
#[cfg(not(c_debug))]
const FLAG_ALLOC_INIT_SHIFT: u32 = 5;
const FLAG_ALLOC_INIT_MASK: u32 = 0x1;
#[cfg(c_debug)]
const FLAG_CALLBACK_QTY_SHIFT: u32 = 7;
#[cfg(not(c_debug))]
const FLAG_CALLBACK_QTY_SHIFT: u32 = 6;
const FLAG_CALLBACK_QTY_MASK: u32 = 0x3;
#[cfg(c_debug)]
const FLAG_CALLBACK_INIT_SHIFT: u32 = 9;
#[cfg(not(c_debug))]
const FLAG_CALLBACK_INIT_SHIFT: u32 = 8;
const FLAG_CALLBACK_INIT_MASK: u32 = 0x1;
#[cfg(c_debug)]
const FLAG_ALLOC_EXTRA_SHIFT: u32 = 10;
#[cfg(not(c_debug))]
const FLAG_ALLOC_EXTRA_SHIFT: u32 = 9;
const FLAG_ALLOC_EXTRA_MASK: u32 = 0xFFFF;

/// Byte-identical Rust mirror of the C `struct MemContext`.
///
/// `c-debug` feature gates the `name` / `sequence_new` fields and the `active` bit slot to
/// match the C `#ifdef DEBUG` blocks. Sizes:
///   * 64-bit DEBUG: 32 bytes (`8 name + 8 seq + 4 flags + 4 parent_idx + 8 parent`).
///   * 32-bit DEBUG: 24 bytes (`u64` is 4-aligned on 32-bit Linux: `4+8+4+4+4`).
///   * 64-bit release: 16 bytes (`4 flags + 4 parent_idx + 8 parent`).
///   * 32-bit release: 12 bytes.
#[repr(C)]
pub struct MemContext {
    #[cfg(c_debug)]
    pub name: *const c_char,
    #[cfg(c_debug)]
    pub sequence_new: u64,
    pub flags: u32,
    pub context_parent_idx: u32,
    pub context_parent: *mut Self,
}

/// Compile-time assertion that the Rust mirror matches the test-pinned C `sizeof`.
const _: () = {
    #[cfg(all(target_pointer_width = "64", c_debug))]
    assert!(
        core::mem::size_of::<MemContext>() == 32,
        "MemContext must be 32 bytes on 64-bit DEBUG"
    );
    #[cfg(all(target_pointer_width = "32", c_debug))]
    assert!(
        core::mem::size_of::<MemContext>() == 24,
        "MemContext must be 24 bytes on 32-bit DEBUG"
    );
    #[cfg(all(target_pointer_width = "64", not(c_debug)))]
    assert!(
        core::mem::size_of::<MemContext>() == 16,
        "MemContext must be 16 bytes on 64-bit release"
    );
    #[cfg(all(target_pointer_width = "32", not(c_debug)))]
    assert!(
        core::mem::size_of::<MemContext>() == 12,
        "MemContext must be 12 bytes on 32-bit release"
    );
};

// Some accessors take `&self` / `&mut self` even when one cfg branch ignores both inputs (the
// non-DEBUG `active` accessor returns a constant). Clippy complains; suppress at the impl level
// so the public API stays uniform across cfg variants.
#[allow(
    clippy::unused_self,
    clippy::needless_pass_by_ref_mut,
    clippy::missing_const_for_fn,
    unused_variables
)]
impl MemContext {
    /// `true` while the context is in active use; cleared by `memContextCallbackRecurse` before
    /// the callback fires. DEBUG-only on the C side; release builds always return `true` from
    /// this accessor (the bit does not exist in the layout).
    #[must_use]
    pub const fn active(&self) -> bool {
        #[cfg(c_debug)]
        {
            (self.flags >> FLAG_ACTIVE_SHIFT) & FLAG_ACTIVE_MASK != 0
        }
        #[cfg(not(c_debug))]
        {
            true
        }
    }

    /// Set the active bit. No-op on non-DEBUG builds where the bit does not exist.
    pub fn set_active(&mut self, value: bool) {
        #[cfg(c_debug)]
        Self::set_bits(&mut self.flags, FLAG_ACTIVE_SHIFT, FLAG_ACTIVE_MASK, u32::from(value));
    }

    /// Encoded `MemQty` (0 = none, 1 = one, 2 = many).
    #[must_use]
    pub const fn child_qty(&self) -> u8 {
        ((self.flags >> FLAG_CHILD_QTY_SHIFT) & FLAG_CHILD_QTY_MASK) as u8
    }

    pub fn set_child_qty(&mut self, value: u8) {
        Self::set_bits(&mut self.flags, FLAG_CHILD_QTY_SHIFT, FLAG_CHILD_QTY_MASK, u32::from(value));
    }

    #[must_use]
    pub const fn child_initialized(&self) -> bool {
        (self.flags >> FLAG_CHILD_INIT_SHIFT) & FLAG_CHILD_INIT_MASK != 0
    }

    pub fn set_child_initialized(&mut self, value: bool) {
        Self::set_bits(&mut self.flags, FLAG_CHILD_INIT_SHIFT, FLAG_CHILD_INIT_MASK, u32::from(value));
    }

    #[must_use]
    pub const fn alloc_qty(&self) -> u8 {
        ((self.flags >> FLAG_ALLOC_QTY_SHIFT) & FLAG_ALLOC_QTY_MASK) as u8
    }

    pub fn set_alloc_qty(&mut self, value: u8) {
        Self::set_bits(&mut self.flags, FLAG_ALLOC_QTY_SHIFT, FLAG_ALLOC_QTY_MASK, u32::from(value));
    }

    #[must_use]
    pub const fn alloc_initialized(&self) -> bool {
        (self.flags >> FLAG_ALLOC_INIT_SHIFT) & FLAG_ALLOC_INIT_MASK != 0
    }

    pub fn set_alloc_initialized(&mut self, value: bool) {
        Self::set_bits(&mut self.flags, FLAG_ALLOC_INIT_SHIFT, FLAG_ALLOC_INIT_MASK, u32::from(value));
    }

    #[must_use]
    pub const fn callback_qty(&self) -> u8 {
        ((self.flags >> FLAG_CALLBACK_QTY_SHIFT) & FLAG_CALLBACK_QTY_MASK) as u8
    }

    pub fn set_callback_qty(&mut self, value: u8) {
        Self::set_bits(
            &mut self.flags,
            FLAG_CALLBACK_QTY_SHIFT,
            FLAG_CALLBACK_QTY_MASK,
            u32::from(value),
        );
    }

    #[must_use]
    pub const fn callback_initialized(&self) -> bool {
        (self.flags >> FLAG_CALLBACK_INIT_SHIFT) & FLAG_CALLBACK_INIT_MASK != 0
    }

    pub fn set_callback_initialized(&mut self, value: bool) {
        Self::set_bits(
            &mut self.flags,
            FLAG_CALLBACK_INIT_SHIFT,
            FLAG_CALLBACK_INIT_MASK,
            u32::from(value),
        );
    }

    /// Extra-allocation byte count appended after the `MemContext` header.
    #[must_use]
    pub const fn alloc_extra(&self) -> u32 {
        (self.flags >> FLAG_ALLOC_EXTRA_SHIFT) & FLAG_ALLOC_EXTRA_MASK
    }

    pub fn set_alloc_extra(&mut self, value: u32) {
        debug_assert!(value <= FLAG_ALLOC_EXTRA_MASK, "alloc_extra exceeds 16 bits");
        Self::set_bits(&mut self.flags, FLAG_ALLOC_EXTRA_SHIFT, FLAG_ALLOC_EXTRA_MASK, value);
    }

    const fn set_bits(flags: &mut u32, shift: u32, mask: u32, value: u32) {
        *flags = (*flags & !(mask << shift)) | ((value & mask) << shift);
    }
}

/// Mirror of `struct MemContextChildOne` from `src/common/memContext.c`.
///
/// One child context held inline; size = 8 bytes on 64-bit / 4 bytes on 32-bit.
#[repr(C)]
pub struct MemContextChildOne {
    pub context: *mut MemContext,
}

/// Mirror of `struct MemContextChildMany`. Test asserts size = 16 / 12.
#[repr(C)]
pub struct MemContextChildMany {
    pub list: *mut *mut MemContext,
    pub list_size: u32,
    pub free_idx: u32,
}

const _: () = {
    #[cfg(target_pointer_width = "64")]
    assert!(core::mem::size_of::<MemContextChildMany>() == 16);
    #[cfg(target_pointer_width = "32")]
    assert!(core::mem::size_of::<MemContextChildMany>() == 12);
};

/// Mirror of `struct MemContextAllocOne`.
#[repr(C)]
pub struct MemContextAllocOne {
    pub alloc: *mut MemContextAlloc,
}

/// Mirror of `struct MemContextAllocMany`. Test asserts size = 16 / 12.
#[repr(C)]
pub struct MemContextAllocMany {
    pub list: *mut *mut MemContextAlloc,
    pub list_size: u32,
    pub free_idx: u32,
}

const _: () = {
    #[cfg(target_pointer_width = "64")]
    assert!(core::mem::size_of::<MemContextAllocMany>() == 16);
    #[cfg(target_pointer_width = "32")]
    assert!(core::mem::size_of::<MemContextAllocMany>() == 12);
};

/// Mirror of `struct MemContextCallbackOne`. Test asserts size = 16 / 8.
#[repr(C)]
pub struct MemContextCallbackOne {
    pub function: Option<unsafe extern "C" fn(*mut c_void)>,
    pub argument: *mut c_void,
}

const _: () = {
    #[cfg(target_pointer_width = "64")]
    assert!(core::mem::size_of::<MemContextCallbackOne>() == 16);
    #[cfg(target_pointer_width = "32")]
    assert!(core::mem::size_of::<MemContextCallbackOne>() == 8);
};

/// Allocation header laid out before every buffer returned by `mem_new` / `mem_resize`. Mirror
/// of `struct MemContextAlloc`. Test asserts size = 8 on both 32-bit and 64-bit.
#[repr(C)]
pub struct MemContextAlloc {
    /// Index in the allocation list (32 bits in C, occupying the low 32 bits of the union word).
    pub alloc_idx: u32,
    /// Total allocation size in bytes (header + payload, 4 GB max).
    pub size: u32,
}

const _: () = assert!(core::mem::size_of::<MemContextAlloc>() == 8);

/// Mirror of `MemContextNewParam` from `src/common/memContext.h` (the variadic-parameter struct
/// used by the `memContextNewP` macro). The leading `bool dummy` field expands from
/// `VAR_PARAM_HEADER`.
#[repr(C)]
pub struct MemContextNewParam {
    pub dummy: bool,
    pub child_qty: u8,
    pub alloc_qty: u8,
    pub callback_qty: u8,
    pub alloc_extra: u16,
}

/// 3D table mirroring `memContextSizePossible[memQtyMany + 1][memQtyMany + 1][memQtyOne + 1]`
/// from `src/common/memContext.c:108–139`. Indexed `[child_qty][alloc_qty][callback_qty]`,
/// returns the total bytes needed for the trailing optional regions (child + alloc + callback)
/// after the `MemContext` header and the alloc-extra padding.
const fn child_one() -> usize {
    core::mem::size_of::<MemContextChildOne>()
}
const fn child_many() -> usize {
    core::mem::size_of::<MemContextChildMany>()
}
const fn alloc_one() -> usize {
    core::mem::size_of::<MemContextAllocOne>()
}
const fn alloc_many() -> usize {
    core::mem::size_of::<MemContextAllocMany>()
}
const fn callback_one() -> usize {
    core::mem::size_of::<MemContextCallbackOne>()
}

#[allow(dead_code)]
const SIZE_POSSIBLE: [[[usize; 2]; 3]; 3] = [
    // child none
    [
        [0, callback_one()],                           // alloc none
        [alloc_one(), alloc_one() + callback_one()],   // alloc one
        [alloc_many(), alloc_many() + callback_one()], // alloc many
    ],
    // child one
    [
        [child_one(), child_one() + callback_one()],
        [child_one() + alloc_one(), child_one() + alloc_one() + callback_one()],
        [child_one() + alloc_many(), child_one() + alloc_many() + callback_one()],
    ],
    // child many
    [
        [child_many(), child_many() + callback_one()],
        [child_many() + alloc_one(), child_many() + alloc_one() + callback_one()],
        [child_many() + alloc_many(), child_many() + alloc_many() + callback_one()],
    ],
];

// libc allocators. `pgbr_mem_context_*` allocations come from the same heap as the C
// `memAllocInternal` so the C and Rust paths can share buffers byte-for-byte. On null return we
// panic; the FFI guard maps the panic to `ErrorType::Unknown` for the C caller. The legacy C
// `memAllocInternal` test (`TEST_ERROR(memAllocInternal((size_t)5629499534213120), MemoryError,
// …)` at memContextTest.c:43) calls the static helper directly and is unaffected — that path
// stays in C and is exercised independently. The Rust side panics defensively because in
// practice `memContextNewP` / `memNew` allocations succeed.
unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

/// Allocate `size` bytes via libc malloc. Panics on null return; the FFI panic guard surfaces
/// the failure to the C caller as `ErrorType::Unknown`.
unsafe fn mem_alloc(size: usize) -> *mut c_void {
    // SAFETY: libc malloc is always callable with any size; null return is the failure
    // indicator we explicitly check for.
    let ptr = unsafe { malloc(size) };
    assert!(!ptr.is_null(), "malloc returned null for {size} bytes");
    ptr
}

/// Reallocate `ptr` to `new_size` bytes via libc realloc. Panics on null return.
#[allow(dead_code)]
unsafe fn mem_realloc(ptr: *mut c_void, new_size: usize) -> *mut c_void {
    // SAFETY: caller asserts `ptr` came from a previous `mem_alloc` / libc malloc and is still
    // live (or null, which makes realloc behave like malloc).
    let new_ptr = unsafe { realloc(ptr, new_size) };
    assert!(!new_ptr.is_null(), "realloc returned null for {new_size} bytes");
    new_ptr
}

/// libc free. Mirrors the legacy `memFreeInternal` minus the `ASSERT(buffer != NULL)` (the
/// asserts live in the C wrapper).
unsafe fn mem_free(ptr: *mut c_void) {
    // SAFETY: caller asserts `ptr` came from a previous `mem_alloc` / libc malloc.
    unsafe { free(ptr) };
}

/// Allocate an array of `count` `*mut T` pointers, all initialised to null. Mirrors the legacy
/// `memAllocPtrArrayInternal`.
#[allow(clippy::expect_used)]
unsafe fn mem_alloc_ptr_array<T>(count: usize) -> *mut *mut T {
    // SAFETY: see `mem_alloc`. On success the returned buffer is `count * sizeof(*mut T)`
    // bytes; we zero-initialise via `write_bytes`.
    unsafe {
        let bytes = count
            .checked_mul(core::mem::size_of::<*mut T>())
            .expect("ptr-array size overflow");
        let ptr = mem_alloc(bytes).cast::<*mut T>();
        core::ptr::write_bytes(ptr, 0, count);
        ptr
    }
}

/// Reallocate the pointer array `old` (of `old_count` slots) to `new_count` slots, zero-filling
/// the new tail. Mirrors `memReAllocPtrArrayInternal`.
#[allow(clippy::expect_used)]
unsafe fn mem_realloc_ptr_array<T>(old: *mut *mut T, old_count: usize, new_count: usize) -> *mut *mut T {
    // SAFETY: caller asserts `old` came from `mem_alloc_ptr_array` with `old_count` slots.
    unsafe {
        let bytes = new_count
            .checked_mul(core::mem::size_of::<*mut T>())
            .expect("ptr-array size overflow");
        let ptr = mem_realloc(old.cast::<c_void>(), bytes).cast::<*mut T>();
        // Zero the new tail.
        core::ptr::write_bytes(ptr.add(old_count), 0, new_count - old_count);
        ptr
    }
}

// ─── Tree algorithms (32B-3) ───────────────────────────────────────────────────────────────────
//
// `mem_context_new` allocates and initialises a new context, registering it in the parent's
// child list and pushing a `New` entry on the mem-context stack. `mem_context_callback_recurse`
// runs the destructor callbacks tree-deep before any memory is freed (the C wrapper keeps these
// halves under `TRY_BEGIN`/`FINALLY`/`TRY_END` so a callback longjmp does not leak the freed
// memory). `mem_context_free_release_recurse` frees the allocation tree. `mem_context_move`
// reparents an existing context, and `mem_context_size` (DEBUG-only on the C side) sums the
// allocation totals for audit reporting.
//
// All readers of bitfield-packed fields go through the `MemContext::*` accessors, which honour
// the `cfg(c_debug)` shifts. The C `__attribute__((constructor))` in `memContext.c` aborts the
// process at load time if `pgbr_mem_context_struct_size()` disagrees with `sizeof(struct
// MemContext)`, so reaching this code already guarantees the layouts match.
//
// Clippy allowances:
//   * `cast_ptr_alignment` — these algorithms reach into a single malloc'd block via a `*mut u8`
//     cursor that's then cast to the appropriate optional-region struct. Alignment is correct
//     because `mem_context_new` pads `alloc_extra` to `align_of::<*mut c_void>()` before
//     deciding the layout.
//   * `must_use_candidate` / `too_long_first_doc_paragraph` — FFI-shape API; the documentation
//     intentionally explains what the C wrapper expects, and the values are inspected by C
//     callers rather than chained through Rust.

/// Pointer to the optional child region following the `MemContext` header.
unsafe fn child_offset_ptr(this: *mut MemContext) -> *mut u8 {
    // SAFETY: caller upholds `this` validity; the returned pointer points inside the same
    // malloc'd block as `this`.
    unsafe {
        let after_struct = this.add(1).cast::<u8>();
        after_struct.add((*this).alloc_extra() as usize)
    }
}

/// Pointer to the optional alloc region; sits after the child region.
unsafe fn alloc_offset_ptr(this: *mut MemContext) -> *mut u8 {
    // SAFETY: caller upholds `this` validity.
    unsafe {
        let after_struct = this.add(1).cast::<u8>();
        let child_size = SIZE_POSSIBLE[(*this).child_qty() as usize][0][0];
        after_struct.add(child_size + (*this).alloc_extra() as usize)
    }
}

/// Pointer to the optional callback region; sits after the alloc region.
unsafe fn callback_offset_ptr(this: *mut MemContext) -> *mut u8 {
    // SAFETY: caller upholds `this` validity.
    unsafe {
        let after_struct = this.add(1).cast::<u8>();
        let pre = SIZE_POSSIBLE[(*this).child_qty() as usize][(*this).alloc_qty() as usize][0];
        after_struct.add(pre + (*this).alloc_extra() as usize)
    }
}

/// Find an unused slot in the parent's child list, growing it if needed.
/// Mirrors the legacy `memContextNewIndex`.
///
/// # Safety
///
/// `this` must be a valid `MemContext *` whose `child_qty == MEM_QTY_MANY`. `child` must point
/// at the parent's child-many region (returned by [`child_offset_ptr`] cast to
/// `*mut MemContextChildMany`).
unsafe fn mem_context_new_index(this: *mut MemContext, child: *mut MemContextChildMany) -> u32 {
    // SAFETY: caller upholds the validity invariants above.
    unsafe {
        if (*this).child_initialized() {
            let cm = &mut *child;
            while cm.free_idx < cm.list_size {
                if (*cm.list.add(cm.free_idx as usize)).is_null() {
                    break;
                }
                cm.free_idx += 1;
            }
            if cm.free_idx == cm.list_size {
                let new_size = cm.list_size * 2;
                cm.list = mem_realloc_ptr_array(cm.list, cm.list_size as usize, new_size as usize);
                cm.list_size = new_size;
            }
        } else {
            core::ptr::write(
                child,
                MemContextChildMany {
                    list: mem_alloc_ptr_array(MEM_CONTEXT_INITIAL_SIZE as usize),
                    list_size: MEM_CONTEXT_INITIAL_SIZE,
                    free_idx: 0,
                },
            );
            (*this).set_child_initialized(true);
        }
        (*child).free_idx
    }
}

/// Allocate and initialise a new `MemContext` whose parent is the current context.
///
/// Mirrors the legacy `memContextNew`. The C wrapper still owns the parameter validation
/// (ASSERTs) and the `errorTryDepth()` lookup. On return the context is registered in the
/// parent's child list and a `New` entry is pushed on the mem-context stack so an error unwind
/// will free the partially-built context.
///
/// # Safety
///
/// `name` must be either a valid NUL-terminated C string with the lifetime of the new context
/// (when `cfg(c_debug)` is on) or any value when `cfg(c_debug)` is off (the field doesn't
/// exist). `try_depth` is the current `errorTryDepth()`. The current context (slot
/// `memContextCurrentStackIdx`) must have `child_qty != MEM_QTY_NONE`.
#[allow(
    clippy::cast_ptr_alignment,
    clippy::expect_used,
    clippy::too_long_first_doc_paragraph,
    clippy::must_use_candidate
)]
pub unsafe fn mem_context_new(
    name: *const c_char,
    child_qty_param: u8,
    alloc_qty_param: u8,
    callback_qty_param: u8,
    alloc_extra_param: u16,
    try_depth: u32,
) -> *mut MemContext {
    let _ = name;

    // Pad allocExtra so trailing optional regions stay aligned.
    let mut alloc_extra = alloc_extra_param as usize;
    let align = core::mem::align_of::<*mut c_void>();
    if !alloc_extra.is_multiple_of(align) {
        alloc_extra += align - (alloc_extra & (align - 1));
    }

    let child_qty = if child_qty_param > 1 { MEM_QTY_MANY } else { child_qty_param };
    let alloc_qty = if alloc_qty_param > 1 { MEM_QTY_MANY } else { alloc_qty_param };
    let callback_qty = callback_qty_param;

    // SAFETY: see module-level note. We only touch the new allocation and the parent's child
    // list (read via the same accessors that `cfg(c_debug)` keeps in sync).
    unsafe {
        let context_current = current().cast::<MemContext>();

        let total_size = core::mem::size_of::<MemContext>()
            + alloc_extra
            + SIZE_POSSIBLE[child_qty as usize][alloc_qty as usize][callback_qty as usize];

        let this = mem_alloc(total_size).cast::<MemContext>();

        core::ptr::write(
            this,
            MemContext {
                #[cfg(c_debug)]
                name,
                #[cfg(c_debug)]
                sequence_new: next_sequence(),
                flags: 0,
                context_parent_idx: 0,
                context_parent: context_current,
            },
        );

        let m = &mut *this;
        m.set_active(true);
        m.set_child_qty(child_qty);
        m.set_alloc_qty(alloc_qty);
        m.set_callback_qty(callback_qty);
        m.set_alloc_extra(u32::try_from(alloc_extra).expect("alloc_extra fits in 16 bits"));

        // Register `this` in the current context's child list.
        if (*context_current).child_qty() == MEM_QTY_ONE {
            let one = child_offset_ptr(context_current).cast::<MemContextChildOne>();
            (*one).context = this;
            (*context_current).set_child_initialized(true);
        } else {
            // MEM_QTY_MANY (none was rejected on the C side).
            let many = child_offset_ptr(context_current).cast::<MemContextChildMany>();
            let idx = mem_context_new_index(context_current, many);
            (*this).context_parent_idx = idx;
            *(*many).list.add(idx as usize) = this;
            (*many).free_idx += 1;
        }

        // Push the new context onto the stack so an error unwind frees it.
        push_new(this.cast::<c_void>(), try_depth);

        this
    }
}

/// Set the destructor callback on `this`. Mirrors `memContextCallbackSet`.
///
/// The C wrapper holds the `ASSERT(active)` / `ASSERT(callbackQty != none)` checks plus the
/// DEBUG-only "callback is already set" diagnostic.
///
/// # Safety
///
/// `this` must be a valid `MemContext *` whose `callback_qty != MEM_QTY_NONE`. `function` must
/// remain a valid `extern "C" fn(*mut c_void)` for the lifetime of the context.
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn mem_context_callback_set(this: *mut MemContext, function: unsafe extern "C" fn(*mut c_void), argument: *mut c_void) {
    // SAFETY: caller upholds `this` validity and `callback_qty != MEM_QTY_NONE`.
    unsafe {
        let cb = callback_offset_ptr(this).cast::<MemContextCallbackOne>();
        core::ptr::write(
            cb,
            MemContextCallbackOne {
                function: Some(function),
                argument,
            },
        );
        (*this).set_callback_initialized(true);
    }
}

/// Clear the destructor callback on `this`. Mirrors `memContextCallbackClear`.
///
/// # Safety
///
/// `this` must be a valid `MemContext *` whose `callback_qty != MEM_QTY_NONE`.
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn mem_context_callback_clear(this: *mut MemContext) {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let cb = callback_offset_ptr(this).cast::<MemContextCallbackOne>();
        core::ptr::write(
            cb,
            MemContextCallbackOne {
                function: None,
                argument: core::ptr::null_mut(),
            },
        );
        (*this).set_callback_initialized(false);
    }
}

/// Run the destructor callbacks for `this` and every context below it.
///
/// Mirrors `memContextCallbackRecurse`. A callback may longjmp via the C error machinery; the C
/// wrapper of `memContextFree` puts this call inside `TRY_BEGIN`/`FINALLY` so the freed memory
/// still gets reclaimed in `mem_context_free_release_recurse`.
///
/// # Safety
///
/// `this` must be a valid `MemContext *`.
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn mem_context_callback_recurse(this: *mut MemContext) {
    // SAFETY: caller upholds `this` validity. Recursion is bounded by the tree depth which the
    // legacy code does not bound either; the test suite does not push deeper than ~10 levels.
    unsafe {
        // DEBUG: certain actions against `this` are no longer allowed.
        (*this).set_active(false);

        if (*this).callback_initialized() {
            let cb = &*callback_offset_ptr(this).cast::<MemContextCallbackOne>();
            if let Some(f) = cb.function {
                f(cb.argument);
            }
            (*this).set_callback_initialized(false);
        }

        if (*this).child_initialized() {
            if (*this).child_qty() == MEM_QTY_ONE {
                let child = (*child_offset_ptr(this).cast::<MemContextChildOne>()).context;
                if !child.is_null() {
                    mem_context_callback_recurse(child);
                }
            } else {
                let cm = &*child_offset_ptr(this).cast::<MemContextChildMany>();
                for idx in 0..cm.list_size {
                    let child = *cm.list.add(idx as usize);
                    if !child.is_null() {
                        mem_context_callback_recurse(child);
                    }
                }
            }
        }
    }
}

/// Free the allocation tree rooted at `this`. Mirrors `memContextFreeRecurse`.
///
/// Returns null on success or the offending context pointer when the DEBUG-only "cannot free
/// current context" invariant is violated; the C wrapper translates a non-null return into a
/// `THROW_FMT(AssertError, "cannot free current context '%s'", err->name)`.
///
/// # Safety
///
/// `this` must be a valid `MemContext *` whose tree has not been freed yet.
#[allow(clippy::cast_ptr_alignment, clippy::needless_pass_by_ref_mut)]
pub unsafe fn mem_context_free_release_recurse(this: *mut MemContext) -> *mut MemContext {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let top = top_context();

        // DEBUG: cannot free the current context (top is special — it can be reset).
        #[cfg(c_debug)]
        if this.cast::<c_void>() == current() && this.cast::<c_void>() != top {
            return this;
        }

        // Free children.
        if (*this).child_initialized() {
            if (*this).child_qty() == MEM_QTY_ONE {
                let child = (*child_offset_ptr(this).cast::<MemContextChildOne>()).context;
                if !child.is_null() {
                    let err = mem_context_free_release_recurse(child);
                    if !err.is_null() {
                        return err;
                    }
                }
            } else {
                let cm_ptr = child_offset_ptr(this).cast::<MemContextChildMany>();
                let cm = &*cm_ptr;
                for idx in 0..cm.list_size {
                    let child = *cm.list.add(idx as usize);
                    if !child.is_null() {
                        let err = mem_context_free_release_recurse(child);
                        if !err.is_null() {
                            return err;
                        }
                    }
                }
                mem_free((*cm_ptr).list.cast::<c_void>());
            }
        }

        // Free allocations.
        if (*this).alloc_initialized() {
            if (*this).alloc_qty() == MEM_QTY_ONE {
                let ao = alloc_offset_ptr(this).cast::<MemContextAllocOne>();
                let alloc = (*ao).alloc;
                if !alloc.is_null() {
                    mem_free(alloc.cast::<c_void>());
                }
            } else {
                let am_ptr = alloc_offset_ptr(this).cast::<MemContextAllocMany>();
                let am = &*am_ptr;
                for idx in 0..am.list_size {
                    let alloc = *am.list.add(idx as usize);
                    if !alloc.is_null() {
                        mem_free(alloc.cast::<c_void>());
                    }
                }
                mem_free((*am_ptr).list.cast::<c_void>());
            }
        }

        if this.cast::<c_void>() == top {
            // Reset top: the legacy code re-initialises rather than freeing.
            (*this).set_child_initialized(false);
            (*this).set_alloc_initialized(false);
            (*this).set_active(true);
        } else {
            // Detach from the parent's child list and free `this`.
            let parent = (*this).context_parent;
            if (*parent).child_qty() == MEM_QTY_ONE {
                (*child_offset_ptr(parent).cast::<MemContextChildOne>()).context = core::ptr::null_mut();
            } else {
                let cm_ptr = child_offset_ptr(parent).cast::<MemContextChildMany>();
                let cm = &mut *cm_ptr;
                let idx = (*this).context_parent_idx;
                if idx < cm.free_idx {
                    cm.free_idx = idx;
                }
                *cm.list.add(idx as usize) = core::ptr::null_mut();
            }
            mem_free(this.cast::<c_void>());
        }

        core::ptr::null_mut()
    }
}

/// Reparent `this` to `parent_new`. Mirrors `memContextMove`.
///
/// No-op when `this` is null or already a child of `parent_new`.
///
/// # Safety
///
/// `this` (when non-null) must be a valid live `MemContext *` and `parent_new` must be a valid
/// live `MemContext *`. The C wrapper handles the `parent_new != NULL` ASSERT.
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn mem_context_move(this: *mut MemContext, parent_new: *mut MemContext) {
    if this.is_null() {
        return;
    }
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let old_parent = (*this).context_parent;
        if old_parent == parent_new {
            return;
        }

        // Null out the slot in the old parent.
        if (*old_parent).child_qty() == MEM_QTY_ONE {
            (*child_offset_ptr(old_parent).cast::<MemContextChildOne>()).context = core::ptr::null_mut();
        } else {
            let cm = &mut *child_offset_ptr(old_parent).cast::<MemContextChildMany>();
            *cm.list.add((*this).context_parent_idx as usize) = core::ptr::null_mut();
        }

        // Place in the new parent.
        if (*parent_new).child_qty() == MEM_QTY_ONE {
            (*child_offset_ptr(parent_new).cast::<MemContextChildOne>()).context = this;
            (*parent_new).set_child_initialized(true);
        } else {
            let cm_ptr = child_offset_ptr(parent_new).cast::<MemContextChildMany>();
            let idx = mem_context_new_index(parent_new, cm_ptr);
            (*this).context_parent_idx = idx;
            *(*cm_ptr).list.add(idx as usize) = this;
        }

        (*this).context_parent = parent_new;
    }
}

/// Sum the allocation footprint of `this` and the subtree below it.
///
/// Mirrors `memContextSize`, which the C side wraps in `#ifdef DEBUG`. Always-defined here
/// because the layout-mirror constants compile in both flavours; the C wrapper still guards the
/// call on `#ifdef DEBUG` so non-DEBUG builds do not pay the recursion cost.
///
/// # Safety
///
/// `this` must be a valid `MemContext *`.
#[allow(clippy::cast_ptr_alignment, clippy::must_use_candidate)]
pub unsafe fn mem_context_size(this: *const MemContext) -> usize {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let mut total: usize = 0;
        let after_struct = this.cast::<u8>().add(core::mem::size_of::<MemContext>());
        let mut offset = after_struct.add((*this).alloc_extra() as usize);

        // Children.
        match (*this).child_qty() {
            MEM_QTY_ONE => {
                if (*this).child_initialized() {
                    let co = offset.cast::<MemContextChildOne>();
                    if !(*co).context.is_null() {
                        total += mem_context_size((*co).context);
                    }
                }
                offset = offset.add(core::mem::size_of::<MemContextChildOne>());
            }
            MEM_QTY_MANY => {
                if (*this).child_initialized() {
                    let cm = offset.cast::<MemContextChildMany>();
                    for idx in 0..(*cm).list_size {
                        let child = *(*cm).list.add(idx as usize);
                        if !child.is_null() {
                            total += mem_context_size(child);
                        }
                    }
                    total += (*cm).list_size as usize * core::mem::size_of::<*mut MemContext>();
                }
                offset = offset.add(core::mem::size_of::<MemContextChildMany>());
            }
            _ => {}
        }

        // Allocations.
        match (*this).alloc_qty() {
            MEM_QTY_ONE => {
                if (*this).alloc_initialized() {
                    let ao = offset.cast::<MemContextAllocOne>();
                    if !(*ao).alloc.is_null() {
                        total += (*(*ao).alloc).size as usize;
                    }
                }
                offset = offset.add(core::mem::size_of::<MemContextAllocOne>());
            }
            MEM_QTY_MANY => {
                if (*this).alloc_initialized() {
                    let am = offset.cast::<MemContextAllocMany>();
                    for idx in 0..(*am).list_size {
                        let alloc = *(*am).list.add(idx as usize);
                        if !alloc.is_null() {
                            total += (*alloc).size as usize;
                        }
                    }
                    total += (*am).list_size as usize * core::mem::size_of::<*mut MemContextAlloc>();
                }
                offset = offset.add(core::mem::size_of::<MemContextAllocMany>());
            }
            _ => {}
        }

        // Callback (no recursion needed; just adjust offset for the trailing region size).
        if (*this).callback_qty() != MEM_QTY_NONE {
            offset = offset.add(core::mem::size_of::<MemContextCallbackOne>());
        }

        ((offset as usize).wrapping_sub(this as usize)) + total
    }
}

/// The top context (slot 0 of the mem-context stack). Set once at process start by [`init_top`].
#[must_use]
pub fn top_context() -> *mut c_void {
    // SAFETY: see module-level note. Slot 0 is initialised before `main` runs.
    unsafe { entry_at(0).mem_context }
}

// ─── Stack (32A) ───────────────────────────────────────────────────────────────────────────────

/// Mirror of `struct MemContextStack` defined in `src/common/memContext.c`.
///
/// Layout-compatible: `MemContext *` (pointer, 8 bytes on 64-bit / 4 on 32-bit) + `enum` (treated
/// as `int` by GCC/clang on the supported targets, 4 bytes) + `unsigned int` (4 bytes). 64-bit
/// total = 16 bytes; 32-bit total = 12 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemContextStackEntry {
    /// Opaque `MemContext *` — the bitfield-packed struct definition lives in
    /// `src/common/memContext.c` and is mirrored to Rust in 32B. 32A only ever shuffles raw
    /// pointers around.
    pub mem_context: *mut c_void,
    /// `STACK_TYPE_SWITCH` or `STACK_TYPE_NEW`.
    pub type_: i32,
    pub try_depth: u32,
}

// SAFETY for every read/write below: pgBackRest's process model is single-threaded per fork so
// concurrent access from the same process is impossible by construction.

const ZERO_ENTRY: MemContextStackEntry = MemContextStackEntry {
    mem_context: core::ptr::null_mut(),
    type_: STACK_TYPE_SWITCH,
    try_depth: 0,
};

/// 128-entry call-stack of mem-context pushes/switches.
///
/// Slot 0 holds the top context (initialised by the C-side `__attribute__((constructor))`
/// `pgbr_mem_context_init_top_ctor`); slots 1..=127 fill on `switch` / `push_new`. Exported
/// under the legacy C symbol name so `src/common/memContext.c` can keep the
/// `extern struct MemContextStack memContextStack[…]` declaration the test depends on.
#[unsafe(no_mangle)]
pub static mut memContextStack: [MemContextStackEntry; MEM_CONTEXT_STACK_MAX] = [ZERO_ENTRY; MEM_CONTEXT_STACK_MAX];

/// Cursor for the current allocation context. Mirrors `memContextCurrentStackIdx` from the
/// legacy C.
#[unsafe(no_mangle)]
pub static mut memContextCurrentStackIdx: u32 = 0;

/// Cursor for the highest used stack slot, including pending `New` entries. Mirrors
/// `memContextMaxStackIdx` from the legacy C.
#[unsafe(no_mangle)]
pub static mut memContextMaxStackIdx: u32 = 0;

/// Audit sequence counter.
///
/// Bumped by [`next_sequence`] when the still-in-C `memContextNew` stamps a new context (DEBUG
/// only). 32A defines the counter unconditionally so the production build does not need a
/// separate flavour of this crate; the 8 bytes of unused storage in non-DEBUG is negligible.
#[unsafe(no_mangle)]
pub static mut memContextSequence: u64 = 0;

/// Callback the C side passes to [`discard`] / [`clean`] so this module can free a popped
/// `MemContext *`.
///
/// Avoids a hard link-time dependency on `memContextFree` (which lives in
/// `src/common/memContext.c`). Tests that pull in `libpgbr_ffi.a` for `pgbr_stack_trace_*` only
/// — `error`, `error-retry` — would otherwise fail at link with
/// `undefined reference to memContextFree`.
pub type FreeCallback = unsafe extern "C" fn(*mut c_void);

/// Sets `memContextStack[0].mem_context` to the C-side `&contextTop`.
///
/// Called from `__attribute__((constructor))` in `src/common/memContext.c` before `main` runs
/// so the legacy invariant "slot 0 always points at TOP" survives the storage move from C to
/// Rust.
///
/// `pgbr-ffi::pgbr_mem_context_init_top` re-exports this function with the C-visible name so
/// cbindgen surfaces it in `pgbr_ffi.h`.
///
/// # Safety
///
/// `top` must be a valid `MemContext *` whose lifetime is the entire process. Calling this with
/// a different `top` after the first call would silently swap the top context underneath any
/// running code.
pub unsafe fn init_top(top: *mut c_void) {
    // SAFETY: see module-level note. We only touch slot 0 and the cursors, which are owned by
    // this module.
    unsafe {
        let base = (&raw mut memContextStack).cast::<MemContextStackEntry>();
        core::ptr::write(
            base,
            MemContextStackEntry {
                mem_context: top,
                type_: STACK_TYPE_SWITCH,
                try_depth: 0,
            },
        );
    }
}

#[inline]
unsafe fn current_idx() -> u32 {
    // SAFETY: see module-level note.
    unsafe { core::ptr::read(&raw const memContextCurrentStackIdx) }
}

#[inline]
unsafe fn max_idx() -> u32 {
    // SAFETY: see module-level note.
    unsafe { core::ptr::read(&raw const memContextMaxStackIdx) }
}

#[inline]
unsafe fn entry_at(idx: u32) -> MemContextStackEntry {
    // SAFETY: see module-level note. Caller asserts `idx < MEM_CONTEXT_STACK_MAX`.
    unsafe {
        let base = (&raw const memContextStack).cast::<MemContextStackEntry>();
        core::ptr::read(base.add(idx as usize))
    }
}

#[inline]
unsafe fn write_entry(idx: u32, entry: MemContextStackEntry) {
    // SAFETY: see module-level note. Caller asserts `idx < MEM_CONTEXT_STACK_MAX`.
    unsafe {
        let base = (&raw mut memContextStack).cast::<MemContextStackEntry>();
        core::ptr::write(base.add(idx as usize), entry);
    }
}

#[inline]
unsafe fn set_current_idx(value: u32) {
    // SAFETY: see module-level note.
    unsafe { core::ptr::write(&raw mut memContextCurrentStackIdx, value) };
}

#[inline]
unsafe fn set_max_idx(value: u32) {
    // SAFETY: see module-level note.
    unsafe { core::ptr::write(&raw mut memContextMaxStackIdx, value) };
}

/// Outcome of a `switch_back` / `keep` / `discard` call when the stack-top type is wrong.
///
/// The C wrapper translates `Err(_)` into a `THROW_FMT(AssertError, ..., name)` so the existing
/// diagnostic format stays byte-identical. The `mem_context` pointer is the offending top-of-
/// stack context whose `name` (DEBUG-only field) the C side reads to format the message — Rust
/// hands back the pointer rather than the formatted string so the bitfield-mirror work is fully
/// deferred to 32B.
#[derive(Debug, Clone, Copy)]
pub enum StackTopMismatch {
    /// `switch_back` saw a stack-top of type `New` instead of `Switch`. The C diagnostic reads
    /// "current context expected but new context '%s' found".
    ExpectedSwitchFoundNew { mem_context: *mut c_void },
    /// `keep` or `discard` saw a stack-top of type `Switch` instead of `New`. The C diagnostic
    /// reads "new context expected but current context '%s' found".
    ExpectedNewFoundSwitch { mem_context: *mut c_void },
}

/// Push a `New`-typed entry onto the stack.
///
/// Used by the still-in-C `memContextNew` after it allocates and initialises the new mem
/// context — `memContextNew` calls this instead of directly bumping `memContextMaxStackIdx` so
/// the stack-mutation code path lives in one place.
///
/// # Safety
///
/// `mem_context` must be a valid `MemContext *`. The caller asserts the stack has room
/// (`max_idx() < MEM_CONTEXT_STACK_MAX - 1`).
pub unsafe fn push_new(mem_context: *mut c_void, try_depth: u32) {
    // SAFETY: see module-level note.
    unsafe {
        let new_max = max_idx() + 1;
        assert!((new_max as usize) < MEM_CONTEXT_STACK_MAX, "mem context stack overflow");
        write_entry(
            new_max,
            MemContextStackEntry {
                mem_context,
                type_: STACK_TYPE_NEW,
                try_depth,
            },
        );
        set_max_idx(new_max);
    }
}

/// Switch the current context to `mem_context`.
///
/// Mirrors `memContextSwitch` minus the `this != NULL` and `this->active` C-side `ASSERT`s,
/// which the C wrapper still runs because 32A does not yet have a Rust accessor for the
/// `active` bitfield.
///
/// # Safety
///
/// `mem_context` must be a valid `MemContext *`.
pub unsafe fn switch(mem_context: *mut c_void, try_depth: u32) {
    // SAFETY: see module-level note.
    unsafe {
        assert!(
            (current_idx() as usize) < MEM_CONTEXT_STACK_MAX - 1,
            "mem context stack overflow"
        );
        let new_max = max_idx() + 1;
        write_entry(
            new_max,
            MemContextStackEntry {
                mem_context,
                type_: STACK_TYPE_SWITCH,
                try_depth,
            },
        );
        set_max_idx(new_max);
        set_current_idx(new_max);
    }
}

/// Switch back to the prior `Switch`-typed context. Mirrors `memContextSwitchBack`.
///
/// In DEBUG builds the C side wants to throw `"current context expected but new context '%s'
/// found"` if the stack-top is a `New` entry. To keep the bitfield-mirror work in 32B, this
/// function returns the offending entry instead of formatting the string itself; the C wrapper
/// reads `entry.name` and re-throws.
///
/// # Errors
///
/// Returns `Err(StackTopMismatch::ExpectedSwitchFoundNew)` when the stack-top is `New`. The
/// stack is **not** modified in this case (matching the legacy C behaviour where `THROW_FMT`
/// long-jumps before any decrement).
pub fn switch_back() -> core::result::Result<(), StackTopMismatch> {
    // SAFETY: see module-level note.
    unsafe {
        assert!(current_idx() > 0, "mem context stack underflow");
        let max = max_idx();
        let top = entry_at(max);
        if top.type_ == STACK_TYPE_NEW {
            return Err(StackTopMismatch::ExpectedSwitchFoundNew {
                mem_context: top.mem_context,
            });
        }
        assert!(current_idx() == max, "mem context stack out of sync");
        set_max_idx(max - 1);
        let mut cur = current_idx() - 1;
        while entry_at(cur).type_ == STACK_TYPE_NEW {
            cur -= 1;
        }
        set_current_idx(cur);
        Ok(())
    }
}

/// Promote the most recently `push_new`'d context so it survives an error unwind. Mirrors
/// `memContextKeep`.
///
/// # Errors
///
/// Returns `Err(StackTopMismatch::ExpectedNewFoundSwitch)` when the stack-top is a `Switch`
/// entry instead of `New`. The stack is not modified in that case — the C wrapper re-throws as
/// `AssertError` ("new context expected but current context '%s' found").
pub fn keep() -> core::result::Result<(), StackTopMismatch> {
    // SAFETY: see module-level note.
    unsafe {
        let max = max_idx();
        let top = entry_at(max);
        if top.type_ != STACK_TYPE_NEW {
            return Err(StackTopMismatch::ExpectedNewFoundSwitch {
                mem_context: top.mem_context,
            });
        }
        set_max_idx(max - 1);
        Ok(())
    }
}

/// Discard the most recently `push_new`'d context: pop and invoke `free` on the popped pointer.
/// Mirrors `memContextDiscard`.
///
/// `free` is the still-in-C `memContextFree`. 32B replaces the callback with a Rust port.
///
/// # Errors
///
/// Returns `Err(StackTopMismatch::ExpectedNewFoundSwitch)` when the stack-top is a `Switch`
/// entry instead of `New`. The stack is not modified and `free` is not called in that case.
///
/// # Safety
///
/// `free` must be a valid C function pointer that may be invoked with the popped
/// `MemContext *`.
pub unsafe fn discard(free: FreeCallback) -> core::result::Result<(), StackTopMismatch> {
    // SAFETY: see module-level note.
    unsafe {
        let max = max_idx();
        let top = entry_at(max);
        if top.type_ != STACK_TYPE_NEW {
            return Err(StackTopMismatch::ExpectedNewFoundSwitch {
                mem_context: top.mem_context,
            });
        }
        free(top.mem_context);
        set_max_idx(max - 1);
        Ok(())
    }
}

/// Returns the current `MemContext *` (the entry at `memContextStack[memContextCurrentStackIdx]`).
/// Mirrors `memContextCurrent`.
#[must_use]
pub fn current() -> *mut c_void {
    // SAFETY: see module-level note. The legacy code does not bounds-check `current_idx` because
    // the stack is initialised to slot 0 holding `contextTop`.
    unsafe { entry_at(current_idx()).mem_context }
}

/// Returns the `MemContext *` that was current immediately before the last `switch`. Mirrors
/// `memContextPrior`. Walks past intervening `New` entries that cannot be switched to.
#[must_use]
pub fn prior() -> *mut c_void {
    // SAFETY: see module-level note.
    unsafe {
        let cur = current_idx();
        assert!(cur > 0, "mem context prior() called at stack bottom");
        let mut prior_idx = 1u32;
        while entry_at(cur - prior_idx).type_ == STACK_TYPE_NEW {
            prior_idx += 1;
        }
        entry_at(cur - prior_idx).mem_context
    }
}

/// Drop entries from the stack whose `try_depth >= try_depth_floor`.
///
/// Invokes `free` on each `New` entry (unless `fatal == true`, in which case destructors are
/// skipped to avoid masking the original error) and snaps `current_idx` back to the highest
/// `Switch` entry below the floor.
///
/// `free` is the still-in-C `memContextFree`; the callback indirection avoids a hard link-time
/// dependency on `memContextFree` for tests that pull in `libpgbr_ffi.a` only for
/// `pgbr_stack_trace_*` (`error`, `error-retry`).
///
/// Mirrors `memContextClean(tryDepth, fatal)`.
///
/// # Safety
///
/// `free` must be a valid C function pointer that may be invoked with each popped
/// `MemContext *` while `fatal == false`.
pub unsafe fn clean(try_depth_floor: u32, fatal: bool, free: FreeCallback) {
    // SAFETY: see module-level note. The legacy `ASSERT(tryDepth > 0)` becomes a Rust assert.
    assert!(try_depth_floor > 0, "memContextClean: tryDepth must be > 0");
    // SAFETY: see module-level note.
    unsafe {
        while entry_at(max_idx()).try_depth >= try_depth_floor {
            let max = max_idx();
            let entry = entry_at(max);
            if entry.type_ == STACK_TYPE_NEW {
                if !fatal {
                    free(entry.mem_context);
                }
            } else {
                // Switch: pop the current cursor too, walking past any New frames.
                let mut cur = current_idx() - 1;
                while entry_at(cur).type_ == STACK_TYPE_NEW {
                    cur -= 1;
                }
                set_current_idx(cur);
            }
            set_max_idx(max - 1);
        }
    }
}

/// Bump and return `memContextSequence`.
///
/// Used by the still-in-C `memContextNew` (DEBUG only) to stamp the new context's audit sequence
/// number.
pub fn next_sequence() -> u64 {
    // SAFETY: see module-level note.
    unsafe {
        let next = core::ptr::read(&raw const memContextSequence) + 1;
        core::ptr::write(&raw mut memContextSequence, next);
        next
    }
}

/// Read accessor for the C-side `memContextCurrentStackIdx` cursor. Used by the test rewrite in
/// 32D so the test can assert on stack state without touching the raw extern.
#[must_use]
pub fn current_stack_idx() -> u32 {
    // SAFETY: see module-level note.
    unsafe { current_idx() }
}

/// Read accessor for the C-side `memContextMaxStackIdx` cursor.
#[must_use]
pub fn max_stack_idx() -> u32 {
    // SAFETY: see module-level note.
    unsafe { max_idx() }
}

/// Read accessor for an entry in `memContextStack` by index.
///
/// # Safety
///
/// `idx` must be `< MEM_CONTEXT_STACK_MAX`.
#[must_use]
pub unsafe fn stack_entry_at(idx: u32) -> MemContextStackEntry {
    // SAFETY: caller asserts `idx < MEM_CONTEXT_STACK_MAX`.
    unsafe { entry_at(idx) }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::explicit_iter_loop
)]
mod tests {
    //! The state arrays and cursors are real Rust statics now (no `#[cfg(test)]` mocks needed).
    //! Each test resets them via [`fresh_state`] before running and serialises with
    //! [`TEST_LOCK`] because the storage is shared across all tests in this module.
    //!
    //! `discard()` and `clean()` take a `FreeCallback` parameter so the unit-test binary does
    //! not need a `memContextFree` extern; the [`fake_free`] helper records each pointer in
    //! [`FREE_CALLS`] for assertions.
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static FREE_CALLS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

    extern "C" fn fake_free(this: *mut c_void) {
        FREE_CALLS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(this as usize);
    }

    fn fresh_state() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: TEST_LOCK serialises tests so no other reference is alive. We use
        // `core::ptr::write` to avoid creating a `&mut` reference to a `static mut` (which
        // clippy's `static_mut_refs` lint flags as UB risk).
        unsafe {
            // Reset the stack via the public init hook so we exercise the same code path the
            // C-side `__attribute__((constructor))` uses in the integrated build.
            init_top(0x1000usize as *mut c_void);
            let base = (&raw mut memContextStack).cast::<MemContextStackEntry>();
            for idx in 1..MEM_CONTEXT_STACK_MAX {
                core::ptr::write(
                    base.add(idx),
                    MemContextStackEntry {
                        mem_context: core::ptr::null_mut(),
                        type_: STACK_TYPE_SWITCH,
                        try_depth: 0,
                    },
                );
            }
            core::ptr::write(&raw mut memContextCurrentStackIdx, 0);
            core::ptr::write(&raw mut memContextMaxStackIdx, 0);
            core::ptr::write(&raw mut memContextSequence, 0);
        }
        FREE_CALLS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
        guard
    }

    #[test]
    fn current_returns_top_at_startup() {
        let _g = fresh_state();
        assert_eq!(current() as usize, 0x1000);
    }

    #[test]
    fn switch_then_switch_back_round_trips() {
        let _g = fresh_state();
        let new_ctx = 0x2000usize as *mut c_void;
        // SAFETY: pointer is a sentinel that we never dereference.
        unsafe { switch(new_ctx, 1) };
        assert_eq!(current() as usize, 0x2000);
        assert!(switch_back().is_ok());
        assert_eq!(current() as usize, 0x1000);
    }

    #[test]
    fn switch_back_errors_when_top_is_new() {
        let _g = fresh_state();
        // Mirror the legacy test sequence at memContextTest.c:205–209: switch first so the
        // current cursor advances above 0, push_new on top, then assert switch_back errors
        // because the stack-top is a New entry (not a Switch).
        let switched = 0x2900usize as *mut c_void;
        let new_ctx = 0x3000usize as *mut c_void;
        // SAFETY: sentinel pointers.
        unsafe {
            switch(switched, 0);
            push_new(new_ctx, 0);
        }
        match switch_back() {
            Err(StackTopMismatch::ExpectedSwitchFoundNew { mem_context }) => {
                assert_eq!(mem_context as usize, 0x3000);
            }
            other => panic!("expected ExpectedSwitchFoundNew, got {other:?}"),
        }
    }

    #[test]
    fn keep_pops_new_entry() {
        let _g = fresh_state();
        let new_ctx = 0x4000usize as *mut c_void;
        // SAFETY: sentinel pointer.
        unsafe { push_new(new_ctx, 0) };
        // SAFETY: see module-level note.
        unsafe { assert_eq!(max_idx(), 1) };
        assert!(keep().is_ok());
        // SAFETY: see module-level note.
        unsafe { assert_eq!(max_idx(), 0) };
        // current_idx is unchanged because keep does not touch it.
        assert_eq!(current() as usize, 0x1000);
    }

    #[test]
    fn keep_errors_when_top_is_switch() {
        let _g = fresh_state();
        let new_ctx = 0x5000usize as *mut c_void;
        // SAFETY: sentinel pointer.
        unsafe { switch(new_ctx, 0) };
        match keep() {
            Err(StackTopMismatch::ExpectedNewFoundSwitch { mem_context }) => {
                assert_eq!(mem_context as usize, 0x5000);
            }
            other => panic!("expected ExpectedNewFoundSwitch, got {other:?}"),
        }
    }

    #[test]
    fn discard_calls_mem_context_free_on_top() {
        let _g = fresh_state();
        let new_ctx = 0x6000usize as *mut c_void;
        // SAFETY: sentinel pointer.
        unsafe { push_new(new_ctx, 0) };
        // SAFETY: fake_free is a valid C function pointer.
        assert!(unsafe { discard(fake_free) }.is_ok());
        let calls = FREE_CALLS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(*calls, vec![0x6000]);
    }

    #[test]
    fn prior_walks_past_new_frames() {
        let _g = fresh_state();
        let switched = 0x7000usize as *mut c_void;
        let new_a = 0x7100usize as *mut c_void;
        let new_b = 0x7200usize as *mut c_void;
        // Push a Switch on top of TOP, then two News above the switch. Prior should still see
        // TOP because News are not switchable.
        // SAFETY: sentinel pointers.
        unsafe {
            switch(switched, 0);
            push_new(new_a, 0);
            push_new(new_b, 0);
        }
        assert_eq!(current() as usize, 0x7000);
        assert_eq!(prior() as usize, 0x1000);
    }

    #[test]
    fn clean_unwinds_to_try_depth_floor() {
        let _g = fresh_state();
        let switched = 0x8000usize as *mut c_void;
        let new_inside = 0x8100usize as *mut c_void;
        // SAFETY: sentinel pointers.
        unsafe {
            switch(switched, 5); // try_depth = 5
            push_new(new_inside, 5); // try_depth = 5
        }
        // Clean everything at try_depth >= 5 and free the New entry.
        // SAFETY: fake_free is a valid C function pointer.
        unsafe { clean(5, false, fake_free) };
        // Stack should now be just TOP again.
        // SAFETY: see module-level note.
        unsafe { assert_eq!(max_idx(), 0) };
        assert_eq!(current() as usize, 0x1000);
        let calls = FREE_CALLS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(*calls, vec![0x8100]);
    }

    #[test]
    fn clean_skips_destructors_on_fatal() {
        let _g = fresh_state();
        let new_inside = 0x8200usize as *mut c_void;
        // SAFETY: sentinel pointer.
        unsafe { push_new(new_inside, 3) };
        // SAFETY: fake_free is a valid C function pointer.
        unsafe { clean(3, true, fake_free) };
        // SAFETY: see module-level note.
        unsafe { assert_eq!(max_idx(), 0) };
        let calls = FREE_CALLS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(calls.is_empty(), "fatal-path clean must not call memContextFree");
    }

    #[test]
    fn next_sequence_monotonic() {
        let _g = fresh_state();
        assert_eq!(next_sequence(), 1);
        assert_eq!(next_sequence(), 2);
        assert_eq!(next_sequence(), 3);
    }
}
