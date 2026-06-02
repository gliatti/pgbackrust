//! Memory-context stack-state algorithms and storage.
//!
//! This module owns both the **algorithmic** layer of the mem-context stack (`switch`,
//! `switch_back`, `keep`, `discard`, `current`, `prior`, `clean`, plus the `push_new` helper used
//! by [`mem_context_new`]) and the **storage** for the 128-entry stack array
//! ([`MEM_CONTEXT_STACK`]), the cursor variables ([`MEM_CONTEXT_CURRENT_STACK_IDX`],
//! [`MEM_CONTEXT_MAX_STACK_IDX`]), and the audit sequence counter ([`MEM_CONTEXT_SEQUENCE`]).
//!
//! Slot zero of the stack holds the address of the top context ([`TOP_CONTEXT`]). [`init_top`]
//! primes that slot, and [`top_setup`] initialises the top context's bitfields; both must run once
//! before the first allocation.
//!
//! The layout originally mirrored the C `struct MemContext` byte-for-byte so the Rust and C halves
//! could share the same malloc'd allocations. The C tree has since been removed; the algorithms
//! and the `#[repr(C)]` layout are retained as-is.

use core::ffi::c_char;
use core::ffi::c_void;

/// Maximum stack depth tracked. Mirrors the original C `MEM_CONTEXT_STACK_MAX`.
pub const MEM_CONTEXT_STACK_MAX: usize = 128;

/// Mirror of the original C `MemQty` enum. The bitfield uses 2 bits to hold one of these values.
pub const MEM_QTY_NONE: u8 = 0;
pub const MEM_QTY_ONE: u8 = 1;
pub const MEM_QTY_MANY: u8 = 2;

/// Number of `MemContext` slots reserved per child / alloc list when the list is first
/// initialised. Mirrors the original C `MEM_CONTEXT_INITIAL_SIZE`.
pub const MEM_CONTEXT_INITIAL_SIZE: u32 = 4;

/// Number of `MemContextAlloc` slots reserved per allocation list when first initialised.
/// Mirrors the original C `MEM_CONTEXT_ALLOC_INITIAL_SIZE`.
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

// ─── Tree-structure mirrors ──────────────────────────────────────────────────────────────────────
//
// `MemContext` and its satellite structs use `#[repr(C)]` with a GCC-SysV-compatible bitfield
// layout. The layout matches what the original C `struct MemContext` produced on 64-bit
// (`sizeof == 32`) and 32-bit (`sizeof == 24`) — see the size assertions below — so the
// allocation math in `mem_context_new` / `mem_context_free_release_recurse` stays correct.

/// Bitfield-packed flags region of `MemContext`.
///
/// GCC's System V ABI packs consecutive bitfields LSB-first into a single 32-bit storage unit
/// when the total bit count fits. The layout uses 26 bits.
///
/// LSB-first bit layout (matches `GCC` `SysV` ABI):
///
/// | bits  | field                  |
/// |-------|------------------------|
/// | 0     | `active`               |
/// | 1-2   | `child_qty`            |
/// | 3     | `child_initialized`    |
/// | 4-5   | `alloc_qty`            |
/// | 6     | `alloc_initialized`    |
/// | 7-8   | `callback_qty`         |
/// | 9     | `callback_initialized` |
/// | 10-25 | `alloc_extra`          |
const FLAG_ACTIVE_SHIFT: u32 = 0;
const FLAG_ACTIVE_MASK: u32 = 0x1;
const FLAG_CHILD_QTY_SHIFT: u32 = 1;
const FLAG_CHILD_QTY_MASK: u32 = 0x3;
const FLAG_CHILD_INIT_SHIFT: u32 = 3;
const FLAG_CHILD_INIT_MASK: u32 = 0x1;
const FLAG_ALLOC_QTY_SHIFT: u32 = 4;
const FLAG_ALLOC_QTY_MASK: u32 = 0x3;
const FLAG_ALLOC_INIT_SHIFT: u32 = 6;
const FLAG_ALLOC_INIT_MASK: u32 = 0x1;
const FLAG_CALLBACK_QTY_SHIFT: u32 = 7;
const FLAG_CALLBACK_QTY_MASK: u32 = 0x3;
const FLAG_CALLBACK_INIT_SHIFT: u32 = 9;
const FLAG_CALLBACK_INIT_MASK: u32 = 0x1;
const FLAG_ALLOC_EXTRA_SHIFT: u32 = 10;
const FLAG_ALLOC_EXTRA_MASK: u32 = 0xFFFF;

/// `#[repr(C)]` mem-context header.
///
/// Carries the audit `name` / `sequence_new` fields and an `active` bit slot. Sizes:
///   * 64-bit: 32 bytes (`8 name + 8 seq + 4 flags + 4 parent_idx + 8 parent`).
///   * 32-bit: 24 bytes (`u64` is 4-aligned on 32-bit Linux: `4+8+4+4+4`).
#[repr(C)]
pub struct MemContext {
    pub name: *const c_char,
    pub sequence_new: u64,
    pub flags: u32,
    pub context_parent_idx: u32,
    pub context_parent: *mut Self,
}

/// Compile-time assertion that the layout matches the expected `sizeof`.
const _: () = {
    #[cfg(target_pointer_width = "64")]
    assert!(
        core::mem::size_of::<MemContext>() == 32,
        "MemContext must be 32 bytes on 64-bit"
    );
    #[cfg(target_pointer_width = "32")]
    assert!(
        core::mem::size_of::<MemContext>() == 24,
        "MemContext must be 24 bytes on 32-bit"
    );
};

// The setters take `&mut self` and the const-ness lint (nursery) would otherwise fire on the
// bitfield helpers; suppress at the impl level so the accessor API stays uniform.
#[allow(
    clippy::unused_self,
    clippy::needless_pass_by_ref_mut,
    clippy::missing_const_for_fn,
    unused_variables
)]
impl MemContext {
    /// `true` while the context is in active use; cleared by [`mem_context_callback_recurse`]
    /// before the callback fires.
    #[must_use]
    pub const fn active(&self) -> bool {
        (self.flags >> FLAG_ACTIVE_SHIFT) & FLAG_ACTIVE_MASK != 0
    }

    /// Set the active bit.
    pub fn set_active(&mut self, value: bool) {
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

/// Mirror of the original C `struct MemContextChildOne`.
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

/// 3D table mirroring the original C `memContextSizePossible[memQtyMany + 1][memQtyMany +
/// 1][memQtyOne + 1]`. Indexed `[child_qty][alloc_qty][callback_qty]`,
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

// libc allocators. Tree-internal allocations (`mem_context_new` and friends) go straight to libc
// malloc/realloc/free. On null return these helpers panic; the no-panic `*_or_null` variants
// below are used on the public allocation path so a `MemoryError` can be surfaced instead.
unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

/// Allocate `size` bytes via libc malloc. Panics on null return.
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

/// libc free wrapped for tree-internal use. Different from the public [`mem_free`] (which
/// operates on a user buffer); this helper just calls libc free on a malloc'd block.
unsafe fn libc_free(ptr: *mut c_void) {
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

// ─── Tree algorithms ─────────────────────────────────────────────────────────────────────────────
//
// `mem_context_new` allocates and initialises a new context, registering it in the parent's
// child list and pushing a `New` entry on the mem-context stack. `mem_context_callback_recurse`
// runs the destructor callbacks tree-deep before any memory is freed (the caller is expected to
// run these halves under a try/finally so a callback unwind does not leak the freed memory).
// `mem_context_free_release_recurse` frees the allocation tree. `mem_context_move` reparents an
// existing context, and `mem_context_size` sums the allocation totals for audit reporting.
//
// All readers of bitfield-packed fields go through the `MemContext::*` accessors, which encode
// the documented shift/mask positions. The `const _: ()` size assertions above guarantee the
// layout matches what the allocation math expects.
//
// Clippy allowances:
//   * `cast_ptr_alignment` — these algorithms reach into a single malloc'd block via a `*mut u8`
//     cursor that's then cast to the appropriate optional-region struct. Alignment is correct
//     because `mem_context_new` pads `alloc_extra` to `align_of::<*mut c_void>()` before
//     deciding the layout.
//   * `must_use_candidate` / `too_long_first_doc_paragraph` — the returned values are inspected
//     by callers rather than chained through Rust, and the docs lead with usage context.

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
/// Mirrors the legacy `memContextNew`. On return the context is registered in the parent's child
/// list and a `New` entry is pushed on the mem-context stack so an error unwind will free the
/// partially-built context.
///
/// # Safety
///
/// `name` must be a valid NUL-terminated C string with the lifetime of the new context. The
/// current context (slot `MEM_CONTEXT_CURRENT_STACK_IDX`) must have `child_qty != MEM_QTY_NONE`.
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
    // list (read via the `MemContext::*` accessors).
    unsafe {
        let context_current = current().cast::<MemContext>();

        let total_size = core::mem::size_of::<MemContext>()
            + alloc_extra
            + SIZE_POSSIBLE[child_qty as usize][alloc_qty as usize][callback_qty as usize];

        let this = mem_alloc(total_size).cast::<MemContext>();

        core::ptr::write(
            this,
            MemContext {
                name,
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
            // MEM_QTY_MANY (none rejected by the caller).
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
/// Mirrors `memContextCallbackRecurse`. A callback may unwind via the error machinery; the caller
/// is expected to run this inside a try/finally so the freed memory still gets reclaimed in
/// [`mem_context_free_release_recurse`].
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
/// Returns null on success or the offending context pointer when the "cannot free current
/// context" invariant is violated; the caller turns a non-null return into an `AssertError`
/// ("cannot free current context '%s'", reading the context's `name`).
///
/// # Safety
///
/// `this` must be a valid `MemContext *` whose tree has not been freed yet.
#[allow(clippy::cast_ptr_alignment, clippy::needless_pass_by_ref_mut)]
pub unsafe fn mem_context_free_release_recurse(this: *mut MemContext) -> *mut MemContext {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let top = top_context();

        // Cannot free the current context (top is special — it can be reset).
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
                libc_free((*cm_ptr).list.cast::<c_void>());
            }
        }

        // Free allocations.
        if (*this).alloc_initialized() {
            if (*this).alloc_qty() == MEM_QTY_ONE {
                let ao = alloc_offset_ptr(this).cast::<MemContextAllocOne>();
                let alloc = (*ao).alloc;
                if !alloc.is_null() {
                    libc_free(alloc.cast::<c_void>());
                }
            } else {
                let am_ptr = alloc_offset_ptr(this).cast::<MemContextAllocMany>();
                let am = &*am_ptr;
                for idx in 0..am.list_size {
                    let alloc = *am.list.add(idx as usize);
                    if !alloc.is_null() {
                        libc_free(alloc.cast::<c_void>());
                    }
                }
                libc_free((*am_ptr).list.cast::<c_void>());
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
            libc_free(this.cast::<c_void>());
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
/// Mirrors `memContextSize`. Used for audit reporting; the caller decides when the recursion
/// cost is worth paying.
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

// ─── Top context ─────────────────────────────────────────────────────────────────────────────────
//
// The top context is the root of the mem-context tree. Rust's const-init cannot set the bitfield
// bits via the non-const `MemContext::set_*` methods, so the bits get initialised once at process
// start by [`top_setup`].

/// Layout of the top context: a [`MemContext`] header followed by its child and alloc lists.
///
/// A `MemContext` followed by a `MemContextChildMany` and a `MemContextAllocMany`. Lives as a
/// process-wide `static mut` so `&TOP_CONTEXT` is the same pointer for every caller.
#[repr(C)]
pub struct MemContextTop {
    pub mem_context: MemContext,
    pub child_many: MemContextChildMany,
    pub alloc_many: MemContextAllocMany,
}

/// Default-construct an all-zero `MemContextTop`. The bitfields live inside `mem_context.flags`
/// as a single `u32` and the `set_*` accessors are not `const`, so the bits get filled in by
/// [`top_setup`] before the first allocation.
const fn make_top() -> MemContextTop {
    MemContextTop {
        mem_context: MemContext {
            name: TOP_NAME.as_ptr(),
            sequence_new: 0,
            flags: 0,
            context_parent_idx: 0,
            context_parent: core::ptr::null_mut(),
        },
        child_many: MemContextChildMany {
            list: core::ptr::null_mut(),
            list_size: 0,
            free_idx: 0,
        },
        alloc_many: MemContextAllocMany {
            list: core::ptr::null_mut(),
            list_size: 0,
            free_idx: 0,
        },
    }
}

// `c_char` is `i8` on this target, so the `u8 -> c_char` byte casts trip
// `cast_possible_wrap`; the values are plain ASCII (< 128) so the cast is exact.
#[allow(clippy::cast_possible_wrap)]
static TOP_NAME: [c_char; 4] = [b'T' as c_char, b'O' as c_char, b'P' as c_char, 0];

/// Process-wide top context, the root of the mem-context tree.
///
/// Thread-safety: this and the `MEM_CONTEXT_*` `static mut`s below are **not** synchronised.
/// They are reached only from single-threaded contexts today (this module's serialised
/// `#[cfg(test)]` tests; the Rust port has no live multi-threaded caller of the mem-context
/// allocator). The `core::ptr::read`/`write` dance avoids `&mut`-to-`static mut` lints but
/// does **not** make concurrent access sound — before any multi-threaded use these must be
/// guarded by a lock (or the whole subsystem retired). The "pgBackRust forks, never
/// threads" assumption is false in the Rust port.
pub static mut TOP_CONTEXT: MemContextTop = make_top();

/// Initialise the bitfields on [`TOP_CONTEXT`] and prime `MEM_CONTEXT_STACK[0]` with its address.
///
/// Must be called once before the first allocation. The setters are not `const`, so we apply them
/// to a stack-local `MemContext` and then copy the resulting `flags` word into the static via
/// `core::ptr::write` (avoiding `&mut` to a `static mut`).
pub fn top_setup() {
    // SAFETY: process-singleton; the caller guarantees this runs once during single-threaded init.
    unsafe {
        let mut tmp = MemContext {
            name: TOP_NAME.as_ptr(),
            sequence_new: 0,
            flags: 0,
            context_parent_idx: 0,
            context_parent: core::ptr::null_mut(),
        };
        tmp.set_active(true);
        tmp.set_child_qty(MEM_QTY_MANY);
        tmp.set_alloc_qty(MEM_QTY_MANY);

        let flags_ptr = &raw mut TOP_CONTEXT.mem_context.flags;
        core::ptr::write(flags_ptr, tmp.flags);

        init_top((&raw mut TOP_CONTEXT).cast::<c_void>());
    }
}

// ─── Allocations ─────────────────────────────────────────────────────────────────────────────────
//
// `mem_new` / `mem_resize` / `mem_free` are the public allocation API. The `mem_alloc_or_null` /
// `mem_realloc_or_null` helpers below mirror libc malloc / realloc with no panic on failure, so
// the caller can surface a `MemoryError` on a null return instead of aborting.

/// Wrap libc `malloc`. Returns null on failure (caller is expected to translate to `MemoryError`).
unsafe fn mem_alloc_or_null(size: usize) -> *mut c_void {
    // SAFETY: libc malloc is safe to call with any size; null indicates failure.
    unsafe { malloc(size) }
}

/// Wrap libc `realloc`. Returns null on failure.
unsafe fn mem_realloc_or_null(ptr: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: caller asserts `ptr` came from libc malloc / realloc.
    unsafe { realloc(ptr, size) }
}

/// Find a free slot in the current context's alloc list and allocate
/// `sizeof(MemContextAlloc) + size` bytes. Returns the new alloc header (or null on libc OOM).
/// Mirrors `memContextAllocNew`.
///
/// # Safety
///
/// The current context (slot `MEM_CONTEXT_CURRENT_STACK_IDX`) must have
/// `alloc_qty != MEM_QTY_NONE`.
#[allow(clippy::cast_ptr_alignment, clippy::expect_used, clippy::must_use_candidate)]
pub unsafe fn mem_context_alloc_new(size: usize) -> *mut MemContextAlloc {
    // SAFETY: caller upholds the current-context invariants.
    unsafe {
        let total = core::mem::size_of::<MemContextAlloc>()
            .checked_add(size)
            .expect("alloc total overflow");
        let result = mem_alloc_or_null(total).cast::<MemContextAlloc>();
        if result.is_null() {
            return core::ptr::null_mut();
        }

        let ctx = current().cast::<MemContext>();

        if (*ctx).alloc_qty() == MEM_QTY_ONE {
            let one = alloc_offset_ptr(ctx).cast::<MemContextAllocOne>();
            *result = MemContextAlloc {
                alloc_idx: 0,
                size: u32::try_from(total).expect("alloc total fits in 32 bits"),
            };
            (*one).alloc = result;
            (*ctx).set_alloc_initialized(true);
        } else {
            // MEM_QTY_MANY (none rejected by the caller).
            let many = alloc_offset_ptr(ctx).cast::<MemContextAllocMany>();

            if (*ctx).alloc_initialized() {
                while (*many).free_idx < (*many).list_size && !(*(*many).list.add((*many).free_idx as usize)).is_null() {
                    (*many).free_idx += 1;
                }

                if (*many).free_idx == (*many).list_size {
                    let new_size = (*many).list_size * 2;
                    (*many).list = mem_realloc_ptr_array((*many).list, (*many).list_size as usize, new_size as usize);
                    (*many).list_size = new_size;
                }
            } else {
                core::ptr::write(
                    many,
                    MemContextAllocMany {
                        list: mem_alloc_ptr_array(MEM_CONTEXT_ALLOC_INITIAL_SIZE as usize),
                        list_size: MEM_CONTEXT_ALLOC_INITIAL_SIZE,
                        free_idx: 0,
                    },
                );
                (*ctx).set_alloc_initialized(true);
            }

            *result = MemContextAlloc {
                alloc_idx: (*many).free_idx,
                size: u32::try_from(total).expect("alloc total fits in 32 bits"),
            };
            *(*many).list.add((*many).free_idx as usize) = result;
            (*many).free_idx += 1;
        }

        result
    }
}

/// Resize an existing allocation; updates the list pointer in case realloc moved the buffer.
/// Mirrors `memContextAllocResize`.
///
/// # Safety
///
/// `alloc` must be a valid `MemContextAlloc *` from a previous `mem_context_alloc_new` whose
/// owning context is current.
#[allow(clippy::cast_ptr_alignment, clippy::expect_used)]
pub unsafe fn mem_context_alloc_resize(alloc: *mut MemContextAlloc, size: usize) -> *mut MemContextAlloc {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let total = core::mem::size_of::<MemContextAlloc>()
            .checked_add(size)
            .expect("alloc total overflow");
        let new_alloc = mem_realloc_or_null(alloc.cast::<c_void>(), total).cast::<MemContextAlloc>();
        if new_alloc.is_null() {
            return core::ptr::null_mut();
        }
        (*new_alloc).size = u32::try_from(total).expect("alloc total fits in 32 bits");

        let ctx = current().cast::<MemContext>();
        if (*ctx).alloc_qty() == MEM_QTY_ONE {
            (*alloc_offset_ptr(ctx).cast::<MemContextAllocOne>()).alloc = new_alloc;
        } else {
            let many = alloc_offset_ptr(ctx).cast::<MemContextAllocMany>();
            *(*many).list.add((*new_alloc).alloc_idx as usize) = new_alloc;
        }

        new_alloc
    }
}

/// Allocate `size` bytes in the current context.
///
/// Returns the user-visible buffer pointer (the alloc header sits immediately before it).
/// Returns null on libc OOM.
///
/// # Safety
///
/// Same as [`mem_context_alloc_new`].
#[allow(clippy::must_use_candidate)]
pub unsafe fn mem_new(size: usize) -> *mut c_void {
    // SAFETY: see [`mem_context_alloc_new`].
    unsafe {
        let alloc = mem_context_alloc_new(size);
        if alloc.is_null() {
            return core::ptr::null_mut();
        }
        alloc.add(1).cast::<c_void>()
    }
}

/// Allocate an array of `count` `*mut c_void` pointers (zero-initialised). Returns null on OOM.
///
/// # Safety
///
/// Same as [`mem_new`].
#[allow(clippy::must_use_candidate)]
pub unsafe fn mem_new_ptr_array(count: usize) -> *mut c_void {
    // SAFETY: see [`mem_new`].
    unsafe {
        let bytes = count * core::mem::size_of::<*mut c_void>();
        let buffer = mem_new(bytes);
        if buffer.is_null() {
            return core::ptr::null_mut();
        }
        core::ptr::write_bytes(buffer.cast::<u8>(), 0, bytes);
        buffer
    }
}

/// Resize the buffer that backs `buffer`. Returns the new buffer pointer (which may differ from
/// the input) or null on libc OOM.
///
/// # Safety
///
/// `buffer` must be a non-null pointer returned by a previous [`mem_new`] / [`mem_resize`] in
/// the current context.
#[allow(clippy::cast_ptr_alignment)]
#[allow(clippy::must_use_candidate)]
pub unsafe fn mem_resize(buffer: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: caller upholds the invariants.
    unsafe {
        let alloc = buffer.cast::<MemContextAlloc>().sub(1);
        let new_alloc = mem_context_alloc_resize(alloc, size);
        if new_alloc.is_null() {
            return core::ptr::null_mut();
        }
        new_alloc.add(1).cast::<c_void>()
    }
}

/// Free a buffer previously returned by [`mem_new`] / [`mem_resize`]. Mirrors `memFree`.
///
/// The C wrapper retains the `ASSERT_ALLOC_MANY_VALID` check that pins specific text in the
/// test; here we trust the caller.
///
/// # Safety
///
/// `buffer` must be a valid pointer returned by [`mem_new`] / [`mem_resize`] in the current
/// context.
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn mem_free(buffer: *mut c_void) {
    // SAFETY: caller upholds the invariants.
    unsafe {
        let alloc = buffer.cast::<MemContextAlloc>().sub(1);
        let ctx = current().cast::<MemContext>();

        if (*ctx).alloc_qty() == MEM_QTY_ONE {
            (*alloc_offset_ptr(ctx).cast::<MemContextAllocOne>()).alloc = core::ptr::null_mut();
        } else {
            let many = alloc_offset_ptr(ctx).cast::<MemContextAllocMany>();
            let idx = (*alloc).alloc_idx;
            if idx < (*many).free_idx {
                (*many).free_idx = idx;
            }
            *(*many).list.add(idx as usize) = core::ptr::null_mut();
        }

        libc_free(alloc.cast::<c_void>());
    }
}

/// Returns the pointer to the alloc-extra payload immediately following the `MemContext`
/// header. Mirrors `memContextAllocExtra`.
///
/// # Safety
///
/// `this` must be a valid `MemContext *` whose `alloc_extra > 0`.
#[must_use]
pub const unsafe fn mem_context_alloc_extra(this: *mut MemContext) -> *mut c_void {
    // SAFETY: caller upholds the validity invariants.
    unsafe { this.add(1).cast::<c_void>() }
}

/// Recover the owning `MemContext *` given an alloc-extra pointer.
///
/// Mirrors `memContextFromAllocExtra`.
///
/// # Safety
///
/// `alloc_extra` must be a pointer previously returned by [`mem_context_alloc_extra`] of a live
/// context.
#[allow(clippy::cast_ptr_alignment)]
#[must_use]
pub const unsafe fn mem_context_from_alloc_extra(alloc_extra: *mut c_void) -> *mut MemContext {
    // SAFETY: caller upholds the validity invariants.
    unsafe { alloc_extra.cast::<MemContext>().sub(1) }
}

/// Validation predicate used by `ASSERT_ALLOC_MANY_VALID`.
///
/// Returns `true` when the alloc header is non-null, not the `NULL - sizeof(MemContextAlloc)`
/// sentinel produced by passing NULL to `MEM_CONTEXT_ALLOC_HEADER`, and corresponds to a live
/// entry in the current context's many-style alloc list.
///
/// # Safety
///
/// `alloc` must either be null or point at the start of a `MemContextAlloc` header inside an
/// allocation owned by the current context.
#[allow(clippy::cast_ptr_alignment, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
#[must_use]
pub unsafe fn mem_alloc_valid(alloc: *mut MemContextAlloc) -> bool {
    if alloc.is_null() {
        return false;
    }
    // The allocation header sits at `(MemContextAlloc *)buffer - 1`, so a `NULL` buffer produces
    // the `(uintptr_t)-sizeof(MemContextAlloc)` sentinel we guard against here.
    let alloc_int = alloc as usize;
    let sentinel = 0_usize.wrapping_sub(core::mem::size_of::<MemContextAlloc>());
    if alloc_int == sentinel {
        return false;
    }
    // SAFETY: caller upholds the alloc-validity invariants for non-sentinel pointers.
    unsafe {
        let ctx = current().cast::<MemContext>();
        if (*ctx).alloc_qty() != MEM_QTY_MANY || !(*ctx).alloc_initialized() {
            return false;
        }
        let many = alloc_offset_ptr(ctx).cast::<MemContextAllocMany>();
        let idx = (*alloc).alloc_idx;
        if idx >= (*many).list_size {
            return false;
        }
        !(*(*many).list.add(idx as usize)).is_null()
    }
}

// ─── Audit ─────────────────────────────────────────────────────────────────────────────────────
//
// The audit walks the context tree using the `name` / `sequence_new` fields to detect newly
// created children and verify their return types. Callers invoke it only where the cost is
// warranted.

/// Mirror of the C `MemContextAuditState` struct. 64-bit layout: `8 mem_context` +
/// `1 return_type_any + 7 padding` + `8 sequence_context_new` = 24 bytes.
#[repr(C)]
pub struct MemContextAuditState {
    pub mem_context: *mut MemContext,
    pub return_type_any: bool,
    pub sequence_context_new: u64,
}

const _: () = {
    #[cfg(target_pointer_width = "64")]
    assert!(core::mem::size_of::<MemContextAuditState>() == 24);
};

/// Walk `state.mem_context`'s child list and stash the highest `sequence_new` so a later
/// [`mem_context_audit_end`] call can detect newly-created children. Mirrors
/// `memContextAuditBegin`.
///
/// # Safety
///
/// `state` must be a valid `MemContextAuditState *` whose `mem_context` is live.
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn mem_context_audit_begin(state: *mut MemContextAuditState) {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let s = &mut *state;
        let mc = s.mem_context;

        if !(*mc).child_initialized() {
            return;
        }

        if (*mc).child_qty() == MEM_QTY_ONE {
            let child = (*child_offset_ptr(mc).cast::<MemContextChildOne>()).context;
            if !child.is_null() {
                s.sequence_context_new = (*child).sequence_new;
            }
        } else {
            // MEM_QTY_MANY
            let cm = &*child_offset_ptr(mc).cast::<MemContextChildMany>();
            for idx in 0..cm.list_size {
                let child = *cm.list.add(idx as usize);
                if !child.is_null() && (*child).sequence_new > s.sequence_context_new {
                    s.sequence_context_new = (*child).sequence_new;
                }
            }
        }
    }
}

/// Compare a child context's name (`actual`) against the expected return type (`expected`).
/// Allows actual to end with a `::extra` suffix and expected to end with ` *`. Mirrors the
/// static `memContextAuditNameMatch`.
///
/// # Safety
///
/// Both pointers must be valid NUL-terminated C strings.
// ASCII byte literals (`:`, ` `, `*`, all < 128) cast exactly into `c_char`; the
// `cast_possible_wrap` lint flags the signedness change harmlessly. The nursery
// `const fn` suggestion is declined — this walks raw pointers and is only ever
// called at runtime.
#[allow(clippy::cast_possible_wrap, clippy::missing_const_for_fn)]
unsafe fn audit_name_match(actual: *const c_char, expected: *const c_char) -> bool {
    // SAFETY: caller upholds NUL-termination.
    unsafe {
        let mut i: usize = 0;
        loop {
            let a = *actual.add(i);
            if a == 0 {
                break;
            }
            if a != *expected.add(i) {
                break;
            }
            i += 1;
        }
        let a = *actual.add(i);
        let e = *expected.add(i);

        // Either actual is exhausted or it continues with `::`.
        let actual_ok = a == 0 || (a == b':' as c_char && *actual.add(i + 1) == b':' as c_char);
        // Either expected is exhausted or it ends with ` *`.
        let expected_ok = e == 0 || (e == b' ' as c_char && *expected.add(i + 1) == b'*' as c_char && *expected.add(i + 2) == 0);

        actual_ok && expected_ok
    }
}

/// Outcome of a [`mem_context_audit_end`] call.
#[repr(C)]
pub struct AuditEndResult {
    /// `0` = success, `1` = "expected return type X but found Y",
    /// `2` = "expected return type X already found but also found Y".
    pub kind: i32,
    /// On `kind == 2`, the previously-found name; null otherwise.
    pub return_type_found: *const c_char,
    /// On `kind != 0`, the offending name; null otherwise.
    pub return_type_invalid: *const c_char,
}

impl AuditEndResult {
    pub const OK: Self = Self {
        kind: 0,
        return_type_found: core::ptr::null(),
        return_type_invalid: core::ptr::null(),
    };
}

/// Walk the children created since the matching [`mem_context_audit_begin`] call.
///
/// Checks that any whose name matches `return_type` is unique. Mirrors
/// `memContextAuditEnd`. The C wrapper rethrows `kind != 0` as `AssertError`.
///
/// # Safety
///
/// `state` must be a valid `MemContextAuditState *` produced by `mem_context_audit_begin`.
/// `return_type` must be a valid NUL-terminated C string.
#[allow(clippy::cast_ptr_alignment, clippy::must_use_candidate)]
pub unsafe fn mem_context_audit_end(state: *const MemContextAuditState, return_type: *const c_char) -> AuditEndResult {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let s = &*state;
        if s.return_type_any {
            return AuditEndResult::OK;
        }

        let mc = s.mem_context;
        if !(*mc).child_initialized() {
            return AuditEndResult::OK;
        }

        let mut return_type_invalid: *const c_char = core::ptr::null();
        let mut return_type_found: *const c_char = core::ptr::null();

        if (*mc).child_qty() == MEM_QTY_ONE {
            let child = (*child_offset_ptr(mc).cast::<MemContextChildOne>()).context;
            if !child.is_null() && (*child).sequence_new > s.sequence_context_new && !audit_name_match((*child).name, return_type) {
                return_type_invalid = (*child).name;
            }
        } else {
            let cm = &*child_offset_ptr(mc).cast::<MemContextChildMany>();
            for idx in 0..cm.list_size {
                let child = *cm.list.add(idx as usize);
                if child.is_null() || (*child).sequence_new <= s.sequence_context_new {
                    continue;
                }
                if audit_name_match((*child).name, return_type) {
                    if !return_type_found.is_null() {
                        return_type_invalid = (*child).name;
                        break;
                    }
                    return_type_found = (*child).name;
                } else {
                    return_type_invalid = (*child).name;
                    break;
                }
            }
        }

        if !return_type_invalid.is_null() {
            if !return_type_found.is_null() {
                return AuditEndResult {
                    kind: 2,
                    return_type_found,
                    return_type_invalid,
                };
            }
            return AuditEndResult {
                kind: 1,
                return_type_found: core::ptr::null(),
                return_type_invalid,
            };
        }
        AuditEndResult::OK
    }
}

/// Rename a context using its alloc-extra pointer. Mirrors `memContextAuditAllocExtraName`.
/// Returns the input `alloc_extra` unchanged so the macro can be used inline.
///
/// # Safety
///
/// `alloc_extra` must be a pointer returned by [`mem_context_alloc_extra`] of a live context.
/// `name` must be a NUL-terminated C string with a lifetime that outlives the context.
pub unsafe fn mem_context_audit_alloc_extra_name(alloc_extra: *mut c_void, name: *const c_char) -> *mut c_void {
    // SAFETY: caller upholds the validity invariants.
    unsafe {
        let mc = mem_context_from_alloc_extra(alloc_extra);
        (*mc).name = name;
        alloc_extra
    }
}

// ─── Stack ─────────────────────────────────────────────────────────────────────────────────────

/// One entry in the mem-context stack.
///
/// `#[repr(C)]`: `MemContext *` (8 bytes on 64-bit / 4 on 32-bit) + `i32` (4 bytes) + `u32`
/// (4 bytes). 64-bit total = 16 bytes; 32-bit total = 12 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemContextStackEntry {
    /// The `MemContext *` for this entry. The stack only ever shuffles raw pointers around.
    pub mem_context: *mut c_void,
    /// `STACK_TYPE_SWITCH` or `STACK_TYPE_NEW`.
    pub type_: i32,
    pub try_depth: u32,
}

// SAFETY for every read/write below: pgBackRust's process model is single-threaded per fork so
// concurrent access from the same process is impossible by construction.

const ZERO_ENTRY: MemContextStackEntry = MemContextStackEntry {
    mem_context: core::ptr::null_mut(),
    type_: STACK_TYPE_SWITCH,
    try_depth: 0,
};

/// 128-entry call-stack of mem-context pushes/switches.
///
/// Slot 0 holds the top context (primed by [`init_top`]); slots 1..=127 fill on `switch` /
/// `push_new`.
pub static mut MEM_CONTEXT_STACK: [MemContextStackEntry; MEM_CONTEXT_STACK_MAX] = [ZERO_ENTRY; MEM_CONTEXT_STACK_MAX];

/// Cursor for the current allocation context.
pub static mut MEM_CONTEXT_CURRENT_STACK_IDX: u32 = 0;

/// Cursor for the highest used stack slot, including pending `New` entries.
pub static mut MEM_CONTEXT_MAX_STACK_IDX: u32 = 0;

/// Audit sequence counter, bumped by [`next_sequence`] when [`mem_context_new`] stamps a new
/// context.
pub static mut MEM_CONTEXT_SEQUENCE: u64 = 0;

/// Callback passed to [`discard`] / [`clean`] so they can free a popped `MemContext *`.
///
/// The indirection lets callers that never create contexts use the stack without pulling in the
/// free path.
pub type FreeCallback = unsafe extern "C" fn(*mut c_void);

/// Sets `MEM_CONTEXT_STACK[0].mem_context` to the top context's address.
///
/// Must run once before the first allocation so the invariant "slot 0 always points at TOP"
/// holds.
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
        let base = (&raw mut MEM_CONTEXT_STACK).cast::<MemContextStackEntry>();
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
    unsafe { core::ptr::read(&raw const MEM_CONTEXT_CURRENT_STACK_IDX) }
}

#[inline]
unsafe fn max_idx() -> u32 {
    // SAFETY: see module-level note.
    unsafe { core::ptr::read(&raw const MEM_CONTEXT_MAX_STACK_IDX) }
}

#[inline]
unsafe fn entry_at(idx: u32) -> MemContextStackEntry {
    // SAFETY: see module-level note. Caller asserts `idx < MEM_CONTEXT_STACK_MAX`.
    unsafe {
        let base = (&raw const MEM_CONTEXT_STACK).cast::<MemContextStackEntry>();
        core::ptr::read(base.add(idx as usize))
    }
}

#[inline]
unsafe fn write_entry(idx: u32, entry: MemContextStackEntry) {
    // SAFETY: see module-level note. Caller asserts `idx < MEM_CONTEXT_STACK_MAX`.
    unsafe {
        let base = (&raw mut MEM_CONTEXT_STACK).cast::<MemContextStackEntry>();
        core::ptr::write(base.add(idx as usize), entry);
    }
}

#[inline]
unsafe fn set_current_idx(value: u32) {
    // SAFETY: see module-level note.
    unsafe { core::ptr::write(&raw mut MEM_CONTEXT_CURRENT_STACK_IDX, value) };
}

#[inline]
unsafe fn set_max_idx(value: u32) {
    // SAFETY: see module-level note.
    unsafe { core::ptr::write(&raw mut MEM_CONTEXT_MAX_STACK_IDX, value) };
}

/// Outcome of a `switch_back` / `keep` / `discard` call when the stack-top type is wrong.
///
/// The carried `mem_context` pointer is the offending top-of-stack context; the caller reads its
/// `name` field to format an `AssertError` diagnostic.
#[derive(Debug, Clone, Copy)]
pub enum StackTopMismatch {
    /// `switch_back` saw a stack-top of type `New` instead of `Switch`. Diagnostic:
    /// "current context expected but new context '%s' found".
    ExpectedSwitchFoundNew { mem_context: *mut c_void },
    /// `keep` or `discard` saw a stack-top of type `Switch` instead of `New`. Diagnostic:
    /// "new context expected but current context '%s' found".
    ExpectedNewFoundSwitch { mem_context: *mut c_void },
}

/// Push a `New`-typed entry onto the stack.
///
/// Used by [`mem_context_new`] after it allocates and initialises the new context, so the
/// stack-mutation code path lives in one place.
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
/// Mirrors `memContextSwitch`. The caller is responsible for the `this != NULL` and
/// `this->active` preconditions.
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
/// If the stack-top is a `New` entry this returns the offending entry instead of formatting a
/// message; the caller reads `entry.name` and throws "current context expected but new context
/// '%s' found".
///
/// # Errors
///
/// Returns `Err(StackTopMismatch::ExpectedSwitchFoundNew)` when the stack-top is `New`. The
/// stack is **not** modified in this case (the throw happens before any decrement).
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
/// entry instead of `New`. The stack is not modified in that case — the caller throws an
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
/// `free` is the caller-supplied context-free routine.
///
/// # Errors
///
/// Returns `Err(StackTopMismatch::ExpectedNewFoundSwitch)` when the stack-top is a `Switch`
/// entry instead of `New`. The stack is not modified and `free` is not called in that case.
///
/// # Safety
///
/// `free` must be a valid function pointer that may be invoked with the popped `MemContext *`.
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

/// Returns the current `MemContext *` (the entry at
/// `MEM_CONTEXT_STACK[MEM_CONTEXT_CURRENT_STACK_IDX]`). Mirrors `memContextCurrent`.
#[must_use]
pub fn current() -> *mut c_void {
    // SAFETY: see module-level note. `current_idx` is not bounds-checked because slot 0 always
    // holds the top context.
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
/// `free` is the caller-supplied context-free routine; the callback indirection lets callers that
/// never create contexts use the stack without pulling in the free path.
///
/// Mirrors `memContextClean(tryDepth, fatal)`.
///
/// # Safety
///
/// `free` must be a valid function pointer that may be invoked with each popped `MemContext *`
/// while `fatal == false`.
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

/// Bump and return [`MEM_CONTEXT_SEQUENCE`].
///
/// Used by [`mem_context_new`] to stamp the new context's audit sequence number.
pub fn next_sequence() -> u64 {
    // SAFETY: see module-level note.
    unsafe {
        let next = core::ptr::read(&raw const MEM_CONTEXT_SEQUENCE) + 1;
        core::ptr::write(&raw mut MEM_CONTEXT_SEQUENCE, next);
        next
    }
}

/// Read accessor for the [`MEM_CONTEXT_CURRENT_STACK_IDX`] cursor.
#[must_use]
pub fn current_stack_idx() -> u32 {
    // SAFETY: see module-level note.
    unsafe { current_idx() }
}

/// Read accessor for the [`MEM_CONTEXT_MAX_STACK_IDX`] cursor.
#[must_use]
pub fn max_stack_idx() -> u32 {
    // SAFETY: see module-level note.
    unsafe { max_idx() }
}

/// Read accessor for an entry in [`MEM_CONTEXT_STACK`] by index.
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
    //! `discard()` and `clean()` take a `FreeCallback` parameter, so the [`fake_free`] helper
    //! stands in for a real context-free routine and records each pointer in [`FREE_CALLS`] for
    //! assertions.
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
            // Reset the stack via the public init hook so we exercise the same code path
            // start-up uses to prime slot 0.
            init_top(0x1000usize as *mut c_void);
            let base = (&raw mut MEM_CONTEXT_STACK).cast::<MemContextStackEntry>();
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
            core::ptr::write(&raw mut MEM_CONTEXT_CURRENT_STACK_IDX, 0);
            core::ptr::write(&raw mut MEM_CONTEXT_MAX_STACK_IDX, 0);
            core::ptr::write(&raw mut MEM_CONTEXT_SEQUENCE, 0);
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
        // Switch first so the current cursor advances above 0, push_new on top, then assert
        // switch_back errors because the stack-top is a New entry (not a Switch).
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
        assert!(calls.is_empty(), "fatal-path clean must not call the free callback");
    }

    #[test]
    fn next_sequence_monotonic() {
        let _g = fresh_state();
        assert_eq!(next_sequence(), 1);
        assert_eq!(next_sequence(), 2);
        assert_eq!(next_sequence(), 3);
    }
}
