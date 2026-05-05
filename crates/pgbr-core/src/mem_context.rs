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

#[cfg(c_debug)]
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
//
// 32B (this sub-issue) only ships the externs + the layout mirror so the surface is ready for
// the 32B-2 algorithm migration (#236). No live caller exercises these helpers yet — the
// `dead_code` allow stays until 32B-2 lands.
#[allow(dead_code)]
unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

/// Allocate `size` bytes via libc malloc. Panics on null return; the FFI panic guard surfaces
/// the failure to the C caller as `ErrorType::Unknown`.
#[allow(dead_code)]
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
#[allow(dead_code)]
unsafe fn mem_free(ptr: *mut c_void) {
    // SAFETY: caller asserts `ptr` came from a previous `mem_alloc` / libc malloc.
    unsafe { free(ptr) };
}

/// Allocate an array of `count` `*mut T` pointers, all initialised to null. Mirrors the legacy
/// `memAllocPtrArrayInternal`.
#[allow(dead_code, clippy::expect_used)]
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
#[allow(dead_code, clippy::expect_used)]
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

// ─── Tree algorithms (32B-3 / future) ──────────────────────────────────────────────────────────
//
// 32B-1 shipped the layout mirror, 32B-2 lands the dep-tracking improvements (build.rs +
// `pgbr-core/*.rs` listed as ninja inputs) so the cargo build re-runs whenever the Rust mirror
// changes. The actual algorithm migration was attempted in 32B-2 but a build-system-level cfg
// propagation failure blocks it: `meson setup -Dbuildtype=debug` in test.pl flow ends up with
// libpgbr_ffi.a built **without** the c-debug cfg even though `[build-ffi.sh] c_debug=1` is
// printed and the same flags work when run manually from `/work/pgbackrust`. The Rust struct
// then has the non-DEBUG layout (16 bytes) while the C side has the DEBUG layout (32 bytes),
// and `mem_context_new` / `_callback_set` corrupt memory when reading bitfield-packed fields.
// A 32B-3 sub-issue tracks the root-cause analysis of the test-build cfg path.

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
