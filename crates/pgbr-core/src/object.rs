//! Object helper bodies migrated from `src/common/type/object.c`.
//!
//! Three thin functions that compose the existing `mem_context` machinery: `move_obj`
//! and `move_to_interface` walk back from the object's `allocExtra` pointer to its
//! owning `MemContext` and forward the move; `free_obj` resolves the same `MemContext`
//! and hands it to a caller-supplied free callback.
//!
//! The free callback is passed as a parameter rather than statically linked here because
//! the legacy `memContextFree` function still lives on the C side (`src/common/memContext.c`)
//! — the same pattern already used by `pgbr_mem_context_discard` /
//! `pgbr_mem_context_clean`.

use core::ffi::c_void;

use crate::mem_context;

/// `objMove(thisVoid, parentNew)`. No-op when `thisVoid` is null. Returns `thisVoid`
/// unchanged so the caller can use the C-style `void *` return.
///
/// # Safety
///
/// `this_void`, when non-null, must point at the `allocExtra` slot of an object
/// allocated via `OBJ_NEW_*`. `parent_new` must be a valid `MemContext` (or null
/// for the legacy "no-op move" case the C code never actually exercises but the
/// signature permits).
#[must_use]
pub unsafe fn move_obj(this_void: *mut c_void, parent_new: *mut c_void) -> *mut c_void {
    if !this_void.is_null() {
        // SAFETY: caller upholds the contract that `this_void` is a live `allocExtra`
        // pointer; the resulting `MemContext` therefore borrows from a live allocation.
        let mc = unsafe { mem_context::mem_context_from_alloc_extra(this_void) };
        // SAFETY: same — `mc` is a live `MemContext`, `parent_new` is the caller's
        // chosen destination context.
        unsafe { mem_context::mem_context_move(mc.cast(), parent_new.cast()) };
    }
    this_void
}

/// `objMoveToInterface(thisVoid, interfaceVoid, current)`.
///
/// Mirrors the legacy C body: if the object's owning context already matches the
/// caller's `current` context the call is a no-op and `this_void` is returned
/// unchanged; otherwise the object is moved into `interfaceVoid`'s owning context so
/// the interface becomes responsible for cleanup.
///
/// # Safety
///
/// `this_void` and `interface_void`, when non-null, must point at the `allocExtra`
/// slots of objects allocated via `OBJ_NEW_*`. `current` is a borrowed pointer the
/// caller obtained from `mem_context_current` — never freed by this function.
#[must_use]
pub unsafe fn move_to_interface(this_void: *mut c_void, interface_void: *mut c_void, current: *const c_void) -> *mut c_void {
    // SAFETY: caller upholds the live-allocation contract.
    let this_mc = unsafe { mem_context::mem_context_from_alloc_extra(this_void) };
    if this_mc.cast::<c_void>().cast_const() == current {
        this_void
    } else {
        // SAFETY: caller upholds the contract for `interface_void`.
        let interface_mc = unsafe { mem_context::mem_context_from_alloc_extra(interface_void) };
        // SAFETY: `move_obj` upholds its own contract internally.
        unsafe { move_obj(this_void, interface_mc.cast()) }
    }
}

/// `objFree(thisVoid)`. No-op when null. Resolves the owning context and forwards it
/// to the supplied free callback (typically the C-side `memContextFree`).
///
/// # Safety
///
/// `this_void`, when non-null, must point at the `allocExtra` slot of an object
/// allocated via `OBJ_NEW_*`. `free_callback` must be safe to invoke on the resulting
/// `MemContext` pointer.
pub unsafe fn free_obj(this_void: *mut c_void, free_callback: unsafe extern "C" fn(*mut c_void)) {
    if !this_void.is_null() {
        // SAFETY: caller upholds the live-allocation contract.
        let mc = unsafe { mem_context::mem_context_from_alloc_extra(this_void) };
        // SAFETY: caller asserts `free_callback` is a valid free function for `mc`.
        unsafe { free_callback(mc.cast()) };
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn move_obj_with_null_returns_null() {
        // No `mem_context` work is done because the early-out covers null.
        // SAFETY: null pointer is the documented no-op input.
        let r = unsafe { move_obj(core::ptr::null_mut(), core::ptr::null_mut()) };
        assert!(r.is_null());
    }

    #[test]
    fn move_to_interface_returns_self_when_already_in_current_context() {
        // The branch we exercise here just compares pointers and skips the move; we can
        // safely fabricate an `allocExtra` pointer plus a matching `MemContext` pointer
        // because `mem_context_from_alloc_extra` is a const-time pointer arithmetic
        // helper that does not dereference its argument's payload.
        let mut storage = [0u8; 4096];
        let alloc_extra: *mut c_void = storage.as_mut_ptr().cast();
        // SAFETY: `mem_context_from_alloc_extra` is pointer arithmetic only.
        let mc = unsafe { mem_context::mem_context_from_alloc_extra(alloc_extra) };
        // current == this_mc -> branch returns alloc_extra unchanged with no further
        // reads or writes.
        // SAFETY: same — only the early-out branch is reached.
        let r = unsafe { move_to_interface(alloc_extra, core::ptr::null_mut(), mc.cast_const().cast::<c_void>()) };
        assert_eq!(r, alloc_extra);
    }

    extern "C" fn capture_callback(arg: *mut c_void) {
        CAPTURED_FREE.with(|cell| cell.set(arg));
    }

    thread_local! {
        static CAPTURED_FREE: core::cell::Cell<*mut c_void> = const { core::cell::Cell::new(core::ptr::null_mut()) };
    }

    #[test]
    fn free_obj_with_null_skips_callback() {
        CAPTURED_FREE.with(|cell| cell.set(core::ptr::null_mut()));
        // SAFETY: documented no-op input.
        unsafe { free_obj(core::ptr::null_mut(), capture_callback) };
        assert!(CAPTURED_FREE.with(core::cell::Cell::get).is_null());
    }

    #[test]
    fn free_obj_with_non_null_invokes_callback_on_owning_context() {
        let mut storage = [0u8; 4096];
        let alloc_extra: *mut c_void = storage.as_mut_ptr().cast();
        // SAFETY: `mem_context_from_alloc_extra` is pointer arithmetic only.
        let expected_mc = unsafe { mem_context::mem_context_from_alloc_extra(alloc_extra) };

        CAPTURED_FREE.with(|cell| cell.set(core::ptr::null_mut()));
        // SAFETY: capture_callback only stores the pointer and never dereferences it.
        unsafe { free_obj(alloc_extra, capture_callback) };
        assert_eq!(CAPTURED_FREE.with(core::cell::Cell::get), expected_mc.cast::<c_void>());
    }
}
