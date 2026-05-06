//! In-memory log capture used by `test/src/common/harnessLog.c`.
//!
//! The legacy harness intercepted the log write path through the meson `SHIM_MODULE`
//! mechanism (which inlined `src/common/log.c` into the test binary so the harness could
//! redefine `logWrite`). Phase 31 sub-issue B already moved every formatter helper to
//! Rust, leaving the SHIM as nothing but an `#include` of `log.c`. This sub-issue (C)
//! removes the last legacy state-coupling: the harness now drives an in-memory capture
//! buffer through FFI accessors, so the harness no longer needs the C log internals at
//! all.
//!
//! When [`is_installed`] is true, [`super::format::log_post`] routes the file sink (the
//! `level_file` channel) to [`append`] instead of `write(2)`. The harness reads the
//! captured bytes via [`drain`] / [`contains`] and clears them between assertions.
//!
//! Threading model is the same single-threaded fork-per-process invariant as the rest of
//! `pgbr_core::log` — no internal locking.

use std::cell::UnsafeCell;
use std::sync::OnceLock;

/// Process-global capture state.
struct CaptureState {
    installed: bool,
    buffer: Vec<u8>,
}

impl CaptureState {
    const fn new() -> Self {
        Self {
            installed: false,
            buffer: Vec::new(),
        }
    }
}

#[allow(clippy::non_send_fields_in_send_ty)]
struct UnsafeGlobal<T>(UnsafeCell<T>);
// SAFETY: same single-threaded contract as the rest of `pgbr_core::log`.
unsafe impl<T> Sync for UnsafeGlobal<T> {}
unsafe impl<T> Send for UnsafeGlobal<T> {}

static STATE: OnceLock<UnsafeGlobal<CaptureState>> = OnceLock::new();

fn cell() -> &'static UnsafeCell<CaptureState> {
    &STATE.get_or_init(|| UnsafeGlobal(UnsafeCell::new(CaptureState::new()))).0
}

/// # Safety
///
/// Caller upholds the single-threaded contract (no two threads holding `&mut` at once).
#[allow(clippy::mut_from_ref)]
unsafe fn state_mut() -> &'static mut CaptureState {
    // SAFETY: see the contract above.
    unsafe { &mut *cell().get() }
}

/// # Safety
///
/// Same single-threaded contract as [`state_mut`].
unsafe fn state_ref() -> &'static CaptureState {
    // SAFETY: see the contract above.
    unsafe { &*cell().get() }
}

/// Enable capture. Subsequent file-sink writes go to the capture buffer instead of
/// `fd_file`. Idempotent — calling twice clears the buffer the second time.
pub fn install() {
    // SAFETY: see `state_mut`.
    let s = unsafe { state_mut() };
    s.installed = true;
    s.buffer.clear();
}

/// Disable capture and discard any buffered bytes.
pub fn uninstall() {
    // SAFETY: see `state_mut`.
    let s = unsafe { state_mut() };
    s.installed = false;
    s.buffer.clear();
    s.buffer.shrink_to_fit();
}

/// Whether capture is currently active. Cheap read used by `format::log_post`.
#[must_use]
pub fn is_installed() -> bool {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.installed
}

/// Append `bytes` to the capture buffer.
///
/// Called by the formatter when capture is installed. Allocates only on first growth past
/// the previously-drained capacity.
pub fn append(bytes: &[u8]) {
    // SAFETY: see `state_mut`.
    let s = unsafe { state_mut() };
    if s.installed {
        s.buffer.extend_from_slice(bytes);
    }
}

/// Take the captured bytes and reset the buffer. Returns an empty `Vec` when capture is
/// not installed or has already been drained.
#[must_use]
pub fn drain() -> Vec<u8> {
    // SAFETY: see `state_mut`.
    let s = unsafe { state_mut() };
    core::mem::take(&mut s.buffer)
}

/// Whether the captured bytes contain `needle` as a UTF-8 substring. Returns `false` when
/// the captured bytes are not valid UTF-8 (the harness only ever feeds ASCII / UTF-8).
#[must_use]
pub fn contains(needle: &str) -> bool {
    // SAFETY: see `state_ref`.
    let s = unsafe { state_ref() };
    let Ok(captured) = core::str::from_utf8(&s.buffer) else {
        return false;
    };
    captured.contains(needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: TEST_LOCK serialises tests so no other reference is alive.
        let s = unsafe { state_mut() };
        *s = CaptureState::new();
        g
    }

    #[test]
    fn install_idempotent_clears_buffer() {
        let _g = fresh();
        install();
        append(b"first");
        install();
        let drained = drain();
        assert!(drained.is_empty());
    }

    #[test]
    fn append_only_when_installed() {
        let _g = fresh();
        append(b"ignored");
        assert!(drain().is_empty());

        install();
        append(b"hello");
        append(b" world");
        let drained = drain();
        assert_eq!(drained, b"hello world");
        // After drain the buffer is empty for the next assertion cycle.
        append(b"second");
        assert_eq!(drain(), b"second");
    }

    #[test]
    fn uninstall_clears_and_disables() {
        let _g = fresh();
        install();
        append(b"data");
        uninstall();
        assert!(!is_installed());
        append(b"more");
        assert!(drain().is_empty());
    }

    #[test]
    fn contains_finds_utf8_substrings() {
        let _g = fresh();
        install();
        append(b"P00   WARN: hello world\n");
        assert!(contains("WARN: hello"));
        assert!(!contains("ERROR"));
    }
}
