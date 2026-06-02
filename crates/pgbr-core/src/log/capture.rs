//! In-memory log capture sink used by the in-crate `#[cfg(test)] mod tests`
//! blocks across the workspace.
//!
//! When [`is_installed`] is true, [`super::format::log_post`] routes the file
//! sink (the `level_file` channel) to [`append`] instead of `write(2)`. Test
//! code reads the captured bytes via [`drain`] / [`contains`] and clears them
//! between assertions.
//!
//! # Threading
//!
//! Unlike the fork-per-process C original, the Rust port runs real threads: the
//! `cargo test` harness parallelises test functions, and the server /
//! parallel-dispatch paths spawn worker threads. Several of those threads emit
//! log lines, and the `installed` flag is process-global — so a test that
//! installs capture makes *every* concurrently-running thread route its file
//! sink through [`append`]. The previous implementation guarded the state with
//! an `unsafe impl Sync` over an `UnsafeCell` and a "single-threaded" comment;
//! that invariant does not hold here, and concurrent `append`s raced on the
//! buffer's `Vec` reallocation, intermittently aborting the process with
//! `free(): invalid next size`. The state is therefore guarded by a [`Mutex`].

use std::sync::{Mutex, MutexGuard, PoisonError};

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

/// Process-global capture buffer, serialised by a `Mutex` so concurrent
/// [`append`] calls from parallel threads cannot race on the inner `Vec`.
static STATE: Mutex<CaptureState> = Mutex::new(CaptureState::new());

/// Lock the capture state, tolerating a poisoned mutex.
///
/// A panicking test thread can poison the lock; the captured bytes are
/// diagnostic scratch, so recovering the guard (rather than propagating the
/// poison) keeps unrelated tests running — and never leaves the logger wedged.
fn lock() -> MutexGuard<'static, CaptureState> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Enable capture. Subsequent file-sink writes go to the capture buffer instead
/// of `fd_file`. Idempotent — calling twice clears the buffer the second time.
pub fn install() {
    let mut s = lock();
    s.installed = true;
    s.buffer.clear();
}

/// Disable capture and discard any buffered bytes.
pub fn uninstall() {
    let mut s = lock();
    s.installed = false;
    s.buffer.clear();
    s.buffer.shrink_to_fit();
}

/// Whether capture is currently active. Cheap read used by `format::log_post`.
#[must_use]
pub fn is_installed() -> bool {
    lock().installed
}

/// Append `bytes` to the capture buffer.
///
/// Called by the formatter when capture is installed. No-op when capture is not
/// installed.
pub fn append(bytes: &[u8]) {
    let mut s = lock();
    if s.installed {
        s.buffer.extend_from_slice(bytes);
    }
}

/// Take the captured bytes and reset the buffer. Returns an empty `Vec` when
/// capture is not installed or has already been drained.
#[must_use]
pub fn drain() -> Vec<u8> {
    core::mem::take(&mut lock().buffer)
}

/// Whether the captured bytes contain `needle` as a UTF-8 substring. Returns
/// `false` when the captured bytes are not valid UTF-8 (the harness only ever
/// feeds ASCII / UTF-8).
#[must_use]
pub fn contains(needle: &str) -> bool {
    let s = lock();
    core::str::from_utf8(&s.buffer).is_ok_and(|captured| captured.contains(needle))
}

/// Reset capture state to its default (installed = false, empty buffer). Called
/// by `log::test_support::fresh_state` so a previous `capture::tests::*` test
/// that left `installed = true` cannot route a later `log::format::tests::*`
/// file-sink write into the capture buffer instead of the temp-file fd.
#[cfg(test)]
pub(super) fn reset_state() {
    *lock() = CaptureState::new();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Acquire the workspace-wide log test lock (also used by `log::tests::*` and
    /// `log::format::tests::*`) and reset capture state. See `log::test_support`
    /// for why a single lock is required across this whole module.
    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let g = super::super::test_support::TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_state();
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

    /// Regression guard for the `free(): invalid next size` heap corruption:
    /// hammer `append` from many threads at once. Before the `Mutex`, the
    /// concurrent `Vec::extend_from_slice` calls raced on a reallocation and
    /// intermittently aborted the process; with the lock the run is sound and
    /// every byte is accounted for.
    ///
    /// Holds `TEST_LOCK` for the duration so it does not interleave with the
    /// other (serial) capture tests, then spawns its own worker threads — the
    /// concurrency under test is between those workers, which the capture
    /// `Mutex` (not `TEST_LOCK`) is responsible for making safe.
    #[test]
    fn concurrent_appends_do_not_corrupt_the_heap() {
        const THREADS: usize = 16;
        const PER_THREAD: usize = 4_000;

        let _g = fresh();
        install();

        // Each thread appends a fixed 8-byte record many times.
        let record = *b"abcdefgh";

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..PER_THREAD {
                        append(&record);
                    }
                });
            }
        });

        let captured = drain();
        // No bytes lost or duplicated, and the buffer is internally consistent.
        assert_eq!(captured.len(), THREADS * PER_THREAD * record.len());
        assert!(
            captured.chunks_exact(record.len()).all(|c| c == record),
            "every 8-byte record must be intact (no torn writes)"
        );
    }
}
