//! Logger state and line formatter for the C `logInit` / `logFileSet` / `logInternal`
//! machinery.
//!
//! Owns every file-scope variable the legacy `src/common/log.c` used to keep, plus the
//! prefix / message / dispatch helpers that build a complete log line and `write(2)` it
//! to the right fd.
//!
//! Specifically: the four log levels (stdout / stderr / file / any), the three file
//! descriptors (stdout / stderr / file), the banner / timestamp / dry-run flags, the
//! process metadata, and the 32 KiB `logBuffer` scratchpad. Sub-issue A migrated only
//! the state. Sub-issue B (this revision) hoists the formatter itself — header
//! composition, message append, multi-fd dispatch, banner emission, multi-line indent
//! — into the [`format`] submodule. Sub-issue C will replace the harness shim with an
//! FFI capture buffer.
//!
//! Threading model mirrors `stack_trace` and `mem_context`: pgBackRust forks for
//! parallelism, so each child process keeps its own copy of this state and a single
//! thread serialises access. The `UnsafeGlobal` wrapper makes the state `Sync` for
//! the static slot without paying for a runtime lock.

pub mod format;

use core::ffi::{CStr, c_char};
use std::cell::UnsafeCell;
use std::sync::OnceLock;

/// Documented production size of a single log message including its header.
///
/// Mirrors the `LOG_BUFFER_SIZE` macro defined in `src/common/log.h` (32 KiB). Public so
/// callers outside the crate can size their own scratch on the same boundary.
pub const LOG_BUFFER_SIZE: usize = 32 * 1024;

/// Actual size of the heap-allocated scratch buffer.
///
/// `test/src/meson.build` compiles the unit-test binary with `-DLOG_BUFFER_SIZE=262144`
/// (256 KiB) so very long error messages don't get truncated mid-test. The Rust side
/// can't see that compile-time override, so the heap buffer is permanently sized to the
/// larger value to satisfy both builds. The extra 224 KiB is per-process and one-shot.
///
/// The trailing 4 KiB padding absorbs glibc's SIMD-vectorised `strncpy` / `memset`
/// over-writes: those routines may scribble up to a full vector beyond the logical end
/// of the buffer before checking the bound. The legacy `static char logBuffer[]` array
/// in `.bss` had adjacent static data soaking up the over-write; the Rust `Box<[u8]>`
/// can sit at the end of an mmap region with an unmapped guard page right after it.
const LOG_BUFFER_ALLOC: usize = 256 * 1024 + 4096;

/// Numeric values of the C `LogLevel` enum from `src/common/logLevel.h`.
///
/// Carried as plain `i32` across the FFI surface to match the C `int`-sized enum and
/// avoid `#[repr(C)]` enum subtleties on platforms where `enum` is not 32-bit.
pub const LOG_LEVEL_OFF: i32 = 0;
pub const LOG_LEVEL_ASSERT: i32 = 1;
pub const LOG_LEVEL_ERROR: i32 = 2;
pub const LOG_LEVEL_WARN: i32 = 3;
pub const LOG_LEVEL_INFO: i32 = 4;
pub const LOG_LEVEL_DETAIL: i32 = 5;
pub const LOG_LEVEL_DEBUG: i32 = 6;
pub const LOG_LEVEL_TRACE: i32 = 7;

/// `LOG_LEVEL_MIN` from `logLevel.h` (the lowest non-OFF level).
pub const LOG_LEVEL_MIN: i32 = LOG_LEVEL_ASSERT;
/// `LOG_LEVEL_MAX` from `logLevel.h` (the highest level).
pub const LOG_LEVEL_MAX: i32 = LOG_LEVEL_TRACE;

/// String table mirroring `logLevelList[LOG_LEVEL_TOTAL]` in `src/common/log.c`.
const LOG_LEVEL_NAMES: [&CStr; 8] = [c"OFF", c"ASSERT", c"ERROR", c"WARN", c"INFO", c"DETAIL", c"DEBUG", c"TRACE"];

/// File descriptors for the standard streams. Match `<unistd.h>` POSIX values; the C side
/// uses `STDOUT_FILENO` / `STDERR_FILENO` directly.
const STDOUT_FILENO: i32 = 1;
const STDERR_FILENO: i32 = 2;

/// Process-global log state. Defaults match the C statics in `src/common/log.c:25-48`.
pub struct LogState {
    pub level_std_out: i32,
    pub level_std_err: i32,
    pub level_file: i32,
    pub level_any: i32,
    pub fd_std_out: i32,
    pub fd_std_err: i32,
    pub fd_file: i32,
    pub file_banner: bool,
    pub timestamp: bool,
    pub process_id: u32,
    pub process_size: i32,
    pub dry_run: bool,
    /// 32 KiB scratchpad used by `logPre` / `logPost` / `logInternal*` to format a single
    /// log line. The C formatter still owns the writes; we just lend it the buffer.
    /// Heap-allocated so the static foot-print stays bounded — putting the array directly in
    /// a `static` would push the binary's bss up by 32 KiB even when logging is disabled.
    pub buffer: Box<[u8]>,
}

impl LogState {
    fn new() -> Self {
        Self {
            level_std_out: LOG_LEVEL_ERROR,
            level_std_err: LOG_LEVEL_ERROR,
            level_file: LOG_LEVEL_OFF,
            level_any: LOG_LEVEL_ERROR,
            fd_std_out: STDOUT_FILENO,
            fd_std_err: STDERR_FILENO,
            fd_file: -1,
            file_banner: false,
            timestamp: false,
            process_id: 0,
            process_size: 2,
            dry_run: false,
            buffer: vec![0u8; LOG_BUFFER_ALLOC].into_boxed_slice(),
        }
    }
}

#[allow(clippy::non_send_fields_in_send_ty)]
struct UnsafeGlobal<T>(UnsafeCell<T>);
// SAFETY: pgBackRust forks for parallelism rather than threading; logging happens from a
// single thread per process. The legacy C code already relies on this invariant.
unsafe impl<T> Sync for UnsafeGlobal<T> {}
unsafe impl<T> Send for UnsafeGlobal<T> {}

static STATE: OnceLock<UnsafeGlobal<LogState>> = OnceLock::new();

fn cell() -> &'static UnsafeCell<LogState> {
    &STATE.get_or_init(|| UnsafeGlobal(UnsafeCell::new(LogState::new()))).0
}

/// # Safety
///
/// Caller must ensure no other reference to the state is alive at the same time.
#[allow(clippy::mut_from_ref)]
unsafe fn state_mut() -> &'static mut LogState {
    // SAFETY: caller upholds the no-aliasing invariant.
    unsafe { &mut *cell().get() }
}

/// # Safety
///
/// Same single-threaded contract as [`state_mut`].
unsafe fn state_ref() -> &'static LogState {
    // SAFETY: caller upholds the no-aliasing invariant.
    unsafe { &*cell().get() }
}

/// In-place promotion of `level_any` to the loudest of the three output sinks. The file
/// level only counts when the file descriptor is actually open (matches `logAnySet` in
/// `src/common/log.c:108-122`).
const fn any_set_in(state: &mut LogState) {
    let mut promoted = state.level_std_out;

    if state.level_std_err > promoted {
        promoted = state.level_std_err;
    }

    if state.level_file > promoted && state.fd_file != -1 {
        promoted = state.level_file;
    }

    state.level_any = promoted;
}

/// Promote `level_any` to the loudest of the three open output sinks.
pub fn any_set() {
    // SAFETY: see `state_mut`.
    any_set_in(unsafe { state_mut() });
}

/// `logAny` — returns true if a message at `level` would be emitted to at least one sink.
#[must_use]
pub fn any(level: i32) -> bool {
    debug_assert!((LOG_LEVEL_MIN..=LOG_LEVEL_MAX).contains(&level), "log level out of range");
    // SAFETY: see `state_ref`.
    level <= unsafe { state_ref() }.level_any
}

/// `logInit` body. Sets the levels, timestamp flag, process id / size, and dry-run flag,
/// then promotes `level_any`.
///
/// Asserts mirror the C side: levels must be `<= LOG_LEVEL_MAX`, ids must be `<= 999`.
pub fn init(
    level_std_out: i32,
    level_std_err: i32,
    level_file: i32,
    timestamp: bool,
    process_id: u32,
    process_max: u32,
    dry_run: bool,
) {
    debug_assert!(level_std_out <= LOG_LEVEL_MAX, "level_std_out out of range");
    debug_assert!(level_std_err <= LOG_LEVEL_MAX, "level_std_err out of range");
    debug_assert!(level_file <= LOG_LEVEL_MAX, "level_file out of range");
    debug_assert!(process_id <= 999, "process_id out of range");
    debug_assert!(process_max <= 999, "process_max out of range");

    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    state.level_std_out = level_std_out;
    state.level_std_err = level_std_err;
    state.level_file = level_file;
    state.timestamp = timestamp;
    state.process_id = process_id;
    state.process_size = if process_max > 99 { 3 } else { 2 };
    state.dry_run = dry_run;

    any_set_in(state);
}

/// State-side companion to the C `logClose`.
///
/// Resets every level to OFF so subsequent `logAny` calls return false. The actual
/// `close(fd)` syscall stays on the C side because POSIX I/O is the C build's
/// responsibility.
pub fn close() {
    init(LOG_LEVEL_OFF, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 1, false);
}

/// `logLevelEnum(seq)` — converts a stringId sequence number into a `LogLevel`. The C
/// side asserts `seq < LOG_LEVEL_MAX`; the Rust side keeps the same assert.
///
/// The C body skips the `OFF` slot when `seq > 0`: sequence 0 → OFF, sequence 1 →
/// ERROR (skipping ASSERT, which has no stringId), sequence 2 → WARN, etc.
#[must_use]
#[allow(clippy::cast_possible_wrap)]
pub fn level_enum(seq: u32) -> i32 {
    debug_assert!(seq < LOG_LEVEL_MAX as u32, "level_enum seq out of range");
    let mut value = seq;
    if seq > 0 {
        value += 1;
    }
    // value is bounded by LOG_LEVEL_MAX (= 7) so the cast cannot wrap.
    value as i32
}

/// `logLevelStr(level)` — returns the static `CStr` for `level`. Caller must ensure
/// `level <= LOG_LEVEL_MAX`; out-of-range values trigger the same assert as the C side.
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub fn level_str(level: i32) -> &'static CStr {
    debug_assert!((0..=LOG_LEVEL_MAX).contains(&level), "level_str level out of range");
    // Bounded by the assert above to be in [0, LOG_LEVEL_MAX].
    LOG_LEVEL_NAMES[level as usize]
}

// -----------------------------------------------------------------------------
// Field accessors
//
// One getter / setter per state field. The C-side formatter still reads the state at
// the start of each `logPre` / `logPost` call via these helpers, and the test harness
// uses the setters to redirect file descriptors.
// -----------------------------------------------------------------------------

#[must_use]
pub fn level_std_out() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.level_std_out
}

pub fn set_level_std_out(value: i32) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.level_std_out = value;
}

#[must_use]
pub fn level_std_err() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.level_std_err
}

pub fn set_level_std_err(value: i32) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.level_std_err = value;
}

#[must_use]
pub fn level_file() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.level_file
}

pub fn set_level_file(value: i32) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.level_file = value;
}

#[must_use]
pub fn level_any() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.level_any
}

#[must_use]
pub fn fd_std_out() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.fd_std_out
}

pub fn set_fd_std_out(value: i32) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.fd_std_out = value;
}

#[must_use]
pub fn fd_std_err() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.fd_std_err
}

pub fn set_fd_std_err(value: i32) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.fd_std_err = value;
}

#[must_use]
pub fn fd_file() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.fd_file
}

pub fn set_fd_file(value: i32) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.fd_file = value;
}

#[must_use]
pub fn file_banner() -> bool {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.file_banner
}

pub fn set_file_banner(value: bool) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.file_banner = value;
}

#[must_use]
pub fn timestamp() -> bool {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.timestamp
}

pub fn set_timestamp(value: bool) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.timestamp = value;
}

#[must_use]
pub fn process_id() -> u32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.process_id
}

pub fn set_process_id(value: u32) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.process_id = value;
}

#[must_use]
pub fn process_size() -> i32 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.process_size
}

#[must_use]
pub fn dry_run() -> bool {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.dry_run
}

pub fn set_dry_run(value: bool) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.dry_run = value;
}

/// Mutable pointer to the 32 KiB log buffer.
///
/// The C-side formatter writes header + message into this buffer and then `write(2)`s
/// the result to the appropriate fd. The buffer is process-global; concurrent writes
/// are unsound — same single-threaded invariant as the rest of the state.
#[must_use]
pub fn buffer_ptr() -> *mut c_char {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.buffer.as_mut_ptr().cast::<c_char>()
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Lock and `fresh_state` helper shared between this module's tests and
    //! `log::format`'s tests.
    //!
    //! Both test sets touch the same process-global `LogState`. A single lock here
    //! serialises them; if each module defined its own lock, parallel `cargo test`
    //! could interleave a `log::tests::*` write with a `log::format::tests::*` read.
    use std::sync::Mutex;

    pub static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire `TEST_LOCK`, reset `STATE` to a fresh `LogState`, and hand back the
    /// guard so the caller's test run holds the lock for its lifetime.
    pub fn fresh_state() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: TEST_LOCK serialises tests so no other reference is alive.
        let state = unsafe { super::state_mut() };
        *state = super::LogState::new();
        guard
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::test_support::fresh_state;
    use super::*;

    #[test]
    fn defaults_match_c_initialisers() {
        let _guard = fresh_state();
        assert_eq!(level_std_out(), LOG_LEVEL_ERROR);
        assert_eq!(level_std_err(), LOG_LEVEL_ERROR);
        assert_eq!(level_file(), LOG_LEVEL_OFF);
        assert_eq!(level_any(), LOG_LEVEL_ERROR);
        assert_eq!(fd_std_out(), STDOUT_FILENO);
        assert_eq!(fd_std_err(), STDERR_FILENO);
        assert_eq!(fd_file(), -1);
        assert!(!file_banner());
        assert!(!timestamp());
        assert_eq!(process_id(), 0);
        assert_eq!(process_size(), 2);
        assert!(!dry_run());
    }

    #[test]
    fn init_sets_all_fields_and_promotes_any() {
        let _guard = fresh_state();
        init(LOG_LEVEL_INFO, LOG_LEVEL_WARN, LOG_LEVEL_ERROR, true, 7, 99, true);
        assert_eq!(level_std_out(), LOG_LEVEL_INFO);
        assert_eq!(level_std_err(), LOG_LEVEL_WARN);
        assert_eq!(level_file(), LOG_LEVEL_ERROR);
        assert!(timestamp());
        assert_eq!(process_id(), 7);
        assert_eq!(process_size(), 2);
        assert!(dry_run());
        // logLevelFile is louder but fd_file is still -1, so it does not count.
        assert_eq!(level_any(), LOG_LEVEL_INFO);
    }

    #[test]
    fn init_process_size_widens_above_99() {
        let _guard = fresh_state();
        init(LOG_LEVEL_INFO, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 100, false);
        assert_eq!(process_size(), 3);
    }

    #[test]
    fn close_resets_to_off() {
        let _guard = fresh_state();
        init(LOG_LEVEL_INFO, LOG_LEVEL_INFO, LOG_LEVEL_INFO, true, 5, 99, true);
        close();
        assert_eq!(level_std_out(), LOG_LEVEL_OFF);
        assert_eq!(level_std_err(), LOG_LEVEL_OFF);
        assert_eq!(level_file(), LOG_LEVEL_OFF);
        assert_eq!(level_any(), LOG_LEVEL_OFF);
        assert!(!timestamp());
        assert_eq!(process_id(), 0);
        assert!(!dry_run());
    }

    #[test]
    fn any_set_promotes_to_loudest_of_open_sinks() {
        let _guard = fresh_state();
        set_level_std_out(LOG_LEVEL_OFF);
        set_level_std_err(LOG_LEVEL_OFF);
        set_level_file(LOG_LEVEL_OFF);
        set_fd_file(-1);
        any_set();
        assert!(!any(LOG_LEVEL_ERROR));

        set_level_std_err(LOG_LEVEL_ERROR);
        any_set();
        assert!(any(LOG_LEVEL_ERROR));

        set_level_file(LOG_LEVEL_WARN);
        any_set();
        // file is louder but fd_file is still -1 -- WARN must not promote.
        assert!(!any(LOG_LEVEL_WARN));

        set_fd_file(1);
        any_set();
        assert!(any(LOG_LEVEL_WARN));
    }

    #[test]
    fn level_enum_skips_assert_slot_for_nonzero_seq() {
        // seq 0 -> OFF (= 0). seq 1 -> ERROR (= 2). seq 2 -> WARN (= 3). ... seq 6 -> TRACE.
        assert_eq!(level_enum(0), LOG_LEVEL_OFF);
        assert_eq!(level_enum(1), LOG_LEVEL_ERROR);
        assert_eq!(level_enum(2), LOG_LEVEL_WARN);
        assert_eq!(level_enum(3), LOG_LEVEL_INFO);
        assert_eq!(level_enum(4), LOG_LEVEL_DETAIL);
        assert_eq!(level_enum(5), LOG_LEVEL_DEBUG);
        assert_eq!(level_enum(6), LOG_LEVEL_TRACE);
    }

    #[test]
    fn level_str_round_trips_each_level() {
        assert_eq!(level_str(LOG_LEVEL_OFF).to_str().unwrap(), "OFF");
        assert_eq!(level_str(LOG_LEVEL_ASSERT).to_str().unwrap(), "ASSERT");
        assert_eq!(level_str(LOG_LEVEL_ERROR).to_str().unwrap(), "ERROR");
        assert_eq!(level_str(LOG_LEVEL_WARN).to_str().unwrap(), "WARN");
        assert_eq!(level_str(LOG_LEVEL_INFO).to_str().unwrap(), "INFO");
        assert_eq!(level_str(LOG_LEVEL_DETAIL).to_str().unwrap(), "DETAIL");
        assert_eq!(level_str(LOG_LEVEL_DEBUG).to_str().unwrap(), "DEBUG");
        assert_eq!(level_str(LOG_LEVEL_TRACE).to_str().unwrap(), "TRACE");
    }

    #[test]
    fn buffer_ptr_is_writable_and_persists_across_calls() {
        let _guard = fresh_state();
        let p = buffer_ptr().cast::<u8>();
        // SAFETY: buffer is exactly LOG_BUFFER_SIZE bytes, single-threaded test.
        unsafe {
            *p = b'A';
            *p.add(1) = b'B';
            *p.add(2) = 0;
        }
        let q = buffer_ptr().cast::<u8>();
        assert_eq!(p, q);
        // SAFETY: q points to the same buffer we just wrote into.
        unsafe {
            assert_eq!(*q, b'A');
            assert_eq!(*q.add(1), b'B');
        }
    }

    #[test]
    fn fd_setters_round_trip() {
        let _guard = fresh_state();
        set_fd_std_out(42);
        set_fd_std_err(43);
        set_fd_file(44);
        assert_eq!(fd_std_out(), 42);
        assert_eq!(fd_std_err(), 43);
        assert_eq!(fd_file(), 44);
    }

    #[test]
    fn flag_setters_round_trip() {
        let _guard = fresh_state();
        set_file_banner(true);
        set_timestamp(true);
        set_dry_run(true);
        assert!(file_banner());
        assert!(timestamp());
        assert!(dry_run());
    }

    #[test]
    fn process_id_setter_round_trips() {
        let _guard = fresh_state();
        set_process_id(123);
        assert_eq!(process_id(), 123);
    }
}
