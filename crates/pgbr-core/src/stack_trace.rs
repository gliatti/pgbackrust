//! Function call-stack accumulator shared with the C `STACK_TRACE_PUSH` /
//! `STACK_TRACE_POP` machinery and the parameter-logging helpers.
//!
//! The state is process-global (matching the legacy `static struct stackTraceLocal` in
//! `src/common/stackTrace.c`) and not safe for concurrent access — pgBackRust forks for
//! parallelism, so each child process has its own copy of this state.
//!
//! The libbacktrace integration stays on the C side: `backtrace_full` calls back into a
//! C function that reads frames here through the FFI getters
//! ([`frame_at`], [`stack_size`]). The harness flips a `force_no_backtrace` flag the C
//! side checks before calling `backtrace_full`.

use core::ffi::c_char;
use std::cell::UnsafeCell;
use std::ffi::CStr;
use std::sync::OnceLock;

/// Maximum call-stack depth tracked. Mirrors `STACK_TRACE_MAX` in
/// `src/common/stackTrace.c`. The C side asserts on overflow rather than silently
/// dropping frames; we do the same.
pub const STACK_TRACE_MAX: usize = 128;

/// Maximum size of a single parameter (including the trailing NUL). Mirrors
/// `STACK_TRACE_PARAM_MAX` in `src/common/stackTrace.h`.
pub const STACK_TRACE_PARAM_MAX: usize = 4096;

/// Total bytes available for parameter storage, shared across all stack frames.
pub const PARAM_BUFFER_SIZE: usize = 32 * 1024;

/// One entry in the stack-trace accumulator.
///
/// The string fields hold borrowed C pointers (`__FILE__` / `__func__` static literals),
/// so the struct itself is `Copy` and the C side keeps ownership of the underlying
/// bytes.
#[derive(Clone, Copy)]
pub struct StackFrame {
    pub file_name: *const c_char,
    pub function_name: *const c_char,
    pub file_line: u32,
    /// Log level from the C `LogLevel` enum, carried as a plain `i32` so the FFI surface
    /// stays flat.
    pub function_log_level: i32,
    pub try_depth: u32,
    pub param_overflow: bool,
    pub param_log: bool,
    /// Byte offset into the parameter buffer where this frame's scratch starts. The
    /// legacy C struct stores a raw pointer (`char *param`); we keep an offset so the
    /// FFI surface does not have to expose interior pointers.
    pub param_offset: usize,
    /// Number of payload bytes already written to this frame's scratch (does not
    /// include the trailing NUL byte).
    pub param_size: usize,
}

impl StackFrame {
    const fn zeroed() -> Self {
        Self {
            file_name: core::ptr::null(),
            function_name: core::ptr::null(),
            file_line: 0,
            function_log_level: 0,
            try_depth: 0,
            param_overflow: false,
            param_log: false,
            param_offset: 0,
            param_size: 0,
        }
    }
}

/// Process-global accumulator state.
///
/// `param_buffer` is heap-allocated to keep the static foot-print bounded — putting the
/// 32 KiB array directly in a `static` would push the binary's bss up by 32 KiB even
/// when stack tracing is disabled.
pub struct StackTraceLocal {
    pub stack_size: usize,
    pub stack: [StackFrame; STACK_TRACE_MAX],
    pub param_buffer: Box<[u8]>,
    pub test_flag: bool,
    pub force_no_backtrace: bool,
}

impl StackTraceLocal {
    fn new() -> Self {
        Self {
            stack_size: 0,
            stack: [StackFrame::zeroed(); STACK_TRACE_MAX],
            param_buffer: vec![0u8; PARAM_BUFFER_SIZE].into_boxed_slice(),
            // Matches the C initialiser `stackTraceTestLocal = {.testFlag = true}`.
            test_flag: true,
            force_no_backtrace: false,
        }
    }
}

#[allow(clippy::non_send_fields_in_send_ty)]
struct UnsafeGlobal<T>(UnsafeCell<T>);
// SAFETY: pgBackRust forks for parallelism rather than threading; logging happens from a
// single thread per process. The legacy C code already relies on this invariant.
unsafe impl<T> Sync for UnsafeGlobal<T> {}
unsafe impl<T> Send for UnsafeGlobal<T> {}

static STATE: OnceLock<UnsafeGlobal<StackTraceLocal>> = OnceLock::new();

fn cell() -> &'static UnsafeCell<StackTraceLocal> {
    &STATE.get_or_init(|| UnsafeGlobal(UnsafeCell::new(StackTraceLocal::new()))).0
}

/// # Safety
///
/// Caller must ensure no other reference to the state is alive at the same time.
#[allow(clippy::mut_from_ref)]
unsafe fn state_mut() -> &'static mut StackTraceLocal {
    // SAFETY: caller upholds the no-aliasing invariant.
    unsafe { &mut *cell().get() }
}

/// # Safety
///
/// Same single-threaded contract as [`state_mut`].
unsafe fn state_ref() -> &'static StackTraceLocal {
    // SAFETY: caller upholds the no-aliasing invariant.
    unsafe { &*cell().get() }
}

/// Push a new frame; returns the effective log level for the new top of stack.
///
/// The legacy C raises the new frame's log level to the parent's whenever the caller
/// asks for a quieter level than its parent — that way a noisy `logLevelTrace` caller
/// is never silenced just because the new frame requested `logLevelDebug`.
#[must_use]
pub fn push(file_name: *const c_char, function_name: *const c_char, function_log_level: i32, try_depth: u32) -> i32 {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };

    assert!(state.stack_size < STACK_TRACE_MAX - 1, "stack trace overflow");

    let mut new_frame = StackFrame {
        file_name,
        function_name,
        file_line: 0,
        function_log_level,
        try_depth,
        param_overflow: false,
        param_log: false,
        param_offset: 0,
        param_size: 0,
    };

    if state.stack_size == 0 {
        new_frame.param_offset = 0;
    } else {
        let prior = state.stack[state.stack_size - 1];
        new_frame.param_offset = prior.param_offset + prior.param_size + 1;
        if function_log_level < prior.function_log_level {
            new_frame.function_log_level = prior.function_log_level;
        }
    }

    state.stack[state.stack_size] = new_frame;
    state.stack_size += 1;

    new_frame.function_log_level
}

/// DEBUG-build pop. `test == false` always pops; `test == true` defers to the harness
/// `test_flag` so the `FUNCTION_TEST_RETURN` family of macros can early-out.
///
/// On mismatch returns `Err(actual_top_frame)` so the C shim can format the diagnostic
/// `AssertError` message.
///
/// # Safety
///
/// Caller must ensure `expected_file_name` and `expected_function_name` are valid
/// NUL-terminated C strings.
pub unsafe fn pop_debug(
    expected_file_name: *const c_char,
    expected_function_name: *const c_char,
    test: bool,
) -> Result<(), StackFrame> {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };

    assert!(state.stack_size > 0, "stack trace underflow");

    if test && !state.test_flag {
        return Ok(());
    }

    state.stack_size -= 1;
    let actual = state.stack[state.stack_size];

    // SAFETY: caller asserts pointers are NUL-terminated readable C strings; the stack
    // frame's stored pointers came from earlier C call sites and live for the process.
    let actual_file = unsafe { CStr::from_ptr(actual.file_name) };
    let actual_func = unsafe { CStr::from_ptr(actual.function_name) };
    let expected_file = unsafe { CStr::from_ptr(expected_file_name) };
    let expected_func = unsafe { CStr::from_ptr(expected_function_name) };

    if actual_file != expected_file || actual_func != expected_func {
        return Err(actual);
    }

    Ok(())
}

/// Non-DEBUG-build pop. Just decrements the stack size.
pub fn pop_release() {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(state.stack_size > 0, "stack trace underflow");
    state.stack_size -= 1;
}

/// Mark the top frame's `param_log` flag.
pub fn param_log() {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(state.stack_size > 0, "stack trace empty");
    state.stack[state.stack_size - 1].param_log = true;
}

/// Reserve a slot in the parameter buffer for the next argument and return a raw
/// pointer the C side formats into via `FUNCTION_LOG_<TYPE>_FORMAT`.
///
/// On overflow returns a pointer into the reserved tail of the buffer (so the C call
/// site can finish its `vsnprintf` without trampling other frames) and sets the
/// frame's `param_overflow` flag — exactly matching the C semantics.
///
/// # Safety
///
/// `name_ptr` must be a valid NUL-terminated C string.
#[must_use]
pub unsafe fn param_buffer(name_ptr: *const c_char) -> *mut c_char {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(state.stack_size > 0, "stack trace empty");

    // SAFETY: caller asserts `name_ptr` is NUL-terminated and readable.
    let name_cstr = unsafe { CStr::from_ptr(name_ptr) };
    let name_bytes = name_cstr.to_bytes();
    let name_size = name_bytes.len();

    let frame_idx = state.stack_size - 1;
    let frame = state.stack[frame_idx];

    let used = frame.param_offset + frame.param_size + name_size + 4;

    if used > PARAM_BUFFER_SIZE.saturating_sub(STACK_TRACE_PARAM_MAX * 2) {
        state.stack[frame_idx].param_overflow = true;
        let fallback_offset = PARAM_BUFFER_SIZE - STACK_TRACE_PARAM_MAX;
        // SAFETY: `fallback_offset < PARAM_BUFFER_SIZE`.
        return unsafe { state.param_buffer.as_mut_ptr().add(fallback_offset).cast::<c_char>() };
    }

    let mut size = frame.param_size;
    if size != 0 {
        state.param_buffer[frame.param_offset + size] = b',';
        state.param_buffer[frame.param_offset + size + 1] = b' ';
        size += 2;
    }

    state.param_buffer[frame.param_offset + size..frame.param_offset + size + name_size].copy_from_slice(name_bytes);
    size += name_size;
    state.param_buffer[frame.param_offset + size] = b':';
    state.param_buffer[frame.param_offset + size + 1] = b' ';
    size += 2;

    state.stack[frame_idx].param_size = size;

    // SAFETY: `frame.param_offset + size` is within bounds by the headroom check above.
    unsafe {
        state
            .param_buffer
            .as_mut_ptr()
            .add(frame.param_offset + size)
            .cast::<c_char>()
    }
}

/// Bump the top frame's `param_size` by `size` bytes. No-op on overflowed frames.
pub fn param_add(size: usize) {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(state.stack_size > 0, "stack trace empty");
    let idx = state.stack_size - 1;
    if !state.stack[idx].param_overflow {
        state.stack[idx].param_size += size;
    }
}

/// Drop frames whose `try_depth >= try_depth_floor`. Called by the error machinery on
/// throw to unwind the stack alongside the C `TRY` jump buffer.
pub fn clean(try_depth_floor: u32) {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    while state.stack_size > 0 && state.stack[state.stack_size - 1].try_depth >= try_depth_floor {
        state.stack_size -= 1;
    }
}

/// `stackTraceTestStart`.
pub fn test_start() {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.test_flag = true;
}

/// `stackTraceTestStop`.
pub fn test_stop() {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.test_flag = false;
}

/// `stackTraceTest`.
#[must_use]
pub fn test_flag() -> bool {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.test_flag
}

/// `stackTraceTestFileLineSet`.
pub fn test_file_line_set(file_line: u32) {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(state.stack_size > 0, "stack trace empty");
    state.stack[state.stack_size - 1].file_line = file_line;
}

/// Force the libbacktrace path to be skipped.
pub fn force_no_backtrace_set(value: bool) {
    // SAFETY: see `state_mut`.
    unsafe { state_mut() }.force_no_backtrace = value;
}

/// Read the libbacktrace force flag.
#[must_use]
pub fn force_no_backtrace_get() -> bool {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.force_no_backtrace
}

/// Number of frames currently on the stack.
#[must_use]
pub fn stack_size() -> usize {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.stack_size
}

/// Read-only access to a single frame.
#[must_use]
pub fn frame_at(idx: usize) -> Option<StackFrame> {
    // SAFETY: see `state_ref`.
    let state = unsafe { state_ref() };
    if idx >= state.stack_size {
        return None;
    }
    Some(state.stack[idx])
}

/// Test-only: bump `stack_size` by 1 without writing a new frame. Used by the
/// `stackTraceTestFileLineSet` test in `stackTraceTest.c` which manually advances the
/// cursor before calling the setter.
pub fn test_size_inc() {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(state.stack_size < STACK_TRACE_MAX - 1, "stack trace overflow");
    state.stack_size += 1;
}

/// Test-only: decrement `stack_size` by 1.
pub fn test_size_dec() {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(state.stack_size > 0, "stack trace underflow");
    state.stack_size -= 1;
}

/// Test-only: write a frame field.
///
/// `field` is `0` for `file_line`, `1` for `function_log_level`, `2` for `param_size`,
/// `3` for `param_offset`. Unknown discriminants are ignored — the C side asserts at
/// the call site that it picked a supported field.
#[allow(clippy::cast_possible_truncation)]
pub fn test_set_frame_field(idx: usize, field: i32, value: u64) {
    // SAFETY: see `state_mut`.
    let state = unsafe { state_mut() };
    assert!(idx < state.stack_size, "frame index out of range");
    let frame = &mut state.stack[idx];
    match field {
        0 => frame.file_line = value as u32,
        1 => frame.function_log_level = value as i32,
        2 => frame.param_size = value as usize,
        3 => frame.param_offset = value as usize,
        _ => {} // Unknown — caller picked a bad discriminant; silently ignore.
    }
}

/// Test-only: read the parameter buffer pointer and size, allowing the test to compute
/// offsets the same way the legacy code did with `&stackTraceLocal.functionParamBuffer[0]`.
#[must_use]
pub fn param_buffer_ptr() -> *const u8 {
    // SAFETY: see `state_ref`.
    unsafe { state_ref() }.param_buffer.as_ptr()
}

/// Renders the parameter string for `stack_idx`.
///
/// Mirrors `stackTraceParamIdx` in the legacy code — branches between `"buffer full"`
/// / `"void"` / the actual buffer slice / `"trace|debug log level required for
/// parameters"` based on the frame's flags.
#[must_use]
pub fn param_idx(stack_idx: usize) -> ParamIdx {
    // SAFETY: see `state_ref`.
    let state = unsafe { state_ref() };
    assert!(stack_idx < state.stack_size, "param_idx out of range");

    let frame = state.stack[stack_idx];

    if frame.param_log {
        if frame.param_overflow {
            return ParamIdx::Static(c"buffer full - parameters not available");
        }
        if frame.param_size == 0 {
            return ParamIdx::Static(c"void");
        }
        return ParamIdx::Buffer {
            offset: frame.param_offset,
        };
    }

    if frame.function_log_level == LOG_LEVEL_TRACE {
        ParamIdx::Static(c"trace log level required for parameters")
    } else {
        ParamIdx::Static(c"debug log level required for parameters")
    }
}

/// Numeric value of the C `logLevelTrace` enum. The C definition (in
/// `src/common/logLevel.h`) is the last element in a 0-based enum: off=0, assert=1,
/// error=2, warn=3, info=4, detail=5, debug=6, trace=7.
const LOG_LEVEL_TRACE: i32 = 7;

/// Result of [`param_idx`].
pub enum ParamIdx {
    /// A statically allocated NUL-terminated message.
    Static(&'static CStr),
    /// A slice of the parameter buffer, identified by its offset. The slice is
    /// NUL-terminated by the cat helpers.
    Buffer { offset: usize },
}

/// Trim a leading path prefix that ends just before `src/`. Mirrors `stackTraceTrimSrc`
/// in the legacy C.
#[must_use]
pub fn trim_src(file_name: &str) -> &str {
    file_name.find("src/").map_or(file_name, |idx| &file_name[idx + 4..])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests share `STATE`. Serialise so a parallel test runner does not interleave.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cstr(s: &str) -> Box<core::ffi::CStr> {
        std::ffi::CString::new(s).unwrap().into_boxed_c_str()
    }

    fn fresh_state() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: TEST_LOCK serialises tests so no other reference is alive.
        let state = unsafe { state_mut() };
        state.stack_size = 0;
        state.test_flag = true;
        state.force_no_backtrace = false;
        guard
    }

    #[test]
    fn push_records_metadata_and_returns_promoted_log_level() {
        let _guard = fresh_state();
        let file = cstr("a.c");
        let func = cstr("a_func");
        let lvl = push(file.as_ptr(), func.as_ptr(), 5, 0);
        assert_eq!(lvl, 5);
        assert_eq!(stack_size(), 1);
    }

    #[test]
    fn push_promotes_log_level_to_max_of_self_and_parent() {
        let _guard = fresh_state();
        let file = cstr("a.c");
        let func = cstr("a");
        let _ = push(file.as_ptr(), func.as_ptr(), 7, 0);
        let _ = push(file.as_ptr(), func.as_ptr(), 5, 0);
        assert_eq!(frame_at(1).unwrap().function_log_level, 7);
    }

    #[test]
    fn clean_drops_frames_at_or_above_try_depth() {
        let _guard = fresh_state();
        let file = cstr("a.c");
        let func = cstr("a");
        let _ = push(file.as_ptr(), func.as_ptr(), 5, 0);
        let _ = push(file.as_ptr(), func.as_ptr(), 5, 2);
        let _ = push(file.as_ptr(), func.as_ptr(), 5, 3);
        clean(2);
        assert_eq!(stack_size(), 1);
    }

    #[test]
    fn test_flag_round_trips() {
        let _guard = fresh_state();
        assert!(test_flag());
        test_stop();
        assert!(!test_flag());
        test_start();
        assert!(test_flag());
    }

    #[test]
    fn param_buffer_appends_with_separators() {
        let _guard = fresh_state();
        let file = cstr("a.c");
        let func = cstr("a");
        let _ = push(file.as_ptr(), func.as_ptr(), 5, 0);
        let name = cstr("alpha");
        // SAFETY: name is a valid NUL-terminated CString.
        let _ = unsafe { param_buffer(name.as_ptr()) };
        // The frame holds "alpha: " (7 bytes) — the C side fills the value next.
        assert_eq!(frame_at(0).unwrap().param_size, 7);
    }

    #[test]
    fn param_idx_branches_track_log_flag_and_overflow() {
        let _guard = fresh_state();
        let file = cstr("a.c");
        let func = cstr("a");
        let _ = push(file.as_ptr(), func.as_ptr(), 6, 0); // logLevelDebug = 6

        if let ParamIdx::Static(s) = param_idx(0) {
            assert_eq!(s.to_str().unwrap(), "debug log level required for parameters");
        } else {
            panic!("expected static");
        }

        param_log();
        if let ParamIdx::Static(s) = param_idx(0) {
            assert_eq!(s.to_str().unwrap(), "void");
        } else {
            panic!("expected void");
        }
    }

    #[test]
    fn trim_src_strips_anything_before_src_dir() {
        assert_eq!(trim_src("/work/pgbackrust/src/common/foo.c"), "common/foo.c");
        assert_eq!(trim_src("nope.c"), "nope.c");
        assert_eq!(trim_src("src/x.c"), "x.c");
    }

    #[test]
    fn force_no_backtrace_round_trips() {
        let _guard = fresh_state();
        assert!(!force_no_backtrace_get());
        force_no_backtrace_set(true);
        assert!(force_no_backtrace_get());
        force_no_backtrace_set(false);
    }

    #[test]
    fn test_size_inc_dec_for_test_helper() {
        let _guard = fresh_state();
        assert_eq!(stack_size(), 0);
        test_size_inc();
        assert_eq!(stack_size(), 1);
        test_size_dec();
        assert_eq!(stack_size(), 0);
    }

    #[test]
    fn test_set_frame_field_writes_each_discriminant() {
        let _guard = fresh_state();
        let file = cstr("a.c");
        let func = cstr("a");
        let _ = push(file.as_ptr(), func.as_ptr(), 0, 0);

        test_set_frame_field(0, 0, 99); // file_line
        assert_eq!(frame_at(0).unwrap().file_line, 99);

        test_set_frame_field(0, 1, 7); // function_log_level
        assert_eq!(frame_at(0).unwrap().function_log_level, 7);

        test_set_frame_field(0, 2, 12); // param_size
        assert_eq!(frame_at(0).unwrap().param_size, 12);

        test_set_frame_field(0, 3, 5); // param_offset
        assert_eq!(frame_at(0).unwrap().param_offset, 5);
    }
}
