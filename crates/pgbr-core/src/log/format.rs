//! Line formatter for the legacy `src/common/log.c` `logInternal` / `logInternalFmt` /
//! `logSignal` API.
//!
//! Builds the prefix (timestamp, process id, level name, error code, dry-run tag, debug
//! `file::function` suffix), appends the message body, then dispatches to up to three
//! file descriptors (stdout / stderr / file) via `write(2)`. The output is byte-identical
//! to the legacy C formatter — `logTest.c` exercises every prefix variant and asserts
//! the exact bytes through the existing `harnessLog` capture.
//!
//! State (levels / fds / flags / process metadata / shared scratchpad) lives in the
//! parent module; this submodule reads it through the `super::*` accessors. The 32 KiB
//! scratchpad is shared with the C side: tests still poke at `pgbr_log_buffer_ptr()` to
//! inspect what was rendered.
//!
//! # Threading
//!
//! Same single-threaded contract as the rest of the crate. pgBackRust forks for
//! parallelism rather than threading; concurrent `log_internal` / `log_internal_fmt` /
//! `log_signal` calls are unsound and would race on the shared scratchpad.
//!
//! # Errors
//!
//! `write(2)` failures surface as [`pgbr_error::Error`] values with the
//! [`ErrorType::FileWrite`] category. The FFI shims in `pgbr-ffi` translate that into
//! the thread-local last-error slot the C wrapper checks before invoking
//! `pgbr_error_throw_from_last`.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::mem::MaybeUninit;
use std::format;

use pgbr_error::format::{Arg, format_message};
use pgbr_error::{Error, ErrorType};

use super::{
    LOG_BUFFER_SIZE, LOG_LEVEL_DEBUG, LOG_LEVEL_MAX, LOG_LEVEL_MIN, buffer_ptr, dry_run, fd_file, fd_std_err, fd_std_out,
    file_banner, level_file, level_std_err, level_std_out, level_str, process_id, process_size, set_file_banner, timestamp,
};

/// Process-start banner written to the log file before the first message of a fresh
/// session. Mirrors the `LOG_BANNER` macro in `src/common/log.c`.
const LOG_BANNER: &[u8] = b"-------------------PROCESS START-------------------\n";

/// Static prefix for `log_signal`; matches `LOG_SIGNAL_MESSAGE_PRE` in `src/common/log.c`.
const LOG_SIGNAL_MESSAGE_PRE: &[u8] = b"terminated on signal ";

/// Inserted between the level prefix and the message body when `dry_run` is on.
const DRY_RUN_PREFIX: &[u8] = b"[DRY-RUN] ";

/// 90-byte block of spaces used by `log_write_indent` to indent continuation lines
/// without re-allocating. The legacy C buffer is `87`; we keep the same outer bound so
/// the `indent_size < INDENT_BUFFER.len()` assertion behaves the same.
const INDENT_BUFFER: [u8; 90] = [b' '; 90];

/// Result of [`log_pre`] — three offsets into the shared scratchpad.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct LogPreResult {
    /// Offset where the next byte (the message body, or the trailing newline if no body
    /// has been appended yet) should land.
    pub buffer_pos: usize,
    /// Offset of the first byte of the stderr-friendly prefix (skips timestamp and
    /// process-id prefix and the alignment padding around the level name).
    pub stderr_offset: usize,
    /// Number of leading spaces required for continuation lines (the columns used by
    /// the prefix built so far). Equal to `buffer_pos` after `log_pre` finishes the
    /// level prefix; the debug branch extends it before the `file::function` suffix.
    pub indent_size: usize,
}

// ---------------------------------------------------------------------------
// libc bindings.
//
// pgBackRust targets glibc on Linux. The struct definitions and the `__errno_location`
// linkage match the Debian 13 toolchain pinned in `Dockerfile.dev`.
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
type ssize_t = isize;
#[allow(non_camel_case_types)]
type size_t = usize;
#[allow(non_camel_case_types)]
type off_t = i64;
#[allow(non_camel_case_types)]
type time_t = i64;

#[repr(C)]
struct Timeval {
    tv_sec: time_t,
    tv_usec: c_long,
}

#[repr(C)]
#[allow(clippy::struct_field_names)]
struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

unsafe extern "C" {
    fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t;
    fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int;
    fn localtime_r(time: *const time_t, result: *mut Tm) -> *mut Tm;
    fn __errno_location() -> *mut c_int;
    fn strerror(errnum: c_int) -> *const c_char;
}

const SEEK_END: c_int = 2;

#[inline]
unsafe fn errno_value() -> c_int {
    // SAFETY: `__errno_location` returns a valid thread-local pointer.
    unsafe { *__errno_location() }
}

unsafe fn strerror_string(errnum: c_int) -> String {
    // SAFETY: `strerror` returns a static (or thread-local for *_r variants) NUL-terminated
    // string. Reading it through `CStr` is safe as long as we do it on the calling thread
    // before any subsequent locale-changing call, which we do not perform here.
    unsafe {
        let p = strerror(errnum);
        if p.is_null() {
            return String::new();
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

// ---------------------------------------------------------------------------
// Buffer access.
// ---------------------------------------------------------------------------

/// SAFETY contract enforced by the single-threaded invariant: only one logger call runs
/// at a time, so handing out a `&mut [u8]` to the shared 32 KiB scratchpad is sound.
#[allow(clippy::mut_from_ref)]
unsafe fn buffer_slice() -> &'static mut [u8] {
    // SAFETY: `buffer_ptr` returns a pointer to the shared `LogState` scratch buffer
    // whose backing allocation is at least `LOG_BUFFER_SIZE` bytes (in practice the
    // 256 KiB + 4 KiB heap block — see `LOG_BUFFER_ALLOC`).
    unsafe { core::slice::from_raw_parts_mut(buffer_ptr().cast::<u8>(), LOG_BUFFER_SIZE) }
}

// ---------------------------------------------------------------------------
// Prefix builder.
// ---------------------------------------------------------------------------

/// Mirrors `logRange` in `src/common/log.c` byte-for-byte.
#[must_use]
pub const fn log_range(level: i32, range_min: i32, range_max: i32) -> bool {
    level >= range_min && level <= range_max
}

/// Build the prefix portion of a log line into the shared scratchpad. Mirrors `logPre`
/// in `src/common/log.c`.
///
/// `process_id_param` is the per-call override — `u32::MAX` selects the process-global
/// `process_id` from state, matching the C `processId == (unsigned int)-1` branch.
///
/// `code` is the optional error code — `0` suppresses the `[NNN]: ` segment.
///
/// Emits no message body; the caller appends the body before invoking [`log_post`].
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::missing_panics_doc
)]
pub fn log_pre(level: i32, process_id_param: u32, file_name: &str, function_name: &str, code: i32) -> LogPreResult {
    debug_assert!((LOG_LEVEL_MIN..=LOG_LEVEL_MAX).contains(&level), "log level out of range");

    let log_timestamp = timestamp();
    let log_process_id = process_id();
    let log_process_size = process_size();
    let log_dry_run = dry_run();

    // SAFETY: see `buffer_slice`.
    let buffer = unsafe { buffer_slice() };
    let mut buffer_pos = 0_usize;

    // 1. Timestamp.
    if log_timestamp {
        buffer_pos += format_timestamp_into(&mut buffer[buffer_pos..]);
    }

    // 2. Process id and aligned level name: `P{pid:0width$} {level:>6}: `.
    let effective_pid = if process_id_param == u32::MAX {
        log_process_id
    } else {
        process_id_param
    };
    let level_cstr = level_str(level);
    let level_name = level_cstr.to_str().expect("log level names are static ASCII");
    let prefix = format!(
        "P{:0pid_width$} {:>6}: ",
        effective_pid,
        level_name,
        pid_width = log_process_size as usize
    );
    let prefix_bytes = prefix.as_bytes();
    buffer[buffer_pos..buffer_pos + prefix_bytes.len()].copy_from_slice(prefix_bytes);
    buffer_pos += prefix_bytes.len();

    // 3. Stderr offset and base indent. `stderr_offset` is computed as
    //    `buffer_pos - len(level_name) - 2` so stderr output starts at the level name
    //    (skipping timestamp + `P{pid} ` + alignment padding).
    let stderr_offset = buffer_pos - level_name.len() - 2;
    let mut indent_size = buffer_pos;

    // 4. Error code: `[NNN]: `.
    if code != 0 {
        let code_str = format!("[{code:03}]: ");
        let bytes = code_str.as_bytes();
        buffer[buffer_pos..buffer_pos + bytes.len()].copy_from_slice(bytes);
        buffer_pos += bytes.len();
    }

    // 5. Dry-run prefix.
    if log_dry_run {
        buffer[buffer_pos..buffer_pos + DRY_RUN_PREFIX.len()].copy_from_slice(DRY_RUN_PREFIX);
        buffer_pos += DRY_RUN_PREFIX.len();
    }

    // 6. Debug suffix: padding + `{file_stem}::{function_name}: ` for DEBUG / TRACE.
    if level >= LOG_LEVEL_DEBUG {
        // C: `(logLevel - logLevelDebug + 1) * 4` spaces, advancing both buffer_pos and
        // indent_size so continuation lines align under the file::function column.
        let padding = ((level - LOG_LEVEL_DEBUG + 1) * 4) as usize;
        for _ in 0..padding {
            buffer[buffer_pos] = b' ';
            buffer_pos += 1;
            indent_size += 1;
        }

        // Strip the last 2 bytes of `file_name` to drop the `.c` extension. C uses
        // `strlen(fileName) - 2`; we replicate via byte slicing because all C-side file
        // names are ASCII.
        let stem_len = file_name.len().saturating_sub(2);
        let dbg = format!("{}::{function_name}: ", &file_name[..stem_len]);
        let bytes = dbg.as_bytes();
        buffer[buffer_pos..buffer_pos + bytes.len()].copy_from_slice(bytes);
        buffer_pos += bytes.len();
    }

    LogPreResult {
        buffer_pos,
        stderr_offset,
        indent_size,
    }
}

/// Render the current local timestamp (`YYYY-MM-DD HH:MM:SS.mmm `) into `buf`. Returns
/// the number of bytes written (always 24).
#[allow(clippy::cast_possible_truncation)]
fn format_timestamp_into(buf: &mut [u8]) -> usize {
    let mut tv = MaybeUninit::<Timeval>::uninit();
    // SAFETY: `gettimeofday` writes to *tv; passing null for `tz` is the documented
    // way to request only the wall-clock time.
    unsafe {
        gettimeofday(tv.as_mut_ptr(), core::ptr::null_mut());
    }
    // SAFETY: `gettimeofday` is documented to fully initialise *tv on success.
    let tv = unsafe { tv.assume_init() };

    let mut tm = MaybeUninit::<Tm>::uninit();
    // SAFETY: `localtime_r` is reentrant and fills *result. `tv.tv_sec` is a valid
    // `time_t` produced by `gettimeofday`.
    unsafe {
        localtime_r(&raw const tv.tv_sec, tm.as_mut_ptr());
    }
    // SAFETY: `localtime_r` is documented to fully initialise *result on success.
    let tm = unsafe { tm.assume_init() };

    let msec = (tv.tv_usec / 1000) as i32;

    let formatted = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} ",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        msec,
    );
    let bytes = formatted.as_bytes();
    buf[..bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

// ---------------------------------------------------------------------------
// Output dispatch.
// ---------------------------------------------------------------------------

/// Append the trailing newline + NUL and dispatch the rendered line to up to three file
/// descriptors. Mirrors `logPost` in `src/common/log.c`.
///
/// On `write(2)` failure the function returns an `Err(Error)` carrying the first detail
/// that failed; subsequent fds are not attempted, matching the legacy `THROW_SYS_ERROR`
/// behavior.
pub fn log_post(data: &mut LogPreResult, level: i32, range_min: i32, range_max: i32) -> Result<(), Error> {
    debug_assert!((LOG_LEVEL_MIN..=LOG_LEVEL_MAX).contains(&level), "log level out of range");
    debug_assert!((LOG_LEVEL_MIN..=LOG_LEVEL_MAX).contains(&range_min), "range_min out of range");
    debug_assert!((LOG_LEVEL_MIN..=LOG_LEVEL_MAX).contains(&range_max), "range_max out of range");
    debug_assert!(range_min <= range_max, "inverted range");

    // SAFETY: see `buffer_slice`.
    let buffer = unsafe { buffer_slice() };

    // Append linefeed and NUL terminator.
    buffer[data.buffer_pos] = b'\n';
    data.buffer_pos += 1;
    if data.buffer_pos < buffer.len() {
        buffer[data.buffer_pos] = 0;
    }

    let log_level_std_out = level_std_out();
    let log_level_std_err = level_std_err();
    let log_level_file = level_file();
    let log_fd_std_out = fd_std_out();
    let log_fd_std_err = fd_std_err();
    let log_fd_file = fd_file();

    // Console (stderr / stdout) routing.
    if level <= log_level_std_err {
        let promote_via_stderr = log_level_std_err > log_level_std_out && log_range(log_level_std_err, range_min, range_max);
        let promote_via_stdout = log_level_std_err <= log_level_std_out && log_range(log_level_std_out, range_min, range_max);

        if promote_via_stderr || promote_via_stdout {
            let stderr_indent = data.indent_size - data.stderr_offset;
            log_write_indent(
                log_fd_std_err,
                &buffer[data.stderr_offset..data.buffer_pos],
                stderr_indent,
                "log to stderr",
            )?;
        }
    } else if level <= log_level_std_out && log_range(log_level_std_out, range_min, range_max) {
        log_write_indent(log_fd_std_out, &buffer[..data.buffer_pos], data.indent_size, "log to stdout")?;
    }

    // File routing — write the process-start banner the first time round.
    if level <= log_level_file && log_fd_file != -1 && log_range(log_level_file, range_min, range_max) {
        if !file_banner() {
            // SAFETY: `lseek(SEEK_END)` on a regular file fd is well-defined; an error
            // only happens for invalid fds, in which case the subsequent `write` will
            // also fail and surface the real diagnostic.
            let pos = unsafe { lseek(log_fd_file, 0, SEEK_END) };
            if pos > 0 {
                log_write(log_fd_file, b"\n", "banner spacing to file")?;
            }
            log_write(log_fd_file, LOG_BANNER, "banner to file")?;
            set_file_banner(true);
        }
        log_write_indent(log_fd_file, &buffer[..data.buffer_pos], data.indent_size, "log to file")?;
    }

    Ok(())
}

/// Single `write(2)` call with the legacy `THROW_SYS_ERROR_FMT(FileWriteError, "unable
/// to write %s")` semantics. Mirrors `logWrite` in `src/common/log.c`.
#[allow(clippy::cast_possible_wrap)]
fn log_write(fd: i32, message: &[u8], error_detail: &str) -> Result<(), Error> {
    debug_assert_ne!(fd, -1, "log_write: closed fd");
    debug_assert!(!message.is_empty(), "log_write: empty message");

    // SAFETY: `write` is well-defined for any fd / pointer / length triple. We pass a
    // valid byte slice and a length matching its size.
    let n = unsafe { write(fd, message.as_ptr().cast::<c_void>(), message.len()) };
    // `message.len()` here is bounded by `LOG_BUFFER_SIZE` (32 KiB) so the cast cannot wrap.
    if n != message.len() as ssize_t {
        // SAFETY: `errno_value` reads through `__errno_location` which is always valid.
        let err = unsafe { errno_value() };
        // SAFETY: see `strerror_string`.
        let detail = unsafe { strerror_string(err) };
        let msg = format!("unable to write {error_detail}: [{err}] {detail}");
        return Err(Error::new(ErrorType::FileWrite, msg));
    }
    Ok(())
}

/// Write `message` to `fd`, indenting every continuation line by `indent_size` spaces
/// so multi-line log entries align under the prefix. Mirrors `logWriteIndent` in
/// `src/common/log.c`.
fn log_write_indent(fd: i32, message: &[u8], indent_size: usize, error_detail: &str) -> Result<(), Error> {
    debug_assert_ne!(fd, -1, "log_write_indent: closed fd");
    debug_assert!(!message.is_empty(), "log_write_indent: empty message");
    debug_assert!(
        indent_size > 0 && indent_size < INDENT_BUFFER.len(),
        "indent_size out of range"
    );

    let mut start = 0_usize;
    let mut first = true;

    while let Some(rel) = memchr(b'\n', &message[start..]) {
        if first {
            first = false;
        } else {
            log_write(fd, &INDENT_BUFFER[..indent_size], error_detail)?;
        }
        log_write(fd, &message[start..=start + rel], error_detail)?;
        start += rel + 1;
    }

    Ok(())
}

#[inline]
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

// ---------------------------------------------------------------------------
// Public entry points (mirrors of logInternal / logInternalFmt / logSignal).
// ---------------------------------------------------------------------------

/// Render and dispatch a pre-formatted message. Mirrors `logInternal` in
/// `src/common/log.c`.
pub fn log_internal(
    level: i32,
    range_min: i32,
    range_max: i32,
    process_id_param: u32,
    file_name: &str,
    function_name: &str,
    code: i32,
    message: &str,
) -> Result<(), Error> {
    let mut data = log_pre(level, process_id_param, file_name, function_name, code);

    // SAFETY: see `buffer_slice`.
    let buffer = unsafe { buffer_slice() };

    // Truncate to fit the buffer minus the trailing newline + NUL.
    let max = LOG_BUFFER_SIZE.saturating_sub(data.buffer_pos).saturating_sub(2);
    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(max);
    buffer[data.buffer_pos..data.buffer_pos + copy_len].copy_from_slice(&bytes[..copy_len]);
    data.buffer_pos += copy_len;

    log_post(&mut data, level, range_min, range_max)
}

/// Render and dispatch a printf-formatted message. The `template` and `args` follow the
/// shared `pgbr_error::format` contract — see Phase 27 sub-issue B.
#[allow(clippy::too_many_arguments)]
pub fn log_internal_fmt(
    level: i32,
    range_min: i32,
    range_max: i32,
    process_id_param: u32,
    file_name: &str,
    function_name: &str,
    code: i32,
    template: &str,
    args: &[Arg<'_>],
) -> Result<(), Error> {
    let mut data = log_pre(level, process_id_param, file_name, function_name, code);

    // SAFETY: see `buffer_slice`.
    let buffer = unsafe { buffer_slice() };

    let formatted = format_message(template, args);
    let max = LOG_BUFFER_SIZE.saturating_sub(data.buffer_pos).saturating_sub(2);
    let bytes = formatted.as_bytes();
    let copy_len = bytes.len().min(max);
    buffer[data.buffer_pos..data.buffer_pos + copy_len].copy_from_slice(&bytes[..copy_len]);
    data.buffer_pos += copy_len;

    log_post(&mut data, level, range_min, range_max)
}

/// Render and dispatch a signal-exit message. Mirrors `logSignal` in `src/common/log.c`.
pub fn log_signal(level: i32, signal_name: &str) -> Result<(), Error> {
    debug_assert!((LOG_LEVEL_MIN..=LOG_LEVEL_MAX).contains(&level), "log level out of range");
    assert!(
        LOG_BUFFER_SIZE >= LOG_SIGNAL_MESSAGE_PRE.len(),
        "log buffer smaller than signal banner"
    );

    // SAFETY: see `buffer_slice`.
    let buffer = unsafe { buffer_slice() };

    buffer[..LOG_SIGNAL_MESSAGE_PRE.len()].copy_from_slice(LOG_SIGNAL_MESSAGE_PRE);
    let mut data = LogPreResult {
        buffer_pos: LOG_SIGNAL_MESSAGE_PRE.len(),
        stderr_offset: 0,
        indent_size: 4,
    };

    // Append the signal name (truncate if it would not fit) and ensure the buffer
    // remains NUL-terminated at its hard end.
    let name_bytes = signal_name.as_bytes();
    let max = LOG_BUFFER_SIZE.saturating_sub(data.buffer_pos).saturating_sub(2);
    let copy_len = name_bytes.len().min(max);
    buffer[data.buffer_pos..data.buffer_pos + copy_len].copy_from_slice(&name_bytes[..copy_len]);
    data.buffer_pos += copy_len;
    buffer[LOG_BUFFER_SIZE - 1] = 0;

    log_post(&mut data, level, LOG_LEVEL_MIN, LOG_LEVEL_MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_wrap)]
mod tests {
    use super::super::test_support::fresh_state;
    use super::super::{
        LOG_LEVEL_ERROR, LOG_LEVEL_INFO, LOG_LEVEL_OFF, LOG_LEVEL_TRACE, LOG_LEVEL_WARN, init, set_fd_file, set_fd_std_err,
        set_fd_std_out, set_file_banner,
    };
    use super::*;
    use std::ffi::CString;
    use std::os::unix::io::IntoRawFd;

    fn buffer_str(len: usize) -> String {
        // SAFETY: see `buffer_slice`.
        let buf = unsafe { buffer_slice() };
        String::from_utf8(buf[..len].to_vec()).unwrap()
    }

    fn write_to_temp(suffix: &str) -> (std::path::PathBuf, i32) {
        let path = std::env::temp_dir().join(format!("pgbr-log-test-{}-{}.log", std::process::id(), suffix));
        // Truncate any leftover from a previous run.
        let _ = std::fs::remove_file(&path);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .unwrap();
        let fd = file.into_raw_fd();
        (path, fd)
    }

    fn read_temp(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn log_range_matches_c_logic() {
        assert!(log_range(LOG_LEVEL_INFO, LOG_LEVEL_MIN, LOG_LEVEL_MAX));
        assert!(!log_range(LOG_LEVEL_INFO, LOG_LEVEL_TRACE, LOG_LEVEL_MAX));
        assert!(!log_range(LOG_LEVEL_INFO, LOG_LEVEL_MIN, LOG_LEVEL_ERROR));
        assert!(log_range(LOG_LEVEL_TRACE, LOG_LEVEL_TRACE, LOG_LEVEL_TRACE));
    }

    #[test]
    fn log_pre_renders_warn_with_pid_padded_to_two() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 99, false);
        let r = log_pre(LOG_LEVEL_WARN, 44, "file", "function", 0);
        assert_eq!(buffer_str(r.buffer_pos), "P44   WARN: ");
        // "WARN" is right-aligned in 6 columns inside the "{:>6}" slot, so the level
        // name starts at offset 6 ("P44 " + 2 padding spaces).
        assert_eq!(r.stderr_offset, 6);
        // indent = full prefix length (12 chars).
        assert_eq!(r.indent_size, 12);
    }

    #[test]
    fn log_pre_renders_pid_padded_to_three_when_max_above_99() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 999, false);
        let r = log_pre(LOG_LEVEL_INFO, 5, "file", "function", 0);
        assert_eq!(buffer_str(r.buffer_pos), "P005   INFO: ");
    }

    #[test]
    fn log_pre_uses_state_pid_for_uint_max_param() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 7, 99, false);
        let r = log_pre(LOG_LEVEL_INFO, u32::MAX, "file", "function", 0);
        // process_id from state = 7, padded to width 2 = "07".
        assert!(buffer_str(r.buffer_pos).starts_with("P07 "));
    }

    #[test]
    fn log_pre_includes_error_code_segment() {
        let _g = fresh_state();
        init(LOG_LEVEL_ERROR, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 99, false);
        let r = log_pre(LOG_LEVEL_ERROR, 44, "file", "function", 26);
        assert_eq!(buffer_str(r.buffer_pos), "P44  ERROR: [026]: ");
    }

    #[test]
    fn log_pre_includes_dry_run_prefix() {
        let _g = fresh_state();
        init(LOG_LEVEL_INFO, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 1, 99, true);
        let r = log_pre(LOG_LEVEL_INFO, 1, "file", "function", 0);
        assert_eq!(buffer_str(r.buffer_pos), "P01   INFO: [DRY-RUN] ");
    }

    #[test]
    fn log_pre_includes_debug_padding_and_file_function() {
        let _g = fresh_state();
        init(LOG_LEVEL_DEBUG, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 999, false);
        let r = log_pre(LOG_LEVEL_DEBUG, 999, "test.c", "test_func", 0);
        assert_eq!(buffer_str(r.buffer_pos), "P999  DEBUG:     test::test_func: ");
        // Debug-level continuation indent extends to include the 4-space padding.
        assert_eq!(r.indent_size, "P999  DEBUG:     ".len());
    }

    #[test]
    fn log_pre_includes_trace_padding_eight_spaces() {
        let _g = fresh_state();
        init(LOG_LEVEL_TRACE, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 999, false);
        let r = log_pre(LOG_LEVEL_TRACE, 0, "test.c", "test_func", 0);
        // process_max=999 → process_size=3, matches the C `logTest.c` invocation.
        assert_eq!(buffer_str(r.buffer_pos), "P000  TRACE:         test::test_func: ");
    }

    #[test]
    fn log_pre_timestamp_format_is_iso_with_milliseconds() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, true, 0, 99, false);
        let r = log_pre(LOG_LEVEL_WARN, 0, "file", "function", 0);
        let s = buffer_str(r.buffer_pos);
        // First 23 chars are the timestamp, char 23 is the trailing space, then "P00".
        assert_eq!(s.len(), "YYYY-MM-DD HH:MM:SS.mmm P00   WARN: ".len());
        let ts = &s[..23];
        // Spot-check the structural punctuation; we cannot pin down the values without
        // a clock fake, but the layout is fixed.
        assert_eq!(ts.as_bytes()[4], b'-');
        assert_eq!(ts.as_bytes()[7], b'-');
        assert_eq!(ts.as_bytes()[10], b' ');
        assert_eq!(ts.as_bytes()[13], b':');
        assert_eq!(ts.as_bytes()[16], b':');
        assert_eq!(ts.as_bytes()[19], b'.');
    }

    #[test]
    fn log_internal_writes_warn_message_to_buffer() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 99, false);
        // Redirect stdout/stderr to /dev/null to avoid noise.
        let null = CString::new("/dev/null").unwrap();
        // SAFETY: opening /dev/null read-write is always safe.
        let null_fd = unsafe { libc_open_devnull(null.as_ptr()) };
        set_fd_std_out(null_fd);
        set_fd_std_err(null_fd);

        log_internal(
            LOG_LEVEL_WARN,
            LOG_LEVEL_MIN,
            LOG_LEVEL_MAX,
            44,
            "file",
            "function",
            0,
            "hello",
        )
        .unwrap();
        // SAFETY: see `buffer_slice`.
        let buf = unsafe { buffer_slice() };
        // Find the trailing newline that log_post appended.
        let nl = buf.iter().position(|&b| b == b'\n').unwrap();
        let line = std::str::from_utf8(&buf[..nl]).unwrap();
        assert_eq!(line, "P44   WARN: hello");

        // SAFETY: closing the duplicated fd is fine — we own it.
        unsafe { libc_close(null_fd) };
    }

    #[test]
    fn log_internal_fmt_substitutes_args_via_format_message() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 99, false);
        let null = CString::new("/dev/null").unwrap();
        // SAFETY: see above.
        let null_fd = unsafe { libc_open_devnull(null.as_ptr()) };
        set_fd_std_out(null_fd);
        set_fd_std_err(null_fd);

        log_internal_fmt(
            LOG_LEVEL_WARN,
            LOG_LEVEL_MIN,
            LOG_LEVEL_MAX,
            u32::MAX,
            "file",
            "function",
            0,
            "format %d",
            &[Arg::I32(99)],
        )
        .unwrap();

        // SAFETY: see `buffer_slice`.
        let buf = unsafe { buffer_slice() };
        let nl = buf.iter().position(|&b| b == b'\n').unwrap();
        let line = std::str::from_utf8(&buf[..nl]).unwrap();
        assert_eq!(line, "P00   WARN: format 99");

        // SAFETY: see above.
        unsafe { libc_close(null_fd) };
    }

    #[test]
    fn log_internal_writes_to_stderr_when_above_stdout_level() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_ERROR, LOG_LEVEL_OFF, false, 0, 99, false);
        let (stdout_path, stdout_fd) = write_to_temp("stdout-stderr-routing");
        let (stderr_path, stderr_fd) = write_to_temp("stderr-stderr-routing");
        set_fd_std_out(stdout_fd);
        set_fd_std_err(stderr_fd);

        // ERROR level: matches stderr (= ERROR), does not match stdout (= WARN).
        log_internal(
            LOG_LEVEL_ERROR,
            LOG_LEVEL_MIN,
            LOG_LEVEL_MAX,
            44,
            "file",
            "function",
            1,
            "boom",
        )
        .unwrap();

        // SAFETY: closing the duplicated fds.
        unsafe {
            libc_close(stdout_fd);
            libc_close(stderr_fd);
        }
        let stdout_content = read_temp(&stdout_path);
        let stderr_content = read_temp(&stderr_path);
        // stderr captures the level prefix only (no "P44 " timestamp/process id).
        assert_eq!(stderr_content, "ERROR: [001]: boom\n");
        assert_eq!(stdout_content, "");

        let _ = std::fs::remove_file(&stdout_path);
        let _ = std::fs::remove_file(&stderr_path);
    }

    #[test]
    fn log_internal_indents_continuation_lines_to_indent_size() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 99, false);
        let (out_path, out_fd) = write_to_temp("indent");
        set_fd_std_out(out_fd);
        set_fd_std_err(out_fd);

        log_internal(
            LOG_LEVEL_ERROR,
            LOG_LEVEL_MIN,
            LOG_LEVEL_MAX,
            44,
            "file",
            "function",
            26,
            "message1\nmessage2",
        )
        .unwrap();

        // SAFETY: closing the duplicated fd.
        unsafe { libc_close(out_fd) };
        let content = read_temp(&out_path);
        assert_eq!(content, "P44  ERROR: [026]: message1\n            message2\n");
        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn log_internal_writes_banner_then_message_to_file() {
        let _g = fresh_state();
        let (file_path, file_fd) = write_to_temp("file-banner");
        let null = CString::new("/dev/null").unwrap();
        // SAFETY: see above.
        let null_fd = unsafe { libc_open_devnull(null.as_ptr()) };

        init(LOG_LEVEL_OFF, LOG_LEVEL_OFF, LOG_LEVEL_INFO, false, 0, 99, false);
        set_fd_std_out(null_fd);
        set_fd_std_err(null_fd);
        set_fd_file(file_fd);
        set_file_banner(false);
        // Recompute level_any so the file sink registers as enabled.
        super::super::any_set();

        log_internal(
            LOG_LEVEL_INFO,
            LOG_LEVEL_MIN,
            LOG_LEVEL_MAX,
            7,
            "file",
            "function",
            0,
            "first",
        )
        .unwrap();
        log_internal(
            LOG_LEVEL_INFO,
            LOG_LEVEL_MIN,
            LOG_LEVEL_MAX,
            7,
            "file",
            "function",
            0,
            "second",
        )
        .unwrap();

        // SAFETY: closing the duplicated fds.
        unsafe {
            libc_close(file_fd);
            libc_close(null_fd);
        }
        let content = read_temp(&file_path);
        assert_eq!(
            content,
            "-------------------PROCESS START-------------------\n\
             P07   INFO: first\n\
             P07   INFO: second\n",
        );
        let _ = std::fs::remove_file(&file_path);
    }

    #[test]
    fn log_signal_writes_terminated_on_signal_message() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 99, false);
        let (out_path, out_fd) = write_to_temp("signal");
        set_fd_std_out(out_fd);
        set_fd_std_err(out_fd);

        log_signal(LOG_LEVEL_WARN, "SIGTERM").unwrap();

        // SAFETY: closing the duplicated fd.
        unsafe { libc_close(out_fd) };
        let content = read_temp(&out_path);
        // log_signal sets stderr_offset = 0 and indent_size = 4, so the signal banner
        // is treated as a stdout-style write.
        assert_eq!(content, "terminated on signal SIGTERM\n");
        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn log_internal_returns_error_on_invalid_fd() {
        let _g = fresh_state();
        init(LOG_LEVEL_WARN, LOG_LEVEL_OFF, LOG_LEVEL_OFF, false, 0, 99, false);
        set_fd_std_out(-999);

        let err = log_internal(LOG_LEVEL_WARN, LOG_LEVEL_MIN, LOG_LEVEL_MAX, 0, "file", "function", 0, "x").unwrap_err();
        assert_eq!(err.error_type(), ErrorType::FileWrite);
        assert!(err.message().starts_with("unable to write log to stdout"));
    }

    // libc helpers used only inside #[cfg(test)] for fd setup.
    unsafe extern "C" {
        #[link_name = "open"]
        fn libc_open(path: *const c_char, flags: c_int) -> c_int;
        #[link_name = "close"]
        fn libc_close(fd: c_int) -> c_int;
    }

    const O_RDWR: c_int = 2;

    unsafe fn libc_open_devnull(path: *const c_char) -> c_int {
        // SAFETY: caller passes a NUL-terminated path.
        let fd = unsafe { libc_open(path, O_RDWR) };
        assert!(fd >= 0, "open(/dev/null) failed");
        fd
    }
}
