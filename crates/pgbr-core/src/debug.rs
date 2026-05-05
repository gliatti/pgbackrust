//! Tiny string-to-buffer helpers shared with the C `FUNCTION_LOG_PARAM_*` machinery.
//!
//! These mirror the four functions in `src/common/debug.c` byte-for-byte:
//!
//! - [`type_to_log`] — write a literal type name (no quoting).
//! - [`obj_name_to_log`] — write `{Name}` if the object is non-null, otherwise `null`.
//! - [`ptr_to_log`] — write `(Name)` if the pointer is non-null, otherwise `null`.
//!
//! `objToLog` keeps its body in C because it dispatches to a C callback (the
//! `ObjToLogFormat` function pointer) that writes through the C-side `StringStatic`
//! cursor; the Rust side handles only the null branch via [`type_to_log`] when the
//! C wrapper observes a null object.
//!
//! The legacy C path goes through `StringStatic` (`strStcInit` / `strStcCat` /
//! `strStcFmt`); those primitives reserve one byte for the NUL terminator and copy at
//! most `bufferSize - 1` payload bytes. The contract this module reproduces:
//!
//! - When `buffer` is empty, write nothing and return `0`.
//! - When `buffer.len() == 1`, the C code never enters the cat branch (it requires
//!   `remainsSize > 1`), so we do the same and return `0` without writing the NUL.
//! - Otherwise copy `min(payload.len(), buffer.len() - 1)` bytes and write the NUL at
//!   that position. The returned `usize` is the payload byte count (excluding NUL),
//!   matching `strStcResultSize`.

/// Copy `payload` into `buffer` with the `strStcCat` truncation contract.
///
/// The trailing NUL is written when at least one byte fits, the return value is the
/// number of payload bytes written (excluding the NUL).
pub fn write_truncated(buffer: &mut [u8], payload: &str) -> usize {
    if buffer.len() <= 1 {
        return 0;
    }
    let max_payload = buffer.len() - 1;
    let bytes = payload.as_bytes();
    let written = bytes.len().min(max_payload);
    buffer[..written].copy_from_slice(&bytes[..written]);
    buffer[written] = 0;
    written
}

/// Copy `prefix`, `inner`, `suffix` into `buffer` — same truncation contract as
/// [`write_truncated`] but applied to a three-segment concatenation. The C side renders
/// `objNameToLog` as `{Name}` and `ptrToLog` as `(Name)`; this helper produces the same
/// byte sequence in one pass without an intermediate allocation, so an unbounded `inner`
/// (in theory: typeName / pointerName fed by the call site) cannot exceed the buffer.
fn write_truncated_wrapped(buffer: &mut [u8], prefix: u8, inner: &str, suffix: u8) -> usize {
    if buffer.len() <= 1 {
        return 0;
    }
    let max_payload = buffer.len() - 1;
    let inner_bytes = inner.as_bytes();
    let mut written = 0usize;

    // prefix
    if written < max_payload {
        buffer[written] = prefix;
        written += 1;
    }

    // inner — bounded by remaining payload capacity
    if written < max_payload {
        let take = (max_payload - written).min(inner_bytes.len());
        buffer[written..written + take].copy_from_slice(&inner_bytes[..take]);
        written += take;
    }

    // suffix
    if written < max_payload {
        buffer[written] = suffix;
        written += 1;
    }

    buffer[written] = 0;
    written
}

/// Write a type label (e.g. `"void"`, `"size_t"`, `"null"`) verbatim into `buffer`.
///
/// Matches the C `typeToLog(typeName, buffer, bufferSize)` shape exactly — the legacy
/// implementation called `strStcFmt(&debugLog, "%s", typeName)`, which after vsnprintf
/// truncation behaves identically to a memcpy + NUL.
#[must_use]
pub fn type_to_log(type_name: &str, buffer: &mut [u8]) -> usize {
    write_truncated(buffer, type_name)
}

/// Write `{name}` for a non-null object, `null` otherwise.
///
/// Matches the C `objNameToLog(object, name, buffer, bufferSize)` shape exactly.
#[must_use]
pub fn obj_name_to_log(present: bool, name: &str, buffer: &mut [u8]) -> usize {
    if !present {
        return write_truncated(buffer, "null");
    }
    write_truncated_wrapped(buffer, b'{', name, b'}')
}

/// Write `(name)` for a non-null pointer, `null` otherwise.
///
/// Matches the C `ptrToLog(pointer, name, buffer, bufferSize)` shape exactly.
#[must_use]
pub fn ptr_to_log(present: bool, name: &str, buffer: &mut [u8]) -> usize {
    if !present {
        return write_truncated(buffer, "null");
    }
    write_truncated_wrapped(buffer, b'(', name, b')')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn render<F: FnOnce(&mut [u8]) -> usize>(buffer_size: usize, f: F) -> (usize, String) {
        let mut buf = vec![0xAAu8; buffer_size];
        let n = f(&mut buf);
        // The function returns the payload byte count (excluding NUL); take that many bytes as
        // the visible output. Anything past `n` may be the sentinel `0xAA` (when the function
        // chose not to write — e.g. zero-length buffer) or the trailing NUL.
        (n, String::from_utf8(buf[..n].to_vec()).expect("ascii"))
    }

    #[test]
    fn type_to_log_fits_full_string() {
        let (n, out) = render(16, |b| type_to_log("void", b));
        assert_eq!(n, 4);
        assert_eq!(out, "void");
    }

    #[test]
    fn type_to_log_truncates_to_buffer_minus_one() {
        // bufferSize 4 → max payload 3
        let (n, out) = render(4, |b| type_to_log("12345", b));
        assert_eq!(n, 3);
        assert_eq!(out, "123");
    }

    #[test]
    fn type_to_log_buffer_size_one_writes_nothing() {
        // strStcCat / strStcFmt require remainsSize > 1 — a 1-byte buffer is no-op.
        let (n, out) = render(1, |b| type_to_log("anything", b));
        assert_eq!(n, 0);
        assert_eq!(out, "");
    }

    #[test]
    fn type_to_log_buffer_size_zero_writes_nothing() {
        let (n, _) = render(0, |b| type_to_log("anything", b));
        assert_eq!(n, 0);
    }

    #[test]
    fn obj_name_to_log_full_object() {
        let (n, out) = render(STACK, |b| obj_name_to_log(true, "Object", b));
        assert_eq!(n, 8);
        assert_eq!(out, "{Object}");
    }

    #[test]
    fn obj_name_to_log_truncated_object() {
        let (n, out) = render(4, |b| obj_name_to_log(true, "Object", b));
        assert_eq!(n, 3);
        assert_eq!(out, "{Ob");
    }

    #[test]
    fn obj_name_to_log_full_null() {
        let (n, out) = render(STACK, |b| obj_name_to_log(false, "Object", b));
        assert_eq!(n, 4);
        assert_eq!(out, "null");
    }

    #[test]
    fn obj_name_to_log_truncated_null() {
        let (n, out) = render(4, |b| obj_name_to_log(false, "Object", b));
        assert_eq!(n, 3);
        assert_eq!(out, "nul");
    }

    #[test]
    fn ptr_to_log_full_pointer() {
        let (n, out) = render(STACK, |b| ptr_to_log(true, "char *", b));
        assert_eq!(n, 8);
        assert_eq!(out, "(char *)");
    }

    #[test]
    fn ptr_to_log_truncated_pointer() {
        let (n, out) = render(4, |b| ptr_to_log(true, "char *", b));
        assert_eq!(n, 3);
        assert_eq!(out, "(ch");
    }

    #[test]
    fn ptr_to_log_full_null() {
        let (n, out) = render(STACK, |b| ptr_to_log(false, "char *", b));
        assert_eq!(n, 4);
        assert_eq!(out, "null");
    }

    #[test]
    fn ptr_to_log_truncated_null() {
        let (n, out) = render(4, |b| ptr_to_log(false, "char *", b));
        assert_eq!(n, 3);
        assert_eq!(out, "nul");
    }

    #[test]
    fn obj_name_to_log_inner_overflows_after_prefix() {
        // bufferSize 5 → max payload 4 → prefix '{' + 'A' 'B' 'C' (no suffix space)
        let (n, out) = render(5, |b| obj_name_to_log(true, "ABCDEFG", b));
        assert_eq!(n, 4);
        assert_eq!(out, "{ABC");
    }

    #[test]
    fn obj_name_to_log_inner_zero_length_still_wraps() {
        let (n, out) = render(8, |b| obj_name_to_log(true, "", b));
        assert_eq!(n, 2);
        assert_eq!(out, "{}");
    }

    const STACK: usize = 256;
}
