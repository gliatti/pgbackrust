//! Retry-error accumulator for the C → Rust migration.
//!
//! [`RetryState`] is the Rust-side replacement for the legacy `ErrorRetry` object in
//! `src/common/error/retry.c`. It records the first error seen and, for every subsequent
//! retry, either deduplicates against an existing entry by message text or appends a new
//! entry. [`RetryState::format_message`] reproduces the legacy multi-line summary
//! verbatim — the differential test in `errorRetryTest.c` asserts byte equality against a
//! `legacy_*` re-implementation of the original C code.
//!
//! The C side passes wall-clock millisecond timestamps in: this module never reads the
//! clock. That keeps the Rust state deterministic for unit tests and lets the harness
//! drive `hrnTimeMSecSet` without crossing the FFI boundary.

use std::ffi::CString;

use crate::ErrorType;

/// Single deduplicated retry record. The C struct of the same name has identical fields.
#[derive(Debug, Clone)]
struct RetryItem {
    error_type_code: i32,
    message: String,
    total: u32,
    retry_first_ms: u64,
    retry_last_ms: u64,
}

/// Accumulator for the first error and any number of subsequent retry attempts.
///
/// The `time_begin_ms` baseline is captured at construction time. Every `add` call passes
/// the current wall-clock millisecond reading; the stored `retry_first_ms` /
/// `retry_last_ms` fields are deltas from `time_begin_ms`, matching the legacy C output.
///
/// `first_message_cstr` and `formatted_cstr` are NUL-terminated mirrors of the data the
/// FFI layer hands back to C as `*const c_char`. They are populated lazily on first read
/// and invalidated by every mutation through [`RetryState::add`], which keeps the
/// pointers stable across consecutive reads while letting `add` advance state without
/// requiring the caller to re-fetch immediately.
#[derive(Debug, Clone)]
pub struct RetryState {
    first_type_code: Option<i32>,
    first_message: Option<String>,
    items: Vec<RetryItem>,
    time_begin_ms: u64,
    first_message_cstr: Option<CString>,
    formatted_cstr: Option<CString>,
}

impl RetryState {
    /// Build an empty state baselined at `time_begin_ms`.
    #[must_use]
    pub const fn new(time_begin_ms: u64) -> Self {
        Self {
            first_type_code: None,
            first_message: None,
            items: Vec::new(),
            time_begin_ms,
            first_message_cstr: None,
            formatted_cstr: None,
        }
    }

    /// Record an error. The first call captures the type and message verbatim. Subsequent
    /// calls either bump the total of an existing entry whose message matches, or append a
    /// new `RetryItem` with `retry_first_ms == retry_last_ms == now_ms - time_begin_ms`.
    pub fn add(&mut self, error_type_code: i32, message: &str, now_ms: u64) {
        // Any state mutation invalidates the cached C strings so the FFI layer rebuilds
        // them from the new state on the next read.
        self.first_message_cstr = None;
        self.formatted_cstr = None;

        if self.first_type_code.is_none() {
            self.first_type_code = Some(error_type_code);
            self.first_message = Some(message.to_owned());
            return;
        }

        // saturating_sub matches the C unsigned wrap-around when now_ms < time_begin_ms,
        // which never happens in practice but keeps the Rust path defined.
        let retry_time = now_ms.saturating_sub(self.time_begin_ms);

        if let Some(existing) = self.items.iter_mut().find(|item| item.message == message) {
            existing.total = existing.total.saturating_add(1);
            existing.retry_last_ms = retry_time;
        } else {
            self.items.push(RetryItem {
                error_type_code,
                message: message.to_owned(),
                total: 1,
                retry_first_ms: retry_time,
                retry_last_ms: retry_time,
            });
        }
    }

    /// NUL-terminated mirror of [`RetryState::first_message`]. Populates the cache on
    /// first call and returns the same pointer until the next mutation. Returns `None`
    /// when no first error is set.
    pub fn first_message_cstr(&mut self) -> Option<&CString> {
        if self.first_message_cstr.is_none() {
            let msg = self.first_message.as_ref()?;
            self.first_message_cstr = Some(string_to_cstring(msg));
        }
        self.first_message_cstr.as_ref()
    }

    /// NUL-terminated mirror of [`RetryState::format_message`]. Populates the cache on
    /// first call and returns the same pointer until the next mutation. Returns `None`
    /// when no first error is set.
    pub fn formatted_cstr(&mut self) -> Option<&CString> {
        if self.formatted_cstr.is_none() {
            let s = self.format_message()?;
            self.formatted_cstr = Some(string_to_cstring(&s));
        }
        self.formatted_cstr.as_ref()
    }

    /// Numeric code of the first error, if any.
    #[must_use]
    pub const fn first_type_code(&self) -> Option<i32> {
        self.first_type_code
    }

    /// Message text of the first error, if any.
    #[must_use]
    pub fn first_message(&self) -> Option<&str> {
        self.first_message.as_deref()
    }

    /// Number of deduplicated retry items beyond the first error.
    #[must_use]
    pub const fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Render the multi-line retry summary. Returns `None` when no first error is set —
    /// the legacy C code would have asserted on a `NULL` first message, so callers must
    /// only invoke this once at least one `add` has occurred.
    ///
    /// Each retry item is appended on its own line, matching the C `strCatFmt` calls in
    /// the legacy implementation byte-for-byte:
    ///
    /// ```text
    /// <first message>
    ///     [<TypeName>] on retry at <ms>ms: <message>
    ///     [<TypeName>] on <total> retries from <first>-<last>ms: <message>
    /// ```
    ///
    /// The `[TypeName]` token uses `errorTypeName(...)`; for the Rust path that's the
    /// kebab-case-to-`UpperCamelCase` symbol mapping via
    /// [`ErrorType::c_name_for_code`]. Unknown codes fall back to `"UnknownError"` so
    /// no formatter ever panics on bad input.
    #[must_use]
    pub fn format_message(&self) -> Option<String> {
        use std::fmt::Write as _;

        let first = self.first_message.as_ref()?;
        let mut out = String::with_capacity(first.len() + self.items.len() * 64);
        out.push_str(first);

        for item in &self.items {
            let type_name = ErrorType::c_name_for_code(item.error_type_code);
            out.push_str("\n    [");
            out.push_str(type_name);
            out.push_str("] ");

            if item.retry_first_ms == item.retry_last_ms {
                let _ = write!(out, "on retry at {}", item.retry_first_ms);
            } else {
                let _ = write!(
                    out,
                    "on {} retries from {}-{}",
                    item.total, item.retry_first_ms, item.retry_last_ms
                );
            }

            out.push_str("ms: ");
            out.push_str(&item.message);
        }

        Some(out)
    }
}

/// Strip interior NULs defensively; matches the discipline used elsewhere in the crate
/// for last-error `CString` caching. Production messages never contain NULs, but a fuzzed
/// or malformed input must not panic the FFI layer.
fn string_to_cstring(s: &str) -> CString {
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != 0).collect();
    CString::new(bytes).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn format_error_code() -> i32 {
        // FormatError per src/build/error/error.yaml. Generated enum drops the "Error" suffix
        // since it's redundant in `ErrorType::Format`; the C name is reattached via `c_name`.
        ErrorType::Format.code()
    }

    fn kernel_error_code() -> i32 {
        ErrorType::Kernel.code()
    }

    fn service_error_code() -> i32 {
        ErrorType::Service.code()
    }

    #[test]
    fn empty_state_has_no_first_error() {
        let s = RetryState::new(0);
        assert_eq!(s.first_type_code(), None);
        assert_eq!(s.first_message(), None);
        assert_eq!(s.item_count(), 0);
        assert_eq!(s.format_message(), None);
    }

    #[test]
    fn first_add_captures_type_and_message_without_creating_an_item() {
        let mut s = RetryState::new(0);
        s.add(format_error_code(), "first error", 10);
        assert_eq!(s.first_type_code(), Some(format_error_code()));
        assert_eq!(s.first_message(), Some("first error"));
        assert_eq!(s.item_count(), 0);
        assert_eq!(s.format_message().as_deref(), Some("first error"));
    }

    #[test]
    fn second_add_with_new_message_appends_item() {
        let mut s = RetryState::new(0);
        s.add(format_error_code(), "first", 10);
        s.add(kernel_error_code(), "second", 50);
        assert_eq!(s.item_count(), 1);
        assert_eq!(
            s.format_message().as_deref(),
            Some("first\n    [KernelError] on retry at 50ms: second"),
        );
    }

    #[test]
    fn second_add_with_same_message_dedupes_and_updates_last_time() {
        let mut s = RetryState::new(0);
        s.add(format_error_code(), "first", 10);
        s.add(format_error_code(), "first", 50);
        s.add(format_error_code(), "first", 150);
        // Only one item, total == 2, last == 150
        assert_eq!(s.item_count(), 1);
        assert_eq!(
            s.format_message().as_deref(),
            Some("first\n    [FormatError] on 2 retries from 50-150ms: first"),
        );
    }

    #[test]
    fn full_scenario_matches_legacy_c_byte_for_byte() {
        // Mirrors the "retry (detail enabled)" test case in errorRetryTest.c.
        // hrnTimeMSecSet({0, 50, 75, 150}) is consumed by the C harness; here we pass the
        // millisecond values directly to add(now_ms = ...).
        let mut s = RetryState::new(0);
        s.add(format_error_code(), "message1", 0);
        s.add(format_error_code(), "message1", 50);
        s.add(kernel_error_code(), "message2", 75);
        s.add(service_error_code(), "message1", 150);

        assert_eq!(s.first_type_code(), Some(format_error_code()));
        assert_eq!(
            s.format_message().as_deref(),
            Some("message1\n    [FormatError] on 2 retries from 50-150ms: message1\n    [KernelError] on retry at 75ms: message2",),
        );
    }

    #[test]
    fn time_delta_uses_baseline() {
        let mut s = RetryState::new(1_000);
        s.add(format_error_code(), "a", 1_000);
        s.add(format_error_code(), "b", 1_050);
        // retry_first_ms = 1050 - 1000 = 50
        assert_eq!(
            s.format_message().as_deref(),
            Some("a\n    [FormatError] on retry at 50ms: b"),
        );
    }

    #[test]
    fn now_before_baseline_saturates_to_zero() {
        let mut s = RetryState::new(1_000);
        s.add(format_error_code(), "a", 1_000);
        s.add(format_error_code(), "b", 500);
        assert_eq!(s.format_message().as_deref(), Some("a\n    [FormatError] on retry at 0ms: b"),);
    }

    #[test]
    fn unknown_error_type_codes_fall_back_to_unknown_error_label() {
        let mut s = RetryState::new(0);
        s.add(format_error_code(), "first", 0);
        // Pretend a code that's not in the table.
        s.add(7777, "weird", 50);
        assert_eq!(
            s.format_message().as_deref(),
            Some("first\n    [UnknownError] on retry at 50ms: weird"),
        );
    }

    #[test]
    fn c_name_for_known_codes_matches_error_define_symbol() {
        // Spot-check: the values must match the C-side `errorTypeName` output verbatim,
        // since the retry-message format is byte-asserted against the legacy C in the
        // differential test.
        assert_eq!(ErrorType::c_name_for_code(format_error_code()), "FormatError");
        assert_eq!(ErrorType::c_name_for_code(kernel_error_code()), "KernelError");
        assert_eq!(ErrorType::c_name_for_code(service_error_code()), "ServiceError");
        assert_eq!(ErrorType::c_name_for_code(7777), "UnknownError");
    }
}
