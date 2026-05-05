//! Shared error model for the pgBackRust C->Rust migration.
//!
//! The crate exposes:
//!
//! - [`ErrorType`] — `#[repr(i32)]` enum with discriminants matching the C `errorType*` codes.
//!   Generated at build time from `src/build/error/error.yaml`.
//! - [`Error`] — owned error value carrying a typed code and a message.
//! - [`Result`] — convenience alias for `core::result::Result<T, Error>`.
//! - Thread-local last-error helpers (`set_last_error`, `take_last_error`, `last_error_code`,
//!   `last_error_message`) used by the FFI bridge in `pgbr-ffi` so a Rust function returning
//!   `Result<T, Error>` can hand its `Err` to a C caller through the `(i32 code, char* message)`
//!   pair the legacy code already understands.

use core::fmt;
use std::cell::RefCell;
use std::ffi::CString;

pub mod format;

include!(concat!(env!("OUT_DIR"), "/error_types.rs"));

/// Owned error value. Crosses crate boundaries inside the workspace; does not implement `Copy`.
#[derive(Debug, Clone)]
pub struct Error {
    error_type: ErrorType,
    message: String,
}

impl Error {
    /// Build an error from a typed code and an owned message.
    #[must_use]
    pub fn new(error_type: ErrorType, message: impl Into<String>) -> Self {
        Self {
            error_type,
            message: message.into(),
        }
    }

    /// Typed category of this error.
    #[must_use]
    pub const fn error_type(&self) -> ErrorType {
        self.error_type
    }

    /// Numeric code matching the C `errorType*` table.
    #[must_use]
    pub const fn code(&self) -> i32 {
        self.error_type.code()
    }

    /// Whether the C side flags this error category as fatal.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        self.error_type.is_fatal()
    }

    /// Diagnostic message attached to this error.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.error_type.code(), self.error_type.name(), self.message)
    }
}

impl std::error::Error for Error {}

/// Convenience alias used throughout the workspace for fallible operations.
pub type Result<T> = core::result::Result<T, Error>;

thread_local! {
    static LAST_ERROR: RefCell<Option<Error>> = const { RefCell::new(None) };
    static LAST_ERROR_CSTR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Records `error` as the thread's last error, replacing any previous value.
pub fn set_last_error(error: Error) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(error));
    LAST_ERROR_CSTR.with(|slot| *slot.borrow_mut() = None);
}

/// Removes and returns the thread's last error, leaving the slot empty.
#[must_use]
pub fn take_last_error() -> Option<Error> {
    LAST_ERROR_CSTR.with(|slot| *slot.borrow_mut() = None);
    LAST_ERROR.with(|slot| slot.borrow_mut().take())
}

/// Returns a clone of the thread's last error, if any. Useful for inspection without consuming;
/// FFI bridges typically use `take_last_error` instead.
#[must_use]
pub fn last_error() -> Option<Error> {
    LAST_ERROR.with(|slot| slot.borrow().clone())
}

/// Numeric code of the thread's last error, or 0 if no error is set.
#[must_use]
pub fn last_error_code() -> i32 {
    LAST_ERROR.with(|slot| slot.borrow().as_ref().map_or(0, Error::code))
}

/// Pointer to a NUL-terminated UTF-8 message of the thread's last error, or `null` if no error
/// is set.
///
/// The pointer is valid until the next mutation of the thread-local slot
/// (`set_last_error` / `take_last_error` / `clear_last_error` / `last_error_message`). Callers
/// must not free it and must not retain it across such mutations.
#[must_use]
pub fn last_error_message() -> *const core::ffi::c_char {
    LAST_ERROR.with(|slot| {
        let Some(message) = slot.borrow().as_ref().map(|e| e.message().to_owned()) else {
            return core::ptr::null();
        };
        LAST_ERROR_CSTR.with(|cstr_slot| {
            let mut cstr_mut = cstr_slot.borrow_mut();
            if cstr_mut.is_none() {
                // Strip any interior NULs defensively rather than panic on user-supplied content;
                // the resulting buffer is guaranteed to be free of NULs so CString::new succeeds.
                let bytes: Vec<u8> = message.into_bytes().into_iter().filter(|b| *b != 0).collect();
                *cstr_mut = Some(CString::new(bytes).unwrap_or_default());
            }
            cstr_mut.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
        })
    })
}

/// Clears the thread's last error.
pub fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
    LAST_ERROR_CSTR.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_round_trip_through_from_code() {
        assert_eq!(ErrorType::from_code(25), Some(ErrorType::Assert));
        assert_eq!(ErrorType::from_code(94), Some(ErrorType::Memory));
        assert_eq!(ErrorType::from_code(125), Some(ErrorType::Unknown));
        assert_eq!(ErrorType::from_code(7777), None);
    }

    #[test]
    fn fatal_flag_matches_yaml() {
        assert!(ErrorType::Assert.is_fatal());
        assert!(ErrorType::Memory.is_fatal());
        assert!(!ErrorType::Checksum.is_fatal());
    }

    #[test]
    fn name_uses_yaml_kebab_case() {
        assert_eq!(ErrorType::OptionInvalid.name(), "option-invalid");
        assert_eq!(ErrorType::Memory.name(), "memory");
    }

    #[test]
    fn from_name_round_trips_known_variants() {
        assert_eq!(ErrorType::from_name("memory"), Some(ErrorType::Memory));
        assert_eq!(ErrorType::from_name("option-invalid"), Some(ErrorType::OptionInvalid));
        assert_eq!(ErrorType::from_name("runtime"), Some(ErrorType::Runtime));
        assert_eq!(ErrorType::from_name("Runtime"), None);
        assert_eq!(ErrorType::from_name(""), None);
        assert_eq!(ErrorType::from_name("nope"), None);
    }

    #[test]
    fn parent_chain_is_flat_to_runtime_with_self_loop() {
        // Every production entry currently parents to runtime; runtime is its own parent.
        assert_eq!(ErrorType::Runtime.parent(), ErrorType::Runtime);
        assert_eq!(ErrorType::Runtime.parent_code(), ErrorType::Runtime.code());
        assert_eq!(ErrorType::Memory.parent(), ErrorType::Runtime);
        assert_eq!(ErrorType::FileMissing.parent_code(), ErrorType::Runtime.code());
    }

    #[test]
    fn extends_matches_c_semantics() {
        // Strict: a non-self-parented type does not extend itself.
        assert!(!ErrorType::Memory.extends(ErrorType::Memory));
        assert!(!ErrorType::FileMissing.extends(ErrorType::FileMissing));

        // Self-parented runtime extends runtime (first iteration finds the parent).
        assert!(ErrorType::Runtime.extends(ErrorType::Runtime));

        // Every non-runtime variant extends runtime through one hop.
        assert!(ErrorType::Memory.extends(ErrorType::Runtime));
        assert!(ErrorType::FileMissing.extends(ErrorType::Runtime));

        // No production cross-relationships exist (everything parents to runtime).
        assert!(!ErrorType::Memory.extends(ErrorType::FileMissing));
    }

    #[test]
    fn error_carries_type_and_message() {
        let err = Error::new(ErrorType::FileMissing, "no such file: /tmp/missing");
        assert_eq!(err.error_type(), ErrorType::FileMissing);
        assert_eq!(err.code(), 55);
        assert!(!err.is_fatal());
        assert_eq!(err.message(), "no such file: /tmp/missing");
        assert_eq!(format!("{err}"), "[55] file-missing: no such file: /tmp/missing");
    }

    #[test]
    fn last_error_helpers_round_trip_through_thread_local() {
        clear_last_error();
        assert_eq!(last_error_code(), 0);
        assert!(last_error_message().is_null());

        set_last_error(Error::new(ErrorType::Crypto, "bad key"));
        assert_eq!(last_error_code(), 95);

        let ptr = last_error_message();
        assert!(!ptr.is_null());
        // SAFETY: pointer points to a CString cached in this thread's slot and no mutation has
        // happened since the populating call above.
        let cstr = unsafe { core::ffi::CStr::from_ptr(ptr) };
        assert_eq!(cstr.to_str().unwrap(), "bad key");

        let taken = take_last_error().expect("error was set");
        assert_eq!(taken.code(), 95);
        assert_eq!(last_error_code(), 0);
        assert!(last_error_message().is_null());
    }
}
