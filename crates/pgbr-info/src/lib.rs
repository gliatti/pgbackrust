//! On-disk pgBackRest metadata files: `archive.info`, `backup.info`, and `backup.manifest`.
//!
//! These files are INI-with-checksum documents that describe the state of a pgBackRest
//! repository — what `PostgreSQL` clusters have been backed up, what backups exist for
//! each cluster, what versions are supported, and what files each backup captured. This
//! crate ships:
//!
//! - [`format`] — a strict INI parser, a stable renderer, and the
//!   `checksumed_load` / `checksumed_render` pair that enforce the SHA-1-over-the-
//!   file-content-with-the-checksum-line-removed invariant.
//! - [`InfoArchive`] — typed wrapper around `archive.info`. Holds the format / version
//!   markers, the active database identity in `[db]`, and the historical clusters in
//!   `[db:history]`.
//! - [`InfoBackup`] — typed wrapper around `backup.info`. Adds the catalog / control
//!   versions to `[db]`, plus a `[backup:current]` block keyed by backup label and a
//!   `[db:history]` block of historical clusters.
//! - [`Manifest`] — typed wrapper around a backup's `backup.manifest`: the per-backup
//!   inventory of every file, path, and symlink with size / timestamp / checksum metadata.
//!
//! Reads and writes go through a [`pgbr_storage::Storage`] reference so callers can stay
//! backend-agnostic — `Posix` today, `S3` / `Azure` / `GCS` / … as they land.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod archive;
pub mod backup;
pub mod format;
pub mod manifest;

use std::fmt;

use pgbr_io::IoError;
use pgbr_storage::StorageError;

pub use crate::archive::{DbHistoryEntry, InfoArchive};
pub use crate::backup::InfoBackup;
pub use crate::format::{InfoFile, InfoFormatError};
pub use crate::manifest::{Manifest, ManifestFile, ManifestLink, ManifestPath};

/// Failure surface for the `pgbr-info` crate.
#[derive(Debug)]
pub enum InfoError {
    /// An I/O operation against the file stream failed (read, write, flush, close).
    Io(IoError),
    /// The storage backend itself surfaced an error (path missing, permission, …).
    Storage(StorageError),
    /// The on-disk format was malformed or the checksum did not match.
    Format(InfoFormatError),
    /// A required `key` was missing from `section` while building a typed wrapper.
    MissingField {
        /// Name of the section that should have contained `key`.
        section: &'static str,
        /// Name of the key that was missing.
        key: &'static str,
    },
    /// A field value or section key was syntactically wrong (e.g. `[db:history]` row keys
    /// must parse as integers). `context` says where the failure happened, `value` is the
    /// offending text.
    InvalidValue {
        /// Free-form context (e.g. `"[db:history] key"`).
        context: String,
        /// The value that failed validation.
        value: String,
    },
    /// `serde_json` failed to parse / serialise a value. `context` describes which row
    /// or section the error came from so the diagnostic is actionable.
    Json {
        /// Free-form context describing where the failure occurred.
        context: String,
        /// Wrapped serde error.
        error: serde_json::Error,
    },
}

impl fmt::Display for InfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "info i/o error: {err}"),
            Self::Storage(err) => write!(f, "info storage error: {err}"),
            Self::Format(err) => write!(f, "info format error: {err}"),
            Self::MissingField { section, key } => {
                write!(f, "missing required field [{section}].{key}")
            }
            Self::InvalidValue { context, value } => {
                write!(f, "invalid value in {context}: {value}")
            }
            Self::Json { context, error } => write!(f, "json error in {context}: {error}"),
        }
    }
}

impl std::error::Error for InfoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Storage(err) => Some(err),
            Self::Format(err) => Some(err),
            Self::Json { error, .. } => Some(error),
            Self::MissingField { .. } | Self::InvalidValue { .. } => None,
        }
    }
}

impl From<IoError> for InfoError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

impl From<StorageError> for InfoError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::Io(io) => Self::Io(io),
            other => Self::Storage(other),
        }
    }
}

impl From<InfoFormatError> for InfoError {
    fn from(err: InfoFormatError) -> Self {
        Self::Format(err)
    }
}

impl From<serde_json::Error> for InfoError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json {
            context: "json".to_owned(),
            error: err,
        }
    }
}
