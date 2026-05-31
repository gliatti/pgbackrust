#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Polymorphic storage backend interface for the pgBackRust C->Rust migration.
//!
//! Mirrors the C `Storage` abstraction in `src/storage/storage.h` — every command (backup,
//! restore, archive-get/push, expire, verify, …) accesses repositories and PG data through
//! this interface, with concrete backends for posix, s3, azure, gcs, cifs, and sftp.
//!
//! This crate ships the trait shape (designed so non-posix backends can plug in cleanly) and
//! a working `Posix` backend backed by `std::fs`. Other backends are added by later phases.
//!
//! Trait-level guarantees:
//!
//! - All paths are passed as `&Path`. Backends decide how to interpret them; `Posix` resolves
//!   relative paths against the configured root and accepts absolute paths verbatim.
//! - Error returns are typed via [`StorageError`]. `IoError` from streaming operations is
//!   convertible into `StorageError::Io` so backends can use `?`.
//! - `list` returns a materialised `Vec<StorageInfo>` for now. Iterators / streaming will be
//!   added when the manifest scan code is migrated and the perf cost is observable.
//! - No method takes `&mut self`. Backends that need mutable state (connection pools, caches)
//!   wrap it in interior mutability so callers can share a single `Arc<dyn Storage>` across
//!   threads.

#![cfg_attr(not(test), forbid(unsafe_code))]

use std::fmt;
use std::path::{Path, PathBuf};

use pgbr_io::{IoError, IoRead, IoWrite};

pub mod azure;
pub mod cifs;
pub mod gcs;
pub mod http;
pub mod posix;
pub mod remote;
pub mod s3;
pub mod sftp;

pub use crate::azure::{Azure, AzureAuth, AzureConfig};
pub use crate::cifs::Cifs;
pub use crate::gcs::{Gcs, GcsAuth, GcsConfig};
pub use crate::http::HttpOptions;
pub use crate::posix::Posix;
pub use crate::remote::{RemoteStorage, StorageInfoDto, StorageKindDto, StorageRequestHandler};
pub use crate::s3::{S3, S3Config};
pub use crate::sftp::{Sftp, SftpAuth, SftpConfig};

/// Metadata about an entry in a storage backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageInfo {
    /// Absolute or backend-resolved path of the entry.
    pub path: PathBuf,
    /// What kind of entry this is.
    pub kind: StorageKind,
    /// Size in bytes for files; `0` for non-files.
    pub size: u64,
    /// Last-modified time as Unix epoch seconds, if the backend tracks it.
    pub modified: Option<i64>,
}

/// Type of an entry returned by [`Storage::info`] / [`Storage::list`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    /// A regular file.
    File,
    /// A directory ("path" in pgBackRest C parlance).
    Path,
    /// A symbolic link.
    Link,
    /// Anything else: device, socket, FIFO, …
    Special,
}

/// Typed failure returned by every [`Storage`] method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// The path does not exist.
    NotFound { path: PathBuf },
    /// The path already exists when an exclusive create was requested.
    AlreadyExists { path: PathBuf },
    /// The current process lacks permission for the operation.
    PermissionDenied { path: PathBuf },
    /// Wrapped error from the backend (filesystem, HTTP, …) that doesn't map to a category above.
    Backend { path: PathBuf, message: String },
    /// Raised by the [`IoRead`] / [`IoWrite`] layer when used through this backend.
    Io(IoError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { path } => write!(f, "not found: {}", path.display()),
            Self::AlreadyExists { path } => write!(f, "already exists: {}", path.display()),
            Self::PermissionDenied { path } => write!(f, "permission denied: {}", path.display()),
            Self::Backend { path, message } => write!(f, "backend error at {}: {message}", path.display()),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<IoError> for StorageError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

/// Polymorphic storage backend.
///
/// Designed to accommodate filesystem, object-store, and SSH-tunneled backends. Implementations
/// must be `Send + Sync` so callers can share a single instance across worker threads.
pub trait Storage: Send + Sync {
    /// Whether `path` exists.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the existence check itself fails (e.g. permission denied
    /// on a parent directory). A missing path is reported as `Ok(false)`, not an error.
    fn exists(&self, path: &Path) -> Result<bool, StorageError>;

    /// Inspect `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if `path` does not exist; other [`StorageError`]
    /// variants for permission / backend failures.
    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError>;

    /// List entries in a directory. Entries are returned in a deterministic (sorted) order.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if `path` does not exist or is not a directory.
    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError>;

    /// Open a file for reading.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if the file does not exist.
    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError>;

    /// Open a file for writing. Truncates if the file exists, creates it otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] for permission / backend failures.
    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError>;

    /// Write `bytes` to `path` as a single all-or-nothing operation.
    ///
    /// On local filesystem backends (see [`Storage::is_local`]) this is a
    /// crash-safe write: the bytes go to a sibling temporary path that is
    /// fsync'd and then atomically renamed onto `path`, so a concurrent
    /// reader (or a crash mid-write) never observes a half-written or
    /// truncated primary. On remote/object-store backends the default
    /// implementation falls back to a plain [`Storage::open_write`] +
    /// `write_all` + `close`, which is not atomic from the local POSIX point
    /// of view but is the strongest single-call guarantee the backend
    /// offers.
    ///
    /// pgBackRest uses this for the small "info" files
    /// (`archive.info`, `backup.info`, and their `.copy` mirrors) so a
    /// process crash in the middle of `save_keyed` cannot leave the primary
    /// truncated; the `.copy` mirror written first acts as a recoverable
    /// fallback on the load side.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] for permission / backend / I/O failures. On
    /// backends that override this with a temp+rename, a failure during the
    /// rename leaves the temp file in place; callers should treat the write
    /// as failed and not assume any partial state.
    fn write_atomic_path(&self, path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        let mut writer = self.open_write(path)?;
        writer.write(bytes)?;
        writer.flush()?;
        writer.close()?;
        Ok(())
    }

    /// Remove a file. When `error_on_missing` is `false`, a missing file is treated as success.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if the file is missing and `error_on_missing` is `true`.
    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError>;

    /// Atomically rename `source` to `target`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] for permission / backend failures or if the source is missing.
    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError>;

    /// Create a directory. With `recursive = true`, missing parents are created as well.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::AlreadyExists`] if `path` already exists (non-recursive only),
    /// or other variants for permission / backend failures.
    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError>;

    /// Remove a directory. With `recursive = true`, contents are removed as well. With
    /// `error_on_missing = false`, a missing directory is treated as success.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if the directory is missing and `error_on_missing`
    /// is `true`; other variants for permission / backend / non-empty failures.
    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError>;

    /// Create a symbolic link at `link_path` pointing at `target`.
    ///
    /// Symlinks only make sense on a real filesystem, so this has a default
    /// implementation that returns a [`StorageError::Backend`] "symlinks not
    /// supported" error. Filesystem backends (e.g. [`Posix`]) override it; object
    /// stores and other non-filesystem backends keep the default.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] from the default implementation. Overriding
    /// backends return [`StorageError`] variants for permission / backend failures or
    /// [`StorageError::AlreadyExists`] when `link_path` already exists.
    fn create_symlink(&self, link_path: &Path, _target: &Path) -> Result<(), StorageError> {
        Err(StorageError::Backend {
            path: link_path.to_path_buf(),
            message: "symlinks not supported by this backend".to_owned(),
        })
    }

    /// Whether files on this backend live on the local filesystem and may be
    /// written via `std::fs` directly (the parallel-copy fast path), as opposed
    /// to backends whose writes must go through [`Storage::open_write`]
    /// (remote/object backends: SSH-tunneled, S3, Azure, GCS, SFTP).
    ///
    /// Defaults to `false` so any backend is treated as remote/safe — writing
    /// through `open_write` — unless it explicitly opts in. Only the local
    /// filesystem backends ([`Posix`] and [`Cifs`]) override this to `true`.
    fn is_local(&self) -> bool {
        false
    }
}
