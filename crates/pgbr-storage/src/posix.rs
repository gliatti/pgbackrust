//! Filesystem-backed storage using `std::fs`.
//!
//! `Posix` is the local-disk backend. Every path passed to its trait methods is confined under
//! the configured `root` by `resolve` (GHSA-vq5g-8277-5pwc):
//!
//! - a relative path is lexically normalized (`.`, repeated separators and `..` collapse) and
//!   joined onto `root`; a `..` that would climb out of `root` is rejected;
//! - an absolute path is accepted only when it lies lexically *under* `root` (internal callers
//!   legitimately hand the backend already-rooted absolute paths, e.g. a manifest scan of
//!   `/var/lib/postgresql/data` on a backend rooted there, or the paths `list` itself returned);
//!   any other absolute path is rejected.
//!
//! Rejections surface as [`StorageError::Backend`] whose message starts with `path validation`
//! (see [`crate::path_validate::normalize_under_root`]). The check is purely lexical: it does
//! not follow symlinks.
//!
//! This is defense in depth. Untrusted (network-sourced) paths are still validated first by
//! [`crate::path_validate::validate_relative`] in [`crate::remote::StorageRequestHandler`], and
//! the `repo-*` commands confine their user-supplied path parameters before reaching the
//! backend; `resolve` is the last line that guarantees no caller can read, write or delete
//! outside the storage root. See `path_validate.rs`.
//!
//! `PosixRead` / `PosixWrite` adapt `std::fs::File` into the `IoRead` / `IoWrite` traits from
//! `pgbr-io`. When `pgbr-io` ships dedicated `FileRead` / `FileWrite` types in a later phase
//! these private adapters can be replaced by simple re-exports.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use pgbr_io::{IoError, IoRead, IoWrite};

use crate::{Storage, StorageError, StorageInfo, StorageKind};

/// Local-filesystem storage backend rooted at `root`.
///
/// Relative paths passed to the trait methods are normalized and joined onto `root`; absolute
/// paths are accepted only when they lie under `root`. Anything that would escape `root` is
/// rejected.
///
/// Every file and directory the backend creates gets an explicit mode
/// (`file_mode` / `path_mode`, Unix only) instead of the process default: with
/// `neutral-umask` the umask is `0000`, so relying on `std::fs` defaults would
/// publish world-writable `0666` / `0777` entries (GHSA-5qj2-9x5v-7c87).
#[derive(Debug, Clone)]
pub struct Posix {
    root: PathBuf,
    file_mode: u32,
    path_mode: u32,
}

impl Posix {
    /// Build a `Posix` backend rooted at `root`, creating files with
    /// [`crate::REPO_FILE_MODE`] (`0640`) and directories with
    /// [`crate::REPO_PATH_MODE`] (`0750`).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_modes(root, crate::REPO_FILE_MODE, crate::REPO_PATH_MODE)
    }

    /// Build a `Posix` backend rooted at `root` that creates files with
    /// `file_mode` and directories with `path_mode` (e.g. `0600` / `0700` for a
    /// PG data directory). The modes are applied at creation time on
    /// Unix and ignored elsewhere.
    #[must_use]
    pub fn with_modes(root: impl Into<PathBuf>, file_mode: u32, path_mode: u32) -> Self {
        Self {
            root: root.into(),
            file_mode,
            path_mode,
        }
    }

    /// Configured root. Useful for diagnostics and tests.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve `path` against the configured root, confining it under `root`.
    ///
    /// The path is lexically normalized by
    /// [`crate::path_validate::normalize_under_root`]: a relative path is
    /// joined onto `root` once `.` / `..` are collapsed, and an absolute path
    /// is accepted only when it already lies under `root` (internal callers
    /// pass such already-rooted paths, e.g. entries returned by `list`). The
    /// root itself (`.`, `""` or `root` verbatim) resolves to `root`.
    ///
    /// # Errors
    ///
    /// [`StorageError::Backend`] (message starting with `path validation`)
    /// when `path` is absolute but not under `root`, or climbs out of `root`
    /// via `..` components. Nothing is touched on disk in that case.
    fn resolve(&self, path: &Path) -> Result<PathBuf, StorageError> {
        let rel = crate::path_validate::normalize_under_root(&self.root, path)?;
        // `root.join("")` would append a trailing separator; keep the root
        // spelled exactly as configured when `path` designates the root.
        if rel.as_os_str().is_empty() {
            return Ok(self.root.clone());
        }
        Ok(self.root.join(rel))
    }
}

#[allow(clippy::cast_possible_wrap)]
fn modified_secs(meta: &fs::Metadata) -> Option<i64> {
    let modified = meta.modified().ok()?;
    let duration = modified.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    // Saturate on overflow rather than panic; mtimes past year 292277026596 are not a concern,
    // but `i64::try_from` keeps clippy quiet about silent truncation.
    Some(i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}

pub(crate) fn map_io(err: &std::io::Error, path: &Path) -> StorageError {
    match err.kind() {
        std::io::ErrorKind::NotFound => StorageError::NotFound {
            path: path.to_path_buf(),
        },
        std::io::ErrorKind::AlreadyExists => StorageError::AlreadyExists {
            path: path.to_path_buf(),
        },
        std::io::ErrorKind::PermissionDenied => StorageError::PermissionDenied {
            path: path.to_path_buf(),
        },
        _ => StorageError::Backend {
            path: path.to_path_buf(),
            message: err.to_string(),
        },
    }
}

/// Open `path` for writing, creating it if missing and truncating it otherwise
/// (the `std::fs::File::create` semantics). When `mode` is `Some` the file is
/// *created* with that mode on Unix (`open(2)` `O_CREAT` mode, still subject to
/// the umask), so it is never briefly visible with a looser default; an
/// existing file keeps its mode. `mode` is ignored on non-Unix platforms.
pub(crate) fn open_create_truncate(path: &Path, mode: Option<u32>) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(mode) = mode {
            options.mode(mode);
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
}

/// Create the directory `path` (and, when `recursive`, every missing parent).
/// On Unix each directory created gets `mode` (`mkdir(2)` mode, still subject
/// to the umask); pre-existing directories are left untouched. On non-Unix
/// platforms `mode` is ignored. Semantics otherwise match `fs::create_dir` /
/// `fs::create_dir_all`.
pub(crate) fn create_dir_with_mode(path: &Path, mode: u32, recursive: bool) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    builder.create(path)
}

/// Crash-safe local write: stream `bytes` to `<path>.tmp`, `fsync(2)` the
/// data, `rename(2)` onto `path`, then `fsync(2)` the parent directory.
/// `rename(2)` is atomic on POSIX, so a concurrent reader (or a crash before
/// the rename completes) never observes a half-written or truncated primary
/// file; the trailing directory fsync makes the published name itself durable
/// across a power loss (on Unix — a clean no-op on Windows).
///
/// `path` must be the fully-resolved (root-joined) target path — this helper
/// does no path resolution.
///
/// When `mode` is `Some`, the temp file is *created* with that mode (Unix
/// only; see [`open_create_truncate`]) and the rename publishes it as-is, so
/// the primary never exists with a looser default mode. `None` keeps the
/// historical `File::create` behaviour (`0666` minus the umask).
///
/// # Errors
///
/// Surfaces any backend / I/O failure from `create`, `write_all`, `sync_all`,
/// or `rename` as a [`StorageError`]. On a rename failure the temp file is
/// left in place (it carries the would-be-new content); callers should treat
/// the write as failed and ignore the stale temp file (a subsequent
/// successful write will replace it).
pub(crate) fn write_atomic_local(path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<(), StorageError> {
    // Sibling temp path. We append `.tmp` to the file name (not a directory of
    // its own) so it lives in the same directory as `path` and the rename
    // crosses no filesystem boundary — `rename(2)` is only atomic within a
    // single filesystem.
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = PathBuf::from(tmp_name);

    // Best-effort cleanup of any leftover temp from a previous crashed write;
    // a missing file is fine. We don't surface this error: if the create
    // below fails for the same reason, we'll report that.
    let _ = fs::remove_file(&tmp_path);

    // Create + write + fsync.
    {
        let mut file = open_create_truncate(&tmp_path, mode).map_err(|err| map_io(&err, &tmp_path))?;
        Write::write_all(&mut file, bytes).map_err(|err| map_io(&err, &tmp_path))?;
        file.sync_all().map_err(|err| map_io(&err, &tmp_path))?;
        // `file` is dropped here — closes the fd before the rename.
    }

    // Atomic publish.
    fs::rename(&tmp_path, path).map_err(|err| map_io(&err, path))?;

    // Durability of the rename itself: `rename(2)` is atomic, but the updated
    // directory entry only survives a power loss once the *parent directory* is
    // fsync'd. Without this a crash right after the rename can leave the
    // directory reflecting neither the old nor the new name, defeating the
    // "atomic across power loss" promise. On Windows there is no directory fd to
    // fsync (NTFS metadata journalling makes the rename durable), so this is a
    // clean no-op there.
    fsync_parent_dir(path)
}

/// fsync the directory containing `path` so a just-published rename survives a
/// power loss. No-op on platforms (Windows) where directories cannot be opened
/// as a file handle for `sync_all`.
#[cfg(unix)]
pub(crate) fn fsync_parent_dir(path: &Path) -> Result<(), StorageError> {
    // A resolved target always has a parent (it lives under `root`); fall back
    // to "." defensively so we never index past the start of the path.
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let dir = fs::File::open(parent).map_err(|err| map_io(&err, parent))?;
    dir.sync_all().map_err(|err| map_io(&err, parent))
}

#[cfg(not(unix))]
pub(crate) fn fsync_parent_dir(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

fn info_from_metadata(path: PathBuf, meta: &fs::Metadata) -> StorageInfo {
    let kind = if meta.is_file() {
        StorageKind::File
    } else if meta.is_dir() {
        StorageKind::Path
    } else if meta.is_symlink() {
        StorageKind::Link
    } else {
        StorageKind::Special
    };
    let size = if matches!(kind, StorageKind::File) { meta.len() } else { 0 };
    StorageInfo {
        path,
        kind,
        size,
        modified: modified_secs(meta),
    }
}

impl Storage for Posix {
    fn is_local(&self) -> bool {
        true
    }

    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        let resolved = self.resolve(path)?;
        match fs::symlink_metadata(&resolved) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(map_io(&err, &resolved)),
        }
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        let resolved = self.resolve(path)?;
        let meta = fs::symlink_metadata(&resolved).map_err(|err| map_io(&err, &resolved))?;
        Ok(info_from_metadata(resolved, &meta))
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        let resolved = self.resolve(path)?;
        let read_dir = fs::read_dir(&resolved).map_err(|err| map_io(&err, &resolved))?;
        let mut entries: Vec<StorageInfo> = Vec::new();
        for entry in read_dir {
            let entry = entry.map_err(|err| map_io(&err, &resolved))?;
            let entry_path = entry.path();
            let meta = fs::symlink_metadata(&entry_path).map_err(|err| map_io(&err, &entry_path))?;
            entries.push(info_from_metadata(entry_path, &meta));
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        let resolved = self.resolve(path)?;
        let file = fs::File::open(&resolved).map_err(|err| map_io(&err, &resolved))?;
        Ok(Box::new(PosixRead {
            file,
            path: resolved,
            eof: false,
        }))
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        let resolved = self.resolve(path)?;
        let file = open_create_truncate(&resolved, Some(self.file_mode)).map_err(|err| map_io(&err, &resolved))?;
        Ok(Box::new(PosixWrite {
            file: Some(file),
            path: resolved,
        }))
    }

    /// Crash-safe write for the local filesystem: bytes are streamed to a
    /// sibling `<path>.tmp` file, fsync'd to disk, and `std::fs::rename`d
    /// onto `path`. On POSIX `rename(2)` is atomic across power loss within
    /// the same directory, so a concurrent reader (or a crash mid-write)
    /// never observes a half-written primary.
    fn write_atomic_path(&self, path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        let resolved = self.resolve(path)?;
        write_atomic_local(&resolved, bytes, Some(self.file_mode))
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path)?;
        match fs::remove_file(&resolved) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !error_on_missing => Ok(()),
            Err(err) => Err(map_io(&err, &resolved)),
        }
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        let resolved_source = self.resolve(source)?;
        let resolved_target = self.resolve(target)?;
        fs::rename(&resolved_source, &resolved_target).map_err(|err| map_io(&err, &resolved_source))
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path)?;
        create_dir_with_mode(&resolved, self.path_mode, recursive).map_err(|err| map_io(&err, &resolved))
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path)?;
        let result = if recursive {
            fs::remove_dir_all(&resolved)
        } else {
            fs::remove_dir(&resolved)
        };
        match result {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !error_on_missing => Ok(()),
            Err(err) => Err(map_io(&err, &resolved)),
        }
    }

    fn create_symlink(&self, link_path: &Path, target: &Path) -> Result<(), StorageError> {
        // `link_path` is resolved against the configured root (it is a path inside
        // the managed tree); `target` is written into the link verbatim, exactly as
        // pgBackRust records it in the manifest (typically an absolute path).
        let resolved = self.resolve(link_path)?;
        std::os::unix::fs::symlink(target, &resolved).map_err(|err| map_io(&err, &resolved))
    }

    fn read_link(&self, path: &Path) -> Result<PathBuf, StorageError> {
        // `path` is resolved against the configured root; the returned target is
        // whatever the link stores verbatim (typically an absolute path), which
        // is exactly what a backup records in the manifest and what a restore
        // hands back to `create_symlink`.
        let resolved = self.resolve(path)?;
        fs::read_link(&resolved).map_err(|err| map_io(&err, &resolved))
    }
}

/// Adapter that exposes a `std::fs::File` as a [`pgbr_io::IoRead`].
///
/// Replace with `pgbr_io::FileRead` once that type ships.
struct PosixRead {
    file: fs::File,
    path: PathBuf,
    eof: bool,
}

impl IoRead for PosixRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let n = Read::read(&mut self.file, buf).map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

/// Adapter that exposes a `std::fs::File` as a [`pgbr_io::IoWrite`].
///
/// Replace with `pgbr_io::FileWrite` once that type ships.
struct PosixWrite {
    file: Option<fs::File>,
    path: PathBuf,
}

impl IoWrite for PosixWrite {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        let file = self.file.as_mut().ok_or(IoError::Closed)?;
        Write::write_all(file, buf).map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))
    }

    fn flush(&mut self) -> Result<(), IoError> {
        let file = self.file.as_mut().ok_or(IoError::Closed)?;
        Write::flush(file).map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))
    }

    fn close(&mut self) -> Result<(), IoError> {
        if let Some(file) = self.file.take() {
            file.sync_all()
                .map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    #[test]
    fn posix_info_for_file_returns_size() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        write_file(&tmp.path().join("hello.txt"), b"hello world");

        let info = storage.info(Path::new("hello.txt")).unwrap();
        assert_eq!(info.kind, StorageKind::File);
        assert_eq!(info.size, 11);
        assert_eq!(info.path, tmp.path().join("hello.txt"));
        assert!(info.modified.is_some());
    }

    #[test]
    fn posix_exists_true_for_existing_file_false_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        write_file(&tmp.path().join("present"), b"x");

        assert!(storage.exists(Path::new("present")).unwrap());
        assert!(!storage.exists(Path::new("absent")).unwrap());
    }

    #[test]
    fn posix_list_returns_sorted_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        write_file(&tmp.path().join("c.txt"), b"c");
        write_file(&tmp.path().join("a.txt"), b"a");
        write_file(&tmp.path().join("b.txt"), b"b");
        fs::create_dir(tmp.path().join("d_dir")).unwrap();

        let entries = storage.list(Path::new(".")).unwrap();
        let names: Vec<_> = entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.txt", "b.txt", "c.txt", "d_dir"]);

        let dir_entry = entries.iter().find(|e| e.path.ends_with("d_dir")).unwrap();
        assert_eq!(dir_entry.kind, StorageKind::Path);
        assert_eq!(dir_entry.size, 0);
    }

    #[test]
    fn posix_open_read_then_open_write_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        {
            let mut writer = storage.open_write(Path::new("payload.bin")).unwrap();
            writer.write(b"abc").unwrap();
            writer.write(b"def").unwrap();
            writer.close().unwrap();
        }

        let mut reader = storage.open_read(Path::new("payload.bin")).unwrap();
        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"abcdef");

        // Subsequent read returns 0 (EOF).
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn posix_remove_with_error_on_missing_false_succeeds_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        // No file exists; should be a no-op.
        storage.remove(Path::new("ghost"), false).unwrap();
    }

    #[test]
    fn posix_remove_with_error_on_missing_true_errors_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        let err = storage.remove(Path::new("ghost"), true).unwrap_err();
        match err {
            StorageError::NotFound { path } => assert_eq!(path, tmp.path().join("ghost")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn posix_rename_moves_file() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        write_file(&tmp.path().join("src"), b"payload");

        storage.rename(Path::new("src"), Path::new("dst")).unwrap();
        assert!(!tmp.path().join("src").exists());
        assert_eq!(fs::read(tmp.path().join("dst")).unwrap(), b"payload");
    }

    #[test]
    fn posix_create_path_recursive() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        // Non-recursive on a missing parent should fail.
        let err = storage.create_path(Path::new("a/b/c"), false).unwrap_err();
        assert!(matches!(err, StorageError::NotFound { .. } | StorageError::Backend { .. }));

        storage.create_path(Path::new("a/b/c"), true).unwrap();
        assert!(tmp.path().join("a/b/c").is_dir());
    }

    #[test]
    fn posix_remove_path_recursive() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        storage.create_path(Path::new("nest/inner"), true).unwrap();
        write_file(&tmp.path().join("nest/inner/file"), b"x");

        // Non-recursive remove on non-empty dir should error.
        let err = storage.remove_path(Path::new("nest"), false, true).unwrap_err();
        assert!(matches!(
            err,
            StorageError::Backend { .. } | StorageError::PermissionDenied { .. }
        ));

        storage.remove_path(Path::new("nest"), true, true).unwrap();
        assert!(!tmp.path().join("nest").exists());

        // Missing path with error_on_missing=false is OK.
        storage.remove_path(Path::new("nest"), true, false).unwrap();
    }

    #[test]
    fn posix_info_not_found_returns_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        let err = storage.info(Path::new("nope")).unwrap_err();
        match err {
            StorageError::NotFound { path } => assert_eq!(path, tmp.path().join("nope")),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn posix_create_symlink_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        // Materialise a real target so the link resolves to it.
        write_file(&tmp.path().join("real_dir_placeholder"), b"x");
        let target = tmp.path().join("real_dir_placeholder");

        storage.create_symlink(Path::new("pg_wal"), &target).unwrap();

        // The link exists, is reported as a Link, and reads back the target verbatim.
        let info = storage.info(Path::new("pg_wal")).unwrap();
        assert_eq!(info.kind, StorageKind::Link, "created entry must be a symlink");
        let read = fs::read_link(tmp.path().join("pg_wal")).unwrap();
        assert_eq!(read, target, "symlink must point at the recorded target");
    }

    /// Permission bits (`& 0o777`) of `path`.
    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Assert `path` was created with `expected`: no bit beyond `expected` is
    /// set, and the owner bits are intact. Written this way (rather than
    /// `mode == expected`) so the check holds under any sane umask, while
    /// still rejecting the historical `0666`/`0777`-minus-umask defaults.
    #[cfg(unix)]
    fn assert_created_with(path: &Path, expected: u32) {
        let actual = mode_of(path);
        assert_eq!(
            actual & !expected,
            0,
            "{}: mode {actual:o} is looser than {expected:o}",
            path.display()
        );
        assert_eq!(
            actual & 0o700,
            expected & 0o700,
            "{}: owner bits of {actual:o} differ from {expected:o}",
            path.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_open_write_creates_file_0640() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        let mut writer = storage.open_write(Path::new("file.bin")).unwrap();
        writer.write(b"x").unwrap();
        writer.close().unwrap();

        assert_created_with(&tmp.path().join("file.bin"), 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn posix_create_path_recursive_creates_every_level_0750() {
        let tmp = tempfile::tempdir().unwrap();
        let root_mode = mode_of(tmp.path());
        let storage = Posix::new(tmp.path());

        storage.create_path(Path::new("a/b/c"), true).unwrap();
        for level in ["a", "a/b", "a/b/c"] {
            assert_created_with(&tmp.path().join(level), 0o750);
        }
        // The pre-existing root is not touched.
        assert_eq!(mode_of(tmp.path()), root_mode);

        // Non-recursive create gets the same mode.
        storage.create_path(Path::new("single"), false).unwrap();
        assert_created_with(&tmp.path().join("single"), 0o750);
    }

    #[cfg(unix)]
    #[test]
    fn posix_write_atomic_path_creates_file_0640() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());

        storage.write_atomic_path(Path::new("backup.info"), b"payload").unwrap();

        let published = tmp.path().join("backup.info");
        assert_eq!(fs::read(&published).unwrap(), b"payload");
        assert_created_with(&published, 0o640);
        assert!(!tmp.path().join("backup.info.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn posix_with_modes_is_honoured() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::with_modes(tmp.path(), 0o600, 0o700);

        storage.create_path(Path::new("pg/sub"), true).unwrap();
        assert_created_with(&tmp.path().join("pg"), 0o700);
        assert_created_with(&tmp.path().join("pg/sub"), 0o700);

        let mut writer = storage.open_write(Path::new("pg/sub/file")).unwrap();
        writer.write(b"x").unwrap();
        writer.close().unwrap();
        assert_created_with(&tmp.path().join("pg/sub/file"), 0o600);

        storage.write_atomic_path(Path::new("pg/backup_label"), b"label").unwrap();
        assert_created_with(&tmp.path().join("pg/backup_label"), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_file_without_mode_keeps_historical_default() {
        let tmp = tempfile::tempdir().unwrap();

        // Reference: what a plain `File::create` produces under this umask.
        let reference = tmp.path().join("reference");
        fs::File::create(&reference).unwrap();

        let target = tmp.path().join("target");
        crate::atomic_write_file(&target, b"data").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"data");
        assert_eq!(mode_of(&target), mode_of(&reference));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_file_mode_creates_with_requested_mode() {
        let tmp = tempfile::tempdir().unwrap();

        let target = tmp.path().join("segment");
        crate::atomic_write_file_mode(&target, b"wal", Some(0o600)).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"wal");
        assert_created_with(&target, 0o600);

        // `None` is the historical behaviour.
        let reference = tmp.path().join("reference");
        fs::File::create(&reference).unwrap();
        let plain = tmp.path().join("plain");
        crate::atomic_write_file_mode(&plain, b"x", None).unwrap();
        assert_eq!(mode_of(&plain), mode_of(&reference));
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_all_mode_applies_mode_to_created_dirs_only() {
        let tmp = tempfile::tempdir().unwrap();
        let existing = tmp.path().join("existing");
        fs::create_dir(&existing).unwrap();
        crate::set_path_mode(&existing, 0o755).unwrap();

        crate::create_dir_all_mode(&existing.join("x/y"), 0o770).unwrap();
        assert_created_with(&existing.join("x"), 0o770);
        assert_created_with(&existing.join("x/y"), 0o770);
        assert_eq!(mode_of(&existing), 0o755);

        // Already present: a no-op, not an error.
        crate::create_dir_all_mode(&existing.join("x/y"), 0o770).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn set_path_mode_changes_mode_and_errors_on_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        fs::File::create(&file).unwrap();

        crate::set_path_mode(&file, 0o600).unwrap();
        assert_eq!(mode_of(&file), 0o600);
        crate::set_path_mode(&file, 0o640).unwrap();
        assert_eq!(mode_of(&file), 0o640);

        let err = crate::set_path_mode(&tmp.path().join("missing"), 0o600).unwrap_err();
        assert!(matches!(err, StorageError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn posix_relative_path_resolves_against_root() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        write_file(&tmp.path().join("rel.txt"), b"r");

        // Relative path resolves to root/rel.txt.
        let info = storage.info(Path::new("rel.txt")).unwrap();
        assert_eq!(info.path, tmp.path().join("rel.txt"));

        // An absolute path already under the root resolves to the same file.
        let info_abs = storage.info(&tmp.path().join("rel.txt")).unwrap();
        assert_eq!(info_abs.path, tmp.path().join("rel.txt"));

        // An absolute path outside the root is now rejected (GHSA-vq5g-8277-5pwc).
        let other_tmp = tempfile::tempdir().unwrap();
        write_file(&other_tmp.path().join("outside.txt"), b"o");
        let err = storage.info(&other_tmp.path().join("outside.txt")).unwrap_err();
        assert!(matches!(err, StorageError::Backend { .. }), "got {err:?}");
    }

    /// Assert `err` is the `path validation` rejection and its message contains `needle`.
    fn assert_path_validation(err: &StorageError, needle: &str) {
        match err {
            StorageError::Backend { message, .. } => {
                assert!(message.contains("path validation"), "unexpected message: {message}");
                assert!(message.contains(needle), "message {message:?} lacks {needle:?}");
            }
            other => panic!("expected Backend path-validation error, got {other:?}"),
        }
    }

    #[test]
    fn posix_absolute_under_root_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        fs::create_dir(tmp.path().join("sub")).unwrap();
        write_file(&tmp.path().join("sub/inside.txt"), b"inside");

        let mut reader = storage.open_read(&tmp.path().join("sub/inside.txt")).unwrap();
        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"inside");

        // The root itself, spelled absolutely, lists the root.
        let entries = storage.list(tmp.path()).unwrap();
        assert!(entries.iter().any(|e| e.path.ends_with("sub")));
    }

    #[test]
    fn posix_absolute_outside_root_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        let other_tmp = tempfile::tempdir().unwrap();
        let outside = other_tmp.path().join("secret.txt");
        write_file(&outside, b"secret");

        let Err(err) = storage.open_read(&outside) else {
            panic!("open_read of a path outside the root must fail");
        };
        assert_path_validation(&err, "not under the storage root");

        // Writes and deletes outside the root are refused too, leaving the file intact.
        let Err(err) = storage.open_write(&outside) else {
            panic!("open_write of a path outside the root must fail");
        };
        assert_path_validation(&err, "not under the storage root");
        let err = storage.remove(&outside, true).unwrap_err();
        assert_path_validation(&err, "not under the storage root");
        assert_eq!(fs::read(&outside).unwrap(), b"secret");
    }

    #[test]
    fn posix_parent_escape_rejected() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        fs::create_dir(&root).unwrap();
        // A real file one level above the root: a successful escape would find it.
        write_file(&parent.path().join("x"), b"escaped");
        let storage = Posix::new(&root);

        let err = storage.list(Path::new("..")).unwrap_err();
        assert_path_validation(&err, "escapes");
        let Err(err) = storage.open_read(Path::new("../x")) else {
            panic!("open_read of ../x must fail");
        };
        assert_path_validation(&err, "escapes");
        let err = storage.exists(Path::new("sub/../../x")).unwrap_err();
        assert_path_validation(&err, "escapes");
        let err = storage.remove(Path::new("../x"), true).unwrap_err();
        assert_path_validation(&err, "escapes");
        assert_eq!(fs::read(parent.path().join("x")).unwrap(), b"escaped");
    }

    #[test]
    fn posix_dot_dot_inside_root_normalizes() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        write_file(&tmp.path().join("f"), b"normalized");

        // `sub` need not exist: normalization is lexical.
        let mut reader = storage.open_read(Path::new("sub/../f")).unwrap();
        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"normalized");

        let info = storage.info(Path::new("./sub/./../f")).unwrap();
        assert_eq!(info.path, tmp.path().join("f"));
    }
}
