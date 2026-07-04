//! Filesystem-backed storage using `std::fs`.
//!
//! `Posix` is the local-disk backend. All paths passed to its trait methods are interpreted
//! relative to the configured `root` (or accepted verbatim if absolute). The wrapper does not
//! attempt to enforce a chroot — internal callers legitimately hand it already-rooted absolute
//! paths (e.g. a manifest scan of `/var/lib/postgresql/data`), so `resolve` cannot reject them.
//!
//! **Untrusted (network-sourced) paths are NOT validated here.** A path arriving from a remote
//! peer over the storage protocol is validated by [`crate::path_validate::validate_relative`]
//! in [`crate::remote::StorageRequestHandler`] *before* it reaches this backend: the peer may
//! neither pass an absolute path nor climb out of the root with `..`. Enforcing the chroot in
//! the worker (rather than in `resolve`) keeps the internal already-rooted callers working while
//! still closing the traversal hole for every network request. See `path_validate.rs`.
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

/// Local-filesystem storage backend rooted at `root`. Relative paths passed to the trait
/// methods are joined onto `root`; absolute paths are accepted verbatim.
#[derive(Debug, Clone)]
pub struct Posix {
    root: PathBuf,
}

impl Posix {
    /// Build a `Posix` backend rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Configured root. Useful for diagnostics and tests.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve `path` against the configured root.
    ///
    /// A relative path is joined onto `root`; an absolute path is accepted
    /// verbatim. This intentionally does **not** enforce a chroot: internal
    /// callers pass already-rooted absolute paths (a manifest scan of a PG
    /// data directory, a `.tmp` sibling built from an absolute target, …) and
    /// must keep working. Untrusted network-sourced paths never reach here
    /// un-validated — the remote worker checks them with
    /// [`crate::path_validate::validate_relative`] first (see the module docs).
    fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
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

fn map_io(err: &std::io::Error, path: &Path) -> StorageError {
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
/// # Errors
///
/// Surfaces any backend / I/O failure from `create`, `write_all`, `sync_all`,
/// or `rename` as a [`StorageError`]. On a rename failure the temp file is
/// left in place (it carries the would-be-new content); callers should treat
/// the write as failed and ignore the stale temp file (a subsequent
/// successful write will replace it).
pub(crate) fn write_atomic_local(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
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
        let mut file = fs::File::create(&tmp_path).map_err(|err| map_io(&err, &tmp_path))?;
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
fn fsync_parent_dir(path: &Path) -> Result<(), StorageError> {
    // A resolved target always has a parent (it lives under `root`); fall back
    // to "." defensively so we never index past the start of the path.
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let dir = fs::File::open(parent).map_err(|err| map_io(&err, parent))?;
    dir.sync_all().map_err(|err| map_io(&err, parent))
}

#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) -> Result<(), StorageError> {
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
        let resolved = self.resolve(path);
        match fs::symlink_metadata(&resolved) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(map_io(&err, &resolved)),
        }
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        let resolved = self.resolve(path);
        let meta = fs::symlink_metadata(&resolved).map_err(|err| map_io(&err, &resolved))?;
        Ok(info_from_metadata(resolved, &meta))
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        let resolved = self.resolve(path);
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
        let resolved = self.resolve(path);
        let file = fs::File::open(&resolved).map_err(|err| map_io(&err, &resolved))?;
        Ok(Box::new(PosixRead {
            file,
            path: resolved,
            eof: false,
        }))
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        let resolved = self.resolve(path);
        let file = fs::File::create(&resolved).map_err(|err| map_io(&err, &resolved))?;
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
        let resolved = self.resolve(path);
        write_atomic_local(&resolved, bytes)
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path);
        match fs::remove_file(&resolved) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !error_on_missing => Ok(()),
            Err(err) => Err(map_io(&err, &resolved)),
        }
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        let resolved_source = self.resolve(source);
        let resolved_target = self.resolve(target);
        fs::rename(&resolved_source, &resolved_target).map_err(|err| map_io(&err, &resolved_source))
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path);
        let result = if recursive {
            fs::create_dir_all(&resolved)
        } else {
            fs::create_dir(&resolved)
        };
        result.map_err(|err| map_io(&err, &resolved))
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path);
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
        let resolved = self.resolve(link_path);
        std::os::unix::fs::symlink(target, &resolved).map_err(|err| map_io(&err, &resolved))
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

    #[test]
    fn posix_relative_path_resolves_against_root() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Posix::new(tmp.path());
        write_file(&tmp.path().join("rel.txt"), b"r");

        // Relative path resolves to root/rel.txt.
        let info = storage.info(Path::new("rel.txt")).unwrap();
        assert_eq!(info.path, tmp.path().join("rel.txt"));

        // Absolute path is taken verbatim, ignoring root.
        let info_abs = storage.info(&tmp.path().join("rel.txt")).unwrap();
        assert_eq!(info_abs.path, tmp.path().join("rel.txt"));

        // An absolute path outside the root still works (and is not chrooted).
        let other_tmp = tempfile::tempdir().unwrap();
        write_file(&other_tmp.path().join("outside.txt"), b"o");
        let info_outside = storage.info(&other_tmp.path().join("outside.txt")).unwrap();
        assert_eq!(info_outside.path, other_tmp.path().join("outside.txt"));
    }
}
