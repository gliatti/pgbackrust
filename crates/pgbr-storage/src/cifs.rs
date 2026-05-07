//! `CIFS` / `SMB` storage backend.
//!
//! In practice `CIFS` shares mount as `POSIX`-looking paths, so this backend
//! delegates to [`Posix`] for every operation. The intended behavioural
//! difference is that [`IoWrite::close`] skips the `fsync`-equivalent: `SMB`
//! sync semantics are unreliable across the network, and pgBackRest's C side
//! treats `CIFS` sync as a no-op.
//!
//! The current implementation forwards `close` straight through to the
//! underlying `Posix` writer, which still calls `sync_all`. The trait shape
//! is in place so call sites can switch backend types today; the optimisation
//! lands once `Posix::open_write` exposes a sync-control knob.
// TODO: thread a `no_sync` flag through `Posix::open_write` so this backend
// can actually skip the fsync-on-close.

use std::path::{Path, PathBuf};

use pgbr_io::{IoError, IoRead, IoWrite};

use crate::{Posix, Storage, StorageError, StorageInfo};

/// `CIFS` / `SMB` storage backend. Wraps a [`Posix`] backend for the share's
/// mount point and forwards every operation to it.
#[derive(Debug, Clone)]
pub struct Cifs {
    inner: Posix,
}

impl Cifs {
    /// Build a `Cifs` backend rooted at `root` (the mount point of the share).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { inner: Posix::new(root) }
    }

    /// Configured root. Useful for diagnostics and tests.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.inner.root()
    }
}

impl Storage for Cifs {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        self.inner.exists(path)
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        self.inner.info(path)
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        self.inner.list(path)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        self.inner.open_read(path)
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        let underlying = self.inner.open_write(path)?;
        Ok(Box::new(CifsWrite { inner: underlying }))
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner.remove(path, error_on_missing)
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        self.inner.rename(source, target)
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        self.inner.create_path(path, recursive)
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner.remove_path(path, recursive, error_on_missing)
    }
}

/// Writer wrapper that documents the `CIFS` no-fsync intent. Today it forwards
/// every method to the underlying [`IoWrite`] verbatim; once the underlying
/// `Posix` writer exposes a sync-control knob, `close` here will request the
/// no-sync variant.
struct CifsWrite {
    inner: Box<dyn IoWrite>,
}

impl IoWrite for CifsWrite {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.inner.flush()
    }

    fn close(&mut self) -> Result<(), IoError> {
        // CIFS: this is the call we eventually want to skip the fsync on. For
        // now we forward to the underlying `Posix` close so the writer's
        // sink-state machine still records "closed" correctly. The C side
        // also performs no sync at this point.
        self.inner.close()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::fs;

    use super::*;
    use crate::{Posix, StorageKind};

    #[test]
    fn cifs_round_trips_through_posix() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Cifs::new(tmp.path());

        {
            let mut writer = storage.open_write(Path::new("payload.bin")).unwrap();
            writer.write(b"abc").unwrap();
            writer.write(b"def").unwrap();
            writer.flush().unwrap();
            writer.close().unwrap();
        }

        let mut reader = storage.open_read(Path::new("payload.bin")).unwrap();
        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"abcdef");
        let n2 = reader.read(&mut buf).unwrap();
        assert_eq!(n2, 0);
        assert!(reader.eof());
    }

    #[test]
    fn cifs_list_matches_posix() {
        let tmp = tempfile::tempdir().unwrap();
        // Pre-populate the directory.
        fs::write(tmp.path().join("a.txt"), b"a").unwrap();
        fs::write(tmp.path().join("c.txt"), b"cc").unwrap();
        fs::write(tmp.path().join("b.txt"), b"bbb").unwrap();
        fs::create_dir(tmp.path().join("sub")).unwrap();

        let cifs = Cifs::new(tmp.path());
        let posix = Posix::new(tmp.path());

        let cifs_entries = cifs.list(Path::new(".")).unwrap();
        let posix_entries = posix.list(Path::new(".")).unwrap();

        assert_eq!(cifs_entries, posix_entries);
        let names: Vec<_> = cifs_entries
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.txt", "b.txt", "c.txt", "sub"]);
        let sub = cifs_entries.iter().find(|e| e.path.ends_with("sub")).unwrap();
        assert_eq!(sub.kind, StorageKind::Path);
    }

    #[test]
    fn cifs_rename_works() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Cifs::new(tmp.path());
        fs::write(tmp.path().join("src"), b"payload").unwrap();

        storage.rename(Path::new("src"), Path::new("dst")).unwrap();

        assert!(!tmp.path().join("src").exists());
        assert_eq!(fs::read(tmp.path().join("dst")).unwrap(), b"payload");
    }

    #[test]
    fn cifs_remove_path_recursive() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Cifs::new(tmp.path());

        storage.create_path(Path::new("nest/inner"), true).unwrap();
        fs::write(tmp.path().join("nest/inner/file"), b"x").unwrap();

        storage.remove_path(Path::new("nest"), true, true).unwrap();
        assert!(!tmp.path().join("nest").exists());

        // Missing path with `error_on_missing = false` is a no-op.
        storage.remove_path(Path::new("nest"), true, false).unwrap();
    }

    #[test]
    fn cifs_root_accessor_returns_configured_root() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Cifs::new(tmp.path());
        assert_eq!(storage.root(), tmp.path());
    }
}
