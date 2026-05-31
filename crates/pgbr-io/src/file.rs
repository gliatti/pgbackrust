//! File-backed [`IoRead`] / [`IoWrite`] implementations.
//!
//! [`FileRead`] wraps [`std::fs::File`] for read-only streaming. [`FileWrite`]
//! wraps it for write-only streaming with an explicit `close` step that
//! `fsync`s the file to durable storage — matching pgBackRest's POSIX storage
//! semantics. Errors carry the offending path so callers don't have to thread
//! it through manually.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::{IoError, IoRead, IoWrite};

/// Read-only view over a [`std::fs::File`] implementing [`IoRead`].
pub struct FileRead {
    path: PathBuf,
    file: File,
    eof: bool,
}

impl FileRead {
    /// Open `path` for reading.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] formatted as `"open {path}: {os_err}"` if
    /// the file cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IoError> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path).map_err(|err| IoError::Backend(format!("open {}: {err}", path.display())))?;
        Ok(Self { path, file, eof: false })
    }

    /// Path the stream was opened against — useful for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl IoRead for FileRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let n = self
            .file
            .read(buf)
            .map_err(|err| IoError::Backend(format!("read {}: {err}", self.path.display())))?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

/// Writable view over a [`std::fs::File`] implementing [`IoWrite`].
///
/// The inner `File` is held in an [`Option`] so [`IoWrite::close`] can drop it
/// (after `sync_all`) while keeping the [`FileWrite`] value alive for
/// idempotent re-`close` and useful diagnostics.
pub struct FileWrite {
    path: PathBuf,
    file: Option<File>,
}

impl FileWrite {
    /// Open `path` for writing, creating the file if needed and truncating any
    /// existing content.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] formatted as `"open {path}: {os_err}"` if
    /// the file cannot be opened.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, IoError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|err| IoError::Backend(format!("open {}: {err}", path.display())))?;
        Ok(Self { path, file: Some(file) })
    }

    /// Open `path` for writing, failing if the file already exists.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] formatted as `"open {path}: {os_err}"` if
    /// the file cannot be opened — including the `AlreadyExists` case.
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self, IoError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|err| IoError::Backend(format!("open {}: {err}", path.display())))?;
        Ok(Self { path, file: Some(file) })
    }

    /// Path the stream was opened against — useful for diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl IoWrite for FileWrite {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        let file = self.file.as_mut().ok_or(IoError::Closed)?;
        file.write_all(buf)
            .map_err(|err| IoError::Backend(format!("write {}: {err}", self.path.display())))
    }

    fn flush(&mut self) -> Result<(), IoError> {
        let file = self.file.as_mut().ok_or(IoError::Closed)?;
        file.flush()
            .map_err(|err| IoError::Backend(format!("flush {}: {err}", self.path.display())))
    }

    fn close(&mut self) -> Result<(), IoError> {
        // Idempotent: a second close is a no-op success.
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        file.sync_all()
            .map_err(|err| IoError::Backend(format!("sync {}: {err}", self.path.display())))?;
        // `file` drops here, releasing the OS handle.
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::{NamedTempFile, tempdir};

    #[test]
    fn file_read_drains_input() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"hello, file").unwrap();
        tmp.flush().unwrap();

        let mut r = FileRead::open(tmp.path()).unwrap();
        assert_eq!(r.path(), tmp.path());
        let bytes = r.read_all().unwrap();
        assert_eq!(bytes, b"hello, file");
        // EOF is observable after reading past end.
        let mut scratch = [0u8; 4];
        assert_eq!(r.read(&mut scratch).unwrap(), 0);
        assert!(r.eof());
    }

    #[test]
    fn file_read_short_read_then_eof() {
        let mut tmp = NamedTempFile::new().unwrap();
        let payload = vec![0xABu8; 100];
        tmp.write_all(&payload).unwrap();
        tmp.flush().unwrap();

        let mut r = FileRead::open(tmp.path()).unwrap();
        let mut total = 0usize;
        let mut last_n = 0usize;
        let mut chunk = [0u8; 30];
        loop {
            let n = r.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            total += n;
            last_n = n;
            assert!(n <= 30);
        }
        assert_eq!(total, 100);
        // Final non-zero chunk was the leftover 10 bytes (100 % 30 == 10).
        assert_eq!(last_n, 10);
        assert!(r.eof());
        // Subsequent calls keep returning 0 with eof set.
        assert_eq!(r.read(&mut chunk).unwrap(), 0);
        assert!(r.eof());
    }

    #[test]
    fn file_write_then_read_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");

        let mut w = FileWrite::create(&path).unwrap();
        assert_eq!(w.path(), path);
        w.write(b"hello, ").unwrap();
        w.write(b"file").unwrap();
        w.flush().unwrap();
        w.close().unwrap();

        let mut r = FileRead::open(&path).unwrap();
        assert_eq!(r.read_all().unwrap(), b"hello, file");
    }

    #[test]
    fn file_write_close_blocks_subsequent_writes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");

        let mut w = FileWrite::create(&path).unwrap();
        w.write(b"x").unwrap();
        w.close().unwrap();
        match w.write(b"y") {
            Err(IoError::Closed) => {}
            other => panic!("expected Closed, got {other:?}"),
        }
        match w.flush() {
            Err(IoError::Closed) => {}
            other => panic!("expected Closed from flush, got {other:?}"),
        }
    }

    #[test]
    fn file_write_close_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");

        let mut w = FileWrite::create(&path).unwrap();
        w.write(b"abc").unwrap();
        w.close().unwrap();
        // Second close: no error.
        w.close().unwrap();
        // Third for good measure.
        w.close().unwrap();
    }

    #[test]
    fn file_write_create_new_errors_when_file_exists() {
        let tmp = NamedTempFile::new().unwrap();
        match FileWrite::create_new(tmp.path()) {
            Err(IoError::Backend(msg)) => {
                assert!(
                    msg.starts_with("open "),
                    "expected message to start with 'open ', got {msg:?}"
                );
            }
            Ok(_) => panic!("create_new should have failed on existing path"),
            Err(other) => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn file_open_error_is_wrapped() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.bin");
        match FileRead::open(&missing) {
            Err(IoError::Backend(msg)) => {
                assert!(msg.starts_with("open "), "got {msg:?}");
                assert!(msg.contains("does-not-exist.bin"), "got {msg:?}");
            }
            Ok(_) => panic!("expected open to fail"),
            Err(other) => panic!("expected Backend, got {other:?}"),
        }
    }
}
