//! Central path validation for network-sourced storage paths.
//!
//! A remote worker ([`crate::remote::StorageRequestHandler`]) executes
//! `storage-*` requests on behalf of a *peer* process reached over SSH / TLS.
//! The peer is not necessarily trusted to the same degree as local code: a
//! malicious or compromised peer must not be able to steer a `storage-read` /
//! `storage-write` / `storage-remove` / `storage-list` at an arbitrary file on
//! the worker host by sending either an absolute path (`/etc/passwd`) or a path
//! that climbs out of the repository root with `..` components
//! (`../../etc/passwd`).
//!
//! [`validate_relative`] enforces the single invariant that closes both holes:
//! the path must be **relative** and must contain **no `..` (`ParentDir`)
//! component**. Combined with a rooted [`crate::Posix`] whose `resolve` joins
//! onto its root, a path that satisfies this invariant can never escape the
//! root. Empty paths and lone `.` / plain-name components are allowed (they
//! stay inside the root); a `RootDir` / prefix (Windows drive) component makes
//! the path absolute and is therefore rejected.

use std::path::{Component, Path};

use crate::StorageError;

/// Reject any path that could escape a rooted storage backend.
///
/// A path is accepted only when it is relative **and** contains no parent-dir
/// (`..`) component. This is the guard applied to every path arriving from a
/// remote peer over the storage protocol before it is handed to the underlying
/// (rooted) [`Storage`](crate::Storage) backend, so the peer can neither pass
/// an absolute path nor climb above the configured root.
///
/// # Errors
///
/// Returns [`StorageError::Backend`] carrying `path` when the path is absolute
/// or contains a `..` component.
pub fn validate_relative(path: &Path) -> Result<(), StorageError> {
    if path.is_absolute() {
        return Err(StorageError::Backend {
            path: path.to_path_buf(),
            message: "path validation: absolute paths are not permitted from a remote peer".to_owned(),
        });
    }

    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(StorageError::Backend {
                    path: path.to_path_buf(),
                    message: "path validation: '..' (parent-dir) components are not permitted from a remote peer".to_owned(),
                });
            }
            // A `RootDir` or `Prefix` (Windows drive / UNC) component makes a
            // path absolute; `path.is_absolute()` above already caught it, but
            // reject defensively in case of a platform quirk.
            Component::RootDir | Component::Prefix(_) => {
                return Err(StorageError::Backend {
                    path: path.to_path_buf(),
                    message: "path validation: absolute paths are not permitted from a remote peer".to_owned(),
                });
            }
            // `Normal` (plain name) and `CurDir` (`.`) keep the path inside the
            // root — allowed.
            Component::Normal(_) | Component::CurDir => {}
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn accepts_plain_relative_path() {
        validate_relative(Path::new("archive/9.6-1/backup.info")).unwrap();
    }

    #[test]
    fn accepts_empty_path() {
        validate_relative(Path::new("")).unwrap();
    }

    #[test]
    fn accepts_current_dir_component() {
        validate_relative(Path::new("./backup/./info")).unwrap();
    }

    #[test]
    fn rejects_leading_parent_dir() {
        let err = validate_relative(Path::new("../../etc/passwd")).unwrap_err();
        match err {
            StorageError::Backend { message, .. } => assert!(message.contains("parent-dir")),
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_embedded_parent_dir() {
        let err = validate_relative(Path::new("archive/../../secret")).unwrap_err();
        assert!(matches!(err, StorageError::Backend { .. }));
    }

    #[test]
    fn rejects_unix_absolute_path() {
        let err = validate_relative(Path::new("/etc/passwd")).unwrap_err();
        match err {
            StorageError::Backend { path, message } => {
                assert_eq!(path, PathBuf::from("/etc/passwd"));
                assert!(message.contains("absolute"));
            }
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    #[cfg(windows)]
    fn rejects_windows_absolute_path() {
        let err = validate_relative(Path::new(r"C:\Windows\System32")).unwrap_err();
        assert!(matches!(err, StorageError::Backend { .. }));
    }

    #[test]
    #[cfg(windows)]
    fn rejects_windows_drive_relative_root() {
        // A bare backslash root is absolute on the current drive.
        let err = validate_relative(Path::new(r"\Windows")).unwrap_err();
        assert!(matches!(err, StorageError::Backend { .. }));
    }
}
