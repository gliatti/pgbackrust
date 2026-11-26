//! Central path validation for untrusted storage paths.
//!
//! Two kinds of callers hand a storage backend a path it must not let escape
//! its configured root:
//!
//! - **Remote peers.** A remote worker ([`crate::remote::StorageRequestHandler`])
//!   executes `storage-*` requests on behalf of a *peer* process reached over
//!   SSH / TLS. A malicious or compromised peer must not be able to steer a
//!   `storage-read` / `storage-write` / `storage-remove` / `storage-list` at an
//!   arbitrary file on the worker host by sending either an absolute path
//!   (`/etc/passwd`) or a path that climbs out of the repository root with `..`
//!   components (`../../etc/passwd`). [`validate_relative`] guards this
//!   surface: the path must be **relative** and must contain **no `..`
//!   (`ParentDir`) component**.
//! - **`repo-*` commands** (`repo-ls`, `repo-get`, `repo-put`, `repo-rm`, see
//!   `GHSA-vq5g-8277-5pwc`). Their path argument is resolved under `repoN-path`.
//!   [`normalize_under_root`] (filesystem backends) and [`normalize_object_key`]
//!   (object stores) normalize the argument **lexically** — no filesystem
//!   access — and reject anything that would leave the root: a relative path
//!   whose `..` components climb above the root, or an absolute path that is
//!   not lexically under the configured root. An absolute path under the root
//!   is accepted and converted to the equivalent root-relative path.
//!
//! Combined with a rooted backend whose `resolve` joins onto its root, a path
//! that passed one of these guards can never escape the root.

use std::path::{Component, Path, PathBuf};

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

/// A path after lexical normalization: its anchor (`Prefix` / `RootDir`
/// components, empty for a relative path) followed by the remaining components.
///
/// `parts` holds only `Normal` components, except for leading `ParentDir`
/// components of a relative path whose `..` climbed above its start.
struct Lexical<'a> {
    anchor: Vec<Component<'a>>,
    parts: Vec<Component<'a>>,
}

impl Lexical<'_> {
    /// `true` when a `..` climbed above the start of a relative path.
    fn escapes(&self) -> bool {
        self.parts.iter().any(|component| matches!(component, Component::ParentDir))
    }
}

/// Lexically normalize `path` without touching the filesystem.
///
/// `.` and empty components collapse, and `..` pops the previous name. A `..`
/// at the anchor of a rooted path stays at the anchor (as `/..` is `/` on
/// POSIX); a `..` above the start of a relative path is kept as a leading
/// `ParentDir` so the caller can reject it.
fn lexical(path: &Path) -> Lexical<'_> {
    let mut anchor = Vec::new();
    let mut parts: Vec<Component<'_>> = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => anchor.push(component),
            Component::CurDir => {}
            Component::Normal(_) => parts.push(component),
            Component::ParentDir => {
                if matches!(parts.last(), Some(Component::Normal(_))) {
                    parts.pop();
                } else if anchor.is_empty() {
                    parts.push(component);
                }
            }
        }
    }

    Lexical { anchor, parts }
}

/// A path is rooted when it is absolute **or** starts with a `RootDir` /
/// `Prefix` component (on Windows `/etc` is not `is_absolute()` but is rooted).
fn is_rooted(path: &Path) -> bool {
    path.is_absolute() || matches!(path.components().next(), Some(Component::RootDir | Component::Prefix(_)))
}

fn escapes_root_error(path: &Path) -> StorageError {
    StorageError::Backend {
        path: path.to_path_buf(),
        message: "path validation: path escapes the storage root via '..' components".to_owned(),
    }
}

/// Confine `path` under the storage `root`, lexically.
///
/// A relative `path` is normalized (`.` and repeated separators collapse, `..`
/// pops the previous component); a `..` climbing above its start is rejected.
/// A rooted `path` (absolute, or starting with a root / prefix component) is
/// accepted only when, after normalizing both, it starts with every component
/// of `root`; the remainder is returned. The result is always relative to
/// `root` (possibly empty, meaning the root itself) and is ready to be joined
/// onto the backend root. No filesystem access is performed.
///
/// # Errors
///
/// Returns [`StorageError::Backend`] carrying `path` when a rooted `path` is
/// not lexically under `root`, or when a relative `path` escapes it via `..`.
pub fn normalize_under_root(root: &Path, path: &Path) -> Result<PathBuf, StorageError> {
    let normalized = lexical(path);

    if is_rooted(path) || !normalized.anchor.is_empty() {
        let root_normalized = lexical(root);
        let under_root = (is_rooted(root) || !root_normalized.anchor.is_empty())
            && normalized.anchor == root_normalized.anchor
            && normalized.parts.starts_with(&root_normalized.parts);

        if !under_root {
            return Err(StorageError::Backend {
                path: path.to_path_buf(),
                message: format!(
                    "path validation: absolute path is not under the storage root '{}'",
                    root.display()
                ),
            });
        }

        return Ok(normalized.parts.iter().skip(root_normalized.parts.len()).collect());
    }

    if normalized.escapes() {
        return Err(escapes_root_error(path));
    }

    Ok(normalized.parts.iter().collect())
}

/// Normalize `path` into an object-store key relative to the bucket root.
///
/// Backslashes become `/`, a leading root is dropped (the bucket root **is**
/// the repository root), `.` and empty segments collapse and `..` pops the
/// previous segment. The segments are joined with `/`; the root itself is `""`.
///
/// # Errors
///
/// Returns [`StorageError::Backend`] carrying `path` when a `..` segment climbs
/// above the root.
pub fn normalize_object_key(path: &Path) -> Result<String, StorageError> {
    let raw = path.to_string_lossy().replace('\\', "/");
    let mut segments: Vec<&str> = Vec::new();

    for segment in raw.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(escapes_root_error(path));
                }
            }
            name => segments.push(name),
        }
    }

    Ok(segments.join("/"))
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

    const ROOT: &str = "/srv/repo";

    fn under_root(path: &str) -> Result<PathBuf, StorageError> {
        normalize_under_root(Path::new(ROOT), Path::new(path))
    }

    fn backend_message(err: StorageError) -> String {
        match err {
            StorageError::Backend { message, .. } => message,
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn normalize_under_root_keeps_plain_relative_path() {
        assert_eq!(
            under_root("archive/main/archive.info").unwrap(),
            PathBuf::from("archive/main/archive.info")
        );
    }

    #[test]
    fn normalize_under_root_collapses_dot_and_repeated_separators() {
        assert_eq!(under_root("a/./b//c").unwrap(), PathBuf::from("a/b/c"));
    }

    #[test]
    fn normalize_under_root_resolves_inner_parent_dir() {
        assert_eq!(under_root("a/../b").unwrap(), PathBuf::from("b"));
    }

    #[test]
    fn normalize_under_root_empty_and_dot_are_root() {
        assert_eq!(under_root("").unwrap(), PathBuf::new());
        assert_eq!(under_root(".").unwrap(), PathBuf::new());
        assert_eq!(under_root("a/..").unwrap(), PathBuf::new());
    }

    #[test]
    fn normalize_under_root_rejects_lone_parent_dir() {
        let message = backend_message(under_root("..").unwrap_err());
        assert!(message.contains("escapes"), "{message}");
    }

    #[test]
    fn normalize_under_root_rejects_relative_escape() {
        let err = under_root("a/../../b").unwrap_err();
        match err {
            StorageError::Backend { path, message } => {
                assert_eq!(path, PathBuf::from("a/../../b"));
                assert!(message.contains("escapes"), "{message}");
            }
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn normalize_under_root_rejects_traversal_to_etc_passwd() {
        let message = backend_message(under_root("../../etc/passwd").unwrap_err());
        assert!(message.contains("escapes"), "{message}");
    }

    #[test]
    fn normalize_under_root_absolute_under_root_becomes_relative() {
        assert_eq!(under_root("/srv/repo/x").unwrap(), PathBuf::from("x"));
        assert_eq!(under_root("/srv/repo/archive/main").unwrap(), PathBuf::from("archive/main"));
    }

    #[test]
    fn normalize_under_root_absolute_root_itself_is_empty() {
        assert_eq!(under_root("/srv/repo").unwrap(), PathBuf::new());
        assert_eq!(under_root("/srv/repo/").unwrap(), PathBuf::new());
    }

    #[test]
    fn normalize_under_root_absolute_normalized_before_comparison() {
        assert_eq!(under_root("/srv/repo/sub/../x").unwrap(), PathBuf::from("x"));
        assert_eq!(under_root("/srv/./repo//x").unwrap(), PathBuf::from("x"));
    }

    #[test]
    fn normalize_under_root_rejects_filesystem_root() {
        let message = backend_message(under_root("/").unwrap_err());
        assert!(message.contains("not under the storage root"), "{message}");
    }

    #[test]
    fn normalize_under_root_rejects_absolute_outside_root() {
        let err = under_root("/etc/passwd").unwrap_err();
        match err {
            StorageError::Backend { path, message } => {
                assert_eq!(path, PathBuf::from("/etc/passwd"));
                assert!(message.contains("not under the storage root"), "{message}");
                assert!(message.contains(ROOT), "{message}");
            }
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn normalize_under_root_rejects_absolute_climbing_out_of_root() {
        let message = backend_message(under_root("/srv/repo/../etc/passwd").unwrap_err());
        assert!(message.contains("not under the storage root"), "{message}");
    }

    #[test]
    fn normalize_under_root_rejects_sibling_sharing_name_prefix() {
        // Component-wise comparison: `/srv/repository` is not under `/srv/repo`.
        let message = backend_message(under_root("/srv/repository/x").unwrap_err());
        assert!(message.contains("not under the storage root"), "{message}");
    }

    #[test]
    fn normalize_under_root_rejects_absolute_parent_of_root() {
        let message = backend_message(under_root("/srv").unwrap_err());
        assert!(message.contains("not under the storage root"), "{message}");
    }

    #[test]
    fn normalize_under_root_normalizes_root_components() {
        for root in ["/srv/./repo/", "/srv/x/../repo", "/srv//repo"] {
            let got = normalize_under_root(Path::new(root), Path::new("/srv/repo/x")).unwrap();
            assert_eq!(got, PathBuf::from("x"), "root {root}");
            normalize_under_root(Path::new(root), Path::new("/srv/x/y")).unwrap_err();
        }
    }

    #[test]
    fn normalize_under_root_relative_ignores_root() {
        // A relative path is confined by construction; the root is not consulted.
        let got = normalize_under_root(Path::new("/srv/x/../repo"), Path::new("a/./b")).unwrap();
        assert_eq!(got, PathBuf::from("a/b"));
    }

    #[test]
    fn normalize_under_root_rejects_absolute_with_relative_root() {
        let message = backend_message(normalize_under_root(Path::new("repo"), Path::new("/repo/x")).unwrap_err());
        assert!(message.contains("not under the storage root"), "{message}");
    }

    #[test]
    fn normalize_object_key_strips_leading_root() {
        assert_eq!(normalize_object_key(Path::new("/a/b")).unwrap(), "a/b");
    }

    #[test]
    fn normalize_object_key_collapses_dot_and_repeated_separators() {
        assert_eq!(normalize_object_key(Path::new("a//b/./c")).unwrap(), "a/b/c");
    }

    #[test]
    fn normalize_object_key_resolves_inner_parent_dir() {
        assert_eq!(normalize_object_key(Path::new("a/../b")).unwrap(), "b");
    }

    #[test]
    fn normalize_object_key_rejects_escape() {
        let err = normalize_object_key(Path::new("../x")).unwrap_err();
        match err {
            StorageError::Backend { path, message } => {
                assert_eq!(path, PathBuf::from("../x"));
                assert!(message.contains("escapes"), "{message}");
            }
            other => panic!("expected Backend error, got {other:?}"),
        }
        let message = backend_message(normalize_object_key(Path::new("/a/../../x")).unwrap_err());
        assert!(message.contains("escapes"), "{message}");
    }

    #[test]
    fn normalize_object_key_converts_backslashes() {
        assert_eq!(normalize_object_key(Path::new(r"a\b\..\c")).unwrap(), "a/c");
        assert_eq!(normalize_object_key(Path::new(r"\a\b")).unwrap(), "a/b");
        normalize_object_key(Path::new(r"..\x")).unwrap_err();
    }

    #[test]
    fn normalize_object_key_root_is_empty() {
        assert_eq!(normalize_object_key(Path::new("")).unwrap(), "");
        assert_eq!(normalize_object_key(Path::new("/")).unwrap(), "");
        assert_eq!(normalize_object_key(Path::new("/./")).unwrap(), "");
    }
}
