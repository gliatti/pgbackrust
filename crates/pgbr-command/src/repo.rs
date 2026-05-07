//! Repository utility commands: `repo-ls`, `repo-get`, `repo-put`,
//! `repo-rm`.
//!
//! C reference: `src/command/repo/ls.c`, `src/command/repo/get.c`,
//! `src/command/repo/put.c`, `src/command/repo/rm.c`. `repo-get` and
//! `repo-put` here are the raw byte-copy path; compression / encryption
//! filters land alongside the corresponding filter crates.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use pgbr_config::LoadedConfig;
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;

/// Compute the listing for `repo-ls`. Pure function — no I/O beyond the
/// supplied storage backend — so tests can assert against it without
/// capturing stdout.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if the underlying `list` call fails.
pub fn ls_inner(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<Vec<PathBuf>, CommandError> {
    let target = config.params.first().map_or_else(|| PathBuf::from("."), PathBuf::from);

    let entries = repo_storage.list(&target)?;
    Ok(entries.into_iter().map(|info| info.path).collect())
}

/// `repo-ls` — list entries beneath the first positional argument (or the
/// repo root when none is given).
///
/// # Errors
///
/// Returns whatever [`ls_inner`] surfaces.
// CLI command writes to stdout by design.
#[allow(clippy::print_stdout)]
pub fn ls(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let entries = ls_inner(config, repo_storage)?;
    for entry in entries {
        println!("{}", entry.display());
    }
    Ok(())
}

/// Inner `repo-get` implementation: read the file at the first positional
/// path from `repo_storage` and copy its contents into `out`.
///
/// Factored out of [`get`] so tests can pass a `Vec<u8>` (or any other
/// [`std::io::Write`]) without touching the process stdout handle.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if no positional path was supplied.
/// - [`CommandError::Storage`] if the open / read fails (a missing path
///   surfaces as [`pgbr_storage::StorageError::NotFound`]).
/// - [`CommandError::Other`] if writing to `out` fails.
pub fn get_to<W: Write>(config: &LoadedConfig, repo_storage: &dyn Storage, out: &mut W) -> Result<(), CommandError> {
    let path = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<path>".to_owned(),
    })?;
    let mut reader = repo_storage.open_read(Path::new(path))?;
    let bytes = reader.read_all()?;
    out.write_all(&bytes)
        .map_err(|err| CommandError::Other(format!("write output: {err}")))?;
    Ok(())
}

/// `repo-get <path>` — read `<path>` from the repo and write its
/// contents to stdout.
///
/// # Errors
///
/// Returns [`CommandError::MissingOption`] if no positional path was
/// supplied. Storage / I/O failures bubble up as
/// [`CommandError::Storage`] / [`CommandError::Io`].
pub fn get(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    get_to(config, repo_storage, &mut handle)
}

/// Inner `repo-put` implementation.
///
/// Reads every byte of `input` and copies it into the file at the first
/// positional path inside `repo_storage`, flushing and closing the writer
/// at the end so the file is durable.
///
/// Factored out of [`put`] so tests can pass an `io::Cursor<&[u8]>` (or
/// any other [`std::io::Read`]) without touching the process stdin
/// handle.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if no target path was supplied.
/// - [`CommandError::Storage`] if the open / write / flush / close fails.
/// - [`CommandError::Other`] if reading from `input` fails.
pub fn put_from<R: Read>(config: &LoadedConfig, repo_storage: &dyn Storage, input: &mut R) -> Result<(), CommandError> {
    let path = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<path>".to_owned(),
    })?;
    let mut writer = repo_storage.open_write(Path::new(path))?;
    let mut buf = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        let n = input
            .read(&mut buf)
            .map_err(|err| CommandError::Other(format!("read input: {err}")))?;
        if n == 0 {
            break;
        }
        writer.write(&buf[..n])?;
    }
    writer.flush()?;
    writer.close()?;
    Ok(())
}

/// `repo-put <path>` — read stdin and write to `<path>` in the repo.
///
/// # Errors
///
/// Returns [`CommandError::MissingOption`] if no target path was
/// supplied. Storage / I/O failures bubble up as
/// [`CommandError::Storage`] / [`CommandError::Io`].
pub fn put(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    put_from(config, repo_storage, &mut handle)
}

/// `repo-rm` — remove every positional argument from the repository.
/// Directories are removed recursively. A missing entry is not an error
/// (matches the C side's `error_on_missing = false`).
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if a removal fails for a reason other
/// than "missing".
pub fn rm(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    for raw in &config.params {
        let path = Path::new(raw);
        remove_any(repo_storage, path)?;
    }
    Ok(())
}

fn remove_any(storage: &dyn Storage, path: &Path) -> Result<(), CommandError> {
    // Probe to decide whether to call remove (file) or remove_path
    // (directory). exists() is cheaper than info() on most backends.
    match storage.info(path) {
        Ok(info) if matches!(info.kind, pgbr_storage::StorageKind::Path) => match storage.remove_path(path, true, false) {
            Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
            Err(err) => Err(err.into()),
        },
        Ok(_) => match storage.remove(path, false) {
            Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
            Err(err) => Err(err.into()),
        },
        Err(StorageError::NotFound { .. }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};
    use pgbr_storage::Posix;
    use tempfile::TempDir;

    use super::{CommandError, get_to, put_from};

    fn fake_config(command: &str, params: Vec<String>) -> LoadedConfig {
        LoadedConfig {
            command: command.to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: None,
            options: BTreeMap::new(),
            params,
        }
    }

    fn posix_repo() -> (TempDir, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(repo.path());
        (repo, storage)
    }

    #[test]
    fn repo_get_missing_param_errors_with_missing_option() {
        let cfg = fake_config("repo-get", Vec::new());
        let (_repo, storage) = posix_repo();
        let mut buf: Vec<u8> = Vec::new();
        let err = get_to(&cfg, &storage, &mut buf).expect_err("missing path must error");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "<path>"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn repo_put_missing_param_errors_with_missing_option() {
        let cfg = fake_config("repo-put", Vec::new());
        let (_repo, storage) = posix_repo();
        let mut input = Cursor::new(Vec::<u8>::new());
        let err = put_from(&cfg, &storage, &mut input).expect_err("missing path must error");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "<path>"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn repo_get_reads_existing_file_to_writer() {
        let (repo, storage) = posix_repo();
        std::fs::write(repo.path().join("greeting.txt"), b"hello").expect("seed file");

        let cfg = fake_config("repo-get", vec!["greeting.txt".to_owned()]);
        let mut buf: Vec<u8> = Vec::new();
        get_to(&cfg, &storage, &mut buf).expect("get_to should succeed");
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn repo_get_unknown_path_errors_with_storage_not_found() {
        let (_repo, storage) = posix_repo();
        let cfg = fake_config("repo-get", vec!["nope.txt".to_owned()]);
        let mut buf: Vec<u8> = Vec::new();
        let err = get_to(&cfg, &storage, &mut buf).expect_err("missing file must error");
        match err {
            CommandError::Storage(pgbr_storage::StorageError::NotFound { .. }) => {}
            other => panic!("expected Storage(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn repo_put_writes_stdin_to_storage() {
        let (repo, storage) = posix_repo();
        let cfg = fake_config("repo-put", vec!["wrote.txt".to_owned()]);
        let mut input = Cursor::new(b"world".to_vec());

        put_from(&cfg, &storage, &mut input).expect("put_from should succeed");

        let written = std::fs::read(repo.path().join("wrote.txt")).expect("read back");
        assert_eq!(written, b"world");
    }

    #[test]
    fn repo_put_to_nested_path_errors_when_parent_missing() {
        // Posix::open_write is backed by std::fs::File::create which does
        // NOT auto-create missing parent directories. Document that
        // semantics with a test: the call must surface a Storage backend
        // error rather than silently succeed or panic.
        let (_repo, storage) = posix_repo();
        let cfg = fake_config("repo-put", vec!["nested/dir/file.txt".to_owned()]);
        let mut input = Cursor::new(b"payload".to_vec());

        let err = put_from(&cfg, &storage, &mut input).expect_err("missing parent must error");
        match err {
            CommandError::Storage(pgbr_storage::StorageError::Backend { .. })
            | CommandError::Storage(pgbr_storage::StorageError::NotFound { .. }) => {}
            other => panic!("expected Storage(Backend|NotFound), got {other:?}"),
        }
    }
}
