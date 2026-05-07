//! Repository utility commands: `repo-ls`, `repo-get`, `repo-put`,
//! `repo-rm`.
//!
//! C reference: `src/command/repo/ls.c`, `src/command/repo/get.c`,
//! `src/command/repo/put.c`, `src/command/repo/rm.c`. `ls` and `rm` ship
//! fully implemented; `get` and `put` are stubs until streaming I/O wired
//! through `pgbr-io` is exposed at the dispatcher layer.

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

/// `repo-get` — copy a file out of the repository to stdout.
///
/// # Errors
///
/// Returns [`CommandError::NotYetImplemented`] until the C port lands.
pub fn get(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "repo-get".to_owned(),
    })
}

/// `repo-put` — copy stdin to a file inside the repository.
///
/// # Errors
///
/// Returns [`CommandError::NotYetImplemented`] until the C port lands.
pub fn put(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "repo-put".to_owned(),
    })
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
