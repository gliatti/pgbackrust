//! Stanza-management commands: `stanza-create`, `stanza-delete`,
//! `stanza-upgrade`.
//!
//! C reference: `src/command/stanza/create.c`, `src/command/stanza/delete.c`,
//! `src/command/stanza/upgrade.c`. The Rust port currently only implements
//! delete; create and upgrade are stubs until the on-disk info-file work in
//! `pgbr-info` lands.

use std::path::{Path, PathBuf};

use pgbr_config::LoadedConfig;
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

/// `stanza-create` — initialise on-disk repository state for a stanza.
///
/// # Errors
///
/// Returns [`CommandError::NotYetImplemented`] until the C port lands.
pub fn create(_config: &LoadedConfig, _repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "stanza-create".to_owned(),
    })
}

/// `stanza-delete` — wipe an existing stanza's repository state.
///
/// Recursively removes `archive/<stanza>` and `backup/<stanza>` from the
/// repository. Both removals tolerate a missing directory
/// (`error_on_missing = false`) so the command is idempotent.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] if either removal fails for a reason other
///   than "missing".
pub fn delete(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;

    let archive: PathBuf = format!("archive/{stanza}").into();
    let backup: PathBuf = format!("backup/{stanza}").into();

    remove_subtree(repo_storage, &archive)?;
    remove_subtree(repo_storage, &backup)?;
    Ok(())
}

fn remove_subtree(storage: &dyn Storage, path: &Path) -> Result<(), CommandError> {
    match storage.remove_path(path, true, false) {
        Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// `stanza-upgrade` — record a new PG version after a major-version upgrade.
///
/// # Errors
///
/// Returns [`CommandError::NotYetImplemented`] until the C port lands.
pub fn upgrade(_config: &LoadedConfig, _repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "stanza-upgrade".to_owned(),
    })
}
