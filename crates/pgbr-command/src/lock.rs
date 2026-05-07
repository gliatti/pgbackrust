//! Lock-file commands: `start` and `stop`.
//!
//! C reference: `src/command/control/start.c` and
//! `src/command/control/stop.c`. The on-disk contract is unchanged from C:
//! a stop file at `<lock-path>/<stanza>.stop` (or `all.stop` when no
//! stanza is supplied) tells the rest of pgBackRest to refuse new
//! commands. `--force` is recorded inside the stop file body.

use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_storage::Storage;

use crate::CommandError;

/// Default lock-path when `--lock-path` is not supplied. Matches the C
/// default in `src/build/config/config.yaml`.
const DEFAULT_LOCK_PATH: &str = "/tmp/pgbackrest";

fn lock_path(config: &LoadedConfig) -> PathBuf {
    match config.options.get(&("lock-path".to_owned(), None)) {
        Some(OptionValue::Path(p) | OptionValue::String(p)) => PathBuf::from(p),
        _ => PathBuf::from(DEFAULT_LOCK_PATH),
    }
}

fn force_flag(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("force".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

fn stop_file(config: &LoadedConfig) -> PathBuf {
    let stanza = config.stanza.as_deref().unwrap_or("all");
    lock_path(config).join(format!("{stanza}.stop"))
}

/// Write `<lock-path>/<stanza>.stop` (or `all.stop` if no stanza) so the
/// rest of pgBackRest refuses new commands. With `--force`, the file body
/// records `force=1\n`.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] / [`CommandError::Io`] if the
/// underlying storage call fails.
pub fn stop(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let path = stop_file(config);
    // Best-effort: ensure the lock-path directory exists.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        repo_storage.create_path(parent, true).or_else(|err| match err {
            pgbr_storage::StorageError::AlreadyExists { .. } => Ok(()),
            other => Err(other),
        })?;
    }

    let mut writer = repo_storage.open_write(&path)?;
    if force_flag(config) {
        writer.write(b"force=1\n")?;
    }
    writer.close()?;
    Ok(())
}

/// Remove the stop file written by [`stop`]. Idempotent: a missing file is
/// not an error.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if the underlying storage call fails
/// for a reason other than "missing".
pub fn start(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let path = stop_file(config);
    repo_storage.remove(&path, false)?;
    Ok(())
}

/// Resolve where the stop file lives without writing it. Exposed for tests
/// outside this module that want to assert paths.
#[must_use]
pub fn stop_file_path(config: &LoadedConfig) -> PathBuf {
    stop_file(config)
}

/// Hook for callers that need the resolved lock directory (without the
/// stanza-specific filename).
#[must_use]
pub fn resolved_lock_path(config: &LoadedConfig) -> PathBuf {
    lock_path(config)
}

/// Re-export of the default for documentation / debugging.
#[must_use]
pub const fn default_lock_path() -> &'static str {
    DEFAULT_LOCK_PATH
}

/// Probe whether a stop file exists for the given config. Used by other
/// commands that must refuse to run when the operator has called `stop`.
///
/// # Errors
///
/// Propagates any [`pgbr_storage::StorageError`] other than `NotFound`.
pub fn is_stopped(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<bool, CommandError> {
    let path = stop_file(config);
    Ok(repo_storage.exists(&path)?)
}

/// Internal helper exposed only for tests in this crate.
#[doc(hidden)]
#[must_use]
pub fn _stop_file_for(lock_path: &Path, stanza: Option<&str>) -> PathBuf {
    lock_path.join(format!("{}.stop", stanza.unwrap_or("all")))
}
