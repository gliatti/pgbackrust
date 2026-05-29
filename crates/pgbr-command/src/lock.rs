//! Lock-file commands (`start` / `stop`) plus advisory lock-file
//! acquisition (the `lock-type` machinery).
//!
//! C reference: `src/command/control/start.c`, `src/command/control/stop.c`
//! and `src/common/lock.c`.
//!
//! Two distinct on-disk contracts live here, both unchanged from C:
//!
//! * **Stop files** — a stop file at `<lock-path>/<stanza>.stop` (or
//!   `all.stop` when no stanza is supplied) tells the rest of pgBackRest to
//!   refuse new commands. `--force` is recorded inside the stop file body.
//!   Managed by [`stop`] / [`start`].
//! * **Advisory locks** — before a mutating command (backup / restore /
//!   archive / …) runs, it takes a non-blocking exclusive `flock` on
//!   `<lock-path>/<stanza>-<type>.lock` so two runs can't collide. Managed
//!   by [`lock_acquire`], released by dropping the returned [`LockHandle`]s.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_storage::Storage;

use crate::CommandError;

/// Default lock-path when `--lock-path` is not supplied. Matches the C
/// default in `src/build/config/config.yaml`.
const DEFAULT_LOCK_PATH: &str = "/tmp/pgbackrest";

/// Resolve the lock directory from the configured `lock-path`, falling back to
/// [`DEFAULT_LOCK_PATH`].
///
/// `lock-path` is the user-facing knob that controls *where* every advisory
/// lock and stop file lives; it is honoured by all of [`stop`] / [`start`] /
/// [`is_stopped`] (via [`stop_file`]) and by [`acquire_command_lock`] (via
/// [`resolved_lock_path`]), so a custom `--lock-path` redirects the whole lock
/// surface consistently. (The separate `lock` *list* option in `config.yaml` is
/// an `internal` remote-protocol detail — the names of locks a remote worker is
/// asked to hold — and is consumed by the protocol layer, not here.)
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

// ---------------------------------------------------------------------------
// Advisory lock-file acquisition (lock-type). C ref: src/common/lock.c.
// ---------------------------------------------------------------------------

/// A held advisory lock on one `<lock-path>/<stanza>-<type>.lock` file.
///
/// Dropping the handle closes the file descriptor, which releases the
/// underlying `flock`, and best-effort removes the now-stale lock file.
///
/// C ref: `lockAcquire` / `lockRelease` in `src/common/lock.c`. As in C the
/// lock is held only for the lifetime of the process that took it; the file
/// itself is purely a rendezvous point for the `flock`.
#[derive(Debug)]
pub struct LockHandle {
    path: PathBuf,
    /// Held open for the lifetime of the lock: when the `File` drops, its
    /// fd closes and the kernel releases the `flock`.
    file: File,
}

impl LockHandle {
    /// Path of the lock file this handle holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LockHandle {
    fn drop(&mut self) {
        // Release the advisory lock explicitly (closing the fd would do it
        // too, but being explicit makes the intent obvious and is harmless).
        let _ = FileExt::unlock(&self.file);
        // Best-effort: remove the now-stale lock file so a stale-PID file
        // doesn't linger. A failure here is non-fatal — the lock is already
        // released. C does the same (`storageRemoveP(..., .errorOnMissing
        // = false)`).
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The concrete lock file names a [`LockType`] maps to. `All` expands to
/// both `archive` and `backup`, mirroring C (`lockAcquire` is called once
/// per type in `cmdLockAcquire`). `None` maps to nothing.
const fn lock_type_names(lock_type: LockType) -> &'static [&'static str] {
    match lock_type {
        LockType::Archive => &["archive"],
        LockType::Backup => &["backup"],
        LockType::Restore => &["restore"],
        LockType::All => &["archive", "backup"],
        LockType::None => &[],
    }
}

/// Resolve the lock-file path for a stanza + single lock-type name.
fn lock_file_path(lock_path: &Path, stanza: &str, type_name: &str) -> PathBuf {
    lock_path.join(format!("{stanza}-{type_name}.lock"))
}

/// Acquire the advisory lock(s) implied by `lock_type`.
///
/// Takes a non-blocking exclusive lock for each lock file implied by
/// `lock_type`, writing the current PID into each file (informational, as in
/// C). The directory `lock_path` is created if it does not exist.
///
/// Returns one [`LockHandle`] per acquired lock; dropping them releases the
/// locks (and removes the files). `LockType::None` acquires nothing and
/// returns an empty `Vec`.
///
/// On Unix the lock is a real `flock(LOCK_EX | LOCK_NB)` (via [`fs2`]); on
/// other platforms it degrades to the platform's advisory lock (Windows
/// `LockFileEx`), and where no advisory lock is available the exclusive file
/// creation still prevents the common collision case.
///
/// C ref: `lockAcquire` in `src/common/lock.c` (the `<stanza>-<type>.lock`
/// file with an exclusive, non-blocking flock).
///
/// # Errors
///
/// Returns [`CommandError::Other`] if the lock is already held by another
/// process (the message names the conflicting `lock_type`, e.g. "unable to
/// acquire lock ... another backup is running"), or [`CommandError::Io`] if
/// creating the directory / opening / writing a lock file fails for any
/// other reason. On the first failure, any locks already acquired in this
/// call are released (their handles drop).
pub fn lock_acquire(lock_path: &Path, stanza: &str, lock_type: LockType) -> Result<Vec<LockHandle>, CommandError> {
    let names = lock_type_names(lock_type);
    if names.is_empty() {
        return Ok(Vec::new());
    }

    // Ensure the lock directory exists (C: `storagePathCreateP`).
    std::fs::create_dir_all(lock_path)
        .map_err(|err| CommandError::Other(format!("unable to create lock path '{}': {err}", lock_path.display())))?;

    let mut handles = Vec::with_capacity(names.len());
    for type_name in names {
        let path = lock_file_path(lock_path, stanza, type_name);
        let handle = acquire_one(&path, type_name)?;
        // `handles` drops on early `?` return above, releasing prior locks.
        handles.push(handle);
    }
    Ok(handles)
}

/// Acquire a single lock file: open (creating it), take the non-blocking
/// exclusive lock, then write the PID. Separated out so an error after a
/// successful open still releases via the local `File` dropping.
fn acquire_one(path: &Path, type_name: &str) -> Result<LockHandle, CommandError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|err| CommandError::Other(format!("unable to open lock file '{}': {err}", path.display())))?;

    // Non-blocking exclusive lock. `WouldBlock` means another process holds
    // it: surface the friendly "another <type> is running" message.
    if let Err(err) = FileExt::try_lock_exclusive(&file) {
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Err(CommandError::Other(format!(
                "unable to acquire lock on file '{}': another {type_name} is running",
                path.display()
            )));
        }
        return Err(CommandError::Other(format!(
            "unable to acquire lock on file '{}': {err}",
            path.display()
        )));
    }

    // Lock held: record our PID (informational, matches C which writes the
    // pid for diagnostics). Truncate first so a reused/stale file is clean.
    if let Err(err) = write_pid(&mut file) {
        // Drop the lock we just took before returning the error.
        let _ = FileExt::unlock(&file);
        return Err(CommandError::Other(format!(
            "unable to write pid to lock file '{}': {err}",
            path.display()
        )));
    }

    Ok(LockHandle {
        path: path.to_path_buf(),
        file,
    })
}

/// Truncate `file` and write the current PID followed by a newline.
fn write_pid(file: &mut File) -> std::io::Result<()> {
    let pid = std::process::id();
    file.set_len(0)?;
    file.write_all(format!("{pid}\n").as_bytes())?;
    file.flush()
}

/// Resolve the lock-file path for a stanza + lock-type name without taking
/// the lock. Exposed for tests / callers that want to assert paths.
#[doc(hidden)]
#[must_use]
pub fn _lock_file_for(lock_path: &Path, stanza: &str, type_name: &str) -> PathBuf {
    lock_file_path(lock_path, stanza, type_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[test]
    fn lock_acquire_then_second_fails() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path();

        // First acquire succeeds.
        let first = lock_acquire(lock_path, "demo", LockType::Backup).unwrap();
        assert_eq!(first.len(), 1);
        assert!(first[0].path().exists());
        assert_eq!(first[0].path(), &lock_path.join("demo-backup.lock"));

        // Second acquire of the same stanza+type fails while the first is
        // alive.
        let second = lock_acquire(lock_path, "demo", LockType::Backup);
        let err = second.expect_err("second acquire must fail while first held");
        let msg = err.to_string();
        assert!(msg.contains("another backup is running"), "unexpected message: {msg}");

        // After dropping the first handle the lock is released; a fresh
        // acquire then succeeds.
        drop(first);
        let third = lock_acquire(lock_path, "demo", LockType::Backup).expect("acquire after release must succeed");
        assert_eq!(third.len(), 1);
    }

    #[test]
    fn lock_type_all_takes_two() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path();

        let handles = lock_acquire(lock_path, "demo", LockType::All).unwrap();
        assert_eq!(handles.len(), 2);

        let names: Vec<_> = handles
            .iter()
            .map(|h| h.path().file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"demo-archive.lock".to_owned()), "missing archive: {names:?}");
        assert!(names.contains(&"demo-backup.lock".to_owned()), "missing backup: {names:?}");

        // Both component locks are genuinely held: a backup-only acquire (a
        // subset of `All`) must collide.
        let conflict = lock_acquire(lock_path, "demo", LockType::Backup);
        assert!(conflict.is_err());
    }

    #[test]
    fn lock_type_none_is_noop() {
        let dir = TempDir::new().unwrap();
        let handles = lock_acquire(dir.path(), "demo", LockType::None).unwrap();
        assert!(handles.is_empty());
        // Nothing should have been written into the lock path.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(entries.is_empty(), "lock-type=none must not write files");
    }

    #[test]
    fn lock_writes_pid() {
        let dir = TempDir::new().unwrap();
        let handles = lock_acquire(dir.path(), "demo", LockType::Restore).unwrap();
        assert_eq!(handles.len(), 1);

        let contents = std::fs::read_to_string(handles[0].path()).unwrap();
        let pid: u32 = contents.trim().parse().expect("lock file body must be a PID");
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn lock_handle_drop_removes_file() {
        let dir = TempDir::new().unwrap();
        let path = {
            let handles = lock_acquire(dir.path(), "demo", LockType::Archive).unwrap();
            handles[0].path().to_path_buf()
        };
        // Handle dropped at end of the block above; file is cleaned up.
        assert!(!path.exists(), "drop must remove the stale lock file");
    }

    use std::collections::BTreeMap;

    use pgbr_config::ConfigCommandRole;

    fn config_with(stanza: Option<&str>, opts: Vec<(&str, OptionValue)>) -> LoadedConfig {
        let mut options = BTreeMap::new();
        for (name, value) in opts {
            options.insert((name.to_owned(), None), value);
        }
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn lock_path_option_is_honored() {
        // A configured `--lock-path` redirects both the resolved lock directory
        // and the stop file; an absent option falls back to the default.
        let cfg = config_with(
            Some("demo"),
            vec![("lock-path", OptionValue::Path("/custom/locks".to_owned()))],
        );
        assert_eq!(resolved_lock_path(&cfg), PathBuf::from("/custom/locks"));
        assert_eq!(stop_file_path(&cfg), PathBuf::from("/custom/locks/demo.stop"));

        let default_cfg = config_with(Some("demo"), Vec::new());
        assert_eq!(resolved_lock_path(&default_cfg), PathBuf::from(DEFAULT_LOCK_PATH));
        assert_eq!(
            stop_file_path(&default_cfg),
            PathBuf::from(DEFAULT_LOCK_PATH).join("demo.stop")
        );
    }

    #[test]
    fn stop_file_uses_all_when_no_stanza() {
        let cfg = config_with(None, vec![("lock-path", OptionValue::Path("/l".to_owned()))]);
        assert_eq!(stop_file_path(&cfg), PathBuf::from("/l/all.stop"));
    }
}
