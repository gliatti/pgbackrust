//! Lock-file commands (`start` / `stop`) plus advisory lock-file
//! acquisition (the `lock-type` machinery).
//!
//! C reference: `src/command/control/start.c`, `src/command/control/stop.c`
//! and `src/common/lock.c`.
//!
//! Two distinct on-disk contracts live here, both unchanged from C:
//!
//! * **Stop files** — a stop file at `<lock-path>/<stanza>.stop` (or
//!   `all.stop` when no stanza is supplied) tells the rest of pgBackRust to
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

use crate::CommandError;

/// Default lock-path when `--lock-path` is not supplied. Matches the C
/// default in `src/build/config/config.yaml`.
const DEFAULT_LOCK_PATH: &str = "/tmp/pgbackrust";

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
/// rest of pgBackRust refuses new commands. With `--force`, the file body
/// records `force=1\n`.
///
/// Stop files are intrinsically LOCAL to the host running `pgbackrust`
/// (stock pgBackRust C uses `storageLocalWrite` in
/// `src/command/control/stop.c`). Going through a `Storage` backend would
/// route the path through whichever repository is configured — on S3 /
/// Azure / GCS / SFTP it would create an object key inside the bucket
/// instead of a local sentinel file, so subsequent local `is_stopped`
/// checks would never see it. We use `std::fs` directly, mirroring
/// [`lock_acquire`] which already touches the same `lock_path` locally.
///
/// The file is published via a write-then-rename so a concurrent
/// [`is_stopped`] never observes a partial body.
///
/// # Errors
///
/// Returns [`CommandError::Other`] if creating the lock directory,
/// writing the temporary file, or renaming it into place fails.
pub fn stop(config: &LoadedConfig) -> Result<(), CommandError> {
    let path = stop_file(config);
    // Best-effort: ensure the lock-path directory exists.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|err| CommandError::Other(format!("unable to create lock path '{}': {err}", parent.display())))?;
    }

    let body: &[u8] = if force_flag(config) { b"force=1\n" } else { b"" };
    // Atomic-ish publish: write to a temp file, then rename. This keeps a
    // concurrent `is_stopped` from observing a partial file.
    let tmp = path.with_extension("stop.tmp");
    std::fs::write(&tmp, body)
        .map_err(|err| CommandError::Other(format!("unable to write stop file '{}': {err}", tmp.display())))?;
    std::fs::rename(&tmp, &path)
        .map_err(|err| CommandError::Other(format!("unable to publish stop file '{}': {err}", path.display())))?;
    Ok(())
}

/// Remove the stop file written by [`stop`].
///
/// Idempotent: a missing file is not an error. Operates on the local
/// filesystem for the same reason [`stop`] does — stop files are LOCAL host
/// sentinels, not repository objects.
///
/// # Errors
///
/// Returns [`CommandError::Other`] if the underlying `unlink` fails for a
/// reason other than "missing".
pub fn start(config: &LoadedConfig) -> Result<(), CommandError> {
    let path = stop_file(config);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CommandError::Other(format!(
            "unable to remove stop file '{}': {err}",
            path.display()
        ))),
    }
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
/// Two sentinels are checked, both on the LOCAL filesystem (matching
/// [`stop`]): the stanza-scoped `<lock-path>/<stanza>.stop` file written by
/// `stop --stanza=<stanza>`, AND `<lock-path>/all.stop` written by `stop
/// --force` (or `stop` with no stanza) which blocks every stanza. Either
/// being present blocks the calling command.
///
/// # Errors
///
/// This call is currently infallible — both checks are pure `Path::exists`
/// probes — but the result is wrapped in `Result` so future
/// permission-error reporting can plumb through without breaking the
/// signature.
#[allow(clippy::unnecessary_wraps)]
pub fn is_stopped(config: &LoadedConfig) -> Result<bool, CommandError> {
    let stanza_stop = stop_file(config);
    if stanza_stop.exists() {
        return Ok(true);
    }
    let all_stop = lock_path(config).join("all.stop");
    Ok(all_stop.exists())
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

    /// Build a config rooted under `lock_path` on the local filesystem. The
    /// stop-file commands MUST operate on this local path, not on any
    /// `Storage` backend, so a posix-rooted tempdir is the right fixture.
    fn config_local_locked(stanza: Option<&str>, lock_path: &Path, extra: Vec<(&str, OptionValue)>) -> LoadedConfig {
        let mut opts = vec![("lock-path", OptionValue::Path(lock_path.to_string_lossy().into_owned()))];
        opts.extend(extra);
        config_with(stanza, opts)
    }

    #[test]
    fn stop_creates_stanza_stop_file_locally() {
        // `stop --stanza=demo` must write `<lock-path>/demo.stop` on the host
        // filesystem (NOT via any Storage backend). The file appears under
        // the configured lock-path even when the lock-path dir does not yet
        // exist (created on demand).
        let lock_dir = TempDir::new().expect("lock tempdir");
        // Use a not-yet-created subdirectory so `stop` exercises the
        // create-dir-all path.
        let lock_path = lock_dir.path().join("inner");
        assert!(!lock_path.exists(), "precondition: lock-path must not exist yet");
        let cfg = config_local_locked(Some("demo"), &lock_path, Vec::new());

        stop(&cfg).expect("stop should succeed");

        let expected = lock_path.join("demo.stop");
        assert!(
            expected.exists(),
            "stop file must exist on the local filesystem at {expected:?}"
        );
        // Body is empty when --force is not set.
        let body = std::fs::read(&expected).expect("read stop file");
        assert!(body.is_empty(), "stop file body must be empty without --force, got {body:?}");
    }

    #[test]
    fn start_removes_stanza_stop_file() {
        // Pre-create a stop file then `start` removes it. After the call the
        // sentinel is gone from the local filesystem.
        let lock_dir = TempDir::new().expect("lock tempdir");
        let lock_path = lock_dir.path();
        let cfg = config_local_locked(Some("demo"), lock_path, Vec::new());

        let stop_path = lock_path.join("demo.stop");
        std::fs::write(&stop_path, b"").expect("seed stop file");
        assert!(stop_path.exists());

        start(&cfg).expect("start should succeed");
        assert!(!stop_path.exists(), "start must remove the stop file");
    }

    #[test]
    fn start_when_no_file_is_idempotent_ok() {
        // No stop file present → `start` returns Ok(()). Calling it twice in
        // a row must also be a no-op.
        let lock_dir = TempDir::new().expect("lock tempdir");
        let cfg = config_local_locked(Some("demo"), lock_dir.path(), Vec::new());
        let stop_path = lock_dir.path().join("demo.stop");
        assert!(!stop_path.exists(), "precondition: no stop file");

        start(&cfg).expect("idempotent start (1)");
        start(&cfg).expect("idempotent start (2)");
        assert!(!stop_path.exists());
    }

    #[test]
    fn is_stopped_sees_stanza_and_all_stop() {
        // The stanza-scoped `<stanza>.stop` blocks the calling stanza, AND
        // an `all.stop` (set by stock `stop --force` or `stop` with no
        // stanza) blocks every stanza too. With neither file present,
        // is_stopped returns false.
        let lock_dir = TempDir::new().expect("lock tempdir");
        let lock_path = lock_dir.path();
        let cfg = config_local_locked(Some("demo"), lock_path, Vec::new());

        assert!(!is_stopped(&cfg).expect("is_stopped: clean"), "no files → not stopped");

        // Stanza-scoped sentinel.
        let stanza_stop = lock_path.join("demo.stop");
        std::fs::write(&stanza_stop, b"").expect("seed demo.stop");
        assert!(is_stopped(&cfg).expect("is_stopped: stanza"), "demo.stop → stopped");
        std::fs::remove_file(&stanza_stop).expect("remove demo.stop");

        // Cluster-wide sentinel.
        let all_stop = lock_path.join("all.stop");
        std::fs::write(&all_stop, b"").expect("seed all.stop");
        assert!(is_stopped(&cfg).expect("is_stopped: all"), "all.stop → stopped");
        std::fs::remove_file(&all_stop).expect("remove all.stop");

        assert!(!is_stopped(&cfg).expect("is_stopped: clean again"), "cleanup → not stopped");
    }

    #[test]
    fn stop_with_force_writes_force_marker() {
        // With `--force` set, `stop` records `force=1\n` in the file body so
        // a peer process can tell a forced stop from a graceful one.
        let lock_dir = TempDir::new().expect("lock tempdir");
        let lock_path = lock_dir.path();
        let cfg = config_local_locked(Some("demo"), lock_path, vec![("force", OptionValue::Boolean(true))]);

        stop(&cfg).expect("stop --force should succeed");

        let body = std::fs::read(lock_path.join("demo.stop")).expect("read stop file");
        assert_eq!(body, b"force=1\n", "force=1\\n marker expected, got {body:?}");
    }
}
