//! `annotate` command — attach key/value annotations to an existing backup.
//!
//! C reference: `src/command/annotate/annotate.c` +
//! `infoBackupDataAnnotationSet` in `src/info/infoBackup.c`.
//!
//! Merges the repeatable `--annotation=key=value` option into the target
//! backup's `backup-annotation` object in `backup.info`:
//!
//! - a non-empty value sets / updates the key,
//! - an empty value removes the key (pgBackRest's delete convention),
//! - an annotation object emptied by removals is dropped entirely so the
//!   `backup-annotation` field disappears from the entry.
//!
//! The C command iterates over every configured repo; the Rust port acts on
//! the single repository `Storage` it is handed (the dispatcher selects the
//! repo). Multi-repo fan-out is deferred until the repo-selection layer
//! lands.

use std::collections::BTreeMap;
use std::path::PathBuf;

use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_info::InfoBackup;
use pgbr_storage::Storage;
use serde_json::{Map, Value};

use crate::CommandError;
use crate::backup::acquire_command_lock;

/// JSON key under which a backup entry stores its annotations.
const ANNOTATION_KEY: &str = "backup-annotation";

/// Outcome of an [`annotate_inner`] pass: which annotation keys were set or
/// updated, and which were removed, on the target backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnotateResult {
    /// The backup label that was annotated.
    pub backup_label: String,
    /// Annotation keys set or updated by this pass (non-empty values).
    pub set_keys: Vec<String>,
    /// Annotation keys removed by this pass (empty values).
    pub removed_keys: Vec<String>,
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

/// Pull the `--set` backup label out of the resolved configuration.
fn require_set(config: &LoadedConfig) -> Result<&str, CommandError> {
    match config.options.get(&("set".to_owned(), None)) {
        Some(OptionValue::String(label)) => Ok(label.as_str()),
        _ => Err(CommandError::MissingOption {
            option: "set".to_owned(),
        }),
    }
}

/// Pull the `--annotation` hash out of the resolved configuration. An absent
/// option means there is nothing to apply (an empty merge).
fn annotations(config: &LoadedConfig) -> BTreeMap<String, String> {
    match config.options.get(&("annotation".to_owned(), None)) {
        Some(OptionValue::Hash(map)) => map.clone(),
        _ => BTreeMap::new(),
    }
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// Merge an annotation hash into the existing `backup-annotation` value.
///
/// This is the pure core of the command, isolated so it can be unit-tested
/// without any storage or `backup.info` plumbing:
///
/// - a non-empty value sets / updates the key,
/// - an empty value removes the key (pgBackRest's delete convention),
/// - if every key is removed the result is `None`, so the caller drops the
///   `backup-annotation` field entirely (matches the C
///   `backupAnnotation = NULL` behaviour).
///
/// `existing` may hold a non-object [`Value`]; it is then treated as absent
/// and replaced wholesale.
fn merge_annotations(existing: Option<&Value>, updates: &BTreeMap<String, String>) -> Option<Value> {
    let mut annotation = match existing {
        Some(Value::Object(existing)) => existing.clone(),
        _ => Map::new(),
    };

    for (key, value) in updates {
        if value.is_empty() {
            // Empty value -> delete convention.
            annotation.remove(key);
        } else {
            annotation.insert(key.clone(), Value::String(value.clone()));
        }
    }

    if annotation.is_empty() {
        None
    } else {
        Some(Value::Object(annotation))
    }
}

/// Apply the annotation hash to one backup entry's JSON value, mutating the
/// `backup-annotation` object in place via [`merge_annotations`]. Returns the
/// keys set and removed so the caller can report what changed.
fn apply_annotations(entry: &mut Value, requested: &BTreeMap<String, String>) -> (Vec<String>, Vec<String>) {
    let mut set_keys = Vec::new();
    let mut removed_keys = Vec::new();

    // Determine which keys this pass actually changes for reporting. An empty
    // value only counts as a removal if the key was present beforehand.
    let present = |key: &str| -> bool { matches!(entry.get(ANNOTATION_KEY), Some(Value::Object(obj)) if obj.contains_key(key)) };
    for (key, value) in requested {
        if value.is_empty() {
            if present(key) {
                removed_keys.push(key.clone());
            }
        } else {
            set_keys.push(key.clone());
        }
    }

    let merged = merge_annotations(entry.get(ANNOTATION_KEY), requested);

    // Reflect the merged object back onto the entry. An emptied object is
    // dropped entirely (matches the C `backupAnnotation = NULL` behaviour).
    if let Value::Object(obj) = entry {
        match merged {
            Some(value) => {
                obj.insert(ANNOTATION_KEY.to_owned(), value);
            }
            None => {
                obj.remove(ANNOTATION_KEY);
            }
        }
    }

    (set_keys, removed_keys)
}

/// Core annotation pass. The thin [`annotate`] entry point prints a
/// confirmation and returns `()`; tests assert against [`AnnotateResult`]
/// directly.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` or `--set` was not
///   supplied.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for backend failures
///   while loading or re-saving `backup.info`.
/// - [`CommandError::Other`] if `backup.info` is malformed, or if the `--set`
///   label is not present in `[backup:current]`.
pub fn annotate_inner(config: &LoadedConfig, repo: &dyn Storage) -> Result<AnnotateResult, CommandError> {
    let stanza = require_stanza(config)?;
    let label = require_set(config)?.to_owned();
    let requested = annotations(config);

    let path = backup_info_path(stanza);
    let mut info = InfoBackup::load(repo, &path).map_err(|err| CommandError::Other(err.to_string()))?;

    let Some(entry) = info.current.get_mut(&label) else {
        return Err(CommandError::Other(format!("backup '{label}' does not exist")));
    };

    let (set_keys, removed_keys) = apply_annotations(entry, &requested);

    info.save(repo, &path).map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(AnnotateResult {
        backup_label: label,
        set_keys,
        removed_keys,
    })
}

/// `annotate` — attach key/value annotations to an existing backup.
///
/// The confirmation line is a *human-facing* status message, so it is routed
/// through the logger ([`crate::control::log_info`]) at `INFO` rather than
/// written to stdout — `annotate` produces no machine-readable result, and the
/// C command likewise reports success with `LOG_INFO`, not a `printf`.
///
/// Holds the **backup** advisory lock for the whole command: `annotate` does a
/// read-modify-write of `backup.info`, the same file `backup` / `expire`
/// mutate, so a concurrent `annotate` (or a concurrent `backup` / `expire`)
/// would lose updates. The lock matches the type those commands take. Before
/// acquiring the lock we also honour the `stop` sentinel, so a stopped stanza
/// is refused without creating a lock file. C ref: `cmdLockAcquire` +
/// `lockStopTest`.
///
/// # Errors
///
/// Returns [`CommandError::Other`] when the stanza is stopped, or when
/// another `backup` / `expire` / `annotate` already holds the backup lock.
/// Otherwise surfaces whatever [`annotate_inner`] returns; see its docs.
pub fn annotate(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    // Refuse to run when the operator has called `stop` for this stanza (or
    // `stop --force` which writes `all.stop` and blocks every stanza). The
    // gate runs BEFORE acquiring the backup lock so a stopped stanza doesn't
    // even create a lock file. C ref: cmdLockAcquire's lockStopTest check.
    if crate::lock::is_stopped(config)? {
        return Err(CommandError::Other(format!("stop file exists for stanza {stanza}")));
    }
    // Hold the backup lock for the whole command — annotate rewrites the same
    // `backup.info` that backup / expire mutate. C ref: lockAcquire(lockTypeBackup).
    let _locks = acquire_command_lock(config, LockType::Backup)?;

    let result = annotate_inner(config, repo_storage)?;

    crate::control::log_info(&format!(
        "backup set '{}' annotated ({} set, {} removed)",
        result.backup_label,
        result.set_keys.len(),
        result.removed_keys.len()
    ));

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::InfoBackup;
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{CommandError, annotate, annotate_inner, merge_annotations};

    /// Build a `BTreeMap` of update pairs for the pure merge tests.
    fn updates(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn merge_adds_new_keys() {
        // No existing annotations -> object with the new keys.
        let result = merge_annotations(None, &updates(&[("k1", "v1"), ("k2", "v2")]));
        assert_eq!(result, Some(json!({ "k1": "v1", "k2": "v2" })));
    }

    #[test]
    fn merge_updates_existing_key() {
        let existing = json!({ "k1": "old", "keep": "yes" });
        let result = merge_annotations(Some(&existing), &updates(&[("k1", "new")]));
        assert_eq!(result, Some(json!({ "k1": "new", "keep": "yes" })));
    }

    #[test]
    fn merge_empty_value_removes_key() {
        let existing = json!({ "k1": "v1", "k2": "v2" });
        let result = merge_annotations(Some(&existing), &updates(&[("k1", "")]));
        assert_eq!(result, Some(json!({ "k2": "v2" })));
    }

    #[test]
    fn merge_removing_last_key_drops_object() {
        let existing = json!({ "only": "v" });
        let result = merge_annotations(Some(&existing), &updates(&[("only", "")]));
        assert_eq!(result, None);
    }

    #[test]
    fn merge_removing_absent_key_is_noop() {
        // Removing a key that was never present must not resurrect an object.
        let result = merge_annotations(None, &updates(&[("ghost", "")]));
        assert_eq!(result, None);
    }

    #[test]
    fn merge_replaces_non_object_existing() {
        // A non-object existing value is treated as absent and replaced.
        let existing = json!("not-an-object");
        let result = merge_annotations(Some(&existing), &updates(&[("k1", "v1")]));
        assert_eq!(result, Some(json!({ "k1": "v1" })));
    }

    fn fake_config(stanza: &str, set: Option<&str>, annotations: &[(&str, &str)]) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(s) = set {
            options.insert(("set".to_owned(), None), OptionValue::String(s.to_owned()));
        }
        if !annotations.is_empty() {
            let map = annotations.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
            options.insert(("annotation".to_owned(), None), OptionValue::Hash(map));
        }
        LoadedConfig {
            command: "annotate".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    /// Build a `backup.info` containing a single backup `label` with the given
    /// inner JSON object, persisted under `backup/<stanza>/backup.info`.
    fn seed_backup_info(repo: &Posix, stanza: &str, label: &str, entry: serde_json::Value) -> TempDir {
        let mut current = BTreeMap::new();
        current.insert(label.to_owned(), entry);

        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history: BTreeMap::new(),
        };

        let stanza_dir = tempfile::tempdir().expect("placeholder tempdir");
        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup dir");
        info.save(repo, Path::new(&format!("backup/{stanza}/backup.info")))
            .expect("save backup.info");
        stanza_dir
    }

    fn load_backup_info(repo: &Posix, stanza: &str) -> InfoBackup {
        InfoBackup::load(repo, Path::new(&format!("backup/{stanza}/backup.info"))).expect("reload backup.info")
    }

    #[test]
    fn annotate_adds_new_annotation() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let label = "20240101-120000F";
        let _seed = seed_backup_info(&repo, "demo", label, json!({ "backup-label": label, "backup-type": "full" }));

        let cfg = fake_config("demo", Some(label), &[("key1", "value1")]);
        let result = annotate_inner(&cfg, &repo).expect("annotate should succeed");
        assert_eq!(result.set_keys, vec!["key1".to_owned()]);
        assert!(result.removed_keys.is_empty());

        let info = load_backup_info(&repo, "demo");
        assert_eq!(info.current[label]["backup-annotation"]["key1"], json!("value1"));
    }

    #[test]
    fn annotate_updates_existing_annotation() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let label = "20240101-120000F";
        let _seed = seed_backup_info(
            &repo,
            "demo",
            label,
            json!({ "backup-label": label, "backup-annotation": { "key1": "old" } }),
        );

        let cfg = fake_config("demo", Some(label), &[("key1", "new")]);
        let result = annotate_inner(&cfg, &repo).expect("annotate should succeed");
        assert_eq!(result.set_keys, vec!["key1".to_owned()]);

        let info = load_backup_info(&repo, "demo");
        assert_eq!(info.current[label]["backup-annotation"]["key1"], json!("new"));
    }

    #[test]
    fn annotate_empty_value_removes_key() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let label = "20240101-120000F";
        let _seed = seed_backup_info(
            &repo,
            "demo",
            label,
            json!({ "backup-label": label, "backup-annotation": { "key1": "v" } }),
        );

        let cfg = fake_config("demo", Some(label), &[("key1", "")]);
        let result = annotate_inner(&cfg, &repo).expect("annotate should succeed");
        assert!(result.set_keys.is_empty());
        assert_eq!(result.removed_keys, vec!["key1".to_owned()]);

        let info = load_backup_info(&repo, "demo");
        // The only key was removed, so the whole annotation field is dropped.
        assert!(info.current[label].get("backup-annotation").is_none());
    }

    #[test]
    fn annotate_unknown_backup_errors() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let _seed = seed_backup_info(
            &repo,
            "demo",
            "20240101-120000F",
            json!({ "backup-label": "20240101-120000F" }),
        );

        let cfg = fake_config("demo", Some("20991231-235959F"), &[("key1", "value1")]);
        let err = annotate_inner(&cfg, &repo).expect_err("unknown backup must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("does not exist"), "got: {msg}"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn annotate_missing_set_option_errors() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let _seed = seed_backup_info(
            &repo,
            "demo",
            "20240101-120000F",
            json!({ "backup-label": "20240101-120000F" }),
        );

        let cfg = fake_config("demo", None, &[("key1", "value1")]);
        let err = annotate_inner(&cfg, &repo).expect_err("missing --set must fail");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "set"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    /// Build an annotate config that ALSO carries `lock-path`, so the lock
    /// helpers in `annotate` actually take the backup lock under a tempdir.
    fn fake_config_with_lock_path(stanza: &str, set: Option<&str>, annotations: &[(&str, &str)], lock_path: &Path) -> LoadedConfig {
        let mut cfg = fake_config(stanza, set, annotations);
        cfg.options.insert(
            ("lock-path".to_owned(), None),
            OptionValue::Path(lock_path.to_string_lossy().into_owned()),
        );
        cfg
    }

    #[test]
    fn annotate_acquires_backup_lock() {
        // The `annotate` public entry point must take `LockType::Backup` so a
        // concurrent `backup` / `expire` / `annotate` can't race on the
        // read-modify-write of `backup.info`. With `lock-path` pointing at an
        // isolated tempdir, calling `annotate` creates the expected lock
        // file, and a concurrent `lock_acquire` on the same stanza+type then
        // fails with "another backup is running".
        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let lock_path = lock_dir.path();
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let label = "20240101-120000F";
        let _seed = seed_backup_info(&repo, "demo", label, json!({ "backup-label": label }));

        let expected_lock = lock_path.join("demo-backup.lock");
        assert!(!expected_lock.exists(), "precondition: lock file must not exist yet");

        // Hold a parallel backup lock for the duration of the call so we can
        // observe the conflict deterministically. With the parallel handle
        // held, `annotate` must fail to acquire and surface the friendly
        // "another backup is running" message.
        let parallel = crate::lock::lock_acquire(lock_path, "demo", pgbr_config::LockType::Backup).expect("seed: parallel acquire");
        assert!(expected_lock.exists(), "parallel acquire must have created the lock file");

        let cfg = fake_config_with_lock_path("demo", Some(label), &[("k", "v")], lock_path);
        let err = annotate(&cfg, &repo).expect_err("annotate must fail while backup lock is held");
        let msg = err.to_string();
        assert!(
            msg.contains("another backup is running"),
            "unexpected annotate error message: {msg}"
        );

        // After releasing the parallel lock, annotate succeeds and the lock
        // file is created (and cleaned up on Drop).
        drop(parallel);
        assert!(!expected_lock.exists(), "drop must remove the stale lock file");
        let cfg2 = fake_config_with_lock_path("demo", Some(label), &[("k", "v")], lock_path);
        annotate(&cfg2, &repo).expect("annotate must succeed once lock is free");
        assert!(!expected_lock.exists(), "annotate must release & clean up its lock file");
    }

    #[test]
    fn annotate_refuses_when_stopped() {
        // A `<lock-path>/<stanza>.stop` sentinel must short-circuit `annotate`
        // BEFORE it touches `backup.info` or creates a lock file. The error
        // message mentions the stop condition and the stanza.
        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let lock_path = lock_dir.path();
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let label = "20240101-120000F";
        let _seed = seed_backup_info(&repo, "demo", label, json!({ "backup-label": label }));

        // Touch the stop file.
        let stop_path = lock_path.join("demo.stop");
        std::fs::write(&stop_path, b"").expect("seed stop file");

        let cfg = fake_config_with_lock_path("demo", Some(label), &[("k", "v")], lock_path);
        let err = annotate(&cfg, &repo).expect_err("annotate must refuse while stopped");
        let msg = err.to_string();
        assert!(msg.contains("stop file"), "expected stop-file mention, got: {msg}");
        assert!(msg.contains("demo"), "expected stanza name in error, got: {msg}");

        // No lock file should have been created (the stop check runs first).
        assert!(
            !lock_path.join("demo-backup.lock").exists(),
            "stop gate must run before lock acquisition"
        );
    }

    /// Serializes the process-global `pgbr_core::log` state across the capture
    /// tests in this crate so concurrent `cargo test` threads do not race on it.
    static LOG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn annotate_confirmation_goes_to_logger_not_stdout() {
        // The success line is routed through `pgbr_core::log`, not `println!`.
        // Install the in-memory capture sink, raise the file-sink level to INFO,
        // run the public `annotate`, and assert the rendered INFO line landed in
        // the capture buffer (proving it took the logger path).
        let _guard = LOG_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());
        let label = "20240101-120000F";
        let _seed = seed_backup_info(&repo, "demo", label, json!({ "backup-label": label }));

        pgbr_core::log::capture::install();
        // Route INFO to the (captured) file sink; the banner is emitted once per
        // session, so reset it so the capture starts clean.
        pgbr_core::log::set_level_file(pgbr_core::log::LOG_LEVEL_INFO);
        pgbr_core::log::set_file_banner(false);

        let cfg = fake_config("demo", Some(label), &[("key1", "value1")]);
        annotate(&cfg, &repo).expect("annotate should succeed");

        let captured = String::from_utf8(pgbr_core::log::capture::drain()).expect("captured bytes are utf-8");
        pgbr_core::log::capture::uninstall();

        assert!(
            captured.contains("backup set '20240101-120000F' annotated (1 set, 0 removed)"),
            "logger should carry the annotate confirmation, got: {captured:?}"
        );
        assert!(
            captured.contains("INFO:"),
            "confirmation must be logged at INFO, got: {captured:?}"
        );
    }
}
