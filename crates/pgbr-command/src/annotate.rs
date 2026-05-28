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

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::InfoBackup;
use pgbr_storage::Storage;
use serde_json::{Map, Value};

use crate::CommandError;

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

/// Apply the annotation hash to one backup entry's JSON value, mutating the
/// `backup-annotation` object in place. Returns the keys set and removed so
/// the caller can report what changed.
fn apply_annotations(entry: &mut Value, requested: &BTreeMap<String, String>) -> (Vec<String>, Vec<String>) {
    let mut set_keys = Vec::new();
    let mut removed_keys = Vec::new();

    // Pull out (or start) the existing annotation object. If the field holds
    // a non-object value it is treated as absent and replaced.
    let mut annotation = match entry.get(ANNOTATION_KEY) {
        Some(Value::Object(existing)) => existing.clone(),
        _ => Map::new(),
    };

    for (key, value) in requested {
        if value.is_empty() {
            // Empty value -> delete convention. Only count keys that were
            // actually present.
            if annotation.remove(key).is_some() {
                removed_keys.push(key.clone());
            }
        } else {
            annotation.insert(key.clone(), Value::String(value.clone()));
            set_keys.push(key.clone());
        }
    }

    // Reflect the merged object back onto the entry. An emptied object is
    // dropped entirely (matches the C `backupAnnotation = NULL` behaviour).
    if let Value::Object(obj) = entry {
        if annotation.is_empty() {
            obj.remove(ANNOTATION_KEY);
        } else {
            obj.insert(ANNOTATION_KEY.to_owned(), Value::Object(annotation));
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
/// # Errors
///
/// Surfaces whatever [`annotate_inner`] returns; see its docs.
#[allow(clippy::print_stdout)]
pub fn annotate(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let result = annotate_inner(config, repo_storage)?;

    println!(
        "backup set '{}' annotated ({} set, {} removed)",
        result.backup_label,
        result.set_keys.len(),
        result.removed_keys.len()
    );

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

    use super::{CommandError, annotate_inner};

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
}
