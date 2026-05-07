//! `expire` command — apply retention policy to existing backups.
//!
//! C reference: `src/command/expire/expire.c`. The Rust port currently
//! implements full-backup retention (`repo-retention-full`) only:
//!
//! - Loads `backup/<stanza>/backup.info` via [`pgbr_info::InfoBackup`].
//! - Sorts the `[backup:current]` entries by `backup-timestamp-stop`.
//! - Keeps the N most recent full backups; everything older — full,
//!   diff, or incr — is removed via [`Storage::remove_path`] (recursive
//!   and idempotent on missing).
//! - Rewrites `backup.info` without the expired labels.
//!
//! `repo-retention-archive` (PITR archive expiry) is intentionally
//! deferred — the WAL-segment lookup and lock semantics deserve their
//! own commit. Missing `repo-retention-full` is a no-op (matches the C
//! behaviour of leaving every backup in place).

use std::path::PathBuf;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoBackup, InfoError};
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;

/// Outcome of an [`expire_inner`] pass: which labels were removed and
/// which were retained, in chronological order (oldest first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpireSummary {
    /// Backup labels removed by this pass.
    pub expired_labels: Vec<String>,
    /// Backup labels left in place after this pass.
    pub kept_labels: Vec<String>,
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// Load `backup.info`. Returns `Ok(None)` if the file does not exist
/// (yields a no-op in [`expire_inner`]). Other failures map to typed
/// [`CommandError`]s.
fn load_backup_info(repo: &dyn Storage, stanza: &str) -> Result<Option<InfoBackup>, CommandError> {
    let path = backup_info_path(stanza);
    match repo.exists(&path) {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(err) => return Err(err.into()),
    }

    match InfoBackup::load(repo, &path) {
        Ok(info) => Ok(Some(info)),
        Err(InfoError::Storage(StorageError::NotFound { .. })) => Ok(None),
        Err(err) => Err(CommandError::Other(err.to_string())),
    }
}

/// Pull `backup-timestamp-stop` out of a `[backup:current]` entry. Missing
/// or malformed values are treated as `0` so older corrupt entries sort
/// to the front and are the first to expire — matches the C tendency to
/// trust the file but stay deterministic when it is partially malformed.
fn timestamp_stop(value: &serde_json::Value) -> i64 {
    value
        .get("backup-timestamp-stop")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

/// Pull `backup-type` out of a `[backup:current]` entry. Returns `""` if
/// absent, which causes the entry to be treated as a non-full backup.
fn backup_type(value: &serde_json::Value) -> &str {
    value.get("backup-type").and_then(serde_json::Value::as_str).unwrap_or("")
}

/// `repo-retention-full` lookup. Missing option is reported as `None`
/// (no-op). A non-integer value is reported as `Other`.
fn retention_full(config: &LoadedConfig) -> Result<Option<u32>, CommandError> {
    match config.options.get(&("repo-retention-full".to_owned(), None)) {
        None => Ok(None),
        Some(OptionValue::Integer(n)) => {
            if *n <= 0 {
                Ok(Some(0))
            } else {
                u32::try_from(*n)
                    .map(Some)
                    .map_err(|_| CommandError::Other(format!("repo-retention-full out of range: {n}")))
            }
        }
        Some(other) => Err(CommandError::Other(format!(
            "repo-retention-full must be an integer, got {other:?}"
        ))),
    }
}

/// Core retention pass. The thin [`expire`] entry point prints the
/// summary and returns `()`; tests assert against [`ExpireSummary`]
/// directly.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for backend
///   failures while loading `backup.info`, removing backup directories,
///   or re-saving the info file.
/// - [`CommandError::Other`] if `repo-retention-full` is present but
///   carries a non-integer / out-of-range value, or if the loaded
///   `backup.info` is malformed.
pub fn expire_inner(config: &LoadedConfig, repo: &dyn Storage) -> Result<ExpireSummary, CommandError> {
    let stanza = require_stanza(config)?;

    // No backup.info -> nothing to do.
    let Some(mut info) = load_backup_info(repo, stanza)? else {
        return Ok(ExpireSummary {
            expired_labels: Vec::new(),
            kept_labels: Vec::new(),
        });
    };

    // No retention configured -> nothing to do (matches C: archive-side
    // retention is intentionally out of scope for this slice).
    let Some(keep_full) = retention_full(config)? else {
        let kept_labels: Vec<String> = info.current.keys().cloned().collect();
        return Ok(ExpireSummary {
            expired_labels: Vec::new(),
            kept_labels,
        });
    };

    // Sort current entries oldest-first by backup-timestamp-stop. Ties
    // break by label so the order is stable across runs.
    let mut entries: Vec<(String, serde_json::Value)> = info.current.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    entries.sort_by(|(a_label, a_val), (b_label, b_val)| {
        timestamp_stop(a_val)
            .cmp(&timestamp_stop(b_val))
            .then_with(|| a_label.cmp(b_label))
    });

    // Walk newest-first across full backups, marking the most recent
    // `keep_full` for retention.
    let mut full_kept: usize = 0;
    let mut keep_label: Vec<bool> = vec![false; entries.len()];
    let cutoff_full_ts: Option<i64> = if keep_full == 0 {
        None
    } else {
        let mut last_full_ts: Option<i64> = None;
        for idx in (0..entries.len()).rev() {
            if backup_type(&entries[idx].1) == "full" && full_kept < keep_full as usize {
                keep_label[idx] = true;
                full_kept += 1;
                last_full_ts = Some(timestamp_stop(&entries[idx].1));
            }
        }
        last_full_ts
    };

    // Every diff/incr backup whose timestamp is at least the oldest
    // retained full's timestamp is kept; everything older expires (its
    // parent full is gone, so the chain is broken).
    if let Some(cutoff) = cutoff_full_ts {
        for (idx, (_, value)) in entries.iter().enumerate() {
            if !keep_label[idx] && timestamp_stop(value) >= cutoff && backup_type(value) != "full" {
                keep_label[idx] = true;
            }
        }
    }

    let mut expired_labels: Vec<String> = Vec::new();
    let mut kept_labels: Vec<String> = Vec::new();
    for (idx, (label, _)) in entries.iter().enumerate() {
        if keep_label[idx] {
            kept_labels.push(label.clone());
        } else {
            expired_labels.push(label.clone());
        }
    }

    // Remove the on-disk backup directory for every expired label; the
    // call is recursive and idempotent so a partially-deleted backup is
    // a no-op rather than a failure.
    for label in &expired_labels {
        let path = PathBuf::from(format!("backup/{stanza}/{label}"));
        match repo.remove_path(&path, true, false) {
            Ok(()) | Err(StorageError::NotFound { .. }) => {}
            Err(err) => return Err(err.into()),
        }
        info.current.remove(label);
    }

    // Persist the rewritten backup.info only when something actually
    // changed — keeps the file's mtime stable on no-op runs.
    if !expired_labels.is_empty() {
        let path = backup_info_path(stanza);
        info.save(repo, &path).map_err(|err| CommandError::Other(err.to_string()))?;
    }

    Ok(ExpireSummary {
        expired_labels,
        kept_labels,
    })
}

/// `expire` — apply retention policy to existing backups.
///
/// Thin printer over [`expire_inner`]: writes a one-line summary of the
/// retention pass to stdout and returns `Ok(())` on success.
///
/// # Errors
///
/// Forwards every error from [`expire_inner`].
pub fn expire(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let summary = expire_inner(config, repo_storage)?;
    if summary.expired_labels.is_empty() {
        println!("expire: nothing to expire ({} kept)", summary.kept_labels.len());
    } else {
        println!(
            "expire: removed {} backup(s), kept {}",
            summary.expired_labels.len(),
            summary.kept_labels.len()
        );
        for label in &summary.expired_labels {
            println!("  expired: {label}");
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{DbHistoryEntry, InfoBackup};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{ExpireSummary, expire_inner};

    fn cfg(stanza: Option<&str>, retention_full: Option<i64>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(n) = retention_full {
            options.insert(("repo-retention-full".to_owned(), None), OptionValue::Integer(n));
        }
        LoadedConfig {
            command: "expire".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    fn empty_repo() -> (TempDir, Posix) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(dir.path());
        (dir, storage)
    }

    /// Build an `InfoBackup` and seed it into `backup/<stanza>/backup.info`.
    /// Each `(label, ts, ty)` tuple becomes one `[backup:current]` row.
    fn seed_backup_info(repo: &Posix, stanza: &str, entries: &[(&str, i64, &str)]) {
        let mut current = BTreeMap::new();
        for (label, ts, ty) in entries {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
                    "backup-timestamp-stop": ts,
                    "backup-type": *ty,
                }),
            );
        }

        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );

        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        };

        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup/<stanza>");
        info.save(repo, &super::backup_info_path(stanza)).expect("save backup.info");
    }

    /// Materialise an empty `backup/<stanza>/<label>/file` so deletion
    /// has something to actually remove.
    fn seed_backup_dir(repo: &Posix, stanza: &str, label: &str) {
        let dir = format!("backup/{stanza}/{label}");
        repo.create_path(Path::new(&dir), true).expect("create backup label dir");
        let mut w = repo.open_write(Path::new(&format!("{dir}/marker"))).expect("open marker");
        w.write(b"x").expect("write marker");
        w.close().expect("close marker");
    }

    #[test]
    fn no_backup_info_is_idempotent_no_op() {
        let (_dir, repo) = empty_repo();
        let summary = expire_inner(&cfg(Some("demo"), Some(2)), &repo).expect("expire_inner");
        assert_eq!(
            summary,
            ExpireSummary {
                expired_labels: Vec::new(),
                kept_labels: Vec::new(),
            }
        );
    }

    #[test]
    fn retention_keeps_latest_n_fulls() {
        let (_dir, repo) = empty_repo();
        seed_backup_info(
            &repo,
            "demo",
            &[
                ("20260101-100000F", 100, "full"),
                ("20260101-110000F", 200, "full"),
                ("20260101-120000F", 300, "full"),
                ("20260101-130000F", 400, "full"),
                ("20260101-140000F", 500, "full"),
            ],
        );

        let summary = expire_inner(&cfg(Some("demo"), Some(2)), &repo).expect("expire_inner");

        assert_eq!(
            summary.kept_labels,
            vec!["20260101-130000F".to_owned(), "20260101-140000F".to_owned()]
        );
        assert_eq!(
            summary.expired_labels,
            vec![
                "20260101-100000F".to_owned(),
                "20260101-110000F".to_owned(),
                "20260101-120000F".to_owned(),
            ]
        );
    }

    #[test]
    fn expired_diff_under_expired_full_also_expires() {
        let (_dir, repo) = empty_repo();
        seed_backup_info(
            &repo,
            "demo",
            &[
                ("20260101-100000F", 100, "full"),
                ("20260101-100000F_20260101-101500D", 150, "diff"),
                ("20260101-200000F", 200, "full"),
            ],
        );

        let summary = expire_inner(&cfg(Some("demo"), Some(1)), &repo).expect("expire_inner");

        assert_eq!(summary.kept_labels, vec!["20260101-200000F".to_owned()]);
        assert_eq!(
            summary.expired_labels,
            vec!["20260101-100000F".to_owned(), "20260101-100000F_20260101-101500D".to_owned(),]
        );
    }

    #[test]
    fn repo_directories_for_expired_backups_are_removed() {
        let (dir, repo) = empty_repo();
        seed_backup_info(
            &repo,
            "demo",
            &[("20260101-100000F", 100, "full"), ("20260101-200000F", 200, "full")],
        );
        seed_backup_dir(&repo, "demo", "20260101-100000F");
        seed_backup_dir(&repo, "demo", "20260101-200000F");

        let expired_path = dir.path().join("backup/demo/20260101-100000F");
        let kept_path = dir.path().join("backup/demo/20260101-200000F");
        assert!(expired_path.exists());
        assert!(kept_path.exists());

        expire_inner(&cfg(Some("demo"), Some(1)), &repo).expect("expire_inner");

        assert!(!expired_path.exists(), "expired backup directory must be removed");
        assert!(kept_path.exists(), "kept backup directory must remain");
    }

    #[test]
    fn backup_info_is_rewritten_without_expired_entries() {
        let (_dir, repo) = empty_repo();
        seed_backup_info(
            &repo,
            "demo",
            &[
                ("20260101-100000F", 100, "full"),
                ("20260101-200000F", 200, "full"),
                ("20260101-300000F", 300, "full"),
            ],
        );

        expire_inner(&cfg(Some("demo"), Some(1)), &repo).expect("expire_inner");

        let reloaded = InfoBackup::load(&repo, &super::backup_info_path("demo")).expect("reload backup.info");
        let labels: Vec<&String> = reloaded.current.keys().collect();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], "20260101-300000F");
    }
}
