//! `expire` command — apply retention policy to existing backups and WAL.
//!
//! C reference: `src/command/expire/expire.c`. The Rust port implements
//! full-backup retention (`repo-retention-full`) followed by WAL-archive
//! retention (`repo-retention-archive`):
//!
//! - Loads `backup/<stanza>/backup.info` via [`pgbr_info::InfoBackup`].
//! - Sorts the `[backup:current]` entries by `backup-timestamp-stop`.
//! - Keeps the N most recent full backups; everything older — full,
//!   diff, or incr — is removed via [`Storage::remove_path`] (recursive
//!   and idempotent on missing).
//! - Rewrites `backup.info` without the expired labels.
//! - Then, if `repo-retention-archive` is set, removes archived WAL
//!   segments under `archive/<stanza>/` that predate the WAL needed to
//!   recover the oldest backup still inside the archive-retention window
//!   (see [`expire_archive`]).
//!
//! Missing `repo-retention-full` leaves every backup in place (matches
//! the C behaviour); missing `repo-retention-archive` leaves every WAL
//! segment in place.
//!
//! ## Simplifications (documented deferrals)
//!
//! - `repo-retention-archive-type` is read but archive retention is
//!   always counted against **full** backups (the common case). The
//!   C tree additionally supports counting against diff/incr backups;
//!   that variant is deferred.
//! - WAL lives in a flat `archive/<stanza>/<segment>` layout (matching
//!   [`crate::archive`]), not the C tree's per-version `archive/<stanza>/
//!   <version>-<db-id>/<segment-prefix>/<segment>` scheme. Cross-timeline
//!   WAL handling is therefore out of scope — segment names are compared
//!   as strings, which is the correct ordering *within* a timeline (names
//!   are zero-padded hex and sort lexicographically in timeline order).

use std::path::PathBuf;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoBackup, InfoError};
use pgbr_storage::{Storage, StorageError, StorageKind};

use crate::CommandError;

/// Outcome of an [`expire_inner`] pass: which labels were removed and
/// which were retained, in chronological order (oldest first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpireSummary {
    /// Backup labels removed by this pass.
    pub expired_labels: Vec<String>,
    /// Backup labels left in place after this pass.
    pub kept_labels: Vec<String>,
    /// Archived WAL segment names removed by this pass (base segment names,
    /// without any compression suffix), in ascending order. Empty when
    /// `repo-retention-archive` is unset or nothing qualified for removal.
    pub expired_archive_segments: Vec<String>,
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

/// `repo-retention-archive` lookup. Missing option is reported as `None`
/// (archive expiry is skipped entirely). A non-positive or non-integer
/// value is reported as `None` / `Other` respectively — a zero/negative
/// retention is treated as "unset" to match the C tree, which skips
/// archive expiry when the option is not effectively set.
fn retention_archive(config: &LoadedConfig) -> Result<Option<u32>, CommandError> {
    match config.options.get(&("repo-retention-archive".to_owned(), None)) {
        None => Ok(None),
        Some(OptionValue::Integer(n)) => {
            if *n <= 0 {
                Ok(None)
            } else {
                u32::try_from(*n)
                    .map(Some)
                    .map_err(|_| CommandError::Other(format!("repo-retention-archive out of range: {n}")))
            }
        }
        Some(other) => Err(CommandError::Other(format!(
            "repo-retention-archive must be an integer, got {other:?}"
        ))),
    }
}

/// Pull `backup-archive-start` out of a `[backup:current]` entry, or
/// `None` if the backup did not record one (e.g. a backup taken with
/// `--no-online`, or one whose WAL range is unknown).
fn backup_archive_start(value: &serde_json::Value) -> Option<&str> {
    value.get("backup-archive-start").and_then(serde_json::Value::as_str)
}

/// Strip a known compression suffix (`.gz`/`.zst`/`.bz2`/`.lz4`) from a
/// stored WAL file name to recover its base segment name. Names that
/// carry no recognised suffix are returned unchanged.
///
/// Kept in sync with [`crate::archive`]'s `COMPRESS_SUFFIXES`.
fn strip_compress_suffix(name: &str) -> &str {
    for suffix in [".gz", ".zst", ".bz2", ".lz4"] {
        if let Some(base) = name.strip_suffix(suffix) {
            return base;
        }
    }
    name
}

/// WAL-archive retention pass, run *after* backup expiry.
///
/// `keep_archive` is `repo-retention-archive`: the number of (full)
/// backups, counting from the newest, whose WAL must be retained.
/// `kept_full_oldest_first` is the list of full-backup `[backup:current]`
/// entries that survived backup expiry, oldest first.
///
/// The cutoff is the `backup-archive-start` of the Nth-most-recent
/// retained full backup (N = `keep_archive`). Every archived WAL segment
/// whose base name sorts strictly before that cutoff is removed; the
/// cutoff segment and everything after it is kept (it is the WAL needed
/// to recover the oldest backup still inside the retention window).
///
/// When fewer full backups survive than `keep_archive` requires, or the
/// retained backup recorded no `backup-archive-start`, nothing is removed
/// — it is "too soon" to expire WAL, matching the C tree.
///
/// Returns the removed base segment names in ascending order.
fn expire_archive(
    repo: &dyn Storage,
    stanza: &str,
    keep_archive: u32,
    kept_full_oldest_first: &[serde_json::Value],
) -> Result<Vec<String>, CommandError> {
    // Too few backups to satisfy archive retention -> keep all WAL.
    let keep_archive = keep_archive as usize;
    if kept_full_oldest_first.len() < keep_archive {
        return Ok(Vec::new());
    }

    // The Nth-most-recent retained full backup (newest = index len-1).
    // Its `backup-archive-start` is the cutoff: WAL before it can go.
    let cutoff_index = kept_full_oldest_first.len() - keep_archive;
    let Some(cutoff) = backup_archive_start(&kept_full_oldest_first[cutoff_index]) else {
        // Retained backup has no recorded WAL range -> keep all WAL.
        return Ok(Vec::new());
    };

    // Enumerate WAL segments. The archive directory may not exist yet
    // (no WAL pushed) — treat a missing directory as "no segments".
    let archive_dir = PathBuf::from(format!("archive/{stanza}"));
    let entries = match repo.list(&archive_dir) {
        Ok(entries) => entries,
        Err(StorageError::NotFound { .. }) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    // Remove every file segment whose base name sorts before the cutoff.
    let mut removed: Vec<String> = Vec::new();
    for entry in entries {
        if entry.kind != StorageKind::File {
            continue;
        }
        let Some(file_name) = entry.path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let base = strip_compress_suffix(file_name);
        if base < cutoff {
            let path = archive_dir.join(file_name);
            match repo.remove(&path, false) {
                Ok(()) | Err(StorageError::NotFound { .. }) => {}
                Err(err) => return Err(err.into()),
            }
            removed.push(base.to_owned());
        }
    }

    removed.sort();
    Ok(removed)
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
            expired_archive_segments: Vec::new(),
        });
    };

    // No backup retention configured. Backups are all kept, but archive
    // retention may still apply against the surviving full backups.
    let Some(keep_full) = retention_full(config)? else {
        let kept_labels: Vec<String> = info.current.keys().cloned().collect();
        let kept_full_oldest_first = full_backups_oldest_first(&info, &kept_labels);
        let expired_archive_segments = match retention_archive(config)? {
            Some(keep_archive) => expire_archive(repo, stanza, keep_archive, &kept_full_oldest_first)?,
            None => Vec::new(),
        };
        return Ok(ExpireSummary {
            expired_labels: Vec::new(),
            kept_labels,
            expired_archive_segments,
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

    // Archive retention runs after backups are expired, counted against
    // the full backups that survived (in `kept_labels`, oldest first).
    let kept_full_oldest_first = full_backups_oldest_first(&info, &kept_labels);
    let expired_archive_segments = match retention_archive(config)? {
        Some(keep_archive) => expire_archive(repo, stanza, keep_archive, &kept_full_oldest_first)?,
        None => Vec::new(),
    };

    Ok(ExpireSummary {
        expired_labels,
        kept_labels,
        expired_archive_segments,
    })
}

/// Collect the `[backup:current]` JSON entries for the full backups named
/// in `kept_labels`, preserving the order of `kept_labels` (which callers
/// pass oldest-first). Labels absent from `info.current`, or whose entry
/// is not a full backup, are skipped.
fn full_backups_oldest_first(info: &InfoBackup, kept_labels: &[String]) -> Vec<serde_json::Value> {
    kept_labels
        .iter()
        .filter_map(|label| info.current.get(label))
        .filter(|value| backup_type(value) == "full")
        .cloned()
        .collect()
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
    if !summary.expired_archive_segments.is_empty() {
        println!(
            "expire: removed {} archived WAL segment(s)",
            summary.expired_archive_segments.len()
        );
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
        cfg_archive(stanza, retention_full, None)
    }

    /// `cfg` plus an optional `repo-retention-archive` integer.
    fn cfg_archive(stanza: Option<&str>, retention_full: Option<i64>, retention_archive: Option<i64>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(n) = retention_full {
            options.insert(("repo-retention-full".to_owned(), None), OptionValue::Integer(n));
        }
        if let Some(n) = retention_archive {
            options.insert(("repo-retention-archive".to_owned(), None), OptionValue::Integer(n));
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

    /// Build an `InfoBackup` and seed it, recording WAL ranges. Each
    /// `(label, ts, ty, archive_start, archive_stop)` tuple becomes one
    /// `[backup:current]` row carrying `backup-archive-start`/`-stop`.
    fn seed_backup_info_wal(repo: &Posix, stanza: &str, entries: &[(&str, i64, &str, &str, &str)]) {
        let mut current = BTreeMap::new();
        for (label, ts, ty, archive_start, archive_stop) in entries {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
                    "backup-timestamp-stop": ts,
                    "backup-type": *ty,
                    "backup-archive-start": *archive_start,
                    "backup-archive-stop": *archive_stop,
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

    /// Materialise an archived WAL segment file at
    /// `archive/<stanza>/<segment>` so archive expiry has something to
    /// remove. `suffix` lets a test simulate a compressed segment.
    fn seed_archive_segment(repo: &Posix, stanza: &str, segment: &str, suffix: &str) {
        let dir = format!("archive/{stanza}");
        repo.create_path(Path::new(&dir), true).expect("create archive dir");
        let mut w = repo
            .open_write(Path::new(&format!("{dir}/{segment}{suffix}")))
            .expect("open segment");
        w.write(b"wal").expect("write segment");
        w.close().expect("close segment");
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
                expired_archive_segments: Vec::new(),
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

    #[test]
    fn archive_retention_absent_is_noop() {
        let (dir, repo) = empty_repo();
        // Three fulls with `repo-retention-full` keeping all three, no
        // `repo-retention-archive` -> WAL is left completely untouched.
        seed_backup_info_wal(
            &repo,
            "demo",
            &[
                (
                    "20260101-100000F",
                    100,
                    "full",
                    "000000010000000000000001",
                    "000000010000000000000002",
                ),
                (
                    "20260101-110000F",
                    200,
                    "full",
                    "000000010000000000000005",
                    "000000010000000000000006",
                ),
                (
                    "20260101-120000F",
                    300,
                    "full",
                    "000000010000000000000009",
                    "00000001000000000000000A",
                ),
            ],
        );
        for seg in [
            "000000010000000000000001",
            "000000010000000000000005",
            "000000010000000000000009",
        ] {
            seed_archive_segment(&repo, "demo", seg, "");
        }

        // retention-full=3 keeps all; retention-archive unset.
        let summary = expire_inner(&cfg(Some("demo"), Some(3)), &repo).expect("expire_inner");

        assert!(
            summary.expired_archive_segments.is_empty(),
            "no archive retention -> no segments removed"
        );
        for seg in [
            "000000010000000000000001",
            "000000010000000000000005",
            "000000010000000000000009",
        ] {
            assert!(
                dir.path().join(format!("archive/demo/{seg}")).exists(),
                "segment {seg} must remain when archive retention is unset"
            );
        }
    }

    #[test]
    fn archive_retention_removes_segments_before_retained_backup() {
        let (dir, repo) = empty_repo();
        // Three fulls; keep all backups (retention-full=3) but retain WAL
        // for only the newest backup (retention-archive=1). The cutoff is
        // the newest backup's archive-start (...0009): segments before it
        // are removed, segments from it on are kept.
        seed_backup_info_wal(
            &repo,
            "demo",
            &[
                (
                    "20260101-100000F",
                    100,
                    "full",
                    "000000010000000000000001",
                    "000000010000000000000002",
                ),
                (
                    "20260101-110000F",
                    200,
                    "full",
                    "000000010000000000000005",
                    "000000010000000000000006",
                ),
                (
                    "20260101-120000F",
                    300,
                    "full",
                    "000000010000000000000009",
                    "00000001000000000000000A",
                ),
            ],
        );
        // WAL spanning before, at, and after the cutoff. The ...0008 file
        // carries a `.gz` suffix to prove the suffix is stripped before
        // the string comparison.
        seed_archive_segment(&repo, "demo", "000000010000000000000001", "");
        seed_archive_segment(&repo, "demo", "000000010000000000000005", "");
        seed_archive_segment(&repo, "demo", "000000010000000000000008", ".gz");
        seed_archive_segment(&repo, "demo", "000000010000000000000009", "");
        seed_archive_segment(&repo, "demo", "00000001000000000000000A", "");

        let summary = expire_inner(&cfg_archive(Some("demo"), Some(3), Some(1)), &repo).expect("expire_inner");

        assert_eq!(
            summary.expired_archive_segments,
            vec![
                "000000010000000000000001".to_owned(),
                "000000010000000000000005".to_owned(),
                "000000010000000000000008".to_owned(),
            ],
            "segments strictly before the cutoff archive-start are removed"
        );
        assert!(!dir.path().join("archive/demo/000000010000000000000001").exists());
        assert!(!dir.path().join("archive/demo/000000010000000000000005").exists());
        assert!(!dir.path().join("archive/demo/000000010000000000000008.gz").exists());
        assert!(
            dir.path().join("archive/demo/000000010000000000000009").exists(),
            "the cutoff segment itself is kept"
        );
        assert!(
            dir.path().join("archive/demo/00000001000000000000000A").exists(),
            "segments after the cutoff are kept"
        );
    }

    #[test]
    fn archive_retention_keeps_all_when_n_exceeds_backup_count() {
        let (dir, repo) = empty_repo();
        // Two fulls but archive retention asks for 5 backups' worth of WAL:
        // too soon to expire anything, so every segment is preserved.
        seed_backup_info_wal(
            &repo,
            "demo",
            &[
                (
                    "20260101-100000F",
                    100,
                    "full",
                    "000000010000000000000005",
                    "000000010000000000000006",
                ),
                (
                    "20260101-110000F",
                    200,
                    "full",
                    "000000010000000000000009",
                    "00000001000000000000000A",
                ),
            ],
        );
        // An old segment that *would* be removed if the cutoff applied.
        seed_archive_segment(&repo, "demo", "000000010000000000000001", "");
        seed_archive_segment(&repo, "demo", "000000010000000000000005", "");

        let summary = expire_inner(&cfg_archive(Some("demo"), Some(2), Some(5)), &repo).expect("expire_inner");

        assert!(
            summary.expired_archive_segments.is_empty(),
            "retention larger than the backup count removes nothing"
        );
        assert!(dir.path().join("archive/demo/000000010000000000000001").exists());
        assert!(dir.path().join("archive/demo/000000010000000000000005").exists());
    }
}
