//! `info` command — read `archive.info` and `backup.info` from the repo
//! and print a structured per-stanza summary.
//!
//! C reference: `src/command/info/info.c`. Each stanza is reported
//! independently: a missing `archive.info` *or* missing `backup.info`
//! degrades to a partial summary rather than failing the whole command.
//! When `--stanza` is omitted the command discovers every stanza visible
//! under `archive/` and `backup/` and reports the union.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use pgbr_config::LoadedConfig;
use pgbr_info::{InfoArchive, InfoBackup};
use pgbr_storage::{Storage, StorageError, StorageKind};

use crate::CommandError;

/// Top-level status for a stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StanzaStatus {
    /// Both `archive.info` and `backup.info` loaded cleanly.
    Ok,
    /// Neither info file exists — stanza has not been initialised.
    NotInitialized,
    /// At least one of the info files failed to load (missing or malformed).
    /// The contained string is a human-readable reason suitable for display.
    Error(String),
}

/// Summary of one backup row from `[backup:current]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    /// Backup label, e.g. `20260101-100000F`.
    pub label: String,
    /// `full`, `diff`, `incr`, or whatever the on-disk value was.
    pub backup_type: String,
    /// `backup-timestamp-stop` — Unix epoch seconds. `None` if the field is
    /// missing or not an integer.
    pub stop_timestamp: Option<i64>,
    /// `backup-info-repo-size` — total bytes of this backup in the repo.
    /// `None` if the field is missing or not an integer.
    pub repo_size: Option<u64>,
}

/// Summary of one stanza, suitable for display or programmatic inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StanzaSummary {
    /// Stanza name.
    pub name: String,
    /// Loaded status — `Ok`, `NotInitialized`, or `Error(reason)`.
    pub status: StanzaStatus,
    /// Active cluster's textual major-version label (e.g. `"14"`). `None`
    /// when neither info file loaded.
    pub pg_version: Option<String>,
    /// Active cluster's `pg_control.system_identifier`. `None` when neither
    /// info file loaded.
    pub pg_system_id: Option<u64>,
    /// Backups discovered in `[backup:current]`. Empty when `backup.info`
    /// did not load or the section was empty.
    pub backups: Vec<BackupSummary>,
}

/// Render a byte count with a binary-prefix suffix.
#[allow(clippy::cast_precision_loss)]
fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    // Casts lose precision for sizes above 2^53 bytes (8 PiB), which is well outside
    // the range of any realistic pgBackRest backup. Suppressed locally.
    if bytes >= TIB {
        format!("{:.1}TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1}GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

/// Pull a `Vec<String>` of stanza names from a `<top>/<stanza>` directory.
/// A missing top directory yields an empty list (the stanza set is
/// open-ended; not having any backups yet is not an error).
fn list_stanzas_under(storage: &dyn Storage, top: &Path) -> Result<Vec<String>, CommandError> {
    match storage.list(top) {
        Ok(entries) => {
            let mut names = Vec::new();
            for info in entries {
                if !matches!(info.kind, StorageKind::Path) {
                    continue;
                }
                if let Some(name) = info.path.file_name().and_then(|n| n.to_str()) {
                    names.push(name.to_owned());
                }
            }
            Ok(names)
        }
        Err(StorageError::NotFound { .. }) => Ok(Vec::new()),
        Err(err) => Err(err.into()),
    }
}

/// Discover every stanza name visible in the repository — the union of
/// directory entries under `archive/` and `backup/`.
fn discover_stanzas(repo_storage: &dyn Storage) -> Result<Vec<String>, CommandError> {
    let mut names = list_stanzas_under(repo_storage, Path::new("archive"))?;
    names.extend(list_stanzas_under(repo_storage, Path::new("backup"))?);
    names.sort();
    names.dedup();
    Ok(names)
}

/// Decode one `[backup:current]` entry into a `BackupSummary`.
fn decode_backup(label: &str, value: &serde_json::Value) -> BackupSummary {
    let backup_type = value
        .get("backup-type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?")
        .to_owned();
    let stop_timestamp = value.get("backup-timestamp-stop").and_then(serde_json::Value::as_i64);
    let repo_size = value.get("backup-info-repo-size").and_then(serde_json::Value::as_u64);
    BackupSummary {
        label: label.to_owned(),
        backup_type,
        stop_timestamp,
        repo_size,
    }
}

/// Build a `StanzaSummary` for `name` by attempting to load both info files.
/// Each is tried independently — a missing file degrades to `NotInitialized`
/// or `Error(...)` rather than propagating.
fn summarize_stanza(repo_storage: &dyn Storage, name: &str) -> StanzaSummary {
    let archive_path = PathBuf::from(format!("archive/{name}/archive.info"));
    let backup_path = PathBuf::from(format!("backup/{name}/backup.info"));

    let archive = InfoArchive::load(repo_storage, &archive_path);
    let backup = InfoBackup::load(repo_storage, &backup_path);

    let archive_missing = matches!(archive, Err(pgbr_info::InfoError::Storage(StorageError::NotFound { .. })));
    let backup_missing = matches!(backup, Err(pgbr_info::InfoError::Storage(StorageError::NotFound { .. })));

    let status = match (&archive, &backup) {
        (Ok(_), Ok(_)) => StanzaStatus::Ok,
        _ if archive_missing && backup_missing => StanzaStatus::NotInitialized,
        (Err(err), _) if !archive_missing => StanzaStatus::Error(format!("archive.info: {err}")),
        (_, Err(err)) if !backup_missing => StanzaStatus::Error(format!("backup.info: {err}")),
        _ => StanzaStatus::Error("partial: one info file missing".to_owned()),
    };

    // Prefer backup.info for identity (it has catalog/control versions);
    // fall back to archive.info when only that loaded.
    let (pg_version, pg_system_id) = match (&archive, &backup) {
        (_, Ok(b)) => (Some(b.db_version.clone()), Some(b.db_system_id)),
        (Ok(a), _) => (Some(a.db_version.clone()), Some(a.db_system_id)),
        _ => (None, None),
    };

    let backups = backup.as_ref().map_or_else(
        |_| Vec::new(),
        |b| b.current.iter().map(|(label, value)| decode_backup(label, value)).collect(),
    );

    StanzaSummary {
        name: name.to_owned(),
        status,
        pg_version,
        pg_system_id,
        backups,
    }
}

/// Pure entry point — returns one `StanzaSummary` per resolved stanza.
///
/// Used by tests to assert on the typed return value rather than scraping
/// stdout. The CLI wrapper `info` calls this and prints each summary.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if the repository listing fails (for
/// the no-stanza-arg path that has to scan `archive/` and `backup/`).
/// Per-stanza failures are reported inside the corresponding
/// [`StanzaSummary::status`] and never propagate.
pub fn info_inner(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<Vec<StanzaSummary>, CommandError> {
    let stanzas = if let Some(name) = config.stanza.as_deref() {
        vec![name.to_owned()]
    } else {
        discover_stanzas(repo_storage)?
    };

    let summaries = stanzas.iter().map(|name| summarize_stanza(repo_storage, name)).collect();
    Ok(summaries)
}

/// Render one `StanzaSummary` to a human-readable multi-line string.
fn format_stanza(summary: &StanzaSummary) -> String {
    let mut out = String::new();
    // Writing into a String never fails, so the `_ =` is purely for the compiler.
    let _ = writeln!(out, "stanza: {}", summary.name);
    let status_line = match &summary.status {
        StanzaStatus::Ok => "ok".to_owned(),
        StanzaStatus::NotInitialized => "error (stanza not initialized)".to_owned(),
        StanzaStatus::Error(reason) => format!("error ({reason})"),
    };
    let _ = writeln!(out, "    status: {status_line}");
    if let Some(v) = &summary.pg_version {
        let _ = writeln!(out, "    pg_version: {v}");
    }
    if let Some(id) = summary.pg_system_id {
        let _ = writeln!(out, "    pg_system_id: {id}");
    }
    if !summary.backups.is_empty() {
        out.push_str("    backups:\n");
        for b in &summary.backups {
            let stop = b.stop_timestamp.map_or_else(|| "?".to_owned(), |ts| ts.to_string());
            let size = b.repo_size.map_or_else(|| "?".to_owned(), human_size);
            let _ = writeln!(out, "        {} ({}) {} {}", b.label, b.backup_type, stop, size);
        }
    }
    out
}

/// `info` — print backup history for one or more stanzas.
///
/// # Errors
///
/// Returns whatever [`info_inner`] surfaces.
// CLI command: writing to stdout is the whole point.
#[allow(clippy::print_stdout)]
pub fn info(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let summaries = info_inner(config, repo_storage)?;
    for summary in &summaries {
        print!("{}", format_stanza(summary));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};
    use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{StanzaStatus, info_inner};

    fn fake_config(stanza: Option<&str>) -> LoadedConfig {
        LoadedConfig {
            command: "info".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options: BTreeMap::new(),
            params: Vec::new(),
        }
    }

    fn posix_repo() -> (TempDir, Posix) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(dir.path());
        (dir, storage)
    }

    fn sample_archive() -> InfoArchive {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            history,
        }
    }

    fn sample_backup_with(current: BTreeMap<String, serde_json::Value>) -> InfoBackup {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        }
    }

    #[test]
    fn info_for_uninitialized_stanza_reports_not_initialized() {
        let (_dir, storage) = posix_repo();

        let cfg = fake_config(Some("demo"));
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "demo");
        assert_eq!(summaries[0].status, StanzaStatus::NotInitialized);
        assert!(summaries[0].pg_version.is_none());
        assert!(summaries[0].pg_system_id.is_none());
        assert!(summaries[0].backups.is_empty());
    }

    #[test]
    fn info_with_archive_only_reports_no_backups() {
        let (_dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");

        sample_archive()
            .save(&storage, std::path::Path::new("archive/demo/archive.info"))
            .expect("save archive.info");

        let cfg = fake_config(Some("demo"));
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.name, "demo");
        // archive.info loaded, backup.info missing => Error(...)
        assert!(matches!(s.status, StanzaStatus::Error(_)), "got {:?}", s.status);
        assert_eq!(s.pg_version.as_deref(), Some("14"));
        assert!(s.backups.is_empty());
    }

    #[test]
    fn info_with_archive_and_backup_lists_each_backup() {
        let (_dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");
        storage
            .create_path(std::path::Path::new("backup/demo"), true)
            .expect("create backup/demo");

        sample_archive()
            .save(&storage, std::path::Path::new("archive/demo/archive.info"))
            .expect("save archive.info");

        let mut current = BTreeMap::new();
        current.insert(
            "20260101-100000F".to_owned(),
            json!({
                "backup-info-size": 12345,
                "backup-info-repo-size": 67890,
                "backup-label": "20260101-100000F",
                "backup-timestamp-stop": 1_700_000_000,
                "backup-type": "full"
            }),
        );
        current.insert(
            "20260101-100000F_20260102-100000I".to_owned(),
            json!({
                "backup-info-size": 99,
                "backup-info-repo-size": 50,
                "backup-label": "20260101-100000F_20260102-100000I",
                "backup-timestamp-stop": 1_700_086_400,
                "backup-type": "incr",
                "backup-prior": "20260101-100000F"
            }),
        );

        sample_backup_with(current)
            .save(&storage, std::path::Path::new("backup/demo/backup.info"))
            .expect("save backup.info");

        let cfg = fake_config(Some("demo"));
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.name, "demo");
        assert_eq!(s.status, StanzaStatus::Ok);
        assert_eq!(s.pg_version.as_deref(), Some("14"));
        assert_eq!(s.backups.len(), 2);

        let labels: Vec<&str> = s.backups.iter().map(|b| b.label.as_str()).collect();
        assert!(labels.iter().any(|l| *l == "20260101-100000F"));
        assert!(labels.iter().any(|l| *l == "20260101-100000F_20260102-100000I"));

        let full = s.backups.iter().find(|b| b.label == "20260101-100000F").unwrap();
        assert_eq!(full.backup_type, "full");
        assert_eq!(full.stop_timestamp, Some(1_700_000_000));
        assert_eq!(full.repo_size, Some(67890));
    }

    #[test]
    fn info_no_stanza_arg_lists_all_stanzas_found() {
        let (_dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");
        storage
            .create_path(std::path::Path::new("archive/prod"), true)
            .expect("create archive/prod");

        let cfg = fake_config(None);
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 2);
        let names: Vec<&str> = summaries.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"demo"), "got {names:?}");
        assert!(names.contains(&"prod"), "got {names:?}");
        // Neither has info files; both should report NotInitialized.
        for s in &summaries {
            assert_eq!(s.status, StanzaStatus::NotInitialized);
        }
    }
}
