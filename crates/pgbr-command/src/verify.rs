//! `verify` command — confirm repository integrity.
//!
//! C reference: `src/command/verify/verify.c`. This first slice covers the
//! manifest-file integrity pass: for each selected backup it loads the
//! backup's `backup.manifest` and re-reads every checksummed file from the
//! repository, recomputing its SHA-1 (via the [`pgbr_io::Sha1`] filter) and
//! comparing it against the value recorded in the manifest. Missing files
//! and size mismatches are detected too.
//!
//! - Backup selection follows `--set <label>`; absent, every label in
//!   `backup/<stanza>/backup.info`'s `[backup:current]` block is verified.
//! - Backup files are read from the flat layout
//!   `backup/<stanza>/<label>/<file.path>` (the C side stores the captured
//!   files under the backup directory).
//!
//! Corruption is **collected, not thrown**: a verify run that finds damage
//! still completes and reports every problem it found. [`verify_inner`]
//! always returns a [`VerifyReport`]; only structural failures — an absent
//! `--stanza`, an unreadable / malformed `backup.info`, or an unreadable
//! `backup.manifest` — bubble up as a [`CommandError`].
//!
//! Archive / WAL verification and the per-page checksum re-validation
//! (`checksum-page`) are intentionally deferred to later commits.

use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoBackup, InfoError, Manifest};
use pgbr_io::{Filter, IoRead, Sha1};
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;

/// A single integrity problem found while verifying a backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyProblem {
    /// The manifest references a file that is not present in the repository.
    MissingFile {
        /// Backup label the file belongs to.
        backup: String,
        /// Manifest-relative path of the missing file.
        path: String,
    },
    /// The file exists but its recomputed SHA-1 does not match the manifest.
    ChecksumMismatch {
        /// Backup label the file belongs to.
        backup: String,
        /// Manifest-relative path of the file.
        path: String,
        /// Checksum recorded in the manifest.
        expected: String,
        /// Checksum recomputed from the on-disk file.
        actual: String,
    },
    /// The file exists but its on-disk size does not match the manifest.
    SizeMismatch {
        /// Backup label the file belongs to.
        backup: String,
        /// Manifest-relative path of the file.
        path: String,
        /// Size recorded in the manifest.
        expected: u64,
        /// Size of the on-disk file.
        actual: u64,
    },
}

/// Result of a [`verify_inner`] pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of backups whose manifests were inspected.
    pub backups_checked: usize,
    /// Number of checksummed files that were re-read and compared.
    pub files_checked: usize,
    /// Every integrity problem found, in the order discovered.
    pub problems: Vec<VerifyProblem>,
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

fn manifest_path(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/backup.manifest"))
}

fn backup_file_path(stanza: &str, label: &str, file: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/{file}"))
}

/// `--set` lookup. Returns the requested single-backup label, or `None`
/// when the option is absent (verify every backup in `backup.info`).
fn requested_set(config: &LoadedConfig) -> Option<&str> {
    match config.options.get(&("set".to_owned(), None)) {
        Some(OptionValue::String(label)) => Some(label.as_str()),
        _ => None,
    }
}

/// Resolve the set of backup labels to verify. With `--set`, just that one
/// (whether or not it appears in `backup.info`). Without, every label in
/// `backup/<stanza>/backup.info`'s `[backup:current]` block.
fn select_backups(config: &LoadedConfig, repo: &dyn Storage, stanza: &str) -> Result<Vec<String>, CommandError> {
    if let Some(label) = requested_set(config) {
        return Ok(vec![label.to_owned()]);
    }

    let info = InfoBackup::load(repo, &backup_info_path(stanza)).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: backup_info_path(stanza),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    Ok(info.current.keys().cloned().collect())
}

/// Recompute the SHA-1 of a repository file by streaming it through the
/// [`Sha1`] filter. Returns `(digest_hex, byte_count)`.
fn hash_repo_file(repo: &dyn Storage, path: &Path) -> Result<(String, u64), CommandError> {
    let mut reader: Box<dyn IoRead> = repo.open_read(path)?;
    let bytes = reader.read_all()?;
    let size = bytes.len() as u64;

    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    sha.process(&bytes, &mut sink)?;
    Ok((sha.digest_hex(), size))
}

/// Verify a single backup's manifest, appending any problems found to
/// `report` and counting every checksummed file inspected.
fn verify_backup(repo: &dyn Storage, stanza: &str, label: &str, report: &mut VerifyReport) -> Result<(), CommandError> {
    let manifest = Manifest::load(repo, &manifest_path(stanza, label)).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: manifest_path(stanza, label),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    report.backups_checked += 1;

    for file in &manifest.files {
        // Zero-length files carry no checksum; nothing to re-read.
        let Some(expected) = file.checksum.as_deref() else {
            continue;
        };

        report.files_checked += 1;

        let path = backup_file_path(stanza, label, &file.path);
        let exists = repo.exists(&path)?;
        if !exists {
            report.problems.push(VerifyProblem::MissingFile {
                backup: label.to_owned(),
                path: file.path.clone(),
            });
            continue;
        }

        let (actual, actual_size) = hash_repo_file(repo, &path)?;

        if actual_size != file.size {
            report.problems.push(VerifyProblem::SizeMismatch {
                backup: label.to_owned(),
                path: file.path.clone(),
                expected: file.size,
                actual: actual_size,
            });
        }

        if actual != expected {
            report.problems.push(VerifyProblem::ChecksumMismatch {
                backup: label.to_owned(),
                path: file.path.clone(),
                expected: expected.to_owned(),
                actual,
            });
        }
    }

    Ok(())
}

/// Core verification pass. The thin [`verify`] entry point prints the
/// report and maps a non-empty problem list to a non-zero exit; tests
/// assert against the [`VerifyReport`] directly.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] if `backup.info` (no `--set`) or a selected
///   backup's `backup.manifest` is absent, or for backend read failures.
/// - [`CommandError::Io`] for stream failures while re-reading files.
/// - [`CommandError::Other`] if `backup.info` / `backup.manifest` is
///   malformed.
pub fn verify_inner(config: &LoadedConfig, repo: &dyn Storage) -> Result<VerifyReport, CommandError> {
    let stanza = require_stanza(config)?;
    let labels = select_backups(config, repo, stanza)?;

    let mut report = VerifyReport {
        backups_checked: 0,
        files_checked: 0,
        problems: Vec::new(),
    };

    for label in &labels {
        verify_backup(repo, stanza, label, &mut report)?;
    }

    Ok(report)
}

/// `verify` — confirm repository integrity.
///
/// Runs [`verify_inner`], prints a one-line summary plus a line per problem,
/// and returns `Ok(())` when the repository is clean. When any problem is
/// found it returns [`CommandError::Other`] so the CLI exit code reflects
/// the corruption — the verification itself still completed.
///
/// # Errors
///
/// Forwards every structural error from [`verify_inner`], and returns
/// [`CommandError::Other`] when one or more integrity problems were found.
#[allow(clippy::print_stdout)]
pub fn verify(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let report = verify_inner(config, repo_storage)?;

    println!(
        "verify: {} backup(s), {} file(s) checked, {} problem(s)",
        report.backups_checked,
        report.files_checked,
        report.problems.len()
    );

    for problem in &report.problems {
        match problem {
            VerifyProblem::MissingFile { backup, path } => {
                println!("  missing: {backup}/{path}");
            }
            VerifyProblem::ChecksumMismatch {
                backup,
                path,
                expected,
                actual,
            } => {
                println!("  checksum mismatch: {backup}/{path} (expected {expected}, got {actual})");
            }
            VerifyProblem::SizeMismatch {
                backup,
                path,
                expected,
                actual,
            } => {
                println!("  size mismatch: {backup}/{path} (expected {expected}, got {actual})");
            }
        }
    }

    if report.problems.is_empty() {
        Ok(())
    } else {
        Err(CommandError::Other(format!(
            "verify found {} problem(s)",
            report.problems.len()
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{DbHistoryEntry, InfoBackup, Manifest, ManifestFile};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{VerifyProblem, verify_inner};
    use crate::CommandError;

    /// SHA-1 of `bytes`, computed exactly the way `verify` recomputes it, so
    /// test fixtures record the digest verify will compare against.
    fn sha1_hex(bytes: &[u8]) -> String {
        let mut f = pgbr_io::Sha1::new();
        let mut sink = Vec::new();
        pgbr_io::Filter::process(&mut f, bytes, &mut sink).unwrap();
        f.digest_hex()
    }

    fn cfg(stanza: Option<&str>, set: Option<&str>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(label) = set {
            options.insert(("set".to_owned(), None), OptionValue::String(label.to_owned()));
        }
        LoadedConfig {
            command: "verify".to_owned(),
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

    /// Seed `backup/<stanza>/backup.info` listing every `(label, type)`.
    fn seed_backup_info(repo: &Posix, stanza: &str, labels: &[&str]) {
        let mut current = BTreeMap::new();
        for label in labels {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
                    "backup-timestamp-stop": 1_704_110_410_i64,
                    "backup-type": "full",
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

    /// Write a `backup.manifest` for `label` referencing the given files.
    fn seed_manifest(repo: &Posix, stanza: &str, label: &str, files: Vec<ManifestFile>) {
        let manifest = Manifest {
            backup_label: label.to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files,
            paths: Vec::new(),
            links: Vec::new(),
        };
        repo.create_path(Path::new(&format!("backup/{stanza}/{label}")), true)
            .expect("create backup label dir");
        manifest
            .save(repo, &super::manifest_path(stanza, label))
            .expect("save manifest");
    }

    /// Materialise a captured backup file under `backup/<stanza>/<label>/<rel>`.
    fn write_backup_file(repo: &Posix, stanza: &str, label: &str, rel: &str, bytes: &[u8]) {
        // Ensure parent directories exist for nested paths.
        if let Some(parent) = Path::new(&format!("backup/{stanza}/{label}/{rel}")).parent() {
            repo.create_path(parent, true).expect("create parent dir");
        }
        let mut w = repo
            .open_write(&super::backup_file_path(stanza, label, rel))
            .expect("open backup file");
        w.write(bytes).expect("write backup file");
        w.close().expect("close backup file");
    }

    fn file_entry(path: &str, bytes: &[u8], checksum: Option<String>) -> ManifestFile {
        ManifestFile {
            path: path.to_owned(),
            size: bytes.len() as u64,
            timestamp: 1_704_110_400,
            checksum,
            checksum_page: None,
        }
    }

    #[test]
    fn verify_clean_backup_has_no_problems() {
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let a = b"PG_VERSION contents\n";
        let b = b"some heap page bytes \x00\x01\x02";

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![
                file_entry("pg_data/PG_VERSION", a, Some(sha1_hex(a))),
                file_entry("pg_data/base/1/1259", b, Some(sha1_hex(b))),
            ],
        );
        write_backup_file(&repo, "demo", label, "pg_data/PG_VERSION", a);
        write_backup_file(&repo, "demo", label, "pg_data/base/1/1259", b);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert!(report.problems.is_empty(), "clean backup must report no problems: {report:?}");
        assert_eq!(report.files_checked, 2);
        assert_eq!(report.backups_checked, 1);
    }

    #[test]
    fn verify_detects_missing_file() {
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let a = b"present file";
        let b = b"this one is never written to disk";

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![
                file_entry("pg_data/present", a, Some(sha1_hex(a))),
                file_entry("pg_data/absent", b, Some(sha1_hex(b))),
            ],
        );
        write_backup_file(&repo, "demo", label, "pg_data/present", a);
        // "pg_data/absent" intentionally not written.

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.files_checked, 2);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(
            report.problems[0],
            VerifyProblem::MissingFile {
                backup: label.to_owned(),
                path: "pg_data/absent".to_owned(),
            }
        );
    }

    #[test]
    fn verify_detects_checksum_mismatch() {
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let bytes = b"the real file content";
        // Record a checksum that does not match `bytes`, but a size that does
        // so only the checksum problem is reported.
        let wrong = "0000000000000000000000000000000000000000".to_owned();

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![file_entry("pg_data/corrupt", bytes, Some(wrong.clone()))],
        );
        write_backup_file(&repo, "demo", label, "pg_data/corrupt", bytes);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.files_checked, 1);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(
            report.problems[0],
            VerifyProblem::ChecksumMismatch {
                backup: label.to_owned(),
                path: "pg_data/corrupt".to_owned(),
                expected: wrong,
                actual: sha1_hex(bytes),
            }
        );
    }

    #[test]
    fn verify_missing_stanza_errors() {
        let (_dir, repo) = empty_repo();
        let err = verify_inner(&cfg(None, None), &repo).expect_err("verify requires a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn verify_set_selects_single_backup() {
        let (_dir, repo) = empty_repo();
        let first = "20240101-120000F";
        let second = "20240102-120000F";

        seed_backup_info(&repo, "demo", &[first, second]);

        let a = b"first backup file";
        seed_manifest(&repo, "demo", first, vec![file_entry("pg_data/a", a, Some(sha1_hex(a)))]);
        write_backup_file(&repo, "demo", first, "pg_data/a", a);

        let b = b"second backup file";
        seed_manifest(&repo, "demo", second, vec![file_entry("pg_data/b", b, Some(sha1_hex(b)))]);
        write_backup_file(&repo, "demo", second, "pg_data/b", b);

        // --set the first backup: only it should be checked.
        let report = verify_inner(&cfg(Some("demo"), Some(first)), &repo).expect("verify_inner");
        assert_eq!(report.backups_checked, 1);
        assert_eq!(report.files_checked, 1);
        assert!(report.problems.is_empty());
    }
}
