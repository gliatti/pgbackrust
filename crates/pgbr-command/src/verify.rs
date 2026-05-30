//! `verify` command — confirm whole-repository integrity.
//!
//! C reference: `src/command/verify/verify.c` (+ `src/command/verify/file.c`).
//! `verify` walks the repository and reports every integrity problem it finds
//! rather than aborting on the first. The pass has three stages, mirroring the
//! C `verifyProcess`:
//!
//! 1. **Info-file consistency.** Load `backup/<stanza>/backup.info` and
//!    `archive/<stanza>/archive.info` and confirm they describe the same
//!    cluster: the active database identity (`db-id` / `db-system-id` /
//!    `db-version`) and the `[db:history]` lists must agree. C ref:
//!    `verifyPgHistory`. (A missing `archive.info` is tolerated — a repo can
//!    legitimately hold only backups — and recorded as an informational
//!    problem rather than aborting.)
//! 2. **Backup files.** For every backup in `[backup:current]` (or just the
//!    `--set` backup), load its `backup.manifest` and re-read every
//!    checksummed file, recomputing its SHA-1 and comparing to the recorded
//!    value. A file whose manifest entry carries a `reference` is read from the
//!    backup that physically holds its bytes
//!    (`backup/<stanza>/<reference>/<path>`), exactly as restore resolves
//!    differential / incremental references. Missing files and size mismatches
//!    are detected too. C ref: `verifyFile`.
//! 3. **WAL archive.** Walk `archive/<stanza>/` and verify every WAL segment.
//!    The C implementation lays archives out as
//!    `archive/<archive-id>/<wal-path>/<segment>-<sha1>` and verifies the
//!    SHA-1 encoded in the filename; this fork currently writes a **flat**
//!    `archive/<stanza>/<segment>` layout with no checksum in the name (see
//!    `archive.rs`). So when a segment filename carries a `-<40-hex>` suffix
//!    its embedded checksum is verified; otherwise the segment is verified for
//!    presence + readability and the missing-checksum gap is recorded as a
//!    note on the result.
//!
//! Corruption is **collected, not thrown**: a verify run that finds damage
//! still completes and reports every problem it found. [`verify_inner`] always
//! returns a [`VerifyReport`]; only structural failures — an absent
//! `--stanza`, an unreadable / malformed `backup.info`, or an unreadable
//! `backup.manifest` — bubble up as a [`CommandError`].

use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoArchive, InfoBackup, InfoError, Manifest};
use pgbr_io::{Filter, IoRead, Sha1};
use pgbr_storage::{Storage, StorageError, StorageKind};

use crate::CommandError;

/// Length of a SHA-1 digest rendered as lowercase hexadecimal.
const SHA1_HEX_LEN: usize = 40;

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

impl VerifyProblem {
    /// Backup label this problem is attributed to.
    #[must_use]
    pub fn backup(&self) -> &str {
        match self {
            Self::MissingFile { backup, .. } | Self::ChecksumMismatch { backup, .. } | Self::SizeMismatch { backup, .. } => backup,
        }
    }

    /// Manifest-relative path this problem is attributed to.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::MissingFile { path, .. } | Self::ChecksumMismatch { path, .. } | Self::SizeMismatch { path, .. } => path,
        }
    }
}

/// Per-backup verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerify {
    /// Backup label, e.g. `"20240101-120000F"`.
    pub label: String,
    /// Total number of checksummed files inspected in this backup.
    pub total: usize,
    /// Number of files that re-read clean (correct size + checksum).
    pub valid: usize,
    /// Human-readable problem descriptions for this backup, in discovery order.
    pub errors: Vec<String>,
}

/// A single archive (WAL) segment problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveProblem {
    /// A segment whose filename embeds a SHA-1 (`<segment>-<sha1>`) failed its
    /// checksum check.
    ChecksumMismatch {
        /// Segment filename, relative to `archive/<stanza>/`.
        segment: String,
        /// Checksum encoded in the filename.
        expected: String,
        /// Checksum recomputed from the segment's bytes.
        actual: String,
    },
    /// A segment that was listed but could not be read back.
    Unreadable {
        /// Segment filename, relative to `archive/<stanza>/`.
        segment: String,
        /// Backend error message.
        message: String,
    },
}

/// WAL-archive verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveVerify {
    /// Total number of WAL segments found under `archive/<stanza>/`.
    pub total: usize,
    /// Number of segments verified clean.
    pub valid: usize,
    /// Number of segments whose checksum could be verified from the filename.
    pub checksum_verified: usize,
    /// Number of segments present + readable but with no embedded checksum to
    /// verify (the flat-layout gap; see the module docs).
    pub presence_only: usize,
    /// Problems found while verifying segments, in discovery order.
    pub problems: Vec<ArchiveProblem>,
}

/// Result of a [`verify_inner`] pass — the whole-repository report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of backups whose manifests were inspected.
    pub backups_checked: usize,
    /// Number of checksummed files that were re-read and compared (across all
    /// backups).
    pub files_checked: usize,
    /// Every backup-file integrity problem found, in the order discovered.
    pub problems: Vec<VerifyProblem>,
    /// Per-backup structured results.
    pub backups: Vec<BackupVerify>,
    /// WAL-archive verification result.
    pub archive: ArchiveVerify,
    /// Repository-level consistency notes (info-file disagreements, a missing
    /// `archive.info`, etc.). Non-fatal: recorded, not thrown.
    pub info_problems: Vec<String>,
}

impl VerifyReport {
    /// Total problem count across info, backup-file, and archive stages.
    #[must_use]
    pub const fn total_problems(&self) -> usize {
        self.info_problems.len() + self.problems.len() + self.archive.problems.len()
    }
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

fn archive_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/archive.info"))
}

fn manifest_path(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/backup.manifest"))
}

fn backup_file_path(stanza: &str, label: &str, file: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/{file}"))
}

fn archive_dir(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}"))
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
fn select_backups(config: &LoadedConfig, info: &InfoBackup) -> Vec<String> {
    if let Some(label) = requested_set(config) {
        return vec![label.to_owned()];
    }
    info.current.keys().cloned().collect()
}

/// Load `backup.info`, mapping a missing file / parse failure to a structural
/// [`CommandError`] (verify cannot proceed without it).
fn load_backup_info(repo: &dyn Storage, stanza: &str) -> Result<InfoBackup, CommandError> {
    InfoBackup::load(repo, &backup_info_path(stanza)).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: backup_info_path(stanza),
        }),
        other => CommandError::Other(other.to_string()),
    })
}

/// Verify the cross-file consistency of `backup.info` and `archive.info`, the
/// way C's `verifyPgHistory` does. A missing `archive.info` is tolerated (it is
/// recorded as a note, not a hard error, since a repository can legitimately
/// hold only backups); a malformed one is recorded too. Any disagreement on the
/// active database identity or the history lists is appended to `notes`.
fn verify_info_consistency(repo: &dyn Storage, stanza: &str, backup: &InfoBackup, notes: &mut Vec<String>) {
    let archive = match InfoArchive::load(repo, &archive_info_path(stanza)) {
        Ok(archive) => archive,
        Err(InfoError::Storage(StorageError::NotFound { .. })) => {
            notes.push("archive.info is missing; skipping archive/backup history consistency check".to_owned());
            return;
        }
        Err(err) => {
            notes.push(format!("archive.info is unusable: {err}"));
            return;
        }
    };

    // Active database identity must match between the two files (verify treats
    // the database as inaccessible, so it cannot tell which would be right).
    if archive.db_id != backup.db_id || archive.db_system_id != backup.db_system_id || archive.db_version != backup.db_version {
        notes.push(format!(
            "backup info db mismatch: backup.info db-id={} system-id={} version={} but \
             archive.info db-id={} system-id={} version={}",
            backup.db_id, backup.db_system_id, backup.db_version, archive.db_id, archive.db_system_id, archive.db_version,
        ));
    }

    // The full history lists must match (same db-ids → same {system-id, version}).
    if archive.history != backup.history {
        notes.push("archive and backup history lists do not match".to_owned());
    }
}

/// Recompute the SHA-1 of a repository file by streaming it through the
/// [`Sha1`] filter. Returns `(digest_hex, byte_count)`.
fn hash_repo_file(repo: &dyn Storage, path: &Path) -> Result<(String, u64), CommandError> {
    let mut reader: Box<dyn IoRead> = repo.open_read(path)?;
    let bytes = reader.read_all()?;
    Ok((sha1_hex(&bytes), bytes.len() as u64))
}

/// SHA-1 of `bytes` as lowercase hex, computed exactly the way verify compares.
fn sha1_hex(bytes: &[u8]) -> String {
    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    // Sha1::process never fails for a plain byte slice; map the (impossible)
    // error to an empty digest so this helper stays infallible for callers.
    if sha.process(bytes, &mut sink).is_err() {
        return String::new();
    }
    sha.digest_hex()
}

/// Verify a single backup's manifest, appending any problems found to `report`,
/// counting every checksummed file inspected, and building the per-backup
/// [`BackupVerify`] summary.
///
/// A file whose manifest entry carries a `reference` is read from the backup
/// that physically holds its bytes (`backup/<stanza>/<reference>/<path>`),
/// mirroring restore's differential / incremental reference resolution.
fn verify_backup(repo: &dyn Storage, stanza: &str, label: &str, report: &mut VerifyReport) -> Result<(), CommandError> {
    let manifest = Manifest::load(repo, &manifest_path(stanza, label)).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: manifest_path(stanza, label),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    report.backups_checked += 1;

    let mut summary = BackupVerify {
        label: label.to_owned(),
        total: 0,
        valid: 0,
        errors: Vec::new(),
    };

    for file in &manifest.files {
        // Zero-length files carry no checksum; nothing to re-read.
        let Some(expected) = file.checksum.as_deref() else {
            continue;
        };

        report.files_checked += 1;
        summary.total += 1;

        // A referenced file's bytes live in the backup named by `reference`;
        // otherwise they live in this backup's own directory.
        let holder = file.reference.as_deref().unwrap_or(label);
        let path = backup_file_path(stanza, holder, &file.path);

        if !repo.exists(&path)? {
            let problem = VerifyProblem::MissingFile {
                backup: label.to_owned(),
                path: file.path.clone(),
            };
            summary.errors.push(describe_problem(&problem));
            report.problems.push(problem);
            continue;
        }

        let (actual, actual_size) = hash_repo_file(repo, &path)?;

        let mut file_ok = true;

        if actual_size != file.size {
            file_ok = false;
            let problem = VerifyProblem::SizeMismatch {
                backup: label.to_owned(),
                path: file.path.clone(),
                expected: file.size,
                actual: actual_size,
            };
            summary.errors.push(describe_problem(&problem));
            report.problems.push(problem);
        }

        if actual != expected {
            file_ok = false;
            let problem = VerifyProblem::ChecksumMismatch {
                backup: label.to_owned(),
                path: file.path.clone(),
                expected: expected.to_owned(),
                actual,
            };
            summary.errors.push(describe_problem(&problem));
            report.problems.push(problem);
        }

        if file_ok {
            summary.valid += 1;
        }
    }

    report.backups.push(summary);
    Ok(())
}

/// Render a [`VerifyProblem`] as a one-line, user-facing string (also used to
/// populate the per-backup `errors` list).
fn describe_problem(problem: &VerifyProblem) -> String {
    match problem {
        VerifyProblem::MissingFile { backup, path } => format!("missing: {backup}/{path}"),
        VerifyProblem::ChecksumMismatch {
            backup,
            path,
            expected,
            actual,
        } => format!("checksum mismatch: {backup}/{path} (expected {expected}, got {actual})"),
        VerifyProblem::SizeMismatch {
            backup,
            path,
            expected,
            actual,
        } => format!("size mismatch: {backup}/{path} (expected {expected}, got {actual})"),
    }
}

/// If `segment` carries a trailing `-<40-hex>` SHA-1 (the C archive layout),
/// split it into `(base_segment, checksum)`. Returns `None` for the flat-layout
/// names this fork writes, which have no embedded checksum.
fn split_segment_checksum(segment: &str) -> Option<(&str, &str)> {
    // Strip any compression suffix before inspecting (e.g. `...-<sha1>.gz`).
    let core = segment.split('.').next().unwrap_or(segment);
    let (base, candidate) = core.rsplit_once('-')?;
    if candidate.len() == SHA1_HEX_LEN && candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some((base, candidate))
    } else {
        None
    }
}

/// Verify the WAL archive under `archive/<stanza>/`. Each regular file is a WAL
/// segment: if its filename embeds a SHA-1 the checksum is verified, otherwise
/// the segment is verified for presence + readability. `archive.info` and any
/// directory entries are skipped. A missing archive directory yields an empty
/// (all-zero) result — nothing to verify is not a problem.
fn verify_archive(repo: &dyn Storage, stanza: &str) -> Result<ArchiveVerify, CommandError> {
    let mut result = ArchiveVerify {
        total: 0,
        valid: 0,
        checksum_verified: 0,
        presence_only: 0,
        problems: Vec::new(),
    };

    let dir = archive_dir(stanza);
    let entries = match repo.list(&dir) {
        Ok(entries) => entries,
        Err(StorageError::NotFound { .. }) => return Ok(result),
        Err(err) => return Err(CommandError::Storage(err)),
    };

    for entry in entries {
        if entry.kind != StorageKind::File {
            continue;
        }

        let name = entry
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .map_or_else(|| entry.path.display().to_string(), str::to_owned);

        // `archive.info` / `archive.info.copy` are metadata, not WAL segments.
        if name.starts_with("archive.info") {
            continue;
        }

        result.total += 1;

        // Read the segment back (so an unreadable file is caught either way).
        let bytes = match repo.open_read(&entry.path).and_then(|mut r| Ok(r.read_all()?)) {
            Ok(bytes) => bytes,
            Err(err) => {
                result.problems.push(ArchiveProblem::Unreadable {
                    segment: name.clone(),
                    message: err.to_string(),
                });
                continue;
            }
        };

        // Own the embedded checksum (if any) so `name` is free to move into a
        // problem below without an outstanding borrow into it.
        let embedded = split_segment_checksum(&name).map(|(_, sha)| sha.to_owned());
        if let Some(expected) = embedded {
            let actual = sha1_hex(&bytes);
            if actual == expected {
                result.valid += 1;
                result.checksum_verified += 1;
            } else {
                result.problems.push(ArchiveProblem::ChecksumMismatch {
                    segment: name,
                    expected,
                    actual,
                });
            }
        } else {
            // Flat layout: present + readable is the best we can assert.
            result.valid += 1;
            result.presence_only += 1;
        }
    }

    Ok(result)
}

/// Core verification pass over the whole repository.
///
/// The thin [`verify`] entry point prints the report and maps a non-empty
/// problem list to a non-zero exit; tests assert against the [`VerifyReport`]
/// directly.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] if `backup.info` or a selected backup's
///   `backup.manifest` is absent, or for backend read failures.
/// - [`CommandError::Io`] for stream failures while re-reading files.
/// - [`CommandError::Other`] if `backup.info` / `backup.manifest` is malformed.
pub fn verify_inner(config: &LoadedConfig, repo: &dyn Storage) -> Result<VerifyReport, CommandError> {
    let stanza = require_stanza(config)?;

    let mut report = VerifyReport {
        backups_checked: 0,
        files_checked: 0,
        problems: Vec::new(),
        backups: Vec::new(),
        archive: ArchiveVerify {
            total: 0,
            valid: 0,
            checksum_verified: 0,
            presence_only: 0,
            problems: Vec::new(),
        },
        info_problems: Vec::new(),
    };

    // Stage 1: info-file consistency.
    let info = load_backup_info(repo, stanza)?;
    verify_info_consistency(repo, stanza, &info, &mut report.info_problems);

    // Stage 2: per-backup files (with reference resolution).
    let labels = select_backups(config, &info);
    for label in &labels {
        verify_backup(repo, stanza, label, &mut report)?;
    }

    // Stage 3: WAL archive.
    report.archive = verify_archive(repo, stanza)?;

    Ok(report)
}

/// `verify` — confirm whole-repository integrity.
///
/// Runs [`verify_inner`], prints a structured summary plus a line per problem,
/// and returns `Ok(())` when the repository is clean. When any problem is found
/// it returns [`CommandError::Other`] so the CLI exit code reflects the
/// corruption — the verification itself still completed (C ref: `cmdVerify`
/// throws `RuntimeError` only after rendering the full report).
///
/// # Errors
///
/// Forwards every structural error from [`verify_inner`], and returns
/// [`CommandError::Other`] when one or more integrity problems were found.
#[allow(clippy::print_stdout)]
pub fn verify(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let report = verify_inner(config, repo_storage)?;

    println!(
        "verify: {} backup(s), {} file(s) checked, {} WAL segment(s), {} problem(s)",
        report.backups_checked,
        report.files_checked,
        report.archive.total,
        report.total_problems(),
    );

    for note in &report.info_problems {
        println!("  info: {note}");
    }

    for backup in &report.backups {
        println!("  backup {}: {}/{} file(s) valid", backup.label, backup.valid, backup.total);
        for err in &backup.errors {
            println!("    {err}");
        }
    }

    println!(
        "  archive: {}/{} segment(s) valid ({} checksum-verified, {} presence-only)",
        report.archive.valid, report.archive.total, report.archive.checksum_verified, report.archive.presence_only,
    );
    for problem in &report.archive.problems {
        match problem {
            ArchiveProblem::ChecksumMismatch {
                segment,
                expected,
                actual,
            } => println!("    checksum mismatch: {segment} (expected {expected}, got {actual})"),
            ArchiveProblem::Unreadable { segment, message } => {
                println!("    unreadable: {segment} ({message})");
            }
        }
    }

    let total = report.total_problems();
    if total == 0 {
        Ok(())
    } else {
        Err(CommandError::Other(format!(
            "{total} fatal error(s) encountered, see output for details"
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup, Manifest, ManifestFile};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{ArchiveProblem, VerifyProblem, split_segment_checksum, verify_inner};
    use crate::CommandError;

    /// SHA-1 of `bytes`, computed exactly the way `verify` recomputes it, so
    /// test fixtures record the digest verify will compare against.
    fn sha1_hex(bytes: &[u8]) -> String {
        super::sha1_hex(bytes)
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

    /// Seed an `archive/<stanza>/archive.info` matching `seed_backup_info`'s
    /// cluster identity / history so the consistency check passes.
    fn seed_archive_info(repo: &Posix, stanza: &str) {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        let archive = InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            history,
        };
        repo.create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive/<stanza>");
        archive
            .save(repo, &super::archive_info_path(stanza))
            .expect("save archive.info");
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
            option_checksum_page: None,
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

    /// Write a WAL segment under `archive/<stanza>/<segment>`.
    fn write_archive_segment(repo: &Posix, stanza: &str, segment: &str, bytes: &[u8]) {
        repo.create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive dir");
        let mut w = repo
            .open_write(Path::new(&format!("archive/{stanza}/{segment}")))
            .expect("open segment");
        w.write(bytes).expect("write segment");
        w.close().expect("close segment");
    }

    fn file_entry(path: &str, bytes: &[u8], checksum: Option<String>) -> ManifestFile {
        ManifestFile {
            path: path.to_owned(),
            size: bytes.len() as u64,
            timestamp: 1_704_110_400,
            checksum,
            checksum_page: None,
            reference: None,
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        }
    }

    /// Like [`file_entry`] but the bytes physically live in `reference`.
    fn referenced_entry(path: &str, bytes: &[u8], reference: &str) -> ManifestFile {
        ManifestFile {
            path: path.to_owned(),
            size: bytes.len() as u64,
            timestamp: 1_704_110_400,
            checksum: Some(sha1_hex(bytes)),
            checksum_page: None,
            reference: Some(reference.to_owned()),
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
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
        assert_eq!(report.backups.len(), 1);
        assert_eq!(report.backups[0].valid, 2);
        assert_eq!(report.backups[0].total, 2);
        assert!(report.backups[0].errors.is_empty());
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
        // The per-backup summary names the offending file.
        assert_eq!(report.backups[0].valid, 1);
        assert_eq!(report.backups[0].total, 2);
        assert!(
            report.backups[0].errors.iter().any(|e| e.contains("pg_data/absent")),
            "backup errors must name the missing file: {:?}",
            report.backups[0].errors
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

    #[test]
    fn verify_multi_backup_with_references_all_valid() {
        // A full backup holds two files; a differential references one of the
        // full's files (its bytes physically live in the full) and adds a
        // changed file of its own. Every checksum is valid → zero problems.
        let (_dir, repo) = empty_repo();
        let full = "20240101-120000F";
        let diff = "20240101-120000F_20240102-120000D";

        seed_backup_info(&repo, "demo", &[full, diff]);
        seed_archive_info(&repo, "demo");

        let unchanged = b"unchanged heap page";
        let changed_old = b"original";
        let changed_new = b"modified in diff";

        // Full backup: both files physically present.
        seed_manifest(
            &repo,
            "demo",
            full,
            vec![
                file_entry("base/1/unchanged", unchanged, Some(sha1_hex(unchanged))),
                file_entry("base/1/changed", changed_old, Some(sha1_hex(changed_old))),
            ],
        );
        write_backup_file(&repo, "demo", full, "base/1/unchanged", unchanged);
        write_backup_file(&repo, "demo", full, "base/1/changed", changed_old);

        // Diff: references the unchanged file from the full, holds the changed one.
        seed_manifest(
            &repo,
            "demo",
            diff,
            vec![
                referenced_entry("base/1/unchanged", unchanged, full),
                file_entry("base/1/changed", changed_new, Some(sha1_hex(changed_new))),
            ],
        );
        write_backup_file(&repo, "demo", diff, "base/1/changed", changed_new);
        // The referenced file is NOT written into the diff dir; verify must
        // resolve it to the full.

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.backups_checked, 2);
        assert_eq!(report.files_checked, 4, "2 full + 2 diff (referenced counts)");
        assert!(
            report.problems.is_empty(),
            "all checksums valid → no problems: {:?}",
            report.problems
        );
        assert!(
            report.info_problems.is_empty(),
            "info files agree: {:?}",
            report.info_problems
        );
        for b in &report.backups {
            assert_eq!(b.valid, b.total, "backup {} should be fully valid", b.label);
        }
    }

    #[test]
    fn verify_detects_corrupt_file_in_repo() {
        // Two backups; corrupt one file's bytes in the *second* backup. The
        // first backup stays clean; only the second's error list names the file.
        let (_dir, repo) = empty_repo();
        let first = "20240101-120000F";
        let second = "20240102-120000F";

        seed_backup_info(&repo, "demo", &[first, second]);

        let clean = b"clean bytes";
        seed_manifest(
            &repo,
            "demo",
            first,
            vec![file_entry("base/clean", clean, Some(sha1_hex(clean)))],
        );
        write_backup_file(&repo, "demo", first, "base/clean", clean);

        let intended = b"the intended content";
        seed_manifest(
            &repo,
            "demo",
            second,
            vec![file_entry("base/corrupt", intended, Some(sha1_hex(intended)))],
        );
        // Write *different* bytes (but the SAME length, so only the checksum
        // mismatch fires, not a size mismatch) than the manifest records.
        let tampered = b"TAMPERED on-disk!!!!";
        assert_eq!(tampered.len(), intended.len(), "tampered bytes must match the intended size");
        write_backup_file(&repo, "demo", second, "base/corrupt", tampered);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.problems.len(), 1);
        match &report.problems[0] {
            VerifyProblem::ChecksumMismatch { backup, path, .. } => {
                assert_eq!(backup, second);
                assert_eq!(path, "base/corrupt");
            }
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
        // First backup clean, second backup names the file.
        let first_summary = report.backups.iter().find(|b| b.label == first).unwrap();
        assert!(first_summary.errors.is_empty());
        let second_summary = report.backups.iter().find(|b| b.label == second).unwrap();
        assert_eq!(second_summary.valid, 0);
        assert!(
            second_summary.errors.iter().any(|e| e.contains("base/corrupt")),
            "second backup errors must name the corrupt file: {:?}",
            second_summary.errors
        );
    }

    #[test]
    fn verify_detects_missing_referenced_file() {
        // A diff references a file from the full, but the full never physically
        // stored it (and the diff doesn't either). Verify must report it missing,
        // attributed to the diff that referenced it.
        let (_dir, repo) = empty_repo();
        let full = "20240101-120000F";
        let diff = "20240101-120000F_20240102-120000D";

        seed_backup_info(&repo, "demo", &[full, diff]);

        // Full: empty (no files written, manifest lists none).
        seed_manifest(&repo, "demo", full, Vec::new());

        // Diff references base/1/gone from the full, but it isn't there.
        let gone = b"bytes that were supposed to be in the full";
        seed_manifest(&repo, "demo", diff, vec![referenced_entry("base/1/gone", gone, full)]);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.problems.len(), 1);
        assert_eq!(
            report.problems[0],
            VerifyProblem::MissingFile {
                backup: diff.to_owned(),
                path: "base/1/gone".to_owned(),
            }
        );
    }

    #[test]
    fn verify_info_mismatch_recorded_not_thrown() {
        // archive.info disagrees with backup.info on the system id → recorded as
        // an info problem, but verify still completes and returns a report.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";
        seed_backup_info(&repo, "demo", &[label]);

        // Write a divergent archive.info.
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 1234,
                db_version: "14".to_owned(),
            },
        );
        let archive = InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 1234, // != backup.info's 6_873_049_345_984_568_091
            db_version: "14".to_owned(),
            history,
        };
        repo.create_path(Path::new("archive/demo"), true).unwrap();
        archive.save(&repo, &super::archive_info_path("demo")).unwrap();

        let a = b"x";
        seed_manifest(&repo, "demo", label, vec![file_entry("base/a", a, Some(sha1_hex(a)))]);
        write_backup_file(&repo, "demo", label, "base/a", a);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner completes");
        assert!(
            report.info_problems.iter().any(|n| n.contains("db mismatch")),
            "expected a db-mismatch note: {:?}",
            report.info_problems
        );
        assert!(report.total_problems() >= 1);
    }

    #[test]
    fn verify_archive_presence_only_for_flat_layout() {
        // Flat-layout segments (no checksum in the name) are verified for
        // presence + readability and counted presence-only.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";
        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(&repo, "demo", label, Vec::new());

        write_archive_segment(&repo, "demo", "000000010000000000000001", b"wal one");
        write_archive_segment(&repo, "demo", "000000010000000000000002", b"wal two");

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.archive.total, 2);
        assert_eq!(report.archive.valid, 2);
        assert_eq!(report.archive.presence_only, 2);
        assert_eq!(report.archive.checksum_verified, 0);
        assert!(report.archive.problems.is_empty());
    }

    #[test]
    fn verify_archive_checksum_segments_valid_and_tampered() {
        // C-style segment names embed the SHA-1 (`<segment>-<sha1>`). A valid
        // one verifies; a tampered one (bytes changed after the name was fixed)
        // reports a checksum mismatch.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";
        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(&repo, "demo", label, Vec::new());

        let good = b"valid wal segment bytes";
        let good_name = format!("000000010000000000000003-{}", sha1_hex(good));
        write_archive_segment(&repo, "demo", &good_name, good);

        // Name records the checksum of `intended`, but we write tampered bytes.
        let intended = b"intended wal bytes";
        let bad_name = format!("000000010000000000000004-{}", sha1_hex(intended));
        write_archive_segment(&repo, "demo", &bad_name, b"tampered wal bytes!!");

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.archive.total, 2);
        assert_eq!(report.archive.valid, 1);
        assert_eq!(report.archive.checksum_verified, 1);
        assert_eq!(report.archive.problems.len(), 1);
        match &report.archive.problems[0] {
            ArchiveProblem::ChecksumMismatch {
                segment,
                expected,
                actual,
            } => {
                assert_eq!(segment, &bad_name);
                assert_eq!(expected, &sha1_hex(intended));
                assert_eq!(actual, &sha1_hex(b"tampered wal bytes!!"));
            }
            other @ ArchiveProblem::Unreadable { .. } => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn split_segment_checksum_recognizes_layouts() {
        // Flat layout: no embedded checksum.
        assert!(split_segment_checksum("000000010000000000000001").is_none());
        // C layout: 24-char segment + '-' + 40-hex sha1.
        let name = "000000010000000000000001-1234567890abcdef1234567890abcdef12345678";
        assert_eq!(
            split_segment_checksum(name),
            Some(("000000010000000000000001", "1234567890abcdef1234567890abcdef12345678"))
        );
        // C layout with a compression suffix.
        let gz = "000000010000000000000001-1234567890abcdef1234567890abcdef12345678.gz";
        assert_eq!(
            split_segment_checksum(gz),
            Some(("000000010000000000000001", "1234567890abcdef1234567890abcdef12345678"))
        );
        // Trailing token that is not 40 hex chars is not a checksum.
        assert!(split_segment_checksum("000000010000000000000001-notachecksum").is_none());
    }
}
