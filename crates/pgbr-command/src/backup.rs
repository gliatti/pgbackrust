//! `backup` command — full backup, with optional compression + encryption.
//!
//! C reference: `src/command/backup/backup.c`.
//!
//! This slice implements the **full** backup path: every non-excluded file in
//! the PG data directory is read, its **plaintext** SHA-1 + size are computed
//! (pgBackRest records the uncompressed checksum), the plaintext is run through
//! the [`RepoTransform`] forward chain (compress then encrypt), and the
//! transformed bytes are written to `backup/<stanza>/<label>/<relpath><suffix>`
//! in the repository — where `<suffix>` is the compression extension
//! (`.gz` / `.zst` / …, empty for no compression). A [`pgbr_info::Manifest`]
//! inventories the result and a `[backup:current]` entry — carrying the applied
//! compress-type / encrypted flag so restore can reverse the transform — is
//! appended to `backup.info`.
//!
//! With `compress-type=none` and no cipher the transform is the identity and
//! files are copied verbatim with an empty suffix, exactly as before.
//!
//! Deliberately out of scope for this slice (follow-ups):
//!
//! - **Incremental / differential backups.** Only `full` is produced; there is
//!   no prior-backup reference or delta computation.
//! - **Symlink target resolution.** The `Storage` trait has no link-target
//!   accessor yet, so [`ManifestLink`] entries are recorded with an empty
//!   `destination`. See the `// TODO: resolve link target` note in [`walk`].
//!
//! The real work lives in [`backup_inner`], which takes the backup label and
//! start timestamp as parameters so tests can pin them; the public [`backup`]
//! entry point derives both from [`SystemTime::now`].

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pgbr_config::LoadedConfig;
use pgbr_info::{InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath};
use pgbr_io::{Filter, Sha1};
use pgbr_storage::{Storage, StorageInfo, StorageKind};
use serde_json::json;

use crate::CommandError;
use crate::pipeline::{RepoTransform, metadata_compress_type_key, metadata_encrypted_key};

/// Backup type recorded for a full backup.
const BACKUP_TYPE_FULL: &str = "full";

/// Path prefixes (PG-data-relative, `/`-separated) excluded from a backup.
///
/// `pg_wal` is archived separately; the remaining directories hold transient
/// runtime state that must not be captured. `postmaster.pid` / `postmaster.opts`
/// are matched as exact paths but live in the same list for simplicity — a
/// trailing-`/`-free entry matches either the file itself or a directory
/// prefix. Mirrors the standard pgBackRest exclusion set (minimal subset).
const EXCLUDE_PREFIXES: &[&str] = &[
    "postmaster.pid",
    "postmaster.opts",
    "pg_wal",
    "pg_replslot",
    "pg_dynshmem",
    "pg_notify",
    "pg_serial",
    "pg_snapshots",
    "pg_stat_tmp",
    "pg_subtrans",
];

/// Result of a successful [`backup_inner`], surfaced for tests / callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    /// Label assigned to the backup, e.g. `"20240101-120000F"`.
    pub label: String,
    /// Number of files copied into the backup.
    pub file_count: usize,
    /// Total size, in bytes, of the copied files.
    pub total_size: u64,
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// Whether a PG-data-relative path is excluded from the backup.
///
/// A path is excluded when it equals an entry in [`EXCLUDE_PREFIXES`] or sits
/// underneath one (i.e. the entry is a path component prefix). Comparison is on
/// `/`-separated components so `pg_walk` is *not* excluded by `pg_wal`.
fn is_excluded(rel: &str) -> bool {
    EXCLUDE_PREFIXES
        .iter()
        .any(|prefix| rel == *prefix || rel.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/')))
}

/// One entry discovered by [`walk`]: its PG-data-relative path plus the
/// `StorageInfo` the backend reported for it.
struct WalkEntry {
    /// PG-data-relative, `/`-separated path (e.g. `"base/1/1259"`).
    rel: String,
    info: StorageInfo,
}

/// Recursively enumerate every entry under `dir` (a storage-relative path),
/// descending into directories. Entries are returned depth-first in the sorted
/// order [`Storage::list`] yields.
///
/// The backend's `StorageInfo::path` is rooted at the backend root (absolute
/// for `Posix`), so the relative path is reconstructed here by joining the
/// directory we are listing with each entry's file name.
fn walk(storage: &dyn Storage, dir: &Path) -> Result<Vec<WalkEntry>, CommandError> {
    let mut out = Vec::new();
    walk_into(storage, dir, "", &mut out)?;
    Ok(out)
}

/// Inner recursion for [`walk`]. `rel_prefix` is the `/`-separated relative
/// path of `dir` (empty for the root).
fn walk_into(storage: &dyn Storage, dir: &Path, rel_prefix: &str, out: &mut Vec<WalkEntry>) -> Result<(), CommandError> {
    for info in storage.list(dir)? {
        let name = match info.path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_owned(),
            // Skip non-UTF-8 names: the manifest format keys on UTF-8 paths.
            None => continue,
        };
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };

        match info.kind {
            StorageKind::Path => {
                let child_dir = if rel_prefix.is_empty() {
                    PathBuf::from(&name)
                } else {
                    dir.join(&name)
                };
                out.push(WalkEntry { rel: rel.clone(), info });
                walk_into(storage, &child_dir, &rel, out)?;
            }
            _ => out.push(WalkEntry { rel, info }),
        }
    }
    Ok(())
}

/// `backup` — take a full backup of the active stanza (raw copy).
///
/// Computes the backup label (`YYYYMMDD-HHMMSSF`) and start timestamp from
/// [`SystemTime::now`], then delegates to [`backup_inner`].
///
/// # Errors
///
/// See [`backup_inner`].
#[allow(clippy::print_stdout)]
pub fn backup(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let timestamp_start = i64::try_from(secs).unwrap_or(i64::MAX);
    let label = full_backup_label(timestamp_start);
    let transform = RepoTransform::from_options(config);

    let outcome = backup_inner(stanza, repo_storage, pg_storage, &label, timestamp_start, &transform)?;
    println!(
        "backup {} complete: {} file(s), {} byte(s)",
        outcome.label, outcome.file_count, outcome.total_size
    );
    Ok(())
}

/// Format a full-backup label `YYYYMMDD-HHMMSSF` from a Unix timestamp.
///
/// Uses a self-contained civil-date conversion (no `chrono` / `time`
/// dependency). The trailing `F` marks a full backup.
fn full_backup_label(timestamp: i64) -> String {
    let (year, month, day, hour, minute, second) = unix_to_civil(timestamp);
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}F")
}

/// Convert a Unix timestamp (seconds, UTC) to `(year, month, day, hour, minute,
/// second)`. Algorithm from Howard Hinnant's `days_from_civil` inverse. All
/// intermediates stay non-negative `i64`, so the final `u32` narrowings are
/// lossless (each result is bounded well within `u32`).
fn unix_to_civil(timestamp: i64) -> (i64, u32, u32, u32, u32, u32) {
    let secs = timestamp.rem_euclid(86_400);
    let days = timestamp.div_euclid(86_400);

    let hour = secs / 3600;
    let minute = (secs % 3600) / 60;
    let second = secs % 60;

    // Shift epoch to 0000-03-01 to make leap handling uniform.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    (
        year,
        u32::try_from(month).unwrap_or(0),
        u32::try_from(day).unwrap_or(0),
        u32::try_from(hour).unwrap_or(0),
        u32::try_from(minute).unwrap_or(0),
        u32::try_from(second).unwrap_or(0),
    )
}

/// Take a full backup with a caller-supplied `label`, `timestamp_start`, and
/// repo `transform` (compression + encryption).
///
/// Steps:
///
/// 1. Load `backup/<stanza>/backup.info` (error if the stanza is uninitialised).
/// 2. Recursively walk the PG data dir via `pg_storage`, applying
///    [`EXCLUDE_PREFIXES`].
/// 3. For each non-excluded file: compute the **plaintext** SHA-1 + size
///    (recorded in the [`Manifest`]), run the plaintext through
///    `transform.forward_chain()` (compress then encrypt), and write the
///    transformed bytes to `backup/<stanza>/<label>/<relpath><suffix>`.
/// 4. Record directories as [`ManifestPath`] and symlinks as [`ManifestLink`]
///    (with an empty destination — see module docs).
/// 5. Save `backup.manifest`, then add a `[backup:current]` entry to
///    `backup.info` — including the applied compress-type and encrypted flag —
///    and save it.
///
/// # Errors
///
/// - [`CommandError::Other`] if the stanza is not initialised, or if
///   `backup.info` / `backup.manifest` cannot be read or written.
/// - [`CommandError::Io`] if a filter in the transform chain fails.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for repository / PG-data
///   read/write failures.
pub fn backup_inner(
    stanza: &str,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    label: &str,
    timestamp_start: i64,
    transform: &RepoTransform,
) -> Result<BackupOutcome, CommandError> {
    let info_path = backup_info_path(stanza);
    if !repo_storage.exists(&info_path)? {
        return Err(CommandError::Other(
            "stanza not initialized; run stanza-create first".to_owned(),
        ));
    }

    let mut info = InfoBackup::load(repo_storage, &info_path).map_err(|err| CommandError::Other(err.to_string()))?;

    let backup_root = format!("backup/{stanza}/{label}");

    let mut files = Vec::new();
    let mut paths = Vec::new();
    let mut links = Vec::new();
    let mut total_size: u64 = 0;
    let mut repo_size: u64 = 0;

    for entry in walk(pg_storage, Path::new("."))? {
        if is_excluded(&entry.rel) {
            continue;
        }

        match entry.info.kind {
            StorageKind::File => {
                let src = PathBuf::from(&entry.rel);
                let mut reader = pg_storage.open_read(&src)?;
                let bytes = reader.read_all()?;

                // Checksum and size are taken over the PLAINTEXT, independent
                // of how the bytes are stored in the repo (pgBackRest semantics).
                let mut sha1 = Sha1::new();
                let mut sink = Vec::new();
                sha1.process(&bytes, &mut sink)?;
                let checksum = sha1.digest_hex();

                // Compress-then-encrypt the plaintext into the repo bytes. With
                // the identity transform this returns the bytes unchanged.
                let repo_bytes = transform.apply_forward(&bytes)?;

                // The repo filename carries the compression suffix; encryption
                // does not change it.
                let dest = PathBuf::from(format!("{backup_root}/{}{}", entry.rel, transform.repo_suffix()));
                if let Some(parent) = dest.parent() {
                    repo_storage.create_path(parent, true)?;
                }
                let mut writer = repo_storage.open_write(&dest)?;
                writer.write(&repo_bytes)?;
                writer.flush()?;
                writer.close()?;

                total_size += entry.info.size;
                repo_size += repo_bytes.len() as u64;
                files.push(ManifestFile {
                    path: entry.rel,
                    size: entry.info.size,
                    timestamp: entry.info.modified.unwrap_or(0),
                    checksum: Some(checksum),
                    checksum_page: None,
                });
            }
            StorageKind::Path => {
                paths.push(ManifestPath { path: entry.rel });
            }
            StorageKind::Link => {
                // TODO: resolve link target once `Storage` exposes a
                // link-target accessor; record an empty destination for now.
                links.push(ManifestLink {
                    path: entry.rel,
                    destination: String::new(),
                });
            }
            StorageKind::Special => {
                // Sockets / FIFOs / devices are not part of a base backup.
            }
        }
    }

    let file_count = files.len();
    let timestamp_stop = timestamp_start;

    let manifest = Manifest {
        backup_label: label.to_owned(),
        backup_type: BACKUP_TYPE_FULL.to_owned(),
        timestamp_start,
        timestamp_stop,
        db_version: info.db_version.clone(),
        db_system_id: info.db_system_id,
        files,
        paths,
        links,
    };

    // Ensure the backup directory exists even for an (improbably) empty cluster
    // so the manifest write below has a home.
    repo_storage.create_path(Path::new(&backup_root), true)?;
    manifest
        .save(repo_storage, &PathBuf::from(format!("{backup_root}/backup.manifest")))
        .map_err(|err| CommandError::Other(err.to_string()))?;

    info.current.insert(
        label.to_owned(),
        json!({
            "backup-type": BACKUP_TYPE_FULL,
            "backup-timestamp-start": timestamp_start,
            "backup-timestamp-stop": timestamp_stop,
            "backup-info-size": total_size,
            "backup-info-repo-size": repo_size,
            // Record the applied transform so restore can reverse it without
            // relying on the restore command's own compress/cipher options.
            metadata_compress_type_key(): transform.compress_type.as_str_id(),
            metadata_encrypted_key(): transform.is_encrypted(),
            "db-id": info.db_id,
        }),
    );
    info.save(repo_storage, &info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(BackupOutcome {
        label: label.to_owned(),
        file_count,
        total_size,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_io::{Filter, Sha1};
    use pgbr_storage::Posix;

    use super::*;
    use crate::pipeline::{CompressType, RepoTransform};

    const LABEL: &str = "20240101-120000F";

    fn posix_pair() -> (tempfile::TempDir, tempfile::TempDir, Posix, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_storage = Posix::new(repo.path());
        let pg_storage = Posix::new(pg.path());
        (repo, pg, repo_storage, pg_storage)
    }

    /// Write `bytes` to a PG-data-relative path, creating parents as needed.
    fn seed_file(pg: &Posix, rel: &str, bytes: &[u8]) {
        let path = PathBuf::from(rel);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            pg.create_path(parent, true).unwrap();
        }
        let mut w = pg.open_write(&path).unwrap();
        w.write(bytes).unwrap();
        w.flush().unwrap();
        w.close().unwrap();
    }

    /// Pre-create `backup.info` so the stanza counts as initialised.
    fn init_stanza(repo: &Posix, stanza: &str) {
        repo.create_path(Path::new(&format!("backup/{stanza}")), true).unwrap();
        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current: BTreeMap::new(),
            history: BTreeMap::new(),
        };
        info.save(repo, &backup_info_path(stanza)).unwrap();
    }

    /// Seed a small but representative PG data dir.
    fn seed_cluster(pg: &Posix) {
        seed_file(pg, "PG_VERSION", b"14\n");
        seed_file(pg, "base/1/1259", b"relation-data-1259");
        seed_file(pg, "base/1/1260", b"relation-data-1260");
        seed_file(pg, "global/pg_control", b"\x01\x02\x03\x04");
        // Excluded entries.
        seed_file(pg, "postmaster.pid", b"12345\n");
        seed_file(pg, "pg_wal/000000010000000000000001", b"wal-segment");
    }

    fn sha1_hex(bytes: &[u8]) -> String {
        let mut sha1 = Sha1::new();
        let mut sink = Vec::new();
        sha1.process(bytes, &mut sink).unwrap();
        sha1.digest_hex()
    }

    #[test]
    fn backup_copies_files_and_writes_manifest() {
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        let outcome = backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("backup");
        assert_eq!(outcome.label, LABEL);
        assert_eq!(outcome.file_count, 4, "4 non-excluded files expected");

        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        let manifest_path = backup_root.join("backup.manifest");
        assert!(manifest_path.exists(), "manifest should exist");

        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("load manifest");
        assert_eq!(manifest.backup_type, "full");
        assert_eq!(manifest.backup_label, LABEL);

        let listed: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert!(listed.contains(&"PG_VERSION"), "manifest must list PG_VERSION: {listed:?}");
        assert!(listed.contains(&"base/1/1259"));
        assert!(listed.contains(&"base/1/1260"));
        assert!(listed.contains(&"global/pg_control"));
        assert!(!listed.contains(&"postmaster.pid"));
        assert!(!listed.iter().any(|p| p.starts_with("pg_wal")));

        // Directories captured as paths.
        let path_set: Vec<&str> = manifest.paths.iter().map(|p| p.path.as_str()).collect();
        assert!(path_set.contains(&"base"));
        assert!(path_set.contains(&"base/1"));
        assert!(path_set.contains(&"global"));

        // Copied files match the originals byte-for-byte.
        assert_eq!(std::fs::read(backup_root.join("PG_VERSION")).unwrap(), b"14\n");
        assert_eq!(std::fs::read(backup_root.join("base/1/1259")).unwrap(), b"relation-data-1259");
    }

    #[test]
    fn backup_records_checksums() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let content = b"relation-data-1259";
        seed_file(&pg_s, "base/1/1259", content);

        backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("backup");

        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("load manifest");
        let file = manifest.file("base/1/1259").expect("file in manifest");
        assert_eq!(file.checksum.as_deref(), Some(sha1_hex(content).as_str()));
        assert_eq!(file.size, content.len() as u64);
    }

    #[test]
    fn backup_excludes_postmaster_pid_and_pg_wal() {
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("backup");

        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("load manifest");
        assert!(manifest.file("postmaster.pid").is_none());
        assert!(
            !manifest.files.iter().any(|f| f.path.starts_with("pg_wal")),
            "no pg_wal files in manifest"
        );

        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        assert!(
            !backup_root.join("postmaster.pid").exists(),
            "excluded file must not be copied"
        );
        assert!(!backup_root.join("pg_wal").exists(), "pg_wal must not be copied");
    }

    #[test]
    fn backup_updates_backup_info_current() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let entry = info.current.get(LABEL).expect("new label in [backup:current]");
        assert_eq!(entry["backup-type"], json!("full"));
        assert_eq!(entry["backup-timestamp-start"], json!(1_704_110_400));
        assert_eq!(entry["db-id"], json!(1));
        // Identity transform records compress-type=none and not encrypted.
        assert_eq!(entry["backup-info-compress-type"], json!("none"));
        assert_eq!(entry["backup-info-encrypted"], json!(false));
    }

    #[test]
    fn backup_uninitialized_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        seed_cluster(&pg_s);

        let err = backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity())
            .expect_err("uninitialised stanza must error");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "stanza not initialized; run stanza-create first"),
            other => panic!("expected Other(not initialized), got {other:?}"),
        }
    }

    #[test]
    fn backup_missing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let cfg = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: None,
            options: BTreeMap::new(),
            params: Vec::new(),
        };
        let err = backup(&cfg, &repo_s, &pg_s).expect_err("backup requires a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn walk_enumerates_nested_entries_with_relative_paths() {
        let (_repo, _pg, _repo_s, pg_s) = posix_pair();
        seed_file(&pg_s, "PG_VERSION", b"14\n");
        seed_file(&pg_s, "base/1/1259", b"x");
        seed_file(&pg_s, "global/pg_control", b"y");

        let entries = walk(&pg_s, Path::new(".")).expect("walk");
        let rels: Vec<&str> = entries.iter().map(|e| e.rel.as_str()).collect();

        assert!(rels.contains(&"PG_VERSION"));
        assert!(rels.contains(&"base"));
        assert!(rels.contains(&"base/1"));
        assert!(rels.contains(&"base/1/1259"));
        assert!(rels.contains(&"global"));
        assert!(rels.contains(&"global/pg_control"));

        // Directories carry StorageKind::Path; the leaf file is a File.
        let leaf = entries.iter().find(|e| e.rel == "base/1/1259").unwrap();
        assert_eq!(leaf.info.kind, StorageKind::File);
        let dir = entries.iter().find(|e| e.rel == "base/1").unwrap();
        assert_eq!(dir.info.kind, StorageKind::Path);
    }

    #[test]
    fn is_excluded_matches_prefixes_not_substrings() {
        assert!(is_excluded("postmaster.pid"));
        assert!(is_excluded("pg_wal"));
        assert!(is_excluded("pg_wal/000000010000000000000001"));
        assert!(is_excluded("pg_stat_tmp/foo"));
        // Not excluded: a sibling that merely shares a prefix.
        assert!(!is_excluded("pg_walk"));
        assert!(!is_excluded("base/1/1259"));
        assert!(!is_excluded("postmaster.pidx"));
    }

    #[test]
    fn full_backup_label_formats_known_timestamp() {
        // 2024-01-01 12:00:00 UTC == 1704110400.
        assert_eq!(full_backup_label(1_704_110_400), "20240101-120000F");
        // Epoch.
        assert_eq!(full_backup_label(0), "19700101-000000F");
    }

    #[test]
    fn backup_none_still_raw() {
        // The identity transform must reproduce the prior raw-copy behaviour:
        // repo files are byte-identical to the source and carry no suffix.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let content = b"relation-data-1259";
        seed_file(&pg_s, "base/1/1259", content);

        backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("backup");

        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        // No `.gz`/`.zst`/... suffix appended.
        assert!(backup_root.join("base/1/1259").exists(), "raw file must keep its name");
        assert!(!backup_root.join("base/1/1259.gz").exists());
        // Byte-identical to the source.
        assert_eq!(std::fs::read(backup_root.join("base/1/1259")).unwrap(), content);
    }

    #[test]
    fn backup_gz_writes_suffixed_compressed_repo_file() {
        // A gz transform writes `<rel>.gz` with bytes that differ from the
        // plaintext, while the manifest still records the PLAINTEXT sha1+size.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let content = b"relation data that compresses, relation data that compresses, again";
        seed_file(&pg_s, "base/1/1259", content);

        let transform = RepoTransform {
            compress_type: CompressType::Gz,
            compress_level: 6,
            cipher_pass: None,
        };
        backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &transform).expect("backup");

        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        let repo_file = backup_root.join("base/1/1259.gz");
        assert!(repo_file.exists(), "compressed repo file must carry the .gz suffix");
        assert!(!backup_root.join("base/1/1259").exists(), "no un-suffixed file");
        let repo_bytes = std::fs::read(&repo_file).unwrap();
        assert_ne!(repo_bytes.as_slice(), content, "repo bytes must be compressed");

        // Manifest records the PLAINTEXT checksum/size and the relpath WITHOUT
        // the compression suffix.
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("load manifest");
        let file = manifest.file("base/1/1259").expect("file in manifest");
        assert_eq!(file.checksum.as_deref(), Some(sha1_hex(content).as_str()));
        assert_eq!(file.size, content.len() as u64);

        // backup.info records the transform.
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let entry = info.current.get(LABEL).expect("label entry");
        assert_eq!(entry["backup-info-compress-type"], json!("gz"));
        assert_eq!(entry["backup-info-encrypted"], json!(false));
    }
}
