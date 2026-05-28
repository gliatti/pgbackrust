//! `restore` command — copy a backup into a PG data directory.
//!
//! C reference: `src/command/restore/restore.c`. This first slice covers the
//! **raw copy** path: it re-creates every directory the manifest records, then
//! copies every captured file from the repository's flat backup layout
//! (`backup/<stanza>/<label>/<file.path>`) into the PG target, verifying each
//! restored file's SHA-1 (via the [`pgbr_io::Sha1`] filter) against the value
//! recorded in the manifest.
//!
//! Backup selection:
//!
//! - `--set <label>` restores that specific backup; an unknown label (not in
//!   `backup/<stanza>/backup.info`'s `[backup:current]` block) is a
//!   [`CommandError::Other`].
//! - Without `--set`, the lexicographically-greatest label in
//!   `[backup:current]` is restored — pgBackRest labels sort chronologically
//!   (`YYYYMMDD-HHMMSSF…`), so the greatest label is the latest backup. An
//!   empty `[backup:current]` is a [`CommandError::Other`].
//!
//! Checksum verification is **on** and a mismatch is a **hard error**
//! ([`CommandError::Other`]): restoring corrupt data silently is worse than
//! failing the restore.
//!
//! # Deferred to later commits
//!
//! - `--delta` (only restore files that differ from what is on disk),
//! - tablespace remapping (`--tablespace-map` / `--tablespace-map-all`),
//! - recovery-config generation (`recovery.conf` / `postgresql.auto.conf`),
//! - `--db-include` / `--db-exclude` selective database restore,
//! - symlink re-creation — the [`pgbr_storage::Storage`] trait has no
//!   link-create method yet, so `[target:link]` entries are skipped and merely
//!   counted (`RestoreOutcome::skipped_links`). TODO: wire this up once
//!   `Storage` grows a symlink primitive.
//!
//! This is the full raw-restore path; everything above is genuinely out of
//! scope for the slice, not silently dropped.

use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoBackup, InfoError, Manifest};
use pgbr_io::{Filter, IoRead, IoWrite, Sha1};
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;

/// Result of a [`restore_inner`] pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Backup label that was restored.
    pub label: String,
    /// Number of files copied into the PG target.
    pub files_restored: usize,
    /// Number of directories created in the PG target.
    pub paths_created: usize,
    /// Number of `[target:link]` entries skipped (symlink re-creation deferred).
    pub skipped_links: usize,
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

/// `--set` lookup. Returns the requested backup label, or `None` when the
/// option is absent (restore the latest backup).
fn requested_set(config: &LoadedConfig) -> Option<&str> {
    match config.options.get(&("set".to_owned(), None)) {
        Some(OptionValue::String(label)) => Some(label.as_str()),
        _ => None,
    }
}

/// Resolve the single backup label to restore.
///
/// With `--set`, that label — but only if it is present in
/// `[backup:current]` (an unknown set is an error). Without `--set`, the
/// lexicographically-greatest label in `[backup:current]`, which is the most
/// recent backup given pgBackRest's chronological label format. An empty
/// `[backup:current]` is an error.
fn select_backup(config: &LoadedConfig, repo: &dyn Storage, stanza: &str) -> Result<String, CommandError> {
    let info = InfoBackup::load(repo, &backup_info_path(stanza)).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: backup_info_path(stanza),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    if let Some(label) = requested_set(config) {
        if info.current.contains_key(label) {
            return Ok(label.to_owned());
        }
        return Err(CommandError::Other(format!(
            "backup set {label} is not present in the repository"
        )));
    }

    // `BTreeMap` keys iterate in ascending order, so the last one is the
    // lexicographically-greatest (and therefore most recent) label.
    info.current
        .keys()
        .next_back()
        .cloned()
        .ok_or_else(|| CommandError::Other("no backups to restore".to_owned()))
}

/// Stream one backup file from the repository into the PG target, recomputing
/// its SHA-1 along the way. Returns the digest of the bytes written.
fn copy_file(repo: &dyn Storage, pg: &dyn Storage, src: &Path, dst: &Path) -> Result<String, CommandError> {
    // Make sure the destination's parent directory exists. Directories from
    // `[target:path]` are created up front, but defensively create the parent
    // here too so files in unlisted paths still land.
    if let Some(parent) = dst.parent()
        && !parent.as_os_str().is_empty()
    {
        pg.create_path(parent, true)?;
    }

    let mut reader: Box<dyn IoRead> = repo.open_read(src)?;
    let bytes = reader.read_all()?;

    let mut writer: Box<dyn IoWrite> = pg.open_write(dst)?;
    writer.write(&bytes)?;
    writer.flush()?;
    writer.close()?;

    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    sha.process(&bytes, &mut sink)?;
    Ok(sha.digest_hex())
}

/// Core restore pass. The thin [`restore`] entry point prints the outcome;
/// tests assert against the returned [`RestoreOutcome`] directly.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] if `backup.info` is absent, or for backend
///   read/write failures.
/// - [`CommandError::Io`] for stream failures while copying files.
/// - [`CommandError::Other`] if `backup.info` / `backup.manifest` is
///   malformed, if there are no backups to restore, if `--set` names an
///   unknown backup, or if a restored file's SHA-1 does not match the
///   manifest.
pub fn restore_inner(config: &LoadedConfig, repo: &dyn Storage, pg: &dyn Storage) -> Result<RestoreOutcome, CommandError> {
    let stanza = require_stanza(config)?;
    let label = select_backup(config, repo, stanza)?;

    let manifest = Manifest::load(repo, &manifest_path(stanza, &label)).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: manifest_path(stanza, &label),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    // 1. Re-create every directory recorded in the manifest.
    let mut paths_created = 0;
    for path in &manifest.paths {
        pg.create_path(Path::new(&path.path), true)?;
        paths_created += 1;
    }

    // 2. Copy every file, verifying its checksum on the way out.
    let mut files_restored = 0;
    for file in &manifest.files {
        let src = backup_file_path(stanza, &label, &file.path);
        let dst = PathBuf::from(&file.path);
        let actual = copy_file(repo, pg, &src, &dst)?;

        // Zero-length files carry no checksum; nothing to compare.
        if let Some(expected) = file.checksum.as_deref()
            && actual != expected
        {
            return Err(CommandError::Other(format!("restore checksum mismatch for {}", file.path)));
        }

        files_restored += 1;
    }

    // 3. Symlinks: deferred — count them and move on. TODO: re-create once the
    //    `Storage` trait gains a symlink-create method.
    let skipped_links = manifest.links.len();

    Ok(RestoreOutcome {
        label,
        files_restored,
        paths_created,
        skipped_links,
    })
}

/// `restore` — restore a backup into a PG data directory.
///
/// Runs [`restore_inner`] and prints a one-line summary.
///
/// # Errors
///
/// Forwards every error from [`restore_inner`].
#[allow(clippy::print_stdout)]
pub fn restore(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let outcome = restore_inner(config, repo_storage, pg_storage)?;

    println!(
        "restore: backup {} — {} file(s) restored, {} path(s) created, {} link(s) skipped",
        outcome.label, outcome.files_restored, outcome.paths_created, outcome.skipped_links
    );

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{DbHistoryEntry, InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{RestoreOutcome, restore_inner};
    use crate::CommandError;

    /// SHA-1 of `bytes`, computed the way `restore` recomputes it, so fixtures
    /// can record the digest the restore will compare against.
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
            command: "restore".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    /// A paired (repo, pg-target) of `Posix` storages, each over its own tempdir.
    fn posix_pair() -> (TempDir, TempDir, Posix, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_storage = Posix::new(repo.path());
        let pg_storage = Posix::new(pg.path());
        (repo, pg, repo_storage, pg_storage)
    }

    /// Seed `backup/<stanza>/backup.info` listing every label in `[backup:current]`.
    fn seed_backup_info(repo: &Posix, stanza: &str, labels: &[&str]) {
        let mut current = BTreeMap::new();
        for label in labels {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
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

    /// Write a `backup.manifest` for `label` plus the captured files it lists.
    /// `files` is `(rel_path, bytes, checksum)`; `paths` are directory entries.
    fn seed_backup(
        repo: &Posix,
        stanza: &str,
        label: &str,
        files: &[(&str, &[u8], Option<String>)],
        paths: &[&str],
        links: &[(&str, &str)],
    ) {
        repo.create_path(Path::new(&format!("backup/{stanza}/{label}")), true)
            .expect("create backup label dir");

        let manifest_files: Vec<ManifestFile> = files
            .iter()
            .map(|(path, bytes, checksum)| ManifestFile {
                path: (*path).to_owned(),
                size: bytes.len() as u64,
                timestamp: 1_704_110_400,
                checksum: checksum.clone(),
                checksum_page: None,
            })
            .collect();

        let manifest = Manifest {
            backup_label: label.to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: manifest_files,
            paths: paths.iter().map(|p| ManifestPath { path: (*p).to_owned() }).collect(),
            links: links
                .iter()
                .map(|(p, d)| ManifestLink {
                    path: (*p).to_owned(),
                    destination: (*d).to_owned(),
                })
                .collect(),
        };
        manifest
            .save(repo, &super::manifest_path(stanza, label))
            .expect("save manifest");

        // Materialise each captured file under backup/<stanza>/<label>/<rel>.
        for (rel, bytes, _) in files {
            let full = format!("backup/{stanza}/{label}/{rel}");
            if let Some(parent) = Path::new(&full).parent() {
                repo.create_path(parent, true).expect("create capture parent");
            }
            let mut w = repo
                .open_write(&super::backup_file_path(stanza, label, rel))
                .expect("open capture file");
            w.write(bytes).expect("write capture file");
            w.close().expect("close capture file");
        }
    }

    #[test]
    fn restore_copies_files_to_pg_target() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let a = b"PG_VERSION contents".as_slice();
        let b = b"base table page bytes".as_slice();
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[
                ("pg_data/PG_VERSION", a, Some(sha1_hex(a))),
                ("pg_data/base/1/1259", b, Some(sha1_hex(b))),
            ],
            &["pg_data", "pg_data/base", "pg_data/base/1"],
            &[],
        );

        let outcome = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.files_restored, 2);

        // Read the restored files back via the pg storage and compare bytes.
        let restored_a = {
            let mut r = pg_s.open_read(Path::new("pg_data/PG_VERSION")).expect("open restored a");
            r.read_all().expect("read a")
        };
        assert_eq!(restored_a, a);

        let restored_b = {
            let mut r = pg_s.open_read(Path::new("pg_data/base/1/1259")).expect("open restored b");
            r.read_all().expect("read b")
        };
        assert_eq!(restored_b, b);
    }

    #[test]
    fn restore_creates_directories() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[],
            &["pg_data", "pg_data/base", "pg_data/global"],
            &[],
        );

        let outcome = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.paths_created, 3);

        for dir in ["pg_data", "pg_data/base", "pg_data/global"] {
            let info = pg_s.info(Path::new(dir)).unwrap_or_else(|_| panic!("dir {dir} should exist"));
            assert_eq!(info.kind, pgbr_storage::StorageKind::Path, "{dir} should be a directory");
        }
    }

    #[test]
    fn restore_selects_latest_when_no_set() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let older = "20240101-120000F";
        let newer = "20240202-120000F";

        seed_backup_info(&repo_s, stanza, &[older, newer]);
        // Both backups list a single, distinctly-named file so we can tell which
        // manifest was actually restored.
        let old_bytes = b"older".as_slice();
        let new_bytes = b"newer".as_slice();
        seed_backup(
            &repo_s,
            stanza,
            older,
            &[("only/old.txt", old_bytes, Some(sha1_hex(old_bytes)))],
            &["only"],
            &[],
        );
        seed_backup(
            &repo_s,
            stanza,
            newer,
            &[("only/new.txt", new_bytes, Some(sha1_hex(new_bytes)))],
            &["only"],
            &[],
        );

        let outcome = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.label, newer);
        assert!(
            pg_s.exists(Path::new("only/new.txt")).unwrap(),
            "newer file should be restored"
        );
        assert!(
            !pg_s.exists(Path::new("only/old.txt")).unwrap(),
            "older file should not be restored"
        );
    }

    #[test]
    fn restore_set_selects_specific_backup() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let older = "20240101-120000F";
        let newer = "20240202-120000F";

        seed_backup_info(&repo_s, stanza, &[older, newer]);
        let old_bytes = b"older".as_slice();
        let new_bytes = b"newer".as_slice();
        seed_backup(
            &repo_s,
            stanza,
            older,
            &[("only/old.txt", old_bytes, Some(sha1_hex(old_bytes)))],
            &["only"],
            &[],
        );
        seed_backup(
            &repo_s,
            stanza,
            newer,
            &[("only/new.txt", new_bytes, Some(sha1_hex(new_bytes)))],
            &["only"],
            &[],
        );

        // Explicitly select the older backup.
        let outcome = restore_inner(&cfg(Some(stanza), Some(older)), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.label, older);
        assert!(
            pg_s.exists(Path::new("only/old.txt")).unwrap(),
            "older file should be restored"
        );
        assert!(
            !pg_s.exists(Path::new("only/new.txt")).unwrap(),
            "newer file should not be restored"
        );
    }

    #[test]
    fn restore_checksum_mismatch_is_a_hard_error() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let bytes = b"genuine bytes".as_slice();
        seed_backup_info(&repo_s, stanza, &[label]);
        // Record a deliberately wrong checksum for the file.
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[(
                "pg_data/corrupt",
                bytes,
                Some("0000000000000000000000000000000000000000".to_owned()),
            )],
            &["pg_data"],
            &[],
        );

        let err = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect_err("checksum mismatch must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("checksum mismatch"), "unexpected message: {msg}"),
            other => panic!("expected Other(checksum mismatch), got {other:?}"),
        }
    }

    #[test]
    fn restore_unknown_set_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        seed_backup_info(&repo_s, stanza, &["20240101-120000F"]);

        let err = restore_inner(&cfg(Some(stanza), Some("20990909-000000F")), &repo_s, &pg_s).expect_err("unknown set must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("not present"), "unexpected message: {msg}"),
            other => panic!("expected Other(not present), got {other:?}"),
        }
    }

    #[test]
    fn restore_no_backups_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        // An empty [backup:current] block.
        seed_backup_info(&repo_s, stanza, &[]);

        let err = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect_err("no backups must fail");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "no backups to restore"),
            other => panic!("expected Other(no backups to restore), got {other:?}"),
        }
    }

    #[test]
    fn restore_missing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let err = restore_inner(&cfg(None, None), &repo_s, &pg_s).expect_err("missing stanza must fail");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption(stanza), got {other:?}"),
        }
    }

    #[test]
    fn restore_counts_skipped_links() {
        // A backup with one symlink: it is skipped but counted in the outcome.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[],
            &["pg_data"],
            &[("pg_data/pg_wal", "/var/lib/pg_wal")],
        );

        let outcome: RestoreOutcome = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.skipped_links, 1);
    }
}
