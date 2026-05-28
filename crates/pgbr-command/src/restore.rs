//! `restore` command — copy a backup into a PG data directory.
//!
//! C reference: `src/command/restore/restore.c`. This slice re-creates every
//! directory the manifest records, then for every captured file reads it from
//! the repository's flat backup layout
//! (`backup/<stanza>/<label>/<file.path><suffix>`), reverses the backup's
//! [`RepoTransform`] (decrypt then decompress), writes the recovered plaintext
//! to the PG target, and verifies its SHA-1 (via the [`pgbr_io::Sha1`] filter)
//! against the value recorded in the manifest. Because the manifest records
//! the *plaintext* checksum, that single check validates the whole
//! compress -> encrypt -> decrypt -> decompress round trip.
//!
//! The transform is read from the backup's recorded `backup.info` metadata
//! (compress-type + encrypted flag), so restore reverses exactly what the
//! backup applied — independent of the restore command's own compress/cipher
//! options. The cipher *password* is never stored in the repo, so it is sourced
//! from the resolved options. When the metadata is absent (e.g. an older
//! backup), the transform falls back to the resolved options.
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
//! # Manifest references (differential restore)
//!
//! A differential backup records files unchanged since its base full backup
//! with `reference: Some(<full label>)` instead of re-copying their bytes. When
//! restore encounters such a file it reads the bytes from the *referenced*
//! backup's directory (`backup/<stanza>/<reference label>/<path><suffix>`)
//! rather than the restored backup's own dir. The referenced backup's transform
//! (compress / cipher) is read from its own `[backup:current]` entry in
//! `backup.info`, so each file is reversed with exactly the transform it was
//! written under. The final plaintext is SHA-1-checked the same way regardless
//! of which backup supplied the bytes. Files with `reference: None` restore from
//! the restored backup's own dir, exactly as before.
//!
//! # Delta restore (`--delta`)
//!
//! When `--delta` is set, each manifest file is checked against what is already
//! on the PG target *before* copying: if the target file exists with the same
//! size and (when the manifest records one) the same SHA-1, the copy is skipped
//! and counted in [`RestoreOutcome::files_skipped`]. Mismatched or missing files
//! are restored exactly as in a non-delta restore. Without `--delta`, every
//! manifest file is copied (the prior behaviour, unchanged).
//!
//! Delta restore also removes target files that are **not** present in the
//! manifest so the target ends up matching the backup exactly. After the copy
//! pass, the PG target is walked recursively and any regular file whose
//! manifest-relative path is absent from the manifest's `[target:file]` set is
//! removed (counted in [`RestoreOutcome::files_removed`]). Empty directories and
//! symlinks are left alone — directory/symlink reconciliation is still deferred
//! along with symlink re-creation.
//!
//! # Deferred to later commits
//!
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
use pgbr_info::{InfoBackup, InfoError, Manifest, ManifestFile};
use pgbr_io::{Filter, IoRead, Sha1};
use pgbr_storage::{Storage, StorageError, StorageKind};

use crate::CommandError;
use crate::pipeline::RepoTransform;

/// Result of a [`restore_inner`] pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Backup label that was restored.
    pub label: String,
    /// Number of files actually copied into the PG target.
    pub files_restored: usize,
    /// Number of files skipped because the target already matched the manifest
    /// (delta restore only; always `0` without `--delta`).
    pub files_skipped: usize,
    /// Number of stray target files removed because they were absent from the
    /// manifest (delta restore only; always `0` without `--delta`).
    pub files_removed: usize,
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

/// Whether `--delta` was supplied and set to `true`.
fn delta_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("delta".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Whether the file already on the PG target matches the manifest entry, so the
/// copy can be skipped under `--delta`.
///
/// A file matches when it exists with the same size as the manifest records
/// and, when the manifest records a checksum, the same SHA-1. A zero-length
/// manifest file carries no checksum, so a same-size (zero-byte) target matches
/// on size alone. A missing target, a size mismatch, a checksum mismatch, or any
/// read error all count as "does not match" — i.e. restore it.
fn target_matches(pg: &dyn Storage, rel: &Path, file: &ManifestFile) -> bool {
    // Size first: cheap, and a mismatch settles it without reading the file.
    match pg.info(rel) {
        Ok(info) if info.kind == StorageKind::File && info.size == file.size => {}
        _ => return false,
    }

    // When the manifest records a checksum, the target's SHA-1 must match it.
    let Some(expected) = file.checksum.as_deref() else {
        // No recorded checksum (zero-length file); same size is enough.
        return true;
    };

    let Ok(mut reader) = pg.open_read(rel) else {
        return false;
    };
    let Ok(bytes) = reader.read_all() else {
        return false;
    };
    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    if sha.process(&bytes, &mut sink).is_err() {
        return false;
    }
    sha.digest_hex() == expected
}

/// Recursively collect every regular file under `dir` in the PG target,
/// returning paths relative to the target root (matching the manifest's
/// `[target:file]` key format). Symlinks and directories are not collected.
///
/// Used by delta restore to find stray files absent from the manifest.
fn collect_target_files(pg: &dyn Storage, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CommandError> {
    let entries = match pg.list(dir) {
        Ok(entries) => entries,
        // A directory recorded in the manifest may not actually exist on the
        // target (e.g. nothing was restored into it). Treat that as empty.
        Err(StorageError::NotFound { .. }) => return Ok(()),
        Err(err) => return Err(CommandError::Storage(err)),
    };

    for entry in entries {
        // `list` returns backend-resolved (absolute) paths; recompute the
        // target-relative path by appending the file name to `dir`.
        let Some(name) = entry.path.file_name() else {
            continue;
        };
        let rel = dir.join(name);
        match entry.kind {
            StorageKind::File => out.push(rel),
            StorageKind::Path => collect_target_files(pg, &rel, out)?,
            // Symlinks / specials are left untouched (symlink handling deferred).
            StorageKind::Link | StorageKind::Special => {}
        }
    }

    Ok(())
}

/// Resolve the single backup to restore, returning its label and its
/// `[backup:current]` metadata entry.
///
/// With `--set`, that label — but only if it is present in
/// `[backup:current]` (an unknown set is an error). Without `--set`, the
/// lexicographically-greatest label in `[backup:current]`, which is the most
/// recent backup given pgBackRest's chronological label format. An empty
/// `[backup:current]` is an error.
///
/// The returned metadata entry carries the compress-type / encrypted flag the
/// backup recorded, which [`restore_inner`] feeds to
/// [`RepoTransform::from_metadata`]. The whole [`InfoBackup`] is returned too so
/// referenced backups' transforms can be resolved during reference restore.
fn select_backup(
    config: &LoadedConfig,
    repo: &dyn Storage,
    stanza: &str,
) -> Result<(String, serde_json::Value, InfoBackup), CommandError> {
    let info = InfoBackup::load(repo, &backup_info_path(stanza)).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: backup_info_path(stanza),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    if let Some(label) = requested_set(config) {
        if let Some(entry) = info.current.get(label) {
            let entry = entry.clone();
            return Ok((label.to_owned(), entry, info));
        }
        return Err(CommandError::Other(format!(
            "backup set {label} is not present in the repository"
        )));
    }

    // `BTreeMap` keys iterate in ascending order, so the last one is the
    // lexicographically-greatest (and therefore most recent) label.
    let Some((label, entry)) = info.current.iter().next_back() else {
        return Err(CommandError::Other("no backups to restore".to_owned()));
    };
    let label = label.clone();
    let entry = entry.clone();
    Ok((label, entry, info))
}

/// Read one backup file from the repository, reverse the backup `transform`
/// (decrypt then decompress) to recover the plaintext, write the plaintext into
/// the PG target, and return the SHA-1 of the recovered plaintext.
///
/// `src` is the repo path *including* the compression suffix; `dst` is the
/// plaintext PG-target path.
fn copy_file(
    repo: &dyn Storage,
    pg: &dyn Storage,
    src: &Path,
    dst: &Path,
    transform: &RepoTransform,
) -> Result<String, CommandError> {
    // Make sure the destination's parent directory exists. Directories from
    // `[target:path]` are created up front, but defensively create the parent
    // here too so files in unlisted paths still land.
    if let Some(parent) = dst.parent()
        && !parent.as_os_str().is_empty()
    {
        pg.create_path(parent, true)?;
    }

    let mut reader: Box<dyn IoRead> = repo.open_read(src)?;
    let repo_bytes = reader.read_all()?;

    // Reverse the transform: decrypt then decompress. With the identity
    // transform this returns the bytes unchanged.
    let plaintext = transform.apply_reverse(&repo_bytes)?;

    let mut writer = pg.open_write(dst)?;
    writer.write(&plaintext)?;
    writer.flush()?;
    writer.close()?;

    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    sha.process(&plaintext, &mut sink)?;
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
    let delta = delta_enabled(config);
    let (label, metadata, info) = select_backup(config, repo, stanza)?;

    // The transform the restored backup applied — read from the recorded
    // metadata, with the resolved options supplying the cipher password (never
    // stored in the repo) and any value the metadata omits.
    let transform = RepoTransform::from_metadata(&metadata, config);

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

    // 2. Copy every file, reversing the transform and verifying its plaintext
    //    checksum on the way out. Under `--delta`, a file whose target copy
    //    already matches the manifest (same size + SHA-1) is skipped.
    let mut files_restored = 0;
    let mut files_skipped = 0;
    for file in &manifest.files {
        let dst = PathBuf::from(&file.path);

        if delta && target_matches(pg, &dst, file) {
            files_skipped += 1;
            continue;
        }

        // A referenced file's bytes live in an earlier backup (differential
        // restore). Resolve which backup supplies the bytes and the transform
        // they were written under: the restored backup uses `transform`; a
        // referenced backup uses the transform recorded in *its* `backup.info`
        // entry (the cipher password still comes from the restore options).
        let (src_label, src_transform) = match file.reference.as_deref() {
            None => (label.as_str(), transform.clone()),
            Some(reference) => {
                let reference_transform = info
                    .current
                    .get(reference)
                    .map_or_else(|| transform.clone(), |entry| RepoTransform::from_metadata(entry, config));
                (reference, reference_transform)
            }
        };

        // The repo file carries the compression suffix; the PG-target file does not.
        let repo_rel = format!("{}{}", file.path, src_transform.repo_suffix());
        let src = backup_file_path(stanza, src_label, &repo_rel);
        let actual = copy_file(repo, pg, &src, &dst, &src_transform)?;

        // Zero-length files carry no checksum; nothing to compare.
        if let Some(expected) = file.checksum.as_deref()
            && actual != expected
        {
            return Err(CommandError::Other(format!("restore checksum mismatch for {}", file.path)));
        }

        files_restored += 1;
    }

    // 3. Delta restore removes target files absent from the manifest so the
    //    target matches the backup exactly. Walk every restored directory root
    //    and delete any regular file not listed in `[target:file]`.
    let files_removed = if delta { remove_stray_files(pg, &manifest)? } else { 0 };

    // 4. Symlinks: deferred — count them and move on. TODO: re-create once the
    //    `Storage` trait gains a symlink-create method.
    let skipped_links = manifest.links.len();

    Ok(RestoreOutcome {
        label,
        files_restored,
        files_skipped,
        files_removed,
        paths_created,
        skipped_links,
    })
}

/// Delete every regular file under the manifest's directory roots that is not
/// listed in the manifest's `[target:file]` set, returning the number removed.
///
/// Roots are the top-level components of the manifest's recorded paths and
/// files, so the walk covers exactly the tree the backup describes without
/// descending into unrelated parts of the filesystem.
fn remove_stray_files(pg: &dyn Storage, manifest: &Manifest) -> Result<usize, CommandError> {
    use std::collections::BTreeSet;

    // The set of paths the manifest captured — anything else under the roots is stray.
    let kept: BTreeSet<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();

    // Top-level directory roots to walk: the first component of every recorded
    // path and file. A `BTreeSet` dedups them so each root is walked once.
    let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
    for path in &manifest.paths {
        if let Some(root) = Path::new(&path.path).components().next() {
            roots.insert(PathBuf::from(root.as_os_str()));
        }
    }
    for file in &manifest.files {
        if let Some(root) = Path::new(&file.path).components().next() {
            roots.insert(PathBuf::from(root.as_os_str()));
        }
    }

    let mut present = Vec::new();
    for root in &roots {
        collect_target_files(pg, root, &mut present)?;
    }

    let mut files_removed = 0;
    for rel in present {
        // Compare against the manifest's `/`-joined string keys.
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if !kept.contains(rel_str.as_str()) {
            pg.remove(&rel, false)?;
            files_removed += 1;
        }
    }

    Ok(files_removed)
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
        "restore: backup {} — {} file(s) restored, {} skipped, {} removed, {} path(s) created, {} link(s) skipped",
        outcome.label,
        outcome.files_restored,
        outcome.files_skipped,
        outcome.files_removed,
        outcome.paths_created,
        outcome.skipped_links
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
        cfg_delta(stanza, set, false)
    }

    /// Like [`cfg`] but also toggles `--delta`.
    fn cfg_delta(stanza: Option<&str>, set: Option<&str>, delta: bool) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(label) = set {
            options.insert(("set".to_owned(), None), OptionValue::String(label.to_owned()));
        }
        if delta {
            options.insert(("delta".to_owned(), None), OptionValue::Boolean(true));
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
                reference: None,
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

    // ---- delta restore -----------------------------------------------------

    #[test]
    fn delta_skips_matching_files() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let same = b"already identical contents".as_slice();
        let other = b"needs restoring".as_slice();
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[
                ("pg_data/match.txt", same, Some(sha1_hex(same))),
                ("pg_data/other.txt", other, Some(sha1_hex(other))),
            ],
            &["pg_data"],
            &[],
        );

        // Pre-place the matching file (identical to the backup) on the target.
        seed_pg_file(&pg_s, "pg_data/match.txt", same);

        let outcome = restore_inner(&cfg_delta(Some(stanza), None, true), &repo_s, &pg_s).expect("delta restore");
        // One file matched and was skipped; the other was restored.
        assert_eq!(outcome.files_skipped, 1);
        assert_eq!(outcome.files_restored, 1);

        // The skipped file is untouched and the other file is now present.
        let kept = {
            let mut r = pg_s.open_read(Path::new("pg_data/match.txt")).expect("open match");
            r.read_all().expect("read match")
        };
        assert_eq!(kept, same, "skipped file content must be unchanged");

        let restored = {
            let mut r = pg_s.open_read(Path::new("pg_data/other.txt")).expect("open other");
            r.read_all().expect("read other")
        };
        assert_eq!(restored, other);
    }

    #[test]
    fn delta_restores_changed_files() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let backup_bytes = b"the canonical backup contents".as_slice();
        let stale_bytes = b"stale local edits that differ".as_slice();
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[("pg_data/changed.txt", backup_bytes, Some(sha1_hex(backup_bytes)))],
            &["pg_data"],
            &[],
        );

        // Pre-place a file with DIFFERENT content (and a different size).
        seed_pg_file(&pg_s, "pg_data/changed.txt", stale_bytes);

        let outcome = restore_inner(&cfg_delta(Some(stanza), None, true), &repo_s, &pg_s).expect("delta restore");
        assert_eq!(outcome.files_restored, 1, "mismatched file must be restored");
        assert_eq!(outcome.files_skipped, 0);

        let restored = {
            let mut r = pg_s.open_read(Path::new("pg_data/changed.txt")).expect("open changed");
            r.read_all().expect("read changed")
        };
        assert_eq!(restored, backup_bytes, "target must now match the backup");
    }

    #[test]
    fn delta_restores_missing_files() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let bytes = b"a file absent from the target".as_slice();
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[("pg_data/fresh.txt", bytes, Some(sha1_hex(bytes)))],
            &["pg_data"],
            &[],
        );

        // Nothing pre-placed on the target.
        let outcome = restore_inner(&cfg_delta(Some(stanza), None, true), &repo_s, &pg_s).expect("delta restore");
        assert_eq!(outcome.files_restored, 1, "missing file must be restored normally");
        assert_eq!(outcome.files_skipped, 0);

        let restored = {
            let mut r = pg_s.open_read(Path::new("pg_data/fresh.txt")).expect("open fresh");
            r.read_all().expect("read fresh")
        };
        assert_eq!(restored, bytes);
    }

    #[test]
    fn delta_removes_files_absent_from_manifest() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let bytes = b"a managed file".as_slice();
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[("pg_data/keep.txt", bytes, Some(sha1_hex(bytes)))],
            &["pg_data", "pg_data/sub"],
            &[],
        );

        // Pre-place a stray file not present in the manifest, plus one in a subdir.
        seed_pg_file(&pg_s, "pg_data/stray.txt", b"not in the backup");
        seed_pg_file(&pg_s, "pg_data/sub/orphan.txt", b"also not in the backup");

        let outcome = restore_inner(&cfg_delta(Some(stanza), None, true), &repo_s, &pg_s).expect("delta restore");
        assert_eq!(outcome.files_restored, 1);
        assert_eq!(outcome.files_removed, 2, "both stray files must be removed");

        assert!(
            pg_s.exists(Path::new("pg_data/keep.txt")).unwrap(),
            "managed file must remain"
        );
        assert!(
            !pg_s.exists(Path::new("pg_data/stray.txt")).unwrap(),
            "stray file must be removed"
        );
        assert!(
            !pg_s.exists(Path::new("pg_data/sub/orphan.txt")).unwrap(),
            "nested stray file must be removed"
        );
    }

    #[test]
    fn non_delta_restores_everything() {
        // No-regression guard: without `--delta`, even a byte-identical
        // pre-existing target file is restored (counted, not skipped) and no
        // stray-file removal happens.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let same = b"already identical contents".as_slice();
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[("pg_data/match.txt", same, Some(sha1_hex(same)))],
            &["pg_data"],
            &[],
        );
        seed_pg_file(&pg_s, "pg_data/match.txt", same);
        // A stray file that delta would remove but a normal restore leaves alone.
        seed_pg_file(&pg_s, "pg_data/stray.txt", b"untouched without delta");

        let outcome = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.files_restored, 1, "matching file is still restored without --delta");
        assert_eq!(outcome.files_skipped, 0);
        assert_eq!(outcome.files_removed, 0);
        assert!(
            pg_s.exists(Path::new("pg_data/stray.txt")).unwrap(),
            "stray file must survive a non-delta restore"
        );
    }

    #[test]
    fn target_matches_helper() {
        let (_repo, _pg, _repo_s, pg_s) = posix_pair();

        let bytes = b"helper fixture bytes".as_slice();
        let file = ManifestFile {
            path: "pg_data/h.txt".to_owned(),
            size: bytes.len() as u64,
            timestamp: 1_704_110_400,
            checksum: Some(sha1_hex(bytes)),
            checksum_page: None,
            reference: None,
        };

        // Missing target: does not match.
        assert!(
            !super::target_matches(&pg_s, Path::new("pg_data/h.txt"), &file),
            "missing target must not match"
        );

        // Same size + same checksum: matches.
        seed_pg_file(&pg_s, "pg_data/h.txt", bytes);
        assert!(
            super::target_matches(&pg_s, Path::new("pg_data/h.txt"), &file),
            "identical target must match"
        );

        // Same size, different content (checksum mismatch): does not match.
        let other = b"helper fixturf bytes".as_slice(); // same length, one byte differs
        assert_eq!(other.len(), bytes.len(), "fixture must keep the size equal");
        seed_pg_file(&pg_s, "pg_data/h.txt", other);
        assert!(
            !super::target_matches(&pg_s, Path::new("pg_data/h.txt"), &file),
            "checksum mismatch must not match"
        );

        // Different size: does not match (size check short-circuits).
        seed_pg_file(&pg_s, "pg_data/h.txt", b"a different length entirely");
        assert!(
            !super::target_matches(&pg_s, Path::new("pg_data/h.txt"), &file),
            "size mismatch must not match"
        );

        // Zero-length manifest file (no checksum): matches a zero-length target on size alone.
        let empty_file = ManifestFile {
            path: "pg_data/empty".to_owned(),
            size: 0,
            timestamp: 1_704_110_400,
            checksum: None,
            checksum_page: None,
            reference: None,
        };
        seed_pg_file(&pg_s, "pg_data/empty", b"");
        assert!(
            super::target_matches(&pg_s, Path::new("pg_data/empty"), &empty_file),
            "zero-length target must match a checksum-less manifest entry"
        );
    }

    // ---- end-to-end backup -> restore round trips --------------------------

    use crate::backup::backup_inner;
    use crate::pipeline::{CompressType, RepoTransform};

    /// Pre-create `backup.info` with an empty `[backup:current]` so `backup_inner`
    /// can append its own entry — mirrors `backup::tests::init_stanza`.
    fn init_stanza(repo: &Posix, stanza: &str) {
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
            current: BTreeMap::new(),
            history,
        };
        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup/<stanza>");
        info.save(repo, &super::backup_info_path(stanza)).expect("save backup.info");
    }

    /// Write `bytes` to a PG-data-relative path under `pg`, creating parents.
    fn seed_pg_file(pg: &Posix, rel: &str, bytes: &[u8]) {
        let path = std::path::PathBuf::from(rel);
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

    /// A restore config carrying the supplied options (compress/cipher).
    fn restore_cfg(stanza: &str, options: Vec<((&str, Option<u32>), OptionValue)>) -> LoadedConfig {
        let mut map: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        for ((name, idx), value) in options {
            map.insert((name.to_owned(), idx), value);
        }
        LoadedConfig {
            command: "restore".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options: map,
            params: Vec::new(),
        }
    }

    const FILES: &[(&str, &[u8])] = &[
        ("PG_VERSION", b"14\n"),
        ("base/1/1259", b"relation data 1259, relation data 1259, relation data 1259"),
        (
            "global/pg_control",
            b"\x01\x02\x03\x04control file bytes that repeat repeat repeat",
        ),
    ];

    #[test]
    fn backup_then_restore_gz_round_trip() {
        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_dst = tempfile::tempdir().unwrap();
        let repo_s = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());
        let pg_dst_s = Posix::new(pg_dst.path());

        let stanza = "demo";
        let label = "20240101-120000F";
        init_stanza(&repo_s, stanza);
        for (rel, bytes) in FILES {
            seed_pg_file(&pg_src_s, rel, bytes);
        }

        let transform = RepoTransform {
            compress_type: CompressType::Gz,
            compress_level: 6,
            cipher_pass: None,
        };
        backup_inner(stanza, &repo_s, &pg_src_s, label, 1_704_110_400, &transform).expect("backup");

        // Repo files carry the .gz suffix.
        for (rel, _) in FILES {
            assert!(
                repo_dir.path().join(format!("backup/{stanza}/{label}/{rel}.gz")).exists(),
                "expected compressed repo file {rel}.gz"
            );
        }

        // Restore reads the transform from backup.info — no compress options needed.
        let outcome = restore_inner(&restore_cfg(stanza, Vec::new()), &repo_s, &pg_dst_s).expect("restore");
        assert_eq!(outcome.label, label);
        assert_eq!(outcome.files_restored, FILES.len());

        // Restored files match the originals byte-for-byte.
        for (rel, bytes) in FILES {
            let restored = {
                let mut r = pg_dst_s.open_read(Path::new(rel)).expect("open restored");
                r.read_all().expect("read restored")
            };
            assert_eq!(restored.as_slice(), *bytes, "round trip mismatch for {rel}");
        }
    }

    #[test]
    fn backup_then_restore_gz_cipher_round_trip() {
        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_dst = tempfile::tempdir().unwrap();
        let repo_s = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());
        let pg_dst_s = Posix::new(pg_dst.path());

        let stanza = "demo";
        let label = "20240101-120000F";
        init_stanza(&repo_s, stanza);
        for (rel, bytes) in FILES {
            seed_pg_file(&pg_src_s, rel, bytes);
        }

        // zst + AES-256-CBC.
        let transform = RepoTransform {
            compress_type: CompressType::Zst,
            compress_level: 3,
            cipher_pass: Some("backup-secret".to_owned()),
        };
        backup_inner(stanza, &repo_s, &pg_src_s, label, 1_704_110_400, &transform).expect("backup");

        for (rel, bytes) in FILES {
            let repo_path = repo_dir.path().join(format!("backup/{stanza}/{label}/{rel}.zst"));
            assert!(repo_path.exists(), "expected encrypted+compressed repo file {rel}.zst");
            let repo_bytes = std::fs::read(&repo_path).unwrap();
            assert_ne!(
                repo_bytes.as_slice(),
                *bytes,
                "repo bytes for {rel} must NOT equal the plaintext"
            );
            // Encrypted output carries the OpenSSL Salted__ header.
            assert!(
                repo_bytes.starts_with(b"Salted__"),
                "encrypted repo file must be Salted__-framed"
            );
        }

        // Restore must supply the cipher password (not stored in the repo); the
        // compress-type comes from the recorded metadata.
        let cfg = restore_cfg(
            stanza,
            vec![(("cipher-pass", None), OptionValue::String("backup-secret".to_owned()))],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_dst_s).expect("restore");
        assert_eq!(outcome.files_restored, FILES.len());

        for (rel, bytes) in FILES {
            let restored = {
                let mut r = pg_dst_s.open_read(Path::new(rel)).expect("open restored");
                r.read_all().expect("read restored")
            };
            assert_eq!(restored.as_slice(), *bytes, "round trip mismatch for {rel}");
        }
    }

    #[test]
    fn backup_then_restore_none_raw_round_trip() {
        // The no-regression path: identity transform, no suffix, repo files
        // byte-identical to source, restore recovers them verbatim.
        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_dst = tempfile::tempdir().unwrap();
        let repo_s = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());
        let pg_dst_s = Posix::new(pg_dst.path());

        let stanza = "demo";
        let label = "20240101-120000F";
        init_stanza(&repo_s, stanza);
        for (rel, bytes) in FILES {
            seed_pg_file(&pg_src_s, rel, bytes);
        }

        backup_inner(stanza, &repo_s, &pg_src_s, label, 1_704_110_400, &RepoTransform::identity()).expect("backup");

        for (rel, bytes) in FILES {
            let repo_path = repo_dir.path().join(format!("backup/{stanza}/{label}/{rel}"));
            assert!(repo_path.exists(), "raw repo file {rel} must keep its name");
            assert_eq!(
                std::fs::read(&repo_path).unwrap().as_slice(),
                *bytes,
                "raw repo bytes for {rel}"
            );
        }

        let outcome = restore_inner(&restore_cfg(stanza, Vec::new()), &repo_s, &pg_dst_s).expect("restore");
        assert_eq!(outcome.files_restored, FILES.len());
        for (rel, bytes) in FILES {
            let restored = {
                let mut r = pg_dst_s.open_read(Path::new(rel)).expect("open restored");
                r.read_all().expect("read restored")
            };
            assert_eq!(restored.as_slice(), *bytes, "round trip mismatch for {rel}");
        }
    }

    #[test]
    fn backup_then_diff_then_restore_round_trip() {
        // END TO END: full backup, modify one file, diff backup (which
        // references the unchanged files from the full), then restore the DIFF
        // into a fresh target. Every file — referenced-from-full and
        // changed-in-diff — must be present and correct. This proves reference
        // resolution works across two backup directories.
        use crate::backup::{BackupType, backup_inner_typed};

        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_dst = tempfile::tempdir().unwrap();
        let repo_s = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());
        let pg_dst_s = Posix::new(pg_dst.path());

        let stanza = "demo";
        let full_label = "20240101-120000F";
        init_stanza(&repo_s, stanza);

        // Seed and take a full backup (gz, to exercise the transform too).
        let unchanged = b"PG_VERSION-like file unchanged across the diff";
        let original = b"original relation data 1259, original relation data 1259";
        seed_pg_file(&pg_src_s, "PG_VERSION", unchanged);
        seed_pg_file(&pg_src_s, "base/1/1259", original);

        let transform = RepoTransform {
            compress_type: CompressType::Gz,
            compress_level: 6,
            cipher_pass: None,
        };
        backup_inner_typed(
            stanza,
            &repo_s,
            &pg_src_s,
            BackupType::Full,
            Some(full_label),
            1_704_110_400,
            &transform,
        )
        .expect("full backup");

        // Modify one file; the diff should copy it and reference the unchanged one.
        let modified = b"MODIFIED relation data 1259 with completely new contents now";
        seed_pg_file(&pg_src_s, "base/1/1259", modified);

        let diff =
            backup_inner_typed(stanza, &repo_s, &pg_src_s, BackupType::Diff, None, 1_704_196_800, &transform).expect("diff backup");
        let diff_label = diff.label;
        assert_eq!(diff_label, format!("{full_label}_20240102-120000D"));

        // The unchanged file's bytes live ONLY in the full backup dir.
        assert!(
            repo_dir
                .path()
                .join(format!("backup/{stanza}/{full_label}/PG_VERSION.gz"))
                .exists(),
            "unchanged bytes must live in the full backup dir"
        );
        assert!(
            !repo_dir
                .path()
                .join(format!("backup/{stanza}/{diff_label}/PG_VERSION.gz"))
                .exists(),
            "unchanged file must not be duplicated in the diff dir"
        );

        // Restore the DIFF into a fresh target. No options needed: each file's
        // transform is read from its source backup's recorded metadata.
        let outcome = restore_inner(
            &restore_cfg(stanza, vec![(("set", None), OptionValue::String(diff_label.clone()))]),
            &repo_s,
            &pg_dst_s,
        )
        .expect("restore diff");
        assert_eq!(outcome.label, diff_label);
        assert_eq!(outcome.files_restored, 2, "both files must be restored");

        // The referenced (from-full) file restores to its full-backup contents.
        let restored_unchanged = {
            let mut r = pg_dst_s.open_read(Path::new("PG_VERSION")).expect("open restored PG_VERSION");
            r.read_all().expect("read restored PG_VERSION")
        };
        assert_eq!(
            restored_unchanged.as_slice(),
            unchanged,
            "referenced file must match the full backup"
        );

        // The changed (in-diff) file restores to its modified contents.
        let restored_changed = {
            let mut r = pg_dst_s.open_read(Path::new("base/1/1259")).expect("open restored 1259");
            r.read_all().expect("read restored 1259")
        };
        assert_eq!(
            restored_changed.as_slice(),
            modified,
            "changed file must match the diff backup"
        );
    }
}
