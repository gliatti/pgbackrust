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
//! removed (counted in [`RestoreOutcome::files_removed`]). Empty directories are
//! left alone — directory reconciliation is still deferred.
//!
//! # Symlink re-creation
//!
//! Every `[target:link]` entry is re-created as a real symlink in the PG target
//! pointing at its recorded destination, via [`pgbr_storage::Storage::create_symlink`].
//! On the [`pgbr_storage::Posix`] backend this is a `std::os::unix::fs::symlink`;
//! backends that do not support symlinks return the trait's default
//! "unsupported" error and the link is counted in [`RestoreOutcome::skipped_links`]
//! instead. Successful re-creations are counted in [`RestoreOutcome::links_created`].
//!
//! # Recovery configuration
//!
//! After the file copy, restore writes the version-appropriate recovery
//! configuration so `PostgreSQL` knows how to fetch WAL and where to stop. The
//! split is keyed on the manifest's `db_version`:
//!
//! - **PG < 12** — a `recovery.conf` is written into the PG data dir.
//! - **PG >= 12** — the recovery block is appended to `postgresql.auto.conf`
//!   (existing contents preserved) and a `recovery.signal` file is created
//!   (or `standby.signal` for `--type=standby`).
//!
//! The block always contains the `restore_command` `PostgreSQL` runs to fetch an
//! archived WAL segment, plus the resolved recovery-target type: `--type=immediate`
//! adds `recovery_target = 'immediate'`; `--type=standby` adds `standby_mode = 'on'`
//! on PG < 12 (PG >= 12 relies on the `standby.signal` file); `--type=time|name|lsn|xid`
//! emit `recovery_target_<type> = '<--target value>'` (with `recovery_target_inclusive
//! = 'false'` when `--target-exclusive` is set for time/lsn/xid); `--type=default`
//! (or unset) writes only the `restore_command`. `--type=none` writes no recovery
//! files at all. The generator is the pure [`recovery_files`] function so it is
//! unit-testable without any storage.
//!
//! # Deferred to later commits
//!
//! - tablespace remapping (`--tablespace-map` / `--tablespace-map-all`),
//! - `--db-include` / `--db-exclude` selective database restore,
//! - `--type=preserve` (leave any existing recovery file untouched) and the full
//!   `--recovery-option` passthrough — only the target-type-derived settings are
//!   generated here,
//! - `--target-action` / `--target-timeline` recovery settings.
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
    /// Number of `[target:link]` symlinks re-created in the PG target.
    pub links_created: usize,
    /// Number of `[target:link]` entries skipped because the backend does not
    /// support symlinks (or the link could not be created).
    pub skipped_links: usize,
    /// Relative paths of the recovery files written after the copy pass
    /// (e.g. `recovery.conf`, or `postgresql.auto.conf` + `recovery.signal`).
    /// Empty when `--type=none`.
    pub recovery_files_written: Vec<String>,
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

/// First `PostgreSQL` major version that drives recovery via GUCs in
/// `postgresql.auto.conf` + a `recovery.signal` file, rather than the standalone
/// `recovery.conf` of earlier versions. Mirrors C's `PG_VERSION_RECOVERY_GUC`.
const PG_VERSION_RECOVERY_GUC: u32 = 12;

/// The resolved `--type` (recovery target type) for a restore. Mirrors C's
/// `CFGOPTVAL_RESTORE_TYPE_*`. Only the variants this slice acts on are modelled;
/// `preserve` is treated like `default` here (its leave-existing-file behaviour is
/// deferred — see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryType {
    /// No recovery file is written at all.
    None,
    /// Recover immediately (consistency point), no target.
    Immediate,
    /// Bring the cluster up as a hot standby.
    Standby,
    /// A `recovery_target_<kind>` setting (`time` / `name` / `lsn` / `xid`).
    Target(TargetKind),
    /// Default recovery (recover to the end of the WAL): only `restore_command`.
    Default,
}

/// The kind of point-in-time target carried by `--type` when it names one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Time,
    Name,
    Lsn,
    Xid,
}

impl TargetKind {
    /// The `recovery_target_<kind>` GUC suffix `PostgreSQL` expects.
    const fn guc_suffix(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::Name => "name",
            Self::Lsn => "lsn",
            Self::Xid => "xid",
        }
    }

    /// Whether `recovery_target_inclusive` is meaningful for this kind. `PostgreSQL`
    /// accepts it for time / lsn / xid but not for name (matches the C generator,
    /// whose `target-exclusive` option only depends on those three).
    const fn supports_inclusive(self) -> bool {
        matches!(self, Self::Time | Self::Lsn | Self::Xid)
    }
}

/// Read the `--type` option as a [`RecoveryType`]. Absent or an unrecognised value
/// resolves to [`RecoveryType::Default`], matching the option's `default: default`.
fn recovery_type(config: &LoadedConfig) -> RecoveryType {
    let raw = match config.options.get(&("type".to_owned(), None)) {
        Some(OptionValue::StringId(value) | OptionValue::String(value)) => value.as_str(),
        _ => "default",
    };
    match raw {
        "none" => RecoveryType::None,
        "immediate" => RecoveryType::Immediate,
        "standby" => RecoveryType::Standby,
        "time" => RecoveryType::Target(TargetKind::Time),
        "name" => RecoveryType::Target(TargetKind::Name),
        "lsn" => RecoveryType::Target(TargetKind::Lsn),
        "xid" => RecoveryType::Target(TargetKind::Xid),
        // `default`, `preserve`, or anything else: end-of-WAL recovery.
        _ => RecoveryType::Default,
    }
}

/// Read a plain string option, preferring `--target` for the `time`/`name`/`lsn`/`xid`
/// target value.
fn string_option<'a>(config: &'a LoadedConfig, name: &str) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::String(value) | OptionValue::StringId(value) | OptionValue::Path(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Whether `--target-exclusive` was supplied and set to `true`.
fn target_exclusive(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("target-exclusive".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// The `restore_command` `PostgreSQL` runs to fetch one archived WAL segment.
/// `%f` is the segment name `PostgreSQL` substitutes and `"%p"` the destination
/// path. Mirrors the C generator's
/// `<exe> archive-get %f "%p"` shape, reduced here to the binary name + stanza.
fn restore_command(stanza: &str) -> String {
    format!("pgbackrest --stanza={stanza} archive-get %f \"%p\"")
}

/// Render the recovery settings block (a `key = 'value'` line per setting) for the
/// given PG major version and resolved recovery type. The leading header line
/// identifies the restore. Always emits `restore_command`; the recovery-target
/// lines depend on the type. Returns an empty string for [`RecoveryType::None`]
/// (callers should not write any recovery file in that case).
fn recovery_block(db_major: u32, stanza: &str, ty: RecoveryType, target: Option<&str>, exclusive: bool) -> String {
    use std::fmt::Write as _;

    if ty == RecoveryType::None {
        return String::new();
    }

    let mut out = String::from("# Recovery settings generated by pgBackRest restore\n");
    // `write!` into a `String` is infallible.
    let _ = writeln!(out, "restore_command = '{}'", restore_command(stanza));

    match ty {
        RecoveryType::Immediate => out.push_str("recovery_target = 'immediate'\n"),
        RecoveryType::Standby => {
            // standby_mode is only a GUC on PG < 12; on >= 12 the standby.signal
            // file (written by the caller) drives standby mode instead.
            if db_major < PG_VERSION_RECOVERY_GUC {
                out.push_str("standby_mode = 'on'\n");
            }
        }
        RecoveryType::Target(kind) => {
            if let Some(value) = target {
                let _ = writeln!(out, "recovery_target_{} = '{value}'", kind.guc_suffix());
                if exclusive && kind.supports_inclusive() {
                    out.push_str("recovery_target_inclusive = 'false'\n");
                }
            }
        }
        // Default writes only restore_command; None returned early above.
        RecoveryType::Default | RecoveryType::None => {}
    }

    out
}

/// Parse the manifest's textual `db_version` (e.g. `"14"`, `"9.6"`) into a major
/// version number used for the PG < 12 vs >= 12 recovery split. `"9.6"` -> `9`
/// (pre-10 versions are all < 12), everything else takes the integer prefix.
/// Unparsable input is treated as `>= 12` (modern default).
fn db_major_version(db_version: &str) -> u32 {
    let prefix: String = db_version.chars().take_while(char::is_ascii_digit).collect();
    prefix.parse::<u32>().unwrap_or(PG_VERSION_RECOVERY_GUC)
}

/// Pure generator for the recovery files a restore must write, given the backed-up
/// cluster's `db_version` and the resolved recovery options. Returns `(relative
/// path, contents)` pairs to write into the PG data dir, in write order.
///
/// - **PG < 12** -> `[("recovery.conf", <block>)]`.
/// - **PG >= 12** -> `[("postgresql.auto.conf", <block>), (<signal>, "")]` where
///   `<signal>` is `standby.signal` for `--type=standby`, else `recovery.signal`.
///   The `postgresql.auto.conf` entry holds *only the new block*; the caller is
///   responsible for appending it to any existing file contents.
/// - **`--type=none`** -> `[]` (no recovery files).
fn recovery_files(db_version: &str, stanza: &str, config: &LoadedConfig) -> Vec<(PathBuf, String)> {
    let ty = recovery_type(config);
    if ty == RecoveryType::None {
        return Vec::new();
    }

    let db_major = db_major_version(db_version);
    let target = string_option(config, "target");
    let exclusive = target_exclusive(config);
    let block = recovery_block(db_major, stanza, ty, target, exclusive);

    if db_major < PG_VERSION_RECOVERY_GUC {
        vec![(PathBuf::from("recovery.conf"), block)]
    } else {
        let signal = if ty == RecoveryType::Standby {
            "standby.signal"
        } else {
            "recovery.signal"
        };
        vec![
            (PathBuf::from("postgresql.auto.conf"), block),
            (PathBuf::from(signal), String::new()),
        ]
    }
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

    // 4. Re-create every `[target:link]` symlink in the PG target. A backend that
    //    cannot create symlinks (the trait default) leaves the link uncreated and
    //    counted in `skipped_links` instead.
    let mut links_created = 0;
    let mut skipped_links = 0;
    for link in &manifest.links {
        let link_path = PathBuf::from(&link.path);
        // Defensively create the link's parent directory (paths are created up
        // front, but a link could sit in an unlisted path).
        if let Some(parent) = link_path.parent()
            && !parent.as_os_str().is_empty()
        {
            pg.create_path(parent, true)?;
        }
        match pg.create_symlink(&link_path, Path::new(&link.destination)) {
            Ok(()) => links_created += 1,
            Err(_) => skipped_links += 1,
        }
    }

    // 5. Write the version-appropriate recovery configuration. The pure
    //    `recovery_files` generator decides which files and contents apply; the
    //    only impure step is appending the block to any existing
    //    `postgresql.auto.conf`.
    let recovery_files_written = write_recovery_files(pg, &manifest.db_version, stanza, config)?;

    Ok(RestoreOutcome {
        label,
        files_restored,
        files_skipped,
        files_removed,
        paths_created,
        links_created,
        skipped_links,
        recovery_files_written,
    })
}

/// Write the recovery files produced by [`recovery_files`] into the PG target,
/// returning the relative paths written. `postgresql.auto.conf` is *appended* to
/// (existing contents preserved); every other file is written verbatim.
fn write_recovery_files(
    pg: &dyn Storage,
    db_version: &str,
    stanza: &str,
    config: &LoadedConfig,
) -> Result<Vec<String>, CommandError> {
    let mut written = Vec::new();

    for (rel, block) in recovery_files(db_version, stanza, config) {
        let contents = if rel == Path::new("postgresql.auto.conf") {
            append_to_existing(pg, &rel, &block)?
        } else {
            block.into_bytes()
        };

        let mut writer = pg.open_write(&rel)?;
        writer.write(&contents)?;
        writer.flush()?;
        writer.close()?;
        written.push(rel.to_string_lossy().into_owned());
    }

    Ok(written)
}

/// Build the new contents of `postgresql.auto.conf`: any existing file's bytes
/// (with a trailing newline ensured) followed by the recovery `block`. A missing
/// file is treated as empty so the block is written on its own.
fn append_to_existing(pg: &dyn Storage, rel: &Path, block: &str) -> Result<Vec<u8>, CommandError> {
    let mut existing = match pg.open_read(rel) {
        Ok(mut reader) => reader.read_all()?,
        Err(StorageError::NotFound { .. }) => Vec::new(),
        Err(err) => return Err(CommandError::Storage(err)),
    };

    // Separate old and new settings with a blank line, mirroring the C generator.
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        existing.push(b'\n');
    }
    if !existing.is_empty() {
        existing.push(b'\n');
    }
    existing.extend_from_slice(block.as_bytes());
    Ok(existing)
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
        "restore: backup {} — {} file(s) restored, {} skipped, {} removed, {} path(s) created, {} link(s) created, \
         {} link(s) skipped, {} recovery file(s) written",
        outcome.label,
        outcome.files_restored,
        outcome.files_skipped,
        outcome.files_removed,
        outcome.paths_created,
        outcome.links_created,
        outcome.skipped_links,
        outcome.recovery_files_written.len(),
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
        seed_backup_ver(repo, stanza, label, "14", files, paths, links);
    }

    /// Like [`seed_backup`] but records `db_version` in the manifest, so recovery
    /// tests can drive the PG-version-dependent split.
    fn seed_backup_ver(
        repo: &Posix,
        stanza: &str,
        label: &str,
        db_version: &str,
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
            db_version: db_version.to_owned(),
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
    fn restore_creates_symlinks() {
        // A backup with one symlink: the Posix backend re-creates it pointing at
        // the recorded destination, counted in `links_created`.
        let (_repo, pg, repo_s, pg_s) = posix_pair();
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
        assert_eq!(outcome.links_created, 1, "Posix must re-create the symlink");
        assert_eq!(outcome.skipped_links, 0);

        // The symlink exists in the target and points at the recorded destination.
        let read = std::fs::read_link(pg.path().join("pg_data/pg_wal")).expect("read_link");
        assert_eq!(read, Path::new("/var/lib/pg_wal"), "symlink must point at the destination");
    }

    // ---- recovery config generation ----------------------------------------

    /// A restore config carrying `--type` (and, optionally, `--target`).
    fn cfg_recovery(stanza: &str, ty: Option<&str>, target: Option<&str>, target_exclusive: bool) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(ty) = ty {
            options.insert(("type".to_owned(), None), OptionValue::StringId(ty.to_owned()));
        }
        if let Some(target) = target {
            options.insert(("target".to_owned(), None), OptionValue::String(target.to_owned()));
        }
        if target_exclusive {
            options.insert(("target-exclusive".to_owned(), None), OptionValue::Boolean(true));
        }
        LoadedConfig {
            command: "restore".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn restore_recovery_conf_for_pg11() {
        // PG < 12: a recovery.conf is written with the restore_command line.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "11", &[], &["pg_data"], &[]);

        let outcome = restore_inner(&cfg_recovery(stanza, None, None, false), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.recovery_files_written, vec!["recovery.conf".to_owned()]);

        let contents = {
            let mut r = pg_s.open_read(Path::new("recovery.conf")).expect("open recovery.conf");
            String::from_utf8(r.read_all().expect("read recovery.conf")).unwrap()
        };
        assert!(
            contents.contains("restore_command = 'pgbackrest --stanza=demo archive-get %f \"%p\"'"),
            "recovery.conf must contain restore_command: {contents}"
        );
        assert!(
            !pg_s.exists(Path::new("recovery.signal")).unwrap(),
            "PG<12 must not write recovery.signal"
        );
    }

    #[test]
    fn restore_signal_file_for_pg14() {
        // PG >= 12: postgresql.auto.conf gets the recovery block APPENDED and
        // recovery.signal is created.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        // Pre-seed an existing postgresql.auto.conf so we can prove the block is appended.
        seed_pg_file(
            &pg_s,
            "postgresql.auto.conf",
            b"# existing setting\nshared_buffers = '128MB'\n",
        );

        let outcome = restore_inner(&cfg_recovery(stanza, None, None, false), &repo_s, &pg_s).expect("restore");
        assert_eq!(
            outcome.recovery_files_written,
            vec!["postgresql.auto.conf".to_owned(), "recovery.signal".to_owned()]
        );

        let contents = {
            let mut r = pg_s.open_read(Path::new("postgresql.auto.conf")).expect("open auto.conf");
            String::from_utf8(r.read_all().expect("read auto.conf")).unwrap()
        };
        assert!(
            contents.starts_with("# existing setting\nshared_buffers = '128MB'\n"),
            "existing contents must be preserved: {contents}"
        );
        assert!(
            contents.contains("restore_command = 'pgbackrest --stanza=demo archive-get %f \"%p\"'"),
            "recovery block must be appended: {contents}"
        );
        assert!(
            pg_s.exists(Path::new("recovery.signal")).unwrap(),
            "PG>=12 must write recovery.signal"
        );
        assert!(
            !pg_s.exists(Path::new("standby.signal")).unwrap(),
            "non-standby restore must not write standby.signal"
        );
        assert!(
            !pg_s.exists(Path::new("recovery.conf")).unwrap(),
            "PG>=12 must not write recovery.conf"
        );
    }

    #[test]
    fn restore_standby_writes_standby_signal() {
        // --type=standby on PG >= 12: standby.signal instead of recovery.signal.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        let outcome = restore_inner(&cfg_recovery(stanza, Some("standby"), None, false), &repo_s, &pg_s).expect("restore");
        assert_eq!(
            outcome.recovery_files_written,
            vec!["postgresql.auto.conf".to_owned(), "standby.signal".to_owned()]
        );
        assert!(
            pg_s.exists(Path::new("standby.signal")).unwrap(),
            "standby restore must write standby.signal"
        );
        assert!(
            !pg_s.exists(Path::new("recovery.signal")).unwrap(),
            "standby restore must not write recovery.signal"
        );
        // standby_mode is NOT a GUC on PG >= 12; the block carries only restore_command.
        let contents = {
            let mut r = pg_s.open_read(Path::new("postgresql.auto.conf")).expect("open auto.conf");
            String::from_utf8(r.read_all().expect("read auto.conf")).unwrap()
        };
        assert!(
            !contents.contains("standby_mode"),
            "PG>=12 standby must not write standby_mode: {contents}"
        );
    }

    #[test]
    fn restore_type_none_writes_no_recovery_files() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        let outcome = restore_inner(&cfg_recovery(stanza, Some("none"), None, false), &repo_s, &pg_s).expect("restore");
        assert!(
            outcome.recovery_files_written.is_empty(),
            "type=none writes no recovery files"
        );
        assert!(!pg_s.exists(Path::new("recovery.signal")).unwrap());
        assert!(!pg_s.exists(Path::new("postgresql.auto.conf")).unwrap());
    }

    #[test]
    fn recovery_files_pure_fn() {
        let stanza = "demo";

        // PG < 12 -> recovery.conf only.
        let cfg11 = cfg_recovery(stanza, None, None, false);
        let pg11 = super::recovery_files("11", stanza, &cfg11);
        assert_eq!(pg11.len(), 1);
        assert_eq!(pg11[0].0, std::path::PathBuf::from("recovery.conf"));
        assert!(
            pg11[0]
                .1
                .contains("restore_command = 'pgbackrest --stanza=demo archive-get %f \"%p\"'")
        );

        // 9.6 -> still treated as < 12.
        let pg96 = super::recovery_files("9.6", stanza, &cfg11);
        assert_eq!(pg96[0].0, std::path::PathBuf::from("recovery.conf"));

        // PG >= 12 default -> postgresql.auto.conf + recovery.signal.
        let cfg14 = cfg_recovery(stanza, None, None, false);
        let pg14 = super::recovery_files("14", stanza, &cfg14);
        assert_eq!(pg14.len(), 2);
        assert_eq!(pg14[0].0, std::path::PathBuf::from("postgresql.auto.conf"));
        assert_eq!(pg14[1].0, std::path::PathBuf::from("recovery.signal"));

        // PG >= 12 standby -> standby.signal.
        let cfg_sb = cfg_recovery(stanza, Some("standby"), None, false);
        let sb = super::recovery_files("14", stanza, &cfg_sb);
        assert_eq!(sb[1].0, std::path::PathBuf::from("standby.signal"));

        // immediate -> recovery_target = 'immediate'.
        let cfg_imm = cfg_recovery(stanza, Some("immediate"), None, false);
        let imm = super::recovery_files("14", stanza, &cfg_imm);
        assert!(imm[0].1.contains("recovery_target = 'immediate'"));

        // time target with --target-exclusive -> recovery_target_time + inclusive=false.
        let cfg_time = cfg_recovery(stanza, Some("time"), Some("2024-01-01 12:00:00"), true);
        let timev = super::recovery_files("11", stanza, &cfg_time);
        assert!(timev[0].1.contains("recovery_target_time = '2024-01-01 12:00:00'"));
        assert!(timev[0].1.contains("recovery_target_inclusive = 'false'"));

        // name target: no inclusive line even with --target-exclusive.
        let cfg_name = cfg_recovery(stanza, Some("name"), Some("my_restore_point"), true);
        let namev = super::recovery_files("11", stanza, &cfg_name);
        assert!(namev[0].1.contains("recovery_target_name = 'my_restore_point'"));
        assert!(!namev[0].1.contains("recovery_target_inclusive"));

        // standby on PG < 12 -> standby_mode = 'on'.
        let pg11_sb = super::recovery_files("11", stanza, &cfg_sb);
        assert!(pg11_sb[0].1.contains("standby_mode = 'on'"));

        // none -> nothing.
        let cfg_none = cfg_recovery(stanza, Some("none"), None, false);
        assert!(super::recovery_files("14", stanza, &cfg_none).is_empty());
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

    #[test]
    fn backup_full_diff_incr_then_restore_incr() {
        // END TO END: full -> modify -> diff -> modify -> incr, then restore the
        // INCR into a fresh target. Three files exercise all three holders:
        //   - file a: never changes after the full   -> bytes live in the FULL
        //   - file b: last changed in the diff        -> bytes live in the DIFF
        //   - file c: changed for the incr            -> bytes live in the INCR
        // Restore of the incr follows each file's single recorded reference; the
        // incr must have resolved file b's reference to the diff (its physical
        // holder) at backup time, so no multi-hop chain walking is needed.
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

        // gz transform throughout, so reference restore must also reverse the
        // referenced backup's recorded transform.
        let transform = RepoTransform {
            compress_type: CompressType::Gz,
            compress_level: 6,
            cipher_pass: None,
        };

        let a = b"file a content that never changes after the full backup";
        let b_v1 = b"file b version one, present in the full backup only-ish";
        let c_v1 = b"file c version one, present in the full backup";
        seed_pg_file(&pg_src_s, "base/1/a", a);
        seed_pg_file(&pg_src_s, "base/1/b", b_v1);
        seed_pg_file(&pg_src_s, "base/1/c", c_v1);

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

        // Modify b; diff (prior = full).
        let b_v2 = b"file b version TWO, changed only for the differential backup";
        seed_pg_file(&pg_src_s, "base/1/b", b_v2);
        let diff =
            backup_inner_typed(stanza, &repo_s, &pg_src_s, BackupType::Diff, None, 1_704_196_800, &transform).expect("diff backup");
        let diff_label = diff.label;

        // Modify c; incr (prior = diff).
        let c_v2 = b"file c version TWO, changed only for the incremental backup";
        seed_pg_file(&pg_src_s, "base/1/c", c_v2);
        let incr =
            backup_inner_typed(stanza, &repo_s, &pg_src_s, BackupType::Incr, None, 1_704_283_200, &transform).expect("incr backup");
        let incr_label = incr.label;
        assert_eq!(incr_label, format!("{full_label}_20240103-120000I"));

        // The incr manifest must reference file b directly at the DIFF (its
        // physical holder) — not at the full — so restore needs only one hop.
        let incr_manifest = Manifest::load(&repo_s, &super::manifest_path(stanza, &incr_label)).expect("load incr manifest");
        assert_eq!(
            incr_manifest.file("base/1/a").and_then(|f| f.reference.as_deref()),
            Some(full_label),
            "file a must reference the full"
        );
        assert_eq!(
            incr_manifest.file("base/1/b").and_then(|f| f.reference.as_deref()),
            Some(diff_label.as_str()),
            "file b must reference the diff (its physical holder), not the full"
        );

        // Physical-holder invariants: only the changed file's bytes live in the
        // incr dir; a's bytes live in the full, b's bytes live in the diff.
        assert!(
            repo_dir
                .path()
                .join(format!("backup/{stanza}/{incr_label}/base/1/c.gz"))
                .exists(),
            "incr-changed file must live in the incr dir"
        );
        assert!(
            !repo_dir
                .path()
                .join(format!("backup/{stanza}/{incr_label}/base/1/a.gz"))
                .exists(),
            "full-held file must not be duplicated into the incr dir"
        );
        assert!(
            !repo_dir
                .path()
                .join(format!("backup/{stanza}/{incr_label}/base/1/b.gz"))
                .exists(),
            "diff-held file must not be duplicated into the incr dir"
        );

        // Restore the INCR into a fresh target. No options needed: each file's
        // transform is read from its source backup's recorded metadata.
        let outcome = restore_inner(
            &restore_cfg(stanza, vec![(("set", None), OptionValue::String(incr_label.clone()))]),
            &repo_s,
            &pg_dst_s,
        )
        .expect("restore incr");
        assert_eq!(outcome.label, incr_label);
        assert_eq!(outcome.files_restored, 3, "all three files must be restored");

        // Every file present and correct, sourced from whichever backup holds it.
        for (rel, expected) in [
            ("base/1/a", a.as_slice()),
            ("base/1/b", b_v2.as_slice()),
            ("base/1/c", c_v2.as_slice()),
        ] {
            let restored = {
                let mut r = pg_dst_s.open_read(Path::new(rel)).expect("open restored file");
                r.read_all().expect("read restored file")
            };
            assert_eq!(restored.as_slice(), expected, "incr restore mismatch for {rel}");
        }
    }
}
