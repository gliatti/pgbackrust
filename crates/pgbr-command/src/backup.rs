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
//! # Differential and incremental backups (`--type=diff` / `--type=incr`)
//!
//! A differential or incremental backup captures only the files that changed
//! since a *prior* backup; files that are unchanged are recorded with a
//! *reference* to the backup that physically holds their bytes instead of being
//! re-copied. [`backup_inner_typed`] drives all three paths:
//!
//! - `full` — every non-excluded file is copied, every [`ManifestFile`] carries
//!   `reference: None`. Identical to the prior behaviour.
//! - `diff` — the latest **full** backup is located in `backup.info`, its
//!   manifest loaded, and each current PG file compared (size + plaintext SHA-1)
//!   against the full's entry. An unchanged file is recorded with
//!   `reference: Some(<full label>)` and **not** copied into the diff dir; a
//!   changed or new file is copied as usual with `reference: None`. The diff's
//!   label is `<full label>_<YYYYMMDD-HHMMSS>D` and its `backup.info` entry
//!   records `backup-type: "diff"` plus `backup-reference: [<full label>]`.
//! - `incr` — like `diff` but the *prior* backup is the latest backup of **any**
//!   type (full / diff / incr), not just the latest full. Each current PG file is
//!   compared against the prior's manifest entry; an unchanged file is recorded
//!   with a reference to the backup that **physically holds** the bytes — which
//!   may be the prior itself or, when the prior's own entry is a reference, the
//!   backup the prior points at (the reference chain is resolved to its physical
//!   holder at backup time). Because the recorded reference already names the
//!   physical holder, restore — which follows each file's `reference` exactly
//!   once — reconstructs an incr without walking a multi-hop chain. The incr's
//!   label is anchored to the **full at the root of its chain**:
//!   `<full root>_<YYYYMMDD-HHMMSS>I`, where the full root is the prior label's
//!   first segment (everything before the first `_`). Its `backup.info` entry
//!   records `backup-type: "incr"` plus `backup-reference: [<prior label>]`.
//!
//! Deliberately out of scope for this slice (follow-ups):
//!
//! - **Symlink target resolution.** The `Storage` trait has no link-target
//!   accessor yet, so [`ManifestLink`] entries are recorded with an empty
//!   `destination`. See the `// TODO: resolve link target` note in [`walk`].
//!
//! The real work lives in [`backup_inner_typed`], which takes the backup type,
//! label, and start timestamp as parameters so tests can pin them;
//! [`backup_inner`] is a thin full-backup wrapper, and the public [`backup`]
//! entry point derives the type from the resolved options and the timestamp
//! from [`SystemTime::now`].

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath};
use pgbr_io::{Filter, Sha1};
use pgbr_storage::{Storage, StorageInfo, StorageKind};
use serde_json::json;

use crate::CommandError;
use crate::pipeline::{RepoTransform, metadata_compress_type_key, metadata_encrypted_key};

/// Backup type recorded for a full backup.
const BACKUP_TYPE_FULL: &str = "full";
/// Backup type recorded for a differential backup.
const BACKUP_TYPE_DIFF: &str = "diff";
/// Backup type recorded for an incremental backup.
const BACKUP_TYPE_INCR: &str = "incr";

/// Which kind of backup [`backup_inner_typed`] should produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupType {
    /// A full backup: every file is copied.
    Full,
    /// A differential backup against the latest full: unchanged files are
    /// referenced rather than re-copied.
    Diff,
    /// An incremental backup against the latest backup of any type: unchanged
    /// files are referenced (resolved to their physical holder) rather than
    /// re-copied.
    Incr,
}

impl BackupType {
    /// The `backup-type` string recorded in `backup.info` / `backup.manifest`.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Full => BACKUP_TYPE_FULL,
            Self::Diff => BACKUP_TYPE_DIFF,
            Self::Incr => BACKUP_TYPE_INCR,
        }
    }

    /// Map the resolved `--type` option (`StringId`) to a [`BackupType`].
    ///
    /// Defaults to [`BackupType::Full`] when the option is absent. `diff` maps to
    /// [`BackupType::Diff`], `incr` to [`BackupType::Incr`]; anything else
    /// (including an unrecognised value) maps to [`BackupType::Full`].
    fn from_options(config: &LoadedConfig) -> Self {
        match config.options.get(&("type".to_owned(), None)) {
            Some(OptionValue::StringId(value)) if value == BACKUP_TYPE_DIFF => Self::Diff,
            Some(OptionValue::StringId(value)) if value == BACKUP_TYPE_INCR => Self::Incr,
            _ => Self::Full,
        }
    }
}

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
    let backup_type = BackupType::from_options(config);
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let timestamp_start = i64::try_from(secs).unwrap_or(i64::MAX);
    let transform = RepoTransform::from_options(config);

    // The diff label depends on the full it references, so it is computed inside
    // `backup_inner_typed` (which knows the full label); full labels are
    // timestamp-derived up front. Pass `None` to let the inner function pick.
    let outcome = backup_inner_typed(
        stanza,
        repo_storage,
        pg_storage,
        backup_type,
        None,
        timestamp_start,
        &transform,
    )?;
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

/// Format a differential-backup label from the referenced full's label and the
/// diff's start timestamp: `<full label>_<YYYYMMDD-HHMMSS>D`.
fn diff_backup_label(full_label: &str, timestamp: i64) -> String {
    let (year, month, day, hour, minute, second) = unix_to_civil(timestamp);
    format!("{full_label}_{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}D")
}

/// Format an incremental-backup label from the chain's full root and the incr's
/// start timestamp: `<full root>_<YYYYMMDD-HHMMSS>I`.
fn incr_backup_label(full_root: &str, timestamp: i64) -> String {
    let (year, month, day, hour, minute, second) = unix_to_civil(timestamp);
    format!("{full_root}_{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}I")
}

/// The full backup at the root of a chain, given any backup label.
///
/// pgBackRest anchors every diff/incr label to its chain's full: the full's
/// label is the first `_`-separated segment (`<YYYYMMDD-HHMMSS>F`). A full label
/// has no `_`, so it is its own root.
fn full_root_label(label: &str) -> &str {
    label.split_once('_').map_or(label, |(root, _)| root)
}

/// Derive the label for a backup from its type and the prior backup it
/// references. `prior_label` is `Some` whenever `backup_type` is
/// [`BackupType::Diff`] (the latest full) or [`BackupType::Incr`] (the latest
/// backup of any type); the caller resolves it before calling.
fn derive_label(backup_type: BackupType, prior_label: Option<&str>, timestamp: i64) -> String {
    match backup_type {
        BackupType::Full => full_backup_label(timestamp),
        BackupType::Diff => diff_backup_label(prior_label.unwrap_or_default(), timestamp),
        BackupType::Incr => incr_backup_label(full_root_label(prior_label.unwrap_or_default()), timestamp),
    }
}

/// Outcome of capturing one file into a backup: the manifest entry plus the
/// number of bytes physically written to the repo (`0` for a referenced file).
struct CapturedFile {
    file: ManifestFile,
    repo_bytes: u64,
}

/// Capture one PG-data file into the backup, returning its [`ManifestFile`].
///
/// The plaintext SHA-1 + size are recorded regardless of how (or whether) the
/// bytes land in the repo. For a diff or incr (`prior_manifest` is `Some`), a
/// file whose size **and** checksum match the prior backup's entry is unchanged:
/// it is recorded with a reference to the backup that **physically holds** the
/// bytes and **not** copied. The physical holder is the prior backup itself when
/// the prior copied the file, or — when the prior's own entry is a reference —
/// the backup the prior points at (resolving the chain to its physical holder so
/// restore never has to chase multiple hops). Otherwise the plaintext is run
/// through `transform` and written to `<backup_root>/<rel><suffix>` with
/// `reference: None`.
fn capture_file(
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    entry: &WalkEntry,
    backup_root: &str,
    transform: &RepoTransform,
    prior_manifest: Option<&Manifest>,
    prior_label: Option<&str>,
) -> Result<CapturedFile, CommandError> {
    let src = PathBuf::from(&entry.rel);
    let mut reader = pg_storage.open_read(&src)?;
    let bytes = reader.read_all()?;

    // Checksum and size are taken over the PLAINTEXT, independent of how the
    // bytes are stored in the repo (pgBackRest semantics).
    let mut sha1 = Sha1::new();
    let mut sink = Vec::new();
    sha1.process(&bytes, &mut sink)?;
    let checksum = sha1.digest_hex();

    let base = ManifestFile {
        path: entry.rel.clone(),
        size: entry.info.size,
        timestamp: entry.info.modified.unwrap_or(0),
        checksum: Some(checksum.clone()),
        checksum_page: None,
        reference: None,
    };

    // For a diff/incr: when the prior backup holds this file unchanged (same
    // size AND checksum), record a reference to the backup that physically holds
    // the bytes and do NOT copy them. If the prior's own entry is a reference,
    // the bytes live in *that* backup, so resolve through it; otherwise the prior
    // itself holds them.
    if let Some(prior_manifest) = prior_manifest
        && let Some(prior_file) = prior_manifest.file(&entry.rel)
        && prior_file.size == entry.info.size
        && prior_file.checksum.as_deref() == Some(checksum.as_str())
    {
        let holder = prior_file.reference.clone().or_else(|| prior_label.map(ToOwned::to_owned));
        return Ok(CapturedFile {
            file: ManifestFile {
                reference: holder,
                ..base
            },
            repo_bytes: 0,
        });
    }

    // Full backup, or a changed / new file in a diff: copy it. Compress-then-
    // encrypt the plaintext into the repo bytes; the identity transform returns
    // the bytes unchanged. The repo filename carries the compression suffix;
    // encryption does not change it.
    let repo_bytes = transform.apply_forward(&bytes)?;
    let dest = PathBuf::from(format!("{backup_root}/{}{}", entry.rel, transform.repo_suffix()));
    if let Some(parent) = dest.parent() {
        repo_storage.create_path(parent, true)?;
    }
    let mut writer = repo_storage.open_write(&dest)?;
    writer.write(&repo_bytes)?;
    writer.flush()?;
    writer.close()?;

    Ok(CapturedFile {
        file: base,
        repo_bytes: repo_bytes.len() as u64,
    })
}

/// Find the label of the latest full backup recorded in `backup.info`.
///
/// "Latest" is the lexicographically-greatest label whose `backup-type` is
/// `full` — pgBackRest full labels sort chronologically. Returns `None` when no
/// full backup exists.
fn latest_full_label(info: &InfoBackup) -> Option<String> {
    info.current
        .iter()
        .rev()
        .find(|(_, entry)| entry.get("backup-type").and_then(serde_json::Value::as_str) == Some(BACKUP_TYPE_FULL))
        .map(|(label, _)| label.clone())
}

/// Find the label of the latest backup of **any** type recorded in
/// `backup.info` — the "prior" backup an incremental references.
///
/// `info.current` is a `BTreeMap` keyed by label, so its keys iterate in
/// ascending (chronological) order; the last key is the most recent backup.
/// Returns `None` when no backup exists.
fn latest_any_label(info: &InfoBackup) -> Option<String> {
    info.current.keys().next_back().cloned()
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

/// Take a **full** backup with a caller-supplied `label`.
///
/// Thin wrapper over [`backup_inner_typed`] kept for the existing call sites /
/// tests that only ever produced full backups (`timestamp_start` and
/// `transform` are forwarded unchanged).
///
/// # Errors
///
/// See [`backup_inner_typed`].
pub fn backup_inner(
    stanza: &str,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    label: &str,
    timestamp_start: i64,
    transform: &RepoTransform,
) -> Result<BackupOutcome, CommandError> {
    backup_inner_typed(
        stanza,
        repo_storage,
        pg_storage,
        BackupType::Full,
        Some(label),
        timestamp_start,
        transform,
    )
}

/// Resolve the prior backup (label + loaded manifest) a diff/incr references.
///
/// A diff's prior is the latest full backup; an incr's prior is the latest
/// backup of any type. A full backup has no prior — `(None, None)`.
///
/// # Errors
///
/// [`CommandError::Other`] if a diff has no prior full, if an incr has no prior
/// backup at all, or if the prior's `backup.manifest` cannot be loaded.
fn resolve_prior(
    repo_storage: &dyn Storage,
    stanza: &str,
    backup_type: BackupType,
    info: &InfoBackup,
) -> Result<(Option<String>, Option<Manifest>), CommandError> {
    let prior_label = match backup_type {
        BackupType::Full => return Ok((None, None)),
        BackupType::Diff => latest_full_label(info)
            .ok_or_else(|| CommandError::Other("differential backup requires a prior full backup".to_owned()))?,
        BackupType::Incr => {
            latest_any_label(info).ok_or_else(|| CommandError::Other("incremental backup requires a prior backup".to_owned()))?
        }
    };

    let prior_manifest = Manifest::load(
        repo_storage,
        &PathBuf::from(format!("backup/{stanza}/{prior_label}/backup.manifest")),
    )
    .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok((Some(prior_label), Some(prior_manifest)))
}

/// Take a backup of the given `backup_type`.
///
/// `timestamp_start` and `transform` (compression + encryption) are
/// caller-supplied. `label` pins the backup label for tests; when `None` it is
/// derived — a full backup from the timestamp (`<ts>F`), a diff from the
/// referenced full plus the timestamp (`<full>_<ts>D`), an incr from the chain's
/// full root plus the timestamp (`<full root>_<ts>I`).
///
/// Steps:
///
/// 1. Load `backup/<stanza>/backup.info` (error if the stanza is uninitialised).
/// 2. For a diff: locate the latest full backup; for an incr: locate the latest
///    backup of any type (the "prior"). Load the prior's `backup.manifest`
///    (error if no qualifying prior exists).
/// 3. Recursively walk the PG data dir via `pg_storage`, applying
///    [`EXCLUDE_PREFIXES`].
/// 4. For each non-excluded file: compute the **plaintext** SHA-1 + size
///    (recorded in the [`Manifest`]). For a diff/incr, if the prior's manifest
///    holds an entry with the same size **and** checksum, record the file with a
///    reference to the backup that physically holds the bytes (resolving the
///    prior's own reference, if any) and skip copying; otherwise (full backup, or
///    a changed / new file) run the plaintext through `transform.forward_chain()`
///    (compress then encrypt), write the transformed bytes to
///    `backup/<stanza>/<label>/<relpath><suffix>`, and record `reference: None`.
/// 5. Record directories as [`ManifestPath`] and symlinks as [`ManifestLink`]
///    (with an empty destination — see module docs).
/// 6. Save `backup.manifest`, then add a `[backup:current]` entry to
///    `backup.info` — including the applied compress-type, encrypted flag, and
///    (for a diff/incr) the `backup-reference` chain — and save it.
///
/// # Errors
///
/// - [`CommandError::Other`] if the stanza is not initialised, if a diff is
///   requested with no prior full backup, if an incr is requested with no prior
///   backup at all, or if `backup.info` / `backup.manifest` cannot be read or
///   written.
/// - [`CommandError::Io`] if a filter in the transform chain fails.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for repository / PG-data
///   read/write failures.
pub fn backup_inner_typed(
    stanza: &str,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    backup_type: BackupType,
    label: Option<&str>,
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

    // For a diff/incr, resolve the prior backup and load its manifest so
    // unchanged files can be detected by (size, checksum).
    let (prior_label, prior_manifest) = resolve_prior(repo_storage, stanza, backup_type, &info)?;

    let label = label.map_or_else(
        || derive_label(backup_type, prior_label.as_deref(), timestamp_start),
        ToOwned::to_owned,
    );

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
                let captured = capture_file(
                    repo_storage,
                    pg_storage,
                    &entry,
                    &backup_root,
                    transform,
                    prior_manifest.as_ref(),
                    prior_label.as_deref(),
                )?;
                total_size += captured.file.size;
                repo_size += captured.repo_bytes;
                files.push(captured.file);
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
        backup_label: label.clone(),
        backup_type: backup_type.as_str().to_owned(),
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

    let mut entry = json!({
        "backup-type": backup_type.as_str(),
        "backup-timestamp-start": timestamp_start,
        "backup-timestamp-stop": timestamp_stop,
        "backup-info-size": total_size,
        "backup-info-repo-size": repo_size,
        // Record the applied transform so restore can reverse it without
        // relying on the restore command's own compress/cipher options.
        metadata_compress_type_key(): transform.compress_type.as_str_id(),
        metadata_encrypted_key(): transform.is_encrypted(),
        "db-id": info.db_id,
    });
    // A diff/incr records the chain of backups its files depend on. The prior
    // backup is the head of that chain (the latest full for a diff, the latest
    // backup of any type for an incr).
    if let Some(prior_label) = prior_label.as_ref() {
        entry["backup-reference"] = json!([prior_label]);
    }
    info.current.insert(label.clone(), entry);
    info.save(repo_storage, &info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(BackupOutcome {
        label,
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

    // ---- differential backups ----------------------------------------------

    /// A backup config carrying `--type=<value>` (and a stanza).
    fn typed_cfg(stanza: &str, backup_type: &str) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("type".to_owned(), None), OptionValue::StringId(backup_type.to_owned()));
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn backup_type_from_options_maps_type() {
        // Default (absent) and unrecognised values map to full; diff -> Diff,
        // incr -> Incr.
        let mut diff = BTreeMap::new();
        diff.insert(("type".to_owned(), None), OptionValue::StringId("diff".to_owned()));
        let mut incr = BTreeMap::new();
        incr.insert(("type".to_owned(), None), OptionValue::StringId("incr".to_owned()));
        let mut bogus = BTreeMap::new();
        bogus.insert(("type".to_owned(), None), OptionValue::StringId("nonsense".to_owned()));
        let cfg = |opts: BTreeMap<(String, Option<u32>), OptionValue>| LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: opts,
            params: Vec::new(),
        };
        assert_eq!(BackupType::from_options(&cfg(BTreeMap::new())), BackupType::Full);
        assert_eq!(BackupType::from_options(&cfg(diff)), BackupType::Diff);
        assert_eq!(BackupType::from_options(&cfg(incr)), BackupType::Incr);
        assert_eq!(BackupType::from_options(&cfg(bogus)), BackupType::Full);
    }

    #[test]
    fn diff_requires_prior_full() {
        // A diff with no prior full backup in backup.info is a hard error.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        let err = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Diff,
            None,
            1_704_196_800,
            &RepoTransform::identity(),
        )
        .expect_err("diff without a full must error");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "differential backup requires a prior full backup"),
            other => panic!("expected Other(requires prior full), got {other:?}"),
        }
    }

    #[test]
    fn diff_references_unchanged_files() {
        // Seed a full backup, then take a diff where one file is unchanged and
        // one is modified. The unchanged file must be recorded with a reference
        // to the full and NOT copied into the diff dir; the changed file must be
        // copied with reference None.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");

        let unchanged = b"this file does not change between backups";
        let original = b"original contents of the file that will change";
        seed_file(&pg_s, "base/1/unchanged", unchanged);
        seed_file(&pg_s, "base/1/changed", original);

        // Full backup.
        let full = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
        )
        .expect("full backup");
        assert_eq!(full.label, LABEL);

        // Modify one file; leave the other untouched.
        let modified = b"MODIFIED contents that are completely different now";
        seed_file(&pg_s, "base/1/changed", modified);

        // Differential backup (label derived: <full>_<ts>D).
        let diff = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Diff,
            None,
            1_704_196_800,
            &RepoTransform::identity(),
        )
        .expect("diff backup");
        assert_eq!(diff.label, format!("{LABEL}_20240102-120000D"));

        let diff_label = diff.label;
        let manifest =
            Manifest::load(&repo_s, Path::new(&format!("backup/demo/{diff_label}/backup.manifest"))).expect("load diff manifest");
        assert_eq!(manifest.backup_type, "diff");

        // Unchanged file: referenced to the full, not copied.
        let unchanged_entry = manifest.file("base/1/unchanged").expect("unchanged in manifest");
        assert_eq!(unchanged_entry.reference.as_deref(), Some(LABEL));
        assert_eq!(unchanged_entry.checksum.as_deref(), Some(sha1_hex(unchanged).as_str()));
        let diff_root = repo_dir.path().join(format!("backup/demo/{diff_label}"));
        assert!(
            !diff_root.join("base/1/unchanged").exists(),
            "unchanged file must NOT be copied into the diff dir"
        );

        // Changed file: copied, no reference.
        let changed_entry = manifest.file("base/1/changed").expect("changed in manifest");
        assert_eq!(changed_entry.reference, None);
        assert_eq!(changed_entry.checksum.as_deref(), Some(sha1_hex(modified).as_str()));
        assert!(
            diff_root.join("base/1/changed").exists(),
            "changed file must be copied into the diff dir"
        );
        assert_eq!(std::fs::read(diff_root.join("base/1/changed")).unwrap(), modified);

        // backup.info records the diff type and a backup-reference chain.
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let entry = info.current.get(&diff_label).expect("diff entry in backup.info");
        assert_eq!(entry["backup-type"], json!("diff"));
        assert_eq!(entry["backup-reference"], json!([LABEL]));
    }

    // ---- incremental backups -----------------------------------------------

    #[test]
    fn full_root_label_extracts_chain_root() {
        // A full label is its own root; diff/incr labels anchor to their full.
        assert_eq!(full_root_label("20240101-120000F"), "20240101-120000F");
        assert_eq!(full_root_label("20240101-120000F_20240102-120000D"), "20240101-120000F");
        assert_eq!(full_root_label("20240101-120000F_20240103-120000I"), "20240101-120000F");
    }

    #[test]
    fn incr_requires_prior_backup() {
        // An incr with an empty [backup:current] block is a hard error.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        let err = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Incr,
            None,
            1_704_196_800,
            &RepoTransform::identity(),
        )
        .expect_err("incr without a prior must error");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "incremental backup requires a prior backup"),
            other => panic!("expected Other(requires prior backup), got {other:?}"),
        }
    }

    #[test]
    fn incr_label_anchored_to_full_root() {
        // full -> diff -> incr: the incr label must anchor to the FULL root, not
        // to the diff that is its immediate prior.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/a", b"file a contents");

        // Full.
        backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
        )
        .expect("full backup");

        // Diff (prior = full).
        let diff = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Diff,
            None,
            1_704_196_800,
            &RepoTransform::identity(),
        )
        .expect("diff backup");
        assert_eq!(diff.label, format!("{LABEL}_20240102-120000D"));

        // Incr (prior = diff, but label anchors to the FULL root LABEL).
        let incr = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Incr,
            None,
            1_704_283_200,
            &RepoTransform::identity(),
        )
        .expect("incr backup");
        assert_eq!(incr.label, format!("{LABEL}_20240103-120000I"));

        // backup.info records type=incr and the prior (the diff) as the chain head.
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let entry = info.current.get(&incr.label).expect("incr entry in backup.info");
        assert_eq!(entry["backup-type"], json!("incr"));
        assert_eq!(entry["backup-reference"], json!([format!("{LABEL}_20240102-120000D")]));
    }

    #[test]
    fn incr_references_prior_unchanged_files() {
        // full -> modify file b -> diff -> modify file c -> incr. The incr's
        // manifest must reference each unchanged file at the backup that
        // PHYSICALLY holds it: file a (untouched since full) -> full; file b
        // (last changed in diff) -> diff. Only the newly-changed file c is copied
        // into the incr dir.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");

        let a = b"file a never changes after the full";
        let b_v1 = b"file b version one (in the full)";
        let c_v1 = b"file c version one (in the full)";
        seed_file(&pg_s, "base/1/a", a);
        seed_file(&pg_s, "base/1/b", b_v1);
        seed_file(&pg_s, "base/1/c", c_v1);

        // Full backup.
        backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
        )
        .expect("full backup");

        // Modify b only; diff.
        let b_v2 = b"file b version two (changed for the diff)";
        seed_file(&pg_s, "base/1/b", b_v2);
        let diff = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Diff,
            None,
            1_704_196_800,
            &RepoTransform::identity(),
        )
        .expect("diff backup");
        let diff_label = diff.label;

        // Modify c only; incr.
        let c_v2 = b"file c version two (changed for the incr)";
        seed_file(&pg_s, "base/1/c", c_v2);
        let incr = backup_inner_typed(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Incr,
            None,
            1_704_283_200,
            &RepoTransform::identity(),
        )
        .expect("incr backup");
        let incr_label = incr.label;

        let manifest =
            Manifest::load(&repo_s, Path::new(&format!("backup/demo/{incr_label}/backup.manifest"))).expect("load incr manifest");
        assert_eq!(manifest.backup_type, "incr");

        // File a: unchanged since the full, which physically holds it.
        let entry_a = manifest.file("base/1/a").expect("a in manifest");
        assert_eq!(entry_a.reference.as_deref(), Some(LABEL));
        assert_eq!(entry_a.checksum.as_deref(), Some(sha1_hex(a).as_str()));

        // File b: last changed in the diff, which physically holds it. The incr
        // must point DIRECTLY at the diff (the physical holder), not at the full.
        let entry_b = manifest.file("base/1/b").expect("b in manifest");
        assert_eq!(entry_b.reference.as_deref(), Some(diff_label.as_str()));
        assert_eq!(entry_b.checksum.as_deref(), Some(sha1_hex(b_v2).as_str()));

        // File c: newly changed for the incr — copied, no reference.
        let entry_c = manifest.file("base/1/c").expect("c in manifest");
        assert_eq!(entry_c.reference, None);
        assert_eq!(entry_c.checksum.as_deref(), Some(sha1_hex(c_v2).as_str()));

        // Only c is physically present in the incr dir.
        let incr_root = repo_dir.path().join(format!("backup/demo/{incr_label}"));
        assert!(incr_root.join("base/1/c").exists(), "changed file c must be copied");
        assert!(!incr_root.join("base/1/a").exists(), "unchanged a must not be copied");
        assert!(!incr_root.join("base/1/b").exists(), "diff-held b must not be copied");
        assert_eq!(std::fs::read(incr_root.join("base/1/c")).unwrap(), c_v2);
    }

    #[test]
    fn full_backup_unchanged() {
        // No-regression: a default (full) backup via the public entry point
        // copies every file with no references.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        backup(&typed_cfg("demo", "full"), &repo_s, &pg_s).expect("full backup");

        // The full label is timestamp-derived; find the single backup recorded.
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        assert_eq!(info.current.len(), 1, "exactly one backup recorded");
        let (label, entry) = info.current.iter().next().unwrap();
        assert_eq!(entry["backup-type"], json!("full"));
        assert!(
            entry.get("backup-reference").is_none(),
            "a full backup has no reference chain"
        );

        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("load manifest");
        assert!(
            manifest.files.iter().all(|f| f.reference.is_none()),
            "every file in a full backup must be reference-free"
        );
        // Every recorded file is physically present in the backup dir.
        let backup_root = repo_dir.path().join(format!("backup/demo/{label}"));
        for file in &manifest.files {
            assert!(backup_root.join(&file.path).exists(), "full backup must copy {}", file.path);
        }
    }
}
