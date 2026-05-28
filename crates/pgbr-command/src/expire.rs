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
//! ## Archive-retention model (faithful to the C `removeExpiredArchive`)
//!
//! - `repo-retention-archive-type` (`full` | `diff` | `incr`) selects the
//!   *anchor* set of backups whose WAL is retained. `repo-retention-archive`
//!   is the count of those backups, from newest, whose archive must survive.
//! - WAL is stored per archive-id under `archive/<stanza>/<archive-id>/`,
//!   where `<archive-id>` is `<db-version>-<db-id>` (e.g. `14-1`). One
//!   archive-id exists per `PostgreSQL` cluster identity in the
//!   `archive.info` `[db:history]` block, so a version upgrade produces a
//!   second archive-id (`15-2`) alongside the old one (`14-1`). Each
//!   archive-id is expired independently against the backups that belong
//!   to it (matched by the per-backup `db-id` field).
//! - For a given archive-id, the *retention backup* is the oldest backup
//!   in the retained window that belongs to that archive-id. WAL needed to
//!   make every backup up to and including the retention backup consistent
//!   (each backup's `[archive-start, archive-stop]` range) is preserved,
//!   plus everything from the retention backup's `archive-start` onward
//!   (open-ended, for PITR). WAL strictly before the oldest retained range
//!   is removed. This mirrors the C `ArchiveRange` list logic.
//! - An archive-id with no surviving backup is removed entirely — unless it
//!   is the *current* cluster, which is always kept.
//! - History files (`<timeline>.history`) older than the retention backup's
//!   start timeline are expired.
//!
//! The keep/remove decision is factored into the pure, unit-tested
//! [`compute_archive_plan`] (per-archive-id ranges + drop flag) and
//! [`segment_in_ranges`] (does a WAL name fall inside any kept range).
//!
//! ## Documented gaps
//!
//! - The legacy flat `archive/<stanza>/<segment>` layout produced by the
//!   current [`crate::archive`] push path (no per-archive-id subdirectory)
//!   is still handled: loose WAL files directly under `archive/<stanza>/`
//!   are expired against the global cutoff (the oldest retained anchor
//!   backup's `archive-start`). Once `archive` writes the per-archive-id
//!   layout this fallback becomes dead but harmless.
//! - Major-path (`<timeline+LSN-prefix>` directory) vs. individual-segment
//!   handling is unified here: this port lists WAL leaf names recursively
//!   per archive-id and filters them by range, rather than the C tree's
//!   two-tier "drop whole major path, else scan files" optimisation. The
//!   resulting keep/remove set is identical; only the deletion granularity
//!   differs (we always remove leaf files, never whole prefix dirs, except
//!   for a fully-unreferenced archive-id which is dropped wholesale).

use std::path::PathBuf;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoArchive, InfoBackup, InfoError};
use pgbr_storage::{Storage, StorageError, StorageKind};

use crate::CommandError;

/// An archive-id paired with whether it is the *current* cluster.
type ArchiveIdMarked = (String, bool);

/// Map of `db-id` to textual `db-version`, used to reconstruct archive-ids.
type VersionById = std::collections::BTreeMap<u32, String>;

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

/// Pull `backup-archive-stop` out of a `[backup:current]` entry, or `None`
/// if absent (same conditions as [`backup_archive_start`]).
fn backup_archive_stop(value: &serde_json::Value) -> Option<&str> {
    value.get("backup-archive-stop").and_then(serde_json::Value::as_str)
}

/// Pull the per-backup `db-id` (the C `backupPgId`) out of a
/// `[backup:current]` entry. This indexes the backup to the archive-id it
/// belongs to. Returns `None` if absent — such backups cannot be matched
/// to an archive-id and are skipped during per-archive-id expiry.
fn backup_pg_id(value: &serde_json::Value) -> Option<u32> {
    value
        .get("db-id")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

/// `repo-retention-archive-type` lookup. Defaults to `full` when unset
/// (matching the C default), and treats any unrecognised value as `full`.
fn retention_archive_type(config: &LoadedConfig) -> ArchiveRetentionType {
    match config.options.get(&("repo-retention-archive-type".to_owned(), None)) {
        Some(OptionValue::String(s)) => ArchiveRetentionType::parse(s),
        _ => ArchiveRetentionType::Full,
    }
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

/// Which backup type anchors archive retention (`repo-retention-archive-type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveRetentionType {
    /// Count only full backups.
    Full,
    /// Count full + differential backups.
    Diff,
    /// Count full + differential + incremental backups (i.e. all).
    Incr,
}

impl ArchiveRetentionType {
    /// Parse the textual option value; anything unrecognised falls back to
    /// [`ArchiveRetentionType::Full`] (the C default).
    fn parse(s: &str) -> Self {
        match s {
            "diff" => Self::Diff,
            "incr" => Self::Incr,
            _ => Self::Full,
        }
    }

    /// Does a backup of `backup_type` participate in the anchor set for
    /// this retention type? `full` always counts; `diff` adds differentials;
    /// `incr` adds incrementals on top.
    fn includes(self, backup_type: &str) -> bool {
        match self {
            Self::Full => backup_type == "full",
            Self::Diff => backup_type == "full" || backup_type == "diff",
            Self::Incr => matches!(backup_type, "full" | "diff" | "incr"),
        }
    }
}

/// Minimal, layout-independent view of one backup, sufficient to compute
/// the archive-retention boundary. Built from a `[backup:current]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupForArchive {
    /// Backup label (e.g. `20260101-100000F`). Labels sort
    /// chronologically as strings, which [`compute_archive_plan`] relies on.
    pub label: String,
    /// `backup-type`: `full` / `diff` / `incr`.
    pub backup_type: String,
    /// The archive-id this backup belongs to (`<db-version>-<db-id>`).
    pub archive_id: String,
    /// `backup-archive-start`, or `None` for a `--no-online` backup.
    pub archive_start: Option<String>,
    /// `backup-archive-stop`, or `None`.
    pub archive_stop: Option<String>,
}

/// A WAL range `[start, stop]` that must be preserved. `stop == None` means
/// open-ended (everything from `start` onward), used for the retention
/// backup so the cluster stays recoverable via PITR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveRange {
    /// Inclusive lower bound (full 24-char WAL segment name).
    pub start: String,
    /// Inclusive upper bound, or `None` for open-ended.
    pub stop: Option<String>,
}

/// The retention decision for a single archive-id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIdPlan {
    /// The archive-id this plan applies to.
    pub archive_id: String,
    /// When `true`, no backup anchors this archive-id and it is not the
    /// current cluster: the whole directory is removed and `ranges` is
    /// empty. When `false`, `ranges` lists the WAL to keep.
    pub drop_all: bool,
    /// Ranges of WAL to preserve. Empty + `drop_all == false` means the
    /// anchoring backup recorded no WAL (e.g. `--no-online`), so nothing is
    /// expired (too risky) — see [`segment_in_ranges`] callers.
    pub ranges: Vec<ArchiveRange>,
    /// `true` when an anchoring backup was found but recorded no archive
    /// range, so WAL expiry must be skipped for safety.
    pub skip_expiry: bool,
    /// Timeline (`[0:8]` of the retention backup's `archive-start`) below
    /// which `.history` files are expired. `None` when expiry is skipped.
    pub history_timeline: Option<String>,
}

/// Compute the per-archive-id retention plans — the pure heart of archive
/// expiry, unit-tested in isolation.
///
/// Inputs:
/// - `backups`: every surviving backup (any order); each carries its
///   archive-id, type, and WAL range.
/// - `archive_ids`: the archive-ids known to `archive.info` history,
///   together with whether each is the *current* cluster (never dropped).
/// - `retention_type` / `keep_archive`: the anchor selection.
///
/// Algorithm (mirrors C `removeExpiredArchive`):
/// 1. Build the global anchor list — backups whose type matches
///    `retention_type`, sorted newest→oldest. If empty, or
///    `keep_archive > anchors.len()`, return an empty plan set (too soon).
/// 2. The retained anchor window is the newest `keep_archive` of those.
/// 3. For each archive-id, intersect the retained window with the backups
///    that belong to it. If none, the archive-id is dropped (unless current).
///    The retention backup is the oldest backup in that intersection (or, if
///    the intersection is empty but local backups exist, the newest local
///    backup so the cluster stays recoverable).
/// 4. Build keep-ranges from every local backup whose label `<=` the
///    retention backup's label and that has an archive range. The retention
///    backup contributes an open-ended range (`stop = None`).
///
/// Returns one [`ArchiveIdPlan`] per archive-id that has at least one local
/// backup or is droppable, in ascending archive-id order.
#[must_use]
pub fn compute_archive_plan(
    backups: &[BackupForArchive],
    archive_ids: &[(String, bool)],
    retention_type: ArchiveRetentionType,
    keep_archive: u32,
) -> Vec<ArchiveIdPlan> {
    // (1) Global anchor list, newest -> oldest by label.
    let mut anchors: Vec<&BackupForArchive> = backups.iter().filter(|b| retention_type.includes(&b.backup_type)).collect();
    anchors.sort_by(|a, b| b.label.cmp(&a.label));

    let keep_archive = keep_archive as usize;
    // Too soon to expire: no anchors, or not enough of them yet.
    if anchors.is_empty() || keep_archive > anchors.len() {
        return Vec::new();
    }

    // (2) The retained anchor window: newest `keep_archive` labels.
    let retained_window: std::collections::BTreeSet<&str> = anchors.iter().take(keep_archive).map(|b| b.label.as_str()).collect();

    let mut plans: Vec<ArchiveIdPlan> = Vec::new();

    for (archive_id, is_current) in archive_ids {
        // Backups belonging to this archive-id, oldest -> newest.
        let mut local: Vec<&BackupForArchive> = backups.iter().filter(|b| &b.archive_id == archive_id).collect();
        local.sort_by(|a, b| a.label.cmp(&b.label));

        if local.is_empty() {
            // No backup anchors this archive-id. Drop it unless it is the
            // current cluster (whose archive directory must never go).
            if !is_current {
                plans.push(ArchiveIdPlan {
                    archive_id: archive_id.clone(),
                    drop_all: true,
                    ranges: Vec::new(),
                    skip_expiry: false,
                    history_timeline: None,
                });
            }
            continue;
        }

        // (3) Intersection of the retained window with local backups,
        // oldest -> newest. The retention backup is the first of these, or
        // the newest local backup when the window misses this archive-id
        // entirely (so the cluster remains recoverable).
        let local_retained: Vec<&BackupForArchive> = local
            .iter()
            .copied()
            .filter(|b| retained_window.contains(b.label.as_str()))
            .collect();
        // `local` is non-empty (checked above), so `local.last()` is `Some`.
        let Some(retention_backup) = local_retained.first().copied().or_else(|| local.last().copied()) else {
            continue;
        };

        // Backups performed with --no-online have no archive start and
        // cannot anchor expiry: keep all WAL for this archive-id.
        let Some(_retention_start) = retention_backup.archive_start.as_deref() else {
            plans.push(ArchiveIdPlan {
                archive_id: archive_id.clone(),
                drop_all: false,
                ranges: Vec::new(),
                skip_expiry: true,
                history_timeline: None,
            });
            continue;
        };

        // (4) Build keep-ranges from local backups up to and including the
        // retention backup. The retention backup contributes an open-ended
        // range; older ones contribute their closed [start, stop].
        let mut ranges: Vec<ArchiveRange> = Vec::new();
        for b in &local {
            if b.label.as_str() > retention_backup.label.as_str() {
                continue;
            }
            let Some(start) = b.archive_start.as_deref() else {
                continue;
            };
            let stop = if b.label == retention_backup.label {
                None
            } else {
                b.archive_stop.clone()
            };
            ranges.push(ArchiveRange {
                start: start.to_owned(),
                stop,
            });
        }

        // History files are expired below the retention backup's timeline.
        let history_timeline = retention_backup
            .archive_start
            .as_deref()
            .filter(|s| s.len() >= 8)
            .map(|s| s[0..8].to_owned());

        plans.push(ArchiveIdPlan {
            archive_id: archive_id.clone(),
            drop_all: false,
            ranges,
            skip_expiry: false,
            history_timeline,
        });
    }

    plans
}

/// Does a WAL segment name fall inside any kept range?
///
/// The comparison is on the full 24-char segment name (timeline + 64-bit
/// LSN), matching the C individual-file path. `stop == None` ranges are
/// open-ended. `segment` should be the 24-char base name (compression suffix
/// stripped); names shorter than 24 chars (history files etc.) compare as-is.
#[must_use]
pub fn segment_in_ranges(segment: &str, ranges: &[ArchiveRange]) -> bool {
    let key = &segment[0..segment.len().min(24)];
    ranges.iter().any(|r| {
        let start_key = &r.start[0..r.start.len().min(24)];
        key >= start_key && r.stop.as_deref().is_none_or(|stop| key <= &stop[0..stop.len().min(24)])
    })
}

/// Build [`BackupForArchive`] views for the surviving backups, resolving
/// each backup's archive-id from its `db-id` via the archive history map.
/// Backups missing a `db-id`, or whose `db-id` is absent from `history`,
/// are skipped (they cannot be tied to an archive-id).
fn backups_for_archive(info: &InfoBackup, history: &VersionById) -> Vec<BackupForArchive> {
    let mut out: Vec<BackupForArchive> = Vec::new();
    for (label, value) in &info.current {
        let Some(pg_id) = backup_pg_id(value) else {
            continue;
        };
        let Some(version) = history.get(&pg_id) else {
            continue;
        };
        out.push(BackupForArchive {
            label: label.clone(),
            backup_type: backup_type(value).to_owned(),
            archive_id: format!("{version}-{pg_id}"),
            archive_start: backup_archive_start(value).map(str::to_owned),
            archive_stop: backup_archive_stop(value).map(str::to_owned),
        });
    }
    out
}

/// Resolve the set of archive-ids, pairing each with a flag marking the
/// *current* cluster. The archive-id is `<db-version>-<db-id>` drawn from
/// the `[db:history]` rows; the current one is the row whose key equals the
/// active `db-id`.
///
/// Prefers `archive.info` (authoritative for which cluster is current). When
/// `archive.info` is absent or unreadable, falls back to `backup.info`'s
/// history — the two files share the same `db-id` keys and versions, so the
/// archive-id reconstruction is identical; only the "current" marker comes
/// from the active `db-id` recorded in `backup.info`.
fn load_archive_ids(
    repo: &dyn Storage,
    stanza: &str,
    backup_info: &InfoBackup,
) -> Result<(Vec<ArchiveIdMarked>, VersionById), CommandError> {
    let archive_info_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    let loaded = match repo.exists(&archive_info_path) {
        Ok(true) => match InfoArchive::load(repo, &archive_info_path) {
            Ok(info) => Some((info.history, info.db_id)),
            // A malformed/cipher archive.info should not abort backup expiry;
            // fall back to the backup history.
            Err(_) => None,
        },
        Ok(false) => None,
        Err(err) => return Err(err.into()),
    };

    let (history, current_id) = match loaded {
        Some((history, current_id)) => (history, current_id),
        None => (backup_info.history.clone(), backup_info.db_id),
    };

    let mut ids: Vec<ArchiveIdMarked> = Vec::new();
    let mut version_by_id: VersionById = std::collections::BTreeMap::new();
    for (db_id, entry) in &history {
        version_by_id.insert(*db_id, entry.db_version.clone());
        ids.push((format!("{}-{}", entry.db_version, db_id), *db_id == current_id));
    }
    ids.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((ids, version_by_id))
}

/// WAL-archive retention pass, run *after* backup expiry.
///
/// Drives [`compute_archive_plan`] across the per-archive-id directory
/// layout, falling back to a flat-layout cutoff for loose WAL files that
/// sit directly under `archive/<stanza>/` (the current [`crate::archive`]
/// push layout). Returns the removed base segment names in ascending order.
fn expire_archive(
    repo: &dyn Storage,
    stanza: &str,
    keep_archive: u32,
    retention_type: ArchiveRetentionType,
    kept_anchor_oldest_first: &[serde_json::Value],
    info: &InfoBackup,
) -> Result<Vec<String>, CommandError> {
    let archive_root = PathBuf::from(format!("archive/{stanza}"));

    // List the archive root. A missing directory means no WAL pushed yet.
    let root_entries = match repo.list(&archive_root) {
        Ok(entries) => entries,
        Err(StorageError::NotFound { .. }) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    // Partition the root into per-archive-id subdirectories vs. loose files.
    // `archive.info` (and its `.copy`) live here too and are never WAL.
    let mut archive_id_dirs: Vec<String> = Vec::new();
    let mut loose_files: Vec<String> = Vec::new();
    for entry in &root_entries {
        let Some(name) = entry.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == "archive.info" || name == "archive.info.copy" {
            continue;
        }
        match entry.kind {
            StorageKind::Path if is_archive_id(name) => archive_id_dirs.push(name.to_owned()),
            StorageKind::File => loose_files.push(name.to_owned()),
            _ => {}
        }
    }

    let mut removed: Vec<String> = Vec::new();

    // (A) Per-archive-id layout — the faithful path.
    if !archive_id_dirs.is_empty() {
        // Prefer archive.info for the authoritative archive-id set + which
        // one is the current cluster (never dropped). Fall back to the
        // backup.info history (same db-id keys/versions) when archive.info
        // is absent or unreadable.
        let (history_ids, version_by_id) = load_archive_ids(repo, stanza, info)?;
        let backups = backups_for_archive(info, &version_by_id);

        // Restrict to archive-ids that actually exist on disk, but preserve
        // the "current" flag from history. Any on-disk archive-id not in
        // history is treated as non-current (droppable when unreferenced).
        let on_disk: std::collections::BTreeSet<&str> = archive_id_dirs.iter().map(String::as_str).collect();
        let mut archive_ids: Vec<(String, bool)> = history_ids
            .into_iter()
            .filter(|(id, _)| on_disk.contains(id.as_str()))
            .collect();
        let known: std::collections::BTreeSet<String> = archive_ids.iter().map(|(id, _)| id.clone()).collect();
        for id in &archive_id_dirs {
            if !known.contains(id) {
                archive_ids.push((id.clone(), false));
            }
        }
        archive_ids.sort_by(|a, b| a.0.cmp(&b.0));

        let plans = compute_archive_plan(&backups, &archive_ids, retention_type, keep_archive);

        for plan in &plans {
            let id_dir = archive_root.join(&plan.archive_id);
            if plan.drop_all {
                match repo.remove_path(&id_dir, true, false) {
                    Ok(()) | Err(StorageError::NotFound { .. }) => {}
                    Err(err) => return Err(err.into()),
                }
                continue;
            }
            if plan.skip_expiry {
                continue;
            }
            remove_wal_under(repo, &id_dir, plan, &mut removed)?;
        }
    }

    // (B) Legacy flat layout — loose WAL files directly under the root.
    if !loose_files.is_empty()
        && let Some(cutoff) = flat_cutoff(keep_archive, kept_anchor_oldest_first)
    {
        for file_name in loose_files {
            let base = strip_compress_suffix(&file_name);
            if base < cutoff.as_str() {
                let path = archive_root.join(&file_name);
                match repo.remove(&path, false) {
                    Ok(()) | Err(StorageError::NotFound { .. }) => {}
                    Err(err) => return Err(err.into()),
                }
                removed.push(base.to_owned());
            }
        }
    }

    removed.sort();
    removed.dedup();
    Ok(removed)
}

/// The flat-layout cutoff: the `backup-archive-start` of the Nth-most-recent
/// retained anchor backup (N = `keep_archive`). `None` (keep everything)
/// when too few anchors survive or the anchor recorded no WAL range.
fn flat_cutoff(keep_archive: u32, kept_anchor_oldest_first: &[serde_json::Value]) -> Option<String> {
    let keep_archive = keep_archive as usize;
    if kept_anchor_oldest_first.len() < keep_archive || keep_archive == 0 {
        return None;
    }
    let cutoff_index = kept_anchor_oldest_first.len() - keep_archive;
    backup_archive_start(&kept_anchor_oldest_first[cutoff_index]).map(str::to_owned)
}

/// Recursively list WAL leaf files under an archive-id directory and remove
/// every segment not covered by `plan.ranges`. History (`.history`) files
/// are expired by timeline against `plan.history_timeline`. Appends removed
/// base segment names to `removed`.
fn remove_wal_under(
    repo: &dyn Storage,
    id_dir: &std::path::Path,
    plan: &ArchiveIdPlan,
    removed: &mut Vec<String>,
) -> Result<(), CommandError> {
    let mut leaves: Vec<PathBuf> = Vec::new();
    collect_files(repo, id_dir, &mut leaves)?;

    for leaf in leaves {
        let Some(name) = leaf.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let base = strip_compress_suffix(name);

        // History files: expire those below the retention timeline.
        if let Some(timeline) = base.strip_suffix(".history") {
            if let Some(keep_below) = plan.history_timeline.as_deref()
                && timeline.len() >= 8
                && &timeline[0..8] < keep_below
            {
                match repo.remove(&leaf, false) {
                    Ok(()) | Err(StorageError::NotFound { .. }) => {}
                    Err(err) => return Err(err.into()),
                }
                removed.push(base.to_owned());
            }
            continue;
        }

        // Only WAL-segment-shaped names participate in range filtering;
        // anything else (e.g. backup-history sidecar files) is left alone.
        if !looks_like_wal_segment(base) {
            continue;
        }

        if !segment_in_ranges(base, &plan.ranges) {
            match repo.remove(&leaf, false) {
                Ok(()) | Err(StorageError::NotFound { .. }) => {}
                Err(err) => return Err(err.into()),
            }
            removed.push(base.to_owned());
        }
    }
    Ok(())
}

/// Depth-first collect every file path beneath `dir` (inclusive of nested
/// major-path subdirectories). A missing directory is treated as empty.
fn collect_files(repo: &dyn Storage, dir: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<(), CommandError> {
    let entries = match repo.list(dir) {
        Ok(entries) => entries,
        Err(StorageError::NotFound { .. }) => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let Some(name) = entry.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let child = dir.join(name);
        match entry.kind {
            StorageKind::File => out.push(child),
            StorageKind::Path => collect_files(repo, &child, out)?,
            _ => {}
        }
    }
    Ok(())
}

/// Does `name` look like an archive-id directory (`<version>-<db-id>`)?
/// The version is `\d+(\.\d+)?` (e.g. `14` or `9.6`) and the db-id is a
/// positive integer. Mirrors the C `REGEX_ARCHIVE_DIR_DB_VERSION`.
fn is_archive_id(name: &str) -> bool {
    let Some((version, id)) = name.rsplit_once('-') else {
        return false;
    };
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit() || b == b'.') && version.bytes().any(|b| b.is_ascii_digit())
}

/// A WAL segment file name is 24 hex chars optionally followed by `-<hash>`
/// or `.partial` / `.backup`. We accept any name whose first 24 chars are
/// all hex — enough to distinguish segments from history files and stray
/// entries. Mirrors the C `^[0-F]{24}.*$`.
fn looks_like_wal_segment(name: &str) -> bool {
    name.len() >= 24 && name.as_bytes()[0..24].iter().all(u8::is_ascii_hexdigit)
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

    let archive_type = retention_archive_type(config);

    // No backup retention configured. Backups are all kept, but archive
    // retention may still apply against the surviving anchor backups.
    let Some(keep_full) = retention_full(config)? else {
        let kept_labels: Vec<String> = info.current.keys().cloned().collect();
        let kept_anchor_oldest_first = anchor_backups_oldest_first(&info, &kept_labels, archive_type);
        let expired_archive_segments = match retention_archive(config)? {
            Some(keep_archive) => expire_archive(repo, stanza, keep_archive, archive_type, &kept_anchor_oldest_first, &info)?,
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
    // the anchor backups that survived (in `kept_labels`, oldest first).
    let kept_anchor_oldest_first = anchor_backups_oldest_first(&info, &kept_labels, archive_type);
    let expired_archive_segments = match retention_archive(config)? {
        Some(keep_archive) => expire_archive(repo, stanza, keep_archive, archive_type, &kept_anchor_oldest_first, &info)?,
        None => Vec::new(),
    };

    Ok(ExpireSummary {
        expired_labels,
        kept_labels,
        expired_archive_segments,
    })
}

/// Collect the `[backup:current]` JSON entries for the anchor backups named
/// in `kept_labels`, preserving the order of `kept_labels` (which callers
/// pass oldest-first). Labels absent from `info.current`, or whose type does
/// not match `archive_type` (full / full+diff / full+diff+incr), are
/// skipped. Used only by the legacy flat-layout fallback.
fn anchor_backups_oldest_first(
    info: &InfoBackup,
    kept_labels: &[String],
    archive_type: ArchiveRetentionType,
) -> Vec<serde_json::Value> {
    kept_labels
        .iter()
        .filter_map(|label| info.current.get(label))
        .filter(|value| archive_type.includes(backup_type(value)))
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

    use super::{
        ArchiveIdPlan, ArchiveRange, ArchiveRetentionType, BackupForArchive, ExpireSummary, compute_archive_plan, expire_inner,
        segment_in_ranges,
    };

    fn cfg(stanza: Option<&str>, retention_full: Option<i64>) -> LoadedConfig {
        cfg_archive(stanza, retention_full, None)
    }

    /// `cfg` plus an optional `repo-retention-archive` integer.
    fn cfg_archive(stanza: Option<&str>, retention_full: Option<i64>, retention_archive: Option<i64>) -> LoadedConfig {
        cfg_archive_type(stanza, retention_full, retention_archive, None)
    }

    /// `cfg_archive` plus an optional `repo-retention-archive-type` string.
    fn cfg_archive_type(
        stanza: Option<&str>,
        retention_full: Option<i64>,
        retention_archive: Option<i64>,
        archive_type: Option<&str>,
    ) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(n) = retention_full {
            options.insert(("repo-retention-full".to_owned(), None), OptionValue::Integer(n));
        }
        if let Some(n) = retention_archive {
            options.insert(("repo-retention-archive".to_owned(), None), OptionValue::Integer(n));
        }
        if let Some(t) = archive_type {
            options.insert(
                ("repo-retention-archive-type".to_owned(), None),
                OptionValue::String(t.to_owned()),
            );
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

    /// Build + seed `backup.info` with full per-backup detail, including the
    /// per-backup `db-id` (archive-id key) and a `[db:history]` block keyed
    /// by `db-id` carrying the version label. Each tuple is
    /// `(label, ts, ty, archive_start, archive_stop, db_id)`.
    #[allow(clippy::too_many_lines)]
    fn seed_backup_info_full(
        repo: &Posix,
        stanza: &str,
        entries: &[(&str, i64, &str, &str, &str, u32)],
        history_versions: &[(u32, &str)],
        active_db_id: u32,
    ) {
        let mut current = BTreeMap::new();
        for (label, ts, ty, archive_start, archive_stop, db_id) in entries {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
                    "backup-timestamp-stop": ts,
                    "backup-type": *ty,
                    "backup-archive-start": *archive_start,
                    "backup-archive-stop": *archive_stop,
                    "db-id": *db_id,
                }),
            );
        }

        let mut history = BTreeMap::new();
        for (db_id, version) in history_versions {
            history.insert(
                *db_id,
                DbHistoryEntry {
                    db_id: 6_873_049_345_984_568_091 + u64::from(*db_id),
                    db_version: (*version).to_owned(),
                },
            );
        }

        let active_version = history_versions
            .iter()
            .find(|(id, _)| *id == active_db_id)
            .map_or("14", |(_, v)| v);

        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: active_db_id,
            db_system_id: 6_873_049_345_984_568_091 + u64::from(active_db_id),
            db_version: active_version.to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        };

        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup/<stanza>");
        info.save(repo, &super::backup_info_path(stanza)).expect("save backup.info");
    }

    /// Materialise a WAL segment in the per-archive-id layout at
    /// `archive/<stanza>/<archive-id>/<major-path>/<segment>`. The major
    /// path is the first 16 chars of the segment name, matching how
    /// pgBackRest groups WAL on disk.
    fn seed_archive_id_segment(repo: &Posix, stanza: &str, archive_id: &str, segment: &str, suffix: &str) {
        let major = &segment[0..16.min(segment.len())];
        let dir = format!("archive/{stanza}/{archive_id}/{major}");
        repo.create_path(Path::new(&dir), true).expect("create archive-id major dir");
        let mut w = repo
            .open_write(Path::new(&format!("{dir}/{segment}{suffix}")))
            .expect("open segment");
        w.write(b"wal").expect("write segment");
        w.close().expect("close segment");
    }

    /// Whether a per-archive-id WAL segment still exists on disk.
    fn archive_id_segment_exists(dir: &Path, stanza: &str, archive_id: &str, segment: &str, suffix: &str) -> bool {
        let major = &segment[0..16.min(segment.len())];
        dir.join(format!("archive/{stanza}/{archive_id}/{major}/{segment}{suffix}"))
            .exists()
    }

    fn ba(label: &str, ty: &str, archive_id: &str, start: &str, stop: &str) -> BackupForArchive {
        BackupForArchive {
            label: label.to_owned(),
            backup_type: ty.to_owned(),
            archive_id: archive_id.to_owned(),
            archive_start: Some(start.to_owned()),
            archive_stop: Some(stop.to_owned()),
        }
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

    // ------------------------------------------------------------------
    // Pure boundary-function tests ([`compute_archive_plan`]).
    // ------------------------------------------------------------------

    #[test]
    fn plan_anchors_on_oldest_retained_full() {
        // Three fulls on archive-id 14-1; keep the newest 2's WAL. The
        // retention backup is the 2nd-newest (...0005 start). Ranges: that
        // backup open-ended, plus the closed range of every older backup up
        // to it. The oldest full (...0001) is *not* retained, so its WAL
        // before ...0005 expires; but its own [start, stop] range is kept so
        // it stays consistent.
        let backups = vec![
            ba(
                "20260101-100000F",
                "full",
                "14-1",
                "000000010000000000000001",
                "000000010000000000000002",
            ),
            ba(
                "20260101-110000F",
                "full",
                "14-1",
                "000000010000000000000005",
                "000000010000000000000006",
            ),
            ba(
                "20260101-120000F",
                "full",
                "14-1",
                "000000010000000000000009",
                "00000001000000000000000A",
            ),
        ];
        let plans = compute_archive_plan(&backups, &[("14-1".to_owned(), true)], ArchiveRetentionType::Full, 2);
        assert_eq!(plans.len(), 1);
        let plan = &plans[0];
        assert!(!plan.drop_all);
        assert!(!plan.skip_expiry);
        // Ranges: [...0001, ...0002] (older, closed) and [...0005, open).
        assert_eq!(
            plan.ranges,
            vec![
                ArchiveRange {
                    start: "000000010000000000000001".to_owned(),
                    stop: Some("000000010000000000000002".to_owned()),
                },
                ArchiveRange {
                    start: "000000010000000000000005".to_owned(),
                    stop: None,
                },
            ]
        );
    }

    #[test]
    fn plan_archive_type_full_vs_diff() {
        // A full + a later diff. With type=full and keep=1 the diff is not an
        // anchor, so the retention backup is the full -> open-ended from the
        // full's start. With type=diff and keep=1 the diff is the anchor, so
        // WAL is retained only from the diff's start (the full contributes a
        // closed range so it stays consistent).
        let backups = vec![
            ba(
                "20260101-100000F",
                "full",
                "14-1",
                "000000010000000000000001",
                "000000010000000000000002",
            ),
            ba(
                "20260101-100000F_20260101-110000D",
                "diff",
                "14-1",
                "000000010000000000000005",
                "000000010000000000000006",
            ),
        ];

        let plan_full = compute_archive_plan(&backups, &[("14-1".to_owned(), true)], ArchiveRetentionType::Full, 1);
        assert_eq!(
            plan_full[0].ranges,
            vec![ArchiveRange {
                start: "000000010000000000000001".to_owned(),
                stop: None,
            }],
            "type=full anchors on the full -> open from the full's start"
        );

        let plan_diff = compute_archive_plan(&backups, &[("14-1".to_owned(), true)], ArchiveRetentionType::Diff, 1);
        assert_eq!(
            plan_diff[0].ranges,
            vec![
                ArchiveRange {
                    start: "000000010000000000000001".to_owned(),
                    stop: Some("000000010000000000000002".to_owned()),
                },
                ArchiveRange {
                    start: "000000010000000000000005".to_owned(),
                    stop: None,
                },
            ],
            "type=diff anchors on the diff -> full kept consistent, open from the diff"
        );
    }

    #[test]
    fn plan_per_archive_id_across_db_history_upgrade() {
        // Two archive-ids: 14-1 (old, upgraded away) and 15-2 (current).
        // A full on each. keep=1, type=full. The global anchor window is the
        // single newest full overall (...2000 on 15-2). 14-1 has no backup in
        // that window, so its retention backup falls back to its newest local
        // backup (...1000) -> open from there (still recoverable). 15-2 keeps
        // open from ...2000.
        let backups = vec![
            ba(
                "20260101-100000F",
                "full",
                "14-1",
                "000000010000000000001000",
                "000000010000000000001001",
            ),
            ba(
                "20260201-100000F",
                "full",
                "15-2",
                "000000010000000000002000",
                "000000010000000000002001",
            ),
        ];
        let archive_ids = vec![("14-1".to_owned(), false), ("15-2".to_owned(), true)];
        let plans = compute_archive_plan(&backups, &archive_ids, ArchiveRetentionType::Full, 1);
        assert_eq!(plans.len(), 2);

        let p14 = plans.iter().find(|p| p.archive_id == "14-1").unwrap();
        assert!(!p14.drop_all, "14-1 has a local backup, so it is not dropped");
        assert_eq!(
            p14.ranges,
            vec![ArchiveRange {
                start: "000000010000000000001000".to_owned(),
                stop: None,
            }],
            "14-1 falls back to its newest local backup for recoverability"
        );

        let p15 = plans.iter().find(|p| p.archive_id == "15-2").unwrap();
        assert_eq!(
            p15.ranges,
            vec![ArchiveRange {
                start: "000000010000000000002000".to_owned(),
                stop: None,
            }]
        );
    }

    #[test]
    fn plan_drops_unreferenced_non_current_archive_id() {
        // 14-1 has no backups and is not current -> dropped wholesale.
        // 15-2 (current) has the only backup.
        let backups = vec![ba(
            "20260201-100000F",
            "full",
            "15-2",
            "000000010000000000002000",
            "000000010000000000002001",
        )];
        let archive_ids = vec![("14-1".to_owned(), false), ("15-2".to_owned(), true)];
        let plans = compute_archive_plan(&backups, &archive_ids, ArchiveRetentionType::Full, 1);

        let p14 = plans.iter().find(|p| p.archive_id == "14-1").unwrap();
        assert!(p14.drop_all, "unreferenced non-current archive-id is dropped");
        assert!(p14.ranges.is_empty());
    }

    #[test]
    fn plan_too_soon_returns_empty() {
        // keep=2 but only one full exists -> too soon, no plans at all.
        let backups = vec![ba(
            "20260101-100000F",
            "full",
            "14-1",
            "000000010000000000000001",
            "000000010000000000000002",
        )];
        let plans = compute_archive_plan(&backups, &[("14-1".to_owned(), true)], ArchiveRetentionType::Full, 2);
        assert!(plans.is_empty(), "not enough anchor backups -> keep everything");
    }

    #[test]
    fn segment_in_ranges_open_and_closed() {
        let ranges = vec![
            ArchiveRange {
                start: "000000010000000000000001".to_owned(),
                stop: Some("000000010000000000000002".to_owned()),
            },
            ArchiveRange {
                start: "000000010000000000000005".to_owned(),
                stop: None,
            },
        ];
        // Inside the closed range.
        assert!(segment_in_ranges("000000010000000000000001", &ranges));
        assert!(segment_in_ranges("000000010000000000000002", &ranges));
        // Between the two ranges -> not covered.
        assert!(!segment_in_ranges("000000010000000000000003", &ranges));
        // Below everything.
        assert!(!segment_in_ranges("000000010000000000000000", &ranges));
        // At / past the open range start.
        assert!(segment_in_ranges("000000010000000000000005", &ranges));
        assert!(segment_in_ranges("00000001000000000000FFFF", &ranges));
    }

    // ------------------------------------------------------------------
    // End-to-end per-archive-id expiry ([`expire_inner`]).
    // ------------------------------------------------------------------

    #[test]
    fn e2e_per_archive_id_removes_only_pre_boundary_segments() {
        let (dir, repo) = empty_repo();
        // Two fulls on archive-id 14-1; keep all backups, but archive-retain
        // only the newest (keep_archive=1). The retention backup is the newest
        // full (...0009). WAL before the oldest kept range expires; the oldest
        // backup's own [start, stop] range stays so it remains consistent.
        seed_backup_info_full(
            &repo,
            "demo",
            &[
                (
                    "20260101-100000F",
                    100,
                    "full",
                    "000000010000000000000001",
                    "000000010000000000000002",
                    1,
                ),
                (
                    "20260101-120000F",
                    300,
                    "full",
                    "000000010000000000000009",
                    "00000001000000000000000A",
                    1,
                ),
            ],
            &[(1, "14")],
            1,
        );

        // Segments: ...0000 (before oldest range -> remove),
        // ...0001/...0002 (oldest backup range -> keep for consistency),
        // ...0005 (between ranges -> remove), ...0009 (retention start -> keep),
        // ...000B (after retention start -> keep).
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000000", "");
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000001", "");
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000002", ".gz");
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000005", "");
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000009", "");
        seed_archive_id_segment(&repo, "demo", "14-1", "00000001000000000000000B", "");

        let summary = expire_inner(&cfg_archive(Some("demo"), Some(2), Some(1)), &repo).expect("expire_inner");

        assert_eq!(
            summary.expired_archive_segments,
            vec!["000000010000000000000000".to_owned(), "000000010000000000000005".to_owned(),],
            "only segments outside every kept range are removed"
        );
        assert!(!archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "000000010000000000000000",
            ""
        ));
        assert!(!archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "000000010000000000000005",
            ""
        ));
        // Retained ranges survive.
        assert!(archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "000000010000000000000001",
            ""
        ));
        assert!(archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "000000010000000000000002",
            ".gz"
        ));
        assert!(archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "000000010000000000000009",
            ""
        ));
        assert!(archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "00000001000000000000000B",
            ""
        ));
    }

    #[test]
    fn e2e_per_archive_id_expires_across_db_history_upgrade() {
        let (dir, repo) = empty_repo();
        // 14-1 (old) and 15-2 (current), one full each. keep_archive=1,
        // type=full. 14-1 keeps from its own full's start (recoverability
        // fallback); pre-...1000 WAL is removed. 15-2 keeps from ...2000.
        seed_backup_info_full(
            &repo,
            "demo",
            &[
                (
                    "20260101-100000F",
                    100,
                    "full",
                    "000000010000000000001000",
                    "000000010000000000001001",
                    1,
                ),
                (
                    "20260201-100000F",
                    500,
                    "full",
                    "000000010000000000002000",
                    "000000010000000000002001",
                    2,
                ),
            ],
            &[(1, "14"), (2, "15")],
            2,
        );

        // 14-1 WAL: one before its start (remove) + one at its start (keep).
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000999", "");
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000001000", "");
        // 15-2 WAL: one before its start (remove) + one at its start (keep).
        seed_archive_id_segment(&repo, "demo", "15-2", "000000010000000000001999", "");
        seed_archive_id_segment(&repo, "demo", "15-2", "000000010000000000002000", "");

        let summary = expire_inner(&cfg_archive(Some("demo"), Some(2), Some(1)), &repo).expect("expire_inner");

        assert_eq!(
            summary.expired_archive_segments,
            vec!["000000010000000000000999".to_owned(), "000000010000000000001999".to_owned(),],
            "each archive-id is expired against its own retention backup"
        );
        assert!(!archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "000000010000000000000999",
            ""
        ));
        assert!(archive_id_segment_exists(
            dir.path(),
            "demo",
            "14-1",
            "000000010000000000001000",
            ""
        ));
        assert!(!archive_id_segment_exists(
            dir.path(),
            "demo",
            "15-2",
            "000000010000000000001999",
            ""
        ));
        assert!(archive_id_segment_exists(
            dir.path(),
            "demo",
            "15-2",
            "000000010000000000002000",
            ""
        ));
    }

    #[test]
    fn e2e_drops_unreferenced_non_current_archive_id_directory() {
        let (dir, repo) = empty_repo();
        // 14-1 has no backups (its were expired) and is not current; its
        // whole directory is removed. 15-2 (current) keeps from ...2000.
        seed_backup_info_full(
            &repo,
            "demo",
            &[(
                "20260201-100000F",
                500,
                "full",
                "000000010000000000002000",
                "000000010000000000002001",
                2,
            )],
            &[(1, "14"), (2, "15")],
            2,
        );
        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000500", "");
        seed_archive_id_segment(&repo, "demo", "15-2", "000000010000000000002000", "");

        expire_inner(&cfg_archive(Some("demo"), Some(1), Some(1)), &repo).expect("expire_inner");

        assert!(
            !dir.path().join("archive/demo/14-1").exists(),
            "unreferenced non-current archive-id directory is removed wholesale"
        );
        assert!(
            dir.path().join("archive/demo/15-2").exists(),
            "current archive-id directory is preserved"
        );
        assert!(archive_id_segment_exists(
            dir.path(),
            "demo",
            "15-2",
            "000000010000000000002000",
            ""
        ));
    }

    #[test]
    fn e2e_per_archive_id_history_files_expired_by_timeline() {
        let (dir, repo) = empty_repo();
        // Retention backup on timeline 00000002 (its archive-start). A
        // 00000001.history file (older timeline) is expired; a
        // 00000002.history (same timeline) is kept.
        seed_backup_info_full(
            &repo,
            "demo",
            &[
                (
                    "20260101-100000F",
                    100,
                    "full",
                    "000000020000000000000001",
                    "000000020000000000000002",
                    1,
                ),
                (
                    "20260101-120000F",
                    300,
                    "full",
                    "000000020000000000000009",
                    "00000002000000000000000A",
                    1,
                ),
            ],
            &[(1, "14")],
            1,
        );
        // History files live directly under the archive-id dir.
        let id_dir = "archive/demo/14-1".to_owned();
        repo.create_path(Path::new(&id_dir), true).expect("create id dir");
        for hist in ["00000001.history", "00000002.history"] {
            let mut w = repo.open_write(Path::new(&format!("{id_dir}/{hist}"))).expect("open history");
            w.write(b"h").expect("write history");
            w.close().expect("close history");
        }
        // Plus a WAL segment so the directory is also exercised for WAL.
        seed_archive_id_segment(&repo, "demo", "14-1", "000000020000000000000009", "");

        let summary = expire_inner(&cfg_archive(Some("demo"), Some(2), Some(1)), &repo).expect("expire_inner");

        assert!(
            summary.expired_archive_segments.contains(&"00000001.history".to_owned()),
            "older-timeline history file is expired"
        );
        assert!(
            !dir.path().join(format!("{id_dir}/00000001.history")).exists(),
            "00000001.history removed (timeline < retention timeline 00000002)"
        );
        assert!(
            dir.path().join(format!("{id_dir}/00000002.history")).exists(),
            "00000002.history kept (same timeline as retention backup)"
        );
    }

    #[test]
    fn e2e_archive_id_layout_with_archive_info_marks_current() {
        let (dir, repo) = empty_repo();
        // Seed a real archive.info so the *current* cluster comes from there.
        // 14-1 has no backups -> would be dropped, but archive.info marks
        // db-id 1 as current here, so it must be preserved instead.
        seed_backup_info_full(
            &repo,
            "demo",
            &[(
                "20260201-100000F",
                500,
                "full",
                "000000010000000000002000",
                "000000010000000000002001",
                2,
            )],
            &[(1, "14"), (2, "15")],
            2,
        );
        // archive.info naming 14-1 (db-id 1) as the current cluster.
        let mut history = BTreeMap::new();
        history.insert(
            1u32,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_092,
                db_version: "14".to_owned(),
            },
        );
        history.insert(
            2u32,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_093,
                db_version: "15".to_owned(),
            },
        );
        let archive_info = pgbr_info::InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_092,
            db_version: "14".to_owned(),
            history,
        };
        repo.create_path(Path::new("archive/demo"), true)
            .expect("create archive/demo");
        archive_info
            .save(&repo, Path::new("archive/demo/archive.info"))
            .expect("save archive.info");

        seed_archive_id_segment(&repo, "demo", "14-1", "000000010000000000000500", "");
        seed_archive_id_segment(&repo, "demo", "15-2", "000000010000000000002000", "");

        expire_inner(&cfg_archive(Some("demo"), Some(1), Some(1)), &repo).expect("expire_inner");

        assert!(
            dir.path().join("archive/demo/14-1").exists(),
            "archive.info marks 14-1 current, so it is preserved despite having no backups"
        );
    }

    // Touch ArchiveIdPlan's public fields so the struct stays exercised even
    // if a future refactor stops constructing it in a test path.
    #[test]
    fn archive_id_plan_fields_are_public() {
        let plan = ArchiveIdPlan {
            archive_id: "14-1".to_owned(),
            drop_all: false,
            ranges: vec![ArchiveRange {
                start: "000000010000000000000001".to_owned(),
                stop: None,
            }],
            skip_expiry: false,
            history_timeline: Some("00000001".to_owned()),
        };
        assert_eq!(plan.archive_id, "14-1");
        assert!(!plan.drop_all);
        assert_eq!(plan.ranges.len(), 1);
    }
}
