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

use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_info::{InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath};
use pgbr_io::{Filter, Sha1};
use pgbr_postgres::lsn::{WAL_SEGMENT_SIZE_DEFAULT, lsn_text_to_wal_segment, parse_lsn};
use pgbr_protocol::message::{OkResponse, Request, Response};
use pgbr_protocol::parallel::{Job, ParallelExecutor};
use pgbr_storage::{Storage, StorageInfo, StorageKind};
use serde_json::json;

use crate::CommandError;
use crate::backup_control::{BackupControl, BackupServerInfo, BackupStopResult, LibpqBackupControl};
use crate::pipeline::{RepoTransform, metadata_compress_type_key, metadata_encrypted_key};

/// Default number of file-copy workers when no `process-max` is configured.
///
/// `backup_inner_typed` has no access to the resolved config (its signature is
/// fixed), so it uses a single worker — reproducing the prior serial behaviour
/// byte-for-byte. The public [`backup`] entry point reads `process-max` from the
/// configuration and routes through [`backup_inner_with_workers`] to fan out.
const DEFAULT_PROCESS_MAX: usize = 1;

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
/// runtime state that cannot be reused after recovery and so must not be
/// captured. A trailing-`/`-free entry matches either the directory itself or
/// any path beneath it. Mirrors pgBackRest's `manifestBuildInfo` directory
/// exclusions (C ref: `src/info/manifest/manifest.c`, the
/// `MANIFEST_TARGET_PGDATA` path skips).
const EXCLUDE_PREFIXES: &[&str] = &[
    "pg_wal",
    "pg_replslot",
    "pg_dynshmem",
    "pg_notify",
    "pg_serial",
    "pg_snapshots",
    "pg_stat_tmp",
    "pg_subtrans",
];

/// Exact PG-data **root-level** file names pgBackRest always excludes.
///
/// These are skipped only when the file sits directly in the data root (the
/// path has no `/` separator), exactly as pgBackRest's `manifestBuildInfo`
/// gates them on `manifestParentName == MANIFEST_TARGET_PGDATA`:
///
/// - `postmaster.pid` / `postmaster.opts` — running-process state that would
///   confuse a restored cluster.
/// - `recovery.signal` / `standby.signal` (PG >= 12) and `recovery.conf` /
///   `recovery.done` (PG < 12) — recovery control files recreated by restore.
/// - `postgresql.auto.conf.tmp` — temp file for the atomic auto.conf rewrite.
/// - `backup_label` / `backup_label.old` — obsolete in-progress backup markers.
/// - `backup_manifest` / `backup_manifest.tmp` (PG >= 13) — server-side backup
///   manifests, unrelated to pgBackRest's own manifest.
///
/// The per-version gating in pgBackRest is intentionally not reproduced here:
/// each name is excluded unconditionally, which is safe because none of these
/// is a real file pgBackRest would ever want to capture on any version.
const EXCLUDE_ROOT_FILES: &[&str] = &[
    "postmaster.pid",
    "postmaster.opts",
    "recovery.signal",
    "standby.signal",
    "recovery.conf",
    "recovery.done",
    "postgresql.auto.conf.tmp",
    "backup_label",
    "backup_label.old",
    "backup_manifest",
    "backup_manifest.tmp",
];

/// Basename pgBackRest excludes wherever it appears in a db path.
///
/// `pg_internal.init` is recreated on startup, so it is skipped regardless of
/// which directory holds it (e.g. `base/<db>/pg_internal.init`,
/// `global/pg_internal.init`). pgBackRest also tolerates a stray temp variant
/// `pg_internal.init.<pid>`; both forms are matched by [`is_pg_internal_init`].
const PG_INTERNAL_INIT: &str = "pg_internal.init";

/// Result of a successful [`backup_inner`], surfaced for tests / callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupOutcome {
    /// Label assigned to the backup, e.g. `"20240101-120000F"`.
    pub label: String,
    /// Number of files copied into the backup.
    pub file_count: usize,
    /// Total size, in bytes, of the copied files.
    pub total_size: u64,
    /// The backup-control bracket (start/stop LSN + WAL segments) when the
    /// backup was driven through `pg_backup_start` / `pg_backup_stop`; `None`
    /// for the DB-free file-copy-only path used by the unit tests.
    pub bracket: Option<BackupBracket>,
}

/// The `PostgreSQL` backup-control bracket captured around the file copy: the
/// start / stop LSNs and the WAL segment names they fall in.
///
/// pgBackRest records all four in the manifest and the `backup.info`
/// `[backup:current]` entry (`backup-lsn-start` / `backup-lsn-stop` /
/// `backup-archive-start` / `backup-archive-stop`) so expire / restore can
/// reason about WAL retention and recovery start points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupBracket {
    /// Textual start LSN returned by `pg_backup_start` (`"XXXXXXXX/YYYYYYYY"`).
    pub lsn_start: String,
    /// Textual stop LSN returned by `pg_backup_stop`.
    pub lsn_stop: String,
    /// WAL segment name containing the start LSN (`backup-archive-start`).
    pub archive_start: String,
    /// WAL segment name containing the stop LSN (`backup-archive-stop`).
    pub archive_stop: String,
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// Take the advisory lock(s) a command needs, holding them for its duration.
///
/// C ref: every mutating command opens with `lockAcquire(cfgLockType())`
/// (`src/main.c`). The lock category is fixed per command (backup → backup,
/// archive → archive, expire → backup, stanza-* → all); this helper maps that
/// [`LockType`] onto the on-disk `<lock-path>/<stanza>-<type>.lock` files via
/// [`crate::lock::lock_acquire`].
///
/// The returned handles must be bound (`let _locks = …;`) so they live to the
/// end of the command and release on drop. `LockType::None` and a `None`
/// stanza both yield an empty `Vec` (nothing to lock); the caller still binds
/// it, so two concurrent runs that *do* have a stanza collide as they should.
///
/// Lock-path resolution mirrors the rest of the crate: a real CLI run always
/// has the `lock-path` option resolved (its `config.yaml` default is
/// `/tmp/pgbackrest`), so the option is present and
/// [`crate::lock::resolved_lock_path`] returns the configured directory and the
/// lock is genuinely taken. Hand-built test configs that omit the `lock-path`
/// option no-op (empty `Vec`) so the many unit tests that drive these entry
/// points concurrently never collide on a shared default lock file; tests that
/// want to exercise locking set `lock-path` explicitly to an isolated temp dir.
///
/// # Errors
///
/// Returns whatever [`crate::lock::lock_acquire`] returns — notably
/// [`CommandError::Other`] when another run already holds the lock.
pub(crate) fn acquire_command_lock(
    config: &LoadedConfig,
    lock_type: LockType,
) -> Result<Vec<crate::lock::LockHandle>, CommandError> {
    // No stanza ⇒ nothing stanza-scoped to lock (commands that require a
    // stanza already error earlier; this keeps the helper total).
    let Some(stanza) = config.stanza.as_deref() else {
        return Ok(Vec::new());
    };
    if lock_type == LockType::None {
        return Ok(Vec::new());
    }
    // Only lock when a lock-path is actually configured. A resolved CLI run
    // always carries the option (default `/tmp/pgbackrest`); hand-built test
    // configs that omit it skip locking so parallel tests don't share a file.
    if !config.options.contains_key(&("lock-path".to_owned(), None)) {
        return Ok(Vec::new());
    }

    let lock_path = crate::lock::resolved_lock_path(config);
    crate::lock::lock_acquire(&lock_path, stanza, lock_type)
}

/// Whether a PG-data-relative path is excluded from the backup by the
/// **built-in** pgBackRest exclusion set (independent of any `--exclude`).
///
/// A path is excluded when any of the following holds:
///
/// - it equals an entry in [`EXCLUDE_PREFIXES`] or sits underneath one (the
///   entry is a `/`-separated path-component prefix), so `pg_walk` is *not*
///   excluded by `pg_wal`;
/// - it is a root-level file (no `/` in the path) whose name is in
///   [`EXCLUDE_ROOT_FILES`]; or
/// - its basename is `pg_internal.init` (or a `pg_internal.init.<digits>` temp
///   variant) anywhere in the tree — see [`is_pg_internal_init`].
fn is_excluded(rel: &str) -> bool {
    if EXCLUDE_PREFIXES
        .iter()
        .any(|prefix| rel == *prefix || rel.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/')))
    {
        return true;
    }

    // Root-level exact-name files: only excluded when directly in the data root
    // (mirrors pgBackRest gating these on `manifestParentName == PGDATA`).
    if !rel.contains('/') && EXCLUDE_ROOT_FILES.contains(&rel) {
        return true;
    }

    // pg_internal.init (and its temp variants) anywhere in the tree.
    let basename = rel.rsplit('/').next().unwrap_or(rel);
    is_pg_internal_init(basename)
}

/// Whether a basename is `pg_internal.init` or a `pg_internal.init.<digits>`
/// temp variant.
///
/// pgBackRest skips `pg_internal.init` (recreated on startup) and tolerates a
/// stray temp file `pg_internal.init.<pid>`. C ref: the `PG_FILE_PGINTERNALINIT`
/// check in `manifestBuildInfo`, which matches the bare name or the name
/// followed by `\.[0-9]+`.
fn is_pg_internal_init(basename: &str) -> bool {
    match basename.strip_prefix(PG_INTERNAL_INIT) {
        Some("") => true,
        Some(rest) => {
            // A `.<digits>` temp suffix: a leading dot then one-or-more digits.
            rest.strip_prefix('.')
                .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        }
        None => false,
    }
}

/// Whether a PG-data-relative path is excluded by a user-supplied `--exclude`
/// entry.
///
/// pgBackRest's `--exclude` accepts paths relative to the PG data root. For this
/// slice each entry is treated as such a relative path: `rel_path` is excluded
/// when it equals an entry exactly, or sits underneath one (the entry names a
/// directory whose entire subtree is excluded — i.e. `rel_path` starts with
/// `<entry>/`). Matching is on whole `/`-separated path components, so an entry
/// `mydir` excludes `mydir` and `mydir/file` but never `mydirx`. A trailing `/`
/// on an entry is tolerated (normalised away) so `pg_log/` and `pg_log` behave
/// identically. Empty entries never match.
fn is_user_excluded(rel_path: &str, excludes: &[String]) -> bool {
    excludes.iter().any(|raw| {
        let entry = raw.strip_suffix('/').unwrap_or(raw);
        !entry.is_empty() && (rel_path == entry || rel_path.strip_prefix(entry).is_some_and(|rest| rest.starts_with('/')))
    })
}

/// `PostgreSQL` data-page size — the unit page-checksum validation operates on.
///
/// Mirrors [`pgbr_postgres::page::BLCKSZ`] (8192). A relation file's bytes are
/// validated one `PAGE_SIZE` slice at a time.
const PAGE_SIZE: usize = pgbr_postgres::page::BLCKSZ;

/// Whether a PG-data-relative path is a *relation file* eligible for
/// page-checksum validation.
///
/// A relation file holds the heap / index / fork data `PostgreSQL` writes in
/// `PAGE_SIZE`-aligned data pages, each carrying the `pd_checksum` header field
/// that page-checksum validation verifies. pgBackRest validates the main, fsm
/// and vm forks; this slice recognises a file as a relation segment when **all**
/// of the following hold:
///
/// - it lives under `base/` (per-database relations), `global/` (shared
///   catalogs), or a tablespace path `pg_tblspc/<oid>/PG_<ver>_<cat>/...`, and
/// - its basename is a bare relfilenode — `<digits>` — optionally followed by a
///   `.<digits>` segment number (e.g. `1259`, `16384.1`).
///
/// Fork suffixes (`_fsm`, `_vm`, `_init`) and non-numeric files (`PG_VERSION`,
/// `pg_control`, `pg_filenode.map`, …) are **not** relation segments and return
/// `false`, as do files anywhere outside the three relation roots
/// (`pg_wal/...`, etc.).
fn is_relation_file(rel_path: &str) -> bool {
    let components: Vec<&str> = rel_path.split('/').collect();
    let (root_ok, depth_ok) = match components.first().copied() {
        // base/<db-oid>/<segment>
        Some("base") => (true, components.len() == 3),
        // global/<segment>
        Some("global") => (true, components.len() == 2),
        // pg_tblspc/<oid>/PG_<ver>_<cat>/<db-oid>/<segment>
        Some("pg_tblspc") => {
            let tblspc_shape = components.len() == 5
                && components
                    .get(2)
                    .is_some_and(|name| pgbr_postgres::tablespace::parse_tablespace_dir_name(name).is_some());
            (true, tblspc_shape)
        }
        _ => (false, false),
    };
    if !root_ok || !depth_ok {
        return false;
    }

    let Some(basename) = components.last() else {
        return false;
    };
    is_relation_segment_name(basename)
}

/// Whether a basename is a relation segment name: `<digits>` or
/// `<digits>.<digits>`.
///
/// Both the relfilenode and (when present) the segment number must be
/// non-empty all-ASCII-digit fields. This deliberately rejects fork suffixes
/// (`1259_vm`), the `pg_filenode.map`, `PG_VERSION`, and anything else
/// non-numeric.
fn is_relation_segment_name(name: &str) -> bool {
    let all_digits = |field: &str| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit());
    match name.split_once('.') {
        Some((node, segment)) => all_digits(node) && all_digits(segment),
        None => all_digits(name),
    }
}

/// Whether a single `PAGE_SIZE` page passes checksum validation.
///
/// An all-zero page is treated as valid (pgBackRest's empty-page handling: a
/// freshly extended but never-written page is all zeroes and carries no
/// meaningful checksum). Any other page is valid iff its stored `pd_checksum`
/// matches the value [`pgbr_postgres::page::pg_checksum_page`] computes for the
/// given `block_no`. A page whose length is not exactly `PAGE_SIZE` is treated
/// as invalid (it cannot be a well-formed data page).
fn is_valid_page(page: &[u8], block_no: u32) -> bool {
    if page.iter().all(|&b| b == 0) {
        return true;
    }
    pgbr_postgres::page::page_checksum_valid(page, block_no).unwrap_or(false)
}

/// Validate every page of a page-aligned relation file.
///
/// `bytes` must already be confirmed page-aligned (a multiple of `PAGE_SIZE`)
/// by the caller. Returns the (possibly empty) list of block numbers whose
/// stored checksum did not validate, in ascending order. An all-empty (or
/// empty-`bytes`) file yields an empty list.
fn validate_relation_pages(bytes: &[u8]) -> Vec<u32> {
    let mut invalid = Vec::new();
    for (idx, page) in bytes.chunks_exact(PAGE_SIZE).enumerate() {
        let block_no = u32::try_from(idx).unwrap_or(u32::MAX);
        if !is_valid_page(page, block_no) {
            invalid.push(block_no);
        }
    }
    invalid
}

/// Emit a `WARN` line naming a relation file's invalid pages.
///
/// The `ManifestFile` records only a `checksum_page = Some(false)` bool — it
/// has no invalid-page-list field (another concern owns that) — so the failing
/// block numbers surface here on stderr, matching pgBackRest's
/// `WARN: invalid page checksum(s) found in file ...` diagnostic.
#[allow(clippy::print_stderr)]
fn warn_invalid_pages(rel: &str, invalid_blocks: &[u32]) {
    let blocks = invalid_blocks.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    eprintln!("WARN: invalid page checksum(s) found in file {rel} at block(s) {blocks}");
}

/// Read a source file's Unix mode / owner uid / gid from its on-disk path.
///
/// Returns `(mode, uid, gid)` recorded into the [`ManifestFile`] on backup so
/// restore can re-apply the file mode (uid/gid are recorded only). The mode is
/// masked to the permission + setuid/setgid/sticky bits (`0o7777`), dropping the
/// file-type bits `st_mode` also carries. On non-Unix platforms (or if the stat
/// fails) every field is `None`. C ref: `ManifestFile.mode/user/group` in
/// `src/info/manifest.c`.
#[cfg(unix)]
fn file_mode_owner(abs_path: &Path) -> (Option<u32>, Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(abs_path).map_or((None, None, None), |meta| {
        (Some(meta.mode() & 0o7777), Some(meta.uid()), Some(meta.gid()))
    })
}

/// Non-Unix stub: file mode / owner are not modelled, so all three are `None`.
#[cfg(not(unix))]
fn file_mode_owner(_abs_path: &Path) -> (Option<u32>, Option<u32>, Option<u32>) {
    (None, None, None)
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

/// `backup` — take a backup of the active stanza, driven through the
/// `PostgreSQL` backup-control protocol when a DB connection is configured.
///
/// Computes the backup type / label / start timestamp and the resolved
/// transform / worker count / exclusions, resolves the backup-control
/// connection(s) per the `backup-standby` policy, then delegates to
/// [`run_backup`], which brackets the file copy with
/// `pg_backup_start` / `pg_backup_stop` (PG >= 15) or
/// `pg_start_backup` / `pg_stop_backup` (PG < 15). When no DB source is
/// configured the copy runs DB-free, exactly as before.
///
/// # Errors
///
/// See [`run_backup`]; plus connection failures and `backup-standby=y` with no
/// reachable standby.
#[allow(clippy::print_stdout)]
pub fn backup(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    // Hold the backup lock for the whole command. C ref: lockAcquire(lockTypeBackup).
    let _locks = acquire_command_lock(config, LockType::Backup)?;
    let backup_type = BackupType::from_options(config);
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let timestamp_start = i64::try_from(secs).unwrap_or(i64::MAX);
    let transform = RepoTransform::from_options(config);
    let process_max = process_max(config);
    let checksum_page = checksum_page_enabled(config);
    let excludes = excludes_from_config(config);
    let start_fast = start_fast_enabled(config);

    // File-bundling / block-incremental features. Validate the cross-option
    // constraints up front: bundling and repo-hardlink are mutually exclusive
    // (a bundled file has no standalone repo object to hard-link), and
    // block-incremental requires bundling (block bytes live in bundles).
    let features = BackupFeatures::from_options(config);
    validate_features(config, features)?;

    // Surface the applied user exclusions: pgBackRest records these in the
    // manifest's `[backup:option]` metadata, but the `Manifest` struct here owns
    // no exclude field (another concern), so for this slice the applied entries
    // are logged and used only to filter the walk.
    if !excludes.is_empty() {
        println!("backup will exclude user path(s): {}", excludes.join(", "));
    }

    // Resolve the backup-control connections per the `backup-standby` policy:
    // the *primary* connection drives pg_backup_start/stop, an optional *standby*
    // connection is polled for replay before the file copy. When no DB source is
    // configured the backup falls back to the DB-free file-copy path so a purely
    // local repo-only invocation still works. C ref: backup.c's dbGet().
    let ControlConnections {
        mut primary,
        mut standby,
    } = resolve_control_connections(config, standby_mode(config))?;

    // The diff label depends on the full it references, so it is computed inside
    // `run_backup` (which knows the full label); full labels are timestamp-derived
    // up front. Pass `None` to let the inner function pick.
    let outcome = run_backup(
        stanza,
        repo_storage,
        pg_storage,
        backup_type,
        None,
        timestamp_start,
        &transform,
        process_max,
        checksum_page,
        &excludes,
        primary.as_mut().map(|c| c as &mut dyn BackupControl),
        standby.as_mut().map(|c| c as &mut dyn BackupControl),
        start_fast,
        features,
    )?;
    println!(
        "backup {} complete: {} file(s), {} byte(s)",
        outcome.label, outcome.file_count, outcome.total_size
    );
    Ok(())
}

/// The backup-control connections resolved per the `backup-standby` policy.
struct ControlConnections {
    /// Connection that drives `pg_backup_start` / `pg_backup_stop` — the primary
    /// (not in recovery). `None` when no DB source is configured (DB-free path).
    primary: Option<LibpqBackupControl>,
    /// Optional in-recovery standby whose replay is polled before the file copy.
    standby: Option<LibpqBackupControl>,
}

/// Open the backup-control connection(s) the `backup-standby` policy calls for.
///
/// The candidate clusters are `DATABASE_URL` (treated as `pg1`) plus every
/// configured `pgN-host` / `pgN-socket-path` (`N` = 1..=8, pgBackRest's maximum).
/// Each reachable candidate is probed with `pg_is_in_recovery()`:
///
/// - the first non-recovery cluster becomes the `primary` (runs start/stop);
/// - the first in-recovery cluster becomes the `standby` (polled for replay).
///
/// Policy:
///
/// - [`StandbyMode::No`] — only the primary is used; no standby is opened.
/// - [`StandbyMode::Prefer`] — a standby is used when one is reachable + in
///   recovery, else the backup proceeds against the primary alone.
/// - [`StandbyMode::Yes`] — a reachable in-recovery standby is **required**; its
///   absence is a hard error.
///
/// When no DB source is configured at all, returns `{ primary: None, standby:
/// None }` (the DB-free file-copy path); `backup-standby=y` with no DB source is
/// an error, mirroring pgBackRest refusing a standby backup it cannot reach.
///
/// # Errors
///
/// [`CommandError::Other`] when a connection fails, when `backup-standby=y` but
/// no standby is reachable, or when no primary is reachable for a DB-driven run.
fn resolve_control_connections(config: &LoadedConfig, mode: StandbyMode) -> Result<ControlConnections, CommandError> {
    /// Highest `pgN` index pgBackRest supports.
    const MAX_PG_INDEX: u32 = 8;

    // Gather candidate conninfos, deduplicated, primary (pg1 / DATABASE_URL)
    // first so it is preferred as the primary when reachable + not in recovery.
    let mut conninfos: Vec<String> = Vec::new();
    if let Some(pg1) = derive_conninfo_with_url(config, std::env::var("DATABASE_URL").ok().as_deref()) {
        conninfos.push(pg1);
    }
    for index in 2..=MAX_PG_INDEX {
        if let Some(conninfo) = derive_conninfo_for_index(config, index)
            && !conninfos.contains(&conninfo)
        {
            conninfos.push(conninfo);
        }
    }

    // No DB configured at all: the DB-free path, unless a standby was demanded.
    if conninfos.is_empty() {
        if mode == StandbyMode::Yes {
            return Err(CommandError::Other(
                "backup-standby=y requires a reachable standby, but no PostgreSQL connection is configured".to_owned(),
            ));
        }
        return Ok(ControlConnections {
            primary: None,
            standby: None,
        });
    }

    let mut primary: Option<LibpqBackupControl> = None;
    let mut standby: Option<LibpqBackupControl> = None;
    for conninfo in &conninfos {
        let mut control = LibpqBackupControl::open(conninfo)?;
        let in_recovery = control.is_in_recovery()?;
        if in_recovery {
            if standby.is_none() && mode != StandbyMode::No {
                standby = Some(control);
            }
        } else if primary.is_none() {
            primary = Some(control);
        }
    }

    if mode == StandbyMode::Yes && standby.is_none() {
        return Err(CommandError::Other(
            "backup-standby=y requires a reachable in-recovery standby, but none was found".to_owned(),
        ));
    }
    if primary.is_none() {
        return Err(CommandError::Other(
            "no primary (non-recovery) PostgreSQL connection is reachable for backup".to_owned(),
        ));
    }

    Ok(ControlConnections { primary, standby })
}

/// Whether the resolved `start-fast` option is set (forces an immediate
/// checkpoint at `pg_backup_start`). `start-fast` is a `Boolean` defaulting to
/// false; absent or non-boolean values resolve to false.
fn start_fast_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("start-fast".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Resolve the `backup-standby` option to a [`StandbyMode`].
///
/// `backup-standby` is a `bool-like` string-id with allow-list `n` / `prefer` /
/// `y` (default `n`). Absent / unrecognised values resolve to [`StandbyMode::No`].
fn standby_mode(config: &LoadedConfig) -> StandbyMode {
    match config.options.get(&("backup-standby".to_owned(), None)) {
        Some(OptionValue::StringId(value)) if value == "y" => StandbyMode::Yes,
        Some(OptionValue::StringId(value)) if value == "prefer" => StandbyMode::Prefer,
        Some(OptionValue::Boolean(true)) => StandbyMode::Yes,
        _ => StandbyMode::No,
    }
}

/// The resolved `backup-standby` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandbyMode {
    /// `n` — never read files from a standby; always back up the primary.
    No,
    /// `prefer` — use a reachable in-recovery standby if one exists, else the
    /// primary.
    Prefer,
    /// `y` — require a standby; error if none is reachable / in recovery.
    Yes,
}

/// Build a libpq conninfo string for the cluster indexed by `pg_index` (1-based,
/// e.g. `2` → `pg2-*`), or `None` when no host / socket is configured for it.
///
/// Mirrors [`derive_conninfo_with_url`] but for an arbitrary `pgN` index, so the
/// `backup-standby` path can connect to a second cluster. A cluster is treated
/// as connectable only when a `pgN-host` or `pgN-socket-path` is configured (a
/// bare local `pgN-path` is not enough to imply a live server).
fn derive_conninfo_for_index(config: &LoadedConfig, pg_index: u32) -> Option<String> {
    let opt = |name: &str| -> Option<String> {
        match config.options.get(&(name.to_owned(), None)) {
            Some(OptionValue::String(s) | OptionValue::Path(s) | OptionValue::StringId(s)) if !s.is_empty() => Some(s.clone()),
            Some(OptionValue::Integer(i)) => Some(i.to_string()),
            _ => None,
        }
    };
    let host = opt(&format!("pg{pg_index}-host")).or_else(|| opt(&format!("pg{pg_index}-socket-path")))?;
    let mut parts: Vec<String> = vec![format!("host={host}")];
    if let Some(p) = opt(&format!("pg{pg_index}-port")) {
        parts.push(format!("port={p}"));
    }
    if let Some(db) = opt(&format!("pg{pg_index}-database")) {
        parts.push(format!("dbname={db}"));
    }
    if let Some(user) = opt(&format!("pg{pg_index}-user")) {
        parts.push(format!("user={user}"));
    }
    Some(parts.join(" "))
}

/// Build a libpq conninfo string for the primary cluster from the resolved
/// configuration, or `None` when no DB source is configured.
///
/// `database_url` is the already-resolved `DATABASE_URL` (the env read stays in
/// [`resolve_control_connections`] so this stays a pure, unit-testable helper).
/// It wins when set; otherwise the connection is derived from the `pg1-*`
/// options via [`derive_conninfo_for_index`]. Mirrors stanza.rs's
/// `derive_conninfo`, kept here so backup is self-contained.
fn derive_conninfo_with_url(config: &LoadedConfig, database_url: Option<&str>) -> Option<String> {
    if let Some(url) = database_url
        && !url.is_empty()
    {
        return Some(url.to_owned());
    }
    derive_conninfo_for_index(config, 1)
}

/// The user-supplied `--exclude` entries from the resolved config.
///
/// `exclude` is a `List` option (`("exclude", None)` → [`OptionValue::List`]).
/// Blank entries are dropped here so an empty or whitespace-only `--exclude`
/// never silently swallows the whole data directory; the remaining entries are
/// matched by [`is_user_excluded`]. Returns an empty `Vec` when the option is
/// absent or not a list.
fn excludes_from_config(config: &LoadedConfig) -> Vec<String> {
    match config.options.get(&("exclude".to_owned(), None)) {
        Some(OptionValue::List(entries)) => entries.iter().filter(|e| !e.trim().is_empty()).cloned().collect(),
        _ => Vec::new(),
    }
}

/// Default `repo-bundle-size` (20 MiB) when the option is absent.
const DEFAULT_BUNDLE_SIZE: u64 = 20 * 1024 * 1024;
/// Default `repo-bundle-limit` (2 MiB) when the option is absent.
const DEFAULT_BUNDLE_LIMIT: u64 = 2 * 1024 * 1024;

/// The bundling / block-incremental features a backup applies, resolved from the
/// `repo-bundle*` / `repo-block` options.
///
/// All-off ([`BackupFeatures::disabled`]) reproduces the prior per-file,
/// parallel copy path byte-for-byte; the `backup_inner_*` test wrappers always
/// pass that, so every existing test keeps its exact behaviour. The public
/// [`backup`] entry reads the real values from the resolved config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupFeatures {
    /// `repo-bundle=y`: pack small files into shared bundle objects.
    pub bundle: bool,
    /// `repo-bundle-size`: maximum bytes per bundle object.
    pub bundle_size: u64,
    /// `repo-bundle-limit`: files with a repo size at or below this are eligible
    /// for bundling; larger files stay as individual objects.
    pub bundle_limit: u64,
    /// `repo-block=y`: split large eligible files into blocks (requires `bundle`).
    pub block: bool,
}

impl BackupFeatures {
    /// All features off — the classic per-file parallel copy path.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            bundle: false,
            bundle_size: DEFAULT_BUNDLE_SIZE,
            bundle_limit: DEFAULT_BUNDLE_LIMIT,
            block: false,
        }
    }

    /// Read the bundling / block options from the resolved configuration.
    ///
    /// `repo-bundle` / `repo-block` are booleans; `repo-bundle-size` /
    /// `repo-bundle-limit` are `Size` (bytes). Absent size options fall back to
    /// pgBackRest's defaults (20 MiB / 2 MiB).
    #[must_use]
    pub fn from_options(config: &LoadedConfig) -> Self {
        let boolean = |name: &str| matches!(config.options.get(&(name.to_owned(), None)), Some(OptionValue::Boolean(true)));
        let size = |name: &str, default: u64| match config.options.get(&(name.to_owned(), None)) {
            Some(OptionValue::Size(value)) => *value,
            Some(OptionValue::Integer(value)) if *value >= 0 => u64::try_from(*value).unwrap_or(default),
            _ => default,
        };
        // Group options resolve to `repo1-...`; the `repoN-` prefix is stripped by
        // the config layer to the bare option name with a group index, but the CLI
        // also accepts the bare name (index None). Check both the indexed and
        // un-indexed forms so a hand-built or real config resolves either way.
        let boolean_grouped = |name: &str| boolean(name) || boolean_indexed(config, name);
        let size_grouped = |name: &str, default: u64| {
            let bare = size(name, default);
            if bare == default {
                size_indexed(config, name, default)
            } else {
                bare
            }
        };
        Self {
            bundle: boolean_grouped("repo-bundle"),
            bundle_size: size_grouped("repo-bundle-size", DEFAULT_BUNDLE_SIZE),
            bundle_limit: size_grouped("repo-bundle-limit", DEFAULT_BUNDLE_LIMIT),
            block: boolean_grouped("repo-block"),
        }
    }
}

/// Validate the cross-option constraints on the bundling / block features.
///
/// - **Bundling vs `repo-hardlink`** — a bundled file shares a repo object with
///   other files, so there is no standalone object to hard-link; the two are
///   mutually exclusive. (The option model's `depend` already disallows this in a
///   real CLI run, but the check is enforced here too so a hand-built config or a
///   future option-model change still fails loudly rather than producing a
///   corrupt backup.)
/// - **`repo-block` requires `repo-bundle`** — block bytes are stored inside
///   bundle objects, so block-incremental without bundling is rejected.
///
/// # Errors
///
/// [`CommandError::Other`] when either constraint is violated.
fn validate_features(config: &LoadedConfig, features: BackupFeatures) -> Result<(), CommandError> {
    if features.bundle && repo_hardlink_enabled(config) {
        return Err(CommandError::Other(
            "repo-bundle and repo-hardlink are mutually exclusive".to_owned(),
        ));
    }
    if features.block && !features.bundle {
        return Err(CommandError::Other("repo-block requires repo-bundle".to_owned()));
    }
    Ok(())
}

/// Whether `repo-hardlink=y` is set (checking both the un-indexed and `repoN-`
/// group-indexed forms, mirroring [`BackupFeatures::from_options`]).
fn repo_hardlink_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("repo-hardlink".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    ) || boolean_indexed(config, "repo-hardlink")
}

/// Read a boolean group option that resolved with a group index (`repo1-...`),
/// scanning indices 1..=8 (pgBackRest's repo maximum).
fn boolean_indexed(config: &LoadedConfig, name: &str) -> bool {
    (1..=8).any(|idx| {
        matches!(
            config.options.get(&(name.to_owned(), Some(idx))),
            Some(OptionValue::Boolean(true))
        )
    })
}

/// Read a `Size` group option that resolved with a group index (`repo1-...`),
/// returning the first set index's value or `default` when none is set.
fn size_indexed(config: &LoadedConfig, name: &str, default: u64) -> u64 {
    for idx in 1..=8 {
        match config.options.get(&(name.to_owned(), Some(idx))) {
            Some(OptionValue::Size(value)) => return *value,
            Some(OptionValue::Integer(value)) if *value >= 0 => return u64::try_from(*value).unwrap_or(default),
            _ => {}
        }
    }
    default
}

/// Number of parallel file-copy workers, from the resolved `process-max` option.
///
/// `process-max` is an `Integer` (default 1). Values `<= 0` clamp to one worker
/// so the copy phase always makes progress; the dispatcher additionally caps the
/// thread count at the number of files to copy.
fn process_max(config: &LoadedConfig) -> usize {
    match config.options.get(&("process-max".to_owned(), None)) {
        Some(OptionValue::Integer(value)) if *value >= 1 => usize::try_from(*value).unwrap_or(1),
        _ => 1,
    }
}

/// Whether `--checksum-page` page validation is enabled, from the resolved option.
///
/// `checksum-page` is a `Boolean`. For this slice the option is honoured as-is
/// and defaults to `false` when absent (pgBackRest's true default ties this to
/// whether the cluster has `data_checksums` enabled, which is resolved
/// elsewhere). When on, eligible relation files have every page's stored
/// checksum verified during the copy.
fn checksum_page_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("checksum-page".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
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

/// One file the copy phase must physically write into the backup.
///
/// Produced on the main thread by [`plan_file`] (which has already decided the
/// file is *not* a reference) and consumed by a worker thread, which reads
/// `abs_src`, runs the plaintext through the forward transform chain, and writes
/// the result to `abs_dest`. The fields are all owned so the job can cross the
/// thread boundary the parallel dispatcher imposes; `rel` correlates the worker's
/// result back to the planned [`ManifestFile`] skeleton.
#[derive(Debug, Clone)]
struct CopyJob {
    /// PG-data-relative path, used as the dispatcher correlation key.
    rel: String,
    /// Absolute source path of the file on disk (from `StorageInfo::path`).
    abs_src: PathBuf,
    /// Absolute destination path in the repo, suffix included.
    abs_dest: PathBuf,
    /// Whether the worker should page-checksum-validate this file. Set only for
    /// an eligible relation file when `--checksum-page` is on; the worker still
    /// re-checks page alignment before validating.
    validate_pages: bool,
}

/// What a worker reports back for one [`CopyJob`].
#[derive(Debug, Clone)]
struct CopyResult {
    /// Plaintext SHA-1 (lowercase hex) of the source file.
    checksum: String,
    /// Number of bytes physically written to the repo (post-transform).
    repo_bytes: u64,
    /// Page-checksum-validation outcome for this file: `None` when the file was
    /// not validated (checksum-page off, not a relation file, or not
    /// page-aligned); `Some(true)` when every page validated; `Some(false)` when
    /// one or more pages failed. When `Some(false)`, `invalid_blocks` lists them.
    checksum_page: Option<bool>,
    /// Block numbers whose stored checksum failed validation (empty unless
    /// `checksum_page == Some(false)`), used to emit a warning on the main thread.
    invalid_blocks: Vec<u32>,
}

/// Outcome of planning one PG-data file: either a finished (referenced) manifest
/// entry that needs no copy, or a skeleton entry plus the copy job that will
/// fill in its checksum once a worker has read the source.
enum FilePlan {
    /// File is unchanged vs the prior backup — recorded with a reference, not
    /// copied. The [`ManifestFile`] is complete.
    Referenced(ManifestFile),
    /// File must be copied. The skeleton carries everything except the checksum
    /// (filled from the worker's [`CopyResult`]); `job` describes the copy.
    Copy { skeleton: ManifestFile, job: CopyJob },
}

/// Decide how to capture one PG-data file, **without** doing any copy I/O.
///
/// For a diff or incr (`prior_manifest` is `Some`), a file whose size **and**
/// checksum match the prior backup's entry is unchanged: it is recorded with a
/// reference to the backup that **physically holds** the bytes (resolving the
/// prior's own reference, if any, so restore never chases a multi-hop chain) and
/// not copied. Detecting "unchanged" requires the plaintext checksum, so an
/// unchanged-candidate file is read and hashed here on the main thread; this
/// mirrors the C `manifestBuild` pass, which likewise decides references before
/// handing copy work to the parallel workers.
///
/// Any file that is new or changed (and every file in a full backup) yields a
/// [`FilePlan::Copy`] whose worker re-reads the source and computes the checksum
/// itself, so the bytes are read off disk exactly once on the copy path.
fn plan_file(
    pg_storage: &dyn Storage,
    entry: &WalkEntry,
    abs_repo_backup_root: &Path,
    transform: &RepoTransform,
    prior_manifest: Option<&Manifest>,
    prior_label: Option<&str>,
    checksum_page: bool,
) -> Result<FilePlan, CommandError> {
    // Capture the source file's Unix mode / owner from the metadata already on
    // disk (the same stat the walk performed for size/mtime). Recorded into the
    // manifest so restore can re-apply the file mode; `None` on non-Unix.
    let (mode, user, group) = file_mode_owner(&entry.info.path);
    let skeleton = ManifestFile {
        path: entry.rel.clone(),
        size: entry.info.size,
        timestamp: entry.info.modified.unwrap_or(0),
        checksum: None,
        checksum_page: None,
        reference: None,
        mode,
        user,
        group,
        bundle_id: None,
        bundle_offset: None,
        block_map: None,
    };

    // For a diff/incr: when the prior backup *might* hold this file unchanged
    // (same recorded size), hash the plaintext and compare checksums. A match
    // records a reference to the backup that physically holds the bytes and skips
    // the copy entirely. A size mismatch can never be unchanged, so it falls
    // through to the copy path without paying for a hash here.
    if let Some(prior_manifest) = prior_manifest
        && let Some(prior_file) = prior_manifest.file(&entry.rel)
        && prior_file.size == entry.info.size
    {
        let mut reader = pg_storage.open_read(&PathBuf::from(&entry.rel))?;
        let bytes = reader.read_all()?;
        let checksum = plaintext_sha1(&bytes)?;
        if prior_file.checksum.as_deref() == Some(checksum.as_str()) {
            let holder = prior_file.reference.clone().or_else(|| prior_label.map(ToOwned::to_owned));
            return Ok(FilePlan::Referenced(ManifestFile {
                checksum: Some(checksum),
                reference: holder,
                ..skeleton
            }));
        }
    }

    // Full backup, or a new / changed file in a diff / incr: copy it. The repo
    // filename carries the compression suffix; encryption does not change it.
    let abs_dest = abs_repo_backup_root.join(format!("{}{}", entry.rel, transform.repo_suffix()));
    // Page-checksum validation applies only when the option is on AND the file
    // is an eligible relation file. The worker re-checks page alignment before
    // validating (a non-page-aligned relation file is left unvalidated).
    let validate_pages = checksum_page && is_relation_file(&entry.rel);
    Ok(FilePlan::Copy {
        skeleton,
        job: CopyJob {
            rel: entry.rel.clone(),
            abs_src: entry.info.path.clone(),
            abs_dest,
            validate_pages,
        },
    })
}

/// Compute the plaintext SHA-1 (lowercase hex) of `bytes`.
///
/// pgBackRest records the *uncompressed* checksum regardless of how the bytes
/// are stored in the repo, so this is taken over the plaintext on both the
/// reference-detection (main thread) and copy (worker) paths.
fn plaintext_sha1(bytes: &[u8]) -> Result<String, CommandError> {
    let mut sha1 = Sha1::new();
    let mut sink = Vec::new();
    sha1.process(bytes, &mut sink)?;
    Ok(sha1.digest_hex())
}

/// Copy one file into the repo: read `abs_src`, compress-then-encrypt the
/// plaintext into the repo bytes (the identity transform passes them through),
/// create the destination's parent directory, and write `abs_dest`. Returns the
/// plaintext checksum + the number of repo bytes written.
///
/// This is the per-file unit of work run on a dispatcher worker thread. It does
/// all of its I/O through `std::fs` against absolute paths, so it needs no
/// `Storage` handle and no borrow from the caller — only the owned `transform`
/// captured by the worker closure.
fn copy_file(job: &CopyJob, transform: &RepoTransform) -> Result<CopyResult, CommandError> {
    let bytes = std::fs::read(&job.abs_src).map_err(|err| CommandError::Other(format!("read {}: {err}", job.abs_src.display())))?;

    let checksum = plaintext_sha1(&bytes)?;

    // Page-checksum validation runs on the same plaintext bytes the checksum is
    // taken over, before the transform. A relation file is only validated when
    // its size is an exact multiple of `PAGE_SIZE`; an unaligned file (or a
    // non-relation file, which is never flagged) is left unvalidated
    // (`checksum_page == None`).
    let (checksum_page, invalid_blocks) = if job.validate_pages && !bytes.is_empty() && bytes.len() % PAGE_SIZE == 0 {
        let invalid = validate_relation_pages(&bytes);
        (Some(invalid.is_empty()), invalid)
    } else {
        (None, Vec::new())
    };

    let repo_bytes = transform.apply_forward(&bytes)?;
    if let Some(parent) = job.abs_dest.parent() {
        std::fs::create_dir_all(parent).map_err(|err| CommandError::Other(format!("create {}: {err}", parent.display())))?;
    }
    std::fs::write(&job.abs_dest, &repo_bytes)
        .map_err(|err| CommandError::Other(format!("write {}: {err}", job.abs_dest.display())))?;

    Ok(CopyResult {
        checksum,
        repo_bytes: repo_bytes.len() as u64,
        checksum_page,
        invalid_blocks,
    })
}

/// Inputs to [`run_bundled_copy`]. Grouped into a struct so the signature stays
/// readable (and clippy's `too_many_arguments` stays happy).
struct BundledCopyCtx<'a> {
    /// Repository storage backend.
    repo_storage: &'a dyn Storage,
    /// `backup/<stanza>/<label>` repo-relative root of this backup.
    backup_root: &'a str,
    /// The compress + encrypt transform applied to every file (and block).
    transform: &'a RepoTransform,
    /// This backup's label (recorded as the holder of every block / file it
    /// physically stores).
    label: &'a str,
    /// Skeleton manifest entries for the files that must be copied (everything
    /// except the checksum). Correlated to [`Self::jobs`] by `path`.
    skeletons: Vec<ManifestFile>,
    /// The copy jobs (absolute source + page-validation flag) for those files.
    jobs: Vec<CopyJob>,
    /// Files already decided as whole-file references (unchanged in a diff/incr);
    /// passed through unchanged.
    referenced: Vec<ManifestFile>,
    /// The prior backup's manifest, for block-incremental block reuse on a
    /// diff/incr. `None` for a full backup.
    prior_manifest: Option<&'a Manifest>,
    /// The resolved bundling / block features.
    features: BackupFeatures,
    /// Backup start timestamp, used to compute each file's age for the block-size
    /// policy.
    timestamp_start: i64,
}

/// Serial copy pass for `repo-bundle=y` (and optionally `repo-block=y`).
///
/// Small files (repo size ≤ `repo-bundle-limit`) are packed into shared bundle
/// objects via [`crate::bundle::BundlePacker`]; each records its `bundle_id` /
/// `bundle_offset` in the manifest. Large files stay as individual repo objects
/// (the unbundled layout) **unless** `repo-block` is on and the file is
/// block-eligible, in which case it is split into blocks: each changed block is
/// transformed and appended to a bundle, unchanged blocks (matching the prior
/// backup's block map by checksum) are referenced, and a per-file block map is
/// recorded. A full backup writes a self-referencing block map so later
/// diff/incr backups have something to diff against.
///
/// Returns the completed manifest file entries plus the total repo bytes written.
///
/// # Errors
///
/// Propagates read / write / transform failures.
fn run_bundled_copy(ctx: BundledCopyCtx<'_>) -> Result<(Vec<ManifestFile>, u64), CommandError> {
    let mut files: Vec<ManifestFile> = ctx.referenced;
    let mut repo_size: u64 = 0;

    // Correlate jobs to skeletons by path so each file has both its planned
    // manifest entry and its absolute source / validation flag.
    let mut job_by_rel: std::collections::HashMap<String, CopyJob> = ctx.jobs.into_iter().map(|j| (j.rel.clone(), j)).collect();

    // The open bundle for small files; appended to in walk order. A separate
    // packer tracks block bundles so block and whole-file bundles never collide
    // in the same object (block bundles use ids offset above the file bundles).
    let mut file_packer = crate::bundle::BundlePacker::new(ctx.features.bundle_size);
    // Lazily-opened append writers keyed by bundle id, so each bundle object is
    // written once with all its members concatenated.
    let mut bundle_bytes: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();

    for skeleton in ctx.skeletons {
        let job = job_by_rel
            .remove(&skeleton.path)
            .ok_or_else(|| CommandError::Other(format!("no copy job for {}", skeleton.path)))?;
        let bytes =
            std::fs::read(&job.abs_src).map_err(|err| CommandError::Other(format!("read {}: {err}", job.abs_src.display())))?;
        let checksum = plaintext_sha1(&bytes)?;

        // Page-checksum validation, identical to the per-file path.
        let (checksum_page, invalid_blocks) = if job.validate_pages && !bytes.is_empty() && bytes.len() % PAGE_SIZE == 0 {
            let invalid = validate_relation_pages(&bytes);
            (Some(invalid.is_empty()), invalid)
        } else {
            (None, Vec::new())
        };
        if checksum_page == Some(false) {
            warn_invalid_pages(&skeleton.path, &invalid_blocks);
        }

        // Decide the block size for this file (age + size policy). A `Some` size
        // means block-incremental applies; `None` means store the file whole.
        let age = ctx.timestamp_start.saturating_sub(skeleton.timestamp);
        let block_size = if ctx.features.block {
            crate::block::block_size(skeleton.size, age)
        } else {
            None
        };

        let entry = if let Some(block_size) = block_size {
            // Block-incremental file: split, store changed blocks in bundles,
            // reference unchanged ones, record a per-file block map.
            let prior_map = ctx
                .prior_manifest
                .and_then(|m| m.file(&skeleton.path))
                .and_then(|f| f.block_map.as_ref());
            let block_map = build_block_map(
                &bytes,
                block_size,
                ctx.transform,
                ctx.label,
                prior_map,
                &mut bundle_bytes,
                &mut file_packer,
                &mut repo_size,
            )?;
            ManifestFile {
                checksum: Some(checksum),
                checksum_page,
                block_map: Some(block_map),
                ..skeleton
            }
        } else {
            // Whole file. Transform once; bundle it when it fits the limit,
            // otherwise write it as its own repo object (unbundled layout).
            let repo_bytes = ctx.transform.apply_forward(&bytes)?;
            let repo_len = repo_bytes.len() as u64;
            repo_size += repo_len;
            if repo_len <= ctx.features.bundle_limit {
                let slot = file_packer.place(repo_len);
                bundle_bytes.entry(slot.bundle_id).or_default().extend_from_slice(&repo_bytes);
                ManifestFile {
                    checksum: Some(checksum),
                    checksum_page,
                    bundle_id: Some(slot.bundle_id),
                    bundle_offset: Some(slot.offset),
                    ..skeleton
                }
            } else {
                // Over the limit: its own object at `<rel><suffix>`, as in the
                // unbundled path.
                let abs_dest = job.abs_dest.clone();
                if let Some(parent) = abs_dest.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|err| CommandError::Other(format!("create {}: {err}", parent.display())))?;
                }
                std::fs::write(&abs_dest, &repo_bytes)
                    .map_err(|err| CommandError::Other(format!("write {}: {err}", abs_dest.display())))?;
                ManifestFile {
                    checksum: Some(checksum),
                    checksum_page,
                    ..skeleton
                }
            }
        };
        files.push(entry);
    }

    // Flush every accumulated bundle object to the repo, creating the bundle
    // subdirectory first so the writes have a home.
    if !bundle_bytes.is_empty() {
        ctx.repo_storage
            .create_path(Path::new(&format!("{}/{}", ctx.backup_root, crate::bundle::BUNDLE_DIR)), true)?;
    }
    for (id, data) in bundle_bytes {
        let path = crate::bundle::bundle_object_path(ctx.backup_root, id);
        write_repo_file(ctx.repo_storage, &path, &data)?;
    }

    Ok((files, repo_size))
}

/// Build a block-incremental [`BlockMap`] for one file's `bytes`.
///
/// Each block is transformed (compress + encrypt) on its own. A block whose
/// plaintext checksum matches the prior backup's block at the same index is
/// *referenced* (its bytes are reused from the backup the prior pointed at, so
/// nothing new is stored); otherwise the transformed block is appended to a
/// bundle in *this* backup and the new location recorded. A full backup (no
/// prior map) stores every block here and the map self-references this backup.
///
/// `bundle_bytes` / `packer` / `repo_size` are the shared accumulators threaded
/// from [`run_bundled_copy`] so blocks share the same bundle objects as whole
/// bundled files.
///
/// # Errors
///
/// Propagates transform failures.
#[allow(clippy::too_many_arguments)]
fn build_block_map(
    bytes: &[u8],
    block_size: u64,
    transform: &RepoTransform,
    label: &str,
    prior_map: Option<&pgbr_info::manifest::BlockMap>,
    bundle_bytes: &mut std::collections::BTreeMap<u64, Vec<u8>>,
    packer: &mut crate::bundle::BundlePacker,
    repo_size: &mut u64,
) -> Result<pgbr_info::manifest::BlockMap, CommandError> {
    use pgbr_info::manifest::{BlockMap, BlockRef};

    let blocks = crate::block::split_blocks(bytes, block_size);
    let mut refs: Vec<BlockRef> = Vec::with_capacity(blocks.len());

    for (idx, block) in blocks.iter().enumerate() {
        let checksum = plaintext_sha1(block)?;

        // Reuse an unchanged block from the prior backup when its checksum matches.
        if let Some(prior) = prior_map.and_then(|m| m.blocks.get(idx))
            && prior.checksum == checksum
        {
            refs.push(prior.clone());
            continue;
        }

        // Changed / new block: transform it and append to a bundle in this backup.
        let repo_bytes = transform.apply_forward(block)?;
        let repo_len = repo_bytes.len() as u64;
        *repo_size += repo_len;
        let slot = packer.place(repo_len);
        bundle_bytes.entry(slot.bundle_id).or_default().extend_from_slice(&repo_bytes);
        refs.push(BlockRef {
            checksum,
            reference: label.to_owned(),
            bundle_id: slot.bundle_id,
            offset: slot.offset,
            size: repo_len,
        });
    }

    Ok(BlockMap {
        block_size,
        blocks: refs,
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

/// Encode a [`CopyJob`] as a dispatcher [`Request`]: the job's `rel` path is the
/// `cmd`, and the absolute source / destination paths ride in `param`.
///
/// The dispatcher's [`Job`]/[`Request`] shape (a command name plus a JSON
/// `param` array) is the only channel through which per-file work reaches a
/// worker, so the copy's inputs are serialised into it here and decoded back in
/// [`request_to_copy_job`]. The shared, owned `RepoTransform` is captured by the
/// worker closure rather than sent per job.
fn copy_job_to_request(job: &CopyJob) -> Request {
    Request {
        cmd: job.rel.clone(),
        param: vec![
            json!(job.abs_src.to_string_lossy()),
            json!(job.abs_dest.to_string_lossy()),
            json!(job.validate_pages),
        ],
    }
}

/// Decode a [`Request`] produced by [`copy_job_to_request`] back into a
/// [`CopyJob`] inside a worker.
fn request_to_copy_job(request: &Request) -> Result<CopyJob, String> {
    let abs_src = request
        .param
        .first()
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "copy job missing source path".to_owned())?;
    let abs_dest = request
        .param
        .get(1)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "copy job missing destination path".to_owned())?;
    // Older-shaped requests without the validate-pages flag default to false
    // (no page-checksum validation), preserving the prior behaviour.
    let validate_pages = request.param.get(2).and_then(serde_json::Value::as_bool).unwrap_or(false);
    Ok(CopyJob {
        rel: request.cmd.clone(),
        abs_src: PathBuf::from(abs_src),
        abs_dest: PathBuf::from(abs_dest),
        validate_pages,
    })
}

/// Run every [`CopyJob`] across `worker_count` workers via the in-process
/// dispatcher, returning each job's [`CopyResult`] keyed by its `rel` path.
///
/// Each worker re-decodes its job, reads the source, applies the (cloned, owned)
/// forward transform, and writes the repo file; its `(checksum, repo_bytes)`
/// outcome is serialised into the response `out` and collected here. The first
/// failing job surfaces as an `Err` (the dispatcher isolates panics into errors
/// too), so a copy failure fails the whole backup just as the serial path did.
///
/// `worker_count == 1` runs a single worker — byte-for-byte the prior serial
/// behaviour. Results come back in completion order; the caller correlates them
/// by key and re-sorts the manifest, so order does not affect the output.
fn run_copy_jobs(
    jobs: &[CopyJob],
    transform: &RepoTransform,
    worker_count: usize,
) -> Result<Vec<(String, CopyResult)>, CommandError> {
    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    let dispatcher_jobs: Vec<Job> = jobs
        .iter()
        .map(|job| Job {
            key: job.rel.clone(),
            request: copy_job_to_request(job),
        })
        .collect();

    // The dispatcher demands a `Send + Sync + 'static` worker, so the closure
    // can only borrow owned data: an owned clone of the transform (cheap) and
    // whatever rides in each `Request`. No `Storage` handle crosses the boundary
    // — workers do their I/O through `std::fs` against the absolute paths in the
    // request, so nothing borrowed from this stack frame escapes.
    let worker_transform = transform.clone();
    let results = ParallelExecutor::new(worker_count).run(dispatcher_jobs, move |request| {
        let job = request_to_copy_job(request)?;
        let copied = copy_file(&job, &worker_transform).map_err(|err| err.to_string())?;
        Ok(Response::Ok(OkResponse {
            out: Some(json!({
                "checksum": copied.checksum,
                "repoBytes": copied.repo_bytes,
                // `checksum_page` is `Option<bool>`: serialises to `null` when the
                // file was not validated, and the decoder maps `null` back to `None`.
                "checksumPage": copied.checksum_page,
                "invalidBlocks": copied.invalid_blocks,
            })),
        }))
    });

    let mut out = Vec::with_capacity(results.len());
    for job_result in results {
        match job_result.result {
            Ok(Response::Ok(OkResponse { out: Some(value) })) => {
                let checksum = value
                    .get("checksum")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| CommandError::Other(format!("copy of {} returned no checksum", job_result.key)))?
                    .to_owned();
                let repo_bytes = value
                    .get("repoBytes")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| CommandError::Other(format!("copy of {} returned no repo size", job_result.key)))?;
                // `checksumPage` is absent/`null` (not validated) or a bool.
                let checksum_page = match value.get("checksumPage") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => Some(v.as_bool().ok_or_else(|| {
                        CommandError::Other(format!("copy of {} returned a non-bool checksumPage", job_result.key))
                    })?),
                };
                let invalid_blocks = value
                    .get("invalidBlocks")
                    .and_then(serde_json::Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()))
                            .collect::<Vec<u32>>()
                    })
                    .unwrap_or_default();
                out.push((
                    job_result.key,
                    CopyResult {
                        checksum,
                        repo_bytes,
                        checksum_page,
                        invalid_blocks,
                    },
                ));
            }
            Ok(_) => {
                return Err(CommandError::Other(format!(
                    "copy of {} produced an unexpected empty response",
                    job_result.key
                )));
            }
            Err(message) => return Err(CommandError::Other(message)),
        }
    }
    Ok(out)
}

/// Resolve the absolute on-disk path of `relative` within `storage`.
///
/// Used to anchor each copy job's destination at an absolute path so the workers
/// (which use `std::fs`, not the `Storage` handle) write to the right place. The
/// directory must already exist; the caller creates the backup root first.
fn absolute_path(storage: &dyn Storage, relative: &Path) -> Result<PathBuf, CommandError> {
    Ok(storage.info(relative)?.path)
}

/// The classified result of walking the PG data dir: referenced files (decided
/// without copying), the skeletons + jobs for files that must be copied, and the
/// directory / symlink inventory.
struct BackupPlan {
    /// Files unchanged vs the prior backup — complete manifest entries, no copy.
    referenced: Vec<ManifestFile>,
    /// Skeletons for files that need copying; checksum is filled from the
    /// matching [`CopyResult`]. Parallel to nothing — correlated by `path`.
    copy_skeletons: Vec<ManifestFile>,
    /// The copy jobs handed to the worker pool, one per [`Self::copy_skeletons`].
    copy_jobs: Vec<CopyJob>,
    /// Directory entries.
    paths: Vec<ManifestPath>,
    /// Symlink entries.
    links: Vec<ManifestLink>,
}

/// Walk the PG data dir and classify every non-excluded entry into a
/// [`BackupPlan`], deciding diff/incr references on the main thread but deferring
/// the actual file copies to [`run_copy_jobs`].
///
/// Each entry is dropped when the built-in [`is_excluded`] set matches **or**
/// when a user-supplied `--exclude` entry matches via [`is_user_excluded`]; the
/// two are applied together, so `--exclude` extends (never replaces) the
/// built-in set.
///
/// # Errors
///
/// Propagates walk / read failures and any error from [`plan_file`].
fn plan_backup(
    pg_storage: &dyn Storage,
    abs_repo_backup_root: &Path,
    transform: &RepoTransform,
    prior_manifest: Option<&Manifest>,
    prior_label: Option<&str>,
    checksum_page: bool,
    excludes: &[String],
) -> Result<BackupPlan, CommandError> {
    let mut plan = BackupPlan {
        referenced: Vec::new(),
        copy_skeletons: Vec::new(),
        copy_jobs: Vec::new(),
        paths: Vec::new(),
        links: Vec::new(),
    };

    for entry in walk(pg_storage, Path::new("."))? {
        if is_excluded(&entry.rel) || is_user_excluded(&entry.rel, excludes) {
            continue;
        }

        match entry.info.kind {
            StorageKind::File => match plan_file(
                pg_storage,
                &entry,
                abs_repo_backup_root,
                transform,
                prior_manifest,
                prior_label,
                checksum_page,
            )? {
                FilePlan::Referenced(file) => plan.referenced.push(file),
                FilePlan::Copy { skeleton, job } => {
                    plan.copy_skeletons.push(skeleton);
                    plan.copy_jobs.push(job);
                }
            },
            StorageKind::Path => plan.paths.push(ManifestPath { path: entry.rel }),
            StorageKind::Link => {
                // TODO: resolve link target once `Storage` exposes a
                // link-target accessor; record an empty destination for now.
                plan.links.push(ManifestLink {
                    path: entry.rel,
                    destination: String::new(),
                });
            }
            // Sockets / FIFOs / devices are not part of a base backup.
            StorageKind::Special => {}
        }
    }

    Ok(plan)
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
    backup_inner_with_workers(
        stanza,
        repo_storage,
        pg_storage,
        backup_type,
        label,
        timestamp_start,
        transform,
        DEFAULT_PROCESS_MAX,
        false,
        &[],
    )
}

/// Take a backup of the given `backup_type`, copying files across `process_max`
/// parallel workers.
///
/// Identical to [`backup_inner_typed`] except the caller chooses the number of
/// file-copy workers (`process-max`). The copy phase fans out across the
/// in-process [`pgbr_protocol::parallel`] dispatcher: each non-referenced file
/// becomes a [`CopyJob`] that a worker reads, transforms (compress + encrypt),
/// and writes, returning its plaintext SHA-1 and repo size. Reference decisions
/// for diff / incr backups stay on the main thread (they need the prior
/// manifest), exactly as the C `manifestBuild` pass decides references before
/// dispatching copy work.
///
/// The manifest's file / path / link lists are sorted by path before the
/// manifest is assembled, so the on-disk `backup.manifest` — and therefore its
/// checksum — is identical regardless of the order in which workers finish.
/// `process_max == 1` reproduces the prior serial behaviour byte-for-byte.
///
/// `excludes` are user-supplied `--exclude` entries (PG-data-relative paths)
/// applied **in addition** to the built-in [`is_excluded`] set; pass `&[]` for
/// no extra exclusions.
///
/// # Errors
///
/// Same as [`backup_inner_typed`], plus a [`CommandError::Other`] if a copy
/// worker fails (its error message is propagated and fails the whole backup).
#[allow(clippy::too_many_arguments)]
pub fn backup_inner_with_workers(
    stanza: &str,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    backup_type: BackupType,
    label: Option<&str>,
    timestamp_start: i64,
    transform: &RepoTransform,
    process_max: usize,
    checksum_page: bool,
    excludes: &[String],
) -> Result<BackupOutcome, CommandError> {
    // No backup-control handle: the DB-free file-copy path the unit tests rely
    // on. `start-fast` is irrelevant without a server, so it defaults to false.
    run_backup(
        stanza,
        repo_storage,
        pg_storage,
        backup_type,
        label,
        timestamp_start,
        transform,
        process_max,
        checksum_page,
        excludes,
        None,
        None,
        false,
        BackupFeatures::disabled(),
    )
}

/// Core backup engine, optionally bracketed by the `PostgreSQL` backup-control
/// protocol.
///
/// When `control` is `Some`, the copy is wrapped in a non-exclusive online
/// backup on a single session: the server version + system identifier are
/// validated against the stanza's `backup.info`, `pg_backup_start` (PG >= 15) /
/// `pg_start_backup` (PG < 15) is called to get the start LSN, the data files
/// are copied, then `pg_backup_stop` / `pg_stop_backup` is called to get the
/// stop LSN and the `backup_label` / `tablespace_map` file contents (which are
/// written into the backup root). The start / stop LSNs and their WAL segment
/// names are recorded in the manifest's `[backup:current]` entry.
///
/// When `control` is `None` (the DB-free path) the copy runs exactly as before,
/// no server interaction happens, and no LSN / archive fields are recorded.
///
/// `start_fast` is the resolved `start-fast` option, passed to `backup_start`.
///
/// `standby` is an optional second control on a *standby* (in-recovery) cluster.
/// When present (a `backup-standby=y|prefer` run with a reachable standby), the
/// data files are read from the standby's data directory (already wired into
/// `pg_storage` by the caller) and, after `backup_start` runs on the primary
/// `control`, the standby is polled until it has replayed past the start LSN —
/// so the copied files include every change up to the start point.
///
/// # Errors
///
/// Same as [`backup_inner_with_workers`], plus [`CommandError::Other`] when the
/// server's version / system id does not match the stanza, or when any
/// backup-control query fails.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_backup(
    stanza: &str,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    backup_type: BackupType,
    label: Option<&str>,
    timestamp_start: i64,
    transform: &RepoTransform,
    process_max: usize,
    checksum_page: bool,
    excludes: &[String],
    mut control: Option<&mut dyn BackupControl>,
    mut standby: Option<&mut dyn BackupControl>,
    start_fast: bool,
    features: BackupFeatures,
) -> Result<BackupOutcome, CommandError> {
    let info_path = backup_info_path(stanza);
    if !repo_storage.exists(&info_path)? {
        return Err(CommandError::Other(
            "stanza not initialized; run stanza-create first".to_owned(),
        ));
    }

    let mut info = InfoBackup::load(repo_storage, &info_path).map_err(|err| CommandError::Other(err.to_string()))?;

    // Validate the live cluster against the stanza before touching any files:
    // a system-id / version mismatch means the configured PG is not the cluster
    // this stanza was created for. C ref: backup.c's dbGet() / dbPgCheck().
    let server_info = match control.as_mut() {
        Some(control) => Some(validate_server_against_stanza(&mut **control, &info)?),
        None => None,
    };

    // For a diff/incr, resolve the prior backup and load its manifest so
    // unchanged files can be detected by (size, checksum).
    let (prior_label, prior_manifest) = resolve_prior(repo_storage, stanza, backup_type, &info)?;

    let label = label.map_or_else(
        || derive_label(backup_type, prior_label.as_deref(), timestamp_start),
        ToOwned::to_owned,
    );

    let backup_root = format!("backup/{stanza}/{label}");

    // The backup root must exist before planning copies so the workers' absolute
    // destination paths anchor under a real directory (and so the manifest write
    // later has a home, even for an improbably empty cluster).
    repo_storage.create_path(Path::new(&backup_root), true)?;
    let abs_repo_backup_root = absolute_path(repo_storage, Path::new(&backup_root))?;

    // Begin the online backup (if a control connection is present). The start
    // LSN is captured now; the copy then runs while the backup is open.
    let start_lsn = match (control.as_mut(), server_info.as_ref()) {
        (Some(control), Some(_)) => Some(control.backup_start(&label, start_fast)?),
        _ => None,
    };

    // When backing up from a standby, the start ran on the primary but the files
    // are read from the standby; the standby must have replayed past the start
    // LSN before the copy so the captured files are consistent with it.
    if let (Some(standby), Some(start_lsn)) = (standby.as_mut(), start_lsn.as_ref()) {
        wait_for_standby_replay(&mut **standby, start_lsn)?;
    }

    // Walk the PG dir and classify every entry: referenced files (decided here,
    // not copied), copy jobs (dispatched to workers), directories, and links.
    // User `--exclude` entries are applied alongside the built-in exclusions.
    let mut plan = plan_backup(
        pg_storage,
        &abs_repo_backup_root,
        transform,
        prior_manifest.as_ref(),
        prior_label.as_deref(),
        checksum_page,
        excludes,
    )?;

    // Produce the file entries + total repo size. With bundling off this is the
    // classic per-file parallel copy (byte-for-byte unchanged); with bundling on
    // the small files are packed into shared bundle objects and large eligible
    // files may be block-split — a serial pass since a bundle object is appended
    // to in order.
    let referenced = std::mem::take(&mut plan.referenced);
    let (mut files, repo_size) = if features.bundle {
        run_bundled_copy(BundledCopyCtx {
            repo_storage,
            backup_root: &backup_root,
            transform,
            label: &label,
            skeletons: plan.copy_skeletons,
            jobs: plan.copy_jobs,
            referenced,
            prior_manifest: prior_manifest.as_ref(),
            features,
            timestamp_start,
        })?
    } else {
        let copy_results = run_copy_jobs(&plan.copy_jobs, transform, process_max)?;
        let mut result_by_rel: std::collections::HashMap<String, CopyResult> = copy_results.into_iter().collect();

        let mut files: Vec<ManifestFile> = referenced;
        let mut repo_size: u64 = 0;
        for skeleton in plan.copy_skeletons {
            let copied = result_by_rel
                .remove(&skeleton.path)
                .ok_or_else(|| CommandError::Other(format!("no copy result for {}", skeleton.path)))?;
            repo_size += copied.repo_bytes;
            // A file with one or more invalid pages records `checksum_page = Some(false)`
            // and a warning naming the bad blocks (the `ManifestFile` has no invalid-page
            // list field — another concern owns that — so the blocks surface only in the
            // warning, exactly as the task scopes it).
            if copied.checksum_page == Some(false) {
                warn_invalid_pages(&skeleton.path, &copied.invalid_blocks);
            }
            files.push(ManifestFile {
                checksum: Some(copied.checksum),
                checksum_page: copied.checksum_page,
                ..skeleton
            });
        }
        (files, repo_size)
    };
    let mut paths = plan.paths;
    let mut links = plan.links;

    // Sort every manifest list by path so the on-disk manifest (and its
    // checksum) is deterministic regardless of worker completion order.
    files.sort_by(|a, b| a.path.cmp(&b.path));
    paths.sort_by(|a, b| a.path.cmp(&b.path));
    links.sort_by(|a, b| a.path.cmp(&b.path));

    let total_size: u64 = files.iter().map(|f| f.size).sum();
    let file_count = files.len();
    let timestamp_stop = timestamp_start;

    // Close the online backup (on the same session) and assemble the bracket.
    // The stop also yields the `backup_label` / `tablespace_map` file contents,
    // which are written into the backup root. The backup timeline is taken from
    // the start LSN's WAL — for this slice (no streaming standby promotion) the
    // start and stop share timeline 1; pgBackRest reads the real timeline from
    // pg_control, deferred until the fuller pg_control decode lands.
    let bracket = match (control.as_mut(), start_lsn) {
        (Some(control), Some(start_lsn)) => {
            let stop = control.backup_stop()?;
            write_backup_label_files(repo_storage, &backup_root, &stop)?;
            Some(build_bracket(&start_lsn, &stop)?)
        }
        _ => None,
    };

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

    // The backup root was created up front (before planning copies), so it
    // exists even for an improbably empty cluster and the manifest write has a
    // home.
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
    // The on-disk version / system id recorded for restore parity. When the
    // backup was DB-driven these come from the live server (already validated to
    // match the stanza); otherwise they mirror the stanza's recorded identity.
    entry["db-version"] = json!(info.db_version);
    entry["db-system-id"] = json!(info.db_system_id);
    // Record the backup-control bracket (start/stop LSN + WAL segments) when the
    // backup was driven through pg_backup_start/stop.
    if let Some(bracket) = bracket.as_ref() {
        entry["backup-lsn-start"] = json!(bracket.lsn_start);
        entry["backup-lsn-stop"] = json!(bracket.lsn_stop);
        entry["backup-archive-start"] = json!(bracket.archive_start);
        entry["backup-archive-stop"] = json!(bracket.archive_stop);
    }
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
        bracket,
    })
}

/// Validate a live server's identity against the stanza's `backup.info`.
///
/// The system identifier must match exactly (a mismatch means the configured PG
/// is a *different* cluster), and the server's major-version label must equal
/// the stanza's `db-version`. C ref: `dbPgCheck` in `src/command/backup/backup.c`,
/// which raises `DbMismatchError` on either disagreement.
///
/// Returns the validated [`BackupServerInfo`] on success.
///
/// # Errors
///
/// [`CommandError::Other`] when the server cannot be queried or its identity
/// disagrees with the stanza.
fn validate_server_against_stanza(control: &mut dyn BackupControl, info: &InfoBackup) -> Result<BackupServerInfo, CommandError> {
    let server = control.server_info()?;
    if server.system_identifier != info.db_system_id {
        return Err(CommandError::Other(format!(
            "backup database system-id {} does not match stanza db-system-id {}",
            server.system_identifier, info.db_system_id
        )));
    }
    let server_label = pgbr_postgres::version::SUPPORTED
        .iter()
        .find(|v| {
            // PG < 10 keeps the `.x` minor in the label; PG >= 10 is the bare major.
            let major = server.release_major();
            if major == 9 {
                v.label.starts_with("9.")
            } else {
                v.label == major.to_string()
            }
        })
        .map(|v| v.label);
    if let Some(server_label) = server_label
        && server_label != info.db_version
    {
        return Err(CommandError::Other(format!(
            "backup database version {} does not match stanza db-version {}",
            server_label, info.db_version
        )));
    }
    Ok(server)
}

/// Write the `backup_label` and (when non-empty) `tablespace_map` files
/// returned by `pg_backup_stop` into the backup root.
///
/// pgBackRest stores these alongside the copied data so a restore can place
/// `backup_label` at the data-root and re-create the tablespace symlinks from
/// `tablespace_map`. An empty `spcmapfile` (a cluster with no tablespaces) is
/// not written.
///
/// # Errors
///
/// [`CommandError::Storage`] / [`CommandError::Io`] on write failure.
fn write_backup_label_files(repo_storage: &dyn Storage, backup_root: &str, stop: &BackupStopResult) -> Result<(), CommandError> {
    write_repo_file(
        repo_storage,
        &format!("{backup_root}/backup_label"),
        stop.label_file.as_bytes(),
    )?;
    if !stop.spcmap_file.is_empty() {
        write_repo_file(
            repo_storage,
            &format!("{backup_root}/tablespace_map"),
            stop.spcmap_file.as_bytes(),
        )?;
    }
    Ok(())
}

/// Write `bytes` to a repository-relative path via the storage backend.
fn write_repo_file(repo_storage: &dyn Storage, rel: &str, bytes: &[u8]) -> Result<(), CommandError> {
    let mut writer = repo_storage.open_write(Path::new(rel))?;
    writer.write(bytes)?;
    writer.flush()?;
    writer.close()?;
    Ok(())
}

/// Poll a standby's replay position until it has caught up to (or past) the
/// backup `start_lsn`.
///
/// pgBackRest reads the standby's data files only after the standby has replayed
/// the WAL up to the primary's backup start point; otherwise the copied files
/// could predate the start LSN and the restore would be inconsistent. C ref:
/// `backupStandbyInit` / the `pg_last_wal_replay_lsn()` loop in
/// `src/command/backup/backup.c`.
///
/// The poll loops until the parsed replay LSN is `>= start_lsn`, sleeping briefly
/// between attempts, with a bounded number of attempts so a wedged standby fails
/// the backup rather than hanging forever.
///
/// # Errors
///
/// [`CommandError::Other`] when the standby cannot be queried, returns an
/// unparseable LSN, or does not catch up within the attempt budget.
fn wait_for_standby_replay(standby: &mut dyn BackupControl, start_lsn: &str) -> Result<(), CommandError> {
    /// Maximum number of replay-position polls before giving up.
    const MAX_ATTEMPTS: u32 = 600;
    /// Delay between polls.
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

    let target =
        parse_lsn(start_lsn).ok_or_else(|| CommandError::Other(format!("backup start returned an invalid LSN: {start_lsn}")))?;

    for attempt in 0..MAX_ATTEMPTS {
        if let Some(replay_text) = standby.replay_lsn()? {
            let replayed = parse_lsn(&replay_text)
                .ok_or_else(|| CommandError::Other(format!("standby replay returned an invalid LSN: {replay_text}")))?;
            if replayed >= target {
                return Ok(());
            }
        }
        // Don't sleep after the final attempt — fall straight through to the error.
        if attempt + 1 < MAX_ATTEMPTS {
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    Err(CommandError::Other(format!(
        "standby did not replay to backup start LSN {start_lsn} within {MAX_ATTEMPTS} attempts"
    )))
}

/// Build a [`BackupBracket`] from the textual start LSN and the stop result.
///
/// Each LSN is mapped to the WAL segment that contains it on timeline 1 using
/// the default 16 MiB segment size (the only size this slice models — the real
/// timeline + `wal_segment_size` come from `pg_control`, deferred to the fuller
/// decode). An unparseable LSN is a hard error: the server returned something
/// that is not a `PostgreSQL` LSN.
///
/// # Errors
///
/// [`CommandError::Other`] when either LSN cannot be parsed.
fn build_bracket(start_lsn: &str, stop: &BackupStopResult) -> Result<BackupBracket, CommandError> {
    const TIMELINE: u32 = 1;
    // Confirm both LSNs parse (the WAL-segment derivation needs valid hex halves).
    if parse_lsn(start_lsn).is_none() {
        return Err(CommandError::Other(format!(
            "backup start returned an invalid LSN: {start_lsn}"
        )));
    }
    if parse_lsn(&stop.lsn).is_none() {
        return Err(CommandError::Other(format!(
            "backup stop returned an invalid LSN: {}",
            stop.lsn
        )));
    }
    let archive_start = lsn_text_to_wal_segment(TIMELINE, start_lsn, WAL_SEGMENT_SIZE_DEFAULT)
        .ok_or_else(|| CommandError::Other(format!("could not derive WAL segment for start LSN {start_lsn}")))?;
    let archive_stop = lsn_text_to_wal_segment(TIMELINE, &stop.lsn, WAL_SEGMENT_SIZE_DEFAULT)
        .ok_or_else(|| CommandError::Other(format!("could not derive WAL segment for stop LSN {}", stop.lsn)))?;
    Ok(BackupBracket {
        lsn_start: start_lsn.to_owned(),
        lsn_stop: stop.lsn.clone(),
        archive_start,
        archive_stop,
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

    #[cfg(unix)]
    #[test]
    fn backup_records_file_mode_and_owner() {
        // A seeded file with an explicit mode must have that mode (and the
        // process's uid/gid) recorded in the manifest on Unix.
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation-data-with-mode");

        // Set a distinctive, non-default mode on the source file.
        let abs_src = pg_s.info(Path::new("base/1/1259")).expect("stat source").path;
        std::fs::set_permissions(&abs_src, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        let src_meta = std::fs::metadata(&abs_src).expect("metadata");

        backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("backup");

        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("load manifest");
        let file = manifest.file("base/1/1259").expect("file in manifest");
        assert_eq!(file.mode, Some(0o640), "manifest must record the source file mode");
        assert_eq!(file.user, Some(src_meta.uid()), "manifest must record the source uid");
        assert_eq!(file.group, Some(src_meta.gid()), "manifest must record the source gid");
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
    fn is_excluded_covers_root_files_and_pg_internal_init() {
        // Root-level recovery / backup-label / postmaster files are excluded only
        // when they sit directly in the data root.
        assert!(is_excluded("recovery.signal"));
        assert!(is_excluded("standby.signal"));
        assert!(is_excluded("recovery.conf"));
        assert!(is_excluded("recovery.done"));
        assert!(is_excluded("backup_label.old"));
        assert!(is_excluded("backup_label"));
        assert!(is_excluded("backup_manifest"));
        assert!(is_excluded("backup_manifest.tmp"));
        assert!(is_excluded("postgresql.auto.conf.tmp"));
        assert!(is_excluded("postmaster.opts"));
        assert!(is_excluded("postmaster.pid"));

        // The same names *nested* under a subdir are NOT root files, so they are
        // not excluded by the root-file rule (a relation named recovery.signal is
        // implausible, but the gating must match pgBackRest's PGDATA-root check).
        assert!(!is_excluded("base/1/recovery.signal"));
        assert!(!is_excluded("subdir/backup_label"));

        // tablespace_map is a REAL file pgBackRest backs up — never excluded.
        assert!(!is_excluded("tablespace_map"));

        // pg_internal.init is excluded wherever it appears (db paths), incl. the
        // `.<pid>` temp variant; a non-numeric suffix is NOT the temp form.
        assert!(is_excluded("pg_internal.init"));
        assert!(is_excluded("base/1/pg_internal.init"));
        assert!(is_excluded("global/pg_internal.init"));
        assert!(is_excluded("base/16384/pg_internal.init.4242"));
        assert!(!is_excluded("base/1/pg_internal.init.bak"));
        assert!(!is_excluded("base/1/pg_internal.initial"));
    }

    #[test]
    fn is_pg_internal_init_matches_bare_and_temp_variants() {
        assert!(is_pg_internal_init("pg_internal.init"));
        assert!(is_pg_internal_init("pg_internal.init.0"));
        assert!(is_pg_internal_init("pg_internal.init.12345"));
        // Not matches: a trailing dot with no digits, non-numeric suffix, or a
        // longer name that merely begins with the literal.
        assert!(!is_pg_internal_init("pg_internal.init."));
        assert!(!is_pg_internal_init("pg_internal.init.x"));
        assert!(!is_pg_internal_init("pg_internal.initial"));
        assert!(!is_pg_internal_init("PG_VERSION"));
    }

    #[test]
    fn is_user_excluded_exact_subtree_and_non_match() {
        let excludes = vec!["mydir".to_owned(), "afile".to_owned()];
        // Exact match.
        assert!(is_user_excluded("mydir", &excludes));
        assert!(is_user_excluded("afile", &excludes));
        // Subtree match: anything under an excluded directory.
        assert!(is_user_excluded("mydir/sub/leaf", &excludes));
        assert!(is_user_excluded("mydir/file", &excludes));
        // Non-match: a sibling sharing a prefix, or an unrelated path.
        assert!(!is_user_excluded("mydirx", &excludes));
        assert!(!is_user_excluded("afilex", &excludes));
        assert!(!is_user_excluded("base/1/1259", &excludes));
        // No excludes → nothing matches.
        assert!(!is_user_excluded("mydir", &[]));
    }

    #[test]
    fn is_user_excluded_tolerates_trailing_slash_and_empties() {
        let excludes = vec!["pg_log/".to_owned(), String::new()];
        // A trailing slash on the entry is normalised away.
        assert!(is_user_excluded("pg_log", &excludes));
        assert!(is_user_excluded("pg_log/server.log", &excludes));
        // An empty entry never matches (would otherwise swallow everything).
        assert!(!is_user_excluded("", &excludes));
        assert!(!is_user_excluded("anything", &[String::new()]));
    }

    #[test]
    fn excludes_from_config_reads_list_and_drops_blanks() {
        let cfg = |opts: BTreeMap<(String, Option<u32>), OptionValue>| LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: opts,
            params: Vec::new(),
        };
        // Absent → empty.
        assert!(excludes_from_config(&cfg(BTreeMap::new())).is_empty());
        // A List with a blank entry drops the blank, keeps the rest.
        let mut opts = BTreeMap::new();
        opts.insert(
            ("exclude".to_owned(), None),
            OptionValue::List(vec!["mydir".to_owned(), "  ".to_owned(), "afile".to_owned()]),
        );
        assert_eq!(excludes_from_config(&cfg(opts)), vec!["mydir".to_owned(), "afile".to_owned()]);
    }

    #[test]
    fn backup_excludes_user_paths() {
        // A backup with --exclude=["mydir","afile"] must omit those paths (and a
        // subtree under mydir) from the manifest while siblings remain.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"keep this relation");
        seed_file(&pg_s, "afile", b"user-excluded top-level file");
        seed_file(&pg_s, "mydir/data", b"user-excluded dir content");
        seed_file(&pg_s, "mydir/nested/deep", b"deep user-excluded content");
        // A sibling that merely shares a prefix must NOT be excluded.
        seed_file(&pg_s, "afilexyz", b"sibling kept");
        seed_file(&pg_s, "mydirx/data", b"sibling dir kept");

        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(
            ("exclude".to_owned(), None),
            OptionValue::List(vec!["mydir".to_owned(), "afile".to_owned()]),
        );
        let cfg = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        };

        backup(&cfg, &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");
        let listed: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();

        // User-excluded entries (and the mydir subtree) are absent.
        assert!(!listed.contains(&"afile"), "afile must be excluded: {listed:?}");
        assert!(
            !listed.iter().any(|p| *p == "mydir" || p.starts_with("mydir/")),
            "mydir subtree must be excluded: {listed:?}"
        );
        // Siblings sharing a prefix remain, as does the unrelated relation.
        assert!(listed.contains(&"afilexyz"), "prefix-sibling file must remain: {listed:?}");
        assert!(listed.contains(&"mydirx/data"), "prefix-sibling dir must remain: {listed:?}");
        assert!(listed.contains(&"base/1/1259"), "unrelated relation must remain: {listed:?}");

        // The excluded files were not physically copied either.
        let backup_root = repo_dir.path().join(format!("backup/demo/{label}"));
        assert!(!backup_root.join("afile").exists(), "afile must not be copied");
        assert!(!backup_root.join("mydir").exists(), "mydir must not be copied");
    }

    #[test]
    fn backup_excludes_new_builtin_files() {
        // The extended built-in exclusion set must skip pg_internal.init,
        // recovery/standby signal files, backup_label.old and postmaster.opts
        // even though they were seeded into the cluster.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"keep this relation");
        seed_file(&pg_s, "global/pg_internal.init", b"shared internal init");
        seed_file(&pg_s, "base/1/pg_internal.init", b"per-db internal init");
        seed_file(&pg_s, "recovery.signal", b"");
        seed_file(&pg_s, "standby.signal", b"");
        seed_file(&pg_s, "recovery.conf", b"restore_command = ...");
        seed_file(&pg_s, "backup_label.old", b"obsolete label");
        seed_file(&pg_s, "postmaster.opts", b"opts");

        backup(&typed_cfg("demo", "full"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        for excluded in [
            "global/pg_internal.init",
            "base/1/pg_internal.init",
            "recovery.signal",
            "standby.signal",
            "recovery.conf",
            "backup_label.old",
            "postmaster.opts",
        ] {
            assert!(
                manifest.file(excluded).is_none(),
                "{excluded} must be excluded from the manifest"
            );
            let backup_root = repo_dir.path().join(format!("backup/demo/{label}"));
            assert!(!backup_root.join(excluded).exists(), "{excluded} must not be copied");
        }
        // The real relation survives.
        assert!(manifest.file("base/1/1259").is_some(), "real relation must be backed up");
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

    /// `typed_cfg` plus an explicit `lock-path` so the command takes a real
    /// advisory lock under an isolated directory (no shared default path).
    fn typed_cfg_locked(stanza: &str, backup_type: &str, lock_path: &Path) -> LoadedConfig {
        let mut cfg = typed_cfg(stanza, backup_type);
        cfg.options.insert(
            ("lock-path".to_owned(), None),
            OptionValue::Path(lock_path.to_string_lossy().into_owned()),
        );
        cfg
    }

    #[test]
    fn backup_acquires_backup_lock() {
        // Backup must take the `<stanza>-backup.lock` under the configured
        // lock-path for its whole duration, so a concurrent run can't collide.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let cfg = typed_cfg_locked("demo", "full", lock_dir.path());
        let expected_lock = lock_dir.path().join("demo-backup.lock");

        // Simulate a *concurrent* backup already holding the lock: a fresh
        // `backup` must then fail with the "another backup is running" error,
        // proving the entry point genuinely acquires the backup lock.
        let held = crate::lock::lock_acquire(lock_dir.path(), "demo", LockType::Backup).expect("pre-acquire backup lock");
        assert!(expected_lock.exists(), "lock file must appear while held");

        let err = backup(&cfg, &repo_s, &pg_s).expect_err("backup must fail while the backup lock is held");
        assert!(
            err.to_string().contains("another backup is running"),
            "unexpected error: {err}"
        );

        // Releasing the concurrent lock lets a backup run to completion; the
        // handle drops at return so the stale lock file is cleaned up.
        drop(held);
        backup(&cfg, &repo_s, &pg_s).expect("backup succeeds once the lock is free");
        assert!(
            !expected_lock.exists(),
            "lock file must be removed after the command releases it"
        );
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

    // ---- parallel file copy ------------------------------------------------

    /// A comparable, order-independent view of a manifest's file entries:
    /// `(path, size, checksum, reference)` tuples sorted by path. Used to assert
    /// two backups produced identical manifests regardless of worker order.
    fn manifest_file_tuples(manifest: &Manifest) -> Vec<(String, u64, Option<String>, Option<String>)> {
        let mut tuples: Vec<_> = manifest
            .files
            .iter()
            .map(|f| (f.path.clone(), f.size, f.checksum.clone(), f.reference.clone()))
            .collect();
        tuples.sort();
        tuples
    }

    /// Seed a cluster with enough files that 4 workers actually have work to
    /// spread, including a couple of nested directories.
    fn seed_many_files(pg: &Posix, count: usize) {
        seed_file(pg, "PG_VERSION", b"14\n");
        seed_file(pg, "global/pg_control", b"\x01\x02\x03\x04");
        for n in 0..count {
            let content = format!("relation data for file number {n}, padded padded padded padded {n}");
            seed_file(pg, &format!("base/1/{}", 1000 + n), content.as_bytes());
        }
    }

    #[test]
    fn backup_parallel_matches_serial() {
        // A full backup of the same seeded data with process-max=1 and
        // process-max=4 must yield identical manifests (files, sizes, checksums,
        // references) and byte-identical repo contents — the parallel path only
        // changes *how* the copy work is scheduled, never the result. Two repos
        // are used so the runs do not interfere; the PG data is identical.
        let pg_dir = tempfile::tempdir().expect("pg tempdir");
        let pg_s = Posix::new(pg_dir.path());
        seed_many_files(&pg_s, 12);

        let repo1_dir = tempfile::tempdir().expect("repo1 tempdir");
        let repo2_dir = tempfile::tempdir().expect("repo2 tempdir");
        let repo1_s = Posix::new(repo1_dir.path());
        let repo2_s = Posix::new(repo2_dir.path());
        init_stanza(&repo1_s, "demo");
        init_stanza(&repo2_s, "demo");

        backup_inner_with_workers(
            "demo",
            &repo1_s,
            &pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
            1,
            false,
            &[],
        )
        .expect("serial backup");
        backup_inner_with_workers(
            "demo",
            &repo2_s,
            &pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
            4,
            false,
            &[],
        )
        .expect("parallel backup");

        let manifest_path = format!("backup/demo/{LABEL}/backup.manifest");
        let m1 = Manifest::load(&repo1_s, Path::new(&manifest_path)).expect("serial manifest");
        let m4 = Manifest::load(&repo2_s, Path::new(&manifest_path)).expect("parallel manifest");

        // Identical file inventory (path, size, checksum, reference).
        assert_eq!(
            manifest_file_tuples(&m1),
            manifest_file_tuples(&m4),
            "parallel and serial manifests must list identical files"
        );

        // The on-disk manifest bytes (and thus the backrest-checksum) must match
        // exactly, proving the deterministic sort makes order irrelevant.
        let bytes1 = std::fs::read(repo1_dir.path().join(&manifest_path)).unwrap();
        let bytes4 = std::fs::read(repo2_dir.path().join(&manifest_path)).unwrap();
        assert_eq!(bytes1, bytes4, "serialised backup.manifest must be byte-identical");

        // Every copied repo file is byte-identical across the two runs.
        for file in &m1.files {
            let p1 = repo1_dir.path().join(format!("backup/demo/{LABEL}/{}", file.path));
            let p4 = repo2_dir.path().join(format!("backup/demo/{LABEL}/{}", file.path));
            assert_eq!(
                std::fs::read(&p1).unwrap(),
                std::fs::read(&p4).unwrap(),
                "repo file {} differs",
                file.path
            );
        }
    }

    #[test]
    fn backup_process_max_4_uses_workers() {
        // A backup with process-max=4 over several files succeeds, lists every
        // expected file in the manifest with the correct plaintext checksum, and
        // physically writes each one into the backup dir.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let mut expected: Vec<(String, Vec<u8>)> = Vec::new();
        seed_file(&pg_s, "PG_VERSION", b"14\n");
        expected.push(("PG_VERSION".to_owned(), b"14\n".to_vec()));
        for n in 0..8 {
            let rel = format!("base/1/{}", 2000 + n);
            let content = format!("worker file {n} contents contents contents {n}").into_bytes();
            seed_file(&pg_s, &rel, &content);
            expected.push((rel, content));
        }

        backup_inner_with_workers(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
            4,
            false,
            &[],
        )
        .expect("parallel backup");

        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("manifest");
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        for (rel, content) in &expected {
            let entry = manifest.file(rel).unwrap_or_else(|| panic!("{rel} must be in manifest"));
            assert_eq!(
                entry.checksum.as_deref(),
                Some(sha1_hex(content).as_str()),
                "checksum for {rel}"
            );
            assert_eq!(entry.reference, None, "full backup file {rel} must not be a reference");
            assert_eq!(
                std::fs::read(backup_root.join(rel)).unwrap(),
                *content,
                "repo bytes for {rel}"
            );
        }
        // Manifest is sorted by path (deterministic regardless of completion order).
        let paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted, "manifest files must be sorted by path");
    }

    #[test]
    fn process_max_reads_option_and_clamps() {
        // process-max maps the Integer option to a worker count; absent /
        // non-positive values clamp to a single worker.
        let cfg = |value: Option<i64>| {
            let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
            if let Some(v) = value {
                options.insert(("process-max".to_owned(), None), OptionValue::Integer(v));
            }
            LoadedConfig {
                command: "backup".to_owned(),
                command_role: pgbr_config::ConfigCommandRole::Main,
                stanza: Some("demo".to_owned()),
                options,
                params: Vec::new(),
            }
        };
        assert_eq!(process_max(&cfg(None)), 1, "absent defaults to 1");
        assert_eq!(process_max(&cfg(Some(0))), 1, "zero clamps to 1");
        assert_eq!(process_max(&cfg(Some(-3))), 1, "negative clamps to 1");
        assert_eq!(process_max(&cfg(Some(4))), 4);
    }

    #[test]
    fn diff_parallel_matches_serial() {
        // The parallel path must also reproduce diff backups identically: seed a
        // full, change some files, then take a diff with 1 vs 4 workers into two
        // repos and assert the diff manifests (references + checksums) match.
        let pg_dir = tempfile::tempdir().expect("pg tempdir");
        let pg_s = Posix::new(pg_dir.path());
        seed_many_files(&pg_s, 10);

        let run = |repo_s: &Posix, workers: usize| {
            init_stanza(repo_s, "demo");
            backup_inner_with_workers(
                "demo",
                repo_s,
                &pg_s,
                BackupType::Full,
                Some(LABEL),
                1_704_110_400,
                &RepoTransform::identity(),
                workers,
                false,
                &[],
            )
            .expect("full backup");
        };

        let repo1_dir = tempfile::tempdir().expect("repo1 tempdir");
        let repo2_dir = tempfile::tempdir().expect("repo2 tempdir");
        let repo1_s = Posix::new(repo1_dir.path());
        let repo2_s = Posix::new(repo2_dir.path());
        run(&repo1_s, 1);
        run(&repo2_s, 4);

        // Change a couple of files identically in both runs' shared PG dir.
        seed_file(&pg_s, "base/1/1003", b"CHANGED for the diff, completely different bytes now");
        seed_file(&pg_s, "base/1/1007", b"ALSO CHANGED, different length and content entirely!!");

        let diff1 = backup_inner_with_workers(
            "demo",
            &repo1_s,
            &pg_s,
            BackupType::Diff,
            None,
            1_704_196_800,
            &RepoTransform::identity(),
            1,
            false,
            &[],
        )
        .expect("serial diff");
        let diff4 = backup_inner_with_workers(
            "demo",
            &repo2_s,
            &pg_s,
            BackupType::Diff,
            None,
            1_704_196_800,
            &RepoTransform::identity(),
            4,
            false,
            &[],
        )
        .expect("parallel diff");
        assert_eq!(diff1.label, diff4.label);

        let manifest_path = format!("backup/demo/{}/backup.manifest", diff1.label);
        let m1 = Manifest::load(&repo1_s, Path::new(&manifest_path)).expect("serial diff manifest");
        let m4 = Manifest::load(&repo2_s, Path::new(&manifest_path)).expect("parallel diff manifest");
        assert_eq!(
            manifest_file_tuples(&m1),
            manifest_file_tuples(&m4),
            "parallel and serial diff manifests must list identical files (incl. references)"
        );
        // Some files must be referenced (unchanged) and some copied (changed).
        assert!(
            m1.files.iter().any(|f| f.reference.is_some()),
            "diff must reference unchanged files"
        );
        assert!(m1.files.iter().any(|f| f.reference.is_none()), "diff must copy changed files");
    }

    // ---- page-checksum validation (--checksum-page) ------------------------

    use pgbr_postgres::page::{BLCKSZ, pg_checksum_page};

    /// Build a single `BLCKSZ` data page with deterministic non-zero content and
    /// a *correct* stored `pd_checksum` for `block_no`. The page is valid by
    /// construction: its header checksum matches what `pg_checksum_page` derives.
    fn valid_page(block_no: u32, fill: u8) -> Vec<u8> {
        let mut page = vec![fill.max(1); BLCKSZ];
        // Vary the body a little per block so distinct pages differ (no casts:
        // write the block number's low bytes straight from its LE encoding).
        page[16..20].copy_from_slice(&block_no.to_le_bytes());
        // Zero the stored-checksum field, compute, then write it back (LE).
        page[8] = 0;
        page[9] = 0;
        let cksum = pg_checksum_page(&page, block_no).expect("checksum");
        page[8..10].copy_from_slice(&cksum.to_le_bytes());
        page
    }

    /// Build a `count`-page relation file whose every page is valid.
    fn valid_relation(count: u32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(usize::try_from(count).unwrap_or(0) * BLCKSZ);
        for block_no in 0..count {
            // Cycle the fill byte over a non-zero range without casting.
            let fill = 0x40u8.wrapping_add(u8::try_from(block_no % 16).unwrap_or(0));
            bytes.extend_from_slice(&valid_page(block_no, fill));
        }
        bytes
    }

    /// A backup config with `--checksum-page` enabled (and a stanza + type).
    fn checksum_page_cfg(stanza: &str) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("type".to_owned(), None), OptionValue::StringId("full".to_owned()));
        options.insert(("checksum-page".to_owned(), None), OptionValue::Boolean(true));
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn is_relation_file_recognises_relation_segments() {
        // Under base/<db>/<seg>: a bare relfilenode and a segment are relations.
        assert!(is_relation_file("base/16384/1259"));
        assert!(is_relation_file("base/1/1259"));
        assert!(is_relation_file("base/16384/16385.1"));
        // Under global/<seg>: shared catalogs.
        assert!(is_relation_file("global/1259"));
        assert!(is_relation_file("global/2659.3"));
        // Under a tablespace path PG_<ver>_<cat>.
        assert!(is_relation_file("pg_tblspc/16400/PG_14_202107181/16384/1259"));
        assert!(is_relation_file("pg_tblspc/16400/PG_16_202307071/16384/16385.2"));
    }

    #[test]
    fn is_relation_file_rejects_non_relations() {
        // Fork suffixes are not bare relation segments.
        assert!(!is_relation_file("base/16384/1259_fsm"));
        assert!(!is_relation_file("base/16384/1259_vm"));
        assert!(!is_relation_file("base/16384/1259_init"));
        // Non-numeric files under base/global.
        assert!(!is_relation_file("base/1/PG_VERSION"));
        assert!(!is_relation_file("base/16384/pg_filenode.map"));
        assert!(!is_relation_file("global/pg_control"));
        assert!(!is_relation_file("global/pg_filenode.map"));
        // Wrong depth: a relfilenode directly under base/ (missing the db oid).
        assert!(!is_relation_file("base/1259"));
        assert!(!is_relation_file("base/16384"));
        // Outside the relation roots entirely.
        assert!(!is_relation_file("PG_VERSION"));
        assert!(!is_relation_file("pg_wal/000000010000000000000001"));
        assert!(!is_relation_file("pg_xact/0000"));
        // A tablespace path with a malformed PG_ dir name is not a relation.
        assert!(!is_relation_file("pg_tblspc/16400/NOT_A_PG_DIR/16384/1259"));
        // Empty / dotted edge cases.
        assert!(!is_relation_file("base/1/.42"));
        assert!(!is_relation_file("base/1/42."));
    }

    #[test]
    fn is_valid_page_handles_zero_and_checksum() {
        // All-zero page is valid (empty-page handling).
        let zero = vec![0u8; BLCKSZ];
        assert!(is_valid_page(&zero, 0));
        // A correctly-checksummed page validates; corrupting it fails.
        let good = valid_page(7, 0x55);
        assert!(is_valid_page(&good, 7));
        let mut bad = good.clone();
        bad[8] ^= 0x01; // flip a stored-checksum bit
        assert!(!is_valid_page(&bad, 7));
        // A page validated against the wrong block number fails (transposed page).
        assert!(!is_valid_page(&good, 8));
    }

    #[test]
    fn backup_checksum_page_valid_records_some_true() {
        // A relation file made of valid pages, backed up with checksum-page on,
        // records checksum_page = Some(true). A non-relation file (PG_VERSION)
        // is never validated, so it stays None.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let relation = valid_relation(3);
        seed_file(&pg_s, "base/1/1259", &relation);
        seed_file(&pg_s, "PG_VERSION", b"14\n");

        backup(&checksum_page_cfg("demo"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        let relfile = manifest.file("base/1/1259").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page,
            Some(true),
            "all-valid relation pages must record checksum_page=Some(true)"
        );
        // Non-relation files are not validated.
        let version = manifest.file("PG_VERSION").expect("PG_VERSION in manifest");
        assert_eq!(version.checksum_page, None, "non-relation file must not be validated");
    }

    #[test]
    fn backup_checksum_page_corrupt_records_some_false() {
        // A relation file with one deliberately corrupted page checksum records
        // checksum_page = Some(false). Build a 2-page file, corrupt block 1's
        // stored checksum so it no longer matches.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let mut relation = valid_relation(2);
        // Flip a bit in block 1's stored pd_checksum (offset BLCKSZ + 8).
        relation[BLCKSZ + 8] ^= 0x01;
        seed_file(&pg_s, "base/1/1259", &relation);

        backup(&checksum_page_cfg("demo"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        let relfile = manifest.file("base/1/1259").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page,
            Some(false),
            "a corrupted page checksum must record checksum_page=Some(false)"
        );
        // The relation's plaintext checksum/size are still recorded.
        assert_eq!(relfile.size, relation.len() as u64);
        assert_eq!(relfile.checksum.as_deref(), Some(sha1_hex(&relation).as_str()));
    }

    #[test]
    fn backup_checksum_page_off_leaves_none() {
        // Without --checksum-page, even a valid relation file is not validated.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", &valid_relation(2));

        backup(&typed_cfg("demo", "full"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");
        let relfile = manifest.file("base/1/1259").expect("relation in manifest");
        assert_eq!(relfile.checksum_page, None, "checksum-page off must leave checksum_page None");
    }

    #[test]
    fn backup_checksum_page_skips_unaligned_relation() {
        // A relation-named file whose size is NOT a multiple of BLCKSZ is left
        // unvalidated (checksum_page None) even with the option on.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        // 100 bytes is not page-aligned.
        seed_file(
            &pg_s,
            "base/1/1259",
            b"not page aligned content of arbitrary length here .....",
        );

        backup(&checksum_page_cfg("demo"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");
        let relfile = manifest.file("base/1/1259").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page, None,
            "a non-page-aligned relation file must not be validated"
        );
    }

    #[test]
    fn backup_checksum_page_all_zero_pages_valid() {
        // An all-zero, page-aligned relation file validates as Some(true)
        // (empty-page handling).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", &vec![0u8; BLCKSZ * 2]);

        backup(&checksum_page_cfg("demo"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");
        let relfile = manifest.file("base/1/1259").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page,
            Some(true),
            "all-zero pages must validate as Some(true)"
        );
    }

    // ---- backup-control protocol (pg_backup_start/stop) --------------------

    /// An in-memory [`BackupControl`] for the DB-free unit tests: it records the
    /// calls it received and replays scripted LSNs / file contents, so the
    /// control-driven backup path can be exercised end-to-end with no libpq.
    #[derive(Debug, Default)]
    struct FakeBackupControl {
        /// Reported server version number / system identifier.
        server_version_num: u32,
        system_identifier: u64,
        /// LSN `backup_start` returns.
        start_lsn: String,
        /// Stop LSN + label / spcmap files `backup_stop` returns.
        stop: BackupStopResult,
        /// Whether `is_in_recovery` reports a standby.
        in_recovery: bool,
        /// Sequence of replay LSNs `replay_lsn` returns (last value repeats).
        replay_lsns: Vec<Option<String>>,
        /// Call log, for asserting the protocol order / arguments.
        calls: std::cell::RefCell<Vec<String>>,
        /// Cursor into `replay_lsns`.
        replay_cursor: std::cell::Cell<usize>,
    }

    impl FakeBackupControl {
        /// A primary fake for a given PG version with scripted LSNs.
        fn primary(server_version_num: u32, system_identifier: u64, start_lsn: &str, stop: BackupStopResult) -> Self {
            Self {
                server_version_num,
                system_identifier,
                start_lsn: start_lsn.to_owned(),
                stop,
                in_recovery: false,
                replay_lsns: Vec::new(),
                calls: std::cell::RefCell::new(Vec::new()),
                replay_cursor: std::cell::Cell::new(0),
            }
        }
    }

    impl BackupControl for FakeBackupControl {
        fn server_info(&mut self) -> Result<BackupServerInfo, CommandError> {
            self.calls.borrow_mut().push("server_info".to_owned());
            Ok(BackupServerInfo {
                server_version_num: self.server_version_num,
                system_identifier: self.system_identifier,
            })
        }

        fn backup_start(&mut self, label: &str, fast: bool) -> Result<String, CommandError> {
            self.calls.borrow_mut().push(format!("backup_start({label},{fast})"));
            Ok(self.start_lsn.clone())
        }

        fn backup_stop(&mut self) -> Result<BackupStopResult, CommandError> {
            self.calls.borrow_mut().push("backup_stop".to_owned());
            Ok(self.stop.clone())
        }

        fn is_in_recovery(&mut self) -> Result<bool, CommandError> {
            self.calls.borrow_mut().push("is_in_recovery".to_owned());
            Ok(self.in_recovery)
        }

        fn replay_lsn(&mut self) -> Result<Option<String>, CommandError> {
            self.calls.borrow_mut().push("replay_lsn".to_owned());
            let idx = self.replay_cursor.get().min(self.replay_lsns.len().saturating_sub(1));
            self.replay_cursor.set(self.replay_cursor.get() + 1);
            Ok(self.replay_lsns.get(idx).cloned().flatten())
        }
    }

    /// The `backup.info` identity the [`init_stanza`] helper writes (PG 14).
    const STANZA_SYSTEM_ID: u64 = 6_873_049_345_984_568_091;

    /// Run a control-driven backup through `run_backup` with a fake primary.
    fn run_backup_with_fake(
        repo_s: &Posix,
        pg_s: &Posix,
        control: &mut FakeBackupControl,
        start_fast: bool,
    ) -> Result<BackupOutcome, CommandError> {
        run_backup(
            "demo",
            repo_s,
            pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
            1,
            false,
            &[],
            Some(control as &mut dyn BackupControl),
            None,
            start_fast,
            BackupFeatures::disabled(),
        )
    }

    #[test]
    fn control_driven_backup_brackets_copy_and_records_lsns() {
        // A control-driven full backup must: validate the server, call
        // backup_start, copy files, call backup_stop, write backup_label /
        // tablespace_map, and record the start/stop LSN + WAL segments.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/16B3E40",
            BackupStopResult {
                lsn: "0/16B3F00".to_owned(),
                label_file: "START WAL LOCATION: 0/16B3E40\n".to_owned(),
                spcmap_file: "16400 /mnt/ts1\n".to_owned(),
            },
        );

        let outcome = run_backup_with_fake(&repo_s, &pg_s, &mut control, true).expect("control-driven backup");

        // The bracket is recorded with the right LSNs and WAL segments.
        let bracket = outcome.bracket.expect("bracket present for a DB-driven backup");
        assert_eq!(bracket.lsn_start, "0/16B3E40");
        assert_eq!(bracket.lsn_stop, "0/16B3F00");
        assert_eq!(bracket.archive_start, "000000010000000000000001");
        assert_eq!(bracket.archive_stop, "000000010000000000000001");

        // Protocol order: server_info, backup_start(label,fast=true), backup_stop.
        let calls = control.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![
                "server_info".to_owned(),
                format!("backup_start({LABEL},true)"),
                "backup_stop".to_owned(),
            ],
            "protocol calls in order"
        );

        // backup_label + tablespace_map written into the backup root.
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        assert_eq!(
            std::fs::read_to_string(backup_root.join("backup_label")).unwrap(),
            "START WAL LOCATION: 0/16B3E40\n"
        );
        assert_eq!(
            std::fs::read_to_string(backup_root.join("tablespace_map")).unwrap(),
            "16400 /mnt/ts1\n"
        );

        // The data file was still copied.
        assert!(backup_root.join("base/1/1259").exists(), "data file copied");

        // backup.info records the LSN / archive fields and the live identity.
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let entry = info.current.get(LABEL).expect("backup entry");
        assert_eq!(entry["backup-lsn-start"], json!("0/16B3E40"));
        assert_eq!(entry["backup-lsn-stop"], json!("0/16B3F00"));
        assert_eq!(entry["backup-archive-start"], json!("000000010000000000000001"));
        assert_eq!(entry["backup-archive-stop"], json!("000000010000000000000001"));
        assert_eq!(entry["db-version"], json!("14"));
        assert_eq!(entry["db-system-id"], json!(STANZA_SYSTEM_ID));
    }

    #[test]
    fn control_driven_backup_no_spcmap_skips_tablespace_map() {
        // A cluster with no tablespaces returns an empty spcmapfile; the
        // tablespace_map file must NOT be written, but backup_label still is.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/0",
            BackupStopResult {
                lsn: "0/30".to_owned(),
                label_file: "backup label body\n".to_owned(),
                spcmap_file: String::new(),
            },
        );

        run_backup_with_fake(&repo_s, &pg_s, &mut control, false).expect("backup");

        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        assert!(backup_root.join("backup_label").exists(), "backup_label written");
        assert!(
            !backup_root.join("tablespace_map").exists(),
            "no tablespace_map when spcmapfile is empty"
        );
    }

    #[test]
    fn control_driven_backup_rejects_system_id_mismatch() {
        // A server whose system identifier differs from the stanza is a hard
        // error before any file is copied.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");

        let mut control = FakeBackupControl::primary(
            140_010,
            999, // wrong system id
            "0/0",
            BackupStopResult {
                lsn: "0/30".to_owned(),
                label_file: String::new(),
                spcmap_file: String::new(),
            },
        );

        let err = run_backup_with_fake(&repo_s, &pg_s, &mut control, false).expect_err("mismatch must error");
        assert!(err.to_string().contains("does not match stanza db-system-id"), "got {err}");

        // No backup directory contents were produced (validation failed first).
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        assert!(
            !backup_root.join("base/1/1259").exists(),
            "no file copied when validation fails"
        );
    }

    #[test]
    fn control_driven_backup_rejects_version_mismatch() {
        // The stanza is PG 14; a PG 16 server must be rejected.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"x");

        let mut control = FakeBackupControl::primary(
            160_004, // PG 16 vs stanza's "14"
            STANZA_SYSTEM_ID,
            "0/0",
            BackupStopResult {
                lsn: "0/30".to_owned(),
                label_file: String::new(),
                spcmap_file: String::new(),
            },
        );

        let err = run_backup_with_fake(&repo_s, &pg_s, &mut control, false).expect_err("version mismatch must error");
        assert!(err.to_string().contains("does not match stanza db-version"), "got {err}");
    }

    #[test]
    fn control_driven_backup_rejects_invalid_start_lsn() {
        // A server that returns a non-LSN string for the start fails the backup.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"x");

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "not-an-lsn",
            BackupStopResult {
                lsn: "0/30".to_owned(),
                label_file: String::new(),
                spcmap_file: String::new(),
            },
        );

        let err = run_backup_with_fake(&repo_s, &pg_s, &mut control, false).expect_err("bad start LSN must error");
        assert!(err.to_string().contains("invalid LSN"), "got {err}");
    }

    #[test]
    fn standby_replay_wait_returns_when_caught_up() {
        // The standby reports a replay LSN behind, then equal to, the start LSN;
        // wait_for_standby_replay must return Ok once it reaches the target.
        let mut standby = FakeBackupControl {
            in_recovery: true,
            replay_lsns: vec![Some("0/100".to_owned()), Some("0/150".to_owned()), Some("0/200".to_owned())],
            ..FakeBackupControl::primary(
                140_010,
                STANZA_SYSTEM_ID,
                "0/0",
                BackupStopResult {
                    lsn: "0/0".to_owned(),
                    label_file: String::new(),
                    spcmap_file: String::new(),
                },
            )
        };
        // Target 0/200 is reached on the third poll.
        wait_for_standby_replay(&mut standby, "0/200").expect("standby catches up");
        // At least three replay polls happened.
        let replay_calls = standby.calls.borrow().iter().filter(|c| *c == "replay_lsn").count();
        assert!(replay_calls >= 3, "expected >= 3 replay polls, got {replay_calls}");
    }

    #[test]
    fn standby_replay_wait_rejects_invalid_lsn() {
        let mut standby = FakeBackupControl {
            in_recovery: true,
            replay_lsns: vec![Some("garbage".to_owned())],
            ..FakeBackupControl::primary(
                140_010,
                STANZA_SYSTEM_ID,
                "0/0",
                BackupStopResult {
                    lsn: "0/0".to_owned(),
                    label_file: String::new(),
                    spcmap_file: String::new(),
                },
            )
        };
        let err = wait_for_standby_replay(&mut standby, "0/200").expect_err("invalid replay LSN");
        assert!(err.to_string().contains("invalid LSN"), "got {err}");
    }

    #[test]
    fn build_bracket_maps_lsns_to_wal_segments() {
        let stop = BackupStopResult {
            lsn: "0/2000000".to_owned(),
            label_file: String::new(),
            spcmap_file: String::new(),
        };
        let bracket = build_bracket("0/16B3E40", &stop).expect("bracket");
        assert_eq!(bracket.archive_start, "000000010000000000000001");
        // 0/2000000 = 0x02000000 / 16 MiB (0x01000000) = 2 -> ...00000002.
        assert_eq!(bracket.archive_stop, "000000010000000000000002");
    }

    #[test]
    fn start_fast_enabled_reads_boolean() {
        let cfg = |value: Option<bool>| {
            let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
            if let Some(v) = value {
                options.insert(("start-fast".to_owned(), None), OptionValue::Boolean(v));
            }
            LoadedConfig {
                command: "backup".to_owned(),
                command_role: pgbr_config::ConfigCommandRole::Main,
                stanza: Some("demo".to_owned()),
                options,
                params: Vec::new(),
            }
        };
        assert!(!start_fast_enabled(&cfg(None)), "absent defaults to false");
        assert!(!start_fast_enabled(&cfg(Some(false))));
        assert!(start_fast_enabled(&cfg(Some(true))));
    }

    #[test]
    fn standby_mode_reads_option() {
        let cfg = |value: Option<&str>| {
            let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
            if let Some(v) = value {
                options.insert(("backup-standby".to_owned(), None), OptionValue::StringId(v.to_owned()));
            }
            LoadedConfig {
                command: "backup".to_owned(),
                command_role: pgbr_config::ConfigCommandRole::Main,
                stanza: Some("demo".to_owned()),
                options,
                params: Vec::new(),
            }
        };
        assert_eq!(standby_mode(&cfg(None)), StandbyMode::No, "absent defaults to No");
        assert_eq!(standby_mode(&cfg(Some("n"))), StandbyMode::No);
        assert_eq!(standby_mode(&cfg(Some("prefer"))), StandbyMode::Prefer);
        assert_eq!(standby_mode(&cfg(Some("y"))), StandbyMode::Yes);
    }

    #[test]
    fn derive_conninfo_for_index_builds_pgn() {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(
            ("pg2-host".to_owned(), None),
            OptionValue::String("standby.example".to_owned()),
        );
        options.insert(("pg2-port".to_owned(), None), OptionValue::Integer(5433));
        options.insert(("pg2-database".to_owned(), None), OptionValue::String("postgres".to_owned()));
        let cfg = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        };
        // pg1 has no host -> None; pg2 has a host -> a conninfo.
        assert_eq!(derive_conninfo_for_index(&cfg, 1), None);
        let conninfo = derive_conninfo_for_index(&cfg, 2).expect("pg2 conninfo");
        assert!(conninfo.contains("host=standby.example"), "{conninfo}");
        assert!(conninfo.contains("port=5433"), "{conninfo}");
        assert!(conninfo.contains("dbname=postgres"), "{conninfo}");
    }

    #[test]
    fn derive_conninfo_with_url_prefers_database_url() {
        let cfg = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: BTreeMap::new(),
            params: Vec::new(),
        };
        // DATABASE_URL wins verbatim.
        assert_eq!(
            derive_conninfo_with_url(&cfg, Some("postgresql:///x")),
            Some("postgresql:///x".to_owned())
        );
        // Empty URL + no pg1 host -> None.
        assert_eq!(derive_conninfo_with_url(&cfg, Some("")), None);
        assert_eq!(derive_conninfo_with_url(&cfg, None), None);
    }

    // Live-PostgreSQL backup through the libpq backup-control path. Skipped by
    // default; run with `cargo test -p pgbr-command -- --include-ignored` and
    // DATABASE_URL pointing at a reachable cluster. Documents the real contract.
    #[test]
    #[ignore = "requires a running PostgreSQL server (set DATABASE_URL)"]
    fn control_driven_backup_against_real_database() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };

        // Learn the live cluster's identity so we can seed a matching stanza.
        let mut probe = LibpqBackupControl::open(&url).expect("open DATABASE_URL connection");
        let server = probe.server_info().expect("server info");

        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_s = Posix::new(repo.path());
        let pg_s = Posix::new(pg.path());

        // Seed a stanza whose identity matches the live server.
        repo_s.create_path(Path::new("backup/demo"), true).unwrap();
        let major_string = server.release_major().to_string();
        let label_major = if server.release_major() == 9 {
            "9.6"
        } else {
            major_string.as_str()
        };
        let version_entry = pgbr_postgres::version::by_label(label_major).expect("known PG version");
        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: server.system_identifier,
            db_version: version_entry.label.to_owned(),
            db_catalog_version: version_entry.catalog_version_no,
            db_control_version: version_entry.pg_control_version,
            current: BTreeMap::new(),
            history: BTreeMap::new(),
        };
        info.save(&repo_s, &backup_info_path("demo")).unwrap();
        seed_file(&pg_s, "base/1/1259", b"relation contents for the live backup");

        let mut control = LibpqBackupControl::open(&url).expect("control connection");
        let outcome = run_backup(
            "demo",
            &repo_s,
            &pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            &RepoTransform::identity(),
            1,
            false,
            &[],
            Some(&mut control as &mut dyn BackupControl),
            None,
            true,
            BackupFeatures::disabled(),
        )
        .expect("live control-driven backup");

        let bracket = outcome.bracket.expect("bracket from live PG");
        assert!(pgbr_postgres::lsn::parse_lsn(&bracket.lsn_start).is_some());
        assert!(pgbr_postgres::lsn::parse_lsn(&bracket.lsn_stop).is_some());
        // backup_label must have been returned and written.
        let backup_root = repo.path().join(format!("backup/demo/{LABEL}"));
        assert!(backup_root.join("backup_label").exists(), "live backup_label written");
    }

    // ---- file bundling + block-incremental ---------------------------------

    /// A `full` backup config with `repo-bundle` (and optional `repo-block`) set.
    fn bundle_cfg(stanza: &str, block: bool, bundle_limit: Option<u64>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("type".to_owned(), None), OptionValue::StringId("full".to_owned()));
        options.insert(("repo-bundle".to_owned(), None), OptionValue::Boolean(true));
        if block {
            options.insert(("repo-block".to_owned(), None), OptionValue::Boolean(true));
        }
        if let Some(limit) = bundle_limit {
            options.insert(("repo-bundle-limit".to_owned(), None), OptionValue::Size(limit));
        }
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn backup_features_from_options_reads_values() {
        let cfg = bundle_cfg("demo", true, Some(4096));
        let f = BackupFeatures::from_options(&cfg);
        assert!(f.bundle);
        assert!(f.block);
        assert_eq!(f.bundle_limit, 4096);
        assert_eq!(f.bundle_size, DEFAULT_BUNDLE_SIZE);
        // All-off config: disabled defaults.
        let off = BackupFeatures::from_options(&typed_cfg("demo", "full"));
        assert!(!off.bundle && !off.block);
    }

    #[test]
    fn validate_features_rejects_block_without_bundle() {
        let mut cfg = typed_cfg("demo", "full");
        cfg.options
            .insert(("repo-block".to_owned(), None), OptionValue::Boolean(true));
        let features = BackupFeatures {
            bundle: false,
            block: true,
            ..BackupFeatures::disabled()
        };
        let err = validate_features(&cfg, features).expect_err("block without bundle must fail");
        assert!(err.to_string().contains("repo-block requires repo-bundle"), "{err}");
    }

    #[test]
    fn validate_features_rejects_bundle_with_hardlink() {
        let mut cfg = bundle_cfg("demo", false, None);
        cfg.options
            .insert(("repo-hardlink".to_owned(), None), OptionValue::Boolean(true));
        let features = BackupFeatures::from_options(&cfg);
        let err = validate_features(&cfg, features).expect_err("bundle + hardlink must fail");
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn backup_bundle_packs_small_files() {
        // With repo-bundle on, small files are packed into bundle objects and
        // recorded with bundle id/offset; no per-file repo object is written.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"small relation one");
        seed_file(&pg_s, "base/1/1260", b"small relation two, slightly bigger");
        seed_file(&pg_s, "PG_VERSION", b"14\n");

        backup(&bundle_cfg("demo", false, None), &repo_s, &pg_s).expect("bundled backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        // Every file is bundled (all are tiny, well under the 2 MiB limit).
        for f in &manifest.files {
            assert!(f.bundle_id.is_some(), "{} must be bundled", f.path);
            assert!(f.bundle_offset.is_some());
        }
        // A bundle object exists; no individual per-file repo objects were written.
        let backup_root = repo_dir.path().join(format!("backup/demo/{label}"));
        assert!(backup_root.join("bundle/1").exists(), "bundle object must exist");
        assert!(
            !backup_root.join("base/1/1259").exists(),
            "no standalone repo file when bundled"
        );
    }

    #[test]
    fn backup_bundle_large_file_stays_standalone() {
        // A file over the bundle limit is written as its own repo object.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let big = vec![7u8; 4096];
        seed_file(&pg_s, "base/1/1259", &big);
        seed_file(&pg_s, "PG_VERSION", b"14\n");

        // Limit of 100 bytes: the 4096-byte file exceeds it and stays standalone;
        // PG_VERSION is bundled. repo-block off so the big file is not split.
        backup(&bundle_cfg("demo", false, Some(100)), &repo_s, &pg_s).expect("bundled backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        let big_file = manifest.file("base/1/1259").expect("big file");
        assert!(big_file.bundle_id.is_none(), "over-limit file must not be bundled");
        let small = manifest.file("PG_VERSION").expect("small file");
        assert!(small.bundle_id.is_some(), "small file must be bundled");

        let backup_root = repo_dir.path().join(format!("backup/demo/{label}"));
        assert!(
            backup_root.join("base/1/1259").exists(),
            "over-limit file is a standalone object"
        );
    }

    #[test]
    fn backup_block_writes_block_map_for_large_file() {
        // A large, fresh, block-eligible file gets a block map; small files do not.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        // 256 KiB easily clears the block-eligibility floor.
        let big: Vec<u8> = (0..256 * 1024u32).map(|n| (n % 251) as u8).collect();
        seed_file(&pg_s, "base/1/1259", &big);
        seed_file(&pg_s, "PG_VERSION", b"14\n");

        backup(&bundle_cfg("demo", true, None), &repo_s, &pg_s).expect("block backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        let big_file = manifest.file("base/1/1259").expect("big file");
        let bm = big_file.block_map.as_ref().expect("large file must have a block map");
        assert!(bm.blocks.len() > 1, "256 KiB file must split into multiple blocks");
        // Full backup: every block references this backup.
        assert!(
            bm.blocks.iter().all(|b| b.reference == *label),
            "full backup blocks self-reference"
        );
        // Small file: no block map.
        assert!(manifest.file("PG_VERSION").unwrap().block_map.is_none());
    }
}
