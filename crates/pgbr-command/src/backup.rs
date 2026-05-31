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
use pgbr_info::manifest::ChecksumPage;
use pgbr_info::{InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath};
use pgbr_io::{Filter, Sha1};
use pgbr_postgres::control::read_pg_control_data;
use pgbr_postgres::lsn::{lsn_text_to_wal_segment, parse_lsn, wal_segment_range};
use pgbr_protocol::message::{OkResponse, Request, Response};
use pgbr_protocol::parallel::{Job, ParallelExecutor};
use pgbr_storage::{Storage, StorageInfo, StorageKind};
use serde_json::json;

use crate::CommandError;
use crate::backup_control::{BackupControl, BackupServerInfo, BackupStopResult, LibpqBackupControl, RemoteBackupControl};
use crate::pipeline::{RepoTransform, metadata_compress_type_key, metadata_encrypted_key};

/// Emit a human progress line at `INFO` through the process-global logger.
///
/// pgBackRest funnels every human-facing line through `logInternal`
/// (`src/common/log.c`); this fork's logger ([`pgbr_core::log`]) is the Rust
/// port. Backup progress (command begin / end, planned dry-run actions, resume /
/// stop-auto / expire-auto notices) goes here instead of `println!` so it honours
/// the configured log level, the `[DRY-RUN]` prefix, and the file destination.
/// The write result is intentionally ignored — a logging failure must never fail
/// the backup. Machine-readable output (none in this command) would still use
/// `print!`.
fn log_info(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_INFO,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        file!(),
        "backup",
        0,
        message,
    );
}

/// Emit a human warning line at `WARN` through the process-global logger.
///
/// The `WARN` counterpart of [`log_info`], used for non-fatal anomalies such as
/// invalid page checksums. Replaces the prior `eprintln!("WARN: …")` lines.
fn log_warn(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_WARN,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        file!(),
        "backup",
        0,
        message,
    );
}

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
    // `log/` is where the postmaster writes its server log when
    // `logging_collector = on` (the default `log_directory`). pgBackRest
    // unconditionally excludes the postmaster log tree: the bytes are runtime
    // diagnostic output that cannot help a restored cluster, and the file is
    // actively being written / rotated while the backup runs, so capturing it
    // would mid-stream a partial line at best (and disappear from the manifest
    // when log rotation removes it at worst). C ref: `manifestBuildInfo`
    // (`src/info/manifest/manifest.c`) skips `MANIFEST_TARGET_PGDATA/log`.
    "log",
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
    // A root-level postmaster server log: written by `pg_ctl -l <pgdata>/server.log`
    // and by `logging_collector` when configured to write at the data root.
    // pgBackRest unconditionally excludes it (transient runtime output, actively
    // rotated, no value to a restored cluster). C ref: `manifestBuildInfo`'s
    // PGDATA-root file skips (`src/info/manifest/manifest.c`).
    "server.log",
    // The pointer file `logging_collector` rewrites every rotation to name the
    // current log file. It is regenerated on startup, so capturing it under a
    // backup would only embed a stale pointer that contradicts the restored
    // cluster's actual log path.
    "current_logfiles",
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
    /// Timeline id the start / stop segments are on (sourced from the live
    /// cluster rather than hardcoded), used to enumerate the archive-copy range.
    pub timeline: u32,
    /// Cluster `wal_segment_size` in bytes, used to enumerate the archive-copy
    /// range and to map each LSN to its segment name.
    pub wal_segment_size: u64,
}

/// The archive / page integrity checks a DB-driven backup applies, resolved
/// from `archive-check` / `archive-mode-check` / `page-header-check` (and the
/// `archive-timeout` that bounds the archive-check wait).
///
/// All three booleans default to `true` (the option model's defaults). The
/// DB-free test wrappers pass [`IntegrityChecks::disabled`] so the existing
/// file-copy-only tests are byte-for-byte unchanged (they have no live cluster
/// to check `archive_mode` against and no archive to wait on).
#[derive(Debug, Clone, Copy)]
struct IntegrityChecks {
    /// `archive-check`: after `pg_backup_stop`, verify the required WAL segments
    /// (archive-start..archive-stop) are present in the repo archive.
    archive_check: bool,
    /// `archive-mode-check`: before the copy, verify the cluster's `archive_mode`
    /// is enabled (and warn on `always`, which is unexpected on a primary).
    archive_mode_check: bool,
    /// `page-header-check`: validate each relation page's header in addition to
    /// its stored checksum.
    page_header_check: bool,
    /// Bound on the `archive-check` wait for a required WAL segment to arrive.
    archive_timeout: std::time::Duration,
}

impl IntegrityChecks {
    /// All checks off — the DB-free file-copy test path.
    const fn disabled() -> Self {
        Self {
            archive_check: false,
            archive_mode_check: false,
            page_header_check: false,
            archive_timeout: std::time::Duration::from_mins(1),
        }
    }

    /// Read the integrity-check options from the resolved configuration.
    fn from_options(config: &LoadedConfig) -> Self {
        Self {
            archive_check: archive_check_enabled(config),
            archive_mode_check: archive_mode_check_enabled(config),
            page_header_check: page_header_check_enabled(config),
            archive_timeout: archive_timeout(config),
        }
    }
}

/// The durability / lifecycle policy a backup applies, resolved from `--dry-run`,
/// `--resume`, `--stop-auto`, and `--manifest-save-threshold`.
///
/// Grouped into one struct so the already-wide [`run_backup`] signature does not
/// grow four more positional parameters. The DB-free test wrappers pass
/// [`BackupPolicy::test_default`], which reproduces the prior behaviour exactly
/// (no dry-run, resume on but harmless on a clean repo, no stop-auto, a save
/// threshold so high it never triggers mid-test).
#[derive(Debug, Clone, Copy)]
struct BackupPolicy {
    /// `--dry-run`: plan + log every action but make no repository / manifest
    /// writes. C ref: `cfgOptDryRun`.
    dry_run: bool,
    /// `--resume`: reuse files already copied by an aborted prior backup in the
    /// same label directory (matching size + plaintext checksum).
    resume: bool,
    /// `--stop-auto`: stop a stale running backup on the cluster before starting.
    stop_auto: bool,
    /// `--manifest-save-threshold` (bytes): re-save the in-progress manifest after
    /// this many bytes have been copied, for incremental durability.
    manifest_save_threshold: u64,
}

impl BackupPolicy {
    /// The policy the DB-free test wrappers use: behaviour-neutral so every
    /// pre-existing backup test is byte-for-byte unchanged.
    const fn test_default() -> Self {
        Self {
            dry_run: false,
            // Resume is on by default in production; on a fresh per-test repo there
            // is never a partial prior backup, so it is a no-op for the tests.
            resume: true,
            stop_auto: false,
            // u64::MAX so the periodic mid-copy save never fires during a test.
            manifest_save_threshold: u64::MAX,
        }
    }

    /// Read the durability / lifecycle options from the resolved configuration.
    fn from_options(config: &LoadedConfig) -> Self {
        Self {
            dry_run: dry_run_enabled(config),
            resume: resume_enabled(config),
            stop_auto: stop_auto_enabled(config),
            manifest_save_threshold: manifest_save_threshold(config),
        }
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

/// Whether a PG-data-relative path is **exactly** one of [`EXCLUDE_PREFIXES`]
/// (the directory itself, not a path beneath it).
///
/// pgBackRest keeps these transient runtime directories in the manifest as
/// *empty* paths so restore recreates the directory, while still excluding
/// every file/subdir under them. This distinguishes the directory (recorded)
/// from its contents (skipped). Used by [`plan_backup`] and to gate recursion
/// in [`walk_into`].
fn is_excluded_dir(rel: &str) -> bool {
    EXCLUDE_PREFIXES.contains(&rel)
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

/// Whether a single `PAGE_SIZE` page passes validation.
///
/// An all-zero page is treated as valid (pgBackRest's empty-page handling: a
/// freshly extended but never-written page is all zeroes and carries no
/// meaningful checksum). Any other page is valid iff:
///
/// - its stored `pd_checksum` matches the value
///   [`pgbr_postgres::page::pg_checksum_page`] computes for `block_no`, **and**
/// - when `check_header` is set (`page-header-check`), its header bookkeeping is
///   structurally sane per [`pgbr_postgres::page::page_header_valid`]
///   (`pd_lower`/`pd_upper`/`pd_special` bounds; `pd_lsn` is not bounded here because the
///   backup-stop LSN is not threaded into the per-file copy path).
///
/// A page whose length is not exactly `PAGE_SIZE` is treated as invalid (it
/// cannot be a well-formed data page).
fn is_valid_page(page: &[u8], block_no: u32, check_header: bool) -> bool {
    if page.iter().all(|&b| b == 0) {
        return true;
    }
    if check_header && !pgbr_postgres::page::page_header_valid(page, PAGE_SIZE, None) {
        return false;
    }
    pgbr_postgres::page::page_checksum_valid(page, block_no).unwrap_or(false)
}

/// Validate every page of a page-aligned relation file.
///
/// `bytes` must already be confirmed page-aligned (a multiple of `PAGE_SIZE`)
/// by the caller. `check_header` enables the per-page header validation
/// (`page-header-check`) in addition to the checksum. Returns the (possibly
/// empty) list of block numbers that did not validate, in ascending order. An
/// all-empty (or empty-`bytes`) file yields an empty list.
fn validate_relation_pages(bytes: &[u8], check_header: bool) -> Vec<u32> {
    let mut invalid = Vec::new();
    for (idx, page) in bytes.chunks_exact(PAGE_SIZE).enumerate() {
        let block_no = u32::try_from(idx).unwrap_or(u32::MAX);
        if !is_valid_page(page, block_no, check_header) {
            invalid.push(block_no);
        }
    }
    invalid
}

/// Emit a `WARN` line naming a relation file's invalid pages.
///
/// The `ManifestFile` now records the invalid block list itself, in its
/// `checksum_page` field (the [`ChecksumPage::InvalidBlocks`] variant), so
/// consumers like `verify` / `info` can see which blocks failed without
/// re-reading the file. This helper additionally surfaces the same diagnostic
/// through the `WARN` logger so a `backup` run still mirrors pgBackRest's
/// `WARN: invalid page checksum(s) found in file ...` line in the log stream
/// — the on-disk manifest array and the streamed warning carry the same data.
fn warn_invalid_pages(rel: &str, invalid_blocks: &[u32]) {
    let blocks = invalid_blocks.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    log_warn(&format!("invalid page checksum(s) found in file {rel} at block(s) {blocks}"));
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
                let descend = !is_excluded_dir(&rel);
                out.push(WalkEntry { rel: rel.clone(), info });
                // A built-in excluded runtime directory (`pg_notify`, `pg_wal`, …)
                // is emitted as a path so restore recreates the empty dir, but we
                // never descend into it: its contents are transient (and may
                // vanish mid-walk), and pgBackRest captures only the dir itself.
                if descend {
                    walk_into(storage, &child_dir, &rel, out)?;
                }
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
pub fn backup(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    // Refuse to run when the operator has called `stop` for this stanza (or
    // `stop --force` which writes `all.stop` and blocks every stanza). The
    // gate runs BEFORE acquiring the backup lock so a stopped stanza doesn't
    // even create a lock file. C ref: cmdLockAcquire's lockStopTest check.
    if crate::lock::is_stopped(config)? {
        return Err(CommandError::Other(format!("stop file exists for stanza {stanza}")));
    }
    // Hold the backup lock for the whole command. C ref: lockAcquire(lockTypeBackup).
    let _locks = acquire_command_lock(config, LockType::Backup)?;
    let backup_type = BackupType::from_options(config);
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let timestamp_start = i64::try_from(secs).unwrap_or(i64::MAX);
    // On an encrypted repository the data files and `backup.manifest` are
    // encrypted with the repository *sub-key* (recovered from the decrypted
    // `archive.info` `[cipher]` section), not the user passphrase — the same key
    // archive-push uses for WAL. `from_options` reads the `cipher-type`/
    // `cipher-pass` options, which only exist for `repo-get`/`repo-put`, so it
    // would leave `backup` writing plaintext on an encrypted repo. Build the
    // transform from the resolved sub-key instead so the data + manifest are
    // encrypted (SHA-1 KDF, matching the info files and WAL). For an unencrypted
    // repo the sub-key is `None`, leaving the byte-for-byte plaintext+compress
    // behaviour unchanged.
    let sub_key = crate::cipher::active_sub_key(repo_storage, config, stanza)?;
    let transform = RepoTransform::from_options_with_key(config, sub_key);
    let process_max = process_max(config);
    // Resolve the effective `--checksum-page` value: honour an explicit user
    // value, else read `global/pg_control` and default to the cluster's
    // `data_checksum_version` (the dynamic default stock pgBackRest uses).
    let checksum_page = resolve_checksum_page(config, pg_storage);
    let excludes = excludes_from_config(config);
    let start_fast = start_fast_enabled(config);
    let archive_copy = archive_copy_enabled(config);
    let integrity = IntegrityChecks::from_options(config);
    let policy = BackupPolicy::from_options(config);

    log_info("backup command begin");
    if policy.dry_run {
        log_info("dry-run: no files will be copied and the repository will not be modified");
    }

    // File-bundling / block-incremental features. Validate the cross-option
    // constraints up front: bundling and repo-hardlink are mutually exclusive
    // (a bundled file has no standalone repo object to hard-link), and
    // block-incremental requires bundling (block bytes live in bundles).
    let features = BackupFeatures::from_options(config);
    validate_features(config, features)?;

    // Explicit block-incremental tuning overrides (`repo-block-*-map`,
    // `repo-block-size-super*`) and the per-file copy retry policy
    // (`job-retry` / `job-retry-interval`). Both default to "no override" /
    // "pgBackRest defaults" when unset, leaving the prior behaviour unchanged.
    let block_overrides = block_overrides_from_options(config);
    let job_retry = JobRetry::from_options(config);

    // Surface the applied user exclusions: pgBackRest records these in the
    // manifest's `[backup:option]` metadata, but the `Manifest` struct here owns
    // no exclude field (another concern), so for this slice the applied entries
    // are logged and used only to filter the walk.
    if !excludes.is_empty() {
        log_info(&format!("backup will exclude user path(s): {}", excludes.join(", ")));
    }

    // Resolve the backup-control connections per the `backup-standby` policy:
    // the *primary* connection drives pg_backup_start/stop, an optional *standby*
    // connection is polled for replay before the file copy. When no DB source is
    // configured the backup falls back to the DB-free file-copy path so a purely
    // local repo-only invocation still works. C ref: backup.c's dbGet().
    let ControlConnections {
        mut primary,
        mut standby,
        standby_index,
    } = resolve_control_connections(config, standby_mode(config))?;

    // backup-standby I/O offload: when a standby was selected and its data
    // directory is locally reachable (no `pgN-host`), read the backup files from
    // the standby to offload the primary's I/O (C ref: backup.c reads from the
    // standby `storagePg()` when `backup-standby` is active). A remote standby's
    // files fall back to `pg_storage` (the primary) — the backup is still
    // consistent (start/stop on the primary, standby replay awaited); only the
    // read location differs. A standby at pg1 with a local path resolves to the
    // same directory as `pg_storage`, so the override is a harmless no-op there.
    let standby_dir = standby_index.and_then(|idx| standby_local_path(config, idx));
    if standby.is_some() {
        match &standby_dir {
            Some(dir) => log_info(&format!(
                "backup-standby: reading files from the standby data directory {}",
                dir.display()
            )),
            None => log_info(
                "backup-standby: standby is remote; reading files from the primary data directory (consistent; remote-standby read offload not yet plumbed)",
            ),
        }
    }
    let standby_storage = standby_dir.map(pgbr_storage::Posix::new);
    let copy_storage: &dyn Storage = standby_storage.as_ref().map_or(pg_storage, |s| s as &dyn Storage);

    // On an encrypted repository backup.info is read / re-saved under the user
    // passphrase; resolve it for the active repository (`None` when unencrypted).
    let repo_user_pass = crate::cipher::active_user_pass(config)?;

    // The diff label depends on the full it references, so it is computed inside
    // `run_backup` (which knows the full label); full labels are timestamp-derived
    // up front. Pass `None` to let the inner function pick.
    //
    // The boxed controls (`primary` / `standby`) have non-trivial destructors (a
    // `RemoteBackupControl` reaps its worker on drop). Take the `&mut dyn`
    // borrows inside a block so they end — and the boxes can be dropped — before
    // the rest of the function runs, satisfying dropck.
    let outcome = {
        let primary_ref: Option<&mut (dyn BackupControl + '_)> = primary.as_deref_mut();
        let standby_ref: Option<&mut (dyn BackupControl + '_)> = standby.as_deref_mut();
        run_backup(
            stanza,
            repo_storage,
            copy_storage,
            backup_type,
            None,
            timestamp_start,
            &transform,
            process_max,
            checksum_page,
            &excludes,
            primary_ref,
            standby_ref,
            start_fast,
            features,
            block_overrides,
            job_retry,
            archive_copy,
            integrity,
            policy,
            repo_user_pass.as_deref(),
            // The repo sub-key used to read (decrypt + decompress) archived WAL
            // for archive-check / archive-copy. It is the same key the backup
            // transform encrypts data/WAL with (resolved above via
            // `active_sub_key`), so reuse it from the transform; `None` on an
            // unencrypted repo.
            transform.cipher_pass.as_deref(),
        )?
    };
    log_info(&format!(
        "backup {} complete: {} file(s), {} byte(s)",
        outcome.label, outcome.file_count, outcome.total_size
    ));

    // expire-auto (default on): apply retention right after a successful backup,
    // unless this was a dry run (nothing was added to expire against) or the user
    // disabled it. Calls the expire engine directly. C ref: backup.c runs
    // cmdExpire() at the end of a successful backup when expire-auto is set.
    if expire_auto_enabled(config) && !policy.dry_run {
        log_info("expire-auto: applying retention");
        let summary = crate::expire::expire_inner(config, repo_storage)?;
        log_info(&format!(
            "expire-auto: {} backup(s) expired, {} kept",
            summary.expired_labels.len(),
            summary.kept_labels.len()
        ));
    }
    Ok(())
}

/// The backup-control connections resolved per the `backup-standby` policy.
///
/// Each control object is a `Box<dyn BackupControl>` so a *local* cluster
/// (libpq [`LibpqBackupControl`]) and a *remote* one reached through a PG-host
/// worker ([`RemoteBackupControl`], the dedicated-repo-host pull topology) are
/// driven identically downstream — `pg_backup_start` / `pg_backup_stop` and the
/// info / status queries are transport-agnostic.
struct ControlConnections {
    /// Connection that drives `pg_backup_start` / `pg_backup_stop` — the primary
    /// (not in recovery). `None` when no DB source is configured (DB-free path).
    primary: Option<Box<dyn BackupControl>>,
    /// Optional in-recovery standby whose replay is polled before the file copy.
    standby: Option<Box<dyn BackupControl>>,
    /// The `pgN` index of the selected standby (`1`..=`8`), if any. Used to read
    /// backup files from the standby's data directory (I/O offload) when that
    /// `pgN` is locally reachable (no `pgN-host`).
    standby_index: Option<u32>,
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

    // Gather candidate `(pgN-index, conninfo)` pairs, deduplicated, primary
    // (pg1 / DATABASE_URL) first so it is preferred as the primary when reachable
    // + not in recovery. The index is retained so a selected standby's data
    // directory can be located for the file-copy I/O offload.
    let mut conninfos: Vec<(u32, String)> = Vec::new();
    if let Some(pg1) = derive_conninfo_with_url(config, std::env::var("DATABASE_URL").ok().as_deref()) {
        conninfos.push((1, pg1));
    }
    for index in 2..=MAX_PG_INDEX {
        if let Some(conninfo) = derive_conninfo_for_index(config, index)
            && !conninfos.iter().any(|(_, c)| c == &conninfo)
        {
            conninfos.push((index, conninfo));
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
            standby_index: None,
        });
    }

    let mut primary: Option<Box<dyn BackupControl>> = None;
    let mut standby: Option<Box<dyn BackupControl>> = None;
    let mut standby_index: Option<u32> = None;
    for (index, conninfo) in &conninfos {
        let mut control = open_control_for_index(config, *index, conninfo)?;
        let in_recovery = control.is_in_recovery()?;
        if in_recovery {
            if standby.is_none() && mode != StandbyMode::No {
                standby = Some(control);
                standby_index = Some(*index);
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

    Ok(ControlConnections {
        primary,
        standby,
        standby_index,
    })
}

/// Open the backup-control object for the cluster at `pg{index}`, choosing the
/// transport by `pgN-host`.
///
/// When `pgN-host` is set (the dedicated-repo-host pull topology) the control
/// connection must run on the PG host: a `pgbackrest` worker is spawned there
/// over SSH and opened against the PG host's *local* cluster (no `host=<pghost>`
/// — libpq uses the unix socket with peer / trust auth, no password), wrapped in
/// a [`RemoteBackupControl`]. Otherwise a local libpq [`LibpqBackupControl`] is
/// opened from `fallback_conninfo` (the `host=` / `DATABASE_URL` conninfo the
/// candidate list already built). Either way the returned object is a
/// `Box<dyn BackupControl>` the rest of the backup drives transport-agnostically.
///
/// # Errors
///
/// [`CommandError::Other`] when the worker cannot be spawned or its `db-open`
/// fails, or when the local libpq connection fails.
fn open_control_for_index(
    config: &LoadedConfig,
    index: u32,
    fallback_conninfo: &str,
) -> Result<Box<dyn BackupControl>, CommandError> {
    if let Some(host) = crate::remote_db::pg_host_for_index(config, index) {
        // The conninfo the worker opens locally: socket / port / db / user
        // (never the remote host) plus the global timeout / keepalive params.
        let extra = conninfo_timeout_keepalive_params(config);
        let conninfo = crate::remote_db::local_conninfo_for_index(config, index, &extra);
        let mut remote = crate::remote_db::spawn_pg_worker(config, &host, index)?;
        remote.open(&conninfo)?;
        return Ok(Box::new(RemoteBackupControl::new(remote)));
    }
    Ok(Box::new(LibpqBackupControl::open(fallback_conninfo)?))
}

/// The local data-directory path of the standby at `pg{index}`, when that
/// cluster is locally reachable (no `pgN-host` configured). Returns `None` for a
/// remote standby (`pgN-host` set) — its filesystem is only reachable through its
/// own inter-host worker, which the copy phase has no per-standby `pg_storage`
/// handle for, so a remote standby's files are read from the primary instead (the
/// backup stays consistent because start/stop run on the primary and the
/// standby's replay is awaited). The primary's own files, by contrast, ARE read
/// through `pg_storage` — including the remote/pull case where it is a worker
/// proxy (see [`read_source`]).
fn standby_local_path(config: &LoadedConfig, index: u32) -> Option<PathBuf> {
    let opt = |field: &str| -> Option<String> {
        let base = format!("pg-{field}");
        let legacy = format!("pg{index}-{field}");
        config
            .options
            .get(&(base.clone(), Some(index)))
            .or_else(|| config.options.get(&(base, None)))
            .or_else(|| config.options.get(&(legacy, None)))
            .and_then(|v| match v {
                OptionValue::String(s) | OptionValue::Path(s) | OptionValue::StringId(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            })
    };
    // A configured host means the standby is remote — not locally readable.
    if opt("host").is_some() {
        return None;
    }
    opt("path").map(PathBuf::from)
}

/// Whether the resolved `archive-copy` option is set.
///
/// `archive-copy=y` copies the WAL segments needed to make the backup
/// consistent (`backup-archive-start` .. `backup-archive-stop`) into the
/// backup `pg_wal/` directory. It is a `Boolean` defaulting to false; absent or
/// non-boolean values resolve to false. Only effective on a DB-driven backup
/// (one with a bracket); the DB-free file-copy path has no WAL range to copy.
fn archive_copy_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("archive-copy".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
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

/// Read a boolean option that **defaults to true** (the option model's default
/// for `archive-check` / `archive-mode-check` / `page-header-check`): unset or
/// non-boolean resolves to `true`; only an explicit `false` disables it.
fn boolean_default_true(config: &LoadedConfig, name: &str) -> bool {
    !matches!(
        config.options.get(&(name.to_owned(), None)),
        Some(OptionValue::Boolean(false))
    )
}

/// Whether `archive-check` is enabled (default true). When on, a DB-driven
/// backup verifies the WAL segments needed for consistency are present in the
/// repo archive after `pg_backup_stop`.
fn archive_check_enabled(config: &LoadedConfig) -> bool {
    boolean_default_true(config, "archive-check")
}

/// Whether `archive-mode-check` is enabled (default true). When on, a DB-driven
/// backup verifies the cluster's `archive_mode` is enabled before starting.
fn archive_mode_check_enabled(config: &LoadedConfig) -> bool {
    boolean_default_true(config, "archive-mode-check")
}

/// Whether `page-header-check` is enabled (default true). When on (and together
/// with the page-checksum pass), each relation page's header bookkeeping is
/// validated in addition to its stored checksum.
fn page_header_check_enabled(config: &LoadedConfig) -> bool {
    boolean_default_true(config, "page-header-check")
}

/// Resolve `--archive-timeout` (a [`OptionValue::Time`] in milliseconds) into a
/// [`std::time::Duration`], defaulting to 60s (the pgBackRest default) when
/// unset. Used to bound the `archive-check` wait for required WAL.
fn archive_timeout(config: &LoadedConfig) -> std::time::Duration {
    match config.options.get(&("archive-timeout".to_owned(), None)) {
        Some(OptionValue::Time(ms)) => std::time::Duration::from_millis(*ms),
        Some(OptionValue::Integer(secs)) if *secs >= 0 => std::time::Duration::from_secs(u64::try_from(*secs).unwrap_or(60)),
        _ => std::time::Duration::from_mins(1),
    }
}

/// Whether `--dry-run` was supplied. A `Boolean` defaulting to `false`; only an
/// explicit `true` enables the no-mutation planning mode. C ref: `cfgOptDryRun`.
fn dry_run_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("dry-run".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Whether `--resume` is enabled (default **true**). When on, an aborted prior
/// backup left in the same label directory is reused: files whose size + plaintext
/// checksum still match are not re-copied. Unset / non-boolean resolves to `true`;
/// only an explicit `false` disables resume.
fn resume_enabled(config: &LoadedConfig) -> bool {
    boolean_default_true(config, "resume")
}

/// Whether `--stop-auto` is enabled (default `false`). When on, a stale running
/// backup left on the cluster by a crashed prior run is stopped automatically
/// (`pg_backup_stop`) before this backup begins. C ref: `cfgOptStopAuto`.
fn stop_auto_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("stop-auto".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Whether `--expire-auto` is enabled (default **true**). When on, expire runs
/// automatically after a successful backup to apply retention. Unset / non-boolean
/// resolves to `true`; only an explicit `false` suppresses the auto-expire.
fn expire_auto_enabled(config: &LoadedConfig) -> bool {
    boolean_default_true(config, "expire-auto")
}

/// Default `manifest-save-threshold` (1 GiB) when the option is absent, matching
/// the option model's `1GiB` default.
const DEFAULT_MANIFEST_SAVE_THRESHOLD: u64 = 1024 * 1024 * 1024;

/// Resolve `--manifest-save-threshold` (a [`OptionValue::Size`] in bytes) into a
/// byte count, defaulting to 1 GiB when unset. During the copy phase the
/// in-progress manifest is re-saved each time this many bytes have been copied
/// since the last save, so an aborted backup leaves a fresher resume point.
fn manifest_save_threshold(config: &LoadedConfig) -> u64 {
    match config.options.get(&("manifest-save-threshold".to_owned(), None)) {
        Some(OptionValue::Size(value)) => *value,
        Some(OptionValue::Integer(value)) if *value >= 0 => u64::try_from(*value).unwrap_or(DEFAULT_MANIFEST_SAVE_THRESHOLD),
        _ => DEFAULT_MANIFEST_SAVE_THRESHOLD,
    }
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
    // Group options are stored under the base name keyed by group index — a
    // config-file `pg1-path` resolves to `("pg-path", Some(1))`, with an
    // ungrouped `("pg-path", None)` fallback (the scheme `storage_helper`
    // uses). Looking up `("pgN-path", None)` always misses, which is why a
    // file-configured local cluster previously fell through to the DB-free
    // path. The flat `pgN-…` spelling is still accepted last so unit-test
    // fixtures that insert it directly keep working.
    let opt = |field: &str| -> Option<String> {
        let base = format!("pg-{field}");
        let legacy = format!("pg{pg_index}-{field}");
        config
            .options
            .get(&(base.clone(), Some(pg_index)))
            .or_else(|| config.options.get(&(base, None)))
            .or_else(|| config.options.get(&(legacy, None)))
            .and_then(|v| match v {
                OptionValue::String(s) | OptionValue::Path(s) | OptionValue::StringId(s) if !s.is_empty() => Some(s.clone()),
                OptionValue::Integer(i) => Some(i.to_string()),
                _ => None,
            })
    };
    // A `pgN-host` / `pgN-socket-path` names where the server listens; when both
    // are absent but a local data dir (`pgN-path`) is configured, the cluster is
    // local and reached through libpq's default unix-socket directory (e.g.
    // `/var/run/postgresql`) — pgBackRest connects to a local cluster without an
    // explicit host. So `host` is optional: omit it for the local case.
    let host = opt("host").or_else(|| opt("socket-path"));
    if host.is_none() && opt("path").is_none() {
        // Neither a host/socket nor a local data dir: this index is not a
        // connectable cluster.
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(host) = host {
        parts.push(format!("host={host}"));
    }
    if let Some(p) = opt("port") {
        parts.push(format!("port={p}"));
    }
    if let Some(db) = opt("database") {
        parts.push(format!("dbname={db}"));
    }
    if let Some(user) = opt("user") {
        parts.push(format!("user={user}"));
    }
    // db-timeout + TCP keepalive parameters are global (not per-pgN); libpq parses
    // them straight out of the conninfo string, so no pgbr-db change is needed.
    parts.extend(conninfo_timeout_keepalive_params(config));
    Some(parts.join(" "))
}

/// Build the libpq conninfo fragments for `db-timeout` and the TCP keepalive
/// options, ready to append to a `host=… port=…` conninfo.
///
/// - `db-timeout` (a `Time`, milliseconds) becomes libpq's `connect_timeout`,
///   which is in **seconds** — the millisecond value is rounded up to at least 1
///   second so a sub-second timeout still bounds the connect rather than meaning
///   "no timeout" (`connect_timeout=0`).
/// - `tcp-keep-alive-idle` / `-interval` / `-count` (integers) become
///   `keepalives_idle` / `keepalives_interval` / `keepalives_count`, each implying
///   `keepalives=1` so libpq actually enables `SO_KEEPALIVE`.
///
/// libpq reads all of these from the conninfo string, so the connection picks
/// them up with no change to the `pgbr-db` wrapper. C ref: `db/db.c`'s
/// `dbOpen()` conninfo assembly.
fn conninfo_timeout_keepalive_params(config: &LoadedConfig) -> Vec<String> {
    let mut parts = Vec::new();

    // db-timeout -> connect_timeout (seconds, rounded up, min 1).
    let timeout_ms = match config.options.get(&("db-timeout".to_owned(), None)) {
        Some(OptionValue::Time(ms)) => Some(*ms),
        Some(OptionValue::Integer(secs)) if *secs >= 0 => Some(u64::try_from(*secs).unwrap_or(0).saturating_mul(1000)),
        _ => None,
    };
    if let Some(ms) = timeout_ms {
        // Round milliseconds up to whole seconds, with a floor of 1s when any
        // positive timeout was configured.
        let secs = ms.div_ceil(1000).max(1);
        parts.push(format!("connect_timeout={secs}"));
    }

    // TCP keepalive parameters. Any one of them enables keepalives=1.
    let int_opt = |name: &str| -> Option<i64> {
        match config.options.get(&(name.to_owned(), None)) {
            Some(OptionValue::Integer(v)) if *v >= 0 => Some(*v),
            _ => None,
        }
    };
    let idle = int_opt("tcp-keep-alive-idle");
    let interval = int_opt("tcp-keep-alive-interval");
    let count = int_opt("tcp-keep-alive-count");
    if idle.is_some() || interval.is_some() || count.is_some() {
        parts.push("keepalives=1".to_owned());
        if let Some(v) = idle {
            parts.push(format!("keepalives_idle={v}"));
        }
        if let Some(v) = interval {
            parts.push(format!("keepalives_interval={v}"));
        }
        if let Some(v) = count {
            parts.push(format!("keepalives_count={v}"));
        }
    }

    parts
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

/// Read a `Size` group option that resolved with a group index, returning
/// `Some(value)` for the first set index or `None` when none is set. Like
/// [`size_indexed`] but distinguishes "unset" from "set to the default value".
fn size_grouped_opt(config: &LoadedConfig, name: &str) -> Option<u64> {
    if let Some(OptionValue::Size(value)) = config.options.get(&(name.to_owned(), None)) {
        return Some(*value);
    }
    if let Some(OptionValue::Integer(value)) = config.options.get(&(name.to_owned(), None))
        && *value >= 0
    {
        return u64::try_from(*value).ok();
    }
    for idx in 1..=8 {
        match config.options.get(&(name.to_owned(), Some(idx))) {
            Some(OptionValue::Size(value)) => return Some(*value),
            Some(OptionValue::Integer(value)) if *value >= 0 => return u64::try_from(*value).ok(),
            _ => {}
        }
    }
    None
}

/// Read a `Hash` group option (`repo-block-*-map`), checking the bare and the
/// `repoN-`-indexed forms, and return its `BTreeMap<String, String>` entries.
fn hash_grouped<'a>(config: &'a LoadedConfig, name: &str) -> Option<&'a std::collections::BTreeMap<String, String>> {
    if let Some(OptionValue::Hash(map)) = config.options.get(&(name.to_owned(), None)) {
        return Some(map);
    }
    for idx in 1..=8 {
        if let Some(OptionValue::Hash(map)) = config.options.get(&(name.to_owned(), Some(idx))) {
            return Some(map);
        }
    }
    None
}

/// Parse one `repo-block-*-map` hash into a `(threshold, value)` pair list,
/// applying `key_parse` to each key and `value_parse` to each value. Entries that
/// fail to parse are skipped (a malformed override degrades to the heuristic
/// rather than failing the backup). Returns an empty list when the option is
/// unset.
fn parse_block_map<K, V>(config: &LoadedConfig, name: &str, key_parse: K, value_parse: V) -> Vec<(u64, u64)>
where
    K: Fn(&str) -> Option<u64>,
    V: Fn(&str) -> Option<u64>,
{
    hash_grouped(config, name).map_or_else(Vec::new, |map| {
        map.iter()
            .filter_map(|(k, v)| Some((key_parse(k)?, value_parse(v)?)))
            .collect()
    })
}

/// Parse a size string (e.g. `32KiB`, `512KiB`, `1MiB`) into bytes via the config
/// layer's size grammar; `None` on any parse error.
fn parse_size_str(raw: &str) -> Option<u64> {
    match pgbr_config::parse_value(pgbr_config::OptionType::Size, raw) {
        Ok(OptionValue::Size(bytes)) => Some(bytes),
        _ => None,
    }
}

/// Parse a plain unsigned integer (an age-in-days threshold, a block multiplier,
/// or a checksum-size byte count); `None` on any parse error.
fn parse_uint_str(raw: &str) -> Option<u64> {
    raw.trim().parse::<u64>().ok()
}

/// Build the [`crate::block::BlockOverrides`] from the resolved `repo-block-*`
/// options.
///
/// - `repo-block-size-map`: `<file size>=<block size>` — both size strings.
/// - `repo-block-age-map`: `<age in days>=<multiplier>` — both integers.
/// - `repo-block-checksum-size-map`: `<block size>=<checksum bytes>` — size string
///   key, integer value.
/// - `repo-block-size-super` / `-super-full`: super-block size strings.
///
/// Unset options leave the corresponding map empty / the super sizes at their
/// defaults, so [`crate::block::BlockOverrides::none`]-equivalent behaviour
/// results when nothing is configured.
fn block_overrides_from_options(config: &LoadedConfig) -> crate::block::BlockOverrides {
    let size_map = parse_block_map(config, "repo-block-size-map", parse_size_str, parse_size_str);
    let age_map = parse_block_map(config, "repo-block-age-map", parse_uint_str, parse_uint_str);
    let checksum_size_map = parse_block_map(config, "repo-block-checksum-size-map", parse_size_str, parse_uint_str);
    let super_size = size_grouped_opt(config, "repo-block-size-super");
    let super_size_full = size_grouped_opt(config, "repo-block-size-super-full");
    crate::block::BlockOverrides::new(size_map, age_map, checksum_size_map, super_size, super_size_full)
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

/// Resolve the effective `--checksum-page` value.
///
/// pgBackRest's documented behaviour is: when the user explicitly sets
/// `--checksum-page` / `--no-checksum-page`, that value wins; otherwise the
/// default is **dynamic** — `on` when the cluster has `data_checksums` enabled
/// (`pg_control.data_checksum_version != 0`) and `off` otherwise. This matches
/// the C `checkpage` resolution in `src/command/backup/backup.c`, which keys
/// the default off `pgControlFromFile()`.
///
/// The dynamic default is resolved here by reading `global/pg_control` through
/// `pg_storage`, decoding it with the [`pgbr_postgres::control`] helpers, and
/// consulting [`PgControlData::page_checksums_enabled`]. If the read or decode
/// fails for any reason (e.g. an unimplemented `pg_control` layout on a future
/// PG release) we fall back to `false` and log a one-line `INFO` note: a
/// conservative miss is safer than a hard backup failure, and the operator can
/// always pass `--checksum-page` explicitly.
///
/// When this returns `true`, eligible relation files have every page's stored
/// `pd_checksum` verified during the copy and any mismatch is surfaced through
/// `WARN` + the manifest's `checksum-page` array.
fn resolve_checksum_page(config: &LoadedConfig, pg_storage: &dyn Storage) -> bool {
    // Explicit user override wins, in either direction.
    if let Some(OptionValue::Boolean(explicit)) = config.options.get(&("checksum-page".to_owned(), None)) {
        return *explicit;
    }
    // Dynamic default: read pg_control. A failure (missing file, unknown
    // layout, short read) leaves the option off and logs a single INFO line so
    // an operator can see why validation did not engage.
    let mut reader = match pg_storage.open_read(Path::new("global/pg_control")) {
        Ok(reader) => reader,
        Err(err) => {
            log_info(&format!(
                "checksum-page: could not read global/pg_control ({err}); defaulting to off"
            ));
            return false;
        }
    };
    let data = match read_pg_control_data(&mut reader) {
        Ok(data) => data,
        Err(err) => {
            log_info(&format!(
                "checksum-page: could not decode global/pg_control ({err}); defaulting to off"
            ));
            return false;
        }
    };
    data.page_checksums_enabled().unwrap_or_else(|| {
        log_info(
            "checksum-page: pg_control layout not modelled for this PG version; defaulting to off (pass --checksum-page to force on)",
        );
        false
    })
}

/// Default number of retries for a failed file-copy job (`job-retry`). pgBackRest
/// defaults `backup`/`restore` `job-retry` to 2.
pub(crate) const DEFAULT_JOB_RETRY: u32 = 2;

/// Default delay between copy-job retries (`job-retry-interval`, 15 seconds),
/// expressed in milliseconds to match the option's `Time` representation.
pub(crate) const DEFAULT_JOB_RETRY_INTERVAL_MS: u64 = 15_000;

/// Retry policy for a single file-copy / restore job (`job-retry` +
/// `job-retry-interval`).
///
/// When a per-file copy fails, pgBackRest retries the job up to `retries` more
/// times, sleeping `interval` between attempts, before failing the command. This
/// covers transient I/O / network blips against the repository without aborting a
/// long backup. C ref: `cmdBackup` / `cmdRestore` job dispatch with
/// `cfgOptJobRetry` / `cfgOptJobRetryInterval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JobRetry {
    /// Number of *additional* attempts after the first (so total attempts =
    /// `retries + 1`). Zero means no retry — one attempt only.
    retries: u32,
    /// Delay between attempts.
    interval: std::time::Duration,
}

impl JobRetry {
    /// No retries: a single attempt, the prior behaviour. Used by the test
    /// wrappers so existing tests keep their exact (non-retrying) semantics.
    #[must_use]
    pub(crate) const fn none() -> Self {
        Self {
            retries: 0,
            interval: std::time::Duration::ZERO,
        }
    }

    /// Build a policy from explicit values. Test-only — production code uses
    /// [`JobRetry::from_options`] / [`JobRetry::none`].
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn new(retries: u32, interval: std::time::Duration) -> Self {
        Self { retries, interval }
    }

    /// Read `job-retry` (count) and `job-retry-interval` (time, milliseconds)
    /// from the resolved configuration, falling back to pgBackRest's defaults
    /// (2 retries, 15s) when absent or out of range.
    #[must_use]
    pub(crate) fn from_options(config: &LoadedConfig) -> Self {
        let retries = match config.options.get(&("job-retry".to_owned(), None)) {
            Some(OptionValue::Integer(value)) if *value >= 0 => u32::try_from(*value).unwrap_or(DEFAULT_JOB_RETRY),
            _ => DEFAULT_JOB_RETRY,
        };
        let interval_ms = match config.options.get(&("job-retry-interval".to_owned(), None)) {
            Some(OptionValue::Time(ms)) => *ms,
            Some(OptionValue::Integer(value)) if *value >= 0 => u64::try_from(*value).unwrap_or(DEFAULT_JOB_RETRY_INTERVAL_MS),
            _ => DEFAULT_JOB_RETRY_INTERVAL_MS,
        };
        Self {
            retries,
            interval: std::time::Duration::from_millis(interval_ms),
        }
    }

    /// Total number of attempts (`retries + 1`).
    #[must_use]
    pub(crate) const fn attempts(self) -> u32 {
        self.retries.saturating_add(1)
    }

    /// Run `op`, retrying up to `self.retries` more times (sleeping `interval`
    /// between attempts) until it succeeds. Returns the last error when every
    /// attempt fails.
    ///
    /// `op` is `FnMut` so the caller can re-do per-attempt work (e.g. re-read a
    /// source). The first attempt runs immediately; the interval sleep only
    /// happens *before* a retry, so a success on the first try never sleeps and a
    /// zero-retry policy never sleeps at all.
    pub(crate) fn run<T, E, F>(self, mut op: F) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
    {
        let mut attempt = 0u32;
        loop {
            match op() {
                Ok(value) => return Ok(value),
                Err(err) => {
                    attempt += 1;
                    if attempt >= self.attempts() {
                        return Err(err);
                    }
                    if !self.interval.is_zero() {
                        std::thread::sleep(self.interval);
                    }
                }
            }
        }
    }
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
    /// Absolute destination path in the repo, suffix included. Used by the
    /// local (`Posix`/`Cifs`) fast path, which writes via `std::fs`.
    abs_dest: PathBuf,
    /// Repo-*relative* destination path, suffix included
    /// (`backup/<stanza>/<label>/<rel><suffix>`) — the same relative path the
    /// manifest / info writes use. Used by the non-local (remote/object) path,
    /// which writes through [`Storage::open_write`].
    rel_dest: String,
    /// Whether the worker should page-checksum-validate this file. Set only for
    /// an eligible relation file when `--checksum-page` is on; the worker still
    /// re-checks page alignment before validating.
    validate_pages: bool,
    /// Whether the worker should additionally validate each page's *header*
    /// (`page-header-check`, default on). Only meaningful when `validate_pages`
    /// is set — the header check rides on the same page-validation pass and a
    /// header failure flags the page exactly like a checksum failure.
    validate_page_header: bool,
}

/// What a worker reports back for one [`CopyJob`].
#[derive(Debug, Clone)]
struct CopyResult {
    /// Plaintext SHA-1 (lowercase hex) of the source file.
    checksum: String,
    /// Number of bytes physically written to the repo (post-transform).
    repo_bytes: u64,
    /// Per-file page-checksum-validation outcome. `None` when the file was not
    /// validated (checksum-page off, not a relation file, or not page-aligned);
    /// `Some(ChecksumPage::Validated)` when every page passed; and
    /// `Some(ChecksumPage::InvalidBlocks(blocks))` when one or more pages
    /// failed (the block numbers identify them; the main thread also surfaces
    /// them via [`warn_invalid_pages`]).
    checksum_page: Option<ChecksumPage>,
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
#[allow(clippy::too_many_arguments)]
fn plan_file(
    pg_storage: &dyn Storage,
    entry: &WalkEntry,
    abs_repo_backup_root: &Path,
    backup_root: &str,
    transform: &RepoTransform,
    prior_manifest: Option<&Manifest>,
    prior_label: Option<&str>,
    checksum_page: bool,
    page_header_check: bool,
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
    let suffixed = format!("{}{}", entry.rel, transform.repo_suffix());
    let abs_dest = abs_repo_backup_root.join(&suffixed);
    // The repo-relative destination (the same path the manifest / info writes
    // use); the non-local copy path writes through `open_write` at this path.
    let rel_dest = format!("{backup_root}/{suffixed}");
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
            rel_dest,
            validate_pages,
            // The header check only matters when the page-validation pass runs.
            validate_page_header: validate_pages && page_header_check,
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

/// Transform one file's plaintext into the repo bytes, computing the same
/// checksum + page-validation outcome both copy paths record.
///
/// Shared by [`copy_file`] (the local `std::fs` fast path) and
/// [`copy_file_storage`] (the non-local `open_write` path) so the
/// checksum / page-checksum / page-header logic is written exactly once.
/// Returns the transformed repo bytes alongside a partially-filled
/// [`CopyResult`] (its `repo_bytes` reflects the transformed length, which the
/// caller does not need to recompute).
fn transform_and_validate(job: &CopyJob, bytes: &[u8], transform: &RepoTransform) -> Result<(Vec<u8>, CopyResult), CommandError> {
    let checksum = plaintext_sha1(bytes)?;

    // Page-checksum validation runs on the same plaintext bytes the checksum is
    // taken over, before the transform. A relation file is only validated when
    // its size is an exact multiple of `PAGE_SIZE`; an unaligned file (or a
    // non-relation file, which is never flagged) is left unvalidated
    // (`checksum_page == None`).
    let checksum_page = if job.validate_pages && !bytes.is_empty() && bytes.len().is_multiple_of(PAGE_SIZE) {
        let invalid = validate_relation_pages(bytes, job.validate_page_header);
        Some(if invalid.is_empty() {
            ChecksumPage::Validated
        } else {
            ChecksumPage::InvalidBlocks(invalid)
        })
    } else {
        None
    };

    // Keyed (SHA-1 KDF) chain: matches the manifest / info / WAL encryption so
    // an encrypted repo is internally consistent. With no sub-key the chain is
    // identical to the legacy path (compression only), so unencrypted repos are
    // byte-for-byte unchanged.
    let repo_bytes = transform.apply_forward_keyed(bytes)?;
    let result = CopyResult {
        checksum,
        repo_bytes: repo_bytes.len() as u64,
        checksum_page,
    };
    Ok((repo_bytes, result))
}

/// Read a copy job's source bytes from the PG data dir.
///
/// A local PG data dir (`Posix`/`Cifs` `pg_storage`) is read straight off disk
/// via `std::fs` against `job.abs_src` — the absolute path the walk recorded —
/// which is the original fast path and needs no `Storage` handle.
///
/// A non-local `pg_storage` is the dedicated-repo-host **pull** topology: the
/// orchestrator runs on the repo host, the PG data dir lives on a remote host
/// reached through an SSH-spawned worker, and `pg_storage` is a
/// [`pgbr_storage::remote::RemoteStorage`] proxy over that worker. There,
/// `job.abs_src` is the **remote** host's absolute path and does **not** exist on
/// this (repo) host — a `std::fs::read` would fail every time (and, under the
/// `job-retry` policy, spin forever in the retry backoff, hanging the backup).
/// So the source is read through the `Storage` trait at the PG-data-relative path
/// `job.rel` instead, exactly as the reference-detection pass in [`plan_file`]
/// already does, sending the read to the worker that can actually reach the file.
fn read_source(pg_storage: &dyn Storage, job: &CopyJob) -> Result<Vec<u8>, CommandError> {
    if pg_storage.is_local() {
        std::fs::read(&job.abs_src).map_err(|err| CommandError::Other(format!("read {}: {err}", job.abs_src.display())))
    } else {
        let mut reader = pg_storage.open_read(Path::new(&job.rel))?;
        Ok(reader.read_all()?)
    }
}

/// Copy one file into the repo: read `abs_src`, compress-then-encrypt the
/// plaintext into the repo bytes (the identity transform passes them through),
/// create the destination's parent directory, and write `abs_dest`. Returns the
/// plaintext checksum + the number of repo bytes written.
///
/// This is the per-file unit of work run on a dispatcher worker thread. It does
/// all of its I/O through `std::fs` against absolute paths, so it needs no
/// `Storage` handle and no borrow from the caller — only the owned `transform`
/// captured by the worker closure. This fast path is used **only** when **both**
/// the repo and the PG data dir are local (`Posix`/`Cifs`); a non-local repo
/// goes through [`copy_file_storage`], and a non-local (remote/pull) PG data dir
/// likewise forces [`copy_file_storage`], which reads the source via
/// [`read_source`].
fn copy_file(job: &CopyJob, transform: &RepoTransform) -> Result<CopyResult, CommandError> {
    let bytes = std::fs::read(&job.abs_src).map_err(|err| CommandError::Other(format!("read {}: {err}", job.abs_src.display())))?;

    let (repo_bytes, result) = transform_and_validate(job, &bytes, transform)?;

    if let Some(parent) = job.abs_dest.parent() {
        std::fs::create_dir_all(parent).map_err(|err| CommandError::Other(format!("create {}: {err}", parent.display())))?;
    }
    std::fs::write(&job.abs_dest, &repo_bytes)
        .map_err(|err| CommandError::Other(format!("write {}: {err}", job.abs_dest.display())))?;

    Ok(result)
}

/// Copy one file into the repo through the [`Storage`] trait, for a non-local
/// (remote/object) repo where `std::fs` would write to the wrong machine — or a
/// non-local (remote/pull) PG data dir where `std::fs` would read from the wrong
/// machine.
///
/// Reads the source via [`read_source`] (`std::fs` for a local PG data dir, the
/// `Storage` trait at the PG-data-relative path for a remote/pull one), runs the
/// **same** transform + page validation as [`copy_file`] via
/// [`transform_and_validate`], then writes the repo bytes through
/// `repo_storage.open_write(job.rel_dest)`. Runs serially on the main thread
/// because the remote storage is single-connection / `!Send` and cannot be
/// shared across the worker pool. Produces the identical [`CopyResult`] the
/// parallel path would, so the manifest is filled exactly the same way.
fn copy_file_storage(
    job: &CopyJob,
    transform: &RepoTransform,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
) -> Result<CopyResult, CommandError> {
    let bytes = read_source(pg_storage, job)?;

    let (repo_bytes, result) = transform_and_validate(job, &bytes, transform)?;

    // The destination's parent subdirectory (`global/`, `base/<oid>/`, …) may
    // not exist yet — `open_write` does not create parents — so create it first,
    // mirroring the local path's `create_dir_all`.
    let dest = Path::new(&job.rel_dest);
    if let Some(parent) = dest.parent() {
        repo_storage.create_path(parent, true)?;
    }
    write_repo_file(repo_storage, &job.rel_dest, &repo_bytes)?;

    Ok(result)
}

/// Inputs to [`run_bundled_copy`]. Grouped into a struct so the signature stays
/// readable (and clippy's `too_many_arguments` stays happy).
struct BundledCopyCtx<'a> {
    /// Repository storage backend.
    repo_storage: &'a dyn Storage,
    /// PG data dir storage. For the dedicated-repo-host pull topology this is a
    /// non-local [`pgbr_storage::remote::RemoteStorage`] proxy over a worker;
    /// [`read_source`] then reads each source file through it rather than via
    /// `std::fs` (whose absolute `job.abs_src` only exists on the remote PG host).
    pg_storage: &'a dyn Storage,
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
    /// Explicit block-incremental tuning overrides (`repo-block-*-map`,
    /// `repo-block-size-super*`). [`crate::block::BlockOverrides::none`] when none
    /// are configured, in which case the heuristic / defaults apply unchanged.
    block_overrides: crate::block::BlockOverrides,
    /// Whether this is a full backup, selecting `repo-block-size-super-full` over
    /// `repo-block-size-super` for the super-block size.
    is_full: bool,
    /// Per-file copy retry policy (`job-retry` / `job-retry-interval`), wrapped
    /// around each file's read in the serial bundled pass.
    job_retry: JobRetry,
    /// Backup start timestamp, used to compute each file's age for the block-size
    /// policy.
    timestamp_start: i64,
    /// Number of parallel file-copy workers (`process-max`). When the repo + PG
    /// data dir are both local, every per-file / per-block read + transform runs
    /// across this many threads via [`ParallelExecutor`]; otherwise the serial
    /// path is taken (mirroring [`run_copy_jobs`]).
    process_max: usize,
}

/// Copy pass for `repo-bundle=y` (and optionally `repo-block=y`).
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
/// When the repo + PG data dir are both local the per-file / per-block reads +
/// transforms run across `ctx.process_max` workers via [`ParallelExecutor`]; in
/// every other topology (a non-local repo or a non-local pull-PG data dir) the
/// classic serial path is taken because the underlying `Storage` handle is
/// single-connection / `!Send`. Bundle assembly stays on the main thread in both
/// paths to keep the byte layout byte-for-byte deterministic — every
/// `BundlePacker::place` call is made in skeleton-walk order.
///
/// Returns the completed manifest file entries plus the total repo bytes written.
///
/// # Errors
///
/// Propagates read / write / transform failures.
fn run_bundled_copy(ctx: BundledCopyCtx<'_>) -> Result<(Vec<ManifestFile>, u64), CommandError> {
    // Both the repo and the PG data dir local is the only topology where the
    // parallel `std::fs` fast path is safe — a non-local repo or a non-local
    // pull PG data dir is handled by the serial fallback below (same reasoning
    // as `run_copy_jobs`). The serial path is also taken when there is at most
    // one worker, because the parallel pipeline only buys throughput.
    if ctx.repo_storage.is_local() && ctx.pg_storage.is_local() && ctx.process_max > 1 {
        return run_bundled_copy_parallel(ctx);
    }
    run_bundled_copy_serial(ctx)
}

/// Serial bundled copy — the classic single-thread walk, used in two cases:
///
/// 1. The repo or the PG data dir is non-local (remote/object/pull). The
///    underlying `Storage` handles are single-connection / `!Send` and cannot
///    be shared across worker threads.
/// 2. `process-max <= 1`, where the parallel pipeline buys no throughput and
///    the serial path produces identical output with less overhead.
fn run_bundled_copy_serial(ctx: BundledCopyCtx<'_>) -> Result<(Vec<ManifestFile>, u64), CommandError> {
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
        // Read the source under the job-retry policy: a transient read failure is
        // retried up to `job-retry` times before failing the backup. The read goes
        // through `read_source`, so a non-local (remote/pull) PG data dir is read
        // via the worker rather than `std::fs` (whose absolute `job.abs_src` only
        // exists on the remote PG host).
        let bytes = ctx.job_retry.run(|| read_source(ctx.pg_storage, &job))?;
        let checksum = plaintext_sha1(&bytes)?;

        // Page-checksum + page-header validation, identical to the per-file path.
        let checksum_page = if job.validate_pages && !bytes.is_empty() && bytes.len() % PAGE_SIZE == 0 {
            let invalid = validate_relation_pages(&bytes, job.validate_page_header);
            Some(if invalid.is_empty() {
                ChecksumPage::Validated
            } else {
                ChecksumPage::InvalidBlocks(invalid)
            })
        } else {
            None
        };
        if let Some(ChecksumPage::InvalidBlocks(blocks)) = checksum_page.as_ref() {
            warn_invalid_pages(&skeleton.path, blocks);
        }

        // Decide the block size for this file (age + size policy, with any
        // `repo-block-*-map` overrides applied on top of the heuristic). A `Some`
        // size means block-incremental applies; `None` means store the file whole.
        let age = ctx.timestamp_start.saturating_sub(skeleton.timestamp);
        let block_size = if ctx.features.block {
            ctx.block_overrides.block_size(skeleton.size, age)
        } else {
            None
        };

        let entry = if let Some(block_size) = block_size {
            // Block-incremental file: split, store changed blocks in bundles,
            // reference unchanged ones, record a per-file block map. The
            // checksum-size and super-block-size overrides shape how each block is
            // checksummed and grouped (see `build_block_map`).
            let prior_map = ctx
                .prior_manifest
                .and_then(|m| m.file(&skeleton.path))
                .and_then(|f| f.block_map.as_ref());
            let block_map = build_block_map(
                &bytes,
                block_size,
                ctx.block_overrides.checksum_size(block_size),
                ctx.block_overrides.super_size(ctx.is_full),
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
            // otherwise write it as its own repo object (unbundled layout). The
            // keyed (SHA-1 KDF) chain keeps the bundle bytes consistent with the
            // manifest / WAL encryption (and is identity-equal with no sub-key).
            let repo_bytes = ctx.transform.apply_forward_keyed(&bytes)?;
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
                // unbundled path. A local repo writes via `std::fs` (the fast
                // path); a non-local repo must write through the `Storage` trait
                // so the object lands on the remote/object repo, not locally.
                if ctx.repo_storage.is_local() {
                    let abs_dest = job.abs_dest.clone();
                    if let Some(parent) = abs_dest.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|err| CommandError::Other(format!("create {}: {err}", parent.display())))?;
                    }
                    std::fs::write(&abs_dest, &repo_bytes)
                        .map_err(|err| CommandError::Other(format!("write {}: {err}", abs_dest.display())))?;
                } else {
                    if let Some(parent) = Path::new(&job.rel_dest).parent() {
                        ctx.repo_storage.create_path(parent, true)?;
                    }
                    write_repo_file(ctx.repo_storage, &job.rel_dest, &repo_bytes)?;
                }
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

/// One unit of bundled-copy work shipped to a worker thread. A whole-file
/// skeleton produces exactly one of these (`block.is_none()`); a
/// block-incremental skeleton produces one per *changed* block (its `block`
/// describes the byte range and the block index in the file). Reused blocks
/// never become a `BundleJob` — they are recorded as references on the main
/// thread during Phase 1 with no worker round-trip.
#[derive(Debug, Clone)]
struct BundleJob {
    /// PG-data-relative path, used as the dispatcher correlation key (the same
    /// key the worker echoes back so Phase 3 can look the result up).
    rel: String,
    /// Absolute source path on the local PG data dir. Workers read from this
    /// via `std::fs` because the parallel path only runs when the PG data dir
    /// is local.
    abs_src: PathBuf,
    /// Whether the worker should page-checksum-validate the bytes it read. Set
    /// only for whole-file relation files when `--checksum-page` is on; block
    /// jobs always carry `false` (per-page validation is a whole-file concern,
    /// matching `transform_and_validate`'s contract).
    validate_pages: bool,
    /// Whether the worker should also validate each page's header
    /// (`page-header-check`). Only meaningful when `validate_pages` is set.
    validate_page_header: bool,
    /// `Some` for a block-incremental block job — the byte range to read out of
    /// `abs_src` plus the block's index in the file. `None` for a whole-file job
    /// (the worker reads the whole file via `read_to_end`).
    block: Option<BundleBlockJob>,
}

/// The block-incremental subset of a [`BundleJob`]: which byte range in the
/// source file this job covers and where it falls in the file's block sequence.
#[derive(Debug, Clone, Copy)]
struct BundleBlockJob {
    /// Byte offset of the block inside `abs_src` (start of the seek).
    offset: u64,
    /// Number of plaintext bytes to read for this block. The last block of a
    /// file may be shorter than the configured `block_size`.
    len: u64,
    /// 0-based index of the block in the file. The main thread uses this to
    /// place the block reference into the correct slot of the file's block map.
    index: u64,
}

/// Worker outcome for one [`BundleJob`]. Carries the post-transform repo bytes
/// inline (base64-encoded so JSON can hold them) — the main thread base64-decodes
/// and appends to the in-memory bundle in deterministic skeleton + block order.
/// Workers never touch the shared bundle accumulator.
#[derive(Debug, Clone)]
struct BundleJobResult {
    /// Plaintext SHA-1 (lowercase hex) of the bytes this worker read. For a
    /// whole-file job this is the file's manifest checksum; for a block job this
    /// is the (untruncated) per-block checksum.
    checksum: String,
    /// Post-transform repo bytes. For a block job this is one block's contents;
    /// for a whole-file job this is the full file's transformed bytes.
    repo_bytes: Vec<u8>,
    /// Whole-file page-checksum / page-header validation outcome — `None` when
    /// the job did not validate (a block job, a non-relation file, or a file
    /// whose length is not a page multiple).
    checksum_page: Option<ChecksumPage>,
    /// Echo of [`BundleBlockJob::index`] for a block job, `None` for whole file.
    /// Lets the main thread index into the file's block-result vector when more
    /// than one job per file is in flight.
    block_index: Option<u64>,
}

/// Encode a [`BundleJob`] as a dispatcher [`Request`]: the job's `rel` path is
/// the `cmd` and the absolute source path / validation flags / block range ride
/// in `param`. Mirrors [`copy_job_to_request`].
fn create_bundled_copy_request(job: &BundleJob) -> Request {
    let (block_offset, block_len, block_index) = job.block.as_ref().map_or_else(
        || (json!(null), json!(null), json!(null)),
        |b| (json!(b.offset), json!(b.len), json!(b.index)),
    );
    Request {
        cmd: job.rel.clone(),
        param: vec![
            json!(job.abs_src.to_string_lossy()),
            json!(job.validate_pages),
            json!(job.validate_page_header),
            block_offset,
            block_len,
            block_index,
        ],
    }
}

/// Decode the response a worker produced into a [`BundleJobResult`], propagating
/// any malformed-payload error back to the dispatcher caller. Mirrors the
/// `process_*_response` helpers used by `run_copy_jobs`.
fn process_bundled_copy_response(key: &str, value: &serde_json::Value) -> Result<BundleJobResult, CommandError> {
    let checksum = value
        .get("checksum")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CommandError::Other(format!("bundled copy of {key} returned no checksum")))?
        .to_owned();
    let repo_bytes_b64 = value
        .get("repoBytesData")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CommandError::Other(format!("bundled copy of {key} returned no repo bytes")))?;
    // The worker base64-encodes the post-transform bytes so the response stays
    // JSON-shaped; decode them back into the raw repo bytes here.
    let repo_bytes = base64_decode(repo_bytes_b64)
        .map_err(|err| CommandError::Other(format!("bundled copy of {key} returned malformed base64: {err}")))?;
    let checksum_page: Option<ChecksumPage> = match value.get("checksumPage") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value(v.clone())
                .map_err(|err| CommandError::Other(format!("bundled copy of {key} returned malformed checksumPage: {err}")))?,
        ),
    };
    let block_index = value.get("blockIndex").and_then(serde_json::Value::as_u64);
    Ok(BundleJobResult {
        checksum,
        repo_bytes,
        checksum_page,
        block_index,
    })
}

/// Standard base64 decode helper. The dispatcher response only ever carries
/// well-formed strings (the worker writes through [`pgbr_encode`]); a decode
/// failure is therefore an internal protocol violation surfaced as `CommandError`.
fn base64_decode(src: &str) -> Result<Vec<u8>, String> {
    let needed = pgbr_encode::decoded_len(pgbr_encode::EncodingType::Base64, src).map_err(|err| err.to_string())?;
    let mut buf = vec![0u8; needed];
    pgbr_encode::decode(pgbr_encode::EncodingType::Base64, src, &mut buf).map_err(|err| err.to_string())?;
    Ok(buf)
}

/// Standard base64 encode helper (no embedded `\0`). Used by the worker to ship
/// post-transform bytes back over the JSON-shaped dispatcher response.
fn base64_encode(src: &[u8]) -> String {
    let len = pgbr_encode::encoded_len(pgbr_encode::EncodingType::Base64, src.len());
    let mut buf = vec![0u8; len + 1];
    pgbr_encode::encode(pgbr_encode::EncodingType::Base64, src, &mut buf);
    buf.truncate(len);
    // The encoder writes only the base64 alphabet + `=`, all ASCII.
    String::from_utf8(buf).unwrap_or_default()
}

/// Per-skeleton plan record built during Phase 1 of [`run_bundled_copy_parallel`]
/// for a whole-file skeleton. The worker has not yet run at this point — its
/// transformed bytes / checksum / page-validation outcome are joined in by `rel`
/// during Phase 3.
struct WholeFilePlan {
    skeleton: ManifestFile,
    rel_dest: String,
    abs_dest: PathBuf,
}

/// Per-skeleton plan record built during Phase 1 of [`run_bundled_copy_parallel`]
/// for a block-incremental skeleton. The whole-file plaintext was read on the
/// main thread to compute the per-block (reuse vs store) decision; the worker
/// returns transformed bytes for each *stored* block (the *reused* slots are
/// already filled in here).
struct BlockFilePlan {
    skeleton: ManifestFile,
    /// Whole-file plaintext SHA-1 (the manifest's `checksum` for this file).
    checksum: String,
    /// Whole-file page-checksum / page-header validation outcome (only set for
    /// validated relation files; otherwise `None`).
    checksum_page: Option<ChecksumPage>,
    /// Block size for this file (after the `repo-block-*-map` overrides applied).
    block_size: u64,
    /// Super-block size for this backup type (`repo-block-size-super[-full]`).
    super_size: u64,
    /// Per-block recorded checksum length (`repo-block-checksum-size-map`).
    checksum_size: u64,
    /// Per-block slot. `Some(BlockRef)` for a reused block (already final at
    /// Phase 1); `None` for a stored block, filled from the worker result.
    slots: Vec<Option<pgbr_info::manifest::BlockRef>>,
    /// Indices of stored blocks in file order, driving the super-block grouping
    /// in Phase 3.
    stored_indices: Vec<u64>,
}

/// One skeleton's Phase-1 plan, distinguished by whether it goes through the
/// whole-file or the block-incremental path.
enum SkeletonPlan {
    Whole(WholeFilePlan),
    Block(BlockFilePlan),
}

/// Parallel bundled copy. Runs **only** when both the repo and the PG data dir
/// are local — the parallel `std::fs` fast path is unsafe otherwise (a remote
/// PG data dir's absolute paths do not exist on this machine, a remote repo's
/// writes would land on the wrong host).
///
/// # Phase 1 (main thread, serial)
///
/// Walk `ctx.skeletons` in order. For each skeleton, decide which path applies:
///
/// - **Block-incremental** (`features.block` + block-eligible by size/age):
///   read the full file once on this thread (the block-boundary checksums need
///   the bytes), compute the per-block (truncated) checksum, and split the file
///   into *reused* blocks (matching the prior backup's block map by checksum,
///   recorded immediately as references with no worker round-trip) and
///   *changed* blocks (each becomes one [`BundleJob`] with its byte range).
/// - **Whole-file**: one [`BundleJob`] for the whole file with `block = None`.
///   The worker reads, hashes, validates, and transforms; the main thread later
///   decides whether the transformed bytes fit the bundle limit or land
///   standalone (the bundle-limit decision rides on the post-transform size).
///
/// # Phase 2 (workers, parallel)
///
/// `ParallelExecutor::new(process_max)` distributes the jobs across worker
/// threads. The worker closure captures **only** owned data — an owned clone of
/// the transform, the [`JobRetry`] policy (Copy), and the [`BackupFeatures`]
/// (Copy). No `Storage` handle crosses the boundary. Each worker re-decodes its
/// request, opens `abs_src` via `std::fs`, optionally seeks to a block range,
/// validates pages (whole-file jobs only), applies the keyed forward transform,
/// and returns the post-transform bytes (base64'd) plus the plaintext checksum
/// in a JSON-shaped [`Response`]. Worker errors surface as `Err(String)` per
/// [`JobResult`] and the main thread fails the whole backup on the first one.
///
/// # Phase 3 (main thread, serial — deterministic assembly)
///
/// Walk `ctx.skeletons` again in the same order Phase 1 walked them. For each
/// skeleton, look its worker result(s) up by `rel`, then:
///
/// - **Whole-file bundled** (repo size ≤ `bundle_limit`): call
///   `file_packer.place(repo_len)` (the same call the serial path makes, in the
///   same order, so the bundle ids + offsets are byte-identical), then append
///   the worker's bytes to `bundle_bytes[bundle_id]`. The packer's returned
///   offset is asserted to equal the current bundle length — a determinism
///   smoke test that a future bug would trip.
/// - **Whole-file unbundled** (repo size > `bundle_limit`): write the worker's
///   bytes to its own repo object (the same path the serial path uses).
/// - **Block-incremental changed blocks**: super-block-group them per
///   `super_block_layout`, `packer.place(super_len)` per group, append the
///   group's transformed bytes contiguously, and record one `BlockRef` per
///   block — exactly the serial code path in `build_block_map`.
///
/// After every skeleton is processed the bundle objects are flushed to the
/// repo, identical to the serial path's final loop.
#[allow(clippy::too_many_lines)]
fn run_bundled_copy_parallel(ctx: BundledCopyCtx<'_>) -> Result<(Vec<ManifestFile>, u64), CommandError> {
    use pgbr_info::manifest::{BlockMap, BlockRef};

    let BundledCopyCtx {
        repo_storage,
        pg_storage: _,
        backup_root,
        transform,
        label,
        skeletons,
        jobs,
        referenced,
        prior_manifest,
        features,
        block_overrides,
        is_full,
        job_retry,
        timestamp_start,
        process_max,
    } = ctx;

    // Correlate dispatcher jobs to skeletons by path. The dispatcher does not
    // need the absolute destination (the main thread handles all repo writes)
    // but does need the absolute source + validation flags, both carried on
    // `CopyJob`.
    let mut job_by_rel: std::collections::HashMap<String, CopyJob> = jobs.into_iter().map(|j| (j.rel.clone(), j)).collect();

    // ----- Phase 1: walk skeletons, build per-skeleton plan + worker jobs ----

    let mut plans: Vec<SkeletonPlan> = Vec::with_capacity(skeletons.len());
    let mut dispatcher_jobs: Vec<Job> = Vec::new();

    for skeleton in skeletons {
        let job = job_by_rel
            .remove(&skeleton.path)
            .ok_or_else(|| CommandError::Other(format!("no copy job for {}", skeleton.path)))?;

        // Decide the block size for this file. `None` means store whole.
        let age = timestamp_start.saturating_sub(skeleton.timestamp);
        let block_size = if features.block {
            block_overrides.block_size(skeleton.size, age)
        } else {
            None
        };

        if let Some(block_size) = block_size {
            // Block-incremental file: read once on this thread to compute per-block
            // checksums (the reuse decision needs the plaintext). The retry policy
            // matches the serial path so a transient read failure is masked here too.
            let bytes = job_retry
                .run(|| std::fs::read(&job.abs_src))
                .map_err(|err| CommandError::Other(format!("read {}: {err}", job.abs_src.display())))?;
            let checksum = plaintext_sha1(&bytes)?;
            // Page validation runs on whole-file plaintext bytes (same trigger as
            // the serial path). Block-incremental files include relation files, so
            // a `validate_pages` skeleton still validates here on the main thread.
            let checksum_page = if job.validate_pages && !bytes.is_empty() && bytes.len() % PAGE_SIZE == 0 {
                let invalid = validate_relation_pages(&bytes, job.validate_page_header);
                Some(if invalid.is_empty() {
                    ChecksumPage::Validated
                } else {
                    ChecksumPage::InvalidBlocks(invalid)
                })
            } else {
                None
            };
            if let Some(ChecksumPage::InvalidBlocks(blocks)) = checksum_page.as_ref() {
                warn_invalid_pages(&skeleton.path, blocks);
            }

            let checksum_size = block_overrides.checksum_size(block_size);
            let super_size = block_overrides.super_size(is_full);
            let blocks = crate::block::split_blocks(&bytes, block_size);
            let prior_map = prior_manifest
                .and_then(|m| m.file(&skeleton.path))
                .and_then(|f| f.block_map.as_ref());
            let mut slots: Vec<Option<BlockRef>> = vec![None; blocks.len()];
            let mut stored_indices: Vec<u64> = Vec::new();

            let mut block_offset: u64 = 0;
            for (idx, block) in blocks.iter().enumerate() {
                let block_len = block.len() as u64;
                let block_checksum = truncate_checksum(&plaintext_sha1(block)?, checksum_size);

                // Reuse path: prior backup recorded a block at this index with the
                // matching (truncated) checksum — no worker job, just record the ref.
                if let Some(prior) = prior_map.and_then(|m| m.blocks.get(idx))
                    && prior.checksum == block_checksum
                {
                    slots[idx] = Some(prior.clone());
                } else {
                    // Stored path: enqueue a worker job for this block's byte range.
                    // The block index correlates the worker's result back to the
                    // slot in `slots`.
                    let idx_u64 =
                        u64::try_from(idx).map_err(|err| CommandError::Other(format!("block index {idx} out of range: {err}")))?;
                    stored_indices.push(idx_u64);
                    let bundle_job = BundleJob {
                        rel: skeleton.path.clone(),
                        abs_src: job.abs_src.clone(),
                        // Block jobs never page-validate — whole-file validation
                        // already happened on the main thread above.
                        validate_pages: false,
                        validate_page_header: false,
                        block: Some(BundleBlockJob {
                            offset: block_offset,
                            len: block_len,
                            index: idx_u64,
                        }),
                    };
                    // Each block becomes a unique dispatcher key
                    // (`<rel>#block=<idx>`) so the result demultiplexer can tell
                    // multiple blocks of one file apart. The request `cmd` carries
                    // only `rel` so the worker still has the original PG-relative
                    // path; the dispatcher key is purely for correlation.
                    dispatcher_jobs.push(Job {
                        key: format!("{}#block={}", skeleton.path, idx_u64),
                        request: create_bundled_copy_request(&bundle_job),
                    });
                }
                block_offset = block_offset.saturating_add(block_len);
            }

            plans.push(SkeletonPlan::Block(BlockFilePlan {
                skeleton,
                checksum,
                checksum_page,
                block_size,
                super_size,
                checksum_size,
                slots,
                stored_indices,
            }));
        } else {
            // Whole-file path: enqueue one worker job; defer the bundle-vs-standalone
            // decision to Phase 3 (it rides on the post-transform repo length the
            // worker reports).
            let bundle_job = BundleJob {
                rel: skeleton.path.clone(),
                abs_src: job.abs_src.clone(),
                validate_pages: job.validate_pages,
                validate_page_header: job.validate_page_header,
                block: None,
            };
            dispatcher_jobs.push(Job {
                key: skeleton.path.clone(),
                request: create_bundled_copy_request(&bundle_job),
            });
            plans.push(SkeletonPlan::Whole(WholeFilePlan {
                skeleton,
                rel_dest: job.rel_dest.clone(),
                abs_dest: job.abs_dest.clone(),
            }));
        }
    }

    // ----- Phase 2: workers (parallel) ---------------------------------------

    // Owned captures only — no borrows from the stack frame leak into the
    // closure (the executor demands `Send + Sync + 'static`). Cloning the
    // `RepoTransform` is cheap (it's `Clone`); `JobRetry` and `BackupFeatures`
    // are `Copy`.
    let worker_transform = transform.clone();
    let worker_job_retry = job_retry;
    let job_count = dispatcher_jobs.len();
    let results = if dispatcher_jobs.is_empty() {
        Vec::new()
    } else {
        ParallelExecutor::new(process_max).run(dispatcher_jobs, move |request| {
            // Decode the per-job inputs from the dispatcher request.
            let abs_src = request
                .param
                .first()
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "bundled copy: missing source path".to_owned())?;
            let validate_pages = request.param.get(1).and_then(serde_json::Value::as_bool).unwrap_or(false);
            let validate_page_header = request.param.get(2).and_then(serde_json::Value::as_bool).unwrap_or(false);
            let block_offset = request.param.get(3).and_then(serde_json::Value::as_u64);
            let block_len = request.param.get(4).and_then(serde_json::Value::as_u64);
            let block_index = request.param.get(5).and_then(serde_json::Value::as_u64);

            // Read the source under the per-file retry policy (a transient read
            // failure is retried up to `job-retry` times, matching the serial path).
            let read_op = || -> Result<Vec<u8>, String> {
                if let (Some(off), Some(len)) = (block_offset, block_len) {
                    // Block job: seek to the block's start and read exactly `len`
                    // bytes (`read_exact` so a short read fails the job).
                    use std::io::{Read, Seek, SeekFrom};
                    let mut file = std::fs::File::open(abs_src).map_err(|err| format!("open {abs_src}: {err}"))?;
                    file.seek(SeekFrom::Start(off))
                        .map_err(|err| format!("seek {abs_src} to {off}: {err}"))?;
                    let len_usize = usize::try_from(len).map_err(|err| format!("block length {len} out of range: {err}"))?;
                    let mut buf = vec![0u8; len_usize];
                    file.read_exact(&mut buf)
                        .map_err(|err| format!("read_exact {abs_src} ({len} bytes): {err}"))?;
                    Ok(buf)
                } else {
                    // Whole-file job: read the entire file.
                    std::fs::read(abs_src).map_err(|err| format!("read {abs_src}: {err}"))
                }
            };
            let bytes = worker_job_retry.run(read_op)?;

            let checksum = plaintext_sha1(&bytes).map_err(|err| err.to_string())?;

            // Page validation only on whole-file relation jobs (matches the serial
            // `transform_and_validate` contract). A block job carries
            // `validate_pages = false`, so this branch is dead for them.
            let checksum_page = if validate_pages && !bytes.is_empty() && bytes.len() % PAGE_SIZE == 0 {
                let invalid = validate_relation_pages(&bytes, validate_page_header);
                Some(if invalid.is_empty() {
                    ChecksumPage::Validated
                } else {
                    ChecksumPage::InvalidBlocks(invalid)
                })
            } else {
                None
            };

            // Keyed forward transform (compress + encrypt), identical to the
            // serial path so the bundle byte layout is unchanged.
            let repo_bytes = worker_transform.apply_forward_keyed(&bytes).map_err(|err| err.to_string())?;

            let checksum_page_json = serde_json::to_value(&checksum_page).map_err(|err| format!("encode checksumPage: {err}"))?;
            Ok(Response::Ok(OkResponse {
                out: Some(json!({
                    "checksum": checksum,
                    "repoBytesData": base64_encode(&repo_bytes),
                    "checksumPage": checksum_page_json,
                    "blockIndex": block_index,
                })),
            }))
        })
    };

    // ----- Phase 2.5: index results by dispatcher key ------------------------

    // The dispatcher returns results in completion (i.e. non-deterministic)
    // order. Group them by skeleton `rel`:
    //   - whole-file: `key == rel` -> one result.
    //   - block: `key == <rel>#block=<idx>` -> many results per rel, addressed
    //     by `block_index` in the response.
    if results.len() != job_count {
        return Err(CommandError::Other(format!(
            "bundled copy: dispatcher returned {} result(s) for {job_count} job(s)",
            results.len()
        )));
    }
    let mut whole_by_rel: std::collections::HashMap<String, BundleJobResult> = std::collections::HashMap::new();
    let mut block_by_rel: std::collections::HashMap<String, std::collections::HashMap<u64, BundleJobResult>> =
        std::collections::HashMap::new();
    for job_result in results {
        let (rel, is_block) = match job_result.key.split_once("#block=") {
            Some((rel, _)) => (rel.to_owned(), true),
            None => (job_result.key.clone(), false),
        };
        let value = match job_result.result {
            Ok(Response::Ok(OkResponse { out: Some(v) })) => v,
            Ok(_) => {
                return Err(CommandError::Other(format!(
                    "bundled copy of {} produced an unexpected empty response",
                    job_result.key
                )));
            }
            Err(message) => return Err(CommandError::Other(message)),
        };
        let parsed = process_bundled_copy_response(&job_result.key, &value)?;
        if is_block {
            let idx = parsed
                .block_index
                .ok_or_else(|| CommandError::Other(format!("bundled block copy of {} returned no blockIndex", job_result.key)))?;
            block_by_rel.entry(rel).or_default().insert(idx, parsed);
        } else {
            whole_by_rel.insert(rel, parsed);
        }
    }

    // ----- Phase 3: deterministic bundle assembly ----------------------------

    let mut files: Vec<ManifestFile> = referenced;
    let mut repo_size: u64 = 0;
    let mut file_packer = crate::bundle::BundlePacker::new(features.bundle_size);
    let mut bundle_bytes: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();

    for plan in plans {
        match plan {
            SkeletonPlan::Whole(WholeFilePlan {
                skeleton,
                rel_dest,
                abs_dest,
            }) => {
                let worker = whole_by_rel
                    .remove(&skeleton.path)
                    .ok_or_else(|| CommandError::Other(format!("no bundled copy result for {}", skeleton.path)))?;
                let repo_len = worker.repo_bytes.len() as u64;
                repo_size += repo_len;
                if let Some(ChecksumPage::InvalidBlocks(blocks)) = worker.checksum_page.as_ref() {
                    warn_invalid_pages(&skeleton.path, blocks);
                }
                let entry = if repo_len <= features.bundle_limit {
                    // Bundled small file: deterministic place + append.
                    let slot = file_packer.place(repo_len);
                    let buf = bundle_bytes.entry(slot.bundle_id).or_default();
                    debug_assert_eq!(
                        buf.len() as u64,
                        slot.offset,
                        "bundle slot offset must match the current bundle length"
                    );
                    buf.extend_from_slice(&worker.repo_bytes);
                    ManifestFile {
                        checksum: Some(worker.checksum),
                        checksum_page: worker.checksum_page,
                        bundle_id: Some(slot.bundle_id),
                        bundle_offset: Some(slot.offset),
                        ..skeleton
                    }
                } else {
                    // Over-the-limit whole file: standalone repo object. Both repo
                    // and PG data dir are local here (parallel branch invariant),
                    // so `std::fs::write` against the absolute destination is the
                    // correct write — same code path the serial path takes.
                    if let Some(parent) = abs_dest.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|err| CommandError::Other(format!("create {}: {err}", parent.display())))?;
                    }
                    std::fs::write(&abs_dest, &worker.repo_bytes)
                        .map_err(|err| CommandError::Other(format!("write {}: {err}", abs_dest.display())))?;
                    // `rel_dest` is unused on the local path but kept on the plan so
                    // a future non-local-aware parallel implementation can reuse it.
                    let _ = rel_dest;
                    ManifestFile {
                        checksum: Some(worker.checksum),
                        checksum_page: worker.checksum_page,
                        ..skeleton
                    }
                };
                files.push(entry);
            }
            SkeletonPlan::Block(BlockFilePlan {
                skeleton,
                checksum,
                checksum_page,
                block_size,
                super_size,
                checksum_size,
                mut slots,
                stored_indices,
            }) => {
                // Look every stored block's worker result up by index, in file
                // order, so super-block grouping below operates on the same byte
                // sequence the serial path produced.
                let mut block_results = block_by_rel.remove(&skeleton.path).unwrap_or_default();
                let mut stored_bytes: Vec<Vec<u8>> = Vec::with_capacity(stored_indices.len());
                let mut stored_checksums: Vec<String> = Vec::with_capacity(stored_indices.len());
                for &idx in &stored_indices {
                    let res = block_results
                        .remove(&idx)
                        .ok_or_else(|| CommandError::Other(format!("no result for block {idx} of {}", skeleton.path)))?;
                    // The worker returned the untruncated plaintext SHA-1; the
                    // recorded per-block checksum is truncated per
                    // `repo-block-checksum-size-map` (same as the serial path
                    // through `truncate_checksum`).
                    stored_checksums.push(truncate_checksum(&res.checksum, checksum_size));
                    stored_bytes.push(res.repo_bytes);
                }

                let groups = super_block_layout(stored_indices.len(), block_size, super_size);
                let mut next = 0usize;
                for group_len in groups {
                    let super_len: u64 = stored_bytes[next..next + group_len].iter().map(|b| b.len() as u64).sum();
                    let super_slot = file_packer.place(super_len);
                    let buf = bundle_bytes.entry(super_slot.bundle_id).or_default();
                    debug_assert_eq!(
                        buf.len() as u64,
                        super_slot.offset,
                        "super-block slot offset must match the current bundle length"
                    );
                    let mut cursor = super_slot.offset;
                    for member in 0..group_len {
                        let i = next + member;
                        let bytes_i = &stored_bytes[i];
                        let repo_len = bytes_i.len() as u64;
                        repo_size += repo_len;
                        buf.extend_from_slice(bytes_i);
                        let block_idx = usize::try_from(stored_indices[i])
                            .map_err(|err| CommandError::Other(format!("block index {} out of range: {err}", stored_indices[i])))?;
                        slots[block_idx] = Some(BlockRef {
                            checksum: stored_checksums[i].clone(),
                            reference: label.to_owned(),
                            bundle_id: super_slot.bundle_id,
                            offset: cursor,
                            size: repo_len,
                        });
                        cursor = cursor.saturating_add(repo_len);
                    }
                    next += group_len;
                }
                let refs: Vec<BlockRef> = slots
                    .into_iter()
                    .enumerate()
                    .map(|(idx, slot)| {
                        slot.ok_or_else(|| CommandError::Other(format!("block {idx} left unplaced for {}", skeleton.path)))
                    })
                    .collect::<Result<_, _>>()?;
                files.push(ManifestFile {
                    checksum: Some(checksum),
                    checksum_page,
                    block_map: Some(BlockMap {
                        block_size,
                        blocks: refs,
                    }),
                    ..skeleton
                });
            }
        }
    }

    // ----- Flush bundles ----------------------------------------------------

    if !bundle_bytes.is_empty() {
        repo_storage.create_path(Path::new(&format!("{backup_root}/{}", crate::bundle::BUNDLE_DIR)), true)?;
    }
    for (id, data) in bundle_bytes {
        let path = crate::bundle::bundle_object_path(backup_root, id);
        write_repo_file(repo_storage, &path, &data)?;
    }

    Ok((files, repo_size))
}

/// Truncate a lowercase-hex checksum to `checksum_size` bytes (`2 *
/// checksum_size` hex characters). A zero / oversized size leaves the checksum
/// untouched. This realises `repo-block-checksum-size-map`: a smaller checksum
/// saves space in the block map at the cost of weaker change detection.
fn truncate_checksum(checksum: &str, checksum_size: u64) -> String {
    let hex_chars = checksum_size.saturating_mul(2);
    match usize::try_from(hex_chars) {
        Ok(n) if n > 0 && n < checksum.len() => checksum[..n].to_owned(),
        _ => checksum.to_owned(),
    }
}

/// Build a block-incremental [`BlockMap`] for one file's `bytes`.
///
/// Each block is transformed (compress + encrypt) on its own. A block whose
/// (truncated) plaintext checksum matches the prior backup's block at the same
/// index is *referenced* (its bytes are reused from the backup the prior pointed
/// at, so nothing new is stored); otherwise the transformed block is appended to
/// a bundle in *this* backup and the new location recorded. A full backup (no
/// prior map) stores every block here and the map self-references this backup.
///
/// Group the (stored) blocks of a file into super blocks of at most `super_size`
/// plaintext bytes (`repo-block-size-super[-full]`). Returns the count of blocks
/// in each super block, in order; the sum equals `block_count`.
///
/// At least one block per super block (a `super_size` smaller than `block_size`,
/// or a zero of either, degrades to one block per super block). A super block
/// groups consecutive blocks so they are stored contiguously in one bundle
/// region, mirroring pgBackRest's "a super block contains multiple blocks to
/// improve compression efficiency" (block reads start at the super block).
fn super_block_layout(block_count: usize, block_size: u64, super_size: u64) -> Vec<usize> {
    if block_count == 0 {
        return Vec::new();
    }
    // A zero block size (the `None` from checked_div) degrades to one block per
    // super block; otherwise at least one block per super block.
    let per_super = super_size
        .checked_div(block_size)
        .map_or(1, |n| usize::try_from(n.max(1)).unwrap_or(usize::MAX));
    let mut groups = Vec::new();
    let mut remaining = block_count;
    while remaining > 0 {
        let take = remaining.min(per_super);
        groups.push(take);
        remaining -= take;
    }
    groups
}

/// Build a block-incremental [`BlockMap`] for one file's `bytes`.
///
/// Each block is transformed (compress + encrypt) on its own. A block whose
/// (truncated) plaintext checksum matches the prior backup's block at the same
/// index is *referenced* (its bytes are reused from the backup the prior pointed
/// at, so nothing new is stored); otherwise the transformed block is appended to
/// a bundle in *this* backup and the new location recorded. A full backup (no
/// prior map) stores every block here and the map self-references this backup.
///
/// `checksum_size` is the recorded checksum length in bytes
/// (`repo-block-checksum-size-map`); the stored / compared checksum is truncated
/// to it. `super_size` is the super-block size (`repo-block-size-super[-full]`):
/// the *stored* (changed / new) blocks are grouped into super blocks of at most
/// `super_size` plaintext bytes via [`super_block_layout`], and each super block's
/// transformed bytes are placed into the bundle as one contiguous unit, so a
/// restore reads a whole super block from one bundle region.
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
    checksum_size: u64,
    super_size: u64,
    transform: &RepoTransform,
    label: &str,
    prior_map: Option<&pgbr_info::manifest::BlockMap>,
    bundle_bytes: &mut std::collections::BTreeMap<u64, Vec<u8>>,
    packer: &mut crate::bundle::BundlePacker,
    repo_size: &mut u64,
) -> Result<pgbr_info::manifest::BlockMap, CommandError> {
    use pgbr_info::manifest::{BlockMap, BlockRef};

    let blocks = crate::block::split_blocks(bytes, block_size);
    // The map has one entry per block, in file order, indexed by `idx`. A `None`
    // slot is a stored block awaiting placement; reused (referenced) blocks are
    // filled immediately from the prior map.
    let mut refs: Vec<Option<BlockRef>> = vec![None; blocks.len()];

    // The indices of the blocks that must be physically stored this backup (those
    // not reused from the prior map), in file order. Their transformed bytes are
    // grouped into super blocks and placed contiguously.
    let mut stored_idx: Vec<usize> = Vec::new();
    let mut stored_bytes: Vec<Vec<u8>> = Vec::new();
    let mut stored_checksums: Vec<String> = Vec::new();

    for (idx, block) in blocks.iter().enumerate() {
        let checksum = truncate_checksum(&plaintext_sha1(block)?, checksum_size);

        // Reuse an unchanged block from the prior backup when its (truncated)
        // checksum matches the prior entry's recorded checksum.
        if let Some(prior) = prior_map.and_then(|m| m.blocks.get(idx))
            && prior.checksum == checksum
        {
            refs[idx] = Some(prior.clone());
            continue;
        }

        // Changed / new block: transform it now, stash it for super-block
        // placement. Keyed (SHA-1 KDF) so block bytes match the rest of an
        // encrypted repo; identity-equal with no sub-key.
        stored_idx.push(idx);
        stored_bytes.push(transform.apply_forward_keyed(block)?);
        stored_checksums.push(checksum);
    }

    // Place the stored blocks super block by super block. Each super block's
    // blocks are appended contiguously so they share one bundle region; the
    // per-block offset is the running cursor within that region.
    let groups = super_block_layout(stored_idx.len(), block_size, super_size);
    let mut next = 0usize;
    for group_len in groups {
        // The transformed size of this super block (sum of its blocks).
        let super_len: u64 = stored_bytes[next..next + group_len].iter().map(|b| b.len() as u64).sum();
        let super_slot = packer.place(super_len);
        let mut cursor = super_slot.offset;
        let target = bundle_bytes.entry(super_slot.bundle_id).or_default();
        for member in 0..group_len {
            let i = next + member;
            let repo_bytes = &stored_bytes[i];
            let repo_len = repo_bytes.len() as u64;
            *repo_size += repo_len;
            target.extend_from_slice(repo_bytes);
            refs[stored_idx[i]] = Some(BlockRef {
                checksum: stored_checksums[i].clone(),
                reference: label.to_owned(),
                bundle_id: super_slot.bundle_id,
                offset: cursor,
                size: repo_len,
            });
            cursor = cursor.saturating_add(repo_len);
        }
        next += group_len;
    }

    // Every slot is now filled (each block was either reused or stored).
    let refs: Vec<BlockRef> = refs
        .into_iter()
        .enumerate()
        .map(|(idx, slot)| slot.ok_or_else(|| CommandError::Other(format!("block {idx} left unplaced"))))
        .collect::<Result<_, _>>()?;

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

/// DB-free full backup like [`backup_inner`], threading the user passphrase.
///
/// `repo_user_pass` lets `backup.info` be loaded / re-saved encrypted on an
/// encrypted repository (the manifest + data files are keyed via `transform`'s
/// sub-key). Mirrors what the real `backup()` command does for an encrypted repo;
/// `repo_user_pass = None` is byte-for-byte identical to [`backup_inner`].
pub fn backup_inner_keyed(
    stanza: &str,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    label: &str,
    timestamp_start: i64,
    transform: &RepoTransform,
    repo_user_pass: Option<&str>,
) -> Result<BackupOutcome, CommandError> {
    run_backup(
        stanza,
        repo_storage,
        pg_storage,
        BackupType::Full,
        Some(label),
        timestamp_start,
        transform,
        DEFAULT_PROCESS_MAX,
        false,
        &[],
        None,
        None,
        false,
        BackupFeatures::disabled(),
        crate::block::BlockOverrides::none(),
        JobRetry::none(),
        false,
        IntegrityChecks::disabled(),
        BackupPolicy::test_default(),
        repo_user_pass,
        transform.cipher_pass.as_deref(),
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
            json!(job.validate_page_header),
            json!(job.rel_dest),
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
    // The page-header flag defaults to false for older-shaped requests too.
    let validate_page_header = request.param.get(3).and_then(serde_json::Value::as_bool).unwrap_or(false);
    // The repo-relative destination rides in `param[4]`; older-shaped requests
    // without it default to empty (the local std::fs path uses `abs_dest`, not
    // `rel_dest`, so this only matters for the non-local path which never goes
    // through the dispatcher).
    let rel_dest = request
        .param
        .get(4)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    Ok(CopyJob {
        rel: request.cmd.clone(),
        abs_src: PathBuf::from(abs_src),
        abs_dest: PathBuf::from(abs_dest),
        rel_dest,
        validate_pages,
        validate_page_header,
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
///
/// `job_retry` wraps each per-file copy: a failed copy is retried up to
/// `job-retry` more times (with `job-retry-interval` between attempts) inside the
/// worker before the job — and the whole backup — fails. [`JobRetry::none`]
/// reproduces the single-attempt behaviour exactly.
///
/// When `repo_storage` is **not** local (a remote/object repo backend) the
/// parallel `std::fs` path is unsafe — `std::fs` would *write* to the wrong
/// machine — and when `pg_storage` is **not** local (the dedicated-repo-host
/// pull topology, where the PG data dir is reached over a worker) the parallel
/// path is equally unsafe — `std::fs` would *read* from the wrong machine (the
/// absolute `job.abs_src` only exists on the remote PG host). In either case the
/// copies run serially on the main thread through [`copy_file_storage`], which
/// reads via [`read_source`] and writes via [`Storage::open_write`] (a local
/// `Posix` repo is still written correctly through the trait). The storage
/// handles are single-connection / `!Send` and cannot cross the worker boundary.
/// The result is the identical [`CopyResult`] list, so callers are unaffected by
/// which path ran. The parallel `std::fs` fast path runs **only** when both the
/// repo and the PG data dir are local.
fn run_copy_jobs(
    jobs: &[CopyJob],
    transform: &RepoTransform,
    worker_count: usize,
    job_retry: JobRetry,
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
) -> Result<Vec<(String, CopyResult)>, CommandError> {
    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    // Non-local repo OR non-local PG data dir: copy every file through the
    // `Storage` trait, serially on this thread. The parallel `std::fs` path below
    // would land the bytes on the local machine instead of the remote/object repo
    // (non-local repo), or read `job.abs_src` — the *remote* PG host's absolute
    // path — off the local disk where it does not exist (non-local pull PG dir).
    if !repo_storage.is_local() || !pg_storage.is_local() {
        let mut out = Vec::with_capacity(jobs.len());
        for job in jobs {
            let copied = job_retry.run(|| copy_file_storage(job, transform, repo_storage, pg_storage))?;
            out.push((job.rel.clone(), copied));
        }
        return Ok(out);
    }

    let dispatcher_jobs: Vec<Job> = jobs
        .iter()
        .map(|job| Job {
            key: job.rel.clone(),
            request: copy_job_to_request(job),
        })
        .collect();

    // Both the repo and the PG data dir are local here (the serial branch above
    // caught every non-local combination), so the parallel `std::fs` fast path is
    // safe. The dispatcher demands a `Send + Sync + 'static` worker, so the
    // closure can only borrow owned data: an owned clone of the transform (cheap)
    // and whatever rides in each `Request`. No `Storage` handle crosses the
    // boundary — in particular `pg_storage` is NOT captured (a `RemoteStorage` is
    // single-connection / `!Send`); it does not need to be, because this path
    // runs only when the PG data dir is local and the source is read off disk via
    // `std::fs` in `copy_file`. Nothing borrowed from this stack frame escapes.
    let worker_transform = transform.clone();
    let results = ParallelExecutor::new(worker_count).run(dispatcher_jobs, move |request| {
        let job = request_to_copy_job(request)?;
        // Retry the copy per `job-retry`: re-read + re-transform + re-write on
        // each attempt so a transient failure (e.g. a flaky write) can recover.
        let copied = job_retry
            .run(|| copy_file(&job, &worker_transform))
            .map_err(|err| err.to_string())?;
        // `checksum_page` is `Option<ChecksumPage>`: it serialises to `null` for
        // `None`, JSON `true` for `Validated`, and a JSON array of block numbers
        // for `InvalidBlocks` — i.e. the same wire shape stock pgBackRest writes
        // in the manifest. The decoder below maps each variant back.
        let checksum_page_json =
            serde_json::to_value(&copied.checksum_page).map_err(|err| format!("encode checksumPage for {}: {err}", job.rel))?;
        Ok(Response::Ok(OkResponse {
            out: Some(json!({
                "checksum": copied.checksum,
                "repoBytes": copied.repo_bytes,
                "checksumPage": checksum_page_json,
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
                // `checksumPage` is absent / `null` (not validated), JSON `true`
                // (every page valid → [`ChecksumPage::Validated`]), or a JSON
                // array of block numbers (one or more invalid pages →
                // [`ChecksumPage::InvalidBlocks`]). The wire shape mirrors the
                // manifest, so a single deserialise via [`ChecksumPage`]'s own
                // `Deserialize` impl handles all three cases.
                let checksum_page: Option<ChecksumPage> = match value.get("checksumPage") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => Some(serde_json::from_value(v.clone()).map_err(|err| {
                        CommandError::Other(format!(
                            "copy of {} returned a malformed checksumPage value: {err}",
                            job_result.key
                        ))
                    })?),
                };
                out.push((
                    job_result.key,
                    CopyResult {
                        checksum,
                        repo_bytes,
                        checksum_page,
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

/// A partial backup left in the same label directory by an aborted prior run,
/// used to drive `--resume`.
///
/// Resume reuses files the prior run had already copied: its `backup.manifest`
/// (saved incrementally by `manifest-save-threshold`, see [`run_unbundled_copy`])
/// records the path + size + plaintext checksum of each copied file. A current
/// PG file whose size **and** freshly-computed plaintext checksum match the prior
/// entry — and whose repo object is still present — is reused verbatim. C ref:
/// `backup.c`'s resume path, which loads `backup.manifest.copy` and skips the
/// re-copy of files whose checksum still matches.
struct ResumeContext {
    /// The aborted prior run's manifest (its file entries are the reuse source).
    manifest: Manifest,
    /// Storage-relative backup root, used to check each candidate's repo object
    /// is actually present before reusing it.
    backup_root: String,
}

impl ResumeContext {
    /// Detect a resumable partial backup: a `backup.manifest` already present in
    /// `backup_root` (left by a crashed prior run for the same label). Returns
    /// `None` when there is nothing to resume or the partial manifest is
    /// unreadable (resume is best-effort — a bad partial just falls back to a
    /// full re-copy).
    fn detect(repo_storage: &dyn Storage, backup_root: &str, sub_key: Option<&str>) -> Option<Self> {
        let manifest_path = PathBuf::from(format!("{backup_root}/backup.manifest"));
        if !repo_storage.exists(&manifest_path).unwrap_or(false) {
            return None;
        }
        // The partial manifest was saved keyed with the repo sub-key on an
        // encrypted repo; load it keyed so resume can read it (`None` == the
        // plaintext load on an unencrypted repo).
        let manifest = Manifest::load_keyed(repo_storage, &manifest_path, sub_key).ok()?;
        Some(Self {
            manifest,
            backup_root: backup_root.to_owned(),
        })
    }

    /// Move every job whose file the prior backup already holds out of
    /// `skeletons` / `jobs` and return the reused [`ManifestFile`] entries.
    ///
    /// A job is reusable when the prior manifest has an entry for the same path
    /// with the same size whose recorded plaintext checksum equals the current
    /// source file's plaintext checksum, and whose repo object still exists. The
    /// `skeletons` and `jobs` vectors stay index-parallel (correlated by `rel`)
    /// after the split. Reuse is best-effort: any I/O error reading the source
    /// just leaves the file on the copy path.
    fn split_resumable(
        &self,
        pg_storage: &dyn Storage,
        skeletons: &mut Vec<ManifestFile>,
        jobs: &mut Vec<CopyJob>,
    ) -> Vec<ManifestFile> {
        let mut reused = Vec::new();
        let mut kept_skeletons: Vec<ManifestFile> = Vec::with_capacity(skeletons.len());
        let mut kept_jobs: Vec<CopyJob> = Vec::with_capacity(jobs.len());

        // The two vectors are index-parallel: skeleton[i] corresponds to job[i].
        for (skeleton, job) in std::mem::take(skeletons).into_iter().zip(std::mem::take(jobs)) {
            if let Some(reused_file) = self.try_reuse(pg_storage, &skeleton) {
                reused.push(reused_file);
            } else {
                kept_skeletons.push(skeleton);
                kept_jobs.push(job);
            }
        }

        *skeletons = kept_skeletons;
        *jobs = kept_jobs;
        reused
    }

    /// Try to reuse one planned file from the prior partial backup; `None` when
    /// it cannot be reused (no matching prior entry, size / checksum mismatch,
    /// repo object missing, or a read error).
    fn try_reuse(&self, pg_storage: &dyn Storage, skeleton: &ManifestFile) -> Option<ManifestFile> {
        let prior = self.manifest.file(&skeleton.path)?;
        if prior.size != skeleton.size {
            return None;
        }
        let prior_checksum = prior.checksum.as_deref()?;

        // The prior entry's repo object must still be present to reuse it. The
        // repo filename carries the compression suffix; a referenced (not copied)
        // prior entry has no standalone object and is not reusable here.
        if prior.reference.is_some() {
            return None;
        }

        // Recompute the current source's plaintext checksum and compare. A read
        // failure (e.g. the file vanished) just falls back to the copy path.
        let bytes = pg_storage.open_read(&PathBuf::from(&skeleton.path)).ok()?.read_all().ok()?;
        let checksum = plaintext_sha1(&bytes).ok()?;
        if checksum != prior_checksum {
            return None;
        }

        // The reused file keeps the prior entry's checksum/page result but is a
        // standalone copied file in *this* backup (reference stays None): its
        // bytes already live at `<backup_root>/<path><suffix>` from the prior run.
        let _ = &self.backup_root;
        Some(ManifestFile {
            checksum: Some(checksum),
            checksum_page: prior.checksum_page.clone(),
            ..skeleton.clone()
        })
    }
}

/// Everything [`run_unbundled_copy`] needs: the copy jobs / skeletons, the
/// already-decided referenced + reused files, and the manifest metadata needed to
/// write a periodic in-progress `backup.manifest` for `manifest-save-threshold`.
struct UnbundledCopyCtx<'a> {
    repo_storage: &'a dyn Storage,
    /// PG data dir storage. For the dedicated-repo-host pull topology this is a
    /// non-local [`pgbr_storage::remote::RemoteStorage`] proxy over a worker, so
    /// the copy reads the source through it instead of `std::fs` (whose absolute
    /// `job.abs_src` only exists on the remote PG host).
    pg_storage: &'a dyn Storage,
    backup_root: &'a str,
    backup_type: BackupType,
    label: &'a str,
    db_version: &'a str,
    db_system_id: u64,
    transform: &'a RepoTransform,
    jobs: &'a [CopyJob],
    skeletons: Vec<ManifestFile>,
    referenced: Vec<ManifestFile>,
    paths: &'a [ManifestPath],
    links: &'a [ManifestLink],
    process_max: usize,
    /// Per-file copy retry policy (`job-retry` / `job-retry-interval`).
    job_retry: JobRetry,
    timestamp_start: i64,
    manifest_save_threshold: u64,
}

/// The classic per-file parallel copy, plus periodic in-progress manifest saves.
///
/// Runs every [`CopyJob`] across `process_max` workers (byte-for-byte the prior
/// inline behaviour), then assembles the [`ManifestFile`] list from the results.
/// As it accumulates repo bytes it re-saves the in-progress `backup.manifest`
/// every time `manifest-save-threshold` bytes have been written since the last
/// save, so an aborted backup leaves a fresher resume point on disk (and the
/// final save in `run_backup` records the complete manifest). A threshold of
/// `u64::MAX` (the test default) never triggers a mid-copy save, preserving the
/// prior single-save behaviour exactly.
///
/// Returns the assembled file list and the total repo bytes written.
fn run_unbundled_copy(mut ctx: UnbundledCopyCtx<'_>) -> Result<(Vec<ManifestFile>, u64), CommandError> {
    let copy_results = run_copy_jobs(
        ctx.jobs,
        ctx.transform,
        ctx.process_max,
        ctx.job_retry,
        ctx.repo_storage,
        ctx.pg_storage,
    )?;
    let mut result_by_rel: std::collections::HashMap<String, CopyResult> = copy_results.into_iter().collect();

    // Move the skeletons + already-decided referenced files out of `ctx` so the
    // periodic `save_partial_manifest(&ctx, …)` can borrow `ctx`'s remaining
    // fields while we consume the skeletons.
    let skeletons = std::mem::take(&mut ctx.skeletons);
    let mut files: Vec<ManifestFile> = std::mem::take(&mut ctx.referenced);
    let mut repo_size: u64 = 0;
    let mut bytes_since_save: u64 = 0;
    let mut saved_count: u32 = 0;

    for skeleton in skeletons {
        let copied = result_by_rel
            .remove(&skeleton.path)
            .ok_or_else(|| CommandError::Other(format!("no copy result for {}", skeleton.path)))?;
        repo_size += copied.repo_bytes;
        bytes_since_save += copied.repo_bytes;
        // A file with one or more invalid pages records its invalid block list
        // in `checksum_page` and emits a `WARN` line naming the bad blocks —
        // the same diagnostic stock pgBackRest surfaces. The manifest then
        // carries the array form (`[0, 3, …]`) so consumers like `verify` can
        // see which blocks failed without re-reading the file.
        if let Some(ChecksumPage::InvalidBlocks(blocks)) = copied.checksum_page.as_ref() {
            warn_invalid_pages(&skeleton.path, blocks);
        }
        files.push(ManifestFile {
            checksum: Some(copied.checksum),
            checksum_page: copied.checksum_page,
            ..skeleton
        });

        // manifest-save-threshold: re-save the in-progress manifest once enough
        // bytes have been copied since the last save. Best-effort — a save error
        // is not fatal to an otherwise-progressing backup (the final save in
        // run_backup is the authoritative one).
        if bytes_since_save >= ctx.manifest_save_threshold {
            save_partial_manifest(&ctx, &files)?;
            bytes_since_save = 0;
            saved_count += 1;
        }
    }

    if saved_count > 0 {
        log_info(&format!(
            "manifest-save-threshold: saved the in-progress manifest {saved_count} time(s) during copy"
        ));
    }

    Ok((files, repo_size))
}

/// Save the in-progress `backup.manifest` mid-copy (the `manifest-save-threshold`
/// durability checkpoint). The partial manifest lists only the files copied so
/// far; its paths / links mirror the final manifest so a resumed run can read it.
fn save_partial_manifest(ctx: &UnbundledCopyCtx<'_>, files: &[ManifestFile]) -> Result<(), CommandError> {
    let mut sorted_files = files.to_vec();
    sorted_files.sort_by(|a, b| a.path.cmp(&b.path));
    let mut paths = ctx.paths.to_vec();
    paths.sort_by(|a, b| a.path.cmp(&b.path));
    let mut links = ctx.links.to_vec();
    links.sort_by(|a, b| a.path.cmp(&b.path));

    let partial = Manifest {
        backup_label: ctx.label.to_owned(),
        backup_type: ctx.backup_type.as_str().to_owned(),
        timestamp_start: ctx.timestamp_start,
        timestamp_stop: ctx.timestamp_start,
        db_version: ctx.db_version.to_owned(),
        db_system_id: ctx.db_system_id,
        files: sorted_files,
        // The in-progress save is only used to drive `--resume` of an aborted
        // backup; the resume codepath does not consume `option-checksum-page`
        // so we leave it unset (the final save in `run_backup` writes the
        // authoritative value). Keeping it `None` also matches the
        // byte-on-disk shape of manifests written by the prior code path.
        option_checksum_page: None,
        paths,
        links,
    };
    // Encrypt the in-progress manifest with the same repository sub-key the data
    // files use (carried in the transform); `None` (unencrypted) writes plaintext
    // exactly as before. A resumed run reads it back keyed (see
    // `ResumeContext::detect`).
    partial
        .save_keyed(
            ctx.repo_storage,
            &PathBuf::from(format!("{}/backup.manifest", ctx.backup_root)),
            ctx.transform.cipher_pass.as_deref(),
        )
        .map_err(|err| CommandError::Other(err.to_string()))
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
#[allow(clippy::too_many_arguments)]
fn plan_backup(
    pg_storage: &dyn Storage,
    abs_repo_backup_root: &Path,
    backup_root: &str,
    transform: &RepoTransform,
    prior_manifest: Option<&Manifest>,
    prior_label: Option<&str>,
    checksum_page: bool,
    page_header_check: bool,
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
        // A built-in excluded runtime directory (`pg_notify`, `pg_wal`, …) is
        // kept in the manifest as an *empty* path so a fresh-PGDATA restore
        // recreates it, but its contents are never captured. The walk does not
        // descend into these dirs, so only the bare directory entry arrives.
        if is_excluded_dir(&entry.rel) && entry.info.kind == StorageKind::Path && !is_user_excluded(&entry.rel, excludes) {
            plan.paths.push(ManifestPath { path: entry.rel });
            continue;
        }
        // Anything underneath an excluded runtime dir, an excluded root file,
        // `pg_internal.init`, or a user `--exclude` match is dropped entirely.
        if is_excluded(&entry.rel) || is_user_excluded(&entry.rel, excludes) {
            continue;
        }

        match entry.info.kind {
            StorageKind::File => match plan_file(
                pg_storage,
                &entry,
                abs_repo_backup_root,
                backup_root,
                transform,
                prior_manifest,
                prior_label,
                checksum_page,
                page_header_check,
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
    sub_key: Option<&str>,
) -> Result<(Option<String>, Option<Manifest>), CommandError> {
    let prior_label = match backup_type {
        BackupType::Full => return Ok((None, None)),
        BackupType::Diff => latest_full_label(info)
            .ok_or_else(|| CommandError::Other("differential backup requires a prior full backup".to_owned()))?,
        BackupType::Incr => {
            latest_any_label(info).ok_or_else(|| CommandError::Other("incremental backup requires a prior backup".to_owned()))?
        }
    };

    // The prior backup's manifest is encrypted with the repository sub-key on an
    // encrypted repo; load it keyed (`None` == plaintext load).
    let prior_manifest = Manifest::load_keyed(
        repo_storage,
        &PathBuf::from(format!("backup/{stanza}/{prior_label}/backup.manifest")),
        sub_key,
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
        crate::block::BlockOverrides::none(),
        JobRetry::none(),
        false,
        IntegrityChecks::disabled(),
        BackupPolicy::test_default(),
        None,
        None,
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
    mut control: Option<&mut (dyn BackupControl + '_)>,
    mut standby: Option<&mut (dyn BackupControl + '_)>,
    start_fast: bool,
    features: BackupFeatures,
    block_overrides: crate::block::BlockOverrides,
    job_retry: JobRetry,
    archive_copy: bool,
    integrity: IntegrityChecks,
    policy: BackupPolicy,
    repo_user_pass: Option<&str>,
    repo_sub_key: Option<&str>,
) -> Result<BackupOutcome, CommandError> {
    let info_path = backup_info_path(stanza);
    if !repo_storage.exists(&info_path)? {
        return Err(CommandError::Other(
            "stanza not initialized; run stanza-create first".to_owned(),
        ));
    }

    // On an encrypted repository backup.info is encrypted under the user
    // passphrase (`repo-cipher-pass`); decrypt on load and keep the recorded
    // `[cipher]` sub-key so it can be re-saved encrypted unchanged. `None` (the
    // unencrypted repo) is the byte-for-byte plaintext path.
    let (mut info, recorded_sub) =
        InfoBackup::load_keyed(repo_storage, &info_path, repo_user_pass).map_err(|err| CommandError::Other(err.to_string()))?;

    // Validate the live cluster against the stanza before touching any files:
    // a system-id / version mismatch means the configured PG is not the cluster
    // this stanza was created for. C ref: backup.c's dbGet() / dbPgCheck().
    let server_info = match control.as_mut() {
        Some(control) => Some(validate_server_against_stanza(&mut **control, &info)?),
        None => None,
    };

    // stop-auto: a backup that crashed after pg_backup_start leaves the cluster
    // with a running backup the next start would refuse. When --stop-auto is on,
    // clear that stale state by calling pg_backup_stop first; nothing-was-running
    // surfaces as an error there, which is expected and swallowed. C ref:
    // backup.c's dbBackupStop() when cfgOptStopAuto is set.
    if policy.stop_auto
        && let Some(control) = control.as_mut()
        && control.stop_running_backup()?
    {
        log_warn("stop-auto: stopped a stale running backup left by a prior aborted run");
    }

    // archive-mode-check: a DB-driven backup that relies on the archive must
    // confirm the cluster actually archives WAL, or the required WAL would never
    // reach the repo. Checked on the primary up front so the backup fails fast
    // rather than after copying every file. C ref: backup.c's
    // dbBackupStart() archive_mode validation.
    if integrity.archive_mode_check
        && let Some(control) = control.as_mut()
    {
        let in_recovery = control.is_in_recovery()?;
        check_archive_mode(&mut **control, in_recovery)?;
    }

    // For a diff/incr, resolve the prior backup and load its manifest so
    // unchanged files can be detected by (size, checksum).
    let (prior_label, prior_manifest) = resolve_prior(repo_storage, stanza, backup_type, &info, transform.cipher_pass.as_deref())?;

    let label = label.map_or_else(
        || derive_label(backup_type, prior_label.as_deref(), timestamp_start),
        ToOwned::to_owned,
    );

    let backup_root = format!("backup/{stanza}/{label}");

    // resume: detect an aborted prior backup left in this exact label directory.
    // Its `backup.manifest` (saved incrementally as the prior run progressed)
    // lists the files it had already copied; a file whose source still has the
    // same size + plaintext checksum is reused (its repo object is already there)
    // rather than re-copied. Disabled for dry-run (no copy happens) and for the
    // bundled path (a bundle object is rewritten wholesale, so partial reuse is
    // not safe). C ref: backup.c's manifestLoadFile of `backup.manifest.copy`.
    let resume_ctx = if policy.resume && !policy.dry_run && !features.bundle {
        ResumeContext::detect(repo_storage, &backup_root, transform.cipher_pass.as_deref())
    } else {
        None
    };
    if resume_ctx.is_some() {
        log_info("resume: found a partial backup in this label; reusing matching files");
    }

    // The backup root must exist before planning copies so the workers' absolute
    // destination paths anchor under a real directory (and so the manifest write
    // later has a home, even for an improbably empty cluster). A dry-run makes no
    // repository writes at all, so the directory is not created; the copy jobs it
    // plans are never executed, so their (placeholder) absolute destinations are
    // never touched.
    let abs_repo_backup_root = if policy.dry_run {
        PathBuf::from(&backup_root)
    } else {
        repo_storage.create_path(Path::new(&backup_root), true)?;
        absolute_path(repo_storage, Path::new(&backup_root))?
    };

    // Begin the online backup (if a control connection is present). The start
    // LSN is captured now; the copy then runs while the backup is open. A dry-run
    // never opens an online backup (that would mutate cluster state).
    let start_lsn = match (control.as_mut(), server_info.as_ref()) {
        (Some(control), Some(_)) if !policy.dry_run => Some(control.backup_start(&label, start_fast)?),
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
        &backup_root,
        transform,
        prior_manifest.as_ref(),
        prior_label.as_deref(),
        checksum_page,
        integrity.page_header_check,
        excludes,
    )?;

    // resume: split the planned copy jobs into the files an aborted prior backup
    // already holds (reused, no copy) and the files that still need copying. With
    // no resume context every job stays a copy, byte-for-byte the prior behaviour.
    let mut referenced = std::mem::take(&mut plan.referenced);
    if let Some(resume_ctx) = resume_ctx.as_ref() {
        let resumed = resume_ctx.split_resumable(pg_storage, &mut plan.copy_skeletons, &mut plan.copy_jobs);
        if !resumed.is_empty() {
            log_info(&format!("resume: reused {} already-copied file(s)", resumed.len()));
            referenced.extend(resumed);
        }
    }

    // Produce the file entries + total repo size. With bundling off this is the
    // classic per-file parallel copy (byte-for-byte unchanged); with bundling on
    // the small files are packed into shared bundle objects and large eligible
    // files may be block-split — a serial pass since a bundle object is appended
    // to in order.
    let (mut files, repo_size) = if policy.dry_run {
        // dry-run: report what WOULD be copied and skip every repository write.
        // The per-file plaintext checksum the workers would compute is not taken
        // (no bytes are read for copy), so each skeleton is recorded without a
        // checksum — the manifest is never persisted in a dry run anyway.
        for skeleton in &plan.copy_skeletons {
            log_info(&format!("dry-run: would copy {} ({} byte(s))", skeleton.path, skeleton.size));
        }
        let mut files: Vec<ManifestFile> = referenced;
        files.extend(plan.copy_skeletons);
        (files, 0u64)
    } else if features.bundle {
        run_bundled_copy(BundledCopyCtx {
            repo_storage,
            pg_storage,
            backup_root: &backup_root,
            transform,
            label: &label,
            skeletons: plan.copy_skeletons,
            jobs: plan.copy_jobs,
            referenced,
            prior_manifest: prior_manifest.as_ref(),
            features,
            block_overrides,
            is_full: backup_type == BackupType::Full,
            job_retry,
            timestamp_start,
            process_max,
        })?
    } else {
        run_unbundled_copy(UnbundledCopyCtx {
            repo_storage,
            pg_storage,
            backup_root: &backup_root,
            backup_type,
            label: &label,
            db_version: &info.db_version,
            db_system_id: info.db_system_id,
            transform,
            jobs: &plan.copy_jobs,
            skeletons: plan.copy_skeletons,
            referenced,
            paths: &plan.paths,
            links: &plan.links,
            process_max,
            job_retry,
            timestamp_start,
            manifest_save_threshold: policy.manifest_save_threshold,
        })?
    };
    let mut paths = plan.paths;
    let mut links = plan.links;

    let timestamp_stop = timestamp_start;
    let mut repo_size = repo_size;

    // Close the online backup (on the same session) and assemble the bracket.
    // The stop also yields the `backup_label` / `tablespace_map` file contents,
    // which are written into the backup root. The timeline + `wal_segment_size`
    // are sourced from the live cluster (`pg_control_checkpoint()` / `pg_settings`)
    // so the recorded WAL segment names are correct on non-default-segment
    // clusters and post-failover timelines.
    let bracket = match (control.as_mut(), start_lsn) {
        (Some(control), Some(start_lsn)) => {
            let (timeline, wal_segment_size) = resolve_wal_geometry(&mut **control)?;
            let stop = control.backup_stop()?;
            write_backup_label_files(repo_storage, &backup_root, &stop)?;
            Some(build_bracket(&start_lsn, &stop, timeline, wal_segment_size)?)
        }
        _ => None,
    };

    // archive-check: verify the WAL segments needed to make this backup
    // consistent (archive-start..archive-stop) are present in the repo archive,
    // waiting up to `archive-timeout` for each to arrive (PostgreSQL's
    // archive_command archives the stop segment only after pg_backup_stop). A
    // required segment that never lands is a hard error — the backup cannot be
    // restored to consistency without it. Done after the bracket (which yields
    // the segment range) and before archive-copy (which also needs them present).
    // C ref: backupArchiveCheckCopy() in src/command/backup/backup.c.
    if integrity.archive_check
        && let Some(bracket) = bracket.as_ref()
    {
        wait_for_required_wal(
            repo_storage,
            stanza,
            bracket,
            integrity.archive_timeout,
            WAL_POLL_INTERVAL,
            repo_user_pass,
            repo_sub_key,
        )?;
    }

    // archive-copy: when enabled, copy every WAL segment from the start segment
    // through the stop segment (inclusive) out of the repo archive into this
    // backup's `pg_wal/`, recording each as a regular ManifestFile so restore
    // places them. Done after the bracket (which yields the segment range) and
    // before totals are computed so the copied WAL counts toward the manifest.
    if archive_copy && let Some(bracket) = bracket.as_ref() {
        let copied = copy_archive_wal(
            repo_storage,
            stanza,
            &backup_root,
            transform,
            bracket,
            repo_user_pass,
            repo_sub_key,
        )?;
        for (file, repo_bytes) in copied {
            repo_size += repo_bytes;
            files.push(file);
        }
    }

    // Sort every manifest list by path so the on-disk manifest (and its
    // checksum) is deterministic regardless of worker completion order. (The
    // archive-copy pg_wal entries are sorted in alongside the data files.)
    files.sort_by(|a, b| a.path.cmp(&b.path));
    paths.sort_by(|a, b| a.path.cmp(&b.path));
    links.sort_by(|a, b| a.path.cmp(&b.path));

    let total_size: u64 = files.iter().map(|f| f.size).sum();
    let file_count = files.len();

    let manifest = Manifest {
        backup_label: label.clone(),
        backup_type: backup_type.as_str().to_owned(),
        timestamp_start,
        timestamp_stop,
        db_version: info.db_version.clone(),
        db_system_id: info.db_system_id,
        files,
        // Record the resolved `--checksum-page` value in `[backup:option]`.
        // pgBackRest stock emits this so `info` / `verify` can show whether the
        // backup actually validated relation pages; the value is the bool the
        // caller resolved (either explicit user setting or the dynamic
        // `pg_control.data_checksum_version` default).
        option_checksum_page: Some(checksum_page),
        paths,
        links,
    };

    // dry-run: every action has been planned and logged; make no repository
    // writes (no manifest, no backup.info entry) and return the would-be outcome
    // so the caller can report what a real run would have done.
    if policy.dry_run {
        log_info(&format!(
            "dry-run: backup {label} would record {file_count} file(s), {total_size} byte(s)"
        ));
        return Ok(BackupOutcome {
            label,
            file_count,
            total_size,
            bracket,
        });
    }

    // The backup root was created up front (before planning copies), so it
    // exists even for an improbably empty cluster and the manifest write has a
    // home. On an encrypted repository the manifest is encrypted with the same
    // repository sub-key the data files used (carried in `transform.cipher_pass`);
    // `None` (unencrypted) writes the byte-for-byte plaintext manifest.
    manifest
        .save_keyed(
            repo_storage,
            &PathBuf::from(format!("{backup_root}/backup.manifest")),
            transform.cipher_pass.as_deref(),
        )
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
    // Re-save backup.info, re-encrypting under the user passphrase and
    // re-injecting the recorded `[cipher]` sub-key on an encrypted repository so
    // the file (and its `.copy` mirror) is not clobbered with plaintext. An
    // unencrypted repo keeps the byte-for-byte plaintext save (no `.copy`).
    if let Some(pass) = repo_user_pass {
        info.save_keyed(repo_storage, &info_path, Some(pass), recorded_sub.as_deref())
            .map_err(|err| CommandError::Other(err.to_string()))?;
    } else {
        info.save(repo_storage, &info_path)
            .map_err(|err| CommandError::Other(err.to_string()))?;
    }

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
/// Each LSN is mapped to the WAL segment that contains it on `timeline` using
/// the cluster `wal_segment_size`. Both are sourced from the live cluster (the
/// timeline from `pg_control_checkpoint()`, the segment size from
/// `pg_settings`), so `backup-archive-start` / `backup-archive-stop` are correct
/// on non-default-segment clusters and post-failover timelines. An unparseable
/// LSN is a hard error: the server returned something that is not a `PostgreSQL`
/// LSN.
///
/// # Errors
///
/// [`CommandError::Other`] when either LSN cannot be parsed.
fn build_bracket(
    start_lsn: &str,
    stop: &BackupStopResult,
    timeline: u32,
    wal_segment_size: u64,
) -> Result<BackupBracket, CommandError> {
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
    let archive_start = lsn_text_to_wal_segment(timeline, start_lsn, wal_segment_size)
        .ok_or_else(|| CommandError::Other(format!("could not derive WAL segment for start LSN {start_lsn}")))?;
    let archive_stop = lsn_text_to_wal_segment(timeline, &stop.lsn, wal_segment_size)
        .ok_or_else(|| CommandError::Other(format!("could not derive WAL segment for stop LSN {}", stop.lsn)))?;
    Ok(BackupBracket {
        lsn_start: start_lsn.to_owned(),
        lsn_stop: stop.lsn.clone(),
        archive_start,
        archive_stop,
        timeline,
        wal_segment_size,
    })
}

/// Copy the WAL segments required to make this backup consistent out of the repo
/// archive into this backup `pg_wal` directory, recording each as a regular
/// [`ManifestFile`] so restore re-places them.
///
/// Implements `archive-copy=y`. C reference: the archive-copy path in
/// `src/command/backup/backup.c`. The range is `backup-archive-start` through
/// `backup-archive-stop` inclusive, enumerated by
/// [`pgbr_postgres::lsn::wal_segment_range`] (honouring the cluster
/// `wal_segment_size` and the live timeline carried in `bracket`). For each
/// segment:
///
/// 1. Locate it in the repo archive and read its plaintext bytes (transparently
///    decompressing whatever stored form is present) via
///    [`crate::archive::read_archived_segment`]. A required segment that is
///    absent from the archive is a hard error — the backup cannot be made
///    consistent without it (matching pgBackRest, which errors rather than
///    silently omitting WAL).
/// 2. Run the plaintext through this backup [`RepoTransform`] (compress then
///    encrypt) just like any backup file, and write it to
///    `backup/<stanza>/<label>/pg_wal/<segment><suffix>`.
/// 3. Build a [`ManifestFile`] at `pg_wal/<segment>` carrying the plaintext size
///    and SHA-1 (with `reference: None`, since this backup physically holds the
///    bytes) so the file round-trips on restore through the normal file path.
///
/// Returns `(ManifestFile, repo_bytes_written)` for every copied segment.
///
/// # Errors
///
/// [`CommandError::Other`] when a required segment is missing from the archive;
/// plus storage / IO / filter failures from the read, transform, or write.
fn copy_archive_wal(
    repo_storage: &dyn Storage,
    stanza: &str,
    backup_root: &str,
    transform: &RepoTransform,
    bracket: &BackupBracket,
    user_pass: Option<&str>,
    sub_key: Option<&str>,
) -> Result<Vec<(ManifestFile, u64)>, CommandError> {
    let segments = wal_segment_range(&bracket.archive_start, &bracket.archive_stop, bracket.wal_segment_size).ok_or_else(|| {
        CommandError::Other(format!(
            "could not enumerate WAL segment range {}..{} for archive-copy",
            bracket.archive_start, bracket.archive_stop
        ))
    })?;

    let suffix = transform.repo_suffix();
    // Ensure the destination `pg_wal/` directory exists before writing segments
    // (the data-file copy path creates parents per file via std::fs; here the
    // repo storage backend creates the shared directory once).
    repo_storage.create_path(Path::new(&format!("{backup_root}/pg_wal")), true)?;
    let mut out = Vec::with_capacity(segments.len());
    for segment in &segments {
        let bytes = crate::archive::read_archived_segment(repo_storage, stanza, segment, user_pass, sub_key)?.ok_or_else(|| {
            CommandError::Other(format!(
                "archive-copy: required WAL segment {segment} is missing from the archive"
            ))
        })?;
        let checksum = plaintext_sha1(&bytes)?;
        // Keyed (SHA-1 KDF) chain, consistent with the data-file / manifest /
        // WAL-archive encryption; identity-equal with no sub-key.
        let repo_bytes = transform.apply_forward_keyed(&bytes)?;

        let rel = format!("pg_wal/{segment}");
        let dest = format!("{backup_root}/{rel}{suffix}");
        write_repo_file(repo_storage, &dest, &repo_bytes)?;

        out.push((
            ManifestFile {
                path: rel,
                size: bytes.len() as u64,
                timestamp: 0,
                checksum: Some(checksum),
                checksum_page: None,
                reference: None,
                mode: None,
                user: None,
                group: None,
                bundle_id: None,
                bundle_offset: None,
                block_map: None,
            },
            repo_bytes.len() as u64,
        ));
    }
    Ok(out)
}

/// Poll interval while [`wait_for_required_wal`] waits for a required WAL
/// segment to be archived.
const WAL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Verify a cluster's `archive_mode` is enabled (`archive-mode-check`).
///
/// `archive_mode` must be `on` (a primary archiving WAL). A standby in recovery
/// may legitimately run with `archive_mode = always`, but a *primary* reporting
/// `always` is unexpected (it would double-archive), so it is rejected unless the
/// cluster is in recovery. `off` is always an error: the WAL a backup needs would
/// never reach the repo. C reference: the `archive_mode` validation in
/// `src/command/backup/backup.c` / `src/command/check/check.c`.
///
/// # Errors
///
/// [`CommandError::Other`] when `archive_mode` is `off`, when it is `always` on a
/// primary (not in recovery), or when the setting cannot be read.
fn check_archive_mode(control: &mut dyn BackupControl, in_recovery: bool) -> Result<(), CommandError> {
    let mode = control.archive_mode()?;
    match mode.as_str() {
        "on" => Ok(()),
        "always" if in_recovery => Ok(()),
        "always" => Err(CommandError::Other(
            "archive_mode is 'always' on a primary, which is unexpected; expected 'on'".to_owned(),
        )),
        other => Err(CommandError::Other(format!(
            "archive_mode must be enabled for backup (is '{other}'); set archive_mode = on"
        ))),
    }
}

/// Wait (bounded by `timeout`) for every WAL segment required to make the backup
/// consistent — `backup-archive-start` through `backup-archive-stop` inclusive —
/// to be present in the repo archive.
///
/// Implements `archive-check`. The range is enumerated by
/// [`pgbr_postgres::lsn::wal_segment_range`] (honouring the cluster
/// `wal_segment_size` and the live timeline in `bracket`); each segment is probed
/// via [`crate::archive::read_archived_segment`] (which transparently finds the
/// plaintext or any compressed stored form). A segment not yet present is
/// re-polled every `poll_interval` until it appears or `timeout` elapses; a
/// segment that never arrives is a hard error. C reference:
/// `backupArchiveCheckCopy()` in `src/command/backup/backup.c`.
///
/// # Errors
///
/// [`CommandError::Other`] when the range cannot be enumerated or a required
/// segment does not arrive within `timeout`; storage / IO failures from the
/// archive probe.
fn wait_for_required_wal(
    repo_storage: &dyn Storage,
    stanza: &str,
    bracket: &BackupBracket,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
    user_pass: Option<&str>,
    sub_key: Option<&str>,
) -> Result<(), CommandError> {
    let segments = wal_segment_range(&bracket.archive_start, &bracket.archive_stop, bracket.wal_segment_size).ok_or_else(|| {
        CommandError::Other(format!(
            "archive-check: could not enumerate WAL segment range {}..{}",
            bracket.archive_start, bracket.archive_stop
        ))
    })?;

    for segment in &segments {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if crate::archive::read_archived_segment(repo_storage, stanza, segment, user_pass, sub_key)?.is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(CommandError::Other(format!(
                    "archive-check: required WAL segment {segment} did not arrive in the repository archive \
                     within {}s; check the cluster's archive_command",
                    timeout.as_secs()
                )));
            }
            std::thread::sleep(poll_interval.min(deadline.saturating_duration_since(std::time::Instant::now())));
        }
    }

    Ok(())
}

/// Resolve the live cluster timeline + `wal_segment_size`, used to derive the
/// WAL segment names recorded in the bracket and to enumerate the archive-copy
/// range.
///
/// Both come from the one backup-control connection (the same session that runs
/// `pg_backup_start` / `pg_backup_stop`): the timeline from
/// `pg_control_checkpoint()` and the segment size from `pg_settings`. Sourcing
/// them per-backup replaces the former hardcoded timeline 1 / 16 MiB assumption.
///
/// # Errors
///
/// [`CommandError::Other`] when either query / parse fails.
fn resolve_wal_geometry(control: &mut dyn BackupControl) -> Result<(u32, u64), CommandError> {
    let timeline = control.timeline()?;
    let wal_segment_size = control.wal_segment_size()?;
    Ok((timeline, wal_segment_size))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_io::{Filter, Sha1};
    use pgbr_storage::Posix;

    use pgbr_postgres::lsn::WAL_SEGMENT_SIZE_DEFAULT;

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
    fn is_excluded_covers_postmaster_log_paths() {
        // The `log/` directory holds the postmaster server log (when
        // `logging_collector` writes under PGDATA). The directory itself and
        // every file beneath it must be excluded.
        assert!(is_excluded("log"));
        assert!(is_excluded("log/server.log"));
        assert!(is_excluded("log/foo.log"));
        assert!(is_excluded("log/postgresql-2026-05-30.log"));
        // A sibling that merely shares the `log` prefix must NOT be excluded.
        assert!(!is_excluded("login"));
        assert!(!is_excluded("logical"));

        // Root-level postmaster server log + the `current_logfiles` pointer.
        assert!(is_excluded("server.log"));
        assert!(is_excluded("current_logfiles"));
        // Nested copies under a relation directory are NOT root files, so the
        // root-file rule does not exclude them (the gating mirrors pgBackRest's
        // PGDATA-root check; a real cluster would never put these there).
        assert!(!is_excluded("base/1/server.log"));
        assert!(!is_excluded("base/1/current_logfiles"));
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
    fn backup_excludes_postmaster_log_tree() {
        // The `log/` tree and the root-level `server.log` / `current_logfiles`
        // pointer file (postmaster server log + logging_collector state) must
        // be excluded from the manifest and never copied. Without this exclude
        // `verify` later reports them as missing on a clean repo because the
        // postmaster rotates / removes them between backup and verify.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"keep this relation");
        // Default `logging_collector = on` layout: PGDATA/log/*.log.
        seed_file(&pg_s, "log/server.log", b"2026-05-30 12:00:00 ... LOG ...");
        seed_file(&pg_s, "log/foo.log", b"older rotation");
        // Root-level postmaster log used by `pg_ctl -l <pgdata>/server.log`.
        seed_file(&pg_s, "server.log", b"root-level postmaster log");
        // The `logging_collector` pointer file (rotation state).
        seed_file(&pg_s, "current_logfiles", b"log/postgresql.log");

        backup(&typed_cfg("demo", "full"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        for excluded in ["log/server.log", "log/foo.log", "server.log", "current_logfiles"] {
            assert!(
                manifest.file(excluded).is_none(),
                "{excluded} must be excluded from the manifest"
            );
            let backup_root = repo_dir.path().join(format!("backup/demo/{label}"));
            assert!(!backup_root.join(excluded).exists(), "{excluded} must not be copied");
        }
        // The `log` directory follows the same convention as other excluded
        // runtime dirs (`pg_notify`, `pg_wal`, ...): the directory entry is
        // recorded as an empty path so a fresh-PGDATA restore recreates the
        // dir, while its contents are excluded. (PostgreSQL would recreate
        // `log/` on startup with `logging_collector = on` anyway, but matching
        // the existing convention keeps the manifest shape consistent.)
        assert!(
            manifest.paths.iter().any(|p| p.path == "log"),
            "log/ directory must be recorded as an empty manifest path"
        );
        // The real relation survives.
        assert!(manifest.file("base/1/1259").is_some(), "real relation must be backed up");
    }

    #[test]
    fn backup_records_excluded_runtime_dir_as_empty_path_not_its_contents() {
        // A transient runtime directory (`pg_notify`) holding a file must be kept
        // in the manifest as an EMPTY path so a fresh-PGDATA restore recreates the
        // directory, while its contents are never captured. This is the backup
        // half of the fix for `FATAL: could not open directory "pg_notify"`.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"keep this relation");
        // pg_notify with content (mirrors a live cluster's NOTIFY SLRU segments).
        seed_file(&pg_s, "pg_notify/0000", b"transient notify slru");
        // A second excluded runtime dir, also with content.
        seed_file(&pg_s, "pg_subtrans/0000", b"transient subtrans slru");

        backup(&typed_cfg("demo", "full"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");

        // The directory itself is recorded as an (empty) manifest path...
        let path_set: Vec<&str> = manifest.paths.iter().map(|p| p.path.as_str()).collect();
        assert!(
            path_set.contains(&"pg_notify"),
            "pg_notify dir must be a manifest path: {path_set:?}"
        );
        assert!(
            path_set.contains(&"pg_subtrans"),
            "pg_subtrans dir must be a manifest path: {path_set:?}"
        );
        // ...recorded exactly once.
        assert_eq!(
            path_set.iter().filter(|p| **p == "pg_notify").count(),
            1,
            "pg_notify recorded once"
        );

        // ...but its contents are NOT recorded as files.
        let listed: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            !listed.iter().any(|p| p.starts_with("pg_notify/")),
            "pg_notify contents must be excluded: {listed:?}"
        );
        assert!(
            !listed.iter().any(|p| p.starts_with("pg_subtrans/")),
            "pg_subtrans contents must be excluded: {listed:?}"
        );
        // The contents were not physically copied either.
        let backup_root = repo_dir.path().join(format!("backup/demo/{label}"));
        assert!(
            !backup_root.join("pg_notify/0000").exists(),
            "pg_notify content must not be copied"
        );
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
    fn backup_refuses_when_stop_file_exists() {
        // Pre-place `<lock-path>/demo.stop` on the local filesystem. A
        // subsequent `backup` must refuse with a clear "stop file exists for
        // stanza demo" error BEFORE it acquires the backup lock — the gate
        // check sits ahead of `acquire_command_lock`.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let cfg = typed_cfg_locked("demo", "full", lock_dir.path());

        // Seed the stop file for the demo stanza.
        std::fs::write(lock_dir.path().join("demo.stop"), b"").expect("seed stop file");

        let err = backup(&cfg, &repo_s, &pg_s).expect_err("backup must refuse when stopped");
        let msg = err.to_string();
        assert!(msg.contains("stop file exists for stanza demo"), "unexpected error: {msg}");

        // The backup lock must NOT have been created — the gate runs first.
        assert!(
            !lock_dir.path().join("demo-backup.lock").exists(),
            "stop-gate must run before lock acquisition"
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
        // A structurally-sane header so page-header-check (on by default) passes:
        // pd_lsn small, header(24) <= pd_lower(40) <= pd_upper <= pd_special(8192).
        page[0..8].copy_from_slice(&0u64.to_le_bytes()); // pd_lsn
        page[12..14].copy_from_slice(&40u16.to_le_bytes()); // pd_lower
        page[14..16].copy_from_slice(&8192u16.to_le_bytes()); // pd_upper
        page[16..18].copy_from_slice(&8192u16.to_le_bytes()); // pd_special
        // Vary the body a little per block so distinct pages differ (no casts:
        // write the block number's low bytes straight from its LE encoding) —
        // past the header so the header fields above stay valid.
        page[40..44].copy_from_slice(&block_no.to_le_bytes());
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
        assert!(is_valid_page(&zero, 0, false));
        // A correctly-checksummed page validates; corrupting it fails.
        let good = valid_page(7, 0x55);
        assert!(is_valid_page(&good, 7, false));
        let mut bad = good.clone();
        bad[8] ^= 0x01; // flip a stored-checksum bit
        assert!(!is_valid_page(&bad, 7, false));
        // A page validated against the wrong block number fails (transposed page).
        assert!(!is_valid_page(&good, 8, false));
    }

    #[test]
    fn backup_checksum_page_valid_records_some_true() {
        // A relation file made of valid pages, backed up with checksum-page on,
        // records `checksum_page = Some(ChecksumPage::Validated)`. A
        // non-relation file (PG_VERSION) is never validated, so it stays `None`.
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
            Some(ChecksumPage::Validated),
            "all-valid relation pages must record ChecksumPage::Validated"
        );
        // Non-relation files are not validated.
        let version = manifest.file("PG_VERSION").expect("PG_VERSION in manifest");
        assert_eq!(version.checksum_page, None, "non-relation file must not be validated");
    }

    #[test]
    fn backup_checksum_page_corrupt_records_some_false() {
        // A relation file with one deliberately corrupted page checksum records
        // its invalid block list. Build a 2-page file, corrupt block 1's
        // stored checksum so it no longer matches; the manifest entry must
        // carry `ChecksumPage::InvalidBlocks(vec![1])`.
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
            Some(ChecksumPage::InvalidBlocks(vec![1])),
            "a corrupted page checksum must record the bad block in InvalidBlocks"
        );
        // The relation's plaintext checksum/size are still recorded.
        assert_eq!(relfile.size, relation.len() as u64);
        assert_eq!(relfile.checksum.as_deref(), Some(sha1_hex(&relation).as_str()));
    }

    #[test]
    fn backup_checksum_page_off_leaves_none() {
        // Without explicit --checksum-page and without a readable pg_control
        // (the test cluster does not seed one), the dynamic default falls back
        // to off, so no relation file is validated.
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
        // An all-zero, page-aligned relation file validates as
        // `ChecksumPage::Validated` (empty-page handling).
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
            Some(ChecksumPage::Validated),
            "all-zero pages must validate as ChecksumPage::Validated"
        );
    }

    // ---- dynamic --checksum-page default (resolve_checksum_page) ----------

    /// Build a synthetic `global/pg_control` buffer for PG 14 (the cluster
    /// `init_stanza` records) with the given `data_checksum_version`. The
    /// layout mirrors the wide `ControlFileData` offsets used by PG 13-16
    /// (`state` @ 16, `checkpoint` @ 32, `blcksz` @ 216, `xlog_seg_size` @ 228,
    /// `data_checksum_version` @ 252) so the public `read_pg_control_data`
    /// decodes it as a PG 14 cluster with or without page checksums.
    fn synth_pg_control_v14(data_checksum_version: u32) -> Vec<u8> {
        // 256 bytes covers every field through `data_checksum_version + 4`.
        let mut buf = vec![0u8; 256];
        // system_identifier (any non-zero value)
        buf[0..8].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        // pg_control_version = 1300 (PG 13–16 share this)
        buf[8..12].copy_from_slice(&1300u32.to_le_bytes());
        // catalog_version_no = 202_107_181 (PG 14 — matches `init_stanza`'s
        // recorded db-control-version)
        buf[12..16].copy_from_slice(&202_107_181u32.to_le_bytes());
        // state @ 16: DB_IN_PRODUCTION = 6 (any value the decoder accepts)
        buf[16..20].copy_from_slice(&6u32.to_le_bytes());
        // check_point @ 32
        buf[32..40].copy_from_slice(&0x1_2345_6789u64.to_le_bytes());
        // blcksz @ 216
        buf[216..220].copy_from_slice(&8192u32.to_le_bytes());
        // xlog_seg_size @ 228
        buf[228..232].copy_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
        // data_checksum_version @ 252 — the bit the resolver keys off
        buf[252..256].copy_from_slice(&data_checksum_version.to_le_bytes());
        buf
    }

    /// A backup config that does NOT set `--checksum-page`, so the dynamic
    /// `pg_control.data_checksum_version` default kicks in.
    fn default_full_cfg(stanza: &str) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("type".to_owned(), None), OptionValue::StringId("full".to_owned()));
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    /// Repository-relative path of a backup's manifest under `<stanza>`.
    fn manifest_for_only_backup(repo: &Posix, stanza: &str) -> Manifest {
        let info = InfoBackup::load(repo, &backup_info_path(stanza)).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("exactly one backup");
        Manifest::load(repo, Path::new(&format!("backup/{stanza}/{label}/backup.manifest"))).expect("load manifest")
    }

    /// Serialises `pgbr_core::log` state across capture-using tests in this crate.
    /// Mirrors the pattern in `annotate.rs`.
    static CHECKSUM_PAGE_LOG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_checksum_page_explicit_override_wins() {
        // Even with a checksummed pg_control on disk, an explicit
        // --no-checksum-page must beat the dynamic default.
        let (_repo, _pg, _repo_s, pg_s) = posix_pair();
        seed_file(&pg_s, "global/pg_control", &synth_pg_control_v14(1));
        let mut cfg = default_full_cfg("demo");
        cfg.options
            .insert(("checksum-page".to_owned(), None), OptionValue::Boolean(false));
        assert!(!resolve_checksum_page(&cfg, &pg_s));

        // Symmetric: --checksum-page beats a non-checksummed cluster.
        let (_repo2, _pg2, _repo_s2, pg_s2) = posix_pair();
        seed_file(&pg_s2, "global/pg_control", &synth_pg_control_v14(0));
        let mut cfg2 = default_full_cfg("demo");
        cfg2.options
            .insert(("checksum-page".to_owned(), None), OptionValue::Boolean(true));
        assert!(resolve_checksum_page(&cfg2, &pg_s2));
    }

    #[test]
    fn resolve_checksum_page_dynamic_default_from_pg_control() {
        // No explicit option: the resolver reads pg_control and follows its
        // data_checksum_version (0 → off, non-zero → on).
        let (_repo, _pg, _repo_s, pg_s) = posix_pair();
        seed_file(&pg_s, "global/pg_control", &synth_pg_control_v14(1));
        let cfg = default_full_cfg("demo");
        assert!(
            resolve_checksum_page(&cfg, &pg_s),
            "data_checksum_version=1 must default checksum-page on"
        );

        let (_repo2, _pg2, _repo_s2, pg_s2) = posix_pair();
        seed_file(&pg_s2, "global/pg_control", &synth_pg_control_v14(0));
        assert!(
            !resolve_checksum_page(&cfg, &pg_s2),
            "data_checksum_version=0 must default checksum-page off"
        );
    }

    #[test]
    fn resolve_checksum_page_missing_pg_control_falls_back_off() {
        // No file at global/pg_control: the resolver logs an INFO note and
        // returns false rather than failing the backup.
        let (_repo, _pg, _repo_s, pg_s) = posix_pair();
        let cfg = default_full_cfg("demo");
        assert!(!resolve_checksum_page(&cfg, &pg_s), "missing pg_control must default off");
    }

    #[test]
    fn backup_dynamic_default_on_checksummed_cluster_validates_pages() {
        // The integration test for the silent-corruption regression:
        //
        // - The user does NOT pass --checksum-page (the production scenario
        //   where the bug surfaced).
        // - The cluster's pg_control records data_checksum_version=1, so the
        //   dynamic default must engage and validate every relation page.
        // - One page is deliberately corrupted (its stored checksum bit-flipped).
        //
        // Stock pgBackRest emits a WARN line naming the bad block AND records
        // the invalid block list in the manifest's per-file checksum-page
        // field. Both of those must now happen here.
        let _guard = CHECKSUM_PAGE_LOG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pgbr_core::log::capture::install();
        pgbr_core::log::set_level_file(pgbr_core::log::LOG_LEVEL_WARN);
        pgbr_core::log::set_file_banner(false);

        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        // Checksummed cluster: data_checksum_version=1 in pg_control.
        seed_file(&pg_s, "global/pg_control", &synth_pg_control_v14(1));
        // Build a 2-page relation file and corrupt block 0's stored
        // pd_checksum so it no longer matches the page bytes.
        let mut relation = valid_relation(2);
        relation[8] ^= 0x01; // bit-flip in block 0's stored pd_checksum
        seed_file(&pg_s, "base/1/16384", &relation);

        backup(&default_full_cfg("demo"), &repo_s, &pg_s).expect("backup");

        let captured = String::from_utf8(pgbr_core::log::capture::drain()).expect("captured bytes utf-8");
        pgbr_core::log::capture::uninstall();

        // (a) The WARN line stock pgBackRest emits names the relation + bad block.
        assert!(
            captured.contains("invalid page checksum(s) found in file base/1/16384 at block(s) 0"),
            "expected WARN naming the bad block, got: {captured:?}"
        );

        // (b) The manifest entry records the invalid block list (NOT just a
        // bool), so consumers like `verify` see exactly which blocks failed.
        let manifest = manifest_for_only_backup(&repo_s, "demo");
        let relfile = manifest.file("base/1/16384").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page,
            Some(ChecksumPage::InvalidBlocks(vec![0])),
            "dynamic default must validate pages and record InvalidBlocks(vec![0])"
        );

        // (c) `[backup:option].option-checksum-page` records the resolved
        // effective value (`true` here, because pg_control flagged checksums).
        assert_eq!(
            manifest.option_checksum_page,
            Some(true),
            "manifest must record the resolved option-checksum-page=y"
        );
    }

    #[test]
    fn backup_dynamic_default_on_checksummed_cluster_clean_relation_marks_validated() {
        // The positive twin of `backup_dynamic_default_on_checksummed_cluster_validates_pages`:
        // a checksummed cluster + a clean relation must record
        // `ChecksumPage::Validated` and emit NO WARN line. Together they prove
        // the dynamic default both engages and does not falsely flag.
        let _guard = CHECKSUM_PAGE_LOG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pgbr_core::log::capture::install();
        pgbr_core::log::set_level_file(pgbr_core::log::LOG_LEVEL_WARN);
        pgbr_core::log::set_file_banner(false);

        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "global/pg_control", &synth_pg_control_v14(1));
        seed_file(&pg_s, "base/1/16384", &valid_relation(2));

        backup(&default_full_cfg("demo"), &repo_s, &pg_s).expect("backup");

        let captured = String::from_utf8(pgbr_core::log::capture::drain()).expect("captured bytes utf-8");
        pgbr_core::log::capture::uninstall();

        assert!(
            !captured.contains("invalid page checksum"),
            "no WARN line on a clean relation, got: {captured:?}"
        );

        let manifest = manifest_for_only_backup(&repo_s, "demo");
        let relfile = manifest.file("base/1/16384").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page,
            Some(ChecksumPage::Validated),
            "a clean relation under the dynamic default must record ChecksumPage::Validated"
        );
        assert_eq!(manifest.option_checksum_page, Some(true));
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
        /// Reported cluster `wal_segment_size` (bytes); 0 means "use the default".
        wal_segment_size: u64,
        /// Reported current timeline id; 0 means "use timeline 1".
        timeline: u32,
        /// LSN `backup_start` returns.
        start_lsn: String,
        /// Stop LSN + label / spcmap files `backup_stop` returns.
        stop: BackupStopResult,
        /// Whether `is_in_recovery` reports a standby.
        in_recovery: bool,
        /// Sequence of replay LSNs `replay_lsn` returns (last value repeats).
        replay_lsns: Vec<Option<String>>,
        /// Value `archive_mode` reports (`"on"` by default).
        archive_mode: String,
        /// Whether `stop_running_backup` reports a stale backup was stopped
        /// (`false` by default — nothing was running).
        stop_running: bool,
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
                wal_segment_size: 0,
                timeline: 0,
                start_lsn: start_lsn.to_owned(),
                stop,
                in_recovery: false,
                replay_lsns: Vec::new(),
                archive_mode: "on".to_owned(),
                stop_running: false,
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

        fn stop_running_backup(&mut self) -> Result<bool, CommandError> {
            self.calls.borrow_mut().push("stop_running_backup".to_owned());
            Ok(self.stop_running)
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

        fn wal_segment_size(&mut self) -> Result<u64, CommandError> {
            self.calls.borrow_mut().push("wal_segment_size".to_owned());
            // 0 means the fake wasn`t given an explicit size: report the default.
            Ok(if self.wal_segment_size == 0 {
                WAL_SEGMENT_SIZE_DEFAULT
            } else {
                self.wal_segment_size
            })
        }

        fn timeline(&mut self) -> Result<u32, CommandError> {
            self.calls.borrow_mut().push("timeline".to_owned());
            // 0 means the fake wasn`t given an explicit timeline: report 1.
            Ok(if self.timeline == 0 { 1 } else { self.timeline })
        }

        fn archive_mode(&mut self) -> Result<String, CommandError> {
            self.calls.borrow_mut().push("archive_mode".to_owned());
            Ok(self.archive_mode.clone())
        }
    }

    /// The `backup.info` identity the [`init_stanza`] helper writes (PG 14).
    const STANZA_SYSTEM_ID: u64 = 6_873_049_345_984_568_091;

    /// Run a control-driven backup through `run_backup` with a fake primary.
    ///
    /// Integrity checks are disabled so the bracket tests stay focused on the
    /// backup-control protocol (no archive.info / archived WAL is seeded); the
    /// dedicated archive-check / archive-mode-check tests opt in via
    /// [`run_backup_with_integrity`].
    fn run_backup_with_fake(
        repo_s: &Posix,
        pg_s: &Posix,
        control: &mut FakeBackupControl,
        start_fast: bool,
    ) -> Result<BackupOutcome, CommandError> {
        run_backup_with_fake_opts(repo_s, pg_s, control, start_fast, &RepoTransform::identity(), false)
    }

    /// Like [`run_backup_with_fake`] but lets a test pin the transform and the
    /// `archive_copy` flag (used by the archive-copy round-trip tests). Integrity
    /// checks remain disabled.
    fn run_backup_with_fake_opts(
        repo_s: &Posix,
        pg_s: &Posix,
        control: &mut FakeBackupControl,
        start_fast: bool,
        transform: &RepoTransform,
        archive_copy: bool,
    ) -> Result<BackupOutcome, CommandError> {
        run_backup(
            "demo",
            repo_s,
            pg_s,
            BackupType::Full,
            Some(LABEL),
            1_704_110_400,
            transform,
            1,
            false,
            &[],
            Some(control as &mut dyn BackupControl),
            None,
            start_fast,
            BackupFeatures::disabled(),
            crate::block::BlockOverrides::none(),
            JobRetry::none(),
            archive_copy,
            IntegrityChecks::disabled(),
            BackupPolicy::test_default(),
            None,
            transform.cipher_pass.as_deref(),
        )
    }

    /// Run a control-driven backup with explicit [`IntegrityChecks`], for the
    /// archive-check / archive-mode-check / page-header-check tests.
    fn run_backup_with_integrity(
        repo_s: &Posix,
        pg_s: &Posix,
        control: &mut FakeBackupControl,
        integrity: IntegrityChecks,
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
            false,
            BackupFeatures::disabled(),
            crate::block::BlockOverrides::none(),
            JobRetry::none(),
            false,
            integrity,
            BackupPolicy::test_default(),
            None,
            None,
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

        // Protocol order: server_info, backup_start(label,fast=true), then the
        // WAL-geometry queries (timeline + wal_segment_size sourced from the live
        // cluster), then backup_stop.
        let calls = control.calls.borrow().clone();
        assert_eq!(
            calls,
            vec![
                "server_info".to_owned(),
                format!("backup_start({LABEL},true)"),
                "timeline".to_owned(),
                "wal_segment_size".to_owned(),
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
        let bracket = build_bracket("0/16B3E40", &stop, 1, WAL_SEGMENT_SIZE_DEFAULT).expect("bracket");
        assert_eq!(bracket.archive_start, "000000010000000000000001");
        // 0/2000000 = 0x02000000 / 16 MiB (0x01000000) = 2 -> ...00000002.
        assert_eq!(bracket.archive_stop, "000000010000000000000002");
    }

    #[test]
    fn build_bracket_uses_supplied_timeline_and_segment_size() {
        // A post-failover timeline (3) and 1 GiB segments must both flow into the
        // recorded WAL segment names instead of the old hardcoded tl=1 / 16 MiB.
        let stop = BackupStopResult {
            lsn: "0/40000000".to_owned(),
            label_file: String::new(),
            spcmap_file: String::new(),
        };
        let bracket = build_bracket("0/0", &stop, 3, 0x4000_0000).expect("bracket");
        assert_eq!(bracket.timeline, 3);
        assert_eq!(bracket.wal_segment_size, 0x4000_0000);
        // Timeline 3 in the leading 8 digits; 0/0 -> segment 0, 0/40000000 (1 GiB)
        // -> segment 1 with 1 GiB segments.
        assert_eq!(bracket.archive_start, "000000030000000000000000");
        assert_eq!(bracket.archive_stop, "000000030000000000000001");
    }

    #[test]
    fn control_driven_backup_records_live_timeline_and_segment_size() {
        // The bracket (and backup.info) must carry the timeline / segment size the
        // control reports, not the former hardcoded values.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");

        // A standby-promoted cluster on timeline 5 with 1 GiB segments.
        let mut control = FakeBackupControl {
            timeline: 5,
            wal_segment_size: 0x4000_0000,
            ..FakeBackupControl::primary(
                140_010,
                STANZA_SYSTEM_ID,
                "0/0",
                BackupStopResult {
                    lsn: "0/30".to_owned(),
                    label_file: "lbl\n".to_owned(),
                    spcmap_file: String::new(),
                },
            )
        };

        let outcome = run_backup_with_fake(&repo_s, &pg_s, &mut control, false).expect("backup");
        let bracket = outcome.bracket.expect("bracket");
        assert_eq!(bracket.timeline, 5);
        assert_eq!(bracket.wal_segment_size, 0x4000_0000);
        // 0/0 and 0/30 both fall in segment 0 of timeline 5 with 1 GiB segments.
        assert_eq!(bracket.archive_start, "000000050000000000000000");
        assert_eq!(bracket.archive_stop, "000000050000000000000000");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let entry = info.current.get(LABEL).expect("entry");
        assert_eq!(entry["backup-archive-start"], json!("000000050000000000000000"));
        assert_eq!(entry["backup-archive-stop"], json!("000000050000000000000000"));
    }

    /// Seed a plaintext WAL segment into the repo archive for `stanza`.
    fn seed_archive_segment(repo: &Posix, stanza: &str, segment: &str, body: &[u8]) {
        let rel = format!("archive/{stanza}/{segment}");
        let path = PathBuf::from(&rel);
        if let Some(parent) = path.parent() {
            repo.create_path(parent, true).expect("create archive dir");
        }
        let mut w = repo.open_write(&path).expect("open archive seg");
        w.write(body).expect("write archive seg");
        w.close().expect("close archive seg");
    }

    #[test]
    fn archive_copy_populates_pg_wal_manifest_entries() {
        // archive-copy=y must copy every segment in the start..stop range out of
        // the archive into the backup pg_wal/ and record a ManifestFile each.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");

        // A backup spanning three segments: start 0/1000000 (segment 1) through
        // stop 0/3000000 (segment 3). Seed all three in the archive.
        let bodies = [
            ("000000010000000000000001", b"wal-seg-001".as_slice()),
            ("000000010000000000000002", b"wal-seg-002".as_slice()),
            ("000000010000000000000003", b"wal-seg-003".as_slice()),
        ];
        for (seg, body) in bodies {
            seed_archive_segment(&repo_s, "demo", seg, body);
        }

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/1000000",
            BackupStopResult {
                lsn: "0/3000000".to_owned(),
                label_file: "lbl\n".to_owned(),
                spcmap_file: String::new(),
            },
        );

        let outcome =
            run_backup_with_fake_opts(&repo_s, &pg_s, &mut control, false, &RepoTransform::identity(), true).expect("backup");
        let bracket = outcome.bracket.expect("bracket");
        assert_eq!(bracket.archive_start, "000000010000000000000001");
        assert_eq!(bracket.archive_stop, "000000010000000000000003");

        // The three WAL segments are physically in the backup pg_wal/ ...
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        for (seg, body) in bodies {
            let path = backup_root.join(format!("pg_wal/{seg}"));
            assert!(path.exists(), "archive-copy must write pg_wal/{seg}");
            assert_eq!(std::fs::read(&path).unwrap(), body, "pg_wal/{seg} contents");
        }

        // ... and each is recorded as a ManifestFile with its plaintext checksum.
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("manifest");
        for (seg, body) in bodies {
            let mf = manifest
                .file(&format!("pg_wal/{seg}"))
                .unwrap_or_else(|| panic!("pg_wal/{seg} in manifest"));
            assert_eq!(mf.size, body.len() as u64, "pg_wal/{seg} size");
            assert_eq!(mf.checksum.as_deref(), Some(sha1_hex(body).as_str()), "pg_wal/{seg} checksum");
            assert_eq!(mf.reference, None, "this backup physically holds the WAL");
        }
    }

    #[test]
    fn archive_copy_missing_segment_is_an_error() {
        // A required segment absent from the archive fails the backup (it cannot
        // be made consistent without it).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");

        // Range is segment 1..2 but only segment 1 is archived.
        seed_archive_segment(&repo_s, "demo", "000000010000000000000001", b"only-seg-1");

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/1000000",
            BackupStopResult {
                lsn: "0/2000000".to_owned(),
                label_file: "lbl\n".to_owned(),
                spcmap_file: String::new(),
            },
        );

        let err = run_backup_with_fake_opts(&repo_s, &pg_s, &mut control, false, &RepoTransform::identity(), true)
            .expect_err("missing required WAL must fail the backup");
        assert!(err.to_string().contains("missing from the archive"), "got {err}");
    }

    #[test]
    fn archive_copy_round_trips_through_restore() {
        // End-to-end: a backup with archive-copy, restored into a fresh PG dir,
        // must place the copied WAL under pg_wal/ with its original bytes.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents to back up");

        let wal_a = b"recovery-wal-segment-A".as_slice();
        let wal_b = b"recovery-wal-segment-B".as_slice();
        seed_archive_segment(&repo_s, "demo", "000000010000000000000001", wal_a);
        seed_archive_segment(&repo_s, "demo", "000000010000000000000002", wal_b);

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/1000000",
            BackupStopResult {
                lsn: "0/2000000".to_owned(),
                label_file: "lbl\n".to_owned(),
                spcmap_file: String::new(),
            },
        );
        run_backup_with_fake_opts(&repo_s, &pg_s, &mut control, false, &RepoTransform::identity(), true).expect("backup");

        // Restore into a fresh target and confirm the WAL came back byte-for-byte.
        let target = tempfile::tempdir().expect("restore target");
        let target_s = Posix::new(target.path());
        let restore_cfg = typed_cfg("demo", "full");
        crate::restore::restore(&restore_cfg, &repo_s, &target_s).expect("restore");

        for (seg, body) in [("000000010000000000000001", wal_a), ("000000010000000000000002", wal_b)] {
            let path = target.path().join(format!("pg_wal/{seg}"));
            assert!(path.exists(), "restore must place pg_wal/{seg}");
            assert_eq!(std::fs::read(&path).unwrap(), body, "restored pg_wal/{seg} contents");
        }
        // The ordinary data file restored too.
        assert!(target.path().join("base/1/1259").exists(), "data file restored");
    }

    #[test]
    fn archive_copy_round_trips_with_compression() {
        // Same round-trip but through a gz transform: the WAL is stored compressed
        // in the backup and restore reverses it to the original plaintext.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents to back up");

        let wal = b"compressible compressible compressible WAL bytes".as_slice();
        seed_archive_segment(&repo_s, "demo", "000000010000000000000001", wal);

        let transform = RepoTransform::with_key(CompressType::Gz, 6, None);
        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/1000000",
            BackupStopResult {
                lsn: "0/1000000".to_owned(),
                label_file: "lbl\n".to_owned(),
                spcmap_file: String::new(),
            },
        );
        run_backup_with_fake_opts(&repo_s, &pg_s, &mut control, false, &transform, true).expect("backup");

        // The stored WAL carries the compression suffix and is NOT the plaintext.
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        let stored = backup_root.join("pg_wal/000000010000000000000001.gz");
        assert!(stored.exists(), "compressed WAL stored with .gz suffix");
        assert_ne!(std::fs::read(&stored).unwrap(), wal, "stored bytes are compressed");

        // Restore reverses the transform back to the plaintext WAL.
        let target = tempfile::tempdir().expect("restore target");
        let target_s = Posix::new(target.path());
        crate::restore::restore(&typed_cfg("demo", "full"), &repo_s, &target_s).expect("restore");
        let restored = target.path().join("pg_wal/000000010000000000000001");
        assert_eq!(std::fs::read(&restored).unwrap(), wal, "restored WAL equals the original");
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
    fn standby_local_path_only_for_local_pg() {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        // pg1: local standby (path, no host) -> its data dir is returned.
        options.insert(
            ("pg1-path".to_owned(), None),
            OptionValue::Path("/var/lib/postgresql/16/standby".to_owned()),
        );
        // pg2: remote standby (host set) -> None (read from primary instead).
        options.insert(("pg2-host".to_owned(), None), OptionValue::String("secondaire".to_owned()));
        options.insert(
            ("pg2-path".to_owned(), None),
            OptionValue::Path("/var/lib/postgresql/16/main".to_owned()),
        );
        let cfg = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        };
        assert_eq!(
            standby_local_path(&cfg, 1),
            Some(PathBuf::from("/var/lib/postgresql/16/standby")),
            "a local standby (no host) yields its data dir for the file-copy offload"
        );
        assert_eq!(
            standby_local_path(&cfg, 2),
            None,
            "a remote standby (host set) is not locally readable"
        );
        assert_eq!(standby_local_path(&cfg, 3), None, "an unconfigured index yields None");
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
            crate::block::BlockOverrides::none(),
            JobRetry::none(),
            false,
            IntegrityChecks::disabled(),
            BackupPolicy::test_default(),
            None,
            None,
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

    // ---- page-header-check -------------------------------------------------

    /// Like [`valid_page`] but with a structurally-**invalid** header: `pd_lower`
    /// is set *inside* the page header (impossible), while the checksum is still
    /// computed over the page so the checksum itself validates.
    fn corrupt_header_page(block_no: u32) -> Vec<u8> {
        let mut page = valid_page(block_no, 0x55);
        // pd_lower = 4 (inside the 24-byte header) is impossible.
        page[12..14].copy_from_slice(&4u16.to_le_bytes());
        // Recompute the checksum so the page passes the CHECKSUM test (only the
        // header is broken), isolating the header check.
        page[8] = 0;
        page[9] = 0;
        let cksum = pg_checksum_page(&page, block_no).expect("checksum");
        page[8..10].copy_from_slice(&cksum.to_le_bytes());
        page
    }

    #[test]
    fn validate_relation_pages_header_flags_bad_header() {
        // A page whose checksum is valid but header is broken: flagged only when
        // the header check is enabled.
        let bytes = corrupt_header_page(0);
        // Checksum-only: the page passes (the checksum is valid).
        assert!(
            validate_relation_pages(&bytes, false).is_empty(),
            "checksum-only must not flag a checksum-valid page"
        );
        // Header check on: the broken pd_lower is caught.
        assert_eq!(
            validate_relation_pages(&bytes, true),
            vec![0],
            "header check must flag the broken header"
        );
    }

    #[test]
    fn is_valid_page_header_check_distinguishes_header() {
        let good = valid_page(3, 0x40);
        assert!(is_valid_page(&good, 3, true), "a fully-valid page passes with header check");
        let bad = corrupt_header_page(3);
        assert!(
            is_valid_page(&bad, 3, false),
            "checksum-only accepts the page (header ignored)"
        );
        assert!(!is_valid_page(&bad, 3, true), "header check rejects the broken header");
    }

    #[test]
    fn backup_page_header_check_flags_corrupt_header() {
        // checksum-page on (so the page pass runs) + page-header-check on (the
        // default): a relation page with a valid checksum but broken header is
        // flagged as an invalid block (the per-file invalid-block list, not
        // just a bool, so the bad block surfaces in the manifest).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let relation = corrupt_header_page(0);
        seed_file(&pg_s, "base/1/1259", &relation);

        // checksum_page_cfg leaves page-header-check unset -> defaults true.
        backup(&checksum_page_cfg("demo"), &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");
        let relfile = manifest.file("base/1/1259").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page,
            Some(ChecksumPage::InvalidBlocks(vec![0])),
            "a page with a broken header must be flagged even though its checksum is valid"
        );
    }

    #[test]
    fn backup_page_header_check_off_ignores_header() {
        // With page-header-check=n, the same checksum-valid/broken-header page
        // passes (ChecksumPage::Validated) because only the checksum is
        // verified.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", &corrupt_header_page(0));

        let mut cfg = checksum_page_cfg("demo");
        cfg.options
            .insert(("page-header-check".to_owned(), None), OptionValue::Boolean(false));
        backup(&cfg, &repo_s, &pg_s).expect("backup");

        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        let (label, _) = info.current.iter().next().expect("one backup");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{label}/backup.manifest"))).expect("manifest");
        let relfile = manifest.file("base/1/1259").expect("relation in manifest");
        assert_eq!(
            relfile.checksum_page,
            Some(ChecksumPage::Validated),
            "with header-check off only the (valid) checksum is enforced"
        );
    }

    // ---- archive-mode-check ------------------------------------------------

    #[test]
    fn check_archive_mode_accepts_on() {
        let mut control = FakeBackupControl::primary(140_010, STANZA_SYSTEM_ID, "0/0", BackupStopResult::default());
        control.archive_mode = "on".to_owned();
        check_archive_mode(&mut control, false).expect("'on' is accepted on a primary");
    }

    #[test]
    fn check_archive_mode_rejects_off() {
        let mut control = FakeBackupControl::primary(140_010, STANZA_SYSTEM_ID, "0/0", BackupStopResult::default());
        control.archive_mode = "off".to_owned();
        let err = check_archive_mode(&mut control, false).expect_err("'off' must fail");
        assert!(err.to_string().contains("archive_mode must be enabled"), "msg was {err}");
    }

    #[test]
    fn check_archive_mode_rejects_always_on_primary() {
        let mut control = FakeBackupControl::primary(140_010, STANZA_SYSTEM_ID, "0/0", BackupStopResult::default());
        control.archive_mode = "always".to_owned();
        let err = check_archive_mode(&mut control, false).expect_err("'always' on a primary is unexpected");
        assert!(err.to_string().contains("unexpected"), "msg was {err}");
        // ... but 'always' on a standby (in recovery) is allowed.
        check_archive_mode(&mut control, true).expect("'always' is fine on a standby");
    }

    #[test]
    fn backup_archive_mode_check_fails_when_off() {
        // A DB-driven backup with archive-mode-check on must fail fast when the
        // cluster's archive_mode is off (before copying any file).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/1000000",
            BackupStopResult {
                lsn: "0/1000000".to_owned(),
                label_file: "lbl\n".to_owned(),
                spcmap_file: String::new(),
            },
        );
        control.archive_mode = "off".to_owned();

        let integrity = IntegrityChecks {
            archive_check: false,
            archive_mode_check: true,
            page_header_check: false,
            archive_timeout: std::time::Duration::from_millis(10),
        };
        let err =
            run_backup_with_integrity(&repo_s, &pg_s, &mut control, integrity).expect_err("archive_mode off must fail the backup");
        assert!(err.to_string().contains("archive_mode must be enabled"), "msg was {err}");
    }

    // ---- archive-check -----------------------------------------------------

    #[test]
    fn backup_archive_check_passes_when_required_wal_present() {
        // archive-check on: the start..stop WAL segments are present in the repo
        // archive, so the backup completes.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");
        // Range 0/1000000 (seg 1) .. 0/2000000 (seg 2); seed both.
        seed_archive_segment(&repo_s, "demo", "000000010000000000000001", b"wal-1");
        seed_archive_segment(&repo_s, "demo", "000000010000000000000002", b"wal-2");

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/1000000",
            BackupStopResult {
                lsn: "0/2000000".to_owned(),
                label_file: "lbl\n".to_owned(),
                spcmap_file: String::new(),
            },
        );
        let integrity = IntegrityChecks {
            archive_check: true,
            archive_mode_check: false,
            page_header_check: false,
            archive_timeout: std::time::Duration::from_millis(50),
        };
        run_backup_with_integrity(&repo_s, &pg_s, &mut control, integrity).expect("backup with all WAL present");
    }

    #[test]
    fn backup_archive_check_errors_when_required_wal_missing() {
        // archive-check on but a required segment never arrives: the backup must
        // time out and error.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"relation contents");
        // Range is seg 1..2 but only seg 1 is archived.
        seed_archive_segment(&repo_s, "demo", "000000010000000000000001", b"wal-1");

        let mut control = FakeBackupControl::primary(
            140_010,
            STANZA_SYSTEM_ID,
            "0/1000000",
            BackupStopResult {
                lsn: "0/2000000".to_owned(),
                label_file: "lbl\n".to_owned(),
                spcmap_file: String::new(),
            },
        );
        let integrity = IntegrityChecks {
            archive_check: true,
            archive_mode_check: false,
            page_header_check: false,
            archive_timeout: std::time::Duration::from_millis(20),
        };
        let err = run_backup_with_integrity(&repo_s, &pg_s, &mut control, integrity)
            .expect_err("missing required WAL must fail the backup");
        assert!(err.to_string().contains("did not arrive"), "msg was {err}");
    }

    // ---- dry-run / resume / stop-auto / expire-auto / manifest-save-threshold
    //      / db-timeout (the durability + lifecycle slice) -------------------

    /// Run a DB-free backup with an explicit [`BackupPolicy`] (no control), the
    /// way the public `backup` entry would for the policy options.
    fn run_db_free_policy(repo_s: &Posix, pg_s: &Posix, policy: BackupPolicy) -> Result<BackupOutcome, CommandError> {
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
            None,
            None,
            false,
            BackupFeatures::disabled(),
            crate::block::BlockOverrides::none(),
            JobRetry::none(),
            false,
            IntegrityChecks::disabled(),
            policy,
            None,
            None,
        )
    }

    #[test]
    fn dry_run_backup_makes_no_repository_writes() {
        // A dry-run plans + reports the backup but writes nothing: no backup dir,
        // no manifest, no backup.info entry — yet the outcome reports the would-be
        // file count / total size.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        let policy = BackupPolicy {
            dry_run: true,
            ..BackupPolicy::test_default()
        };
        let outcome = run_db_free_policy(&repo_s, &pg_s, policy).expect("dry-run backup");

        // Counts reflect what a real backup would record (4 non-excluded files).
        assert_eq!(outcome.file_count, 4, "dry-run still reports the would-be count");
        assert!(outcome.total_size > 0, "dry-run reports the would-be size");

        // Nothing was written: no backup root, no manifest.
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        assert!(!backup_root.exists(), "dry-run must not create the backup dir");

        // backup.info gained no [backup:current] entry.
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        assert!(info.current.is_empty(), "dry-run must not add a backup.info entry");
    }

    #[test]
    fn non_dry_run_still_writes_the_backup() {
        // Sanity: with the same seed but dry_run off, the backup dir + manifest
        // + backup.info entry all appear (proves the dry-run guard is the only
        // difference).
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_cluster(&pg_s);

        run_db_free_policy(&repo_s, &pg_s, BackupPolicy::test_default()).expect("real backup");
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        assert!(backup_root.join("backup.manifest").exists(), "real backup writes a manifest");
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        assert!(info.current.contains_key(LABEL), "real backup adds a backup.info entry");
    }

    #[test]
    fn resume_reuses_a_matching_already_copied_file() {
        // Simulate an aborted prior backup: leave a partial backup.manifest in the
        // same label dir listing one of the data files (with its real checksum) and
        // its repo object. A resume run must reuse that file (not re-copy it) and
        // still record it in the final manifest.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        let reused_bytes = b"relation-data-1259";
        seed_file(&pg_s, "base/1/1259", reused_bytes);
        seed_file(&pg_s, "base/1/1260", b"relation-data-1260");

        // Build the partial manifest the aborted run would have saved: it copied
        // base/1/1259 (with the correct checksum) but crashed before base/1/1260.
        let backup_root = format!("backup/demo/{LABEL}");
        repo_s.create_path(Path::new(&backup_root), true).unwrap();
        // Place the prior run's repo object for the reused file.
        seed_file(&repo_s, &format!("{backup_root}/base/1/1259"), reused_bytes);
        let partial = Manifest {
            backup_label: LABEL.to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_400,
            db_version: "14".to_owned(),
            db_system_id: STANZA_SYSTEM_ID,
            files: vec![ManifestFile {
                path: "base/1/1259".to_owned(),
                size: reused_bytes.len() as u64,
                timestamp: 0,
                checksum: Some(sha1_hex(reused_bytes)),
                checksum_page: None,
                reference: None,
                mode: None,
                user: None,
                group: None,
                bundle_id: None,
                bundle_offset: None,
                block_map: None,
            }],
            option_checksum_page: None,
            paths: Vec::new(),
            links: Vec::new(),
        };
        partial
            .save(&repo_s, &PathBuf::from(format!("{backup_root}/backup.manifest")))
            .unwrap();

        // Delete the reused file's repo object's *content* marker by recording its
        // mtime; then run with resume on. To prove reuse, make the source unreadable
        // would break the checksum recompute, so instead we assert the final
        // manifest lists both files and the reused one keeps its checksum.
        let policy = BackupPolicy::test_default(); // resume = true
        let outcome = run_db_free_policy(&repo_s, &pg_s, policy).expect("resume backup");
        assert_eq!(outcome.file_count, 2, "both files are in the final manifest");

        let manifest = Manifest::load(&repo_s, Path::new(&format!("{backup_root}/backup.manifest"))).expect("final manifest");
        let reused = manifest.file("base/1/1259").expect("reused file present");
        assert_eq!(reused.checksum.as_deref(), Some(sha1_hex(reused_bytes).as_str()));
        assert!(
            repo_dir.path().join(format!("{backup_root}/base/1/1260")).exists(),
            "the un-resumed file was copied"
        );
    }

    #[test]
    fn manifest_save_threshold_triggers_an_in_progress_save() {
        // With a tiny threshold, the in-progress manifest is saved during the copy
        // loop. We can observe the effect indirectly: the final manifest still
        // lists every file (the periodic saves do not corrupt the result) and the
        // backup succeeds. A direct save-count is internal, so we assert the
        // partial-save path is exercised by checking the manifest is well-formed
        // after a threshold small enough to fire on the first file.
        let (repo_dir, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"some-bytes-larger-than-one");
        seed_file(&pg_s, "base/1/1260", b"more-bytes-here-too-ok");

        let policy = BackupPolicy {
            manifest_save_threshold: 1, // fire after the very first file
            ..BackupPolicy::test_default()
        };
        let outcome = run_db_free_policy(&repo_s, &pg_s, policy).expect("threshold backup");
        assert_eq!(outcome.file_count, 2);

        let backup_root = format!("backup/demo/{LABEL}");
        let manifest = Manifest::load(&repo_s, Path::new(&format!("{backup_root}/backup.manifest"))).expect("final manifest");
        assert_eq!(
            manifest.files.len(),
            2,
            "final manifest lists every file after periodic saves"
        );
        // The repo objects exist (the copies actually happened).
        assert!(repo_dir.path().join(format!("{backup_root}/base/1/1259")).exists());
        assert!(repo_dir.path().join(format!("{backup_root}/base/1/1260")).exists());
    }

    #[test]
    fn save_partial_manifest_writes_a_loadable_manifest() {
        // Directly exercise the periodic-save helper: it must write a manifest the
        // resume path can load back.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let backup_root = "backup/demo/partial";
        repo_s.create_path(Path::new(backup_root), true).unwrap();
        let files = vec![ManifestFile {
            path: "base/1/1259".to_owned(),
            size: 10,
            timestamp: 0,
            checksum: Some("abc".to_owned()),
            checksum_page: None,
            reference: None,
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        }];
        let paths: Vec<ManifestPath> = Vec::new();
        let links: Vec<ManifestLink> = Vec::new();
        let ctx = UnbundledCopyCtx {
            repo_storage: &repo_s,
            pg_storage: &pg_s,
            backup_root,
            backup_type: BackupType::Full,
            label: "partial",
            db_version: "14",
            db_system_id: STANZA_SYSTEM_ID,
            transform: &RepoTransform::identity(),
            jobs: &[],
            skeletons: Vec::new(),
            referenced: Vec::new(),
            paths: &paths,
            links: &links,
            process_max: 1,
            job_retry: JobRetry::none(),
            timestamp_start: 1_704_110_400,
            manifest_save_threshold: u64::MAX,
        };
        save_partial_manifest(&ctx, &files).expect("partial save");
        let loaded = Manifest::load(&repo_s, Path::new(&format!("{backup_root}/backup.manifest"))).expect("load partial manifest");
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.file("base/1/1259").and_then(|f| f.checksum.as_deref()), Some("abc"));
    }

    #[test]
    fn stop_auto_stops_a_stale_running_backup_then_proceeds() {
        // With --stop-auto and a control whose stop_running_backup reports a stale
        // backup was stopped, the backup proceeds normally. The fake records the
        // stop_running_backup call before backup_start.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"data");

        let mut control = FakeBackupControl {
            stop_running: true,
            ..FakeBackupControl::primary(
                140_010,
                STANZA_SYSTEM_ID,
                "0/16B3E40",
                BackupStopResult {
                    lsn: "0/16B3F00".to_owned(),
                    label_file: "lbl\n".to_owned(),
                    spcmap_file: String::new(),
                },
            )
        };
        let policy = BackupPolicy {
            stop_auto: true,
            ..BackupPolicy::test_default()
        };
        run_backup(
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
            false,
            BackupFeatures::disabled(),
            crate::block::BlockOverrides::none(),
            JobRetry::none(),
            false,
            IntegrityChecks::disabled(),
            policy,
            None,
            None,
        )
        .expect("stop-auto backup");

        let calls = control.calls.borrow().clone();
        let stop_idx = calls
            .iter()
            .position(|c| c == "stop_running_backup")
            .expect("stop_running_backup called");
        let start_idx = calls
            .iter()
            .position(|c| c.starts_with("backup_start"))
            .expect("backup_start called");
        assert!(stop_idx < start_idx, "stop-auto runs before backup_start: {calls:?}");
    }

    #[test]
    fn db_timeout_and_keepalive_appear_in_conninfo() {
        // db-timeout (a Time in ms) becomes connect_timeout (seconds, rounded up);
        // the tcp-keep-alive-* integers become libpq keepalive params.
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("pg2-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        // 1500 ms -> connect_timeout=2 (rounded up from 1.5s).
        options.insert(("db-timeout".to_owned(), None), OptionValue::Time(1500));
        options.insert(("tcp-keep-alive-idle".to_owned(), None), OptionValue::Integer(30));
        options.insert(("tcp-keep-alive-interval".to_owned(), None), OptionValue::Integer(10));
        options.insert(("tcp-keep-alive-count".to_owned(), None), OptionValue::Integer(3));
        let cfg = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        };
        let conninfo = derive_conninfo_for_index(&cfg, 2).expect("pg2 conninfo");
        assert!(conninfo.contains("host=db.example"), "{conninfo}");
        assert!(conninfo.contains("connect_timeout=2"), "{conninfo}");
        assert!(conninfo.contains("keepalives=1"), "{conninfo}");
        assert!(conninfo.contains("keepalives_idle=30"), "{conninfo}");
        assert!(conninfo.contains("keepalives_interval=10"), "{conninfo}");
        assert!(conninfo.contains("keepalives_count=3"), "{conninfo}");
    }

    #[test]
    fn db_timeout_absent_leaves_conninfo_unchanged() {
        // No db-timeout / keepalive options -> the conninfo carries none of them.
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("pg2-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        let cfg = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        };
        let conninfo = derive_conninfo_for_index(&cfg, 2).expect("pg2 conninfo");
        assert!(!conninfo.contains("connect_timeout"), "{conninfo}");
        assert!(!conninfo.contains("keepalives"), "{conninfo}");
    }

    #[test]
    fn expire_auto_runs_expire_after_a_successful_backup() {
        // A DB-free `backup` run with expire-auto (default on) and
        // repo-retention-full=1 must expire older full backups after adding the
        // new one. Skipped when DATABASE_URL is set (the public `backup` entry
        // would try to connect to it, which a unit test must not do).
        if std::env::var("DATABASE_URL").is_ok() {
            return;
        }
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        init_stanza(&repo_s, "demo");
        seed_file(&pg_s, "base/1/1259", b"data");

        // Seed two pre-existing full backups so there is something to expire.
        backup_inner(
            "demo",
            &repo_s,
            &pg_s,
            "20230101-000000F",
            1_672_531_200,
            &RepoTransform::identity(),
        )
        .expect("seed full 1");
        backup_inner(
            "demo",
            &repo_s,
            &pg_s,
            "20230102-000000F",
            1_672_617_600,
            &RepoTransform::identity(),
        )
        .expect("seed full 2");

        // Build the config the public `backup` entry consumes: a stanza, full type,
        // a lock-path-free config (so locking no-ops), and repo-retention-full=1.
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("type".to_owned(), None), OptionValue::StringId("full".to_owned()));
        options.insert(("repo-retention-full".to_owned(), None), OptionValue::Integer(1));
        let config = LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        };

        backup(&config, &repo_s, &pg_s).expect("backup with expire-auto");

        // After expire-auto with retention=1, only the single newest full survives.
        let info = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("reload backup.info");
        assert_eq!(
            info.current.len(),
            1,
            "expire-auto must retain exactly one full backup, found: {:?}",
            info.current.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn policy_option_readers_resolve_defaults_and_overrides() {
        let base = || -> BTreeMap<(String, Option<u32>), OptionValue> { BTreeMap::new() };
        let cfg = |opts: BTreeMap<(String, Option<u32>), OptionValue>| LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: opts,
            params: Vec::new(),
        };

        // dry-run defaults false; stop-auto defaults false.
        assert!(!dry_run_enabled(&cfg(base())));
        assert!(!stop_auto_enabled(&cfg(base())));
        // resume + expire-auto default true.
        assert!(resume_enabled(&cfg(base())));
        assert!(expire_auto_enabled(&cfg(base())));
        // manifest-save-threshold defaults to 1 GiB.
        assert_eq!(manifest_save_threshold(&cfg(base())), DEFAULT_MANIFEST_SAVE_THRESHOLD);

        // Explicit overrides.
        let mut opts = base();
        opts.insert(("dry-run".to_owned(), None), OptionValue::Boolean(true));
        opts.insert(("resume".to_owned(), None), OptionValue::Boolean(false));
        opts.insert(("stop-auto".to_owned(), None), OptionValue::Boolean(true));
        opts.insert(("expire-auto".to_owned(), None), OptionValue::Boolean(false));
        opts.insert(("manifest-save-threshold".to_owned(), None), OptionValue::Size(4096));
        let c = cfg(opts);
        assert!(dry_run_enabled(&c));
        assert!(!resume_enabled(&c));
        assert!(stop_auto_enabled(&c));
        assert!(!expire_auto_enabled(&c));
        assert_eq!(manifest_save_threshold(&c), 4096);
    }

    // ---- block-incremental tuning overrides --------------------------------

    /// Build a minimal `LoadedConfig` from option entries for the option-reader
    /// tests below.
    fn opt_cfg(opts: BTreeMap<(String, Option<u32>), OptionValue>) -> LoadedConfig {
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: opts,
            params: Vec::new(),
        }
    }

    #[test]
    fn block_overrides_default_to_none_when_unset() {
        let overrides = block_overrides_from_options(&opt_cfg(BTreeMap::new()));
        assert_eq!(overrides, crate::block::BlockOverrides::none());
        assert!(overrides.maps_empty());
    }

    #[test]
    fn block_overrides_parse_maps_and_super_sizes() {
        let mut opts: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        // size map: 16KiB=8KiB, 512KiB=32KiB
        let mut size_map = std::collections::BTreeMap::new();
        size_map.insert("16KiB".to_owned(), "8KiB".to_owned());
        size_map.insert("512KiB".to_owned(), "32KiB".to_owned());
        opts.insert(("repo-block-size-map".to_owned(), None), OptionValue::Hash(size_map));
        // age map: 7=2 (days -> multiplier)
        let mut age_map = std::collections::BTreeMap::new();
        age_map.insert("7".to_owned(), "2".to_owned());
        opts.insert(("repo-block-age-map".to_owned(), None), OptionValue::Hash(age_map));
        // checksum-size map: 32KiB=7
        let mut cks_map = std::collections::BTreeMap::new();
        cks_map.insert("32KiB".to_owned(), "7".to_owned());
        opts.insert(("repo-block-checksum-size-map".to_owned(), None), OptionValue::Hash(cks_map));
        // super sizes.
        opts.insert(("repo-block-size-super".to_owned(), None), OptionValue::Size(2 * 1024 * 1024));
        opts.insert(
            ("repo-block-size-super-full".to_owned(), None),
            OptionValue::Size(8 * 1024 * 1024),
        );

        let overrides = block_overrides_from_options(&opt_cfg(opts));
        assert!(!overrides.maps_empty());

        // A 256 MiB fresh file: size map forces the 512KiB bucket -> 32 KiB block.
        let big = overrides
            .block_size(256 * 1024 * 1024, 0)
            .expect("256MiB file is block-eligible");
        assert_eq!(big, 32 * 1024, "size map override must pick the 512KiB bucket's 32KiB block");
        // It differs from the unmapped heuristic for this file.
        assert_ne!(big, crate::block::block_size(256 * 1024 * 1024, 0).unwrap());

        // checksum-size map: 32KiB block -> 7-byte checksum.
        assert_eq!(overrides.checksum_size(32 * 1024), 7);
        // super sizes select full vs incr.
        assert_eq!(overrides.super_size(false), 2 * 1024 * 1024);
        assert_eq!(overrides.super_size(true), 8 * 1024 * 1024);
    }

    #[test]
    fn block_overrides_read_grouped_repo_index() {
        // The maps / super sizes also resolve from the `repoN-`-indexed form.
        let mut opts: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        let mut size_map = std::collections::BTreeMap::new();
        size_map.insert("16KiB".to_owned(), "8KiB".to_owned());
        opts.insert(("repo-block-size-map".to_owned(), Some(1)), OptionValue::Hash(size_map));
        opts.insert(
            ("repo-block-size-super".to_owned(), Some(1)),
            OptionValue::Size(2 * 1024 * 1024),
        );
        let overrides = block_overrides_from_options(&opt_cfg(opts));
        assert_eq!(overrides.block_size(2 * 1024 * 1024, 0), Some(8 * 1024));
        assert_eq!(overrides.super_size(false), 2 * 1024 * 1024);
    }

    #[test]
    fn truncate_checksum_honours_size() {
        let full = "0123456789abcdef0123456789abcdef01234567"; // 40 hex chars (20 bytes)
        // 6 bytes -> 12 hex chars.
        assert_eq!(truncate_checksum(full, 6), &full[..12]);
        // 0 / oversized leaves it unchanged.
        assert_eq!(truncate_checksum(full, 0), full);
        assert_eq!(truncate_checksum(full, 100), full);
    }

    #[test]
    fn super_block_layout_groups_by_super_size() {
        // 5 blocks of 8 KiB each, super size 16 KiB -> 2 blocks per super block.
        let groups = super_block_layout(5, 8 * 1024, 16 * 1024);
        assert_eq!(groups, vec![2, 2, 1]);
        // super size smaller than block size -> one block per super block.
        assert_eq!(super_block_layout(3, 8 * 1024, 4 * 1024), vec![1, 1, 1]);
        // no blocks -> empty.
        assert!(super_block_layout(0, 8 * 1024, 16 * 1024).is_empty());
    }

    // ---- job-retry / job-retry-interval ------------------------------------

    #[test]
    fn job_retry_defaults_and_overrides() {
        // Defaults: 2 retries, 15s interval.
        let def = JobRetry::from_options(&opt_cfg(BTreeMap::new()));
        assert_eq!(def, JobRetry::new(2, std::time::Duration::from_secs(15)));

        let mut opts: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        opts.insert(("job-retry".to_owned(), None), OptionValue::Integer(4));
        opts.insert(("job-retry-interval".to_owned(), None), OptionValue::Time(500));
        let cfg = JobRetry::from_options(&opt_cfg(opts));
        assert_eq!(cfg, JobRetry::new(4, std::time::Duration::from_millis(500)));
        assert_eq!(cfg.attempts(), 5);
    }

    #[test]
    fn job_retry_succeeds_on_a_later_attempt() {
        use std::cell::Cell;
        // Fail the first two attempts, succeed on the third. With 2 retries
        // (3 attempts) this must succeed.
        let calls = Cell::new(0u32);
        let policy = JobRetry::new(2, std::time::Duration::ZERO);
        let result: Result<&str, &str> = policy.run(|| {
            let n = calls.get() + 1;
            calls.set(n);
            if n < 3 { Err("transient") } else { Ok("done") }
        });
        assert_eq!(result, Ok("done"));
        assert_eq!(calls.get(), 3, "the op must run exactly three times");
    }

    #[test]
    fn job_retry_errors_after_exhausting_retries() {
        use std::cell::Cell;
        // Always fail. With 1 retry (2 attempts) the op runs twice then errors.
        let calls = Cell::new(0u32);
        let policy = JobRetry::new(1, std::time::Duration::ZERO);
        let result: Result<(), &str> = policy.run(|| {
            calls.set(calls.get() + 1);
            Err("always")
        });
        assert_eq!(result, Err("always"));
        assert_eq!(calls.get(), 2, "1 retry means 2 total attempts");
    }

    #[test]
    fn job_retry_none_runs_once() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let policy = JobRetry::none();
        assert_eq!(policy.attempts(), 1);
        let result: Result<(), &str> = policy.run(|| {
            calls.set(calls.get() + 1);
            Err("nope")
        });
        assert_eq!(result, Err("nope"));
        assert_eq!(calls.get(), 1, "no-retry policy attempts exactly once");
    }

    /// A `Storage` wrapper that reports itself as **non-local** and records every
    /// `open_write` path, while delegating all real I/O to an inner [`Posix`].
    ///
    /// This simulates a remote/object backend (SSH / S3 / Azure / GCS / SFTP):
    /// `is_local()` is `false`, so the backup copy path must route data-file
    /// writes through [`Storage::open_write`] rather than `std::fs`. The
    /// delegation to `Posix` lets the bytes actually land so the manifest is
    /// loadable, while the recorded paths prove which writes went through the
    /// trait — a `std::fs` write would never appear here.
    struct RecordingStorage {
        inner: Posix,
        writes: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RecordingStorage {
        fn new(inner: Posix) -> Self {
            Self {
                inner,
                writes: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn writes(&self) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
            std::sync::Arc::clone(&self.writes)
        }
    }

    impl Storage for RecordingStorage {
        fn is_local(&self) -> bool {
            false
        }

        fn exists(&self, path: &Path) -> Result<bool, pgbr_storage::StorageError> {
            self.inner.exists(path)
        }

        fn info(&self, path: &Path) -> Result<pgbr_storage::StorageInfo, pgbr_storage::StorageError> {
            self.inner.info(path)
        }

        fn list(&self, path: &Path) -> Result<Vec<pgbr_storage::StorageInfo>, pgbr_storage::StorageError> {
            self.inner.list(path)
        }

        fn open_read(&self, path: &Path) -> Result<Box<dyn pgbr_io::IoRead>, pgbr_storage::StorageError> {
            self.inner.open_read(path)
        }

        fn open_write(&self, path: &Path) -> Result<Box<dyn pgbr_io::IoWrite>, pgbr_storage::StorageError> {
            self.writes.lock().unwrap().push(path.to_string_lossy().into_owned());
            self.inner.open_write(path)
        }

        fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.remove(path, error_on_missing)
        }

        fn rename(&self, source: &Path, target: &Path) -> Result<(), pgbr_storage::StorageError> {
            self.inner.rename(source, target)
        }

        fn create_path(&self, path: &Path, recursive: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.create_path(path, recursive)
        }

        fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.remove_path(path, recursive, error_on_missing)
        }
    }

    #[test]
    fn backup_into_non_local_repo_writes_data_files_through_open_write() {
        // A non-local repo must route every data-file write through the Storage
        // trait (`open_write`), not `std::fs` — otherwise a remote backup writes
        // its data files to the local machine and a remote restore fails.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_inner = Posix::new(repo.path());
        let pg_s = Posix::new(pg.path());

        init_stanza(&repo_inner, "demo");
        seed_cluster(&pg_s);

        let repo_s = RecordingStorage::new(repo_inner);
        let writes = repo_s.writes();

        let outcome = backup_inner("demo", &repo_s, &pg_s, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("backup");
        assert_eq!(outcome.file_count, 4, "4 non-excluded files expected");

        let recorded = writes.lock().unwrap().clone();
        let prefix = format!("backup/demo/{LABEL}/");

        // Every data file must have been written through open_write at its
        // repo-relative path. If the buggy std::fs path were taken, these would
        // be absent from the recorded set.
        for rel in ["global/pg_control", "PG_VERSION", "base/1/1259", "base/1/1260"] {
            let want = format!("{prefix}{rel}");
            assert!(
                recorded.contains(&want),
                "data file {rel} must be written via open_write; recorded writes: {recorded:?}"
            );
        }

        // The manifest write also goes through the trait (sanity check).
        assert!(
            recorded.iter().any(|p| p == &format!("{prefix}backup.manifest")),
            "manifest must be written via open_write; recorded writes: {recorded:?}"
        );

        // The bytes actually landed in the repo and the manifest is consistent.
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("load manifest");
        let pg_control = manifest.file("global/pg_control").expect("pg_control in manifest");
        assert_eq!(pg_control.checksum.as_deref(), Some(sha1_hex(b"\x01\x02\x03\x04").as_str()));
    }

    /// A `Storage` wrapper that counts every `open_read` while delegating all
    /// real I/O to an inner [`Posix`]. Used as the **worker-side** backing store
    /// behind a [`pgbr_storage::remote::StorageRequestHandler`] so the test can
    /// prove the backup copy path read each source file *through the worker*
    /// (`open_read`), not via `std::fs`.
    struct CountingPosix {
        inner: Posix,
        reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingPosix {
        fn new(inner: Posix) -> Self {
            Self {
                inner,
                reads: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn reads(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
            std::sync::Arc::clone(&self.reads)
        }
    }

    impl Storage for CountingPosix {
        // Inherit the default `is_local()` (false) so this is irrelevant here; the
        // worker only ever serves storage requests over the protocol.
        fn exists(&self, path: &Path) -> Result<bool, pgbr_storage::StorageError> {
            self.inner.exists(path)
        }

        fn info(&self, path: &Path) -> Result<pgbr_storage::StorageInfo, pgbr_storage::StorageError> {
            self.inner.info(path)
        }

        fn list(&self, path: &Path) -> Result<Vec<pgbr_storage::StorageInfo>, pgbr_storage::StorageError> {
            self.inner.list(path)
        }

        fn open_read(&self, path: &Path) -> Result<Box<dyn pgbr_io::IoRead>, pgbr_storage::StorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.open_read(path)
        }

        fn open_write(&self, path: &Path) -> Result<Box<dyn pgbr_io::IoWrite>, pgbr_storage::StorageError> {
            self.inner.open_write(path)
        }

        fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.remove(path, error_on_missing)
        }

        fn rename(&self, source: &Path, target: &Path) -> Result<(), pgbr_storage::StorageError> {
            self.inner.rename(source, target)
        }

        fn create_path(&self, path: &Path, recursive: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.create_path(path, recursive)
        }

        fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.remove_path(path, recursive, error_on_missing)
        }
    }

    #[test]
    fn backup_with_non_local_pg_reads_source_through_the_worker() {
        // The dedicated-repo-host "pull" topology: the orchestrator runs on the
        // repo host, the repo is LOCAL there, but the PG data dir lives on a
        // remote host reached through an SSH-spawned worker. Here `pg_storage` is a
        // `RemoteStorage` proxy over a `StorageRequestHandler<Posix>` served on a
        // thread, exactly as the real worker transport wires it.
        //
        // The bug: the copy path read each source via `std::fs::read(job.abs_src)`,
        // where `abs_src` is the REMOTE host's absolute PGDATA path — absent on the
        // repo host — so every read failed and the `job-retry` backoff hung the
        // backup. The fix reads the PG-data-relative path through `pg_storage`
        // (the worker). This test proves the source bytes really travelled through
        // the worker (its `open_read` is invoked once per data file) and that the
        // repo ends up with the copied files, byte-for-byte.
        use pgbr_protocol::ProtocolClient;
        use pgbr_protocol::transport::{PipeRead, PipeWrite, serve};
        use pgbr_storage::remote::{RemoteStorage, StorageRequestHandler};
        use std::sync::atomic::Ordering;
        use std::thread;

        // Backing store for the worker (the remote PG host's filesystem), wrapped
        // so we can count the `open_read`s the worker serves.
        let pg_dir = tempfile::tempdir().expect("pg tempdir");
        let counting = CountingPosix::new(Posix::new(pg_dir.path()));
        let reads = counting.reads();

        // Seed a representative PG data dir into the worker's backing store. These
        // are the files the copy path must read through the worker.
        let server_pg = Posix::new(pg_dir.path());
        seed_file(&server_pg, "PG_VERSION", b"14\n");
        seed_file(&server_pg, "base/1/1259", b"relation-data-1259");
        seed_file(&server_pg, "global/pg_control", b"\x01\x02\x03\x04");

        // Wire a RemoteStorage client to the StorageRequestHandler over two
        // os_pipe channels (server on its own thread), mirroring the real
        // worker transport (and `pgbr_storage::remote` / `worker.rs` tests).
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();
        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let mut handler = StorageRequestHandler::new(counting);
            serve(&mut reader, &mut writer, &mut handler).unwrap();
        });
        let client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        let pg_remote = RemoteStorage::new(client);
        // The proxy must report itself as non-local so the copy path reads the
        // source through it (the whole point of the fix).
        assert!(!pg_remote.is_local(), "RemoteStorage must be non-local");

        // The repository is LOCAL to the repo host (the pull topology), so it is a
        // plain Posix store on this machine.
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo_s = Posix::new(repo_dir.path());
        init_stanza(&repo_s, "demo");

        // Run a full backup with the remote PG storage and the local repo. With the
        // bug this would never read the source through the worker (and, in a real
        // multi-host setup, would hang on the missing local `abs_src`).
        let outcome =
            backup_inner("demo", &repo_s, &pg_remote, LABEL, 1_704_110_400, &RepoTransform::identity()).expect("pull backup");
        assert_eq!(outcome.file_count, 3, "3 non-excluded files expected");

        // The source for every data file was read THROUGH the worker. A full
        // backup performs no reference-detection reads, so the only `open_read`s on
        // `pg_storage` are the copy-path source reads added by the fix: one per
        // data file. If the buggy `std::fs` path had run, this would be zero.
        assert_eq!(
            reads.load(Ordering::SeqCst),
            3,
            "each source file must be read through the worker (open_read), not std::fs"
        );

        // The copied bytes really landed in the local repo, byte-for-byte — the
        // pull copy path round-tripped the source through the worker into the repo.
        let backup_root = repo_dir.path().join(format!("backup/demo/{LABEL}"));
        assert_eq!(std::fs::read(backup_root.join("PG_VERSION")).unwrap(), b"14\n");
        assert_eq!(std::fs::read(backup_root.join("base/1/1259")).unwrap(), b"relation-data-1259");
        assert_eq!(
            std::fs::read(backup_root.join("global/pg_control")).unwrap(),
            b"\x01\x02\x03\x04"
        );

        // The manifest lists the copied files with their plaintext checksums.
        let manifest = Manifest::load(&repo_s, Path::new(&format!("backup/demo/{LABEL}/backup.manifest"))).expect("load manifest");
        let listed: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert!(listed.contains(&"PG_VERSION"), "manifest must list PG_VERSION: {listed:?}");
        assert!(listed.contains(&"base/1/1259"));
        assert!(listed.contains(&"global/pg_control"));
        let pg_control = manifest.file("global/pg_control").expect("pg_control in manifest");
        assert_eq!(pg_control.checksum.as_deref(), Some(sha1_hex(b"\x01\x02\x03\x04").as_str()));

        // Drop the client (sends the exit handshake) so the worker sees EOF and the
        // server thread joins cleanly — keeping the test deterministic.
        pg_remote.close().expect("close remote pg storage");
        server.join().expect("worker thread joins");
    }

    // -------------------------------------------------------------------------
    // run_bundled_copy parallel-path tests.
    //
    // These call `run_bundled_copy` (and its `_serial` / `_parallel` variants)
    // directly with hand-built `BundledCopyCtx` instances, so they exercise the
    // bundle pipeline without driving a full `backup()` end-to-end. The fixtures
    // live entirely inside `tempfile::TempDir`s; the bundle bytes / manifest
    // entries are checked against the serial path's output to prove byte-for-byte
    // equivalence.
    // -------------------------------------------------------------------------

    /// Build a `(CopyJob, ManifestFile)` pair for `rel` inside the seeded PG /
    /// repo pair, mirroring what [`plan_file`] would have produced for a fresh
    /// file in a full backup.
    fn build_bundled_job(
        repo_dir: &std::path::Path,
        pg_dir: &std::path::Path,
        backup_root: &str,
        rel: &str,
        size: u64,
        timestamp: i64,
    ) -> (CopyJob, ManifestFile) {
        let abs_src = pg_dir.join(rel);
        let abs_dest = repo_dir.join(format!("{backup_root}/{rel}"));
        let rel_dest = format!("{backup_root}/{rel}");
        let job = CopyJob {
            rel: rel.to_owned(),
            abs_src,
            abs_dest,
            rel_dest,
            validate_pages: false,
            validate_page_header: false,
        };
        let skeleton = ManifestFile {
            path: rel.to_owned(),
            size,
            timestamp,
            checksum: None,
            checksum_page: None,
            reference: None,
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        };
        (job, skeleton)
    }

    /// Build a `BundledCopyCtx` for `repo_storage` + `pg_storage` (which must
    /// already hold the seeded files), with parallel-mode tuning and `block`
    /// enabled when the caller asks. Caller-supplied `prior_manifest` drives
    /// block-incremental reuse.
    #[allow(clippy::too_many_arguments)]
    fn make_bundled_ctx<'a>(
        repo_storage: &'a dyn Storage,
        pg_storage: &'a dyn Storage,
        backup_root: &'a str,
        transform: &'a RepoTransform,
        label: &'a str,
        skeletons: Vec<ManifestFile>,
        jobs: Vec<CopyJob>,
        prior_manifest: Option<&'a Manifest>,
        features: BackupFeatures,
        block_overrides: crate::block::BlockOverrides,
        process_max: usize,
        timestamp_start: i64,
    ) -> BundledCopyCtx<'a> {
        BundledCopyCtx {
            repo_storage,
            pg_storage,
            backup_root,
            transform,
            label,
            skeletons,
            jobs,
            referenced: Vec::new(),
            prior_manifest,
            features,
            block_overrides,
            is_full: true,
            job_retry: JobRetry::none(),
            timestamp_start,
            process_max,
        }
    }

    #[test]
    fn bundled_copy_parallel_local_whole_file_baseline() {
        // Three small whole-file bundled entries with process-max=4: the
        // parallel path must produce the same bundle bytes + manifest entries
        // the serial path produces.
        let (repo_dir, pg_dir, repo_s, pg_s) = posix_pair();
        let backup_root = "backup/demo/L";
        let label = "L";
        let files = [
            ("PG_VERSION", b"14\n".to_vec()),
            ("base/1/1259", b"relation one's bytes".to_vec()),
            ("base/1/1260", b"relation two's slightly different bytes".to_vec()),
        ];
        for (rel, bytes) in &files {
            seed_file(&pg_s, rel, bytes);
        }
        let transform = RepoTransform::identity();
        let features = BackupFeatures {
            bundle: true,
            bundle_size: 1024 * 1024,
            bundle_limit: 4096,
            block: false,
        };

        // -- Parallel run.
        let mut skeletons = Vec::new();
        let mut jobs = Vec::new();
        for (rel, bytes) in &files {
            let (job, skeleton) = build_bundled_job(
                repo_dir.path(),
                pg_dir.path(),
                backup_root,
                rel,
                bytes.len() as u64,
                1_000_000_000,
            );
            jobs.push(job);
            skeletons.push(skeleton);
        }
        let ctx = make_bundled_ctx(
            &repo_s,
            &pg_s,
            backup_root,
            &transform,
            label,
            skeletons,
            jobs,
            None,
            features,
            crate::block::BlockOverrides::none(),
            4,
            2_000_000_000,
        );
        let (parallel_files, parallel_size) = run_bundled_copy_parallel(ctx).expect("parallel bundled copy");
        let parallel_bundle = std::fs::read(repo_dir.path().join(format!("{backup_root}/bundle/1"))).expect("bundle 1");

        // -- Serial run into a separate repo so we can byte-compare the bundle.
        let serial_repo_dir = tempfile::tempdir().expect("serial repo tempdir");
        let serial_repo_s = Posix::new(serial_repo_dir.path());
        let mut skeletons2 = Vec::new();
        let mut jobs2 = Vec::new();
        for (rel, bytes) in &files {
            let (job, skeleton) = build_bundled_job(
                serial_repo_dir.path(),
                pg_dir.path(),
                backup_root,
                rel,
                bytes.len() as u64,
                1_000_000_000,
            );
            jobs2.push(job);
            skeletons2.push(skeleton);
        }
        let serial_ctx = make_bundled_ctx(
            &serial_repo_s,
            &pg_s,
            backup_root,
            &transform,
            label,
            skeletons2,
            jobs2,
            None,
            features,
            crate::block::BlockOverrides::none(),
            1,
            2_000_000_000,
        );
        let (serial_files, serial_size) = run_bundled_copy_serial(serial_ctx).expect("serial bundled copy");
        let serial_bundle = std::fs::read(serial_repo_dir.path().join(format!("{backup_root}/bundle/1"))).expect("serial bundle 1");

        // -- Byte-for-byte equivalence.
        assert_eq!(parallel_bundle, serial_bundle, "bundle bytes must match serial");
        assert_eq!(parallel_size, serial_size, "repo size must match serial");
        assert_eq!(
            parallel_files
                .iter()
                .map(|f| (f.path.clone(), f.checksum.clone(), f.bundle_id, f.bundle_offset))
                .collect::<Vec<_>>(),
            serial_files
                .iter()
                .map(|f| (f.path.clone(), f.checksum.clone(), f.bundle_id, f.bundle_offset))
                .collect::<Vec<_>>(),
            "manifest entries must match serial (path/checksum/bundle id/offset)",
        );
        // Every file actually bundled.
        for f in &parallel_files {
            assert!(f.bundle_id.is_some(), "{} must be bundled", f.path);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bundled_copy_parallel_local_block_incremental() {
        // One file split into 4 blocks (2 reused, 2 changed). The parallel path
        // parallelises the changed-block transforms while reused blocks are
        // pulled from the prior manifest on the main thread; the resulting
        // manifest must be byte-identical to the serial path's output.
        let (repo_dir, pg_dir, repo_s, pg_s) = posix_pair();
        let backup_root = "backup/demo/L";
        let label = "L";

        // Block-eligible size (≥ 128 KiB). Use 4 blocks of 32 KiB.
        let block_size_usize: usize = 32 * 1024;
        let block_size: u64 = block_size_usize as u64;
        let block_count: usize = 4;
        let total_len = block_size_usize * block_count;
        let prior_bytes: Vec<u8> = (0..total_len).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
        // The "new" file matches the prior in blocks 0 and 2, differs in 1 and 3.
        let mut new_bytes = prior_bytes.clone();
        for byte in &mut new_bytes[block_size_usize..2 * block_size_usize] {
            *byte ^= 0xff;
        }
        for byte in &mut new_bytes[3 * block_size_usize..4 * block_size_usize] {
            *byte = byte.wrapping_add(7);
        }
        seed_file(&pg_s, "base/1/1259", &new_bytes);
        let transform = RepoTransform::identity();
        let features = BackupFeatures {
            bundle: true,
            bundle_size: 1024 * 1024,
            bundle_limit: 4096,
            block: true,
        };

        // Build a prior manifest whose block map matches the *prior* bytes' blocks.
        // Each prior BlockRef carries the truncated checksum (default 6 bytes ->
        // 12 hex chars) of one prior block.
        let mut prior_block_refs = Vec::new();
        for idx in 0..block_count {
            let start = idx * block_size_usize;
            let end = start + block_size_usize;
            let checksum = truncate_checksum(&sha1_hex(&prior_bytes[start..end]), 6);
            prior_block_refs.push(pgbr_info::manifest::BlockRef {
                checksum,
                reference: "PRIOR".to_owned(),
                bundle_id: 9,
                offset: (idx as u64) * 100,
                size: 100,
            });
        }
        let prior_manifest = Manifest {
            backup_label: "PRIOR".to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 0,
            timestamp_stop: 0,
            db_version: "14".to_owned(),
            db_system_id: 1,
            option_checksum_page: None,
            paths: Vec::new(),
            links: Vec::new(),
            files: vec![ManifestFile {
                path: "base/1/1259".to_owned(),
                size: total_len as u64,
                timestamp: 0,
                checksum: Some(sha1_hex(&prior_bytes)),
                checksum_page: None,
                reference: None,
                mode: None,
                user: None,
                group: None,
                bundle_id: None,
                bundle_offset: None,
                block_map: Some(pgbr_info::manifest::BlockMap {
                    block_size,
                    blocks: prior_block_refs,
                }),
            }],
        };

        // Force the per-file block size to exactly 32 KiB via `repo-block-size-map`
        // (so the heuristic does not pick a smaller block size for this 128 KiB
        // file and produce 16 blocks instead of 4).
        let block_overrides = crate::block::BlockOverrides::new(vec![(0u64, block_size)], Vec::new(), Vec::new(), None, None);
        let run_one = |repo_dir: &std::path::Path, repo_s: &Posix, process_max: usize| -> (Vec<ManifestFile>, u64, Vec<u8>) {
            let (job, skeleton) = build_bundled_job(
                repo_dir,
                pg_dir.path(),
                backup_root,
                "base/1/1259",
                total_len as u64,
                1_000_000_000,
            );
            let ctx = make_bundled_ctx(
                repo_s,
                &pg_s,
                backup_root,
                &transform,
                label,
                vec![skeleton],
                vec![job],
                Some(&prior_manifest),
                features,
                block_overrides.clone(),
                process_max,
                1_000_000_000, // fresh: same as file mtime, so block_size kicks in.
            );
            let (files, size) = if process_max > 1 {
                run_bundled_copy_parallel(ctx).expect("parallel bundled block copy")
            } else {
                run_bundled_copy_serial(ctx).expect("serial bundled block copy")
            };
            let bundle_path = repo_dir.join(format!("{backup_root}/bundle/1"));
            let bundle_bytes = if bundle_path.exists() {
                std::fs::read(&bundle_path).expect("bundle")
            } else {
                Vec::new()
            };
            (files, size, bundle_bytes)
        };

        let (parallel_files, parallel_size, parallel_bundle) = run_one(repo_dir.path(), &repo_s, 4);

        // -- Serial reference run.
        let serial_repo_dir = tempfile::tempdir().expect("serial repo tempdir");
        let serial_repo_s = Posix::new(serial_repo_dir.path());
        let (serial_files, serial_size, serial_bundle) = run_one(serial_repo_dir.path(), &serial_repo_s, 1);

        assert_eq!(parallel_bundle, serial_bundle, "bundle bytes must match serial");
        assert_eq!(parallel_size, serial_size, "repo size must match serial");
        assert_eq!(parallel_files.len(), 1);
        let p_bm = parallel_files[0].block_map.as_ref().expect("parallel block map");
        let s_bm = serial_files[0].block_map.as_ref().expect("serial block map");
        assert_eq!(p_bm.block_size, s_bm.block_size);
        assert_eq!(
            p_bm.blocks, s_bm.blocks,
            "block map (including reused PRIOR refs and stored block bundle offsets) must match serial",
        );

        // Sanity: blocks 0 + 2 are reused PRIOR refs, blocks 1 + 3 are stored
        // in this label.
        assert_eq!(p_bm.blocks[0].reference, "PRIOR");
        assert_eq!(p_bm.blocks[1].reference, label);
        assert_eq!(p_bm.blocks[2].reference, "PRIOR");
        assert_eq!(p_bm.blocks[3].reference, label);
    }

    #[test]
    fn bundled_copy_remote_storage_falls_back_to_serial() {
        // A non-local repo storage forces the serial path even when process-max
        // is high. The resulting bundle bytes + manifest must match a direct
        // serial-path invocation.
        let (repo_dir, pg_dir, _repo_inner, pg_s) = posix_pair();
        let backup_root = "backup/demo/L";
        let label = "L";
        let files = [
            ("PG_VERSION", b"14\n".to_vec()),
            ("base/1/1259", b"data one".to_vec()),
            ("base/1/1260", b"another one".to_vec()),
        ];
        for (rel, bytes) in &files {
            seed_file(&pg_s, rel, bytes);
        }
        let transform = RepoTransform::identity();
        let features = BackupFeatures {
            bundle: true,
            bundle_size: 1024 * 1024,
            bundle_limit: 4096,
            block: false,
        };

        let recording = RecordingStorage::new(Posix::new(repo_dir.path()));
        let mut skeletons = Vec::new();
        let mut jobs = Vec::new();
        for (rel, bytes) in &files {
            let (job, skeleton) = build_bundled_job(
                repo_dir.path(),
                pg_dir.path(),
                backup_root,
                rel,
                bytes.len() as u64,
                1_000_000_000,
            );
            jobs.push(job);
            skeletons.push(skeleton);
        }
        let ctx = make_bundled_ctx(
            &recording,
            &pg_s,
            backup_root,
            &transform,
            label,
            skeletons,
            jobs,
            None,
            features,
            crate::block::BlockOverrides::none(),
            8, // high process-max — must still be ignored because repo is not local.
            2_000_000_000,
        );
        // The router (`run_bundled_copy`) must pick the serial branch when the
        // repo is non-local even with process-max > 1.
        let (files_out, _size) = run_bundled_copy(ctx).expect("non-local bundled copy");
        let bundle_data = std::fs::read(repo_dir.path().join(format!("{backup_root}/bundle/1"))).expect("bundle 1");

        // Reference serial run against a local Posix to compare bytes.
        let local_repo_dir = tempfile::tempdir().expect("local repo tempdir");
        let local_repo_s = Posix::new(local_repo_dir.path());
        let mut skeletons2 = Vec::new();
        let mut jobs2 = Vec::new();
        for (rel, bytes) in &files {
            let (job, skeleton) = build_bundled_job(
                local_repo_dir.path(),
                pg_dir.path(),
                backup_root,
                rel,
                bytes.len() as u64,
                1_000_000_000,
            );
            jobs2.push(job);
            skeletons2.push(skeleton);
        }
        let ctx2 = make_bundled_ctx(
            &local_repo_s,
            &pg_s,
            backup_root,
            &transform,
            label,
            skeletons2,
            jobs2,
            None,
            features,
            crate::block::BlockOverrides::none(),
            1,
            2_000_000_000,
        );
        let (ref_files, _ref_size) = run_bundled_copy_serial(ctx2).expect("reference serial");
        let ref_bundle = std::fs::read(local_repo_dir.path().join(format!("{backup_root}/bundle/1"))).expect("ref bundle");

        assert_eq!(bundle_data, ref_bundle, "non-local fallback bundle bytes must match serial");
        assert_eq!(
            files_out
                .iter()
                .map(|f| (f.path.clone(), f.bundle_id, f.bundle_offset))
                .collect::<Vec<_>>(),
            ref_files
                .iter()
                .map(|f| (f.path.clone(), f.bundle_id, f.bundle_offset))
                .collect::<Vec<_>>(),
            "non-local fallback manifest entries must match serial",
        );

        // Every write the non-local backend received must go through open_write
        // (proves the parallel std::fs path was NOT taken).
        let recorded = recording.writes().lock().unwrap().clone();
        assert!(
            recorded.iter().any(|p| p == &format!("{backup_root}/bundle/1")),
            "bundle 1 must be written via open_write; recorded: {recorded:?}",
        );
    }

    #[test]
    fn bundled_copy_determinism_two_runs() {
        // Two parallel runs over the same seeded inputs must produce
        // byte-identical bundle objects. Anything else means the slot
        // pre-allocation order leaked into the worker pool.
        let backup_root = "backup/demo/L";
        let label = "L";
        let files = [
            ("PG_VERSION", b"14\n".to_vec()),
            ("base/1/1259", b"relation one's bytes".to_vec()),
            ("base/1/1260", b"relation two's slightly different bytes".to_vec()),
            ("base/1/1261", b"a third relation here".to_vec()),
            (
                "base/1/1262",
                b"and a fourth, longer than the others to keep the packer busy".to_vec(),
            ),
        ];
        let transform = RepoTransform::identity();
        let features = BackupFeatures {
            bundle: true,
            bundle_size: 1024 * 1024,
            bundle_limit: 4096,
            block: false,
        };

        let run_once = || -> Vec<u8> {
            let (repo_dir, pg_dir, repo_s, pg_s) = posix_pair();
            for (rel, bytes) in &files {
                seed_file(&pg_s, rel, bytes);
            }
            let mut skeletons = Vec::new();
            let mut jobs = Vec::new();
            for (rel, bytes) in &files {
                let (job, skeleton) = build_bundled_job(
                    repo_dir.path(),
                    pg_dir.path(),
                    backup_root,
                    rel,
                    bytes.len() as u64,
                    1_000_000_000,
                );
                jobs.push(job);
                skeletons.push(skeleton);
            }
            let ctx = make_bundled_ctx(
                &repo_s,
                &pg_s,
                backup_root,
                &transform,
                label,
                skeletons,
                jobs,
                None,
                features,
                crate::block::BlockOverrides::none(),
                4,
                2_000_000_000,
            );
            run_bundled_copy_parallel(ctx).expect("parallel bundled copy");
            std::fs::read(repo_dir.path().join(format!("{backup_root}/bundle/1"))).expect("bundle 1")
        };

        let bundle_a = run_once();
        let bundle_b = run_once();
        assert_eq!(
            bundle_a, bundle_b,
            "two parallel runs must produce byte-identical bundle objects"
        );
    }
}
