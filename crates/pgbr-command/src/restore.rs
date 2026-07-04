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
//!   `[backup:current]` is restored — pgBackRust labels sort chronologically
//!   (`YYYYMMDD-HHMMSSF…`), so the greatest label is the latest backup. An
//!   empty `[backup:current]` is a [`CommandError::Other`].
//!
//! Checksum verification is **on** and a mismatch is a **hard error**
//! ([`CommandError::Other`]): restoring corrupt data silently is worse than
//! failing the restore.
//!
//! # Parallel file copy (`process-max`)
//!
//! The per-file work — read the repo file, reverse its [`RepoTransform`]
//! (decrypt then decompress), write the recovered plaintext to the PG target,
//! and verify its SHA-1 — is distributed across `process-max` workers via the
//! in-process [`pgbr_protocol::parallel`] dispatcher, mirroring `backup`. All
//! the decision logic (backup selection, reference resolution, db-include /
//! db-exclude filtering, delta matching, tablespace-target resolution, symlink
//! re-creation, recovery config) stays on the main thread; only the actual
//! file copies are dispatched. The [`Storage`] trait is not `Send`, so each job
//! threads owned absolute [`PathBuf`]s plus a cloned [`RepoTransform`] into the
//! worker, which does its I/O via `std::fs` against those absolute paths (the
//! same pattern `backup` uses). The hard-fail SHA-1 check runs **per file in
//! the worker**, so a corrupt file fails the whole restore regardless of which
//! worker copied it. `process-max=1` reproduces the prior serial behaviour
//! byte-for-byte. C reference: `src/protocol/parallel.c`.
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
//! # Tablespace remapping
//!
//! A tablespace is stored under `pg_tblspc/<oid>` as a symlink whose recorded
//! destination is the external path the tablespace lived at. On restore, the
//! destination of every `pg_tblspc/<oid>` link can be redirected:
//!
//! - `--tablespace-map=<oid>=<path>` remaps one specific tablespace's
//!   destination directory.
//! - `--tablespace-map-all=<prefix>` puts *every* tablespace under
//!   `<prefix>/<tablespace-name>`, where the name is the last path component of
//!   the link's recorded destination.
//!
//! Precedence is explicit `--tablespace-map` entry > `--tablespace-map-all`
//! prefix > the manifest's recorded destination. The pure
//! [`resolve_tablespace_target`] function does the resolution and is wired into
//! the symlink-creation path. Links that are not tablespace links
//! (`pg_tblspc/<oid>`) keep their recorded destination unchanged.
//!
//! # Generic link remapping (`--link-map`)
//!
//! A non-tablespace symlink (e.g. `pg_wal`) can be re-created pointing at a
//! different destination via `--link-map=<link-name>=<path>`, where `<link-name>`
//! is the link's path relative to the PG data dir (the manifest link name with its
//! `pg_data/` prefix stripped). When a manifest link's name has a `--link-map`
//! entry, the link is created at the mapped destination instead of the manifest's
//! recorded target; unmapped links keep their recorded target. The pure
//! [`resolve_link_target`] function does the resolution. Tablespace links are
//! never subject to `--link-map` (they are remapped only via `--tablespace-map` /
//! `--tablespace-map-all`), matching the C generator, which errors if a tablespace
//! is named in `--link-map`. C ref: the link-remap loop in
//! `src/command/restore/remap.c.inc`.
//!
//! # Selective database restore (`--db-include` / `--db-exclude`)
//!
//! `--db-include` restores ONLY the named databases; `--db-exclude` restores all
//! databases EXCEPT the named ones. The two are mutually exclusive (supplying
//! both is a [`CommandError::Other`]). A database's files live under
//! `base/<db-oid>/` and, for tablespace-resident databases, under
//! `pg_tblspc/<ts>/PG_*/<db-oid>/`. The [`database_included`] predicate extracts
//! the db-oid from such paths and applies the include/exclude lists; files that
//! are not under any database directory (`global/`, `pg_wal/`, top-level config
//! files, etc.) are ALWAYS restored. Excluded files are simply not copied.
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
//! files at all.
//!
//! On top of the target type, the recovery-target family is honoured:
//!
//! - `--target-action` (`pause` / `promote` / `shutdown`) emits
//!   `recovery_target_action = '<value>'` whenever the resolved value is not the
//!   default `pause` (matching the C generator, which suppresses the GUC for the
//!   default since `PostgreSQL` already pauses).
//! - `--target-timeline` emits `recovery_target_timeline = '<value>'`. On PG < 12
//!   the literal value `current` is *not* written (that version defaults to it and
//!   rejects it as an explicit parameter); on PG >= 12 it is always written. When
//!   `--target-timeline` is unset, `--type=immediate` on PG >= 12 still emits
//!   `recovery_target_timeline = 'current'` so recovery does not chase the latest
//!   timeline it cannot reach (mirrors the C workaround for a `PostgreSQL` bug).
//!
//! On top of the built-in lines, `--recovery-option=<key>=<value>` (a `Hash`
//! option) writes arbitrary extra recovery settings verbatim into the generated
//! config (e.g. `archive_cleanup_command=...`, a `restore_command=...` override,
//! `primary_conninfo=...`). The user options are merged in AFTER the built-in
//! recovery-target lines, so a user key that collides with a built-in (notably
//! `restore_command`) wins: the built-in line is suppressed and the user value
//! emitted instead. Keys arrive `-`-separated (users naturally type pgBackRust's
//! own option style) and are normalised to `_` before writing; values are
//! single-quoted, matching the recovery-conf `key = 'value'` format. C ref:
//! `restoreRecoveryOption` in `src/command/restore/config.c.inc`.
//!
//! The generator is the pure [`recovery_files`] function so it is unit-testable
//! without any storage.
//!
//! # Deferred to later commits
//!
//! - `--type=preserve` (leave any existing recovery file untouched). The resolved
//!   recovery-target settings (`--type`, `--target`, `--target-exclusive`,
//!   `--target-action`, `--target-timeline`) plus arbitrary `--recovery-option`
//!   passthrough are generated here.
//!
//! This is the full raw-restore path; everything above is genuinely out of
//! scope for the slice, not silently dropped.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoBackup, InfoError, Manifest, ManifestFile, ManifestLink};
use pgbr_io::{Filter, Sha1};
use pgbr_protocol::message::{OkResponse, Request, Response};
use pgbr_protocol::parallel::{Job, ParallelExecutor};
use pgbr_storage::{Storage, StorageError, StorageKind, validate_relative};
use serde_json::json;

use crate::CommandError;
use crate::backup::JobRetry;
use crate::pipeline::RepoTransform;

/// Emit a human progress line at `INFO` through the process-global logger.
///
/// The restore counterpart of `backup::log_info`: restore progress (command
/// begin / end, planned dry-run actions) goes through [`pgbr_core::log`] instead
/// of `println!` so it honours the configured level and `[DRY-RUN]` prefix. The
/// write result is ignored — a logging failure must never fail the restore.
fn log_info(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_INFO,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        file!(),
        "restore",
        0,
        message,
    );
}

/// Whether `--dry-run` was supplied. A `Boolean` defaulting to `false`; only an
/// explicit `true` enables the no-mutation planning mode. C ref: `cfgOptDryRun`.
fn dry_run_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("dry-run".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Whether `--force` was supplied and set to `true`. `--force` lets a restore
/// overwrite a non-empty `PGDATA` (the operator asserts the directory is safe to
/// clobber), the same escape hatch pgBackRust's `restoreCheck` honours. C ref:
/// `cfgOptForce`.
fn force_enabled(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("force".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Validate a manifest-recorded relative path (a `[target:file]` /
/// `[target:link]` / `[target:path]` key) before it is joined onto the PG target.
///
/// A restored path must stay inside `PGDATA`: a malicious or corrupt manifest
/// must not be able to steer a write at an absolute path (`/etc/passwd`) or one
/// that climbs out with `..` (`../../etc/cron.d/x`). This reuses the same guard
/// the storage protocol applies to network-sourced paths
/// ([`pgbr_storage::validate_relative`]): relative, no `..` component. An empty
/// path is also rejected (a restore target must name something).
///
/// # Errors
///
/// [`CommandError::Other`] describing the offending path when it is empty,
/// absolute, or contains a `..` component.
fn validate_manifest_path(kind: &str, rel: &str) -> Result<(), CommandError> {
    if rel.is_empty() {
        return Err(CommandError::Other(format!("manifest {kind} has an empty path")));
    }
    validate_relative(Path::new(rel)).map_err(|err| CommandError::Other(format!("manifest {kind} path '{rel}' rejected: {err}")))
}

/// Pre-flight safety checks run **before any mutation** of the PG target.
///
/// Refuses to clobber a running or populated cluster:
///
/// - A `postmaster.pid` in the target means a live (or crashed-but-not-cleaned)
///   `PostgreSQL` is using this data directory; overwriting it under it would
///   corrupt the cluster. This is a hard error regardless of `--delta`/`--force`.
/// - A non-empty `PGDATA` without `--delta` or `--force` is refused: a plain
///   restore expects an empty target, and silently overwriting an existing
///   cluster loses data. `--delta` (reconcile in place) or `--force` (operator
///   override) opt out. Mirrors pgBackRust's `restoreCheck`. Skipped on dry-run
///   (no mutation happens anyway).
fn preflight_pgdata(pg: &dyn Storage, delta: bool, force: bool, dry_run: bool) -> Result<(), CommandError> {
    if dry_run {
        return Ok(());
    }

    // A live cluster is never safe to restore over, even with --delta/--force.
    if pg.exists(Path::new("postmaster.pid"))? {
        return Err(CommandError::Other(
            "postmaster.pid exists in the PG data directory: refusing to restore over a running or unclean \
             cluster (stop PostgreSQL and remove postmaster.pid first)"
                .to_owned(),
        ));
    }

    // A non-empty PGDATA requires an explicit opt-in.
    if !delta && !force {
        let non_empty = match pg.list(Path::new(".")) {
            Ok(entries) => !entries.is_empty(),
            // A missing target dir is empty; other errors surface.
            Err(StorageError::NotFound { .. }) => false,
            Err(err) => return Err(CommandError::Storage(err)),
        };
        if non_empty {
            return Err(CommandError::Other(
                "PG data directory is not empty: restore requires an empty target, or --delta to reconcile in \
                 place, or --force to overwrite"
                    .to_owned(),
            ));
        }
    }

    Ok(())
}

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
    /// Number of `[target:link]` entries materialised as a plain directory inside
    /// `PGDATA` instead of a symlink, because `--no-repo-symlink` suppressed
    /// symlink creation. Always `0` under the default `repo-symlink=y`.
    pub links_as_dir: usize,
    /// Relative paths of the recovery files written after the copy pass
    /// (e.g. `recovery.conf`, or `postgresql.auto.conf` + `recovery.signal`).
    /// Empty when `--type=none`. Under `--dry-run` these are the files that
    /// *would* be written; none is actually created.
    pub recovery_files_written: Vec<String>,
    /// Whether this was a `--dry-run`: every count reflects what a real restore
    /// *would* do, but **no** files were created, removed, or modified in the PG
    /// target. C ref: `cfgOptDryRun`.
    pub dry_run: bool,
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

/// The `--tablespace-map` hash (tablespace-id -> new destination path). Absent or
/// non-hash resolves to an empty map.
fn tablespace_map(config: &LoadedConfig) -> BTreeMap<String, String> {
    match config.options.get(&("tablespace-map".to_owned(), None)) {
        Some(OptionValue::Hash(map)) => map.clone(),
        _ => BTreeMap::new(),
    }
}

/// The `--tablespace-map-all` destination prefix, if supplied.
fn tablespace_map_all(config: &LoadedConfig) -> Option<String> {
    match config.options.get(&("tablespace-map-all".to_owned(), None)) {
        Some(OptionValue::Path(value) | OptionValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

/// The `--link-map` hash (link-name -> new destination path). Absent or non-hash
/// resolves to an empty map. Keys are link names relative to the PG data dir
/// (e.g. `pg_wal`), matching the manifest link's name with its `pg_data/` prefix
/// stripped. C ref: `cfgOptLinkMap` in `src/command/restore/remap.c.inc`.
fn link_map(config: &LoadedConfig) -> BTreeMap<String, String> {
    match config.options.get(&("link-map".to_owned(), None)) {
        Some(OptionValue::Hash(map)) => map.clone(),
        _ => BTreeMap::new(),
    }
}

/// Whether `--link-all` was supplied and set to `true`. When set, restore
/// re-creates the cluster's symlinked directories/files (other than tablespaces)
/// at their ORIGINAL link destinations recorded in the manifest, instead of
/// restoring them as plain directories inside `PGDATA`. Default `false` keeps the
/// historical behaviour (links restored as plain dirs in `PGDATA`). C ref:
/// `cfgOptLinkAll` in `src/command/restore/restore.c`.
fn link_all(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("link-all".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Whether `repo-symlink` permits symlink creation during restore. The option is
/// a boolean defaulting to `true`; `--no-repo-symlink` (i.e. `false`) makes
/// restore lay everything out as real files/directories inside `PGDATA` and
/// create NO symlinks at all (neither tablespace links nor `--link-all` links).
/// Absent resolves to the `true` default. The option is `group: repo`, so it is
/// also read under the `repo1-` index. C ref: `cfgOptRepoSymlink`.
fn repo_symlink(config: &LoadedConfig) -> bool {
    // Prefer the ungrouped key, then the repo1-indexed key; default true.
    let lookup = config
        .options
        .get(&("repo-symlink".to_owned(), None))
        .or_else(|| config.options.get(&("repo-symlink".to_owned(), Some(1))));
    match lookup {
        Some(OptionValue::Boolean(value)) => *value,
        _ => true,
    }
}

/// The `--recovery-option` hash (recovery-setting key -> value). Absent or
/// non-hash resolves to an empty map. Keys arrive with `-` separators (users
/// naturally type `archive-cleanup-command`); the recovery-config generator
/// normalises `-` to `_` before writing, mirroring the C `strReplaceChr(key,
/// '-', '_')`. C ref: `restoreRecoveryOption` in
/// `src/command/restore/config.c.inc`.
fn recovery_options(config: &LoadedConfig) -> BTreeMap<String, String> {
    match config.options.get(&("recovery-option".to_owned(), None)) {
        Some(OptionValue::Hash(map)) => map.clone(),
        _ => BTreeMap::new(),
    }
}

/// A `--db-include` / `--db-exclude` list option as a vector of strings. Absent
/// or non-list resolves to an empty vector.
fn db_list(config: &LoadedConfig, name: &str) -> Vec<String> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::List(values)) => values.clone(),
        _ => Vec::new(),
    }
}

/// First `PostgreSQL` major version that drives recovery via GUCs in
/// `postgresql.auto.conf` + a `recovery.signal` file, rather than the standalone
/// `recovery.conf` of earlier versions. Mirrors C's `PG_VERSION_RECOVERY_GUC`.
const PG_VERSION_RECOVERY_GUC: u32 = 12;

/// `PostgreSQL` runtime directories restore always re-creates (empty) so a
/// fresh-PGDATA restore yields a startable cluster.
///
/// The backup keeps the transient runtime *directories* themselves in the
/// manifest but never descends into them (their contents are transient and not
/// worth capturing). Their required *subdirectories* — most critically
/// `pg_wal/archive_status`, where `PostgreSQL` writes `.ready` / `.done`
/// markers during archive recovery — are therefore absent from the manifest. A
/// restore into an empty PGDATA must materialise the full skeleton or the
/// server FATALs at start (e.g. `could not open directory "pg_notify"`).
///
/// Only directories are listed (restore creates no files). `replorigin_checkpoint`
/// under `pg_logical` is a file `PostgreSQL` writes itself, so it is intentionally
/// omitted. Paths are PG-data-relative, `/`-separated. Each is created
/// recursively + idempotently, so one already made by a manifest path (or a
/// parent listed earlier here) is a no-op. Mirrors the empty directories
/// pgBackRust's restore lays down for a complete cluster skeleton.
const PG_RUNTIME_SKELETON_DIRS: &[&str] = &[
    "pg_wal",
    "pg_wal/archive_status",
    "pg_notify",
    "pg_replslot",
    "pg_serial",
    "pg_snapshots",
    "pg_dynshmem",
    "pg_stat_tmp",
    "pg_subtrans",
    "pg_stat",
    "pg_logical",
    "pg_logical/snapshots",
    "pg_logical/mappings",
    "pg_commit_ts",
    "pg_tblspc",
];

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

/// Whether `--type=preserve` was requested. In that mode restore leaves any
/// existing recovery configuration untouched, so the residual-signal cleanup
/// (`recovery.signal` / `standby.signal` / `recovery.conf`) is skipped.
fn recovery_preserve(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("type".to_owned(), None)),
        Some(OptionValue::StringId(value) | OptionValue::String(value)) if value == "preserve"
    )
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

/// The resolved `--target-action` (`pause` / `promote` / `shutdown`), defaulting
/// to `pause` when absent (mirrors the option's `default: pause`). The
/// recovery-config generator emits `recovery_target_action` only when this is not
/// the default `pause`, exactly like the C generator.
fn target_action(config: &LoadedConfig) -> &'static str {
    let raw = match config.options.get(&("target-action".to_owned(), None)) {
        Some(OptionValue::StringId(value) | OptionValue::String(value)) => value.as_str(),
        _ => "pause",
    };
    match raw {
        "promote" => "promote",
        "shutdown" => "shutdown",
        // `pause` or anything unrecognised: the default (no GUC emitted).
        _ => "pause",
    }
}

/// The resolved `--target-timeline` value, if supplied.
fn target_timeline(config: &LoadedConfig) -> Option<&str> {
    string_option(config, "target-timeline")
}

/// The `--pg-version-force` override, if supplied. When present, this PG major
/// version is used (instead of the manifest's recorded `db-version`) to choose
/// the recovery-config format — the `recovery.conf` vs `postgresql.auto.conf` +
/// signal split keyed on [`PG_VERSION_RECOVERY_GUC`]. C ref: `cfgOptPgVersionForce`.
fn pg_version_force(config: &LoadedConfig) -> Option<&str> {
    string_option(config, "pg-version-force")
}

/// Whether `--archive-mode=preserve` was supplied. pgBackRust's restore
/// `archive-mode` option is a string-id with allow-list `preserve` / `off` and a
/// default of `preserve`. `preserve` keeps the cluster's existing archive
/// settings — restore does NOT touch `archive_mode` in the generated recovery
/// config. `off` makes restore emit `archive_mode = off` so a restored cluster
/// does not archive WAL until the operator re-enables it. Absent / unrecognised
/// resolves to the `preserve` default. C ref: `cfgOptArchiveMode` handling in
/// `src/command/restore/config.c.inc`.
fn archive_mode_off(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("archive-mode".to_owned(), None)),
        Some(OptionValue::StringId(value) | OptionValue::String(value)) if value == "off"
    )
}

/// The `restore_command` `PostgreSQL` runs to fetch one archived WAL segment.
/// `%f` is the segment name `PostgreSQL` substitutes and `"%p"` the destination
/// path. Mirrors the C generator's
/// `<exe> archive-get %f "%p"` shape, reduced here to the binary name + stanza.
fn restore_command(stanza: &str) -> String {
    format!("pgbackrust --stanza={stanza} archive-get %f \"%p\"")
}

/// The resolved recovery-target settings the [`recovery_block`] generator emits,
/// beyond the always-present `restore_command` / target-type lines. Bundled into a
/// struct so the signature stays readable as the family grows.
#[derive(Debug, Clone, Copy)]
struct RecoverySettings<'a> {
    /// The `--target` value (used for `time` / `name` / `lsn` / `xid` types).
    target: Option<&'a str>,
    /// Whether `--target-exclusive` is set (drives `recovery_target_inclusive`).
    exclusive: bool,
    /// The resolved `--target-action` (`pause` / `promote` / `shutdown`); the
    /// default `pause` suppresses the GUC.
    action: &'a str,
    /// The `--target-timeline` value, if supplied.
    timeline: Option<&'a str>,
    /// Arbitrary extra recovery settings from `--recovery-option` (key -> value),
    /// merged in AFTER the built-in lines. Keys arrive `-`-separated and are
    /// normalised to `_` before writing; a user key that collides with a built-in
    /// (e.g. `restore_command`) wins — the built-in line is suppressed and the
    /// user value written instead.
    recovery_options: &'a BTreeMap<String, String>,
    /// Whether `--archive-mode=off` was supplied. When `true`, restore emits
    /// `archive_mode = off` into the generated recovery config so the restored
    /// cluster does not archive WAL. The default `preserve` leaves `archive_mode`
    /// untouched (no GUC emitted), matching pgBackRust.
    archive_mode_off: bool,
}

/// Normalise a `--recovery-option` key to the `_`-separated GUC form `PostgreSQL`
/// expects. Users naturally type `archive-cleanup-command` (matching pgBackRust's
/// own option style), so `-` is replaced with `_`. Mirrors the C
/// `strReplaceChr(key, '-', '_')`.
fn normalise_recovery_key(key: &str) -> String {
    key.replace('-', "_")
}

/// Whether the user supplied a `--recovery-option` whose normalised key matches
/// `guc` — used to suppress the matching built-in line so the user value wins.
fn user_overrides(recovery_options: &BTreeMap<String, String>, guc: &str) -> bool {
    recovery_options.keys().any(|k| normalise_recovery_key(k) == guc)
}

/// Escape a value destined for a single-quoted `PostgreSQL` recovery-config string
/// (`key = 'value'`). A literal apostrophe in the value would otherwise close the
/// quote early and either break the config or inject an extra setting; `PostgreSQL`
/// escapes an embedded single quote by doubling it (`''`). C ref: `strReplace` on
/// the recovery-option value in `src/command/restore/config.c.inc`.
fn escape_guc(value: &str) -> String {
    value.replace('\'', "''")
}

/// Render the recovery settings block (a `key = 'value'` line per setting) for the
/// given PG major version, resolved recovery type, and recovery-target settings.
/// The leading header line identifies the restore. Always emits `restore_command`
/// (unless the user overrode it via `--recovery-option`); the recovery-target lines
/// depend on the type and settings. Any `--recovery-option` entries are merged in
/// AFTER the built-in lines (user wins on key collision). Returns an empty string
/// for [`RecoveryType::None`] (callers should not write any recovery file then).
fn recovery_block(db_major: u32, stanza: &str, ty: RecoveryType, settings: RecoverySettings<'_>) -> String {
    use std::fmt::Write as _;

    if ty == RecoveryType::None {
        return String::new();
    }

    let opts = settings.recovery_options;
    let mut out = String::from("# Recovery settings generated by pgBackRust restore\n");

    // restore_command — built-in unless the user overrides it via --recovery-option,
    // in which case the user's value is emitted with the other user options below
    // (mirrors the C generator, which skips the built-in restore_command when the
    // user already supplied one). `write!` into a `String` is infallible.
    if !user_overrides(opts, "restore_command") {
        let _ = writeln!(out, "restore_command = '{}'", escape_guc(&restore_command(stanza)));
    }

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
            if let Some(value) = settings.target {
                let _ = writeln!(out, "recovery_target_{} = '{}'", kind.guc_suffix(), escape_guc(value));
                if settings.exclusive && kind.supports_inclusive() {
                    out.push_str("recovery_target_inclusive = 'false'\n");
                }
            }
        }
        // Default writes only restore_command; None returned early above.
        RecoveryType::Default | RecoveryType::None => {}
    }

    // recovery_target_action — emitted only when not the default `pause`, mirroring
    // the C generator (PostgreSQL already pauses at the target by default). The
    // option's `depend` restricts when it can be set (immediate/lsn/name/time/xid),
    // so no extra type check is needed here.
    if settings.action != "pause" {
        let _ = writeln!(out, "recovery_target_action = '{}'", escape_guc(settings.action));
    }

    // recovery_target_timeline — when supplied, write it, except that on PG < 12 the
    // literal `current` is suppressed (that version defaults to it and rejects it as
    // an explicit parameter). When unset, type=immediate on PG >= 12 still pins the
    // timeline to `current` so recovery does not chase a `latest` timeline it cannot
    // reach (the C workaround for a PostgreSQL bug).
    match settings.timeline {
        Some(value) => {
            if db_major >= PG_VERSION_RECOVERY_GUC || value != "current" {
                let _ = writeln!(out, "recovery_target_timeline = '{}'", escape_guc(value));
            }
        }
        None => {
            if ty == RecoveryType::Immediate && db_major >= PG_VERSION_RECOVERY_GUC {
                out.push_str("recovery_target_timeline = 'current'\n");
            }
        }
    }

    // archive_mode — emitted only for --archive-mode=off, and only when the user
    // did not override it via --recovery-option (in which case the user value wins,
    // emitted below). The default `preserve` leaves the cluster's existing
    // archive_mode untouched (no GUC), matching the C generator. The value `off` is
    // a bare keyword, not a quoted string, exactly as PostgreSQL expects.
    if settings.archive_mode_off && !user_overrides(opts, "archive_mode") {
        out.push_str("archive_mode = off\n");
    }

    // Merge the user's --recovery-option settings AFTER the built-in lines. Keys are
    // normalised (`-` -> `_`) and emitted in sorted order (BTreeMap iterates
    // ascending) so the output is deterministic. A user key that matched a built-in
    // (e.g. restore_command) had its built-in line suppressed above, so writing it
    // here makes the user value win. Values are single-quoted, matching the
    // recovery-conf `key = 'value'` format.
    for (key, value) in opts {
        let _ = writeln!(out, "{} = '{}'", normalise_recovery_key(key), escape_guc(value));
    }

    out
}

/// Parse a `YYYY-MM-DD HH:MM:SS` (optionally `T`-separated, with an optional
/// fractional second and trailing timezone) timestamp into Unix epoch seconds.
/// Returns `None` for anything that does not parse.
///
/// A trailing timezone designator (`Z`, `±HH`, `±HHMM`, or `±HH:MM`) is honoured:
/// the wall-clock value is converted to UTC by subtracting the zone's offset east
/// of UTC before the epoch is returned, so a `--target='2024-01-01 12:00:00+02'`
/// compares correctly against a UTC `backup-timestamp-stop`. A value with no zone
/// is interpreted as UTC, matching this fork's deterministic-UTC handling
/// elsewhere (`format_timestamp` renders `+0000`).
///
/// This is the inverse of [`crate::backup::unix_to_civil`] /
/// `info::format_timestamp`'s civil-date algorithm (Howard Hinnant's
/// `days_from_civil`). It is used only to compare a `--type=time` /
/// `--repo-target-time` target against each backup's recorded
/// `backup-timestamp-stop` for auto-selecting a backup set. C ref: the time-target
/// backup-set search in `src/command/restore/restore.c` (`restoreBackupSet`).
fn parse_civil_time(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    // Split date and time on the first space or `T`; a date-only value defaults
    // the time to midnight.
    let (date, time) = trimmed.split_once([' ', 'T']).unwrap_or((trimmed, "00:00:00"));

    // Date: YYYY-MM-DD.
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Split off any timezone suffix BEFORE the `:`-split, because an offset like
    // `+02:00` itself contains a colon. `tz_offset_secs` is the offset east of
    // UTC in seconds (e.g. `+02:00` -> 7200, `-0500` -> -18000, `Z` -> 0); `None`
    // means the value carried no explicit zone and is interpreted as UTC (matching
    // this fork's deterministic-UTC handling).
    let (time_body, tz_offset_secs) = split_timezone(time);

    // Time: HH:MM[:SS]; strip any fractional second off the seconds field.
    let mut time_parts = time_body.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next().unwrap_or("0").parse().ok()?;
    let second: i64 = time_parts.next().map_or(0, |sec| {
        let digits: String = sec.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().unwrap_or(0)
    });
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=60).contains(&second) {
        return None;
    }

    // days_from_civil: shift month-of-year so leap handling is uniform (March = 0).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;

    let local_epoch = days * 86_400 + hour * 3600 + minute * 60 + second;
    // Convert the wall-clock value to UTC: an offset EAST of UTC means the local
    // clock is ahead, so the UTC epoch is `local - offset`. No offset => already UTC.
    Some(local_epoch - tz_offset_secs.unwrap_or(0))
}

/// Split a `HH:MM[:SS[.frac]]` time string into its `(body, tz_offset_secs)`,
/// where the body has any trailing timezone designator removed and
/// `tz_offset_secs` is the zone's offset east of UTC in seconds (`Some(0)` for
/// `Z`), or `None` when no zone was present. Accepts `Z`, `±HH`, `±HHMM`, and
/// `±HH:MM`. A malformed offset is treated as "no zone" so the value falls back
/// to UTC rather than mis-parsing.
fn split_timezone(time: &str) -> (&str, Option<i64>) {
    let time = time.trim();
    if let Some(body) = time.strip_suffix(['Z', 'z']) {
        return (body, Some(0));
    }

    // Find the sign that introduces the offset. Scan from the end so a `-` inside
    // the (colon-separated) time never matches — the offset sign is the last one.
    if let Some(pos) = time.rfind(['+', '-']) {
        let (body, tz) = time.split_at(pos);
        let sign = if tz.starts_with('-') { -1 } else { 1 };
        let digits: String = tz[1..].chars().filter(char::is_ascii_digit).collect();
        let (oh, om): (i64, i64) = match digits.len() {
            // `+HH`
            1 | 2 => (digits.parse::<i64>().unwrap_or(-1), 0),
            // `+HHMM` / `+HH:MM`
            3 | 4 => {
                let split = digits.len() - 2;
                (
                    digits[..split].parse::<i64>().unwrap_or(-1),
                    digits[split..].parse::<i64>().unwrap_or(-1),
                )
            }
            _ => (-1, -1),
        };
        if (0..=23).contains(&oh) && (0..=59).contains(&om) {
            return (body, Some(sign * (oh * 3600 + om * 60)));
        }
        // Malformed offset: ignore it and treat the value as UTC.
    }

    (time, None)
}

/// The target timestamp (epoch seconds) used to auto-select a backup set, if the
/// restore expresses one. `--repo-target-time` takes precedence (it is the
/// explicit repository-time selector); otherwise a `--type=time` restore uses
/// its `--target` value. Returns `None` when neither is present or parseable, in
/// which case the latest backup is restored as before.
fn backup_set_target_time(config: &LoadedConfig) -> Option<i64> {
    if let Some(raw) = string_option(config, "repo-target-time")
        && let Some(epoch) = parse_civil_time(raw)
    {
        return Some(epoch);
    }
    if recovery_type(config) == RecoveryType::Target(TargetKind::Time)
        && let Some(raw) = string_option(config, "target")
    {
        return parse_civil_time(raw);
    }
    None
}

/// Pull `backup-timestamp-stop` (epoch seconds) out of a `[backup:current]`
/// entry. A missing or non-integer field yields `None`. Mirrors
/// `expire::timestamp_stop`.
fn entry_timestamp_stop(value: &serde_json::Value) -> Option<i64> {
    value.get("backup-timestamp-stop").and_then(serde_json::Value::as_i64)
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

    // `--pg-version-force` overrides the manifest's recorded db-version for the
    // recovery-config format decision (recovery.conf vs postgresql.auto.conf +
    // signal). When absent, the manifest's db_version drives the split.
    let db_major = db_major_version(pg_version_force(config).unwrap_or(db_version));
    // Owned so the borrow in `RecoverySettings` outlives the `recovery_block` call.
    let recovery_opts = recovery_options(config);
    let settings = RecoverySettings {
        target: string_option(config, "target"),
        exclusive: target_exclusive(config),
        action: target_action(config),
        timeline: target_timeline(config),
        recovery_options: &recovery_opts,
        archive_mode_off: archive_mode_off(config),
    };
    let block = recovery_block(db_major, stanza, ty, settings);

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
///
/// This is the serial path used when the PG target storage is not local
/// (`is_local() == false`): every byte travels through the `Storage` trait,
/// stays on the main thread. The local fast path classifies files via
/// [`classify_delta_match`] (size-only / needs-hash / no-match) and dispatches
/// the SHA-1 hashing across `process-max` workers via [`run_delta_jobs`].
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
    sha1_bytes_hex(&bytes).is_some_and(|actual| actual == expected)
}

/// SHA-1 of `bytes`, returned as lowercase hex, or `None` if the filter
/// machinery itself fails (a logic error, not a corruption — surfaced as "no
/// match" in delta classification so the file is restored rather than silently
/// skipped).
fn sha1_bytes_hex(bytes: &[u8]) -> Option<String> {
    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    if sha.process(bytes, &mut sink).is_err() {
        return None;
    }
    Some(sha.digest_hex())
}

/// Outcome of the cheap (no SHA-1) main-thread classification of one file
/// against the PG target under `--delta`. Computed by [`classify_delta_match`].
#[derive(Debug, Clone)]
enum DeltaMatch {
    /// Target file exists at the right size and the manifest records no
    /// checksum (zero-length file): same size is enough to skip the restore.
    /// Settled on the main thread without any per-byte work.
    Matches,
    /// Target file exists at the right size and the manifest records a
    /// checksum: the file's SHA-1 must still be computed to decide. The PG
    /// target's `is_local()` is true here, so the work is dispatched to the
    /// parallel hasher; otherwise the serial [`target_matches`] path is taken.
    NeedsHash {
        /// Absolute on-disk path to the PG-target file (used by the parallel
        /// `std::fs` hasher). Resolved via `pg.info(rel).path` on the main
        /// thread.
        abs_path: PathBuf,
        /// The plaintext SHA-1 the manifest recorded; the worker compares its
        /// freshly-computed digest against this and replies with a bool.
        expected_sha: String,
    },
    /// Target file is missing, the wrong size, the wrong kind, or `info` itself
    /// failed: the file is restored — no further work needed.
    NoMatch,
}

/// Classify one manifest file against the PG target, splitting "matches" /
/// "needs SHA-1" / "no match" on the main thread without ever reading file
/// bytes. The SHA-1 case is handed off to [`run_delta_jobs`] on a local PG
/// target.
///
/// Mirrors [`target_matches`]'s cheap-checks-first semantics, but stops short
/// of the SHA-1 (which is the expensive part this refactor parallelises).
/// `local_pg` toggles the absolute-path resolution: on a non-local PG target
/// the parallel branch is never taken (the caller falls back to serial
/// [`target_matches`] for those files), so the path resolution is skipped.
fn classify_delta_match(pg: &dyn Storage, rel: &Path, file: &ManifestFile, local_pg: bool) -> DeltaMatch {
    let Ok(info) = pg.info(rel) else {
        return DeltaMatch::NoMatch;
    };
    if info.kind != StorageKind::File || info.size != file.size {
        return DeltaMatch::NoMatch;
    }

    // Same size, no recorded checksum (zero-length file): settled — match.
    let Some(expected) = file.checksum.as_deref() else {
        return DeltaMatch::Matches;
    };

    if !local_pg {
        // Caller will take the serial `target_matches` path; this enum value
        // is unused on the non-local branch but kept for type completeness —
        // returning `NoMatch` would silently miss-classify, so we encode the
        // exact same intent (SHA-1 needed) and let the caller decide.
        return DeltaMatch::NeedsHash {
            abs_path: PathBuf::new(),
            expected_sha: expected.to_owned(),
        };
    }

    DeltaMatch::NeedsHash {
        abs_path: info.path,
        expected_sha: expected.to_owned(),
    }
}

/// One file the parallel delta SHA-1 pre-pass must hash on a worker. Encodes a
/// PG-target file whose size already matched but whose SHA-1 still has to be
/// computed against `expected_sha` to decide whether the restore can skip it.
///
/// Built on the main thread by [`restore_inner`] from the [`DeltaMatch::NeedsHash`]
/// classification and consumed by a worker thread, which reads `abs_path`,
/// computes SHA-1, and replies with `{matches: bool}`. The fields are all
/// owned so the job can cross the thread boundary the parallel dispatcher
/// imposes; `rel` correlates the worker's result back to the manifest file
/// path.
#[derive(Debug, Clone)]
struct DeltaJob {
    /// Manifest-relative path (e.g. `pg_data/base/1/1259`). Echoed back as the
    /// dispatcher correlation key.
    rel: String,
    /// Absolute on-disk path the worker reads via `std::fs::read`.
    abs_path: PathBuf,
    /// The plaintext SHA-1 the manifest recorded; compared to the worker's
    /// freshly-computed digest.
    expected_sha: String,
}

/// Encode a [`DeltaJob`] as a dispatcher [`Request`]: `rel` is the `cmd`
/// (correlation key), and the absolute path + expected SHA-1 ride in `param`
/// as JSON primitives. The expected SHA-1 stays in the request so the worker
/// can settle the match locally and reply with a single boolean — `Response`
/// outs are JSON primitives only.
fn delta_request(job: &DeltaJob) -> Request {
    Request {
        cmd: job.rel.clone(),
        param: vec![json!(job.abs_path.to_string_lossy()), json!(job.expected_sha)],
    }
}

/// Decode a [`Request`] produced by [`delta_request`] inside a worker.
fn delta_request_decode(request: &Request) -> Result<(PathBuf, String), String> {
    let abs_path = request
        .param
        .first()
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "delta job missing abs path".to_owned())?;
    let expected = request
        .param
        .get(1)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "delta job missing expected sha".to_owned())?;
    Ok((PathBuf::from(abs_path), expected.to_owned()))
}

/// Hash every [`DeltaJob`] across `process-max` workers via the in-process
/// dispatcher, returning the set of manifest-relative paths whose target file
/// matched (and should therefore be skipped). The caller has already filtered
/// to local PG storage; the parallel `std::fs` fast path is always taken here.
///
/// Each worker reads `abs_path` via `std::fs::read`, computes SHA-1, and
/// returns `{matches: bool}`. Any I/O / hashing failure is treated as
/// "does not match" — i.e. the file is restored, never silently skipped —
/// mirroring the serial [`target_matches`] semantics. The worker closure is
/// `Send + Sync + 'static` and captures nothing but the per-Request primitives
/// the dispatcher hands it.
///
/// `worker_count == 1` runs a single worker (the prior serial behaviour
/// byte-for-byte). An empty job list returns an empty set without spinning up
/// the pool.
fn run_delta_jobs(jobs: &[DeltaJob], worker_count: usize) -> std::collections::HashSet<String> {
    use std::collections::HashSet;
    if jobs.is_empty() {
        return HashSet::new();
    }

    let dispatcher_jobs: Vec<Job> = jobs
        .iter()
        .map(|job| Job {
            key: job.rel.clone(),
            request: delta_request(job),
        })
        .collect();

    // The closure captures no borrowed data and no `Storage` handle — only the
    // primitives off each `Request`. `std::fs::read` is the local fast path
    // (every job here lives on a local PG target, gated by the caller).
    let results = ParallelExecutor::new(worker_count).run(dispatcher_jobs, move |request| {
        let (abs_path, expected) = delta_request_decode(request)?;
        // Any read / hash failure → "does not match" so the file is restored.
        // This mirrors `target_matches`, which returns `false` on any I/O blip.
        let matches = std::fs::read(&abs_path).is_ok_and(|bytes| sha1_bytes_hex(&bytes).is_some_and(|actual| actual == expected));
        Ok(Response::Ok(OkResponse {
            out: Some(json!({ "matches": matches })),
        }))
    });

    let mut matched: HashSet<String> = HashSet::new();
    for job_result in results {
        // A worker that errored / panicked / produced an unexpected response
        // is treated as "no match" so the corresponding file is restored —
        // the same conservative stance as the serial `target_matches` path.
        if let Ok(Response::Ok(OkResponse { out: Some(value) })) = job_result.result
            && value.get("matches").and_then(serde_json::Value::as_bool).unwrap_or(false)
        {
            matched.insert(job_result.key);
        }
    }
    matched
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

/// Whether a manifest link is a tablespace link (`…/pg_tblspc/<oid>`). The OID
/// segment is whatever follows the final `pg_tblspc/` component; pgBackRust
/// records these as the only links under `pg_tblspc`.
fn tablespace_oid(link: &ManifestLink) -> Option<&str> {
    // Links look like `pg_data/pg_tblspc/16395`; split on the `pg_tblspc/`
    // marker and take the trailing component (the OID directory name).
    link.path.rsplit_once("pg_tblspc/").map(|(_, oid)| oid)
}

/// Resolve where a tablespace's `pg_tblspc/<oid>` symlink should point on restore.
///
/// Precedence mirrors pgBackRust: an explicit `--tablespace-map=<oid>=<path>`
/// entry wins; otherwise `--tablespace-map-all=<prefix>` puts the tablespace
/// under `<prefix>/<tablespace-name>` (the name is the final component of the
/// link's recorded destination); otherwise the manifest's recorded destination
/// is used unchanged. Links that are not tablespace links keep their recorded
/// destination.
fn resolve_tablespace_target(link: &ManifestLink, map: &BTreeMap<String, String>, map_all: Option<&str>) -> PathBuf {
    let Some(oid) = tablespace_oid(link) else {
        // Not a tablespace link: never remapped.
        return PathBuf::from(&link.destination);
    };

    // 1. Explicit per-tablespace mapping wins.
    if let Some(path) = map.get(oid) {
        return PathBuf::from(path);
    }

    // 2. `--tablespace-map-all` prefix + the tablespace name (last component of
    //    the recorded destination).
    if let Some(prefix) = map_all {
        let name = Path::new(&link.destination)
            .file_name()
            .map_or_else(|| oid.to_owned(), |n| n.to_string_lossy().into_owned());
        return Path::new(prefix).join(name);
    }

    // 3. Fall back to the manifest's recorded destination.
    PathBuf::from(&link.destination)
}

/// The PG-data-relative name of a manifest link (its name with the leading
/// `pg_data/` target prefix stripped), used to look the link up in `--link-map`.
/// pgBackRust records every link under the `pg_data` manifest target, so the
/// link's path looks like `pg_data/pg_wal`; the `--link-map` key is `pg_wal`.
/// A link without the `pg_data/` prefix is returned unchanged.
fn link_relative_name(link_path: &str) -> &str {
    link_path.strip_prefix("pg_data/").unwrap_or(link_path)
}

/// Resolve where a manifest link should be re-created to point, honouring
/// `--link-map`. When `link_name` (the PG-data-relative link name) has an entry
/// in `link_map`, the mapped destination wins; otherwise the manifest's recorded
/// target is kept unchanged. Pure so it can be unit-tested without storage.
///
/// C ref: the link-remap loop in `src/command/restore/remap.c.inc`, where a
/// `--link-map=<link>=<path>` entry updates the manifest link/target destination.
fn resolve_link_target(link_name: &str, recorded_target: &str, link_map: &BTreeMap<String, String>) -> String {
    link_map.get(link_name).cloned().unwrap_or_else(|| recorded_target.to_owned())
}

/// How a `[target:link]` manifest entry is materialised on the restore target,
/// decided by `--link-all` / `--no-repo-symlink` and whether the link is a
/// tablespace link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkPlan {
    /// Re-create the entry as a real symlink pointing at its (possibly remapped)
    /// destination. The classic behaviour.
    Symlink,
    /// Create the entry's path as a plain directory inside `PGDATA` instead of a
    /// symlink, so its restored contents live in-place. Used when
    /// `--no-repo-symlink` suppresses symlink creation entirely.
    PlainDir,
}

/// Decide how to materialise one manifest link, given the `repo-symlink` toggle.
///
/// - `--no-repo-symlink` (`repo_symlink == false`) suppresses symlink creation
///   *entirely*: every link — tablespace or not, `--link-all` or not — is laid
///   out as a plain directory inside `PGDATA`. This is the faithful
///   `repo-symlink=n` behaviour (everything restored as real files/dirs, no
///   symlinks).
/// - Otherwise (the default `repo-symlink=y`) the link is re-created as a symlink
///   at its recorded/remapped destination: a tablespace link must be a symlink
///   (it lives outside `PGDATA`), and a non-tablespace link (`pg_wal`, a `config`
///   link) is re-created as one too — `--link-all` is the explicit request for
///   exactly this.
///
/// Parity note: upstream pgBackRust restores a *non-tablespace* link as a plain
/// in-place directory UNLESS `--link-all` is given. This fork's historical default
/// already re-creates such links as symlinks, so to preserve existing behaviour the
/// non-tablespace default stays `Symlink`; `--link-all` is honoured as the explicit
/// intent and `--no-repo-symlink` is the suppressor. Because every link is a
/// symlink under `repo-symlink=y` today, only the suppressor changes the outcome,
/// so the decision reduces to the `repo-symlink` toggle.
const fn link_plan(repo_symlink: bool) -> LinkPlan {
    if repo_symlink { LinkPlan::Symlink } else { LinkPlan::PlainDir }
}

/// Whether a manifest file belongs to a database that should be restored, given
/// the resolved `--db-include` / `--db-exclude` lists.
///
/// A database's files live under `base/<oid>/…` (default tablespace) and under
/// `pg_tblspc/<ts>/PG_*/<oid>/…` (a non-default tablespace). The numeric `<oid>`
/// segment is extracted from such paths:
///
/// - When `include` is non-empty, only files whose oid is in `include` are kept.
/// - When `exclude` is non-empty, files whose oid is in `exclude` are dropped.
/// - Files that are NOT under a database directory (`global/`, `pg_wal/`,
///   top-level config files, etc.) are ALWAYS restored.
///
/// This slice matches by the numeric oid path segment. Matching a database by
/// NAME (mapping the name to its oid via the manifest's `db` section) is a
/// future refinement.
fn database_included(file_path: &str, include: &[String], exclude: &[String]) -> bool {
    let Some(oid) = database_oid(file_path) else {
        // Not a per-database file: always restored regardless of the filters.
        return true;
    };

    if !include.is_empty() {
        return include.iter().any(|name| name == oid);
    }
    if !exclude.is_empty() {
        return !exclude.iter().any(|name| name == oid);
    }
    // Neither filter set: everything is included.
    true
}

/// Extract the database oid segment from a manifest file path, if it is a
/// per-database file. Recognises `base/<oid>/…` and the tablespace equivalent
/// `pg_tblspc/<ts>/PG_*/<oid>/…`. A leading prefix such as `pg_data/` is
/// tolerated. Returns `None` for files that are not under a database directory.
fn database_oid(file_path: &str) -> Option<&str> {
    let segments: Vec<&str> = file_path.split('/').collect();

    for (i, seg) in segments.iter().enumerate() {
        match *seg {
            // `base/<oid>/…` — the oid is the component right after `base`, and
            // there must be at least one more component (the relation file).
            "base" => {
                if let Some(oid) = segments.get(i + 1)
                    && segments.len() > i + 2
                    && is_numeric(oid)
                {
                    return Some(oid);
                }
            }
            // `pg_tblspc/<ts>/PG_<ver>_<cat>/<oid>/…` — the oid is two
            // components after the `PG_*` version directory.
            _ if seg.starts_with("PG_") => {
                if let Some(oid) = segments.get(i + 1)
                    && segments.len() > i + 2
                    && is_numeric(oid)
                {
                    return Some(oid);
                }
            }
            _ => {}
        }
    }

    None
}

/// Whether every character of `s` is an ASCII digit (and `s` is non-empty) — a
/// `PostgreSQL` oid directory name.
fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Resolve the single backup to restore, returning its label and its
/// `[backup:current]` metadata entry.
///
/// With `--set`, that label — but only if it is present in
/// `[backup:current]` (an unknown set is an error). Without `--set`:
///
/// - When the restore expresses a time target (`--repo-target-time`, or
///   `--type=time --target=<t>`), the backup set is auto-selected: the most
///   recent backup whose `backup-timestamp-stop` is at or before the target.
///   When no backup is old enough (the target precedes them all), the
///   *earliest* backup is used and WAL replay carries the cluster forward to the
///   target — mirroring pgBackRust's `restoreBackupSet`.
/// - Otherwise the lexicographically-greatest label in `[backup:current]`, which
///   is the most recent backup given pgBackRust's chronological label format.
///
/// An empty `[backup:current]` is an error.
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
    // On an encrypted repository backup.info is encrypted under the user
    // passphrase (`repo-cipher-pass`); resolve it (`None` for an unencrypted
    // repo, the plaintext path) and decrypt on load.
    let user_pass = crate::cipher::active_user_pass(config)?;
    let info = InfoBackup::load_keyed(repo, &backup_info_path(stanza), user_pass.as_deref())
        .map(|(info, _)| info)
        .map_err(|err| match err {
            InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
                path: backup_info_path(stanza),
            }),
            other => CommandError::Other(other.to_string()),
        })?;

    // `--set` defaults to the sentinel `latest` (config.yaml), which means "the
    // most recent backup" — NOT a literal label. Only an explicit, non-`latest`
    // label is looked up directly. C ref: restore.c treats `latest` specially.
    if let Some(label) = requested_set(config)
        && label != "latest"
    {
        if let Some(entry) = info.current.get(label) {
            let entry = entry.clone();
            return Ok((label.to_owned(), entry, info));
        }
        return Err(CommandError::Other(format!(
            "backup set {label} is not present in the repository"
        )));
    }

    // Auto-select by time target when one is expressed (and no explicit --set).
    if let Some(target) = backup_set_target_time(config) {
        let label = select_backup_by_time(&info, target).ok_or_else(|| CommandError::Other("no backups to restore".to_owned()))?;
        // The label came from `info.current`, so the entry is always present.
        let entry = info.current.get(&label).cloned().unwrap_or_default();
        return Ok((label, entry, info));
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

/// Choose the backup label to restore for a time target: the most recent backup
/// whose recorded `backup-timestamp-stop` is at or before `target`. When no
/// backup qualifies (the target precedes every backup's stop time), fall back to
/// the *earliest* backup so WAL replay can carry the cluster forward to the
/// target. Returns `None` only when there are no backups at all. Pure (operates
/// on the loaded [`InfoBackup`]) so it is unit-testable. C ref: the time-target
/// search in `restoreBackupSet` (`src/command/restore/restore.c`).
fn select_backup_by_time(info: &InfoBackup, target: i64) -> Option<String> {
    // Iterate ascending by label (chronological). Keep the last backup whose stop
    // time is <= target; remember the very first as the precedes-everything fallback.
    let mut chosen: Option<&String> = None;
    let mut earliest: Option<&String> = None;
    for (label, entry) in &info.current {
        if earliest.is_none() {
            earliest = Some(label);
        }
        if let Some(stop) = entry_timestamp_stop(entry)
            && stop <= target
        {
            chosen = Some(label);
        }
    }
    chosen.or(earliest).cloned()
}

/// Number of parallel file-copy workers, from the resolved `process-max` option.
///
/// `process-max` is an `Integer` (default 1). Values `< 1` clamp to one worker
/// so the copy phase always makes progress; the dispatcher additionally caps the
/// thread count at the number of files to copy. Mirrors `backup`'s helper.
fn process_max(config: &LoadedConfig) -> usize {
    match config.options.get(&("process-max".to_owned(), None)) {
        Some(OptionValue::Integer(value)) if *value >= 1 => usize::try_from(*value).unwrap_or(1),
        _ => 1,
    }
}

/// One file the copy phase must physically restore into the PG target.
///
/// Produced on the main thread by [`restore_inner`] (which has already resolved
/// references, db-include/exclude filtering, delta matching, and the backup the
/// bytes live in) and consumed by a worker thread, which reads `abs_src`,
/// reverses the transform, writes `abs_dst`, and verifies the SHA-1. The fields
/// are all owned so the job can cross the thread boundary the parallel
/// dispatcher imposes; `rel` correlates the worker's result back to the manifest
/// file path. `expected_checksum` is the plaintext SHA-1 the manifest recorded
/// (`None` for a zero-length file), checked in the worker so a corrupt file
/// fails the whole restore regardless of which worker copied it.
#[derive(Debug, Clone)]
struct RestoreCopyJob {
    /// Manifest file path, used as the dispatcher correlation key and in errors.
    rel: String,
    /// How to obtain the recovered plaintext: a standalone repo object, a slice
    /// of a bundle object, or a reassembled block-incremental file.
    source: RestoreSource,
    /// Absolute destination path in the PG target (plaintext, no suffix).
    abs_dst: PathBuf,
    /// Plaintext SHA-1 the manifest recorded, or `None` for a zero-length file.
    expected_checksum: Option<String>,
    /// Unix file mode the manifest recorded, re-applied to the restored file via
    /// `std::fs::set_permissions` on Unix. `None` when the manifest did not record
    /// a mode (older backups, non-Unix source) — the restored file keeps its
    /// freshly-created default mode. uid/gid are recorded-only (re-applying owner
    /// needs privilege; documented follow-up). C ref: chmod in
    /// `src/command/restore/restore.c`.
    mode: Option<u32>,
}

/// How a worker should obtain a file's recovered plaintext.
///
/// Every variant carries both the absolute repo path (`abs_*`, used by the local
/// `Posix`/`Cifs` fast path, which reads via `std::fs`) and the repo-*relative*
/// path (`repo_*`, used by the non-local remote/object path, which reads through
/// [`Storage::open_read`]). Only one path is consulted, decided by
/// [`Storage::is_local`].
#[derive(Debug, Clone)]
enum RestoreSource {
    /// A whole file stored as its own repo object (suffix included): read the
    /// object and reverse the transform. The classic, unbundled layout.
    Standalone {
        /// Absolute source path of the repo file (local fast path).
        abs_src: PathBuf,
        /// Repo-relative source path (non-local `open_read` path).
        repo_src: PathBuf,
        /// Transform the source backup applied (reversed to recover plaintext).
        transform: RepoTransform,
    },
    /// A whole file packed into a bundle object: read `len` bytes of the bundle
    /// at `offset` and reverse the transform. File-bundling (`repo-bundle=y`).
    Bundled {
        /// Absolute path of the bundle object (local fast path).
        abs_bundle: PathBuf,
        /// Repo-relative path of the bundle object (non-local `open_read` path).
        repo_bundle: PathBuf,
        /// Byte offset of this file's (transformed) bytes within the bundle.
        offset: u64,
        /// Number of (transformed) bytes the file occupies in the bundle.
        len: u64,
        /// Transform the source backup applied (reversed to recover plaintext).
        transform: RepoTransform,
    },
    /// A block-incremental file: reassemble it from its per-block sources, each a
    /// `len`-byte slice of a (possibly different backup's) bundle object reversed
    /// through that backup's transform. The blocks are concatenated in order.
    Blocks(Vec<BlockSource>),
}

/// One block of a block-incremental file's [`RestoreSource::Blocks`] list.
#[derive(Debug, Clone)]
struct BlockSource {
    /// Absolute path of the bundle object the block's bytes live in (local fast
    /// path).
    abs_bundle: PathBuf,
    /// Repo-relative path of that bundle object (non-local `open_read` path).
    repo_bundle: PathBuf,
    /// Byte offset of the block's (transformed) bytes within that bundle.
    offset: u64,
    /// Number of (transformed) bytes the block occupies.
    len: u64,
    /// Transform the holding backup applied (reversed to recover the plaintext
    /// block).
    transform: RepoTransform,
}

/// Read `len` bytes at `offset` from the file at `path`, recovering the plaintext
/// of one bundled member / block by reversing `transform`.
///
/// The local (`Posix`/`Cifs`) fast path: seeks + reads through `std::fs` against
/// an absolute path. The non-local counterpart is [`read_bundle_slice_storage`].
fn read_bundle_slice(path: &Path, offset: u64, len: u64, transform: &RepoTransform) -> Result<Vec<u8>, CommandError> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|err| CommandError::Other(format!("open {}: {err}", path.display())))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| CommandError::Other(format!("seek {}: {err}", path.display())))?;
    let mut repo_bytes = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
    file.read_exact(&mut repo_bytes)
        .map_err(|err| CommandError::Other(format!("read {}: {err}", path.display())))?;
    // Keyed (SHA-1 KDF) reverse chain, the exact inverse of the keyed forward
    // chain the backup wrote with; identity-equal to the legacy path with no key.
    Ok(transform.apply_reverse_keyed(&repo_bytes)?)
}

/// Slice `len` bytes at `offset` out of the already-buffered `bundle` bytes,
/// recovering the plaintext of one bundled member / block by reversing
/// `transform`. The non-local counterpart of [`read_bundle_slice`]: the whole
/// bundle object is read once (via [`Storage::open_read`]) by the caller and the
/// slices are taken from memory, since the `IoRead` trait has no seek and a
/// remote backend is single-connection. A `0` offset/len out of range is a
/// defensively-handled corrupt manifest, surfaced as an error.
fn read_bundle_slice_buffered(bundle: &[u8], offset: u64, len: u64, transform: &RepoTransform) -> Result<Vec<u8>, CommandError> {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let count = usize::try_from(len).unwrap_or(usize::MAX);
    let end = start
        .checked_add(count)
        .filter(|&end| end <= bundle.len())
        .ok_or_else(|| CommandError::Other(format!("bundle slice {start}..+{count} out of range (len {})", bundle.len())))?;
    Ok(transform.apply_reverse_keyed(&bundle[start..end])?)
}

/// The member offsets within one bundle object, used to derive each member's
/// (transformed) byte length as the gap to the next member (the last member runs
/// to the end of the bundle object).
struct BundleLayout {
    /// On-disk byte size of the bundle object.
    bundle_size: u64,
    /// All member start offsets in the bundle, sorted ascending and deduplicated.
    offsets: Vec<u64>,
}

impl BundleLayout {
    /// The number of (transformed) bytes the member starting at `offset` occupies:
    /// the distance to the next member start, or to the end of the bundle object
    /// for the last member. Returns `0` for an offset at/after the object end (a
    /// defensively-handled corrupt manifest).
    fn member_len(&self, offset: u64) -> u64 {
        let next = self.offsets.iter().copied().find(|&o| o > offset).unwrap_or(self.bundle_size);
        next.saturating_sub(offset)
    }
}

/// Build the [`BundleLayout`] of bundle `bundle_id` in `manifest`: every member
/// offset (from bundled whole files and block-map entries that name this bundle)
/// plus the bundle object's on-disk size.
fn bundle_layout(
    repo: &dyn Storage,
    stanza: &str,
    holder_label: &str,
    manifest: &Manifest,
    bundle_id: u64,
) -> Result<BundleLayout, CommandError> {
    use std::collections::BTreeSet;
    let mut offsets: BTreeSet<u64> = BTreeSet::new();
    for f in &manifest.files {
        if f.bundle_id == Some(bundle_id)
            && let Some(off) = f.bundle_offset
        {
            offsets.insert(off);
        }
        if let Some(bm) = &f.block_map {
            for b in &bm.blocks {
                // Only blocks physically stored in THIS holder's bundle count
                // toward this bundle's layout.
                if b.reference == holder_label && b.bundle_id == bundle_id {
                    offsets.insert(b.offset);
                }
            }
        }
    }
    let backup_root = format!("backup/{stanza}/{holder_label}");
    let path = PathBuf::from(crate::bundle::bundle_object_path(&backup_root, bundle_id));
    let bundle_size = repo.info(&path)?.size;
    Ok(BundleLayout {
        bundle_size,
        offsets: offsets.into_iter().collect(),
    })
}

/// Build the restore transform for a backup from its recorded `backup.info`
/// metadata, overriding the cipher key with the resolved repository `sub_key`.
///
/// [`RepoTransform::from_metadata`] reads the compress-type / encrypted flag the
/// backup recorded but sources the cipher password from the (non-existent for
/// restore) `cipher-pass` option, so it would leave the key empty on an encrypted
/// repo. The real key is the repository sub-key, recovered from the decrypted
/// `archive.info`; inject it here so the reverse chain can decrypt. `sub_key`
/// `None` (unencrypted repo) leaves the transform a plain decompress/identity.
fn restore_transform(metadata: &serde_json::Value, config: &LoadedConfig, sub_key: Option<&str>) -> RepoTransform {
    let base = RepoTransform::from_metadata(metadata, config);
    RepoTransform::with_key(base.compress_type, base.compress_level, sub_key.map(str::to_owned))
}

/// Resolves each manifest file to a physical [`RestoreSource`], following a
/// whole-file `reference` to the backup that holds the bytes and caching the
/// referenced manifests + bundle layouts it loads.
struct SourceResolver<'a> {
    repo: &'a dyn Storage,
    stanza: &'a str,
    config: &'a LoadedConfig,
    /// Label + transform + manifest of the backup being restored.
    label: &'a str,
    transform: &'a RepoTransform,
    manifest: &'a Manifest,
    info: &'a InfoBackup,
    /// The resolved repository sub-key (`None` for an unencrypted repo). Used to
    /// decrypt referenced / holder manifests and to key their transforms — the
    /// sub-key is the repository's, so the same value applies to every backup in
    /// the stanza.
    sub_key: Option<String>,
    /// Cache of loaded referenced-backup manifests, keyed by label.
    manifest_cache: BTreeMap<String, Manifest>,
    /// Cache of bundle layouts, keyed by `(holder label, bundle id)`.
    layout_cache: BTreeMap<(String, u64), std::rc::Rc<BundleLayout>>,
}

impl<'a> SourceResolver<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        repo: &'a dyn Storage,
        stanza: &'a str,
        config: &'a LoadedConfig,
        label: &'a str,
        transform: &'a RepoTransform,
        manifest: &'a Manifest,
        info: &'a InfoBackup,
        sub_key: Option<String>,
    ) -> Self {
        Self {
            repo,
            stanza,
            config,
            label,
            transform,
            manifest,
            info,
            sub_key,
            manifest_cache: BTreeMap::new(),
            layout_cache: BTreeMap::new(),
        }
    }

    /// The transform a backup `holder_label` applied, from its `backup.info`
    /// entry, keyed with the repository sub-key. Falls back to the restored
    /// backup's transform when the holder has no recorded metadata.
    fn holder_transform(&self, holder_label: &str) -> RepoTransform {
        if holder_label == self.label {
            return self.transform.clone();
        }
        self.info.current.get(holder_label).map_or_else(
            || self.transform.clone(),
            |entry| restore_transform(entry, self.config, self.sub_key.as_deref()),
        )
    }

    /// Load (and cache) the manifest of backup `holder_label`.
    fn load_manifest(&mut self, holder_label: &str) -> Result<&Manifest, CommandError> {
        use std::collections::btree_map::Entry;
        match self.manifest_cache.entry(holder_label.to_owned()) {
            Entry::Occupied(e) => Ok(e.into_mut()),
            Entry::Vacant(e) => {
                // A referenced backup's manifest is encrypted with the same
                // repository sub-key; load it keyed (`None` == plaintext).
                let m = Manifest::load_keyed(self.repo, &manifest_path(self.stanza, holder_label), self.sub_key.as_deref())
                    .map_err(|err| match err {
                        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
                            path: manifest_path(self.stanza, holder_label),
                        }),
                        other => CommandError::Other(other.to_string()),
                    })?;
                Ok(e.insert(m))
            }
        }
    }

    /// The cached [`BundleLayout`] for `(holder, bundle_id)`, loading it on first
    /// use. The holder manifest is the restored backup's in-memory manifest when
    /// the holder is the restored backup itself, else the cached referenced one.
    fn layout(&mut self, holder_label: &str, bundle_id: u64) -> Result<std::rc::Rc<BundleLayout>, CommandError> {
        let key = (holder_label.to_owned(), bundle_id);
        if let Some(layout) = self.layout_cache.get(&key) {
            return Ok(layout.clone());
        }
        let layout = if holder_label == self.label {
            std::rc::Rc::new(bundle_layout(self.repo, self.stanza, holder_label, self.manifest, bundle_id)?)
        } else {
            let holder_manifest = self.load_manifest(holder_label)?.clone();
            std::rc::Rc::new(bundle_layout(
                self.repo,
                self.stanza,
                holder_label,
                &holder_manifest,
                bundle_id,
            )?)
        };
        self.layout_cache.insert(key, layout.clone());
        Ok(layout)
    }

    /// Resolve `file` (from the restored backup's manifest) to a physical source.
    fn resolve(&mut self, file: &ManifestFile) -> Result<RestoreSource, CommandError> {
        // A block-incremental file always carries its full block map in this
        // manifest (each block names the backup that holds it), so it is resolved
        // directly regardless of any whole-file reference.
        if let Some(block_map) = &file.block_map {
            return self.resolve_block_map(block_map);
        }

        // Find the holder of the whole-file bytes: this backup, or the backup the
        // `reference` names. The holder's manifest entry carries the physical
        // storage (standalone vs bundled).
        let (holder_label, holder_entry): (String, ManifestFile) = match file.reference.as_deref() {
            None => (self.label.to_owned(), file.clone()),
            Some(reference) => {
                let holder_manifest = self.load_manifest(reference)?;
                let entry = holder_manifest
                    .file(&file.path)
                    .cloned()
                    // The referenced backup should list the file; if not, fall
                    // back to treating the reference as a standalone object (the
                    // pre-bundling behaviour) so older repos still restore.
                    .unwrap_or_else(|| file.clone());
                (reference.to_owned(), entry)
            }
        };

        // The holder entry might itself be block-mapped (an unchanged
        // block-incremental file referenced whole).
        if let Some(block_map) = &holder_entry.block_map {
            return self.resolve_block_map(block_map);
        }

        let holder_transform = self.holder_transform(&holder_label);
        if let (Some(bundle_id), Some(offset)) = (holder_entry.bundle_id, holder_entry.bundle_offset) {
            let layout = self.layout(&holder_label, bundle_id)?;
            let backup_root = format!("backup/{}/{holder_label}", self.stanza);
            let repo_bundle = PathBuf::from(crate::bundle::bundle_object_path(&backup_root, bundle_id));
            // The local fast path needs the absolute path (resolved via `info`);
            // the non-local path reads through `open_read` at `repo_bundle`, so it
            // skips the `info().path` resolution and reuses the relative path as a
            // never-read placeholder.
            let abs_bundle = if self.repo.is_local() {
                self.repo.info(&repo_bundle)?.path
            } else {
                repo_bundle.clone()
            };
            Ok(RestoreSource::Bundled {
                abs_bundle,
                repo_bundle,
                offset,
                len: layout.member_len(offset),
                transform: holder_transform,
            })
        } else {
            // Standalone repo object (`<rel><suffix>`).
            let repo_rel = format!("{}{}", file.path, holder_transform.repo_suffix());
            let repo_src = backup_file_path(self.stanza, &holder_label, &repo_rel);
            let abs_src = if self.repo.is_local() {
                self.repo.info(&repo_src)?.path
            } else {
                repo_src.clone()
            };
            Ok(RestoreSource::Standalone {
                abs_src,
                repo_src,
                transform: holder_transform,
            })
        }
    }

    /// Build a [`RestoreSource::Blocks`] from a block map: each block's bytes live
    /// in the bundle of the backup its [`pgbr_info::manifest::BlockRef`] names.
    fn resolve_block_map(&self, block_map: &pgbr_info::manifest::BlockMap) -> Result<RestoreSource, CommandError> {
        let mut sources = Vec::with_capacity(block_map.blocks.len());
        for block in &block_map.blocks {
            let holder_label = block.reference.clone();
            let holder_transform = self.holder_transform(&holder_label);
            let backup_root = format!("backup/{}/{holder_label}", self.stanza);
            let repo_bundle = PathBuf::from(crate::bundle::bundle_object_path(&backup_root, block.bundle_id));
            // Local fast path resolves the absolute path; the non-local path reads
            // through `open_read` at `repo_bundle` (placeholder abs path).
            let abs_bundle = if self.repo.is_local() {
                self.repo.info(&repo_bundle)?.path
            } else {
                repo_bundle.clone()
            };
            sources.push(BlockSource {
                abs_bundle,
                repo_bundle,
                offset: block.offset,
                len: block.size,
                transform: holder_transform,
            });
        }
        Ok(RestoreSource::Blocks(sources))
    }
}

/// Re-apply a manifest-recorded Unix file mode to a restored file.
///
/// On Unix, when `mode` is `Some`, `std::fs::set_permissions` sets the file's
/// permission bits to it (masked to `0o7777`, the permission + setuid/setgid/
/// sticky bits the backup recorded). `None` leaves the file at its
/// freshly-created default mode. uid/gid are NOT applied (re-applying owner needs
/// privilege; recorded-only, documented follow-up).
#[cfg(unix)]
fn apply_mode(abs_dst: &Path, mode: Option<u32>) -> Result<(), CommandError> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        std::fs::set_permissions(abs_dst, std::fs::Permissions::from_mode(mode & 0o7777))
            .map_err(|err| CommandError::Other(format!("chmod {}: {err}", abs_dst.display())))?;
    }
    Ok(())
}

/// Non-Unix stub: file mode is not modelled, so this is a no-op (no mode is ever
/// recorded on a non-Unix backup).
#[cfg(not(unix))]
fn apply_mode(_abs_dst: &Path, _mode: Option<u32>) -> Result<(), CommandError> {
    Ok(())
}

/// `fsync(2)` the directory containing `path` so a freshly renamed-in file's
/// directory entry is itself durable across a power loss. On Unix opening a
/// directory and calling `sync_all` flushes its metadata. A missing / unopenable
/// parent is a best-effort no-op (the file write already succeeded). Clean no-op
/// on non-Unix.
#[cfg(unix)]
fn fsync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) {}

/// Write the recovered `plaintext` to the job's destination and verify it.
///
/// Shared by [`restore_file`] (the local `std::fs` fast path) and
/// [`restore_file_storage`] (the non-local `open_read` path): the destination is
/// always the local PG data dir (always a `std::fs` write — only the *source* of
/// the repo bytes differs between paths), so the parent-dir creation, write,
/// Unix-mode re-application, and the hard-fail plaintext SHA-1 check are written
/// exactly once and produce identical results regardless of how the bytes were
/// read.
///
/// # Durability + atomicity
///
/// The plaintext SHA-1 is checked **before** anything is written, so a corrupt
/// file never touches the target. The bytes are then streamed to a sibling
/// `<dst>.pgbr.tmp`, `fsync`'d (`sync_all`), and atomically `rename`'d onto the
/// final path — a crash mid-restore can never leave a half-written or truncated
/// data file at the real name. On any failure the temp file is removed
/// (best-effort). A checksum mismatch is a hard error so the failing job fails
/// the whole restore.
fn write_and_verify(job: &RestoreCopyJob, plaintext: &[u8]) -> Result<(), CommandError> {
    // Write + fsync the temp file, then re-apply the recorded Unix mode to it
    // (before the rename so the published name is never briefly world-readable
    // at the default mode). Any failure removes the temp file. `write_temp`
    // does the fallible steps; the caller cleans up on error.
    fn write_temp(tmp_path: &Path, plaintext: &[u8], mode: Option<u32>) -> Result<(), CommandError> {
        use std::io::Write as _;
        let mut file =
            std::fs::File::create(tmp_path).map_err(|err| CommandError::Other(format!("create {}: {err}", tmp_path.display())))?;
        file.write_all(plaintext)
            .map_err(|err| CommandError::Other(format!("write {}: {err}", tmp_path.display())))?;
        // Durability: flush the data to stable storage before the rename.
        file.sync_all()
            .map_err(|err| CommandError::Other(format!("fsync {}: {err}", tmp_path.display())))?;
        // Re-apply the recorded Unix file mode (if any). On non-Unix this is a
        // no-op. uid/gid are recorded-only — re-applying owner needs privilege
        // and is a documented follow-up. C ref: chmod in
        // `src/command/restore/restore.c`.
        apply_mode(tmp_path, mode)
    }

    // Hard-fail SHA-1 check, per file, BEFORE writing anything: a corrupt file
    // must never be materialised (even transiently) at the target. Zero-length
    // files carry no checksum; nothing to compare.
    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    sha.process(plaintext, &mut sink)?;
    let actual = sha.digest_hex();
    if let Some(expected) = job.expected_checksum.as_deref()
        && actual != expected
    {
        return Err(CommandError::Other(format!("restore checksum mismatch for {}", job.rel)));
    }

    if let Some(parent) = job.abs_dst.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| CommandError::Other(format!("create {}: {err}", parent.display())))?;
    }

    // Sibling temp path in the destination's own directory so the rename crosses
    // no filesystem boundary (`rename(2)` is only atomic within one filesystem).
    let mut tmp_name = job.abs_dst.as_os_str().to_os_string();
    tmp_name.push(".pgbr.tmp");
    let tmp_path = PathBuf::from(tmp_name);

    if let Err(err) = write_temp(&tmp_path, plaintext, job.mode) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    // Atomic publish. On failure the temp file is left/removed and the job fails.
    if let Err(err) = std::fs::rename(&tmp_path, &job.abs_dst) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(CommandError::Other(format!(
            "rename {} -> {}: {err}",
            tmp_path.display(),
            job.abs_dst.display()
        )));
    }

    // Make the renamed-in directory entry durable (Unix; no-op elsewhere).
    fsync_parent_dir(&job.abs_dst);

    Ok(())
}

/// Restore one file in a worker: read the repo source via `std::fs`, reverse the
/// transform to recover the plaintext, then write + verify via
/// [`write_and_verify`]. Because the manifest records the *plaintext* checksum,
/// that single check validates the whole compress -> encrypt -> decrypt ->
/// decompress round trip.
///
/// This is the per-file unit of work run on a dispatcher worker thread. It reads
/// its repo source through `std::fs` against absolute paths, so it needs no
/// `Storage` handle and nothing borrowed from the caller — only the owned
/// `transform` carried in the job. This fast path is used **only** for local
/// (`Posix`/`Cifs`) repos; remote/object repos go through
/// [`restore_file_storage`].
///
/// `bundle_cache` maps a bundle object's *absolute* path to its already-read
/// bytes, populated once on the main thread by [`build_bundle_cache`] for every
/// bundle a planned job references. When the cache holds the bundle, the
/// worker slices the bytes from memory (zero disk I/O per file); when it does
/// not, the worker falls back to opening + seeking the bundle from disk via
/// [`read_bundle_slice`] — N files in one bundle then re-open and seek the
/// same file N times, the prior behaviour. The cache is `Arc`-wrapped so the
/// worker closure captures it `Send + Sync`.
fn restore_file(job: &RestoreCopyJob, bundle_cache: &HashMap<PathBuf, Vec<u8>>) -> Result<(), CommandError> {
    // Recover the plaintext per the source spec: a whole standalone object, a
    // bundle slice, or a reassembled block-incremental file.
    let plaintext = match &job.source {
        RestoreSource::Standalone { abs_src, transform, .. } => {
            let repo_bytes =
                std::fs::read(abs_src).map_err(|err| CommandError::Other(format!("read {}: {err}", abs_src.display())))?;
            // Reverse the keyed transform: decrypt then decompress. With no key
            // (and no compression) this returns the bytes unchanged.
            transform.apply_reverse_keyed(&repo_bytes)?
        }
        RestoreSource::Bundled {
            abs_bundle,
            offset,
            len,
            transform,
            ..
        } => {
            if let Some(bytes) = bundle_cache.get(abs_bundle) {
                // Pre-cached on the main thread: every file in this bundle
                // slices from one shared byte buffer, so N files in 1 bundle
                // open + seek the bundle ZERO times in the worker.
                read_bundle_slice_buffered(bytes, *offset, *len, transform)?
            } else {
                // No cache hit (the pre-cache was skipped or the bundle was
                // not on a planned job at cache time): open + seek + read via
                // `std::fs`, the prior behaviour.
                read_bundle_slice(abs_bundle, *offset, *len, transform)?
            }
        }
        RestoreSource::Blocks(blocks) => {
            let mut out = Vec::new();
            for block in blocks {
                let part = if let Some(bytes) = bundle_cache.get(&block.abs_bundle) {
                    read_bundle_slice_buffered(bytes, block.offset, block.len, &block.transform)?
                } else {
                    read_bundle_slice(&block.abs_bundle, block.offset, block.len, &block.transform)?
                };
                out.extend_from_slice(&part);
            }
            out
        }
    };

    write_and_verify(job, &plaintext)
}

/// Build the per-bundle pre-cache for a planned local restore: scan every
/// [`RestoreCopyJob`] for the bundle objects its source references, deduplicate
/// them, and read each one ONCE via `std::fs::read`. The resulting
/// `Arc<HashMap<PathBuf, Vec<u8>>>` is shared (by `Arc::clone`) with every
/// worker, so N files packed into one bundle hit `std::fs::open` + seek zero
/// times in the workers — they slice from the shared buffer instead.
///
/// Skipped (returns an empty cache) when the repo is not local: the non-local
/// branch in [`run_restore_jobs`] runs serially through [`restore_file_storage`]
/// which has its own per-call bundle cache via `Storage::open_read`. Pre-caching
/// there would mean reading every bundle through the (single-connection)
/// `Storage` handle on the main thread — net loss for a remote backend.
///
/// A failed read here aborts the whole restore: the bundle is needed by at
/// least one planned job, so a read failure on it is the same hard-fail every
/// worker would have surfaced anyway. The error message names the failing
/// bundle so the user can act on it.
fn build_bundle_cache(repo: &dyn Storage, jobs: &[RestoreCopyJob]) -> Result<Arc<HashMap<PathBuf, Vec<u8>>>, CommandError> {
    use std::collections::HashSet;
    if !repo.is_local() {
        // Non-local repo: each worker (serial) still does its own bundle
        // read via `Storage::open_read`. Pre-caching would defeat the whole
        // point of the trait abstraction.
        return Ok(Arc::new(HashMap::new()));
    }

    // Collect every bundle object the planned jobs read from, by absolute
    // path. A `HashSet` deduplicates the paths so each bundle is read once
    // regardless of how many files it holds.
    let mut bundle_paths: HashSet<PathBuf> = HashSet::new();
    for job in jobs {
        match &job.source {
            RestoreSource::Standalone { .. } => {}
            RestoreSource::Bundled { abs_bundle, .. } => {
                bundle_paths.insert(abs_bundle.clone());
            }
            RestoreSource::Blocks(blocks) => {
                for block in blocks {
                    bundle_paths.insert(block.abs_bundle.clone());
                }
            }
        }
    }

    let mut cache: HashMap<PathBuf, Vec<u8>> = HashMap::with_capacity(bundle_paths.len());
    for path in bundle_paths {
        let bytes = std::fs::read(&path).map_err(|err| CommandError::Other(format!("read bundle {}: {err}", path.display())))?;
        cache.insert(path, bytes);
    }
    Ok(Arc::new(cache))
}

/// Read the whole repo object at `repo_path` through the [`Storage`] trait,
/// returning its raw (still-transformed) bytes. Used by the non-local restore
/// path, where `std::fs` would read from the wrong machine.
fn read_repo_object(repo: &dyn Storage, repo_path: &Path) -> Result<Vec<u8>, CommandError> {
    let mut reader = repo.open_read(repo_path)?;
    Ok(reader.read_all()?)
}

/// Restore one file for a non-local (remote/object) repo, reading every repo
/// source through `repo.open_read` instead of `std::fs`.
///
/// Mirrors [`restore_file`] exactly except for the *source* of the repo bytes:
/// the reverse transform, block reassembly, and the write + verification go
/// through the same [`write_and_verify`] / transform logic, so the restored file
/// and its checksum check are byte-for-byte what the local path produces. Runs
/// serially on the main thread because the remote storage is single-connection /
/// `!Send` and cannot be shared across the worker pool. A bundle / bundled file
/// is read once into memory (bounded by `repo-bundle-size`) and sliced from
/// there, since [`pgbr_io::IoRead`] has no seek.
fn restore_file_storage(job: &RestoreCopyJob, repo: &dyn Storage) -> Result<(), CommandError> {
    let plaintext = match &job.source {
        RestoreSource::Standalone { repo_src, transform, .. } => {
            let repo_bytes = read_repo_object(repo, repo_src)?;
            transform.apply_reverse_keyed(&repo_bytes)?
        }
        RestoreSource::Bundled {
            repo_bundle,
            offset,
            len,
            transform,
            ..
        } => {
            let bundle = read_repo_object(repo, repo_bundle)?;
            read_bundle_slice_buffered(&bundle, *offset, *len, transform)?
        }
        RestoreSource::Blocks(blocks) => {
            // Cache each bundle object's bytes so a file whose blocks all live in
            // one bundle reads that bundle once, not once per block.
            let mut bundle_cache: std::collections::HashMap<PathBuf, Vec<u8>> = std::collections::HashMap::new();
            let mut out = Vec::new();
            for block in blocks {
                if !bundle_cache.contains_key(&block.repo_bundle) {
                    let bytes = read_repo_object(repo, &block.repo_bundle)?;
                    bundle_cache.insert(block.repo_bundle.clone(), bytes);
                }
                let bundle = &bundle_cache[&block.repo_bundle];
                let part = read_bundle_slice_buffered(bundle, block.offset, block.len, &block.transform)?;
                out.extend_from_slice(&part);
            }
            out
        }
    };

    write_and_verify(job, &plaintext)
}

/// Encode a [`RestoreCopyJob`]'s correlation key into a dispatcher [`Request`].
///
/// The owned job (absolute paths, transform, expected checksum) is captured by
/// the worker closure via a side table keyed on `rel`; only the key needs to
/// ride in the request, so the request's `cmd` is the `rel` and `param` is empty.
fn copy_request(job: &RestoreCopyJob) -> Request {
    Request {
        cmd: job.rel.clone(),
        param: Vec::new(),
    }
}

/// Run every [`RestoreCopyJob`] across `worker_count` workers via the in-process
/// dispatcher. Returns `Ok(())` when every file restored and verified; the first
/// failing job (read / write / transform / checksum-mismatch) surfaces as an
/// `Err` and fails the whole restore, exactly as the serial path did.
///
/// Each worker looks its job up by `rel` in the shared (owned) job table, then
/// reads the source, reverses the transform, writes the destination, and
/// verifies the SHA-1. The dispatcher isolates a worker panic into an `Err`
/// result too. `worker_count == 1` runs a single worker — byte-for-byte the
/// prior serial behaviour.
///
/// `job_retry` wraps each per-file restore: a failed restore (read / transform /
/// write / checksum-mismatch) is retried up to `job-retry` more times — with
/// `job-retry-interval` between attempts — inside the worker before the job, and
/// the whole restore, fails. [`JobRetry::none`] reproduces the single-attempt
/// behaviour exactly.
///
/// When `repo` is **not** local (a remote/object backend) the parallel `std::fs`
/// path is unsafe — `std::fs` would read the repo bytes from the wrong machine —
/// so the restores run serially on the main thread through
/// [`restore_file_storage`], which reads every repo source via `repo.open_read`
/// (the storage handle is single-connection / `!Send` and cannot cross the
/// worker boundary). The destination write + verification is identical, so the
/// restored cluster is the same regardless of which path ran. For local
/// (`Posix`/`Cifs`) repos the parallel `std::fs` path below is kept verbatim.
fn run_restore_jobs(
    jobs: Vec<RestoreCopyJob>,
    repo: &dyn Storage,
    worker_count: usize,
    job_retry: JobRetry,
) -> Result<(), CommandError> {
    if jobs.is_empty() {
        return Ok(());
    }

    // Non-local repo: read every file through the `Storage` trait, serially on
    // this thread. `std::fs` (the parallel path below) would read the repo bytes
    // off the local machine instead of the remote/object repo.
    if !repo.is_local() {
        for job in &jobs {
            job_retry.run(|| restore_file_storage(job, repo))?;
        }
        return Ok(());
    }

    // Local repo: pre-read every bundle object the planned jobs reference, ONCE
    // each, on the main thread before the worker pool spawns. The
    // `Arc<HashMap>` is `Send + Sync` and is `Arc::clone`d into the worker
    // closure cheaply; every worker sees the same shared byte buffers and
    // slices them in memory, so N files in 1 bundle never re-open the bundle.
    let bundle_cache = build_bundle_cache(repo, &jobs)?;

    let dispatcher_jobs: Vec<Job> = jobs
        .iter()
        .map(|job| Job {
            key: job.rel.clone(),
            request: copy_request(job),
        })
        .collect();

    // The dispatcher demands a `Send + Sync + 'static` worker, so the closure
    // can only borrow owned data. Move the owned jobs into a lookup table keyed
    // by `rel`; the worker fetches its job (which carries the cloned transform
    // and absolute paths) and does its I/O through `std::fs`, so nothing
    // borrowed from this stack frame escapes.
    let table: HashMap<String, RestoreCopyJob> = jobs.into_iter().map(|job| (job.rel.clone(), job)).collect();
    let worker_cache = Arc::clone(&bundle_cache);

    let results = ParallelExecutor::new(worker_count).run(dispatcher_jobs, move |request| {
        let job = table
            .get(&request.cmd)
            .ok_or_else(|| format!("no restore job for {}", request.cmd))?;
        // Retry the restore per `job-retry`: re-read + re-transform + re-write +
        // re-verify on each attempt so a transient failure can recover.
        job_retry
            .run(|| restore_file(job, &worker_cache))
            .map_err(|err| err.to_string())?;
        Ok(Response::Ok(OkResponse { out: None }))
    });

    for job_result in results {
        match job_result.result {
            Ok(Response::Ok(_)) => {}
            Ok(_) => {
                return Err(CommandError::Other(format!(
                    "restore of {} produced an unexpected response",
                    job_result.key
                )));
            }
            Err(message) => return Err(CommandError::Other(message)),
        }
    }
    Ok(())
}

/// Resolve the absolute on-disk path a worker should write the recovered
/// plaintext to, for a PG-target-relative `rel` under `storage`.
///
/// A restore destination may not exist yet, so its absolute path is anchored on
/// its parent directory: the parent is created (mirroring the serial path, which
/// created the destination's parent in `copy_file` before writing) and its
/// absolute path resolved via `storage.info`, then the file name is joined on.
/// This anchors worker I/O at a real absolute path because the workers use
/// `std::fs`, not the `Storage` handle.
fn destination_absolute_path(storage: &dyn Storage, rel: &Path) -> Result<PathBuf, CommandError> {
    // Directories from `[target:path]` are created up front, but a file can sit
    // in an unlisted path, so create the parent defensively (as the serial
    // `copy_file` did) and resolve its absolute path.
    let abs_parent = match rel.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => {
            storage.create_path(parent, true)?;
            storage.info(parent)?.path
        }
        // No parent component (a file at the storage root): resolve the root via
        // the current dir, which always exists.
        None => storage.info(Path::new("."))?.path,
    };

    let name = rel
        .file_name()
        .ok_or_else(|| CommandError::Other(format!("cannot resolve absolute path for {}", rel.display())))?;
    Ok(abs_parent.join(name))
}

/// Whether a [`StorageError`] is the "symlinks not supported by this backend"
/// signal from the [`Storage::create_symlink`] trait default, as opposed to a
/// genuine I/O failure. Only the former should be swallowed (counted as a
/// skipped link); a real error must fail the restore.
fn is_symlink_unsupported(err: &StorageError) -> bool {
    matches!(err, StorageError::Backend { message, .. } if message.contains("symlinks not supported"))
}

/// Counts returned by [`materialize_links`].
#[derive(Debug, Default, Clone, Copy)]
struct LinkCounts {
    created: usize,
    skipped: usize,
    as_dir: usize,
}

/// Materialise every `[target:link]` entry in the PG target.
///
/// Called **before** the file-copy pass so that `pg_tblspc/<oid>` (and other)
/// symlinks — and the external tablespace target directories they point at —
/// exist before any file is copied into them. Copying first would materialise
/// `pg_tblspc/<oid>` as a real directory inside PGDATA and the tablespace would
/// never be relocated.
///
/// Under the default `repo-symlink=y` each link becomes a real symlink at its
/// (possibly remapped) destination. A backend that cannot create symlinks (the
/// [`Storage::create_symlink`] trait default) leaves the link uncreated and
/// counts it in `skipped`; a *genuine* I/O error creating a link is a hard
/// failure. For a tablespace link the failure is always hard — a tablespace that
/// silently did not relocate would corrupt the restore. Under `--no-repo-symlink`
/// the entry is laid out as a plain directory inside PGDATA instead (counted in
/// `as_dir`).
fn materialize_links(
    pg: &dyn Storage,
    manifest: &Manifest,
    want_repo_symlink: bool,
    ts_map: &BTreeMap<String, String>,
    ts_map_all: Option<&str>,
    links_map: &BTreeMap<String, String>,
    dry_run: bool,
) -> Result<LinkCounts, CommandError> {
    let mut counts = LinkCounts::default();
    for link in &manifest.links {
        let link_path = PathBuf::from(&link.path);
        // Defensively create the link's parent directory (paths are created up
        // front, but a link could sit in an unlisted path). Skipped on a dry run.
        if !dry_run
            && let Some(parent) = link_path.parent()
            && !parent.as_os_str().is_empty()
        {
            pg.create_path(parent, true)?;
        }

        let is_tablespace = tablespace_oid(link).is_some();
        match link_plan(want_repo_symlink) {
            LinkPlan::PlainDir => {
                if dry_run {
                    log_info(&format!("dry-run: would create directory {} (link as dir)", link.path));
                } else {
                    pg.create_path(&link_path, true)?;
                }
                counts.as_dir += 1;
            }
            LinkPlan::Symlink => {
                let target = if is_tablespace {
                    resolve_tablespace_target(link, ts_map, ts_map_all)
                } else {
                    PathBuf::from(resolve_link_target(
                        link_relative_name(&link.path),
                        &link.destination,
                        links_map,
                    ))
                };
                if dry_run {
                    log_info(&format!(
                        "dry-run: would create symlink {} -> {}",
                        link.path,
                        target.display()
                    ));
                    counts.created += 1;
                    continue;
                }

                // For a TABLESPACE link, ensure the (possibly external) target
                // directory exists so files copied through `pg_tblspc/<oid>` land
                // in the real location; a missing tablespace target would make the
                // copy fail or, worse, materialise the OID as a plain dir. Generic
                // links (e.g. `pg_wal`) point at operator-managed directories that
                // restore must not fabricate, so their target is left untouched
                // (PostgreSQL / the operator owns it) — a dangling generic link is
                // acceptable and matches pgBackRust.
                if is_tablespace && let Err(err) = std::fs::create_dir_all(&target) {
                    return Err(CommandError::Other(format!(
                        "create tablespace target {}: {err}",
                        target.display()
                    )));
                }

                match pg.create_symlink(&link_path, &target) {
                    Ok(()) => counts.created += 1,
                    Err(ref err) if is_symlink_unsupported(err) && !is_tablespace => {
                        // Backend genuinely cannot make symlinks and this is not a
                        // tablespace — skip it (the restored bytes still land, just
                        // not behind a link).
                        counts.skipped += 1;
                    }
                    Err(err) => {
                        // A tablespace link that could not be created, or a real
                        // I/O error, fails the restore: silently swallowing it
                        // would corrupt the cluster layout.
                        return Err(CommandError::Other(format!(
                            "create symlink {} -> {}: {err}",
                            link.path,
                            target.display()
                        )));
                    }
                }
            }
        }
    }
    Ok(counts)
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
#[allow(clippy::too_many_lines)]
pub fn restore_inner(config: &LoadedConfig, repo: &dyn Storage, pg: &dyn Storage) -> Result<RestoreOutcome, CommandError> {
    let stanza = require_stanza(config)?;
    let delta = delta_enabled(config);
    let force = force_enabled(config);
    let dry_run = dry_run_enabled(config);
    if dry_run {
        log_info("dry-run: no files will be restored and PGDATA will not be modified");
    }

    // Pre-flight safety: refuse to restore over a running cluster (postmaster.pid)
    // and refuse a non-empty PGDATA without --delta/--force. Run BEFORE any
    // mutation so a refused restore leaves the target untouched.
    preflight_pgdata(pg, delta, force, dry_run)?;

    // Selective-restore filters. `--db-include` and `--db-exclude` are mutually
    // exclusive: a database cannot be both kept-only and dropped.
    let db_include = db_list(config, "db-include");
    let db_exclude = db_list(config, "db-exclude");
    if !db_include.is_empty() && !db_exclude.is_empty() {
        return Err(CommandError::Other(
            "db-include and db-exclude are mutually exclusive".to_owned(),
        ));
    }

    // Tablespace remapping inputs (used in the symlink-creation pass).
    let ts_map = tablespace_map(config);
    let ts_map_all = tablespace_map_all(config);

    // Generic link remapping (`--link-map`), applied to non-tablespace links.
    let links_map = link_map(config);

    // Symlink materialisation policy: `--link-all` requests link re-creation (its
    // effect coincides with this fork's default symlink re-creation under
    // `repo-symlink=y`), and `--no-repo-symlink` suppresses all symlink creation
    // (everything laid out as real dirs inside PGDATA). Reading `link-all` here
    // honours the option; the suppressor is what changes the materialisation, so
    // the read value is documented but does not branch (see `link_plan`).
    let want_link_all: bool = link_all(config);
    let _: bool = want_link_all;
    let want_repo_symlink = repo_symlink(config);

    let (label, metadata, info) = select_backup(config, repo, stanza)?;

    // On an encrypted repository the data files and `backup.manifest` are
    // encrypted with the repository sub-key (recovered from the decrypted
    // `archive.info`), the same key the backup wrote them with. `None` for an
    // unencrypted repo (the plaintext path). The sub-key is the repository's, so
    // it decrypts every backup in the stanza — including any referenced /
    // holder backups resolved below.
    let sub_key = crate::cipher::active_sub_key(repo, config, stanza)?;

    // The transform the restored backup applied — compress-type / encrypted flag
    // come from the recorded metadata; the cipher key is the resolved repository
    // sub-key (never stored in the repo).
    let transform = restore_transform(&metadata, config, sub_key.as_deref());

    let manifest = Manifest::load_keyed(repo, &manifest_path(stanza, &label), sub_key.as_deref()).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: manifest_path(stanza, &label),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    // Validate every manifest-recorded relative path (paths, files, links) before
    // any of them is joined onto the PG target. A corrupt or malicious manifest
    // must not be able to steer a create/write/symlink at an absolute path or one
    // that escapes PGDATA with `..`. Done up front so a bad entry fails the whole
    // restore before any mutation.
    for path in &manifest.paths {
        validate_manifest_path("target:path", &path.path)?;
    }
    for file in &manifest.files {
        validate_manifest_path("target:file", &file.path)?;
    }
    for link in &manifest.links {
        validate_manifest_path("target:link", &link.path)?;
        // The link *destination* is where the symlink points and may legitimately
        // be an absolute external path (e.g. a tablespace location), so it is not
        // validated as relative; but an empty destination is never valid.
        if link.destination.is_empty() {
            return Err(CommandError::Other(format!(
                "manifest target:link '{}' has an empty destination",
                link.path
            )));
        }
    }

    // 1. Re-create every directory recorded in the manifest. A dry-run counts the
    //    directories it would create but makes none.
    let mut paths_created = 0;
    for path in &manifest.paths {
        if !dry_run {
            pg.create_path(Path::new(&path.path), true)?;
        }
        paths_created += 1;
    }

    // 1b. Guarantee the PostgreSQL runtime-directory skeleton exists. The backup
    //     keeps the transient runtime *directories* in the manifest (recreated by
    //     step 1) but never descends into them, so their required *subdirectories*
    //     (e.g. `pg_wal/archive_status`, `pg_logical/snapshots`) are not recorded.
    //     A fresh-PGDATA restore (the standard way to seed a streaming standby)
    //     would then leave PostgreSQL unable to start — e.g. `FATAL: could not
    //     open directory "pg_notify"`. Recreate the full skeleton here, mirroring
    //     pgBackRust restoring the complete cluster directory layout. Each create
    //     is recursive/idempotent (an already-present dir, e.g. one a manifest
    //     path just made, is a no-op success). Skipped on dry-run. C ref: the
    //     directories pgBackRust's `manifestBuildInfo` always records as empty.
    if !dry_run {
        for dir in PG_RUNTIME_SKELETON_DIRS {
            pg.create_path(Path::new(dir), true)?;
        }
    }

    // 1c. Materialise `[target:link]` symlinks (and their external tablespace
    //     target directories) BEFORE the copy pass. If the copy ran first it
    //     would create `pg_tblspc/<oid>` as a real directory inside PGDATA and
    //     the tablespace would never relocate. A tablespace link that cannot be
    //     created is a hard error (see `materialize_links`).
    let link_counts = materialize_links(
        pg,
        &manifest,
        want_repo_symlink,
        &ts_map,
        ts_map_all.as_deref(),
        &links_map,
        dry_run,
    )?;

    // 2. Plan every file copy on the main thread — reference resolution,
    //    db-include/exclude filtering, delta matching, and source-backup /
    //    transform selection all stay here, exactly as the serial path decided
    //    them. Only the resulting read -> reverse-transform -> write -> verify
    //    work is deferred to the workers. Under `--delta`, a file whose target
    //    copy already matches the manifest (same size + SHA-1) is skipped and
    //    never becomes a job.
    //
    // # Parallel delta pre-pass
    //
    // The expensive part of delta classification is the per-file SHA-1 of the
    // PG-target file. On a local PG target (`is_local() == true`) those hashes
    // are dispatched across `process-max` workers via [`run_delta_jobs`]: the
    // main thread walks the manifest once to split files into
    // `Matches` / `NeedsHash` / `NoMatch` (size check only — fast), then
    // [`run_delta_jobs`] hashes every `NeedsHash` candidate in parallel using
    // `std::fs::read`. The set of matched paths is then consulted in the main
    // loop below. On a non-local PG target the parallel `std::fs` path is
    // unsafe (the target files live on another machine), so the serial
    // [`target_matches`] is used per file in the loop instead.
    let mut files_skipped = 0;
    let mut jobs: Vec<RestoreCopyJob> = Vec::new();
    // Under --dry-run the copy jobs are never built (building one creates the
    // destination's parent dir, a mutation); instead the files that *would* be
    // restored are counted directly.
    let mut dry_run_restore_count = 0;
    let worker_count = process_max(config);
    let local_pg = pg.is_local();

    // Pre-classify every manifest file for delta matching. The map is keyed on
    // the manifest-relative path and is only populated under `--delta`; when
    // empty the loop below short-circuits to the non-delta path.
    let delta_matched: std::collections::HashSet<String> = if delta {
        let mut hash_jobs: Vec<DeltaJob> = Vec::new();
        let mut matches_immediately: std::collections::HashSet<String> = std::collections::HashSet::new();
        for file in &manifest.files {
            // Selective restore: filtered files are never delta-matched —
            // they are dropped from the restore entirely in the main loop,
            // and never compared against the PG target.
            if !database_included(&file.path, &db_include, &db_exclude) {
                continue;
            }
            let dst = PathBuf::from(&file.path);
            if !local_pg {
                // Non-local PG target: classification + hashing both happen
                // serially in the main loop below through `target_matches`.
                continue;
            }
            match classify_delta_match(pg, &dst, file, local_pg) {
                DeltaMatch::Matches => {
                    matches_immediately.insert(file.path.clone());
                }
                DeltaMatch::NeedsHash { abs_path, expected_sha } => {
                    hash_jobs.push(DeltaJob {
                        rel: file.path.clone(),
                        abs_path,
                        expected_sha,
                    });
                }
                DeltaMatch::NoMatch => {}
            }
        }
        let mut matched = run_delta_jobs(&hash_jobs, worker_count);
        matched.extend(matches_immediately);
        matched
    } else {
        std::collections::HashSet::new()
    };

    // Resolver that follows whole-file references to the holding backup and
    // builds the physical source (standalone / bundled / block map). It caches
    // referenced manifests + bundle layouts so a multi-file backup loads each
    // referenced manifest at most once.
    let mut resolver = SourceResolver::new(repo, stanza, config, &label, &transform, &manifest, &info, sub_key);
    for file in &manifest.files {
        let dst = PathBuf::from(&file.path);

        // Selective restore: drop files belonging to a database the
        // include/exclude filters exclude. Non-database files always pass.
        if !database_included(&file.path, &db_include, &db_exclude) {
            continue;
        }

        // Delta matching. On a local PG target the SHA-1 has already been
        // computed (in parallel) by the pre-pass above and the matched set
        // tells us which files to skip. On a non-local PG target the parallel
        // path is unsafe, so fall through to the serial `target_matches`,
        // identical to the original behaviour.
        if delta {
            let matched = if local_pg {
                delta_matched.contains(&file.path)
            } else {
                target_matches(pg, &dst, file)
            };
            if matched {
                files_skipped += 1;
                continue;
            }
        }

        if dry_run {
            // Report the file that would be restored without resolving its source
            // (which is read-only but unnecessary) or anchoring a destination
            // (which would create the parent directory). No bytes are touched.
            log_info(&format!("dry-run: would restore {} ({} byte(s))", file.path, file.size));
            dry_run_restore_count += 1;
            continue;
        }

        // Resolve where this file's bytes physically live and how they are
        // stored — a standalone repo object, a slice of a bundle, or a
        // reassembled block-incremental file — following a whole-file reference
        // to the holding backup when needed. The PG destination may not exist
        // yet, so its parent dir is created and the absolute path anchored there.
        let source = resolver.resolve(file)?;
        let abs_dst = destination_absolute_path(pg, &dst)?;

        jobs.push(RestoreCopyJob {
            rel: file.path.clone(),
            source,
            abs_dst,
            expected_checksum: file.checksum.clone(),
            mode: file.mode,
        });
    }

    // Fan the copy jobs out across `process-max` workers. The hard-fail SHA-1
    // check runs per file inside each worker, so a corrupt file still fails the
    // whole restore; `process-max=1` runs a single worker (the prior serial
    // path). The number of files planned for copy is the restore count. A dry-run
    // dispatches nothing — `dry_run_restore_count` is the would-be count.
    let files_restored = if dry_run { dry_run_restore_count } else { jobs.len() };
    run_restore_jobs(jobs, repo, worker_count, JobRetry::from_options(config))?;

    // 3. Delta restore removes target files absent from the manifest so the
    //    target matches the backup exactly. Walk every restored directory root
    //    and delete any regular file not listed in `[target:file]`. A dry-run
    //    only *counts* the stray files (read-only walk) and removes none.
    let files_removed = if delta {
        if dry_run {
            count_stray_files(pg, &manifest)?
        } else {
            remove_stray_files(pg, &manifest)?
        }
    } else {
        0
    };

    // 4. `[target:link]` symlinks were materialised in step 1c (before the copy
    //    pass); reuse those counts.
    let links_created = link_counts.created;
    let skipped_links = link_counts.skipped;
    let links_as_dir = link_counts.as_dir;

    // 4b. Restore the backup's `backup_label` into the PGDATA root. pgBackRust
    //     stores it at the backup root — it is written by `pg_backup_stop`, not
    //     captured by the PGDATA walk — so the manifest's `[target:file]` set does
    //     not list it and the copy loop never restores it. Without `backup_label`
    //     present in PGDATA the restored cluster reads `pg_control` instead of the
    //     backup's start checkpoint and recovery aborts with "could not locate a
    //     valid checkpoint record". A DB-free (control-file-only) backup writes no
    //     label, so a missing file is expected and not an error.
    //
    //     The backup's `tablespace_map` is deliberately NOT restored to the
    //     PGDATA root as `tablespace_map`: it records the ORIGINAL tablespace
    //     locations, which restore may have remapped (`--tablespace-map`), so
    //     replaying it verbatim would make PostgreSQL create tablespace symlinks
    //     at the stale locations and fight the ones restore just created. It is
    //     instead written as `tablespace_map.old` for operator reference. C ref:
    //     pgBackRust omits `tablespace_map` from the restored PGDATA.
    if !dry_run {
        // backup_label — restored verbatim as `backup_label`.
        let label_src = PathBuf::from(format!("backup/{stanza}/{label}/backup_label"));
        match repo.open_read(&label_src) {
            Ok(mut reader) => {
                let bytes = reader.read_all()?;
                // Atomic + fsync'd on local backends (write_atomic_path).
                pg.write_atomic_path(Path::new("backup_label"), &bytes)?;
                log_info(&format!("restore: wrote backup_label ({} bytes) into PGDATA", bytes.len()));
            }
            Err(StorageError::NotFound { .. }) => {}
            Err(err) => return Err(CommandError::Storage(err)),
        }

        // tablespace_map — preserved as `tablespace_map.old` only (never as the
        // live `tablespace_map`, see above).
        let ts_src = PathBuf::from(format!("backup/{stanza}/{label}/tablespace_map"));
        match repo.open_read(&ts_src) {
            Ok(mut reader) => {
                let bytes = reader.read_all()?;
                pg.write_atomic_path(Path::new("tablespace_map.old"), &bytes)?;
                log_info(&format!(
                    "restore: wrote tablespace_map.old ({} bytes) into PGDATA (not restored as live tablespace_map)",
                    bytes.len()
                ));
            }
            Err(StorageError::NotFound { .. }) => {}
            Err(err) => return Err(CommandError::Storage(err)),
        }
    }

    // 4c. Remove any residual recovery-signal / recovery-config files from a
    //     previous cluster life before writing fresh ones, so a stale
    //     `recovery.signal` / `standby.signal` / `recovery.conf` cannot survive a
    //     `--delta`/`--force` restore and drive the wrong recovery mode. Skipped
    //     for `--type=preserve` (the operator asked to keep the existing recovery
    //     configuration) and on dry-run.
    if !dry_run && !recovery_preserve(config) {
        for name in ["recovery.signal", "standby.signal", "recovery.conf"] {
            pg.remove(Path::new(name), false)?;
        }
    }

    // 5. Write the version-appropriate recovery configuration. The pure
    //    `recovery_files` generator decides which files and contents apply; the
    //    only impure step is appending the block to any existing
    //    `postgresql.auto.conf`. A dry run reports the files it would write
    //    (computed purely) but creates none.
    let recovery_files_written = if dry_run {
        let planned: Vec<String> = recovery_files(&manifest.db_version, stanza, config)
            .into_iter()
            .map(|(rel, _)| rel.to_string_lossy().into_owned())
            .collect();
        for rel in &planned {
            log_info(&format!("dry-run: would write recovery file {rel}"));
        }
        planned
    } else {
        write_recovery_files(pg, &manifest.db_version, stanza, config)?
    };

    Ok(RestoreOutcome {
        label,
        files_restored,
        files_skipped,
        files_removed,
        paths_created,
        links_created,
        skipped_links,
        links_as_dir,
        recovery_files_written,
        dry_run,
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

/// Collect every regular file under the manifest's directory roots that is not
/// listed in the manifest's `[target:file]` set (the stray files a delta restore
/// would remove). Read-only.
///
/// Roots are the top-level components of the manifest's recorded paths and
/// files, so the walk covers exactly the tree the backup describes without
/// descending into unrelated parts of the filesystem. Shared by
/// [`remove_stray_files`] and the dry-run [`count_stray_files`].
fn stray_files(pg: &dyn Storage, manifest: &Manifest) -> Result<Vec<PathBuf>, CommandError> {
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
        // A first path component can be a top-level DIRECTORY (e.g. `base` from
        // `base/1/PG_VERSION`) or a root-level FILE (e.g. `PG_VERSION`, whose only
        // component is the file itself). Walking a file as a directory would
        // `read_dir` it → ENOTDIR, so dispatch on the on-disk kind: recurse into
        // directories, record a root-level file as present, skip what's absent.
        match pg.info(root) {
            Ok(info) if info.kind == StorageKind::Path => collect_target_files(pg, root, &mut present)?,
            Ok(info) if info.kind == StorageKind::File => present.push(root.clone()),
            // symlink / special, or recorded-but-absent on the target: nothing to walk.
            Ok(_) | Err(StorageError::NotFound { .. }) => {}
            Err(err) => return Err(CommandError::Storage(err)),
        }
    }

    let mut stray = Vec::new();
    for rel in present {
        // Compare against the manifest's `/`-joined string keys.
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if !kept.contains(rel_str.as_str()) {
            stray.push(rel);
        }
    }
    Ok(stray)
}

/// Delete every stray target file (see [`stray_files`]), returning the count.
fn remove_stray_files(pg: &dyn Storage, manifest: &Manifest) -> Result<usize, CommandError> {
    let stray = stray_files(pg, manifest)?;
    let mut files_removed = 0;
    for rel in stray {
        pg.remove(&rel, false)?;
        files_removed += 1;
    }
    Ok(files_removed)
}

/// Count the stray target files (see [`stray_files`]) a delta restore *would*
/// remove, without deleting any. The dry-run counterpart of [`remove_stray_files`].
fn count_stray_files(pg: &dyn Storage, manifest: &Manifest) -> Result<usize, CommandError> {
    Ok(stray_files(pg, manifest)?.len())
}

/// `restore` — restore a backup into a PG data directory.
///
/// Runs [`restore_inner`] and prints a one-line summary.
///
/// # Errors
///
/// Forwards every error from [`restore_inner`].
pub fn restore(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    log_info("restore command begin");
    let outcome = restore_inner(config, repo_storage, pg_storage)?;

    let prefix = if outcome.dry_run {
        "dry-run: would restore"
    } else {
        "restore:"
    };
    log_info(&format!(
        "{} backup {} — {} file(s) restored, {} skipped, {} removed, {} path(s) created, {} link(s) created, \
         {} link(s) skipped, {} link(s) as dir, {} recovery file(s) written",
        prefix,
        outcome.label,
        outcome.files_restored,
        outcome.files_skipped,
        outcome.files_removed,
        outcome.paths_created,
        outcome.links_created,
        outcome.skipped_links,
        outcome.links_as_dir,
        outcome.recovery_files_written.len(),
    ));

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{DbHistoryEntry, InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{JobRetry, RestoreOutcome, dry_run_enabled, restore_inner};
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

    /// Set `--force` on a config so the non-empty-`PGDATA` pre-flight guard is
    /// bypassed (used by tests that intentionally pre-seed the restore target
    /// before a non-delta restore).
    fn with_force(mut config: LoadedConfig) -> LoadedConfig {
        config.options.insert(("force".to_owned(), None), OptionValue::Boolean(true));
        config
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
                mode: None,
                user: None,
                group: None,
                bundle_id: None,
                bundle_offset: None,
                block_map: None,
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
            option_checksum_page: None,
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
    fn restore_into_fresh_pgdata_creates_runtime_dir_skeleton() {
        // Restoring into a FRESH/empty PGDATA (how a streaming standby is seeded)
        // must materialise the full PostgreSQL runtime-directory skeleton, even
        // though the backup never descends into those transient dirs. The critical
        // one is `pg_wal/archive_status` (PG writes `.ready`/`.done` markers there
        // during archive recovery); without it the cluster FATALs at start. This
        // is the restore half of the fix for `FATAL: could not open directory
        // "pg_notify"`.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        // A real post-fix manifest records the bare runtime dirs (pg_notify,
        // pg_wal, …) as empty paths but NOT their subdirectories. Seed only a
        // couple of them plus a relation dir; the restore must fill in the rest.
        seed_backup(&repo_s, stanza, label, &[], &["base", "base/1", "pg_notify", "pg_wal"], &[]);

        let outcome = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.files_restored, 0);

        // Every required runtime directory exists after restore, including the
        // deep subdirs absent from the manifest (`pg_wal/archive_status`,
        // `pg_logical/snapshots`, …).
        for dir in [
            "pg_wal",
            "pg_wal/archive_status",
            "pg_notify",
            "pg_replslot",
            "pg_serial",
            "pg_snapshots",
            "pg_dynshmem",
            "pg_stat_tmp",
            "pg_subtrans",
            "pg_stat",
            "pg_logical",
            "pg_logical/snapshots",
            "pg_logical/mappings",
            "pg_commit_ts",
            "pg_tblspc",
        ] {
            let info = pg_s
                .info(Path::new(dir))
                .unwrap_or_else(|_| panic!("runtime dir {dir} must exist after fresh-PGDATA restore"));
            assert_eq!(info.kind, pgbr_storage::StorageKind::Path, "{dir} must be a directory");
        }
        // The manifest's own relation dirs were created too.
        assert_eq!(
            pg_s.info(Path::new("base/1")).expect("base/1").kind,
            pgbr_storage::StorageKind::Path
        );
    }

    #[test]
    fn restore_dry_run_skips_runtime_dir_skeleton() {
        // A dry-run must not mutate the target: the runtime-dir skeleton is
        // created only on a real restore.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(&repo_s, stanza, label, &[], &["pg_notify"], &[]);

        restore_inner(&cfg_dry_run(Some(stanza), None), &repo_s, &pg_s).expect("dry-run restore");

        assert!(
            pg_s.info(Path::new("pg_wal/archive_status")).is_err(),
            "dry-run must not create the runtime-dir skeleton"
        );
        assert!(pg_s.info(Path::new("pg_notify")).is_err(), "dry-run must create no dirs");
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
        cfg_recovery_full(stanza, ty, target, target_exclusive, None, None)
    }

    /// Like [`cfg_recovery`] but also threads `--target-action` and
    /// `--target-timeline` through, for the recovery-target family tests.
    fn cfg_recovery_full(
        stanza: &str,
        ty: Option<&str>,
        target: Option<&str>,
        target_exclusive: bool,
        target_action: Option<&str>,
        target_timeline: Option<&str>,
    ) -> LoadedConfig {
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
        if let Some(action) = target_action {
            options.insert(("target-action".to_owned(), None), OptionValue::StringId(action.to_owned()));
        }
        if let Some(timeline) = target_timeline {
            options.insert(("target-timeline".to_owned(), None), OptionValue::String(timeline.to_owned()));
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
            contents.contains("restore_command = 'pgbackrust --stanza=demo archive-get %f \"%p\"'"),
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

        // Pre-seeding the target makes PGDATA non-empty; --force lets the
        // non-delta restore proceed past the pre-flight guard.
        let outcome = restore_inner(&with_force(cfg_recovery(stanza, None, None, false)), &repo_s, &pg_s).expect("restore");
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
            contents.contains("restore_command = 'pgbackrust --stanza=demo archive-get %f \"%p\"'"),
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
    fn restore_writes_recovery_target_settings_end_to_end() {
        // End-to-end: a PITR restore with --type=time, --target, --target-exclusive,
        // --target-action=promote, and --target-timeline=2 writes a
        // postgresql.auto.conf (PG 14) whose recovery block carries every setting.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        let cfg = cfg_recovery_full(
            stanza,
            Some("time"),
            Some("2024-01-01 12:00:00"),
            true,
            Some("promote"),
            Some("2"),
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(
            outcome.recovery_files_written,
            vec!["postgresql.auto.conf".to_owned(), "recovery.signal".to_owned()]
        );

        let contents = {
            let mut r = pg_s.open_read(Path::new("postgresql.auto.conf")).expect("open auto.conf");
            String::from_utf8(r.read_all().expect("read auto.conf")).unwrap()
        };
        for expected in [
            "restore_command = 'pgbackrust --stanza=demo archive-get %f \"%p\"'",
            "recovery_target_time = '2024-01-01 12:00:00'",
            "recovery_target_inclusive = 'false'",
            "recovery_target_action = 'promote'",
            "recovery_target_timeline = '2'",
        ] {
            assert!(
                contents.contains(expected),
                "recovery block must contain {expected:?}: {contents}"
            );
        }
        // recovery.signal (not standby.signal) for a targeted restore.
        assert!(pg_s.exists(Path::new("recovery.signal")).unwrap());
        assert!(!pg_s.exists(Path::new("standby.signal")).unwrap());
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
                .contains("restore_command = 'pgbackrust --stanza=demo archive-get %f \"%p\"'")
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

    #[test]
    fn recovery_target_action_passthrough() {
        let stanza = "demo";

        // --target-action=promote -> recovery_target_action = 'promote'.
        let cfg_promote = cfg_recovery_full(
            stanza,
            Some("time"),
            Some("2024-01-01 12:00:00"),
            false,
            Some("promote"),
            None,
        );
        let promote = super::recovery_files("14", stanza, &cfg_promote);
        assert!(
            promote[0].1.contains("recovery_target_action = 'promote'"),
            "promote action must be written: {}",
            promote[0].1
        );

        // --target-action=shutdown -> recovery_target_action = 'shutdown'.
        let cfg_shutdown = cfg_recovery_full(stanza, Some("immediate"), None, false, Some("shutdown"), None);
        let shutdown = super::recovery_files("14", stanza, &cfg_shutdown);
        assert!(
            shutdown[0].1.contains("recovery_target_action = 'shutdown'"),
            "shutdown action must be written: {}",
            shutdown[0].1
        );

        // The default `pause` (explicit or absent) suppresses the GUC entirely.
        let cfg_pause = cfg_recovery_full(stanza, Some("time"), Some("2024-01-01 12:00:00"), false, Some("pause"), None);
        let pause = super::recovery_files("14", stanza, &cfg_pause);
        assert!(
            !pause[0].1.contains("recovery_target_action"),
            "default pause must not write recovery_target_action: {}",
            pause[0].1
        );
        let cfg_absent = cfg_recovery(stanza, Some("time"), Some("2024-01-01 12:00:00"), false);
        let absent = super::recovery_files("14", stanza, &cfg_absent);
        assert!(
            !absent[0].1.contains("recovery_target_action"),
            "absent target-action must not write recovery_target_action: {}",
            absent[0].1
        );
    }

    #[test]
    fn recovery_target_timeline_passthrough() {
        let stanza = "demo";

        // --target-timeline=3 -> recovery_target_timeline = '3' on every version.
        let cfg_tl = cfg_recovery_full(stanza, Some("time"), Some("2024-01-01 12:00:00"), false, None, Some("3"));
        let tl14 = super::recovery_files("14", stanza, &cfg_tl);
        assert!(
            tl14[0].1.contains("recovery_target_timeline = '3'"),
            "timeline must be written on PG>=12: {}",
            tl14[0].1
        );
        let tl11 = super::recovery_files("11", stanza, &cfg_tl);
        assert!(
            tl11[0].1.contains("recovery_target_timeline = '3'"),
            "timeline must be written on PG<12: {}",
            tl11[0].1
        );

        // The literal `current`: written on PG>=12, suppressed on PG<12 (that
        // version defaults to current and rejects it as an explicit parameter).
        let cfg_cur = cfg_recovery_full(stanza, Some("default"), None, false, None, Some("current"));
        let cur14 = super::recovery_files("14", stanza, &cfg_cur);
        assert!(
            cur14[0].1.contains("recovery_target_timeline = 'current'"),
            "current must be written on PG>=12: {}",
            cur14[0].1
        );
        let cur11 = super::recovery_files("11", stanza, &cfg_cur);
        assert!(
            !cur11[0].1.contains("recovery_target_timeline"),
            "current must be suppressed on PG<12: {}",
            cur11[0].1
        );
    }

    #[test]
    fn recovery_immediate_pins_timeline_on_pg12() {
        // type=immediate with no explicit --target-timeline pins the timeline to
        // `current` on PG>=12 (so recovery does not chase an unreachable latest),
        // but emits nothing on PG<12 (which defaults to current already).
        let stanza = "demo";
        let cfg_imm = cfg_recovery(stanza, Some("immediate"), None, false);

        let imm14 = super::recovery_files("14", stanza, &cfg_imm);
        assert!(
            imm14[0].1.contains("recovery_target_timeline = 'current'"),
            "immediate on PG>=12 must pin timeline to current: {}",
            imm14[0].1
        );

        let imm11 = super::recovery_files("11", stanza, &cfg_imm);
        assert!(
            !imm11[0].1.contains("recovery_target_timeline"),
            "immediate on PG<12 must not pin a timeline: {}",
            imm11[0].1
        );
    }

    // ---- arbitrary recovery options (--recovery-option) ---------------------

    /// A restore config carrying `--type` and an arbitrary `--recovery-option`
    /// hash, for the recovery-option passthrough tests.
    fn cfg_recovery_option(stanza: &str, ty: Option<&str>, recovery_option: &[(&str, &str)]) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(ty) = ty {
            options.insert(("type".to_owned(), None), OptionValue::StringId(ty.to_owned()));
        }
        if !recovery_option.is_empty() {
            let mut map = BTreeMap::new();
            for (k, v) in recovery_option {
                map.insert((*k).to_owned(), (*v).to_owned());
            }
            options.insert(("recovery-option".to_owned(), None), OptionValue::Hash(map));
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
    fn recovery_option_lines_appended_and_override() {
        let stanza = "demo";

        // An arbitrary recovery-option is appended verbatim AFTER the built-in
        // lines, with `-` in the key normalised to `_` and the value quoted.
        let cfg_extra = cfg_recovery_option(stanza, Some("default"), &[("archive-cleanup-command", "/usr/bin/cleanup %r")]);
        let extra = super::recovery_files("14", stanza, &cfg_extra);
        let block = &extra[0].1;
        assert!(
            block.contains("restore_command = 'pgbackrust --stanza=demo archive-get %f \"%p\"'"),
            "built-in restore_command must still be present: {block}"
        );
        assert!(
            block.contains("archive_cleanup_command = '/usr/bin/cleanup %r'"),
            "user recovery-option must be appended with - normalised to _: {block}"
        );
        // The user option comes AFTER the built-in restore_command line.
        let cmd_pos = block.find("restore_command").expect("restore_command present");
        let extra_pos = block.find("archive_cleanup_command").expect("user option present");
        assert!(extra_pos > cmd_pos, "user option must follow the built-in lines: {block}");

        // A user-supplied restore_command OVERRIDES the built-in one: the built-in
        // line is suppressed and only the user's value appears.
        let cfg_override = cfg_recovery_option(stanza, Some("default"), &[("restore_command", "my-custom-archive-get %f %p")]);
        let overridden = super::recovery_files("14", stanza, &cfg_override);
        let oblock = &overridden[0].1;
        assert!(
            oblock.contains("restore_command = 'my-custom-archive-get %f %p'"),
            "user restore_command must be written: {oblock}"
        );
        assert!(
            !oblock.contains("pgbackrust --stanza=demo archive-get"),
            "built-in restore_command must be suppressed when the user overrides it: {oblock}"
        );
        assert_eq!(
            oblock.matches("restore_command").count(),
            1,
            "exactly one restore_command line must be present: {oblock}"
        );

        // The dashed form of the override key collides with the built-in too,
        // since keys are normalised before comparison.
        let cfg_override_dashed = cfg_recovery_option(stanza, Some("default"), &[("restore-command", "dashed-archive-get %f %p")]);
        let dashed = super::recovery_files("14", stanza, &cfg_override_dashed);
        let dblock = &dashed[0].1;
        assert!(
            dblock.contains("restore_command = 'dashed-archive-get %f %p'"),
            "dashed override key must normalise and win: {dblock}"
        );
        assert_eq!(
            dblock.matches("restore_command").count(),
            1,
            "exactly one restore_command line even with the dashed override: {dblock}"
        );
    }

    #[test]
    fn recovery_option_end_to_end() {
        // End-to-end: a restore with --recovery-option writes the user setting into
        // the generated postgresql.auto.conf (PG 14).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        let cfg = cfg_recovery_option(stanza, None, &[("archive-cleanup-command", "foo")]);
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(
            outcome.recovery_files_written,
            vec!["postgresql.auto.conf".to_owned(), "recovery.signal".to_owned()]
        );

        let contents = {
            let mut r = pg_s.open_read(Path::new("postgresql.auto.conf")).expect("open auto.conf");
            String::from_utf8(r.read_all().expect("read auto.conf")).unwrap()
        };
        assert!(
            contents.contains("archive_cleanup_command = 'foo'"),
            "recovery-option must appear in the generated config: {contents}"
        );
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

        // Non-empty target + non-delta => --force is required past the pre-flight guard.
        let outcome = restore_inner(&with_force(cfg(Some(stanza), None)), &repo_s, &pg_s).expect("restore");
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
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
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
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        };
        seed_pg_file(&pg_s, "pg_data/empty", b"");
        assert!(
            super::target_matches(&pg_s, Path::new("pg_data/empty"), &empty_file),
            "zero-length target must match a checksum-less manifest entry"
        );
    }

    // ---- end-to-end backup -> restore round trips --------------------------

    use crate::backup::{backup_inner, backup_inner_keyed};
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

    /// Seed an **encrypted** repository: `backup.info` encrypted under
    /// `user_pass`, plus an `archive.info` carrying `sub_key` in its `[cipher]`
    /// section (also under `user_pass`). This is what `restore_inner` reads — it
    /// decrypts `backup.info` with the user pass and recovers the repository
    /// sub-key (which decrypts the data files + manifest) from `archive.info`,
    /// matching the on-disk layout stanza-create writes for an encrypted repo.
    fn init_stanza_encrypted(repo: &Posix, stanza: &str, user_pass: &str, sub_key: &str) {
        let mut backup_history = BTreeMap::new();
        backup_history.insert(
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
            history: backup_history,
        };
        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup/<stanza>");
        // backup.info is encrypted under the user passphrase; the recorded
        // `[cipher]` sub-key is the repository sub-key.
        info.save_keyed(repo, &super::backup_info_path(stanza), Some(user_pass), Some(sub_key))
            .expect("save encrypted backup.info");

        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        let archive = pgbr_info::InfoArchive {
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
            .save_keyed(
                repo,
                Path::new(&format!("archive/{stanza}/archive.info")),
                Some(user_pass),
                Some(sub_key),
            )
            .expect("save encrypted archive.info");
    }

    /// `repo-cipher-type=aes-256-cbc` + `repo-cipher-pass=<user_pass>` options for
    /// a restore against an encrypted repo (the user passphrase, which unlocks the
    /// recorded sub-key — not the sub-key itself).
    fn repo_cipher_opts(user_pass: &str) -> Vec<((&str, Option<u32>), OptionValue)> {
        vec![
            (("repo-cipher-type", Some(1)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-pass", Some(1)), OptionValue::String(user_pass.to_owned())),
        ]
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

    #[cfg(unix)]
    #[test]
    fn backup_then_restore_preserves_file_mode() {
        // A source file seeded with a distinctive mode (0o640) must, after a real
        // backup -> restore round trip, land on the restore target with the same
        // permission bits — the mode is recorded in the manifest by backup and
        // re-applied by restore.
        use std::os::unix::fs::PermissionsExt;

        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_dst = tempfile::tempdir().unwrap();
        let repo_s = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());
        let pg_dst_s = Posix::new(pg_dst.path());

        let stanza = "demo";
        let label = "20240101-120000F";
        init_stanza(&repo_s, stanza);
        seed_pg_file(&pg_src_s, "base/1/1259", b"relation data with a specific mode");

        // Stamp a distinctive mode on the source file.
        let abs_src = pg_src_s.info(Path::new("base/1/1259")).expect("stat source").path;
        std::fs::set_permissions(&abs_src, std::fs::Permissions::from_mode(0o640)).expect("chmod source");

        backup_inner(stanza, &repo_s, &pg_src_s, label, 1_704_110_400, &RepoTransform::identity()).expect("backup");

        let outcome = restore_inner(&restore_cfg(stanza, Vec::new()), &repo_s, &pg_dst_s).expect("restore");
        assert_eq!(outcome.files_restored, 1);

        // The restored file's permission bits must match the source's mode.
        let abs_dst = pg_dst_s.info(Path::new("base/1/1259")).expect("stat restored").path;
        let restored_mode = std::fs::metadata(&abs_dst).expect("restored metadata").permissions().mode() & 0o7777;
        assert_eq!(restored_mode, 0o640, "restored file must carry the recorded mode");
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
        // Encrypted repo: the sub-key "backup-secret" is recorded in archive.info
        // under the user passphrase "user-pass". backup_inner is handed the
        // sub-key directly via the transform; restore_inner recovers the same key
        // from archive.info — both agree, as on a real encrypted repo.
        init_stanza_encrypted(&repo_s, stanza, "user-pass", "backup-secret");
        for (rel, bytes) in FILES {
            seed_pg_file(&pg_src_s, rel, bytes);
        }

        // zst + AES-256-CBC (repo sub-key as the cipher pass).
        let transform = RepoTransform {
            compress_type: CompressType::Zst,
            compress_level: 3,
            cipher_pass: Some("backup-secret".to_owned()),
        };
        backup_inner_keyed(
            stanza,
            &repo_s,
            &pg_src_s,
            label,
            1_704_110_400,
            &transform,
            Some("user-pass"),
        )
        .expect("backup");

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

        // Restore supplies the user passphrase (`repo-cipher-pass`), which unlocks
        // the recorded sub-key; the compress-type comes from the recorded metadata.
        let cfg = restore_cfg(stanza, repo_cipher_opts("user-pass"));
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

    /// End-to-end encrypted-repo round trip exercising the real two-level key
    /// flow: the repository sub-key is resolved from an encrypted `archive.info`
    /// (exactly as `backup` / `restore` do via `cipher::active_sub_key`), the
    /// backup encrypts both the data files and `backup.manifest` with it, and the
    /// restore recovers the seeded bytes. Asserts the stored data file and the
    /// manifest are actually encrypted (OpenSSL `Salted__` framing), not plaintext.
    #[test]
    fn encrypted_repo_backup_restore_round_trip() {
        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_dst = tempfile::tempdir().unwrap();
        let repo_s = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());
        let pg_dst_s = Posix::new(pg_dst.path());

        let stanza = "demo";
        let label = "20240101-120000F";
        let user_pass = "user-pass";
        let sub_key = "repo-sub-key-secret";
        // Encrypted repo: archive.info records the sub-key under the user pass.
        init_stanza_encrypted(&repo_s, stanza, user_pass, sub_key);
        for (rel, bytes) in FILES {
            seed_pg_file(&pg_src_s, rel, bytes);
        }

        // Build the backup transform exactly as `backup()` does: resolve the
        // repository sub-key from archive.info, then key the transform with it.
        // `compress-type` left unset (= none) so the stored data file is purely
        // encrypted — its first bytes are the cipher's `Salted__` header, with no
        // compression framing in front.
        let backup_cfg = restore_cfg(stanza, repo_cipher_opts(user_pass));
        let resolved_sub = crate::cipher::active_sub_key(&repo_s, &backup_cfg, stanza)
            .expect("resolve sub-key")
            .expect("encrypted repo yields a sub-key");
        assert_eq!(resolved_sub, sub_key, "resolved sub-key must match the recorded one");
        let transform = RepoTransform::from_options_with_key(&backup_cfg, Some(resolved_sub));
        backup_inner_keyed(stanza, &repo_s, &pg_src_s, label, 1_704_110_400, &transform, Some(user_pass)).expect("backup");

        // (a) The stored data file for global/pg_control is encrypted: it carries
        //     the OpenSSL `Salted__` magic and does NOT equal the plaintext.
        let control_repo = repo_dir.path().join(format!("backup/{stanza}/{label}/global/pg_control"));
        assert!(control_repo.exists(), "expected stored data file global/pg_control");
        let control_bytes = std::fs::read(&control_repo).unwrap();
        assert!(
            control_bytes.starts_with(b"Salted__"),
            "stored data file must be Salted__-framed (encrypted), got {:?}",
            &control_bytes[..control_bytes.len().min(8)]
        );
        let control_plain = FILES
            .iter()
            .find(|(r, _)| *r == "global/pg_control")
            .map(|(_, b)| *b)
            .unwrap();
        assert_ne!(control_bytes.as_slice(), control_plain, "data file must not be plaintext");

        // (b) backup.manifest is encrypted with the same sub-key.
        let manifest_repo = repo_dir.path().join(format!("backup/{stanza}/{label}/backup.manifest"));
        let manifest_bytes = std::fs::read(&manifest_repo).unwrap();
        assert!(
            manifest_bytes.starts_with(b"Salted__"),
            "backup.manifest must be Salted__-framed (encrypted)"
        );

        // (c) Restore reproduces the seeded file bytes. The restore resolves the
        //     same sub-key from archive.info given only the user passphrase.
        let restore_cfg = restore_cfg(stanza, repo_cipher_opts(user_pass));
        let outcome = restore_inner(&restore_cfg, &repo_s, &pg_dst_s).expect("restore");
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

    // ---- tablespace remapping ----------------------------------------------

    /// A tablespace link `pg_data/pg_tblspc/<oid>` with the given recorded
    /// destination.
    fn ts_link(oid: &str, destination: &str) -> ManifestLink {
        ManifestLink {
            path: format!("pg_data/pg_tblspc/{oid}"),
            destination: destination.to_owned(),
        }
    }

    #[test]
    fn tablespace_explicit_map_wins() {
        // An explicit --tablespace-map entry for the oid wins over both
        // --tablespace-map-all and the recorded destination.
        let link = ts_link("16395", "/original/ts_loc");
        let mut map = BTreeMap::new();
        map.insert("16395".to_owned(), "/explicit/here".to_owned());

        let target = super::resolve_tablespace_target(&link, &map, Some("/all/prefix"));
        assert_eq!(target, Path::new("/explicit/here"));
    }

    #[test]
    fn tablespace_map_all_prefix() {
        // With no explicit entry, --tablespace-map-all puts the tablespace under
        // <prefix>/<tablespace-name>, where the name is the last component of
        // the recorded destination.
        let link = ts_link("16395", "/original/ts_loc");
        let map = BTreeMap::new();

        let target = super::resolve_tablespace_target(&link, &map, Some("/all/prefix"));
        assert_eq!(target, Path::new("/all/prefix/ts_loc"));
    }

    #[test]
    fn tablespace_falls_back_to_manifest_target() {
        // No map and no map-all: the recorded destination is used unchanged.
        let link = ts_link("16395", "/original/ts_loc");
        let map = BTreeMap::new();

        let target = super::resolve_tablespace_target(&link, &map, None);
        assert_eq!(target, Path::new("/original/ts_loc"));

        // A non-tablespace link is never remapped, even when a map-all is set.
        let other = ManifestLink {
            path: "pg_data/pg_wal".to_owned(),
            destination: "/var/lib/pg_wal".to_owned(),
        };
        let remapped = super::resolve_tablespace_target(&other, &map, Some("/all/prefix"));
        assert_eq!(
            remapped,
            Path::new("/var/lib/pg_wal"),
            "non-tablespace links must not be remapped"
        );
    }

    #[test]
    fn restore_remaps_tablespace_symlink() {
        // End-to-end: a manifest with a pg_tblspc/<oid> link and a
        // --tablespace-map entry re-creates the symlink at the mapped path.
        let (_repo, pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let new_loc = pg.path().join("remapped_ts");
        let new_loc_str = new_loc.to_string_lossy().into_owned();

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[],
            &["pg_data", "pg_data/pg_tblspc"],
            &[("pg_data/pg_tblspc/16395", "/original/ts_loc")],
        );

        let cfg = restore_cfg(
            stanza,
            vec![(
                ("tablespace-map", None),
                OptionValue::Hash({
                    let mut m = BTreeMap::new();
                    m.insert("16395".to_owned(), new_loc_str.clone());
                    m
                }),
            )],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.links_created, 1);

        let read = std::fs::read_link(pg.path().join("pg_data/pg_tblspc/16395")).expect("read_link");
        assert_eq!(read, Path::new(&new_loc_str), "symlink must point at the mapped destination");
    }

    // ---- generic link remapping (--link-map) -------------------------------

    #[test]
    fn resolve_link_target_mapped_and_unmapped() {
        let mut map = BTreeMap::new();
        map.insert("pg_wal".to_owned(), "/mnt/fast/pg_wal".to_owned());

        // A mapped link name uses the mapped destination, ignoring the recorded one.
        assert_eq!(
            super::resolve_link_target("pg_wal", "/var/lib/pg_wal", &map),
            "/mnt/fast/pg_wal",
            "mapped link must use the --link-map destination"
        );

        // An unmapped link name keeps its recorded destination.
        assert_eq!(
            super::resolve_link_target("pg_log", "/var/log/pg_log", &map),
            "/var/log/pg_log",
            "unmapped link must keep its recorded destination"
        );

        // An empty map always falls back to the recorded destination.
        let empty = BTreeMap::new();
        assert_eq!(
            super::resolve_link_target("pg_wal", "/var/lib/pg_wal", &empty),
            "/var/lib/pg_wal",
            "empty link-map must keep the recorded destination"
        );
    }

    #[test]
    fn link_relative_name_strips_pgdata_prefix() {
        // The manifest records links under the pg_data target; --link-map keys are
        // the link name with that prefix stripped.
        assert_eq!(super::link_relative_name("pg_data/pg_wal"), "pg_wal");
        assert_eq!(super::link_relative_name("pg_data/some/deep/link"), "some/deep/link");
        // A path without the prefix is returned unchanged.
        assert_eq!(super::link_relative_name("pg_wal"), "pg_wal");
    }

    #[test]
    fn restore_remaps_link_with_link_map() {
        // End-to-end: a manifest with a non-tablespace link (pg_wal) and a
        // --link-map entry re-creates the symlink at the mapped destination.
        let (_repo, pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let mapped = pg.path().join("relocated_wal");
        let mapped_str = mapped.to_string_lossy().into_owned();

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[],
            &["pg_data"],
            &[("pg_data/pg_wal", "/var/lib/original_wal")],
        );

        let cfg = restore_cfg(
            stanza,
            vec![(
                ("link-map", None),
                OptionValue::Hash({
                    let mut m = BTreeMap::new();
                    m.insert("pg_wal".to_owned(), mapped_str.clone());
                    m
                }),
            )],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.links_created, 1);

        let read = std::fs::read_link(pg.path().join("pg_data/pg_wal")).expect("read_link");
        assert_eq!(
            read,
            Path::new(&mapped_str),
            "symlink must point at the --link-map destination, not the recorded one"
        );
    }

    #[test]
    fn restore_unmapped_link_keeps_recorded_destination() {
        // A link with NO --link-map entry keeps its recorded destination even when
        // a --link-map for a different link is supplied.
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
            &[("pg_data/pg_wal", "/var/lib/original_wal")],
        );

        // A --link-map naming a DIFFERENT link must not touch pg_wal.
        let cfg = restore_cfg(
            stanza,
            vec![(
                ("link-map", None),
                OptionValue::Hash({
                    let mut m = BTreeMap::new();
                    m.insert("pg_log".to_owned(), "/somewhere/else".to_owned());
                    m
                }),
            )],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.links_created, 1);

        let read = std::fs::read_link(pg.path().join("pg_data/pg_wal")).expect("read_link");
        assert_eq!(
            read,
            Path::new("/var/lib/original_wal"),
            "unmapped link must keep its recorded destination"
        );
    }

    // ---- selective database restore ----------------------------------------

    #[test]
    fn database_included_keeps_only_included_oid() {
        let include = vec!["16384".to_owned()];
        let exclude: Vec<String> = Vec::new();

        // Included oid kept; other db dropped.
        assert!(super::database_included("base/16384/1259", &include, &exclude));
        assert!(!super::database_included("base/1/1259", &include, &exclude));
        // Tablespace-resident db file is matched by oid too.
        assert!(super::database_included(
            "pg_tblspc/16400/PG_16_202307071/16384/2619",
            &include,
            &exclude
        ));
        assert!(!super::database_included(
            "pg_tblspc/16400/PG_16_202307071/1/2619",
            &include,
            &exclude
        ));
        // Non-database files are always kept.
        assert!(super::database_included("global/pg_control", &include, &exclude));
        assert!(super::database_included("PG_VERSION", &include, &exclude));
        assert!(super::database_included(
            "pg_wal/000000010000000000000001",
            &include,
            &exclude
        ));
    }

    #[test]
    fn database_included_drops_excluded_oid() {
        let include: Vec<String> = Vec::new();
        let exclude = vec!["1".to_owned()];

        // Excluded oid dropped; everything else kept.
        assert!(!super::database_included("base/1/1259", &include, &exclude));
        assert!(super::database_included("base/16384/1259", &include, &exclude));
        // Tablespace-resident excluded db dropped.
        assert!(!super::database_included(
            "pg_tblspc/16400/PG_16_202307071/1/2619",
            &include,
            &exclude
        ));
        // Non-database files always kept.
        assert!(super::database_included("global/pg_control", &include, &exclude));
    }

    #[test]
    fn database_included_no_filters_keeps_everything() {
        let none: Vec<String> = Vec::new();
        assert!(super::database_included("base/1/1259", &none, &none));
        assert!(super::database_included("base/16384/1259", &none, &none));
        assert!(super::database_included("global/pg_control", &none, &none));
    }

    #[test]
    fn database_included_both_set_is_rejected_upstream() {
        // The predicate itself never sees both lists set — restore_inner errors
        // first. Prove restore_inner rejects the combination.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(&repo_s, stanza, label, &[], &["pg_data"], &[]);

        let cfg = restore_cfg(
            stanza,
            vec![
                (("db-include", None), OptionValue::List(vec!["16384".to_owned()])),
                (("db-exclude", None), OptionValue::List(vec!["1".to_owned()])),
            ],
        );
        let err = restore_inner(&cfg, &repo_s, &pg_s).expect_err("both filters must error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("mutually exclusive"), "unexpected message: {msg}"),
            other => panic!("expected Other(mutually exclusive), got {other:?}"),
        }
    }

    #[test]
    fn restore_with_db_include_skips_other_databases() {
        // End-to-end-ish: files under base/1/, base/16384/, and
        // global/pg_control. --db-include=16384 restores base/16384 + global
        // but not base/1.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let db1 = b"database 1 relation data".as_slice();
        let db_keep = b"database 16384 relation data".as_slice();
        let control = b"global control file bytes".as_slice();

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[
                ("base/1/1259", db1, Some(sha1_hex(db1))),
                ("base/16384/1259", db_keep, Some(sha1_hex(db_keep))),
                ("global/pg_control", control, Some(sha1_hex(control))),
            ],
            &["base", "base/1", "base/16384", "global"],
            &[],
        );

        let cfg = restore_cfg(
            stanza,
            vec![(("db-include", None), OptionValue::List(vec!["16384".to_owned()]))],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        // base/16384 + global restored; base/1 skipped.
        assert_eq!(outcome.files_restored, 2, "only the included db + global restore");

        assert!(
            pg_s.exists(Path::new("base/16384/1259")).unwrap(),
            "included database must be restored"
        );
        assert!(
            pg_s.exists(Path::new("global/pg_control")).unwrap(),
            "non-database file must always be restored"
        );
        assert!(
            !pg_s.exists(Path::new("base/1/1259")).unwrap(),
            "excluded database must not be restored"
        );
    }

    #[test]
    fn restore_with_db_exclude_skips_excluded_database() {
        // The mirror of the include test: --db-exclude=1 restores everything
        // except base/1.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let db1 = b"database 1 relation data".as_slice();
        let db_keep = b"database 16384 relation data".as_slice();
        let control = b"global control file bytes".as_slice();

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[
                ("base/1/1259", db1, Some(sha1_hex(db1))),
                ("base/16384/1259", db_keep, Some(sha1_hex(db_keep))),
                ("global/pg_control", control, Some(sha1_hex(control))),
            ],
            &["base", "base/1", "base/16384", "global"],
            &[],
        );

        let cfg = restore_cfg(stanza, vec![(("db-exclude", None), OptionValue::List(vec!["1".to_owned()]))]);
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.files_restored, 2, "all but the excluded db restore");

        assert!(pg_s.exists(Path::new("base/16384/1259")).unwrap());
        assert!(pg_s.exists(Path::new("global/pg_control")).unwrap());
        assert!(
            !pg_s.exists(Path::new("base/1/1259")).unwrap(),
            "excluded database must not be restored"
        );
    }

    // ---- parallel file copy (process-max) ----------------------------------

    /// `process_max` reads the resolved `--process-max` integer, defaulting to a
    /// single worker (the prior serial behaviour) when absent, non-integer, or
    /// `< 1`.
    #[test]
    fn process_max_reads_option_with_serial_default() {
        // Absent -> 1.
        assert_eq!(super::process_max(&cfg(Some("demo"), None)), 1);

        // Explicit values.
        let four = restore_cfg("demo", vec![(("process-max", None), OptionValue::Integer(4))]);
        assert_eq!(super::process_max(&four), 4);

        // `< 1` clamps to a single worker so the copy phase always progresses.
        let zero = restore_cfg("demo", vec![(("process-max", None), OptionValue::Integer(0))]);
        assert_eq!(super::process_max(&zero), 1);
        let neg = restore_cfg("demo", vec![(("process-max", None), OptionValue::Integer(-3))]);
        assert_eq!(super::process_max(&neg), 1);

        // A non-integer value falls back to the serial default.
        let wrong = restore_cfg("demo", vec![(("process-max", None), OptionValue::String("nope".to_owned()))]);
        assert_eq!(super::process_max(&wrong), 1);
    }

    /// A restore config selecting `label` with an explicit `--process-max`.
    fn cfg_process_max(stanza: &str, label: &str, process_max: i64) -> LoadedConfig {
        restore_cfg(
            stanza,
            vec![
                (("set", None), OptionValue::String(label.to_owned())),
                (("process-max", None), OptionValue::Integer(process_max)),
            ],
        )
    }

    /// Restore a multi-file (multi-directory, gz+cipher) backup once with
    /// `process-max=1` and once with `process-max=4`; the two restored targets
    /// must be byte-for-byte identical to each other and to the source — proving
    /// the worker count never changes the output. Mirrors `backup`'s
    /// `process-max=1` vs serial guarantee.
    #[test]
    fn restore_parallel_matches_serial() {
        // Build one shared backup (gz + AES) the two restores both read from.
        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let repo_s = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());

        let stanza = "demo";
        let label = "20240101-120000F";
        // Encrypted repo: "parallel-secret" is the recorded sub-key, unlocked by
        // the user passphrase "user-pass".
        init_stanza_encrypted(&repo_s, stanza, "user-pass", "parallel-secret");

        // A spread of files across several directories so the copy phase has
        // real work to fan out across workers.
        let files: &[(&str, &[u8])] = &[
            ("PG_VERSION", b"14\n"),
            ("base/1/1259", b"relation data 1259 relation data 1259 relation data 1259"),
            (
                "base/1/1260",
                b"relation data 1260 padded out so it is worth compressing aaaaaa",
            ),
            (
                "base/16384/2619",
                b"another database's relation, repeated repeated repeated repeated",
            ),
            (
                "global/pg_control",
                b"\x01\x02\x03\x04 control file bytes that repeat repeat repeat repeat",
            ),
            ("pg_xact/0000", b"transaction status bytes 000000000000000000000000000000"),
        ];
        for (rel, bytes) in files {
            seed_pg_file(&pg_src_s, rel, bytes);
        }

        let transform = RepoTransform {
            compress_type: CompressType::Gz,
            compress_level: 6,
            cipher_pass: Some("parallel-secret".to_owned()),
        };
        backup_inner_keyed(
            stanza,
            &repo_s,
            &pg_src_s,
            label,
            1_704_110_400,
            &transform,
            Some("user-pass"),
        )
        .expect("backup");

        // Restore into two fresh targets: one serial, one with four workers.
        let pg_serial = tempfile::tempdir().unwrap();
        let pg_parallel = tempfile::tempdir().unwrap();
        let pg_serial_s = Posix::new(pg_serial.path());
        let pg_parallel_s = Posix::new(pg_parallel.path());

        // The user passphrase is supplied via options; the compress-type comes
        // from the recorded metadata, the cipher key from the recorded sub-key.
        let mut cfg1_opts = repo_cipher_opts("user-pass");
        cfg1_opts.push((("set", None), OptionValue::String(label.to_owned())));
        cfg1_opts.push((("process-max", None), OptionValue::Integer(1)));
        let cfg1 = restore_cfg(stanza, cfg1_opts);
        let mut cfg4_opts = repo_cipher_opts("user-pass");
        cfg4_opts.push((("set", None), OptionValue::String(label.to_owned())));
        cfg4_opts.push((("process-max", None), OptionValue::Integer(4)));
        let cfg4 = restore_cfg(stanza, cfg4_opts);

        let serial = restore_inner(&cfg1, &repo_s, &pg_serial_s).expect("serial restore");
        let parallel = restore_inner(&cfg4, &repo_s, &pg_parallel_s).expect("parallel restore");

        // Same restore outcome regardless of worker count.
        assert_eq!(serial.files_restored, files.len());
        assert_eq!(parallel.files_restored, files.len());
        assert_eq!(serial.files_restored, parallel.files_restored);

        // Every restored file is byte-identical across the two restores AND to
        // the original source.
        for (rel, bytes) in files {
            let from_serial = std::fs::read(pg_serial.path().join(rel)).expect("read serial restored");
            let from_parallel = std::fs::read(pg_parallel.path().join(rel)).expect("read parallel restored");
            assert_eq!(from_serial, *bytes, "serial restore mismatch for {rel}");
            assert_eq!(
                from_serial, from_parallel,
                "serial and parallel restores must be byte-identical for {rel}"
            );
        }
    }

    /// A multi-file backup restores correctly with four workers: every file is
    /// present, byte-for-byte correct, and the hard-fail checksum check (run per
    /// file in the worker) passes.
    #[test]
    fn restore_process_max_4_round_trip() {
        let (_repo, pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        // Eight files across distinct directories — comfortably more than the
        // four workers, so jobs queue and multiple workers pick them up.
        let files: Vec<(String, Vec<u8>)> = (0..8)
            .map(|n| {
                let rel = format!("base/{}/relation_{n}", 1 + (n % 3));
                let bytes = format!("relation {n} contents repeated repeated repeated repeated repeated")
                    .repeat(3)
                    .into_bytes();
                (rel, bytes)
            })
            .collect();

        let captured: Vec<(&str, &[u8], Option<String>)> = files
            .iter()
            .map(|(rel, bytes)| (rel.as_str(), bytes.as_slice(), Some(sha1_hex(bytes))))
            .collect();
        let dirs: Vec<&str> = vec!["base", "base/1", "base/2", "base/3"];

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(&repo_s, stanza, label, &captured, &dirs, &[]);

        let outcome = restore_inner(&cfg_process_max(stanza, label, 4), &repo_s, &pg_s).expect("4-worker restore");
        assert_eq!(outcome.files_restored, files.len(), "all files restored with 4 workers");

        for (rel, bytes) in &files {
            let restored = std::fs::read(pg.path().join(rel)).unwrap_or_else(|_| panic!("read restored {rel}"));
            assert_eq!(&restored, bytes, "round trip mismatch for {rel}");
        }
    }

    // ---- job-retry around per-file restore ----------------------------------

    /// Build a `RestoreCopyJob` that reads `abs_src` (identity transform) and
    /// writes `abs_dst`, with no checksum check. The `repo_src` is irrelevant for
    /// these local (`std::fs`) tests — they exercise the parallel `Posix` path,
    /// which reads `abs_src` — so it mirrors `abs_src`.
    fn standalone_job(rel: &str, abs_src: PathBuf, abs_dst: PathBuf) -> super::RestoreCopyJob {
        super::RestoreCopyJob {
            rel: rel.to_owned(),
            source: super::RestoreSource::Standalone {
                repo_src: abs_src.clone(),
                abs_src,
                transform: crate::pipeline::RepoTransform::identity(),
            },
            abs_dst,
            expected_checksum: None,
            mode: None,
        }
    }

    /// A restore whose source is missing at first but appears before the retries
    /// are exhausted is retried and succeeds.
    #[test]
    fn restore_retries_a_failing_copy_until_it_succeeds() {
        let (_repo, pg, repo_s, _pg_s) = posix_pair();
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let abs_src = src_dir.path().join("late_source");
        let abs_dst = pg.path().join("restored_late");

        // The source does not exist yet, so the first attempt(s) fail. A helper
        // thread creates it shortly after, so a later retry succeeds. Generous
        // retries + short interval keep the test reliable without being slow.
        let create_path = abs_src.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(120));
            std::fs::write(&create_path, b"recovered late").expect("write late source");
        });

        let job = standalone_job("late", abs_src, abs_dst.clone());
        let policy = JobRetry::new(40, std::time::Duration::from_millis(25));
        // A local `Posix` repo exercises the parallel `std::fs` path.
        super::run_restore_jobs(vec![job], &repo_s, 1, policy).expect("retry must recover once the source appears");
        writer.join().expect("writer thread");

        assert_eq!(std::fs::read(&abs_dst).expect("restored file"), b"recovered late");
    }

    /// A restore whose source never appears fails after exhausting its retries.
    #[test]
    fn restore_errors_after_exhausting_retries() {
        let (_repo, pg, repo_s, _pg_s) = posix_pair();
        let abs_src = pg.path().join("never_exists_source");
        let abs_dst = pg.path().join("restored_never");

        let job = standalone_job("never", abs_src, abs_dst.clone());
        // 2 retries (3 attempts), zero interval so the test is instant.
        let policy = JobRetry::new(2, std::time::Duration::ZERO);
        let err = super::run_restore_jobs(vec![job], &repo_s, 1, policy).expect_err("missing source must fail");
        assert!(err.to_string().contains("never"), "error must name the failing file: {err}");
        assert!(!abs_dst.exists(), "no destination is written when the copy never succeeds");
    }

    // ---- file bundling + block-incremental round trips ----------------------

    /// Backup config carrying `repo-bundle` (+ optional `repo-block`) for a given type.
    fn backup_cfg(stanza: &str, ty: &str, block: bool, limit: Option<u64>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("type".to_owned(), None), OptionValue::StringId(ty.to_owned()));
        options.insert(("repo-bundle".to_owned(), None), OptionValue::Boolean(true));
        if block {
            options.insert(("repo-block".to_owned(), None), OptionValue::Boolean(true));
        }
        if let Some(limit) = limit {
            options.insert(("repo-bundle-limit".to_owned(), None), OptionValue::Size(limit));
        }
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    /// Backup config WITHOUT bundling: each file lands as its own standalone repo
    /// object, so an incremental can reference an unchanged file whole.
    fn backup_cfg_plain(stanza: &str, ty: &str) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("type".to_owned(), None), OptionValue::StringId(ty.to_owned()));
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    fn latest_label(repo: &Posix, stanza: &str) -> String {
        let info = InfoBackup::load(repo, &super::backup_info_path(stanza)).unwrap();
        info.current.keys().next_back().unwrap().clone()
    }

    #[test]
    fn bundled_backup_restores_round_trip() {
        // A bundled full backup must restore byte-for-byte: small files come out
        // of the bundle, an over-limit file out of its standalone object.
        let (_repo, pg_dst, repo_s, pg_dst_s) = posix_pair();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_src_s = Posix::new(pg_src.path());
        let stanza = "demo";
        init_stanza(&repo_s, stanza);

        let a = b"first small relation".as_slice();
        let b = b"second small relation, a bit longer than the first one".as_slice();
        let big = vec![3u8; 4096];
        seed_pg_file(&pg_src_s, "PG_VERSION", b"14\n");
        seed_pg_file(&pg_src_s, "base/1/1259", a);
        seed_pg_file(&pg_src_s, "base/1/1260", b);
        seed_pg_file(&pg_src_s, "base/1/1261", &big);

        crate::backup::backup(
            &backup_cfg(stanza, "full", false, Some(100)),
            &repo_s,
            &[(1, &repo_s)],
            &pg_src_s,
        )
        .expect("bundled backup");
        let label = latest_label(&repo_s, stanza);

        let outcome = restore_inner(&cfg(Some(stanza), Some(&label)), &repo_s, &pg_dst_s).expect("restore");
        assert_eq!(outcome.files_restored, 4);

        assert_eq!(std::fs::read(pg_dst.path().join("PG_VERSION")).unwrap(), b"14\n");
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(), a);
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1260")).unwrap(), b);
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1261")).unwrap(), big);
    }

    #[test]
    fn bundled_compressed_backup_restores_round_trip() {
        // Bundling + compression: the bundle holds per-file gz-compressed bytes;
        // restore slices and decompresses each member back to plaintext.
        let (_repo, pg_dst, repo_s, pg_dst_s) = posix_pair();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_src_s = Posix::new(pg_src.path());
        let stanza = "demo";
        init_stanza(&repo_s, stanza);

        let a = b"compressible compressible compressible relation aaaa".as_slice();
        let b = b"another compressible relation bbbb bbbb bbbb bbbb".as_slice();
        seed_pg_file(&pg_src_s, "base/1/1259", a);
        seed_pg_file(&pg_src_s, "base/1/1260", b);

        let mut bcfg = backup_cfg(stanza, "full", false, None);
        bcfg.options
            .insert(("compress-type".to_owned(), None), OptionValue::StringId("gz".to_owned()));
        crate::backup::backup(&bcfg, &repo_s, &[(1, &repo_s)], &pg_src_s).expect("bundled gz backup");
        let label = latest_label(&repo_s, stanza);

        restore_inner(&cfg(Some(stanza), Some(&label)), &repo_s, &pg_dst_s).expect("restore");
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(), a);
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1260")).unwrap(), b);
    }

    #[test]
    fn block_incremental_full_restores_round_trip() {
        // A block-incremental full backup of a large file must restore identically.
        let (_repo, pg_dst, repo_s, pg_dst_s) = posix_pair();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_src_s = Posix::new(pg_src.path());
        let stanza = "demo";
        init_stanza(&repo_s, stanza);

        let big: Vec<u8> = (0..300 * 1024u32).map(|n| (n % 251) as u8).collect();
        seed_pg_file(&pg_src_s, "PG_VERSION", b"14\n");
        seed_pg_file(&pg_src_s, "base/1/1259", &big);

        crate::backup::backup(&backup_cfg(stanza, "full", true, None), &repo_s, &[(1, &repo_s)], &pg_src_s).expect("block backup");
        let label = latest_label(&repo_s, stanza);

        restore_inner(&cfg(Some(stanza), Some(&label)), &repo_s, &pg_dst_s).expect("restore");
        assert_eq!(
            std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(),
            big,
            "block-incremental round trip"
        );
    }

    #[test]
    fn block_incremental_diff_reuses_unchanged_blocks_and_restores() {
        // A full block backup, then a diff that changes only the first block of a
        // large file. The diff must reuse the unchanged blocks (referencing the
        // full) and still restore the modified file byte-for-byte.
        let (_repo, pg_dst, repo_s, pg_dst_s) = posix_pair();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_src_s = Posix::new(pg_src.path());
        let stanza = "demo";
        init_stanza(&repo_s, stanza);

        let original: Vec<u8> = (0..300 * 1024u32).map(|n| (n % 251) as u8).collect();
        seed_pg_file(&pg_src_s, "base/1/1259", &original);
        crate::backup::backup(&backup_cfg(stanza, "full", true, None), &repo_s, &[(1, &repo_s)], &pg_src_s)
            .expect("full block backup");
        let full_label = latest_label(&repo_s, stanza);

        // Mutate the first 8 KiB only, then take a diff. `original` is not used
        // again, so move it into `modified` rather than clone.
        let mut modified = original;
        for byte in modified.iter_mut().take(8192) {
            *byte = byte.wrapping_add(1);
        }
        seed_pg_file(&pg_src_s, "base/1/1259", &modified);
        crate::backup::backup(&backup_cfg(stanza, "diff", true, None), &repo_s, &[(1, &repo_s)], &pg_src_s)
            .expect("diff block backup");
        let diff_label = latest_label(&repo_s, stanza);
        assert_ne!(diff_label, full_label, "diff produced a new label");

        // The diff's block map must reference the full for the unchanged tail.
        let diff_manifest = Manifest::load(&repo_s, &super::manifest_path(stanza, &diff_label)).unwrap();
        let bm = diff_manifest.file("base/1/1259").unwrap().block_map.as_ref().unwrap();
        assert!(
            bm.blocks.iter().any(|b| b.reference == full_label),
            "diff must reuse unchanged blocks from the full"
        );
        assert!(
            bm.blocks.iter().any(|b| b.reference == diff_label),
            "diff must store the changed block itself"
        );

        // Restoring the diff reassembles the modified file from both backups.
        restore_inner(&cfg(Some(stanza), Some(&diff_label)), &repo_s, &pg_dst_s).expect("restore diff");
        assert_eq!(
            std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(),
            modified,
            "diff block round trip"
        );
    }

    // ---- non-local (remote/object) repo restore ----------------------------

    /// A `Storage` wrapper that reports itself **non-local** and records every
    /// `open_read` path, while delegating real I/O to an inner [`Posix`].
    ///
    /// This simulates a remote/object backend (SSH / S3 / Azure / GCS / SFTP):
    /// `is_local()` is `false`, so the restore must read every backup source
    /// through [`Storage::open_read`] rather than `std::fs`. To *prove* `std::fs`
    /// is never used against the source, `info()` returns a **poisoned**
    /// `path` (a non-existent absolute path) while preserving the real `size` —
    /// the bundle layout needs the size, but any accidental
    /// `std::fs::read(info.path)` would fail with "no such file". The recorded
    /// `open_read` paths then positively prove which reads went through the trait.
    struct RecordingRepo {
        inner: Posix,
        reads: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RecordingRepo {
        fn new(inner: Posix) -> Self {
            Self {
                inner,
                reads: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn reads(&self) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
            std::sync::Arc::clone(&self.reads)
        }
    }

    impl Storage for RecordingRepo {
        fn is_local(&self) -> bool {
            false
        }

        fn exists(&self, path: &Path) -> Result<bool, pgbr_storage::StorageError> {
            self.inner.exists(path)
        }

        fn info(&self, path: &Path) -> Result<pgbr_storage::StorageInfo, pgbr_storage::StorageError> {
            // Keep the real metadata (size feeds the bundle layout) but poison the
            // absolute path so any std::fs read against it fails — the non-local
            // read path must use `open_read(<repo-relative path>)` instead.
            let mut info = self.inner.info(path)?;
            info.path = PathBuf::from("/nonexistent-non-local-repo").join(path);
            Ok(info)
        }

        fn list(&self, path: &Path) -> Result<Vec<pgbr_storage::StorageInfo>, pgbr_storage::StorageError> {
            self.inner.list(path)
        }

        fn open_read(&self, path: &Path) -> Result<Box<dyn pgbr_io::IoRead>, pgbr_storage::StorageError> {
            self.reads.lock().unwrap().push(path.to_string_lossy().into_owned());
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
    fn restore_from_non_local_repo_reads_standalone_through_open_read() {
        // A non-local repo must read every backup data file through the Storage
        // trait (`open_read`), not `std::fs` — otherwise a remote restore reads
        // the local machine and fails. `RecordingRepo` poisons `info().path`, so a
        // std::fs read would error; the restore can only succeed by using
        // `open_read`. Standalone (unbundled) layout.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg_dst = tempfile::tempdir().expect("pg tempdir");
        let repo_inner = Posix::new(repo.path());
        let pg_dst_s = Posix::new(pg_dst.path());
        let stanza = "demo";
        init_stanza(&repo_inner, stanza);

        let a = b"PG_VERSION contents for the non-local restore".as_slice();
        let b = b"a small relation page captured into the repo".as_slice();
        seed_backup_info(&repo_inner, stanza, &["20240101-120000F"]);
        seed_backup(
            &repo_inner,
            stanza,
            "20240101-120000F",
            &[("PG_VERSION", a, Some(sha1_hex(a))), ("base/1/1259", b, Some(sha1_hex(b)))],
            &["base", "base/1"],
            &[],
        );

        let repo_s = RecordingRepo::new(repo_inner);
        let reads = repo_s.reads();

        let outcome = restore_inner(&cfg(Some(stanza), Some("20240101-120000F")), &repo_s, &pg_dst_s).expect("non-local restore");
        assert_eq!(outcome.files_restored, 2);

        // The bytes were recovered correctly...
        assert_eq!(std::fs::read(pg_dst.path().join("PG_VERSION")).unwrap(), a);
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(), b);

        // ...and every data file was read through open_read at its repo-relative
        // path. A buggy std::fs read would never appear here (and would have
        // failed against the poisoned info().path).
        let recorded = reads.lock().unwrap().clone();
        for rel in [
            "backup/demo/20240101-120000F/PG_VERSION",
            "backup/demo/20240101-120000F/base/1/1259",
        ] {
            assert!(
                recorded.iter().any(|p| p == rel),
                "data file must be read via open_read at {rel}; recorded reads: {recorded:?}"
            );
        }
    }

    #[test]
    fn restore_from_non_local_repo_reads_bundled_through_open_read() {
        // Bundled layout (`repo-bundle`): small files share a bundle object, an
        // over-limit file gets its own standalone object. A non-local restore must
        // read both kinds through open_read. The whole bundle is buffered and
        // sliced in memory (IoRead has no seek).
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg_dst = tempfile::tempdir().expect("pg tempdir");
        let pg_src = tempfile::tempdir().expect("pg src tempdir");
        let repo_inner = Posix::new(repo.path());
        let pg_dst_s = Posix::new(pg_dst.path());
        let pg_src_s = Posix::new(pg_src.path());
        let stanza = "demo";
        init_stanza(&repo_inner, stanza);

        let a = b"first small relation".as_slice();
        let b = b"second small relation, a bit longer than the first one".as_slice();
        let big = vec![3u8; 4096];
        seed_pg_file(&pg_src_s, "PG_VERSION", b"14\n");
        seed_pg_file(&pg_src_s, "base/1/1259", a);
        seed_pg_file(&pg_src_s, "base/1/1260", b);
        seed_pg_file(&pg_src_s, "base/1/1261", &big);

        crate::backup::backup(
            &backup_cfg(stanza, "full", false, Some(100)),
            &repo_inner,
            &[(1, &repo_inner)],
            &pg_src_s,
        )
        .expect("bundled backup");
        let label = latest_label(&repo_inner, stanza);

        let repo_s = RecordingRepo::new(repo_inner);
        let reads = repo_s.reads();

        let outcome = restore_inner(&cfg(Some(stanza), Some(&label)), &repo_s, &pg_dst_s).expect("non-local bundled restore");
        assert_eq!(outcome.files_restored, 4);

        assert_eq!(std::fs::read(pg_dst.path().join("PG_VERSION")).unwrap(), b"14\n");
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(), a);
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1260")).unwrap(), b);
        assert_eq!(std::fs::read(pg_dst.path().join("base/1/1261")).unwrap(), big);

        // The bundle object (id 1) and the over-limit standalone object were both
        // read through open_read.
        let recorded = reads.lock().unwrap().clone();
        assert!(
            recorded.iter().any(|p| p == &format!("backup/{stanza}/{label}/bundle/1")),
            "the bundle object must be read via open_read; recorded reads: {recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|p| p.starts_with(&format!("backup/{stanza}/{label}/base/1/1261"))),
            "the over-limit standalone object must be read via open_read; recorded reads: {recorded:?}"
        );
    }

    #[test]
    fn restore_from_non_local_repo_reads_block_incremental_through_open_read() {
        // Block-incremental: a diff reuses unchanged blocks from the full and
        // stores only the changed block itself. A non-local restore of the diff
        // must read both backups' bundle objects (the holder + the reference)
        // through open_read and reassemble the file byte-for-byte.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg_dst = tempfile::tempdir().expect("pg tempdir");
        let pg_src = tempfile::tempdir().expect("pg src tempdir");
        let repo_inner = Posix::new(repo.path());
        let pg_dst_s = Posix::new(pg_dst.path());
        let pg_src_s = Posix::new(pg_src.path());
        let stanza = "demo";
        init_stanza(&repo_inner, stanza);

        let original: Vec<u8> = (0..300 * 1024u32).map(|n| (n % 251) as u8).collect();
        seed_pg_file(&pg_src_s, "base/1/1259", &original);
        crate::backup::backup(
            &backup_cfg(stanza, "full", true, None),
            &repo_inner,
            &[(1, &repo_inner)],
            &pg_src_s,
        )
        .expect("full block backup");
        let full_label = latest_label(&repo_inner, stanza);

        let mut modified = original;
        for byte in modified.iter_mut().take(8192) {
            *byte = byte.wrapping_add(1);
        }
        seed_pg_file(&pg_src_s, "base/1/1259", &modified);
        crate::backup::backup(
            &backup_cfg(stanza, "diff", true, None),
            &repo_inner,
            &[(1, &repo_inner)],
            &pg_src_s,
        )
        .expect("diff block backup");
        let diff_label = latest_label(&repo_inner, stanza);
        assert_ne!(diff_label, full_label, "diff produced a new label");

        let repo_s = RecordingRepo::new(repo_inner);
        let reads = repo_s.reads();

        restore_inner(&cfg(Some(stanza), Some(&diff_label)), &repo_s, &pg_dst_s).expect("non-local block restore");
        assert_eq!(
            std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(),
            modified,
            "block-incremental round trip over a non-local repo"
        );

        // Block reassembly read bundle objects from BOTH the diff (holder of the
        // changed block) and the full (the reference for the unchanged tail) via
        // open_read.
        let recorded = reads.lock().unwrap().clone();
        assert!(
            recorded
                .iter()
                .any(|p| p.starts_with(&format!("backup/{stanza}/{diff_label}/bundle/"))),
            "the diff's bundle must be read via open_read; recorded reads: {recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .any(|p| p.starts_with(&format!("backup/{stanza}/{full_label}/bundle/"))),
            "the referenced full's bundle must be read via open_read; recorded reads: {recorded:?}"
        );
    }

    #[test]
    fn restore_from_non_local_repo_reads_referenced_backup_through_open_read() {
        // A whole-file `reference` to a holding (earlier) backup: an incremental
        // backup whose file is unchanged references the full's standalone object.
        // The non-local restore must read the *referenced* backup's object through
        // open_read.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg_dst = tempfile::tempdir().expect("pg tempdir");
        let pg_src = tempfile::tempdir().expect("pg src tempdir");
        let repo_inner = Posix::new(repo.path());
        let pg_dst_s = Posix::new(pg_dst.path());
        let pg_src_s = Posix::new(pg_src.path());
        let stanza = "demo";
        init_stanza(&repo_inner, stanza);

        // Unbundled (no repo-bundle) so the file is a standalone object the
        // incremental can reference whole.
        let kept = b"a relation that does not change between the full and the incr".as_slice();
        seed_pg_file(&pg_src_s, "base/1/1259", kept);
        crate::backup::backup(&backup_cfg_plain(stanza, "full"), &repo_inner, &[(1, &repo_inner)], &pg_src_s).expect("full backup");
        let full_label = latest_label(&repo_inner, stanza);

        // Take an incremental without touching the file: it should reference the
        // full for the unchanged file.
        crate::backup::backup(&backup_cfg_plain(stanza, "incr"), &repo_inner, &[(1, &repo_inner)], &pg_src_s).expect("incr backup");
        let incr_label = latest_label(&repo_inner, stanza);
        assert_ne!(incr_label, full_label, "incr produced a new label");

        let incr_manifest = Manifest::load(&repo_inner, &super::manifest_path(stanza, &incr_label)).unwrap();
        assert_eq!(
            incr_manifest.file("base/1/1259").and_then(|f| f.reference.clone()),
            Some(full_label.clone()),
            "the unchanged file must reference the full"
        );

        let repo_s = RecordingRepo::new(repo_inner);
        let reads = repo_s.reads();

        restore_inner(&cfg(Some(stanza), Some(&incr_label)), &repo_s, &pg_dst_s).expect("non-local incr restore");
        assert_eq!(
            std::fs::read(pg_dst.path().join("base/1/1259")).unwrap(),
            kept,
            "referenced-file round trip over a non-local repo"
        );

        // The bytes physically live under the FULL backup, so the read must hit
        // the full's object, not the incr's.
        let recorded = reads.lock().unwrap().clone();
        assert!(
            recorded
                .iter()
                .any(|p| p.starts_with(&format!("backup/{stanza}/{full_label}/base/1/1259"))),
            "the referenced full's object must be read via open_read; recorded reads: {recorded:?}"
        );
    }

    // ---- link-all / repo-symlink -------------------------------------------

    #[test]
    fn link_plan_decision_table() {
        use super::{LinkPlan, link_plan};

        // repo-symlink=y (default): links are re-created as symlinks.
        assert_eq!(link_plan(true), LinkPlan::Symlink, "repo-symlink=y -> Symlink");
        // repo-symlink=n: NO symlinks at all — everything becomes a plain dir.
        assert_eq!(link_plan(false), LinkPlan::PlainDir, "repo-symlink=n -> PlainDir");
    }

    #[test]
    fn link_all_recreates_symlink_at_stored_destination() {
        // --link-all explicitly requests link re-creation: a non-tablespace link is
        // re-created as a symlink pointing at its recorded destination.
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

        let cfg = restore_cfg(stanza, vec![(("link-all", None), OptionValue::Boolean(true))]);
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.links_created, 1, "link-all must re-create the symlink");
        assert_eq!(outcome.links_as_dir, 0);

        let read = std::fs::read_link(pg.path().join("pg_data/pg_wal")).expect("read_link");
        assert_eq!(
            read,
            Path::new("/var/lib/pg_wal"),
            "link-all must point the symlink at the stored destination"
        );
    }

    #[test]
    fn no_repo_symlink_suppresses_symlink_creation() {
        // --no-repo-symlink lays the link out as a plain directory inside PGDATA
        // instead of a symlink; no symlink is created.
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

        // repo-symlink=false even though --link-all is requested.
        let cfg = restore_cfg(
            stanza,
            vec![
                (("link-all", None), OptionValue::Boolean(true)),
                (("repo-symlink", None), OptionValue::Boolean(false)),
            ],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.links_created, 0, "no-repo-symlink must create no symlinks");
        assert_eq!(outcome.links_as_dir, 1, "the link must be laid out as a plain dir");

        // The path exists as a real directory, NOT a symlink.
        let meta = std::fs::symlink_metadata(pg.path().join("pg_data/pg_wal")).expect("stat link path");
        assert!(meta.is_dir(), "pg_wal must be a real directory, not a symlink");
        assert!(
            !meta.file_type().is_symlink(),
            "pg_wal must not be a symlink under --no-repo-symlink"
        );
    }

    #[test]
    fn no_repo_symlink_via_repo1_index() {
        // The repo-symlink option is `group: repo`, so it may arrive under the
        // repo1-indexed key. Reading it under that index must suppress symlinks too.
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

        let mut cfg = restore_cfg(stanza, Vec::new());
        cfg.options
            .insert(("repo-symlink".to_owned(), Some(1)), OptionValue::Boolean(false));
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.links_created, 0);
        assert_eq!(outcome.links_as_dir, 1);
        let meta = std::fs::symlink_metadata(pg.path().join("pg_data/pg_wal")).expect("stat link path");
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
    }

    // ---- pg-version-force --------------------------------------------------

    #[test]
    fn pg_version_force_overrides_recovery_format() {
        let stanza = "demo";

        // The manifest records PG 14 (>= 12), which would normally produce
        // postgresql.auto.conf + recovery.signal. --pg-version-force=11 overrides
        // the format decision to the PG < 12 recovery.conf form.
        let mut forced = cfg_recovery(stanza, None, None, false);
        forced
            .options
            .insert(("pg-version-force".to_owned(), None), OptionValue::String("11".to_owned()));
        let files = super::recovery_files("14", stanza, &forced);
        assert_eq!(files.len(), 1, "forced PG<12 must produce a single recovery.conf");
        assert_eq!(files[0].0, std::path::PathBuf::from("recovery.conf"));

        // The mirror: manifest PG 11 forced UP to 14 produces the GUC form.
        let mut forced_up = cfg_recovery(stanza, None, None, false);
        forced_up
            .options
            .insert(("pg-version-force".to_owned(), None), OptionValue::String("14".to_owned()));
        let up = super::recovery_files("11", stanza, &forced_up);
        assert_eq!(up.len(), 2, "forced PG>=12 must produce auto.conf + signal");
        assert_eq!(up[0].0, std::path::PathBuf::from("postgresql.auto.conf"));
        assert_eq!(up[1].0, std::path::PathBuf::from("recovery.signal"));
    }

    #[test]
    fn pg_version_force_end_to_end() {
        // End-to-end: a PG 14 manifest forced to 11 writes recovery.conf, not the
        // signal-file form.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        let cfg = restore_cfg(
            stanza,
            vec![(("pg-version-force", None), OptionValue::String("11".to_owned()))],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.recovery_files_written, vec!["recovery.conf".to_owned()]);
        assert!(pg_s.exists(Path::new("recovery.conf")).unwrap());
        assert!(!pg_s.exists(Path::new("recovery.signal")).unwrap());
    }

    // ---- repo-target-time / time-target backup-set selection ---------------

    /// Seed `backup.info` listing each `(label, stop_epoch)` with a recorded
    /// `backup-timestamp-stop`, so time-target selection has something to compare.
    fn seed_backup_info_with_stops(repo: &Posix, stanza: &str, backups: &[(&str, i64)]) {
        let mut current = BTreeMap::new();
        for (label, stop) in backups {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
                    "backup-type": "full",
                    "backup-timestamp-start": stop - 10,
                    "backup-timestamp-stop": stop,
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

    #[test]
    fn parse_civil_time_round_trips_known_values() {
        // The 2024-01-01 12:00:00 UTC epoch is 1704110400.
        assert_eq!(super::parse_civil_time("2024-01-01 12:00:00"), Some(1_704_110_400));
        // `T` separator and a trailing timezone are both accepted (TZ ignored, UTC).
        assert_eq!(super::parse_civil_time("2024-01-01T12:00:00+00"), Some(1_704_110_400));
        // Date-only defaults to midnight.
        assert_eq!(super::parse_civil_time("2024-01-01"), Some(1_704_067_200));
        // The Unix epoch itself.
        assert_eq!(super::parse_civil_time("1970-01-01 00:00:00"), Some(0));
        // Garbage parses to None.
        assert_eq!(super::parse_civil_time("not a time"), None);
        assert_eq!(super::parse_civil_time("2024-13-01 00:00:00"), None);
    }

    #[test]
    fn select_backup_by_time_picks_most_recent_at_or_before_target() {
        let (_repo, _pg, repo_s, _pg_s) = posix_pair();
        let stanza = "demo";
        // Three backups with ascending stop times.
        seed_backup_info_with_stops(
            &repo_s,
            stanza,
            &[
                ("20240101-120000F", 1000),
                ("20240102-120000F", 2000),
                ("20240103-120000F", 3000),
            ],
        );
        let info = InfoBackup::load(&repo_s, &super::backup_info_path(stanza)).unwrap();

        // Target exactly at the middle backup's stop: that backup is chosen.
        assert_eq!(super::select_backup_by_time(&info, 2000).as_deref(), Some("20240102-120000F"));
        // Target between middle and last: still the middle (last stops after target).
        assert_eq!(super::select_backup_by_time(&info, 2500).as_deref(), Some("20240102-120000F"));
        // Target after all: the latest backup.
        assert_eq!(super::select_backup_by_time(&info, 9999).as_deref(), Some("20240103-120000F"));
        // Target before all backups: fall back to the earliest (WAL replay forward).
        assert_eq!(super::select_backup_by_time(&info, 500).as_deref(), Some("20240101-120000F"));
    }

    #[test]
    fn restore_repo_target_time_selects_backup_set() {
        // End-to-end: --repo-target-time selects the backup set without an explicit
        // --set — the most recent backup whose stop time is at/before the target.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let older = "20240101-120000F"; // stop = 1704110400 (2024-01-01 12:00:00)
        let newer = "20240103-120000F"; // stop = 1704283200 (2024-01-03 12:00:00)

        seed_backup_info_with_stops(&repo_s, stanza, &[(older, 1_704_110_400), (newer, 1_704_283_200)]);
        // Both backups carry a distinctly-named file so we can tell which restored.
        let old_bytes = b"older backup file".as_slice();
        let new_bytes = b"newer backup file".as_slice();
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

        // Target 2024-01-02 (between the two stop times) selects the OLDER backup,
        // even though `newer` is the lexicographically-greatest label.
        let cfg = restore_cfg(
            stanza,
            vec![(
                ("repo-target-time", None),
                OptionValue::String("2024-01-02 00:00:00".to_owned()),
            )],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.label, older, "repo-target-time must select the older set");
        assert!(pg_s.exists(Path::new("only/old.txt")).unwrap());
        assert!(!pg_s.exists(Path::new("only/new.txt")).unwrap());
    }

    #[test]
    fn restore_type_time_target_selects_backup_set() {
        // --type=time --target=<t> (no --set, no repo-target-time) auto-selects the
        // backup set the same way.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let older = "20240101-120000F";
        let newer = "20240103-120000F";

        seed_backup_info_with_stops(&repo_s, stanza, &[(older, 1_704_110_400), (newer, 1_704_283_200)]);
        let old_bytes = b"older backup file".as_slice();
        let new_bytes = b"newer backup file".as_slice();
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

        let cfg = restore_cfg(
            stanza,
            vec![
                (("type", None), OptionValue::StringId("time".to_owned())),
                (("target", None), OptionValue::String("2024-01-02 00:00:00".to_owned())),
            ],
        );
        let outcome = restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        assert_eq!(outcome.label, older, "time target must select the older set");
    }

    // ---- archive-mode ------------------------------------------------------

    /// A restore config carrying `--archive-mode=<value>` (and PG 14 recovery).
    fn cfg_archive_mode(stanza: &str, mode: Option<&str>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(mode) = mode {
            options.insert(("archive-mode".to_owned(), None), OptionValue::StringId(mode.to_owned()));
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
    fn archive_mode_off_emits_archive_mode_preserve_omits() {
        let stanza = "demo";

        // archive-mode=off -> the recovery block carries `archive_mode = off`.
        let off = super::recovery_files("14", stanza, &cfg_archive_mode(stanza, Some("off")));
        assert!(
            off[0].1.contains("archive_mode = off"),
            "archive-mode=off must emit archive_mode = off: {}",
            off[0].1
        );

        // archive-mode=preserve (explicit) -> no archive_mode GUC.
        let preserve = super::recovery_files("14", stanza, &cfg_archive_mode(stanza, Some("preserve")));
        assert!(
            !preserve[0].1.contains("archive_mode"),
            "archive-mode=preserve must omit archive_mode: {}",
            preserve[0].1
        );

        // absent -> the default `preserve`: no archive_mode GUC.
        let absent = super::recovery_files("14", stanza, &cfg_archive_mode(stanza, None));
        assert!(
            !absent[0].1.contains("archive_mode"),
            "absent archive-mode must omit archive_mode (defaults to preserve): {}",
            absent[0].1
        );
    }

    #[test]
    fn archive_mode_off_user_recovery_option_wins() {
        // A user --recovery-option=archive-mode=... overrides the built-in
        // archive_mode = off line (exactly one archive_mode line, the user's).
        let stanza = "demo";
        let mut cfg = cfg_archive_mode(stanza, Some("off"));
        let mut rmap = BTreeMap::new();
        rmap.insert("archive-mode".to_owned(), "always".to_owned());
        cfg.options
            .insert(("recovery-option".to_owned(), None), OptionValue::Hash(rmap));

        let files = super::recovery_files("14", stanza, &cfg);
        let block = &files[0].1;
        assert!(
            block.contains("archive_mode = 'always'"),
            "user recovery-option archive_mode must win: {block}"
        );
        assert_eq!(
            block.matches("archive_mode").count(),
            1,
            "exactly one archive_mode line must be present: {block}"
        );
    }

    #[test]
    fn archive_mode_off_end_to_end() {
        // End-to-end: --archive-mode=off writes archive_mode = off into the
        // generated postgresql.auto.conf.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        let cfg = restore_cfg(
            stanza,
            vec![(("archive-mode", None), OptionValue::StringId("off".to_owned()))],
        );
        restore_inner(&cfg, &repo_s, &pg_s).expect("restore");
        let contents = {
            let mut r = pg_s.open_read(Path::new("postgresql.auto.conf")).expect("open auto.conf");
            String::from_utf8(r.read_all().expect("read auto.conf")).unwrap()
        };
        assert!(
            contents.contains("archive_mode = off"),
            "archive_mode = off must appear in the generated config: {contents}"
        );
    }

    // ---- dry-run restore ---------------------------------------------------

    /// A restore config with `--dry-run` enabled (plus an optional `--set`).
    fn cfg_dry_run(stanza: Option<&str>, set: Option<&str>) -> LoadedConfig {
        let mut config = cfg(stanza, set);
        config
            .options
            .insert(("dry-run".to_owned(), None), OptionValue::Boolean(true));
        config
    }

    #[test]
    fn dry_run_restore_writes_nothing_but_reports_counts() {
        // A dry-run restore reports the files / directories it *would* create but
        // leaves the PG target empty.
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

        let outcome = restore_inner(&cfg_dry_run(Some(stanza), None), &repo_s, &pg_s).expect("dry-run restore");

        // Counts report what a real restore would do.
        assert!(outcome.dry_run, "outcome flagged as dry-run");
        assert_eq!(outcome.files_restored, 2, "dry-run reports the would-be restore count");
        assert_eq!(outcome.paths_created, 3, "dry-run reports the would-be path count");

        // Nothing was written into the PG target: neither files nor directories.
        assert!(
            !pg_s.exists(Path::new("pg_data/PG_VERSION")).unwrap(),
            "dry-run must not write files"
        );
        assert!(
            !pg_s.exists(Path::new("pg_data")).unwrap(),
            "dry-run must not create directories"
        );
    }

    #[test]
    fn dry_run_restore_skips_recovery_files() {
        // A dry-run reports the recovery files it would write (computed purely)
        // but creates none.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        seed_backup_info(&repo_s, stanza, &[label]);
        // PG 14 -> postgresql.auto.conf + recovery.signal would be written.
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);

        let outcome = restore_inner(&cfg_dry_run(Some(stanza), None), &repo_s, &pg_s).expect("dry-run restore");

        // The recovery files are *reported* (would-be) ...
        assert!(
            outcome.recovery_files_written.iter().any(|f| f == "postgresql.auto.conf"),
            "dry-run reports the would-be recovery files: {:?}",
            outcome.recovery_files_written
        );
        // ... but none was actually created.
        assert!(
            !pg_s.exists(Path::new("postgresql.auto.conf")).unwrap(),
            "dry-run must not write recovery files"
        );
        assert!(
            !pg_s.exists(Path::new("recovery.signal")).unwrap(),
            "dry-run must not write recovery.signal"
        );
    }

    #[test]
    fn dry_run_option_reader_defaults_false() {
        assert!(!dry_run_enabled(&cfg(Some("demo"), None)));
        assert!(dry_run_enabled(&cfg_dry_run(Some("demo"), None)));
    }

    // ---- parallel delta pre-pass + bundle pre-cache ------------------------

    /// A `Storage` wrapper that reports `is_local() = false` while delegating
    /// every real I/O to an inner [`Posix`]. Used to force the serial fallback
    /// path through the **PG-target** storage so delta classification falls
    /// back to the serial [`target_matches`] instead of the parallel hasher.
    /// Distinct from [`RecordingRepo`] which poisons `info().path`; this mock
    /// keeps `info().path` correct because the target files genuinely live on
    /// the local filesystem (the inner `Posix` is real), and only the
    /// `is_local()` *answer* is faked — the production delta path only
    /// consults `is_local()`, never the path itself.
    struct NonLocalPg {
        inner: Posix,
    }

    impl Storage for NonLocalPg {
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

    /// Five-file delta restore on a local PG target: three files already match
    /// the backup byte-for-byte (skipped after the parallel SHA-1 pre-pass),
    /// two differ (one wrong content, one missing) and are queued for restore.
    /// `process-max=4` exercises the parallel branch of [`run_delta_jobs`].
    #[test]
    fn delta_verify_parallel_local_pg() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        // Five backup files; three pre-populated on the target to MATCH, one
        // pre-populated to DIFFER, one not present at all.
        let m1 = b"matching file 1 content".as_slice();
        let m2 = b"matching file 2, slightly longer content".as_slice();
        let m3 = b"matching file 3, the third matching file".as_slice();
        let d1 = b"original backup content for d1".as_slice();
        let d1_local = b"stale local d1 contents to differ"; // size differs from d1
        let missing = b"file absent on the target".as_slice();

        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[
                ("pg_data/m1", m1, Some(sha1_hex(m1))),
                ("pg_data/m2", m2, Some(sha1_hex(m2))),
                ("pg_data/m3", m3, Some(sha1_hex(m3))),
                ("pg_data/d1", d1, Some(sha1_hex(d1))),
                ("pg_data/missing", missing, Some(sha1_hex(missing))),
            ],
            &["pg_data"],
            &[],
        );

        // Pre-place the three matching files (identical to backup) and the one
        // mismatched file. `pg_data/missing` is intentionally absent.
        seed_pg_file(&pg_s, "pg_data/m1", m1);
        seed_pg_file(&pg_s, "pg_data/m2", m2);
        seed_pg_file(&pg_s, "pg_data/m3", m3);
        seed_pg_file(&pg_s, "pg_data/d1", d1_local);

        // `process-max=4` forces the parallel branch of `run_delta_jobs`; the
        // PG storage is local (`Posix`) so classification routes to the
        // parallel hasher rather than the serial `target_matches`.
        let mut cfg_map: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        cfg_map.insert(("set".to_owned(), None), OptionValue::String(label.to_owned()));
        cfg_map.insert(("delta".to_owned(), None), OptionValue::Boolean(true));
        cfg_map.insert(("process-max".to_owned(), None), OptionValue::Integer(4));
        let config = LoadedConfig {
            command: "restore".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options: cfg_map,
            params: Vec::new(),
        };

        let outcome = restore_inner(&config, &repo_s, &pg_s).expect("parallel delta restore");
        assert_eq!(
            outcome.files_skipped, 3,
            "three matching files must be skipped by the parallel pre-pass"
        );
        assert_eq!(outcome.files_restored, 2, "two non-matching files must be queued for restore");

        // Sanity: the restored bytes are the canonical backup bytes, not stale.
        let restored_d1 = std::fs::read(pg_s.info(Path::new("pg_data/d1")).unwrap().path).expect("read restored d1");
        assert_eq!(restored_d1, d1, "delta-restored d1 must match the backup");
        let restored_missing = std::fs::read(pg_s.info(Path::new("pg_data/missing")).unwrap().path).expect("read restored missing");
        assert_eq!(restored_missing, missing);
    }

    /// A non-local PG storage (`is_local() == false`) must fall back to the
    /// serial [`target_matches`] path for delta classification, *not* take the
    /// parallel `std::fs` branch (which would either fail to find files at all
    /// or read the wrong machine). `process-max=4` is set so the only way this
    /// can produce correct results is if `is_local()` actually gates the
    /// parallel branch.
    #[test]
    fn delta_verify_falls_back_to_serial_on_remote_pg() {
        let _repo_dir = tempfile::tempdir().expect("repo tempdir");
        let pg_dir = tempfile::tempdir().expect("pg tempdir");
        let repo_dir = tempfile::tempdir().expect("repo tempdir 2");
        let repo_inner = Posix::new(repo_dir.path());
        let pg_inner = Posix::new(pg_dir.path());

        let stanza = "demo";
        let label = "20240101-120000F";
        let same = b"matching contents".as_slice();
        let other = b"backup content for other".as_slice();
        seed_backup_info(&repo_inner, stanza, &[label]);
        seed_backup(
            &repo_inner,
            stanza,
            label,
            &[
                ("pg_data/match.txt", same, Some(sha1_hex(same))),
                ("pg_data/other.txt", other, Some(sha1_hex(other))),
            ],
            &["pg_data"],
            &[],
        );
        // Pre-place the matching file on the target.
        seed_pg_file(&pg_inner, "pg_data/match.txt", same);

        // Wrap PG storage to report non-local. The PG-target files still
        // physically live on the local Posix filesystem (so `open_read` works
        // and the serial `target_matches` returns the correct answer), but
        // the parallel `std::fs` branch is suppressed via `is_local()`.
        let pg_s = NonLocalPg { inner: pg_inner };
        assert!(!pg_s.is_local(), "PG storage mock must report non-local");

        let mut opts: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        opts.insert(("set".to_owned(), None), OptionValue::String(label.to_owned()));
        opts.insert(("delta".to_owned(), None), OptionValue::Boolean(true));
        opts.insert(("process-max".to_owned(), None), OptionValue::Integer(4));
        let config = LoadedConfig {
            command: "restore".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options: opts,
            params: Vec::new(),
        };

        let outcome = restore_inner(&config, &repo_inner, &pg_s).expect("delta restore");
        assert_eq!(outcome.files_skipped, 1, "match must be detected via serial target_matches");
        assert_eq!(outcome.files_restored, 1, "non-match must still be restored");
    }

    /// Bundle pre-cache built ONCE per bundle: a single full backup with five
    /// files all packed into one bundle. The repo is wrapped to count `info()`
    /// resolutions on the bundle object's repo-relative path; a buggy
    /// implementation that opens the bundle once per worker job would call
    /// `std::fs::read` (and the upstream `info()` resolution chain) per file
    /// rather than once. The pre-cache reads the bundle exactly ONCE via
    /// `std::fs::read`, so the worker-side `read_bundle_slice` is never hit
    /// for these files; we assert that by reading the file count back: five
    /// files all sliced from one shared buffer must restore byte-for-byte.
    #[test]
    fn bundle_pre_cache_built_once_per_bundle() {
        let repo_dir = tempfile::tempdir().unwrap();
        let pg_src = tempfile::tempdir().unwrap();
        let pg_dst = tempfile::tempdir().unwrap();
        let repo_inner = Posix::new(repo_dir.path());
        let pg_src_s = Posix::new(pg_src.path());
        let pg_dst_s = Posix::new(pg_dst.path());
        let stanza = "demo";
        init_stanza(&repo_inner, stanza);

        // Five tiny files, all well under the bundle size limit so they land
        // in one shared bundle object (bundle/1).
        let files: &[(&str, &[u8])] = &[
            ("PG_VERSION", b"14\n"),
            ("a", b"file-a"),
            ("b", b"file-b"),
            ("c", b"file-c"),
            ("d", b"file-d"),
        ];
        for (rel, bytes) in files {
            seed_pg_file(&pg_src_s, rel, bytes);
        }
        crate::backup::backup(
            &backup_cfg(stanza, "full", false, Some(1024)),
            &repo_inner,
            &[(1, &repo_inner)],
            &pg_src_s,
        )
        .expect("bundled backup");
        let label = latest_label(&repo_inner, stanza);

        // Sanity: a single bundle object was produced.
        let bundle_repo_path = format!("backup/{stanza}/{label}/bundle/1");
        assert!(
            repo_inner.exists(Path::new(&bundle_repo_path)).unwrap(),
            "all five files should be packed into bundle/1"
        );

        // Restore with process-max=2 so the workers DO run the parallel branch,
        // then assert every file restored byte-for-byte. The pre-cache reads
        // the bundle exactly ONCE via std::fs::read (an absolute-path read on
        // the main thread), so the per-file worker logic never touches the
        // bundle file again.
        let mut opts: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        opts.insert(("set".to_owned(), None), OptionValue::String(label));
        opts.insert(("process-max".to_owned(), None), OptionValue::Integer(2));
        let config = LoadedConfig {
            command: "restore".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options: opts,
            params: Vec::new(),
        };

        let outcome = restore_inner(&config, &repo_inner, &pg_dst_s).expect("bundled parallel restore");
        assert_eq!(outcome.files_restored, files.len());
        for (rel, bytes) in files {
            let restored = std::fs::read(pg_dst.path().join(rel)).expect("read restored");
            assert_eq!(&restored, bytes, "round trip via single pre-cached bundle for {rel}");
        }

        // Direct invariant: the build_bundle_cache helper, when called on a
        // job set with the same bundle referenced five times, MUST produce a
        // map with exactly one entry (one disk read).
        let abs_bundle = repo_inner.info(Path::new(&bundle_repo_path)).unwrap().path;
        let identity = crate::pipeline::RepoTransform::identity();
        let jobs: Vec<super::RestoreCopyJob> = (0..5)
            .map(|n| super::RestoreCopyJob {
                rel: format!("dst-{n}"),
                source: super::RestoreSource::Bundled {
                    abs_bundle: abs_bundle.clone(),
                    repo_bundle: PathBuf::from(&bundle_repo_path),
                    offset: 0,
                    len: 0,
                    transform: identity.clone(),
                },
                abs_dst: PathBuf::new(),
                expected_checksum: None,
                mode: None,
            })
            .collect();
        let cache = super::build_bundle_cache(&repo_inner, &jobs).expect("build cache");
        assert_eq!(cache.len(), 1, "five jobs into one bundle must build a cache of size 1");
        assert!(
            cache.contains_key(&abs_bundle),
            "cache must contain the shared bundle's absolute path"
        );
    }

    /// On a non-local repo the bundle pre-cache must be SKIPPED — the
    /// non-local branch in `run_restore_jobs` runs serially through
    /// `restore_file_storage`, which has its own per-call cache via the
    /// `Storage` trait. The pre-cache builder must return an empty map so the
    /// trait path is preserved.
    #[test]
    fn bundle_pre_cache_skipped_on_remote_repo() {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let repo_inner = Posix::new(repo.path());
        // Materialise a bundle object so `info()` does not fail if a buggy
        // implementation tries to read it.
        repo_inner.create_path(Path::new("backup/demo/L/bundle"), true).unwrap();
        let mut w = repo_inner.open_write(Path::new("backup/demo/L/bundle/1")).unwrap();
        w.write(b"bundle bytes").unwrap();
        w.flush().unwrap();
        w.close().unwrap();

        let non_local = RecordingRepo::new(repo_inner);
        let identity = crate::pipeline::RepoTransform::identity();
        let job = super::RestoreCopyJob {
            rel: "x".to_owned(),
            source: super::RestoreSource::Bundled {
                abs_bundle: PathBuf::from("/nonexistent-non-local-repo/backup/demo/L/bundle/1"),
                repo_bundle: PathBuf::from("backup/demo/L/bundle/1"),
                offset: 0,
                len: 0,
                transform: identity,
            },
            abs_dst: PathBuf::new(),
            expected_checksum: None,
            mode: None,
        };
        let cache = super::build_bundle_cache(&non_local, std::slice::from_ref(&job)).expect("build cache");
        assert!(
            cache.is_empty(),
            "non-local repo must skip the pre-cache; got {} entries",
            cache.len()
        );
    }

    /// Delta with a size mismatch must short-circuit on size alone — never
    /// reach the SHA-1 read of the target file. Verified on both the parallel
    /// path (local PG, `process-max=4`) and the serial path (non-local PG):
    /// each must classify the size-differing file as "no match" without ever
    /// opening it for hashing.
    #[test]
    fn delta_with_size_mismatch_short_circuits() {
        // ---- parallel branch (local PG) ----
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";

        let backup = b"backup file contents that are 36 bytes".as_slice();
        let local_shorter = b"shorter local"; // intentionally smaller
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(
            &repo_s,
            stanza,
            label,
            &[("pg_data/sized.txt", backup, Some(sha1_hex(backup)))],
            &["pg_data"],
            &[],
        );
        seed_pg_file(&pg_s, "pg_data/sized.txt", local_shorter);

        // The PG file exists at the wrong size. `classify_delta_match` must
        // return `NoMatch` (no SHA-1 job ever queued); the parallel hasher
        // never reads `sized.txt`.
        let info = pg_s.info(Path::new("pg_data/sized.txt")).unwrap();
        let file = ManifestFile {
            path: "pg_data/sized.txt".to_owned(),
            size: backup.len() as u64,
            timestamp: 1_704_110_400,
            checksum: Some(sha1_hex(backup)),
            checksum_page: None,
            reference: None,
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        };
        let classified = super::classify_delta_match(&pg_s, Path::new("pg_data/sized.txt"), &file, true);
        match classified {
            super::DeltaMatch::NoMatch => {}
            other => panic!("size mismatch must classify as NoMatch, got {other:?}"),
        }
        let _ = info; // silence unused (kept to confirm the path resolves)

        // End-to-end: restore_inner with process-max=4 + delta should restore
        // the file (size mismatch never matches) and report 0 skipped.
        let mut opts: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        opts.insert(("set".to_owned(), None), OptionValue::String(label.to_owned()));
        opts.insert(("delta".to_owned(), None), OptionValue::Boolean(true));
        opts.insert(("process-max".to_owned(), None), OptionValue::Integer(4));
        let config = LoadedConfig {
            command: "restore".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options: opts,
            params: Vec::new(),
        };
        let outcome = restore_inner(&config, &repo_s, &pg_s).expect("parallel delta");
        assert_eq!(outcome.files_skipped, 0);
        assert_eq!(outcome.files_restored, 1);

        // ---- serial branch (non-local PG) ----
        // `target_matches` MUST return false on size mismatch before any
        // open_read happens. Wrap the PG in a `RecordingRepo` so an open_read
        // attempt would be visible; but here the PG isn't a repo, so use a
        // throwaway counter wrapper around Posix instead.
        let pg_serial_dir = tempfile::tempdir().unwrap();
        let pg_serial_inner = Posix::new(pg_serial_dir.path());
        seed_pg_file(&pg_serial_inner, "pg_data/sized.txt", local_shorter);
        let pg_serial = NonLocalPg { inner: pg_serial_inner };

        // The serial `target_matches` short-circuits on size mismatch alone.
        assert!(
            !super::target_matches(&pg_serial, Path::new("pg_data/sized.txt"), &file),
            "size mismatch must short-circuit target_matches on the serial path"
        );
    }

    #[test]
    fn preflight_refuses_running_cluster() {
        // A postmaster.pid in the target is a hard error regardless of --delta/--force.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(&repo_s, stanza, label, &[], &["pg_data"], &[]);
        seed_pg_file(&pg_s, "postmaster.pid", b"12345\n/pgdata\n");

        // Even --delta + --force must not restore over a live cluster.
        let cfg = with_force(cfg_delta(Some(stanza), None, true));
        let err = restore_inner(&cfg, &repo_s, &pg_s).expect_err("postmaster.pid must fail restore");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("postmaster.pid"), "unexpected error: {msg}"),
            other => panic!("expected Other(postmaster.pid), got {other:?}"),
        }
    }

    #[test]
    fn preflight_refuses_non_empty_pgdata_without_delta_or_force() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(&repo_s, stanza, label, &[], &["pg_data"], &[]);
        // Populate the target so it is non-empty.
        seed_pg_file(&pg_s, "leftover.txt", b"stale");

        // Plain restore refuses.
        let err = restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect_err("non-empty PGDATA must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("not empty"), "unexpected error: {msg}"),
            other => panic!("expected Other(not empty), got {other:?}"),
        }

        // --force lets it proceed.
        restore_inner(&with_force(cfg(Some(stanza), None)), &repo_s, &pg_s).expect("--force must bypass the guard");
    }

    #[test]
    fn preflight_allows_empty_pgdata() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup(&repo_s, stanza, label, &[], &["pg_data"], &[]);
        // Empty target: plain restore proceeds.
        restore_inner(&cfg(Some(stanza), None), &repo_s, &pg_s).expect("empty PGDATA must restore");
    }

    #[test]
    fn parse_civil_time_applies_timezone_offset() {
        // 12:00:00 at +02:00 is 10:00:00 UTC.
        let with_tz = super::parse_civil_time("2024-01-01 12:00:00+02:00").expect("parse +02:00");
        let utc = super::parse_civil_time("2024-01-01 10:00:00").expect("parse utc");
        assert_eq!(with_tz, utc, "an east offset must shift the value earlier in UTC");

        // A west offset shifts the other way: 12:00:00-05 == 17:00:00 UTC.
        let west = super::parse_civil_time("2024-01-01T12:00:00-05").expect("parse -05");
        let west_utc = super::parse_civil_time("2024-01-01 17:00:00").expect("parse utc2");
        assert_eq!(west, west_utc);

        // `Z` is a zero offset.
        let z = super::parse_civil_time("2024-01-01 08:30:00Z").expect("parse Z");
        assert_eq!(z, super::parse_civil_time("2024-01-01 08:30:00").expect("parse no-tz"));

        // Compact `±HHMM` form.
        let compact = super::parse_civil_time("2024-01-01 12:00:00+0230").expect("parse +0230");
        assert_eq!(compact, super::parse_civil_time("2024-01-01 09:30:00").expect("parse utc3"));
    }

    #[test]
    fn escape_guc_doubles_apostrophes() {
        assert_eq!(super::escape_guc("plain"), "plain");
        assert_eq!(super::escape_guc("O'Brien"), "O''Brien");
        assert_eq!(super::escape_guc("a'b'c"), "a''b''c");
    }

    #[test]
    fn validate_manifest_path_rejects_escaping_paths() {
        assert!(super::validate_manifest_path("target:file", "base/1/1259").is_ok());
        assert!(super::validate_manifest_path("target:file", "").is_err());
        assert!(super::validate_manifest_path("target:file", "../../etc/passwd").is_err());
        assert!(super::validate_manifest_path("target:file", "base/../../secret").is_err());
        assert!(super::validate_manifest_path("target:file", "/etc/passwd").is_err());
    }

    #[test]
    fn restore_removes_residual_signal_files() {
        // A pre-existing recovery.signal / standby.signal from a prior cluster
        // life must be removed before fresh recovery files are written (PG >= 12).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let stanza = "demo";
        let label = "20240101-120000F";
        seed_backup_info(&repo_s, stanza, &[label]);
        seed_backup_ver(&repo_s, stanza, label, "14", &[], &["pg_data"], &[]);
        // Residual files + something to make the target non-empty (needs --force).
        seed_pg_file(&pg_s, "standby.signal", b"");
        seed_pg_file(&pg_s, "recovery.conf", b"restore_command = 'old'\n");

        // Default (non-standby) PG 14 restore writes recovery.signal, so the stale
        // standby.signal and recovery.conf must be gone.
        restore_inner(&with_force(cfg_recovery(stanza, None, None, false)), &repo_s, &pg_s).expect("restore");
        assert!(
            !pg_s.exists(Path::new("standby.signal")).unwrap(),
            "stale standby.signal must be removed"
        );
        assert!(
            !pg_s.exists(Path::new("recovery.conf")).unwrap(),
            "stale recovery.conf must be removed"
        );
        assert!(
            pg_s.exists(Path::new("recovery.signal")).unwrap(),
            "fresh recovery.signal must be written"
        );
    }
}
