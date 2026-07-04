//! repo-sync (Layer 1): byte-identical mirroring of backups + WAL from the
//! active repository to every other configured repository.
//!
//! Repos in a multi-repo set are byte-identical (compression global; bundling /
//! block-incremental / cipher-type validated identical; cipher sub-key shared).
//! Syncing is therefore a PURE RAW BYTE COPY of stored objects at the SAME repo
//! paths — no decode / re-encode / re-bundle / re-block / size recompute. The
//! only metadata work is merging the synced backup's `backup.info` entry
//! verbatim, copying missing db-history, and (encrypted repos) sharing the
//! source sub-key.
//!
//! Two entry points share this module:
//!
//! - the inline `--repo-sync` option on `backup`, which mirrors the
//!   just-completed backup (`backup::sync_backup_to_repo`); and
//! - the standalone [`command`] (`repo-sync`), which reconciles WAL and/or
//!   backups in bulk with `--type` / `--set`, idempotently and with diff/incr
//!   ancestor backfill.
//!
//! C reference: there is no single C analogue — pgBackRust mirrors repositories
//! by re-running `archive-push` / `backup` against each. This command performs
//! the same end state as a raw object copy because the repositories are
//! configured as identical mirrors.

pub mod archive;
pub mod backup;

use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_io::IoWrite;
use pgbr_storage::{Storage, StorageInfo, StorageKind};

use crate::CommandError;

/// What a single sync produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Whether this outcome counts backup objects or WAL segments.
    pub kind: SyncKind,
    /// Number of objects/segments copied (idempotent skips not counted).
    pub items: usize,
    /// Total raw bytes copied.
    pub bytes: u64,
}

/// The two object classes repo-sync mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    /// A backup (manifest + standalone/bundle/block files + backup.info entry).
    Backup,
    /// One or more WAL segments under archive/<stanza>/<archive-id>/.
    Wal,
}

/// Recursively enumerate every `File` under `root` in `storage`, returning
/// storage-rooted paths (suitable for `open_read` / `open_write` on the same or
/// a sibling backend rooted identically).
///
/// Backups and archived WAL contain no symbolic links or special objects, so
/// those kinds are skipped. A missing `root` yields no entries (the caller's
/// idempotent / uninitialised checks handle "nothing to copy").
///
/// Shared by [`backup`] and [`archive`] so both mirror the full subtree the
/// same way. `Storage::list` only descends one level, so the recursion is the
/// directory walk.
pub(super) fn list_recursive(storage: &dyn Storage, root: &Path, out: &mut Vec<StorageInfo>) -> Result<(), CommandError> {
    if !storage.exists(root)? {
        return Ok(());
    }
    for mut info in storage.list(root)? {
        // `Storage::list` reports each entry's backend-resolved path (absolute for
        // the posix backend). Rebuild the storage-rooted path as `root/<name>` so
        // the entries are valid `open_read` / `open_write` arguments on a sibling
        // backend rooted elsewhere — the whole point of a cross-repo raw copy.
        let Some(name) = info.path.file_name() else {
            continue;
        };
        let rel = root.join(name);
        match info.kind {
            StorageKind::Path => list_recursive(storage, &rel, out)?,
            StorageKind::File => {
                info.path = rel;
                out.push(info);
            }
            // Backups / WAL contain no links or special objects to mirror.
            StorageKind::Link | StorageKind::Special => {}
        }
    }
    Ok(())
}

/// Raw-copy one stored object at storage-rooted `path` from `src` to the same
/// path in `dst`, creating the destination's parent directory first.
///
/// `src_size` is the source object's byte length, taken from the listing that
/// enumerated it (or an explicit `info` probe for the manifest). It is the
/// completeness oracle for the destination copy:
///
/// - destination absent → copy, returning `Ok(Some(bytes_copied))`;
/// - destination present with the SAME size → already mirrored, skip
///   (`Ok(None)`);
/// - destination present with a DIFFERENT size → a torn copy from a sync killed
///   mid-write (the posix/sftp backends write in place with no temp+rename, so a
///   partial object survives). `open_write` truncates, so re-copy over it and
///   warn that a partial object was repaired.
///
/// After the copy, the copied byte count is checked against `src_size`; a
/// mismatch means the source object changed length mid-copy and the destination
/// is now the wrong size, so it is a hard error rather than a silently-sealed
/// short object.
///
/// RAW bytes only — never decode / decrypt / decompress. The stored objects are
/// byte-identical across mirror repositories.
///
/// Shared by [`backup`] and [`archive`] so both raw-copy objects with the same
/// torn-write detection.
///
/// # Errors
///
/// [`CommandError::Other`] when the copied byte count differs from `src_size`
/// (the source changed mid-copy). Propagates storage / I/O failures.
pub(super) fn copy_object(src: &dyn Storage, dst: &dyn Storage, path: &Path, src_size: u64) -> Result<Option<u64>, CommandError> {
    if dst.exists(path)? {
        // A completed prior copy has the source's exact size. A different size is
        // a torn object left by a sync killed mid-write; fall through to re-copy
        // (open_write truncates) after warning.
        let dst_size = dst.info(path)?.size;
        if dst_size == src_size {
            return Ok(None);
        }
        log_warn(&format!(
            "repo-sync: repairing partial object {} (destination {dst_size} byte(s), source {src_size} byte(s))",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        dst.create_path(parent, true)?;
    }
    let mut reader = src.open_read(path)?;
    let mut writer = dst.open_write(path)?;
    let copied = pgbr_io::copy(&mut reader, &mut writer)?;
    writer.flush()?;
    writer.close()?;

    // The source object changed length between the listing/probe and the copy;
    // the destination is now the wrong size. Fail rather than seal a short object
    // (which the manifest sentinel would otherwise make permanent).
    if copied != src_size {
        return Err(CommandError::Other(format!(
            "repo-sync: source object {} changed size mid-copy (expected {src_size} byte(s), copied {copied})",
            path.display()
        )));
    }

    Ok(Some(copied))
}

/// Standalone `repo-sync`: mirror WAL and/or backups from the active repository
/// to every other configured repository. Idempotent (present objects skipped),
/// with diff/incr ancestor backfill.
///
/// `--type` (`all` | `wal` | `backup`, default `all`) selects what to sync;
/// `--set=LABEL` restricts a backup sync to one backup set (its dependency chain
/// is backfilled). The active `--repo` (default 1) is the source; targets are all
/// other entries in `repo_storages`.
///
/// Best-effort across targets and objects: a failure mirroring one backup / WAL
/// stream to one repository is logged and recorded, and the command continues
/// with the remaining work, returning an error only after attempting everything.
///
/// # Errors
///
/// [`CommandError::MissingOption`] when no stanza is set; propagates the lock
/// acquisition failure (another backup is running). After best-effort
/// mirroring, returns [`CommandError::Other`] summarising the first failure when
/// any target/object could not be synced. A cipher-sub-key mismatch (source vs
/// an already-populated target) surfaces as [`CommandError::Other`] via
/// [`assert_consistent`].
pub fn command(
    config: &LoadedConfig,
    repo_storage: &dyn Storage,
    repo_storages: &[(u32, &dyn Storage)],
) -> Result<(), CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;

    // Refuse to run when the operator has called `stop` for this stanza, then
    // hold the backup lock for the whole command — repo-sync mutates the
    // destination repositories' backup.info / objects exactly as a backup does,
    // so it shares the `backup` lock category. Mirrors `backup::backup`.
    if crate::lock::is_stopped(config)? {
        return Err(CommandError::Other(format!("stop file exists for stanza {stanza}")));
    }
    let _locks = crate::backup::acquire_command_lock(config, LockType::Backup)?;

    let src_index = crate::cipher::active_repo_index(config);
    let src: &dyn Storage = repo_storage;

    // Targets are every configured repository other than the source.
    let targets: Vec<(u32, &dyn Storage)> = repo_storages.iter().copied().filter(|(idx, _)| *idx != src_index).collect();
    if targets.is_empty() {
        log_info("repo-sync: no other repositories configured; nothing to mirror");
        return Ok(());
    }

    let sync_type = sync_type(config);
    let set = sync_set(config);

    // The set of backup labels to mirror, resolved once from the source
    // backup.info: a single `--set` label (its ancestors are backfilled inside
    // `sync_backup_to_repo`) or every backup in the source. WAL-only runs skip
    // this entirely. A `--set` whose label is unknown is a hard error.
    let backup_labels = if matches!(sync_type, SyncType::All | SyncType::Backup) {
        resolve_backup_labels(config, src, src_index, stanza, set.as_deref())?
    } else {
        Vec::new()
    };

    // Best-effort: keep going past a single failure so one unreachable target
    // does not strand the others, but remember the first error to fail the
    // command afterwards.
    let mut first_error: Option<CommandError> = None;

    for (dst_index, dst) in targets {
        // A raw byte copy is only valid between identical mirrors; this also
        // aligns a fresh encrypted target's sub-key (or errors on a populated
        // divergent one).
        if let Err(err) = assert_consistent(config, src, src_index, dst, dst_index, stanza) {
            log_warn(&format!("repo-sync: skipping repo{dst_index}: {err}"));
            first_error.get_or_insert(err);
            continue;
        }

        if matches!(sync_type, SyncType::All | SyncType::Wal) {
            match archive::sync_archive_to_repo(config, stanza, src, src_index, dst) {
                Ok(outcome) => log_info(&format!(
                    "repo-sync: repo{dst_index} <- WAL: {} segment(s), {} byte(s)",
                    outcome.items, outcome.bytes
                )),
                Err(err) => {
                    log_warn(&format!("repo-sync: repo{dst_index} WAL sync failed: {err}"));
                    first_error.get_or_insert(err);
                }
            }
        }

        if matches!(sync_type, SyncType::All | SyncType::Backup) {
            for label in &backup_labels {
                match backup::sync_backup_to_repo(config, stanza, label, src, src_index, dst, dst_index) {
                    Ok(outcome) => log_info(&format!(
                        "repo-sync: repo{dst_index} <- backup {label}: {} object(s), {} byte(s)",
                        outcome.items, outcome.bytes
                    )),
                    Err(err) => {
                        log_warn(&format!("repo-sync: repo{dst_index} backup {label} sync failed: {err}"));
                        first_error.get_or_insert(err);
                    }
                }
            }
        }
    }

    first_error.map_or(Ok(()), Err)
}

/// Resolve the ordered list of backup labels a backup sync should mirror.
///
/// With `--set=LABEL`, exactly that label (its diff/incr ancestors are
/// backfilled recursively inside [`backup::sync_backup_to_repo`]); the label
/// must exist in the source `backup.info`. Without `--set`, every backup in the
/// source `backup.info.current`, in label order (so a chain's earlier members
/// are attempted before later ones, though backfill makes the order
/// non-load-bearing).
fn resolve_backup_labels(
    config: &LoadedConfig,
    src: &dyn Storage,
    src_index: u32,
    stanza: &str,
    set: Option<&str>,
) -> Result<Vec<String>, CommandError> {
    let src_user_pass = crate::cipher::repo_user_pass(config, src_index)?;
    let (src_info, _) = pgbr_info::InfoBackup::load_keyed(src, &backup_info_path(stanza), src_user_pass.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;

    match set {
        Some(label) => {
            if src_info.current.contains_key(label) {
                Ok(vec![label.to_owned()])
            } else {
                Err(CommandError::Other(format!(
                    "repo-sync: backup {label} not present in source repo{src_index} backup.info"
                )))
            }
        }
        None => Ok(src_info.current.keys().cloned().collect()),
    }
}

/// What the standalone `repo-sync` command mirrors, from `--type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncType {
    /// Both WAL and backups (the default).
    All,
    /// Archived WAL only.
    Wal,
    /// Backups only.
    Backup,
}

/// Read the resolved `--type` option (`all` | `wal` | `backup`), defaulting to
/// [`SyncType::All`] when absent or unrecognised (the allow-list is enforced by
/// the config layer, so an unknown value here is treated as the default).
fn sync_type(config: &LoadedConfig) -> SyncType {
    match config.options.get(&("type".to_owned(), None)) {
        Some(OptionValue::StringId(value) | OptionValue::String(value)) => match value.as_str() {
            "wal" => SyncType::Wal,
            "backup" => SyncType::Backup,
            _ => SyncType::All,
        },
        _ => SyncType::All,
    }
}

/// Read the resolved `--set` option (the backup label to restrict a backup sync
/// to), or `None` when unset. Mirrors the `expire`/`restore` `set` read.
fn sync_set(config: &LoadedConfig) -> Option<String> {
    match config.options.get(&("set".to_owned(), None)) {
        Some(OptionValue::String(value) | OptionValue::StringId(value)) => Some(value.clone()),
        _ => None,
    }
}

/// Validate that repositories `src_index` and `dst_index` are configured as
/// byte-identical mirrors: identical `repo-bundle` / `repo-bundle-size` /
/// `repo-bundle-limit`, `repo-block` and the per-repo block-sizing group options
/// (`repo-block-size-map` / `repo-block-age-map` / `repo-block-checksum-size-map`
/// / `repo-block-size-super` / `repo-block-size-super-full`), and
/// `repoN-cipher-type`. Compression is global and already identical, so it is
/// not re-checked here. Mismatches mean a raw byte copy would produce an invalid
/// target, so they are a hard error.
///
/// When both repositories already carry an `archive.info` for `stanza`, their
/// database identities (`db_system_id` plus the derived archive-id
/// `db_version-db_id`) must match: the WAL engine copies segments under the
/// SOURCE archive-id without touching the destination's `archive.info`, so a
/// target stanza initialised against a different cluster would receive WAL under
/// an archive-id its own `archive.info` never resolves — leaving `info` looking
/// synced while archive-get / PITR from the mirror finds nothing. A destination
/// with no `archive.info` yet is a fresh mirror and passes. This identity check
/// runs for encrypted AND unencrypted repositories.
///
/// For an encrypted mirror the destination must additionally share the source's
/// cipher sub-key (the stored objects decrypt with it). This resolves both
/// sub-keys: when they already match, nothing to do; when the destination has
/// none yet but is otherwise empty (no backups, no WAL), the source sub-key is
/// written into the destination's `archive.info` / `backup.info` `[cipher]`
/// sections so subsequent raw copies decrypt; when the destination already holds
/// objects under a divergent sub-key, aligning would orphan them, so it is a hard
/// error.
///
/// # Errors
///
/// [`CommandError::Other`] describing the first option that differs, or a
/// non-empty destination whose cipher sub-key diverges from the source.
fn assert_consistent(
    config: &LoadedConfig,
    src: &dyn Storage,
    src_index: u32,
    dst: &dyn Storage,
    dst_index: u32,
    stanza: &str,
) -> Result<(), CommandError> {
    // Bundling + block-incremental group options must match: a raw byte copy of
    // bundle / block objects is only valid when both repositories pack them the
    // same way. `repo-bundle` / `repo-block` default to false; the size/limit
    // options are only meaningful when their toggle is on, but compare them
    // unconditionally so an explicit divergent value is still caught.
    for name in [
        "repo-bundle",
        "repo-bundle-size",
        "repo-bundle-limit",
        "repo-block",
        // Per-repo block sizing lives in these group options (there is no
        // `repo-block-size`); a raw copy of block objects is only valid when both
        // repositories size and age their blocks identically.
        "repo-block-size-map",
        "repo-block-age-map",
        "repo-block-checksum-size-map",
        "repo-block-size-super",
        "repo-block-size-super-full",
    ] {
        let src_value = config.options.get(&(name.to_owned(), Some(src_index)));
        let dst_value = config.options.get(&(name.to_owned(), Some(dst_index)));
        if src_value != dst_value {
            return Err(CommandError::Other(format!(
                "repo-sync: repo{src_index} and repo{dst_index} differ on {name}; repositories must be identical mirrors"
            )));
        }
    }

    // Cipher type must match (raw bytes encrypted one way cannot land in a
    // differently-typed repository).
    let src_cipher = crate::cipher::cipher_type(config, src_index);
    let dst_cipher = crate::cipher::cipher_type(config, dst_index);
    if src_cipher != dst_cipher {
        return Err(CommandError::Other(format!(
            "repo-sync: repo{src_index} and repo{dst_index} differ on repo-cipher-type; repositories must be identical mirrors"
        )));
    }

    // Database identity must match once BOTH repositories have an `archive.info`.
    // The WAL engine copies segments under the source archive-id and never
    // rewrites the destination's `archive.info`, so a target stanza created /
    // upgraded against a different cluster would silently accumulate WAL under an
    // archive-id its own `archive.info` cannot resolve. A destination with no
    // `archive.info` yet is a fresh mirror and is left to adopt the source's
    // identity when its stanza is created. Each file is loaded under its own
    // repository's user passphrase (`None` for an unencrypted repo).
    assert_db_identity(config, src, src_index, dst, dst_index, stanza)?;

    // Unencrypted mirror: no sub-key to reconcile.
    if !src_cipher.is_encrypted() {
        return Ok(());
    }

    // Encrypted mirror: the destination must share the source's sub-key.
    let src_sub_key = crate::cipher::repo_sub_key(src, config, src_index, stanza)?;
    let dst_sub_key = crate::cipher::repo_sub_key(dst, config, dst_index, stanza)?;

    match (src_sub_key.as_deref(), dst_sub_key.as_deref()) {
        // Already aligned (or both uninitialised) — nothing to do.
        (a, b) if a == b => Ok(()),
        // Source has a sub-key the destination is missing: align the
        // destination when it is still empty, otherwise refuse.
        (Some(src_key), _) => {
            if dst_has_objects(dst, stanza)? {
                return Err(CommandError::Other(format!(
                    "repo-sync: repo{dst_index} already holds objects under a different cipher sub-key than repo{src_index}; \
                     repositories must share a sub-key (re-create the stanza on repo{dst_index} from repo{src_index}'s key)"
                )));
            }
            align_sub_key(config, dst, dst_index, stanza, src_key)?;
            Ok(())
        }
        // Source has no sub-key but the destination does: the source stanza is
        // not initialised on an encrypted repo — nothing to mirror yet, so the
        // divergence is harmless (no source objects exist to copy).
        (None, _) => Ok(()),
    }
}

/// Hard-error unless the source and destination `archive.info` describe the same
/// active cluster. Only enforced when BOTH files exist: a fresh destination
/// (no `archive.info`) is a valid mirror target that adopts the source identity
/// at stanza creation.
///
/// The comparison is the archive-id (`db_version-db_id`) plus `db_system_id`
/// equality — the same triple that keys WAL under `archive/<stanza>/<archive-id>`.
/// A mismatch means the destination stanza was initialised against a different
/// cluster; a raw WAL copy under the source archive-id would land where the
/// destination's own `archive.info` never looks, so it is rejected with both
/// archive-ids named.
///
/// # Errors
///
/// [`CommandError::Other`] when the two archive identities diverge; propagates
/// `archive.info` load failures.
fn assert_db_identity(
    config: &LoadedConfig,
    src: &dyn Storage,
    src_index: u32,
    dst: &dyn Storage,
    dst_index: u32,
    stanza: &str,
) -> Result<(), CommandError> {
    let archive_path = PathBuf::from(format!("archive/{stanza}/archive.info"));

    // A destination with no `archive.info` yet is a fresh mirror: nothing to
    // compare, its identity is established when its stanza is created.
    if !src.exists(&archive_path)? || !dst.exists(&archive_path)? {
        return Ok(());
    }

    let src_user_pass = crate::cipher::repo_user_pass(config, src_index)?;
    let dst_user_pass = crate::cipher::repo_user_pass(config, dst_index)?;

    let (src_info, _) = pgbr_info::InfoArchive::load_keyed(src, &archive_path, src_user_pass.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;
    let (dst_info, _) = pgbr_info::InfoArchive::load_keyed(dst, &archive_path, dst_user_pass.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;

    let src_archive_id = crate::archive::archive_id(&src_info);
    let dst_archive_id = crate::archive::archive_id(&dst_info);
    if src_archive_id != dst_archive_id || src_info.db_system_id != dst_info.db_system_id {
        return Err(CommandError::Other(format!(
            "repo-sync: repo{src_index} archive {src_archive_id} (system id {}) and repo{dst_index} archive {dst_archive_id} \
             (system id {}) describe different clusters; re-create the stanza on repo{dst_index} from repo{src_index}",
            src_info.db_system_id, dst_info.db_system_id
        )));
    }

    Ok(())
}

/// Whether the destination repository already holds any mirrored objects for
/// `stanza` — completed backups (`backup.info.current`) or any archived WAL.
/// Used to decide whether a fresh encrypted target may adopt the source sub-key
/// (empty) or must be rejected (populated under a divergent key).
///
/// The `archive.info` / `backup.info` files and their `.copy` / `.presync`
/// siblings are excluded by prefix match, so the recovery snapshots
/// [`align_sub_key`] writes never count as objects and re-running a sub-key
/// alignment stays idempotent.
fn dst_has_objects(dst: &dyn Storage, stanza: &str) -> Result<bool, CommandError> {
    // Any WAL under archive/<stanza>/ means the destination is populated.
    let archive_root = PathBuf::from(format!("archive/{stanza}"));
    let mut wal = Vec::new();
    list_recursive(dst, &archive_root, &mut wal)?;
    if wal.iter().any(|info| {
        info.path
            .file_name()
            .and_then(|n| n.to_str())
            // Exclude the info file, its `.copy`, AND the `.presync` snapshot
            // `align_sub_key` leaves behind — none of these are mirrored objects.
            // Match by prefix (like the backup arm) so the `.presync` variant is
            // covered too.
            .is_some_and(|n| !n.starts_with("archive.info"))
    }) {
        return Ok(true);
    }

    // Any data file under a backup/<stanza>/<label>/ directory means populated.
    let backup_root = PathBuf::from(format!("backup/{stanza}"));
    let mut backups = Vec::new();
    list_recursive(dst, &backup_root, &mut backups)?;
    Ok(backups.iter().any(|info| {
        info.path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| !n.starts_with("backup.info"))
    }))
}

/// Rewrite the destination's `archive.info` (and `backup.info` when present) so
/// their `[cipher]` sections embed `src_sub_key`, keeping the destination's own
/// user passphrase. After this the destination's stored objects (none yet) and
/// future raw-copied objects decrypt with the shared sub-key.
///
/// # Race window and recovery
///
/// This runs only after [`dst_has_objects`] reports the destination empty, but
/// the two steps are not atomic and the backup lock is host-local. A concurrent
/// `archive-push` from ANOTHER host, landing WAL between the emptiness probe and
/// this rewrite, would have keyed those segments under the destination's OLD
/// sub-key — which the overwrite here supersedes, orphaning them. As a
/// mitigation (not a fix for the race), each info file is snapshotted to a
/// `<name>.presync` sibling (`archive/<stanza>/archive.info.presync`,
/// `backup/<stanza>/backup.info.presync`) BEFORE it is overwritten, so the
/// superseded sub-key material stays recoverable by an operator. The `.presync`
/// snapshots are excluded from [`dst_has_objects`] so they never make the target
/// look populated on a re-run.
fn align_sub_key(
    config: &LoadedConfig,
    dst: &dyn Storage,
    dst_index: u32,
    stanza: &str,
    src_sub_key: &str,
) -> Result<(), CommandError> {
    let dst_user_pass = crate::cipher::repo_user_pass(config, dst_index)?;

    let archive_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    if dst.exists(&archive_path)? {
        preserve_presync(dst, &archive_path)?;
        let (info, _) = pgbr_info::InfoArchive::load_keyed(dst, &archive_path, dst_user_pass.as_deref())
            .map_err(|err| CommandError::Other(err.to_string()))?;
        info.save_keyed(dst, &archive_path, dst_user_pass.as_deref(), Some(src_sub_key))
            .map_err(|err| CommandError::Other(err.to_string()))?;
    }

    let info_path = backup_info_path(stanza);
    if dst.exists(&info_path)? {
        preserve_presync(dst, &info_path)?;
        let (info, _) = pgbr_info::InfoBackup::load_keyed(dst, &info_path, dst_user_pass.as_deref())
            .map_err(|err| CommandError::Other(err.to_string()))?;
        info.save_keyed(dst, &info_path, dst_user_pass.as_deref(), Some(src_sub_key))
            .map_err(|err| CommandError::Other(err.to_string()))?;
    }

    Ok(())
}

/// Raw-copy the current bytes of the info file at `path` to a `<name>.presync`
/// sibling, preserving the pre-alignment sub-key material verbatim (ciphertext
/// and all) so it stays recoverable after [`align_sub_key`] overwrites the
/// original. Overwrites any prior snapshot (a re-run re-snapshots the current
/// state). RAW bytes only — the file is never decoded.
fn preserve_presync(dst: &dyn Storage, path: &Path) -> Result<(), CommandError> {
    // `<name>.presync` alongside the original; `path` always has a file name here
    // (it is one of the fixed info paths), so `file_name` cannot be absent.
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(());
    };
    let presync = path.with_file_name(format!("{name}.presync"));
    let mut reader = dst.open_read(path)?;
    let mut writer = dst.open_write(&presync)?;
    pgbr_io::copy(&mut reader, &mut writer)?;
    writer.flush()?;
    writer.close()?;
    Ok(())
}

/// `backup/<stanza>/backup.info`.
fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// Emit an INFO-level log line. Mirrors `backup::log_info`: the write result is
/// intentionally ignored — a logging failure must never fail the sync.
fn log_info(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_INFO,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        file!(),
        "repo-sync",
        0,
        message,
    );
}

/// Emit a WARN-level log line for a best-effort, non-fatal sync miss.
fn log_warn(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_WARN,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        file!(),
        "repo-sync",
        0,
        message,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_storage::Posix;

    use super::*;

    fn cfg(options: Vec<((&str, Option<u32>), OptionValue)>) -> LoadedConfig {
        let mut map: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        for ((name, idx), value) in options {
            map.insert((name.to_owned(), idx), value);
        }
        LoadedConfig {
            command: "repo-sync".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: map,
            params: Vec::new(),
        }
    }

    #[test]
    fn sync_type_defaults_to_all() {
        assert_eq!(sync_type(&cfg(Vec::new())), SyncType::All);
    }

    #[test]
    fn sync_type_reads_string_id() {
        let wal = cfg(vec![(("type", None), OptionValue::StringId("wal".to_owned()))]);
        assert_eq!(sync_type(&wal), SyncType::Wal);
        let backup = cfg(vec![(("type", None), OptionValue::StringId("backup".to_owned()))]);
        assert_eq!(sync_type(&backup), SyncType::Backup);
        let all = cfg(vec![(("type", None), OptionValue::StringId("all".to_owned()))]);
        assert_eq!(sync_type(&all), SyncType::All);
        // An unrecognised value falls back to the default.
        let weird = cfg(vec![(("type", None), OptionValue::StringId("bogus".to_owned()))]);
        assert_eq!(sync_type(&weird), SyncType::All);
    }

    #[test]
    fn sync_set_reads_label_or_none() {
        assert_eq!(sync_set(&cfg(Vec::new())), None);
        let one = cfg(vec![(("set", None), OptionValue::String("20240101-000000F".to_owned()))]);
        assert_eq!(sync_set(&one).as_deref(), Some("20240101-000000F"));
        let id = cfg(vec![(("set", None), OptionValue::StringId("20240101-000000F".to_owned()))]);
        assert_eq!(sync_set(&id).as_deref(), Some("20240101-000000F"));
    }

    #[test]
    fn command_without_stanza_is_missing_option() {
        let mut config = cfg(Vec::new());
        config.stanza = None;
        let dir = tempfile::tempdir().unwrap();
        let repo = Posix::new(dir.path());
        let err = command(&config, &repo, &[(1, &repo)]).expect_err("repo-sync needs a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption(stanza), got {other:?}"),
        }
    }

    #[test]
    fn command_with_no_other_repos_is_noop() {
        // Only the source repository is configured: nothing to mirror, Ok(()).
        let config = cfg(Vec::new());
        let dir = tempfile::tempdir().unwrap();
        let repo = Posix::new(dir.path());
        command(&config, &repo, &[(1, &repo)]).expect("single-repo repo-sync is a no-op");
    }

    #[test]
    fn assert_consistent_rejects_divergent_bundling() {
        let config = cfg(vec![
            (("repo-bundle", Some(1)), OptionValue::Boolean(true)),
            (("repo-bundle", Some(2)), OptionValue::Boolean(false)),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let src = Posix::new(dir.path());
        let dst_dir = tempfile::tempdir().unwrap();
        let dst = Posix::new(dst_dir.path());
        let err = assert_consistent(&config, &src, 1, &dst, 2, "demo").expect_err("bundling mismatch must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("repo-bundle"), "message was {msg:?}"),
            other => panic!("expected Other(repo-bundle), got {other:?}"),
        }
    }

    #[test]
    fn assert_consistent_rejects_divergent_cipher_type() {
        let config = cfg(vec![
            (("repo-cipher-type", Some(1)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-type", Some(2)), OptionValue::StringId("none".to_owned())),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let src = Posix::new(dir.path());
        let dst_dir = tempfile::tempdir().unwrap();
        let dst = Posix::new(dst_dir.path());
        let err = assert_consistent(&config, &src, 1, &dst, 2, "demo").expect_err("cipher-type mismatch must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("repo-cipher-type"), "message was {msg:?}"),
            other => panic!("expected Other(repo-cipher-type), got {other:?}"),
        }
    }

    #[test]
    fn assert_consistent_ok_for_matching_unencrypted_mirror() {
        // Identical (default) bundling/block/cipher → consistent, no sub-key work.
        let config = cfg(Vec::new());
        let dir = tempfile::tempdir().unwrap();
        let src = Posix::new(dir.path());
        let dst_dir = tempfile::tempdir().unwrap();
        let dst = Posix::new(dst_dir.path());
        assert_consistent(&config, &src, 1, &dst, 2, "demo").expect("matching unencrypted mirror is consistent");
    }

    #[test]
    fn dst_has_objects_detects_backup_and_wal() {
        use std::path::Path;

        let dir = tempfile::tempdir().unwrap();
        let dst = Posix::new(dir.path());
        // Empty repo: no objects.
        assert!(!dst_has_objects(&dst, "demo").unwrap());

        // A backup.info alone does not count as "objects".
        dst.create_path(Path::new("backup/demo"), true).unwrap();
        let mut w = dst.open_write(Path::new("backup/demo/backup.info")).unwrap();
        w.write(b"x").unwrap();
        w.close().unwrap();
        assert!(!dst_has_objects(&dst, "demo").unwrap());

        // A real backup data file under a label dir counts.
        dst.create_path(Path::new("backup/demo/20240101-000000F"), true).unwrap();
        let mut w = dst
            .open_write(Path::new("backup/demo/20240101-000000F/backup.manifest"))
            .unwrap();
        w.write(b"m").unwrap();
        w.close().unwrap();
        assert!(dst_has_objects(&dst, "demo").unwrap());
    }

    /// Seed a plaintext `archive.info` for `stanza` carrying the given active
    /// `db_id` / `db_version` (and a matching single-entry history), mirroring the
    /// seeding style in `sync/backup.rs` tests. Unencrypted, so no cipher sub-key.
    fn seed_plain_archive_info(repo: &Posix, stanza: &str, db_id: u32, db_version: &str, db_system_id: u64) {
        use std::path::Path;

        use pgbr_info::{DbHistoryEntry, InfoArchive};

        let mut history = BTreeMap::new();
        history.insert(
            db_id,
            DbHistoryEntry {
                db_id: db_system_id,
                db_version: db_version.to_owned(),
            },
        );
        let archive = InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id,
            db_system_id,
            db_version: db_version.to_owned(),
            history,
        };
        repo.create_path(Path::new(&format!("archive/{stanza}")), true).unwrap();
        archive
            .save(repo, Path::new(&format!("archive/{stanza}/archive.info")))
            .unwrap();
    }

    #[test]
    fn assert_consistent_rejects_divergent_db_identity() {
        // Two initialised unencrypted repos whose archive.info identities differ:
        // a raw WAL copy under the source archive-id would strand under an id the
        // destination's own archive.info never resolves, so this must hard-error.
        let config = cfg(Vec::new());
        let src_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst_dir = tempfile::tempdir().unwrap();
        let dst = Posix::new(dst_dir.path());

        seed_plain_archive_info(&src, "demo", 1, "16", 6_873_049_345_984_568_091);
        // Different db_id AND db_version → different archive-id (17-2 vs 16-1).
        seed_plain_archive_info(&dst, "demo", 2, "17", 7_000_000_000_000_000_000);

        let err = assert_consistent(&config, &src, 1, &dst, 2, "demo").expect_err("divergent db identity must fail");
        match err {
            CommandError::Other(msg) => {
                assert!(msg.contains("16-1"), "message was {msg:?}");
                assert!(msg.contains("17-2"), "message was {msg:?}");
            }
            other => panic!("expected Other(different clusters), got {other:?}"),
        }
    }

    #[test]
    fn assert_consistent_accepts_matching_db_identity() {
        // Same archive-id and system id on both repos → a valid mirror.
        let config = cfg(Vec::new());
        let src_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst_dir = tempfile::tempdir().unwrap();
        let dst = Posix::new(dst_dir.path());

        seed_plain_archive_info(&src, "demo", 1, "16", 6_873_049_345_984_568_091);
        seed_plain_archive_info(&dst, "demo", 1, "16", 6_873_049_345_984_568_091);

        assert_consistent(&config, &src, 1, &dst, 2, "demo").expect("matching db identities are consistent");
    }

    #[test]
    fn align_sub_key_writes_presync_and_stays_empty() {
        use std::path::Path;

        use pgbr_io::IoRead;

        // Seed an encrypted destination archive.info + backup.info under one user
        // pass but a stale sub-key, then align it to a new sub-key. The pre-align
        // bytes must survive in `.presync`, and dst_has_objects must still report
        // the destination empty (the `.presync` snapshots are excluded).
        let user_pass = "0123456789012345678901234567890123456789012345678901234567890123";
        let stale_sub_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let src_sub_key = "2222222222222222222222222222222222222222222222222222222222222222";

        let config = cfg(vec![
            (("repo-cipher-type", Some(2)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-pass", Some(2)), OptionValue::String(user_pass.to_owned())),
        ]);

        let dst_dir = tempfile::tempdir().unwrap();
        let dst = Posix::new(dst_dir.path());

        // Seed encrypted archive.info + backup.info under the stale sub-key.
        {
            use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup};

            let mut history = BTreeMap::new();
            history.insert(
                1,
                DbHistoryEntry {
                    db_id: 6_873_049_345_984_568_091,
                    db_version: "16".to_owned(),
                },
            );
            let archive = InfoArchive {
                backrest_format: 5,
                backrest_version: "2.58".to_owned(),
                db_id: 1,
                db_system_id: 6_873_049_345_984_568_091,
                db_version: "16".to_owned(),
                history: history.clone(),
            };
            dst.create_path(Path::new("archive/demo"), true).unwrap();
            archive
                .save_keyed(
                    &dst,
                    Path::new("archive/demo/archive.info"),
                    Some(user_pass),
                    Some(stale_sub_key),
                )
                .unwrap();

            let backup = InfoBackup {
                backrest_format: 5,
                backrest_version: "2.58".to_owned(),
                db_id: 1,
                db_system_id: 6_873_049_345_984_568_091,
                db_version: "16".to_owned(),
                db_catalog_version: 202_107_181,
                db_control_version: 1300,
                current: BTreeMap::new(),
                history,
            };
            dst.create_path(Path::new("backup/demo"), true).unwrap();
            backup
                .save_keyed(&dst, &backup_info_path("demo"), Some(user_pass), Some(stale_sub_key))
                .unwrap();
        }

        // Capture the pre-align bytes so we can assert the snapshot preserved them.
        let archive_before = {
            let mut r = dst.open_read(Path::new("archive/demo/archive.info")).unwrap();
            r.read_all().unwrap()
        };

        align_sub_key(&config, &dst, 2, "demo", src_sub_key).expect("align_sub_key");

        // The `.presync` snapshots exist and hold the pre-align bytes verbatim.
        assert!(dst.exists(Path::new("archive/demo/archive.info.presync")).unwrap());
        assert!(dst.exists(Path::new("backup/demo/backup.info.presync")).unwrap());
        let presync_bytes = {
            let mut r = dst.open_read(Path::new("archive/demo/archive.info.presync")).unwrap();
            r.read_all().unwrap()
        };
        assert_eq!(presync_bytes, archive_before, "presync must preserve pre-align bytes");

        // The `.presync` files are excluded, so the destination still reads empty.
        assert!(!dst_has_objects(&dst, "demo").unwrap());
    }
}
