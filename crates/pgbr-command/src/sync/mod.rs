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
            match archive::sync_archive_to_repo(config, stanza, src, src_index, dst, dst_index) {
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
/// `repo-bundle-limit`, `repo-block` / `repo-block-size`, and
/// `repoN-cipher-type`. Compression is global and already identical, so it is
/// not re-checked here. Mismatches mean a raw byte copy would produce an invalid
/// target, so they are a hard error.
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
        "repo-block-size",
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

/// Whether the destination repository already holds any mirrored objects for
/// `stanza` — completed backups (`backup.info.current`) or any archived WAL.
/// Used to decide whether a fresh encrypted target may adopt the source sub-key
/// (empty) or must be rejected (populated under a divergent key).
fn dst_has_objects(dst: &dyn Storage, stanza: &str) -> Result<bool, CommandError> {
    // Any WAL under archive/<stanza>/ means the destination is populated.
    let archive_root = PathBuf::from(format!("archive/{stanza}"));
    let mut wal = Vec::new();
    list_recursive(dst, &archive_root, &mut wal)?;
    if wal.iter().any(|info| {
        info.path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n != "archive.info" && n != "archive.info.copy")
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
        let (info, _) = pgbr_info::InfoArchive::load_keyed(dst, &archive_path, dst_user_pass.as_deref())
            .map_err(|err| CommandError::Other(err.to_string()))?;
        info.save_keyed(dst, &archive_path, dst_user_pass.as_deref(), Some(src_sub_key))
            .map_err(|err| CommandError::Other(err.to_string()))?;
    }

    let info_path = backup_info_path(stanza);
    if dst.exists(&info_path)? {
        let (info, _) = pgbr_info::InfoBackup::load_keyed(dst, &info_path, dst_user_pass.as_deref())
            .map_err(|err| CommandError::Other(err.to_string()))?;
        info.save_keyed(dst, &info_path, dst_user_pass.as_deref(), Some(src_sub_key))
            .map_err(|err| CommandError::Other(err.to_string()))?;
    }

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
}
