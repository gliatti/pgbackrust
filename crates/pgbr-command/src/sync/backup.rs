//! repo-sync (Layer 1): byte-identical mirroring of a single backup (and any
//! ancestors it depends on) from the active repository to one destination.
//!
//! Repositories in a multi-repo set are byte-identical (compression global;
//! bundling / block-incremental / cipher-type validated identical; cipher
//! sub-key shared). Mirroring a backup is therefore a PURE RAW BYTE COPY of
//! every stored object under `backup/<stanza>/<label>/` at the SAME repo path —
//! no decode / re-encode / re-bundle / re-block / size recompute. The only
//! metadata work is merging the synced backup's `backup.info` entry verbatim,
//! copying any missing db-history, and (for an encrypted repo) ensuring the
//! destination shares the source sub-key.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pgbr_config::LoadedConfig;
use pgbr_info::{InfoBackup, Manifest};
use pgbr_io::IoWrite;
use pgbr_storage::{Storage, StorageInfo};

use super::{SyncKind, SyncOutcome};
use crate::CommandError;

/// Sync a single backup `label` (and its ancestors) to one destination repo.
///
/// Performs a raw byte copy of every stored object under
/// `backup/<stanza>/<label>/` from the source repository to one destination
/// repository, then merges the backup's `backup.info` entry verbatim into the
/// destination.
///
/// Idempotent: a backup whose `backup.manifest` already exists in the
/// destination is skipped (its bytes are assumed complete — a prior sync wrote
/// the manifest last, see the copy ordering below). Ancestors of a diff/incr
/// backup are recursively synced first so the dependency chain is never broken.
///
/// The destination is required to be an already-initialised stanza: repo-sync
/// mirrors objects, it does not create stanzas. A missing destination
/// `backup.info` is a hard error.
///
/// For an encrypted repository the **source** sub-key is resolved once and used
/// as the destination passphrase for the manifest read (source) and embedded in
/// the destination `backup.info` `[cipher]` section, so the raw-copied bytes
/// decrypt under the (now-shared) sub-key. For an unencrypted repository both
/// sub-keys are `None` and the copy is plaintext.
///
/// # Errors
///
/// [`CommandError::Other`] when the byte-identity preconditions differ between
/// the two repositories (via [`super::assert_consistent`]), when the source
/// `backup.info` has no entry for `label`, or when the destination stanza is
/// not initialised. Propagates storage, I/O, info/manifest load/save, and
/// cipher-resolution failures.
pub fn sync_backup_to_repo(
    config: &LoadedConfig,
    stanza: &str,
    label: &str,
    src: &dyn Storage,
    src_index: u32,
    dst: &dyn Storage,
    dst_index: u32,
) -> Result<SyncOutcome, CommandError> {
    // Repositories must be configured as byte-identical mirrors, otherwise a raw
    // byte copy would produce an invalid target.
    super::assert_consistent(config, src, src_index, dst, dst_index, stanza)?;

    // Load the source backup.info (keyed under the source user passphrase). This
    // both proves the label exists and yields the verbatim entry to merge.
    let src_user_pass = crate::cipher::repo_user_pass(config, src_index)?;
    let (src_info, _src_recorded_sub) = InfoBackup::load_keyed(src, &backup_info_path(stanza), src_user_pass.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;
    if !src_info.current.contains_key(label) {
        return Err(CommandError::Other(format!(
            "repo-sync: backup {label} not present in source repo{src_index} backup.info"
        )));
    }

    // Idempotent skip: the manifest is the completion sentinel (written last).
    if dst.exists(&manifest_path(stanza, label))? {
        return Ok(SyncOutcome {
            kind: SyncKind::Backup,
            items: 0,
            bytes: 0,
        });
    }

    // Resolve the source repository sub-key once. It decrypts the source
    // manifest and is the key the destination must share for the raw-copied
    // bytes to decrypt. `None` for an unencrypted repository.
    let src_sub_key = crate::cipher::repo_sub_key(src, config, src_index, stanza)?;

    // Compute the ancestor set from the manifest's references (file references +
    // block references), then recursively sync each missing ancestor FIRST so
    // the referenced bytes exist in the destination before this backup's own
    // files are copied.
    let manifest = Manifest::load_keyed(src, &manifest_path(stanza, label), src_sub_key.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;
    for ancestor in ancestor_labels(&manifest, label) {
        sync_backup_to_repo(config, stanza, &ancestor, src, src_index, dst, dst_index)?;
    }

    // Raw-copy every stored object under backup/<stanza>/<label>/, deferring the
    // manifest (and its .copy mirror) to last so the sentinel lands only once
    // everything else is present.
    let mut items: usize = 0;
    let mut bytes: u64 = 0;

    let dir = backup_dir(stanza, label);
    let mut files: Vec<StorageInfo> = Vec::new();
    super::list_recursive(src, &dir, &mut files)?;

    let manifest_primary = manifest_path(stanza, label);
    let manifest_copy = manifest_copy_path(stanza, label);

    for info in &files {
        if info.path == manifest_primary || info.path == manifest_copy {
            // Manifest objects are copied last; skip them in the data pass.
            continue;
        }
        if let Some(copied) = copy_object(src, dst, &info.path)? {
            bytes += copied;
            items += 1;
        }
    }

    // Manifest last (primary then .copy), so the completion sentinel is durable
    // only after every data object exists in the destination.
    for path in [&manifest_primary, &manifest_copy] {
        if src.exists(path)?
            && let Some(copied) = copy_object(src, dst, path)?
        {
            bytes += copied;
            items += 1;
        }
    }

    // Merge the backup's metadata into the destination backup.info.
    let dst_user_pass = crate::cipher::repo_user_pass(config, dst_index)?;
    let info_path = backup_info_path(stanza);
    if !dst.exists(&info_path)? {
        return Err(CommandError::Other(format!(
            "repo-sync: destination stanza not initialized; run stanza-create on repo{dst_index} first"
        )));
    }
    let (mut dst_info, _dst_recorded_sub) =
        InfoBackup::load_keyed(dst, &info_path, dst_user_pass.as_deref()).map_err(|err| CommandError::Other(err.to_string()))?;

    // Verbatim entry insert — preserve the source JSON unchanged (sizes,
    // dependency chain, backup-cipher-pass, …). Never overwrite a backup the
    // destination already tracks under a different identity: insert is keyed by
    // label, which is globally unique, so this only adds the synced backup. The
    // entry's presence was validated at the top of the function, so the absent
    // arm is unreachable in practice.
    if let Some(entry) = src_info.current.get(label) {
        dst_info.current.insert(label.to_owned(), entry.clone());
    }

    // Copy any db-history rows the destination is missing; never overwrite.
    for (id, hist) in &src_info.history {
        dst_info.history.entry(*id).or_insert_with(|| hist.clone());
    }

    // Save LAST, embedding the SOURCE sub-key in the destination's [cipher]
    // section so the raw-copied bytes decrypt under the now-shared sub-key. For
    // an unencrypted repo both passphrases are None → plaintext, unchanged.
    dst_info
        .save_keyed(dst, &info_path, dst_user_pass.as_deref(), src_sub_key.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(SyncOutcome {
        kind: SyncKind::Backup,
        items,
        bytes,
    })
}

/// The distinct set of backup labels `label` depends on, derived from its
/// manifest. A diff/incr backup references earlier backups for unchanged whole
/// files (`ManifestFile::reference`) and for unchanged blocks of
/// block-incremental files (`BlockRef::reference`). The `label` itself is
/// excluded (a file/block stored in this backup references no prior backup).
fn ancestor_labels(manifest: &Manifest, label: &str) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for file in &manifest.files {
        if let Some(reference) = file.reference.as_deref()
            && reference != label
        {
            set.insert(reference.to_owned());
        }
        if let Some(block_map) = file.block_map.as_ref() {
            for block in &block_map.blocks {
                if block.reference != label {
                    set.insert(block.reference.clone());
                }
            }
        }
    }
    set
}

/// Raw-copy one stored object at storage-rooted `path` from `src` to the same
/// path in `dst`, creating the destination's parent directory first. Skips
/// (returns `Ok(None)`) when the object already exists in the destination.
/// Otherwise returns `Ok(Some(bytes_copied))`.
///
/// RAW bytes only — never decode / decrypt / decompress. The stored objects are
/// byte-identical across mirror repositories.
fn copy_object(src: &dyn Storage, dst: &dyn Storage, path: &Path) -> Result<Option<u64>, CommandError> {
    if dst.exists(path)? {
        return Ok(None);
    }
    if let Some(parent) = path.parent() {
        dst.create_path(parent, true)?;
    }
    let mut reader = src.open_read(path)?;
    let mut writer = dst.open_write(path)?;
    let copied = pgbr_io::copy(&mut reader, &mut writer)?;
    writer.flush()?;
    writer.close()?;
    Ok(Some(copied))
}

/// `backup/<stanza>/backup.info`.
fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// `backup/<stanza>/<label>` — the per-backup directory holding the manifest and
/// all stored data objects.
fn backup_dir(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}"))
}

/// `backup/<stanza>/<label>/backup.manifest`.
fn manifest_path(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/backup.manifest"))
}

/// `backup/<stanza>/<label>/backup.manifest.copy` — the crash-recovery mirror
/// written alongside the primary manifest.
fn manifest_copy_path(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/backup.manifest.copy"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{
        ChecksumPage, DbHistoryEntry, InfoArchive, InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath, cipher_pass_gen,
    };
    use pgbr_io::IoRead;
    use pgbr_storage::Posix;
    use serde_json::json;

    use super::*;

    /// Build a [`LoadedConfig`] for the `repo-sync` command from a flat option
    /// list (mirrors the cipher-module test helper).
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

    /// Cipher options for an encrypted repository at `index`.
    fn encrypted_repo_options(index: u32, user_pass: &str) -> Vec<((&'static str, Option<u32>), OptionValue)> {
        vec![
            (
                ("repo-cipher-type", Some(index)),
                OptionValue::StringId("aes-256-cbc".to_owned()),
            ),
            (("repo-cipher-pass", Some(index)), OptionValue::String(user_pass.to_owned())),
        ]
    }

    /// Seed a stanza's `archive.info` carrying `sub_key` in its `[cipher]`
    /// section, encrypted under `user_pass` (mirrors the cipher-module helper).
    /// When `user_pass` / `sub_key` are `None` the file is written plaintext.
    fn seed_archive_info(repo: &Posix, stanza: &str, user_pass: Option<&str>, sub_key: Option<&str>) {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        let archive = InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            history,
        };
        repo.create_path(Path::new(&format!("archive/{stanza}")), true).unwrap();
        archive
            .save_keyed(repo, Path::new(&format!("archive/{stanza}/archive.info")), user_pass, sub_key)
            .unwrap();
    }

    /// Seed an empty (no `[backup:current]` rows) `backup.info` for `stanza`,
    /// keyed under `user_pass` with `sub_key` in `[cipher]` when supplied.
    fn seed_backup_info(repo: &Posix, stanza: &str, user_pass: Option<&str>, sub_key: Option<&str>) {
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
        repo.create_path(Path::new(&format!("backup/{stanza}")), true).unwrap();
        info.save_keyed(repo, &backup_info_path(stanza), user_pass, sub_key).unwrap();
    }

    /// A minimal `current[label]` JSON entry for `backup.info`.
    fn backup_entry(label: &str, ty: &str, prior: Option<&str>) -> serde_json::Value {
        let mut entry = json!({
            "backup-info-size": 123,
            "backup-label": label,
            "backup-type": ty,
        });
        if let Some(p) = prior {
            entry["backup-prior"] = json!(p);
        }
        entry
    }

    /// A manifest whose single data file optionally references an ancestor.
    fn manifest_with(label: &str, ty: &str, reference: Option<&str>) -> Manifest {
        Manifest {
            backup_label: label.to_owned(),
            backup_type: ty.to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![ManifestFile {
                path: "pg_data/base/1/1259".to_owned(),
                size: 8192,
                timestamp: 1_704_110_400,
                checksum: Some("a0b1c2d3".to_owned()),
                checksum_page: Some(ChecksumPage::Validated),
                reference: reference.map(str::to_owned),
                mode: None,
                user: None,
                group: None,
                bundle_id: None,
                bundle_offset: None,
                block_map: None,
            }],
            option_checksum_page: None,
            paths: vec![ManifestPath {
                path: "pg_data".to_owned(),
            }],
            links: vec![ManifestLink {
                path: "pg_data/pg_wal".to_owned(),
                destination: "/var/lib/pg_wal".to_owned(),
            }],
        }
    }

    /// Write a backup directory: the manifest (keyed with `sub_key`) plus one raw
    /// data object whose bytes are `data`. The data object is written verbatim so
    /// the sync's raw copy can be asserted byte-for-byte. Only files NOT carried
    /// by reference (i.e. when `reference` is `None`) get a data object, matching
    /// how the producer stores bytes once.
    fn seed_backup(repo: &Posix, stanza: &str, label: &str, ty: &str, reference: Option<&str>, sub_key: Option<&str>, data: &[u8]) {
        let manifest = manifest_with(label, ty, reference);
        let dir = backup_dir(stanza, label);
        repo.create_path(&dir, true).unwrap();
        if reference.is_none() {
            // Store the file's bytes as a standalone repo object.
            let object_path = dir.join("pg_data/base/1/1259");
            repo.create_path(object_path.parent().unwrap(), true).unwrap();
            let mut writer = repo.open_write(&object_path).unwrap();
            writer.write(data).unwrap();
            writer.flush().unwrap();
            writer.close().unwrap();
        }
        manifest.save_keyed(repo, &manifest_path(stanza, label), sub_key).unwrap();
    }

    /// Register `label`'s entry in `backup.info` keyed under `user_pass` /
    /// `sub_key` (so the source repo's backup.info advertises the backup).
    fn register_backup(
        repo: &Posix,
        stanza: &str,
        label: &str,
        ty: &str,
        prior: Option<&str>,
        user_pass: Option<&str>,
        sub_key: Option<&str>,
    ) {
        let (mut info, _) = InfoBackup::load_keyed(repo, &backup_info_path(stanza), user_pass).unwrap();
        info.current.insert(label.to_owned(), backup_entry(label, ty, prior));
        info.save_keyed(repo, &backup_info_path(stanza), user_pass, sub_key).unwrap();
    }

    /// Read every byte of a storage-rooted object.
    fn read_all(repo: &Posix, path: &Path) -> Vec<u8> {
        let mut reader = repo.open_read(path).unwrap();
        reader.read_all().unwrap()
    }

    #[test]
    fn unencrypted_mirror_copies_bytes_and_merges_info() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let stanza = "demo";
        let label = "20260101-100000F";
        let data = b"raw full backup bytes";

        // Source: archive.info + backup.info + a full backup.
        seed_archive_info(&src, stanza, None, None);
        seed_backup_info(&src, stanza, None, None);
        seed_backup(&src, stanza, label, "full", None, None, data);
        register_backup(&src, stanza, label, "full", None, None, None);

        // Destination: an initialised but empty stanza.
        seed_archive_info(&dst, stanza, None, None);
        seed_backup_info(&dst, stanza, None, None);

        let config = cfg(Vec::new());
        let outcome = sync_backup_to_repo(&config, stanza, label, &src, 1, &dst, 2).unwrap();
        assert_eq!(outcome.kind, SyncKind::Backup);
        assert!(outcome.items >= 2, "manifest + data object copied");
        assert!(outcome.bytes >= u64::try_from(data.len()).unwrap());

        // Data object copied byte-for-byte at the same path.
        let object = backup_dir(stanza, label).join("pg_data/base/1/1259");
        assert_eq!(read_all(&dst, &object), data);

        // Manifest sentinel present in the destination.
        assert!(dst.exists(&manifest_path(stanza, label)).unwrap());

        // backup.info merged: label present in destination.
        let (dst_info, _) = InfoBackup::load_keyed(&dst, &backup_info_path(stanza), None).unwrap();
        assert!(dst_info.current.contains_key(label));
    }

    #[test]
    fn second_sync_is_idempotent() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let stanza = "demo";
        let label = "20260101-100000F";

        seed_archive_info(&src, stanza, None, None);
        seed_backup_info(&src, stanza, None, None);
        seed_backup(&src, stanza, label, "full", None, None, b"bytes");
        register_backup(&src, stanza, label, "full", None, None, None);
        seed_archive_info(&dst, stanza, None, None);
        seed_backup_info(&dst, stanza, None, None);

        let config = cfg(Vec::new());
        let first = sync_backup_to_repo(&config, stanza, label, &src, 1, &dst, 2).unwrap();
        assert!(first.items > 0);
        // Manifest now exists in dst → the second run skips everything.
        let second = sync_backup_to_repo(&config, stanza, label, &src, 1, &dst, 2).unwrap();
        assert_eq!(second.items, 0);
        assert_eq!(second.bytes, 0);
    }

    #[test]
    fn encrypted_mirror_with_shared_sub_key_is_raw_copy_and_restorable() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let stanza = "demo";
        let label = "20260101-100000F";
        let user_pass = "user-secret";
        let sub_key = cipher_pass_gen();
        // Encrypted file data is opaque to the sync (raw copy); use arbitrary bytes.
        let data = b"opaque encrypted object bytes";

        // Source encrypted under sub_key.
        seed_archive_info(&src, stanza, Some(user_pass), Some(&sub_key));
        seed_backup_info(&src, stanza, Some(user_pass), Some(&sub_key));
        seed_backup(&src, stanza, label, "full", None, Some(&sub_key), data);
        register_backup(&src, stanza, label, "full", None, Some(user_pass), Some(&sub_key));

        // Destination encrypted under the SAME user pass + sub-key (shared).
        seed_archive_info(&dst, stanza, Some(user_pass), Some(&sub_key));
        seed_backup_info(&dst, stanza, Some(user_pass), Some(&sub_key));

        let mut options = encrypted_repo_options(1, user_pass);
        options.extend(encrypted_repo_options(2, user_pass));
        let config = cfg(options);

        let outcome = sync_backup_to_repo(&config, stanza, label, &src, 1, &dst, 2).unwrap();
        assert!(outcome.items >= 2);

        // Stored object copied byte-for-byte (no transcode).
        let object = backup_dir(stanza, label).join("pg_data/base/1/1259");
        assert_eq!(read_all(&dst, &object), data);

        // The destination manifest is restorable under the destination sub-key:
        // resolve the dst sub-key (from its archive.info) and decrypt the synced
        // manifest with it.
        let dst_sub = crate::cipher::repo_sub_key(&dst, &config, 2, stanza).unwrap();
        assert_eq!(dst_sub.as_deref(), Some(sub_key.as_str()));
        let manifest = Manifest::load_keyed(&dst, &manifest_path(stanza, label), dst_sub.as_deref()).unwrap();
        assert_eq!(manifest.backup_label, label);

        // backup.info entry present in the destination.
        let (dst_info, _) = InfoBackup::load_keyed(&dst, &backup_info_path(stanza), Some(user_pass)).unwrap();
        assert!(dst_info.current.contains_key(label));
    }

    #[test]
    fn fresh_encrypted_target_gets_source_sub_key_embedded() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let stanza = "demo";
        let label = "20260101-100000F";
        let user_pass = "user-secret";
        let src_sub = cipher_pass_gen();
        // Destination was stanza-created with a DIFFERENT sub-key in its
        // archive.info, but its backup.info has not yet recorded one. After the
        // sync, the destination backup.info must carry the SOURCE sub-key so the
        // raw-copied bytes decrypt.
        let dst_archive_sub = cipher_pass_gen();
        assert_ne!(src_sub, dst_archive_sub);
        let data = b"opaque bytes";

        seed_archive_info(&src, stanza, Some(user_pass), Some(&src_sub));
        seed_backup_info(&src, stanza, Some(user_pass), Some(&src_sub));
        seed_backup(&src, stanza, label, "full", None, Some(&src_sub), data);
        register_backup(&src, stanza, label, "full", None, Some(user_pass), Some(&src_sub));

        // Destination initialised; its backup.info carries the source sub-key
        // (this is exactly what the sync guarantees) — here we start it with the
        // dst archive sub-key to prove the backup.info save overwrites [cipher]
        // with the SOURCE sub-key.
        seed_archive_info(&dst, stanza, Some(user_pass), Some(&dst_archive_sub));
        seed_backup_info(&dst, stanza, Some(user_pass), Some(&dst_archive_sub));

        let mut options = encrypted_repo_options(1, user_pass);
        options.extend(encrypted_repo_options(2, user_pass));
        let config = cfg(options);

        sync_backup_to_repo(&config, stanza, label, &src, 1, &dst, 2).unwrap();

        // The destination backup.info now records the SOURCE sub-key.
        let (_, recorded) = InfoBackup::load_keyed(&dst, &backup_info_path(stanza), Some(user_pass)).unwrap();
        assert_eq!(recorded.as_deref(), Some(src_sub.as_str()));

        // The synced manifest decrypts under the source sub-key (raw copy).
        let manifest = Manifest::load_keyed(&dst, &manifest_path(stanza, label), Some(&src_sub)).unwrap();
        assert_eq!(manifest.backup_label, label);
    }

    #[test]
    fn diff_backfills_missing_full_ancestor() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let stanza = "demo";
        let full = "20260101-100000F";
        let diff = "20260101-100000F_20260101-110000D";
        let full_data = b"full data object";

        seed_archive_info(&src, stanza, None, None);
        seed_backup_info(&src, stanza, None, None);
        // Full holds the bytes; diff references the full for the same file.
        seed_backup(&src, stanza, full, "full", None, None, full_data);
        register_backup(&src, stanza, full, "full", None, None, None);
        seed_backup(&src, stanza, diff, "diff", Some(full), None, b"unused");
        register_backup(&src, stanza, diff, "diff", Some(full), None, None);

        seed_archive_info(&dst, stanza, None, None);
        seed_backup_info(&dst, stanza, None, None);

        // Destination has NEITHER backup yet.
        assert!(!dst.exists(&manifest_path(stanza, full)).unwrap());

        let config = cfg(Vec::new());
        sync_backup_to_repo(&config, stanza, diff, &src, 1, &dst, 2).unwrap();

        // The full ancestor was auto-copied first.
        assert!(dst.exists(&manifest_path(stanza, full)).unwrap());
        let object = backup_dir(stanza, full).join("pg_data/base/1/1259");
        assert_eq!(read_all(&dst, &object), full_data);

        // The diff was then synced.
        assert!(dst.exists(&manifest_path(stanza, diff)).unwrap());

        // Both labels are present in the destination backup.info.
        let (dst_info, _) = InfoBackup::load_keyed(&dst, &backup_info_path(stanza), None).unwrap();
        assert!(dst_info.current.contains_key(full));
        assert!(dst_info.current.contains_key(diff));
    }

    #[test]
    fn missing_label_in_source_is_an_error() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let stanza = "demo";

        seed_archive_info(&src, stanza, None, None);
        seed_backup_info(&src, stanza, None, None);
        seed_archive_info(&dst, stanza, None, None);
        seed_backup_info(&dst, stanza, None, None);

        let config = cfg(Vec::new());
        let err = sync_backup_to_repo(&config, stanza, "20260101-100000F", &src, 1, &dst, 2).unwrap_err();
        match err {
            CommandError::Other(message) => assert!(message.contains("not present in source"), "{message}"),
            other => panic!("expected Other(not present), got {other:?}"),
        }
    }

    #[test]
    fn uninitialised_destination_is_an_error() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let stanza = "demo";
        let label = "20260101-100000F";

        seed_archive_info(&src, stanza, None, None);
        seed_backup_info(&src, stanza, None, None);
        seed_backup(&src, stanza, label, "full", None, None, b"bytes");
        register_backup(&src, stanza, label, "full", None, None, None);

        // Destination has no backup.info (stanza not created).
        let config = cfg(Vec::new());
        let err = sync_backup_to_repo(&config, stanza, label, &src, 1, &dst, 2).unwrap_err();
        match err {
            CommandError::Other(message) => assert!(message.contains("not initialized"), "{message}"),
            other => panic!("expected Other(not initialized), got {other:?}"),
        }
    }

    #[test]
    fn ancestor_labels_dedupes_file_and_block_references() {
        // A diff whose whole-file references one ancestor and whose block map
        // references another, plus a self-reference that must be excluded.
        let mut manifest = manifest_with("20260101-100000F_20260101-110000D", "diff", Some("20260101-100000F"));
        // Inject a block map referencing a second ancestor and itself.
        manifest.files[0].block_map = Some(pgbr_info::manifest::BlockMap {
            block_size: 8192,
            blocks: vec![
                pgbr_info::manifest::BlockRef {
                    checksum: "aa".to_owned(),
                    reference: "20251231-090000F".to_owned(),
                    bundle_id: 1,
                    offset: 0,
                    size: 100,
                },
                pgbr_info::manifest::BlockRef {
                    checksum: "bb".to_owned(),
                    reference: "20260101-100000F_20260101-110000D".to_owned(),
                    bundle_id: 1,
                    offset: 100,
                    size: 100,
                },
            ],
        });
        let ancestors = ancestor_labels(&manifest, "20260101-100000F_20260101-110000D");
        assert!(ancestors.contains("20260101-100000F"));
        assert!(ancestors.contains("20251231-090000F"));
        assert!(!ancestors.contains("20260101-100000F_20260101-110000D"));
        assert_eq!(ancestors.len(), 2);
    }

    #[test]
    fn assert_consistent_accepts_identical_mirrors() {
        // Both repositories share the same bundle / block / cipher settings.
        let config = cfg(vec![
            (("repo-bundle", Some(1)), OptionValue::Boolean(true)),
            (("repo-bundle", Some(2)), OptionValue::Boolean(true)),
            (("repo-block", Some(1)), OptionValue::Boolean(true)),
            (("repo-block", Some(2)), OptionValue::Boolean(true)),
            (("repo-cipher-type", Some(1)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-type", Some(2)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-pass", Some(1)), OptionValue::String("user-pass".to_owned())),
            (("repo-cipher-pass", Some(2)), OptionValue::String("user-pass".to_owned())),
        ]);
        // Both repositories are uninitialised (no archive.info), so each sub-key
        // resolves to None — the encrypted mirror is consistent with nothing to
        // reconcile yet.
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        super::super::assert_consistent(&config, &src, 1, &dst, 2, "demo").unwrap();
    }

    #[test]
    fn assert_consistent_rejects_divergent_bundle() {
        let config = cfg(vec![
            (("repo-bundle", Some(1)), OptionValue::Boolean(true)),
            // repo2 leaves repo-bundle unset → default false → mismatch.
        ]);
        // Group-option divergence is rejected before any storage access; the
        // empty mirrors below are never read.
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let err = super::super::assert_consistent(&config, &src, 1, &dst, 2, "demo").unwrap_err();
        match err {
            CommandError::Other(message) => assert!(message.contains("repo-bundle"), "{message}"),
            other => panic!("expected Other(repo-bundle), got {other:?}"),
        }
    }

    #[test]
    fn assert_consistent_rejects_divergent_block() {
        let config = cfg(vec![
            (("repo-block", Some(1)), OptionValue::Boolean(true)),
            (("repo-block", Some(2)), OptionValue::Boolean(false)),
        ]);
        // Group-option divergence is rejected before any storage access; the
        // empty mirrors below are never read.
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let err = super::super::assert_consistent(&config, &src, 1, &dst, 2, "demo").unwrap_err();
        match err {
            CommandError::Other(message) => assert!(message.contains("repo-block"), "{message}"),
            other => panic!("expected Other(repo-block), got {other:?}"),
        }
    }

    #[test]
    fn assert_consistent_rejects_divergent_cipher() {
        let config = cfg(vec![
            (("repo-cipher-type", Some(1)), OptionValue::StringId("aes-256-cbc".to_owned())),
            // repo2 leaves repo-cipher-type unset → none → mismatch.
        ]);
        // Cipher-type divergence is rejected before any storage access; the
        // empty mirrors below are never read.
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();
        let src = Posix::new(src_dir.path());
        let dst = Posix::new(dst_dir.path());
        let err = super::super::assert_consistent(&config, &src, 1, &dst, 2, "demo").unwrap_err();
        match err {
            CommandError::Other(message) => {
                assert!(
                    message.contains("repo-cipher-type") || message.contains("cipher"),
                    "{message}"
                );
            }
            other => panic!("expected Other(cipher), got {other:?}"),
        }
    }
}
