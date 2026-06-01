//! Shared per-repository cipher resolution for the command layer.
//!
//! pgBackRust's repository encryption is two-level (see
//! [`pgbr_info::cipher`]):
//!
//! - `archive.info` / `backup.info` are encrypted with a key derived directly
//!   from the **user passphrase** (`repo-cipher-pass`). They are loaded with
//!   [`pgbr_info::InfoArchive::load_keyed`] / [`pgbr_info::InfoBackup::load_keyed`]
//!   passing the user passphrase, which also recovers the repository **sub-key**
//!   from the file's `[cipher]` section.
//! - `backup.manifest` and the backed-up file data are encrypted with the
//!   repository sub-key, not the user passphrase. To read a manifest you must
//!   first recover the sub-key (load `archive.info` keyed) and decrypt the
//!   manifest with it.
//!
//! For an **unencrypted** repository (`repo-cipher-type` unset or `none`) every
//! resolver here returns `None`, so the keyed loaders fall back to the
//! byte-for-byte plaintext path and existing behaviour is unchanged.
//!
//! This module is the single place the read/write command code resolves those
//! two passphrases, so `check` / `backup` / `restore` / `info` / `expire` /
//! `archive` all agree on the same key for the same `(repo-index, stanza)`.

use std::path::PathBuf;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{CipherType, InfoArchive, RepoKeys};
use pgbr_storage::Storage;

use crate::CommandError;

/// The active repository index from the `--repo` option, defaulting to 1.
///
/// Single-repository commands (`check` / `backup` / `restore` / `info` /
/// `expire`) resolve their cipher options at this index. Mirrors
/// `archive::active_repo_index` (kept in sync).
#[must_use]
pub fn active_repo_index(config: &LoadedConfig) -> u32 {
    match config.options.get(&("repo".to_owned(), None)) {
        Some(OptionValue::Integer(n)) if *n >= 1 => u32::try_from(*n).unwrap_or(1),
        _ => 1,
    }
}

/// Fetch a `repo`-group `string-id` option at group index `index`.
fn repo_string_id<'a>(config: &'a LoadedConfig, name: &str, index: u32) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), Some(index))) {
        Some(OptionValue::StringId(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Fetch a `repo`-group `String` option at group index `index`.
fn repo_string<'a>(config: &'a LoadedConfig, name: &str, index: u32) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), Some(index))) {
        Some(OptionValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// The configured [`CipherType`] for repository `index` (`none` when unset).
#[must_use]
pub fn cipher_type(config: &LoadedConfig, index: u32) -> CipherType {
    repo_string_id(config, "repo-cipher-type", index).map_or(CipherType::None, CipherType::from_str_id)
}

/// Resolve the **user passphrase** (`repo-cipher-pass`) for repository `index`.
///
/// Returns `Ok(None)` for an unencrypted repository (the common case), so the
/// keyed info loaders fall back to the plaintext path. For an encrypted
/// repository the configured `repo-cipher-pass` is required.
///
/// This is the key for loading `archive.info` / `backup.info`
/// ([`pgbr_info::InfoArchive::load_keyed`] / [`pgbr_info::InfoBackup::load_keyed`]).
///
/// # Errors
///
/// [`CommandError::MissingOption`] (`"repo-cipher-pass"`) when the repository is
/// encrypted but no passphrase is configured.
pub fn repo_user_pass(config: &LoadedConfig, index: u32) -> Result<Option<String>, CommandError> {
    if !cipher_type(config, index).is_encrypted() {
        return Ok(None);
    }
    let pass = repo_string(config, "repo-cipher-pass", index)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CommandError::MissingOption {
            option: "repo-cipher-pass".to_owned(),
        })?;
    Ok(Some(pass.to_owned()))
}

/// Resolve the user passphrase for the **active** repository (`--repo`, default
/// 1). Convenience wrapper over [`repo_user_pass`].
///
/// # Errors
///
/// As [`repo_user_pass`].
pub fn active_user_pass(config: &LoadedConfig) -> Result<Option<String>, CommandError> {
    repo_user_pass(config, active_repo_index(config))
}

/// Resolve the repository **sub-key** used to decrypt a stanza's
/// `backup.manifest` (and WAL / file data) for repository `index`, or `None`
/// when that repository is unencrypted.
///
/// The sub-key is stored, encrypted under the user passphrase, in the `[cipher]`
/// section of the stanza's `archive.info`; this loads `archive.info` keyed with
/// the user passphrase, recovers the recorded sub-key, and resolves it through
/// [`RepoKeys::resolve`]. A repository with no `archive.info` yet (uninitialised)
/// returns `Ok(None)`.
///
/// # Errors
///
/// [`CommandError::MissingOption`] when an encrypted repository has no
/// `repo-cipher-pass`; [`CommandError::Other`] when the recorded sub-key cannot
/// be decrypted (wrong passphrase / corrupt `[cipher]` section);
/// [`CommandError::Storage`] on an underlying storage error.
pub fn repo_sub_key(repo: &dyn Storage, config: &LoadedConfig, index: u32, stanza: &str) -> Result<Option<String>, CommandError> {
    let cipher_type = cipher_type(config, index);
    if !cipher_type.is_encrypted() {
        return Ok(None);
    }
    let user_pass = repo_user_pass(config, index)?.ok_or_else(|| CommandError::MissingOption {
        option: "repo-cipher-pass".to_owned(),
    })?;

    let info_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    if !repo.exists(&info_path)? {
        return Ok(None);
    }
    let (_, recorded) =
        InfoArchive::load_keyed(repo, &info_path, Some(&user_pass)).map_err(|err| CommandError::Other(err.to_string()))?;
    let keys = RepoKeys::resolve(cipher_type, Some(&user_pass), recorded.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;
    Ok(keys.repo_sub_pass().map(str::to_owned))
}

/// Resolve the manifest sub-key for the **active** repository (`--repo`, default
/// 1). Convenience wrapper over [`repo_sub_key`].
///
/// # Errors
///
/// As [`repo_sub_key`].
pub fn active_sub_key(repo: &dyn Storage, config: &LoadedConfig, stanza: &str) -> Result<Option<String>, CommandError> {
    repo_sub_key(repo, config, active_repo_index(config), stanza)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{DbHistoryEntry, InfoArchive, cipher_pass_gen};
    use pgbr_storage::Posix;

    use super::*;

    fn cfg(options: Vec<((&str, Option<u32>), OptionValue)>) -> LoadedConfig {
        let mut map: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        for ((name, idx), value) in options {
            map.insert((name.to_owned(), idx), value);
        }
        LoadedConfig {
            command: "info".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: map,
            params: Vec::new(),
        }
    }

    #[test]
    fn unencrypted_repo_resolves_to_none() {
        let config = cfg(Vec::new());
        assert!(!cipher_type(&config, 1).is_encrypted());
        assert_eq!(repo_user_pass(&config, 1).unwrap(), None);
        assert_eq!(active_user_pass(&config).unwrap(), None);
    }

    #[test]
    fn encrypted_repo_returns_user_pass() {
        let config = cfg(vec![
            (("repo-cipher-type", Some(1)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-pass", Some(1)), OptionValue::String("user-secret".to_owned())),
        ]);
        assert!(cipher_type(&config, 1).is_encrypted());
        assert_eq!(repo_user_pass(&config, 1).unwrap().as_deref(), Some("user-secret"));
    }

    #[test]
    fn encrypted_repo_without_pass_errors() {
        let config = cfg(vec![(
            ("repo-cipher-type", Some(1)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        )]);
        let err = repo_user_pass(&config, 1).unwrap_err();
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "repo-cipher-pass"),
            other => panic!("expected MissingOption(repo-cipher-pass), got {other:?}"),
        }
    }

    #[test]
    fn active_repo_index_reads_repo_option() {
        assert_eq!(active_repo_index(&cfg(Vec::new())), 1);
        let config = cfg(vec![(("repo", None), OptionValue::Integer(2))]);
        assert_eq!(active_repo_index(&config), 2);
    }

    /// Seed an encrypted `archive.info` carrying `sub_key` in its `[cipher]`
    /// section, encrypted under `user_pass`, mirroring what stanza-create writes.
    fn seed_encrypted_archive_info(repo: &Posix, stanza: &str, user_pass: &str, sub_key: &str) {
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
            .save_keyed(
                repo,
                Path::new(&format!("archive/{stanza}/archive.info")),
                Some(user_pass),
                Some(sub_key),
            )
            .unwrap();
    }

    #[test]
    fn sub_key_recovered_from_encrypted_archive_info() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Posix::new(dir.path());
        let sub_key = cipher_pass_gen();
        seed_encrypted_archive_info(&repo, "demo", "user-secret", &sub_key);

        let config = cfg(vec![
            (("repo-cipher-type", Some(1)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-pass", Some(1)), OptionValue::String("user-secret".to_owned())),
        ]);
        let resolved = repo_sub_key(&repo, &config, 1, "demo").unwrap();
        assert_eq!(resolved.as_deref(), Some(sub_key.as_str()));
        // The active-index wrapper resolves the same key.
        assert_eq!(
            active_sub_key(&repo, &config, "demo").unwrap().as_deref(),
            Some(sub_key.as_str())
        );
    }

    #[test]
    fn sub_key_none_for_unencrypted_repo() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Posix::new(dir.path());
        let config = cfg(Vec::new());
        assert_eq!(repo_sub_key(&repo, &config, 1, "demo").unwrap(), None);
    }

    #[test]
    fn sub_key_none_for_uninitialised_repo() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Posix::new(dir.path());
        let config = cfg(vec![
            (("repo-cipher-type", Some(1)), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("repo-cipher-pass", Some(1)), OptionValue::String("user-secret".to_owned())),
        ]);
        // No archive.info yet → no sub-key.
        assert_eq!(repo_sub_key(&repo, &config, 1, "demo").unwrap(), None);
    }
}
