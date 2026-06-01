//! Typed wrapper around `backup.info`.
//!
//! `backup.info` lives at the root of a `backup/` repository and carries everything
//! `archive.info` does plus:
//!
//! - the catalog and control versions of the active cluster,
//! - the full `[backup:current]` block, where each key is a backup label and each value is
//!   a JSON object describing that backup (timestamps, label, size, dependency chain, …),
//! - and a `[db:history]` block whose rows additionally carry the catalog / control
//!   versions for every historical cluster.
//!
//! Mirrors the `InfoBackup` / `InfoPg` pair in `src/info/infoBackup.{c,h}` and
//! `src/info/infoPg.{c,h}`.

use std::collections::BTreeMap;
use std::path::Path;

use pgbr_io::IoWrite;
use pgbr_storage::Storage;

use crate::InfoError;
use crate::archive::{
    DbHistoryEntry, bytes_to_text, copy_path, decode_maybe_encrypted, encode_maybe_encrypted, json_string, log_copy_recovery,
    parse_required_string, parse_required_u32, parse_required_u64, read_and_decode, strip_json_quotes, write_with_copy,
};
use crate::format::{self, BACKREST_SECTION, CIPHER_PASS_KEY, CIPHER_SECTION, InfoFile};

/// Section that holds the active cluster's identity (with catalog / control versions).
const DB_SECTION: &str = "db";
/// Section that holds the per-`db-id` history of clusters.
const DB_HISTORY_SECTION: &str = "db:history";
/// Section that holds the current set of completed backups, keyed by backup label.
const BACKUP_CURRENT_SECTION: &str = "backup:current";

const KEY_FORMAT: &str = "backrest-format";
const KEY_VERSION: &str = "backrest-version";
const KEY_DB_ID: &str = "db-id";
const KEY_DB_SYSTEM_ID: &str = "db-system-id";
const KEY_DB_VERSION: &str = "db-version";
const KEY_DB_CATALOG_VERSION: &str = "db-catalog-version";
const KEY_DB_CONTROL_VERSION: &str = "db-control-version";
/// Per-backup record key holding that backup's encryption sub-key (the key the
/// backup's manifest + file data are encrypted with). pgBackRust keeps this in
/// the manifest; recording it on the `[backup:current]` entry as well lets
/// restore resolve the chain straight from `backup.info`.
const KEY_BACKUP_CIPHER_PASS: &str = "backup-cipher-pass";

/// Decoded `backup.info`. The `[backup:current]` block is preserved verbatim as a map of
/// labels to opaque JSON values — this crate does not (yet) decode the inner backup
/// description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoBackup {
    /// pgBackRust on-disk format version (currently `5`).
    pub backrest_format: u32,
    /// pgBackRust version string of the writer that last persisted this file.
    pub backrest_version: String,
    /// Active cluster's `db-id`.
    pub db_id: u32,
    /// Active cluster's `pg_control.system_identifier`.
    pub db_system_id: u64,
    /// Active cluster's textual major-version label.
    pub db_version: String,
    /// Active cluster's catalog version (`pg_control.catalog_version_no`).
    pub db_catalog_version: u32,
    /// Active cluster's control version (`pg_control.pg_control_version`).
    pub db_control_version: u32,
    /// Backups currently visible in this repository, keyed by backup label.
    pub current: BTreeMap<String, serde_json::Value>,
    /// Historical clusters that have written to this backup, keyed by `db-id`.
    pub history: BTreeMap<u32, DbHistoryEntry>,
}

impl InfoBackup {
    /// Decode an in-memory `backup.info` document. Verifies the SHA-1 checksum.
    ///
    /// # Errors
    ///
    /// Returns [`InfoError::Format`] for parse / checksum errors, [`InfoError::MissingField`]
    /// for absent required keys, and [`InfoError::Json`] for malformed `[backup:current]`
    /// or `[db:history]` rows.
    pub fn from_text(raw: &str) -> Result<Self, InfoError> {
        let file = format::checksumed_load(raw)?;
        Self::from_file(&file)
    }

    /// Render this `InfoBackup` to text, with the `backrest-checksum` recomputed.
    #[must_use]
    pub fn to_text(&self) -> String {
        format::checksumed_render(&self.to_file())
    }

    /// Read `backup.info` from `path` via `storage`.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`]; format
    /// failures as [`InfoError::Format`]; missing fields as [`InfoError::MissingField`].
    pub fn load(storage: &dyn Storage, path: &Path) -> Result<Self, InfoError> {
        Self::load_keyed(storage, path, None).map(|(backup, _)| backup)
    }

    /// Write `backup.info` to `path` via `storage`.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`].
    pub fn save(&self, storage: &dyn Storage, path: &Path) -> Result<(), InfoError> {
        let text = self.to_text();
        let mut writer: Box<dyn IoWrite> = storage.open_write(path)?;
        writer.write(text.as_bytes())?;
        writer.flush()?;
        writer.close()?;
        Ok(())
    }

    /// Decode a `backup.info` document that may be encrypted under the user
    /// passphrase, returning the wrapper and the recovered repo sub-key. See
    /// [`crate::InfoArchive::from_bytes_keyed`].
    ///
    /// # Errors
    ///
    /// [`InfoError::Format`] for parse / checksum errors (a wrong passphrase
    /// typically surfaces here), plus missing-field / JSON errors.
    pub fn from_bytes_keyed(raw: &[u8], passphrase: Option<&str>) -> Result<(Self, Option<String>), InfoError> {
        let plaintext = decode_maybe_encrypted(raw, passphrase)?;
        let text = bytes_to_text(plaintext)?;
        let file = format::checksumed_load(&text)?;
        let cipher_pass = file.get(CIPHER_SECTION, CIPHER_PASS_KEY).map(strip_json_quotes);
        let backup = Self::from_file(&file)?;
        Ok((backup, cipher_pass))
    }

    /// Render this `backup.info` to bytes, injecting `cipher_pass` into the
    /// `[cipher]` section and encrypting under `passphrase` when supplied. See
    /// [`crate::InfoArchive::to_bytes_keyed`].
    ///
    /// # Errors
    ///
    /// [`InfoError::Io`] if the cipher filter fails.
    pub fn to_bytes_keyed(&self, passphrase: Option<&str>, cipher_pass: Option<&str>) -> Result<Vec<u8>, InfoError> {
        let text = format::checksumed_render(&self.to_file_with_cipher(cipher_pass));
        encode_maybe_encrypted(text.as_bytes(), passphrase)
    }

    /// Read `backup.info` from `path`, decrypting under `passphrase` when the
    /// repository is encrypted. Returns the wrapper and the recovered repo
    /// sub-key.
    ///
    /// Crash-recovery fallback: if the primary fails to load (storage error,
    /// parse error, or checksum mismatch), the sibling `<path>.copy` mirror
    /// (written first by [`InfoBackup::save_keyed`]) is tried next. When the
    /// `.copy` succeeds it is returned and a `WARN`-level line is logged
    /// noting crash recovery was needed. When both fail, the primary's error
    /// is propagated.
    ///
    /// # Errors
    ///
    /// Storage / I/O / format failures as for [`InfoBackup::load`].
    pub fn load_keyed(storage: &dyn Storage, path: &Path, passphrase: Option<&str>) -> Result<(Self, Option<String>), InfoError> {
        match read_and_decode(storage, path, passphrase, Self::from_bytes_keyed) {
            Ok(value) => Ok(value),
            Err(primary_err) => {
                let copy = copy_path(path);
                match read_and_decode(storage, &copy, passphrase, Self::from_bytes_keyed) {
                    Ok(value) => {
                        log_copy_recovery(path, &primary_err);
                        Ok(value)
                    }
                    Err(_copy_err) => Err(primary_err),
                }
            }
        }
    }

    /// Write `backup.info` (and its `.copy` mirror) to `path`, storing
    /// `cipher_pass` in the `[cipher]` section and encrypting under `passphrase`
    /// when the repository is encrypted. Matches pgBackRust's
    /// `infoBackupSaveFile`.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`].
    pub fn save_keyed(
        &self,
        storage: &dyn Storage,
        path: &Path,
        passphrase: Option<&str>,
        cipher_pass: Option<&str>,
    ) -> Result<(), InfoError> {
        let bytes = self.to_bytes_keyed(passphrase, cipher_pass)?;
        write_with_copy(storage, path, &bytes)
    }

    /// Record `backup_sub_pass` (a per-backup file encryption sub-key) on the
    /// `[backup:current]` entry for `label`. No-op when `label` is unknown.
    ///
    /// This lets restore resolve the per-backup file key straight from
    /// `backup.info` without first decrypting the manifest.
    pub fn set_backup_cipher_pass(&mut self, label: &str, backup_sub_pass: &str) {
        if let Some(entry) = self.current.get_mut(label)
            && let Some(map) = entry.as_object_mut()
        {
            map.insert(
                KEY_BACKUP_CIPHER_PASS.to_owned(),
                serde_json::Value::String(backup_sub_pass.to_owned()),
            );
        }
    }

    /// The per-backup file encryption sub-key recorded for `label`, if any.
    #[must_use]
    pub fn backup_cipher_pass(&self, label: &str) -> Option<&str> {
        self.current
            .get(label)?
            .get(KEY_BACKUP_CIPHER_PASS)
            .and_then(serde_json::Value::as_str)
    }

    fn from_file(file: &InfoFile) -> Result<Self, InfoError> {
        let backrest_format = parse_required_u32(file, BACKREST_SECTION, KEY_FORMAT)?;
        let backrest_version = parse_required_string(file, BACKREST_SECTION, KEY_VERSION)?;

        let db_id = parse_required_u32(file, DB_SECTION, KEY_DB_ID)?;
        let db_system_id = parse_required_u64(file, DB_SECTION, KEY_DB_SYSTEM_ID)?;
        let db_version = parse_required_string(file, DB_SECTION, KEY_DB_VERSION)?;
        let db_catalog_version = parse_required_u32(file, DB_SECTION, KEY_DB_CATALOG_VERSION)?;
        let db_control_version = parse_required_u32(file, DB_SECTION, KEY_DB_CONTROL_VERSION)?;

        let mut current = BTreeMap::new();
        if let Some(rows) = file.sections.get(BACKUP_CURRENT_SECTION) {
            for (label, raw_value) in rows {
                let value: serde_json::Value = serde_json::from_str(raw_value).map_err(|err| InfoError::Json {
                    context: format!("[{BACKUP_CURRENT_SECTION}].{label}"),
                    error: err,
                })?;
                current.insert(label.clone(), value);
            }
        }

        let mut history = BTreeMap::new();
        if let Some(rows) = file.sections.get(DB_HISTORY_SECTION) {
            for (key, raw_value) in rows {
                let id: u32 = key.parse().map_err(|_| InfoError::InvalidValue {
                    context: format!("[{DB_HISTORY_SECTION}] row key"),
                    value: key.clone(),
                })?;
                let entry: DbHistoryEntry = serde_json::from_str(raw_value).map_err(|err| InfoError::Json {
                    context: format!("[{DB_HISTORY_SECTION}].{key}"),
                    error: err,
                })?;
                history.insert(id, entry);
            }
        }

        Ok(Self {
            backrest_format,
            backrest_version,
            db_id,
            db_system_id,
            db_version,
            db_catalog_version,
            db_control_version,
            current,
            history,
        })
    }

    fn to_file(&self) -> InfoFile {
        self.to_file_with_cipher(None)
    }

    /// Build the [`InfoFile`], optionally injecting the repository sub-key into
    /// a `[cipher]` section (placed right after `[backrest]`, before
    /// `[backup:current]`).
    fn to_file_with_cipher(&self, cipher_pass: Option<&str>) -> InfoFile {
        let mut file = InfoFile::new();

        // [backrest]
        file.set(BACKREST_SECTION, KEY_FORMAT, self.backrest_format.to_string());
        file.set(BACKREST_SECTION, KEY_VERSION, json_string(&self.backrest_version));

        // [cipher] — present only for an encrypted repository (see InfoArchive).
        if let Some(pass) = cipher_pass {
            file.set(CIPHER_SECTION, CIPHER_PASS_KEY, json_string(pass));
        }

        // [backup:current] is emitted *before* the [db] section so that load->save
        // round-trips match how the C side orders sections (alphabetical for everything
        // outside the trailing [backrest] block).
        for (label, value) in &self.current {
            file.set(BACKUP_CURRENT_SECTION, label, value.to_string());
        }

        // [db]
        file.set(DB_SECTION, KEY_DB_CATALOG_VERSION, self.db_catalog_version.to_string());
        file.set(DB_SECTION, KEY_DB_CONTROL_VERSION, self.db_control_version.to_string());
        file.set(DB_SECTION, KEY_DB_ID, self.db_id.to_string());
        file.set(DB_SECTION, KEY_DB_SYSTEM_ID, self.db_system_id.to_string());
        file.set(DB_SECTION, KEY_DB_VERSION, json_string(&self.db_version));

        // [db:history]
        for (id, entry) in &self.history {
            let json = serde_json::to_string(entry).unwrap_or_else(|_| String::from("{}"));
            file.set(DB_HISTORY_SECTION, &id.to_string(), json);
        }

        file
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> InfoBackup {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );

        let mut current = BTreeMap::new();
        current.insert(
            "20260101-100000F".to_owned(),
            json!({
                "backup-info-size": 12345,
                "backup-label": "20260101-100000F",
                "backup-type": "full"
            }),
        );

        InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        }
    }

    #[test]
    fn round_trips_via_text() {
        let backup = sample();
        let text = backup.to_text();
        let parsed = InfoBackup::from_text(&text).unwrap();
        assert_eq!(parsed, backup);
    }

    #[test]
    fn backup_current_section_keeps_arbitrary_entries() {
        let mut backup = sample();
        backup.current.insert(
            "20260102-100000F_20260103-080000I".to_owned(),
            json!({
                "backup-info-size": 99,
                "backup-label": "20260102-100000F_20260103-080000I",
                "backup-type": "incr",
                "backup-prior": "20260102-100000F"
            }),
        );

        let text = backup.to_text();
        let parsed = InfoBackup::from_text(&text).unwrap();
        assert_eq!(parsed.current.len(), 2);
        assert_eq!(
            parsed.current["20260102-100000F_20260103-080000I"]["backup-prior"],
            json!("20260102-100000F")
        );
    }

    #[test]
    fn cipher_section_and_keyed_round_trip() {
        let backup = sample();
        let sub_key = crate::cipher::cipher_pass_gen();

        // Rendered text carries the [cipher] section.
        let bytes = backup.to_bytes_keyed(None, Some(&sub_key)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("[cipher]"));

        // Encrypted whole-file round trip recovers the struct + sub-key.
        let bytes = backup.to_bytes_keyed(Some("pw"), Some(&sub_key)).unwrap();
        assert_eq!(&bytes[..8], b"Salted__");
        let (decoded, sub) = InfoBackup::from_bytes_keyed(&bytes, Some("pw")).unwrap();
        assert_eq!(decoded, backup);
        assert_eq!(sub.as_deref(), Some(sub_key.as_str()));
        assert!(InfoBackup::from_bytes_keyed(&bytes, Some("nope")).is_err());
    }

    #[test]
    fn per_backup_cipher_pass_set_and_get() {
        let mut backup = sample();
        let label = "20260101-100000F";
        assert_eq!(backup.backup_cipher_pass(label), None);

        backup.set_backup_cipher_pass(label, "theBackupSubKey==");
        assert_eq!(backup.backup_cipher_pass(label), Some("theBackupSubKey=="));

        // Survives a text round trip (it is just another key on the JSON record).
        let text = backup.to_text();
        let parsed = InfoBackup::from_text(&text).unwrap();
        assert_eq!(parsed.backup_cipher_pass(label), Some("theBackupSubKey=="));

        // Unknown label is a no-op.
        backup.set_backup_cipher_pass("no-such-label", "x");
        assert_eq!(backup.backup_cipher_pass("no-such-label"), None);
    }

    #[test]
    fn save_keyed_writes_primary_and_copy() {
        use pgbr_storage::Posix;
        let dir = tempfile::tempdir().unwrap();
        let storage = Posix::new(dir.path());

        let backup = sample();
        let sub_key = crate::cipher::cipher_pass_gen();
        let path = Path::new("backup/demo/backup.info");
        storage.create_path(Path::new("backup/demo"), true).unwrap();
        backup.save_keyed(&storage, path, Some("pw"), Some(&sub_key)).unwrap();

        assert!(storage.exists(path).unwrap());
        assert!(storage.exists(Path::new("backup/demo/backup.info.copy")).unwrap());

        let (reloaded, sub) = InfoBackup::load_keyed(&storage, path, Some("pw")).unwrap();
        assert_eq!(reloaded, backup);
        assert_eq!(sub.as_deref(), Some(sub_key.as_str()));
    }

    #[test]
    fn missing_db_catalog_version_is_reported() {
        let mut file = InfoFile::new();
        file.set(BACKREST_SECTION, KEY_FORMAT, "5");
        file.set(BACKREST_SECTION, KEY_VERSION, "\"2.58\"");
        file.set(DB_SECTION, KEY_DB_ID, "1");
        file.set(DB_SECTION, KEY_DB_SYSTEM_ID, "1");
        file.set(DB_SECTION, KEY_DB_VERSION, "\"14\"");
        // No db-catalog-version / db-control-version on purpose.

        let text = format::checksumed_render(&file);
        let err = InfoBackup::from_text(&text).unwrap_err();
        assert!(matches!(
            err,
            InfoError::MissingField {
                section: "db",
                key: "db-catalog-version"
            }
        ));
    }
}
