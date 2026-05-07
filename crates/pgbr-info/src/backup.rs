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

use pgbr_io::{IoRead, IoWrite};
use pgbr_storage::Storage;

use crate::archive::{DbHistoryEntry, json_string, parse_required_string, parse_required_u32, parse_required_u64};
use crate::format::{self, BACKREST_SECTION, InfoFile};
use crate::{InfoError, InfoFormatError};

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

/// Decoded `backup.info`. The `[backup:current]` block is preserved verbatim as a map of
/// labels to opaque JSON values — this crate does not (yet) decode the inner backup
/// description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoBackup {
    /// pgBackRest on-disk format version (currently `5`).
    pub backrest_format: u32,
    /// pgBackRest version string of the writer that last persisted this file.
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
        let mut reader: Box<dyn IoRead> = storage.open_read(path)?;
        let bytes = reader.read_all()?;
        let raw = String::from_utf8(bytes).map_err(|err| {
            InfoError::Format(InfoFormatError::InvalidLine {
                line_number: 0,
                line: format!("non-utf8 input: {err}"),
            })
        })?;
        Self::from_text(&raw)
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
        let mut file = InfoFile::new();

        // [backrest]
        file.set(BACKREST_SECTION, KEY_FORMAT, self.backrest_format.to_string());
        file.set(BACKREST_SECTION, KEY_VERSION, json_string(&self.backrest_version));

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
