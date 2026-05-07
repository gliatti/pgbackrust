//! Typed wrapper around `archive.info`.
//!
//! `archive.info` lives at the root of an `archive/` repository and records:
//!
//! - the `pgBackRest` format version and the writer version that last touched it,
//! - the currently-active `PostgreSQL` cluster (its `db-id`, `db-system-id`, `db-version`),
//! - and the full history of clusters that have ever written to this repository, keyed by the
//!   per-cluster `db-id` integer.
//!
//! Mirrors the `InfoArchive` / `InfoPg` pair in `src/info/infoArchive.{c,h}` and
//! `src/info/infoPg.{c,h}`.

use std::collections::BTreeMap;
use std::path::Path;

use pgbr_io::{IoRead, IoWrite};
use pgbr_storage::Storage;
use serde::{Deserialize, Serialize};

use crate::format::{self, BACKREST_SECTION, InfoFile};
use crate::{InfoError, InfoFormatError};

/// Section that holds the active cluster's identity.
const DB_SECTION: &str = "db";
/// Section that holds the per-`db-id` history of clusters.
const DB_HISTORY_SECTION: &str = "db:history";

const KEY_FORMAT: &str = "backrest-format";
const KEY_VERSION: &str = "backrest-version";
const KEY_DB_ID: &str = "db-id";
const KEY_DB_SYSTEM_ID: &str = "db-system-id";
const KEY_DB_VERSION: &str = "db-version";

/// One row of the `[db:history]` block.
///
/// Each row is keyed by the `db-id` integer (so it is not stored on the struct itself)
/// and the right-hand side is a JSON object containing the system id and the textual
/// major-version label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbHistoryEntry {
    /// The system id (`pg_control.system_identifier`) of this historical cluster.
    #[serde(rename = "db-id")]
    pub db_id: u64,
    /// Textual `PostgreSQL` major-version label (e.g. `"14"`).
    #[serde(rename = "db-version")]
    pub db_version: String,
}

/// Decoded `archive.info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoArchive {
    /// pgBackRest on-disk format version (currently `5`).
    pub backrest_format: u32,
    /// pgBackRest version string of the writer that last persisted this file.
    pub backrest_version: String,
    /// Active cluster's `db-id` (the integer index into `[db:history]`).
    pub db_id: u32,
    /// Active cluster's `pg_control.system_identifier`.
    pub db_system_id: u64,
    /// Active cluster's textual major-version label (e.g. `"14"`).
    pub db_version: String,
    /// Historical clusters that have written to this archive, keyed by `db-id`.
    pub history: BTreeMap<u32, DbHistoryEntry>,
}

impl InfoArchive {
    /// Decode an `archive.info` already-loaded into memory. Verifies the SHA-1 checksum.
    ///
    /// # Errors
    ///
    /// Returns [`InfoError::Format`] for parse / checksum errors,
    /// [`InfoError::MissingField`] for required keys that are absent, and
    /// [`InfoError::Json`] for malformed `[db:history]` rows.
    pub fn from_text(raw: &str) -> Result<Self, InfoError> {
        let file = format::checksumed_load(raw)?;
        Self::from_file(&file)
    }

    /// Render this `InfoArchive` to text, with the `backrest-checksum` recomputed.
    #[must_use]
    pub fn to_text(&self) -> String {
        format::checksumed_render(&self.to_file())
    }

    /// Read `archive.info` from `path` via `storage`. Streams through `IoRead::read_all`
    /// so any backend can plug in.
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

    /// Write `archive.info` to `path` via `storage`. Truncates / creates the file as
    /// dictated by [`Storage::open_write`].
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
            history,
        })
    }

    fn to_file(&self) -> InfoFile {
        let mut file = InfoFile::new();

        // [backrest]
        file.set(BACKREST_SECTION, KEY_FORMAT, self.backrest_format.to_string());
        file.set(BACKREST_SECTION, KEY_VERSION, json_string(&self.backrest_version));

        // [db]
        file.set(DB_SECTION, KEY_DB_ID, self.db_id.to_string());
        file.set(DB_SECTION, KEY_DB_SYSTEM_ID, self.db_system_id.to_string());
        file.set(DB_SECTION, KEY_DB_VERSION, json_string(&self.db_version));

        // [db:history]
        for (id, entry) in &self.history {
            // The C side serialises history rows as a single-line JSON object. Use the
            // same encoding so cross-compat tools see what they expect.
            let json = serde_json::to_string(entry).unwrap_or_else(|_| String::from("{}"));
            file.set(DB_HISTORY_SECTION, &id.to_string(), json);
        }

        file
    }
}

/// Encode `s` as a JSON string literal (i.e. with surrounding quotes and escapes).
pub(crate) fn json_string(s: &str) -> String {
    serde_json::Value::String(s.to_owned()).to_string()
}

/// Strip surrounding double quotes from a JSON-string-encoded value. Returns the input
/// unchanged when it is not surrounded by quotes (which lets us also handle bare numbers).
pub(crate) fn strip_json_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        // Use serde_json so escape sequences inside the string round-trip cleanly.
        serde_json::from_str::<String>(trimmed).unwrap_or_else(|_| trimmed.to_owned())
    } else {
        trimmed.to_owned()
    }
}

pub(crate) fn parse_required_string(file: &InfoFile, section: &'static str, key: &'static str) -> Result<String, InfoError> {
    let raw = file.get(section, key).ok_or(InfoError::MissingField { section, key })?;
    Ok(strip_json_quotes(raw))
}

pub(crate) fn parse_required_u32(file: &InfoFile, section: &'static str, key: &'static str) -> Result<u32, InfoError> {
    let raw = file.get(section, key).ok_or(InfoError::MissingField { section, key })?;
    raw.trim()
        .parse::<u32>()
        .map_err(|_| InfoError::MissingField { section, key })
}

pub(crate) fn parse_required_u64(file: &InfoFile, section: &'static str, key: &'static str) -> Result<u64, InfoError> {
    let raw = file.get(section, key).ok_or(InfoError::MissingField { section, key })?;
    raw.trim()
        .parse::<u64>()
        .map_err(|_| InfoError::MissingField { section, key })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample() -> InfoArchive {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            history,
        }
    }

    #[test]
    fn round_trips_via_text() {
        let archive = sample();
        let text = archive.to_text();
        let parsed = InfoArchive::from_text(&text).unwrap();
        assert_eq!(parsed, archive);
    }

    #[test]
    fn missing_db_section_reports_missing_field() {
        let mut file = InfoFile::new();
        file.set(BACKREST_SECTION, KEY_FORMAT, "5");
        file.set(BACKREST_SECTION, KEY_VERSION, "\"2.58\"");
        let text = format::checksumed_render(&file);
        let err = InfoArchive::from_text(&text).unwrap_err();
        assert!(matches!(err, InfoError::MissingField { section: "db", .. }));
    }

    #[test]
    fn flipping_byte_in_loaded_archive_is_detected() {
        let archive = sample();
        let mut text = archive.to_text();
        // Flip the first '1' that appears in the body. Whichever value it lands on, the
        // checksum no longer matches.
        let pos = text.find("db-id=1").unwrap() + "db-id=".len();
        let bytes = unsafe { text.as_bytes_mut() };
        bytes[pos] = b'2';
        let err = InfoArchive::from_text(&text).unwrap_err();
        assert!(matches!(err, InfoError::Format(InfoFormatError::ChecksumMismatch { .. })));
    }
}
