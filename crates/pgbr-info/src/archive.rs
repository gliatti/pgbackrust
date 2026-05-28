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

use crate::cipher::{self};
use crate::format::{self, BACKREST_SECTION, CIPHER_PASS_KEY, CIPHER_SECTION, InfoFile};
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
        Self::load_keyed(storage, path, None).map(|(archive, _)| archive)
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

    /// Decode an `archive.info` document that may be encrypted under the user
    /// passphrase, returning the parsed wrapper **and** the repository sub-key
    /// recovered from the `[cipher]` section (if present). When `passphrase` is
    /// `Some`, the bytes are first decrypted (pgBackRest `"Salted__"` + SHA-1
    /// framing) and then parsed; when `None`, the bytes are parsed directly.
    ///
    /// # Errors
    ///
    /// [`InfoError::Format`] for parse / checksum errors (a wrong passphrase
    /// typically surfaces here, since the decrypted bytes are garbage), plus
    /// the usual missing-field / JSON errors.
    pub fn from_bytes_keyed(raw: &[u8], passphrase: Option<&str>) -> Result<(Self, Option<String>), InfoError> {
        let plaintext = decode_maybe_encrypted(raw, passphrase)?;
        let text = bytes_to_text(plaintext)?;
        let file = format::checksumed_load(&text)?;
        let cipher_pass = file.get(CIPHER_SECTION, CIPHER_PASS_KEY).map(strip_json_quotes);
        let archive = Self::from_file(&file)?;
        Ok((archive, cipher_pass))
    }

    /// Render this `archive.info` to bytes, injecting `cipher_pass` into the
    /// `[cipher]` section (when supplied) and encrypting the whole document
    /// under `passphrase` (when supplied).
    ///
    /// # Errors
    ///
    /// [`InfoError::Io`] if the cipher filter fails.
    pub fn to_bytes_keyed(&self, passphrase: Option<&str>, cipher_pass: Option<&str>) -> Result<Vec<u8>, InfoError> {
        let text = format::checksumed_render(&self.to_file_with_cipher(cipher_pass));
        encode_maybe_encrypted(text.as_bytes(), passphrase)
    }

    /// Read `archive.info` from `path`, decrypting under `passphrase` when the
    /// repository is encrypted. Returns the wrapper and the recovered repo
    /// sub-key.
    ///
    /// # Errors
    ///
    /// Storage / I/O / format failures as for [`InfoArchive::load`].
    pub fn load_keyed(storage: &dyn Storage, path: &Path, passphrase: Option<&str>) -> Result<(Self, Option<String>), InfoError> {
        let mut reader: Box<dyn IoRead> = storage.open_read(path)?;
        let bytes = reader.read_all()?;
        Self::from_bytes_keyed(&bytes, passphrase)
    }

    /// Write `archive.info` (and its `.copy` mirror) to `path` via `storage`,
    /// storing `cipher_pass` in the `[cipher]` section and encrypting under
    /// `passphrase` when the repository is encrypted. Matches pgBackRest's
    /// `infoArchiveSaveFile`, which always writes both the primary and the
    /// `.copy` file from the same buffer.
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
        self.to_file_with_cipher(None)
    }

    /// Build the [`InfoFile`], optionally injecting the repository sub-key into
    /// a `[cipher]` section. The cipher section is placed right after
    /// `[backrest]`, matching pgBackRest's `infoSave`.
    fn to_file_with_cipher(&self, cipher_pass: Option<&str>) -> InfoFile {
        let mut file = InfoFile::new();

        // [backrest]
        file.set(BACKREST_SECTION, KEY_FORMAT, self.backrest_format.to_string());
        file.set(BACKREST_SECTION, KEY_VERSION, json_string(&self.backrest_version));

        // [cipher] — present only for an encrypted repository. The sub-key is
        // stored JSON-string-encoded, and the whole file is encrypted under the
        // user passphrase by the keyed save path. C ref: INFO_SECTION_CIPHER.
        if let Some(pass) = cipher_pass {
            file.set(CIPHER_SECTION, CIPHER_PASS_KEY, json_string(pass));
        }

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

/// Decrypt `raw` under `passphrase` if encrypted, sharing the cipher logic with
/// the backup side.
pub(crate) fn decode_maybe_encrypted(raw: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, InfoError> {
    cipher::decode_maybe_encrypted(raw, passphrase)
}

/// Encrypt `plaintext` under `passphrase` if requested.
pub(crate) fn encode_maybe_encrypted(plaintext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, InfoError> {
    cipher::encode_maybe_encrypted(plaintext, passphrase)
}

/// Interpret a (decrypted) info-file byte buffer as UTF-8 text.
pub(crate) fn bytes_to_text(bytes: Vec<u8>) -> Result<String, InfoError> {
    String::from_utf8(bytes).map_err(|err| {
        InfoError::Format(InfoFormatError::InvalidLine {
            line_number: 0,
            line: format!("non-utf8 input: {err}"),
        })
    })
}

/// Write `bytes` to `path` and to its `.copy` mirror, matching pgBackRest's
/// `infoArchiveSaveFile` / `infoBackupSaveFile` (both files are written from
/// the same buffer so they stay in lock-step).
pub(crate) fn write_with_copy(storage: &dyn Storage, path: &Path, bytes: &[u8]) -> Result<(), InfoError> {
    write_one(storage, path, bytes)?;
    let copy_path = copy_path(path);
    write_one(storage, &copy_path, bytes)?;
    Ok(())
}

/// The `<name>.copy` sibling path for an info file.
fn copy_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".copy");
    std::path::PathBuf::from(s)
}

/// Write a single info file's bytes via `storage`.
fn write_one(storage: &dyn Storage, path: &Path, bytes: &[u8]) -> Result<(), InfoError> {
    let mut writer: Box<dyn IoWrite> = storage.open_write(path)?;
    writer.write(bytes)?;
    writer.flush()?;
    writer.close()?;
    Ok(())
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

    #[test]
    fn cipher_section_round_trips_in_plaintext_info() {
        // The [cipher] sub-key is injected on render and recovered on the keyed
        // parse path (the struct itself stays cipher-agnostic).
        let archive = sample();
        let bytes = archive.to_bytes_keyed(None, Some("aRepoSubKeyBase64==")).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("[cipher]"), "rendered file must carry a [cipher] section");
        assert!(text.contains("cipher-pass=\"aRepoSubKeyBase64==\""));

        let (parsed, sub) = InfoArchive::from_bytes_keyed(&bytes, None).unwrap();
        assert_eq!(sub.as_deref(), Some("aRepoSubKeyBase64=="));
        assert_eq!(parsed, archive);
    }

    #[test]
    fn encrypted_keyed_round_trip() {
        let archive = sample();
        let sub_key = crate::cipher::cipher_pass_gen();

        // Encrypt the whole file under the user passphrase.
        let bytes = archive.to_bytes_keyed(Some("user-passphrase"), Some(&sub_key)).unwrap();
        assert_eq!(&bytes[..8], b"Salted__", "encrypted info file uses pgBackRest framing");

        // Decrypt + parse recovers the original (including the [cipher] sub-key).
        let (parsed, sub) = InfoArchive::from_bytes_keyed(&bytes, Some("user-passphrase")).unwrap();
        assert_eq!(parsed, archive);
        assert_eq!(sub.as_deref(), Some(sub_key.as_str()));

        // Wrong passphrase fails.
        assert!(InfoArchive::from_bytes_keyed(&bytes, Some("wrong")).is_err());
    }

    #[test]
    fn save_keyed_writes_primary_and_copy() {
        use pgbr_storage::Posix;
        let dir = tempfile::tempdir().unwrap();
        let storage = Posix::new(dir.path());

        let archive = sample();
        let sub_key = crate::cipher::cipher_pass_gen();
        let path = Path::new("archive/demo/archive.info");
        storage.create_path(Path::new("archive/demo"), true).unwrap();
        archive.save_keyed(&storage, path, Some("pw"), Some(&sub_key)).unwrap();

        assert!(storage.exists(path).unwrap(), "primary file written");
        assert!(
            storage.exists(Path::new("archive/demo/archive.info.copy")).unwrap(),
            ".copy mirror written"
        );

        let (reloaded, sub) = InfoArchive::load_keyed(&storage, path, Some("pw")).unwrap();
        assert_eq!(reloaded, archive);
        assert_eq!(sub.as_deref(), Some(sub_key.as_str()));
    }

    #[test]
    fn plaintext_keyed_save_omits_cipher_section() {
        use pgbr_storage::Posix;
        let dir = tempfile::tempdir().unwrap();
        let storage = Posix::new(dir.path());

        let archive = sample();
        let path = Path::new("archive/demo/archive.info");
        storage.create_path(Path::new("archive/demo"), true).unwrap();
        archive.save_keyed(&storage, path, None, None).unwrap();

        // Unencrypted file is readable as plain text and has no [cipher] section.
        let (reloaded, sub) = InfoArchive::load_keyed(&storage, path, None).unwrap();
        assert_eq!(reloaded, archive);
        assert_eq!(sub, None);
    }
}
