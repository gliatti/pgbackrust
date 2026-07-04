//! Typed wrapper around `archive.info`.
//!
//! `archive.info` lives at the root of an `archive/` repository and records:
//!
//! - the `pgBackRust` format version and the writer version that last touched it,
//! - the currently-active `PostgreSQL` cluster (its `db-id`, `db-system-id`, `db-version`),
//! - and the full history of clusters that have ever written to this repository, keyed by the
//!   per-cluster `db-id` integer.
//!
//! Mirrors the `InfoArchive` / `InfoPg` pair in `src/info/infoArchive.{c,h}` and
//! `src/info/infoPg.{c,h}`.

use std::collections::BTreeMap;
use std::path::Path;

use pgbr_io::IoRead;
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
    /// pgBackRust on-disk format version (currently `5`).
    pub backrest_format: u32,
    /// pgBackRust version string of the writer that last persisted this file.
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
    ///
    /// # Errors
    ///
    /// [`InfoError::Json`] if a `[db:history]` row fails to serialise (in practice
    /// unreachable for these plain structs, but the error is propagated rather
    /// than masked).
    pub fn to_text(&self) -> Result<String, InfoError> {
        Ok(format::checksumed_render(&self.to_file()?))
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

    /// Write `archive.info` to `path` via `storage`.
    ///
    /// Routes through the same crash-safe path as [`InfoArchive::save_keyed`]:
    /// the `.copy` mirror and the primary are each written via
    /// [`Storage::write_atomic_path`] (temp + rename), the `.copy` first, so a
    /// crash never leaves a torn primary that the load-side fallback cannot
    /// recover. This is the unencrypted (`passphrase = None`, no `[cipher]`
    /// section) special case of `save_keyed`.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`].
    pub fn save(&self, storage: &dyn Storage, path: &Path) -> Result<(), InfoError> {
        self.save_keyed(storage, path, None, None)
    }

    /// Decode an `archive.info` document that may be encrypted under the user
    /// passphrase, returning the parsed wrapper **and** the repository sub-key
    /// recovered from the `[cipher]` section (if present). When `passphrase` is
    /// `Some`, the bytes are first decrypted (pgBackRust `"Salted__"` + SHA-1
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
        let text = format::checksumed_render_checked(&self.to_file_with_cipher(cipher_pass)?)?;
        encode_maybe_encrypted(text.as_bytes(), passphrase)
    }

    /// Read `archive.info` from `path`, decrypting under `passphrase` when the
    /// repository is encrypted. Returns the wrapper and the recovered repo
    /// sub-key.
    ///
    /// Crash-recovery fallback: if the primary fails to load (storage error,
    /// parse error, or checksum mismatch — exactly the surface a half-written
    /// or torn primary would present), the sibling `<path>.copy` mirror
    /// (written first by [`InfoArchive::save_keyed`]) is tried next. When the
    /// `.copy` succeeds it is returned and a `WARN`-level line is logged
    /// noting that crash recovery was needed. When both fail, the primary's
    /// error is propagated (so the user sees the actual root cause).
    ///
    /// # Errors
    ///
    /// Storage / I/O / format failures as for [`InfoArchive::load`].
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

    /// Write `archive.info` (and its `.copy` mirror) to `path` via `storage`,
    /// storing `cipher_pass` in the `[cipher]` section and encrypting under
    /// `passphrase` when the repository is encrypted. Matches pgBackRust's
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

    fn to_file(&self) -> Result<InfoFile, InfoError> {
        self.to_file_with_cipher(None)
    }

    /// Build the [`InfoFile`], optionally injecting the repository sub-key into
    /// a `[cipher]` section. The cipher section is placed right after
    /// `[backrest]`, matching pgBackRust's `infoSave`.
    ///
    /// # Errors
    ///
    /// [`InfoError::Json`] if a `[db:history]` row fails to serialise.
    fn to_file_with_cipher(&self, cipher_pass: Option<&str>) -> Result<InfoFile, InfoError> {
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
            let json = serde_json::to_string(entry).map_err(|err| InfoError::Json {
                context: format!("[{DB_HISTORY_SECTION}].{id}"),
                error: err,
            })?;
            file.set(DB_HISTORY_SECTION, &id.to_string(), json);
        }

        Ok(file)
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

/// Write `bytes` to `path` and to its `.copy` mirror, matching pgBackRust's
/// `infoArchiveSaveFile` / `infoBackupSaveFile` (both files are written from
/// the same buffer so they stay in lock-step).
///
/// Crash-safety ordering: the `.copy` mirror is written **first** and the
/// primary **second**. Each write goes through
/// [`Storage::write_atomic_path`], so on a local filesystem each individual
/// file lands via a temp+rename and is never observed half-written. The
/// "copy first" order guarantees that a crash between the two writes leaves
/// a fresh `.copy` (whatever the new state is) and a stale primary — and the
/// load-side fallback in [`InfoArchive::load_keyed`] /
/// [`crate::InfoBackup::load_keyed`] picks up the `.copy` when the primary
/// fails to parse / checksum, so the new state is still recoverable.
pub(crate) fn write_with_copy(storage: &dyn Storage, path: &Path, bytes: &[u8]) -> Result<(), InfoError> {
    let copy = copy_path(path);
    storage.write_atomic_path(&copy, bytes)?;
    storage.write_atomic_path(path, bytes)?;
    Ok(())
}

/// The `<name>.copy` sibling path for an info file.
pub(crate) fn copy_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".copy");
    std::path::PathBuf::from(s)
}

/// Open `path` for reading, slurp the whole file, and hand the bytes to
/// `decode`. Shared between [`InfoArchive::load_keyed`] and
/// [`crate::InfoBackup::load_keyed`] (and their primary-then-`.copy`
/// fallback) so the same I/O + parse failure surface gates both attempts.
pub(crate) fn read_and_decode<T>(
    storage: &dyn Storage,
    path: &Path,
    passphrase: Option<&str>,
    decode: impl FnOnce(&[u8], Option<&str>) -> Result<T, InfoError>,
) -> Result<T, InfoError> {
    let mut reader: Box<dyn IoRead> = storage.open_read(path)?;
    let bytes = reader.read_all()?;
    decode(&bytes, passphrase)
}

/// Process-global counter incremented every time [`log_copy_recovery`] fires.
/// Test-only: the production code uses it as a side-channel observation point
/// so the crash-recovery tests can confirm the warning fired without having
/// to capture `stderr` (which is awkward to do portably from within a
/// `cargo test` harness).
#[cfg(test)]
pub(crate) static COPY_RECOVERY_WARNINGS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Emit a `WARN` line stating that the `.copy` mirror was used because the
/// primary failed. Best-effort: a formatter / write failure is intentionally
/// swallowed so a successful crash-recovery load is never downgraded to an
/// error just because the log pipe is gone.
///
/// `pgbr-info` does not pull in `pgbr-core` for logging, so this writes
/// directly to `stderr` — pgBackRust's `LOG_WARN` lines surface the same way
/// (the in-process logger fans out to whichever sinks `logInit` has open,
/// stderr being one).
pub(crate) fn log_copy_recovery(path: &Path, err: &InfoError) {
    // `clippy::print_stderr` would flag a bare `eprintln!`; this helper is the
    // single chokepoint for the warning so the allow is local to it.
    #[allow(clippy::print_stderr)]
    {
        eprintln!(
            "WARN: {} could not be loaded ({err}); using the .copy fallback (crash-recovery)",
            path.display()
        );
    }
    #[cfg(test)]
    {
        COPY_RECOVERY_WARNINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
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
    raw.trim().parse::<u32>().map_err(|_| InfoError::InvalidValue {
        context: format!("[{section}].{key}"),
        value: raw.to_owned(),
    })
}

pub(crate) fn parse_required_u64(file: &InfoFile, section: &'static str, key: &'static str) -> Result<u64, InfoError> {
    let raw = file.get(section, key).ok_or(InfoError::MissingField { section, key })?;
    raw.trim().parse::<u64>().map_err(|_| InfoError::InvalidValue {
        context: format!("[{section}].{key}"),
        value: raw.to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use pgbr_io::IoWrite;

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
        let text = archive.to_text().unwrap();
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
        let mut text = archive.to_text().unwrap();
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
        assert_eq!(&bytes[..8], b"Salted__", "encrypted info file uses pgBackRust framing");

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

    /// Tracing wrapper that records every [`Storage`] method invocation,
    /// delegating the work to a wrapped [`Posix`] backend. Lets the crash-
    /// safety tests assert that `write_with_copy` reaches the atomic path
    /// rather than `open_write` (which would not be crash-safe).
    struct TracingStorage {
        inner: pgbr_storage::Posix,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl TracingStorage {
        fn new(root: impl Into<std::path::PathBuf>) -> Self {
            Self {
                inner: pgbr_storage::Posix::new(root),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn record(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl pgbr_storage::Storage for TracingStorage {
        fn exists(&self, path: &Path) -> Result<bool, pgbr_storage::StorageError> {
            self.inner.exists(path)
        }

        fn info(&self, path: &Path) -> Result<pgbr_storage::StorageInfo, pgbr_storage::StorageError> {
            self.inner.info(path)
        }

        fn list(&self, path: &Path) -> Result<Vec<pgbr_storage::StorageInfo>, pgbr_storage::StorageError> {
            self.inner.list(path)
        }

        fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, pgbr_storage::StorageError> {
            self.record(format!("open_read:{}", path.display()));
            self.inner.open_read(path)
        }

        fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, pgbr_storage::StorageError> {
            self.record(format!("open_write:{}", path.display()));
            self.inner.open_write(path)
        }

        fn write_atomic_path(&self, path: &Path, bytes: &[u8]) -> Result<(), pgbr_storage::StorageError> {
            self.record(format!("write_atomic_path:{}", path.display()));
            self.inner.write_atomic_path(path, bytes)
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
    fn write_with_copy_uses_atomic_rename() {
        // The trait-level guarantee: `write_with_copy` routes both the `.copy`
        // and the primary through `Storage::write_atomic_path`, never through
        // the non-atomic `open_write` truncating fast path. The `.copy` is
        // written first so a crash between the two leaves a recoverable copy
        // (asserted in `load_keyed_falls_back_to_copy_on_primary_corruption`).
        let dir = tempfile::tempdir().unwrap();
        let storage = TracingStorage::new(dir.path());
        storage.create_path(Path::new("archive/demo"), true).unwrap();

        let archive = sample();
        let path = Path::new("archive/demo/archive.info");
        archive.save_keyed(&storage, path, None, None).unwrap();

        let calls = storage.calls();
        let writes: Vec<&String> = calls
            .iter()
            .filter(|c| c.starts_with("write_atomic_path:") || c.starts_with("open_write:"))
            .collect();

        // Exactly two writes, both atomic, with the .copy first.
        assert_eq!(writes.len(), 2, "two info writes expected, got {writes:?}");
        assert!(
            writes[0].starts_with("write_atomic_path:") && writes[0].ends_with("archive.info.copy"),
            ".copy mirror must be written first via the atomic path; got {writes:?}"
        );
        assert!(
            writes[1].starts_with("write_atomic_path:") && writes[1].ends_with("archive.info"),
            "primary must be written second via the atomic path; got {writes:?}"
        );

        // The Posix backend's atomic path uses a temp+rename, so no .tmp
        // stragglers must be left after a clean save.
        assert!(
            !dir.path().join("archive/demo/archive.info.tmp").exists(),
            "primary temp file must be renamed away"
        );
        assert!(
            !dir.path().join("archive/demo/archive.info.copy.tmp").exists(),
            ".copy temp file must be renamed away"
        );
    }

    #[test]
    fn load_keyed_falls_back_to_copy_on_primary_corruption() {
        // Simulate the "crash between the .copy write and the primary write"
        // outcome: the .copy carries the new, valid bytes, and the primary
        // carries garbage left over from a half-finished write. `load_keyed`
        // must transparently recover via the .copy and warn the operator.
        use pgbr_storage::Posix;
        let dir = tempfile::tempdir().unwrap();
        let storage = Posix::new(dir.path());

        let archive = sample();
        let path = Path::new("archive/demo/archive.info");
        storage.create_path(Path::new("archive/demo"), true).unwrap();

        // Lay down a healthy pair, then corrupt only the primary.
        archive.save_keyed(&storage, path, None, None).unwrap();
        std::fs::write(dir.path().join("archive/demo/archive.info"), b"NOT A VALID INFO FILE\n").unwrap();

        // Snapshot the warning counter to observe a `log_copy_recovery` call
        // without trying to capture stderr (which is awkward to do portably
        // from a `cargo test` harness; the stderr text itself remains the
        // operator-facing signal in production).
        let before = COPY_RECOVERY_WARNINGS.load(std::sync::atomic::Ordering::Relaxed);
        let (reloaded, sub) = InfoArchive::load_keyed(&storage, path, None).unwrap();
        let after = COPY_RECOVERY_WARNINGS.load(std::sync::atomic::Ordering::Relaxed);

        assert_eq!(reloaded, archive, "value recovered from .copy fallback");
        assert_eq!(sub, None);
        assert!(after > before, "crash-recovery warning must have fired");
    }

    #[test]
    fn load_keyed_propagates_when_both_fail() {
        // When both the primary and the .copy fail to load, the primary's
        // error is the one surfaced (it's the file the operator originally
        // asked for). The .copy failure is intentionally swallowed — the
        // operator doesn't need a noisy multi-error report; the primary's
        // diagnostic is what they'll act on.
        use pgbr_storage::Posix;
        let dir = tempfile::tempdir().unwrap();
        let storage = Posix::new(dir.path());

        let path = Path::new("archive/demo/archive.info");
        storage.create_path(Path::new("archive/demo"), true).unwrap();
        std::fs::write(dir.path().join("archive/demo/archive.info"), b"NOT VALID 1\n").unwrap();
        std::fs::write(dir.path().join("archive/demo/archive.info.copy"), b"NOT VALID 2\n").unwrap();

        let err = InfoArchive::load_keyed(&storage, path, None).unwrap_err();
        // The primary's error is what gets propagated; the exact variant
        // depends on the parse stage but it MUST be the primary one (the
        // checksum on "NOT VALID 1" can never match the format-required line).
        assert!(
            matches!(err, InfoError::Format(_)),
            "expected primary's format error, got {err:?}"
        );
    }
}
