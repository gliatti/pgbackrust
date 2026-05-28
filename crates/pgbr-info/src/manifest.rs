//! `backup.manifest` reader / writer.
//!
//! `backup.manifest` lives at the root of a backup directory and is the per-backup
//! inventory: every file, path, and symlink captured by the backup, each with its
//! size / timestamp / checksum metadata. It is the largest of the on-disk info files,
//! but shares the exact same SHA-1-checksummed INI envelope as `archive.info` and
//! `backup.info` (see [`crate::format`]). Mirrors `src/info/manifest.{c,h}` in the C tree.
//!
//! The on-disk layout, trimmed to the parts this slice models:
//!
//! ```text
//! [backup]
//! backup-label="20240101-120000F"
//! backup-timestamp-start=1704110400
//! backup-timestamp-stop=1704110410
//! backup-type="full"
//!
//! [backup:db]
//! db-system-id=6873049345984568091
//! db-version="14"
//!
//! [target:file]
//! pg_data/PG_VERSION={"size":3,"timestamp":1704110400,"checksum":"<sha1>"}
//!
//! [target:link]
//! pg_data/pg_wal={"destination":"/var/lib/pg_wal"}
//!
//! [target:path]
//! pg_data={}
//!
//! [backrest]
//! backrest-checksum="..."
//! backrest-format=5
//! backrest-version="2.58"
//! ```
//!
//! # Simplification
//!
//! The C side shrinks large manifests by hoisting the most common per-entry values into
//! `[target:file:default]` / `[target:path:default]` / `[target:link:default]` sections
//! and recording only the deltas in each entry. This first slice does **not** implement
//! that default-deduplication optimisation: every `[target:file]` / `[target:path]` /
//! `[target:link]` entry is stored verbatim as a full JSON value. The `*:default`
//! sections are neither read nor written.

use std::path::Path;

use pgbr_io::{IoRead, IoWrite};
use pgbr_storage::Storage;
use serde::{Deserialize, Serialize};

use crate::archive::{json_string, parse_required_string, parse_required_u64};
use crate::format::{self, BACKREST_SECTION, InfoFile};
use crate::{InfoError, InfoFormatError};

/// Section that holds the top-level backup metadata.
const BACKUP_SECTION: &str = "backup";
/// Section that holds the backed-up cluster's identity.
const BACKUP_DB_SECTION: &str = "backup:db";
/// Section that lists every file in the backup, keyed by repository-relative path.
const TARGET_FILE_SECTION: &str = "target:file";
/// Section that lists every path (directory) in the backup, keyed by path.
const TARGET_PATH_SECTION: &str = "target:path";
/// Section that lists every symlink in the backup, keyed by path.
const TARGET_LINK_SECTION: &str = "target:link";

const KEY_FORMAT: &str = "backrest-format";
const KEY_VERSION: &str = "backrest-version";
const KEY_BACKUP_LABEL: &str = "backup-label";
const KEY_BACKUP_TYPE: &str = "backup-type";
const KEY_TIMESTAMP_START: &str = "backup-timestamp-start";
const KEY_TIMESTAMP_STOP: &str = "backup-timestamp-stop";
const KEY_DB_SYSTEM_ID: &str = "db-system-id";
const KEY_DB_VERSION: &str = "db-version";

/// pgBackRest on-disk format version this writer emits.
const BACKREST_FORMAT: u32 = 5;
/// pgBackRest version string this writer stamps into the file.
const BACKREST_VERSION: &str = "2.58";

/// JSON shape of a `[target:file]` value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileValue {
    size: u64,
    timestamp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checksum: Option<String>,
    #[serde(rename = "checksum-page", default, skip_serializing_if = "Option::is_none")]
    checksum_page: Option<bool>,
}

/// JSON shape of a `[target:link]` value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkValue {
    destination: String,
}

/// One file entry in `[target:file]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFile {
    /// Repository-relative path, e.g. `"pg_data/base/1/1259"`.
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// File modification time as a Unix timestamp.
    pub timestamp: i64,
    /// SHA-1 checksum (lowercase hex). `None` for zero-length files.
    pub checksum: Option<String>,
    /// Whether page-checksum validation was applied to this file. `None` when absent.
    pub checksum_page: Option<bool>,
}

/// One path (directory) entry in `[target:path]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPath {
    /// Repository-relative path, e.g. `"pg_data/base/1"`.
    pub path: String,
}

/// One symlink entry in `[target:link]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLink {
    /// Repository-relative path of the link itself, e.g. `"pg_data/pg_wal"`.
    pub path: String,
    /// Target the link points at, e.g. `"/var/lib/pg_wal"`.
    pub destination: String,
}

/// Parsed `backup.manifest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Backup label, e.g. `"20240101-120000F"`.
    pub backup_label: String,
    /// Backup type, e.g. `"full"`, `"diff"`, `"incr"`.
    pub backup_type: String,
    /// Backup start time as a Unix timestamp.
    pub timestamp_start: i64,
    /// Backup stop time as a Unix timestamp.
    pub timestamp_stop: i64,
    /// Backed-up cluster's textual major-version label (e.g. `"14"`).
    pub db_version: String,
    /// Backed-up cluster's `pg_control.system_identifier`.
    pub db_system_id: u64,
    /// Every file captured by the backup.
    pub files: Vec<ManifestFile>,
    /// Every path (directory) captured by the backup.
    pub paths: Vec<ManifestPath>,
    /// Every symlink captured by the backup.
    pub links: Vec<ManifestLink>,
}

impl Manifest {
    /// Read `backup.manifest` from `path` via `storage`. Streams through
    /// [`IoRead::read_all`] so any backend can plug in.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`]; format
    /// or checksum failures as [`InfoError::Format`]; absent required keys as
    /// [`InfoError::MissingField`]; malformed entry JSON as [`InfoError::Json`].
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

    /// Write `backup.manifest` to `path` via `storage`.
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

    /// Decode an in-memory `backup.manifest` document. Verifies the SHA-1 checksum.
    ///
    /// # Errors
    ///
    /// Returns [`InfoError::Format`] for parse / checksum errors,
    /// [`InfoError::MissingField`] for absent required keys, and [`InfoError::Json`] for
    /// malformed `[target:file]` / `[target:link]` entries.
    pub fn from_text(raw: &str) -> Result<Self, InfoError> {
        let file = format::checksumed_load(raw)?;
        Self::from_file(&file)
    }

    /// Render this `Manifest` to text, with the `backrest-checksum` recomputed.
    #[must_use]
    pub fn to_text(&self) -> String {
        format::checksumed_render(&self.to_file())
    }

    /// Total size of all files in the manifest.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// Look up a file entry by its path.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&ManifestFile> {
        self.files.iter().find(|f| f.path == path)
    }

    fn from_file(file: &InfoFile) -> Result<Self, InfoError> {
        let backup_label = parse_required_string(file, BACKUP_SECTION, KEY_BACKUP_LABEL)?;
        let backup_type = parse_required_string(file, BACKUP_SECTION, KEY_BACKUP_TYPE)?;
        let timestamp_start = parse_required_i64(file, BACKUP_SECTION, KEY_TIMESTAMP_START)?;
        let timestamp_stop = parse_required_i64(file, BACKUP_SECTION, KEY_TIMESTAMP_STOP)?;

        let db_version = parse_required_string(file, BACKUP_DB_SECTION, KEY_DB_VERSION)?;
        let db_system_id = parse_required_u64(file, BACKUP_DB_SECTION, KEY_DB_SYSTEM_ID)?;

        let mut files = Vec::new();
        if let Some(rows) = file.sections.get(TARGET_FILE_SECTION) {
            for (path, raw_value) in rows {
                let value: FileValue = serde_json::from_str(raw_value).map_err(|err| InfoError::Json {
                    context: format!("[{TARGET_FILE_SECTION}].{path}"),
                    error: err,
                })?;
                files.push(ManifestFile {
                    path: path.clone(),
                    size: value.size,
                    timestamp: value.timestamp,
                    checksum: value.checksum,
                    checksum_page: value.checksum_page,
                });
            }
        }

        let mut paths = Vec::new();
        if let Some(rows) = file.sections.get(TARGET_PATH_SECTION) {
            for path in rows.keys() {
                paths.push(ManifestPath { path: path.clone() });
            }
        }

        let mut links = Vec::new();
        if let Some(rows) = file.sections.get(TARGET_LINK_SECTION) {
            for (path, raw_value) in rows {
                let value: LinkValue = serde_json::from_str(raw_value).map_err(|err| InfoError::Json {
                    context: format!("[{TARGET_LINK_SECTION}].{path}"),
                    error: err,
                })?;
                links.push(ManifestLink {
                    path: path.clone(),
                    destination: value.destination,
                });
            }
        }

        Ok(Self {
            backup_label,
            backup_type,
            timestamp_start,
            timestamp_stop,
            db_version,
            db_system_id,
            files,
            paths,
            links,
        })
    }

    fn to_file(&self) -> InfoFile {
        let mut file = InfoFile::new();

        // [backup]
        file.set(BACKUP_SECTION, KEY_BACKUP_LABEL, json_string(&self.backup_label));
        file.set(BACKUP_SECTION, KEY_TIMESTAMP_START, self.timestamp_start.to_string());
        file.set(BACKUP_SECTION, KEY_TIMESTAMP_STOP, self.timestamp_stop.to_string());
        file.set(BACKUP_SECTION, KEY_BACKUP_TYPE, json_string(&self.backup_type));

        // [backup:db]
        file.set(BACKUP_DB_SECTION, KEY_DB_SYSTEM_ID, self.db_system_id.to_string());
        file.set(BACKUP_DB_SECTION, KEY_DB_VERSION, json_string(&self.db_version));

        // [target:file]
        for entry in &self.files {
            let value = FileValue {
                size: entry.size,
                timestamp: entry.timestamp,
                checksum: entry.checksum.clone(),
                checksum_page: entry.checksum_page,
            };
            let json = serde_json::to_string(&value).unwrap_or_else(|_| String::from("{}"));
            file.set(TARGET_FILE_SECTION, &entry.path, json);
        }

        // [target:link]
        for entry in &self.links {
            let value = LinkValue {
                destination: entry.destination.clone(),
            };
            let json = serde_json::to_string(&value).unwrap_or_else(|_| String::from("{}"));
            file.set(TARGET_LINK_SECTION, &entry.path, json);
        }

        // [target:path]
        for entry in &self.paths {
            file.set(TARGET_PATH_SECTION, &entry.path, "{}");
        }

        // [backrest] — format / version markers. The checksum is filled in by
        // `checksumed_render`.
        file.set(BACKREST_SECTION, KEY_FORMAT, BACKREST_FORMAT.to_string());
        file.set(BACKREST_SECTION, KEY_VERSION, json_string(BACKREST_VERSION));

        file
    }
}

/// Read a required `i64`-valued key (timestamps can in principle predate the epoch).
fn parse_required_i64(file: &InfoFile, section: &'static str, key: &'static str) -> Result<i64, InfoError> {
    let raw = file.get(section, key).ok_or(InfoError::MissingField { section, key })?;
    raw.trim()
        .parse::<i64>()
        .map_err(|_| InfoError::MissingField { section, key })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::Path;

    use pgbr_storage::Posix;

    use super::*;

    fn sample() -> Manifest {
        Manifest {
            backup_label: "20240101-120000F".to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![
                ManifestFile {
                    path: "pg_data/PG_VERSION".to_owned(),
                    size: 3,
                    timestamp: 1_704_110_400,
                    checksum: Some("e1f2c3d4".to_owned()),
                    checksum_page: None,
                },
                ManifestFile {
                    path: "pg_data/base/1/1259".to_owned(),
                    size: 8192,
                    timestamp: 1_704_110_400,
                    checksum: Some("a0b1c2d3".to_owned()),
                    checksum_page: Some(true),
                },
            ],
            paths: vec![ManifestPath {
                path: "pg_data".to_owned(),
            }],
            links: vec![ManifestLink {
                path: "pg_data/pg_wal".to_owned(),
                destination: "/var/lib/pg_wal".to_owned(),
            }],
        }
    }

    #[test]
    fn parse_renders_round_trip() {
        let manifest = sample();
        let text = manifest.to_text();
        let parsed = Manifest::from_text(&text).unwrap();
        // Re-render and re-parse: a parse->render->parse cycle must be structurally stable.
        let text2 = parsed.to_text();
        let parsed2 = Manifest::from_text(&text2).unwrap();
        assert_eq!(parsed, parsed2);
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn total_size_sums_file_sizes() {
        let manifest = sample();
        assert_eq!(manifest.total_size(), 3 + 8192);
    }

    #[test]
    fn file_lookup_by_path() {
        let manifest = sample();
        let found = manifest.file("pg_data/base/1/1259").unwrap();
        assert_eq!(found.size, 8192);
        assert_eq!(found.checksum_page, Some(true));
        assert!(manifest.file("pg_data/does/not/exist").is_none());
    }

    #[test]
    fn checksum_mismatch_detected() {
        let manifest = sample();
        let mut text = manifest.to_text();
        // Flip a body byte in the backup label. The checksum line itself is untouched, so
        // the comparison must report a mismatch.
        let needle = "20240101-120000F";
        let pos = text.find(needle).unwrap();
        let bytes = unsafe { text.as_bytes_mut() };
        bytes[pos] = b'9';
        let err = Manifest::from_text(&text).unwrap_err();
        assert!(matches!(err, InfoError::Format(InfoFormatError::ChecksumMismatch { .. })));
    }

    #[test]
    fn load_save_round_trip_via_posix() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Posix::new(dir.path());
        let manifest = sample();

        let path = Path::new("backup.manifest");
        manifest.save(&storage, path).unwrap();
        let loaded = Manifest::load(&storage, path).unwrap();
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn missing_checksum_fails() {
        // Build a manifest document without a checksum line at all.
        let mut file = InfoFile::new();
        file.set(BACKUP_SECTION, KEY_BACKUP_LABEL, "\"20240101-120000F\"");
        file.set(BACKUP_SECTION, KEY_BACKUP_TYPE, "\"full\"");
        file.set(BACKUP_SECTION, KEY_TIMESTAMP_START, "1");
        file.set(BACKUP_SECTION, KEY_TIMESTAMP_STOP, "2");
        file.set(BACKUP_DB_SECTION, KEY_DB_VERSION, "\"14\"");
        file.set(BACKUP_DB_SECTION, KEY_DB_SYSTEM_ID, "1");
        let text = format::render(&file);
        let err = Manifest::from_text(&text).unwrap_err();
        assert!(matches!(err, InfoError::Format(InfoFormatError::MissingChecksum)));
    }
}
