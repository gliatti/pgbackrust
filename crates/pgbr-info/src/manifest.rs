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

use pgbr_storage::Storage;
use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::InfoError;
use crate::archive::{
    bytes_to_text, copy_path, decode_maybe_encrypted, encode_maybe_encrypted, json_string, log_copy_recovery,
    parse_required_string, parse_required_u64, read_and_decode, write_with_copy,
};
use crate::format::{self, BACKREST_SECTION, InfoFile};

/// Section that holds the top-level backup metadata.
const BACKUP_SECTION: &str = "backup";
/// Section that holds the backed-up cluster's identity.
const BACKUP_DB_SECTION: &str = "backup:db";
/// Section that records the per-backup applied option values. Mirrors
/// pgBackRust's `[backup:option]` section, which surfaces the effective value of
/// each user-visible toggle (e.g. `option-checksum-page`) for tooling like
/// `info` / `verify` / `expire`. Booleans use the `y`/`n` short form, matching
/// the C writer.
const BACKUP_OPTION_SECTION: &str = "backup:option";
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
/// `[backup:option]` key that records whether page-checksum validation was
/// applied to relation files in this backup. Mirrors pgBackRust's
/// `option-checksum-page`.
const KEY_OPTION_CHECKSUM_PAGE: &str = "option-checksum-page";

/// pgBackRust on-disk format version this writer emits.
const BACKREST_FORMAT: u32 = 5;
/// pgBackRust version string this writer stamps into the file.
const BACKREST_VERSION: &str = "2.58";

/// Per-file page-checksum-validation outcome. Mirrors stock pgBackRust's
/// `"checksum-page"` field on a relation file's `[target:file]` manifest entry:
///
/// - [`ChecksumPage::Validated`] renders / parses as JSON `true` — every page
///   in the file passed validation.
/// - [`ChecksumPage::InvalidBlocks`] renders as a JSON array of block numbers
///   (e.g. `[0, 3, 17]`) — those blocks failed the page-checksum (and / or
///   page-header) check. Order is preserved by the caller; the backup pipeline
///   produces ascending block numbers.
/// - An absent field (i.e. `Option<ChecksumPage>::None`) means the file was
///   not eligible for validation (non-relation, page-unaligned, or
///   `--checksum-page` disabled).
///
/// pgBackRust stock writes `true` per validated relation file and an
/// invalid-block list per file with corrupt pages, so widening from the prior
/// `Option<bool>` (which could not represent the array form) is required to
/// surface corruption faithfully in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumPage {
    /// Every page in the file passed validation.
    Validated,
    /// One or more pages failed validation; the contained vector holds their
    /// block numbers (file-order ascending in pipeline output, but the type
    /// imposes no ordering constraint).
    InvalidBlocks(Vec<u32>),
}

impl Serialize for ChecksumPage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Validated => serializer.serialize_bool(true),
            Self::InvalidBlocks(blocks) => blocks.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ChecksumPage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ChecksumPageVisitor;

        impl<'de> Visitor<'de> for ChecksumPageVisitor {
            type Value = ChecksumPage;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("`true` for a validated file or an array of u32 block numbers for invalid pages")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // `true` is the validated marker pgBackRust writes; `false`
                // is not part of the on-disk vocabulary (an invalid file
                // always renders as the block-list array form) but accept it
                // as the validated marker's complement to keep the
                // deserialiser robust against hand-edited fixtures.
                if v {
                    Ok(ChecksumPage::Validated)
                } else {
                    Ok(ChecksumPage::InvalidBlocks(Vec::new()))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut blocks = Vec::new();
                while let Some(block) = seq.next_element::<u32>()? {
                    blocks.push(block);
                }
                Ok(ChecksumPage::InvalidBlocks(blocks))
            }
        }

        deserializer.deserialize_any(ChecksumPageVisitor)
    }
}

/// JSON shape of a `[target:file]` value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileValue {
    size: u64,
    timestamp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checksum: Option<String>,
    /// Per-file page-checksum-validation outcome. See [`ChecksumPage`].
    ///
    /// Renders as JSON `true` for [`ChecksumPage::Validated`] and as a sorted
    /// array of block numbers (e.g. `[0, 3, 17]`) for
    /// [`ChecksumPage::InvalidBlocks`]. Absent when `None` (the file was not
    /// eligible / not validated). The deserialiser accepts the same shapes
    /// plus an absent key for backward compatibility with manifests written
    /// before this widening.
    #[serde(rename = "checksum-page", default, skip_serializing_if = "Option::is_none")]
    checksum_page: Option<ChecksumPage>,
    /// Label of the backup the file's bytes actually live in. `None` for a file
    /// copied into *this* backup; `Some(label)` for a file a differential /
    /// incremental backup defers to an earlier backup. Absent from the JSON when
    /// `None`, so full-backup manifests render byte-for-byte as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    /// Unix file mode bits (e.g. `0o600`). `None` on platforms / backups that
    /// did not record it. Absent from the JSON when `None`, so manifests written
    /// without the field stay byte-for-byte unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<u32>,
    /// Owner user id (uid). `None` when not recorded. Absent from the JSON when
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<u32>,
    /// Owner group id (gid). `None` when not recorded. Absent from the JSON when
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group: Option<u32>,
    /// Identifier of the bundle object the file's bytes live in (file-bundling,
    /// `repo-bundle=y`). Serialised as `bni` to mirror the C manifest key. Absent
    /// from the JSON when `None`, so non-bundled manifests stay byte-unchanged.
    #[serde(rename = "bni", default, skip_serializing_if = "Option::is_none")]
    bundle_id: Option<u64>,
    /// Byte offset of the file's bytes within its bundle object. Serialised as
    /// `bno`. Absent from the JSON when `None`.
    #[serde(rename = "bno", default, skip_serializing_if = "Option::is_none")]
    bundle_offset: Option<u64>,
    /// Block-incremental map (`repo-block=y`): the per-block checksum + location
    /// list that lets diff/incr backups store only changed blocks. Serialised as
    /// `blk`. Absent from the JSON when `None`, so non-block manifests stay
    /// byte-unchanged.
    #[serde(rename = "blk", default, skip_serializing_if = "Option::is_none")]
    block_map: Option<BlockMapValue>,
}

/// JSON shape of a single block in a [`BlockMap`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockValue {
    /// SHA-1 checksum (lowercase hex) of the block's plaintext bytes.
    #[serde(rename = "c")]
    checksum: String,
    /// Label of the backup whose bundle physically holds this block's bytes.
    #[serde(rename = "r")]
    reference: String,
    /// Identifier of the bundle object the block's bytes live in.
    #[serde(rename = "b")]
    bundle_id: u64,
    /// Byte offset of the block's (transformed) bytes within that bundle.
    #[serde(rename = "o")]
    offset: u64,
    /// Number of (transformed) bytes the block occupies in the bundle.
    #[serde(rename = "s")]
    size: u64,
}

/// JSON shape of a `[target:link]` value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkValue {
    destination: String,
}

/// Location of one block's stored bytes within a block-incremental backup.
///
/// A block-incremental file (`repo-block=y`) is split into fixed-size blocks;
/// each block's bytes live in a bundle object — possibly in *this* backup
/// (changed block) or in an earlier backup (unchanged block a diff/incr defers
/// to). The [`BlockRef`] records the SHA-1 of the block's plaintext plus where
/// the (compressed/encrypted) bytes physically live, so restore can pull each
/// block from the right backup and reverse the transform. C ref: the block-map
/// entries in `src/info/manifest.c` / `src/command/backup/blockMap.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRef {
    /// SHA-1 checksum (lowercase hex) of the block's plaintext bytes.
    pub checksum: String,
    /// Label of the backup whose bundle physically holds this block's bytes.
    pub reference: String,
    /// Identifier of the bundle object the block's bytes live in.
    pub bundle_id: u64,
    /// Byte offset of the block's (transformed) bytes within that bundle.
    pub offset: u64,
    /// Number of (transformed) bytes the block occupies in the bundle.
    pub size: u64,
}

/// The block-incremental map for one file: its block size plus an ordered list
/// of [`BlockRef`]s, one per block (block `i` covers plaintext bytes
/// `[i*block_size, (i+1)*block_size)`).
///
/// A full backup with `repo-block=y` writes a map whose every block references
/// itself; a later diff/incr reuses unchanged blocks by referencing the earlier
/// backup and only stores the changed blocks in its own bundle. C ref:
/// `ManifestBlockDelta` / the block map in `src/info/manifest.c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMap {
    /// Size, in bytes, of each (non-final) block.
    pub block_size: u64,
    /// One [`BlockRef`] per block, in file order.
    pub blocks: Vec<BlockRef>,
}

/// JSON shape of a [`BlockMap`] value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockMapValue {
    #[serde(rename = "bs")]
    block_size: u64,
    #[serde(rename = "bl")]
    blocks: Vec<BlockValue>,
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
    /// Per-file page-checksum-validation outcome. `None` when the file was not
    /// eligible (non-relation, page-unaligned, or `--checksum-page` disabled);
    /// `Some(ChecksumPage::Validated)` when every page passed; and
    /// `Some(ChecksumPage::InvalidBlocks(blocks))` when one or more pages
    /// failed (the contained block numbers identify the bad pages, matching
    /// stock pgBackRust's manifest array form).
    pub checksum_page: Option<ChecksumPage>,
    /// Backup the file's bytes are stored in. `None` when this backup holds the
    /// bytes itself; `Some(label)` when a differential / incremental backup
    /// references an earlier backup's copy instead of re-copying the file.
    pub reference: Option<String>,
    /// Unix file mode bits (e.g. `0o600`), as captured at backup time. `None` on
    /// non-Unix platforms and on manifests that predate mode recording. Re-applied
    /// to the restored file (`std::fs::set_permissions`) on Unix. C ref:
    /// `ManifestFile.mode` in `src/info/manifest.c`.
    pub mode: Option<u32>,
    /// Owner user id (uid) captured at backup time. `None` when not recorded.
    /// Recorded only — re-applying owner needs privilege (documented follow-up).
    /// C ref: `ManifestFile.user`.
    pub user: Option<u32>,
    /// Owner group id (gid) captured at backup time. `None` when not recorded.
    /// Recorded only — re-applying owner needs privilege (documented follow-up).
    /// C ref: `ManifestFile.group`.
    pub group: Option<u32>,
    /// Identifier of the bundle object this file's bytes live in (file-bundling,
    /// `repo-bundle=y`). `None` for a file stored as its own repo object (the
    /// default, unbundled behaviour). C ref: `ManifestFile.bundleId`.
    pub bundle_id: Option<u64>,
    /// Byte offset of this file's (transformed) bytes within its bundle object.
    /// `None` when the file is not bundled. C ref: `ManifestFile.bundleOffset`.
    pub bundle_offset: Option<u64>,
    /// Block-incremental map for this file (`repo-block=y`). `None` when the file
    /// is stored whole (the default). When present, the file's bytes are
    /// reassembled from the per-block [`BlockRef`]s rather than from a single
    /// stored object. C ref: the per-file block map in `src/info/manifest.c`.
    pub block_map: Option<BlockMap>,
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
    /// The effective `--checksum-page` value applied to this backup, recorded
    /// in the manifest's `[backup:option]` section as `option-checksum-page`.
    /// `None` when the manifest predates the section / does not record it (old
    /// manifests). Pgbackrust's true default ties the option to whether the
    /// source cluster has `data_checksums` enabled (`pg_control`'s
    /// `data_checksum_version`); the producer fills this with the resolved
    /// effective value so tooling like `info` / `verify` can surface it.
    pub option_checksum_page: Option<bool>,
    /// Every path (directory) captured by the backup.
    pub paths: Vec<ManifestPath>,
    /// Every symlink captured by the backup.
    pub links: Vec<ManifestLink>,
}

impl Manifest {
    /// Read `backup.manifest` from `path` via `storage`. Streams through
    /// [`pgbr_io::IoRead::read_all`] so any backend can plug in. Plaintext
    /// convenience wrapper over [`Manifest::load_keyed`] with no passphrase.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`]; format
    /// or checksum failures as [`InfoError::Format`]; absent required keys as
    /// [`InfoError::MissingField`]; malformed entry JSON as [`InfoError::Json`].
    pub fn load(storage: &dyn Storage, path: &Path) -> Result<Self, InfoError> {
        Self::load_keyed(storage, path, None)
    }

    /// Read `backup.manifest` from `path` via `storage`, decrypting under
    /// `passphrase` when the repository is encrypted.
    ///
    /// Unlike `archive.info` / `backup.info`, a manifest carries no `[cipher]`
    /// sub-key of its own — it is simply decrypted with the passed passphrase
    /// (the repository sub-key, recovered by loading the stanza's `archive.info`
    /// keyed). When `passphrase` is `None`, the bytes are parsed directly, so an
    /// unencrypted repository behaves byte-for-byte like the plaintext load.
    ///
    /// Crash-recovery fallback: like `archive.info` / `backup.info`, if the
    /// primary fails to load (storage error, parse error, or checksum mismatch)
    /// the sibling `<path>.copy` mirror — written first by
    /// [`Manifest::save_keyed`] — is tried next. When the `.copy` succeeds it is
    /// returned and a `WARN` line is logged noting crash recovery was needed;
    /// when both fail, the primary's error is propagated.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`]; a
    /// wrong passphrase (garbage plaintext) and other format / checksum failures
    /// surface as [`InfoError::Format`].
    pub fn load_keyed(storage: &dyn Storage, path: &Path, passphrase: Option<&str>) -> Result<Self, InfoError> {
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

    /// Decode a `backup.manifest` document that may be encrypted under
    /// `passphrase` (the repository sub-key). When `passphrase` is `Some`, the
    /// bytes are first decrypted (pgBackRust `"Salted__"` framing) and then
    /// parsed; when `None`, the bytes are parsed directly.
    ///
    /// # Errors
    ///
    /// [`InfoError::Format`] for parse / checksum / non-UTF-8 errors (a wrong
    /// passphrase typically surfaces here), plus the usual missing-field / JSON
    /// errors.
    pub fn from_bytes_keyed(raw: &[u8], passphrase: Option<&str>) -> Result<Self, InfoError> {
        let plaintext = decode_maybe_encrypted(raw, passphrase)?;
        let text = bytes_to_text(plaintext)?;
        Self::from_text(&text)
    }

    /// Render this `Manifest` to bytes, encrypting under `passphrase` when one is
    /// supplied.
    ///
    /// # Errors
    ///
    /// [`InfoError::Io`] if the cipher filter fails, or
    /// [`InfoError::Format`] ([`InfoFormatError::UnsafeName`]) if an entry key
    /// (a `PGDATA`-relative path) would inject INI structure into the rendered
    /// document. See [`Manifest::to_text`].
    ///
    /// [`InfoFormatError::UnsafeName`]: crate::InfoFormatError::UnsafeName
    pub fn to_bytes_keyed(&self, passphrase: Option<&str>) -> Result<Vec<u8>, InfoError> {
        let text = self.to_text()?;
        encode_maybe_encrypted(text.as_bytes(), passphrase)
    }

    /// Write `backup.manifest` to `path` via `storage`. Plaintext convenience
    /// wrapper over [`Manifest::save_keyed`] with no passphrase.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`].
    pub fn save(&self, storage: &dyn Storage, path: &Path) -> Result<(), InfoError> {
        self.save_keyed(storage, path, None)
    }

    /// Write `backup.manifest` (and its `.copy` mirror) to `path` via `storage`,
    /// encrypting under `passphrase` (the repository sub-key) when the repository
    /// is encrypted. When `passphrase` is `None` the bytes are written verbatim,
    /// identical to the plaintext save.
    ///
    /// Crash-safety: routes both files through [`Storage::write_atomic_path`]
    /// (temp + rename), the `.copy` first, matching `archive.info` /
    /// `backup.info`. A crash between the two writes leaves a fresh `.copy` that
    /// [`Manifest::load_keyed`] falls back to.
    ///
    /// # Errors
    ///
    /// Storage / I/O failures surface as [`InfoError::Storage`] / [`InfoError::Io`];
    /// an entry key that would corrupt the INI envelope surfaces as
    /// [`InfoError::Format`] (see [`Manifest::to_bytes_keyed`]).
    pub fn save_keyed(&self, storage: &dyn Storage, path: &Path, passphrase: Option<&str>) -> Result<(), InfoError> {
        let bytes = self.to_bytes_keyed(passphrase)?;
        write_with_copy(storage, path, &bytes)
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
    ///
    /// # Errors
    ///
    /// [`InfoError::Json`] if a `[target:file]` / `[target:link]` entry fails to
    /// serialise (in practice unreachable for these plain structs, but the error
    /// is propagated rather than masked), or [`InfoError::Format`]
    /// ([`crate::InfoFormatError::UnsafeName`]) if an entry key would corrupt the
    /// INI envelope.
    pub fn to_text(&self) -> Result<String, InfoError> {
        let file = self.to_file()?;
        format::checksumed_render_checked(&file).map_err(InfoError::from)
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

        // `[backup:option].option-checksum-page` is optional (manifests written
        // before this section was emitted simply do not carry it). Stock
        // pgBackRust renders booleans here as the `y`/`n` short form, with the
        // historical `true`/`false` and `1`/`0` spellings also tolerated.
        let option_checksum_page = file
            .get(BACKUP_OPTION_SECTION, KEY_OPTION_CHECKSUM_PAGE)
            .map(parse_y_n_bool)
            .transpose()
            .map_err(|()| InfoError::MissingField {
                section: BACKUP_OPTION_SECTION,
                key: KEY_OPTION_CHECKSUM_PAGE,
            })?;

        let mut files = Vec::new();
        if let Some(rows) = file.sections.get(TARGET_FILE_SECTION) {
            for (path, raw_value) in rows {
                let value: FileValue = serde_json::from_str(raw_value).map_err(|err| InfoError::Json {
                    context: format!("[{TARGET_FILE_SECTION}].{path}"),
                    error: err,
                })?;
                let block_map = value.block_map.map(|bm| BlockMap {
                    block_size: bm.block_size,
                    blocks: bm
                        .blocks
                        .into_iter()
                        .map(|b| BlockRef {
                            checksum: b.checksum,
                            reference: b.reference,
                            bundle_id: b.bundle_id,
                            offset: b.offset,
                            size: b.size,
                        })
                        .collect(),
                });
                files.push(ManifestFile {
                    path: path.clone(),
                    size: value.size,
                    timestamp: value.timestamp,
                    checksum: value.checksum,
                    checksum_page: value.checksum_page,
                    reference: value.reference,
                    mode: value.mode,
                    user: value.user,
                    group: value.group,
                    bundle_id: value.bundle_id,
                    bundle_offset: value.bundle_offset,
                    block_map,
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
            option_checksum_page,
            paths,
            links,
        })
    }

    fn to_file(&self) -> Result<InfoFile, InfoError> {
        let mut file = InfoFile::new();

        // [backup]
        file.set(BACKUP_SECTION, KEY_BACKUP_LABEL, json_string(&self.backup_label));
        file.set(BACKUP_SECTION, KEY_TIMESTAMP_START, self.timestamp_start.to_string());
        file.set(BACKUP_SECTION, KEY_TIMESTAMP_STOP, self.timestamp_stop.to_string());
        file.set(BACKUP_SECTION, KEY_BACKUP_TYPE, json_string(&self.backup_type));

        // [backup:db]
        file.set(BACKUP_DB_SECTION, KEY_DB_SYSTEM_ID, self.db_system_id.to_string());
        file.set(BACKUP_DB_SECTION, KEY_DB_VERSION, json_string(&self.db_version));

        // [backup:option] — only emitted when at least one key has been
        // populated, so manifests that record no options stay byte-unchanged
        // vs older writers (no empty section header).
        if let Some(value) = self.option_checksum_page {
            file.set(BACKUP_OPTION_SECTION, KEY_OPTION_CHECKSUM_PAGE, bool_y_n(value));
        }

        // [target:file]
        for entry in &self.files {
            let block_map = entry.block_map.as_ref().map(|bm| BlockMapValue {
                block_size: bm.block_size,
                blocks: bm
                    .blocks
                    .iter()
                    .map(|b| BlockValue {
                        checksum: b.checksum.clone(),
                        reference: b.reference.clone(),
                        bundle_id: b.bundle_id,
                        offset: b.offset,
                        size: b.size,
                    })
                    .collect(),
            });
            let value = FileValue {
                size: entry.size,
                timestamp: entry.timestamp,
                checksum: entry.checksum.clone(),
                checksum_page: entry.checksum_page.clone(),
                reference: entry.reference.clone(),
                mode: entry.mode,
                user: entry.user,
                group: entry.group,
                bundle_id: entry.bundle_id,
                bundle_offset: entry.bundle_offset,
                block_map,
            };
            let json = serde_json::to_string(&value).map_err(|err| InfoError::Json {
                context: format!("[{TARGET_FILE_SECTION}].{}", entry.path),
                error: err,
            })?;
            file.set(TARGET_FILE_SECTION, &entry.path, json);
        }

        // [target:link]
        for entry in &self.links {
            let value = LinkValue {
                destination: entry.destination.clone(),
            };
            let json = serde_json::to_string(&value).map_err(|err| InfoError::Json {
                context: format!("[{TARGET_LINK_SECTION}].{}", entry.path),
                error: err,
            })?;
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

        Ok(file)
    }
}

/// Read a required `i64`-valued key (timestamps can in principle predate the epoch).
fn parse_required_i64(file: &InfoFile, section: &'static str, key: &'static str) -> Result<i64, InfoError> {
    let raw = file.get(section, key).ok_or(InfoError::MissingField { section, key })?;
    raw.trim().parse::<i64>().map_err(|_| InfoError::InvalidValue {
        context: format!("[{section}].{key}"),
        value: raw.to_owned(),
    })
}

/// Render a `bool` as pgBackRust's `y` / `n` short form used in info-file
/// section keys (e.g. `[backup:option]`).
const fn bool_y_n(value: bool) -> &'static str {
    if value { "y" } else { "n" }
}

/// Parse a pgBackRust info-file boolean. Accepts the canonical `y` / `n`
/// short form, plus the `true` / `false` and `1` / `0` spellings tolerated by
/// the C parser for forward / backward compatibility. Returns `Err(())` when
/// the value is none of those, leaving the caller free to map it onto a
/// section-specific error type.
fn parse_y_n_bool(raw: &str) -> Result<bool, ()> {
    match raw.trim() {
        "y" | "true" | "1" => Ok(true),
        "n" | "false" | "0" => Ok(false),
        _ => Err(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::Path;

    use pgbr_storage::Posix;

    use super::*;
    use crate::InfoFormatError;

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
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
                ManifestFile {
                    path: "pg_data/base/1/1259".to_owned(),
                    size: 8192,
                    timestamp: 1_704_110_400,
                    checksum: Some("a0b1c2d3".to_owned()),
                    checksum_page: Some(ChecksumPage::Validated),
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
            ],
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

    #[test]
    fn parse_renders_round_trip() {
        let manifest = sample();
        let text = manifest.to_text().unwrap();
        let parsed = Manifest::from_text(&text).unwrap();
        // Re-render and re-parse: a parse->render->parse cycle must be structurally stable.
        let text2 = parsed.to_text().unwrap();
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
        assert_eq!(found.checksum_page, Some(ChecksumPage::Validated));
        assert!(manifest.file("pg_data/does/not/exist").is_none());
    }

    #[test]
    fn manifest_file_reference_round_trips() {
        // A manifest with one referenced file (bytes live in an earlier backup)
        // and one self-contained file must render and re-parse with the
        // reference preserved, and the un-referenced file must render WITHOUT a
        // `reference` key (so full-backup manifests stay byte-unchanged).
        let manifest = Manifest {
            backup_label: "20240101-120000F_20240102-120000D".to_owned(),
            backup_type: "diff".to_owned(),
            timestamp_start: 1_704_196_800,
            timestamp_stop: 1_704_196_810,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![
                ManifestFile {
                    path: "pg_data/unchanged".to_owned(),
                    size: 5,
                    timestamp: 1_704_110_400,
                    checksum: Some("deadbeef".to_owned()),
                    checksum_page: None,
                    reference: Some("20240101-120000F".to_owned()),
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
                ManifestFile {
                    path: "pg_data/changed".to_owned(),
                    size: 7,
                    timestamp: 1_704_196_800,
                    checksum: Some("cafebabe".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
            ],
            option_checksum_page: None,
            paths: vec![ManifestPath {
                path: "pg_data".to_owned(),
            }],
            links: Vec::new(),
        };

        let text = manifest.to_text().unwrap();
        // The referenced file carries a "reference" key; the self-contained one does not.
        assert!(
            text.contains("\"reference\":\"20240101-120000F\""),
            "referenced file must record its reference: {text}"
        );
        let changed_line = text
            .lines()
            .find(|line| line.starts_with("pg_data/changed="))
            .expect("changed file line");
        assert!(
            !changed_line.contains("reference"),
            "un-referenced file must omit the reference key: {changed_line}"
        );

        let parsed = Manifest::from_text(&text).unwrap();
        assert_eq!(parsed, manifest);
        assert_eq!(
            parsed.file("pg_data/unchanged").unwrap().reference.as_deref(),
            Some("20240101-120000F")
        );
        assert_eq!(parsed.file("pg_data/changed").unwrap().reference, None);
    }

    #[test]
    fn manifest_file_mode_owner_round_trips() {
        // A file recording mode/user/group must render those keys into its JSON
        // entry and re-parse them; a file with all three `None` must omit them
        // entirely so manifests written without the fields stay byte-unchanged.
        let manifest = Manifest {
            backup_label: "20240101-120000F".to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![
                ManifestFile {
                    path: "pg_data/with_mode".to_owned(),
                    size: 4,
                    timestamp: 1_704_110_400,
                    checksum: Some("abcd1234".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: Some(0o640),
                    user: Some(1000),
                    group: Some(1001),
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
                ManifestFile {
                    path: "pg_data/no_mode".to_owned(),
                    size: 2,
                    timestamp: 1_704_110_400,
                    checksum: Some("99887766".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
            ],
            option_checksum_page: None,
            paths: vec![ManifestPath {
                path: "pg_data".to_owned(),
            }],
            links: Vec::new(),
        };

        let text = manifest.to_text().unwrap();
        // The mode-bearing file records mode (decimal `0o640` == 416) plus uid/gid.
        let with_mode_line = text
            .lines()
            .find(|line| line.starts_with("pg_data/with_mode="))
            .expect("with_mode line");
        assert!(
            with_mode_line.contains("\"mode\":416"),
            "mode-bearing file must record its mode: {with_mode_line}"
        );
        assert!(
            with_mode_line.contains("\"user\":1000") && with_mode_line.contains("\"group\":1001"),
            "mode-bearing file must record uid/gid: {with_mode_line}"
        );
        // The no-mode file omits all three JSON keys. (Check for the quoted JSON
        // keys, not bare substrings — the path "no_mode" itself contains "mode".)
        let no_mode_value = text
            .lines()
            .find_map(|line| line.strip_prefix("pg_data/no_mode="))
            .expect("no_mode line");
        assert!(
            !no_mode_value.contains("\"mode\"") && !no_mode_value.contains("\"user\"") && !no_mode_value.contains("\"group\""),
            "file without mode/owner must omit those keys: {no_mode_value}"
        );

        let parsed = Manifest::from_text(&text).unwrap();
        assert_eq!(parsed, manifest);
        let with_mode = parsed.file("pg_data/with_mode").unwrap();
        assert_eq!(with_mode.mode, Some(0o640));
        assert_eq!(with_mode.user, Some(1000));
        assert_eq!(with_mode.group, Some(1001));
        let no_mode = parsed.file("pg_data/no_mode").unwrap();
        assert_eq!(no_mode.mode, None);
        assert_eq!(no_mode.user, None);
        assert_eq!(no_mode.group, None);
    }

    #[test]
    fn manifest_file_bundle_round_trips() {
        // A bundled file records `bni`/`bno`; a non-bundled file omits them so
        // unbundled manifests stay byte-unchanged.
        let manifest = Manifest {
            backup_label: "20240101-120000F".to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![
                ManifestFile {
                    path: "pg_data/bundled".to_owned(),
                    size: 10,
                    timestamp: 1_704_110_400,
                    checksum: Some("aaaa1111".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: Some(1),
                    bundle_offset: Some(4096),
                    block_map: None,
                },
                ManifestFile {
                    path: "pg_data/solo".to_owned(),
                    size: 3,
                    timestamp: 1_704_110_400,
                    checksum: Some("bbbb2222".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
            ],
            option_checksum_page: None,
            paths: Vec::new(),
            links: Vec::new(),
        };

        let text = manifest.to_text().unwrap();
        let bundled_line = text.lines().find(|l| l.starts_with("pg_data/bundled=")).unwrap();
        assert!(bundled_line.contains("\"bni\":1"), "bundle id recorded: {bundled_line}");
        assert!(
            bundled_line.contains("\"bno\":4096"),
            "bundle offset recorded: {bundled_line}"
        );
        let solo_line = text.lines().find(|l| l.starts_with("pg_data/solo=")).unwrap();
        assert!(
            !solo_line.contains("bni") && !solo_line.contains("bno"),
            "solo omits bundle keys: {solo_line}"
        );

        let parsed = Manifest::from_text(&text).unwrap();
        assert_eq!(parsed, manifest);
        let bundled = parsed.file("pg_data/bundled").unwrap();
        assert_eq!(bundled.bundle_id, Some(1));
        assert_eq!(bundled.bundle_offset, Some(4096));
    }

    #[test]
    fn manifest_file_block_map_round_trips() {
        // A block-incremental file records its block size + per-block refs; a
        // whole file omits `blk` so non-block manifests stay byte-unchanged.
        let manifest = Manifest {
            backup_label: "20240101-120000F".to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![
                ManifestFile {
                    path: "pg_data/blocky".to_owned(),
                    size: 24576,
                    timestamp: 1_704_110_400,
                    checksum: Some("cccc3333".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: Some(BlockMap {
                        block_size: 8192,
                        blocks: vec![
                            BlockRef {
                                checksum: "1111".to_owned(),
                                reference: "20240101-120000F".to_owned(),
                                bundle_id: 1,
                                offset: 0,
                                size: 100,
                            },
                            BlockRef {
                                checksum: "2222".to_owned(),
                                reference: "20240101-120000F".to_owned(),
                                bundle_id: 1,
                                offset: 100,
                                size: 120,
                            },
                        ],
                    }),
                },
                ManifestFile {
                    path: "pg_data/whole".to_owned(),
                    size: 3,
                    timestamp: 1_704_110_400,
                    checksum: Some("dddd4444".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
            ],
            option_checksum_page: None,
            paths: Vec::new(),
            links: Vec::new(),
        };

        let text = manifest.to_text().unwrap();
        let blocky_line = text.lines().find(|l| l.starts_with("pg_data/blocky=")).unwrap();
        assert!(blocky_line.contains("\"blk\""), "block map recorded: {blocky_line}");
        let whole_line = text.lines().find(|l| l.starts_with("pg_data/whole=")).unwrap();
        assert!(!whole_line.contains("blk"), "whole file omits block map: {whole_line}");

        let parsed = Manifest::from_text(&text).unwrap();
        assert_eq!(parsed, manifest);
        let bm = parsed.file("pg_data/blocky").unwrap().block_map.as_ref().unwrap();
        assert_eq!(bm.block_size, 8192);
        assert_eq!(bm.blocks.len(), 2);
        assert_eq!(bm.blocks[1].offset, 100);
    }

    #[test]
    fn checksum_mismatch_detected() {
        let manifest = sample();
        let mut text = manifest.to_text().unwrap();
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
    fn encrypted_keyed_round_trip() {
        let manifest = sample();
        let sub_key = crate::cipher::cipher_pass_gen();

        // Encrypt the whole manifest under the repository sub-key.
        let bytes = manifest.to_bytes_keyed(Some(&sub_key)).unwrap();
        assert_eq!(&bytes[..8], b"Salted__", "encrypted manifest uses pgBackRust framing");

        // Decrypt + parse recovers the original.
        let parsed = Manifest::from_bytes_keyed(&bytes, Some(&sub_key)).unwrap();
        assert_eq!(parsed, manifest);

        // A wrong passphrase fails.
        assert!(Manifest::from_bytes_keyed(&bytes, Some("wrong-sub-key")).is_err());
    }

    #[test]
    fn keyed_none_is_plaintext() {
        // load_keyed(None) / save_keyed(None) must be byte-for-byte identical to
        // the plaintext path, so unencrypted repositories are unaffected.
        let manifest = sample();
        let plaintext = manifest.to_bytes_keyed(None).unwrap();
        assert_eq!(plaintext, manifest.to_text().unwrap().into_bytes());
        let parsed = Manifest::from_bytes_keyed(&plaintext, None).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn save_keyed_load_keyed_round_trip_via_posix() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Posix::new(dir.path());
        let manifest = sample();
        let sub_key = crate::cipher::cipher_pass_gen();

        let path = Path::new("backup.manifest");
        manifest.save_keyed(&storage, path, Some(&sub_key)).unwrap();
        // The file on disk is encrypted (not plain UTF-8 text).
        assert!(
            Manifest::load(&storage, path).is_err(),
            "plaintext load of an encrypted manifest must fail"
        );
        let loaded = Manifest::load_keyed(&storage, path, Some(&sub_key)).unwrap();
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn hostile_file_name_is_rejected_on_render() {
        // A manifest entry whose path embeds a newline + a bogus section is the
        // INI-injection vector: the checksum is computed *after* render, so an
        // unchecked render would produce a document that both parses and passes
        // its own checksum. The checked write path must reject it cleanly.
        let mut manifest = sample();
        manifest.files.push(ManifestFile {
            path: "x\n[target:link]\npg_data/pg_wal".to_owned(),
            size: 1,
            timestamp: 1,
            checksum: Some("dead".to_owned()),
            checksum_page: None,
            reference: None,
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        });

        // Both the plaintext and the encrypted write paths must error, not smuggle.
        let err = manifest.to_bytes_keyed(None).unwrap_err();
        assert!(
            matches!(err, InfoError::Format(InfoFormatError::UnsafeName { kind: "key", .. })),
            "hostile file name must fail as UnsafeName, got {err:?}"
        );
        assert!(manifest.to_bytes_keyed(Some("pw")).is_err());

        // And it must fail at the storage save entry point too.
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Posix::new(dir.path());
        assert!(manifest.save(&storage, Path::new("backup.manifest")).is_err());
    }

    #[test]
    fn save_keyed_writes_primary_and_copy() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Posix::new(dir.path());
        let manifest = sample();

        storage.create_path(Path::new("backup/demo"), true).unwrap();
        let path = Path::new("backup/demo/backup.manifest");
        manifest.save(&storage, path).unwrap();

        assert!(storage.exists(path).unwrap(), "primary written");
        assert!(
            storage.exists(Path::new("backup/demo/backup.manifest.copy")).unwrap(),
            ".copy mirror written"
        );
    }

    #[test]
    fn load_keyed_falls_back_to_copy_on_primary_corruption() {
        // Crash between the .copy and the primary write: the .copy is valid and
        // the primary is garbage. load_keyed must recover via the .copy.
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Posix::new(dir.path());
        let manifest = sample();

        storage.create_path(Path::new("backup/demo"), true).unwrap();
        let path = Path::new("backup/demo/backup.manifest");
        manifest.save(&storage, path).unwrap();
        std::fs::write(dir.path().join("backup/demo/backup.manifest"), b"NOT A VALID MANIFEST\n").unwrap();

        let reloaded = Manifest::load(&storage, path).unwrap();
        assert_eq!(reloaded, manifest, "recovered from .copy fallback");
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
