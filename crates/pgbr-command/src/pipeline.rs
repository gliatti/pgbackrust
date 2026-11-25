//! Repo-side transform pipeline shared by `backup` and `restore`.
//!
//! A backup may compress and/or encrypt every file before it lands in the
//! repository. Restore has to reverse exactly those transforms, in the
//! opposite order, to recover the original plaintext. Keeping both sides in
//! agreement is what [`RepoTransform`] is for: it captures *what was applied*
//! (compression codec + level, optional cipher password) and builds the
//! forward (backup-side) and reverse (restore-side) [`pgbr_io::FilterChain`]s
//! from a single source of truth.
//!
//! C reference: `src/common/compress/helper.c` (codec/extension mapping) and
//! the filter wiring inside `src/command/backup/backup.c` /
//! `src/command/restore/restore.c`.
//!
//! # pgBackRust semantics modelled here
//!
//! - **Order.** Backup compresses *then* encrypts; restore decrypts *then*
//!   decompresses. Compressing before encrypting is mandatory — ciphertext is
//!   incompressible, so the reverse order would defeat compression.
//! - **Suffix.** The repo filename carries the compression extension
//!   (`.gz` / `.bz2` / `.lz4` / `.zst`); encryption does **not** change the
//!   name. [`RepoTransform::repo_suffix`].
//! - **Checksum.** The manifest records the SHA-1 and size of the *plaintext*
//!   file, independent of how it is stored in the repo. That is what restore
//!   verifies after reversing the transform — so the check validates the whole
//!   compress -> encrypt -> decrypt -> decompress round trip.
//! - **Identity.** `compress-type=none` with no cipher is the identity
//!   transform: empty suffix, pass-through chains. The pre-existing raw-copy
//!   behaviour is preserved byte-for-byte.

use pgbr_compress::filter::{
    Bz2Compress, Bz2Decompress, GzCompress, GzDecompress, Lz4Compress, Lz4Decompress, ZstCompress, ZstDecompress,
};
use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_io::FilterChain;
use pgbr_io::filter::{Cipher, CipherDigest, CipherMode};

use crate::CommandError;

/// Compression codec applied to a repo file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressType {
    /// No compression — bytes are stored verbatim.
    None,
    /// gzip (gzip-framed deflate).
    Gz,
    /// bzip2.
    Bz2,
    /// LZ4 frame.
    Lz4,
    /// Zstandard.
    Zst,
}

impl CompressType {
    /// Parse a `compress-type` string-id (`none` / `gz` / `bz2` / `lz4` /
    /// `zst`). Anything unrecognised falls back to [`CompressType::None`] so a
    /// malformed option degrades to a raw copy rather than failing the backup.
    ///
    /// This lossy form is kept for the *backup / suffix-parsing* side, where a
    /// stray value can only ever mean "not compressed". On the **restore** side
    /// use [`CompressType::try_from_str_id`] instead: reversing a backup with a
    /// codec we do not understand must be a hard error, never a silent raw copy
    /// of what is actually compressed data (which would corrupt the restored
    /// file).
    #[must_use]
    pub fn from_str_id(value: &str) -> Self {
        match value {
            "gz" => Self::Gz,
            "bz2" => Self::Bz2,
            "lz4" => Self::Lz4,
            "zst" => Self::Zst,
            // "none" and any unrecognised value.
            _ => Self::None,
        }
    }

    /// Strict parse of a `compress-type` string-id: unlike
    /// [`CompressType::from_str_id`] an unrecognised codec is a hard error
    /// rather than a silent degrade to [`CompressType::None`].
    ///
    /// Used on the restore path ([`RepoTransform::from_metadata_checked`]):
    /// a `backup.info` that records a codec this build cannot decode must abort
    /// the restore, because decompressing with the wrong (or no) codec would
    /// hand back corrupt bytes that still pass no check.
    ///
    /// # Errors
    ///
    /// [`CommandError::Other`] naming the unknown `compress-type` value.
    pub fn try_from_str_id(value: &str) -> Result<Self, CommandError> {
        match value {
            "none" => Ok(Self::None),
            "gz" => Ok(Self::Gz),
            "bz2" => Ok(Self::Bz2),
            "lz4" => Ok(Self::Lz4),
            "zst" => Ok(Self::Zst),
            other => Err(CommandError::Other(format!(
                "unknown compress-type `{other}` recorded in backup.info; cannot reverse the repo transform"
            ))),
        }
    }

    /// The canonical `compress-type` string-id for this codec, as recorded in
    /// `backup.info`.
    #[must_use]
    pub const fn as_str_id(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gz => "gz",
            Self::Bz2 => "bz2",
            Self::Lz4 => "lz4",
            Self::Zst => "zst",
        }
    }

    /// The repo filename suffix for this codec (`".gz"` / `".bz2"` /
    /// `".lz4"` / `".zst"`, or `""` for [`CompressType::None`]).
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Gz => ".gz",
            Self::Bz2 => ".bz2",
            Self::Lz4 => ".lz4",
            Self::Zst => ".zst",
        }
    }

    /// A sane default compression level for this codec, matching pgBackRust's
    /// per-type defaults: `gz`=6, `bz2`=9, `lz4`=1, `zst`=3. Used when
    /// `compress-level` is not supplied.
    #[must_use]
    pub const fn default_level(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Gz => 6,
            Self::Bz2 => 9,
            Self::Lz4 => 1,
            Self::Zst => 3,
        }
    }
}

/// The transforms a backup applied to its files, so restore can reverse them.
///
/// Built from the resolved CLI/config options ([`RepoTransform::from_options`])
/// on the backup side, and reconstructed from the recorded `backup.info`
/// metadata on the restore side ([`RepoTransform::from_metadata`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoTransform {
    /// Compression codec (or [`CompressType::None`]).
    pub compress_type: CompressType,
    /// Compression level passed to the codec.
    pub compress_level: i32,
    /// `Some(pass)` enables AES-256-CBC with that password; `None` means no
    /// encryption.
    ///
    /// Under the real two-level key scheme this is a resolved sub-key — the
    /// repo sub-key (for WAL / manifest) or a per-backup sub-key (for backup
    /// file data) — rather than the raw user passphrase. The cipher digest is
    /// selected by which builder produced the chain (see
    /// [`RepoTransform::forward_chain`] for the legacy MD5 path and
    /// [`RepoTransform::forward_chain_keyed`] for the pgBackRust SHA-1 path).
    pub cipher_pass: Option<String>,
}

impl RepoTransform {
    /// The identity transform: no compression, no encryption.
    #[must_use]
    pub const fn identity() -> Self {
        Self {
            compress_type: CompressType::None,
            compress_level: 0,
            cipher_pass: None,
        }
    }

    /// Read the transform from the resolved CLI/config options.
    ///
    /// - `compress-type` (`StringId`) selects the codec; when absent it
    ///   defaults to `gz` if the `compress` boolean is true, otherwise `none`.
    /// - `compress-level` (`Integer`) overrides the per-codec default level.
    /// - `cipher-type` (`StringId`) of `aes-256-cbc` enables encryption with
    ///   the `cipher-pass` (`String`) password; any other value (or absent)
    ///   means no encryption.
    #[must_use]
    pub fn from_options(config: &LoadedConfig) -> Self {
        let compress_type = string_id_opt(config, "compress-type").map_or_else(
            // No explicit compress-type: honour the legacy `compress` boolean
            // (true -> gz, otherwise none).
            || {
                if boolean_opt(config, "compress") == Some(true) {
                    CompressType::Gz
                } else {
                    CompressType::None
                }
            },
            CompressType::from_str_id,
        );

        let compress_level = integer_opt(config, "compress-level")
            .and_then(|n| i32::try_from(n).ok())
            .unwrap_or_else(|| compress_type.default_level());

        let cipher_pass = match string_id_opt(config, "cipher-type") {
            Some("aes-256-cbc") => string_opt(config, "cipher-pass").map(str::to_owned),
            _ => None,
        };

        Self {
            compress_type,
            compress_level,
            cipher_pass,
        }
    }

    /// Build a key-managed transform for the real two-level encryption scheme.
    ///
    /// `cipher_pass` is a **resolved sub-key** — the repository sub-key (for WAL
    /// archive / manifest files) or a per-backup sub-key (for a backup's file
    /// data), as produced by [`pgbr_info::RepoKeys`]. Pair it with the keyed
    /// chain builders ([`RepoTransform::forward_chain_keyed`] /
    /// [`reverse_chain_keyed`](Self::reverse_chain_keyed)) so the cipher uses
    /// pgBackRust's default SHA-1 KDF, making the repo bytes byte-compatible
    /// with a pgBackRust C repository.
    ///
    /// `compress_type` / `compress_level` come from the resolved options; pass
    /// `None` for `cipher_pass` to layer compression only.
    #[must_use]
    pub const fn with_key(compress_type: CompressType, compress_level: i32, cipher_pass: Option<String>) -> Self {
        Self {
            compress_type,
            compress_level,
            cipher_pass,
        }
    }

    /// Take the compression settings resolved from `config` but override the
    /// encryption key with `sub_key` (a resolved repo / backup sub-key).
    /// `sub_key = None` disables encryption. Use with the keyed chain builders.
    ///
    /// This is the bridge backup / restore use: compression is read from the
    /// command options while the cipher key comes from the resolved key chain
    /// rather than the raw user passphrase.
    #[must_use]
    pub fn from_options_with_key(config: &LoadedConfig, sub_key: Option<String>) -> Self {
        let base = Self::from_options(config);
        Self::with_key(base.compress_type, base.compress_level, sub_key)
    }

    /// `true` when a backup's recorded `backup.info` `[backup:current]` `entry`
    /// says its repo bytes are encrypted. When the flag is absent (older
    /// metadata) it falls back to "encrypted iff the options resolve a cipher".
    fn metadata_is_encrypted(entry: &serde_json::Value, config: &LoadedConfig) -> bool {
        entry
            .get(metadata_encrypted_key())
            .and_then(serde_json::Value::as_bool)
            .unwrap_or_else(|| Self::from_options(config).cipher_pass.is_some())
    }

    /// Reconstruct the transform from the values recorded in a backup's
    /// `backup.info` `[backup:current]` entry (see
    /// [`metadata_compress_type_key`] / [`metadata_encrypted_key`]), overriding
    /// the cipher key with the caller-resolved `sub_key`, and **failing loudly**
    /// on anything that would otherwise corrupt the restored bytes.
    ///
    /// This is the correct restore-side constructor. Compared with the lossy
    /// [`from_metadata`](Self::from_metadata) it fixes two silent hazards:
    ///
    /// - **Unknown codec.** A recorded `compress-type` this build cannot decode
    ///   is a hard error ([`CompressType::try_from_str_id`]) rather than a silent
    ///   degrade to [`CompressType::None`], which would hand back still-compressed
    ///   bytes as if they were plaintext.
    /// - **Missing key.** If the backup is marked encrypted but the caller could
    ///   not resolve a decryption key (`sub_key == None`), it errors instead of
    ///   building a reverse chain with no decrypt filter (which would "restore"
    ///   the ciphertext verbatim). The key is the resolved repository / backup
    ///   **sub-key** (`repo-cipher-pass` → `[cipher]` sub-key), never the raw
    ///   user passphrase — passing the wrong key level here cannot decrypt.
    ///
    /// `compress_level` is taken from the options (it does not affect the reverse
    /// chain). For an unencrypted repo pass `sub_key = None`.
    ///
    /// # Errors
    ///
    /// [`CommandError::Other`] for an unknown recorded `compress-type`;
    /// [`CommandError::MissingOption`] (`"repo-cipher-pass"`) when the backup is
    /// encrypted but no `sub_key` was resolved.
    pub fn from_metadata_checked(
        entry: &serde_json::Value,
        config: &LoadedConfig,
        sub_key: Option<&str>,
    ) -> Result<Self, CommandError> {
        let from_opts = Self::from_options(config);

        // A recorded codec must be understood; anything else aborts the restore
        // rather than silently degrading to a raw copy of compressed data.
        let compress_type = match entry.get(metadata_compress_type_key()).and_then(serde_json::Value::as_str) {
            Some(recorded) => CompressType::try_from_str_id(recorded)?,
            None => from_opts.compress_type,
        };

        let cipher_pass = if Self::metadata_is_encrypted(entry, config) {
            // Encrypted backup: the ONLY valid key is the resolved sub-key. If
            // the caller has none, refuse — do not build a decrypt-less chain
            // (silent ciphertext restore) and do not fall back to the raw user
            // passphrase (wrong key level, cannot decrypt).
            let key = sub_key.ok_or_else(|| CommandError::MissingOption {
                option: "repo-cipher-pass".to_owned(),
            })?;
            Some(key.to_owned())
        } else {
            None
        };

        Ok(Self {
            compress_type,
            compress_level: from_opts.compress_level,
            cipher_pass,
        })
    }

    /// Reconstruct the transform from the values recorded in a backup's
    /// `backup.info` `[backup:current]` entry (see
    /// [`metadata_compress_type_key`] / [`metadata_encrypted_key`]), falling
    /// back to the resolved options for anything the metadata does not pin.
    ///
    /// # Lossy — prefer [`from_metadata_checked`](Self::from_metadata_checked)
    ///
    /// This constructor cannot resolve the repository sub-key (it has no storage
    /// handle) and cannot fail, so it is only safe when the caller **injects the
    /// resolved key afterwards** via [`with_key`](Self::with_key) (as restore
    /// does) or when the repo is unencrypted. It leaves `cipher_pass` empty for
    /// an encrypted backup — a reverse chain built directly from the result
    /// would skip decryption. New code should use
    /// [`from_metadata_checked`](Self::from_metadata_checked), which errors in
    /// that case instead. An unknown recorded `compress-type` still degrades to
    /// [`CompressType::None`] here for backwards compatibility; the checked form
    /// rejects it.
    #[must_use]
    pub fn from_metadata(entry: &serde_json::Value, config: &LoadedConfig) -> Self {
        let from_opts = Self::from_options(config);

        let compress_type = entry
            .get(metadata_compress_type_key())
            .and_then(serde_json::Value::as_str)
            .map_or(from_opts.compress_type, CompressType::from_str_id);

        // The repository sub-key is not resolvable here, so callers must inject
        // it via `with_key` (restore does exactly that). We deliberately do NOT
        // fall back to the raw user passphrase: that is the wrong key level and
        // would never decrypt a real pgBackRust repo. `cipher_pass` is therefore
        // left empty; `from_metadata_checked` is the constructor that turns a
        // missing key into a hard error.
        Self {
            compress_type,
            compress_level: from_opts.compress_level,
            cipher_pass: None,
        }
    }

    /// `true` when the repo bytes are encrypted under this transform.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.cipher_pass.is_some()
    }

    /// The repo-side filename suffix for this compression (`".gz"`, `".zst"`,
    /// `""` for none). Encryption does not change the suffix.
    #[must_use]
    pub const fn repo_suffix(&self) -> &'static str {
        self.compress_type.suffix()
    }

    /// Build the forward (backup-side) filter chain: compress **then** encrypt,
    /// using the legacy MD5 KDF (`openssl enc` default).
    ///
    /// # Legacy — no production caller
    ///
    /// Nothing in the command layer uses the MD5 chain any more: `backup`,
    /// `restore`, `archive` **and** `repo-get` / `repo-put` all go through the
    /// keyed SHA-1 chain ([`forward_chain_keyed`](Self::forward_chain_keyed) /
    /// [`reverse_chain_keyed`](Self::reverse_chain_keyed)) so their on-disk
    /// bytes are byte-compatible with a pgBackRust C repository. This method is
    /// retained only so the cross-KDF invariant stays under test (an MD5 chain
    /// must never decrypt SHA-1 ciphertext). Do not add new production callers.
    ///
    /// An empty chain (no compression, no cipher) passes bytes through
    /// unchanged, preserving the raw-copy behaviour.
    #[must_use]
    pub fn forward_chain(&self) -> FilterChain {
        self.forward_chain_with_digest(CipherDigest::Md5)
    }

    /// Build the reverse (restore-side) filter chain: decrypt **then**
    /// decompress — the exact inverse of [`RepoTransform::forward_chain`]
    /// (legacy MD5 KDF). See [`forward_chain`](Self::forward_chain): legacy,
    /// no production caller.
    #[must_use]
    pub fn reverse_chain(&self) -> FilterChain {
        self.reverse_chain_with_digest(CipherDigest::Md5)
    }

    /// Build the forward chain for the real two-level key scheme: compress
    /// **then** encrypt with pgBackRust's default **SHA-1** KDF. Pair this with
    /// a [`cipher_pass`](Self::cipher_pass) that is a resolved sub-key (see
    /// [`RepoTransform::with_key`]) so the repo bytes match a pgBackRust C
    /// repository.
    #[must_use]
    pub fn forward_chain_keyed(&self) -> FilterChain {
        self.forward_chain_with_digest(CipherDigest::Sha1)
    }

    /// Reverse of [`RepoTransform::forward_chain_keyed`] (SHA-1 KDF).
    #[must_use]
    pub fn reverse_chain_keyed(&self) -> FilterChain {
        self.reverse_chain_with_digest(CipherDigest::Sha1)
    }

    /// Shared forward-chain builder parameterised by the KDF `digest`.
    fn forward_chain_with_digest(&self, digest: CipherDigest) -> FilterChain {
        let mut chain = FilterChain::new();
        match self.compress_type {
            CompressType::None => {}
            CompressType::Gz => chain.push(GzCompress::new(self.compress_level, false)),
            CompressType::Bz2 => chain.push(Bz2Compress::new(self.compress_level)),
            CompressType::Lz4 => chain.push(Lz4Compress::new(self.compress_level, false)),
            CompressType::Zst => chain.push(ZstCompress::new(self.compress_level)),
        }
        if let Some(pass) = &self.cipher_pass {
            chain.push(Cipher::new(CipherMode::Encrypt, digest, pass.as_bytes()));
        }
        chain
    }

    /// Shared reverse-chain builder parameterised by the KDF `digest`.
    fn reverse_chain_with_digest(&self, digest: CipherDigest) -> FilterChain {
        let mut chain = FilterChain::new();
        if let Some(pass) = &self.cipher_pass {
            chain.push(Cipher::new(CipherMode::Decrypt, digest, pass.as_bytes()));
        }
        match self.compress_type {
            CompressType::None => {}
            CompressType::Gz => chain.push(GzDecompress::new(false)),
            CompressType::Bz2 => chain.push(Bz2Decompress::new()),
            CompressType::Lz4 => chain.push(Lz4Decompress::new()),
            CompressType::Zst => chain.push(ZstDecompress::new()),
        }
        chain
    }

    /// Run `input` through this transform's [`forward_chain`](Self::forward_chain),
    /// returning the repo-side bytes (legacy MD5 KDF).
    ///
    /// # Errors
    ///
    /// Propagates any [`pgbr_io::IoError`] raised by a filter in the chain.
    pub fn apply_forward(&self, input: &[u8]) -> Result<Vec<u8>, pgbr_io::IoError> {
        run_chain(&mut self.forward_chain(), input)
    }

    /// Run `input` (repo-side bytes) through this transform's
    /// [`reverse_chain`](Self::reverse_chain), returning the recovered plaintext
    /// (legacy MD5 KDF).
    ///
    /// # Errors
    ///
    /// Propagates any [`pgbr_io::IoError`] raised by a filter in the chain.
    pub fn apply_reverse(&self, input: &[u8]) -> Result<Vec<u8>, pgbr_io::IoError> {
        run_chain(&mut self.reverse_chain(), input)
    }

    /// Run `input` through the key-managed forward chain
    /// ([`forward_chain_keyed`](Self::forward_chain_keyed), SHA-1 KDF).
    ///
    /// # Errors
    ///
    /// Propagates any [`pgbr_io::IoError`] raised by a filter in the chain.
    pub fn apply_forward_keyed(&self, input: &[u8]) -> Result<Vec<u8>, pgbr_io::IoError> {
        run_chain(&mut self.forward_chain_keyed(), input)
    }

    /// Run `input` through the key-managed reverse chain
    /// ([`reverse_chain_keyed`](Self::reverse_chain_keyed), SHA-1 KDF).
    ///
    /// # Errors
    ///
    /// Propagates any [`pgbr_io::IoError`] raised by a filter in the chain.
    pub fn apply_reverse_keyed(&self, input: &[u8]) -> Result<Vec<u8>, pgbr_io::IoError> {
        run_chain(&mut self.reverse_chain_keyed(), input)
    }
}

/// Drive `input` through `chain` (process + finish) and return the output.
///
/// Filters in this codebase buffer their whole input in `process` and emit in
/// `finish`, so the one-shot `process` + `finish` sequence is the correct
/// driver regardless of how many filters the chain holds.
fn run_chain(chain: &mut FilterChain, input: &[u8]) -> Result<Vec<u8>, pgbr_io::IoError> {
    let mut out = Vec::new();
    chain.process(input, &mut out)?;
    chain.finish(&mut out)?;
    Ok(out)
}

/// `backup.info` key recording the compression codec of the backup's files.
#[must_use]
pub const fn metadata_compress_type_key() -> &'static str {
    "backup-info-compress-type"
}

/// `backup.info` key recording whether the backup's files are encrypted.
#[must_use]
pub const fn metadata_encrypted_key() -> &'static str {
    "backup-info-encrypted"
}

/// Fetch a `StringId` option (no group index) as `&str`.
fn string_id_opt<'a>(config: &'a LoadedConfig, name: &str) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::StringId(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Fetch a `String` option (no group index) as `&str`.
fn string_opt<'a>(config: &'a LoadedConfig, name: &str) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Fetch an `Integer` option (no group index).
fn integer_opt(config: &LoadedConfig, name: &str) -> Option<i64> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Integer(value)) => Some(*value),
        _ => None,
    }
}

/// Fetch a `Boolean` option (no group index).
fn boolean_opt(config: &LoadedConfig, name: &str) -> Option<bool> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Boolean(value)) => Some(*value),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};

    use super::*;

    /// Build a `LoadedConfig` whose options map holds the supplied entries.
    fn cfg(options: Vec<((&str, Option<u32>), OptionValue)>) -> LoadedConfig {
        let mut map: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        for ((name, idx), value) in options {
            map.insert((name.to_owned(), idx), value);
        }
        LoadedConfig {
            command: "backup".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options: map,
            params: Vec::new(),
        }
    }

    #[test]
    fn pipeline_none_is_identity() {
        // No compress/cipher options at all.
        let transform = RepoTransform::from_options(&cfg(Vec::new()));
        assert_eq!(transform.compress_type, CompressType::None);
        assert!(transform.cipher_pass.is_none());
        assert!(!transform.is_encrypted());
        assert_eq!(transform.repo_suffix(), "");
        assert_eq!(transform, RepoTransform::identity());

        // Forward then reverse leaves the bytes untouched.
        let input = b"raw bytes, no transform applied";
        let repo = transform.apply_forward(input).unwrap();
        assert_eq!(repo, input, "identity forward chain must be a pass-through");
        let recovered = transform.apply_reverse(&repo).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn pipeline_gz_round_trips() {
        let transform = RepoTransform::from_options(&cfg(vec![(("compress-type", None), OptionValue::StringId("gz".to_owned()))]));
        assert_eq!(transform.compress_type, CompressType::Gz);
        assert_eq!(transform.repo_suffix(), ".gz");
        assert_eq!(transform.compress_level, 6, "gz default level");
        assert!(transform.cipher_pass.is_none());

        let input = b"the quick brown fox jumps over the lazy dog, repeated repeated repeated";
        let repo = transform.apply_forward(input).unwrap();
        assert_ne!(repo, input, "gz forward chain must transform the bytes");
        let recovered = transform.apply_reverse(&repo).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn pipeline_gz_plus_cipher_round_trips() {
        let transform = RepoTransform::from_options(&cfg(vec![
            (("compress-type", None), OptionValue::StringId("gz".to_owned())),
            (("cipher-type", None), OptionValue::StringId("aes-256-cbc".to_owned())),
            (("cipher-pass", None), OptionValue::String("s3cr3t".to_owned())),
        ]));
        assert_eq!(transform.compress_type, CompressType::Gz);
        assert!(transform.is_encrypted());
        assert_eq!(transform.cipher_pass.as_deref(), Some("s3cr3t"));
        // Encryption does not change the suffix.
        assert_eq!(transform.repo_suffix(), ".gz");

        let input = b"compress then encrypt; decrypt then decompress must recover this";
        let repo = transform.apply_forward(input).unwrap();
        assert_ne!(repo, input, "compress+encrypt must transform the bytes");
        let recovered = transform.apply_reverse(&repo).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn pipeline_zst_round_trips() {
        let transform = RepoTransform::from_options(&cfg(vec![(("compress-type", None), OptionValue::StringId("zst".to_owned()))]));
        assert_eq!(transform.compress_type, CompressType::Zst);
        assert_eq!(transform.repo_suffix(), ".zst");
        assert_eq!(transform.compress_level, 3, "zst default level");

        let input = b"zstandard payload payload payload payload payload payload payload";
        let repo = transform.apply_forward(input).unwrap();
        let recovered = transform.apply_reverse(&repo).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn compress_level_override_is_honoured() {
        let transform = RepoTransform::from_options(&cfg(vec![
            (("compress-type", None), OptionValue::StringId("gz".to_owned())),
            (("compress-level", None), OptionValue::Integer(1)),
        ]));
        assert_eq!(transform.compress_level, 1, "explicit compress-level wins over default");
    }

    #[test]
    fn legacy_compress_boolean_selects_gz() {
        // No compress-type, but compress=true -> gz.
        let transform = RepoTransform::from_options(&cfg(vec![(("compress", None), OptionValue::Boolean(true))]));
        assert_eq!(transform.compress_type, CompressType::Gz);

        // compress=false -> none.
        let off = RepoTransform::from_options(&cfg(vec![(("compress", None), OptionValue::Boolean(false))]));
        assert_eq!(off.compress_type, CompressType::None);
    }

    #[test]
    fn cipher_type_none_disables_encryption_even_with_pass() {
        let transform = RepoTransform::from_options(&cfg(vec![
            (("cipher-type", None), OptionValue::StringId("none".to_owned())),
            (("cipher-pass", None), OptionValue::String("ignored".to_owned())),
        ]));
        assert!(!transform.is_encrypted(), "cipher-type=none must not encrypt");
    }

    #[test]
    fn from_metadata_prefers_recorded_compress_type() {
        // Backup was written with zst+cipher; restore command line says gz only.
        let entry = serde_json::json!({
            metadata_compress_type_key(): "zst",
            metadata_encrypted_key(): true,
        });
        let restore_cfg = cfg(vec![
            (("compress-type", None), OptionValue::StringId("gz".to_owned())),
            (("cipher-pass", None), OptionValue::String("pw".to_owned())),
        ]);
        let transform = RepoTransform::from_metadata(&entry, &restore_cfg);
        assert_eq!(
            transform.compress_type,
            CompressType::Zst,
            "recorded compress-type must win over the restore CLI"
        );
        // The lossy constructor never sources the cipher key from options
        // (the raw user passphrase is the wrong key level). Callers inject the
        // resolved sub-key via `with_key` (restore) instead.
        assert!(
            transform.cipher_pass.is_none(),
            "from_metadata must not seed the key from the raw passphrase"
        );
    }

    #[test]
    fn from_metadata_absent_falls_back_to_options() {
        // No transform recorded in backup.info -> use the resolved options.
        let entry = serde_json::json!({});
        let opts = cfg(vec![(("compress-type", None), OptionValue::StringId("gz".to_owned()))]);
        let transform = RepoTransform::from_metadata(&entry, &opts);
        assert_eq!(transform.compress_type, CompressType::Gz);
        assert!(!transform.is_encrypted());
    }

    #[test]
    fn from_metadata_checked_uses_recorded_compress_type_and_sub_key() {
        // Backup recorded zst + encrypted; the resolved sub-key drives the
        // decrypt filter (not the raw restore-CLI passphrase).
        let entry = serde_json::json!({
            metadata_compress_type_key(): "zst",
            metadata_encrypted_key(): true,
        });
        let restore_cfg = cfg(vec![(("cipher-pass", None), OptionValue::String("user-pass".to_owned()))]);
        let transform = RepoTransform::from_metadata_checked(&entry, &restore_cfg, Some("theRepoSubKey==")).unwrap();
        assert_eq!(transform.compress_type, CompressType::Zst);
        assert!(transform.is_encrypted());
        assert_eq!(
            transform.cipher_pass.as_deref(),
            Some("theRepoSubKey=="),
            "checked constructor keys off the resolved sub-key, not the passphrase"
        );
    }

    #[test]
    fn from_metadata_checked_errors_when_encrypted_and_no_sub_key() {
        // Encrypted backup but no resolvable key -> hard error, never a
        // decrypt-less chain that would restore ciphertext verbatim.
        let entry = serde_json::json!({
            metadata_encrypted_key(): true,
        });
        let err = RepoTransform::from_metadata_checked(&entry, &cfg(Vec::new()), None).unwrap_err();
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "repo-cipher-pass"),
            other => panic!("expected MissingOption(repo-cipher-pass), got {other:?}"),
        }
    }

    #[test]
    fn from_metadata_checked_errors_on_unknown_compress_type() {
        // A codec this build cannot decode must abort the restore, not degrade
        // to a raw copy of what is really compressed data.
        let entry = serde_json::json!({
            metadata_compress_type_key(): "xz",
        });
        let err = RepoTransform::from_metadata_checked(&entry, &cfg(Vec::new()), None).unwrap_err();
        match err {
            CommandError::Other(msg) => assert!(msg.contains("xz"), "message was {msg:?}"),
            other => panic!("expected Other(unknown compress-type), got {other:?}"),
        }
    }

    #[test]
    fn from_metadata_checked_unencrypted_is_identity_when_no_metadata() {
        // Unencrypted, nothing recorded -> plain decompress/identity, no key.
        let entry = serde_json::json!({});
        let transform = RepoTransform::from_metadata_checked(&entry, &cfg(Vec::new()), None).unwrap();
        assert_eq!(transform.compress_type, CompressType::None);
        assert!(!transform.is_encrypted());
    }

    #[test]
    fn str_id_round_trips_through_compress_type() {
        for id in ["none", "gz", "bz2", "lz4", "zst"] {
            assert_eq!(CompressType::from_str_id(id).as_str_id(), id);
            // The strict parser accepts every known codec too.
            assert_eq!(CompressType::try_from_str_id(id).unwrap().as_str_id(), id);
        }
        // Unrecognised degrades to none on the lossy path...
        assert_eq!(CompressType::from_str_id("xz"), CompressType::None);
        // ...but is a hard error on the strict path.
        assert!(CompressType::try_from_str_id("xz").is_err());
    }

    #[test]
    fn keyed_chain_round_trips_with_sha1() {
        let transform = RepoTransform::with_key(CompressType::Gz, 6, Some("aRepoSubKey==".to_owned()));
        assert!(transform.is_encrypted());
        assert_eq!(transform.repo_suffix(), ".gz");

        let input = b"compress with gz, then encrypt under the resolved sub-key (SHA-1 KDF)";
        let repo = transform.apply_forward_keyed(input).unwrap();
        assert_ne!(repo, input);
        let recovered = transform.apply_reverse_keyed(&repo).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn keyed_and_legacy_chains_differ_in_bytes() {
        // The same sub-key under SHA-1 (keyed) vs MD5 (legacy) must produce
        // ciphertext that does NOT cross-decrypt — they use different KDFs.
        let transform = RepoTransform::with_key(CompressType::None, 0, Some("k".to_owned()));
        let keyed = transform.apply_forward_keyed(b"payload payload payload").unwrap();
        // Reversing the keyed bytes with the legacy (MD5) chain must fail.
        assert!(transform.apply_reverse(&keyed).is_err(), "MD5 must not decrypt SHA-1 bytes");
        // But the keyed reverse recovers it.
        assert_eq!(transform.apply_reverse_keyed(&keyed).unwrap(), b"payload payload payload");
    }

    #[test]
    fn with_key_none_disables_encryption() {
        let transform = RepoTransform::with_key(CompressType::None, 0, None);
        assert!(!transform.is_encrypted());
        let input = b"no key -> identity";
        assert_eq!(transform.apply_forward_keyed(input).unwrap(), input);
    }

    #[test]
    fn from_options_with_key_takes_compression_from_options() {
        let cfg = cfg(vec![(("compress-type", None), OptionValue::StringId("zst".to_owned()))]);
        let transform = RepoTransform::from_options_with_key(&cfg, Some("subkey".to_owned()));
        assert_eq!(transform.compress_type, CompressType::Zst);
        assert_eq!(transform.compress_level, 3, "zst default level from options");
        assert_eq!(transform.cipher_pass.as_deref(), Some("subkey"));

        let input = b"zstandard then sha1-keyed encryption, reversed cleanly cleanly cleanly";
        let repo = transform.apply_forward_keyed(input).unwrap();
        let recovered = transform.apply_reverse_keyed(&repo).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn bz2_and_lz4_round_trip_via_pipeline() {
        for (id, ct) in [("bz2", CompressType::Bz2), ("lz4", CompressType::Lz4)] {
            let transform =
                RepoTransform::from_options(&cfg(vec![(("compress-type", None), OptionValue::StringId(id.to_owned()))]));
            assert_eq!(transform.compress_type, ct);
            let input = b"bzip2 and lz4 payloads round trip too, with some repetition repetition";
            let repo = transform.apply_forward(input).unwrap();
            assert_ne!(repo, input);
            let recovered = transform.apply_reverse(&repo).unwrap();
            assert_eq!(recovered, input, "{id} round trip");
        }
    }
}
