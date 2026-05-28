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
//! # pgBackRest semantics modelled here
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
use pgbr_io::filter::Cipher;

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

    /// A sane default compression level for this codec, matching pgBackRest's
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

    /// Reconstruct the transform from the values recorded in a backup's
    /// `backup.info` `[backup:current]` entry (see
    /// [`metadata_compress_type_key`] / [`metadata_encrypted_key`]), falling
    /// back to the resolved options for anything the metadata does not pin.
    ///
    /// This is what restore uses: a backup is reversed using the transform it
    /// was *written* with, not whatever compress/cipher options happen to be
    /// on the restore command line. The cipher password, however, is never
    /// stored in `backup.info`, so the password always comes from the options.
    #[must_use]
    pub fn from_metadata(entry: &serde_json::Value, config: &LoadedConfig) -> Self {
        let from_opts = Self::from_options(config);

        let compress_type = entry
            .get(metadata_compress_type_key())
            .and_then(serde_json::Value::as_str)
            .map_or(from_opts.compress_type, CompressType::from_str_id);

        // Whether the repo bytes are encrypted is recorded; the password is
        // not, so it is sourced from the options. If the backup says it is
        // encrypted but no password is available, leave `cipher_pass` empty —
        // the decrypt filter will then surface a clear error downstream.
        let encrypted = entry
            .get(metadata_encrypted_key())
            .and_then(serde_json::Value::as_bool)
            .unwrap_or_else(|| from_opts.cipher_pass.is_some());
        let cipher_pass = if encrypted {
            from_opts
                .cipher_pass
                .clone()
                .or_else(|| string_opt(config, "cipher-pass").map(str::to_owned))
        } else {
            None
        };

        Self {
            compress_type,
            compress_level: from_opts.compress_level,
            cipher_pass,
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

    /// Build the forward (backup-side) filter chain: compress **then** encrypt.
    ///
    /// An empty chain (no compression, no cipher) passes bytes through
    /// unchanged, preserving the raw-copy behaviour.
    #[must_use]
    pub fn forward_chain(&self) -> FilterChain {
        let mut chain = FilterChain::new();
        match self.compress_type {
            CompressType::None => {}
            CompressType::Gz => chain.push(GzCompress::new(self.compress_level, false)),
            CompressType::Bz2 => chain.push(Bz2Compress::new(self.compress_level)),
            CompressType::Lz4 => chain.push(Lz4Compress::new(self.compress_level, false)),
            CompressType::Zst => chain.push(ZstCompress::new(self.compress_level)),
        }
        if let Some(pass) = &self.cipher_pass {
            chain.push(Cipher::encrypt(pass.as_bytes()));
        }
        chain
    }

    /// Build the reverse (restore-side) filter chain: decrypt **then**
    /// decompress — the exact inverse of [`RepoTransform::forward_chain`].
    #[must_use]
    pub fn reverse_chain(&self) -> FilterChain {
        let mut chain = FilterChain::new();
        if let Some(pass) = &self.cipher_pass {
            chain.push(Cipher::decrypt(pass.as_bytes()));
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
    /// returning the repo-side bytes.
    ///
    /// # Errors
    ///
    /// Propagates any [`pgbr_io::IoError`] raised by a filter in the chain.
    pub fn apply_forward(&self, input: &[u8]) -> Result<Vec<u8>, pgbr_io::IoError> {
        run_chain(&mut self.forward_chain(), input)
    }

    /// Run `input` (repo-side bytes) through this transform's
    /// [`reverse_chain`](Self::reverse_chain), returning the recovered plaintext.
    ///
    /// # Errors
    ///
    /// Propagates any [`pgbr_io::IoError`] raised by a filter in the chain.
    pub fn apply_reverse(&self, input: &[u8]) -> Result<Vec<u8>, pgbr_io::IoError> {
        run_chain(&mut self.reverse_chain(), input)
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
        assert!(transform.is_encrypted());
        assert_eq!(transform.cipher_pass.as_deref(), Some("pw"), "password sourced from options");
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
    fn str_id_round_trips_through_compress_type() {
        for id in ["none", "gz", "bz2", "lz4", "zst"] {
            assert_eq!(CompressType::from_str_id(id).as_str_id(), id);
        }
        // Unrecognised degrades to none.
        assert_eq!(CompressType::from_str_id("xz"), CompressType::None);
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
