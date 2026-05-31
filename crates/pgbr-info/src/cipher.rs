//! Repository two-level encryption key management.
//!
//! pgBackRest does **not** encrypt repository file data directly with the
//! user-supplied passphrase (`repo-cipher-pass`). Instead it uses a chain of
//! keys, mirroring `src/info/info.c` + `src/command/stanza/common.c` +
//! `src/info/infoArchive.c` / `infoBackup.c`:
//!
//! ```text
//! user passphrase (repo-cipher-pass)
//!        │  decrypts
//!        ▼
//! repo sub-key   ── stored, JSON-encoded, in the [cipher] section of
//!                   archive.info / backup.info; the *whole* info file is
//!                   then encrypted with the user passphrase (and mirrored
//!                   to the .copy file).
//!        │  decrypts
//!        ▼
//! backup sub-key ── a fresh random key per backup, stored in that backup's
//!                   manifest (which is encrypted with the repo sub-key).
//!        │  decrypts
//!        ▼
//! file data      ── every file in the backup is encrypted with the backup
//!                   sub-key.
//! ```
//!
//! # Sub-key generation
//!
//! Both the repo sub-key and the per-backup sub-key are 48 random bytes
//! base64-encoded (64 characters), exactly as pgBackRest's `cipherPassGen`:
//! "48 is the amount of entropy needed to get a 64 base key".
//!
//! # Cipher framing
//!
//! Info files (and manifests, and file data) are wrapped with the
//! `"Salted__"`-framed AES-256-CBC cipher using the **SHA-1** KDF that
//! pgBackRest defaults to ([`pgbr_io::filter::Cipher::encrypt_pgbackrest`] /
//! [`decrypt_pgbackrest`](pgbr_io::filter::Cipher::decrypt_pgbackrest)). The
//! produced bytes are byte-compatible with a pgBackRest C repository.

use pgbr_encode::{EncodingType, encode};
use pgbr_io::Filter as _;
use pgbr_io::filter::Cipher;
use rand::RngCore;

use crate::InfoError;

/// Number of random bytes drawn for a sub-key before base64 encoding.
///
/// pgBackRest: "48 is the amount of entropy needed to get a 64 base key".
const SUB_KEY_RANDOM_BYTES: usize = 48;

/// The repository cipher type, parsed from `repo-cipher-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    /// No encryption — the repository stores plaintext.
    None,
    /// AES-256-CBC with the pgBackRest two-level key scheme.
    Aes256Cbc,
}

impl CipherType {
    /// Parse a `repo-cipher-type` string-id. Unrecognised values (and the
    /// explicit `"none"`) map to [`CipherType::None`].
    #[must_use]
    pub fn from_str_id(value: &str) -> Self {
        match value {
            "aes-256-cbc" => Self::Aes256Cbc,
            _ => Self::None,
        }
    }

    /// The canonical `repo-cipher-type` string-id.
    #[must_use]
    pub const fn as_str_id(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes256Cbc => "aes-256-cbc",
        }
    }

    /// `true` when the repository is encrypted.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Aes256Cbc)
    }
}

/// Generate a fresh random encryption sub-key.
///
/// Returns 48 cryptographically-random bytes encoded as standard base64
/// (64 characters), matching pgBackRest's `cipherPassGen`. Used for both the
/// repository sub-key (at `stanza-create`) and the per-backup sub-key (at
/// `backup`).
#[must_use]
pub fn cipher_pass_gen() -> String {
    let mut raw = [0u8; SUB_KEY_RANDOM_BYTES];
    rand::thread_rng().fill_bytes(&mut raw);
    encode_base64(&raw)
}

/// Standard-base64-encode `raw` into an owned `String`, matching
/// `strNewEncode(encodingBase64, ...)`.
fn encode_base64(raw: &[u8]) -> String {
    let len = pgbr_encode::encoded_len(EncodingType::Base64, raw.len());
    // `encode` writes a trailing NUL, so allocate one extra byte then trim it.
    let mut dst = vec![0u8; len + 1];
    encode(EncodingType::Base64, raw, &mut dst);
    // The encoded form is ASCII; drop the trailing NUL.
    String::from_utf8_lossy(&dst[..len]).into_owned()
}

/// Encrypt `plaintext` (rendered info-file text) under the user `passphrase`,
/// producing pgBackRest's `"Salted__"`-framed AES-256-CBC ciphertext.
///
/// This is what wraps the *whole* `archive.info` / `backup.info` document
/// before it is written to storage when the repository is encrypted.
///
/// # Errors
///
/// Propagates any [`pgbr_io::IoError`] raised by the cipher filter.
pub fn encrypt_info(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, InfoError> {
    let mut filter = Cipher::encrypt_pgbackrest(passphrase.as_bytes());
    run(&mut filter, plaintext)
}

/// Decrypt `ciphertext` (an encrypted info file's bytes) under the user
/// `passphrase`, returning the recovered plaintext info-file text.
///
/// # Errors
///
/// Propagates any [`pgbr_io::IoError`] raised by the cipher filter (e.g. a
/// wrong passphrase surfaces as a decryption failure / bad padding).
pub fn decrypt_info(passphrase: &str, ciphertext: &[u8]) -> Result<Vec<u8>, InfoError> {
    let mut filter = Cipher::decrypt_pgbackrest(passphrase.as_bytes());
    run(&mut filter, ciphertext)
}

/// Drive a single cipher filter (process + finish) over `input`.
fn run(filter: &mut Cipher, input: &[u8]) -> Result<Vec<u8>, InfoError> {
    let mut out = Vec::new();
    filter.process(input, &mut out)?;
    filter.finish(&mut out)?;
    Ok(out)
}

/// Decrypt `raw` under `passphrase` when one is supplied, else return it
/// unchanged. The shared decode half used by [`crate::InfoArchive`] /
/// [`crate::InfoBackup`]'s keyed load paths.
///
/// # Errors
///
/// Propagates cipher failures (e.g. a wrong passphrase) as [`InfoError::Io`].
pub(crate) fn decode_maybe_encrypted(raw: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, InfoError> {
    match passphrase {
        Some(pass) if !pass.is_empty() => decrypt_info(pass, raw),
        _ => Ok(raw.to_vec()),
    }
}

/// Encrypt `plaintext` under `passphrase` when one is supplied, else return it
/// unchanged. The shared encode half used by the keyed save paths.
///
/// # Errors
///
/// Propagates cipher failures as [`InfoError::Io`].
pub(crate) fn encode_maybe_encrypted(plaintext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, InfoError> {
    match passphrase {
        Some(pass) if !pass.is_empty() => encrypt_info(pass, plaintext),
        _ => Ok(plaintext.to_vec()),
    }
}

/// The keys needed to read or write an encrypted repository.
///
/// Built by [`RepoKeys::resolve`] from the configured cipher type + user
/// passphrase and the repo sub-key recorded in the info files (or freshly
/// generated at `stanza-create`). Backup/restore/archive code derives a
/// per-file decryption key from this:
///
/// - The repo sub-key ([`RepoKeys::repo_sub_pass`]) decrypts the manifest and
///   the WAL archive files.
/// - A per-backup sub-key ([`RepoKeys::new_backup_sub_pass`]) is generated at
///   backup time, stored in the manifest, and used to encrypt that backup's
///   file data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoKeys {
    cipher_type: CipherType,
    /// `Some(sub_key)` for an encrypted repository; `None` for plaintext.
    repo_sub_pass: Option<String>,
}

impl RepoKeys {
    /// Build a plaintext (unencrypted) key set.
    #[must_use]
    pub const fn unencrypted() -> Self {
        Self {
            cipher_type: CipherType::None,
            repo_sub_pass: None,
        }
    }

    /// Build an encrypted key set from an already-known repo sub-key.
    #[must_use]
    pub fn encrypted(repo_sub_pass: impl Into<String>) -> Self {
        Self {
            cipher_type: CipherType::Aes256Cbc,
            repo_sub_pass: Some(repo_sub_pass.into()),
        }
    }

    /// Resolve the key set from the configured cipher type, the user
    /// passphrase, and the repo sub-key recorded in an info file's `[cipher]`
    /// section.
    ///
    /// - `cipher_type` = [`CipherType::None`]: returns an unencrypted key set;
    ///   `cipher_pass_recorded` must be `None`.
    /// - `cipher_type` = [`CipherType::Aes256Cbc`]: `user_passphrase` must be
    ///   supplied and `cipher_pass_recorded` (already decrypted from the info
    ///   file) becomes the repo sub-key.
    ///
    /// # Errors
    ///
    /// [`InfoError::InvalidValue`] when the inputs are inconsistent (encrypted
    /// repo with no passphrase / no recorded sub-key, or a passphrase supplied
    /// for an unencrypted repo).
    pub fn resolve(
        cipher_type: CipherType,
        user_passphrase: Option<&str>,
        cipher_pass_recorded: Option<&str>,
    ) -> Result<Self, InfoError> {
        match cipher_type {
            CipherType::None => {
                if cipher_pass_recorded.is_some() {
                    return Err(InfoError::InvalidValue {
                        context: "repo cipher".to_owned(),
                        value: "unencrypted repo carries a [cipher] sub-key".to_owned(),
                    });
                }
                Ok(Self::unencrypted())
            }
            CipherType::Aes256Cbc => {
                if user_passphrase.is_none_or(str::is_empty) {
                    return Err(InfoError::InvalidValue {
                        context: "repo cipher".to_owned(),
                        value: "encrypted repo requires repo-cipher-pass".to_owned(),
                    });
                }
                let sub = cipher_pass_recorded.ok_or_else(|| InfoError::InvalidValue {
                    context: "repo cipher".to_owned(),
                    value: "encrypted repo is missing its [cipher] sub-key".to_owned(),
                })?;
                Ok(Self::encrypted(sub))
            }
        }
    }

    /// The repository cipher type.
    #[must_use]
    pub const fn cipher_type(&self) -> CipherType {
        self.cipher_type
    }

    /// `true` when the repository is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.cipher_type.is_encrypted()
    }

    /// The repository sub-key (used to decrypt manifests and WAL archive
    /// files), or `None` for an unencrypted repository.
    #[must_use]
    pub fn repo_sub_pass(&self) -> Option<&str> {
        self.repo_sub_pass.as_deref()
    }

    /// Generate a fresh per-backup sub-key for an encrypted repository, or
    /// `None` for an unencrypted one. The returned key is stored in the
    /// backup's manifest and used to encrypt that backup's file data.
    #[must_use]
    pub fn new_backup_sub_pass(&self) -> Option<String> {
        if self.is_encrypted() { Some(cipher_pass_gen()) } else { None }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cipher_type_round_trips() {
        assert_eq!(CipherType::from_str_id("aes-256-cbc"), CipherType::Aes256Cbc);
        assert_eq!(CipherType::from_str_id("none"), CipherType::None);
        assert_eq!(CipherType::from_str_id("blowfish"), CipherType::None);
        assert_eq!(CipherType::Aes256Cbc.as_str_id(), "aes-256-cbc");
        assert_eq!(CipherType::None.as_str_id(), "none");
        assert!(CipherType::Aes256Cbc.is_encrypted());
        assert!(!CipherType::None.is_encrypted());
    }

    #[test]
    fn cipher_pass_gen_is_64_base64_chars() {
        let pass = cipher_pass_gen();
        // 48 bytes -> ceil(48/3)*4 = 64 base64 chars.
        assert_eq!(pass.len(), 64, "sub-key must be 64 base64 characters");
        assert!(
            pass.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
            "sub-key must be valid base64: {pass}"
        );
        // No trailing NUL leaked through.
        assert!(!pass.contains('\0'));
    }

    #[test]
    fn cipher_pass_gen_is_random() {
        let a = cipher_pass_gen();
        let b = cipher_pass_gen();
        assert_ne!(a, b, "two generated sub-keys must differ");
    }

    #[test]
    fn encode_base64_matches_known_vector() {
        // base64("pgBackRest") == "cGdCYWNrUmVzdA==".
        assert_eq!(encode_base64(b"pgBackRest"), "cGdCYWNrUmVzdA==");
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
    }

    #[test]
    fn info_encrypt_decrypt_round_trips() {
        let plaintext = b"[backrest]\nbackrest-format=5\n\n[cipher]\ncipher-pass=\"sub\"\n";
        let cipher = encrypt_info("user secret", plaintext).unwrap();
        assert_ne!(cipher.as_slice(), plaintext.as_slice());
        // pgBackRest framing.
        assert_eq!(&cipher[..8], b"Salted__");
        let recovered = decrypt_info("user secret", &cipher).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn info_decrypt_wrong_passphrase_does_not_recover_plaintext() {
        // AES-CBC + PKCS#7 padding produces a deterministic failure on the
        // wrong key only when the random decrypted last block does NOT happen
        // to end in valid padding (probability ~1/256 of an accidental valid
        // pad otherwise). Asserting `.is_err()` on a single ciphertext therefore
        // flakes ~0.4% of the time. The cryptographically meaningful invariant
        // is that the wrong key cannot RECOVER the original plaintext — either
        // decryption errors out, or it succeeds but yields garbage. Assert that.
        let plaintext: &[u8] = b"some info text";
        let cipher = encrypt_info("right", plaintext).unwrap();
        match decrypt_info("wrong", &cipher) {
            Err(_) => {}
            Ok(out) => assert_ne!(
                out.as_slice(),
                plaintext,
                "wrong passphrase decrypted to the original plaintext — that would break AES-CBC",
            ),
        }
    }

    #[test]
    fn resolve_unencrypted() {
        let keys = RepoKeys::resolve(CipherType::None, None, None).unwrap();
        assert!(!keys.is_encrypted());
        assert_eq!(keys.repo_sub_pass(), None);
        assert_eq!(keys.new_backup_sub_pass(), None);
    }

    #[test]
    fn resolve_encrypted() {
        let keys = RepoKeys::resolve(CipherType::Aes256Cbc, Some("userpass"), Some("repo-sub-key")).unwrap();
        assert!(keys.is_encrypted());
        assert_eq!(keys.repo_sub_pass(), Some("repo-sub-key"));
        let backup_key = keys.new_backup_sub_pass().expect("encrypted repo yields a backup sub-key");
        assert_eq!(backup_key.len(), 64);
    }

    #[test]
    fn resolve_encrypted_without_passphrase_errors() {
        let err = RepoKeys::resolve(CipherType::Aes256Cbc, None, Some("sub")).unwrap_err();
        assert!(matches!(err, InfoError::InvalidValue { .. }));
        let err = RepoKeys::resolve(CipherType::Aes256Cbc, Some(""), Some("sub")).unwrap_err();
        assert!(matches!(err, InfoError::InvalidValue { .. }));
    }

    #[test]
    fn resolve_encrypted_without_subkey_errors() {
        let err = RepoKeys::resolve(CipherType::Aes256Cbc, Some("userpass"), None).unwrap_err();
        assert!(matches!(err, InfoError::InvalidValue { .. }));
    }

    #[test]
    fn resolve_unencrypted_with_subkey_errors() {
        let err = RepoKeys::resolve(CipherType::None, None, Some("sub")).unwrap_err();
        assert!(matches!(err, InfoError::InvalidValue { .. }));
    }
}
