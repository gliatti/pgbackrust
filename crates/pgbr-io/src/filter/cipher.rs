//! AES-256-CBC cipher filter, OpenSSL-compatible `Salted__` framing.
//!
//! Wire format (matches `openssl enc -aes-256-cbc -salt`, and the on-disk
//! layout pgBackRest's repos use today):
//!
//! ```text
//! "Salted__"   8 bytes — OpenSSL salt magic
//! <salt>       8 bytes — random per encryption
//! <ciphertext> AES-256-CBC, PKCS#7-padded
//! ```
//!
//! Key + IV are derived from `(password, salt)` via the legacy OpenSSL KDF
//! `EVP_BytesToKey(MD5, password, salt, 1)`. That function emits
//! `MD5(D_{n-1} || password || salt)` until 48 bytes are available; the
//! first 32 are the AES-256 key and the next 16 are the IV. MD5 +
//! 1-iteration is a known-weak KDF, but the on-disk format is locked for
//! backward compatibility with existing pgBackRest repos.
//!
//! # Implementation note (buffering)
//!
//! This first slice accumulates the entire input in [`Filter::process`]
//! and performs the encrypt / decrypt one-shot inside [`Filter::finish`].
//! That keeps the streaming-state machinery — partial blocks straddling
//! `process` calls, deferred header consumption on decrypt — out of the
//! way until the chunked codepath is actually needed. The on-disk format
//! and KDF are the hard contract; chunked block-streaming is a future
//! refinement that won't change the bytes on the wire.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest as _, Md5};
use rand::RngCore;

use crate::{Filter, IoError};

type Encryptor = cbc::Encryptor<aes::Aes256>;
type Decryptor = cbc::Decryptor<aes::Aes256>;

/// `"Salted__"` magic prefix — 8 bytes, matches OpenSSL's `enc -salt`.
const SALT_MAGIC: &[u8; 8] = b"Salted__";
/// Length of the random per-encryption salt that follows the magic.
const SALT_LEN: usize = 8;
/// AES-256 key length, in bytes.
const KEY_LEN: usize = 32;
/// AES-CBC IV length, in bytes (one AES block).
const IV_LEN: usize = 16;
/// AES block size, in bytes — used to size the encrypt scratch buffer.
const BLOCK_SIZE: usize = 16;

/// Direction of the cipher filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// Encrypt plaintext into `Salted__`-framed ciphertext.
    Encrypt,
    /// Decrypt `Salted__`-framed ciphertext back to plaintext.
    Decrypt,
}

/// AES-256-CBC filter compatible with `openssl enc -aes-256-cbc -salt`.
///
/// The filter buffers its input in `process` and performs the actual
/// encrypt / decrypt in `finish`. See the module docstring for why.
pub struct Cipher {
    mode: CipherMode,
    pass: Vec<u8>,
    /// Accumulated input, encrypted or decrypted in one shot at `finish`.
    pending: Vec<u8>,
}

impl Cipher {
    /// Build an encryption filter using `password`. A fresh random salt
    /// is drawn at `finish`-time, so two `Cipher::encrypt` filters built
    /// with the same password produce different ciphertexts.
    #[must_use]
    pub fn encrypt(password: &[u8]) -> Self {
        Self {
            mode: CipherMode::Encrypt,
            pass: password.to_vec(),
            pending: Vec::new(),
        }
    }

    /// Build a decryption filter using `password`. The filter expects the
    /// stream to start with `"Salted__"` followed by 8 salt bytes; the
    /// remainder is treated as PKCS#7-padded AES-256-CBC ciphertext.
    #[must_use]
    pub fn decrypt(password: &[u8]) -> Self {
        Self {
            mode: CipherMode::Decrypt,
            pass: password.to_vec(),
            pending: Vec::new(),
        }
    }

    /// Direction of the cipher filter.
    #[must_use]
    pub const fn mode(&self) -> CipherMode {
        self.mode
    }

    /// Derive a 32-byte AES key + 16-byte IV from `(pass, salt)` using
    /// `EVP_BytesToKey(MD5, pass, salt, 1)`:
    ///
    /// ```text
    /// D_1 = MD5(pass || salt)
    /// D_n = MD5(D_{n-1} || pass || salt)   for n >= 2
    /// ```
    ///
    /// Concatenate `D_1 .. D_n` until 48 bytes are available; the first
    /// 32 are the key, the next 16 the IV. `Md5` blocks are 16 bytes, so
    /// we need exactly three rounds (`16 + 16 + 16 = 48`).
    fn derive_key_iv(pass: &[u8], salt: &[u8]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
        let mut buf: Vec<u8> = Vec::with_capacity(KEY_LEN + IV_LEN);
        let mut prev: Vec<u8> = Vec::new();
        while buf.len() < KEY_LEN + IV_LEN {
            let mut hasher = Md5::new();
            if !prev.is_empty() {
                hasher.update(&prev);
            }
            hasher.update(pass);
            hasher.update(salt);
            prev = hasher.finalize().to_vec();
            buf.extend_from_slice(&prev);
        }
        let mut key = [0u8; KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        key.copy_from_slice(&buf[..KEY_LEN]);
        iv.copy_from_slice(&buf[KEY_LEN..KEY_LEN + IV_LEN]);
        (key, iv)
    }
}

impl Filter for Cipher {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        // Accumulate input verbatim — actual encrypt/decrypt happens in finish.
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        match self.mode {
            CipherMode::Encrypt => {
                let mut salt = [0u8; SALT_LEN];
                rand::thread_rng().fill_bytes(&mut salt);
                let (key, iv) = Self::derive_key_iv(&self.pass, &salt);

                out.extend_from_slice(SALT_MAGIC);
                out.extend_from_slice(&salt);

                // PKCS#7 always emits at least one extra block when the input
                // length is already a multiple of the block size, so the scratch
                // buffer is `len + BLOCK_SIZE` rounded down to a block boundary.
                let msg_len = self.pending.len();
                let mut scratch = vec![0u8; msg_len + BLOCK_SIZE];
                scratch[..msg_len].copy_from_slice(&self.pending);
                let encryptor = Encryptor::new(&key.into(), &iv.into());
                let ciphertext = encryptor
                    .encrypt_padded_mut::<Pkcs7>(&mut scratch, msg_len)
                    .map_err(|e| IoError::Backend(format!("cipher: encryption failed: {e}")))?;
                out.extend_from_slice(ciphertext);
            }
            CipherMode::Decrypt => {
                if self.pending.len() < SALT_MAGIC.len() + SALT_LEN {
                    return Err(IoError::Backend("cipher: input too short for header".to_owned()));
                }
                if &self.pending[..SALT_MAGIC.len()] != SALT_MAGIC {
                    return Err(IoError::Backend("cipher: missing Salted__ magic".to_owned()));
                }
                // Split header from body, then own the bytes so the decryptor
                // can mutate in place without aliasing `self.pending`.
                let salt: [u8; SALT_LEN] = self.pending[SALT_MAGIC.len()..SALT_MAGIC.len() + SALT_LEN]
                    .try_into()
                    .map_err(|_| IoError::Backend("cipher: salt slice".to_owned()))?;
                let mut body = self.pending[SALT_MAGIC.len() + SALT_LEN..].to_vec();

                let (key, iv) = Self::derive_key_iv(&self.pass, &salt);

                let decryptor = Decryptor::new(&key.into(), &iv.into());
                let plaintext = decryptor
                    .decrypt_padded_mut::<Pkcs7>(&mut body)
                    .map_err(|e| IoError::Backend(format!("cipher: decryption failed: {e}")))?;
                out.extend_from_slice(plaintext);
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "cipher"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// End-to-end helper: feed `plaintext` through an encrypt filter, then
    /// pipe the result through a decrypt filter, and return the recovered
    /// plaintext.
    fn roundtrip(plaintext: &[u8], password: &[u8]) -> Vec<u8> {
        let mut enc = Cipher::encrypt(password);
        let mut ciphertext = Vec::new();
        Filter::process(&mut enc, plaintext, &mut ciphertext).unwrap();
        Filter::finish(&mut enc, &mut ciphertext).unwrap();

        let mut dec = Cipher::decrypt(password);
        let mut recovered = Vec::new();
        Filter::process(&mut dec, &ciphertext, &mut recovered).unwrap();
        Filter::finish(&mut dec, &mut recovered).unwrap();
        recovered
    }

    #[test]
    fn round_trip_short_message() {
        let plaintext = b"hello world";
        let recovered = roundtrip(plaintext, b"hunter2");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_long_message() {
        // 100 KB of pseudo-random-ish bytes (a deterministic pattern keeps
        // the test reproducible without pulling in an RNG seed).
        let plaintext: Vec<u8> = (0..100_000).map(|i| (i * 31 ^ 0xa5) as u8).collect();
        let recovered = roundtrip(&plaintext, b"correct horse battery staple");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_password_fails() {
        let mut enc = Cipher::encrypt(b"hunter2");
        let mut ciphertext = Vec::new();
        Filter::process(&mut enc, b"top secret", &mut ciphertext).unwrap();
        Filter::finish(&mut enc, &mut ciphertext).unwrap();

        let mut dec = Cipher::decrypt(b"wrong");
        let mut recovered = Vec::new();
        Filter::process(&mut dec, &ciphertext, &mut recovered).unwrap();
        let err = Filter::finish(&mut dec, &mut recovered).unwrap_err();
        match err {
            IoError::Backend(msg) => assert!(msg.contains("decryption failed"), "expected decryption failure, got: {msg}"),
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_truncated_header_errors() {
        let mut dec = Cipher::decrypt(b"pw");
        let mut out = Vec::new();
        Filter::process(&mut dec, b"Salt", &mut out).unwrap();
        let err = Filter::finish(&mut dec, &mut out).unwrap_err();
        match err {
            IoError::Backend(msg) => assert!(msg.contains("input too short"), "expected truncated-header error, got: {msg}"),
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_missing_salted_magic_errors() {
        let mut dec = Cipher::decrypt(b"pw");
        let mut out = Vec::new();
        // 16 bytes that don't start with "Salted__".
        Filter::process(&mut dec, b"NotSalted_xxxxxx", &mut out).unwrap();
        let err = Filter::finish(&mut dec, &mut out).unwrap_err();
        match err {
            IoError::Backend(msg) => assert!(msg.contains("Salted__ magic"), "expected missing-magic error, got: {msg}"),
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    /// Hand-computed `EVP_BytesToKey(MD5, "password", 0x0123456789abcdef, 1)`
    /// reference vector. Locks the KDF behavior so silent drift from the C
    /// side / OpenSSL CLI is caught at test time.
    ///
    /// Reproduce on a Unix box with:
    ///
    /// ```sh
    /// echo -n "" | openssl enc -aes-256-cbc -k password \
    ///     -S 0123456789abcdef -nopad -P
    /// ```
    ///
    /// Or via Python:
    ///
    /// ```py
    /// import hashlib
    /// pw = b"password"; salt = bytes.fromhex("0123456789abcdef")
    /// d1 = hashlib.md5(pw + salt).digest()
    /// d2 = hashlib.md5(d1 + pw + salt).digest()
    /// d3 = hashlib.md5(d2 + pw + salt).digest()
    /// key = (d1 + d2).hex()
    /// iv  = d3.hex()
    /// ```
    #[test]
    fn kdf_matches_openssl_reference() {
        let salt: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let (key, iv) = Cipher::derive_key_iv(b"password", &salt);

        let expected_key = [
            0x45, 0xcd, 0x1c, 0x2d, 0x6c, 0xd6, 0xfa, 0x6d, 0xb6, 0xd7, 0x26, 0x83, 0xb5, 0x8e, 0xe0, 0x6c, 0x3a, 0x66, 0xb9, 0xf0,
            0x5e, 0xad, 0xaa, 0x05, 0x3b, 0x67, 0x5d, 0x62, 0x20, 0x3b, 0x06, 0x08,
        ];
        let expected_iv = [
            0xeb, 0xb6, 0xc9, 0x87, 0xd4, 0x3b, 0x07, 0x64, 0xfb, 0x7d, 0x91, 0x5e, 0x2b, 0x88, 0xe2, 0x8d,
        ];
        assert_eq!(key, expected_key, "EVP_BytesToKey key drift");
        assert_eq!(iv, expected_iv, "EVP_BytesToKey iv drift");
    }

    #[test]
    fn name_is_cipher() {
        assert_eq!(Cipher::encrypt(b"x").name(), "cipher");
        assert_eq!(Cipher::decrypt(b"x").name(), "cipher");
    }

    #[test]
    fn mode_accessor() {
        assert_eq!(Cipher::encrypt(b"x").mode(), CipherMode::Encrypt);
        assert_eq!(Cipher::decrypt(b"x").mode(), CipherMode::Decrypt);
    }
}
