//! `SHA-1` and `SHA-256` pass-through filters.
//!
//! Each digester forwards its input verbatim while updating an internal
//! `RustCrypto` hasher. The current digest is queryable at any time —
//! the hasher is cloned so the streaming state isn't consumed.

use std::fmt::Write as _;

use sha1::Digest as _;

use crate::{Filter, IoError};

/// `SHA-1` digester. Fed bytes via [`Filter::process`]; the running digest is
/// available via [`Sha1::digest_hex`] / [`Sha1::digest_bytes`].
#[derive(Debug, Clone, Default)]
pub struct Sha1 {
    inner: sha1::Sha1,
}

impl Sha1 {
    /// Build a fresh digester.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lower-case hex digest of all bytes processed so far.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        bytes_to_hex(&self.digest_bytes())
    }

    /// Raw 20-byte digest of all bytes processed so far.
    #[must_use]
    pub fn digest_bytes(&self) -> [u8; 20] {
        let bytes = self.inner.clone().finalize();
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        out
    }
}

impl Filter for Sha1 {
    fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError> {
        sha1::Digest::update(&mut self.inner, input);
        out.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), IoError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "sha1"
    }
}

/// `SHA-256` digester. Same shape as [`Sha1`] over the `sha2` crate.
#[derive(Debug, Clone, Default)]
pub struct Sha256 {
    inner: sha2::Sha256,
}

impl Sha256 {
    /// Build a fresh digester.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lower-case hex digest of all bytes processed so far.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        bytes_to_hex(&self.digest_bytes())
    }

    /// Raw 32-byte digest of all bytes processed so far.
    #[must_use]
    pub fn digest_bytes(&self) -> [u8; 32] {
        let bytes = sha2::Digest::finalize(self.inner.clone());
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

impl Filter for Sha256 {
    fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError> {
        sha2::Digest::update(&mut self.inner, input);
        out.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), IoError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "sha256"
    }
}

/// Render a byte slice as lower-case hex. Pre-allocates the exact capacity
/// and uses `write!` to dodge clippy's `format_collect` lint.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing into a `String` cannot fail.
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sha1_of_abc_matches_reference() {
        let mut sha = Sha1::new();
        let mut out = Vec::new();
        Filter::process(&mut sha, b"abc", &mut out).unwrap();
        Filter::finish(&mut sha, &mut out).unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(sha.digest_hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(sha.name(), "sha1");
    }

    #[test]
    fn sha1_of_empty_matches_reference() {
        let sha = Sha1::new();
        assert_eq!(sha.digest_hex(), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha1_streaming_chunks_match_one_shot() {
        let mut split = Sha1::new();
        let mut sink = Vec::new();
        Filter::process(&mut split, b"a", &mut sink).unwrap();
        Filter::process(&mut split, b"b", &mut sink).unwrap();
        Filter::process(&mut split, b"c", &mut sink).unwrap();
        Filter::finish(&mut split, &mut sink).unwrap();
        assert_eq!(sink, b"abc");
        assert_eq!(split.digest_hex(), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha1_digest_bytes_round_trip() {
        let mut sha = Sha1::new();
        let mut sink = Vec::new();
        Filter::process(&mut sha, b"abc", &mut sink).unwrap();
        let raw = sha.digest_bytes();
        assert_eq!(raw.len(), 20);
        // First two bytes of the canonical digest "a999..." are 0xa9 0x99.
        assert_eq!(raw[0], 0xa9);
        assert_eq!(raw[1], 0x99);
    }

    #[test]
    fn sha256_of_abc_matches_reference() {
        let mut sha = Sha256::new();
        let mut out = Vec::new();
        Filter::process(&mut sha, b"abc", &mut out).unwrap();
        Filter::finish(&mut sha, &mut out).unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(
            sha.digest_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha.name(), "sha256");
    }

    #[test]
    fn sha256_of_empty_matches_reference() {
        let sha = Sha256::new();
        assert_eq!(
            sha.digest_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_streaming_chunks_match_one_shot() {
        let mut split = Sha256::new();
        let mut sink = Vec::new();
        Filter::process(&mut split, b"ab", &mut sink).unwrap();
        Filter::process(&mut split, b"c", &mut sink).unwrap();
        Filter::finish(&mut split, &mut sink).unwrap();
        assert_eq!(sink, b"abc");
        assert_eq!(
            split.digest_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_digest_bytes_length() {
        let sha = Sha256::new();
        assert_eq!(sha.digest_bytes().len(), 32);
    }
}
