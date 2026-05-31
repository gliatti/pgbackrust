//! Built-in filter implementations.
//!
//! - [`Sha1`] / [`Sha256`] / [`Size`] are pass-through observers: they
//!   forward input verbatim while computing a side channel (digest, byte
//!   count) over the byte stream that flows through a
//!   [`crate::FilterChain`].
//! - [`Cipher`] is a transforming filter: it encrypts plaintext into
//!   `"Salted__"`-framed AES-256-CBC ciphertext, or decrypts the same
//!   format back to plaintext. The KDF digest is selectable via
//!   [`CipherDigest`] (MD5 for the `openssl enc` CLI default, SHA-1 for
//!   pgBackRest repository compatibility). See [`cipher`] for the on-disk
//!   format and KDF details.

pub mod cipher;
mod hash;
mod size;

pub use crate::filter::cipher::{Cipher, CipherDigest, CipherMode};
pub use crate::filter::hash::{Sha1, Sha256};
pub use crate::filter::size::Size;
