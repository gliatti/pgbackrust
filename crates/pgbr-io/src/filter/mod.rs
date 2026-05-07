//! Built-in filter implementations.
//!
//! - [`Sha1`] / [`Sha256`] / [`Size`] are pass-through observers: they
//!   forward input verbatim while computing a side channel (digest, byte
//!   count) over the byte stream that flows through a
//!   [`crate::FilterChain`].
//! - [`Cipher`] is a transforming filter: it encrypts plaintext into
//!   `"Salted__"`-framed AES-256-CBC ciphertext, or decrypts the same
//!   format back to plaintext. See [`cipher`] for the on-disk format and
//!   KDF details.

pub mod cipher;
mod hash;
mod size;

pub use crate::filter::cipher::{Cipher, CipherMode};
pub use crate::filter::hash::{Sha1, Sha256};
pub use crate::filter::size::Size;
