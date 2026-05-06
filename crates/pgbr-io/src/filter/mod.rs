//! Pass-through observability and digest filters.
//!
//! Each filter forwards its input verbatim — they exist to compute a side
//! channel (digest, byte count) over the byte stream that flows through a
//! [`crate::FilterChain`]. Inserting them never changes the stream's
//! contents.

mod hash;
mod size;

pub use crate::filter::hash::{Sha1, Sha256};
pub use crate::filter::size::Size;
