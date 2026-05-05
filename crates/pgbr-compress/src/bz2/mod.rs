//! libbz2 glue: error-code classification (Phase 20) plus the streaming bzip2
//! compressor (Phase 21).
//!
//! Classify helpers live in [`error`]; the compressor lives in [`compress`].

pub mod compress;
pub mod decompress;
pub mod error;

pub use error::{Classification, ErrorKind, classify};
