//! libzstd glue: error-code classification (Phase 23) plus the streaming zstd
//! compressor (Phase 24).

pub mod compress;
pub mod decompress;
pub mod error;

pub use error::{Classification, classify};
