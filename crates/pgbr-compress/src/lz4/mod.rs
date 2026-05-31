//! liblz4 glue: error-code classification (Phase 17) and the streaming LZ4-frame
//! compressor (Phase 18).
//!
//! The classify helpers live in [`error`]; the compressor lives in [`compress`]. Error
//! helpers are re-exported at the module root so the FFI bridge can write
//! `pgbr_compress::lz4::classify(...)` directly.

pub mod compress;
pub mod decompress;
pub mod error;

pub use error::{Classification, classify};
