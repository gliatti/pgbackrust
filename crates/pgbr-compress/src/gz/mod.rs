//! zlib glue: error-code classification (Phase 14), streaming gzip / zlib-wrapped deflate
//! compressor (Phase 15), and matching streaming inflate decompressor (Phase 16).
//!
//! The classify helpers live in [`error`]; the compressor lives in [`compress`]; the
//! decompressor lives in [`decompress`]. Error helpers are re-exported at the module root
//! so existing callers (`pgbr_compress::gz::classify`, `pgbr_compress::gz::Classification`,
//! etc.) keep working unchanged.

pub mod compress;
pub mod decompress;
pub mod error;

pub use error::{Classification, ErrorKind, Z_OK, Z_STREAM_END, classify};
