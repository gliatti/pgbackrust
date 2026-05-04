//! libbz2 glue: error-code classification (Phase 20).
//!
//! The classify helpers live in [`error`].

pub mod error;

pub use error::{Classification, ErrorKind, classify};
