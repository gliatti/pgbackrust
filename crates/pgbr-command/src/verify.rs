//! `verify` command stub.
//!
//! C reference: `src/command/verify/verify.c`. Implement after the
//! manifest and archive-info readers are ported.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `verify` — confirm repository integrity.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn verify(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "verify".to_owned(),
    })
}
