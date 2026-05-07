//! `manifest` command stub.
//!
//! C reference: `src/command/manifest/manifest.c`. Implement once the
//! manifest reader in `pgbr-info` is in place.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `manifest` — render the backup manifest in a human-readable form.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn manifest(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "manifest".to_owned(),
    })
}
