//! `expire` command stub.
//!
//! C reference: `src/command/expire/expire.c`. Implement once the
//! `pgbr-info` crate can read `backup.info` and the retention policy
//! evaluator is ported.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `expire` — apply retention policy to existing backups.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn expire(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "expire".to_owned(),
    })
}
