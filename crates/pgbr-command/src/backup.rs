//! `backup` command stub.
//!
//! C reference: `src/command/backup/backup.c`. Replace with the full port
//! once `pgbr-info`, `pgbr-protocol`, and `pgbr-db` expose enough surface
//! area to drive a backup end-to-end.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `backup` — take a full / diff / incr backup of the active stanza.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn backup(_config: &LoadedConfig, _repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "backup".to_owned(),
    })
}
