//! `restore` command stub.
//!
//! C reference: `src/command/restore/restore.c`. Replace with the full port
//! once the manifest reader and parallel job dispatcher are in place.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `restore` — restore a backup into a PG data directory.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn restore(_config: &LoadedConfig, _repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "restore".to_owned(),
    })
}
