//! Archive commands: `archive-get`, `archive-push`.
//!
//! C reference: `src/command/archive/get/get.c` and
//! `src/command/archive/push/push.c`. Both stubbed until the streaming
//! pieces of `pgbr-io` and `pgbr-protocol` are wired up.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `archive-get` — fetch a WAL segment from the repository.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn get(_config: &LoadedConfig, _repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "archive-get".to_owned(),
    })
}

/// `archive-push` — upload a WAL segment from PG into the repository.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn push(_config: &LoadedConfig, _repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "archive-push".to_owned(),
    })
}
