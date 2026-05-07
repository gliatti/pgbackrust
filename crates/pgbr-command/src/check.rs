//! `check` command stub.
//!
//! C reference: `src/command/check/check.c`. Implement once `pgbr-db`
//! exposes enough surface to issue a probe query against PG.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `check` — verify the configured repository is reachable from PG and
/// vice versa.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn check(_config: &LoadedConfig, _repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "check".to_owned(),
    })
}
