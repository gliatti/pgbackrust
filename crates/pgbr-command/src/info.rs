//! `info` command stub.
//!
//! C reference: `src/command/info/info.c`. Implement once the on-disk
//! info-file reader (`pgbr-info`) is available.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `info` — print backup history for one or more stanzas.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn info(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "info".to_owned(),
    })
}
