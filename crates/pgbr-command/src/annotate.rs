//! `annotate` command stub.
//!
//! C reference: `src/command/annotate/annotate.c`. Implement after the
//! info-file writer is ported.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `annotate` — attach a key/value annotation to an existing backup.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn annotate(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "annotate".to_owned(),
    })
}
