//! Server commands: `server`, `server-ping`.
//!
//! C reference: `src/command/server/server.c` and
//! `src/command/server/ping.c`. Implement once the TLS server logic in
//! `pgbr-protocol` is ported.

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// `server` — listen for protocol connections from remote pgBackRest
/// processes.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn server(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "server".to_owned(),
    })
}

/// `server-ping` — health check against a running `server` instance.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`].
pub fn ping(_config: &LoadedConfig) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "server-ping".to_owned(),
    })
}
