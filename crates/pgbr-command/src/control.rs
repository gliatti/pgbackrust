//! Control commands: `version`.
//!
//! C reference: `src/command/control/control.c`. The C source pulls the
//! version string from the Meson-generated `version.h` (`PROJECT_VERSION`).
//! The Rust port hard-codes 2.58 for now and will switch to a build-time
//! const once the workspace exposes one.

use crate::CommandError;

const VERSION: &str = "pgBackRest 2.58";

/// Print the running version to stdout.
///
/// # Errors
///
/// Currently never fails. The signature returns `Result` so the dispatcher
/// can treat every command uniformly.
// `unnecessary_wraps`: Result is required by the dispatcher signature.
// `print_stdout`: CLI command writes to stdout by design.
#[allow(clippy::print_stdout, clippy::unnecessary_wraps)]
pub fn version(_config: &pgbr_config::LoadedConfig) -> Result<(), CommandError> {
    // TODO: source from build-time const (e.g. `env!("CARGO_PKG_VERSION")` once
    // the workspace version matches the user-facing pgBackRest version, or a
    // dedicated `pgbr-build` constant).
    println!("{VERSION}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};

    use super::version;

    #[test]
    fn version_succeeds() {
        let cfg = LoadedConfig {
            command: "version".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: None,
            options: BTreeMap::new(),
            params: Vec::new(),
        };
        version(&cfg).expect("version always succeeds");
    }
}
