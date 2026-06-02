//! Control commands: `version`.
//!
//! C reference: `src/command/control/control.c`. The C source pulls the
//! version string from the Meson-generated `version.h` (`PROJECT_VERSION`).
//! The Rust port sources it from the cargo workspace version at compile time
//! (`env!("CARGO_PKG_VERSION")`), so the banner tracks the crate version.
//!
//! Note: this *product* version is distinct from the on-disk format version
//! (`backrest-version`, currently `2.58`) stamped into info/manifest files,
//! which is deliberately pinned to the pgBackRest format this port targets so
//! existing repositories stay compatible.
//!
//! This module also hosts the crate-internal [`log_info`] / [`log_warn`]
//! helpers (see below): the thin wrappers that reroute *human-facing*
//! progress / warning lines from `println!` / `eprintln!` to the migrated
//! `pgbr_core::log` formatter. Machine-readable command output (the version
//! string here, the info / repo-ls / manifest / verify reports, `repo-get`
//! bytes, the server's own log file) stays on stdout — only status chatter is
//! rerouted, exactly as the C side splits `LOG_INFO` / `LOG_WARN` from the
//! command result it prints with `printf`.

use crate::CommandError;

const VERSION: &str = concat!("pgBackRust ", env!("CARGO_PKG_VERSION"));

/// Emit a human-facing progress line at `INFO` through the `pgbr_core::log`
/// formatter.
///
/// This is the Rust analogue of the C `LOG_INFO` macro: the message is routed
/// to whichever sinks the logger has open (console at the configured
/// `log-level-console`, plus the log file at `log-level-file`) instead of being
/// hard-written to stdout. Keeping status lines off stdout leaves the stream
/// free for the machine-readable command result. A formatting / write failure
/// from the logger is intentionally swallowed: progress chatter must never turn
/// a successful command into an error (the C `logInternal` path likewise only
/// throws on a real `write(2)` failure, which would already have aborted the
/// command's own output).
///
/// `process_id` is passed as `u32::MAX` so the formatter uses the process-global
/// id set by `logInit`; `code` is `0` (no error code segment).
pub(crate) fn log_info(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_INFO,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        "command.c",
        "command",
        0,
        message,
    );
}

/// Emit a human-facing warning line at `WARN` through the `pgbr_core::log`
/// formatter — the Rust analogue of the C `LOG_WARN` macro. See [`log_info`] for
/// the routing / error-swallowing rationale.
pub(crate) fn log_warn(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_WARN,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        "command.c",
        "command",
        0,
        message,
    );
}

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
