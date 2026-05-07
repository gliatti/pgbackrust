//! `help` command.
//!
//! C reference: `src/command/help/help.c`, which renders text from the
//! generated `help.auto.c.inc` (compiled from `src/build/help/help.xml`).
//! The Rust port reads the same XML source through
//! [`pgbr_build::parse_help`] at runtime and writes a minimal listing or
//! summary to stdout.

use std::fs;
use std::path::PathBuf;

use crate::CommandError;

/// Where the on-disk `help.xml` lives, relative to the repository root.
const HELP_XML_RELATIVE: &str = "src/build/help/help.xml";

/// Resolve the path to `help.xml`. The C build embeds the file at compile
/// time; until `pgbr-build` does the same, fall back to reading it from the
/// working directory.
fn help_xml_path() -> PathBuf {
    PathBuf::from(HELP_XML_RELATIVE)
}

fn load_help() -> Result<pgbr_build::Help, CommandError> {
    let path = help_xml_path();
    let xml = fs::read_to_string(&path).map_err(|e| CommandError::Other(format!("cannot read {}: {e}", path.display())))?;
    pgbr_build::parse_help(&xml).map_err(|e| CommandError::Other(format!("cannot parse {}: {e}", path.display())))
}

/// Print either the full command list (no params) or a one-command summary
/// (`pgbackrest help <command>`).
///
/// # Errors
///
/// Returns [`CommandError::Other`] if the help XML cannot be read or parsed.
// CLI command writes to stdout by design.
#[allow(clippy::print_stdout)]
pub fn help(config: &pgbr_config::LoadedConfig) -> Result<(), CommandError> {
    let help = load_help()?;

    if let Some(target) = config.params.first() {
        let cmd = help
            .commands
            .iter()
            .find(|c| c.id == *target || c.name.eq_ignore_ascii_case(target));
        match cmd {
            Some(cmd) => {
                println!("{}: {}", cmd.id, cmd.summary);
                if let Some(text) = &cmd.text {
                    println!("\n{text}");
                }
            }
            None => {
                return Err(CommandError::Other(format!("no help available for `{target}`")));
            }
        }
    } else {
        println!("Available commands:");
        for cmd in &help.commands {
            println!("  {:<16} {}", cmd.id, cmd.summary);
        }
    }
    Ok(())
}
