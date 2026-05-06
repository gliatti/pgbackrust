//! Lower a `pgbr_build::Config` into the runtime `Cfg` model.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pgbr_build::config::{CommandDef, Config};

use crate::command::CfgCommand;
use crate::types::{ConfigCommandRole, LockType};

/// Top-level runtime configuration.
///
/// Currently only carries resolved commands. Options (and `option_group`) will
/// land in subsequent revisions; the field placeholders are left out
/// deliberately rather than introduced as empty stubs that future code would
/// have to migrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    pub commands: BTreeMap<String, CfgCommand>,
}

/// Errors from lowering a typed `pgbr_build::Config` into `Cfg`.
///
/// These are validation failures: the YAML parsed successfully into the build
/// schema but contained values the runtime doesn't recognise (an unknown role,
/// an unknown lock type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// `command.<name>.command-role` contains a role that is not one of
    /// `main`, `async`, `local`, `remote`.
    UnknownRole { command: String, role: String },
    /// `command.<name>.lock-type` is not one of `archive`, `backup`,
    /// `restore`, `all`, `none`.
    UnknownLockType { command: String, lock_type: String },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRole { command, role } => {
                write!(f, "command `{command}`: unknown command-role `{role}`")
            }
            Self::UnknownLockType { command, lock_type } => {
                write!(f, "command `{command}`: unknown lock-type `{lock_type}`")
            }
        }
    }
}

impl std::error::Error for CompileError {}

/// Lower a typed `pgbr_build::Config` into the runtime [`Cfg`].
///
/// # Errors
///
/// Returns [`CompileError`] if a command declares a role or lock-type the
/// runtime does not recognise.
pub fn compile(input: &Config) -> Result<Cfg, CompileError> {
    let mut commands = BTreeMap::new();
    for (name, def) in &input.command {
        commands.insert(name.clone(), compile_command(name, def)?);
    }
    Ok(Cfg { commands })
}

fn compile_command(name: &str, def: &CommandDef) -> Result<CfgCommand, CompileError> {
    let mut roles: BTreeSet<ConfigCommandRole> = BTreeSet::new();
    // `main` is implicit per the `config.yaml` docstring on the `command:` section.
    roles.insert(ConfigCommandRole::Main);

    for raw in def.command_role.keys() {
        let role = ConfigCommandRole::parse(raw).ok_or_else(|| CompileError::UnknownRole {
            command: name.to_owned(),
            role: raw.clone(),
        })?;
        roles.insert(role);
    }

    let lock_type = match def.lock_type.as_deref() {
        None => LockType::None,
        Some(raw) => LockType::parse(raw).ok_or_else(|| CompileError::UnknownLockType {
            command: name.to_owned(),
            lock_type: raw.to_owned(),
        })?,
    };

    Ok(CfgCommand {
        name: name.to_owned(),
        roles,
        lock_type,
        lock_required: def.lock_required.unwrap_or(false),
        lock_remote_required: def.lock_remote_required.unwrap_or(false),
        // `log-file:` defaults to `true` when absent, per the docstring on
        // `command:` in config.yaml.
        log_file: def.log_file.unwrap_or(true),
        log_level_default: def.log_level_default.clone(),
        parameter_allowed: def.parameter_allowed.unwrap_or(false),
        internal: def.internal.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgbr_build::config::parse_config;

    const FIXTURE_PATH: &str = "../../src/build/config/config.yaml";

    fn load_fixture() -> Cfg {
        let yaml = std::fs::read_to_string(FIXTURE_PATH).unwrap_or_else(|err| panic!("read {FIXTURE_PATH}: {err}"));
        let parsed = parse_config(&yaml).unwrap_or_else(|err| panic!("parse: {err}"));
        compile(&parsed).unwrap_or_else(|err| panic!("compile: {err}"))
    }

    #[test]
    fn compiles_a_minimal_command() {
        let yaml = "
command:
  ping:
    log-file: false
optionGroup: {}
option: {}
";
        let parsed = parse_config(yaml).unwrap();
        let cfg = compile(&parsed).unwrap();
        let ping = &cfg.commands["ping"];
        assert_eq!(ping.name, "ping");
        assert_eq!(ping.roles.len(), 1, "main is implicit");
        assert!(ping.roles.contains(&ConfigCommandRole::Main));
        assert!(!ping.log_file);
        assert!(!ping.lock_required);
        assert_eq!(ping.lock_type, LockType::None);
    }

    #[test]
    fn explicit_roles_supplement_implicit_main() {
        let yaml = "
command:
  backup:
    command-role:
      local: {}
      remote: {}
    lock-required: true
    lock-type: backup
optionGroup: {}
option: {}
";
        let parsed = parse_config(yaml).unwrap();
        let cfg = compile(&parsed).unwrap();
        let cmd = &cfg.commands["backup"];
        assert!(cmd.roles.contains(&ConfigCommandRole::Main));
        assert!(cmd.roles.contains(&ConfigCommandRole::Local));
        assert!(cmd.roles.contains(&ConfigCommandRole::Remote));
        assert_eq!(cmd.roles.len(), 3);
        assert!(cmd.lock_required);
        assert_eq!(cmd.lock_type, LockType::Backup);
    }

    #[test]
    fn log_file_defaults_to_true_when_absent() {
        let yaml = "
command:
  hello: {}
optionGroup: {}
option: {}
";
        let parsed = parse_config(yaml).unwrap();
        let cfg = compile(&parsed).unwrap();
        assert!(cfg.commands["hello"].log_file);
    }

    #[test]
    fn unknown_role_is_rejected() {
        let yaml = "
command:
  weird:
    command-role:
      surprise: {}
optionGroup: {}
option: {}
";
        let parsed = parse_config(yaml).unwrap();
        let err = compile(&parsed).unwrap_err();
        assert!(matches!(err, CompileError::UnknownRole { command, role }
            if command == "weird" && role == "surprise"));
    }

    #[test]
    fn unknown_lock_type_is_rejected() {
        let yaml = "
command:
  weird:
    lock-type: pancake
optionGroup: {}
option: {}
";
        let parsed = parse_config(yaml).unwrap();
        let err = compile(&parsed).unwrap_err();
        assert!(matches!(err, CompileError::UnknownLockType { command, lock_type }
            if command == "weird" && lock_type == "pancake"));
    }

    // ---- repository fixture ------------------------------------------------

    #[test]
    fn fixture_compiles_without_errors() {
        let cfg = load_fixture();
        assert!(cfg.commands.len() >= 15, "≥15 commands expected, got {}", cfg.commands.len());
        // Spot-check a representative set.
        for name in ["backup", "restore", "archive-push", "archive-get", "info", "expire"] {
            assert!(cfg.commands.contains_key(name), "missing command {name} in compiled fixture");
        }
    }

    #[test]
    fn fixture_backup_resolves_to_expected_shape() {
        let cfg = load_fixture();
        let backup = &cfg.commands["backup"];
        assert!(backup.has_role(ConfigCommandRole::Main));
        assert!(backup.has_role(ConfigCommandRole::Local));
        assert!(backup.has_role(ConfigCommandRole::Remote));
        assert!(backup.lock_required);
        assert!(backup.lock_remote_required);
        assert_eq!(backup.lock_type, LockType::Backup);
    }

    #[test]
    fn fixture_archive_get_has_async_role_and_no_log_file() {
        let cfg = load_fixture();
        let cmd = &cfg.commands["archive-get"];
        assert!(cmd.has_role(ConfigCommandRole::Async));
        assert!(cmd.has_role(ConfigCommandRole::Local));
        assert!(cmd.has_role(ConfigCommandRole::Remote));
        assert!(!cmd.log_file);
        assert!(cmd.parameter_allowed);
    }

    #[test]
    fn fixture_help_command_log_level_default_is_debug() {
        let cfg = load_fixture();
        let help = &cfg.commands["help"];
        assert_eq!(help.log_level_default.as_deref(), Some("DEBUG"));
        assert!(help.parameter_allowed);
        assert!(!help.log_file);
    }
}
