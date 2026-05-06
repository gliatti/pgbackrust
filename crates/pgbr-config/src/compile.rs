//! Lower a `pgbr_build::Config` into the runtime `Cfg` model.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use pgbr_build::config::{CommandDef, Config, Depend, OptionCommandEntry, OptionCommandSpec, OptionDef};

use crate::command::CfgCommand;
use crate::option::{CfgOption, ResolvedCommandUsage, ResolvedDepend};
use crate::types::{ConfigCommandRole, DefaultType, LockType, OptionGroup, OptionSection, OptionType};

/// Top-level runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    /// All commands declared in `config.yaml`, keyed by command name.
    pub commands: BTreeMap<String, CfgCommand>,
    /// All options declared in `config.yaml`, keyed by option name. Each
    /// option has had inheritance applied and its `command:` field
    /// expanded into a per-command usage map.
    pub options: BTreeMap<String, CfgOption>,
    /// Option groups (`pg`, `repo`) declared at the top level.
    pub option_groups: BTreeSet<OptionGroup>,
}

/// Errors from lowering a typed `pgbr_build::Config` into [`Cfg`].
///
/// These are validation failures: the YAML parsed successfully into the build
/// schema but contained a value the runtime can't make sense of (an unknown
/// role, a cyclic `inherit:` chain, a `+inherit:` pointing at a missing
/// option, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// `command.<name>.command-role` contains a role that is not one of
    /// `main`, `async`, `local`, `remote`. Also raised for
    /// `option.<name>.command-role` and per-command-override `command-role`.
    UnknownRole { context: String, role: String },
    /// `command.<name>.lock-type` is not one of `archive`, `backup`,
    /// `restore`, `all`, `none`.
    UnknownLockType { command: String, lock_type: String },
    /// An option's `type:` is not one of the recognised values.
    UnknownOptionType { option: String, option_type: String },
    /// An option's `section:` is not `global` or `stanza`.
    UnknownSection { option: String, section: String },
    /// An option's `group:` is not `pg` or `repo`.
    UnknownGroup { option: String, group: String },
    /// `optionGroup:` declares a group whose name is not `pg` or `repo`.
    UnknownTopLevelOptionGroup(String),
    /// An option's `default-type:` is not `literal`, `dynamic`, or `quote`.
    UnknownDefaultType { option: String, default_type: String },
    /// An option requires a `type:` (either locally or via `inherit:`) and has
    /// neither.
    MissingOptionType { option: String },
    /// An option's `inherit:`, `command: <name>`, or `+inherit:` references
    /// an option that does not exist.
    UnknownOption { from: String, target: String },
    /// An option's `command:` map references a command that does not exist.
    UnknownCommand { option: String, command: String },
    /// A `depend:` clause did not name an option (the YAML form
    /// `depend: { list: [...] }` without `option:`).
    DependMissingOption { owner: String },
    /// `inherit:` / `command:` form a cycle through the named option.
    CyclicInheritance(String),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRole { context, role } => {
                write!(f, "{context}: unknown command-role `{role}`")
            }
            Self::UnknownLockType { command, lock_type } => {
                write!(f, "command `{command}`: unknown lock-type `{lock_type}`")
            }
            Self::UnknownOptionType { option, option_type } => {
                write!(f, "option `{option}`: unknown type `{option_type}`")
            }
            Self::UnknownSection { option, section } => {
                write!(f, "option `{option}`: unknown section `{section}`")
            }
            Self::UnknownGroup { option, group } => {
                write!(f, "option `{option}`: unknown group `{group}`")
            }
            Self::UnknownTopLevelOptionGroup(name) => {
                write!(f, "optionGroup: unknown entry `{name}`")
            }
            Self::UnknownDefaultType { option, default_type } => {
                write!(f, "option `{option}`: unknown default-type `{default_type}`")
            }
            Self::MissingOptionType { option } => {
                write!(f, "option `{option}`: `type:` must be set locally or via `inherit:`")
            }
            Self::UnknownOption { from, target } => {
                write!(f, "{from} references unknown option `{target}`")
            }
            Self::UnknownCommand { option, command } => {
                write!(f, "option `{option}`: unknown command `{command}`")
            }
            Self::DependMissingOption { owner } => {
                write!(f, "{owner}: `depend:` clause must name an option")
            }
            Self::CyclicInheritance(option) => {
                write!(f, "option `{option}`: cyclic inherit/command dependency")
            }
        }
    }
}

impl std::error::Error for CompileError {}

/// Lower a typed `pgbr_build::Config` into the runtime [`Cfg`].
///
/// # Errors
///
/// Returns [`CompileError`] if any command or option contains a value the
/// runtime cannot make sense of (unknown enum value, dangling reference,
/// cyclic inheritance).
pub fn compile(input: &Config) -> Result<Cfg, CompileError> {
    let mut commands = BTreeMap::new();
    for (name, def) in &input.command {
        commands.insert(name.clone(), compile_command(name, def)?);
    }

    let mut option_groups = BTreeSet::new();
    for raw in input.option_group.keys() {
        let group = OptionGroup::parse(raw).ok_or_else(|| CompileError::UnknownTopLevelOptionGroup(raw.clone()))?;
        option_groups.insert(group);
    }

    let options = resolve_options(input, &commands)?;

    Ok(Cfg {
        commands,
        options,
        option_groups,
    })
}

fn compile_command(name: &str, def: &CommandDef) -> Result<CfgCommand, CompileError> {
    let mut roles: BTreeSet<ConfigCommandRole> = BTreeSet::new();
    // `main` is implicit per the `config.yaml` docstring on the `command:` section.
    roles.insert(ConfigCommandRole::Main);

    for raw in def.command_role.keys() {
        let role = ConfigCommandRole::parse(raw).ok_or_else(|| CompileError::UnknownRole {
            context: format!("command `{name}`"),
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

// ---- Option resolution -----------------------------------------------------

fn resolve_options(input: &Config, commands: &BTreeMap<String, CfgCommand>) -> Result<BTreeMap<String, CfgOption>, CompileError> {
    let order = topo_sort_options(input)?;
    let mut resolved: BTreeMap<String, CfgOption> = BTreeMap::new();
    for name in order {
        let def = &input.option[&name];
        let opt = resolve_option(&name, def, commands, &resolved)?;
        resolved.insert(name, opt);
    }
    Ok(resolved)
}

/// Topologically sort options so that every option's `inherit:` parent and
/// every option referenced via `command: <name>` or `+inherit: <name>` is
/// resolved before the option itself.
fn topo_sort_options(input: &Config) -> Result<Vec<String>, CompileError> {
    let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, def) in &input.option {
        let mut d = BTreeSet::new();
        if let Some(parent) = &def.inherit {
            d.insert(parent.clone());
        }
        match &def.command {
            OptionCommandSpec::Inherit(other) => {
                d.insert(other.clone());
            }
            OptionCommandSpec::Map(map) => {
                if let Some(entry) = map.get("+inherit") {
                    for v in entry.shortcut_values() {
                        d.insert(v.to_owned());
                    }
                }
            }
        }
        deps.insert(name.clone(), d);
    }

    let mut state: BTreeMap<String, TopoVisit> = BTreeMap::new();
    let mut order: Vec<String> = Vec::with_capacity(input.option.len());

    for name in input.option.keys() {
        topo_visit(name, &deps, &mut state, &mut order, input)?;
    }
    Ok(order)
}

fn topo_visit(
    node: &str,
    deps: &BTreeMap<String, BTreeSet<String>>,
    state: &mut BTreeMap<String, TopoVisit>,
    order: &mut Vec<String>,
    input: &Config,
) -> Result<(), CompileError> {
    match state.get(node) {
        Some(TopoVisit::Done) => return Ok(()),
        Some(TopoVisit::InProgress) => {
            return Err(CompileError::CyclicInheritance(node.to_owned()));
        }
        None => {}
    }
    state.insert(node.to_owned(), TopoVisit::InProgress);
    if let Some(children) = deps.get(node) {
        for child in children {
            if !input.option.contains_key(child) {
                return Err(CompileError::UnknownOption {
                    from: format!("option `{node}`"),
                    target: child.clone(),
                });
            }
            topo_visit(child, deps, state, order, input)?;
        }
    }
    state.insert(node.to_owned(), TopoVisit::Done);
    order.push(node.to_owned());
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TopoVisit {
    InProgress,
    Done,
}

// resolve_option is a long, mostly-linear field-merge function — splitting it
// into helpers per attribute would obscure rather than clarify the logic. Keep
// it monolithic and silence the line-count lint locally.
#[allow(clippy::too_many_lines)]
fn resolve_option(
    name: &str,
    def: &OptionDef,
    commands: &BTreeMap<String, CfgCommand>,
    resolved: &BTreeMap<String, CfgOption>,
) -> Result<CfgOption, CompileError> {
    // Start with the parent's resolved option as a base, if `inherit:` is set.
    let mut opt = if let Some(parent_name) = def.inherit.as_deref() {
        let parent = resolved.get(parent_name).ok_or_else(|| CompileError::UnknownOption {
            from: format!("option `{name}`"),
            target: parent_name.to_owned(),
        })?;
        let mut p = parent.clone();
        name.clone_into(&mut p.name);
        p.inherits_from = Some(parent_name.to_owned());
        p
    } else {
        CfgOption {
            name: name.to_owned(),
            // `option_type` is required; if `inherit:` is unset, the local
            // `type:` field must be set or `MissingOptionType` is raised below.
            option_type: OptionType::String,
            section: None,
            group: None,
            default: None,
            default_type: None,
            negate: false,
            reset: false,
            sequence: false,
            internal: false,
            secure: false,
            required: false,
            bool_like: false,
            beta: false,
            allow_list: None,
            allow_range: None,
            depend: None,
            deprecate: BTreeSet::new(),
            roles: BTreeSet::new(),
            commands: BTreeMap::new(),
            inherits_from: None,
        }
    };

    let has_parent = def.inherit.is_some();

    // type: required either locally or from parent.
    if let Some(t) = def.type_.as_deref() {
        opt.option_type = OptionType::parse(t).ok_or_else(|| CompileError::UnknownOptionType {
            option: name.to_owned(),
            option_type: t.to_owned(),
        })?;
    } else if !has_parent {
        return Err(CompileError::MissingOptionType { option: name.to_owned() });
    }

    if let Some(s) = def.section.as_deref() {
        opt.section = Some(OptionSection::parse(s).ok_or_else(|| CompileError::UnknownSection {
            option: name.to_owned(),
            section: s.to_owned(),
        })?);
    }
    if let Some(g) = def.group.as_deref() {
        opt.group = Some(OptionGroup::parse(g).ok_or_else(|| CompileError::UnknownGroup {
            option: name.to_owned(),
            group: g.to_owned(),
        })?);
    }
    if let Some(d) = def.default_type.as_deref() {
        opt.default_type = Some(DefaultType::parse(d).ok_or_else(|| CompileError::UnknownDefaultType {
            option: name.to_owned(),
            default_type: d.to_owned(),
        })?);
    }

    if let Some(v) = &def.default {
        opt.default = Some(v.clone());
    }
    if let Some(v) = def.negate {
        opt.negate = v;
    }
    if let Some(v) = def.reset {
        opt.reset = v;
    }
    if let Some(v) = def.sequence {
        opt.sequence = v;
    }
    if let Some(v) = def.internal {
        opt.internal = v;
    }
    if let Some(v) = def.secure {
        opt.secure = v;
    }
    if let Some(v) = def.required {
        opt.required = v;
    }
    if let Some(v) = def.bool_like {
        opt.bool_like = v;
    }
    if let Some(v) = def.beta {
        opt.beta = v;
    }
    if let Some(v) = &def.allow_list {
        opt.allow_list = Some(v.clone());
    }
    if let Some(v) = &def.allow_range {
        opt.allow_range = Some(v.clone());
    }
    if let Some(v) = &def.depend {
        opt.depend = Some(resolve_depend(v, &format!("option `{name}`"))?);
    }
    if let Some(d) = &def.deprecate {
        opt.deprecate.extend(d.keys().cloned());
    }

    // Option-level command-role override. Locally-set replaces parent.
    if !def.command_role.is_empty() {
        let mut roles = BTreeSet::new();
        for raw in def.command_role.keys() {
            roles.insert(ConfigCommandRole::parse(raw).ok_or_else(|| CompileError::UnknownRole {
                context: format!("option `{name}`"),
                role: raw.clone(),
            })?);
        }
        opt.roles = roles;
    }

    // commands: locally-specified command:-block REPLACES parent's commands.
    // A locally-empty Map means "field absent" → inherit parent's commands.
    if option_command_locally_specified(&def.command) {
        opt.commands = resolve_commands_field(&def.command, name, commands, resolved)?;
    }

    Ok(opt)
}

fn option_command_locally_specified(spec: &OptionCommandSpec) -> bool {
    match spec {
        OptionCommandSpec::Inherit(_) => true,
        OptionCommandSpec::Map(m) => !m.is_empty(),
    }
}

fn resolve_commands_field(
    spec: &OptionCommandSpec,
    option_name: &str,
    commands: &BTreeMap<String, CfgCommand>,
    resolved: &BTreeMap<String, CfgOption>,
) -> Result<BTreeMap<String, ResolvedCommandUsage>, CompileError> {
    let mut out: BTreeMap<String, ResolvedCommandUsage> = BTreeMap::new();

    match spec {
        OptionCommandSpec::Inherit(other) => {
            // `command: <option-name>` — copy the resolved command list of the
            // referenced option, stripped of attributes (command set only).
            let other_opt = resolved.get(other).ok_or_else(|| CompileError::UnknownOption {
                from: format!("option `{option_name}`"),
                target: other.clone(),
            })?;
            for cmd_name in other_opt.commands.keys() {
                out.insert(cmd_name.clone(), ResolvedCommandUsage::default());
            }
        }
        OptionCommandSpec::Map(map) => {
            // Phase 1: include via real command names, +role:, +inherit:.
            for (key, entry) in map {
                match key.as_str() {
                    "+role" => add_role_includes(entry, commands, &mut out, option_name)?,
                    "+inherit" => add_inherit_includes(entry, resolved, &mut out, option_name)?,
                    "-command" => { /* phase 2 */ }
                    real_command => {
                        if !commands.contains_key(real_command) {
                            return Err(CompileError::UnknownCommand {
                                option: option_name.to_owned(),
                                command: real_command.to_owned(),
                            });
                        }
                        let usage = command_override_to_usage(entry, option_name, real_command)?;
                        out.insert(real_command.to_owned(), usage);
                    }
                }
            }
            // Phase 2: -command: removes from the include set.
            if let Some(entry) = map.get("-command") {
                for excluded in entry.shortcut_values() {
                    out.remove(excluded);
                }
            }
        }
    }
    Ok(out)
}

fn add_role_includes(
    entry: &OptionCommandEntry,
    commands: &BTreeMap<String, CfgCommand>,
    out: &mut BTreeMap<String, ResolvedCommandUsage>,
    option_name: &str,
) -> Result<(), CompileError> {
    for raw in entry.shortcut_values() {
        if raw == "any" {
            for cmd_name in commands.keys() {
                out.entry(cmd_name.clone()).or_default();
            }
            continue;
        }
        let role = ConfigCommandRole::parse(raw).ok_or_else(|| CompileError::UnknownRole {
            context: format!("option `{option_name}` (+role)"),
            role: raw.to_owned(),
        })?;
        for (cmd_name, cmd) in commands {
            if cmd.has_role(role) {
                out.entry(cmd_name.clone()).or_default();
            }
        }
    }
    Ok(())
}

fn add_inherit_includes(
    entry: &OptionCommandEntry,
    resolved: &BTreeMap<String, CfgOption>,
    out: &mut BTreeMap<String, ResolvedCommandUsage>,
    option_name: &str,
) -> Result<(), CompileError> {
    for opt_name in entry.shortcut_values() {
        let other = resolved.get(opt_name).ok_or_else(|| CompileError::UnknownOption {
            from: format!("option `{option_name}` (+inherit)"),
            target: opt_name.to_owned(),
        })?;
        for cmd_name in other.commands.keys() {
            // "stripped of attributes": include is a bare command name, no
            // override carries over from the inherited option.
            out.entry(cmd_name.clone()).or_default();
        }
    }
    Ok(())
}

fn command_override_to_usage(
    entry: &OptionCommandEntry,
    option_name: &str,
    command_name: &str,
) -> Result<ResolvedCommandUsage, CompileError> {
    match entry {
        OptionCommandEntry::Override(o) => {
            let depend = match &o.depend {
                Some(d) => Some(resolve_depend(
                    d,
                    &format!("option `{option_name}`, command `{command_name}`"),
                )?),
                None => None,
            };
            let roles = if let Some(map) = &o.command_role {
                let mut roles = BTreeSet::new();
                for raw in map.keys() {
                    roles.insert(ConfigCommandRole::parse(raw).ok_or_else(|| CompileError::UnknownRole {
                        context: format!("option `{option_name}`, command `{command_name}`"),
                        role: raw.clone(),
                    })?);
                }
                roles
            } else {
                BTreeSet::new()
            };
            Ok(ResolvedCommandUsage {
                default: o.default.clone(),
                required: o.required,
                internal: o.internal,
                depend,
                allow_list: o.allow_list.clone(),
                sequence: o.sequence,
                roles,
            })
        }
        // A real command-name key with a scalar/sequence value is a schema
        // oddity that doesn't appear in the canonical YAML; fall back to a
        // default (empty) usage rather than failing.
        OptionCommandEntry::Scalar(_) | OptionCommandEntry::Sequence(_) => Ok(ResolvedCommandUsage::default()),
    }
}

fn resolve_depend(d: &Depend, owner: &str) -> Result<ResolvedDepend, CompileError> {
    let option = d
        .option
        .clone()
        .ok_or_else(|| CompileError::DependMissingOption { owner: owner.to_owned() })?;
    Ok(ResolvedDepend {
        option,
        list: d.list.clone(),
        default: d.default.clone(),
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
        assert!(matches!(err, CompileError::UnknownRole { context, role }
            if context.contains("weird") && role == "surprise"));
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

    // ---- option resolution -------------------------------------------------

    #[test]
    fn option_inherits_fields_from_parent() {
        let yaml = "
command:
  backup: {}
optionGroup: {}
option:
  parent:
    type: string
    section: global
    default: hi
    command:
      backup: {}
  child:
    inherit: parent
";
        let cfg = compile(&parse_config(yaml).unwrap()).unwrap();
        let child = &cfg.options["child"];
        assert_eq!(child.option_type, OptionType::String);
        assert_eq!(child.section, Some(OptionSection::Global));
        assert_eq!(child.default.as_ref().and_then(|v| v.as_str()), Some("hi"));
        assert_eq!(child.inherits_from.as_deref(), Some("parent"));
        // commands inherited from parent
        assert!(child.commands.contains_key("backup"));
    }

    #[test]
    fn option_local_command_replaces_parent_command_set() {
        let yaml = "
command:
  backup: {}
  restore: {}
optionGroup: {}
option:
  parent:
    type: string
    command:
      backup: {}
  child:
    inherit: parent
    command:
      restore: {}
";
        let cfg = compile(&parse_config(yaml).unwrap()).unwrap();
        let child = &cfg.options["child"];
        assert!(!child.commands.contains_key("backup"));
        assert!(child.commands.contains_key("restore"));
    }

    #[test]
    fn option_command_inherit_string_copies_command_set_only() {
        let yaml = "
command:
  backup: {}
  restore: {}
optionGroup: {}
option:
  source:
    type: string
    command:
      backup:
        required: true
      restore: {}
  consumer:
    type: integer
    command: source
";
        let cfg = compile(&parse_config(yaml).unwrap()).unwrap();
        let consumer = &cfg.options["consumer"];
        assert_eq!(consumer.commands.len(), 2);
        // Per-command overrides from source are NOT carried over: required is None.
        assert!(consumer.commands.contains_key("backup"));
        assert_eq!(consumer.commands["backup"].required, None);
        assert!(consumer.commands.contains_key("restore"));
    }

    #[test]
    fn role_shortcut_any_includes_every_command() {
        let yaml = "
command:
  one: {}
  two: {}
optionGroup: {}
option:
  ubiq:
    type: boolean
    command:
      +role: any
";
        let cfg = compile(&parse_config(yaml).unwrap()).unwrap();
        assert_eq!(cfg.options["ubiq"].commands.len(), 2);
        assert!(cfg.options["ubiq"].commands.contains_key("one"));
        assert!(cfg.options["ubiq"].commands.contains_key("two"));
    }

    #[test]
    fn role_shortcut_with_specific_role_filters_commands() {
        let yaml = "
command:
  has-async:
    command-role:
      async: {}
  no-async: {}
optionGroup: {}
option:
  async-only:
    type: integer
    command:
      +role: async
";
        let cfg = compile(&parse_config(yaml).unwrap()).unwrap();
        let cmds = &cfg.options["async-only"].commands;
        assert!(cmds.contains_key("has-async"));
        assert!(!cmds.contains_key("no-async"));
    }

    #[test]
    fn negative_command_shortcut_excludes_after_includes() {
        let yaml = "
command:
  one: {}
  two: {}
  three: {}
optionGroup: {}
option:
  most:
    type: integer
    command:
      +role: any
      -command: two
      -command: three
";
        let cfg = compile(&parse_config(yaml).unwrap()).unwrap();
        let cmds = &cfg.options["most"].commands;
        assert!(cmds.contains_key("one"));
        assert!(!cmds.contains_key("two"));
        assert!(!cmds.contains_key("three"));
    }

    #[test]
    fn unknown_option_type_is_rejected() {
        let yaml = "
command: {}
optionGroup: {}
option:
  weird:
    type: not-a-real-type
";
        let err = compile(&parse_config(yaml).unwrap()).unwrap_err();
        assert!(matches!(err, CompileError::UnknownOptionType { option, option_type }
                if option == "weird" && option_type == "not-a-real-type"));
    }

    #[test]
    fn missing_option_type_is_rejected_when_not_inherited() {
        let yaml = "
command: {}
optionGroup: {}
option:
  weird:
    section: global
";
        let err = compile(&parse_config(yaml).unwrap()).unwrap_err();
        assert!(matches!(err, CompileError::MissingOptionType { option } if option == "weird"));
    }

    #[test]
    fn unknown_inherit_target_is_rejected() {
        let yaml = "
command: {}
optionGroup: {}
option:
  child:
    inherit: ghost
";
        let err = compile(&parse_config(yaml).unwrap()).unwrap_err();
        assert!(matches!(err, CompileError::UnknownOption { from, target }
                if from.contains("child") && target == "ghost"));
    }

    #[test]
    fn cyclic_inherit_is_rejected() {
        let yaml = "
command: {}
optionGroup: {}
option:
  a:
    inherit: b
  b:
    inherit: a
";
        let err = compile(&parse_config(yaml).unwrap()).unwrap_err();
        assert!(matches!(err, CompileError::CyclicInheritance(_)));
    }

    // ---- repository fixture: option resolution -----------------------------

    #[test]
    fn fixture_resolves_all_options() {
        let cfg = load_fixture();
        assert!(cfg.options.len() >= 100, "≥100 options expected, got {}", cfg.options.len());
        for name in ["stanza", "repo-path", "compress-level", "buffer-size", "pg-host", "cmd-ssh"] {
            assert!(cfg.options.contains_key(name), "missing option {name}");
        }
    }

    #[test]
    fn fixture_buffer_size_excludes_start_and_stop_via_dash_command() {
        let cfg = load_fixture();
        let cmds = &cfg.options["buffer-size"].commands;
        assert!(!cmds.contains_key("start"), "start should be -command-excluded");
        assert!(!cmds.contains_key("stop"), "stop should be -command-excluded");
        // It SHOULD include other commands per `+role: any`.
        assert!(cmds.contains_key("backup"));
    }

    #[test]
    fn fixture_cmd_ssh_inherits_from_cmd_with_local_command_override() {
        let cfg = load_fixture();
        let cmd_ssh = &cfg.options["cmd-ssh"];
        assert_eq!(cmd_ssh.inherits_from.as_deref(), Some("cmd"));
        // Inherited fields:
        assert_eq!(cmd_ssh.option_type, OptionType::String);
        // Local override: required: true (parent has no required field)
        assert!(cmd_ssh.required);
        // Local override: command: { +role: remote }, REPLACES parent's command set.
        // So cmd-ssh's commands must all support the remote role.
        for cmd_name in cmd_ssh.commands.keys() {
            let cmd = &cfg.commands[cmd_name];
            assert!(
                cmd.has_role(ConfigCommandRole::Remote),
                "cmd-ssh.commands contains {cmd_name} which has no remote role",
            );
        }
    }

    #[test]
    fn fixture_compress_level_inherits_command_set_from_compress() {
        let cfg = load_fixture();
        let compress = &cfg.options["compress"];
        let level = &cfg.options["compress-level"];
        // command: compress -> resolved commands must equal compress's keys.
        assert_eq!(
            level.commands.keys().collect::<BTreeSet<_>>(),
            compress.commands.keys().collect::<BTreeSet<_>>(),
        );
        // Per-command attributes are stripped: required is None even though
        // compress.commands.<name>.required may be set.
        for usage in level.commands.values() {
            assert_eq!(usage.required, None);
            assert_eq!(usage.default, None);
        }
    }

    #[test]
    fn fixture_stanza_per_command_overrides_required_false() {
        let cfg = load_fixture();
        let stanza = &cfg.options["stanza"];
        assert_eq!(stanza.commands["info"].required, Some(false));
        // For commands that don't override required, the entry exists with no
        // override (None), so the option-level required applies.
        assert_eq!(stanza.commands["backup"].required, None);
    }
}
