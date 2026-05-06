//! Command-line argument tokenizer and resolver.
//!
//! Two-phase parsing of the `pgbackrest` invocation's argv:
//!
//! 1. [`parse_cli`] turns a flat `argv`-style iterator into a [`CliInput`] —
//!    a structurally validated form (command identifier, raw option entries,
//!    positional parameters). No knowledge of which options exist is needed
//!    at this stage.
//! 2. [`resolve_cli`] takes a [`CliInput`] and a compiled [`Cfg`] and
//!    produces a [`ResolvedCli`]: command + command-role lookup, indexed-
//!    group decoding (`pg1-host` -> option `pg-host`, group index `1`),
//!    typed value parsing via [`crate::value::parse_value`], and per-command
//!    validity checks.
//!
//! Splitting the two phases lets `pgbr-config` consume `argv` with no Cfg in
//! hand (useful for `--version`/`--help` which short-circuit before the YAML
//! is even loaded), and lets tests exercise the tokenizer without building a
//! full Cfg.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::compile::Cfg;
use crate::types::{ConfigCommandRole, OptionGroup};
use crate::value::{OptionValue, ValueError, parse_value};

/// Modifier prefix on a CLI option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliModifier {
    /// `--option=value` or `--option value` (the canonical form).
    None,
    /// `--no-option` (only for booleans with `negate: true`).
    Negate,
    /// `--reset-option` — wipes any previously set value, including defaults.
    Reset,
}

/// One option as it appeared on the command line, before any Cfg lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOptionEntry {
    /// Raw key as written, with the `--` and any modifier prefix removed
    /// (e.g. `--no-online` becomes `online` with [`CliModifier::Negate`]).
    /// Indexed group prefixes (`repo1-`, `pg2-`) are still attached here.
    pub raw_key: String,
    pub modifier: CliModifier,
    /// `None` for booleans / [`CliModifier::Negate`] / [`CliModifier::Reset`]
    /// where no value was supplied.
    pub value: Option<String>,
}

/// Structurally tokenized argv.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliInput {
    /// First positional argument (the command), if any.
    pub command: Option<String>,
    /// Optional `:role` suffix on the command (`backup:async`).
    pub command_role: Option<String>,
    /// Options in the order they appeared.
    pub options: Vec<CliOptionEntry>,
    /// Positional arguments after the command. Empty unless the command has
    /// `parameter-allowed: true`.
    pub params: Vec<String>,
}

/// Errors raised by [`parse_cli`] (purely structural).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// `--option` was supplied without a value, but it doesn't look like a
    /// boolean (no `=` and the next argv token also begins with `--`).
    MissingValue { key: String },
    /// `--=value` or other malformed key.
    EmptyKey,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue { key } => write!(f, "option `--{key}` is missing its value"),
            Self::EmptyKey => f.write_str("option key is empty"),
        }
    }
}

impl std::error::Error for CliError {}

/// Tokenize an argv iterator into [`CliInput`].
///
/// `args` should NOT include `argv[0]` (the program name); pass `env::args().skip(1)`.
///
/// # Errors
///
/// Returns [`CliError`] for structurally malformed input. Semantic errors
/// (unknown option, type mismatch, …) are deferred to [`resolve_cli`].
pub fn parse_cli<I, S>(args: I) -> Result<CliInput, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let mut out = CliInput::default();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(after_dashes) = arg.strip_prefix("--") {
            // `--` alone terminates option parsing; remaining args are positional.
            if after_dashes.is_empty() {
                for rest in &args[i + 1..] {
                    push_positional(&mut out, rest.clone());
                }
                break;
            }
            let (key_with_value, has_inline_value) = match after_dashes.split_once('=') {
                Some((k, v)) => ((k.to_owned(), Some(v.to_owned())), true),
                None => ((after_dashes.to_owned(), None), false),
            };
            let (raw_key, inline_value) = key_with_value;
            if raw_key.is_empty() {
                return Err(CliError::EmptyKey);
            }
            let (modifier, key) = strip_modifier(&raw_key);
            let value = if has_inline_value {
                inline_value
            } else if matches!(modifier, CliModifier::Negate | CliModifier::Reset) {
                None
            } else if args.get(i + 1).is_some_and(|next| !next.starts_with("--")) {
                // A bare boolean option has no following value — distinguish
                // by whether the next argv token *looks* like another option.
                // This matches the C parser's behaviour for boolean shorthand.
                let v = args[i + 1].clone();
                i += 1;
                Some(v)
            } else {
                None
            };
            out.options.push(CliOptionEntry {
                raw_key: key.to_owned(),
                modifier,
                value,
            });
        } else {
            push_positional(&mut out, arg.to_owned());
        }
        i += 1;
    }
    Ok(out)
}

fn push_positional(out: &mut CliInput, arg: String) {
    if out.command.is_none() {
        // Split off an optional `:role` suffix on the command (`backup:async`).
        if let Some((cmd, role)) = arg.split_once(':') {
            out.command = Some(cmd.to_owned());
            out.command_role = Some(role.to_owned());
        } else {
            out.command = Some(arg);
        }
    } else {
        out.params.push(arg);
    }
}

fn strip_modifier(raw_key: &str) -> (CliModifier, &str) {
    raw_key.strip_prefix("no-").map_or_else(
        || {
            raw_key
                .strip_prefix("reset-")
                .map_or_else(|| (CliModifier::None, raw_key), |rest| (CliModifier::Reset, rest))
        },
        |rest| (CliModifier::Negate, rest),
    )
}

// ---- resolution against a compiled Cfg ------------------------------------

/// CLI input mapped against a compiled [`Cfg`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCli {
    pub command: String,
    pub command_role: ConfigCommandRole,
    /// Resolved option values. Key is `(option_name, group_index)`. Group
    /// index is `None` for non-grouped options, `Some(N)` for group options
    /// (e.g. `repo1-path` => `("repo-path", Some(1))`).
    pub options: BTreeMap<(String, Option<u32>), OptionValue>,
    /// Options the user reset with `--reset-X`. Same key shape as `options`.
    pub resets: BTreeSet<(String, Option<u32>)>,
    pub params: Vec<String>,
}

/// Errors raised by [`resolve_cli`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliResolveError {
    /// `argv` had no positional command.
    MissingCommand,
    /// The command isn't declared in `config.yaml`.
    UnknownCommand { command: String },
    /// The `:role` suffix on the command is not one of `main`/`async`/`local`/`remote`.
    UnknownRole { command: String, role: String },
    /// The command does not declare the requested role.
    RoleNotValidForCommand { command: String, role: ConfigCommandRole },
    /// The option name (after stripping group index) isn't declared.
    UnknownOption { command: String, option: String },
    /// The option exists but isn't valid for the current command.
    OptionNotValidForCommand { command: String, option: String },
    /// `--no-X` was used on an option whose `negate:` is `false`.
    NegateNotAllowed { option: String },
    /// A non-boolean option was supplied without a value.
    MissingValue { option: String },
    /// `--reset-X` was used on an option whose `reset:` is `false`.
    ResetNotAllowed { option: String },
    /// Positional parameters were given but the command does not accept them.
    ParametersNotAllowed { command: String, count: usize },
    /// The raw value didn't parse for the option's type.
    ValueParse { option: String, error: ValueError },
    /// `repo3-foo` references a group index but the option's group is not
    /// `pg`/`repo`, or the group prefix is malformed.
    InvalidGroupIndex { option: String, raw: String },
}

impl fmt::Display for CliResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommand => f.write_str("no command supplied"),
            Self::UnknownCommand { command } => write!(f, "unknown command `{command}`"),
            Self::UnknownRole { command, role } => write!(f, "command `{command}`: unknown role `{role}`"),
            Self::RoleNotValidForCommand { command, role } => {
                write!(f, "command `{command}` does not declare role `{}`", role.as_str())
            }
            Self::UnknownOption { command, option } => write!(f, "command `{command}`: unknown option `{option}`"),
            Self::OptionNotValidForCommand { command, option } => {
                write!(f, "option `{option}` is not valid for command `{command}`")
            }
            Self::NegateNotAllowed { option } => {
                write!(f, "option `{option}` does not allow `--no-` negation")
            }
            Self::MissingValue { option } => write!(f, "option `{option}` requires a value"),
            Self::ResetNotAllowed { option } => write!(f, "option `{option}` does not allow `--reset-`"),
            Self::ParametersNotAllowed { command, count } => {
                write!(f, "command `{command}` does not accept positional parameters (got {count})")
            }
            Self::ValueParse { option, error } => write!(f, "option `{option}`: {error}"),
            Self::InvalidGroupIndex { option, raw } => {
                write!(f, "option `{option}`: invalid group index in `{raw}`")
            }
        }
    }
}

impl std::error::Error for CliResolveError {}

/// Resolve a tokenized [`CliInput`] against a compiled [`Cfg`].
///
/// # Errors
///
/// Returns [`CliResolveError`] when the CLI references an unknown command
/// or option, when an option is used incorrectly (negate without `negate:`,
/// reset without `reset:`, missing value, type mismatch), or when
/// positional parameters are given to a command that doesn't accept them.
pub fn resolve_cli(input: CliInput, cfg: &Cfg) -> Result<ResolvedCli, CliResolveError> {
    let command = input.command.ok_or(CliResolveError::MissingCommand)?;
    let cmd_def = cfg.commands.get(&command).ok_or_else(|| CliResolveError::UnknownCommand {
        command: command.clone(),
    })?;

    let command_role = if let Some(raw) = input.command_role.as_deref() {
        let role = ConfigCommandRole::parse(raw).ok_or_else(|| CliResolveError::UnknownRole {
            command: command.clone(),
            role: raw.to_owned(),
        })?;
        if !cmd_def.has_role(role) {
            return Err(CliResolveError::RoleNotValidForCommand {
                command: command.clone(),
                role,
            });
        }
        role
    } else {
        ConfigCommandRole::Main
    };

    let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
    let mut resets: BTreeSet<(String, Option<u32>)> = BTreeSet::new();

    for entry in &input.options {
        let (option_name, group_index) = decode_option_key(&entry.raw_key, cfg, &command)?;
        let opt = &cfg.options[&option_name];

        if !opt.commands.contains_key(&command) {
            return Err(CliResolveError::OptionNotValidForCommand {
                command: command.clone(),
                option: option_name,
            });
        }

        match entry.modifier {
            CliModifier::Negate => {
                if !opt.negate {
                    return Err(CliResolveError::NegateNotAllowed { option: option_name });
                }
                options.insert((option_name, group_index), OptionValue::Boolean(false));
            }
            CliModifier::Reset => {
                if !opt.reset {
                    return Err(CliResolveError::ResetNotAllowed { option: option_name });
                }
                resets.insert((option_name.clone(), group_index));
                options.remove(&(option_name, group_index));
            }
            CliModifier::None => match (&entry.value, opt.option_type) {
                (None, crate::types::OptionType::Boolean) => {
                    options.insert((option_name, group_index), OptionValue::Boolean(true));
                }
                (None, _) => {
                    return Err(CliResolveError::MissingValue { option: option_name });
                }
                (Some(raw), _) => {
                    let value = parse_value(opt.option_type, raw).map_err(|error| CliResolveError::ValueParse {
                        option: option_name.clone(),
                        error,
                    })?;
                    options.insert((option_name, group_index), value);
                }
            },
        }
    }

    if !input.params.is_empty() && !cmd_def.parameter_allowed {
        return Err(CliResolveError::ParametersNotAllowed {
            command,
            count: input.params.len(),
        });
    }

    Ok(ResolvedCli {
        command,
        command_role,
        options,
        resets,
        params: input.params,
    })
}

/// Split a raw option key (`repo1-path`) into a canonical option name
/// (`repo-path`) and an optional group index. Returns `(name, None)` for
/// non-grouped options and for unknown keys (the caller surfaces the
/// unknown-option error).
fn decode_option_key(raw_key: &str, cfg: &Cfg, command: &str) -> Result<(String, Option<u32>), CliResolveError> {
    // Fast path: exact match → non-grouped option.
    if cfg.options.contains_key(raw_key) {
        return Ok((raw_key.to_owned(), None));
    }

    // Try to peel off a group prefix: `pg<N>-rest` or `repo<N>-rest`.
    for (prefix, group) in [("pg", OptionGroup::Pg), ("repo", OptionGroup::Repo)] {
        if let Some(after) = raw_key.strip_prefix(prefix) {
            // `after` must start with one or more ASCII digits, then `-`.
            let digit_end = after.bytes().take_while(u8::is_ascii_digit).count();
            if digit_end == 0 || after.as_bytes().get(digit_end) != Some(&b'-') {
                continue;
            }
            let idx_str = &after[..digit_end];
            let rest = &after[digit_end + 1..];
            let canonical = format!("{prefix}-{rest}");
            if let Some(opt) = cfg.options.get(&canonical) {
                if opt.group != Some(group) {
                    return Err(CliResolveError::InvalidGroupIndex {
                        option: canonical,
                        raw: raw_key.to_owned(),
                    });
                }
                let idx = idx_str.parse::<u32>().map_err(|_| CliResolveError::InvalidGroupIndex {
                    option: canonical.clone(),
                    raw: raw_key.to_owned(),
                })?;
                return Ok((canonical, Some(idx)));
            }
        }
    }

    Err(CliResolveError::UnknownOption {
        command: command.to_owned(),
        option: raw_key.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgbr_build::config::parse_config;

    fn small_cfg() -> Cfg {
        let yaml = r"
command:
  backup:
    command-role:
      local: {}
      remote: {}
    parameter-allowed: false
  archive-push:
    command-role:
      async: {}
    parameter-allowed: true
optionGroup:
  pg: {}
  repo: {}
option:
  online:
    type: boolean
    default: true
    negate: true
    reset: true
    command:
      backup: {}
      archive-push: {}
  buffer-size:
    type: size
    default: 1MiB
    reset: true
    command:
      backup: {}
      archive-push: {}
  pg-path:
    type: path
    group: pg
    command:
      backup: {}
  repo-path:
    type: path
    group: repo
    command:
      backup: {}
      archive-push: {}
  stanza:
    type: string
    command:
      backup: {}
      archive-push: {}
";
        crate::compile::compile(&parse_config(yaml).unwrap()).unwrap()
    }

    // ---- parse_cli (tokenizer) --------------------------------------------

    #[test]
    fn parses_command_only() {
        let r = parse_cli(["backup"]).unwrap();
        assert_eq!(r.command.as_deref(), Some("backup"));
        assert!(r.command_role.is_none());
        assert!(r.options.is_empty());
    }

    #[test]
    fn parses_inline_value() {
        let r = parse_cli(["backup", "--stanza=demo"]).unwrap();
        assert_eq!(r.options[0].raw_key, "stanza");
        assert_eq!(r.options[0].value.as_deref(), Some("demo"));
        assert_eq!(r.options[0].modifier, CliModifier::None);
    }

    #[test]
    fn parses_separate_value() {
        let r = parse_cli(["backup", "--stanza", "demo"]).unwrap();
        assert_eq!(r.options[0].raw_key, "stanza");
        assert_eq!(r.options[0].value.as_deref(), Some("demo"));
    }

    #[test]
    fn boolean_form_has_no_value() {
        let r = parse_cli(["backup", "--online", "--stanza=demo"]).unwrap();
        let online = &r.options[0];
        assert_eq!(online.raw_key, "online");
        assert!(online.value.is_none());
        let stanza = &r.options[1];
        assert_eq!(stanza.raw_key, "stanza");
        assert_eq!(stanza.value.as_deref(), Some("demo"));
    }

    #[test]
    fn negate_and_reset_modifiers() {
        let r = parse_cli(["backup", "--no-online", "--reset-buffer-size"]).unwrap();
        assert_eq!(r.options[0].raw_key, "online");
        assert_eq!(r.options[0].modifier, CliModifier::Negate);
        assert_eq!(r.options[1].raw_key, "buffer-size");
        assert_eq!(r.options[1].modifier, CliModifier::Reset);
    }

    #[test]
    fn double_dash_terminates_option_parsing() {
        let r = parse_cli(["archive-push", "--stanza=demo", "--", "--this-is-a-param"]).unwrap();
        assert_eq!(r.command.as_deref(), Some("archive-push"));
        assert_eq!(r.options.len(), 1);
        assert_eq!(r.params, vec!["--this-is-a-param".to_owned()]);
    }

    #[test]
    fn command_role_split_on_colon() {
        let r = parse_cli(["backup:async"]).unwrap();
        assert_eq!(r.command.as_deref(), Some("backup"));
        assert_eq!(r.command_role.as_deref(), Some("async"));
    }

    #[test]
    fn empty_key_is_rejected() {
        let err = parse_cli(["backup", "--=value"]).unwrap_err();
        assert_eq!(err, CliError::EmptyKey);
    }

    // ---- resolve_cli (against Cfg) ----------------------------------------

    #[test]
    fn resolves_command_and_inline_string_option() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let r = resolve_cli(input, &cfg).unwrap();
        assert_eq!(r.command, "backup");
        assert_eq!(r.command_role, ConfigCommandRole::Main);
        assert_eq!(r.options[&("stanza".to_owned(), None)], OptionValue::String("demo".into()));
    }

    #[test]
    fn boolean_default_true_when_no_value() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--online"]).unwrap();
        let r = resolve_cli(input, &cfg).unwrap();
        assert_eq!(r.options[&("online".to_owned(), None)], OptionValue::Boolean(true));
    }

    #[test]
    fn negate_resolves_to_boolean_false_when_allowed() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--no-online"]).unwrap();
        let r = resolve_cli(input, &cfg).unwrap();
        assert_eq!(r.options[&("online".to_owned(), None)], OptionValue::Boolean(false));
    }

    #[test]
    fn reset_modifier_clears_value_and_records_reset() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--buffer-size=2MiB", "--reset-buffer-size"]).unwrap();
        let r = resolve_cli(input, &cfg).unwrap();
        assert!(r.options.get(&("buffer-size".to_owned(), None)).is_none());
        assert!(r.resets.contains(&("buffer-size".to_owned(), None)));
    }

    #[test]
    fn group_indexed_option_decoded() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--pg1-path=/var/lib/pg"]).unwrap();
        let r = resolve_cli(input, &cfg).unwrap();
        let v = r.options.get(&("pg-path".to_owned(), Some(1))).unwrap();
        assert_eq!(v, &OptionValue::Path("/var/lib/pg".into()));
    }

    #[test]
    fn unknown_command_is_rejected() {
        let cfg = small_cfg();
        let input = parse_cli(["dance"]).unwrap();
        assert!(matches!(
            resolve_cli(input, &cfg),
            Err(CliResolveError::UnknownCommand { .. })
        ));
    }

    #[test]
    fn unknown_option_is_rejected() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--mystery=42"]).unwrap();
        assert!(matches!(resolve_cli(input, &cfg), Err(CliResolveError::UnknownOption { .. })));
    }

    #[test]
    fn option_not_valid_for_command_is_rejected() {
        let cfg = small_cfg();
        // pg-path is only valid for backup, not archive-push.
        let input = parse_cli(["archive-push", "--pg1-path=/var/lib/pg"]).unwrap();
        assert!(matches!(
            resolve_cli(input, &cfg),
            Err(CliResolveError::OptionNotValidForCommand { .. })
        ));
    }

    #[test]
    fn negate_on_non_negate_option_is_rejected() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--no-stanza"]).unwrap();
        assert!(matches!(
            resolve_cli(input, &cfg),
            Err(CliResolveError::NegateNotAllowed { .. })
        ));
    }

    #[test]
    fn type_mismatch_surfaces_value_parse_error() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--buffer-size=1.5MiB"]).unwrap();
        assert!(matches!(resolve_cli(input, &cfg), Err(CliResolveError::ValueParse { .. })));
    }

    #[test]
    fn parameters_rejected_when_not_allowed() {
        let cfg = small_cfg();
        let input = parse_cli(["backup", "--stanza=demo", "extra"]).unwrap();
        assert!(matches!(
            resolve_cli(input, &cfg),
            Err(CliResolveError::ParametersNotAllowed { .. })
        ));
    }

    #[test]
    fn parameters_accepted_when_allowed() {
        let cfg = small_cfg();
        let input = parse_cli(["archive-push", "--stanza=demo", "/path/to/wal"]).unwrap();
        let r = resolve_cli(input, &cfg).unwrap();
        assert_eq!(r.params, vec!["/path/to/wal".to_owned()]);
    }

    #[test]
    fn role_suffix_resolves_when_command_supports_role() {
        let cfg = small_cfg();
        let input = parse_cli(["backup:local", "--stanza=demo"]).unwrap();
        let r = resolve_cli(input, &cfg).unwrap();
        assert_eq!(r.command_role, ConfigCommandRole::Local);
    }

    #[test]
    fn role_suffix_rejected_when_command_lacks_role() {
        let cfg = small_cfg();
        // backup has no async role.
        let input = parse_cli(["backup:async"]).unwrap();
        assert!(matches!(
            resolve_cli(input, &cfg),
            Err(CliResolveError::RoleNotValidForCommand { .. })
        ));
    }
}
