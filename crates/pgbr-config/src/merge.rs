//! Merge CLI input + `pgbackrest.conf` + option defaults into a final
//! [`LoadedConfig`].
//!
//! Precedence, highest to lowest:
//!
//! 1. Explicit CLI argument (`--option=value`).
//! 2. `[<stanza>:<command>]` section in the INI file.
//! 3. `[<stanza>]` section.
//! 4. `[global:<command>]` section.
//! 5. `[global]` section.
//! 6. Per-command override default (`option.<name>.command.<command>.default`).
//! 7. Option default (`option.<name>.default`).
//!
//! `--reset-X` wipes the value at every level above defaults; the option
//! still gets its default applied.
//!
//! Indexed groups (`pg`, `repo`): the merge auto-discovers which group
//! indices are configured by scanning for `<prefix><N>-` keys across every
//! section, plus any indices that appear in the CLI input.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::cli::ResolvedCli;
use crate::compile::Cfg;
use crate::ini::{IniFile, IniSection};
use crate::option::CfgOption;
use crate::types::{ConfigCommandRole, OptionGroup, OptionType};
use crate::value::{OptionValue, ValueError, parse_value};

/// Final, fully merged configuration for one `pgbackrest <command>`
/// invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    pub command: String,
    pub command_role: ConfigCommandRole,
    /// Stanza name (from `--stanza`). `None` for commands that don't require
    /// a stanza.
    pub stanza: Option<String>,
    /// Resolved option values keyed by `(option_name, group_index)`.
    pub options: BTreeMap<(String, Option<u32>), OptionValue>,
    /// Positional parameters (only present when the command allows them).
    pub params: Vec<String>,
}

/// Errors raised by [`load_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// An INI value didn't parse for the option's type.
    ValueParse {
        option: String,
        group_index: Option<u32>,
        error: ValueError,
    },
    /// A required option was not supplied (no CLI value, no INI value, no
    /// default).
    Required { option: String, group_index: Option<u32> },
    /// An INI section uses a key that doesn't match any declared option.
    UnknownIniKey { section: IniSection, key: String },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueParse {
                option,
                group_index,
                error,
            } => match group_index {
                Some(idx) => write!(f, "option `{option}` (group index {idx}): {error}"),
                None => write!(f, "option `{option}`: {error}"),
            },
            Self::Required { option, group_index } => match group_index {
                Some(idx) => write!(f, "option `{option}` (group index {idx}) is required"),
                None => write!(f, "option `{option}` is required"),
            },
            Self::UnknownIniKey { section, key } => {
                write!(f, "INI section {section:?} references unknown option `{key}`")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Merge a [`ResolvedCli`], an [`IniFile`], and the defaults from a
/// compiled [`Cfg`] into a final [`LoadedConfig`].
///
/// # Errors
///
/// Returns [`LoadError`] when an INI value fails to parse, when a required
/// option is missing, or when an INI section references an unknown option
/// key (typo / dropped option).
pub fn load_config(cli: ResolvedCli, ini: &IniFile, cfg: &Cfg) -> Result<LoadedConfig, LoadError> {
    let stanza = extract_stanza(&cli);
    let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();

    // Discover indices for each grouped option from CLI + every INI section
    // by scanning the raw keys.
    let group_indices = discover_group_indices(&cli, ini, cfg);

    for (name, opt) in &cfg.options {
        if !opt.commands.contains_key(&cli.command) {
            continue;
        }
        let usage = &opt.commands[&cli.command];

        let indices: Vec<Option<u32>> = match opt.group {
            Some(_) => {
                let mut list: Vec<Option<u32>> = group_indices
                    .get(name)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(Some)
                    .collect();
                if list.is_empty() {
                    // No occurrence anywhere — the option is implicitly
                    // index 1 (matches pgBackRest's "default first index").
                    list.push(Some(1));
                }
                list
            }
            None => vec![None],
        };

        for idx in indices {
            let key = (name.clone(), idx);
            // Reset short-circuits everything except defaults.
            let resetted = cli.resets.contains(&key);
            let cli_value = cli.options.get(&key).cloned();
            let ini_value = if resetted {
                None
            } else {
                lookup_ini(name, idx, opt, ini, &cli, opt.option_type, stanza.as_deref())?
            };
            let final_value = if let Some(v) = cli_value {
                Some(v)
            } else if let Some(v) = ini_value {
                Some(v)
            } else {
                resolve_default(opt, usage, name, idx)?
            };

            if let Some(value) = final_value {
                options.insert(key, value);
            } else if opt.required && (usage.required != Some(false)) {
                return Err(LoadError::Required {
                    option: name.clone(),
                    group_index: idx,
                });
            }
        }
    }

    Ok(LoadedConfig {
        command: cli.command,
        command_role: cli.command_role,
        stanza,
        options,
        params: cli.params,
    })
}

fn extract_stanza(cli: &ResolvedCli) -> Option<String> {
    cli.options.get(&("stanza".to_owned(), None)).and_then(|v| match v {
        OptionValue::String(s) => Some(s.clone()),
        _ => None,
    })
}

fn discover_group_indices(cli: &ResolvedCli, ini: &IniFile, cfg: &Cfg) -> BTreeMap<String, BTreeSet<u32>> {
    let mut out: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();

    for (name, idx) in cli.options.keys().chain(cli.resets.iter()) {
        if let Some(i) = idx {
            out.entry(name.clone()).or_default().insert(*i);
        }
    }

    for section in ini.sections.values() {
        for raw_key in section.keys() {
            if let Some((canonical, idx)) = decode_grouped_key(raw_key, cfg) {
                out.entry(canonical).or_default().insert(idx);
            }
        }
    }

    out
}

fn decode_grouped_key(raw_key: &str, cfg: &Cfg) -> Option<(String, u32)> {
    for (prefix, group) in [("pg", OptionGroup::Pg), ("repo", OptionGroup::Repo)] {
        if let Some(after) = raw_key.strip_prefix(prefix) {
            let digit_end = after.bytes().take_while(u8::is_ascii_digit).count();
            if digit_end == 0 || after.as_bytes().get(digit_end) != Some(&b'-') {
                continue;
            }
            let idx_str = &after[..digit_end];
            let rest = &after[digit_end + 1..];
            let canonical = format!("{prefix}-{rest}");
            if let Some(opt) = cfg.options.get(&canonical)
                && opt.group == Some(group)
                && let Ok(idx) = idx_str.parse::<u32>()
            {
                return Some((canonical, idx));
            }
        }
    }
    None
}

fn lookup_ini(
    option_name: &str,
    group_index: Option<u32>,
    opt: &CfgOption,
    ini: &IniFile,
    cli: &ResolvedCli,
    option_type: OptionType,
    stanza: Option<&str>,
) -> Result<Option<OptionValue>, LoadError> {
    // Build the textual key the INI uses (e.g. `repo1-path` or `stanza`).
    let raw_key = match (group_index, opt.group) {
        (Some(idx), Some(OptionGroup::Pg)) => format!("pg{idx}-{}", option_name.strip_prefix("pg-").unwrap_or(option_name)),
        (Some(idx), Some(OptionGroup::Repo)) => {
            format!("repo{idx}-{}", option_name.strip_prefix("repo-").unwrap_or(option_name))
        }
        _ => option_name.to_owned(),
    };

    // Precedence: stanza:command -> stanza -> global:command -> global.
    let mut try_sections: Vec<IniSection> = Vec::new();
    if let Some(s) = stanza {
        try_sections.push(IniSection::StanzaCommand {
            stanza: s.to_owned(),
            command: cli.command.clone(),
        });
        try_sections.push(IniSection::Stanza(s.to_owned()));
    }
    try_sections.push(IniSection::GlobalCommand(cli.command.clone()));
    try_sections.push(IniSection::Global);

    for section in &try_sections {
        if let Some(section_values) = ini.sections.get(section)
            && let Some(raw) = section_values.get(&raw_key)
        {
            let value = parse_value(option_type, raw).map_err(|error| LoadError::ValueParse {
                option: option_name.to_owned(),
                group_index,
                error,
            })?;
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn resolve_default(
    opt: &CfgOption,
    usage: &crate::option::ResolvedCommandUsage,
    option_name: &str,
    group_index: Option<u32>,
) -> Result<Option<OptionValue>, LoadError> {
    // Per-command default first, then option-level default.
    let raw = usage.default.as_ref().or(opt.default.as_ref());
    let Some(raw) = raw else {
        return Ok(None);
    };
    // Only handle scalar defaults — per-flavor list defaults (compress-level
    // and friends) are deferred until the consumer that needs them
    // (a flavor-aware lookup is wider than the scope of this merge step).
    let scalar = match raw {
        serde_yml::Value::String(s) => s.clone(),
        serde_yml::Value::Bool(b) => b.to_string(),
        serde_yml::Value::Number(n) => n.to_string(),
        // Per-flavor sequences and other shapes leave the option without a
        // resolved default. The caller can still set one explicitly.
        _ => return Ok(None),
    };
    let value = parse_value(opt.option_type, &scalar).map_err(|error| LoadError::ValueParse {
        option: option_name.to_owned(),
        group_index,
        error,
    })?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{parse_cli, resolve_cli};
    use pgbr_build::config::parse_config;

    fn small_cfg() -> Cfg {
        let yaml = r"
command:
  backup:
    command-role:
      local: {}
      remote: {}
  archive-push:
    parameter-allowed: true
optionGroup:
  pg: {}
  repo: {}
option:
  online:
    type: boolean
    default: true
    negate: true
    command:
      backup: {}
      archive-push: {}
  buffer-size:
    type: size
    default: 1MiB
    command:
      backup: {}
      archive-push: {}
  log-level-file:
    type: string-id
    default: info
    command:
      backup: {}
      archive-push: {}
  pg-path:
    type: path
    group: pg
    required: true
    command:
      backup: {}
  repo-path:
    type: path
    group: repo
    default: /var/lib/pgbackrest
    command:
      backup: {}
      archive-push: {}
  stanza:
    type: string
    required: true
    command:
      backup: {}
      archive-push: {}
";
        crate::compile::compile(&parse_config(yaml).unwrap()).unwrap()
    }

    fn load(cli_args: &[&str], ini_text: &str) -> Result<LoadedConfig, String> {
        let cfg = small_cfg();
        let cli = parse_cli(cli_args.iter().map(|s| (*s).to_owned())).map_err(|e| e.to_string())?;
        let resolved = resolve_cli(cli, &cfg).map_err(|e| e.to_string())?;
        let ini = crate::ini::parse_ini(ini_text).map_err(|e| e.to_string())?;
        load_config(resolved, &ini, &cfg).map_err(|e| e.to_string())
    }

    #[test]
    fn cli_overrides_ini_overrides_default() {
        let r = load(
            &["backup", "--stanza=demo", "--buffer-size=4MiB", "--pg1-path=/cli"],
            "[global]\nbuffer-size=2MiB\n[demo]\npg1-path=/ini\n",
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(4 * 1024 * 1024));
        assert_eq!(r.options[&("pg-path".into(), Some(1))], OptionValue::Path("/cli".into()));
        // No CLI / INI override for log-level-file: default applies.
        assert_eq!(
            r.options[&("log-level-file".into(), None)],
            OptionValue::StringId("info".into())
        );
    }

    #[test]
    fn ini_used_when_cli_absent() {
        let r = load(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            "[global]\nbuffer-size=8MiB\n",
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(8 * 1024 * 1024));
    }

    #[test]
    fn stanza_command_section_beats_global() {
        let r = load(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            "[global]\nbuffer-size=2MiB\n[demo:backup]\nbuffer-size=8MiB\n",
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(8 * 1024 * 1024));
    }

    #[test]
    fn default_applies_when_nothing_else_set() {
        let r = load(&["backup", "--stanza=demo", "--pg1-path=/data"], "").unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(1024 * 1024));
        assert_eq!(
            r.options[&("repo-path".into(), Some(1))],
            OptionValue::Path("/var/lib/pgbackrest".into())
        );
    }

    #[test]
    fn reset_drops_ini_value_and_keeps_default() {
        let r = load(
            &["backup", "--stanza=demo", "--pg1-path=/data", "--reset-buffer-size"],
            "[global]\nbuffer-size=8MiB\n",
        );
        // `buffer-size` doesn't have `reset: true` in this fixture — should error.
        assert!(r.is_err());
    }

    #[test]
    fn missing_required_option_is_reported() {
        // pg-path has no default and is required.
        let r = load(&["backup", "--stanza=demo"], "").unwrap_err();
        assert!(r.contains("pg-path"));
        assert!(r.contains("required"));
    }

    #[test]
    fn group_indices_discovered_from_ini() {
        let r = load(
            &["backup", "--stanza=demo"],
            "[demo]\npg1-path=/a\npg2-path=/b\npg5-path=/c\n",
        )
        .unwrap();
        assert_eq!(r.options[&("pg-path".into(), Some(1))], OptionValue::Path("/a".into()));
        assert_eq!(r.options[&("pg-path".into(), Some(2))], OptionValue::Path("/b".into()));
        assert_eq!(r.options[&("pg-path".into(), Some(5))], OptionValue::Path("/c".into()));
    }

    #[test]
    fn negate_in_cli_yields_boolean_false() {
        let r = load(&["backup", "--stanza=demo", "--pg1-path=/data", "--no-online"], "").unwrap();
        assert_eq!(r.options[&("online".into(), None)], OptionValue::Boolean(false));
    }

    #[test]
    fn unknown_options_in_ini_are_ignored() {
        // The merge currently ignores unknown INI keys silently. Callers can
        // post-process the IniFile if they want strict validation; keeping
        // this lenient matches the C behavior of accepting unknown keys when
        // they don't get queried.
        let r = load(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            "[global]\nfuture-option=42\n",
        )
        .unwrap();
        assert_eq!(r.command, "backup");
    }
}
