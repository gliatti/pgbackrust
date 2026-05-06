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
    /// The resolved value isn't in the option's `allow-list`.
    NotInAllowList {
        option: String,
        group_index: Option<u32>,
        value: String,
        allowed: Vec<String>,
    },
    /// The resolved numeric value is outside the option's `allow-range`.
    OutOfAllowRange {
        option: String,
        group_index: Option<u32>,
        value: String,
        range: String,
    },
    /// An option's `depend:` constraint is not satisfied — the depended option
    /// has a value not in the dependency's `list`, and the dep doesn't supply a
    /// fallback `default`.
    DependNotSatisfied {
        option: String,
        group_index: Option<u32>,
        depend_option: String,
        /// String form of the depended option's resolved value (or `"unset"` if
        /// nothing was set).
        depend_value: String,
        /// String forms of the values in `depend.list`. Empty when the depend
        /// only requires the option to be set.
        depend_list: Vec<String>,
    },
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
            Self::NotInAllowList {
                option,
                group_index,
                value,
                allowed,
            } => {
                let suffix = group_index.map(|i| format!(" (group {i})")).unwrap_or_default();
                write!(
                    f,
                    "option `{option}`{suffix}: value `{value}` is not in allow-list [{}]",
                    allowed.join(", "),
                )
            }
            Self::OutOfAllowRange {
                option,
                group_index,
                value,
                range,
            } => {
                let suffix = group_index.map(|i| format!(" (group {i})")).unwrap_or_default();
                write!(f, "option `{option}`{suffix}: value `{value}` is outside allow-range {range}")
            }
            Self::DependNotSatisfied {
                option,
                group_index,
                depend_option,
                depend_value,
                depend_list,
            } => {
                let suffix = group_index.map(|i| format!(" (group {i})")).unwrap_or_default();
                if depend_list.is_empty() {
                    write!(
                        f,
                        "option `{option}`{suffix}: depends on option `{depend_option}` being set (currently {depend_value})",
                    )
                } else {
                    write!(
                        f,
                        "option `{option}`{suffix}: depends on option `{depend_option}` value being one of [{}] (currently {depend_value})",
                        depend_list.join(", "),
                    )
                }
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
                validate_value(&value, opt, usage, name, idx)?;
                options.insert(key, value);
            } else if opt.required && (usage.required != Some(false)) {
                return Err(LoadError::Required {
                    option: name.clone(),
                    group_index: idx,
                });
            }
        }
    }

    validate_depends(&options, cfg, &cli.command)?;

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

fn validate_value(
    value: &OptionValue,
    opt: &CfgOption,
    usage: &crate::option::ResolvedCommandUsage,
    option_name: &str,
    group_index: Option<u32>,
) -> Result<(), LoadError> {
    // allow-list — per-command override wins, falls back to option-level.
    if let Some(allowed) = usage.allow_list.as_ref().or(opt.allow_list.as_ref()) {
        let allowed_strs: Vec<String> = allowed.iter().filter_map(value_to_match_str).collect();
        if let Some(value_str) = option_value_to_match_str(value)
            && !allowed_strs.iter().any(|a| a == &value_str)
        {
            return Err(LoadError::NotInAllowList {
                option: option_name.to_owned(),
                group_index,
                value: value_str,
                allowed: allowed_strs,
            });
        }
    }

    // allow-range — only the simple `[min, max]` shape is enforced here.
    // Per-flavor allow-range (e.g. `[{bz2: [1, 9]}, {gz: [-1, 9]}]`) is left
    // to the flavor-aware caller.
    if let Some(range) = opt.allow_range.as_ref() {
        let serde_yml::Value::Sequence(items) = range else {
            return Ok(());
        };
        if items.len() != 2 {
            return Ok(());
        }
        let (Some(min), Some(max)) = (yaml_to_i64(&items[0]), yaml_to_i64(&items[1])) else {
            return Ok(());
        };
        let n = match value {
            OptionValue::Integer(n) => Some(*n),
            OptionValue::Time(n) | OptionValue::Size(n) => i64::try_from(*n).ok(),
            _ => None,
        };
        if let Some(v) = n
            && (v < min || v > max)
        {
            return Err(LoadError::OutOfAllowRange {
                option: option_name.to_owned(),
                group_index,
                value: v.to_string(),
                range: format!("[{min}, {max}]"),
            });
        }
    }
    Ok(())
}

fn value_to_match_str(v: &serde_yml::Value) -> Option<String> {
    match v {
        serde_yml::Value::String(s) => Some(s.clone()),
        serde_yml::Value::Bool(b) => Some(b.to_string()),
        serde_yml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn option_value_to_match_str(v: &OptionValue) -> Option<String> {
    match v {
        OptionValue::String(s) | OptionValue::StringId(s) | OptionValue::Path(s) => Some(s.clone()),
        OptionValue::Boolean(b) => Some(b.to_string()),
        OptionValue::Integer(n) => Some(n.to_string()),
        OptionValue::Size(n) | OptionValue::Time(n) => Some(n.to_string()),
        OptionValue::List(_) | OptionValue::Hash(_) => None,
    }
}

fn yaml_to_i64(v: &serde_yml::Value) -> Option<i64> {
    match v {
        serde_yml::Value::Number(n) => n.as_i64(),
        serde_yml::Value::String(s) => s.parse::<i64>().ok(),
        _ => None,
    }
}

/// Match candidates for an [`OptionValue`] when comparing against an
/// allow-list / depend-list entry. Returns the primary string form first;
/// booleans also include the `y`/`n` shorthand because depend-lists in
/// `config.yaml` historically use either spelling.
fn option_value_match_candidates(v: &OptionValue) -> Vec<String> {
    match v {
        OptionValue::Boolean(true) => vec!["true".to_owned(), "y".to_owned()],
        OptionValue::Boolean(false) => vec!["false".to_owned(), "n".to_owned()],
        _ => option_value_to_match_str(v).into_iter().collect(),
    }
}

fn validate_depends(options: &BTreeMap<(String, Option<u32>), OptionValue>, cfg: &Cfg, command: &str) -> Result<(), LoadError> {
    for (name, idx) in options.keys() {
        let Some(opt) = cfg.options.get(name) else {
            continue;
        };
        // Per-command override wins, falls back to option-level.
        let depend = opt
            .commands
            .get(command)
            .and_then(|usage| usage.depend.as_ref())
            .or(opt.depend.as_ref());
        let Some(depend) = depend else {
            continue;
        };

        // Look up the depended option's value. If the depending option is
        // grouped, look at the same index; otherwise None. If the depended
        // option is grouped but the depending one isn't, fall back to index 1.
        let dep_opt = cfg.options.get(&depend.option);
        let dep_idx: Option<u32> = match (idx, dep_opt.and_then(|o| o.group)) {
            (Some(i), Some(_)) => Some(*i),
            (None, Some(_)) => Some(1),
            _ => None,
        };
        let dep_value = options.get(&(depend.option.clone(), dep_idx));

        let depend_list_strs: Vec<String> = depend
            .list
            .as_ref()
            .map(|l| l.iter().filter_map(value_to_match_str).collect())
            .unwrap_or_default();

        match dep_value {
            None => {
                // Depended option has no resolved value.
                if depend.default.is_some() {
                    // Lenient: dep is unsatisfied but tolerated. Future,
                    // type-aware substitution will plug in `depend.default`.
                    continue;
                }
                return Err(LoadError::DependNotSatisfied {
                    option: name.clone(),
                    group_index: *idx,
                    depend_option: depend.option.clone(),
                    depend_value: "unset".to_owned(),
                    depend_list: depend_list_strs,
                });
            }
            Some(v) => {
                if depend.list.is_none() {
                    // Bare `depend: <name>` — satisfied iff dep has any value.
                    continue;
                }
                let candidates = option_value_match_candidates(v);
                if candidates.iter().any(|c| depend_list_strs.iter().any(|d| d == c)) {
                    continue;
                }
                let value_str = candidates.first().cloned().unwrap_or_else(|| "<opaque>".to_owned());
                return Err(LoadError::DependNotSatisfied {
                    option: name.clone(),
                    group_index: *idx,
                    depend_option: depend.option.clone(),
                    depend_value: value_str,
                    depend_list: depend_list_strs,
                });
            }
        }
    }
    Ok(())
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
    fn allow_list_rejects_disallowed_value() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  output:
    type: string-id
    default: text
    allow-list:
      - text
      - json
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--output=xml"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let err = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap_err();
        assert!(matches!(err, LoadError::NotInAllowList { .. }));
    }

    #[test]
    fn allow_list_accepts_allowed_value() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  output:
    type: string-id
    default: text
    allow-list:
      - text
      - json
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--output=json"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("output".into(), None)], OptionValue::StringId("json".into()));
    }

    #[test]
    fn allow_range_rejects_out_of_range_integer() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  process-max:
    type: integer
    default: 1
    allow-range: [1, 999]
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--process-max=2000"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let err = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap_err();
        assert!(matches!(err, LoadError::OutOfAllowRange { .. }));
    }

    #[test]
    fn allow_range_accepts_in_range_integer() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  process-max:
    type: integer
    default: 1
    allow-range: [1, 999]
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--process-max=8"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("process-max".into(), None)], OptionValue::Integer(8));
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

    #[test]
    fn depend_satisfied_when_value_in_list() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  online:
    type: boolean
    default: true
    negate: true
    command:
      backup: {}
  force:
    type: boolean
    default: false
    negate: true
    depend:
      option: online
      list: [false]
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--no-online", "--force"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("force".into(), None)], OptionValue::Boolean(true));
        assert_eq!(r.options[&("online".into(), None)], OptionValue::Boolean(false));
    }

    #[test]
    fn depend_not_satisfied_when_value_not_in_list() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  online:
    type: boolean
    default: true
    negate: true
    command:
      backup: {}
  force:
    type: boolean
    default: false
    negate: true
    depend:
      option: online
      list: [false]
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        // online stays true (its default); force is set explicitly.
        let cli = parse_cli(["backup", "--stanza=demo", "--force"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let err = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap_err();
        match err {
            LoadError::DependNotSatisfied {
                option,
                depend_option,
                depend_value,
                depend_list,
                ..
            } => {
                assert_eq!(option, "force");
                assert_eq!(depend_option, "online");
                assert_eq!(depend_value, "true");
                assert_eq!(depend_list, vec!["false".to_owned()]);
            }
            other => panic!("expected DependNotSatisfied, got {other:?}"),
        }
    }

    #[test]
    fn bare_string_depend_satisfied_when_dep_set() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  alpha:
    type: string
    command:
      backup: {}
  beta:
    type: string
    depend: alpha
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--alpha=hi", "--beta=there"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("beta".into(), None)], OptionValue::String("there".into()));
    }

    #[test]
    fn bare_string_depend_violated_when_dep_unset() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  alpha:
    type: string
    command:
      backup: {}
  beta:
    type: string
    depend: alpha
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--beta=there"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let err = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap_err();
        match err {
            LoadError::DependNotSatisfied {
                option,
                depend_option,
                depend_value,
                depend_list,
                ..
            } => {
                assert_eq!(option, "beta");
                assert_eq!(depend_option, "alpha");
                assert_eq!(depend_value, "unset");
                assert!(depend_list.is_empty());
            }
            other => panic!("expected DependNotSatisfied, got {other:?}"),
        }
    }

    #[test]
    fn depend_with_fallback_default_skips_strict_check() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  alpha:
    type: string
    command:
      backup: {}
  beta:
    type: string
    depend:
      option: alpha
      default: fallback
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        // alpha is unset; beta is set. The dep has a fallback default, so the
        // depend constraint is treated leniently and beta keeps its value.
        let cli = parse_cli(["backup", "--stanza=demo", "--beta=there"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("beta".into(), None)], OptionValue::String("there".into()));
    }

    #[test]
    fn per_command_depend_overrides_option_depend() {
        // beta's option-level depend is `alpha`, but for `backup` the
        // depend is overridden to `gamma`. Set alpha and beta but NOT gamma:
        // the per-command override should fire and reject beta.
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  alpha:
    type: string
    command:
      backup: {}
  gamma:
    type: string
    command:
      backup: {}
  beta:
    type: string
    depend: alpha
    command:
      backup:
        depend: gamma
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--alpha=a", "--beta=b"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let err = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap_err();
        match err {
            LoadError::DependNotSatisfied {
                option, depend_option, ..
            } => {
                assert_eq!(option, "beta");
                assert_eq!(depend_option, "gamma");
            }
            other => panic!("expected DependNotSatisfied(gamma), got {other:?}"),
        }
    }
}
