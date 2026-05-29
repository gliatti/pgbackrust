//! Merge CLI input + `PGBACKREST_<OPTION>` env vars + `pgbackrest.conf` +
//! option defaults into a final [`LoadedConfig`].
//!
//! Precedence, highest to lowest:
//!
//! 1. Explicit CLI argument (`--option=value`).
//! 2. `PGBACKREST_<OPTION>` environment variable (see [`crate::env`]).
//! 3. `[<stanza>:<command>]` section in the INI file.
//! 4. `[<stanza>]` section.
//! 5. `[global:<command>]` section.
//! 6. `[global]` section.
//! 7. Per-command override default (`option.<name>.command.<command>.default`).
//! 8. Option default (`option.<name>.default`).
//!
//! `--reset-X` wipes the value at every level above defaults (env included);
//! the option still gets its default applied.
//!
//! Indexed groups (`pg`, `repo`): the merge auto-discovers which group
//! indices are configured by scanning for `<prefix><N>-` keys across every
//! section, plus any indices that appear in the CLI input or the env map.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use crate::cli::ResolvedCli;
use crate::compile::Cfg;
use crate::ini::{IniFile, IniSection};
use crate::option::CfgOption;
use crate::types::{ConfigCommandRole, DefaultType, OptionGroup, OptionType};
use crate::value::{OptionValue, ValueError, parse_value};

/// Raw `PGBACKREST_<OPTION>` env values keyed by `(option_name, group_index)`,
/// as produced by [`crate::env::collect_env`]. Slotted into the merge between
/// the CLI and the INI file.
pub type EnvValues = BTreeMap<(String, Option<u32>), String>;

/// The `default:` tag (used with `default-type: dynamic`) whose value is the
/// running executable's path — i.e. `argv[0]`. In `config.yaml` the `cmd`,
/// `pg-host-cmd`, and `repo-host-cmd` options all carry `default: bin`.
const DYNAMIC_TAG_BIN: &str = "bin";

/// Fallback used for the `bin` dynamic default when the [`RuntimeContext`]
/// doesn't carry an executable path.
const DYNAMIC_BIN_FALLBACK: &str = "pgbackrest";

/// The option whose resolved value selects the "flavor" entry of a per-flavor
/// sequence default (e.g. `compress-level`'s `[{gz: 6}, {zst: 3}, …]` is keyed
/// by the value of `compress-type`).
const FLAVOR_SOURCE_OPTION: &str = "compress-type";

/// Flavor used when [`FLAVOR_SOURCE_OPTION`] has no resolved value. Matches
/// `compress-type`'s own scalar default in `config.yaml`.
const FLAVOR_DEFAULT: &str = "gz";

/// Runtime values that feed dynamic default resolution.
///
/// `default-type: dynamic` options carry a tag (e.g. `bin`) instead of a
/// literal default; the real value is computed from the running process. This
/// struct threads those runtime inputs into [`load_config_with_context`].
/// Fields beyond `exe_path` (e.g. a resolved `PostgreSQL` version) can be
/// added here as more dynamic tags are implemented.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeContext {
    /// Path of the running pgBackRest executable (`argv[0]`). Used by the
    /// `bin` dynamic default. `None` falls back to `"pgbackrest"`.
    pub exe_path: Option<String>,
}

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
/// compiled [`Cfg`] into a final [`LoadedConfig`], using a default
/// [`RuntimeContext`].
///
/// This is a thin wrapper over [`load_config_with_context`] retained so
/// existing callers (e.g. `pgbr-cli`) compile unchanged. Dynamic defaults
/// that need runtime inputs (the `bin` executable path) fall back to their
/// documented defaults when called this way.
///
/// # Errors
///
/// Returns [`LoadError`] when an INI value fails to parse, when a required
/// option is missing, or when an INI section references an unknown option
/// key (typo / dropped option).
pub fn load_config(cli: ResolvedCli, ini: &IniFile, cfg: &Cfg) -> Result<LoadedConfig, LoadError> {
    load_config_with_context(cli, ini, cfg, &RuntimeContext::default())
}

/// Merge a [`ResolvedCli`], an [`IniFile`], and the defaults from a
/// compiled [`Cfg`] into a final [`LoadedConfig`], resolving dynamic and
/// per-flavor defaults using `ctx`.
///
/// Resolution runs in two passes so that flavor-dependent defaults (e.g.
/// `compress-level`, whose default depends on the resolved `compress-type`)
/// can read the value of their flavor-source option after it has been
/// resolved:
///
/// 1. Every option whose default is *not* a per-flavor sequence is resolved.
/// 2. Per-flavor sequence defaults are resolved against the now-populated
///    options map (the flavor source falls back to [`FLAVOR_DEFAULT`] when
///    unset).
///
/// # Errors
///
/// Returns [`LoadError`] when an INI value fails to parse, when a required
/// option is missing, or when an INI section references an unknown option
/// key (typo / dropped option).
pub fn load_config_with_context(
    cli: ResolvedCli,
    ini: &IniFile,
    cfg: &Cfg,
    ctx: &RuntimeContext,
) -> Result<LoadedConfig, LoadError> {
    load_config_with_env(cli, &EnvValues::new(), ini, cfg, ctx)
}

/// Merge a [`ResolvedCli`], the `PGBACKREST_<OPTION>` environment values
/// (`env`), an [`IniFile`], and the defaults from a compiled [`Cfg`] into a
/// final [`LoadedConfig`].
///
/// This is the full five-source entry point. The env values sit between the
/// CLI and the INI file in precedence (CLI > ENV > stanza:cmd > stanza >
/// global:cmd > global > default). `env` holds raw strings keyed by
/// `(option_name, group_index)` (build it with [`crate::env::collect_env`] /
/// [`crate::env::env_values_from_process`]); each value is parsed via
/// [`crate::value::parse_value`] exactly like an INI value. Pass an empty map
/// to disable the env source — [`load_config_with_context`] and [`load_config`]
/// do precisely that for backward compatibility.
///
/// # Errors
///
/// Returns [`LoadError`] when a CLI / env / INI value fails to parse, when a
/// required option is missing, or when validation (allow-list, allow-range,
/// depend) fails.
pub fn load_config_with_env(
    cli: ResolvedCli,
    env: &EnvValues,
    ini: &IniFile,
    cfg: &Cfg,
    ctx: &RuntimeContext,
) -> Result<LoadedConfig, LoadError> {
    load_config_with_env_multi(cli, env, std::slice::from_ref(ini), cfg, ctx)
}

/// Merge a [`ResolvedCli`], the `PGBACKREST_<OPTION>` environment values
/// (`env`), an ordered slice of [`IniFile`] config sources, and the defaults
/// from a compiled [`Cfg`] into a final [`LoadedConfig`].
///
/// This is the multi-source variant of [`load_config_with_env`]. pgBackRest
/// reads the main `--config` file plus every `*.conf` under
/// `--config-include-path`, treating them all as the same "config file"
/// precedence level (below the CLI and env, above defaults). The slice is
/// applied **in load order**: the main config first, then the include files
/// (sorted by name). When two sources set the same key in the same INI
/// section, a *later* source wins — matching pgBackRest, where include files
/// are loaded after the main config and override it.
///
/// The five-source precedence is therefore CLI, then ENV, then the combined
/// config files, then defaults; the combined config files themselves resolve by
/// section (`stanza:cmd`, `stanza`, `global:cmd`, `global`, in that order)
/// exactly as the single-file path does. The single-file
/// [`load_config_with_env`] is a thin wrapper over this (a one-element slice),
/// so all existing behaviour is preserved.
///
/// # Errors
///
/// Returns [`LoadError`] when a CLI / env / INI value fails to parse, when a
/// required option is missing, or when validation (allow-list, allow-range,
/// depend) fails.
pub fn load_config_with_env_multi(
    cli: ResolvedCli,
    env: &EnvValues,
    inis: &[IniFile],
    cfg: &Cfg,
    ctx: &RuntimeContext,
) -> Result<LoadedConfig, LoadError> {
    let combined = merge_ini_files(inis);
    load_config_with_env_single(cli, env, &combined, cfg, ctx)
}

/// Collapse an ordered slice of [`IniFile`] config sources into one combined
/// [`IniFile`], applying later sources over earlier ones at the
/// `(section, key)` granularity.
///
/// This is how pgBackRest layers its config files: the main `--config` file is
/// loaded first, then each `*.conf` under the include path (sorted by name);
/// a later file's value for the same key in the same section overrides the
/// earlier one. A single-element slice returns that file unchanged, so the
/// single-file path is a no-op pass-through.
fn merge_ini_files(inis: &[IniFile]) -> IniFile {
    // Fast path: the overwhelmingly common single-file case clones the one
    // file as-is (no per-key churn).
    if let [only] = inis {
        return only.clone();
    }
    let mut combined = IniFile::default();
    for ini in inis {
        for (section, values) in &ini.sections {
            let entry = combined.sections.entry(section.clone()).or_default();
            for (key, value) in values {
                // Later file wins for the same (section, key).
                entry.insert(key.clone(), value.clone());
            }
        }
    }
    combined
}

/// The original single-`IniFile` merge body, now reached through
/// [`load_config_with_env`] / [`load_config_with_env_multi`] after the
/// config sources have been collapsed into one [`IniFile`].
fn load_config_with_env_single(
    cli: ResolvedCli,
    env: &EnvValues,
    ini: &IniFile,
    cfg: &Cfg,
    ctx: &RuntimeContext,
) -> Result<LoadedConfig, LoadError> {
    let stanza = extract_stanza(&cli);
    let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();

    // Discover indices for each grouped option from CLI + env + every INI
    // section by scanning the raw keys.
    let group_indices = discover_group_indices(&cli, env, ini, cfg);

    // Per-flavor sequence defaults are deferred to a second pass so the
    // flavor-source option (e.g. `compress-type`) is already resolved when
    // their default is selected. Each entry records the data needed to finish
    // the default later.
    let mut deferred_flavor: Vec<DeferredFlavorDefault> = Vec::new();

    // Keys whose value came from an explicit source (CLI or INI), as opposed to
    // a default. The depend pass gates on this: an option with an unsatisfied
    // `depend:` is silently dropped when it was only defaulted (the option is
    // inactive), but is an error when the user set it explicitly.
    let mut explicit: BTreeSet<(String, Option<u32>)> = BTreeSet::new();

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
            // Env sits below the CLI but above the INI file; reset wipes it too.
            let env_value = if resetted {
                None
            } else {
                lookup_env(name, idx, env, opt.option_type)?
            };
            let ini_value = if resetted {
                None
            } else {
                lookup_ini(name, idx, opt, ini, &cli, opt.option_type, stanza.as_deref())?
            };
            // Whether the value (if any) comes from an explicit source rather
            // than a default — drives depend gating below.
            let is_explicit = cli_value.is_some() || env_value.is_some() || ini_value.is_some();
            // A per-flavor sequence default is deferred to pass two so the
            // flavor source is resolved first; everything else resolves now.
            let mut deferred = false;
            let final_value = if let Some(v) = cli_value {
                Some(v)
            } else if let Some(v) = env_value {
                Some(v)
            } else if let Some(v) = ini_value {
                Some(v)
            } else if let Some(seq) = flavor_sequence_default(opt, usage) {
                deferred_flavor.push(DeferredFlavorDefault {
                    key: key.clone(),
                    sequence: seq,
                });
                deferred = true;
                None
            } else {
                resolve_default(opt, usage, name, idx, ctx)?
            };

            if let Some(value) = final_value {
                validate_value(&value, opt, usage, name, idx)?;
                if is_explicit {
                    explicit.insert(key.clone());
                }
                options.insert(key, value);
            } else if !deferred && opt.required && (usage.required != Some(false)) {
                // A deferred flavor default isn't "missing" yet — pass two
                // will fill it. Only error for genuinely unresolved options.
                return Err(LoadError::Required {
                    option: name.clone(),
                    group_index: idx,
                });
            }
        }
    }

    // Pass two: resolve per-flavor sequence defaults against the resolved
    // flavor-source value.
    for deferred in &deferred_flavor {
        let (name, idx) = &deferred.key;
        let Some(opt) = cfg.options.get(name) else {
            continue;
        };
        let usage = &opt.commands[&cli.command];
        let flavor = resolved_flavor(&options);
        if let Some(value) = pick_flavor_default(&deferred.sequence, &flavor, opt.option_type, name, *idx)? {
            validate_value(&value, opt, usage, name, *idx)?;
            options.insert(deferred.key.clone(), value);
        } else if opt.required && (usage.required != Some(false)) {
            return Err(LoadError::Required {
                option: name.clone(),
                group_index: *idx,
            });
        }
    }

    apply_depends(&mut options, &explicit, cfg, &cli.command)?;

    Ok(LoadedConfig {
        command: cli.command,
        command_role: cli.command_role,
        stanza,
        options,
        params: cli.params,
    })
}

/// A per-flavor sequence default whose resolution is deferred to pass two.
struct DeferredFlavorDefault {
    key: (String, Option<u32>),
    sequence: Vec<serde_yml::Value>,
}

fn extract_stanza(cli: &ResolvedCli) -> Option<String> {
    cli.options.get(&("stanza".to_owned(), None)).and_then(|v| match v {
        OptionValue::String(s) => Some(s.clone()),
        _ => None,
    })
}

fn discover_group_indices(cli: &ResolvedCli, env: &EnvValues, ini: &IniFile, cfg: &Cfg) -> BTreeMap<String, BTreeSet<u32>> {
    let mut out: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();

    for (name, idx) in cli.options.keys().chain(cli.resets.iter()) {
        if let Some(i) = idx {
            out.entry(name.clone()).or_default().insert(*i);
        }
    }

    // Env values are already decoded to `(option_name, group_index)` keys.
    for (name, idx) in env.keys() {
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

    // Propagate indices across every option in the same `OptionGroup`. Naming
    // `pg2-host` in the INI must materialise the whole `pg` group at index 2
    // — including `pg-local`, whose hardcoded default `false` then satisfies
    // the `pg-host` depend without any explicit `pg2-local=…` key. Without
    // this, the resolution loop only iterated `pg-local` over indices seen
    // directly for `pg-local`, leaving `pg-local` materialised only at the
    // empty-set-fallback index 1 and causing `depend: pg-local` checks at
    // index >= 2 to fire on an `unset` value.
    let mut by_group: HashMap<OptionGroup, BTreeSet<u32>> = HashMap::new();
    for (name, indices) in &out {
        if let Some(opt) = cfg.options.get(name)
            && let Some(group) = opt.group
        {
            by_group.entry(group).or_default().extend(indices.iter().copied());
        }
    }
    for (name, opt) in &cfg.options {
        let Some(group) = opt.group else { continue };
        let Some(group_indices) = by_group.get(&group) else {
            continue;
        };
        if group_indices.is_empty() {
            continue;
        }
        out.entry(name.clone()).or_default().extend(group_indices.iter().copied());
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

/// Resolve the `PGBACKREST_<OPTION>` env value for `(option_name, group_index)`
/// from the pre-collected `env` map, parsing the raw string as `option_type`
/// (just like [`lookup_ini`]). Returns `None` when no env var was set for this
/// key.
fn lookup_env(
    option_name: &str,
    group_index: Option<u32>,
    env: &EnvValues,
    option_type: OptionType,
) -> Result<Option<OptionValue>, LoadError> {
    let Some(raw) = env.get(&(option_name.to_owned(), group_index)) else {
        return Ok(None);
    };
    let value = parse_value(option_type, raw).map_err(|error| LoadError::ValueParse {
        option: option_name.to_owned(),
        group_index,
        error,
    })?;
    Ok(Some(value))
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
            && !allow_list_contains(opt.option_type, &allowed_strs, value, &value_str)
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

/// Whether `value` is permitted by the option's allow-list. For `size`/`time`
/// options the allow-list entries are human-readable strings (`"1MiB"` / `"1m"`)
/// while the resolved value is a canonical byte/millisecond count, so both sides
/// are parsed into integers and compared numerically. Every other type compares
/// the canonical string form (`value_str`) directly.
fn allow_list_contains(option_type: OptionType, allowed_strs: &[String], value: &OptionValue, value_str: &str) -> bool {
    match (option_type, value) {
        (OptionType::Size | OptionType::Time, OptionValue::Size(n) | OptionValue::Time(n)) => allowed_strs
            .iter()
            .filter_map(|s| match parse_value(option_type, s) {
                Ok(OptionValue::Size(a) | OptionValue::Time(a)) => Some(a),
                _ => None,
            })
            .any(|a| a == *n),
        _ => allowed_strs.iter().any(|a| a == value_str),
    }
}

fn value_to_match_str(v: &serde_yml::Value) -> Option<String> {
    match v {
        serde_yml::Value::String(s) => Some(s.clone()),
        serde_yml::Value::Bool(b) => Some(b.to_string()),
        serde_yml::Value::Number(n) => Some(n.to_string()),
        // A compile-time-feature-gated allow-list entry is a single-key mapping
        // `{value: FEATURE_FLAG}` — e.g. `{zst: HAVE_LIBZST}` in config.yaml,
        // mirroring pgBackRest's `#ifdef HAVE_LIBZST`. This build links every
        // optional codec (zstd, lz4, bz2, …) unconditionally, so the gate is
        // always satisfied: take the key as the permitted value.
        serde_yml::Value::Mapping(m) if m.len() == 1 => m.iter().next().and_then(|(k, _)| k.as_str().map(ToOwned::to_owned)),
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

/// Gate options on their `depend:` constraint.
///
/// An option whose dependency is not satisfied is *inactive*: if its value was
/// only a default it is silently dropped (matching pgBackRest, where e.g.
/// `repo-azure-*` defaults never apply unless `repo-type=azure`); if the user
/// set it *explicitly* (CLI/INI) it is a [`LoadError::DependNotSatisfied`].
/// Options whose dependency is satisfied (or that have no `depend:`) are kept.
fn apply_depends(
    options: &mut BTreeMap<(String, Option<u32>), OptionValue>,
    explicit: &BTreeSet<(String, Option<u32>)>,
    cfg: &Cfg,
    command: &str,
) -> Result<(), LoadError> {
    // Collect first (can't mutate `options` while iterating its keys).
    let mut drop_keys: Vec<(String, Option<u32>)> = Vec::new();

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

        // Determine whether the dependency is satisfied. Bare `depend: <name>`
        // is satisfied by any value; a listed depend needs the value in the list.
        let satisfied = dep_value.is_some_and(|v| {
            depend.list.is_none() || {
                let candidates = option_value_match_candidates(v);
                candidates.iter().any(|c| depend_list_strs.iter().any(|d| d == c))
            }
        });
        if satisfied {
            continue;
        }

        // `depend: {..., default: x}` tolerates an unsatisfied dependency: the
        // option keeps its value rather than erroring or being dropped.
        // (Type-aware substitution of `depend.default` is a future refinement.)
        if depend.default.is_some() {
            continue;
        }

        let key = (name.clone(), *idx);
        if explicit.contains(&key) {
            // The user set this explicitly but the dependency isn't met → error.
            let depend_value = dep_value.map_or_else(
                || "unset".to_owned(),
                |v| {
                    option_value_match_candidates(v)
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "<opaque>".to_owned())
                },
            );
            return Err(LoadError::DependNotSatisfied {
                option: name.clone(),
                group_index: *idx,
                depend_option: depend.option.clone(),
                depend_value,
                depend_list: depend_list_strs,
            });
        }
        // Defaulted value with an unsatisfied dependency → the option is
        // inactive; drop it. (`depend.default` substitution stays a future
        // refinement; for now an inactive option simply has no value.)
        drop_keys.push(key);
    }

    for key in drop_keys {
        options.remove(&key);
    }
    Ok(())
}

fn resolve_default(
    opt: &CfgOption,
    usage: &crate::option::ResolvedCommandUsage,
    option_name: &str,
    group_index: Option<u32>,
    ctx: &RuntimeContext,
) -> Result<Option<OptionValue>, LoadError> {
    // Per-command default first, then option-level default.
    let raw = usage.default.as_ref().or(opt.default.as_ref());
    let Some(raw) = raw else {
        return Ok(None);
    };

    // `default-type: dynamic`: the `default:` holds a tag naming a runtime
    // value, not a literal. Resolve recognised tags from the context.
    if opt.default_type == Some(DefaultType::Dynamic) {
        return Ok(resolve_dynamic_default(raw, ctx));
    }

    // Only handle scalar defaults here. Per-flavor sequence defaults are
    // resolved by the caller's second pass (see `flavor_sequence_default` /
    // `pick_flavor_default`).
    let scalar = match raw {
        serde_yml::Value::String(s) => s.clone(),
        serde_yml::Value::Bool(b) => b.to_string(),
        serde_yml::Value::Number(n) => n.to_string(),
        // Per-flavor sequences and other shapes leave the option without a
        // resolved default. The caller can still set one explicitly.
        _ => return Ok(None),
    };

    // `default-type: literal` defaults are C string-concatenation expressions
    // that the deleted C generator used to expand (e.g.
    // `CFGOPTDEF_CONFIG_PATH "/" PROJECT_CONFIG_FILE`). Expand them here so the
    // resolved value is a concrete string rather than raw C-macro text.
    let scalar = if opt.default_type == Some(DefaultType::Literal) {
        expand_literal_default(&scalar)
    } else {
        scalar
    };

    let value = parse_value(opt.option_type, &scalar).map_err(|error| LoadError::ValueParse {
        option: option_name.to_owned(),
        group_index,
        error,
    })?;
    Ok(Some(value))
}

/// Resolve a C preprocessor identifier used in a `default-type: literal`
/// default to its string value. The C build generator expanded these when it
/// emitted the auto files; the Rust pipeline reads the raw `config.yaml`, so
/// the expansion happens here. Values mirror pgBackRest's `PROJECT_CONFIG_*`
/// (`src/version.h`) and the `CFGOPTDEF_CONFIG_PATH` define.
fn literal_macro_value(ident: &str) -> Option<&'static str> {
    match ident {
        "CFGOPTDEF_CONFIG_PATH" => Some("/etc/pgbackrest"),
        "PROJECT_CONFIG_FILE" => Some("pgbackrest.conf"),
        "PROJECT_CONFIG_INCLUDE_PATH" => Some("conf.d"),
        _ => None,
    }
}

/// Expand a `default-type: literal` default — a C string-concatenation
/// expression of whitespace-separated tokens, each either a `"..."` string
/// literal (taken verbatim, without the quotes) or a macro identifier resolved
/// via [`literal_macro_value`]. Unknown identifiers are kept verbatim so a
/// missing macro surfaces as a visible (and typically invalid) value rather
/// than silent corruption.
fn expand_literal_default(raw: &str) -> String {
    let mut out = String::new();
    for token in raw.split_whitespace() {
        if let Some(inner) = token.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            out.push_str(inner);
        } else if let Some(val) = literal_macro_value(token) {
            out.push_str(val);
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Resolve a `default-type: dynamic` default. The `bin` tag yields the
/// executable path from `ctx` (falling back to [`DYNAMIC_BIN_FALLBACK`]).
/// Unrecognised tags stay unresolved (returning `None`) rather than erroring,
/// so new dynamic tags can be added incrementally.
fn resolve_dynamic_default(raw: &serde_yml::Value, ctx: &RuntimeContext) -> Option<OptionValue> {
    let serde_yml::Value::String(tag) = raw else {
        // TODO: non-string dynamic tags (none exist in config.yaml today).
        return None;
    };
    match tag.as_str() {
        DYNAMIC_TAG_BIN => Some(OptionValue::String(
            ctx.exe_path.clone().unwrap_or_else(|| DYNAMIC_BIN_FALLBACK.to_owned()),
        )),
        // TODO: other dynamic tags (e.g. environment- or option-derived
        // defaults) resolve here as they're ported.
        _ => None,
    }
}

/// If `opt`'s default (per-command override first, then option-level) is a
/// per-flavor sequence — a YAML sequence of single-key maps like
/// `[{gz: 6}, {zst: 3}]` — return the sequence so the caller can defer its
/// resolution until the flavor source is known. Returns `None` for any other
/// default shape (including dynamic, handled elsewhere).
fn flavor_sequence_default(opt: &CfgOption, usage: &crate::option::ResolvedCommandUsage) -> Option<Vec<serde_yml::Value>> {
    if opt.default_type == Some(DefaultType::Dynamic) {
        return None;
    }
    let raw = usage.default.as_ref().or(opt.default.as_ref())?;
    let serde_yml::Value::Sequence(items) = raw else {
        return None;
    };
    // Confirm every entry is a single-key map; otherwise it's not a per-flavor
    // sequence and we leave it to the existing (scalar-only) path.
    if items.is_empty()
        || !items
            .iter()
            .all(|item| matches!(item, serde_yml::Value::Mapping(m) if m.len() == 1))
    {
        return None;
    }
    Some(items.clone())
}

/// The current flavor used to select a per-flavor default — the resolved
/// value of [`FLAVOR_SOURCE_OPTION`] (`compress-type`), or [`FLAVOR_DEFAULT`]
/// when it isn't set.
fn resolved_flavor(options: &BTreeMap<(String, Option<u32>), OptionValue>) -> String {
    options
        .get(&(FLAVOR_SOURCE_OPTION.to_owned(), None))
        .and_then(option_value_to_match_str)
        .unwrap_or_else(|| FLAVOR_DEFAULT.to_owned())
}

/// Pick the entry of a per-flavor sequence whose single key matches `flavor`
/// and parse its value as `option_type`. Returns `None` when no entry matches.
fn pick_flavor_default(
    sequence: &[serde_yml::Value],
    flavor: &str,
    option_type: OptionType,
    option_name: &str,
    group_index: Option<u32>,
) -> Result<Option<OptionValue>, LoadError> {
    for item in sequence {
        let serde_yml::Value::Mapping(map) = item else {
            continue;
        };
        let Some((key, value)) = map.iter().next() else {
            continue;
        };
        let key_matches = match key {
            serde_yml::Value::String(s) => s == flavor,
            _ => false,
        };
        if !key_matches {
            continue;
        }
        let scalar = match value {
            serde_yml::Value::String(s) => s.clone(),
            serde_yml::Value::Bool(b) => b.to_string(),
            serde_yml::Value::Number(n) => n.to_string(),
            _ => return Ok(None),
        };
        let parsed = parse_value(option_type, &scalar).map_err(|error| LoadError::ValueParse {
            option: option_name.to_owned(),
            group_index,
            error,
        })?;
        return Ok(Some(parsed));
    }
    Ok(None)
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

    /// Like [`load`] but threads a `PGBACKREST_<OPTION>` environment through an
    /// injected lookup, exercising the full five-source merge.
    fn load_with_env(cli_args: &[&str], env: &[(&str, &str)], ini_text: &str) -> Result<LoadedConfig, String> {
        let cfg = small_cfg();
        let cli = parse_cli(cli_args.iter().map(|s| (*s).to_owned())).map_err(|e| e.to_string())?;
        let resolved = resolve_cli(cli, &cfg).map_err(|e| e.to_string())?;
        let ini = crate::ini::parse_ini(ini_text).map_err(|e| e.to_string())?;
        let env_map: BTreeMap<&str, &str> = env.iter().copied().collect();
        let env_values = crate::env::collect_env(&cfg, |name| env_map.get(name).map(|v| (*v).to_owned()));
        load_config_with_env(resolved, &env_values, &ini, &cfg, &RuntimeContext::default()).map_err(|e| e.to_string())
    }

    /// Like [`load`] but takes several INI texts (in load order) and merges them
    /// through the multi-source entry point, mirroring how `pgbr-cli` layers the
    /// main `--config` file with the `*.conf` include files.
    fn load_multi(cli_args: &[&str], ini_texts: &[&str]) -> Result<LoadedConfig, String> {
        let cfg = small_cfg();
        let cli = parse_cli(cli_args.iter().map(|s| (*s).to_owned())).map_err(|e| e.to_string())?;
        let resolved = resolve_cli(cli, &cfg).map_err(|e| e.to_string())?;
        let inis: Vec<IniFile> = ini_texts
            .iter()
            .map(|t| crate::ini::parse_ini(t).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        load_config_with_env_multi(resolved, &EnvValues::new(), &inis, &cfg, &RuntimeContext::default()).map_err(|e| e.to_string())
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

    #[test]
    fn defaulted_option_with_unsatisfied_depend_is_dropped_not_errored() {
        // `extra` has a default AND depends on `kind` being `special`. With
        // `kind` left at its `normal` default, `extra` is inactive: its default
        // must NOT apply and must NOT raise DependNotSatisfied (mirrors
        // config.yaml's cloud options like repo-azure-* under repo-type=posix).
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  kind:
    type: string-id
    default: normal
    command:
      backup: {}
  extra:
    type: string
    default: fallback
    depend:
      option: kind
      list:
        - special
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let loaded = load_config(resolved, &crate::ini::IniFile::default(), &cfg)
            .expect("a defaulted option with an unsatisfied depend must not error");
        assert!(
            !loaded.options.contains_key(&("extra".to_owned(), None)),
            "inactive defaulted option must be dropped from the resolved set"
        );
    }

    #[test]
    fn literal_default_expands_c_macro_expressions() {
        assert_eq!(expand_literal_default("CFGOPTDEF_CONFIG_PATH"), "/etc/pgbackrest");
        assert_eq!(
            expand_literal_default("CFGOPTDEF_CONFIG_PATH \"/\" PROJECT_CONFIG_FILE"),
            "/etc/pgbackrest/pgbackrest.conf"
        );
        assert_eq!(
            expand_literal_default("CFGOPTDEF_CONFIG_PATH \"/\" PROJECT_CONFIG_INCLUDE_PATH"),
            "/etc/pgbackrest/conf.d"
        );
    }

    #[test]
    fn real_config_info_resolves_end_to_end() {
        // Guards the two binary-blocking bugs: literal-macro defaults
        // (`config-path` etc.) and depend-gating on cloud-option defaults.
        // `pgbackrest info --stanza=demo --repo1-path=/tmp/x` must fully resolve.
        let parsed = pgbr_build::parse_config(pgbr_build::inputs::CONFIG_YAML).unwrap();
        let cfg = crate::compile::compile(&parsed).unwrap();
        let cli = parse_cli(["info", "--stanza=demo", "--repo1-path=/tmp/x"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let loaded =
            load_config(resolved, &crate::ini::IniFile::default(), &cfg).expect("info must resolve against the real config.yaml");
        // No resolved value may carry unexpanded C-macro text (the literal-default bug).
        for ((name, _), value) in &loaded.options {
            if let OptionValue::Path(s) | OptionValue::String(s) | OptionValue::StringId(s) = value {
                assert!(
                    !s.contains("CFGOPTDEF") && !s.contains("PROJECT_"),
                    "option `{name}` has an unexpanded literal default: {s:?}"
                );
            }
        }
    }

    // ---- dynamic and per-flavor defaults -----------------------------------

    /// Config with a `default-type: dynamic` option (`cmd`, like config.yaml's
    /// real `cmd`/`*-host-cmd` options) whose `default:` is the `bin` tag.
    fn dynamic_cfg() -> Cfg {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  cmd:
    type: string
    default-type: dynamic
    default: bin
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        crate::compile::compile(&parse_config(yaml).unwrap()).unwrap()
    }

    /// Config mirroring `compress-level`'s per-flavor sequence default keyed by
    /// `compress-type`.
    fn flavor_cfg() -> Cfg {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  compress-type:
    type: string-id
    default: gz
    command:
      backup: {}
  compress-level:
    type: integer
    required: false
    default:
      - gz: 6
      - zst: 3
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        crate::compile::compile(&parse_config(yaml).unwrap()).unwrap()
    }

    #[test]
    fn dynamic_bin_default_uses_exe_path() {
        let cfg = dynamic_cfg();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let ctx = RuntimeContext {
            exe_path: Some("/usr/bin/pgbackrest".to_owned()),
        };
        let r = load_config_with_context(resolved, &crate::ini::IniFile::default(), &cfg, &ctx).unwrap();
        assert_eq!(
            r.options[&("cmd".into(), None)],
            OptionValue::String("/usr/bin/pgbackrest".into())
        );
    }

    #[test]
    fn dynamic_bin_default_falls_back_when_no_exe_path() {
        let cfg = dynamic_cfg();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        // Default context => no exe path => falls back to "pgbackrest".
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("cmd".into(), None)], OptionValue::String("pgbackrest".into()));
    }

    #[test]
    fn dynamic_unknown_tag_stays_unresolved() {
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  weird:
    type: string
    required: false
    default-type: dynamic
    default: not-a-known-tag
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        // Unrecognised dynamic tag => no value, but no error either.
        assert!(!r.options.contains_key(&("weird".into(), None)));
    }

    #[test]
    fn per_flavor_default_picks_matching_compress_type() {
        // compress-type = zst => compress-level default is 3.
        let cfg = flavor_cfg();
        let cli = parse_cli(["backup", "--stanza=demo", "--compress-type=zst"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("compress-level".into(), None)], OptionValue::Integer(3));

        // compress-type = gz => compress-level default is 6.
        let cfg = flavor_cfg();
        let cli = parse_cli(["backup", "--stanza=demo", "--compress-type=gz"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("compress-level".into(), None)], OptionValue::Integer(6));
    }

    #[test]
    fn per_flavor_default_defaults_flavor_when_unset() {
        // No compress-type on the CLI: it resolves to its own default `gz`,
        // so compress-level's flavor falls back to gz => 6.
        let cfg = flavor_cfg();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("compress-type".into(), None)], OptionValue::StringId("gz".into()));
        assert_eq!(r.options[&("compress-level".into(), None)], OptionValue::Integer(6));
    }

    #[test]
    fn per_flavor_default_uses_fallback_when_source_has_no_default() {
        // compress-type here has NO scalar default, so it resolves to nothing;
        // the flavor falls back to the documented `gz` => compress-level = 6.
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  compress-type:
    type: string-id
    required: false
    command:
      backup: {}
  compress-level:
    type: integer
    required: false
    default:
      - gz: 6
      - zst: 3
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert!(!r.options.contains_key(&("compress-type".into(), None)));
        assert_eq!(r.options[&("compress-level".into(), None)], OptionValue::Integer(6));
    }

    #[test]
    fn size_allow_list_matches_default_by_canonical_bytes() {
        // Regression: a `size` option whose default (1MiB) is in the
        // allow-list must validate. The allow-list entries are human strings
        // ("1MiB") while the resolved value is a byte count, so the comparison
        // parses both sides to bytes instead of comparing string forms.
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  buffer-size:
    type: size
    default: 1MiB
    allow-list:
      - 512KiB
      - 1MiB
      - 2MiB
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let r = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(1024 * 1024));
    }

    #[test]
    fn size_allow_list_rejects_value_not_in_list() {
        // A CLI value outside the allow-list still errors after the numeric
        // comparison fix (3MiB is not among 512KiB / 1MiB / 2MiB).
        let yaml = r"
command:
  backup: {}
optionGroup: {}
option:
  buffer-size:
    type: size
    default: 1MiB
    allow-list:
      - 512KiB
      - 1MiB
      - 2MiB
    command:
      backup: {}
  stanza:
    type: string
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo", "--buffer-size=3MiB"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let err = load_config(resolved, &crate::ini::IniFile::default(), &cfg).unwrap_err();
        assert!(matches!(err, LoadError::NotInAllowList { .. }));
    }

    #[test]
    fn load_config_unchanged_for_scalar_defaults() {
        // The original scalar-default path is untouched: buffer-size default
        // 1MiB still applies via plain `load_config`.
        let r = load(&["backup", "--stanza=demo", "--pg1-path=/data"], "").unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(1024 * 1024));
        assert_eq!(
            r.options[&("log-level-file".into(), None)],
            OptionValue::StringId("info".into())
        );
        assert_eq!(
            r.options[&("repo-path".into(), Some(1))],
            OptionValue::Path("/var/lib/pgbackrest".into())
        );
    }

    // ---- PGBACKREST_<OPTION> environment source ----------------------------

    #[test]
    fn env_overrides_ini_and_default() {
        // buffer-size: env beats the [global] INI value; log-level-file: env
        // beats the option default. pg-path comes from the CLI (required).
        let r = load_with_env(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            &[("PGBACKREST_BUFFER_SIZE", "4MiB"), ("PGBACKREST_LOG_LEVEL_FILE", "debug")],
            "[global]\nbuffer-size=2MiB\n",
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(4 * 1024 * 1024));
        assert_eq!(
            r.options[&("log-level-file".into(), None)],
            OptionValue::StringId("debug".into())
        );
    }

    #[test]
    fn cli_overrides_env() {
        // CLI buffer-size wins over the env var, which would otherwise win.
        let r = load_with_env(
            &["backup", "--stanza=demo", "--pg1-path=/data", "--buffer-size=8MiB"],
            &[("PGBACKREST_BUFFER_SIZE", "4MiB")],
            "",
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(8 * 1024 * 1024));
    }

    #[test]
    fn env_grouped_index_and_boolean() {
        // A grouped env var (PGBACKREST_PG1_PATH) decodes to (pg-path, 1), and a
        // boolean env value uses the y/n spelling.
        let r = load_with_env(
            &["backup", "--stanza=demo"],
            &[("PGBACKREST_PG1_PATH", "/env/pg"), ("PGBACKREST_ONLINE", "n")],
            "",
        )
        .unwrap();
        assert_eq!(r.options[&("pg-path".into(), Some(1))], OptionValue::Path("/env/pg".into()));
        assert_eq!(r.options[&("online".into(), None)], OptionValue::Boolean(false));
    }

    #[test]
    fn empty_env_map_matches_plain_load_config() {
        // load_config (empty env) and load_config_with_env (empty env) agree.
        let plain = load(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            "[global]\nbuffer-size=2MiB\n",
        )
        .unwrap();
        let with_empty_env = load_with_env(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            &[],
            "[global]\nbuffer-size=2MiB\n",
        )
        .unwrap();
        assert_eq!(plain, with_empty_env);
    }

    // ---- multi-source (config-include-path) config files -------------------

    #[test]
    fn single_element_slice_matches_single_file() {
        // A one-element slice through the multi-source path must produce exactly
        // the same result as the single-file path (the `pgbr-cli` invariant when
        // no include files exist).
        let single = load(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            "[global]\nbuffer-size=2MiB\n",
        )
        .unwrap();
        let multi = load_multi(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            &["[global]\nbuffer-size=2MiB\n"],
        )
        .unwrap();
        assert_eq!(single, multi);
    }

    #[test]
    fn later_include_file_overrides_earlier_for_same_key() {
        // The main config sets buffer-size=2MiB; a later include file sets it to
        // 8MiB in the same [global] section. The later source wins (pgBackRest
        // loads include files after the main config).
        let r = load_multi(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            &["[global]\nbuffer-size=2MiB\n", "[global]\nbuffer-size=8MiB\n"],
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(8 * 1024 * 1024));
    }

    #[test]
    fn include_files_extend_main_config() {
        // The main config sets buffer-size; a later include file sets a
        // different key (log-level-file) in the same section. Both values
        // survive — the include file extends rather than wholesale-replaces.
        let r = load_multi(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            &["[global]\nbuffer-size=4MiB\n", "[global]\nlog-level-file=debug\n"],
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(4 * 1024 * 1024));
        assert_eq!(
            r.options[&("log-level-file".into(), None)],
            OptionValue::StringId("debug".into())
        );
    }

    #[test]
    fn include_file_order_is_significant() {
        // Three include files all set buffer-size; the last one in the slice
        // wins regardless of value magnitude (later = higher precedence).
        let r = load_multi(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            &[
                "[global]\nbuffer-size=1MiB\n",
                "[global]\nbuffer-size=8MiB\n",
                "[global]\nbuffer-size=2MiB\n",
            ],
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(2 * 1024 * 1024));
    }

    #[test]
    fn cli_still_overrides_combined_include_files() {
        // CLI sits above every config file: even when an include file sets
        // buffer-size, an explicit CLI value wins.
        let r = load_multi(
            &["backup", "--stanza=demo", "--pg1-path=/data", "--buffer-size=4MiB"],
            &["[global]\nbuffer-size=1MiB\n", "[global]\nbuffer-size=8MiB\n"],
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(4 * 1024 * 1024));
    }

    #[test]
    fn empty_slice_resolves_with_only_defaults() {
        // No config files at all (the "missing main config + missing include
        // dir" case `pgbr-cli` never actually hits, but the merge must tolerate)
        // resolves purely from CLI + defaults.
        let r = load_multi(&["backup", "--stanza=demo", "--pg1-path=/data"], &[]).unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(1024 * 1024));
    }

    #[test]
    fn section_precedence_preserved_across_merged_files() {
        // A later include file's [global] value does NOT beat an earlier file's
        // more-specific [demo:backup] value: section precedence (stanza:cmd >
        // global) still wins after the files are combined.
        let r = load_multi(
            &["backup", "--stanza=demo", "--pg1-path=/data"],
            &["[demo:backup]\nbuffer-size=8MiB\n", "[global]\nbuffer-size=2MiB\n"],
        )
        .unwrap();
        assert_eq!(r.options[&("buffer-size".into(), None)], OptionValue::Size(8 * 1024 * 1024));
    }

    #[test]
    fn merge_ini_files_single_element_is_passthrough() {
        // The merge helper returns a single-element slice's file unchanged.
        let ini = crate::ini::parse_ini("[global]\nbuffer-size=2MiB\n").unwrap();
        let combined = merge_ini_files(std::slice::from_ref(&ini));
        assert_eq!(combined, ini);
    }

    /// Regression for the `pg2-host` depend bug: naming any option in a group
    /// at index N must instantiate the whole group at N, so that defaulted
    /// siblings (`pg-local` here) materialise at the same index and satisfy
    /// `depend:` constraints. Before the fix, only the option explicitly
    /// scraped from the INI received index N — `pg-local` was only filled in
    /// at the empty-set fallback index 1, leaving `(pg-local, Some(2))` as
    /// `None` and the `pg-host` depend tripping on an `unset` value at >= 2.
    #[test]
    fn grouped_depend_satisfied_at_index_ge_2_via_default() {
        let yaml = r"
command:
  backup: {}
optionGroup:
  pg: {}
  repo: {}
option:
  pg-local:
    type: boolean
    group: pg
    default: false
    negate: true
    command:
      backup: {}
  pg-host:
    type: string
    group: pg
    depend:
      option: pg-local
      list: [false]
    command:
      backup: {}
  repo-local:
    type: boolean
    group: repo
    default: false
    negate: true
    command:
      backup: {}
  repo-host:
    type: string
    group: repo
    depend:
      option: repo-local
      list: [false]
    command:
      backup: {}
  stanza:
    type: string
    required: true
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        // ONLY `pg2-host` (and `repo2-host`) appear in the INI; nothing else
        // pins index 2 for `pg-local` / `repo-local`. The propagation pass in
        // `discover_group_indices` must instantiate the rest of the group at
        // index 2 so the depend defaults satisfy.
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let ini = crate::ini::parse_ini("[demo]\npg2-host=secondaire\nrepo2-host=archive\n").unwrap();
        let r = load_config(resolved, &ini, &cfg).unwrap();

        // The explicit pg2-host value is preserved at (pg-host, Some(2)).
        assert_eq!(
            r.options[&("pg-host".into(), Some(2))],
            OptionValue::String("secondaire".into())
        );
        // The defaulted pg-local materialises at the SAME index — that is the
        // entire point of the fix — and carries its `false` default.
        assert_eq!(r.options[&("pg-local".into(), Some(2))], OptionValue::Boolean(false));
        // Symmetric for the `repo` group.
        assert_eq!(
            r.options[&("repo-host".into(), Some(2))],
            OptionValue::String("archive".into())
        );
        assert_eq!(r.options[&("repo-local".into(), Some(2))], OptionValue::Boolean(false));
    }

    /// Negative regression: the group-index propagation must NOT silently
    /// swallow legitimate depend failures. When the user explicitly sets
    /// `pg2-local=true` *and* `pg2-host=…`, the depend `pg-local in [false]`
    /// is genuinely unsatisfied at index 2 and must still raise
    /// `DependNotSatisfied` — exactly as it would at index 1.
    #[test]
    fn grouped_depend_still_fires_when_local_explicit_true() {
        let yaml = r"
command:
  backup: {}
optionGroup:
  pg: {}
option:
  pg-local:
    type: boolean
    group: pg
    default: false
    negate: true
    command:
      backup: {}
  pg-host:
    type: string
    group: pg
    depend:
      option: pg-local
      list: [false]
    command:
      backup: {}
  stanza:
    type: string
    required: true
    command:
      backup: {}
";
        let cfg = crate::compile::compile(&parse_config(yaml).unwrap()).unwrap();
        let cli = parse_cli(["backup", "--stanza=demo"]).unwrap();
        let resolved = resolve_cli(cli, &cfg).unwrap();
        let ini = crate::ini::parse_ini("[demo]\npg2-local=true\npg2-host=x\n").unwrap();
        let err = load_config(resolved, &ini, &cfg).unwrap_err();
        match err {
            LoadError::DependNotSatisfied {
                option,
                group_index,
                depend_option,
                depend_value,
                depend_list,
            } => {
                assert_eq!(option, "pg-host");
                assert_eq!(group_index, Some(2));
                assert_eq!(depend_option, "pg-local");
                assert_eq!(depend_value, "true");
                assert_eq!(depend_list, vec!["false".to_owned()]);
            }
            other => panic!("expected DependNotSatisfied at (pg-host, Some(2)), got {other:?}"),
        }
    }
}
