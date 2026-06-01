//! `PGBACKRUST_<OPTION>` environment-variable option source.
//!
//! pgBackRust lets any option be set through an environment variable whose
//! name is `PGBACKRUST_` followed by the option name uppercased with every
//! `-` turned into `_`. Indexed group options carry their index in the name,
//! e.g.
//!
//! - `--repo1-path` ⇄ `PGBACKRUST_REPO1_PATH`
//! - `--compress-type` ⇄ `PGBACKRUST_COMPRESS_TYPE`
//! - `--pg2-host` ⇄ `PGBACKRUST_PG2_HOST`
//!
//! In the merge precedence the env source sits **below the CLI but above the
//! config file** (CLI > ENV > stanza:cmd > stanza > global:cmd > global >
//! default). Booleans accept `y`/`n` (and the other spellings
//! [`crate::value::parse_value`] understands); negation and reset are *not*
//! expressed through the environment. An empty-string value is ignored (it is
//! treated as "unset"), matching the C parser in `src/config/parse.c`.
//!
//! This module is intentionally pure: the actual `std::env::var` read is
//! injected as a closure so tests never touch the real process environment.
//! [`env_values_from_process`] is the thin convenience wrapper that reads the
//! live environment.

use std::collections::BTreeMap;

use crate::compile::Cfg;
use crate::types::OptionGroup;

/// The prefix every pgBackRust option environment variable carries.
const ENV_PREFIX: &str = "PGBACKRUST_";

/// Highest group index probed when collecting env vars for indexed (`pg`/`repo`)
/// options. pgBackRust's own ceiling is 256 (`CFG_OPTION_KEY_MAX`); probing that
/// many slots per grouped option is cheap (a string build + a closure call) and
/// keeps parity with the C parser, which scans the whole environment.
const GROUP_INDEX_MAX: u32 = 256;

/// Build the environment-variable name for an option key.
///
/// `option_with_index` is the key as it would appear on the command line
/// (group prefix included), e.g. `repo1-path` -> `PGBACKRUST_REPO1_PATH`,
/// `compress-type` -> `PGBACKRUST_COMPRESS_TYPE`.
///
/// The transform is: prepend [`ENV_PREFIX`], uppercase, and replace every `-`
/// with `_`. This is the inverse of the decode performed by [`collect_env`].
#[must_use]
pub fn option_env_name(option_with_index: &str) -> String {
    let mut out = String::with_capacity(ENV_PREFIX.len() + option_with_index.len());
    out.push_str(ENV_PREFIX);
    for ch in option_with_index.chars() {
        match ch {
            '-' => out.push('_'),
            other => out.extend(other.to_uppercase()),
        }
    }
    out
}

/// Render the CLI-style raw key for an option name and optional group index
/// (`repo-path` + `Some(1)` -> `repo1-path`). Mirrors the key shape the CLI and
/// INI sources use so the env source decodes to the same `(name, index)` keys.
fn raw_key_for(option_name: &str, group: Option<OptionGroup>, index: Option<u32>) -> String {
    match (group, index) {
        (Some(OptionGroup::Pg), Some(idx)) => {
            format!("pg{idx}-{}", option_name.strip_prefix("pg-").unwrap_or(option_name))
        }
        (Some(OptionGroup::Repo), Some(idx)) => {
            format!("repo{idx}-{}", option_name.strip_prefix("repo-").unwrap_or(option_name))
        }
        _ => option_name.to_owned(),
    }
}

/// Collect every `PGBACKRUST_<OPTION>` value that `lookup` resolves, keyed by
/// `(option_name, group_index)` — the same key shape the CLI/INI sources use.
///
/// For each option declared in `cfg`:
/// - **non-grouped** options probe a single env var (`PGBACKRUST_<NAME>`),
///   keyed `(name, None)`;
/// - **grouped** (`pg`/`repo`) options probe `PGBACKRUST_<PREFIX><N>_...` for
///   `N` from 1 to [`GROUP_INDEX_MAX`] inclusive, keyed `(name, Some(N))`.
///
/// `lookup` is the injected environment reader: given an env var *name* it
/// returns its value (or `None`). An empty-string value is ignored (treated as
/// unset), matching pgBackRust. The returned map holds the *raw* string values;
/// the merge step parses them via [`crate::value::parse_value`], exactly as it
/// does for INI values.
pub fn collect_env<F>(cfg: &Cfg, lookup: F) -> BTreeMap<(String, Option<u32>), String>
where
    F: Fn(&str) -> Option<String>,
{
    let mut out: BTreeMap<(String, Option<u32>), String> = BTreeMap::new();

    for (name, opt) in &cfg.options {
        match opt.group {
            None => {
                if let Some(value) = read_non_empty(&lookup, &option_env_name(name)) {
                    out.insert((name.clone(), None), value);
                }
            }
            Some(group) => {
                for idx in 1..=GROUP_INDEX_MAX {
                    let raw_key = raw_key_for(name, Some(group), Some(idx));
                    if let Some(value) = read_non_empty(&lookup, &option_env_name(&raw_key)) {
                        out.insert((name.clone(), Some(idx)), value);
                    }
                }
            }
        }
    }

    out
}

/// Look up `env_name` via `lookup`, returning the value only when it is present
/// and non-empty (an empty string is treated as unset).
fn read_non_empty<F>(lookup: &F, env_name: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(env_name) {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Convenience wrapper over [`collect_env`] that reads the *real* process
/// environment via [`std::env::var`]. Use this in the `pgbackrust` binary; the
/// pure [`collect_env`] is preferred in tests.
#[must_use]
pub fn env_values_from_process(cfg: &Cfg) -> BTreeMap<(String, Option<u32>), String> {
    collect_env(cfg, |name| std::env::var(name).ok())
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
  compress-type:
    type: string-id
    default: gz
    command:
      backup: {}
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

    #[test]
    fn env_name_uppercases_and_swaps_dash() {
        assert_eq!(option_env_name("repo1-path"), "PGBACKRUST_REPO1_PATH");
        assert_eq!(option_env_name("compress-type"), "PGBACKRUST_COMPRESS_TYPE");
        assert_eq!(option_env_name("stanza"), "PGBACKRUST_STANZA");
        assert_eq!(option_env_name("pg2-host"), "PGBACKRUST_PG2_HOST");
    }

    #[test]
    fn collect_env_reads_non_grouped_option() {
        let cfg = small_cfg();
        let collected = collect_env(&cfg, |name| (name == "PGBACKRUST_COMPRESS_TYPE").then(|| "zst".to_owned()));
        assert_eq!(
            collected.get(&("compress-type".to_owned(), None)).map(String::as_str),
            Some("zst")
        );
        // Nothing else was set.
        assert_eq!(collected.len(), 1);
    }

    #[test]
    fn collect_env_decodes_grouped_repo_index() {
        let cfg = small_cfg();
        let env: BTreeMap<&str, &str> = [
            ("PGBACKRUST_REPO1_PATH", "/var/lib/repo1"),
            ("PGBACKRUST_REPO3_PATH", "/var/lib/repo3"),
            ("PGBACKRUST_PG2_PATH", "/data/pg2"),
        ]
        .into_iter()
        .collect();
        let collected = collect_env(&cfg, |name| env.get(name).map(|v| (*v).to_owned()));
        assert_eq!(
            collected.get(&("repo-path".to_owned(), Some(1))).map(String::as_str),
            Some("/var/lib/repo1")
        );
        assert_eq!(
            collected.get(&("repo-path".to_owned(), Some(3))).map(String::as_str),
            Some("/var/lib/repo3")
        );
        assert_eq!(
            collected.get(&("pg-path".to_owned(), Some(2))).map(String::as_str),
            Some("/data/pg2")
        );
        assert_eq!(collected.len(), 3);
    }

    #[test]
    fn collect_env_ignores_empty_string_value() {
        let cfg = small_cfg();
        let collected = collect_env(&cfg, |name| (name == "PGBACKRUST_STANZA").then(String::new));
        assert!(collected.is_empty(), "empty env value must be treated as unset");
    }

    #[test]
    fn collect_env_ignores_unknown_env_vars() {
        let cfg = small_cfg();
        // An env var that doesn't map to any declared option is never read,
        // because collect_env probes per-option, not the whole environment.
        let env: BTreeMap<&str, &str> = [("PGBACKRUST_NOT_AN_OPTION", "x"), ("UNRELATED", "y")].into_iter().collect();
        let collected = collect_env(&cfg, |name| env.get(name).map(|v| (*v).to_owned()));
        assert!(collected.is_empty());
    }
}
