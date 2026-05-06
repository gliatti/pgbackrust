//! Resolved option model.
//!
//! `CfgOption` is the runtime form of `pgbr_build::config::OptionDef` after
//! [`compile`] has applied:
//!
//! - inheritance via `inherit:` — parent fields are copied, then locally set
//!   fields override;
//! - command-list resolution — `command:` shortcut keys (`+role`, `+inherit`,
//!   `-command`) are expanded against the command set, real command-name
//!   keys are preserved with their per-command override;
//! - typed enum parsing — `type:`, `section:`, `group:`, `default-type:`,
//!   `command-role:` are turned into the matching Rust enums and rejected if
//!   unrecognised;
//! - default values — boolean fields default to `false` when neither the
//!   option nor its parent set them.
//!
//! [`compile`]: crate::compile::compile

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{ConfigCommandRole, DefaultType, OptionGroup, OptionSection, OptionType};

// `CfgOption` mirrors the YAML's bool-heavy schema (negate, reset, sequence,
// internal, secure, required, bool_like, beta). Bundling them into a state-
// machine enum would be more boilerplate than insight, so suppress the lint.
#[allow(clippy::struct_excessive_bools)]
/// One pgBackRest option (e.g. `repo-path`, `pg1-host`, `compress-level`)
/// after resolution from `config.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgOption {
    /// Option name as written in `config.yaml`.
    pub name: String,
    /// `type:` from `config.yaml`. Required, either locally or via `inherit:`.
    pub option_type: OptionType,
    /// `section:`. Absent for command-line-only options.
    pub section: Option<OptionSection>,
    /// `group:`. `Pg` or `Repo` for indexed options, else `None`.
    pub group: Option<OptionGroup>,
    /// `default:`. The build-time value (a YAML scalar / sequence / mapping)
    /// is preserved verbatim — type-specific parsing is the runtime's job.
    pub default: Option<serde_yml::Value>,
    /// `default-type:`. Drives how `default:` is rendered/evaluated.
    pub default_type: Option<DefaultType>,
    /// `negate:` — boolean options that accept `--no-<name>`.
    pub negate: bool,
    /// `reset:` — option may be reset to its default.
    pub reset: bool,
    /// `sequence:` — string-id default rendered as a member of an enum sequence.
    pub sequence: bool,
    /// `internal:` — hidden from user-facing docs.
    pub internal: bool,
    /// `secure:` — value is a secret and is logged as `<redacted>`.
    pub secure: bool,
    /// `required:`.
    pub required: bool,
    /// `bool-like:` — string-id option that also accepts y/n shorthand.
    pub bool_like: bool,
    /// `beta:` — only available when `--beta` is passed.
    pub beta: bool,
    /// `allow-list:` at the option level. Per-command overrides land in
    /// [`ResolvedCommandUsage::allow_list`].
    pub allow_list: Option<Vec<serde_yml::Value>>,
    /// `allow-range:` (potentially per-flavor).
    pub allow_range: Option<serde_yml::Value>,
    /// `depend:` at the option level.
    pub depend: Option<ResolvedDepend>,
    /// `deprecate:` — old names this option also matches.
    pub deprecate: BTreeSet<String>,
    /// Option-level `command-role:`. Empty means "all roles of every
    /// command listed in `commands`" (per the YAML's docstring).
    pub roles: BTreeSet<ConfigCommandRole>,
    /// Resolved per-command usage. Key is the command name (`backup`,
    /// `archive-push`, …). Value is the override applied for that command.
    pub commands: BTreeMap<String, ResolvedCommandUsage>,
    /// Parent option name when this option uses `inherit:`. `None` otherwise.
    /// Kept for diagnostics; not consulted at runtime.
    pub inherits_from: Option<String>,
}

/// Per-command override applied to one option for one command.
///
/// All fields are `Option<T>` because a missing override means "fall back to
/// the option-level value". An empty `roles` set means the same.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedCommandUsage {
    pub default: Option<serde_yml::Value>,
    pub required: Option<bool>,
    pub internal: Option<bool>,
    pub depend: Option<ResolvedDepend>,
    pub allow_list: Option<Vec<serde_yml::Value>>,
    pub sequence: Option<bool>,
    /// Per-command-role-set override. Empty means "fall back to the
    /// option-level role set; if that is also empty, all roles".
    pub roles: BTreeSet<ConfigCommandRole>,
}

/// Resolved `depend:` clause. The `option:` field is required after parsing
/// (a bare-string `depend: foo` is normalized to `{option: foo}` by
/// [`pgbr_build::config::Depend`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDepend {
    pub option: String,
    pub list: Option<Vec<serde_yml::Value>>,
    pub default: Option<serde_yml::Value>,
}
