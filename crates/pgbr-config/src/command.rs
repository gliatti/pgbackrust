//! Resolved command model.
//!
//! `CfgCommand` is the runtime form of `pgbr_build::config::CommandDef`: enums
//! resolve to the typed Rust forms, defaults are applied (`log_file: true`
//! when absent, `LockType::None` when absent, etc.), and the `Main` role is
//! added implicitly per `config.yaml`'s docstring (`main` is implicit on
//! every command).

use std::collections::BTreeSet;

use crate::types::{ConfigCommandRole, LockType};

// `CfgCommand` mirrors the bool-heavy schema of `config.yaml`'s
// `command:` block (lock-required, lock-remote-required, log-file,
// parameter-allowed, internal). Bundling them into a state-machine enum
// would be more boilerplate than insight, so suppress the lint.
#[allow(clippy::struct_excessive_bools)]
/// One pgBackRest command (e.g. `backup`, `restore`, `archive-push`) after
/// resolution from `config.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgCommand {
    /// Command name as written in `config.yaml` (`backup`, `archive-push`, …).
    pub name: String,
    /// Roles enabled for this command; always contains `Main`. Sorted so
    /// equality is deterministic.
    pub roles: BTreeSet<ConfigCommandRole>,
    /// Lock category. `None` when the command does not declare `lock-type:`.
    pub lock_type: LockType,
    /// `lock-required:` from `config.yaml`. Defaults to `false`.
    pub lock_required: bool,
    /// `lock-remote-required:`. Defaults to `false`.
    pub lock_remote_required: bool,
    /// `log-file:`. Defaults to `true` per the YAML's docstring on `command:`.
    pub log_file: bool,
    /// `log-level-default:`, applied when the command emits its standard
    /// boilerplate messages. `None` means "use the global default".
    pub log_level_default: Option<String>,
    /// `parameter-allowed:`. Defaults to `false`.
    pub parameter_allowed: bool,
    /// `internal:` — hidden from the end-user docs.
    pub internal: bool,
}

impl CfgCommand {
    /// Whether `role` is one of this command's roles.
    #[must_use]
    pub fn has_role(&self, role: ConfigCommandRole) -> bool {
        self.roles.contains(&role)
    }
}
