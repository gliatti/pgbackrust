//! Runtime configuration model for the pgBackRest Rust rewrite.
//!
//! This crate consumes the typed `pgbr_build::Config` produced from
//! `src/build/config/config.yaml` and lowers it into a runtime configuration
//! model — `Cfg` and friends — used at the start of every pgBackRest
//! invocation to decide which command is being run, which options are valid
//! for it, and what their resolved values are.
//!
//! The C reference is `src/config/config.{h,c}` plus the auto-generated
//! `src/config/parse.auto.c.inc`.
//!
//! The first slice (this revision) covers the command model: parsing
//! `pgbr_build::config::Config` into a `Cfg` whose `commands` field exposes
//! every command's roles, lock requirements, and logging defaults. Option
//! resolution (inheritance, `+role`/`-command` shortcut expansion, default
//! application, allow-list checks) is deferred to subsequent revisions.

pub mod command;
pub mod compile;
pub mod option;
pub mod types;
pub mod value;

pub use crate::command::CfgCommand;
pub use crate::compile::{Cfg, CompileError, compile};
pub use crate::option::{CfgOption, ResolvedCommandUsage, ResolvedDepend};
pub use crate::types::{ConfigCommandRole, DefaultType, LockType, OptionGroup, OptionSection, OptionType};
pub use crate::value::{OptionValue, ValueError, parse_value};
