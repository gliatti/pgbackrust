#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// `EmptyMap` represents YAML `{}` placeholders — semantically a map with
// zero-sized values, which clippy::zero_sized_map_values flags as a candidate
// for a BTreeSet. Switching to a set would lose the ability to deserialize
// from a YAML mapping. Suppress the lint at crate level.
#![allow(clippy::zero_sized_map_values)]

//! Build-time inputs for the pgBackRest Rust rewrite.
//!
//! Parses the four hand-written definition files (`config.yaml`, `error.yaml`,
//! `help.xml`, `postgres.yaml`) into typed Rust structures consumed by
//! `pgbr-config`, `pgbr-postgres`, etc.
//!
//! The canonical copies of those files live under `crates/pgbr-build/inputs/`
//! and are embedded at compile time via [`mod@inputs`], so consumers share one
//! source of truth with no runtime file dependency.

pub mod config;
pub mod error;
pub mod help;
pub mod inputs;
pub mod postgres;

pub use crate::config::{Config, parse_config};
pub use crate::error::{ErrorDef, parse_errors};
pub use crate::help::{ConfigKey, ConfigSection, Help, HelpCommand, HelpCommandOption, HelpError, parse_help};
pub use crate::postgres::{PostgresVersions, parse_postgres};
