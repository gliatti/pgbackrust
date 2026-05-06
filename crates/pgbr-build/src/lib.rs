// `EmptyMap` represents YAML `{}` placeholders — semantically a map with
// zero-sized values, which clippy::zero_sized_map_values flags as a candidate
// for a BTreeSet. Switching to a set would lose the ability to deserialize
// from a YAML mapping. Suppress the lint at crate level.
#![allow(clippy::zero_sized_map_values)]

//! Build-time inputs for the pgBackRest Rust rewrite.
//!
//! Parses the four hand-written input files under `src/build/` (`config.yaml`,
//! `error.yaml`, `help.xml`, `postgres.yaml`) into typed Rust structures consumed
//! by `pgbr-config`, `pgbr-postgres`, etc.
//!
//! This crate runs in parallel with the existing C generator at `src/build/`.
//! The C generator keeps emitting `*.auto.h` / `*.auto.c.inc` for the C build
//! during the transition; this crate produces the same information as Rust types
//! for the Rust port to consume.

pub mod config;
pub mod error;
pub mod help;
pub mod postgres;

pub use crate::config::{Config, parse_config};
pub use crate::error::{ErrorDef, parse_errors};
pub use crate::help::{ConfigKey, ConfigSection, Help, HelpCommand, HelpCommandOption, HelpError, parse_help};
pub use crate::postgres::{PostgresVersions, parse_postgres};
