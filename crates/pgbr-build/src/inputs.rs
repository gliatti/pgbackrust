//! The four hand-written pgBackRust definition files, embedded at compile time.
//!
//! These were historically read from `src/build/` by the C code generator.
//! With the C tree removed, the canonical copies live under
//! `crates/pgbr-build/inputs/` and are embedded here so every consumer
//! (`pgbr-config`, `pgbr-postgres`, `pgbr-cli`, the help command, …) shares
//! one source of truth without depending on a runtime file path.

/// `config.yaml` — every command, option group, and option definition.
pub const CONFIG_YAML: &str = include_str!("../inputs/config.yaml");

/// `error.yaml` — the error-code table.
pub const ERROR_YAML: &str = include_str!("../inputs/error.yaml");

/// `help.xml` — command and option documentation.
pub const HELP_XML: &str = include_str!("../inputs/help.xml");

/// `postgres.yaml` — the list of supported `PostgreSQL` major versions.
pub const POSTGRES_YAML: &str = include_str!("../inputs/postgres.yaml");
