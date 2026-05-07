//! Per-command implementations for the pgBackRest Rust rewrite.
//!
//! This crate is the dispatcher layer: given a fully resolved
//! [`pgbr_config::LoadedConfig`] plus the two `Storage` instances the
//! command framework hands out (one for the repository, one for the PG
//! data directory), [`dispatch`] routes execution to the per-command
//! function declared in the matching submodule.
//!
//! Each user-facing command lives in its own module so the migration can
//! replace one stub at a time. A handful of commands ship fully
//! implemented in this initial slice; the rest return
//! [`CommandError::NotYetImplemented`] until their port lands.
//!
//! C reference for the full set: `src/command/<name>/<name>.c`.

#![cfg_attr(not(test), forbid(unsafe_code))]

use std::fmt;

pub mod annotate;
pub mod archive;
pub mod backup;
pub mod check;
pub mod control;
pub mod expire;
pub mod help;
pub mod info;
pub mod lock;
pub mod manifest;
pub mod repo;
pub mod restore;
pub mod server;
pub mod stanza;
pub mod verify;

/// Typed failure raised by any per-command function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// `config.command` did not match any known command name.
    UnknownCommand { command: String },
    /// The command exists but its Rust implementation is still a stub.
    NotYetImplemented { command: String },
    /// A required option is absent from the resolved configuration.
    MissingOption { option: String },
    /// Wrapped failure from a [`pgbr_storage::Storage`] call.
    Storage(pgbr_storage::StorageError),
    /// Wrapped failure from a [`pgbr_io::IoRead`] / [`pgbr_io::IoWrite`] call.
    Io(pgbr_io::IoError),
    /// Catch-all for command-specific failures that don't have a dedicated
    /// variant yet (file-system reads outside `Storage`, XML parse errors,
    /// etc.). The contained message is already user-facing.
    Other(String),
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand { command } => write!(f, "unknown command: {command}"),
            Self::NotYetImplemented { command } => {
                write!(f, "command `{command}` is not yet implemented in the Rust port")
            }
            Self::MissingOption { option } => write!(f, "required option `{option}` is missing"),
            Self::Storage(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<pgbr_storage::StorageError> for CommandError {
    fn from(err: pgbr_storage::StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<pgbr_io::IoError> for CommandError {
    fn from(err: pgbr_io::IoError) -> Self {
        Self::Io(err)
    }
}

/// Route a resolved configuration to the matching per-command function.
///
/// `repo_storage` and `pg_storage` are the two `Storage` instances every
/// pgBackRest command needs: the first points at the backup repository,
/// the second at the `PostgreSQL` data directory of the active stanza. The
/// caller wires up real backends (posix / s3 / azure / …); tests use
/// `Posix` rooted at a `tempfile::TempDir`.
///
/// # Errors
///
/// Returns [`CommandError::UnknownCommand`] if the command name is not in
/// the dispatch table, or whatever the dispatched implementation returns.
pub fn dispatch(
    config: &pgbr_config::LoadedConfig,
    repo_storage: &dyn pgbr_storage::Storage,
    pg_storage: &dyn pgbr_storage::Storage,
) -> Result<(), CommandError> {
    match config.command.as_str() {
        "version" => control::version(config),
        "help" => help::help(config),
        "start" => lock::start(config, repo_storage),
        "stop" => lock::stop(config, repo_storage),
        "stanza-create" => stanza::create(config, repo_storage, pg_storage),
        "stanza-delete" => stanza::delete(config, repo_storage),
        "stanza-upgrade" => stanza::upgrade(config, repo_storage, pg_storage),
        "info" => info::info(config, repo_storage),
        "repo-ls" => repo::ls(config, repo_storage),
        "repo-get" => repo::get(config, repo_storage),
        "repo-put" => repo::put(config, repo_storage),
        "repo-rm" => repo::rm(config, repo_storage),
        "backup" => backup::backup(config, repo_storage, pg_storage),
        "restore" => restore::restore(config, repo_storage, pg_storage),
        "archive-get" => archive::get(config, repo_storage, pg_storage),
        "archive-push" => archive::push(config, repo_storage, pg_storage),
        "expire" => expire::expire(config, repo_storage),
        "verify" => verify::verify(config, repo_storage),
        "check" => check::check(config, repo_storage, pg_storage),
        "annotate" => annotate::annotate(config, repo_storage),
        "manifest" => manifest::manifest(config, repo_storage),
        "server" => server::server(config, repo_storage),
        "server-ping" => server::ping(config),
        other => Err(CommandError::UnknownCommand {
            command: other.to_owned(),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_storage::{Posix, Storage};
    use tempfile::TempDir;

    use super::{CommandError, dispatch};

    fn fake_config(command: &str, stanza: Option<&str>, lock_path: Option<&Path>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(p) = lock_path {
            options.insert(("lock-path".to_owned(), None), OptionValue::Path(p.display().to_string()));
        }
        LoadedConfig {
            command: command.to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    fn posix_pair() -> (TempDir, TempDir, Posix, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_storage = Posix::new(repo.path());
        let pg_storage = Posix::new(pg.path());
        (repo, pg, repo_storage, pg_storage)
    }

    #[test]
    fn unknown_command_surfaces_typed_error() {
        let cfg = fake_config("not-a-command", None, None);
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let err = dispatch(&cfg, &repo_s, &pg_s).expect_err("dispatch must fail for unknown command");
        match err {
            CommandError::UnknownCommand { command } => assert_eq!(command, "not-a-command"),
            other => panic!("expected UnknownCommand, got {other:?}"),
        }
    }

    #[test]
    fn not_yet_implemented_path_for_backup() {
        let cfg = fake_config("backup", Some("demo"), None);
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let err = dispatch(&cfg, &repo_s, &pg_s).expect_err("backup is not yet implemented");
        match err {
            CommandError::NotYetImplemented { command } => assert_eq!(command, "backup"),
            other => panic!("expected NotYetImplemented, got {other:?}"),
        }
    }

    #[test]
    fn version_returns_ok() {
        let cfg = fake_config("version", None, None);
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        dispatch(&cfg, &repo_s, &pg_s).expect("version should succeed");
    }

    #[test]
    fn stop_then_start_round_trip_via_posix() {
        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let lock_path = lock_dir.path();
        let (_repo, _pg, repo_s, pg_s) = posix_pair();

        let stop_cfg = fake_config("stop", Some("demo"), Some(lock_path));
        dispatch(&stop_cfg, &repo_s, &pg_s).expect("stop should succeed");
        let stop_file = lock_path.join("demo.stop");
        assert!(stop_file.exists(), "stop file should exist after `stop`");

        let start_cfg = fake_config("start", Some("demo"), Some(lock_path));
        dispatch(&start_cfg, &repo_s, &pg_s).expect("start should succeed");
        assert!(!stop_file.exists(), "stop file should be gone after `start`");

        // start is idempotent: a second invocation is a no-op.
        dispatch(&start_cfg, &repo_s, &pg_s).expect("start is idempotent");
    }

    #[test]
    fn stanza_delete_removes_archive_and_backup_subtrees() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let pg_dir = tempfile::tempdir().expect("pg tempdir");
        let repo_storage = Posix::new(repo_dir.path());
        let pg_storage = Posix::new(pg_dir.path());

        // Seed both subtrees so we can confirm deletion.
        repo_storage
            .create_path(Path::new("archive/demo/some/sub"), true)
            .expect("create archive subtree");
        repo_storage
            .create_path(Path::new("backup/demo/some/sub"), true)
            .expect("create backup subtree");
        assert!(repo_dir.path().join("archive/demo").exists());
        assert!(repo_dir.path().join("backup/demo").exists());

        let cfg = fake_config("stanza-delete", Some("demo"), None);
        dispatch(&cfg, &repo_storage, &pg_storage).expect("stanza-delete should succeed");

        assert!(!repo_dir.path().join("archive/demo").exists());
        assert!(!repo_dir.path().join("backup/demo").exists());

        // Idempotent: a second call must also succeed.
        dispatch(&cfg, &repo_storage, &pg_storage).expect("stanza-delete idempotent");
    }

    #[test]
    fn stanza_delete_without_stanza_is_missing_option() {
        let cfg = fake_config("stanza-delete", None, None);
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let err = dispatch(&cfg, &repo_s, &pg_s).expect_err("stanza-delete requires a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn repo_ls_inner_lists_entries() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo_storage = Posix::new(repo_dir.path());

        // Seed a few entries.
        repo_storage.create_path(Path::new("archive"), false).expect("create archive");
        repo_storage.create_path(Path::new("backup"), false).expect("create backup");
        let mut w = repo_storage
            .open_write(Path::new("backup.info"))
            .expect("open_write backup.info");
        w.write(b"hello").expect("write");
        w.close().expect("close");

        let mut cfg = fake_config("repo-ls", None, None);
        cfg.params.push(".".to_owned());
        let entries = super::repo::ls_inner(&cfg, &repo_storage).expect("ls_inner");
        let mut names: Vec<String> = entries.iter().map(|p| p.display().to_string()).collect();
        names.sort();
        assert!(names.iter().any(|n| n.ends_with("archive")), "expected archive in {names:?}");
        assert!(names.iter().any(|n| n.ends_with("backup")), "expected backup in {names:?}");
        assert!(
            names.iter().any(|n| n.ends_with("backup.info")),
            "expected backup.info in {names:?}"
        );
    }
}
