#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
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
pub mod backup_control;
pub mod block;
pub mod bundle;
pub mod check;
pub mod cipher;
pub mod control;
pub mod expire;
pub mod help;
pub mod info;
pub mod lock;
pub mod manifest;
pub mod pipeline;
pub mod remote_db;
pub mod repo;
pub mod restore;
pub mod server;
pub mod stanza;
pub mod verify;
pub mod worker;

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
/// `repo_storage` is the *active* repository (selected by `--repo`); the
/// commands that span every repository — `archive-push`/`archive-get` and the
/// stanza-management commands — are instead handed the full set via
/// [`dispatch_multi`]. This thin entry point treats the active repository as the
/// only one, so single-repo callers (and tests) keep a simple two-storage
/// signature. C ref: the `repoIdxList` iteration in `src/command/*`.
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
    // The single active repository is treated as the only configured one,
    // carrying the conventional first index (1) for the stanza commands' per-repo
    // cipher resolution.
    dispatch_multi(config, repo_storage, &[(1, repo_storage)], pg_storage)
}

/// Route a resolved configuration to the matching per-command function, with an
/// explicit set of *all* configured repositories.
///
/// `repo_storage` is the active repository (used by single-repo commands such as
/// `info`, `expire`, `restore`, the `repo-*` family, …). `repo_storages` is the
/// full list — one `(group_index, backend)` pair per configured repository —
/// used by the commands that must touch every repository: `archive-push` fans
/// each WAL segment out to all of them, `archive-get` reads from the first that
/// has the segment, and `stanza-create`/`-delete`/`-upgrade` initialise / remove
/// / upgrade the stanza on each (reading each repository's own `repoN-cipher-*`
/// at its `group_index`). For a single-repository configuration `repo_storages`
/// is just `[(1, repo_storage)]`, which is exactly what [`dispatch`] passes.
///
/// # Errors
///
/// Returns [`CommandError::UnknownCommand`] if the command name is not in
/// the dispatch table, or whatever the dispatched implementation returns.
pub fn dispatch_multi(
    config: &pgbr_config::LoadedConfig,
    repo_storage: &dyn pgbr_storage::Storage,
    repo_storages: &[(u32, &dyn pgbr_storage::Storage)],
    pg_storage: &dyn pgbr_storage::Storage,
) -> Result<(), CommandError> {
    // The subordinate `local` / `remote` worker roles short-circuit the
    // command table: regardless of the user-facing command name, a worker
    // invocation serves the protocol on stdin/stdout rather than running a
    // command itself. C ref: src/command/{local,remote}, src/main.c.
    if worker::is_worker(config) {
        return worker::run_worker_stdio(config);
    }

    // The archive commands do not (yet) apply per-repo encryption, so they only
    // need the backends — drop the indexes into a plain slice.
    let archive_repos: Vec<&dyn pgbr_storage::Storage> = repo_storages.iter().map(|(_, s)| *s).collect();

    match config.command.as_str() {
        "version" => control::version(config),
        "help" => help::help(config),
        "start" => lock::start(config),
        "stop" => lock::stop(config),
        "stanza-create" => stanza::create(config, repo_storages, pg_storage),
        "stanza-delete" => stanza::delete(config, repo_storages),
        "stanza-upgrade" => stanza::upgrade(config, repo_storages, pg_storage),
        "info" => info::info(config, repo_storage),
        "repo-ls" => repo::ls(config, repo_storage),
        "repo-get" => repo::get(config, repo_storage),
        "repo-put" => repo::put(config, repo_storage),
        "repo-rm" => repo::rm(config, repo_storage),
        "backup" => backup::backup(config, repo_storage, pg_storage),
        "restore" => restore::restore(config, repo_storage, pg_storage),
        "archive-get" => archive_get_with_prefetch(config, &archive_repos, pg_storage),
        "archive-push" => archive::push(config, &archive_repos, pg_storage),
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

/// Number of WAL segments ahead of the one `PostgreSQL` just requested that the
/// asynchronous `archive-get` pre-fetcher tries to stage into the spool. The
/// actual count staged is still bounded by `archive-get-queue-max` (see
/// [`archive_get_with_prefetch`]); this only caps how far ahead the look-ahead walks
/// when the byte cap would otherwise let it run unbounded. Mirrors the C side's
/// fixed look-ahead window in `src/command/archive/get/get.c`.
const ARCHIVE_GET_PREFETCH_AHEAD: u64 = 64;

/// Default `wal-segment-size` (16 MiB) used when computing the look-ahead window
/// for the pre-fetcher. The window is only a *segment-name* enumeration, so the
/// exact size only affects where the low half rolls over into the high half; the
/// 16 MiB default matches the overwhelmingly common cluster configuration and
/// keeps this dispatch-side helper from needing a live cluster probe.
const DEFAULT_WAL_SEGMENT_SIZE: u64 = 16 * 1024 * 1024;

/// Run `archive-get`, then — in asynchronous mode — pre-fetch the next WAL
/// segments into the spool, bounded by `archive-get-queue-max`.
///
/// The foreground [`archive::get`] always runs first so `PostgreSQL` gets the
/// segment it asked for (served from the spool if a previous pre-fetch staged
/// it, otherwise straight from the repository). Once it succeeds, and only when
/// `archive-async=true`, the look-ahead pre-fetcher stages the *following*
/// segments so the next few `archive-get` calls are served locally. The amount
/// staged is capped by `archive-get-queue-max` (the `queue_max` parameter of
/// [`archive::prefetch_get_spool`]) so the spool never over-fills ahead of
/// recovery. This is where the resolved `archive-get-queue-max` option is
/// actually applied to the async path. C ref: `src/command/archive/get/get.c`.
///
/// # Errors
///
/// Surfaces whatever [`archive::get`] returns. A pre-fetch failure is **not**
/// fatal — the requested segment was already delivered — so it is swallowed
/// (best-effort look-ahead), matching the C side treating a pre-fetch miss as a
/// no-op rather than a command failure.
fn archive_get_with_prefetch(
    config: &pgbr_config::LoadedConfig,
    repo_storages: &[&dyn pgbr_storage::Storage],
    pg_storage: &dyn pgbr_storage::Storage,
) -> Result<(), CommandError> {
    archive::get(config, repo_storages, pg_storage)?;

    // Look-ahead pre-fetch only applies to the asynchronous path with a spool.
    if !archive_async_enabled(config) {
        return Ok(());
    }
    let (Some(stanza), Some(spool_root), Some(requested)) = (
        config.stanza.as_deref(),
        spool_path_opt(config),
        config.params.first().map(String::as_str),
    ) else {
        return Ok(());
    };

    let segments = prefetch_segment_window(requested, ARCHIVE_GET_PREFETCH_AHEAD);
    if segments.is_empty() {
        return Ok(());
    }

    let queue_max = archive_get_queue_max(config);
    let spool = pgbr_storage::Posix::new(std::path::PathBuf::from(spool_root));
    // Pre-fetch from the first repository (the same precedence archive-get uses
    // when serving a single segment). Best-effort: a miss leaves recovery to the
    // synchronous path on the next call, so a pre-fetch error is not propagated.
    if let Some(repo) = repo_storages.first() {
        let index = cipher::active_repo_index(config);
        let _ = archive::prefetch_get_spool(config, &spool, *repo, index, stanza, &segments, queue_max);
    }
    Ok(())
}

/// Whether `archive-async=true` is set in the resolved configuration. Defaults
/// to `false` (synchronous) when the option is absent.
fn archive_async_enabled(config: &pgbr_config::LoadedConfig) -> bool {
    matches!(
        config.options.get(&("archive-async".to_owned(), None)),
        Some(pgbr_config::OptionValue::Boolean(true))
    )
}

/// Read the resolved `spool-path` (an [`OptionValue::Path`]), or `None` when
/// unset.
fn spool_path_opt(config: &pgbr_config::LoadedConfig) -> Option<String> {
    match config.options.get(&("spool-path".to_owned(), None)) {
        Some(pgbr_config::OptionValue::Path(p) | pgbr_config::OptionValue::String(p)) => Some(p.clone()),
        _ => None,
    }
}

/// Read the resolved `archive-get-queue-max` byte cap, or `None` when unset
/// (which leaves [`archive::prefetch_get_spool`] unbounded). Accepts both the
/// canonical [`OptionValue::Size`] and a non-negative [`OptionValue::Integer`]
/// for the hand-built configs used in tests.
fn archive_get_queue_max(config: &pgbr_config::LoadedConfig) -> Option<u64> {
    match config.options.get(&("archive-get-queue-max".to_owned(), None)) {
        Some(pgbr_config::OptionValue::Size(value)) => Some(*value),
        Some(pgbr_config::OptionValue::Integer(value)) if *value >= 0 => u64::try_from(*value).ok(),
        _ => None,
    }
}

/// Enumerate up to `ahead` WAL segment names *following* `requested` (exclusive
/// of `requested` itself), on the same timeline, for the asynchronous pre-fetch
/// look-ahead window.
///
/// Returns an empty vector when `requested` is not a valid 24-hex segment name
/// or when `ahead` is zero. The enumeration reuses
/// [`pgbr_postgres::lsn::wal_segment_range`] over the 16 MiB-default segment
/// ordering (low half rolls over into the high half), so the window crosses a
/// logical-file boundary correctly. Pure: no I/O.
fn prefetch_segment_window(requested: &str, ahead: u64) -> Vec<String> {
    use pgbr_postgres::lsn::{parse_wal_segment, segments_per_logical_file, wal_segment_range};

    if ahead == 0 {
        return Vec::new();
    }
    let Some((tli, hi, lo)) = parse_wal_segment(requested) else {
        return Vec::new();
    };
    let per_file = segments_per_logical_file(DEFAULT_WAL_SEGMENT_SIZE);
    let start_segno = u64::from(hi) * per_file + u64::from(lo);
    // The window starts at the segment *after* the requested one.
    let first = start_segno + 1;
    let last = start_segno + ahead;
    let (Some(start_hi), Some(start_lo)) = (u32::try_from(first / per_file).ok(), u32::try_from(first % per_file).ok()) else {
        return Vec::new();
    };
    let (Some(stop_hi), Some(stop_lo)) = (u32::try_from(last / per_file).ok(), u32::try_from(last % per_file).ok()) else {
        return Vec::new();
    };
    let start = format!("{tli:08X}{start_hi:08X}{start_lo:08X}");
    let stop = format!("{tli:08X}{stop_hi:08X}{stop_lo:08X}");
    wal_segment_range(&start, &stop, DEFAULT_WAL_SEGMENT_SIZE).unwrap_or_default()
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
    fn server_ping_dispatches_to_real_implementation() {
        // `server-ping` now drives a real TCP client (`server::ping_tcp`):
        // dispatching it with nothing listening on the default address
        // surfaces a connect failure (`CommandError::Other`), not the generic
        // `NotYetImplemented` stub. The transport-agnostic protocol core lives
        // in `server::serve` / `server::ping_exchange`.
        let cfg = fake_config("server-ping", None, None);
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let err = dispatch(&cfg, &repo_s, &pg_s).expect_err("server-ping with no server must fail to connect");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("tcp connect"), "message was {msg:?}"),
            other => panic!("expected Other(tcp connect), got {other:?}"),
        }
    }

    #[test]
    fn backup_dispatches_to_real_implementation() {
        // `backup` is implemented now: dispatching it against an empty repo
        // surfaces the uninitialized-stanza error from the command, not the
        // generic `NotYetImplemented` stub response.
        let cfg = fake_config("backup", Some("demo"), None);
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let err = dispatch(&cfg, &repo_s, &pg_s).expect_err("backup against an empty repo must error");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "stanza not initialized; run stanza-create first"),
            other => panic!("expected Other(not initialized), got {other:?}"),
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

    // -------------------------------------------------------------------
    // archive-get-queue-max dispatch wiring
    // -------------------------------------------------------------------

    use super::{
        ARCHIVE_GET_PREFETCH_AHEAD, archive_async_enabled, archive_get_queue_max, prefetch_segment_window, spool_path_opt,
    };

    #[test]
    fn archive_async_enabled_reads_boolean() {
        let mut cfg = fake_config("archive-get", Some("demo"), None);
        assert!(!archive_async_enabled(&cfg), "absent option defaults to synchronous");
        cfg.options
            .insert(("archive-async".to_owned(), None), OptionValue::Boolean(true));
        assert!(archive_async_enabled(&cfg));
        cfg.options
            .insert(("archive-async".to_owned(), None), OptionValue::Boolean(false));
        assert!(!archive_async_enabled(&cfg));
    }

    #[test]
    fn spool_path_opt_reads_path_or_string() {
        let mut cfg = fake_config("archive-get", Some("demo"), None);
        assert_eq!(spool_path_opt(&cfg), None);
        cfg.options.insert(
            ("spool-path".to_owned(), None),
            OptionValue::Path("/var/spool/pgbr".to_owned()),
        );
        assert_eq!(spool_path_opt(&cfg).as_deref(), Some("/var/spool/pgbr"));
    }

    #[test]
    fn archive_get_queue_max_reads_size_and_integer() {
        let mut cfg = fake_config("archive-get", Some("demo"), None);
        // Absent → unbounded prefetch.
        assert_eq!(archive_get_queue_max(&cfg), None);
        cfg.options.insert(
            ("archive-get-queue-max".to_owned(), None),
            OptionValue::Size(128 * 1024 * 1024),
        );
        assert_eq!(archive_get_queue_max(&cfg), Some(128 * 1024 * 1024));
        // A non-negative integer is accepted too (hand-built configs).
        cfg.options
            .insert(("archive-get-queue-max".to_owned(), None), OptionValue::Integer(4096));
        assert_eq!(archive_get_queue_max(&cfg), Some(4096));
        // A negative integer is rejected (treated as unset).
        cfg.options
            .insert(("archive-get-queue-max".to_owned(), None), OptionValue::Integer(-1));
        assert_eq!(archive_get_queue_max(&cfg), None);
    }

    #[test]
    fn prefetch_segment_window_enumerates_following_segments() {
        // The window starts at the segment AFTER the requested one and runs
        // `ahead` segments long, on the same timeline.
        let window = prefetch_segment_window("000000010000000000000002", 3);
        assert_eq!(
            window,
            vec![
                "000000010000000000000003".to_owned(),
                "000000010000000000000004".to_owned(),
                "000000010000000000000005".to_owned(),
            ],
        );
        // The requested segment itself is never included.
        assert!(!window.contains(&"000000010000000000000002".to_owned()));
    }

    #[test]
    fn prefetch_segment_window_rolls_over_logical_file_boundary() {
        // Requesting the last segment of logical file 0 (low half 0x000000FF for
        // the 16 MiB default = 256 segments/file) rolls the next one into the
        // high half.
        let window = prefetch_segment_window("0000000100000000000000FF", 1);
        assert_eq!(window, vec!["000000010000000100000000".to_owned()]);
    }

    #[test]
    fn prefetch_segment_window_rejects_malformed_or_zero() {
        assert!(prefetch_segment_window("not-a-segment", 4).is_empty());
        assert!(prefetch_segment_window("000000010000000000000002", 0).is_empty());
        // The default window size is non-zero so a real call always looks ahead;
        // exercising it through the function (rather than asserting on the const
        // directly) keeps the check meaningful without a constant assertion.
        assert!(
            !prefetch_segment_window("000000010000000000000002", ARCHIVE_GET_PREFETCH_AHEAD).is_empty(),
            "the default look-ahead window must enumerate at least one segment"
        );
    }
}
