//! `check` command — verify the repository is reachable, the stanza is
//! initialized, and (when a cluster is configured) the end-to-end WAL archive
//! path works against a live `PostgreSQL`.
//!
//! C reference: `src/command/check/check.c` (`cmdCheck` / `checkArchive`).
//!
//! ## Repo-side checks (no live `PostgreSQL`)
//!
//! 1. A stanza must be configured.
//! 2. The stanza must be initialized — both `archive.info` and `backup.info`
//!    load cleanly.
//! 3. The two info files must agree on the database identity
//!    (`db-system-id` and `db-version`).
//! 4. The repository must be writable — a probe file is written, read back,
//!    compared, and removed.
//! 5. The WAL archive store must be functional — a small test object is written
//!    into the stanza's current archive-id directory
//!    (`archive/<stanza>/<archive-id>/`), read back, byte-compared, and then
//!    removed. This mirrors the repo half of the C `checkArchive`.
//!
//! ## Live-PG checks (the C `checkArchive` cluster half)
//!
//! When a libpq connection is derivable from the resolved configuration
//! (`pg1-*`) or from `DATABASE_URL` (the same gate `stanza.rs` uses), the
//! command additionally:
//!
//! 6. Connects to the cluster, reads `server_version_num` and the system
//!    identifier, and confirms they agree with the stanza's info-file db
//!    history.
//! 7. Confirms `archive_mode` is `on` and `archive_command` references
//!    `pgbackrest`.
//! 8. Forces a fresh WAL segment to be archived: on a primary it calls
//!    `pg_create_restore_point('pgBackRest Archive Check')` then
//!    `pg_switch_wal()` (`pg_switch_xlog()` pre-10) and records the switched
//!    segment name. On a standby it cannot switch, so it instead inspects the
//!    most recent segment already present in the repo.
//! 9. Polls the repo's `archive/<stanza>/<archive-id>/` subtree for up to
//!    `--archive-timeout` seconds (default 60) until that segment appears,
//!    proving `PostgreSQL`'s `archive_command` → `archive-push` → repo path is
//!    working end to end.
//!
//! All libpq calls are funnelled through the [`CheckDb`] trait so the whole
//! flow — including the WAL wait loop — is unit-testable with an in-memory fake
//! DB and the in-memory repo `Storage` already used by the repo-side tests. The
//! real implementation, [`ConnCheckDb`], is a thin wrapper over
//! [`pgbr_db::Connection`]; it is exercised only by the `#[ignore]`d,
//! `DATABASE_URL`-gated integration tests.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_db::Connection;
use pgbr_info::{InfoArchive, InfoBackup};
use pgbr_io::{IoRead, IoWrite};
use pgbr_storage::Storage;

use crate::CommandError;

/// Outcome of a successful repo + stanza-init verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The stanza that was checked.
    pub stanza: String,
    /// Active cluster's textual major-version label (e.g. `"14"`), taken from
    /// the agreed-upon info files.
    pub db_version: String,
    /// Active cluster's `pg_control.system_identifier`.
    pub db_system_id: u64,
    /// Whether the repository write-probe round trip succeeded.
    pub repo_writable: bool,
    /// The stanza's current archive-id (`<db-version>-<db-id>`, e.g. `14-1`),
    /// taken from `archive.info`'s active `[db]` block.
    pub archive_id: String,
    /// Whether the WAL-archive round trip succeeded: a test object written into
    /// `archive/<stanza>/<archive-id>/`, read back, byte-compared, and removed.
    pub archive_ok: bool,
    /// Live-`PostgreSQL` portion of the check. `None` when no DB connection was
    /// derivable from the configuration (the repo-side checks still run); `Some`
    /// when the cluster was contacted.
    pub pg: Option<PgCheckReport>,
}

/// Outcome of the live-`PostgreSQL` portion of `check` (the C `checkArchive`
/// cluster half).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgCheckReport {
    /// `server_version_num` reported by the cluster (e.g. `160004`).
    pub server_version_num: u32,
    /// `system_identifier` reported by the cluster.
    pub system_id: u64,
    /// Whether the cluster is in recovery (`pg_is_in_recovery()`) — i.e. a
    /// standby. The forced WAL switch is skipped on a standby.
    pub in_recovery: bool,
    /// The WAL segment whose arrival in the repo was verified. On a primary this
    /// is the segment produced by the forced switch; on a standby it is the most
    /// recent segment already present in the repo.
    pub wal_segment: String,
    /// Whether `wal_segment` was found in the repo within the archive timeout.
    pub archive_wait_ok: bool,
}

/// The minimal set of live-`PostgreSQL` operations the `check` command needs.
///
/// Every libpq call the command makes goes through this trait so the whole live
/// flow can be driven by an in-memory fake in unit tests. [`ConnCheckDb`] is the
/// real wrapper over [`pgbr_db::Connection`].
pub trait CheckDb {
    /// `server_version_num` from `pg_settings` (e.g. `160004`).
    ///
    /// # Errors
    /// Any backend / query failure, surfaced as [`CommandError`].
    fn version(&mut self) -> Result<u32, CommandError>;

    /// `system_identifier` from `pg_control_system()`.
    ///
    /// # Errors
    /// Any backend / query failure, surfaced as [`CommandError`].
    fn system_id(&mut self) -> Result<u64, CommandError>;

    /// Whether the cluster is in recovery (`pg_is_in_recovery()`) — `true` for a
    /// standby.
    ///
    /// # Errors
    /// Any backend / query failure, surfaced as [`CommandError`].
    fn is_in_recovery(&mut self) -> Result<bool, CommandError>;

    /// `(archive_mode, archive_command)` from `pg_settings`.
    ///
    /// # Errors
    /// Any backend / query failure, surfaced as [`CommandError`].
    fn archive_settings(&mut self) -> Result<(String, String), CommandError>;

    /// Create the named restore point (`pg_create_restore_point`). Called only
    /// on a primary, immediately before the WAL switch, to match the C
    /// `checkArchive`.
    ///
    /// # Errors
    /// Any backend / query failure, surfaced as [`CommandError`].
    fn create_restore_point(&mut self, name: &str) -> Result<(), CommandError>;

    /// Force a WAL switch and return the name of the segment that was just
    /// completed (and is therefore queued for archiving). `server_version_num`
    /// selects the function name: `pg_switch_wal()` on PG >= 10,
    /// `pg_switch_xlog()` before.
    ///
    /// # Errors
    /// Any backend / query failure, surfaced as [`CommandError`].
    fn switch_wal(&mut self, server_version_num: u32) -> Result<String, CommandError>;

    /// Name of the most recent WAL segment the cluster has produced
    /// (`pg_walfile_name(pg_last_wal_replay_lsn())` on a standby, falling back to
    /// the receive position). Used on a standby, where a switch cannot be forced.
    ///
    /// # Errors
    /// Any backend / query failure, surfaced as [`CommandError`].
    fn last_wal_segment(&mut self, server_version_num: u32) -> Result<String, CommandError>;
}

/// Real [`CheckDb`] backed by a live libpq [`Connection`].
///
/// Mirrors the SQL the C `checkArchive` / `dbWalSwitch` run. Exercised only by
/// the `DATABASE_URL`-gated integration tests; the unit tests use a fake.
pub struct ConnCheckDb<'conn> {
    conn: &'conn mut Connection,
}

impl<'conn> ConnCheckDb<'conn> {
    /// Wrap a live connection.
    #[must_use]
    pub const fn new(conn: &'conn mut Connection) -> Self {
        Self { conn }
    }

    /// Run a query that returns a single scalar text value at `(0, 0)`.
    fn scalar(&mut self, sql: &str) -> Result<String, CommandError> {
        let result = self.conn.query(sql).map_err(|err| CommandError::Other(err.to_string()))?;
        result
            .value(0, 0)
            .ok_or_else(|| CommandError::Other(format!("query returned no value: {sql}")))
    }
}

impl CheckDb for ConnCheckDb<'_> {
    fn version(&mut self) -> Result<u32, CommandError> {
        let raw =
            self.scalar("select (select setting from pg_catalog.pg_settings where name = 'server_version_num')::int4::text")?;
        raw.trim()
            .parse::<u32>()
            .map_err(|_| CommandError::Other(format!("could not parse server_version_num {raw:?}")))
    }

    fn system_id(&mut self) -> Result<u64, CommandError> {
        let raw = self.scalar("select system_identifier::text from pg_catalog.pg_control_system()")?;
        raw.trim()
            .parse::<u64>()
            .map_err(|_| CommandError::Other(format!("could not parse system_identifier {raw:?}")))
    }

    fn is_in_recovery(&mut self) -> Result<bool, CommandError> {
        let raw = self.scalar("select pg_catalog.pg_is_in_recovery()::text")?;
        Ok(matches!(raw.trim(), "t" | "true" | "on" | "1"))
    }

    fn archive_settings(&mut self) -> Result<(String, String), CommandError> {
        let mode = self
            .scalar("select setting from pg_catalog.pg_settings where name = 'archive_mode'")
            .unwrap_or_default();
        let command = self
            .scalar("select setting from pg_catalog.pg_settings where name = 'archive_command'")
            .unwrap_or_default();
        Ok((mode.trim().to_owned(), command.trim().to_owned()))
    }

    fn create_restore_point(&mut self, name: &str) -> Result<(), CommandError> {
        // Quote the literal defensively; the name is a fixed constant here but
        // routing it through a parameterless query keeps the trait simple.
        let escaped = name.replace('\'', "''");
        self.scalar(&format!("select pg_catalog.pg_create_restore_point('{escaped}')::text"))
            .map(|_| ())
    }

    fn switch_wal(&mut self, server_version_num: u32) -> Result<String, CommandError> {
        let (switch_fn, walfile_fn) = wal_function_names(server_version_num);
        // pg_switch_wal() returns the LSN at the end of the just-completed
        // segment; pg_walfile_name() turns it into the segment file name. This
        // matches dbWalSwitch in src/db/db.c.
        self.scalar(&format!("select pg_catalog.{walfile_fn}(pg_catalog.{switch_fn}())"))
    }

    fn last_wal_segment(&mut self, server_version_num: u32) -> Result<String, CommandError> {
        let (_switch_fn, walfile_fn) = wal_function_names(server_version_num);
        let lsn_expr = if server_version_num >= 100_000 {
            "coalesce(pg_catalog.pg_last_wal_replay_lsn(), pg_catalog.pg_last_wal_receive_lsn())"
        } else {
            "coalesce(pg_catalog.pg_last_xlog_replay_location(), pg_catalog.pg_last_xlog_receive_location())"
        };
        self.scalar(&format!("select pg_catalog.{walfile_fn}({lsn_expr})"))
    }
}

/// Pick the `(switch, walfile-name)` SQL function names for `server_version_num`.
/// PG >= 10 uses the `wal` spelling; earlier releases use `xlog`.
const fn wal_function_names(server_version_num: u32) -> (&'static str, &'static str) {
    if server_version_num >= 100_000 {
        ("pg_switch_wal", "pg_walfile_name")
    } else {
        ("pg_switch_xlog", "pg_xlogfile_name")
    }
}

/// Resolve a libpq conninfo for the live-`PostgreSQL` checks, or `None` when no
/// DB source is configured. `database_url` is the already-read `DATABASE_URL`.
///
/// `DATABASE_URL` wins when set; otherwise a connection is derived from
/// `pg1-host` + `pg1-port` / `pg1-socket-path` / `pg1-database` / `pg1-user`.
/// A bare local `pg1-path` is **not** enough to imply a live server (matching
/// `stanza.rs`), so the live checks are skipped in that case.
fn derive_conninfo_with_url(config: &LoadedConfig, database_url: Option<&str>) -> Option<String> {
    if let Some(url) = database_url
        && !url.is_empty()
    {
        return Some(url.to_owned());
    }

    let opt = |name: &str| -> Option<String> {
        match config.options.get(&(name.to_owned(), None)) {
            Some(OptionValue::String(s) | OptionValue::Path(s) | OptionValue::StringId(s)) if !s.is_empty() => Some(s.clone()),
            Some(OptionValue::Integer(i)) => Some(i.to_string()),
            _ => None,
        }
    };

    let host = opt("pg1-host").or_else(|| opt("pg1-socket-path"))?;
    let mut parts: Vec<String> = vec![format!("host={host}")];
    if let Some(p) = opt("pg1-port") {
        parts.push(format!("port={p}"));
    }
    if let Some(db) = opt("pg1-database") {
        parts.push(format!("dbname={db}"));
    }
    if let Some(user) = opt("pg1-user") {
        parts.push(format!("user={user}"));
    }
    Some(parts.join(" "))
}

/// Resolve `--archive-timeout` (a [`OptionValue::Time`] in milliseconds) into a
/// [`Duration`], defaulting to 60s (the pgBackRest default) when unset.
fn archive_timeout(config: &LoadedConfig) -> Duration {
    match config.options.get(&("archive-timeout".to_owned(), None)) {
        Some(OptionValue::Time(ms)) => Duration::from_millis(*ms),
        Some(OptionValue::Integer(secs)) if *secs >= 0 => Duration::from_secs(u64::try_from(*secs).unwrap_or(60)),
        _ => Duration::from_mins(1),
    }
}

/// Repo-side `check`: confirm the stanza is initialized and the repo writable.
///
/// Confirms the info files agree and the repository is writable. Used by the
/// no-DB unit tests; the public [`check`] entry point additionally runs the
/// live-PG checks when a connection is derivable.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] when no `--stanza` was supplied.
/// - [`CommandError::Other`] when the stanza is not initialized, the info files
///   disagree on database identity, or the write probe round trip mismatches.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for backend failures
///   during the write probe.
pub fn check_inner(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<CheckReport, CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;

    // 2. The stanza must be initialized — both info files must load.
    let archive_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    let backup_path = PathBuf::from(format!("backup/{stanza}/backup.info"));

    let archive = InfoArchive::load(repo_storage, &archive_path)
        .map_err(|err| CommandError::Other(format!("stanza '{stanza}' is not initialized: archive.info: {err}")))?;
    let backup = InfoBackup::load(repo_storage, &backup_path)
        .map_err(|err| CommandError::Other(format!("stanza '{stanza}' is not initialized: backup.info: {err}")))?;

    // 3. The two info files must agree on the database identity.
    if archive.db_system_id != backup.db_system_id || archive.db_version != backup.db_version {
        return Err(CommandError::Other(
            "archive.info / backup.info disagree on db identity".to_owned(),
        ));
    }

    // 4. The repository must be writable: write -> read-back -> compare -> remove.
    let repo_writable = probe_repo_writable(repo_storage, stanza)?;

    // 5. The WAL archive must be functional: write a test object into the
    //    current archive-id directory, read it back, compare, and remove it.
    //    The current archive-id is `<db-version>-<db-id>`, derived from the
    //    active `[db]` block of `archive.info` (mirrors `infoArchiveId` /
    //    `archiveId` in the C tree).
    let archive_id = format!("{}-{}", archive.db_version, archive.db_id);
    let archive_ok = probe_archive_round_trip(repo_storage, stanza, &archive_id)?;

    Ok(CheckReport {
        stanza: stanza.to_owned(),
        db_version: backup.db_version,
        db_system_id: backup.db_system_id,
        repo_writable,
        archive_id,
        archive_ok,
        pg: None,
    })
}

/// Run the live-`PostgreSQL` half of `check` (the C `checkArchive` cluster
/// half) against `db`, verifying the cluster matches the stanza and that a
/// freshly-archived WAL segment lands in the repo.
///
/// This is the testable core: `db` is any [`CheckDb`] (a fake in unit tests, a
/// [`ConnCheckDb`] in the real path) and [`wait_for_segment`] polls the repo
/// [`Storage`] for the segment. The `archive` info file supplies the identity to
/// cross-check and the `archive_id` directory to poll.
///
/// # Errors
///
/// [`CommandError::Other`] when the cluster cannot be reached, its identity does
/// not match the stanza, archiving is misconfigured, or the segment never
/// arrives within `timeout`.
#[allow(clippy::too_many_arguments)]
fn check_pg<D: CheckDb>(
    db: &mut D,
    archive: &InfoArchive,
    archive_id: &str,
    stanza: &str,
    repo_storage: &dyn Storage,
    timeout: Duration,
    poll_interval: Duration,
    archive_mode_check: bool,
) -> Result<PgCheckReport, CommandError> {
    // 6. Identity cross-check: server version + system id must match the
    //    stanza's active db identity (exactly as the C check confirms the
    //    cluster is the one the stanza was created for).
    let server_version_num = db.version()?;
    let system_id = db.system_id()?;

    let version_label = pg_version_label_from_num(server_version_num)
        .ok_or_else(|| CommandError::Other(format!("unsupported server_version_num {server_version_num}")))?;

    if system_id != archive.db_system_id {
        return Err(CommandError::Other(format!(
            "cluster system-id {system_id} does not match stanza '{stanza}' archive.info db-system-id {}",
            archive.db_system_id
        )));
    }
    if version_label != archive.db_version {
        return Err(CommandError::Other(format!(
            "cluster version {version_label} does not match stanza '{stanza}' archive.info db-version {}",
            archive.db_version
        )));
    }

    // Whether the cluster is a standby (in recovery) — needed both to validate
    // archive_mode (a primary should not be 'always') and to pick the WAL-switch
    // strategy below.
    let in_recovery = db.is_in_recovery()?;

    // 7. archive_mode must be enabled (archive-mode-check) and archive_command
    //    must reference pgbackrest. `always` is expected only on a standby; a
    //    primary reporting `always` is unexpected and rejected. The archive_mode
    //    half is skipped when archive-mode-check is off.
    let (archive_mode, archive_command) = db.archive_settings()?;
    if archive_mode_check {
        match archive_mode.as_str() {
            "on" => {}
            "always" if in_recovery => {}
            "always" => {
                return Err(CommandError::Other(
                    "archive_mode is 'always' on a primary, which is unexpected; expected 'on'".to_owned(),
                ));
            }
            other => {
                return Err(CommandError::Other(format!("archive_mode must be enabled (is '{other}')")));
            }
        }
    }
    if !archive_command.contains("pgbackrest") {
        return Err(CommandError::Other(format!(
            "archive_command '{archive_command}' does not reference pgbackrest"
        )));
    }

    // 8. Force a fresh segment to archive (primary), or pick the latest already
    //    produced segment (standby — a switch cannot be forced in recovery).
    let wal_segment = if in_recovery {
        db.last_wal_segment(server_version_num)?
    } else {
        db.create_restore_point("pgBackRest Archive Check")?;
        db.switch_wal(server_version_num)?
    };

    // 9. Wait (bounded) for that segment to land in the repo via the cluster's
    //    archive_command -> archive-push.
    let archive_wait_ok = wait_for_segment(repo_storage, stanza, archive_id, &wal_segment, timeout, poll_interval)?;
    if !archive_wait_ok {
        return Err(CommandError::Other(format!(
            "WAL segment '{wal_segment}' did not arrive in the repository for stanza '{stanza}' \
             archive-id '{archive_id}' within {}s; check the cluster's archive_command",
            timeout.as_secs()
        )));
    }

    Ok(PgCheckReport {
        server_version_num,
        system_id,
        in_recovery,
        wal_segment,
        archive_wait_ok,
    })
}

/// Poll `archive/<stanza>/<archive-id>/` until an entry matching `segment`
/// appears or `timeout` elapses. Returns `Ok(true)` on a hit, `Ok(false)` on
/// timeout.
///
/// Matching is prefix-based (`walSegmentFind` in the C tree): an archived
/// segment may carry a compression / checksum suffix (`<segment>-<sha>.gz`), so
/// any directory entry whose file name starts with `segment` counts.
fn wait_for_segment(
    repo_storage: &dyn Storage,
    stanza: &str,
    archive_id: &str,
    segment: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<bool, CommandError> {
    let archive_dir = PathBuf::from(format!("archive/{stanza}/{archive_id}"));
    let deadline = Instant::now() + timeout;

    loop {
        if segment_present(repo_storage, &archive_dir, segment)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(poll_interval.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Whether a WAL `segment` (by prefix) is present under `archive_dir`. A missing
/// directory simply means "not yet archived" and is reported as `false`.
fn segment_present(repo_storage: &dyn Storage, archive_dir: &Path, segment: &str) -> Result<bool, CommandError> {
    let entries = match repo_storage.list(archive_dir) {
        Ok(entries) => entries,
        Err(pgbr_storage::StorageError::NotFound { .. }) => return Ok(false),
        Err(err) => return Err(CommandError::Storage(err)),
    };
    Ok(entries.iter().any(|entry| {
        entry.path.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
            name == segment || name.starts_with(&format!("{segment}-")) || name.starts_with(&format!("{segment}."))
        })
    }))
}

/// Map a `server_version_num` (e.g. `160004`, `90600`) to a pgBackRest major
/// version label (`"9.6"`, `"10"`, …), mirroring `stanza.rs`'s helper of the
/// same name. PG < 10 keeps the `9.x` minor; PG >= 10 collapses to the bare
/// major. Returns `None` for a version with no registry entry.
fn pg_version_label_from_num(server_version_num: u32) -> Option<&'static str> {
    let label = if server_version_num < 100_000 {
        format!("{}.{}", server_version_num / 10_000, (server_version_num % 10_000) / 100)
    } else {
        (server_version_num / 10_000).to_string()
    };
    pgbr_postgres::version::by_label(&label).map(|v| v.label)
}

/// Write a small probe file under `<stanza>/`, read it back, compare, then
/// remove it. Returns `Ok(true)` only when the round trip matched.
fn probe_repo_writable(repo_storage: &dyn Storage, stanza: &str) -> Result<bool, CommandError> {
    let probe_path = PathBuf::from(format!("{stanza}/check-{}", std::process::id()));
    let payload = format!("pgbackrest check probe for stanza '{stanza}'").into_bytes();

    // Ensure the stanza directory exists so the probe write does not fail merely
    // because the repo has only the `archive/<stanza>` and `backup/<stanza>`
    // subtrees but no `<stanza>/` directory of its own. `create_path` is a no-op
    // when the directory already exists.
    repo_storage.create_path(&PathBuf::from(stanza), true)?;

    // Write.
    {
        let mut writer: Box<dyn IoWrite> = repo_storage.open_write(&probe_path)?;
        writer.write(&payload)?;
        writer.flush()?;
        writer.close()?;
    }

    // Read back and compare. Always attempt removal afterwards so a comparison
    // failure does not leak the probe file.
    let read_result: Result<Vec<u8>, CommandError> = (|| {
        let mut reader: Box<dyn IoRead> = repo_storage.open_read(&probe_path)?;
        Ok(reader.read_all()?)
    })();

    let remove_result = repo_storage.remove(&probe_path, true);

    let read_back = read_result?;
    remove_result?;

    if read_back == payload {
        Ok(true)
    } else {
        Err(CommandError::Other(format!(
            "repo write probe for stanza '{stanza}' read back unexpected content"
        )))
    }
}

/// WAL-archive round trip: write a small test object into the stanza's current
/// archive-id directory, read it back, byte-compare, then remove it. Returns
/// `Ok(true)` only when the round trip matched.
///
/// This is the repo-side half of the C `checkArchive`: rather than asking a
/// live cluster to push a WAL segment and waiting for the async archiver, it
/// directly exercises the repository's `archive/<stanza>/<archive-id>/` subtree
/// — the same path WAL segments land in — to confirm the archive store is
/// readable and writable. The test object is named `<archive-id>.check-<pid>`
/// so it cannot collide with a real WAL segment (which is a hex name) and is
/// cleaned up even on read/compare failure.
fn probe_archive_round_trip(repo_storage: &dyn Storage, stanza: &str, archive_id: &str) -> Result<bool, CommandError> {
    let archive_dir = format!("archive/{stanza}/{archive_id}");
    let test_name = format!("{archive_id}.check-{}", std::process::id());
    let test_path = PathBuf::from(format!("{archive_dir}/{test_name}"));
    let payload = format!("pgbackrest archive check for stanza '{stanza}' archive-id '{archive_id}'").into_bytes();

    // Ensure the archive-id directory exists. On a freshly-created stanza that
    // has never archived a segment the directory may be absent; `create_path`
    // is a no-op when it already exists.
    repo_storage.create_path(&PathBuf::from(&archive_dir), true)?;

    // Write.
    {
        let mut writer: Box<dyn IoWrite> = repo_storage.open_write(&test_path)?;
        writer.write(&payload)?;
        writer.flush()?;
        writer.close()?;
    }

    // Read back and compare. Always attempt removal afterwards so a comparison
    // failure does not leak the test object.
    let read_result: Result<Vec<u8>, CommandError> = (|| {
        let mut reader: Box<dyn IoRead> = repo_storage.open_read(&test_path)?;
        Ok(reader.read_all()?)
    })();

    let remove_result = repo_storage.remove(&test_path, true);

    let read_back = read_result?;
    remove_result?;

    if read_back == payload {
        Ok(true)
    } else {
        Err(CommandError::Other(format!(
            "archive check for stanza '{stanza}' archive-id '{archive_id}' read back unexpected content"
        )))
    }
}

/// Build a [`CheckReport`], adding the live-PG checks when a cluster is reachable.
///
/// A connection is derived from `config` / `DATABASE_URL`. The repo-side checks
/// always run; the live checks run only when a cluster is configured.
///
/// # Errors
///
/// Propagates any error from the repo-side [`check_inner`] or the live-PG
/// [`check_pg`].
pub fn run_check(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<CheckReport, CommandError> {
    let mut report = check_inner(config, repo_storage)?;

    // Live-PG half: only when a connection is derivable (matching stanza.rs).
    let Some(conninfo) = derive_conninfo_with_url(config, std::env::var("DATABASE_URL").ok().as_deref()) else {
        return Ok(report);
    };

    // Reload the archive info for the identity cross-check / archive-id.
    // `check_inner` already proved both info files load and agree, so this load
    // is reliable.
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;
    let archive = InfoArchive::load(repo_storage, &PathBuf::from(format!("archive/{stanza}/archive.info")))
        .map_err(|err| CommandError::Other(format!("stanza '{stanza}' archive.info: {err}")))?;

    let mut conn = Connection::open(&conninfo).map_err(|err| CommandError::Other(err.to_string()))?;
    let mut db = ConnCheckDb::new(&mut conn);
    let pg = check_pg(
        &mut db,
        &archive,
        &report.archive_id,
        stanza,
        repo_storage,
        archive_timeout(config),
        Duration::from_millis(250),
        archive_mode_check(config),
    )?;
    report.pg = Some(pg);
    Ok(report)
}

/// Whether `archive-mode-check` is enabled (default true, the option model's
/// default): only an explicit `false` disables the cluster's `archive_mode`
/// validation in the live-PG check.
fn archive_mode_check(config: &LoadedConfig) -> bool {
    !matches!(
        config.options.get(&("archive-mode-check".to_owned(), None)),
        Some(OptionValue::Boolean(false))
    )
}

/// `check` — verify the configured repository is reachable, the stanza is
/// initialized, and (when a cluster is configured) the live WAL archive path
/// works, then print the resulting [`CheckReport`].
///
/// `pg_storage` is accepted for dispatch-signature compatibility.
///
/// # Errors
///
/// Propagates any error from [`run_check`].
#[allow(clippy::print_stdout)]
pub fn check(config: &LoadedConfig, repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let report = run_check(config, repo_storage)?;
    println!(
        "stanza '{}' check ok: db-version={} db-system-id={} repo-writable={} archive-id={} archive-ok={}",
        report.stanza, report.db_version, report.db_system_id, report.repo_writable, report.archive_id, report.archive_ok
    );
    if let Some(pg) = &report.pg {
        println!(
            "  pg check ok: server-version-num={} system-id={} in-recovery={} wal-segment={} archive-wait-ok={}",
            pg.server_version_num, pg.system_id, pg.in_recovery, pg.wal_segment, pg.archive_wait_ok
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::time::Duration;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{InfoArchive, InfoBackup};
    use pgbr_io::IoWrite;
    use pgbr_storage::{Posix, Storage};
    use tempfile::TempDir;

    use super::{
        CheckDb, CommandError, archive_timeout, check_inner, check_pg, derive_conninfo_with_url, pg_version_label_from_num,
        wait_for_segment, wal_function_names,
    };

    /// In-memory [`CheckDb`] driving the live-PG flow without a real server.
    struct FakeDb {
        server_version_num: u32,
        system_id: u64,
        in_recovery: bool,
        archive_mode: String,
        archive_command: String,
        switch_segment: String,
        last_segment: String,
        restore_point: Option<String>,
        switched: bool,
        fail_version: bool,
    }

    impl Default for FakeDb {
        fn default() -> Self {
            Self {
                server_version_num: 160_004,
                system_id: 6_873_049_345_984_568_091,
                in_recovery: false,
                archive_mode: "on".to_owned(),
                archive_command: "pgbackrest --stanza=demo archive-push %p".to_owned(),
                switch_segment: "000000010000000000000003".to_owned(),
                last_segment: "000000010000000000000002".to_owned(),
                restore_point: None,
                switched: false,
                fail_version: false,
            }
        }
    }

    impl CheckDb for FakeDb {
        fn version(&mut self) -> Result<u32, CommandError> {
            if self.fail_version {
                return Err(CommandError::Other("simulated connect failure".to_owned()));
            }
            Ok(self.server_version_num)
        }
        fn system_id(&mut self) -> Result<u64, CommandError> {
            Ok(self.system_id)
        }
        fn is_in_recovery(&mut self) -> Result<bool, CommandError> {
            Ok(self.in_recovery)
        }
        fn archive_settings(&mut self) -> Result<(String, String), CommandError> {
            Ok((self.archive_mode.clone(), self.archive_command.clone()))
        }
        fn create_restore_point(&mut self, name: &str) -> Result<(), CommandError> {
            self.restore_point = Some(name.to_owned());
            Ok(())
        }
        fn switch_wal(&mut self, _server_version_num: u32) -> Result<String, CommandError> {
            self.switched = true;
            Ok(self.switch_segment.clone())
        }
        fn last_wal_segment(&mut self, _server_version_num: u32) -> Result<String, CommandError> {
            Ok(self.last_segment.clone())
        }
    }

    /// Drop a WAL segment file into `archive/<stanza>/<archive-id>/`, optionally
    /// with a compression-style suffix, to simulate archive-push landing it.
    fn land_segment(storage: &dyn Storage, stanza: &str, archive_id: &str, name: &str) {
        let dir = Path::new("archive").join(stanza).join(archive_id);
        storage.create_path(&dir, true).expect("create archive-id dir");
        let mut w = storage.open_write(&dir.join(name)).expect("write segment");
        w.write(b"wal").expect("write bytes");
        w.flush().expect("flush");
        w.close().expect("close");
    }

    fn config_for(stanza: Option<&str>) -> LoadedConfig {
        LoadedConfig {
            command: "check".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options: BTreeMap::new(),
            params: Vec::new(),
        }
    }

    fn archive_info(system_id: u64, version: &str) -> InfoArchive {
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: system_id,
            db_version: version.to_owned(),
            history: BTreeMap::new(),
        }
    }

    fn backup_info(system_id: u64, version: &str) -> InfoBackup {
        InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: system_id,
            db_version: version.to_owned(),
            db_catalog_version: 202_209_061,
            db_control_version: 1300,
            current: BTreeMap::new(),
            history: BTreeMap::new(),
        }
    }

    /// Seed both info files for `stanza` with the given (per-file) identity.
    fn seed_stanza(storage: &dyn Storage, stanza: &str, archive: &InfoArchive, backup: &InfoBackup) {
        storage
            .create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive dir");
        storage
            .create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup dir");
        archive
            .save(storage, Path::new(&format!("archive/{stanza}/archive.info")))
            .expect("save archive.info");
        backup
            .save(storage, Path::new(&format!("backup/{stanza}/backup.info")))
            .expect("save backup.info");
    }

    fn posix() -> (TempDir, Posix) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(dir.path());
        (dir, storage)
    }

    #[test]
    fn check_requires_stanza() {
        let (_dir, storage) = posix();
        let cfg = config_for(None);
        match check_inner(&cfg, &storage).expect_err("check requires a stanza") {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn check_uninitialized_stanza_fails() {
        let (_dir, storage) = posix();
        let cfg = config_for(Some("demo"));
        match check_inner(&cfg, &storage).expect_err("uninitialized stanza must fail") {
            CommandError::Other(msg) => assert!(msg.contains("not initialized"), "expected 'not initialized' in {msg:?}"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn check_initialized_stanza_passes() {
        let (_dir, storage) = posix();
        let system_id = 6_873_049_345_984_568_091;
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "14"),
            &backup_info(system_id, "14"),
        );

        let cfg = config_for(Some("demo"));
        let report = check_inner(&cfg, &storage).expect("initialized stanza should pass");
        assert_eq!(report.stanza, "demo");
        assert_eq!(report.db_version, "14");
        assert_eq!(report.db_system_id, system_id);
        assert!(report.repo_writable, "repo should be reported writable");
        // archive_info() seeds db_id = 1, so the archive-id is `<version>-1`.
        assert_eq!(report.archive_id, "14-1");
        assert!(report.archive_ok, "archive round trip should succeed");
    }

    #[test]
    fn check_mismatched_db_identity_fails() {
        let (_dir, storage) = posix();
        // archive.info and backup.info carry different system ids.
        seed_stanza(&storage, "demo", &archive_info(1111, "14"), &backup_info(2222, "14"));

        let cfg = config_for(Some("demo"));
        match check_inner(&cfg, &storage).expect_err("mismatched identity must fail") {
            CommandError::Other(msg) => assert!(
                msg.contains("disagree on db identity"),
                "expected identity-disagreement message, got {msg:?}"
            ),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn check_probe_file_is_cleaned_up() {
        let (_dir, storage) = posix();
        let system_id = 42;
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "16"),
            &backup_info(system_id, "16"),
        );

        let cfg = config_for(Some("demo"));
        check_inner(&cfg, &storage).expect("check should pass");

        // No `check-*` probe file should survive under the stanza directory.
        let entries = storage.list(Path::new("demo")).unwrap_or_default();
        let leftover: Vec<_> = entries
            .iter()
            .filter_map(|e| e.path.file_name().and_then(|n| n.to_str()))
            .filter(|name| name.starts_with("check-"))
            .collect();
        assert!(leftover.is_empty(), "probe file(s) left behind: {leftover:?}");

        // The probe file itself must be gone.
        let probe = Path::new("demo").join(format!("check-{}", std::process::id()));
        assert!(
            matches!(storage.exists(&probe), Ok(false)),
            "probe file should not exist after check"
        );
    }

    #[test]
    fn check_archive_round_trip_ok() {
        let (_dir, storage) = posix();
        let system_id = 6_873_049_345_984_568_091;
        // Use a non-default version so the archive-id is unambiguous (`15-1`).
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "15"),
            &backup_info(system_id, "15"),
        );

        let cfg = config_for(Some("demo"));
        let report = check_inner(&cfg, &storage).expect("archive round trip should succeed");
        assert_eq!(report.archive_id, "15-1");
        assert!(report.archive_ok, "archive round trip should be reported ok");

        // The test object must not survive in the archive-id directory.
        let archive_id_dir = Path::new("archive").join("demo").join("15-1");
        let entries = storage.list(&archive_id_dir).unwrap_or_default();
        let leftover: Vec<_> = entries
            .iter()
            .filter_map(|e| e.path.file_name().and_then(|n| n.to_str()))
            .filter(|name| name.contains(".check-"))
            .collect();
        assert!(leftover.is_empty(), "archive test object(s) left behind: {leftover:?}");

        // The test object itself must be gone.
        let test_obj = archive_id_dir.join(format!("15-1.check-{}", std::process::id()));
        assert!(
            matches!(storage.exists(&test_obj), Ok(false)),
            "archive test object should not exist after check"
        );
    }

    #[test]
    fn check_archive_fails_when_archive_dir_unwritable() {
        let (_dir, storage) = posix();
        let system_id = 99;
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "16"),
            &backup_info(system_id, "16"),
        );

        // Place a regular *file* exactly where the archive-id directory
        // (`archive/demo/16-1`) needs to be created. `create_dir_all` then
        // fails because a non-directory already occupies the path, so the
        // archive round trip cannot proceed.
        let blocker = Path::new("archive").join("demo").join("16-1");
        {
            let mut w = storage.open_write(&blocker).expect("write blocker file");
            w.write(b"not a directory").expect("write blocker bytes");
            w.flush().expect("flush blocker");
            w.close().expect("close blocker");
        }

        let cfg = config_for(Some("demo"));
        let err = check_inner(&cfg, &storage).expect_err("archive check must fail when the dir is unwritable");
        assert!(
            matches!(err, CommandError::Storage(_) | CommandError::Io(_)),
            "expected a Storage/Io error, got {err:?}"
        );
    }

    // ---- live-PG (CheckDb) flow, driven by FakeDb + in-memory repo Storage ----

    #[test]
    fn wal_function_names_switch_on_version() {
        assert_eq!(wal_function_names(160_004), ("pg_switch_wal", "pg_walfile_name"));
        assert_eq!(wal_function_names(100_000), ("pg_switch_wal", "pg_walfile_name"));
        assert_eq!(wal_function_names(90_600), ("pg_switch_xlog", "pg_xlogfile_name"));
    }

    #[test]
    fn pg_version_label_maps_num_to_label() {
        assert_eq!(pg_version_label_from_num(160_004), Some("16"));
        assert_eq!(pg_version_label_from_num(100_000), Some("10"));
        assert_eq!(pg_version_label_from_num(90_600), Some("9.6"));
        assert_eq!(pg_version_label_from_num(999_999), None);
    }

    #[test]
    fn archive_timeout_defaults_and_reads_option() {
        let cfg = config_for(Some("demo"));
        assert_eq!(archive_timeout(&cfg), Duration::from_mins(1));

        let mut cfg2 = config_for(Some("demo"));
        cfg2.options
            .insert(("archive-timeout".to_owned(), None), OptionValue::Time(5_000));
        assert_eq!(archive_timeout(&cfg2), Duration::from_secs(5));
    }

    #[test]
    fn derive_conninfo_skips_without_db_source() {
        let cfg = config_for(Some("demo"));
        assert_eq!(derive_conninfo_with_url(&cfg, None), None);
        assert_eq!(derive_conninfo_with_url(&cfg, Some("")), None);
        assert_eq!(
            derive_conninfo_with_url(&cfg, Some("host=/tmp dbname=postgres")).as_deref(),
            Some("host=/tmp dbname=postgres"),
        );
    }

    #[test]
    fn derive_conninfo_builds_from_pg1_options() {
        let mut cfg = config_for(Some("demo"));
        cfg.options
            .insert(("pg1-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        cfg.options.insert(("pg1-port".to_owned(), None), OptionValue::Integer(5433));
        let conninfo = derive_conninfo_with_url(&cfg, None).expect("pg1-host present -> conninfo");
        assert!(conninfo.contains("host=db.example"), "conninfo was {conninfo:?}");
        assert!(conninfo.contains("port=5433"), "conninfo was {conninfo:?}");
    }

    #[test]
    fn wait_for_segment_finds_exact_and_suffixed() {
        let (_dir, storage) = posix();
        land_segment(&storage, "demo", "16-1", "000000010000000000000003");
        assert!(
            wait_for_segment(
                &storage,
                "demo",
                "16-1",
                "000000010000000000000003",
                Duration::from_millis(0),
                Duration::from_millis(1),
            )
            .expect("poll ok"),
            "exact segment should be found"
        );

        // A compression/checksum suffix must still match by prefix.
        land_segment(&storage, "demo", "16-1", "000000010000000000000004-abcdef0123456789.gz");
        assert!(
            wait_for_segment(
                &storage,
                "demo",
                "16-1",
                "000000010000000000000004",
                Duration::from_millis(0),
                Duration::from_millis(1),
            )
            .expect("poll ok"),
            "suffixed segment should match by prefix"
        );
    }

    #[test]
    fn wait_for_segment_times_out_when_absent() {
        let (_dir, storage) = posix();
        // archive-id directory does not even exist -> not found is "not yet".
        let found = wait_for_segment(
            &storage,
            "demo",
            "16-1",
            "000000010000000000000009",
            Duration::from_millis(20),
            Duration::from_millis(5),
        )
        .expect("poll ok");
        assert!(!found, "missing segment must time out to false");
    }

    #[test]
    fn check_pg_primary_switches_waits_and_succeeds() {
        let (_dir, storage) = posix();
        let archive = archive_info(6_873_049_345_984_568_091, "16");
        // Segment lands before/at the poll, so the wait succeeds immediately.
        land_segment(&storage, "demo", "16-1", "000000010000000000000003");

        let mut db = FakeDb::default();
        let report = check_pg(
            &mut db,
            &archive,
            "16-1",
            "demo",
            &storage,
            Duration::from_millis(50),
            Duration::from_millis(2),
            true,
        )
        .expect("primary check should succeed");

        assert!(!report.in_recovery);
        assert_eq!(report.wal_segment, "000000010000000000000003");
        assert!(report.archive_wait_ok);
        assert_eq!(report.server_version_num, 160_004);
        // A primary must have created the restore point and switched WAL.
        assert_eq!(db.restore_point.as_deref(), Some("pgBackRest Archive Check"));
        assert!(db.switched, "primary must force a WAL switch");
    }

    #[test]
    fn check_pg_standby_skips_switch_and_uses_last_segment() {
        let (_dir, storage) = posix();
        let archive = archive_info(6_873_049_345_984_568_091, "16");
        land_segment(&storage, "demo", "16-1", "000000010000000000000002");

        let mut db = FakeDb {
            in_recovery: true,
            ..FakeDb::default()
        };
        let report = check_pg(
            &mut db,
            &archive,
            "16-1",
            "demo",
            &storage,
            Duration::from_millis(50),
            Duration::from_millis(2),
            true,
        )
        .expect("standby check should succeed");

        assert!(report.in_recovery);
        assert_eq!(report.wal_segment, "000000010000000000000002");
        assert!(report.archive_wait_ok);
        // A standby must NOT switch WAL or create a restore point.
        assert!(!db.switched, "standby must not switch WAL");
        assert!(db.restore_point.is_none(), "standby must not create a restore point");
    }

    #[test]
    fn check_pg_fails_when_segment_never_arrives() {
        let (_dir, storage) = posix();
        let archive = archive_info(6_873_049_345_984_568_091, "16");
        // No segment landed -> the wait must time out and the check must fail.
        let mut db = FakeDb::default();
        let err = check_pg(
            &mut db,
            &archive,
            "16-1",
            "demo",
            &storage,
            Duration::from_millis(20),
            Duration::from_millis(5),
            true,
        )
        .expect_err("missing segment must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("did not arrive"), "message was {msg:?}"),
            other => panic!("expected Other(did not arrive), got {other:?}"),
        }
    }

    #[test]
    fn check_pg_rejects_system_id_mismatch() {
        let (_dir, storage) = posix();
        let archive = archive_info(1234, "16");
        let mut db = FakeDb::default(); // system_id differs from 1234
        let err = check_pg(
            &mut db,
            &archive,
            "16-1",
            "demo",
            &storage,
            Duration::from_millis(5),
            Duration::from_millis(1),
            true,
        )
        .expect_err("system-id mismatch must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("system-id"), "message was {msg:?}"),
            other => panic!("expected Other(system-id), got {other:?}"),
        }
    }

    #[test]
    fn check_pg_rejects_version_mismatch() {
        let (_dir, storage) = posix();
        // archive.info says 14 but the fake cluster reports 16.
        let archive = archive_info(6_873_049_345_984_568_091, "14");
        let mut db = FakeDb::default();
        let err = check_pg(
            &mut db,
            &archive,
            "14-1",
            "demo",
            &storage,
            Duration::from_millis(5),
            Duration::from_millis(1),
            true,
        )
        .expect_err("version mismatch must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("version"), "message was {msg:?}"),
            other => panic!("expected Other(version), got {other:?}"),
        }
    }

    #[test]
    fn check_pg_rejects_archiving_disabled() {
        let (_dir, storage) = posix();
        let archive = archive_info(6_873_049_345_984_568_091, "16");

        let mut off = FakeDb {
            archive_mode: "off".to_owned(),
            ..FakeDb::default()
        };
        let err = check_pg(
            &mut off,
            &archive,
            "16-1",
            "demo",
            &storage,
            Duration::from_millis(5),
            Duration::from_millis(1),
            true,
        )
        .expect_err("archive_mode off must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("archive_mode"), "message was {msg:?}"),
            other => panic!("expected Other(archive_mode), got {other:?}"),
        }

        let mut bad_cmd = FakeDb {
            archive_command: "cp %p /somewhere/%f".to_owned(),
            ..FakeDb::default()
        };
        let err = check_pg(
            &mut bad_cmd,
            &archive,
            "16-1",
            "demo",
            &storage,
            Duration::from_millis(5),
            Duration::from_millis(1),
            true,
        )
        .expect_err("archive_command not referencing pgbackrest must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("archive_command"), "message was {msg:?}"),
            other => panic!("expected Other(archive_command), got {other:?}"),
        }
    }

    #[test]
    fn check_pg_propagates_connect_failure() {
        let (_dir, storage) = posix();
        let archive = archive_info(6_873_049_345_984_568_091, "16");
        let mut db = FakeDb {
            fail_version: true,
            ..FakeDb::default()
        };
        let err = check_pg(
            &mut db,
            &archive,
            "16-1",
            "demo",
            &storage,
            Duration::from_millis(5),
            Duration::from_millis(1),
            true,
        )
        .expect_err("connect failure must propagate");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("connect failure"), "message was {msg:?}"),
            other => panic!("expected Other(connect failure), got {other:?}"),
        }
    }

    #[test]
    fn run_check_skips_pg_without_db_source() {
        // No pg1-host / DATABASE_URL -> run_check returns the repo-side report
        // with `pg: None`. (Guard against a stray ambient DATABASE_URL.)
        if std::env::var("DATABASE_URL").is_ok() {
            return;
        }
        let (_dir, storage) = posix();
        let system_id = 6_873_049_345_984_568_091;
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "16"),
            &backup_info(system_id, "16"),
        );
        let cfg = config_for(Some("demo"));
        let report = super::run_check(&cfg, &storage).expect("repo-side check should pass");
        assert!(report.pg.is_none(), "no DB configured -> pg checks skipped");
        assert!(report.archive_ok);
    }

    // Live-PostgreSQL end-to-end check through the real ConnCheckDb path.
    // Skipped by default; run with `cargo test -p pgbr-command -- --include-ignored`
    // and DATABASE_URL pointing at a reachable cluster.
    #[test]
    #[ignore = "requires a running PostgreSQL server (set DATABASE_URL)"]
    fn check_pg_against_real_database() {
        use pgbr_db::Connection;

        use super::ConnCheckDb;

        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let mut conn = Connection::open(&url).expect("open DATABASE_URL connection");
        let mut db = ConnCheckDb::new(&mut conn);

        // Smoke-test each CheckDb accessor against the live server.
        let version = db.version().expect("server_version_num");
        assert!(version >= 90_600, "unexpected server_version_num {version}");
        let sysid = db.system_id().expect("system_identifier");
        assert_ne!(sysid, 0);
        let _ = db.is_in_recovery().expect("pg_is_in_recovery");
        let (mode, _command) = db.archive_settings().expect("archive settings");
        assert!(!mode.is_empty(), "archive_mode should be readable");

        // On a primary, exercise the restore-point + switch path and confirm the
        // returned name is a 24-hex WAL segment.
        if !db.is_in_recovery().expect("recovery") {
            db.create_restore_point("pgBackRest Archive Check")
                .expect("create restore point");
            let segment = db.switch_wal(version).expect("switch wal");
            assert_eq!(segment.len(), 24, "WAL segment name should be 24 hex chars: {segment}");
        }
    }
}
