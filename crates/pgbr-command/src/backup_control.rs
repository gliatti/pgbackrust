//! The `PostgreSQL` backup-control protocol abstraction.
//!
//! Real pgBackRest does not just copy the data directory: it brackets the file
//! copy with `PostgreSQL`'s online-backup control functions so the copied files
//! form a consistent, restorable image. C reference: `src/command/backup/backup.c`
//! (`backupStart` / `backupStop`) and `src/db/db.c` (`dbBackupStart` /
//! `dbBackupStop`).
//!
//! The protocol, per `PostgreSQL` major version:
//!
//! - **PG >= 15**: `SELECT lsn FROM pg_backup_start(label := $label, fast := $fast)`
//!   to begin, then `SELECT lsn, labelfile, spcmapfile FROM
//!   pg_backup_stop(wait_for_archive := true)` to finish.
//! - **PG < 15**: `SELECT lsn FROM pg_start_backup($label, $fast, false)` (the
//!   trailing `false` selects a *non-exclusive* backup) and
//!   `SELECT lsn, labelfile, spcmapfile FROM pg_stop_backup(false, true)`.
//!
//! A non-exclusive backup must run start and stop **on the same session**, so a
//! single [`BackupControl`] handle drives the whole bracket. The stop call
//! returns the `backup_label` and `tablespace_map` file contents, which the
//! backup command writes into the repository.
//!
//! # Testability
//!
//! Every libpq interaction is funnelled through the [`BackupControl`] trait so
//! the file-copy / manifest path can be exercised with an in-memory fake and no
//! live database. [`LibpqBackupControl`] is the production implementation
//! wrapping a [`pgbr_db::Connection`]; the SQL-string builders
//! ([`backup_start_sql`] / `backup_stop_sql`) are pure functions with their own
//! unit tests, and a test-only `FakeBackupControl` lives in the test module of
//! `backup.rs`.

use pgbr_db::{Connection, QueryRows};
use pgbr_io::{IoRead, IoWrite};

use crate::CommandError;
use crate::remote_db::RemoteDb;

/// SQL the [`BackupControl`] info / status methods run, shared by
/// [`LibpqBackupControl`] (libpq) and [`RemoteBackupControl`] (worker) so the
/// two paths never drift. `backup_start` / `backup_stop` use the version-aware
/// [`backup_start_sql`] / [`backup_stop_sql`] builders instead.
mod sql {
    /// `server_version_num` from `pg_settings` (an int4).
    pub const SERVER_VERSION_NUM: &str =
        "select (select setting from pg_catalog.pg_settings where name = 'server_version_num')::int4";
    /// `system_identifier` from `pg_control_system()` as text.
    pub const SYSTEM_IDENTIFIER: &str = "select system_identifier::text from pg_catalog.pg_control_system()";
    /// `pg_is_in_recovery()` as text (`t` / `f`).
    pub const IS_IN_RECOVERY: &str = "select pg_catalog.pg_is_in_recovery()::text";
    /// `pg_last_wal_replay_lsn()` as text (SQL `NULL` until WAL is replayed).
    pub const REPLAY_LSN: &str = "select pg_catalog.pg_last_wal_replay_lsn()::text";
    /// `wal_segment_size` in bytes, derived from `pg_settings` setting * unit.
    pub const WAL_SEGMENT_SIZE: &str = "select (setting::int8 * \
         case unit when '8kB' then 8192 when 'kB' then 1024 when 'MB' then 1048576 \
         when 'GB' then 1073741824 else 1 end)::text \
         from pg_catalog.pg_settings where name = 'wal_segment_size'";
    /// `timeline_id` from `pg_control_checkpoint()` as text.
    pub const TIMELINE: &str = "select timeline_id::text from pg_catalog.pg_control_checkpoint()";
    /// `archive_mode` setting.
    pub const ARCHIVE_MODE: &str = "select setting from pg_catalog.pg_settings where name = 'archive_mode'";
}

/// What [`BackupControl::server_info`] reports about the connected cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupServerInfo {
    /// `server_version_num` (e.g. `160004`, `90600`).
    pub server_version_num: u32,
    /// `pg_control.system_identifier`.
    pub system_identifier: u64,
}

impl BackupServerInfo {
    /// The major-version number used to select the backup-control SQL dialect.
    ///
    /// `server_version_num` encodes the major as `<major>00<minor>` for PG < 10
    /// (e.g. `90600` → major `906`, but the *release* major is 9) and
    /// `<major>0000` for PG >= 10 (`160004` → `16`). For the
    /// pre-15-vs-15+ branch the only thing that matters is whether the release
    /// major is `< 15`, so this returns the release major: `9` for the 9.x line,
    /// otherwise `server_version_num / 10000`.
    #[must_use]
    pub const fn release_major(&self) -> u32 {
        if self.server_version_num < 100_000 {
            9
        } else {
            self.server_version_num / 10_000
        }
    }

    /// Whether this server uses the PG >= 15 `pg_backup_start` / `pg_backup_stop`
    /// function names (vs the legacy `pg_start_backup` / `pg_stop_backup`).
    #[must_use]
    pub const fn uses_pg_backup_start(&self) -> bool {
        self.release_major() >= 15
    }
}

/// What [`BackupControl::backup_stop`] returns when the online backup is closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupStopResult {
    /// Textual stop LSN (`"XXXXXXXX/YYYYYYYY"`).
    pub lsn: String,
    /// Contents of the `backup_label` file to write into the backup root.
    pub label_file: String,
    /// Contents of the `tablespace_map` file. Empty when the cluster has no
    /// tablespaces (the file is then not written).
    pub spcmap_file: String,
}

/// The `PostgreSQL` backup-control protocol, abstracted away from libpq.
///
/// One handle drives a single non-exclusive backup from start to stop on the
/// same session. Implementors: [`LibpqBackupControl`] for a real connection and
/// the test-only `FakeBackupControl` for the DB-free unit tests.
pub trait BackupControl {
    /// Read the server version number + system identifier, used to validate the
    /// cluster against the stanza and to pick the backup-control SQL dialect.
    ///
    /// # Errors
    ///
    /// Surfaces query / parse failures as [`CommandError::Other`].
    fn server_info(&mut self) -> Result<BackupServerInfo, CommandError>;

    /// Begin the online backup, returning the start LSN as text.
    ///
    /// `fast` forces an immediate checkpoint (the resolved `start-fast` option).
    ///
    /// # Errors
    ///
    /// Surfaces query failures as [`CommandError::Other`].
    fn backup_start(&mut self, label: &str, fast: bool) -> Result<String, CommandError>;

    /// Finish the online backup, returning the stop LSN plus the `backup_label`
    /// and `tablespace_map` file contents.
    ///
    /// # Errors
    ///
    /// Surfaces query failures as [`CommandError::Other`].
    fn backup_stop(&mut self) -> Result<BackupStopResult, CommandError>;

    /// Stop a *stale* running backup left by a crashed prior run, returning
    /// `true` when one was actually stopped (and `false` when nothing was
    /// running). Backs the `--stop-auto` option.
    ///
    /// A backup that aborted after `pg_backup_start` leaves the cluster believing
    /// a backup is still in progress, which would make the next `pg_backup_start`
    /// fail. `stop-auto` calls `pg_backup_stop` to clear that state first. Because
    /// `pg_backup_stop` raises when *no* backup is running, the default
    /// implementation treats a query error as "nothing to stop" (`Ok(false)`)
    /// rather than failing the new backup. C ref: `dbBackupStop` invoked from
    /// `backup.c` when `cfgOptStopAuto` is set.
    ///
    /// # Errors
    ///
    /// The default implementation never errors (a failed stop means nothing was
    /// running); a custom implementation may surface [`CommandError::Other`].
    fn stop_running_backup(&mut self) -> Result<bool, CommandError> {
        Ok(self.backup_stop().is_ok())
    }

    /// Whether the cluster on this connection is in recovery (a standby).
    ///
    /// Mirrors `SELECT pg_is_in_recovery()`. Used by `backup-standby` to tell a
    /// standby (in recovery) from the primary.
    ///
    /// # Errors
    ///
    /// Surfaces query failures as [`CommandError::Other`].
    fn is_in_recovery(&mut self) -> Result<bool, CommandError>;

    /// The latest WAL location replayed by a standby, as text.
    ///
    /// Mirrors `SELECT pg_last_wal_replay_lsn()` (PG >= 10) — used to poll a
    /// standby until it has replayed past the backup start LSN before file copy.
    /// Returns `None` when the server reports SQL `NULL` (e.g. the standby has
    /// not replayed any WAL yet).
    ///
    /// # Errors
    ///
    /// Surfaces query failures as [`CommandError::Other`].
    fn replay_lsn(&mut self) -> Result<Option<String>, CommandError>;

    /// The cluster `wal_segment_size`, in bytes (e.g. `16777216` for the 16 MiB
    /// default).
    ///
    /// Mirrors `SELECT setting::int8 * (...) FROM pg_settings WHERE name =
    /// 'wal_segment_size'`. The size determines how an LSN maps to a WAL segment
    /// name ([`pgbr_postgres::lsn::lsn_to_wal_segment`]), so a non-default-segment
    /// cluster records the correct `backup-archive-start` / `backup-archive-stop`.
    ///
    /// # Errors
    ///
    /// Surfaces query / parse failures as [`CommandError::Other`].
    fn wal_segment_size(&mut self) -> Result<u64, CommandError>;

    /// The current timeline id of the cluster.
    ///
    /// Mirrors `SELECT timeline_id FROM pg_control_checkpoint()`. After a
    /// failover the timeline advances, so the WAL segment names a backup records
    /// must carry the live timeline rather than a hardcoded `1`.
    ///
    /// # Errors
    ///
    /// Surfaces query / parse failures as [`CommandError::Other`].
    fn timeline(&mut self) -> Result<u32, CommandError>;

    /// The cluster's `archive_mode` setting (`"on"`, `"off"`, or `"always"`).
    ///
    /// Mirrors `SELECT setting FROM pg_settings WHERE name = 'archive_mode'`.
    /// `backup` / `check` read this for `archive-mode-check`: WAL archiving must
    /// be enabled or a backup cannot rely on its required WAL reaching the repo.
    ///
    /// # Errors
    ///
    /// Surfaces query failures as [`CommandError::Other`].
    fn archive_mode(&mut self) -> Result<String, CommandError>;
}

/// Build the `pg_backup_start` / `pg_start_backup` SQL for a given server
/// version and parameters.
///
/// The `label` is single-quote-escaped so an apostrophe in a user-supplied
/// label cannot break out of the literal; the `fast` flag is rendered as the
/// SQL `true` / `false` keyword. Pure function — no I/O — so the dialect choice
/// is unit-testable without a server.
#[must_use]
pub fn backup_start_sql(info: &BackupServerInfo, label: &str, fast: bool) -> String {
    let label_lit = sql_quote(label);
    let fast_lit = sql_bool(fast);
    // `pg_backup_start` / `pg_start_backup` return a *scalar* `pg_lsn`, so the
    // function item in the FROM clause must be aliased (`… as lsn`) to give its
    // single output column the name `lsn` — otherwise the column is named after
    // the function and `select lsn` fails with `column "lsn" does not exist`.
    // pgBackRest's `db/db.c` uses the same `as lsn` alias.
    if info.uses_pg_backup_start() {
        // PG >= 15: keyword arguments, always non-exclusive.
        format!("select lsn::text as lsn from pg_catalog.pg_backup_start(label => {label_lit}, fast => {fast_lit}) as lsn")
    } else {
        // PG < 15: positional args; the trailing `false` selects a
        // non-exclusive backup (so start/stop must share this session).
        format!("select lsn::text as lsn from pg_catalog.pg_start_backup({label_lit}, {fast_lit}, false) as lsn")
    }
}

/// Build the `pg_backup_stop` / `pg_stop_backup` SQL for a given server version.
///
/// Both forms wait for the stop WAL to be archived (`wait_for_archive := true`).
/// Pure function — no I/O.
#[must_use]
pub fn backup_stop_sql(info: &BackupServerInfo) -> String {
    if info.uses_pg_backup_start() {
        // PG >= 15.
        "select lsn::text as lsn, labelfile, spcmapfile from pg_catalog.pg_backup_stop(wait_for_archive => true)".to_owned()
    } else {
        // PG < 15: pg_stop_backup(exclusive => false, wait_for_archive => true).
        "select lsn::text as lsn, labelfile, spcmapfile from pg_catalog.pg_stop_backup(false, true)".to_owned()
    }
}

/// Single-quote-escape a string literal for inlining into SQL (doubles every
/// embedded `'`). The result includes the surrounding quotes.
fn sql_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Render a boolean as the SQL `true` / `false` keyword.
const fn sql_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// The production [`BackupControl`] implementation, wrapping a live libpq
/// [`pgbr_db::Connection`]. All queries run on the one owned connection so a
/// non-exclusive backup's start and stop share a session.
pub struct LibpqBackupControl {
    conn: Connection,
    /// Cached server info, resolved lazily on first [`BackupControl::server_info`]
    /// so the dialect-selecting `backup_start` / `backup_stop` can reuse it
    /// without re-querying.
    info: Option<BackupServerInfo>,
}

impl LibpqBackupControl {
    /// Open a backup-control connection from a libpq conninfo string.
    ///
    /// # Errors
    ///
    /// [`CommandError::Other`] when the connection cannot be established.
    pub fn open(conninfo: &str) -> Result<Self, CommandError> {
        let conn = Connection::open(conninfo).map_err(|err| CommandError::Other(err.to_string()))?;
        Ok(Self { conn, info: None })
    }

    /// Wrap an already-open connection (used when the caller has the handle).
    #[must_use]
    pub const fn new(conn: Connection) -> Self {
        Self { conn, info: None }
    }

    /// Resolve (and cache) the server info, querying libpq only once.
    fn resolve_info(&mut self) -> Result<BackupServerInfo, CommandError> {
        if let Some(info) = &self.info {
            return Ok(info.clone());
        }
        let version_result = self
            .conn
            .query(sql::SERVER_VERSION_NUM)
            .map_err(|err| CommandError::Other(err.to_string()))?;
        let server_version_num = parse_server_version_num(version_result.value(0, 0).as_deref())?;

        let control_result = self
            .conn
            .query(sql::SYSTEM_IDENTIFIER)
            .map_err(|err| CommandError::Other(err.to_string()))?;
        let system_identifier = parse_system_identifier(control_result.value(0, 0).as_deref())?;

        let info = BackupServerInfo {
            server_version_num,
            system_identifier,
        };
        self.info = Some(info.clone());
        Ok(info)
    }
}

impl BackupControl for LibpqBackupControl {
    fn server_info(&mut self) -> Result<BackupServerInfo, CommandError> {
        self.resolve_info()
    }

    fn backup_start(&mut self, label: &str, fast: bool) -> Result<String, CommandError> {
        let info = self.resolve_info()?;
        let sql = backup_start_sql(&info, label, fast);
        let result = self.conn.query(&sql).map_err(|err| CommandError::Other(err.to_string()))?;
        result
            .value(0, 0)
            .ok_or_else(|| CommandError::Other("backup start returned no LSN".to_owned()))
    }

    fn backup_stop(&mut self) -> Result<BackupStopResult, CommandError> {
        let info = self.resolve_info()?;
        let sql = backup_stop_sql(&info);
        let result = self.conn.query(&sql).map_err(|err| CommandError::Other(err.to_string()))?;
        let lsn = result
            .value(0, 0)
            .ok_or_else(|| CommandError::Other("backup stop returned no LSN".to_owned()))?;
        // labelfile / spcmapfile may be SQL NULL on some paths; treat NULL as empty.
        let label_file = result.value(0, 1).unwrap_or_default();
        let spcmap_file = result.value(0, 2).unwrap_or_default();
        Ok(BackupStopResult {
            lsn,
            label_file,
            spcmap_file,
        })
    }

    fn is_in_recovery(&mut self) -> Result<bool, CommandError> {
        let result = self
            .conn
            .query(sql::IS_IN_RECOVERY)
            .map_err(|err| CommandError::Other(err.to_string()))?;
        Ok(parse_in_recovery(result.value(0, 0).as_deref()))
    }

    fn replay_lsn(&mut self) -> Result<Option<String>, CommandError> {
        let result = self
            .conn
            .query(sql::REPLAY_LSN)
            .map_err(|err| CommandError::Other(err.to_string()))?;
        // NULL (no WAL replayed yet) surfaces as `None` from `value`.
        Ok(result.value(0, 0))
    }

    fn wal_segment_size(&mut self) -> Result<u64, CommandError> {
        // `current_setting('wal_segment_size')` returns a unit-suffixed string
        // (e.g. "16MB"); read the raw byte count from pg_settings instead, where
        // `setting * unit` is the size in the unit's base. pgBackRest derives the
        // byte size the same way (setting times the documented byte multiplier).
        let result = self
            .conn
            .query(sql::WAL_SEGMENT_SIZE)
            .map_err(|err| CommandError::Other(err.to_string()))?;
        parse_wal_segment_size(result.value(0, 0).as_deref())
    }

    fn timeline(&mut self) -> Result<u32, CommandError> {
        let result = self
            .conn
            .query(sql::TIMELINE)
            .map_err(|err| CommandError::Other(err.to_string()))?;
        parse_timeline(result.value(0, 0).as_deref())
    }

    fn archive_mode(&mut self) -> Result<String, CommandError> {
        let result = self
            .conn
            .query(sql::ARCHIVE_MODE)
            .map_err(|err| CommandError::Other(err.to_string()))?;
        Ok(result.value(0, 0).unwrap_or_default().trim().to_owned())
    }
}

/// Parse a `server_version_num` scalar text into a `u32`.
fn parse_server_version_num(raw: Option<&str>) -> Result<u32, CommandError> {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read server_version_num from pg_settings".to_owned()))
}

/// Parse a `system_identifier` scalar text into a `u64`.
fn parse_system_identifier(raw: Option<&str>) -> Result<u64, CommandError> {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .ok_or_else(|| CommandError::Other("could not read system_identifier from pg_control_system()".to_owned()))
}

/// Interpret a `pg_is_in_recovery()` scalar text as a bool (`PostgreSQL` renders
/// boolean text as `t` / `f`).
fn parse_in_recovery(raw: Option<&str>) -> bool {
    matches!(raw, Some("t" | "true"))
}

/// Parse a `wal_segment_size` byte-count scalar text into a `u64`.
fn parse_wal_segment_size(raw: Option<&str>) -> Result<u64, CommandError> {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .ok_or_else(|| CommandError::Other("could not read wal_segment_size from pg_settings".to_owned()))
}

/// Parse a `timeline_id` scalar text into a `u32`.
fn parse_timeline(raw: Option<&str>) -> Result<u32, CommandError> {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read timeline_id from pg_control_checkpoint()".to_owned()))
}

/// Pull the single scalar text value at `(0, 0)` out of a [`QueryRows`], or
/// `None` for an empty result / SQL `NULL`.
fn scalar_from_rows(rows: &QueryRows) -> Option<String> {
    rows.rows.first().and_then(|row| row.first()).and_then(Clone::clone)
}

/// The production *remote* [`BackupControl`].
///
/// Drives `pg_backup_start` / `pg_backup_stop` (and the info / status queries) on
/// a worker that owns the real libpq connection, for the dedicated-repo-host
/// (pull) topology (`pgN-host`). Runs the **same** SQL as [`LibpqBackupControl`],
/// but via the worker `db-query` protocol — so start and stop still share the
/// worker's one persistent session, as a non-exclusive backup requires.
///
/// The caller is responsible for `db-open`ing the worker connection (against the
/// PG host's *local* cluster — no `host=<pghost>`) before driving this.
pub struct RemoteBackupControl<R: IoRead, W: IoWrite> {
    db: RemoteDb<R, W>,
    /// Cached server info, resolved lazily on first [`BackupControl::server_info`].
    info: Option<BackupServerInfo>,
}

impl<R: IoRead, W: IoWrite> RemoteBackupControl<R, W> {
    /// Wrap a [`RemoteDb`] whose connection is already open.
    #[must_use]
    pub const fn new(db: RemoteDb<R, W>) -> Self {
        Self { db, info: None }
    }

    /// Run `sql` on the worker and return the scalar text value at `(0, 0)`, or
    /// `None` for an empty result / SQL `NULL`.
    fn scalar(&mut self, sql: &str) -> Result<Option<String>, CommandError> {
        let rows = self.db.query(sql)?;
        Ok(scalar_from_rows(&rows))
    }

    /// Resolve (and cache) the server info, querying the worker only once.
    fn resolve_info(&mut self) -> Result<BackupServerInfo, CommandError> {
        if let Some(info) = &self.info {
            return Ok(info.clone());
        }
        let server_version_num = parse_server_version_num(self.scalar(sql::SERVER_VERSION_NUM)?.as_deref())?;
        let system_identifier = parse_system_identifier(self.scalar(sql::SYSTEM_IDENTIFIER)?.as_deref())?;
        let info = BackupServerInfo {
            server_version_num,
            system_identifier,
        };
        self.info = Some(info.clone());
        Ok(info)
    }
}

impl<R: IoRead, W: IoWrite> BackupControl for RemoteBackupControl<R, W> {
    fn server_info(&mut self) -> Result<BackupServerInfo, CommandError> {
        self.resolve_info()
    }

    fn backup_start(&mut self, label: &str, fast: bool) -> Result<String, CommandError> {
        let info = self.resolve_info()?;
        let rows = self.db.query(&backup_start_sql(&info, label, fast))?;
        scalar_from_rows(&rows).ok_or_else(|| CommandError::Other("backup start returned no LSN".to_owned()))
    }

    fn backup_stop(&mut self) -> Result<BackupStopResult, CommandError> {
        let info = self.resolve_info()?;
        let rows = self.db.query(&backup_stop_sql(&info))?;
        let row = rows
            .rows
            .first()
            .ok_or_else(|| CommandError::Other("backup stop returned no row".to_owned()))?;
        let lsn = row
            .first()
            .and_then(Clone::clone)
            .ok_or_else(|| CommandError::Other("backup stop returned no LSN".to_owned()))?;
        // labelfile / spcmapfile may be SQL NULL; treat NULL as empty.
        let label_file = row.get(1).and_then(Clone::clone).unwrap_or_default();
        let spcmap_file = row.get(2).and_then(Clone::clone).unwrap_or_default();
        Ok(BackupStopResult {
            lsn,
            label_file,
            spcmap_file,
        })
    }

    fn is_in_recovery(&mut self) -> Result<bool, CommandError> {
        Ok(parse_in_recovery(self.scalar(sql::IS_IN_RECOVERY)?.as_deref()))
    }

    fn replay_lsn(&mut self) -> Result<Option<String>, CommandError> {
        self.scalar(sql::REPLAY_LSN)
    }

    fn wal_segment_size(&mut self) -> Result<u64, CommandError> {
        parse_wal_segment_size(self.scalar(sql::WAL_SEGMENT_SIZE)?.as_deref())
    }

    fn timeline(&mut self) -> Result<u32, CommandError> {
        parse_timeline(self.scalar(sql::TIMELINE)?.as_deref())
    }

    fn archive_mode(&mut self) -> Result<String, CommandError> {
        Ok(self.scalar(sql::ARCHIVE_MODE)?.unwrap_or_default().trim().to_owned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn release_major_strips_minor() {
        let pg96 = BackupServerInfo {
            server_version_num: 90_600,
            system_identifier: 1,
        };
        assert_eq!(pg96.release_major(), 9);
        assert!(!pg96.uses_pg_backup_start());

        let pg14 = BackupServerInfo {
            server_version_num: 140_010,
            system_identifier: 1,
        };
        assert_eq!(pg14.release_major(), 14);
        assert!(!pg14.uses_pg_backup_start());

        let pg15 = BackupServerInfo {
            server_version_num: 150_004,
            system_identifier: 1,
        };
        assert_eq!(pg15.release_major(), 15);
        assert!(pg15.uses_pg_backup_start());

        let pg18 = BackupServerInfo {
            server_version_num: 180_000,
            system_identifier: 1,
        };
        assert_eq!(pg18.release_major(), 18);
        assert!(pg18.uses_pg_backup_start());
    }

    #[test]
    fn backup_start_sql_pg15_plus_uses_keyword_args() {
        let info = BackupServerInfo {
            server_version_num: 160_004,
            system_identifier: 1,
        };
        let sql = backup_start_sql(&info, "20240101-120000F", false);
        assert!(sql.contains("pg_backup_start"), "{sql}");
        assert!(sql.contains("label => '20240101-120000F'"), "{sql}");
        assert!(sql.contains("fast => false"), "{sql}");

        let fast_sql = backup_start_sql(&info, "lbl", true);
        assert!(fast_sql.contains("fast => true"), "{fast_sql}");
    }

    #[test]
    fn backup_start_sql_pre15_uses_positional_nonexclusive() {
        let info = BackupServerInfo {
            server_version_num: 140_010,
            system_identifier: 1,
        };
        let sql = backup_start_sql(&info, "lbl", false);
        assert!(sql.contains("pg_start_backup"), "{sql}");
        // Positional args ending in the non-exclusive `false`.
        assert!(sql.contains("pg_start_backup('lbl', false, false)"), "{sql}");
    }

    #[test]
    fn backup_start_sql_escapes_quotes_in_label() {
        let info = BackupServerInfo {
            server_version_num: 160_004,
            system_identifier: 1,
        };
        // A label containing an apostrophe must be doubled, not break the literal.
        let sql = backup_start_sql(&info, "o'brien", false);
        assert!(sql.contains("'o''brien'"), "{sql}");
    }

    #[test]
    fn backup_stop_sql_selects_label_and_spcmap() {
        let pg16 = BackupServerInfo {
            server_version_num: 160_004,
            system_identifier: 1,
        };
        let sql = pg16_then(&pg16);
        assert!(sql.contains("pg_backup_stop"), "{sql}");
        assert!(sql.contains("wait_for_archive => true"), "{sql}");
        assert!(sql.contains("labelfile"), "{sql}");
        assert!(sql.contains("spcmapfile"), "{sql}");

        let pg13 = BackupServerInfo {
            server_version_num: 130_005,
            system_identifier: 1,
        };
        let sql13 = backup_stop_sql(&pg13);
        assert!(sql13.contains("pg_stop_backup(false, true)"), "{sql13}");
    }

    fn pg16_then(info: &BackupServerInfo) -> String {
        backup_stop_sql(info)
    }

    #[test]
    fn sql_quote_doubles_embedded_apostrophes() {
        assert_eq!(sql_quote("plain"), "'plain'");
        assert_eq!(sql_quote("o'brien"), "'o''brien'");
        assert_eq!(sql_quote("a'b'c"), "'a''b''c'");
    }

    // -------- RemoteBackupControl over the worker protocol (no real PG) -------

    #[test]
    fn remote_backup_control_drives_start_stop_over_the_worker() {
        use std::thread;

        use pgbr_protocol::transport::{PipeRead, PipeWrite, serve};
        use pgbr_protocol::{OkResponse, ProtocolClient, Request, Response};

        // A fake worker answering each db-query with a canned result matched by
        // SQL content (and db-open / db-close with success). This proves
        // RemoteBackupControl encodes the same SQL LibpqBackupControl runs and
        // decodes the replies — including the multi-column pg_backup_stop row.
        fn one_col(value: &str) -> Response {
            let rows = QueryRows {
                columns: vec!["v".to_owned()],
                rows: vec![vec![Some(value.to_owned())]],
            };
            Response::Ok(OkResponse {
                out: Some(serde_json::to_value(&rows).unwrap()),
            })
        }
        fn stop_row(lsn: &str, label: &str, spcmap: Option<&str>) -> Response {
            let rows = QueryRows {
                columns: vec!["lsn".to_owned(), "labelfile".to_owned(), "spcmapfile".to_owned()],
                rows: vec![vec![Some(lsn.to_owned()), Some(label.to_owned()), spcmap.map(str::to_owned)]],
            };
            Response::Ok(OkResponse {
                out: Some(serde_json::to_value(&rows).unwrap()),
            })
        }

        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let mut handler = |req: &Request| -> Response {
                match req.cmd.as_str() {
                    "db-open" | "db-close" => Response::Ok(OkResponse { out: None }),
                    "db-query" => {
                        let sql = req.param.first().and_then(|v| v.as_str()).unwrap_or_default();
                        if sql.contains("server_version_num") {
                            one_col("160004")
                        } else if sql.contains("pg_control_system") {
                            one_col("6873049345984568091")
                        } else if sql.contains("pg_backup_start") {
                            one_col("0/2000028")
                        } else if sql.contains("pg_backup_stop") {
                            stop_row("0/3000000", "START WAL LOCATION: 0/2000028\n", None)
                        } else if sql.contains("pg_is_in_recovery") {
                            one_col("f")
                        } else if sql.contains("wal_segment_size") {
                            one_col("16777216")
                        } else if sql.contains("pg_control_checkpoint") {
                            one_col("1")
                        } else if sql.contains("archive_mode") {
                            one_col("on")
                        } else {
                            one_col("")
                        }
                    }
                    other => panic!("unexpected worker command {other}"),
                }
            };
            serve(&mut reader, &mut writer, &mut handler).unwrap();
        });

        let client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        let mut db = RemoteDb::new(client);
        db.open("host=/var/run/postgresql").expect("db-open");
        let mut control = RemoteBackupControl::new(db);

        // server_info resolves + caches the version / system id.
        let info = control.server_info().expect("server_info");
        assert_eq!(info.server_version_num, 160_004);
        assert_eq!(info.system_identifier, 6_873_049_345_984_568_091);
        assert!(info.uses_pg_backup_start(), "PG16 uses pg_backup_start");

        // The non-exclusive backup bracket: start returns the LSN, stop returns
        // the LSN + the backup_label content (spcmap NULL -> empty).
        let start = control.backup_start("20240101-120000F", false).expect("backup_start");
        assert_eq!(start, "0/2000028");
        let stop = control.backup_stop().expect("backup_stop");
        assert_eq!(stop.lsn, "0/3000000");
        assert!(stop.label_file.contains("START WAL LOCATION"));
        assert!(stop.spcmap_file.is_empty(), "NULL spcmap -> empty");

        // The status accessors round-trip through db-query too.
        assert!(!control.is_in_recovery().expect("is_in_recovery"));
        assert_eq!(control.wal_segment_size().expect("wal_segment_size"), 16_777_216);
        assert_eq!(control.timeline().expect("timeline"), 1);
        assert_eq!(control.archive_mode().expect("archive_mode"), "on");

        // Drop the control (and its RemoteDb / write pipe) so the worker reads
        // EOF and the serve loop returns.
        drop(control);
        server.join().unwrap();
    }
}
