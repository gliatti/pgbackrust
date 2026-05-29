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

use pgbr_db::Connection;

use crate::CommandError;

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
    if info.uses_pg_backup_start() {
        // PG >= 15: keyword arguments, always non-exclusive.
        format!("select lsn::text as lsn from pg_catalog.pg_backup_start(label => {label_lit}, fast => {fast_lit})")
    } else {
        // PG < 15: positional args; the trailing `false` selects a
        // non-exclusive backup (so start/stop must share this session).
        format!("select lsn::text as lsn from pg_catalog.pg_start_backup({label_lit}, {fast_lit}, false)")
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
            .query("select (select setting from pg_catalog.pg_settings where name = 'server_version_num')::int4")
            .map_err(|err| CommandError::Other(err.to_string()))?;
        let server_version_num = version_result
            .value(0, 0)
            .and_then(|s| s.trim().parse::<u32>().ok())
            .ok_or_else(|| CommandError::Other("could not read server_version_num from pg_settings".to_owned()))?;

        let control_result = self
            .conn
            .query("select system_identifier::text from pg_catalog.pg_control_system()")
            .map_err(|err| CommandError::Other(err.to_string()))?;
        let system_identifier = control_result
            .value(0, 0)
            .and_then(|s| s.trim().parse::<u64>().ok())
            .ok_or_else(|| CommandError::Other("could not read system_identifier from pg_control_system()".to_owned()))?;

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
            .query("select pg_catalog.pg_is_in_recovery()::text")
            .map_err(|err| CommandError::Other(err.to_string()))?;
        // PostgreSQL renders boolean text as "t" / "f".
        Ok(matches!(result.value(0, 0).as_deref(), Some("t" | "true")))
    }

    fn replay_lsn(&mut self) -> Result<Option<String>, CommandError> {
        let result = self
            .conn
            .query("select pg_catalog.pg_last_wal_replay_lsn()::text")
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
            .query(
                "select (setting::int8 * \
                 case unit when '8kB' then 8192 when 'kB' then 1024 when 'MB' then 1048576 \
                 when 'GB' then 1073741824 else 1 end)::text \
                 from pg_catalog.pg_settings where name = 'wal_segment_size'",
            )
            .map_err(|err| CommandError::Other(err.to_string()))?;
        result
            .value(0, 0)
            .and_then(|s| s.trim().parse::<u64>().ok())
            .ok_or_else(|| CommandError::Other("could not read wal_segment_size from pg_settings".to_owned()))
    }

    fn timeline(&mut self) -> Result<u32, CommandError> {
        let result = self
            .conn
            .query("select timeline_id::text from pg_catalog.pg_control_checkpoint()")
            .map_err(|err| CommandError::Other(err.to_string()))?;
        result
            .value(0, 0)
            .and_then(|s| s.trim().parse::<u32>().ok())
            .ok_or_else(|| CommandError::Other("could not read timeline_id from pg_control_checkpoint()".to_owned()))
    }

    fn archive_mode(&mut self) -> Result<String, CommandError> {
        let result = self
            .conn
            .query("select setting from pg_catalog.pg_settings where name = 'archive_mode'")
            .map_err(|err| CommandError::Other(err.to_string()))?;
        Ok(result.value(0, 0).unwrap_or_default().trim().to_owned())
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
}
