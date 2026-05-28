//! Stanza-management commands: `stanza-create`, `stanza-delete`,
//! `stanza-upgrade`.
//!
//! C reference: `src/command/stanza/create.c`, `src/command/stanza/delete.c`,
//! `src/command/stanza/upgrade.c`.
//!
//! The cluster's identity (system id, PG version, catalog version, control
//! version) is obtained from **either** of two sources, matching the C
//! implementation's two information paths:
//!
//! - A **live libpq connection** — when a DB connection is derivable from the
//!   resolved configuration (`pg1-*` options) or from `DATABASE_URL`. The
//!   version comes from `server_version_num`; the system id / catalog version
//!   / control version come from `pg_control_system()` (available on PG 9.6+),
//!   mirroring `dbOpen` in `src/db/db.c`.
//! - The on-disk **`<pg-path>/global/pg_control`** file — read via
//!   [`pgbr_postgres::control::decode_pg_control_header`]. This is the default
//!   and keeps `stanza-create` / `stanza-upgrade` testable without a running
//!   `PostgreSQL`.
//!
//! The row→identity mapping ([`query_result_to_identity`]) is a pure function
//! over already-parsed column values, so it is unit-tested without any live
//! server; [`cluster_identity_from_db`] is the thin libpq adapter around it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_db::Connection;
use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup};
use pgbr_postgres::control::{PgControlHeader, decode_pg_control_header, header_version};
use pgbr_postgres::version::by_catalog_version_no;
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;
use crate::backup::acquire_command_lock;

/// pgBackRest on-disk info-file format version written by this port.
const BACKREST_FORMAT: u32 = 5;
/// pgBackRest version string stamped into freshly written info files.
const BACKREST_VERSION: &str = "2.58";
/// Path of the control file relative to the PG data directory.
const PG_CONTROL_PATH: &str = "global/pg_control";

/// Cluster identity resolved from `pg_control` (or a live libpq connection),
/// plus the textual PG label.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClusterIdentity {
    header: PgControlHeader,
    version: String,
}

/// What [`create_inner`] wrote, for assertions in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOutcome {
    /// Textual PG major-version label recorded for the new stanza.
    pub db_version: String,
    /// `pg_control.system_identifier` recorded for the new stanza.
    pub db_system_id: u64,
}

/// What [`upgrade_inner`] did, for assertions in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeOutcome {
    /// Whether the recorded cluster identity actually changed.
    pub upgraded: bool,
    /// The active `db-id` after the operation (incremented when upgraded).
    pub new_db_id: u32,
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

/// Read `global/pg_control` from the PG data directory and resolve its
/// version label.
fn read_cluster_identity(pg_storage: &dyn Storage) -> Result<ClusterIdentity, CommandError> {
    let mut reader = pg_storage.open_read(Path::new(PG_CONTROL_PATH))?;
    let bytes = reader.read_all()?;
    let header = decode_pg_control_header(&bytes).map_err(|err| CommandError::Other(err.to_string()))?;
    let version = header_version(&header)
        .ok_or_else(|| {
            CommandError::Other(format!(
                "unsupported PG control version {}/{} in {PG_CONTROL_PATH}",
                header.pg_control_version, header.catalog_version_no
            ))
        })?
        .label
        .to_owned();

    Ok(ClusterIdentity { header, version })
}

/// The four raw values pgBackRest needs to identify a cluster, exactly as the
/// libpq queries return them as text. Kept separate from [`ClusterIdentity`]
/// so the mapping below ([`query_result_to_identity`]) is a pure function that
/// needs no live `PostgreSQL` to exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DbIdentityRow {
    /// `server_version_num` from `pg_settings` (e.g. `160004`, `90600`).
    server_version_num: u32,
    /// `system_identifier` from `pg_control_system()`.
    system_identifier: u64,
    /// `catalog_version_no` from `pg_control_system()`.
    catalog_version_no: u32,
    /// `pg_control_version` from `pg_control_system()`.
    pg_control_version: u32,
}

/// Map a `server_version_num` (e.g. `160004`, `90600`) to a pgBackRest major
/// version label (`"9.6"`, `"10"`, …). Mirrors the C `pgVersionFromNum` /
/// `(num / 100 * 100)` major-stripping in `src/postgres/interface.c`.
///
/// PG < 10 encodes the major as `9.x` (`90600` → `9.6`); PG >= 10 uses
/// `<major>0000` (`160004` → `16`). Returns `None` for a version number with
/// no [`pgbr_postgres::version::SUPPORTED`] entry.
fn pg_version_label_from_num(server_version_num: u32) -> Option<&'static str> {
    // Strip the minor: PG < 10 keeps the .x minor (e.g. 90600 -> "9.6"); PG >=
    // 10 collapses to the bare major (e.g. 160004 -> "16").
    let label = if server_version_num < 100_000 {
        format!("{}.{}", server_version_num / 10_000, (server_version_num % 10_000) / 100)
    } else {
        (server_version_num / 10_000).to_string()
    };
    pgbr_postgres::version::by_label(&label).map(|v| v.label)
}

/// Pure mapping from the raw libpq column values to a [`ClusterIdentity`].
///
/// Cross-checks the cluster's catalog version against the
/// [`pgbr_postgres::version::SUPPORTED`] registry (the same authority the
/// control-file path uses) and verifies the `(pg_control_version,
/// catalog_version_no)` pair agrees with the version derived from
/// `server_version_num`. No I/O, no libpq — unit-testable with synthetic rows.
fn query_result_to_identity(row: DbIdentityRow) -> Result<ClusterIdentity, CommandError> {
    let version = pg_version_label_from_num(row.server_version_num)
        .ok_or_else(|| CommandError::Other(format!("unsupported server_version_num {}", row.server_version_num)))?;

    // The catalog version is the unique per-major key; confirm it is known and
    // that the reported control version matches the registry entry, exactly as
    // decode_pg_control_header validates the on-disk header.
    let entry = by_catalog_version_no(row.catalog_version_no).ok_or_else(|| {
        CommandError::Other(format!(
            "unknown catalog_version_no {} reported by pg_control_system()",
            row.catalog_version_no
        ))
    })?;
    if entry.pg_control_version != row.pg_control_version {
        return Err(CommandError::Other(format!(
            "pg_control_system() control version {} does not match catalog_version_no {} (expected {})",
            row.pg_control_version, row.catalog_version_no, entry.pg_control_version
        )));
    }

    Ok(ClusterIdentity {
        header: PgControlHeader {
            system_identifier: row.system_identifier,
            pg_control_version: row.pg_control_version,
            catalog_version_no: row.catalog_version_no,
        },
        version: version.to_owned(),
    })
}

/// Query a live `PostgreSQL` for its cluster identity.
///
/// Runs the same information queries the C `dbOpen` uses: `server_version_num`
/// from `pg_settings`, and `system_identifier` / `catalog_version_no` /
/// `pg_control_version` from `pg_control_system()` (PG 9.6+). The parsed
/// columns are handed to the pure [`query_result_to_identity`] mapper.
///
/// # Errors
///
/// [`CommandError::Other`] on connection failure, query failure, missing /
/// unparseable columns, or an unrecognised version.
fn cluster_identity_from_db(conn: &mut Connection) -> Result<ClusterIdentity, CommandError> {
    let version_result = conn
        .query("select (select setting from pg_catalog.pg_settings where name = 'server_version_num')::int4")
        .map_err(|err| CommandError::Other(err.to_string()))?;
    let server_version_num = version_result
        .value(0, 0)
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read server_version_num from pg_settings".to_owned()))?;

    let control_result = conn
        .query(
            "select system_identifier::text, catalog_version_no::text, pg_control_version::text \
             from pg_catalog.pg_control_system()",
        )
        .map_err(|err| CommandError::Other(err.to_string()))?;
    let system_identifier = control_result
        .value(0, 0)
        .and_then(|s| s.trim().parse::<u64>().ok())
        .ok_or_else(|| CommandError::Other("could not read system_identifier from pg_control_system()".to_owned()))?;
    let catalog_version_no = control_result
        .value(0, 1)
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read catalog_version_no from pg_control_system()".to_owned()))?;
    let pg_control_version = control_result
        .value(0, 2)
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read pg_control_version from pg_control_system()".to_owned()))?;

    query_result_to_identity(DbIdentityRow {
        server_version_num,
        system_identifier,
        catalog_version_no,
        pg_control_version,
    })
}

/// Build a libpq conninfo string for the primary cluster when the resolved
/// configuration (or `DATABASE_URL`) describes a reachable `PostgreSQL`, or
/// `None` when no DB source is configured (the caller then falls back to
/// reading `global/pg_control`).
///
/// `DATABASE_URL` wins when set (it is already a complete libpq URI). Otherwise
/// a connection is derived from `pg1-host` + `pg1-port` / `pg1-socket-path` /
/// `pg1-database` / `pg1-user`; a bare local `pg1-path` alone is **not** enough
/// to imply a live server, so the control-file path stays the default.
fn derive_conninfo(config: &LoadedConfig) -> Option<String> {
    derive_conninfo_with_url(config, std::env::var("DATABASE_URL").ok().as_deref())
}

/// Pure core of [`derive_conninfo`]: `database_url` is the already-resolved
/// `DATABASE_URL` (so the env read stays out of the unit tests).
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

    // Only treat the cluster as connectable when a host or a unix-socket
    // directory is configured; otherwise leave the on-disk path as the source.
    // libpq accepts a directory in `host=` and reads it as a socket dir.
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

/// Resolve the cluster identity, preferring a live libpq connection when one is
/// configured and falling back to the on-disk `global/pg_control` otherwise.
fn resolve_cluster_identity(config: &LoadedConfig, pg_storage: &dyn Storage) -> Result<ClusterIdentity, CommandError> {
    if let Some(conninfo) = derive_conninfo(config) {
        let mut conn = Connection::open(&conninfo).map_err(|err| CommandError::Other(err.to_string()))?;
        return cluster_identity_from_db(&mut conn);
    }
    read_cluster_identity(pg_storage)
}

/// `stanza-create` — initialise on-disk repository state for a stanza.
///
/// Reads the cluster identity from `<pg-path>/global/pg_control`, then writes
/// fresh `archive/<stanza>/archive.info` and `backup/<stanza>/backup.info`
/// seeded with that identity (db-id 1, one history entry).
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Other`] if `pg_control` cannot be read / decoded, its
///   version is unsupported, or the stanza already exists.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for repository write
///   failures.
pub fn create(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    // Hold both archive+backup locks for the whole command. C ref: lockAcquire(lockTypeAll).
    let _locks = acquire_command_lock(config, LockType::All)?;
    let identity = resolve_cluster_identity(config, pg_storage)?;
    create_with_identity(stanza, repo_storage, identity)?;
    Ok(())
}

/// Test/`pg_control`-only convenience: read the identity off disk, then create.
#[cfg(test)]
fn create_inner(stanza: &str, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<CreateOutcome, CommandError> {
    let identity = read_cluster_identity(pg_storage)?;
    create_with_identity(stanza, repo_storage, identity)
}

fn create_with_identity(
    stanza: &str,
    repo_storage: &dyn Storage,
    identity: ClusterIdentity,
) -> Result<CreateOutcome, CommandError> {
    let archive_info_path = archive_info_path(stanza);
    let backup_info_path = backup_info_path(stanza);

    if repo_storage.exists(&archive_info_path)? || repo_storage.exists(&backup_info_path)? {
        return Err(CommandError::Other("stanza already exists".to_owned()));
    }

    let header = identity.header;
    let mut history = BTreeMap::new();
    history.insert(
        1,
        DbHistoryEntry {
            db_id: header.system_identifier,
            db_version: identity.version.clone(),
        },
    );

    let archive = InfoArchive {
        backrest_format: BACKREST_FORMAT,
        backrest_version: BACKREST_VERSION.to_owned(),
        db_id: 1,
        db_system_id: header.system_identifier,
        db_version: identity.version.clone(),
        history: history.clone(),
    };

    let backup = InfoBackup {
        backrest_format: BACKREST_FORMAT,
        backrest_version: BACKREST_VERSION.to_owned(),
        db_id: 1,
        db_system_id: header.system_identifier,
        db_version: identity.version.clone(),
        db_catalog_version: header.catalog_version_no,
        db_control_version: header.pg_control_version,
        current: BTreeMap::new(),
        history,
    };

    repo_storage.create_path(&PathBuf::from(format!("archive/{stanza}")), true)?;
    repo_storage.create_path(&PathBuf::from(format!("backup/{stanza}")), true)?;

    archive
        .save(repo_storage, &archive_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;
    backup
        .save(repo_storage, &backup_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(CreateOutcome {
        db_version: identity.version,
        db_system_id: header.system_identifier,
    })
}

fn archive_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/archive.info"))
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// `stanza-delete` — wipe an existing stanza's repository state.
///
/// Recursively removes `archive/<stanza>` and `backup/<stanza>` from the
/// repository. Both removals tolerate a missing directory
/// (`error_on_missing = false`) so the command is idempotent.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] if either removal fails for a reason other
///   than "missing".
pub fn delete(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    // Hold both archive+backup locks for the whole command. C ref: lockAcquire(lockTypeAll).
    let _locks = acquire_command_lock(config, LockType::All)?;

    let archive: PathBuf = format!("archive/{stanza}").into();
    let backup: PathBuf = format!("backup/{stanza}").into();

    remove_subtree(repo_storage, &archive)?;
    remove_subtree(repo_storage, &backup)?;
    Ok(())
}

fn remove_subtree(storage: &dyn Storage, path: &Path) -> Result<(), CommandError> {
    match storage.remove_path(path, true, false) {
        Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// `stanza-upgrade` — record a new PG version after a major-version upgrade.
///
/// Re-reads `<pg-path>/global/pg_control` and compares the cluster's system id
/// and version against what `archive.info` / `backup.info` already record. If
/// either differs, a new history entry is appended (incrementing `db-id`) and
/// the top-level `db-*` fields are bumped to the current cluster. If both
/// match, the command is a no-op.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Other`] if `pg_control` cannot be read / decoded, its
///   version is unsupported, or the stanza was never initialised.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for repository
///   read/write failures.
pub fn upgrade(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    // Hold both archive+backup locks for the whole command. C ref: lockAcquire(lockTypeAll).
    let _locks = acquire_command_lock(config, LockType::All)?;
    let identity = resolve_cluster_identity(config, pg_storage)?;
    upgrade_with_identity(stanza, repo_storage, identity)?;
    Ok(())
}

/// Test/`pg_control`-only convenience: read the identity off disk, then upgrade.
#[cfg(test)]
fn upgrade_inner(stanza: &str, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<UpgradeOutcome, CommandError> {
    let identity = read_cluster_identity(pg_storage)?;
    upgrade_with_identity(stanza, repo_storage, identity)
}

fn upgrade_with_identity(
    stanza: &str,
    repo_storage: &dyn Storage,
    identity: ClusterIdentity,
) -> Result<UpgradeOutcome, CommandError> {
    let archive_info_path = archive_info_path(stanza);
    let backup_info_path = backup_info_path(stanza);

    if !repo_storage.exists(&archive_info_path)? || !repo_storage.exists(&backup_info_path)? {
        return Err(CommandError::Other(
            "stanza not initialized; run stanza-create first".to_owned(),
        ));
    }

    let mut archive = InfoArchive::load(repo_storage, &archive_info_path).map_err(|err| CommandError::Other(err.to_string()))?;
    let mut backup = InfoBackup::load(repo_storage, &backup_info_path).map_err(|err| CommandError::Other(err.to_string()))?;

    let header = identity.header;
    let changed = archive.db_system_id != header.system_identifier || archive.db_version != identity.version;

    if !changed {
        return Ok(UpgradeOutcome {
            upgraded: false,
            new_db_id: archive.db_id,
        });
    }

    // The new db-id is one past the highest history key (which always
    // includes the currently-active id), so it is monotonic even if a prior
    // upgrade left a gap.
    let next_id = archive.history.keys().copied().max().unwrap_or(archive.db_id) + 1;
    let new_entry = DbHistoryEntry {
        db_id: header.system_identifier,
        db_version: identity.version.clone(),
    };

    archive.db_id = next_id;
    archive.db_system_id = header.system_identifier;
    archive.db_version.clone_from(&identity.version);
    archive.history.insert(next_id, new_entry.clone());

    backup.db_id = next_id;
    backup.db_system_id = header.system_identifier;
    backup.db_version = identity.version;
    backup.db_catalog_version = header.catalog_version_no;
    backup.db_control_version = header.pg_control_version;
    backup.history.insert(next_id, new_entry);

    archive
        .save(repo_storage, &archive_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;
    backup
        .save(repo_storage, &backup_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(UpgradeOutcome {
        upgraded: true,
        new_db_id: next_id,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pgbr_postgres::version;
    use pgbr_postgres::version::{SUPPORTED, VersionInterface};
    use pgbr_storage::Posix;

    /// Build a synthetic 16-byte `pg_control` file inside the PG data dir.
    fn write_pg_control(pg: &Posix, system_id: u64, v: &VersionInterface) {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&system_id.to_le_bytes());
        buf[8..12].copy_from_slice(&v.pg_control_version.to_le_bytes());
        buf[12..16].copy_from_slice(&v.catalog_version_no.to_le_bytes());
        pg.create_path(Path::new("global"), true).unwrap();
        let mut w = pg.open_write(Path::new("global/pg_control")).unwrap();
        w.write(&buf).unwrap();
        w.flush().unwrap();
        w.close().unwrap();
    }

    fn posix_pair() -> (tempfile::TempDir, tempfile::TempDir, Posix, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_storage = Posix::new(repo.path());
        let pg_storage = Posix::new(pg.path());
        (repo, pg, repo_storage, pg_storage)
    }

    fn config_with_stanza(stanza: Option<&str>) -> LoadedConfig {
        LoadedConfig {
            command: "stanza-create".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options: BTreeMap::new(),
            params: Vec::new(),
        }
    }

    /// `config_with_stanza` plus an explicit `lock-path` so the command takes
    /// its real `all` (archive + backup) advisory locks under an isolated dir.
    fn config_with_stanza_locked(stanza: Option<&str>, lock_path: &Path) -> LoadedConfig {
        let mut cfg = config_with_stanza(stanza);
        cfg.options.insert(
            ("lock-path".to_owned(), None),
            OptionValue::Path(lock_path.to_string_lossy().into_owned()),
        );
        cfg
    }

    #[test]
    fn stanza_create_acquires_all_locks() {
        // stanza-create takes the `all` lock (archive + backup). A concurrent
        // holder of the backup component makes it fail.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 0x0102_0304, &SUPPORTED[0]);

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let cfg = config_with_stanza_locked(Some("demo"), lock_dir.path());

        let held = crate::lock::lock_acquire(lock_dir.path(), "demo", LockType::Backup).expect("pre-acquire backup lock");
        let err = create(&cfg, &repo_s, &pg_s).expect_err("create must fail while a component lock is held");
        assert!(err.to_string().contains("running"), "unexpected error: {err}");

        drop(held);
        create(&cfg, &repo_s, &pg_s).expect("create succeeds once the locks are free");
        assert!(
            !lock_dir.path().join("demo-backup.lock").exists(),
            "lock files must be released after the command returns"
        );
    }

    #[test]
    fn stanza_delete_acquires_all_locks() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);
        create_inner("demo", &repo_s, &pg_s).expect("seed stanza");

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let mut cfg = config_with_stanza_locked(Some("demo"), lock_dir.path());
        cfg.command = "stanza-delete".to_owned();

        let held = crate::lock::lock_acquire(lock_dir.path(), "demo", LockType::Archive).expect("pre-acquire archive lock");
        let err = delete(&cfg, &repo_s).expect_err("delete must fail while a component lock is held");
        assert!(err.to_string().contains("running"), "unexpected error: {err}");

        drop(held);
        delete(&cfg, &repo_s).expect("delete succeeds once the locks are free");
    }

    #[test]
    fn stanza_upgrade_acquires_all_locks() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);
        create_inner("demo", &repo_s, &pg_s).expect("seed stanza");

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let mut cfg = config_with_stanza_locked(Some("demo"), lock_dir.path());
        cfg.command = "stanza-upgrade".to_owned();

        let held = crate::lock::lock_acquire(lock_dir.path(), "demo", LockType::Backup).expect("pre-acquire backup lock");
        let err = upgrade(&cfg, &repo_s, &pg_s).expect_err("upgrade must fail while a component lock is held");
        assert!(err.to_string().contains("running"), "unexpected error: {err}");

        drop(held);
        upgrade(&cfg, &repo_s, &pg_s).expect("upgrade succeeds once the locks are free");
    }

    #[test]
    fn stanza_create_writes_info_files_from_pg_control() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let v = &SUPPORTED[0];
        let system_id: u64 = 0x0102_0304_0506_0708;
        write_pg_control(&pg_s, system_id, v);

        let cfg = config_with_stanza(Some("demo"));
        create(&cfg, &repo_s, &pg_s).expect("stanza-create should succeed");

        let archive = InfoArchive::load(&repo_s, &archive_info_path("demo")).expect("load archive.info");
        assert_eq!(archive.db_system_id, system_id);
        assert_eq!(archive.db_version, v.label);
        assert_eq!(archive.db_id, 1);
        assert_eq!(archive.history.len(), 1);
        assert_eq!(archive.history[&1].db_id, system_id);

        let backup = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("load backup.info");
        assert_eq!(backup.db_system_id, system_id);
        assert_eq!(backup.db_version, v.label);
        assert_eq!(backup.db_catalog_version, v.catalog_version_no);
        assert_eq!(backup.db_control_version, v.pg_control_version);
        assert!(backup.current.is_empty());
    }

    #[test]
    fn stanza_create_missing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 1, &SUPPORTED[0]);

        let cfg = config_with_stanza(None);
        let err = create(&cfg, &repo_s, &pg_s).expect_err("stanza-create requires a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn stanza_create_existing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 42, &SUPPORTED[0]);

        let cfg = config_with_stanza(Some("demo"));
        create(&cfg, &repo_s, &pg_s).expect("first create succeeds");

        let err = create(&cfg, &repo_s, &pg_s).expect_err("second create must fail");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "stanza already exists"),
            other => panic!("expected Other(stanza already exists), got {other:?}"),
        }
    }

    #[test]
    fn stanza_upgrade_no_change_is_noop() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);

        let outcome = create_inner("demo", &repo_s, &pg_s).expect("create");
        assert_eq!(outcome.db_version, SUPPORTED[0].label);

        let outcome = upgrade_inner("demo", &repo_s, &pg_s).expect("upgrade noop");
        assert!(!outcome.upgraded, "same pg_control must be a no-op");
        assert_eq!(outcome.new_db_id, 1);
    }

    #[test]
    fn stanza_upgrade_appends_history_on_version_change() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let system_id: u64 = 99;
        write_pg_control(&pg_s, system_id, &SUPPORTED[0]);

        create_inner("demo", &repo_s, &pg_s).expect("create");

        // Same cluster (system id), but a different PG major version.
        write_pg_control(&pg_s, system_id, &SUPPORTED[1]);
        let outcome = upgrade_inner("demo", &repo_s, &pg_s).expect("upgrade");
        assert!(outcome.upgraded, "version change must upgrade");
        assert_eq!(outcome.new_db_id, 2);

        let archive = InfoArchive::load(&repo_s, &archive_info_path("demo")).expect("load archive.info");
        assert_eq!(archive.db_id, 2);
        assert_eq!(archive.db_version, SUPPORTED[1].label);
        assert_eq!(archive.history.len(), 2);
        assert_eq!(archive.history[&1].db_version, SUPPORTED[0].label);
        assert_eq!(archive.history[&2].db_version, SUPPORTED[1].label);

        let backup = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("load backup.info");
        assert_eq!(backup.db_id, 2);
        assert_eq!(backup.db_catalog_version, SUPPORTED[1].catalog_version_no);
        assert_eq!(backup.db_control_version, SUPPORTED[1].pg_control_version);
    }

    #[test]
    fn stanza_upgrade_uninitialized_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 1, &SUPPORTED[0]);

        let err = upgrade_inner("demo", &repo_s, &pg_s).expect_err("uninitialized stanza must error");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "stanza not initialized; run stanza-create first"),
            other => panic!("expected Other(not initialized), got {other:?}"),
        }
    }

    #[test]
    fn query_result_to_identity_maps_synthetic_rows() {
        // PG 16: server_version_num 160004 -> label "16"; control/catalog from
        // the registry; an arbitrary system id passes through unchanged.
        let v = version::by_label("16").expect("PG 16 in registry");
        let identity = query_result_to_identity(DbIdentityRow {
            server_version_num: 160_004,
            system_identifier: 0x0102_0304_0506_0708,
            catalog_version_no: v.catalog_version_no,
            pg_control_version: v.pg_control_version,
        })
        .expect("synthetic PG 16 rows map cleanly");

        assert_eq!(identity.version, "16");
        assert_eq!(identity.header.system_identifier, 0x0102_0304_0506_0708);
        assert_eq!(identity.header.catalog_version_no, v.catalog_version_no);
        assert_eq!(identity.header.pg_control_version, v.pg_control_version);
    }

    #[test]
    fn query_result_to_identity_maps_pg96() {
        // PG 9.6: server_version_num 90600 -> label "9.6".
        let v = version::by_label("9.6").expect("PG 9.6 in registry");
        let identity = query_result_to_identity(DbIdentityRow {
            server_version_num: 90_600,
            system_identifier: 7,
            catalog_version_no: v.catalog_version_no,
            pg_control_version: v.pg_control_version,
        })
        .expect("synthetic PG 9.6 rows map cleanly");
        assert_eq!(identity.version, "9.6");
        assert_eq!(identity.header.system_identifier, 7);
    }

    #[test]
    fn query_result_to_identity_rejects_unknown_version() {
        let v = version::by_label("16").expect("PG 16 in registry");
        let err = query_result_to_identity(DbIdentityRow {
            server_version_num: 80_400, // PG 8.4, unsupported
            system_identifier: 1,
            catalog_version_no: v.catalog_version_no,
            pg_control_version: v.pg_control_version,
        })
        .expect_err("unsupported version must error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("server_version_num"), "message was {msg:?}"),
            other => panic!("expected Other(server_version_num), got {other:?}"),
        }
    }

    #[test]
    fn query_result_to_identity_rejects_unknown_catalog() {
        let err = query_result_to_identity(DbIdentityRow {
            server_version_num: 160_004,
            system_identifier: 1,
            catalog_version_no: 1, // not in the registry
            pg_control_version: 1300,
        })
        .expect_err("unknown catalog version must error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("catalog_version_no"), "message was {msg:?}"),
            other => panic!("expected Other(catalog_version_no), got {other:?}"),
        }
    }

    #[test]
    fn query_result_to_identity_rejects_control_catalog_mismatch() {
        let v = version::by_label("16").expect("PG 16 in registry");
        let err = query_result_to_identity(DbIdentityRow {
            server_version_num: 160_004,
            system_identifier: 1,
            catalog_version_no: v.catalog_version_no,
            pg_control_version: v.pg_control_version + 1, // disagrees with catalog
        })
        .expect_err("control/catalog mismatch must error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("control version"), "message was {msg:?}"),
            other => panic!("expected Other(control version), got {other:?}"),
        }
    }

    #[test]
    fn pg_version_label_from_num_handles_majors() {
        assert_eq!(pg_version_label_from_num(90_600), Some("9.6"));
        assert_eq!(pg_version_label_from_num(100_000), Some("10"));
        assert_eq!(pg_version_label_from_num(160_004), Some("16"));
        assert_eq!(pg_version_label_from_num(180_000), Some("18"));
        assert_eq!(pg_version_label_from_num(80_400), None); // PG 8.4 unsupported
        assert_eq!(pg_version_label_from_num(990_000), None);
    }

    #[test]
    fn derive_conninfo_none_without_db_config() {
        let cfg = config_with_stanza(Some("demo"));
        assert_eq!(
            derive_conninfo_with_url(&cfg, None),
            None,
            "no pg1-host and no DATABASE_URL means control-file path"
        );
    }

    #[test]
    fn derive_conninfo_database_url_wins() {
        let cfg = config_with_stanza(Some("demo"));
        assert_eq!(
            derive_conninfo_with_url(&cfg, Some("host=/tmp dbname=postgres")).as_deref(),
            Some("host=/tmp dbname=postgres"),
        );
        // An empty DATABASE_URL is ignored (falls through to config-derived).
        assert_eq!(derive_conninfo_with_url(&cfg, Some("")), None);
    }

    #[test]
    fn derive_conninfo_builds_from_pg1_options() {
        let mut cfg = config_with_stanza(Some("demo"));
        cfg.options
            .insert(("pg1-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        cfg.options.insert(("pg1-port".to_owned(), None), OptionValue::Integer(5433));
        cfg.options
            .insert(("pg1-database".to_owned(), None), OptionValue::String("postgres".to_owned()));
        let conninfo = derive_conninfo_with_url(&cfg, None).expect("pg1-host present -> conninfo");
        assert!(conninfo.contains("host=db.example"), "conninfo was {conninfo:?}");
        assert!(conninfo.contains("port=5433"), "conninfo was {conninfo:?}");
        assert!(conninfo.contains("dbname=postgres"), "conninfo was {conninfo:?}");
    }

    // Live-PostgreSQL stanza-create through the libpq identity path. Skipped by
    // default; run with `cargo test -p pgbr-command -- --include-ignored` and
    // DATABASE_URL pointing at a reachable cluster.
    #[test]
    #[ignore = "requires a running PostgreSQL server (set DATABASE_URL)"]
    fn stanza_create_via_db_path() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };

        let mut conn = Connection::open(&url).expect("open DATABASE_URL connection");
        let identity = cluster_identity_from_db(&mut conn).expect("identity from live PG");
        assert!(!identity.version.is_empty());
        assert_ne!(identity.header.system_identifier, 0);

        // Full create through the public entry point, which routes to the DB
        // path because DATABASE_URL is set.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_s = Posix::new(repo.path());
        let pg_s = Posix::new(pg.path());
        let cfg = config_with_stanza(Some("dblive"));
        create(&cfg, &repo_s, &pg_s).expect("stanza-create via DB path");

        let archive = InfoArchive::load(&repo_s, &archive_info_path("dblive")).expect("archive.info");
        assert_eq!(archive.db_system_id, identity.header.system_identifier);
        assert_eq!(archive.db_version, identity.version);
    }
}
