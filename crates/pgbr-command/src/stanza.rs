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
//!
//! ## Multiple repositories
//!
//! pgBackRest initialises (resp. removes / upgrades) the stanza on **every**
//! configured repository. [`create`] / [`delete`] / [`upgrade`] take a slice of
//! `(group_index, repo_storage)` pairs — one per configured repository — and run
//! the operation against each, reading that repository's own `repoN-cipher-*`
//! options at its `group_index` so each repository keeps its own (possibly
//! distinct) encryption settings. The cluster identity is resolved once (it does
//! not vary by repository) and applied to all. C ref: the `repoIdxList`
//! iteration in `src/command/stanza/create.c` / `delete.c` / `upgrade.c`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_db::Connection;
use pgbr_info::{CipherType, DbHistoryEntry, InfoArchive, InfoBackup, cipher_pass_gen};
use pgbr_io::IoRead;
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

/// The resolved repository cipher configuration for one repository index.
///
/// `repo-cipher-type` is a `repo`-group `string-id`; `repo-cipher-pass` is the
/// user passphrase (a secure string). Both are read at the repository's own
/// group index so each configured repository keeps its own encryption settings.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoCipherConfig {
    cipher_type: CipherType,
    /// The user passphrase (`repo-cipher-pass`); required when encrypted.
    user_pass: Option<String>,
}

impl RepoCipherConfig {
    /// Read the repository cipher configuration from the resolved options at
    /// repository group index `index`.
    fn from_config(config: &LoadedConfig, index: u32) -> Self {
        let cipher_type = repo_string_id(config, "repo-cipher-type", index).map_or(CipherType::None, CipherType::from_str_id);
        let user_pass = repo_string(config, "repo-cipher-pass", index)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        Self { cipher_type, user_pass }
    }

    /// The passphrase under which info files are encrypted, or `None` when the
    /// repository is unencrypted.
    fn passphrase(&self) -> Option<&str> {
        if self.cipher_type.is_encrypted() {
            self.user_pass.as_deref()
        } else {
            None
        }
    }

    /// Validate that an encrypted repository has a passphrase configured.
    fn require_passphrase(&self) -> Result<(), CommandError> {
        if self.cipher_type.is_encrypted() && self.user_pass.as_deref().is_none_or(str::is_empty) {
            return Err(CommandError::MissingOption {
                option: "repo-cipher-pass".to_owned(),
            });
        }
        Ok(())
    }
}

/// Fetch a `repo`-group `StringId` option at group index `index`.
fn repo_string_id<'a>(config: &'a LoadedConfig, name: &str, index: u32) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), Some(index))) {
        Some(OptionValue::StringId(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Fetch a `repo`-group `String` option at group index `index`.
fn repo_string<'a>(config: &'a LoadedConfig, name: &str, index: u32) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), Some(index))) {
        Some(OptionValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
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

/// `server_version_num` from `pg_settings` (an int4). Shared by the local
/// (libpq) and remote (worker) identity readers so they never drift.
const SQL_SERVER_VERSION_NUM: &str = "select (select setting from pg_catalog.pg_settings where name = 'server_version_num')::int4";

/// `system_identifier` / `catalog_version_no` / `pg_control_version` (all as
/// text) from `pg_control_system()` (PG 9.6+).
const SQL_PG_CONTROL_SYSTEM: &str = "select system_identifier::text, catalog_version_no::text, pg_control_version::text \
     from pg_catalog.pg_control_system()";

/// Assemble a [`DbIdentityRow`] from the four raw scalar texts and hand it to the
/// pure [`query_result_to_identity`] mapper. Shared by the libpq and remote
/// paths.
fn identity_from_scalars(
    server_version_num: Option<&str>,
    system_identifier: Option<&str>,
    catalog_version_no: Option<&str>,
    pg_control_version: Option<&str>,
) -> Result<ClusterIdentity, CommandError> {
    let server_version_num = server_version_num
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read server_version_num from pg_settings".to_owned()))?;
    let system_identifier = system_identifier
        .and_then(|s| s.trim().parse::<u64>().ok())
        .ok_or_else(|| CommandError::Other("could not read system_identifier from pg_control_system()".to_owned()))?;
    let catalog_version_no = catalog_version_no
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read catalog_version_no from pg_control_system()".to_owned()))?;
    let pg_control_version = pg_control_version
        .and_then(|s| s.trim().parse::<u32>().ok())
        .ok_or_else(|| CommandError::Other("could not read pg_control_version from pg_control_system()".to_owned()))?;

    query_result_to_identity(DbIdentityRow {
        server_version_num,
        system_identifier,
        catalog_version_no,
        pg_control_version,
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
        .query(SQL_SERVER_VERSION_NUM)
        .map_err(|err| CommandError::Other(err.to_string()))?;
    let control_result = conn
        .query(SQL_PG_CONTROL_SYSTEM)
        .map_err(|err| CommandError::Other(err.to_string()))?;

    identity_from_scalars(
        version_result.value(0, 0).as_deref(),
        control_result.value(0, 0).as_deref(),
        control_result.value(0, 1).as_deref(),
        control_result.value(0, 2).as_deref(),
    )
}

/// Read the cluster identity from a worker on the PG host (the dedicated-repo-host
/// pull topology, `pgN-host`).
///
/// Spawns the SSH worker, opens its connection against the PG host's *local*
/// cluster (no `host=<pghost>`), runs the **same** two queries as
/// [`cluster_identity_from_db`] via the worker `db-query` protocol, then closes
/// the worker connection. `index` is the 1-based `pgN` group index.
///
/// # Errors
///
/// [`CommandError::Other`] when the worker cannot be spawned, its `db-open`
/// fails, a query fails, or the identity cannot be derived.
fn cluster_identity_from_remote(config: &LoadedConfig, host: &str, index: u32) -> Result<ClusterIdentity, CommandError> {
    let conninfo = crate::remote_db::local_conninfo_for_index(config, index, &[]);
    let mut remote = crate::remote_db::spawn_pg_worker(config, host, index)?;
    remote.open(&conninfo)?;

    let version_rows = remote.query(SQL_SERVER_VERSION_NUM)?;
    let control_rows = remote.query(SQL_PG_CONTROL_SYSTEM)?;
    let _ = remote.close();

    let version_value = version_rows.rows.first().and_then(|r| r.first()).and_then(Clone::clone);
    let control_row = control_rows.rows.first();
    let system_identifier = control_row.and_then(|r| r.first()).and_then(Clone::clone);
    let catalog_version_no = control_row.and_then(|r| r.get(1)).and_then(Clone::clone);
    let pg_control_version = control_row.and_then(|r| r.get(2)).and_then(Clone::clone);

    identity_from_scalars(
        version_value.as_deref(),
        system_identifier.as_deref(),
        catalog_version_no.as_deref(),
        pg_control_version.as_deref(),
    )
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

    // Group options are stored under the base name keyed by group index — a
    // config-file `pg1-host` resolves to `("pg-host", Some(1))`, with an
    // ungrouped `("pg-host", None)` fallback (the scheme `storage_helper` uses).
    // The flat `pg1-…` spelling is accepted last for unit-test fixtures.
    let opt = |field: &str| -> Option<String> {
        let base = format!("pg-{field}");
        let legacy = format!("pg1-{field}");
        config
            .options
            .get(&(base.clone(), Some(1)))
            .or_else(|| config.options.get(&(base, None)))
            .or_else(|| config.options.get(&(legacy, None)))
            .and_then(|v| match v {
                OptionValue::String(s) | OptionValue::Path(s) | OptionValue::StringId(s) if !s.is_empty() => Some(s.clone()),
                OptionValue::Integer(i) => Some(i.to_string()),
                _ => None,
            })
    };

    // Only treat the cluster as connectable when a host or a unix-socket
    // directory is configured; otherwise leave the on-disk path as the source.
    // libpq accepts a directory in `host=` and reads it as a socket dir.
    let host = opt("host").or_else(|| opt("socket-path"))?;

    let mut parts: Vec<String> = vec![format!("host={host}")];
    if let Some(p) = opt("port") {
        parts.push(format!("port={p}"));
    }
    if let Some(db) = opt("database") {
        parts.push(format!("dbname={db}"));
    }
    if let Some(user) = opt("user") {
        parts.push(format!("user={user}"));
    }

    // Connection timeout (`db-timeout`, a `time` option in milliseconds) maps to
    // libpq `connect_timeout`, which is expressed in *seconds*. Round up so a
    // sub-second timeout still yields at least one second (libpq treats 0 as
    // "no timeout", which would silently disable the bound). C ref: the
    // `connect_timeout` set from `cfgOptionUInt64(cfgOptDbTimeout)` in
    // `src/db/db.c` / `src/postgres/client.c`.
    if let Some(ms) = time_opt(config, "db-timeout") {
        let secs = ms.div_ceil(1000).max(1);
        parts.push(format!("connect_timeout={secs}"));
    }

    // TCP keepalive (`tcp-keep-alive-idle` / `-interval` / `-count`, integer
    // seconds / probe counts) maps to the libpq `keepalives_*` parameters. Any
    // configured value turns keepalives on (`keepalives=1`); each present knob is
    // forwarded. C ref: `pgClientOpen` setting `keepalives_idle` /
    // `keepalives_interval` / `keepalives_count` in `src/postgres/client.c`.
    let idle = integer_opt(config, "tcp-keep-alive-idle");
    let interval = integer_opt(config, "tcp-keep-alive-interval");
    let count = integer_opt(config, "tcp-keep-alive-count");
    if idle.is_some() || interval.is_some() || count.is_some() {
        parts.push("keepalives=1".to_owned());
        if let Some(v) = idle {
            parts.push(format!("keepalives_idle={v}"));
        }
        if let Some(v) = interval {
            parts.push(format!("keepalives_interval={v}"));
        }
        if let Some(v) = count {
            parts.push(format!("keepalives_count={v}"));
        }
    }

    Some(parts.join(" "))
}

/// Read a `time` option (milliseconds) with no group index.
fn time_opt(config: &LoadedConfig, name: &str) -> Option<u64> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Time(ms)) => Some(*ms),
        _ => None,
    }
}

/// Read an `integer` option with no group index, dropping non-positive values
/// (libpq keepalive knobs are positive seconds / probe counts).
fn integer_opt(config: &LoadedConfig, name: &str) -> Option<i64> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Integer(v)) if *v > 0 => Some(*v),
        _ => None,
    }
}

/// The `pgN` index stanza-create / -upgrade read the cluster identity at.
const STANZA_PG_INDEX: u32 = 1;

/// Resolve the cluster identity, preferring a live `PostgreSQL` connection when
/// one is configured and falling back to the on-disk `global/pg_control`
/// otherwise.
///
/// When `pg1-host` is set (the dedicated-repo-host pull topology), the identity
/// is read through a worker on the PG host (a *local* connection there), not via
/// a direct TCP connect from the repo host. Otherwise a derivable
/// `pg1-*` / `DATABASE_URL` connection is opened locally with libpq, and a bare
/// local `pg1-path` falls back to reading the on-disk control file.
fn resolve_cluster_identity(config: &LoadedConfig, pg_storage: &dyn Storage) -> Result<ClusterIdentity, CommandError> {
    if let Some(host) = crate::remote_db::pg_host_for_index(config, STANZA_PG_INDEX) {
        return cluster_identity_from_remote(config, &host, STANZA_PG_INDEX);
    }
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
pub fn create(config: &LoadedConfig, repo_storages: &[(u32, &dyn Storage)], pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    if repo_storages.is_empty() {
        return Err(CommandError::Other(
            "stanza-create requires at least one repository".to_owned(),
        ));
    }
    // Hold both archive+backup locks for the whole command. C ref: lockAcquire(lockTypeAll).
    let _locks = acquire_command_lock(config, LockType::All)?;

    // Validate every repository's cipher config up front so a missing passphrase
    // fails before any repository is touched.
    let mut ciphers = Vec::with_capacity(repo_storages.len());
    for (index, _) in repo_storages {
        let cipher = RepoCipherConfig::from_config(config, *index);
        cipher.require_passphrase()?;
        ciphers.push(cipher);
    }

    // The cluster identity does not vary by repository: resolve it once.
    let identity = resolve_cluster_identity(config, pg_storage)?;
    for ((_, repo_storage), cipher) in repo_storages.iter().zip(&ciphers) {
        create_with_identity(stanza, *repo_storage, identity.clone(), cipher)?;
    }
    Ok(())
}

/// Test/`pg_control`-only convenience: read the identity off disk, then create.
#[cfg(test)]
fn create_inner(stanza: &str, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<CreateOutcome, CommandError> {
    let identity = read_cluster_identity(pg_storage)?;
    create_with_identity(
        stanza,
        repo_storage,
        identity,
        &RepoCipherConfig {
            cipher_type: CipherType::None,
            user_pass: None,
        },
    )
}

fn create_with_identity(
    stanza: &str,
    repo_storage: &dyn Storage,
    identity: ClusterIdentity,
    cipher: &RepoCipherConfig,
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

    // For an encrypted repository, generate a fresh random sub-key per info
    // file (archive + backup get *distinct* sub-keys, matching pgBackRest's
    // two `cipherPassGen` calls in `cmdStanzaCreate`). The sub-key is stored in
    // the file's [cipher] section and the whole file is then encrypted under
    // the user passphrase.
    let (archive_cipher_pass, backup_cipher_pass) = if cipher.cipher_type.is_encrypted() {
        (Some(cipher_pass_gen()), Some(cipher_pass_gen()))
    } else {
        (None, None)
    };

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

    let passphrase = cipher.passphrase();
    archive
        .save_keyed(repo_storage, &archive_info_path, passphrase, archive_cipher_pass.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;
    backup
        .save_keyed(repo_storage, &backup_info_path, passphrase, backup_cipher_pass.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(CreateOutcome {
        db_version: identity.version,
        db_system_id: header.system_identifier,
    })
}

/// `true` when the info file at `path` is encrypted, detected by pgBackRest's
/// `"Salted__"` cipher header at the start of the file.
fn info_file_is_encrypted(storage: &dyn Storage, path: &Path) -> Result<bool, CommandError> {
    let mut reader = storage.open_read(path)?;
    let mut head = [0u8; 8];
    let mut filled = 0;
    // Read up to 8 bytes (the magic length); a shorter file simply isn't
    // encrypted in this format.
    while filled < head.len() {
        let n = reader.read(&mut head[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled == head.len() && &head == b"Salted__")
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
pub fn delete(config: &LoadedConfig, repo_storages: &[(u32, &dyn Storage)]) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    // Hold both archive+backup locks for the whole command. C ref: lockAcquire(lockTypeAll).
    let _locks = acquire_command_lock(config, LockType::All)?;

    let archive: PathBuf = format!("archive/{stanza}").into();
    let backup: PathBuf = format!("backup/{stanza}").into();

    // Remove the stanza from every configured repository (idempotent per repo).
    for (_, repo_storage) in repo_storages {
        remove_subtree(*repo_storage, &archive)?;
        remove_subtree(*repo_storage, &backup)?;
    }
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
pub fn upgrade(config: &LoadedConfig, repo_storages: &[(u32, &dyn Storage)], pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    if repo_storages.is_empty() {
        return Err(CommandError::Other(
            "stanza-upgrade requires at least one repository".to_owned(),
        ));
    }
    // Hold both archive+backup locks for the whole command. C ref: lockAcquire(lockTypeAll).
    let _locks = acquire_command_lock(config, LockType::All)?;

    // Validate every repository's cipher config up front.
    let mut ciphers = Vec::with_capacity(repo_storages.len());
    for (index, _) in repo_storages {
        let cipher = RepoCipherConfig::from_config(config, *index);
        cipher.require_passphrase()?;
        ciphers.push(cipher);
    }

    // The cluster identity does not vary by repository: resolve it once.
    let identity = resolve_cluster_identity(config, pg_storage)?;
    for ((_, repo_storage), cipher) in repo_storages.iter().zip(&ciphers) {
        upgrade_with_identity(stanza, *repo_storage, identity.clone(), cipher)?;
    }
    Ok(())
}

/// Test/`pg_control`-only convenience: read the identity off disk, then upgrade.
#[cfg(test)]
fn upgrade_inner(stanza: &str, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<UpgradeOutcome, CommandError> {
    let identity = read_cluster_identity(pg_storage)?;
    upgrade_with_identity(
        stanza,
        repo_storage,
        identity,
        &RepoCipherConfig {
            cipher_type: CipherType::None,
            user_pass: None,
        },
    )
}

fn upgrade_with_identity(
    stanza: &str,
    repo_storage: &dyn Storage,
    identity: ClusterIdentity,
    cipher: &RepoCipherConfig,
) -> Result<UpgradeOutcome, CommandError> {
    let archive_info_path = archive_info_path(stanza);
    let backup_info_path = backup_info_path(stanza);

    if !repo_storage.exists(&archive_info_path)? || !repo_storage.exists(&backup_info_path)? {
        return Err(CommandError::Other(
            "stanza not initialized; run stanza-create first".to_owned(),
        ));
    }

    // The cipher type must not change between create and upgrade: encryption is
    // a stanza-create-time decision. Detect the *on-disk* encryption state up
    // front (by the pgBackRest cipher header) and refuse to "add" encryption to
    // an existing unencrypted repository, or "drop" it from an encrypted one,
    // before attempting a decrypt that would otherwise fail cryptically.
    let on_disk_encrypted = info_file_is_encrypted(repo_storage, &archive_info_path)?;
    if on_disk_encrypted != cipher.cipher_type.is_encrypted() {
        return Err(CommandError::Other(
            "repo-cipher-type does not match the existing repository; encryption must be set at stanza-create".to_owned(),
        ));
    }

    let passphrase = cipher.passphrase();
    let (mut archive, archive_cipher_pass) = InfoArchive::load_keyed(repo_storage, &archive_info_path, passphrase)
        .map_err(|err| CommandError::Other(err.to_string()))?;
    let (mut backup, backup_cipher_pass) =
        InfoBackup::load_keyed(repo_storage, &backup_info_path, passphrase).map_err(|err| CommandError::Other(err.to_string()))?;

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

    // Preserve the existing repo sub-keys across the upgrade.
    archive
        .save_keyed(repo_storage, &archive_info_path, passphrase, archive_cipher_pass.as_deref())
        .map_err(|err| CommandError::Other(err.to_string()))?;
    backup
        .save_keyed(repo_storage, &backup_info_path, passphrase, backup_cipher_pass.as_deref())
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

    /// `config_with_stanza` plus `repo1-cipher-type=aes-256-cbc` +
    /// `repo1-cipher-pass`, exercising the encrypted info-file path.
    fn config_with_cipher(stanza: Option<&str>, pass: &str) -> LoadedConfig {
        let mut cfg = config_with_stanza(stanza);
        cfg.options.insert(
            ("repo-cipher-type".to_owned(), Some(1)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        cfg.options
            .insert(("repo-cipher-pass".to_owned(), Some(1)), OptionValue::String(pass.to_owned()));
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
        let err =
            create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect_err("create must fail while a component lock is held");
        assert!(err.to_string().contains("running"), "unexpected error: {err}");

        drop(held);
        create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("create succeeds once the locks are free");
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
        let err = delete(&cfg, &[(1, &repo_s as &dyn Storage)]).expect_err("delete must fail while a component lock is held");
        assert!(err.to_string().contains("running"), "unexpected error: {err}");

        drop(held);
        delete(&cfg, &[(1, &repo_s as &dyn Storage)]).expect("delete succeeds once the locks are free");
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
        let err =
            upgrade(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect_err("upgrade must fail while a component lock is held");
        assert!(err.to_string().contains("running"), "unexpected error: {err}");

        drop(held);
        upgrade(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("upgrade succeeds once the locks are free");
    }

    #[test]
    fn stanza_create_writes_info_files_from_pg_control() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let v = &SUPPORTED[0];
        let system_id: u64 = 0x0102_0304_0506_0708;
        write_pg_control(&pg_s, system_id, v);

        let cfg = config_with_stanza(Some("demo"));
        create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("stanza-create should succeed");

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
    fn stanza_create_encrypted_stores_repo_subkey() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let v = &SUPPORTED[0];
        let system_id: u64 = 0x0a0b_0c0d;
        write_pg_control(&pg_s, system_id, v);

        let cfg = config_with_cipher(Some("enc"), "user-passphrase");
        create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("encrypted stanza-create should succeed");

        // The on-disk info files must NOT be plaintext (they start with the
        // pgBackRest cipher header) and must NOT be loadable without the pass.
        let raw = {
            let mut r = repo_s.open_read(&archive_info_path("enc")).unwrap();
            r.read_all().unwrap()
        };
        assert_eq!(&raw[..8], b"Salted__", "encrypted info file uses pgBackRest framing");
        assert!(
            InfoArchive::load(&repo_s, &archive_info_path("enc")).is_err(),
            "plain load of an encrypted file must fail"
        );

        // The .copy mirror is written too.
        assert!(
            repo_s.exists(Path::new("archive/enc/archive.info.copy")).unwrap(),
            "archive.info.copy must exist"
        );
        assert!(
            repo_s.exists(Path::new("backup/enc/backup.info.copy")).unwrap(),
            "backup.info.copy must exist"
        );

        // Decrypting with the user passphrase recovers a [cipher] sub-key in
        // each info file, and the two sub-keys differ (distinct cipherPassGen).
        let (archive, arc_sub) = InfoArchive::load_keyed(&repo_s, &archive_info_path("enc"), Some("user-passphrase")).unwrap();
        let (_backup, bak_sub) = InfoBackup::load_keyed(&repo_s, &backup_info_path("enc"), Some("user-passphrase")).unwrap();
        let arc_sub = arc_sub.expect("archive carries a repo sub-key");
        let bak_sub = bak_sub.expect("backup carries a repo sub-key");
        assert_eq!(arc_sub.len(), 64, "sub-key is 64 base64 chars");
        assert_eq!(bak_sub.len(), 64);
        assert_ne!(arc_sub, bak_sub, "archive and backup get distinct sub-keys");
        assert_eq!(archive.db_system_id, system_id);
    }

    #[test]
    fn stanza_create_encrypted_without_pass_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);

        // cipher-type set but no cipher-pass.
        let mut cfg = config_with_stanza(Some("enc"));
        cfg.options.insert(
            ("repo-cipher-type".to_owned(), Some(1)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        let err = create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect_err("encrypted create needs a passphrase");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "repo-cipher-pass"),
            other => panic!("expected MissingOption(repo-cipher-pass), got {other:?}"),
        }
    }

    #[test]
    fn stanza_upgrade_encrypted_round_trips() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let system_id: u64 = 55;
        write_pg_control(&pg_s, system_id, &SUPPORTED[0]);

        let cfg = config_with_cipher(Some("enc"), "pw");
        create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("encrypted create");

        // The repo sub-key recorded at create time.
        let (_arc, sub_before) = InfoArchive::load_keyed(&repo_s, &archive_info_path("enc"), Some("pw")).unwrap();
        let sub_before = sub_before.unwrap();

        // A version change upgrades while preserving encryption + the sub-key.
        write_pg_control(&pg_s, system_id, &SUPPORTED[1]);
        upgrade(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("encrypted upgrade");

        let (archive, sub_after) = InfoArchive::load_keyed(&repo_s, &archive_info_path("enc"), Some("pw")).unwrap();
        assert_eq!(archive.db_version, SUPPORTED[1].label);
        assert_eq!(archive.db_id, 2);
        assert_eq!(
            sub_after.as_deref(),
            Some(sub_before.as_str()),
            "sub-key preserved across upgrade"
        );
    }

    #[test]
    fn stanza_upgrade_cipher_mismatch_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);

        // Create UNENCRYPTED.
        let cfg = config_with_stanza(Some("plain"));
        create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("unencrypted create");

        // Now try to upgrade while *adding* encryption.
        let enc_cfg = config_with_cipher(Some("plain"), "pw");
        let err = upgrade(&enc_cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect_err("adding encryption on upgrade must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("stanza-create"), "message was {msg:?}"),
            other => panic!("expected Other(cipher mismatch), got {other:?}"),
        }
    }

    #[test]
    fn stanza_create_missing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 1, &SUPPORTED[0]);

        let cfg = config_with_stanza(None);
        let err = create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect_err("stanza-create requires a stanza");
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
        create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("first create succeeds");

        let err = create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect_err("second create must fail");
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
    fn identity_from_scalars_parses_text_columns() {
        // The shared helper both the libpq and the remote (worker) readers use:
        // it parses the four raw scalar texts and maps them. A PG 16 row maps
        // cleanly to the "16" identity.
        let v = version::by_label("16").expect("PG 16 in registry");
        let identity = identity_from_scalars(
            Some("160004"),
            Some("6873049345984568091"),
            Some(&v.catalog_version_no.to_string()),
            Some(&v.pg_control_version.to_string()),
        )
        .expect("scalar texts map to PG 16 identity");
        assert_eq!(identity.version, "16");
        assert_eq!(identity.header.system_identifier, 6_873_049_345_984_568_091);
        assert_eq!(identity.header.catalog_version_no, v.catalog_version_no);

        // A missing server_version_num is a clear error (the worker returned no
        // value / SQL NULL).
        let err = identity_from_scalars(None, Some("1"), Some("1"), Some("1")).expect_err("missing version errors");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("server_version_num"), "{msg}"),
            other => panic!("expected Other(server_version_num), got {other:?}"),
        }
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

    #[test]
    fn derive_conninfo_appends_connect_timeout_from_db_timeout() {
        let mut cfg = config_with_stanza(Some("demo"));
        cfg.options
            .insert(("pg1-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        // db-timeout is a `time` option in milliseconds: 30_000 ms -> 30 s.
        cfg.options.insert(("db-timeout".to_owned(), None), OptionValue::Time(30_000));
        let conninfo = derive_conninfo_with_url(&cfg, None).expect("conninfo");
        assert!(conninfo.contains("connect_timeout=30"), "conninfo was {conninfo:?}");

        // A sub-second timeout still rounds up to at least one second so libpq
        // does not treat it as "no timeout".
        cfg.options.insert(("db-timeout".to_owned(), None), OptionValue::Time(250));
        let conninfo = derive_conninfo_with_url(&cfg, None).expect("conninfo");
        assert!(conninfo.contains("connect_timeout=1"), "conninfo was {conninfo:?}");
    }

    #[test]
    fn derive_conninfo_appends_keepalive_params() {
        let mut cfg = config_with_stanza(Some("demo"));
        cfg.options
            .insert(("pg1-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        cfg.options
            .insert(("tcp-keep-alive-idle".to_owned(), None), OptionValue::Integer(60));
        cfg.options
            .insert(("tcp-keep-alive-interval".to_owned(), None), OptionValue::Integer(10));
        cfg.options
            .insert(("tcp-keep-alive-count".to_owned(), None), OptionValue::Integer(5));
        let conninfo = derive_conninfo_with_url(&cfg, None).expect("conninfo");
        assert!(conninfo.contains("keepalives=1"), "conninfo was {conninfo:?}");
        assert!(conninfo.contains("keepalives_idle=60"), "conninfo was {conninfo:?}");
        assert!(conninfo.contains("keepalives_interval=10"), "conninfo was {conninfo:?}");
        assert!(conninfo.contains("keepalives_count=5"), "conninfo was {conninfo:?}");
    }

    #[test]
    fn derive_conninfo_keepalive_partial_still_enables() {
        // Only one keepalive knob set: keepalives is still turned on and just
        // that knob forwarded.
        let mut cfg = config_with_stanza(Some("demo"));
        cfg.options
            .insert(("pg1-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        cfg.options
            .insert(("tcp-keep-alive-idle".to_owned(), None), OptionValue::Integer(120));
        let conninfo = derive_conninfo_with_url(&cfg, None).expect("conninfo");
        assert!(conninfo.contains("keepalives=1"), "conninfo was {conninfo:?}");
        assert!(conninfo.contains("keepalives_idle=120"), "conninfo was {conninfo:?}");
        assert!(!conninfo.contains("keepalives_interval"), "conninfo was {conninfo:?}");
        assert!(!conninfo.contains("keepalives_count"), "conninfo was {conninfo:?}");
    }

    #[test]
    fn derive_conninfo_no_keepalive_or_timeout_when_unset() {
        let mut cfg = config_with_stanza(Some("demo"));
        cfg.options
            .insert(("pg1-host".to_owned(), None), OptionValue::String("db.example".to_owned()));
        let conninfo = derive_conninfo_with_url(&cfg, None).expect("conninfo");
        assert!(!conninfo.contains("keepalives"), "conninfo was {conninfo:?}");
        assert!(!conninfo.contains("connect_timeout"), "conninfo was {conninfo:?}");
    }

    #[test]
    fn derive_conninfo_database_url_unchanged_by_timeout_and_keepalive() {
        // A DATABASE_URL is a complete URI and must be returned verbatim — the
        // connect_timeout / keepalive params are only appended to the
        // config-derived conninfo, never to a user-supplied URL.
        let mut cfg = config_with_stanza(Some("demo"));
        cfg.options.insert(("db-timeout".to_owned(), None), OptionValue::Time(30_000));
        cfg.options
            .insert(("tcp-keep-alive-idle".to_owned(), None), OptionValue::Integer(60));
        assert_eq!(
            derive_conninfo_with_url(&cfg, Some("host=/tmp dbname=postgres")).as_deref(),
            Some("host=/tmp dbname=postgres"),
        );
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
        create(&cfg, &[(1, &repo_s as &dyn Storage)], &pg_s).expect("stanza-create via DB path");

        let archive = InfoArchive::load(&repo_s, &archive_info_path("dblive")).expect("archive.info");
        assert_eq!(archive.db_system_id, identity.header.system_identifier);
        assert_eq!(archive.db_version, identity.version);
    }

    // -----------------------------------------------------------------------
    // Multiple repositories
    // -----------------------------------------------------------------------

    #[test]
    fn stanza_create_initializes_every_repo() {
        // stanza-create must write archive.info + backup.info on EVERY
        // configured repository.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());
        write_pg_control(&pg_s, 0x0102_0304, &SUPPORTED[0]);

        let cfg = config_with_stanza(Some("demo"));
        create(&cfg, &[(1, &repo1_s as &dyn Storage), (2, &repo2_s as &dyn Storage)], &pg_s)
            .expect("multi-repo stanza-create should succeed");

        for repo in [&repo1_s, &repo2_s] {
            let archive = InfoArchive::load(repo, &archive_info_path("demo")).expect("archive.info on each repo");
            assert_eq!(archive.db_version, SUPPORTED[0].label);
            assert!(
                repo.exists(&backup_info_path("demo")).expect("exists"),
                "backup.info should exist on each repo"
            );
        }
    }

    #[test]
    fn stanza_create_honors_per_repo_cipher() {
        // repo1 is unencrypted; repo2 is encrypted with its own repo2-cipher-*.
        // Each repository must use its own cipher settings.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());
        write_pg_control(&pg_s, 0x0a0b_0c0d, &SUPPORTED[0]);

        let mut cfg = config_with_stanza(Some("demo"));
        // repo2 encrypted; repo1 left unencrypted (no repo1-cipher-*).
        cfg.options.insert(
            ("repo-cipher-type".to_owned(), Some(2)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        cfg.options.insert(
            ("repo-cipher-pass".to_owned(), Some(2)),
            OptionValue::String("repo2-pass".to_owned()),
        );

        create(&cfg, &[(1, &repo1_s as &dyn Storage), (2, &repo2_s as &dyn Storage)], &pg_s)
            .expect("multi-repo create with mixed cipher should succeed");

        // repo1: plaintext info file, loadable without a passphrase.
        assert!(
            InfoArchive::load(&repo1_s, &archive_info_path("demo")).is_ok(),
            "repo1 (unencrypted) info must load plainly"
        );

        // repo2: encrypted (pgBackRest cipher header), not plainly loadable, but
        // loadable with repo2's passphrase.
        let raw = {
            let mut r = repo2_s.open_read(&archive_info_path("demo")).unwrap();
            r.read_all().unwrap()
        };
        assert_eq!(&raw[..8], b"Salted__", "repo2 info must be encrypted");
        assert!(
            InfoArchive::load(&repo2_s, &archive_info_path("demo")).is_err(),
            "plain load of repo2's encrypted file must fail"
        );
        assert!(
            InfoArchive::load_keyed(&repo2_s, &archive_info_path("demo"), Some("repo2-pass")).is_ok(),
            "repo2 info must load with repo2's passphrase"
        );
    }

    #[test]
    fn stanza_create_missing_pass_on_one_repo_fails_before_writing() {
        // repo2 declares encryption but no passphrase: the whole command must
        // fail up front, leaving repo1 untouched.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);

        let mut cfg = config_with_stanza(Some("demo"));
        cfg.options.insert(
            ("repo-cipher-type".to_owned(), Some(2)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );

        let err = create(&cfg, &[(1, &repo1_s as &dyn Storage), (2, &repo2_s as &dyn Storage)], &pg_s)
            .expect_err("missing passphrase on any repo must fail the command");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "repo-cipher-pass"),
            other => panic!("expected MissingOption(repo-cipher-pass), got {other:?}"),
        }
        assert!(
            !repo1_s.exists(&archive_info_path("demo")).expect("exists"),
            "repo1 must be untouched when validation fails up front"
        );
    }

    #[test]
    fn stanza_delete_removes_from_every_repo() {
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);

        let mut cfg = config_with_stanza(Some("demo"));
        create(&cfg, &[(1, &repo1_s as &dyn Storage), (2, &repo2_s as &dyn Storage)], &pg_s).expect("seed both repos");

        cfg.command = "stanza-delete".to_owned();
        delete(&cfg, &[(1, &repo1_s as &dyn Storage), (2, &repo2_s as &dyn Storage)]).expect("delete from both repos");

        for repo in [&repo1_s, &repo2_s] {
            assert!(
                !repo.exists(Path::new("archive/demo")).expect("exists"),
                "archive/demo should be gone from each repo"
            );
            assert!(
                !repo.exists(Path::new("backup/demo")).expect("exists"),
                "backup/demo should be gone from each repo"
            );
        }
    }

    #[test]
    fn stanza_upgrade_applies_to_every_repo() {
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());
        let system_id: u64 = 99;
        write_pg_control(&pg_s, system_id, &SUPPORTED[0]);

        let mut cfg = config_with_stanza(Some("demo"));
        let repo_set: [(u32, &dyn Storage); 2] = [(1, &repo1_s as &dyn Storage), (2, &repo2_s as &dyn Storage)];
        create(&cfg, &repo_set, &pg_s).expect("seed both repos");

        // Same cluster, new PG version → both repos upgrade to db-id 2.
        write_pg_control(&pg_s, system_id, &SUPPORTED[1]);
        cfg.command = "stanza-upgrade".to_owned();
        upgrade(&cfg, &repo_set, &pg_s).expect("upgrade both repos");

        for repo in [&repo1_s, &repo2_s] {
            let archive = InfoArchive::load(repo, &archive_info_path("demo")).expect("archive.info");
            assert_eq!(archive.db_id, 2, "each repo should be upgraded");
            assert_eq!(archive.db_version, SUPPORTED[1].label);
        }
    }
}
