//! Remote DB control over a spawned `pgbackrest` worker, for the dedicated
//! repository host ("pull") topology.
//!
//! When `pgN-host` is set, backup / check / stanza-create run **on the repo
//! host** but the `PostgreSQL` control connection must run **on the PG host** —
//! a worker there opens a *local* libpq connection over the unix socket
//! (peer / trust auth → no password) rather than the repo host connecting back
//! over TCP (which fails `fe_sendauth: no password supplied`). The file side
//! already reaches the PG host through an SSH worker
//! ([`crate::worker`] / `pgbr_storage::remote::RemoteStorage`); this module is
//! the DB analogue.
//!
//! C reference: `src/db/db.c` driving `src/db/protocol.c` over the protocol
//! helper, i.e. `dbGet` choosing a remote `dbProtocol` connection when the
//! cluster is not local.
//!
//! Pieces:
//!
//! - [`RemoteDb`] — wraps a [`ProtocolClient`] (and, when spawned, the worker
//!   [`Child`] so its pipes stay live) and exposes `open` / `query` / `execute`
//!   / `close` by sending `db-open` / `db-query` / `db-execute` / `db-close`.
//!   Generic over the byte transport so it is exercised in tests over in-process
//!   pipes without spawning a real child.
//! - [`spawn_pg_worker`] — spawn the SSH worker on the PG host and wrap its
//!   protocol client in a [`RemoteDb`], reading the `pgN-host*` SSH family from
//!   the resolved config.
//! - [`local_conninfo_for_index`] — build the *local* libpq conninfo for the
//!   `db-open` parameter: `pgN-socket-path` / `pgN-port` / `pgN-database` /
//!   `pgN-user`, but **never** `host=<pghost>` (the worker is already on the PG
//!   host, so it connects to the local cluster's default / configured socket).

use std::process::{Child, ChildStdin, ChildStdout};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_db::{DbProtocolClient, QueryRows};
use pgbr_io::{IoRead, IoWrite};
use pgbr_protocol::transport::{PipeRead, PipeWrite};
use pgbr_protocol::{PGBACKREST_PROGRAM, ProcessClient, ProtocolClient};

use crate::CommandError;

/// The `pgbackrest` command the spawned worker is invoked with. The
/// `<command>:remote` form makes the child's [`crate::worker::is_worker`]
/// recognise the `Remote` command role and serve the protocol (storage **and**
/// db) on its stdio. `backup` declares the `remote` role and accepts `pg-path`,
/// matching the storage helper's worker command so one worker covers both the
/// file and DB sides on the PG host.
const WORKER_COMMAND_REMOTE: &str = "backup:remote";

/// A remote `PostgreSQL` control channel: a [`ProtocolClient`] to a worker that
/// owns the actual libpq connection.
///
/// Generic over the reader / writer so it works over child pipes
/// ([`PipeRead`] / [`PipeWrite`]) in production and in-process pipes in tests.
/// When built from a spawned worker the [`Child`] is retained so the worker's
/// stdin / stdout pipes outlive the client; on [`Drop`] the worker is reaped
/// after the client (and its write pipe) is gone, so the worker reads EOF and
/// exits.
pub struct RemoteDb<R: IoRead, W: IoWrite> {
    /// `Some` for a spawned worker, `None` when driven over caller-supplied
    /// pipes (tests). Dropped after `client` (declaration order = drop order).
    child: Option<Child>,
    client: ProtocolClient<R, W>,
}

/// The concrete [`RemoteDb`] over a spawned child's pipes.
pub type ProcessRemoteDb = RemoteDb<PipeRead<ChildStdout>, PipeWrite<ChildStdin>>;

impl<R: IoRead, W: IoWrite> RemoteDb<R, W> {
    /// Wrap an existing [`ProtocolClient`] (no child to reap). Used in tests to
    /// drive a worker `serve` loop over in-process pipes.
    pub const fn new(client: ProtocolClient<R, W>) -> Self {
        Self { child: None, client }
    }

    /// Open the worker's libpq connection from the *local* `conninfo` (sent as
    /// the `db-open` parameter; the worker opens it on the PG host).
    ///
    /// # Errors
    ///
    /// [`CommandError::Other`] if the request fails or the worker reports an
    /// error (e.g. the libpq connect failed on the PG host).
    pub fn open(&mut self, conninfo: &str) -> Result<(), CommandError> {
        let resp = self
            .client
            .execute(&DbProtocolClient::open_request(conninfo))
            .map_err(|err| CommandError::Other(format!("remote db-open: {err}")))?;
        DbProtocolClient::decode_unit_response(&pgbr_protocol::Response::Ok(resp))
            .map_err(|err| CommandError::Other(format!("remote db-open: {err}")))
    }

    /// Run a `SELECT`-style query on the worker's connection, returning the rows.
    ///
    /// # Errors
    ///
    /// [`CommandError::Other`] if the request fails or the worker reports an
    /// error / an undecodable result.
    pub fn query(&mut self, sql: &str) -> Result<QueryRows, CommandError> {
        let resp = self
            .client
            .execute(&DbProtocolClient::query_request(sql))
            .map_err(|err| CommandError::Other(format!("remote db-query: {err}")))?;
        DbProtocolClient::decode_query_response(&pgbr_protocol::Response::Ok(resp))
            .map_err(|err| CommandError::Other(format!("remote db-query: {err}")))
    }

    /// Run a statement that returns no rows on the worker's connection.
    ///
    /// # Errors
    ///
    /// [`CommandError::Other`] if the request fails or the worker reports an
    /// error.
    pub fn execute(&mut self, sql: &str) -> Result<(), CommandError> {
        let resp = self
            .client
            .execute(&DbProtocolClient::execute_request(sql))
            .map_err(|err| CommandError::Other(format!("remote db-execute: {err}")))?;
        DbProtocolClient::decode_unit_response(&pgbr_protocol::Response::Ok(resp))
            .map_err(|err| CommandError::Other(format!("remote db-execute: {err}")))
    }

    /// Close the worker's connection (best-effort; idempotent on the worker).
    ///
    /// # Errors
    ///
    /// [`CommandError::Other`] if the request fails or the worker reports an
    /// error.
    pub fn close(&mut self) -> Result<(), CommandError> {
        let resp = self
            .client
            .execute(&DbProtocolClient::close_request())
            .map_err(|err| CommandError::Other(format!("remote db-close: {err}")))?;
        DbProtocolClient::decode_unit_response(&pgbr_protocol::Response::Ok(resp))
            .map_err(|err| CommandError::Other(format!("remote db-close: {err}")))
    }
}

impl<R: IoRead, W: IoWrite> Drop for RemoteDb<R, W> {
    fn drop(&mut self) {
        // The client (and its write pipe) is dropped after this returns, per
        // field order — but reap defensively so `wait` does not block on a
        // worker that has not yet read EOF: kill (a no-op for an already-exited
        // worker), then wait to avoid a zombie. Errors are not actionable in
        // Drop, so they are ignored.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn the SSH worker on `host` (the resolved `pgN-host`) and wrap its
/// protocol client in a [`RemoteDb`]. The worker serves the db-* protocol on
/// its stdio (it also serves storage-*, unused here).
///
/// `index` is the 1-based `pgN` group index. The SSH connection params come
/// from the matching `pgN-host-{user,port,cmd}` family; the worker is invoked
/// as `<host-cmd> backup:remote --stanza=<s> --pg1-path=<pgN-path>` so it roots
/// at the remote data directory (the worker reads `pg1-path` to pick its root).
///
/// # Errors
///
/// [`CommandError::MissingOption`] when `pgN-path` is not configured (the worker
/// needs a root), or [`CommandError::Other`] when the `ssh` process cannot be
/// spawned.
pub fn spawn_pg_worker(config: &LoadedConfig, host: &str, index: u32) -> Result<ProcessRemoteDb, CommandError> {
    let remote_path = pg_string_option(config, "path", index).ok_or_else(|| CommandError::MissingOption {
        option: format!("pg{index}-path"),
    })?;

    let ssh_user = pg_string_option(config, "host-user", index);
    let ssh_port = pg_integer_option(config, "host-port", index).and_then(|p| u16::try_from(p).ok());
    let remote_program = pg_string_option(config, "host-cmd", index).unwrap_or_else(|| PGBACKREST_PROGRAM.to_owned());

    let mut remote_args = vec![WORKER_COMMAND_REMOTE.to_owned()];
    if let Some(stanza) = &config.stanza {
        remote_args.push(format!("--stanza={stanza}"));
    }
    remote_args.push(format!("--pg1-path={remote_path}"));

    let process = ProcessClient::spawn_ssh(host, ssh_port, ssh_user.as_deref(), &remote_program, &remote_args)
        .map_err(|err| CommandError::Other(format!("spawn pg worker on {host}: {err}")))?;
    let (child, client) = process.into_parts();
    Ok(RemoteDb {
        child: Some(child),
        client,
    })
}

/// Build the *local* libpq conninfo for the `db-open` parameter at `pgN`.
///
/// Reads `pgN-socket-path` / `pgN-port` / `pgN-database` / `pgN-user` (plus the
/// global `db-timeout` / keepalive params via `extra`) but **omits** `host=` —
/// the worker is already on the PG host, so the connection uses the local
/// default / configured unix socket (peer / trust auth, no password). The result
/// may be empty (no socket / port / db / user configured), in which case libpq
/// connects to its compiled-in defaults — the intended local-cluster behaviour.
#[must_use]
pub fn local_conninfo_for_index(config: &LoadedConfig, index: u32, extra: &[String]) -> String {
    let socket_path = pg_string_option(config, "socket-path", index);
    let port = pg_string_option(config, "port", index);
    let database = pg_string_option(config, "database", index);
    let user = pg_string_option(config, "user", index);

    let mut parts: Vec<String> = Vec::new();
    if let Some(socket) = socket_path {
        // libpq reads a directory in `host=` as the unix-socket directory.
        parts.push(format!("host={socket}"));
    }
    if let Some(p) = port {
        parts.push(format!("port={p}"));
    }
    if let Some(db) = database {
        parts.push(format!("dbname={db}"));
    }
    if let Some(u) = user {
        parts.push(format!("user={u}"));
    }
    parts.extend(extra.iter().cloned());
    parts.join(" ")
}

/// Read a `pgN-<field>` string-like option at group index `index`, mirroring the
/// resolution `derive_conninfo_for_index` / `storage_helper` use: grouped base
/// key first (`("pg-<field>", Some(index))`), then the ungrouped base
/// (`("pg-<field>", None)`), then the flat `("pgN-<field>", None)` spelling
/// (for unit-test fixtures). Integers are stringified.
fn pg_string_option(config: &LoadedConfig, field: &str, index: u32) -> Option<String> {
    let base = format!("pg-{field}");
    let legacy = format!("pg{index}-{field}");
    config
        .options
        .get(&(base.clone(), Some(index)))
        .or_else(|| config.options.get(&(base, None)))
        .or_else(|| config.options.get(&(legacy, None)))
        .and_then(|v| match v {
            OptionValue::String(s) | OptionValue::Path(s) | OptionValue::StringId(s) if !s.is_empty() => Some(s.clone()),
            OptionValue::Integer(i) => Some(i.to_string()),
            _ => None,
        })
}

/// Read a `pgN-<field>` integer option at group index `index`, with the same
/// key-resolution fallback as [`pg_string_option`].
fn pg_integer_option(config: &LoadedConfig, field: &str, index: u32) -> Option<i64> {
    let base = format!("pg-{field}");
    let legacy = format!("pg{index}-{field}");
    config
        .options
        .get(&(base.clone(), Some(index)))
        .or_else(|| config.options.get(&(base, None)))
        .or_else(|| config.options.get(&(legacy, None)))
        .and_then(|v| match v {
            OptionValue::Integer(i) => Some(*i),
            _ => None,
        })
}

/// The resolved `pgN-host` for `index`, when set.
///
/// This is the predicate that selects the remote DB path. Reads the grouped base
/// key, the ungrouped base, then the flat `pgN-host` spelling, matching the other
/// `pg`-family readers.
#[must_use]
pub fn pg_host_for_index(config: &LoadedConfig, index: u32) -> Option<String> {
    pg_string_option(config, "host", index)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};

    use super::{local_conninfo_for_index, pg_host_for_index};

    fn cfg(opts: &[(&str, Option<u32>, OptionValue)]) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        for (name, idx, value) in opts {
            options.insert(((*name).to_owned(), *idx), value.clone());
        }
        LoadedConfig {
            command: "check".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn pg_host_detected_from_grouped_and_legacy_keys() {
        // Grouped base key (the config-file spelling).
        let grouped = cfg(&[("pg-host", Some(1), OptionValue::String("pg.example".to_owned()))]);
        assert_eq!(pg_host_for_index(&grouped, 1).as_deref(), Some("pg.example"));
        // No pg2-host -> None for index 2.
        assert_eq!(pg_host_for_index(&grouped, 2), None);

        // Flat legacy spelling (unit-test fixture style).
        let legacy = cfg(&[("pg1-host", None, OptionValue::String("legacy.example".to_owned()))]);
        assert_eq!(pg_host_for_index(&legacy, 1).as_deref(), Some("legacy.example"));
    }

    #[test]
    fn local_conninfo_omits_host_uses_socket_path() {
        // The conninfo sent to the worker's db-open must NOT carry host=<pghost>
        // (that would make the worker connect back over TCP). With pg1-host set
        // (the remote selector) plus a socket path, the local conninfo uses the
        // socket dir, the port, db, and user — never the host.
        let config = cfg(&[
            ("pg-host", Some(1), OptionValue::String("pg.example".to_owned())),
            ("pg-socket-path", Some(1), OptionValue::Path("/var/run/postgresql".to_owned())),
            ("pg-port", Some(1), OptionValue::Integer(5433)),
            ("pg-database", Some(1), OptionValue::String("postgres".to_owned())),
            ("pg-user", Some(1), OptionValue::String("pgbackrest".to_owned())),
        ]);
        let conninfo = local_conninfo_for_index(&config, 1, &[]);
        assert!(
            !conninfo.contains("pg.example"),
            "local conninfo must not carry the remote host: {conninfo:?}"
        );
        assert!(conninfo.contains("host=/var/run/postgresql"), "{conninfo:?}");
        assert!(conninfo.contains("port=5433"), "{conninfo:?}");
        assert!(conninfo.contains("dbname=postgres"), "{conninfo:?}");
        assert!(conninfo.contains("user=pgbackrest"), "{conninfo:?}");
    }

    #[test]
    fn local_conninfo_without_socket_is_bare_defaults() {
        // No socket/port/db/user configured (only pg1-host + pg1-path elsewhere):
        // the local conninfo is empty, so libpq uses its compiled-in default
        // socket — the intended local-cluster behaviour.
        let config = cfg(&[("pg-host", Some(1), OptionValue::String("pg.example".to_owned()))]);
        let conninfo = local_conninfo_for_index(&config, 1, &[]);
        assert!(
            !conninfo.contains("host=pg.example"),
            "must not connect back to the remote host: {conninfo:?}"
        );
        assert!(conninfo.trim().is_empty(), "expected empty default conninfo: {conninfo:?}");
    }

    #[test]
    fn local_conninfo_appends_extra_params() {
        let config = cfg(&[("pg-host", Some(1), OptionValue::String("pg.example".to_owned()))]);
        let extra = vec!["connect_timeout=30".to_owned(), "keepalives=1".to_owned()];
        let conninfo = local_conninfo_for_index(&config, 1, &extra);
        assert!(conninfo.contains("connect_timeout=30"), "{conninfo:?}");
        assert!(conninfo.contains("keepalives=1"), "{conninfo:?}");
    }
}
