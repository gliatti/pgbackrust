//! Remote DB protocol: message-mapping layer.
//!
//! pgBackRust's main process drives a remote worker that owns a libpq
//! [`Connection`] and answers a small set of protocol commands on its
//! behalf (C reference: `src/db/protocol.c`, `dbOpenProtocol` /
//! `dbQueryProtocol`). This module provides the pieces, all decoupled
//! from the byte transport (which lives in `pgbr_protocol::codec` /
//! `transport`):
//!
//! - [`DbExecutor`] — a trait abstracting query execution so the handler
//!   can be unit-tested without a real libpq connection. It is implemented
//!   for [`Connection`] (the real path).
//! - [`handle_db_request`] — the stateless server side over an existing
//!   executor: maps a [`pgbr_protocol::Request`] (`db-query` / `db-execute`)
//!   to a [`pgbr_protocol::Response`].
//! - [`DbRequestHandler`] — the stateful server side a worker uses: it owns
//!   an `Option<Connection>` and additionally serves `db-open` (open a libpq
//!   connection *locally*, on the PG host) and `db-close` (drop it). The
//!   connection persists between requests so a non-exclusive backup's
//!   `pg_backup_start` / `pg_backup_stop` share one session. [`Connection`]
//!   is `!Send`, but a worker is single-threaded, so the handler keeps it
//!   inside the worker process.
//! - [`DbProtocolClient`] — the client side: builds the requests and
//!   decodes the responses back into typed results.
//!
//! The wire payload for a query result is [`QueryRows`], a flattened,
//! JSON-serializable view of [`QueryResult`].

use std::fmt;

use pgbr_protocol::{ErrResponse, OkResponse, Request, Response};
use serde::{Deserialize, Serialize};

use crate::{Connection, DbError, QueryResult};

/// Prefix every DB protocol command shares (`db-open`, `db-query`, …). A worker
/// keys on this to route a request to the [`DbRequestHandler`] vs the storage
/// handler.
pub const DB_PROTOCOL_PREFIX: &str = "db-";

/// Protocol command name: open a libpq connection (the worker opens it locally,
/// from the PG host's perspective, with the conninfo in `param[0]`).
pub const CMD_DB_OPEN: &str = "db-open";
/// Protocol command name: run a `SELECT`-style query and return its rows.
pub const CMD_DB_QUERY: &str = "db-query";
/// Protocol command name: run a statement that returns no rows.
pub const CMD_DB_EXECUTE: &str = "db-execute";
/// Protocol command name: close the worker's open connection.
pub const CMD_DB_CLOSE: &str = "db-close";

/// Error code carried by an [`ErrResponse`] produced by this layer. The C
/// protocol surfaces a numeric `pgbr_error::ErrorType` code; we use a single
/// generic code here since the message is the load-bearing part.
pub(crate) const DB_PROTOCOL_ERR_CODE: u32 = 1;

/// A JSON-serializable query result carried over the protocol.
///
/// Flattens a [`QueryResult`] into owned column names and rows of optional
/// text values (`None` is a SQL `NULL`), so it can cross the wire as the
/// `out` payload of an [`OkResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryRows {
    /// Column names, in column order.
    pub columns: Vec<String>,
    /// Rows, each a vector aligned with `columns`; `None` is SQL `NULL`.
    pub rows: Vec<Vec<Option<String>>>,
}

impl From<&QueryResult> for QueryRows {
    fn from(result: &QueryResult) -> Self {
        let column_count = result.column_count();
        let row_count = result.row_count();

        let mut columns = Vec::with_capacity(column_count);
        for col in 0..column_count {
            columns.push(result.column_name(col).unwrap_or_default());
        }

        let mut rows = Vec::with_capacity(row_count);
        for row in 0..row_count {
            let mut values = Vec::with_capacity(column_count);
            for col in 0..column_count {
                values.push(result.value(row, col));
            }
            rows.push(values);
        }

        Self { columns, rows }
    }
}

/// Errors raised by the DB protocol layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbProtocolError {
    /// The underlying database operation failed.
    Db(DbError),
    /// The request was malformed (e.g. missing/ill-typed parameter, or an
    /// unrecognised command) — or the peer returned an error response.
    Protocol(String),
    /// A response payload could not be decoded into the expected shape.
    Decode(String),
}

impl fmt::Display for DbProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(err) => write!(f, "db error: {err}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::Decode(msg) => write!(f, "decode error: {msg}"),
        }
    }
}

impl std::error::Error for DbProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Db(err) => Some(err),
            Self::Protocol(_) | Self::Decode(_) => None,
        }
    }
}

impl From<DbError> for DbProtocolError {
    fn from(err: DbError) -> Self {
        Self::Db(err)
    }
}

/// Abstracts query execution so the protocol handler can be exercised
/// without a live libpq connection.
///
/// Implemented for [`Connection`] (the real path) and trivially for test
/// mocks. Both methods take `&mut self` because libpq query execution
/// mutates connection state.
pub trait DbExecutor {
    /// Run a `SELECT`-style query and return its rows.
    ///
    /// # Errors
    ///
    /// Returns [`DbProtocolError`] if the underlying query fails.
    fn query(&mut self, sql: &str) -> Result<QueryRows, DbProtocolError>;

    /// Run a statement that returns no rows.
    ///
    /// # Errors
    ///
    /// Returns [`DbProtocolError`] if the underlying statement fails.
    fn execute(&mut self, sql: &str) -> Result<(), DbProtocolError>;
}

impl DbExecutor for Connection {
    // `use_self` would suggest `Self::query`, but inside this trait impl that
    // resolves to the trait method (infinite recursion); we must name the
    // inherent `Connection` methods explicitly.
    #[allow(clippy::use_self)]
    fn query(&mut self, sql: &str) -> Result<QueryRows, DbProtocolError> {
        let result = Connection::query(self, sql)?;
        Ok(QueryRows::from(&result))
    }

    #[allow(clippy::use_self)]
    fn execute(&mut self, sql: &str) -> Result<(), DbProtocolError> {
        Connection::execute(self, sql)?;
        Ok(())
    }
}

/// Pull the single string parameter (`param[0]`) out of a request — the SQL for
/// `db-query` / `db-execute`, the conninfo for `db-open` — or describe why it is
/// missing / ill-typed.
fn sql_param(request: &Request) -> Result<&str, String> {
    request.param.first().map_or_else(
        || Err(format!("{} requires a string parameter", request.cmd)),
        |value| {
            value
                .as_str()
                .ok_or_else(|| format!("{} param[0] must be a string", request.cmd))
        },
    )
}

/// Turn a [`DbProtocolError`] into an [`ErrResponse`], preserving the message.
fn err_response(err: &DbProtocolError) -> Response {
    Response::Err(ErrResponse {
        err: DB_PROTOCOL_ERR_CODE,
        message: err.to_string(),
        stack: None,
    })
}

/// Handle one db-protocol request against `exec`.
///
/// Recognised commands:
/// - `db-query` (`param[0]` = sql) → `Ok { out: QueryRows as JSON }`
/// - `db-execute` (`param[0]` = sql) → `Ok { out: null }`
/// - anything else → `Err`
///
/// Database failures and malformed requests are reported as a
/// [`Response::Err`] rather than panicking, so the worker can keep serving.
pub fn handle_db_request<E: DbExecutor>(exec: &mut E, request: &Request) -> Response {
    match request.cmd.as_str() {
        CMD_DB_QUERY => {
            let sql = match sql_param(request) {
                Ok(sql) => sql,
                Err(msg) => return err_response(&DbProtocolError::Protocol(msg)),
            };
            match exec.query(sql) {
                Ok(rows) => match serde_json::to_value(&rows) {
                    Ok(value) => Response::Ok(OkResponse { out: Some(value) }),
                    Err(json_err) => err_response(&DbProtocolError::Decode(json_err.to_string())),
                },
                Err(err) => err_response(&err),
            }
        }
        CMD_DB_EXECUTE => {
            let sql = match sql_param(request) {
                Ok(sql) => sql,
                Err(msg) => return err_response(&DbProtocolError::Protocol(msg)),
            };
            match exec.execute(sql) {
                Ok(()) => Response::Ok(OkResponse {
                    out: Some(serde_json::Value::Null),
                }),
                Err(err) => err_response(&err),
            }
        }
        other => err_response(&DbProtocolError::Protocol(format!("unknown db protocol command: {other}"))),
    }
}

/// Stateful, worker-side DB protocol handler.
///
/// Owns the worker's single libpq [`Connection`] (lazily created on `db-open`)
/// and serves the full DB command set on its behalf:
///
/// - `db-open` (`param[0]` = conninfo) → open the connection *locally* (the
///   worker runs on the PG host, so a `host=`-less conninfo uses the unix
///   socket with peer/trust auth → no password). `Ok { out: null }`. A second
///   `db-open` while a connection is already open replaces it.
/// - `db-query` (`param[0]` = sql) → run on the open connection → `Ok { out:
///   QueryRows }`.
/// - `db-execute` (`param[0]` = sql) → run on the open connection → `Ok { out:
///   null }`.
/// - `db-close` → drop the connection → `Ok { out: null }`. Idempotent.
///
/// A `db-query` / `db-execute` before `db-open` is an error (no connection).
/// The connection persists across requests so a non-exclusive backup's
/// start / stop share one session. [`Connection`] is `!Send`; the handler keeps
/// it inside the (single-threaded) worker process and never sends it across a
/// thread boundary.
#[derive(Debug, Default)]
pub struct DbRequestHandler {
    conn: Option<Connection>,
}

impl DbRequestHandler {
    /// A handler with no open connection.
    #[must_use]
    pub const fn new() -> Self {
        Self { conn: None }
    }

    /// Handle one `db-*` request, mutating the held connection as needed.
    ///
    /// Unknown verbs (not `db-open` / `db-query` / `db-execute` / `db-close`)
    /// and database / protocol failures yield a [`Response::Err`] so the worker
    /// keeps serving rather than tearing down.
    pub fn handle(&mut self, request: &Request) -> Response {
        match request.cmd.as_str() {
            CMD_DB_OPEN => self.handle_open(request),
            CMD_DB_CLOSE => {
                self.conn = None;
                Response::Ok(OkResponse {
                    out: Some(serde_json::Value::Null),
                })
            }
            CMD_DB_QUERY | CMD_DB_EXECUTE => self.conn.as_mut().map_or_else(
                || {
                    err_response(&DbProtocolError::Protocol(format!(
                        "{} requires an open connection (send db-open first)",
                        request.cmd
                    )))
                },
                |conn| handle_db_request(conn, request),
            ),
            other => err_response(&DbProtocolError::Protocol(format!("unknown db protocol command: {other}"))),
        }
    }

    /// Open (or replace) the connection from the `db-open` conninfo parameter.
    fn handle_open(&mut self, request: &Request) -> Response {
        let conninfo = match sql_param(request) {
            Ok(conninfo) => conninfo,
            Err(msg) => return err_response(&DbProtocolError::Protocol(msg)),
        };
        match Connection::open(conninfo) {
            Ok(conn) => {
                self.conn = Some(conn);
                Response::Ok(OkResponse {
                    out: Some(serde_json::Value::Null),
                })
            }
            Err(err) => err_response(&DbProtocolError::Db(err)),
        }
    }
}

/// Client side of the DB protocol: builds the `db-open` / `db-query` /
/// `db-execute` / `db-close` requests and decodes the responses into typed
/// results.
///
/// This is a stateless helper; all methods are associated functions.
pub struct DbProtocolClient;

impl DbProtocolClient {
    /// Build a `db-open` request for `conninfo` (a libpq conninfo string).
    #[must_use]
    pub fn open_request(conninfo: &str) -> Request {
        Request {
            cmd: CMD_DB_OPEN.to_owned(),
            param: vec![serde_json::Value::String(conninfo.to_owned())],
        }
    }

    /// Build a `db-close` request.
    #[must_use]
    pub fn close_request() -> Request {
        Request {
            cmd: CMD_DB_CLOSE.to_owned(),
            param: Vec::new(),
        }
    }

    /// Build a `db-query` request for `sql`.
    #[must_use]
    pub fn query_request(sql: &str) -> Request {
        Request {
            cmd: CMD_DB_QUERY.to_owned(),
            param: vec![serde_json::Value::String(sql.to_owned())],
        }
    }

    /// Build a `db-execute` request for `sql`.
    #[must_use]
    pub fn execute_request(sql: &str) -> Request {
        Request {
            cmd: CMD_DB_EXECUTE.to_owned(),
            param: vec![serde_json::Value::String(sql.to_owned())],
        }
    }

    /// Decode a `db-open` / `db-close` / `db-execute` response (all return an
    /// empty / null `out`): success is `Ok(())`, an error response maps to
    /// [`DbProtocolError::Protocol`].
    ///
    /// # Errors
    ///
    /// Returns [`DbProtocolError::Protocol`] for an error response.
    pub fn decode_unit_response(resp: &Response) -> Result<(), DbProtocolError> {
        match resp {
            Response::Ok(_) => Ok(()),
            Response::Err(err) => Err(DbProtocolError::Protocol(err.message.clone())),
        }
    }

    /// Decode a `db-query` response into [`QueryRows`].
    ///
    /// # Errors
    ///
    /// Returns [`DbProtocolError::Protocol`] for an error response,
    /// [`DbProtocolError::Decode`] for a missing or ill-shaped `out` payload.
    pub fn decode_query_response(resp: &Response) -> Result<QueryRows, DbProtocolError> {
        match resp {
            Response::Ok(ok) => {
                let out = ok
                    .out
                    .as_ref()
                    .ok_or_else(|| DbProtocolError::Decode("db-query response missing out".to_owned()))?;
                serde_json::from_value(out.clone()).map_err(|err| DbProtocolError::Decode(err.to_string()))
            }
            Response::Err(err) => Err(DbProtocolError::Protocol(err.message.clone())),
        }
    }

    /// Decode a `db-execute` response.
    ///
    /// # Errors
    ///
    /// Returns [`DbProtocolError::Protocol`] for an error response.
    pub fn decode_execute_response(resp: &Response) -> Result<(), DbProtocolError> {
        match resp {
            Response::Ok(_) => Ok(()),
            Response::Err(err) => Err(DbProtocolError::Protocol(err.message.clone())),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A canned executor that answers queries/executes without libpq.
    struct MockExec {
        query_result: Result<QueryRows, DbProtocolError>,
        execute_result: Result<(), DbProtocolError>,
    }

    impl MockExec {
        fn with_rows(rows: QueryRows) -> Self {
            Self {
                query_result: Ok(rows),
                execute_result: Ok(()),
            }
        }

        fn with_error(err: DbProtocolError) -> Self {
            Self {
                query_result: Err(err.clone()),
                execute_result: Err(err),
            }
        }
    }

    impl DbExecutor for MockExec {
        fn query(&mut self, _sql: &str) -> Result<QueryRows, DbProtocolError> {
            self.query_result.clone()
        }

        fn execute(&mut self, _sql: &str) -> Result<(), DbProtocolError> {
            self.execute_result.clone()
        }
    }

    fn sample_rows() -> QueryRows {
        QueryRows {
            columns: vec!["version".to_owned()],
            rows: vec![vec![Some("PostgreSQL 16".to_owned())], vec![None]],
        }
    }

    #[test]
    fn db_query_round_trip() {
        let rows = sample_rows();
        let mut mock = MockExec::with_rows(rows.clone());

        let req = DbProtocolClient::query_request("SELECT version()");
        assert_eq!(req.cmd, "db-query");
        assert_eq!(req.param, vec![serde_json::Value::String("SELECT version()".to_owned())]);

        let resp = handle_db_request(&mut mock, &req);
        assert!(matches!(resp, Response::Ok(_)), "expected Ok, got {resp:?}");

        let decoded = DbProtocolClient::decode_query_response(&resp).unwrap();
        assert_eq!(decoded, rows);
    }

    #[test]
    fn db_execute_round_trip() {
        let mut mock = MockExec::with_rows(sample_rows());

        let req = DbProtocolClient::execute_request("CREATE TABLE t (id int)");
        assert_eq!(req.cmd, "db-execute");

        let resp = handle_db_request(&mut mock, &req);
        match &resp {
            Response::Ok(ok) => assert_eq!(ok.out, Some(serde_json::Value::Null)),
            Response::Err(err) => panic!("expected Ok{{null}}, got err: {err:?}"),
        }

        DbProtocolClient::decode_execute_response(&resp).unwrap();
    }

    #[test]
    fn unknown_command_errs() {
        let mut mock = MockExec::with_rows(sample_rows());
        let req = Request {
            cmd: "bogus".to_owned(),
            param: vec![],
        };

        let resp = handle_db_request(&mut mock, &req);
        let Response::Err(err) = &resp else {
            panic!("expected Err, got {resp:?}");
        };
        assert!(err.message.contains("unknown db protocol command"));
        assert!(err.message.contains("bogus"));

        // The client decoder surfaces it as a DbProtocolError too.
        let decoded = DbProtocolClient::decode_query_response(&resp);
        match decoded {
            Err(DbProtocolError::Protocol(msg)) => assert!(msg.contains("bogus")),
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn executor_error_maps_to_err_response() {
        let db_err = DbError::Query {
            sql: "SELECT 1".to_owned(),
            message: "relation does not exist".to_owned(),
        };
        let mut mock = MockExec::with_error(DbProtocolError::Db(db_err));

        let req = DbProtocolClient::query_request("SELECT 1");
        let resp = handle_db_request(&mut mock, &req);

        let Response::Err(err) = &resp else {
            panic!("expected Err, got {resp:?}");
        };
        assert!(
            err.message.contains("relation does not exist"),
            "message should carry the db error: {}",
            err.message
        );

        // Execute path maps the same way.
        let exec_resp = handle_db_request(&mut mock, &DbProtocolClient::execute_request("SELECT 1"));
        assert!(matches!(exec_resp, Response::Err(_)));
        let exec_decoded = DbProtocolClient::decode_execute_response(&exec_resp);
        assert!(matches!(exec_decoded, Err(DbProtocolError::Protocol(_))));
    }

    #[test]
    fn missing_sql_param_errs() {
        let mut mock = MockExec::with_rows(sample_rows());
        let req = Request {
            cmd: "db-query".to_owned(),
            param: vec![],
        };
        let resp = handle_db_request(&mut mock, &req);
        let Response::Err(err) = &resp else {
            panic!("expected Err, got {resp:?}");
        };
        assert!(err.message.contains("requires a string parameter"));
    }

    #[test]
    fn db_request_handler_query_before_open_errs() {
        // A db-query before db-open has no connection to run against, so it
        // must come back as an error rather than panicking.
        let mut handler = DbRequestHandler::new();
        let resp = handler.handle(&DbProtocolClient::query_request("SELECT 1"));
        let Response::Err(err) = &resp else {
            panic!("expected Err (no open connection), got {resp:?}");
        };
        assert!(err.message.contains("requires an open connection"), "{}", err.message);
    }

    #[test]
    fn db_request_handler_close_is_idempotent() {
        // db-close with nothing open is a no-op success; a second close too.
        let mut handler = DbRequestHandler::new();
        DbProtocolClient::decode_unit_response(&handler.handle(&DbProtocolClient::close_request()))
            .expect("close with nothing open is ok");
        DbProtocolClient::decode_unit_response(&handler.handle(&DbProtocolClient::close_request())).expect("second close is ok");
    }

    #[test]
    fn db_request_handler_open_rejects_bad_conninfo() {
        // db-open against an unreachable socket surfaces the libpq connect
        // failure as an error response (no connection is retained).
        let mut handler = DbRequestHandler::new();
        let req = DbProtocolClient::open_request("host=/nonexistent-socket-path-98765 connect_timeout=1");
        let resp = handler.handle(&req);
        assert!(matches!(resp, Response::Err(_)), "expected Err, got {resp:?}");
        // With no connection retained, a follow-up query also errors with the
        // "requires an open connection" message.
        let q = handler.handle(&DbProtocolClient::query_request("SELECT 1"));
        let Response::Err(err) = &q else {
            panic!("expected Err, got {q:?}");
        };
        assert!(err.message.contains("requires an open connection"), "{}", err.message);
    }

    #[test]
    fn db_request_handler_unknown_command_errs() {
        let mut handler = DbRequestHandler::new();
        let req = Request {
            cmd: "db-bogus".to_owned(),
            param: vec![],
        };
        let resp = handler.handle(&req);
        let Response::Err(err) = &resp else {
            panic!("expected Err, got {resp:?}");
        };
        assert!(err.message.contains("unknown db protocol command"), "{}", err.message);
    }

    #[test]
    fn db_protocol_client_builds_open_and_close_requests() {
        let open = DbProtocolClient::open_request("host=/tmp dbname=postgres");
        assert_eq!(open.cmd, "db-open");
        assert_eq!(
            open.param,
            vec![serde_json::Value::String("host=/tmp dbname=postgres".to_owned())]
        );

        let close = DbProtocolClient::close_request();
        assert_eq!(close.cmd, "db-close");
        assert!(close.param.is_empty());
    }

    #[test]
    fn non_string_sql_param_errs() {
        let mut mock = MockExec::with_rows(sample_rows());
        let req = Request {
            cmd: "db-execute".to_owned(),
            param: vec![serde_json::Value::from(42)],
        };
        let resp = handle_db_request(&mut mock, &req);
        let Response::Err(err) = &resp else {
            panic!("expected Err, got {resp:?}");
        };
        assert!(err.message.contains("must be a string"));
    }

    #[test]
    fn query_rows_json_round_trip() {
        // Covers the wire encoding of QueryRows independent of the handler.
        let rows = sample_rows();
        let value = serde_json::to_value(&rows).unwrap();
        let back: QueryRows = serde_json::from_value(value).unwrap();
        assert_eq!(back, rows);
    }

    #[test]
    fn db_protocol_error_display_and_source() {
        let db = DbProtocolError::Db(DbError::QueryNull {
            sql: "SELECT 1".to_owned(),
        });
        assert!(format!("{db}").contains("db error"));
        assert!(std::error::Error::source(&db).is_some());

        let proto = DbProtocolError::Protocol("boom".to_owned());
        assert!(format!("{proto}").contains("protocol error"));
        assert!(std::error::Error::source(&proto).is_none());

        let decode = DbProtocolError::Decode("bad json".to_owned());
        assert!(format!("{decode}").contains("decode error"));

        // From<DbError> conversion.
        let converted: DbProtocolError = DbError::Connect { message: "x".to_owned() }.into();
        assert!(matches!(converted, DbProtocolError::Db(_)));
    }

    // Real-libpq path: opens a Connection and runs `SELECT 1`. Gated on
    // DATABASE_URL; run with `cargo test -p pgbr-db -- --include-ignored`.
    #[test]
    #[ignore = "requires a running PostgreSQL server (set DATABASE_URL)"]
    fn real_libpq_query() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let mut conn = Connection::open(&url).expect("open connection");

        // Drive the real Connection through the DbExecutor trait + handler.
        let req = DbProtocolClient::query_request("SELECT 1 AS one");
        let resp = handle_db_request(&mut conn, &req);
        let rows = DbProtocolClient::decode_query_response(&resp).expect("decode rows");
        assert_eq!(rows.columns, vec!["one".to_owned()]);
        assert_eq!(rows.rows, vec![vec![Some("1".to_owned())]]);

        // execute() path against a temp table.
        let create = DbProtocolClient::execute_request("CREATE TEMP TABLE pgbr_proto_test (id int)");
        DbProtocolClient::decode_execute_response(&handle_db_request(&mut conn, &create)).expect("execute create");
    }
}
