//! Safe Rust wrapper around libpq.
//!
//! Wraps connection lifecycle (`PQconnectdb` / `PQfinish`), simple
//! query execution (`PQexec`), and result inspection (`PQresultStatus`,
//! `PQgetvalue`, `PQntuples`, `PQnfields`, `PQfname`) behind a typed
//! Rust API. Connections are `!Send` because libpq is not thread-safe
//! per-connection.

use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_char;
use std::ptr::NonNull;

/// One `PostgreSQL` client connection.
pub struct Connection {
    ptr: NonNull<libpq_sys::PGconn>,
    // Connection is not Send: libpq's connection is not thread-safe per-connection.
    _not_send: std::marker::PhantomData<*mut ()>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

/// Errors raised by `pgbr-db`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// `PQconnectdb` failed or `PQstatus` returned `CONNECTION_BAD`.
    Connect {
        /// libpq error message (or a synthetic message for input-validation failures).
        message: String,
    },
    /// `PQexec` returned a result status other than `PGRES_COMMAND_OK` /
    /// `PGRES_TUPLES_OK`.
    Query {
        /// SQL string that was sent to the server.
        sql: String,
        /// libpq error message (or a synthetic message for input-validation failures).
        message: String,
    },
    /// `PQexec` returned NULL (libpq out-of-memory or invalid connection).
    QueryNull {
        /// SQL string that was sent to the server.
        sql: String,
    },
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect { message } => write!(f, "connect failed: {message}"),
            Self::Query { sql, message } => write!(f, "query failed for {sql:?}: {message}"),
            Self::QueryNull { sql } => write!(f, "query returned null result for {sql:?}"),
        }
    }
}

impl std::error::Error for DbError {}

impl Connection {
    /// Open a connection from a libpq-format conninfo string
    /// (e.g. `"host=/tmp dbname=postgres"`).
    pub fn open(conninfo: &str) -> Result<Self, DbError> {
        let c_conninfo = CString::new(conninfo).map_err(|_| DbError::Connect {
            message: "conninfo contains an interior NUL byte".to_owned(),
        })?;
        // SAFETY: `c_conninfo.as_ptr()` is a valid NUL-terminated C string;
        // `PQconnectdb` either returns a non-null pointer (success or
        // CONNECTION_BAD) or, on out-of-memory, a NULL we treat as an error.
        let raw = unsafe { libpq_sys::PQconnectdb(c_conninfo.as_ptr()) };
        let ptr = NonNull::new(raw).ok_or_else(|| DbError::Connect {
            message: "PQconnectdb returned null (out of memory)".to_owned(),
        })?;
        // SAFETY: ptr is non-null and was just returned by libpq.
        let status = unsafe { libpq_sys::PQstatus(ptr.as_ptr()) };
        if status != libpq_sys::ConnStatusType::CONNECTION_OK {
            // SAFETY: ptr is non-null and we own it; PQerrorMessage returns a pointer
            // owned by the connection that is valid until PQfinish runs.
            let msg = unsafe { cstr_to_string(libpq_sys::PQerrorMessage(ptr.as_ptr())) };
            // SAFETY: ptr is non-null and we own it; PQfinish is the matching destructor.
            unsafe {
                libpq_sys::PQfinish(ptr.as_ptr());
            }
            return Err(DbError::Connect { message: msg });
        }
        Ok(Self {
            ptr,
            _not_send: std::marker::PhantomData,
        })
    }

    /// Execute a SQL command that returns no rows. On non-OK status, the
    /// libpq error message is propagated via `DbError::Query`.
    ///
    /// Takes `&mut self` because `PQexec` mutates connection state (it changes
    /// the connection's last-error-message buffer), even though the underlying
    /// pointer itself is not reassigned.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn execute(&mut self, sql: &str) -> Result<(), DbError> {
        let result = self.exec_inner(sql)?;
        // SAFETY: result is non-null; we own it and PQclear is the destructor.
        let status = unsafe { libpq_sys::PQresultStatus(result.as_ptr()) };
        if status != libpq_sys::ExecStatusType::PGRES_COMMAND_OK {
            // SAFETY: result is non-null; PQresultErrorMessage returns a pointer
            // owned by the result that is valid until PQclear runs.
            let msg = unsafe { cstr_to_string(libpq_sys::PQresultErrorMessage(result.as_ptr())) };
            // SAFETY: result is non-null; PQclear is the matching destructor.
            unsafe {
                libpq_sys::PQclear(result.as_ptr());
            }
            return Err(DbError::Query {
                sql: sql.to_owned(),
                message: msg,
            });
        }
        // SAFETY: result is non-null; PQclear is the matching destructor.
        unsafe {
            libpq_sys::PQclear(result.as_ptr());
        }
        Ok(())
    }

    /// Execute a SQL query and return its rows as a typed `QueryResult`.
    ///
    /// Takes `&mut self` for the same reason as [`Connection::execute`].
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn query(&mut self, sql: &str) -> Result<QueryResult, DbError> {
        let result = self.exec_inner(sql)?;
        // SAFETY: result is non-null; we own it and PQclear is the destructor.
        let status = unsafe { libpq_sys::PQresultStatus(result.as_ptr()) };
        if status != libpq_sys::ExecStatusType::PGRES_TUPLES_OK {
            // SAFETY: result is non-null; PQresultErrorMessage returns a pointer
            // owned by the result that is valid until PQclear runs.
            let msg = unsafe { cstr_to_string(libpq_sys::PQresultErrorMessage(result.as_ptr())) };
            // SAFETY: result is non-null; PQclear is the matching destructor.
            unsafe {
                libpq_sys::PQclear(result.as_ptr());
            }
            return Err(DbError::Query {
                sql: sql.to_owned(),
                message: msg,
            });
        }
        Ok(QueryResult { ptr: result })
    }

    fn exec_inner(&self, sql: &str) -> Result<NonNull<libpq_sys::PGresult>, DbError> {
        let c_sql = CString::new(sql).map_err(|_| DbError::Query {
            sql: sql.to_owned(),
            message: "SQL contains an interior NUL byte".to_owned(),
        })?;
        // SAFETY: self.ptr is a valid PGconn we own; c_sql.as_ptr() is a valid
        // NUL-terminated C string. PQexec returns a non-null PGresult on success
        // and NULL only on OOM / invalid-connection conditions.
        let raw = unsafe { libpq_sys::PQexec(self.ptr.as_ptr(), c_sql.as_ptr()) };
        NonNull::new(raw).ok_or_else(|| DbError::QueryNull { sql: sql.to_owned() })
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: ptr was returned by PQconnectdb, has not been freed, and we own it.
        unsafe {
            libpq_sys::PQfinish(self.ptr.as_ptr());
        }
    }
}

/// Result of a `SELECT`-style query. Owns the underlying `PGresult` and frees it on drop.
pub struct QueryResult {
    ptr: NonNull<libpq_sys::PGresult>,
}

impl QueryResult {
    /// Number of rows returned by the query.
    #[must_use]
    pub fn row_count(&self) -> usize {
        // SAFETY: self.ptr is a valid PGresult we own.
        let n = unsafe { libpq_sys::PQntuples(self.ptr.as_ptr()) };
        // PQntuples returns int; PGRES_TUPLES_OK guarantees it is non-negative.
        usize::try_from(n).unwrap_or(0)
    }

    /// Number of columns in each returned row.
    #[must_use]
    pub fn column_count(&self) -> usize {
        // SAFETY: self.ptr is a valid PGresult we own.
        let n = unsafe { libpq_sys::PQnfields(self.ptr.as_ptr()) };
        usize::try_from(n).unwrap_or(0)
    }

    /// Name of column `col`, or `None` if `col` is out of range or libpq returns NULL.
    #[must_use]
    pub fn column_name(&self, col: usize) -> Option<String> {
        let col_int = i32::try_from(col).ok()?;
        // SAFETY: self.ptr is a valid PGresult we own. PQfname returns NULL for
        // out-of-range column indexes; otherwise a pointer owned by the result.
        let name_ptr = unsafe { libpq_sys::PQfname(self.ptr.as_ptr(), col_int) };
        if name_ptr.is_null() {
            return None;
        }
        // SAFETY: name_ptr is non-null and points to a NUL-terminated string
        // owned by the PGresult, valid until PQclear runs.
        let s = unsafe { CStr::from_ptr(name_ptr) }.to_string_lossy().into_owned();
        Some(s)
    }

    /// Value at `(row, col)`. Returns `None` for SQL `NULL` or for an out-of-range index.
    #[must_use]
    pub fn value(&self, row: usize, col: usize) -> Option<String> {
        let row_int = i32::try_from(row).ok()?;
        let col_int = i32::try_from(col).ok()?;
        if row >= self.row_count() || col >= self.column_count() {
            return None;
        }
        // SAFETY: self.ptr is a valid PGresult we own; row/col were just bounds-checked.
        let is_null = unsafe { libpq_sys::PQgetisnull(self.ptr.as_ptr(), row_int, col_int) };
        if is_null != 0 {
            return None;
        }
        // SAFETY: bounds-checked; PQgetvalue returns a pointer owned by the result
        // that is valid until PQclear runs.
        let value_ptr = unsafe { libpq_sys::PQgetvalue(self.ptr.as_ptr(), row_int, col_int) };
        if value_ptr.is_null() {
            return None;
        }
        // SAFETY: value_ptr is non-null and points to a NUL-terminated text
        // representation owned by the PGresult.
        let s = unsafe { CStr::from_ptr(value_ptr) }.to_string_lossy().into_owned();
        Some(s)
    }
}

impl Drop for QueryResult {
    fn drop(&mut self) {
        // SAFETY: ptr was returned by PQexec, has not been freed, and we own it.
        unsafe {
            libpq_sys::PQclear(self.ptr.as_ptr());
        }
    }
}

/// Helper for turning a libpq-returned C string into a Rust String. Returns
/// an empty string for NULL pointers.
///
/// # Safety
///
/// `p` must either be NULL or point to a valid NUL-terminated C string that
/// remains valid for the duration of this call.
unsafe fn cstr_to_string(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: caller guarantees p is non-null and points to a valid NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn connect_with_invalid_conninfo_errors() {
        // Non-existent socket path — libpq should report CONNECTION_BAD without
        // ever reaching a real server.
        let result = Connection::open("host=/nonexistent-socket-path-12345 connect_timeout=1");
        match result {
            Err(DbError::Connect { message }) => {
                assert!(!message.is_empty(), "libpq error message should not be empty");
            }
            Err(other) => panic!("expected DbError::Connect, got {other:?}"),
            Ok(_) => panic!("expected connection to fail"),
        }
    }

    #[test]
    fn conninfo_with_nul_byte_is_rejected() {
        let result = Connection::open("host=\0bad");
        match result {
            Err(DbError::Connect { message }) => {
                assert_eq!(message, "conninfo contains an interior NUL byte");
            }
            other => panic!("expected DbError::Connect with NUL message, got {other:?}"),
        }
    }

    #[test]
    fn db_error_display_formats() {
        let connect_err = DbError::Connect {
            message: "boom".to_owned(),
        };
        assert!(format!("{connect_err}").contains("connect failed"));

        let query_err = DbError::Query {
            sql: "SELECT 1".to_owned(),
            message: "syntax".to_owned(),
        };
        assert!(format!("{query_err}").contains("query failed"));

        let null_err = DbError::QueryNull {
            sql: "SELECT 1".to_owned(),
        };
        assert!(format!("{null_err}").contains("null result"));
    }

    // End-to-end test that requires a running PostgreSQL. Skipped by default;
    // run with `cargo test -p pgbr-db -- --include-ignored` and DATABASE_URL set.
    #[test]
    #[ignore = "requires a running PostgreSQL server (set DATABASE_URL)"]
    fn end_to_end_query_against_real_database() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            // No DATABASE_URL set — nothing to do.
            return;
        };

        let mut conn = Connection::open(&url).expect("open connection");

        // SQL with NUL byte must be rejected without ever calling PQexec.
        let nul_err = conn.execute("SELECT 1\0").unwrap_err();
        match nul_err {
            DbError::Query { message, .. } => {
                assert_eq!(message, "SQL contains an interior NUL byte");
            }
            other => panic!("expected DbError::Query, got {other:?}"),
        }

        // execute() round-trip.
        conn.execute("CREATE TEMP TABLE pgbr_db_test (id int, label text)").unwrap();
        conn.execute("INSERT INTO pgbr_db_test VALUES (1, 'a'), (2, NULL)").unwrap();

        // query() round-trip with NULL handling.
        let result = conn.query("SELECT id, label FROM pgbr_db_test ORDER BY id").unwrap();
        assert_eq!(result.row_count(), 2);
        assert_eq!(result.column_count(), 2);
        assert_eq!(result.column_name(0).as_deref(), Some("id"));
        assert_eq!(result.column_name(1).as_deref(), Some("label"));
        assert_eq!(result.value(0, 0).as_deref(), Some("1"));
        assert_eq!(result.value(0, 1).as_deref(), Some("a"));
        assert_eq!(result.value(1, 0).as_deref(), Some("2"));
        assert_eq!(result.value(1, 1), None);
    }
}
