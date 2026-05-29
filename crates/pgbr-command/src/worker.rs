//! The `local` / `remote` worker role: the callee side of the protocol.
//!
//! pgBackRest's main process does not touch a repository or PG data directory
//! that lives on another host (or that it wants to parallelize on the same
//! host) directly. Instead it spawns a subordinate `pgbackrest` invocation —
//! a `--remote` worker reached over SSH, or a `--local` worker on the same
//! machine — and drives it over the JSON-line protocol from [`pgbr_protocol`]:
//! every `Storage` (or DB) operation becomes one request/response exchange.
//!
//! This module is the worker half of that picture. C reference:
//! `src/command/remote/remote.c`, `src/command/local/local.c`, and the
//! protocol loop in `src/protocol/server.c`.
//!
//! Pieces:
//!
//! - [`WorkerHandler`] — a [`pgbr_protocol::transport::RequestHandler`] that
//!   delegates `storage-*` requests to a
//!   [`pgbr_storage::remote::StorageRequestHandler`] wrapping a local
//!   [`pgbr_storage::Posix`] rooted at the worker's repository / PG path, and
//!   `db-*` requests to a [`pgbr_db::DbRequestHandler`] that owns a libpq
//!   [`pgbr_db::Connection`] the worker opens *locally* (on the PG host, via
//!   the unix socket — peer/trust auth, no password). Anything else is
//!   answered with an error response. This is what makes the "dedicated repo
//!   host (pull)" topology work: a backup / check / stanza command running on
//!   the repo host with `pg1-host=<pghost>` reaches the cluster's control
//!   connection through this worker rather than via a direct TCP libpq connect.
//! - [`serve_worker`] — build the handler and run the transport
//!   [`serve`](pgbr_protocol::transport::serve) loop over a reader / writer
//!   pair. Transport-agnostic, so it is exercised in tests over in-process
//!   pipes without spawning a real child.
//! - [`run_worker_stdio`] — pick the root from the resolved config and serve
//!   on the process's real stdin / stdout, which is how the main process and
//!   the worker actually talk once the child has been spawned.

use std::io::{Stdin, Stdout};
use std::path::{Path, PathBuf};

use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
use pgbr_db::{DB_PROTOCOL_PREFIX, DbRequestHandler};
use pgbr_io::{IoRead, IoWrite};
use pgbr_protocol::transport::{PipeRead, PipeWrite, RequestHandler, serve};
use pgbr_protocol::{ErrResponse, Request, Response};
use pgbr_storage::Posix;
use pgbr_storage::remote::StorageRequestHandler;

use crate::CommandError;

/// Prefix every storage protocol command shares (`storage-exists`,
/// `storage-write`, ...). Requests with this prefix are delegated to the
/// wrapped [`StorageRequestHandler`].
const STORAGE_PREFIX: &str = "storage-";

/// Error code carried by [`ErrResponse`] for a request the worker refuses to
/// handle. The message is the load-bearing part; the numeric code mirrors the
/// generic error used elsewhere in the protocol layer.
const WORKER_ERR_CODE: u32 = 1;

/// Worker-side [`RequestHandler`] for the `local` / `remote` roles.
///
/// `storage-*` requests are forwarded to a [`StorageRequestHandler`] over a
/// [`Posix`] rooted at the worker's repository or PG path; `db-*` requests are
/// forwarded to a [`DbRequestHandler`] that owns the worker's libpq connection
/// (lazily opened on `db-open`). Every other command yields an [`ErrResponse`].
///
/// The [`DbRequestHandler`]'s [`pgbr_db::Connection`] is `!Send`, but a worker
/// process is single-threaded and serves requests one at a time, so the
/// connection never crosses a thread boundary.
pub struct WorkerHandler {
    storage: StorageRequestHandler<Posix>,
    db: DbRequestHandler,
}

impl WorkerHandler {
    /// Build a worker handler serving a local [`Posix`] rooted at `root`, with
    /// no DB connection open yet (the first `db-open` request opens one).
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            storage: StorageRequestHandler::new(Posix::new(root)),
            db: DbRequestHandler::new(),
        }
    }
}

impl RequestHandler for WorkerHandler {
    fn handle(&mut self, req: &Request) -> Response {
        if req.cmd.starts_with(STORAGE_PREFIX) {
            self.storage.handle(req)
        } else if req.cmd.starts_with(DB_PROTOCOL_PREFIX) {
            self.db.handle(req)
        } else {
            Response::Err(ErrResponse {
                err: WORKER_ERR_CODE,
                message: format!("worker: unsupported protocol command `{}`", req.cmd),
                stack: None,
            })
        }
    }
}

/// Build a [`WorkerHandler`] rooted at `root` and run the protocol
/// [`serve`](pgbr_protocol::transport::serve) loop over `reader` / `writer`.
///
/// The loop terminates cleanly when the caller hangs up (EOF) or sends the
/// `exit` handshake. Generic over the byte transport so it runs equally over
/// child pipes, a socket, or in-process pipes in tests.
///
/// # Errors
///
/// Returns [`CommandError::Other`] wrapping the underlying
/// [`pgbr_protocol::ProtocolError`] if the serve loop fails on a framing or
/// I/O error.
pub fn serve_worker<R: IoRead, W: IoWrite>(root: &Path, reader: &mut R, writer: &mut W) -> Result<(), CommandError> {
    let mut handler = WorkerHandler::new(root);
    serve(reader, writer, &mut handler).map_err(|e| CommandError::Other(format!("worker serve: {e}")))
}

/// Resolve the filesystem root the worker should serve from the merged config.
///
/// A `remote` worker operates on whichever resource the main process asked it
/// to reach; we pick `pg1-path` (the PG data directory) when present, falling
/// back to `repo1-path` (the repository) — matching the two roots a worker is
/// ever spawned for. Returns [`CommandError::MissingOption`] when neither is
/// configured.
fn worker_root(config: &LoadedConfig) -> Result<PathBuf, CommandError> {
    for name in ["pg1-path", "pg-path", "repo1-path", "repo-path"] {
        if let Some(OptionValue::Path(p) | OptionValue::String(p)) = config.options.get(&(name.to_owned(), None))
            && !p.is_empty()
        {
            return Ok(PathBuf::from(p));
        }
    }
    Err(CommandError::MissingOption {
        option: "pg1-path or repo1-path".to_owned(),
    })
}

/// `true` when `config` selects the worker role — either the internal
/// `local` / `remote` command names or the `Local` / `Remote` command role.
#[must_use]
pub fn is_worker(config: &LoadedConfig) -> bool {
    matches!(config.command.as_str(), "local" | "remote")
        || matches!(config.command_role, ConfigCommandRole::Local | ConfigCommandRole::Remote)
}

/// Serve the worker protocol on the process's real stdin / stdout.
///
/// This is the entry point the main process reaches after spawning the child
/// (`pgbackrest ... --remote` / `--local`): the child reads requests from its
/// stdin and writes responses to its stdout, which are the SSH / pipe channels
/// back to the main process. The root is taken from the resolved config
/// (`pg1-path`, else `repo1-path`).
///
/// # Errors
///
/// Returns [`CommandError::MissingOption`] when no servable root is
/// configured, or [`CommandError::Other`] if the serve loop fails.
pub fn run_worker_stdio(config: &LoadedConfig) -> Result<(), CommandError> {
    let root = worker_root(config)?;
    let mut reader: PipeRead<Stdin> = PipeRead::new(std::io::stdin());
    let mut writer: PipeWrite<Stdout> = PipeWrite::new(std::io::stdout());
    serve_worker(&root, &mut reader, &mut writer)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::thread;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_protocol::transport::{PipeRead, PipeWrite};
    use pgbr_protocol::{ProtocolClient, Request};
    use pgbr_storage::Storage;
    use pgbr_storage::remote::RemoteStorage;
    use tempfile::TempDir;

    use super::{is_worker, run_worker_stdio, serve_worker};
    use crate::CommandError;

    fn worker_config(command: &str, role: ConfigCommandRole, root: Option<&Path>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(p) = root {
            options.insert(("pg1-path".to_owned(), None), OptionValue::Path(p.display().to_string()));
        }
        LoadedConfig {
            command: command.to_owned(),
            command_role: role,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn worker_serves_storage_requests() {
        // Wire a RemoteStorage client to `serve_worker` over two os_pipe
        // channels (server on its own thread), rooted at a TempDir Posix.
        // A put -> get -> exists round-trip proves the worker answers the
        // storage protocol end to end, and the bytes land in the tempdir.
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            serve_worker(&root, &mut reader, &mut writer).unwrap();
        });

        let client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        let remote = RemoteStorage::new(client);

        let path = Path::new("file.txt");
        let payload = b"worker payload\n";

        // put (scope the writer so its shared-client clone is dropped before
        // `remote.close()` tries to unwrap the sole Arc).
        {
            let mut w = remote.open_write(path).unwrap();
            w.write(payload).unwrap();
            w.close().unwrap();
        }

        // get
        {
            let mut r = remote.open_read(path).unwrap();
            assert_eq!(r.read_all().unwrap(), payload);
        }

        // exists
        assert!(remote.exists(path).unwrap());
        assert!(!remote.exists(Path::new("missing")).unwrap());

        // The bytes really landed in the tempdir on disk.
        let on_disk = std::fs::read(dir.path().join("file.txt")).unwrap();
        assert_eq!(on_disk, payload);

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn worker_unknown_command_errs() {
        // A command that is neither `storage-*` nor `db-*` must come back as an
        // error response, which the client surfaces as a `ProtocolError::Worker`.
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            serve_worker(&root, &mut reader, &mut writer).unwrap();
        });

        let mut client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        let req = Request {
            cmd: "bogus-verb".to_owned(),
            param: Vec::new(),
        };
        let err = client.execute(&req).expect_err("unknown command must error");
        let msg = err.to_string();
        assert!(msg.contains("unsupported protocol command"), "message was {msg:?}");
        assert!(msg.contains("bogus-verb"), "message was {msg:?}");

        client.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn worker_routes_db_commands_to_db_handler() {
        // The worker now serves the DB protocol too. Without a real PostgreSQL
        // we cannot drive `db-open`, but we can prove the routing reaches the
        // `DbRequestHandler`: a `db-query` before any `db-open` is answered by
        // the DB handler's "requires an open connection" error (NOT the
        // "unsupported protocol command" the storage-only worker used to
        // return), and `db-close` succeeds as an idempotent no-op.
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();

        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            serve_worker(&root, &mut reader, &mut writer).unwrap();
        });

        let mut client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));

        // db-query before db-open -> DB-handler error.
        let query = pgbr_db::DbProtocolClient::query_request("SELECT 1");
        let err = client.execute(&query).expect_err("query before open must error");
        let msg = err.to_string();
        assert!(msg.contains("requires an open connection"), "message was {msg:?}");

        // db-close with nothing open -> idempotent success. (The null `out`
        // round-trips to `None` over the wire — serde maps JSON `null` for an
        // `Option<Value>` to `None` — so assert success, not the exact payload.)
        let close = pgbr_db::DbProtocolClient::close_request();
        let resp = pgbr_protocol::Response::Ok(client.execute(&close).expect("db-close is a no-op success"));
        pgbr_db::DbProtocolClient::decode_unit_response(&resp).expect("db-close decodes as success");

        client.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn dispatch_routes_remote_to_worker() {
        // A `remote` command (and the Remote command role) is recognized as a
        // worker invocation by `is_worker`, the predicate `dispatch` keys on.
        let dir = TempDir::new().unwrap();
        let cfg = worker_config("remote", ConfigCommandRole::Remote, Some(dir.path()));
        assert!(is_worker(&cfg));

        // The Local role is also a worker even under a user-facing command name.
        let local = worker_config("backup", ConfigCommandRole::Local, Some(dir.path()));
        assert!(is_worker(&local));

        // A plain main command is not.
        let main = worker_config("info", ConfigCommandRole::Main, None);
        assert!(!is_worker(&main));
    }

    #[test]
    fn run_worker_stdio_without_root_is_missing_option() {
        // Routing reaches the worker but bails before touching stdin when no
        // servable root is configured — proving the dispatch arm is wired and
        // testable without blocking on real stdin.
        let cfg = worker_config("remote", ConfigCommandRole::Remote, None);
        let err = run_worker_stdio(&cfg).expect_err("no root configured must fail fast");
        match err {
            CommandError::MissingOption { option } => {
                assert!(option.contains("path"), "option was {option:?}");
            }
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }
}
