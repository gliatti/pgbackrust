//! Process transport for the pgBackRust local/remote protocol.
//!
//! pgBackRust's main process drives helper workers (a `--local` worker for
//! parallel work on the same host, a `--remote` worker reached over SSH) by
//! spawning a child `pgbackrust` invocation and exchanging the JSON-line
//! protocol over the child's stdin/stdout pipes. C reference:
//! `src/protocol/client.c`, `src/protocol/server.c`, `src/common/exec.c`.
//!
//! This module supplies three pieces layered on top of the
//! [`crate::codec`] framing:
//!
//! - [`PipeRead`] / [`PipeWrite`] — thin adapters bridging any
//!   [`std::io::Read`] / [`std::io::Write`] (notably [`std::process::ChildStdout`]
//!   / [`std::process::ChildStdin`]) into [`pgbr_io::IoRead`] /
//!   [`pgbr_io::IoWrite`] so the codec can run over child pipes.
//! - [`ProtocolClient`] — the caller side: write a [`Request`], flush, read
//!   one [`Response`], surfacing an error response as a typed error.
//! - [`serve`] — the callee side: read requests in a loop and dispatch each
//!   to a [`RequestHandler`], stopping cleanly at EOF or on an `exit` request.
//! - [`ProcessClient`] — spawns a child worker with piped stdin/stdout and
//!   wraps a [`ProtocolClient`] over its pipes.

use core::fmt;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};

use pgbr_io::{IoError, IoRead, IoWrite};

use crate::codec::{CodecError, read_message, write_message};
use crate::message::{Message, OkResponse, Request, Response};

/// The command name used for the no-op/exit handshake that cleanly shuts a
/// worker down. Matches the C protocol's `exit` command.
pub const EXIT_COMMAND: &str = "exit";

/// The command name used as a liveness no-op. Matches the C protocol's `noOp`.
pub const NOOP_COMMAND: &str = "noOp";

/// Errors raised by the process transport.
#[derive(Debug)]
pub enum ProtocolError {
    /// Framing / serialization failure from the underlying codec.
    Codec(CodecError),
    /// Backend I/O failure on a pipe or socket.
    Io(IoError),
    /// The worker returned an error response. Carries the worker's message.
    Worker(String),
    /// The worker returned a file-missing error response (error code
    /// [`WORKER_CODE_FILE_MISSING`]). Surfaced distinctly from [`Self::Worker`]
    /// so a storage backend can reconstruct the typed `StorageError::NotFound`
    /// that local backends return for a missing path (callers rely on matching
    /// that variant to treat an absent file as "not present" rather than a hard
    /// error). Carries the worker's message.
    WorkerNotFound(String),
    /// Failed to spawn or manage the child worker process.
    Spawn(String),
}

/// Protocol error code for a missing file (`file-missing` in `error.yaml`); the
/// worker encodes `StorageError::NotFound` as this code, and the client maps it
/// back to [`ProtocolError::WorkerNotFound`].
pub const WORKER_CODE_FILE_MISSING: u32 = 55;

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Worker(msg) | Self::WorkerNotFound(msg) => write!(f, "worker error: {msg}"),
            Self::Spawn(msg) => write!(f, "spawn: {msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Worker(_) | Self::WorkerNotFound(_) | Self::Spawn(_) => None,
        }
    }
}

impl From<CodecError> for ProtocolError {
    fn from(err: CodecError) -> Self {
        Self::Codec(err)
    }
}

impl From<IoError> for ProtocolError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

/// Adapts any [`std::io::Read`] into a [`pgbr_io::IoRead`].
///
/// Used to wrap a child process's [`ChildStdout`], but works over any
/// `std::io::Read` (e.g. one end of an `os_pipe::pipe()` or an in-memory
/// cursor) so the transport is testable without spawning a process.
pub struct PipeRead<R: Read> {
    inner: R,
    eof: bool,
}

impl<R: Read> PipeRead<R> {
    /// Wrap `inner` as an [`IoRead`].
    pub const fn new(inner: R) -> Self {
        Self { inner, eof: false }
    }

    /// Consume the adapter and return the wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> IoRead for PipeRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self
            .inner
            .read(buf)
            .map_err(|e| IoError::Backend(format!("pipe read: {e}")))?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

/// Adapts any [`std::io::Write`] into a [`pgbr_io::IoWrite`].
///
/// Used to wrap a child process's [`ChildStdin`], but works over any
/// `std::io::Write` so the transport is testable without spawning a process.
/// `close` flushes and drops the underlying writer's resources via the
/// `closed` flag; the actual FD close happens when the adapter is dropped.
pub struct PipeWrite<W: Write> {
    inner: W,
    closed: bool,
}

impl<W: Write> PipeWrite<W> {
    /// Wrap `inner` as an [`IoWrite`].
    pub const fn new(inner: W) -> Self {
        Self { inner, closed: false }
    }

    /// Consume the adapter and return the wrapped writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> IoWrite for PipeWrite<W> {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        self.inner
            .write_all(buf)
            .map_err(|e| IoError::Backend(format!("pipe write: {e}")))
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        Write::flush(&mut self.inner).map_err(|e| IoError::Backend(format!("pipe flush: {e}")))
    }

    fn close(&mut self) -> Result<(), IoError> {
        if self.closed {
            return Ok(());
        }
        // Flush any pending bytes so the peer sees a complete final message
        // before the FD is closed (which happens when `inner` is dropped).
        Write::flush(&mut self.inner).map_err(|e| IoError::Backend(format!("pipe close flush: {e}")))?;
        self.closed = true;
        Ok(())
    }
}

/// The caller side of the protocol: sends requests to a worker and reads
/// responses.
///
/// Generic over the reader / writer so it works equally over child pipes
/// ([`PipeRead`] / [`PipeWrite`]), in-memory buffers, or sockets.
pub struct ProtocolClient<R: IoRead, W: IoWrite> {
    reader: R,
    writer: W,
}

impl<R: IoRead, W: IoWrite> ProtocolClient<R, W> {
    /// Build a client over an existing reader / writer pair.
    pub const fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    /// Write `request`, flush, then read exactly one response.
    ///
    /// Returns the [`OkResponse`] payload on success, or maps an error
    /// response to [`ProtocolError::Worker`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Codec`] on framing / serialization failure,
    /// [`ProtocolError::Io`] on a flush failure, [`ProtocolError::Worker`] if
    /// the worker replied with an error, or [`ProtocolError::Codec`] wrapping
    /// [`CodecError::UnexpectedEof`] if the worker closed without replying.
    pub fn execute(&mut self, request: &Request) -> Result<OkResponse, ProtocolError> {
        write_message(&mut self.writer, &Message::Request(request.clone()))?;
        self.writer.flush()?;

        match read_message(&mut self.reader)? {
            Some(Message::Response(Response::Ok(ok))) => Ok(ok),
            Some(Message::Response(Response::Err(err))) => Err(if err.err == WORKER_CODE_FILE_MISSING {
                ProtocolError::WorkerNotFound(err.message)
            } else {
                ProtocolError::Worker(err.message)
            }),
            Some(Message::Request(_)) => Err(ProtocolError::Worker(
                "expected a response from worker but received a request".to_owned(),
            )),
            None => Err(ProtocolError::Codec(CodecError::UnexpectedEof)),
        }
    }

    /// Send the connection-greeting handshake that carries the requested
    /// stanza to the server side.
    ///
    /// The first message on a freshly-opened mutual-TLS connection to a
    /// `pgbackrust server` is a no-op whose `param` list optionally carries a
    /// single `stanza=<name>` token. The server reads it before calling
    /// `authorize_client`, so the CN authorization runs against the *client's*
    /// requested stanza rather than whatever stanza (if any) the server
    /// process was itself started with (the daemon is typically started
    /// without `--stanza`, which would otherwise resolve to `<none>` and
    /// reject every authorized CN). The server replies with a plain success
    /// response, which this method consumes; the rest of the connection then
    /// runs the regular storage/db protocol.
    ///
    /// `stanza == None` produces a noOp with an empty `param` vector — useful
    /// for the `*`-wildcard auth case, and as the regression guard for
    /// `greet(None)` in the unit tests. Callers issue it exactly once, right
    /// after the transport is built.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Codec`] on a framing/serialization failure,
    /// [`ProtocolError::Io`] on a flush failure, or [`ProtocolError::Worker`]
    /// if the server rejected the greeting (typically: CN not authorized for
    /// the requested stanza).
    pub fn greet(&mut self, stanza: Option<&str>) -> Result<(), ProtocolError> {
        let mut param = Vec::new();
        if let Some(s) = stanza {
            param.push(serde_json::Value::String(format!("stanza={s}")));
        }
        let req = Request {
            cmd: NOOP_COMMAND.to_owned(),
            param,
        };
        let _ = self.execute(&req)?;
        Ok(())
    }

    /// Send the `exit` handshake so the worker's [`serve`] loop terminates
    /// cleanly, then close the writer so the peer reads EOF.
    ///
    /// `exit` is fire-and-forget: the worker stops its loop without replying,
    /// so this does not read a response.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Codec`] / [`ProtocolError::Io`] if the exit
    /// message cannot be written, flushed, or the writer cannot be closed.
    pub fn close(&mut self) -> Result<(), ProtocolError> {
        let exit = Request {
            cmd: EXIT_COMMAND.to_owned(),
            param: Vec::new(),
        };
        write_message(&mut self.writer, &Message::Request(exit))?;
        self.writer.flush()?;
        self.writer.close()?;
        Ok(())
    }
}

/// Dispatch target for [`serve`]: maps an incoming [`Request`] to a
/// [`Response`].
pub trait RequestHandler {
    /// Handle one request and produce the response to send back.
    fn handle(&mut self, req: &Request) -> Response;
}

/// Blanket impl so a plain `FnMut(&Request) -> Response` closure can be used
/// as a handler without a wrapper type.
impl<F: FnMut(&Request) -> Response> RequestHandler for F {
    fn handle(&mut self, req: &Request) -> Response {
        self(req)
    }
}

/// The callee side of the protocol: read requests in a loop, dispatch each to
/// `handler`, and write the response back.
///
/// The loop terminates cleanly (returns `Ok(())`) when:
///
/// - the reader reaches EOF (the caller dropped its writer), or
/// - an `exit` request arrives (the caller called [`ProtocolClient::close`]).
///
/// A `noOp` request is answered with an empty [`OkResponse`] without invoking
/// `handler`, matching the C protocol's liveness probe.
///
/// # Errors
///
/// Returns [`ProtocolError::Codec`] on a framing / parse failure or
/// [`ProtocolError::Io`] on a write/flush failure.
pub fn serve<R: IoRead, W: IoWrite, H: RequestHandler>(
    reader: &mut R,
    writer: &mut W,
    handler: &mut H,
) -> Result<(), ProtocolError> {
    loop {
        let req = match read_message(reader)? {
            // EOF: caller hung up, stop cleanly.
            None => return Ok(()),
            Some(Message::Request(req)) => req,
            // A response on the request channel is a protocol violation; the
            // caller should never send one. Treat it as a clean stop after
            // surfacing nothing — there is no one to report to here.
            Some(Message::Response(_)) => {
                return Err(ProtocolError::Worker(
                    "serve received a response where a request was expected".to_owned(),
                ));
            }
        };

        if req.cmd == EXIT_COMMAND {
            return Ok(());
        }

        let response = if req.cmd == NOOP_COMMAND {
            Response::Ok(OkResponse { out: None })
        } else {
            handler.handle(&req)
        };

        write_message(writer, &Message::Response(response))?;
        writer.flush()?;
    }
}

/// The SSH client program pgBackRust invokes to reach a remote worker.
/// Matches the default of pgBackRust's `cmd-ssh` option.
pub const SSH_PROGRAM: &str = "ssh";

/// The default worker program name spawned on the local or remote side.
pub const PGBACKRUST_PROGRAM: &str = "pgbackrust";

/// Build the argument vector for launching a remote worker over SSH.
///
/// Models pgBackRust's `protocolRemoteParamSsh` (`src/protocol/helper.c`):
/// a fixed block of hardening `-o` options, an optional `-p <port>`, the
/// `[<user>@]<host>` destination, then the remote program followed by its
/// arguments. The returned tuple is `("ssh", args)` where the program name
/// is [`SSH_PROGRAM`]; pass it straight to [`ProcessClient::spawn`].
///
/// The `-o` block pins the connection to deterministic, non-interactive
/// behaviour:
/// - `LogLevel=error`, `Compression=no`, `PasswordAuthentication=no` —
///   carried over verbatim from the C implementation, and
/// - `StrictHostKeyChecking=accept-new` — accept a first-seen host key but
///   still refuse a *changed* key, so the spawn never blocks on an
///   interactive prompt while preserving man-in-the-middle protection.
///
/// `ssh_port` and `ssh_user` are emitted only when set, exactly as the C
/// builder tests `cfgOptionIdxTest` / formats `user@host`. The arg vector is
/// fully deterministic for a given input, which is what the unit tests pin.
#[must_use]
pub fn build_ssh_command(
    host: &str,
    ssh_port: Option<u16>,
    ssh_user: Option<&str>,
    remote_program: &str,
    remote_args: &[String],
) -> (String, Vec<String>) {
    let mut args: Vec<String> = Vec::with_capacity(8 + 1 + remote_args.len());

    // Fixed hardening options (mirror protocolRemoteParamSsh).
    args.push("-o".to_owned());
    args.push("LogLevel=error".to_owned());
    args.push("-o".to_owned());
    args.push("Compression=no".to_owned());
    args.push("-o".to_owned());
    args.push("PasswordAuthentication=no".to_owned());
    args.push("-o".to_owned());
    args.push("StrictHostKeyChecking=accept-new".to_owned());

    // Optional port.
    if let Some(port) = ssh_port {
        args.push("-p".to_owned());
        args.push(port.to_string());
    }

    // Destination: `user@host` when a user is set, otherwise bare `host`.
    match ssh_user {
        Some(user) => args.push(format!("{user}@{host}")),
        None => args.push(host.to_owned()),
    }

    // Remote program then its arguments (the worker role + config flags the
    // caller supplies, e.g. `--remote`).
    args.push(remote_program.to_owned());
    args.extend(remote_args.iter().cloned());

    (SSH_PROGRAM.to_owned(), args)
}

/// Build the argument vector for launching a worker on the local host.
///
/// Models pgBackRust's `protocolLocalParam`: there is no SSH wrapper, just
/// the `pgbackrust` program itself plus the role / config arguments the
/// caller supplies (e.g. `["--local", ...]`). Returns `(program, role_args)`
/// ready for [`ProcessClient::spawn`].
#[must_use]
pub fn build_local_command(program: &str, role_args: &[String]) -> (String, Vec<String>) {
    (program.to_owned(), role_args.to_vec())
}

/// Spawns a child worker (`pgbackrust --remote` / `--local`) with piped
/// stdin/stdout and exchanges protocol messages with it.
///
/// The child's stdout is wrapped in a [`PipeRead`] and its stdin in a
/// [`PipeWrite`]; together they back a [`ProtocolClient`]. stderr is
/// inherited so worker diagnostics surface to the user, mirroring the C
/// `execOpen` behaviour.
pub struct ProcessClient {
    child: Child,
    client: ProtocolClient<PipeRead<ChildStdout>, PipeWrite<ChildStdin>>,
}

impl ProcessClient {
    /// Spawn `command` with `args`, piping stdin and stdout, ready for a
    /// protocol exchange.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the process cannot be spawned or
    /// either pipe handle is unexpectedly missing.
    pub fn spawn(command: &str, args: &[String]) -> Result<Self, ProtocolError> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| ProtocolError::Spawn(format!("spawn {command}: {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ProtocolError::Spawn(format!("{command}: child stdin pipe missing")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProtocolError::Spawn(format!("{command}: child stdout pipe missing")))?;

        let client = ProtocolClient::new(PipeRead::new(stdout), PipeWrite::new(stdin));
        Ok(Self { child, client })
    }

    /// Spawn a remote worker over SSH (`ssh [opts] [-p port] [user@]host
    /// pgbackrust --remote ...`).
    ///
    /// Builds the SSH command line with [`build_ssh_command`] and delegates to
    /// [`ProcessClient::spawn`], so the protocol then runs over the local
    /// `ssh` process's piped stdin/stdout — the SSH client transparently
    /// forwards them to the remote `pgbackrust` worker's stdin/stdout.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the `ssh` process cannot be spawned
    /// or either pipe handle is unexpectedly missing.
    pub fn spawn_ssh(
        host: &str,
        ssh_port: Option<u16>,
        ssh_user: Option<&str>,
        remote_program: &str,
        remote_args: &[String],
    ) -> Result<Self, ProtocolError> {
        let (command, args) = build_ssh_command(host, ssh_port, ssh_user, remote_program, remote_args);
        Self::spawn(&command, &args)
    }

    /// Spawn a local worker (`program role_args...`, e.g. `pgbackrust
    /// --local ...`).
    ///
    /// Builds the command line with [`build_local_command`] and delegates to
    /// [`ProcessClient::spawn`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the process cannot be spawned or
    /// either pipe handle is unexpectedly missing.
    pub fn spawn_local(program: &str, args: &[String]) -> Result<Self, ProtocolError> {
        let (command, args) = build_local_command(program, args);
        Self::spawn(&command, &args)
    }

    /// Send `request` to the worker and return its [`OkResponse`].
    ///
    /// # Errors
    ///
    /// Propagates any [`ProtocolError`] from the underlying
    /// [`ProtocolClient::execute`].
    pub fn execute(&mut self, request: &Request) -> Result<OkResponse, ProtocolError> {
        self.client.execute(request)
    }

    /// Split the spawned worker into its [`Child`] handle and the
    /// [`ProtocolClient`] running over the child's piped stdin/stdout.
    ///
    /// This lets a caller hand the [`ProtocolClient`] to something that needs a
    /// `ProtocolClient` directly (e.g. `pgbr_storage::remote::RemoteStorage`)
    /// while retaining the [`Child`] so the pipes stay live for as long as the
    /// proxy is used. Whoever keeps the [`Child`] is responsible for reaping it
    /// (drop, [`Child::wait`], or [`Child::kill`]) once the protocol writer has
    /// been closed and dropped — see [`ProcessClient::shutdown`] for the
    /// in-order teardown this module performs itself.
    #[must_use]
    pub fn into_parts(self) -> (Child, ProtocolClient<PipeRead<ChildStdout>, PipeWrite<ChildStdin>>) {
        (self.child, self.client)
    }

    /// Send the `exit` handshake, wait for the child to terminate, and return
    /// its exit status.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if waiting on the child fails, or any
    /// [`ProtocolError`] raised while sending the exit handshake.
    pub fn shutdown(self) -> Result<ExitStatus, ProtocolError> {
        // Destructure so the client (and with it the `PipeWrite<ChildStdin>`)
        // can be dropped *before* we wait. `PipeWrite::close` flushes but does
        // not close the FD on its own; the child only reads EOF on its stdin
        // once the handle is actually dropped, which is what lets it exit and
        // `wait` return rather than blocking forever.
        let Self { mut child, mut client } = self;
        client.close()?;
        drop(client);
        child.wait().map_err(|e| ProtocolError::Spawn(format!("wait for child: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::message::ErrResponse;
    use serde_json::json;
    use std::thread;

    /// An echo handler: wraps the request's `cmd` + `param` into the `out`
    /// payload of an Ok response.
    struct EchoHandler;
    impl RequestHandler for EchoHandler {
        fn handle(&mut self, req: &Request) -> Response {
            Response::Ok(OkResponse {
                out: Some(json!({ "cmd": req.cmd, "param": req.param })),
            })
        }
    }

    #[test]
    fn pipe_adapters_round_trip() {
        let (reader, writer) = os_pipe::pipe().unwrap();
        let mut pw = PipeWrite::new(writer);
        let mut pr = PipeRead::new(reader);

        let payload = b"hello, worker\n";
        pw.write(payload).unwrap();
        pw.flush().unwrap();
        // Drop the writer end so the reader sees EOF after the payload.
        pw.close().unwrap();
        drop(pw);

        let mut got = vec![0u8; payload.len()];
        pr.read_exact(&mut got).unwrap();
        assert_eq!(&got, payload);

        // After draining, the reader reports EOF.
        let mut tail = [0u8; 4];
        assert_eq!(pr.read(&mut tail).unwrap(), 0);
        assert!(pr.eof());
    }

    #[test]
    fn client_server_round_trip_over_pipes() {
        // Two pipes: client->server (requests) and server->client (responses).
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        // Server runs in a thread: reads requests from req_r, writes responses
        // to resp_w, dispatching through EchoHandler.
        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let mut handler = EchoHandler;
            serve(&mut reader, &mut writer, &mut handler).unwrap();
        });

        let mut client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));

        let request = Request {
            cmd: "archiveGet".to_owned(),
            param: vec![json!("000000010000000000000001")],
        };
        let ok = client.execute(&request).unwrap();
        assert_eq!(
            ok.out,
            Some(json!({ "cmd": "archiveGet", "param": ["000000010000000000000001"] }))
        );

        // Tell the server to exit and ensure it joins cleanly.
        client.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn serve_stops_on_exit_request() {
        // Pre-build a request stream containing one real request then `exit`.
        let mut req_buf = pgbr_io::MemWrite::new();
        write_message(
            &mut req_buf,
            &Message::Request(Request {
                cmd: "doWork".to_owned(),
                param: Vec::new(),
            }),
        )
        .unwrap();
        write_message(
            &mut req_buf,
            &Message::Request(Request {
                cmd: EXIT_COMMAND.to_owned(),
                param: Vec::new(),
            }),
        )
        .unwrap();

        let mut reader = pgbr_io::MemRead::new(req_buf.take());
        let mut writer = pgbr_io::MemWrite::new();
        let mut handler = EchoHandler;

        // Returns Ok(()) when it hits the exit request.
        serve(&mut reader, &mut writer, &mut handler).unwrap();

        // Exactly one response was written (for `doWork`); `exit` produced none.
        let mut resp_reader = pgbr_io::MemRead::new(writer.take());
        assert!(read_message(&mut resp_reader).unwrap().is_some());
        assert!(read_message(&mut resp_reader).unwrap().is_none());
    }

    #[test]
    fn serve_stops_on_eof() {
        // A single request, then the stream ends (caller dropped writer).
        let mut req_buf = pgbr_io::MemWrite::new();
        write_message(
            &mut req_buf,
            &Message::Request(Request {
                cmd: "doWork".to_owned(),
                param: Vec::new(),
            }),
        )
        .unwrap();

        let mut reader = pgbr_io::MemRead::new(req_buf.take());
        let mut writer = pgbr_io::MemWrite::new();
        let mut handler = EchoHandler;

        serve(&mut reader, &mut writer, &mut handler).unwrap();
    }

    #[test]
    fn error_response_maps_to_worker_error() {
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        // Handler that always returns an error response.
        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let mut handler = |_req: &Request| {
                Response::Err(ErrResponse {
                    err: 25,
                    message: "boom on worker".to_owned(),
                    stack: None,
                })
            };
            serve(&mut reader, &mut writer, &mut handler).unwrap();
        });

        let mut client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        let err = client
            .execute(&Request {
                cmd: "willFail".to_owned(),
                param: Vec::new(),
            })
            .unwrap_err();
        match err {
            ProtocolError::Worker(msg) => assert_eq!(msg, "boom on worker"),
            other => panic!("expected Worker error, got {other:?}"),
        }

        client.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn closure_handler_works() {
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let mut handler = |req: &Request| {
                Response::Ok(OkResponse {
                    out: Some(json!(req.cmd.clone())),
                })
            };
            serve(&mut reader, &mut writer, &mut handler).unwrap();
        });

        let mut client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        let ok = client
            .execute(&Request {
                cmd: "ping".to_owned(),
                param: Vec::new(),
            })
            .unwrap();
        assert_eq!(ok.out, Some(json!("ping")));
        client.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn protocol_error_display_variants() {
        let codec = ProtocolError::Codec(CodecError::UnexpectedEof);
        assert!(format!("{codec}").starts_with("codec:"));
        let io = ProtocolError::Io(IoError::Backend("disk".to_owned()));
        assert_eq!(format!("{io}"), "i/o: disk");
        let worker = ProtocolError::Worker("nope".to_owned());
        assert_eq!(format!("{worker}"), "worker error: nope");
        let spawn = ProtocolError::Spawn("no such file".to_owned());
        assert_eq!(format!("{spawn}"), "spawn: no such file");
    }

    /// Real-subprocess FD-plumbing check. `cat` echoes stdin to stdout
    /// verbatim, so a message written through the [`ProcessClient`] writer
    /// reads back identically through its reader at the framing level. We
    /// drive the framing manually here (cat is not a protocol server, so we
    /// do not use the `exit` handshake — cat would just echo it back into a
    /// closing pipe) to prove the spawn + pipe wiring works end to end over
    /// real file descriptors. Unix-only: depends on `/bin/cat`.
    #[test]
    #[cfg_attr(not(unix), ignore)]
    fn process_client_spawns_and_exchanges() {
        let proc = ProcessClient::spawn("/bin/cat", &[]).expect("spawn /bin/cat");
        // Destructure so we can drop the writer half on its own (sending cat a
        // clean stdin EOF) rather than going through the protocol `exit` path.
        let ProcessClient { mut child, client } = proc;
        let ProtocolClient { mut reader, mut writer } = client;

        // Write a request frame into cat's stdin; flush so it is delivered.
        let request = Message::Request(Request {
            cmd: "echoMe".to_owned(),
            param: vec![json!("payload")],
        });
        write_message(&mut writer, &request).unwrap();
        writer.flush().unwrap();

        // cat echoes the exact bytes back on stdout; read one frame.
        let echoed = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(echoed, request);

        // Drop the writer (closing cat's stdin) so cat reads EOF and exits 0.
        drop(writer);
        // Drain any trailing output so cat is never blocked writing to a full
        // pipe, then wait for it to exit cleanly.
        let _ = reader.read_all();
        let status = child.wait().expect("wait for cat");
        assert!(status.success());
    }

    #[test]
    fn build_ssh_command_minimal() {
        let (program, args) = build_ssh_command(
            "repo1.example.com",
            None,
            None,
            "pgbackrust",
            &["--remote".to_owned(), "info".to_owned()],
        );
        assert_eq!(program, "ssh");
        assert_eq!(
            args,
            vec![
                "-o",
                "LogLevel=error",
                "-o",
                "Compression=no",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "repo1.example.com",
                "pgbackrust",
                "--remote",
                "info",
            ]
        );
    }

    #[test]
    fn build_ssh_command_with_port_and_user() {
        let (program, args) = build_ssh_command(
            "db1.example.com",
            Some(2222),
            Some("postgres"),
            "pgbackrust",
            &["--remote".to_owned()],
        );
        assert_eq!(program, "ssh");
        assert_eq!(
            args,
            vec![
                "-o",
                "LogLevel=error",
                "-o",
                "Compression=no",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-p",
                "2222",
                "postgres@db1.example.com",
                "pgbackrust",
                "--remote",
            ]
        );
    }

    #[test]
    fn build_local_command_passes_args() {
        let (program, args) = build_local_command("pgbackrust", &["--local".to_owned(), "--process=1".to_owned()]);
        assert_eq!(program, "pgbackrust");
        assert_eq!(args, vec!["--local", "--process=1"]);

        // No args still yields just the program with an empty arg vector.
        let (program, args) = build_local_command("/usr/bin/pgbackrust", &[]);
        assert_eq!(program, "/usr/bin/pgbackrust");
        assert!(args.is_empty());
    }

    /// `spawn_local` wires the command up through the same piped-stdio path as
    /// [`ProcessClient::spawn`]. We point it at `/bin/cat` (an echo) and reuse
    /// the manual-framing FD check from [`process_client_spawns_and_exchanges`]
    /// to prove the local spawn path plumbs file descriptors end to end.
    /// Unix-only: depends on `/bin/cat`.
    #[test]
    #[cfg_attr(not(unix), ignore)]
    fn spawn_local_runs_echo() {
        let proc = ProcessClient::spawn_local("/bin/cat", &[]).expect("spawn_local /bin/cat");
        let ProcessClient { mut child, client } = proc;
        let ProtocolClient { mut reader, mut writer } = client;

        let request = Message::Request(Request {
            cmd: "echoLocal".to_owned(),
            param: vec![json!("payload")],
        });
        write_message(&mut writer, &request).unwrap();
        writer.flush().unwrap();

        let echoed = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(echoed, request);

        drop(writer);
        let _ = reader.read_all();
        let status = child.wait().expect("wait for cat");
        assert!(status.success());
    }

    /// `ProtocolClient::greet(Some("demo"))` sends exactly one noOp request
    /// whose `param` list carries the `stanza=demo` token, and consumes the
    /// matching `Ok` response. Asserting both directions on a pipe pair pins
    /// the wire shape the TLS server side decodes.
    #[test]
    fn greet_sends_noop_with_stanza_param_and_consumes_response() {
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        // Fake server: read one request, assert it is the greeting, reply Ok.
        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let msg = read_message(&mut reader).unwrap().expect("greeting message");
            match msg {
                Message::Request(req) => {
                    assert_eq!(req.cmd, NOOP_COMMAND, "greet must send a noOp");
                    assert_eq!(
                        req.param,
                        vec![json!("stanza=demo")],
                        "greet must carry stanza=<name> as its sole param"
                    );
                }
                other @ Message::Response(_) => panic!("expected a Request, got {other:?}"),
            }
            let resp = Message::Response(Response::Ok(OkResponse { out: None }));
            write_message(&mut writer, &resp).unwrap();
            writer.flush().unwrap();
        });

        let mut client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        client.greet(Some("demo")).expect("greet must succeed on Ok reply");

        // The server thread completed without panicking; the read+reply round
        // trip confirms both directions of the greeting.
        server.join().expect("server thread");
    }

    /// `ProtocolClient::greet(None)` produces an empty-param noOp — the
    /// `*`-wildcard auth case where the client does not name a stanza.
    #[test]
    fn greet_none_sends_noop_with_empty_param() {
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let msg = read_message(&mut reader).unwrap().expect("greeting message");
            match msg {
                Message::Request(req) => {
                    assert_eq!(req.cmd, NOOP_COMMAND);
                    assert!(req.param.is_empty(), "greet(None) must produce an empty param vec");
                }
                other @ Message::Response(_) => panic!("expected a Request, got {other:?}"),
            }
            let resp = Message::Response(Response::Ok(OkResponse { out: None }));
            write_message(&mut writer, &resp).unwrap();
            writer.flush().unwrap();
        });

        let mut client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        client.greet(None).expect("greet(None) must succeed on Ok reply");

        server.join().expect("server thread");
    }
}
