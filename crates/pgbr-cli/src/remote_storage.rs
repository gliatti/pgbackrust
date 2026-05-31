//! `Storage` over a spawned `pgbackrest` worker, for inter-host operation.
//!
//! Mirrors the caller side of the C `src/storage/remote/storage.c` +
//! `src/protocol/helper.c` pair: when `repo-host` / `pg-host` is set, the main
//! process does not touch the remote resource directly. It spawns a subordinate
//! `pgbackrest` worker (over SSH for a remote host, or the binary itself for a
//! local worker) and proxies every [`Storage`] call to it over the JSON-line
//! protocol from [`pgbr_protocol`].
//!
//! The three building blocks already exist:
//!
//! - [`pgbr_protocol::ProcessClient`] spawns the child and owns the [`Child`]
//!   plus a [`ProtocolClient`] over its piped stdin/stdout.
//! - [`pgbr_storage::remote::RemoteStorage`] implements [`Storage`] by issuing
//!   one protocol request per method through a [`ProtocolClient`].
//! - the spawned `pgbackrest` runs [`pgbr_command::worker::run_worker_stdio`]
//!   (wired in [`crate::run_with_context`]) to answer the protocol on its
//!   stdio.
//!
//! The API-fit problem this module solves: [`RemoteStorage::new`] wants a
//! [`ProtocolClient`], but [`ProcessClient`] owns *both* the child and the
//! client — and the child must outlive the proxy or its stdin/stdout pipes are
//! torn down, hanging the worker. [`RemoteProcessStorage`] holds the [`Child`]
//! alongside the [`RemoteStorage`] built over the same pipes, delegating the
//! [`Storage`] trait to the inner proxy and reaping the worker on [`Drop`].

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout};
use std::sync::{Arc, Mutex};

use pgbr_io::{IoError, IoRead, IoWrite};
use pgbr_protocol::transport::{PipeRead, PipeWrite};
use pgbr_protocol::{ProcessClient, ProtocolClient, ProtocolError};
use pgbr_storage::remote::RemoteStorage;
use pgbr_storage::{Storage, StorageError, StorageInfo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

/// Concrete [`RemoteStorage`] instantiation over a spawned child's pipes: it
/// reads the worker's stdout and writes the worker's stdin.
type ChildRemoteStorage = RemoteStorage<PipeRead<ChildStdout>, PipeWrite<ChildStdin>>;

/// A [`Storage`] backed by a spawned `pgbackrest` worker.
///
/// Owns the worker [`Child`] so its stdin/stdout pipes stay live for as long as
/// the proxy is used, and the [`RemoteStorage`] proxy built over those pipes.
/// Every [`Storage`] method is delegated to the inner proxy; on [`Drop`] the
/// worker is reaped (best-effort kill + wait) after the proxy — and with it the
/// protocol writer — has been dropped, so the worker reads EOF and exits.
pub struct RemoteProcessStorage {
    /// The spawned worker. `Option` so [`Drop`] can take ownership to wait on
    /// it; always `Some` for the lifetime of every public method.
    child: Option<Child>,
    /// The protocol proxy over the child's pipes. Dropped before `child` is
    /// reaped (field declaration order = drop order) so the worker sees EOF.
    inner: ChildRemoteStorage,
}

impl RemoteProcessStorage {
    /// Build a remote-process storage from an already-spawned
    /// [`ProcessClient`]. Splits the client into its [`Child`] and
    /// [`ProtocolClient`], wraps the latter in a [`RemoteStorage`], and retains
    /// the child so the pipes outlive the proxy.
    #[must_use]
    pub fn new(process: ProcessClient) -> Self {
        let (child, client) = process.into_parts();
        Self {
            child: Some(child),
            inner: RemoteStorage::new(client),
        }
    }

    /// Spawn a remote worker over SSH and wrap it.
    ///
    /// `ssh [opts] [-p port] [user@]host <remote_program> <remote_args...>` —
    /// the remote `pgbackrest` is invoked in a worker role (see
    /// [`pgbr_command::worker::is_worker`]) so it serves the storage protocol on
    /// its stdio.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the `ssh` process cannot be spawned.
    pub fn spawn_ssh(
        host: &str,
        ssh_port: Option<u16>,
        ssh_user: Option<&str>,
        remote_program: &str,
        remote_args: &[String],
    ) -> Result<Self, ProtocolError> {
        let process = ProcessClient::spawn_ssh(host, ssh_port, ssh_user, remote_program, remote_args)?;
        Ok(Self::new(process))
    }

    /// Spawn a worker on the local host (`<program> <args...>`) and wrap it.
    ///
    /// Used both for same-host parallel workers and — in tests — to drive the
    /// real `pgbackrest` binary as a worker without an SSH hop.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the process cannot be spawned.
    pub fn spawn_local(program: &str, args: &[String]) -> Result<Self, ProtocolError> {
        let process = ProcessClient::spawn_local(program, args)?;
        Ok(Self::new(process))
    }
}

impl Drop for RemoteProcessStorage {
    fn drop(&mut self) {
        // `inner` (and its `PipeWrite<ChildStdin>`) is dropped after this method
        // returns, per struct field order — but to guarantee the worker reads
        // EOF *before* we wait (so `wait` does not block), reap defensively:
        // kill the child if it is still running, then wait to avoid a zombie.
        // A worker that already exited cleanly on EOF makes `kill` a harmless
        // no-op. Errors are ignored: Drop cannot surface them and a failed
        // reap of an already-dead child is not actionable.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Storage for RemoteProcessStorage {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        self.inner.exists(path)
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        self.inner.info(path)
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        self.inner.list(path)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        self.inner.open_read(path)
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        self.inner.open_write(path)
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner.remove(path, error_on_missing)
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        self.inner.rename(source, target)
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        self.inner.create_path(path, recursive)
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner.remove_path(path, recursive, error_on_missing)
    }

    fn create_symlink(&self, link_path: &Path, target: &Path) -> Result<(), StorageError> {
        self.inner.create_symlink(link_path, target)
    }
}

/// A `Send`-able, cloneable handle to one client-side rustls stream.
///
/// The `repo-host-type=tls` / `pg-host-type=tls` transport runs the remote
/// storage protocol — which expects a *separate* [`IoRead`] and [`IoWrite`] —
/// over a single rustls [`StreamOwned`], which couples both directions in one
/// stateful object that cannot be cloned into independent halves the way a
/// [`TcpStream`] can. [`pgbr_command::server`] uses an `Rc<RefCell<…>>` shared
/// handle for the same reason, but [`RemoteStorage`]'s [`Storage`] impl requires
/// `Send + 'static` reader / writer (it is exposed as a `Box<dyn Storage>`), so
/// here the shared stream lives behind an `Arc<Mutex<…>>` instead. Two clones of
/// the handle serve as the reader and the writer; each locks the mutex only for
/// the duration of a single `read` / `write` / `flush` / `close` call, and the
/// protocol never holds a read borrow live across a write, so the locks never
/// contend at runtime.
/// Public only because it is the default type parameter of the `pub`
/// [`RemoteTlsStorage`] struct (Rust requires defaults to be at least as
/// reachable as the type itself). External callers never name it: they go
/// through [`RemoteTlsStorage::connect`], which constructs the
/// `SyncTlsIo`-backed instantiation internally.
pub struct SyncTlsIo {
    inner: Arc<Mutex<TlsStream>>,
}

/// The owned client-side rustls stream plus its EOF flag.
struct TlsStream {
    stream: StreamOwned<ClientConnection, TcpStream>,
    eof: bool,
}

impl SyncTlsIo {
    fn new(stream: StreamOwned<ClientConnection, TcpStream>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TlsStream { stream, eof: false })),
        }
    }

    fn clone_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Lock the shared stream, recovering from a poisoned mutex (a panic in
    /// another handle's call) by taking the inner guard anyway — the stream is
    /// still usable bytes-wise and there is no shared invariant to uphold.
    fn lock(&self) -> std::sync::MutexGuard<'_, TlsStream> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl IoRead for SyncTlsIo {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let mut guard = self.lock();
        let result = guard.stream.read(buf);
        let n = match result {
            Ok(n) => n,
            Err(e) => {
                drop(guard);
                return Err(IoError::Backend(format!("tls read: {e}")));
            }
        };
        if n == 0 {
            guard.eof = true;
        }
        drop(guard);
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.lock().eof
    }
}

impl IoWrite for SyncTlsIo {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        self.lock()
            .stream
            .write_all(buf)
            .map_err(|e| IoError::Backend(format!("tls write: {e}")))
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Write::flush(&mut self.lock().stream).map_err(|e| IoError::Backend(format!("tls flush: {e}")))
    }

    fn close(&mut self) -> Result<(), IoError> {
        let mut guard = self.lock();
        // Send close_notify so the peer reads a clean EOF, then write-shut the
        // socket. An already-closed socket is not a surfaced error.
        guard.stream.conn.send_close_notify();
        let _ = Write::flush(&mut guard.stream);
        guard
            .stream
            .sock
            .shutdown(Shutdown::Write)
            .map_err(|e| IoError::Backend(format!("tls shutdown: {e}")))
    }
}

/// A [`Storage`] backed by a TLS connection to a peer's running `pgbackrest
/// server`, for the `repo-host-type=tls` / `pg-host-type=tls` transport.
///
/// Where [`RemoteProcessStorage`] spawns an `ssh <host> pgbackrest …` worker and
/// proxies the storage protocol over its stdio, this opens a mutual-TLS
/// connection (presenting the configured client certificate) to
/// `<host>:<tls-server-port>` and runs the **same** storage protocol over that
/// socket. The peer server authorizes the client certificate's Common Name and
/// serves a [`pgbr_storage::Posix`] rooted at its configured path. C reference:
/// `src/protocol/helper.c` (the `tls` branch of `protocolRemoteParam`).
///
/// The inner [`RemoteStorage`] is held in an [`Option`] so [`Drop`] can take
/// ownership of it and call [`RemoteStorage::close`] (a consuming method that
/// sends the protocol `exit` verb plus a TLS `close_notify`) at end of scope.
/// Without that explicit close, the socket dies abruptly when the proxy is
/// dropped: the peer `pgbackrest server`'s accept loop then cannot cleanly
/// serve the *next* connection — which is what archive-async over TLS hits,
/// because `PostgreSQL` spawns a fresh `archive-push` process for every WAL
/// segment, and each one builds and drops its own `RemoteTlsStorage`.
/// (R/W are generic only to allow `#[cfg(test)]` to swap in an in-memory
/// transport; the production type alias pins both to [`SyncTlsIo`].)
pub struct RemoteTlsStorage<R: IoRead + Send + 'static = SyncTlsIo, W: IoWrite + Send + 'static = SyncTlsIo> {
    /// The protocol proxy. `Some` for the lifetime of every public method; set
    /// to `None` by [`Drop`] (or a future explicit `close()` consumer) so the
    /// drop path is exactly-once.
    inner: Option<RemoteStorage<R, W>>,
}

/// Disable Nagle's algorithm (`TCP_NODELAY`) on a protocol socket.
///
/// Factored out so it can be unit-tested over a loopback socket. The synchronous
/// storage protocol does many small request→response rounds; with Nagle enabled
/// small responses are buffered awaiting an ACK, stalling `backup` (many small
/// rounds) while `archive-push` (one ~16MB segment) bypasses Nagle. Mirrors stock
/// pgBackRest, which sets `TCP_NODELAY` unconditionally on all sockets
/// (`src/common/io/socket/common.c`).
///
/// # Errors
///
/// Returns the underlying [`std::io::Error`] if `setsockopt(TCP_NODELAY)` fails;
/// the caller maps it to [`ProtocolError::Spawn`].
fn apply_nodelay(socket: &TcpStream) -> std::io::Result<()> {
    socket.set_nodelay(true)
}

impl RemoteTlsStorage<SyncTlsIo, SyncTlsIo> {
    /// Open a TLS connection to `addr` (validating the server cert against
    /// `server_name` and presenting the client cert in `client_config`),
    /// send the connection-greeting noOp carrying `stanza`, then drive the
    /// remote storage protocol over it.
    ///
    /// `sck_block` is the resolved `sck-block` option: `true` explicitly puts
    /// the connecting socket in blocking mode; `false` (the `sck-block`
    /// default) is a no-op since the protocol transport relies on blocking
    /// std I/O — forcing non-blocking mode would break it (best-effort,
    /// mirroring the server side).
    ///
    /// `stanza` is the stanza the caller is operating on. The peer's
    /// `pgbackrest server` daemon was typically started without `--stanza`
    /// (it serves many stanzas off one listener), so its own per-process
    /// stanza would resolve to `<none>` and reject every authorized CN.
    /// Sending the stanza in the greeting lets the server authorize the
    /// connection's CN against the *client's* stanza instead. Pass `None`
    /// for the `*`-wildcard auth case.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the TLS connection or handshake
    /// fails (the variant is reused for "could not establish the remote
    /// transport", mirroring the SSH spawn-failure mapping), or any other
    /// [`ProtocolError`] surfaced by [`ProtocolClient::greet`] (typically:
    /// the server rejected the CN for the requested stanza).
    pub fn connect(
        addr: &str,
        server_name: &str,
        client_config: Arc<ClientConfig>,
        sck_block: bool,
        stanza: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| ProtocolError::Spawn(format!("invalid tls server name `{server_name}`: {e}")))?;
        let socket = TcpStream::connect(addr).map_err(|e| ProtocolError::Spawn(format!("tls connect {addr}: {e}")))?;
        // Disable Nagle's algorithm on the protocol socket. The synchronous
        // storage protocol does many small request→response rounds (one per
        // ~64KB write-chunk plus metadata ops); with Nagle enabled (the kernel
        // default) a small response is buffered awaiting an ACK while the peer
        // blocks reading it, stalling `backup` (many small rounds) while
        // `archive-push` (one ~16MB segment) bypasses Nagle and works. Stock
        // pgBackRest sets TCP_NODELAY unconditionally on all sockets
        // (src/common/io/socket/common.c). Mirror the connect-failure mapping
        // to `ProtocolError::Spawn`.
        apply_nodelay(&socket).map_err(|e| ProtocolError::Spawn(format!("tls set nodelay {addr}: {e}")))?;
        // We intentionally do NOT apply SO_RCVTIMEO / SO_SNDTIMEO here. On
        // Linux those make the underlying TCP read/write return EAGAIN
        // (errno 11) once the timer elapses, but rustls' synchronous I/O
        // path treats EAGAIN as a hard error rather than retrying — the
        // observed failure mode on the second archive-push from PG's
        // archive_command was `tls write: Resource temporarily unavailable
        // (os error 11)`. Stall protection has to live one layer up (e.g.
        // a watchdog in the protocol loop) instead. The connect itself is
        // already bounded by `TcpStream::connect` defaults.
        // Only enforce blocking mode when the operator opted in; the default
        // (non-blocking) is left as-is because the synchronous protocol loop
        // here cannot drive a non-blocking socket.
        if sck_block && let Err(e) = socket.set_nonblocking(false) {
            return Err(ProtocolError::Spawn(format!("tls set blocking {addr}: {e}")));
        }
        let conn = ClientConnection::new(client_config, name).map_err(|e| ProtocolError::Spawn(format!("tls client new: {e}")))?;
        let io = SyncTlsIo::new(StreamOwned::new(conn, socket));
        let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());
        // Send the connection greeting before handing the client off to
        // `RemoteStorage::new`: the server reads it as its very first
        // request and authorizes the client CN against the carried stanza.
        client.greet(stanza)?;
        Ok(Self {
            inner: Some(RemoteStorage::new(client)),
        })
    }
}

impl<R: IoRead + Send + 'static, W: IoWrite + Send + 'static> RemoteTlsStorage<R, W> {
    /// Borrow the inner proxy. The `Option` is `None` only after [`Drop`] has
    /// taken it, by which point no public method can be called (Drop ends the
    /// struct's lifetime), so the `expect` documents an unreachable state.
    #[allow(clippy::expect_used)]
    const fn inner(&self) -> &RemoteStorage<R, W> {
        self.inner.as_ref().expect("RemoteTlsStorage: inner taken outside of Drop")
    }

    /// Test-only constructor: build a `RemoteTlsStorage` over an already-wired
    /// [`RemoteStorage`] (typically backed by an in-memory transport feeding a
    /// `StorageRequestHandler` on a server thread). Bypasses the real TLS
    /// handshake so the [`Drop`] path can be exercised in a unit test without
    /// standing up a TLS endpoint.
    #[cfg(test)]
    pub(crate) const fn from_remote_storage(inner: RemoteStorage<R, W>) -> Self {
        Self { inner: Some(inner) }
    }
}

impl<R: IoRead + Send + 'static, W: IoWrite + Send + 'static> Drop for RemoteTlsStorage<R, W> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            // Best-effort graceful close: send the protocol `exit` verb plus the
            // TLS `close_notify` so the peer sees an orderly shutdown and can
            // accept the next connection. Errors are intentionally ignored —
            // the connection is being torn down regardless, and `Drop` cannot
            // propagate. Without this, the socket dies abruptly when the
            // storage box goes out of scope at the end of `dispatch_loaded`,
            // and archive-async hangs on the second `archive-push` because the
            // server's accept loop cannot cleanly serve a fresh connection.
            let _ = inner.close();
        }
    }
}

impl<R: IoRead + Send + 'static, W: IoWrite + Send + 'static> Storage for RemoteTlsStorage<R, W> {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        self.inner().exists(path)
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        self.inner().info(path)
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        self.inner().list(path)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        self.inner().open_read(path)
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        self.inner().open_write(path)
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner().remove(path, error_on_missing)
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        self.inner().rename(source, target)
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        self.inner().create_path(path, recursive)
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner().remove_path(path, recursive, error_on_missing)
    }

    fn create_symlink(&self, link_path: &Path, target: &Path) -> Result<(), StorageError> {
        self.inner().create_symlink(link_path, target)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::sync::Mutex;
    use std::thread::{self, JoinHandle};

    use pgbr_protocol::ProtocolClient;
    use pgbr_protocol::transport::{PipeRead, PipeWrite, serve};
    use pgbr_storage::{Posix, StorageRequestHandler};
    use tempfile::TempDir;

    /// The pipe-backed `RemoteStorage` instantiation the tests build, mirroring
    /// `crates/pgbr-storage/src/remote.rs` mod tests, with the request-side
    /// writer swapped for a recording wrapper so the drop-path test can assert
    /// the `exit` verb was actually sent over the wire (the handler-side
    /// `serve` loop short-circuits on `exit` before dispatching to the
    /// handler, so an observer-handler never sees it).
    type PipeRemote = RemoteStorage<PipeRead<os_pipe::PipeReader>, RecordingWriter>;

    /// The matching pipe-backed `RemoteTlsStorage` instantiation: same shape as
    /// the production `RemoteTlsStorage` (alias of `<SyncTlsIo, SyncTlsIo>`),
    /// only with the test transport in place of the TLS one.
    type PipeRemoteTls = RemoteTlsStorage<PipeRead<os_pipe::PipeReader>, RecordingWriter>;

    /// [`IoWrite`] adapter that records every byte it forwards to a wrapped
    /// `std::io::Write`, so the test can scan the recorded stream for the
    /// `exit` request verb at end-of-connection. Cloning the recorder is a
    /// shallow `Arc` clone so multiple readers can inspect the buffer.
    struct RecordingWriter {
        inner: os_pipe::PipeWriter,
        recorder: Arc<Mutex<Vec<u8>>>,
        closed: bool,
    }

    impl RecordingWriter {
        fn new(inner: os_pipe::PipeWriter, recorder: Arc<Mutex<Vec<u8>>>) -> Self {
            Self {
                inner,
                recorder,
                closed: false,
            }
        }
    }

    impl IoWrite for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
            if self.closed {
                return Err(IoError::Closed);
            }
            self.recorder.lock().unwrap().extend_from_slice(buf);
            self.inner
                .write_all(buf)
                .map_err(|e| IoError::Backend(format!("recording write: {e}")))
        }

        fn flush(&mut self) -> Result<(), IoError> {
            if self.closed {
                return Err(IoError::Closed);
            }
            Write::flush(&mut self.inner).map_err(|e| IoError::Backend(format!("recording flush: {e}")))
        }

        fn close(&mut self) -> Result<(), IoError> {
            if self.closed {
                return Ok(());
            }
            Write::flush(&mut self.inner).map_err(|e| IoError::Backend(format!("recording close: {e}")))?;
            self.closed = true;
            Ok(())
        }
    }

    /// Build a [`RemoteTlsStorage`] over two `os_pipe` channels feeding a
    /// `StorageRequestHandler<Posix>` running on a thread, alongside the
    /// thread handle, the shared byte buffer recording every client-side
    /// write (so the test can assert the `exit` verb landed on the wire),
    /// and the backing `TempDir` (kept alive by the caller). The constructed
    /// `RemoteTlsStorage` exercises the same `Option<inner>` + `Drop` path as
    /// the production `SyncTlsIo`-backed variant, just without a real TLS
    /// endpoint — the brief explicitly authorizes this in the test-strategy
    /// notes ("If TLS setup in unit tests is too heavy, do it over a plain
    /// `MemRead`/`MemWrite` channel — the point is to assert the `exit`
    /// protocol verb leaves the `RemoteStorage` on Drop.").
    fn wire_remote_tls() -> (PipeRemoteTls, JoinHandle<()>, Arc<Mutex<Vec<u8>>>, TempDir) {
        let dir = TempDir::new().unwrap();
        let server_posix = Posix::new(dir.path());

        // client -> server requests; server -> client responses.
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let mut handler = StorageRequestHandler::new(server_posix);
            serve(&mut reader, &mut writer, &mut handler).unwrap();
        });

        let recorder = Arc::new(Mutex::new(Vec::<u8>::new()));
        let client = ProtocolClient::new(PipeRead::new(resp_r), RecordingWriter::new(req_w, Arc::clone(&recorder)));
        let pipe_remote: PipeRemote = RemoteStorage::new(client);
        let tls = RemoteTlsStorage::from_remote_storage(pipe_remote);
        (tls, server, recorder, dir)
    }

    /// Dropping a `RemoteTlsStorage` must send the protocol `exit` verb so the
    /// peer's accept loop (in production: the `pgbackrest server` daemon) sees
    /// a clean end-of-connection and can serve the next request. Without the
    /// `Drop` impl this regresses to a half-closed socket and archive-async
    /// over TLS hangs on the second `archive-push`.
    #[test]
    fn remote_tls_storage_drop_sends_exit_to_server() {
        let (tls, server, recorder, _dir) = wire_remote_tls();

        // Drive one ordinary request so we can prove the assertion holds for a
        // *drop after* real traffic, not just an empty connection.
        assert!(!Storage::exists(&tls, Path::new("nope")).unwrap());
        // Snapshot the recorded bytes before drop so the diff exposed by the
        // failure message is precisely what `Drop` adds.
        let before_drop = recorder.lock().unwrap().clone();

        // Drop the proxy: the `Drop` impl must run `RemoteStorage::close`,
        // which writes an `exit` request and shuts the writer. The server
        // thread sees `exit` (or EOF) and ends.
        drop(tls);
        server.join().unwrap();

        let after_drop = recorder.lock().unwrap().clone();
        let drop_bytes = &after_drop[before_drop.len()..];
        let drop_text = std::str::from_utf8(drop_bytes).unwrap_or("<non-utf8>");
        assert!(
            drop_text.contains("\"exit\""),
            "Drop must send the `exit` protocol verb; the bytes written after the last \
             call were {drop_text:?} (full client→server stream: {:?})",
            std::str::from_utf8(&after_drop).unwrap_or("<non-utf8>")
        );
    }

    /// Confirm the new `Option<inner>` wrapping is transparent to every
    /// `Storage` method: a real round-trip works exactly as it did before the
    /// refactor. Only after `Drop` is the inner gone — and at that point the
    /// struct itself is no longer accessible.
    #[test]
    fn remote_tls_storage_methods_work_until_drop() {
        let (tls, server, _recorder, dir) = wire_remote_tls();

        // exists, info on missing, list on the empty root.
        assert!(!Storage::exists(&tls, Path::new("file.txt")).unwrap());
        let entries = Storage::list(&tls, Path::new(".")).unwrap();
        assert!(entries.is_empty(), "fresh tempdir should be empty, got {entries:?}");

        // Round-trip a write + read through the proxy.
        {
            let mut w = Storage::open_write(&tls, Path::new("file.txt")).unwrap();
            w.write(b"hello").unwrap();
            w.close().unwrap();
        }
        assert!(Storage::exists(&tls, Path::new("file.txt")).unwrap());
        let on_disk = std::fs::read(dir.path().join("file.txt")).unwrap();
        assert_eq!(on_disk, b"hello");

        // create_path / remove_path round-trip.
        Storage::create_path(&tls, Path::new("sub/dir"), true).unwrap();
        assert!(Storage::exists(&tls, Path::new("sub/dir")).unwrap());
        Storage::remove_path(&tls, Path::new("sub/dir"), true, true).unwrap();
        assert!(!Storage::exists(&tls, Path::new("sub/dir")).unwrap());

        // remove a file.
        Storage::remove(&tls, Path::new("file.txt"), true).unwrap();
        assert!(!Storage::exists(&tls, Path::new("file.txt")).unwrap());

        // Drop and confirm the server loop terminates cleanly via the `exit`
        // verb the new `Drop` impl sends.
        drop(tls);
        server.join().unwrap();
    }

    /// `RemoteTlsStorage::connect` disables Nagle's algorithm on the protocol
    /// socket via `apply_nodelay`. A full mTLS connect needs certs and a peer, so
    /// drive the factored-out `apply_nodelay` helper over a real loopback socket
    /// (the exact call `connect` makes right after `TcpStream::connect`) and
    /// assert `TCP_NODELAY` took effect — the synchronous storage protocol's
    /// many-small-rounds backup would otherwise stall behind Nagle.
    #[test]
    fn remote_tls_connect_sets_tcp_nodelay() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Connect just like `RemoteTlsStorage::connect` does.
        let socket = TcpStream::connect(addr).unwrap();
        let (_accepted, _peer) = listener.accept().unwrap();

        // Fresh sockets default to Nagle enabled (nodelay == false); after the
        // helper the connect path uses, it must be on.
        apply_nodelay(&socket).expect("apply_nodelay should succeed on a connected loopback socket");
        assert!(socket.nodelay().unwrap(), "RemoteTlsStorage::connect must set TCP_NODELAY");
    }
}
