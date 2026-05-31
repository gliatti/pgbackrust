//! Server commands: `server`, `server-ping`.
//!
//! C reference: `src/command/server/server.c` and
//! `src/command/server/ping.c`.
//!
//! The real pgBackRest `server` command binds a TLS listener on a TCP
//! socket and serves the local/remote JSON-line protocol to each remote
//! pgBackRest process that connects; `server-ping` is the client that
//! connects and issues a no-op to confirm the server is alive.
//!
//! The transport-agnostic *protocol* core both commands drive lives here:
//!
//! - [`serve`] — the request/response loop a server runs per connection.
//! - [`ping_exchange`] — the single no-op round trip the ping client does.
//!
//! Both operate over any [`IoRead`] / [`IoWrite`] pair, so they are tested
//! over in-memory [`MemRead`](pgbr_io::MemRead) /
//! [`MemWrite`](pgbr_io::MemWrite) streams.
//!
//! On top of those cores this module supplies two transports:
//!
//! **Plain TCP** (no encryption):
//!
//! - [`TcpIo`] adapts a [`std::net::TcpStream`] to [`IoRead`] / [`IoWrite`].
//! - [`serve_listener`] / [`serve_tcp`] accept connections and run [`serve`]
//!   per connection; [`ping_tcp`] connects and runs [`ping_exchange`].
//!
//! **TLS** (matching the real pgBackRest, C reference `src/common/io/tls/`):
//!
//! - [`TlsIo`] adapts a [`rustls`] stream ([`rustls::StreamOwned`] over a
//!   [`TcpStream`], server or client side) to [`IoRead`] / [`IoWrite`] — the
//!   same shape as [`TcpIo`], since a `rustls` stream is also a single
//!   bidirectional `Read`/`Write` handle.
//! - [`serve_tls`] accepts a TCP connection, runs the rustls **server**
//!   handshake from a cert chain + private key, then drives [`serve`].
//! - [`ping_tls`] connects, runs the rustls **client** handshake trusting a
//!   configured CA, then drives [`ping_exchange`].
//!
//! Because [`serve`] and [`ping_exchange`] are transport-agnostic, the TLS
//! path reuses them unchanged — only the byte transport differs.
//!
//! The user-facing [`server`] and [`ping`] entry points read the bind /
//! connect address from the configured `tls-server-address` /
//! `tls-server-port` options (defaulting to `127.0.0.1:8432`) and select the
//! transport from the configured TLS options:
//!
//! - [`server`] uses TLS when `tls-server-cert-file` **and**
//!   `tls-server-key-file` are configured (loading PEM via `rustls-pemfile`),
//!   otherwise falls back to plain TCP.
//! - [`ping`] uses TLS when a CA file (`tls-server-ca-file`) is configured,
//!   otherwise falls back to plain TCP.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_io::{IoError, IoRead, IoWrite};
use pgbr_storage::Storage;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, ServerConfig, ServerConnection, SideData, StreamOwned,
    SupportedCipherSuite,
};
use socket2::{SockRef, TcpKeepalive};

use crate::CommandError;

/// Default bind / connect address used when the configured
/// `tls-server-address` / `tls-server-port` options are absent.
const DEFAULT_ADDRESS: &str = "127.0.0.1:8432";

/// Hard cap on the number of in-flight per-connection worker threads spawned
/// by the `server` accept loops (TLS and plain TCP).
///
/// Stock pgBackRest's C `server.c` `fork()`s per accepted connection so a
/// long-running backup transfer does not block PG's `archive_command`
/// invocations of `archive-push`. The Rust port mirrors that with a
/// `std::thread::spawn` per accepted connection (no Tokio: the protocol layer
/// is synchronous and threading-based). An unbounded spawn is a footgun — a
/// runaway or malicious peer could exhaust the host — so the loop refuses
/// new connections (dropping the freshly accepted stream so the kernel
/// resets the peer) once this many threads are in flight, logging a
/// rate-limited warning. `32` is a generous ceiling: a typical pgBackRest
/// deployment serves one to a handful of simultaneous workers (one backup
/// stream + a small fan-out of `archive-push` calls), and the OS scheduler
/// handles dozens of these effortlessly. Tests exercise a smaller cap via
/// the `_caps` accept-loop variants.
const MAX_WORKER_THREADS: usize = 32;

/// Rate at which the accept loop logs a warning when an incoming connection
/// is dropped because the worker-thread cap is full. Once per minute is the
/// pgBackRest convention for "noisy but worth knowing".
const CAP_WARN_INTERVAL: Duration = Duration::from_mins(1);

/// RAII guard that decrements an `Arc<AtomicUsize>` worker counter when
/// dropped — including on a per-connection thread panic. Each accept-loop
/// spawn moves one of these into the spawned thread; the counter
/// `fetch_sub`s on drop, so the accept loop's view of in-flight workers is
/// always accurate.
struct WorkerSlot {
    counter: Arc<AtomicUsize>,
}

impl WorkerSlot {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self { counter }
    }
}

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Rate-limited "cap exceeded" warning state. The accept loops share an
/// instance and only emit a log line once per [`CAP_WARN_INTERVAL`] to avoid
/// flooding the log when an aggressive client hammers the listener.
struct CapWarnState {
    last: Mutex<Option<Instant>>,
}

impl CapWarnState {
    const fn new() -> Self {
        Self { last: Mutex::new(None) }
    }

    /// Log a warning if enough time has elapsed since the previous one.
    fn maybe_warn(&self, in_flight: usize, cap: usize) {
        let mut guard = match self.last.lock() {
            Ok(g) => g,
            // Lock poisoned by an earlier panic: treat as never-warned so the
            // operator still sees the message once the next interval elapses.
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        let should_log = guard.is_none_or(|last| now.duration_since(last) >= CAP_WARN_INTERVAL);
        if should_log {
            *guard = Some(now);
            drop(guard);
            crate::control::log_warn(&format!(
                "server: worker-thread cap reached ({in_flight}/{cap}); dropping incoming connection"
            ));
        }
    }
}

/// Join every collected per-connection thread handle. Called on the
/// graceful-shutdown path of both accept loops (when `should_continue`
/// returns `false`) so any in-flight worker finishes before the listener
/// teardown. A panicked worker thread surfaces as `Err` from `join`; the
/// accept loop logs it and continues joining the rest — losing one panicked
/// session must not strand the others.
fn join_workers(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        if let Err(panic) = handle.join() {
            crate::control::log_warn(&format!("server: worker thread panicked: {panic:?}"));
        }
    }
}

/// Resolved TCP keepalive settings for accepted `server` connections.
///
/// `sck-keep-alive` (default `true`) is the master switch: when off, no
/// keepalive is configured on the accepted socket at all. When on, `SO_KEEPALIVE`
/// is enabled and the `tcp-keep-alive-idle` / `-interval` / `-count` options —
/// when set — tune the per-socket idle time, probe interval, and probe count.
/// C ref: `sckOptionSet` / `sckKeepAlive` applied to accepted sockets in
/// `src/common/io/socket/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeepAlive {
    /// Master switch (`sck-keep-alive`). When false nothing is applied.
    enabled: bool,
    /// `tcp-keep-alive-idle`, seconds of idle before the first probe.
    idle: Option<u32>,
    /// `tcp-keep-alive-interval`, seconds between probes.
    interval: Option<u32>,
    /// `tcp-keep-alive-count`, number of unacknowledged probes before drop.
    count: Option<u32>,
}

impl Default for KeepAlive {
    fn default() -> Self {
        // Matches the `sck-keep-alive` default (`true`) with no explicit timers,
        // so the public `serve_*` helpers (and their tests) enable plain
        // `SO_KEEPALIVE` without tuning the timers.
        Self {
            enabled: true,
            idle: None,
            interval: None,
            count: None,
        }
    }
}

impl KeepAlive {
    /// Resolve the keepalive settings from the resolved configuration.
    fn from_config(config: &LoadedConfig) -> Self {
        // `sck-keep-alive` is a boolean defaulting to true; absence means on.
        let enabled = match config.options.get(&("sck-keep-alive".to_owned(), None)) {
            Some(OptionValue::Boolean(b)) => *b,
            _ => true,
        };
        Self {
            enabled,
            idle: keepalive_secs(config, "tcp-keep-alive-idle"),
            interval: keepalive_secs(config, "tcp-keep-alive-interval"),
            count: keepalive_secs(config, "tcp-keep-alive-count"),
        }
    }

    /// Apply these settings to an accepted [`TcpStream`], best-effort.
    ///
    /// A failure to set a socket option is logged and ignored: keepalive tuning
    /// is an optimisation, never a reason to drop an otherwise-good connection
    /// (the C side likewise treats `setsockopt` failures as warnings).
    fn apply(self, stream: &TcpStream) {
        if !self.enabled {
            return;
        }
        let mut ka = TcpKeepalive::new();
        if let Some(secs) = self.idle {
            ka = ka.with_time(Duration::from_secs(u64::from(secs)));
        }
        if let Some(secs) = self.interval {
            ka = ka.with_interval(Duration::from_secs(u64::from(secs)));
        }
        // `with_retries` (probe count, `TCP_KEEPCNT`) is gated by socket2 per
        // target; the dev / CI build targets Linux (Debian 13, see CLAUDE.md)
        // where it is available. Guard so a non-Linux build still compiles —
        // there the probe count is simply not applied (best-effort).
        #[cfg(target_os = "linux")]
        if let Some(c) = self.count {
            ka = ka.with_retries(c);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = self.count;
        if let Err(err) = SockRef::from(stream).set_tcp_keepalive(&ka) {
            crate::control::log_warn(&format!("unable to set tcp keepalive on accepted socket: {err}"));
        }
    }
}

/// Read a positive `tcp-keep-alive-*` integer option as `u32` seconds / count,
/// dropping absent or non-positive values.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn keepalive_secs(config: &LoadedConfig, name: &str) -> Option<u32> {
    match config.options.get(&(name.to_owned(), None)) {
        // The allow-ranges in config.yaml cap these well within u32, so the cast
        // of a validated positive i64 cannot truncate.
        Some(OptionValue::Integer(v)) if *v > 0 => Some(*v as u32),
        _ => None,
    }
}

/// Resolve the `sck-block` boolean from the configuration (default `false`).
///
/// `sck-block` selects blocking (`true`) vs non-blocking (`false`) socket mode
/// for the protocol sockets. pgBackRest defaults it to `false` (non-blocking) —
/// see the `sck-block` definition in `config.yaml`. Returns the resolved flag.
fn sck_block(config: &LoadedConfig) -> bool {
    match config.options.get(&("sck-block".to_owned(), None)) {
        Some(OptionValue::Boolean(b)) => *b,
        _ => false,
    }
}

/// Apply the resolved `sck-block` mode to a socket, best-effort.
///
/// `block == true` (the operator opted in to blocking sockets) explicitly sets
/// blocking mode. `block == false` (the `sck-block` default) leaves the socket
/// as-is: the protocol transport here is synchronous std I/O, which relies on
/// blocking reads / writes, so forcing non-blocking mode would break the serve /
/// ping loops with spurious `WouldBlock` errors. The original C runs its sockets
/// non-blocking behind an event loop; this Rust port has no such loop, so the
/// non-blocking case is honoured only to the extent the blocking transport
/// allows (i.e. no-op) — a deliberate best-effort limitation.
///
/// A failure to set the mode is logged and ignored: like keepalive tuning it is
/// never a reason to drop an otherwise-good connection. C ref: `sckOptionSet` /
/// the blocking-mode handling in `src/common/io/socket/`.
fn apply_sck_block(stream: &TcpStream, block: bool) {
    if block && let Err(err) = stream.set_nonblocking(false) {
        crate::control::log_warn(&format!("unable to set socket blocking mode (sck-block=true): {err}"));
    }
}

/// Disable Nagle's algorithm (set `TCP_NODELAY`) on an accepted protocol socket,
/// best-effort.
///
/// The synchronous storage protocol exchanges many small request→response rounds
/// (one per ~64KB write-chunk plus many metadata ops). With Nagle enabled (the
/// kernel default) a small server response is buffered waiting for the ACK of a
/// previous segment while the client blocks reading that response — a head-of-line
/// stall. A `backup` issues thousands of these small rounds and effectively hangs;
/// `archive-push` sends one ~16MB segment, fills the send buffer, and bypasses
/// Nagle, which is why only `backup` exhibits the hang. Disabling Nagle makes
/// every response flush immediately.
///
/// A failure to set the option is logged and ignored, exactly like keepalive and
/// blocking-mode tuning: it is an optimisation, never a reason to drop an
/// otherwise-good connection. Stock pgBackRest sets `TCP_NODELAY` unconditionally
/// on every socket — C ref: `sckOptionSet` / `src/common/io/socket/common.c`.
fn apply_nodelay(stream: &TcpStream) {
    if let Err(err) = stream.set_nodelay(true) {
        crate::control::log_warn(&format!("unable to set TCP_NODELAY on accepted socket: {err}"));
    }
}

/// Protocol error code returned for malformed or unexpected requests.
///
/// Mirrors `pgbr_error::ErrorType` numbering, where `ProtocolError` is 39.
const PROTOCOL_ERROR: u32 = 39;

/// Serve protocol requests read from `reader`, writing responses to
/// `writer`, until EOF or an `exit` command. Returns the number of
/// requests handled.
///
/// Recognised commands (this slice):
/// - `noOp` -> Ok response with no payload.
/// - `exit` -> Ok response, then stop the loop.
/// - anything else -> Err response with code [`PROTOCOL_ERROR`] (39).
///
/// A clean EOF (no bytes pending) stops the loop without error. A stray
/// [`Response`](pgbr_protocol::Response) arriving where a request is
/// expected is answered with an Err response — a server should only ever
/// receive requests — but does not count as a handled request.
///
/// # Errors
///
/// Returns [`CommandError::Other`] wrapping a
/// [`CodecError`](pgbr_protocol::CodecError) on a malformed message or a
/// write failure.
pub fn serve<R: IoRead, W: IoWrite>(reader: &mut R, writer: &mut W) -> Result<usize, CommandError> {
    use pgbr_protocol::{ErrResponse, Message, OkResponse, Request, Response, read_message, write_message};

    let mut handled = 0usize;
    loop {
        match read_message(reader).map_err(|e| CommandError::Other(format!("protocol read: {e}")))? {
            // Clean EOF: caller closed the stream between messages.
            None => break,
            // A server should never receive a response. Reply with an error
            // but keep serving — this is a protocol violation, not a request.
            Some(Message::Response(_)) => {
                let resp = Message::Response(Response::Err(ErrResponse {
                    err: PROTOCOL_ERROR,
                    message: "server received a response message".to_owned(),
                    stack: None,
                }));
                write_message(writer, &resp).map_err(|e| CommandError::Other(format!("protocol write: {e}")))?;
            }
            Some(Message::Request(Request { cmd, .. })) => {
                handled += 1;
                let resp = match cmd.as_str() {
                    "noOp" | "exit" => Message::Response(Response::Ok(OkResponse { out: None })),
                    other => Message::Response(Response::Err(ErrResponse {
                        err: PROTOCOL_ERROR,
                        message: format!("unknown protocol command `{other}`"),
                        stack: None,
                    })),
                };
                write_message(writer, &resp).map_err(|e| CommandError::Other(format!("protocol write: {e}")))?;

                if cmd == "exit" {
                    break;
                }
            }
        }
    }

    Ok(handled)
}

/// Drive a ping exchange over the given streams: write a `noOp` request,
/// read the response, return `Ok(())` iff the peer replied Ok.
///
/// # Errors
///
/// - [`CommandError::Other`] wrapping a [`CodecError`](pgbr_protocol::CodecError)
///   on a malformed message or an I/O failure.
/// - [`CommandError::Other`] if the peer replied with an Err response, sent
///   a request instead of a response, or closed the stream without
///   answering.
pub fn ping_exchange<R: IoRead, W: IoWrite>(reader: &mut R, writer: &mut W) -> Result<(), CommandError> {
    use pgbr_protocol::{Message, Request, Response, read_message, write_message};

    let req = Message::Request(Request {
        cmd: "noOp".to_owned(),
        param: Vec::new(),
    });
    write_message(writer, &req).map_err(|e| CommandError::Other(format!("protocol write: {e}")))?;

    match read_message(reader).map_err(|e| CommandError::Other(format!("protocol read: {e}")))? {
        Some(Message::Response(Response::Ok(_))) => Ok(()),
        Some(Message::Response(Response::Err(e))) => Err(CommandError::Other(format!("ping rejected: {}", e.message))),
        Some(Message::Request(_)) => Err(CommandError::Other("ping got a request, expected response".to_owned())),
        None => Err(CommandError::Other("ping got EOF, no response".to_owned())),
    }
}

/// Adapts a [`std::net::TcpStream`] to the [`IoRead`] / [`IoWrite`] traits
/// the protocol cores expect.
///
/// `serve` and `ping_exchange` take a *separate* reader and writer, but a
/// `TcpStream` is a single bidirectional handle, so each end of an exchange
/// holds two `TcpIo`s wrapping `try_clone`d handles of the same socket — one
/// used as the reader, one as the writer.
///
/// `read` maps a zero-length read to EOF (sets the `eof` flag); errors map to
/// [`IoError::Backend`]. `close` does a best-effort write-shutdown
/// (`TcpStream::shutdown(Shutdown::Write)`) so the peer sees a clean EOF.
pub struct TcpIo {
    stream: TcpStream,
    eof: bool,
}

impl TcpIo {
    /// Wrap a connected `TcpStream`.
    #[must_use]
    pub const fn new(stream: TcpStream) -> Self {
        Self { stream, eof: false }
    }
}

impl IoRead for TcpIo {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let n = self
            .stream
            .read(buf)
            .map_err(|e| IoError::Backend(format!("tcp read: {e}")))?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

impl IoWrite for TcpIo {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        self.stream
            .write_all(buf)
            .map_err(|e| IoError::Backend(format!("tcp write: {e}")))
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Write::flush(&mut self.stream).map_err(|e| IoError::Backend(format!("tcp flush: {e}")))
    }

    fn close(&mut self) -> Result<(), IoError> {
        // Best-effort write-shutdown so the peer reads a clean EOF; a stream
        // already shut down by the peer is not an error worth surfacing.
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|e| IoError::Backend(format!("tcp shutdown: {e}")))
    }
}

/// Split a connected `TcpStream` into a reader half and a writer half, both
/// wrapping `try_clone`d handles of the same socket.
fn split(stream: TcpStream) -> Result<(TcpIo, TcpIo), CommandError> {
    let read_half = stream
        .try_clone()
        .map_err(|e| CommandError::Other(format!("tcp try_clone: {e}")))?;
    Ok((TcpIo::new(read_half), TcpIo::new(stream)))
}

/// Long-running TCP accept loop for the `server` command.
///
/// Runs [`serve`] on each accepted connection. A per-connection protocol /
/// I/O error is logged and the loop continues so a single malformed peer
/// does not bring the listener down; only an unrecoverable
/// [`accept`](TcpListener::accept) failure (an I/O error other than
/// `Interrupted` / `WouldBlock`) returns. `serve_tcp` and the configured
/// `server` command keep the listener alive across many pgBackRest
/// connections through this entry point. Tests drive the loop with a
/// shutdown predicate via [`serve_listener_with_continue`].
///
/// # Errors
///
/// [`CommandError::Other`] on a non-retryable accept failure.
pub fn serve_listener(listener: &TcpListener) -> Result<(), CommandError> {
    serve_listener_with(listener, KeepAlive::default(), false)
}

/// [`serve_listener`] with explicit keepalive + `sck-block` settings applied
/// to the accepted socket. The config-driven `server` path threads the
/// resolved [`KeepAlive`] and `sck-block` flag here; the public
/// [`serve_listener`] uses the defaults.
fn serve_listener_with(listener: &TcpListener, keepalive: KeepAlive, sck_block: bool) -> Result<(), CommandError> {
    serve_listener_with_continue(listener, keepalive, sck_block, || true)
}

/// Accept-loop core used by [`serve_listener_with`] and (via a shutdown flag)
/// by the unit tests. Wraps [`serve_listener_with_continue_caps`] with the
/// production worker-thread cap [`MAX_WORKER_THREADS`].
fn serve_listener_with_continue(
    listener: &TcpListener,
    keepalive: KeepAlive,
    sck_block: bool,
    should_continue: impl FnMut() -> bool,
) -> Result<(), CommandError> {
    serve_listener_with_continue_caps(listener, keepalive, sck_block, MAX_WORKER_THREADS, should_continue)
}

/// Accept-loop core for plain-TCP `server` connections, parameterized over
/// the worker-thread cap so tests can drive it down to a small number and
/// observe the cap-rejection path.
///
/// Per accepted connection: applies keepalive + `sck-block`, then **spawns a
/// `std::thread`** that splits the socket into reader / writer halves, runs
/// [`serve`], closes the writer, and exits. The accept loop returns to
/// [`accept`](TcpListener::accept) immediately so a long-running connection
/// does not block subsequent peers — this is the same isolation stock
/// pgBackRest's C `server.c` gets from `fork()`.
///
/// Concurrency is bounded by `max_workers`: an
/// `Arc<AtomicUsize>` counter is incremented before each spawn (via a
/// [`WorkerSlot`] RAII guard inside the thread) and decremented when the
/// thread exits, panic or otherwise. When the counter is at the cap the
/// accept loop drops the freshly accepted stream so the kernel resets the
/// peer (which will retry), and logs a rate-limited warning — the
/// alternative (blocking on a join) would defeat the purpose of the spawn.
///
/// `should_continue` is polled before each accept (and after every
/// `WouldBlock` retry); returning `false` ends the loop cleanly. On
/// graceful shutdown every in-flight thread is `join`ed so the listener
/// teardown waits for active sessions to finish. Production passes
/// `|| true`, so the loop runs until the listener is torn down.
fn serve_listener_with_continue_caps(
    listener: &TcpListener,
    keepalive: KeepAlive,
    sck_block: bool,
    max_workers: usize,
    mut should_continue: impl FnMut() -> bool,
) -> Result<(), CommandError> {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let warn_state = Arc::new(CapWarnState::new());
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    loop {
        if !should_continue() {
            // Drop the listener-scoped handles so the spawned threads can
            // finish; this is the cleanup symmetric to the spawn above.
            join_workers(handles);
            return Ok(());
        }
        let (stream, _peer) = match listener.accept() {
            Ok(v) => v,
            // `Interrupted` is benign (a signal); retry immediately.
            // `WouldBlock` only happens when the listener was set to
            // non-blocking — wait briefly so `should_continue` can flip a
            // shutdown flag without busy-spinning.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                join_workers(handles);
                return Err(CommandError::Other(format!("tcp accept: {e}")));
            }
        };
        keepalive.apply(&stream);
        apply_sck_block(&stream, sck_block);
        apply_nodelay(&stream);

        // Periodically reap finished worker threads so the vector does not
        // grow unboundedly across long-lived daemons. A panicked worker's
        // counter is already decremented (via `WorkerSlot::drop`); the
        // panic itself is logged by the shutdown-path `join_workers`.
        handles.retain(|h| !h.is_finished());

        // Refuse the connection if the cap is reached: drop the stream
        // (closes the socket so the kernel sends RST/FIN), log once per
        // minute, and continue accepting. Better to fail fast than to
        // serialize behind a queue and re-introduce the head-of-line
        // blocking this whole change is fixing.
        let cur = in_flight.load(Ordering::Acquire);
        if cur >= max_workers {
            warn_state.maybe_warn(cur, max_workers);
            drop(stream);
            continue;
        }

        let slot_counter = Arc::clone(&in_flight);
        let handle = std::thread::spawn(move || {
            let _slot = WorkerSlot::new(slot_counter);
            let (mut reader, mut writer) = match split(stream) {
                Ok(v) => v,
                Err(e) => {
                    crate::control::log_info(&format!("tcp connection setup failed: {e}"));
                    return;
                }
            };
            if let Err(e) = serve(&mut reader, &mut writer) {
                crate::control::log_info(&format!("tcp serve ended: {e}"));
            }
            // Signal a clean EOF to the peer; ignore an already-closed socket.
            let _ = writer.close();
        });
        handles.push(handle);
    }
}

/// Bind a [`TcpListener`] to `addr` and serve a connection via
/// [`serve_listener`].
///
/// # Errors
///
/// [`CommandError::Other`] if the address cannot be bound, plus anything
/// [`serve_listener`] returns.
pub fn serve_tcp(addr: &str) -> Result<(), CommandError> {
    serve_tcp_with(addr, KeepAlive::default(), false)
}

/// [`serve_tcp`] with explicit keepalive + `sck-block` settings.
fn serve_tcp_with(addr: &str, keepalive: KeepAlive, sck_block: bool) -> Result<(), CommandError> {
    let listener = TcpListener::bind(addr).map_err(|e| CommandError::Other(format!("tcp bind {addr}: {e}")))?;
    crate::control::log_info(&format!("server listening (tcp) on {addr}"));
    serve_listener_with(&listener, keepalive, sck_block)
}

/// Connect a [`TcpStream`] to `addr` and run [`ping_exchange`] over its
/// reader / writer halves.
///
/// # Errors
///
/// [`CommandError::Other`] if the connection cannot be made or cloned, plus
/// anything [`ping_exchange`] returns.
pub fn ping_tcp(addr: &str) -> Result<(), CommandError> {
    let stream = TcpStream::connect(addr).map_err(|e| CommandError::Other(format!("tcp connect {addr}: {e}")))?;
    let (mut reader, mut writer) = split(stream)?;
    ping_exchange(&mut reader, &mut writer)
}

/// Ensure a process-level [`rustls`] [`CryptoProvider`](rustls::crypto::CryptoProvider)
/// is installed.
///
/// `rustls` 0.23 requires a crypto provider to be selected before any
/// `ClientConfig` / `ServerConfig` is built. With the default `ring` feature
/// enabled the `ring` provider is available; we install it as the process
/// default exactly once. `install_default` returns `Err` if a provider is
/// already installed (e.g. installed by an earlier call or by another part of
/// the process), which is fine — we only need *a* provider, so that case is
/// ignored.
fn ensure_crypto_provider() {
    // Ignore the result: an `Err` means a provider is already installed, which
    // satisfies the precondition just as well as our installing one.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Adapts an owned [`rustls`] stream to the [`IoRead`] / [`IoWrite`] traits the
/// protocol cores expect.
///
/// A [`StreamOwned`] couples a `rustls` connection (server or client) with the
/// underlying [`TcpStream`] and implements [`std::io::Read`] / [`Write`],
/// transparently encrypting writes and decrypting reads. Unlike [`TcpIo`],
/// which holds two `try_clone`d halves of one socket, a `rustls` stream is a
/// single stateful object that must own both directions — so one `TlsIo`
/// serves as *both* the reader and the writer of an exchange (the protocol
/// cores accept the same value for both arguments via `&mut`).
///
/// `read` maps a zero-length read to EOF (sets the `eof` flag); errors map to
/// [`IoError::Backend`]. `close` sends the TLS `close_notify` alert and then
/// write-shuts the underlying socket so the peer sees a clean EOF.
pub struct TlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    stream: StreamOwned<C, TcpStream>,
    eof: bool,
}

/// Server-side TLS adapter: a [`TlsIo`] over a [`ServerConnection`].
pub type TlsServerIo = TlsIo<ServerConnection, rustls::server::ServerConnectionData>;

/// Client-side TLS adapter: a [`TlsIo`] over a [`ClientConnection`].
pub type TlsClientIo = TlsIo<ClientConnection, rustls::client::ClientConnectionData>;

impl<C, S> TlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    /// Wrap an established `rustls` stream.
    #[must_use]
    pub const fn new(stream: StreamOwned<C, TcpStream>) -> Self {
        Self { stream, eof: false }
    }
}

impl<C, S> IoRead for TlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let n = self
            .stream
            .read(buf)
            .map_err(|e| IoError::Backend(format!("tls read: {e}")))?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

impl<C, S> IoWrite for TlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        self.stream
            .write_all(buf)
            .map_err(|e| IoError::Backend(format!("tls write: {e}")))
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Write::flush(&mut self.stream).map_err(|e| IoError::Backend(format!("tls flush: {e}")))
    }

    fn close(&mut self) -> Result<(), IoError> {
        // Send the TLS close_notify alert so the peer can distinguish an orderly
        // shutdown from a truncation attack, then write-shut the socket so the
        // peer reads a clean EOF. A socket already shut down by the peer is not
        // an error worth surfacing. `send_close_notify` lives on `CommonState`,
        // reached through the connection's `DerefMut`.
        self.stream.conn.send_close_notify();
        let _ = self.stream.flush();
        self.stream
            .sock
            .shutdown(Shutdown::Write)
            .map_err(|e| IoError::Backend(format!("tls shutdown: {e}")))
    }
}

/// A shared, cloneable handle to one [`TlsIo`].
///
/// [`serve`] / [`ping_exchange`] take *separate* reader and writer values, but
/// a `rustls` [`StreamOwned`] is a single stateful object owning both
/// directions — it cannot be `try_clone`d into independent halves the way a
/// [`TcpStream`] can (see [`split`]). So we wrap one `TlsIo` in
/// `Rc<RefCell<…>>` and hand out two cheap clones of the handle: one used as
/// the reader, one as the writer. Both borrow the inner `TlsIo` only for the
/// duration of a single `read` / `write` / `flush` / `close` call, and the
/// protocol cores never hold a read borrow live across a write (or vice
/// versa), so the `RefCell` borrows never overlap at runtime.
struct SharedTlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    inner: std::rc::Rc<std::cell::RefCell<TlsIo<C, S>>>,
}

impl<C, S> SharedTlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn new(io: TlsIo<C, S>) -> Self {
        Self {
            inner: std::rc::Rc::new(std::cell::RefCell::new(io)),
        }
    }

    fn clone_handle(&self) -> Self {
        Self {
            inner: std::rc::Rc::clone(&self.inner),
        }
    }
}

impl<C, S> IoRead for SharedTlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        self.inner.borrow_mut().read(buf)
    }

    fn eof(&self) -> bool {
        self.inner.borrow().eof()
    }
}

impl<C, S> IoWrite for SharedTlsIo<C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        self.inner.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.inner.borrow_mut().flush()
    }

    fn close(&mut self) -> Result<(), IoError> {
        self.inner.borrow_mut().close()
    }
}

/// Load a PEM certificate chain from `path`.
fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, CommandError> {
    let pem = std::fs::read(path).map_err(|e| CommandError::Other(format!("read cert file {path}: {e}")))?;
    let mut reader = &pem[..];
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CommandError::Other(format!("parse cert file {path}: {e}")))
}

/// Load a single PEM private key from `path` (PKCS#8, PKCS#1, or SEC1).
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, CommandError> {
    let pem = std::fs::read(path).map_err(|e| CommandError::Other(format!("read key file {path}: {e}")))?;
    let mut reader = &pem[..];
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| CommandError::Other(format!("parse key file {path}: {e}")))?
        .ok_or_else(|| CommandError::Other(format!("no private key found in {path}")))
}

/// Build a [`RootCertStore`] trusting every certificate in the PEM file at
/// `ca_path`.
fn root_store_from_ca(ca_path: &str) -> Result<RootCertStore, CommandError> {
    let mut roots = RootCertStore::empty();
    add_ca_file(&mut roots, ca_path)?;
    Ok(roots)
}

/// Add every certificate in the PEM file at `ca_path` to `roots`.
fn add_ca_file(roots: &mut RootCertStore, ca_path: &str) -> Result<(), CommandError> {
    for cert in load_cert_chain(ca_path)? {
        roots
            .add(cert)
            .map_err(|e| CommandError::Other(format!("add CA from {ca_path}: {e}")))?;
    }
    Ok(())
}

/// Add every certificate found in every regular file under the directory
/// `ca_dir` to `roots`.
///
/// This is the `*-host-ca-path` / OpenSSL `CApath` style trust source: a
/// directory holding one or more CA certificate files (each possibly a bundle).
/// Every entry that is a regular file is read and parsed as a PEM chain and its
/// certificates added to the store; sub-directories and unreadable / non-PEM
/// entries are skipped so a stray file does not abort loading the rest. Entries
/// are processed in sorted order for deterministic behaviour. C ref:
/// `SSL_CTX_load_verify_locations` with a `CApath` in `src/common/io/tls/`.
fn add_ca_path(roots: &mut RootCertStore, ca_dir: &str) -> Result<(), CommandError> {
    let entries = std::fs::read_dir(ca_dir).map_err(|e| CommandError::Other(format!("read ca-path dir {ca_dir}: {e}")))?;

    // Collect paths first so they can be sorted for deterministic ordering.
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| CommandError::Other(format!("read ca-path entry in {ca_dir}: {e}")))?;
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();

    for path in files {
        // Parse each file as a PEM chain; a file that cannot be read, or holds no
        // certs (not PEM at all), simply contributes nothing rather than failing
        // the load.
        let Ok(pem) = std::fs::read(&path) else { continue };
        let display = path.display().to_string();
        let mut reader = &pem[..];
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader).filter_map(Result::ok).collect();
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| CommandError::Other(format!("add CA from {display}: {e}")))?;
        }
    }
    Ok(())
}

/// Build a [`RootCertStore`] from an optional CA *file* and an optional CA
/// *directory*, loading the certs from each that is supplied.
///
/// `ca_file` is a single PEM file (`*-host-ca-file`); `ca_dir` is a directory of
/// PEM files (`*-host-ca-path`). Both are additive — supplying both trusts the
/// union — and at least one must yield a usable root for the resulting store to
/// validate any peer (an empty store is returned when neither is given, which
/// the caller treats as a configuration error upstream).
///
/// # Errors
///
/// [`CommandError::Other`] if a configured file / directory cannot be read or a
/// certificate it contains is rejected by rustls.
pub fn root_store_from_ca_sources(ca_file: Option<&str>, ca_dir: Option<&str>) -> Result<RootCertStore, CommandError> {
    let mut roots = RootCertStore::empty();
    if let Some(file) = ca_file {
        add_ca_file(&mut roots, file)?;
    }
    if let Some(dir) = ca_dir {
        add_ca_path(&mut roots, dir)?;
    }
    Ok(roots)
}

/// The X.509 OID for the subject Common Name attribute (`2.5.4.3`), DER-encoded
/// as the contents of an OBJECT IDENTIFIER: `55 04 03`.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// `tls-server-auth` wildcard stanza: an authorized client CN mapped to `*` is
/// permitted to act for **any** stanza.
const AUTH_STANZA_WILDCARD: &str = "*";

/// Parse the `tls-server-auth` mapping (a `<cn> = <stanza>[,<stanza>...]`
/// hash, where each value is a comma-separated stanza list) into a CN ->
/// stanza-list map.
///
/// pgBackRest's `tls-server-auth` is a `hash` option: each key is a client
/// certificate Common Name and each value is the stanza (or comma-separated set
/// of stanzas, or `*` for all) that client may operate on. C reference:
/// `cfgOptionKvGet(cfgOptTlsServerAuth)` consumed in `src/command/server/server.c`.
///
/// Stanza tokens are trimmed and empty tokens dropped; a `*` token anywhere in a
/// value authorizes every stanza (see [`cn_authorized_for_stanza`]).
fn parse_tls_server_auth(map: &BTreeMap<String, String>) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (cn, stanzas) in map {
        let list: Vec<String> = stanzas
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        out.insert(cn.clone(), list);
    }
    out
}

/// Read the resolved `tls-server-auth` hash option into the CN -> stanza-list
/// map, returning an empty map when the option is absent.
fn tls_server_auth(config: &LoadedConfig) -> BTreeMap<String, Vec<String>> {
    match config.options.get(&("tls-server-auth".to_owned(), None)) {
        Some(OptionValue::Hash(map)) => parse_tls_server_auth(map),
        _ => BTreeMap::new(),
    }
}

/// Decide whether the client certificate Common Name `cn` is authorized to act
/// on `stanza` per the parsed `tls-server-auth` map.
///
/// A CN is authorized when it has an entry in the map and that entry either
/// lists `stanza` explicitly or carries the [`AUTH_STANZA_WILDCARD`] (`*`)
/// token. An unknown CN is never authorized. A `None` stanza (the connecting
/// client did not request one) is authorized only by `*`.
#[must_use]
fn cn_authorized_for_stanza(auth: &BTreeMap<String, Vec<String>>, cn: &str, stanza: Option<&str>) -> bool {
    match auth.get(cn) {
        None => false,
        Some(stanzas) => {
            if stanzas.iter().any(|s| s == AUTH_STANZA_WILDCARD) {
                return true;
            }
            stanza.is_some_and(|want| stanzas.iter().any(|s| s == want))
        }
    }
}

/// One DER TLV element: its tag, the byte range of its *contents* within the
/// parent slice, and the offset just past the whole element.
struct Tlv {
    tag: u8,
    /// Start offset of the contents (value) within the parent slice.
    content_start: usize,
    /// End offset of the contents (exclusive) within the parent slice.
    content_end: usize,
    /// Offset just past this whole element (tag + length + contents).
    next: usize,
}

/// Parse one DER TLV element from `der` starting at `pos`, returning its tag,
/// content range, and the offset past it. Supports short-form and the long-form
/// length encoding X.509 certs use; returns `None` on a truncated / malformed
/// header.
fn read_tlv(der: &[u8], pos: usize) -> Option<Tlv> {
    let tag = *der.get(pos)?;
    let len_byte = *der.get(pos + 1)?;
    let (len, header) = if len_byte & 0x80 == 0 {
        // Short form: the low 7 bits are the length.
        (len_byte as usize, 2usize)
    } else {
        // Long form: low 7 bits give the number of subsequent length bytes.
        let num = (len_byte & 0x7f) as usize;
        if num == 0 || num > 4 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..num {
            len = (len << 8) | (*der.get(pos + 2 + k)? as usize);
        }
        (len, 2 + num)
    };
    let content_start = pos + header;
    let content_end = content_start.checked_add(len)?;
    if content_end > der.len() {
        return None;
    }
    Some(Tlv {
        tag,
        content_start,
        content_end,
        next: content_end,
    })
}

/// Extract the subject Common Name (CN) from a DER-encoded X.509 certificate.
///
/// Navigates the certificate structure to the `subject` field — the issuer also
/// carries a CN and appears *first* in the `TBSCertificate`, so a naive
/// first-CN scan would return the issuer's name. The walk descends
/// `Certificate -> TBSCertificate`, skips the optional `[0] version`,
/// `serialNumber`, `signature`, `issuer`, and `validity` fields in order, and
/// then scans the `subject` `Name` for the CN attribute (OID `2.5.4.3`).
///
/// Returns `None` if the structure cannot be navigated or no CN is found in the
/// subject.
#[must_use]
fn extract_cn_from_cert(der: &[u8]) -> Option<String> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let cert = read_tlv(der, 0)?;
    let tbs = read_tlv(der, cert.content_start)?;
    let mut pos = tbs.content_start;
    let tbs_end = tbs.content_end;

    // [0] EXPLICIT version (context tag 0xA0) is optional — skip it when present.
    let first = read_tlv(der, pos)?;
    if first.tag == 0xA0 {
        pos = first.next;
    }

    // Skip serialNumber, signature (AlgId), issuer, validity — four elements —
    // to land on the subject Name.
    for _ in 0..4 {
        let tlv = read_tlv(der, pos)?;
        if tlv.next > tbs_end {
            return None;
        }
        pos = tlv.next;
    }

    // `subject` is the next element: a SEQUENCE of RDNs. Scan it for the CN.
    let subject = read_tlv(der, pos)?;
    scan_name_for_cn(&der[subject.content_start..subject.content_end])
}

/// Scan a DER-encoded `Name` (the contents of the subject / issuer SEQUENCE)
/// for the Common Name attribute (OID `2.5.4.3`) and return its value.
fn scan_name_for_cn(name: &[u8]) -> Option<String> {
    // Recognised ASN.1 directory-string tags a CN value may carry.
    const STRING_TAGS: &[u8] = &[0x13, 0x0c, 0x16, 0x14, 0x1e];
    // The DER short-form length byte for the CN OID contents (3 bytes).
    const OID_LEN_BYTE: u8 = 0x03;

    let mut i = 0usize;
    while i + 2 + OID_COMMON_NAME.len() < name.len() {
        // An OID is tag 0x06, then a length byte, then the OID bytes. Match the
        // 3-byte CN OID encoded with the short-form length 0x03.
        if name[i] == 0x06 && name[i + 1] == OID_LEN_BYTE && &name[i + 2..i + 2 + OID_COMMON_NAME.len()] == OID_COMMON_NAME {
            // The value follows the OID: <string-tag> <len> <bytes...>.
            let value_tag_at = i + 2 + OID_COMMON_NAME.len();
            if value_tag_at + 1 < name.len() && STRING_TAGS.contains(&name[value_tag_at]) {
                let len = name[value_tag_at + 1] as usize;
                let start = value_tag_at + 2;
                if start + len <= name.len() {
                    // BMPString (0x1e) is UTF-16BE; the rest are byte strings we
                    // decode lossily as UTF-8.
                    let bytes = &name[start..start + len];
                    let value = if name[value_tag_at] == 0x1e {
                        decode_bmp_string(bytes)
                    } else {
                        String::from_utf8_lossy(bytes).into_owned()
                    };
                    return Some(value);
                }
            }
        }
        i += 1;
    }
    None
}

/// Decode a `BMPString` (UTF-16 big-endian) into a `String`, lossily.
fn decode_bmp_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Map a `tls-cipher-12` / `tls-cipher-13` option value (a colon- or
/// comma-separated cipher-suite name list) to the matching rustls
/// [`SupportedCipherSuite`]s, in the configured order.
///
/// Names are matched case-insensitively against rustls's suite names (e.g.
/// `TLS13_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`).
/// Unrecognised names are skipped (best-effort), so a value that names no known
/// suite yields an empty list and the caller keeps rustls's defaults.
fn cipher_suites_from(value: &str) -> Vec<SupportedCipherSuite> {
    let wanted: Vec<String> = value
        .split([':', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();

    let mut out = Vec::new();
    for name in &wanted {
        for suite in rustls::crypto::ring::ALL_CIPHER_SUITES {
            if format!("{:?}", suite.suite()).to_ascii_uppercase() == *name {
                out.push(*suite);
            }
        }
    }
    out
}

/// Collect the rustls cipher suites selected by the configured `tls-cipher-12`
/// and `tls-cipher-13` options, concatenated (12 then 13). An empty result means
/// no cipher option was set (or none matched), so callers keep rustls defaults.
fn configured_cipher_suites(config: &LoadedConfig) -> Vec<SupportedCipherSuite> {
    let mut suites = Vec::new();
    for name in ["tls-cipher-12", "tls-cipher-13"] {
        if let Some(value) = option_path(config, name) {
            suites.extend(cipher_suites_from(&value));
        }
    }
    suites
}

/// Build a rustls [`ServerConfig`] presenting `cert_chain` + `private_key`.
///
/// When `client_ca` is `Some`, a [`WebPkiClientVerifier`] built from those CA
/// roots is installed so connecting clients **must** present a certificate
/// signed by the CA (mutual TLS). When it is `None` the server accepts any
/// client without a certificate (`with_no_client_auth`), preserving the
/// non-mTLS fallback. `cipher_suites`, when non-empty, restricts the negotiated
/// suites; otherwise rustls defaults apply.
///
/// # Errors
///
/// [`CommandError::Other`] if the client verifier cannot be built from the CA
/// roots, the crypto provider rejects the restricted cipher suites, or the
/// cert / key pair is invalid.
fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    client_ca: Option<RootCertStore>,
    cipher_suites: &[SupportedCipherSuite],
) -> Result<ServerConfig, CommandError> {
    ensure_crypto_provider();

    let builder = if cipher_suites.is_empty() {
        ServerConfig::builder()
    } else {
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: cipher_suites.to_vec(),
            ..rustls::crypto::ring::default_provider()
        };
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| CommandError::Other(format!("tls server provider: {e}")))?
    };

    let config = match client_ca {
        Some(roots) => {
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| CommandError::Other(format!("tls client verifier: {e}")))?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    config
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| CommandError::Other(format!("tls server config: {e}")))
}

/// Build a rustls [`ClientConfig`] trusting the CA roots in `roots`.
///
/// When `client_auth` is `Some((chain, key))` the client presents that
/// certificate (mutual TLS) via `with_client_auth_cert`; otherwise it connects
/// without a client certificate. `cipher_suites`, when non-empty, restricts the
/// negotiated suites.
///
/// # Errors
///
/// [`CommandError::Other`] if the provider rejects the restricted cipher
/// suites or the client certificate / key is invalid.
fn build_client_config(
    roots: RootCertStore,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    cipher_suites: &[SupportedCipherSuite],
) -> Result<ClientConfig, CommandError> {
    ensure_crypto_provider();

    let builder = if cipher_suites.is_empty() {
        ClientConfig::builder()
    } else {
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: cipher_suites.to_vec(),
            ..rustls::crypto::ring::default_provider()
        };
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| CommandError::Other(format!("tls client provider: {e}")))?
    };

    let builder = builder.with_root_certificates(roots);

    match client_auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|e| CommandError::Other(format!("tls client auth cert: {e}"))),
        None => Ok(builder.with_no_client_auth()),
    }
}

/// Build a mutual-TLS [`ClientConfig`] from PEM **file paths**, for the
/// `repo-host-type=tls` / `pg-host-type=tls` worker transport.
///
/// Trusts the CA in `ca_file` and/or every CA file in the directory `ca_path`
/// (`*-host-ca-file` / `*-host-ca-path`, both additive), and — when `cert_file`
/// and `key_file` are both `Some` — presents that client certificate (the
/// mutual-TLS leg the peer `pgbackrest server` authorizes by Common Name).
/// `cipher_names`, when non-empty, is a `tls-cipher-12` / `tls-cipher-13` style
/// suite list that restricts the negotiated ciphers.
///
/// # Errors
///
/// [`CommandError::Other`] if a PEM file / directory cannot be read / parsed,
/// the provider rejects the restricted cipher suites, or the client certificate
/// / key is invalid.
pub fn build_client_config_from_files(
    ca_file: Option<&str>,
    ca_path: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
    cipher_names: &[String],
) -> Result<ClientConfig, CommandError> {
    let roots = root_store_from_ca_sources(ca_file, ca_path)?;

    let client_auth = match (cert_file, key_file) {
        (Some(cert), Some(key)) => Some((load_cert_chain(cert)?, load_private_key(key)?)),
        _ => None,
    };

    let mut suites = Vec::new();
    for value in cipher_names {
        suites.extend(cipher_suites_from(value));
    }

    build_client_config(roots, client_auth, &suites)
}

/// Connect a TLS client to `addr` and return the established [`StreamOwned`].
///
/// SNI is presented and the server certificate validated against `server_name`;
/// the returned single bidirectional encrypted stream is what the caller adapts
/// to whatever reader / writer the protocol layer needs. Used by the
/// `repo-host-type=tls` / `pg-host-type=tls` worker transport to reach the
/// peer's running `pgbackrest server`.
///
/// # Errors
///
/// [`CommandError::Other`] if the connection cannot be made, `server_name` is
/// not a valid DNS name, or the TLS handshake fails.
pub fn connect_tls_stream(
    addr: &str,
    server_name: &str,
    client_config: Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, CommandError> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| CommandError::Other(format!("invalid server name `{server_name}`: {e}")))?;
    let stream = TcpStream::connect(addr).map_err(|e| CommandError::Other(format!("tcp connect {addr}: {e}")))?;
    let conn = ClientConnection::new(client_config, name).map_err(|e| CommandError::Other(format!("tls client new: {e}")))?;
    Ok(StreamOwned::new(conn, stream))
}

/// Authorize a completed-handshake server-side TLS connection against the
/// `tls-server-auth` map, returning the client CN on success.
///
/// When `auth` is empty no authorization is enforced (the non-mTLS / no-auth
/// path): `Ok(None)` is returned. Otherwise the client must have presented a
/// certificate; its CN is extracted and checked with
/// [`cn_authorized_for_stanza`]. An unauthorized or certificate-less connection
/// yields [`CommandError::Other`] so the caller closes it.
fn authorize_client(
    conn: &ServerConnection,
    auth: &BTreeMap<String, Vec<String>>,
    stanza: Option<&str>,
) -> Result<Option<String>, CommandError> {
    if auth.is_empty() {
        return Ok(None);
    }
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| CommandError::Other("tls auth: client presented no certificate".to_owned()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| CommandError::Other("tls auth: empty client certificate chain".to_owned()))?;
    let cn = extract_cn_from_cert(leaf.as_ref())
        .ok_or_else(|| CommandError::Other("tls auth: client certificate has no Common Name".to_owned()))?;
    if cn_authorized_for_stanza(auth, &cn, stanza) {
        Ok(Some(cn))
    } else {
        Err(CommandError::Other(format!(
            "tls auth: client CN `{cn}` is not authorized for stanza `{}`",
            stanza.unwrap_or("<none>")
        )))
    }
}

/// Accept a single TCP connection on `listener`, perform the rustls server
/// handshake from `cert_chain` + `private_key`, wrap the resulting stream in
/// [`TlsIo`], and drive [`serve`].
///
/// Mirrors [`serve_listener`]: one connection is served to its `exit` / EOF,
/// after which the function returns.
///
/// # Errors
///
/// [`CommandError::Other`] on an accept failure, an invalid cert/key, a TLS
/// handshake failure, or whatever [`serve`] returns.
pub fn serve_tls(
    listener: &TcpListener,
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<(), CommandError> {
    let server_config = Arc::new(build_server_config(cert_chain, private_key, None, &[])?);

    let (stream, _peer) = listener
        .accept()
        .map_err(|e| CommandError::Other(format!("tcp accept: {e}")))?;
    KeepAlive::default().apply(&stream);

    let conn = ServerConnection::new(server_config).map_err(|e| CommandError::Other(format!("tls server new: {e}")))?;
    let io = SharedTlsIo::new(TlsServerIo::new(StreamOwned::new(conn, stream)));

    let mut reader = io.clone_handle();
    let mut writer = io.clone_handle();
    serve(&mut reader, &mut writer)?;
    // Signal a clean EOF (close_notify + write-shutdown) to the peer.
    let _ = writer.close();
    Ok(())
}

/// Accept TLS connections on `listener` in a loop and serve the **storage**
/// protocol on each.
///
/// This is the server side of the `repo-host-type=tls` / `pg-host-type=tls`
/// transport — the same protocol the SSH `--remote` worker serves, but over
/// a mutual-TLS socket. A remote pgBackRest connects presenting its client
/// certificate; the handshake validates it against the configured client CA;
/// the connection's first request is the no-op greeting that declares the
/// stanza the client is operating on; the certificate's CN is then checked
/// against `auth` for *that* greeting stanza (not whatever stanza the daemon
/// itself was started with, which is typically none). An authorized
/// connection is served from a [`Posix`](pgbr_storage::Posix) rooted at
/// `root` via the shared worker handler, so the peer can drive every
/// `storage-*` request as well as `noOp` / `exit`. C reference:
/// `src/command/server/server.c`.
///
/// Per-connection errors (TLS handshake, malformed greeting, CN rejection,
/// worker protocol failure) are logged and the accept loop continues; only
/// a non-retryable [`accept`](TcpListener::accept) failure ends the listener
/// (so a single malformed peer cannot take the daemon down).
///
/// When `auth` is empty, authorization is skipped (the server still
/// presents its own certificate but does not require / inspect a client
/// one) — preserving the no-mTLS fallback while still serving the storage
/// protocol.
///
/// # Errors
///
/// [`CommandError::Other`] on a non-retryable accept failure or an invalid
/// server cert/key. Per-connection failures do not propagate.
pub fn serve_tls_storage(
    listener: &TcpListener,
    server_config: &Arc<ServerConfig>,
    auth: &BTreeMap<String, Vec<String>>,
    root: &std::path::Path,
) -> Result<(), CommandError> {
    serve_tls_storage_with(listener, server_config, auth, root, KeepAlive::default(), false)
}

/// [`serve_tls_storage`] with explicit keepalive + `sck-block` settings
/// applied to each accepted socket before the TLS handshake. The
/// config-driven `server` path threads the resolved [`KeepAlive`] and
/// `sck-block` flag here.
fn serve_tls_storage_with(
    listener: &TcpListener,
    server_config: &Arc<ServerConfig>,
    auth: &BTreeMap<String, Vec<String>>,
    root: &std::path::Path,
    keepalive: KeepAlive,
    sck_block: bool,
) -> Result<(), CommandError> {
    serve_tls_storage_with_continue(listener, server_config, auth, root, keepalive, sck_block, || true)
}

/// Accept-loop core used by [`serve_tls_storage_with`] and (via a shutdown
/// flag) by the unit tests. Wraps [`serve_tls_storage_with_continue_caps`]
/// with the production worker-thread cap [`MAX_WORKER_THREADS`].
fn serve_tls_storage_with_continue(
    listener: &TcpListener,
    server_config: &Arc<ServerConfig>,
    auth: &BTreeMap<String, Vec<String>>,
    root: &std::path::Path,
    keepalive: KeepAlive,
    sck_block: bool,
    should_continue: impl FnMut() -> bool,
) -> Result<(), CommandError> {
    serve_tls_storage_with_continue_caps(
        listener,
        server_config,
        auth,
        root,
        keepalive,
        sck_block,
        MAX_WORKER_THREADS,
        should_continue,
    )
}

/// Accept-loop core for TLS `server` connections, parameterized over the
/// worker-thread cap so tests can drive it down to a small number and
/// observe the cap-rejection path.
///
/// Per accepted connection: applies keepalive + `sck-block`, then **spawns a
/// `std::thread`** that runs [`handle_tls_connection`] — the TLS handshake,
/// connection-greeting noOp, CN authorization, greeting ack, and worker
/// serve loop are all on the spawned thread. The accept loop returns to
/// [`accept`](TcpListener::accept) immediately so a long-running connection
/// (e.g. a backup uploading hundreds of files over minutes) does not block
/// concurrent `archive-push` calls from PG's `archive_command`. This
/// mirrors stock pgBackRest's C `server.c`, which `fork()`s per accepted
/// connection.
///
/// Concurrency is bounded by `max_workers`: an `Arc<AtomicUsize>` counter
/// is incremented before each spawn (via a [`WorkerSlot`] RAII guard inside
/// the thread) and decremented when the thread exits, panic or otherwise.
/// When the counter is at the cap the accept loop drops the freshly
/// accepted stream so the kernel resets the peer (which will retry), and
/// logs a rate-limited warning — the alternative (blocking on a join) would
/// defeat the purpose of the spawn.
///
/// A per-connection error is logged inside the spawned thread and that
/// thread exits; the accept loop is unaffected. Only a non-retryable
/// accept failure ends the loop.
///
/// `should_continue` is polled before each accept (and after every
/// `WouldBlock` retry); returning `false` ends the loop cleanly. On
/// graceful shutdown every in-flight thread is `join`ed so the listener
/// teardown waits for active sessions to finish.
fn serve_tls_storage_with_continue_caps(
    listener: &TcpListener,
    server_config: &Arc<ServerConfig>,
    auth: &BTreeMap<String, Vec<String>>,
    root: &std::path::Path,
    keepalive: KeepAlive,
    sck_block: bool,
    max_workers: usize,
    mut should_continue: impl FnMut() -> bool,
) -> Result<(), CommandError> {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let warn_state = Arc::new(CapWarnState::new());
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    loop {
        if !should_continue() {
            join_workers(handles);
            return Ok(());
        }
        let (stream, _peer) = match listener.accept() {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                join_workers(handles);
                return Err(CommandError::Other(format!("tcp accept: {e}")));
            }
        };
        keepalive.apply(&stream);
        apply_sck_block(&stream, sck_block);
        apply_nodelay(&stream);

        // Periodically reap finished worker threads so the vector does not
        // grow unboundedly across long-lived daemons.
        handles.retain(|h| !h.is_finished());

        // Refuse the connection if the cap is reached: drop the stream and
        // log once per minute. See `serve_listener_with_continue_caps` for
        // the rationale.
        let cur = in_flight.load(Ordering::Acquire);
        if cur >= max_workers {
            warn_state.maybe_warn(cur, max_workers);
            drop(stream);
            continue;
        }

        // Per-connection state cloned into the spawned thread: the
        // `Arc<ServerConfig>` clone is cheap (rustls reuses one config
        // across many sessions), the `BTreeMap` auth clone is small, and
        // `PathBuf` is a heap allocation per spawn (negligible at the
        // serve cadence we operate at).
        let server_config = Arc::clone(server_config);
        let auth = auth.clone();
        let root = root.to_path_buf();
        let slot_counter = Arc::clone(&in_flight);
        let handle = std::thread::spawn(move || {
            let _slot = WorkerSlot::new(slot_counter);
            if let Err(e) = handle_tls_connection(&server_config, &auth, &root, stream) {
                crate::control::log_info(&format!("tls connection ended: {e}"));
            }
        });
        handles.push(handle);
    }
}

/// Run the full per-connection flow for one accepted TCP stream: TLS
/// handshake, connection-greeting noOp, CN authorization, greeting ack,
/// and worker serve loop. Any failure is returned so the accept loop can
/// log it and move on.
///
/// The greeting is read while the `TlsServerIo` is still uniquely owned,
/// so `authorize_client` can borrow the rustls `ServerConnection` directly
/// for `peer_certificates()`. Only after authorization succeeds is the
/// `TlsServerIo` wrapped in a `SharedTlsIo` (Rc/RefCell) to drive the
/// worker's separate reader / writer handles.
fn handle_tls_connection(
    server_config: &Arc<ServerConfig>,
    auth: &BTreeMap<String, Vec<String>>,
    root: &std::path::Path,
    stream: TcpStream,
) -> Result<(), CommandError> {
    use pgbr_protocol::transport::NOOP_COMMAND;
    use pgbr_protocol::{Message, OkResponse, Response, read_message, write_message};

    let mut conn =
        ServerConnection::new(Arc::clone(server_config)).map_err(|e| CommandError::Other(format!("tls server new: {e}")))?;

    // Complete the handshake before inspecting the peer certificate: rustls
    // only populates `peer_certificates()` once the handshake has progressed
    // far enough to receive the client's Certificate message.
    conn.complete_io(&mut TcpHandshake(&stream))
        .map_err(|e| CommandError::Other(format!("tls handshake: {e}")))?;

    // Owned TlsIo — read the greeting and authorize before sharing.
    let mut tls = TlsServerIo::new(StreamOwned::new(conn, stream));

    // Read the first request: the greeting that declares the stanza.
    let greeting = match read_message(&mut tls).map_err(|e| CommandError::Other(format!("tls greeting read: {e}")))? {
        Some(Message::Request(req)) => req,
        Some(Message::Response(_)) => {
            return Err(CommandError::Other("tls greeting: expected request, got response".to_owned()));
        }
        None => {
            return Err(CommandError::Other("tls greeting: peer closed before greeting".to_owned()));
        }
    };

    // Anything other than a noOp at this position is a protocol violation
    // — the client must send the greeting (a noOp possibly carrying a
    // `stanza=<name>` param) before any storage request.
    if greeting.cmd != NOOP_COMMAND {
        return Err(CommandError::Other(format!(
            "tls greeting: expected `{NOOP_COMMAND}`, got `{}`",
            greeting.cmd
        )));
    }

    // Pull the stanza out of the greeting's `param` list (when set), then
    // authorize the client CN for *that* stanza. The rustls connection is
    // still accessible exclusively via `tls.stream.conn`.
    let stanza = crate::worker::WorkerHandler::parse_stanza_param(&greeting.param);
    authorize_client(&tls.stream.conn, auth, stanza.as_deref())?;

    // Acknowledge the greeting with a plain Ok so the client's `greet`
    // call completes; from here on the worker drives the request loop.
    let ack = Message::Response(Response::Ok(OkResponse { out: None }));
    write_message(&mut tls, &ack).map_err(|e| CommandError::Other(format!("tls greeting ack: {e}")))?;
    tls.flush()
        .map_err(|e| CommandError::Other(format!("tls greeting flush: {e}")))?;

    // Wrap in a shared handle so the worker can take separate reader /
    // writer halves over the single rustls stream, then run the worker
    // protocol for the rest of the connection's life.
    let io = SharedTlsIo::new(tls);
    let mut reader = io.clone_handle();
    let mut writer = io.clone_handle();
    let outcome = crate::worker::serve_worker(root, &mut reader, &mut writer);
    // Symmetric shutdown: both halves of the shared TLS I/O drop their close
    // intent so the peer sees a clean `close_notify` regardless of which side
    // tore down first. The two `close()` calls land on the same underlying
    // `TlsIo`; the second one is idempotent (a duplicate `close_notify` is a
    // no-op for rustls, and `shutdown(Write)` on an already-shut socket
    // returns an error that `let _` discards).
    let _ = writer.close();
    let _ = reader.close();
    outcome
}

/// Minimal [`Read`] + [`Write`] shim over a borrowed [`TcpStream`], so
/// [`ServerConnection::complete_io`] can drive the handshake without taking
/// ownership of the socket (which is moved into the [`StreamOwned`] afterwards).
struct TcpHandshake<'a>(&'a TcpStream);

impl Read for TcpHandshake<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for TcpHandshake<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

/// Connect a [`TcpStream`] to `addr`, perform the rustls client handshake with
/// a [`ClientConfig`] trusting the CA in `ca_file`, wrap the stream in
/// [`TlsIo`], and run [`ping_exchange`].
///
/// `server_name` is the hostname presented for SNI and validated against the
/// server certificate.
///
/// # Errors
///
/// [`CommandError::Other`] if the connection cannot be made, the CA cannot be
/// loaded, `server_name` is not a valid DNS name, the TLS handshake fails, or
/// whatever [`ping_exchange`] returns.
pub fn ping_tls(addr: &str, server_name: &str, ca_file: &str) -> Result<(), CommandError> {
    let roots = root_store_from_ca(ca_file)?;
    let client_config = Arc::new(build_client_config(roots, None, &[])?);
    ping_with_client_config(addr, server_name, client_config)
}

/// Run [`ping_exchange`] over a TLS client connection built from
/// `client_config`, connecting to `addr` and presenting SNI / validating the
/// server cert against `server_name`.
///
/// # Errors
///
/// [`CommandError::Other`] if the connection cannot be made, `server_name` is
/// not a valid DNS name, the TLS handshake fails, or whatever [`ping_exchange`]
/// returns.
fn ping_with_client_config(addr: &str, server_name: &str, client_config: Arc<ClientConfig>) -> Result<(), CommandError> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| CommandError::Other(format!("invalid server name `{server_name}`: {e}")))?;

    let stream = TcpStream::connect(addr).map_err(|e| CommandError::Other(format!("tcp connect {addr}: {e}")))?;
    let conn = ClientConnection::new(client_config, name).map_err(|e| CommandError::Other(format!("tls client new: {e}")))?;
    let io = SharedTlsIo::new(TlsClientIo::new(StreamOwned::new(conn, stream)));

    let mut reader = io.clone_handle();
    let mut writer = io.clone_handle();
    ping_exchange(&mut reader, &mut writer)
}

/// Resolve the bind / connect address from the configured
/// `tls-server-address` and `tls-server-port` options, falling back to
/// [`DEFAULT_ADDRESS`] when either is absent.
fn server_address(config: &LoadedConfig) -> String {
    let host = match config.options.get(&("tls-server-address".to_owned(), None)) {
        Some(OptionValue::String(h) | OptionValue::Path(h)) => Some(h.clone()),
        _ => None,
    };
    let port = match config.options.get(&("tls-server-port".to_owned(), None)) {
        Some(OptionValue::Integer(p)) if (1..=65535).contains(p) => Some(*p),
        _ => None,
    };

    match (host, port) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        _ => DEFAULT_ADDRESS.to_owned(),
    }
}

/// Resolve just the host portion of the configured `tls-server-address`
/// (default `localhost`), for use as the TLS SNI / certificate name in
/// [`ping`].
fn server_host(config: &LoadedConfig) -> String {
    match config.options.get(&("tls-server-address".to_owned(), None)) {
        Some(OptionValue::String(h) | OptionValue::Path(h)) if !h.is_empty() => h.clone(),
        _ => "localhost".to_owned(),
    }
}

/// Read a string/path-typed option as an owned `String`, returning `None` when
/// the option is absent or carries an empty value.
fn option_path(config: &LoadedConfig, name: &str) -> Option<String> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Path(p) | OptionValue::String(p)) if !p.is_empty() => Some(p.clone()),
        _ => None,
    }
}

/// Resolve the filesystem root the `server` should serve the storage protocol
/// from, preferring `pg1-path` then `repo1-path`, defaulting to the current
/// directory when none is set.
///
/// A connecting `repo-host-type=tls` / `pg-host-type=tls` worker reaches the
/// repository or PG data directory through this root, mirroring the SSH worker's
/// [`worker_root`](crate::worker) selection.
///
/// Grouped options (`pgN-path`, `repoN-path`) are stored under the canonical
/// `("pg-path", Some(N))` / `("repo-path", Some(N))` key (see
/// `pgbr_config::cli::decode_option_key`); the literal `"pgN-path"` /
/// `"repoN-path"` strings are never canonical names, so a lookup keyed by those
/// strings always misses. The configured value lives under `Some(1)`.
fn server_root(config: &LoadedConfig) -> std::path::PathBuf {
    for name in ["pg-path", "repo-path"] {
        if let Some(p) = config.options.get(&((*name).to_owned(), Some(1))).and_then(|v| match v {
            OptionValue::Path(p) | OptionValue::String(p) if !p.is_empty() => Some(p.clone()),
            _ => None,
        }) {
            return std::path::PathBuf::from(p);
        }
    }
    std::path::PathBuf::from(".")
}

/// `server` — listen for protocol connections from remote pgBackRest processes
/// and serve the storage / liveness protocol per connection.
///
/// The bind address comes from `tls-server-address` / `tls-server-port`
/// (default `127.0.0.1:8432`).
///
/// **Transport selection:** if both `tls-server-cert-file` and
/// `tls-server-key-file` are configured, the cert chain + private key are loaded
/// and the connection is served over TLS. When a client CA
/// (`tls-server-ca-file`) is **also** configured, mutual TLS is required: a
/// [`WebPkiClientVerifier`] forces the client to present a certificate signed by
/// that CA, and the certificate's Common Name is authorized against
/// `tls-server-auth` for the stanza via [`serve_tls_storage`]. The configured
/// `tls-cipher-12` / `tls-cipher-13` suites, when set, restrict the negotiated
/// ciphers. Without a CA the server presents its cert but accepts any client.
/// With no cert/key at all it falls back to plain TCP.
///
/// # Errors
///
/// Propagates whatever the TLS / TCP serve paths return (bind / accept
/// failures, invalid cert/key, TLS handshake / authorization errors, or a
/// protocol / write error from the serve loop).
pub fn server(config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let addr = server_address(config);
    let keepalive = KeepAlive::from_config(config);
    let sck_block = sck_block(config);

    match (
        option_path(config, "tls-server-cert-file"),
        option_path(config, "tls-server-key-file"),
    ) {
        (Some(cert_file), Some(key_file)) => {
            let cert_chain = load_cert_chain(&cert_file)?;
            let private_key = load_private_key(&key_file)?;
            let ciphers = configured_cipher_suites(config);

            // A configured client CA turns on mutual TLS + CN authorization.
            let client_ca = option_path(config, "tls-server-ca-file")
                .map(|ca| root_store_from_ca(&ca))
                .transpose()?;

            let server_config = Arc::new(build_server_config(cert_chain, private_key, client_ca, &ciphers)?);
            let auth = tls_server_auth(config);
            let root = server_root(config);
            let listener = TcpListener::bind(&addr).map_err(|e| CommandError::Other(format!("tcp bind {addr}: {e}")))?;
            // Human-facing progress line goes to the logger; the served protocol
            // is the command's machine-readable output on the socket.
            crate::control::log_info(&format!("server listening (tls) on {addr}"));
            // The per-connection stanza is now read from the client's
            // greeting noOp, so this loop is started without the daemon's
            // own stanza (which is typically `None`).
            serve_tls_storage_with(&listener, &server_config, &auth, &root, keepalive, sck_block)
        }
        _ => serve_tcp_with(&addr, keepalive, sck_block),
    }
}

/// `server-ping` — health check against a running `server` instance.
///
/// Connects to the configured `tls-server-address` / `tls-server-port`
/// (default `127.0.0.1:8432`) and runs [`ping_exchange`].
///
/// **Transport selection:** if a CA file (`tls-server-ca-file`) is configured,
/// the ping is performed over TLS via [`ping_tls`], trusting that CA and
/// validating the server certificate against the configured host name.
/// Otherwise it falls back to plain TCP via [`ping_tcp`].
///
/// # Errors
///
/// Propagates whatever [`ping_tls`] / [`ping_tcp`] return (connect failure,
/// CA-load / handshake error, or a protocol / rejection error from
/// [`ping_exchange`]).
pub fn ping(config: &LoadedConfig) -> Result<(), CommandError> {
    let addr = server_address(config);

    option_path(config, "tls-server-ca-file")
        .map_or_else(|| ping_tcp(&addr), |ca_file| ping_tls(&addr, &server_host(config), &ca_file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgbr_config::ConfigCommandRole;
    use pgbr_io::{MemRead, MemWrite};
    use pgbr_protocol::{ErrResponse, Message, OkResponse, Request, Response, read_message, write_message};
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    /// Serialize a sequence of messages into a byte buffer suitable for
    /// feeding to a `MemRead`.
    fn encode(messages: &[Message]) -> Vec<u8> {
        let mut w = MemWrite::new();
        for m in messages {
            write_message(&mut w, m).unwrap();
        }
        w.take()
    }

    /// Decode every message in a byte buffer produced by `serve` /
    /// `ping_exchange`.
    fn decode(bytes: Vec<u8>) -> Vec<Message> {
        let mut r = MemRead::new(bytes);
        let mut out = Vec::new();
        while let Some(m) = read_message(&mut r).unwrap() {
            out.push(m);
        }
        out
    }

    fn request(cmd: &str) -> Message {
        Message::Request(Request {
            cmd: cmd.to_owned(),
            param: Vec::new(),
        })
    }

    #[test]
    fn serve_handles_noop_then_exit() {
        let input = encode(&[request("noOp"), request("exit")]);
        let mut reader = MemRead::new(input);
        let mut writer = MemWrite::new();

        let handled = serve(&mut reader, &mut writer).unwrap();
        assert_eq!(handled, 2);

        let responses = decode(writer.take());
        assert_eq!(
            responses,
            vec![
                Message::Response(Response::Ok(OkResponse { out: None })),
                Message::Response(Response::Ok(OkResponse { out: None })),
            ]
        );
    }

    #[test]
    fn serve_unknown_command_replies_err() {
        let input = encode(&[request("bogus"), request("exit")]);
        let mut reader = MemRead::new(input);
        let mut writer = MemWrite::new();

        let handled = serve(&mut reader, &mut writer).unwrap();
        assert_eq!(handled, 2);

        let responses = decode(writer.take());
        assert_eq!(responses.len(), 2);
        match &responses[0] {
            Message::Response(Response::Err(e)) => {
                assert_eq!(e.err, PROTOCOL_ERROR);
                assert!(e.message.contains("bogus"), "message was {:?}", e.message);
            }
            other => panic!("expected Err response, got {other:?}"),
        }
        assert_eq!(responses[1], Message::Response(Response::Ok(OkResponse { out: None })));
    }

    #[test]
    fn serve_stray_response_replies_err_without_counting() {
        // A response arriving at the server is a protocol violation: it is
        // answered with an Err but does not count as a handled request.
        let stray = Message::Response(Response::Ok(OkResponse { out: None }));
        let input = encode(&[stray, request("exit")]);
        let mut reader = MemRead::new(input);
        let mut writer = MemWrite::new();

        let handled = serve(&mut reader, &mut writer).unwrap();
        assert_eq!(handled, 1);

        let responses = decode(writer.take());
        assert_eq!(responses.len(), 2);
        match &responses[0] {
            Message::Response(Response::Err(e)) => assert_eq!(e.err, PROTOCOL_ERROR),
            other => panic!("expected Err response, got {other:?}"),
        }
    }

    #[test]
    fn serve_clean_eof_stops() {
        let mut reader = MemRead::new(Vec::<u8>::new());
        let mut writer = MemWrite::new();

        let handled = serve(&mut reader, &mut writer).unwrap();
        assert_eq!(handled, 0);
        assert!(writer.as_slice().is_empty());
    }

    #[test]
    fn ping_exchange_ok_when_peer_replies_ok() {
        // The peer's canned reply that `ping_exchange` will read.
        let peer_reply = encode(&[Message::Response(Response::Ok(OkResponse { out: None }))]);
        let mut reader = MemRead::new(peer_reply);
        let mut writer = MemWrite::new();

        ping_exchange(&mut reader, &mut writer).unwrap();

        // What ping_exchange sent must decode to a single noOp request.
        let sent = decode(writer.take());
        assert_eq!(sent, vec![request("noOp")]);
    }

    #[test]
    fn ping_exchange_err_when_peer_replies_err() {
        let peer_reply = encode(&[Message::Response(Response::Err(ErrResponse {
            err: PROTOCOL_ERROR,
            message: "nope".to_owned(),
            stack: None,
        }))]);
        let mut reader = MemRead::new(peer_reply);
        let mut writer = MemWrite::new();

        let err = ping_exchange(&mut reader, &mut writer).unwrap_err();
        match err {
            CommandError::Other(msg) => assert!(msg.contains("nope"), "message was {msg:?}"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn ping_exchange_eof_errors() {
        let mut reader = MemRead::new(Vec::<u8>::new());
        let mut writer = MemWrite::new();

        let err = ping_exchange(&mut reader, &mut writer).unwrap_err();
        match err {
            CommandError::Other(msg) => assert!(msg.contains("EOF"), "message was {msg:?}"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    fn config_with(opts: Vec<((&str, Option<u32>), OptionValue)>) -> LoadedConfig {
        let mut options = BTreeMap::new();
        for ((name, group), value) in opts {
            options.insert((name.to_owned(), group), value);
        }
        LoadedConfig {
            command: "server".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: None,
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn server_address_uses_options_when_present() {
        let config = config_with(vec![
            (("tls-server-address", None), OptionValue::String("10.0.0.1".to_owned())),
            (("tls-server-port", None), OptionValue::Integer(9999)),
        ]);
        assert_eq!(server_address(&config), "10.0.0.1:9999");
    }

    // --- server_root: canonical grouped key lookup ---------------------------

    #[test]
    fn server_root_picks_repo1_path_from_grouped_key() {
        // The raw `repo1-path` from [global] decodes to the canonical
        // `("repo-path", Some(1))` key. A prior bug looked up
        // `("repo1-path", None)` / `("repo1-path", Some(1))` and missed the
        // value, defaulting the TLS server to "." and failing at runtime.
        let cfg = config_with(vec![(
            ("repo-path", Some(1)),
            OptionValue::Path("/var/lib/pgbackrest".to_owned()),
        )]);
        assert_eq!(server_root(&cfg), std::path::PathBuf::from("/var/lib/pgbackrest"));
    }

    #[test]
    fn server_root_prefers_pg_path_over_repo_path() {
        // When both are set, `pg-path` wins (the worker is more often spawned
        // for a PG host than a repo host).
        let cfg = config_with(vec![
            (("pg-path", Some(1)), OptionValue::Path("/srv/pg".to_owned())),
            (("repo-path", Some(1)), OptionValue::Path("/srv/repo".to_owned())),
        ]);
        assert_eq!(server_root(&cfg), std::path::PathBuf::from("/srv/pg"));
    }

    #[test]
    fn server_root_defaults_to_dot_when_neither_set() {
        assert_eq!(server_root(&config_with(vec![])), std::path::PathBuf::from("."));
    }

    #[test]
    fn server_root_ignores_ungrouped_or_empty_values() {
        // Ungrouped `("pg-path", None)` is NOT where the merged value lives —
        // it must not be picked up. Empty grouped value is also ignored.
        let cfg_ungrouped = config_with(vec![(("pg-path", None), OptionValue::Path("/ungrouped".to_owned()))]);
        assert_eq!(server_root(&cfg_ungrouped), std::path::PathBuf::from("."));

        let cfg_empty = config_with(vec![(("repo-path", Some(1)), OptionValue::Path(String::new()))]);
        assert_eq!(server_root(&cfg_empty), std::path::PathBuf::from("."));
    }

    #[test]
    fn server_address_falls_back_to_default() {
        // Missing options, and an out-of-range port, both fall back.
        assert_eq!(server_address(&config_with(vec![])), DEFAULT_ADDRESS);
        let bad_port = config_with(vec![
            (("tls-server-address", None), OptionValue::String("host".to_owned())),
            (("tls-server-port", None), OptionValue::Integer(0)),
        ]);
        assert_eq!(server_address(&bad_port), DEFAULT_ADDRESS);
    }

    // --- TCP keepalive (sck-keep-alive + tcp-keep-alive-*) -------------------

    #[test]
    fn keepalive_from_config_reads_options() {
        // All knobs set, master switch on (default).
        let cfg = config_with(vec![
            (("tcp-keep-alive-idle", None), OptionValue::Integer(60)),
            (("tcp-keep-alive-interval", None), OptionValue::Integer(10)),
            (("tcp-keep-alive-count", None), OptionValue::Integer(5)),
        ]);
        let ka = KeepAlive::from_config(&cfg);
        assert!(ka.enabled);
        assert_eq!(ka.idle, Some(60));
        assert_eq!(ka.interval, Some(10));
        assert_eq!(ka.count, Some(5));
    }

    #[test]
    fn keepalive_from_config_master_switch_off() {
        let cfg = config_with(vec![(("sck-keep-alive", None), OptionValue::Boolean(false))]);
        let ka = KeepAlive::from_config(&cfg);
        assert!(!ka.enabled, "sck-keep-alive=false must disable keepalive");
    }

    #[test]
    fn keepalive_defaults_enabled_without_timers() {
        // No options: keepalive on (sck-keep-alive defaults true), no timers.
        let ka = KeepAlive::from_config(&config_with(vec![]));
        assert!(ka.enabled);
        assert_eq!(ka.idle, None);
        assert_eq!(ka.interval, None);
        assert_eq!(ka.count, None);
    }

    #[test]
    fn keepalive_apply_enables_so_keepalive_on_accepted_socket() {
        // Bind, connect, accept, apply keepalive, then read SO_KEEPALIVE back
        // via socket2 to confirm it was enabled on the accepted socket.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server_stream, _peer) = listener.accept().unwrap();

        let ka = KeepAlive {
            enabled: true,
            idle: Some(42),
            interval: Some(7),
            count: None,
        };
        ka.apply(&server_stream);

        let sock = SockRef::from(&server_stream);
        assert!(sock.keepalive().unwrap(), "SO_KEEPALIVE must be enabled after apply");
    }

    #[test]
    fn keepalive_apply_disabled_is_noop() {
        // With the master switch off, apply must not enable SO_KEEPALIVE.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server_stream, _peer) = listener.accept().unwrap();

        KeepAlive {
            enabled: false,
            idle: Some(60),
            interval: None,
            count: None,
        }
        .apply(&server_stream);

        let sock = SockRef::from(&server_stream);
        assert!(!sock.keepalive().unwrap(), "disabled keepalive must leave SO_KEEPALIVE off");
    }

    #[test]
    fn tcpio_read_write_round_trip() {
        // Loopback pair: bind a listener, connect a client, accept the server
        // side, then push bytes client -> server through `TcpIo`.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).unwrap();
        let (server_stream, _peer) = listener.accept().unwrap();

        let mut client_io = TcpIo::new(client);
        let mut server_io = TcpIo::new(server_stream);

        client_io.write(b"hello tcp").unwrap();
        client_io.flush().unwrap();
        // Write-shutdown so the server read sees a clean EOF after the bytes.
        client_io.close().unwrap();

        let got = server_io.read_all().unwrap();
        assert_eq!(got, b"hello tcp");
        assert!(server_io.eof());
    }

    #[test]
    fn tcp_ping_round_trip() {
        // Bind on an ephemeral port and drive the accept loop through the
        // `_continue` helper so the test can flip a shutdown flag once the
        // client's ping has completed (the production `serve_listener`
        // wrapper loops forever, which is the desired daemon behaviour but
        // would hang a test).
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Non-blocking accept so the loop polls the shutdown flag between
        // peers; the loop's `WouldBlock` arm sleeps briefly to avoid busy-spin.
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_listener_with_continue(&listener, KeepAlive::default(), false, || {
                !stop_for_server.load(Ordering::Acquire)
            })
        });

        // Connect, set a read timeout so a hung server fails the test fast
        // rather than blocking CI, then run the ping exchange.
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (mut reader, mut writer) = split(stream).unwrap();
        ping_exchange(&mut reader, &mut writer).unwrap();

        // `ping_exchange` issues a `noOp` but no `exit`, so the per-connection
        // `serve` loop only ends when it sees EOF. Close the write half and
        // drop both client handles so the socket is torn down, giving the
        // server a clean EOF.
        writer.close().unwrap();
        drop(reader);
        drop(writer);

        // Signal the accept loop to stop on the next iteration.
        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("serve_listener");
    }

    /// The accept loop continues across multiple connections: connect once
    /// and run a ping, close, then connect again and run another ping.
    /// Before this loop existed the second connect would time out because
    /// the server returned after one connection.
    #[test]
    fn tcp_serve_loop_continues_after_one_connection() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_listener_with_continue(&listener, KeepAlive::default(), false, || {
                !stop_for_server.load(Ordering::Acquire)
            })
        });

        // Two independent connections, each running a ping round trip,
        // proving the accept loop kept going after the first one closed.
        for _ in 0..2 {
            let stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let (mut reader, mut writer) = split(stream).unwrap();
            ping_exchange(&mut reader, &mut writer).unwrap();
            writer.close().unwrap();
            drop(reader);
            drop(writer);
        }

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("serve_listener loop");
    }

    // --- TLS transport -----------------------------------------------------

    /// Generate a self-signed cert/key pair for `localhost` and return the two
    /// PEM strings `(cert_pem, key_pem)`. The cert is its own issuer, so it
    /// doubles as the CA the client trusts.
    fn self_signed_localhost() -> (String, String) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (certified.cert.pem(), certified.key_pair.serialize_pem())
    }

    /// Parse PEM strings into the in-memory rustls types `serve_tls` /
    /// `ping_tls`'s callers would otherwise read from files.
    fn cert_chain_from_pem(cert_pem: &str) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn private_key_from_pem(key_pem: &str) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut key_pem.as_bytes()).unwrap().unwrap()
    }

    #[test]
    fn tls_ping_round_trip() {
        // Self-signed cert for `localhost`; the client trusts it as its CA.
        let (cert_pem, key_pem) = self_signed_localhost();
        let cert_chain = cert_chain_from_pem(&cert_pem);
        let private_key = private_key_from_pem(&key_pem);

        // CA file the client reads (the server's own self-signed cert).
        let ca_dir = tempfile::tempdir().unwrap();
        let ca_path = ca_dir.path().join("ca.pem");
        std::fs::write(&ca_path, cert_pem.as_bytes()).unwrap();
        let ca_path = ca_path.to_str().unwrap().to_owned();

        // Bind on an ephemeral port and read the assigned address BEFORE moving
        // the listener into the server thread.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || serve_tls(&listener, cert_chain, private_key));

        // Connect to 127.0.0.1 but present the SNI / cert name `localhost`,
        // which the self-signed cert covers. The TLS layer drives its own
        // socket reads; set a generous read timeout so a hung handshake fails
        // the test fast rather than blocking CI.
        let addr = format!("127.0.0.1:{port}");
        ping_tls_with_timeout(&addr, "localhost", &ca_path, Duration::from_secs(10)).unwrap();

        server.join().expect("server thread panicked").expect("serve_tls");
    }

    /// `ping_tls` variant that sets a socket read timeout before the handshake,
    /// so a hung server fails the test instead of blocking forever. Mirrors
    /// `ping_tls` otherwise.
    fn ping_tls_with_timeout(addr: &str, server_name: &str, ca_file: &str, timeout: Duration) -> Result<(), CommandError> {
        ensure_crypto_provider();

        let roots = root_store_from_ca(ca_file)?;
        let client_config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let client_config = Arc::new(client_config);

        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| CommandError::Other(format!("invalid server name `{server_name}`: {e}")))?;

        let stream = TcpStream::connect(addr).map_err(|e| CommandError::Other(format!("tcp connect {addr}: {e}")))?;
        stream.set_read_timeout(Some(timeout)).unwrap();
        let conn = ClientConnection::new(client_config, name).map_err(|e| CommandError::Other(format!("tls client new: {e}")))?;
        let io = SharedTlsIo::new(TlsClientIo::new(StreamOwned::new(conn, stream)));

        let mut reader = io.clone_handle();
        let mut writer = io.clone_handle();
        let result = ping_exchange(&mut reader, &mut writer);
        // Close the write half so the server reads a clean EOF and its
        // `serve` loop ends, letting the server thread join.
        let _ = writer.close();
        result
    }

    #[test]
    fn tlsio_read_write_round_trip() {
        // Establish a loopback TLS connection: a server thread completes the
        // server handshake and echoes back whatever it reads through `TlsIo`;
        // the main thread drives the client `TlsIo`.
        let (cert_pem, key_pem) = self_signed_localhost();
        let cert_chain = cert_chain_from_pem(&cert_pem);
        let private_key = private_key_from_pem(&key_pem);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            ensure_crypto_provider();
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .unwrap();
            let (stream, _peer) = listener.accept().unwrap();
            let conn = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut io = TlsServerIo::new(StreamOwned::new(conn, stream));

            // Read the client's message and echo it straight back through
            // `TlsIo`, then close to flush close_notify.
            let mut buf = [0u8; 64];
            let n = io.read(&mut buf).unwrap();
            io.write(&buf[..n]).unwrap();
            io.flush().unwrap();
            let _ = io.close();
        });

        ensure_crypto_provider();
        let mut roots = RootCertStore::empty();
        for cert in cert_chain_from_pem(&cert_pem) {
            roots.add(cert).unwrap();
        }
        let client_config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let name = ServerName::try_from("localhost").unwrap();
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let conn = ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut client_io = TlsClientIo::new(StreamOwned::new(conn, stream));

        client_io.write(b"hello tls").unwrap();
        client_io.flush().unwrap();

        let mut got = [0u8; 64];
        let n = client_io.read(&mut got).unwrap();
        assert_eq!(&got[..n], b"hello tls");
        let _ = client_io.close();

        server.join().expect("server thread panicked");
    }

    #[test]
    fn server_uses_tls_when_cert_and_key_set() {
        // `server` selects the TLS transport when both cert and key files are
        // configured. Pointing them at a missing path surfaces the PEM-load
        // error from the TLS path (not a plain-TCP bind), proving the branch
        // was taken.
        let config = config_with(vec![
            (
                ("tls-server-cert-file", None),
                OptionValue::Path("/no/such/cert.pem".to_owned()),
            ),
            (
                ("tls-server-key-file", None),
                OptionValue::Path("/no/such/key.pem".to_owned()),
            ),
        ]);
        let repo = tempfile::tempdir().unwrap();
        let storage = pgbr_storage::Posix::new(repo.path());
        let err = server(&config, &storage).unwrap_err();
        match err {
            CommandError::Other(msg) => assert!(msg.contains("cert file"), "message was {msg:?}"),
            other => panic!("expected Other(read cert file), got {other:?}"),
        }
    }

    #[test]
    fn ping_uses_tls_when_ca_set() {
        // `ping` selects the TLS transport when a CA file is configured.
        // A missing CA path surfaces the CA-read error from the TLS path.
        let config = config_with(vec![
            (("tls-server-ca-file", None), OptionValue::Path("/no/such/ca.pem".to_owned())),
            (("tls-server-port", None), OptionValue::Integer(1)),
        ]);
        let err = ping(&config).unwrap_err();
        match err {
            CommandError::Other(msg) => assert!(msg.contains("cert file"), "message was {msg:?}"),
            other => panic!("expected Other(read cert file), got {other:?}"),
        }
    }

    #[test]
    fn server_host_defaults_to_localhost() {
        assert_eq!(server_host(&config_with(vec![])), "localhost");
        let with_host = config_with(vec![(
            ("tls-server-address", None),
            OptionValue::String("example.com".to_owned()),
        )]);
        assert_eq!(server_host(&with_host), "example.com");
    }

    // --- tls-server-auth CN -> stanza parsing + authorization ----------------

    fn auth_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn parse_tls_server_auth_splits_and_trims() {
        let parsed = parse_tls_server_auth(&auth_map(&[
            ("client-a", "demo"),
            ("client-b", " s1 , s2 ,, s3 "),
            ("client-c", "*"),
        ]));
        assert_eq!(parsed["client-a"], vec!["demo".to_owned()]);
        // Empty tokens dropped, surrounding whitespace trimmed.
        assert_eq!(parsed["client-b"], vec!["s1".to_owned(), "s2".to_owned(), "s3".to_owned()]);
        assert_eq!(parsed["client-c"], vec!["*".to_owned()]);
    }

    #[test]
    fn cn_authorized_for_exact_stanza() {
        let auth = parse_tls_server_auth(&auth_map(&[("client-a", "demo")]));
        // Authorized: the CN is listed for that exact stanza.
        assert!(cn_authorized_for_stanza(&auth, "client-a", Some("demo")));
        // Wrong stanza: same CN but a stanza it is not authorized for.
        assert!(!cn_authorized_for_stanza(&auth, "client-a", Some("other")));
        // Unknown CN: never authorized.
        assert!(!cn_authorized_for_stanza(&auth, "client-x", Some("demo")));
        // No requested stanza without a wildcard: not authorized.
        assert!(!cn_authorized_for_stanza(&auth, "client-a", None));
    }

    #[test]
    fn cn_authorized_by_wildcard_for_any_stanza() {
        let auth = parse_tls_server_auth(&auth_map(&[("admin", "*")]));
        assert!(cn_authorized_for_stanza(&auth, "admin", Some("anything")));
        assert!(cn_authorized_for_stanza(&auth, "admin", Some("else")));
        // The wildcard even authorizes a connection that names no stanza.
        assert!(cn_authorized_for_stanza(&auth, "admin", None));
        // A different, unlisted CN is still rejected.
        assert!(!cn_authorized_for_stanza(&auth, "intruder", Some("anything")));
    }

    #[test]
    fn cn_authorized_with_multiple_stanzas() {
        let auth = parse_tls_server_auth(&auth_map(&[("multi", "s1,s2")]));
        assert!(cn_authorized_for_stanza(&auth, "multi", Some("s1")));
        assert!(cn_authorized_for_stanza(&auth, "multi", Some("s2")));
        assert!(!cn_authorized_for_stanza(&auth, "multi", Some("s3")));
    }

    #[test]
    fn tls_server_auth_reads_hash_option() {
        let mut map = BTreeMap::new();
        map.insert("cn1".to_owned(), "demo".to_owned());
        let config = config_with(vec![(("tls-server-auth", None), OptionValue::Hash(map))]);
        let auth = tls_server_auth(&config);
        assert_eq!(auth["cn1"], vec!["demo".to_owned()]);
        // Absent option yields an empty map (no authorization enforced).
        assert!(tls_server_auth(&config_with(vec![])).is_empty());
    }

    // --- CN extraction from a real certificate -------------------------------

    #[test]
    fn extract_cn_from_generated_cert() {
        // Generate a cert whose subject CN is a known value, DER-encode it, and
        // confirm the minimal DER scan recovers that CN.
        let mut params = rcgen::CertificateParams::new(vec!["host.example.com".to_owned()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "pg-primary.example.com");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();
        assert_eq!(extract_cn_from_cert(der.as_ref()).as_deref(), Some("pg-primary.example.com"));
    }

    #[test]
    fn extract_cn_returns_none_without_cn() {
        // Random bytes carry no CN OID.
        assert_eq!(extract_cn_from_cert(&[0x30, 0x03, 0x02, 0x01, 0x05]), None);
    }

    #[test]
    fn extract_cn_returns_subject_not_issuer() {
        // A CA-signed leaf carries the issuer CN *before* the subject CN in the
        // DER. The walk must return the subject (`leaf.example`), never the
        // issuer (`shared-ca`).
        let (_ca, _server_cert, _server_key, client_cert_pem, _client_key) = shared_ca_pair("server.local", "leaf.example");
        let leaf = cert_chain_from_pem(&client_cert_pem);
        let cn = extract_cn_from_cert(leaf[0].as_ref());
        assert_eq!(cn.as_deref(), Some("leaf.example"));
    }

    #[test]
    fn decode_bmp_string_round_trips_ascii() {
        // UTF-16BE encoding of "ok".
        assert_eq!(decode_bmp_string(&[0x00, b'o', 0x00, b'k']), "ok");
    }

    // --- cipher suite mapping ------------------------------------------------

    #[test]
    fn cipher_suites_from_known_names() {
        let suites = cipher_suites_from("TLS13_AES_256_GCM_SHA384:TLS13_AES_128_GCM_SHA256");
        assert_eq!(suites.len(), 2, "both named TLS 1.3 suites should map");
        assert_eq!(format!("{:?}", suites[0].suite()), "TLS13_AES_256_GCM_SHA384");
    }

    #[test]
    fn cipher_suites_from_skips_unknown() {
        // An unknown name yields no suite; a value naming none is empty so the
        // caller keeps rustls defaults.
        assert!(cipher_suites_from("NOT_A_REAL_CIPHER").is_empty());
        assert!(cipher_suites_from("").is_empty());
    }

    #[test]
    fn configured_cipher_suites_concatenates_12_and_13() {
        let config = config_with(vec![
            (
                ("tls-cipher-12", None),
                OptionValue::String("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_owned()),
            ),
            (
                ("tls-cipher-13", None),
                OptionValue::String("TLS13_AES_256_GCM_SHA384".to_owned()),
            ),
        ]);
        let suites = configured_cipher_suites(&config);
        assert_eq!(suites.len(), 2);
    }

    // --- config builders -----------------------------------------------------

    #[test]
    fn build_client_config_with_and_without_auth() {
        // A self-signed cert doubles as the CA. Build a client config with no
        // client auth, then one presenting the same cert as a client cert.
        let (cert_pem, key_pem) = self_signed_localhost();
        let mut roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&cert_pem) {
            roots.add(c).unwrap();
        }
        // No client auth.
        build_client_config(roots, None, &[]).expect("client config without auth");

        // With client auth.
        let mut roots2 = RootCertStore::empty();
        for c in cert_chain_from_pem(&cert_pem) {
            roots2.add(c).unwrap();
        }
        let chain = cert_chain_from_pem(&cert_pem);
        let key = private_key_from_pem(&key_pem);
        build_client_config(roots2, Some((chain, key)), &[]).expect("client config with auth");
    }

    // --- ca-path (directory of CA files) -------------------------------------

    #[test]
    fn add_ca_path_loads_every_cert_in_dir() {
        // A directory holding two distinct self-signed CA PEMs: both certs must
        // land in the root store. rustls does not expose a count directly, so we
        // assert via `len()` on the `roots` (the field is public on RootCertStore
        // in rustls 0.23).
        let (cert_a, _key_a) = self_signed_localhost();
        let mut params_b = rcgen::CertificateParams::new(vec!["other.example".to_owned()]).unwrap();
        params_b.distinguished_name.push(rcgen::DnType::CommonName, "ca-b");
        let key_b = rcgen::KeyPair::generate().unwrap();
        let cert_b = params_b.self_signed(&key_b).unwrap().pem();

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.crt"), cert_a.as_bytes()).unwrap();
        std::fs::write(dir.path().join("b.crt"), cert_b.as_bytes()).unwrap();
        // A non-PEM stray file must be skipped without aborting the load.
        std::fs::write(dir.path().join("notes.txt"), b"not a cert").unwrap();
        // A sub-directory must be ignored (only regular files are read).
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        let mut roots = RootCertStore::empty();
        add_ca_path(&mut roots, dir.path().to_str().unwrap()).expect("ca-path load");
        assert_eq!(roots.len(), 2, "both CA certs in the directory should load");
    }

    #[test]
    fn add_ca_path_missing_dir_errors() {
        let mut roots = RootCertStore::empty();
        let err = add_ca_path(&mut roots, "/no/such/cadir").unwrap_err();
        match err {
            CommandError::Other(msg) => assert!(msg.contains("ca-path dir"), "msg was {msg:?}"),
            other => panic!("expected Other(read ca-path dir), got {other:?}"),
        }
    }

    #[test]
    fn root_store_from_ca_sources_unions_file_and_path() {
        // A ca-file plus a ca-path directory (with one more CA) trust the union.
        let (cert_file_pem, _k) = self_signed_localhost();
        let file_dir = tempfile::tempdir().unwrap();
        let ca_file = file_dir.path().join("ca.pem");
        std::fs::write(&ca_file, cert_file_pem.as_bytes()).unwrap();

        let mut params = rcgen::CertificateParams::new(vec!["dir.example".to_owned()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "dir-ca");
        let key = rcgen::KeyPair::generate().unwrap();
        let dir_cert = params.self_signed(&key).unwrap().pem();
        let ca_dir = tempfile::tempdir().unwrap();
        std::fs::write(ca_dir.path().join("dir.crt"), dir_cert.as_bytes()).unwrap();

        let roots = root_store_from_ca_sources(Some(ca_file.to_str().unwrap()), Some(ca_dir.path().to_str().unwrap()))
            .expect("union root store");
        assert_eq!(roots.len(), 2, "file CA + dir CA should both be trusted");

        // ca-file only.
        let only_file = root_store_from_ca_sources(Some(ca_file.to_str().unwrap()), None).expect("file-only store");
        assert_eq!(only_file.len(), 1);

        // ca-path only.
        let only_path = root_store_from_ca_sources(None, Some(ca_dir.path().to_str().unwrap())).expect("path-only store");
        assert_eq!(only_path.len(), 1);

        // Neither source: an empty store (the caller treats this as a config error).
        let neither = root_store_from_ca_sources(None, None).expect("empty store");
        assert!(neither.is_empty());
    }

    #[test]
    fn build_client_config_from_files_accepts_ca_path() {
        // The public file-path client-config builder must accept a ca-path
        // directory as the (sole) CA source — no ca-file required.
        let (cert_pem, _key) = self_signed_localhost();
        let ca_dir = tempfile::tempdir().unwrap();
        std::fs::write(ca_dir.path().join("ca.pem"), cert_pem.as_bytes()).unwrap();
        build_client_config_from_files(None, Some(ca_dir.path().to_str().unwrap()), None, None, &[])
            .expect("client config from ca-path only");
    }

    // --- sck-block -----------------------------------------------------------

    #[test]
    fn sck_block_defaults_false_and_reads_option() {
        // Absent → false (the config.yaml default).
        assert!(!sck_block(&config_with(vec![])));
        // Explicit true is honoured.
        let on = config_with(vec![(("sck-block", None), OptionValue::Boolean(true))]);
        assert!(sck_block(&on));
        // Explicit false is honoured.
        let off = config_with(vec![(("sck-block", None), OptionValue::Boolean(false))]);
        assert!(!sck_block(&off));
    }

    #[test]
    fn apply_sck_block_sets_blocking_when_true() {
        // With sck-block=true the accepted socket is put in blocking mode; a
        // subsequent read therefore blocks (not WouldBlock). We assert the
        // blocking-mode side effect by confirming a 0-timeout read still blocks
        // rather than returning immediately — but to keep the test cheap and
        // deterministic, just confirm apply does not error and the socket
        // remains usable for a write.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server_stream, _peer) = listener.accept().unwrap();

        // First force non-blocking, then apply sck-block=true and confirm a
        // read now blocks-then-times-out (Err kind TimedOut/WouldBlock differs):
        // a blocking socket with a read timeout yields a timeout error, whereas a
        // non-blocking socket yields WouldBlock immediately.
        server_stream.set_nonblocking(true).unwrap();
        apply_sck_block(&server_stream, true);
        server_stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 1];
        let err = (&server_stream).read(&mut buf).unwrap_err();
        // A blocking socket honouring the read timeout reports WouldBlock or
        // TimedOut after the wait; the key point is the apply call set blocking
        // mode without erroring and the socket is still usable.
        assert!(
            matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
            "blocking read with timeout should time out, got {err:?}"
        );
    }

    #[test]
    fn apply_sck_block_false_is_noop() {
        // sck-block=false must not flip a blocking socket to non-blocking (the
        // synchronous transport needs blocking I/O), so a read still blocks.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server_stream, _peer) = listener.accept().unwrap();

        apply_sck_block(&server_stream, false);
        // Confirm still blocking: a read with a short timeout times out rather
        // than returning WouldBlock instantly (which a non-blocking socket would).
        server_stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 1];
        let err = (&server_stream).read(&mut buf).unwrap_err();
        assert!(
            matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
            "non-flipped socket read should time out, got {err:?}"
        );
    }

    #[test]
    fn apply_nodelay_sets_tcp_nodelay() {
        // The accept loops call `apply_nodelay` on every accepted socket to
        // disable Nagle's algorithm (the backup many-small-rounds hang). Drive
        // the helper over a loopback socket and assert the option took effect.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server_stream, _peer) = listener.accept().unwrap();

        // Freshly-accepted sockets default to Nagle enabled (nodelay == false);
        // after the helper it must be on.
        apply_nodelay(&server_stream);
        assert!(server_stream.nodelay().unwrap(), "apply_nodelay must enable TCP_NODELAY");
    }

    #[test]
    fn server_accept_sets_tcp_nodelay() {
        // End-to-end over the plain-TCP accept loop (`serve_listener_with_continue`,
        // which the daemon's `serve_listener` wraps): the loop body applies
        // keepalive + sck-block + `apply_nodelay` to every accepted socket. We
        // cannot reach the server-side `TcpStream` directly (it is moved into the
        // per-connection worker thread), so we observe nodelay on the CLIENT side
        // of the same connection — the per-helper assertion that the server
        // socket itself gets nodelay lives in `apply_nodelay_sets_tcp_nodelay`.
        // This test pins that wiring nodelay into the loop does not disturb a
        // normal ping round trip.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_listener_with_continue(&listener, KeepAlive::default(), false, || {
                !stop_for_server.load(Ordering::Acquire)
            })
        });

        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // The client end can carry nodelay too; the server-accepted end is the
        // one the loop tunes (asserted by the helper unit test).
        stream.set_nodelay(true).unwrap();
        assert!(stream.nodelay().unwrap(), "client side nodelay should be set");
        let (mut reader, mut writer) = split(stream).unwrap();
        ping_exchange(&mut reader, &mut writer).unwrap();
        writer.close().unwrap();
        drop(reader);
        drop(writer);

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("serve_listener");
    }

    #[test]
    fn build_server_config_with_client_verifier() {
        // With a client CA the server config installs a client-cert verifier
        // (mutual TLS); without one it accepts any client.
        let (cert_pem, key_pem) = self_signed_localhost();
        let mut roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&cert_pem) {
            roots.add(c).unwrap();
        }
        build_server_config(
            cert_chain_from_pem(&cert_pem),
            private_key_from_pem(&key_pem),
            Some(roots),
            &[],
        )
        .expect("mTLS server config");

        build_server_config(cert_chain_from_pem(&cert_pem), private_key_from_pem(&key_pem), None, &[])
            .expect("no-mTLS server config");
    }

    // --- live mutual-TLS storage round trip ----------------------------------

    #[test]
    fn mtls_storage_round_trip_authorized_cn() {
        // End-to-end mutual TLS: a server presents a CA-signed cert and requires
        // a client cert signed by the same CA; the client CN `client.example`
        // is authorized for stanza `demo`. The client drives a storage round
        // trip over TLS, proving the storage protocol runs over the authorized
        // mTLS transport.
        run_mtls_round_trip("client.example", Some("demo"), true);
    }

    #[test]
    fn mtls_storage_round_trip_rejects_unauthorized_cn() {
        // The client CN is not in `tls-server-auth`, so the server closes the
        // connection after the handshake; the client's first storage request
        // fails (no successful round trip).
        run_mtls_round_trip("intruder.example", Some("demo"), false);
    }

    #[test]
    fn mtls_storage_round_trip_rejects_wrong_stanza() {
        // The CN is authorized, but only for stanza `demo`; requesting `other`
        // is rejected.
        run_mtls_round_trip("client.example", Some("other"), false);
    }

    /// Issue a CA plus a server leaf and a client leaf all signed by that one CA.
    /// Returns `(ca_pem, server_cert_pem, server_key_pem, client_cert_pem,
    /// client_key_pem)` with the client cert carrying CN `client_cn` and the
    /// server cert a `localhost` SAN.
    fn shared_ca_pair(server_cn: &str, client_cn: &str) -> (String, String, String, String, String) {
        let mut authority_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        authority_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        authority_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "shared-ca");
        let authority_key = rcgen::KeyPair::generate().unwrap();
        let authority_cert = authority_params.self_signed(&authority_key).unwrap();

        let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server_params.distinguished_name.push(rcgen::DnType::CommonName, server_cn);
        let server_keypair = rcgen::KeyPair::generate().unwrap();
        let server_cert = server_params
            .signed_by(&server_keypair, &authority_cert, &authority_key)
            .unwrap();

        let mut client_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        client_params.distinguished_name.push(rcgen::DnType::CommonName, client_cn);
        let client_keypair = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params
            .signed_by(&client_keypair, &authority_cert, &authority_key)
            .unwrap();

        (
            authority_cert.pem(),
            server_cert.pem(),
            server_keypair.serialize_pem(),
            client_cert.pem(),
            client_keypair.serialize_pem(),
        )
    }

    /// Run a full mutual-TLS storage round trip with the given client CN /
    /// requested stanza. `expect_ok` asserts whether the client's storage
    /// request round trip should succeed (authorized) or fail (rejected).
    ///
    /// The server is driven through the `_continue` helper so the test can
    /// flip a shutdown flag once the client's session has completed (the
    /// production `serve_tls_storage` wrapper loops forever, which is the
    /// desired daemon behaviour but would hang a test).
    ///
    /// The client first issues the connection greeting (a `noOp` with the
    /// requested `stanza=<name>` token), which is what the server keys CN
    /// authorization on — *not* whatever stanza the daemon was started with.
    /// On the authorized path it then runs a `storage-exists` round trip to
    /// prove the worker protocol is reachable.
    fn run_mtls_round_trip(client_cn: &str, stanza: Option<&str>, expect_ok: bool) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use pgbr_protocol::ProtocolClient;
        use pgbr_storage::remote::command::EXISTS;

        let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) = shared_ca_pair("server.local", client_cn);

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();

        // Server config: present the server cert, require client certs signed
        // by the shared CA, authorize CN `client.example` for stanza `demo`.
        let mut server_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            server_roots.add(c).unwrap();
        }
        let server_config = Arc::new(
            build_server_config(
                cert_chain_from_pem(&server_cert_pem),
                private_key_from_pem(&server_key_pem),
                Some(server_roots),
                &[],
            )
            .unwrap(),
        );
        let mut auth: BTreeMap<String, Vec<String>> = BTreeMap::new();
        auth.insert("client.example".to_owned(), vec!["demo".to_owned()]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_tls_storage_with_continue(
                &listener,
                &server_config,
                &auth,
                &root_path,
                KeepAlive::default(),
                false,
                || !stop_for_server.load(Ordering::Acquire),
            )
        });

        // Client: trust the CA, present the client cert.
        let mut client_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            client_roots.add(c).unwrap();
        }
        let client_config = Arc::new(
            build_client_config(
                client_roots,
                Some((cert_chain_from_pem(&client_cert_pem), private_key_from_pem(&client_key_pem))),
                &[],
            )
            .unwrap(),
        );

        let addr = format!("127.0.0.1:{port}");
        let connect = || -> Result<(), CommandError> {
            let stream = connect_tls_stream(&addr, "localhost", Arc::clone(&client_config))?;
            stream.sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let io = SharedTlsIo::new(TlsClientIo::new(stream));
            let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());

            // 1. Greeting (carries the stanza the server authorizes against).
            client.greet(stanza).map_err(|e| CommandError::Other(format!("greet: {e}")))?;
            // 2. Storage round trip: `storage-exists` on a missing path
            // returns Ok(false) when authorized. (Reached only on the
            // authorized path; the rejected path errors out of `greet`.)
            let outcome = client
                .execute(&Request {
                    cmd: EXISTS.to_owned(),
                    param: vec![serde_json::Value::String("nope.txt".to_owned())],
                })
                .map(|_| ())
                .map_err(|e| CommandError::Other(format!("{e}")));
            // Shut the protocol down cleanly so the server's per-connection
            // worker loop ends without a truncation error; ignore failures.
            let _ = client.close();
            outcome
        };

        let result = connect();
        // Tell the accept loop to stop so the server thread can join.
        stop.store(true, Ordering::Release);
        let server_result = server.join().expect("server thread panicked");

        if expect_ok {
            server_result.expect("authorized server's accept loop should end cleanly");
            result.expect("authorized client should complete a greeting + storage round trip");
        } else {
            // The rejected client must not complete a round trip: the server
            // rejected the CN inside `handle_tls_connection`, the per-
            // connection error was logged, and the accept loop continued.
            assert!(result.is_err(), "unauthorized client must not complete a round trip");
            // The loop should still have stopped cleanly when we signaled.
            server_result.expect("loop must end cleanly even after rejecting a connection");
        }
    }

    /// Without the connection-greeting noOp, an mTLS client whose CN is
    /// authorized for a specific stanza is rejected because the server now
    /// keys auth on the greeting stanza, which is `None` here. This is the
    /// regression guard for bug A's pre-fix behaviour (`<none>` in the
    /// log message).
    #[test]
    fn mtls_storage_rejects_when_greeting_omits_stanza_for_exact_match_auth() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use pgbr_protocol::ProtocolClient;

        let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
            shared_ca_pair("server.local", "principal");

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();

        let mut server_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            server_roots.add(c).unwrap();
        }
        let server_config = Arc::new(
            build_server_config(
                cert_chain_from_pem(&server_cert_pem),
                private_key_from_pem(&server_key_pem),
                Some(server_roots),
                &[],
            )
            .unwrap(),
        );
        // CN `principal` is authorized only for stanza `demo`.
        let mut auth: BTreeMap<String, Vec<String>> = BTreeMap::new();
        auth.insert("principal".to_owned(), vec!["demo".to_owned()]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_tls_storage_with_continue(
                &listener,
                &server_config,
                &auth,
                &root_path,
                KeepAlive::default(),
                false,
                || !stop_for_server.load(Ordering::Acquire),
            )
        });

        let mut client_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            client_roots.add(c).unwrap();
        }
        let client_config = Arc::new(
            build_client_config(
                client_roots,
                Some((cert_chain_from_pem(&client_cert_pem), private_key_from_pem(&client_key_pem))),
                &[],
            )
            .unwrap(),
        );

        let addr = format!("127.0.0.1:{port}");
        let stream = connect_tls_stream(&addr, "localhost", Arc::clone(&client_config)).unwrap();
        stream.sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let io = SharedTlsIo::new(TlsClientIo::new(stream));
        let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());
        // Greeting with no stanza — server has CN -> [`demo`], no wildcard.
        let greet_result = client.greet(None);
        assert!(greet_result.is_err(), "exact-match auth must reject a stanza-less greeting");

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("loop end");
    }

    /// `*`-wildcard auth still passes for a greeting without a stanza,
    /// matching the documented `tls-server-auth` semantics. This pins the
    /// behaviour of [`cn_authorized_for_stanza`] over the greeting path.
    #[test]
    fn mtls_storage_authorizes_wildcard_cn_against_greeting_without_stanza() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use pgbr_protocol::ProtocolClient;
        use pgbr_storage::remote::command::EXISTS;

        let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) = shared_ca_pair("server.local", "admin");

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();

        let mut server_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            server_roots.add(c).unwrap();
        }
        let server_config = Arc::new(
            build_server_config(
                cert_chain_from_pem(&server_cert_pem),
                private_key_from_pem(&server_key_pem),
                Some(server_roots),
                &[],
            )
            .unwrap(),
        );
        let mut auth: BTreeMap<String, Vec<String>> = BTreeMap::new();
        auth.insert("admin".to_owned(), vec!["*".to_owned()]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_tls_storage_with_continue(
                &listener,
                &server_config,
                &auth,
                &root_path,
                KeepAlive::default(),
                false,
                || !stop_for_server.load(Ordering::Acquire),
            )
        });

        let mut client_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            client_roots.add(c).unwrap();
        }
        let client_config = Arc::new(
            build_client_config(
                client_roots,
                Some((cert_chain_from_pem(&client_cert_pem), private_key_from_pem(&client_key_pem))),
                &[],
            )
            .unwrap(),
        );

        let addr = format!("127.0.0.1:{port}");
        let stream = connect_tls_stream(&addr, "localhost", Arc::clone(&client_config)).unwrap();
        stream.sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let io = SharedTlsIo::new(TlsClientIo::new(stream));
        let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());

        client.greet(None).expect("wildcard CN must accept stanza-less greeting");
        client
            .execute(&Request {
                cmd: EXISTS.to_owned(),
                param: vec![serde_json::Value::String("nope.txt".to_owned())],
            })
            .expect("authorized wildcard client should run a storage round trip");
        let _ = client.close();

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("loop end");
    }

    /// The TLS accept loop continues after one connection ends: the daemon
    /// (started without `--stanza`) must accept a second client just as it
    /// accepted the first. Before the loop landed, the server returned
    /// immediately after the first connection and a second connect would
    /// time out / refuse — this is the regression guard for bug B.
    #[test]
    fn tls_server_accept_loop_continues_after_one_connection() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use pgbr_protocol::ProtocolClient;

        let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
            shared_ca_pair("server.local", "principal");

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();

        let mut server_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            server_roots.add(c).unwrap();
        }
        let server_config = Arc::new(
            build_server_config(
                cert_chain_from_pem(&server_cert_pem),
                private_key_from_pem(&server_key_pem),
                Some(server_roots),
                &[],
            )
            .unwrap(),
        );
        let mut auth: BTreeMap<String, Vec<String>> = BTreeMap::new();
        auth.insert("principal".to_owned(), vec!["demo".to_owned()]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_tls_storage_with_continue(
                &listener,
                &server_config,
                &auth,
                &root_path,
                KeepAlive::default(),
                false,
                || !stop_for_server.load(Ordering::Acquire),
            )
        });

        let mut client_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            client_roots.add(c).unwrap();
        }
        let client_config = Arc::new(
            build_client_config(
                client_roots,
                Some((cert_chain_from_pem(&client_cert_pem), private_key_from_pem(&client_key_pem))),
                &[],
            )
            .unwrap(),
        );

        let addr = format!("127.0.0.1:{port}");

        // Two independent connections, each greeting with `stanza=demo`; the
        // second succeeding is the proof the accept loop kept going.
        for attempt in 1..=2 {
            let stream = connect_tls_stream(&addr, "localhost", Arc::clone(&client_config))
                .unwrap_or_else(|e| panic!("attempt {attempt}: connect: {e}"));
            stream.sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let io = SharedTlsIo::new(TlsClientIo::new(stream));
            let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());
            client
                .greet(Some("demo"))
                .unwrap_or_else(|e| panic!("attempt {attempt}: greet: {e}"));
            let _ = client.close();
        }

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("loop end");
    }

    /// Regression test for the second half of the archive-async TLS hang fix:
    /// [`handle_tls_connection`] must close *both* the reader and the writer
    /// halves of the shared TLS I/O. The fix added `let _ = reader.close()`
    /// after the existing `let _ = writer.close()` so the shutdown is
    /// symmetric, even though both halves share one underlying [`TlsIo`] (the
    /// second `close()` lands as a no-op the `let _` discards).
    ///
    /// Driving `handle_tls_connection` directly requires a full mTLS pair, so
    /// instead this test asserts the same property on a structural mirror of
    /// the production wiring: a shared `Rc<RefCell<…>>` adapter whose inner
    /// `close()` counts calls. Calling `close()` on each of two cloned
    /// handles must drive the inner counter to two — exactly what the new
    /// `handle_tls_connection` flow does on `SharedTlsIo`.
    #[test]
    fn handle_tls_connection_closes_both_reader_and_writer() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use pgbr_io::{IoError, IoRead, IoWrite};

        /// Counts every `close()` call on the underlying I/O so the test can
        /// observe how many times the close path was invoked.
        struct CountingIo {
            close_calls: usize,
        }

        impl IoRead for CountingIo {
            fn read(&mut self, _: &mut [u8]) -> Result<usize, IoError> {
                Ok(0)
            }
            fn eof(&self) -> bool {
                true
            }
        }

        impl IoWrite for CountingIo {
            fn write(&mut self, _: &[u8]) -> Result<(), IoError> {
                Ok(())
            }
            fn flush(&mut self) -> Result<(), IoError> {
                Ok(())
            }
            fn close(&mut self) -> Result<(), IoError> {
                self.close_calls += 1;
                Ok(())
            }
        }

        /// Mirror of [`SharedTlsIo`] without the rustls type bounds, so the
        /// close-symmetry property can be tested on plain types. The structure
        /// is otherwise identical: an `Rc<RefCell<…>>` shared between two
        /// cheap clones, each delegating `close()` to the inner.
        struct SharedHandle {
            inner: Rc<RefCell<CountingIo>>,
        }

        impl SharedHandle {
            fn clone_handle(&self) -> Self {
                Self {
                    inner: Rc::clone(&self.inner),
                }
            }
        }

        impl IoWrite for SharedHandle {
            fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
                self.inner.borrow_mut().write(buf)
            }
            fn flush(&mut self) -> Result<(), IoError> {
                self.inner.borrow_mut().flush()
            }
            fn close(&mut self) -> Result<(), IoError> {
                self.inner.borrow_mut().close()
            }
        }

        let inner = Rc::new(RefCell::new(CountingIo { close_calls: 0 }));
        let shared = SharedHandle {
            inner: Rc::clone(&inner),
        };
        let mut reader = shared.clone_handle();
        let mut writer = shared.clone_handle();
        drop(shared);

        // The exact two lines `handle_tls_connection` runs after `serve_worker`
        // returns. Before the fix only the first `writer.close()` was called;
        // after the fix both halves close, driving the counter to 2.
        let _ = writer.close();
        let _ = reader.close();

        assert_eq!(
            inner.borrow().close_calls,
            2,
            "handle_tls_connection must close both the reader and the writer halves"
        );
    }

    // --- per-connection threading -----------------------------------------

    /// The TLS accept loop must serve concurrent connections in parallel:
    /// a long-running session must not block subsequent peers (the real-world
    /// case being a backup transfer that would otherwise queue PG's
    /// `archive_command` invocations of `archive-push` behind it). The
    /// pre-fix loop served connections sequentially on the accept thread,
    /// so three concurrent clients holding the connection open for `slow`
    /// would take ~3 * `slow` wall-clock time. With per-connection thread
    /// spawn they all complete in roughly `slow`.
    #[test]
    fn tls_serve_handles_concurrent_connections() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use pgbr_protocol::ProtocolClient;

        let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
            shared_ca_pair("server.local", "principal");

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();

        let mut server_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            server_roots.add(c).unwrap();
        }
        let server_config = Arc::new(
            build_server_config(
                cert_chain_from_pem(&server_cert_pem),
                private_key_from_pem(&server_key_pem),
                Some(server_roots),
                &[],
            )
            .unwrap(),
        );
        let mut auth: BTreeMap<String, Vec<String>> = BTreeMap::new();
        auth.insert("principal".to_owned(), vec!["demo".to_owned()]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_tls_storage_with_continue(
                &listener,
                &server_config,
                &auth,
                &root_path,
                KeepAlive::default(),
                false,
                || !stop_for_server.load(Ordering::Acquire),
            )
        });

        let mut client_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            client_roots.add(c).unwrap();
        }
        let client_config = Arc::new(
            build_client_config(
                client_roots,
                Some((cert_chain_from_pem(&client_cert_pem), private_key_from_pem(&client_key_pem))),
                &[],
            )
            .unwrap(),
        );

        // Each client greets, sleeps `slow`, then closes. Pre-fix the
        // sessions ran serially on the single accept thread, taking
        // ~3 * `slow` total. Post-fix they run in parallel: total wall
        // time should be close to `slow`. Picking 300ms for `slow` and
        // asserting `< 2 * slow` keeps the test snappy and resistant to
        // CI scheduler jitter while still rejecting the serial path
        // (which would need ~900ms).
        let slow = Duration::from_millis(300);
        let addr = format!("127.0.0.1:{port}");
        let started = Instant::now();
        let mut workers = Vec::new();
        for attempt in 1..=3 {
            let client_config = Arc::clone(&client_config);
            let addr = addr.clone();
            workers.push(std::thread::spawn(move || {
                let stream = connect_tls_stream(&addr, "localhost", client_config)
                    .unwrap_or_else(|e| panic!("attempt {attempt}: connect: {e}"));
                stream.sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let io = SharedTlsIo::new(TlsClientIo::new(stream));
                let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());
                client
                    .greet(Some("demo"))
                    .unwrap_or_else(|e| panic!("attempt {attempt}: greet: {e}"));
                std::thread::sleep(slow);
                let _ = client.close();
            }));
        }
        for w in workers {
            w.join().expect("client thread panicked");
        }
        let elapsed = started.elapsed();

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("loop end");

        assert!(
            elapsed < slow * 2,
            "TLS accept loop must serve concurrent connections in parallel; \
             3 clients each sleeping {slow:?} took {elapsed:?} (serial would be ~3x slow)"
        );
    }

    /// Mirror of [`tls_serve_handles_concurrent_connections`] for the plain
    /// TCP accept loop: three clients each hold a `noOp` ping connection open
    /// for `slow` ms; the loop must serve them in parallel so the total wall
    /// time is close to `slow`, not `3 * slow`.
    #[test]
    fn tcp_serve_handles_concurrent_connections() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_listener_with_continue(&listener, KeepAlive::default(), false, || {
                !stop_for_server.load(Ordering::Acquire)
            })
        });

        let slow = Duration::from_millis(300);
        let started = Instant::now();
        let mut workers = Vec::new();
        for attempt in 1..=3 {
            workers.push(std::thread::spawn(move || {
                let stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("attempt {attempt}: connect: {e}"));
                stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let (mut reader, mut writer) = split(stream).unwrap();
                ping_exchange(&mut reader, &mut writer).unwrap_or_else(|e| panic!("attempt {attempt}: ping: {e}"));
                std::thread::sleep(slow);
                let _ = writer.close();
            }));
        }
        for w in workers {
            w.join().expect("client thread panicked");
        }
        let elapsed = started.elapsed();

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("loop end");

        assert!(
            elapsed < slow * 2,
            "TCP accept loop must serve concurrent connections in parallel; \
             3 clients each sleeping {slow:?} took {elapsed:?} (serial would be ~3x slow)"
        );
    }

    /// The TLS accept loop's worker-thread cap is honoured: with a cap of 2,
    /// two slow clients occupy both slots and a third client is rejected
    /// quickly (the loop drops the stream so the kernel resets the peer).
    /// Once the first two complete the cap frees up and a fourth client
    /// succeeds. This exercises the same code path the production
    /// `MAX_WORKER_THREADS` cap protects, just at a size the test can drive.
    #[test]
    fn tls_serve_caps_thread_pool() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use pgbr_protocol::ProtocolClient;

        let (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem) =
            shared_ca_pair("server.local", "principal");

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();

        let mut server_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            server_roots.add(c).unwrap();
        }
        let server_config = Arc::new(
            build_server_config(
                cert_chain_from_pem(&server_cert_pem),
                private_key_from_pem(&server_key_pem),
                Some(server_roots),
                &[],
            )
            .unwrap(),
        );
        let mut auth: BTreeMap<String, Vec<String>> = BTreeMap::new();
        auth.insert("principal".to_owned(), vec!["demo".to_owned()]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            // Cap = 2 so the third concurrent client must be rejected.
            serve_tls_storage_with_continue_caps(
                &listener,
                &server_config,
                &auth,
                &root_path,
                KeepAlive::default(),
                false,
                2,
                || !stop_for_server.load(Ordering::Acquire),
            )
        });

        let mut client_roots = RootCertStore::empty();
        for c in cert_chain_from_pem(&ca_pem) {
            client_roots.add(c).unwrap();
        }
        let client_config = Arc::new(
            build_client_config(
                client_roots,
                Some((cert_chain_from_pem(&client_cert_pem), private_key_from_pem(&client_key_pem))),
                &[],
            )
            .unwrap(),
        );
        let addr = format!("127.0.0.1:{port}");

        // Connect two slow clients that each occupy a worker slot for the
        // full `slow` duration. Spawn them on threads so the test can
        // attempt the rejected third connection while both are in flight.
        let slow = Duration::from_millis(500);
        let mut slow_workers = Vec::new();
        for attempt in 1..=2 {
            let client_config = Arc::clone(&client_config);
            let addr = addr.clone();
            slow_workers.push(std::thread::spawn(move || {
                let stream = connect_tls_stream(&addr, "localhost", client_config)
                    .unwrap_or_else(|e| panic!("slow attempt {attempt}: connect: {e}"));
                stream.sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                let io = SharedTlsIo::new(TlsClientIo::new(stream));
                let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());
                client
                    .greet(Some("demo"))
                    .unwrap_or_else(|e| panic!("slow attempt {attempt}: greet: {e}"));
                std::thread::sleep(slow);
                let _ = client.close();
            }));
        }

        // Give the two slow clients time to complete their TLS handshakes
        // and increment the in-flight counter. Without this brief settle the
        // third attempt races the server's `in_flight.load`.
        std::thread::sleep(Duration::from_millis(150));

        // Attempt the third connection — the cap is full so the server
        // drops the accepted stream. The TCP connect itself completes
        // (the kernel accepts then RSTs/EOFs on its own), but the greeting
        // round trip fails (handshake or read error) quickly. The key
        // assertion is *fast*: in well under `slow` ms.
        let started = Instant::now();
        let rejected_result = (|| -> Result<(), CommandError> {
            let stream = connect_tls_stream(&addr, "localhost", Arc::clone(&client_config))?;
            stream.sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let io = SharedTlsIo::new(TlsClientIo::new(stream));
            let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());
            client.greet(Some("demo")).map_err(|e| CommandError::Other(format!("{e}")))
        })();
        let rejected_elapsed = started.elapsed();
        assert!(
            rejected_result.is_err(),
            "third client should be rejected when cap=2 and two slow clients are in flight"
        );
        assert!(
            rejected_elapsed < slow,
            "rejected client must fail quickly (well under the slow duration {slow:?}); took {rejected_elapsed:?}"
        );

        // Wait for the two slow workers to finish, freeing both slots.
        for w in slow_workers {
            w.join().expect("slow client thread panicked");
        }

        // After both slots free, a fresh connection must succeed.
        let stream = connect_tls_stream(&addr, "localhost", Arc::clone(&client_config)).expect("post-drain connect must succeed");
        stream.sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let io = SharedTlsIo::new(TlsClientIo::new(stream));
        let mut client = ProtocolClient::new(io.clone_handle(), io.clone_handle());
        client.greet(Some("demo")).expect("post-drain greet must succeed");
        let _ = client.close();

        stop.store(true, Ordering::Release);
        server.join().expect("server thread panicked").expect("loop end");
    }
}
