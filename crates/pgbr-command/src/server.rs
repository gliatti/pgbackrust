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

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_io::{IoError, IoRead, IoWrite};
use pgbr_storage::Storage;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, ServerConfig, ServerConnection, SideData, StreamOwned,
};

use crate::CommandError;

/// Default bind / connect address used when the configured
/// `tls-server-address` / `tls-server-port` options are absent.
const DEFAULT_ADDRESS: &str = "127.0.0.1:8432";

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

/// Accept connections on an already-bound [`TcpListener`] and run [`serve`]
/// on each until the listener is exhausted.
///
/// This slice handles a single connection then returns: each accepted socket
/// is served to its `exit`/EOF, after which the function stops. That keeps the
/// transport simple and makes loopback tests deterministic; serving multiple
/// connections in a loop is a follow-up (wrap the body in `for stream in
/// listener.incoming()`).
///
/// # Errors
///
/// [`CommandError::Other`] on an accept / clone failure, or whatever [`serve`]
/// returns for a protocol or write error.
pub fn serve_listener(listener: &TcpListener) -> Result<(), CommandError> {
    let (stream, _peer) = listener
        .accept()
        .map_err(|e| CommandError::Other(format!("tcp accept: {e}")))?;
    let (mut reader, mut writer) = split(stream)?;
    serve(&mut reader, &mut writer)?;
    // Signal a clean EOF to the peer; ignore an already-closed socket.
    let _ = writer.close();
    Ok(())
}

/// Bind a [`TcpListener`] to `addr` and serve a connection via
/// [`serve_listener`].
///
/// # Errors
///
/// [`CommandError::Other`] if the address cannot be bound, plus anything
/// [`serve_listener`] returns.
pub fn serve_tcp(addr: &str) -> Result<(), CommandError> {
    let listener = TcpListener::bind(addr).map_err(|e| CommandError::Other(format!("tcp bind {addr}: {e}")))?;
    serve_listener(&listener)
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
    for cert in load_cert_chain(ca_path)? {
        roots
            .add(cert)
            .map_err(|e| CommandError::Other(format!("add CA from {ca_path}: {e}")))?;
    }
    Ok(roots)
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
    ensure_crypto_provider();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| CommandError::Other(format!("tls server config: {e}")))?;
    let server_config = Arc::new(server_config);

    let (stream, _peer) = listener
        .accept()
        .map_err(|e| CommandError::Other(format!("tcp accept: {e}")))?;

    let conn = ServerConnection::new(server_config).map_err(|e| CommandError::Other(format!("tls server new: {e}")))?;
    let io = SharedTlsIo::new(TlsServerIo::new(StreamOwned::new(conn, stream)));

    let mut reader = io.clone_handle();
    let mut writer = io.clone_handle();
    serve(&mut reader, &mut writer)?;
    // Signal a clean EOF (close_notify + write-shutdown) to the peer.
    let _ = writer.close();
    Ok(())
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
    ensure_crypto_provider();

    let roots = root_store_from_ca(ca_file)?;
    let client_config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let client_config = Arc::new(client_config);

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

/// `server` — listen for protocol connections from remote pgBackRest
/// processes and drive [`serve`] per connection.
///
/// The bind address comes from `tls-server-address` / `tls-server-port`
/// (default `127.0.0.1:8432`).
///
/// **Transport selection:** if both `tls-server-cert-file` and
/// `tls-server-key-file` are configured, the cert chain + private key are
/// loaded from those PEM files and the connection is served over TLS via
/// [`serve_tls`]. Otherwise the server falls back to plain TCP via
/// [`serve_tcp`]. The transport-agnostic [`serve`] core is identical on both
/// paths.
///
/// # Errors
///
/// Propagates whatever [`serve_tls`] / [`serve_tcp`] return (bind / accept
/// failures, invalid cert/key, TLS handshake errors, or a protocol / write
/// error from [`serve`]).
pub fn server(config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let addr = server_address(config);

    match (
        option_path(config, "tls-server-cert-file"),
        option_path(config, "tls-server-key-file"),
    ) {
        (Some(cert_file), Some(key_file)) => {
            let cert_chain = load_cert_chain(&cert_file)?;
            let private_key = load_private_key(&key_file)?;
            let listener = TcpListener::bind(&addr).map_err(|e| CommandError::Other(format!("tcp bind {addr}: {e}")))?;
            serve_tls(&listener, cert_chain, private_key)
        }
        _ => serve_tcp(&addr),
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
    use std::time::Duration;

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
        // Bind on an ephemeral port, read the assigned address BEFORE moving
        // the listener into the server thread, then ping it from the main
        // thread and join.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || serve_listener(&listener));

        // Connect, set a read timeout so a hung server fails the test fast
        // rather than blocking CI, then run the ping exchange.
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (mut reader, mut writer) = split(stream).unwrap();
        ping_exchange(&mut reader, &mut writer).unwrap();

        // `ping_exchange` issues a `noOp` but no `exit`, so the server's read
        // loop only ends when it sees EOF. Close the write half and drop both
        // client handles so the socket is torn down, giving the server a clean
        // EOF; otherwise the join below would block on a still-open socket.
        writer.close().unwrap();
        drop(reader);
        drop(writer);

        // The server thread completed without error after serving the
        // connection to its clean EOF.
        server.join().expect("server thread panicked").expect("serve_listener");
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
}
