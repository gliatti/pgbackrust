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
//! On top of those cores this module supplies a **plain-TCP** transport:
//!
//! - [`TcpIo`] adapts a [`std::net::TcpStream`] to [`IoRead`] / [`IoWrite`].
//! - [`serve_listener`] / [`serve_tcp`] accept connections and run [`serve`]
//!   per connection; [`ping_tcp`] connects and runs [`ping_exchange`].
//!
//! The user-facing [`server`] and [`ping`] entry points read the bind /
//! connect address from the configured `tls-server-address` /
//! `tls-server-port` options (defaulting to `127.0.0.1:8432`) and drive the
//! TCP helpers.
//!
//! **TLS is a documented follow-up.** The real pgBackRest `server` terminates
//! TLS on the socket; here the transport is plain TCP. Because [`serve`] and
//! [`ping_exchange`] are transport-agnostic, TLS slots in later by swapping
//! [`TcpIo`] for a TLS stream adapter (rustls / openssl) — the protocol cores
//! do not change.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_io::{IoError, IoRead, IoWrite};
use pgbr_storage::Storage;

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

/// `server` — listen for protocol connections from remote pgBackRest
/// processes over plain TCP and drive [`serve`] per connection.
///
/// The bind address comes from `tls-server-address` / `tls-server-port`
/// (default `127.0.0.1:8432`). TLS termination is a documented follow-up: the
/// transport-agnostic [`serve`] core is unchanged, so it slots in by swapping
/// [`TcpIo`] for a TLS stream adapter.
///
/// # Errors
///
/// Propagates whatever [`serve_tcp`] returns (bind / accept failures, or a
/// protocol / write error from [`serve`]).
pub fn server(config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    serve_tcp(&server_address(config))
}

/// `server-ping` — health check against a running `server` instance.
///
/// Connects over plain TCP to the configured `tls-server-address` /
/// `tls-server-port` (default `127.0.0.1:8432`) and runs [`ping_exchange`].
/// TLS is the same documented follow-up as for [`server`].
///
/// # Errors
///
/// Propagates whatever [`ping_tcp`] returns (connect failure, or a protocol /
/// rejection error from [`ping_exchange`]).
pub fn ping(config: &LoadedConfig) -> Result<(), CommandError> {
    ping_tcp(&server_address(config))
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
}
