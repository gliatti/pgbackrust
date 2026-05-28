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
//! The TLS/TCP transport is out of scope for this slice. What lives here
//! is the transport-agnostic *protocol* core both commands drive:
//!
//! - [`serve`] — the request/response loop a server runs per connection.
//! - [`ping_exchange`] — the single no-op round trip the ping client does.
//!
//! Both operate over any [`IoRead`] / [`IoWrite`] pair, so they are tested
//! over in-memory [`MemRead`](pgbr_io::MemRead) /
//! [`MemWrite`](pgbr_io::MemWrite) streams. The user-facing [`server`] and
//! [`ping`] entry points remain [`CommandError::NotYetImplemented`] until
//! the transport lands: once it does, `server` will accept a connection,
//! wrap its read/write halves, and call [`serve`]; `ping` will connect and
//! call [`ping_exchange`].

use pgbr_config::LoadedConfig;
use pgbr_io::{IoRead, IoWrite};
use pgbr_storage::Storage;

use crate::CommandError;

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

/// `server` — listen for protocol connections from remote pgBackRest
/// processes.
///
/// The serve loop itself is implemented and tested as [`serve`]; what is
/// still missing is the transport. When the TLS/TCP listener lands this
/// will bind a socket, accept connections, and call [`serve`] with the
/// connection's read/write halves per client.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`] until the socket
/// transport is ported.
pub fn server(_config: &LoadedConfig, _repo_storage: &dyn Storage) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "server".to_owned(),
    })
}

/// `server-ping` — health check against a running `server` instance.
///
/// The exchange itself is implemented and tested as [`ping_exchange`];
/// what is still missing is the transport. When the TLS/TCP client lands
/// this will connect to the configured server and call [`ping_exchange`]
/// over the socket's read/write halves.
///
/// # Errors
///
/// Always returns [`CommandError::NotYetImplemented`] until the socket
/// transport is ported.
pub fn ping(_config: &LoadedConfig) -> Result<(), CommandError> {
    Err(CommandError::NotYetImplemented {
        command: "server-ping".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgbr_config::ConfigCommandRole;
    use pgbr_io::{MemRead, MemWrite};
    use pgbr_protocol::{ErrResponse, Message, OkResponse, Request, Response, read_message, write_message};
    use std::collections::BTreeMap;

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

    #[test]
    fn server_command_is_not_yet_implemented() {
        // `server` and `ping` are thin NotYetImplemented wrappers until the
        // TLS transport lands; the tested core lives in `serve` /
        // `ping_exchange` above. Build a minimal config to call them.
        let config = LoadedConfig {
            command: "server".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: None,
            options: BTreeMap::new(),
            params: Vec::new(),
        };
        let repo = pgbr_storage::Posix::new("/");

        assert_eq!(
            server(&config, &repo),
            Err(CommandError::NotYetImplemented {
                command: "server".to_owned(),
            })
        );
        assert_eq!(
            ping(&config),
            Err(CommandError::NotYetImplemented {
                command: "server-ping".to_owned(),
            })
        );
    }
}
