//! Line-delimited message codec over [`pgbr_io::IoRead`] / [`pgbr_io::IoWrite`].
//!
//! [`read_message`] consumes one newline-terminated JSON object from the
//! underlying reader; [`write_message`] serializes a [`Message`] and
//! appends a trailing newline. Together they form the framing layer
//! between typed protocol messages and a raw byte stream.

use core::fmt;

use pgbr_io::{IoError, IoRead, IoWrite};
use serde::de::Error as _;

use crate::message::Message;

/// Hard ceiling on the length of a single newline-delimited message, in bytes.
///
/// A peer that never emits a terminator would otherwise make [`read_message`]
/// grow its accumulation buffer without bound, exhausting memory (a trivial
/// denial-of-service). Legitimate protocol messages — JSON request/response
/// envelopes — are tiny (kilobytes at most), so a 16 MiB cap is orders of
/// magnitude above any well-formed line while still bounding the blast radius
/// of a hostile or corrupt stream. When a line reaches this size before a
/// `\n` is seen, [`read_message`] fails with [`CodecError::MessageTooLarge`]
/// *before* the offending byte is buffered.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

/// Errors raised by [`read_message`] / [`write_message`].
#[derive(Debug)]
pub enum CodecError {
    /// Backend I/O failure (read or write).
    Io(IoError),
    /// JSON serialization or parse failure.
    Parse(serde_json::Error),
    /// EOF reached after some bytes of a message but before a terminator.
    UnexpectedEof,
    /// A single message exceeded [`MAX_MESSAGE_LEN`] before its terminator.
    MessageTooLarge {
        /// The configured ceiling that was breached.
        limit: usize,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Parse(e) => write!(f, "parse: {e}"),
            Self::UnexpectedEof => f.write_str("unexpected EOF before message terminator"),
            Self::MessageTooLarge { limit } => {
                write!(f, "message exceeded maximum length of {limit} bytes")
            }
        }
    }
}

impl std::error::Error for CodecError {}

impl From<IoError> for CodecError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for CodecError {
    fn from(err: serde_json::Error) -> Self {
        Self::Parse(err)
    }
}

/// Read one newline-terminated JSON message from `read`.
///
/// Returns `Ok(None)` if `read` is at EOF before any byte arrives;
/// `Err(CodecError::UnexpectedEof)` if EOF arrives mid-message.
///
/// The accumulation buffer is capped at [`MAX_MESSAGE_LEN`]: a peer that
/// streams bytes without ever emitting a `\n` is rejected with
/// [`CodecError::MessageTooLarge`] rather than being allowed to grow the
/// buffer without bound (a memory-exhaustion `DoS`). The cap is checked
/// *before* each byte is appended, so an oversized line never materializes
/// in memory.
///
/// # Framing note
///
/// Bytes are consumed one at a time so `read_message` never reads past the
/// first `\n` into a following message. `IoRead` offers no push-back, and the
/// callers ([`crate::transport`], the command servers) invoke `read_message`
/// repeatedly over a *shared* reader that carries back-to-back messages, so
/// over-reading a block would silently drop whatever framing followed the
/// terminator. Framing therefore stays byte-exact; the [`MAX_MESSAGE_LEN`]
/// cap is what bounds the cost of a hostile stream. A future buffered
/// transport that owns push-back could read in larger blocks instead, but
/// that requires per-connection state the current signature does not carry.
///
/// # Errors
///
/// Returns [`CodecError`] for backend I/O failures, mid-message EOF, an
/// oversized line, or invalid JSON.
pub fn read_message<R: IoRead>(read: &mut R) -> Result<Option<Message>, CodecError> {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = read.read(&mut byte)?;
        if n == 0 {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(CodecError::UnexpectedEof)
            };
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= MAX_MESSAGE_LEN {
            return Err(CodecError::MessageTooLarge { limit: MAX_MESSAGE_LEN });
        }
        line.push(byte[0]);
    }
    let s = core::str::from_utf8(&line).map_err(|e| serde_json::Error::custom(format!("invalid utf-8: {e}")))?;
    Ok(Some(Message::from_json(s)?))
}

/// Write a JSON message followed by `\n` to `write`.
///
/// # Errors
///
/// Returns [`CodecError`] for backend I/O failures or serialization errors.
pub fn write_message<W: IoWrite>(write: &mut W, msg: &Message) -> Result<(), CodecError> {
    let json = msg.to_json()?;
    write.write(json.as_bytes())?;
    write.write(b"\n")?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::message::{ErrResponse, OkResponse, Request, Response};
    use pgbr_io::{MemRead, MemWrite};
    use serde_json::json;

    #[test]
    fn request_round_trips_through_codec() {
        let req = Message::Request(Request {
            cmd: "archiveGet".to_owned(),
            param: vec![json!("000000010000000000000001"), json!(true)],
        });

        let mut w = MemWrite::new();
        write_message(&mut w, &req).unwrap();
        let bytes = w.take();
        assert_eq!(bytes.last(), Some(&b'\n'));

        let mut r = MemRead::new(bytes);
        let parsed = read_message(&mut r).unwrap().unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn response_ok_with_no_out_serializes_to_empty_out() {
        let resp = Message::Response(Response::Ok(OkResponse { out: None }));
        let mut w = MemWrite::new();
        write_message(&mut w, &resp).unwrap();
        assert_eq!(w.as_slice(), b"{}\n");

        let mut r = MemRead::new(w.take());
        let parsed = read_message(&mut r).unwrap().unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn response_err_round_trips() {
        let resp = Message::Response(Response::Err(ErrResponse {
            err: 25,
            message: "assert failure".to_owned(),
            stack: Some("at frob:42".to_owned()),
        }));

        let mut w = MemWrite::new();
        write_message(&mut w, &resp).unwrap();
        let mut r = MemRead::new(w.take());
        let parsed = read_message(&mut r).unwrap().unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn read_message_returns_none_at_eof() {
        let mut r = MemRead::new(Vec::<u8>::new());
        assert!(read_message(&mut r).unwrap().is_none());
    }

    #[test]
    fn read_message_errors_on_unexpected_eof() {
        let mut r = MemRead::new(b"{\"cmd\":\"x\"".to_vec());
        match read_message(&mut r) {
            Err(CodecError::UnexpectedEof) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn multiple_messages_in_stream() {
        let messages = vec![
            Message::Request(Request {
                cmd: "noOp".to_owned(),
                param: Vec::new(),
            }),
            Message::Response(Response::Ok(OkResponse {
                out: Some(json!("done")),
            })),
            Message::Request(Request {
                cmd: "exit".to_owned(),
                param: Vec::new(),
            }),
        ];

        let mut w = MemWrite::new();
        for m in &messages {
            write_message(&mut w, m).unwrap();
        }

        let mut r = MemRead::new(w.take());
        for m in &messages {
            let parsed = read_message(&mut r).unwrap().unwrap();
            assert_eq!(&parsed, m);
        }
        assert!(read_message(&mut r).unwrap().is_none());
    }

    #[test]
    fn codec_error_displays_each_variant() {
        let io = CodecError::Io(IoError::Backend("disk full".to_owned()));
        assert_eq!(format!("{io}"), "i/o: disk full");

        let eof = CodecError::UnexpectedEof;
        assert_eq!(format!("{eof}"), "unexpected EOF before message terminator");

        let big = CodecError::MessageTooLarge { limit: MAX_MESSAGE_LEN };
        assert_eq!(
            format!("{big}"),
            format!("message exceeded maximum length of {MAX_MESSAGE_LEN} bytes")
        );
    }

    /// A peer that streams bytes forever without a terminator must be rejected
    /// with `MessageTooLarge` rather than growing the buffer without bound.
    #[test]
    fn read_message_rejects_oversized_line() {
        // One byte past the cap, no `\n` anywhere.
        let payload = vec![b'a'; MAX_MESSAGE_LEN + 1];
        let mut r = MemRead::new(payload);
        match read_message(&mut r) {
            Err(CodecError::MessageTooLarge { limit }) => assert_eq!(limit, MAX_MESSAGE_LEN),
            other => panic!("expected MessageTooLarge, got {other:?}"),
        }
    }

    /// A line of exactly `MAX_MESSAGE_LEN` payload bytes followed by `\n` sits
    /// on the boundary and must still parse (given valid JSON). We build a
    /// JSON string literal padded out to the cap so parsing succeeds.
    #[test]
    fn read_message_accepts_line_at_the_limit() {
        // `"<pad>"` — two quotes plus padding == MAX_MESSAGE_LEN payload bytes.
        let pad = MAX_MESSAGE_LEN - 2;
        let mut bytes = Vec::with_capacity(MAX_MESSAGE_LEN + 1);
        bytes.push(b'"');
        bytes.resize(1 + pad, b'x');
        bytes.push(b'"');
        assert_eq!(bytes.len(), MAX_MESSAGE_LEN);
        bytes.push(b'\n');
        let mut r = MemRead::new(bytes);
        // A bare JSON string is not a valid `Message`, so this fails at the
        // parse stage — crucially *not* at the size cap. Proves the boundary
        // byte count is accepted by the framer.
        match read_message(&mut r) {
            Err(CodecError::Parse(_)) => {}
            other => panic!("expected Parse error at the limit boundary, got {other:?}"),
        }
    }

    /// A normal-sized message is unaffected by the cap.
    #[test]
    fn read_message_accepts_normal_message() {
        let req = Message::Request(Request {
            cmd: "archivePush".to_owned(),
            param: vec![json!("000000010000000000000002")],
        });
        let mut w = MemWrite::new();
        write_message(&mut w, &req).unwrap();
        let mut r = MemRead::new(w.take());
        assert_eq!(read_message(&mut r).unwrap().unwrap(), req);
    }

    /// A stream that ends mid-message (no terminator, under the cap) still
    /// surfaces `UnexpectedEof`, not a size error.
    #[test]
    fn read_message_partial_then_eof_is_unexpected_eof() {
        let mut r = MemRead::new(b"{\"cmd\":\"partial\",\"param\":[".to_vec());
        match read_message(&mut r) {
            Err(CodecError::UnexpectedEof) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }
}
