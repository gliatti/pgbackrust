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

/// Errors raised by [`read_message`] / [`write_message`].
#[derive(Debug)]
pub enum CodecError {
    /// Backend I/O failure (read or write).
    Io(IoError),
    /// JSON serialization or parse failure.
    Parse(serde_json::Error),
    /// EOF reached after some bytes of a message but before a terminator.
    UnexpectedEof,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Parse(e) => write!(f, "parse: {e}"),
            Self::UnexpectedEof => f.write_str("unexpected EOF before message terminator"),
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
/// # Errors
///
/// Returns [`CodecError`] for backend I/O failures, mid-message EOF, or
/// invalid JSON.
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
    }
}
