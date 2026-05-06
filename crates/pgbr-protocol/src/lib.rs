//! Wire-format types for the pgBackRest local/remote protocol.
//!
//! pgBackRest's main process drives helper processes (local workers and
//! remote SSH endpoints) over a JSON-line RPC protocol. Each direction of
//! the conversation is a stream of newline-terminated JSON objects:
//!
//! - request:  `{"cmd": "<command>", "param": [<args>...]}`
//! - ok:       `{"out": <value>}`
//! - err:      `{"err": <code>, "out": "<message>", "errStack": "<trace>"}`
//!
//! This crate ships only the message *types* and a line-delimited *codec*
//! over [`pgbr_io::IoRead`] / [`pgbr_io::IoWrite`]. The actual transport
//! (sockets, pipes), the parallel job dispatcher, and helpers like
//! `protocolHelperGet` are intentionally deferred — they will build on
//! the message types added here.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod codec;
pub mod message;

pub use crate::codec::{CodecError, read_message, write_message};
pub use crate::message::{ErrResponse, Message, OkResponse, Request, Response};
