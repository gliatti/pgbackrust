#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
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
//! This crate ships the message *types*, a line-delimited *codec* over
//! [`pgbr_io::IoRead`] / [`pgbr_io::IoWrite`], and a process *transport*
//! ([`transport`]) that spawns a child worker over piped stdin/stdout and
//! exchanges messages with it. The socket transport and helpers like
//! `protocolHelperGet` build on these.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod codec;
pub mod message;
pub mod parallel;
pub mod transport;

pub use crate::codec::{CodecError, read_message, write_message};
pub use crate::message::{ErrResponse, Message, OkResponse, Request, Response};
pub use crate::parallel::{Job, JobResult, ParallelExecutor};
pub use crate::transport::{
    EXIT_COMMAND, NOOP_COMMAND, PipeRead, PipeWrite, ProcessClient, ProtocolClient, ProtocolError, RequestHandler, serve,
};
