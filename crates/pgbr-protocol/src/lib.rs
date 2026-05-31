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
    EXIT_COMMAND, NOOP_COMMAND, PGBACKREST_PROGRAM, PipeRead, PipeWrite, ProcessClient, ProtocolClient, ProtocolError,
    RequestHandler, SSH_PROGRAM, build_local_command, build_ssh_command, serve,
};

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// Default `compress-level-network` (matches `config.yaml`'s default of `1`):
/// the gz level applied to the inter-host protocol stream.
pub const DEFAULT_NETWORK_COMPRESS_LEVEL: i32 = 1;

/// Sentinel for "no network compression level configured" so
/// [`network_compress_level`] can distinguish an unset state from a
/// legitimately-configured `0`.
const NETWORK_COMPRESS_LEVEL_UNSET: i32 = i32::MIN;

/// Process-global gz compression level applied to the inter-host protocol stream
/// (the `compress-level-network` option). The main process sets this once at
/// startup via [`set_network_compress_level`]; the remote/local transport reads
/// it through [`network_compress_level`] when negotiating stream compression.
static NETWORK_COMPRESS_LEVEL: AtomicI32 = AtomicI32::new(NETWORK_COMPRESS_LEVEL_UNSET);

/// Override the process-global network compression level. Any value in the
/// option's documented range (`-5..=12`) is accepted, including `0` (no
/// compression).
pub fn set_network_compress_level(level: i32) {
    NETWORK_COMPRESS_LEVEL.store(level, Ordering::Relaxed);
}

/// The configured network compression level, falling back to
/// [`DEFAULT_NETWORK_COMPRESS_LEVEL`] when the CLI has not set one.
#[must_use]
pub fn network_compress_level() -> i32 {
    match NETWORK_COMPRESS_LEVEL.load(Ordering::Relaxed) {
        NETWORK_COMPRESS_LEVEL_UNSET => DEFAULT_NETWORK_COMPRESS_LEVEL,
        level => level,
    }
}

/// Process-global protocol timeout in milliseconds, applied to the request /
/// response exchange with a worker over the local/remote transport.
///
/// `0` means "no timeout configured" (the default); the main process sets it
/// from the resolved `protocol-timeout` option via [`set_protocol_timeout_ms`].
/// The transport reads it through [`protocol_timeout`].
static PROTOCOL_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

/// Override the process-global protocol timeout (milliseconds). `0` clears it.
pub fn set_protocol_timeout_ms(millis: u64) {
    PROTOCOL_TIMEOUT_MS.store(millis, Ordering::Relaxed);
}

/// The configured protocol timeout as a [`std::time::Duration`], or `None` when
/// no timeout is set (`0`).
#[must_use]
pub fn protocol_timeout() -> Option<std::time::Duration> {
    match PROTOCOL_TIMEOUT_MS.load(Ordering::Relaxed) {
        0 => None,
        millis => Some(std::time::Duration::from_millis(millis)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that mutate the process-global network-compression /
    /// protocol-timeout state.
    static GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn network_compress_level_defaults_and_round_trips() {
        let _g = GLOBAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Reset to the unset sentinel so the default is observed.
        set_network_compress_level(NETWORK_COMPRESS_LEVEL_UNSET);
        assert_eq!(network_compress_level(), DEFAULT_NETWORK_COMPRESS_LEVEL);

        // A configured level (including 0) is honoured.
        set_network_compress_level(0);
        assert_eq!(network_compress_level(), 0);
        set_network_compress_level(9);
        assert_eq!(network_compress_level(), 9);

        set_network_compress_level(NETWORK_COMPRESS_LEVEL_UNSET);
    }

    #[test]
    fn protocol_timeout_round_trips() {
        let _g = GLOBAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        set_protocol_timeout_ms(0);
        assert_eq!(protocol_timeout(), None, "0 means no timeout configured");

        set_protocol_timeout_ms(90_000);
        assert_eq!(protocol_timeout(), Some(std::time::Duration::from_secs(90)));

        set_protocol_timeout_ms(0);
        assert_eq!(protocol_timeout(), None);
    }
}
