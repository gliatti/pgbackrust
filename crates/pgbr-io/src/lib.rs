//! I/O abstractions used across the pgBackRest Rust rewrite.
//!
//! Mirrors the role of `src/common/io/` in the C tree: a buffer-oriented read
//! and write surface together with a chain of filters that can transform the
//! byte stream (compression, encryption, hashing, line splitting). Concrete
//! source/sink implementations (file, socket, in-memory) compose with the
//! filter chain to build pipelines such as
//! `IoRead<File> -> Decompress -> Decrypt -> consumer`.
//!
//! This first slice ships:
//!
//! - [`IoRead`] / [`IoWrite`] traits — buffer-oriented `read(&mut buf)` /
//!   `write(&buf)` with `flush` and `eof` semantics matching the C side.
//! - [`MemRead`] / [`MemWrite`] — in-memory implementations used by tests
//!   and by the `Buffer` storage backend.
//! - [`Filter`] trait + [`FilterChain`] — composes a sequence of filters
//!   that transform a byte stream as it flows through the pipeline.
//! - [`Identity`] — a no-op filter, useful as a unit type and for testing
//!   the chain machinery.
//!
//! The full set of production filters (`gz`, `bz2`, `lz4`, `zst`, `sha`,
//! `cipher`, `size`, `time`, `block`) lives in their own crates and plugs
//! into `FilterChain` via the [`Filter`] trait.

#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod file;
pub mod filter;

pub use crate::file::{FileRead, FileWrite};
pub use crate::filter::{Sha1, Sha256, Size};

use std::cmp::min;
use std::fmt;

/// Errors raised by [`IoRead`] / [`IoWrite`] implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    /// Tried to read past EOF on a closed source.
    UnexpectedEof,
    /// Tried to write to a sink that has been closed.
    Closed,
    /// Wrapped error from a backend (filesystem, socket, …). The message is
    /// already formatted; callers should propagate it verbatim.
    Backend(String),
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of input"),
            Self::Closed => f.write_str("i/o sink is closed"),
            Self::Backend(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for IoError {}

/// Buffer-oriented byte source.
///
/// Implementations fill `buf` with up to `buf.len()` bytes and return how
/// many were written. A return value of `0` signals EOF; subsequent calls
/// must keep returning `0`.
pub trait IoRead {
    /// Read into `buf`. Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] for any backend failure.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError>;

    /// `true` once the source has signalled EOF.
    fn eof(&self) -> bool;

    /// Read until `buf` is full or EOF is reached.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::UnexpectedEof`] if EOF is reached before `buf` is
    /// filled and `buf` is non-empty.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), IoError> {
        let mut off = 0;
        while off < buf.len() {
            let n = self.read(&mut buf[off..])?;
            if n == 0 {
                return Err(IoError::UnexpectedEof);
            }
            off += n;
        }
        Ok(())
    }

    /// Drain the source into a freshly allocated `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] for any backend failure.
    fn read_all(&mut self) -> Result<Vec<u8>, IoError> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        Ok(out)
    }
}

/// Buffer-oriented byte sink.
pub trait IoWrite {
    /// Write the entire contents of `buf` to the sink.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Closed`] if the sink has been closed, or
    /// [`IoError::Backend`] for any backend failure.
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError>;

    /// Flush any pending buffered bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] for any backend failure.
    fn flush(&mut self) -> Result<(), IoError>;

    /// Close the sink. Subsequent `write` / `flush` calls return
    /// [`IoError::Closed`].
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] for any backend failure during close.
    fn close(&mut self) -> Result<(), IoError>;
}

/// In-memory [`IoRead`]. Generic over the backing buffer (`Vec<u8>`,
/// `&[u8]`, `[u8; N]`, …) so tests can pass either an owned or a borrowed
/// byte source.
pub struct MemRead<B: AsRef<[u8]>> {
    data: B,
    cursor: usize,
}

impl<B: AsRef<[u8]>> MemRead<B> {
    /// Wrap a byte buffer as a readable source.
    #[must_use]
    pub const fn new(data: B) -> Self {
        Self { data, cursor: 0 }
    }
}

impl<B: AsRef<[u8]>> IoRead for MemRead<B> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let data = self.data.as_ref();
        let n = min(buf.len(), data.len() - self.cursor);
        buf[..n].copy_from_slice(&data[self.cursor..self.cursor + n]);
        self.cursor += n;
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.cursor >= self.data.as_ref().len()
    }
}

/// Growable in-memory [`IoWrite`]. Useful for testing the output side of a
/// filter chain.
#[derive(Debug, Default)]
pub struct MemWrite {
    buffer: Vec<u8>,
    closed: bool,
}

impl MemWrite {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take ownership of the accumulated bytes, replacing the buffer with an
    /// empty `Vec`.
    #[must_use]
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }

    /// Borrow the accumulated bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

impl IoWrite for MemWrite {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        self.buffer.extend_from_slice(buf);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), IoError> {
        self.closed = true;
        Ok(())
    }
}

/// Stream filter: receives bytes via `process` and emits transformed bytes
/// to its `out` parameter. `finish` flushes any internal state at end-of-stream.
///
/// The `out` buffer is *appended to* — implementations should `extend` rather
/// than overwrite, so a chain can collect output across multiple chunks.
pub trait Filter {
    /// Apply the filter to `input`, appending transformed bytes to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] when the underlying transform fails.
    fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError>;

    /// Signal end-of-stream and flush any internal state into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Backend`] when finalisation fails.
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError>;

    /// Stable, lower-snake_case identifier for diagnostics (e.g. `"gz"`,
    /// `"sha256"`). The identifier mirrors the C side's filter type names.
    fn name(&self) -> &'static str;
}

/// Sequence of [`Filter`]s applied in order. Chunks pushed to `process`
/// pass through every filter in turn.
#[derive(Default)]
pub struct FilterChain {
    filters: Vec<Box<dyn Filter>>,
}

impl FilterChain {
    /// Build an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a filter to the chain.
    pub fn push<F: Filter + 'static>(&mut self, filter: F) {
        self.filters.push(Box::new(filter));
    }

    /// Push `input` through every filter and append the final bytes to `out`.
    ///
    /// # Errors
    ///
    /// Propagates the first [`IoError`] raised by any filter in the chain.
    pub fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut current: Vec<u8> = input.to_vec();
        let mut next: Vec<u8> = Vec::with_capacity(current.len());
        for filter in &mut self.filters {
            next.clear();
            filter.process(&current, &mut next)?;
            std::mem::swap(&mut current, &mut next);
        }
        out.extend_from_slice(&current);
        Ok(())
    }

    /// Signal end-of-stream and append the final bytes to `out`.
    ///
    /// # Errors
    ///
    /// Propagates the first [`IoError`] raised by any filter in the chain.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut current: Vec<u8> = Vec::new();
        for filter in &mut self.filters {
            // Each filter sees both the carry-over from prior filters and
            // its own end-of-stream signal.
            let mut next = Vec::new();
            filter.process(&current, &mut next)?;
            filter.finish(&mut next)?;
            current = next;
        }
        out.extend_from_slice(&current);
        Ok(())
    }

    /// Number of filters in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// `true` when the chain has no filters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

/// No-op filter: emits its input verbatim. Useful as a placeholder and for
/// exercising the [`FilterChain`] machinery in tests.
#[derive(Debug, Default)]
pub struct Identity;

impl Filter for Identity {
    fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError> {
        out.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), IoError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "identity"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_read_drains_input() {
        let mut r = MemRead::new(b"hello");
        assert_eq!(r.read_all().unwrap(), b"hello");
        assert!(r.eof());
    }

    #[test]
    fn read_exact_short_returns_unexpected_eof() {
        let mut r = MemRead::new(b"hi");
        let mut buf = [0u8; 4];
        assert_eq!(r.read_exact(&mut buf).unwrap_err(), IoError::UnexpectedEof);
    }

    #[test]
    fn mem_write_collects_bytes_and_close_blocks_writes() {
        let mut w = MemWrite::new();
        w.write(b"hello, ").unwrap();
        w.write(b"world").unwrap();
        assert_eq!(w.as_slice(), b"hello, world");
        w.close().unwrap();
        assert_eq!(w.write(b"more").unwrap_err(), IoError::Closed);
    }

    #[test]
    fn empty_chain_is_passthrough() {
        let mut chain = FilterChain::new();
        let mut out = Vec::new();
        chain.process(b"abc", &mut out).unwrap();
        chain.finish(&mut out).unwrap();
        assert_eq!(out, b"abc");
    }

    #[test]
    fn identity_chain_preserves_input() {
        let mut chain = FilterChain::new();
        chain.push(Identity);
        chain.push(Identity);
        let mut out = Vec::new();
        chain.process(b"hello", &mut out).unwrap();
        chain.finish(&mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn filter_chain_len_and_is_empty() {
        let mut chain = FilterChain::new();
        assert!(chain.is_empty());
        chain.push(Identity);
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
    }

    /// A filter that uppercases ASCII letters to test the chain's
    /// transformation semantics.
    struct Upper;

    impl Filter for Upper {
        fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError> {
            out.extend(input.iter().map(u8::to_ascii_uppercase));
            Ok(())
        }

        fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), IoError> {
            Ok(())
        }

        fn name(&self) -> &'static str {
            "upper"
        }
    }

    #[test]
    fn filter_chain_transforms_input() {
        let mut chain = FilterChain::new();
        chain.push(Upper);
        let mut out = Vec::new();
        chain.process(b"Hello, World!", &mut out).unwrap();
        chain.finish(&mut out).unwrap();
        assert_eq!(out, b"HELLO, WORLD!");
    }

    /// A filter that emits an "X" only at finish-time, to verify the finish
    /// path actually flushes.
    struct EndMarker(bool);

    impl Filter for EndMarker {
        fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError> {
            out.extend_from_slice(input);
            Ok(())
        }

        fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
            if !self.0 {
                out.push(b'X');
                self.0 = true;
            }
            Ok(())
        }

        fn name(&self) -> &'static str {
            "end-marker"
        }
    }

    #[test]
    fn filter_finish_flushes_internal_state() {
        let mut chain = FilterChain::new();
        chain.push(EndMarker(false));
        let mut out = Vec::new();
        chain.process(b"abc", &mut out).unwrap();
        chain.finish(&mut out).unwrap();
        assert_eq!(out, b"abcX");
    }
}
