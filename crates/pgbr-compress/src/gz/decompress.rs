//! Streaming gzip / zlib-wrapped inflate decompressor.
//!
//! Mirrors `src/common/compress/gz/decompress.c` — same `inflateInit2_` parameters
//! (`windowBits = 15` for raw / `31` for gzip), same `inflate(..., Z_NO_FLUSH)` driving
//! loop. Goes through `libz-sys` directly so the inflate path matches the legacy C code
//! byte-for-byte (deflate-compressed streams are always inflated identically by libz, but
//! routing through the same zlib build keeps error codes and edge-case behaviour
//! identical too — particularly the `Z_BUF_ERROR` / `Z_STREAM_END` ordering on truncated
//! input).
//!
//! The state machine that decides "more input?" / "done?" stays on the C side (see the
//! `GzDecompress` struct in `gz/decompress.c`); this module exposes a thin
//! single-inflate-tick API.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    pub use libz_sys::{Z_NO_FLUSH, Z_OK, Z_STREAM_END, inflate, inflateEnd, inflateInit2_, z_stream, zlibVersion};
}

/// `WINDOW_BITS` from `src/common/compress/gz/common.h`. 15 = 32 KiB sliding window.
const WINDOW_BITS: i32 = 15;
/// `WANT_GZ` from `src/common/compress/gz/common.h`. Adding this to `WINDOW_BITS` tells
/// `inflateInit2` to expect a gzip header / trailer.
const WANT_GZ: i32 = 16;

/// Allocate an all-zero `z_stream`. Same `invalid_value`-lint suppression rationale as in
/// the compress sibling — libz documents NULL allocator hooks as the way to ask for the
/// default heap allocator.
#[allow(invalid_value, unsafe_code, clippy::uninit_assumed_init)]
const fn zeroed_z_stream() -> sys::z_stream {
    // SAFETY: see `zalloc` documentation in `zlib.h`; passing the struct with NULL
    // function-pointer fields is the documented way to request the default allocator,
    // and is also what the legacy C code does (`{.zalloc = NULL}`).
    unsafe { core::mem::MaybeUninit::<sys::z_stream>::zeroed().assume_init() }
}

/// Streaming inflate state. Owns a libz `z_stream` plus the heap allocation it uses for
/// its workspace.
///
/// Construction calls `inflateInit2_` with the legacy parameters, drop calls
/// `inflateEnd`. Cloning is not supported — libz's internal state is not safe to copy.
pub struct Decompress {
    /// `Box` keeps the `z_stream` at a stable address; libz writes to it across calls.
    stream: Box<sys::z_stream>,
}

/// Outcome of a single [`Decompress::inflate_tick`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InflateTick {
    /// Bytes written into the destination buffer during this call.
    pub written: usize,
    /// Bytes consumed from the source buffer during this call.
    pub consumed: usize,
    /// `true` iff libz returned `Z_STREAM_END` — the stream is fully decompressed and
    /// the caller must not call `inflate_tick` again.
    pub stream_end: bool,
}

impl Decompress {
    /// Initialize a new decompressor with the legacy `inflateInit2_` parameters.
    ///
    /// `raw=false` expects gzip-wrapped input; `raw=true` expects zlib-wrapped input.
    /// Note: matching `gzCompressNew`, "raw" here does not mean header-less deflate;
    /// `windowBits = -15` would, but the legacy `gzDecompressNew` never selects it.
    ///
    /// Returns `Err(code)` with the raw zlib return code on initialization failure so
    /// the caller can hand it to the legacy `gzError` mapper.
    pub fn new(raw: bool) -> Result<Self, i32> {
        let window_bits = if raw { WINDOW_BITS } else { WINDOW_BITS | WANT_GZ };

        let mut stream: Box<sys::z_stream> = Box::new(zeroed_z_stream());
        let stream_size = i32::try_from(core::mem::size_of::<sys::z_stream>()).unwrap_or(i32::MAX);

        // SAFETY: `stream` points to a fresh, zero-initialized `z_stream` we own; libz
        // owns the writes from this point on. `zlibVersion()` returns a static
        // NUL-terminated string from the linked libz; passing the matching
        // `sizeof(z_stream)` is required by `inflateInit2_` to verify ABI compatibility.
        #[allow(unsafe_code)]
        let ret = unsafe { sys::inflateInit2_(ptr::from_mut(stream.as_mut()), window_bits, sys::zlibVersion(), stream_size) };

        if ret != sys::Z_OK {
            return Err(ret);
        }

        Ok(Self { stream })
    }

    /// Run one `inflate(Z_NO_FLUSH)` call.
    ///
    /// `src` is the next slice of compressed bytes (may be empty if the caller is just
    /// trying to drain the encoder's internal pending buffer); `dst` is the output slice
    /// (must have remaining capacity).
    ///
    /// Returns the `(written, consumed, stream_end)` tuple. `Err(code)` carries the raw
    /// zlib return code on error so the caller can hand it to `gzError`.
    pub fn inflate_tick(&mut self, src: &[u8], dst: &mut [u8]) -> Result<InflateTick, i32> {
        // Point libz at the caller's buffers. `next_in` is `*mut u8` in the bindings even
        // though the data is read-only; not all zlib builds accept const input pointers
        // (mirrors the same comment in the legacy C code).
        self.stream.next_in = src.as_ptr().cast_mut();
        self.stream.avail_in = u32::try_from(src.len()).unwrap_or(u32::MAX);
        self.stream.next_out = dst.as_mut_ptr();
        self.stream.avail_out = u32::try_from(dst.len()).unwrap_or(u32::MAX);

        let avail_in_before = self.stream.avail_in;
        let avail_out_before = self.stream.avail_out;

        // SAFETY: `self.stream` is a live `z_stream` previously initialized by
        // `inflateInit2_`. The slices outlive the call and we clear the back-pointers
        // before returning so libz never observes a dangling pointer between calls.
        #[allow(unsafe_code)]
        let ret = unsafe { sys::inflate(ptr::from_mut(self.stream.as_mut()), sys::Z_NO_FLUSH) };

        let written = (avail_out_before - self.stream.avail_out) as usize;
        let consumed = (avail_in_before - self.stream.avail_in) as usize;

        // Clear the borrowed pointers — the slices are about to die, and libz must not
        // dereference them until the caller hands us fresh slices on the next tick.
        self.stream.next_in = ptr::null_mut();
        self.stream.next_out = ptr::null_mut();
        self.stream.avail_in = 0;
        self.stream.avail_out = 0;

        match ret {
            sys::Z_OK => Ok(InflateTick {
                written,
                consumed,
                stream_end: false,
            }),
            sys::Z_STREAM_END => Ok(InflateTick {
                written,
                consumed,
                stream_end: true,
            }),
            // `Z_BUF_ERROR` (`-5`) means no progress was possible — usually because the
            // caller passed an empty src and dst is not full. The legacy code routed this
            // through `gzError` (an Assert), so propagate it as an error code.
            _ => Err(ret),
        }
    }
}

impl Drop for Decompress {
    fn drop(&mut self) {
        // SAFETY: `self.stream` was successfully initialized in `Decompress::new`;
        // calling `inflateEnd` exactly once on a live stream is part of libz's contract.
        // We ignore the return code — it can only signal "stream was never used" or
        // "stream already ended", neither of which is actionable in a `Drop`.
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::inflateEnd(ptr::from_mut(self.stream.as_mut()));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::super::compress::Compress;
    use super::{Decompress, WANT_GZ, WINDOW_BITS};

    /// Compress `plaintext` with the sibling `gz::compress::Compress` (so the bytes match
    /// what the legacy gzip encoder produces) and decompress with this module. Asserts
    /// the round-trip recovers the original bytes.
    fn round_trip(level: i32, raw: bool, plaintext: &[u8]) -> Vec<u8> {
        let mut comp = Compress::new(level, raw).unwrap();
        let mut compressed = Vec::with_capacity(plaintext.len() + 256);

        // Stream the input through the compressor in small chunks.
        let mut input_pos = 0;
        while input_pos < plaintext.len() {
            let src = &plaintext[input_pos..];
            let mut dst = [0u8; 33];
            let tick = comp.deflate_tick(src, &mut dst, false).unwrap();
            compressed.extend_from_slice(&dst[..tick.written]);
            input_pos += tick.consumed;
        }
        loop {
            let mut dst = [0u8; 17];
            let tick = comp.deflate_tick(&[], &mut dst, true).unwrap();
            compressed.extend_from_slice(&dst[..tick.written]);
            if tick.stream_end {
                break;
            }
        }

        // Decompress with this module.
        let mut decomp = Decompress::new(raw).unwrap();
        let mut out = Vec::with_capacity(plaintext.len());
        let mut input_pos = 0;
        loop {
            let src = &compressed[input_pos..];
            let mut dst = [0u8; 19];
            let tick = decomp.inflate_tick(src, &mut dst).unwrap();
            out.extend_from_slice(&dst[..tick.written]);
            input_pos += tick.consumed;
            if tick.stream_end {
                break;
            }
        }
        out
    }

    #[test]
    fn roundtrip_simple_data_gzip() {
        let plaintext = b"A simple string";
        assert_eq!(round_trip(1, false, plaintext), plaintext);
    }

    #[test]
    fn roundtrip_simple_data_zlib_wrapper() {
        let plaintext = b"A simple string";
        assert_eq!(round_trip(1, true, plaintext), plaintext);
    }

    #[test]
    fn roundtrip_all_levels() {
        let plaintext: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
        for level in -1..=9 {
            let decoded = round_trip(level, false, &plaintext);
            assert_eq!(decoded, plaintext, "gzip level={level}");
            let decoded = round_trip(level, true, &plaintext);
            assert_eq!(decoded, plaintext, "zlib-wrap level={level}");
        }
    }

    #[test]
    fn roundtrip_zero_byte_input() {
        // Encoding nothing must still emit a valid gzip / zlib stream that decodes to an
        // empty plaintext.
        for raw in [false, true] {
            let plaintext: &[u8] = &[];
            // Bypass `round_trip` (which sets a non-empty inner loop guard) and run the
            // empty case manually.
            let mut comp = Compress::new(1, raw).unwrap();
            let mut compressed = Vec::with_capacity(64);
            loop {
                let mut dst = [0u8; 17];
                let tick = comp.deflate_tick(&[], &mut dst, true).unwrap();
                compressed.extend_from_slice(&dst[..tick.written]);
                if tick.stream_end {
                    break;
                }
            }
            let mut decomp = Decompress::new(raw).unwrap();
            let mut out = Vec::new();
            let mut input_pos = 0;
            loop {
                let mut dst = [0u8; 19];
                let tick = decomp.inflate_tick(&compressed[input_pos..], &mut dst).unwrap();
                out.extend_from_slice(&dst[..tick.written]);
                input_pos += tick.consumed;
                if tick.stream_end {
                    break;
                }
            }
            assert_eq!(out, plaintext, "raw={raw}");
        }
    }

    #[test]
    fn roundtrip_large_pattern() {
        // 1 MiB with a repeating ASCII pattern — same shape as the
        // `compress a large non-zero input buffer into small output buffer` test in
        // `compressTest.c`.
        let mut plaintext = vec![0u8; 1024 * 1024 - 1];
        for (idx, b) in plaintext.iter_mut().enumerate() {
            *b = (idx % 94 + 32) as u8;
        }
        for raw in [false, true] {
            let decoded = round_trip(3, raw, &plaintext);
            assert_eq!(decoded.len(), plaintext.len(), "raw={raw}");
            assert_eq!(decoded, plaintext, "raw={raw}");
        }
    }

    #[test]
    fn truncated_data_yields_buf_error() {
        // Inflate of empty input with no pending data should return Z_BUF_ERROR (-5).
        // The legacy code maps this to AssertError via `gzError`.
        let mut decomp = Decompress::new(false).unwrap();
        let mut dst = [0u8; 16];
        match decomp.inflate_tick(&[], &mut dst) {
            Ok(tick) => panic!("expected Z_BUF_ERROR, got {tick:?}"),
            Err(code) => assert_eq!(code, -5, "Z_BUF_ERROR"),
        }
    }

    #[test]
    fn corrupt_data_yields_data_error() {
        // Pure garbage input should fail with Z_DATA_ERROR (-3).
        let mut decomp = Decompress::new(false).unwrap();
        let garbage = b"this is not a gzip stream at all";
        let mut dst = [0u8; 64];
        match decomp.inflate_tick(garbage, &mut dst) {
            Ok(tick) => panic!("expected Z_DATA_ERROR, got {tick:?}"),
            Err(code) => assert_eq!(code, -3, "Z_DATA_ERROR"),
        }
    }

    #[test]
    fn window_constants_match_c_header() {
        assert_eq!(WINDOW_BITS, 15);
        assert_eq!(WANT_GZ, 16);
    }
}
