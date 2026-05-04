//! Streaming gzip / zlib-wrapped deflate compressor.
//!
//! Mirrors `src/common/compress/gz/compress.c` — same `deflateInit2_` parameters
//! (`memLevel = 9`, `Z_DEFAULT_STRATEGY`, `windowBits = 15` for raw / `31` for gzip),
//! same `deflate(..., Z_NO_FLUSH | Z_FINISH)` driving loop. Goes through `libz-sys`
//! directly so the compressed output is byte-identical to the legacy C path; flate2
//! does not expose `memLevel`, which is why we bypass it here.
//!
//! The state machine that decides "more input?" / "flushing?" / "done?" stays on the C
//! side (see the `GzCompress` struct in `gz/compress.c`); this module exposes a thin
//! single-deflate-tick API and the legacy `inputSame` semantics fall out naturally from
//! how much input each tick consumes.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    #[cfg(test)]
    pub use libz_sys::Z_STREAM_ERROR;
    pub use libz_sys::{
        Z_DEFAULT_STRATEGY, Z_DEFLATED, Z_FINISH, Z_NO_FLUSH, Z_OK, Z_STREAM_END, deflate, deflateEnd, deflateInit2_, z_stream,
        zlibVersion,
    };
}

/// `MEM_LEVEL` from `src/common/compress/gz/compress.c` — controls how much memory zlib
/// allocates internally. Hard-coded at 9 (the legacy maximum) so the encoder makes the
/// same chunking decisions across a migration.
const MEM_LEVEL: i32 = 9;
/// `WINDOW_BITS` from `src/common/compress/gz/common.h`. 15 = 32 KiB sliding window.
const WINDOW_BITS: i32 = 15;
/// `WANT_GZ` from `src/common/compress/gz/common.h`. Adding this to `WINDOW_BITS` tells
/// `deflateInit2` to wrap the deflate stream in a gzip header / trailer.
const WANT_GZ: i32 = 16;

/// Allocate an all-zero `z_stream`. Sequestered behind a single `#[allow(invalid_value)]`
/// because libz's documented init requires NULL function pointers for `zalloc` / `zfree`,
/// which would otherwise trip the lint at every call site.
#[allow(invalid_value, unsafe_code, clippy::uninit_assumed_init)]
const fn zeroed_z_stream() -> sys::z_stream {
    // SAFETY: see the `zalloc` documentation in `zlib.h` — passing the struct to libz
    // with NULL function-pointer fields is the documented way to request the default
    // allocator, and is also what the legacy C code does (`{.zalloc = NULL}`).
    unsafe { core::mem::MaybeUninit::<sys::z_stream>::zeroed().assume_init() }
}

/// Streaming deflate state. Owns a libz `z_stream` plus the heap allocation it uses for
/// its workspace.
///
/// Construction calls `deflateInit2_` with the legacy parameters, drop calls
/// `deflateEnd`. Cloning is not supported — libz's internal state is not safe to copy.
pub struct Compress {
    /// `Box` keeps the `z_stream` at a stable address; libz writes to it across calls.
    stream: Box<sys::z_stream>,
}

/// Outcome of a single [`Compress::deflate_tick`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateTick {
    /// Bytes written into the destination buffer during this call.
    pub written: usize,
    /// Bytes consumed from the source buffer during this call.
    pub consumed: usize,
    /// `true` iff libz returned `Z_STREAM_END` — the stream is fully flushed and the
    /// caller must not call `deflate_tick` again.
    pub stream_end: bool,
}

impl Compress {
    /// Initialize a new compressor with the legacy `deflateInit2_` parameters.
    ///
    /// `level` matches the user-facing compression level (`-1`..=`9`, where `-1` =
    /// `Z_DEFAULT_COMPRESSION`); `raw=false` produces gzip-wrapped output, `raw=true`
    /// produces zlib-wrapped output (this is how the legacy code uses the flag — note
    /// that despite the name, "raw" here does **not** mean header-less deflate; that
    /// would be `windowBits = -15`, which the legacy `gzCompressNew` never selects).
    ///
    /// Returns `Err(code)` with the raw zlib return code on initialization failure so
    /// the caller can hand it to the legacy `gzError` mapper.
    pub fn new(level: i32, raw: bool) -> Result<Self, i32> {
        let window_bits = if raw { WINDOW_BITS } else { WINDOW_BITS | WANT_GZ };

        // The `z_stream` must be zero-initialized so libz uses its default allocator
        // hooks. `zlib.h` documents that `zalloc = NULL`, `zfree = NULL`, `opaque = NULL`
        // tells `deflateInit2_` to install the built-in heap allocator — the zero pattern
        // is the documented init for the struct, even though Rust's `invalid_value` lint
        // rightly flags NULL function pointers as a general hazard.
        let mut stream: Box<sys::z_stream> = Box::new(zeroed_z_stream());

        let stream_size = i32::try_from(core::mem::size_of::<sys::z_stream>()).unwrap_or(i32::MAX);

        // SAFETY: `stream` points to a fresh, zero-initialized `z_stream` we own; libz
        // owns the writes from this point on. `zlibVersion()` returns a static
        // NUL-terminated string from the linked libz; passing the matching
        // `sizeof(z_stream)` is required by `deflateInit2_` to verify ABI compatibility.
        #[allow(unsafe_code)]
        let ret = unsafe {
            sys::deflateInit2_(
                ptr::from_mut(stream.as_mut()),
                level,
                sys::Z_DEFLATED,
                window_bits,
                MEM_LEVEL,
                sys::Z_DEFAULT_STRATEGY,
                sys::zlibVersion(),
                stream_size,
            )
        };

        if ret != sys::Z_OK {
            return Err(ret);
        }

        Ok(Self { stream })
    }

    /// Run one `deflate` call.
    ///
    /// `src` is the input slice (may be empty when flushing). `dst` is the output slice
    /// (must always have remaining capacity). `finish=true` switches to `Z_FINISH` mode,
    /// driving the encoder toward `Z_STREAM_END`.
    ///
    /// Returns the `(written, consumed, stream_end)` tuple. `Err(code)` carries the raw
    /// zlib return code on error so the caller can hand it to `gzError`.
    pub fn deflate_tick(&mut self, src: &[u8], dst: &mut [u8], finish: bool) -> Result<DeflateTick, i32> {
        // Point libz at the caller's buffers. Note that `next_in` is `*mut u8` in the
        // bindings even though the data is read-only; not all zlib builds accept const
        // input pointers, mirroring the same comment in the legacy C code.
        self.stream.next_in = src.as_ptr().cast_mut();
        self.stream.avail_in = u32::try_from(src.len()).unwrap_or(u32::MAX);
        self.stream.next_out = dst.as_mut_ptr();
        self.stream.avail_out = u32::try_from(dst.len()).unwrap_or(u32::MAX);

        let avail_in_before = self.stream.avail_in;
        let avail_out_before = self.stream.avail_out;

        let flush = if finish { sys::Z_FINISH } else { sys::Z_NO_FLUSH };

        // SAFETY: `self.stream` is a live `z_stream` previously initialized by
        // `deflateInit2_`. The slices outlive the call and we clear the back-pointers
        // before returning so libz never observes a dangling pointer between calls.
        #[allow(unsafe_code)]
        let ret = unsafe { sys::deflate(ptr::from_mut(self.stream.as_mut()), flush) };

        let written = (avail_out_before - self.stream.avail_out) as usize;
        let consumed = (avail_in_before - self.stream.avail_in) as usize;

        // Clear the borrowed pointers — the slices are about to die, and libz must not
        // dereference them until the caller hands us fresh slices on the next tick.
        self.stream.next_in = ptr::null_mut();
        self.stream.next_out = ptr::null_mut();
        self.stream.avail_in = 0;
        self.stream.avail_out = 0;

        match ret {
            sys::Z_OK => Ok(DeflateTick {
                written,
                consumed,
                stream_end: false,
            }),
            sys::Z_STREAM_END => Ok(DeflateTick {
                written,
                consumed,
                stream_end: true,
            }),
            // `deflate` may also return `Z_BUF_ERROR` when no progress is possible; the
            // legacy code routed this through `gzError` (an Assert), so propagate it as
            // an error code for the caller.
            _ => Err(ret),
        }
    }
}

impl Drop for Compress {
    fn drop(&mut self) {
        // SAFETY: `self.stream` was successfully initialized in `Compress::new`; calling
        // `deflateEnd` exactly once on a live stream is part of libz's contract. We
        // ignore the return code — it can only signal "stream was never used" or "stream
        // already ended", neither of which is actionable in a `Drop`.
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::deflateEnd(ptr::from_mut(self.stream.as_mut()));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::{Compress, MEM_LEVEL, WANT_GZ, WINDOW_BITS, sys};
    use core::ptr;

    /// Run a full compress→decompress round trip and assert the bytes round-trip.
    fn round_trip(level: i32, raw: bool, plaintext: &[u8]) -> Vec<u8> {
        let mut comp = Compress::new(level, raw).unwrap();

        // Compress in small chunks to exercise the partial-consumption path.
        let mut compressed = Vec::with_capacity(plaintext.len() + 256);
        let mut input_pos = 0;
        loop {
            let chunk_end = (input_pos + 16).min(plaintext.len());
            let src = &plaintext[input_pos..chunk_end];

            let mut dst = [0u8; 17]; // small dst forces multi-tick when src is partially consumed
            loop {
                let tick = comp.deflate_tick(src, &mut dst, false).unwrap();
                compressed.extend_from_slice(&dst[..tick.written]);
                input_pos += tick.consumed;
                if tick.consumed == src.len() || tick.written == 0 {
                    break;
                }
            }

            if input_pos >= plaintext.len() {
                break;
            }
        }

        // Flush.
        loop {
            let mut dst = [0u8; 19];
            let tick = comp.deflate_tick(&[], &mut dst, true).unwrap();
            compressed.extend_from_slice(&dst[..tick.written]);
            if tick.stream_end {
                break;
            }
        }

        // Decompress with libz directly so the test does not assume anything about the
        // Rust decompressor (which lives in a different phase). This validates that the
        // compressed bytes are valid zlib / gzip output.
        decompress_with_libz(raw, &compressed)
    }

    fn decompress_with_libz(raw: bool, compressed: &[u8]) -> Vec<u8> {
        let window_bits = if raw { WINDOW_BITS } else { WINDOW_BITS | WANT_GZ };
        let mut stream: sys::z_stream = super::zeroed_z_stream();
        let stream_size = i32::try_from(core::mem::size_of::<sys::z_stream>()).unwrap();
        let ret = unsafe { libz_sys::inflateInit2_(ptr::from_mut(&mut stream), window_bits, sys::zlibVersion(), stream_size) };
        assert_eq!(ret, sys::Z_OK, "inflateInit2_ failed");

        let mut out = Vec::with_capacity(1024);
        let mut buf = [0u8; 4096];
        let mut input_pos = 0;
        loop {
            stream.next_in = compressed[input_pos..].as_ptr().cast_mut();
            stream.avail_in = u32::try_from(compressed.len() - input_pos).unwrap();
            stream.next_out = buf.as_mut_ptr();
            stream.avail_out = u32::try_from(buf.len()).unwrap();

            let avail_in_before = stream.avail_in;
            let avail_out_before = stream.avail_out;
            let r = unsafe { libz_sys::inflate(ptr::from_mut(&mut stream), sys::Z_NO_FLUSH) };
            input_pos += (avail_in_before - stream.avail_in) as usize;
            out.extend_from_slice(&buf[..(avail_out_before - stream.avail_out) as usize]);

            stream.next_in = ptr::null_mut();
            stream.next_out = ptr::null_mut();

            if r == sys::Z_STREAM_END {
                break;
            }
            assert!(r >= 0, "inflate error: {r}");
            if input_pos >= compressed.len() && stream.avail_out == u32::try_from(buf.len()).unwrap() {
                break;
            }
        }
        unsafe {
            let _ = libz_sys::inflateEnd(ptr::from_mut(&mut stream));
        }
        out
    }

    #[test]
    fn roundtrip_simple_data_gzip() {
        let plaintext = b"A simple string";
        let decoded = round_trip(1, false, plaintext);
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn roundtrip_simple_data_zlib_wrapper() {
        let plaintext = b"A simple string";
        let decoded = round_trip(1, true, plaintext);
        assert_eq!(decoded, plaintext);
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
        // Encoding nothing must still emit a valid gzip / zlib stream that decodes to
        // an empty plaintext — same behaviour the legacy code's `gzCompressNew` ->
        // `Z_FINISH` path produces.
        let decoded = round_trip(1, false, &[]);
        assert!(decoded.is_empty());
        let decoded = round_trip(1, true, &[]);
        assert!(decoded.is_empty());
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
    fn deflate_init_rejects_invalid_level() {
        // libz `deflateInit2` returns `Z_STREAM_ERROR (-2)` for level outside [-1, 9].
        match Compress::new(99, false) {
            Ok(_) => panic!("expected error for invalid level"),
            Err(code) => assert_eq!(code, sys::Z_STREAM_ERROR),
        }
    }

    #[test]
    fn mem_level_constant_matches_c_header() {
        assert_eq!(MEM_LEVEL, 9);
        assert_eq!(WINDOW_BITS, 15);
        assert_eq!(WANT_GZ, 16);
    }
}
