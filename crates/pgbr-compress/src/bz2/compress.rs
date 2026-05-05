//! Streaming bzip2 compressor — Phase 21.
//!
//! Mirrors `src/common/compress/bz2/compress.c` — same `BZ2_bzCompressInit` parameters
//! (`workFactor = 0`, `verbosity = 0`), same `BZ2_bzCompress(..., BZ_RUN | BZ_FINISH)`
//! driving loop. Goes through `bzip2-sys` directly so the compressed bytes are
//! identical to the legacy path.
//!
//! The state machine that decides "more input?" / "flushing?" / "done?" stays on the C
//! side; this module exposes a thin single-tick API.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    pub use bzip2_sys::{BZ2_bzCompress, BZ2_bzCompressEnd, BZ2_bzCompressInit, bz_stream};
    pub const BZ_OK: i32 = 0;
    pub const BZ_RUN: i32 = 0;
    pub const BZ_FINISH: i32 = 2;
    pub const BZ_RUN_OK: i32 = 1;
    pub const BZ_FLUSH_OK: i32 = 2;
    pub const BZ_FINISH_OK: i32 = 3;
    pub const BZ_STREAM_END: i32 = 4;
}

#[allow(invalid_value, unsafe_code, clippy::uninit_assumed_init)]
const fn zeroed_bz_stream() -> sys::bz_stream {
    // SAFETY: `bzlib.h` documents NULL `bzalloc` / `bzfree` as the request for the
    // default heap allocator (mirrors zlib). The legacy C code does the same:
    // `{.bzalloc = NULL}`.
    unsafe { core::mem::MaybeUninit::<sys::bz_stream>::zeroed().assume_init() }
}

/// Streaming bzip2 compressor state.
pub struct Compress {
    /// `Box` keeps the `bz_stream` at a stable address; libbz2 writes to it across calls.
    stream: Box<sys::bz_stream>,
}

/// Outcome of a single [`Compress::compress_tick`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressTick {
    /// Bytes written to `dst`.
    pub written: usize,
    /// Bytes consumed from `src`.
    pub consumed: usize,
    /// `true` iff libbz2 returned `BZ_STREAM_END`.
    pub stream_end: bool,
}

impl Compress {
    /// Initialize a new compressor with the legacy `BZ2_bzCompressInit` parameters.
    ///
    /// `level` matches the user-facing compression level (`1..=9`). Returns `Err(code)`
    /// with the raw libbz2 return code on initialization failure so the caller can hand
    /// it to `bz2Error`.
    pub fn new(level: i32) -> Result<Self, i32> {
        let mut stream: Box<sys::bz_stream> = Box::new(zeroed_bz_stream());

        // SAFETY: `stream` points to a fresh, zero-initialized `bz_stream`. Pass
        // `verbosity = 0` and `workFactor = 0` to match the legacy call.
        #[allow(unsafe_code)]
        let ret = unsafe { sys::BZ2_bzCompressInit(ptr::from_mut(stream.as_mut()), level, 0, 0) };

        if ret != sys::BZ_OK {
            return Err(ret);
        }

        Ok(Self { stream })
    }

    /// Run one `BZ2_bzCompress` call.
    ///
    /// `src` is the input slice (may be empty when flushing). `dst` is the output slice
    /// (must always have remaining capacity). `finish=true` switches to `BZ_FINISH`,
    /// driving the encoder toward `BZ_STREAM_END`.
    ///
    /// Returns the `(written, consumed, stream_end)` tuple. `Err(code)` carries the raw
    /// libbz2 return code on error so the caller can hand it to `bz2Error`.
    pub fn compress_tick(&mut self, src: &[u8], dst: &mut [u8], finish: bool) -> Result<CompressTick, i32> {
        // libbz2's `next_in` is `*mut c_char`; the data is read-only but the API does
        // not accept const pointers (mirrors the same comment in the legacy C code).
        self.stream.next_in = src.as_ptr().cast_mut().cast::<core::ffi::c_char>();
        self.stream.avail_in = u32::try_from(src.len()).unwrap_or(u32::MAX);
        self.stream.next_out = dst.as_mut_ptr().cast::<core::ffi::c_char>();
        self.stream.avail_out = u32::try_from(dst.len()).unwrap_or(u32::MAX);

        let avail_in_before = self.stream.avail_in;
        let avail_out_before = self.stream.avail_out;

        let action = if finish { sys::BZ_FINISH } else { sys::BZ_RUN };

        // SAFETY: `self.stream` is a live `bz_stream` previously initialized by
        // `BZ2_bzCompressInit`. The slices outlive the call and we clear the
        // back-pointers before returning so libbz2 never observes a dangling pointer.
        #[allow(unsafe_code)]
        let ret = unsafe { sys::BZ2_bzCompress(ptr::from_mut(self.stream.as_mut()), action) };

        let written = (avail_out_before - self.stream.avail_out) as usize;
        let consumed = (avail_in_before - self.stream.avail_in) as usize;

        // Clear the borrowed pointers — the slices are about to die.
        self.stream.next_in = ptr::null_mut();
        self.stream.next_out = ptr::null_mut();
        self.stream.avail_in = 0;
        self.stream.avail_out = 0;

        match ret {
            // BZ_RUN_OK / BZ_FLUSH_OK / BZ_FINISH_OK are all "still working, call me
            // again" success codes; `BZ_STREAM_END` means the FINISH cycle is complete.
            sys::BZ_RUN_OK | sys::BZ_FLUSH_OK | sys::BZ_FINISH_OK => Ok(CompressTick {
                written,
                consumed,
                stream_end: false,
            }),
            sys::BZ_STREAM_END => Ok(CompressTick {
                written,
                consumed,
                stream_end: true,
            }),
            _ => Err(ret),
        }
    }
}

impl Drop for Compress {
    fn drop(&mut self) {
        // SAFETY: `self.stream` was initialized by `BZ2_bzCompressInit`. `BZ2_bzCompressEnd`
        // is the matching deallocator.
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::BZ2_bzCompressEnd(ptr::from_mut(self.stream.as_mut()));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::{Compress, sys, zeroed_bz_stream};
    use core::ptr;

    /// Round-trip helper: compress with this module, decompress with libbz2 directly.
    fn round_trip(level: i32, plaintext: &[u8]) -> Vec<u8> {
        let mut comp = Compress::new(level).unwrap();
        let mut compressed = Vec::with_capacity(plaintext.len() + 256);

        let mut input_pos = 0;
        while input_pos < plaintext.len() {
            let mut dst = [0u8; 64];
            let tick = comp.compress_tick(&plaintext[input_pos..], &mut dst, false).unwrap();
            compressed.extend_from_slice(&dst[..tick.written]);
            input_pos += tick.consumed;
        }
        loop {
            let mut dst = [0u8; 64];
            let tick = comp.compress_tick(&[], &mut dst, true).unwrap();
            compressed.extend_from_slice(&dst[..tick.written]);
            if tick.stream_end {
                break;
            }
        }

        decompress_with_libbz2(&compressed)
    }

    fn decompress_with_libbz2(compressed: &[u8]) -> Vec<u8> {
        let mut stream = zeroed_bz_stream();
        // SAFETY: `BZ2_bzDecompressInit` initializes the all-zero stream we own.
        let ret = unsafe { bzip2_sys::BZ2_bzDecompressInit(ptr::from_mut(&mut stream), 0, 0) };
        assert_eq!(ret, sys::BZ_OK, "bzDecompressInit failed");

        let mut out = Vec::with_capacity(compressed.len() * 4 + 64);
        let mut buf = [0u8; 4096];
        let mut input_pos = 0;
        loop {
            stream.next_in = compressed[input_pos..].as_ptr().cast_mut().cast::<core::ffi::c_char>();
            stream.avail_in = u32::try_from(compressed.len() - input_pos).unwrap();
            stream.next_out = buf.as_mut_ptr().cast::<core::ffi::c_char>();
            stream.avail_out = u32::try_from(buf.len()).unwrap();

            let avail_in_before = stream.avail_in;
            let avail_out_before = stream.avail_out;
            // SAFETY: `BZ2_bzDecompress` reads/writes the stream we just configured.
            let r = unsafe { bzip2_sys::BZ2_bzDecompress(ptr::from_mut(&mut stream)) };
            input_pos += (avail_in_before - stream.avail_in) as usize;
            out.extend_from_slice(&buf[..(avail_out_before - stream.avail_out) as usize]);

            stream.next_in = ptr::null_mut();
            stream.next_out = ptr::null_mut();

            if r == sys::BZ_STREAM_END {
                break;
            }
            assert!(r >= 0, "bzDecompress error: {r}");
        }
        // SAFETY: `stream` was initialized above and has not been freed yet.
        unsafe {
            let _ = bzip2_sys::BZ2_bzDecompressEnd(ptr::from_mut(&mut stream));
        }

        out
    }

    #[test]
    fn roundtrip_simple_data() {
        let plaintext = b"A simple string";
        assert_eq!(round_trip(1, plaintext), plaintext);
    }

    #[test]
    fn roundtrip_zero_byte_input() {
        // Empty bzip2 frame: still a valid stream that decodes to nothing.
        assert!(round_trip(1, &[]).is_empty());
    }

    #[test]
    fn roundtrip_all_levels() {
        let plaintext: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
        for level in 1..=9 {
            assert_eq!(round_trip(level, &plaintext), plaintext, "level={level}");
        }
    }

    #[test]
    fn roundtrip_large_pattern() {
        let mut plaintext = vec![0u8; 1024 * 1024 - 1];
        for (idx, b) in plaintext.iter_mut().enumerate() {
            *b = (idx % 94 + 32) as u8;
        }
        let decoded = round_trip(3, &plaintext);
        assert_eq!(decoded.len(), plaintext.len());
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn invalid_level_rejected() {
        match Compress::new(0) {
            Ok(_) => panic!("level 0 should be rejected"),
            Err(code) => assert_eq!(code, -2, "BZ_PARAM_ERROR"),
        }
        match Compress::new(10) {
            Ok(_) => panic!("level 10 should be rejected"),
            Err(code) => assert_eq!(code, -2, "BZ_PARAM_ERROR"),
        }
    }
}
