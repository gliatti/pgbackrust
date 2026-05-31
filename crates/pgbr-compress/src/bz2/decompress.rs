//! Streaming bzip2 decompressor — Phase 22.
//!
//! Mirrors `src/common/compress/bz2/decompress.c` — same `BZ2_bzDecompressInit`
//! parameters (`small = 0`, `verbosity = 0`), same `BZ2_bzDecompress` driving loop.
//! Routes through `bzip2-sys` directly so error codes and edge-case behaviour match
//! the legacy path byte-for-byte.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    pub use bzip2_sys::{BZ2_bzDecompress, BZ2_bzDecompressEnd, BZ2_bzDecompressInit, bz_stream};
    pub const BZ_OK: i32 = 0;
    pub const BZ_STREAM_END: i32 = 4;
}

#[allow(invalid_value, unsafe_code, clippy::uninit_assumed_init)]
const fn zeroed_bz_stream() -> sys::bz_stream {
    // SAFETY: same rationale as the compress sibling — NULL `bzalloc` / `bzfree` is the
    // documented "use the default allocator" request.
    unsafe { core::mem::MaybeUninit::<sys::bz_stream>::zeroed().assume_init() }
}

/// Streaming bzip2 decompressor state.
pub struct Decompress {
    stream: Box<sys::bz_stream>,
}

/// Outcome of a single [`Decompress::decompress_tick`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompressTick {
    /// Bytes written to `dst`.
    pub written: usize,
    /// Bytes consumed from `src`.
    pub consumed: usize,
    /// `true` iff libbz2 returned `BZ_STREAM_END`.
    pub stream_end: bool,
}

impl Decompress {
    /// Initialize a new decompressor with the legacy `BZ2_bzDecompressInit` parameters.
    pub fn new() -> Result<Self, i32> {
        let mut stream: Box<sys::bz_stream> = Box::new(zeroed_bz_stream());

        // SAFETY: `stream` points to a fresh, zero-initialized `bz_stream`. Pass
        // `verbosity = 0` and `small = 0` to match the legacy call.
        #[allow(unsafe_code)]
        let ret = unsafe { sys::BZ2_bzDecompressInit(ptr::from_mut(stream.as_mut()), 0, 0) };

        if ret != sys::BZ_OK {
            return Err(ret);
        }

        Ok(Self { stream })
    }

    /// Run one `BZ2_bzDecompress` call.
    ///
    /// Returns the `(written, consumed, stream_end)` tuple. `Err(code)` carries the raw
    /// libbz2 return code on error.
    pub fn decompress_tick(&mut self, src: &[u8], dst: &mut [u8]) -> Result<DecompressTick, i32> {
        self.stream.next_in = src.as_ptr().cast_mut().cast::<core::ffi::c_char>();
        self.stream.avail_in = u32::try_from(src.len()).unwrap_or(u32::MAX);
        self.stream.next_out = dst.as_mut_ptr().cast::<core::ffi::c_char>();
        self.stream.avail_out = u32::try_from(dst.len()).unwrap_or(u32::MAX);

        let avail_in_before = self.stream.avail_in;
        let avail_out_before = self.stream.avail_out;

        // SAFETY: `self.stream` is a live `bz_stream` previously initialized by
        // `BZ2_bzDecompressInit`. The slices outlive the call.
        #[allow(unsafe_code)]
        let ret = unsafe { sys::BZ2_bzDecompress(ptr::from_mut(self.stream.as_mut())) };

        let written = (avail_out_before - self.stream.avail_out) as usize;
        let consumed = (avail_in_before - self.stream.avail_in) as usize;

        self.stream.next_in = ptr::null_mut();
        self.stream.next_out = ptr::null_mut();
        self.stream.avail_in = 0;
        self.stream.avail_out = 0;

        match ret {
            sys::BZ_OK => Ok(DecompressTick {
                written,
                consumed,
                stream_end: false,
            }),
            sys::BZ_STREAM_END => Ok(DecompressTick {
                written,
                consumed,
                stream_end: true,
            }),
            _ => Err(ret),
        }
    }
}

impl Drop for Decompress {
    fn drop(&mut self) {
        // SAFETY: `self.stream` was initialized by `BZ2_bzDecompressInit`.
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::BZ2_bzDecompressEnd(ptr::from_mut(self.stream.as_mut()));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::super::compress::Compress;
    use super::Decompress;

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

        let mut decomp = Decompress::new().unwrap();
        let mut out = Vec::with_capacity(plaintext.len() + 16);
        let mut buf = [0u8; 4096];
        let mut input_pos = 0;
        loop {
            let tick = decomp.decompress_tick(&compressed[input_pos..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..tick.written]);
            input_pos += tick.consumed;
            if tick.stream_end {
                break;
            }
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
        assert_eq!(round_trip(3, &plaintext).len(), plaintext.len());
    }

    #[test]
    fn corrupt_data_yields_error() {
        let mut decomp = Decompress::new().unwrap();
        let garbage = b"this is not a bz2 stream at all and never will be it just isn't";
        let mut dst = [0u8; 64];
        match decomp.decompress_tick(garbage, &mut dst) {
            Ok(tick) => panic!("expected error, got {tick:?}"),
            Err(code) => assert!(code < 0, "expected libbz2 error code, got {code}"),
        }
    }
}
