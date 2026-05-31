//! Streaming zstd decompressor — Phase 25.
//!
//! Mirrors `src/common/compress/zst/decompress.c`. Owns a `ZSTD_DStream` and exposes
//! `decompress_stream` so the C-side `IoFilter` wrapper can drive it without seeing
//! `<zstd.h>`.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    pub use zstd_sys::{
        ZSTD_DStream, ZSTD_createDStream, ZSTD_decompressStream, ZSTD_freeDStream, ZSTD_inBuffer, ZSTD_initDStream, ZSTD_outBuffer,
    };
}

/// Streaming zstd decompressor state.
pub struct Decompress {
    ctx: *mut sys::ZSTD_DStream,
}

/// Outcome of a single [`Decompress::decompress_stream`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompressTick {
    /// Bytes written to `dst`.
    pub written: usize,
    /// Bytes consumed from `src`.
    pub consumed: usize,
    /// libzstd's "next-call hint" — `0` means the current frame is complete.
    pub hint: usize,
}

impl Decompress {
    /// Allocate a fresh streaming zstd decompressor.
    pub fn new() -> Result<Self, usize> {
        // SAFETY: `ZSTD_createDStream` returns a heap-allocated context or null.
        #[allow(unsafe_code)]
        let ctx = unsafe { sys::ZSTD_createDStream() };
        if ctx.is_null() {
            #[allow(clippy::cast_sign_loss)]
            return Err(-1_isize as usize);
        }

        // SAFETY: `ctx` is fresh. `ZSTD_initDStream` returns 0 or an error code.
        #[allow(unsafe_code)]
        let code = unsafe { sys::ZSTD_initDStream(ctx) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            // SAFETY: free the just-allocated context.
            #[allow(unsafe_code)]
            unsafe {
                let _ = sys::ZSTD_freeDStream(ctx);
            }
            return Err(code);
        }

        Ok(Self { ctx })
    }

    /// Run `ZSTD_decompressStream`. Returns `(written, consumed, hint)`.
    pub fn decompress_stream(&mut self, src: &[u8], dst: &mut [u8]) -> Result<DecompressTick, usize> {
        let mut input = sys::ZSTD_inBuffer {
            src: src.as_ptr().cast::<core::ffi::c_void>(),
            size: src.len(),
            pos: 0,
        };
        let mut output = sys::ZSTD_outBuffer {
            dst: dst.as_mut_ptr().cast::<core::ffi::c_void>(),
            size: dst.len(),
            pos: 0,
        };

        // SAFETY: caller-owned slices outlive the call.
        #[allow(unsafe_code)]
        let code = unsafe { sys::ZSTD_decompressStream(self.ctx, ptr::from_mut(&mut output), ptr::from_mut(&mut input)) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            return Err(code);
        }

        Ok(DecompressTick {
            written: output.pos,
            consumed: input.pos,
            hint: code,
        })
    }
}

impl Drop for Decompress {
    fn drop(&mut self) {
        if self.ctx.is_null() {
            return;
        }
        // SAFETY: `self.ctx` was created by `ZSTD_createDStream`.
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::ZSTD_freeDStream(self.ctx);
        }
        self.ctx = ptr::null_mut();
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
            let tick = comp.compress_stream(&plaintext[input_pos..], &mut dst).unwrap();
            compressed.extend_from_slice(&dst[..tick.written]);
            input_pos += tick.consumed;
        }
        loop {
            let mut dst = [0u8; 64];
            let tick = comp.end_stream(&mut dst).unwrap();
            compressed.extend_from_slice(&dst[..tick.written]);
            if tick.remaining == 0 {
                break;
            }
        }

        let mut decomp = Decompress::new().unwrap();
        let mut out = Vec::with_capacity(plaintext.len() + 16);
        let mut buf = [0u8; 4096];
        let mut input_pos = 0;
        loop {
            let tick = decomp.decompress_stream(&compressed[input_pos..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..tick.written]);
            input_pos += tick.consumed;
            if tick.hint == 0 {
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
    fn roundtrip_various_levels() {
        let plaintext: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
        for level in [-1, 1, 3, 10, 19] {
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
        let garbage = b"this is not a zst stream at all and never will be it just isn't";
        let mut dst = [0u8; 64];
        match decomp.decompress_stream(garbage, &mut dst) {
            Ok(tick) => panic!("expected error, got {tick:?}"),
            Err(code) => assert!(
                matches!(
                    super::super::error::classify(code),
                    super::super::error::Classification::Throw { .. }
                ),
                "expected libzstd error, got code {code}"
            ),
        }
    }
}
