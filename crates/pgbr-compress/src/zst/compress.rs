//! Streaming zstd compressor — Phase 24.
//!
//! Mirrors `src/common/compress/zst/compress.c`. Owns a `ZSTD_CStream` and exposes
//! `compress_stream` / `end_stream` calls so the C-side `IoFilter` wrapper can drive
//! it without seeing `<zstd.h>`.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    pub use zstd_sys::{
        ZSTD_CStream, ZSTD_compressStream, ZSTD_createCStream, ZSTD_endStream, ZSTD_freeCStream, ZSTD_inBuffer, ZSTD_initCStream,
        ZSTD_outBuffer,
    };
}

/// Streaming zstd compressor state.
pub struct Compress {
    /// Owned `ZSTD_CStream`. Released by `ZSTD_freeCStream` on drop.
    ctx: *mut sys::ZSTD_CStream,
}

/// Outcome of a single [`Compress::compress_stream`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressTick {
    /// Bytes written to `dst`.
    pub written: usize,
    /// Bytes consumed from `src`.
    pub consumed: usize,
}

/// Outcome of a single [`Compress::end_stream`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndTick {
    /// Bytes written to `dst`.
    pub written: usize,
    /// Bytes still queued internally — `0` means the trailer has been fully written
    /// and the stream is done.
    pub remaining: usize,
}

impl Compress {
    /// Allocate a fresh streaming zstd compressor with `level`.
    ///
    /// Returns `Err(code)` with the raw libzstd return code on failure so the caller
    /// can hand it to `zstError`.
    pub fn new(level: i32) -> Result<Self, usize> {
        // SAFETY: `ZSTD_createCStream` returns a heap-allocated context or null.
        #[allow(unsafe_code)]
        let ctx = unsafe { sys::ZSTD_createCStream() };
        if ctx.is_null() {
            // libzstd does not expose a code for OOM here; use an asserted "GENERIC"
            // sentinel that maps to `<unknown>` in the error classifier.
            #[allow(clippy::cast_sign_loss)]
            return Err(-1_isize as usize);
        }

        // SAFETY: `ctx` is a fresh, live context. `ZSTD_initCStream` returns either 0
        // or an `ZSTD_isError`-flagged value.
        #[allow(unsafe_code)]
        let code = unsafe { sys::ZSTD_initCStream(ctx, level) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            // SAFETY: free the just-allocated context.
            #[allow(unsafe_code)]
            unsafe {
                let _ = sys::ZSTD_freeCStream(ctx);
            }
            return Err(code);
        }

        Ok(Self { ctx })
    }

    /// Run `ZSTD_compressStream`. Returns the number of `(written, consumed)` bytes.
    /// `Err(code)` carries the raw libzstd return code on failure.
    pub fn compress_stream(&mut self, src: &[u8], dst: &mut [u8]) -> Result<CompressTick, usize> {
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

        // SAFETY: caller-owned slices outlive the call; libzstd reads / writes through
        // the in/out buffer structs which we just pointed at the slices.
        #[allow(unsafe_code)]
        let code = unsafe { sys::ZSTD_compressStream(self.ctx, ptr::from_mut(&mut output), ptr::from_mut(&mut input)) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            return Err(code);
        }

        Ok(CompressTick {
            written: output.pos,
            consumed: input.pos,
        })
    }

    /// Run `ZSTD_endStream` to write the frame trailer. `remaining == 0` means the
    /// frame is complete; non-zero means more `end_stream` calls are needed to drain
    /// libzstd's internal buffer.
    pub fn end_stream(&mut self, dst: &mut [u8]) -> Result<EndTick, usize> {
        let mut output = sys::ZSTD_outBuffer {
            dst: dst.as_mut_ptr().cast::<core::ffi::c_void>(),
            size: dst.len(),
            pos: 0,
        };

        // SAFETY: caller-owned slice outlives the call.
        #[allow(unsafe_code)]
        let code = unsafe { sys::ZSTD_endStream(self.ctx, ptr::from_mut(&mut output)) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            return Err(code);
        }

        Ok(EndTick {
            written: output.pos,
            remaining: code,
        })
    }
}

impl Drop for Compress {
    fn drop(&mut self) {
        if self.ctx.is_null() {
            return;
        }
        // SAFETY: `self.ctx` was created by `ZSTD_createCStream` and has not been
        // freed yet.
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::ZSTD_freeCStream(self.ctx);
        }
        self.ctx = ptr::null_mut();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::Compress;
    use core::ptr;

    /// Round-trip helper: compress with this module, decompress with libzstd directly.
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

        decompress_with_libzstd(&compressed)
    }

    fn decompress_with_libzstd(compressed: &[u8]) -> Vec<u8> {
        // SAFETY: standard libzstd init / decompress / free dance.
        let dctx = unsafe { zstd_sys::ZSTD_createDStream() };
        assert!(!dctx.is_null(), "ZSTD_createDStream returned null");
        let init = unsafe { zstd_sys::ZSTD_initDStream(dctx) };
        assert!(!matches!(
            super::super::error::classify(init),
            super::super::error::Classification::Throw { .. }
        ));

        let mut out = Vec::with_capacity(compressed.len() * 4 + 64);
        let mut buf = [0u8; 4096];
        let mut input_pos = 0;
        loop {
            let mut input = zstd_sys::ZSTD_inBuffer {
                src: compressed[input_pos..].as_ptr().cast::<core::ffi::c_void>(),
                size: compressed.len() - input_pos,
                pos: 0,
            };
            let mut output = zstd_sys::ZSTD_outBuffer {
                dst: buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                size: buf.len(),
                pos: 0,
            };
            let r = unsafe { zstd_sys::ZSTD_decompressStream(dctx, ptr::from_mut(&mut output), ptr::from_mut(&mut input)) };
            assert!(!matches!(
                super::super::error::classify(r),
                super::super::error::Classification::Throw { .. }
            ));
            input_pos += input.pos;
            out.extend_from_slice(&buf[..output.pos]);
            if r == 0 {
                break;
            }
        }
        unsafe {
            let _ = zstd_sys::ZSTD_freeDStream(dctx);
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
}
