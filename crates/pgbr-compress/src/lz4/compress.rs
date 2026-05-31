//! Streaming LZ4-frame compressor — Phase 18.
//!
//! Mirrors `src/common/compress/lz4/compress.c`. Owns an `LZ4F_compressionContext_t`
//! plus the legacy `LZ4F_preferences_t` (only `compressionLevel` and
//! `contentChecksumFlag` diverge from zero, exactly as the C side configured them) and
//! exposes the same `compress_begin` / `compress_update` / `compress_end` /
//! `compress_bound` / `free_context` call shape so the C-side `IoFilter` wrapper can
//! drive it without seeing `<lz4frame.h>`.
//!
//! The buffer-management state machine in the legacy `lz4CompressProcess` (the internal
//! overflow `Buffer*`, the `inputSame` / `flushing` / `first` flags) stays on the C side
//! because it plugs into pgBackRust's `IoFilter` — this module just wraps the liblz4
//! calls behind a safe Rust API.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    pub use lz4_sys::{
        BlockChecksum, BlockMode, BlockSize, ContentChecksum, FrameType, LZ4F_VERSION, LZ4F_compressBegin, LZ4F_compressBound,
        LZ4F_compressEnd, LZ4F_compressUpdate, LZ4F_createCompressionContext, LZ4F_freeCompressionContext, LZ4FCompressionContext,
        LZ4FFrameInfo, LZ4FPreferences,
    };
}

/// Streaming LZ4-frame compressor state.
///
/// Construction creates a fresh `LZ4F_compressionContext_t`, drop releases it. Cloning
/// is not supported (`LZ4F_compressionContext_t` is an opaque handle that can be used
/// by exactly one stream at a time).
pub struct Compress {
    /// Opaque handle into liblz4's allocation. Must be released exactly once via
    /// `LZ4F_freeCompressionContext` on drop.
    ctx: sys::LZ4FCompressionContext,
    /// Stable preferences — only `compressionLevel` and `contentChecksumFlag` diverge
    /// from the all-zero default to match the legacy C struct initializer.
    prefs: sys::LZ4FPreferences,
}

impl Compress {
    /// Allocate a fresh streaming LZ4-frame compressor.
    ///
    /// `level` matches the legacy `lz4CompressNew` parameter (`-5..=12`). `raw=false`
    /// enables LZ4's frame content checksum (the default for all callers); `raw=true`
    /// disables it (used for "raw" frames embedded in the pgBackRest block-incremental
    /// repository format). Returns `Err(code)` with the raw `LZ4F_errorCode_t` on
    /// failure so the caller can hand it to `lz4Error`.
    pub fn new(level: i32, raw: bool) -> Result<Self, usize> {
        let prefs = sys::LZ4FPreferences {
            frame_info: sys::LZ4FFrameInfo {
                block_size_id: sys::BlockSize::Default,
                block_mode: sys::BlockMode::Linked,
                content_checksum_flag: if raw {
                    sys::ContentChecksum::NoChecksum
                } else {
                    sys::ContentChecksum::ChecksumEnabled
                },
                frame_type: sys::FrameType::Frame,
                content_size: 0,
                dict_id: 0,
                block_checksum_flag: sys::BlockChecksum::NoBlockChecksum,
            },
            #[allow(clippy::cast_sign_loss)]
            compression_level: level as u32,
            auto_flush: 0,
            favor_dec_speed: 0,
            reserved: [0; 3],
        };

        let mut ctx = sys::LZ4FCompressionContext(ptr::null_mut());

        // SAFETY: `LZ4F_createCompressionContext` writes `ctx` and returns either 0 on
        // success or an `LZ4F_isError`-flagged value on failure. We pass the documented
        // `LZ4F_VERSION` constant.
        #[allow(unsafe_code)]
        let code = unsafe { sys::LZ4F_createCompressionContext(&mut ctx, sys::LZ4F_VERSION) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            return Err(code);
        }

        Ok(Self { ctx, prefs })
    }

    /// Worst-case compressed size for `src_size` source bytes through this preference
    /// set. Mirrors `LZ4F_compressBound(src_size, &prefs)`. The value is used by the C
    /// side to size its destination buffer so a single `compressUpdate` call always has
    /// somewhere to put its output.
    #[must_use]
    pub fn compress_bound(&self, src_size: usize) -> usize {
        // SAFETY: `LZ4F_compressBound` reads `&prefs` and returns a size_t; it has no
        // failure mode beyond returning an `LZ4F_isError`-flagged value, which we treat
        // exactly like a real `compressBound` value (the C caller routes the result
        // through `lz4Error` regardless).
        #[allow(unsafe_code)]
        unsafe {
            sys::LZ4F_compressBound(src_size, core::ptr::from_ref(&self.prefs))
        }
    }

    /// Write the LZ4 frame header into `dst` and return the number of bytes written.
    ///
    /// Wraps `LZ4F_compressBegin`. Returns `Err(code)` with the raw `LZ4F_errorCode_t`
    /// on failure.
    pub fn compress_begin(&mut self, dst: &mut [u8]) -> Result<usize, usize> {
        // SAFETY: caller-owned slice; we pass the documented `dstMaxSize`. liblz4
        // returns either the byte count written or an `LZ4F_isError`-flagged code.
        #[allow(unsafe_code)]
        let code = unsafe { sys::LZ4F_compressBegin(self.ctx, dst.as_mut_ptr(), dst.len(), core::ptr::from_ref(&self.prefs)) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            Err(code)
        } else {
            Ok(code)
        }
    }

    /// Compress `src` into `dst` and return the number of bytes written. May write zero
    /// bytes if liblz4 buffers the input internally.
    ///
    /// Wraps `LZ4F_compressUpdate`. Returns `Err(code)` with the raw `LZ4F_errorCode_t`
    /// on failure.
    pub fn compress_update(&mut self, src: &[u8], dst: &mut [u8]) -> Result<usize, usize> {
        // SAFETY: caller-owned slices; liblz4 reads `src` and writes `dst` honouring the
        // sizes we pass.
        #[allow(unsafe_code)]
        let code = unsafe { sys::LZ4F_compressUpdate(self.ctx, dst.as_mut_ptr(), dst.len(), src.as_ptr(), src.len(), ptr::null()) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            Err(code)
        } else {
            Ok(code)
        }
    }

    /// Flush any buffered data and write the LZ4 frame trailer into `dst`. Returns the
    /// number of bytes written.
    ///
    /// Wraps `LZ4F_compressEnd`. Returns `Err(code)` with the raw `LZ4F_errorCode_t` on
    /// failure.
    pub fn compress_end(&mut self, dst: &mut [u8]) -> Result<usize, usize> {
        // SAFETY: same contract as `compress_update`.
        #[allow(unsafe_code)]
        let code = unsafe { sys::LZ4F_compressEnd(self.ctx, dst.as_mut_ptr(), dst.len(), ptr::null()) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            Err(code)
        } else {
            Ok(code)
        }
    }

    /// Compression level the context was constructed with — exposed so the C wrapper
    /// can echo it in `lz4CompressToLog` without storing the prefs struct twice.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn level(&self) -> i32 {
        self.prefs.compression_level as i32
    }
}

impl Drop for Compress {
    fn drop(&mut self) {
        if self.ctx.0.is_null() {
            return;
        }
        // SAFETY: `self.ctx` came from `LZ4F_createCompressionContext` and has not been
        // freed yet. liblz4 documents this call as the matching deallocator. Move the
        // handle out (rather than passing a copy) so the post-drop sentinel below cannot
        // accidentally double-free.
        let ctx = core::mem::replace(&mut self.ctx, sys::LZ4FCompressionContext(core::ptr::null_mut()));
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::LZ4F_freeCompressionContext(ctx);
        }
    }
}

/// Convenience helper used by the test code to predicate against
/// `super::error::Classification`. Mirrors the legacy `LZ4F_isError(code) == 0` check.
#[cfg(test)]
trait ClassificationExt {
    fn is_err(&self) -> bool;
}

#[cfg(test)]
impl ClassificationExt for super::error::Classification<'_> {
    fn is_err(&self) -> bool {
        matches!(self, super::error::Classification::Throw { .. })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::{ClassificationExt, Compress};

    /// Compress `plaintext` end-to-end through this module and return the resulting
    /// frame. Matches what the C `IoFilter` would emit for the same `(level, raw,
    /// plaintext)` triple when the destination buffer is large enough to hold every
    /// chunk.
    fn compress_one_shot(level: i32, raw: bool, plaintext: &[u8]) -> Vec<u8> {
        let mut comp = Compress::new(level, raw).unwrap();
        let bound = comp.compress_bound(plaintext.len());
        let header_max = 19_usize;
        let mut out = vec![0u8; bound + header_max];

        let mut total = 0;
        total += comp.compress_begin(&mut out[total..]).unwrap();
        total += comp.compress_update(plaintext, &mut out[total..]).unwrap();
        total += comp.compress_end(&mut out[total..]).unwrap();

        out.truncate(total);
        out
    }

    /// Decompress an LZ4 frame produced by `compress_one_shot` using lz4-sys's frame
    /// decompressor; the round-trip checks correctness without depending on the Phase
    /// 19 pgbr-compress decompressor (which has not been written yet).
    fn decompress_with_lz4_frame(frame: &[u8]) -> Vec<u8> {
        use core::ptr;

        let mut dctx = lz4_sys::LZ4FDecompressionContext(ptr::null_mut());
        // SAFETY: `LZ4F_createDecompressionContext` writes `dctx` and returns 0 on
        // success or an `LZ4F_isError`-flagged value on failure.
        let code = unsafe { lz4_sys::LZ4F_createDecompressionContext(&mut dctx, lz4_sys::LZ4F_VERSION) };
        assert!(!super::super::error::classify(code).is_err(), "createDctx failed: {code}");

        let mut out = Vec::with_capacity(frame.len() * 4 + 64);
        let mut buf = [0u8; 4096];

        let mut input_pos = 0;
        loop {
            let mut dst_size = buf.len();
            let mut src_size = frame.len() - input_pos;
            // SAFETY: `LZ4F_decompress` reads `src_size` bytes and writes up to
            // `dst_size` bytes; it returns an `LZ4F_isError`-flagged code on failure or
            // 0 (== end-of-frame) / >0 (== more bytes wanted) on success.
            let code = unsafe {
                lz4_sys::LZ4F_decompress(
                    dctx,
                    buf.as_mut_ptr(),
                    &mut dst_size,
                    frame.as_ptr().add(input_pos),
                    &mut src_size,
                    ptr::null(),
                )
            };
            assert!(!super::super::error::classify(code).is_err(), "decompress error: {code}");
            out.extend_from_slice(&buf[..dst_size]);
            input_pos += src_size;
            if code == 0 {
                break;
            }
        }

        // SAFETY: `dctx` was created above and has not been freed yet.
        unsafe {
            let _ = lz4_sys::LZ4F_freeDecompressionContext(dctx);
        }

        out
    }

    #[test]
    fn roundtrip_simple_data() {
        let plaintext = b"A simple string";
        for raw in [false, true] {
            let frame = compress_one_shot(1, raw, plaintext);
            let decoded = decompress_with_lz4_frame(&frame);
            assert_eq!(decoded, plaintext, "raw={raw}");
        }
    }

    #[test]
    fn roundtrip_zero_byte_input() {
        for raw in [false, true] {
            let frame = compress_one_shot(1, raw, &[]);
            let decoded = decompress_with_lz4_frame(&frame);
            assert!(decoded.is_empty(), "raw={raw}");
        }
    }

    #[test]
    fn roundtrip_all_levels() {
        let plaintext: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
        for level in [-5, -1, 0, 1, 6, 9, 12] {
            for raw in [false, true] {
                let frame = compress_one_shot(level, raw, &plaintext);
                let decoded = decompress_with_lz4_frame(&frame);
                assert_eq!(decoded, plaintext, "level={level} raw={raw}");
            }
        }
    }

    #[test]
    fn roundtrip_large_pattern() {
        let mut plaintext = vec![0u8; 1024 * 1024 - 1];
        for (idx, b) in plaintext.iter_mut().enumerate() {
            *b = (idx % 94 + 32) as u8;
        }
        for raw in [false, true] {
            let frame = compress_one_shot(3, raw, &plaintext);
            let decoded = decompress_with_lz4_frame(&frame);
            assert_eq!(decoded.len(), plaintext.len(), "raw={raw}");
            assert_eq!(decoded, plaintext, "raw={raw}");
        }
    }

    #[test]
    fn level_getter() {
        let comp = Compress::new(7, false).unwrap();
        assert_eq!(comp.level(), 7);
    }
}
