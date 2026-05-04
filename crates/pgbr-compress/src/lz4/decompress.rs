//! Streaming LZ4-frame decompressor — Phase 19.
//!
//! Mirrors `src/common/compress/lz4/decompress.c`. Owns an
//! `LZ4F_decompressionContext_t` and exposes the legacy `decompress` call shape
//! (`LZ4F_decompress` returning `srcConsumed` / `dstWritten` plus a hint for the next
//! call) so the C-side `IoFilter` wrapper can drive it without seeing `<lz4frame.h>`.
//!
//! The buffer-cursor state in the legacy `lz4DecompressProcess` (the `inputOffset` /
//! `inputSame` / `frameDone` / `done` flags) stays on the C side because it plugs into
//! pgBackRust's `IoFilter` framework — this module just wraps the liblz4 calls behind
//! a safe Rust API.

use core::ptr;

#[allow(unsafe_code)]
mod sys {
    pub use lz4_sys::{
        LZ4F_VERSION, LZ4F_createDecompressionContext, LZ4F_decompress, LZ4F_freeDecompressionContext, LZ4FDecompressionContext,
    };
}

/// Streaming LZ4-frame decompressor state.
///
/// Construction creates a fresh `LZ4F_decompressionContext_t`, drop releases it.
pub struct Decompress {
    /// Opaque handle into liblz4's allocation. Must be released exactly once via
    /// `LZ4F_freeDecompressionContext` on drop.
    ctx: sys::LZ4FDecompressionContext,
}

/// Outcome of a single [`Decompress::decompress_tick`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompressTick {
    /// Bytes actually written to the destination buffer.
    pub written: usize,
    /// Bytes actually consumed from the source buffer.
    pub consumed: usize,
    /// liblz4's "next-call hint" — `0` means the previously-decompressed frame is
    /// complete; non-zero means the caller must keep feeding more compressed bytes.
    /// The legacy code maps `hint == 0` to `frameDone = true`.
    pub hint: usize,
}

impl Decompress {
    /// Allocate a fresh streaming LZ4-frame decompressor.
    ///
    /// Returns `Err(code)` with the raw `LZ4F_errorCode_t` on failure so the caller can
    /// hand it to `lz4Error`. The legacy `lz4DecompressNew` ignores the `raw` flag —
    /// liblz4 detects the frame variant from the input header automatically — so this
    /// constructor takes no parameters.
    pub fn new() -> Result<Self, usize> {
        let mut ctx = sys::LZ4FDecompressionContext(ptr::null_mut());

        // SAFETY: `LZ4F_createDecompressionContext` writes `ctx` and returns either 0
        // on success or an `LZ4F_isError`-flagged value on failure. We pass the
        // documented `LZ4F_VERSION` constant.
        #[allow(unsafe_code)]
        let code = unsafe { sys::LZ4F_createDecompressionContext(&mut ctx, sys::LZ4F_VERSION) };

        if matches!(super::error::classify(code), super::error::Classification::Throw { .. }) {
            return Err(code);
        }

        Ok(Self { ctx })
    }

    /// Run one `LZ4F_decompress` call.
    ///
    /// Reads from `src`, writes to `dst`, returns the `(written, consumed, hint)` tuple.
    /// `hint == 0` means the current frame is complete. `Err(code)` carries the raw
    /// `LZ4F_errorCode_t` on failure.
    pub fn decompress_tick(&mut self, src: &[u8], dst: &mut [u8]) -> Result<DecompressTick, usize> {
        let mut src_size = src.len();
        let mut dst_size = dst.len();

        // SAFETY: caller-owned slices; liblz4 reads `src_size` bytes, writes up to
        // `dst_size` bytes, and updates both in-place to reflect actual consumption /
        // production. The hint return value tells the caller how to size their next
        // input chunk.
        #[allow(unsafe_code)]
        let hint = unsafe {
            sys::LZ4F_decompress(
                self.ctx,
                dst.as_mut_ptr(),
                &mut dst_size,
                src.as_ptr(),
                &mut src_size,
                ptr::null(),
            )
        };

        if matches!(super::error::classify(hint), super::error::Classification::Throw { .. }) {
            return Err(hint);
        }

        Ok(DecompressTick {
            written: dst_size,
            consumed: src_size,
            hint,
        })
    }
}

impl Drop for Decompress {
    fn drop(&mut self) {
        if self.ctx.0.is_null() {
            return;
        }
        // SAFETY: `self.ctx` came from `LZ4F_createDecompressionContext` and has not
        // been freed yet. Move the handle out so the post-drop sentinel cannot
        // accidentally double-free.
        let ctx = core::mem::replace(&mut self.ctx, sys::LZ4FDecompressionContext(core::ptr::null_mut()));
        #[allow(unsafe_code)]
        unsafe {
            let _ = sys::LZ4F_freeDecompressionContext(ctx);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::super::compress::Compress;
    use super::Decompress;

    /// Compress `plaintext` with the sibling `lz4::compress::Compress` (so the bytes
    /// match the legacy LZ4F encoder) and decompress with this module. Asserts the
    /// round-trip recovers the original bytes.
    fn round_trip(level: i32, raw: bool, plaintext: &[u8]) -> Vec<u8> {
        // Compress (one-shot — same approach as the compress module's tests).
        let mut comp = Compress::new(level, raw).unwrap();
        let bound = comp.compress_bound(plaintext.len());
        let mut frame = vec![0u8; bound + 19];
        let mut total = 0;
        total += comp.compress_begin(&mut frame[total..]).unwrap();
        if !plaintext.is_empty() {
            total += comp.compress_update(plaintext, &mut frame[total..]).unwrap();
        }
        total += comp.compress_end(&mut frame[total..]).unwrap();
        frame.truncate(total);

        // Decompress.
        let mut decomp = Decompress::new().unwrap();
        let mut out = Vec::with_capacity(plaintext.len() + 16);
        let mut buf = [0u8; 4096];
        let mut input_pos = 0;
        loop {
            let tick = decomp.decompress_tick(&frame[input_pos..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..tick.written]);
            input_pos += tick.consumed;
            if tick.hint == 0 {
                break;
            }
            assert!(input_pos <= frame.len(), "decompress_tick consumed past end of frame");
        }
        out
    }

    #[test]
    fn roundtrip_simple_data() {
        let plaintext = b"A simple string";
        for raw in [false, true] {
            assert_eq!(round_trip(1, raw, plaintext), plaintext);
        }
    }

    #[test]
    fn roundtrip_zero_byte_input() {
        for raw in [false, true] {
            let decoded = round_trip(1, raw, &[]);
            assert!(decoded.is_empty(), "raw={raw}");
        }
    }

    #[test]
    fn roundtrip_all_levels() {
        let plaintext: Vec<u8> = (0..4096_u32).map(|i| (i % 251) as u8).collect();
        for level in [-5, -1, 0, 1, 6, 9, 12] {
            for raw in [false, true] {
                assert_eq!(round_trip(level, raw, &plaintext), plaintext, "level={level} raw={raw}");
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
            assert_eq!(round_trip(3, raw, &plaintext).len(), plaintext.len(), "raw={raw}");
        }
    }

    #[test]
    fn corrupt_data_yields_error() {
        let mut decomp = Decompress::new().unwrap();
        let garbage = b"this is not an lz4 frame at all and never will be it just isn't";
        let mut dst = [0u8; 64];
        match decomp.decompress_tick(garbage, &mut dst) {
            Ok(tick) => panic!("expected error, got {tick:?}"),
            Err(code) => {
                assert!(matches!(
                    super::super::error::classify(code),
                    super::super::error::Classification::Throw { .. }
                ));
            }
        }
    }
}
