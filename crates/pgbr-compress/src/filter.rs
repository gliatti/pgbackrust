//! [`pgbr_io::Filter`] adapters for the compression codecs.
//!
//! Each codec in this crate (`gz`, `bz2`, `lz4`, `zst`) exposes a streaming,
//! tick-based API that partially consumes input and partially fills an output
//! buffer per call. This module wraps each one in a compressing and a
//! decompressing [`Filter`] so the codecs compose inside a
//! [`pgbr_io::FilterChain`] — the building block for the compressed
//! repo-get / repo-put / archive paths.
//!
//! # Implementation note (buffering)
//!
//! Like [`pgbr_io::filter::Cipher`], these adapters accumulate the entire input
//! in [`Filter::process`] and perform the compress / decompress one-shot inside
//! [`Filter::finish`]. Driving the codec's tick loop to completion over the
//! whole buffer in one place sidesteps the partial-consumption / output-stall
//! bookkeeping that a true chunked codepath would need (a tick may consume only
//! part of `src`, or fill `dst` before consuming any input). The compressed
//! bytes on the wire are unaffected by this choice; chunked block-streaming is a
//! future refinement. The caveat is that the full input — and full output — are
//! held in memory at once, so these adapters are not suited to inputs larger
//! than available RAM.

use pgbr_io::{Filter, IoError};

use crate::{bz2, gz, lz4, zst};

/// Scratch buffer size for one codec tick. Large enough to amortize the
/// per-call overhead while keeping the transient allocation modest.
const TICK_BUF: usize = 64 * 1024;

/// gzip-wrapped deflate compressing filter (`gz::compress::Compress`).
///
/// Buffers input in `process`; compresses in `finish`. `raw=false` emits
/// gzip-framed output, `raw=true` emits zlib-wrapped output — matching the
/// flag's meaning in [`gz::compress::Compress::new`].
pub struct GzCompress {
    level: i32,
    raw: bool,
    pending: Vec<u8>,
}

impl GzCompress {
    /// Build a gzip compressing filter at `level` (`-1`..=`9`).
    #[must_use]
    pub const fn new(level: i32, raw: bool) -> Self {
        Self {
            level,
            raw,
            pending: Vec::new(),
        }
    }
}

impl Filter for GzCompress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut comp = gz::compress::Compress::new(self.level, self.raw)
            .map_err(|code| IoError::Backend(format!("gz compress init failed: zlib code {code}")))?;

        // Feed the buffered input, then flush. The deflate tick may consume only
        // part of `src` or fill `dst` before consuming any input, so loop until
        // every byte is consumed and the encoder reports `stream_end`.
        let mut buf = vec![0u8; TICK_BUF];
        let mut pos = 0;
        while pos < self.pending.len() {
            let tick = comp
                .deflate_tick(&self.pending[pos..], &mut buf, false)
                .map_err(|code| IoError::Backend(format!("gz deflate failed: zlib code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            pos += tick.consumed;
            if tick.consumed == 0 && tick.written == 0 {
                return Err(IoError::Backend("gz deflate made no progress".to_owned()));
            }
        }
        loop {
            let tick = comp
                .deflate_tick(&[], &mut buf, true)
                .map_err(|code| IoError::Backend(format!("gz deflate flush failed: zlib code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            if tick.stream_end {
                break;
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "gz-compress"
    }
}

/// gzip-wrapped deflate decompressing filter (`gz::decompress::Decompress`).
///
/// `raw` must match the value the matching [`GzCompress`] was built with.
pub struct GzDecompress {
    raw: bool,
    pending: Vec<u8>,
}

impl GzDecompress {
    /// Build a gzip decompressing filter. `raw=false` expects gzip-framed
    /// input, `raw=true` expects zlib-wrapped input.
    #[must_use]
    pub const fn new(raw: bool) -> Self {
        Self {
            raw,
            pending: Vec::new(),
        }
    }
}

impl Filter for GzDecompress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut decomp = gz::decompress::Decompress::new(self.raw)
            .map_err(|code| IoError::Backend(format!("gz decompress init failed: zlib code {code}")))?;

        let mut buf = vec![0u8; TICK_BUF];
        let mut pos = 0;
        loop {
            let tick = decomp
                .inflate_tick(&self.pending[pos..], &mut buf)
                .map_err(|code| IoError::Backend(format!("gz inflate failed: zlib code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            pos += tick.consumed;
            if tick.stream_end {
                break;
            }
            if tick.consumed == 0 && tick.written == 0 {
                return Err(IoError::Backend("gz inflate truncated or made no progress".to_owned()));
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "gz-decompress"
    }
}

/// bzip2 compressing filter (`bz2::compress::Compress`).
///
/// Buffers input in `process`; compresses in `finish`.
pub struct Bz2Compress {
    level: i32,
    pending: Vec<u8>,
}

impl Bz2Compress {
    /// Build a bzip2 compressing filter at `level` (`1`..=`9`).
    #[must_use]
    pub const fn new(level: i32) -> Self {
        Self {
            level,
            pending: Vec::new(),
        }
    }
}

impl Filter for Bz2Compress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut comp = bz2::compress::Compress::new(self.level)
            .map_err(|code| IoError::Backend(format!("bz2 compress init failed: libbz2 code {code}")))?;

        let mut buf = vec![0u8; TICK_BUF];
        let mut pos = 0;
        while pos < self.pending.len() {
            let tick = comp
                .compress_tick(&self.pending[pos..], &mut buf, false)
                .map_err(|code| IoError::Backend(format!("bz2 compress failed: libbz2 code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            pos += tick.consumed;
            if tick.consumed == 0 && tick.written == 0 {
                return Err(IoError::Backend("bz2 compress made no progress".to_owned()));
            }
        }
        loop {
            let tick = comp
                .compress_tick(&[], &mut buf, true)
                .map_err(|code| IoError::Backend(format!("bz2 compress flush failed: libbz2 code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            if tick.stream_end {
                break;
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "bz2-compress"
    }
}

/// bzip2 decompressing filter (`bz2::decompress::Decompress`).
pub struct Bz2Decompress {
    pending: Vec<u8>,
}

impl Bz2Decompress {
    /// Build a bzip2 decompressing filter.
    #[must_use]
    pub const fn new() -> Self {
        Self { pending: Vec::new() }
    }
}

impl Default for Bz2Decompress {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter for Bz2Decompress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut decomp = bz2::decompress::Decompress::new()
            .map_err(|code| IoError::Backend(format!("bz2 decompress init failed: libbz2 code {code}")))?;

        let mut buf = vec![0u8; TICK_BUF];
        let mut pos = 0;
        loop {
            let tick = decomp
                .decompress_tick(&self.pending[pos..], &mut buf)
                .map_err(|code| IoError::Backend(format!("bz2 decompress failed: libbz2 code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            pos += tick.consumed;
            if tick.stream_end {
                break;
            }
            if tick.consumed == 0 && tick.written == 0 {
                return Err(IoError::Backend("bz2 decompress truncated or made no progress".to_owned()));
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "bz2-decompress"
    }
}

/// LZ4-frame compressing filter (`lz4::compress::Compress`).
///
/// Buffers input in `process`; compresses in `finish`. `raw=false` enables the
/// LZ4 frame content checksum (the default), `raw=true` disables it.
pub struct Lz4Compress {
    level: i32,
    raw: bool,
    pending: Vec<u8>,
}

impl Lz4Compress {
    /// Build an LZ4-frame compressing filter at `level` (`-5`..=`12`).
    #[must_use]
    pub const fn new(level: i32, raw: bool) -> Self {
        Self {
            level,
            raw,
            pending: Vec::new(),
        }
    }
}

impl Filter for Lz4Compress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut comp = lz4::compress::Compress::new(self.level, self.raw)
            .map_err(|code| IoError::Backend(format!("lz4 compress init failed: liblz4 code {code}")))?;

        // `compress_bound` reports the worst-case size for one `compress_update`;
        // size the destination for header + body + trailer so each call has room.
        let header_max = 19_usize;
        let trailer_max = 8_usize;
        let bound = comp.compress_bound(self.pending.len());
        let mut frame = vec![0u8; header_max + bound + trailer_max];

        let mut total = comp
            .compress_begin(&mut frame)
            .map_err(|code| IoError::Backend(format!("lz4 compress begin failed: liblz4 code {code}")))?;
        if !self.pending.is_empty() {
            total += comp
                .compress_update(&self.pending, &mut frame[total..])
                .map_err(|code| IoError::Backend(format!("lz4 compress update failed: liblz4 code {code}")))?;
        }
        total += comp
            .compress_end(&mut frame[total..])
            .map_err(|code| IoError::Backend(format!("lz4 compress end failed: liblz4 code {code}")))?;

        out.extend_from_slice(&frame[..total]);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "lz4-compress"
    }
}

/// LZ4-frame decompressing filter (`lz4::decompress::Decompress`).
///
/// liblz4 detects the frame variant from the header, so there is no `raw`
/// parameter — one decompressing filter handles both `Lz4Compress` modes.
pub struct Lz4Decompress {
    pending: Vec<u8>,
}

impl Lz4Decompress {
    /// Build an LZ4-frame decompressing filter.
    #[must_use]
    pub const fn new() -> Self {
        Self { pending: Vec::new() }
    }
}

impl Default for Lz4Decompress {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter for Lz4Decompress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut decomp = lz4::decompress::Decompress::new()
            .map_err(|code| IoError::Backend(format!("lz4 decompress init failed: liblz4 code {code}")))?;

        let mut buf = vec![0u8; TICK_BUF];
        let mut pos = 0;
        loop {
            let tick = decomp
                .decompress_tick(&self.pending[pos..], &mut buf)
                .map_err(|code| IoError::Backend(format!("lz4 decompress failed: liblz4 code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            pos += tick.consumed;
            // hint == 0 means the frame is complete.
            if tick.hint == 0 {
                break;
            }
            if tick.consumed == 0 && tick.written == 0 {
                return Err(IoError::Backend("lz4 decompress truncated or made no progress".to_owned()));
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "lz4-decompress"
    }
}

/// zstd compressing filter (`zst::compress::Compress`).
///
/// Buffers input in `process`; compresses in `finish`.
pub struct ZstCompress {
    level: i32,
    pending: Vec<u8>,
}

impl ZstCompress {
    /// Build a zstd compressing filter at `level`.
    #[must_use]
    pub const fn new(level: i32) -> Self {
        Self {
            level,
            pending: Vec::new(),
        }
    }
}

impl Filter for ZstCompress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut comp = zst::compress::Compress::new(self.level)
            .map_err(|code| IoError::Backend(format!("zst compress init failed: libzstd code {code}")))?;

        let mut buf = vec![0u8; TICK_BUF];
        let mut pos = 0;
        while pos < self.pending.len() {
            let tick = comp
                .compress_stream(&self.pending[pos..], &mut buf)
                .map_err(|code| IoError::Backend(format!("zst compress failed: libzstd code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            pos += tick.consumed;
            if tick.consumed == 0 && tick.written == 0 {
                return Err(IoError::Backend("zst compress made no progress".to_owned()));
            }
        }
        loop {
            let tick = comp
                .end_stream(&mut buf)
                .map_err(|code| IoError::Backend(format!("zst compress end failed: libzstd code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            // remaining == 0 means the frame trailer is fully written.
            if tick.remaining == 0 {
                break;
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "zst-compress"
    }
}

/// zstd decompressing filter (`zst::decompress::Decompress`).
pub struct ZstDecompress {
    pending: Vec<u8>,
}

impl ZstDecompress {
    /// Build a zstd decompressing filter.
    #[must_use]
    pub const fn new() -> Self {
        Self { pending: Vec::new() }
    }
}

impl Default for ZstDecompress {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter for ZstDecompress {
    fn process(&mut self, input: &[u8], _out: &mut Vec<u8>) -> Result<(), IoError> {
        self.pending.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), IoError> {
        let mut decomp = zst::decompress::Decompress::new()
            .map_err(|code| IoError::Backend(format!("zst decompress init failed: libzstd code {code}")))?;

        let mut buf = vec![0u8; TICK_BUF];
        let mut pos = 0;
        loop {
            let tick = decomp
                .decompress_stream(&self.pending[pos..], &mut buf)
                .map_err(|code| IoError::Backend(format!("zst decompress failed: libzstd code {code}")))?;
            out.extend_from_slice(&buf[..tick.written]);
            pos += tick.consumed;
            // hint == 0 means the current frame is complete.
            if tick.hint == 0 {
                break;
            }
            if tick.consumed == 0 && tick.written == 0 {
                return Err(IoError::Backend("zst decompress truncated or made no progress".to_owned()));
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "zst-decompress"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pgbr_io::FilterChain;

    /// Push `input` through `filter` (process + finish) and return the output.
    fn run_filter<F: Filter>(mut filter: F, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        filter.process(input, &mut out).unwrap();
        filter.finish(&mut out).unwrap();
        out
    }

    /// Drive `input` through a single-filter `FilterChain` and return the output.
    fn run_chain<F: Filter + 'static>(filter: F, input: &[u8]) -> Vec<u8> {
        let mut chain = FilterChain::new();
        chain.push(filter);
        let mut out = Vec::new();
        chain.process(input, &mut out).unwrap();
        chain.finish(&mut out).unwrap();
        out
    }

    const SAMPLE: &[u8] = b"the quick brown fox jumps over the lazy dog, then does it again and again";

    // ---- gz ----------------------------------------------------------------

    #[test]
    fn gz_filter_round_trip() {
        for raw in [false, true] {
            let compressed = run_filter(GzCompress::new(6, raw), SAMPLE);
            assert_ne!(compressed, SAMPLE, "expected compressed bytes to differ (raw={raw})");
            let recovered = run_filter(GzDecompress::new(raw), &compressed);
            assert_eq!(recovered, SAMPLE, "raw={raw}");
        }
    }

    #[test]
    fn gz_filter_in_chain() {
        let compressed = run_chain(GzCompress::new(6, false), SAMPLE);
        let recovered = run_filter(GzDecompress::new(false), &compressed);
        assert_eq!(recovered, SAMPLE);
    }

    #[test]
    fn gz_filter_empty_input() {
        let compressed = run_filter(GzCompress::new(6, false), &[]);
        let recovered = run_filter(GzDecompress::new(false), &compressed);
        assert!(recovered.is_empty());
    }

    #[test]
    fn gz_filter_names() {
        assert_eq!(GzCompress::new(1, false).name(), "gz-compress");
        assert_eq!(GzDecompress::new(false).name(), "gz-decompress");
    }

    // ---- bz2 ---------------------------------------------------------------

    #[test]
    fn bz2_filter_round_trip() {
        let compressed = run_filter(Bz2Compress::new(9), SAMPLE);
        assert_ne!(compressed, SAMPLE, "expected compressed bytes to differ");
        let recovered = run_filter(Bz2Decompress::new(), &compressed);
        assert_eq!(recovered, SAMPLE);
    }

    #[test]
    fn bz2_filter_in_chain() {
        let compressed = run_chain(Bz2Compress::new(9), SAMPLE);
        let recovered = run_filter(Bz2Decompress::new(), &compressed);
        assert_eq!(recovered, SAMPLE);
    }

    #[test]
    fn bz2_filter_names() {
        assert_eq!(Bz2Compress::new(1).name(), "bz2-compress");
        assert_eq!(Bz2Decompress::new().name(), "bz2-decompress");
    }

    // ---- lz4 ---------------------------------------------------------------

    #[test]
    fn lz4_filter_round_trip() {
        for raw in [false, true] {
            let compressed = run_filter(Lz4Compress::new(1, raw), SAMPLE);
            assert_ne!(compressed, SAMPLE, "expected compressed bytes to differ (raw={raw})");
            // One decompressing filter handles both frame variants.
            let recovered = run_filter(Lz4Decompress::new(), &compressed);
            assert_eq!(recovered, SAMPLE, "raw={raw}");
        }
    }

    #[test]
    fn lz4_filter_in_chain() {
        let compressed = run_chain(Lz4Compress::new(1, false), SAMPLE);
        let recovered = run_filter(Lz4Decompress::new(), &compressed);
        assert_eq!(recovered, SAMPLE);
    }

    #[test]
    fn lz4_filter_empty_input() {
        let compressed = run_filter(Lz4Compress::new(1, false), &[]);
        let recovered = run_filter(Lz4Decompress::new(), &compressed);
        assert!(recovered.is_empty());
    }

    #[test]
    fn lz4_filter_names() {
        assert_eq!(Lz4Compress::new(1, false).name(), "lz4-compress");
        assert_eq!(Lz4Decompress::new().name(), "lz4-decompress");
    }

    // ---- zst ---------------------------------------------------------------

    #[test]
    fn zst_filter_round_trip() {
        let compressed = run_filter(ZstCompress::new(3), SAMPLE);
        assert_ne!(compressed, SAMPLE, "expected compressed bytes to differ");
        let recovered = run_filter(ZstDecompress::new(), &compressed);
        assert_eq!(recovered, SAMPLE);
    }

    #[test]
    fn zst_filter_in_chain() {
        let compressed = run_chain(ZstCompress::new(3), SAMPLE);
        let recovered = run_filter(ZstDecompress::new(), &compressed);
        assert_eq!(recovered, SAMPLE);
    }

    #[test]
    fn zst_filter_empty_input() {
        let compressed = run_filter(ZstCompress::new(3), &[]);
        let recovered = run_filter(ZstDecompress::new(), &compressed);
        assert!(recovered.is_empty());
    }

    #[test]
    fn zst_filter_names() {
        assert_eq!(ZstCompress::new(1).name(), "zst-compress");
        assert_eq!(ZstDecompress::new().name(), "zst-decompress");
    }

    // ---- compressibility sanity check --------------------------------------

    /// A highly compressible input must produce a meaningfully smaller output —
    /// proof that the codec actually ran rather than passing bytes through.
    #[test]
    fn compresses_repetitive_input_smaller() {
        let input = vec![0u8; 10_000];

        for (label, compressed) in [
            ("gz", run_filter(GzCompress::new(6, false), &input)),
            ("bz2", run_filter(Bz2Compress::new(9), &input)),
            ("lz4", run_filter(Lz4Compress::new(1, false), &input)),
            ("zst", run_filter(ZstCompress::new(3), &input)),
        ] {
            assert!(
                compressed.len() < input.len() / 2,
                "{label}: expected compressed ({}) << input ({})",
                compressed.len(),
                input.len()
            );
        }
    }

    /// A larger pseudo-random-ish payload exercises the multi-tick path (input
    /// exceeds a single `TICK_BUF` worth of compressed output) for every codec.
    #[test]
    fn round_trip_large_payload() {
        let input: Vec<u8> = (0..200_000_u32)
            .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 13) & 0xff).unwrap_or(0))
            .collect();

        let gz = run_filter(GzCompress::new(6, false), &input);
        assert_eq!(run_filter(GzDecompress::new(false), &gz), input, "gz");

        let bz2 = run_filter(Bz2Compress::new(9), &input);
        assert_eq!(run_filter(Bz2Decompress::new(), &bz2), input, "bz2");

        let lz4 = run_filter(Lz4Compress::new(9, false), &input);
        assert_eq!(run_filter(Lz4Decompress::new(), &lz4), input, "lz4");

        let zst = run_filter(ZstCompress::new(3), &input);
        assert_eq!(run_filter(ZstDecompress::new(), &zst), input, "zst");
    }
}
