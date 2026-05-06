//! Byte-count pass-through filter.

use crate::{Filter, IoError};

/// Counts the total number of input bytes seen.
#[derive(Debug, Clone, Copy, Default)]
pub struct Size {
    bytes: u64,
}

impl Size {
    /// Build a fresh counter starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: 0 }
    }

    /// Bytes seen so far.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

impl Filter for Size {
    fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), IoError> {
        self.bytes = self.bytes.saturating_add(u64::try_from(input.len()).unwrap_or(u64::MAX));
        out.extend_from_slice(input);
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), IoError> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "size"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::FilterChain;

    #[test]
    fn size_counts_input_length() {
        let mut size = Size::new();
        let mut out = Vec::new();
        Filter::process(&mut size, b"hello, world!", &mut out).unwrap();
        Filter::finish(&mut size, &mut out).unwrap();
        assert_eq!(size.bytes(), 13);
        assert_eq!(out, b"hello, world!");
        assert_eq!(size.name(), "size");
    }

    #[test]
    fn size_counts_across_multiple_chunks() {
        let mut size = Size::new();
        let mut out = Vec::new();
        Filter::process(&mut size, b"abc", &mut out).unwrap();
        Filter::process(&mut size, b"defgh", &mut out).unwrap();
        Filter::finish(&mut size, &mut out).unwrap();
        assert_eq!(size.bytes(), 8);
        assert_eq!(out, b"abcdefgh");
    }

    #[test]
    fn size_in_filter_chain() {
        let mut chain = FilterChain::new();
        chain.push(Size::new());
        let mut out = Vec::new();
        chain.process(b"chain bytes", &mut out).unwrap();
        chain.finish(&mut out).unwrap();
        assert_eq!(out, b"chain bytes");
    }

    #[test]
    fn size_default_is_zero() {
        let size = Size::default();
        assert_eq!(size.bytes(), 0);
    }
}
