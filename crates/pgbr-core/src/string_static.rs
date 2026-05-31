//! Tiny static-buffer string concatenation helpers shared with the C
//! `StringStatic` API in `src/common/type/stringStatic.h`.
//!
//! The C side keeps the public `StringStatic { buffer, bufferSize, resultSize }` struct
//! and the variadic `strStcFmt` (which routes through `vsnprintf`); only the byte-copy
//! primitives (`strStcCat`, `strStcCatChr`) move into Rust because they are pure data
//! manipulation with no variadic args.
//!
//! The contract this module mirrors:
//!
//! - All operations require `buffer.len() > 1` (the legacy code uses `remainsSize > 1`,
//!   reserving one byte for the trailing NUL); a smaller buffer is a no-op.
//! - Output is always NUL-terminated when at least one byte fits.
//! - The returned `usize` is the **delta** added to `resultSize`. The C wrapper applies
//!   the delta to the live `StringStatic` cursor; the Rust side never sees the cursor
//!   itself.

/// Append `cat` to the writable tail of `buffer`. Returns the number of payload bytes
/// written (not counting the trailing NUL). Returns `0` when the buffer is too small or
/// `cat` is empty.
pub fn cat(buffer: &mut [u8], cat: &str) -> usize {
    if buffer.len() <= 1 {
        return 0;
    }
    let remains_size = buffer.len();
    let cat_size = cat.len();
    let result_size = if cat_size > remains_size - 1 {
        remains_size - 1
    } else {
        cat_size
    };

    buffer[..result_size].copy_from_slice(&cat.as_bytes()[..result_size]);
    buffer[result_size] = 0;
    result_size
}

/// Append a single byte to the writable tail of `buffer`. Returns `1` on success, `0`
/// when the buffer is too small to hold both the new byte and the trailing NUL.
pub fn cat_chr(buffer: &mut [u8], byte: u8) -> usize {
    if buffer.len() <= 1 {
        return 0;
    }
    buffer[0] = byte;
    buffer[1] = 0;
    1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn render(size: usize, payload: &str) -> (usize, Vec<u8>) {
        let mut buf = vec![0xAAu8; size];
        let n = cat(&mut buf, payload);
        (n, buf)
    }

    #[test]
    fn cat_writes_full_payload_when_room() {
        let (n, buf) = render(8, "abcd");
        assert_eq!(n, 4);
        assert_eq!(&buf[..5], b"abcd\0");
    }

    #[test]
    fn cat_truncates_when_buffer_too_small() {
        // size 4 → max payload 3
        let (n, buf) = render(4, "abcdef");
        assert_eq!(n, 3);
        assert_eq!(&buf[..4], b"abc\0");
    }

    #[test]
    fn cat_buffer_size_zero_writes_nothing() {
        let mut buf = [0u8; 0];
        assert_eq!(cat(&mut buf, "x"), 0);
    }

    #[test]
    fn cat_buffer_size_one_writes_nothing() {
        let mut buf = [0xAAu8; 1];
        assert_eq!(cat(&mut buf, "x"), 0);
        assert_eq!(buf[0], 0xAA);
    }

    #[test]
    fn cat_empty_payload_writes_only_terminator() {
        let mut buf = [0xAAu8; 4];
        assert_eq!(cat(&mut buf, ""), 0);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn cat_chr_writes_byte_and_nul() {
        let mut buf = [0xAAu8; 4];
        assert_eq!(cat_chr(&mut buf, b'Z'), 1);
        assert_eq!(&buf[..2], b"Z\0");
    }

    #[test]
    fn cat_chr_buffer_size_one_writes_nothing() {
        let mut buf = [0xAAu8; 1];
        assert_eq!(cat_chr(&mut buf, b'Z'), 0);
        assert_eq!(buf[0], 0xAA);
    }

    #[test]
    fn cat_truncation_preserves_bytes_outside_window() {
        // The C strStcCat overwrites only `result_size + 1` bytes; everything beyond
        // remains untouched. Mirror that here.
        let mut buf = [0xCCu8; 8];
        let n = cat(&mut buf, "ab");
        assert_eq!(n, 2);
        assert_eq!(&buf[..3], b"ab\0");
        assert!(buf[3..].iter().all(|b| *b == 0xCC));
    }
}
