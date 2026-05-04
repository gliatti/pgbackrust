// The encoders deliberately convert between signed and unsigned 8-bit integers when packing
// nibbles together — every cast in this module is checked by the surrounding length / table-
// lookup invariants, so the relevant lints are silenced rather than rewritten with .cast_*.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss)]

//! Binary <-> printable string encoders used throughout the pgBackRust workspace.
//!
//! Three encodings: standard base64 with `=` padding, URL-safe base64 without padding, and
//! lowercase hex. All functions are pure (no allocation, no global state) and write into
//! caller-provided buffers — matching the calling convention of the C API the FFI shim mirrors.
//!
//! Decoders validate their input before writing anything: an [`Err`] result means the
//! destination buffer was not touched.

#![cfg_attr(not(test), forbid(unsafe_code))]

use core::fmt;

/// One of the three encodings supported by [`encode`] / [`decode`].
///
/// Discriminants match the C `EncodingType` enum (0=Base64, 1=Base64Url, 2=Hex) so a Rust value
/// and the legacy C value share a single `i32` representation across the FFI boundary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingType {
    /// Standard `RFC 4648 §4` base64 with `=` padding.
    Base64 = 0,
    /// URL-safe base64 (`-_` alphabet, no `=` padding) — `RFC 4648 §5`.
    Base64Url = 1,
    /// Lowercase hex (`0-9a-f`).
    Hex = 2,
}

impl EncodingType {
    /// Returns the variant whose discriminant equals `code`, or `None` if the code is not part
    /// of the enum.
    #[must_use]
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Base64),
            1 => Some(Self::Base64Url),
            2 => Some(Self::Hex),
            _ => None,
        }
    }
}

/// Reasons a decoder may reject its input. Encodings validate the input before writing anything
/// to the destination buffer; if [`decode`] returns `Err(_)`, `dst` was not modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Source length is not a multiple of the encoding's group size (4 for base64, 2 for hex).
    InvalidLength {
        /// Length seen.
        len: usize,
        /// Expected group size.
        group: usize,
    },
    /// Character at `position` is not in the encoding's alphabet.
    InvalidCharacter {
        /// 0-based byte offset of the offending character.
        position: usize,
    },
    /// `=` padding appears outside the last two positions of a base64 string.
    PaddingMisplaced,
    /// Second-to-last character is `=` but last character is not.
    PaddingTrailing,
    /// Input encoding does not support decoding (currently `Base64Url`, mirroring the legacy C
    /// behaviour).
    Unsupported,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { len, group } => {
                write!(f, "encoded size {len} is not evenly divisible by {group}")
            }
            Self::InvalidCharacter { position } => write!(f, "invalid character found at position {position}"),
            Self::PaddingMisplaced => f.write_str("'=' character may only appear in the last two positions"),
            Self::PaddingTrailing => f.write_str("last character must be '=' if second to last is"),
            Self::Unsupported => f.write_str("encoding does not support decoding"),
        }
    }
}

impl std::error::Error for DecodeError {}

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

const fn base64_decode_table() -> [i8; 256] {
    let mut table = [-1i8; 256];
    let mut i = 0usize;
    while i < BASE64_ALPHABET.len() {
        table[BASE64_ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    table
}

const fn hex_decode_table() -> [i8; 256] {
    let mut table = [-1i8; 256];
    let mut i = 0usize;
    while i < 10 {
        table[(b'0' + i as u8) as usize] = i as i8;
        i += 1;
    }
    let mut j = 0usize;
    while j < 6 {
        table[(b'a' + j as u8) as usize] = (10 + j) as i8;
        table[(b'A' + j as u8) as usize] = (10 + j) as i8;
        j += 1;
    }
    table
}

const BASE64_DECODE: [i8; 256] = base64_decode_table();
const HEX_DECODE: [i8; 256] = hex_decode_table();

/// Number of bytes the encoded representation of a `src_len`-byte input occupies, **excluding**
/// any trailing NUL written by [`encode`]. Mirrors the C `encodeToStrSize`.
#[must_use]
pub const fn encoded_len(encoding: EncodingType, src_len: usize) -> usize {
    match encoding {
        EncodingType::Base64 => src_len.div_ceil(3) * 4,
        EncodingType::Base64Url => {
            let groups = src_len / 3 * 4;
            let remainder = src_len % 3;
            if remainder == 0 { groups } else { groups + remainder + 1 }
        }
        EncodingType::Hex => src_len * 2,
    }
}

/// Encode `src` into `dst` using the chosen encoding and write a trailing NUL byte.
///
/// `dst` must be at least `encoded_len(encoding, src.len()) + 1` bytes long.
///
/// # Panics
///
/// Panics if `dst` is too short for the encoded form plus the trailing NUL.
pub fn encode(encoding: EncodingType, src: &[u8], dst: &mut [u8]) {
    let needed = encoded_len(encoding, src.len()) + 1;
    assert!(
        dst.len() >= needed,
        "encode destination too small: have {} need {}",
        dst.len(),
        needed
    );
    match encoding {
        EncodingType::Base64 => encode_base64::<true>(src, dst),
        EncodingType::Base64Url => encode_base64::<false>(src, dst),
        EncodingType::Hex => encode_hex(src, dst),
    }
}

fn encode_base64<const PAD: bool>(src: &[u8], dst: &mut [u8]) {
    let alphabet = if PAD { BASE64_ALPHABET } else { BASE64_URL_ALPHABET };
    let mut di = 0usize;
    let mut si = 0usize;
    while si < src.len() {
        dst[di] = alphabet[(src[si] >> 2) as usize];
        di += 1;

        let remaining = src.len() - si;
        if remaining == 1 {
            dst[di] = alphabet[((src[si] & 0x03) << 4) as usize];
            di += 1;
            if PAD {
                dst[di] = b'=';
                dst[di + 1] = b'=';
                di += 2;
            }
        } else {
            dst[di] = alphabet[(((src[si] & 0x03) << 4) | ((src[si + 1] & 0xf0) >> 4)) as usize];
            di += 1;

            if remaining == 2 {
                dst[di] = alphabet[((src[si + 1] & 0x0f) << 2) as usize];
                di += 1;
                if PAD {
                    dst[di] = b'=';
                    di += 1;
                }
            } else {
                dst[di] = alphabet[(((src[si + 1] & 0x0f) << 2) | ((src[si + 2] & 0xc0) >> 6)) as usize];
                dst[di + 1] = alphabet[(src[si + 2] & 0x3f) as usize];
                di += 2;
            }
        }

        si += 3;
    }
    dst[di] = 0;
}

fn encode_hex(src: &[u8], dst: &mut [u8]) {
    let mut di = 0usize;
    for &byte in src {
        dst[di] = HEX_ALPHABET[(byte >> 4) as usize];
        dst[di + 1] = HEX_ALPHABET[(byte & 0x0f) as usize];
        di += 2;
    }
    dst[di] = 0;
}

/// Decoded byte length for a `src` string, or an error explaining why `src` is invalid.
///
/// Mirrors the C `decodeToBinSize`. Returns [`DecodeError::Unsupported`] for `Base64Url`
/// because the legacy C decoder does not support it.
pub fn decoded_len(encoding: EncodingType, src: &str) -> Result<usize, DecodeError> {
    match encoding {
        EncodingType::Base64 => base64_decoded_len(src.as_bytes()),
        EncodingType::Base64Url => Err(DecodeError::Unsupported),
        EncodingType::Hex => hex_decoded_len(src.as_bytes()),
    }
}

/// Decode `src` into `dst` using the chosen encoding. The function validates `src` first; if it
/// returns `Err(_)`, `dst` is not modified.
///
/// # Panics
///
/// Panics if `dst` is too small for the decoded length returned by [`decoded_len`].
pub fn decode(encoding: EncodingType, src: &str, dst: &mut [u8]) -> Result<(), DecodeError> {
    match encoding {
        EncodingType::Base64 => decode_base64(src.as_bytes(), dst),
        EncodingType::Base64Url => Err(DecodeError::Unsupported),
        EncodingType::Hex => decode_hex(src.as_bytes(), dst),
    }
}

fn validate_base64(src: &[u8]) -> Result<(), DecodeError> {
    let len = src.len();
    if !len.is_multiple_of(4) {
        return Err(DecodeError::InvalidLength { len, group: 4 });
    }
    for (idx, &byte) in src.iter().enumerate() {
        if byte == b'=' {
            if idx < len - 2 {
                return Err(DecodeError::PaddingMisplaced);
            }
            if idx == len - 2 && src[len - 1] != b'=' {
                return Err(DecodeError::PaddingTrailing);
            }
        } else if BASE64_DECODE[byte as usize] < 0 {
            return Err(DecodeError::InvalidCharacter { position: idx });
        }
    }
    Ok(())
}

fn base64_decoded_len(src: &[u8]) -> Result<usize, DecodeError> {
    validate_base64(src)?;
    if src.is_empty() {
        return Ok(0);
    }
    let mut len = src.len() / 4 * 3;
    if src[src.len() - 1] == b'=' {
        len -= 1;
        if src[src.len() - 2] == b'=' {
            len -= 1;
        }
    }
    Ok(len)
}

fn decode_base64(src: &[u8], dst: &mut [u8]) -> Result<(), DecodeError> {
    validate_base64(src)?;
    let needed = base64_decoded_len(src)?;
    assert!(
        dst.len() >= needed,
        "decode destination too small: have {} need {}",
        dst.len(),
        needed
    );

    let mut di = 0usize;
    let mut si = 0usize;
    while si < src.len() {
        let a = BASE64_DECODE[src[si] as usize] as u8;
        let b = BASE64_DECODE[src[si + 1] as usize] as u8;
        dst[di] = (a << 2) | (b >> 4);
        di += 1;

        if src[si + 2] != b'=' {
            let c = BASE64_DECODE[src[si + 2] as usize] as u8;
            dst[di] = (b << 4) | (c >> 2);
            di += 1;

            if src[si + 3] != b'=' {
                let d = BASE64_DECODE[src[si + 3] as usize] as u8;
                dst[di] = ((c << 6) & 0xc0) | d;
                di += 1;
            }
        }
        si += 4;
    }
    Ok(())
}

fn validate_hex(src: &[u8]) -> Result<(), DecodeError> {
    if !src.len().is_multiple_of(2) {
        return Err(DecodeError::InvalidLength {
            len: src.len(),
            group: 2,
        });
    }
    for (idx, &byte) in src.iter().enumerate() {
        if HEX_DECODE[byte as usize] < 0 {
            return Err(DecodeError::InvalidCharacter { position: idx });
        }
    }
    Ok(())
}

fn hex_decoded_len(src: &[u8]) -> Result<usize, DecodeError> {
    validate_hex(src)?;
    Ok(src.len() / 2)
}

fn decode_hex(src: &[u8], dst: &mut [u8]) -> Result<(), DecodeError> {
    validate_hex(src)?;
    let needed = src.len() / 2;
    assert!(
        dst.len() >= needed,
        "decode destination too small: have {} need {}",
        dst.len(),
        needed
    );

    for (i, pair) in src.chunks_exact(2).enumerate() {
        let hi = HEX_DECODE[pair[0] as usize] as u8;
        let lo = HEX_DECODE[pair[1] as usize] as u8;
        dst[i] = (hi << 4) | lo;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn round_trip(encoding: EncodingType, input: &[u8]) {
        let enc_len = encoded_len(encoding, input.len());
        let mut buf = vec![0u8; enc_len + 1];
        encode(encoding, input, &mut buf);
        assert_eq!(buf[enc_len], 0, "missing NUL terminator");
        let s = std::str::from_utf8(&buf[..enc_len]).expect("alphabet is ASCII");

        if encoding == EncodingType::Base64Url {
            // Legacy C decoder doesn't support Base64Url — only validate encoded form.
            assert!(!s.contains('+') && !s.contains('/') && !s.contains('='));
            return;
        }

        let dec_len = decoded_len(encoding, s).expect("just-encoded form must decode");
        assert_eq!(dec_len, input.len());

        let mut dec = vec![0u8; dec_len];
        decode(encoding, s, &mut dec).expect("just-encoded form must decode");
        assert_eq!(dec, input);
    }

    #[test]
    fn base64_known_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, expected) in cases {
            let enc_len = encoded_len(EncodingType::Base64, raw.len());
            let mut buf = vec![0u8; enc_len + 1];
            encode(EncodingType::Base64, raw, &mut buf);
            let got = std::str::from_utf8(&buf[..enc_len]).unwrap();
            assert_eq!(got, *expected, "encoding {raw:?}");
        }
    }

    #[test]
    fn base64_url_known_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (&[0xff, 0xee, 0xdd], "_-7d"),
            (&[0xff], "_w"),
            (&[0xff, 0xee], "_-4"),
            (b"", ""),
        ];
        for (raw, expected) in cases {
            let enc_len = encoded_len(EncodingType::Base64Url, raw.len());
            let mut buf = vec![0u8; enc_len + 1];
            encode(EncodingType::Base64Url, raw, &mut buf);
            let got = std::str::from_utf8(&buf[..enc_len]).unwrap();
            assert_eq!(got, *expected, "encoding {raw:?}");
        }
    }

    #[test]
    fn hex_known_vectors() {
        let cases: &[(&[u8], &str)] = &[(b"", ""), (&[0u8, 0xff, 0x10, 0xab], "00ff10ab"), (b"hello", "68656c6c6f")];
        for (raw, expected) in cases {
            let enc_len = encoded_len(EncodingType::Hex, raw.len());
            let mut buf = vec![0u8; enc_len + 1];
            encode(EncodingType::Hex, raw, &mut buf);
            let got = std::str::from_utf8(&buf[..enc_len]).unwrap();
            assert_eq!(got, *expected, "encoding {raw:?}");
        }
    }

    #[test]
    fn base64_decode_rejects_invalid_inputs() {
        assert!(matches!(
            decoded_len(EncodingType::Base64, "abc"),
            Err(DecodeError::InvalidLength { len: 3, group: 4 })
        ));
        assert!(matches!(
            decoded_len(EncodingType::Base64, "ab=cdefg"),
            Err(DecodeError::InvalidLength { len: 8, group: 4 } | DecodeError::PaddingMisplaced)
        ));
        assert!(matches!(
            decoded_len(EncodingType::Base64, "abcd=fgh"),
            Err(DecodeError::PaddingMisplaced)
        ));
        assert!(matches!(
            decoded_len(EncodingType::Base64, "abc!"),
            Err(DecodeError::InvalidCharacter { position: 3 })
        ));
    }

    #[test]
    fn hex_decode_rejects_invalid_inputs() {
        assert!(matches!(
            decoded_len(EncodingType::Hex, "abc"),
            Err(DecodeError::InvalidLength { len: 3, group: 2 })
        ));
        assert!(matches!(
            decoded_len(EncodingType::Hex, "0g"),
            Err(DecodeError::InvalidCharacter { position: 1 })
        ));
    }

    #[test]
    fn base64_url_does_not_support_decoding() {
        assert_eq!(decoded_len(EncodingType::Base64Url, "abcd"), Err(DecodeError::Unsupported));
        let mut dst = [0u8; 8];
        assert_eq!(
            decode(EncodingType::Base64Url, "abcd", &mut dst),
            Err(DecodeError::Unsupported)
        );
    }

    #[test]
    fn round_trip_random_inputs_base64_and_hex() {
        // Deterministic LCG over a fixed seed — running the suite twice reproduces the same
        // 10 000 inputs. Covers every length from 0..=200 plus randomised long samples.
        let mut state: u64 = 0xdead_beef_cafe_babe;
        let mut buf = Vec::with_capacity(257);
        for iter in 0..10_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = if iter < 257 { iter } else { ((state >> 32) as usize) % 257 };
            buf.clear();
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                buf.push((state >> 56) as u8);
            }
            round_trip(EncodingType::Base64, &buf);
            round_trip(EncodingType::Base64Url, &buf);
            round_trip(EncodingType::Hex, &buf);
        }
    }
}
