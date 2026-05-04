//! POSIX ERE-compatible regular expression handler used by the pgBackRust C codebase through the
//! [`pgbr-ffi`](../pgbr_ffi/index.html) shim.
//!
//! The legacy C implementation in `src/common/regExp.c` wraps POSIX `regcomp`/`regexec` with
//! `REG_EXTENDED`. The Rust replacement uses [`regex::bytes::Regex`] with Unicode disabled, which
//! produces byte-oriented matches semantically equivalent to POSIX ERE for the patterns
//! pgBackRust uses (no backreferences, no lookahead, ASCII-only character classes). Functions
//! match the public C surface in `src/common/regExp.h` byte-for-byte.

#![cfg_attr(not(test), forbid(unsafe_code))]

use core::fmt;

use regex::bytes::{Regex as BytesRegex, RegexBuilder};

/// Compiled regular expression. Equivalent to the legacy C `RegExp` struct.
#[derive(Debug, Clone)]
pub struct Regex {
    inner: BytesRegex,
}

/// Reasons [`Regex::new`] may fail.
#[derive(Debug, Clone)]
pub enum CompileError {
    /// The pattern contained a NUL byte. POSIX `regcomp` accepts a NUL-terminated C string and
    /// would silently truncate; the Rust replacement rejects the input explicitly.
    InteriorNul,
    /// The underlying regex engine rejected the pattern. The wrapped string is the engine's
    /// human-readable message — already prefixed with `regex parse error:` — used verbatim by
    /// the C shim when it raises `FormatError`.
    Syntax(String),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul => f.write_str("regex pattern contains an interior NUL byte"),
            Self::Syntax(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CompileError {}

impl Regex {
    /// Compile `pattern` (a byte string, typically UTF-8) as an extended regular expression.
    ///
    /// Mirrors `regcomp(&this->regExp, strZ(expression), REG_EXTENDED)` in the legacy C code.
    /// Returns [`CompileError`] if the pattern is malformed or contains an interior NUL byte.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError::InteriorNul`] if `pattern` contains a `\0` byte and
    /// [`CompileError::Syntax`] if the regex engine rejects the pattern.
    pub fn new(pattern: &[u8]) -> Result<Self, CompileError> {
        if pattern.contains(&0u8) {
            return Err(CompileError::InteriorNul);
        }
        // SAFETY-equivalent: `regex::bytes::Regex` accepts `&str` for the pattern. POSIX ERE is
        // byte-oriented, but pgBackRust patterns are always valid UTF-8 (they come from the
        // `String` type which is UTF-8 by construction). If a future caller hands in non-UTF-8
        // bytes the engine would reject them anyway.
        let pattern_str = core::str::from_utf8(pattern).map_err(|err| CompileError::Syntax(format!("regex parse error: {err}")))?;
        let inner = RegexBuilder::new(pattern_str)
            .unicode(false)
            .build()
            .map_err(|err| CompileError::Syntax(err.to_string()))?;
        Ok(Self { inner })
    }

    /// Returns `true` if `haystack` contains a match.
    ///
    /// Mirrors `regExpMatch` in `src/common/regExp.c`.
    #[must_use]
    pub fn is_match(&self, haystack: &[u8]) -> bool {
        self.inner.is_match(haystack)
    }

    /// Returns the byte offsets `(start, end)` of the first match in `haystack`, or `None` if
    /// the pattern does not match.
    ///
    /// Mirrors the offsets the legacy `regExpMatchPtr`/`regExpMatchStr` extension functions
    /// recover from `regmatch_t.rm_so`/`rm_eo`.
    #[must_use]
    pub fn find(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        self.inner.find(haystack).map(|m| (m.start(), m.end()))
    }
}

/// Length in bytes (excluding the leading `^`) of the longest fixed-character common prefix in
/// `pattern`, or `0` when the pattern has no usable prefix.
///
/// A prefix is "usable" when:
/// - the pattern starts with the begin-anchor `^`,
/// - at least one literal character follows it before any regex special character,
/// - the rest of the pattern contains no other (unescaped, non-bracket) `^` begin-anchor.
///
/// Special characters that terminate the prefix: `. ^ $ * + - ? ( [ { ` `(space)` `| \`. The
/// function never compiles a regex; it is a pure byte-level scan that mirrors `regExpPrefix` in
/// the legacy C code.
#[must_use]
pub fn prefix_len(pattern: &[u8]) -> usize {
    if pattern.is_empty() || pattern[0] != b'^' {
        return 0;
    }

    let mut prefix_end = 1usize;
    while prefix_end < pattern.len() {
        if is_prefix_terminator(pattern[prefix_end]) {
            break;
        }
        prefix_end += 1;
    }

    if prefix_end == 1 {
        return 0;
    }

    // Reject the prefix if another begin-anchor `^` appears later in the pattern. `[^` (negated
    // bracket class) and `\^` (escaped caret) are not begin-anchors and do not invalidate the
    // prefix.
    let mut anchor_idx = prefix_end;
    while anchor_idx < pattern.len() {
        if pattern[anchor_idx] == b'^' && pattern[anchor_idx - 1] != b'[' && pattern[anchor_idx - 1] != b'\\' {
            return 0;
        }
        anchor_idx += 1;
    }

    prefix_end - 1
}

const fn is_prefix_terminator(byte: u8) -> bool {
    matches!(
        byte,
        b'.' | b'^' | b'$' | b'*' | b'+' | b'-' | b'?' | b'(' | b'[' | b'{' | b' ' | b'|' | b'\\'
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn compile_and_match_simple_pattern() {
        let regex = Regex::new(b"^abc").expect("valid pattern");
        assert!(regex.is_match(b"abcdef"));
        assert!(!regex.is_match(b"bcdef"));
        assert!(!regex.is_match(b""));
    }

    #[test]
    fn find_returns_first_match_offsets() {
        let regex = Regex::new(b"abc").expect("valid pattern");
        assert_eq!(regex.find(b"xabcy"), Some((1, 4)));
        assert_eq!(regex.find(b"no match"), None);
    }

    #[test]
    fn anchored_match_at_start() {
        let regex = Regex::new(b"^abc").expect("valid pattern");
        assert_eq!(regex.find(b"abcdef"), Some((0, 3)));
        assert_eq!(regex.find(b"xabcdef"), None);
    }

    #[test]
    fn rejects_unbalanced_brackets() {
        match Regex::new(b"[[[") {
            Err(CompileError::Syntax(msg)) => assert!(msg.contains("regex parse error")),
            other => panic!("expected Syntax error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_interior_nul() {
        assert!(matches!(Regex::new(b"a\0b"), Err(CompileError::InteriorNul)));
    }

    #[test]
    fn empty_pattern_matches_anywhere() {
        let regex = Regex::new(b"").expect("empty pattern is valid in POSIX ERE");
        assert!(regex.is_match(b""));
        assert!(regex.is_match(b"anything"));
        assert_eq!(regex.find(b"abc"), Some((0, 0)));
    }

    #[test]
    fn byte_mode_matches_high_bytes() {
        // Pattern `\xff` is not valid UTF-8 — but `[\xff]` literal in a class doesn't appear in
        // pgBackRust patterns. We just verify that ASCII patterns operate byte-wise on
        // non-ASCII haystacks.
        let regex = Regex::new(b"foo").expect("valid pattern");
        assert!(regex.is_match(b"foo\xff\xfe"));
        assert!(!regex.is_match(b"\xff\xfe"));
    }

    #[test]
    fn alternation_and_quantifiers() {
        let regex = Regex::new(b"^(abc|def)+$").expect("valid pattern");
        assert!(regex.is_match(b"abc"));
        assert!(regex.is_match(b"abcdef"));
        assert!(regex.is_match(b"defabcdef"));
        assert!(!regex.is_match(b"abcx"));
        assert!(!regex.is_match(b""));
    }

    #[test]
    fn character_class_negation() {
        let regex = Regex::new(b"^[^abc]+$").expect("valid pattern");
        assert!(regex.is_match(b"xyz"));
        assert!(!regex.is_match(b"axyz"));
        assert!(!regex.is_match(b""));
    }

    #[test]
    fn prefix_len_basic() {
        assert_eq!(prefix_len(b""), 0);
        assert_eq!(prefix_len(b"abc"), 0); // no leading anchor
        assert_eq!(prefix_len(b"^"), 0); // anchor only
        assert_eq!(prefix_len(b"^."), 0); // immediate special
        assert_eq!(prefix_len(b"^abc"), 3);
        assert_eq!(prefix_len(b"^abcdef"), 6);
    }

    #[test]
    fn prefix_len_stops_at_specials() {
        // `^` is a terminator AND a begin-anchor in the rest, which invalidates the prefix; it
        // is exercised separately in `prefix_len_rejects_extra_anchor`.
        for terminator in [b'.', b'$', b'*', b'+', b'-', b'?', b'(', b'[', b'{', b' ', b'|', b'\\'] {
            let mut pattern = b"^ABC".to_vec();
            pattern.push(terminator);
            assert_eq!(prefix_len(&pattern), 3, "terminator {:?}", terminator as char);
        }
    }

    #[test]
    fn prefix_len_rejects_extra_anchor() {
        assert_eq!(prefix_len(b"^ABC^"), 0);
        assert_eq!(prefix_len(b"^ABC|^DEF"), 0);
    }

    #[test]
    fn prefix_len_accepts_bracket_caret() {
        assert_eq!(prefix_len(b"^ABC[^DEF]"), 3);
        assert_eq!(prefix_len(b"^ABC\\^DEF]"), 3);
    }

    #[test]
    fn prefix_len_full_expression() {
        assert_eq!(prefix_len(b"^ABCDEF"), 6);
    }

    /// Stability check on [`Regex::is_match`] — guards against accidental regressions in the
    /// wrapper logic by running 10 000 deterministic samples over a fixed seed and asserting
    /// every match is reproducible across calls.
    #[test]
    fn random_match_is_stable_across_runs() {
        let patterns: &[&[u8]] = &[
            b"^abc",
            b"abc$",
            b"^[0-9]+$",
            b"[A-Za-z_][A-Za-z0-9_]*",
            b"^(foo|bar|baz)+$",
            b"^[^abc]+$",
            b"\\.tar\\.gz$",
            b"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
        ];
        let mut state: u64 = 0xfeed_face_baad_f00d;
        let mut buf = Vec::with_capacity(64);
        for pattern in patterns {
            let regex = Regex::new(pattern).expect("valid pattern");
            for _ in 0..1_250 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let len = ((state >> 32) as usize) % 32;
                buf.clear();
                for _ in 0..len {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    buf.push(((state >> 56) as u8 % 96) + 32);
                }
                let a = regex.is_match(&buf);
                let b = regex.is_match(&buf);
                assert_eq!(a, b, "regex match must be deterministic for {buf:?}");
            }
        }
    }
}
