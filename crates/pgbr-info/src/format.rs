//! INI-with-SHA-1-checksum reader / writer shared by `archive.info` and `backup.info`.
//!
//! The on-disk format is INI-like: zero or more `[section]` headers, each followed by
//! `key=value` lines (one per line). The value side is opaque to this layer — callers
//! decode JSON / numbers / strings on top of the raw text returned here.
//!
//! Both info files end with a `[backrest]` section that contains a
//! `backrest-checksum="..."` line. The checksum is the SHA-1 (lowercase hex) of the
//! file content with that single line removed; every other line, including the
//! `[backrest]` header itself, is part of the checksumed text.
//!
//! Ordering is significant: callers expect `parse` followed by `render` to be a
//! byte-identical round trip, so [`InfoFile`] preserves both section and key order via
//! [`indexmap::IndexMap`].

use std::fmt;

use indexmap::IndexMap;
use sha1::{Digest, Sha1};

/// Section name that holds the checksum. Lives at the top of every info file.
pub const BACKREST_SECTION: &str = "backrest";
/// Key name within the `[backrest]` section that stores the SHA-1 checksum.
pub const CHECKSUM_KEY: &str = "backrest-checksum";
/// Section name that holds the repository encryption sub-key.
///
/// Present only when the repository is encrypted
/// (`repo-cipher-type=aes-256-cbc`). Mirrors pgBackRust's
/// `INFO_SECTION_CIPHER` in `src/info/info.c`.
pub const CIPHER_SECTION: &str = "cipher";
/// Key name within the `[cipher]` section that stores the (JSON-string-encoded)
/// repository sub-key — pgBackRust's `INFO_KEY_CIPHER_PASS`.
pub const CIPHER_PASS_KEY: &str = "cipher-pass";

/// Parsed INI document. Sections and keys retain their insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InfoFile {
    /// Insertion-ordered map of `section -> (insertion-ordered map of key -> raw value)`.
    pub sections: IndexMap<String, IndexMap<String, String>>,
}

impl InfoFile {
    /// Build an empty document.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the raw value of `key` inside `section`.
    #[must_use]
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections.get(section).and_then(|s| s.get(key)).map(String::as_str)
    }

    /// Insert or replace `section[key] = value`. Inserts the section if missing.
    pub fn set(&mut self, section: &str, key: &str, value: impl Into<String>) {
        let entry = self.sections.entry(section.to_owned()).or_default();
        entry.insert(key.to_owned(), value.into());
    }
}

/// Failure returned by the format layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoFormatError {
    /// A non-comment, non-blank, non-section line did not contain `=`.
    InvalidLine {
        /// 1-based line number where the offending text appeared.
        line_number: usize,
        /// The line itself (with its terminating newline stripped).
        line: String,
    },
    /// A `[section]` header was missing its closing `]`.
    UnterminatedSection {
        /// 1-based line number where the offending text appeared.
        line_number: usize,
        /// The line itself.
        line: String,
    },
    /// `[backrest].backrest-checksum` did not match the SHA-1 over the rest of the file.
    ChecksumMismatch {
        /// Checksum computed over the on-disk text.
        actual: String,
        /// Checksum the file claimed.
        expected: String,
    },
    /// The file did not contain a `[backrest].backrest-checksum` entry at all.
    MissingChecksum,
    /// A section name or key would corrupt the INI envelope if rendered verbatim
    /// (it contains a newline / carriage-return / `=`, or begins with a character
    /// that would make the emitted line parse as a section header, comment, or be
    /// silently trimmed — i.e. `[`, `#`, `;`, or leading whitespace).
    ///
    /// This is the guard against INI injection through attacker-controlled keys:
    /// manifest entry keys are `PGDATA`-relative file paths, so a file named
    /// `x\n[target:link]\n...` must be rejected at write time rather than smuggled
    /// into the rendered document (where the SHA-1, being computed *after* render,
    /// would happily bless the injected sections).
    UnsafeName {
        /// Whether the offending token was a `section` header or a `key`.
        kind: &'static str,
        /// The offending token itself.
        name: String,
    },
}

impl fmt::Display for InfoFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine { line_number, line } => {
                write!(f, "invalid line {line_number}: {line}")
            }
            Self::UnterminatedSection { line_number, line } => {
                write!(f, "unterminated section header on line {line_number}: {line}")
            }
            Self::ChecksumMismatch { actual, expected } => {
                write!(f, "invalid checksum, actual '{actual}' but expected '{expected}'")
            }
            Self::MissingChecksum => f.write_str("missing backrest-checksum entry"),
            Self::UnsafeName { kind, name } => {
                write!(f, "unsafe {kind} name would corrupt the info file: {name:?}")
            }
        }
    }
}

impl std::error::Error for InfoFormatError {}

/// Strict INI parser. Blank lines and `#` / `;` comments are ignored. Every other line
/// must either be a `[section]` header or a `key=value` pair under the current section.
///
/// # Errors
///
/// Returns [`InfoFormatError::InvalidLine`] for non-section lines without `=`, or
/// [`InfoFormatError::UnterminatedSection`] for `[section` lines missing the closing `]`.
pub fn parse(content: &str) -> Result<InfoFile, InfoFormatError> {
    let mut file = InfoFile::new();
    let mut current_section: Option<String> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_number = idx + 1;
        let trimmed = raw_line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                current_section = Some(name.to_owned());
                file.sections.entry(name.to_owned()).or_default();
            } else {
                return Err(InfoFormatError::UnterminatedSection {
                    line_number,
                    line: raw_line.to_owned(),
                });
            }
            continue;
        }

        let Some(eq_idx) = trimmed.find('=') else {
            return Err(InfoFormatError::InvalidLine {
                line_number,
                line: raw_line.to_owned(),
            });
        };

        let key = trimmed[..eq_idx].to_owned();
        let value = trimmed[eq_idx + 1..].to_owned();

        let section_name = current_section.clone().unwrap_or_default();
        let entry = file.sections.entry(section_name).or_default();
        entry.insert(key, value);
    }

    Ok(file)
}

/// Render an [`InfoFile`] back to text. Sections are emitted in insertion order, keys in
/// insertion order within each section, and sections are separated by a blank line.
#[must_use]
pub fn render(file: &InfoFile) -> String {
    let mut out = String::new();
    let mut first = true;

    for (section, entries) in &file.sections {
        if !first {
            out.push('\n');
        }
        first = false;

        out.push('[');
        out.push_str(section);
        out.push_str("]\n");

        for (key, value) in entries {
            out.push_str(key);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        }
    }

    out
}

/// Reject a section name or key that, rendered verbatim, would break out of its
/// intended INI position.
///
/// A name is rejected when it:
/// - contains a `\n` or `\r` (would inject additional lines),
/// - contains an `=` (a key with `=` would be mis-split on parse; also lets a key
///   masquerade as `key=value` boundary manipulation), or
/// - begins with `[`, `#`, `;`, or an ASCII space / tab (the parser treats these
///   as a section header, a comment, or trims leading whitespace — any of which
///   changes how the round-tripped line is interpreted).
///
/// # Errors
///
/// Returns [`InfoFormatError::UnsafeName`] describing the offending token.
pub fn validate_name(kind: &'static str, name: &str) -> Result<(), InfoFormatError> {
    let unsafe_first = matches!(name.as_bytes().first().copied(), Some(b'[' | b'#' | b';' | b' ' | b'\t'));
    if name.contains(['\n', '\r', '=']) || unsafe_first {
        return Err(InfoFormatError::UnsafeName {
            kind,
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// Validate every section name and key in `file` via [`validate_name`]. Shared
/// by the checked render entry points.
///
/// # Errors
///
/// Returns [`InfoFormatError::UnsafeName`] for the first offending token.
fn validate_all(file: &InfoFile) -> Result<(), InfoFormatError> {
    for (section, entries) in &file.sections {
        validate_name("section", section)?;
        for key in entries.keys() {
            validate_name("key", key)?;
        }
    }
    Ok(())
}

/// Like [`render`] but first validates every section name and key so that no
/// attacker-controlled token can inject INI structure into the rendered file.
///
/// The infallible [`render`] remains for the round-trip test fixtures whose keys
/// are trusted constants; the *write* paths use [`checksumed_render_checked`].
///
/// # Errors
///
/// Returns [`InfoFormatError::UnsafeName`] for the first section or key that
/// would corrupt the envelope. See [`validate_name`].
pub fn render_checked(file: &InfoFile) -> Result<String, InfoFormatError> {
    validate_all(file)?;
    Ok(render(file))
}

/// Compute the SHA-1 (lowercase hex) of `content`. The caller is responsible for handing
/// in the file text *with the `backrest-checksum=...` line already removed*.
#[must_use]
pub fn checksum(content_excluding_checksum_line: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(content_excluding_checksum_line.as_bytes());
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // SAFETY: `write!` to String never fails; we only target ASCII hex.
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Strip the `backrest-checksum=...` line from `content` (preserving every other line and
/// trailing newline behaviour) and return the result.
fn strip_checksum_line(content: &str) -> String {
    // The on-disk line shape is `backrest-checksum=...`. We match on prefix so that
    // whatever quoting / JSON escaping the value uses, the line is still removed cleanly.
    let prefix = format!("{CHECKSUM_KEY}=");
    let mut out = String::with_capacity(content.len());
    for line in content.split_inclusive('\n') {
        // `split_inclusive` keeps the trailing newline; trim it for the prefix check only.
        let body = line.strip_suffix('\n').unwrap_or(line);
        if body.trim_start().starts_with(&prefix) {
            // Drop this line entirely, including its newline.
            continue;
        }
        out.push_str(line);
    }
    out
}

/// Parse `raw`, verify its `backrest-checksum`, and return the resulting [`InfoFile`].
///
/// # Errors
///
/// Returns [`InfoFormatError::MissingChecksum`] if no checksum line is present and
/// [`InfoFormatError::ChecksumMismatch`] if the checksum does not match. Parsing errors
/// from [`parse`] are propagated unchanged.
pub fn checksumed_load(raw: &str) -> Result<InfoFile, InfoFormatError> {
    let file = parse(raw)?;

    let expected_raw = file
        .get(BACKREST_SECTION, CHECKSUM_KEY)
        .ok_or(InfoFormatError::MissingChecksum)?;
    // The on-disk value is JSON-encoded ("abc..."); strip surrounding quotes if present.
    let expected = expected_raw.trim().trim_matches('"').to_owned();

    let stripped = strip_checksum_line(raw);
    let actual = checksum(&stripped);

    if actual != expected {
        return Err(InfoFormatError::ChecksumMismatch { actual, expected });
    }

    Ok(file)
}

/// Render `file` to text after recomputing the `backrest-checksum`. The caller passes a
/// document that may or may not already contain a checksum entry — either is fine.
#[must_use]
pub fn checksumed_render(file: &InfoFile) -> String {
    // Work on a clone so we can drop the existing checksum and re-add the freshly
    // computed one. The original `file` is left untouched.
    let mut clone = file.clone();
    if let Some(section) = clone.sections.get_mut(BACKREST_SECTION) {
        section.shift_remove(CHECKSUM_KEY);
    }

    // Render once without the checksum to get the text the SHA-1 will be taken over.
    let body = render(&clone);
    let digest = checksum(&body);

    // Re-insert the checksum into the `[backrest]` section. The on-disk encoding is a
    // JSON string ("..."), matching the C side which stored every value as JSON.
    clone.set(BACKREST_SECTION, CHECKSUM_KEY, format!("\"{digest}\""));

    render(&clone)
}

/// Like [`checksumed_render`] but validates every section name and key first.
///
/// This way no attacker-controlled token (e.g. a hostile manifest file path)
/// can inject INI structure before the checksum is taken over the rendered
/// text. The checksum is computed *after* render, so validation here is what
/// stops a crafted key from producing a document that both parses and passes
/// its own checksum.
///
/// # Errors
///
/// Returns [`InfoFormatError::UnsafeName`] for the first unsafe section / key.
pub fn checksumed_render_checked(file: &InfoFile) -> Result<String, InfoFormatError> {
    // Validate against the original document (the checksum key added by
    // `checksumed_render` is a trusted constant, so validating up-front is
    // equivalent and keeps the error surface obvious).
    validate_all(file)?;
    Ok(checksumed_render(file))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_archive_info() -> String {
        // `checksumed_render` produces the canonical layout below; the test fixture is
        // produced by computing the checksum the same way the renderer does so the two
        // stay in lock-step.
        let mut file = InfoFile::new();
        file.set(BACKREST_SECTION, "backrest-format", "5");
        file.set(BACKREST_SECTION, "backrest-version", "\"2.58\"");
        file.set("db", "db-id", "1");
        file.set("db", "db-system-id", "6873049345984568091");
        file.set("db", "db-version", "\"14\"");
        file.set("db:history", "1", "{\"db-id\":6873049345984568091,\"db-version\":\"14\"}");
        checksumed_render(&file)
    }

    #[test]
    fn parse_then_render_round_trips_byte_identical() {
        let text = sample_archive_info();
        let parsed = parse(&text).unwrap();
        let rendered = render(&parsed);
        assert_eq!(rendered, text);
    }

    #[test]
    fn checksumed_load_accepts_freshly_rendered_file() {
        let text = sample_archive_info();
        let file = checksumed_load(&text).unwrap();
        assert_eq!(file.get("db", "db-id"), Some("1"));
    }

    #[test]
    fn checksumed_load_rejects_flipped_body_byte() {
        let mut text = sample_archive_info();
        // Flip a single body character (db-id=1 -> db-id=2). The checksum line itself is
        // untouched, so the comparison must report a mismatch.
        let needle = "db-id=1\n";
        let pos = text.find(needle).unwrap();
        let bytes = unsafe { text.as_bytes_mut() };
        bytes[pos + needle.len() - 2] = b'2';

        let err = checksumed_load(&text).unwrap_err();
        assert!(matches!(err, InfoFormatError::ChecksumMismatch { .. }));
    }

    #[test]
    fn checksumed_load_reports_missing_checksum() {
        let mut file = InfoFile::new();
        file.set("db", "db-id", "1");
        let text = render(&file);
        let err = checksumed_load(&text).unwrap_err();
        assert_eq!(err, InfoFormatError::MissingChecksum);
    }

    #[test]
    fn parse_rejects_invalid_line() {
        let err = parse("[db]\nnoequalshere\n").unwrap_err();
        match err {
            InfoFormatError::InvalidLine { line_number, line } => {
                assert_eq!(line_number, 2);
                assert_eq!(line, "noequalshere");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_unterminated_section() {
        let err = parse("[db\nkey=value\n").unwrap_err();
        match err {
            InfoFormatError::UnterminatedSection { line_number, line } => {
                assert_eq!(line_number, 1);
                assert_eq!(line, "[db");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_skips_blank_and_comment_lines() {
        let text = "# leading comment\n\n[db]\n; semicolon comment\ndb-id=1\n";
        let file = parse(text).unwrap();
        assert_eq!(file.get("db", "db-id"), Some("1"));
    }

    #[test]
    fn checksumed_render_overwrites_existing_checksum() {
        let mut file = InfoFile::new();
        file.set(BACKREST_SECTION, "backrest-format", "5");
        file.set(BACKREST_SECTION, CHECKSUM_KEY, "\"deadbeef\"");
        file.set("db", "db-id", "1");

        let rendered = checksumed_render(&file);
        // The stale checksum must not appear in the rendered output.
        assert!(!rendered.contains("deadbeef"));
        // And the freshly rendered file must round-trip through `checksumed_load`.
        assert!(checksumed_load(&rendered).is_ok());
    }

    #[test]
    fn checksumed_render_checked_rejects_injected_key() {
        // A hostile key embedding a newline + a bogus section must be rejected at
        // render time rather than smuggled into the checksumed document.
        let mut file = InfoFile::new();
        file.set(BACKREST_SECTION, "backrest-format", "5");
        file.set("target:file", "x\n[target:link]\npg_data/pg_wal", "{}");

        let err = checksumed_render_checked(&file).unwrap_err();
        assert!(matches!(err, InfoFormatError::UnsafeName { kind: "key", .. }));
    }

    #[test]
    fn validate_name_flags_the_hostile_shapes() {
        // Structural characters and leading tokens the parser would reinterpret.
        assert!(validate_name("key", "has\nnewline").is_err());
        assert!(validate_name("key", "has\rcarriage").is_err());
        assert!(validate_name("key", "has=equals").is_err());
        assert!(validate_name("key", "[section-like").is_err());
        assert!(validate_name("key", "#comment-like").is_err());
        assert!(validate_name("key", ";comment-like").is_err());
        assert!(validate_name("key", " leading-space").is_err());
        assert!(validate_name("key", "\tleading-tab").is_err());
        // A normal PGDATA-relative path is accepted.
        assert!(validate_name("key", "pg_data/base/1/1259").is_ok());
    }

    #[test]
    fn render_checked_matches_render_for_safe_input() {
        let text = sample_archive_info();
        let file = parse(&text).unwrap();
        assert_eq!(render_checked(&file).unwrap(), render(&file));
    }

    #[test]
    fn strip_checksum_line_removes_only_target_line() {
        let input = "[backrest]\nbackrest-checksum=\"abc\"\nbackrest-format=5\n";
        let stripped = strip_checksum_line(input);
        assert_eq!(stripped, "[backrest]\nbackrest-format=5\n");
    }
}
