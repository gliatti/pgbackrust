//! Parser for `pgbackrest.conf` (INI format).
//!
//! Section grammar:
//!
//! - `[global]` — global defaults shared by every stanza.
//! - `[<stanza>]` — stanza-specific overrides (a stanza is the user-defined
//!   `PostgreSQL` cluster identifier passed via `--stanza`).
//! - `[global:<command>]` — global override applied only when running
//!   `<command>`.
//! - `[<stanza>:<command>]` — stanza override applied only when running
//!   `<command>`.
//!
//! Each section holds `key = value` pairs (with optional whitespace around `=`)
//! and `# …` comments. Blank lines are ignored.
//!
//! This module is purely textual; mapping the parsed entries to typed values
//! and resolving precedence against the CLI input lands in [`crate::merge`].

use std::collections::BTreeMap;
use std::fmt;

/// Identifier of one configuration section.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IniSection {
    /// `[global]`.
    Global,
    /// `[global:<command>]`.
    GlobalCommand(String),
    /// `[<stanza>]`.
    Stanza(String),
    /// `[<stanza>:<command>]`.
    StanzaCommand { stanza: String, command: String },
}

impl IniSection {
    fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();
        match trimmed.split_once(':') {
            Some((stanza, command)) => {
                if stanza == "global" {
                    Self::GlobalCommand(command.to_owned())
                } else {
                    Self::StanzaCommand {
                        stanza: stanza.to_owned(),
                        command: command.to_owned(),
                    }
                }
            }
            None => {
                if trimmed == "global" {
                    Self::Global
                } else {
                    Self::Stanza(trimmed.to_owned())
                }
            }
        }
    }
}

/// Parsed contents of one `pgbackrest.conf` file.
///
/// Value lookup uses raw textual keys (option name with optional `repoN-` /
/// `pgN-` prefix); the typed mapping happens in the merge step.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IniFile {
    /// Sections in order of first appearance, each carrying its key/value
    /// pairs (last write wins on duplicate keys within the same section).
    pub sections: BTreeMap<IniSection, BTreeMap<String, String>>,
}

/// Errors raised by [`parse_ini`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IniError {
    /// A non-blank, non-comment line outside any `[section]` header.
    KeyOutsideSection { line: usize, content: String },
    /// `[section` without a closing bracket.
    UnterminatedSection { line: usize, content: String },
    /// A line with no `=` separator and no trailing comment.
    MissingEquals { line: usize, content: String },
    /// A key that's empty after trimming (e.g. `=value`).
    EmptyKey { line: usize },
}

impl fmt::Display for IniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyOutsideSection { line, content } => {
                write!(f, "line {line}: key/value `{content}` is outside any section")
            }
            Self::UnterminatedSection { line, content } => {
                write!(f, "line {line}: unterminated section header `{content}`")
            }
            Self::MissingEquals { line, content } => {
                write!(f, "line {line}: line `{content}` has no `=` separator")
            }
            Self::EmptyKey { line } => write!(f, "line {line}: key is empty"),
        }
    }
}

impl std::error::Error for IniError {}

/// Parse the textual content of a `pgbackrest.conf` file.
///
/// # Errors
///
/// Returns [`IniError`] for structurally invalid content (key outside any
/// section, malformed header, missing `=`).
pub fn parse_ini(content: &str) -> Result<IniFile, IniError> {
    let mut out = IniFile::default();
    let mut current: Option<IniSection> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix('[') {
            let inner = rest.strip_suffix(']').ok_or_else(|| IniError::UnterminatedSection {
                line: line_no,
                content: raw_line.to_owned(),
            })?;
            let section = IniSection::parse(inner);
            // Initialize an empty mapping so an empty section still appears
            // in `sections`.
            out.sections.entry(section.clone()).or_default();
            current = Some(section);
            continue;
        }

        let section = current.as_ref().ok_or_else(|| IniError::KeyOutsideSection {
            line: line_no,
            content: raw_line.to_owned(),
        })?;
        let (k, v) = trimmed.split_once('=').ok_or_else(|| IniError::MissingEquals {
            line: line_no,
            content: raw_line.to_owned(),
        })?;
        let key = k.trim();
        if key.is_empty() {
            return Err(IniError::EmptyKey { line: line_no });
        }
        out.sections
            .entry(section.clone())
            .or_default()
            .insert(key.to_owned(), v.trim().to_owned());
    }

    Ok(out)
}

/// Strip a `#`-prefixed comment from a line. Quotes are not interpreted —
/// pgBackRest's INI grammar doesn't allow `#` inside values.
fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(before, _)| before)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_and_stanza_sections() {
        let ini = parse_ini(
            "[global]\nrepo1-path=/var/lib/pgbackrest\nlog-level-file=detail\n\n[demo]\npg1-path=/var/lib/postgresql/14/main\n",
        )
        .unwrap();

        let global = &ini.sections[&IniSection::Global];
        assert_eq!(global["repo1-path"], "/var/lib/pgbackrest");
        assert_eq!(global["log-level-file"], "detail");

        let demo = &ini.sections[&IniSection::Stanza("demo".to_owned())];
        assert_eq!(demo["pg1-path"], "/var/lib/postgresql/14/main");
    }

    #[test]
    fn parses_command_specific_sections() {
        let ini = parse_ini("[global:archive-push]\nbuffer-size=2MiB\n\n[demo:backup]\nstart-fast=y\n").unwrap();

        let g_arch = &ini.sections[&IniSection::GlobalCommand("archive-push".to_owned())];
        assert_eq!(g_arch["buffer-size"], "2MiB");

        let s_backup = &ini.sections[&IniSection::StanzaCommand {
            stanza: "demo".to_owned(),
            command: "backup".to_owned(),
        }];
        assert_eq!(s_backup["start-fast"], "y");
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let ini = parse_ini("# a comment\n\n[global]\n# another\nrepo1-path=/foo  # trailing\n").unwrap();
        assert_eq!(ini.sections[&IniSection::Global]["repo1-path"], "/foo");
    }

    #[test]
    fn whitespace_around_equals_is_trimmed() {
        let ini = parse_ini("[global]\n  log-level-file =   detail   \n").unwrap();
        assert_eq!(ini.sections[&IniSection::Global]["log-level-file"], "detail");
    }

    #[test]
    fn duplicate_key_in_same_section_last_wins() {
        let ini = parse_ini("[global]\nrepo1-path=/a\nrepo1-path=/b\n").unwrap();
        assert_eq!(ini.sections[&IniSection::Global]["repo1-path"], "/b");
    }

    #[test]
    fn rejects_key_outside_section() {
        let err = parse_ini("repo1-path=/foo\n").unwrap_err();
        assert!(matches!(err, IniError::KeyOutsideSection { line: 1, .. }));
    }

    #[test]
    fn rejects_unterminated_section() {
        let err = parse_ini("[global\nrepo1-path=/foo\n").unwrap_err();
        assert!(matches!(err, IniError::UnterminatedSection { line: 1, .. }));
    }

    #[test]
    fn rejects_missing_equals() {
        let err = parse_ini("[global]\norphan-line\n").unwrap_err();
        assert!(matches!(err, IniError::MissingEquals { line: 2, .. }));
    }

    #[test]
    fn rejects_empty_key() {
        let err = parse_ini("[global]\n=lonely\n").unwrap_err();
        assert!(matches!(err, IniError::EmptyKey { line: 2 }));
    }

    #[test]
    fn empty_section_still_appears() {
        let ini = parse_ini("[global]\n[demo]\n").unwrap();
        assert!(ini.sections.contains_key(&IniSection::Global));
        assert!(ini.sections.contains_key(&IniSection::Stanza("demo".to_owned())));
        assert!(ini.sections[&IniSection::Global].is_empty());
    }
}
