//! `error.yaml` parser.
//!
//! The hand-written `src/build/error/error.yaml` defines every error type the
//! C build emits into `src/common/error/error.auto.{h,c.inc}`. Each entry maps a
//! kebab-case error name to either a bare integer code or a `{code, fatal}` map.
//!
//! Output is sorted by code so consumers can drop the result straight into a
//! lookup table.

use serde::Deserialize;
use std::collections::BTreeMap;

/// One error definition as parsed from `error.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ErrorDef {
    pub code: u32,
    pub name: String,
    /// `true` when the entry's `fatal:` field is set. Defaults to `false`.
    pub fatal: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawEntry {
    Code(u32),
    Detailed(DetailedEntry),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailedEntry {
    code: u32,
    #[serde(default)]
    fatal: bool,
}

/// Parses the YAML text of `src/build/error/error.yaml`.
///
/// Returns the entries sorted by numeric code (the natural order an error table
/// would use in `error.auto.c.inc`).
pub fn parse_errors(yaml: &str) -> Result<Vec<ErrorDef>, serde_yml::Error> {
    let raw: BTreeMap<String, RawEntry> = serde_yml::from_str(yaml)?;

    let mut out: Vec<ErrorDef> = raw
        .into_iter()
        .map(|(name, entry)| match entry {
            RawEntry::Code(code) => ErrorDef {
                code,
                name,
                fatal: false,
            },
            RawEntry::Detailed(d) => ErrorDef {
                code: d.code,
                name,
                fatal: d.fatal,
            },
        })
        .collect();

    out.sort_by_key(|e| e.code);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PATH: &str = "../../src/build/error/error.yaml";

    fn load_fixture() -> String {
        std::fs::read_to_string(FIXTURE_PATH).unwrap_or_else(|err| panic!("read {FIXTURE_PATH}: {err}"))
    }

    #[test]
    fn parses_short_form() {
        let entries = parse_errors("foo: 42\n").unwrap();
        assert_eq!(
            entries,
            vec![ErrorDef {
                code: 42,
                name: "foo".into(),
                fatal: false
            }]
        );
    }

    #[test]
    fn parses_detailed_form_with_fatal() {
        let entries = parse_errors("assert:\n  code: 25\n  fatal: true\n").unwrap();
        assert_eq!(
            entries,
            vec![ErrorDef {
                code: 25,
                name: "assert".into(),
                fatal: true
            }]
        );
    }

    #[test]
    fn parses_detailed_form_without_fatal_defaults_false() {
        let entries = parse_errors("foo:\n  code: 7\n").unwrap();
        assert_eq!(
            entries,
            vec![ErrorDef {
                code: 7,
                name: "foo".into(),
                fatal: false
            }]
        );
    }

    #[test]
    fn output_is_sorted_by_code() {
        let entries = parse_errors("b: 2\na: 1\nc: 3\n").unwrap();
        let codes: Vec<_> = entries.iter().map(|e| e.code).collect();
        assert_eq!(codes, vec![1, 2, 3]);
    }

    #[test]
    fn rejects_unknown_keys_in_detailed_form() {
        // The detailed form uses `deny_unknown_fields`. An unknown sub-key
        // makes that variant fail, and the bare-integer variant also fails
        // (it expects a scalar, not a map). The resulting `untagged` error
        // message is generic (`data did not match any variant`), so we only
        // assert that parsing fails — the specific shape of the error is an
        // implementation detail of `serde_yml`.
        assert!(parse_errors("foo:\n  code: 1\n  banana: true\n").is_err());
    }

    #[test]
    fn parses_repository_fixture() {
        let yaml = load_fixture();
        let entries = parse_errors(&yaml).unwrap();
        // Sanity: the repository file currently defines about 70 errors,
        // including the canonical ones below. We don't pin the exact count to
        // avoid breaking the test every time an error is added.
        assert!(entries.len() >= 50, "expected ≥50 errors, got {}", entries.len());

        let by_name: BTreeMap<&str, &ErrorDef> = entries.iter().map(|e| (e.name.as_str(), e)).collect();
        let assert_def = by_name.get("assert").expect("assert error must be defined");
        assert_eq!(assert_def.code, 25);
        assert!(assert_def.fatal, "assert must be marked fatal");

        let checksum_def = by_name.get("checksum").expect("checksum error must be defined");
        assert_eq!(checksum_def.code, 26);
        assert!(!checksum_def.fatal);
    }

    #[test]
    fn fixture_codes_are_unique() {
        let entries = parse_errors(&load_fixture()).unwrap();
        let mut seen = std::collections::HashSet::new();
        for entry in &entries {
            assert!(
                seen.insert(entry.code),
                "duplicate error code {} (entry {:?})",
                entry.code,
                entry.name,
            );
        }
    }
}
