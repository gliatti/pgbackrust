// Build scripts run at compile time and short-circuit the build on failure, so unwrap/expect/panic
// are the right primitives here — wrapping each i/o or parse step in a typed Error would just add
// noise without giving the build any extra recovery options.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::option_if_let_else)]

//! Build script for `pgbr-error`.
//!
//! Reads `src/build/error/error.yaml` (the C-side source of truth for error codes) and emits a
//! Rust module `error_types.rs` into `OUT_DIR`. The generated module exposes an `ErrorType` enum
//! with the same numeric discriminants as the C `errorType*` codes plus a `from_code` lookup and
//! an `is_fatal` flag.
//!
//! The YAML grammar is intentionally narrow (single-document, two indentation levels, only `code`
//! and `fatal` sub-keys) so we parse it with a hand-rolled state machine rather than pulling a
//! YAML crate into the build graph.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug)]
struct Entry {
    name: String,
    code: i32,
    fatal: bool,
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let yaml_path = manifest_dir
        .join("..")
        .join("..")
        .join("src")
        .join("build")
        .join("error")
        .join("error.yaml");

    println!("cargo:rerun-if-changed={}", yaml_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let content = fs::read_to_string(&yaml_path).unwrap_or_else(|e| panic!("read {}: {}", yaml_path.display(), e));
    let entries = parse_error_yaml(&content);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_path = out_dir.join("error_types.rs");
    let mut out = fs::File::create(&out_path).expect("create error_types.rs");

    emit_module(&mut out, &entries);
}

fn parse_error_yaml(content: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut pending: Option<(String, Option<i32>, bool)> = None;

    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("");
        if line.trim().is_empty() {
            continue;
        }

        let leading = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        let (key, value) = trimmed.split_once(':').unwrap_or_else(|| panic!("missing colon: {trimmed}"));
        let key = key.trim();
        let value = value.trim();

        if leading == 0 {
            // Flush any pending object-form entry before starting a new one.
            if let Some((name, Some(code), fatal)) = pending.take() {
                entries.push(Entry { name, code, fatal });
            }

            if value.is_empty() {
                // `name:` followed by indented sub-keys.
                pending = Some((key.to_string(), None, false));
            } else {
                // `name: code` shorthand.
                let code: i32 = value
                    .parse()
                    .unwrap_or_else(|_| panic!("expected integer code on `{trimmed}`"));
                entries.push(Entry {
                    name: key.to_string(),
                    code,
                    fatal: false,
                });
            }
        } else {
            let (_, code, fatal) = pending.as_mut().expect("indented line without parent key");
            match key {
                "code" => {
                    *code = Some(value.parse().expect("integer `code:`"));
                }
                "fatal" => {
                    *fatal = matches!(value, "true" | "yes");
                }
                other => panic!("unsupported sub-key `{other}` on indented line"),
            }
        }
    }

    if let Some((name, Some(code), fatal)) = pending {
        entries.push(Entry { name, code, fatal });
    }

    entries
}

fn emit_module(out: &mut fs::File, entries: &[Entry]) {
    writeln!(
        out,
        "// Auto-generated from src/build/error/error.yaml by crates/pgbr-error/build.rs. Do not edit by hand."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "/// Error categories shared with the C side. Each discriminant matches the numeric code"
    )
    .unwrap();
    writeln!(
        out,
        "/// emitted by the C `errorType*` table; the values are stable across language boundaries."
    )
    .unwrap();
    writeln!(out, "#[repr(i32)]").unwrap();
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]").unwrap();
    writeln!(out, "#[non_exhaustive]").unwrap();
    writeln!(out, "pub enum ErrorType {{").unwrap();
    for entry in entries {
        writeln!(out, "    {} = {},", to_pascal_case(&entry.name), entry.code).unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl ErrorType {{").unwrap();

    writeln!(
        out,
        "    /// Returns the variant whose discriminant equals `code`, or `None` if `code` is not"
    )
    .unwrap();
    writeln!(out, "    /// part of the shared error table.").unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn from_code(code: i32) -> Option<Self> {{").unwrap();
    writeln!(out, "        match code {{").unwrap();
    for entry in entries {
        writeln!(
            out,
            "            {} => Some(Self::{}),",
            entry.code,
            to_pascal_case(&entry.name)
        )
        .unwrap();
    }
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "    /// Numeric code for this variant.").unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn code(self) -> i32 {{").unwrap();
    writeln!(out, "        self as i32").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    /// Whether the C side flags this variant as fatal (must abort the process)."
    )
    .unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn is_fatal(self) -> bool {{").unwrap();
    let fatal_variants: Vec<String> = entries
        .iter()
        .filter(|e| e.fatal)
        .map(|e| format!("Self::{}", to_pascal_case(&e.name)))
        .collect();
    if fatal_variants.is_empty() {
        writeln!(out, "        false").unwrap();
    } else {
        writeln!(out, "        matches!(self, {})", fatal_variants.join(" | ")).unwrap();
    }
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    /// Stable kebab-case identifier matching the YAML key (used for log output and"
    )
    .unwrap();
    writeln!(out, "    /// for cross-language diagnostics).").unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn name(self) -> &'static str {{").unwrap();
    writeln!(out, "        match self {{").unwrap();
    for entry in entries {
        writeln!(
            out,
            "            Self::{} => \"{}\",",
            to_pascal_case(&entry.name),
            entry.name
        )
        .unwrap();
    }
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();

    writeln!(out, "}}").unwrap();
}

fn to_pascal_case(s: &str) -> String {
    s.split('-')
        .filter(|w| !w.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(chars.flat_map(char::to_lowercase)).collect(),
            }
        })
        .collect()
}
