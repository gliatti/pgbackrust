// Build scripts run at compile time and short-circuit the build on failure, so unwrap/expect/panic
// are the right primitives here — wrapping each i/o or parse step in a typed Error would just add
// noise without giving the build any extra recovery options.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::option_if_let_else)]

//! Build script for `pgbr-error`.
//!
//! Reads `src/build/error/error.yaml` (the C-side source of truth for error codes) and emits a
//! Rust module `error_types.rs` into `OUT_DIR`. The generated module exposes an `ErrorType` enum
//! with the same numeric discriminants as the C `errorType*` codes plus lookups by code/name and
//! a parent-chain `extends` walk that mirrors the C `errorTypeExtends` semantics.
//!
//! The YAML grammar is intentionally narrow (single-document, two indentation levels, only
//! `code`, `fatal`, and an optional `parent:` sub-key) so we parse it with a hand-rolled state
//! machine rather than pulling a YAML crate into the build graph.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

// Sentinel parent name used when an entry omits `parent:`. The runtime entry is its own parent,
// matching the C self-loop in `error.auto.c.inc`.
const DEFAULT_PARENT: &str = "runtime";

#[derive(Debug)]
struct Entry {
    name: String,
    code: i32,
    fatal: bool,
    parent: String,
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
    validate_parents(&entries);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_path = out_dir.join("error_types.rs");
    let mut out = fs::File::create(&out_path).expect("create error_types.rs");

    emit_module(&mut out, &entries);
}

fn parse_error_yaml(content: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut pending: Option<(String, Option<i32>, bool, String)> = None;

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
            if let Some((name, Some(code), fatal, parent)) = pending.take() {
                entries.push(Entry {
                    name,
                    code,
                    fatal,
                    parent,
                });
            }

            if value.is_empty() {
                // `name:` followed by indented sub-keys.
                pending = Some((key.to_string(), None, false, DEFAULT_PARENT.to_string()));
            } else {
                // `name: code` shorthand.
                let code: i32 = value
                    .parse()
                    .unwrap_or_else(|_| panic!("expected integer code on `{trimmed}`"));
                entries.push(Entry {
                    name: key.to_string(),
                    code,
                    fatal: false,
                    parent: DEFAULT_PARENT.to_string(),
                });
            }
        } else {
            let (_, code, fatal, parent) = pending.as_mut().expect("indented line without parent key");
            match key {
                "code" => {
                    *code = Some(value.parse().expect("integer `code:`"));
                }
                "fatal" => {
                    *fatal = matches!(value, "true" | "yes");
                }
                "parent" => {
                    assert!(!value.is_empty(), "empty `parent:` value");
                    *parent = value.to_string();
                }
                other => panic!("unsupported sub-key `{other}` on indented line"),
            }
        }
    }

    if let Some((name, Some(code), fatal, parent)) = pending {
        entries.push(Entry {
            name,
            code,
            fatal,
            parent,
        });
    }

    entries
}

fn validate_parents(entries: &[Entry]) {
    for entry in entries {
        assert!(
            entries.iter().any(|e| e.name == entry.parent),
            "entry `{}` references unknown parent `{}` (must be the name of another YAML entry)",
            entry.name,
            entry.parent
        );
    }
    assert!(
        entries.iter().any(|e| e.name == DEFAULT_PARENT),
        "YAML must define an entry named `{DEFAULT_PARENT}` (used as the default parent)"
    );
}

#[allow(clippy::too_many_lines)]
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

    writeln!(
        out,
        "    /// Returns the variant whose YAML kebab-case name equals `name`, or `None` if no"
    )
    .unwrap();
    writeln!(out, "    /// such variant exists.").unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub fn from_name(name: &str) -> Option<Self> {{").unwrap();
    writeln!(out, "        match name {{").unwrap();
    for entry in entries {
        writeln!(
            out,
            "            \"{}\" => Some(Self::{}),",
            entry.name,
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
    writeln!(out).unwrap();

    writeln!(
        out,
        "    /// C-side symbol name (`PascalCase` + `Error` suffix), matching the second argument of"
    )
    .unwrap();
    writeln!(
        out,
        "    /// `ERROR_DEFINE` in `error.auto.c.inc` and the value returned by the C-side"
    )
    .unwrap();
    writeln!(
        out,
        "    /// `errorTypeName`. Used by the retry-message formatter to reproduce the legacy"
    )
    .unwrap();
    writeln!(out, "    /// `[FormatError]` / `[KernelError]` rendering byte-for-byte.").unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn c_name(self) -> &'static str {{").unwrap();
    writeln!(out, "        match self {{").unwrap();
    for entry in entries {
        writeln!(
            out,
            "            Self::{} => \"{}Error\",",
            to_pascal_case(&entry.name),
            to_pascal_case(&entry.name)
        )
        .unwrap();
    }
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    /// Lookup helper: numeric code → C-side symbol name. Returns the literal"
    )
    .unwrap();
    writeln!(
        out,
        "    /// `\"UnknownError\"` for codes not in the shared table — the retry formatter never"
    )
    .unwrap();
    writeln!(
        out,
        "    /// receives unknown codes in production but the fallback keeps the function total"
    )
    .unwrap();
    writeln!(out, "    /// and the C ABI well-defined for fuzz inputs.").unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn c_name_for_code(code: i32) -> &'static str {{").unwrap();
    writeln!(out, "        match Self::from_code(code) {{").unwrap();
    writeln!(out, "            Some(t) => t.c_name(),").unwrap();
    writeln!(out, "            None => \"UnknownError\",").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    /// Parent variant in the error-type chain. The runtime entry is its own parent"
    )
    .unwrap();
    writeln!(
        out,
        "    /// (matching the C self-loop), so `parent` is a total function on `ErrorType`."
    )
    .unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    // The match arms are deliberately enumerated per variant rather than collapsed into a wildcard
    // so a future YAML edit that introduces a non-runtime parent (e.g. `json-format` -> `format`)
    // is a one-line change here. Today all entries currently parent to runtime, which the lint
    // would flag as duplicate arms — silence it on this method only.
    writeln!(out, "    #[allow(clippy::match_same_arms)]").unwrap();
    writeln!(out, "    pub const fn parent(self) -> Self {{").unwrap();
    writeln!(out, "        match self {{").unwrap();
    for entry in entries {
        writeln!(
            out,
            "            Self::{} => Self::{},",
            to_pascal_case(&entry.name),
            to_pascal_case(&entry.parent)
        )
        .unwrap();
    }
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "    /// Numeric code of the parent variant.").unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn parent_code(self) -> i32 {{").unwrap();
    writeln!(out, "        self.parent() as i32").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    /// Walks the parent chain starting from `self.parent()` and returns `true` if it"
    )
    .unwrap();
    writeln!(
        out,
        "    /// reaches `parent` before hitting the runtime self-loop. Strict: `self.extends(self)`"
    )
    .unwrap();
    writeln!(
        out,
        "    /// is `false` for any variant whose parent is not itself, matching `errorTypeExtends`."
    )
    .unwrap();
    writeln!(out, "    #[must_use]").unwrap();
    writeln!(out, "    pub const fn extends(self, parent: Self) -> bool {{").unwrap();
    writeln!(out, "        let mut find = self;").unwrap();
    writeln!(out, "        loop {{").unwrap();
    writeln!(out, "            let next = find.parent();").unwrap();
    writeln!(out, "            if next as i32 == parent as i32 {{").unwrap();
    writeln!(out, "                return true;").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "            if next as i32 == find as i32 {{").unwrap();
    writeln!(out, "                return false;").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "            find = next;").unwrap();
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
