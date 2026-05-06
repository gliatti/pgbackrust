//! `config.yaml` parser.
//!
//! `src/build/config/config.yaml` is the single source of truth for every
//! pgBackRest command, option group, and option. It is read at build time by
//! the C generator (which emits `config.auto.h` and `parse.auto.c.inc`) and,
//! starting with the Rust rewrite, by this crate (which exposes the same data
//! as typed Rust structures consumed by `pgbr-config`).
//!
//! ## Known limitation: duplicate keys in option `command:` blocks
//!
//! An option's `command:` block can use shortcut entries that legitimately
//! appear with the same key multiple times — `-command: start` followed by
//! `-command: stop` excludes both commands. YAML mappings in `serde_yml` (and
//! every other serde-driven YAML parser) collapse duplicate keys to the last
//! value. Until we replace the parsing path with an event-based walker, only
//! the last `-command:` / `+role:` entry is preserved. The vast majority of
//! options don't use these shortcuts, so this affects ~10 options. Resolution
//! of these shortcuts into a concrete command list is the responsibility of
//! `pgbr-config` and will be reworked there when needed.

use serde::Deserialize;
use std::collections::BTreeMap;

/// Top-level structure of `config.yaml`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub command: BTreeMap<String, CommandDef>,
    #[serde(rename = "optionGroup")]
    pub option_group: BTreeMap<String, EmptyMap>,
    pub option: BTreeMap<String, OptionDef>,
}

/// Empty mapping placeholder. Matches `{}` in YAML and rejects any keys.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EmptyMap {}

/// Per-command settings (e.g. `command.backup`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CommandDef {
    /// Command roles enabled for this command (`main`, `async`, `local`, `remote`).
    /// `main` is implicit and always present.
    #[serde(rename = "command-role")]
    pub command_role: BTreeMap<String, EmptyMap>,
    /// Whether this command logs to a file. Defaults to `true` when absent.
    #[serde(rename = "log-file")]
    pub log_file: Option<bool>,
    /// Override the default log level for the command's standard messages.
    #[serde(rename = "log-level-default")]
    pub log_level_default: Option<String>,
    /// Whether the command acquires a lock at startup.
    #[serde(rename = "lock-required")]
    pub lock_required: Option<bool>,
    /// Whether the command requires a remote-side lock.
    #[serde(rename = "lock-remote-required")]
    pub lock_remote_required: Option<bool>,
    /// Lock category (`archive`, `backup`, or `all`).
    #[serde(rename = "lock-type")]
    pub lock_type: Option<String>,
    /// Whether the command accepts positional parameters.
    #[serde(rename = "parameter-allowed")]
    pub parameter_allowed: Option<bool>,
    /// Hide the command from end-user docs.
    pub internal: Option<bool>,
}

/// Per-option settings (e.g. `option.repo-path`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OptionDef {
    /// Option type: `string`, `path`, `boolean`, `integer`, `size`, `time`,
    /// `string-id`, `list`, `hash`. `None` is valid only when `inherit:` is set
    /// and the type comes from the parent.
    #[serde(rename = "type")]
    pub type_: Option<String>,
    /// Inherit all settings from another option; locally specified fields
    /// override the parent.
    pub inherit: Option<String>,
    /// Default value for the option. Can be a scalar, a sequence of single-key
    /// mappings (per-flavor defaults like `[{bz2: 9}, {gz: 6}]`), etc.
    pub default: Option<serde_yml::Value>,
    /// `literal`, `dynamic`, or `quote`.
    #[serde(rename = "default-type")]
    pub default_type: Option<String>,
    pub negate: Option<bool>,
    pub reset: Option<bool>,
    pub sequence: Option<bool>,
    pub internal: Option<bool>,
    /// Mark a string option as containing a secret (logged as `<redacted>`).
    pub secure: Option<bool>,
    pub required: Option<bool>,
    /// `global` or `stanza` for config-file options. Absent for
    /// command-line-only options.
    pub section: Option<String>,
    /// Option group: `pg` or `repo`.
    pub group: Option<String>,
    /// Booleans that double as string-id values (y/n -> string).
    #[serde(rename = "bool-like")]
    pub bool_like: Option<bool>,
    /// Marked beta — only available when `--beta` is passed.
    pub beta: Option<bool>,
    /// Allowed scalar values, optionally with per-command overrides.
    #[serde(rename = "allow-list")]
    pub allow_list: Option<Vec<serde_yml::Value>>,
    /// Numeric allow-range, optionally per flavor.
    #[serde(rename = "allow-range")]
    pub allow_range: Option<serde_yml::Value>,
    /// Dependency on another option.
    pub depend: Option<Depend>,
    /// Old names this option is also known by (back-compat). Each key is an
    /// old name; the value is currently always an empty map but may grow
    /// metadata in the future.
    pub deprecate: Option<BTreeMap<String, EmptyMap>>,
    /// Per-command settings. Either a string (inherit commands from another
    /// option) or a map keyed by command name (with `+role`/`+inherit`/`-command`
    /// shortcut keys).
    pub command: OptionCommandSpec,
    /// Override `command-role` set at the option level. Empty when absent.
    #[serde(rename = "command-role")]
    pub command_role: BTreeMap<String, EmptyMap>,
}

/// The two shapes an option's `command:` field may take.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OptionCommandSpec {
    /// `command: <option-name>` — inherit the resolved command list of another option.
    Inherit(String),
    /// `command: { name: { ... }, +role: any, -command: stop, ... }`
    Map(BTreeMap<String, OptionCommandEntry>),
}

impl Default for OptionCommandSpec {
    fn default() -> Self {
        Self::Map(BTreeMap::new())
    }
}

// The Override variant carries a struct considerably larger than the other two
// variants; clippy's `large_enum_variant` would normally flag this. The map is
// intentionally heterogeneous (real command names map to overrides; shortcut
// keys map to scalars/sequences) and the size penalty is acceptable here.
#[allow(clippy::large_enum_variant)]
/// One entry within an option's `command:` map.
///
/// Real command names map to an [`OptionCommandOverride`] (possibly empty
/// `{}`). Shortcut keys like `+role`, `+inherit`, `-command` map to a string
/// scalar; when the same shortcut appears multiple times in the source YAML,
/// the [`preprocess_config`] pre-processor fuses them into a list, which lands
/// here as the `Sequence` variant.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OptionCommandEntry {
    /// Scalar value for a single shortcut entry (`+role: any`).
    Scalar(String),
    /// List of values produced by merging duplicate shortcut entries
    /// (`-command: start`, `-command: stop` -> `[start, stop]`).
    Sequence(Vec<String>),
    /// Per-command override for a real command name. `{}` deserializes as the
    /// default (no overrides).
    Override(OptionCommandOverride),
}

impl OptionCommandEntry {
    /// Iterate over the value(s) of a shortcut entry, treating both `Scalar`
    /// and `Sequence` uniformly. Returns an empty iterator for `Override`.
    pub fn shortcut_values(&self) -> impl Iterator<Item = &str> {
        // Box to unify the two iterator types behind a single return shape.
        let v: Box<dyn Iterator<Item = &str>> = match self {
            Self::Scalar(s) => Box::new(std::iter::once(s.as_str())),
            Self::Sequence(v) => Box::new(v.iter().map(String::as_str)),
            Self::Override(_) => Box::new(std::iter::empty()),
        };
        v
    }
}

/// Override applied to a single command for one option (`option.foo.command.backup`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OptionCommandOverride {
    pub default: Option<serde_yml::Value>,
    pub required: Option<bool>,
    pub internal: Option<bool>,
    pub depend: Option<Depend>,
    pub sequence: Option<bool>,
    #[serde(rename = "allow-list")]
    pub allow_list: Option<Vec<serde_yml::Value>>,
    #[serde(rename = "command-role")]
    pub command_role: Option<BTreeMap<String, EmptyMap>>,
}

/// Dependency description for an option.
///
/// Accepts both shapes that `config.yaml` uses:
/// - `depend: <option-name>` — a bare string, equivalent to `{option: <name>}`.
/// - `depend: {option: ..., list: ..., default: ...}` — the explicit map form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Depend {
    /// Name of the option this one depends on.
    pub option: Option<String>,
    /// Allowable values of the dependency option.
    pub list: Option<Vec<serde_yml::Value>>,
    /// Default to apply when the dependency is unresolved.
    pub default: Option<serde_yml::Value>,
}

impl<'de> Deserialize<'de> for Depend {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DependVisitor;

        impl<'de> serde::de::Visitor<'de> for DependVisitor {
            type Value = Depend;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an option name string or a {option, list, default} map")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(Depend {
                    option: Some(s.to_owned()),
                    list: None,
                    default: None,
                })
            }

            fn visit_string<E: serde::de::Error>(self, s: String) -> Result<Self::Value, E> {
                Ok(Depend {
                    option: Some(s),
                    list: None,
                    default: None,
                })
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                #[derive(Default, Deserialize)]
                #[serde(default, deny_unknown_fields)]
                struct Helper {
                    option: Option<String>,
                    list: Option<Vec<serde_yml::Value>>,
                    default: Option<serde_yml::Value>,
                }
                let h = Helper::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(Depend {
                    option: h.option,
                    list: h.list,
                    default: h.default,
                })
            }
        }

        deserializer.deserialize_any(DependVisitor)
    }
}

/// Parses the YAML text of `src/build/config/config.yaml`.
///
/// The hand-written `config.yaml` uses two patterns that strict YAML parsers
/// reject as duplicate keys:
///
/// 1. **Additive shortcuts** — inside an option's `command:` map, the same
///    shortcut key (`+role`, `-command`, `+inherit`) appears on consecutive
///    lines to extend a list (`-command: start` / `-command: stop`).
/// 2. **Override duplicates** — at most one option (`pg-host-port` today) has
///    two non-shortcut keys with the same name (`default: ~` then
///    `default: [{tls: 8432}]`); the second overrides the first.
///
/// [`preprocess_config`] rewrites the YAML text to merge case (1) into a flow
/// sequence and drop earlier occurrences of case (2), producing a
/// duplicate-free YAML that `serde_yml` can parse directly.
pub fn parse_config(yaml: &str) -> Result<Config, serde_yml::Error> {
    let cleaned = preprocess_config(yaml);
    serde_yml::from_str(&cleaned)
}

/// Returns a duplicate-free rewrite of `config.yaml`'s text. See
/// [`parse_config`] for the rationale.
#[must_use]
pub fn preprocess_config(yaml: &str) -> String {
    let lines: Vec<&str> = yaml.lines().collect();
    let mut to_drop = vec![false; lines.len()];
    let mut replacements: BTreeMap<usize, String> = BTreeMap::new();

    let mut stack: Vec<PreprocessFrame> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();

        // Pop frames whose scope has ended (deeper indent than the current
        // line means we've left them).
        while stack.last().is_some_and(|f| f.indent > indent) {
            if let Some(frame) = stack.pop() {
                finalize_frame(&frame, &lines, &mut to_drop, &mut replacements);
            }
        }

        // Push a frame for a newly entered, deeper-indented mapping.
        if stack.last().is_none_or(|f| f.indent < indent) {
            stack.push(PreprocessFrame {
                indent,
                seen: BTreeMap::new(),
            });
        }

        // Record the kv entry on the top frame so finalize_frame() can spot
        // duplicates when the frame is popped.
        if let Some((kv_indent, key, _value)) = parse_kv_line(line)
            && kv_indent == indent
            && let Some(frame) = stack.last_mut()
        {
            frame.seen.entry(key.to_owned()).or_default().push(i);
        }
    }

    while let Some(frame) = stack.pop() {
        finalize_frame(&frame, &lines, &mut to_drop, &mut replacements);
    }

    let mut out = String::with_capacity(yaml.len());
    for (i, line) in lines.iter().enumerate() {
        if to_drop[i] {
            continue;
        }
        if let Some(repl) = replacements.get(&i) {
            out.push_str(repl);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// One enclosing YAML mapping while scanning [`preprocess_config`]'s line stream.
///
/// Holds the indent of its child keys plus, for each key seen, the indices of
/// the lines that introduced it. Once the frame is popped (we leave its scope),
/// duplicate-key resolution runs over `seen`.
struct PreprocessFrame {
    indent: usize,
    seen: BTreeMap<String, Vec<usize>>,
}

fn finalize_frame(frame: &PreprocessFrame, lines: &[&str], to_drop: &mut [bool], replacements: &mut BTreeMap<usize, String>) {
    for (key, indices) in &frame.seen {
        if indices.len() <= 1 {
            continue;
        }

        let is_additive = key.starts_with('+') || key.starts_with('-');
        // Consecutive iff every line strictly between successive indices is
        // blank or a comment (additive shortcuts always come back-to-back
        // in this file).
        let consecutive = indices.windows(2).all(|w| {
            lines[w[0] + 1..w[1]].iter().all(|l| {
                let t = l.trim_start();
                t.is_empty() || t.starts_with('#')
            })
        });

        if is_additive && consecutive {
            let pad = " ".repeat(frame.indent);
            let values: Vec<String> = indices
                .iter()
                .filter_map(|&idx| parse_kv_line(lines[idx]).map(|(_, _, v)| v.to_owned()))
                .collect();
            replacements.insert(indices[0], format!("{pad}{key}: [{}]", values.join(", ")));
            for &idx in &indices[1..] {
                to_drop[idx] = true;
            }
        } else {
            // Last-wins: drop every occurrence except the final one.
            for &idx in &indices[..indices.len() - 1] {
                to_drop[idx] = true;
            }
        }
    }
}

/// Parse a YAML mapping-entry line into (indent, key, value-on-line). Returns
/// `None` for blank lines, comment-only lines, sequence items (`- x`), and
/// any line without a top-level `:` separator.
fn parse_kv_line(line: &str) -> Option<(usize, &str, &str)> {
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();

    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "-" || trimmed.starts_with("- ") {
        return None;
    }

    let bytes = trimmed.as_bytes();
    let mut colon = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b':' && (i + 1 == bytes.len() || matches!(bytes[i + 1], b' ' | b'\t')) {
            colon = Some(i);
            break;
        }
    }
    let pos = colon?;
    let key = &trimmed[..pos];
    let value = trimmed.get(pos + 1..).unwrap_or("").trim();
    Some((indent, key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PATH: &str = "../../src/build/config/config.yaml";

    fn load_fixture() -> String {
        std::fs::read_to_string(FIXTURE_PATH).unwrap_or_else(|err| panic!("read {FIXTURE_PATH}: {err}"))
    }

    #[test]
    fn parses_minimal_command_only() {
        let yaml = "command:\n  ping:\n    log-file: false\n\noptionGroup: {}\n\noption: {}\n";
        let cfg = parse_config(yaml).unwrap();
        assert_eq!(cfg.command["ping"].log_file, Some(false));
        assert!(cfg.option_group.is_empty());
        assert!(cfg.option.is_empty());
    }

    #[test]
    fn parses_command_with_roles() {
        let yaml = "
command:
  backup:
    command-role:
      local: {}
      remote: {}
    lock-required: true
    lock-type: backup
optionGroup: {}
option: {}
";
        let cfg = parse_config(yaml).unwrap();
        let cmd = &cfg.command["backup"];
        assert_eq!(cmd.lock_required, Some(true));
        assert_eq!(cmd.lock_type.as_deref(), Some("backup"));
        assert!(cmd.command_role.contains_key("local"));
        assert!(cmd.command_role.contains_key("remote"));
    }

    #[test]
    fn option_command_can_be_inherited_from_string() {
        let yaml = "
command: {}
optionGroup: {}
option:
  compress-level:
    type: integer
    command: compress
";
        let cfg = parse_config(yaml).unwrap();
        let opt = &cfg.option["compress-level"];
        assert!(matches!(&opt.command, OptionCommandSpec::Inherit(name) if name == "compress"));
    }

    #[test]
    fn option_command_map_with_empty_and_overridden_entries() {
        let yaml = "
command: {}
optionGroup: {}
option:
  set:
    type: string
    command:
      annotate:
        required: true
      info:
        depend:
          option: stanza
      restore:
        default: latest
        required: true
";
        let cfg = parse_config(yaml).unwrap();
        let OptionCommandSpec::Map(map) = &cfg.option["set"].command else {
            panic!("expected Map for set.command");
        };
        let OptionCommandEntry::Override(annotate) = &map["annotate"] else {
            panic!("expected Override for annotate");
        };
        assert_eq!(annotate.required, Some(true));

        let OptionCommandEntry::Override(info) = &map["info"] else {
            panic!("expected Override for info");
        };
        let dep = info.depend.as_ref().unwrap();
        assert_eq!(dep.option.as_deref(), Some("stanza"));

        let OptionCommandEntry::Override(restore) = &map["restore"] else {
            panic!("expected Override for restore");
        };
        assert_eq!(restore.required, Some(true));
        assert_eq!(restore.default.as_ref().and_then(|v| v.as_str()), Some("latest"));
    }

    #[test]
    fn shortcut_keys_parse_as_scalar() {
        let yaml = "
command: {}
optionGroup: {}
option:
  cmd:
    type: string
    command:
      +role: async
";
        let cfg = parse_config(yaml).unwrap();
        let OptionCommandSpec::Map(map) = &cfg.option["cmd"].command else {
            panic!("expected Map");
        };
        let OptionCommandEntry::Scalar(value) = &map["+role"] else {
            panic!("expected Scalar for +role");
        };
        assert_eq!(value, "async");
    }

    #[test]
    fn duplicate_additive_shortcuts_merge_into_sequence() {
        // Two `-command:` entries on consecutive lines must collapse into a
        // single Sequence-valued entry by way of preprocess_config.
        let yaml = "
command: {}
optionGroup: {}
option:
  buffer-size:
    type: size
    command:
      +role: any
      -command: start
      -command: stop
";
        let cfg = parse_config(yaml).unwrap();
        let OptionCommandSpec::Map(map) = &cfg.option["buffer-size"].command else {
            panic!("expected Map");
        };

        // `+role: any` appears once -> stays Scalar.
        let role = &map["+role"];
        assert!(matches!(role, OptionCommandEntry::Scalar(s) if s == "any"));
        assert_eq!(role.shortcut_values().collect::<Vec<_>>(), vec!["any"]);

        // `-command:` appears twice -> Sequence.
        let excludes = &map["-command"];
        let OptionCommandEntry::Sequence(items) = excludes else {
            panic!("expected Sequence for -command, got {excludes:?}");
        };
        assert_eq!(items, &vec!["start".to_owned(), "stop".to_owned()]);
        assert_eq!(excludes.shortcut_values().collect::<Vec<_>>(), vec!["start", "stop"]);
    }

    #[test]
    fn duplicate_non_additive_keys_use_last_wins() {
        // `pg-host-port` has two `default:` lines at option level. Only the
        // last (the per-flavor list) should survive preprocessing.
        let yaml = "
command: {}
optionGroup: {}
option:
  pg-host-port:
    type: integer
    default: ~
    required: false
    default:
      - tls: 8432
";
        let cfg = parse_config(yaml).unwrap();
        let opt = &cfg.option["pg-host-port"];
        let default = opt.default.as_ref().expect("default must survive");

        let serde_yml::Value::Sequence(items) = default else {
            panic!("expected Sequence (the second default), got {default:?}");
        };
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], serde_yml::Value::Mapping(m) if m.contains_key("tls")));
    }

    #[test]
    fn preprocessor_leaves_non_duplicates_alone() {
        let original = "command:\n  ping:\n    log-file: false\noptionGroup: {}\noption: {}\n";
        // Preprocessor should produce the same lines (with a trailing newline)
        // when nothing needs merging or dropping.
        let processed = preprocess_config(original);
        // Allow a single trailing newline difference.
        assert_eq!(processed.trim_end_matches('\n'), original.trim_end_matches('\n'));
    }

    #[test]
    fn fixture_buffer_size_command_excludes_start_and_stop() {
        // Real fixture has the canonical -command shortcut pattern in the
        // `buffer-size` option's command block; verify the merge survived.
        let cfg = parse_config(&load_fixture()).unwrap();
        let buffer_size = &cfg.option["buffer-size"];
        let OptionCommandSpec::Map(map) = &buffer_size.command else {
            panic!("buffer-size.command must be a Map");
        };

        let excludes = map.get("-command").expect("buffer-size has -command exclusions");
        let names: Vec<_> = excludes.shortcut_values().collect();
        assert!(
            names.contains(&"start"),
            "expected -command to include `start`, got {names:?}"
        );
        assert!(names.contains(&"stop"), "expected -command to include `stop`, got {names:?}");
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let yaml = "command: {}\noptionGroup: {}\noption: {}\nsurprise: 1\n";
        let err = parse_config(yaml).unwrap_err();
        assert!(err.to_string().contains("surprise"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_unknown_command_field() {
        let yaml = "
command:
  ping:
    not-a-real-key: 1
optionGroup: {}
option: {}
";
        let err = parse_config(yaml).unwrap_err();
        assert!(err.to_string().contains("not-a-real-key"), "unexpected error: {err}");
    }

    // ---- Repository fixture coverage -----------------------------------------

    #[test]
    fn parses_repository_fixture() {
        let yaml = load_fixture();
        let cfg = parse_config(&yaml).unwrap();

        // Sanity check the count of top-level entities so schema additions are
        // visible without pinning exact numbers.
        assert!(cfg.command.len() >= 15, "≥15 commands expected, got {}", cfg.command.len());
        assert!(cfg.option.len() >= 100, "≥100 options expected, got {}", cfg.option.len());

        // Spot-check the canonical shape.
        assert!(cfg.command.contains_key("backup"));
        assert!(cfg.command.contains_key("restore"));
        assert!(cfg.command.contains_key("archive-push"));
        assert!(cfg.option_group.contains_key("pg"));
        assert!(cfg.option_group.contains_key("repo"));
    }

    #[test]
    fn fixture_command_backup_has_expected_settings() {
        let cfg = parse_config(&load_fixture()).unwrap();
        let backup = &cfg.command["backup"];
        assert_eq!(backup.lock_required, Some(true));
        assert_eq!(backup.lock_remote_required, Some(true));
        assert_eq!(backup.lock_type.as_deref(), Some("backup"));
        assert!(backup.command_role.contains_key("local"));
        assert!(backup.command_role.contains_key("remote"));
    }

    #[test]
    fn fixture_option_stanza_is_required_per_command() {
        let cfg = parse_config(&load_fixture()).unwrap();
        let stanza = &cfg.option["stanza"];
        assert_eq!(stanza.type_.as_deref(), Some("string"));

        let OptionCommandSpec::Map(map) = &stanza.command else {
            panic!("stanza.command must be a Map");
        };
        // `info: { required: false }` is the canonical override that exists on
        // this option in the file.
        let OptionCommandEntry::Override(info) = &map["info"] else {
            panic!("expected Override for info");
        };
        assert_eq!(info.required, Some(false));
    }

    #[test]
    fn fixture_compress_level_uses_per_flavor_default() {
        let cfg = parse_config(&load_fixture()).unwrap();
        let opt = &cfg.option["compress-level"];

        // `default:` is a sequence of single-key mappings: [{bz2: 9}, {gz: 6}, ...]
        let default = opt.default.as_ref().expect("compress-level has a default");
        let serde_yml::Value::Sequence(items) = default else {
            panic!("expected Sequence for compress-level.default, got {default:?}");
        };
        assert!(
            items
                .iter()
                .any(|item| { matches!(item, serde_yml::Value::Mapping(m) if m.contains_key("gz")) })
        );

        // `command:` is `command: compress` (string), inheriting from option `compress`.
        assert!(matches!(&opt.command, OptionCommandSpec::Inherit(name) if name == "compress"));
    }
}
