//! Typed values for option types.
//!
//! Maps the textual form a user types on the command line or writes in
//! `pgbackrest.conf` into a typed `OptionValue`, applying the size/time/bool
//! conventions documented in `help.xml`'s preamble:
//!
//! - **Boolean**: `y`/`n`, `yes`/`no`, `true`/`false`, case-insensitive.
//! - **Integer**: parsed as `i64`.
//! - **Size**: integer with optional case-insensitive suffix `B`, `KiB`/`KB`/`K`,
//!   `MiB`/`MB`/`M`, `GiB`/`GB`/`G`, `TiB`/`TB`/`T`, `PiB`/`PB`/`P`. The
//!   multiplier is a power of 1024 in every case (the C parser also accepts
//!   the SI shorthand `k`, `m`, `g`, … as 1024-based aliases). Fractional
//!   values are rejected.
//! - **Time**: integer in seconds. No suffixes.
//! - **String**, **Path**, **`StringId`**: kept as-is.
//! - **List**: comma-separated.
//! - **Hash**: `key=value` pairs.

use std::collections::BTreeMap;
use std::fmt;

use crate::types::OptionType;

/// A parsed option value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionValue {
    Boolean(bool),
    Integer(i64),
    /// Size in bytes.
    Size(u64),
    /// Time in seconds.
    Time(u64),
    Path(String),
    String(String),
    StringId(String),
    List(Vec<String>),
    Hash(BTreeMap<String, String>),
}

impl OptionValue {
    /// The [`OptionType`] this value carries.
    #[must_use]
    pub const fn option_type(&self) -> OptionType {
        match self {
            Self::Boolean(_) => OptionType::Boolean,
            Self::Integer(_) => OptionType::Integer,
            Self::Size(_) => OptionType::Size,
            Self::Time(_) => OptionType::Time,
            Self::Path(_) => OptionType::Path,
            Self::String(_) => OptionType::String,
            Self::StringId(_) => OptionType::StringId,
            Self::List(_) => OptionType::List,
            Self::Hash(_) => OptionType::Hash,
        }
    }
}

/// Errors raised while turning raw text into an [`OptionValue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    /// The text is not a valid value for the given type.
    Invalid {
        option_type: OptionType,
        raw: String,
        reason: String,
    },
    /// A `Path` value was empty or did not start with `/`.
    InvalidPath { raw: String, reason: String },
    /// A `Hash` entry was missing the `=` separator.
    InvalidHashEntry { raw: String },
    /// `Size` value overflowed `u64`.
    SizeOverflow { raw: String },
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid {
                option_type,
                raw,
                reason,
            } => {
                write!(f, "{}: {raw:?} is not a valid {} value", reason, option_type.as_str())
            }
            Self::InvalidPath { raw, reason } => {
                write!(f, "{reason}: {raw:?} is not a valid path")
            }
            Self::InvalidHashEntry { raw } => {
                write!(f, "hash entry {raw:?} is not in `key=value` form")
            }
            Self::SizeOverflow { raw } => {
                write!(f, "size {raw:?} overflows u64")
            }
        }
    }
}

impl std::error::Error for ValueError {}

/// Parse a raw command-line / config-file string into an [`OptionValue`] of
/// the given type.
///
/// # Errors
///
/// Returns [`ValueError`] when `raw` is not a valid representation of `ty`.
pub fn parse_value(ty: OptionType, raw: &str) -> Result<OptionValue, ValueError> {
    match ty {
        OptionType::Boolean => parse_boolean(raw).map(OptionValue::Boolean),
        OptionType::Integer => parse_integer(raw).map(OptionValue::Integer),
        OptionType::Size => parse_size(raw).map(OptionValue::Size),
        OptionType::Time => parse_time(raw).map(OptionValue::Time),
        OptionType::Path => parse_path(raw).map(OptionValue::Path),
        OptionType::String => Ok(OptionValue::String(raw.to_owned())),
        OptionType::StringId => Ok(OptionValue::StringId(raw.to_owned())),
        OptionType::List => Ok(OptionValue::List(parse_list(raw))),
        OptionType::Hash => parse_hash(raw).map(OptionValue::Hash),
    }
}

fn parse_boolean(raw: &str) -> Result<bool, ValueError> {
    let lc = raw.trim().to_ascii_lowercase();
    match lc.as_str() {
        "y" | "yes" | "true" | "on" | "1" => Ok(true),
        "n" | "no" | "false" | "off" | "0" => Ok(false),
        _ => Err(ValueError::Invalid {
            option_type: OptionType::Boolean,
            raw: raw.to_owned(),
            reason: "expected y/n, yes/no, true/false".to_owned(),
        }),
    }
}

fn parse_integer(raw: &str) -> Result<i64, ValueError> {
    raw.trim().parse::<i64>().map_err(|err| ValueError::Invalid {
        option_type: OptionType::Integer,
        raw: raw.to_owned(),
        reason: err.to_string(),
    })
}

fn parse_size(raw: &str) -> Result<u64, ValueError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ValueError::Invalid {
            option_type: OptionType::Size,
            raw: raw.to_owned(),
            reason: "empty".to_owned(),
        });
    }

    // Split into a numeric prefix and a (possibly empty) suffix.
    let split_at = trimmed
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit() && *c != '-')
        .map_or(trimmed.len(), |(i, _)| i);
    let (num_part, suffix) = trimmed.split_at(split_at);

    let n: u64 = num_part.parse::<u64>().map_err(|err| ValueError::Invalid {
        option_type: OptionType::Size,
        raw: raw.to_owned(),
        reason: format!("invalid number: {err}"),
    })?;

    let multiplier: u64 = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024_u64.pow(4),
        "p" | "pb" | "pib" => 1024_u64.pow(5),
        other => {
            return Err(ValueError::Invalid {
                option_type: OptionType::Size,
                raw: raw.to_owned(),
                reason: format!("unknown size suffix `{other}`"),
            });
        }
    };

    n.checked_mul(multiplier)
        .ok_or_else(|| ValueError::SizeOverflow { raw: raw.to_owned() })
}

fn parse_time(raw: &str) -> Result<u64, ValueError> {
    raw.trim().parse::<u64>().map_err(|err| ValueError::Invalid {
        option_type: OptionType::Time,
        raw: raw.to_owned(),
        reason: err.to_string(),
    })
}

fn parse_path(raw: &str) -> Result<String, ValueError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ValueError::InvalidPath {
            raw: raw.to_owned(),
            reason: "empty".to_owned(),
        });
    }
    if !trimmed.starts_with('/') {
        return Err(ValueError::InvalidPath {
            raw: raw.to_owned(),
            reason: "must begin with `/`".to_owned(),
        });
    }
    if trimmed.contains("//") {
        return Err(ValueError::InvalidPath {
            raw: raw.to_owned(),
            reason: "double-slash `//` not allowed".to_owned(),
        });
    }
    if trimmed.len() > 1 && trimmed.ends_with('/') {
        return Err(ValueError::InvalidPath {
            raw: raw.to_owned(),
            reason: "trailing `/` not allowed".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

fn parse_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_hash(raw: &str) -> Result<BTreeMap<String, String>, ValueError> {
    let mut out = BTreeMap::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| ValueError::InvalidHashEntry { raw: entry.to_owned() })?;
        out.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_accepts_canonical_spellings() {
        for (raw, expected) in [
            ("y", true),
            ("n", false),
            ("yes", true),
            ("no", false),
            ("true", true),
            ("false", false),
            ("on", true),
            ("off", false),
            ("1", true),
            ("0", false),
            ("Y", true),
            ("YES", true),
            ("True", true),
        ] {
            assert_eq!(parse_value(OptionType::Boolean, raw).unwrap(), OptionValue::Boolean(expected));
        }
    }

    #[test]
    fn boolean_rejects_garbage() {
        assert!(parse_value(OptionType::Boolean, "maybe").is_err());
        assert!(parse_value(OptionType::Boolean, "").is_err());
    }

    #[test]
    fn integer_round_trips() {
        assert_eq!(parse_value(OptionType::Integer, "42").unwrap(), OptionValue::Integer(42));
        assert_eq!(parse_value(OptionType::Integer, "-7").unwrap(), OptionValue::Integer(-7));
        assert!(parse_value(OptionType::Integer, "1.5").is_err());
        assert!(parse_value(OptionType::Integer, "x").is_err());
    }

    #[test]
    fn size_with_each_suffix() {
        let cases = [
            ("0", 0_u64),
            ("0B", 0),
            ("1024", 1024),
            ("1KiB", 1024),
            ("1KB", 1024),
            ("1k", 1024),
            ("2MiB", 2 * 1024 * 1024),
            ("3GiB", 3 * 1024_u64.pow(3)),
            ("4TiB", 4 * 1024_u64.pow(4)),
            ("5PiB", 5 * 1024_u64.pow(5)),
            ("16Mb", 16 * 1024 * 1024),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                parse_value(OptionType::Size, raw).unwrap(),
                OptionValue::Size(expected),
                "{raw}"
            );
        }
    }

    #[test]
    fn size_rejects_fraction_and_unknown_suffix() {
        assert!(parse_value(OptionType::Size, "1.5MiB").is_err());
        assert!(parse_value(OptionType::Size, "1XB").is_err());
        assert!(parse_value(OptionType::Size, "").is_err());
    }

    #[test]
    fn size_overflow_reports_typed_error() {
        let huge = format!("{}KB", u64::MAX);
        assert!(matches!(
            parse_value(OptionType::Size, &huge),
            Err(ValueError::SizeOverflow { .. })
        ));
    }

    #[test]
    fn time_accepts_seconds_only() {
        assert_eq!(parse_value(OptionType::Time, "60").unwrap(), OptionValue::Time(60));
        assert!(parse_value(OptionType::Time, "60s").is_err());
    }

    #[test]
    fn path_must_begin_with_slash_no_double_no_trailing() {
        assert_eq!(
            parse_value(OptionType::Path, "/var/lib/pgbackrest").unwrap(),
            OptionValue::Path("/var/lib/pgbackrest".to_owned())
        );
        assert_eq!(parse_value(OptionType::Path, "/").unwrap(), OptionValue::Path("/".to_owned()));
        assert!(matches!(
            parse_value(OptionType::Path, ""),
            Err(ValueError::InvalidPath { .. })
        ));
        assert!(matches!(
            parse_value(OptionType::Path, "var/lib"),
            Err(ValueError::InvalidPath { .. })
        ));
        assert!(matches!(
            parse_value(OptionType::Path, "/var//lib"),
            Err(ValueError::InvalidPath { .. })
        ));
        assert!(matches!(
            parse_value(OptionType::Path, "/var/"),
            Err(ValueError::InvalidPath { .. })
        ));
    }

    #[test]
    fn list_splits_on_comma_and_trims() {
        assert_eq!(
            parse_value(OptionType::List, "a, b ,c").unwrap(),
            OptionValue::List(vec!["a".into(), "b".into(), "c".into()])
        );
        assert_eq!(parse_value(OptionType::List, "").unwrap(), OptionValue::List(vec![]));
    }

    #[test]
    fn hash_parses_key_equal_value() {
        let v = parse_value(OptionType::Hash, "ts_01=/db/ts_01, ts_02=/db/ts_02").unwrap();
        let OptionValue::Hash(map) = v else { panic!() };
        assert_eq!(map["ts_01"], "/db/ts_01");
        assert_eq!(map["ts_02"], "/db/ts_02");
    }

    #[test]
    fn hash_rejects_entry_without_equals() {
        assert!(matches!(
            parse_value(OptionType::Hash, "lonely"),
            Err(ValueError::InvalidHashEntry { .. })
        ));
    }

    #[test]
    fn string_and_string_id_are_passthrough() {
        assert_eq!(
            parse_value(OptionType::String, "hi").unwrap(),
            OptionValue::String("hi".into())
        );
        assert_eq!(
            parse_value(OptionType::StringId, "full").unwrap(),
            OptionValue::StringId("full".into())
        );
    }
}
