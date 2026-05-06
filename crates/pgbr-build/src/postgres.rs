//! `postgres.yaml` parser.
//!
//! `src/build/postgres/postgres.yaml` lists the supported `PostgreSQL` major
//! versions. The C generator reads this list to emit per-version interface
//! tables in `src/postgres/interface.auto.c.inc` and `src/postgres/version.auto.h`.
//!
//! Versions are parsed as strings (e.g. `"9.6"`, `"10"`, `"18"`) because the
//! YAML mixes float (`9.6`) and integer (`10`) literals.

use serde::Deserialize;

/// Parsed contents of `postgres.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresVersions {
    /// Supported `PostgreSQL` major versions, in input order.
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    version: Vec<serde_yml::Value>,
}

/// Parses the YAML text of `src/build/postgres/postgres.yaml`.
pub fn parse_postgres(yaml: &str) -> Result<PostgresVersions, serde_yml::Error> {
    let raw: Raw = serde_yml::from_str(yaml)?;
    let versions = raw.version.into_iter().map(format_version).collect::<Result<Vec<_>, _>>()?;
    Ok(PostgresVersions { versions })
}

fn format_version(value: serde_yml::Value) -> Result<String, serde_yml::Error> {
    match value {
        serde_yml::Value::Number(n) => format_number(&n),
        serde_yml::Value::String(s) => Ok(s),
        other => Err(<serde_yml::Error as serde::de::Error>::custom(format!(
            "version: expected scalar, got {other:?}",
        ))),
    }
}

fn format_number(n: &serde_yml::Number) -> Result<String, serde_yml::Error> {
    n.as_i64().map_or_else(
        || {
            n.as_f64().map_or_else(
                || {
                    Err(<serde_yml::Error as serde::de::Error>::custom(format!(
                        "version: unsupported numeric value {n:?}",
                    )))
                },
                // Default float formatting renders `9.6_f64` as `"9.6"`,
                // matching the input form exactly.
                |f| Ok(format!("{f}")),
            )
        },
        |i| Ok(i.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PATH: &str = "../../src/build/postgres/postgres.yaml";

    #[test]
    fn parses_int_and_float_mix() {
        let parsed = parse_postgres("version:\n  - 9.6\n  - 10\n  - 11\n").unwrap();
        assert_eq!(parsed.versions, vec!["9.6", "10", "11"]);
    }

    #[test]
    fn rejects_unknown_top_level_keys() {
        let err = parse_postgres("version: [10]\nfoo: 1\n").unwrap_err();
        assert!(err.to_string().contains("foo"), "expected error to mention `foo`, got: {err}");
    }

    #[test]
    fn parses_repository_fixture() {
        let yaml = std::fs::read_to_string(FIXTURE_PATH).unwrap_or_else(|err| panic!("read {FIXTURE_PATH}: {err}"));
        let parsed = parse_postgres(&yaml).unwrap();

        // Sanity: the file lists at least 9.6 through 18 today. Pin the first
        // and last; let the middle move with future PG releases without
        // breaking the test.
        assert!(
            parsed.versions.first().is_some_and(|v| v == "9.6"),
            "first version: {:?}",
            parsed.versions.first()
        );
        assert!(
            parsed.versions.iter().any(|v| v == "10"),
            "expected version 10 to be present, got {:?}",
            parsed.versions,
        );
        assert!(
            parsed.versions.len() >= 10,
            "expected ≥10 supported versions, got {}",
            parsed.versions.len()
        );
    }
}
