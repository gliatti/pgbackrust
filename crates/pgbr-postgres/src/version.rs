//! Per-version `PostgreSQL` interface metadata.
//!
//! Each supported major version has a constant set of values that the
//! pgBackRest control-file reader needs to recognise:
//!
//! - `catalog_version_no`: matched against the cluster's `pg_control` to
//!   confirm the version detection (taken from `src/include/catalog/
//!   catversion.h` of the corresponding PG release, mirrored in the C
//!   tree at `src/postgres/interface/version.vendor.h`).
//! - `pg_control_version`: the on-disk format version of `pg_control`
//!   (taken from `src/include/catalog/pg_control.h`, mirrored in the
//!   same vendor header).
//! - `wal_block_size`: in bytes (always 8192 on PG >= 9.6 unless built
//!   with non-default `--with-wal-blocksize`).
//! - `block_size`: page size in bytes (always 8192 with default build).
//!
//! The full per-version on-disk struct layouts (`ControlFileData`,
//! `PageHeaderData`, tablespace map) are intentionally not modelled here yet
//! — that work is queued for a later phase. This module provides the
//! identifying header values so version detection has a Rust home.

/// One supported `PostgreSQL` major version's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInterface {
    /// Major version label as it appears in `postgres.yaml` (`"9.6"`, `"10"`,
    /// ..., `"18"`). Stable identifier used in error messages.
    pub label: &'static str,
    /// `CATALOG_VERSION_NO` from the upstream `PostgreSQL` release.
    pub catalog_version_no: u32,
    /// `PG_CONTROL_VERSION` from the upstream release.
    pub pg_control_version: u32,
    /// Default `XLOG_BLCKSZ` (WAL segment block size). Always 8192.
    pub wal_block_size: u32,
    /// Default `BLCKSZ` (page size). Always 8192.
    pub block_size: u32,
}

/// Every supported `PostgreSQL` major version, in input order.
///
/// Catalog and control-version values are mirrored byte-for-byte from
/// `src/postgres/interface/version.vendor.h`, which itself vendors the
/// upstream `catversion.h` / `pg_control.h` defines.
pub const SUPPORTED: &[VersionInterface] = &[
    VersionInterface {
        label: "9.6",
        catalog_version_no: 201_608_131,
        pg_control_version: 960,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "10",
        catalog_version_no: 201_707_211,
        pg_control_version: 1002,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "11",
        catalog_version_no: 201_809_051,
        pg_control_version: 1100,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "12",
        catalog_version_no: 201_909_212,
        pg_control_version: 1201,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "13",
        catalog_version_no: 202_007_201,
        pg_control_version: 1300,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "14",
        catalog_version_no: 202_107_181,
        pg_control_version: 1300,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "15",
        catalog_version_no: 202_209_061,
        pg_control_version: 1300,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "16",
        catalog_version_no: 202_307_071,
        pg_control_version: 1300,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "17",
        catalog_version_no: 202_406_281,
        pg_control_version: 1700,
        wal_block_size: 8192,
        block_size: 8192,
    },
    VersionInterface {
        label: "18",
        catalog_version_no: 202_506_291,
        pg_control_version: 1800,
        wal_block_size: 8192,
        block_size: 8192,
    },
];

/// Look up a [`VersionInterface`] by its label.
#[must_use]
pub fn by_label(label: &str) -> Option<&'static VersionInterface> {
    SUPPORTED.iter().find(|v| v.label == label)
}

/// Look up a [`VersionInterface`] by its on-disk catalog version.
#[must_use]
pub fn by_catalog_version_no(catalog_version_no: u32) -> Option<&'static VersionInterface> {
    SUPPORTED.iter().find(|v| v.catalog_version_no == catalog_version_no)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Source of truth: every label declared by the C build's
    /// `src/build/postgres/postgres.yaml` must have a matching entry here.
    /// This is the keystone test that prevents the registry from drifting
    /// when the YAML adds a new PG major.
    #[test]
    fn every_postgres_yaml_version_has_an_interface() {
        // crates/pgbr-postgres/src -> ../../src/build/postgres/postgres.yaml
        let yaml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("src")
            .join("build")
            .join("postgres")
            .join("postgres.yaml");
        let yaml = std::fs::read_to_string(&yaml_path).unwrap_or_else(|e| panic!("read {}: {}", yaml_path.display(), e));
        let parsed = pgbr_build::parse_postgres(&yaml).unwrap_or_else(|e| panic!("parse postgres.yaml: {e}"));

        assert!(!parsed.versions.is_empty(), "postgres.yaml had no versions");
        for label in &parsed.versions {
            assert!(
                by_label(label).is_some(),
                "postgres.yaml lists `{label}` but pgbr_postgres::version::SUPPORTED has no entry — \
                 add it to SUPPORTED with values from src/postgres/interface/version.vendor.h",
            );
        }
    }

    #[test]
    fn labels_are_unique() {
        let labels: HashSet<&'static str> = SUPPORTED.iter().map(|v| v.label).collect();
        assert_eq!(labels.len(), SUPPORTED.len());
    }

    #[test]
    fn catalog_version_lookup_works() {
        // PG 16's catalog version per version.vendor.h.
        let entry = by_catalog_version_no(202_307_071).expect("PG 16 entry by catalog version");
        assert_eq!(entry.label, "16");
        assert_eq!(entry.pg_control_version, 1300);
    }

    #[test]
    fn unknown_label_returns_none() {
        assert!(by_label("999").is_none());
    }

    #[test]
    fn block_sizes_are_canonical() {
        for entry in SUPPORTED {
            assert_eq!(entry.block_size, 8192, "{} block_size", entry.label);
            assert_eq!(entry.wal_block_size, 8192, "{} wal_block_size", entry.label);
        }
    }
}
