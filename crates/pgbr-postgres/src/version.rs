//! Per-version `PostgreSQL` interface metadata.
//!
//! Each supported major version has a constant set of values that the
//! pgBackRust control-file reader needs to recognise:
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

/// Map a `pg_control_version` to the matching `PostgreSQL` major-version
/// label (`"9.6"`, `"10"`, …, `"18"`).
///
/// `pg_control_version` is **not** a unique key for a PG major: a single
/// on-disk control format spans several releases when the catalog evolves
/// without changing `ControlFileData` — most notably `1300`, which covers
/// PG 13, 14, 15 and 16. This returns the label of the *first* matching
/// [`SUPPORTED`] entry (lowest major), which is fine for the
/// human-readable / layout-selection uses that key off the control format
/// alone. To pin a decoded `pg_control` to one exact major, match on the
/// `catalog_version_no` instead (see [`by_catalog_version_no`] and
/// [`crate::control::identify`]).
///
/// Provenance: the per-version `PG_CONTROL_VERSION` defines live in the
/// vendored `src/postgres/interface/version.vendor.h` (mirroring upstream
/// `src/include/catalog/pg_control.h`); the C side resolves a version to
/// its control number via `pgControlVersion()` in
/// `src/postgres/interface.c`.
#[must_use]
pub fn pg_control_version_to_pg_version(pg_control_version: u32) -> Option<&'static str> {
    SUPPORTED
        .iter()
        .find(|v| v.pg_control_version == pg_control_version)
        .map(|v| v.label)
}

/// Map a `PostgreSQL` major-version label (`"9.6"`, `"10"`, …, `"18"`) to
/// its `pg_control_version`.
///
/// Inverse of [`pg_control_version_to_pg_version`] (modulo that function's
/// many-to-one collapse: distinct labels such as `"13"`..`"16"` all map
/// back to the same `1300`). Returns `None` for an unrecognised label.
///
/// Provenance: same as [`pg_control_version_to_pg_version`] — mirrors the C
/// `pgControlVersion()` in `src/postgres/interface.c`.
#[must_use]
pub fn pg_version_to_pg_control_version(label: &str) -> Option<u32> {
    by_label(label).map(|v| v.pg_control_version)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Source of truth: every label declared by `postgres.yaml` (embedded via
    /// `pgbr_build::inputs`) must have a matching entry here. This is the
    /// keystone test that prevents the registry from drifting when the YAML
    /// adds a new PG major.
    #[test]
    fn every_postgres_yaml_version_has_an_interface() {
        let parsed =
            pgbr_build::parse_postgres(pgbr_build::inputs::POSTGRES_YAML).unwrap_or_else(|e| panic!("parse postgres.yaml: {e}"));

        assert!(!parsed.versions.is_empty(), "postgres.yaml had no versions");
        for label in &parsed.versions {
            assert!(
                by_label(label).is_some(),
                "postgres.yaml lists `{label}` but pgbr_postgres::version::SUPPORTED has no entry — \
                 add it to SUPPORTED with the upstream catversion/pg_control values",
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

    #[test]
    fn pg_version_round_trips_through_control_version() {
        // For every supported label, label -> control_version ->
        // *some* label that itself maps back to the same control_version.
        for entry in SUPPORTED {
            let ctrl = pg_version_to_pg_control_version(entry.label).expect("label maps to a control version");
            assert_eq!(ctrl, entry.pg_control_version, "{} control version", entry.label);

            let label = pg_control_version_to_pg_version(ctrl).expect("control version maps to a label");
            // The reverse may collapse to the lowest-major label sharing
            // this control version (e.g. 1300 -> "13"), so re-resolve and
            // compare the control versions rather than the labels.
            assert_eq!(
                pg_version_to_pg_control_version(label),
                Some(ctrl),
                "{} reverse-mapped label shares the control version",
                entry.label,
            );
        }
    }

    #[test]
    fn shared_control_version_resolves_to_lowest_major() {
        // 1300 spans PG 13–16; the lookup returns the first (lowest) major.
        assert_eq!(pg_control_version_to_pg_version(1300), Some("13"));
        // Single-major control versions resolve unambiguously.
        assert_eq!(pg_control_version_to_pg_version(960), Some("9.6"));
        assert_eq!(pg_control_version_to_pg_version(1002), Some("10"));
        assert_eq!(pg_control_version_to_pg_version(1100), Some("11"));
        assert_eq!(pg_control_version_to_pg_version(1201), Some("12"));
        assert_eq!(pg_control_version_to_pg_version(1700), Some("17"));
        assert_eq!(pg_control_version_to_pg_version(1800), Some("18"));
    }

    #[test]
    fn unknown_control_version_and_label_return_none() {
        assert_eq!(pg_control_version_to_pg_version(0), None);
        assert_eq!(pg_control_version_to_pg_version(9999), None);
        assert_eq!(pg_version_to_pg_control_version("8.4"), None);
        assert_eq!(pg_version_to_pg_control_version(""), None);
    }
}
