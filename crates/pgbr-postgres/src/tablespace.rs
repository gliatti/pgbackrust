//! Tablespace directory-name parsing.
//!
//! A `PostgreSQL` tablespace lives outside the data directory; the cluster
//! references it through a symlink at `pg_data/pg_tblspc/<oid>` whose target
//! is the tablespace's external location. Inside that location, the cluster
//! creates a version-stamped subdirectory so that several clusters of
//! different major versions can share one tablespace path without
//! colliding. The subdirectory is named:
//!
//! ```text
//! PG_<major-version>_<catalog-version>
//! ```
//!
//! e.g. `PG_16_202307071` for PG 16, or `PG_9.6_201608131` for PG 9.6.
//!
//! Provenance: the C tree builds this name in
//! `src/postgres/interface.c`'s `pgTablespaceId()`:
//!
//! ```c
//! result = strNewFmt("PG_%s_%u", strZ(pgVersionStr), pgCatalogVersion);
//! ```
//!
//! where `pgVersionStr` is the major-version label produced by
//! `pgVersionToStr()` — `"%u"` (`version / 10000`) for PG 10+ and
//! `"%u.%u"` (`major.minor`) for PG 9.x. These are exactly the labels in
//! [`crate::version::SUPPORTED`]. This module provides the inverse: parse
//! such a directory name back into its components.

use crate::version::{VersionInterface, by_catalog_version_no};

/// The prefix every tablespace version directory carries (`PG_`).
///
/// Matches the literal `"PG_"` in C's `strNewFmt("PG_%s_%u", …)`.
const TABLESPACE_PREFIX: &str = "PG_";

/// Components decoded from a `PG_<version>_<catalog>` tablespace directory
/// name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TablespaceDirName {
    /// The `PostgreSQL` major-version label as it appears in the directory
    /// name and in [`crate::version::SUPPORTED`] (`"9.6"`, `"10"`, …,
    /// `"18"`). Borrowed from the input slice.
    pub pg_version_label: String,
    /// The `catalog_version_no` embedded in the directory name. This is the
    /// authoritative key for pinning the directory to a single PG major (a
    /// shared `pg_control_version` such as 1300 spans several majors, but
    /// the catalog version is unique per major).
    pub catalog_version: u32,
}

/// Parse a `PG_<version>_<catalog>` tablespace directory name into its
/// components.
///
/// Splits on `_`. A valid name has exactly three `_`-separated fields:
/// the literal `PG`, the major-version label, and a decimal
/// `catalog_version_no`. The version label itself never contains `_`
/// (it is `"9.6"`, `"10"`, …, `"18"`), so a three-field split is exact.
///
/// Returns `None` when the name is not a tablespace version directory:
/// missing/extra fields, a wrong prefix, an empty version label, or a
/// catalog field that is not a `u32`. This is a *structural* parse — it
/// does not require the (version, catalog) pair to be a recognised
/// `PostgreSQL` release; use [`identify_tablespace_dir_name`] for that.
///
/// # Examples
///
/// ```
/// use pgbr_postgres::tablespace::parse_tablespace_dir_name;
///
/// let parsed = parse_tablespace_dir_name("PG_16_202307071").unwrap();
/// assert_eq!(parsed.pg_version_label, "16");
/// assert_eq!(parsed.catalog_version, 202_307_071);
///
/// let parsed = parse_tablespace_dir_name("PG_9.6_201608131").unwrap();
/// assert_eq!(parsed.pg_version_label, "9.6");
///
/// assert!(parse_tablespace_dir_name("PG_16").is_none());
/// assert!(parse_tablespace_dir_name("base").is_none());
/// ```
#[must_use]
pub fn parse_tablespace_dir_name(name: &str) -> Option<TablespaceDirName> {
    // Cheap up-front rejection: the name must start with `PG_`.
    if !name.starts_with(TABLESPACE_PREFIX) {
        return None;
    }

    // Exactly three `_`-separated fields: "PG", "<version>", "<catalog>".
    // Using a fixed split rather than `splitn`/`rsplit` because none of the
    // three legitimate fields contains an underscore (the version label is
    // `9.6` / `10` / … / `18`).
    let mut fields = name.split('_');
    let prefix = fields.next()?;
    let version = fields.next()?;
    let catalog = fields.next()?;
    // Any further field means the name is malformed (`PG_16_x_y`).
    if fields.next().is_some() {
        return None;
    }

    // `prefix` is "PG" (the trailing `_` of TABLESPACE_PREFIX was consumed
    // by the split), and the version label must be non-empty.
    if prefix != "PG" || version.is_empty() {
        return None;
    }

    let catalog_version: u32 = catalog.parse().ok()?;

    Some(TablespaceDirName {
        pg_version_label: version.to_owned(),
        catalog_version,
    })
}

/// Parse a tablespace directory name and resolve it to a known
/// [`VersionInterface`].
///
/// Like [`parse_tablespace_dir_name`], but additionally requires the
/// embedded `catalog_version` to match an entry in
/// [`crate::version::SUPPORTED`] **and** that entry's label to equal the
/// embedded version label. Returns the matched interface alongside the
/// parsed components, or `None` if either the structure is invalid or the
/// pair is not a recognised release.
///
/// The catalog version is the authoritative match key (it is unique per PG
/// major); cross-checking the label guards against a corrupt name whose
/// label and catalog disagree.
#[must_use]
pub fn identify_tablespace_dir_name(name: &str) -> Option<(&'static VersionInterface, TablespaceDirName)> {
    let parsed = parse_tablespace_dir_name(name)?;
    let version = by_catalog_version_no(parsed.catalog_version)?;
    if version.label == parsed.pg_version_label {
        Some((version, parsed))
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::version::SUPPORTED;

    #[test]
    fn parses_pg16_name() {
        let parsed = parse_tablespace_dir_name("PG_16_202307071").expect("valid PG 16 name");
        assert_eq!(parsed.pg_version_label, "16");
        assert_eq!(parsed.catalog_version, 202_307_071);
    }

    #[test]
    fn parses_pg96_name_with_dotted_label() {
        // PG 9.6's label carries a dot but no underscore, so the 3-field
        // split still lands cleanly: PG / 9.6 / 201608131.
        let parsed = parse_tablespace_dir_name("PG_9.6_201608131").expect("valid PG 9.6 name");
        assert_eq!(parsed.pg_version_label, "9.6");
        assert_eq!(parsed.catalog_version, 201_608_131);
    }

    #[test]
    fn parses_every_supported_version_synthetic_name() {
        // Build the C-format name for each registry entry and round-trip it.
        for v in SUPPORTED {
            let name = format!("PG_{}_{}", v.label, v.catalog_version_no);
            let parsed = parse_tablespace_dir_name(&name).unwrap_or_else(|| panic!("{name} should parse"));
            assert_eq!(parsed.pg_version_label, v.label, "{name} label");
            assert_eq!(parsed.catalog_version, v.catalog_version_no, "{name} catalog");
        }
    }

    #[test]
    fn rejects_too_few_fields() {
        assert!(parse_tablespace_dir_name("PG_16").is_none());
        assert!(parse_tablespace_dir_name("PG").is_none());
        assert!(parse_tablespace_dir_name("PG_").is_none());
    }

    #[test]
    fn rejects_too_many_fields() {
        assert!(parse_tablespace_dir_name("PG_16_202307071_extra").is_none());
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(parse_tablespace_dir_name("XG_16_202307071").is_none());
        assert!(parse_tablespace_dir_name("base").is_none());
        assert!(parse_tablespace_dir_name("pg_tblspc").is_none());
        // Lowercase prefix is not what PostgreSQL writes.
        assert!(parse_tablespace_dir_name("pg_16_202307071").is_none());
    }

    #[test]
    fn rejects_empty_version_label() {
        // "PG__202307071" splits to PG / "" / 202307071.
        assert!(parse_tablespace_dir_name("PG__202307071").is_none());
    }

    #[test]
    fn rejects_non_numeric_catalog() {
        assert!(parse_tablespace_dir_name("PG_16_notanumber").is_none());
        assert!(parse_tablespace_dir_name("PG_16_2023x7071").is_none());
        // A catalog that overflows u32.
        assert!(parse_tablespace_dir_name("PG_16_99999999999999").is_none());
    }

    #[test]
    fn rejects_empty_string() {
        assert!(parse_tablespace_dir_name("").is_none());
    }

    #[test]
    fn identify_resolves_known_release() {
        let (v, parsed) = identify_tablespace_dir_name("PG_16_202307071").expect("PG 16 identified");
        assert_eq!(v.label, "16");
        assert_eq!(v.pg_control_version, 1300);
        assert_eq!(parsed.catalog_version, 202_307_071);
    }

    #[test]
    fn identify_round_trips_every_supported_version() {
        for v in SUPPORTED {
            let name = format!("PG_{}_{}", v.label, v.catalog_version_no);
            let (resolved, _) = identify_tablespace_dir_name(&name).unwrap_or_else(|| panic!("{name} should identify"));
            assert_eq!(resolved.label, v.label, "{name} resolves to its own label");
            assert_eq!(resolved.catalog_version_no, v.catalog_version_no, "{name} catalog");
        }
    }

    #[test]
    fn identify_rejects_unknown_catalog() {
        // Structurally valid but catalog 1 matches no supported release.
        assert!(parse_tablespace_dir_name("PG_16_1").is_some());
        assert!(identify_tablespace_dir_name("PG_16_1").is_none());
    }

    #[test]
    fn identify_rejects_label_catalog_mismatch() {
        // PG 16's catalog version under a PG 15 label: parses, but the
        // label/catalog cross-check fails.
        assert!(parse_tablespace_dir_name("PG_15_202307071").is_some());
        assert!(identify_tablespace_dir_name("PG_15_202307071").is_none());
    }
}
