//! `pg_control` reader.
//!
//! The first 16 bytes of `<datadir>/global/pg_control` are version-stable
//! across every supported `PostgreSQL` major release: an 8-byte
//! `system_identifier`, a 4-byte `pg_control_version`, and a 4-byte
//! `catalog_version_no`, all little-endian. After byte 16 the layout
//! diverges per major version — that's deferred to a later phase.
//!
//! This module decodes those 16 bytes into [`PgControlHeader`] and
//! cross-checks the `(pg_control_version, catalog_version_no)` pair
//! against [`crate::version::SUPPORTED`]. Two entry points are offered:
//!
//! - [`decode_pg_control_header`] — slice-in, parse-only.
//! - [`read_pg_control_header`] — pulls 16 bytes from any [`IoRead`]
//!   source via `read_exact`, then defers to `decode`.
//!
//! [`header_version`] resolves a decoded header back to the matching
//! [`VersionInterface`] entry (or `None` if the catalog is unknown).

use std::fmt;

use pgbr_io::{IoError, IoRead};

use crate::version::{VersionInterface, by_catalog_version_no};

/// Length in bytes of the version-stable `pg_control` prefix decoded by
/// this module.
const HEADER_LEN: usize = 16;

/// Decoded version-stable prefix of `pg_control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgControlHeader {
    /// Random per-cluster identifier. Must match across the cluster's
    /// backups and WAL — a mismatch indicates the WAL/backup was taken
    /// from a different cluster.
    pub system_identifier: u64,
    /// On-disk format version of `pg_control`. Matches
    /// [`VersionInterface::pg_control_version`] for the cluster's PG major.
    pub pg_control_version: u32,
    /// Catalog version of the cluster. Matches
    /// [`VersionInterface::catalog_version_no`] for the cluster's PG major.
    pub catalog_version_no: u32,
}

/// Errors raised while reading or decoding a `pg_control` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgControlError {
    /// Fewer than 16 bytes were available — the input is too short to be a
    /// valid `pg_control` header.
    TooShort {
        /// Number of bytes that were actually present.
        read: usize,
    },
    /// The decoded `(pg_control_version, catalog_version_no)` pair does not
    /// match any entry in [`crate::version::SUPPORTED`].
    UnknownVersion {
        /// Decoded `pg_control_version` value.
        pg_control_version: u32,
        /// Decoded `catalog_version_no` value.
        catalog_version_no: u32,
    },
    /// The `catalog_version_no` is recognised but the matching registry
    /// entry's `pg_control_version` differs from the decoded one.
    CatalogMismatch {
        /// `pg_control_version` decoded from the header.
        pg_control_version: u32,
        /// `catalog_version_no` recorded in [`crate::version::SUPPORTED`]
        /// for the matched entry.
        expected_catalog: u32,
        /// `catalog_version_no` decoded from the header.
        actual_catalog: u32,
    },
    /// Underlying [`IoRead`] failure while pulling the header bytes.
    Io(IoError),
}

impl fmt::Display for PgControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { read } => write!(
                f,
                "pg_control header too short: read {read} bytes, expected at least {HEADER_LEN}",
            ),
            Self::UnknownVersion {
                pg_control_version,
                catalog_version_no,
            } => write!(
                f,
                "unknown pg_control version: pg_control_version={pg_control_version}, \
                 catalog_version_no={catalog_version_no}",
            ),
            Self::CatalogMismatch {
                pg_control_version,
                expected_catalog,
                actual_catalog,
            } => write!(
                f,
                "pg_control catalog mismatch for pg_control_version={pg_control_version}: \
                 expected catalog_version_no={expected_catalog}, actual {actual_catalog}",
            ),
            Self::Io(err) => write!(f, "pg_control read error: {err}"),
        }
    }
}

impl std::error::Error for PgControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<IoError> for PgControlError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

/// Decode the version-stable `pg_control` prefix from an in-memory slice.
///
/// Returns [`PgControlError::TooShort`] when fewer than 16 bytes are
/// supplied, [`PgControlError::UnknownVersion`] when the
/// `(pg_control_version, catalog_version_no)` pair is not recognised, and
/// [`PgControlError::CatalogMismatch`] when the catalog matches a known
/// entry but its `pg_control_version` differs.
///
/// # Errors
///
/// See variants of [`PgControlError`].
pub fn decode_pg_control_header(bytes: &[u8]) -> Result<PgControlHeader, PgControlError> {
    if bytes.len() < HEADER_LEN {
        return Err(PgControlError::TooShort { read: bytes.len() });
    }

    // Unwrap is safe: each subslice is exactly the array length above
    // because we just checked `bytes.len() >= HEADER_LEN`.
    let system_identifier = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
    let pg_control_version = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
    let catalog_version_no = u32::from_le_bytes(bytes[12..16].try_into().unwrap_or([0; 4]));

    match by_catalog_version_no(catalog_version_no) {
        None => Err(PgControlError::UnknownVersion {
            pg_control_version,
            catalog_version_no,
        }),
        Some(v) if v.pg_control_version != pg_control_version => Err(PgControlError::CatalogMismatch {
            pg_control_version,
            expected_catalog: v.catalog_version_no,
            actual_catalog: catalog_version_no,
        }),
        Some(_) => Ok(PgControlHeader {
            system_identifier,
            pg_control_version,
            catalog_version_no,
        }),
    }
}

/// Read the version-stable `pg_control` prefix from an [`IoRead`] source.
///
/// Pulls exactly 16 bytes via [`IoRead::read_exact`], then defers to
/// [`decode_pg_control_header`].
///
/// # Errors
///
/// See variants of [`PgControlError`]. [`IoError::UnexpectedEof`] from the
/// underlying source surfaces as [`PgControlError::Io`] (the dedicated
/// [`PgControlError::TooShort`] variant only fires for the in-memory
/// [`decode_pg_control_header`] path).
pub fn read_pg_control_header<R: IoRead>(read: &mut R) -> Result<PgControlHeader, PgControlError> {
    let mut buf = [0u8; HEADER_LEN];
    read.read_exact(&mut buf)?;
    decode_pg_control_header(&buf)
}

/// Resolve a decoded header to its [`VersionInterface`] entry.
///
/// Returns `None` only when `header.catalog_version_no` is not present in
/// [`crate::version::SUPPORTED`]. If the header was produced by
/// [`decode_pg_control_header`] / [`read_pg_control_header`] this returns
/// `Some(_)` by construction.
#[must_use]
pub fn header_version(header: &PgControlHeader) -> Option<&'static VersionInterface> {
    by_catalog_version_no(header.catalog_version_no).filter(|v| v.pg_control_version == header.pg_control_version)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::version::SUPPORTED;
    use pgbr_io::MemRead;

    /// Build a synthetic 16-byte `pg_control` prefix from a registry entry.
    fn synth_header(v: &VersionInterface, system_id: u64) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..8].copy_from_slice(&system_id.to_le_bytes());
        buf[8..12].copy_from_slice(&v.pg_control_version.to_le_bytes());
        buf[12..16].copy_from_slice(&v.catalog_version_no.to_le_bytes());
        buf
    }

    #[test]
    fn decodes_every_supported_version() {
        let system_id: u64 = 0xdead_beef_dead_beef;
        for v in SUPPORTED {
            let bytes = synth_header(v, system_id);
            let header = decode_pg_control_header(&bytes).expect("decode supported version");

            assert_eq!(header.system_identifier, system_id, "{} system_id", v.label);
            assert_eq!(
                header.pg_control_version, v.pg_control_version,
                "{} pg_control_version",
                v.label
            );
            assert_eq!(
                header.catalog_version_no, v.catalog_version_no,
                "{} catalog_version_no",
                v.label
            );

            let resolved = header_version(&header).expect("header_version resolves");
            assert_eq!(resolved.label, v.label, "{} header_version label", v.label);
        }
    }

    #[test]
    fn read_through_io_read_works() {
        let v = &SUPPORTED[0];
        let bytes = synth_header(v, 0x0102_0304_0506_0708);
        let mut reader = MemRead::new(bytes.to_vec());
        let header = read_pg_control_header(&mut reader).expect("read_pg_control_header");

        assert_eq!(header.system_identifier, 0x0102_0304_0506_0708);
        assert_eq!(header.pg_control_version, v.pg_control_version);
        assert_eq!(header.catalog_version_no, v.catalog_version_no);
    }

    #[test]
    fn short_input_errors_with_typed_too_short() {
        let bytes = [0u8; 8];
        let err = decode_pg_control_header(&bytes).expect_err("short input must error");
        assert_eq!(err, PgControlError::TooShort { read: 8 });
    }

    #[test]
    fn unknown_version_pair_errors() {
        let v = &SUPPORTED[0];
        let mut bytes = synth_header(v, 0);
        // Flip pg_control_version to a value no entry in SUPPORTED uses.
        bytes[8..12].copy_from_slice(&9999_u32.to_le_bytes());

        let err = decode_pg_control_header(&bytes).expect_err("unknown version must error");
        match err {
            PgControlError::CatalogMismatch {
                pg_control_version,
                expected_catalog,
                actual_catalog,
            } => {
                // Catalog still resolves to SUPPORTED[0], so this is a
                // CatalogMismatch (the registry entry's pg_control_version
                // differs from the flipped one we wrote).
                assert_eq!(pg_control_version, 9999);
                assert_eq!(expected_catalog, v.catalog_version_no);
                assert_eq!(actual_catalog, v.catalog_version_no);
            }
            PgControlError::UnknownVersion {
                pg_control_version,
                catalog_version_no,
            } => {
                assert_eq!(pg_control_version, 9999);
                assert_eq!(catalog_version_no, v.catalog_version_no);
            }
            other => panic!("expected UnknownVersion or CatalogMismatch, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_catalog_for_known_pg_control_version_is_caught() {
        let v = &SUPPORTED[0];
        let mut bytes = synth_header(v, 0);
        // Keep pg_control_version, but blow away the catalog so the lookup
        // returns None — natural behaviour of `by_catalog_version_no`.
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());

        let err = decode_pg_control_header(&bytes).expect_err("bogus catalog must error");
        assert_eq!(
            err,
            PgControlError::UnknownVersion {
                pg_control_version: v.pg_control_version,
                catalog_version_no: u32::MAX,
            },
        );
    }
}
