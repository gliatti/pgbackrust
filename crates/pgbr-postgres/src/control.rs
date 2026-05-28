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
//!
//! Beyond the header, pgBackRest consumes a handful of further
//! `pg_control` fields — the checkpoint LSN, the cluster [`DBState`], the
//! page size (`BLCKSZ`) and the WAL segment size (`wal_segment_size`).
//! These live at version-dependent offsets inside `ControlFileData`.
//! [`decode_pg_control_data`] / [`read_pg_control_data`] decode the
//! header and then, for the versions whose on-disk layout is known,
//! read those extra fields from their documented byte offsets into a
//! [`PgControlData`]. Versions whose layout isn't implemented return the
//! header with `None` for the extra fields rather than erroring.

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

/// Cluster status indicator stored in `pg_control` (`DBState`).
///
/// Mirrors the upstream `DBState` enum from `src/include/catalog/
/// pg_control.h`, vendored in the C tree at
/// `src/postgres/interface/version.vendor.h` (the enum is version-stable:
/// changing it requires a `pg_control_version` bump). The numeric
/// discriminants match the on-disk values written by `PostgreSQL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbState {
    /// `DB_STARTUP` (0) — the cluster is starting up.
    Startup,
    /// `DB_SHUTDOWNED` (1) — cleanly shut down.
    Shutdowned,
    /// `DB_SHUTDOWNED_IN_RECOVERY` (2) — shut down while in recovery.
    ShutdownedInRecovery,
    /// `DB_SHUTDOWNING` (3) — in the process of shutting down.
    Shutdowning,
    /// `DB_IN_CRASH_RECOVERY` (4) — performing crash recovery.
    InCrashRecovery,
    /// `DB_IN_ARCHIVE_RECOVERY` (5) — performing archive recovery.
    InArchiveRecovery,
    /// `DB_IN_PRODUCTION` (6) — up and serving normally.
    InProduction,
}

impl DbState {
    /// Map the on-disk `u32` discriminant to a [`DbState`].
    ///
    /// Returns `None` for values outside the known 0..=6 range.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Startup),
            1 => Some(Self::Shutdowned),
            2 => Some(Self::ShutdownedInRecovery),
            3 => Some(Self::Shutdowning),
            4 => Some(Self::InCrashRecovery),
            5 => Some(Self::InArchiveRecovery),
            6 => Some(Self::InProduction),
            _ => None,
        }
    }
}

/// Byte offsets of the version-specific `pg_control` fields pgBackRest
/// reads for one `ControlFileData` layout.
///
/// `state` and `checkPoint` live ahead of the embedded variable-size
/// `CheckPoint` copy and so are identical across every supported version;
/// `block_size` (`blcksz`) and `wal_segment_size` (`xlog_seg_size`) sit
/// after it and shift when the layout in between changes size.
#[derive(Debug, Clone, Copy)]
struct ControlOffsets {
    /// `DBState state` — `u32` (the C `DBState` enum is `int`-sized).
    state: usize,
    /// `XLogRecPtr checkPoint` — `u64` little-endian.
    check_point: usize,
    /// `uint32 blcksz` — page size (`BLCKSZ`).
    block_size: usize,
    /// `uint32 xlog_seg_size` — WAL segment size.
    wal_segment_size: usize,
}

impl ControlOffsets {
    /// One past the highest field these offsets reach, i.e. the minimum
    /// buffer length needed to populate every field (`xlog_seg_size`
    /// end = `wal_segment_size` + 4). Used by tests to size synthetic
    /// fixtures.
    #[cfg(test)]
    const fn min_len(self) -> usize {
        self.wal_segment_size + 4
    }
}

/// `state` / `checkPoint` are at the same offsets for every supported
/// `ControlFileData` layout: the 16-byte version header is followed by
/// `DBState state` (offset 16), then `pg_time_t time` (8-byte aligned to
/// offset 24), then `XLogRecPtr checkPoint` (offset 32). All fields that
/// could move these — the variable-size `CheckPoint` copy and the
/// `prevCheckPoint` pointer present on older layouts — come *after*
/// `checkPoint`. Verified with `offsetof` for every `pg_control_version`
/// (see the per-layout constants below).
const STATE_OFFSET: usize = 16;
const CHECK_POINT_OFFSET: usize = 32;

/// Offsets for the "wide" `ControlFileData` layout, where `blcksz` lands
/// at 216 and `xlog_seg_size` at 228.
///
/// Shared by `pg_control_version` 960 (PG 9.6), 1002 (PG 10), 1201
/// (PG 12), 1300 (PG 13–16), 1700 (PG 17) and 1800 (PG 18). Although the
/// intervening fields differ across these releases — the embedded
/// `CheckPoint` copy is 80 bytes on 960/1002 vs 88 bytes on 1201+, and
/// 960/1002 carry an extra `prevCheckPoint` `XLogRecPtr` plus
/// `enableIntTimes`/`float4ByVal` bools that 1201+ drop — the net byte
/// count up to `blcksz` happens to coincide at 216 for all of them.
///
/// Taken from the `ControlFileData` struct in the C tree at
/// `src/postgres/interface/version.vendor.h` (the `>= PG_VERSION_18`,
/// `>= PG_VERSION_17`, `>= PG_VERSION_13`, `>= PG_VERSION_12`,
/// `>= PG_VERSION_10` and `>= PG_VERSION_96` branches), itself vendored
/// from upstream `src/include/catalog/pg_control.h`. Verified with
/// `offsetof` against the real vendored header compiled for the x86-64
/// `SysV` ABI (8-byte max alignment, little-endian) — the platform
/// pgBackRest targets — for each `PG_VERSION` in that set.
const OFFSETS_WIDE: ControlOffsets = ControlOffsets {
    state: STATE_OFFSET,
    check_point: CHECK_POINT_OFFSET,
    block_size: 216,
    wal_segment_size: 228,
};

/// Offsets for the `pg_control_version == 1100` (PG 11) layout, where
/// `blcksz` lands at 208 and `xlog_seg_size` at 220 — eight bytes earlier
/// than [`OFFSETS_WIDE`].
///
/// PG 11 keeps the 80-byte `CheckPoint` copy and the `prevCheckPoint`
/// `XLogRecPtr` of the 9.6/10 layout, but unlike those it has already
/// dropped the `enableIntTimes` bool. That single removed byte (and its
/// alignment padding) is what pulls `blcksz`/`xlog_seg_size` back by 8
/// relative to [`OFFSETS_WIDE`].
///
/// Taken from the `>= PG_VERSION_11` `ControlFileData` branch in
/// `src/postgres/interface/version.vendor.h`, verified with `offsetof`
/// against the real vendored header compiled for the x86-64 `SysV` ABI.
const OFFSETS_V1100: ControlOffsets = ControlOffsets {
    state: STATE_OFFSET,
    check_point: CHECK_POINT_OFFSET,
    block_size: 208,
    wal_segment_size: 220,
};

/// Resolve the [`ControlOffsets`] for a decoded `pg_control_version`, or
/// `None` if no layout is known for it.
const fn offsets_for(pg_control_version: u32) -> Option<ControlOffsets> {
    match pg_control_version {
        // Every supported version except PG 11 shares the wide layout.
        960 | 1002 | 1201 | 1300 | 1700 | 1800 => Some(OFFSETS_WIDE),
        // PG 11 alone shifts blcksz/xlog_seg_size back by 8 bytes.
        1100 => Some(OFFSETS_V1100),
        _ => None,
    }
}

/// Fuller `pg_control` data beyond the version header. Fields pgBackRest
/// consumes. Offsets are version-dependent; this slice supports the
/// versions enumerated in [`decode_pg_control_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgControlData {
    /// The version-stable header (`system_identifier`,
    /// `pg_control_version`, `catalog_version_no`).
    pub header: PgControlHeader,
    /// Checkpoint LSN (`XLogRecPtr`). `None` if this version's offset
    /// isn't known yet.
    pub checkpoint: Option<u64>,
    /// Cluster status (`DBState`). `None` if this version's offset isn't
    /// known yet, or if the raw value isn't a recognised state.
    pub state: Option<DbState>,
    /// Page size in bytes (`BLCKSZ`). `None` if this version's offset
    /// isn't known yet.
    pub block_size: Option<u32>,
    /// WAL segment size in bytes. `None` if this version's offset isn't
    /// known yet.
    pub wal_segment_size: Option<u32>,
}

/// Read a little-endian `u32` from `bytes` starting at `off`, or `None`
/// if the slice doesn't reach `off + 4`.
fn read_u32_at(bytes: &[u8], off: usize) -> Option<u32> {
    bytes.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a little-endian `u64` from `bytes` starting at `off`, or `None`
/// if the slice doesn't reach `off + 8`.
fn read_u64_at(bytes: &[u8], off: usize) -> Option<u64> {
    bytes
        .get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Decode a fuller [`PgControlData`] from the raw `pg_control` bytes.
///
/// Requires at least the version header. Version-specific fields are
/// populated only for the PG versions whose layout is implemented;
/// unknown-layout versions get `None` for those fields (the header is
/// still returned — an unimplemented layout is not an error).
///
/// Implements the layout for every `pg_control_version` in
/// [`crate::version::SUPPORTED`]: 960 (PG 9.6), 1002 (PG 10), 1100
/// (PG 11), 1201 (PG 12), 1300 (PG 13–16), 1700 (PG 17) and 1800
/// (PG 18). All share `state`/`checkpoint` offsets; PG 11 alone shifts
/// `block_size`/`wal_segment_size` back by 8 bytes (see [`OFFSETS_V1100`]
/// vs [`OFFSETS_WIDE`]). If the buffer ends before a given field's offset
/// that field is left `None` even for an implemented version.
///
/// # Errors
///
/// Returns [`PgControlError`] for the same reasons as
/// [`decode_pg_control_header`] (too short, unknown version, catalog
/// mismatch).
pub fn decode_pg_control_data(bytes: &[u8]) -> Result<PgControlData, PgControlError> {
    let header = decode_pg_control_header(bytes)?;

    let mut data = PgControlData {
        header,
        checkpoint: None,
        state: None,
        block_size: None,
        wal_segment_size: None,
    };

    if let Some(o) = offsets_for(header.pg_control_version) {
        data.checkpoint = read_u64_at(bytes, o.check_point);
        data.state = read_u32_at(bytes, o.state).and_then(DbState::from_raw);
        data.block_size = read_u32_at(bytes, o.block_size);
        data.wal_segment_size = read_u32_at(bytes, o.wal_segment_size);
    }

    Ok(data)
}

/// Largest number of bytes [`read_pg_control_data`] pulls from a stream
/// before decoding. Comfortably covers every implemented layout's
/// highest field offset.
const READ_DATA_CAP: usize = 512;

/// Read a fuller [`PgControlData`] from an [`IoRead`] source.
///
/// Pulls up to [`READ_DATA_CAP`] bytes (stopping early at EOF), then
/// defers to [`decode_pg_control_data`]. Reads fewer bytes than the cap
/// when the source is shorter — a source carrying only the 16-byte
/// header still decodes successfully, with `None` for the extra fields.
///
/// # Errors
///
/// See variants of [`PgControlError`]. A source shorter than the 16-byte
/// header surfaces as [`PgControlError::TooShort`].
pub fn read_pg_control_data<R: IoRead>(read: &mut R) -> Result<PgControlData, PgControlError> {
    let mut buf = Vec::with_capacity(READ_DATA_CAP);
    let mut chunk = [0u8; READ_DATA_CAP];

    while buf.len() < READ_DATA_CAP {
        let want = READ_DATA_CAP - buf.len();
        let n = read.read(&mut chunk[..want])?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    decode_pg_control_data(&buf)
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

    /// Resolve the registry entry for a given label, panicking if absent.
    fn version(label: &str) -> &'static VersionInterface {
        crate::version::by_label(label).expect("label present in SUPPORTED")
    }

    /// Build a synthetic `pg_control` buffer for the cluster identified by
    /// `label`, writing the extra fields at the offsets
    /// [`decode_pg_control_data`] reads (resolved through
    /// [`offsets_for`]). This is a self-consistency fixture: the writer
    /// mirrors the reader's offsets, which proves internal consistency,
    /// not agreement with a real `PostgreSQL` `pg_control` (verified
    /// separately via `offsetof` — see the [`OFFSETS_WIDE`] /
    /// [`OFFSETS_V1100`] doc comments).
    fn synth_data(label: &str, state: u32, checkpoint: u64, block_size: u32, wal_seg: u32) -> Vec<u8> {
        let v = version(label);
        let o = offsets_for(v.pg_control_version).expect("label has an implemented layout");
        let mut buf = vec![0u8; o.min_len()];
        buf[0..8].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        buf[8..12].copy_from_slice(&v.pg_control_version.to_le_bytes());
        buf[12..16].copy_from_slice(&v.catalog_version_no.to_le_bytes());
        buf[o.state..o.state + 4].copy_from_slice(&state.to_le_bytes());
        buf[o.check_point..o.check_point + 8].copy_from_slice(&checkpoint.to_le_bytes());
        buf[o.block_size..o.block_size + 4].copy_from_slice(&block_size.to_le_bytes());
        buf[o.wal_segment_size..o.wal_segment_size + 4].copy_from_slice(&wal_seg.to_le_bytes());
        buf
    }

    /// Decode a synthetic buffer for `label` and assert the written fields
    /// round-trip. Drives the per-version self-consistency tests below.
    fn assert_self_consistent(label: &str) {
        let v = version(label);
        let buf = synth_data(label, 6 /* DB_IN_PRODUCTION */, 0x1_2345_6789, 8192, 16 * 1024 * 1024);
        let data = decode_pg_control_data(&buf).expect("supported layout decodes");

        assert_eq!(
            data.header.pg_control_version, v.pg_control_version,
            "{label} pg_control_version"
        );
        assert_eq!(data.checkpoint, Some(0x1_2345_6789), "{label} checkpoint");
        assert_eq!(data.state, Some(DbState::InProduction), "{label} state");
        assert_eq!(data.block_size, Some(8192), "{label} block_size");
        assert_eq!(data.wal_segment_size, Some(16 * 1024 * 1024), "{label} wal_segment_size");
    }

    #[test]
    fn decode_data_reads_fields_for_v960() {
        assert_self_consistent("9.6");
    }

    #[test]
    fn decode_data_reads_fields_for_v1002() {
        assert_self_consistent("10");
    }

    #[test]
    fn decode_data_reads_fields_for_v1100() {
        assert_self_consistent("11");
    }

    #[test]
    fn decode_data_reads_fields_for_v1201() {
        assert_self_consistent("12");
    }

    #[test]
    fn decode_data_reads_fields_for_v1300() {
        // pg_control_version 1300 covers PG 13–16; exercise the whole set.
        for label in ["13", "14", "15", "16"] {
            assert_self_consistent(label);
        }
    }

    #[test]
    fn decode_data_reads_fields_for_v1700() {
        assert_self_consistent("17");
    }

    #[test]
    fn decode_data_reads_fields_for_v1800() {
        assert_self_consistent("18");
    }

    #[test]
    fn every_supported_version_has_a_known_layout() {
        // Sanity guard: the offset dispatch must cover every registry
        // entry, so adding a PG major without offsets fails here.
        for v in SUPPORTED {
            assert!(
                offsets_for(v.pg_control_version).is_some(),
                "{} (pg_control_version {}) has no implemented layout",
                v.label,
                v.pg_control_version,
            );
        }
    }

    #[test]
    fn unknown_layout_yields_none_extras() {
        // Every `pg_control_version` in SUPPORTED now has offsets, so the
        // public `decode_pg_control_data` (which validates the
        // version/catalog pair against SUPPORTED) can never reach the
        // unknown-layout branch with a real buffer. The layout dispatch is
        // [`offsets_for`]; assert it returns None for a fabricated
        // `pg_control_version` outside the known set, which is exactly the
        // signal `decode_pg_control_data` uses to leave the extra fields
        // `None`.
        for fabricated in [0_u32, 1, 1301, 1801, 9999, u32::MAX] {
            assert!(
                offsets_for(fabricated).is_none(),
                "fabricated pg_control_version {fabricated} must have no implemented layout",
            );
        }

        // And confirm the gate's observable effect end-to-end: a valid
        // header whose buffer is too short to reach any offsets leaves the
        // extra fields None — the same outcome an unknown layout produces.
        let v = version("12");
        let header_only = synth_header(v, 0xabcd_ef01_2345_6789);
        let data = decode_pg_control_data(&header_only).expect("header-only decodes");
        assert_eq!(data.header.system_identifier, 0xabcd_ef01_2345_6789);
        assert_eq!(data.checkpoint, None);
        assert_eq!(data.state, None);
        assert_eq!(data.block_size, None);
        assert_eq!(data.wal_segment_size, None);
    }

    #[test]
    fn decode_data_too_short_errors() {
        let bytes = [0u8; 8];
        let err = decode_pg_control_data(&bytes).expect_err("too short must error");
        assert_eq!(err, PgControlError::TooShort { read: 8 });
    }

    #[test]
    fn decode_data_unknown_state_value_is_none() {
        // A v1300 buffer whose state byte holds a value outside 0..=6.
        let buf = synth_data("16", 42, 7, 8192, 8192);
        let data = decode_pg_control_data(&buf).expect("v1300 decodes");
        assert_eq!(data.state, None, "unrecognised DBState maps to None");
        // The other fields still decode normally.
        assert_eq!(data.block_size, Some(8192));
    }

    #[test]
    fn decode_data_v1300_truncated_after_header_leaves_extras_none() {
        // A v1300 header with nothing past byte 16: the extra-field reads
        // fall off the end of the slice and yield None without erroring.
        let v = version("16");
        let bytes = synth_header(v, 1);
        let data = decode_pg_control_data(&bytes).expect("header-only v1300 decodes");

        assert_eq!(data.header.pg_control_version, 1300);
        assert_eq!(data.checkpoint, None);
        assert_eq!(data.state, None);
        assert_eq!(data.block_size, None);
        assert_eq!(data.wal_segment_size, None);
    }

    #[test]
    fn decode_data_v1100_offsets_differ_from_wide() {
        // PG 11's blcksz/xlog_seg_size sit 8 bytes earlier than the wide
        // layout. Writing at the v1100 offsets and reading back proves the
        // dispatch picks the right (shifted) offsets for 1100.
        let buf = synth_data("11", 1 /* DB_SHUTDOWNED */, 0xfeed, 8192, 32 * 1024 * 1024);
        let data = decode_pg_control_data(&buf).expect("v1100 decodes");
        assert_eq!(data.header.pg_control_version, 1100);
        assert_eq!(data.state, Some(DbState::Shutdowned));
        assert_eq!(data.checkpoint, Some(0xfeed));
        assert_eq!(data.block_size, Some(8192));
        assert_eq!(data.wal_segment_size, Some(32 * 1024 * 1024));

        // The shifted offsets are genuinely different: reading a v1100
        // buffer with the wide offsets must NOT find block_size where
        // v1100 placed it (the wide block_size offset is 8 bytes past the
        // v1100 one and lands on zero-fill here).
        assert_eq!(OFFSETS_V1100.block_size + 8, OFFSETS_WIDE.block_size);
        assert_eq!(read_u32_at(&buf, OFFSETS_WIDE.block_size), Some(0));
    }

    #[test]
    fn read_data_through_io_read_decodes_full_buffer() {
        let buf = synth_data("16", 1 /* DB_SHUTDOWNED */, 0xff00, 8192, 64 * 1024 * 1024);
        let mut reader = MemRead::new(buf);
        let data = read_pg_control_data(&mut reader).expect("read_pg_control_data");

        assert_eq!(data.state, Some(DbState::Shutdowned));
        assert_eq!(data.checkpoint, Some(0xff00));
        assert_eq!(data.block_size, Some(8192));
        assert_eq!(data.wal_segment_size, Some(64 * 1024 * 1024));
    }

    #[test]
    fn read_data_header_only_stream_yields_none_extras() {
        let v = version("16");
        let bytes = synth_header(v, 9).to_vec();
        let mut reader = MemRead::new(bytes);
        let data = read_pg_control_data(&mut reader).expect("header-only stream decodes");

        assert_eq!(data.header.system_identifier, 9);
        assert_eq!(data.block_size, None);
    }

    #[test]
    fn read_data_short_stream_errors_too_short_via_decode() {
        // The streaming path reads what's available (8 bytes), then the
        // in-memory decode reports the typed TooShort.
        let mut reader = MemRead::new(vec![0u8; 8]);
        let err = read_pg_control_data(&mut reader).expect_err("short stream must error");
        assert_eq!(err, PgControlError::TooShort { read: 8 });
    }

    #[test]
    fn dbstate_from_raw_covers_all_variants() {
        assert_eq!(DbState::from_raw(0), Some(DbState::Startup));
        assert_eq!(DbState::from_raw(1), Some(DbState::Shutdowned));
        assert_eq!(DbState::from_raw(2), Some(DbState::ShutdownedInRecovery));
        assert_eq!(DbState::from_raw(3), Some(DbState::Shutdowning));
        assert_eq!(DbState::from_raw(4), Some(DbState::InCrashRecovery));
        assert_eq!(DbState::from_raw(5), Some(DbState::InArchiveRecovery));
        assert_eq!(DbState::from_raw(6), Some(DbState::InProduction));
        assert_eq!(DbState::from_raw(7), None);
        assert_eq!(DbState::from_raw(u32::MAX), None);
    }
}
