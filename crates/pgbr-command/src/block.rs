//! Block-incremental backup helpers (`repo-block=y`).
//!
//! C reference: `src/command/backup/backup.c` (`backupBlockIncrSize`,
//! `backupBlockIncr*`) and `src/info/manifest.c` (the per-file block map).
//!
//! Block-incremental backup splits a large file into fixed-size blocks so that a
//! later differential / incremental backup can store only the blocks that
//! changed, recording an unchanged block as a *reference* to the backup whose
//! bundle physically holds its bytes. A full backup taken with `repo-block=y`
//! writes a block map where every block references itself, giving later
//! diff/incr backups something to diff against.
//!
//! Two pure, unit-testable pieces live here:
//!
//! - [`block_size`] — the age + size → block-size policy. pgBackRust scales the
//!   block size up for bigger and older files (so the per-block bookkeeping stays
//!   proportional to the data), and disables the block map entirely for very old
//!   files (whose blocks are unlikely to ever change again, so a map would be
//!   pure overhead). Returns `None` when no block map should be written.
//! - [`split_blocks`] / [`reassemble`] — split a file's plaintext into blocks and
//!   the inverse, used by the round-trip tests and by the backup / restore paths.
//!
//! # Explicit tuning overrides
//!
//! pgBackRust exposes five options that let an operator override the built-in
//! heuristic (C ref: `backupBlockIncr*` in `src/command/backup/backup.c`):
//!
//! - `repo-block-size-map` — `<file size>=<block size>` pairs. The block size for
//!   the largest *file-size* bucket the file reaches replaces the heuristic's base
//!   block size.
//! - `repo-block-age-map` — `<age in days>=<multiplier>` pairs. The largest
//!   *age* bucket the file reaches multiplies the chosen block size. (When the map
//!   is set but the file is older than every bucket, the heuristic's own
//!   "too old → no map" rule still applies.)
//! - `repo-block-checksum-size-map` — `<block size>=<checksum bytes>` pairs. Maps
//!   the chosen block size to the number of checksum bytes recorded per block.
//! - `repo-block-size-super` / `repo-block-size-super-full` — the super-block size
//!   (a super block groups several blocks for compression). The `-full` variant is
//!   used for full backups, the plain one for diff/incr.
//!
//! [`BlockOverrides`] parses these into sorted lookup tables and
//! [`BlockOverrides::block_size`] / [`BlockOverrides::checksum_size`] /
//! [`BlockOverrides::super_size`] apply them; when an override is unset the
//! behaviour falls back to the heuristic ([`block_size`]) / the built-in defaults,
//! so an absent map leaves the prior behaviour unchanged.

/// One kibibyte.
const KIB: u64 = 1024;
/// One mebibyte.
const MIB: u64 = 1024 * KIB;

/// Files at least this old (in seconds, relative to the backup start) get **no**
/// block map — their contents have long since stopped changing, so per-block
/// bookkeeping would be pure overhead. Mirrors pgBackRust's oldest age-map bucket
/// dropping the map for ancient files (`src/command/backup/backup.c`,
/// `backupBlockIncrSize`'s age handling). Roughly four weeks.
const AGE_NO_BLOCK_SECS: i64 = 4 * 7 * 24 * 60 * 60;

/// A file must be at least this large to be worth a block map at all. Smaller
/// files are bundled / stored whole — splitting them yields no benefit and the
/// map overhead dominates. Mirrors the smallest super-block / block thresholds in
/// pgBackRust.
const MIN_BLOCK_FILE_SIZE: u64 = 128 * KIB;

/// The smallest block size pgBackRust uses (its base bucket). Block sizes scale
/// up from here for larger / older files.
const BASE_BLOCK_SIZE: u64 = 8 * KIB;

/// One week, in seconds — the age-bucket width for the block-size policy.
const WEEK_SECS: i64 = 7 * 24 * 60 * 60;

/// One day, in seconds — the unit the `repo-block-age-map` keys are expressed in
/// ("map file age in days to a block multiplier").
const DAY_SECS: i64 = 24 * 60 * 60;

/// Default super-block size for diff/incr backups (`repo-block-size-super`,
/// 256 KiB) when the option is absent.
pub const DEFAULT_SUPER_SIZE: u64 = 256 * KIB;

/// Default super-block size for full backups (`repo-block-size-super-full`,
/// 1 MiB) when the option is absent.
pub const DEFAULT_SUPER_SIZE_FULL: u64 = MIB;

/// Default per-block checksum size in bytes when no `repo-block-checksum-size-map`
/// bucket matches. pgBackRust uses a 6-byte truncated checksum by default.
pub const DEFAULT_CHECKSUM_SIZE: u64 = 6;

/// Explicit block-incremental tuning overrides, parsed from the resolved
/// `repo-block-*` options.
///
/// Each map is a sorted list of `(threshold, value)` pairs. Lookups select the
/// entry with the **largest threshold not exceeding** the probe (file size, file
/// age, or chosen block size), mirroring pgBackRust's bucketed maps. An empty map
/// means "no override" — the heuristic / defaults apply.
///
/// [`BlockOverrides::none`] (every map empty, both super sizes at their defaults)
/// reproduces the prior heuristic-only behaviour exactly, so callers that pass it
/// keep their existing output byte-for-byte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockOverrides {
    /// `repo-block-size-map`: file size (bytes) → block size (bytes).
    size_map: Vec<(u64, u64)>,
    /// `repo-block-age-map`: file age (days) → block-size multiplier.
    age_map: Vec<(u64, u64)>,
    /// `repo-block-checksum-size-map`: block size (bytes) → checksum size (bytes).
    checksum_size_map: Vec<(u64, u64)>,
    /// `repo-block-size-super` (diff/incr super-block size, bytes).
    super_size: u64,
    /// `repo-block-size-super-full` (full-backup super-block size, bytes).
    super_size_full: u64,
}

impl BlockOverrides {
    /// No overrides: every map empty and both super sizes at their defaults. The
    /// block-size / checksum-size / super-size selectors then fall back to the
    /// heuristic and the built-in defaults, reproducing the prior behaviour.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            size_map: Vec::new(),
            age_map: Vec::new(),
            checksum_size_map: Vec::new(),
            super_size: DEFAULT_SUPER_SIZE,
            super_size_full: DEFAULT_SUPER_SIZE_FULL,
        }
    }

    /// Build the overrides from already-parsed values: the three maps as
    /// `(threshold, value)` pairs (order irrelevant — sorted here) and the two
    /// super-block sizes (`None` falls back to the default).
    ///
    /// This is the typed constructor the option layer feeds; the `from_*_map`
    /// string parsers in `backup.rs` produce the pair lists.
    #[must_use]
    pub fn new(
        size_map: Vec<(u64, u64)>,
        age_map: Vec<(u64, u64)>,
        checksum_size_map: Vec<(u64, u64)>,
        super_size: Option<u64>,
        super_size_full: Option<u64>,
    ) -> Self {
        let sort = |mut v: Vec<(u64, u64)>| {
            v.sort_unstable_by_key(|&(threshold, _)| threshold);
            v
        };
        Self {
            size_map: sort(size_map),
            age_map: sort(age_map),
            checksum_size_map: sort(checksum_size_map),
            super_size: super_size.unwrap_or(DEFAULT_SUPER_SIZE),
            super_size_full: super_size_full.unwrap_or(DEFAULT_SUPER_SIZE_FULL),
        }
    }

    /// True when no map override is configured — the heuristic alone decides the
    /// block size. (Super sizes are always set, so they are not part of this.)
    #[must_use]
    pub const fn maps_empty(&self) -> bool {
        self.size_map.is_empty() && self.age_map.is_empty() && self.checksum_size_map.is_empty()
    }

    /// The value of the largest-threshold entry not exceeding `probe`, or `None`
    /// when the map is empty or every threshold is larger than `probe`. The map is
    /// sorted ascending by threshold, so the last matching entry is the answer.
    fn lookup(map: &[(u64, u64)], probe: u64) -> Option<u64> {
        map.iter()
            .take_while(|&&(threshold, _)| threshold <= probe)
            .last()
            .map(|&(_, value)| value)
    }

    /// Decide the block size for a file, applying the size/age map overrides on
    /// top of the heuristic. Returns `None` when no block map should be written
    /// (the file is too small or too old per the heuristic).
    ///
    /// - When `repo-block-size-map` matches, its block size replaces the
    ///   heuristic's base size; otherwise the heuristic's chosen size is used.
    /// - When `repo-block-age-map` matches, its multiplier scales the chosen size
    ///   and **replaces** the heuristic's own age scaling (the age component is
    ///   computed at age 0 so the map is the sole age contributor — the two never
    ///   compound). With no age-map entry the heuristic's age scaling stands.
    /// - With both maps empty this returns exactly [`block_size`].
    #[must_use]
    pub fn block_size(&self, file_size: u64, age_secs: i64) -> Option<u64> {
        // The heuristic still gates eligibility (too-small / too-old → no map),
        // so an override never resurrects a file the heuristic dropped.
        block_size(file_size, age_secs)?;

        // The age-in-days bucket for this file. A future mtime (negative age)
        // matches no bucket. When the age map has a matching entry it owns the age
        // scaling, so the heuristic base is taken at age 0 to avoid compounding;
        // otherwise the heuristic keeps its own age scaling.
        let age_days = u64::try_from(age_secs.max(0) / DAY_SECS).unwrap_or(0);
        let age_multiplier = Self::lookup(&self.age_map, age_days);
        let heuristic_age = if age_multiplier.is_some() { 0 } else { age_secs };
        let heuristic = block_size(file_size, heuristic_age)?;

        // Size override: the block size for the largest file-size bucket the file
        // reaches replaces the heuristic's base size.
        let mut chosen = Self::lookup(&self.size_map, file_size).unwrap_or(heuristic);

        // Age override: scale by the multiplier for the matching age-in-days bucket.
        if let Some(multiplier) = age_multiplier {
            chosen = chosen.saturating_mul(multiplier);
        }

        Some(chosen)
    }

    /// The per-block checksum size (bytes) for a given chosen `block_size`,
    /// applying `repo-block-checksum-size-map`. Falls back to
    /// [`DEFAULT_CHECKSUM_SIZE`] when the map is empty or no bucket matches.
    #[must_use]
    pub fn checksum_size(&self, block_size: u64) -> u64 {
        Self::lookup(&self.checksum_size_map, block_size).unwrap_or(DEFAULT_CHECKSUM_SIZE)
    }

    /// The super-block size (bytes) for a backup. `is_full` selects
    /// `repo-block-size-super-full`; otherwise `repo-block-size-super`.
    #[must_use]
    pub const fn super_size(&self, is_full: bool) -> u64 {
        if is_full { self.super_size_full } else { self.super_size }
    }
}

/// Decide the block size for a file of `file_size` bytes whose data is `age_secs`
/// old (backup start timestamp minus the file's mtime), or `None` when no block
/// map should be written for it.
///
/// The policy mirrors pgBackRust's `backupBlockIncrSize`:
///
/// - A file smaller than [`MIN_BLOCK_FILE_SIZE`] gets no map (stored whole).
/// - A file older than [`AGE_NO_BLOCK_SECS`] gets no map (its blocks will not
///   change again, so a map is pure overhead).
/// - Otherwise the block size scales with both size and age: it starts at
///   [`BASE_BLOCK_SIZE`] and doubles for each size bucket the file exceeds and for
///   age, clamped to a sane maximum. Bigger / older files therefore get bigger
///   blocks (fewer, coarser blocks), keeping the block map proportional to the
///   data rather than the file count.
///
/// Negative `age_secs` (a file with a future mtime / clock skew) is treated as
/// age zero (freshest bucket).
#[must_use]
pub fn block_size(file_size: u64, age_secs: i64) -> Option<u64> {
    if file_size < MIN_BLOCK_FILE_SIZE {
        return None;
    }
    if age_secs >= AGE_NO_BLOCK_SECS {
        return None;
    }
    let age = age_secs.max(0);

    // Size component: one doubling per power-of-two MiB the file reaches, so a
    // 1 MiB file is one bucket up from the base, 2 MiB two buckets, etc.
    let size_buckets = if file_size < MIB {
        0
    } else {
        // floor(log2(file_size / MIB)) + 1
        let mib = file_size / MIB;
        u64::from(64 - mib.leading_zeros())
    };

    // Age component: one extra doubling per week of age. Older files get coarser
    // blocks because their changes (if any) tend to be coarse-grained.
    let age_buckets = u64::try_from(age / WEEK_SECS).unwrap_or(0);

    let shift = (size_buckets + age_buckets).min(7); // cap at 8 KiB << 7 = 1 MiB.
    Some(BASE_BLOCK_SIZE << shift)
}

/// Split `bytes` into `block_size`-byte chunks (the final chunk may be shorter).
/// An empty input yields no blocks. `block_size` of zero is treated as a single
/// whole-file block so the function is total.
#[must_use]
pub fn split_blocks(bytes: &[u8], block_size: u64) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    // A zero block size means "whole file in one block" (totality guard); any
    // positive size chunks normally, clamped into `usize` for the slice API.
    let chunk = if block_size == 0 {
        bytes.len()
    } else {
        usize::try_from(block_size).unwrap_or(usize::MAX)
    };
    bytes.chunks(chunk).collect()
}

/// Reassemble a file from its ordered blocks — the inverse of [`split_blocks`].
/// Concatenates the blocks in order.
#[must_use]
pub fn reassemble(blocks: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = blocks.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(total);
    for block in blocks {
        out.extend_from_slice(block);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn small_files_get_no_block_map() {
        assert_eq!(block_size(0, 0), None);
        assert_eq!(block_size(8 * KIB, 0), None);
        assert_eq!(block_size(MIN_BLOCK_FILE_SIZE - 1, 0), None);
    }

    #[test]
    fn very_old_files_get_no_block_map() {
        // A large but ancient file: no map.
        assert_eq!(block_size(64 * MIB, AGE_NO_BLOCK_SECS), None);
        assert_eq!(block_size(64 * MIB, AGE_NO_BLOCK_SECS + 1), None);
        // Just under the age cutoff: still mapped.
        assert!(block_size(64 * MIB, AGE_NO_BLOCK_SECS - 1).is_some());
    }

    #[test]
    fn block_size_scales_up_with_file_size() {
        // A small-but-eligible fresh file gets the base block size.
        let small = block_size(MIN_BLOCK_FILE_SIZE, 0).unwrap();
        // A much larger fresh file gets a strictly larger block size.
        let large = block_size(256 * MIB, 0).unwrap();
        assert!(large > small, "bigger files must get bigger blocks: {small} vs {large}");
        // Block sizes are always powers of two of the base.
        assert_eq!(small % BASE_BLOCK_SIZE, 0);
        assert!(small.is_power_of_two());
        assert!(large.is_power_of_two());
    }

    #[test]
    fn block_size_scales_up_with_age() {
        let fresh = block_size(2 * MIB, 0).unwrap();
        let old = block_size(2 * MIB, 3 * 7 * 24 * 60 * 60).unwrap();
        assert!(
            old >= fresh,
            "older files must get blocks at least as coarse: {fresh} vs {old}"
        );
        assert!(old > fresh, "three weeks older must coarsen the block: {fresh} vs {old}");
    }

    #[test]
    fn block_size_is_capped() {
        // An enormous, three-week-old file must still cap at the maximum block.
        let huge = block_size(1024 * 1024 * MIB, 3 * 7 * 24 * 60 * 60).unwrap();
        assert_eq!(huge, BASE_BLOCK_SIZE << 7, "block size must cap at 1 MiB");
    }

    #[test]
    fn negative_age_treated_as_freshest() {
        assert_eq!(block_size(2 * MIB, -100), block_size(2 * MIB, 0));
    }

    #[test]
    fn split_and_reassemble_round_trips() {
        let data: Vec<u8> = (0..20_000u32).map(|n| (n % 251) as u8).collect();
        for bs in [1u64, 100, 4096, 8192, 30_000] {
            let parts: Vec<Vec<u8>> = split_blocks(&data, bs).into_iter().map(<[u8]>::to_vec).collect();
            // Every block but the last is exactly `bs` bytes (when bs <= len).
            if usize::try_from(bs).unwrap_or(usize::MAX) <= data.len() && bs > 0 {
                for block in &parts[..parts.len() - 1] {
                    assert_eq!(block.len() as u64, bs);
                }
            }
            let rebuilt = reassemble(&parts);
            assert_eq!(rebuilt, data, "round trip with block size {bs}");
        }
    }

    #[test]
    fn empty_input_has_no_blocks() {
        assert!(split_blocks(&[], 8192).is_empty());
        assert!(reassemble(&[]).is_empty());
    }

    #[test]
    fn zero_block_size_is_single_block() {
        let data = b"abcdef".to_vec();
        let parts = split_blocks(&data, 0);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], data.as_slice());
    }

    #[test]
    fn no_overrides_matches_heuristic_exactly() {
        let overrides = BlockOverrides::none();
        for &size in &[0u64, 64 * KIB, MIN_BLOCK_FILE_SIZE, MIB, 256 * MIB] {
            for &age in &[-100i64, 0, WEEK_SECS, AGE_NO_BLOCK_SECS] {
                assert_eq!(
                    overrides.block_size(size, age),
                    block_size(size, age),
                    "no-override block_size must equal the heuristic for size={size} age={age}"
                );
            }
        }
        // Defaults for the non-map selectors.
        assert_eq!(overrides.checksum_size(8 * KIB), DEFAULT_CHECKSUM_SIZE);
        assert_eq!(overrides.super_size(false), DEFAULT_SUPER_SIZE);
        assert_eq!(overrides.super_size(true), DEFAULT_SUPER_SIZE_FULL);
        assert!(overrides.maps_empty());
    }

    #[test]
    fn size_map_overrides_chosen_block_size() {
        // Map: files >= 16 KiB get 8 KiB blocks, files >= 512 KiB get 32 KiB.
        let overrides = BlockOverrides::new(
            vec![(16 * KIB, 8 * KIB), (512 * KIB, 32 * KIB)],
            Vec::new(),
            Vec::new(),
            None,
            None,
        );
        // A 256 MiB fresh file: heuristic picks a large block, the map forces the
        // largest bucket <= 256 MiB, which is the 512 KiB bucket → 32 KiB.
        let heuristic = block_size(256 * MIB, 0).unwrap();
        let overridden = overrides.block_size(256 * MIB, 0).unwrap();
        assert_eq!(overridden, 32 * KIB, "size map must pick the matching bucket's block size");
        assert_ne!(overridden, heuristic, "the override must differ from the heuristic here");

        // A file between the two thresholds takes the lower bucket (8 KiB).
        assert_eq!(overrides.block_size(200 * KIB, 0).unwrap(), 8 * KIB);
    }

    #[test]
    fn age_map_scales_chosen_block_size() {
        // No size override (heuristic block size), age map doubles at >= 7 days,
        // quadruples at >= 14 days.
        let overrides = BlockOverrides::new(Vec::new(), vec![(7, 2), (14, 4)], Vec::new(), None, None);
        let base = block_size(2 * MIB, 0).unwrap();
        // Fresh file: no age bucket, unchanged.
        assert_eq!(overrides.block_size(2 * MIB, 0).unwrap(), base);
        // 10 days old: x2.
        assert_eq!(overrides.block_size(2 * MIB, 10 * DAY_SECS).unwrap(), base * 2);
        // 20 days old: x4.
        assert_eq!(overrides.block_size(2 * MIB, 20 * DAY_SECS).unwrap(), base * 4);
    }

    #[test]
    fn size_and_age_map_combine() {
        let overrides = BlockOverrides::new(vec![(16 * KIB, 8 * KIB)], vec![(7, 4)], Vec::new(), None, None);
        // Size bucket forces 8 KiB, age bucket multiplies by 4 → 32 KiB.
        assert_eq!(overrides.block_size(2 * MIB, 10 * DAY_SECS).unwrap(), 32 * KIB);
    }

    #[test]
    fn overrides_respect_heuristic_eligibility() {
        // Even with aggressive maps, a too-small or too-old file gets no map.
        let overrides = BlockOverrides::new(vec![(0, 8 * KIB)], vec![(0, 8)], Vec::new(), None, None);
        assert_eq!(overrides.block_size(MIN_BLOCK_FILE_SIZE - 1, 0), None);
        assert_eq!(overrides.block_size(64 * MIB, AGE_NO_BLOCK_SECS), None);
    }

    #[test]
    fn checksum_size_map_buckets() {
        let overrides = BlockOverrides::new(Vec::new(), Vec::new(), vec![(32 * KIB, 7), (128 * KIB, 8)], None, None);
        // Below the first bucket → default.
        assert_eq!(overrides.checksum_size(8 * KIB), DEFAULT_CHECKSUM_SIZE);
        // Between buckets → lower bucket.
        assert_eq!(overrides.checksum_size(64 * KIB), 7);
        // At/above the top bucket → top bucket.
        assert_eq!(overrides.checksum_size(MIB), 8);
    }

    #[test]
    fn super_size_selects_full_vs_incr() {
        let overrides = BlockOverrides::new(Vec::new(), Vec::new(), Vec::new(), Some(2 * MIB), Some(8 * MIB));
        assert_eq!(overrides.super_size(false), 2 * MIB);
        assert_eq!(overrides.super_size(true), 8 * MIB);
        // Unset super sizes fall back to the defaults.
        let defaulted = BlockOverrides::new(Vec::new(), Vec::new(), Vec::new(), None, None);
        assert_eq!(defaulted.super_size(false), DEFAULT_SUPER_SIZE);
        assert_eq!(defaulted.super_size(true), DEFAULT_SUPER_SIZE_FULL);
    }
}
