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
//! - [`block_size`] — the age + size → block-size policy. pgBackRest scales the
//!   block size up for bigger and older files (so the per-block bookkeeping stays
//!   proportional to the data), and disables the block map entirely for very old
//!   files (whose blocks are unlikely to ever change again, so a map would be
//!   pure overhead). Returns `None` when no block map should be written.
//! - [`split_blocks`] / [`reassemble`] — split a file's plaintext into blocks and
//!   the inverse, used by the round-trip tests and by the backup / restore paths.

/// One kibibyte.
const KIB: u64 = 1024;
/// One mebibyte.
const MIB: u64 = 1024 * KIB;

/// Files at least this old (in seconds, relative to the backup start) get **no**
/// block map — their contents have long since stopped changing, so per-block
/// bookkeeping would be pure overhead. Mirrors pgBackRest's oldest age-map bucket
/// dropping the map for ancient files (`src/command/backup/backup.c`,
/// `backupBlockIncrSize`'s age handling). Roughly four weeks.
const AGE_NO_BLOCK_SECS: i64 = 4 * 7 * 24 * 60 * 60;

/// A file must be at least this large to be worth a block map at all. Smaller
/// files are bundled / stored whole — splitting them yields no benefit and the
/// map overhead dominates. Mirrors the smallest super-block / block thresholds in
/// pgBackRest.
const MIN_BLOCK_FILE_SIZE: u64 = 128 * KIB;

/// The smallest block size pgBackRest uses (its base bucket). Block sizes scale
/// up from here for larger / older files.
const BASE_BLOCK_SIZE: u64 = 8 * KIB;

/// One week, in seconds — the age-bucket width for the block-size policy.
const WEEK_SECS: i64 = 7 * 24 * 60 * 60;

/// Decide the block size for a file of `file_size` bytes whose data is `age_secs`
/// old (backup start timestamp minus the file's mtime), or `None` when no block
/// map should be written for it.
///
/// The policy mirrors pgBackRest's `backupBlockIncrSize`:
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
}
