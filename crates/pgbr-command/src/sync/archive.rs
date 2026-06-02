//! repo-sync WAL engine: byte-identical mirroring of archived WAL from the
//! active repository to one destination repository.
//!
//! Every object under `archive/<stanza>/<archive-id>/` in the source — full and
//! partial WAL segments, backup-history files (`<seg>.<off>.backup`), and
//! timeline-history files (`<tli>.history`) — is enumerated and raw-copied to the
//! **same** path in the destination. Because repositories in a set are
//! byte-identical mirrors (global compression; identical bundling / block /
//! cipher sub-key), the copy is a pure [`pgbr_io::copy`] of the stored bytes:
//! no decompress, no decrypt, no recompute. The archive-id directory name
//! (`<db-version>-<db-id>`) is resolved from the source `archive.info` via
//! [`crate::archive::load_archive_info`].
//!
//! Idempotent: a WAL segment already present in the destination in any stored
//! form (plaintext or a compression suffix) is skipped via
//! [`crate::archive::repo_has_segment`]; non-segment objects are skipped on a
//! plain [`Storage::exists`]. `archive.info` itself is never touched — it is
//! per-repo metadata seeded by `stanza-create`, and the destination is required
//! to be an already-initialised stanza sharing the source cipher sub-key.

use std::path::PathBuf;

use pgbr_config::LoadedConfig;
use pgbr_postgres::lsn::parse_wal_segment;
use pgbr_storage::Storage;

use super::{SyncKind, SyncOutcome};
use crate::CommandError;

/// File extensions a stored WAL object may carry, in the same order the
/// `archive-get` path probes them. Stripped from a listed object's basename to
/// recover the bare segment name for the idempotent
/// [`crate::archive::repo_has_segment`] probe. Mirrors `archive.rs`'s private
/// `COMPRESS_SUFFIXES` (kept local so sync does not depend on that constant's
/// visibility).
const COMPRESS_SUFFIXES: &[&str] = &[".gz", ".zst", ".bz2", ".lz4"];

/// Mirror every WAL object for a stanza to one destination repository.
///
/// Performs a raw byte copy of every WAL object under
/// `archive/<stanza>/<archive-id>/` from the source repository to one
/// destination. The archive-id (`<db-version>-<db-id>`) comes from the source
/// `archive.info`. Idempotent: a segment already present in the destination (in
/// any stored form) is skipped, as is any non-segment object whose exact path
/// already exists.
///
/// `src_index` / `dst_index` are the configured repository group indexes (used
/// only for log/diagnostic context here; the cipher sub-key is shared, so the
/// raw bytes are valid in either repository unchanged).
///
/// # Errors
///
/// Propagates storage and info-load failures. Returns an empty outcome when the
/// source has no `archive.info` (an uninitialised stanza, nothing to mirror).
pub fn sync_archive_to_repo(
    config: &LoadedConfig,
    stanza: &str,
    src: &dyn Storage,
    src_index: u32,
    dst: &dyn Storage,
    dst_index: u32,
) -> Result<SyncOutcome, CommandError> {
    // The source/destination indexes are not needed for the raw copy itself
    // (paths and bytes are identical across mirrors); they exist on the
    // signature for symmetry with the backup engine and future diagnostics.
    let _ = (src_index, dst_index);

    // Resolve the archive-id directory from the SOURCE archive.info. A
    // one-element slice puts the source at position 0 so load_archive_info
    // resolves the cipher passphrase at the first configured index (the active
    // --repo, i.e. the source). No archive.info → nothing has been archived
    // yet, so there is nothing to mirror.
    let Some(info) = crate::archive::load_archive_info(config, &[src], stanza)? else {
        return Ok(SyncOutcome {
            kind: SyncKind::Wal,
            items: 0,
            bytes: 0,
        });
    };
    let aid = crate::archive::archive_id(&info);

    // Enumerate every File under the archive-id directory. WAL lives one level
    // deep in the flat layout, but recurse to be robust against any nested
    // layout the storage backend reports.
    let aid_dir = PathBuf::from(format!("archive/{stanza}/{aid}"));
    let mut files = Vec::new();
    super::list_recursive(src, &aid_dir, &mut files)?;

    let mut items = 0usize;
    let mut bytes = 0u64;
    for entry in files {
        let Some(name) = entry.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // archive.info / archive.info.copy are per-repo metadata seeded by
        // stanza-create; never mirror them.
        if name == "archive.info" || name == "archive.info.copy" {
            continue;
        }

        // For a real WAL segment (24-hex base, possibly with a compression
        // suffix) the destination may already hold a differently-suffixed form,
        // so short-circuit with repo_has_segment (which probes plaintext + every
        // compression suffix). For non-segment objects (.history, .backup) the
        // stored form is unambiguous, so sync_one_segment's plain exists() skip
        // is sufficient.
        if let Some(base) = segment_base(name)
            && crate::archive::repo_has_segment(dst, stanza, &aid, base)?
        {
            continue;
        }

        let n = sync_one_segment(src, dst, stanza, &aid, name)?;
        if n > 0 {
            items += 1;
            bytes += n;
        }
    }

    Ok(SyncOutcome {
        kind: SyncKind::Wal,
        items,
        bytes,
    })
}

/// The bare WAL-segment name for a stored object `name`, or `None` when `name`
/// is not a WAL segment (e.g. a `.history` or `.backup` file).
///
/// A stored segment is a 24-hex name optionally followed by a compression
/// suffix (`000000010000000000000001`, `000000010000000000000001.gz`). Strips
/// any known compression suffix and returns the base when it parses as a WAL
/// segment; partial segments (`….partial`) and non-segment objects return
/// `None` so the caller falls back to an exact-path idempotency check.
fn segment_base(name: &str) -> Option<&str> {
    let base = COMPRESS_SUFFIXES
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name);
    if parse_wal_segment(base).is_some() { Some(base) } else { None }
}

/// Raw-copy one stored WAL object `name` (the basename, including any
/// compression suffix, e.g. `…01.gz`) from the source archive-id directory to
/// the same path in the destination, skipping if already present. Returns the
/// bytes copied (`0` on skip).
///
/// The bytes are copied verbatim — no decompress / decrypt / recompute — because
/// the repositories are byte-identical mirrors.
///
/// # Errors
///
/// Propagates storage / I/O failures from the open / copy / create-path calls.
fn sync_one_segment(src: &dyn Storage, dst: &dyn Storage, stanza: &str, archive_id: &str, name: &str) -> Result<u64, CommandError> {
    let src_path = crate::archive::repo_segment_path(stanza, archive_id, name);
    let dst_path = src_path.clone(); // identical layout across mirrors
    if dst.exists(&dst_path)? {
        return Ok(0);
    }
    if let Some(parent) = dst_path.parent() {
        dst.create_path(parent, true)?;
    }
    let mut reader = src.open_read(&src_path)?;
    let mut writer = dst.open_write(&dst_path)?;
    let n = pgbr_io::copy(&mut reader, &mut writer)?;
    writer.flush()?;
    writer.close()?;
    Ok(n)
}

/// Storage-rooted path of a stored WAL object, mirroring
/// [`crate::archive::repo_segment_path`] for the test fixtures.
#[cfg(test)]
fn test_segment_path(stanza: &str, archive_id: &str, name: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/{archive_id}/{name}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};
    use pgbr_info::InfoArchive;
    use pgbr_storage::{Posix, Storage};
    use tempfile::TempDir;

    use super::{SyncKind, sync_archive_to_repo, sync_one_segment, test_segment_path};

    const STANZA: &str = "demo";
    const ARCHIVE_ID: &str = "16-1";
    const SEGMENT: &str = "000000010000000000000001";
    const SEGMENT_2: &str = "000000010000000000000002";
    const WAL_BODY: &[u8] = b"fake-wal-segment-contents";
    const WAL_BODY_2: &[u8] = b"another-segment-payload";

    /// A `LoadedConfig` for the `repo-sync` command with no options set, so the
    /// repositories resolve as the implicit single unencrypted repo at index 1.
    fn config() -> LoadedConfig {
        LoadedConfig {
            command: "repo-sync".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(STANZA.to_owned()),
            options: BTreeMap::new(),
            params: Vec::new(),
        }
    }

    /// Seed an unencrypted `archive.info` for `STANZA` into `repo` so the
    /// archive-id resolves to [`ARCHIVE_ID`] (`db_version` `"16"`, `db_id` `1`).
    fn seed_archive_info(repo: &Posix) {
        repo.create_path(Path::new(&format!("archive/{STANZA}")), true)
            .expect("create archive dir");
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "16".to_owned(),
            history: BTreeMap::new(),
        }
        .save(repo, Path::new(&format!("archive/{STANZA}/archive.info")))
        .expect("save archive.info");
    }

    /// Write `bytes` to a stored WAL object `name` under the source archive-id
    /// directory.
    fn put_segment(repo: &Posix, name: &str, bytes: &[u8]) {
        let path = test_segment_path(STANZA, ARCHIVE_ID, name);
        if let Some(parent) = path.parent() {
            repo.create_path(parent, true).expect("create parent");
        }
        let mut w = repo.open_write(&path).expect("open_write");
        w.write(bytes).expect("write");
        w.close().expect("close");
    }

    /// Read every byte of a stored WAL object `name` from `repo`, or `None` when
    /// it is absent.
    fn read_segment(repo: &Posix, name: &str) -> Option<Vec<u8>> {
        let path = test_segment_path(STANZA, ARCHIVE_ID, name);
        if !repo.exists(&path).expect("exists") {
            return None;
        }
        let mut r = repo.open_read(&path).expect("open_read");
        Some(r.read_all().expect("read_all"))
    }

    fn repo_pair() -> (TempDir, TempDir, Posix, Posix) {
        let src = tempfile::tempdir().expect("src tempdir");
        let dst = tempfile::tempdir().expect("dst tempdir");
        let src_s = Posix::new(src.path());
        let dst_s = Posix::new(dst.path());
        (src, dst, src_s, dst_s)
    }

    #[test]
    fn copies_wal_segments_to_destination() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        seed_archive_info(&src_s);
        put_segment(&src_s, SEGMENT, WAL_BODY);
        put_segment(&src_s, SEGMENT_2, WAL_BODY_2);

        let cfg = config();
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s, 2).expect("sync");

        assert_eq!(outcome.kind, SyncKind::Wal);
        assert_eq!(outcome.items, 2);
        assert_eq!(outcome.bytes, (WAL_BODY.len() + WAL_BODY_2.len()) as u64);
        assert_eq!(read_segment(&dst_s, SEGMENT).as_deref(), Some(WAL_BODY));
        assert_eq!(read_segment(&dst_s, SEGMENT_2).as_deref(), Some(WAL_BODY_2));
    }

    #[test]
    fn rerun_is_idempotent_noop() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        seed_archive_info(&src_s);
        put_segment(&src_s, SEGMENT, WAL_BODY);

        let cfg = config();
        let first = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s, 2).expect("first sync");
        assert_eq!(first.items, 1);
        assert_eq!(first.bytes, WAL_BODY.len() as u64);

        // Second run: everything is already present, so nothing is copied.
        let second = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s, 2).expect("second sync");
        assert_eq!(second.items, 0);
        assert_eq!(second.bytes, 0);
        assert_eq!(read_segment(&dst_s, SEGMENT).as_deref(), Some(WAL_BODY));
    }

    #[test]
    fn segment_already_in_destination_is_skipped() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        seed_archive_info(&src_s);
        put_segment(&src_s, SEGMENT, WAL_BODY);
        put_segment(&src_s, SEGMENT_2, WAL_BODY_2);
        // Destination already has SEGMENT (same bytes); only SEGMENT_2 should copy.
        put_segment(&dst_s, SEGMENT, WAL_BODY);

        let cfg = config();
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s, 2).expect("sync");

        assert_eq!(outcome.items, 1);
        assert_eq!(outcome.bytes, WAL_BODY_2.len() as u64);
        assert_eq!(read_segment(&dst_s, SEGMENT_2).as_deref(), Some(WAL_BODY_2));
    }

    #[test]
    fn segment_present_under_compression_suffix_is_skipped() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        seed_archive_info(&src_s);
        put_segment(&src_s, SEGMENT, WAL_BODY);
        // Destination holds the segment under a .gz suffix — repo_has_segment
        // probes every suffix, so the plaintext source form must be skipped.
        put_segment(&dst_s, &format!("{SEGMENT}.gz"), b"already-compressed");

        let cfg = config();
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s, 2).expect("sync");

        assert_eq!(outcome.items, 0);
        assert_eq!(outcome.bytes, 0);
        // The plaintext form was NOT written (the .gz form already counts).
        assert_eq!(read_segment(&dst_s, SEGMENT), None);
    }

    #[test]
    fn history_and_backup_files_are_mirrored() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        seed_archive_info(&src_s);
        put_segment(&src_s, SEGMENT, WAL_BODY);
        let history = "00000002.history";
        let backup_history = "000000010000000000000001.00000028.backup";
        put_segment(&src_s, history, b"timeline-history-body");
        put_segment(&src_s, backup_history, b"backup-history-body");

        let cfg = config();
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s, 2).expect("sync");

        assert_eq!(outcome.items, 3);
        assert_eq!(read_segment(&dst_s, history).as_deref(), Some(&b"timeline-history-body"[..]));
        assert_eq!(
            read_segment(&dst_s, backup_history).as_deref(),
            Some(&b"backup-history-body"[..])
        );
    }

    #[test]
    fn no_archive_info_yields_empty_outcome() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        // No archive.info seeded on the source: nothing has been archived.
        let cfg = config();
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s, 2).expect("sync");
        assert_eq!(outcome.kind, SyncKind::Wal);
        assert_eq!(outcome.items, 0);
        assert_eq!(outcome.bytes, 0);
    }

    #[test]
    fn sync_one_segment_copies_then_skips() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        put_segment(&src_s, SEGMENT, WAL_BODY);

        let copied = sync_one_segment(&src_s, &dst_s, STANZA, ARCHIVE_ID, SEGMENT).expect("first copy");
        assert_eq!(copied, WAL_BODY.len() as u64);
        assert_eq!(read_segment(&dst_s, SEGMENT).as_deref(), Some(WAL_BODY));

        // Already present → skip, zero bytes.
        let again = sync_one_segment(&src_s, &dst_s, STANZA, ARCHIVE_ID, SEGMENT).expect("second copy");
        assert_eq!(again, 0);
    }
}
