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
//! (`<db-version>-<db-id>`) is resolved from the source `archive.info`, loaded
//! and decrypted under the SOURCE repository's own cipher passphrase (keyed by
//! the active `--repo` index, not the lowest configured one).
//!
//! Idempotent: a WAL segment already present in the destination in any stored
//! form (plaintext or a compression suffix) is skipped; non-segment objects are
//! re-copied only when the destination copy is absent or torn (size mismatch).
//! `archive.info` itself is never touched — it is per-repo metadata seeded by
//! `stanza-create`, and the destination is required to be an already-initialised
//! stanza sharing the source cipher sub-key.
//!
//! The destination archive-id directory is listed ONCE up front into a
//! basename → size map (and a set of stored segment bases). Every idempotency
//! decision is then answered from that snapshot rather than per-object
//! [`Storage::exists`] probes, so re-syncing a large archive that copies nothing
//! costs one destination listing instead of one signed HEAD (or several, across
//! compression suffixes) per source segment — decisive on S3 / Azure / GCS.

use std::collections::BTreeSet;
use std::path::PathBuf;

use pgbr_config::LoadedConfig;
use pgbr_info::InfoArchive;
use pgbr_postgres::lsn::parse_wal_segment;
use pgbr_storage::Storage;

use super::{SyncKind, SyncOutcome};
use crate::CommandError;

/// Mirror every WAL object for a stanza to one destination repository.
///
/// Performs a raw byte copy of every WAL object under
/// `archive/<stanza>/<archive-id>/` from the source repository to one
/// destination. The archive-id (`<db-version>-<db-id>`) comes from the source
/// `archive.info`, loaded under the SOURCE repository's own cipher passphrase.
/// Idempotent: a segment already present in the destination (in any stored form)
/// is skipped; any other object is re-copied only when the destination copy is
/// absent or a torn (wrong-size) leftover.
///
/// `src_index` is the configured repository group index of the source; it
/// selects the cipher passphrase the source `archive.info` is decrypted under.
/// This must be the ACTIVE `--repo`, not the lowest configured index — with two
/// encrypted repositories under different `repo-cipher-pass` values (a supported
/// configuration: only `cipher-type` and the shared sub-key are validated equal)
/// the wrong passphrase would fail to decrypt the source `archive.info`.
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
) -> Result<SyncOutcome, CommandError> {
    // Resolve the archive-id directory from the SOURCE archive.info, decrypted
    // under the source repository's own cipher passphrase (`None` when the source
    // is unencrypted). Loading it via the source index — not a slice whose
    // position 0 maps to the lowest configured index — is what makes this correct
    // when repo1 and repo2 are encrypted under different user passphrases. No
    // archive.info → nothing has been archived yet, so there is nothing to mirror.
    let Some(info) = load_source_archive_info(config, src, src_index, stanza)? else {
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

    // List the DESTINATION archive-id directory ONCE and answer the segment
    // idempotency decision from the snapshot: `dst_bases` holds every stored
    // WAL-segment base (suffix stripped) so a segment present in ANY compressed
    // form counts as already mirrored. This replaces the per-segment
    // `repo_has_segment` HEAD storm — one listing versus up to five signed HEADs
    // per source segment on the cloud backends. Non-segment objects fall through
    // to `copy_object`, whose own size-checked probe both skips a complete copy
    // and repairs a torn one.
    let mut dst_files = Vec::new();
    super::list_recursive(dst, &aid_dir, &mut dst_files)?;
    let mut dst_bases: BTreeSet<String> = BTreeSet::new();
    for entry in &dst_files {
        let Some(name) = entry.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(base) = segment_base(name) {
            dst_bases.insert(base.to_owned());
        }
    }

    // Create the destination archive-id directory once, before the copy loop,
    // rather than per object. `copy_object` re-creates parents defensively, but
    // doing it here keeps that cost off every segment.
    dst.create_path(&aid_dir, true)?;

    let mut items = 0usize;
    let mut bytes = 0u64;
    for entry in &files {
        let Some(name) = entry.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // archive.info / archive.info.copy are per-repo metadata seeded by
        // stanza-create; never mirror them.
        if name == "archive.info" || name == "archive.info.copy" {
            continue;
        }

        // For a real WAL segment the destination may already hold a
        // differently-suffixed form, so any stored base counts as present —
        // matching the old `repo_has_segment` semantics from the pre-listed set.
        // Non-segment objects (.history, .backup) fall through to the size-checked
        // copy below.
        if let Some(base) = segment_base(name)
            && dst_bases.contains(base)
        {
            continue;
        }

        // Raw byte copy with torn-write repair: `copy_object` skips when the
        // destination already holds the exact name at the source's size, and
        // re-copies over a wrong-size (partial) leftover. The source size comes
        // from the listing that enumerated the object.
        if let Some(n) = super::copy_object(src, dst, &entry.path, entry.size)? {
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

/// Load the SOURCE repository's `archive.info` for `stanza`, decrypted under its
/// own cipher passphrase (resolved from `src_index`; `None` for an unencrypted
/// repo). Returns `Ok(None)` when the source has no `archive.info` yet — an
/// uninitialised stanza with nothing to mirror.
///
/// Mirrors [`crate::archive::load_archive_info`]'s per-repo cipher resolution but
/// keys off the explicit `src_index` (the active `--repo`) rather than slice
/// position, and returns `Option` instead of erroring when the file is absent.
///
/// # Errors
///
/// [`CommandError::MissingOption`] when the source is encrypted but has no
/// `repo-cipher-pass`; [`CommandError::Other`] when the file cannot be loaded /
/// decrypted; [`CommandError::Storage`] on an underlying storage error.
fn load_source_archive_info(
    config: &LoadedConfig,
    src: &dyn Storage,
    src_index: u32,
    stanza: &str,
) -> Result<Option<InfoArchive>, CommandError> {
    let info_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    if !src.exists(&info_path)? {
        return Ok(None);
    }
    let user_pass = crate::cipher::repo_user_pass(config, src_index)?;
    let (info, _) =
        InfoArchive::load_keyed(src, &info_path, user_pass.as_deref()).map_err(|err| CommandError::Other(err.to_string()))?;
    Ok(Some(info))
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
    let base = crate::archive::COMPRESS_SUFFIXES
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name);
    if parse_wal_segment(base).is_some() { Some(base) } else { None }
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

    use super::{SyncKind, sync_archive_to_repo};

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
        let path = crate::archive::repo_segment_path(STANZA, ARCHIVE_ID, name);
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
        let path = crate::archive::repo_segment_path(STANZA, ARCHIVE_ID, name);
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
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("sync");

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
        let first = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("first sync");
        assert_eq!(first.items, 1);
        assert_eq!(first.bytes, WAL_BODY.len() as u64);

        // Second run: everything is already present, so nothing is copied.
        let second = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("second sync");
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
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("sync");

        assert_eq!(outcome.items, 1);
        assert_eq!(outcome.bytes, WAL_BODY_2.len() as u64);
        assert_eq!(read_segment(&dst_s, SEGMENT_2).as_deref(), Some(WAL_BODY_2));
    }

    #[test]
    fn segment_present_under_compression_suffix_is_skipped() {
        let (_src, _dst, src_s, dst_s) = repo_pair();
        seed_archive_info(&src_s);
        put_segment(&src_s, SEGMENT, WAL_BODY);
        // Destination holds the segment under a .gz suffix — the pre-listed base
        // set records the stripped base, so the plaintext source form is skipped.
        put_segment(&dst_s, &format!("{SEGMENT}.gz"), b"already-compressed");

        let cfg = config();
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("sync");

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
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("sync");

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
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("sync");
        assert_eq!(outcome.kind, SyncKind::Wal);
        assert_eq!(outcome.items, 0);
        assert_eq!(outcome.bytes, 0);
    }

    #[test]
    fn truncated_destination_segment_is_recopied() {
        // A prior sync was killed mid-write, leaving a short (torn) copy of a
        // non-segment object at the exact destination path. `copy_object`'s
        // size-checked probe must detect the wrong length and re-copy so the
        // destination bytes equal the source. Use a non-segment name so the copy
        // path (not the base-set skip) is exercised.
        let (_src, _dst, src_s, dst_s) = repo_pair();
        seed_archive_info(&src_s);
        let history = "00000002.history";
        put_segment(&src_s, history, b"full-history-body-contents");
        // Seed a short leftover at the same path in the destination.
        put_segment(&dst_s, history, b"trunc");

        let cfg = config();
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 1, &dst_s).expect("sync");

        // The torn object was repaired: exactly one object copied, dst == src.
        assert_eq!(outcome.items, 1);
        assert_eq!(outcome.bytes, b"full-history-body-contents".len() as u64);
        assert_eq!(
            read_segment(&dst_s, history).as_deref(),
            Some(&b"full-history-body-contents"[..])
        );
    }

    /// A `LoadedConfig` whose repo1 and repo2 are BOTH `aes-256-cbc` but under
    /// DIFFERENT user passphrases — a supported mirror config (only cipher-type
    /// and the shared sub-key are validated equal). Used to prove the source
    /// `archive.info` is decrypted under the active `--repo`'s own passphrase.
    fn encrypted_config(repo1_pass: &str, repo2_pass: &str) -> LoadedConfig {
        use pgbr_config::OptionValue;

        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(
            ("repo-cipher-type".to_owned(), Some(1)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        options.insert(
            ("repo-cipher-pass".to_owned(), Some(1)),
            OptionValue::String(repo1_pass.to_owned()),
        );
        options.insert(
            ("repo-cipher-type".to_owned(), Some(2)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        options.insert(
            ("repo-cipher-pass".to_owned(), Some(2)),
            OptionValue::String(repo2_pass.to_owned()),
        );
        LoadedConfig {
            command: "repo-sync".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(STANZA.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn encrypted_source_at_index_two_decrypts_under_its_own_pass() {
        // Regression for the wrong-passphrase-index bug: with repo1 and repo2
        // encrypted under DIFFERENT user passphrases, a `repo-sync --repo=2` must
        // decrypt the SOURCE archive.info under repo2's passphrase (src_index=2),
        // not repo1's. Seeding archive.info encrypted under repo2's pass and
        // syncing with src_index=2 must resolve and copy; a wrong-index load would
        // fail to decrypt and error.
        let repo1_pass = "1111111111111111111111111111111111111111111111111111111111111111";
        let repo2_pass = "2222222222222222222222222222222222222222222222222222222222222222";
        let sub_key = "3333333333333333333333333333333333333333333333333333333333333333";

        let (_src, _dst, src_s, dst_s) = repo_pair();

        // Seed the SOURCE archive.info encrypted under repo2's user passphrase.
        src_s
            .create_path(Path::new(&format!("archive/{STANZA}")), true)
            .expect("create archive dir");
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "16".to_owned(),
            history: BTreeMap::new(),
        }
        .save_keyed(
            &src_s,
            Path::new(&format!("archive/{STANZA}/archive.info")),
            Some(repo2_pass),
            Some(sub_key),
        )
        .expect("save encrypted archive.info");

        // A stored (already repo-encrypted) WAL object; repo-sync copies its bytes
        // verbatim, so the body need not be valid ciphertext for this test.
        put_segment(&src_s, SEGMENT, WAL_BODY);

        let cfg = encrypted_config(repo1_pass, repo2_pass);
        // src_index = 2 → the active --repo=2; archive.info must load under repo2's
        // pass. Passing 1 here would decrypt with repo1's pass and error.
        let outcome = sync_archive_to_repo(&cfg, STANZA, &src_s, 2, &dst_s).expect("sync must resolve under repo2's pass");

        assert_eq!(outcome.items, 1);
        assert_eq!(outcome.bytes, WAL_BODY.len() as u64);
        assert_eq!(read_segment(&dst_s, SEGMENT).as_deref(), Some(WAL_BODY));
    }
}
