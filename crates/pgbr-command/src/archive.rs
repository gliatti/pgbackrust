//! Archive commands: `archive-get`, `archive-push`.
//!
//! C reference: `src/command/archive/get/get.c` and
//! `src/command/archive/push/push.c`.
//!
//! A WAL segment is copied between the `PostgreSQL` data directory and the
//! repository through the [`Storage`] trait. When `--compress-type` is set to
//! a codec (`gz`/`bz2`/`lz4`/`zst`), `archive-push` runs the segment through
//! the matching compress filter and stores it with the codec's file
//! extension (`archive/<stanza>/<segment>.gz`, …); `compress-type=none`
//! keeps the raw, suffix-less copy. `archive-get` probes the repository for
//! the plaintext segment first, then for each compression suffix, and runs
//! the matching decompress filter so a WAL archived compressed is recovered
//! regardless of the client's current `compress-type` — matching pgBackRest,
//! which names archived WAL with the compression extension.
//!
//! Encryption (`--cipher-pass`) is **not** applied here — that filter wiring
//! lands in a follow-up. The archive-id subdirectory scheme the C version
//! derives from the PG version + system id is likewise simplified to a flat
//! `archive/<stanza>/<segment>` layout for now.

use std::path::{Path, PathBuf};

use pgbr_compress::{Bz2Compress, Bz2Decompress, GzCompress, GzDecompress, Lz4Compress, Lz4Decompress, ZstCompress, ZstDecompress};
use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_io::Filter;
use pgbr_storage::Storage;

use crate::CommandError;

/// File extensions for stored WAL, in the order `archive-get` probes them
/// once the plaintext form is found absent. Each maps to the compress codec
/// that produced it. `pgbackrest` names archived WAL with the codec's
/// extension, so a recovering client must try every suffix.
const COMPRESS_SUFFIXES: &[&str] = &[".gz", ".zst", ".bz2", ".lz4"];

/// Resolve the `compress-type` option to its file-name suffix. Returns
/// `""` for `none` (or when the option is unset), and `.gz`/`.bz2`/`.lz4`/
/// `.zst` for the codecs.
fn compress_suffix(config: &LoadedConfig) -> &'static str {
    match compress_type(config) {
        "gz" => ".gz",
        "bz2" => ".bz2",
        "lz4" => ".lz4",
        "zst" => ".zst",
        _ => "",
    }
}

/// Read the `compress-type` `StringId`, defaulting to `"none"` when unset or
/// not a `StringId`.
fn compress_type(config: &LoadedConfig) -> &str {
    match config.options.get(&("compress-type".to_owned(), None)) {
        Some(OptionValue::StringId(value)) => value.as_str(),
        _ => "none",
    }
}

/// Read the `compress-level` integer, clamped to `i32` range. When unset, a
/// per-codec default mirroring the C tree's `compressLevelDefault` is used.
fn compress_level(config: &LoadedConfig, codec: &str) -> i32 {
    match config.options.get(&("compress-level".to_owned(), None)) {
        Some(OptionValue::Integer(level)) => i32::try_from(*level).unwrap_or_else(|_| default_level(codec)),
        _ => default_level(codec),
    }
}

/// Default compression level per codec (matches `compressLevelDefault` in
/// `src/common/compress/helper.c`).
const fn default_level(codec: &str) -> i32 {
    match codec.as_bytes() {
        b"gz" | b"zst" => 3,
        b"lz4" => 1,
        b"bz2" => 9,
        _ => 0,
    }
}

/// Build the compress [`Filter`] for the configured `compress-type`, or
/// `None` when compression is disabled (`none`).
fn compress_filter_for(config: &LoadedConfig) -> Option<Box<dyn Filter>> {
    let codec = compress_type(config);
    let level = compress_level(config, codec);
    match codec {
        "gz" => Some(Box::new(GzCompress::new(level, false))),
        "bz2" => Some(Box::new(Bz2Compress::new(level))),
        "lz4" => Some(Box::new(Lz4Compress::new(level, false))),
        "zst" => Some(Box::new(ZstCompress::new(level))),
        _ => None,
    }
}

/// Build the decompress [`Filter`] matching a stored WAL file `suffix`
/// (`.gz`/`.bz2`/`.lz4`/`.zst`), or `None` for the plaintext (no-suffix)
/// case.
fn decompress_filter_for(suffix: &str) -> Option<Box<dyn Filter>> {
    match suffix {
        ".gz" => Some(Box::new(GzDecompress::new(false))),
        ".bz2" => Some(Box::new(Bz2Decompress::new())),
        ".lz4" => Some(Box::new(Lz4Decompress::new())),
        ".zst" => Some(Box::new(ZstDecompress::new())),
        _ => None,
    }
}

/// Run `bytes` through `filter` (process + finish) and return the transformed
/// output.
fn run_filter(filter: &mut dyn Filter, bytes: &[u8]) -> Result<Vec<u8>, CommandError> {
    let mut out = Vec::new();
    filter.process(bytes, &mut out)?;
    filter.finish(&mut out)?;
    Ok(out)
}

/// Write `bytes` to `dst_path` in `dst`, creating the destination's parent
/// directory first and flushing/closing the writer so the file is durable.
fn write_segment(bytes: &[u8], dst: &dyn Storage, dst_path: &Path) -> Result<(), CommandError> {
    if let Some(parent) = dst_path.parent() {
        dst.create_path(parent, true)?;
    }

    let mut writer = dst.open_write(dst_path)?;
    writer.write(bytes)?;
    writer.flush()?;
    writer.close()?;
    Ok(())
}

/// Build the repository-relative path for a WAL `segment` under `stanza`.
///
/// Flat layout `archive/<stanza>/<segment>` — the version + system-id
/// archive-id directory used by the C implementation is deferred.
fn repo_segment_path(stanza: &str, segment: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/{segment}"))
}

/// Read every byte of `src_path` from `src` storage.
fn read_segment(src: &dyn Storage, src_path: &Path) -> Result<Vec<u8>, CommandError> {
    let mut reader = src.open_read(src_path)?;
    Ok(reader.read_all()?)
}

/// `archive-push` — copy a completed WAL segment from the PG data directory
/// into the repository at `archive/<stanza>/<segment><suffix>`.
///
/// `config.params[0]` is the WAL source path (relative to the PG data dir,
/// resolved against `pg_storage`); the segment basename is taken from it.
/// When `compress-type` names a codec the segment is run through the matching
/// compress filter and stored with the codec's extension (`.gz`/`.bz2`/
/// `.lz4`/`.zst`); `compress-type=none` stores the raw bytes with no suffix.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] with `"stanza"` if `config.stanza` is
///   `None`, or `"<wal-source>"` if no positional source path was supplied.
/// - [`CommandError::Other`] if the source path has no file-name component.
/// - [`CommandError::Io`] if the configured compress filter fails.
/// - [`CommandError::Storage`] / [`CommandError::Io`] if the read from PG or
///   the write into the repository fails.
pub fn push(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;
    let wal_source = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<wal-source>".to_owned(),
    })?;

    let segment = Path::new(wal_source)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CommandError::Other(format!("invalid wal source path {wal_source}")))?;

    let bytes = read_segment(pg_storage, Path::new(wal_source))?;
    let stored = match compress_filter_for(config) {
        Some(mut filter) => run_filter(filter.as_mut(), &bytes)?,
        None => bytes,
    };

    let dest = repo_segment_path(stanza, &format!("{segment}{}", compress_suffix(config)));
    write_segment(&stored, repo_storage, &dest)
}

/// `archive-get` — copy a WAL segment from the repository back into the PG
/// data directory, transparently decompressing it.
///
/// `config.params[0]` is the segment name; `config.params[1]` is the
/// destination path (relative to the PG data dir, resolved against
/// `pg_storage`).
///
/// The stored form is discovered by probing: the plaintext
/// `archive/<stanza>/<segment>` is preferred, then each compression suffix
/// (`.gz`, `.zst`, `.bz2`, `.lz4`) is tried via [`Storage::exists`]. When a
/// compressed form is found it is run through the matching decompress filter
/// before the plaintext WAL is written to PG — so a WAL archived compressed
/// is recovered regardless of the client's current `compress-type`.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] with `"stanza"` if `config.stanza` is
///   `None`, `"<wal-segment>"` if no segment name was supplied, or
///   `"<destination>"` if no destination path was supplied.
/// - [`CommandError::Io`] if a matched compressed form fails to decompress.
/// - [`CommandError::Storage`] / [`CommandError::Io`] if no stored form is
///   found (surfaces as [`pgbr_storage::StorageError::NotFound`] on the
///   plaintext path) or the write into PG fails.
pub fn get(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;
    let segment = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<wal-segment>".to_owned(),
    })?;
    let dest = config.params.get(1).ok_or_else(|| CommandError::MissingOption {
        option: "<destination>".to_owned(),
    })?;

    // Prefer the plaintext form; fall back to each compression suffix. When
    // nothing is found, fall back to the plaintext path so the caller gets
    // the canonical `NotFound` error for the requested segment.
    let plaintext = repo_segment_path(stanza, segment);
    let (source, suffix) = if repo_storage.exists(&plaintext)? {
        (plaintext, "")
    } else {
        let mut found = None;
        for suffix in COMPRESS_SUFFIXES {
            let candidate = repo_segment_path(stanza, &format!("{segment}{suffix}"));
            if repo_storage.exists(&candidate)? {
                found = Some((candidate, *suffix));
                break;
            }
        }
        found.unwrap_or((plaintext, ""))
    };

    let stored = read_segment(repo_storage, &source)?;
    let bytes = match decompress_filter_for(suffix) {
        Some(mut filter) => run_filter(filter.as_mut(), &stored)?,
        None => stored,
    };

    write_segment(&bytes, pg_storage, Path::new(dest))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_compress::{GzCompress, ZstCompress};
    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_io::Filter;
    use pgbr_storage::{Posix, Storage};
    use tempfile::TempDir;

    use super::{CommandError, get, push};

    const SEGMENT: &str = "000000010000000000000001";
    const WAL_BODY: &[u8] = b"fake-wal-segment-contents";

    fn fake_config(stanza: Option<&str>, params: Vec<String>) -> LoadedConfig {
        LoadedConfig {
            command: "archive-push".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options: BTreeMap::new(),
            params,
        }
    }

    /// `fake_config` plus a `compress-type` `StringId` option.
    fn fake_config_compress(stanza: Option<&str>, params: Vec<String>, compress_type: &str) -> LoadedConfig {
        let mut cfg = fake_config(stanza, params);
        cfg.options.insert(
            ("compress-type".to_owned(), None),
            OptionValue::StringId(compress_type.to_owned()),
        );
        cfg
    }

    /// Run `bytes` through `filter` (process + finish) and return the output.
    fn run<F: Filter>(mut filter: F, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        filter.process(bytes, &mut out).expect("process");
        filter.finish(&mut out).expect("finish");
        out
    }

    fn posix_pair() -> (TempDir, TempDir, Posix, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_storage = Posix::new(repo.path());
        let pg_storage = Posix::new(pg.path());
        (repo, pg, repo_storage, pg_storage)
    }

    /// Write `bytes` to `path` inside `storage`, creating parents as needed.
    fn put(storage: &Posix, path: &str, bytes: &[u8]) {
        let p = Path::new(path);
        if let Some(parent) = p.parent() {
            storage.create_path(parent, true).expect("create parent");
        }
        let mut w = storage.open_write(p).expect("open_write");
        w.write(bytes).expect("write");
        w.close().expect("close");
    }

    /// Read every byte of `path` inside `storage`.
    fn read(storage: &Posix, path: &str) -> Vec<u8> {
        let mut r = storage.open_read(Path::new(path)).expect("open_read");
        r.read_all().expect("read_all")
    }

    #[test]
    fn archive_push_copies_wal_into_repo() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let cfg = fake_config(Some("demo"), vec![wal_source]);
        push(&cfg, &repo_s, &pg_s).expect("push should succeed");

        let dest = format!("archive/demo/{SEGMENT}");
        assert!(
            repo_s.exists(Path::new(&dest)).expect("exists"),
            "segment should land in repo"
        );
        assert_eq!(read(&repo_s, &dest), WAL_BODY, "repo copy should match source bytes");
    }

    #[test]
    fn archive_push_missing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let cfg = fake_config(None, vec![format!("pg_wal/{SEGMENT}")]);
        let err = push(&cfg, &repo_s, &pg_s).expect_err("push must require a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption(stanza), got {other:?}"),
        }
    }

    #[test]
    fn archive_push_missing_param_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let cfg = fake_config(Some("demo"), Vec::new());
        let err = push(&cfg, &repo_s, &pg_s).expect_err("push must require a wal source");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "<wal-source>"),
            other => panic!("expected MissingOption(<wal-source>), got {other:?}"),
        }
    }

    #[test]
    fn archive_get_copies_segment_back_to_pg() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        put(&repo_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()]);
        get(&cfg, &repo_s, &pg_s).expect("get should succeed");

        assert!(pg_s.exists(Path::new(&dest)).expect("exists"), "segment should land in pg");
        assert_eq!(read(&pg_s, &dest), WAL_BODY, "pg copy should match repo bytes");
    }

    #[test]
    fn archive_get_unknown_segment_errors_with_storage() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), format!("pg_wal/{SEGMENT}")]);
        let err = get(&cfg, &repo_s, &pg_s).expect_err("get of an absent segment must fail");
        match err {
            CommandError::Storage(_) => {}
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn archive_push_none_is_raw() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        // Explicit `compress-type=none` must store the segment unchanged with
        // no suffix, exactly like the implicit-default path.
        let cfg = fake_config_compress(Some("demo"), vec![wal_source], "none");
        push(&cfg, &repo_s, &pg_s).expect("push should succeed");

        let dest = format!("archive/demo/{SEGMENT}");
        assert!(
            repo_s.exists(Path::new(&dest)).expect("exists"),
            "raw segment should land in repo"
        );
        assert!(
            !repo_s.exists(Path::new(&format!("{dest}.gz"))).expect("exists"),
            "no compressed copy should exist for compress-type=none"
        );
        assert_eq!(read(&repo_s, &dest), WAL_BODY, "repo copy should match source bytes");
    }

    #[test]
    fn archive_push_gz_stores_compressed_with_suffix() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let cfg = fake_config_compress(Some("demo"), vec![wal_source], "gz");
        push(&cfg, &repo_s, &pg_s).expect("push should succeed");

        let dest = format!("archive/demo/{SEGMENT}.gz");
        assert!(
            repo_s.exists(Path::new(&dest)).expect("exists"),
            "gz segment should land in repo with .gz suffix"
        );
        assert!(
            !repo_s.exists(Path::new(&format!("archive/demo/{SEGMENT}"))).expect("exists"),
            "no plaintext copy should exist for compress-type=gz"
        );
        let stored = read(&repo_s, &dest);
        assert_ne!(stored, WAL_BODY, "stored bytes should differ from the plaintext");
        // The stored bytes must be the gz frame of the plaintext.
        let expected = run(GzCompress::new(super::default_level("gz"), false), WAL_BODY);
        assert_eq!(stored, expected, "stored bytes should be the gz-compressed WAL");
    }

    #[test]
    fn archive_push_then_get_gz_round_trip() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let push_cfg = fake_config_compress(Some("demo"), vec![wal_source], "gz");
        push(&push_cfg, &repo_s, &pg_s).expect("push should succeed");

        // Recover into a fresh PG target; compress-type on get is irrelevant
        // (the stored form is discovered by probing).
        let dest = "pg_wal/recovered".to_owned();
        let get_cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()]);
        get(&get_cfg, &repo_s, &pg_s).expect("get should succeed");

        assert!(
            pg_s.exists(Path::new(&dest)).expect("exists"),
            "recovered segment should land in pg"
        );
        assert_eq!(read(&pg_s, &dest), WAL_BODY, "recovered WAL should equal the original");
    }

    #[test]
    fn archive_get_finds_compressed_when_plaintext_absent() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();

        // Pre-place only the `.zst` form in the repo.
        let compressed = run(ZstCompress::new(super::default_level("zst")), WAL_BODY);
        put(&repo_s, &format!("archive/demo/{SEGMENT}.zst"), &compressed);

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()]);
        get(&cfg, &repo_s, &pg_s).expect("get should find and decompress the .zst form");

        assert!(pg_s.exists(Path::new(&dest)).expect("exists"), "segment should land in pg");
        assert_eq!(read(&pg_s, &dest), WAL_BODY, "recovered WAL should equal the plaintext");
    }

    #[test]
    fn archive_get_prefers_plaintext_when_present() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();

        // Both forms exist: the plaintext holds the real bytes; the `.gz`
        // form holds an unrelated payload so we can detect mis-selection.
        put(&repo_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);
        let decoy = run(
            GzCompress::new(super::default_level("gz"), false),
            b"this is the wrong payload",
        );
        put(&repo_s, &format!("archive/demo/{SEGMENT}.gz"), &decoy);

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()]);
        get(&cfg, &repo_s, &pg_s).expect("get should succeed");

        assert_eq!(read(&pg_s, &dest), WAL_BODY, "plaintext form should be used when both exist");
    }
}
