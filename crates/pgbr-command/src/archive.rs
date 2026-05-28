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
//!
//! ## Multiple repositories
//!
//! pgBackRest copies every WAL segment into **every** configured repository: a
//! segment is only "archived" once it is present on all of them. [`push`] takes
//! a slice of repository [`Storage`] backends (one per configured repo, built by
//! the CLI's `build_all_repo_storages`) and fans the copy out to each — if any
//! repository write fails the whole command fails (the segment is not safely
//! archived). [`get`] is the dual: it tries each repository in order and serves
//! the segment from the first that has it. C ref:
//! `src/command/archive/push/push.c` (`archivePushFile` over `repoIdxList`) and
//! `src/command/archive/get/get.c`.
//!
//! ## Asynchronous (spool) mode (`--archive-async`)
//!
//! With `--archive-async` the foreground `archive-push` does not push the WAL
//! segment to the repository synchronously. Instead it stages the segment in
//! the spool *out* directory (`<spool-path>/archive/<stanza>/out/`) and a
//! background process drains the spool into the repository, recording a
//! `<segment>.ok` (or `<segment>.error` carrying the failure message) status
//! file that the *next* foreground invocation consumes. `archive-get` async
//! pre-fetches upcoming segments into the spool *in* directory
//! (`<spool-path>/archive/<stanza>/in/`) so a later foreground call can serve
//! them without a repository round-trip.
//!
//! The drain ([`drain_push_spool`]) and pre-fetch ([`prefetch_get_spool`])
//! steps are exposed as ordinary functions so tests (and a future protocol
//! handler) can drive them synchronously without spawning a real background
//! process. The spool path layout is factored into pure helpers
//! ([`push_out_dir`], [`get_in_dir`], [`status_ok_path`], [`status_error_path`])
//! that mirror the C `STORAGE_SPOOL_ARCHIVE_{OUT,IN}` expressions and the
//! `.ok` / `.error` status extensions in `src/command/archive/common.h`.
//! Synchronous mode (no `--archive-async`) is unchanged.

use std::path::{Path, PathBuf};

use pgbr_compress::{Bz2Compress, Bz2Decompress, GzCompress, GzDecompress, Lz4Compress, Lz4Decompress, ZstCompress, ZstDecompress};
use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_io::Filter;
use pgbr_storage::{Posix, Storage};

use crate::CommandError;
use crate::backup::acquire_command_lock;

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

/// Status-file extension written for a segment that drained successfully.
/// Matches `STATUS_EXT_OK` in `src/command/archive/common.h`.
const STATUS_EXT_OK: &str = ".ok";

/// Status-file extension written for a segment whose drain failed; the file's
/// body carries the failure message. Matches `STATUS_EXT_ERROR`.
const STATUS_EXT_ERROR: &str = ".error";

/// Whether `--archive-async` is enabled in the resolved configuration.
/// Defaults to `false` (synchronous) when unset.
fn archive_async(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("archive-async".to_owned(), None)),
        Some(OptionValue::Boolean(true))
    )
}

/// Read the resolved `spool-path` (a [`OptionValue::Path`]), or `None` when
/// unset. The path roots the local spool storage used in async mode.
fn spool_path(config: &LoadedConfig) -> Option<&str> {
    match config.options.get(&("spool-path".to_owned(), None)) {
        Some(OptionValue::Path(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Spool *out* directory for `archive-push` async staging:
/// `archive/<stanza>/out` (relative to the spool storage root). Mirrors the
/// C `STORAGE_SPOOL_ARCHIVE_OUT` expression.
fn push_out_dir(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/out"))
}

/// Spool *in* directory for `archive-get` async pre-fetch:
/// `archive/<stanza>/in` (relative to the spool storage root). Mirrors the
/// C `STORAGE_SPOOL_ARCHIVE_IN` expression.
fn get_in_dir(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/in"))
}

/// Path of the success status file for `segment` in the push *out* spool:
/// `archive/<stanza>/out/<segment>.ok`.
fn status_ok_path(stanza: &str, segment: &str) -> PathBuf {
    push_out_dir(stanza).join(format!("{segment}{STATUS_EXT_OK}"))
}

/// Path of the failure status file for `segment` in the push *out* spool:
/// `archive/<stanza>/out/<segment>.error`. The file body holds the message.
fn status_error_path(stanza: &str, segment: &str) -> PathBuf {
    push_out_dir(stanza).join(format!("{segment}{STATUS_EXT_ERROR}"))
}

/// `archive-push` — copy a completed WAL segment from the PG data directory
/// into **every** configured repository at `archive/<stanza>/<segment><suffix>`.
///
/// `config.params[0]` is the WAL source path (relative to the PG data dir,
/// resolved against `pg_storage`); the segment basename is taken from it.
/// When `compress-type` names a codec the segment is run through the matching
/// compress filter and stored with the codec's extension (`.gz`/`.bz2`/
/// `.lz4`/`.zst`); `compress-type=none` stores the raw bytes with no suffix.
///
/// `repo_storages` is the list of repository backends — one per configured
/// repository. The segment is read from PG and compressed once, then written
/// to each repository in turn; the segment is only considered archived when it
/// has reached all of them, so the first per-repository write failure fails the
/// whole command. At least one repository must be supplied.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] with `"stanza"` if `config.stanza` is
///   `None`, or `"<wal-source>"` if no positional source path was supplied.
/// - [`CommandError::Other`] if the source path has no file-name component or
///   `repo_storages` is empty.
/// - [`CommandError::Io`] if the configured compress filter fails.
/// - [`CommandError::Storage`] / [`CommandError::Io`] if the read from PG or a
///   write into any repository fails.
pub fn push(config: &LoadedConfig, repo_storages: &[&dyn Storage], pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;
    if repo_storages.is_empty() {
        return Err(CommandError::Other(
            "archive-push requires at least one repository".to_owned(),
        ));
    }
    // Hold the archive lock for the whole command. C ref: lockAcquire(lockTypeArchive).
    let _locks = acquire_command_lock(config, LockType::Archive)?;
    let wal_source = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<wal-source>".to_owned(),
    })?;

    let segment = Path::new(wal_source)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CommandError::Other(format!("invalid wal source path {wal_source}")))?;

    // Asynchronous mode: stage the segment in the spool out/ directory and let
    // the background drain move it to the repository. Before staging, consume
    // any status file the drain left for this segment from the previous call.
    // The spool stages a single plaintext copy regardless of repo count; the
    // background drain fans it out (a future protocol handler runs the drain).
    if archive_async(config) {
        let spool_root = spool_path(config).ok_or_else(|| CommandError::MissingOption {
            option: "spool-path".to_owned(),
        })?;
        let spool = Posix::new(spool_root);
        return push_async(pg_storage, &spool, stanza, segment, Path::new(wal_source));
    }

    let bytes = read_segment(pg_storage, Path::new(wal_source))?;
    let stored = match compress_filter_for(config) {
        Some(mut filter) => run_filter(filter.as_mut(), &bytes)?,
        None => bytes,
    };

    // Fan the (single, already-compressed) copy out to every repository. The
    // segment is only archived once it has reached all of them.
    let dest = repo_segment_path(stanza, &format!("{segment}{}", compress_suffix(config)));
    for repo in repo_storages {
        write_segment(&stored, *repo, &dest)?;
    }
    Ok(())
}

/// Foreground half of asynchronous `archive-push`.
///
/// First [`consume_push_status`] checks for a `<segment>.ok` / `<segment>.error`
/// status the previous drain wrote for this segment: an `.ok` is removed and
/// the call returns success immediately (the segment is already in the repo);
/// an `.error` is removed and its recorded message is surfaced as an error.
/// When no status is present the raw segment is staged into the spool *out*
/// directory (`archive/<stanza>/out/<segment>`) for the background drain to
/// pick up. Staging copies the plaintext WAL — compression happens during the
/// drain, matching pgBackRest (the async client never compresses).
fn push_async(
    pg_storage: &dyn Storage,
    spool: &dyn Storage,
    stanza: &str,
    segment: &str,
    wal_source: &Path,
) -> Result<(), CommandError> {
    if let Some(outcome) = consume_push_status(spool, stanza, segment)? {
        return outcome;
    }

    // Not yet processed by the drain — stage the raw segment in out/ for the
    // background drain to pick up.
    let bytes = read_segment(pg_storage, wal_source)?;
    let staged = push_out_dir(stanza).join(segment);
    write_segment(&bytes, spool, &staged)
}

/// Inspect the spool *out* directory for a prior drain status of `segment`.
///
/// Returns `Ok(None)` when neither a `.ok` nor `.error` status exists (the
/// caller should stage the segment). Returns `Ok(Some(Ok(())))` after removing
/// a `.ok` status (the segment was already drained to the repo). Returns
/// `Ok(Some(Err(..)))` after removing a `.error` status, carrying the message
/// the drain recorded.
fn consume_push_status(spool: &dyn Storage, stanza: &str, segment: &str) -> Result<Option<Result<(), CommandError>>, CommandError> {
    let ok_path = status_ok_path(stanza, segment);
    if spool.exists(&ok_path)? {
        spool.remove(&ok_path, false)?;
        return Ok(Some(Ok(())));
    }

    let error_path = status_error_path(stanza, segment);
    if spool.exists(&error_path)? {
        let message = String::from_utf8_lossy(&read_segment(spool, &error_path)?).into_owned();
        spool.remove(&error_path, false)?;
        return Ok(Some(Err(CommandError::Other(format!(
            "prior async archive-push of {segment} failed: {message}"
        )))));
    }

    Ok(None)
}

/// Drain the spool *out* directory into the repository.
///
/// This is the background half of asynchronous `archive-push`, exposed as a
/// plain function so tests (and a future protocol handler) can run it
/// synchronously. Every staged WAL segment under `archive/<stanza>/out/`
/// (status files — `.ok` / `.error` — are skipped) is run through the
/// `transform` factory (a fresh compress [`Filter`] per segment, or `None` to
/// store raw) and written to the repository at
/// `archive/<stanza>/<segment><suffix>`. On success the staged copy is removed
/// and a `<segment>.ok` status is written; on failure a `<segment>.error`
/// status carrying the message is written and the staged copy is left in place
/// for a retry. The returned count is the number of segments drained
/// successfully.
///
/// # Errors
///
/// - [`CommandError::Storage`] / [`CommandError::Io`] if listing the spool or
///   writing a status file itself fails (per-segment transfer failures are
///   recorded as `.error` status, not returned).
pub fn drain_push_spool(
    spool: &dyn Storage,
    repo_storage: &dyn Storage,
    stanza: &str,
    suffix: &str,
    transform: &dyn Fn() -> Option<Box<dyn Filter>>,
) -> Result<usize, CommandError> {
    let out_dir = push_out_dir(stanza);
    if !spool.exists(&out_dir)? {
        return Ok(0);
    }

    let mut drained = 0;
    for entry in spool.list(&out_dir)? {
        let Some(segment) = entry.path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        // Skip status files left by earlier drains.
        if segment.ends_with(STATUS_EXT_OK) || segment.ends_with(STATUS_EXT_ERROR) {
            continue;
        }
        let segment = segment.to_owned();
        let staged = out_dir.join(&segment);

        match drain_one(spool, repo_storage, stanza, &segment, suffix, &staged, transform) {
            Ok(()) => {
                spool.remove(&staged, false)?;
                write_segment(b"", spool, &status_ok_path(stanza, &segment))?;
                drained += 1;
            }
            Err(err) => {
                write_segment(err.to_string().as_bytes(), spool, &status_error_path(stanza, &segment))?;
            }
        }
    }

    Ok(drained)
}

/// Transfer a single staged segment to the repository, applying the compress
/// `transform`. Used by [`drain_push_spool`]; a returned error becomes a
/// `.error` status.
fn drain_one(
    spool: &dyn Storage,
    repo_storage: &dyn Storage,
    stanza: &str,
    segment: &str,
    suffix: &str,
    staged: &Path,
    transform: &dyn Fn() -> Option<Box<dyn Filter>>,
) -> Result<(), CommandError> {
    let bytes = read_segment(spool, staged)?;
    let stored = match transform() {
        Some(mut filter) => run_filter(filter.as_mut(), &bytes)?,
        None => bytes,
    };
    let dest = repo_segment_path(stanza, &format!("{segment}{suffix}"));
    write_segment(&stored, repo_storage, &dest)
}

/// `archive-get` — copy a WAL segment from a repository back into the PG
/// data directory, transparently decompressing it.
///
/// `config.params[0]` is the segment name; `config.params[1]` is the
/// destination path (relative to the PG data dir, resolved against
/// `pg_storage`).
///
/// `repo_storages` is the list of repository backends — one per configured
/// repository. The repositories are tried in order and the segment is served
/// from the first that has it (a segment archived to all repositories may only
/// have reached some of them after a partial failure). Within each repository
/// the stored form is discovered by probing: the plaintext
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
/// - [`CommandError::Other`] if `repo_storages` is empty.
/// - [`CommandError::Io`] if a matched compressed form fails to decompress.
/// - [`CommandError::Storage`] / [`CommandError::Io`] if no repository holds the
///   segment (surfaces as [`pgbr_storage::StorageError::NotFound`] on the last
///   repository's plaintext path) or the write into PG fails.
pub fn get(config: &LoadedConfig, repo_storages: &[&dyn Storage], pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;
    if repo_storages.is_empty() {
        return Err(CommandError::Other("archive-get requires at least one repository".to_owned()));
    }
    // Hold the archive lock for the whole command. C ref: lockAcquire(lockTypeArchive).
    let _locks = acquire_command_lock(config, LockType::Archive)?;
    let segment = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<wal-segment>".to_owned(),
    })?;
    let dest = config.params.get(1).ok_or_else(|| CommandError::MissingOption {
        option: "<destination>".to_owned(),
    })?;

    // Asynchronous mode: a previous pre-fetch may have staged this segment in
    // the spool in/ directory. Serve it from there if present, consuming the
    // staged copy; otherwise fall through to a synchronous repository fetch.
    if archive_async(config) {
        let spool_root = spool_path(config).ok_or_else(|| CommandError::MissingOption {
            option: "spool-path".to_owned(),
        })?;
        let spool = Posix::new(spool_root);
        if serve_from_spool(&spool, pg_storage, stanza, segment, Path::new(dest))? {
            return Ok(());
        }
    }

    // Try each repository in order; serve from the first that has the segment.
    // Only the final repository's NotFound surfaces (the canonical "no archive"
    // error); earlier NotFounds just advance to the next repository.
    let last = repo_storages.len() - 1;
    for (idx, repo) in repo_storages.iter().enumerate() {
        if idx == last || repo_has_segment(*repo, stanza, segment)? {
            return fetch_from_repo(*repo, pg_storage, stanza, segment, Path::new(dest));
        }
    }
    // Unreachable: the loop always returns on the last repository, but keep a
    // defensive error so the function is total.
    Err(CommandError::Other("archive-get found no repository to read from".to_owned()))
}

/// Whether `repo` holds `segment` for `stanza` in any stored form (plaintext or
/// a compressed suffix). Used by [`get`] to pick the first repository that has
/// the segment.
fn repo_has_segment(repo: &dyn Storage, stanza: &str, segment: &str) -> Result<bool, CommandError> {
    if repo.exists(&repo_segment_path(stanza, segment))? {
        return Ok(true);
    }
    for suffix in COMPRESS_SUFFIXES {
        if repo.exists(&repo_segment_path(stanza, &format!("{segment}{suffix}")))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Synchronous repository fetch of `segment` into `dest` on `pg_storage`.
///
/// The stored form is discovered by probing: the plaintext
/// `archive/<stanza>/<segment>` is preferred, then each compression suffix is
/// tried via [`Storage::exists`]; a matched compressed form is decompressed
/// before the plaintext WAL is written. When nothing is found the plaintext
/// path is read so the caller gets the canonical `NotFound` error.
fn fetch_from_repo(
    repo_storage: &dyn Storage,
    pg_storage: &dyn Storage,
    stanza: &str,
    segment: &str,
    dest: &Path,
) -> Result<(), CommandError> {
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

    write_segment(&bytes, pg_storage, dest)
}

/// Serve `segment` from the spool *in* directory if it was pre-fetched.
///
/// Returns `Ok(true)` when `archive/<stanza>/in/<segment>` exists: its
/// (already-plaintext) bytes are written to `dest` and the staged copy is
/// removed. Returns `Ok(false)` when the segment was not pre-fetched, so the
/// caller falls back to a synchronous repository fetch.
fn serve_from_spool(
    spool: &dyn Storage,
    pg_storage: &dyn Storage,
    stanza: &str,
    segment: &str,
    dest: &Path,
) -> Result<bool, CommandError> {
    let staged = get_in_dir(stanza).join(segment);
    if !spool.exists(&staged)? {
        return Ok(false);
    }

    let bytes = read_segment(spool, &staged)?;
    write_segment(&bytes, pg_storage, dest)?;
    spool.remove(&staged, false)?;
    Ok(true)
}

/// Pre-fetch `segments` from the repository into the spool *in* directory.
///
/// This is the background half of asynchronous `archive-get`, exposed as a
/// plain function so tests (and a future protocol handler) can run it
/// synchronously. Each requested segment is fetched from the repository
/// (probing the plaintext and compressed forms exactly like [`fetch_from_repo`]
/// via [`decompress_filter_for`]) and written, decompressed, to
/// `archive/<stanza>/in/<segment>` so a later foreground [`get`] serves it
/// without a repository round-trip. Segments absent from the repository are
/// skipped (a future segment may not be archived yet). The returned count is
/// the number of segments pre-fetched.
///
/// # Errors
///
/// - [`CommandError::Io`] if a matched compressed form fails to decompress.
/// - [`CommandError::Storage`] / [`CommandError::Io`] if a repository read or
///   the write into the spool fails.
pub fn prefetch_get_spool(
    spool: &dyn Storage,
    repo_storage: &dyn Storage,
    stanza: &str,
    segments: &[String],
) -> Result<usize, CommandError> {
    let mut prefetched = 0;
    for segment in segments {
        // Probe the stored form; skip segments not yet in the repository.
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
            match found {
                Some(pair) => pair,
                None => continue,
            }
        };

        let stored = read_segment(repo_storage, &source)?;
        let bytes = match decompress_filter_for(suffix) {
            Some(mut filter) => run_filter(filter.as_mut(), &stored)?,
            None => stored,
        };
        write_segment(&bytes, spool, &get_in_dir(stanza).join(segment))?;
        prefetched += 1;
    }

    Ok(prefetched)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_compress::{GzCompress, ZstCompress};
    use pgbr_config::{ConfigCommandRole, LoadedConfig, LockType, OptionValue};
    use pgbr_io::Filter;
    use pgbr_storage::{Posix, Storage};
    use tempfile::TempDir;

    use super::{
        CommandError, drain_push_spool, get, get_in_dir, prefetch_get_spool, push, push_out_dir, status_error_path, status_ok_path,
    };

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

    /// `fake_config` plus `archive-async=true` and a `spool-path` pointing at
    /// `spool` (a tempdir root). Drives the async push/get foreground paths.
    fn fake_config_async(stanza: Option<&str>, params: Vec<String>, spool: &Path) -> LoadedConfig {
        let mut cfg = fake_config(stanza, params);
        cfg.options
            .insert(("archive-async".to_owned(), None), OptionValue::Boolean(true));
        cfg.options.insert(
            ("spool-path".to_owned(), None),
            OptionValue::Path(spool.to_string_lossy().into_owned()),
        );
        cfg
    }

    /// A spool tempdir plus a `Posix` rooted at it, mirroring the storage the
    /// async push/get build internally from `spool-path`.
    fn spool_storage() -> (TempDir, Posix) {
        let spool = tempfile::tempdir().expect("spool tempdir");
        let storage = Posix::new(spool.path());
        (spool, storage)
    }

    /// No-op transform factory (store raw) for [`drain_push_spool`].
    fn no_transform() -> Option<Box<dyn Filter>> {
        None
    }

    #[test]
    fn archive_push_copies_wal_into_repo() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let cfg = fake_config(Some("demo"), vec![wal_source]);
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("push should succeed");

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
        let err = push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect_err("push must require a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption(stanza), got {other:?}"),
        }
    }

    #[test]
    fn archive_push_missing_param_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let cfg = fake_config(Some("demo"), Vec::new());
        let err = push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect_err("push must require a wal source");
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
        get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("get should succeed");

        assert!(pg_s.exists(Path::new(&dest)).expect("exists"), "segment should land in pg");
        assert_eq!(read(&pg_s, &dest), WAL_BODY, "pg copy should match repo bytes");
    }

    /// `fake_config` plus an explicit `lock-path` so the command takes a real
    /// archive lock under an isolated directory.
    fn fake_config_locked(stanza: Option<&str>, params: Vec<String>, lock_path: &Path) -> LoadedConfig {
        let mut cfg = fake_config(stanza, params);
        cfg.options.insert(
            ("lock-path".to_owned(), None),
            OptionValue::Path(lock_path.to_string_lossy().into_owned()),
        );
        cfg
    }

    #[test]
    fn archive_push_acquires_archive_lock() {
        // archive-push must take the `<stanza>-archive.lock`; a concurrent run
        // already holding it makes the push fail with "another archive".
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let cfg = fake_config_locked(Some("demo"), vec![wal_source], lock_dir.path());
        let expected_lock = lock_dir.path().join("demo-archive.lock");

        let held = crate::lock::lock_acquire(lock_dir.path(), "demo", LockType::Archive).expect("pre-acquire archive lock");
        assert!(expected_lock.exists(), "archive lock file must appear while held");

        let err = push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect_err("push must fail while the archive lock is held");
        assert!(
            err.to_string().contains("another archive is running"),
            "unexpected error: {err}"
        );

        drop(held);
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("push succeeds once the lock is free");
    }

    #[test]
    fn archive_get_acquires_archive_lock() {
        // archive-get takes the same archive lock as push.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        put(&repo_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config_locked(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()], lock_dir.path());

        let held = crate::lock::lock_acquire(lock_dir.path(), "demo", LockType::Archive).expect("pre-acquire archive lock");
        let err = get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect_err("get must fail while the archive lock is held");
        assert!(
            err.to_string().contains("another archive is running"),
            "unexpected error: {err}"
        );

        drop(held);
        get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("get succeeds once the lock is free");
        assert!(pg_s.exists(Path::new(&dest)).expect("exists"), "segment should land in pg");
    }

    #[test]
    fn archive_get_unknown_segment_errors_with_storage() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), format!("pg_wal/{SEGMENT}")]);
        let err = get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect_err("get of an absent segment must fail");
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
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("push should succeed");

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
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("push should succeed");

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
        push(&push_cfg, &[&repo_s as &dyn Storage], &pg_s).expect("push should succeed");

        // Recover into a fresh PG target; compress-type on get is irrelevant
        // (the stored form is discovered by probing).
        let dest = "pg_wal/recovered".to_owned();
        let get_cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()]);
        get(&get_cfg, &[&repo_s as &dyn Storage], &pg_s).expect("get should succeed");

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
        get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("get should find and decompress the .zst form");

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
        get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("get should succeed");

        assert_eq!(read(&pg_s, &dest), WAL_BODY, "plaintext form should be used when both exist");
    }

    // -----------------------------------------------------------------------
    // Asynchronous (spool) mode
    // -----------------------------------------------------------------------

    #[test]
    fn spool_path_layout_helpers() {
        assert_eq!(push_out_dir("demo"), Path::new("archive/demo/out"));
        assert_eq!(get_in_dir("demo"), Path::new("archive/demo/in"));
        assert_eq!(
            status_ok_path("demo", SEGMENT),
            Path::new(&format!("archive/demo/out/{SEGMENT}.ok"))
        );
        assert_eq!(
            status_error_path("demo", SEGMENT),
            Path::new(&format!("archive/demo/out/{SEGMENT}.error"))
        );
    }

    #[test]
    fn async_push_writes_to_spool_then_drains_to_repo() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let (spool, spool_s) = spool_storage();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        // Foreground async push only stages into the spool out/ dir; nothing
        // reaches the repo yet.
        let cfg = fake_config_async(Some("demo"), vec![wal_source], spool.path());
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("async push should stage to spool");

        let staged = format!("archive/demo/out/{SEGMENT}");
        assert!(
            spool_s.exists(Path::new(&staged)).expect("exists"),
            "segment should be staged in the spool out/ dir"
        );
        assert_eq!(read(&spool_s, &staged), WAL_BODY, "staged copy should match source bytes");
        assert!(
            !repo_s.exists(Path::new(&format!("archive/demo/{SEGMENT}"))).expect("exists"),
            "nothing should reach the repo before the drain runs"
        );

        // Drain the spool synchronously: the segment lands in the repo, the
        // staged copy is gone, and a .ok status is recorded.
        let drained = drain_push_spool(&spool_s, &repo_s, "demo", "", &no_transform).expect("drain should succeed");
        assert_eq!(drained, 1, "exactly one segment should drain");

        let repo_dest = format!("archive/demo/{SEGMENT}");
        assert!(
            repo_s.exists(Path::new(&repo_dest)).expect("exists"),
            "drained segment should land in the repo"
        );
        assert_eq!(read(&repo_s, &repo_dest), WAL_BODY, "repo copy should match the staged bytes");
        assert!(
            !spool_s.exists(Path::new(&staged)).expect("exists"),
            "staged copy should be removed after a successful drain"
        );
        assert!(
            spool_s
                .exists(Path::new(&format!("archive/demo/out/{SEGMENT}.ok")))
                .expect("exists"),
            "a .ok status should be recorded for the drained segment"
        );
    }

    #[test]
    fn async_push_consumes_prior_ok_status() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let (spool, spool_s) = spool_storage();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        // A prior drain left a .ok status for this segment.
        put(&spool_s, &format!("archive/demo/out/{SEGMENT}.ok"), b"");

        // The foreground push should consume the .ok and return success
        // immediately, without re-staging the segment.
        let cfg = fake_config_async(Some("demo"), vec![wal_source], spool.path());
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("async push should consume the prior .ok status");

        assert!(
            !spool_s
                .exists(Path::new(&format!("archive/demo/out/{SEGMENT}.ok")))
                .expect("exists"),
            "the consumed .ok status should be removed"
        );
        assert!(
            !spool_s
                .exists(Path::new(&format!("archive/demo/out/{SEGMENT}")))
                .expect("exists"),
            "no segment should be staged when a prior .ok status is consumed"
        );
    }

    #[test]
    fn async_push_consumes_prior_error_status() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let (spool, spool_s) = spool_storage();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        // A prior drain failed and recorded an .error status with a message.
        put(&spool_s, &format!("archive/demo/out/{SEGMENT}.error"), b"repo unreachable");

        let cfg = fake_config_async(Some("demo"), vec![wal_source], spool.path());
        let err = push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect_err("a prior .error status must surface as an error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("repo unreachable"), "message should be surfaced: {msg}"),
            other => panic!("expected Other(error message), got {other:?}"),
        }
        assert!(
            !spool_s
                .exists(Path::new(&format!("archive/demo/out/{SEGMENT}.error")))
                .expect("exists"),
            "the consumed .error status should be removed"
        );
    }

    #[test]
    fn async_get_serves_prefetched_segment_from_spool() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let (spool, spool_s) = spool_storage();

        // Pre-fetch the segment from the repo into the spool in/ dir.
        put(&repo_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);
        let prefetched = prefetch_get_spool(&spool_s, &repo_s, "demo", &[SEGMENT.to_owned()]).expect("prefetch should succeed");
        assert_eq!(prefetched, 1, "one segment should be pre-fetched");
        assert!(
            spool_s
                .exists(Path::new(&format!("archive/demo/in/{SEGMENT}")))
                .expect("exists"),
            "segment should be staged in the spool in/ dir"
        );

        // Remove the repo copy so the test fails if get falls back to the repo
        // instead of serving the pre-fetched copy.
        repo_s
            .remove(Path::new(&format!("archive/demo/{SEGMENT}")), true)
            .expect("remove");

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config_async(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()], spool.path());
        get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("async get should serve the pre-fetched segment");

        assert!(pg_s.exists(Path::new(&dest)).expect("exists"), "segment should land in pg");
        assert_eq!(read(&pg_s, &dest), WAL_BODY, "served WAL should equal the pre-fetched bytes");
        assert!(
            !spool_s
                .exists(Path::new(&format!("archive/demo/in/{SEGMENT}")))
                .expect("exists"),
            "the served segment should be removed from the spool in/ dir"
        );
    }

    #[test]
    fn async_get_falls_back_to_repo_when_not_prefetched() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let (spool, _spool_s) = spool_storage();

        // Nothing pre-fetched into the spool in/ dir; only the repo has it.
        put(&repo_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config_async(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()], spool.path());
        get(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("async get should fall back to a synchronous repo fetch");

        assert!(pg_s.exists(Path::new(&dest)).expect("exists"), "segment should land in pg");
        assert_eq!(read(&pg_s, &dest), WAL_BODY, "fetched WAL should equal the repo bytes");
    }

    #[test]
    fn async_push_drain_records_error_status_on_failure() {
        let (_spool, spool_s) = spool_storage();

        // Stage a segment, then drain into a read-only repo path so the write
        // fails and the drain records an .error status (the staged copy stays).
        put(&spool_s, &format!("archive/demo/out/{SEGMENT}"), WAL_BODY);

        // Point the repo at a path under a file (not a directory) so the
        // create_path/write fails for every segment.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let blocker = repo.path().join("archive");
        std::fs::write(&blocker, b"not a directory").expect("write blocker file");
        let repo_s = Posix::new(repo.path());

        let drained = drain_push_spool(&spool_s, &repo_s, "demo", "", &no_transform).expect("drain returns Ok overall");
        assert_eq!(drained, 0, "no segment should drain successfully");
        assert!(
            spool_s
                .exists(Path::new(&format!("archive/demo/out/{SEGMENT}.error")))
                .expect("exists"),
            "a .error status should be recorded for the failed segment"
        );
        assert!(
            spool_s
                .exists(Path::new(&format!("archive/demo/out/{SEGMENT}")))
                .expect("exists"),
            "the staged copy should remain for a retry after a failed drain"
        );
    }

    #[test]
    fn async_push_drain_compresses_with_transform() {
        let (_repo, _pg, repo_s, _pg_s) = posix_pair();
        let (_spool, spool_s) = spool_storage();

        // Stage a raw segment, then drain through a gz transform with the .gz
        // suffix — the repo copy must be the gz frame of the plaintext.
        put(&spool_s, &format!("archive/demo/out/{SEGMENT}"), WAL_BODY);
        let transform = || -> Option<Box<dyn Filter>> { Some(Box::new(GzCompress::new(super::default_level("gz"), false))) };
        let drained = drain_push_spool(&spool_s, &repo_s, "demo", ".gz", &transform).expect("drain should succeed");
        assert_eq!(drained, 1, "one segment should drain");

        let repo_dest = format!("archive/demo/{SEGMENT}.gz");
        assert!(
            repo_s.exists(Path::new(&repo_dest)).expect("exists"),
            "compressed segment should land in the repo with the .gz suffix"
        );
        let expected = run(GzCompress::new(super::default_level("gz"), false), WAL_BODY);
        assert_eq!(
            read(&repo_s, &repo_dest),
            expected,
            "repo copy should be the gz-compressed WAL"
        );
    }

    // -----------------------------------------------------------------------
    // Multiple repositories
    // -----------------------------------------------------------------------

    #[test]
    fn archive_push_fans_out_to_all_repos() {
        // A single WAL segment must reach EVERY configured repository.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());

        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let cfg = fake_config(Some("demo"), vec![wal_source]);
        push(&cfg, &[&repo1_s as &dyn Storage, &repo2_s as &dyn Storage], &pg_s).expect("multi-repo push should succeed");

        let dest = format!("archive/demo/{SEGMENT}");
        for (label, repo) in [("repo1", &repo1_s), ("repo2", &repo2_s)] {
            assert!(
                repo.exists(Path::new(&dest)).expect("exists"),
                "segment should land in {label}"
            );
            assert_eq!(read(repo, &dest), WAL_BODY, "{label} copy should match source bytes");
        }
    }

    #[test]
    fn archive_push_fails_if_any_repo_write_fails() {
        // If one repository cannot be written, the whole push fails (the segment
        // is not safely archived).
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let bad = tempfile::tempdir().expect("bad repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        // Block repo2 by placing a file where the `archive` directory must go.
        std::fs::write(bad.path().join("archive"), b"not a dir").expect("write blocker");
        let bad_s = Posix::new(bad.path());
        let pg_s = Posix::new(pg.path());

        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let cfg = fake_config(Some("demo"), vec![wal_source]);
        push(&cfg, &[&repo1_s as &dyn Storage, &bad_s as &dyn Storage], &pg_s)
            .expect_err("push must fail when any repository write fails");
    }

    #[test]
    fn archive_push_empty_repo_set_errors() {
        let pg_dir = tempfile::tempdir().expect("pg tempdir");
        let pg_s = Posix::new(pg_dir.path());
        let cfg = fake_config(Some("demo"), vec![format!("pg_wal/{SEGMENT}")]);
        let err = push(&cfg, &[], &pg_s).expect_err("empty repo set must error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("at least one repository"), "msg was {msg}"),
            other => panic!("expected Other(at least one repository), got {other:?}"),
        }
    }

    #[test]
    fn archive_get_reads_from_first_repo_that_has_segment() {
        // The segment lives only in repo2; archive-get must fall through repo1
        // and serve it from repo2.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());

        // Only repo2 has the segment.
        put(&repo2_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()]);
        get(&cfg, &[&repo1_s as &dyn Storage, &repo2_s as &dyn Storage], &pg_s).expect("get should serve from repo2");

        assert_eq!(read(&pg_s, &dest), WAL_BODY, "segment should be served from repo2");
    }

    #[test]
    fn archive_get_prefers_earlier_repo() {
        // Both repos have the segment, with different payloads; archive-get must
        // serve the earliest (repo1).
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());

        put(&repo1_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);
        put(&repo2_s, &format!("archive/demo/{SEGMENT}"), b"repo2 payload");

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest.clone()]);
        get(&cfg, &[&repo1_s as &dyn Storage, &repo2_s as &dyn Storage], &pg_s).expect("get should succeed");

        assert_eq!(read(&pg_s, &dest), WAL_BODY, "earliest repo (repo1) should win");
    }

    #[test]
    fn archive_get_missing_in_all_repos_errors() {
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());

        let dest = format!("pg_wal/{SEGMENT}");
        let cfg = fake_config(Some("demo"), vec![SEGMENT.to_owned(), dest]);
        let err = get(&cfg, &[&repo1_s as &dyn Storage, &repo2_s as &dyn Storage], &pg_s)
            .expect_err("get must fail when no repository has the segment");
        match err {
            CommandError::Storage(_) => {}
            other => panic!("expected Storage(not found), got {other:?}"),
        }
    }
}
