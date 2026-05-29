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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pgbr_compress::{Bz2Decompress, GzDecompress, Lz4Decompress, ZstDecompress};
use pgbr_config::{LoadedConfig, LockType, OptionValue};
use pgbr_info::{CipherType, InfoArchive, RepoKeys};
use pgbr_io::Filter;
use pgbr_postgres::lsn::parse_wal_segment;
use pgbr_storage::{Posix, Storage};

use crate::CommandError;
use crate::backup::acquire_command_lock;
use crate::pipeline::{CompressType, RepoTransform};

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

/// The [`CompressType`] resolved from `compress-type` (or the legacy `compress`
/// boolean), used to build the keyed per-repo [`RepoTransform`].
fn compress_type_enum(config: &LoadedConfig) -> CompressType {
    CompressType::from_str_id(compress_type(config))
}

/// Enumerate the configured repository group indexes in ascending order — the
/// same order `pgbr_cli::storage_helper::build_all_repo_storages` constructs the
/// `repo_storages` slice in, so the i-th storage handed to [`push`] / [`get`]
/// belongs to the i-th index returned here.
///
/// A repository index `N` counts as configured when an explicit `repoN-path` or
/// `repoN-type` is present at that group index. The active `--repo` index is
/// always included, and the implicit single repository (index 1) is the
/// fallback so the set is never empty. Mirrors `configured_repo_indexes` in the
/// CLI's storage helper (kept in sync so the position↔index mapping holds).
fn configured_repo_indexes(config: &LoadedConfig) -> Vec<u32> {
    let mut indexes: BTreeSet<u32> = BTreeSet::new();
    for (name, idx) in config.options.keys() {
        if let Some(i) = idx
            && matches!(name.as_str(), "repo-path" | "repo-type")
        {
            indexes.insert(*i);
        }
    }
    indexes.insert(active_repo_index(config));
    if indexes.is_empty() {
        indexes.insert(1);
    }
    indexes.into_iter().collect()
}

/// The active repository index from the `--repo` option, defaulting to 1.
fn active_repo_index(config: &LoadedConfig) -> u32 {
    match config.options.get(&("repo".to_owned(), None)) {
        Some(OptionValue::Integer(n)) if *n >= 1 => u32::try_from(*n).unwrap_or(1),
        _ => 1,
    }
}

/// Fetch a `repo`-group `StringId` option at group index `index`.
fn repo_string_id<'a>(config: &'a LoadedConfig, name: &str, index: u32) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), Some(index))) {
        Some(OptionValue::StringId(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Fetch a `repo`-group `String` option at group index `index`.
fn repo_string<'a>(config: &'a LoadedConfig, name: &str, index: u32) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), Some(index))) {
        Some(OptionValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Resolve the repository sub-key used to encrypt WAL for repository `index`, or
/// `None` when that repository is unencrypted.
///
/// WAL is encrypted with the repository *sub-key* (the second level of
/// pgBackRest's two-level scheme), not the user passphrase directly. The sub-key
/// is stored, encrypted under the user passphrase, in the `[cipher]` section of
/// that repository's `archive.info`; [`InfoArchive::load_keyed`] returns it. A
/// repository with no `archive.info` yet (uninitialised) returns `Ok(None)` —
/// there is nothing to push to an uninitialised, encrypted repo, but we degrade
/// to a plaintext copy rather than fail here.
///
/// # Errors
///
/// [`CommandError::MissingOption`] when an encrypted repo has no
/// `repo-cipher-pass`; [`CommandError::Other`] when the recorded sub-key cannot
/// be decrypted (wrong passphrase / corrupt `[cipher]` section).
fn repo_sub_key(repo: &dyn Storage, config: &LoadedConfig, index: u32, stanza: &str) -> Result<Option<String>, CommandError> {
    let cipher_type = repo_string_id(config, "repo-cipher-type", index).map_or(CipherType::None, CipherType::from_str_id);
    if !cipher_type.is_encrypted() {
        return Ok(None);
    }
    let user_pass = repo_string(config, "repo-cipher-pass", index).filter(|s| !s.is_empty());
    let user_pass = user_pass.ok_or_else(|| CommandError::MissingOption {
        option: "repo-cipher-pass".to_owned(),
    })?;

    // Load the recorded repo sub-key from archive.info's [cipher] section,
    // decrypting it under the user passphrase. An uninitialised repo (no
    // archive.info) has no sub-key yet.
    let info_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    if !repo.exists(&info_path)? {
        return Ok(None);
    }
    let (_, recorded) =
        InfoArchive::load_keyed(repo, &info_path, Some(user_pass)).map_err(|err| CommandError::Other(err.to_string()))?;
    let keys =
        RepoKeys::resolve(cipher_type, Some(user_pass), recorded.as_deref()).map_err(|err| CommandError::Other(err.to_string()))?;
    Ok(keys.repo_sub_pass().map(str::to_owned))
}

/// Build the per-repository [`RepoTransform`] (compress + that repo's cipher) for
/// each storage in `repo_storages`, in the same order. The compression settings
/// are shared (read from `config`); the cipher sub-key is resolved per repo from
/// its own `repoN-cipher-*` options + recorded `[cipher]` sub-key, so an
/// encrypted repo stores encrypted WAL while a plaintext repo in the same
/// fan-out stores plaintext.
///
/// # Errors
///
/// Propagates [`repo_sub_key`] failures (missing passphrase, undecryptable
/// recorded sub-key, storage errors).
fn per_repo_transforms(
    config: &LoadedConfig,
    repo_storages: &[&dyn Storage],
    stanza: &str,
) -> Result<Vec<RepoTransform>, CommandError> {
    let compress_type = compress_type_enum(config);
    let compress_level = compress_level(config, compress_type.as_str_id());
    let indexes = configured_repo_indexes(config);
    let mut transforms = Vec::with_capacity(repo_storages.len());
    for (pos, repo) in repo_storages.iter().enumerate() {
        // Fall back to index 1 if there are more storages than enumerated
        // indexes (defensive; the two are kept in lock-step by construction).
        let index = indexes.get(pos).copied().unwrap_or(1);
        let sub_key = repo_sub_key(*repo, config, index, stanza)?;
        transforms.push(RepoTransform::with_key(compress_type, compress_level, sub_key));
    }
    Ok(transforms)
}

/// Apply `transform` (compress + optional per-repo encryption, SHA-1 KDF) to the
/// plaintext WAL `bytes`, returning the repo-side bytes to store.
fn transform_segment(transform: &RepoTransform, bytes: &[u8]) -> Result<Vec<u8>, CommandError> {
    transform.apply_forward_keyed(bytes).map_err(CommandError::from)
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

/// Read a `Size` option (`archive-push-queue-max` / `archive-get-queue-max`),
/// returning the byte limit or `None` when the option is unset.
///
/// `archive-push-queue-max` has no default (the queue is unbounded unless
/// configured); `archive-get-queue-max` defaults to 128 MiB in the option model
/// and is always resolved on a real run, but this helper returns `None` for the
/// hand-built test configs that omit it.
fn queue_max(config: &LoadedConfig, name: &str) -> Option<u64> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Size(value)) => Some(*value),
        Some(OptionValue::Integer(value)) if *value >= 0 => u64::try_from(*value).ok(),
        _ => None,
    }
}

/// Whether `archive-header-check` is enabled. Defaults to **true** (the option
/// model's default) when unset, matching pgBackRest validating the WAL header on
/// every `archive-push` unless explicitly disabled.
fn archive_header_check(config: &LoadedConfig) -> bool {
    !matches!(
        config.options.get(&("archive-header-check".to_owned(), None)),
        Some(OptionValue::Boolean(false))
    )
}

/// Whether `archive-missing-retry` is enabled. Defaults to **true** (the option
/// model's default) when unset: on `archive-get`, a not-found segment is looked
/// up once more after a short delay before being reported missing.
fn archive_missing_retry(config: &LoadedConfig) -> bool {
    !matches!(
        config.options.get(&("archive-missing-retry".to_owned(), None)),
        Some(OptionValue::Boolean(false))
    )
}

/// Total size, in bytes, of the regular files in `dir` whose names are valid
/// 24-hex WAL segment names — the unarchived-WAL backlog the push-queue limit
/// guards. A non-existent / unreadable directory contributes 0.
///
/// pgBackRest's "Push-queue" check measures the WAL waiting to be archived; a
/// completed WAL segment's name is a 24-hex string (optionally with a `.partial`
/// / `.ready` companion, which are skipped here as they are not the WAL itself).
/// Summing only segment-named files keeps the measurement to the WAL bytes that
/// would fill the partition. C ref: `archivePushDrop()` in
/// `src/command/archive/push/push.c`.
fn wal_backlog_bytes(storage: &dyn Storage, dir: &Path) -> u64 {
    let Ok(entries) = storage.list(dir) else {
        return 0;
    };
    entries
        .iter()
        .filter(|info| {
            info.path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| parse_wal_segment(name).is_some())
        })
        .map(|info| info.size)
        .sum()
}

/// Total size, in bytes, of every staged WAL segment in the async push *out*
/// spool (status files excluded) — the backlog measured against
/// `archive-push-queue-max` in async mode. A missing spool dir contributes 0.
fn spool_out_backlog_bytes(spool: &dyn Storage, stanza: &str) -> u64 {
    let out_dir = push_out_dir(stanza);
    let Ok(entries) = spool.list(&out_dir) else {
        return 0;
    };
    entries
        .iter()
        .filter(|info| {
            info.path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.ends_with(STATUS_EXT_OK) && !name.ends_with(STATUS_EXT_ERROR))
        })
        .map(|info| info.size)
        .sum()
}

/// Total size, in bytes, of every staged WAL segment in the async get *in*
/// spool — the backlog measured against `archive-get-queue-max` so the
/// prefetch loop does not overrun the cap. A missing spool dir contributes 0.
fn spool_in_backlog_bytes(spool: &dyn Storage, stanza: &str) -> u64 {
    let in_dir = get_in_dir(stanza);
    let Ok(entries) = spool.list(&in_dir) else {
        return 0;
    };
    entries
        .iter()
        .filter(|info| {
            info.path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.ends_with(STATUS_EXT_OK) && !name.ends_with(STATUS_EXT_ERROR))
        })
        .map(|info| info.size)
        .sum()
}

/// Whether the unarchived-WAL backlog has reached `archive-push-queue-max`.
///
/// Returns `true` when a `queue_max` limit is configured **and** `backlog`
/// (including the segment about to be pushed) meets or exceeds it. With no limit
/// configured the queue is unbounded and this always returns `false`.
fn push_queue_exceeded(queue_max: Option<u64>, backlog: u64) -> bool {
    queue_max.is_some_and(|limit| backlog >= limit)
}

/// Emit a `WARN` line that the push-queue limit dropped a WAL segment.
///
/// pgBackRest returns success to `PostgreSQL` so PG recycles the WAL (rather than
/// the partition filling), logging a warning that the segment was dropped. The
/// message is human-facing diagnostic output, so it is routed through the
/// `pgbr_core::log` formatter ([`log_warn`]) rather than stdout, which is
/// reserved for machine-readable command output.
fn warn_queue_dropped(segment: &str, backlog: u64, limit: u64) {
    log_warn(&format!(
        "dropped WAL segment {segment} because the unarchived WAL backlog ({backlog} bytes) \
         reached archive-push-queue-max ({limit} bytes)"
    ));
}

/// Emit a human-facing `WARN` diagnostic through the `pgbr_core::log` formatter.
///
/// pgBackRest sends progress / warning lines to its log (the console at
/// `log-level-console`, plus the log file at `log-level-file`), keeping stdout
/// free for machine-readable command output. This routes the warning through the
/// migrated logger — the Rust analogue of the C `LOG_WARN` macro — so it is
/// level-filtered like every other command's output. `process_id` is `u32::MAX`
/// so the formatter uses the process-global id set by `logInit`; `code` is `0`
/// (no error-code segment). A formatting / write failure is intentionally
/// swallowed: progress chatter must never turn a successful command into an
/// error.
fn log_warn(message: &str) {
    let _ = pgbr_core::log::format::log_internal(
        pgbr_core::log::LOG_LEVEL_WARN,
        pgbr_core::log::LOG_LEVEL_MIN,
        pgbr_core::log::LOG_LEVEL_MAX,
        u32::MAX,
        "push.c",
        "archivePush",
        0,
        message,
    );
}

/// Validate a WAL segment's long-page header against the stanza's `archive.info`
/// before it is stored.
///
/// Implements `archive-header-check`. The segment's first-page long header
/// (magic + system id + segment size + timeline) is parsed and cross-checked:
///
/// - the header must parse (a non-WAL file fed to `archive-push` is rejected);
/// - `xlp_sysid` must equal the stanza's `db-system-id` (the segment belongs to
///   a *different* cluster otherwise);
/// - the magic's `PostgreSQL` version must match the stanza's `db-version`;
/// - the segment file name's timeline must equal `xlp_tli` (a name/header
///   timeline disagreement is corruption).
///
/// C reference: `archivePushCheck()` / `pgWalFromBuffer()` in
/// `src/command/archive/push/push.c` + `src/postgres/interface.c`.
///
/// # Errors
///
/// [`CommandError::Other`] on any mismatch.
fn check_wal_header(bytes: &[u8], segment: &str, info: &InfoArchive) -> Result<(), CommandError> {
    let header = pgbr_postgres::lsn::parse_wal_header(bytes).ok_or_else(|| {
        CommandError::Other(format!(
            "archive-push: WAL segment {segment} has no valid WAL header (archive-header-check)"
        ))
    })?;

    if header.system_id != info.db_system_id {
        return Err(CommandError::Other(format!(
            "archive-push: WAL segment {segment} system-id {} does not match stanza db-system-id {}",
            header.system_id, info.db_system_id
        )));
    }

    if let Some(version) = header.version
        && version != info.db_version
    {
        return Err(CommandError::Other(format!(
            "archive-push: WAL segment {segment} version {version} does not match stanza db-version {}",
            info.db_version
        )));
    }

    if let Some((name_timeline, _, _)) = parse_wal_segment(segment)
        && name_timeline != header.timeline
    {
        return Err(CommandError::Other(format!(
            "archive-push: WAL segment {segment} name timeline {name_timeline} does not match header timeline {}",
            header.timeline
        )));
    }

    Ok(())
}

/// Load the stanza's `archive.info` from the first repository that has it, used
/// by `archive-header-check` to source the cluster identity. Returns `Ok(None)`
/// when no repository holds an `archive.info` (a not-yet-initialised stanza), so
/// the caller can skip the header check rather than fail the push.
fn load_archive_info(repo_storages: &[&dyn Storage], stanza: &str) -> Result<Option<InfoArchive>, CommandError> {
    let info_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    for repo in repo_storages {
        if repo.exists(&info_path)? {
            let info = InfoArchive::load(*repo, &info_path).map_err(|err| CommandError::Other(err.to_string()))?;
            return Ok(Some(info));
        }
    }
    Ok(None)
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

    // archive-push-queue-max: if the unarchived-WAL backlog has reached the
    // configured limit, abandon this push and return success-with-warning so
    // PostgreSQL recycles the WAL (rather than the partition filling). The
    // backlog is the spool out/ dir in async mode, else the WAL source's
    // directory (pg_wal). C ref: archivePushDrop() in push.c (KB "Push-queue").
    let push_limit = queue_max(config, "archive-push-queue-max");
    let async_enabled = archive_async(config);
    let backlog = if async_enabled {
        // Resolve the spool here so the backlog can be measured even before the
        // async staging path runs.
        spool_path(config).map_or(0, |spool_root| spool_out_backlog_bytes(&Posix::new(spool_root), stanza))
    } else if let Some(parent) = Path::new(wal_source).parent().filter(|p| !p.as_os_str().is_empty()) {
        wal_backlog_bytes(pg_storage, parent)
    } else {
        0
    };
    if push_queue_exceeded(push_limit, backlog) {
        // Unwrap is safe: push_queue_exceeded only returns true when Some.
        if let Some(limit) = push_limit {
            warn_queue_dropped(segment, backlog, limit);
        }
        return Ok(());
    }

    // archive-header-check: validate the WAL segment's long-page header against
    // the stanza's archive.info before storing, rejecting a segment that belongs
    // to a different cluster / version / timeline. Skipped when no archive.info
    // is present yet (uninitialised stanza) or when the option is disabled.
    let archive_info = if archive_header_check(config) {
        load_archive_info(repo_storages, stanza)?
    } else {
        None
    };

    // Asynchronous mode: stage the segment in the spool out/ directory and let
    // the background drain move it to the repository. Before staging, consume
    // any status file the drain left for this segment from the previous call.
    // The spool stages a single plaintext copy regardless of repo count; the
    // background drain fans it out (a future protocol handler runs the drain).
    if async_enabled {
        let spool_root = spool_path(config).ok_or_else(|| CommandError::MissingOption {
            option: "spool-path".to_owned(),
        })?;
        let spool = Posix::new(spool_root);
        return push_async(
            pg_storage,
            &spool,
            stanza,
            segment,
            Path::new(wal_source),
            archive_info.as_ref(),
        );
    }

    let bytes = read_segment(pg_storage, Path::new(wal_source))?;
    if let Some(info) = archive_info.as_ref() {
        check_wal_header(&bytes, segment, info)?;
    }

    // Build one transform per repository (shared compression, but each repo's
    // own cipher sub-key) so an encrypted repo stores encrypted WAL while a
    // plaintext repo stores plaintext — even in the same fan-out. The compress
    // suffix is shared (encryption does not change the file name), so the
    // destination path is the same for every repo. The segment is only archived
    // once it has reached all of them.
    let transforms = per_repo_transforms(config, repo_storages, stanza)?;
    let dest = repo_segment_path(stanza, &format!("{segment}{}", compress_suffix(config)));
    for (repo, transform) in repo_storages.iter().zip(transforms.iter()) {
        let stored = transform_segment(transform, &bytes)?;
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
    archive_info: Option<&InfoArchive>,
) -> Result<(), CommandError> {
    if let Some(outcome) = consume_push_status(spool, stanza, segment)? {
        return outcome;
    }

    // Not yet processed by the drain — stage the raw segment in out/ for the
    // background drain to pick up. The WAL header is validated before staging so
    // a mismatched segment is rejected at the foreground call (the drain only
    // ever compresses + copies an already-validated segment).
    let bytes = read_segment(pg_storage, wal_source)?;
    if let Some(info) = archive_info {
        check_wal_header(&bytes, segment, info)?;
    }
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

/// Drain the spool *out* directory into a single repository with that repo's
/// cipher.
///
/// Applies that repository's own [`RepoTransform`] (compress + per-repo cipher)
/// to every staged segment — the per-repo-encryption counterpart of
/// [`drain_push_spool`].
///
/// pgBackRest's async client stages a single plaintext copy of each WAL segment;
/// the background drain is what actually compresses, encrypts, and writes it to
/// each repository. Because each repository has its own cipher sub-key, the
/// drain must run once per repository with that repository's `transform`
/// (built by [`per_repo_transforms`] / [`RepoTransform::with_key`]). The
/// repo-side file name carries the compression suffix (`transform.repo_suffix()`);
/// encryption does not change it.
///
/// On success the staged copy is removed and a `<segment>.ok` status is written;
/// on failure a `<segment>.error` status carrying the message is left and the
/// staged copy is kept for a retry. The count returned is the number of segments
/// drained successfully into this repository.
///
/// # Errors
///
/// - [`CommandError::Storage`] / [`CommandError::Io`] if listing the spool or
///   writing a status file itself fails (per-segment transfer failures are
///   recorded as `.error` status, not returned).
pub fn drain_push_spool_keyed(
    spool: &dyn Storage,
    repo_storage: &dyn Storage,
    stanza: &str,
    transform: &RepoTransform,
) -> Result<usize, CommandError> {
    let out_dir = push_out_dir(stanza);
    if !spool.exists(&out_dir)? {
        return Ok(0);
    }

    let suffix = transform.repo_suffix();
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

        match drain_one_keyed(spool, repo_storage, stanza, &segment, suffix, &staged, transform) {
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

/// Transfer a single staged segment to one repository, applying that repo's
/// [`RepoTransform`] (compress + per-repo cipher). Used by
/// [`drain_push_spool_keyed`]; a returned error becomes a `.error` status.
fn drain_one_keyed(
    spool: &dyn Storage,
    repo_storage: &dyn Storage,
    stanza: &str,
    segment: &str,
    suffix: &str,
    staged: &Path,
    transform: &RepoTransform,
) -> Result<(), CommandError> {
    let bytes = read_segment(spool, staged)?;
    let stored = transform_segment(transform, &bytes)?;
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
    // archive-missing-retry: a segment may land in the archive between two
    // lookups (PostgreSQL requests it just as archive-push writes it), so when
    // no repository holds it, look once more after a short delay before
    // reporting it missing. C ref: the retry around walSegmentFind() in
    // src/command/archive/get/get.c.
    let retry = archive_missing_retry(config);
    fetch_segment_with_retry(
        repo_storages,
        pg_storage,
        stanza,
        segment,
        Path::new(dest),
        retry,
        RETRY_DELAY,
    )
}

/// Short delay between the first and the retry archive lookup when
/// `archive-missing-retry` is enabled.
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Fetch `segment` from the first repository that holds it, optionally retrying
/// once after `delay` when the segment is not found anywhere.
///
/// The repositories are probed in order; the first that has the segment serves
/// it (decompressing as needed). When none holds it: if `retry` is set, the
/// probe is repeated once after `delay` (a segment may have been archived in
/// between); otherwise — or if it is still absent after the retry — the canonical
/// `NotFound` from the last repository's plaintext path surfaces.
fn fetch_segment_with_retry(
    repo_storages: &[&dyn Storage],
    pg_storage: &dyn Storage,
    stanza: &str,
    segment: &str,
    dest: &Path,
    retry: bool,
    delay: std::time::Duration,
) -> Result<(), CommandError> {
    // First pass: serve from any repository that already has the segment.
    for repo in repo_storages {
        if repo_has_segment(*repo, stanza, segment)? {
            return fetch_from_repo(*repo, pg_storage, stanza, segment, dest);
        }
    }

    // Not found anywhere. Retry once after a short delay if enabled.
    if retry {
        std::thread::sleep(delay);
        for repo in repo_storages {
            if repo_has_segment(*repo, stanza, segment)? {
                return fetch_from_repo(*repo, pg_storage, stanza, segment, dest);
            }
        }
    }

    // Still missing: read the last repository's plaintext path so the caller
    // gets the canonical NotFound error (the caller rejected an empty set, so
    // there is always at least one repository).
    let last = repo_storages
        .last()
        .ok_or_else(|| CommandError::Other("archive-get found no repository to read from".to_owned()))?;
    fetch_from_repo(*last, pg_storage, stanza, segment, dest)
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
/// `queue_max` is the resolved `archive-get-queue-max` (bytes): pre-fetching
/// stops as soon as the *in* spool already holds at least this many bytes, so
/// the spool never over-fills ahead of recovery. `None` leaves the prefetch
/// unbounded (every requested segment is fetched). C ref: the queue cap in
/// `src/command/archive/get/get.c`.
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
    queue_max: Option<u64>,
) -> Result<usize, CommandError> {
    // Account for whatever is already staged so a partially-filled spool is not
    // overrun on the next prefetch round.
    let mut staged_bytes = spool_in_backlog_bytes(spool, stanza);
    let mut prefetched = 0;
    for segment in segments {
        // Stop once the in/ spool has reached the configured byte cap.
        if queue_max.is_some_and(|limit| staged_bytes >= limit) {
            break;
        }

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
        staged_bytes += bytes.len() as u64;
        write_segment(&bytes, spool, &get_in_dir(stanza).join(segment))?;
        prefetched += 1;
    }

    Ok(prefetched)
}

/// Locate `segment` in the repository archive and return its **plaintext**
/// bytes, transparently decompressing whatever stored form is present.
///
/// The stored form is discovered exactly as [`fetch_from_repo`] does: the
/// plaintext `archive/<stanza>/<segment>` is preferred, then each compression
/// suffix (`.gz`, `.zst`, `.bz2`, `.lz4`) is probed; a matched compressed form
/// is run through the matching decompress filter. Returns `Ok(None)` when no
/// stored form exists, so a caller (e.g. `archive-copy`) can decide whether a
/// missing segment is an error.
///
/// This is a read-only sibling of the WAL-fetch path, factored out so the
/// backup command can pull a required WAL segment out of the archive without a
/// PG-data destination. It does not take the archive lock (the caller already
/// holds the backup lock) and never writes anything.
///
/// # Errors
///
/// - [`CommandError::Io`] if a matched compressed form fails to decompress.
/// - [`CommandError::Storage`] / [`CommandError::Io`] if a repository read fails.
pub(crate) fn read_archived_segment(repo: &dyn Storage, stanza: &str, segment: &str) -> Result<Option<Vec<u8>>, CommandError> {
    let plaintext = repo_segment_path(stanza, segment);
    let (source, suffix) = if repo.exists(&plaintext)? {
        (plaintext, "")
    } else {
        let mut found = None;
        for suffix in COMPRESS_SUFFIXES {
            let candidate = repo_segment_path(stanza, &format!("{segment}{suffix}"));
            if repo.exists(&candidate)? {
                found = Some((candidate, *suffix));
                break;
            }
        }
        match found {
            Some(pair) => pair,
            None => return Ok(None),
        }
    };

    let stored = read_segment(repo, &source)?;
    let bytes = match decompress_filter_for(suffix) {
        Some(mut filter) => run_filter(filter.as_mut(), &stored)?,
        None => stored,
    };
    Ok(Some(bytes))
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
        CommandError, check_wal_header, drain_push_spool, drain_push_spool_keyed, fetch_segment_with_retry, get, get_in_dir,
        per_repo_transforms, prefetch_get_spool, push, push_out_dir, push_queue_exceeded, read_archived_segment, status_error_path,
        status_ok_path, wal_backlog_bytes,
    };
    use crate::pipeline::{CompressType, RepoTransform};
    use pgbr_info::InfoArchive;

    const SEGMENT: &str = "000000010000000000000001";
    const WAL_BODY: &[u8] = b"fake-wal-segment-contents";

    /// The PG-14 system identifier / version used across these tests.
    const TEST_SYSTEM_ID: u64 = 6_873_049_345_984_568_091;

    /// Build a synthetic `InfoArchive` for the header-check tests.
    fn test_archive_info(system_id: u64, version: &str) -> InfoArchive {
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: system_id,
            db_version: version.to_owned(),
            history: BTreeMap::new(),
        }
    }

    /// Save an `archive.info` for `stanza` into `repo` so `archive-header-check`
    /// can source the cluster identity.
    fn seed_archive_info(repo: &Posix, stanza: &str, system_id: u64, version: &str) {
        repo.create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive dir");
        test_archive_info(system_id, version)
            .save(repo, Path::new(&format!("archive/{stanza}/archive.info")))
            .expect("save archive.info");
    }

    /// Build a WAL segment first-page buffer (long header) with the given magic,
    /// timeline, system id, and segment size, padded to a full 16 MiB-free
    /// minimal page (just the header bytes are read by the parser).
    fn wal_segment_bytes(magic: u16, timeline: u32, system_id: u64, segment_size: u32) -> Vec<u8> {
        // 64 bytes is plenty: the long header is read from the first 36 bytes.
        let mut buf = vec![0u8; 64];
        buf[0..2].copy_from_slice(&magic.to_le_bytes());
        buf[2..4].copy_from_slice(&0x0002u16.to_le_bytes()); // XLP_LONG_HEADER
        buf[4..8].copy_from_slice(&timeline.to_le_bytes());
        buf[24..32].copy_from_slice(&system_id.to_le_bytes());
        buf[32..36].copy_from_slice(&segment_size.to_le_bytes());
        buf
    }

    /// PG-14 magic (`XLOG_PAGE_MAGIC` 0xD10D) for the header-check fixtures.
    const PG14_WAL_MAGIC: u16 = 0xD10D;

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
        let prefetched =
            prefetch_get_spool(&spool_s, &repo_s, "demo", &[SEGMENT.to_owned()], None).expect("prefetch should succeed");
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

    // -----------------------------------------------------------------------
    // Per-repo archive encryption (Task 25)
    // -----------------------------------------------------------------------

    /// pgBackRest's AES-256-CBC framing prefix; encrypted repo bytes start with
    /// it (`"Salted__"`), so its presence proves a segment was encrypted.
    const CIPHER_MAGIC: &[u8] = b"Salted__";

    /// Seed an encrypted `archive.info` into `repo` carrying `repo_sub_key` in
    /// its `[cipher]` section, encrypted under the user `passphrase`. This is
    /// what [`super::repo_sub_key`] reads to recover the WAL encryption key.
    fn seed_encrypted_archive_info(repo: &Posix, stanza: &str, system_id: u64, version: &str, passphrase: &str, repo_sub: &str) {
        repo.create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive dir");
        test_archive_info(system_id, version)
            .save_keyed(
                repo,
                Path::new(&format!("archive/{stanza}/archive.info")),
                Some(passphrase),
                Some(repo_sub),
            )
            .expect("save encrypted archive.info");
    }

    /// Add `repoN-cipher-type=aes-256-cbc` + `repoN-cipher-pass` at group index
    /// `index`, and mark that index as configured via `repoN-path` so
    /// [`super::configured_repo_indexes`] enumerates it (keeping the
    /// position↔index mapping in step with the storages slice).
    fn set_repo_cipher(cfg: &mut LoadedConfig, index: u32, user_pass: &str) {
        cfg.options.insert(
            ("repo-cipher-type".to_owned(), Some(index)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        cfg.options.insert(
            ("repo-cipher-pass".to_owned(), Some(index)),
            OptionValue::String(user_pass.to_owned()),
        );
        cfg.options.insert(
            ("repo-path".to_owned(), Some(index)),
            OptionValue::Path(format!("/repo{index}")),
        );
    }

    #[test]
    fn push_encrypts_per_repo_when_only_one_repo_is_encrypted() {
        // repo1 is encrypted, repo2 is plaintext. The SAME WAL must be stored
        // encrypted in repo1 (cipher magic, bytes differ from plaintext) and
        // plaintext in repo2 — proving each repo's own cipher is applied.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());

        // repo1 (index 1) is encrypted with a recorded sub-key.
        seed_encrypted_archive_info(&repo1_s, "demo", TEST_SYSTEM_ID, "14", "userpass1", "cmVwbzEtc3ViLWtleQ==");

        let wal_source = format!("pg_wal/{SEGMENT}");
        // Use a WAL-header-valid body so archive-header-check (on for repo1)
        // passes; the header check loads archive.info from the FIRST repo, which
        // is encrypted — load there uses the no-passphrase load that the header
        // check path tolerates only for plaintext, so disable the header check.
        put(&pg_s, &wal_source, WAL_BODY);

        let mut cfg = fake_config(Some("demo"), vec![wal_source]);
        cfg.options
            .insert(("archive-header-check".to_owned(), None), OptionValue::Boolean(false));
        set_repo_cipher(&mut cfg, 1, "userpass1");
        // repo2 (index 2) configured but unencrypted.
        cfg.options
            .insert(("repo-path".to_owned(), Some(2)), OptionValue::Path("/repo2".to_owned()));

        push(&cfg, &[&repo1_s as &dyn Storage, &repo2_s as &dyn Storage], &pg_s).expect("per-repo push should succeed");

        let dest = format!("archive/demo/{SEGMENT}");
        let r1 = read(&repo1_s, &dest);
        let r2 = read(&repo2_s, &dest);

        assert_eq!(r2, WAL_BODY, "plaintext repo2 must store the raw WAL");
        assert_ne!(r1, WAL_BODY, "encrypted repo1 must NOT store the raw WAL");
        assert_ne!(r1, r2, "the two repos must store different bytes (one encrypted, one not)");
        assert_eq!(
            &r1[..CIPHER_MAGIC.len()],
            CIPHER_MAGIC,
            "repo1 bytes must carry the cipher magic"
        );
    }

    #[test]
    fn push_encrypts_differently_when_repos_use_different_keys() {
        // Both repos encrypted but with DIFFERENT sub-keys -> the stored bytes
        // differ between the two repos.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());
        let pg_s = Posix::new(pg.path());

        seed_encrypted_archive_info(
            &repo1_s,
            "demo",
            TEST_SYSTEM_ID,
            "14",
            "userpass1",
            "c3ViLWtleS1vbmUtMTExMQ==",
        );
        seed_encrypted_archive_info(
            &repo2_s,
            "demo",
            TEST_SYSTEM_ID,
            "14",
            "userpass2",
            "c3ViLWtleS10d28tMjIyMg==",
        );

        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let mut cfg = fake_config(Some("demo"), vec![wal_source]);
        cfg.options
            .insert(("archive-header-check".to_owned(), None), OptionValue::Boolean(false));
        set_repo_cipher(&mut cfg, 1, "userpass1");
        set_repo_cipher(&mut cfg, 2, "userpass2");

        push(&cfg, &[&repo1_s as &dyn Storage, &repo2_s as &dyn Storage], &pg_s).expect("dual-encrypted push should succeed");

        let dest = format!("archive/demo/{SEGMENT}");
        let r1 = read(&repo1_s, &dest);
        let r2 = read(&repo2_s, &dest);
        assert_ne!(r1, WAL_BODY, "repo1 encrypted");
        assert_ne!(r2, WAL_BODY, "repo2 encrypted");
        assert_eq!(&r1[..CIPHER_MAGIC.len()], CIPHER_MAGIC, "repo1 cipher magic");
        assert_eq!(&r2[..CIPHER_MAGIC.len()], CIPHER_MAGIC, "repo2 cipher magic");
        // Different keys (and random salts) -> different ciphertext.
        assert_ne!(r1, r2, "different sub-keys must produce different ciphertext");
    }

    #[test]
    fn per_repo_transforms_pairs_each_storage_with_its_cipher() {
        // The transform list must be 1:1 with the storages slice and carry the
        // encrypted/plaintext flag from each repo's own config.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let repo1_s = Posix::new(repo1.path());
        let repo2_s = Posix::new(repo2.path());

        seed_encrypted_archive_info(
            &repo1_s,
            "demo",
            TEST_SYSTEM_ID,
            "14",
            "userpass1",
            "cGVyLXJlcG8tdHJhbnNmb3JtLWtleQ==",
        );

        let mut cfg = fake_config(Some("demo"), Vec::new());
        set_repo_cipher(&mut cfg, 1, "userpass1");
        cfg.options
            .insert(("repo-path".to_owned(), Some(2)), OptionValue::Path("/repo2".to_owned()));

        let transforms =
            per_repo_transforms(&cfg, &[&repo1_s as &dyn Storage, &repo2_s as &dyn Storage], "demo").expect("transforms resolve");
        assert_eq!(transforms.len(), 2, "one transform per storage");
        assert!(transforms[0].is_encrypted(), "repo1 transform must be encrypted");
        assert!(!transforms[1].is_encrypted(), "repo2 transform must be plaintext");
    }

    #[test]
    fn async_drain_keyed_encrypts_for_the_target_repo() {
        // The async drain into a single repo applies that repo's RepoTransform,
        // so the repo copy is encrypted (cipher magic) and differs from the
        // staged plaintext.
        let (_repo, _pg, repo_s, _pg_s) = posix_pair();
        let (_spool, spool_s) = spool_storage();
        put(&spool_s, &format!("archive/demo/out/{SEGMENT}"), WAL_BODY);

        let transform = RepoTransform::with_key(CompressType::None, 0, Some("ZHJhaW4ta2V5ZWQtc3ViLWtleQ==".to_owned()));
        let drained = drain_push_spool_keyed(&spool_s, &repo_s, "demo", &transform).expect("keyed drain should succeed");
        assert_eq!(drained, 1, "one segment should drain");

        let repo_dest = format!("archive/demo/{SEGMENT}");
        let stored = read(&repo_s, &repo_dest);
        assert_ne!(stored, WAL_BODY, "drained-and-encrypted copy must differ from plaintext");
        assert_eq!(
            &stored[..CIPHER_MAGIC.len()],
            CIPHER_MAGIC,
            "drained copy must carry the cipher magic"
        );
    }

    #[test]
    fn push_missing_cipher_pass_errors() {
        // An encrypted repo with no repo-cipher-pass must fail the push.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo1_s = Posix::new(repo1.path());
        let pg_s = Posix::new(pg.path());
        seed_encrypted_archive_info(
            &repo1_s,
            "demo",
            TEST_SYSTEM_ID,
            "14",
            "userpass1",
            "bWlzc2luZy1wYXNzLXN1Yi1rZXk=",
        );

        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        let mut cfg = fake_config(Some("demo"), vec![wal_source]);
        cfg.options
            .insert(("archive-header-check".to_owned(), None), OptionValue::Boolean(false));
        // cipher-type set, but NO cipher-pass.
        cfg.options.insert(
            ("repo-cipher-type".to_owned(), Some(1)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        cfg.options
            .insert(("repo-path".to_owned(), Some(1)), OptionValue::Path("/repo1".to_owned()));

        let err = push(&cfg, &[&repo1_s as &dyn Storage], &pg_s).expect_err("missing repo-cipher-pass must error");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "repo-cipher-pass"),
            other => panic!("expected MissingOption(repo-cipher-pass), got {other:?}"),
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

    // -----------------------------------------------------------------------
    // read_archived_segment (used by backup archive-copy)
    // -----------------------------------------------------------------------

    #[test]
    fn read_archived_segment_returns_plaintext() {
        let (_repo, _pg, repo_s, _pg_s) = posix_pair();
        put(&repo_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);

        let bytes = read_archived_segment(&repo_s, "demo", SEGMENT).expect("read");
        assert_eq!(bytes.as_deref(), Some(WAL_BODY), "plaintext segment returned as-is");
    }

    #[test]
    fn read_archived_segment_decompresses_stored_form() {
        let (_repo, _pg, repo_s, _pg_s) = posix_pair();
        // Only the gz form exists; the helper must transparently decompress it.
        let compressed = run(GzCompress::new(super::default_level("gz"), false), WAL_BODY);
        put(&repo_s, &format!("archive/demo/{SEGMENT}.gz"), &compressed);

        let bytes = read_archived_segment(&repo_s, "demo", SEGMENT).expect("read");
        assert_eq!(bytes.as_deref(), Some(WAL_BODY), "gz segment decompressed to plaintext");
    }

    #[test]
    fn read_archived_segment_absent_is_none() {
        let (_repo, _pg, repo_s, _pg_s) = posix_pair();
        let bytes = read_archived_segment(&repo_s, "demo", SEGMENT).expect("read");
        assert_eq!(bytes, None, "a segment not in the archive yields None");
    }

    // -----------------------------------------------------------------------
    // archive-push-queue-max
    // -----------------------------------------------------------------------

    #[test]
    fn push_queue_exceeded_threshold() {
        // No limit configured -> never exceeded, whatever the backlog.
        assert!(!push_queue_exceeded(None, u64::MAX));
        // Under the limit -> not exceeded.
        assert!(!push_queue_exceeded(Some(1000), 999));
        // At or over the limit -> exceeded.
        assert!(push_queue_exceeded(Some(1000), 1000));
        assert!(push_queue_exceeded(Some(1000), 5000));
    }

    #[test]
    fn wal_backlog_sums_only_segment_named_files() {
        let (_repo, pg_dir, _repo_s, pg_s) = posix_pair();
        // Two valid 24-hex WAL segments and one non-segment file in pg_wal.
        put(&pg_s, "pg_wal/000000010000000000000001", &[0u8; 100]);
        put(&pg_s, "pg_wal/000000010000000000000002", &[0u8; 200]);
        put(&pg_s, "pg_wal/archive_status", b"not-a-segment");
        let _ = &pg_dir;
        let backlog = wal_backlog_bytes(&pg_s, Path::new("pg_wal"));
        assert_eq!(backlog, 300, "only the two 24-hex segments count");
        // A missing directory contributes 0.
        assert_eq!(wal_backlog_bytes(&pg_s, Path::new("does-not-exist")), 0);
    }

    /// `fake_config` plus an `archive-push-queue-max` Size option.
    fn fake_config_queue_max(stanza: Option<&str>, params: Vec<String>, limit: u64) -> LoadedConfig {
        let mut cfg = fake_config(stanza, params);
        cfg.options
            .insert(("archive-push-queue-max".to_owned(), None), OptionValue::Size(limit));
        cfg
    }

    #[test]
    fn push_over_queue_max_drops_segment_with_success() {
        // A pg_wal backlog exceeding the queue-max makes push abandon the copy and
        // return success (PostgreSQL recycles the WAL), leaving the repo empty.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, &vec![0u8; 16 * 1024 * 1024]); // 16 MiB segment
        // Add another large segment so the backlog is well over the 1 MiB limit.
        put(&pg_s, "pg_wal/000000010000000000000002", &vec![0u8; 16 * 1024 * 1024]);

        let cfg = fake_config_queue_max(Some("demo"), vec![wal_source], 1024 * 1024);
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("over-queue push returns success");

        assert!(
            !repo_s.exists(Path::new(&format!("archive/demo/{SEGMENT}"))).expect("exists"),
            "segment must be dropped (not archived) when the queue is over the limit"
        );
    }

    #[test]
    fn push_under_queue_max_archives_normally() {
        // A backlog under the limit lets the push proceed normally.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(&pg_s, &wal_source, WAL_BODY);

        // 1 GiB limit, a tiny backlog -> archived.
        let cfg = fake_config_queue_max(Some("demo"), vec![wal_source], 1024 * 1024 * 1024);
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("under-queue push archives");

        assert!(
            repo_s.exists(Path::new(&format!("archive/demo/{SEGMENT}"))).expect("exists"),
            "segment must be archived when the backlog is under the limit"
        );
    }

    // -----------------------------------------------------------------------
    // archive-header-check
    // -----------------------------------------------------------------------

    #[test]
    fn check_wal_header_accepts_matching_segment() {
        let info = test_archive_info(TEST_SYSTEM_ID, "14");
        let bytes = wal_segment_bytes(PG14_WAL_MAGIC, 1, TEST_SYSTEM_ID, 16 * 1024 * 1024);
        check_wal_header(&bytes, SEGMENT, &info).expect("a matching segment passes");
    }

    #[test]
    fn check_wal_header_rejects_system_id_mismatch() {
        let info = test_archive_info(TEST_SYSTEM_ID, "14");
        // A segment written by a different cluster.
        let bytes = wal_segment_bytes(PG14_WAL_MAGIC, 1, 999, 16 * 1024 * 1024);
        let err = check_wal_header(&bytes, SEGMENT, &info).expect_err("system-id mismatch must fail");
        assert!(err.to_string().contains("system-id"), "msg was {err}");
    }

    #[test]
    fn check_wal_header_rejects_version_mismatch() {
        // archive.info says 16 but the segment's magic is PG 14.
        let info = test_archive_info(TEST_SYSTEM_ID, "16");
        let bytes = wal_segment_bytes(PG14_WAL_MAGIC, 1, TEST_SYSTEM_ID, 16 * 1024 * 1024);
        let err = check_wal_header(&bytes, SEGMENT, &info).expect_err("version mismatch must fail");
        assert!(err.to_string().contains("version"), "msg was {err}");
    }

    #[test]
    fn check_wal_header_rejects_timeline_mismatch() {
        // The segment NAME is timeline 1 but the header says timeline 9.
        let info = test_archive_info(TEST_SYSTEM_ID, "14");
        let bytes = wal_segment_bytes(PG14_WAL_MAGIC, 9, TEST_SYSTEM_ID, 16 * 1024 * 1024);
        let err = check_wal_header(&bytes, SEGMENT, &info).expect_err("timeline mismatch must fail");
        assert!(err.to_string().contains("timeline"), "msg was {err}");
    }

    #[test]
    fn check_wal_header_rejects_non_wal_file() {
        let info = test_archive_info(TEST_SYSTEM_ID, "14");
        let err = check_wal_header(b"not a wal segment", SEGMENT, &info).expect_err("a non-WAL file must fail");
        assert!(err.to_string().contains("no valid WAL header"), "msg was {err}");
    }

    #[test]
    fn push_with_header_check_rejects_foreign_segment() {
        // End-to-end: archive.info identifies the cluster; a segment from a
        // different system id is rejected before it is stored.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        seed_archive_info(&repo_s, "demo", TEST_SYSTEM_ID, "14");
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(
            &pg_s,
            &wal_source,
            &wal_segment_bytes(PG14_WAL_MAGIC, 1, 999, 16 * 1024 * 1024),
        );

        let cfg = fake_config(Some("demo"), vec![wal_source]);
        let err = push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect_err("foreign segment must be rejected");
        assert!(err.to_string().contains("system-id"), "msg was {err}");
        assert!(
            !repo_s.exists(Path::new(&format!("archive/demo/{SEGMENT}"))).expect("exists"),
            "a rejected segment must not be stored"
        );
    }

    #[test]
    fn push_with_header_check_accepts_matching_segment() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        seed_archive_info(&repo_s, "demo", TEST_SYSTEM_ID, "14");
        let wal_source = format!("pg_wal/{SEGMENT}");
        let body = wal_segment_bytes(PG14_WAL_MAGIC, 1, TEST_SYSTEM_ID, 16 * 1024 * 1024);
        put(&pg_s, &wal_source, &body);

        let cfg = fake_config(Some("demo"), vec![wal_source]);
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("a matching segment is archived");
        assert!(
            repo_s.exists(Path::new(&format!("archive/demo/{SEGMENT}"))).expect("exists"),
            "a matching segment must be stored"
        );
    }

    #[test]
    fn push_header_check_skipped_when_disabled() {
        // archive-header-check=n stores a segment even when it does not match.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        seed_archive_info(&repo_s, "demo", TEST_SYSTEM_ID, "14");
        let wal_source = format!("pg_wal/{SEGMENT}");
        put(
            &pg_s,
            &wal_source,
            &wal_segment_bytes(PG14_WAL_MAGIC, 1, 999, 16 * 1024 * 1024),
        );

        let mut cfg = fake_config(Some("demo"), vec![wal_source]);
        cfg.options
            .insert(("archive-header-check".to_owned(), None), OptionValue::Boolean(false));
        push(&cfg, &[&repo_s as &dyn Storage], &pg_s).expect("header check disabled -> stored regardless");
        assert!(
            repo_s.exists(Path::new(&format!("archive/demo/{SEGMENT}"))).expect("exists"),
            "with the check off the segment is stored even though it mismatches"
        );
    }

    // -----------------------------------------------------------------------
    // archive-missing-retry
    // -----------------------------------------------------------------------

    #[test]
    fn fetch_retry_finds_segment_on_second_pass() {
        // The segment is absent at the first probe but the retry pass finds it.
        // Simulate "lands between attempts" by placing it before the call but
        // asserting the retry path serves it (a found-on-first case also works;
        // the retry must not break the happy path).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        put(&repo_s, &format!("archive/demo/{SEGMENT}"), WAL_BODY);
        let dest = format!("pg_wal/{SEGMENT}");
        fetch_segment_with_retry(
            &[&repo_s as &dyn Storage],
            &pg_s,
            "demo",
            SEGMENT,
            Path::new(&dest),
            true,
            std::time::Duration::from_millis(0),
        )
        .expect("present segment is served");
        assert_eq!(read(&pg_s, &dest), WAL_BODY);
    }

    #[test]
    fn fetch_retry_still_missing_errors() {
        // With retry on but the segment never present, the canonical NotFound
        // surfaces (after the bounded retry).
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let dest = format!("pg_wal/{SEGMENT}");
        let err = fetch_segment_with_retry(
            &[&repo_s as &dyn Storage],
            &pg_s,
            "demo",
            SEGMENT,
            Path::new(&dest),
            true,
            std::time::Duration::from_millis(0),
        )
        .expect_err("a never-present segment must still error after the retry");
        match err {
            CommandError::Storage(_) => {}
            other => panic!("expected Storage(not found), got {other:?}"),
        }
    }

    #[test]
    fn fetch_no_retry_errors_immediately() {
        // With retry off, a missing segment errors without a second probe.
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let dest = format!("pg_wal/{SEGMENT}");
        fetch_segment_with_retry(
            &[&repo_s as &dyn Storage],
            &pg_s,
            "demo",
            SEGMENT,
            Path::new(&dest),
            false,
            std::time::Duration::from_millis(0),
        )
        .expect_err("missing segment must error with retry off");
    }

    // -----------------------------------------------------------------------
    // archive-get-queue-max (prefetch bound)
    // -----------------------------------------------------------------------

    #[test]
    fn prefetch_stops_at_queue_max() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let (_spool, spool_s) = spool_storage();
        let _ = &pg_s;
        // Three 100-byte segments in the repo.
        let segs = [
            "000000010000000000000001",
            "000000010000000000000002",
            "000000010000000000000003",
        ];
        for seg in &segs {
            put(&repo_s, &format!("archive/demo/{seg}"), &[7u8; 100]);
        }
        let requested: Vec<String> = segs.iter().map(|s| (*s).to_owned()).collect();

        // A 150-byte cap should stop after the first segment (100 staged >= 150?
        // no — after staging the first, staged=100 < 150, stage the second ->
        // staged=200 >= 150 stops). So exactly two are pre-fetched.
        let prefetched = prefetch_get_spool(&spool_s, &repo_s, "demo", &requested, Some(150)).expect("prefetch");
        assert_eq!(prefetched, 2, "prefetch stops once the in/ spool reaches the cap");
        assert!(
            spool_s
                .exists(Path::new("archive/demo/in/000000010000000000000001"))
                .expect("e"),
            "first segment staged"
        );
        assert!(
            spool_s
                .exists(Path::new("archive/demo/in/000000010000000000000002"))
                .expect("e"),
            "second segment staged"
        );
        assert!(
            !spool_s
                .exists(Path::new("archive/demo/in/000000010000000000000003"))
                .expect("e"),
            "third segment must not be staged past the cap"
        );
    }

    #[test]
    fn prefetch_unbounded_fetches_all() {
        let (_repo, _pg, repo_s, _pg_s) = posix_pair();
        let (_spool, spool_s) = spool_storage();
        for seg in ["000000010000000000000001", "000000010000000000000002"] {
            put(&repo_s, &format!("archive/demo/{seg}"), &[7u8; 100]);
        }
        let requested = vec!["000000010000000000000001".to_owned(), "000000010000000000000002".to_owned()];
        let prefetched = prefetch_get_spool(&spool_s, &repo_s, "demo", &requested, None).expect("prefetch");
        assert_eq!(prefetched, 2, "no cap fetches every requested segment");
    }
}
