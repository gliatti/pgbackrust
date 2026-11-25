//! `verify` command — confirm whole-repository integrity.
//!
//! C reference: `src/command/verify/verify.c` (+ `src/command/verify/file.c`).
//! `verify` walks the repository and reports every integrity problem it finds
//! rather than aborting on the first. The pass has three stages, mirroring the
//! C `verifyProcess`:
//!
//! 1. **Info-file consistency.** Load `backup/<stanza>/backup.info` and
//!    `archive/<stanza>/archive.info` and confirm they describe the same
//!    cluster: the active database identity (`db-id` / `db-system-id` /
//!    `db-version`) and the `[db:history]` lists must agree. C ref:
//!    `verifyPgHistory`. (A missing `archive.info` is tolerated — a repo can
//!    legitimately hold only backups — and recorded as an informational
//!    problem rather than aborting.)
//! 2. **Backup files.** For every backup in `[backup:current]` (or just the
//!    `--set` backup), load its `backup.manifest` and re-read every
//!    checksummed file, recomputing its SHA-1 and comparing to the recorded
//!    value. A file whose manifest entry carries a `reference` is read from the
//!    backup that physically holds its bytes
//!    (`backup/<stanza>/<reference>/<path>`), exactly as restore resolves
//!    differential / incremental references. On an **encrypted** repository the
//!    info files, each `backup.manifest`, and the file data are decrypted with
//!    the same keys restore uses — the user passphrase (`repo-cipher-pass`) for
//!    the info files and the repository sub-key recovered from `archive.info`'s
//!    `[cipher]` section for the manifest + data — before the SHA-1 is
//!    recomputed, so a healthy encrypted repo verifies clean instead of being
//!    re-hashed as ciphertext. Missing files and size mismatches are detected
//!    too. C ref: `verifyFile`.
//! 3. **WAL archive.** Walk `archive/<stanza>/` and verify every WAL segment.
//!    The C implementation lays archives out as
//!    `archive/<archive-id>/<wal-path>/<segment>-<sha1>` and verifies the
//!    SHA-1 encoded in the filename; this fork currently writes a **flat**
//!    `archive/<stanza>/<segment>` layout with no checksum in the name (see
//!    `archive.rs`). So when a segment filename carries a `-<40-hex>` suffix
//!    its embedded checksum is verified; otherwise the segment is verified for
//!    presence + readability and the missing-checksum gap is recorded as a
//!    note on the result.
//!
//! Corruption is **collected, not thrown**: a verify run that finds damage
//! still completes and reports every problem it found. [`verify_inner`] always
//! returns a [`VerifyReport`]; only structural failures — an absent
//! `--stanza`, an unreadable / malformed `backup.info`, or an unreadable
//! `backup.manifest` — bubble up as a [`CommandError`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoArchive, InfoBackup, InfoError, Manifest};
use pgbr_io::{Filter, IoRead, Sha1};
use pgbr_protocol::message::{OkResponse, Request, Response};
use pgbr_protocol::parallel::{Job, ParallelExecutor};
use pgbr_storage::{Storage, StorageError, StorageKind};
use serde_json::json;

use crate::CommandError;
use crate::backup::JobRetry;
use crate::pipeline::RepoTransform;

/// Length of a SHA-1 digest rendered as lowercase hexadecimal.
const SHA1_HEX_LEN: usize = 40;

/// A single integrity problem found while verifying a backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyProblem {
    /// The manifest references a file that is not present in the repository.
    MissingFile {
        /// Backup label the file belongs to.
        backup: String,
        /// Manifest-relative path of the missing file.
        path: String,
    },
    /// The file exists but its recomputed SHA-1 does not match the manifest.
    ChecksumMismatch {
        /// Backup label the file belongs to.
        backup: String,
        /// Manifest-relative path of the file.
        path: String,
        /// Checksum recorded in the manifest.
        expected: String,
        /// Checksum recomputed from the on-disk file.
        actual: String,
    },
    /// The file exists but its on-disk size does not match the manifest.
    SizeMismatch {
        /// Backup label the file belongs to.
        backup: String,
        /// Manifest-relative path of the file.
        path: String,
        /// Size recorded in the manifest.
        expected: u64,
        /// Size of the on-disk file.
        actual: u64,
    },
}

impl VerifyProblem {
    /// Backup label this problem is attributed to.
    #[must_use]
    pub fn backup(&self) -> &str {
        match self {
            Self::MissingFile { backup, .. } | Self::ChecksumMismatch { backup, .. } | Self::SizeMismatch { backup, .. } => backup,
        }
    }

    /// Manifest-relative path this problem is attributed to.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::MissingFile { path, .. } | Self::ChecksumMismatch { path, .. } | Self::SizeMismatch { path, .. } => path,
        }
    }
}

/// Per-backup verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerify {
    /// Backup label, e.g. `"20240101-120000F"`.
    pub label: String,
    /// Total number of checksummed files inspected in this backup.
    pub total: usize,
    /// Number of files that re-read clean (correct size + checksum).
    pub valid: usize,
    /// Human-readable problem descriptions for this backup, in discovery order.
    pub errors: Vec<String>,
}

/// A single archive (WAL) segment problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveProblem {
    /// A segment whose filename embeds a SHA-1 (`<segment>-<sha1>`) failed its
    /// checksum check.
    ChecksumMismatch {
        /// Segment filename, relative to `archive/<stanza>/`.
        segment: String,
        /// Checksum encoded in the filename.
        expected: String,
        /// Checksum recomputed from the segment's bytes.
        actual: String,
    },
    /// A segment that was listed but could not be read back.
    Unreadable {
        /// Segment filename, relative to `archive/<stanza>/`.
        segment: String,
        /// Backend error message.
        message: String,
    },
}

/// WAL-archive verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveVerify {
    /// Total number of WAL segments found under `archive/<stanza>/`.
    pub total: usize,
    /// Number of segments verified clean.
    pub valid: usize,
    /// Number of segments whose checksum could be verified from the filename.
    pub checksum_verified: usize,
    /// Number of segments present + readable but with no embedded checksum to
    /// verify (the flat-layout gap; see the module docs).
    pub presence_only: usize,
    /// Problems found while verifying segments, in discovery order.
    pub problems: Vec<ArchiveProblem>,
}

/// Result of a [`verify_inner`] pass — the whole-repository report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of backups whose manifests were inspected.
    pub backups_checked: usize,
    /// Number of checksummed files that were re-read and compared (across all
    /// backups).
    pub files_checked: usize,
    /// Every backup-file integrity problem found, in the order discovered.
    pub problems: Vec<VerifyProblem>,
    /// Per-backup structured results.
    pub backups: Vec<BackupVerify>,
    /// WAL-archive verification result.
    pub archive: ArchiveVerify,
    /// Repository-level consistency notes (info-file disagreements, a missing
    /// `archive.info`, etc.). Non-fatal: recorded, not thrown.
    pub info_problems: Vec<String>,
}

impl VerifyReport {
    /// Total problem count across info, backup-file, and archive stages.
    #[must_use]
    pub const fn total_problems(&self) -> usize {
        self.info_problems.len() + self.problems.len() + self.archive.problems.len()
    }
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

fn archive_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/archive.info"))
}

fn manifest_path(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/backup.manifest"))
}

fn backup_file_path(stanza: &str, label: &str, file: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/{file}"))
}

fn archive_dir(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}"))
}

/// `--set` lookup. Returns the requested single-backup label, or `None`
/// when the option is absent (verify every backup in `backup.info`).
fn requested_set(config: &LoadedConfig) -> Option<&str> {
    match config.options.get(&("set".to_owned(), None)) {
        Some(OptionValue::String(label)) => Some(label.as_str()),
        _ => None,
    }
}

/// Resolve the set of backup labels to verify. With `--set`, just that one
/// (whether or not it appears in `backup.info`). Without, every label in
/// `backup/<stanza>/backup.info`'s `[backup:current]` block.
fn select_backups(config: &LoadedConfig, info: &InfoBackup) -> Vec<String> {
    if let Some(label) = requested_set(config) {
        return vec![label.to_owned()];
    }
    info.current.keys().cloned().collect()
}

/// Load `backup.info`, mapping a missing file / parse failure to a structural
/// [`CommandError`] (verify cannot proceed without it).
///
/// `backup.info` is encrypted directly under the user passphrase on an encrypted
/// repository, so it is loaded keyed with `user_pass` (`None` on an unencrypted
/// repo → the plaintext path). The recovered `[cipher]` sub-key ride-along is
/// dropped here; verify resolves the sub-key once, up front, via
/// [`crate::cipher::active_sub_key`].
fn load_backup_info(repo: &dyn Storage, stanza: &str, user_pass: Option<&str>) -> Result<InfoBackup, CommandError> {
    InfoBackup::load_keyed(repo, &backup_info_path(stanza), user_pass)
        .map(|(info, _sub_key)| info)
        .map_err(|err| match err {
            InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
                path: backup_info_path(stanza),
            }),
            other => CommandError::Other(other.to_string()),
        })
}

/// Verify the cross-file consistency of `backup.info` and `archive.info`, the
/// way C's `verifyPgHistory` does. A missing `archive.info` is tolerated (it is
/// recorded as a note, not a hard error, since a repository can legitimately
/// hold only backups); a malformed one is recorded too. Any disagreement on the
/// active database identity or the history lists is appended to `notes`.
///
/// `archive.info`, like `backup.info`, is encrypted directly under the user
/// passphrase, so it is loaded keyed with `user_pass` (`None` → plaintext path).
fn verify_info_consistency(
    repo: &dyn Storage,
    stanza: &str,
    backup: &InfoBackup,
    user_pass: Option<&str>,
    notes: &mut Vec<String>,
) {
    let archive = match InfoArchive::load_keyed(repo, &archive_info_path(stanza), user_pass).map(|(archive, _sub_key)| archive) {
        Ok(archive) => archive,
        Err(InfoError::Storage(StorageError::NotFound { .. })) => {
            notes.push("archive.info is missing; skipping archive/backup history consistency check".to_owned());
            return;
        }
        Err(err) => {
            notes.push(format!("archive.info is unusable: {err}"));
            return;
        }
    };

    // Active database identity must match between the two files (verify treats
    // the database as inaccessible, so it cannot tell which would be right).
    if archive.db_id != backup.db_id || archive.db_system_id != backup.db_system_id || archive.db_version != backup.db_version {
        notes.push(format!(
            "backup info db mismatch: backup.info db-id={} system-id={} version={} but \
             archive.info db-id={} system-id={} version={}",
            backup.db_id, backup.db_system_id, backup.db_version, archive.db_id, archive.db_system_id, archive.db_version,
        ));
    }

    // The full history lists must match (same db-ids → same {system-id, version}).
    if archive.history != backup.history {
        notes.push("archive and backup history lists do not match".to_owned());
    }
}

/// Recompute the SHA-1 of a repository file, reversing the on-disk transform
/// first so the digest matches the **plaintext** SHA-1 the manifest records.
///
/// The backup writer takes the SHA-1 over the plaintext before applying the
/// compress / encrypt chain (see `backup::plaintext_sha1` and
/// `RepoTransform::apply_forward_keyed`), so verify must reverse the chain
/// before hashing — otherwise every compressed or encrypted clean file would
/// flip from `MissingFile` to `ChecksumMismatch`. The returned size is the
/// **plaintext** size, which is what the manifest's `size` field records too.
fn hash_repo_file_reversed(repo: &dyn Storage, path: &Path, transform: &RepoTransform) -> Result<(String, u64), CommandError> {
    let mut reader: Box<dyn IoRead> = repo.open_read(path)?;
    let raw = reader.read_all()?;
    // The backup writer uses the keyed (SHA-1 KDF) chain, so reverse the same
    // way. With an identity transform (no compression, no cipher) this is a
    // pass-through and the digest matches what the legacy helper produced.
    let plaintext = transform.apply_reverse_keyed(&raw)?;
    Ok((sha1_hex(&plaintext), plaintext.len() as u64))
}

/// Resolve the [`RepoTransform`] a backup holder applied to its on-disk bytes,
/// caching one lookup per holder label across a verify pass.
///
/// A manifest entry's `reference = Some(other_label)` means the bytes live in
/// `other_label`'s directory and were written with **that** backup's transform,
/// not the backup being verified. Stock pgBackRust's restore looks the holder's
/// `compress-type` / `encrypted` flags up in `backup.info`'s `[backup:current]`
/// entry for that label; verify mirrors the same lookup, and — exactly like
/// restore ([`RepoTransform::from_metadata_checked`]) — injects the resolved
/// repository `sub_key` so the reverse chain actually decrypts the holder's
/// bytes. Without the key an encrypted holder would be re-hashed as ciphertext
/// and flagged as corrupt.
///
/// When the holder is not listed in `backup.info` (a stray reference the info
/// file did not record) we fall back to the identity transform, the same
/// conservative default `from_metadata_checked` yields with no recorded
/// compress / encrypt flags. An encrypted holder with no resolvable `sub_key`
/// is a hard error (mirroring restore), not a silent ciphertext hash.
fn transform_for_holder<'a>(
    holder: &str,
    info: &InfoBackup,
    config: &LoadedConfig,
    sub_key: Option<&str>,
    cache: &'a mut HashMap<String, RepoTransform>,
) -> Result<&'a RepoTransform, CommandError> {
    if !cache.contains_key(holder) {
        let transform = match info.current.get(holder) {
            Some(entry) => RepoTransform::from_metadata_checked(entry, config, sub_key)?,
            None => RepoTransform::identity(),
        };
        cache.insert(holder.to_owned(), transform);
    }
    // Just inserted (or already present); the lookup cannot miss.
    cache
        .get(holder)
        .ok_or_else(|| CommandError::Other(format!("verify: transform cache miss for holder `{holder}`")))
}

/// SHA-1 of `bytes` as lowercase hex, computed exactly the way verify compares.
fn sha1_hex(bytes: &[u8]) -> String {
    let mut sha = Sha1::new();
    let mut sink = Vec::new();
    // Sha1::process never fails for a plain byte slice; map the (impossible)
    // error to an empty digest so this helper stays infallible for callers.
    if sha.process(bytes, &mut sink).is_err() {
        return String::new();
    }
    sha.digest_hex()
}

/// Number of parallel hash workers, from the resolved `process-max` option.
///
/// Mirrors [`crate::backup::process_max`] verbatim: `process-max` is an
/// `Integer` (default 1). Values `<= 0` clamp to one worker so the verify pass
/// always makes progress; the dispatcher additionally caps the thread count at
/// the number of files to hash.
fn process_max(config: &LoadedConfig) -> usize {
    match config.options.get(&("process-max".to_owned(), None)) {
        Some(OptionValue::Integer(value)) if *value >= 1 => usize::try_from(*value).unwrap_or(1),
        _ => 1,
    }
}

/// A single per-file unit of work for the verify hasher: the manifest-relative
/// path (used as the dispatcher correlation key and as the user-visible path in
/// any [`VerifyProblem`]), the storage-relative path of the on-disk file
/// (suffix included, used by the non-local serial path through
/// [`Storage::open_read`]), the absolute path of that same file (used by the
/// local parallel `std::fs` path), the holder backup label (the key into the
/// per-pass [`RepoTransform`] map shared with the workers), and the expected
/// plaintext size + SHA-1 from the manifest so the main thread can build
/// [`VerifyProblem`] entries from the worker's primitive (sha, size) reply.
#[derive(Debug, Clone)]
struct VerifyJob {
    /// Manifest-relative path, e.g. `pg_data/base/1/1259`. Echoed back as the
    /// [`pgbr_protocol::parallel::JobResult::key`] for correlation.
    rel: String,
    /// Storage-relative on-disk path (suffix included), used by the serial
    /// (non-local) fallback through the [`Storage`] trait.
    storage_path: PathBuf,
    /// Absolute on-disk path (suffix included), used by the parallel local
    /// `std::fs` path. Empty / meaningless on the non-local serial path.
    abs_path: PathBuf,
    /// Holder backup label — the key into the shared `Arc<HashMap<String,
    /// RepoTransform>>` the workers look up to reverse the on-disk transform.
    holder: String,
    /// Plaintext SHA-1 the manifest recorded for this file.
    expected_sha: String,
    /// Plaintext size the manifest recorded for this file.
    expected_size: u64,
}

/// Per-file result from a verify worker: the plaintext SHA-1 + size recomputed
/// from the on-disk bytes. Both stay primitives so they can ride through the
/// dispatcher's JSON `Response` without serialising the [`RepoTransform`] or
/// the [`VerifyProblem`] enum (neither of which implements `Serialize`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifyResult {
    /// SHA-1 of the reversed (plaintext) bytes, lowercase hex.
    actual_sha: String,
    /// Length of the reversed (plaintext) bytes.
    actual_size: u64,
}

/// Encode a [`VerifyJob`] as a dispatcher [`Request`]: the job's `rel` path is
/// the `cmd` (and the dispatcher correlation key), and three JSON strings ride
/// in `param` — the absolute on-disk path, the holder label, and the
/// transform's repo suffix. The transform itself is NOT serialised; workers
/// look it up by holder in the [`Arc<HashMap<String, RepoTransform>>`] the
/// worker closure captures.
fn verify_job_to_request(job: &VerifyJob) -> Request {
    Request {
        cmd: job.rel.clone(),
        param: vec![
            json!(job.abs_path.to_string_lossy()),
            json!(job.holder),
            json!(job.storage_path.to_string_lossy()),
        ],
    }
}

/// Decode a [`Request`] produced by [`verify_job_to_request`] inside a worker.
///
/// Only the worker-side fields — `abs_path`, `holder`, and the storage-relative
/// path used as the third primitive — are extracted; the other [`VerifyJob`]
/// fields (`expected_sha`, `expected_size`) are kept on the main thread where
/// [`VerifyProblem`] entries are built.
fn request_to_verify_job(request: &Request) -> Result<(PathBuf, String, PathBuf), String> {
    let abs_path = request
        .param
        .first()
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "verify job missing abs path".to_owned())?;
    let holder = request
        .param
        .get(1)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "verify job missing holder".to_owned())?;
    let storage_path = request
        .param
        .get(2)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "verify job missing storage path".to_owned())?;
    Ok((PathBuf::from(abs_path), holder.to_owned(), PathBuf::from(storage_path)))
}

/// Run every [`VerifyJob`] across `process-max` workers via the in-process
/// dispatcher, returning each job's [`VerifyResult`] keyed by its `rel` path.
///
/// When `repo.is_local()` is false (any remote/object backend) the parallel
/// `std::fs` path is unsafe — `std::fs::read` would read from the wrong machine
/// or simply find nothing at all — so the jobs run serially on the main thread
/// through [`hash_repo_file_reversed`]. The result list is the identical
/// `(rel, VerifyResult)` shape either way, so the caller is unaffected by
/// which path ran.
///
/// On the local fast path the worker closure captures an
/// `Arc<HashMap<String, RepoTransform>>` (one entry per distinct holder label
/// seen in the backup's manifest, built once on the main thread before the
/// pool is spawned). No [`Storage`] handle and no `&RepoTransform` cross the
/// worker boundary — both would either be `!Send` or fail the
/// `Fn(&Request) -> Result<Response, String> + Send + Sync + 'static` bound the
/// dispatcher requires. The closure only sees primitives off the [`Request`]
/// plus the `Arc<HashMap>` it cloned in.
///
/// `job_retry` wraps each per-file hash: a failed read / decompress is retried
/// up to `job-retry` more times (with `job-retry-interval` between attempts)
/// inside the worker before the job — and the whole verify pass — fails.
//
// `transform_map` is taken by value (rather than by reference) on purpose: the
// parallel branch moves it into the `Fn + Send + Sync + 'static` worker closure
// where the dispatcher will hand it to every thread; a `&Arc<_>` would force an
// extra `Arc::clone` at the call site for the same effect. Clippy flags the
// signature as "not consumed" because the serial branch does not `move` the
// `Arc` anywhere — but the by-value signature is the contract callers see.
#[allow(clippy::needless_pass_by_value)]
fn run_verify_jobs(
    jobs: &[VerifyJob],
    config: &LoadedConfig,
    transform_map: Arc<HashMap<String, RepoTransform>>,
    job_retry: JobRetry,
    repo: &dyn Storage,
) -> Result<Vec<(String, VerifyResult)>, CommandError> {
    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    // Non-local repo: hash every file through the `Storage` trait, serially
    // on this thread. The parallel `std::fs` path below would read from the
    // local machine instead of the remote/object repo, finding either the
    // wrong bytes or no file at all.
    if !repo.is_local() {
        let mut out = Vec::with_capacity(jobs.len());
        for job in jobs {
            let transform = transform_map
                .get(&job.holder)
                .ok_or_else(|| CommandError::Other(format!("verify: unknown holder `{}` for `{}`", job.holder, job.rel)))?;
            let (actual_sha, actual_size) = job_retry.run(|| hash_repo_file_reversed(repo, &job.storage_path, transform))?;
            out.push((job.rel.clone(), VerifyResult { actual_sha, actual_size }));
        }
        return Ok(out);
    }

    let dispatcher_jobs: Vec<Job> = jobs
        .iter()
        .map(|job| Job {
            key: job.rel.clone(),
            request: verify_job_to_request(job),
        })
        .collect();

    // The repo is local here (the serial branch above caught every non-local
    // case), so the parallel `std::fs` fast path is safe. The dispatcher
    // demands a `Send + Sync + 'static` worker, so the closure can only borrow
    // owned data: an `Arc::clone` of the per-holder transform map (cheap,
    // immutable, `Send + Sync`) and whatever rides in each `Request`. No
    // `Storage` handle and no `&RepoTransform` cross the boundary; nothing
    // borrowed from this stack frame escapes.
    let worker_transforms = Arc::clone(&transform_map);
    let results = ParallelExecutor::new(process_max(config)).run(dispatcher_jobs, move |request| {
        let (abs_path, holder, _storage_path) = request_to_verify_job(request)?;
        let transform = worker_transforms
            .get(&holder)
            .ok_or_else(|| format!("verify worker: unknown holder `{holder}`"))?;
        // Retry the read+reverse per `job-retry`: re-read the on-disk file
        // and re-apply the reverse chain on each attempt so a transient I/O
        // blip can recover.
        let (actual_sha, actual_size) = job_retry
            .run(|| -> Result<(String, u64), CommandError> {
                let raw =
                    std::fs::read(&abs_path).map_err(|err| CommandError::Other(format!("read {}: {err}", abs_path.display())))?;
                let plaintext = transform.apply_reverse_keyed(&raw).map_err(CommandError::Io)?;
                Ok((sha1_hex(&plaintext), plaintext.len() as u64))
            })
            .map_err(|err| err.to_string())?;
        Ok(Response::Ok(OkResponse {
            out: Some(json!({
                "actual_sha": actual_sha,
                "actual_size": actual_size,
            })),
        }))
    });

    let mut out = Vec::with_capacity(results.len());
    for job_result in results {
        match job_result.result {
            Ok(Response::Ok(OkResponse { out: Some(value) })) => {
                let actual_sha = value
                    .get("actual_sha")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| CommandError::Other(format!("verify of {} returned no checksum", job_result.key)))?
                    .to_owned();
                let actual_size = value
                    .get("actual_size")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| CommandError::Other(format!("verify of {} returned no size", job_result.key)))?;
                out.push((job_result.key, VerifyResult { actual_sha, actual_size }));
            }
            Ok(_) => {
                return Err(CommandError::Other(format!(
                    "verify of {} produced an unexpected empty response",
                    job_result.key
                )));
            }
            Err(message) => return Err(CommandError::Other(message)),
        }
    }
    Ok(out)
}

/// Verify a single backup's manifest, appending any problems found to `report`,
/// counting every checksummed file inspected, and building the per-backup
/// [`BackupVerify`] summary.
///
/// A file whose manifest entry carries a `reference` is read from the backup
/// that physically holds its bytes (`backup/<stanza>/<reference>/<path>`),
/// mirroring restore's differential / incremental reference resolution. The
/// on-disk filename for each file carries the compression suffix the **holder**
/// backup wrote it with (e.g. `.gz` / `.zst`), so the per-holder
/// [`RepoTransform`] is looked up via [`transform_for_holder`] and its
/// [`RepoTransform::repo_suffix`] is appended before the existence check and
/// the hash. The hash itself reverses the same transform so the recomputed
/// digest matches the plaintext SHA-1 the manifest records.
fn verify_backup(
    repo: &dyn Storage,
    stanza: &str,
    label: &str,
    info: &InfoBackup,
    config: &LoadedConfig,
    sub_key: Option<&str>,
    report: &mut VerifyReport,
) -> Result<(), CommandError> {
    // The `backup.manifest` is encrypted with the repository sub-key (not the
    // user passphrase), the same key the backup wrote it with. `load_keyed` with
    // `sub_key = None` is the byte-for-byte plaintext path for an unencrypted
    // repo, so existing behaviour is unchanged there.
    let manifest = Manifest::load_keyed(repo, &manifest_path(stanza, label), sub_key).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => CommandError::Storage(StorageError::NotFound {
            path: manifest_path(stanza, label),
        }),
        other => CommandError::Other(other.to_string()),
    })?;

    report.backups_checked += 1;

    let mut summary = BackupVerify {
        label: label.to_owned(),
        total: 0,
        valid: 0,
        errors: Vec::new(),
    };

    // One transform lookup per distinct holder label seen in this backup's
    // manifest (typically the backup itself plus one referenced full / diff).
    // The same map is what the worker pool ultimately holds via `Arc`.
    let mut transforms: HashMap<String, RepoTransform> = HashMap::new();

    // Files whose existence check passes get a `VerifyJob`. Missing files are
    // reported immediately (the existence check is cheap, runs once per file,
    // and lives on the main thread because it needs the `Storage` handle).
    let mut jobs: Vec<VerifyJob> = Vec::new();
    let local_repo = repo.is_local();

    for file in &manifest.files {
        // Zero-length files carry no checksum; nothing to re-read.
        let Some(expected) = file.checksum.as_deref() else {
            continue;
        };

        report.files_checked += 1;
        summary.total += 1;

        // A referenced file's bytes live in the backup named by `reference`;
        // otherwise they live in this backup's own directory. The on-disk
        // filename carries that backup's compression suffix.
        let holder = file.reference.as_deref().unwrap_or(label);
        let transform = transform_for_holder(holder, info, config, sub_key, &mut transforms)?.clone();
        let suffixed = format!("{}{}", file.path, transform.repo_suffix());
        let path = backup_file_path(stanza, holder, &suffixed);

        if !repo.exists(&path)? {
            // The user-visible path is the manifest-relative one (the source
            // path), not the on-disk `.gz` variant — mirror stock pgBackRust's
            // verify reporting, which names what users put into the cluster.
            let problem = VerifyProblem::MissingFile {
                backup: label.to_owned(),
                path: file.path.clone(),
            };
            summary.errors.push(describe_problem(&problem));
            report.problems.push(problem);
            continue;
        }

        // The parallel `std::fs` worker needs the *absolute* path; the serial
        // `Storage::open_read` path needs only the storage-relative one. Skip
        // the `info()` round-trip on a non-local repo where the result would
        // be unused (and, for some backends, racy or expensive).
        let abs_path = if local_repo { repo.info(&path)?.path } else { PathBuf::new() };

        jobs.push(VerifyJob {
            rel: file.path.clone(),
            storage_path: path,
            abs_path,
            holder: holder.to_owned(),
            expected_sha: expected.to_owned(),
            expected_size: file.size,
        });
    }

    // Side table: the original `VerifyJob` keyed by its `rel` path, so the
    // main thread can rebuild a [`VerifyProblem`] (which is not `Serialize`)
    // from the worker's primitive `(actual_sha, actual_size)` reply. The
    // `manifest.files` loop already enforces one `rel` per backup, so this is
    // a unique key.
    let job_index: HashMap<&str, &VerifyJob> = jobs.iter().map(|j| (j.rel.as_str(), j)).collect();

    // Wrap the per-holder transform map for the worker pool. `Arc<HashMap<_,_>>`
    // is `Send + Sync` and `Clone` is O(1), so the closure captures it cheaply
    // by move while the main thread keeps its own handle.
    let transform_map = Arc::new(transforms);
    let job_retry = JobRetry::from_options(config);
    let results = run_verify_jobs(&jobs, config, transform_map, job_retry, repo)?;

    // Workers reply with primitives; the main thread reconstructs
    // [`VerifyProblem`] (not `Serialize`) from the (sha, size) pair plus the
    // expected fields stashed on each `VerifyJob` before the pool ran.
    for (rel, result) in results {
        let job = job_index
            .get(rel.as_str())
            .ok_or_else(|| CommandError::Other(format!("verify result for unknown file `{rel}` in backup `{label}`")))?;

        let mut file_ok = true;

        if result.actual_size != job.expected_size {
            file_ok = false;
            let problem = VerifyProblem::SizeMismatch {
                backup: label.to_owned(),
                path: rel.clone(),
                expected: job.expected_size,
                actual: result.actual_size,
            };
            summary.errors.push(describe_problem(&problem));
            report.problems.push(problem);
        }

        if result.actual_sha != job.expected_sha {
            file_ok = false;
            let problem = VerifyProblem::ChecksumMismatch {
                backup: label.to_owned(),
                path: rel.clone(),
                expected: job.expected_sha.clone(),
                actual: result.actual_sha,
            };
            summary.errors.push(describe_problem(&problem));
            report.problems.push(problem);
        }

        if file_ok {
            summary.valid += 1;
        }
    }

    report.backups.push(summary);
    Ok(())
}

/// Render a [`VerifyProblem`] as a one-line, user-facing string (also used to
/// populate the per-backup `errors` list).
fn describe_problem(problem: &VerifyProblem) -> String {
    match problem {
        VerifyProblem::MissingFile { backup, path } => format!("missing: {backup}/{path}"),
        VerifyProblem::ChecksumMismatch {
            backup,
            path,
            expected,
            actual,
        } => format!("checksum mismatch: {backup}/{path} (expected {expected}, got {actual})"),
        VerifyProblem::SizeMismatch {
            backup,
            path,
            expected,
            actual,
        } => format!("size mismatch: {backup}/{path} (expected {expected}, got {actual})"),
    }
}

/// If `segment` carries a trailing `-<40-hex>` SHA-1 (the C archive layout),
/// split it into `(base_segment, checksum)`. Returns `None` for the flat-layout
/// names this fork writes, which have no embedded checksum.
fn split_segment_checksum(segment: &str) -> Option<(&str, &str)> {
    // Strip any compression suffix before inspecting (e.g. `...-<sha1>.gz`).
    let core = segment.split('.').next().unwrap_or(segment);
    let (base, candidate) = core.rsplit_once('-')?;
    if candidate.len() == SHA1_HEX_LEN && candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some((base, candidate))
    } else {
        None
    }
}

/// Verify the WAL archive under `archive/<stanza>/`. Each regular file is a WAL
/// segment: if its filename embeds a SHA-1 the checksum is verified, otherwise
/// the segment is verified for presence + readability. `archive.info` and any
/// directory entries are skipped. A missing archive directory yields an empty
/// (all-zero) result — nothing to verify is not a problem.
fn verify_archive(repo: &dyn Storage, stanza: &str) -> Result<ArchiveVerify, CommandError> {
    let mut result = ArchiveVerify {
        total: 0,
        valid: 0,
        checksum_verified: 0,
        presence_only: 0,
        problems: Vec::new(),
    };

    let dir = archive_dir(stanza);
    let entries = match repo.list(&dir) {
        Ok(entries) => entries,
        Err(StorageError::NotFound { .. }) => return Ok(result),
        Err(err) => return Err(CommandError::Storage(err)),
    };

    for entry in entries {
        if entry.kind != StorageKind::File {
            continue;
        }

        let name = entry
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .map_or_else(|| entry.path.display().to_string(), str::to_owned);

        // `archive.info` / `archive.info.copy` are metadata, not WAL segments.
        if name.starts_with("archive.info") {
            continue;
        }

        result.total += 1;

        // Read the segment back (so an unreadable file is caught either way).
        let bytes = match repo.open_read(&entry.path).and_then(|mut r| Ok(r.read_all()?)) {
            Ok(bytes) => bytes,
            Err(err) => {
                result.problems.push(ArchiveProblem::Unreadable {
                    segment: name.clone(),
                    message: err.to_string(),
                });
                continue;
            }
        };

        // Own the embedded checksum (if any) so `name` is free to move into a
        // problem below without an outstanding borrow into it.
        let embedded = split_segment_checksum(&name).map(|(_, sha)| sha.to_owned());
        if let Some(expected) = embedded {
            let actual = sha1_hex(&bytes);
            if actual == expected {
                result.valid += 1;
                result.checksum_verified += 1;
            } else {
                result.problems.push(ArchiveProblem::ChecksumMismatch {
                    segment: name,
                    expected,
                    actual,
                });
            }
        } else {
            // Flat layout: present + readable is the best we can assert.
            result.valid += 1;
            result.presence_only += 1;
        }
    }

    Ok(result)
}

/// Core verification pass over the whole repository.
///
/// The thin [`verify`] entry point prints the report and maps a non-empty
/// problem list to a non-zero exit; tests assert against the [`VerifyReport`]
/// directly.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] if `backup.info` or a selected backup's
///   `backup.manifest` is absent, or for backend read failures.
/// - [`CommandError::Io`] for stream failures while re-reading files.
/// - [`CommandError::Other`] if `backup.info` / `backup.manifest` is malformed.
pub fn verify_inner(config: &LoadedConfig, repo: &dyn Storage) -> Result<VerifyReport, CommandError> {
    let stanza = require_stanza(config)?;

    let mut report = VerifyReport {
        backups_checked: 0,
        files_checked: 0,
        problems: Vec::new(),
        backups: Vec::new(),
        archive: ArchiveVerify {
            total: 0,
            valid: 0,
            checksum_verified: 0,
            presence_only: 0,
            problems: Vec::new(),
        },
        info_problems: Vec::new(),
    };

    // Repository encryption keys (both `None` for an unencrypted repo, the
    // common case, so every keyed load below falls back to the plaintext path):
    //
    // - `user_pass` (`repo-cipher-pass`) decrypts the info files themselves
    //   (`backup.info` / `archive.info`), which are keyed directly off the user
    //   passphrase.
    // - `sub_key` is the repository sub-key recovered from `archive.info`'s
    //   `[cipher]` section; it decrypts each `backup.manifest` and the backed-up
    //   file data — exactly the key restore resolves via
    //   [`crate::cipher::active_sub_key`]. Without it verify would re-hash
    //   ciphertext and flag a healthy encrypted repo as corrupt.
    let user_pass = crate::cipher::active_user_pass(config)?;
    let sub_key = crate::cipher::active_sub_key(repo, config, stanza)?;

    // Stage 1: info-file consistency.
    let info = load_backup_info(repo, stanza, user_pass.as_deref())?;
    verify_info_consistency(repo, stanza, &info, user_pass.as_deref(), &mut report.info_problems);

    // Stage 2: per-backup files (with reference resolution).
    let labels = select_backups(config, &info);
    for label in &labels {
        verify_backup(repo, stanza, label, &info, config, sub_key.as_deref(), &mut report)?;
    }

    // Stage 3: WAL archive.
    report.archive = verify_archive(repo, stanza)?;

    Ok(report)
}

/// `verify` — confirm whole-repository integrity.
///
/// Runs [`verify_inner`], prints a structured summary plus a line per problem,
/// and returns `Ok(())` when the repository is clean. When any problem is found
/// it returns [`CommandError::Other`] so the CLI exit code reflects the
/// corruption — the verification itself still completed (C ref: `cmdVerify`
/// throws `RuntimeError` only after rendering the full report).
///
/// # Errors
///
/// Forwards every structural error from [`verify_inner`], and returns
/// [`CommandError::Other`] when one or more integrity problems were found.
#[allow(clippy::print_stdout)]
pub fn verify(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let report = verify_inner(config, repo_storage)?;

    println!(
        "verify: {} backup(s), {} file(s) checked, {} WAL segment(s), {} problem(s)",
        report.backups_checked,
        report.files_checked,
        report.archive.total,
        report.total_problems(),
    );

    for note in &report.info_problems {
        println!("  info: {note}");
    }

    for backup in &report.backups {
        println!("  backup {}: {}/{} file(s) valid", backup.label, backup.valid, backup.total);
        for err in &backup.errors {
            println!("    {err}");
        }
    }

    println!(
        "  archive: {}/{} segment(s) valid ({} checksum-verified, {} presence-only)",
        report.archive.valid, report.archive.total, report.archive.checksum_verified, report.archive.presence_only,
    );
    for problem in &report.archive.problems {
        match problem {
            ArchiveProblem::ChecksumMismatch {
                segment,
                expected,
                actual,
            } => println!("    checksum mismatch: {segment} (expected {expected}, got {actual})"),
            ArchiveProblem::Unreadable { segment, message } => {
                println!("    unreadable: {segment} ({message})");
            }
        }
    }

    let total = report.total_problems();
    if total == 0 {
        Ok(())
    } else {
        Err(CommandError::Other(format!(
            "{total} fatal error(s) encountered, see output for details"
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup, Manifest, ManifestFile};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use super::{ArchiveProblem, VerifyProblem, split_segment_checksum, verify_inner};
    use crate::CommandError;

    /// SHA-1 of `bytes`, computed exactly the way `verify` recomputes it, so
    /// test fixtures record the digest verify will compare against.
    fn sha1_hex(bytes: &[u8]) -> String {
        super::sha1_hex(bytes)
    }

    fn cfg(stanza: Option<&str>, set: Option<&str>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(label) = set {
            options.insert(("set".to_owned(), None), OptionValue::String(label.to_owned()));
        }
        LoadedConfig {
            command: "verify".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    fn empty_repo() -> (TempDir, Posix) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(dir.path());
        (dir, storage)
    }

    /// Seed `backup/<stanza>/backup.info` listing every `(label, type)`.
    fn seed_backup_info(repo: &Posix, stanza: &str, labels: &[&str]) {
        let mut current = BTreeMap::new();
        for label in labels {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
                    "backup-timestamp-stop": 1_704_110_410_i64,
                    "backup-type": "full",
                }),
            );
        }

        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );

        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        };

        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup/<stanza>");
        info.save(repo, &super::backup_info_path(stanza)).expect("save backup.info");
    }

    /// Seed an `archive/<stanza>/archive.info` matching `seed_backup_info`'s
    /// cluster identity / history so the consistency check passes.
    fn seed_archive_info(repo: &Posix, stanza: &str) {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        let archive = InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            history,
        };
        repo.create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive/<stanza>");
        archive
            .save(repo, &super::archive_info_path(stanza))
            .expect("save archive.info");
    }

    /// Write a `backup.manifest` for `label` referencing the given files.
    fn seed_manifest(repo: &Posix, stanza: &str, label: &str, files: Vec<ManifestFile>) {
        let manifest = Manifest {
            backup_label: label.to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files,
            option_checksum_page: None,
            paths: Vec::new(),
            links: Vec::new(),
        };
        repo.create_path(Path::new(&format!("backup/{stanza}/{label}")), true)
            .expect("create backup label dir");
        manifest
            .save(repo, &super::manifest_path(stanza, label))
            .expect("save manifest");
    }

    /// Materialise a captured backup file under `backup/<stanza>/<label>/<rel>`.
    fn write_backup_file(repo: &Posix, stanza: &str, label: &str, rel: &str, bytes: &[u8]) {
        // Ensure parent directories exist for nested paths.
        if let Some(parent) = Path::new(&format!("backup/{stanza}/{label}/{rel}")).parent() {
            repo.create_path(parent, true).expect("create parent dir");
        }
        let mut w = repo
            .open_write(&super::backup_file_path(stanza, label, rel))
            .expect("open backup file");
        w.write(bytes).expect("write backup file");
        w.close().expect("close backup file");
    }

    /// Write a WAL segment under `archive/<stanza>/<segment>`.
    fn write_archive_segment(repo: &Posix, stanza: &str, segment: &str, bytes: &[u8]) {
        repo.create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive dir");
        let mut w = repo
            .open_write(Path::new(&format!("archive/{stanza}/{segment}")))
            .expect("open segment");
        w.write(bytes).expect("write segment");
        w.close().expect("close segment");
    }

    fn file_entry(path: &str, bytes: &[u8], checksum: Option<String>) -> ManifestFile {
        ManifestFile {
            path: path.to_owned(),
            size: bytes.len() as u64,
            timestamp: 1_704_110_400,
            checksum,
            checksum_page: None,
            reference: None,
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        }
    }

    /// Like [`file_entry`] but the bytes physically live in `reference`.
    fn referenced_entry(path: &str, bytes: &[u8], reference: &str) -> ManifestFile {
        ManifestFile {
            path: path.to_owned(),
            size: bytes.len() as u64,
            timestamp: 1_704_110_400,
            checksum: Some(sha1_hex(bytes)),
            checksum_page: None,
            reference: Some(reference.to_owned()),
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        }
    }

    #[test]
    fn verify_clean_backup_has_no_problems() {
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let a = b"PG_VERSION contents\n";
        let b = b"some heap page bytes \x00\x01\x02";

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![
                file_entry("pg_data/PG_VERSION", a, Some(sha1_hex(a))),
                file_entry("pg_data/base/1/1259", b, Some(sha1_hex(b))),
            ],
        );
        write_backup_file(&repo, "demo", label, "pg_data/PG_VERSION", a);
        write_backup_file(&repo, "demo", label, "pg_data/base/1/1259", b);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert!(report.problems.is_empty(), "clean backup must report no problems: {report:?}");
        assert_eq!(report.files_checked, 2);
        assert_eq!(report.backups_checked, 1);
        assert_eq!(report.backups.len(), 1);
        assert_eq!(report.backups[0].valid, 2);
        assert_eq!(report.backups[0].total, 2);
        assert!(report.backups[0].errors.is_empty());
    }

    #[test]
    fn verify_detects_missing_file() {
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let a = b"present file";
        let b = b"this one is never written to disk";

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![
                file_entry("pg_data/present", a, Some(sha1_hex(a))),
                file_entry("pg_data/absent", b, Some(sha1_hex(b))),
            ],
        );
        write_backup_file(&repo, "demo", label, "pg_data/present", a);
        // "pg_data/absent" intentionally not written.

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.files_checked, 2);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(
            report.problems[0],
            VerifyProblem::MissingFile {
                backup: label.to_owned(),
                path: "pg_data/absent".to_owned(),
            }
        );
        // The per-backup summary names the offending file.
        assert_eq!(report.backups[0].valid, 1);
        assert_eq!(report.backups[0].total, 2);
        assert!(
            report.backups[0].errors.iter().any(|e| e.contains("pg_data/absent")),
            "backup errors must name the missing file: {:?}",
            report.backups[0].errors
        );
    }

    #[test]
    fn verify_detects_checksum_mismatch() {
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let bytes = b"the real file content";
        // Record a checksum that does not match `bytes`, but a size that does
        // so only the checksum problem is reported.
        let wrong = "0000000000000000000000000000000000000000".to_owned();

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![file_entry("pg_data/corrupt", bytes, Some(wrong.clone()))],
        );
        write_backup_file(&repo, "demo", label, "pg_data/corrupt", bytes);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.files_checked, 1);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(
            report.problems[0],
            VerifyProblem::ChecksumMismatch {
                backup: label.to_owned(),
                path: "pg_data/corrupt".to_owned(),
                expected: wrong,
                actual: sha1_hex(bytes),
            }
        );
    }

    #[test]
    fn verify_missing_stanza_errors() {
        let (_dir, repo) = empty_repo();
        let err = verify_inner(&cfg(None, None), &repo).expect_err("verify requires a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn verify_set_selects_single_backup() {
        let (_dir, repo) = empty_repo();
        let first = "20240101-120000F";
        let second = "20240102-120000F";

        seed_backup_info(&repo, "demo", &[first, second]);

        let a = b"first backup file";
        seed_manifest(&repo, "demo", first, vec![file_entry("pg_data/a", a, Some(sha1_hex(a)))]);
        write_backup_file(&repo, "demo", first, "pg_data/a", a);

        let b = b"second backup file";
        seed_manifest(&repo, "demo", second, vec![file_entry("pg_data/b", b, Some(sha1_hex(b)))]);
        write_backup_file(&repo, "demo", second, "pg_data/b", b);

        // --set the first backup: only it should be checked.
        let report = verify_inner(&cfg(Some("demo"), Some(first)), &repo).expect("verify_inner");
        assert_eq!(report.backups_checked, 1);
        assert_eq!(report.files_checked, 1);
        assert!(report.problems.is_empty());
    }

    #[test]
    fn verify_multi_backup_with_references_all_valid() {
        // A full backup holds two files; a differential references one of the
        // full's files (its bytes physically live in the full) and adds a
        // changed file of its own. Every checksum is valid → zero problems.
        let (_dir, repo) = empty_repo();
        let full = "20240101-120000F";
        let diff = "20240101-120000F_20240102-120000D";

        seed_backup_info(&repo, "demo", &[full, diff]);
        seed_archive_info(&repo, "demo");

        let unchanged = b"unchanged heap page";
        let changed_old = b"original";
        let changed_new = b"modified in diff";

        // Full backup: both files physically present.
        seed_manifest(
            &repo,
            "demo",
            full,
            vec![
                file_entry("base/1/unchanged", unchanged, Some(sha1_hex(unchanged))),
                file_entry("base/1/changed", changed_old, Some(sha1_hex(changed_old))),
            ],
        );
        write_backup_file(&repo, "demo", full, "base/1/unchanged", unchanged);
        write_backup_file(&repo, "demo", full, "base/1/changed", changed_old);

        // Diff: references the unchanged file from the full, holds the changed one.
        seed_manifest(
            &repo,
            "demo",
            diff,
            vec![
                referenced_entry("base/1/unchanged", unchanged, full),
                file_entry("base/1/changed", changed_new, Some(sha1_hex(changed_new))),
            ],
        );
        write_backup_file(&repo, "demo", diff, "base/1/changed", changed_new);
        // The referenced file is NOT written into the diff dir; verify must
        // resolve it to the full.

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.backups_checked, 2);
        assert_eq!(report.files_checked, 4, "2 full + 2 diff (referenced counts)");
        assert!(
            report.problems.is_empty(),
            "all checksums valid → no problems: {:?}",
            report.problems
        );
        assert!(
            report.info_problems.is_empty(),
            "info files agree: {:?}",
            report.info_problems
        );
        for b in &report.backups {
            assert_eq!(b.valid, b.total, "backup {} should be fully valid", b.label);
        }
    }

    #[test]
    fn verify_detects_corrupt_file_in_repo() {
        // Two backups; corrupt one file's bytes in the *second* backup. The
        // first backup stays clean; only the second's error list names the file.
        let (_dir, repo) = empty_repo();
        let first = "20240101-120000F";
        let second = "20240102-120000F";

        seed_backup_info(&repo, "demo", &[first, second]);

        let clean = b"clean bytes";
        seed_manifest(
            &repo,
            "demo",
            first,
            vec![file_entry("base/clean", clean, Some(sha1_hex(clean)))],
        );
        write_backup_file(&repo, "demo", first, "base/clean", clean);

        let intended = b"the intended content";
        seed_manifest(
            &repo,
            "demo",
            second,
            vec![file_entry("base/corrupt", intended, Some(sha1_hex(intended)))],
        );
        // Write *different* bytes (but the SAME length, so only the checksum
        // mismatch fires, not a size mismatch) than the manifest records.
        let tampered = b"TAMPERED on-disk!!!!";
        assert_eq!(tampered.len(), intended.len(), "tampered bytes must match the intended size");
        write_backup_file(&repo, "demo", second, "base/corrupt", tampered);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.problems.len(), 1);
        match &report.problems[0] {
            VerifyProblem::ChecksumMismatch { backup, path, .. } => {
                assert_eq!(backup, second);
                assert_eq!(path, "base/corrupt");
            }
            other => panic!("expected ChecksumMismatch, got {other:?}"),
        }
        // First backup clean, second backup names the file.
        let first_summary = report.backups.iter().find(|b| b.label == first).unwrap();
        assert!(first_summary.errors.is_empty());
        let second_summary = report.backups.iter().find(|b| b.label == second).unwrap();
        assert_eq!(second_summary.valid, 0);
        assert!(
            second_summary.errors.iter().any(|e| e.contains("base/corrupt")),
            "second backup errors must name the corrupt file: {:?}",
            second_summary.errors
        );
    }

    #[test]
    fn verify_detects_missing_referenced_file() {
        // A diff references a file from the full, but the full never physically
        // stored it (and the diff doesn't either). Verify must report it missing,
        // attributed to the diff that referenced it.
        let (_dir, repo) = empty_repo();
        let full = "20240101-120000F";
        let diff = "20240101-120000F_20240102-120000D";

        seed_backup_info(&repo, "demo", &[full, diff]);

        // Full: empty (no files written, manifest lists none).
        seed_manifest(&repo, "demo", full, Vec::new());

        // Diff references base/1/gone from the full, but it isn't there.
        let gone = b"bytes that were supposed to be in the full";
        seed_manifest(&repo, "demo", diff, vec![referenced_entry("base/1/gone", gone, full)]);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.problems.len(), 1);
        assert_eq!(
            report.problems[0],
            VerifyProblem::MissingFile {
                backup: diff.to_owned(),
                path: "base/1/gone".to_owned(),
            }
        );
    }

    #[test]
    fn verify_info_mismatch_recorded_not_thrown() {
        // archive.info disagrees with backup.info on the system id → recorded as
        // an info problem, but verify still completes and returns a report.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";
        seed_backup_info(&repo, "demo", &[label]);

        // Write a divergent archive.info.
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 1234,
                db_version: "14".to_owned(),
            },
        );
        let archive = InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 1234, // != backup.info's 6_873_049_345_984_568_091
            db_version: "14".to_owned(),
            history,
        };
        repo.create_path(Path::new("archive/demo"), true).unwrap();
        archive.save(&repo, &super::archive_info_path("demo")).unwrap();

        let a = b"x";
        seed_manifest(&repo, "demo", label, vec![file_entry("base/a", a, Some(sha1_hex(a)))]);
        write_backup_file(&repo, "demo", label, "base/a", a);

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner completes");
        assert!(
            report.info_problems.iter().any(|n| n.contains("db mismatch")),
            "expected a db-mismatch note: {:?}",
            report.info_problems
        );
        assert!(report.total_problems() >= 1);
    }

    #[test]
    fn verify_archive_presence_only_for_flat_layout() {
        // Flat-layout segments (no checksum in the name) are verified for
        // presence + readability and counted presence-only.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";
        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(&repo, "demo", label, Vec::new());

        write_archive_segment(&repo, "demo", "000000010000000000000001", b"wal one");
        write_archive_segment(&repo, "demo", "000000010000000000000002", b"wal two");

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.archive.total, 2);
        assert_eq!(report.archive.valid, 2);
        assert_eq!(report.archive.presence_only, 2);
        assert_eq!(report.archive.checksum_verified, 0);
        assert!(report.archive.problems.is_empty());
    }

    #[test]
    fn verify_archive_checksum_segments_valid_and_tampered() {
        // C-style segment names embed the SHA-1 (`<segment>-<sha1>`). A valid
        // one verifies; a tampered one (bytes changed after the name was fixed)
        // reports a checksum mismatch.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";
        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(&repo, "demo", label, Vec::new());

        let good = b"valid wal segment bytes";
        let good_name = format!("000000010000000000000003-{}", sha1_hex(good));
        write_archive_segment(&repo, "demo", &good_name, good);

        // Name records the checksum of `intended`, but we write tampered bytes.
        let intended = b"intended wal bytes";
        let bad_name = format!("000000010000000000000004-{}", sha1_hex(intended));
        write_archive_segment(&repo, "demo", &bad_name, b"tampered wal bytes!!");

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert_eq!(report.archive.total, 2);
        assert_eq!(report.archive.valid, 1);
        assert_eq!(report.archive.checksum_verified, 1);
        assert_eq!(report.archive.problems.len(), 1);
        match &report.archive.problems[0] {
            ArchiveProblem::ChecksumMismatch {
                segment,
                expected,
                actual,
            } => {
                assert_eq!(segment, &bad_name);
                assert_eq!(expected, &sha1_hex(intended));
                assert_eq!(actual, &sha1_hex(b"tampered wal bytes!!"));
            }
            other @ ArchiveProblem::Unreadable { .. } => panic!("expected ChecksumMismatch, got {other:?}"),
        }
    }

    /// Seed `backup.info` where each `(label, compress_type)` pair records the
    /// matching `backup-info-compress-type` flag in `[backup:current]`. This is
    /// what verify reads back via `RepoTransform::from_metadata_checked` so each
    /// backup is checksummed against the transform it was actually written with.
    fn seed_backup_info_with_compress(repo: &Posix, stanza: &str, entries: &[(&str, &str)]) {
        let mut current = BTreeMap::new();
        for (label, compress_type) in entries {
            current.insert(
                (*label).to_owned(),
                json!({
                    "backup-info-size": 100,
                    "backup-label": *label,
                    "backup-timestamp-stop": 1_704_110_410_i64,
                    "backup-type": "full",
                    "backup-info-compress-type": *compress_type,
                    "backup-info-encrypted": false,
                }),
            );
        }

        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );

        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        };

        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup/<stanza>");
        info.save(repo, &super::backup_info_path(stanza)).expect("save backup.info");
    }

    /// Apply the keyed forward chain of a [`super::RepoTransform`] to `bytes`
    /// (the exact path backup's writer uses) and return the repo-side bytes.
    fn forward(transform: &crate::pipeline::RepoTransform, bytes: &[u8]) -> Vec<u8> {
        transform.apply_forward_keyed(bytes).expect("apply_forward_keyed")
    }

    #[test]
    fn verify_clean_compressed_backup_passes_when_suffix_matches() {
        // The PRIMARY bug the live PG18 cluster surfaced: backup writes
        // `<rel>.gz` under the label dir, but verify probed `<rel>` (no suffix)
        // and reported every file MISSING. With the per-holder transform
        // lookup the on-disk filename is reconstructed correctly, AND the
        // hash is taken over the reversed (plaintext) bytes so the checksum
        // recorded by the writer matches.
        //
        // The fixture mixes TWO compress types — one regular file under a
        // gz-backup, one referenced file under a zst-backup — to prove the
        // per-holder transform lookup is keyed on the *holder* label, not on
        // the backup being verified.
        let (_dir, repo) = empty_repo();
        let full_gz = "20240101-120000F";
        let full_zst = "20240102-120000F";

        // Each label records its own compress-type in [backup:current]. The
        // verify pass reads these via `RepoTransform::from_metadata_checked`.
        seed_backup_info_with_compress(&repo, "demo", &[(full_gz, "gz"), (full_zst, "zst")]);

        // Build the transforms verify will reconstruct.
        let tf_gz = crate::pipeline::RepoTransform {
            compress_type: crate::pipeline::CompressType::Gz,
            compress_level: 6,
            cipher_pass: None,
        };
        let tf_zst = crate::pipeline::RepoTransform {
            compress_type: crate::pipeline::CompressType::Zst,
            compress_level: 3,
            cipher_pass: None,
        };

        // full_gz holds one file that REFERENCES a file from full_zst, AND
        // its own file. Mixing the holders proves the suffix lookup is keyed
        // on the holder, not the manifest's owner.
        let own = b"PG_VERSION contents\n";
        let referenced_bytes = b"shared heap page bytes that the zst backup physically holds";

        seed_manifest(
            &repo,
            "demo",
            full_gz,
            vec![
                file_entry("pg_data/PG_VERSION", own, Some(sha1_hex(own))),
                referenced_entry("pg_data/base/1/1259", referenced_bytes, full_zst),
            ],
        );

        // full_zst owns its file at <rel>.zst.
        seed_manifest(
            &repo,
            "demo",
            full_zst,
            vec![file_entry(
                "pg_data/base/1/1259",
                referenced_bytes,
                Some(sha1_hex(referenced_bytes)),
            )],
        );

        // Write the on-disk bytes under each holder's directory with each
        // holder's compression suffix.
        write_backup_file(&repo, "demo", full_gz, "pg_data/PG_VERSION.gz", &forward(&tf_gz, own));
        write_backup_file(
            &repo,
            "demo",
            full_zst,
            "pg_data/base/1/1259.zst",
            &forward(&tf_zst, referenced_bytes),
        );

        let report = verify_inner(&cfg(Some("demo"), None), &repo).expect("verify_inner");
        assert!(
            report.problems.is_empty(),
            "a clean compressed backup must report ZERO problems; got: {:?}",
            report.problems
        );
        for backup in &report.backups {
            assert!(
                backup.errors.is_empty(),
                "backup {}'s per-backup errors must be empty: {:?}",
                backup.label,
                backup.errors,
            );
            assert_eq!(
                backup.valid, backup.total,
                "every file in {} must be valid (got {}/{})",
                backup.label, backup.valid, backup.total
            );
        }
    }

    #[test]
    fn verify_corrupt_compressed_file_is_checksum_mismatch_not_missing() {
        // NEGATIVE test for bug #2: if the .gz bytes are truncated, verify
        // must detect the file as a ChecksumMismatch (the reversed bytes
        // either decompress wrong or short), NOT as MissingFile.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        seed_backup_info_with_compress(&repo, "demo", &[(label, "gz")]);

        let tf = crate::pipeline::RepoTransform {
            compress_type: crate::pipeline::CompressType::Gz,
            compress_level: 6,
            cipher_pass: None,
        };

        let plaintext = b"the relation bytes that compress and round-trip cleanly when intact";
        let intended_sha = sha1_hex(plaintext);

        seed_manifest(
            &repo,
            "demo",
            label,
            vec![file_entry("pg_data/base/1/1259", plaintext, Some(intended_sha))],
        );

        // Forward through gz, then TRUNCATE the last byte of the gz frame.
        // The reverse will either fail to decompress or produce different
        // plaintext — either way, NOT a MissingFile.
        let mut gz = forward(&tf, plaintext);
        assert!(gz.len() > 1, "gz output must be at least 2 bytes to truncate");
        gz.pop();
        write_backup_file(&repo, "demo", label, "pg_data/base/1/1259.gz", &gz);

        let result = verify_inner(&cfg(Some("demo"), None), &repo);
        match result {
            // Two acceptable outcomes: the corruption is detected as a
            // ChecksumMismatch in the report, OR the reverse chain errors
            // out (a CommandError) — either way is NOT a silent
            // "MissingFile" against a clean repo, which is the bug.
            Ok(report) => {
                assert!(
                    !report.problems.iter().any(|p| matches!(p, VerifyProblem::MissingFile { .. })),
                    "a corrupt .gz must NOT surface as MissingFile (the bug); problems: {:?}",
                    report.problems,
                );
                assert!(
                    report
                        .problems
                        .iter()
                        .any(|p| matches!(p, VerifyProblem::ChecksumMismatch { .. } | VerifyProblem::SizeMismatch { .. })),
                    "the corruption must be detected as a checksum or size mismatch: {:?}",
                    report.problems,
                );
            }
            Err(err) => {
                // A decompression error surfacing as a CommandError is also
                // acceptable: the corruption is detected, just through the
                // reverse-chain failure rather than the digest comparison.
                let msg = err.to_string();
                assert!(!msg.is_empty(), "a decompression failure should carry a non-empty message");
            }
        }
    }

    #[test]
    fn split_segment_checksum_recognizes_layouts() {
        // Flat layout: no embedded checksum.
        assert!(split_segment_checksum("000000010000000000000001").is_none());
        // C layout: 24-char segment + '-' + 40-hex sha1.
        let name = "000000010000000000000001-1234567890abcdef1234567890abcdef12345678";
        assert_eq!(
            split_segment_checksum(name),
            Some(("000000010000000000000001", "1234567890abcdef1234567890abcdef12345678"))
        );
        // C layout with a compression suffix.
        let gz = "000000010000000000000001-1234567890abcdef1234567890abcdef12345678.gz";
        assert_eq!(
            split_segment_checksum(gz),
            Some(("000000010000000000000001", "1234567890abcdef1234567890abcdef12345678"))
        );
        // Trailing token that is not 40 hex chars is not a checksum.
        assert!(split_segment_checksum("000000010000000000000001-notachecksum").is_none());
    }

    /// `LoadedConfig` with an explicit `process-max` value, so the parallel
    /// branch can be exercised with a known worker count.
    fn cfg_with_process_max(stanza: Option<&str>, process_max: i64) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(("process-max".to_owned(), None), OptionValue::Integer(process_max));
        LoadedConfig {
            command: "verify".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn verify_parallel_local_baseline() {
        // Local repo + 3 valid files in one backup → empty problems,
        // files_checked == 3. The parallel branch (process-max=4) must
        // produce identical results to the serial path.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let a = b"PG_VERSION contents\n";
        let b = b"some heap page bytes \x00\x01\x02";
        let c = b"another relation byte stream";

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![
                file_entry("pg_data/PG_VERSION", a, Some(sha1_hex(a))),
                file_entry("pg_data/base/1/1259", b, Some(sha1_hex(b))),
                file_entry("pg_data/base/1/1260", c, Some(sha1_hex(c))),
            ],
        );
        write_backup_file(&repo, "demo", label, "pg_data/PG_VERSION", a);
        write_backup_file(&repo, "demo", label, "pg_data/base/1/1259", b);
        write_backup_file(&repo, "demo", label, "pg_data/base/1/1260", c);

        // process-max=4 forces the parallel branch (4 workers, 3 jobs); the
        // dispatcher caps the pool at the number of jobs.
        let report = verify_inner(&cfg_with_process_max(Some("demo"), 4), &repo).expect("verify_inner");
        assert!(
            report.problems.is_empty(),
            "clean parallel verify must report no problems: {:?}",
            report.problems
        );
        assert_eq!(report.files_checked, 3);
        assert_eq!(report.backups_checked, 1);
        assert_eq!(report.backups.len(), 1);
        assert_eq!(report.backups[0].valid, 3);
        assert_eq!(report.backups[0].total, 3);
        assert!(report.backups[0].errors.is_empty());
    }

    /// A [`Storage`] adapter that delegates every operation to a wrapped
    /// `Posix` but reports `is_local() = false`, forcing the verify path to
    /// take the serial `Storage::open_read` branch.
    ///
    /// The `Posix` is shared via `Arc` so the test can keep its own handle for
    /// seeding while the verifier owns one too — the mock implements `Send +
    /// Sync` (the `Storage` super-trait bound) and the seeding helpers below
    /// take `&Posix`.
    struct NonLocalMock {
        inner: Posix,
    }

    impl Storage for NonLocalMock {
        fn is_local(&self) -> bool {
            false
        }

        fn exists(&self, path: &Path) -> Result<bool, pgbr_storage::StorageError> {
            self.inner.exists(path)
        }

        fn info(&self, path: &Path) -> Result<pgbr_storage::StorageInfo, pgbr_storage::StorageError> {
            self.inner.info(path)
        }

        fn list(&self, path: &Path) -> Result<Vec<pgbr_storage::StorageInfo>, pgbr_storage::StorageError> {
            self.inner.list(path)
        }

        fn open_read(&self, path: &Path) -> Result<Box<dyn pgbr_io::IoRead>, pgbr_storage::StorageError> {
            self.inner.open_read(path)
        }

        fn open_write(&self, path: &Path) -> Result<Box<dyn pgbr_io::IoWrite>, pgbr_storage::StorageError> {
            self.inner.open_write(path)
        }

        fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.remove(path, error_on_missing)
        }

        fn rename(&self, source: &Path, target: &Path) -> Result<(), pgbr_storage::StorageError> {
            self.inner.rename(source, target)
        }

        fn create_path(&self, path: &Path, recursive: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.create_path(path, recursive)
        }

        fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), pgbr_storage::StorageError> {
            self.inner.remove_path(path, recursive, error_on_missing)
        }
    }

    #[test]
    fn verify_remote_fallback_serial() {
        // A non-local mock (`is_local() = false`) must route every file
        // through the serial `Storage::open_read` branch — the parallel
        // `std::fs` path would not even find the files (the mock's
        // `info().path` is the Posix-resolved absolute path, but the contract
        // for verify says non-local storage must NOT take the std::fs path).
        // process-max=4 is set so the only way this can succeed without
        // hitting the parallel branch is if `is_local()` actually gates it.
        let dir = tempfile::tempdir().expect("repo tempdir");
        let posix = Posix::new(dir.path());
        let label = "20240101-120000F";

        let a = b"PG_VERSION contents\n";
        let b = b"some heap page bytes \x00\x01\x02";
        let c = b"another relation byte stream";

        seed_backup_info(&posix, "demo", &[label]);
        seed_manifest(
            &posix,
            "demo",
            label,
            vec![
                file_entry("pg_data/PG_VERSION", a, Some(sha1_hex(a))),
                file_entry("pg_data/base/1/1259", b, Some(sha1_hex(b))),
                file_entry("pg_data/base/1/1260", c, Some(sha1_hex(c))),
            ],
        );
        write_backup_file(&posix, "demo", label, "pg_data/PG_VERSION", a);
        write_backup_file(&posix, "demo", label, "pg_data/base/1/1259", b);
        write_backup_file(&posix, "demo", label, "pg_data/base/1/1260", c);

        let mock = NonLocalMock { inner: posix };
        assert!(!mock.is_local(), "the mock must report itself non-local");

        let report = verify_inner(&cfg_with_process_max(Some("demo"), 4), &mock).expect("verify_inner");
        assert!(
            report.problems.is_empty(),
            "non-local serial verify must report no problems: {:?}",
            report.problems
        );
        assert_eq!(report.files_checked, 3);
        assert_eq!(report.backups_checked, 1);
        assert_eq!(report.backups[0].valid, 3);
        assert_eq!(report.backups[0].total, 3);
    }

    #[test]
    fn verify_error_aggregation() {
        // Local repo + 2 clean files + 1 size mismatch + 1 checksum mismatch.
        // Both problems must be collected (the pass does NOT stop at the
        // first), assigned to the right backup/path, and `summary.errors`
        // must carry one entry per problem.
        let (_dir, repo) = empty_repo();
        let label = "20240101-120000F";

        let clean1 = b"first clean file bytes";
        let clean2 = b"second clean file bytes";

        // The size-mismatch file: manifest records size=99, on-disk is 4 bytes.
        let size_mismatch_bytes = b"SIZE";

        // The checksum-mismatch file: manifest's checksum is all zeros, real
        // sha1 differs. Size matches so only the checksum problem fires.
        let csum_mismatch_bytes = b"the real bytes (wrong checksum recorded)";
        let wrong_csum = "0000000000000000000000000000000000000000".to_owned();

        let size_mismatch_entry = ManifestFile {
            path: "pg_data/oversized".to_owned(),
            size: 99, // lies — on-disk is 4 bytes
            timestamp: 1_704_110_400,
            checksum: Some(sha1_hex(size_mismatch_bytes)),
            checksum_page: None,
            reference: None,
            mode: None,
            user: None,
            group: None,
            bundle_id: None,
            bundle_offset: None,
            block_map: None,
        };

        seed_backup_info(&repo, "demo", &[label]);
        seed_manifest(
            &repo,
            "demo",
            label,
            vec![
                file_entry("pg_data/clean_a", clean1, Some(sha1_hex(clean1))),
                file_entry("pg_data/clean_b", clean2, Some(sha1_hex(clean2))),
                size_mismatch_entry,
                file_entry("pg_data/bad_csum", csum_mismatch_bytes, Some(wrong_csum.clone())),
            ],
        );
        write_backup_file(&repo, "demo", label, "pg_data/clean_a", clean1);
        write_backup_file(&repo, "demo", label, "pg_data/clean_b", clean2);
        write_backup_file(&repo, "demo", label, "pg_data/oversized", size_mismatch_bytes);
        write_backup_file(&repo, "demo", label, "pg_data/bad_csum", csum_mismatch_bytes);

        let report = verify_inner(&cfg_with_process_max(Some("demo"), 4), &repo).expect("verify_inner");

        assert_eq!(report.files_checked, 4);
        assert_eq!(report.problems.len(), 2, "must collect BOTH problems: {:?}", report.problems);
        let summary = report.backups.iter().find(|b| b.label == label).expect("backup summary");
        assert_eq!(summary.total, 4);
        assert_eq!(summary.valid, 2, "2 clean files must be counted valid");
        assert_eq!(summary.errors.len(), 2, "one entry per problem: {:?}", summary.errors);

        let mut saw_size = false;
        let mut saw_csum = false;
        for problem in &report.problems {
            match problem {
                VerifyProblem::SizeMismatch {
                    backup,
                    path,
                    expected,
                    actual,
                } => {
                    assert_eq!(backup, label);
                    assert_eq!(path, "pg_data/oversized");
                    assert_eq!(*expected, 99);
                    assert_eq!(*actual, size_mismatch_bytes.len() as u64);
                    saw_size = true;
                }
                VerifyProblem::ChecksumMismatch {
                    backup,
                    path,
                    expected,
                    actual,
                } => {
                    assert_eq!(backup, label);
                    assert_eq!(path, "pg_data/bad_csum");
                    assert_eq!(expected, &wrong_csum);
                    assert_eq!(actual, &sha1_hex(csum_mismatch_bytes));
                    saw_csum = true;
                }
                other @ VerifyProblem::MissingFile { .. } => panic!("unexpected problem: {other:?}"),
            }
        }
        assert!(saw_size, "size mismatch must be reported: {:?}", report.problems);
        assert!(saw_csum, "checksum mismatch must be reported: {:?}", report.problems);
    }

    /// A `verify` config carrying `repo-cipher-type=aes-256-cbc` +
    /// `repo-cipher-pass=<user_pass>` (the user passphrase, which unlocks the
    /// recorded sub-key — not the sub-key itself), exactly as a real encrypted
    /// verify invocation resolves its keys via `crate::cipher`.
    fn cfg_encrypted(stanza: &str, user_pass: &str) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        options.insert(
            ("repo-cipher-type".to_owned(), Some(1)),
            OptionValue::StringId("aes-256-cbc".to_owned()),
        );
        options.insert(
            ("repo-cipher-pass".to_owned(), Some(1)),
            OptionValue::String(user_pass.to_owned()),
        );
        LoadedConfig {
            command: "verify".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some(stanza.to_owned()),
            options,
            params: Vec::new(),
        }
    }

    /// Seed a fully **encrypted** stanza the way stanza-create + backup would:
    /// `backup.info` keyed under `user_pass`, `archive.info` keyed under
    /// `user_pass` and carrying `sub_key` in its `[cipher]` section, a
    /// `backup.manifest` keyed under the `sub_key`, and every data file written
    /// through the sub-key forward chain (`backup-info-encrypted=true`). Returns
    /// the manifest-relative path of the single seeded data file.
    fn seed_encrypted_backup(repo: &Posix, stanza: &str, label: &str, user_pass: &str, sub_key: &str, plaintext: &[u8]) -> String {
        // Encrypted archive.info (user pass + recorded sub-key).
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        let archive = InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            history: history.clone(),
        };
        repo.create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive dir");
        archive
            .save_keyed(repo, &super::archive_info_path(stanza), Some(user_pass), Some(sub_key))
            .expect("save encrypted archive.info");

        // Encrypted backup.info (user pass), the entry marked encrypted so
        // `from_metadata_checked` demands a key.
        let mut current = BTreeMap::new();
        current.insert(
            label.to_owned(),
            json!({
                "backup-info-size": 100,
                "backup-label": label,
                "backup-timestamp-stop": 1_704_110_410_i64,
                "backup-type": "full",
                "backup-info-encrypted": true,
            }),
        );
        let info = InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        };
        repo.create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup dir");
        info.save_keyed(repo, &super::backup_info_path(stanza), Some(user_pass), Some(sub_key))
            .expect("save encrypted backup.info");

        // Encrypted backup.manifest (sub-key). The plaintext SHA-1 the manifest
        // records is taken over the plaintext, as the backup writer does.
        let rel = "pg_data/base/1/1259";
        let manifest = Manifest {
            backup_label: label.to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![file_entry(rel, plaintext, Some(sha1_hex(plaintext)))],
            option_checksum_page: None,
            paths: Vec::new(),
            links: Vec::new(),
        };
        repo.create_path(Path::new(&format!("backup/{stanza}/{label}")), true)
            .expect("create backup label dir");
        manifest
            .save_keyed(repo, &super::manifest_path(stanza, label), Some(sub_key))
            .expect("save encrypted manifest");

        // Encrypted data file: forward the plaintext through the sub-key chain,
        // exactly as the backup writer would.
        let tf = crate::pipeline::RepoTransform::with_key(crate::pipeline::CompressType::None, 0, Some(sub_key.to_owned()));
        let repo_bytes = tf.apply_forward_keyed(plaintext).expect("encrypt data file");
        write_backup_file(repo, stanza, label, rel, &repo_bytes);

        rel.to_owned()
    }

    #[test]
    fn verify_clean_encrypted_repo_has_no_problems() {
        // REGRESSION: verify on an encrypted repo previously re-hashed the
        // ciphertext (it never injected the repo sub-key) and declared a
        // healthy encrypted repo CORRUPT. It must now decrypt with the resolved
        // sub-key and report zero problems.
        let (_dir, repo) = empty_repo();
        let stanza = "demo";
        let label = "20240101-120000F";
        let user_pass = "user-secret-pass";
        let sub_key = pgbr_info::cipher_pass_gen();
        let plaintext = b"relation data that must round-trip through decrypt cleanly";

        seed_encrypted_backup(&repo, stanza, label, user_pass, &sub_key, plaintext);

        let report = verify_inner(&cfg_encrypted(stanza, user_pass), &repo).expect("verify_inner on encrypted repo");
        assert!(
            report.problems.is_empty(),
            "a clean ENCRYPTED repo must report zero problems (was re-hashing ciphertext): {:?}",
            report.problems
        );
        assert!(
            report.info_problems.is_empty(),
            "encrypted info files must decrypt and agree: {:?}",
            report.info_problems
        );
        assert_eq!(report.files_checked, 1);
        assert_eq!(report.backups_checked, 1);
        assert_eq!(report.backups[0].valid, 1);
        assert_eq!(report.backups[0].total, 1);
        assert!(report.backups[0].errors.is_empty());
    }

    #[test]
    fn verify_encrypted_repo_detects_tampered_ciphertext() {
        // A corrupted ciphertext byte must be DETECTED (checksum/size mismatch
        // in the report, or a decrypt failure surfaced as a CommandError) — not
        // silently pass, and not spuriously "MissingFile".
        let (_dir, repo) = empty_repo();
        let stanza = "demo";
        let label = "20240101-120000F";
        let user_pass = "user-secret-pass";
        let sub_key = pgbr_info::cipher_pass_gen();
        let plaintext = b"relation data that must round-trip through decrypt cleanly";

        let rel = seed_encrypted_backup(&repo, stanza, label, user_pass, &sub_key, plaintext);

        // Flip the last byte of the encrypted data file on disk.
        let on_disk = super::backup_file_path(stanza, label, &rel);
        let mut bytes = {
            let mut r = repo.open_read(&on_disk).expect("open encrypted file");
            r.read_all().expect("read encrypted file")
        };
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        {
            let mut w = repo.open_write(&on_disk).expect("reopen encrypted file");
            w.write(&bytes).expect("rewrite tampered ciphertext");
            w.close().expect("close tampered file");
        }

        match verify_inner(&cfg_encrypted(stanza, user_pass), &repo) {
            Ok(report) => {
                assert!(
                    !report.problems.iter().any(|p| matches!(p, VerifyProblem::MissingFile { .. })),
                    "tampered ciphertext must NOT surface as MissingFile: {:?}",
                    report.problems
                );
                assert!(
                    !report.problems.is_empty(),
                    "tampered ciphertext must be detected as a problem: {:?}",
                    report.problems
                );
            }
            Err(err) => {
                // A decrypt failure surfacing as a CommandError is also a valid
                // detection: the corruption did not slip through.
                assert!(!err.to_string().is_empty(), "a decrypt failure should carry a message");
            }
        }
    }
}
