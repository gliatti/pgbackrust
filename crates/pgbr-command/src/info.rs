//! `info` command — read `archive.info` and `backup.info` from the repo
//! and print a structured per-stanza summary.
//!
//! C reference: `src/command/info/info.c`. Each stanza is reported
//! independently: a missing `archive.info` *or* missing `backup.info`
//! degrades to a partial summary rather than failing the whole command.
//! When `--stanza` is omitted the command discovers every stanza visible
//! under `archive/` and `backup/` and reports the union.
//!
//! Two output formats are supported via `--output` (a `string-id` option
//! defaulting to `text`):
//!
//! - `text` — the human layout from `formatText*` in the C source:
//!   `stanza: <name>`, `    status: ok|error (<reason>)`, `    cipher: none`,
//!   per-db (`wal archive min/max`) and per-backup lines (`full backup:`,
//!   `timestamp start/stop`, `wal start/stop`, `database size`, `repo`, …).
//! - `json` — the structured shape from `infoRender`: an array of stanza
//!   objects each carrying `name`, `status {code,message}`, `cipher`,
//!   `db [...]`, `archive [...]` and `backup [...]`.
//!
//! ## Fields that are placeholders / zeroed
//!
//! The on-disk info files this fork records do not (yet) capture every datum
//! the C output exposes, so the following are emitted with documented
//! placeholders rather than real values:
//!
//! - `info.size-delta` / `info.repository.size-delta` (per-backup delta sizes)
//!   — not recorded in `[backup:current]`; mirrored from the non-delta size.
//! - `backrest.format` / `backrest.version` per backup — taken from the
//!   stanza-level `backup.info` header (the only copy this fork stores).
//! - `database.repo-key` / `archive[].database.repo-key` — always `1`; this
//!   fork is single-repo, so there is no per-backup repo index to report.
//! - `lsn`, `error`, `annotation`, `database-ref`, `link`, `tablespace` — only
//!   produced by the C side when a manifest is loaded for a specific `--set`;
//!   omitted here.
//! - text timestamps are rendered in UTC (`YYYY-MM-DD HH:MM:SS+0000`) rather
//!   than the C side's local time + computed offset, to keep rendering pure
//!   and deterministic without pulling in a timezone database.
//!
//! ## `--set=<label>` detailed single-backup view
//!
//! When `--set=<label>` names a backup, `info` additionally loads that
//! backup's `backup.manifest` (at `backup/<stanza>/<label>/backup.manifest`)
//! and renders a per-backup *detail* block on top of the summary, mirroring the
//! C side's `set`-specific rendering in `src/command/info/info.c`:
//!
//! - text: after the matching backup's summary lines, a `database list:` of the
//!   backed-up cluster (version + system-id, the only database identity this
//!   fork's [`Manifest`] records) and a `file list:` line carrying the manifest
//!   file count and total size.
//! - JSON: the matching backup object gains a `manifest` detail block with
//!   `file-count`, `file-total-size`, the manifest timestamps, and a `database`
//!   list element for the backed-up cluster.
//!
//! `--set` requires `--stanza`. An unknown label errors; an unreadable manifest
//! degrades to a note (the summary still renders) rather than failing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoArchive, InfoBackup, InfoError, Manifest};
use pgbr_storage::{Storage, StorageError, StorageKind};
use serde_json::{Value, json};

use crate::CommandError;

/// Top-level status for a stanza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StanzaStatus {
    /// Both `archive.info` and `backup.info` loaded cleanly.
    Ok,
    /// Neither info file exists — stanza has not been initialised.
    NotInitialized,
    /// At least one of the info files failed to load (missing or malformed).
    /// The contained string is a human-readable reason suitable for display.
    Error(String),
}

impl StanzaStatus {
    /// Numeric status code, matching the C `INFO_STANZA_STATUS_CODE_*` values
    /// emitted in JSON: `0` ok, `99` other (any error this fork surfaces).
    /// `NotInitialized` maps to `1` (`missing stanza path`).
    #[must_use]
    const fn code(&self) -> i64 {
        match self {
            Self::Ok => 0,
            Self::NotInitialized => 1,
            Self::Error(_) => 99,
        }
    }

    /// Human status message used in the JSON `status.message` field. `Ok`
    /// carries no message (`None`); the others carry their reason.
    #[must_use]
    fn message(&self) -> Option<String> {
        match self {
            Self::Ok => None,
            Self::NotInitialized => Some("missing stanza path".to_owned()),
            Self::Error(reason) => Some(reason.clone()),
        }
    }
}

/// Summary of one backup row from `[backup:current]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    /// Backup label, e.g. `20260101-100000F`.
    pub label: String,
    /// `full`, `diff`, `incr`, or whatever the on-disk value was.
    pub backup_type: String,
    /// `backup-prior` — the label of the backup this one depends on, if any.
    pub prior: Option<String>,
    /// `backup-reference` — the full dependency chain, if recorded.
    pub reference: Vec<String>,
    /// `backup-timestamp-start` — Unix epoch seconds. `None` if missing or
    /// not an integer.
    pub start_timestamp: Option<i64>,
    /// `backup-timestamp-stop` — Unix epoch seconds. `None` if the field is
    /// missing or not an integer.
    pub stop_timestamp: Option<i64>,
    /// `backup-archive-start` — first WAL segment of this backup, if recorded.
    pub archive_start: Option<String>,
    /// `backup-archive-stop` — last WAL segment of this backup, if recorded.
    pub archive_stop: Option<String>,
    /// `backup-info-size` — total bytes of the cluster this backup captured.
    /// `None` if the field is missing or not an integer.
    pub info_size: Option<u64>,
    /// `backup-info-repo-size` — total bytes of this backup in the repo.
    /// `None` if the field is missing or not an integer.
    pub repo_size: Option<u64>,
    /// `db-id` of the cluster this backup belongs to.
    pub db_id: Option<u32>,
}

/// Summary of one stanza, suitable for display or programmatic inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StanzaSummary {
    /// Stanza name.
    pub name: String,
    /// Loaded status — `Ok`, `NotInitialized`, or `Error(reason)`.
    pub status: StanzaStatus,
    /// Active cluster's `db-id` (the integer index into `[db:history]`).
    /// `None` when neither info file loaded.
    pub pg_id: Option<u32>,
    /// Active cluster's textual major-version label (e.g. `"14"`). `None`
    /// when neither info file loaded.
    pub pg_version: Option<String>,
    /// Active cluster's `pg_control.system_identifier`. `None` when neither
    /// info file loaded.
    pub pg_system_id: Option<u64>,
    /// pgBackRest format version from `backup.info` (or `archive.info`).
    /// `None` when neither info file loaded.
    pub backrest_format: Option<u32>,
    /// pgBackRest writer version string. `None` when neither info file loaded.
    pub backrest_version: Option<String>,
    /// Backups discovered in `[backup:current]`. Empty when `backup.info`
    /// did not load or the section was empty.
    pub backups: Vec<BackupSummary>,
}

/// Alias for [`StanzaSummary`] — the task's "`StanzaInfo` model" name. Both
/// refer to the same per-stanza view that [`render_text`] / [`render_json`]
/// consume.
pub type StanzaInfo = StanzaSummary;

/// Render a byte count with a binary-prefix suffix.
#[allow(clippy::cast_precision_loss)]
fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    // Casts lose precision for sizes above 2^53 bytes (8 PiB), which is well outside
    // the range of any realistic pgBackRest backup. Suppressed locally.
    if bytes >= TIB {
        format!("{:.1}TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1}GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes}B")
    }
}

/// Pull a `Vec<String>` of stanza names from a `<top>/<stanza>` directory.
/// A missing top directory yields an empty list (the stanza set is
/// open-ended; not having any backups yet is not an error).
fn list_stanzas_under(storage: &dyn Storage, top: &Path) -> Result<Vec<String>, CommandError> {
    match storage.list(top) {
        Ok(entries) => {
            let mut names = Vec::new();
            for info in entries {
                if !matches!(info.kind, StorageKind::Path) {
                    continue;
                }
                if let Some(name) = info.path.file_name().and_then(|n| n.to_str()) {
                    names.push(name.to_owned());
                }
            }
            Ok(names)
        }
        Err(StorageError::NotFound { .. }) => Ok(Vec::new()),
        Err(err) => Err(err.into()),
    }
}

/// Discover every stanza name visible in the repository — the union of
/// directory entries under `archive/` and `backup/`.
fn discover_stanzas(repo_storage: &dyn Storage) -> Result<Vec<String>, CommandError> {
    let mut names = list_stanzas_under(repo_storage, Path::new("archive"))?;
    names.extend(list_stanzas_under(repo_storage, Path::new("backup"))?);
    names.sort();
    names.dedup();
    Ok(names)
}

/// Decode one `[backup:current]` entry into a `BackupSummary`.
fn decode_backup(label: &str, value: &Value) -> BackupSummary {
    let backup_type = value.get("backup-type").and_then(Value::as_str).unwrap_or("?").to_owned();
    let prior = value.get("backup-prior").and_then(Value::as_str).map(str::to_owned);
    let reference = value
        .get("backup-reference")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |arr| {
            arr.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()
        });
    let start_timestamp = value.get("backup-timestamp-start").and_then(Value::as_i64);
    let stop_timestamp = value.get("backup-timestamp-stop").and_then(Value::as_i64);
    let archive_start = value.get("backup-archive-start").and_then(Value::as_str).map(str::to_owned);
    let archive_stop = value.get("backup-archive-stop").and_then(Value::as_str).map(str::to_owned);
    let info_size = value.get("backup-info-size").and_then(Value::as_u64);
    let repo_size = value.get("backup-info-repo-size").and_then(Value::as_u64);
    let db_id = value.get("db-id").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok());
    BackupSummary {
        label: label.to_owned(),
        backup_type,
        prior,
        reference,
        start_timestamp,
        stop_timestamp,
        archive_start,
        archive_stop,
        info_size,
        repo_size,
        db_id,
    }
}

/// Build a `StanzaSummary` for `name` by attempting to load both info files.
/// Each is tried independently — a missing file degrades to `NotInitialized`
/// or `Error(...)` rather than propagating.
fn summarize_stanza(repo_storage: &dyn Storage, name: &str) -> StanzaSummary {
    let archive_path = PathBuf::from(format!("archive/{name}/archive.info"));
    let backup_path = PathBuf::from(format!("backup/{name}/backup.info"));

    let archive = InfoArchive::load(repo_storage, &archive_path);
    let backup = InfoBackup::load(repo_storage, &backup_path);

    let archive_missing = matches!(archive, Err(pgbr_info::InfoError::Storage(StorageError::NotFound { .. })));
    let backup_missing = matches!(backup, Err(pgbr_info::InfoError::Storage(StorageError::NotFound { .. })));

    let status = match (&archive, &backup) {
        (Ok(_), Ok(_)) => StanzaStatus::Ok,
        _ if archive_missing && backup_missing => StanzaStatus::NotInitialized,
        (Err(err), _) if !archive_missing => StanzaStatus::Error(format!("archive.info: {err}")),
        (_, Err(err)) if !backup_missing => StanzaStatus::Error(format!("backup.info: {err}")),
        _ => StanzaStatus::Error("partial: one info file missing".to_owned()),
    };

    // Prefer backup.info for identity (it has catalog/control versions);
    // fall back to archive.info when only that loaded.
    let (pg_id, pg_version, pg_system_id, backrest_format, backrest_version) = match (&archive, &backup) {
        (_, Ok(b)) => (
            Some(b.db_id),
            Some(b.db_version.clone()),
            Some(b.db_system_id),
            Some(b.backrest_format),
            Some(b.backrest_version.clone()),
        ),
        (Ok(a), _) => (
            Some(a.db_id),
            Some(a.db_version.clone()),
            Some(a.db_system_id),
            Some(a.backrest_format),
            Some(a.backrest_version.clone()),
        ),
        _ => (None, None, None, None, None),
    };

    let backups = backup.as_ref().map_or_else(
        |_| Vec::new(),
        |b| b.current.iter().map(|(label, value)| decode_backup(label, value)).collect(),
    );

    StanzaSummary {
        name: name.to_owned(),
        status,
        pg_id,
        pg_version,
        pg_system_id,
        backrest_format,
        backrest_version,
        backups,
    }
}

/// Pure entry point — returns one `StanzaSummary` per resolved stanza.
///
/// Used by tests to assert on the typed return value rather than scraping
/// stdout. The CLI wrapper `info` calls this and prints each summary.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if the repository listing fails (for
/// the no-stanza-arg path that has to scan `archive/` and `backup/`).
/// Per-stanza failures are reported inside the corresponding
/// [`StanzaSummary::status`] and never propagate.
pub fn info_inner(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<Vec<StanzaSummary>, CommandError> {
    let stanzas = if let Some(name) = config.stanza.as_deref() {
        vec![name.to_owned()]
    } else {
        discover_stanzas(repo_storage)?
    };

    let summaries = stanzas.iter().map(|name| summarize_stanza(repo_storage, name)).collect();
    Ok(summaries)
}

/// Convert Unix epoch seconds to a `YYYY-MM-DD HH:MM:SS+0000` string in UTC.
///
/// The C side renders local time plus a computed timezone offset; this fork
/// renders UTC with a literal `+0000` so the output stays deterministic and
/// pure (no timezone database needed). The civil-date conversion below is the
/// standard "days since 1970 → y/m/d" algorithm (Howard Hinnant's `civil_from_days`).
#[must_use]
fn format_timestamp(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs_of_day = epoch.rem_euclid(86_400);
    let (hour, minute, second) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);

    // civil_from_days: shift epoch so the era starts on 0000-03-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}+0000")
}

/// Render the WAL `min/max` range as text, or `none present` when absent.
fn wal_range(min: Option<&str>, max: Option<&str>) -> String {
    match (min, max) {
        (Some(min), Some(max)) => format!("{min}/{max}"),
        _ => "none present".to_owned(),
    }
}

/// Render the `status:` line value (without the `error (...)` decoration logic
/// already folded into [`StanzaStatus`]).
fn status_line(status: &StanzaStatus) -> String {
    match status {
        StanzaStatus::Ok => "ok".to_owned(),
        StanzaStatus::NotInitialized => "error (missing stanza path)".to_owned(),
        StanzaStatus::Error(reason) => format!("error ({reason})"),
    }
}

/// Append the per-backup text block for one backup (the indented lines under a
/// `<type> backup: <label>` heading), mirroring `formatTextBackup` in the C
/// source.
fn render_backup_text(out: &mut String, b: &BackupSummary) {
    let _ = writeln!(out, "\n        {} backup: {}", b.backup_type, b.label);

    let start = b.start_timestamp.map_or_else(|| "?".to_owned(), format_timestamp);
    let stop = b.stop_timestamp.map_or_else(|| "?".to_owned(), format_timestamp);
    let _ = writeln!(out, "            timestamp start/stop: {start} / {stop}");

    match (b.archive_start.as_deref(), b.archive_stop.as_deref()) {
        (Some(s), Some(e)) => {
            let _ = writeln!(out, "            wal start/stop: {s} / {e}");
        }
        _ => out.push_str("            wal start/stop: n/a\n"),
    }

    let db_size = b.info_size.map_or_else(|| "?".to_owned(), human_size);
    // database backup size (delta) is not recorded per backup in this fork;
    // mirror the full size as a documented placeholder.
    let db_backup_size = db_size.clone();
    let _ = writeln!(
        out,
        "            database size: {db_size}, database backup size: {db_backup_size}"
    );

    let repo_key = b.db_id.unwrap_or(1);
    let repo_size = b.repo_size.map_or_else(|| "?".to_owned(), human_size);
    // backup set size == backup size here (no delta recorded).
    let _ = writeln!(
        out,
        "            repo{repo_key}: backup set size: {repo_size}, backup size: {repo_size}"
    );

    if !b.reference.is_empty() {
        let _ = writeln!(out, "            backup reference list: {}", b.reference.join(", "));
    }
}

/// Render the full per-stanza database/backup text block, grouping backups by
/// their `(db-id)`. Mirrors `formatTextDb`: a `wal archive min/max` header per
/// database followed by each backup. WAL min/max are not derived here (this
/// fork does not scan the archive directory in `info`), so they show
/// `none present`.
fn render_db_text(out: &mut String, summary: &StanzaSummary) {
    let version = summary.pg_version.as_deref().unwrap_or("?");
    let _ = writeln!(out, "\n        db ({version})");
    // WAL archive min/max would require scanning archive/<stanza>/<id>/; not
    // performed by this fork's `info`, so report none present.
    let _ = writeln!(out, "        wal archive min/max ({version}): {}", wal_range(None, None));

    for b in &summary.backups {
        render_backup_text(out, b);
    }
}

/// Render one `StanzaSummary` to its human-readable text block.
fn render_stanza_text(summary: &StanzaSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "stanza: {}", summary.name);
    let _ = writeln!(out, "    status: {}", status_line(&summary.status));

    // cipher is reported when the stanza exists on at least one repo. This
    // fork does not yet thread the repo cipher type into `info`, so report the
    // common case (`none`); documented placeholder.
    if !matches!(summary.status, StanzaStatus::NotInitialized) {
        out.push_str("    cipher: none\n");
        render_db_text(&mut out, summary);
    }
    out
}

/// Render all stanzas to the full human text layout. Pure: no I/O.
#[must_use]
pub fn render_text(stanzas: &[StanzaInfo]) -> String {
    if stanzas.is_empty() {
        return "No stanzas exist in the repository.\n".to_owned();
    }

    let mut out = String::new();
    for (idx, stanza) in stanzas.iter().enumerate() {
        // C separates stanzas with a blank line.
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&render_stanza_text(stanza));
    }
    out
}

/// Build the JSON value for one backup (the `backup[]` element).
fn backup_json(b: &BackupSummary, format: u32, version: &str) -> Value {
    let repo_key = b.db_id.unwrap_or(1);
    let info_size = b.info_size.unwrap_or(0);
    let repo_size = b.repo_size.unwrap_or(0);

    json!({
        "label": b.label,
        "type": b.backup_type,
        // backup-prior / backup-reference are emitted as-is; null / [] when absent.
        "prior": b.prior,
        "reference": b.reference,
        "archive": {
            "start": b.archive_start,
            "stop": b.archive_stop,
        },
        "backrest": {
            // Per-backup backrest format/version are not stored; mirror the
            // stanza-level backup.info header (documented placeholder).
            "format": format,
            "version": version,
        },
        "database": {
            "id": repo_key,
            // Single-repo fork: repo-key is always 1.
            "repo-key": 1,
        },
        "info": {
            "size": info_size,
            // size-delta not recorded per backup; mirror size.
            "delta": info_size,
            "repository": {
                "size": repo_size,
                // repository.delta not recorded per backup; mirror size.
                "delta": repo_size,
            },
        },
        "timestamp": {
            "start": b.start_timestamp.unwrap_or(0),
            "stop": b.stop_timestamp.unwrap_or(0),
        },
    })
}

/// Build the JSON value for one stanza (the array element). Mirrors the
/// `infoRender` stanza object: `name`, `status {code,message[,lock]}`,
/// `cipher`, `db [...]`, `archive [...]`, `backup [...]`.
fn stanza_json(summary: &StanzaSummary) -> Value {
    let db = match (summary.pg_id, summary.pg_system_id, summary.pg_version.as_deref()) {
        (Some(id), Some(system_id), Some(version)) => vec![json!({
            "id": id,
            "repo-key": 1,
            "system-id": system_id,
            "version": version,
        })],
        _ => Vec::new(),
    };

    // archive[] would carry per-db WAL min/max; this fork does not scan the
    // archive directory in `info`, so each db with identity gets a row with
    // null min/max (documented placeholder). The `id` here is the db-id as a
    // string stand-in for the C side's archive id (e.g. "14-1").
    let archive = summary.pg_id.map_or_else(Vec::new, |id| {
        vec![json!({
            "id": id.to_string(),
            "min": Value::Null,
            "max": Value::Null,
            "database": { "id": id, "repo-key": 1 },
        })]
    });

    let format = summary.backrest_format.unwrap_or(0);
    let version = summary.backrest_version.as_deref().unwrap_or("");
    let backup: Vec<Value> = summary.backups.iter().map(|b| backup_json(b, format, version)).collect();

    json!({
        "name": summary.name,
        "status": {
            "code": summary.status.code(),
            "message": summary.status.message(),
        },
        // Single-repo fork: cipher always none.
        "cipher": "none",
        "db": db,
        "archive": archive,
        "backup": backup,
    })
}

/// Render all stanzas to the structured JSON layout (a pretty-printed array of
/// stanza objects). Pure: no I/O.
#[must_use]
pub fn render_json(stanzas: &[StanzaInfo]) -> String {
    let arr = Value::Array(stanzas.iter().map(stanza_json).collect());
    // `to_string` never fails for a value we built ourselves.
    serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".to_owned())
}

/// Whether `--output=json` was requested. Defaults to text for any other
/// value (the only valid alternative per `config.yaml` is `text`).
fn want_json(config: &LoadedConfig) -> bool {
    matches!(
        config.options.get(&("output".to_owned(), None)),
        Some(OptionValue::StringId(v) | OptionValue::String(v)) if v == "json"
    )
}
/// The `--set=<label>` backup label, if one was supplied. `info`'s `set`
/// option is plain `string` (see `config.yaml`), so it arrives as
/// [`OptionValue::String`].
fn set_label(config: &LoadedConfig) -> Option<&str> {
    match config.options.get(&("set".to_owned(), None)) {
        Some(OptionValue::String(label) | OptionValue::StringId(label)) => Some(label.as_str()),
        _ => None,
    }
}

/// Repository-relative path to a backup's manifest.
fn manifest_path(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/backup.manifest"))
}

/// Outcome of trying to load the manifest for a `--set` backup. Distinguishes
/// "loaded" from "present in backup.info but the manifest file could not be
/// read" so the renderers can degrade with a note instead of failing.
enum SetManifest {
    /// Manifest loaded cleanly.
    Loaded(Box<Manifest>),
    /// The backup exists in `backup.info` but its manifest could not be read
    /// (missing file, malformed, checksum mismatch, …). Carries the reason.
    Unavailable(String),
}

/// Load the manifest for `label` under `stanza`. Returns
/// [`SetManifest::Unavailable`] (never an error) when the manifest file cannot
/// be read, so the detail view can still render the summary plus a note. The
/// "unknown label" case is detected separately against `backup.info` before
/// this is called.
fn load_set_manifest(repo: &dyn Storage, stanza: &str, label: &str) -> SetManifest {
    let path = manifest_path(stanza, label);
    match Manifest::load(repo, &path) {
        Ok(manifest) => SetManifest::Loaded(Box::new(manifest)),
        Err(InfoError::Storage(StorageError::NotFound { .. })) => {
            SetManifest::Unavailable(format!("manifest for backup '{label}' not found"))
        }
        Err(err) => SetManifest::Unavailable(format!("manifest for backup '{label}' unreadable: {err}")),
    }
}

/// Find the [`BackupSummary`] for `label` within a stanza summary.
fn find_backup<'a>(summary: &'a StanzaSummary, label: &str) -> Option<&'a BackupSummary> {
    summary.backups.iter().find(|b| b.label == label)
}

/// Render the detailed single-backup *text* block for `--set`. Pure over the
/// loaded [`Manifest`] (plus the `backup.info`-derived [`BackupSummary`] for the
/// summary lines and the stanza name for context). Mirrors the `set`-specific
/// rendering in `src/command/info/info.c`: the backup summary, then the
/// database list of the backed-up cluster and the manifest file list (count +
/// total size).
#[must_use]
fn render_set_text(stanza: &str, backup: &BackupSummary, manifest: &Manifest) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "stanza: {stanza}");

    // The summary block for just this backup (reuses the shared per-backup
    // formatter so the lines match the repo-wide listing exactly).
    render_backup_text(&mut out, backup);

    // database list — this fork's Manifest records the backed-up cluster's
    // identity (version + system-id) rather than a per-database catalog, so the
    // list has a single entry describing that cluster.
    out.push_str("\n            database list:\n");
    let _ = writeln!(
        out,
        "                {} (system-id {})",
        manifest.db_version, manifest.db_system_id
    );

    // file list — the count and total size captured by this backup's manifest.
    let file_count = manifest.files.len();
    let total_size = manifest.total_size();
    let _ = writeln!(
        out,
        "            file list: {file_count} file(s), {} ({total_size}B)",
        human_size(total_size)
    );

    // manifest timestamps (surfaced from the manifest itself).
    let start = format_timestamp(manifest.timestamp_start);
    let stop = format_timestamp(manifest.timestamp_stop);
    let _ = writeln!(out, "            manifest timestamp start/stop: {start} / {stop}");

    out
}

/// Render the detailed single-backup *JSON* detail block for `--set`. Returns
/// the `manifest` object that gets attached to the backup's JSON. Pure over the
/// loaded [`Manifest`].
#[must_use]
fn render_set_json(manifest: &Manifest) -> Value {
    json!({
        "label": manifest.backup_label,
        "type": manifest.backup_type,
        "file-count": manifest.files.len(),
        "file-total-size": manifest.total_size(),
        "path-count": manifest.paths.len(),
        "link-count": manifest.links.len(),
        "timestamp": {
            "start": manifest.timestamp_start,
            "stop": manifest.timestamp_stop,
        },
        // Single-database identity recorded by this fork's Manifest (the
        // backed-up cluster). The C side lists every database in the cluster;
        // this fork carries only the cluster version + system-id.
        "database": [
            {
                "version": manifest.db_version,
                "system-id": manifest.db_system_id,
            }
        ],
    })
}

/// Render the `--set` detail view in text form: the matching backup's summary
/// plus the manifest detail block, or a degradation note when the manifest is
/// unavailable.
fn render_set_view_text(stanza: &str, backup: &BackupSummary, manifest: &SetManifest) -> String {
    match manifest {
        SetManifest::Loaded(manifest) => render_set_text(stanza, backup, manifest),
        SetManifest::Unavailable(note) => {
            let mut out = String::new();
            let _ = writeln!(out, "stanza: {stanza}");
            render_backup_text(&mut out, backup);
            let _ = writeln!(out, "\n            note: {note}");
            out
        }
    }
}

/// Render the `--set` detail view in JSON form: the summary backup object with
/// a `manifest` detail block attached, or a `manifest-note` when the manifest
/// is unavailable.
fn render_set_view_json(backup: &BackupSummary, format: u32, version: &str, manifest: &SetManifest) -> Value {
    let mut obj = backup_json(backup, format, version);
    match manifest {
        SetManifest::Loaded(manifest) => {
            if let Some(map) = obj.as_object_mut() {
                map.insert("manifest".to_owned(), render_set_json(manifest));
            }
        }
        SetManifest::Unavailable(note) => {
            if let Some(map) = obj.as_object_mut() {
                map.insert("manifest-note".to_owned(), Value::String(note.clone()));
            }
        }
    }
    obj
}

/// Drive the `--set` detail path: resolve the stanza, locate the named backup
/// in `backup.info`, load its manifest, and render the detail view in the
/// requested format. Returns the rendered string.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] when `--stanza` is absent (`--set` depends
///   on it per `config.yaml`).
/// - [`CommandError::Other`] when the named label is not present in this
///   stanza's `backup.info` (unknown backup).
fn render_set(config: &LoadedConfig, repo_storage: &dyn Storage, label: &str) -> Result<String, CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;

    let summary = summarize_stanza(repo_storage, stanza);
    let backup = find_backup(&summary, label)
        .ok_or_else(|| CommandError::Other(format!("backup '{label}' does not exist in stanza '{stanza}'")))?;

    let manifest = load_set_manifest(repo_storage, stanza, label);

    if want_json(config) {
        let format = summary.backrest_format.unwrap_or(0);
        let version = summary.backrest_version.as_deref().unwrap_or("");
        let detail = render_set_view_json(backup, format, version, &manifest);
        Ok(serde_json::to_string_pretty(&Value::Array(vec![detail])).unwrap_or_else(|_| "[]".to_owned()))
    } else {
        Ok(render_set_view_text(stanza, backup, &manifest))
    }
}

/// `info` — print backup history for one or more stanzas in the requested
/// `--output` format (`text` default, or `json`).
///
/// # Errors
///
/// Returns whatever [`info_inner`] surfaces.
// CLI command: writing to stdout is the whole point.
#[allow(clippy::print_stdout)]
pub fn info(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    // `--set=<label>` switches to the detailed single-backup view (C ref:
    // src/command/info/info.c set-specific rendering).
    if let Some(label) = set_label(config) {
        let rendered = render_set(config, repo_storage, label)?;
        print!("{rendered}");
        return Ok(());
    }

    let summaries = info_inner(config, repo_storage)?;
    let rendered = if want_json(config) {
        render_json(&summaries)
    } else {
        render_text(&summaries)
    };
    print!("{rendered}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};
    use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup, Manifest, ManifestFile, ManifestLink, ManifestPath};
    use pgbr_storage::{Posix, Storage};
    use serde_json::json;
    use tempfile::TempDir;

    use pgbr_config::OptionValue;

    use super::{CommandError, StanzaStatus, format_timestamp, info, info_inner, render_json, render_set, render_text, want_json};

    fn fake_config(stanza: Option<&str>) -> LoadedConfig {
        LoadedConfig {
            command: "info".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options: BTreeMap::new(),
            params: Vec::new(),
        }
    }

    fn fake_config_output(stanza: Option<&str>, output: &str) -> LoadedConfig {
        let mut cfg = fake_config(stanza);
        cfg.options
            .insert(("output".to_owned(), None), OptionValue::StringId(output.to_owned()));
        cfg
    }
    /// Config carrying `--set=<label>` (and optionally `--output`).
    fn fake_config_set(stanza: Option<&str>, set: &str, output: Option<&str>) -> LoadedConfig {
        let mut cfg = fake_config(stanza);
        cfg.command = "info".to_owned();
        cfg.options
            .insert(("set".to_owned(), None), OptionValue::String(set.to_owned()));
        if let Some(out) = output {
            cfg.options
                .insert(("output".to_owned(), None), OptionValue::StringId(out.to_owned()));
        }
        cfg
    }

    fn posix_repo() -> (TempDir, Posix) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(dir.path());
        (dir, storage)
    }

    fn sample_archive() -> InfoArchive {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            history,
        }
    }

    fn sample_backup_with(current: BTreeMap<String, serde_json::Value>) -> InfoBackup {
        let mut history = BTreeMap::new();
        history.insert(
            1,
            DbHistoryEntry {
                db_id: 6_873_049_345_984_568_091,
                db_version: "14".to_owned(),
            },
        );
        InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
            db_catalog_version: 202_107_181,
            db_control_version: 1300,
            current,
            history,
        }
    }

    #[test]
    fn info_for_uninitialized_stanza_reports_not_initialized() {
        let (_dir, storage) = posix_repo();

        let cfg = fake_config(Some("demo"));
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "demo");
        assert_eq!(summaries[0].status, StanzaStatus::NotInitialized);
        assert!(summaries[0].pg_version.is_none());
        assert!(summaries[0].pg_system_id.is_none());
        assert!(summaries[0].backups.is_empty());
    }

    #[test]
    fn info_with_archive_only_reports_no_backups() {
        let (_dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");

        sample_archive()
            .save(&storage, std::path::Path::new("archive/demo/archive.info"))
            .expect("save archive.info");

        let cfg = fake_config(Some("demo"));
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.name, "demo");
        // archive.info loaded, backup.info missing => Error(...)
        assert!(matches!(s.status, StanzaStatus::Error(_)), "got {:?}", s.status);
        assert_eq!(s.pg_version.as_deref(), Some("14"));
        assert!(s.backups.is_empty());
    }

    #[test]
    fn info_with_archive_and_backup_lists_each_backup() {
        let (_dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");
        storage
            .create_path(std::path::Path::new("backup/demo"), true)
            .expect("create backup/demo");

        sample_archive()
            .save(&storage, std::path::Path::new("archive/demo/archive.info"))
            .expect("save archive.info");

        let mut current = BTreeMap::new();
        current.insert(
            "20260101-100000F".to_owned(),
            json!({
                "backup-info-size": 12345,
                "backup-info-repo-size": 67890,
                "backup-label": "20260101-100000F",
                "backup-timestamp-stop": 1_700_000_000,
                "backup-type": "full"
            }),
        );
        current.insert(
            "20260101-100000F_20260102-100000I".to_owned(),
            json!({
                "backup-info-size": 99,
                "backup-info-repo-size": 50,
                "backup-label": "20260101-100000F_20260102-100000I",
                "backup-timestamp-stop": 1_700_086_400,
                "backup-type": "incr",
                "backup-prior": "20260101-100000F"
            }),
        );

        sample_backup_with(current)
            .save(&storage, std::path::Path::new("backup/demo/backup.info"))
            .expect("save backup.info");

        let cfg = fake_config(Some("demo"));
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.name, "demo");
        assert_eq!(s.status, StanzaStatus::Ok);
        assert_eq!(s.pg_version.as_deref(), Some("14"));
        assert_eq!(s.backups.len(), 2);

        let labels: Vec<&str> = s.backups.iter().map(|b| b.label.as_str()).collect();
        assert!(labels.contains(&"20260101-100000F"));
        assert!(labels.contains(&"20260101-100000F_20260102-100000I"));

        let full = s.backups.iter().find(|b| b.label == "20260101-100000F").unwrap();
        assert_eq!(full.backup_type, "full");
        assert_eq!(full.stop_timestamp, Some(1_700_000_000));
        assert_eq!(full.repo_size, Some(67890));
    }

    #[test]
    fn info_no_stanza_arg_lists_all_stanzas_found() {
        let (_dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");
        storage
            .create_path(std::path::Path::new("archive/prod"), true)
            .expect("create archive/prod");

        let cfg = fake_config(None);
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 2);
        let names: Vec<&str> = summaries.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"demo"), "got {names:?}");
        assert!(names.contains(&"prod"), "got {names:?}");
        // Neither has info files; both should report NotInitialized.
        for s in &summaries {
            assert_eq!(s.status, StanzaStatus::NotInitialized);
        }
    }

    /// Initialise `demo` on `storage` with one `full` backup and return the
    /// info summaries for it.
    fn initialized_demo() -> (TempDir, super::StanzaSummary) {
        let (dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");
        storage
            .create_path(std::path::Path::new("backup/demo"), true)
            .expect("create backup/demo");

        sample_archive()
            .save(&storage, std::path::Path::new("archive/demo/archive.info"))
            .expect("save archive.info");

        let mut current = BTreeMap::new();
        current.insert(
            "20260101-100000F".to_owned(),
            json!({
                "backup-info-size": 1_200_000_000_u64,
                "backup-info-repo-size": 67_890,
                "backup-label": "20260101-100000F",
                "backup-timestamp-start": 1_700_000_000,
                "backup-timestamp-stop": 1_700_000_123,
                "backup-archive-start": "000000010000000000000002",
                "backup-archive-stop": "000000010000000000000003",
                "backup-type": "full",
                "db-id": 1
            }),
        );
        sample_backup_with(current)
            .save(&storage, std::path::Path::new("backup/demo/backup.info"))
            .expect("save backup.info");

        let cfg = fake_config(Some("demo"));
        let mut summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries.len(), 1);
        (dir, summaries.remove(0))
    }

    #[test]
    fn format_timestamp_renders_utc_civil_datetime() {
        // 1_700_000_000 = 2023-11-14 22:13:20 UTC.
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13:20+0000");
        // Epoch zero.
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00+0000");
    }

    #[test]
    fn render_text_for_initialized_stanza_with_full_backup() {
        let (_dir, summary) = initialized_demo();
        let text = render_text(std::slice::from_ref(&summary));

        assert!(text.contains("stanza: demo\n"), "missing stanza line:\n{text}");
        assert!(text.contains("    status: ok\n"), "missing status line:\n{text}");
        assert!(text.contains("    cipher: none\n"), "missing cipher line:\n{text}");
        assert!(text.contains("db (14)"), "missing db group line:\n{text}");
        assert!(
            text.contains("full backup: 20260101-100000F\n"),
            "missing backup heading:\n{text}"
        );
        assert!(
            text.contains("timestamp start/stop: 2023-11-14 22:13:20+0000 / 2023-11-14 22:15:23+0000\n"),
            "missing timestamp line:\n{text}"
        );
        assert!(
            text.contains("wal start/stop: 000000010000000000000002 / 000000010000000000000003\n"),
            "missing wal line:\n{text}"
        );
        assert!(
            text.contains("database size: 1.1GiB, database backup size: 1.1GiB\n"),
            "missing size line:\n{text}"
        );
        assert!(
            text.contains("repo1: backup set size: 66.3KiB, backup size: 66.3KiB\n"),
            "missing repo line:\n{text}"
        );
    }

    #[test]
    fn render_json_for_initialized_stanza_parses_with_expected_keys() {
        let (_dir, summary) = initialized_demo();
        let rendered = render_json(std::slice::from_ref(&summary));

        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        let arr = parsed.as_array().expect("top-level array");
        assert_eq!(arr.len(), 1);

        let stanza = &arr[0];
        assert_eq!(stanza["name"], json!("demo"));
        assert_eq!(stanza["status"]["code"], json!(0));
        assert_eq!(stanza["status"]["message"], serde_json::Value::Null);
        assert_eq!(stanza["cipher"], json!("none"));

        // db array carries the active cluster identity.
        let db = stanza["db"].as_array().expect("db array");
        assert_eq!(db.len(), 1);
        assert_eq!(db[0]["version"], json!("14"));
        assert_eq!(db[0]["id"], json!(1));

        // archive array present (min/max null in this fork).
        assert!(stanza["archive"].is_array());

        // backup array with the single full backup and its nested keys.
        let backup = stanza["backup"].as_array().expect("backup array");
        assert_eq!(backup.len(), 1);
        let b = &backup[0];
        assert_eq!(b["label"], json!("20260101-100000F"));
        assert_eq!(b["type"], json!("full"));
        assert_eq!(b["archive"]["start"], json!("000000010000000000000002"));
        assert_eq!(b["timestamp"]["start"], json!(1_700_000_000));
        assert_eq!(b["timestamp"]["stop"], json!(1_700_000_123));
        assert_eq!(b["info"]["size"], json!(1_200_000_000_u64));
        assert_eq!(b["info"]["repository"]["size"], json!(67_890));
        assert_eq!(b["prior"], serde_json::Value::Null);
    }

    #[test]
    fn output_option_selects_text_vs_json() {
        let text_cfg = fake_config_output(Some("demo"), "text");
        let json_cfg = fake_config_output(Some("demo"), "json");
        let default_cfg = fake_config(Some("demo"));

        assert!(!want_json(&text_cfg));
        assert!(want_json(&json_cfg));
        // Absent option => text default.
        assert!(!want_json(&default_cfg));

        // And the rendered output differs in shape: json parses, text does not.
        let (_dir, summary) = initialized_demo();
        let stanzas = std::slice::from_ref(&summary);
        assert!(serde_json::from_str::<serde_json::Value>(&render_json(stanzas)).is_ok());
        assert!(serde_json::from_str::<serde_json::Value>(&render_text(stanzas)).is_err());
    }

    #[test]
    fn uninitialized_stanza_renders_error_in_both_formats() {
        let (_dir, storage) = posix_repo();
        let cfg = fake_config(Some("demo"));
        let summaries = info_inner(&cfg, &storage).expect("info_inner");
        assert_eq!(summaries[0].status, StanzaStatus::NotInitialized);

        // Text: status line shows error.
        let text = render_text(&summaries);
        assert!(text.contains("stanza: demo\n"), "{text}");
        assert!(text.contains("    status: error (missing stanza path)\n"), "{text}");
        // No cipher / db block for an uninitialised stanza.
        assert!(!text.contains("cipher:"), "{text}");

        // JSON: non-zero status code with a message, empty db/backup arrays.
        let rendered = render_json(&summaries);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        let stanza = &parsed.as_array().expect("array")[0];
        assert_eq!(stanza["name"], json!("demo"));
        assert_eq!(stanza["status"]["code"], json!(1));
        assert_eq!(stanza["status"]["message"], json!("missing stanza path"));
        assert_eq!(stanza["db"].as_array().expect("db array").len(), 0);
        assert_eq!(stanza["backup"].as_array().expect("backup array").len(), 0);
    }
    /// Build a sample manifest for `label` with two files of known sizes.
    fn sample_manifest(label: &str) -> Manifest {
        Manifest {
            backup_label: label.to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_700_000_000,
            timestamp_stop: 1_700_000_123,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![
                ManifestFile {
                    path: "pg_data/PG_VERSION".to_owned(),
                    size: 3,
                    timestamp: 1_700_000_000,
                    checksum: Some("e1f2c3d4".to_owned()),
                    checksum_page: None,
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
                ManifestFile {
                    path: "pg_data/base/1/1259".to_owned(),
                    size: 8192,
                    timestamp: 1_700_000_000,
                    checksum: Some("a0b1c2d3".to_owned()),
                    checksum_page: Some(true),
                    reference: None,
                    mode: None,
                    user: None,
                    group: None,
                    bundle_id: None,
                    bundle_offset: None,
                    block_map: None,
                },
            ],
            paths: vec![ManifestPath {
                path: "pg_data".to_owned(),
            }],
            links: vec![ManifestLink {
                path: "pg_data/pg_wal".to_owned(),
                destination: "/var/lib/pg_wal".to_owned(),
            }],
        }
    }

    /// Seed `demo` with one full backup in `backup.info` AND its on-disk
    /// `backup.manifest`. Returns the live repo + its tempdir (kept alive).
    fn initialized_demo_with_manifest(label: &str) -> (TempDir, Posix) {
        let (dir, storage) = posix_repo();
        storage
            .create_path(std::path::Path::new("archive/demo"), true)
            .expect("create archive/demo");
        storage
            .create_path(std::path::Path::new("backup/demo"), true)
            .expect("create backup/demo");

        sample_archive()
            .save(&storage, std::path::Path::new("archive/demo/archive.info"))
            .expect("save archive.info");

        let mut current = BTreeMap::new();
        current.insert(
            label.to_owned(),
            json!({
                "backup-info-size": 8195_u64,
                "backup-info-repo-size": 4096_u64,
                "backup-label": label,
                "backup-timestamp-start": 1_700_000_000,
                "backup-timestamp-stop": 1_700_000_123,
                "backup-archive-start": "000000010000000000000002",
                "backup-archive-stop": "000000010000000000000003",
                "backup-type": "full",
                "db-id": 1
            }),
        );
        sample_backup_with(current)
            .save(&storage, std::path::Path::new("backup/demo/backup.info"))
            .expect("save backup.info");

        let dir_rel = format!("backup/demo/{label}");
        storage
            .create_path(std::path::Path::new(&dir_rel), true)
            .expect("create backup label dir");
        sample_manifest(label)
            .save(&storage, std::path::Path::new(&format!("{dir_rel}/backup.manifest")))
            .expect("save backup.manifest");

        (dir, storage)
    }

    #[test]
    fn set_text_renders_detailed_view_with_file_count_and_size() {
        let label = "20260101-100000F";
        let (_dir, storage) = initialized_demo_with_manifest(label);

        let cfg = fake_config_set(Some("demo"), label, None);
        let text = render_set(&cfg, &storage, label).expect("render_set text");

        assert!(text.contains("stanza: demo\n"), "missing stanza line:\n{text}");
        assert!(
            text.contains("full backup: 20260101-100000F\n"),
            "missing backup heading:\n{text}"
        );
        assert!(
            text.contains("file list: 2 file(s), 8.0KiB (8195B)"),
            "missing file list line:\n{text}"
        );
        assert!(text.contains("database list:"), "missing database list header:\n{text}");
        assert!(
            text.contains("14 (system-id 6873049345984568091)"),
            "missing database list entry:\n{text}"
        );
        assert!(
            text.contains("manifest timestamp start/stop: 2023-11-14 22:13:20+0000 / 2023-11-14 22:15:23+0000"),
            "missing manifest timestamp line:\n{text}"
        );
    }

    #[test]
    fn set_json_attaches_manifest_detail_block() {
        let label = "20260101-100000F";
        let (_dir, storage) = initialized_demo_with_manifest(label);

        let cfg = fake_config_set(Some("demo"), label, Some("json"));
        let rendered = render_set(&cfg, &storage, label).expect("render_set json");

        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        let arr = parsed.as_array().expect("top-level array");
        assert_eq!(arr.len(), 1);
        let backup = &arr[0];

        assert_eq!(backup["label"], json!(label));
        assert_eq!(backup["type"], json!("full"));

        let manifest = &backup["manifest"];
        assert_eq!(manifest["file-count"], json!(2));
        assert_eq!(manifest["file-total-size"], json!(8195));
        assert_eq!(manifest["path-count"], json!(1));
        assert_eq!(manifest["link-count"], json!(1));
        assert_eq!(manifest["timestamp"]["start"], json!(1_700_000_000));
        assert_eq!(manifest["timestamp"]["stop"], json!(1_700_000_123));

        let dbs = manifest["database"].as_array().expect("database array");
        assert_eq!(dbs.len(), 1);
        assert_eq!(dbs[0]["version"], json!("14"));
        assert_eq!(dbs[0]["system-id"], json!(6_873_049_345_984_568_091_u64));
    }

    #[test]
    fn set_unknown_label_errors() {
        let label = "20260101-100000F";
        let (_dir, storage) = initialized_demo_with_manifest(label);

        let cfg = fake_config_set(Some("demo"), "20991231-235959F", None);
        let err = render_set(&cfg, &storage, "20991231-235959F").expect_err("unknown label must error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("does not exist"), "got: {msg}"),
            other => panic!("expected Other(does not exist), got {other:?}"),
        }
    }

    #[test]
    fn set_requires_stanza() {
        let (_dir, storage) = posix_repo();
        let cfg = fake_config_set(None, "20260101-100000F", None);
        let err = render_set(&cfg, &storage, "20260101-100000F").expect_err("missing stanza must error");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption(stanza), got {other:?}"),
        }
    }

    #[test]
    fn set_missing_manifest_degrades_with_note() {
        let label = "20260101-100000F";
        let (_dir, storage) = initialized_demo_with_manifest(label);
        storage
            .remove(std::path::Path::new(&format!("backup/demo/{label}/backup.manifest")), false)
            .expect("remove manifest");

        let cfg = fake_config_set(Some("demo"), label, None);
        let text = render_set(&cfg, &storage, label).expect("render_set text degrade");
        assert!(text.contains("full backup: 20260101-100000F\n"), "missing summary:\n{text}");
        assert!(text.contains("note:"), "missing degradation note:\n{text}");
        assert!(text.contains("not found"), "note should mention not found:\n{text}");

        let json_cfg = fake_config_set(Some("demo"), label, Some("json"));
        let rendered = render_set(&json_cfg, &storage, label).expect("render_set json degrade");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        let backup = &parsed.as_array().expect("array")[0];
        assert_eq!(backup["label"], json!(label));
        assert!(backup.get("manifest").is_none(), "should have no manifest block:\n{rendered}");
        assert!(
            backup["manifest-note"].as_str().unwrap().contains("not found"),
            "missing manifest-note:\n{rendered}"
        );
    }

    #[test]
    fn info_with_set_dispatches_to_detail_view() {
        let label = "20260101-100000F";
        let (_dir, storage) = initialized_demo_with_manifest(label);
        let cfg = fake_config_set(Some("demo"), label, None);
        info(&cfg, &storage).expect("info --set should succeed");
    }
}
