//! Repository utility commands: `repo-ls`, `repo-get`, `repo-put`,
//! `repo-rm`.
//!
//! C reference: `src/command/repo/ls.c`, `src/command/repo/get.c`,
//! `src/command/repo/put.c`, `src/command/repo/rm.c`.
//!
//! `repo-get` / `repo-put` run their bytes through the shared
//! [`crate::pipeline::RepoTransform`] — the same compress -> encrypt /
//! decrypt -> decompress pipeline that `backup` / `restore` use — so a file
//! written by `repo-put` with `compress-type` / `cipher` options set is
//! readable by the rest of the toolchain (and vice versa). When the transform
//! is the identity (`compress-type=none`, no cipher) both commands fall back to
//! the prior raw byte-copy path: no filename suffix, bytes stored verbatim.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_storage::{Storage, StorageError, StorageInfo, StorageKind};

use crate::CommandError;
use crate::pipeline::RepoTransform;

/// Output format for `repo-ls` (the `--output` option, `text` by default).
///
/// C reference: `cfgOptionSeq(cfgOptOutput)` in `src/command/repo/ls.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// One entry name per line.
    Text,
    /// A JSON array of `{name, type, size, time}` objects.
    Json,
}

impl OutputFormat {
    /// Parse the `--output` string-id (`text` / `json`); anything else
    /// (including absent) falls back to [`OutputFormat::Text`], the option
    /// default.
    #[must_use]
    pub fn from_str_id(value: &str) -> Self {
        match value {
            "json" => Self::Json,
            // "text" and any unrecognised value.
            _ => Self::Text,
        }
    }
}

/// Sort order for `repo-ls` entries (the `--sort` option, `asc` by default).
///
/// Kept in sync with the `sort` `allow-list` in `config.yaml`. C reference:
/// `cfgOptionSeq(cfgOptSort)` -> `StorageInfoSortOrder` in
/// `src/command/repo/ls.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Preserve the backend's native (unsorted) order.
    None,
    /// Ascending by name.
    Asc,
    /// Descending by name.
    Desc,
}

impl SortOrder {
    /// Parse the `--sort` string-id (`none` / `asc` / `desc`); anything else
    /// (including absent) falls back to [`SortOrder::Asc`], the option default.
    #[must_use]
    pub fn from_str_id(value: &str) -> Self {
        match value {
            "none" => Self::None,
            "desc" => Self::Desc,
            // "asc" and any unrecognised value.
            _ => Self::Asc,
        }
    }
}

/// The pgBackRest type string for a [`StorageKind`], used as the `"type"`
/// field of the JSON output. Matches the C `storageListRenderInfo` mapping:
/// `file` / `link` / `path` / `special`.
const fn kind_str(kind: StorageKind) -> &'static str {
    match kind {
        StorageKind::File => "file",
        StorageKind::Link => "link",
        StorageKind::Path => "path",
        StorageKind::Special => "special",
    }
}

/// A single `repo-ls` entry.
///
/// Decoupled from [`StorageInfo`] so the rendering functions are pure and
/// testable. `name` is the entry path *relative to the listed target* (so
/// recursion yields `sub/file`, matching the C `info->name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsEntry {
    /// Name relative to the listed path.
    pub name: String,
    /// Entry kind.
    pub kind: StorageKind,
    /// Size in bytes (files only; `0` otherwise).
    pub size: u64,
    /// Last-modified time as Unix epoch seconds, when the backend tracks it.
    pub time: Option<i64>,
}

/// Compute the listing for `repo-ls` as bare paths.
///
/// Retained for backward compatibility (it predates the richer [`ls_entries`]
/// / [`render_ls`] helpers). Pure function — no I/O beyond the supplied storage
/// backend.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if the underlying `list` call fails.
pub fn ls_inner(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<Vec<PathBuf>, CommandError> {
    let target = config.params.first().map_or_else(|| PathBuf::from("."), PathBuf::from);

    let entries = repo_storage.list(&target)?;
    Ok(entries.into_iter().map(|info| info.path).collect())
}

/// Read the `--recurse` boolean (default `false`).
fn recurse_opt(config: &LoadedConfig) -> bool {
    boolean_opt(config, "recurse").unwrap_or(false)
}

/// Recursively collect entries beneath `target`, expressing each entry's name
/// relative to `target`. When `recurse` is false this is a single shallow
/// `list`. Directories are emitted before their contents (matching the C
/// iterator's pre-order walk).
fn collect_entries(
    repo_storage: &dyn Storage,
    target: &Path,
    prefix: &str,
    recurse: bool,
    out: &mut Vec<LsEntry>,
) -> Result<(), CommandError> {
    for info in repo_storage.list(target)? {
        let StorageInfo {
            path,
            kind,
            size,
            modified,
        } = info;
        // The backend returns full resolved paths; the entry's display name is
        // its final component, optionally prefixed by the relative sub-path
        // accumulated during recursion.
        let leaf = path
            .file_name()
            .map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
        let name = if prefix.is_empty() {
            leaf.clone()
        } else {
            format!("{prefix}/{leaf}")
        };

        let is_path = matches!(kind, StorageKind::Path);
        out.push(LsEntry {
            name: name.clone(),
            kind,
            size,
            time: modified,
        });

        if recurse && is_path {
            collect_entries(repo_storage, &path, &name, recurse, out)?;
        }
    }
    Ok(())
}

/// Compute the `repo-ls` entries with `--recurse` applied and `--sort`
/// ordering imposed. Pure relative to the supplied storage backend so tests
/// can assert against the result without capturing stdout.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if any underlying `list` call fails.
pub fn ls_entries(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<Vec<LsEntry>, CommandError> {
    let target = config.params.first().map_or_else(|| PathBuf::from("."), PathBuf::from);
    let recurse = recurse_opt(config);

    let mut entries = Vec::new();
    collect_entries(repo_storage, &target, "", recurse, &mut entries)?;

    match sort_order_opt(config) {
        SortOrder::None => {}
        SortOrder::Asc => entries.sort_by(|a, b| a.name.cmp(&b.name)),
        SortOrder::Desc => entries.sort_by(|a, b| b.name.cmp(&a.name)),
    }
    Ok(entries)
}

/// Render `repo-ls` entries as text: one name per line.
#[must_use]
pub fn render_ls_text(entries: &[LsEntry]) -> String {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&entry.name);
        out.push('\n');
    }
    out
}

/// Render `repo-ls` entries as a JSON array of `{name, type, size, time}`
/// objects. `size` and `time` are only present for files (matching the C
/// renderer, which omits them for non-file entries).
#[must_use]
pub fn render_ls_json(entries: &[LsEntry]) -> String {
    let array: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".to_owned(), serde_json::Value::from(entry.name.clone()));
            obj.insert("type".to_owned(), serde_json::Value::from(kind_str(entry.kind)));
            if matches!(entry.kind, StorageKind::File) {
                obj.insert("size".to_owned(), serde_json::Value::from(entry.size));
                if let Some(time) = entry.time {
                    obj.insert("time".to_owned(), serde_json::Value::from(time));
                }
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    serde_json::Value::Array(array).to_string()
}

/// Render `repo-ls` entries in the format selected by `--output`. Pure: no
/// I/O, so tests assert against the returned string directly.
#[must_use]
pub fn render_ls(config: &LoadedConfig, entries: &[LsEntry]) -> String {
    match output_format_opt(config) {
        OutputFormat::Text => render_ls_text(entries),
        OutputFormat::Json => render_ls_json(entries),
    }
}

/// `repo-ls` — list entries beneath the first positional argument (or the
/// repo root when none is given), honouring `--recurse`, `--sort` and
/// `--output`.
///
/// # Errors
///
/// Returns whatever [`ls_entries`] surfaces.
// CLI command writes to stdout by design.
#[allow(clippy::print_stdout)]
pub fn ls(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let entries = ls_entries(config, repo_storage)?;
    // `render_ls` already terminates each text line with `\n`; JSON has no
    // trailing newline, so print! keeps the text path byte-identical to the
    // prior per-line println! output while not appending a spurious newline to
    // JSON.
    print!("{}", render_ls(config, &entries));
    if output_format_opt(config) == OutputFormat::Json {
        println!();
    }
    Ok(())
}

/// Inner `repo-get` implementation: read the file at the first positional
/// path from `repo_storage`, reverse the configured repo transform, and copy
/// the recovered bytes into `out`.
///
/// Factored out of [`get`] so tests can pass a `Vec<u8>` (or any other
/// [`std::io::Write`]) without touching the process stdout handle.
///
/// # Path resolution
///
/// The configured [`RepoTransform`] (from `compress-type` / `cipher` options)
/// drives both *which* file is read and *how* it is decoded:
///
/// - **Identity transform** (`compress-type=none`, no cipher): the exact
///   `<path>` is read and its bytes are written through unchanged — the prior
///   raw byte-copy behaviour, byte-for-byte.
/// - **Non-identity transform**: the exact `<path>` is preferred; if it does
///   not exist, the compression-suffixed `<path><suffix>` (e.g. `<path>.gz`) is
///   tried — this is what `repo-put` writes. The bytes that are found are run
///   through [`RepoTransform::reverse_chain`] (decrypt -> decompress) to
///   recover the plaintext.
///
/// # `--raw`
///
/// When `--raw` is set the stored bytes are emitted verbatim: no suffix
/// fallback is attempted and the reverse transform (decrypt -> decompress) is
/// skipped entirely. This mirrors the C `cfgOptRaw` short-circuit in
/// `src/command/repo/get.c`.
///
/// # `--ignore-missing`
///
/// When `--ignore-missing` is set, a missing source file is **not** an error:
/// `get_to` returns `Ok(())` having written nothing. (The C side reports exit
/// code 1 in this case; the byte-level contract callers care about — empty
/// output, no exception — is preserved here.)
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if no positional path was supplied.
/// - [`CommandError::Storage`] if the open / read fails (a missing path
///   surfaces as [`pgbr_storage::StorageError::NotFound`] unless
///   `--ignore-missing` is set).
/// - [`CommandError::Io`] if a filter in the reverse chain fails (e.g. wrong
///   cipher password, corrupt compressed stream).
/// - [`CommandError::Other`] if writing to `out` fails.
pub fn get_to<W: Write>(config: &LoadedConfig, repo_storage: &dyn Storage, out: &mut W) -> Result<(), CommandError> {
    let path = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<path>".to_owned(),
    })?;
    let raw = boolean_opt(config, "raw").unwrap_or(false);
    let ignore_missing = boolean_opt(config, "ignore-missing").unwrap_or(false);

    // `--raw` short-circuits the transform: read the exact path verbatim with
    // no suffix fallback and no reverse chain.
    if raw {
        let Some(bytes) = read_exact_bytes(repo_storage, path, ignore_missing)? else {
            return Ok(());
        };
        out.write_all(&bytes)
            .map_err(|err| CommandError::Other(format!("write output: {err}")))?;
        return Ok(());
    }

    let transform = RepoTransform::from_options(config);

    let Some(stored) = read_repo_bytes(repo_storage, path, &transform, ignore_missing)? else {
        return Ok(());
    };

    let plaintext = if transform == RepoTransform::identity() {
        stored
    } else {
        transform.apply_reverse(&stored)?
    };

    out.write_all(&plaintext)
        .map_err(|err| CommandError::Other(format!("write output: {err}")))?;
    Ok(())
}

/// Read the exact `<path>` with no suffix fallback. `Ok(None)` when the file is
/// missing and `ignore_missing` is set; otherwise a missing file surfaces as
/// [`StorageError::NotFound`].
fn read_exact_bytes(repo_storage: &dyn Storage, path: &str, ignore_missing: bool) -> Result<Option<Vec<u8>>, CommandError> {
    match repo_storage.open_read(Path::new(path)) {
        Ok(mut reader) => Ok(Some(reader.read_all()?)),
        Err(StorageError::NotFound { .. }) if ignore_missing => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Read the repo-side bytes for `repo-get`: prefer the exact `<path>`; when the
/// transform is non-identity and the exact path is absent, fall back to the
/// suffixed `<path><suffix>`. The identity transform never falls back (its
/// suffix is empty anyway) so its `NotFound` surfaces unchanged.
///
/// Returns `Ok(None)` when the file (and its suffixed variant) are missing and
/// `ignore_missing` is set; otherwise a missing file surfaces as
/// [`StorageError::NotFound`].
fn read_repo_bytes(
    repo_storage: &dyn Storage,
    path: &str,
    transform: &RepoTransform,
    ignore_missing: bool,
) -> Result<Option<Vec<u8>>, CommandError> {
    match repo_storage.open_read(Path::new(path)) {
        Ok(mut reader) => Ok(Some(reader.read_all()?)),
        Err(StorageError::NotFound { .. }) if !transform.repo_suffix().is_empty() => {
            let suffixed = format!("{path}{}", transform.repo_suffix());
            match repo_storage.open_read(Path::new(&suffixed)) {
                Ok(mut reader) => Ok(Some(reader.read_all()?)),
                Err(StorageError::NotFound { .. }) if ignore_missing => Ok(None),
                Err(err) => Err(err.into()),
            }
        }
        Err(StorageError::NotFound { .. }) if ignore_missing => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// `repo-get <path>` — read `<path>` from the repo and write its
/// contents to stdout.
///
/// # Errors
///
/// Returns [`CommandError::MissingOption`] if no positional path was
/// supplied. Storage / I/O failures bubble up as
/// [`CommandError::Storage`] / [`CommandError::Io`].
pub fn get(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    get_to(config, repo_storage, &mut handle)
}

/// Inner `repo-put` implementation.
///
/// Reads every byte of `input`, runs it through the configured repo transform
/// (compress -> encrypt), and writes the result into `repo_storage`, flushing
/// and closing the writer at the end so the file is durable.
///
/// The target filename is the first positional path with the transform's
/// compression suffix appended ([`RepoTransform::repo_suffix`]): `<path>.gz`,
/// `<path>.zst`, etc. The identity transform (`compress-type=none`, no cipher)
/// has an empty suffix and a pass-through chain, so it writes the raw bytes to
/// the bare `<path>` exactly as before.
///
/// # `--raw`
///
/// When `--raw` is set the input is stored verbatim at the bare `<path>`: no
/// compress / encrypt transform is applied and no suffix is appended. This
/// mirrors the C `cfgOptRaw` short-circuit in `src/command/repo/put.c` and is
/// the exact inverse of `repo-get --raw`.
///
/// Factored out of [`put`] so tests can pass an `io::Cursor<&[u8]>` (or
/// any other [`std::io::Read`]) without touching the process stdin
/// handle.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if no target path was supplied.
/// - [`CommandError::Storage`] if the open / write / flush / close fails.
/// - [`CommandError::Io`] if a filter in the forward chain fails.
/// - [`CommandError::Other`] if reading from `input` fails.
pub fn put_from<R: Read>(config: &LoadedConfig, repo_storage: &dyn Storage, input: &mut R) -> Result<(), CommandError> {
    let path = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<path>".to_owned(),
    })?;
    let raw = boolean_opt(config, "raw").unwrap_or(false);

    // Slurp stdin: the compress / encrypt filters buffer their whole input
    // before emitting, so there is nothing to gain from streaming here.
    let mut plaintext = Vec::new();
    input
        .read_to_end(&mut plaintext)
        .map_err(|err| CommandError::Other(format!("read input: {err}")))?;

    // `--raw` short-circuits the transform: verbatim bytes at the bare path.
    let (repo_bytes, target) = if raw {
        (plaintext, path.clone())
    } else {
        let transform = RepoTransform::from_options(config);
        let target = format!("{path}{}", transform.repo_suffix());
        let bytes = if transform == RepoTransform::identity() {
            plaintext
        } else {
            transform.apply_forward(&plaintext)?
        };
        (bytes, target)
    };

    let mut writer = repo_storage.open_write(Path::new(&target))?;
    writer.write(&repo_bytes)?;
    writer.flush()?;
    writer.close()?;
    Ok(())
}

/// `repo-put <path>` — read stdin and write to `<path>` in the repo.
///
/// # Errors
///
/// Returns [`CommandError::MissingOption`] if no target path was
/// supplied. Storage / I/O failures bubble up as
/// [`CommandError::Storage`] / [`CommandError::Io`].
pub fn put(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    put_from(config, repo_storage, &mut handle)
}

/// `repo-rm` — remove every positional argument from the repository.
///
/// A file is removed outright. A directory is removed only when it is empty
/// *or* `--recurse` is set; removing a non-empty directory without `--recurse`
/// is rejected with [`CommandError::Other`] — matching the C side's
/// `OptionInvalidError` ("recurse option must be used to delete non-empty
/// path"). A missing entry is never an error (the C `error_on_missing = false`
/// contract).
///
/// # Errors
///
/// - [`CommandError::Other`] when a non-empty directory is targeted without
///   `--recurse`.
/// - [`CommandError::Storage`] if a removal fails for a reason other than
///   "missing".
pub fn rm(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let recurse = recurse_opt(config);
    for raw in &config.params {
        let path = Path::new(raw);
        remove_any(repo_storage, path, recurse)?;
    }
    Ok(())
}

fn remove_any(storage: &dyn Storage, path: &Path, recurse: bool) -> Result<(), CommandError> {
    // Probe to decide whether to call remove (file) or remove_path
    // (directory).
    match storage.info(path) {
        Ok(info) if matches!(info.kind, StorageKind::Path) => {
            // The C side requires --recurse to delete a non-empty directory.
            if !recurse && !storage.list(path)?.is_empty() {
                return Err(CommandError::Other(
                    "recurse option must be used to delete non-empty path".to_owned(),
                ));
            }
            match storage.remove_path(path, recurse, false) {
                Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
                Err(err) => Err(err.into()),
            }
        }
        Ok(_) => match storage.remove(path, false) {
            Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
            Err(err) => Err(err.into()),
        },
        Err(StorageError::NotFound { .. }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Read the `--output` option (default [`OutputFormat::Text`]).
fn output_format_opt(config: &LoadedConfig) -> OutputFormat {
    string_id_opt(config, "output").map_or(OutputFormat::Text, OutputFormat::from_str_id)
}

/// Read the `--sort` option (default [`SortOrder::Asc`]).
fn sort_order_opt(config: &LoadedConfig) -> SortOrder {
    string_id_opt(config, "sort").map_or(SortOrder::Asc, SortOrder::from_str_id)
}

/// Fetch a `StringId` option (no group index) as `&str`.
fn string_id_opt<'a>(config: &'a LoadedConfig, name: &str) -> Option<&'a str> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::StringId(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Fetch a `Boolean` option (no group index).
fn boolean_opt(config: &LoadedConfig, name: &str) -> Option<bool> {
    match config.options.get(&(name.to_owned(), None)) {
        Some(OptionValue::Boolean(value)) => Some(*value),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_storage::{Posix, Storage, StorageKind};
    use tempfile::TempDir;

    use super::{
        CommandError, LsEntry, OutputFormat, SortOrder, get_to, ls_entries, put_from, render_ls, render_ls_json, render_ls_text, rm,
    };
    use crate::pipeline::RepoTransform;

    fn fake_config(command: &str, params: Vec<String>) -> LoadedConfig {
        LoadedConfig {
            command: command.to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: None,
            options: BTreeMap::new(),
            params,
        }
    }

    /// Like [`fake_config`] but with extra option entries (no group index)
    /// merged in — used to drive the `compress-type` / `cipher` transform.
    fn fake_config_with(command: &str, params: Vec<String>, options: Vec<(&str, OptionValue)>) -> LoadedConfig {
        let mut cfg = fake_config(command, params);
        for (name, value) in options {
            cfg.options.insert((name.to_owned(), None), value);
        }
        cfg
    }

    fn posix_repo() -> (TempDir, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(repo.path());
        (repo, storage)
    }

    #[test]
    fn repo_get_missing_param_errors_with_missing_option() {
        let cfg = fake_config("repo-get", Vec::new());
        let (_repo, storage) = posix_repo();
        let mut buf: Vec<u8> = Vec::new();
        let err = get_to(&cfg, &storage, &mut buf).expect_err("missing path must error");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "<path>"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn repo_put_missing_param_errors_with_missing_option() {
        let cfg = fake_config("repo-put", Vec::new());
        let (_repo, storage) = posix_repo();
        let mut input = Cursor::new(Vec::<u8>::new());
        let err = put_from(&cfg, &storage, &mut input).expect_err("missing path must error");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "<path>"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn repo_get_reads_existing_file_to_writer() {
        let (repo, storage) = posix_repo();
        std::fs::write(repo.path().join("greeting.txt"), b"hello").expect("seed file");

        let cfg = fake_config("repo-get", vec!["greeting.txt".to_owned()]);
        let mut buf: Vec<u8> = Vec::new();
        get_to(&cfg, &storage, &mut buf).expect("get_to should succeed");
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn repo_get_unknown_path_errors_with_storage_not_found() {
        let (_repo, storage) = posix_repo();
        let cfg = fake_config("repo-get", vec!["nope.txt".to_owned()]);
        let mut buf: Vec<u8> = Vec::new();
        let err = get_to(&cfg, &storage, &mut buf).expect_err("missing file must error");
        match err {
            CommandError::Storage(pgbr_storage::StorageError::NotFound { .. }) => {}
            other => panic!("expected Storage(NotFound), got {other:?}"),
        }
    }

    #[test]
    fn repo_put_writes_stdin_to_storage() {
        let (repo, storage) = posix_repo();
        let cfg = fake_config("repo-put", vec!["wrote.txt".to_owned()]);
        let mut input = Cursor::new(b"world".to_vec());

        put_from(&cfg, &storage, &mut input).expect("put_from should succeed");

        let written = std::fs::read(repo.path().join("wrote.txt")).expect("read back");
        assert_eq!(written, b"world");
    }

    #[test]
    fn repo_put_to_nested_path_errors_when_parent_missing() {
        // Posix::open_write is backed by std::fs::File::create which does
        // NOT auto-create missing parent directories. Document that
        // semantics with a test: the call must surface a Storage backend
        // error rather than silently succeed or panic.
        let (_repo, storage) = posix_repo();
        let cfg = fake_config("repo-put", vec!["nested/dir/file.txt".to_owned()]);
        let mut input = Cursor::new(b"payload".to_vec());

        let err = put_from(&cfg, &storage, &mut input).expect_err("missing parent must error");
        match err {
            CommandError::Storage(pgbr_storage::StorageError::Backend { .. } | pgbr_storage::StorageError::NotFound { .. }) => {}
            other => panic!("expected Storage(Backend|NotFound), got {other:?}"),
        }
    }

    #[test]
    fn repo_put_none_is_raw() {
        // The default (no compress-type / cipher options) transform is the
        // identity: the file lands at the bare path with verbatim bytes and no
        // suffix. Guards the no-regression contract.
        let (repo, storage) = posix_repo();
        let cfg = fake_config("repo-put", vec!["raw.bin".to_owned()]);
        let payload = b"verbatim bytes, no transform";
        let mut input = Cursor::new(payload.to_vec());

        put_from(&cfg, &storage, &mut input).expect("identity put_from should succeed");

        // Stored at the bare path, byte-for-byte.
        let written = std::fs::read(repo.path().join("raw.bin")).expect("read back");
        assert_eq!(written, payload, "identity put must store raw bytes");
        // No suffixed file was created.
        assert!(!repo.path().join("raw.bin.gz").exists(), "identity put must not suffix");

        // And get recovers them unchanged.
        let get_cfg = fake_config("repo-get", vec!["raw.bin".to_owned()]);
        let mut buf: Vec<u8> = Vec::new();
        get_to(&get_cfg, &storage, &mut buf).expect("identity get_to should succeed");
        assert_eq!(buf, payload);
    }

    #[test]
    fn repo_put_gz_then_get_gz_round_trip() {
        let (repo, storage) = posix_repo();
        let payload = b"the quick brown fox jumps over the lazy dog, repeated repeated repeated repeated";

        // Put with compress-type=gz.
        let put_cfg = fake_config_with(
            "repo-put",
            vec!["doc.txt".to_owned()],
            vec![("compress-type", OptionValue::StringId("gz".to_owned()))],
        );
        let mut input = Cursor::new(payload.to_vec());
        put_from(&put_cfg, &storage, &mut input).expect("gz put_from should succeed");

        // Stored at the .gz-suffixed path, and the on-disk bytes are compressed
        // (not the plaintext).
        let stored = std::fs::read(repo.path().join("doc.txt.gz")).expect("read back compressed");
        assert_ne!(stored.as_slice(), payload.as_slice(), "gz put must compress the bytes");
        assert!(!repo.path().join("doc.txt").exists(), "gz put must not write the bare path");

        // Get with the same transform recovers the original. The exact path
        // does not exist, so this exercises the <path><suffix> fallback.
        let get_cfg = fake_config_with(
            "repo-get",
            vec!["doc.txt".to_owned()],
            vec![("compress-type", OptionValue::StringId("gz".to_owned()))],
        );
        let mut buf: Vec<u8> = Vec::new();
        get_to(&get_cfg, &storage, &mut buf).expect("gz get_to should succeed");
        assert_eq!(buf, payload, "gz round trip must recover the plaintext");
    }

    #[test]
    fn repo_put_cipher_round_trip() {
        let (repo, storage) = posix_repo();
        let payload = b"secret payload that must be encrypted at rest";

        // Put with cipher-pass set (cipher-type=aes-256-cbc enables it).
        let put_cfg = fake_config_with(
            "repo-put",
            vec!["secret.bin".to_owned()],
            vec![
                ("cipher-type", OptionValue::StringId("aes-256-cbc".to_owned())),
                ("cipher-pass", OptionValue::String("secret".to_owned())),
            ],
        );
        let mut input = Cursor::new(payload.to_vec());
        put_from(&put_cfg, &storage, &mut input).expect("cipher put_from should succeed");

        // Encryption does not change the suffix, so the file is at the bare
        // path; its bytes differ from the plaintext.
        assert_eq!(
            RepoTransform::from_options(&put_cfg).repo_suffix(),
            "",
            "cipher-only transform has no suffix"
        );
        let stored = std::fs::read(repo.path().join("secret.bin")).expect("read back ciphertext");
        assert_ne!(stored.as_slice(), payload.as_slice(), "cipher put must encrypt the bytes");

        // Get with the same password recovers the plaintext.
        let get_cfg = fake_config_with(
            "repo-get",
            vec!["secret.bin".to_owned()],
            vec![
                ("cipher-type", OptionValue::StringId("aes-256-cbc".to_owned())),
                ("cipher-pass", OptionValue::String("secret".to_owned())),
            ],
        );
        let mut buf: Vec<u8> = Vec::new();
        get_to(&get_cfg, &storage, &mut buf).expect("cipher get_to should succeed");
        assert_eq!(buf, payload, "cipher round trip must recover the plaintext");
    }

    // ----- repo-ls: rendering (pure) ------------------------------------

    fn file_entry(name: &str, size: u64, time: i64) -> LsEntry {
        LsEntry {
            name: name.to_owned(),
            kind: StorageKind::File,
            size,
            time: Some(time),
        }
    }

    fn path_entry(name: &str) -> LsEntry {
        LsEntry {
            name: name.to_owned(),
            kind: StorageKind::Path,
            size: 0,
            time: None,
        }
    }

    #[test]
    fn ls_render_text_is_one_name_per_line() {
        let entries = vec![path_entry("archive"), file_entry("backup.info", 5, 1_000)];
        assert_eq!(render_ls_text(&entries), "archive\nbackup.info\n");
    }

    #[test]
    fn ls_render_json_is_array_of_objects() {
        let entries = vec![path_entry("archive"), file_entry("backup.info", 5, 1_000)];
        let rendered = render_ls_json(&entries);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json array");
        let arr = parsed.as_array().expect("array");
        assert_eq!(arr.len(), 2);

        // The path entry carries name + type only (no size/time).
        assert_eq!(arr[0]["name"], serde_json::json!("archive"));
        assert_eq!(arr[0]["type"], serde_json::json!("path"));
        assert!(arr[0].get("size").is_none(), "path entry must omit size");
        assert!(arr[0].get("time").is_none(), "path entry must omit time");

        // The file entry carries name + type + size + time.
        assert_eq!(arr[1]["name"], serde_json::json!("backup.info"));
        assert_eq!(arr[1]["type"], serde_json::json!("file"));
        assert_eq!(arr[1]["size"], serde_json::json!(5));
        assert_eq!(arr[1]["time"], serde_json::json!(1_000));
    }

    #[test]
    fn ls_render_dispatches_on_output_option() {
        let entries = vec![file_entry("a.txt", 1, 0)];

        // Default (no option) -> text.
        let text_cfg = fake_config("repo-ls", vec![".".to_owned()]);
        assert_eq!(render_ls(&text_cfg, &entries), render_ls_text(&entries));

        // --output=json -> json.
        let json_cfg = fake_config_with(
            "repo-ls",
            vec![".".to_owned()],
            vec![("output", OptionValue::StringId("json".to_owned()))],
        );
        assert_eq!(render_ls(&json_cfg, &entries), render_ls_json(&entries));
    }

    #[test]
    fn output_format_and_sort_order_parse_from_str_id() {
        assert_eq!(OutputFormat::from_str_id("json"), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str_id("text"), OutputFormat::Text);
        assert_eq!(OutputFormat::from_str_id("garbage"), OutputFormat::Text);

        assert_eq!(SortOrder::from_str_id("none"), SortOrder::None);
        assert_eq!(SortOrder::from_str_id("asc"), SortOrder::Asc);
        assert_eq!(SortOrder::from_str_id("desc"), SortOrder::Desc);
        assert_eq!(SortOrder::from_str_id("garbage"), SortOrder::Asc);
    }

    // ----- repo-ls: listing (storage-backed) ----------------------------

    fn seed(storage: &Posix, rel: &str, body: &[u8]) {
        let mut w = storage.open_write(Path::new(rel)).expect("open_write seed");
        w.write(body).expect("write seed");
        w.close().expect("close seed");
    }

    #[test]
    fn ls_entries_sort_asc_and_desc() {
        let (_repo, storage) = posix_repo();
        seed(&storage, "c.txt", b"c");
        seed(&storage, "a.txt", b"a");
        seed(&storage, "b.txt", b"b");

        // Ascending (the default).
        let asc_cfg = fake_config("repo-ls", vec![".".to_owned()]);
        let asc: Vec<String> = ls_entries(&asc_cfg, &storage)
            .expect("ls_entries asc")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(asc, vec!["a.txt", "b.txt", "c.txt"]);

        // Descending.
        let desc_cfg = fake_config_with(
            "repo-ls",
            vec![".".to_owned()],
            vec![("sort", OptionValue::StringId("desc".to_owned()))],
        );
        let desc: Vec<String> = ls_entries(&desc_cfg, &storage)
            .expect("ls_entries desc")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(desc, vec!["c.txt", "b.txt", "a.txt"]);
    }

    #[test]
    fn ls_entries_recurse_descends_into_subdirs() {
        let (_repo, storage) = posix_repo();
        storage.create_path(Path::new("sub"), false).expect("mkdir sub");
        storage.create_path(Path::new("sub/inner"), false).expect("mkdir sub/inner");
        seed(&storage, "top.txt", b"t");
        seed(&storage, "sub/mid.txt", b"m");
        seed(&storage, "sub/inner/deep.txt", b"d");

        // Without --recurse only the top level is listed.
        let shallow_cfg = fake_config("repo-ls", vec![".".to_owned()]);
        let shallow: Vec<String> = ls_entries(&shallow_cfg, &storage)
            .expect("shallow ls")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(shallow, vec!["sub", "top.txt"], "shallow listing must not descend");

        // With --recurse the nested entries appear with relative names.
        let recurse_cfg = fake_config_with("repo-ls", vec![".".to_owned()], vec![("recurse", OptionValue::Boolean(true))]);
        let deep: Vec<String> = ls_entries(&recurse_cfg, &storage)
            .expect("recurse ls")
            .into_iter()
            .map(|e| e.name)
            .collect();
        // Sorted ascending by relative name.
        assert_eq!(
            deep,
            vec!["sub", "sub/inner", "sub/inner/deep.txt", "sub/mid.txt", "top.txt"],
            "recurse must yield relative nested names"
        );
    }

    // ----- repo-get --raw / --ignore-missing ----------------------------

    #[test]
    fn repo_get_raw_returns_stored_bytes_no_transform() {
        let (repo, storage) = posix_repo();
        let payload = b"the quick brown fox jumps repeated repeated repeated repeated repeated";

        // Store gz-compressed at doc.txt.gz via the normal transform.
        let put_cfg = fake_config_with(
            "repo-put",
            vec!["doc.txt".to_owned()],
            vec![("compress-type", OptionValue::StringId("gz".to_owned()))],
        );
        let mut input = Cursor::new(payload.to_vec());
        put_from(&put_cfg, &storage, &mut input).expect("gz put should succeed");
        let stored = std::fs::read(repo.path().join("doc.txt.gz")).expect("read compressed");
        assert_ne!(stored.as_slice(), payload.as_slice(), "guard: stored bytes are compressed");

        // --raw get of the exact stored path returns the compressed bytes
        // verbatim (no decompress, no suffix fallback).
        let raw_cfg = fake_config_with(
            "repo-get",
            vec!["doc.txt.gz".to_owned()],
            vec![("raw", OptionValue::Boolean(true))],
        );
        let mut buf: Vec<u8> = Vec::new();
        get_to(&raw_cfg, &storage, &mut buf).expect("raw get should succeed");
        assert_eq!(buf, stored, "--raw must return the stored bytes untransformed");

        // The default (non-raw) get with the same transform recovers the
        // plaintext from the suffixed path — contrast with --raw above.
        let default_cfg = fake_config_with(
            "repo-get",
            vec!["doc.txt".to_owned()],
            vec![("compress-type", OptionValue::StringId("gz".to_owned()))],
        );
        let mut decoded: Vec<u8> = Vec::new();
        get_to(&default_cfg, &storage, &mut decoded).expect("default get should succeed");
        assert_eq!(decoded, payload, "default get must apply the reverse transform");
    }

    #[test]
    fn repo_get_ignore_missing_writes_nothing_and_succeeds() {
        let (_repo, storage) = posix_repo();
        let cfg = fake_config_with(
            "repo-get",
            vec!["absent.txt".to_owned()],
            vec![("ignore-missing", OptionValue::Boolean(true))],
        );
        let mut buf: Vec<u8> = Vec::new();
        get_to(&cfg, &storage, &mut buf).expect("ignore-missing must not error on a missing file");
        assert!(buf.is_empty(), "missing file with --ignore-missing yields no output");
    }

    #[test]
    fn repo_get_missing_without_ignore_still_errors() {
        // Sanity contrast: without --ignore-missing a missing file is an error.
        let (_repo, storage) = posix_repo();
        let cfg = fake_config("repo-get", vec!["absent.txt".to_owned()]);
        let mut buf: Vec<u8> = Vec::new();
        let err = get_to(&cfg, &storage, &mut buf).expect_err("missing file must error");
        assert!(matches!(
            err,
            CommandError::Storage(pgbr_storage::StorageError::NotFound { .. })
        ));
    }

    // ----- repo-put --raw -----------------------------------------------

    #[test]
    fn repo_put_raw_stores_verbatim_no_transform_no_suffix() {
        let (repo, storage) = posix_repo();
        let payload = b"verbatim payload, must not be compressed or suffixed despite compress-type";

        // compress-type=gz is set, but --raw must override it: bytes land at
        // the bare path, uncompressed.
        let cfg = fake_config_with(
            "repo-put",
            vec!["blob.bin".to_owned()],
            vec![
                ("compress-type", OptionValue::StringId("gz".to_owned())),
                ("raw", OptionValue::Boolean(true)),
            ],
        );
        let mut input = Cursor::new(payload.to_vec());
        put_from(&cfg, &storage, &mut input).expect("raw put should succeed");

        let written = std::fs::read(repo.path().join("blob.bin")).expect("read back");
        assert_eq!(written, payload, "--raw must store verbatim bytes");
        assert!(!repo.path().join("blob.bin.gz").exists(), "--raw must not append a suffix");

        // --raw get of the same path recovers the exact bytes.
        let get_cfg = fake_config_with(
            "repo-get",
            vec!["blob.bin".to_owned()],
            vec![("raw", OptionValue::Boolean(true))],
        );
        let mut buf: Vec<u8> = Vec::new();
        get_to(&get_cfg, &storage, &mut buf).expect("raw get should succeed");
        assert_eq!(buf, payload, "raw put/get round trip must be byte-for-byte");
    }

    // ----- repo-rm: recurse gating --------------------------------------

    #[test]
    fn repo_rm_removes_a_file() {
        let (repo, storage) = posix_repo();
        seed(&storage, "gone.txt", b"x");
        let cfg = fake_config("repo-rm", vec!["gone.txt".to_owned()]);
        rm(&cfg, &storage).expect("rm file should succeed");
        assert!(!repo.path().join("gone.txt").exists());
    }

    #[test]
    fn repo_rm_missing_is_not_an_error() {
        let (_repo, storage) = posix_repo();
        let cfg = fake_config("repo-rm", vec!["nope.txt".to_owned()]);
        rm(&cfg, &storage).expect("rm of a missing entry must succeed");
    }

    #[test]
    fn repo_rm_empty_dir_without_recurse_succeeds() {
        let (repo, storage) = posix_repo();
        storage.create_path(Path::new("empty"), false).expect("mkdir empty");
        let cfg = fake_config("repo-rm", vec!["empty".to_owned()]);
        rm(&cfg, &storage).expect("rm of an empty dir without recurse must succeed");
        assert!(!repo.path().join("empty").exists());
    }

    #[test]
    fn repo_rm_nonempty_dir_without_recurse_errors() {
        let (_repo, storage) = posix_repo();
        storage.create_path(Path::new("full"), false).expect("mkdir full");
        seed(&storage, "full/file.txt", b"x");

        let cfg = fake_config("repo-rm", vec!["full".to_owned()]);
        let err = rm(&cfg, &storage).expect_err("non-empty dir without --recurse must error");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("recurse"), "message was {msg:?}"),
            other => panic!("expected Other(recurse), got {other:?}"),
        }
    }

    #[test]
    fn repo_rm_nonempty_dir_with_recurse_succeeds() {
        let (repo, storage) = posix_repo();
        storage.create_path(Path::new("full"), false).expect("mkdir full");
        seed(&storage, "full/file.txt", b"x");

        let cfg = fake_config_with(
            "repo-rm",
            vec!["full".to_owned()],
            vec![("recurse", OptionValue::Boolean(true))],
        );
        rm(&cfg, &storage).expect("rm of a non-empty dir with --recurse must succeed");
        assert!(!repo.path().join("full").exists());
    }
}
