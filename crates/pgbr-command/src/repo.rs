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

use pgbr_config::LoadedConfig;
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;
use crate::pipeline::RepoTransform;

/// Compute the listing for `repo-ls`. Pure function — no I/O beyond the
/// supplied storage backend — so tests can assert against it without
/// capturing stdout.
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if the underlying `list` call fails.
pub fn ls_inner(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<Vec<PathBuf>, CommandError> {
    let target = config.params.first().map_or_else(|| PathBuf::from("."), PathBuf::from);

    let entries = repo_storage.list(&target)?;
    Ok(entries.into_iter().map(|info| info.path).collect())
}

/// `repo-ls` — list entries beneath the first positional argument (or the
/// repo root when none is given).
///
/// # Errors
///
/// Returns whatever [`ls_inner`] surfaces.
// CLI command writes to stdout by design.
#[allow(clippy::print_stdout)]
pub fn ls(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let entries = ls_inner(config, repo_storage)?;
    for entry in entries {
        println!("{}", entry.display());
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
/// # Errors
///
/// - [`CommandError::MissingOption`] if no positional path was supplied.
/// - [`CommandError::Storage`] if the open / read fails (a missing path
///   surfaces as [`pgbr_storage::StorageError::NotFound`]).
/// - [`CommandError::Io`] if a filter in the reverse chain fails (e.g. wrong
///   cipher password, corrupt compressed stream).
/// - [`CommandError::Other`] if writing to `out` fails.
pub fn get_to<W: Write>(config: &LoadedConfig, repo_storage: &dyn Storage, out: &mut W) -> Result<(), CommandError> {
    let path = config.params.first().ok_or_else(|| CommandError::MissingOption {
        option: "<path>".to_owned(),
    })?;
    let transform = RepoTransform::from_options(config);

    let raw = read_repo_bytes(repo_storage, path, &transform)?;

    let plaintext = if transform == RepoTransform::identity() {
        raw
    } else {
        transform.apply_reverse(&raw)?
    };

    out.write_all(&plaintext)
        .map_err(|err| CommandError::Other(format!("write output: {err}")))?;
    Ok(())
}

/// Read the repo-side bytes for `repo-get`: prefer the exact `<path>`; when the
/// transform is non-identity and the exact path is absent, fall back to the
/// suffixed `<path><suffix>`. The identity transform never falls back (its
/// suffix is empty anyway) so its `NotFound` surfaces unchanged.
fn read_repo_bytes(repo_storage: &dyn Storage, path: &str, transform: &RepoTransform) -> Result<Vec<u8>, CommandError> {
    match repo_storage.open_read(Path::new(path)) {
        Ok(mut reader) => Ok(reader.read_all()?),
        Err(StorageError::NotFound { .. }) if !transform.repo_suffix().is_empty() => {
            let suffixed = format!("{path}{}", transform.repo_suffix());
            let mut reader = repo_storage.open_read(Path::new(&suffixed))?;
            Ok(reader.read_all()?)
        }
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
    let transform = RepoTransform::from_options(config);

    // Slurp stdin: the compress / encrypt filters buffer their whole input
    // before emitting, so there is nothing to gain from streaming here.
    let mut plaintext = Vec::new();
    input
        .read_to_end(&mut plaintext)
        .map_err(|err| CommandError::Other(format!("read input: {err}")))?;

    let repo_bytes = if transform == RepoTransform::identity() {
        plaintext
    } else {
        transform.apply_forward(&plaintext)?
    };

    let target = format!("{path}{}", transform.repo_suffix());
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
/// Directories are removed recursively. A missing entry is not an error
/// (matches the C side's `error_on_missing = false`).
///
/// # Errors
///
/// Returns [`CommandError::Storage`] if a removal fails for a reason other
/// than "missing".
pub fn rm(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    for raw in &config.params {
        let path = Path::new(raw);
        remove_any(repo_storage, path)?;
    }
    Ok(())
}

fn remove_any(storage: &dyn Storage, path: &Path) -> Result<(), CommandError> {
    // Probe to decide whether to call remove (file) or remove_path
    // (directory). exists() is cheaper than info() on most backends.
    match storage.info(path) {
        Ok(info) if matches!(info.kind, pgbr_storage::StorageKind::Path) => match storage.remove_path(path, true, false) {
            Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
            Err(err) => Err(err.into()),
        },
        Ok(_) => match storage.remove(path, false) {
            Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
            Err(err) => Err(err.into()),
        },
        Err(StorageError::NotFound { .. }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_storage::Posix;
    use tempfile::TempDir;

    use super::{CommandError, get_to, put_from};
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
}
