//! Archive commands: `archive-get`, `archive-push`.
//!
//! C reference: `src/command/archive/get/get.c` and
//! `src/command/archive/push/push.c`.
//!
//! This slice is the raw byte path: a WAL segment is copied verbatim
//! between the `PostgreSQL` data directory and the repository through the
//! [`Storage`] trait. Compression (`--compress-type`) and encryption
//! (`--cipher-pass`) filters are **not** applied here — the filter-chain
//! wiring lands in a follow-up. The archive-id subdirectory scheme the C
//! version derives from the PG version + system id is likewise simplified
//! to a flat `archive/<stanza>/<segment>` layout for now.

use std::path::{Path, PathBuf};

use pgbr_config::LoadedConfig;
use pgbr_storage::Storage;

use crate::CommandError;

/// Build the repository-relative path for a WAL `segment` under `stanza`.
///
/// Flat layout `archive/<stanza>/<segment>` — the version + system-id
/// archive-id directory used by the C implementation is deferred.
fn repo_segment_path(stanza: &str, segment: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/{segment}"))
}

/// Copy every byte from `src` (at `src_path`) into `dst` (at `dst_path`),
/// creating the destination's parent directory first.
///
/// `open_write` does not auto-create parents, so the parent path is
/// materialised with `create_path` before the writer is opened. The writer
/// is flushed and closed so the file is durable before the function
/// returns.
fn copy_segment(src: &dyn Storage, src_path: &Path, dst: &dyn Storage, dst_path: &Path) -> Result<(), CommandError> {
    let mut reader = src.open_read(src_path)?;
    let bytes = reader.read_all()?;

    if let Some(parent) = dst_path.parent() {
        dst.create_path(parent, true)?;
    }

    let mut writer = dst.open_write(dst_path)?;
    writer.write(&bytes)?;
    writer.flush()?;
    writer.close()?;
    Ok(())
}

/// `archive-push` — copy a completed WAL segment from the PG data directory
/// into the repository at `archive/<stanza>/<segment>`.
///
/// `config.params[0]` is the WAL source path (relative to the PG data dir,
/// resolved against `pg_storage`); the segment basename is taken from it.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] with `"stanza"` if `config.stanza` is
///   `None`, or `"<wal-source>"` if no positional source path was supplied.
/// - [`CommandError::Other`] if the source path has no file-name component.
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

    let dest = repo_segment_path(stanza, segment);
    copy_segment(pg_storage, Path::new(wal_source), repo_storage, &dest)
}

/// `archive-get` — copy a WAL segment from the repository
/// (`archive/<stanza>/<segment>`) back into the PG data directory.
///
/// `config.params[0]` is the segment name; `config.params[1]` is the
/// destination path (relative to the PG data dir, resolved against
/// `pg_storage`).
///
/// # Errors
///
/// - [`CommandError::MissingOption`] with `"stanza"` if `config.stanza` is
///   `None`, `"<wal-segment>"` if no segment name was supplied, or
///   `"<destination>"` if no destination path was supplied.
/// - [`CommandError::Storage`] / [`CommandError::Io`] if the read from the
///   repository (a missing segment surfaces as
///   [`pgbr_storage::StorageError::NotFound`]) or the write into PG fails.
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

    let source = repo_segment_path(stanza, segment);
    copy_segment(repo_storage, &source, pg_storage, Path::new(dest))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};
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
}
