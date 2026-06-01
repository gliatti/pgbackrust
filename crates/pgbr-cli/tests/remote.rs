//! Inter-host storage integration tests for the `pgbackrust` binary.
//!
//! These prove the spawn -> worker -> `RemoteStorage` loop assembled in
//! [`pgbr_cli::remote_storage`]: the parent process spawns a `pgbackrust`
//! worker, which serves the storage protocol on its stdio (via
//! `pgbr_command::worker::run_worker_stdio`, routed from `run`), and the parent
//! proxies `Storage` calls to it through `RemoteStorage`.
//!
//! - [`remote_storage_over_spawned_binary_worker`] drives the *real* shipped
//!   binary as a local worker (`pgbackrust backup:remote --repo1-path=<dir>`)
//!   over real OS pipes — no SSH, no `PostgreSQL` — and round-trips
//!   put / get / exists, asserting the bytes land on disk under the worker's
//!   root. This is the end-to-end proof the inter-host wiring works with a real
//!   subprocess.
//! - [`remote_storage_over_ssh`] is the SSH variant, `#[ignore]`d and gated on
//!   `PGBR_IT_SSH_HOST` since it needs a reachable host with `pgbackrust`
//!   installed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use pgbr_cli::remote_storage::RemoteProcessStorage;
use pgbr_io::{IoRead, IoWrite};
use pgbr_storage::Storage;
use tempfile::TempDir;

/// Read a whole file from a `Storage` into a `Vec<u8>`.
fn read_all(storage: &dyn Storage, path: &Path) -> Vec<u8> {
    let mut r = storage.open_read(path).unwrap();
    r.read_all().unwrap()
}

/// Write a whole file to a `Storage`.
fn write_all(storage: &dyn Storage, path: &Path, bytes: &[u8]) {
    let mut w = storage.open_write(path).unwrap();
    w.write(bytes).unwrap();
    w.close().unwrap();
}

#[test]
fn remote_storage_over_spawned_binary_worker() {
    // The worker serves a Posix store rooted at this tempdir (its `repo1-path`).
    let dir = TempDir::new().unwrap();
    let repo_arg = format!("--repo1-path={}", dir.path().display());

    // Spawn the *real* shipped binary as a local worker. `backup:remote` selects
    // the `Remote` command role, which `run` routes to
    // `pgbr_command::worker::run_worker_stdio` before any command dispatch, so
    // the child serves the storage protocol on its stdin/stdout.
    let exe = env!("CARGO_BIN_EXE_pgbackrust");
    let storage = RemoteProcessStorage::spawn_local(exe, &["backup:remote".to_owned(), repo_arg])
        .expect("spawning the pgbackrust binary as a local worker should succeed");

    let path = Path::new("subdir/file.txt");
    let payload = b"inter-host storage over a real spawned worker\n";

    // create-path -> put -> get -> exists through the proxy. The worker's Posix
    // does not auto-create parent dirs, so create-path is part of the round-trip
    // and exercises another protocol command across the process boundary.
    storage.create_path(Path::new("subdir"), true).unwrap();
    write_all(&storage, path, payload);
    assert_eq!(read_all(&storage, path), payload);
    assert!(storage.exists(path).unwrap());
    assert!(!storage.exists(Path::new("nope")).unwrap());

    // The bytes really landed on disk under the worker's root, proving the
    // request crossed the process boundary into the spawned binary.
    let on_disk = std::fs::read(dir.path().join("subdir/file.txt")).unwrap();
    assert_eq!(on_disk, payload);

    // A multi-chunk payload exercises the streaming read/write path across the
    // real subprocess pipes, not just a single small frame.
    let big_path = Path::new("big.bin");
    let big: Vec<u8> = (0..200_000u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
    write_all(&storage, big_path, &big);
    assert_eq!(read_all(&storage, big_path), big);

    // Dropping the proxy closes the protocol pipes and reaps the worker.
    drop(storage);
}

#[test]
#[ignore = "requires an SSH-reachable host with pgbackrust installed; set PGBR_IT_SSH_HOST"]
fn remote_storage_over_ssh() {
    // Gated on a real host: `PGBR_IT_SSH_HOST=user@host` (or just `host`) with
    // `pgbackrust` on its PATH and a writable repo path. Optional
    // `PGBR_IT_SSH_REPO_PATH` overrides the remote repo root.
    let host = std::env::var("PGBR_IT_SSH_HOST").expect("PGBR_IT_SSH_HOST must be set for this test");
    let repo_path = std::env::var("PGBR_IT_SSH_REPO_PATH").unwrap_or_else(|_| "/tmp/pgbr-it-repo".to_owned());

    // Allow a `user@host` form in the env var.
    let (user, host) = host.split_once('@').map_or((None, host.as_str()), |(u, h)| (Some(u), h));

    let remote_args = vec!["backup:remote".to_owned(), format!("--repo1-path={repo_path}")];
    let storage = RemoteProcessStorage::spawn_ssh(host, None, user, "pgbackrust", &remote_args)
        .expect("spawning the ssh worker should succeed");

    let path = Path::new("ssh-roundtrip.txt");
    let payload = b"remote storage over ssh\n";
    write_all(&storage, path, payload);
    assert_eq!(read_all(&storage, path), payload);
    assert!(storage.exists(path).unwrap());

    storage.remove(path, true).unwrap();
    drop(storage);
}
