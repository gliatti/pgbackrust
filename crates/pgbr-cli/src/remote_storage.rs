//! `Storage` over a spawned `pgbackrest` worker, for inter-host operation.
//!
//! Mirrors the caller side of the C `src/storage/remote/storage.c` +
//! `src/protocol/helper.c` pair: when `repo-host` / `pg-host` is set, the main
//! process does not touch the remote resource directly. It spawns a subordinate
//! `pgbackrest` worker (over SSH for a remote host, or the binary itself for a
//! local worker) and proxies every [`Storage`] call to it over the JSON-line
//! protocol from [`pgbr_protocol`].
//!
//! The three building blocks already exist:
//!
//! - [`pgbr_protocol::ProcessClient`] spawns the child and owns the [`Child`]
//!   plus a [`ProtocolClient`] over its piped stdin/stdout.
//! - [`pgbr_storage::remote::RemoteStorage`] implements [`Storage`] by issuing
//!   one protocol request per method through a [`ProtocolClient`].
//! - the spawned `pgbackrest` runs [`pgbr_command::worker::run_worker_stdio`]
//!   (wired in [`crate::run_with_context`]) to answer the protocol on its
//!   stdio.
//!
//! The API-fit problem this module solves: [`RemoteStorage::new`] wants a
//! [`ProtocolClient`], but [`ProcessClient`] owns *both* the child and the
//! client — and the child must outlive the proxy or its stdin/stdout pipes are
//! torn down, hanging the worker. [`RemoteProcessStorage`] holds the [`Child`]
//! alongside the [`RemoteStorage`] built over the same pipes, delegating the
//! [`Storage`] trait to the inner proxy and reaping the worker on [`Drop`].

use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout};

use pgbr_io::{IoRead, IoWrite};
use pgbr_protocol::transport::{PipeRead, PipeWrite};
use pgbr_protocol::{ProcessClient, ProtocolError};
use pgbr_storage::remote::RemoteStorage;
use pgbr_storage::{Storage, StorageError, StorageInfo};

/// Concrete [`RemoteStorage`] instantiation over a spawned child's pipes: it
/// reads the worker's stdout and writes the worker's stdin.
type ChildRemoteStorage = RemoteStorage<PipeRead<ChildStdout>, PipeWrite<ChildStdin>>;

/// A [`Storage`] backed by a spawned `pgbackrest` worker.
///
/// Owns the worker [`Child`] so its stdin/stdout pipes stay live for as long as
/// the proxy is used, and the [`RemoteStorage`] proxy built over those pipes.
/// Every [`Storage`] method is delegated to the inner proxy; on [`Drop`] the
/// worker is reaped (best-effort kill + wait) after the proxy — and with it the
/// protocol writer — has been dropped, so the worker reads EOF and exits.
pub struct RemoteProcessStorage {
    /// The spawned worker. `Option` so [`Drop`] can take ownership to wait on
    /// it; always `Some` for the lifetime of every public method.
    child: Option<Child>,
    /// The protocol proxy over the child's pipes. Dropped before `child` is
    /// reaped (field declaration order = drop order) so the worker sees EOF.
    inner: ChildRemoteStorage,
}

impl RemoteProcessStorage {
    /// Build a remote-process storage from an already-spawned
    /// [`ProcessClient`]. Splits the client into its [`Child`] and
    /// [`ProtocolClient`], wraps the latter in a [`RemoteStorage`], and retains
    /// the child so the pipes outlive the proxy.
    #[must_use]
    pub fn new(process: ProcessClient) -> Self {
        let (child, client) = process.into_parts();
        Self {
            child: Some(child),
            inner: RemoteStorage::new(client),
        }
    }

    /// Spawn a remote worker over SSH and wrap it.
    ///
    /// `ssh [opts] [-p port] [user@]host <remote_program> <remote_args...>` —
    /// the remote `pgbackrest` is invoked in a worker role (see
    /// [`pgbr_command::worker::is_worker`]) so it serves the storage protocol on
    /// its stdio.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the `ssh` process cannot be spawned.
    pub fn spawn_ssh(
        host: &str,
        ssh_port: Option<u16>,
        ssh_user: Option<&str>,
        remote_program: &str,
        remote_args: &[String],
    ) -> Result<Self, ProtocolError> {
        let process = ProcessClient::spawn_ssh(host, ssh_port, ssh_user, remote_program, remote_args)?;
        Ok(Self::new(process))
    }

    /// Spawn a worker on the local host (`<program> <args...>`) and wrap it.
    ///
    /// Used both for same-host parallel workers and — in tests — to drive the
    /// real `pgbackrest` binary as a worker without an SSH hop.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Spawn`] if the process cannot be spawned.
    pub fn spawn_local(program: &str, args: &[String]) -> Result<Self, ProtocolError> {
        let process = ProcessClient::spawn_local(program, args)?;
        Ok(Self::new(process))
    }
}

impl Drop for RemoteProcessStorage {
    fn drop(&mut self) {
        // `inner` (and its `PipeWrite<ChildStdin>`) is dropped after this method
        // returns, per struct field order — but to guarantee the worker reads
        // EOF *before* we wait (so `wait` does not block), reap defensively:
        // kill the child if it is still running, then wait to avoid a zombie.
        // A worker that already exited cleanly on EOF makes `kill` a harmless
        // no-op. Errors are ignored: Drop cannot surface them and a failed
        // reap of an already-dead child is not actionable.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Storage for RemoteProcessStorage {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        self.inner.exists(path)
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        self.inner.info(path)
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        self.inner.list(path)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        self.inner.open_read(path)
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        self.inner.open_write(path)
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner.remove(path, error_on_missing)
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        self.inner.rename(source, target)
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        self.inner.create_path(path, recursive)
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        self.inner.remove_path(path, recursive, error_on_missing)
    }

    fn create_symlink(&self, link_path: &Path, target: &Path) -> Result<(), StorageError> {
        self.inner.create_symlink(link_path, target)
    }
}
