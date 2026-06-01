//! Remote storage proxy over the pgBackRust local/remote protocol.
//!
//! Mirrors the C `src/storage/remote/` pair (`storage.c` on the caller side,
//! `protocol.c` on the worker side). A pgBackRust process that needs to reach a
//! repository or PG data directory living on another host does not access it
//! directly: it drives a helper worker (a child `pgbackrust` reached over SSH,
//! or a `--local` worker) over the JSON-line protocol from [`pgbr_protocol`].
//! Each [`Storage`] call becomes one protocol [`Request`]; the worker answers
//! with one [`Response`].
//!
//! This module ships both halves:
//!
//! - [`RemoteStorage`] — the caller side. Implements [`Storage`] by issuing a
//!   `storage-*` request per method through a [`ProtocolClient`] and decoding
//!   the response.
//! - [`StorageRequestHandler`] — the worker side. Implements
//!   [`pgbr_protocol::transport::RequestHandler`] by mapping each `storage-*`
//!   request onto a wrapped local [`Storage`] (e.g. [`crate::Posix`]).
//!
//! ## Transfer model: chunked streaming
//!
//! File payloads are transferred **chunked**, not whole-file — this supersedes
//! the earlier `storage-read` / `storage-write` whole-file transfer so large
//! files no longer buffer entirely in memory on either end. Each transfer is at
//! most [`CHUNK_SIZE`] (64 KiB) bytes of payload per protocol round-trip,
//! mirroring the C `protocolStorageRead` / `protocolStorageWrite` block
//! protocol in `src/storage/remote/`.
//!
//! - **Read** ([`RemoteStorage::open_read`]) returns a streaming reader that
//!   issues `storage-read-chunk` requests with `{ path, offset, len }`,
//!   receiving up to `len` bytes per request and advancing its offset. A short
//!   or empty chunk signals EOF. The worker keeps a single open reader per path
//!   and serves the requested range sequentially.
//! - **Write** ([`RemoteStorage::open_write`]) returns a streaming writer that
//!   sends `storage-write-open { path }` on first use, then one
//!   `storage-write-chunk { path, bytes }` per buffered `CHUNK_SIZE` block, and
//!   `storage-write-close { path }` on `close` (which finalises and fsyncs the
//!   file on the worker via the local `Storage`'s own `close`).
//!
//! The legacy whole-file `storage-read` / `storage-write` commands are gone;
//! all other `storage-*` commands (exists / info / list / remove / rename /
//! create-path / remove-path / create-symlink) are unchanged and still answer
//! in a single round-trip.
//!
//! ## Wire shapes
//!
//! Paths travel as UTF-8 lossy strings; file bytes travel base64-encoded
//! inside the JSON payload (JSON cannot carry raw binary). The request/response
//! payloads use the [`StorageInfoDto`] / [`StorageKindDto`] serde mirrors of
//! [`StorageInfo`] / [`StorageKind`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use pgbr_io::{IoError, IoRead, IoWrite};
use pgbr_protocol::transport::RequestHandler;
use pgbr_protocol::{ErrResponse, OkResponse, ProtocolClient, ProtocolError, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Storage, StorageError, StorageInfo, StorageKind};

/// Maximum payload bytes carried by a single chunked read/write round-trip.
///
/// 64 KiB matches [`pgbr_io::copy`]'s buffer and the C side's default block
/// size, balancing per-request overhead against memory use — a large file is
/// transferred as a stream of `CHUNK_SIZE`-bounded blocks rather than one giant
/// in-memory payload.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Protocol command names. Most [`Storage`] methods map to exactly one; file
/// transfer is split across the `*-chunk` / `*-open` / `*-close` commands.
pub mod command {
    /// `Storage::exists` — params: `[path]`; out: `bool`.
    pub const EXISTS: &str = "storage-exists";
    /// `Storage::info` — params: `[path]`; out: [`super::StorageInfoDto`].
    pub const INFO: &str = "storage-info";
    /// `Storage::list` — params: `[path]`; out: `[StorageInfoDto, ...]`.
    pub const LIST: &str = "storage-list";
    /// One chunk of a streaming read — params: `[path, offset, len]`;
    /// out: `{ "data": base64 }` carrying up to `len` bytes. A short or empty
    /// `data` field signals EOF. See [`super::CHUNK_SIZE`].
    pub const READ_CHUNK: &str = "storage-read-chunk";
    /// Begin a streaming write — params: `[path]`; out: `{}`. Truncates /
    /// creates the target via the worker's `Storage::open_write`.
    pub const WRITE_OPEN: &str = "storage-write-open";
    /// One chunk of a streaming write — params: `[path, base64]`; out: `{}`.
    pub const WRITE_CHUNK: &str = "storage-write-chunk";
    /// Finish a streaming write — params: `[path]`; out: `{}`. Closes (and
    /// fsyncs) the target via the worker's writer `close`.
    pub const WRITE_CLOSE: &str = "storage-write-close";
    /// `Storage::remove` — params: `[path, error_on_missing]`; out: `{}`.
    pub const REMOVE: &str = "storage-remove";
    /// `Storage::rename` — params: `[source, target]`; out: `{}`.
    pub const RENAME: &str = "storage-rename";
    /// `Storage::create_path` — params: `[path, recursive]`; out: `{}`.
    pub const CREATE_PATH: &str = "storage-create-path";
    /// `Storage::remove_path` — params: `[path, recursive, error_on_missing]`; out: `{}`.
    pub const REMOVE_PATH: &str = "storage-remove-path";
    /// `Storage::create_symlink` — params: `[link_path, target]`; out: `{}`.
    pub const CREATE_SYMLINK: &str = "storage-create-symlink";
}

// ---------------------------------------------------------------------------
// serde DTOs
// ---------------------------------------------------------------------------

/// Serde mirror of [`StorageKind`] for the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageKindDto {
    /// See [`StorageKind::File`].
    File,
    /// See [`StorageKind::Path`].
    Path,
    /// See [`StorageKind::Link`].
    Link,
    /// See [`StorageKind::Special`].
    Special,
}

impl From<StorageKind> for StorageKindDto {
    fn from(kind: StorageKind) -> Self {
        match kind {
            StorageKind::File => Self::File,
            StorageKind::Path => Self::Path,
            StorageKind::Link => Self::Link,
            StorageKind::Special => Self::Special,
        }
    }
}

impl From<StorageKindDto> for StorageKind {
    fn from(kind: StorageKindDto) -> Self {
        match kind {
            StorageKindDto::File => Self::File,
            StorageKindDto::Path => Self::Path,
            StorageKindDto::Link => Self::Link,
            StorageKindDto::Special => Self::Special,
        }
    }
}

/// Serde mirror of [`StorageInfo`] for the wire. `path` is carried as a
/// UTF-8(-lossy) string since JSON keys must be strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageInfoDto {
    /// Backend-resolved path of the entry.
    pub path: String,
    /// Entry kind.
    pub kind: StorageKindDto,
    /// Size in bytes (files only; `0` otherwise).
    pub size: u64,
    /// Last-modified time as Unix epoch seconds, if tracked.
    pub modified: Option<i64>,
}

impl From<&StorageInfo> for StorageInfoDto {
    fn from(info: &StorageInfo) -> Self {
        Self {
            path: info.path.to_string_lossy().into_owned(),
            kind: info.kind.into(),
            size: info.size,
            modified: info.modified,
        }
    }
}

impl From<StorageInfoDto> for StorageInfo {
    fn from(dto: StorageInfoDto) -> Self {
        Self {
            path: PathBuf::from(dto.path),
            kind: dto.kind.into(),
            size: dto.size,
            modified: dto.modified,
        }
    }
}

// ---------------------------------------------------------------------------
// Caller side: RemoteStorage
// ---------------------------------------------------------------------------

/// Shared, lockable handle to the protocol client. Shared between the
/// [`RemoteStorage`] itself and any [`RemoteWrite`] it hands out, so a buffering
/// writer can flush its payload on `close` without borrowing the storage (the
/// `Storage::open_write` signature returns a `'static` `Box<dyn IoWrite>`).
type SharedClient<R, W> = Arc<Mutex<ProtocolClient<R, W>>>;

/// Caller-side [`Storage`] that proxies every operation to a worker over the
/// protocol.
///
/// The [`ProtocolClient`] needs `&mut` to send a request, but the [`Storage`]
/// trait takes `&self` (so a single instance can be shared as
/// `Arc<dyn Storage>`); we bridge that with an `Arc<Mutex<…>>`. Calls are
/// therefore serialized — the protocol is a strict request/response pipe with a
/// single in-flight message, so that matches the wire semantics exactly.
pub struct RemoteStorage<R: IoRead, W: IoWrite> {
    client: SharedClient<R, W>,
}

impl<R: IoRead, W: IoWrite> RemoteStorage<R, W> {
    /// Build a remote storage over an existing reader / writer pair (child
    /// pipes, a socket, or an in-memory transport in tests).
    #[must_use]
    pub fn new(client: ProtocolClient<R, W>) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
        }
    }

    /// Send the `exit` handshake to the worker so its `serve` loop stops, then
    /// close the writer. Consumes the proxy.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the handshake cannot be written / flushed /
    /// closed, if any [`RemoteWrite`] still holds a clone of the shared client,
    /// or if the internal lock is poisoned.
    pub fn close(self) -> Result<(), StorageError> {
        let mutex = Arc::try_unwrap(self.client)
            .map_err(|_| backend(Path::new(""), "remote storage closed while a writer is still open"))?;
        let mut client = mutex
            .into_inner()
            .map_err(|_| backend(Path::new(""), "remote storage mutex poisoned"))?;
        client.close().map_err(|e| protocol_err(Path::new(""), &e))?;
        Ok(())
    }

    /// Issue one request and return its `out` payload (defaulting to `Null`
    /// when the worker replied with an empty `{}` body).
    fn execute(&self, path: &Path, cmd: &str, param: Vec<Value>) -> Result<Value, StorageError> {
        execute_shared(&self.client, path, cmd, param)
    }
}

/// Issue one request through a shared client handle. Factored out so both
/// [`RemoteStorage`] and [`RemoteWrite`] (which only holds the shared handle)
/// can drive the protocol.
fn execute_shared<R: IoRead, W: IoWrite>(
    client: &SharedClient<R, W>,
    path: &Path,
    cmd: &str,
    param: Vec<Value>,
) -> Result<Value, StorageError> {
    let request = Request {
        cmd: cmd.to_owned(),
        param,
    };
    let mut guard = client.lock().map_err(|_| backend(path, "remote storage mutex poisoned"))?;
    let ok: OkResponse = guard.execute(&request).map_err(|e| protocol_err(path, &e))?;
    drop(guard);
    Ok(ok.out.unwrap_or(Value::Null))
}

/// `path.to_string_lossy()` as an owned JSON string value.
fn path_param(path: &Path) -> Value {
    Value::String(path.to_string_lossy().into_owned())
}

impl<R: IoRead + Send + 'static, W: IoWrite + Send + 'static> Storage for RemoteStorage<R, W> {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        let out = self.execute(path, command::EXISTS, vec![path_param(path)])?;
        out.as_bool()
            .ok_or_else(|| backend(path, "storage-exists: expected a boolean response"))
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        let out = self.execute(path, command::INFO, vec![path_param(path)])?;
        let dto: StorageInfoDto =
            serde_json::from_value(out).map_err(|e| backend(path, &format!("storage-info: bad response: {e}")))?;
        Ok(dto.into())
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        let out = self.execute(path, command::LIST, vec![path_param(path)])?;
        let dtos: Vec<StorageInfoDto> =
            serde_json::from_value(out).map_err(|e| backend(path, &format!("storage-list: bad response: {e}")))?;
        Ok(dtos.into_iter().map(Into::into).collect())
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        // Chunked streaming: the reader pulls up to CHUNK_SIZE bytes per
        // `storage-read-chunk` request and stops on a short/empty chunk. The
        // worker validates existence lazily on the first chunk, so probe it
        // here with a single `info` so a missing file surfaces as an error from
        // `open_read` (matching the local backends' eager-open contract).
        self.info(path)?;
        Ok(Box::new(RemoteRead::new(Arc::clone(&self.client), path)))
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        // Chunked streaming: send `storage-write-open` now (so a create/truncate
        // failure surfaces from `open_write`), then stream `storage-write-chunk`
        // blocks, finishing with `storage-write-close` on `close`.
        let writer = RemoteWrite::open(Arc::clone(&self.client), path)?;
        Ok(Box::new(writer))
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        self.execute(path, command::REMOVE, vec![path_param(path), json!(error_on_missing)])?;
        Ok(())
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        self.execute(source, command::RENAME, vec![path_param(source), path_param(target)])?;
        Ok(())
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        self.execute(path, command::CREATE_PATH, vec![path_param(path), json!(recursive)])?;
        Ok(())
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        self.execute(
            path,
            command::REMOVE_PATH,
            vec![path_param(path), json!(recursive), json!(error_on_missing)],
        )?;
        Ok(())
    }

    fn create_symlink(&self, link_path: &Path, target: &Path) -> Result<(), StorageError> {
        self.execute(
            link_path,
            command::CREATE_SYMLINK,
            vec![path_param(link_path), path_param(target)],
        )?;
        Ok(())
    }
}

/// Streaming reader returned by [`RemoteStorage::open_read`].
///
/// Each `read` pulls up to [`CHUNK_SIZE`] bytes from the worker via a
/// `storage-read-chunk` request carrying the current `offset` and the
/// requested `len`, advancing the offset by however many bytes come back. A
/// short or empty chunk marks EOF; once EOF is seen the reader keeps returning
/// `0`. A small leftover buffer absorbs the case where the caller's `buf` is
/// smaller than what a chunk request returned (the reader always asks for at
/// most the smaller of `buf.len()` and `CHUNK_SIZE`, so in practice the chunk
/// fits, but the leftover keeps the contract robust).
///
/// Holds a clone of the shared client handle (not a borrow of the storage) so
/// it is `'static` and satisfies the `Box<dyn IoRead>` return type.
struct RemoteRead<R: IoRead, W: IoWrite> {
    client: SharedClient<R, W>,
    path: PathBuf,
    offset: u64,
    eof: bool,
}

impl<R: IoRead, W: IoWrite> RemoteRead<R, W> {
    fn new(client: SharedClient<R, W>, path: &Path) -> Self {
        Self {
            client,
            path: path.to_path_buf(),
            offset: 0,
            eof: false,
        }
    }
}

impl<R: IoRead, W: IoWrite> IoRead for RemoteRead<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        if self.eof || buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(CHUNK_SIZE);
        let out = execute_shared(
            &self.client,
            &self.path,
            command::READ_CHUNK,
            vec![path_param(&self.path), json!(self.offset), json!(len)],
        )
        .map_err(|e| IoError::Backend(format!("storage-read-chunk: {e}")))?;
        let encoded = out
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| IoError::Backend("storage-read-chunk: missing base64 'data' field".to_owned()))?;
        let bytes = BASE64
            .decode(encoded)
            .map_err(|e| IoError::Backend(format!("storage-read-chunk: bad base64: {e}")))?;
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        self.offset += n as u64;
        // A chunk shorter than what we asked for means the file is exhausted.
        // (`n < len` covers both the empty-chunk and short-tail cases; an exact
        // CHUNK_SIZE file then takes one more round-trip that returns empty.)
        if bytes.len() < len {
            self.eof = true;
        }
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

/// Streaming writer returned by [`RemoteStorage::open_write`].
///
/// Construction sends `storage-write-open` so the target is created/truncated
/// eagerly. Each `write` buffers bytes and flushes a `storage-write-chunk`
/// whenever the buffer reaches [`CHUNK_SIZE`]; `close` flushes any tail and
/// sends `storage-write-close`, which finalises (and fsyncs) the file on the
/// worker. Large payloads therefore never materialise whole on either end.
///
/// Holds a clone of the shared client handle (not a borrow of the storage) so
/// it is `'static` and satisfies the `Box<dyn IoWrite>` return type.
struct RemoteWrite<R: IoRead, W: IoWrite> {
    client: SharedClient<R, W>,
    path: PathBuf,
    buffer: Vec<u8>,
    closed: bool,
}

impl<R: IoRead, W: IoWrite> RemoteWrite<R, W> {
    /// Open a streaming write, sending `storage-write-open` up front.
    fn open(client: SharedClient<R, W>, path: &Path) -> Result<Self, StorageError> {
        execute_shared(&client, path, command::WRITE_OPEN, vec![path_param(path)])?;
        Ok(Self {
            client,
            path: path.to_path_buf(),
            buffer: Vec::with_capacity(CHUNK_SIZE),
            closed: false,
        })
    }

    /// Send the currently buffered bytes as one `storage-write-chunk` and clear
    /// the buffer. A no-op when the buffer is empty.
    fn send_buffer(&mut self) -> Result<(), IoError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let encoded = BASE64.encode(&self.buffer);
        execute_shared(
            &self.client,
            &self.path,
            command::WRITE_CHUNK,
            vec![path_param(&self.path), Value::String(encoded)],
        )
        .map_err(|e| IoError::Backend(format!("storage-write-chunk: {e}")))?;
        self.buffer.clear();
        Ok(())
    }
}

impl<R: IoRead, W: IoWrite> IoWrite for RemoteWrite<R, W> {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        self.buffer.extend_from_slice(buf);
        // Drain full CHUNK_SIZE blocks as they accumulate so neither this
        // writer nor the wire holds more than ~CHUNK_SIZE at a time.
        while self.buffer.len() >= CHUNK_SIZE {
            let rest = self.buffer.split_off(CHUNK_SIZE);
            let chunk = std::mem::replace(&mut self.buffer, rest);
            let encoded = BASE64.encode(&chunk);
            execute_shared(
                &self.client,
                &self.path,
                command::WRITE_CHUNK,
                vec![path_param(&self.path), Value::String(encoded)],
            )
            .map_err(|e| IoError::Backend(format!("storage-write-chunk: {e}")))?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        self.send_buffer()
    }

    fn close(&mut self) -> Result<(), IoError> {
        if self.closed {
            return Ok(());
        }
        // Flush the tail (anything below a full CHUNK_SIZE) before finalising.
        self.send_buffer()?;
        self.closed = true;
        execute_shared(&self.client, &self.path, command::WRITE_CLOSE, vec![path_param(&self.path)])
            .map_err(|e| IoError::Backend(format!("storage-write-close: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Worker side: StorageRequestHandler
// ---------------------------------------------------------------------------

/// An open streaming read on the worker: the local reader plus the byte offset
/// it is currently positioned at, so successive `storage-read-chunk` requests
/// (which the client issues with monotonically increasing offsets) are served
/// from the same handle without reopening per chunk.
struct OpenRead {
    reader: Box<dyn IoRead>,
    /// Absolute offset of the next byte the `reader` will yield.
    position: u64,
}

/// Worker-side [`RequestHandler`] that answers `storage-*` requests against a
/// wrapped local [`Storage`].
///
/// File transfer is chunked (see the module docs): the handler keeps one open
/// reader per in-flight `storage-read-chunk` path and one open writer per
/// in-flight `storage-write-*` path, finalising each on the matching `close`.
pub struct StorageRequestHandler<S: Storage> {
    storage: S,
    /// Open readers keyed by the path being streamed, with their current
    /// offset. Populated lazily on the first `storage-read-chunk` for a path.
    reads: HashMap<PathBuf, OpenRead>,
    /// Open writers keyed by the path being streamed. Populated by
    /// `storage-write-open` and finalised / removed by `storage-write-close`.
    writes: HashMap<PathBuf, Box<dyn IoWrite>>,
}

impl<S: Storage> StorageRequestHandler<S> {
    /// Wrap a local storage backend (e.g. [`crate::Posix`]) to serve requests.
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            reads: HashMap::new(),
            writes: HashMap::new(),
        }
    }

    /// Borrow the wrapped storage.
    pub const fn storage(&self) -> &S {
        &self.storage
    }

    /// Serve one `storage-read-chunk`: read up to `len` bytes starting at
    /// `offset` from the open reader for `path`, opening it on first use.
    fn read_chunk(&mut self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, StorageError> {
        // Open the reader lazily on the first chunk for this path, then take a
        // mutable borrow of the entry for the rest of the call.
        let open = match self.reads.entry(path.to_path_buf()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let reader = self.storage.open_read(path)?;
                e.insert(OpenRead { reader, position: 0 })
            }
        };

        // If the requested offset is behind the current position we cannot
        // rewind a forward-only reader, so reopen and start over; if it is
        // ahead, skip the gap. In normal sequential use offset == position and
        // neither branch fires.
        if offset < open.position {
            let reader = self.storage.open_read(path)?;
            *open = OpenRead { reader, position: 0 };
        }
        while open.position < offset {
            // Clamp the skip distance to CHUNK_SIZE (a `usize`) so the cap
            // always fits a `usize` even on a 32-bit target.
            let gap = usize::try_from((offset - open.position).min(CHUNK_SIZE as u64)).unwrap_or(CHUNK_SIZE);
            let mut skip = vec![0u8; gap];
            let n = open.reader.read(&mut skip)?;
            if n == 0 {
                // Reached EOF before reaching the requested offset.
                return Ok(Vec::new());
            }
            open.position += n as u64;
        }

        let mut buf = vec![0u8; len];
        let mut filled = 0;
        // Fill up to `len` bytes (one underlying read may return short).
        while filled < len {
            let n = open.reader.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        open.position += filled as u64;
        buf.truncate(filled);

        // Drop the handle once exhausted so a re-read of the same path opens a
        // fresh reader rather than serving a stale EOF.
        if filled < len {
            self.reads.remove(path);
        }
        Ok(buf)
    }

    /// Dispatch one request, returning a `Result` so the `?` operator can be
    /// used freely; [`RequestHandler::handle`] maps the error into an
    /// [`ErrResponse`].
    fn dispatch(&mut self, req: &Request) -> Result<OkResponse, StorageError> {
        match req.cmd.as_str() {
            command::EXISTS => {
                let path = param_path(req, 0)?;
                let exists = self.storage.exists(&path)?;
                Ok(ok(json!(exists)))
            }
            command::INFO => {
                let path = param_path(req, 0)?;
                let info = self.storage.info(&path)?;
                Ok(ok(
                    serde_json::to_value(StorageInfoDto::from(&info)).map_err(|e| json_err(&e))?
                ))
            }
            command::LIST => {
                let path = param_path(req, 0)?;
                let entries = self.storage.list(&path)?;
                let dtos: Vec<StorageInfoDto> = entries.iter().map(StorageInfoDto::from).collect();
                Ok(ok(serde_json::to_value(dtos).map_err(|e| json_err(&e))?))
            }
            command::READ_CHUNK => {
                let path = param_path(req, 0)?;
                let offset = param_u64(req, 1, &path)?;
                let len = param_usize(req, 2, &path)?;
                let bytes = self.read_chunk(&path, offset, len)?;
                Ok(ok(json!({ "data": BASE64.encode(&bytes) })))
            }
            command::WRITE_OPEN => {
                let path = param_path(req, 0)?;
                // Open (create/truncate) and stash the writer for this path.
                let writer = self.storage.open_write(&path)?;
                self.writes.insert(path, writer);
                Ok(ok_empty())
            }
            command::WRITE_CHUNK => {
                let path = param_path(req, 0)?;
                let bytes = param_bytes(req, 1, &path)?;
                let writer = self
                    .writes
                    .get_mut(&path)
                    .ok_or_else(|| backend(&path, "storage-write-chunk: no open write for path"))?;
                writer.write(&bytes)?;
                Ok(ok_empty())
            }
            command::WRITE_CLOSE => {
                let path = param_path(req, 0)?;
                let mut writer = self
                    .writes
                    .remove(&path)
                    .ok_or_else(|| backend(&path, "storage-write-close: no open write for path"))?;
                writer.close()?;
                Ok(ok_empty())
            }
            command::REMOVE => {
                let path = param_path(req, 0)?;
                let error_on_missing = param_bool(req, 1, &path)?;
                self.storage.remove(&path, error_on_missing)?;
                Ok(ok_empty())
            }
            command::RENAME => {
                let source = param_path(req, 0)?;
                let target = param_path(req, 1)?;
                self.storage.rename(&source, &target)?;
                Ok(ok_empty())
            }
            command::CREATE_PATH => {
                let path = param_path(req, 0)?;
                let recursive = param_bool(req, 1, &path)?;
                self.storage.create_path(&path, recursive)?;
                Ok(ok_empty())
            }
            command::REMOVE_PATH => {
                let path = param_path(req, 0)?;
                let recursive = param_bool(req, 1, &path)?;
                let error_on_missing = param_bool(req, 2, &path)?;
                self.storage.remove_path(&path, recursive, error_on_missing)?;
                Ok(ok_empty())
            }
            command::CREATE_SYMLINK => {
                let link_path = param_path(req, 0)?;
                let target = param_path(req, 1)?;
                self.storage.create_symlink(&link_path, &target)?;
                Ok(ok_empty())
            }
            other => Err(backend(Path::new(""), &format!("unknown storage command: {other}"))),
        }
    }
}

impl<S: Storage> RequestHandler for StorageRequestHandler<S> {
    fn handle(&mut self, req: &Request) -> Response {
        match self.dispatch(req) {
            Ok(out) => Response::Ok(out),
            Err(err) => Response::Err(ErrResponse {
                err: storage_error_code(&err),
                message: err.to_string(),
                stack: None,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const fn ok(out: Value) -> OkResponse {
    OkResponse { out: Some(out) }
}

const fn ok_empty() -> OkResponse {
    OkResponse { out: None }
}

/// Build a [`StorageError::Backend`] for `path` with `message`.
fn backend(path: &Path, message: &str) -> StorageError {
    StorageError::Backend {
        path: path.to_path_buf(),
        message: message.to_owned(),
    }
}

/// Map a [`ProtocolError`] from the client side into a [`StorageError`].
///
/// A worker file-missing error ([`ProtocolError::WorkerNotFound`]) is mapped to
/// the typed [`StorageError::NotFound`] so callers that match `NotFound` to treat
/// an absent file as "not present" (e.g. an optional `tablespace_map`) behave the
/// same against a remote repo as a local one. Everything else is a `Backend`.
fn protocol_err(path: &Path, err: &ProtocolError) -> StorageError {
    match err {
        ProtocolError::WorkerNotFound(_) => StorageError::NotFound {
            path: path.to_path_buf(),
        },
        _ => backend(path, &err.to_string()),
    }
}

fn json_err(err: &serde_json::Error) -> StorageError {
    backend(Path::new(""), &format!("json: {err}"))
}

/// Extract the `index`-th param as a path.
fn param_path(req: &Request, index: usize) -> Result<PathBuf, StorageError> {
    let s = req
        .param
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| backend(Path::new(""), &format!("{}: missing path param #{index}", req.cmd)))?;
    Ok(PathBuf::from(s))
}

/// Extract the `index`-th param as a boolean.
fn param_bool(req: &Request, index: usize, path: &Path) -> Result<bool, StorageError> {
    req.param
        .get(index)
        .and_then(Value::as_bool)
        .ok_or_else(|| backend(path, &format!("{}: missing bool param #{index}", req.cmd)))
}

/// Extract the `index`-th param as a `u64` (a byte offset on the wire).
fn param_u64(req: &Request, index: usize, path: &Path) -> Result<u64, StorageError> {
    req.param
        .get(index)
        .and_then(Value::as_u64)
        .ok_or_else(|| backend(path, &format!("{}: missing u64 param #{index}", req.cmd)))
}

/// Extract the `index`-th param as a `usize` (a byte length on the wire).
fn param_usize(req: &Request, index: usize, path: &Path) -> Result<usize, StorageError> {
    let value = param_u64(req, index, path)?;
    usize::try_from(value).map_err(|_| backend(path, &format!("{}: length param #{index} out of range", req.cmd)))
}

/// Extract the `index`-th param as base64-decoded bytes.
fn param_bytes(req: &Request, index: usize, path: &Path) -> Result<Vec<u8>, StorageError> {
    let encoded = req
        .param
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| backend(path, &format!("{}: missing base64 param #{index}", req.cmd)))?;
    BASE64
        .decode(encoded)
        .map_err(|e| backend(path, &format!("{}: bad base64: {e}", req.cmd)))
}

/// Map a [`StorageError`] to a numeric protocol error code. The exact value is
/// informational on the wire (the client surfaces the message); codes match
/// `crates/pgbr-build/inputs/error.yaml`.
const fn storage_error_code(err: &StorageError) -> u32 {
    match err {
        // 55 == file-missing in error.yaml.
        StorageError::NotFound { .. } => 55,
        // 39 == protocol: a generic catch-all for the remaining storage faults.
        _ => 39,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Posix;
    use pgbr_protocol::transport::{PipeRead, PipeWrite, serve};
    use std::thread::{self, JoinHandle};
    use tempfile::TempDir;

    /// The concrete `RemoteStorage` instantiation used by the tests: a proxy
    /// over the two `os_pipe` channels backing the in-thread transport.
    type TestRemote = RemoteStorage<PipeRead<os_pipe::PipeReader>, PipeWrite<os_pipe::PipeWriter>>;

    /// Spin up a `StorageRequestHandler<Posix>` serving on a thread, and return
    /// a `RemoteStorage` wired to it over two `os_pipe` channels, plus the
    /// server's join handle and the backing `TempDir` (kept alive by the
    /// caller).
    fn wire() -> (TestRemote, JoinHandle<()>, TempDir, Posix) {
        let dir = TempDir::new().unwrap();
        let posix = Posix::new(dir.path());
        let server_posix = Posix::new(dir.path());

        // client -> server requests; server -> client responses.
        let (req_r, req_w) = os_pipe::pipe().unwrap();
        let (resp_r, resp_w) = os_pipe::pipe().unwrap();

        let server = thread::spawn(move || {
            let mut reader = PipeRead::new(req_r);
            let mut writer = PipeWrite::new(resp_w);
            let mut handler = StorageRequestHandler::new(server_posix);
            serve(&mut reader, &mut writer, &mut handler).unwrap();
        });

        let client = ProtocolClient::new(PipeRead::new(resp_r), PipeWrite::new(req_w));
        let remote = RemoteStorage::new(client);
        (remote, server, dir, posix)
    }

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
    fn put_get_round_trip_matches_backing_posix() {
        let (remote, server, _dir, posix) = wire();
        let path = Path::new("file.txt");
        let payload = b"hello remote storage\n";

        // Write through the remote proxy.
        write_all(&remote, path, payload);

        // The bytes landed in the backing Posix store...
        assert_eq!(read_all(&posix, path), payload);
        // ...and reading back through the proxy yields the same bytes.
        assert_eq!(read_all(&remote, path), payload);

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn exists_info_list() {
        let (remote, server, _dir, _posix) = wire();

        assert!(!remote.exists(Path::new("nope")).unwrap());

        write_all(&remote, Path::new("a.txt"), b"abc");
        write_all(&remote, Path::new("b.txt"), b"defgh");

        assert!(remote.exists(Path::new("a.txt")).unwrap());

        let info = remote.info(Path::new("b.txt")).unwrap();
        assert_eq!(info.kind, StorageKind::File);
        assert_eq!(info.size, 5);

        let entries = remote.list(Path::new(".")).unwrap();
        let names: Vec<String> = entries
            .iter()
            .filter(|e| e.kind == StorageKind::File)
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.txt".to_owned()));
        assert!(names.contains(&"b.txt".to_owned()));

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn remove_deletes_file() {
        let (remote, server, _dir, posix) = wire();
        let path = Path::new("doomed.txt");
        write_all(&remote, path, b"x");
        assert!(posix.exists(path).unwrap());

        remote.remove(path, true).unwrap();
        assert!(!posix.exists(path).unwrap());

        // Removing a missing file with error_on_missing=false is a no-op.
        remote.remove(path, false).unwrap();

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn create_path_then_list() {
        let (remote, server, _dir, posix) = wire();
        remote.create_path(Path::new("sub/dir"), true).unwrap();
        let info = posix.info(Path::new("sub/dir")).unwrap();
        assert_eq!(info.kind, StorageKind::Path);

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn not_found_maps_to_not_found() {
        let (remote, server, _dir, _posix) = wire();
        // open_read on a missing file: the worker's Posix returns NotFound, which
        // serializes to a file-missing (code 55) error response; the client maps
        // it back to the typed StorageError::NotFound (NOT a generic Backend), so
        // callers can treat an absent file as "not present" uniformly across local
        // and remote repos. `Box<dyn IoRead>` is not Debug, so match by hand.
        match remote.open_read(Path::new("missing.txt")) {
            Err(StorageError::NotFound { path }) => assert_eq!(path, Path::new("missing.txt")),
            Err(other) => panic!("expected NotFound, got {other:?}"),
            Ok(_) => panic!("expected open_read on a missing file to error"),
        }

        // info on a missing path likewise maps to the typed NotFound.
        match remote.info(Path::new("missing.txt")) {
            Err(StorageError::NotFound { .. }) => {}
            other => panic!("expected NotFound from info on a missing path, got {other:?}"),
        }

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn unknown_command_errs() {
        // Drive the handler synchronously: an unrecognized command yields an
        // error response rather than panicking.
        let dir = TempDir::new().unwrap();
        let mut handler = StorageRequestHandler::new(Posix::new(dir.path()));
        let resp = handler.handle(&Request {
            cmd: "storage-does-not-exist".to_owned(),
            param: vec![],
        });
        match resp {
            Response::Err(err) => assert!(err.message.contains("unknown storage command")),
            Response::Ok(_) => panic!("expected an error response for an unknown command"),
        }
    }

    #[test]
    fn empty_file_round_trip() {
        let (remote, server, _dir, posix) = wire();
        let path = Path::new("empty.bin");
        write_all(&remote, path, b"");
        assert!(posix.exists(path).unwrap());
        assert_eq!(read_all(&remote, path), b"");

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn binary_payload_round_trip() {
        // Non-UTF8 bytes must survive the base64 hop intact.
        let (remote, server, _dir, _posix) = wire();
        let path = Path::new("blob.bin");
        let payload: Vec<u8> = (0u8..=255).collect();
        write_all(&remote, path, &payload);
        assert_eq!(read_all(&remote, path), payload);

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn kind_dto_round_trips_all_variants() {
        for kind in [StorageKind::File, StorageKind::Path, StorageKind::Link, StorageKind::Special] {
            let dto: StorageKindDto = kind.into();
            let back: StorageKind = dto.into();
            assert_eq!(kind, back);
        }
    }

    /// A deterministic-but-non-trivial byte pattern of `len` bytes, so a
    /// transfer that drops, duplicates, or misorders a chunk fails loudly.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn remote_chunked_read_large_file() {
        // A file several CHUNK_SIZE blocks long round-trips byte-for-byte
        // through the chunked `open_read` path.
        let (remote, server, _dir, posix) = wire();
        let path = Path::new("big-read.bin");
        let payload = pattern(CHUNK_SIZE * 3 + 1234);

        // Seed via the backing Posix directly so we exercise the read path alone.
        write_all(&posix, path, &payload);

        let got = read_all(&remote, path);
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn remote_chunked_write_large_file() {
        // Writing a multi-chunk payload through `open_write` lands byte-for-byte
        // in the backing Posix store.
        let (remote, server, _dir, posix) = wire();
        let path = Path::new("big-write.bin");
        let payload = pattern(CHUNK_SIZE * 4 + 77);

        // Drive several writes whose sizes straddle chunk boundaries so the
        // CHUNK_SIZE-draining logic in `write` is exercised (partial buffer,
        // a write that overflows one block, and a write spanning many blocks).
        {
            let mut w = remote.open_write(path).unwrap();
            let mut off = 0;
            // Write sizes that straddle chunk boundaries: a sub-chunk write, a
            // write that overflows one block, then a write spanning several.
            for step in [100usize, CHUNK_SIZE - 50, CHUNK_SIZE * 2 + 10] {
                let step = step.min(payload.len() - off);
                w.write(&payload[off..off + step]).unwrap();
                off += step;
            }
            // Flush the remainder so the whole payload is written, then finalise.
            if off < payload.len() {
                w.write(&payload[off..]).unwrap();
            }
            w.close().unwrap();
        }

        // The bytes landed verbatim in the backing store...
        assert_eq!(read_all(&posix, path), payload);
        // ...and reading back through the proxy yields the same bytes.
        assert_eq!(read_all(&remote, path), payload);

        remote.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn remote_chunked_read_exact_chunk_boundary() {
        // A file whose size is an exact multiple of CHUNK_SIZE must terminate
        // correctly: no off-by-one truncation and no infinite loop when the
        // final full chunk is followed by an empty one.
        let (remote, server, _dir, posix) = wire();
        let path = Path::new("boundary.bin");
        let payload = pattern(CHUNK_SIZE * 2);
        write_all(&posix, path, &payload);

        // Read in CHUNK_SIZE-sized buffers so each `read` maps to exactly one
        // chunk request, landing the EOF detection right on the boundary.
        let mut reader = remote.open_read(path).unwrap();
        let mut got = Vec::with_capacity(payload.len());
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut reads = 0;
        loop {
            let n = reader.read(&mut buf).unwrap();
            reads += 1;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            // Guard against a runaway loop independent of the EOF assertion.
            assert!(reads <= 8, "read did not terminate at the chunk boundary");
        }
        assert!(reader.eof());
        assert_eq!(got, payload);

        // Drop the streaming reader (it holds a clone of the shared client) so
        // `close` can reclaim sole ownership of the protocol client.
        drop(reader);
        remote.close().unwrap();
        server.join().unwrap();
    }
}
