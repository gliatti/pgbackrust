//! SFTP storage backend over an SSH session (libssh2 via the [`ssh2`] crate).
//!
//! Mirrors the C `storage/sftp` driver (`src/storage/sftp/`). SFTP runs over SSH:
//! [`Sftp::connect`] opens a [`std::net::TcpStream`], hands it to an
//! [`ssh2::Session`], performs the SSH handshake, authenticates (password or
//! private key), and opens the SFTP subsystem channel. The resulting [`Sftp`]
//! then implements the [`Storage`] trait by mapping each method onto the
//! corresponding `ssh2::Sftp` call (`stat` / `readdir` / `open` / `create` /
//! `unlink` / `rename` / `mkdir` / `rmdir`), so the on-the-wire semantics match
//! the local [`crate::Posix`] backend as closely as SFTP allows.
//!
//! ## Path resolution
//!
//! Like `Posix`, all paths are interpreted relative to a configured `base_path`
//! (the remote root): a relative path is joined onto `base_path`, an absolute
//! path is taken verbatim. Joining is done with forward slashes regardless of
//! the host OS, because SFTP servers are POSIX-pathed even when the client runs
//! on Windows — see [`resolve_remote`].
//!
//! ## Error mapping
//!
//! SFTP-level failures carry a numeric status code (the `LIBSSH2_FX_*` family).
//! [`errcode_to_storage`] turns the connection-relevant codes into typed
//! [`StorageError`] variants — `NO_SUCH_FILE` / `NO_SUCH_PATH` -> `NotFound`,
//! `PERMISSION_DENIED` -> `PermissionDenied`, `FILE_ALREADY_EXISTS` ->
//! `AlreadyExists`, everything else -> `Backend`. It is a pure function so it is
//! unit-tested without a live server.
//!
//! ## Testing
//!
//! A real SSH/SFTP server is required to exercise transfers, so the connect +
//! put/get/list/remove round trip is `#[ignore]`d behind `PGBR_SFTP_*` env vars.
//! The connection-free logic — path resolution, error-code mapping, and
//! [`SftpConfig`] construction — is unit-tested, and the full [`Storage`] impl
//! is type-checked and clippy-clean.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_NO_PAD;
use pgbr_io::{IoError, IoRead, IoWrite};
use ssh2::{
    CheckResult, ErrorCode, FileStat, FileType, HashType, KnownHostFileKind, KnownHostKeyFormat, OpenFlags, OpenType, RenameFlags,
    Session,
};

use crate::{Storage, StorageError, StorageInfo, StorageKind};

// SFTP status codes from the SSH File Transfer Protocol (the `LIBSSH2_FX_*`
// family). The `ssh2` crate surfaces these as the inner `i32` of
// [`ErrorCode::SFTP`]; the constants below mirror `libssh2_sftp.h` so the
// mapping is legible and unit-testable without linking libssh2.

/// `LIBSSH2_FX_NO_SUCH_FILE` — the named file does not exist.
const FX_NO_SUCH_FILE: i32 = 2;
/// `LIBSSH2_FX_PERMISSION_DENIED` — caller lacks permission for the operation.
const FX_PERMISSION_DENIED: i32 = 3;
/// `LIBSSH2_FX_NO_SUCH_PATH` — a path component does not exist.
const FX_NO_SUCH_PATH: i32 = 8;
/// `LIBSSH2_FX_FILE_ALREADY_EXISTS` — exclusive create hit an existing entry.
const FX_FILE_ALREADY_EXISTS: i32 = 11;

/// Default SSH port.
pub const DEFAULT_PORT: u16 = 22;

/// How to authenticate the SSH session.
#[derive(Debug, Clone)]
pub enum SftpAuth {
    /// Password authentication for `user`.
    Password(String),
    /// Public-key authentication from a private-key file.
    KeyFile {
        /// Path to the private key (PEM/OpenSSH format).
        private_key: PathBuf,
        /// Optional explicit public-key file (`repo-sftp-public-key-file`). Some
        /// libssh2 key formats need the matching `.pub`; `None` lets ssh2 derive
        /// it from the private key.
        public_key: Option<PathBuf>,
        /// Optional passphrase protecting the private key.
        passphrase: Option<String>,
    },
}

/// The digest used to render / compare a host-key fingerprint
/// (`repo-sftp-host-key-hash-type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyHashType {
    /// MD5 (legacy `ssh-keygen -l -E md5` colon-hex form).
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-256 (the modern default).
    #[default]
    Sha256,
}

impl HostKeyHashType {
    /// Parse the `repo-sftp-host-key-hash-type` option value.
    ///
    /// # Errors
    ///
    /// Returns the unrecognised value as an error string for the caller to wrap.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            other => Err(format!(
                "unrecognised repo-sftp-host-key-hash-type `{other}` (expected md5, sha1, or sha256)"
            )),
        }
    }

    /// The matching ssh2 [`HashType`].
    const fn ssh2_hash(self) -> HashType {
        match self {
            Self::Md5 => HashType::Md5,
            Self::Sha1 => HashType::Sha1,
            Self::Sha256 => HashType::Sha256,
        }
    }
}

/// How the server's host key is verified at connect time
/// (`repo-sftp-host-key-check-type` + the related options).
#[derive(Debug, Clone)]
pub enum HostKeyCheck {
    /// No host-key verification (`none`). Insecure; accepts any server key.
    None,
    /// Pin the server key against a configured fingerprint
    /// (`repo-sftp-host-fingerprint`) hashed with `hash_type`.
    Fingerprint {
        /// The expected fingerprint, as a hex string (with or without colons /
        /// `MD5:`/`SHA256:` prefixes) or — for SHA-256 — the OpenSSH base64 form.
        fingerprint: String,
        /// Which digest the configured fingerprint is in.
        hash_type: HostKeyHashType,
    },
    /// Validate the server key against OpenSSH `known_hosts` files
    /// (`repo-sftp-known-host`). With `accept_new` an unknown host is appended to
    /// the first known-hosts file rather than rejected (the `accept-new` mode);
    /// otherwise an unknown host is an error (the `strict` mode).
    KnownHosts {
        /// `known_hosts` file paths to load (in order). Empty falls back to the
        /// user's `~/.ssh/known_hosts`.
        known_hosts: Vec<PathBuf>,
        /// Append an unknown host key instead of rejecting it.
        accept_new: bool,
    },
}

impl Default for HostKeyCheck {
    fn default() -> Self {
        // Matches config.yaml's `repo-sftp-host-key-check-type` default of
        // `strict`: validate against known_hosts, never auto-accept.
        Self::KnownHosts {
            known_hosts: Vec::new(),
            accept_new: false,
        }
    }
}

/// Immutable inputs needed to open an [`Sftp`] backend.
#[derive(Debug, Clone)]
pub struct SftpConfig {
    /// Hostname or IP of the SFTP server.
    pub host: String,
    /// TCP port (typically [`DEFAULT_PORT`]).
    pub port: u16,
    /// SSH username to authenticate as.
    pub user: String,
    /// Remote root that relative paths are resolved against.
    pub base_path: PathBuf,
    /// Authentication method.
    pub auth: SftpAuth,
    /// How the server's host key is verified at connect time.
    pub host_key_check: HostKeyCheck,
}

impl SftpConfig {
    /// Build a password-auth config pointed at `host` on the [`DEFAULT_PORT`].
    #[must_use]
    pub fn with_password(
        host: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
        base_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            host: host.into(),
            port: DEFAULT_PORT,
            user: user.into(),
            base_path: base_path.into(),
            auth: SftpAuth::Password(password.into()),
            host_key_check: HostKeyCheck::default(),
        }
    }

    /// Build a key-file-auth config pointed at `host` on the [`DEFAULT_PORT`].
    #[must_use]
    pub fn with_key_file(
        host: impl Into<String>,
        user: impl Into<String>,
        private_key: impl Into<PathBuf>,
        passphrase: Option<String>,
        base_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            host: host.into(),
            port: DEFAULT_PORT,
            user: user.into(),
            base_path: base_path.into(),
            auth: SftpAuth::KeyFile {
                private_key: private_key.into(),
                public_key: None,
                passphrase,
            },
            host_key_check: HostKeyCheck::default(),
        }
    }
}

/// SFTP storage backend backed by an authenticated [`ssh2::Session`].
///
/// The session owns the underlying TCP socket. `ssh2::Session` /
/// `ssh2::Sftp` are `Send + Sync` (the channel is mutex-guarded internally),
/// so an `Sftp` can be shared behind an `Arc<dyn Storage>` like the other
/// backends.
pub struct Sftp {
    /// Authenticated SSH session (keeps the socket and SFTP channel alive).
    session: Session,
    /// The SFTP subsystem opened over `session`.
    #[allow(clippy::struct_field_names)]
    sftp: ssh2::Sftp,
    /// Remote root for relative-path resolution.
    base_path: PathBuf,
}

impl Sftp {
    /// Open a TCP connection, run the SSH handshake, authenticate, and start
    /// the SFTP subsystem.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] for connection, handshake, or
    /// authentication failures (and for the SFTP-subsystem open), and the more
    /// specific [`StorageError`] variants for SFTP status codes once the
    /// channel is up.
    pub fn connect(config: SftpConfig) -> Result<Self, StorageError> {
        let SftpConfig {
            host,
            port,
            user,
            base_path: base,
            auth,
            host_key_check,
        } = config;
        let addr = format!("{host}:{port}");

        let tcp = TcpStream::connect(&addr).map_err(|err| StorageError::Backend {
            path: base.clone(),
            message: format!("connect to {addr}: {err}"),
        })?;

        let mut session = Session::new().map_err(|err| map_ssh_error(&err, &base))?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|err| map_ssh_error(&err, &base))?;

        // Verify the server's host key (post-handshake, pre-auth) so we never
        // authenticate to — or send credentials to — an unverified server.
        verify_host_key(&session, &host, port, &host_key_check, &base)?;

        match auth {
            SftpAuth::Password(password) => {
                session
                    .userauth_password(&user, &password)
                    .map_err(|err| map_ssh_error(&err, &base))?;
            }
            SftpAuth::KeyFile {
                private_key,
                public_key,
                passphrase,
            } => {
                session
                    .userauth_pubkey_file(&user, public_key.as_deref(), &private_key, passphrase.as_deref())
                    .map_err(|err| map_ssh_error(&err, &base))?;
            }
        }

        if !session.authenticated() {
            return Err(StorageError::PermissionDenied { path: base });
        }

        let sftp = session.sftp().map_err(|err| map_ssh_error(&err, &base))?;

        Ok(Self {
            session,
            sftp,
            base_path: base,
        })
    }

    /// Configured remote root. Useful for diagnostics and tests.
    #[must_use]
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Borrow the underlying SSH session (for callers that need to issue
    /// channel commands alongside SFTP, e.g. host-key handling).
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// Resolve `path` against `base_path` and render it as a POSIX-style remote
    /// path string (the form SFTP servers expect, regardless of client OS).
    fn resolve(&self, path: &Path) -> PathBuf {
        resolve_remote(&self.base_path, path)
    }
}

/// Join `path` onto `base` for the remote server.
///
/// An absolute `path` is taken verbatim; a relative `path` is joined onto
/// `base`. Separators are always rendered as `/` because the remote is
/// POSIX-pathed even when this client runs on Windows. Pure (no I/O) so it can
/// be unit-tested without a live server.
#[must_use]
pub fn resolve_remote(base: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    // Normalise any backslash separators a Windows host may have introduced to
    // forward slashes — the SFTP server's filesystem is POSIX.
    PathBuf::from(joined.to_string_lossy().replace('\\', "/"))
}

/// Map an SFTP status code (the inner value of [`ErrorCode::SFTP`]) and the
/// path it applies to into a typed [`StorageError`].
///
/// Pure so it can be unit-tested without a live server:
/// `NO_SUCH_FILE` / `NO_SUCH_PATH` -> [`StorageError::NotFound`],
/// `PERMISSION_DENIED` -> [`StorageError::PermissionDenied`],
/// `FILE_ALREADY_EXISTS` -> [`StorageError::AlreadyExists`],
/// any other code -> [`StorageError::Backend`].
#[must_use]
pub fn errcode_to_storage(code: i32, path: &Path) -> StorageError {
    match code {
        FX_NO_SUCH_FILE | FX_NO_SUCH_PATH => StorageError::NotFound {
            path: path.to_path_buf(),
        },
        FX_PERMISSION_DENIED => StorageError::PermissionDenied {
            path: path.to_path_buf(),
        },
        FX_FILE_ALREADY_EXISTS => StorageError::AlreadyExists {
            path: path.to_path_buf(),
        },
        other => StorageError::Backend {
            path: path.to_path_buf(),
            message: format!("sftp error code {other}"),
        },
    }
}

/// Map an [`ssh2::Error`] for `path` into a [`StorageError`]. SFTP-level errors
/// (`ErrorCode::SFTP`) go through [`errcode_to_storage`]; session-level errors
/// (`ErrorCode::Session`) fall back to [`StorageError::Backend`] carrying the
/// libssh2 message.
fn map_ssh_error(err: &ssh2::Error, path: &Path) -> StorageError {
    match err.code() {
        ErrorCode::SFTP(code) => errcode_to_storage(code, path),
        ErrorCode::Session(_) => StorageError::Backend {
            path: path.to_path_buf(),
            message: err.message().to_string(),
        },
    }
}

/// Verify the connected `session`'s host key according to `check`, before any
/// authentication. Returns `Ok(())` when the key is trusted (or checking is
/// disabled) and a [`StorageError`] when it is rejected / cannot be verified.
fn verify_host_key(session: &Session, host: &str, port: u16, check: &HostKeyCheck, base: &Path) -> Result<(), StorageError> {
    match check {
        HostKeyCheck::None => Ok(()),
        HostKeyCheck::Fingerprint { fingerprint, hash_type } => {
            let actual = session
                .host_key_hash(hash_type.ssh2_hash())
                .ok_or_else(|| StorageError::Backend {
                    path: base.to_path_buf(),
                    message: format!("server presented no host key for the configured {hash_type:?} fingerprint"),
                })?;
            if fingerprint_matches(fingerprint, actual) {
                Ok(())
            } else {
                Err(StorageError::Backend {
                    path: base.to_path_buf(),
                    message: format!(
                        "host-key fingerprint mismatch for {host}:{port}: expected {fingerprint}, got {}",
                        hex_lower(actual)
                    ),
                })
            }
        }
        HostKeyCheck::KnownHosts { known_hosts, accept_new } => {
            verify_against_known_hosts(session, host, port, known_hosts, *accept_new, base)
        }
    }
}

/// Compare a configured `expected` host-key fingerprint against the raw `actual`
/// digest bytes. Accepts the expected value in several common renderings: plain
/// or colon-separated lowercase hex (optionally with an `MD5:`/`SHA256:`/`SHA1:`
/// prefix) and, for SHA-256, the OpenSSH base64 form. Pure / unit-testable.
fn fingerprint_matches(expected: &str, actual: &[u8]) -> bool {
    let trimmed = expected
        .trim()
        .trim_start_matches("MD5:")
        .trim_start_matches("SHA256:")
        .trim_start_matches("SHA1:")
        .trim_start_matches("sha256:")
        .trim_start_matches("md5:");
    let normalised: String = trimmed.chars().filter(|c| !matches!(c, ':' | ' ')).collect();
    let actual_hex = hex_lower(actual);
    if normalised.eq_ignore_ascii_case(&actual_hex) {
        return true;
    }
    // OpenSSH SHA-256 fingerprints are unpadded base64 of the raw digest.
    BASE64_NO_PAD.encode(actual).eq(trimmed.trim_end_matches('='))
}

/// Lowercase hex-encode a byte slice (no separators).
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Validate the server key against OpenSSH `known_hosts` files.
fn verify_against_known_hosts(
    session: &Session,
    host: &str,
    port: u16,
    files: &[PathBuf],
    accept_new: bool,
    base: &Path,
) -> Result<(), StorageError> {
    let backend = |message: String| StorageError::Backend {
        path: base.to_path_buf(),
        message,
    };

    let (key, key_type) = session
        .host_key()
        .ok_or_else(|| backend("server presented no host key".to_string()))?;
    let fmt = KnownHostKeyFormat::from(key_type);

    let mut known = session.known_hosts().map_err(|err| map_ssh_error(&err, base))?;

    // Load each configured known_hosts file; an absent file is tolerated (it may
    // be created on accept-new). At least one readable file is required unless we
    // are accepting new keys.
    let mut loaded_any = false;
    for file in files {
        if file.exists() {
            known
                .read_file(file, KnownHostFileKind::OpenSSH)
                .map_err(|err| backend(format!("reading known_hosts {}: {}", file.display(), err.message())))?;
            loaded_any = true;
        }
    }

    match known.check_port(host, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err(backend(format!(
            "host-key mismatch for {host}:{port}: the server key does not match known_hosts (possible MITM)"
        ))),
        CheckResult::NotFound if accept_new => {
            // Append the new key to the first configured known_hosts file.
            known
                .add(host, key, "added by pgbackrest accept-new", fmt)
                .map_err(|err| map_ssh_error(&err, base))?;
            if let Some(target) = files.first() {
                known
                    .write_file(target, KnownHostFileKind::OpenSSH)
                    .map_err(|err| backend(format!("writing known_hosts {}: {}", target.display(), err.message())))?;
            }
            Ok(())
        }
        CheckResult::NotFound => {
            let detail = if loaded_any {
                "not present in known_hosts"
            } else {
                "no known_hosts file configured or readable"
            };
            Err(backend(format!(
                "host key for {host}:{port} is unknown ({detail}); add it to known_hosts or use \
                 repo-sftp-host-key-check-type=accept-new"
            )))
        }
        CheckResult::Failure => Err(backend(format!("failed to check the host key for {host}:{port}"))),
    }
}

/// Translate an `ssh2::FileType` into the crate's [`StorageKind`].
fn kind_of(file_type: &FileType) -> StorageKind {
    if file_type.is_file() {
        StorageKind::File
    } else if file_type.is_dir() {
        StorageKind::Path
    } else if file_type.is_symlink() {
        StorageKind::Link
    } else {
        StorageKind::Special
    }
}

/// Build a [`StorageInfo`] from an SFTP `stat` result for `path`.
fn info_from_stat(path: PathBuf, stat: &FileStat) -> StorageInfo {
    let kind = kind_of(&stat.file_type());
    let size = if matches!(kind, StorageKind::File) {
        stat.size.unwrap_or(0)
    } else {
        0
    };
    let modified = stat.mtime.and_then(|m| i64::try_from(m).ok());
    StorageInfo {
        path,
        kind,
        size,
        modified,
    }
}

impl Storage for Sftp {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        let resolved = self.resolve(path);
        match self.sftp.stat(&resolved) {
            Ok(_) => Ok(true),
            Err(err) => match map_ssh_error(&err, &resolved) {
                StorageError::NotFound { .. } => Ok(false),
                other => Err(other),
            },
        }
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        let resolved = self.resolve(path);
        let stat = self.sftp.stat(&resolved).map_err(|err| map_ssh_error(&err, &resolved))?;
        Ok(info_from_stat(resolved, &stat))
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        let resolved = self.resolve(path);
        let entries = self.sftp.readdir(&resolved).map_err(|err| map_ssh_error(&err, &resolved))?;

        let mut result: Vec<StorageInfo> = entries
            .into_iter()
            .filter(|(entry, _)| {
                // `readdir` includes "." and ".."; drop them to match Posix's
                // `read_dir`, which never yields the directory itself.
                !matches!(entry.file_name().and_then(|n| n.to_str()), Some("." | ".."))
            })
            .map(|(entry, stat)| info_from_stat(entry, &stat))
            .collect();
        result.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(result)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        let resolved = self.resolve(path);
        let file = self.sftp.open(&resolved).map_err(|err| map_ssh_error(&err, &resolved))?;
        Ok(Box::new(SftpRead {
            file,
            path: resolved,
            eof: false,
        }))
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        let resolved = self.resolve(path);
        // Create/truncate with sensible default mode (0o644), mirroring
        // `std::fs::File::create` semantics used by the Posix backend.
        let file = self
            .sftp
            .open_mode(
                &resolved,
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                0o644,
                OpenType::File,
            )
            .map_err(|err| map_ssh_error(&err, &resolved))?;
        Ok(Box::new(SftpWrite {
            file: Some(file),
            path: resolved,
        }))
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path);
        match self.sftp.unlink(&resolved) {
            Ok(()) => Ok(()),
            Err(err) => match map_ssh_error(&err, &resolved) {
                StorageError::NotFound { .. } if !error_on_missing => Ok(()),
                other => Err(other),
            },
        }
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        let resolved_source = self.resolve(source);
        let resolved_target = self.resolve(target);
        // ATOMIC | OVERWRITE matches the C driver / POSIX rename(2): replace the
        // target if it exists. NATIVE lets the server pick its best primitive.
        self.sftp
            .rename(
                &resolved_source,
                &resolved_target,
                Some(RenameFlags::ATOMIC | RenameFlags::OVERWRITE | RenameFlags::NATIVE),
            )
            .map_err(|err| map_ssh_error(&err, &resolved_source))
    }

    fn create_path(&self, path: &Path, recursive: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path);
        if recursive {
            self.mkdir_recursive(&resolved)
        } else {
            self.sftp
                .mkdir(&resolved, 0o755)
                .map_err(|err| map_ssh_error(&err, &resolved))
        }
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        let resolved = self.resolve(path);

        if recursive {
            // Empty the directory first, depth-first, then rmdir it.
            match self.remove_tree(&resolved) {
                Ok(()) => Ok(()),
                Err(StorageError::NotFound { .. }) if !error_on_missing => Ok(()),
                Err(other) => Err(other),
            }
        } else {
            match self.sftp.rmdir(&resolved) {
                Ok(()) => Ok(()),
                Err(err) => match map_ssh_error(&err, &resolved) {
                    StorageError::NotFound { .. } if !error_on_missing => Ok(()),
                    other => Err(other),
                },
            }
        }
    }
}

impl Sftp {
    /// Create `path` and any missing parents (SFTP `mkdir` is one level only).
    fn mkdir_recursive(&self, path: &Path) -> Result<(), StorageError> {
        // Already a directory? Nothing to do.
        if let Ok(stat) = self.sftp.stat(path)
            && stat.is_dir()
        {
            return Ok(());
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            self.mkdir_recursive(parent)?;
        }
        match self.sftp.mkdir(path, 0o755) {
            Ok(()) => Ok(()),
            // Tolerate a race / pre-existing directory created by a parallel run.
            Err(err) => match map_ssh_error(&err, path) {
                StorageError::AlreadyExists { .. } => Ok(()),
                other => Err(other),
            },
        }
    }

    /// Recursively remove the directory `path` and everything under it.
    fn remove_tree(&self, path: &Path) -> Result<(), StorageError> {
        let entries = self.sftp.readdir(path).map_err(|err| map_ssh_error(&err, path))?;
        for (entry, stat) in entries {
            if let Some("." | "..") = entry.file_name().and_then(|n| n.to_str()) {
                continue;
            }
            if stat.is_dir() {
                self.remove_tree(&entry)?;
            } else {
                self.sftp.unlink(&entry).map_err(|err| map_ssh_error(&err, &entry))?;
            }
        }
        self.sftp.rmdir(path).map_err(|err| map_ssh_error(&err, path))
    }
}

/// Adapter exposing an `ssh2::File` opened for reading as a [`pgbr_io::IoRead`].
struct SftpRead {
    file: ssh2::File,
    path: PathBuf,
    eof: bool,
}

impl IoRead for SftpRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let n = Read::read(&mut self.file, buf).map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

/// Adapter exposing an `ssh2::File` opened for writing as a [`pgbr_io::IoWrite`].
struct SftpWrite {
    file: Option<ssh2::File>,
    path: PathBuf,
}

impl IoWrite for SftpWrite {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        let file = self.file.as_mut().ok_or(IoError::Closed)?;
        Write::write_all(file, buf).map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))
    }

    fn flush(&mut self) -> Result<(), IoError> {
        let file = self.file.as_mut().ok_or(IoError::Closed)?;
        Write::flush(file).map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))
    }

    fn close(&mut self) -> Result<(), IoError> {
        if let Some(mut file) = self.file.take() {
            Write::flush(&mut file).map_err(|err| IoError::Backend(format!("{}: {err}", self.path.display())))?;
            // Dropping `file` closes the SFTP handle; flushing first ensures the
            // server has the full payload before the handle goes away.
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn resolve_remote_joins_relative_against_base() {
        let base = Path::new("/srv/repo");
        assert_eq!(
            resolve_remote(base, Path::new("archive/x")),
            PathBuf::from("/srv/repo/archive/x")
        );
    }

    #[test]
    fn resolve_remote_takes_absolute_verbatim() {
        let base = Path::new("/srv/repo");
        assert_eq!(resolve_remote(base, Path::new("/etc/passwd")), PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn resolve_remote_normalises_backslashes_to_slashes() {
        // A relative path that a Windows host might render with backslashes still
        // resolves to a POSIX remote path.
        let base = Path::new("/srv/repo");
        let resolved = resolve_remote(base, Path::new("archive\\sub\\file"));
        assert_eq!(resolved, PathBuf::from("/srv/repo/archive/sub/file"));
    }

    #[test]
    fn errcode_no_such_file_maps_to_not_found() {
        let path = Path::new("/srv/repo/missing");
        assert_eq!(
            errcode_to_storage(FX_NO_SUCH_FILE, path),
            StorageError::NotFound {
                path: path.to_path_buf()
            }
        );
        assert_eq!(
            errcode_to_storage(FX_NO_SUCH_PATH, path),
            StorageError::NotFound {
                path: path.to_path_buf()
            }
        );
    }

    #[test]
    fn errcode_permission_denied_maps() {
        let path = Path::new("/srv/repo/locked");
        assert_eq!(
            errcode_to_storage(FX_PERMISSION_DENIED, path),
            StorageError::PermissionDenied {
                path: path.to_path_buf()
            }
        );
    }

    #[test]
    fn errcode_already_exists_maps() {
        let path = Path::new("/srv/repo/dir");
        assert_eq!(
            errcode_to_storage(FX_FILE_ALREADY_EXISTS, path),
            StorageError::AlreadyExists {
                path: path.to_path_buf()
            }
        );
    }

    #[test]
    fn errcode_unknown_maps_to_backend_with_code() {
        let path = Path::new("/srv/repo/x");
        match errcode_to_storage(4, path) {
            StorageError::Backend { message, path: p } => {
                assert!(message.contains('4'), "message was {message}");
                assert_eq!(p, path.to_path_buf());
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn config_with_password_defaults_port_and_auth() {
        let config = SftpConfig::with_password("host.example", "backup", "s3cr3t", "/srv/repo");
        assert_eq!(config.host, "host.example");
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.user, "backup");
        assert_eq!(config.base_path, PathBuf::from("/srv/repo"));
        match config.auth {
            SftpAuth::Password(pw) => assert_eq!(pw, "s3cr3t"),
            other @ SftpAuth::KeyFile { .. } => panic!("expected Password, got {other:?}"),
        }
    }

    #[test]
    fn config_with_key_file_carries_key_and_passphrase() {
        let config = SftpConfig::with_key_file(
            "host.example",
            "backup",
            "/home/backup/.ssh/id_ed25519",
            Some("phrase".to_string()),
            "/srv/repo",
        );
        assert_eq!(config.port, DEFAULT_PORT);
        match config.auth {
            SftpAuth::KeyFile {
                private_key,
                public_key,
                passphrase,
            } => {
                assert_eq!(private_key, PathBuf::from("/home/backup/.ssh/id_ed25519"));
                assert!(public_key.is_none(), "no explicit public key by default");
                assert_eq!(passphrase.as_deref(), Some("phrase"));
            }
            other @ SftpAuth::Password(_) => panic!("expected KeyFile, got {other:?}"),
        }
        // The default host-key policy is strict known_hosts (never auto-accept).
        match config.host_key_check {
            HostKeyCheck::KnownHosts { accept_new, .. } => assert!(!accept_new),
            other => panic!("expected strict KnownHosts default, got {other:?}"),
        }
    }

    #[test]
    fn host_key_hash_type_parse() {
        assert_eq!(HostKeyHashType::parse("md5").unwrap(), HostKeyHashType::Md5);
        assert_eq!(HostKeyHashType::parse("sha1").unwrap(), HostKeyHashType::Sha1);
        assert_eq!(HostKeyHashType::parse("sha256").unwrap(), HostKeyHashType::Sha256);
        assert!(HostKeyHashType::parse("crc32").is_err());
        assert_eq!(HostKeyHashType::default(), HostKeyHashType::Sha256);
    }

    #[test]
    fn fingerprint_matches_hex_forms() {
        // Raw SHA-256 digest of "host-key" (computed independently).
        let actual: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        // Plain lowercase hex.
        assert!(fingerprint_matches("deadbeef", &actual));
        // Upper-case hex.
        assert!(fingerprint_matches("DEADBEEF", &actual));
        // Colon-separated (ssh-keygen MD5 style).
        assert!(fingerprint_matches("de:ad:be:ef", &actual));
        // With an algorithm prefix.
        assert!(fingerprint_matches("SHA256:deadbeef", &actual));
        // A different value does not match.
        assert!(!fingerprint_matches("cafebabe", &actual));
    }

    #[test]
    fn fingerprint_matches_openssh_base64() {
        // OpenSSH SHA-256 fingerprints are unpadded base64 of the raw digest.
        let actual: [u8; 3] = [0x01, 0x02, 0x03]; // base64 -> "AQID"
        assert!(fingerprint_matches("AQID", &actual));
        assert!(fingerprint_matches("SHA256:AQID", &actual));
        assert!(!fingerprint_matches("AAAA", &actual));
    }

    #[test]
    fn hex_lower_encodes_bytes() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }

    #[test]
    fn sftp_config_default_host_key_check_is_strict() {
        let config = SftpConfig::with_password("h", "u", "p", "/srv");
        assert!(matches!(
            config.host_key_check,
            HostKeyCheck::KnownHosts { accept_new: false, .. }
        ));
    }

    /// Live round trip against a real SFTP server. Skipped unless the
    /// `PGBR_SFTP_*` env vars are set. Run with:
    /// `cargo test -p pgbr-storage -- --ignored`.
    ///
    /// Required env vars: `PGBR_SFTP_HOST`, `PGBR_SFTP_USER`, `PGBR_SFTP_PASSWORD`,
    /// `PGBR_SFTP_PATH`. Optional: `PGBR_SFTP_PORT` (defaults to 22).
    #[test]
    #[ignore = "requires a live SFTP server and PGBR_SFTP_* env vars"]
    fn sftp_round_trip() {
        let host = std::env::var("PGBR_SFTP_HOST").expect("PGBR_SFTP_HOST");
        let user = std::env::var("PGBR_SFTP_USER").expect("PGBR_SFTP_USER");
        let password = std::env::var("PGBR_SFTP_PASSWORD").expect("PGBR_SFTP_PASSWORD");
        let base_path = std::env::var("PGBR_SFTP_PATH").expect("PGBR_SFTP_PATH");
        let port = std::env::var("PGBR_SFTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT);

        let config = SftpConfig {
            host,
            port,
            user,
            base_path: PathBuf::from(base_path),
            auth: SftpAuth::Password(password),
            // The live test server's key is typically not in known_hosts; disable
            // the check so the round trip is about transfers, not key trust.
            host_key_check: HostKeyCheck::None,
        };
        let sftp = Sftp::connect(config).expect("connect");

        let dir = Path::new("pgbr-sftp-round-trip");
        sftp.create_path(dir, true).expect("create_path");

        let file = dir.join("payload.txt");
        {
            let mut writer = sftp.open_write(&file).expect("open_write");
            writer.write(b"hello sftp").expect("write");
            writer.close().expect("close");
        }

        assert!(sftp.exists(&file).expect("exists"));
        let info = sftp.info(&file).expect("info");
        assert_eq!(info.kind, StorageKind::File);
        assert_eq!(info.size, 10);

        let entries = sftp.list(dir).expect("list");
        assert!(entries.iter().any(|e| e.path.ends_with("payload.txt")));

        let mut reader = sftp.open_read(&file).expect("open_read");
        assert_eq!(reader.read_all().expect("read_all"), b"hello sftp");

        sftp.remove(&file, true).expect("remove");
        assert!(!sftp.exists(&file).expect("exists after remove"));

        sftp.remove_path(dir, true, true).expect("remove_path");
        assert!(!sftp.exists(dir).expect("exists dir after remove_path"));
    }
}
