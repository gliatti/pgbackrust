//! Construct the repo + pg [`Storage`] backends from a resolved
//! [`LoadedConfig`], mirroring the C `storageRepoGet` / `storagePgGet` routing
//! in `src/storage/helper.c`.
//!
//! Routing (per the C reference):
//!
//! - If `repo-host` (resp. `pg-host`) is set the storage is *remote* — driven
//!   over an SSH tunnel by the protocol layer. We spawn a `pgbackrest` worker
//!   on that host (`ssh <host> pgbackrest <command>:remote …`, see
//!   [`crate::remote_storage`]) and proxy every [`Storage`] call to it through
//!   [`pgbr_storage::remote::RemoteStorage`]. C ref: `src/protocol/helper.c`.
//! - Otherwise the repo backend is selected by `repo-type` (default `posix`):
//!   `posix`/`cifs` are filesystem-rooted at `repo-path`; `s3`/`azure`/`gcs`
//!   are built from their `repo-*` option families. The pg backend is always a
//!   posix store rooted at `pg-path`.
//!
//! ## Multiple repositories (`--repo=N`)
//!
//! pgBackRest indexes its repository options by a 1-based group index
//! (`repo1-type`, `repo2-path`, …). The `--repo` integer option (default `1`)
//! selects the *active* repository for single-repo commands (`info`, `expire`,
//! `restore`, …) — `--repo=2 info` reads `repo2-*`. [`build_repo_storage`]
//! builds the backend for that active index. Commands that span every
//! repository (`archive-push`, `stanza-create`/`-delete`/`-upgrade`) instead
//! call [`build_all_repo_storages`], which constructs one backend per
//! *configured* repository (every index whose `repoN-path` or `repoN-type` is
//! set, defaulting to `{1}`), enumerated by [`configured_repo_indexes`].
//!
//! `repo`-group options resolve at the active index first, then fall back to the
//! ungrouped key, and finally to the option's documented default. The
//! `pg`-group options the PG backend reads stay at index 1 (the PG cluster is
//! not part of the repository fan-out). C ref: `cfgOptionGroupIdxDefault` /
//! the `repo` iteration in `src/config/config.c` and `src/storage/helper.c`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_protocol::PGBACKREST_PROGRAM;
use pgbr_storage::s3::{S3Encryption, S3UriStyle};
use pgbr_storage::sftp::{HostKeyCheck, HostKeyHashType};
use pgbr_storage::{
    Azure, AzureConfig, Cifs, Gcs, GcsAuth, GcsConfig, HttpOptions, Posix, S3, S3Config, Sftp, SftpAuth, SftpConfig, Storage,
};

use std::sync::Arc;

use crate::CliRunError;
use crate::remote_storage::{RemoteProcessStorage, RemoteTlsStorage};

/// The `pgbackrest` command the spawned worker is invoked with, in the
/// `<command>:remote` form so the child's [`pgbr_command::worker::is_worker`]
/// recognises the `Remote` command role and serves the storage protocol on its
/// stdio. `backup` is used because it declares the `remote` role and accepts
/// both `repo-path` and `pg-path`, so one worker command covers both the repo
/// and PG roots. The worker bypasses the full-config default validation
/// (see [`crate::run_with_context`]), so only the role + the explicitly passed
/// `--stanza` / `--<repo|pg>1-path` matter.
const WORKER_COMMAND_REMOTE: &str = "backup:remote";

/// Default `repo-path` when the option is absent (matches `config.yaml`'s
/// `repo-path` default).
const DEFAULT_REPO_PATH: &str = "/var/lib/pgbackrest";

/// Default `repo-type` (matches `config.yaml`'s `repo-type` default).
const DEFAULT_REPO_TYPE: &str = "posix";

/// Default `repo-host-type` / `pg-host-type` (matches `config.yaml`): the SSH
/// transport.
const DEFAULT_HOST_TYPE: &str = "ssh";

/// The TLS host transport: connect to the peer's running `pgbackrest server`
/// over mutual TLS instead of spawning a worker over SSH.
const HOST_TYPE_TLS: &str = "tls";

/// Default `tls-server-port` the peer `pgbackrest server` listens on (matches
/// `config.yaml`'s `tls-server-port` default), used as the TLS transport port
/// when no `tls-server-port` is configured.
const DEFAULT_TLS_PORT: u16 = 8432;

/// Group index of the `pg`-family options the PG backend reads. The PG cluster
/// is not part of the repository fan-out, so it stays at the first index.
const PG_INDEX: u32 = 1;

/// Resolve the active repository index from the `--repo` integer option,
/// defaulting to `1` when unset (matching `config.yaml`, where `repo` is an
/// ungrouped integer with no explicit default and pgBackRest's
/// "default first index" behaviour).
#[must_use]
pub fn active_repo_index(cfg: &LoadedConfig) -> u32 {
    match cfg.options.get(&("repo".to_owned(), None)) {
        Some(OptionValue::Integer(i)) => u32::try_from(*i).unwrap_or(1),
        _ => 1,
    }
}

/// Build the repository [`Storage`] backend for the *active* repository
/// (selected by `--repo`, default `1`).
///
/// Selects the backend from `repoN-type` (default `posix`) and constructs it
/// from the matching `repoN-*` option family at the active index. When
/// `repoN-host` is set the repository lives on another host: a `pgbackrest`
/// worker is spawned there over SSH and every [`Storage`] call is proxied to it
/// (see [`build_remote_host_storage`]).
///
/// # Errors
///
/// Returns [`CliRunError::Protocol`] when the inter-host worker (`ssh …`) cannot
/// be spawned, [`CliRunError::StorageConfig`] when a required cloud option is
/// missing or `repo-type` is unrecognised, and [`CliRunError::Storage`] when a
/// backend constructor itself rejects the config.
pub fn build_repo_storage(cfg: &LoadedConfig) -> Result<Box<dyn Storage>, CliRunError> {
    build_repo_storage_at(cfg, active_repo_index(cfg))
}

/// Build the repository [`Storage`] backend for repository index `index`,
/// reading the `repoN-*` option family at that group index (with a fallback to
/// the ungrouped key and then the option default).
///
/// This is the index-aware core of [`build_repo_storage`]; [`build_all_repo_storages`]
/// calls it once per configured repository.
///
/// # Errors
///
/// As [`build_repo_storage`].
fn build_repo_storage_at(cfg: &LoadedConfig, index: u32) -> Result<Box<dyn Storage>, CliRunError> {
    // Inter-host operation: the repo lives on another host. Spawn a pgbackrest
    // worker there over SSH and proxy storage to it. The worker is rooted at the
    // remote `repo1-path`, which the worker side resolves from the same option.
    //
    // `repo-local` (or a worker `remote-type=repo`) forces the *local* backend
    // even when `repo-host` is set — the worker that runs on the repo host is
    // itself local to that repository, so it must not recurse into another SSH
    // hop. C ref: `storageRepoGet`'s `repoIsLocal` check.
    if !force_local(cfg, "repo-local", "repo", index)
        && let Some(host) = string_option(cfg, "repo-host", index)
    {
        let path = path_option(cfg, "repo-path", index).unwrap_or_else(|| PathBuf::from(DEFAULT_REPO_PATH));
        return build_remote_host_storage(cfg, &host, "repo", "repo1-path", &path, index);
    }

    let repo_type = string_option(cfg, "repo-type", index).unwrap_or_else(|| DEFAULT_REPO_TYPE.to_owned());

    match repo_type.as_str() {
        "posix" => {
            let root = path_option(cfg, "repo-path", index).unwrap_or_else(|| PathBuf::from(DEFAULT_REPO_PATH));
            Ok(Box::new(Posix::new(root)))
        }
        "cifs" => {
            let root = path_option(cfg, "repo-path", index).unwrap_or_else(|| PathBuf::from(DEFAULT_REPO_PATH));
            Ok(Box::new(Cifs::new(root)))
        }
        "s3" => build_s3(cfg, index),
        "azure" => build_azure(cfg, index),
        "gcs" => build_gcs(cfg, index),
        "sftp" => build_sftp(cfg, index),
        other => Err(CliRunError::StorageConfig(format!(
            "unrecognised repo-type `{other}` (expected one of posix, cifs, s3, azure, gcs, sftp)"
        ))),
    }
}

/// Enumerate the configured repository indexes, smallest first.
///
/// A repository index `N` is "configured" when an explicit `repoN-path` *or*
/// `repoN-type` value is present in the resolved options at that group index.
/// When no grouped repo option is present anywhere the binary still has one
/// repository — index `1` — so the returned set is never empty (it defaults to
/// `{1}`). The active `--repo` index is always included so a `--repo=N` that
/// only relies on defaults still participates.
///
/// Mirrors pgBackRest's repo iteration (`cfgOptionGroupIdxTotal` over the
/// `cfgOptGrpRepo` group) in `src/config/config.c`.
#[must_use]
pub fn configured_repo_indexes(cfg: &LoadedConfig) -> Vec<u32> {
    let mut indexes: BTreeSet<u32> = BTreeSet::new();
    for (name, idx) in cfg.options.keys() {
        if let Some(i) = idx
            && matches!(name.as_str(), "repo-path" | "repo-type")
        {
            indexes.insert(*i);
        }
    }
    // The active repo always counts (it may rely solely on defaults), and an
    // empty set means the implicit single repository at index 1.
    indexes.insert(active_repo_index(cfg));
    if indexes.is_empty() {
        indexes.insert(1);
    }
    indexes.into_iter().collect()
}

/// One configured repository: its 1-based group index plus the constructed
/// [`Storage`] backend. Returned (in a `Vec`) by [`build_all_repo_storages`].
pub type IndexedRepoStorage = (u32, Box<dyn Storage>);

/// Build one repository [`Storage`] backend per *configured* repository,
/// returning them paired with their group index in ascending index order.
///
/// Used by the commands that operate on every repository at once
/// (`archive-push`, `stanza-create`/`-delete`/`-upgrade`): each WAL segment must
/// reach every repository, and a stanza must be initialised on every repository.
/// The index is returned alongside each backend so callers that need per-repo
/// settings (e.g. each repository's own `repoN-cipher-*`) can read them.
///
/// # Errors
///
/// Propagates the first per-repository [`build_repo_storage_at`] failure.
pub fn build_all_repo_storages(cfg: &LoadedConfig) -> Result<Vec<IndexedRepoStorage>, CliRunError> {
    let mut out = Vec::new();
    for index in configured_repo_indexes(cfg) {
        out.push((index, build_repo_storage_at(cfg, index)?));
    }
    Ok(out)
}

/// Build the `PostgreSQL` data-directory [`Storage`] backend from the resolved
/// config: a [`Posix`] store rooted at `pg-path`, or — when `pg-host` is set — a
/// proxy to a `pgbackrest` worker spawned on that host over SSH (see
/// [`build_remote_host_storage`]).
///
/// # Errors
///
/// Returns [`CliRunError::Protocol`] when the inter-host worker (`ssh …`) cannot
/// be spawned, [`CliRunError::StorageConfig`] when `pg-path` is absent (every
/// PG-touching command requires it; commands that never touch PG storage are
/// routed before this is called).
pub fn build_pg_storage(cfg: &LoadedConfig) -> Result<Box<dyn Storage>, CliRunError> {
    // Inter-host operation: the PG data dir lives on another host. The worker is
    // rooted at the remote `pg1-path`. `pg-path` is required regardless so the
    // worker has a root to serve and the option carries to the remote argv.
    let root = path_option(cfg, "pg-path", PG_INDEX)
        .ok_or_else(|| CliRunError::StorageConfig("pg-path is required to build PG storage but is not set".to_owned()))?;

    // `pg-local` (or a worker `remote-type=pg`) forces the local backend even
    // when `pg-host` is set, mirroring the repo side: the worker running on the
    // PG host serves its own local data dir and must not open a second SSH hop.
    if !force_local(cfg, "pg-local", "pg", PG_INDEX)
        && let Some(host) = string_option(cfg, "pg-host", PG_INDEX)
    {
        return build_remote_host_storage(cfg, &host, "pg", "pg1-path", &root, PG_INDEX);
    }

    Ok(Box::new(Posix::new(root)))
}

/// Whether the local backend is forced for `family` (`pg` / `repo`) at group
/// index `index`, even when a `<family>-host` is configured.
///
/// True when the `<family>-local` boolean option is set, or when a worker's
/// `remote-type` string-id names this family (a `remote-type=repo` worker treats
/// the repository as local; `remote-type=pg` treats the PG data dir as local).
/// Mirrors the C `pgIsLocal` / `repoIsLocal` predicates in `src/storage/helper.c`.
fn force_local(cfg: &LoadedConfig, local_option: &str, family: &str, index: u32) -> bool {
    if boolean_option(cfg, local_option, index) == Some(true) {
        return true;
    }
    // A worker invoked with `--remote-type=<family>` is local to that family.
    string_option(cfg, "remote-type", index).is_some_and(|t| t == family)
}

/// Build the inter-host storage transport for `host`, selecting SSH or TLS by
/// the `<family>-host-type` option (default `ssh`).
///
/// `family` is `"repo"` or `"pg"`. For `ssh` (the default) a `pgbackrest` worker
/// is spawned on the host over SSH and proxied via [`RemoteProcessStorage`]
/// (see [`build_ssh_host_storage`]). For `tls` a mutual-TLS connection is opened
/// to the host's running `pgbackrest server` and the same storage protocol is
/// run over it via [`RemoteTlsStorage`] (see [`build_tls_host_storage`]).
/// Mirrors the `ssh` / `tls` branches of the C `protocolRemoteParam` in
/// `src/protocol/helper.c`.
///
/// # Errors
///
/// Returns [`CliRunError::Protocol`] if the SSH worker cannot be spawned or the
/// TLS connection / handshake fails, [`CliRunError::Command`] if a required TLS
/// option (e.g. `<family>-host-ca-file`) is missing or invalid, or
/// [`CliRunError::StorageConfig`] for an unrecognised host-type.
fn build_remote_host_storage(
    cfg: &LoadedConfig,
    host: &str,
    family: &str,
    path_flag: &str,
    remote_path: &Path,
    index: u32,
) -> Result<Box<dyn Storage>, CliRunError> {
    let host_type = string_option(cfg, &format!("{family}-host-type"), index).unwrap_or_else(|| DEFAULT_HOST_TYPE.to_owned());

    match host_type.as_str() {
        DEFAULT_HOST_TYPE => build_ssh_host_storage(cfg, host, family, path_flag, remote_path, index),
        HOST_TYPE_TLS => build_tls_host_storage(cfg, host, family, index),
        other => Err(CliRunError::StorageConfig(format!(
            "unrecognised {family}-host-type `{other}` (expected ssh or tls)"
        ))),
    }
}

/// Spawn a `pgbackrest` worker on `host` over SSH and wrap it in a
/// [`RemoteProcessStorage`] proxy.
///
/// The `*-host-{user,port,cmd}` family supplies the SSH user / port and the
/// remote `pgbackrest` program path. The worker is invoked as
/// `<host-cmd> <command>:remote --stanza=<s> --<path_flag>=<remote_path>`, so it
/// roots at `remote_path` and serves the storage protocol on its stdio.
///
/// # Errors
///
/// Returns [`CliRunError::Protocol`] if the `ssh` process cannot be spawned.
fn build_ssh_host_storage(
    cfg: &LoadedConfig,
    host: &str,
    family: &str,
    path_flag: &str,
    remote_path: &Path,
    index: u32,
) -> Result<Box<dyn Storage>, CliRunError> {
    // SSH connection params from the matching `*-host-{user,port,cmd}` family.
    let ssh_user = string_option(cfg, &format!("{family}-host-user"), index);
    let ssh_port = integer_option(cfg, &format!("{family}-host-port"), index).and_then(|p| u16::try_from(p).ok());
    // The remote `pgbackrest` program path. `*-host-cmd` is a `default-type:
    // dynamic` "bin" option that resolves to the *local* exe path; on the remote
    // host the same install path is the usual convention, falling back to the
    // bare `pgbackrest` program name found on the remote PATH.
    let remote_program = string_option(cfg, &format!("{family}-host-cmd"), index).unwrap_or_else(|| PGBACKREST_PROGRAM.to_owned());

    // Remote worker argv: the worker role command plus the stanza and the root
    // path the worker should serve. The worker side reads `pg1-path` /
    // `repo1-path` to pick its root, so pass exactly the one for this family.
    let mut remote_args = vec![WORKER_COMMAND_REMOTE.to_owned()];
    if let Some(stanza) = &cfg.stanza {
        remote_args.push(format!("--stanza={stanza}"));
    }
    remote_args.push(format!("--{path_flag}={}", remote_path.display()));
    append_host_config_args(cfg, family, index, &mut remote_args);

    let storage = RemoteProcessStorage::spawn_ssh(host, ssh_port, ssh_user.as_deref(), &remote_program, &remote_args)
        .map_err(CliRunError::Protocol)?;
    Ok(Box::new(storage))
}

/// Append the `<family>-host-config*` family to a remote worker's argv so the
/// spawned worker loads the operator-specified config file / paths on the remote
/// host instead of its own defaults.
///
/// pgBackRest lets the operator point a remote worker at a non-default config
/// location with `repo-host-config` / `pg-host-config` (the main config file),
/// `*-host-config-path` (the base config directory) and
/// `*-host-config-include-path` (the `*.conf` include directory). Each, when set,
/// is forwarded as the corresponding global option the worker understands:
///
/// - `<family>-host-config` -> `--config=<…>`
/// - `<family>-host-config-path` -> `--config-path=<…>`
/// - `<family>-host-config-include-path` -> `--config-include-path=<…>`
///
/// Only options explicitly set at the active index (or the ungrouped fallback)
/// are appended; unset options leave the worker on its own defaults. C ref:
/// `protocolRemoteParam` in `src/protocol/helper.c` (the `cfgOptRepoHostConfig*`
/// / `cfgOptPgHostConfig*` pass-through).
fn append_host_config_args(cfg: &LoadedConfig, family: &str, index: u32, args: &mut Vec<String>) {
    // (host-config option suffix, remote worker flag) pairs, in a stable order.
    const FORWARDED: &[(&str, &str)] = &[
        ("host-config", "config"),
        ("host-config-path", "config-path"),
        ("host-config-include-path", "config-include-path"),
    ];
    for (suffix, flag) in FORWARDED {
        if let Some(value) = string_option(cfg, &format!("{family}-{suffix}"), index) {
            args.push(format!("--{flag}={value}"));
        }
    }
}

/// Resolve the TLS host transport's connect address `<host>:<port>` from the
/// `tls-server-port` option (default [`DEFAULT_TLS_PORT`]) — pgBackRest connects
/// to the peer's `pgbackrest server` listener, whose port is `tls-server-port`.
fn tls_host_address(cfg: &LoadedConfig, host: &str) -> String {
    let port = integer_option(cfg, "tls-server-port", 1)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(DEFAULT_TLS_PORT);
    format!("{host}:{port}")
}

/// Open a mutual-TLS connection to `host`'s running `pgbackrest server` and wrap
/// it in a [`RemoteTlsStorage`] proxy running the same storage protocol.
///
/// The `<family>-host-ca-file` (a single CA PEM) and/or `<family>-host-ca-path`
/// (a directory of CA PEMs) supply the CA roots the client trusts for the server
/// certificate — at least one is required and both are additive;
/// `<family>-host-cert-file` / `<family>-host-key-file` (both required for mutual
/// TLS) are the client certificate the peer authorizes by its Common Name
/// against `tls-server-auth`. `tls-cipher-12` / `tls-cipher-13`, when set,
/// restrict the negotiated ciphers. The peer serves a `pgbackrest server` rooted
/// at its configured path, so no remote argv / root is passed here (unlike the
/// SSH worker).
///
/// # Errors
///
/// Returns [`CliRunError::StorageConfig`] when neither `*-host-ca-file` nor
/// `*-host-ca-path` is set, [`CliRunError::Command`] when a PEM file / directory
/// is invalid or a required `*-host-{cert,key}-file` is rejected, and
/// [`CliRunError::Protocol`] when the TLS connection or handshake fails.
fn build_tls_host_storage(cfg: &LoadedConfig, host: &str, family: &str, index: u32) -> Result<Box<dyn Storage>, CliRunError> {
    let ca_file = string_option(cfg, &format!("{family}-host-ca-file"), index);
    let ca_path = string_option(cfg, &format!("{family}-host-ca-path"), index);
    if ca_file.is_none() && ca_path.is_none() {
        return Err(CliRunError::StorageConfig(format!(
            "{family}-host-type=tls requires {family}-host-ca-file or {family}-host-ca-path"
        )));
    }
    let cert_file = string_option(cfg, &format!("{family}-host-cert-file"), index);
    let key_file = string_option(cfg, &format!("{family}-host-key-file"), index);

    // The allowed-cipher option values, in 1.2-then-1.3 order; empty when unset
    // so the peer / rustls defaults apply.
    let cipher_names: Vec<String> = ["tls-cipher-12", "tls-cipher-13"]
        .into_iter()
        .filter_map(|name| string_option(cfg, name, 1))
        .collect();

    let client_config = pgbr_command::server::build_client_config_from_files(
        ca_file.as_deref(),
        ca_path.as_deref(),
        cert_file.as_deref(),
        key_file.as_deref(),
        &cipher_names,
    )
    .map_err(CliRunError::Command)?;

    let addr = tls_host_address(cfg, host);
    // `sck-block` (default false) toggles blocking socket mode on the connecting
    // socket; only enforced when set (the transport relies on blocking I/O).
    let sck_block = boolean_option(cfg, "sck-block", 1).unwrap_or(false);
    // The peer's `pgbackrest server` is typically started without `--stanza`
    // so it can serve many stanzas off one listener; CN authorization must
    // run against the *client's* stanza, which the greeting noOp carries.
    // `cfg.stanza` is the resolved `--stanza=<name>` for this run.
    let stanza = cfg.stanza.as_deref();
    let storage =
        RemoteTlsStorage::connect(&addr, host, Arc::new(client_config), sck_block, stanza).map_err(CliRunError::Protocol)?;
    Ok(Box::new(storage))
}

/// Build the [`S3`] backend from the `repo-s3-*` / `repo-storage-*` options at
/// repository index `index`.
fn build_s3(cfg: &LoadedConfig, index: u32) -> Result<Box<dyn Storage>, CliRunError> {
    let bucket = require_string(cfg, "repo-s3-bucket", index)?;
    let region = require_string(cfg, "repo-s3-region", index)?;

    // `repo-s3-key-type` (default `shared`) selects how credentials are sourced.
    // `shared` uses the configured key/secret; `web-id`/`auto` read AWS
    // web-identity / instance credentials (best-effort: web-id reads the token
    // file env; auto falls back to it). C ref: `storageS3New` key-type switch.
    let key_type = string_option(cfg, "repo-s3-key-type", index).unwrap_or_else(|| "shared".to_owned());
    let (access_key, secret_key, token) = resolve_s3_credentials(cfg, index, &key_type)?;

    // `repo-s3-endpoint` is a bare host (e.g. `s3.us-east-1.amazonaws.com`);
    // `repo-storage-host` overrides it when present. The S3 backend wants a
    // full URL with scheme, so prepend `https://` when the value is scheme-less
    // (matching the C `defaultType = httpProtocolTypeHttps`).
    let raw_host = string_option(cfg, "repo-storage-host", index)
        .or_else(|| string_option(cfg, "repo-s3-endpoint", index))
        .ok_or_else(|| CliRunError::StorageConfig("repo-type=s3 requires repo-s3-endpoint (or repo-storage-host)".to_owned()))?;
    let endpoint = with_scheme(&host_with_optional_port(cfg, &raw_host, index));

    // `repo-s3-uri-style` (default `host`): host vs path bucket addressing.
    let uri_style = match string_option(cfg, "repo-s3-uri-style", index) {
        None => S3UriStyle::default(),
        Some(value) => S3UriStyle::parse(&value).map_err(CliRunError::StorageConfig)?,
    };

    // `repo-s3-role`: STS AssumeRole. Not yet implemented — surface a clear
    // error rather than silently ignoring the configured role, but only when it
    // is actually set so the common path is unaffected.
    if let Some(role) = string_option(cfg, "repo-s3-role", index) {
        return Err(CliRunError::NotSupportedYet(format!(
            "repo-s3-role={role}: STS AssumeRole is not implemented yet (configure static credentials via \
             repo-s3-key-type=shared, or web-identity via repo-s3-key-type=web-id)"
        )));
    }

    let encryption = s3_encryption_from(cfg, index);
    let requester_pays = boolean_option(cfg, "repo-s3-requester-pays", index).unwrap_or(false);
    let tags = hash_option(cfg, "repo-storage-tag", index);
    let http = http_options_from(cfg, index);

    let s3 = S3::new(S3Config {
        endpoint,
        region,
        bucket,
        access_key,
        secret_key,
        token,
        uri_style,
        encryption,
        requester_pays,
        tags,
        http,
    })
    .map_err(CliRunError::Storage)?;
    Ok(Box::new(s3))
}

/// Resolve the S3 access-key / secret-key / session-token triple for `key_type`.
///
/// `shared` reads `repo-s3-key` + `repo-s3-key-secret` (the configured static
/// credentials) plus an optional `repo-s3-token`. `web-id` reads the AWS
/// web-identity token file from the standard environment
/// (`AWS_WEB_IDENTITY_TOKEN_FILE`) and passes its contents as the session token
/// — a best-effort wiring of the web-identity flow without a full STS exchange.
/// `auto` falls back to the web-identity path. C ref: `storageS3New`.
fn resolve_s3_credentials(cfg: &LoadedConfig, index: u32, key_type: &str) -> Result<(String, String, Option<String>), CliRunError> {
    match key_type {
        "shared" => {
            let access_key = require_string(cfg, "repo-s3-key", index)?;
            let secret_key = require_string(cfg, "repo-s3-key-secret", index)?;
            let token = string_option(cfg, "repo-s3-token", index);
            Ok((access_key, secret_key, token))
        }
        "web-id" | "auto" => {
            // Best-effort web-identity: the AWS SDK convention exposes the OIDC
            // token file via AWS_WEB_IDENTITY_TOKEN_FILE and the role via
            // AWS_ROLE_ARN. Without a full STS AssumeRoleWithWebIdentity exchange
            // we cannot mint signing credentials, so require a clear setup.
            let token_file = std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE").ok();
            match token_file {
                Some(path) => {
                    let token = std::fs::read_to_string(&path)
                        .map_err(|err| CliRunError::StorageConfig(format!("repo-s3-key-type={key_type}: reading {path}: {err}")))?;
                    // The web-identity token is an OIDC JWT, not a SigV4 signing
                    // credential; a full implementation would exchange it via STS.
                    // Surface the limitation clearly rather than signing wrongly.
                    let _ = token;
                    Err(CliRunError::NotSupportedYet(format!(
                        "repo-s3-key-type={key_type}: web-identity token file {path} was found, but the STS \
                         AssumeRoleWithWebIdentity exchange that turns it into signing credentials is not \
                         implemented yet; use repo-s3-key-type=shared with static credentials for now"
                    )))
                }
                None => Err(CliRunError::StorageConfig(format!(
                    "repo-s3-key-type={key_type} requires the AWS_WEB_IDENTITY_TOKEN_FILE environment variable \
                     (web-identity credentials); set it or use repo-s3-key-type=shared"
                ))),
            }
        }
        other => Err(CliRunError::StorageConfig(format!(
            "unrecognised repo-s3-key-type `{other}` (expected shared, web-id, or auto)"
        ))),
    }
}

/// Resolve the S3 server-side-encryption settings from `repo-s3-kms-key-id` and
/// `repo-s3-sse-customer-key`. KMS takes precedence when both are set (they are
/// mutually exclusive in practice; pgBackRest disallows configuring both).
fn s3_encryption_from(cfg: &LoadedConfig, index: u32) -> S3Encryption {
    if let Some(kms) = string_option(cfg, "repo-s3-kms-key-id", index) {
        return S3Encryption::Kms(kms);
    }
    string_option(cfg, "repo-s3-sse-customer-key", index).map_or(S3Encryption::None, S3Encryption::CustomerKey)
}

/// Build the [`Azure`] backend from the `repo-azure-*` options at repository
/// index `index`.
fn build_azure(cfg: &LoadedConfig, index: u32) -> Result<Box<dyn Storage>, CliRunError> {
    let account = require_string(cfg, "repo-azure-account", index)?;
    let container = require_string(cfg, "repo-azure-container", index)?;
    let key = require_string(cfg, "repo-azure-key", index)?;
    // `repo-azure-key-type` (default `shared`) selects SharedKey vs SAS auth.
    let key_type = string_option(cfg, "repo-azure-key-type", index).unwrap_or_else(|| "shared".to_owned());
    let (account_key_base64, sas_token) = match key_type.as_str() {
        "shared" => (Some(key), None),
        "sas" => (None, Some(key)),
        other => {
            return Err(CliRunError::StorageConfig(format!(
                "repo-azure-key-type=`{other}` is not supported by the binary yet (expected shared or sas)"
            )));
        }
    };
    // The Azure backend builds the full URL from account + endpoint. An explicit
    // `repo-storage-host` overrides the host entirely; otherwise
    // `repo-azure-endpoint` (default `blob.core.windows.net`) is the DNS suffix
    // and the full host is `<account>.<endpoint>`. `repo-azure-uri-style`
    // (host | path) selects whether the account lives in the hostname (host) or
    // the first path segment (path). C ref: `storageAzureNew`.
    let uri_style = string_option(cfg, "repo-azure-uri-style", index).unwrap_or_else(|| "host".to_owned());
    let endpoint = azure_endpoint(cfg, index, &account, &uri_style)?;

    let http = http_options_from(cfg, index);
    let azure = Azure::new(AzureConfig {
        account,
        container,
        account_key_base64,
        sas_token,
        endpoint,
        tags: hash_option(cfg, "repo-storage-tag", index),
        http,
    })
    .map_err(CliRunError::Storage)?;
    Ok(Box::new(azure))
}

/// Compute the Azure endpoint base URL (including scheme) for the given account
/// and `repo-azure-uri-style`.
///
/// An explicit `repo-storage-host` (with optional `repo-storage-port`) overrides
/// everything. Otherwise the host suffix is `repo-azure-endpoint` (default
/// `blob.core.windows.net`); for host-style the account is prepended to the
/// hostname (`<account>.<suffix>`), and for path-style the bare suffix is used
/// (the backend places the account in the path).
fn azure_endpoint(cfg: &LoadedConfig, index: u32, account: &str, uri_style: &str) -> Result<Option<String>, CliRunError> {
    if let Some(host) = string_option(cfg, "repo-storage-host", index) {
        return Ok(Some(with_scheme(&host_with_optional_port(cfg, &host, index))));
    }
    let suffix = string_option(cfg, "repo-azure-endpoint", index).unwrap_or_else(|| "blob.core.windows.net".to_owned());
    let host = match uri_style {
        "host" => format!("{account}.{suffix}"),
        "path" => suffix,
        other => {
            return Err(CliRunError::StorageConfig(format!(
                "unrecognised repo-azure-uri-style `{other}` (expected host or path)"
            )));
        }
    };
    Ok(Some(with_scheme(&host_with_optional_port(cfg, &host, index))))
}

/// Build the [`Gcs`] backend from the `repo-gcs-*` options at repository index
/// `index`.
fn build_gcs(cfg: &LoadedConfig, index: u32) -> Result<Box<dyn Storage>, CliRunError> {
    let bucket = require_string(cfg, "repo-gcs-bucket", index)?;
    let key = require_string(cfg, "repo-gcs-key", index)?;
    let key_type = string_option(cfg, "repo-gcs-key-type", index).unwrap_or_else(|| "service".to_owned());
    let auth = match key_type.as_str() {
        // `token` auth: the key value is a pre-acquired OAuth2 bearer token.
        "token" => GcsAuth::Token(key),
        // `service` auth: `repo-gcs-key` is the path to the service-account JSON
        // key file; parse it into client_email / private_key / token_uri and let
        // the backend perform the JWT -> access-token exchange.
        "service" => gcs_service_account_auth(&key)?,
        // `auto` discovers a GCE instance credential — best-effort: not wired,
        // so error clearly rather than silently using the wrong auth.
        "auto" => {
            return Err(CliRunError::NotSupportedYet(
                "repo-gcs-key-type=auto: GCE instance-metadata credential discovery is not implemented yet; \
                 use repo-gcs-key-type=service (a service-account key file) or token (a bearer token)"
                    .to_owned(),
            ));
        }
        other => {
            return Err(CliRunError::StorageConfig(format!(
                "unrecognised repo-gcs-key-type `{other}` (expected service, token, or auto)"
            )));
        }
    };

    // An explicit `repo-storage-host` overrides the endpoint; otherwise
    // `repo-gcs-endpoint` (default `storage.googleapis.com`) is the host.
    let raw_host = string_option(cfg, "repo-storage-host", index).or_else(|| string_option(cfg, "repo-gcs-endpoint", index));
    let endpoint = raw_host.map(|h| with_scheme(&host_with_optional_port(cfg, &h, index)));

    let user_project = string_option(cfg, "repo-gcs-user-project", index);
    let http = http_options_from(cfg, index);

    let gcs = Gcs::new(GcsConfig {
        bucket,
        endpoint,
        auth,
        user_project,
        tags: hash_option(cfg, "repo-storage-tag", index),
        http,
    })
    .map_err(CliRunError::Storage)?;
    Ok(Box::new(gcs))
}

/// Load and parse a GCS service-account JSON key file at `path` into a
/// [`GcsAuth::ServiceAccount`].
///
/// The standard Google service-account key JSON carries `client_email`,
/// `private_key` (an RS256 PEM) and `token_uri`; these become the JWT `iss`,
/// signing key and audience / POST target respectively. C ref:
/// `storageGcsAuthService` reading the `key-file`.
fn gcs_service_account_auth(path: &str) -> Result<GcsAuth, CliRunError> {
    let json = std::fs::read_to_string(path)
        .map_err(|err| CliRunError::StorageConfig(format!("repo-gcs-key-type=service: reading key file {path}: {err}")))?;
    pgbr_storage::gcs::service_account_auth_from_json(&json)
        .map_err(|err| CliRunError::StorageConfig(format!("repo-gcs-key-type=service: parsing key file {path}: {err}")))
}

/// Assemble an [`SftpConfig`] from the resolved `repo-sftp-*` option family.
///
/// pgBackRest's SFTP repository authenticates with a private key
/// (`repo-sftp-private-key-file`, optional `repo-sftp-private-key-passphrase`);
/// `repo-sftp-host` / `repo-sftp-host-user` are required and
/// `repo-sftp-host-port` defaults to 22. The remote root is `repo-path`. Pure
/// and unit-testable (no connection is made here).
///
/// # Errors
///
/// [`CliRunError::StorageConfig`] when a required option is missing or the port
/// is out of range.
fn sftp_config_from(cfg: &LoadedConfig, index: u32) -> Result<SftpConfig, CliRunError> {
    let host = require_string(cfg, "repo-sftp-host", index)?;
    let user = require_string(cfg, "repo-sftp-host-user", index)?;
    let private_key = path_option(cfg, "repo-sftp-private-key-file", index)
        .ok_or_else(|| CliRunError::StorageConfig("repo-type=sftp requires repo-sftp-private-key-file".to_owned()))?;
    let passphrase = string_option(cfg, "repo-sftp-private-key-passphrase", index);
    // Optional public-key file alongside the private key (some libssh2 key
    // formats need the explicit `.pub`); `None` lets ssh2 derive it.
    let public_key = path_option(cfg, "repo-sftp-public-key-file", index);
    let port = match integer_option(cfg, "repo-sftp-host-port", index) {
        None => pgbr_storage::sftp::DEFAULT_PORT,
        Some(n) => u16::try_from(n).map_err(|_| CliRunError::StorageConfig(format!("repo-sftp-host-port out of range: {n}")))?,
    };
    let base_path = path_option(cfg, "repo-path", index).unwrap_or_else(|| PathBuf::from(DEFAULT_REPO_PATH));
    let host_key_check = sftp_host_key_check(cfg, index)?;
    Ok(SftpConfig {
        host,
        port,
        user,
        base_path,
        auth: SftpAuth::KeyFile {
            private_key,
            public_key,
            passphrase,
        },
        host_key_check,
    })
}

/// Resolve the SFTP host-key-verification policy from the `repo-sftp-host-key-*`
/// / `repo-sftp-known-host` options.
///
/// `repo-sftp-host-key-check-type` (default `strict`) selects the mode:
/// `none` disables checking, `fingerprint` pins the server key against
/// `repo-sftp-host-fingerprint` (hashed with `repo-sftp-host-key-hash-type`),
/// and `strict` / `accept-new` validate against the `repo-sftp-known-host`
/// known-hosts files (accept-new appending unknown keys). C ref:
/// `storageSftpNew` host-key handling.
fn sftp_host_key_check(cfg: &LoadedConfig, index: u32) -> Result<HostKeyCheck, CliRunError> {
    // Default is `strict` (matches config.yaml). When set explicitly, honour it.
    let mode = string_option(cfg, "repo-sftp-host-key-check-type", index).unwrap_or_else(|| "strict".to_owned());
    match mode.as_str() {
        "none" => Ok(HostKeyCheck::None),
        "fingerprint" | "strict" if string_option(cfg, "repo-sftp-host-fingerprint", index).is_some() => {
            let fingerprint = require_string(cfg, "repo-sftp-host-fingerprint", index)?;
            let hash_type = match string_option(cfg, "repo-sftp-host-key-hash-type", index) {
                None => HostKeyHashType::Sha256,
                Some(value) => HostKeyHashType::parse(&value).map_err(CliRunError::StorageConfig)?,
            };
            Ok(HostKeyCheck::Fingerprint { fingerprint, hash_type })
        }
        "fingerprint" => Err(CliRunError::StorageConfig(
            "repo-sftp-host-key-check-type=fingerprint requires repo-sftp-host-fingerprint".to_owned(),
        )),
        "strict" | "accept-new" => {
            let accept_new = mode == "accept-new";
            let known_hosts = list_option(cfg, "repo-sftp-known-host", index);
            Ok(HostKeyCheck::KnownHosts {
                known_hosts: known_hosts.into_iter().map(PathBuf::from).collect(),
                accept_new,
            })
        }
        other => Err(CliRunError::StorageConfig(format!(
            "unrecognised repo-sftp-host-key-check-type `{other}` (expected none, fingerprint, strict, or accept-new)"
        ))),
    }
}

/// Build the SFTP repository backend, opening the SSH/SFTP connection.
///
/// # Errors
///
/// [`CliRunError::StorageConfig`] for a malformed `repo-sftp-*` family (via
/// [`sftp_config_from`]) and [`CliRunError::Storage`] when the connection or
/// authentication fails.
fn build_sftp(cfg: &LoadedConfig, index: u32) -> Result<Box<dyn Storage>, CliRunError> {
    let config = sftp_config_from(cfg, index)?;
    let sftp = Sftp::connect(config).map_err(CliRunError::Storage)?;
    Ok(Box::new(sftp))
}

/// Prepend `https://` to `host` when it carries no `http(s)://` scheme,
/// matching the C default of `httpProtocolTypeHttps`.
fn with_scheme(host: &str) -> String {
    if host.starts_with("http://") || host.starts_with("https://") {
        host.to_owned()
    } else {
        format!("https://{host}")
    }
}

/// Read a `string`/`string-id`/`path` option as a [`String`] at group index
/// `index`, falling back to the ungrouped key. Returns `None` when absent or
/// not a string-like value.
///
/// The fallback is to the *ungrouped* key only (legacy non-indexed spellings) —
/// never to a different repository's index, so `repo2-*` never leaks `repo1-*`'s
/// explicit values. Options unset at the active index rely on the caller's
/// documented default instead.
fn string_option(cfg: &LoadedConfig, name: &str, index: u32) -> Option<String> {
    cfg.options
        .get(&(name.to_owned(), Some(index)))
        .or_else(|| cfg.options.get(&(name.to_owned(), None)))
        .and_then(|v| match v {
            OptionValue::String(s) | OptionValue::StringId(s) | OptionValue::Path(s) => Some(s.clone()),
            _ => None,
        })
}

/// Read a `path` option as a [`PathBuf`] at group index `index`.
fn path_option(cfg: &LoadedConfig, name: &str, index: u32) -> Option<PathBuf> {
    string_option(cfg, name, index).map(PathBuf::from)
}

/// Read an `integer` option as an [`i64`] at group index `index`, falling back
/// to the ungrouped key. Returns `None` when absent or not an integer-typed
/// value.
fn integer_option(cfg: &LoadedConfig, name: &str, index: u32) -> Option<i64> {
    cfg.options
        .get(&(name.to_owned(), Some(index)))
        .or_else(|| cfg.options.get(&(name.to_owned(), None)))
        .and_then(|v| match v {
            OptionValue::Integer(i) => Some(*i),
            _ => None,
        })
}

/// Read a required string option at group index `index`, erroring with a clear
/// message when absent.
fn require_string(cfg: &LoadedConfig, name: &str, index: u32) -> Result<String, CliRunError> {
    string_option(cfg, name, index).ok_or_else(|| CliRunError::StorageConfig(format!("required option `{name}` is not set")))
}

/// Read a `boolean` option at group index `index`, falling back to the ungrouped
/// key. Returns `None` when absent or not a boolean-typed value.
fn boolean_option(cfg: &LoadedConfig, name: &str, index: u32) -> Option<bool> {
    cfg.options
        .get(&(name.to_owned(), Some(index)))
        .or_else(|| cfg.options.get(&(name.to_owned(), None)))
        .and_then(|v| match v {
            OptionValue::Boolean(b) => Some(*b),
            _ => None,
        })
}

/// Read a `size` option (bytes) at group index `index`, falling back to the
/// ungrouped key. Returns `None` when absent or not a size-typed value.
fn size_option(cfg: &LoadedConfig, name: &str, index: u32) -> Option<u64> {
    cfg.options
        .get(&(name.to_owned(), Some(index)))
        .or_else(|| cfg.options.get(&(name.to_owned(), None)))
        .and_then(|v| match v {
            OptionValue::Size(s) => Some(*s),
            _ => None,
        })
}

/// Read a `hash` option (key→value map) at group index `index`, falling back to
/// the ungrouped key. Returns an empty map when absent or not a hash value.
fn hash_option(cfg: &LoadedConfig, name: &str, index: u32) -> BTreeMap<String, String> {
    cfg.options
        .get(&(name.to_owned(), Some(index)))
        .or_else(|| cfg.options.get(&(name.to_owned(), None)))
        .and_then(|v| match v {
            OptionValue::Hash(h) => Some(h.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Read a `list` option at group index `index`, falling back to the ungrouped
/// key. A single `string`/`path` value is treated as a one-element list.
/// Returns an empty `Vec` when absent.
fn list_option(cfg: &LoadedConfig, name: &str, index: u32) -> Vec<String> {
    cfg.options
        .get(&(name.to_owned(), Some(index)))
        .or_else(|| cfg.options.get(&(name.to_owned(), None)))
        .map(|v| match v {
            OptionValue::List(items) => items.clone(),
            OptionValue::String(s) | OptionValue::StringId(s) | OptionValue::Path(s) => vec![s.clone()],
            _ => Vec::new(),
        })
        .unwrap_or_default()
}

/// Assemble the shared [`HttpOptions`] from the `repo-storage-*` family at group
/// index `index`: TLS verification (`repo-storage-verify-tls`), custom CA roots
/// (`repo-storage-ca-file` / `-ca-path`), the TLS port (`repo-storage-port`) and
/// the upload-chunk size (`repo-storage-upload-chunk-size`).
///
/// Pure (reads only the resolved config), so it is unit-testable without a live
/// endpoint.
fn http_options_from(cfg: &LoadedConfig, index: u32) -> HttpOptions {
    let verify_tls = boolean_option(cfg, "repo-storage-verify-tls", index).unwrap_or(true);
    let ca_file = path_option(cfg, "repo-storage-ca-file", index);
    let ca_path = path_option(cfg, "repo-storage-ca-path", index);
    let port = integer_option(cfg, "repo-storage-port", index).and_then(|p| u16::try_from(p).ok());
    let upload_chunk_size = size_option(cfg, "repo-storage-upload-chunk-size", index);
    HttpOptions {
        verify_tls,
        ca_file,
        ca_path,
        port,
        upload_chunk_size,
    }
}

/// Append `:<port>` to the bare host `host` when `repo-storage-port` is set to a
/// non-default value (the C driver builds the endpoint URL with the explicit
/// port). The host must not already carry a scheme; pass the raw host.
///
/// 443 — the `repo-storage-port` default for HTTPS — is treated as "no override"
/// so the common case yields a clean `https://host` URL.
fn host_with_optional_port(cfg: &LoadedConfig, host: &str, index: u32) -> String {
    match integer_option(cfg, "repo-storage-port", index) {
        Some(port) if port != 443 && (1..=65535).contains(&port) && !host.contains(':') => {
            format!("{host}:{port}")
        }
        _ => host.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};

    use super::{
        active_repo_index, append_host_config_args, build_all_repo_storages, build_pg_storage, build_repo_storage,
        configured_repo_indexes, sftp_config_from, tls_host_address,
    };
    use crate::CliRunError;
    use pgbr_storage::SftpAuth;

    /// Build a minimal `LoadedConfig` carrying the given grouped/ungrouped
    /// options for the `command`. Options are supplied as
    /// `(name, group_index, value)`.
    fn cfg(command: &str, opts: &[(&str, Option<u32>, OptionValue)]) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        for (name, idx, value) in opts {
            options.insert(((*name).to_owned(), *idx), value.clone());
        }
        LoadedConfig {
            command: command.to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: Some("demo".to_owned()),
            options,
            params: Vec::new(),
        }
    }

    #[test]
    fn build_repo_storage_posix() {
        // A config with repo-path builds a Posix store that behaves like one:
        // round-trip a file through the storage rooted at a tempdir.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = cfg(
            "info",
            &[("repo-path", Some(1), OptionValue::Path(dir.path().display().to_string()))],
        );
        let storage = build_repo_storage(&config).expect("posix repo storage");

        // Write a file via the storage, then confirm it landed under the root.
        {
            use pgbr_io::IoWrite;
            let mut w = storage.open_write(Path::new("hello.txt")).expect("open_write");
            w.write(b"world").expect("write");
            w.close().expect("close");
        }
        let on_disk = std::fs::read(dir.path().join("hello.txt")).expect("read back");
        assert_eq!(on_disk, b"world");
    }

    #[test]
    fn build_repo_storage_defaults_to_posix() {
        // No repo-type → posix; no repo-path → the documented default. We can't
        // round-trip through /var/lib/pgbackrest, so just assert it constructs.
        let config = cfg("info", &[]);
        assert!(build_repo_storage(&config).is_ok());
    }

    #[test]
    fn build_repo_storage_cifs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = cfg(
            "info",
            &[
                ("repo-type", Some(1), OptionValue::StringId("cifs".to_owned())),
                ("repo-path", Some(1), OptionValue::Path(dir.path().display().to_string())),
            ],
        );
        assert!(build_repo_storage(&config).is_ok());
    }

    #[test]
    fn build_repo_storage_s3_ok() {
        let config = cfg(
            "info",
            &[
                ("repo-type", Some(1), OptionValue::StringId("s3".to_owned())),
                ("repo-s3-bucket", Some(1), OptionValue::String("my-bucket".to_owned())),
                ("repo-s3-region", Some(1), OptionValue::String("us-east-1".to_owned())),
                (
                    "repo-s3-endpoint",
                    Some(1),
                    OptionValue::String("s3.us-east-1.amazonaws.com".to_owned()),
                ),
                ("repo-s3-key", Some(1), OptionValue::String("AKIA".to_owned())),
                ("repo-s3-key-secret", Some(1), OptionValue::String("secret".to_owned())),
            ],
        );
        assert!(build_repo_storage(&config).is_ok());
    }

    #[test]
    fn build_repo_storage_s3_missing_bucket_errors() {
        let config = cfg(
            "info",
            &[
                ("repo-type", Some(1), OptionValue::StringId("s3".to_owned())),
                ("repo-s3-region", Some(1), OptionValue::String("us-east-1".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Err(CliRunError::StorageConfig(msg)) => assert!(msg.contains("repo-s3-bucket"), "msg was {msg}"),
            Err(other) => panic!("expected StorageConfig error, got {other:?}"),
            Ok(_) => panic!("expected StorageConfig error, got Ok(storage)"),
        }
    }

    #[test]
    fn build_repo_storage_azure_shared_ok() {
        let config = cfg(
            "info",
            &[
                ("repo-type", Some(1), OptionValue::StringId("azure".to_owned())),
                ("repo-azure-account", Some(1), OptionValue::String("acct".to_owned())),
                ("repo-azure-container", Some(1), OptionValue::String("cont".to_owned())),
                // Valid base64 so Azure::new's SharedKey decode succeeds.
                ("repo-azure-key", Some(1), OptionValue::String("a2V5".to_owned())),
            ],
        );
        assert!(build_repo_storage(&config).is_ok());
    }

    #[test]
    fn build_repo_storage_gcs_token_ok() {
        let config = cfg(
            "info",
            &[
                ("repo-type", Some(1), OptionValue::StringId("gcs".to_owned())),
                ("repo-gcs-bucket", Some(1), OptionValue::String("bkt".to_owned())),
                ("repo-gcs-key-type", Some(1), OptionValue::StringId("token".to_owned())),
                ("repo-gcs-key", Some(1), OptionValue::String("ya29.token".to_owned())),
            ],
        );
        assert!(build_repo_storage(&config).is_ok());
    }

    #[test]
    fn build_repo_storage_unknown_type_errors() {
        let config = cfg("info", &[("repo-type", Some(1), OptionValue::StringId("nfs".to_owned()))]);
        match build_repo_storage(&config) {
            Err(CliRunError::StorageConfig(msg)) => assert!(msg.contains("nfs"), "msg was {msg}"),
            Err(other) => panic!("expected StorageConfig error, got {other:?}"),
            Ok(_) => panic!("expected StorageConfig error, got Ok(storage)"),
        }
    }

    #[test]
    fn remote_host_spawns_worker_not_not_supported() {
        // `repo-host` now spawns an `ssh <host> pgbackrest backup:remote …`
        // worker and proxies storage to it, instead of the old
        // `NotSupportedYet` placeholder. The spawn itself either succeeds (ssh
        // on PATH) and yields a constructed `RemoteProcessStorage`, or fails to
        // launch `ssh` (`Protocol`) when ssh is absent (e.g. the minimal dev
        // image). Either outcome proves the placeholder is gone and the SSH
        // spawn path is wired; what must NOT happen is `NotSupportedYet`.
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("backup.example.com".to_owned())),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Ok(_) | Err(CliRunError::Protocol(_)) => {}
            Err(CliRunError::NotSupportedYet(msg)) => {
                panic!("repo-host must no longer be NotSupportedYet, got: {msg}")
            }
            Err(other) => panic!("expected Ok(storage) or Protocol(spawn) error, got {other:?}"),
        }
    }

    #[test]
    fn build_pg_storage_posix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = cfg(
            "backup",
            &[("pg-path", Some(1), OptionValue::Path(dir.path().display().to_string()))],
        );
        let storage = build_pg_storage(&config).expect("pg storage");
        // Seed a file directly and confirm the storage sees it (root binding).
        std::fs::write(dir.path().join("PG_VERSION"), b"16").expect("seed");
        assert!(storage.exists(Path::new("PG_VERSION")).expect("exists"));
    }

    #[test]
    fn build_pg_storage_missing_path_errors() {
        let config = cfg("backup", &[]);
        match build_pg_storage(&config) {
            Err(CliRunError::StorageConfig(msg)) => assert!(msg.contains("pg-path"), "msg was {msg}"),
            Err(other) => panic!("expected StorageConfig error, got {other:?}"),
            Ok(_) => panic!("expected StorageConfig error, got Ok(storage)"),
        }
    }

    #[test]
    fn pg_host_spawns_worker_not_not_supported() {
        // `pg-host` (with the required `pg-path`) spawns an
        // `ssh <host> pgbackrest backup:remote …` worker rather than returning
        // the old `NotSupportedYet` placeholder. As with the repo case, the
        // spawn either succeeds or fails to launch `ssh` — never
        // `NotSupportedYet`.
        let config = cfg(
            "backup",
            &[
                ("pg-host", Some(1), OptionValue::String("db.example.com".to_owned())),
                (
                    "pg-path",
                    Some(1),
                    OptionValue::Path("/var/lib/postgresql/16/main".to_owned()),
                ),
            ],
        );
        match build_pg_storage(&config) {
            Ok(_) | Err(CliRunError::Protocol(_)) => {}
            Err(CliRunError::NotSupportedYet(msg)) => {
                panic!("pg-host must no longer be NotSupportedYet, got: {msg}")
            }
            Err(other) => panic!("expected Ok(storage) or Protocol(spawn) error, got {other:?}"),
        }
    }

    #[test]
    fn pg_host_without_pg_path_still_requires_path() {
        // Even on the remote path, `pg-path` is required so the worker has a
        // root to serve and the option carries to the remote argv.
        let config = cfg(
            "backup",
            &[("pg-host", Some(1), OptionValue::String("db.example.com".to_owned()))],
        );
        match build_pg_storage(&config) {
            Err(CliRunError::StorageConfig(msg)) => assert!(msg.contains("pg-path"), "msg was {msg}"),
            // `Box<dyn Storage>` is not Debug, so handle Ok without formatting it.
            Ok(_) => panic!("expected StorageConfig(pg-path required), got Ok(storage)"),
            Err(other) => panic!("expected StorageConfig(pg-path required), got {other:?}"),
        }
    }

    #[test]
    fn sftp_config_from_builds_key_auth_with_defaults() {
        let config = cfg(
            "info",
            &[
                ("repo-type", Some(1), OptionValue::StringId("sftp".to_owned())),
                (
                    "repo-sftp-host",
                    Some(1),
                    OptionValue::String("backup.example.com".to_owned()),
                ),
                ("repo-sftp-host-user", Some(1), OptionValue::String("pgbackrest".to_owned())),
                (
                    "repo-sftp-private-key-file",
                    Some(1),
                    OptionValue::Path("/home/pgbackrest/.ssh/id_ed25519".to_owned()),
                ),
                ("repo-path", Some(1), OptionValue::Path("/srv/backups".to_owned())),
            ],
        );
        let sftp = sftp_config_from(&config, 1).expect("sftp config");
        assert_eq!(sftp.host, "backup.example.com");
        assert_eq!(sftp.user, "pgbackrest");
        assert_eq!(sftp.port, 22, "port defaults to 22");
        assert_eq!(sftp.base_path, Path::new("/srv/backups"));
        match sftp.auth {
            SftpAuth::KeyFile {
                private_key,
                public_key,
                passphrase,
            } => {
                assert_eq!(private_key, Path::new("/home/pgbackrest/.ssh/id_ed25519"));
                assert!(public_key.is_none());
                assert!(passphrase.is_none());
            }
            SftpAuth::Password(_) => panic!("expected key-file auth"),
        }
        // The default host-key policy is strict known_hosts.
        assert!(matches!(
            sftp.host_key_check,
            pgbr_storage::sftp::HostKeyCheck::KnownHosts { accept_new: false, .. }
        ));
    }

    #[test]
    fn sftp_config_from_honors_custom_port_and_passphrase() {
        let config = cfg(
            "info",
            &[
                ("repo-sftp-host", Some(1), OptionValue::String("host".to_owned())),
                ("repo-sftp-host-user", Some(1), OptionValue::String("u".to_owned())),
                ("repo-sftp-host-port", Some(1), OptionValue::Integer(2222)),
                ("repo-sftp-private-key-file", Some(1), OptionValue::Path("/k".to_owned())),
                (
                    "repo-sftp-private-key-passphrase",
                    Some(1),
                    OptionValue::String("secret".to_owned()),
                ),
            ],
        );
        let sftp = sftp_config_from(&config, 1).expect("sftp config");
        assert_eq!(sftp.port, 2222);
        match sftp.auth {
            SftpAuth::KeyFile { passphrase, .. } => assert_eq!(passphrase.as_deref(), Some("secret")),
            SftpAuth::Password(_) => panic!("expected key-file auth"),
        }
    }

    #[test]
    fn sftp_config_from_requires_host_user_and_key() {
        // Missing host.
        let c1 = cfg(
            "info",
            &[("repo-sftp-host-user", Some(1), OptionValue::String("u".to_owned()))],
        );
        assert!(matches!(sftp_config_from(&c1, 1), Err(CliRunError::StorageConfig(_))));
        // Missing private key.
        let c2 = cfg(
            "info",
            &[
                ("repo-sftp-host", Some(1), OptionValue::String("h".to_owned())),
                ("repo-sftp-host-user", Some(1), OptionValue::String("u".to_owned())),
            ],
        );
        match sftp_config_from(&c2, 1) {
            Err(CliRunError::StorageConfig(msg)) => assert!(msg.contains("private-key"), "msg was {msg}"),
            other => panic!("expected StorageConfig(private-key), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Multiple repositories (`--repo=N`)
    // -----------------------------------------------------------------------

    /// Write `bytes` to `path` through `storage`, creating parents.
    fn put(storage: &dyn pgbr_storage::Storage, path: &str, bytes: &[u8]) {
        use pgbr_io::IoWrite;
        let p = Path::new(path);
        if let Some(parent) = p.parent() {
            storage.create_path(parent, true).expect("create parent");
        }
        let mut w = storage.open_write(p).expect("open_write");
        w.write(bytes).expect("write");
        w.close().expect("close");
    }

    #[test]
    fn active_repo_index_defaults_to_one() {
        // No `--repo` → index 1.
        let config = cfg("info", &[]);
        assert_eq!(active_repo_index(&config), 1);
    }

    #[test]
    fn active_repo_index_reads_repo_option() {
        // `--repo=2` resolves as an ungrouped integer.
        let config = cfg("info", &[("repo", None, OptionValue::Integer(2))]);
        assert_eq!(active_repo_index(&config), 2);
    }

    #[test]
    fn build_repo_storage_selects_active_repo_root() {
        // repo1-path and repo2-path point at distinct tempdirs; `--repo=2`
        // selects the repo2 root. Round-trip a file and confirm it lands under
        // repo2's directory, not repo1's.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let config = cfg(
            "info",
            &[
                ("repo", None, OptionValue::Integer(2)),
                ("repo-path", Some(1), OptionValue::Path(repo1.path().display().to_string())),
                ("repo-path", Some(2), OptionValue::Path(repo2.path().display().to_string())),
            ],
        );
        let storage = build_repo_storage(&config).expect("active repo storage");
        put(storage.as_ref(), "marker.txt", b"two");

        assert!(
            repo2.path().join("marker.txt").exists(),
            "the file should land under the repo2 root"
        );
        assert!(
            !repo1.path().join("marker.txt").exists(),
            "the file must NOT land under the repo1 root"
        );
    }

    #[test]
    fn build_repo_storage_default_active_is_repo1() {
        // Without `--repo`, the default active repo is 1, so repo1-path is used.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let config = cfg(
            "info",
            &[
                ("repo-path", Some(1), OptionValue::Path(repo1.path().display().to_string())),
                ("repo-path", Some(2), OptionValue::Path(repo2.path().display().to_string())),
            ],
        );
        let storage = build_repo_storage(&config).expect("default repo storage");
        put(storage.as_ref(), "marker.txt", b"one");
        assert!(repo1.path().join("marker.txt").exists(), "default should target repo1");
        assert!(!repo2.path().join("marker.txt").exists(), "default must not target repo2");
    }

    #[test]
    fn build_repo_storage_active_repo_uses_own_type() {
        // repo2-type=s3 with its own repo2-s3-* family must build the S3 backend
        // for the active repo without leaking repo1's posix path.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let config = cfg(
            "info",
            &[
                ("repo", None, OptionValue::Integer(2)),
                ("repo-path", Some(1), OptionValue::Path(repo1.path().display().to_string())),
                ("repo-type", Some(2), OptionValue::StringId("s3".to_owned())),
                ("repo-s3-bucket", Some(2), OptionValue::String("b2".to_owned())),
                ("repo-s3-region", Some(2), OptionValue::String("us-east-1".to_owned())),
                (
                    "repo-s3-endpoint",
                    Some(2),
                    OptionValue::String("s3.us-east-1.amazonaws.com".to_owned()),
                ),
                ("repo-s3-key", Some(2), OptionValue::String("AKIA".to_owned())),
                ("repo-s3-key-secret", Some(2), OptionValue::String("secret".to_owned())),
            ],
        );
        assert!(build_repo_storage(&config).is_ok(), "active repo2=s3 should build");
    }

    #[test]
    fn configured_repo_indexes_defaults_to_one() {
        // No grouped repo option anywhere → the implicit single repo {1}.
        let config = cfg("info", &[]);
        assert_eq!(configured_repo_indexes(&config), vec![1]);
    }

    #[test]
    fn configured_repo_indexes_enumerates_paths() {
        // repo1-path + repo3-path configured → {1, 3}, sorted ascending.
        let config = cfg(
            "archive-push",
            &[
                ("repo-path", Some(1), OptionValue::Path("/a".to_owned())),
                ("repo-path", Some(3), OptionValue::Path("/c".to_owned())),
            ],
        );
        assert_eq!(configured_repo_indexes(&config), vec![1, 3]);
    }

    #[test]
    fn configured_repo_indexes_counts_type_only_repos() {
        // A repo configured only by repoN-type (no explicit path) still counts.
        let config = cfg(
            "archive-push",
            &[("repo-type", Some(2), OptionValue::StringId("posix".to_owned()))],
        );
        assert_eq!(configured_repo_indexes(&config), vec![1, 2]);
    }

    #[test]
    fn configured_repo_indexes_includes_active_repo() {
        // `--repo=4` with no grouped repo option configured → just {4}: the
        // active index is always included (it may rely on defaults), and the
        // implicit index 1 is only a fallback for an otherwise-empty set.
        let config = cfg("info", &[("repo", None, OptionValue::Integer(4))]);
        assert_eq!(configured_repo_indexes(&config), vec![4]);

        // With a grouped repo at index 2 AND `--repo=4`, both count.
        let config2 = cfg(
            "info",
            &[
                ("repo", None, OptionValue::Integer(4)),
                ("repo-path", Some(2), OptionValue::Path("/two".to_owned())),
            ],
        );
        assert_eq!(configured_repo_indexes(&config2), vec![2, 4]);
    }

    #[test]
    fn build_all_repo_storages_one_per_configured_repo() {
        // Two posix repos → two backends, each rooted at its own directory.
        let repo1 = tempfile::tempdir().expect("repo1 tempdir");
        let repo2 = tempfile::tempdir().expect("repo2 tempdir");
        let config = cfg(
            "archive-push",
            &[
                ("repo-path", Some(1), OptionValue::Path(repo1.path().display().to_string())),
                ("repo-path", Some(2), OptionValue::Path(repo2.path().display().to_string())),
            ],
        );
        let storages = build_all_repo_storages(&config).expect("all repo storages");
        assert_eq!(storages.len(), 2, "one backend per configured repo");
        assert_eq!(storages[0].0, 1);
        assert_eq!(storages[1].0, 2);

        // Each backend targets its own root.
        put(storages[0].1.as_ref(), "f1.txt", b"1");
        put(storages[1].1.as_ref(), "f2.txt", b"2");
        assert!(repo1.path().join("f1.txt").exists());
        assert!(repo2.path().join("f2.txt").exists());
        assert!(!repo1.path().join("f2.txt").exists(), "repo1 must not get repo2's file");
        assert!(!repo2.path().join("f1.txt").exists(), "repo2 must not get repo1's file");
    }

    // -----------------------------------------------------------------------
    // host-type=tls / host-type=ssh routing
    // -----------------------------------------------------------------------

    #[test]
    fn tls_host_address_uses_tls_server_port() {
        // No tls-server-port → the default 8432.
        let c = cfg("info", &[]);
        assert_eq!(tls_host_address(&c, "backup.example.com"), "backup.example.com:8432");

        // An explicit tls-server-port is honoured.
        let c2 = cfg("info", &[("tls-server-port", None, OptionValue::Integer(9999))]);
        assert_eq!(tls_host_address(&c2, "backup.example.com"), "backup.example.com:9999");
    }

    #[test]
    fn repo_host_type_tls_routes_to_tls_transport() {
        // `repo-host` + `repo-host-type=tls` must take the TLS transport, not the
        // SSH worker spawn. With no server listening the connect fails — but the
        // failure must come from the TLS path: a `Protocol` connect error (no
        // peer) or a `Command`/`StorageConfig` from a missing/invalid cert
        // option. It must NEVER be `NotSupportedYet`, and (since a CA file is
        // supplied that does not exist) it must surface the TLS-side error rather
        // than spawning ssh.
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("127.0.0.1".to_owned())),
                ("repo-host-type", Some(1), OptionValue::StringId("tls".to_owned())),
                (
                    "repo-host-ca-file",
                    Some(1),
                    OptionValue::String("/no/such/ca.pem".to_owned()),
                ),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            // A bad CA path surfaces as a Command error (PEM read failure) from
            // the TLS client-config builder.
            Err(CliRunError::Command(_) | CliRunError::Protocol(_) | CliRunError::StorageConfig(_)) => {}
            Err(CliRunError::NotSupportedYet(msg)) => panic!("repo-host-type=tls must not be NotSupportedYet: {msg}"),
            Ok(_) => panic!("expected a TLS-transport error (no server listening), got Ok(storage)"),
            Err(other) => panic!("expected TLS-path error, got {other:?}"),
        }
    }

    #[test]
    fn repo_host_type_tls_requires_ca_file() {
        // `repo-host-type=tls` without `repo-host-ca-file` is a configuration
        // error (the client cannot validate the server without a CA).
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("127.0.0.1".to_owned())),
                ("repo-host-type", Some(1), OptionValue::StringId("tls".to_owned())),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Err(CliRunError::StorageConfig(msg)) => assert!(msg.contains("repo-host-ca-file"), "msg was {msg}"),
            Ok(_) => panic!("expected StorageConfig(ca-file required), got Ok(storage)"),
            Err(other) => panic!("expected StorageConfig(ca-file required), got {other:?}"),
        }
    }

    #[test]
    fn pg_host_type_tls_routes_to_tls_transport() {
        // The pg side honours `pg-host-type=tls` symmetrically.
        let config = cfg(
            "backup",
            &[
                ("pg-host", Some(1), OptionValue::String("127.0.0.1".to_owned())),
                ("pg-host-type", Some(1), OptionValue::StringId("tls".to_owned())),
                ("pg-host-ca-file", Some(1), OptionValue::String("/no/such/ca.pem".to_owned())),
                (
                    "pg-path",
                    Some(1),
                    OptionValue::Path("/var/lib/postgresql/16/main".to_owned()),
                ),
            ],
        );
        match build_pg_storage(&config) {
            Err(CliRunError::Command(_) | CliRunError::Protocol(_) | CliRunError::StorageConfig(_)) => {}
            Err(CliRunError::NotSupportedYet(msg)) => panic!("pg-host-type=tls must not be NotSupportedYet: {msg}"),
            Ok(_) => panic!("expected a TLS-transport error (no server listening), got Ok(storage)"),
            Err(other) => panic!("expected TLS-path error, got {other:?}"),
        }
    }

    #[test]
    fn repo_host_type_ssh_still_spawns_worker() {
        // The default `ssh` host-type (explicitly set) keeps the SSH worker
        // spawn path: either Ok (ssh on PATH) or Protocol (ssh absent), never
        // the TLS path's CA-file error nor NotSupportedYet.
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("backup.example.com".to_owned())),
                ("repo-host-type", Some(1), OptionValue::StringId("ssh".to_owned())),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Ok(_) | Err(CliRunError::Protocol(_)) => {}
            // `Box<dyn Storage>` is not Debug, so the Err is formatted only here.
            Err(other) => panic!("expected SSH spawn outcome (Ok or Protocol), got {other:?}"),
        }
    }

    #[test]
    fn repo_host_type_unknown_errors() {
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("h".to_owned())),
                ("repo-host-type", Some(1), OptionValue::StringId("carrier-pigeon".to_owned())),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Err(CliRunError::StorageConfig(msg)) => assert!(msg.contains("carrier-pigeon"), "msg was {msg}"),
            Ok(_) => panic!("expected StorageConfig(unknown host-type), got Ok(storage)"),
            Err(other) => panic!("expected StorageConfig(unknown host-type), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // repo-local / pg-local / remote-type force-local routing
    // -----------------------------------------------------------------------

    #[test]
    fn repo_local_forces_local_posix_despite_repo_host() {
        // `repo-host` is set (which would normally route to the SSH/TLS remote
        // path) but `repo-local=true` forces the local posix backend. We prove
        // it is local by round-tripping a file through the repo-path tempdir —
        // the remote path never touches the local filesystem.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("backup.example.com".to_owned())),
                ("repo-local", Some(1), OptionValue::Boolean(true)),
                ("repo-path", Some(1), OptionValue::Path(repo.path().display().to_string())),
            ],
        );
        let storage = build_repo_storage(&config).expect("repo-local must build a local posix backend");
        put(storage.as_ref(), "local.txt", b"x");
        assert!(
            repo.path().join("local.txt").exists(),
            "repo-local should force a local backend rooted at repo-path"
        );
    }

    #[test]
    fn repo_local_false_still_routes_remote() {
        // With `repo-local=false` (the default) and `repo-host` set, the remote
        // path is taken — proven by the absence of NotSupportedYet and an
        // Ok/Protocol outcome from the SSH spawn (never a local posix build).
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("backup.example.com".to_owned())),
                ("repo-local", Some(1), OptionValue::Boolean(false)),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Ok(_) | Err(CliRunError::Protocol(_)) => {}
            Err(other) => panic!("expected SSH spawn outcome (Ok or Protocol), got {other:?}"),
        }
    }

    #[test]
    fn pg_local_forces_local_posix_despite_pg_host() {
        let pg = tempfile::tempdir().expect("pg tempdir");
        let config = cfg(
            "backup",
            &[
                ("pg-host", Some(1), OptionValue::String("db.example.com".to_owned())),
                ("pg-local", Some(1), OptionValue::Boolean(true)),
                ("pg-path", Some(1), OptionValue::Path(pg.path().display().to_string())),
            ],
        );
        let storage = build_pg_storage(&config).expect("pg-local must build a local posix backend");
        std::fs::write(pg.path().join("PG_VERSION"), b"16").expect("seed");
        assert!(
            storage.exists(Path::new("PG_VERSION")).expect("exists"),
            "pg-local should force a local backend rooted at pg-path"
        );
    }

    #[test]
    fn remote_type_repo_forces_local_repo_backend() {
        // A worker invoked with `--remote-type=repo` treats the repository as
        // local even though `repo-host` is configured.
        let repo = tempfile::tempdir().expect("repo tempdir");
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("backup.example.com".to_owned())),
                ("remote-type", None, OptionValue::StringId("repo".to_owned())),
                ("repo-path", Some(1), OptionValue::Path(repo.path().display().to_string())),
            ],
        );
        let storage = build_repo_storage(&config).expect("remote-type=repo must build a local backend");
        put(storage.as_ref(), "rt.txt", b"y");
        assert!(
            repo.path().join("rt.txt").exists(),
            "remote-type=repo should force a local repo backend"
        );
    }

    // -----------------------------------------------------------------------
    // host-config forwarding to the remote worker argv
    // -----------------------------------------------------------------------

    #[test]
    fn host_config_args_forwards_repo_family() {
        // repo-host-config* options are appended as the matching global worker
        // flags (--config / --config-path / --config-include-path).
        let config = cfg(
            "info",
            &[
                (
                    "repo-host-config",
                    Some(1),
                    OptionValue::Path("/etc/pgbackrest.conf".to_owned()),
                ),
                (
                    "repo-host-config-path",
                    Some(1),
                    OptionValue::Path("/etc/pgbackrest".to_owned()),
                ),
                (
                    "repo-host-config-include-path",
                    Some(1),
                    OptionValue::Path("/etc/pgbackrest/conf.d".to_owned()),
                ),
            ],
        );
        let mut args = Vec::new();
        append_host_config_args(&config, "repo", 1, &mut args);
        assert_eq!(
            args,
            vec![
                "--config=/etc/pgbackrest.conf".to_owned(),
                "--config-path=/etc/pgbackrest".to_owned(),
                "--config-include-path=/etc/pgbackrest/conf.d".to_owned(),
            ]
        );
    }

    #[test]
    fn host_config_args_forwards_pg_family() {
        // The pg side maps symmetrically from pg-host-config*.
        let config = cfg(
            "backup",
            &[
                ("pg-host-config", Some(1), OptionValue::Path("/db/pgbackrest.conf".to_owned())),
                (
                    "pg-host-config-include-path",
                    Some(1),
                    OptionValue::Path("/db/conf.d".to_owned()),
                ),
            ],
        );
        let mut args = Vec::new();
        append_host_config_args(&config, "pg", 1, &mut args);
        // Only the two set options are forwarded; config-path (unset) is absent.
        assert_eq!(
            args,
            vec![
                "--config=/db/pgbackrest.conf".to_owned(),
                "--config-include-path=/db/conf.d".to_owned(),
            ]
        );
    }

    #[test]
    fn host_config_args_absent_when_unset() {
        // No host-config options → nothing appended (the worker keeps its
        // defaults).
        let config = cfg("info", &[]);
        let mut args = vec!["backup:remote".to_owned()];
        append_host_config_args(&config, "repo", 1, &mut args);
        assert_eq!(args, vec!["backup:remote".to_owned()], "nothing should be appended");
    }

    #[test]
    fn host_config_args_respects_active_index() {
        // repo2-host-config is read at index 2 only; index 1 sees nothing.
        let config = cfg(
            "info",
            &[("repo-host-config", Some(2), OptionValue::Path("/two.conf".to_owned()))],
        );
        let mut at_one = Vec::new();
        append_host_config_args(&config, "repo", 1, &mut at_one);
        assert!(at_one.is_empty(), "index 1 must not see repo2's config");

        let mut at_two = Vec::new();
        append_host_config_args(&config, "repo", 2, &mut at_two);
        assert_eq!(at_two, vec!["--config=/two.conf".to_owned()]);
    }

    // -----------------------------------------------------------------------
    // host-ca-path acceptance on the TLS transport
    // -----------------------------------------------------------------------

    #[test]
    fn tls_host_accepts_ca_path_instead_of_ca_file() {
        // `repo-host-type=tls` with only `repo-host-ca-path` (a directory) set
        // must NOT be rejected for a missing ca-file: the ca-path is an accepted
        // CA source. With a nonexistent directory the failure surfaces from the
        // CA-loading / TLS path (Command/Protocol), never the
        // "requires ca-file/ca-path" StorageConfig error.
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("127.0.0.1".to_owned())),
                ("repo-host-type", Some(1), OptionValue::StringId("tls".to_owned())),
                ("repo-host-ca-path", Some(1), OptionValue::Path("/no/such/cadir".to_owned())),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Err(CliRunError::Command(_) | CliRunError::Protocol(_)) => {}
            Err(CliRunError::StorageConfig(msg)) => {
                panic!("ca-path should satisfy the CA requirement, but got StorageConfig: {msg}")
            }
            Ok(_) => panic!("expected a TLS-path error (no server / bad ca dir), got Ok(storage)"),
            Err(other) => panic!("expected Command/Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn tls_host_requires_ca_file_or_ca_path() {
        // Neither ca-file nor ca-path → a clear configuration error naming both.
        let config = cfg(
            "info",
            &[
                ("repo-host", Some(1), OptionValue::String("127.0.0.1".to_owned())),
                ("repo-host-type", Some(1), OptionValue::StringId("tls".to_owned())),
                ("repo-path", Some(1), OptionValue::Path("/var/lib/pgbackrest".to_owned())),
            ],
        );
        match build_repo_storage(&config) {
            Err(CliRunError::StorageConfig(msg)) => {
                assert!(msg.contains("repo-host-ca-file"), "msg was {msg}");
                assert!(msg.contains("repo-host-ca-path"), "msg was {msg}");
            }
            Ok(_) => panic!("expected StorageConfig(ca-file/ca-path required), got Ok(storage)"),
            Err(other) => panic!("expected StorageConfig(ca-file/ca-path required), got {other:?}"),
        }
    }
}
