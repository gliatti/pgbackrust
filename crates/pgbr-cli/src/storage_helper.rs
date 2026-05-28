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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_protocol::PGBACKREST_PROGRAM;
use pgbr_storage::{Azure, AzureConfig, Cifs, Gcs, GcsAuth, GcsConfig, Posix, S3, S3Config, Sftp, SftpAuth, SftpConfig, Storage};

use crate::CliRunError;
use crate::remote_storage::RemoteProcessStorage;

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
    if let Some(host) = string_option(cfg, "repo-host", index) {
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

    if let Some(host) = string_option(cfg, "pg-host", PG_INDEX) {
        return build_remote_host_storage(cfg, &host, "pg", "pg1-path", &root, PG_INDEX);
    }

    Ok(Box::new(Posix::new(root)))
}

/// Spawn a `pgbackrest` worker on `host` over SSH and wrap it in a
/// [`RemoteProcessStorage`] proxy.
///
/// `family` is `"repo"` or `"pg"`, selecting which `*-host-{user,port,cmd}`
/// option family supplies the SSH user / port and the remote `pgbackrest`
/// program path. The worker is invoked as
/// `<host-cmd> <command>:remote --stanza=<s> --<path_flag>=<remote_path>`, so it
/// roots at `remote_path` and serves the storage protocol on its stdio. Mirrors
/// the C `protocolRemoteParam` / `storageRemoteNew` in `src/protocol/helper.c`.
///
/// # Errors
///
/// Returns [`CliRunError::Protocol`] if the `ssh` process cannot be spawned.
fn build_remote_host_storage(
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

    let storage = RemoteProcessStorage::spawn_ssh(host, ssh_port, ssh_user.as_deref(), &remote_program, &remote_args)
        .map_err(CliRunError::Protocol)?;
    Ok(Box::new(storage))
}

/// Build the [`S3`] backend from the `repo-s3-*` / `repo-storage-*` options at
/// repository index `index`.
fn build_s3(cfg: &LoadedConfig, index: u32) -> Result<Box<dyn Storage>, CliRunError> {
    let bucket = require_string(cfg, "repo-s3-bucket", index)?;
    let region = require_string(cfg, "repo-s3-region", index)?;
    let access_key = require_string(cfg, "repo-s3-key", index)?;
    let secret_key = require_string(cfg, "repo-s3-key-secret", index)?;
    let token = string_option(cfg, "repo-s3-token", index);

    // `repo-s3-endpoint` is a bare host (e.g. `s3.us-east-1.amazonaws.com`);
    // `repo-storage-host` overrides it when present. The S3 backend wants a
    // full URL with scheme, so prepend `https://` when the value is scheme-less
    // (matching the C `defaultType = httpProtocolTypeHttps`).
    let host = string_option(cfg, "repo-storage-host", index)
        .or_else(|| string_option(cfg, "repo-s3-endpoint", index))
        .ok_or_else(|| CliRunError::StorageConfig("repo-type=s3 requires repo-s3-endpoint (or repo-storage-host)".to_owned()))?;

    Ok(Box::new(S3::new(S3Config {
        endpoint: with_scheme(&host),
        region,
        bucket,
        access_key,
        secret_key,
        token,
    })))
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
    // `repo-azure-endpoint` is a bare suffix (default `blob.core.windows.net`);
    // the Azure backend builds the full URL from account + endpoint, so pass a
    // full URL only when an explicit storage host overrides it.
    let endpoint = string_option(cfg, "repo-storage-host", index).map(|h| with_scheme(&h));

    let azure = Azure::new(AzureConfig {
        account,
        container,
        account_key_base64,
        sas_token,
        endpoint,
    })
    .map_err(CliRunError::Storage)?;
    Ok(Box::new(azure))
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
        // `service` auth needs the parsed service-account JSON (client_email,
        // private_key, token_uri). Loading + parsing that key file is a
        // follow-up; for now the token path is the wired option.
        "service" => {
            return Err(CliRunError::NotSupportedYet(
                "repo-gcs-key-type=service: service-account key-file parsing is not wired into the binary yet \
                 (pgbr-storage::Gcs supports it via GcsAuth::ServiceAccount, but loading the key JSON is a follow-up); \
                 use repo-gcs-key-type=token for now"
                    .to_owned(),
            ));
        }
        other => {
            return Err(CliRunError::StorageConfig(format!(
                "repo-gcs-key-type=`{other}` is not supported by the binary yet (expected token or service)"
            )));
        }
    };
    let endpoint = string_option(cfg, "repo-storage-host", index).map(|h| with_scheme(&h));

    Ok(Box::new(Gcs::new(GcsConfig { bucket, endpoint, auth })))
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
    let port = match integer_option(cfg, "repo-sftp-host-port", index) {
        None => pgbr_storage::sftp::DEFAULT_PORT,
        Some(n) => u16::try_from(n).map_err(|_| CliRunError::StorageConfig(format!("repo-sftp-host-port out of range: {n}")))?,
    };
    let base_path = path_option(cfg, "repo-path", index).unwrap_or_else(|| PathBuf::from(DEFAULT_REPO_PATH));
    Ok(SftpConfig {
        host,
        port,
        user,
        base_path,
        auth: SftpAuth::KeyFile { private_key, passphrase },
    })
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};

    use super::{
        active_repo_index, build_all_repo_storages, build_pg_storage, build_repo_storage, configured_repo_indexes, sftp_config_from,
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
            SftpAuth::KeyFile { private_key, passphrase } => {
                assert_eq!(private_key, Path::new("/home/pgbackrest/.ssh/id_ed25519"));
                assert!(passphrase.is_none());
            }
            SftpAuth::Password(_) => panic!("expected key-file auth"),
        }
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
}
