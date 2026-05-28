//! Construct the repo + pg [`Storage`] backends from a resolved
//! [`LoadedConfig`], mirroring the C `storageRepoGet` / `storagePgGet` routing
//! in `src/storage/helper.c`.
//!
//! Routing (per the C reference):
//!
//! - If `repo-host` (resp. `pg-host`) is set the storage is *remote* — driven
//!   over an SSH tunnel by the protocol layer. That spawn wiring is not yet
//!   ported into the binary, so we return [`CliRunError::NotSupportedYet`] with
//!   an honest message rather than silently falling back to local posix.
//! - Otherwise the repo backend is selected by `repo-type` (default `posix`):
//!   `posix`/`cifs` are filesystem-rooted at `repo-path`; `s3`/`azure`/`gcs`
//!   are built from their `repo-*` option families. The pg backend is always a
//!   posix store rooted at `pg-path`.
//!
//! Group options resolve at index 1 (`repo1-type`, `repo1-path`, `pg1-path`,
//! …) with a fallback to the ungrouped key, matching how the rest of the
//! binary reads grouped options.

use std::path::PathBuf;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_storage::{Azure, AzureConfig, Cifs, Gcs, GcsAuth, GcsConfig, Posix, S3, S3Config, Storage};

use crate::CliRunError;

/// Default `repo-path` when the option is absent (matches `config.yaml`'s
/// `repo-path` default).
const DEFAULT_REPO_PATH: &str = "/var/lib/pgbackrest";

/// Default `repo-type` (matches `config.yaml`'s `repo-type` default).
const DEFAULT_REPO_TYPE: &str = "posix";

/// Build the repository [`Storage`] backend from the resolved config.
///
/// Selects the backend from `repo-type` (default `posix`) and constructs it
/// from the matching `repo-*` option family. Remote (`repo-host`) is reported
/// as [`CliRunError::NotSupportedYet`].
///
/// # Errors
///
/// Returns [`CliRunError::NotSupportedYet`] when `repo-host` is set (inter-host
/// SSH is not wired into the binary yet), [`CliRunError::StorageConfig`] when a
/// required cloud option is missing or `repo-type` is unrecognised, and
/// [`CliRunError::Storage`] when a backend constructor itself rejects the
/// config.
pub fn build_repo_storage(cfg: &LoadedConfig) -> Result<Box<dyn Storage>, CliRunError> {
    // Inter-host operation: repo lives behind an SSH tunnel. The protocol /
    // remote-storage building blocks exist (pgbr_storage::remote,
    // pgbr_protocol) but the spawn wiring is a follow-up — be honest about it.
    if let Some(host) = string_option(cfg, "repo-host") {
        return Err(CliRunError::NotSupportedYet(format!(
            "repo-host={host}: inter-host SSH operation is not wired into the binary yet \
             (the remote building blocks exist in pgbr-storage::remote / pgbr-protocol, \
             but the SSH spawn wiring is a follow-up)"
        )));
    }

    let repo_type = string_option(cfg, "repo-type").unwrap_or_else(|| DEFAULT_REPO_TYPE.to_owned());

    match repo_type.as_str() {
        "posix" => {
            let root = path_option(cfg, "repo-path").unwrap_or_else(|| PathBuf::from(DEFAULT_REPO_PATH));
            Ok(Box::new(Posix::new(root)))
        }
        "cifs" => {
            let root = path_option(cfg, "repo-path").unwrap_or_else(|| PathBuf::from(DEFAULT_REPO_PATH));
            Ok(Box::new(Cifs::new(root)))
        }
        "s3" => build_s3(cfg),
        "azure" => build_azure(cfg),
        "gcs" => build_gcs(cfg),
        "sftp" => Err(CliRunError::NotSupportedYet(
            "repo-type=sftp: SFTP repository storage is not wired into the binary yet \
             (the pgbr-storage::Sftp backend exists, but selecting it from config is a follow-up)"
                .to_owned(),
        )),
        other => Err(CliRunError::StorageConfig(format!(
            "unrecognised repo-type `{other}` (expected one of posix, cifs, s3, azure, gcs, sftp)"
        ))),
    }
}

/// Build the `PostgreSQL` data-directory [`Storage`] backend from the resolved
/// config: a [`Posix`] store rooted at `pg-path`.
///
/// # Errors
///
/// Returns [`CliRunError::NotSupportedYet`] when `pg-host` is set (inter-host
/// SSH is not wired into the binary yet) and [`CliRunError::StorageConfig`]
/// when `pg-path` is absent (every PG-touching command requires it; commands
/// that never touch PG storage are routed before this is called).
pub fn build_pg_storage(cfg: &LoadedConfig) -> Result<Box<dyn Storage>, CliRunError> {
    if let Some(host) = string_option(cfg, "pg-host") {
        return Err(CliRunError::NotSupportedYet(format!(
            "pg-host={host}: inter-host SSH operation is not wired into the binary yet \
             (the remote building blocks exist in pgbr-storage::remote / pgbr-protocol, \
             but the SSH spawn wiring is a follow-up)"
        )));
    }

    let root = path_option(cfg, "pg-path")
        .ok_or_else(|| CliRunError::StorageConfig("pg-path is required to build PG storage but is not set".to_owned()))?;
    Ok(Box::new(Posix::new(root)))
}

/// Build the [`S3`] backend from the `repo-s3-*` / `repo-storage-*` options.
fn build_s3(cfg: &LoadedConfig) -> Result<Box<dyn Storage>, CliRunError> {
    let bucket = require_string(cfg, "repo-s3-bucket")?;
    let region = require_string(cfg, "repo-s3-region")?;
    let access_key = require_string(cfg, "repo-s3-key")?;
    let secret_key = require_string(cfg, "repo-s3-key-secret")?;
    let token = string_option(cfg, "repo-s3-token");

    // `repo-s3-endpoint` is a bare host (e.g. `s3.us-east-1.amazonaws.com`);
    // `repo-storage-host` overrides it when present. The S3 backend wants a
    // full URL with scheme, so prepend `https://` when the value is scheme-less
    // (matching the C `defaultType = httpProtocolTypeHttps`).
    let host = string_option(cfg, "repo-storage-host")
        .or_else(|| string_option(cfg, "repo-s3-endpoint"))
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

/// Build the [`Azure`] backend from the `repo-azure-*` options.
fn build_azure(cfg: &LoadedConfig) -> Result<Box<dyn Storage>, CliRunError> {
    let account = require_string(cfg, "repo-azure-account")?;
    let container = require_string(cfg, "repo-azure-container")?;
    let key = require_string(cfg, "repo-azure-key")?;
    // `repo-azure-key-type` (default `shared`) selects SharedKey vs SAS auth.
    let key_type = string_option(cfg, "repo-azure-key-type").unwrap_or_else(|| "shared".to_owned());
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
    let endpoint = string_option(cfg, "repo-storage-host").map(|h| with_scheme(&h));

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

/// Build the [`Gcs`] backend from the `repo-gcs-*` options.
fn build_gcs(cfg: &LoadedConfig) -> Result<Box<dyn Storage>, CliRunError> {
    let bucket = require_string(cfg, "repo-gcs-bucket")?;
    let key = require_string(cfg, "repo-gcs-key")?;
    let key_type = string_option(cfg, "repo-gcs-key-type").unwrap_or_else(|| "service".to_owned());
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
    let endpoint = string_option(cfg, "repo-storage-host").map(|h| with_scheme(&h));

    Ok(Box::new(Gcs::new(GcsConfig { bucket, endpoint, auth })))
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

/// Read a `string`/`string-id`/`path` option as a [`String`], preferring the
/// group-index-1 entry over the ungrouped one. Returns `None` when absent or
/// not a string-like value.
fn string_option(cfg: &LoadedConfig, name: &str) -> Option<String> {
    cfg.options
        .get(&(name.to_owned(), Some(1)))
        .or_else(|| cfg.options.get(&(name.to_owned(), None)))
        .and_then(|v| match v {
            OptionValue::String(s) | OptionValue::StringId(s) | OptionValue::Path(s) => Some(s.clone()),
            _ => None,
        })
}

/// Read a `path` option as a [`PathBuf`], preferring the group-index-1 entry.
fn path_option(cfg: &LoadedConfig, name: &str) -> Option<PathBuf> {
    string_option(cfg, name).map(PathBuf::from)
}

/// Read a required string option, erroring with a clear message when absent.
fn require_string(cfg: &LoadedConfig, name: &str) -> Result<String, CliRunError> {
    string_option(cfg, name).ok_or_else(|| CliRunError::StorageConfig(format!("required option `{name}` is not set")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};

    use super::{build_pg_storage, build_repo_storage};
    use crate::CliRunError;

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
    fn remote_host_returns_not_supported_yet() {
        let config = cfg(
            "info",
            &[("repo-host", Some(1), OptionValue::String("backup.example.com".to_owned()))],
        );
        match build_repo_storage(&config) {
            Err(CliRunError::NotSupportedYet(msg)) => {
                assert!(msg.contains("repo-host"), "msg was {msg}");
                assert!(msg.contains("SSH"), "msg was {msg}");
            }
            Err(other) => panic!("expected NotSupportedYet, got {other:?}"),
            Ok(_) => panic!("expected NotSupportedYet, got Ok(storage)"),
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
    fn pg_host_returns_not_supported_yet() {
        let config = cfg(
            "backup",
            &[("pg-host", Some(1), OptionValue::String("db.example.com".to_owned()))],
        );
        match build_pg_storage(&config) {
            Err(CliRunError::NotSupportedYet(msg)) => assert!(msg.contains("pg-host"), "msg was {msg}"),
            Err(other) => panic!("expected NotSupportedYet, got {other:?}"),
            Ok(_) => panic!("expected NotSupportedYet, got Ok(storage)"),
        }
    }
}
