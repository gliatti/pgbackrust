//! `manifest` command — dump a backup's `backup.manifest` contents.
//!
//! C reference: `src/command/manifest/manifest.c`. Loads the per-backup
//! inventory at `backup/<stanza>/<label>/backup.manifest` and prints the
//! backup's metadata plus every file, path, and symlink it captured.
//!
//! The C command iterates over every configured repo and can emit either a
//! human-readable dump or a JSON document; this initial Rust port acts on the
//! single repository `Storage` it is handed (the dispatcher selects the repo)
//! and renders the human-readable form. The `--set` option names the target
//! backup label.

use std::path::PathBuf;

use pgbr_config::{LoadedConfig, OptionValue};
use pgbr_info::{InfoError, Manifest};
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;

/// Require `--stanza`.
fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

/// Pull the `--set` backup label out of the resolved configuration.
fn require_set(config: &LoadedConfig) -> Result<&str, CommandError> {
    match config.options.get(&("set".to_owned(), None)) {
        Some(OptionValue::String(label)) => Ok(label.as_str()),
        _ => Err(CommandError::MissingOption {
            option: "set".to_owned(),
        }),
    }
}

/// Repository-relative path to a backup's manifest.
fn manifest_path(stanza: &str, label: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/{label}/backup.manifest"))
}

/// Core load pass. Returns the parsed [`Manifest`] so tests can assert on its
/// structure; the thin [`manifest`] entry point prints it.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` or `--set` was not supplied.
/// - [`CommandError::Other`] if the manifest for the named backup does not
///   exist in the repository.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for other backend
///   failures, and [`CommandError::Other`] for a malformed manifest.
pub fn manifest_inner(config: &LoadedConfig, repo: &dyn Storage) -> Result<Manifest, CommandError> {
    let stanza = require_stanza(config)?;
    let label = require_set(config)?.to_owned();

    let path = manifest_path(stanza, &label);
    Manifest::load(repo, &path).map_err(|err| match err {
        InfoError::Storage(StorageError::NotFound { .. }) => {
            CommandError::Other(format!("manifest for backup '{label}' not found"))
        }
        InfoError::Storage(storage_err) => CommandError::Storage(storage_err),
        other => CommandError::Other(other.to_string()),
    })
}

/// `manifest` — print a backup's metadata and its file / path / link inventory.
///
/// # Errors
///
/// Surfaces whatever [`manifest_inner`] returns; see its docs.
// CLI command: writing the manifest dump to stdout is the whole point.
#[allow(clippy::print_stdout)]
pub fn manifest(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let manifest = manifest_inner(config, repo_storage)?;

    println!("backup label: {}", manifest.backup_label);
    println!("backup type: {}", manifest.backup_type);
    println!("db version: {}", manifest.db_version);
    println!("db system-id: {}", manifest.db_system_id);
    println!("timestamp start: {}", manifest.timestamp_start);
    println!("timestamp stop: {}", manifest.timestamp_stop);
    println!("total size: {}", manifest.total_size());

    println!("files:");
    for file in &manifest.files {
        let checksum = file.checksum.as_deref().unwrap_or("-");
        println!("    {}  {}  {}", file.path, file.size, checksum);
    }

    println!("paths:");
    for path in &manifest.paths {
        println!("    {}", path.path);
    }

    println!("links:");
    for link in &manifest.links {
        println!("    {} -> {}", link.path, link.destination);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
    use pgbr_info::{Manifest, ManifestFile, ManifestLink, ManifestPath};
    use pgbr_storage::{Posix, Storage};

    use super::{CommandError, manifest_inner};

    fn fake_config(stanza: Option<&str>, set: Option<&str>) -> LoadedConfig {
        let mut options: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
        if let Some(s) = set {
            options.insert(("set".to_owned(), None), OptionValue::String(s.to_owned()));
        }
        LoadedConfig {
            command: "manifest".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options,
            params: Vec::new(),
        }
    }

    fn sample_manifest(label: &str) -> Manifest {
        Manifest {
            backup_label: label.to_owned(),
            backup_type: "full".to_owned(),
            timestamp_start: 1_704_110_400,
            timestamp_stop: 1_704_110_410,
            db_version: "14".to_owned(),
            db_system_id: 6_873_049_345_984_568_091,
            files: vec![
                ManifestFile {
                    path: "pg_data/PG_VERSION".to_owned(),
                    size: 3,
                    timestamp: 1_704_110_400,
                    checksum: Some("e1f2c3d4".to_owned()),
                    checksum_page: None,
                },
                ManifestFile {
                    path: "pg_data/base/1/1259".to_owned(),
                    size: 8192,
                    timestamp: 1_704_110_400,
                    checksum: Some("a0b1c2d3".to_owned()),
                    checksum_page: Some(true),
                },
            ],
            paths: vec![ManifestPath {
                path: "pg_data".to_owned(),
            }],
            links: vec![ManifestLink {
                path: "pg_data/pg_wal".to_owned(),
                destination: "/var/lib/pg_wal".to_owned(),
            }],
        }
    }

    /// Persist `manifest` under `backup/<stanza>/<label>/backup.manifest`.
    fn seed_manifest(repo: &Posix, stanza: &str, manifest: &Manifest) {
        let dir = format!("backup/{stanza}/{}", manifest.backup_label);
        repo.create_path(Path::new(&dir), true).expect("create backup dir");
        manifest
            .save(repo, Path::new(&format!("{dir}/backup.manifest")))
            .expect("save backup.manifest");
    }

    #[test]
    fn manifest_missing_stanza_errors() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());

        let cfg = fake_config(None, Some("20240101-120000F"));
        let err = manifest_inner(&cfg, &repo).expect_err("missing stanza must fail");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn manifest_missing_set_errors() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());

        let cfg = fake_config(Some("demo"), None);
        let err = manifest_inner(&cfg, &repo).expect_err("missing --set must fail");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "set"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn manifest_unknown_backup_errors() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());

        // No manifest on disk for this label.
        let cfg = fake_config(Some("demo"), Some("20991231-235959F"));
        let err = manifest_inner(&cfg, &repo).expect_err("unknown backup must fail");
        match err {
            CommandError::Other(msg) => assert!(msg.contains("not found"), "got: {msg}"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn manifest_loads_and_returns_files() {
        let repo_dir = tempfile::tempdir().expect("repo tempdir");
        let repo = Posix::new(repo_dir.path());

        let label = "20240101-120000F";
        seed_manifest(&repo, "demo", &sample_manifest(label));

        let cfg = fake_config(Some("demo"), Some(label));
        let loaded = manifest_inner(&cfg, &repo).expect("manifest_inner should succeed");

        assert_eq!(loaded.backup_label, label);
        assert_eq!(loaded.files.len(), 2);
        assert!(
            loaded.file("pg_data/PG_VERSION").is_some(),
            "expected pg_data/PG_VERSION among {:?}",
            loaded.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }
}
