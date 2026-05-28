//! Stanza-management commands: `stanza-create`, `stanza-delete`,
//! `stanza-upgrade`.
//!
//! C reference: `src/command/stanza/create.c`, `src/command/stanza/delete.c`,
//! `src/command/stanza/upgrade.c`.
//!
//! Unlike the C implementation — which opens a live libpq connection to learn
//! the cluster's identity — this port reads the cluster's system id, PG
//! version, catalog version, and control version straight out of
//! `<pg-path>/global/pg_control` via
//! [`pgbr_postgres::control::read_pg_control_header`]. That keeps
//! `stanza-create` / `stanza-upgrade` testable without a running `PostgreSQL`;
//! the libpq path can replace the control-file read later when remote stanzas
//! need it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pgbr_config::LoadedConfig;
use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup};
use pgbr_postgres::control::{PgControlHeader, decode_pg_control_header, header_version};
use pgbr_storage::{Storage, StorageError};

use crate::CommandError;

/// pgBackRest on-disk info-file format version written by this port.
const BACKREST_FORMAT: u32 = 5;
/// pgBackRest version string stamped into freshly written info files.
const BACKREST_VERSION: &str = "2.58";
/// Path of the control file relative to the PG data directory.
const PG_CONTROL_PATH: &str = "global/pg_control";

/// Cluster identity resolved from `pg_control`, plus the textual PG label.
struct ClusterIdentity {
    header: PgControlHeader,
    version: String,
}

/// What [`create_inner`] wrote, for assertions in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOutcome {
    /// Textual PG major-version label recorded for the new stanza.
    pub db_version: String,
    /// `pg_control.system_identifier` recorded for the new stanza.
    pub db_system_id: u64,
}

/// What [`upgrade_inner`] did, for assertions in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeOutcome {
    /// Whether the recorded cluster identity actually changed.
    pub upgraded: bool,
    /// The active `db-id` after the operation (incremented when upgraded).
    pub new_db_id: u32,
}

fn require_stanza(config: &LoadedConfig) -> Result<&str, CommandError> {
    config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })
}

/// Read `global/pg_control` from the PG data directory and resolve its
/// version label.
fn read_cluster_identity(pg_storage: &dyn Storage) -> Result<ClusterIdentity, CommandError> {
    let mut reader = pg_storage.open_read(Path::new(PG_CONTROL_PATH))?;
    let bytes = reader.read_all()?;
    let header = decode_pg_control_header(&bytes).map_err(|err| CommandError::Other(err.to_string()))?;
    let version = header_version(&header)
        .ok_or_else(|| {
            CommandError::Other(format!(
                "unsupported PG control version {}/{} in {PG_CONTROL_PATH}",
                header.pg_control_version, header.catalog_version_no
            ))
        })?
        .label
        .to_owned();

    Ok(ClusterIdentity { header, version })
}

/// `stanza-create` — initialise on-disk repository state for a stanza.
///
/// Reads the cluster identity from `<pg-path>/global/pg_control`, then writes
/// fresh `archive/<stanza>/archive.info` and `backup/<stanza>/backup.info`
/// seeded with that identity (db-id 1, one history entry).
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Other`] if `pg_control` cannot be read / decoded, its
///   version is unsupported, or the stanza already exists.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for repository write
///   failures.
pub fn create(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    create_inner(stanza, repo_storage, pg_storage)?;
    Ok(())
}

fn create_inner(stanza: &str, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<CreateOutcome, CommandError> {
    let identity = read_cluster_identity(pg_storage)?;

    let archive_info_path = archive_info_path(stanza);
    let backup_info_path = backup_info_path(stanza);

    if repo_storage.exists(&archive_info_path)? || repo_storage.exists(&backup_info_path)? {
        return Err(CommandError::Other("stanza already exists".to_owned()));
    }

    let header = identity.header;
    let mut history = BTreeMap::new();
    history.insert(
        1,
        DbHistoryEntry {
            db_id: header.system_identifier,
            db_version: identity.version.clone(),
        },
    );

    let archive = InfoArchive {
        backrest_format: BACKREST_FORMAT,
        backrest_version: BACKREST_VERSION.to_owned(),
        db_id: 1,
        db_system_id: header.system_identifier,
        db_version: identity.version.clone(),
        history: history.clone(),
    };

    let backup = InfoBackup {
        backrest_format: BACKREST_FORMAT,
        backrest_version: BACKREST_VERSION.to_owned(),
        db_id: 1,
        db_system_id: header.system_identifier,
        db_version: identity.version.clone(),
        db_catalog_version: header.catalog_version_no,
        db_control_version: header.pg_control_version,
        current: BTreeMap::new(),
        history,
    };

    repo_storage.create_path(&PathBuf::from(format!("archive/{stanza}")), true)?;
    repo_storage.create_path(&PathBuf::from(format!("backup/{stanza}")), true)?;

    archive
        .save(repo_storage, &archive_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;
    backup
        .save(repo_storage, &backup_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(CreateOutcome {
        db_version: identity.version,
        db_system_id: header.system_identifier,
    })
}

fn archive_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("archive/{stanza}/archive.info"))
}

fn backup_info_path(stanza: &str) -> PathBuf {
    PathBuf::from(format!("backup/{stanza}/backup.info"))
}

/// `stanza-delete` — wipe an existing stanza's repository state.
///
/// Recursively removes `archive/<stanza>` and `backup/<stanza>` from the
/// repository. Both removals tolerate a missing directory
/// (`error_on_missing = false`) so the command is idempotent.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Storage`] if either removal fails for a reason other
///   than "missing".
pub fn delete(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;

    let archive: PathBuf = format!("archive/{stanza}").into();
    let backup: PathBuf = format!("backup/{stanza}").into();

    remove_subtree(repo_storage, &archive)?;
    remove_subtree(repo_storage, &backup)?;
    Ok(())
}

fn remove_subtree(storage: &dyn Storage, path: &Path) -> Result<(), CommandError> {
    match storage.remove_path(path, true, false) {
        Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// `stanza-upgrade` — record a new PG version after a major-version upgrade.
///
/// Re-reads `<pg-path>/global/pg_control` and compares the cluster's system id
/// and version against what `archive.info` / `backup.info` already record. If
/// either differs, a new history entry is appended (incrementing `db-id`) and
/// the top-level `db-*` fields are bumped to the current cluster. If both
/// match, the command is a no-op.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] if `--stanza` was not supplied.
/// - [`CommandError::Other`] if `pg_control` cannot be read / decoded, its
///   version is unsupported, or the stanza was never initialised.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for repository
///   read/write failures.
pub fn upgrade(config: &LoadedConfig, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let stanza = require_stanza(config)?;
    upgrade_inner(stanza, repo_storage, pg_storage)?;
    Ok(())
}

fn upgrade_inner(stanza: &str, repo_storage: &dyn Storage, pg_storage: &dyn Storage) -> Result<UpgradeOutcome, CommandError> {
    let identity = read_cluster_identity(pg_storage)?;

    let archive_info_path = archive_info_path(stanza);
    let backup_info_path = backup_info_path(stanza);

    if !repo_storage.exists(&archive_info_path)? || !repo_storage.exists(&backup_info_path)? {
        return Err(CommandError::Other(
            "stanza not initialized; run stanza-create first".to_owned(),
        ));
    }

    let mut archive = InfoArchive::load(repo_storage, &archive_info_path).map_err(|err| CommandError::Other(err.to_string()))?;
    let mut backup = InfoBackup::load(repo_storage, &backup_info_path).map_err(|err| CommandError::Other(err.to_string()))?;

    let header = identity.header;
    let changed = archive.db_system_id != header.system_identifier || archive.db_version != identity.version;

    if !changed {
        return Ok(UpgradeOutcome {
            upgraded: false,
            new_db_id: archive.db_id,
        });
    }

    // The new db-id is one past the highest history key (which always
    // includes the currently-active id), so it is monotonic even if a prior
    // upgrade left a gap.
    let next_id = archive.history.keys().copied().max().unwrap_or(archive.db_id) + 1;
    let new_entry = DbHistoryEntry {
        db_id: header.system_identifier,
        db_version: identity.version.clone(),
    };

    archive.db_id = next_id;
    archive.db_system_id = header.system_identifier;
    archive.db_version.clone_from(&identity.version);
    archive.history.insert(next_id, new_entry.clone());

    backup.db_id = next_id;
    backup.db_system_id = header.system_identifier;
    backup.db_version = identity.version;
    backup.db_catalog_version = header.catalog_version_no;
    backup.db_control_version = header.pg_control_version;
    backup.history.insert(next_id, new_entry);

    archive
        .save(repo_storage, &archive_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;
    backup
        .save(repo_storage, &backup_info_path)
        .map_err(|err| CommandError::Other(err.to_string()))?;

    Ok(UpgradeOutcome {
        upgraded: true,
        new_db_id: next_id,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pgbr_postgres::version::{SUPPORTED, VersionInterface};
    use pgbr_storage::Posix;

    /// Build a synthetic 16-byte `pg_control` file inside the PG data dir.
    fn write_pg_control(pg: &Posix, system_id: u64, v: &VersionInterface) {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&system_id.to_le_bytes());
        buf[8..12].copy_from_slice(&v.pg_control_version.to_le_bytes());
        buf[12..16].copy_from_slice(&v.catalog_version_no.to_le_bytes());
        pg.create_path(Path::new("global"), true).unwrap();
        let mut w = pg.open_write(Path::new("global/pg_control")).unwrap();
        w.write(&buf).unwrap();
        w.flush().unwrap();
        w.close().unwrap();
    }

    fn posix_pair() -> (tempfile::TempDir, tempfile::TempDir, Posix, Posix) {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let pg = tempfile::tempdir().expect("pg tempdir");
        let repo_storage = Posix::new(repo.path());
        let pg_storage = Posix::new(pg.path());
        (repo, pg, repo_storage, pg_storage)
    }

    fn config_with_stanza(stanza: Option<&str>) -> LoadedConfig {
        LoadedConfig {
            command: "stanza-create".to_owned(),
            command_role: pgbr_config::ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options: BTreeMap::new(),
            params: Vec::new(),
        }
    }

    #[test]
    fn stanza_create_writes_info_files_from_pg_control() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let v = &SUPPORTED[0];
        let system_id: u64 = 0x0102_0304_0506_0708;
        write_pg_control(&pg_s, system_id, v);

        let cfg = config_with_stanza(Some("demo"));
        create(&cfg, &repo_s, &pg_s).expect("stanza-create should succeed");

        let archive = InfoArchive::load(&repo_s, &archive_info_path("demo")).expect("load archive.info");
        assert_eq!(archive.db_system_id, system_id);
        assert_eq!(archive.db_version, v.label);
        assert_eq!(archive.db_id, 1);
        assert_eq!(archive.history.len(), 1);
        assert_eq!(archive.history[&1].db_id, system_id);

        let backup = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("load backup.info");
        assert_eq!(backup.db_system_id, system_id);
        assert_eq!(backup.db_version, v.label);
        assert_eq!(backup.db_catalog_version, v.catalog_version_no);
        assert_eq!(backup.db_control_version, v.pg_control_version);
        assert!(backup.current.is_empty());
    }

    #[test]
    fn stanza_create_missing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 1, &SUPPORTED[0]);

        let cfg = config_with_stanza(None);
        let err = create(&cfg, &repo_s, &pg_s).expect_err("stanza-create requires a stanza");
        match err {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn stanza_create_existing_stanza_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 42, &SUPPORTED[0]);

        let cfg = config_with_stanza(Some("demo"));
        create(&cfg, &repo_s, &pg_s).expect("first create succeeds");

        let err = create(&cfg, &repo_s, &pg_s).expect_err("second create must fail");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "stanza already exists"),
            other => panic!("expected Other(stanza already exists), got {other:?}"),
        }
    }

    #[test]
    fn stanza_upgrade_no_change_is_noop() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 7, &SUPPORTED[0]);

        let outcome = create_inner("demo", &repo_s, &pg_s).expect("create");
        assert_eq!(outcome.db_version, SUPPORTED[0].label);

        let outcome = upgrade_inner("demo", &repo_s, &pg_s).expect("upgrade noop");
        assert!(!outcome.upgraded, "same pg_control must be a no-op");
        assert_eq!(outcome.new_db_id, 1);
    }

    #[test]
    fn stanza_upgrade_appends_history_on_version_change() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        let system_id: u64 = 99;
        write_pg_control(&pg_s, system_id, &SUPPORTED[0]);

        create_inner("demo", &repo_s, &pg_s).expect("create");

        // Same cluster (system id), but a different PG major version.
        write_pg_control(&pg_s, system_id, &SUPPORTED[1]);
        let outcome = upgrade_inner("demo", &repo_s, &pg_s).expect("upgrade");
        assert!(outcome.upgraded, "version change must upgrade");
        assert_eq!(outcome.new_db_id, 2);

        let archive = InfoArchive::load(&repo_s, &archive_info_path("demo")).expect("load archive.info");
        assert_eq!(archive.db_id, 2);
        assert_eq!(archive.db_version, SUPPORTED[1].label);
        assert_eq!(archive.history.len(), 2);
        assert_eq!(archive.history[&1].db_version, SUPPORTED[0].label);
        assert_eq!(archive.history[&2].db_version, SUPPORTED[1].label);

        let backup = InfoBackup::load(&repo_s, &backup_info_path("demo")).expect("load backup.info");
        assert_eq!(backup.db_id, 2);
        assert_eq!(backup.db_catalog_version, SUPPORTED[1].catalog_version_no);
        assert_eq!(backup.db_control_version, SUPPORTED[1].pg_control_version);
    }

    #[test]
    fn stanza_upgrade_uninitialized_errors() {
        let (_repo, _pg, repo_s, pg_s) = posix_pair();
        write_pg_control(&pg_s, 1, &SUPPORTED[0]);

        let err = upgrade_inner("demo", &repo_s, &pg_s).expect_err("uninitialized stanza must error");
        match err {
            CommandError::Other(msg) => assert_eq!(msg, "stanza not initialized; run stanza-create first"),
            other => panic!("expected Other(not initialized), got {other:?}"),
        }
    }
}
