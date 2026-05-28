//! `check` command — verify the repository is reachable and the stanza is
//! initialized.
//!
//! C reference: `src/command/check/check.c`. The full C command verifies PG
//! connectivity, that `archive_command` is configured, and performs a live WAL
//! archive round-trip. This Rust slice implements the repo-side checks that do
//! not require a live `PostgreSQL`:
//!
//! 1. A stanza must be configured.
//! 2. The stanza must be initialized — both `archive.info` and `backup.info`
//!    load cleanly.
//! 3. The two info files must agree on the database identity
//!    (`db-system-id` and `db-version`).
//! 4. The repository must be writable — a probe file is written, read back,
//!    compared, and removed.
//!
//! PG connectivity, `archive_command` validation, and the live WAL archive
//! round-trip are deferred until `pgbr-db` is wired into the command layer.

use std::path::PathBuf;

use pgbr_config::LoadedConfig;
use pgbr_info::{InfoArchive, InfoBackup};
use pgbr_io::{IoRead, IoWrite};
use pgbr_storage::Storage;

use crate::CommandError;

/// Outcome of a successful repo + stanza-init verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The stanza that was checked.
    pub stanza: String,
    /// Active cluster's textual major-version label (e.g. `"14"`), taken from
    /// the agreed-upon info files.
    pub db_version: String,
    /// Active cluster's `pg_control.system_identifier`.
    pub db_system_id: u64,
    /// Whether the repository write-probe round trip succeeded.
    pub repo_writable: bool,
}

/// Repo-side `check`: confirm the stanza is initialized, the info files agree,
/// and the repository is writable.
///
/// The PG storage handle is unused in this slice (the PG-connectivity checks
/// are deferred), so it is accepted and ignored.
///
/// # Errors
///
/// - [`CommandError::MissingOption`] when no `--stanza` was supplied.
/// - [`CommandError::Other`] when the stanza is not initialized, the info files
///   disagree on database identity, or the write probe round trip mismatches.
/// - [`CommandError::Storage`] / [`CommandError::Io`] for backend failures
///   during the write probe.
pub fn check_inner(config: &LoadedConfig, repo_storage: &dyn Storage) -> Result<CheckReport, CommandError> {
    let stanza = config.stanza.as_deref().ok_or_else(|| CommandError::MissingOption {
        option: "stanza".to_owned(),
    })?;

    // 2. The stanza must be initialized — both info files must load.
    let archive_path = PathBuf::from(format!("archive/{stanza}/archive.info"));
    let backup_path = PathBuf::from(format!("backup/{stanza}/backup.info"));

    let archive = InfoArchive::load(repo_storage, &archive_path)
        .map_err(|err| CommandError::Other(format!("stanza '{stanza}' is not initialized: archive.info: {err}")))?;
    let backup = InfoBackup::load(repo_storage, &backup_path)
        .map_err(|err| CommandError::Other(format!("stanza '{stanza}' is not initialized: backup.info: {err}")))?;

    // 3. The two info files must agree on the database identity.
    if archive.db_system_id != backup.db_system_id || archive.db_version != backup.db_version {
        return Err(CommandError::Other(
            "archive.info / backup.info disagree on db identity".to_owned(),
        ));
    }

    // 4. The repository must be writable: write -> read-back -> compare -> remove.
    let repo_writable = probe_repo_writable(repo_storage, stanza)?;

    Ok(CheckReport {
        stanza: stanza.to_owned(),
        db_version: backup.db_version,
        db_system_id: backup.db_system_id,
        repo_writable,
    })
}

/// Write a small probe file under `<stanza>/`, read it back, compare, then
/// remove it. Returns `Ok(true)` only when the round trip matched.
fn probe_repo_writable(repo_storage: &dyn Storage, stanza: &str) -> Result<bool, CommandError> {
    let probe_path = PathBuf::from(format!("{stanza}/check-{}", std::process::id()));
    let payload = format!("pgbackrest check probe for stanza '{stanza}'").into_bytes();

    // Ensure the stanza directory exists so the probe write does not fail merely
    // because the repo has only the `archive/<stanza>` and `backup/<stanza>`
    // subtrees but no `<stanza>/` directory of its own. `create_path` is a no-op
    // when the directory already exists.
    repo_storage.create_path(&PathBuf::from(stanza), true)?;

    // Write.
    {
        let mut writer: Box<dyn IoWrite> = repo_storage.open_write(&probe_path)?;
        writer.write(&payload)?;
        writer.flush()?;
        writer.close()?;
    }

    // Read back and compare. Always attempt removal afterwards so a comparison
    // failure does not leak the probe file.
    let read_result: Result<Vec<u8>, CommandError> = (|| {
        let mut reader: Box<dyn IoRead> = repo_storage.open_read(&probe_path)?;
        Ok(reader.read_all()?)
    })();

    let remove_result = repo_storage.remove(&probe_path, true);

    let read_back = read_result?;
    remove_result?;

    if read_back == payload {
        Ok(true)
    } else {
        Err(CommandError::Other(format!(
            "repo write probe for stanza '{stanza}' read back unexpected content"
        )))
    }
}

/// `check` — verify the configured repository is reachable and the stanza is
/// initialized, then print the resulting [`CheckReport`].
///
/// The PG storage handle is accepted for dispatch-signature compatibility but
/// unused until PG connectivity checks are ported.
///
/// # Errors
///
/// Propagates any error from [`check_inner`].
#[allow(clippy::print_stdout)]
pub fn check(config: &LoadedConfig, repo_storage: &dyn Storage, _pg_storage: &dyn Storage) -> Result<(), CommandError> {
    let report = check_inner(config, repo_storage)?;
    println!(
        "stanza '{}' check ok: db-version={} db-system-id={} repo-writable={}",
        report.stanza, report.db_version, report.db_system_id, report.repo_writable
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use pgbr_config::{ConfigCommandRole, LoadedConfig};
    use pgbr_info::{InfoArchive, InfoBackup};
    use pgbr_storage::{Posix, Storage};
    use tempfile::TempDir;

    use super::{CommandError, check_inner};

    fn config_for(stanza: Option<&str>) -> LoadedConfig {
        LoadedConfig {
            command: "check".to_owned(),
            command_role: ConfigCommandRole::Main,
            stanza: stanza.map(str::to_owned),
            options: BTreeMap::new(),
            params: Vec::new(),
        }
    }

    fn archive_info(system_id: u64, version: &str) -> InfoArchive {
        InfoArchive {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: system_id,
            db_version: version.to_owned(),
            history: BTreeMap::new(),
        }
    }

    fn backup_info(system_id: u64, version: &str) -> InfoBackup {
        InfoBackup {
            backrest_format: 5,
            backrest_version: "2.58".to_owned(),
            db_id: 1,
            db_system_id: system_id,
            db_version: version.to_owned(),
            db_catalog_version: 202_209_061,
            db_control_version: 1300,
            current: BTreeMap::new(),
            history: BTreeMap::new(),
        }
    }

    /// Seed both info files for `stanza` with the given (per-file) identity.
    fn seed_stanza(storage: &dyn Storage, stanza: &str, archive: &InfoArchive, backup: &InfoBackup) {
        storage
            .create_path(Path::new(&format!("archive/{stanza}")), true)
            .expect("create archive dir");
        storage
            .create_path(Path::new(&format!("backup/{stanza}")), true)
            .expect("create backup dir");
        archive
            .save(storage, Path::new(&format!("archive/{stanza}/archive.info")))
            .expect("save archive.info");
        backup
            .save(storage, Path::new(&format!("backup/{stanza}/backup.info")))
            .expect("save backup.info");
    }

    fn posix() -> (TempDir, Posix) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let storage = Posix::new(dir.path());
        (dir, storage)
    }

    #[test]
    fn check_requires_stanza() {
        let (_dir, storage) = posix();
        let cfg = config_for(None);
        match check_inner(&cfg, &storage).expect_err("check requires a stanza") {
            CommandError::MissingOption { option } => assert_eq!(option, "stanza"),
            other => panic!("expected MissingOption, got {other:?}"),
        }
    }

    #[test]
    fn check_uninitialized_stanza_fails() {
        let (_dir, storage) = posix();
        let cfg = config_for(Some("demo"));
        match check_inner(&cfg, &storage).expect_err("uninitialized stanza must fail") {
            CommandError::Other(msg) => assert!(msg.contains("not initialized"), "expected 'not initialized' in {msg:?}"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn check_initialized_stanza_passes() {
        let (_dir, storage) = posix();
        let system_id = 6_873_049_345_984_568_091;
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "14"),
            &backup_info(system_id, "14"),
        );

        let cfg = config_for(Some("demo"));
        let report = check_inner(&cfg, &storage).expect("initialized stanza should pass");
        assert_eq!(report.stanza, "demo");
        assert_eq!(report.db_version, "14");
        assert_eq!(report.db_system_id, system_id);
        assert!(report.repo_writable, "repo should be reported writable");
    }

    #[test]
    fn check_mismatched_db_identity_fails() {
        let (_dir, storage) = posix();
        // archive.info and backup.info carry different system ids.
        seed_stanza(&storage, "demo", &archive_info(1111, "14"), &backup_info(2222, "14"));

        let cfg = config_for(Some("demo"));
        match check_inner(&cfg, &storage).expect_err("mismatched identity must fail") {
            CommandError::Other(msg) => assert!(
                msg.contains("disagree on db identity"),
                "expected identity-disagreement message, got {msg:?}"
            ),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn check_probe_file_is_cleaned_up() {
        let (_dir, storage) = posix();
        let system_id = 42;
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "16"),
            &backup_info(system_id, "16"),
        );

        let cfg = config_for(Some("demo"));
        check_inner(&cfg, &storage).expect("check should pass");

        // No `check-*` probe file should survive under the stanza directory.
        let entries = storage.list(Path::new("demo")).unwrap_or_default();
        let leftover: Vec<_> = entries
            .iter()
            .filter_map(|e| e.path.file_name().and_then(|n| n.to_str()))
            .filter(|name| name.starts_with("check-"))
            .collect();
        assert!(leftover.is_empty(), "probe file(s) left behind: {leftover:?}");

        // The probe file itself must be gone.
        let probe = Path::new("demo").join(format!("check-{}", std::process::id()));
        assert!(
            matches!(storage.exists(&probe), Ok(false)),
            "probe file should not exist after check"
        );
    }
}
