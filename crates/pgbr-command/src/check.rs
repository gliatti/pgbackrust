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
//! 5. The WAL archive must be functional — a small test object is written into
//!    the stanza's current archive-id directory
//!    (`archive/<stanza>/<archive-id>/`), read back, byte-compared, and then
//!    removed. This mirrors the repo half of the C `checkArchive` WAL
//!    push+get round trip.
//!
//! PG connectivity and `archive_command` validation (the part of the C
//! `checkArchive` that pushes a WAL segment from a *live* cluster and waits for
//! the async archiver to land it in the repo) are deferred until `pgbr-db` is
//! wired into the command layer. The repo-side round trip implemented here
//! does not require a live `PostgreSQL`.

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
    /// The stanza's current archive-id (`<db-version>-<db-id>`, e.g. `14-1`),
    /// taken from `archive.info`'s active `[db]` block.
    pub archive_id: String,
    /// Whether the WAL-archive round trip succeeded: a test object written into
    /// `archive/<stanza>/<archive-id>/`, read back, byte-compared, and removed.
    pub archive_ok: bool,
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

    // 5. The WAL archive must be functional: write a test object into the
    //    current archive-id directory, read it back, compare, and remove it.
    //    The current archive-id is `<db-version>-<db-id>`, derived from the
    //    active `[db]` block of `archive.info` (mirrors `infoArchiveId` /
    //    `archiveId` in the C tree).
    let archive_id = format!("{}-{}", archive.db_version, archive.db_id);
    let archive_ok = probe_archive_round_trip(repo_storage, stanza, &archive_id)?;

    Ok(CheckReport {
        stanza: stanza.to_owned(),
        db_version: backup.db_version,
        db_system_id: backup.db_system_id,
        repo_writable,
        archive_id,
        archive_ok,
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

/// WAL-archive round trip: write a small test object into the stanza's current
/// archive-id directory, read it back, byte-compare, then remove it. Returns
/// `Ok(true)` only when the round trip matched.
///
/// This is the repo-side half of the C `checkArchive`: rather than asking a
/// live cluster to push a WAL segment and waiting for the async archiver, it
/// directly exercises the repository's `archive/<stanza>/<archive-id>/` subtree
/// — the same path WAL segments land in — to confirm the archive store is
/// readable and writable. The test object is named `<archive-id>.check-<pid>`
/// so it cannot collide with a real WAL segment (which is a hex name) and is
/// cleaned up even on read/compare failure.
fn probe_archive_round_trip(repo_storage: &dyn Storage, stanza: &str, archive_id: &str) -> Result<bool, CommandError> {
    let archive_dir = format!("archive/{stanza}/{archive_id}");
    let test_name = format!("{archive_id}.check-{}", std::process::id());
    let test_path = PathBuf::from(format!("{archive_dir}/{test_name}"));
    let payload = format!("pgbackrest archive check for stanza '{stanza}' archive-id '{archive_id}'").into_bytes();

    // Ensure the archive-id directory exists. On a freshly-created stanza that
    // has never archived a segment the directory may be absent; `create_path`
    // is a no-op when it already exists.
    repo_storage.create_path(&PathBuf::from(&archive_dir), true)?;

    // Write.
    {
        let mut writer: Box<dyn IoWrite> = repo_storage.open_write(&test_path)?;
        writer.write(&payload)?;
        writer.flush()?;
        writer.close()?;
    }

    // Read back and compare. Always attempt removal afterwards so a comparison
    // failure does not leak the test object.
    let read_result: Result<Vec<u8>, CommandError> = (|| {
        let mut reader: Box<dyn IoRead> = repo_storage.open_read(&test_path)?;
        Ok(reader.read_all()?)
    })();

    let remove_result = repo_storage.remove(&test_path, true);

    let read_back = read_result?;
    remove_result?;

    if read_back == payload {
        Ok(true)
    } else {
        Err(CommandError::Other(format!(
            "archive check for stanza '{stanza}' archive-id '{archive_id}' read back unexpected content"
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
        "stanza '{}' check ok: db-version={} db-system-id={} repo-writable={} archive-id={} archive-ok={}",
        report.stanza, report.db_version, report.db_system_id, report.repo_writable, report.archive_id, report.archive_ok
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
        // archive_info() seeds db_id = 1, so the archive-id is `<version>-1`.
        assert_eq!(report.archive_id, "14-1");
        assert!(report.archive_ok, "archive round trip should succeed");
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

    #[test]
    fn check_archive_round_trip_ok() {
        let (_dir, storage) = posix();
        let system_id = 6_873_049_345_984_568_091;
        // Use a non-default version so the archive-id is unambiguous (`15-1`).
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "15"),
            &backup_info(system_id, "15"),
        );

        let cfg = config_for(Some("demo"));
        let report = check_inner(&cfg, &storage).expect("archive round trip should succeed");
        assert_eq!(report.archive_id, "15-1");
        assert!(report.archive_ok, "archive round trip should be reported ok");

        // The test object must not survive in the archive-id directory.
        let archive_id_dir = Path::new("archive").join("demo").join("15-1");
        let entries = storage.list(&archive_id_dir).unwrap_or_default();
        let leftover: Vec<_> = entries
            .iter()
            .filter_map(|e| e.path.file_name().and_then(|n| n.to_str()))
            .filter(|name| name.contains(".check-"))
            .collect();
        assert!(leftover.is_empty(), "archive test object(s) left behind: {leftover:?}");

        // The test object itself must be gone.
        let test_obj = archive_id_dir.join(format!("15-1.check-{}", std::process::id()));
        assert!(
            matches!(storage.exists(&test_obj), Ok(false)),
            "archive test object should not exist after check"
        );
    }

    #[test]
    fn check_archive_fails_when_archive_dir_unwritable() {
        use pgbr_io::IoWrite;

        let (_dir, storage) = posix();
        let system_id = 99;
        seed_stanza(
            &storage,
            "demo",
            &archive_info(system_id, "16"),
            &backup_info(system_id, "16"),
        );

        // Place a regular *file* exactly where the archive-id directory
        // (`archive/demo/16-1`) needs to be created. `create_dir_all` then
        // fails because a non-directory already occupies the path, so the
        // archive round trip cannot proceed.
        let blocker = Path::new("archive").join("demo").join("16-1");
        {
            let mut w = storage.open_write(&blocker).expect("write blocker file");
            w.write(b"not a directory").expect("write blocker bytes");
            w.flush().expect("flush blocker");
            w.close().expect("close blocker");
        }

        let cfg = config_for(Some("demo"));
        let err = check_inner(&cfg, &storage).expect_err("archive check must fail when the dir is unwritable");
        assert!(
            matches!(err, CommandError::Storage(_) | CommandError::Io(_)),
            "expected a Storage/Io error, got {err:?}"
        );
    }
}
