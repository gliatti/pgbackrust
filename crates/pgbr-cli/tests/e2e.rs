//! Cargo-native end-to-end tests for the pgBackRest Rust port.
//!
//! These run in CI under plain `cargo test` — no live `PostgreSQL`, no Docker,
//! no Perl harness. They exercise two layers:
//!
//! 1. The command stack (`pgbr_command::dispatch`) over `Posix` tempdirs,
//!    driving a realistic lifecycle: seed a synthetic PG data dir with a real
//!    `pg_control` header, then `stanza-create` -> `backup` -> `restore` ->
//!    `verify` and assert the restored cluster is byte-identical to the
//!    original and that `verify` finds zero problems.
//!
//! 2. The shipped `pgbackrest` binary itself: a `version` smoke test that runs
//!    the real `main` -> `pgbr_cli::run` pipeline, which resolves the full
//!    embedded `config.yaml` (every default, including the suffixed `time`
//!    options like `io-timeout=1m`). This is the test that caught the
//!    `parse_time` regression — before the fix the binary could not resolve
//!    *any* command's config.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
use pgbr_postgres::version::{self, VersionInterface};
use pgbr_storage::{Posix, Storage};
use tempfile::TempDir;

/// The PG major version the synthetic cluster pretends to be. Any entry in the
/// registry works; PG 16 is a representative modern release.
const PG_VERSION_LABEL: &str = "16";
/// A fixed, arbitrary cluster system identifier.
const SYSTEM_ID: u64 = 0x0123_4567_89AB_CDEF;
/// Stanza name used throughout the lifecycle test.
const STANZA: &str = "demo";

/// Build a `LoadedConfig` for `command` carrying just a stanza plus any extra
/// `(name, value)` options. Mirrors how the binary hands a resolved config to
/// `dispatch`, but constructed directly so the test does not depend on the full
/// real-config merge pipeline (whose allow-list rendering is exercised
/// separately by the binary smoke test).
fn config(command: &str, options: Vec<(&str, OptionValue)>) -> LoadedConfig {
    let mut map: BTreeMap<(String, Option<u32>), OptionValue> = BTreeMap::new();
    for (name, value) in options {
        map.insert((name.to_owned(), None), value);
    }
    LoadedConfig {
        command: command.to_owned(),
        command_role: ConfigCommandRole::Main,
        stanza: Some(STANZA.to_owned()),
        options: map,
        params: Vec::new(),
    }
}

/// Write a realistic `global/pg_control` header into the PG data dir.
///
/// The first 16 bytes of a real `pg_control` are version-stable: an 8-byte
/// little-endian `system_identifier`, a 4-byte `pg_control_version`, and a
/// 4-byte `catalog_version_no`. The control/catalog values are taken from the
/// supported-version registry so `decode_pg_control_header` recognises them.
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

/// Write `bytes` to a PG-data-relative path, creating parent dirs as needed.
fn seed_file(pg: &Posix, rel: &str, bytes: &[u8]) {
    let path = Path::new(rel);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        pg.create_path(parent, true).unwrap();
    }
    let mut w = pg.open_write(path).unwrap();
    w.write(bytes).unwrap();
    w.flush().unwrap();
    w.close().unwrap();
}

#[test]
fn e2e_stanza_create_backup_restore_verify_round_trip() {
    let repo_dir = TempDir::new().unwrap();
    let pg_src_dir = TempDir::new().unwrap();
    let pg_dst_dir = TempDir::new().unwrap();

    let repo = Posix::new(repo_dir.path());
    let pg_src = Posix::new(pg_src_dir.path());
    let pg_dst = Posix::new(pg_dst_dir.path());

    let v = version::by_label(PG_VERSION_LABEL).expect("PG 16 is a supported version");

    // --- Seed a synthetic PG data dir with a real pg_control header. ---
    write_pg_control(&pg_src, SYSTEM_ID, v);
    seed_file(&pg_src, "PG_VERSION", b"16\n");
    seed_file(&pg_src, "base/1/1259", b"relation-data-for-pg_class-1259");
    seed_file(&pg_src, "base/1/1249", b"relation-data-for-pg_attribute-1249");
    seed_file(&pg_src, "global/pg_filenode.map", b"\x00\x01\x02\x03\x04\x05\x06\x07");
    // Excluded runtime state — must NOT end up in the backup or the restore.
    seed_file(&pg_src, "postmaster.pid", b"99999\n");
    seed_file(&pg_src, "pg_wal/000000010000000000000001", b"wal-segment-bytes");

    // --- stanza-create ---
    dispatch_ok("stanza-create", &repo, &pg_src, vec![]);
    assert!(
        repo_dir.path().join(format!("backup/{STANZA}/backup.info")).exists(),
        "stanza-create must write backup.info"
    );
    assert!(
        repo_dir.path().join(format!("archive/{STANZA}/archive.info")).exists(),
        "stanza-create must write archive.info"
    );

    // --- backup (full, identity transform via compress-type=none) ---
    dispatch_ok(
        "backup",
        &repo,
        &pg_src,
        vec![("type", OptionValue::StringId("full".to_owned()))],
    );

    // Exactly one backup recorded.
    let info = pgbr_info::InfoBackup::load(&repo, Path::new(&format!("backup/{STANZA}/backup.info"))).unwrap();
    assert_eq!(info.current.len(), 1, "exactly one full backup recorded");
    let label = info.current.keys().next().unwrap().clone();

    // The manifest captured the data files but not the excluded ones.
    let manifest = pgbr_info::Manifest::load(&repo, Path::new(&format!("backup/{STANZA}/{label}/backup.manifest"))).unwrap();
    let files: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    assert!(files.contains(&"PG_VERSION"), "backup must capture PG_VERSION: {files:?}");
    assert!(files.contains(&"base/1/1259"));
    assert!(files.contains(&"global/pg_control"));
    assert!(!files.contains(&"postmaster.pid"), "postmaster.pid must be excluded");
    assert!(
        !files.iter().any(|p| p.starts_with("pg_wal")),
        "pg_wal must be excluded: {files:?}"
    );

    // --- restore into a fresh, empty PG target ---
    dispatch_ok("restore", &repo, &pg_dst, vec![("set", OptionValue::String(label))]);

    // Every captured file is restored byte-for-byte into the new target.
    for file in &manifest.files {
        let restored = pg_dst_dir.path().join(&file.path);
        let original = pg_src_dir.path().join(&file.path);
        assert!(restored.exists(), "restore must recreate {}", file.path);
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            std::fs::read(&original).unwrap(),
            "restored {} must be byte-identical to the source",
            file.path
        );
    }
    // Excluded files were never backed up, so they must be absent post-restore.
    assert!(
        !pg_dst_dir.path().join("postmaster.pid").exists(),
        "excluded postmaster.pid must not be restored"
    );

    // --- verify the restored backup finds zero integrity problems ---
    dispatch_ok("verify", &repo, &pg_dst, vec![]);
    let report = pgbr_command::verify::verify_inner(&config("verify", vec![]), &repo).unwrap();
    assert_eq!(report.backups_checked, 1, "one backup verified");
    assert!(
        report.problems.is_empty(),
        "verify must find no problems, got {:?}",
        report.problems
    );
    assert!(report.files_checked > 0, "verify must have re-read at least one file");
}

/// Dispatch a command via the real `pgbr_command::dispatch` and assert success.
fn dispatch_ok(command: &str, repo: &Posix, pg: &Posix, options: Vec<(&str, OptionValue)>) {
    let cfg = config(command, options);
    pgbr_command::dispatch(&cfg, repo, pg).unwrap_or_else(|e| panic!("`{command}` should succeed, got {e:?}"));
}

#[test]
fn e2e_binary_version_runs() {
    // Run the shipped `pgbackrest` binary's `version` command. The binary
    // resolves the full embedded config.yaml — including the suffixed `time`
    // defaults (`io-timeout=1m`, `protocol-timeout=31m`, …) — before the
    // command runs. A `parse_time` regression makes this fail config
    // resolution for *every* command, so this smoke test guards the whole
    // resolve pipeline as much as the version command itself.
    let exe = env!("CARGO_BIN_EXE_pgbackrest");
    let output = Command::new(exe)
        .arg("version")
        .output()
        .expect("running the pgbackrest binary should not fail to spawn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "`pgbackrest version` must exit 0; stderr was:\n{stderr}\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("pgBackRest"),
        "`pgbackrest version` must print the version banner, got stdout:\n{stdout}"
    );
}
