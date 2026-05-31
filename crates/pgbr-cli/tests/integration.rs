//! Integration test suite for the pgBackRest Rust port.
//!
//! This complements the lifecycle smoke test in `tests/e2e.rs` and is purely
//! cargo-native: no shell drivers, no external orchestrator.
//!
//! Two layers:
//!
//! ## Layer A — always-on local-path command sequences (no `PostgreSQL`, no Docker)
//!
//! Each scenario seeds a synthetic PG data dir (a real `pg_control` header taken
//! from [`pgbr_postgres::version::SUPPORTED`]) over `Posix` tempdirs, then drives
//! *sequences* of commands through [`pgbr_command::dispatch`] and asserts on the
//! observable repository state (on-disk dirs, `backup.info`, manifests, the
//! typed `*_inner` reports). These extend coverage beyond `e2e.rs`'s single
//! create -> backup -> restore -> verify path:
//!
//! - [`info_reports_backup_after_backup`] — `info` sees a backup after `backup`.
//! - [`expire_removes_old_full_backups`] — retention drops the oldest full.
//! - [`verify_detects_corrupted_file`] — `verify` flags a tampered repo file.
//! - [`diff_then_restore_reconstructs_full_tree`] — full -> diff -> restore
//!   reconstructs the complete tree byte-for-byte.
//!
//! These run in plain `cargo test`.
//!
//! ## Layer B — live-`PostgreSQL` backup/restore cycle (`#[ignore]`, opt-in)
//!
//! [`live_pg_backup_restore_cycle`] runs `stanza-create` -> `backup` -> `restore`
//! against a real, initialised cluster's data directory and asserts the data dir
//! round-trips. It is `#[ignore]`d (never runs in CI by default) and additionally
//! gated on the `PGBR_IT_PGDATA` / `PGBR_IT_REPO` env vars. To run it:
//!
//! ```text
//! PGBR_IT_PGDATA=/path/to/pgdata PGBR_IT_REPO=/tmp/pgbr-it-repo \
//!     cargo test -p pgbr-cli --test integration -- --ignored live_pg
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use pgbr_command::backup::{BackupType, backup_inner_typed};
use pgbr_command::pipeline::RepoTransform;
use pgbr_config::{ConfigCommandRole, LoadedConfig, OptionValue};
use pgbr_info::InfoBackup;
use pgbr_postgres::version::{self, VersionInterface};
use pgbr_storage::{Posix, Storage};
use tempfile::TempDir;

/// The PG major version the synthetic cluster pretends to be.
const PG_VERSION_LABEL: &str = "16";
/// A fixed, arbitrary cluster system identifier.
const SYSTEM_ID: u64 = 0x0123_4567_89AB_CDEF;
/// Stanza name used throughout the always-on scenarios.
const STANZA: &str = "demo";

// ---------------------------------------------------------------------------
// Shared helpers (mirrors the pattern in tests/e2e.rs; kept independent so the
// two test files do not couple).
// ---------------------------------------------------------------------------

/// Build a `LoadedConfig` for `command` carrying the stanza plus extra options.
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

/// Write a realistic `global/pg_control` header into the PG data dir. The first
/// 16 bytes of a real `pg_control` are version-stable: an 8-byte LE
/// `system_identifier`, a 4-byte `pg_control_version`, a 4-byte
/// `catalog_version_no` — the latter two taken from the supported-version
/// registry so the header decodes.
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

/// Seed a representative synthetic PG data directory into `pg`.
fn seed_cluster(pg: &Posix, v: &VersionInterface) {
    write_pg_control(pg, SYSTEM_ID, v);
    seed_file(pg, "PG_VERSION", b"16\n");
    seed_file(pg, "base/1/1259", b"relation-data-for-pg_class-1259");
    seed_file(pg, "base/1/1249", b"relation-data-for-pg_attribute-1249");
    seed_file(pg, "global/pg_filenode.map", b"\x00\x01\x02\x03\x04\x05\x06\x07");
}

/// Dispatch a command via the real `pgbr_command::dispatch` and assert success.
fn dispatch_ok(command: &str, repo: &Posix, pg: &Posix, options: Vec<(&str, OptionValue)>) {
    let cfg = config(command, options);
    pgbr_command::dispatch(&cfg, repo, pg).unwrap_or_else(|e| panic!("`{command}` should succeed, got {e:?}"));
}

/// Load the stanza's `backup.info` from the repository tempdir.
fn load_backup_info(repo: &Posix) -> InfoBackup {
    InfoBackup::load(repo, Path::new(&format!("backup/{STANZA}/backup.info"))).unwrap()
}

// ---------------------------------------------------------------------------
// Layer A: always-on local-path scenarios.
// ---------------------------------------------------------------------------

#[test]
fn info_reports_backup_after_backup() {
    let repo_dir = TempDir::new().unwrap();
    let pg_dir = TempDir::new().unwrap();
    let repo = Posix::new(repo_dir.path());
    let pg = Posix::new(pg_dir.path());
    let v = version::by_label(PG_VERSION_LABEL).expect("PG 16 is supported");

    seed_cluster(&pg, v);
    dispatch_ok("stanza-create", &repo, &pg, vec![]);

    // Before any backup, `info` reports the stanza but with no backups.
    let before = pgbr_command::info::info_inner(&config("info", vec![]), &repo).unwrap();
    assert_eq!(before.len(), 1, "exactly the demo stanza is reported");
    assert!(
        before[0].backups.is_empty(),
        "no backups before the first backup, got {:?}",
        before[0].backups
    );

    // Take a full backup, then `info` must list exactly that backup.
    dispatch_ok("backup", &repo, &pg, vec![("type", OptionValue::StringId("full".to_owned()))]);

    // The dispatched `info` command itself must succeed.
    dispatch_ok("info", &repo, &pg, vec![]);

    let after = pgbr_command::info::info_inner(&config("info", vec![]), &repo).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].name, STANZA);
    assert_eq!(after[0].backups.len(), 1, "info must report the one backup taken");
    assert_eq!(after[0].backups[0].backup_type, "full");

    // And the on-disk backup.info agrees: exactly one current backup, of the
    // label `info` reported.
    let info = load_backup_info(&repo);
    assert_eq!(info.current.len(), 1);
    let label = info.current.keys().next().unwrap();
    assert_eq!(&after[0].backups[0].label, label, "info label must match backup.info");
}

#[test]
fn expire_removes_old_full_backups() {
    let repo_dir = TempDir::new().unwrap();
    let pg_dir = TempDir::new().unwrap();
    let repo = Posix::new(repo_dir.path());
    let pg = Posix::new(pg_dir.path());
    let v = version::by_label(PG_VERSION_LABEL).expect("PG 16 is supported");

    seed_cluster(&pg, v);
    dispatch_ok("stanza-create", &repo, &pg, vec![]);

    // Three full backups with pinned, monotonically increasing labels and
    // timestamps. `backup_inner_typed` lets the test fix both so the three
    // fulls are distinct and deterministically ordered — `dispatch`'s backup
    // derives a second-resolution label from the wall clock, which would
    // collide for backups taken in the same second.
    let labels = ["20240101-000000F", "20240102-000000F", "20240103-000000F"];
    let timestamps = [1_704_067_200_i64, 1_704_153_600, 1_704_240_000];
    let transform = RepoTransform::identity();
    for (label, ts) in labels.iter().zip(timestamps) {
        backup_inner_typed(STANZA, &repo, &pg, BackupType::Full, Some(label), ts, &transform)
            .unwrap_or_else(|e| panic!("seeding full backup {label} should succeed, got {e:?}"));
    }

    // Sanity: all three are recorded and present on disk.
    let info = load_backup_info(&repo);
    assert_eq!(info.current.len(), 3, "three full backups recorded before expire");
    for label in labels {
        assert!(
            repo_dir.path().join(format!("backup/{STANZA}/{label}")).exists(),
            "{label} dir must exist before expire"
        );
    }

    // Keep the 2 most recent fulls.
    dispatch_ok("expire", &repo, &pg, vec![("repo-retention-full", OptionValue::Integer(2))]);

    let oldest = labels[0];
    // The oldest backup's directory is gone from the repo...
    assert!(
        !repo_dir.path().join(format!("backup/{STANZA}/{oldest}")).exists(),
        "expire must delete the oldest full backup dir ({oldest})"
    );
    // ...the two newest survive...
    for label in &labels[1..] {
        assert!(
            repo_dir.path().join(format!("backup/{STANZA}/{label}")).exists(),
            "retained backup {label} dir must remain"
        );
    }
    // ...and backup.info no longer lists the oldest, but keeps the rest.
    let info = load_backup_info(&repo);
    assert_eq!(info.current.len(), 2, "backup.info keeps exactly two backups");
    assert!(
        !info.current.contains_key(oldest),
        "backup.info must drop the expired oldest backup {oldest}"
    );
    assert!(info.current.contains_key(labels[1]));
    assert!(info.current.contains_key(labels[2]));
}

#[test]
fn verify_detects_corrupted_file() {
    let repo_dir = TempDir::new().unwrap();
    let pg_dir = TempDir::new().unwrap();
    let repo = Posix::new(repo_dir.path());
    let pg = Posix::new(pg_dir.path());
    let v = version::by_label(PG_VERSION_LABEL).expect("PG 16 is supported");

    seed_cluster(&pg, v);
    dispatch_ok("stanza-create", &repo, &pg, vec![]);
    dispatch_ok("backup", &repo, &pg, vec![("type", OptionValue::StringId("full".to_owned()))]);

    let info = load_backup_info(&repo);
    let label = info.current.keys().next().unwrap().clone();

    // A clean verify finds nothing wrong.
    let clean = pgbr_command::verify::verify_inner(&config("verify", vec![]), &repo).unwrap();
    assert_eq!(clean.backups_checked, 1);
    assert!(
        clean.problems.is_empty(),
        "clean verify must find no problems, got {:?}",
        clean.problems
    );
    assert!(clean.files_checked > 0, "verify must re-read at least one file");

    // Corrupt a captured file in the repo backup dir by overwriting its bytes
    // (identity transform: the repo file has no compression suffix). The
    // manifest still records the original SHA-1, so verify must flag it.
    let target = repo_dir.path().join(format!("backup/{STANZA}/{label}/base/1/1259"));
    assert!(
        target.exists(),
        "the backed-up file must exist before corruption: {}",
        target.display()
    );
    std::fs::write(&target, b"this is not the data that was backed up at all").unwrap();

    let report = pgbr_command::verify::verify_inner(&config("verify", vec![]), &repo).unwrap();
    assert_eq!(report.backups_checked, 1, "still one backup verified");
    assert!(
        !report.problems.is_empty(),
        "verify must report a problem for the corrupted file"
    );
    // The reported problem must concern the file we tampered with.
    let mentions_target = report.problems.iter().any(|p| format!("{p:?}").contains("base/1/1259"));
    assert!(
        mentions_target,
        "verify must flag the corrupted file base/1/1259, got {:?}",
        report.problems
    );
}

#[test]
fn diff_then_restore_reconstructs_full_tree() {
    let repo_dir = TempDir::new().unwrap();
    let pg_src_dir = TempDir::new().unwrap();
    let pg_dst_dir = TempDir::new().unwrap();
    let repo = Posix::new(repo_dir.path());
    let pg_src = Posix::new(pg_src_dir.path());
    let pg_dst = Posix::new(pg_dst_dir.path());
    let v = version::by_label(PG_VERSION_LABEL).expect("PG 16 is supported");

    seed_cluster(&pg_src, v);
    dispatch_ok("stanza-create", &repo, &pg_src, vec![]);

    // Full backup, then change one file and add a new one, then a diff backup.
    dispatch_ok(
        "backup",
        &repo,
        &pg_src,
        vec![("type", OptionValue::StringId("full".to_owned()))],
    );

    // Mutate the source tree: rewrite an existing relation and add a new one.
    // The diff must capture the changed + new files and reference the rest.
    seed_file(&pg_src, "base/1/1259", b"relation-data-for-pg_class-1259-MODIFIED-LONGER");
    seed_file(&pg_src, "base/1/2608", b"brand-new-relation-2608");

    dispatch_ok(
        "backup",
        &repo,
        &pg_src,
        vec![("type", OptionValue::StringId("diff".to_owned()))],
    );

    // Two backups recorded: one full + one diff.
    let info = load_backup_info(&repo);
    assert_eq!(info.current.len(), 2, "one full + one diff recorded");

    // Locate the diff label via `info_inner`, whose `BackupSummary` exposes the
    // backup type as a plain string (so the test needs no serde_json dependency).
    let summaries = pgbr_command::info::info_inner(&config("info", vec![]), &repo).unwrap();
    let diff_label = summaries
        .iter()
        .flat_map(|s| &s.backups)
        .find(|b| b.backup_type == "diff")
        .map(|b| b.label.clone())
        .expect("a diff backup must be recorded");

    // The diff's manifest must inventory the full current tree (changed files
    // copied locally, unchanged files carried as references to the full).
    let manifest = pgbr_info::Manifest::load(&repo, Path::new(&format!("backup/{STANZA}/{diff_label}/backup.manifest"))).unwrap();
    let files: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    for expected in ["PG_VERSION", "base/1/1259", "base/1/1249", "base/1/2608", "global/pg_control"] {
        assert!(files.contains(&expected), "diff manifest must list {expected}, got {files:?}");
    }

    // Restore the diff into a fresh, empty target.
    dispatch_ok("restore", &repo, &pg_dst, vec![("set", OptionValue::String(diff_label))]);

    // Every file in the diff manifest must be reconstructed byte-for-byte from
    // the *current* (post-modification) source tree — references resolved.
    for file in &manifest.files {
        let restored = pg_dst_dir.path().join(&file.path);
        let original = pg_src_dir.path().join(&file.path);
        assert!(restored.exists(), "restore must recreate {}", file.path);
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            std::fs::read(&original).unwrap(),
            "restored {} must be byte-identical to the current source",
            file.path
        );
    }
    // Spot-check the modified and new files specifically.
    assert_eq!(
        std::fs::read(pg_dst_dir.path().join("base/1/1259")).unwrap(),
        b"relation-data-for-pg_class-1259-MODIFIED-LONGER",
        "the modified relation must restore to its new contents"
    );
    assert_eq!(
        std::fs::read(pg_dst_dir.path().join("base/1/2608")).unwrap(),
        b"brand-new-relation-2608",
        "the newly added relation must restore"
    );
}

// ---------------------------------------------------------------------------
// Layer B: live-PostgreSQL backup/restore cycle (#[ignore], opt-in).
// ---------------------------------------------------------------------------

/// Live-`PostgreSQL` backup/restore cycle.
///
/// `#[ignore]`d so it never runs under a plain `cargo test`. Even when run with
/// `--ignored`, it self-skips (early `return`) unless both env vars are set, so
/// it is safe to invoke unconditionally:
///
/// - `PGBR_IT_PGDATA` — path to a real, initialised cluster's data directory.
///   Stop the server first; this drives a file-level (`--no-online`-style)
///   copy of the data dir and does not talk to a running postmaster.
/// - `PGBR_IT_REPO` — an empty/scratch directory to use as the backup repo.
///
/// Run it with:
///
/// ```text
/// PGBR_IT_PGDATA=/path/to/pgdata PGBR_IT_REPO=/tmp/pgbr-it-repo \
///     cargo test -p pgbr-cli --test integration -- --ignored live_pg
/// ```
///
/// The cycle is `stanza-create` -> `backup` -> `restore` into a fresh directory,
/// asserting that every file the backup captured round-trips byte-identically.
#[test]
#[ignore = "requires a live PostgreSQL data dir; set PGBR_IT_PGDATA and PGBR_IT_REPO, run with --ignored"]
fn live_pg_backup_restore_cycle() {
    let Ok(pgdata) = std::env::var("PGBR_IT_PGDATA") else {
        eprintln!("PGBR_IT_PGDATA not set — skipping live PG integration test");
        return;
    };
    let Ok(repo_root) = std::env::var("PGBR_IT_REPO") else {
        eprintln!("PGBR_IT_REPO not set — skipping live PG integration test");
        return;
    };

    let repo = Posix::new(Path::new(&repo_root));
    let pg_src = Posix::new(Path::new(&pgdata));
    // Restore target: a fresh subdir under the repo root, wiped if present.
    let restore_dir = Path::new(&repo_root).join("pgbr-it-restore");
    let _ = std::fs::remove_dir_all(&restore_dir);
    std::fs::create_dir_all(&restore_dir).expect("create restore target dir");
    let pg_dst = Posix::new(&restore_dir);

    // stanza-create -> backup -> restore against the real cluster.
    dispatch_ok("stanza-create", &repo, &pg_src, vec![]);
    dispatch_ok(
        "backup",
        &repo,
        &pg_src,
        vec![("type", OptionValue::StringId("full".to_owned()))],
    );

    let info = load_backup_info(&repo);
    assert_eq!(info.current.len(), 1, "one full backup of the live cluster");
    let label = info.current.keys().next().unwrap().clone();

    let manifest = pgbr_info::Manifest::load(&repo, Path::new(&format!("backup/{STANZA}/{label}/backup.manifest"))).unwrap();
    assert!(!manifest.files.is_empty(), "the live backup must capture at least one file");

    dispatch_ok("restore", &repo, &pg_dst, vec![("set", OptionValue::String(label))]);

    // Every captured file round-trips byte-for-byte.
    for file in &manifest.files {
        let restored = restore_dir.join(&file.path);
        let original = Path::new(&pgdata).join(&file.path);
        assert!(restored.exists(), "restore must recreate {}", file.path);
        assert_eq!(
            std::fs::read(&restored).unwrap(),
            std::fs::read(&original).unwrap(),
            "restored {} must be byte-identical to the live source",
            file.path
        );
    }
}
