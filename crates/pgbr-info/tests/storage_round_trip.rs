//! Integration tests that round-trip `InfoArchive` and `InfoBackup` through a real
//! `Posix` storage backend rooted in a `tempfile::TempDir`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use pgbr_info::{DbHistoryEntry, InfoArchive, InfoBackup};
use pgbr_storage::Posix;
use serde_json::json;
use tempfile::TempDir;

#[test]
fn archive_load_save_round_trip() {
    let tmp = TempDir::new().unwrap();
    let storage = Posix::new(tmp.path());

    let mut history = BTreeMap::new();
    history.insert(
        1,
        DbHistoryEntry {
            db_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
        },
    );
    let archive = InfoArchive {
        backrest_format: 5,
        backrest_version: "2.58".to_owned(),
        db_id: 1,
        db_system_id: 6_873_049_345_984_568_091,
        db_version: "14".to_owned(),
        history,
    };

    let path = Path::new("archive.info");
    archive.save(&storage, path).unwrap();
    let loaded = InfoArchive::load(&storage, path).unwrap();
    assert_eq!(loaded, archive);
}

#[test]
fn backup_load_save_round_trip_with_two_current_entries() {
    let tmp = TempDir::new().unwrap();
    let storage = Posix::new(tmp.path());

    let mut history = BTreeMap::new();
    history.insert(
        1,
        DbHistoryEntry {
            db_id: 6_873_049_345_984_568_091,
            db_version: "14".to_owned(),
        },
    );

    let mut current = BTreeMap::new();
    current.insert(
        "20260101-100000F".to_owned(),
        json!({
            "backup-info-size": 12345,
            "backup-label": "20260101-100000F",
            "backup-type": "full"
        }),
    );
    current.insert(
        "20260101-100000F_20260102-080000I".to_owned(),
        json!({
            "backup-info-size": 67,
            "backup-label": "20260101-100000F_20260102-080000I",
            "backup-type": "incr",
            "backup-prior": "20260101-100000F"
        }),
    );

    let backup = InfoBackup {
        backrest_format: 5,
        backrest_version: "2.58".to_owned(),
        db_id: 1,
        db_system_id: 6_873_049_345_984_568_091,
        db_version: "14".to_owned(),
        db_catalog_version: 202_107_181,
        db_control_version: 1300,
        current,
        history,
    };

    let path = Path::new("backup.info");
    backup.save(&storage, path).unwrap();
    let loaded = InfoBackup::load(&storage, path).unwrap();
    assert_eq!(loaded, backup);
    assert_eq!(loaded.current.len(), 2);
}
