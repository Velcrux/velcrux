//! Integration tests for Option BT: Persistent Transfer Checkpointing with
//! WAL-Backed Fast Recovery & Resume Daemon (`ADR-036`).

#![forbid(unsafe_code)]

use std::process::Command;
use tempfile::tempdir;
use velcrux_core::state::{
    ChunkBitmap, Direction, Role, SqliteStateStore, StateStore, TransferRecord, TransferStatus,
};
use velcrux_core::util::{Hash, TransferId};

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

fn create_sample_db(dir: &std::path::Path) -> (std::path::PathBuf, TransferId, TransferId) {
    let db_path = dir.join("test_state.db");
    let store = SqliteStateStore::new(&db_path).expect("create sqlite store");

    let tid1 = TransferId::generate();
    let tid2 = TransferId::generate();

    let rec1 = TransferRecord {
        transfer_id: tid1,
        idempotency_key: "tx-cp-1".to_string(),
        role: Role::Client,
        direction: Direction::Upload,
        status: TransferStatus::Active,
        remote_path: "datasets/big_dataset.tar".to_string(),
        local_path: "/data/big_dataset.tar".to_string(),
        file_size: 1_000_000_000,
        file_hash: Hash::ZERO,
        verified_up_to: 0,
        last_checkpoint_ms: 1000,
        bytes_completed: 500_000_000,
        staging_relpath: String::new(),
        created_ms: 1000,
        updated_ms: 1000,
    };
    store.upsert_transfer(&rec1).expect("upsert rec1");

    let mut bm1 = ChunkBitmap::new();
    bm1.mark_complete(0, 1024 * 1024);
    bm1.mark_complete(1, 1024 * 1024);
    store.write_bitmap(tid1, &bm1).expect("write bitmap 1");

    let rec2 = TransferRecord {
        transfer_id: tid2,
        idempotency_key: "tx-cp-2".to_string(),
        role: Role::Client,
        direction: Direction::Upload,
        status: TransferStatus::Committed,
        remote_path: "datasets/archive.zip".to_string(),
        local_path: "/data/archive.zip".to_string(),
        file_size: 10_000,
        file_hash: Hash::ZERO,
        verified_up_to: 10_000,
        last_checkpoint_ms: 2000,
        bytes_completed: 10_000,
        staging_relpath: String::new(),
        created_ms: 2000,
        updated_ms: 2000,
    };
    store.upsert_transfer(&rec2).expect("upsert rec2");

    (db_path, tid1, tid2)
}

#[test]
fn test_cli_checkpoint_status_text_and_json() {
    let temp = tempdir().unwrap();
    let (db_path, _tid1, _) = create_sample_db(temp.path());

    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("--state-db")
        .arg(&db_path)
        .arg("checkpoint")
        .arg("status")
        .output()
        .expect("execute checkpoint status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Transfer Checkpoint & Recovery Status (client) ==="));
    assert!(stdout.contains("SQLite WAL Status:"));

    // 2. JSON output on a fresh sample DB to verify active -> resumable transition
    let temp2 = tempdir().unwrap();
    let (db_path2, tid1_b, _) = create_sample_db(temp2.path());
    let json_out = Command::new(velcrux_bin())
        .arg("--state-db")
        .arg(&db_path2)
        .arg("checkpoint")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute checkpoint status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse status json");

    assert_eq!(val["resumable_count"].as_u64().unwrap(), 1);
    assert_eq!(
        val["active_transfers_marked_resumable"].as_u64().unwrap(),
        1
    );
    assert!(val["total_bytes_resumable"].as_u64().unwrap() >= 1_000_000_000);
    assert!(val["transfers"].is_array());
    assert_eq!(
        val["transfers"][0]["transfer_id"].as_str().unwrap(),
        tid1_b.to_string()
    );
}

#[test]
fn test_cli_checkpoint_recover_instantaneous() {
    let temp = tempdir().unwrap();
    let (db_path, tid1, _) = create_sample_db(temp.path());

    // 1. Recover all (marks active as resumable and verifies progress)
    let output = Command::new(velcrux_bin())
        .arg("--state-db")
        .arg(&db_path)
        .arg("checkpoint")
        .arg("recover")
        .output()
        .expect("execute checkpoint recover");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Fast Instantaneous Recovery Report (client) ==="));
    assert!(stdout.contains("Total Resumable Transfers:  1"));
    assert!(stdout.contains(&tid1.to_string()));

    // 2. Recover single transfer by ID with JSON
    let json_out = Command::new(velcrux_bin())
        .arg("--state-db")
        .arg(&db_path)
        .arg("checkpoint")
        .arg("recover")
        .arg("--transfer-id")
        .arg(tid1.to_string())
        .arg("--json")
        .output()
        .expect("execute checkpoint recover single json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse single recover json");

    assert_eq!(val["transfer_id"].as_str().unwrap(), tid1.to_string());
    assert_eq!(val["status"].as_str().unwrap(), "resumable");
    assert_eq!(val["bytes_completed"].as_u64().unwrap(), 2 * 1024 * 1024);
    assert_eq!(val["file_size"].as_u64().unwrap(), 1_000_000_000);
    assert_eq!(val["chunks_completed"].as_u64().unwrap(), 2);
    assert!(val["verified"].as_bool().unwrap());
}

#[test]
fn test_cli_checkpoint_wal_flush_modes() {
    let temp = tempdir().unwrap();
    let (db_path, _, _) = create_sample_db(temp.path());

    // 1. Text flush with truncate mode
    let output = Command::new(velcrux_bin())
        .arg("--state-db")
        .arg(&db_path)
        .arg("checkpoint")
        .arg("wal-flush")
        .arg("--mode")
        .arg("truncate")
        .output()
        .expect("execute checkpoint wal-flush");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== SQLite WAL Checkpoint Flush (client) ==="));
    assert!(stdout.contains("Requested Mode:          Truncate"));

    // 2. JSON flush with passive mode
    let json_out = Command::new(velcrux_bin())
        .arg("--state-db")
        .arg(&db_path)
        .arg("checkpoint")
        .arg("wal-flush")
        .arg("--mode")
        .arg("passive")
        .arg("--json")
        .output()
        .expect("execute checkpoint wal-flush json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse wal-flush json");
    assert_eq!(val["mode"].as_str().unwrap(), "passive");
    assert!(!val["busy"].as_bool().unwrap());
}

#[test]
fn test_cli_checkpoint_prune_stale() {
    let temp = tempdir().unwrap();
    let (db_path, _, tid2) = create_sample_db(temp.path());

    // Prune transfers older than 0 seconds (pruning rec2 which is committed)
    let output = Command::new(velcrux_bin())
        .arg("--state-db")
        .arg(&db_path)
        .arg("checkpoint")
        .arg("prune")
        .arg("--older-than-secs")
        .arg("0")
        .arg("--json")
        .output()
        .expect("execute checkpoint prune");

    assert!(output.status.success());
    let val: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse prune json");
    assert_eq!(val["pruned_transfers"].as_u64().unwrap(), 1);

    // Verify rec2 is no longer in DB
    let store = SqliteStateStore::new(&db_path).expect("open store");
    assert!(matches!(
        store.get_transfer(tid2),
        Err(velcrux_core::state::StateStoreError::NotFound)
    ));
}
