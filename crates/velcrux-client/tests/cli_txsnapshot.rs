//! Integration tests for Option CO: Distributed Global Snapshot Isolation &
//! Transactional Multi-File Checkpoint Mesh (`ADR-057`).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_txsnapshot_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("status")
        .output()
        .expect("execute velcrux txsnapshot status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Distributed Snapshot Isolation & Checkpoint Mesh Status"));
    assert!(stdout.contains("Node ID:"));
    assert!(stdout.contains("Current Epoch:"));
    assert!(stdout.contains("Vector Clock:"));
    assert!(stdout.contains("Committed Snapshots:"));
    assert!(stdout.contains("Catalog Tracked Files:"));
}

#[test]
fn test_cli_txsnapshot_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("status")
        .output()
        .expect("execute velcrux --json txsnapshot status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("parse json output from velcrux txsnapshot status");

    assert!(json_val.get("node_id").is_some());
    assert!(json_val.get("current_epoch").is_some());
    assert!(json_val.get("vector_clock").is_some());
    assert!(json_val.get("total_snapshots").is_some());
    assert!(json_val.get("catalog_file_count").is_some());
}

#[test]
fn test_cli_txsnapshot_lifecycle_stage_prepare_commit_and_read() {
    let dir = tempdir().expect("create tempdir");

    // 1. Begin transaction
    let begin_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("begin")
        .output()
        .expect("begin tx");

    assert!(begin_out.status.success());
    let begin_json: serde_json::Value = serde_json::from_slice(&begin_out.stdout).unwrap();
    let tx_id = begin_json["tx_id"]
        .as_str()
        .expect("tx_id present")
        .to_string();

    // 2. Stage file 1
    let stage1_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx_id)
        .arg("--path")
        .arg("configs/app.toml")
        .arg("--data")
        .arg("env = \"production\"\nport = 8080\n")
        .output()
        .expect("stage 1");
    assert!(stage1_out.status.success());

    // 3. Stage file 2
    let stage2_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx_id)
        .arg("--path")
        .arg("scripts/deploy.sh")
        .arg("--data")
        .arg("#!/bin/sh\necho deployed\n")
        .output()
        .expect("stage 2");
    assert!(stage2_out.status.success());

    // 4. Prepare Phase 1
    let prep_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("prepare")
        .arg("--tx")
        .arg(&tx_id)
        .arg("--participants")
        .arg("edge-node-1,edge-node-2")
        .output()
        .expect("prepare tx");
    assert!(prep_out.status.success());
    let prep_stdout = String::from_utf8_lossy(&prep_out.stdout);
    assert!(prep_stdout.contains("2PC Phase 1 Prepared"));
    assert!(prep_stdout.contains("Staged Operations:   2"));

    // 5. Commit Phase 2
    let commit_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("commit")
        .arg("--tx")
        .arg(&tx_id)
        .arg("--tag")
        .arg("v1.0.0-gold")
        .output()
        .expect("commit tx");
    assert!(commit_out.status.success());
    let commit_stdout = String::from_utf8_lossy(&commit_out.stdout);
    assert!(commit_stdout.contains("2PC Phase 2 Committed"));
    assert!(commit_stdout.contains("Tag:            v1.0.0-gold"));
    assert!(commit_stdout.contains("Total Files:    2"));

    // 6. Read file from snapshot
    let read_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("read")
        .arg("--snapshot")
        .arg("v1.0.0-gold")
        .arg("--path")
        .arg("configs/app.toml")
        .output()
        .expect("read snapshot file");
    assert!(read_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&read_out.stdout),
        "env = \"production\"\nport = 8080\n"
    );

    // 7. List snapshots
    let list_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("list")
        .output()
        .expect("list snapshots");
    assert!(list_out.status.success());
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_stdout.contains("Total Snapshots: 1"));
    assert!(list_stdout.contains("tag: v1.0.0-gold"));
}

#[test]
fn test_cli_txsnapshot_abort() {
    let dir = tempdir().expect("create tempdir");

    // Begin
    let begin_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("begin")
        .output()
        .expect("begin tx");
    let begin_json: serde_json::Value = serde_json::from_slice(&begin_out.stdout).unwrap();
    let tx_id = begin_json["tx_id"].as_str().unwrap().to_string();

    // Stage file
    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx_id)
        .arg("--path")
        .arg("discard.txt")
        .arg("--data")
        .arg("discard me")
        .output()
        .expect("stage file");

    // Abort
    let abort_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("abort")
        .arg("--tx")
        .arg(&tx_id)
        .arg("--reason")
        .arg("operator test cancellation")
        .output()
        .expect("abort tx");
    assert!(abort_out.status.success());
    let abort_stdout = String::from_utf8_lossy(&abort_out.stdout);
    assert!(abort_stdout.contains("Transaction Aborted"));
    assert!(abort_stdout.contains("operator test cancellation"));

    // Status: active transactions should be 0
    let status_out = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("status")
        .output()
        .expect("status check");
    let status_json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["active_transactions"].as_u64().unwrap(), 0);
}

#[test]
fn test_cli_txsnapshot_occ_conflict_detection() {
    let dir = tempdir().expect("create tempdir");

    // 1. Commit baseline tx1
    let b1 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("begin")
        .output()
        .expect("begin tx1");
    let tx1_id = serde_json::from_slice::<serde_json::Value>(&b1.stdout).unwrap()["tx_id"]
        .as_str()
        .unwrap()
        .to_string();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx1_id)
        .arg("--path")
        .arg("counter.txt")
        .arg("--data")
        .arg("rev 1")
        .output()
        .expect("stage tx1");

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("commit")
        .arg("--tx")
        .arg(&tx1_id)
        .arg("--tag")
        .arg("rev1")
        .output()
        .expect("commit tx1");

    // 2. Start Tx2 with expected base version 1
    let b2 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("begin")
        .output()
        .expect("begin tx2");
    let tx2_id = serde_json::from_slice::<serde_json::Value>(&b2.stdout).unwrap()["tx_id"]
        .as_str()
        .unwrap()
        .to_string();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx2_id)
        .arg("--path")
        .arg("counter.txt")
        .arg("--data")
        .arg("tx2 update")
        .arg("--base-version")
        .arg("1")
        .output()
        .expect("stage tx2");

    // 3. Concurrent Tx3 commits revision 2 first
    let b3 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("begin")
        .output()
        .expect("begin tx3");
    let tx3_id = serde_json::from_slice::<serde_json::Value>(&b3.stdout).unwrap()["tx_id"]
        .as_str()
        .unwrap()
        .to_string();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx3_id)
        .arg("--path")
        .arg("counter.txt")
        .arg("--data")
        .arg("tx3 update")
        .output()
        .expect("stage tx3");

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("commit")
        .arg("--tx")
        .arg(&tx3_id)
        .arg("--tag")
        .arg("rev2")
        .output()
        .expect("commit tx3");

    // 4. Tx2 prepare must now be rejected due to OCC conflict!
    let prep_tx2 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("prepare")
        .arg("--tx")
        .arg(&tx2_id)
        .output()
        .expect("prepare tx2");

    assert!(!prep_tx2.status.success());
    let err_str = String::from_utf8_lossy(&prep_tx2.stderr);
    assert!(err_str.contains("OCC conflict"));
}

#[test]
fn test_cli_txsnapshot_directory_rollback() {
    let dir = tempdir().expect("create tempdir");
    let target_dir = dir.path().join("live_worktree");

    // Step 1: Create snap-1 with fileA and fileB
    let b1 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("begin")
        .output()
        .expect("begin 1");
    let tx1_id = serde_json::from_slice::<serde_json::Value>(&b1.stdout).unwrap()["tx_id"]
        .as_str()
        .unwrap()
        .to_string();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx1_id)
        .arg("--path")
        .arg("fileA.txt")
        .arg("--data")
        .arg("content of A v1")
        .output()
        .unwrap();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx1_id)
        .arg("--path")
        .arg("fileB.txt")
        .arg("--data")
        .arg("content of B v1")
        .output()
        .unwrap();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("commit")
        .arg("--tx")
        .arg(&tx1_id)
        .arg("--tag")
        .arg("snap-1")
        .output()
        .unwrap();

    // Step 2: Create snap-2 modifying fileB, deleting fileA, and adding fileC
    let b2 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("--json")
        .arg("txsnapshot")
        .arg("begin")
        .output()
        .expect("begin 2");
    let tx2_id = serde_json::from_slice::<serde_json::Value>(&b2.stdout).unwrap()["tx_id"]
        .as_str()
        .unwrap()
        .to_string();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx2_id)
        .arg("--path")
        .arg("fileB.txt")
        .arg("--data")
        .arg("content of B v2")
        .output()
        .unwrap();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx2_id)
        .arg("--path")
        .arg("fileA.txt")
        .arg("--delete")
        .output()
        .unwrap();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("stage")
        .arg("--tx")
        .arg(&tx2_id)
        .arg("--path")
        .arg("fileC.txt")
        .arg("--data")
        .arg("content of C v2")
        .output()
        .unwrap();

    Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("commit")
        .arg("--tx")
        .arg(&tx2_id)
        .arg("--tag")
        .arg("snap-2")
        .output()
        .unwrap();

    // Step 3: Rollback to snap-2
    let roll2 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("rollback")
        .arg("--snapshot")
        .arg("snap-2")
        .arg("--target-dir")
        .arg(&target_dir)
        .output()
        .expect("rollback to snap-2");
    assert!(roll2.status.success());
    assert!(!target_dir.join("fileA.txt").exists());
    assert_eq!(
        fs::read_to_string(target_dir.join("fileB.txt")).unwrap(),
        "content of B v2"
    );
    assert_eq!(
        fs::read_to_string(target_dir.join("fileC.txt")).unwrap(),
        "content of C v2"
    );

    // Step 4: Atomic rollback back to snap-1
    let roll1 = Command::new(velcrux_bin())
        .env("VELCRUX_TXSNAPSHOT_DIR", dir.path())
        .arg("txsnapshot")
        .arg("rollback")
        .arg("--snapshot")
        .arg("snap-1")
        .arg("--target-dir")
        .arg(&target_dir)
        .output()
        .expect("rollback to snap-1");
    assert!(roll1.status.success());
    let roll1_stdout = String::from_utf8_lossy(&roll1.stdout);
    assert!(roll1_stdout.contains("Atomic Rollback Completed"));
    assert!(roll1_stdout.contains("Restored Files: 2"));
    assert!(roll1_stdout.contains("Deleted Files:  1")); // fileC deleted

    assert_eq!(
        fs::read_to_string(target_dir.join("fileA.txt")).unwrap(),
        "content of A v1"
    );
    assert_eq!(
        fs::read_to_string(target_dir.join("fileB.txt")).unwrap(),
        "content of B v1"
    );
    assert!(!target_dir.join("fileC.txt").exists());
}

#[test]
fn test_cli_txsnapshot_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("txsnapshot")
        .arg("benchmark")
        .arg("--iterations")
        .arg("5")
        .output()
        .expect("execute benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Distributed Snapshot Mesh Microsecond Benchmark"));
    assert!(stdout.contains("Begin Tx Latency:"));
    assert!(stdout.contains("Stage File Latency:"));
    assert!(stdout.contains("Prepare 2PC Latency:"));
    assert!(stdout.contains("Commit 2PC Latency:"));
    assert!(stdout.contains("MVCC Read Latency:"));
    assert!(stdout.contains("Rollback Latency:"));
}
