//! Integration tests for Distributed Lock Manager (DLM) CLI (Option BD).

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
fn test_cli_lock_lifecycle_table() {
    let tmp = tempdir().unwrap();
    let state_file = tmp.path().join("dlm_state.json");

    // 1. Acquire an exclusive lock on /dataset/imagenet
    let output = Command::new(velcrux_bin())
        .arg("lock")
        .arg("acquire")
        .arg("/dataset/imagenet")
        .arg("--holder")
        .arg("worker-node-01")
        .arg("--mode")
        .arg("exclusive")
        .arg("--ttl-secs")
        .arg("120")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute velcrux lock acquire");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DISTRIBUTED LOCK LEASE ACQUIRED"));
    assert!(stdout.contains("Resource Path        : /dataset/imagenet"));
    assert!(stdout.contains("Leaseholder ID       : worker-node-01"));
    assert!(stdout.contains("Lock Mode            : EXCLUSIVE"));

    // Extract lock ID from output
    let lock_id = stdout
        .lines()
        .find(|l| l.contains("Lock Lease ID"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim())
        .expect("parse lock ID");
    assert!(lock_id.starts_with("lck-"));

    // 2. Conflict: second holder trying to acquire exclusive lock on same resource must fail
    let conflict = Command::new(velcrux_bin())
        .arg("lock")
        .arg("acquire")
        .arg("/dataset/imagenet")
        .arg("--holder")
        .arg("worker-node-02")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute conflicting velcrux lock acquire");
    assert!(!conflict.status.success());
    let conflict_err = String::from_utf8_lossy(&conflict.stderr);
    assert!(conflict_err.contains("is busy (held by 'worker-node-01'"));

    // 3. List locks
    let list_out = Command::new(velcrux_bin())
        .arg("lock")
        .arg("list")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute velcrux lock list");
    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("DISTRIBUTED LOCK LEASE REGISTRY & STATUS"));
    assert!(list_str.contains("Total Active Locks   : 1"));
    assert!(list_str.contains("Exclusive Write Locks: 1"));
    assert!(list_str.contains(lock_id));

    let fencing_token = stdout
        .lines()
        .find(|l| l.contains("Lamport Fencing Token"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim())
        .expect("parse fencing token");

    // 4. Verify fencing token
    let verify_out = Command::new(velcrux_bin())
        .arg("lock")
        .arg("verify")
        .arg("/dataset/imagenet")
        .arg(fencing_token)
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute velcrux lock verify");
    assert!(verify_out.status.success());
    let verify_str = String::from_utf8_lossy(&verify_out.stdout);
    assert!(verify_str.contains("VALID (Active Authorized Lease)"));

    // Verify invalid fencing token
    let verify_invalid = Command::new(velcrux_bin())
        .arg("lock")
        .arg("verify")
        .arg("/dataset/imagenet")
        .arg("9999")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute velcrux lock verify invalid");
    assert!(verify_invalid.status.success());
    let invalid_str = String::from_utf8_lossy(&verify_invalid.stdout);
    assert!(invalid_str.contains("INVALID / EXPIRED"));

    // 5. Renew lease
    let renew_out = Command::new(velcrux_bin())
        .arg("lock")
        .arg("renew")
        .arg(lock_id)
        .arg("--holder")
        .arg("worker-node-01")
        .arg("--ttl-secs")
        .arg("300")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute velcrux lock renew");
    assert!(renew_out.status.success());
    let renew_str = String::from_utf8_lossy(&renew_out.stdout);
    assert!(renew_str.contains("DISTRIBUTED LOCK LEASE RENEWED"));

    // 6. Release lock
    let release_out = Command::new(velcrux_bin())
        .arg("lock")
        .arg("release")
        .arg(lock_id)
        .arg("--holder")
        .arg("worker-node-01")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute velcrux lock release");
    assert!(release_out.status.success());
    let release_str = String::from_utf8_lossy(&release_out.stdout);
    assert!(release_str.contains("successfully released"));

    // 7. Verify lock is now released
    let post_list = Command::new(velcrux_bin())
        .arg("lock")
        .arg("list")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("execute velcrux lock list post release");
    assert!(post_list.status.success());
    let post_list_str = String::from_utf8_lossy(&post_list.stdout);
    assert!(post_list_str.contains("Total Active Locks   : 0"));
}

#[test]
fn test_cli_lock_json_mode_and_shared_locks() {
    let tmp = tempdir().unwrap();
    let state_file = tmp.path().join("dlm_json_state.json");

    // 1. Acquire shared lock 1 in JSON mode
    let out1 = Command::new(velcrux_bin())
        .arg("--json")
        .arg("lock")
        .arg("acquire")
        .arg("/shared/repo")
        .arg("--holder")
        .arg("reader-1")
        .arg("--mode")
        .arg("shared")
        .arg("--ttl-secs")
        .arg("60")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("acquire shared 1");
    assert!(out1.status.success());
    let json1: serde_json::Value = serde_json::from_slice(&out1.stdout).expect("parse json");
    assert_eq!(json1["event"], "lock_acquired");
    assert_eq!(json1["lease"]["resource"], "/shared/repo");
    assert_eq!(json1["lease"]["mode"], "shared");
    let lock_id1 = json1["lease"]["lock_id"].as_str().unwrap();

    // 2. Acquire shared lock 2 concurrently on same resource
    let out2 = Command::new(velcrux_bin())
        .arg("--json")
        .arg("lock")
        .arg("acquire")
        .arg("/shared/repo")
        .arg("--holder")
        .arg("reader-2")
        .arg("--mode")
        .arg("shared")
        .arg("--ttl-secs")
        .arg("60")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("acquire shared 2");
    assert!(out2.status.success());
    let json2: serde_json::Value = serde_json::from_slice(&out2.stdout).expect("parse json");
    assert_eq!(json2["event"], "lock_acquired");
    let lock_id2 = json2["lease"]["lock_id"].as_str().unwrap();

    // 3. List in JSON mode
    let list_out = Command::new(velcrux_bin())
        .arg("--json")
        .arg("lock")
        .arg("list")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("list json");
    assert!(list_out.status.success());
    let list_json: serde_json::Value =
        serde_json::from_slice(&list_out.stdout).expect("parse list json");
    assert_eq!(list_json["event"], "lock_list");
    assert_eq!(list_json["report"]["total_active_locks"], 2);
    assert_eq!(list_json["report"]["total_shared_locks"], 2);
    assert_eq!(list_json["report"]["total_exclusive_locks"], 0);

    // 4. Release both in JSON mode
    let rel1 = Command::new(velcrux_bin())
        .arg("--json")
        .arg("lock")
        .arg("release")
        .arg(lock_id1)
        .arg("--holder")
        .arg("reader-1")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("release 1");
    assert!(rel1.status.success());
    let rel1_json: serde_json::Value = serde_json::from_slice(&rel1.stdout).expect("parse rel1");
    assert_eq!(rel1_json["released"], true);

    let rel2 = Command::new(velcrux_bin())
        .arg("--json")
        .arg("lock")
        .arg("release")
        .arg(lock_id2)
        .arg("--holder")
        .arg("reader-2")
        .arg("--state-file")
        .arg(&state_file)
        .output()
        .expect("release 2");
    assert!(rel2.status.success());
    let rel2_json: serde_json::Value = serde_json::from_slice(&rel2.stdout).expect("parse rel2");
    assert_eq!(rel2_json["released"], true);
}
