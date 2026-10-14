//! CLI integration tests for Multi-Tenant Deduplication Poisoning Defense & Namespacing (Option BJ).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use velcrux_core::storage::{DedupNamespacePolicy, NamespacedChunkStore};
use velcrux_core::util::Hash;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[tokio::test]
async fn test_cli_dedup_status_table_and_json() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().join("dedup_store");

    let store = NamespacedChunkStore::new(&root, DedupNamespacePolicy::Isolated, None)
        .await
        .unwrap();

    let data_a = b"tenant A dedicated dataset payload";
    let hash_a = Hash::of(data_a);
    store
        .put_for_tenant("tenant-a", &hash_a, data_a)
        .await
        .unwrap();

    let data_b = b"tenant B secure dataset payload";
    let hash_b = Hash::of(data_b);
    store
        .put_for_tenant("tenant-b", &hash_b, data_b)
        .await
        .unwrap();

    // 1. Text table output
    let out = Command::new(velcrux_bin())
        .arg("dedup")
        .arg("status")
        .arg("--chunk-store")
        .arg(&root)
        .output()
        .expect("run dedup status");

    assert!(
        out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("MULTI-TENANT DEDUPLICATION & NAMESPACE STATUS"));
    assert!(stdout.contains("tenant-a"));
    assert!(stdout.contains("tenant-b"));

    // 2. JSON output
    let out_json = Command::new(velcrux_bin())
        .arg("--json")
        .arg("dedup")
        .arg("status")
        .arg("--chunk-store")
        .arg(&root)
        .output()
        .expect("run dedup status json");

    assert!(
        out_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&out_json.stderr)
    );
    let stdout_json = String::from_utf8_lossy(&out_json.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_json).expect("parse JSON");
    assert_eq!(parsed["event"], "dedup_status");
    assert_eq!(parsed["policy"], "isolated");
    assert_eq!(parsed["tenants"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_cli_dedup_verify_quarantine_and_purge() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().join("dedup_store");

    let store = NamespacedChunkStore::new(&root, DedupNamespacePolicy::Isolated, None)
        .await
        .unwrap();

    let data = b"clean tenant payload for CLI verify test";
    let hash = Hash::of(data);
    store
        .put_for_tenant("tenant-alpha", &hash, data)
        .await
        .unwrap();

    // 1. Verify clean store
    let out_clean = Command::new(velcrux_bin())
        .arg("dedup")
        .arg("verify")
        .arg("--chunk-store")
        .arg(&root)
        .output()
        .expect("run dedup verify");

    assert!(out_clean.status.success());
    let stdout_clean = String::from_utf8_lossy(&out_clean.stdout);
    assert!(stdout_clean.contains("Total Chunks Scanned : 1"));
    assert!(stdout_clean.contains("Valid Chunks         : 1"));
    assert!(stdout_clean.contains("Corrupted/Poisoned   : 0"));
    assert!(stdout_clean.contains("PASS (Clean)"));

    // 2. Corrupt the chunk file to simulate poisoning
    let chunk_path = store
        .get_tenant_store("tenant-alpha")
        .await
        .unwrap()
        .chunk_path(&hash);
    fs::write(&chunk_path, b"POISONED_BYTES").unwrap();

    // 3. Verify detects poisoning and quarantines chunk
    let out_corrupt = Command::new(velcrux_bin())
        .arg("dedup")
        .arg("verify")
        .arg("--chunk-store")
        .arg(&root)
        .output()
        .expect("run dedup verify on corrupted store");

    assert!(out_corrupt.status.success());
    let stdout_corrupt = String::from_utf8_lossy(&out_corrupt.stdout);
    assert!(stdout_corrupt.contains("Corrupted/Poisoned   : 1"));
    assert!(stdout_corrupt.contains("Quarantined Chunks   : 1"));
    assert!(stdout_corrupt.contains("FAIL (Poisoning/Corruption Detected)"));

    // 4. List quarantined chunks
    let out_qlist = Command::new(velcrux_bin())
        .arg("dedup")
        .arg("quarantine")
        .arg("list")
        .arg("--chunk-store")
        .arg(&root)
        .output()
        .expect("run quarantine list");

    assert!(out_qlist.status.success());
    let stdout_qlist = String::from_utf8_lossy(&out_qlist.stdout);
    assert!(stdout_qlist.contains("QUARANTINED POISONED/CORRUPTED CHUNKS"));
    assert!(stdout_qlist.contains("Quarantined Files    : 1"));

    // 5. Purge quarantined chunks
    let out_purge = Command::new(velcrux_bin())
        .arg("dedup")
        .arg("quarantine")
        .arg("purge")
        .arg("--chunk-store")
        .arg(&root)
        .output()
        .expect("run quarantine purge");

    assert!(out_purge.status.success());
    let stdout_purge = String::from_utf8_lossy(&out_purge.stdout);
    assert!(stdout_purge.contains("Purged 1 quarantined chunks"));

    // Verify quarantine list is now empty
    let out_qlist_empty = Command::new(velcrux_bin())
        .arg("dedup")
        .arg("quarantine")
        .arg("list")
        .arg("--chunk-store")
        .arg(&root)
        .output()
        .expect("run quarantine list empty");

    assert!(out_qlist_empty.status.success());
    let stdout_qlist_empty = String::from_utf8_lossy(&out_qlist_empty.stdout);
    assert!(stdout_qlist_empty.contains("Quarantined Files    : 0"));
}
