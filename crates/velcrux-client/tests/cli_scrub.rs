//! Integration tests for Data Integrity Scrubbing & Bit-Rot Repair CLI (Option BF).

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use velcrux_core::storage::chunk_store::{ChunkStore, LocalChunkStore};
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
async fn test_cli_scrub_verify_and_quarantine_table() {
    let tmp = tempdir().unwrap();
    let store_dir = tmp.path().join("cas_store");
    let quarantine_dir = tmp.path().join("quarantine_hold");

    let store = LocalChunkStore::new(&store_dir).await.unwrap();

    let mut hashes = Vec::new();
    for i in 0..5 {
        let data = format!("Test chunk data for CLI scrub test {}", i);
        let hash = Hash::of(data.as_bytes());
        store.put(&hash, data.as_bytes()).await.unwrap();
        hashes.push(hash);
    }

    // 1. Initial healthy scrub run
    let out = Command::new(velcrux_bin())
        .arg("scrub")
        .arg("run")
        .arg(&store_dir)
        .output()
        .expect("run scrub verify");

    assert!(out.status.success(), "stderr: {:?}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DATA INTEGRITY SCRUBBING & BIT-ROT AUDIT REPORT"));
    assert!(stdout.contains("Total Chunks Scanned : 5"));
    assert!(stdout.contains("Intact (Healthy)     : 5"));
    assert!(stdout.contains("Bit-Rot / Corrupted  : 0"));

    // 2. Corrupt chunk 1 on disk
    let p1 = store.chunk_path(&hashes[1]);
    fs::write(&p1, b"Bit rot corrupted byte data!").unwrap();

    // Run scrub check again
    let out_corrupt = Command::new(velcrux_bin())
        .arg("scrub")
        .arg("run")
        .arg(&store_dir)
        .output()
        .expect("run scrub on corrupt store");

    assert!(out_corrupt.status.success());
    let stdout_corrupt = String::from_utf8_lossy(&out_corrupt.stdout);
    assert!(stdout_corrupt.contains("Intact (Healthy)     : 4"));
    assert!(stdout_corrupt.contains("Bit-Rot / Corrupted  : 1"));
    assert!(stdout_corrupt.contains("FINDINGS & ANOMALIES DETECTED (1)"));

    // 3. Check scrub status
    let out_status = Command::new(velcrux_bin())
        .arg("scrub")
        .arg("status")
        .arg(&store_dir)
        .output()
        .expect("check scrub status");

    assert!(out_status.status.success());
    let stdout_status = String::from_utf8_lossy(&out_status.stdout);
    assert!(stdout_status.contains("LATEST CHUNK STORE SCRUBBING STATUS"));
    assert!(stdout_status.contains("Corrupted Chunks     : 1"));
    assert!(stdout_status.contains("ANOMALIES / BIT-ROT DETECTED"));

    // 4. Run quarantine mode
    let out_quarantine = Command::new(velcrux_bin())
        .arg("scrub")
        .arg("run")
        .arg(&store_dir)
        .arg("--mode")
        .arg("quarantine")
        .arg("--quarantine-dir")
        .arg(&quarantine_dir)
        .output()
        .expect("run scrub quarantine");

    assert!(out_quarantine.status.success());
    let stdout_quarantine = String::from_utf8_lossy(&out_quarantine.stdout);
    assert!(stdout_quarantine.contains("Isolated Quarantine  : 1"));

    // Corrupt chunk moved to quarantine dir
    assert!(!p1.exists());
    let quarantined_file = quarantine_dir.join(format!("{}.corrupt", hashes[1]));
    assert!(quarantined_file.exists());
}

#[tokio::test]
async fn test_cli_scrub_repair_and_json_mode() {
    let tmp = tempdir().unwrap();
    let local_dir = tmp.path().join("local_store");
    let peer_dir = tmp.path().join("peer_store");

    let local_store = LocalChunkStore::new(&local_dir).await.unwrap();
    let peer_store = LocalChunkStore::new(&peer_dir).await.unwrap();

    let mut hashes = Vec::new();
    for i in 0..6 {
        let data = format!("Multi-node replicated chunk data {}", i);
        let hash = Hash::of(data.as_bytes());
        local_store.put(&hash, data.as_bytes()).await.unwrap();
        peer_store.put(&hash, data.as_bytes()).await.unwrap();
        hashes.push(hash);
    }

    // Corrupt chunks 0 and 5 on local store
    let p0 = local_store.chunk_path(&hashes[0]);
    let p5 = local_store.chunk_path(&hashes[5]);
    fs::write(&p0, b"Corrupted chunk 0 payload").unwrap();
    fs::write(&p5, b"Corrupted chunk 5 payload").unwrap();

    // 1. Run scrub in heal mode with --json
    let out_heal = Command::new(velcrux_bin())
        .arg("--json")
        .arg("scrub")
        .arg("run")
        .arg(&local_dir)
        .arg("--mode")
        .arg("heal")
        .arg("--peer-store")
        .arg(&peer_dir)
        .output()
        .expect("run scrub heal json");

    assert!(out_heal.status.success());
    let heal_json: serde_json::Value = serde_json::from_slice(&out_heal.stdout).expect("parse heal json");
    assert_eq!(heal_json["event"], "scrub_completed");
    assert_eq!(heal_json["report"]["corrupted_chunks"], 2);
    assert_eq!(heal_json["report"]["repaired_chunks"], 2);

    // 2. Status in --json
    let out_status = Command::new(velcrux_bin())
        .arg("--json")
        .arg("scrub")
        .arg("status")
        .arg(&local_dir)
        .output()
        .expect("status json");

    assert!(out_status.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&out_status.stdout).expect("parse status json");
    assert_eq!(status_json["event"], "scrub_status");
    assert_eq!(status_json["report"]["repaired_chunks"], 2);

    // 3. Dedicated repair subcommand in --json
    let out_repair = Command::new(velcrux_bin())
        .arg("--json")
        .arg("scrub")
        .arg("repair")
        .arg(&local_dir)
        .arg("--peer-store")
        .arg(&peer_dir)
        .output()
        .expect("repair subcommand json");

    assert!(out_repair.status.success());
    let repair_json: serde_json::Value = serde_json::from_slice(&out_repair.stdout).expect("parse repair json");
    assert_eq!(repair_json["event"], "scrub_repair_completed");
}
