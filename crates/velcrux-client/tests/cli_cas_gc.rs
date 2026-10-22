//! Integration tests for Option BV: Content-Addressable Storage (CAS)
//! Generational Garbage Collection, Tombstoning, and Compaction Daemon (`ADR-038`).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use velcrux_core::storage::{CasGcPolicy, CasTombstone, GenerationalCasManager};
use velcrux_core::util::Hash;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_cas_status_text_and_json() {
    let temp = tempdir().unwrap();
    let store_root = temp.path().join("cas_store");
    let mgr = GenerationalCasManager::new(&store_root);

    // Ingest sample chunk
    let data = b"sample test chunk for status verification";
    let hash = Hash::of(data);
    let chunk_path = mgr.chunk_path(&hash);
    fs::create_dir_all(chunk_path.parent().unwrap()).unwrap();
    fs::write(&chunk_path, data).unwrap();

    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("cas")
        .arg("status")
        .arg("--chunk-store")
        .arg(&store_root)
        .output()
        .expect("execute cas status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Content-Addressable Storage (CAS) Status ==="));
    assert!(stdout.contains("Total Chunks:            1"));
    assert!(stdout.contains("Nursery (Gen 0):       1"));

    // 2. JSON output
    let output_json = Command::new(velcrux_bin())
        .arg("cas")
        .arg("status")
        .arg("--chunk-store")
        .arg(&store_root)
        .arg("--json")
        .output()
        .expect("execute cas status json");

    assert!(output_json.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("parse cas status json");
    assert_eq!(v["total_chunks"], 1);
    assert_eq!(v["nursery_chunks"], 1);
    assert_eq!(v["tombstoned_chunks"], 0);
    assert_eq!(v["total_bytes"], data.len() as u64);
}

#[test]
fn test_cli_cas_gc_and_resurrect() {
    let temp = tempdir().unwrap();
    let store_root = temp.path().join("cas_store");
    let mgr = GenerationalCasManager::new(&store_root);

    // Ingest sample chunk
    let data = b"chunk to be tombstoned and resurrected";
    let hash = Hash::of(data);
    let chunk_path = mgr.chunk_path(&hash);
    fs::create_dir_all(chunk_path.parent().unwrap()).unwrap();
    fs::write(&chunk_path, data).unwrap();

    // Run GC with nursery_grace = 0 (immediately eligible for tombstone since unreferenced)
    let output = Command::new(velcrux_bin())
        .arg("cas")
        .arg("gc")
        .arg("--chunk-store")
        .arg(&store_root)
        .arg("--nursery-grace")
        .arg("0")
        .output()
        .expect("execute cas gc");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== CAS Generational Mark-and-Sweep Garbage Collection ==="));
    assert!(stdout.contains("Newly Tombstoned:        1"));
    assert!(mgr.tombstone_path(&hash).exists());

    // Resurrect the tombstoned chunk
    let output_res = Command::new(velcrux_bin())
        .arg("cas")
        .arg("resurrect")
        .arg("--chunk-store")
        .arg(&store_root)
        .arg("--hash")
        .arg(hash.to_hex())
        .arg("--json")
        .output()
        .expect("execute cas resurrect");

    assert!(output_res.status.success());
    let res_v: serde_json::Value =
        serde_json::from_slice(&output_res.stdout).expect("parse resurrect json");
    assert_eq!(res_v["resurrected"], true);
    assert!(!mgr.tombstone_path(&hash).exists());
    assert!(chunk_path.exists());
}

#[test]
fn test_cli_cas_purge_expired_tombstones() {
    let temp = tempdir().unwrap();
    let store_root = temp.path().join("cas_store");
    let mgr = GenerationalCasManager::new(&store_root);

    let data = b"chunk pending hard purge";
    let hash = Hash::of(data);
    let chunk_path = mgr.chunk_path(&hash);
    fs::create_dir_all(chunk_path.parent().unwrap()).unwrap();
    fs::write(&chunk_path, data).unwrap();

    // Attach tombstone
    let tomb = CasTombstone::new(hash, data.len() as u64, "expired tombstone test", None);
    let tomb_path = mgr.tombstone_path(&hash);
    tomb.write_to_file(&tomb_path).unwrap();

    // Hard purge tombstones older than 0 seconds
    let output = Command::new(velcrux_bin())
        .arg("cas")
        .arg("purge")
        .arg("--chunk-store")
        .arg(&store_root)
        .arg("--older-than-secs")
        .arg("0")
        .arg("--json")
        .output()
        .expect("execute cas purge");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse purge json");
    assert_eq!(v["purged_chunks"], 1);
    assert_eq!(v["bytes_reclaimed"], data.len() as u64);
    assert!(!chunk_path.exists());
    assert!(!tomb_path.exists());
}

#[test]
fn test_generational_manager_sweep_lifecycle() {
    let temp = tempdir().unwrap();
    let store_root = temp.path().join("cas_store");
    let mgr = GenerationalCasManager::new(&store_root);

    let (h1, _) = {
        let data = b"chunk 1";
        let h = Hash::of(data);
        let p = mgr.chunk_path(&h);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        (h, p)
    };

    let (h2, _) = {
        let data = b"chunk 2";
        let h = Hash::of(data);
        let p = mgr.chunk_path(&h);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        (h, p)
    };

    // Reference h1, leave h2 unreferenced
    let mut refs = std::collections::HashSet::new();
    refs.insert(h1);

    let policy = CasGcPolicy {
        nursery_grace_secs: 0,
        tombstone_ttl_secs: 86400,
        purge_expired: false,
        dry_run: false,
    };

    let report = mgr.mark_and_sweep(&refs, &policy).unwrap();
    assert_eq!(report.tenured_chunks, 1);
    assert_eq!(report.newly_tombstoned, 1);
    assert!(!mgr.tombstone_path(&h1).exists());
    assert!(mgr.tombstone_path(&h2).exists());
}
