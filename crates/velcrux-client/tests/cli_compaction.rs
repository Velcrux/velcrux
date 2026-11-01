//! Integration tests for Option CM: Autonomous Self-Tuning Storage Tiering
//! & Compaction Engine (`ADR-055`).

#![forbid(unsafe_code)]

use std::process::Command;
use tempfile::tempdir;
use velcrux_core::storage::{AutonomousCompactionEngine, ChunkTemperature, CompactionPolicy};
use velcrux_core::util::Hash;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

fn dummy_hash(val: u64) -> Hash {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&val.to_le_bytes());
    Hash::from_bytes(&b).expect("valid dummy hash")
}

#[test]
fn test_cli_compaction_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("compaction")
        .arg("status")
        .output()
        .expect("execute velcrux compaction status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Autonomous Storage Tiering & Compaction Engine Status"));
    assert!(stdout.contains("Hot Tier (NVMe):"));
    assert!(stdout.contains("Warm Tier (SSD):"));
    assert!(stdout.contains("Cold Tier (Mesh):"));
    assert!(stdout.contains("Glacier Tier (Archive):"));
    assert!(stdout.contains("Tracked Chunks:"));
    assert!(stdout.contains("Reclaimed Bytes:"));
    assert!(stdout.contains("Total Migrations:"));
}

#[test]
fn test_cli_compaction_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("--json")
        .arg("compaction")
        .arg("status")
        .output()
        .expect("execute velcrux --json compaction status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("parse json output from velcrux compaction status");

    assert!(json_val.get("policy").is_some());
    assert!(json_val.get("total_records").is_some());
    assert!(json_val.get("hot_chunks").is_some());
    assert!(json_val.get("reclaimed_bytes_total").is_some());
}

#[test]
fn test_cli_compaction_heatmap() {
    let dir = tempdir().expect("create tempdir");

    // Pre-populate some chunks
    {
        let mut engine = AutonomousCompactionEngine::new(
            CompactionPolicy::default(),
            Some(dir.path().to_path_buf()),
        );
        let h1 = dummy_hash(111);
        let h2 = dummy_hash(222);
        engine.register_chunk(h1, 4096, ChunkTemperature::Hot);
        engine.register_chunk(h2, 8192, ChunkTemperature::Warm);
        engine.record_access(&h1, 4096);
        engine.save_state().expect("save initial state");
    }

    let output = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("compaction")
        .arg("heatmap")
        .arg("--limit")
        .arg("5")
        .output()
        .expect("execute velcrux compaction heatmap");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CAS Chunk Access Heatmap"));
    assert!(stdout.contains("Score:"));
    assert!(stdout.contains("HOT"));

    // Also verify JSON mode
    let json_output = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("compaction")
        .arg("heatmap")
        .arg("--json")
        .output()
        .expect("execute velcrux compaction heatmap --json");

    assert!(json_output.status.success());
    let list: Vec<serde_json::Value> =
        serde_json::from_slice(&json_output.stdout).expect("parse json list from heatmap");
    assert_eq!(list.len(), 2);
}

#[test]
fn test_cli_compaction_manual_migration() {
    let dir = tempdir().expect("create tempdir");
    let h1 = dummy_hash(333);

    // Register chunk in Hot tier
    {
        let mut engine = AutonomousCompactionEngine::new(
            CompactionPolicy::default(),
            Some(dir.path().to_path_buf()),
        );
        engine.register_chunk(h1, 65536, ChunkTemperature::Hot);
        engine.save_state().expect("save state");
    }

    // Migrate manually to glacier
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("compaction")
        .arg("migrate")
        .arg("--chunk")
        .arg(h1.to_hex())
        .arg("--to-tier")
        .arg("glacier")
        .output()
        .expect("execute velcrux compaction migrate");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Manual Chunk Migration Executed"));
    assert!(stdout.contains("Target Tier: glacier"));

    // Verify in status JSON
    let status_out = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("--json")
        .arg("compaction")
        .arg("status")
        .output()
        .expect("execute velcrux compaction status");

    let val: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(val["glacier_chunks"].as_u64().unwrap(), 1);
    assert_eq!(val["hot_chunks"].as_u64().unwrap(), 0);
}

#[test]
fn test_cli_compaction_compact_cycle() {
    let dir = tempdir().expect("create tempdir");

    // 1. Dry run
    let dry_run_out = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("compaction")
        .arg("compact")
        .arg("--dry-run")
        .output()
        .expect("execute compaction compact --dry-run");

    assert!(dry_run_out.status.success());
    let stdout = String::from_utf8_lossy(&dry_run_out.stdout);
    assert!(stdout.contains("Zero-Copy Compaction & Garbage Collection Report"));
    assert!(stdout.contains("DRY RUN"));

    // 2. Active commit JSON
    let active_out = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("compaction")
        .arg("compact")
        .arg("--json")
        .output()
        .expect("execute compaction compact --json");

    assert!(active_out.status.success());
    let val: serde_json::Value = serde_json::from_slice(&active_out.stdout).unwrap();
    assert!(val.get("cycle_id").is_some());
    assert!(val.get("reclaimed_bytes").is_some());
    assert!(val.get("duration_nanoseconds").is_some());
}

#[test]
fn test_cli_compaction_benchmark() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_COMPACTION_DIR", dir.path())
        .arg("compaction")
        .arg("benchmark")
        .arg("--iterations")
        .arg("50")
        .output()
        .expect("execute compaction benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Autonomous Compaction Benchmark (50 iterations)"));
    assert!(stdout.contains("Heatmap Lookup Latency:"));
    assert!(stdout.contains("Tier Evaluation Latency:"));
    assert!(stdout.contains("Compaction Sweep:"));
    assert!(stdout.contains("Simulated Throughput:"));
}
