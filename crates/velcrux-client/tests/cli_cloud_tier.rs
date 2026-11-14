//! CLI Integration tests for Option DK: Autonomous Multi-Cloud Object Storage Tiering & Compaction (`ADR-079`).

#![forbid(unsafe_code)]

use std::process::Command;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_cloud_tier_status_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("status")
        .output()
        .expect("execute cloud-tier status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX MULTI-CLOUD OBJECT STORAGE TIERING & COMPACTION STATUS"));
    assert!(stdout.contains("Configured Endpoints:   4"));
    assert!(stdout.contains("aws-us-east-1"));
    assert!(stdout.contains("gcs-eu-west1"));
    assert!(stdout.contains("azure-eastus"));
    assert!(stdout.contains("local-nvme-tier"));
    assert!(stdout.contains("Compacted Containers:"));
    assert!(stdout.contains("Estimated Cloud Cost:"));

    // 2. JSON mode
    let json_out = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute cloud-tier status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse cloud-tier status json");
    assert_eq!(val["active_endpoints"].as_u64().unwrap(), 4);
    assert!(val["total_compacted_containers"].as_u64().unwrap() >= 2);
    assert!(val["total_indexed_chunks"].as_u64().unwrap() >= 25);
    assert!(val["endpoints"].as_array().unwrap().len() == 4);
}

#[test]
fn test_cli_cloud_tier_compact_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("compact")
        .arg("--target-tier")
        .arg("cool")
        .output()
        .expect("execute cloud-tier compact");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX CLOUD CONTAINER COMPACTION & REPACKING COMPLETE"));
    assert!(stdout.contains("Target Storage Tier:    cool"));

    // 2. JSON mode
    let json_out = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("compact")
        .arg("--target-tier")
        .arg("hot")
        .arg("--json")
        .output()
        .expect("execute cloud-tier compact json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse cloud-tier compact json");
    assert_eq!(val["target_tier"].as_str().unwrap(), "hot");
    assert_eq!(val["total_containers"].as_u64().unwrap(), 1);
    assert_eq!(val["total_indexed_chunks"].as_u64().unwrap(), 30);
}

#[test]
fn test_cli_cloud_tier_read_and_hydrate() {
    let dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // 1. Read
    let read_out = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("read")
        .arg("--chunk")
        .arg(dummy_hash)
        .arg("--json")
        .output()
        .expect("execute cloud-tier read json");

    assert!(read_out.status.success());
    let r_val: serde_json::Value = serde_json::from_slice(&read_out.stdout).unwrap();
    assert_eq!(r_val["chunk_hash"].as_str().unwrap(), dummy_hash);

    // 2. Hydrate
    let hyd_out = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("hydrate")
        .arg("--chunk")
        .arg(dummy_hash)
        .arg("--retrieval-tier")
        .arg("expedited")
        .arg("--json")
        .output()
        .expect("execute cloud-tier hydrate json");

    assert!(hyd_out.status.success());
    let h_val: serde_json::Value = serde_json::from_slice(&hyd_out.stdout).unwrap();
    assert_eq!(h_val["priority"].as_str().unwrap(), "expedited");
    assert_eq!(h_val["status"].as_str().unwrap(), "hydrated_ready_in_cache");
}

#[test]
fn test_cli_cloud_tier_benchmark_text_and_json() {
    let output = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("benchmark")
        .arg("--chunks")
        .arg("50")
        .output()
        .expect("execute cloud-tier benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX CLOUD CONTAINER COMPACTION & RANGE-GET BENCHMARK"));
    assert!(stdout.contains("Chunks Processed:       50 chunks"));
    assert!(stdout.contains("Compaction Throughput:"));
    assert!(stdout.contains("Range-GET Throughput:"));

    let json_out = Command::new(velcrux_bin())
        .arg("cloud-tier")
        .arg("benchmark")
        .arg("--chunks")
        .arg("60")
        .arg("--json")
        .output()
        .expect("execute cloud-tier benchmark json");

    assert!(json_out.status.success());
    let val: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(val["chunks"].as_u64().unwrap(), 60);
    assert!(val["read_iops"].as_f64().unwrap() > 0.0);
}
