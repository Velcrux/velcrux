//! Integration tests for Option CZ: Distributed Global Multi-Cluster Geo-Replication
//! & Conflict-Free Replicated Data Types (`ADR-068`).

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
fn test_cli_geo_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("status")
        .output()
        .expect("execute crdt status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Distributed Global Multi-Cluster Geo-Replication Status ==="));
    assert!(stdout.contains("Registered Clusters:    3"));
    assert!(stdout.contains("Active Topology:        Active-Active Multi-Master Mesh"));
    assert!(stdout.contains("State Convergence:      SYNCHRONIZED"));
    assert!(stdout.contains("us-east"));
    assert!(stdout.contains("eu-west"));
    assert!(stdout.contains("ap-se"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute crdt status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse crdt status json");
    assert_eq!(val["converged"].as_bool().unwrap(), true);
    assert_eq!(val["topology"].as_array().unwrap().len(), 3);
    assert_eq!(val["summaries"].as_array().unwrap().len(), 3);
}

#[test]
fn test_cli_geo_tree_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("tree")
        .arg("--region")
        .arg("us-east")
        .arg("--prefix")
        .arg("/")
        .output()
        .expect("execute crdt tree");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Replicated CRDT Filesystem Hierarchy (us-east) ==="));
    assert!(stdout.contains("Active Region:          us-east"));
    assert!(stdout.contains("/datasets/vision/weights.bin"));
    assert!(stdout.contains("/datasets/vision/config.json"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("tree")
        .arg("--region")
        .arg("eu-west")
        .arg("--json")
        .output()
        .expect("execute crdt tree json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse crdt tree json");
    assert_eq!(val["region_id"].as_str().unwrap(), "eu-west");
    assert!(val["nodes"].as_array().unwrap().len() >= 3);
    assert!(!val["state_digest"].as_str().unwrap().is_empty());
}

#[test]
fn test_cli_geo_sync_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("sync")
        .arg("--region-a")
        .arg("us-east")
        .arg("--region-b")
        .arg("eu-west")
        .output()
        .expect("execute crdt sync");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Anti-Entropy Gossip Synchronization Exchange ==="));
    assert!(stdout.contains("Region A:               us-east"));
    assert!(stdout.contains("Region B:               eu-west"));
    assert!(stdout.contains("Converged After:        YES (100% Identical Digest)"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("sync")
        .arg("--region-a")
        .arg("us-east")
        .arg("--region-b")
        .arg("ap-se")
        .arg("--json")
        .output()
        .expect("execute crdt sync json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse crdt sync json");
    assert_eq!(val["region_a"].as_str().unwrap(), "us-east");
    assert_eq!(val["region_b"].as_str().unwrap(), "ap-se");
    assert_eq!(val["state_converged_after"].as_bool().unwrap(), true);
    assert!(!val["final_state_digest"].as_str().unwrap().is_empty());
}

#[test]
fn test_cli_geo_bench_text_and_json() {
    // 1. Text output benchmark run
    let output = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("bench")
        .arg("--regions")
        .arg("3")
        .arg("--files")
        .arg("5")
        .arg("--simulate-partition")
        .output()
        .expect("execute crdt bench");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Distributed Geo-Replication & CRDT Convergence Benchmark ==="));
    assert!(stdout.contains("Regions Evaluated:      3"));
    assert!(stdout.contains("Concurrent Mutations:   15"));
    assert!(stdout.contains("Partition Simulated:    YES (Trans-oceanic partition & heal)"));
    assert!(stdout.contains("Fully Converged:        YES (Exact State Digest Match)"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("crdt")
        .arg("bench")
        .arg("--regions")
        .arg("2")
        .arg("--files")
        .arg("4")
        .arg("--json")
        .output()
        .expect("execute crdt bench json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse crdt bench json");
    assert_eq!(val["num_regions"].as_u64().unwrap(), 2);
    assert_eq!(val["total_mutations"].as_u64().unwrap(), 8);
    assert_eq!(val["fully_converged"].as_bool().unwrap(), true);
    assert!(val["sync_cycles"].as_u64().unwrap() >= 1);
}
