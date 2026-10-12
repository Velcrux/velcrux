//! Integration tests for Distributed Chunk Store Cluster CLI (Option AY).

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
fn test_cli_cluster_status_table() {
    let output = Command::new(velcrux_bin())
        .arg("cluster")
        .arg("status")
        .output()
        .expect("execute velcrux cluster status");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("VELCRUX DISTRIBUTED CHUNK STORE CLUSTER STATUS"));
    assert!(stdout.contains("Total Nodes          : 3"));
    assert!(stdout.contains("Healthy Nodes        : 3"));
    assert!(stdout.contains("Strict Consistency (W + R > N: guaranteed overlap)"));
    assert!(stdout.contains("NODE ID"));
    assert!(stdout.contains("ADDRESS"));
    assert!(stdout.contains("STATE"));
    assert!(stdout.contains("node-1"));
    assert!(stdout.contains("node-2"));
    assert!(stdout.contains("node-3"));
}

#[test]
fn test_cli_cluster_status_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("status")
        .output()
        .expect("execute velcrux --json cluster status");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json cluster status");

    assert_eq!(json_val["total_nodes"], 3);
    assert_eq!(json_val["healthy_nodes"], 3);
    assert_eq!(json_val["is_strictly_consistent"], true);
    assert_eq!(json_val["quorum"]["replicas"], 3);
    assert_eq!(json_val["quorum"]["write_quorum"], 2);
    assert_eq!(json_val["quorum"]["read_quorum"], 2);
    assert!(json_val["nodes"].is_array());
    assert_eq!(json_val["nodes"].as_array().unwrap().len(), 3);
}

#[test]
fn test_cli_cluster_custom_nodes_and_weak_consistency() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("status")
        .arg("--nodes")
        .arg("127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004")
        .arg("--replicas")
        .arg("4")
        .arg("--write-quorum")
        .arg("2")
        .arg("--read-quorum")
        .arg("2")
        .output()
        .expect("execute velcrux cluster status custom");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected");

    assert_eq!(json_val["total_nodes"], 4);
    // W=2, R=2, N=4 => W+R = 4 which is NOT > 4, so is_strictly_consistent is false
    assert_eq!(json_val["is_strictly_consistent"], false);
}

#[test]
fn test_cli_cluster_rebalance() {
    let output = Command::new(velcrux_bin())
        .arg("cluster")
        .arg("rebalance")
        .output()
        .expect("execute velcrux cluster rebalance");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Anti-Entropy Rebalance Summary:"));
    assert!(stdout.contains("Rebalance Status       : OK"));
}

#[test]
fn test_cli_cluster_rebalance_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("rebalance")
        .output()
        .expect("execute velcrux --json cluster rebalance");

    assert!(output.status.success(), "stderr: {:?}", String::from_utf8_lossy(&output.stderr));
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected");
    assert!(json_val["chunks_inspected"].is_number());
    assert!(json_val["replicas_created"].is_number());
    assert!(json_val["fully_replicated_chunks"].is_number());
}
