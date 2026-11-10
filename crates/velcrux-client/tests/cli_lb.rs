//! Integration tests for Option DH: Autonomous L4/L7 Hardware Load Balancer & Maglev Consistent Hashing Multiplexing Engine (`ADR-076`).

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
fn test_cli_lb_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("lb")
        .arg("status")
        .output()
        .expect("execute lb status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AUTONOMOUS L4/L7 MAGLEV LOAD BALANCER DIRECTOR STATUS"));
    assert!(stdout.contains("Default Pool:           default-storage"));
    assert!(stdout.contains("Registered Pools:       2"));
    assert!(stdout.contains("Total Backends:         6"));
    assert!(stdout.contains("Active Tracked Flows:"));
    assert!(stdout.contains("default-storage"));
    assert!(stdout.contains("vip-tenant-pool"));
    assert!(stdout.contains("storage-node-01"));
    assert!(stdout.contains("vip-node-01"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("lb")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute lb status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse lb status json");
    assert_eq!(val["default_pool"].as_str().unwrap(), "default-storage");
    assert_eq!(val["total_pools"].as_u64().unwrap(), 2);
    assert_eq!(val["total_nodes"].as_u64().unwrap(), 6);
    assert!(val["active_tracked_flows"].as_u64().unwrap() >= 4);

    let pools = val["pools"].as_array().expect("pools array");
    assert_eq!(pools.len(), 2);
    let nodes = val["nodes"].as_array().expect("nodes array");
    assert_eq!(nodes.len(), 6);
}

#[test]
fn test_cli_lb_lookup_text_and_json() {
    // 1. Text output - default traffic
    let output = Command::new(velcrux_bin())
        .arg("lb")
        .arg("lookup")
        .arg("--src")
        .arg("192.168.10.50:52100")
        .arg("--dst")
        .arg("10.0.0.1:7443")
        .arg("--proto")
        .arg("quic")
        .output()
        .expect("execute lb lookup");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("L4/L7 MAGLEV CONSISTENT HASHING FLOW LOOKUP RESULT"));
    assert!(stdout.contains("192.168.10.50:52100 -> 10.0.0.1:7443 (QUIC)"));
    assert!(stdout.contains("Target Cluster Pool:  default-storage"));
    assert!(stdout.contains("Assigned Backend:     storage-node-"));
    assert!(stdout.contains("Maglev Table Slot:"));

    // 2. JSON output - L7 VIP tenant rule
    let json_out = Command::new(velcrux_bin())
        .arg("lb")
        .arg("lookup")
        .arg("--src")
        .arg("172.16.0.10:44120")
        .arg("--dst")
        .arg("10.0.0.1:7443")
        .arg("--tenant")
        .arg("vip-corporate-transfer")
        .arg("--json")
        .output()
        .expect("execute lb lookup json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse lb lookup json");
    assert_eq!(val["protocol"].as_str().unwrap(), "QUIC");
    assert_eq!(val["target_pool"].as_str().unwrap(), "vip-tenant-pool");
    assert!(val["backend_node_id"]
        .as_str()
        .unwrap()
        .starts_with("vip-node-"));
    assert_eq!(val["l7_tenant"].as_str().unwrap(), "vip-corporate-transfer");
    assert!(val["maglev_table_slot"].as_u64().unwrap() < 65537);
}

#[test]
fn test_cli_lb_members_text_and_json() {
    // 1. Text output - list members
    let output = Command::new(velcrux_bin())
        .arg("lb")
        .arg("members")
        .arg("--pool")
        .arg("default-storage")
        .arg("--action")
        .arg("list")
        .output()
        .expect("execute lb members list");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BACKEND POOL MEMBERS & MAGLEV PERMUTATION STATUS"));
    assert!(stdout.contains("Target Pool:            default-storage"));
    assert!(stdout.contains("storage-node-01"));
    assert!(stdout.contains("storage-node-04"));

    // 2. JSON output - add member mutation with churn calculation
    let json_out = Command::new(velcrux_bin())
        .arg("lb")
        .arg("members")
        .arg("--pool")
        .arg("default-storage")
        .arg("--action")
        .arg("add")
        .arg("--node")
        .arg("storage-node-05")
        .arg("--address")
        .arg("10.0.1.15:7443")
        .arg("--weight")
        .arg("100")
        .arg("--json")
        .output()
        .expect("execute lb members add json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse lb members add json");
    assert_eq!(val["pool"].as_str().unwrap(), "default-storage");
    assert_eq!(val["action_performed"].as_str().unwrap(), "add");
    let churn = val["churn_percentage"].as_f64().unwrap();
    // Adding 1 node to 4 nodes should yield ~ 18-25% churn
    assert!(churn >= 12.0 && churn <= 30.0);
    let members = val["members"].as_array().expect("members array");
    assert_eq!(members.len(), 5);

    // 3. Drain node action
    let drain_out = Command::new(velcrux_bin())
        .arg("lb")
        .arg("members")
        .arg("--pool")
        .arg("default-storage")
        .arg("--action")
        .arg("drain")
        .arg("--node")
        .arg("storage-node-02")
        .arg("--json")
        .output()
        .expect("execute lb members drain json");

    assert!(drain_out.status.success());
    let drain_val: serde_json::Value =
        serde_json::from_slice(&drain_out.stdout).expect("parse drain json");
    let drain_members = drain_val["members"].as_array().expect("members array");
    let drained_node = drain_members
        .iter()
        .find(|m| m["id"].as_str().unwrap() == "storage-node-02")
        .expect("found node");
    assert_eq!(drained_node["status"].as_str().unwrap(), "DRAINING");
    assert_eq!(drained_node["slot_count"].as_u64().unwrap(), 0);
}

#[test]
fn test_cli_lb_benchmark_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("lb")
        .arg("benchmark")
        .arg("--iterations")
        .arg("5000")
        .arg("--nodes")
        .arg("8")
        .output()
        .expect("execute lb benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AUTONOMOUS MAGLEV LOAD BALANCER MICROSECOND BENCHMARK"));
    assert!(stdout.contains("Backend Nodes Count:    8"));
    assert!(stdout.contains("Table Capacity (M):     65537 slots (Prime)"));
    assert!(stdout.contains("Lookup Throughput:"));
    assert!(stdout.contains("Addition Churn:"));
    assert!(stdout.contains("VERIFIED PASS"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("lb")
        .arg("benchmark")
        .arg("--iterations")
        .arg("5000")
        .arg("--nodes")
        .arg("8")
        .arg("--json")
        .output()
        .expect("execute lb benchmark json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse lb benchmark json");
    assert_eq!(val["nodes_simulated"].as_u64().unwrap(), 8);
    assert_eq!(val["lookup_iterations"].as_u64().unwrap(), 5000);
    assert_eq!(val["table_size_m"].as_u64().unwrap(), 65537);
    assert!(val["lookup_throughput_ops_per_sec"].as_f64().unwrap() > 50_000.0);
    assert!(val["disruption_compliant"].as_bool().unwrap());
}
