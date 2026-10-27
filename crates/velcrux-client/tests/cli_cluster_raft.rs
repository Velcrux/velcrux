//! Integration tests for Distributed Raft Consensus & Cluster Coordinator CLI (Option BZ).

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
fn test_cli_cluster_raft_status_table() {
    let output = Command::new(velcrux_bin())
        .arg("cluster")
        .arg("status")
        .arg("--raft")
        .output()
        .expect("execute velcrux cluster status --raft");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("VELCRUX DISTRIBUTED RAFT CONSENSUS & CLUSTER STATUS"));
    assert!(stdout.contains("Node ID              : node-1"));
    assert!(stdout.contains("Role                 : Leader"));
    assert!(stdout.contains("Current Term         : 1"));
    assert!(stdout.contains("Leader ID            : node-1"));
    assert!(stdout.contains("Quorum Health        : Quorum OK"));
}

#[test]
fn test_cli_cluster_raft_status_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("status")
        .arg("--raft")
        .output()
        .expect("execute velcrux --json cluster status --raft");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("valid JSON expected from --json cluster status --raft");

    assert_eq!(json_val["node_id"], "node-1");
    assert_eq!(json_val["role"], "leader");
    assert_eq!(json_val["term"], 1);
    assert_eq!(json_val["leader_id"], "node-1");
    assert_eq!(json_val["is_leader"], true);
    assert_eq!(json_val["peer_count"], 2);
}

#[test]
fn test_cli_cluster_join_and_leave() {
    // Join
    let join_output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("join")
        .arg("node-4")
        .arg("--address")
        .arg("127.0.0.1:8004")
        .output()
        .expect("execute velcrux cluster join");

    assert!(
        join_output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&join_output.stderr)
    );
    let join_json: serde_json::Value =
        serde_json::from_slice(&join_output.stdout).expect("valid JSON expected from join");
    assert_eq!(join_json["status"], "committed");
    assert_eq!(join_json["action"], "join");
    assert_eq!(join_json["node_id"], "node-4");
    assert_eq!(join_json["address"], "127.0.0.1:8004");

    // Leave
    let leave_output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("leave")
        .arg("node-4")
        .output()
        .expect("execute velcrux cluster leave");

    assert!(
        leave_output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&leave_output.stderr)
    );
    let leave_json: serde_json::Value =
        serde_json::from_slice(&leave_output.stdout).expect("valid JSON expected from leave");
    assert_eq!(leave_json["status"], "committed");
    assert_eq!(leave_json["action"], "leave");
    assert_eq!(leave_json["node_id"], "node-4");
}

#[test]
fn test_cli_cluster_elect() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("elect")
        .arg("--candidate")
        .arg("node-2")
        .arg("--peers")
        .arg("node-1,node-2,node-3")
        .output()
        .expect("execute velcrux cluster elect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from elect");

    assert_eq!(json_val["candidate"], "node-2");
    assert_eq!(json_val["elected"], true);
    assert_eq!(json_val["votes_granted"], 3);
    assert_eq!(json_val["quorum_needed"], 2);
    assert_eq!(json_val["role"], "Leader");
}

#[test]
fn test_cli_cluster_lease_lifecycle() {
    // 1. Acquire
    let acquire_output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("lease")
        .arg("acquire")
        .arg("transfer-lock-10")
        .arg("--holder")
        .arg("node-1")
        .arg("--ttl-ms")
        .arg("10000")
        .output()
        .expect("execute velcrux cluster lease acquire");

    assert!(
        acquire_output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&acquire_output.stderr)
    );
    let acq_json: serde_json::Value =
        serde_json::from_slice(&acquire_output.stdout).expect("valid JSON from lease acquire");
    assert_eq!(acq_json["resource"], "transfer-lock-10");
    assert_eq!(acq_json["holder"], "node-1");
    assert_eq!(acq_json["epoch"], 1);

    // 2. List
    let list_output = Command::new(velcrux_bin())
        .arg("cluster")
        .arg("lease")
        .arg("list")
        .output()
        .expect("execute velcrux cluster lease list");

    assert!(list_output.status.success());
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_stdout.contains("metadata/root"));

    // 3. Release
    let rel_output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("lease")
        .arg("release")
        .arg("transfer-lock-10")
        .arg("--holder")
        .arg("node-1")
        .output()
        .expect("execute velcrux cluster lease release");

    assert!(rel_output.status.success());
    let rel_json: serde_json::Value =
        serde_json::from_slice(&rel_output.stdout).expect("valid JSON from lease release");
    assert_eq!(rel_json["status"], "released");
    assert_eq!(rel_json["resource"], "transfer-lock-10");
}

#[test]
fn test_cli_cluster_raft_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("cluster")
        .arg("benchmark")
        .arg("--nodes")
        .arg("3")
        .arg("--rounds")
        .arg("10")
        .output()
        .expect("execute velcrux cluster benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from cluster benchmark");

    assert_eq!(json_val["nodes"], 3);
    assert_eq!(json_val["proposals"], 10);
    assert!(json_val["committed_entries"].as_u64().unwrap() >= 10);
    assert_eq!(json_val["partition_recovered"], true);
    assert!(json_val["throughput_proposals_per_sec"].as_f64().unwrap() > 0.0);
}
