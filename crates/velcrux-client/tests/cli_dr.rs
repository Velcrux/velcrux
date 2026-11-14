//! CLI Integration tests for Option DL: Autonomous Multi-Cluster Global Disaster Recovery
//! Failover & Split-Brain Fencing Coordinator (`ADR-080`).

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
fn test_cli_dr_status_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("dr")
        .arg("status")
        .output()
        .expect("execute dr status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX GLOBAL DISASTER RECOVERY & FENCING COORDINATOR"));
    assert!(stdout.contains("Generation Epoch:"));
    assert!(stdout.contains("Active Primary:"));
    assert!(stdout.contains("us-east-1"));
    assert!(stdout.contains("eu-central-1"));
    assert!(stdout.contains("ap-southeast-1"));
    assert!(stdout.contains("witness-ord"));
    assert!(stdout.contains("witness-dub"));
    assert!(stdout.contains("witness-nrt"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("dr")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute dr status --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["active_primary"], "us-east-1");
    assert!(parsed["current_epoch"].as_u64().unwrap() >= 1000);
    assert_eq!(parsed["witness_count"], 3);
    assert_eq!(parsed["quorum_size"], 2);
    assert!(parsed["regions"].as_array().unwrap().len() >= 6);
}

#[test]
fn test_cli_dr_failover_planned_and_emergency() {
    // 1. Planned switchover to eu-central-1
    let output = Command::new(velcrux_bin())
        .arg("dr")
        .arg("failover")
        .arg("--target")
        .arg("eu-central-1")
        .output()
        .expect("execute planned failover");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX DR FAILOVER EXECUTION REPORT"));
    assert!(stdout.contains("Promoted Primary:       eu-central-1"));
    assert!(stdout.contains("PlannedSwitchover"));
    assert!(stdout.contains("SUCCESS"));

    // 2. Emergency failover JSON mode with --force
    let output_json = Command::new(velcrux_bin())
        .arg("dr")
        .arg("failover")
        .arg("--force")
        .arg("--json")
        .output()
        .expect("execute emergency failover --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["mode"], "emergency_failover");
    assert_eq!(parsed["success"], true);
    assert!(parsed["fencing_epoch"].as_u64().unwrap() > 1000);
}

#[test]
fn test_cli_dr_fence_text_and_json() {
    // 1. Text mode fence
    let output = Command::new(velcrux_bin())
        .arg("dr")
        .arg("fence")
        .arg("--cluster")
        .arg("us-east-1")
        .output()
        .expect("execute dr fence");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX CLUSTER STORAGE FENCING BARRIER"));
    assert!(stdout.contains("Fenced Cluster:         us-east-1"));
    assert!(stdout.contains("Storage Write Barrier:  ACTIVE"));
    assert!(stdout.contains("Split-Brain Guard:      ENFORCED"));

    // 2. JSON mode fence with explicit epoch
    let output_json = Command::new(velcrux_bin())
        .arg("dr")
        .arg("fence")
        .arg("--cluster")
        .arg("rogue-isolated-cluster")
        .arg("--epoch")
        .arg("1099")
        .arg("--json")
        .output()
        .expect("execute dr fence --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["fenced_cluster"], "rogue-isolated-cluster");
    assert_eq!(parsed["epoch"], 1099);
    assert_eq!(parsed["storage_barrier_active"], true);
}

#[test]
fn test_cli_dr_failback_text_and_json() {
    // 1. Text mode failback
    let output = Command::new(velcrux_bin())
        .arg("dr")
        .arg("failback")
        .arg("--target")
        .arg("eu-central-1")
        .output()
        .expect("execute dr failback");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX DR RECOVERED PRIMARY FAILBACK REPORT"));
    assert!(stdout.contains("Restored Primary:       eu-central-1"));
    assert!(stdout.contains("SUCCESS"));

    // 2. JSON mode failback
    let output_json = Command::new(velcrux_bin())
        .arg("dr")
        .arg("failback")
        .arg("--target")
        .arg("eu-central-1")
        .arg("--json")
        .output()
        .expect("execute dr failback --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["new_primary"], "eu-central-1");
    assert_eq!(parsed["success"], true);
}

#[test]
fn test_cli_dr_benchmark_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("dr")
        .arg("benchmark")
        .arg("--iterations")
        .arg("30")
        .output()
        .expect("execute dr benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX DISASTER RECOVERY & FENCING BENCHMARK REPORT"));
    assert!(stdout.contains("Simulated Iterations:   30"));
    assert!(stdout.contains("Heartbeat Probe Latency:"));
    assert!(stdout.contains("Quorum Consensus Time:"));
    assert!(stdout.contains("Write Fencing Ops/sec:"));
    assert!(stdout.contains("Split-Brain Prevented:"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("dr")
        .arg("benchmark")
        .arg("--iterations")
        .arg("30")
        .arg("--json")
        .output()
        .expect("execute dr benchmark --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["iterations"], 30);
    assert!(parsed["avg_heartbeat_latency_ns"].as_f64().unwrap() >= 0.0);
    assert!(parsed["avg_fencing_consensus_us"].as_f64().unwrap() >= 0.0);
    assert!(parsed["write_fencing_ops_per_sec"].as_f64().unwrap() > 0.0);
    assert!(parsed["split_brain_prevented_count"].as_u64().unwrap() > 0);
}
