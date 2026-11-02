//! Integration tests for Option CR: Autonomous Dynamic BDP Multi-Path Re-balancing
//! with Real-Time Loss Feedback (`ADR-060`).

#![forbid(unsafe_code)]

use std::process::Command;
use tempfile::tempdir;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_bdp_rebalance_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("status")
        .output()
        .expect("execute velcrux bdp-rebalance status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Autonomous Dynamic BDP Multi-Path Re-balancing Status"));
    assert!(stdout.contains("Controller State:"));
    assert!(stdout.contains("ACTIVE (Autonomous)"));
    assert!(stdout.contains("Active Bonded Subflows:"));
    assert!(stdout.contains("Aggregate Bonded BDP:"));
}

#[test]
fn test_cli_bdp_rebalance_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute velcrux bdp-rebalance status --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse status JSON");

    assert_eq!(json["enabled"], true);
    assert_eq!(json["active_subflows_count"], 4);
    assert!(json["aggregate_bdp_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_bdp_rebalance_subflows() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("subflows")
        .arg("--json")
        .output()
        .expect("execute velcrux bdp-rebalance subflows --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse subflows JSON");

    let subflows = json.as_array().expect("subflows array");
    assert_eq!(subflows.len(), 4);

    let ids: Vec<&str> = subflows
        .iter()
        .map(|s| s["path_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"wan-fiber-primary"));
    assert!(ids.contains(&"wan-ethernet-secondary"));
    assert!(ids.contains(&"wan-starlink-backup"));
    assert!(ids.contains(&"wan-cellular-5g"));
}

#[test]
fn test_cli_bdp_rebalance_evaluate() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("evaluate")
        .arg("--json")
        .output()
        .expect("execute velcrux bdp-rebalance evaluate --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse evaluate JSON");

    assert!(json["aggregate_bdp_bytes"].as_u64().unwrap() > 0);
    let allocations = json["allocations"].as_array().expect("allocations");
    assert_eq!(allocations.len(), 4);
    assert!(json["rebalance_latency_nanos"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_bdp_rebalance_deflect() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("deflect")
        .arg("--from")
        .arg("wan-starlink-backup")
        .arg("--to")
        .arg("wan-fiber-primary")
        .arg("--json")
        .output()
        .expect("execute velcrux bdp-rebalance deflect --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse deflect JSON");

    assert_eq!(json["status"], "deflected");
    assert_eq!(json["from_path"], "wan-starlink-backup");
    assert_eq!(json["to_path"], "wan-fiber-primary");
    assert_eq!(json["total_deflections"], 1);

    // Verify subflows reflect Deflecting state
    let subflow_out = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("subflows")
        .arg("--json")
        .output()
        .expect("execute velcrux bdp-rebalance subflows");

    assert!(subflow_out.status.success());
    let subflow_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&subflow_out.stdout)).expect("parse json");
    let starlink = subflow_json
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["path_id"] == "wan-starlink-backup")
        .expect("find starlink");
    assert_eq!(starlink["congestion_state"], "deflecting");
}

#[test]
fn test_cli_bdp_rebalance_reset() {
    let dir = tempdir().expect("create tempdir");

    // 1. Deflect a subflow first
    let _ = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("deflect")
        .arg("--from")
        .arg("wan-cellular-5g")
        .output();

    // 2. Reset back to nominal
    let reset_out = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("reset")
        .arg("--json")
        .output()
        .expect("execute reset");

    assert!(reset_out.status.success());
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&reset_out.stdout)).expect("parse json");
    assert_eq!(json["status"], "reset");
    assert_eq!(json["nominal"], true);

    // 3. Verify subflows are nominal
    let list_out = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("subflows")
        .arg("--json")
        .output()
        .expect("execute list");
    let subflows: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&list_out.stdout)).expect("parse json");

    for s in subflows.as_array().unwrap() {
        assert_eq!(s["congestion_state"], "nominal");
    }
}

#[test]
fn test_cli_bdp_rebalance_benchmark() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_BDP_REBALANCE_DIR", dir.path())
        .arg("bdp-rebalance")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .arg("--subflows")
        .arg("4")
        .arg("--json")
        .output()
        .expect("execute velcrux bdp-rebalance benchmark --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse benchmark JSON");

    assert_eq!(json["iterations"], 20);
    assert_eq!(json["subflow_count"], 4);
    assert!(json["feedback_ingestion_latency_ns"].as_f64().unwrap() > 0.0);
    assert!(json["d_dwrr_rebalance_calc_latency_ns"].as_f64().unwrap() > 0.0);
    assert!(json["proactive_deflection_latency_ns"].as_f64().unwrap() > 0.0);
    assert!(json["throughput_cycles_per_sec"].as_f64().unwrap() > 0.0);
}
