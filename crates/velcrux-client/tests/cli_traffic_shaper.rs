//! Integration tests for Option DB: Autonomous AI/ML Transfer Anomaly Detection
//! & Self-Healing Traffic Shaper (`ADR-070`).

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
fn test_cli_traffic_status_text_and_json() {
    // 1. Human-readable text format
    let output = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("status")
        .output()
        .expect("execute traffic status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Autonomous AI/ML Transfer Anomaly Detection & Traffic Shaper ==="));
    assert!(stdout.contains("Baseline Capacity:"));
    assert!(stdout.contains("Current Pacing Rate:"));
    assert!(stdout.contains("Current FEC Parity:"));
    assert!(stdout.contains("Anomaly Score:"));
    assert!(stdout.contains("Telemetry Window Size:"));

    // 2. Machine-readable JSON format
    let json_out = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute traffic status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse traffic status json");
    assert!(val["baseline_capacity_bps"].as_f64().is_some());
    assert!(val["current_pacing_bps"].as_f64().is_some());
    assert!(val["current_fec_ratio"].as_f64().is_some());
    assert!(val["current_anomaly_score"].as_f64().is_some());
    assert!(val["total_mitigations_applied"].as_u64().is_some());
}

#[test]
fn test_cli_traffic_incidents_text_and_json() {
    // 1. Text format
    let output = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("incidents")
        .arg("--limit")
        .arg("5")
        .output()
        .expect("execute traffic incidents");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Network Transport Anomaly Incident Log ==="));
    assert!(stdout.contains("Total Incidents Displayed:"));
    assert!(stdout.contains("Incident ID:"));
    assert!(stdout.contains("Classification:"));
    assert!(stdout.contains("Severity:"));
    assert!(stdout.contains("Mitigation Action:"));

    // 2. JSON format
    let json_out = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("incidents")
        .arg("--limit")
        .arg("3")
        .arg("--json")
        .output()
        .expect("execute traffic incidents json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse traffic incidents json");
    assert!(val.as_array().is_some());
    let arr = val.as_array().unwrap();
    assert!(!arr.is_empty());
    assert!(arr[0]["incident_id"].as_str().is_some());
    assert!(arr[0]["anomaly_type"].as_str().is_some());
    assert!(arr[0]["mitigation_action"].as_str().is_some());
}

#[test]
fn test_cli_traffic_bench_text_and_json() {
    // 1. Text format with synthetic Bufferbloat injection
    let output = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("bench")
        .arg("--samples")
        .arg("30")
        .arg("--inject")
        .arg("bufferbloat")
        .output()
        .expect("execute traffic bench");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Autonomous Anomaly Detection & Self-Healing Benchmark ==="));
    assert!(stdout.contains("Total Streamed Samples: 30"));
    assert!(stdout.contains("Anomalies Injected:"));
    assert!(stdout.contains("Anomalies Detected:"));
    assert!(stdout.contains("Detection Accuracy:"));
    assert!(stdout.contains("Avg Anomaly Score:"));
    assert!(stdout.contains("Execution Elapsed:"));

    // 2. JSON format with link degradation
    let json_out = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("bench")
        .arg("--samples")
        .arg("25")
        .arg("--inject")
        .arg("link_degradation")
        .arg("--json")
        .output()
        .expect("execute traffic bench json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse traffic bench json");
    assert_eq!(val["total_samples"], 25);
    assert!(val["anomalies_detected"].as_u64().unwrap() > 0);
    assert!(val["accuracy_percent"].as_f64().unwrap() > 0.0);
    assert!(val["final_pacing_bps"].as_f64().is_some());
}

#[test]
fn test_cli_traffic_tune_text_and_json() {
    // 1. Text format
    let output = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("tune")
        .arg("--sensitivity")
        .arg("0.75")
        .output()
        .expect("execute traffic tune");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Anomaly Detection Sensitivity Tuned ==="));
    assert!(stdout.contains("Anomaly Score Threshold: 0.75"));
    assert!(stdout.contains("Isolation Forest Trees:  25"));
    assert!(stdout.contains("Status:                  UPDATED"));

    // 2. JSON format
    let json_out = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("tune")
        .arg("--sensitivity")
        .arg("0.80")
        .arg("--json")
        .output()
        .expect("execute traffic tune json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse traffic tune json");
    assert_eq!(val["status"], "CONFIGURED");
    assert_eq!(val["anomaly_score_threshold"], 0.80);
    assert_eq!(val["isolation_forest_trees"], 25);
}

#[test]
fn test_cli_traffic_prometheus() {
    let output = Command::new(velcrux_bin())
        .arg("traffic")
        .arg("prometheus")
        .output()
        .expect("execute traffic prometheus");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("velcrux_traffic_anomaly_score"));
    assert!(stdout.contains("velcrux_traffic_pacing_rate_bps"));
    assert!(stdout.contains("velcrux_traffic_fec_redundancy_ratio"));
    assert!(stdout.contains("velcrux_traffic_incidents_total"));
    assert!(stdout.contains("velcrux_traffic_mitigations_total"));
}
