//! Integration tests for Option CP: Deterministic Network Emulation &
//! Jitter Harness for Chaos Sync Verification (`ADR-058`).

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
fn test_cli_netem_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("netem")
        .arg("status")
        .output()
        .expect("execute velcrux netem status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Network Emulation & Jitter Harness Status"));
    assert!(stdout.contains("Status:"));
    assert!(stdout.contains("Base Delay:"));
    assert!(stdout.contains("Delay Jitter:"));
    assert!(stdout.contains("Packet Loss:"));
    assert!(stdout.contains("Packets Processed:"));
}

#[test]
fn test_cli_netem_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("--json")
        .arg("netem")
        .arg("status")
        .output()
        .expect("execute velcrux --json netem status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("parse json output from velcrux netem status");

    assert!(json_val.get("config").is_some());
    assert!(json_val.get("metrics").is_some());
}

#[test]
fn test_cli_netem_apply_preset() {
    let dir = tempdir().expect("create tempdir");

    // Apply Starlink preset
    let apply_out = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("netem")
        .arg("apply")
        .arg("--profile")
        .arg("starlink-satellite")
        .arg("--seed")
        .arg("42")
        .output()
        .expect("apply preset");

    assert!(apply_out.status.success());
    let apply_stdout = String::from_utf8_lossy(&apply_out.stdout);
    assert!(apply_stdout.contains("Network Emulation Profile Applied"));
    assert!(apply_stdout.contains("Preset:             starlink-satellite"));
    assert!(apply_stdout.contains("Status:             ACTIVE"));

    // Query status to verify persistence
    let status_out = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("--json")
        .arg("netem")
        .arg("status")
        .output()
        .expect("query status");

    assert!(status_out.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["config"]["enabled"].as_bool(), Some(true));
    assert_eq!(
        status_json["config"]["preset_name"].as_str(),
        Some("starlink-satellite")
    );
    assert!(status_json["config"]["delay_ms"].as_f64().unwrap() > 0.0);
}

#[test]
fn test_cli_netem_apply_custom_params() {
    let dir = tempdir().expect("create tempdir");

    let apply_out = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("--json")
        .arg("netem")
        .arg("apply")
        .arg("--delay-ms")
        .arg("45.5")
        .arg("--jitter-ms")
        .arg("8.2")
        .arg("--distribution")
        .arg("pareto")
        .arg("--loss-percent")
        .arg("3.5")
        .arg("--reorder-percent")
        .arg("1.2")
        .arg("--bandwidth-mbps")
        .arg("250.0")
        .arg("--seed")
        .arg("9999")
        .output()
        .expect("apply custom");

    assert!(apply_out.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&apply_out.stdout).unwrap();
    assert_eq!(json_val["enabled"].as_bool(), Some(true));
    assert_eq!(json_val["delay_ms"].as_f64(), Some(45.5));
    assert_eq!(json_val["jitter_ms"].as_f64(), Some(8.2));
    assert_eq!(json_val["loss_percent"].as_f64(), Some(3.5));
    assert_eq!(json_val["reorder_percent"].as_f64(), Some(1.2));
    assert_eq!(json_val["bandwidth_mbps"].as_f64(), Some(250.0));
    assert_eq!(json_val["prng_seed"].as_u64(), Some(9999));
}

#[test]
fn test_cli_netem_clear() {
    let dir = tempdir().expect("create tempdir");

    // First apply a profile
    Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("netem")
        .arg("apply")
        .arg("--profile")
        .arg("rural-cellular-5g")
        .output()
        .expect("apply profile");

    // Now clear
    let clear_out = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("netem")
        .arg("clear")
        .output()
        .expect("clear netem");

    assert!(clear_out.status.success());
    let clear_stdout = String::from_utf8_lossy(&clear_out.stdout);
    assert!(clear_stdout.contains("Network Emulation Cleared"));

    // Check status is disabled
    let status_out = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("--json")
        .arg("netem")
        .arg("status")
        .output()
        .expect("status check");
    let status_json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["config"]["enabled"].as_bool(), Some(false));
}

#[test]
fn test_cli_netem_simulate() {
    let dir = tempdir().expect("create tempdir");

    // Apply Transatlantic WAN preset
    Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("netem")
        .arg("apply")
        .arg("--profile")
        .arg("transatlantic-wan")
        .arg("--seed")
        .arg("1234")
        .output()
        .expect("apply wan");

    // Simulate traffic
    let sim_out = Command::new(velcrux_bin())
        .env("VELCRUX_NETEM_DIR", dir.path())
        .arg("--json")
        .arg("netem")
        .arg("simulate")
        .arg("--packets")
        .arg("100")
        .arg("--size")
        .arg("1024")
        .output()
        .expect("simulate traffic");

    assert!(sim_out.status.success());
    let sim_json: serde_json::Value = serde_json::from_slice(&sim_out.stdout).unwrap();
    assert_eq!(sim_json["total_packets"].as_u64(), Some(100));
    assert!(sim_json["delivered"].as_u64().unwrap() >= 90);
    assert!(sim_json["delivery_ratio"].as_f64().unwrap() > 90.0);
    assert!(sim_json["min_rtt_ms"].as_f64().unwrap() > 50.0);
}

#[test]
fn test_cli_netem_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("netem")
        .arg("benchmark")
        .arg("--iterations")
        .arg("50")
        .output()
        .expect("execute benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Deterministic Network Emulation Microsecond Benchmark"));
    assert!(stdout.contains("Iterations:          50"));
    assert!(stdout.contains("Jitter Calc Latency:"));
    assert!(stdout.contains("Markov Loss Latency:"));
    assert!(stdout.contains("Enqueue Latency:"));
    assert!(stdout.contains("Dequeue Latency:"));
    assert!(stdout.contains("Throughput:"));
}
