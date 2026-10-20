//! Integration tests for Option BR: Adaptive Bandwidth Delay Product (BDP)
//! Auto-Tuning Engine with QUIC Congestion Control Feedback Loop (`ADR-034`).

#![forbid(unsafe_code)]

use std::fs;
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
fn test_cli_bdp_inspect_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("bdp")
        .arg("inspect")
        .arg("--bdp-tuning")
        .arg("auto")
        .output()
        .expect("execute bdp inspect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== BDP Transport Flow Control Status ==="));
    assert!(stdout.contains("Tuning Policy:           auto"));
    assert!(stdout.contains("Current Active Window:"));
    assert!(stdout.contains("Target Optimal Window:"));
    assert!(stdout.contains("Network Delay Tier:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("bdp")
        .arg("inspect")
        .arg("--json")
        .output()
        .expect("execute bdp inspect json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse bdp inspect json");
    assert_eq!(val["policy"].as_str().unwrap(), "auto");
    assert!(val["current_window_bytes"].as_u64().unwrap() > 0);
    assert!(val["max_window_bytes"].as_u64().unwrap() >= 512 * 1024 * 1024);
}

#[test]
fn test_cli_bdp_simulate_transatlantic() {
    let output = Command::new(velcrux_bin())
        .arg("bdp")
        .arg("simulate")
        .arg("--bandwidth")
        .arg("10Gbps")
        .arg("--rtt-ms")
        .arg("150")
        .arg("--policy")
        .arg("aggressive")
        .output()
        .expect("execute bdp simulate");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== BDP Auto-Tuning Simulation Report ==="));
    assert!(stdout.contains("Link Bandwidth:          10Gbps"));
    assert!(stdout.contains("Path RTT:                150 ms"));
    assert!(stdout.contains("Tuning Policy:           aggressive"));
    assert!(stdout.contains("Classified Tier:         Transatlantic (100-200ms)"));
    assert!(stdout.contains("Converged Window:"));

    // JSON simulation output
    let json_out = Command::new(velcrux_bin())
        .arg("bdp")
        .arg("simulate")
        .arg("--bandwidth")
        .arg("10Gbps")
        .arg("--rtt-ms")
        .arg("150")
        .arg("--json")
        .output()
        .expect("execute bdp simulate json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse json simulation");
    assert_eq!(val["tier"].as_str().unwrap(), "transatlantic");
    assert!(val["current_window_bytes"].as_u64().unwrap() >= 64 * 1024 * 1024);
}

#[test]
fn test_cli_bdp_simulate_conservative_decay() {
    let output = Command::new(velcrux_bin())
        .arg("bdp")
        .arg("simulate")
        .arg("--bandwidth")
        .arg("100Mbps")
        .arg("--rtt-ms")
        .arg("250")
        .arg("--loss-pct")
        .arg("5.0")
        .arg("--policy")
        .arg("conservative")
        .output()
        .expect("execute bdp simulate conservative");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== BDP Auto-Tuning Simulation Report ==="));
    assert!(stdout.contains("Tuning Policy:           conservative"));
    assert!(stdout.contains("Classified Tier:         Satellite (>200ms)"));
}

#[test]
fn test_cli_sync_with_bdp_tuning_flags() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    let file_src = src.join("large_payload.bin");
    let sample = vec![0x42u8; 128 * 1024];
    fs::write(&file_src, &sample).unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .arg("--bdp-tuning")
        .arg("aggressive")
        .arg("--max-bdp-window")
        .arg("268435456")
        .arg("--min-bdp-window")
        .arg("4194304")
        .output()
        .expect("sync with bdp tuning");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dst_file = dst.join("large_payload.bin");
    assert!(dst_file.exists());
    assert_eq!(fs::read(&dst_file).unwrap(), sample);
}
