//! Integration tests for Option CL: Adaptive Predictive Network Congestion
//! & BBRv3 / Reinforcement-Learned Flow Control (`ADR-054`).

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
fn test_cli_congestion_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_CONGESTION_DIR", dir.path())
        .arg("congestion")
        .arg("status")
        .output()
        .expect("execute velcrux congestion status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("BBRv3 Adaptive Congestion Controller Status"));
    assert!(stdout.contains("BBRv3 Phase:"));
    assert!(stdout.contains("Pacing Rate:"));
    assert!(stdout.contains("Physical Min RTT:"));
    assert!(stdout.contains("Estimated BDP:"));
    assert!(stdout.contains("Congestion Window:"));
    assert!(stdout.contains("RL Reward Score:"));
}

#[test]
fn test_cli_congestion_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_CONGESTION_DIR", dir.path())
        .arg("--json")
        .arg("congestion")
        .arg("status")
        .output()
        .expect("execute velcrux --json congestion status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("valid JSON expected from --json congestion status");

    assert!(json_val["pacing_rate_bps"].is_number());
    assert!(json_val["min_rtt_ns"].is_number());
    assert!(json_val["estimated_bdp_bytes"].is_number());
    assert!(json_val["cwnd_bytes"].is_number());
    assert!(json_val["bbr_phase"].is_string());
    assert!(json_val["rl_reward_score"].is_number());
}

#[test]
fn test_cli_congestion_tune() {
    let dir = tempdir().expect("create tempdir");

    let output = Command::new(velcrux_bin())
        .env("VELCRUX_CONGESTION_DIR", dir.path())
        .arg("congestion")
        .arg("tune")
        .arg("--profile")
        .arg("satellite_leo")
        .arg("--pacing-gain")
        .arg("1.35")
        .arg("--cwnd-gain")
        .arg("2.5")
        .arg("--json")
        .output()
        .expect("execute congestion tune");

    assert!(
        output.status.success(),
        "tune stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json_val["profile"], "satellite_leo");
    assert!(json_val["pacing_rate_bps"].as_u64().unwrap() > 0);
    assert!(json_val["cwnd_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_congestion_sample() {
    let dir = tempdir().expect("create tempdir");

    let output = Command::new(velcrux_bin())
        .env("VELCRUX_CONGESTION_DIR", dir.path())
        .arg("congestion")
        .arg("sample")
        .arg("--rtt-ms")
        .arg("45.5")
        .arg("--bytes-acked")
        .arg("131072")
        .arg("--loss-rate")
        .arg("0.005")
        .arg("--delivery-rate-mbps")
        .arg("250.0")
        .arg("--json")
        .output()
        .expect("execute congestion sample");

    assert!(
        output.status.success(),
        "sample stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json_val["pacing_rate_bps"].as_u64().unwrap() > 0);
    assert!(json_val["cwnd_bytes"].as_u64().unwrap() > 0);
    assert!(json_val["rl_reward_score"].is_number());
}

#[test]
fn test_cli_congestion_simulate() {
    let dir = tempdir().expect("create tempdir");

    let output = Command::new(velcrux_bin())
        .env("VELCRUX_CONGESTION_DIR", dir.path())
        .arg("congestion")
        .arg("simulate")
        .arg("--scenario")
        .arg("starlink")
        .arg("--duration-sec")
        .arg("2")
        .arg("--json")
        .output()
        .expect("execute congestion simulate");

    assert!(
        output.status.success(),
        "simulate stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json_val["scenario"], "starlink");
    assert_eq!(json_val["duration_seconds"], 2);
    assert!(json_val["samples_evaluated"].as_u64().unwrap() >= 10);
    assert!(json_val["average_pacing_rate_bps"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_congestion_benchmark() {
    let dir = tempdir().expect("create tempdir");

    let output = Command::new(velcrux_bin())
        .env("VELCRUX_CONGESTION_DIR", dir.path())
        .arg("congestion")
        .arg("benchmark")
        .arg("--iterations")
        .arg("25")
        .arg("--json")
        .output()
        .expect("execute congestion benchmark");

    assert!(
        output.status.success(),
        "benchmark stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json_val["iterations"], 25);
    assert!(
        json_val["mean_sample_latency_nanoseconds"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    assert!(json_val["throughput_samples_per_sec"].as_f64().unwrap() > 0.0);
    assert!(json_val["final_pacing_rate_bps"].as_u64().unwrap() > 0);
}
