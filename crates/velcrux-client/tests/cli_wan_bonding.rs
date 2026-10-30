//! Integration tests for Option CF: Autonomous Multi-Path WAN Slicing
//! & Sub-Millisecond Dynamic Interface Bonding (`ADR-048`).

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
fn test_cli_wan_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("wan")
        .arg("status")
        .output()
        .expect("execute wan status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Autonomous Multi-Path WAN Slicing & Bonding Status ==="));
    assert!(stdout.contains("Bonded Interfaces:"));
    assert!(stdout.contains("wan0-fiber100g"));
    assert!(stdout.contains("wan1-eth10g"));
    assert!(stdout.contains("wan2-starlink"));
    assert!(stdout.contains("wan3-cellular5g"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("wan")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute wan status json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).expect("parse status json");
    assert_eq!(v["interfaces_bonded"], 4);
    assert!(v["interfaces"].as_array().unwrap().len() >= 4);
}

#[test]
fn test_cli_wan_interfaces_list() {
    let output = Command::new(velcrux_bin())
        .arg("wan")
        .arg("interfaces")
        .output()
        .expect("execute wan interfaces");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Active Bonded WAN Interfaces ==="));
    assert!(stdout.contains("wan0-fiber100g"));
    assert!(stdout.contains("wan2-starlink"));

    let json_out = Command::new(velcrux_bin())
        .arg("wan")
        .arg("interfaces")
        .arg("--json")
        .output()
        .expect("execute wan interfaces json");

    assert!(json_out.status.success());
    let list: Vec<serde_json::Value> = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(list.len(), 4);
    assert_eq!(list[0]["id"], "wan0-fiber100g");
}

#[test]
fn test_cli_wan_slice_and_reassemble_in_order() {
    let output = Command::new(velcrux_bin())
        .arg("wan")
        .arg("slice")
        .arg("--size")
        .arg("131072")
        .arg("--slice-size")
        .arg("32768")
        .output()
        .expect("execute wan slice");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Multi-Path WAN Slicing & Reassembly Execution ==="));
    assert!(stdout.contains("Total Payload:          131072 bytes"));
    assert!(stdout.contains("Total Slices:           4"));
    assert!(stdout.contains("Reordered Arrival:      false"));
    assert!(stdout.contains("Max Reorder Gap:        0"));
    assert!(stdout.contains("Integrity Verified:     true"));

    let json_out = Command::new(velcrux_bin())
        .arg("wan")
        .arg("slice")
        .arg("--size")
        .arg("131072")
        .arg("--slice-size")
        .arg("32768")
        .arg("--json")
        .output()
        .expect("execute wan slice json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(v["total_bytes"], 131072);
    assert_eq!(v["total_slices"], 4);
    assert_eq!(v["reordered"], false);
    assert_eq!(v["integrity_verified"], true);
}

#[test]
fn test_cli_wan_slice_and_reassemble_out_of_order() {
    let json_out = Command::new(velcrux_bin())
        .arg("wan")
        .arg("slice")
        .arg("--size")
        .arg("262144")
        .arg("--slice-size")
        .arg("32768")
        .arg("--reorder")
        .arg("--json")
        .output()
        .expect("execute wan slice reordered json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(v["total_bytes"], 262144);
    assert_eq!(v["total_slices"], 8);
    assert_eq!(v["reordered"], true);
    assert!(v["max_reorder_gap"].as_u64().unwrap() > 0);
    assert_eq!(v["integrity_verified"], true);
}

#[test]
fn test_cli_wan_probe_update_and_degradation() {
    let output = Command::new(velcrux_bin())
        .arg("wan")
        .arg("probe")
        .arg("--interface")
        .arg("wan2-starlink")
        .arg("--srtt-us")
        .arg("120000")
        .arg("--jitter-us")
        .arg("35000")
        .arg("--loss-bp")
        .arg("750")
        .arg("--ecn-bp")
        .arg("120")
        .arg("--json")
        .output()
        .expect("execute wan probe");

    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["interface"], "wan2-starlink");
    assert_eq!(v["srtt_us"], 120000);
    assert_eq!(v["loss_basis_points"], 750);
    assert_eq!(v["new_state"], "degraded");
}

#[test]
fn test_cli_wan_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("wan")
        .arg("benchmark")
        .arg("--iterations")
        .arg("30")
        .arg("--chunk-size")
        .arg("65536")
        .output()
        .expect("execute wan benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Multi-Path WAN Slicing & Bonding Benchmark (30 iters) ==="));
    assert!(stdout.contains("Total Slices Handled:   60"));
    assert!(stdout.contains("Bonded Interfaces:      4"));
    assert!(stdout.contains("Slicing Throughput:"));
    assert!(stdout.contains("Bonding Throughput:"));
    assert!(stdout.contains("Avg Reassembly Latency:"));

    let json_out = Command::new(velcrux_bin())
        .arg("wan")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .arg("--chunk-size")
        .arg("32768")
        .arg("--json")
        .output()
        .expect("execute wan benchmark json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(v["iterations"], 20);
    assert!(v["slicing_throughput_slices_sec"].as_f64().unwrap() > 50.0);
    assert!(v["aggregation_throughput_gbps"].as_f64().unwrap() > 0.0);
}
