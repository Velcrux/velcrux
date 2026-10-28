//! Integration tests for Option CB: Distributed Dynamic Content Router
//! & Anycast Session Migration (`ADR-044`).

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
fn test_cli_router_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("router")
        .arg("status")
        .output()
        .expect("execute router status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Distributed Anycast Content Router Status ==="));
    assert!(stdout.contains("Total Edge PoPs:"));
    assert!(stdout.contains("Healthy PoPs:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("router")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute router status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse router status json");
    assert!(val["total_pops"].as_u64().unwrap() >= 4);
    assert!(val["healthy_pops"].as_u64().unwrap() >= 4);
    assert_eq!(val["offline_pops"].as_u64().unwrap(), 0);
}

#[test]
fn test_cli_router_pops_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("router")
        .arg("pops")
        .output()
        .expect("execute router pops");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Registered Edge Points-of-Presence (PoPs) ==="));
    assert!(stdout.contains("POP ID"));
    assert!(stdout.contains("pop-iad"));
    assert!(stdout.contains("pop-sfo"));
    assert!(stdout.contains("pop-lhr"));
    assert!(stdout.contains("pop-nrt"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("router")
        .arg("pops")
        .arg("--json")
        .output()
        .expect("execute router pops json");

    assert!(json_out.status.success());
    let arr: Vec<serde_json::Value> =
        serde_json::from_slice(&json_out.stdout).expect("parse pops array json");
    assert_eq!(arr.len(), 4);
    let ids: Vec<&str> = arr.iter().map(|p| p["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"pop-iad"));
    assert!(ids.contains(&"pop-sfo"));
    assert!(ids.contains(&"pop-lhr"));
    assert!(ids.contains(&"pop-nrt"));
}

#[test]
fn test_cli_router_route_resolution() {
    // Client in Washington DC (near pop-iad)
    let output_dc = Command::new(velcrux_bin())
        .arg("router")
        .arg("route")
        .arg("client-dc")
        .arg("--lat")
        .arg("38.9072")
        .arg("--lon")
        .arg("-77.0369")
        .arg("--bandwidth")
        .arg("50000000")
        .output()
        .expect("execute route dc");

    assert!(output_dc.status.success());
    let stdout_dc = String::from_utf8_lossy(&output_dc.stdout);
    assert!(stdout_dc.contains("Selected Edge PoP:      pop-iad"));
    assert!(stdout_dc.contains("PoP Region:             us-east"));

    // Client in Tokyo (near pop-nrt) in JSON format
    let output_tokyo = Command::new(velcrux_bin())
        .arg("router")
        .arg("route")
        .arg("client-tokyo")
        .arg("--lat")
        .arg("35.6762")
        .arg("--lon")
        .arg("139.6503")
        .arg("--bandwidth")
        .arg("100000000")
        .arg("--json")
        .output()
        .expect("execute route tokyo json");

    assert!(output_tokyo.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&output_tokyo.stdout).expect("parse route tokyo json");
    assert_eq!(val["client_id"].as_str().unwrap(), "client-tokyo");
    assert_eq!(val["selected_pop_id"].as_str().unwrap(), "pop-nrt");
    assert_eq!(val["pop_region"].as_str().unwrap(), "ap-northeast");
    assert!(val["estimated_rtt_ms"].as_f64().unwrap() > 0.0);
    assert!(val["distance_km"].as_f64().unwrap() < 50.0);
}

#[test]
fn test_cli_router_session_migration() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("router")
        .arg("migrate")
        .arg("sess-tx-999")
        .arg("--source")
        .arg("pop-iad")
        .arg("--target")
        .arg("pop-sfo")
        .arg("--transfer-id")
        .arg("transfer-bulk-1")
        .arg("--offset")
        .arg("5242880")
        .arg("--total")
        .arg("10485760")
        .output()
        .expect("execute migrate");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Live Anycast Session Migration Handover ==="));
    assert!(stdout.contains("Session ID:             sess-tx-999"));
    assert!(stdout.contains("Source PoP:             pop-iad"));
    assert!(stdout.contains("Target PoP:             pop-sfo"));
    assert!(stdout.contains("Handover State:         committed"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("router")
        .arg("migrate")
        .arg("sess-tx-888")
        .arg("--source")
        .arg("pop-lhr")
        .arg("--target")
        .arg("pop-nrt")
        .arg("--offset")
        .arg("1048576")
        .arg("--total")
        .arg("5242880")
        .arg("--json")
        .output()
        .expect("execute migrate json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse migrate json");
    assert_eq!(val["record"]["session_id"].as_str().unwrap(), "sess-tx-888");
    assert_eq!(val["record"]["state"].as_str().unwrap(), "committed");
    assert_eq!(val["ticket"]["target_pop_id"].as_str().unwrap(), "pop-nrt");
    assert!(val["ticket"]["signature_mac"].as_str().unwrap().len() == 64);
}

#[test]
fn test_cli_router_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("router")
        .arg("benchmark")
        .arg("--pops")
        .arg("4")
        .arg("--iterations")
        .arg("20")
        .output()
        .expect("execute benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Anycast Router & Session Migration Benchmark ==="));
    assert!(stdout.contains("Simulated Edge PoPs:    4"));
    assert!(stdout.contains("Routes Evaluated:       20"));
    assert!(stdout.contains("All Migrations Valid:   YES"));

    let json_out = Command::new(velcrux_bin())
        .arg("router")
        .arg("benchmark")
        .arg("--pops")
        .arg("3")
        .arg("--iterations")
        .arg("10")
        .arg("--json")
        .output()
        .expect("execute benchmark json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse benchmark json");
    assert_eq!(val["pop_count"].as_u64().unwrap(), 3);
    assert_eq!(val["routes_evaluated"].as_u64().unwrap(), 10);
    assert_eq!(val["all_migrations_verified"].as_bool().unwrap(), true);
    assert!(val["routing_throughput_routes_per_sec"].as_f64().unwrap() > 0.0);
    assert!(val["failover_convergence_latency_ms"].as_f64().unwrap() >= 0.0);
}
