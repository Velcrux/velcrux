//! Integration tests for Option DD: Autonomous Global Anycast BGP Peering & EVPN-VXLAN Fabric (`ADR-072`).

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
fn test_cli_bgp_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("status")
        .output()
        .expect("execute bgp status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Global Anycast BGP Peering Sessions (RFC 4271) ==="));
    assert!(stdout.contains("[Peer AS174]"));
    assert!(stdout.contains("Session State:       Established (eBGP)"));
    assert!(stdout.contains("Hold / Keepalive:    90s / 30s"));
    assert!(stdout.contains("Session Uptime:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute bgp status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse bgp status json");
    let arr = val.as_array().expect("array of peers");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["peer_asn"].as_u64().unwrap(), 174);
    assert_eq!(arr[0]["state"].as_str().unwrap(), "Established");
    assert!(arr[0]["is_ebgp"].as_bool().unwrap());
}

#[test]
fn test_cli_bgp_routes_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("routes")
        .output()
        .expect("execute bgp routes");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== BGP Routing Information Base (Loc-RIB) [VRF: default] ==="));
    assert!(stdout.contains("Prefix: 198.51.100.0/24"));
    assert!(stdout.contains("LocalPref:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("routes")
        .arg("--json")
        .output()
        .expect("execute bgp routes json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse bgp routes json");
    let arr = val.as_array().expect("array of routes");
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["vrf"].as_str().unwrap(), "default");
    assert!(arr[0]["prefix"].as_str().is_some());
    assert!(arr[0]["local_pref"].as_u64().is_some());
}

#[test]
fn test_cli_bgp_evpn_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("evpn")
        .output()
        .expect("execute bgp evpn");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== EVPN-VXLAN Edge Transit Fabric (RFC 7432 / RFC 7348) ==="));
    assert!(stdout.contains("Local VTEP IP:          10.0.0.1"));
    assert!(stdout.contains("VXLAN UDP Port:         4789"));
    assert!(stdout.contains("FDB Active Mappings:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("evpn")
        .arg("--json")
        .output()
        .expect("execute bgp evpn json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse bgp evpn json");
    assert_eq!(val["local_vtep_ip"].as_str().unwrap(), "10.0.0.1");
    assert_eq!(val["udp_port"].as_u64().unwrap(), 4789);
    assert!(val["total_fdb_entries"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_bgp_advertise_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("advertise")
        .arg("--prefix")
        .arg("198.51.100.1/32")
        .arg("--as-prepends")
        .arg("2")
        .arg("--med")
        .arg("50")
        .output()
        .expect("execute bgp advertise");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Dynamic BGP Anycast Prefix Advertisement ==="));
    assert!(stdout.contains("Prefix CIDR:            198.51.100.1/32"));
    assert!(stdout.contains("AS-Path Prepends:       2 (Path Length 3)"));
    assert!(stdout.contains("Multi-Exit Disc (MED):  50"));
    assert!(stdout.contains("BGP UPDATE Capsule:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("bgp")
        .arg("advertise")
        .arg("--prefix")
        .arg("203.0.113.1/32")
        .arg("--as-prepends")
        .arg("0")
        .arg("--community")
        .arg("no-export")
        .arg("--json")
        .output()
        .expect("execute bgp advertise json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse bgp advertise json");
    assert_eq!(val["prefix"].as_str().unwrap(), "203.0.113.1/32");
    assert_eq!(val["as_prepends"].as_u64().unwrap(), 0);
    assert!(val["announced"].as_bool().unwrap());
    assert!(val["wire_bytes_len"].as_u64().unwrap() > 0);
}
