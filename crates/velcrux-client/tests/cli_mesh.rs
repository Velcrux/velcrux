//! CLI Integration tests for Option DM: Autonomous Micro-Segmented Zero-Trust
//! WireGuard / Noise Mesh Tunnel Fabric (`ADR-081`).

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
fn test_cli_mesh_status_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("status")
        .output()
        .expect("execute mesh status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX ZERO-TRUST WIREGUARD / NOISE MESH TUNNEL FABRIC"));
    assert!(stdout.contains("Virtual Interface:      vlx-wg0"));
    assert!(stdout.contains("Public Key (Hex):"));
    assert!(stdout.contains("Public Key (Base64):"));
    assert!(stdout.contains("Listening UDP Port:     51820"));
    assert!(stdout.contains("dc-us-east"));
    assert!(stdout.contains("vault-eu-central"));
    assert!(stdout.contains("pop-ap-southeast"));
    assert!(stdout.contains("CONNECTED"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute mesh status --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["interface_name"], "vlx-wg0");
    assert_eq!(parsed["listen_port"], 51820);
    assert_eq!(parsed["peer_count"], 3);
    assert_eq!(parsed["connected_peer_count"], 1);
    assert!(parsed["peers"].as_array().unwrap().len() >= 3);
}

#[test]
fn test_cli_mesh_peers_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("peers")
        .output()
        .expect("execute mesh peers");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CONFIGURED ZERO-TRUST MESH TUNNEL PEERS"));
    assert!(stdout.contains("Peer Identifier:        dc-us-east"));
    assert!(stdout.contains("Peer Identifier:        vault-eu-central"));
    assert!(stdout.contains("Curve25519 Public Key:"));
    assert!(stdout.contains("Allowed IPs:"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("peers")
        .arg("--json")
        .output()
        .expect("execute mesh peers --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert!(parsed.as_array().unwrap().len() >= 3);
    assert_eq!(parsed[0]["peer_id"], "dc-us-east");
}

#[test]
fn test_cli_mesh_connect_and_disconnect() {
    let dummy_pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // 1. Connect in text mode
    let output = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("connect")
        .arg("--peer")
        .arg("remote-branch")
        .arg("--public-key")
        .arg(dummy_pubkey)
        .arg("--endpoint")
        .arg("198.51.100.99:51820")
        .arg("--allowed-ips")
        .arg("10.200.99.0/24")
        .output()
        .expect("execute mesh connect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("WIREGUARD / NOISE HANDSHAKE INITIATED"));
    assert!(stdout.contains("Peer Identifier:        remote-branch"));
    assert!(stdout.contains("Session Status:         HANDSHAKE_INITIATED"));

    // 2. Connect in JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("connect")
        .arg("--peer")
        .arg("remote-cloud")
        .arg("--public-key")
        .arg(dummy_pubkey)
        .arg("--allowed-ips")
        .arg("10.200.100.0/24")
        .arg("--json")
        .output()
        .expect("execute mesh connect --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["peer"], "remote-cloud");
    assert_eq!(parsed["handshake_initiated"], true);
    assert_eq!(parsed["status"], "HANDSHAKE_INITIATED");

    // 3. Disconnect peer
    let disc_output = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("disconnect")
        .arg("--peer")
        .arg("dc-us-east")
        .output()
        .expect("execute mesh disconnect");

    assert!(
        disc_output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&disc_output.stderr)
    );

    let disc_stdout = String::from_utf8_lossy(&disc_output.stdout);
    assert!(disc_stdout.contains("MESH PEER DISCONNECTED"));
    assert!(disc_stdout.contains("Peer Identifier:        dc-us-east"));
    assert!(disc_stdout.contains("Session Keys Purged:    YES"));
}

#[test]
fn test_cli_mesh_benchmark_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("benchmark")
        .arg("--packets")
        .arg("40")
        .arg("--packet-size")
        .arg("256")
        .output()
        .expect("execute mesh benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("WIREGUARD / NOISE MESH TUNNEL PERFORMANCE BENCHMARK"));
    assert!(stdout.contains("Packets Processed:      40 packets"));
    assert!(stdout.contains("Noise Handshake Time:"));
    assert!(stdout.contains("Encryption Throughput:"));
    assert!(stdout.contains("Decryption Throughput:"));
    assert!(stdout.contains("Anti-Replay Validation:"));
    assert!(stdout.contains("Replayed Packets Dropped:40 attacks prevented"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("mesh")
        .arg("benchmark")
        .arg("--packets")
        .arg("40")
        .arg("--packet-size")
        .arg("256")
        .arg("--json")
        .output()
        .expect("execute mesh benchmark --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["packets_processed"], 40);
    assert_eq!(parsed["packet_size_bytes"], 256);
    assert!(parsed["handshake_latency_us"].as_f64().unwrap() > 0.0);
    assert!(parsed["encryption_throughput_mb_s"].as_f64().unwrap() > 0.0);
    assert!(parsed["decryption_throughput_mb_s"].as_f64().unwrap() > 0.0);
    assert_eq!(parsed["replayed_packets_dropped"], 40);
}
