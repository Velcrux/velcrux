//! Integration tests for Option BW: Distributed Gossip-Based Peer Discovery
//! and Swarm P2P Acceleration Engine (`ADR-039`).

#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use velcrux_core::swarm::{
    GossipDiscoveryEngine, GossipMessage, PeerState, SwarmChunkMesh, SwarmConfig, SwarmStats,
};
use velcrux_core::util::Hash;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_swarm_status_text_and_json() {
    // 1. Human-readable text format
    let output = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("status")
        .arg("--swarm-port")
        .arg("19888")
        .output()
        .expect("execute swarm status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Velcrux Swarm P2P Mesh Status ==="));
    assert!(stdout.contains("Node ID:"));
    assert!(stdout.contains("Listen Address:"));
    assert!(stdout.contains("Offload Ratio:"));

    // 2. Machine-readable JSON format
    let output_json = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("status")
        .arg("--swarm-port")
        .arg("19889")
        .arg("--json")
        .output()
        .expect("execute swarm status --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON status report");
    assert!(parsed.get("local_peer_id").is_some());
    assert!(parsed.get("local_address").is_some());
    assert_eq!(parsed.get("banned_peers").and_then(|v| v.as_u64()), Some(0));
}

#[test]
fn test_cli_swarm_peers_text_and_json() {
    let seeds = "127.0.0.1:19491,127.0.0.1:19492";

    // 1. Text format
    let output = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("peers")
        .arg("--swarm-seeds")
        .arg(seeds)
        .output()
        .expect("execute swarm peers");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Discovered Swarm Mesh Peers (2) ==="));
    assert!(stdout.contains("127.0.0.1:19491"));
    assert!(stdout.contains("127.0.0.1:19492"));

    // 2. JSON format
    let output_json = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("peers")
        .arg("--swarm-seeds")
        .arg(seeds)
        .arg("--json")
        .output()
        .expect("execute swarm peers --json");

    assert!(output_json.status.success());
    let parsed: Vec<serde_json::Value> =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON peer list");
    assert_eq!(parsed.len(), 2);
    assert_eq!(
        parsed[0].get("state").and_then(|v| v.as_str()),
        Some("alive")
    );
}

#[test]
fn test_cli_swarm_advertise_file_and_dir() {
    let temp = tempdir().unwrap();
    let file_path = temp.path().join("payload.bin");
    fs::write(
        &file_path,
        b"test chunk advertisement payload for swarm mesh",
    )
    .unwrap();

    let sub_dir = temp.path().join("dataset");
    fs::create_dir_all(&sub_dir).unwrap();
    fs::write(sub_dir.join("part1.dat"), b"part 1 data").unwrap();
    fs::write(sub_dir.join("part2.dat"), b"part 2 data").unwrap();

    // 1. Advertise single file (text)
    let output_file = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("advertise")
        .arg(&file_path)
        .output()
        .expect("execute swarm advertise file");

    assert!(output_file.status.success());
    let stdout = String::from_utf8_lossy(&output_file.stdout);
    assert!(stdout.contains("=== Swarm Manifest Advertisement ==="));
    assert!(stdout.contains("Advertised Chunks:  1"));

    // 2. Advertise directory (JSON)
    let output_dir = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("advertise")
        .arg(&sub_dir)
        .arg("--json")
        .output()
        .expect("execute swarm advertise directory");

    assert!(output_dir.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_dir.stdout).expect("valid JSON advertise report");
    assert_eq!(
        parsed.get("advertised_chunks").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        parsed.get("status").and_then(|v| v.as_str()),
        Some("advertised")
    );
}

#[test]
fn test_cli_swarm_benchmark_text_and_json() {
    // 1. Text benchmark output
    let output = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("benchmark")
        .arg("--nodes")
        .arg("8")
        .arg("--chunks")
        .arg("24")
        .output()
        .expect("execute swarm benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Velcrux Swarm P2P Acceleration Benchmark ==="));
    assert!(stdout.contains("Simulated Swarm Nodes:   8"));
    assert!(stdout.contains("Unique Chunks Mesh:      24"));
    assert!(stdout.contains("Server Egress Saved:"));
    assert!(stdout.contains("Integrity Verified:      YES"));

    // 2. JSON benchmark output
    let output_json = Command::new(velcrux_bin())
        .arg("swarm")
        .arg("benchmark")
        .arg("--nodes")
        .arg("5")
        .arg("--chunks")
        .arg("15")
        .arg("--json")
        .output()
        .expect("execute swarm benchmark --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON benchmark report");
    assert_eq!(parsed.get("node_count").and_then(|v| v.as_u64()), Some(5));
    assert_eq!(parsed.get("chunk_count").and_then(|v| v.as_u64()), Some(15));
    assert_eq!(
        parsed.get("integrity_verified").and_then(|v| v.as_bool()),
        Some(true)
    );
    let offload_pct = parsed
        .get("server_offload_percentage")
        .and_then(|v| v.as_f64())
        .unwrap();
    assert!(
        offload_pct >= 70.0,
        "expected >= 70% offload ratio, got {offload_pct}%"
    );
}

#[test]
fn test_swarm_rarest_first_scheduling_and_byzantine_defense() {
    let stats = std::sync::Arc::new(SwarmStats::default());
    let mesh = SwarmChunkMesh::new(std::sync::Arc::clone(&stats));

    let h1 = Hash::of(b"chunk-alpha");
    let h2 = Hash::of(b"chunk-beta");
    let h3 = Hash::of(b"chunk-gamma");

    // Peer A has h1, h2, h3
    mesh.record_peer_chunks("peer-A", &[h1, h2, h3]);
    // Peer B has h2, h3
    mesh.record_peer_chunks("peer-B", &[h2, h3]);
    // Peer C has h3
    mesh.record_peer_chunks("peer-C", &[h3]);

    // Rarest first ordering:
    // h1 is held by 1 peer (rarest)
    // h2 is held by 2 peers
    // h3 is held by 3 peers (most common)
    let manifest_chunks = vec![h3, h1, h2];
    let scheduled = mesh.select_rarest_chunks(&manifest_chunks, 10);

    assert_eq!(scheduled.len(), 3);
    assert_eq!(
        scheduled[0].0, h1,
        "h1 should be scheduled first (rarest, 1 holder)"
    );
    assert_eq!(
        scheduled[1].0, h2,
        "h2 should be scheduled second (2 holders)"
    );
    assert_eq!(
        scheduled[2].0, h3,
        "h3 should be scheduled last (3 holders)"
    );

    // Byzantine Poisoning Defense:
    // Peer A sends corrupt payload for h1
    let corrupt_payload = b"poisoned-malicious-data";
    let verify_result = mesh.ingest_and_verify(&h1, corrupt_payload, "peer-A");
    assert!(verify_result.is_err(), "poisoned chunk must be rejected");
    assert_eq!(
        stats
            .chunks_poisoned_rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Valid chunk ingestion:
    let valid_payload = b"chunk-alpha";
    let ingest_result = mesh.ingest_and_verify(&h1, valid_payload, "peer-A");
    assert!(
        ingest_result.is_ok(),
        "authentic chunk must verify successfully"
    );
    assert!(mesh.has_local_chunk(&h1));
}

#[test]
fn test_gossip_swim_incarnation_refutation() {
    let addr1: std::net::SocketAddr = "127.0.0.1:19401".parse().unwrap();
    let addr2: std::net::SocketAddr = "127.0.0.1:19402".parse().unwrap();

    let node1 = GossipDiscoveryEngine::new("node-1", addr1, SwarmConfig::default());
    let node2 = GossipDiscoveryEngine::new("node-2", addr2, SwarmConfig::default());

    // node-1 discovers node-2
    let ping = GossipMessage::Ping {
        sender_id: "node-2".to_string(),
        incarnation: 1,
        address: addr2,
    };
    node1.handle_gossip_message(&ping);

    let peers = node1.peers();
    let p2 = peers.iter().find(|p| p.peer_id == "node-2").unwrap();
    assert_eq!(p2.state, PeerState::Alive);
    assert_eq!(p2.incarnation, 1);

    // node-2 receives a Suspect message accusing itself at incarnation 1
    let suspect_msg = GossipMessage::Suspect {
        peer_id: "node-2".to_string(),
        incarnation: 1,
        reporter_id: "node-1".to_string(),
    };
    let rebuttal = node2.handle_gossip_message(&suspect_msg);

    // node-2 refutes accusation with incremented incarnation counter (SWIM protocol invariant)
    assert!(rebuttal.is_some());
    match rebuttal.unwrap() {
        GossipMessage::Alive {
            peer_id,
            incarnation,
            address,
        } => {
            assert_eq!(peer_id, "node-2");
            assert_eq!(incarnation, 2);
            assert_eq!(address, addr2);
        }
        other => panic!("expected Alive rebuttal, got {other:?}"),
    }
}
