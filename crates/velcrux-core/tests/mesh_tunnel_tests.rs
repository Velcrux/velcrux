//! Integration tests for Option DM: Autonomous Micro-Segmented Zero-Trust
//! WireGuard / Noise Mesh Tunnel Fabric (`ADR-081`).

use std::net::IpAddr;

use velcrux_core::mesh::{MeshError, MeshTunnelRouter, NoiseKeyPair};

fn setup_hub_and_spokes() -> (MeshTunnelRouter, MeshTunnelRouter, MeshTunnelRouter) {
    let hub_keypair = NoiseKeyPair::generate();
    let spoke1_keypair = NoiseKeyPair::generate();
    let spoke2_keypair = NoiseKeyPair::generate();

    let mut hub = MeshTunnelRouter::with_keypair(hub_keypair, 51820, 1420);
    let mut spoke1 = MeshTunnelRouter::with_keypair(spoke1_keypair, 51821, 1420);
    let mut spoke2 = MeshTunnelRouter::with_keypair(spoke2_keypair, 51822, 1420);

    let hub_pub = hub.local_keypair().public_key_hex();
    let spoke1_pub = spoke1.local_keypair().public_key_hex();
    let spoke2_pub = spoke2.local_keypair().public_key_hex();

    // Hub configures both spokes
    hub.add_peer(
        "spoke-1",
        &spoke1_pub,
        Some("192.168.1.11:51821"),
        &["10.10.1.0/24"],
    )
    .unwrap();
    hub.add_peer(
        "spoke-2",
        &spoke2_pub,
        Some("192.168.1.12:51822"),
        &["10.10.2.0/24"],
    )
    .unwrap();

    // Spokes configure hub for corporate intranet route
    spoke1
        .add_peer(
            "hub",
            &hub_pub,
            Some("192.168.1.1:51820"),
            &["10.10.0.0/16"],
        )
        .unwrap();
    spoke2
        .add_peer(
            "hub",
            &hub_pub,
            Some("192.168.1.1:51820"),
            &["10.10.0.0/16"],
        )
        .unwrap();

    (hub, spoke1, spoke2)
}

#[test]
fn test_mesh_multi_peer_topology_and_status() {
    let (hub, spoke1, _) = setup_hub_and_spokes();

    let hub_status = hub.status();
    assert_eq!(hub_status.interface_name, "vlx-wg0");
    assert_eq!(hub_status.listen_port, 51820);
    assert_eq!(hub_status.peer_count, 2);
    assert_eq!(hub_status.connected_peer_count, 0);

    let spoke_status = spoke1.status();
    assert_eq!(spoke_status.peer_count, 1);
    assert_eq!(spoke_status.peers[0].peer_id, "hub");
}

#[test]
fn test_handshake_flow_and_session_establishment() {
    let (mut hub, mut spoke1, _) = setup_hub_and_spokes();
    let now = 10_000;

    // 1. Spoke 1 initiates handshake to Hub
    let initiation = spoke1.initiate_handshake("hub", now).unwrap();
    assert_eq!(initiation.to_bytes().len(), 148);

    // 2. Hub processes initiation and produces response
    let (response, sender_id) = hub
        .process_handshake_initiation(&initiation, Some("192.168.1.11:51821"), now + 5)
        .unwrap();
    assert_eq!(sender_id, "spoke-1");
    assert_eq!(response.to_bytes().len(), 92);

    // 3. Spoke 1 processes response to finalize session
    let finalized = spoke1
        .process_handshake_response(&response, now + 10)
        .unwrap();
    assert_eq!(finalized, "hub");

    // Both ends should report connected
    assert_eq!(hub.status().connected_peer_count, 1);
    assert_eq!(spoke1.status().connected_peer_count, 1);
}

#[test]
fn test_bidirectional_traffic_encapsulation_and_decapsulation() {
    let (mut hub, mut spoke1, _) = setup_hub_and_spokes();
    let now = 20_000;

    // Establish session
    let initiation = spoke1.initiate_handshake("hub", now).unwrap();
    let (response, _) = hub
        .process_handshake_initiation(&initiation, Some("192.168.1.11:51821"), now + 2)
        .unwrap();
    let _ = spoke1
        .process_handshake_response(&response, now + 4)
        .unwrap();

    // Hub sends to Spoke 1 destination IP (10.10.1.50)
    let dest_spoke1: IpAddr = "10.10.1.50".parse().unwrap();
    let hub_inner_src: IpAddr = "10.10.0.1".parse().unwrap();
    let outbound_payload = b"GET /cluster/health HTTP/1.1\r\nHost: node-50\r\n\r\n";

    let transport_pkt = hub
        .encapsulate_ip_packet(dest_spoke1, outbound_payload)
        .unwrap();

    // Spoke 1 receives and decapsulates packet
    let (decrypted_payload, from_peer) = spoke1
        .decapsulate_transport_packet(&transport_pkt, Some("192.168.1.1:51820"), hub_inner_src)
        .unwrap();

    assert_eq!(from_peer, "hub");
    assert_eq!(decrypted_payload, outbound_payload);

    // Spoke 1 sends reply back to Hub (10.10.0.1)
    let return_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let reply_pkt = spoke1
        .encapsulate_ip_packet(hub_inner_src, return_payload)
        .unwrap();

    let (decrypted_reply, from_spoke) = hub
        .decapsulate_transport_packet(&reply_pkt, Some("192.168.1.11:51821"), dest_spoke1)
        .unwrap();

    assert_eq!(from_spoke, "spoke-1");
    assert_eq!(decrypted_reply, return_payload);

    // Verify transfer bytes accounting
    let hub_st = hub.status();
    assert_eq!(hub_st.total_tx_bytes, outbound_payload.len() as u64);
    assert_eq!(hub_st.total_rx_bytes, return_payload.len() as u64);
}

#[test]
fn test_anti_spoofing_and_cryptographic_routing_enforcement() {
    let (mut hub, _spoke1, mut spoke2) = setup_hub_and_spokes();
    let now = 30_000;

    // Establish session with Spoke 2
    let initiation = spoke2.initiate_handshake("hub", now).unwrap();
    let (response, _) = hub
        .process_handshake_initiation(&initiation, Some("192.168.1.12:51822"), now + 2)
        .unwrap();
    let _ = spoke2
        .process_handshake_response(&response, now + 4)
        .unwrap();

    // Spoke 2 constructs an encapsulated packet
    let dest_hub: IpAddr = "10.10.0.1".parse().unwrap();
    let transport_pkt = spoke2
        .encapsulate_ip_packet(dest_hub, b"Malicious packet spoofing Spoke 1")
        .unwrap();

    // Hub receives packet from Spoke 2 session, but inner source IP claims to be 10.10.1.99 (Spoke 1's subnet)
    let spoofed_source_ip: IpAddr = "10.10.1.99".parse().unwrap();
    let err = hub
        .decapsulate_transport_packet(
            &transport_pkt,
            Some("192.168.1.12:51822"),
            spoofed_source_ip,
        )
        .unwrap_err();

    match err {
        MeshError::CryptographicRoutingViolation { source_ip, peer_id } => {
            assert_eq!(source_ip, "10.10.1.99");
            assert_eq!(peer_id, "spoke-2");
        }
        other => panic!("Expected CryptographicRoutingViolation, got {other:?}"),
    }
}

#[test]
fn test_mesh_roaming_endpoint_update() {
    let (mut hub, mut spoke1, _) = setup_hub_and_spokes();
    let now = 40_000;

    // Handshake from initial endpoint
    let initiation = spoke1.initiate_handshake("hub", now).unwrap();
    let (response, _) = hub
        .process_handshake_initiation(&initiation, Some("192.168.1.11:51821"), now + 2)
        .unwrap();
    let _ = spoke1
        .process_handshake_response(&response, now + 4)
        .unwrap();

    assert_eq!(
        hub.status().peers[0].endpoint.as_deref(),
        Some("192.168.1.11:51821")
    );

    // Spoke 1 roams to a new public IP/port (e.g. mobile 5G or Wi-Fi roaming)
    let new_roamed_endpoint = "198.51.100.88:64231";
    let dest_hub: IpAddr = "10.10.0.1".parse().unwrap();
    let inner_src: IpAddr = "10.10.1.10".parse().unwrap();

    let transport_pkt = spoke1
        .encapsulate_ip_packet(dest_hub, b"Packet sent after roaming to cellular network")
        .unwrap();

    // Hub decapsulates packet from roamed endpoint
    let (payload, peer_id) = hub
        .decapsulate_transport_packet(&transport_pkt, Some(new_roamed_endpoint), inner_src)
        .unwrap();

    assert_eq!(peer_id, "spoke-1");
    assert!(!payload.is_empty());

    // Hub must update the peer's endpoint automatically!
    let peer = hub
        .status()
        .peers
        .into_iter()
        .find(|p| p.peer_id == "spoke-1")
        .unwrap();
    assert_eq!(peer.endpoint.as_deref(), Some(new_roamed_endpoint));
}

#[test]
fn test_mesh_benchmark_execution() {
    let mut router = MeshTunnelRouter::new(51820, 1420);
    let bench = router.run_benchmark(100, 256);

    assert_eq!(bench.packets_processed, 100);
    assert_eq!(bench.packet_size_bytes, 256);
    assert!(bench.handshake_latency_us > 0.0);
    assert!(bench.encryption_throughput_mb_s > 0.0);
    assert!(bench.decryption_throughput_mb_s > 0.0);
    assert!(bench.anti_replay_checks_per_sec > 0.0);
    assert_eq!(bench.replayed_packets_dropped, 100);
}
