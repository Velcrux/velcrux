//! Autonomous Micro-Segmented Zero-Trust WireGuard / Noise Mesh Tunnel Fabric (ADR-081).
//!
//! Provides pure safe Rust site-to-site cryptographic tunneling:
//! - Noise Protocol Framework (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) handshakes.
//! - Cryptographic routing trie with longest-prefix matching and anti-spoofing.
//! - 256-bit sliding window anti-replay protection.
//! - WireGuard wire framing (Handshake Initiation, Response, Cookie, Transport Data).
//! - Dynamic peer discovery, roaming, and MTU clamping.

pub mod noise;
pub mod replay;
pub mod router;
pub mod trie;
pub mod types;

pub use noise::{NoiseHandshake, NoiseSession};
pub use replay::{AntiReplayWindow, REPLAY_WINDOW_SIZE};
pub use router::MeshTunnelRouter;
pub use trie::{AllowedIpsTrie, CidrRule};
pub use types::{
    base64_encode, hex_decode_32, hex_encode, HandshakeInitiationPacket, HandshakeResponsePacket,
    MeshBenchmarkReport, MeshError, MeshResult, MeshStatusReport, NoiseKeyPair, PeerStatus,
    TransportDataPacket, PACKET_COOKIE_REPLY, PACKET_HANDSHAKE_INITIATION,
    PACKET_HANDSHAKE_RESPONSE, PACKET_TRANSPORT_DATA, X25519_BASEPOINT,
};

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn test_keypair_generation_and_encoding() {
        let keypair = NoiseKeyPair::generate();
        let pub_hex = keypair.public_key_hex();
        assert_eq!(pub_hex.len(), 64);

        let decoded = hex_decode_32(&pub_hex).unwrap();
        assert_eq!(decoded, keypair.public_key);

        let pub_b64 = keypair.public_key_base64();
        assert!(!pub_b64.is_empty());
    }

    #[test]
    fn test_sliding_window_anti_replay() {
        let mut window = AntiReplayWindow::new();

        // 1. Initial packet counter 100 accepted
        assert!(window.check_and_update(100).is_ok());
        assert_eq!(window.highest_counter(), 100);

        // 2. Duplicate packet counter 100 rejected (Replay attack!)
        let err = window.check_and_update(100).unwrap_err();
        assert!(matches!(err, MeshError::ReplayAttackDetected { .. }));

        // 3. Forward progress: counter 105 accepted
        assert!(window.check_and_update(105).is_ok());
        assert_eq!(window.highest_counter(), 105);

        // 4. Out-of-order counter 102 within window accepted
        assert!(window.check_and_update(102).is_ok());

        // 5. Duplicate of out-of-order counter 102 rejected
        assert!(window.check_and_update(102).is_err());

        // 6. Ancient packet (>256 behind highest) rejected
        assert!(window.check_and_update(1000).is_ok());
        let err_ancient = window.check_and_update(500).unwrap_err();
        assert!(matches!(
            err_ancient,
            MeshError::ReplayAttackDetected { .. }
        ));
    }

    #[test]
    fn test_allowed_ips_trie_routing_and_anti_spoofing() {
        let mut trie = AllowedIpsTrie::new();

        trie.insert("10.0.0.0/16", "peer-datacenter").unwrap();
        trie.insert("10.0.1.0/24", "peer-branch-office").unwrap();
        trie.insert("192.168.1.50/32", "peer-host-single").unwrap();

        // Longest-prefix match: 10.0.1.5 matches 10.0.1.0/24 over 10.0.0.0/16
        let dest_branch: IpAddr = "10.0.1.5".parse().unwrap();
        assert_eq!(trie.lookup(dest_branch), Some("peer-branch-office"));

        let dest_dc: IpAddr = "10.0.2.10".parse().unwrap();
        assert_eq!(trie.lookup(dest_dc), Some("peer-datacenter"));

        let dest_host: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(trie.lookup(dest_host), Some("peer-host-single"));

        // No route
        let dest_unknown: IpAddr = "172.16.0.1".parse().unwrap();
        assert_eq!(trie.lookup(dest_unknown), None);

        // Anti-spoofing verification
        assert!(trie.check_allowed(dest_branch, "peer-branch-office"));
        assert!(!trie.check_allowed(dest_branch, "peer-datacenter")); // Spoofed!
    }

    #[test]
    fn test_noise_handshake_and_transport_roundtrip() {
        let alice_keypair = NoiseKeyPair::generate();
        let bob_keypair = NoiseKeyPair::generate();

        let now = 5000;

        // 1. Alice creates initiation for Bob
        let (initiation, alice_state) =
            NoiseHandshake::create_initiation(&alice_keypair, &bob_keypair.public_key, 100, now)
                .unwrap();

        // Wire roundtrip serialization check
        let init_wire = initiation.to_bytes();
        assert_eq!(init_wire.len(), 148);
        let parsed_init = HandshakeInitiationPacket::from_bytes(&init_wire).unwrap();

        // 2. Bob processes initiation and responds
        let (response, sender_pubkey, mut bob_session) =
            NoiseHandshake::process_initiation_and_respond(
                &bob_keypair,
                &parsed_init,
                200,
                now + 10,
            )
            .unwrap();

        assert_eq!(sender_pubkey, alice_keypair.public_key);

        let resp_wire = response.to_bytes();
        assert_eq!(resp_wire.len(), 92);
        let parsed_resp = HandshakeResponsePacket::from_bytes(&resp_wire).unwrap();

        // 3. Alice processes response and completes handshake
        let mut alice_session = NoiseHandshake::process_response(
            &alice_keypair,
            &bob_keypair.public_key,
            alice_state,
            &parsed_resp,
            now + 20,
        )
        .unwrap();

        // 4. Transport Data: Alice sends encrypted packet to Bob
        let payload = b"Hello from encrypted zero-trust mesh tunnel!".to_vec();
        let transport_packet = alice_session.encrypt_transport_data(&payload).unwrap();

        let trans_wire = transport_packet.to_bytes();
        let parsed_trans = TransportDataPacket::from_bytes(&trans_wire).unwrap();

        // Bob decrypts packet
        let decrypted = bob_session.decrypt_transport_data(&parsed_trans).unwrap();
        assert_eq!(decrypted, payload);

        // Replaying packet to Bob fails
        assert!(bob_session.decrypt_transport_data(&parsed_trans).is_err());
    }

    #[test]
    fn test_mesh_router_end_to_end_tunneling() {
        let mut router_a = MeshTunnelRouter::new(51820, 1420);
        let mut router_b = MeshTunnelRouter::new(51821, 1420);

        let a_pub_hex = router_a.local_keypair().public_key_hex();
        let b_pub_hex = router_b.local_keypair().public_key_hex();

        // Register each other
        router_a
            .add_peer(
                "peer-b",
                &b_pub_hex,
                Some("127.0.0.1:51821"),
                &["10.42.2.0/24"],
            )
            .unwrap();
        router_b
            .add_peer(
                "peer-a",
                &a_pub_hex,
                Some("127.0.0.1:51820"),
                &["10.42.1.0/24"],
            )
            .unwrap();

        // Handshake
        let initiation = router_a.initiate_handshake("peer-b", 1000).unwrap();
        let (response, sender_id) = router_b
            .process_handshake_initiation(&initiation, Some("127.0.0.1:51820"), 1005)
            .unwrap();
        assert_eq!(sender_id, "peer-a");

        let finalized_id = router_a
            .process_handshake_response(&response, 1010)
            .unwrap();
        assert_eq!(finalized_id, "peer-b");

        // Encapsulate packet from 10.42.1.5 to 10.42.2.8
        let dest_ip: IpAddr = "10.42.2.8".parse().unwrap();
        let inner_src: IpAddr = "10.42.1.5".parse().unwrap();
        let payload = b"ICMP Echo Request over WireGuard mesh tunnel";

        let transport_pkt = router_a.encapsulate_ip_packet(dest_ip, payload).unwrap();

        // Decapsulate on Router B
        let (decrypted, from_peer) = router_b
            .decapsulate_transport_packet(&transport_pkt, Some("127.0.0.1:51820"), inner_src)
            .unwrap();

        assert_eq!(from_peer, "peer-a");
        assert_eq!(decrypted, payload);

        // Anti-spoofing rejection: inner source IP not in peer-a's AllowedIPs
        let spoofed_src: IpAddr = "192.168.99.1".parse().unwrap();
        let spoof_err = router_b
            .decapsulate_transport_packet(&transport_pkt, None, spoofed_src)
            .unwrap_err();
        assert!(matches!(
            spoof_err,
            MeshError::CryptographicRoutingViolation { .. }
        ));
    }

    #[test]
    fn test_mesh_benchmark_execution() {
        let mut router = MeshTunnelRouter::new(51820, 1420);
        let bench = router.run_benchmark(50, 128);

        assert_eq!(bench.packets_processed, 50);
        assert!(bench.handshake_latency_us > 0.0);
        assert!(bench.encryption_throughput_mb_s > 0.0);
        assert!(bench.decryption_throughput_mb_s > 0.0);
        assert!(bench.anti_replay_checks_per_sec > 0.0);
        assert_eq!(bench.replayed_packets_dropped, 50);
    }
}
