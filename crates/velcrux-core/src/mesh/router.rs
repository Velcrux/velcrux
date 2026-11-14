//! Multi-Peer WireGuard / Noise Mesh Tunnel Router (ADR-081).
//!
//! Orchestrates the zero-trust mesh network:
//! - Multi-peer registration and dynamic endpoint roaming.
//! - Cryptographic routing trie with longest-prefix matching and anti-spoofing.
//! - Automated Noise_IKpsk2 handshakes and session key rotation.
//! - WireGuard transport packet encapsulation and decapsulation with anti-replay barriers.

use std::collections::HashMap;
use std::net::IpAddr;

use super::noise::{EphemeralState, NoiseHandshake, NoiseSession};
use super::trie::AllowedIpsTrie;
use super::types::{
    hex_decode_32, HandshakeInitiationPacket, HandshakeResponsePacket, MeshBenchmarkReport,
    MeshError, MeshResult, MeshStatusReport, NoiseKeyPair, PeerStatus, TransportDataPacket,
};

/// Internal record representing a configured mesh peer.
#[derive(Debug, Clone)]
struct PeerRecord {
    peer_id: String,
    public_key: [u8; 32],
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    session: Option<NoiseSession>,
    pending_handshake: Option<EphemeralState>,
    last_handshake_ms: u64,
}

/// Autonomous WireGuard / Noise mesh tunnel router.
#[derive(Debug, Clone)]
pub struct MeshTunnelRouter {
    local_keypair: NoiseKeyPair,
    listen_port: u16,
    mtu: usize,
    peers: HashMap<String, PeerRecord>,
    index_to_peer: HashMap<u32, String>,
    routing_trie: AllowedIpsTrie,
    next_index: u32,
}

impl MeshTunnelRouter {
    /// Create a new mesh tunnel router with a randomly generated local keypair.
    #[must_use]
    pub fn new(listen_port: u16, mtu: usize) -> Self {
        Self {
            local_keypair: NoiseKeyPair::generate(),
            listen_port,
            mtu,
            peers: HashMap::new(),
            index_to_peer: HashMap::new(),
            routing_trie: AllowedIpsTrie::new(),
            next_index: 1000,
        }
    }

    /// Create router with an explicit static keypair.
    #[must_use]
    pub fn with_keypair(keypair: NoiseKeyPair, listen_port: u16, mtu: usize) -> Self {
        Self {
            local_keypair: keypair,
            listen_port,
            mtu,
            peers: HashMap::new(),
            index_to_peer: HashMap::new(),
            routing_trie: AllowedIpsTrie::new(),
            next_index: 1000,
        }
    }

    /// Access local static keypair.
    #[must_use]
    pub fn local_keypair(&self) -> &NoiseKeyPair {
        &self.local_keypair
    }

    /// Configured listening UDP port.
    #[must_use]
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Register a new remote peer in the mesh.
    pub fn add_peer(
        &mut self,
        peer_id: impl Into<String>,
        public_key_hex: &str,
        endpoint: Option<&str>,
        allowed_ips: &[&str],
    ) -> MeshResult<()> {
        let p_id = peer_id.into();
        if self.peers.contains_key(&p_id) {
            return Err(MeshError::PeerAlreadyExists(p_id));
        }

        let pub_key = hex_decode_32(public_key_hex)?;

        // Register CIDR prefixes in cryptographic routing trie
        for &cidr in allowed_ips {
            self.routing_trie.insert(cidr, &p_id)?;
        }

        let record = PeerRecord {
            peer_id: p_id.clone(),
            public_key: pub_key,
            endpoint: endpoint.map(|s| s.to_string()),
            allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
            session: None,
            pending_handshake: None,
            last_handshake_ms: 0,
        };

        self.peers.insert(p_id, record);
        Ok(())
    }

    /// Remove a peer from the mesh and purge its routes and session keys.
    pub fn remove_peer(&mut self, peer_id: &str) -> MeshResult<()> {
        let Some(peer) = self.peers.remove(peer_id) else {
            return Err(MeshError::PeerNotFound(peer_id.to_string()));
        };

        if let Some(session) = peer.session {
            self.index_to_peer.remove(&session.local_index);
        }
        self.routing_trie.remove_peer(peer_id);
        Ok(())
    }

    /// Initiate a Noise_IKpsk2 handshake with a configured peer.
    pub fn initiate_handshake(
        &mut self,
        peer_id: &str,
        now_ms: u64,
    ) -> MeshResult<HandshakeInitiationPacket> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| MeshError::PeerNotFound(peer_id.to_string()))?;

        self.next_index = self.next_index.saturating_add(1);
        let sender_index = self.next_index;

        let (packet, state) = NoiseHandshake::create_initiation(
            &self.local_keypair,
            &peer.public_key,
            sender_index,
            now_ms,
        )?;

        peer.pending_handshake = Some(state);
        self.index_to_peer.insert(sender_index, peer_id.to_string());

        Ok(packet)
    }

    /// Process an incoming HandshakeInitiation packet from a remote peer.
    pub fn process_handshake_initiation(
        &mut self,
        packet: &HandshakeInitiationPacket,
        sender_endpoint: Option<&str>,
        now_ms: u64,
    ) -> MeshResult<(HandshakeResponsePacket, String)> {
        self.next_index = self.next_index.saturating_add(1);
        let responder_index = self.next_index;

        let (resp_packet, initiator_pubkey, session) =
            NoiseHandshake::process_initiation_and_respond(
                &self.local_keypair,
                packet,
                responder_index,
                now_ms,
            )?;

        // Find peer matching the decrypted static public key
        let matching_peer_id = self
            .peers
            .values()
            .find(|p| p.public_key == initiator_pubkey)
            .map(|p| p.peer_id.clone())
            .ok_or_else(|| {
                MeshError::HandshakeFailed("Initiator public key not registered".to_string())
            })?;

        let peer = self.peers.get_mut(&matching_peer_id).unwrap();
        if let Some(ep) = sender_endpoint {
            peer.endpoint = Some(ep.to_string());
        }
        peer.session = Some(session);
        peer.last_handshake_ms = now_ms;

        self.index_to_peer
            .insert(responder_index, matching_peer_id.clone());

        Ok((resp_packet, matching_peer_id))
    }

    /// Process an incoming HandshakeResponse packet on the initiator to finalize session.
    pub fn process_handshake_response(
        &mut self,
        packet: &HandshakeResponsePacket,
        now_ms: u64,
    ) -> MeshResult<String> {
        let peer_id = self
            .index_to_peer
            .get(&packet.receiver_index)
            .cloned()
            .ok_or_else(|| MeshError::HandshakeFailed("Unknown receiver index".to_string()))?;

        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| MeshError::PeerNotFound(peer_id.clone()))?;

        let pending = peer
            .pending_handshake
            .take()
            .ok_or_else(|| MeshError::HandshakeFailed("No pending handshake found".to_string()))?;

        let session = NoiseHandshake::process_response(
            &self.local_keypair,
            &peer.public_key,
            pending,
            packet,
            now_ms,
        )?;

        peer.session = Some(session);
        peer.last_handshake_ms = now_ms;

        Ok(peer_id)
    }

    /// Encapsulate an outgoing IP packet destined for `destination_ip`.
    ///
    /// Routes the packet via longest-prefix matching against the `AllowedIPs` trie.
    pub fn encapsulate_ip_packet(
        &mut self,
        destination_ip: IpAddr,
        payload: &[u8],
    ) -> MeshResult<TransportDataPacket> {
        let peer_id = self
            .routing_trie
            .lookup(destination_ip)
            .ok_or(MeshError::NoRouteToHost(destination_ip))?
            .to_string();

        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| MeshError::PeerNotFound(peer_id.clone()))?;

        let session = peer
            .session
            .as_mut()
            .ok_or_else(|| MeshError::SessionNotEstablished(peer_id))?;

        session.encrypt_transport_data(payload)
    }

    /// Decapsulate an incoming TransportData packet.
    ///
    /// Enforces:
    /// 1. Anti-replay sliding window.
    /// 2. ChaCha20-Poly1305 authenticated decryption.
    /// 3. WireGuard cryptographic routing / anti-spoofing verification (`inner_source_ip`).
    /// 4. Roaming endpoint update if incoming IP/port changed.
    pub fn decapsulate_transport_packet(
        &mut self,
        packet: &TransportDataPacket,
        sender_endpoint: Option<&str>,
        inner_source_ip: IpAddr,
    ) -> MeshResult<(Vec<u8>, String)> {
        let peer_id = self
            .index_to_peer
            .get(&packet.receiver_index)
            .cloned()
            .ok_or_else(|| {
                MeshError::InvalidPacket(format!(
                    "Unknown receiver session index {}",
                    packet.receiver_index
                ))
            })?;

        // Anti-spoofing validation: check inner IP is authorized for this peer
        if !self.routing_trie.check_allowed(inner_source_ip, &peer_id) {
            return Err(MeshError::CryptographicRoutingViolation {
                source_ip: inner_source_ip.to_string(),
                peer_id,
            });
        }

        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| MeshError::PeerNotFound(peer_id.clone()))?;

        // Roaming: update endpoint if sender changed IP/port
        if let Some(ep) = sender_endpoint {
            peer.endpoint = Some(ep.to_string());
        }

        let session = peer
            .session
            .as_mut()
            .ok_or_else(|| MeshError::SessionNotEstablished(peer_id.clone()))?;

        let plaintext = session.decrypt_transport_data(packet)?;
        Ok((plaintext, peer_id))
    }

    /// Generate complete operational status report for the mesh interface.
    #[must_use]
    pub fn status(&self) -> MeshStatusReport {
        let mut total_tx = 0u64;
        let mut total_rx = 0u64;
        let mut connected_count = 0usize;
        let mut peer_statuses = Vec::new();

        for (id, peer) in &self.peers {
            let is_conn = peer.session.is_some();
            if is_conn {
                connected_count += 1;
            }

            let (tx, rx) = peer
                .session
                .as_ref()
                .map(|s| (s.tx_bytes, s.rx_bytes))
                .unwrap_or((0, 0));

            total_tx = total_tx.saturating_add(tx);
            total_rx = total_rx.saturating_add(rx);

            peer_statuses.push(PeerStatus {
                peer_id: id.clone(),
                public_key: super::types::hex_encode(&peer.public_key),
                endpoint: peer.endpoint.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                last_handshake_ms: peer.last_handshake_ms,
                tx_bytes: tx,
                rx_bytes: rx,
                is_connected: is_conn,
            });
        }

        peer_statuses.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

        MeshStatusReport {
            interface_name: "vlx-wg0".to_string(),
            public_key: self.local_keypair.public_key_hex(),
            public_key_base64: self.local_keypair.public_key_base64(),
            listen_port: self.listen_port,
            mtu: self.mtu,
            peer_count: self.peers.len(),
            connected_peer_count: connected_count,
            total_tx_bytes: total_tx,
            total_rx_bytes: total_rx,
            peers: peer_statuses,
        }
    }

    /// Retrieve list of all peer statuses.
    #[must_use]
    pub fn peers_list(&self) -> Vec<PeerStatus> {
        self.status().peers
    }

    /// Run microsecond benchmark testing Noise handshake, transport cipher throughput, and anti-replay barriers.
    pub fn run_benchmark(&mut self, packets: usize, packet_size: usize) -> MeshBenchmarkReport {
        let total_packets = packets.max(10);
        let payload_size = packet_size.max(64);

        // 1. Measure Noise handshake latency
        let peer_b_keypair = NoiseKeyPair::generate();
        let peer_b_pub_hex = peer_b_keypair.public_key_hex();
        let _ = self.add_peer("bench-peer", &peer_b_pub_hex, None, &["10.99.0.0/24"]);

        let hs_start = std::time::Instant::now();
        let initiation = self
            .initiate_handshake("bench-peer", 10_000)
            .expect("initiation generated");

        let mut peer_b_router = MeshTunnelRouter::with_keypair(peer_b_keypair, 51821, 1420);
        let _ = peer_b_router.add_peer(
            "router-a",
            &self.local_keypair.public_key_hex(),
            None,
            &["10.99.1.0/24"],
        );

        let (response, _) = peer_b_router
            .process_handshake_initiation(&initiation, None, 10_000)
            .expect("response generated");

        let _ = self
            .process_handshake_response(&response, 10_000)
            .expect("handshake finalized");
        let hs_elapsed = hs_start.elapsed();
        let handshake_latency_us = hs_elapsed.as_micros() as f64;

        // 2. Measure transport encryption & decryption throughput
        let dummy_payload = vec![0x5a; payload_size];
        let dummy_ip: IpAddr = "10.99.0.42".parse().unwrap();
        let return_ip: IpAddr = "10.99.1.1".parse().unwrap();

        let mut transport_packets = Vec::with_capacity(total_packets);

        let enc_start = std::time::Instant::now();
        for _ in 0..total_packets {
            let pkt = self
                .encapsulate_ip_packet(dummy_ip, &dummy_payload)
                .expect("packet encrypted");
            transport_packets.push(pkt);
        }
        let enc_elapsed = enc_start.elapsed();
        let total_bytes = (total_packets * payload_size) as f64;
        let encryption_throughput_mb_s =
            (total_bytes / (1024.0 * 1024.0)) / enc_elapsed.as_secs_f64().max(0.000001);

        let dec_start = std::time::Instant::now();
        for pkt in &transport_packets {
            let (decrypted, _) = peer_b_router
                .decapsulate_transport_packet(pkt, None, return_ip)
                .expect("packet decrypted");
            assert_eq!(decrypted.len(), payload_size);
        }
        let dec_elapsed = dec_start.elapsed();
        let decryption_throughput_mb_s =
            (total_bytes / (1024.0 * 1024.0)) / dec_elapsed.as_secs_f64().max(0.000001);

        // 3. Measure Anti-Replay validation rate and replay detection
        let mut replayed_dropped = 0u64;
        let replay_start = std::time::Instant::now();
        for pkt in &transport_packets {
            // Attempting to re-feed identical packet to peer_b_router MUST be rejected
            if peer_b_router
                .decapsulate_transport_packet(pkt, None, return_ip)
                .is_err()
            {
                replayed_dropped += 1;
            }
        }
        let replay_elapsed = replay_start.elapsed();
        let anti_replay_checks_per_sec =
            (total_packets as f64) / replay_elapsed.as_secs_f64().max(0.000001);

        // Clean up benchmark peer
        let _ = self.remove_peer("bench-peer");

        MeshBenchmarkReport {
            packets_processed: total_packets,
            packet_size_bytes: payload_size,
            handshake_latency_us,
            encryption_throughput_mb_s,
            decryption_throughput_mb_s,
            anti_replay_checks_per_sec,
            replayed_packets_dropped: replayed_dropped,
        }
    }
}
