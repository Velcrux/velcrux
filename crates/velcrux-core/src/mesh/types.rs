//! Types, wire structures, and telemetry records for Autonomous Zero-Trust WireGuard
//! / Noise Protocol Mesh Tunnel Fabric (ADR-081).

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::crypto::pqc::x25519;

/// Standard Curve25519 base point (9).
pub const X25519_BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// WireGuard / Noise wire packet types.
pub const PACKET_HANDSHAKE_INITIATION: u8 = 1;
pub const PACKET_HANDSHAKE_RESPONSE: u8 = 2;
pub const PACKET_COOKIE_REPLY: u8 = 3;
pub const PACKET_TRANSPORT_DATA: u8 = 4;

/// Curve25519 (X25519) static or ephemeral keypair.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoiseKeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl NoiseKeyPair {
    /// Generate a new Curve25519 keypair using OS entropy.
    #[must_use]
    pub fn generate() -> Self {
        let mut priv_bytes = [0u8; 32];
        let rng = ring::rand::SystemRandom::new();
        ring::rand::SecureRandom::fill(&rng, &mut priv_bytes).expect("system entropy available");

        Self::from_private_bytes(priv_bytes)
    }

    /// Derive keypair from private key scalar bytes (with standard clamping).
    #[must_use]
    pub fn from_private_bytes(mut priv_bytes: [u8; 32]) -> Self {
        priv_bytes[0] &= 248;
        priv_bytes[31] &= 127;
        priv_bytes[31] |= 64;

        let pub_bytes = x25519(&priv_bytes, &X25519_BASEPOINT);
        Self {
            private_key: priv_bytes,
            public_key: pub_bytes,
        }
    }

    /// Public key formatted as hex string.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.public_key)
    }

    /// Public key formatted as standard base64 string.
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        base64_encode(&self.public_key)
    }
}

impl fmt::Debug for NoiseKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseKeyPair")
            .field("public_key", &self.public_key_hex())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// WireGuard Handshake Initiation message (148 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeInitiationPacket {
    /// Message type (always 1).
    pub msg_type: u8,
    /// Random sender session index chosen by initiator.
    pub sender_index: u32,
    /// Unencrypted ephemeral public key (32 bytes).
    pub unencrypted_ephemeral: [u8; 32],
    /// Static public key of initiator encrypted with chaining key (48 bytes: 32B + 16B tag).
    pub encrypted_static: Vec<u8>,
    /// TAI64N timestamp encrypted with chaining key (28 bytes: 12B + 16B tag).
    pub encrypted_timestamp: Vec<u8>,
    /// First MAC protecting against blind packet injection (16 bytes).
    pub mac1: [u8; 16],
    /// Second MAC protecting against DoS cookie challenges (16 bytes).
    pub mac2: [u8; 16],
}

impl HandshakeInitiationPacket {
    /// Serialize message to 148-byte wire buffer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(148);
        buf.push(self.msg_type);
        buf.extend_from_slice(&[0u8; 3]); // Reserved padding
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.unencrypted_ephemeral);
        buf.extend_from_slice(&self.encrypted_static);
        buf.extend_from_slice(&self.encrypted_timestamp);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        buf
    }

    /// Parse message from wire bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, MeshError> {
        if buf.len() < 148 {
            return Err(MeshError::InvalidPacket(format!(
                "HandshakeInitiation too short: {} bytes (expected 148)",
                buf.len()
            )));
        }
        if buf[0] != PACKET_HANDSHAKE_INITIATION {
            return Err(MeshError::InvalidPacket(format!(
                "Expected packet type {}, got {}",
                PACKET_HANDSHAKE_INITIATION, buf[0]
            )));
        }

        let sender_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let mut unencrypted_ephemeral = [0u8; 32];
        unencrypted_ephemeral.copy_from_slice(&buf[8..40]);

        let encrypted_static = buf[40..88].to_vec();
        let encrypted_timestamp = buf[88..116].to_vec();

        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&buf[116..132]);
        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&buf[132..148]);

        Ok(Self {
            msg_type: buf[0],
            sender_index,
            unencrypted_ephemeral,
            encrypted_static,
            encrypted_timestamp,
            mac1,
            mac2,
        })
    }
}

/// WireGuard Handshake Response message (92 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponsePacket {
    /// Message type (always 2).
    pub msg_type: u8,
    /// Sender session index chosen by responder.
    pub sender_index: u32,
    /// Receiver session index (initiator's sender_index).
    pub receiver_index: u32,
    /// Unencrypted ephemeral public key of responder (32 bytes).
    pub unencrypted_ephemeral: [u8; 32],
    /// Empty payload encrypted with chaining key (16 bytes tag).
    pub encrypted_empty: Vec<u8>,
    /// First MAC.
    pub mac1: [u8; 16],
    /// Second MAC.
    pub mac2: [u8; 16],
}

impl HandshakeResponsePacket {
    /// Serialize message to 92-byte wire buffer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(92);
        buf.push(self.msg_type);
        buf.extend_from_slice(&[0u8; 3]); // Reserved padding
        buf.extend_from_slice(&self.sender_index.to_le_bytes());
        buf.extend_from_slice(&self.receiver_index.to_le_bytes());
        buf.extend_from_slice(&self.unencrypted_ephemeral);
        buf.extend_from_slice(&self.encrypted_empty);
        buf.extend_from_slice(&self.mac1);
        buf.extend_from_slice(&self.mac2);
        buf
    }

    /// Parse message from wire bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, MeshError> {
        if buf.len() < 92 {
            return Err(MeshError::InvalidPacket(format!(
                "HandshakeResponse too short: {} bytes (expected 92)",
                buf.len()
            )));
        }
        if buf[0] != PACKET_HANDSHAKE_RESPONSE {
            return Err(MeshError::InvalidPacket(format!(
                "Expected packet type {}, got {}",
                PACKET_HANDSHAKE_RESPONSE, buf[0]
            )));
        }

        let sender_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let receiver_index = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let mut unencrypted_ephemeral = [0u8; 32];
        unencrypted_ephemeral.copy_from_slice(&buf[12..44]);
        let encrypted_empty = buf[44..60].to_vec();

        let mut mac1 = [0u8; 16];
        mac1.copy_from_slice(&buf[60..76]);
        let mut mac2 = [0u8; 16];
        mac2.copy_from_slice(&buf[76..92]);

        Ok(Self {
            msg_type: buf[0],
            sender_index,
            receiver_index,
            unencrypted_ephemeral,
            encrypted_empty,
            mac1,
            mac2,
        })
    }
}

/// WireGuard Transport Data message carrying encrypted IP packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportDataPacket {
    /// Message type (always 4).
    pub msg_type: u8,
    /// Receiver session index identifying target peer.
    pub receiver_index: u32,
    /// 64-bit monotonically increasing transmission counter.
    pub counter: u64,
    /// Encrypted IP payload (payload length + 16 bytes auth tag).
    pub encrypted_payload: Vec<u8>,
}

impl TransportDataPacket {
    /// Serialize message to wire buffer.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.encrypted_payload.len());
        buf.push(self.msg_type);
        buf.extend_from_slice(&[0u8; 3]); // Reserved padding
        buf.extend_from_slice(&self.receiver_index.to_le_bytes());
        buf.extend_from_slice(&self.counter.to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Parse message from wire bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, MeshError> {
        if buf.len() < 32 {
            // Header is 16 bytes + at least 16 bytes auth tag
            return Err(MeshError::InvalidPacket(format!(
                "TransportData too short: {} bytes (expected >= 32)",
                buf.len()
            )));
        }
        if buf[0] != PACKET_TRANSPORT_DATA {
            return Err(MeshError::InvalidPacket(format!(
                "Expected packet type {}, got {}",
                PACKET_TRANSPORT_DATA, buf[0]
            )));
        }

        let receiver_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let encrypted_payload = buf[16..].to_vec();

        Ok(Self {
            msg_type: buf[0],
            receiver_index,
            counter,
            encrypted_payload,
        })
    }
}

/// Detailed telemetry status of an individual mesh peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    /// Local assigned peer ID.
    pub peer_id: String,
    /// Peer Curve25519 public key (hex formatted).
    pub public_key: String,
    /// Remote socket endpoint (IP:Port), if known.
    pub endpoint: Option<String>,
    /// List of routed AllowedIPs CIDR prefixes.
    pub allowed_ips: Vec<String>,
    /// Unix millisecond timestamp of last successful handshake.
    pub last_handshake_ms: u64,
    /// Total bytes transmitted to peer.
    pub tx_bytes: u64,
    /// Total bytes received from peer.
    pub rx_bytes: u64,
    /// Whether an authenticated session is currently established.
    pub is_connected: bool,
}

/// Global operational status of the WireGuard / Noise mesh router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshStatusReport {
    /// Virtual interface name (e.g. "vlx-wg0").
    pub interface_name: String,
    /// Local public key (hex formatted).
    pub public_key: String,
    /// Local public key in standard base64.
    pub public_key_base64: String,
    /// Listening UDP port.
    pub listen_port: u16,
    /// Configured MTU.
    pub mtu: usize,
    /// Total configured peers.
    pub peer_count: usize,
    /// Number of actively connected peers with established sessions.
    pub connected_peer_count: usize,
    /// Total bytes transmitted across mesh.
    pub total_tx_bytes: u64,
    /// Total bytes received across mesh.
    pub total_rx_bytes: u64,
    /// List of peer statuses.
    pub peers: Vec<PeerStatus>,
}

/// Benchmark performance report for WireGuard / Noise mesh router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshBenchmarkReport {
    /// Total simulated IP packets processed.
    pub packets_processed: usize,
    /// Size of each packet payload in bytes.
    pub packet_size_bytes: usize,
    /// Full Noise_IKpsk2 handshake latency in microseconds.
    pub handshake_latency_us: f64,
    /// Symmetric transport encryption throughput in MB/s.
    pub encryption_throughput_mb_s: f64,
    /// Symmetric transport decryption throughput in MB/s.
    pub decryption_throughput_mb_s: f64,
    /// Anti-replay sliding window validation rate (checks/sec).
    pub anti_replay_checks_per_sec: f64,
    /// Replayed packets successfully dropped by anti-replay barrier.
    pub replayed_packets_dropped: u64,
}

/// Domain errors encountered during WireGuard / Noise mesh tunneling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum MeshError {
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Replay attack detected: packet counter {counter} <= highest {highest}")]
    ReplayAttackDetected { counter: u64, highest: u64 },

    #[error("Cryptographic authentication failed: invalid tag or corrupted ciphertext")]
    DecryptionFailed,

    #[error("Cryptographic routing violation: source IP {source_ip} not authorized for peer '{peer_id}'")]
    CryptographicRoutingViolation { source_ip: String, peer_id: String },

    #[error("Peer not found: '{0}'")]
    PeerNotFound(String),

    #[error("Peer '{0}' already exists")]
    PeerAlreadyExists(String),

    #[error("Invalid WireGuard packet: {0}")]
    InvalidPacket(String),

    #[error("Invalid CIDR prefix: '{0}'")]
    InvalidCidr(String),

    #[error("Session expired or not established with peer '{0}'")]
    SessionNotEstablished(String),

    #[error("Destination IP {0} not routable across active mesh peers")]
    NoRouteToHost(IpAddr),
}

/// Result alias for mesh operations.
pub type MeshResult<T> = std::result::Result<T, MeshError>;

// -----------------------------------------------------------------------------
// Safe Encoding Helpers
// -----------------------------------------------------------------------------

/// Encode byte slice to hex string.
#[must_use]
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Decode hex string into a 32-byte array.
pub fn hex_decode_32(hex_str: &str) -> Result<[u8; 32], MeshError> {
    let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    if clean.len() != 64 {
        return Err(MeshError::InvalidPacket(format!(
            "Hex string must be exactly 64 hex characters (got {})",
            clean.len()
        )));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_str = &clean[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| MeshError::InvalidPacket("Invalid hex character".to_string()))?;
    }
    Ok(out)
}

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode byte slice to standard base64 string.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        let idx0 = (b0 >> 2) as usize;
        let idx1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
        let idx2 = (((b1 & 0x0f) << 2) | (b2 >> 6)) as usize;
        let idx3 = (b2 & 0x3f) as usize;

        s.push(BASE64_CHARS[idx0] as char);
        s.push(BASE64_CHARS[idx1] as char);
        if i + 1 < data.len() {
            s.push(BASE64_CHARS[idx2] as char);
        } else {
            s.push('=');
        }
        if i + 2 < data.len() {
            s.push(BASE64_CHARS[idx3] as char);
        } else {
            s.push('=');
        }
        i += 3;
    }
    s
}
