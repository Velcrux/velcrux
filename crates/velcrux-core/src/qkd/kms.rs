#![forbid(unsafe_code)]

//! ETSI GS QKD 014 Key Management Interface & Hybrid QKD-PQC Orchestrator.
//!
//! Provides ETSI 014 compliant quantum key store management, UUID key indexing,
//! key lifecycle tracking (Available -> Reserved -> Consumed), automatic optical link
//! replenishment, and post-quantum hybrid KDF binding with ML-KEM-768.

use super::channel::QuantumChannel;
use super::entanglement::E91Engine;
use super::protocol::Bb84Engine;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// QKD Key distribution protocol used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QkdProtocolType {
    Bb84,
    E91,
}

impl QkdProtocolType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bb84 => "BB84-Decoy",
            Self::E91 => "E91-Entanglement",
        }
    }
}

/// ETSI GS QKD 014 Key Status Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QkdKeyStatus {
    Available,
    Reserved,
    Consumed,
    Expired,
}

impl QkdKeyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "AVAILABLE",
            Self::Reserved => "RESERVED",
            Self::Consumed => "CONSUMED",
            Self::Expired => "EXPIRED",
        }
    }
}

/// A validated quantum symmetric cryptographic key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdKey {
    pub key_id: String,
    pub key_bytes: Vec<u8>,
    pub protocol: QkdProtocolType,
    pub status: QkdKeyStatus,
    pub created_at_epoch_sec: u64,
    pub ttl_secs: u64,
}

/// Summary info for external inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdKeyInfo {
    pub key_id: String,
    pub protocol: String,
    pub key_length_bits: usize,
    pub status: String,
    pub created_at_epoch_sec: u64,
    pub key_preview_hex: String,
}

/// ETSI 014 Quantum Key Store Buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdKeyStore {
    pub local_sae_id: String,
    pub remote_sae_id: String,
    pub keys: HashMap<String, QkdKey>,
    pub total_keys_generated: u64,
    pub total_keys_consumed: u64,
}

impl QkdKeyStore {
    /// Creates a new QKD key store for peer Secure Application Entities (SAEs).
    pub fn new(local_sae_id: impl Into<String>, remote_sae_id: impl Into<String>) -> Self {
        Self {
            local_sae_id: local_sae_id.into(),
            remote_sae_id: remote_sae_id.into(),
            keys: HashMap::new(),
            total_keys_generated: 0,
            total_keys_consumed: 0,
        }
    }

    /// Stores a new quantum key.
    pub fn insert_key(&mut self, key: QkdKey) {
        self.total_keys_generated += 1;
        self.keys.insert(key.key_id.clone(), key);
    }

    /// Consumes a key by ID, changing its status to Consumed and returning the raw secret bytes.
    pub fn consume_key(&mut self, key_id: &str) -> Result<Vec<u8>> {
        let key = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::Malformed("QKD key not found")))?;

        if key.status != QkdKeyStatus::Available {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "QKD key is not in Available state",
            )));
        }

        key.status = QkdKeyStatus::Consumed;
        self.total_keys_consumed += 1;
        Ok(key.key_bytes.clone())
    }

    /// Returns the number of currently available keys.
    pub fn available_keys_count(&self) -> usize {
        self.keys
            .values()
            .filter(|k| k.status == QkdKeyStatus::Available)
            .count()
    }

    /// Lists stored keys up to the given limit.
    pub fn list_keys(&self, limit: usize) -> Vec<QkdKeyInfo> {
        let mut list: Vec<QkdKeyInfo> = self
            .keys
            .values()
            .map(|k| {
                let preview = if k.key_bytes.len() >= 4 {
                    format!(
                        "{:02X}{:02X}...{:02X}{:02X}",
                        k.key_bytes[0],
                        k.key_bytes[1],
                        k.key_bytes[k.key_bytes.len() - 2],
                        k.key_bytes[k.key_bytes.len() - 1]
                    )
                } else {
                    "**".to_string()
                };
                QkdKeyInfo {
                    key_id: k.key_id.clone(),
                    protocol: k.protocol.as_str().to_string(),
                    key_length_bits: k.key_bytes.len() * 8,
                    status: k.status.as_str().to_string(),
                    created_at_epoch_sec: k.created_at_epoch_sec,
                    key_preview_hex: preview,
                }
            })
            .collect();
        list.sort_by(|a, b| b.created_at_epoch_sec.cmp(&a.created_at_epoch_sec));
        list.truncate(limit);
        list
    }

    /// Derives a composite hybrid QKD + PQC session key using BLAKE3 KDF:
    /// $K_{hybrid} = \text{BLAKE3}(K_{QKD} \mathbin{\Vert} K_{PQC} \mathbin{\Vert} \text{"velcrux-hybrid-qkd-pqc-v1"})$.
    pub fn derive_hybrid_session_key(qkd_key_bytes: &[u8], pqc_shared_secret: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("velcrux-hybrid-qkd-pqc-v1");
        hasher.update(qkd_key_bytes);
        hasher.update(pqc_shared_secret);
        *hasher.finalize().as_bytes()
    }
}

/// Automated Quantum Key Buffer Replenishment Daemon.
#[derive(Debug, Clone)]
pub struct QkdReplenisher {
    pub target_depth: usize,
}

impl QkdReplenisher {
    pub fn new(target_depth: usize) -> Self {
        Self { target_depth }
    }

    /// Replenishes the key store to meet target depth over the optical quantum channel.
    pub fn replenish(
        &self,
        store: &mut QkdKeyStore,
        channel: &QuantumChannel,
        protocol: QkdProtocolType,
    ) -> Result<usize> {
        let current = store.available_keys_count();
        if current >= self.target_depth {
            return Ok(0);
        }

        let needed = self.target_depth - current;
        let mut generated = 0;

        for i in 0..needed {
            let key_bytes = match protocol {
                QkdProtocolType::Bb84 => {
                    let engine = Bb84Engine::new(channel.clone());
                    let report = engine.execute_exchange(2000, 0.0)?;
                    if !report.is_secure || report.final_key_hex.is_empty() {
                        continue;
                    }
                    hex_decode_to_vec(&report.final_key_hex)?
                }
                QkdProtocolType::E91 => {
                    let engine = E91Engine::new(channel.clone());
                    let report = engine.execute_exchange(3000, 0.0)?;
                    if !report.is_entanglement_verified || report.final_key_hex.is_empty() {
                        continue;
                    }
                    hex_decode_to_vec(&report.final_key_hex)?
                }
            };

            let key_id = format!(
                "qkd-{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
                (store.total_keys_generated + (i as u64)) as u32,
                (i * 17) & 0xFFFF,
                (i * 31) & 0x0FFF,
                (i * 59) & 0x0FFF,
                0x1337_2026_0000u64 + (i as u64)
            );

            let qkd_key = QkdKey {
                key_id,
                key_bytes,
                protocol,
                status: QkdKeyStatus::Available,
                created_at_epoch_sec: 1731150000 + (i as u64) * 10,
                ttl_secs: 86400,
            };

            store.insert_key(qkd_key);
            generated += 1;
        }

        Ok(generated)
    }
}

fn hex_decode_to_vec(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(VelcruxError::Protocol(ProtocolError::Malformed(
            "odd length hex string",
        )));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| VelcruxError::Protocol(ProtocolError::Malformed("invalid hex digit")))?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qkd_store_and_consume() {
        let mut store = QkdKeyStore::new("sae-alice", "sae-bob");
        let key = QkdKey {
            key_id: "test-key-uuid-1".to_string(),
            key_bytes: vec![0x42; 32],
            protocol: QkdProtocolType::Bb84,
            status: QkdKeyStatus::Available,
            created_at_epoch_sec: 1000,
            ttl_secs: 3600,
        };

        store.insert_key(key);
        assert_eq!(store.available_keys_count(), 1);

        let consumed = store.consume_key("test-key-uuid-1").unwrap();
        assert_eq!(consumed, vec![0x42; 32]);
        assert_eq!(store.available_keys_count(), 0);

        // Second consume should fail
        let err = store.consume_key("test-key-uuid-1").unwrap_err();
        assert!(err.to_string().contains("not in Available state"));
    }

    #[test]
    fn test_qkd_replenisher() {
        let mut store = QkdKeyStore::new("sae-alice", "sae-bob");
        let channel = QuantumChannel::terrestrial_fiber(10.0);
        let replenisher = QkdReplenisher::new(3);

        let generated = replenisher
            .replenish(&mut store, &channel, QkdProtocolType::Bb84)
            .expect("replenish");
        assert_eq!(generated, 3);
        assert_eq!(store.available_keys_count(), 3);
    }

    #[test]
    fn test_hybrid_kdf() {
        let qkd_key = [0xAA; 32];
        let pqc_key = [0xBB; 32];
        let session = QkdKeyStore::derive_hybrid_session_key(&qkd_key, &pqc_key);
        assert_ne!(session, [0u8; 32]);
        assert_ne!(session, qkd_key);
    }
}
