//! Distributed Remote Hardware Root-of-Trust Mesh Engine.
//!
//! Maintains mutual hardware attestation between cluster nodes, enforcing continuous
//! verification, TCB freshness, and TLS 1.3 channel binding across storage and compute peers.

#![forbid(unsafe_code)]

use super::attestation::{EnclaveAttestationEngine, EnclaveVerificationReport};
use super::binding::verify_channel_binding;
use super::types::{
    EnclaveAttestationEvidence, EnclaveMeasurement, EnclavePlatform, EnclavePolicy, TcbVersion,
};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Registered cluster peer in the hardware root-of-trust mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveMeshPeer {
    pub node_id: String,
    pub endpoint: SocketAddr,
    pub platform: EnclavePlatform,
    pub measurement: EnclaveMeasurement,
    pub hardware_chip_id: [u8; 32],
    pub tcb_version: TcbVersion,
    pub verified_at_epoch: u64,
    pub valid_until_epoch: u64,
    pub is_trusted: bool,
}

/// Central Enclave Root-of-Trust Mesh Coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveMeshEngine {
    pub local_node_id: String,
    pub local_platform: EnclavePlatform,
    pub peers: HashMap<String, EnclaveMeshPeer>,
    pub policy: EnclavePolicy,
    pub total_attestations_verified: u64,
    pub total_attestations_rejected: u64,
    pub total_peers_revoked: u64,
}

impl EnclaveMeshEngine {
    pub fn new(local_node_id: impl Into<String>, local_platform: EnclavePlatform) -> Self {
        Self {
            local_node_id: local_node_id.into(),
            local_platform,
            peers: HashMap::new(),
            policy: EnclavePolicy::default(),
            total_attestations_verified: 0,
            total_attestations_rejected: 0,
            total_peers_revoked: 0,
        }
    }

    pub fn with_policy(mut self, policy: EnclavePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Verifies peer attestation evidence and registers the peer in the trusted mesh.
    pub fn verify_and_register_peer(
        &mut self,
        node_id: &str,
        endpoint: SocketAddr,
        evidence: &EnclaveAttestationEvidence,
        tls_exporter_secret: &[u8; 32],
    ) -> Result<EnclaveVerificationReport> {
        // 1. Verify TLS 1.3 Channel Binding
        let binding_res = verify_channel_binding(
            &evidence.quote.report_data,
            tls_exporter_secret,
            &evidence.client_channel_nonce,
            &evidence.server_channel_nonce,
            node_id.as_bytes(),
        );

        if let Err(e) = binding_res {
            self.total_attestations_rejected = self.total_attestations_rejected.saturating_add(1);
            return Err(e);
        }

        // 2. Verify Enclave Hardware Attestation Quote
        let attestation_engine = EnclaveAttestationEngine::new(evidence.quote.platform);
        let report_res = attestation_engine.verify_quote(
            &evidence.quote,
            Some(&evidence.quote.report_data),
            &self.policy,
        );

        let report = match report_res {
            Ok(rep) => rep,
            Err(e) => {
                self.total_attestations_rejected =
                    self.total_attestations_rejected.saturating_add(1);
                return Err(e);
            }
        };

        // 3. Register trusted peer in mesh
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let valid_until = now.saturating_add(self.policy.max_quote_age_seconds);

        let peer = EnclaveMeshPeer {
            node_id: node_id.to_string(),
            endpoint,
            platform: evidence.quote.platform,
            measurement: evidence.quote.measurement.clone(),
            hardware_chip_id: evidence.quote.hardware_chip_id,
            tcb_version: evidence.quote.tcb_version,
            verified_at_epoch: now,
            valid_until_epoch: valid_until,
            is_trusted: true,
        };

        self.peers.insert(node_id.to_string(), peer);
        self.total_attestations_verified = self.total_attestations_verified.saturating_add(1);

        Ok(report)
    }

    /// Checks if a designated node is currently trusted in the enclave mesh.
    pub fn is_peer_trusted(&self, node_id: &str, now_epoch: u64) -> bool {
        if let Some(peer) = self.peers.get(node_id) {
            peer.is_trusted && now_epoch <= peer.valid_until_epoch
        } else {
            false
        }
    }

    /// Manually revokes trust for a peer node.
    pub fn revoke_peer(&mut self, node_id: &str) -> bool {
        if let Some(peer) = self.peers.get_mut(node_id) {
            if peer.is_trusted {
                peer.is_trusted = false;
                self.total_peers_revoked = self.total_peers_revoked.saturating_add(1);
                return true;
            }
        }
        false
    }

    /// Prunes expired peer attestations from active trusted status.
    pub fn prune_expired(&mut self, now_epoch: u64) -> usize {
        let mut expired_count = 0;
        for peer in self.peers.values_mut() {
            if peer.is_trusted && now_epoch > peer.valid_until_epoch {
                peer.is_trusted = false;
                expired_count += 1;
            }
        }
        expired_count
    }

    /// Number of currently trusted nodes.
    pub fn trusted_peer_count(&self, now_epoch: u64) -> usize {
        self.peers
            .values()
            .filter(|p| p.is_trusted && now_epoch <= p.valid_until_epoch)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::binding::generate_channel_binding_report_data;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_enclave_mesh_peer_registration_and_trust_verification() {
        let mut mesh = EnclaveMeshEngine::new("coordinator-01", EnclavePlatform::Simulated);
        let target_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 20)), 7443);

        let exporter_secret = [0x99u8; 32];
        let client_nonce = [0x01u8; 32];
        let server_nonce = [0x02u8; 32];
        let peer_node_id = "storage-enclave-node-02";

        let report_data = generate_channel_binding_report_data(
            &exporter_secret,
            &client_nonce,
            &server_nonce,
            peer_node_id.as_bytes(),
        );

        let attestation_engine = EnclaveAttestationEngine::new(EnclavePlatform::AmdSevSnp);
        let measurement = EnclaveMeasurement::simulated("velcrux-storage-daemon");
        let tcb = TcbVersion::production_baseline();
        let quote = attestation_engine.generate_quote(measurement, report_data, tcb, false);

        let evidence = EnclaveAttestationEvidence {
            quote,
            client_channel_nonce: client_nonce,
            server_channel_nonce: server_nonce,
            tls_exporter_secret_hash: *blake3::hash(&exporter_secret).as_bytes(),
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Initial registration
        let report = mesh
            .verify_and_register_peer(peer_node_id, target_endpoint, &evidence, &exporter_secret)
            .expect("peer verified");

        assert!(report.is_valid);
        assert!(mesh.is_peer_trusted(peer_node_id, now));
        assert_eq!(mesh.trusted_peer_count(now), 1);

        // 2. Check expiration pruning
        let future_expired = now + 4000;
        assert!(!mesh.is_peer_trusted(peer_node_id, future_expired));
        let pruned = mesh.prune_expired(future_expired);
        assert_eq!(pruned, 1);
        assert_eq!(mesh.trusted_peer_count(future_expired), 0);
    }
}
