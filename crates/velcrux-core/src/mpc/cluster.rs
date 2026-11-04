#![forbid(unsafe_code)]

//! Cluster-wide Zero-Knowledge Multi-Party Computation Orchestration.
//!
//! Provides cluster coordinators and nodes with threshold signing sessions for:
//! - Root authorization token minting
//! - Cryptographic storage manifest attestations
//! - Node membership transition certificates
//! - Full cryptographic audit logging with blame attribution

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::curve::Point;
use super::protocol::{
    aggregate_signature_shares, verify_signature_share, CommitmentPackage, ThresholdSignature,
    ThresholdSigner,
};
use super::scalar::Scalar;
use super::vss::{FeldmanCommitmentPackage, Polynomial};
use super::zkp::SchnorrDlogProof;
use crate::error::{ProtocolError, Result, VelcruxError};

/// Threshold cluster configuration and public verification keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcClusterConfig {
    pub threshold: u32,
    pub total_signers: u32,
    pub group_public_key: Point,
    pub participant_keys: HashMap<u32, Point>,
    pub feldman_package: FeldmanCommitmentPackage,
}

/// An audit entry recording a completed or faulted MPC threshold signing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcSessionAuditRecord {
    pub session_id: String,
    pub timestamp_ms: u64,
    pub operation: String,
    pub message_digest: String,
    pub quorum: Vec<u32>,
    pub signature_hex: Option<String>,
    pub latency_us: u64,
    pub success: bool,
    pub blame_node: Option<u32>,
    pub error_message: Option<String>,
}

/// Cryptographically attested root token minted via MPC quorum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcRootToken {
    pub token_id: String,
    pub subject: String,
    pub role: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub quorum: Vec<u32>,
    pub group_public_key: Point,
    pub signature: ThresholdSignature,
}

impl MpcRootToken {
    /// Formats payload bytes to be verified against the MPC signature.
    pub fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"velcrux-mpc-root-token:v1\n");
        bytes.extend_from_slice(self.token_id.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self.subject.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(self.role.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        bytes
    }

    /// Verifies token signature against the master group key and checks expiry.
    pub fn verify(&self, now_ms: u64) -> bool {
        if now_ms > self.expires_at_ms {
            return false;
        }
        let payload = self.payload_bytes();
        self.signature.verify(&self.group_public_key, &payload)
    }
}

/// Storage manifest attestation signed by threshold quorum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcManifestAttestation {
    pub manifest_digest: String,
    pub epoch: u64,
    pub attested_at_ms: u64,
    pub quorum: Vec<u32>,
    pub group_public_key: Point,
    pub signature: ThresholdSignature,
}

impl MpcManifestAttestation {
    pub fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"velcrux-mpc-manifest-attest:v1\n");
        bytes.extend_from_slice(self.manifest_digest.as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(&self.attested_at_ms.to_le_bytes());
        bytes
    }

    pub fn verify(&self) -> bool {
        let payload = self.payload_bytes();
        self.signature.verify(&self.group_public_key, &payload)
    }
}

/// Cluster coordinator managing MPC threshold operations.
pub struct MpcClusterCoordinator {
    pub config: MpcClusterConfig,
    signers: HashMap<u32, ThresholdSigner>,
    zkp_proofs: HashMap<u32, SchnorrDlogProof>,
    audit_history: Arc<RwLock<Vec<MpcSessionAuditRecord>>>,
    session_counter: AtomicU64,
}

impl MpcClusterCoordinator {
    /// Initializes a simulated local test cluster or standalone node with secret shares.
    pub fn initialize(threshold: u32, total_signers: u32) -> Result<Self> {
        if threshold == 0 || threshold > total_signers {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid threshold configuration: must have 1 <= t <= n",
            )));
        }

        let master_secret = Scalar::random_nonzero();
        let poly = Polynomial::random_with_secret(&master_secret, threshold);
        let feldman_package = poly.commitments();
        let group_public_key = feldman_package.group_public_key()?;
        let shares = poly.generate_shares(total_signers);

        let mut participant_keys = HashMap::new();
        let mut signers = HashMap::new();
        let mut zkp_proofs = HashMap::new();

        let context = b"velcrux-mpc-cluster-genesis";

        for share in shares {
            let id = share.participant_id;
            let signer = ThresholdSigner::new(share.clone(), group_public_key);
            participant_keys.insert(id, signer.public_key);

            let proof = SchnorrDlogProof::prove(id, &share.share, context);
            if !proof.verify(context) {
                return Err(VelcruxError::Protocol(ProtocolError::InvalidIdentity(
                    "failed to verify self-generated ZKP proof during DKG",
                )));
            }
            zkp_proofs.insert(id, proof);
            signers.insert(id, signer);
        }

        let config = MpcClusterConfig {
            threshold,
            total_signers,
            group_public_key,
            participant_keys,
            feldman_package,
        };

        Ok(Self {
            config,
            signers,
            zkp_proofs,
            audit_history: Arc::new(RwLock::new(Vec::new())),
            session_counter: AtomicU64::new(1),
        })
    }

    /// Returns master group public key.
    pub fn group_public_key(&self) -> Point {
        self.config.group_public_key
    }

    /// Returns participant verification public key.
    pub fn participant_key(&self, id: u32) -> Option<Point> {
        self.config.participant_keys.get(&id).copied()
    }

    /// Orchestrates a distributed signing round across the requested quorum.
    pub async fn sign_payload(
        &self,
        quorum: &[u32],
        message: &[u8],
        operation_name: &str,
    ) -> Result<ThresholdSignature> {
        let start = Instant::now();
        let session_id = format!(
            "mpc-sess-{:06}",
            self.session_counter.fetch_add(1, Ordering::SeqCst)
        );
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut hasher = blake3::Hasher::new();
        hasher.update(message);
        let msg_digest = hasher.finalize().to_hex().to_string();

        if (quorum.len() as u32) < self.config.threshold {
            let err = format!(
                "insufficient signers: required {}, got {}",
                self.config.threshold,
                quorum.len()
            );
            self.record_audit(MpcSessionAuditRecord {
                session_id: session_id.clone(),
                timestamp_ms: now_ms,
                operation: operation_name.to_string(),
                message_digest: msg_digest,
                quorum: quorum.to_vec(),
                signature_hex: None,
                latency_us: start.elapsed().as_micros() as u64,
                success: false,
                blame_node: None,
                error_message: Some(err.clone()),
            })
            .await;
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "insufficient quorum for threshold signing",
            )));
        }

        // Round 1: collect commitments
        let mut nonces_map = HashMap::new();
        let mut commitments = Vec::with_capacity(quorum.len());

        for &id in quorum {
            let signer = self.signers.get(&id).ok_or_else(|| {
                VelcruxError::Protocol(ProtocolError::Malformed("signer node not found in cluster"))
            })?;
            let (nonces, comm) = signer.round1_commit();
            nonces_map.insert(id, nonces);
            commitments.push(comm);
        }

        let pkg = CommitmentPackage { commitments };

        // Round 2: generate shares and verify individually
        let mut shares = Vec::with_capacity(quorum.len());
        for comm in &pkg.commitments {
            let id = comm.participant_id;
            let signer = self.signers.get(&id).unwrap();
            let nonces = nonces_map.get(&id).unwrap();

            let share = signer.round2_sign(nonces, &pkg, message)?;

            let pubkey = self.participant_key(id).ok_or_else(|| {
                VelcruxError::Protocol(ProtocolError::Malformed("missing participant pubkey"))
            })?;

            if let Err(e) = verify_signature_share(
                &share,
                comm,
                &pubkey,
                &self.config.group_public_key,
                &pkg,
                message,
            ) {
                let err_msg = format!("cryptographic share verification failed for node {}", id);
                self.record_audit(MpcSessionAuditRecord {
                    session_id,
                    timestamp_ms: now_ms,
                    operation: operation_name.to_string(),
                    message_digest: msg_digest,
                    quorum: quorum.to_vec(),
                    signature_hex: None,
                    latency_us: start.elapsed().as_micros() as u64,
                    success: false,
                    blame_node: Some(id),
                    error_message: Some(err_msg),
                })
                .await;
                return Err(e);
            }

            shares.push(share);
        }

        // Aggregation
        let sig =
            aggregate_signature_shares(&pkg, &shares, &self.config.group_public_key, message)?;
        let latency_us = start.elapsed().as_micros() as u64;

        self.record_audit(MpcSessionAuditRecord {
            session_id,
            timestamp_ms: now_ms,
            operation: operation_name.to_string(),
            message_digest: msg_digest,
            quorum: quorum.to_vec(),
            signature_hex: Some(sig.to_hex()),
            latency_us,
            success: true,
            blame_node: None,
            error_message: None,
        })
        .await;

        Ok(sig)
    }

    /// Mints a cluster root authorization token signed via threshold MPC.
    pub async fn issue_root_token(
        &self,
        subject: &str,
        role: &str,
        ttl_secs: u64,
        quorum: &[u32],
    ) -> Result<MpcRootToken> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let expires_at_ms = now_ms + ttl_secs * 1000;
        let token_id = format!(
            "tok-{:08x}",
            blake3::hash(format!("{}:{}:{}", subject, role, now_ms).as_bytes()).as_bytes()[..4]
                .iter()
                .fold(0u32, |acc, &b| (acc << 8) | (b as u32))
        );

        let mut dummy = MpcRootToken {
            token_id: token_id.clone(),
            subject: subject.to_string(),
            role: role.to_string(),
            issued_at_ms: now_ms,
            expires_at_ms,
            quorum: quorum.to_vec(),
            group_public_key: self.config.group_public_key,
            signature: ThresholdSignature {
                r: Point::IDENTITY,
                z: Scalar::ZERO,
            },
        };

        let payload = dummy.payload_bytes();
        let sig = self
            .sign_payload(quorum, &payload, "issue_root_token")
            .await?;
        dummy.signature = sig;

        Ok(dummy)
    }

    /// Signs an epoch storage manifest attestation via threshold MPC.
    pub async fn attest_storage_manifest(
        &self,
        manifest_digest: &[u8; 32],
        epoch: u64,
        quorum: &[u32],
    ) -> Result<MpcManifestAttestation> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let digest_hex = hex::encode(manifest_digest);

        let mut dummy = MpcManifestAttestation {
            manifest_digest: digest_hex,
            epoch,
            attested_at_ms: now_ms,
            quorum: quorum.to_vec(),
            group_public_key: self.config.group_public_key,
            signature: ThresholdSignature {
                r: Point::IDENTITY,
                z: Scalar::ZERO,
            },
        };

        let payload = dummy.payload_bytes();
        let sig = self
            .sign_payload(quorum, &payload, "attest_storage_manifest")
            .await?;
        dummy.signature = sig;

        Ok(dummy)
    }

    /// Verifies any arbitrary threshold signature against the cluster master key.
    pub fn verify_signature(&self, message: &[u8], signature: &ThresholdSignature) -> bool {
        signature.verify(&self.config.group_public_key, message)
    }

    /// Appends an audit record.
    async fn record_audit(&self, record: MpcSessionAuditRecord) {
        let mut history = self.audit_history.write().await;
        history.push(record);
    }

    /// Retrieves audit log records.
    pub async fn get_audit_records(&self) -> Vec<MpcSessionAuditRecord> {
        self.audit_history.read().await.clone()
    }

    /// Retrieves registered ZKP discrete log knowledge proofs.
    pub fn get_zkp_proofs(&self) -> &HashMap<u32, SchnorrDlogProof> {
        &self.zkp_proofs
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mpc_cluster_root_token_and_manifest_attestation() {
        let coord = MpcClusterCoordinator::initialize(3, 5).expect("init cluster");

        // Quorum of 3 nodes: {1, 3, 5}
        let quorum = vec![1, 3, 5];

        // 1. Issue root token
        let token = coord
            .issue_root_token("admin-user-01", "cluster:root", 3600, &quorum)
            .await
            .expect("issue token");

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(token.verify(now_ms));
        assert!(!token.verify(now_ms + 4000 * 1000)); // expired

        // 2. Attest manifest
        let manifest_hash = [0x5au8; 32];
        let attest = coord
            .attest_storage_manifest(&manifest_hash, 101, &quorum)
            .await
            .expect("attest");
        assert!(attest.verify());

        // 3. Inspect audit logs
        let audits = coord.get_audit_records().await;
        assert_eq!(audits.len(), 2);
        assert!(audits.iter().all(|a| a.success));
    }
}
