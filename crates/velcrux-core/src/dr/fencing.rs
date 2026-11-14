//! Split-Brain Prevention & Cryptographic Fencing Engine (ADR-080).
//!
//! Enforces monotonic generation epochs, witness quorum lease approval,
//! and strict storage write fencing barriers to guarantee that an isolated
//! or partitioned former primary cannot corrupt shared data or commit split-brain writes.

use std::collections::HashMap;

use super::types::{DrError, DrResult, FencingToken};

/// Storage and gateway I/O fencing barrier engine.
#[derive(Debug, Clone)]
pub struct StorageFencingEngine {
    current_epoch: u64,
    active_token: Option<FencingToken>,
    fenced_clusters: HashMap<String, u64>,
    witness_secrets: HashMap<String, Vec<u8>>,
}

impl StorageFencingEngine {
    /// Create a new storage fencing engine initialized with a starting epoch.
    #[must_use]
    pub fn new(initial_epoch: u64) -> Self {
        Self {
            current_epoch: initial_epoch,
            active_token: None,
            fenced_clusters: HashMap::new(),
            witness_secrets: HashMap::new(),
        }
    }

    /// Register a quorum witness node and its pre-shared authentication secret.
    pub fn register_witness(&mut self, witness_id: impl Into<String>, secret: &[u8]) {
        self.witness_secrets
            .insert(witness_id.into(), secret.to_vec());
    }

    /// Number of configured quorum witness nodes.
    #[must_use]
    pub fn witness_count(&self) -> usize {
        self.witness_secrets.len()
    }

    /// Required quorum approvals ($\lfloor N/2 \rfloor + 1$).
    #[must_use]
    pub fn quorum_requirement(&self) -> usize {
        if self.witness_secrets.is_empty() {
            1
        } else {
            (self.witness_secrets.len() / 2) + 1
        }
    }

    /// Current monotonic generation epoch barrier.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Active fencing lease token, if currently issued.
    #[must_use]
    pub fn active_token(&self) -> Option<&FencingToken> {
        self.active_token.as_ref()
    }

    /// Check if a specific cluster region has been explicitly fenced.
    #[must_use]
    pub fn is_cluster_fenced(&self, cluster_id: &str) -> bool {
        self.fenced_clusters.contains_key(cluster_id)
    }

    /// Validate whether a storage write or gateway I/O operation is permitted.
    ///
    /// Writes are rejected if:
    /// - The cluster is explicitly marked as fenced.
    /// - The provided fencing epoch is strictly less than the current epoch barrier.
    /// - The active lease has expired.
    /// - The cluster attempting the write is not the authorized lease holder.
    pub fn validate_write(&self, token_epoch: u64, cluster_id: &str, now_ms: u64) -> DrResult<()> {
        if self.is_cluster_fenced(cluster_id) {
            return Err(DrError::UnauthorizedCluster {
                cluster: cluster_id.to_string(),
                holder: self
                    .active_token
                    .as_ref()
                    .map(|t| t.holder_cluster.clone())
                    .unwrap_or_else(|| "<none>".to_string()),
            });
        }

        if token_epoch < self.current_epoch {
            return Err(DrError::FencedObsoleteEpoch {
                attempted: token_epoch,
                current: self.current_epoch,
            });
        }

        if let Some(token) = &self.active_token {
            if token.holder_cluster != cluster_id {
                return Err(DrError::UnauthorizedCluster {
                    cluster: cluster_id.to_string(),
                    holder: token.holder_cluster.clone(),
                });
            }

            if token.is_expired(now_ms) {
                return Err(DrError::FencedExpiredLease {
                    expired_at: token.expires_at_ms(),
                    now: now_ms,
                });
            }
        }

        Ok(())
    }

    /// Issue a new fencing token to `candidate_holder` approved by a quorum of witnesses.
    pub fn issue_fencing_token(
        &mut self,
        candidate_holder: &str,
        lease_duration_ms: u64,
        now_ms: u64,
        approving_witnesses: &[String],
    ) -> DrResult<FencingToken> {
        let required = self.quorum_requirement();
        let mut valid_signatures = Vec::new();

        let new_epoch = self.current_epoch.saturating_add(1);

        for witness_id in approving_witnesses {
            if let Some(secret) = self.witness_secrets.get(witness_id) {
                let sig =
                    FencingToken::compute_signature(secret, new_epoch, candidate_holder, now_ms);
                valid_signatures.push(sig);
            }
        }

        if valid_signatures.len() < required {
            return Err(DrError::QuorumNotReached {
                required,
                acquired: valid_signatures.len(),
            });
        }

        let mut token =
            FencingToken::new_candidate(new_epoch, candidate_holder, now_ms, lease_duration_ms);
        token.quorum_signatures = valid_signatures;

        // Unfence candidate if previously fenced
        self.fenced_clusters.remove(candidate_holder);

        self.current_epoch = new_epoch;
        self.active_token = Some(token.clone());

        Ok(token)
    }

    /// Forcibly fence a cluster region and invalidate its write permissions.
    ///
    /// Monotonically elevates the generation epoch barrier and revokes active leases.
    pub fn fence_cluster(
        &mut self,
        cluster_id: &str,
        target_epoch: Option<u64>,
        now_ms: u64,
    ) -> DrResult<FencingToken> {
        let next_epoch = match target_epoch {
            Some(epoch) if epoch > self.current_epoch => epoch,
            _ => self.current_epoch.saturating_add(1),
        };

        self.current_epoch = next_epoch;
        self.fenced_clusters.insert(cluster_id.to_string(), now_ms);

        // If the fenced cluster was the active token holder, revoke it
        if let Some(token) = &self.active_token {
            if token.holder_cluster == cluster_id {
                self.active_token = None;
            }
        }

        // Return revocation fencing token marker
        let token = FencingToken::new_candidate(
            self.current_epoch,
            format!("fenced:{cluster_id}"),
            now_ms,
            0,
        );
        Ok(token)
    }

    /// Remove explicit fencing status on a recovered cluster (e.g. after demotion or divergence reconciliation).
    pub fn unfence_cluster(&mut self, cluster_id: &str) {
        self.fenced_clusters.remove(cluster_id);
    }
}
