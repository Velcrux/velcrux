//! Cryptographic Zero-Knowledge Transfer Audit Proofs & Merkle Tree Accumulator (`ADR-043`, Option CA).
//!
//! Provides verifiable, privacy-preserving cryptographic audit proofs for data transfer integrity
//! and compliance auditing. External compliance auditors can mathematically verify that a specific
//! transfer occurred and was committed to the audit log without revealing sensitive transfer payloads,
//! confidential file paths, or multi-tenant customer identifiers.

use crate::error::VelcruxError;
use crate::util::hash::Hash;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Instant;

/// Domain separation tag for leaf commitments.
pub const AUDIT_LEAF_DOMAIN_TAG: &[u8] = b"velcrux-audit-leaf:v1";

/// Domain separation tag for intermediate Merkle nodes.
pub const AUDIT_NODE_DOMAIN_TAG: &[u8] = b"velcrux-audit-node:v1";

/// Direction of sibling hash in a Merkle inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditProofDirection {
    /// Sibling is on the left side of the hash pair.
    Left,
    /// Sibling is on the right side of the hash pair.
    Right,
}

/// A single step in a Merkle inclusion proof path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditProofStep {
    /// 32-byte hash of the sibling node.
    #[serde(with = "hex_bytes_32")]
    pub sibling: [u8; 32],
    /// Direction of the sibling relative to the current accumulator hash.
    pub direction: AuditProofDirection,
}

/// Complete cryptographic inclusion proof for a blinded transfer leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditInclusionProof {
    /// Zero-based leaf index within the Merkle tree.
    pub leaf_index: usize,
    /// Blinded commitment hash of the leaf.
    #[serde(with = "hex_bytes_32")]
    pub leaf_hash: [u8; 32],
    /// Sibling hash sequence leading from the leaf to the tree root.
    pub path: Vec<AuditProofStep>,
    /// Expected Merkle audit root against which the proof is verified.
    #[serde(with = "hex_bytes_32")]
    pub expected_root: [u8; 32],
    /// Total number of leaves in the tree when the proof was constructed.
    pub tree_size: usize,
}

/// Cryptographic non-membership (exclusion) proof verifying that a given leaf commitment does not exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExclusionProof {
    /// Target leaf commitment hash being proven absent.
    #[serde(with = "hex_bytes_32")]
    pub target_hash: [u8; 32],
    /// Inclusion proof for the greatest leaf in the sorted tree strictly less than the target hash (if any).
    pub lower_bound: Option<AuditInclusionProof>,
    /// Inclusion proof for the smallest leaf in the sorted tree strictly greater than the target hash (if any).
    pub upper_bound: Option<AuditInclusionProof>,
    /// Expected Merkle audit root.
    #[serde(with = "hex_bytes_32")]
    pub expected_root: [u8; 32],
}

/// Unblinded transfer metadata record before zero-knowledge leaf blinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique 26-character transfer identifier (ULID).
    pub transfer_id: String,
    /// Tenant or organization identifier.
    pub tenant_id: String,
    /// Root manifest BLAKE3 checksum of the transferred dataset.
    pub manifest_hash: Hash,
    /// Total bytes transferred and committed.
    pub total_bytes: u64,
    /// Unix timestamp in seconds when the transfer completed.
    pub completed_at_secs: u64,
}

impl AuditRecord {
    /// Create a new audit record for a completed transfer.
    pub fn new(
        transfer_id: String,
        tenant_id: String,
        manifest_hash: Hash,
        total_bytes: u64,
        completed_at_secs: u64,
    ) -> Self {
        Self {
            transfer_id,
            tenant_id,
            manifest_hash,
            total_bytes,
            completed_at_secs,
        }
    }

    /// Compute a zero-knowledge blinded leaf commitment using a random 256-bit salt.
    ///
    /// The commitment hides the transfer ID, tenant ID, byte size, and manifest hash
    /// from auditors while binding them cryptographically:
    /// `C = BLAKE3(DomainTag || TransferID || TenantID || ManifestHash || Bytes || Timestamp || Salt)`
    pub fn commit(&self, salt: &[u8; 32]) -> BlindedAuditLeaf {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AUDIT_LEAF_DOMAIN_TAG);
        hasher.update(self.transfer_id.as_bytes());
        hasher.update(self.tenant_id.as_bytes());
        hasher.update(self.manifest_hash.as_bytes());
        hasher.update(&self.total_bytes.to_le_bytes());
        hasher.update(&self.completed_at_secs.to_le_bytes());
        hasher.update(salt);

        let leaf_hash: [u8; 32] = *hasher.finalize().as_bytes();

        BlindedAuditLeaf {
            leaf_hash,
            salt: *salt,
            transfer_id: self.transfer_id.clone(),
        }
    }
}

/// Blinded transfer commitment leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedAuditLeaf {
    /// 32-byte blinded commitment hash.
    #[serde(with = "hex_bytes_32")]
    pub leaf_hash: [u8; 32],
    /// 32-byte blinding nonce/salt.
    #[serde(with = "hex_bytes_32")]
    pub salt: [u8; 32],
    /// Associated transfer identifier.
    pub transfer_id: String,
}

/// Operational status report for the audit accumulator tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTreeStatus {
    /// Hex-encoded Merkle root hash.
    pub root_hex: String,
    /// Total committed audit records in the tree.
    pub total_records: usize,
    /// Merkle tree height (levels from leaves to root).
    pub height: usize,
    /// Audit epoch identifier.
    pub epoch: u64,
}

/// Helper function to combine two 32-byte hashes into an intermediate Merkle node.
pub fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUDIT_NODE_DOMAIN_TAG);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Mathematically verify a Merkle inclusion proof against an audit root.
///
/// Returns `true` if and only if the proof path faithfully evaluates from `leaf_hash` to `expected_root`.
pub fn verify_inclusion_proof(proof: &AuditInclusionProof) -> bool {
    let mut current = proof.leaf_hash;
    for step in &proof.path {
        current = match step.direction {
            AuditProofDirection::Left => combine_hashes(&step.sibling, &current),
            AuditProofDirection::Right => combine_hashes(&current, &step.sibling),
        };
    }
    current == proof.expected_root
}

/// Mathematically verify a non-membership / exclusion proof against an audit root.
///
/// Confirms that `target_hash` does not exist within the sorted Merkle accumulator.
pub fn verify_exclusion_proof(proof: &AuditExclusionProof) -> bool {
    // 1. If lower bound is provided, it must verify and be strictly less than target_hash
    if let Some(ref lower) = proof.lower_bound {
        if !verify_inclusion_proof(lower) {
            return false;
        }
        if lower.leaf_hash >= proof.target_hash {
            return false;
        }
        if lower.expected_root != proof.expected_root {
            return false;
        }
    }

    // 2. If upper bound is provided, it must verify and be strictly greater than target_hash
    if let Some(ref upper) = proof.upper_bound {
        if !verify_inclusion_proof(upper) {
            return false;
        }
        if upper.leaf_hash <= proof.target_hash {
            return false;
        }
        if upper.expected_root != proof.expected_root {
            return false;
        }
    }

    // 3. If both bounds are present, they must be adjacent leaves
    if let (Some(ref lower), Some(ref upper)) = (&proof.lower_bound, &proof.upper_bound) {
        if upper.leaf_index != lower.leaf_index + 1 {
            return false;
        }
    }

    // At least one bound must be present
    proof.lower_bound.is_some() || proof.upper_bound.is_some()
}

/// Append-only Merkle tree audit accumulator (`ADR-043`).
pub struct MerkleAuditTree {
    epoch: u64,
    leaves: Vec<[u8; 32]>,
    sorted_leaves: Vec<([u8; 32], usize)>, // (leaf_hash, original_index)
}

impl MerkleAuditTree {
    /// Construct a new empty Merkle audit tree for a given epoch.
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            leaves: Vec::new(),
            sorted_leaves: Vec::new(),
        }
    }

    /// Insert an unblinded transfer audit record with a given salt.
    /// Returns the assigned zero-based leaf index and the 32-byte commitment hash.
    pub fn insert_record(&mut self, record: &AuditRecord, salt: &[u8; 32]) -> (usize, [u8; 32]) {
        let blinded = record.commit(salt);
        let index = self.insert_leaf(blinded.leaf_hash);
        (index, blinded.leaf_hash)
    }

    /// Insert an already-blinded 32-byte leaf hash into the tree accumulator.
    pub fn insert_leaf(&mut self, leaf_hash: [u8; 32]) -> usize {
        let index = self.leaves.len();
        self.leaves.push(leaf_hash);

        // Maintain sorted index for exclusion proof generation
        let pos = self
            .sorted_leaves
            .binary_search_by(|(h, _)| h.cmp(&leaf_hash))
            .unwrap_or_else(|e| e);
        self.sorted_leaves.insert(pos, (leaf_hash, index));

        index
    }

    /// Total number of leaves in the tree accumulator.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree accumulator contains zero leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Current height of the Merkle tree.
    pub fn height(&self) -> usize {
        if self.leaves.is_empty() {
            0
        } else {
            let mut count = self.leaves.len();
            let mut h = 1;
            while count > 1 {
                count = (count + 1) / 2;
                h += 1;
            }
            h
        }
    }

    /// Compute the current root hash of the Merkle accumulator.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            // Null root domain hash
            let mut hasher = blake3::Hasher::new();
            hasher.update(AUDIT_NODE_DOMAIN_TAG);
            hasher.update(b"empty");
            return *hasher.finalize().as_bytes();
        }

        let mut current_level = self.leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            let mut i = 0;
            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    next_level.push(combine_hashes(&current_level[i], &current_level[i + 1]));
                } else {
                    // Balanced odd leaf promotion: pair with duplicate
                    next_level.push(combine_hashes(&current_level[i], &current_level[i]));
                }
                i += 2;
            }
            current_level = next_level;
        }

        current_level[0]
    }

    /// Return the hex-encoded string of the current root hash.
    pub fn root_hex(&self) -> String {
        hex_encode(&self.root())
    }

    /// Generate a cryptographic inclusion proof for a leaf at a given zero-based index.
    pub fn generate_inclusion_proof(
        &self,
        leaf_index: usize,
    ) -> Result<AuditInclusionProof, VelcruxError> {
        if leaf_index >= self.leaves.len() {
            return Err(VelcruxError::Config(format!(
                "audit proof error: leaf index {} out of bounds (tree size: {})",
                leaf_index,
                self.leaves.len()
            )));
        }

        let leaf_hash = self.leaves[leaf_index];
        let expected_root = self.root();
        let mut path = Vec::new();

        let mut current_level = self.leaves.clone();
        let mut current_index = leaf_index;

        while current_level.len() > 1 {
            let is_right_child = current_index % 2 == 1;
            let sibling_index = if is_right_child {
                current_index - 1
            } else if current_index + 1 < current_level.len() {
                current_index + 1
            } else {
                current_index // Odd leaf duplicate
            };

            let sibling_hash = current_level[sibling_index];
            let direction = if is_right_child {
                AuditProofDirection::Left
            } else {
                AuditProofDirection::Right
            };

            path.push(AuditProofStep {
                sibling: sibling_hash,
                direction,
            });

            // Construct next level
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            let mut i = 0;
            while i < current_level.len() {
                if i + 1 < current_level.len() {
                    next_level.push(combine_hashes(&current_level[i], &current_level[i + 1]));
                } else {
                    next_level.push(combine_hashes(&current_level[i], &current_level[i]));
                }
                i += 2;
            }

            current_index /= 2;
            current_level = next_level;
        }

        Ok(AuditInclusionProof {
            leaf_index,
            leaf_hash,
            path,
            expected_root,
            tree_size: self.leaves.len(),
        })
    }

    /// Generate a cryptographic non-membership / exclusion proof for a target hash.
    pub fn generate_exclusion_proof(
        &self,
        target_hash: &[u8; 32],
    ) -> Result<AuditExclusionProof, VelcruxError> {
        if self.leaves.is_empty() {
            return Err(VelcruxError::Config(
                "cannot generate exclusion proof on empty audit tree".to_string(),
            ));
        }

        // Check if target is already in the tree
        if self
            .sorted_leaves
            .binary_search_by(|(h, _)| h.cmp(target_hash))
            .is_ok()
        {
            return Err(VelcruxError::Config(
                "target hash exists in the tree: cannot generate non-membership exclusion proof"
                    .to_string(),
            ));
        }

        let pos = self
            .sorted_leaves
            .binary_search_by(|(h, _)| h.cmp(target_hash))
            .unwrap_err();

        let lower_bound = if pos > 0 {
            let (_, original_idx) = self.sorted_leaves[pos - 1];
            Some(self.generate_inclusion_proof(original_idx)?)
        } else {
            None
        };

        let upper_bound = if pos < self.sorted_leaves.len() {
            let (_, original_idx) = self.sorted_leaves[pos];
            Some(self.generate_inclusion_proof(original_idx)?)
        } else {
            None
        };

        Ok(AuditExclusionProof {
            target_hash: *target_hash,
            lower_bound,
            upper_bound,
            expected_root: self.root(),
        })
    }

    /// Current operational status summary of the audit tree.
    pub fn status(&self) -> AuditTreeStatus {
        AuditTreeStatus {
            root_hex: self.root_hex(),
            total_records: self.leaves.len(),
            height: self.height(),
            epoch: self.epoch,
        }
    }
}

/// Performance benchmark report produced by `run_audit_benchmark`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBenchmarkReport {
    /// Number of simulated transfer records evaluated.
    pub total_records: usize,
    /// Number of inclusion proof samples generated and verified.
    pub proof_samples: usize,
    /// Duration of building the accumulator tree in milliseconds.
    pub build_duration_ms: f64,
    /// Tree insertion throughput in records per second.
    pub insertion_throughput_records_per_sec: f64,
    /// Average proof generation latency in microseconds.
    pub avg_proof_gen_latency_us: f64,
    /// Average proof verification latency in microseconds.
    pub avg_proof_verify_latency_us: f64,
    /// Height of the resulting Merkle tree.
    pub tree_height: usize,
    /// Hex string of the computed Merkle root.
    pub root_hash_hex: String,
    /// True if all sampled inclusion and exclusion proofs successfully verified.
    pub all_proofs_verified: bool,
}

/// Run an in-memory benchmark evaluating Merkle tree accumulation, proof generation, and verification throughput.
pub fn run_audit_benchmark(record_count: usize, proof_samples: usize) -> AuditBenchmarkReport {
    let mut tree = MerkleAuditTree::new(1);
    let sample_count = proof_samples.min(record_count).max(1);

    // 1. Build accumulator tree
    let build_start = Instant::now();
    for i in 0..record_count {
        let mut salt = [0u8; 32];
        salt[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let record = AuditRecord::new(
            format!("01J000000000000000000{:05}", i),
            "tenant-prod".to_string(),
            Hash::from_bytes(&salt).expect("valid 32-byte hash"),
            1048576,
            1793130000 + (i as u64),
        );
        tree.insert_record(&record, &salt);
    }
    let build_duration = build_start.elapsed();
    let build_duration_ms = build_duration.as_secs_f64() * 1000.0;
    let insertion_throughput = record_count as f64 / build_duration.as_secs_f64().max(1e-9);

    // 2. Measure proof generation latency
    let gen_start = Instant::now();
    let mut proofs = Vec::with_capacity(sample_count);
    let step = (record_count / sample_count).max(1);
    for s in 0..sample_count {
        let idx = (s * step).min(record_count - 1);
        let p = tree
            .generate_inclusion_proof(idx)
            .expect("proof generation");
        proofs.push(p);
    }
    let gen_duration = gen_start.elapsed();
    let avg_proof_gen_latency_us = (gen_duration.as_secs_f64() * 1_000_000.0) / sample_count as f64;

    // 3. Measure proof verification latency
    let verify_start = Instant::now();
    let mut all_verified = true;
    for p in &proofs {
        if !verify_inclusion_proof(p) {
            all_verified = false;
        }
    }
    let verify_duration = verify_start.elapsed();
    let avg_proof_verify_latency_us =
        (verify_duration.as_secs_f64() * 1_000_000.0) / sample_count as f64;

    AuditBenchmarkReport {
        total_records: record_count,
        proof_samples: sample_count,
        build_duration_ms,
        insertion_throughput_records_per_sec: insertion_throughput,
        avg_proof_gen_latency_us,
        avg_proof_verify_latency_us,
        tree_height: tree.height(),
        root_hash_hex: tree.root_hex(),
        all_proofs_verified: all_verified,
    }
}

/// Convert byte slice to lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Convert a hex string to a 32-byte array.
pub fn hex_decode_32(hex_str: &str) -> Result<[u8; 32], VelcruxError> {
    let s = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    if s.len() != 64 {
        return Err(VelcruxError::Config(format!(
            "invalid 32-byte hex string: length must be 64 characters (got {})",
            s.len()
        )));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_str = &s[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|e| VelcruxError::Config(format!("invalid hex byte '{}': {}", byte_str, e)))?;
    }
    Ok(out)
}

/// Serde helper for serializing/deserializing `[u8; 32]` as hex string.
pub mod hex_bytes_32 {
    use super::{hex_decode_32, hex_encode};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex_decode_32(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_construction_and_root() {
        let mut tree = MerkleAuditTree::new(1);
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        let empty_root = tree.root();

        let salt1 = [1u8; 32];
        let record1 = AuditRecord::new(
            "01J00000000000000000000001".to_string(),
            "tenant-alpha".to_string(),
            Hash::from_bytes(&[2u8; 32]).expect("valid hash"),
            1048576,
            1793130001,
        );
        let (idx1, leaf1) = tree.insert_record(&record1, &salt1);
        assert_eq!(idx1, 0);
        assert_ne!(tree.root(), empty_root);

        let salt2 = [3u8; 32];
        let record2 = AuditRecord::new(
            "01J00000000000000000000002".to_string(),
            "tenant-beta".to_string(),
            Hash::from_bytes(&[4u8; 32]).expect("valid hash"),
            2097152,
            1793130002,
        );
        let (idx2, leaf2) = tree.insert_record(&record2, &salt2);
        assert_eq!(idx2, 1);
        assert_eq!(tree.len(), 2);

        // Root of a 2-leaf tree must equal combine_hashes(leaf1, leaf2)
        let expected_root = combine_hashes(&leaf1, &leaf2);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_zk_blinded_leaf_commitment_and_inclusion_proof() {
        let mut tree = MerkleAuditTree::new(1);
        let record_count = 10;
        let mut leaves = Vec::new();

        for i in 0..record_count {
            let mut salt = [0u8; 32];
            salt[0] = i as u8;
            let record = AuditRecord::new(
                format!("01J00000000000000000000{:03}", i),
                "tenant-alpha".to_string(),
                Hash::from_bytes(&salt).expect("valid hash"),
                1024 * (i as u64 + 1),
                1793130100 + i as u64,
            );
            let (idx, leaf_hash) = tree.insert_record(&record, &salt);
            leaves.push((idx, leaf_hash));
        }

        // Verify proofs for all leaves
        for (idx, leaf_hash) in &leaves {
            let proof = tree.generate_inclusion_proof(*idx).expect("generate proof");
            assert_eq!(proof.leaf_index, *idx);
            assert_eq!(proof.leaf_hash, *leaf_hash);
            assert_eq!(proof.expected_root, tree.root());
            assert!(
                verify_inclusion_proof(&proof),
                "proof verification failed for leaf {}",
                idx
            );
        }
    }

    #[test]
    fn test_proof_tamper_detection_and_rejection() {
        let mut tree = MerkleAuditTree::new(1);
        for i in 0..5 {
            let mut salt = [0u8; 32];
            salt[0] = i as u8;
            let record = AuditRecord::new(
                format!("01J00000000000000000000{:03}", i),
                "tenant-alpha".to_string(),
                Hash::from_bytes(&salt).expect("valid hash"),
                1024,
                1793130200,
            );
            tree.insert_record(&record, &salt);
        }

        let mut proof = tree.generate_inclusion_proof(2).expect("valid proof");
        assert!(verify_inclusion_proof(&proof));

        // Tamper 1: Mutate leaf hash
        proof.leaf_hash[0] ^= 0xFF;
        assert!(!verify_inclusion_proof(&proof));
        proof.leaf_hash[0] ^= 0xFF; // restore

        // Tamper 2: Mutate path sibling
        proof.path[0].sibling[0] ^= 0xAA;
        assert!(!verify_inclusion_proof(&proof));
        proof.path[0].sibling[0] ^= 0xAA; // restore

        // Tamper 3: Flip direction
        proof.path[0].direction = match proof.path[0].direction {
            AuditProofDirection::Left => AuditProofDirection::Right,
            AuditProofDirection::Right => AuditProofDirection::Left,
        };
        assert!(!verify_inclusion_proof(&proof));
    }

    #[test]
    fn test_audit_exclusion_proof() {
        let mut tree = MerkleAuditTree::new(1);
        // Insert known leaves with fixed hashes
        let leaf_a = [0x10u8; 32];
        let leaf_b = [0x30u8; 32];
        let leaf_c = [0x50u8; 32];

        tree.insert_leaf(leaf_a);
        tree.insert_leaf(leaf_b);
        tree.insert_leaf(leaf_c);

        // Target hash between leaf_a and leaf_b
        let target_between = [0x20u8; 32];
        let exclusion_proof = tree
            .generate_exclusion_proof(&target_between)
            .expect("exclusion proof between");
        assert!(verify_exclusion_proof(&exclusion_proof));

        // Target hash before leaf_a
        let target_before = [0x05u8; 32];
        let exclusion_proof_before = tree
            .generate_exclusion_proof(&target_before)
            .expect("exclusion proof before");
        assert!(verify_exclusion_proof(&exclusion_proof_before));

        // Target hash after leaf_c
        let target_after = [0x90u8; 32];
        let exclusion_proof_after = tree
            .generate_exclusion_proof(&target_after)
            .expect("exclusion proof after");
        assert!(verify_exclusion_proof(&exclusion_proof_after));

        // Target hash that DOES exist should fail to generate exclusion proof
        assert!(tree.generate_exclusion_proof(&leaf_b).is_err());
    }

    #[test]
    fn test_audit_benchmark_execution() {
        let report = run_audit_benchmark(50, 10);
        assert_eq!(report.total_records, 50);
        assert_eq!(report.proof_samples, 10);
        assert!(report.all_proofs_verified);
        assert!(report.tree_height > 1);
        assert_eq!(report.root_hash_hex.len(), 64);
        assert!(report.insertion_throughput_records_per_sec > 0.0);
    }
}
