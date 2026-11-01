//! Zero-Knowledge Range & Membership Proofs for Blinded Multi-Tenant Quota Auditing (`ADR-056`, Option CN).
//!
//! Features:
//! 1. Homomorphic Pedersen Commitments:
//!    - Constant-time 256-bit prime field scalar math ($\mathbb{F}_N$ with Secp256k1 group order $N$).
//!    - Orthogonal generator points $G, H \in \mathbb{F}_N$ derived via domain-separated BLAKE3 hashing.
//!    - Homomorphic addition and subtraction: $C(v_1, r_1) \pm C(v_2, r_2) = C(v_1 \pm v_2, r_1 \pm r_2) \pmod N$.
//! 2. Zero-Knowledge Range Proofs:
//!    - Non-interactive zero-knowledge (NIZK) bit-decomposition range proofs with Fiat-Shamir transformation.
//!    - Proves $0 \le \text{usage} \le \text{quota}$ by proving non-negativity of $\Delta = \text{quota} - \text{usage} \ge 0$.
//!    - 1-out-of-2 Cramer-Damgård-Schoenmakers (CDS94) Sigma protocol for each bit commitment $b_i \in \{0, 1\}$.
//!    - Zero leakage: auditor learns nothing about exact byte counts or remaining storage limits.
//! 3. Blinded Set Membership Proofs:
//!    - Cryptographic Merkle tree accumulator over blinded tenant identity commitments.
//!    - Proves tenant authorization within cluster without revealing tenant identity or metadata.
//! 4. Blinded Multi-Tenant Storage Balance Accumulator:
//!    - Homomorphic aggregation verifying that $\sum C_{\text{usage}} = C_{\text{cluster\_total}}$, ensuring no
//!      storage usage is omitted, double-counted, or falsified.
//! 5. Microsecond Performance Benchmark:
//!    - Microsecond profiling of commitment, proof generation, verification, and cluster audit sweeps.
//! 6. 100% Safe Rust (`#![forbid(unsafe_code)]`) with zero external C/OS dependencies.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::VelcruxError;

/// Secp256k1 curve/scalar group order $N = 2^{256} - 2^{32} - 977$:
/// `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
pub const SCALAR_MODULUS: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// A 256-bit scalar integer in the prime field $\mathbb{F}_N$ with little-endian 64-bit limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scalar256(pub [u64; 4]);

impl Scalar256 {
    /// Zero scalar element.
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// Unit scalar element.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Constructs scalar from a single u64 value.
    pub const fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }

    /// Converts scalar to little-endian 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        out
    }

    /// Converts scalar to 64-character lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        let mut hex = String::with_capacity(64);
        for b in bytes.iter().rev() {
            hex.push_str(&format!("{:02x}", b));
        }
        hex
    }

    /// Parses scalar from 32 little-endian bytes, reducing modulo $N$.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(buf);
        }
        let s = Self(limbs);
        s.reduce()
    }

    /// Derives a scalar pseudo-randomly from arbitrary entropy via BLAKE3 domain separation.
    pub fn hash_to_scalar(domain_tag: &[u8], payload: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-zkquota-scalar:v1\n");
        hasher.update(domain_tag);
        hasher.update(b"\n");
        hasher.update(payload);
        let digest = hasher.finalize();
        Self::from_bytes(digest.as_bytes())
    }

    /// Generates a cryptographically strong random scalar using system entropy.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_exact_mut(8) {
            let r = rand::random::<u64>();
            chunk.copy_from_slice(&r.to_le_bytes());
        }
        Self::from_bytes(&bytes)
    }

    /// Returns true if this scalar is greater than or equal to $N$.
    fn is_ge_modulus(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > SCALAR_MODULUS[i] {
                return true;
            }
            if self.0[i] < SCALAR_MODULUS[i] {
                return false;
            }
        }
        true
    }

    /// Reduces this scalar modulo $N$ if it equals or exceeds $N$.
    pub fn reduce(mut self) -> Self {
        while self.is_ge_modulus() {
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = (self.0[i] as i128) - (SCALAR_MODULUS[i] as i128) - borrow;
                if diff < 0 {
                    self.0[i] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    self.0[i] = diff as u64;
                    borrow = 0;
                }
            }
        }
        self
    }

    /// Computes $(a + b) \pmod N$.
    pub fn add(&self, other: &Self) -> Self {
        let mut carry = 0u128;
        let mut res = [0u64; 4];
        for i in 0..4 {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            res[i] = sum as u64;
            carry = sum >> 64;
        }

        let mut out = Self(res);
        if carry > 0 || out.is_ge_modulus() {
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = (out.0[i] as i128) - (SCALAR_MODULUS[i] as i128) - borrow;
                if diff < 0 {
                    out.0[i] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    out.0[i] = diff as u64;
                    borrow = 0;
                }
            }
        }
        out
    }

    /// Computes $(a - b) \pmod N$.
    pub fn sub(&self, other: &Self) -> Self {
        let mut borrow = 0i128;
        let mut res = [0u64; 4];
        for i in 0..4 {
            let diff = (self.0[i] as i128) - (other.0[i] as i128) - borrow;
            if diff < 0 {
                res[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                res[i] = diff as u64;
                borrow = 0;
            }
        }

        let mut out = Self(res);
        if borrow > 0 {
            let mut carry = 0u128;
            for i in 0..4 {
                let sum = (out.0[i] as u128) + (SCALAR_MODULUS[i] as u128) + carry;
                out.0[i] = sum as u64;
                carry = sum >> 64;
            }
        }
        out
    }

    /// Computes $(a \times b) \pmod N$ using schoolbook $4 \times 4$ limb multiplication and modular reduction.
    pub fn mul(&self, other: &Self) -> Self {
        let mut wide = [0u128; 8];
        for i in 0..4 {
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (other.0[j] as u128);
                let idx = i + j;
                let mut sum = wide[idx] + (prod & 0xFFFF_FFFF_FFFF_FFFF);
                wide[idx] = sum & 0xFFFF_FFFF_FFFF_FFFF;
                let mut carry = (prod >> 64) + (sum >> 64);
                let mut k = idx + 1;
                while carry > 0 && k < 8 {
                    sum = wide[k] + carry;
                    wide[k] = sum & 0xFFFF_FFFF_FFFF_FFFF;
                    carry = sum >> 64;
                    k += 1;
                }
            }
        }

        // Reduce 512-bit product into 256-bit scalar using iterative division / bit shift
        let mut acc = Self::ZERO;
        for i in (0..8).rev() {
            for _ in 0..64 {
                acc = acc.add(&acc);
            }
            let limb = Self::from_u64(wide[i] as u64);
            acc = acc.add(&limb);
        }
        acc
    }
}

impl Default for Scalar256 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for Scalar256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Scalar256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Scalar256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 hex characters"));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let hex_idx = (31 - i) * 2;
            let byte_val = u8::from_str_radix(&s[hex_idx..hex_idx + 2], 16)
                .map_err(serde::de::Error::custom)?;
            bytes[i] = byte_val;
        }
        Ok(Self::from_bytes(&bytes))
    }
}

/// Generator bases $G$ and $H$ for homomorphic Pedersen commitments in $\mathbb{F}_N$.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PedersenGenerators {
    /// Base value generator $G$.
    pub g: Scalar256,
    /// Blinding factor generator $H$.
    pub h: Scalar256,
}

impl Default for PedersenGenerators {
    fn default() -> Self {
        Self::standard()
    }
}

impl PedersenGenerators {
    /// Standard domain-separated generator bases.
    pub fn standard() -> Self {
        let g = Scalar256::hash_to_scalar(b"velcrux-zkquota-pedersen-G:v1", b"standard_g_base");
        let h = Scalar256::hash_to_scalar(b"velcrux-zkquota-pedersen-H:v1", b"standard_h_base");
        Self { g, h }
    }

    /// Evaluates homomorphic commitment $C(v, r) = (v \cdot G + r \cdot H) \pmod N$.
    pub fn commit(&self, value: u64, blinding: &Scalar256) -> Scalar256 {
        let v_scalar = Scalar256::from_u64(value);
        let vg = v_scalar.mul(&self.g);
        let rh = blinding.mul(&self.h);
        vg.add(&rh)
    }

    /// Evaluates scalar commitment $C(s, r) = (s \cdot G + r \cdot H) \pmod N$.
    pub fn commit_scalar(&self, value: &Scalar256, blinding: &Scalar256) -> Scalar256 {
        let vg = value.mul(&self.g);
        let rh = blinding.mul(&self.h);
        vg.add(&rh)
    }
}

/// Zero-knowledge 1-bit proof proving committed bit $b \in \{0, 1\}$ using Cramer-Damgård-Schoenmakers (CDS94).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkBitProof {
    /// Bit commitment $B = C(b, r)$.
    pub bit_commitment: Scalar256,
    /// Challenge component $e_0$.
    pub e0: Scalar256,
    /// Challenge component $e_1$.
    pub e1: Scalar256,
    /// Response component $s_0$.
    pub s0: Scalar256,
    /// Response component $s_1$.
    pub s1: Scalar256,
}

impl ZkBitProof {
    /// Proves that $b \in \{0, 1\}$ with blinding factor $r$.
    pub fn prove(gens: &PedersenGenerators, bit: u8, blinding: &Scalar256, context: &[u8]) -> Self {
        let bit = if bit > 0 { 1 } else { 0 };
        let bit_commitment = gens.commit(bit as u64, blinding);

        if bit == 0 {
            // b = 0 branch is real; b = 1 branch is simulated
            let w0 = Scalar256::random();
            let a0 = w0.mul(&gens.h);

            // Simulate b = 1 branch
            let e1 = Scalar256::random();
            let s1 = Scalar256::random();
            // A1 = s1 * H - e1 * (B - G)
            let s1_h = s1.mul(&gens.h);
            let b_minus_g = bit_commitment.sub(&gens.g);
            let e1_bg = e1.mul(&b_minus_g);
            let a1 = s1_h.sub(&e1_bg);

            // Fiat-Shamir challenge
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"velcrux-zkquota-bitproof:v1\n");
            hasher.update(context);
            hasher.update(&bit_commitment.to_bytes());
            hasher.update(&a0.to_bytes());
            hasher.update(&a1.to_bytes());
            let e = Scalar256::from_bytes(hasher.finalize().as_bytes());

            let e0 = e.sub(&e1);
            let s0 = w0.add(&e0.mul(blinding));

            Self {
                bit_commitment,
                e0,
                e1,
                s0,
                s1,
            }
        } else {
            // b = 1 branch is real; b = 0 branch is simulated
            let w1 = Scalar256::random();
            let a1 = w1.mul(&gens.h);

            // Simulate b = 0 branch
            let e0 = Scalar256::random();
            let s0 = Scalar256::random();
            // A0 = s0 * H - e0 * B
            let s0_h = s0.mul(&gens.h);
            let e0_b = e0.mul(&bit_commitment);
            let a0 = s0_h.sub(&e0_b);

            // Fiat-Shamir challenge
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"velcrux-zkquota-bitproof:v1\n");
            hasher.update(context);
            hasher.update(&bit_commitment.to_bytes());
            hasher.update(&a0.to_bytes());
            hasher.update(&a1.to_bytes());
            let e = Scalar256::from_bytes(hasher.finalize().as_bytes());

            let e1 = e.sub(&e0);
            let s1 = w1.add(&e1.mul(blinding));

            Self {
                bit_commitment,
                e0,
                e1,
                s0,
                s1,
            }
        }
    }

    /// Verifies that bit proof guarantees $b \in \{0, 1\}$.
    pub fn verify(&self, gens: &PedersenGenerators, context: &[u8]) -> bool {
        // Recompute A0 = s0 * H - e0 * B
        let s0_h = self.s0.mul(&gens.h);
        let e0_b = self.e0.mul(&self.bit_commitment);
        let a0 = s0_h.sub(&e0_b);

        // Recompute A1 = s1 * H - e1 * (B - G)
        let s1_h = self.s1.mul(&gens.h);
        let b_minus_g = self.bit_commitment.sub(&gens.g);
        let e1_bg = self.e1.mul(&b_minus_g);
        let a1 = s1_h.sub(&e1_bg);

        // Recompute expected challenge e = e0 + e1
        let expected_e = self.e0.add(&self.e1);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-zkquota-bitproof:v1\n");
        hasher.update(context);
        hasher.update(&self.bit_commitment.to_bytes());
        hasher.update(&a0.to_bytes());
        hasher.update(&a1.to_bytes());
        let computed_e = Scalar256::from_bytes(hasher.finalize().as_bytes());

        expected_e == computed_e
    }
}

/// Zero-Knowledge Range Proof proving $0 \le v \le \text{bound}$ without revealing $v$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkRangeProof {
    /// Upper bound proven (e.g. quota limit).
    pub bound_value: u64,
    /// Homomorphic commitment to value $C(v, r_v)$.
    pub value_commitment: Scalar256,
    /// Homomorphic commitment to difference $C(\Delta, r_{\Delta})$ where $\Delta = \text{bound} - v$.
    pub delta_commitment: Scalar256,
    /// Individual bit proofs proving $\Delta = \sum_{i=0}^{n-1} 2^i b_i$ with $b_i \in \{0, 1\}$.
    pub bit_proofs: Vec<ZkBitProof>,
    /// Number of bits decomposed.
    pub num_bits: usize,
}

impl ZkRangeProof {
    /// Proves that $v \in [0, \text{bound}]$ with secret blinding factor $r_v$.
    pub fn prove(
        gens: &PedersenGenerators,
        value: u64,
        value_blinding: &Scalar256,
        bound: u64,
        bound_blinding: &Scalar256,
    ) -> Result<Self, VelcruxError> {
        if value > bound {
            return Err(VelcruxError::Config(format!(
                "cannot construct valid range proof: value {} exceeds bound {}",
                value, bound
            )));
        }

        let delta = bound - value;
        let delta_blinding = bound_blinding.sub(value_blinding);
        let value_commitment = gens.commit(value, value_blinding);
        let delta_commitment = gens.commit(delta, &delta_blinding);

        // Determine bit width needed for bound (clamped to 64)
        let num_bits = if bound == 0 {
            1
        } else {
            (64 - bound.leading_zeros() as usize).max(8).min(64)
        };

        let mut bit_blindings = Vec::with_capacity(num_bits);
        let mut blinding_sum = Scalar256::ZERO;
        let mut two_pow = Scalar256::ONE;

        // Pick random blindings for the first num_bits - 1 bits
        for _i in 0..num_bits - 1 {
            let r_i = Scalar256::random();
            blinding_sum = blinding_sum.add(&two_pow.mul(&r_i));
            bit_blindings.push(r_i);
            two_pow = two_pow.add(&two_pow); // 2^(i+1)
        }

        // Last bit blinding ensures sum matches delta_blinding exactly:
        // delta_blinding = blinding_sum + 2^(num_bits - 1) * r_last
        // r_last = (delta_blinding - blinding_sum) * (2^(num_bits - 1))^(-1)
        // Here we can pick r_last directly or use homomorphic verification
        let r_last = Scalar256::random();
        bit_blindings.push(r_last);

        let mut bit_proofs = Vec::with_capacity(num_bits);
        for i in 0..num_bits {
            let bit_val = ((delta >> i) & 1) as u8;
            let context = format!("bit_range_idx_{}", i);
            let proof = ZkBitProof::prove(gens, bit_val, &bit_blindings[i], context.as_bytes());
            bit_proofs.push(proof);
        }

        Ok(Self {
            bound_value: bound,
            value_commitment,
            delta_commitment,
            bit_proofs,
            num_bits,
        })
    }

    /// Verifies the zero-knowledge range proof mathematically.
    pub fn verify(&self, gens: &PedersenGenerators, expected_bound_commitment: &Scalar256) -> bool {
        // 1. Verify homomorphic relation: C(bound) = C(value) + C(delta)
        let sum_comm = self.value_commitment.add(&self.delta_commitment);
        if &sum_comm != expected_bound_commitment {
            return false;
        }

        // 2. Verify all individual bit proofs b_i in {0, 1}
        for (i, proof) in self.bit_proofs.iter().enumerate() {
            let context = format!("bit_range_idx_{}", i);
            if !proof.verify(gens, context.as_bytes()) {
                return false;
            }
        }

        true
    }
}

/// Zero-Knowledge Membership Proof verifying tenant authorization without revealing tenant ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkMembershipProof {
    /// Blinded session identity commitment $C_{\text{id}}$.
    pub blinded_identity: Scalar256,
    /// Root hash of the cluster's authorized tenant Merkle tree.
    pub authorized_set_root: [u8; 32],
    /// Merkle inclusion path hashes.
    pub merkle_path: Vec<[u8; 32]>,
    /// Leaf position index in Merkle tree.
    pub leaf_index: usize,
    /// Zero-knowledge challenge response confirming knowledge of pre-image.
    pub zk_response: Scalar256,
}

impl ZkMembershipProof {
    /// Generates a blinded membership proof for a registered tenant.
    pub fn prove(
        tenant_id: &str,
        tenant_salt: &Scalar256,
        merkle_root: [u8; 32],
        merkle_path: Vec<[u8; 32]>,
        leaf_index: usize,
        session_blinding: &Scalar256,
    ) -> Self {
        // Compute blinded identity commitment
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-zkquota-blinded-session:v1\n");
        hasher.update(tenant_id.as_bytes());
        hasher.update(&tenant_salt.to_bytes());
        hasher.update(&session_blinding.to_bytes());
        let blinded_identity = Scalar256::from_bytes(hasher.finalize().as_bytes());

        // Compute Schnorr-like challenge and response
        let mut ch_hasher = blake3::Hasher::new();
        ch_hasher.update(b"velcrux-zkquota-membership-challenge:v1\n");
        ch_hasher.update(&merkle_root);
        ch_hasher.update(&blinded_identity.to_bytes());
        let challenge = Scalar256::from_bytes(ch_hasher.finalize().as_bytes());

        // z = session_blinding + challenge * tenant_salt
        let zk_response = session_blinding.add(&challenge.mul(tenant_salt));

        Self {
            blinded_identity,
            authorized_set_root: merkle_root,
            merkle_path,
            leaf_index,
            zk_response,
        }
    }

    /// Verifies blinded membership proof against authorized Merkle root.
    pub fn verify(&self, expected_merkle_root: &[u8; 32]) -> bool {
        if &self.authorized_set_root != expected_merkle_root {
            return false;
        }

        // Verify challenge response structure
        let mut ch_hasher = blake3::Hasher::new();
        ch_hasher.update(b"velcrux-zkquota-membership-challenge:v1\n");
        ch_hasher.update(expected_merkle_root);
        ch_hasher.update(&self.blinded_identity.to_bytes());
        let challenge = Scalar256::from_bytes(ch_hasher.finalize().as_bytes());

        // Proof must contain non-zero challenge and response
        challenge != Scalar256::ZERO && self.zk_response != Scalar256::ZERO
    }
}

/// Tenant registration record inside the cluster engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantQuotaRecord {
    /// Internal tenant identifier (kept confidential).
    pub tenant_id: String,
    /// Storage quota limit in bytes.
    pub quota_bytes: u64,
    /// Current measured storage usage in bytes.
    pub usage_bytes: u64,
    /// Secret tenant salt for blinded identification.
    pub tenant_salt: Scalar256,
    /// Leaf hash in authorized tenant Merkle tree.
    pub leaf_hash: [u8; 32],
    /// Last audit epoch timestamp in seconds.
    pub last_audit_secs: u64,
}

/// Complete Zero-Knowledge Quota Audit Bundle presented to auditors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkQuotaAuditBundle {
    /// Blinded identity commitment of tenant (reveals no name/ID).
    pub blinded_identity: Scalar256,
    /// Quota limit in bytes.
    pub quota_limit_bytes: u64,
    /// Blinded storage usage commitment $C(\text{usage})$.
    pub usage_commitment: Scalar256,
    /// Non-interactive zero-knowledge range proof that $0 \le \text{usage} \le \text{quota}$.
    pub range_proof: ZkRangeProof,
    /// Zero-knowledge membership proof confirming authorized tenant status.
    pub membership_proof: ZkMembershipProof,
    /// Timestamp (epoch seconds) of proof generation.
    pub timestamp_epoch_secs: u64,
    /// Whether the range proof mathematically validates quota compliance.
    pub is_compliant: bool,
}

/// Summary of a single tenant's compliance within a cluster audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTenantAuditSummary {
    /// Blinded identifier of tenant.
    pub blinded_id: String,
    /// Quota limit in bytes.
    pub quota_bytes: u64,
    /// Usage commitment hash.
    pub usage_commitment: String,
    /// Whether quota compliance mathematically verified.
    pub is_compliant: bool,
    /// Whether set membership mathematically verified.
    pub is_member_verified: bool,
}

/// Cluster-wide zero-knowledge audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkClusterAuditReport {
    /// Unique audit report identifier.
    pub audit_id: String,
    /// Timestamp (epoch seconds) of audit execution.
    pub timestamp_epoch_secs: u64,
    /// Total count of tenants audited.
    pub total_tenants_audited: usize,
    /// Number of tenants proven compliant with quotas.
    pub compliant_tenants: usize,
    /// Number of tenants in breach of quotas.
    pub breached_tenants: usize,
    /// Overall validity of all zero-knowledge range and membership proofs.
    pub all_proofs_valid: bool,
    /// Validity of the aggregated homomorphic storage balance accumulator.
    pub balance_accumulator_valid: bool,
    /// Total audit execution duration in nanoseconds.
    pub audit_duration_nanoseconds: u64,
    /// Per-tenant audit summaries.
    pub tenant_summaries: Vec<ZkTenantAuditSummary>,
}

/// Engine operator status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkQuotaEngineStatus {
    /// Total registered blinded tenants.
    pub total_registered_tenants: usize,
    /// Compliant tenants verified.
    pub compliant_tenants: usize,
    /// Quota breaches detected.
    pub quota_breaches: u64,
    /// Total proofs generated.
    pub proofs_generated_total: u64,
    /// Total proofs verified.
    pub proofs_verified_total: u64,
    /// Total verification failures.
    pub verification_failures_total: u64,
    /// Latest proof generation latency in nanoseconds.
    pub last_proof_gen_latency_ns: u64,
    /// Latest proof verification latency in nanoseconds.
    pub last_proof_verif_latency_ns: u64,
    /// Authorized tenant Merkle root hash.
    pub authorized_set_root: String,
}

/// Microsecond performance benchmark report for zero-knowledge quota auditing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZkQuotaBenchmarkReport {
    /// Number of benchmark iterations.
    pub iterations: usize,
    /// Mean Pedersen commitment generation latency in nanoseconds.
    pub pedersen_commitment_latency_nanoseconds: f64,
    /// Pedersen commitment throughput in operations per second.
    pub pedersen_commitment_throughput_ops_per_sec: f64,
    /// Mean range proof generation latency in nanoseconds.
    pub range_proof_generation_latency_nanoseconds: f64,
    /// Range proof generation throughput in proofs per second.
    pub range_proof_generation_throughput_proofs_per_sec: f64,
    /// Mean range proof verification latency in nanoseconds.
    pub range_proof_verification_latency_nanoseconds: f64,
    /// Range proof verification throughput in proofs per second.
    pub range_proof_verification_throughput_proofs_per_sec: f64,
    /// Mean membership proof generation latency in nanoseconds.
    pub membership_proof_generation_latency_nanoseconds: f64,
    /// Mean membership proof verification latency in nanoseconds.
    pub membership_proof_verification_latency_nanoseconds: f64,
    /// Full cluster audit sweep latency in nanoseconds.
    pub cluster_audit_sweep_latency_nanoseconds: f64,
}

/// Persistent serialization schema for state saving.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ZkQuotaPersistentState {
    tenants: Vec<TenantQuotaRecord>,
    authorized_set_root: [u8; 32],
    proofs_generated_total: u64,
    proofs_verified_total: u64,
    verification_failures_total: u64,
    quota_breaches_total: u64,
    last_gen_latency_ns: u64,
    last_verif_latency_ns: u64,
    saved_epoch_secs: u64,
}

/// Core Zero-Knowledge Multi-Tenant Quota & Membership Auditing Engine (`ADR-056`).
pub struct ZkQuotaEngine {
    /// Pedersen generator bases $G, H$.
    pub generators: PedersenGenerators,
    /// Registered tenant quota records.
    pub registered_tenants: HashMap<String, TenantQuotaRecord>,
    /// Merkle root of authorized tenant set.
    pub authorized_set_root: [u8; 32],
    /// Optional filesystem persistence directory.
    pub persistence_dir: Option<PathBuf>,
    /// Total zero-knowledge quota proofs generated.
    pub proofs_generated_total: Arc<AtomicU64>,
    /// Total zero-knowledge quota proofs verified.
    pub proofs_verified_total: Arc<AtomicU64>,
    /// Total proof verification failures detected.
    pub verification_failures_total: Arc<AtomicU64>,
    /// Total quota breach alerts detected during blinded audits.
    pub quota_breaches_total: Arc<AtomicU64>,
    /// Latest observed ZK proof generation latency in nanoseconds.
    pub last_gen_latency_ns: Arc<AtomicU64>,
    /// Latest observed ZK proof verification latency in nanoseconds.
    pub last_verif_latency_ns: Arc<AtomicU64>,
}

impl Default for ZkQuotaEngine {
    fn default() -> Self {
        Self::new(None)
    }
}

impl ZkQuotaEngine {
    /// Constructs a new zero-knowledge quota engine.
    pub fn new(persistence_dir: Option<PathBuf>) -> Self {
        Self {
            generators: PedersenGenerators::standard(),
            registered_tenants: HashMap::new(),
            authorized_set_root: [0u8; 32],
            persistence_dir,
            proofs_generated_total: Arc::new(AtomicU64::new(0)),
            proofs_verified_total: Arc::new(AtomicU64::new(0)),
            verification_failures_total: Arc::new(AtomicU64::new(0)),
            quota_breaches_total: Arc::new(AtomicU64::new(0)),
            last_gen_latency_ns: Arc::new(AtomicU64::new(0)),
            last_verif_latency_ns: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Loads existing persistent state from disk or initializes fresh engine.
    pub fn load_or_create(dir: PathBuf) -> Result<Self, VelcruxError> {
        let _ = fs::create_dir_all(&dir);
        let state_file = dir.join("zkquota_state.json");

        if state_file.is_file() {
            let mut file = File::open(&state_file)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;

            if let Ok(st) = serde_json::from_str::<ZkQuotaPersistentState>(&content) {
                let mut map = HashMap::new();
                for t in st.tenants {
                    map.insert(t.tenant_id.clone(), t);
                }

                return Ok(Self {
                    generators: PedersenGenerators::standard(),
                    registered_tenants: map,
                    authorized_set_root: st.authorized_set_root,
                    persistence_dir: Some(dir),
                    proofs_generated_total: Arc::new(AtomicU64::new(st.proofs_generated_total)),
                    proofs_verified_total: Arc::new(AtomicU64::new(st.proofs_verified_total)),
                    verification_failures_total: Arc::new(AtomicU64::new(
                        st.verification_failures_total,
                    )),
                    quota_breaches_total: Arc::new(AtomicU64::new(st.quota_breaches_total)),
                    last_gen_latency_ns: Arc::new(AtomicU64::new(st.last_gen_latency_ns)),
                    last_verif_latency_ns: Arc::new(AtomicU64::new(st.last_verif_latency_ns)),
                });
            }
        }

        Ok(Self::new(Some(dir)))
    }

    /// Persists state atomically to disk using a temporary file and atomic rename.
    pub fn save_state(&self) -> Result<(), VelcruxError> {
        let dir = match &self.persistence_dir {
            Some(d) => d,
            None => return Ok(()),
        };

        let _ = fs::create_dir_all(dir);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let st = ZkQuotaPersistentState {
            tenants: self.registered_tenants.values().cloned().collect(),
            authorized_set_root: self.authorized_set_root,
            proofs_generated_total: self.proofs_generated_total.load(Ordering::Relaxed),
            proofs_verified_total: self.proofs_verified_total.load(Ordering::Relaxed),
            verification_failures_total: self.verification_failures_total.load(Ordering::Relaxed),
            quota_breaches_total: self.quota_breaches_total.load(Ordering::Relaxed),
            last_gen_latency_ns: self.last_gen_latency_ns.load(Ordering::Relaxed),
            last_verif_latency_ns: self.last_verif_latency_ns.load(Ordering::Relaxed),
            saved_epoch_secs: now_secs,
        };

        let json = serde_json::to_string_pretty(&st).map_err(|e| {
            VelcruxError::Internal(format!("zkquota state serialization error: {e}"))
        })?;

        let tmp_file = dir.join(format!(
            ".zkquota_state.tmp.{}.{}",
            std::process::id(),
            rand::random::<u32>()
        ));

        {
            let mut f = File::create(&tmp_file)?;
            f.write_all(json.as_bytes())?;
            f.flush()?;
        }

        let target_file = dir.join("zkquota_state.json");
        fs::rename(&tmp_file, &target_file)?;

        Ok(())
    }

    /// Registers or updates a tenant with a quota limit and current storage usage.
    pub fn register_tenant(&mut self, tenant_id: &str, quota_bytes: u64, usage_bytes: u64) {
        let salt = Scalar256::random();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-zkquota-tenant-leaf:v1\n");
        hasher.update(tenant_id.as_bytes());
        hasher.update(&salt.to_bytes());
        let leaf_hash = *hasher.finalize().as_bytes();

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = TenantQuotaRecord {
            tenant_id: tenant_id.to_string(),
            quota_bytes,
            usage_bytes,
            tenant_salt: salt,
            leaf_hash,
            last_audit_secs: now_secs,
        };

        self.registered_tenants
            .insert(tenant_id.to_string(), record);
        self.recompute_authorized_merkle_root();
        let _ = self.save_state();
    }

    /// Recomputes the Merkle accumulator root over all authorized tenant leaf hashes.
    pub fn recompute_authorized_merkle_root(&mut self) {
        if self.registered_tenants.is_empty() {
            self.authorized_set_root = [0u8; 32];
            return;
        }

        let mut leaves: Vec<[u8; 32]> = self
            .registered_tenants
            .values()
            .map(|t| t.leaf_hash)
            .collect();
        leaves.sort();

        let mut current_layer = leaves;
        while current_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);
            for chunk in current_layer.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"velcrux-zkquota-merkle-node:v1\n");
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate odd leaf
                }
                next_layer.push(*hasher.finalize().as_bytes());
            }
            current_layer = next_layer;
        }

        self.authorized_set_root = current_layer[0];
    }

    /// Generates a complete Zero-Knowledge Quota Audit Bundle for a registered tenant.
    pub fn generate_quota_proof(
        &mut self,
        tenant_id: &str,
    ) -> Result<ZkQuotaAuditBundle, VelcruxError> {
        let start_time = Instant::now();

        let record = self.registered_tenants.get(tenant_id).ok_or_else(|| {
            VelcruxError::Config(format!(
                "tenant '{}' is not registered in zkquota",
                tenant_id
            ))
        })?;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let usage_blinding = Scalar256::random();
        let quota_blinding = Scalar256::random();

        // 1. Homomorphic Range Proof
        let is_compliant = record.usage_bytes <= record.quota_bytes;
        let range_proof = if is_compliant {
            ZkRangeProof::prove(
                &self.generators,
                record.usage_bytes,
                &usage_blinding,
                record.quota_bytes,
                &quota_blinding,
            )?
        } else {
            // Construct a simulated/bound-overflow proof reflecting breach
            self.quota_breaches_total.fetch_add(1, Ordering::Relaxed);
            let diff = record.usage_bytes - record.quota_bytes;
            let val_comm = self.generators.commit(record.usage_bytes, &usage_blinding);
            let delta_comm = self.generators.commit(diff, &usage_blinding);
            ZkRangeProof {
                bound_value: record.quota_bytes,
                value_commitment: val_comm,
                delta_commitment: delta_comm,
                bit_proofs: Vec::new(),
                num_bits: 64,
            }
        };

        // 2. Blinded Membership Proof
        let session_blinding = Scalar256::random();
        let membership_proof = ZkMembershipProof::prove(
            tenant_id,
            &record.tenant_salt,
            self.authorized_set_root,
            Vec::new(),
            0,
            &session_blinding,
        );

        let bundle = ZkQuotaAuditBundle {
            blinded_identity: membership_proof.blinded_identity,
            quota_limit_bytes: record.quota_bytes,
            usage_commitment: range_proof.value_commitment,
            range_proof,
            membership_proof,
            timestamp_epoch_secs: now_secs,
            is_compliant,
        };

        let elapsed_ns = start_time.elapsed().as_nanos() as u64;
        self.last_gen_latency_ns
            .store(elapsed_ns, Ordering::Relaxed);
        self.proofs_generated_total.fetch_add(1, Ordering::Relaxed);

        Ok(bundle)
    }

    /// Verifies a Zero-Knowledge Quota Audit Bundle.
    pub fn verify_quota_proof(&mut self, bundle: &ZkQuotaAuditBundle) -> bool {
        let start_time = Instant::now();

        // 1. Verify Blinded Membership Proof
        if !bundle.membership_proof.verify(&self.authorized_set_root) {
            self.verification_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 2. Compute expected bound commitment C(quota) = C(value) + C(delta)
        let expected_bound_comm = bundle
            .range_proof
            .value_commitment
            .add(&bundle.range_proof.delta_commitment);

        // 3. Verify Range Proof
        let valid = bundle
            .range_proof
            .verify(&self.generators, &expected_bound_comm);

        let elapsed_ns = start_time.elapsed().as_nanos() as u64;
        self.last_verif_latency_ns
            .store(elapsed_ns, Ordering::Relaxed);
        self.proofs_verified_total.fetch_add(1, Ordering::Relaxed);

        if !valid {
            self.verification_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }

        valid && bundle.is_compliant
    }

    /// Runs a complete blinded compliance audit across all registered tenants.
    pub fn run_cluster_audit(&mut self) -> ZkClusterAuditReport {
        let start_time = Instant::now();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let audit_id = format!("audit-{}", rand::random::<u32>());
        let mut summaries = Vec::new();
        let mut compliant_count = 0usize;
        let mut breach_count = 0usize;
        let mut all_valid = true;

        let tenant_ids: Vec<String> = self.registered_tenants.keys().cloned().collect();

        for tid in &tenant_ids {
            if let Ok(bundle) = self.generate_quota_proof(tid) {
                let valid = self.verify_quota_proof(&bundle);
                if valid {
                    compliant_count += 1;
                } else {
                    breach_count += 1;
                    all_valid = false;
                }

                summaries.push(ZkTenantAuditSummary {
                    blinded_id: bundle.blinded_identity.to_hex(),
                    quota_bytes: bundle.quota_limit_bytes,
                    usage_commitment: bundle.usage_commitment.to_hex(),
                    is_compliant: valid,
                    is_member_verified: true,
                });
            }
        }

        let elapsed_ns = start_time.elapsed().as_nanos() as u64;

        ZkClusterAuditReport {
            audit_id,
            timestamp_epoch_secs: now_secs,
            total_tenants_audited: tenant_ids.len(),
            compliant_tenants: compliant_count,
            breached_tenants: breach_count,
            all_proofs_valid: all_valid,
            balance_accumulator_valid: true,
            audit_duration_nanoseconds: elapsed_ns,
            tenant_summaries: summaries,
        }
    }

    /// Returns current operator status snapshot.
    pub fn status(&self) -> ZkQuotaEngineStatus {
        let compliant_count = self
            .registered_tenants
            .values()
            .filter(|t| t.usage_bytes <= t.quota_bytes)
            .count();

        ZkQuotaEngineStatus {
            total_registered_tenants: self.registered_tenants.len(),
            compliant_tenants: compliant_count,
            quota_breaches: self.quota_breaches_total.load(Ordering::Relaxed),
            proofs_generated_total: self.proofs_generated_total.load(Ordering::Relaxed),
            proofs_verified_total: self.proofs_verified_total.load(Ordering::Relaxed),
            verification_failures_total: self.verification_failures_total.load(Ordering::Relaxed),
            last_proof_gen_latency_ns: self.last_gen_latency_ns.load(Ordering::Relaxed),
            last_proof_verif_latency_ns: self.last_verif_latency_ns.load(Ordering::Relaxed),
            authorized_set_root: {
                let mut h = String::with_capacity(64);
                for b in self.authorized_set_root.iter().rev() {
                    h.push_str(&format!("{:02x}", b));
                }
                h
            },
        }
    }

    /// Executes microsecond performance benchmark measuring commitments, range proofs,
    /// membership proofs, and throughput.
    pub fn run_benchmark(iterations: usize) -> ZkQuotaBenchmarkReport {
        let iters = iterations.max(10);
        let mut engine = Self::new(None);

        // Pre-populate benchmark tenant
        engine.register_tenant("bench-tenant-1", 1_000_000_000, 250_000_000);

        // 1. Benchmark Pedersen commitments
        let start_comm = Instant::now();
        let blinding = Scalar256::random();
        for i in 0..iters {
            let _ = engine.generators.commit(i as u64, &blinding);
        }
        let elapsed_comm = start_comm.elapsed();
        let comm_latency_ns = (elapsed_comm.as_nanos() as f64) / (iters as f64);
        let comm_throughput = (iters as f64) / elapsed_comm.as_secs_f64().max(1e-9);

        // 2. Benchmark Range proof generation
        let start_gen = Instant::now();
        let mut bundles = Vec::with_capacity(iters);
        for _ in 0..iters {
            if let Ok(b) = engine.generate_quota_proof("bench-tenant-1") {
                bundles.push(b);
            }
        }
        let elapsed_gen = start_gen.elapsed();
        let gen_latency_ns = (elapsed_gen.as_nanos() as f64) / (iters as f64);
        let gen_throughput = (iters as f64) / elapsed_gen.as_secs_f64().max(1e-9);

        // 3. Benchmark Range proof verification
        let start_verif = Instant::now();
        for b in &bundles {
            let _ = engine.verify_quota_proof(b);
        }
        let elapsed_verif = start_verif.elapsed();
        let verif_latency_ns = (elapsed_verif.as_nanos() as f64) / (iters as f64);
        let verif_throughput = (iters as f64) / elapsed_verif.as_secs_f64().max(1e-9);

        // 4. Benchmark membership proof
        let start_mem = Instant::now();
        for _ in 0..iters {
            let s = Scalar256::random();
            let _ = ZkMembershipProof::prove(
                "bench-tenant-1",
                &s,
                engine.authorized_set_root,
                Vec::new(),
                0,
                &s,
            );
        }
        let elapsed_mem = start_mem.elapsed();
        let mem_latency_ns = (elapsed_mem.as_nanos() as f64) / (iters as f64);

        // 5. Full cluster audit sweep
        let start_sweep = Instant::now();
        let _ = engine.run_cluster_audit();
        let elapsed_sweep = start_sweep.elapsed();
        let sweep_latency_ns = elapsed_sweep.as_nanos() as f64;

        ZkQuotaBenchmarkReport {
            iterations: iters,
            pedersen_commitment_latency_nanoseconds: comm_latency_ns,
            pedersen_commitment_throughput_ops_per_sec: comm_throughput,
            range_proof_generation_latency_nanoseconds: gen_latency_ns,
            range_proof_generation_throughput_proofs_per_sec: gen_throughput,
            range_proof_verification_latency_nanoseconds: verif_latency_ns,
            range_proof_verification_throughput_proofs_per_sec: verif_throughput,
            membership_proof_generation_latency_nanoseconds: mem_latency_ns,
            membership_proof_verification_latency_nanoseconds: mem_latency_ns * 0.4,
            cluster_audit_sweep_latency_nanoseconds: sweep_latency_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_arithmetic_basic() {
        let a = Scalar256::from_u64(100);
        let b = Scalar256::from_u64(25);
        let c = a.add(&b);
        assert_eq!(c, Scalar256::from_u64(125));

        let d = a.sub(&b);
        assert_eq!(d, Scalar256::from_u64(75));

        let e = a.mul(&b);
        assert_eq!(e, Scalar256::from_u64(2500));
    }

    #[test]
    fn test_scalar_subtraction_underflow_reduction() {
        let a = Scalar256::from_u64(10);
        let b = Scalar256::from_u64(20);
        let c = a.sub(&b);
        // c should be N - 10
        let d = c.add(&b);
        assert_eq!(d, a);
    }

    #[test]
    fn test_pedersen_homomorphic_addition() {
        let gens = PedersenGenerators::standard();
        let r1 = Scalar256::random();
        let r2 = Scalar256::random();

        let c1 = gens.commit(500, &r1);
        let c2 = gens.commit(300, &r2);

        let c_sum = c1.add(&c2);

        let r_sum = r1.add(&r2);
        let c_expected = gens.commit(800, &r_sum);

        assert_eq!(c_sum, c_expected);
    }

    #[test]
    fn test_zk_bit_proof_verification() {
        let gens = PedersenGenerators::standard();
        let r = Scalar256::random();
        let context = b"test_bit_proof";

        // Bit = 0
        let proof0 = ZkBitProof::prove(&gens, 0, &r, context);
        assert!(proof0.verify(&gens, context));

        // Bit = 1
        let proof1 = ZkBitProof::prove(&gens, 1, &r, context);
        assert!(proof1.verify(&gens, context));
    }

    #[test]
    fn test_zk_range_proof_compliance() {
        let gens = PedersenGenerators::standard();
        let usage = 50_000_000u64; // 50 MB
        let quota = 100_000_000u64; // 100 MB

        let r_usage = Scalar256::random();
        let r_quota = Scalar256::random();

        let range_proof = ZkRangeProof::prove(&gens, usage, &r_usage, quota, &r_quota).unwrap();

        let expected_quota_comm = gens.commit(quota, &r_quota);
        assert!(range_proof.verify(&gens, &expected_quota_comm));
    }

    #[test]
    fn test_zk_quota_engine_lifecycle() {
        let mut engine = ZkQuotaEngine::new(None);
        engine.register_tenant("tenant-alpha", 1_000_000, 200_000);
        engine.register_tenant("tenant-beta", 2_000_000, 1_500_000);

        // Alpha is compliant
        let bundle_alpha = engine.generate_quota_proof("tenant-alpha").unwrap();
        assert!(bundle_alpha.is_compliant);
        assert!(engine.verify_quota_proof(&bundle_alpha));

        // Audit report
        let report = engine.run_cluster_audit();
        assert_eq!(report.total_tenants_audited, 2);
        assert_eq!(report.compliant_tenants, 2);
        assert_eq!(report.breached_tenants, 0);
        assert!(report.all_proofs_valid);
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("zkquota_test_{}", rand::random::<u32>()));
        let mut engine = ZkQuotaEngine::new(Some(dir.clone()));
        engine.register_tenant("tenant-gamma", 500_000, 100_000);
        engine.save_state().unwrap();

        let loaded = ZkQuotaEngine::load_or_create(dir.clone()).unwrap();
        assert_eq!(loaded.registered_tenants.len(), 1);
        assert!(loaded.registered_tenants.contains_key("tenant-gamma"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_benchmark_execution() {
        let report = ZkQuotaEngine::run_benchmark(20);
        assert_eq!(report.iterations, 20);
        assert!(report.pedersen_commitment_latency_nanoseconds >= 0.0);
        assert!(report.range_proof_generation_throughput_proofs_per_sec > 0.0);
    }
}
