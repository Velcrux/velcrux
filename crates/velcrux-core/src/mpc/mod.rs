#![forbid(unsafe_code)]

//! Zero-Knowledge Multi-Party Computation (MPC) Distributed Threshold Key Signing (`ADR-069`, Option DA).
//!
//! Features:
//! 1. Constant-time prime field scalar arithmetic over Curve25519 order field $\mathbb{F}_\ell$.
//! 2. Twisted Edwards Curve25519 point arithmetic in extended projective coordinates $(X : Y : Z : T)$ with complete addition.
//! 3. Shamir Secret Sharing with polynomial evaluation and Lagrange basis interpolation.
//! 4. Feldman Verifiable Secret Sharing (VSS) with public polynomial commitments precluding dealer equivocation.
//! 5. Non-Interactive Zero-Knowledge Proofs (NIZK) of discrete logarithm knowledge (Schnorr DLEQ) preventing rogue-key attacks.
//! 6. Two-round FROST threshold signing protocol with per-participant binding factors and deterministic blame attribution.
//! 7. 100% standard 64-byte Ed25519 wire format signatures verifiable against master public key by any RFC 8032 verifier.
//! 8. Cluster coordinator orchestration for root authorization tokens, manifest attestations, and audit trails.

pub mod cluster;
pub mod curve;
pub mod protocol;
pub mod scalar;
pub mod vss;
pub mod zkp;

pub use cluster::{
    MpcClusterConfig, MpcClusterCoordinator, MpcManifestAttestation, MpcRootToken,
    MpcSessionAuditRecord,
};
pub use curve::{FieldElement, Point};
pub use protocol::{
    aggregate_signature_shares, verify_signature_share, CommitmentPackage, NonceCommitment,
    SignatureShare, SigningNonces, ThresholdSignature, ThresholdSigner,
};
pub use scalar::Scalar;
pub use vss::{
    compute_lagrange_coefficient, reconstruct_secret, FeldmanCommitmentPackage, Polynomial,
    SecretShare,
};
pub use zkp::SchnorrDlogProof;
