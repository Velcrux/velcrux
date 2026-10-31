//! Confidential Computing & Hardware TEE Remote Attestation Module (Option CH, ADR-050).

pub mod tee;

pub use tee::{
    hex_decode, TeeAttestationEngine, TeeAttestationQuote, TeeAttestationReport,
    TeeBenchmarkReport, TeePlatform, TeePolicy,
};
