//! Confidential Enclave Attestation & Remote Hardware Root-of-Trust Mesh (`ADR-077`).
//!
//! Features:
//! - AMD SEV-SNP, Intel SGX/TDX, AWS Nitro, and simulated enclave hardware attestation quotes.
//! - Cryptographic launch measurements (`MrEnclave`, `MrSigner`, `LaunchDigest`) and TCB SVN baseline enforcement.
//! - Strict non-debug policy enforcement.
//! - TLS 1.3 Channel Binding (`tls-exporter` / RFC 9266) embedded in 64-byte `REPORTDATA` defeating hypervisor MITM relay attacks.
//! - Hardware-derived data sealing and unsealing under `MRENCLAVE` or `MRSIGNER` policies.
//! - Distributed mutual attestation root-of-trust mesh for zero-trust cluster coordination.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod binding;
pub mod mesh;
pub mod sealing;
pub mod types;

pub use attestation::{EnclaveAttestationEngine, EnclaveVerificationReport};
pub use binding::{generate_channel_binding_report_data, verify_channel_binding};
pub use mesh::{EnclaveMeshEngine, EnclaveMeshPeer};
pub use sealing::{EnclaveSealingEngine, SealedEnclavePayload, SealingPolicy};
pub use types::{
    EnclaveAttestationEvidence, EnclaveMeasurement, EnclavePlatform, EnclavePolicy, EnclaveQuote,
    TcbVersion,
};
