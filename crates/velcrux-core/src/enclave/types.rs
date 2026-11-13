//! Core data structures and types for Confidential Enclave Attestation & Remote Hardware Root-of-Trust Mesh.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported Confidential Computing / Trusted Execution Environment (TEE) hardware architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclavePlatform {
    /// AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP)
    AmdSevSnp,
    /// Intel Software Guard Extensions (SGX)
    IntelSgx,
    /// Intel Trust Domain Extensions (TDX)
    IntelTdx,
    /// AWS Nitro Enclaves
    AwsNitro,
    /// Cryptographically verified simulated hardware enclave for testing and edge gateways
    Simulated,
}

impl EnclavePlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AmdSevSnp => "amd_sev_snp",
            Self::IntelSgx => "intel_sgx",
            Self::IntelTdx => "intel_tdx",
            Self::AwsNitro => "aws_nitro",
            Self::Simulated => "simulated",
        }
    }
}

impl fmt::Display for EnclavePlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cryptographic measurements defining the enclave initial state and binary integrity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnclaveMeasurement {
    /// Primary launch digest (SHA-384 48-byte hash for AMD SEV-SNP or SHA-256 32-byte for others).
    pub launch_digest: Vec<u8>,
    /// Intel SGX MRENCLAVE: 256-bit SHA-256 hash representing enclave code & data layout.
    pub mr_enclave: Option<[u8; 32]>,
    /// Intel SGX MRSIGNER: 256-bit SHA-256 hash of the enclave author's public signing key.
    pub mr_signer: Option<[u8; 32]>,
    /// Independent Software Vendor (ISV) Product Identifier.
    pub isv_prod_id: u16,
    /// Independent Software Vendor (ISV) Security Version Number (SVN).
    pub isv_svn: u16,
}

impl EnclaveMeasurement {
    /// Constructs a simulated measurement from a code descriptor.
    pub fn simulated(descriptor: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-enclave-code-measurement:v1:");
        hasher.update(descriptor.as_bytes());
        let digest_bytes = hasher.finalize();

        let mut mr_e = [0u8; 32];
        mr_e.copy_from_slice(digest_bytes.as_bytes());

        let mut mr_s = [0u8; 32];
        let mut signer_hasher = blake3::Hasher::new();
        signer_hasher.update(b"velcrux-author-signer-key:v1:");
        signer_hasher.update(descriptor.as_bytes());
        mr_s.copy_from_slice(signer_hasher.finalize().as_bytes());

        Self {
            launch_digest: digest_bytes.as_bytes().to_vec(),
            mr_enclave: Some(mr_e),
            mr_signer: Some(mr_s),
            isv_prod_id: 1,
            isv_svn: 2,
        }
    }

    pub fn launch_digest_hex(&self) -> String {
        hex_encode(&self.launch_digest)
    }

    pub fn mr_enclave_hex(&self) -> Option<String> {
        self.mr_enclave.map(|m| hex_encode(&m))
    }

    pub fn mr_signer_hex(&self) -> Option<String> {
        self.mr_signer.map(|m| hex_encode(&m))
    }
}

/// Trusted Computing Base (TCB) Security Version Number (SVN) composite state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TcbVersion {
    pub bootloader_svn: u8,
    pub tee_svn: u8,
    pub snp_or_cpusvn: u8,
    pub microcode_svn: u8,
}

impl TcbVersion {
    pub fn new(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            bootloader_svn: bootloader,
            tee_svn: tee,
            snp_or_cpusvn: snp,
            microcode_svn: microcode,
        }
    }

    pub fn production_baseline() -> Self {
        Self {
            bootloader_svn: 3,
            tee_svn: 4,
            snp_or_cpusvn: 8,
            microcode_svn: 12,
        }
    }

    /// Checks if this TCB version meets or exceeds the required threshold on all components.
    pub fn is_at_least(&self, required: &TcbVersion) -> bool {
        self.bootloader_svn >= required.bootloader_svn
            && self.tee_svn >= required.tee_svn
            && self.snp_or_cpusvn >= required.snp_or_cpusvn
            && self.microcode_svn >= required.microcode_svn
    }
}

/// Strict security policy applied during enclave quote and measurement validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclavePolicy {
    /// Whether debug-mode enclaves are permitted (strictly `false` in production).
    pub allow_debug: bool,
    /// Minimum acceptable TCB SVN levels.
    pub min_tcb: TcbVersion,
    /// List of hardware platforms permitted in the mesh.
    pub accepted_platforms: Vec<EnclavePlatform>,
    /// Optional expected MRENCLAVE / launch digest requirement.
    pub expected_mr_enclave: Option<Vec<u8>>,
    /// Optional expected MRSIGNER requirement.
    pub expected_mr_signer: Option<Vec<u8>>,
    /// Maximum allowed quote age in seconds before re-attestation is required.
    pub max_quote_age_seconds: u64,
}

impl Default for EnclavePolicy {
    fn default() -> Self {
        Self {
            allow_debug: false,
            min_tcb: TcbVersion::production_baseline(),
            accepted_platforms: vec![
                EnclavePlatform::AmdSevSnp,
                EnclavePlatform::IntelSgx,
                EnclavePlatform::IntelTdx,
                EnclavePlatform::AwsNitro,
                EnclavePlatform::Simulated,
            ],
            expected_mr_enclave: None,
            expected_mr_signer: None,
            max_quote_age_seconds: 3600, // 1 hour validity
        }
    }
}

/// Cryptographic Hardware Attestation Quote produced by the enclave root of trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveQuote {
    pub platform: EnclavePlatform,
    pub measurement: EnclaveMeasurement,
    /// 64-byte user-defined data embedded in the quote (e.g. TLS 1.3 channel binding hash).
    #[serde(with = "hex_64")]
    pub report_data: [u8; 64],
    pub tcb_version: TcbVersion,
    pub is_debug: bool,
    pub hardware_chip_id: [u8; 32],
    pub timestamp_epoch_secs: u64,
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

impl EnclaveQuote {
    /// Computes the canonical signature digest over the quote fields.
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-enclave-quote-digest:v1:");
        hasher.update(self.platform.as_str().as_bytes());
        hasher.update(&self.measurement.launch_digest);
        if let Some(ref e) = self.measurement.mr_enclave {
            hasher.update(e);
        }
        if let Some(ref s) = self.measurement.mr_signer {
            hasher.update(s);
        }
        hasher.update(&self.measurement.isv_prod_id.to_be_bytes());
        hasher.update(&self.measurement.isv_svn.to_be_bytes());
        hasher.update(&self.report_data);
        hasher.update(&[
            self.tcb_version.bootloader_svn,
            self.tcb_version.tee_svn,
            self.tcb_version.snp_or_cpusvn,
            self.tcb_version.microcode_svn,
        ]);
        hasher.update(&[self.is_debug as u8]);
        hasher.update(&self.hardware_chip_id);
        hasher.update(&self.timestamp_epoch_secs.to_be_bytes());
        let hash = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }
}

/// Attestation evidence payload exchanged across the mesh for mutual authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveAttestationEvidence {
    pub quote: EnclaveQuote,
    pub client_channel_nonce: [u8; 32],
    pub server_channel_nonce: [u8; 32],
    pub tls_exporter_secret_hash: [u8; 32],
}

/// Encodes bytes to lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Decodes a hex string to raw bytes.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(b);
    }
    Some(bytes)
}

mod hex_64 {
    use super::{hex_decode, hex_encode};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcb_version_comparison() {
        let base = TcbVersion::new(2, 2, 4, 8);
        let higher = TcbVersion::new(3, 3, 5, 10);
        let lower = TcbVersion::new(1, 2, 4, 8);

        assert!(higher.is_at_least(&base));
        assert!(base.is_at_least(&base));
        assert!(!lower.is_at_least(&base));
    }

    #[test]
    fn test_enclave_measurement_generation() {
        let m = EnclaveMeasurement::simulated("velcrux-storage-gateway-v1");
        assert_eq!(m.launch_digest.len(), 32);
        assert!(m.mr_enclave.is_some());
        assert!(m.mr_signer.is_some());
        assert_eq!(m.isv_prod_id, 1);
    }
}
