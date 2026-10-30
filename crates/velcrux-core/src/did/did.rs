//! Zero-Trust Decentralized Identity (DID) & Verifiable Credential Attestation Mesh (Option CG, ADR-049).
//!
//! Implements W3C `did:key` and `did:peer` decentralized identifiers, standard W3C Verifiable Credentials
//! (VC Data Model v1.1/v2.0) for transfer authorization, Ed25519 signature attestation, and ephemeral
//! cryptographic capability delegation chains without centralized PKI dependencies.

#![forbid(unsafe_code)]

use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::audit::hex_encode;
use crate::error::VelcruxError;

/// Bitcoin Base58 alphabet (W3C multibase base58btc, 'z').
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode raw byte slice into a Base58BTC string.
pub fn base58_encode(data: &[u8]) -> String {
    let mut zeros = 0;
    while zeros < data.len() && data[zeros] == 0 {
        zeros += 1;
    }

    let size = (data.len() - zeros) * 138 / 100 + 1;
    let mut b58 = vec![0u8; size];

    for &byte in &data[zeros..] {
        let mut carry = byte as u32;
        let mut i = 0;
        for it in b58.iter_mut().rev() {
            if carry == 0 && i >= size {
                break;
            }
            carry += 256 * (*it as u32);
            *it = (carry % 58) as u8;
            carry /= 58;
            i += 1;
        }
    }

    let mut it = 0;
    while it < b58.len() && b58[it] == 0 {
        it += 1;
    }

    let mut res = String::with_capacity(zeros + (b58.len() - it));
    for _ in 0..zeros {
        res.push('1');
    }
    for &b in &b58[it..] {
        res.push(BASE58_ALPHABET[b as usize] as char);
    }
    res
}

/// Decode a Base58BTC string into raw bytes.
pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut zeros = 0;
    let bytes = s.as_bytes();
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    }

    let size = (bytes.len() - zeros) * 733 / 1000 + 1;
    let mut b256 = vec![0u8; size];

    for &ch in &bytes[zeros..] {
        let val = match BASE58_ALPHABET.iter().position(|&c| c == ch) {
            Some(v) => v as u32,
            None => return None,
        };
        let mut carry = val;
        let mut i = 0;
        for it in b256.iter_mut().rev() {
            if carry == 0 && i >= size {
                break;
            }
            carry += 58 * (*it as u32);
            *it = (carry % 256) as u8;
            carry /= 256;
            i += 1;
        }
    }

    let mut it = 0;
    while it < b256.len() && b256[it] == 0 {
        it += 1;
    }

    let mut res = Vec::with_capacity(zeros + (b256.len() - it));
    res.resize(zeros, 0u8);
    res.extend_from_slice(&b256[it..]);
    Some(res)
}

/// Supported Decentralized Identifier (DID) method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidMethod {
    /// W3C `did:key`: public key encoded in multicodec + multibase.
    Key,
    /// W3C `did:peer`: peer-to-peer decentralized identifier (numalgo 0 inception key).
    Peer,
}

/// W3C Verification Method in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// W3C Decentralized Identifier Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation: Vec<String>,
}

/// Construct a canonical DID from a 32-byte Ed25519 public key.
pub fn did_from_ed25519_pubkey(pubkey: &[u8; 32], method: DidMethod) -> String {
    // Ed25519 multicodec prefix: 0xed, 0x01 (varint)
    let mut multicodec_bytes = Vec::with_capacity(34);
    multicodec_bytes.push(0xed);
    multicodec_bytes.push(0x01);
    multicodec_bytes.extend_from_slice(pubkey);

    let b58 = base58_encode(&multicodec_bytes);
    match method {
        DidMethod::Key => format!("did:key:z{}", b58),
        DidMethod::Peer => format!("did:peer:0z{}", b58),
    }
}

/// Generate a new random Ed25519 keypair, returning PKCS#8 bytes and 32-byte public key.
pub fn generate_ed25519_keypair() -> Result<(Vec<u8>, [u8; 32]), VelcruxError> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| {
        VelcruxError::Config(format!("Failed to generate Ed25519 keypair: {:?}", e))
    })?;
    let keypair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| VelcruxError::Config(format!("Failed to parse Ed25519 keypair: {:?}", e)))?;
    let pk_bytes: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    Ok((pkcs8.as_ref().to_vec(), pk_bytes))
}

/// Parse an Ed25519 keypair from PKCS#8 bytes, returning the keypair and its 32-byte public key.
pub fn parse_ed25519_keypair(
    pkcs8: &[u8],
) -> Result<(signature::Ed25519KeyPair, [u8; 32]), VelcruxError> {
    let kp = signature::Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|e| {
        VelcruxError::Config(format!("Failed to parse Ed25519 PKCS#8 bytes: {:?}", e))
    })?;
    let pk_bytes: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
    Ok((kp, pk_bytes))
}

/// Resolve a `did:key` or `did:peer` into its raw Ed25519 public key and W3C DID Document.
pub fn resolve_did(did: &str) -> Result<([u8; 32], DidDocument), VelcruxError> {
    let multibase_str = if let Some(stripped) = did.strip_prefix("did:key:z") {
        stripped
    } else if let Some(stripped) = did.strip_prefix("did:peer:0z") {
        stripped
    } else {
        return Err(VelcruxError::Config(format!(
            "Unsupported or malformed DID method for '{}': only did:key:z... and did:peer:0z... supported",
            did
        )));
    };

    let raw = base58_decode(multibase_str).ok_or_else(|| {
        VelcruxError::Config(format!(
            "Invalid Base58BTC multibase string in DID: {}",
            did
        ))
    })?;

    if raw.len() != 34 || raw[0] != 0xed || raw[1] != 0x01 {
        return Err(VelcruxError::Config(format!(
            "DID '{}' is not a valid Ed25519 multicodec key (expected 34 bytes with 0xed01 header, got {} bytes)",
            did,
            raw.len()
        )));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[2..34]);

    let key_id = format!("{}#key-1", did);
    let vm = VerificationMethod {
        id: key_id.clone(),
        type_: "Ed25519VerificationKey2020".to_string(),
        controller: did.to_string(),
        public_key_multibase: format!("z{}", multibase_str),
    };

    let doc = DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
        ],
        id: did.to_string(),
        verification_method: vec![vm],
        authentication: vec![key_id.clone()],
        assertion_method: vec![key_id.clone()],
        capability_delegation: vec![key_id],
    };

    Ok((pubkey, doc))
}

/// Subject claims of a Velcrux Transfer Capability Verifiable Credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferCapabilitySubject {
    /// Subject DID granted the capability.
    pub id: String,
    /// Target organization / tenant ID.
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Path prefixes or glob patterns permitted for transfer.
    #[serde(rename = "allowedPaths")]
    pub allowed_paths: Vec<String>,
    /// Permitted operations (e.g. "upload", "download", "sync", "admin").
    #[serde(rename = "allowedOperations")]
    pub allowed_operations: Vec<String>,
    /// Maximum allowed transfer bandwidth in bits per second (0 = unlimited).
    #[serde(rename = "maxBandwidthBps")]
    pub max_bandwidth_bps: u64,
    /// Maximum burst rate limit quota.
    #[serde(rename = "rateLimitBurst")]
    pub rate_limit_burst: u64,
    /// Maximum delegation depth (0 = cannot delegate to sub-agents).
    #[serde(rename = "delegationDepth")]
    pub delegation_depth: u32,
}

/// Cryptographic digital proof block embedded in a Verifiable Credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub type_: String,
    pub created: u64,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// W3C Verifiable Credential for Velcrux zero-trust transfer authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: u64,
    #[serde(rename = "expirationDate")]
    pub expiration_date: u64,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: TransferCapabilitySubject,
    #[serde(rename = "parentCredential", skip_serializing_if = "Option::is_none")]
    pub parent_credential: Option<Box<VerifiableCredential>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialProof>,
}

impl VerifiableCredential {
    /// Compute the domain-separated canonical BLAKE3 signing digest over the credential claims.
    pub fn compute_signing_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-vc-attestation:v1\0");
        hasher.update(self.id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.issuer.as_bytes());
        hasher.update(b"\0");
        hasher.update(&self.issuance_date.to_be_bytes());
        hasher.update(&self.expiration_date.to_be_bytes());
        hasher.update(self.credential_subject.id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.credential_subject.tenant_id.as_bytes());
        hasher.update(b"\0");

        for p in &self.credential_subject.allowed_paths {
            hasher.update(p.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b"\0");

        for op in &self.credential_subject.allowed_operations {
            hasher.update(op.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b"\0");

        hasher.update(&self.credential_subject.max_bandwidth_bps.to_be_bytes());
        hasher.update(&self.credential_subject.rate_limit_burst.to_be_bytes());
        hasher.update(&self.credential_subject.delegation_depth.to_be_bytes());

        if let Some(parent) = &self.parent_credential {
            let parent_digest = parent.compute_signing_digest();
            hasher.update(&parent_digest);
        }

        *hasher.finalize().as_bytes()
    }
}

/// Verification outcome and detailed claims report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub is_valid: bool,
    pub issuer_did: String,
    pub subject_did: String,
    pub tenant_id: String,
    pub allowed_paths: Vec<String>,
    pub allowed_operations: Vec<String>,
    pub delegation_depth: u32,
    pub delegation_chain_depth: usize,
    pub time_to_expiry_seconds: i64,
    pub verification_latency_nanoseconds: u64,
}

/// Benchmark report measuring DID resolution, issuance, and verification latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidBenchmarkReport {
    pub iterations: usize,
    pub resolution_latency_nanoseconds: f64,
    pub resolution_ops_per_second: f64,
    pub issuance_latency_nanoseconds: f64,
    pub issuance_ops_per_second: f64,
    pub verification_latency_nanoseconds: f64,
    pub verification_ops_per_second: f64,
}

/// Zero-Trust DID & Verifiable Credential Attestation Engine.
pub struct DidAttestationEngine {
    resolutions_total: AtomicU64,
    vc_issued_total: AtomicU64,
    vc_verified_total: AtomicU64,
    vc_failures_total: AtomicU64,
    last_latency_ns: AtomicU64,
    active_delegations: AtomicU64,
}

impl Default for DidAttestationEngine {
    fn default() -> Self {
        Self {
            resolutions_total: AtomicU64::new(0),
            vc_issued_total: AtomicU64::new(0),
            vc_verified_total: AtomicU64::new(0),
            vc_failures_total: AtomicU64::new(0),
            last_latency_ns: AtomicU64::new(0),
            active_delegations: AtomicU64::new(0),
        }
    }
}

impl DidAttestationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a `did:key` or `did:peer` identifier.
    pub fn resolve(&self, did: &str) -> Result<([u8; 32], DidDocument), VelcruxError> {
        let (pk, doc) = resolve_did(did)?;
        self.resolutions_total.fetch_add(1, Ordering::Relaxed);
        Ok((pk, doc))
    }

    /// Issue a new cryptographically signed Verifiable Credential.
    pub fn issue_credential(
        &self,
        keypair: &signature::Ed25519KeyPair,
        issuer_did: &str,
        subject_did: &str,
        tenant_id: &str,
        allowed_paths: Vec<String>,
        allowed_operations: Vec<String>,
        max_bandwidth_bps: u64,
        valid_duration_seconds: u64,
        delegation_depth: u32,
        parent_credential: Option<VerifiableCredential>,
    ) -> Result<VerifiableCredential, VelcruxError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now + valid_duration_seconds;

        // If parent exists, enforce delegation invariants
        if let Some(parent) = &parent_credential {
            if parent.credential_subject.delegation_depth == 0 {
                return Err(VelcruxError::Config(
                    "Parent credential has delegation_depth=0 and cannot be delegated further"
                        .to_string(),
                ));
            }
            if delegation_depth >= parent.credential_subject.delegation_depth {
                return Err(VelcruxError::Config(format!(
                    "Delegated credential delegation_depth ({}) must be strictly less than parent delegation_depth ({})",
                    delegation_depth, parent.credential_subject.delegation_depth
                )));
            }
            if exp > parent.expiration_date {
                return Err(VelcruxError::Config(
                    "Delegated credential expiration cannot exceed parent credential expiration"
                        .to_string(),
                ));
            }
            // Enforce operation containment
            for op in &allowed_operations {
                let parent_has_op = parent
                    .credential_subject
                    .allowed_operations
                    .iter()
                    .any(|po| po == "*" || po.eq_ignore_ascii_case(op));
                if !parent_has_op {
                    return Err(VelcruxError::Config(format!(
                        "Privilege escalation attempt: operation '{}' is not authorized by parent operations {:?}",
                        op, parent.credential_subject.allowed_operations
                    )));
                }
            }
            // Enforce path containment
            for p in &allowed_paths {
                let parent_has_path = parent.credential_subject.allowed_paths.iter().any(|pp| {
                    if pp == "*" || pp == "/*" {
                        return true;
                    }
                    if let Some(pp_prefix) = pp.strip_suffix('*') {
                        p.starts_with(pp_prefix)
                    } else {
                        p == pp
                    }
                });
                if !parent_has_path {
                    return Err(VelcruxError::Config(format!(
                        "Privilege escalation attempt: path '{}' is not authorized by parent allowed paths {:?}",
                        p, parent.credential_subject.allowed_paths
                    )));
                }
            }
        }

        let id = format!("urn:uuid:{}", ulid::Ulid::new().to_string().to_lowercase());

        let mut vc = VerifiableCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://velcrux.io/credentials/v1".to_string(),
            ],
            id,
            type_: vec![
                "VerifiableCredential".to_string(),
                "VelcruxTransferCapabilityCredential".to_string(),
            ],
            issuer: issuer_did.to_string(),
            issuance_date: now,
            expiration_date: exp,
            credential_subject: TransferCapabilitySubject {
                id: subject_did.to_string(),
                tenant_id: tenant_id.to_string(),
                allowed_paths,
                allowed_operations,
                max_bandwidth_bps,
                rate_limit_burst: 65536,
                delegation_depth,
            },
            parent_credential: parent_credential.map(Box::new),
            proof: None,
        };

        let digest = vc.compute_signing_digest();
        let sig = keypair.sign(&digest);
        let sig_bytes = sig.as_ref();

        vc.proof = Some(CredentialProof {
            type_: "Ed25519Signature2020".to_string(),
            created: now,
            verification_method: format!("{}#key-1", issuer_did),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: hex_encode(sig_bytes),
        });

        self.vc_issued_total.fetch_add(1, Ordering::Relaxed);
        if vc.parent_credential.is_some() {
            self.active_delegations.fetch_add(1, Ordering::Relaxed);
        }

        Ok(vc)
    }

    /// Verify a Verifiable Credential against requested path, operation, and delegation chain.
    pub fn verify_credential(
        &self,
        vc: &VerifiableCredential,
        requested_path: Option<&str>,
        requested_op: Option<&str>,
    ) -> Result<VerificationReport, VelcruxError> {
        let start = Instant::now();
        let res = self.verify_internal(vc, requested_path, requested_op, 0);
        let latency_ns = start.elapsed().as_nanos() as u64;
        self.last_latency_ns.store(latency_ns, Ordering::Relaxed);

        match res {
            Ok(mut report) => {
                report.verification_latency_nanoseconds = latency_ns;
                self.vc_verified_total.fetch_add(1, Ordering::Relaxed);
                Ok(report)
            }
            Err(e) => {
                self.vc_failures_total.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    fn verify_internal(
        &self,
        vc: &VerifiableCredential,
        requested_path: Option<&str>,
        requested_op: Option<&str>,
        depth: usize,
    ) -> Result<VerificationReport, VelcruxError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Time checks
        if now < vc.issuance_date {
            return Err(VelcruxError::Config(format!(
                "Verifiable Credential is not yet valid (issuanceDate={}, now={})",
                vc.issuance_date, now
            )));
        }
        if now > vc.expiration_date {
            return Err(VelcruxError::Config(format!(
                "Verifiable Credential has expired (expirationDate={}, now={})",
                vc.expiration_date, now
            )));
        }

        // 2. Proof existence
        let proof = vc.proof.as_ref().ok_or_else(|| {
            VelcruxError::Config("Verifiable Credential lacks proof block".into())
        })?;

        // 3. Resolve issuer DID
        let (issuer_pk, _) = resolve_did(&vc.issuer)?;

        // 4. Decode proof signature
        let sig_bytes = hex_decode_64(&proof.proof_value).ok_or_else(|| {
            VelcruxError::Config("Proof signature hex string is invalid".to_string())
        })?;

        // 5. Recompute canonical digest & verify Ed25519 signature
        let digest = vc.compute_signing_digest();
        let peer_pubkey = signature::UnparsedPublicKey::new(&signature::ED25519, &issuer_pk);
        if peer_pubkey.verify(&digest, &sig_bytes).is_err() {
            return Err(VelcruxError::Config(
                "Cryptographic signature verification failed on Verifiable Credential".to_string(),
            ));
        }

        // 6. Scope check on requested path
        if let Some(path) = requested_path {
            let matched = vc.credential_subject.allowed_paths.iter().any(|pattern| {
                if pattern == "*" || pattern == "/*" {
                    return true;
                }
                if let Some(prefix) = pattern.strip_suffix('*') {
                    path.starts_with(prefix)
                } else {
                    path == pattern
                }
            });
            if !matched {
                return Err(VelcruxError::Config(format!(
                    "Path '{}' is not authorized by allowed_paths {:?}",
                    path, vc.credential_subject.allowed_paths
                )));
            }
        }

        // 7. Scope check on requested operation
        if let Some(op) = requested_op {
            let matched = vc
                .credential_subject
                .allowed_operations
                .iter()
                .any(|o| o.eq_ignore_ascii_case(op) || o == "*");
            if !matched {
                return Err(VelcruxError::Config(format!(
                    "Operation '{}' is not authorized by allowed_operations {:?}",
                    op, vc.credential_subject.allowed_operations
                )));
            }
        }

        // 8. If parent credential exists, recursively verify delegation invariants
        let mut total_chain_depth = depth;
        if let Some(parent) = &vc.parent_credential {
            // Parent's subject DID must match this credential's issuer DID
            if parent.credential_subject.id != vc.issuer {
                return Err(VelcruxError::Config(format!(
                    "Delegation chain mismatch: parent subject '{}' does not match child issuer '{}'",
                    parent.credential_subject.id, vc.issuer
                )));
            }
            if parent.credential_subject.delegation_depth == 0 {
                return Err(VelcruxError::Config(
                    "Parent credential delegation_depth is 0; delegation rejected".to_string(),
                ));
            }
            // Child allowed operations must be subset of parent allowed operations
            for child_op in &vc.credential_subject.allowed_operations {
                let parent_has_op = parent
                    .credential_subject
                    .allowed_operations
                    .iter()
                    .any(|po| po == "*" || po.eq_ignore_ascii_case(child_op));
                if !parent_has_op {
                    return Err(VelcruxError::Config(format!(
                        "Privilege escalation attempt: child operation '{}' not present in parent credential",
                        child_op
                    )));
                }
            }
            // Child allowed paths must be subset of parent allowed paths
            for cp in &vc.credential_subject.allowed_paths {
                let parent_has_path = parent.credential_subject.allowed_paths.iter().any(|pp| {
                    if pp == "*" || pp == "/*" {
                        return true;
                    }
                    if let Some(pp_prefix) = pp.strip_suffix('*') {
                        cp.starts_with(pp_prefix)
                    } else {
                        cp == pp
                    }
                });
                if !parent_has_path {
                    return Err(VelcruxError::Config(format!(
                        "Privilege escalation attempt: child path '{}' is not authorized by parent allowed paths {:?}",
                        cp, parent.credential_subject.allowed_paths
                    )));
                }
            }

            // Verify parent recursively
            let parent_report = self.verify_internal(parent, None, None, depth + 1)?;
            total_chain_depth = parent_report.delegation_chain_depth;
        }

        let time_to_exp = (vc.expiration_date as i64) - (now as i64);

        Ok(VerificationReport {
            is_valid: true,
            issuer_did: vc.issuer.clone(),
            subject_did: vc.credential_subject.id.clone(),
            tenant_id: vc.credential_subject.tenant_id.clone(),
            allowed_paths: vc.credential_subject.allowed_paths.clone(),
            allowed_operations: vc.credential_subject.allowed_operations.clone(),
            delegation_depth: vc.credential_subject.delegation_depth,
            delegation_chain_depth: total_chain_depth,
            time_to_expiry_seconds: time_to_exp,
            verification_latency_nanoseconds: 0,
        })
    }

    /// Read atomic telemetry stats.
    pub fn stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            self.resolutions_total.load(Ordering::Relaxed),
            self.vc_issued_total.load(Ordering::Relaxed),
            self.vc_verified_total.load(Ordering::Relaxed),
            self.vc_failures_total.load(Ordering::Relaxed),
            self.last_latency_ns.load(Ordering::Relaxed),
            self.active_delegations.load(Ordering::Relaxed),
        )
    }

    /// Benchmark DID resolution, VC issuance, and VC verification latency.
    pub fn run_benchmark(&self, iterations: usize) -> DidBenchmarkReport {
        let iters = iterations.max(1);
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk_bytes: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();

        let issuer_did = did_from_ed25519_pubkey(&pk_bytes, DidMethod::Key);
        let subject_did = did_from_ed25519_pubkey(&[0x42u8; 32], DidMethod::Key);

        // 1. Resolution benchmark
        let start_res = Instant::now();
        for _ in 0..iters {
            let _ = resolve_did(&issuer_did).unwrap();
        }
        let elapsed_res = start_res.elapsed();
        let avg_res_ns = (elapsed_res.as_nanos() as f64) / (iters as f64);
        let res_ops_sec = (iters as f64) / elapsed_res.as_secs_f64();

        // 2. Issuance benchmark
        let start_issue = Instant::now();
        let mut sample_vc = None;
        for _ in 0..iters {
            let vc = self
                .issue_credential(
                    &keypair,
                    &issuer_did,
                    &subject_did,
                    "tenant-bench",
                    vec!["/data/*".to_string()],
                    vec!["upload".to_string(), "download".to_string()],
                    1_000_000_000,
                    3600,
                    1,
                    None,
                )
                .unwrap();
            sample_vc = Some(vc);
        }
        let elapsed_issue = start_issue.elapsed();
        let avg_issue_ns = (elapsed_issue.as_nanos() as f64) / (iters as f64);
        let issue_ops_sec = (iters as f64) / elapsed_issue.as_secs_f64();

        // 3. Verification benchmark
        let vc_to_verify = sample_vc.unwrap();
        let start_verify = Instant::now();
        for _ in 0..iters {
            let _ = self
                .verify_credential(&vc_to_verify, Some("/data/file.bin"), Some("upload"))
                .unwrap();
        }
        let elapsed_verify = start_verify.elapsed();
        let avg_verify_ns = (elapsed_verify.as_nanos() as f64) / (iters as f64);
        let verify_ops_sec = (iters as f64) / elapsed_verify.as_secs_f64();

        DidBenchmarkReport {
            iterations: iters,
            resolution_latency_nanoseconds: avg_res_ns,
            resolution_ops_per_second: res_ops_sec,
            issuance_latency_nanoseconds: avg_issue_ns,
            issuance_ops_per_second: issue_ops_sec,
            verification_latency_nanoseconds: avg_verify_ns,
            verification_ops_per_second: verify_ops_sec,
        }
    }
}

/// Helper to decode hex string into bytes.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
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

/// Helper to decode 64-byte hex signature.
fn hex_decode_64(hex: &str) -> Option<[u8; 64]> {
    if hex.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base58_roundtrip() {
        let original = b"Velcrux Decentralized Identity and Verifiable Credentials";
        let encoded = base58_encode(original);
        let decoded = base58_decode(&encoded).expect("decode failed");
        assert_eq!(&decoded[..], &original[..]);
    }

    #[test]
    fn test_did_key_generation_and_resolution() {
        let pubkey = [0x55u8; 32];
        let did = did_from_ed25519_pubkey(&pubkey, DidMethod::Key);
        assert!(did.starts_with("did:key:z6M"));

        let (resolved_pk, doc) = resolve_did(&did).expect("resolve did:key");
        assert_eq!(resolved_pk, pubkey);
        assert_eq!(doc.id, did);
        assert_eq!(doc.verification_method.len(), 1);
        assert!(doc.verification_method[0].id.starts_with(&did));
    }

    #[test]
    fn test_did_peer_generation_and_resolution() {
        let pubkey = [0x77u8; 32];
        let did = did_from_ed25519_pubkey(&pubkey, DidMethod::Peer);
        assert!(did.starts_with("did:peer:0z6M"));

        let (resolved_pk, doc) = resolve_did(&did).expect("resolve did:peer");
        assert_eq!(resolved_pk, pubkey);
        assert_eq!(doc.id, did);
    }

    #[test]
    fn test_verifiable_credential_issuance_and_verification() {
        let engine = DidAttestationEngine::new();
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk_bytes: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();

        let issuer_did = did_from_ed25519_pubkey(&pk_bytes, DidMethod::Key);
        let subject_did = did_from_ed25519_pubkey(&[0x11u8; 32], DidMethod::Key);

        let vc = engine
            .issue_credential(
                &keypair,
                &issuer_did,
                &subject_did,
                "tenant-alpha",
                vec!["/backups/*".to_string(), "/reports/daily.pdf".to_string()],
                vec!["upload".to_string(), "download".to_string()],
                100_000_000,
                3600,
                1,
                None,
            )
            .expect("issue vc");

        // Verify authorized path and op
        let report = engine
            .verify_credential(&vc, Some("/backups/node1.tar"), Some("upload"))
            .expect("verify valid vc");
        assert!(report.is_valid);
        assert_eq!(report.issuer_did, issuer_did);
        assert_eq!(report.subject_did, subject_did);
        assert_eq!(report.tenant_id, "tenant-alpha");

        // Verify unauthorized path rejected
        assert!(engine
            .verify_credential(&vc, Some("/etc/shadow"), Some("upload"))
            .is_err());

        // Verify unauthorized op rejected
        assert!(engine
            .verify_credential(&vc, Some("/backups/node1.tar"), Some("delete"))
            .is_err());
    }

    #[test]
    fn test_ephemeral_capability_delegation_chain() {
        let engine = DidAttestationEngine::new();
        let rng = ring::rand::SystemRandom::new();

        // 1. Root tenant keypair
        let root_pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let root_kp = signature::Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref()).unwrap();
        let root_pk: [u8; 32] = root_kp.public_key().as_ref().try_into().unwrap();
        let root_did = did_from_ed25519_pubkey(&root_pk, DidMethod::Key);

        // 2. Intermediate client agent keypair
        let agent_pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let agent_kp = signature::Ed25519KeyPair::from_pkcs8(agent_pkcs8.as_ref()).unwrap();
        let agent_pk: [u8; 32] = agent_kp.public_key().as_ref().try_into().unwrap();
        let agent_did = did_from_ed25519_pubkey(&agent_pk, DidMethod::Key);

        // 3. Ephemeral worker sub-agent keypair
        let worker_pk: [u8; 32] = [0x88u8; 32];
        let worker_did = did_from_ed25519_pubkey(&worker_pk, DidMethod::Key);

        // Root delegates to Agent with delegationDepth=1
        let root_vc = engine
            .issue_credential(
                &root_kp,
                &root_did,
                &agent_did,
                "tenant-enterprise",
                vec!["/vault/*".to_string()],
                vec!["upload".to_string(), "download".to_string()],
                500_000_000,
                7200,
                1,
                None,
            )
            .unwrap();

        // Agent delegates to Ephemeral Worker with delegationDepth=0
        let worker_vc = engine
            .issue_credential(
                &agent_kp,
                &agent_did,
                &worker_did,
                "tenant-enterprise",
                vec!["/vault/shard-1.bin".to_string()],
                vec!["download".to_string()],
                100_000_000,
                3600,
                0,
                Some(root_vc),
            )
            .unwrap();

        // Verify delegation chain succeeds
        let report = engine
            .verify_credential(&worker_vc, Some("/vault/shard-1.bin"), Some("download"))
            .expect("verify delegation chain");
        assert!(report.is_valid);
        assert_eq!(report.delegation_chain_depth, 1);

        // Worker cannot delegate further because delegationDepth=0
        assert!(engine
            .issue_credential(
                &agent_kp,
                &agent_did,
                &worker_did,
                "tenant-enterprise",
                vec!["/vault/*".to_string()],
                vec!["download".to_string()],
                100_000_000,
                3600,
                0,
                Some(worker_vc),
            )
            .is_err());
    }

    #[test]
    fn test_did_benchmark_execution() {
        let engine = DidAttestationEngine::new();
        let report = engine.run_benchmark(10);
        assert_eq!(report.iterations, 10);
        assert!(report.resolution_ops_per_second > 1000.0);
        assert!(report.issuance_ops_per_second > 100.0);
        assert!(report.verification_ops_per_second > 100.0);
    }
}
