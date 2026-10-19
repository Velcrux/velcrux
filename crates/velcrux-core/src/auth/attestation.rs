#![forbid(unsafe_code)]

//! Cryptographic Detached Manifest Signing & End-to-End Attestation (`SECURITY.md` §7, `ADR-031`).
//!
//! Provides verifiable provenance and non-repudiation for dataset transfers and storage roots.
//! A detached attestation binds an authoritative Ed25519 signature to a canonical manifest BLAKE3
//! root digest, file counts, byte totals, issuer identity, timestamps, expiration windows, and
//! arbitrary deployment metadata (e.g. build ID, git commit, compliance classification).
//!
//! # Security Guarantees
//! - **Domain Separation**: All signed preimages are prefixed with [`ATTESTATION_DOMAIN_SEPARATOR`]
//!   to prevent cross-protocol signature forgery (e.g. preventing attestation signatures from being
//!   replayed in SSH/TLS exporter authentication).
//! - **Secret Redaction**: Private keys and sensitive key material are protected by [`Secret<T>`],
//!   guaranteeing they are never leaked in debug/display formatting or structured log outputs
//!   per `SECURITY.md` §7.
//! - **Deterministic Preimage**: The canonical byte representation is serialized with fixed-width
//!   little-endian integers and sorted metadata pairs, ensuring cross-platform bit-level repeatability.
//! - **Pure Safe Rust**: `#![forbid(unsafe_code)]` enforced across all signing and verification logic.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::chunking::ChunkParams;
use crate::error::{ProtocolError, Result, VelcruxError};
use crate::manifest::scanner::{scan_directory_tree, scan_single_file};
use crate::manifest::writer::ManifestWriter;
use crate::protocol::ManifestBegin;
use crate::util::{Hash, Secret};

/// Domain separation prefix for manifest attestations.
pub const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"VELCRUX-MANIFEST-ATTESTATION-V1\0";

/// Current manifest attestation schema version.
pub const ATTESTATION_VERSION_1: u32 = 1;

/// Standard filename extension for detached manifest signatures.
pub const DEFAULT_SIG_EXT: &str = ".velcrux-manifest.sig";

// ---------------------------------------------------------------------------
// Hex serialization helpers (pure Rust, `#![forbid(unsafe_code)]`)
// ---------------------------------------------------------------------------

/// Encode a byte slice to lowercase hex.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Decode a hex string to bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(VelcruxError::Config("hex string has odd length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| VelcruxError::Config(format!("invalid hex byte: {e}")))?;
        out.push(byte);
    }
    Ok(out)
}

/// Base64 decoding helper (pure Rust).
fn decode_base64(s: &str) -> Result<Vec<u8>> {
    let mut clean = String::new();
    for c in s.chars() {
        if !c.is_whitespace() {
            clean.push(c);
        }
    }

    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;

    for c in clean.chars() {
        if c == '=' {
            break;
        }
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(VelcruxError::Config(format!("invalid base64 char: {c}"))),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

/// Base64 encoding helper (pure Rust).
fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };

        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < bytes.len() {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if i + 2 < bytes.len() {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }
    out
}

mod hex_bytes_32 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = decode_hex(&s).map_err(serde::de::Error::custom)?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes for public key, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

mod hex_bytes_64 {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = decode_hex(&s).map_err(serde::de::Error::custom)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes for signature, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// Attestation Payload & Envelope
// ---------------------------------------------------------------------------

/// The claims and metadata attested by the signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPayload {
    /// Schema format version (always [`ATTESTATION_VERSION_1`]).
    pub version: u32,
    /// Root BLAKE3 digest of the transfer manifest.
    pub manifest_hash: Hash,
    /// Declared count of files included in the manifest.
    pub file_count: u64,
    /// Declared total bytes of all files in the manifest.
    pub total_bytes: u64,
    /// Canonical identity string of the attestation issuer (e.g. SPIFFE ID, email, service name).
    pub issuer: String,
    /// Attestation creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Optional expiration timestamp (Unix epoch seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Sorted, application-defined key-value metadata tags.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl AttestationPayload {
    /// Produce the deterministic, canonical binary representation for cryptographic signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(ATTESTATION_DOMAIN_SEPARATOR);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(self.manifest_hash.as_bytes());
        buf.extend_from_slice(&self.file_count.to_le_bytes());
        buf.extend_from_slice(&self.total_bytes.to_le_bytes());
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.unwrap_or(0).to_le_bytes());

        let issuer_bytes = self.issuer.as_bytes();
        buf.extend_from_slice(&(issuer_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(issuer_bytes);

        buf.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        for (k, v) in &self.metadata {
            let k_bytes = k.as_bytes();
            buf.extend_from_slice(&(k_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(k_bytes);

            let v_bytes = v.as_bytes();
            buf.extend_from_slice(&(v_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(v_bytes);
        }
        buf
    }
}

/// A complete detached cryptographic attestation envelope containing claims, public key, and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    /// Attested claims and metadata.
    pub payload: AttestationPayload,
    /// 32-byte Ed25519 public key of the signing identity (hex-encoded in JSON).
    #[serde(with = "hex_bytes_32")]
    pub public_key: [u8; 32],
    /// 64-byte Ed25519 signature over canonical payload bytes (hex-encoded in JSON).
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
}

impl AttestationEnvelope {
    /// Serialize the envelope to a pretty-printed JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| VelcruxError::Protocol(ProtocolError::InvalidManifest(e.to_string())))
    }

    /// Deserialize an envelope from a JSON string.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s)
            .map_err(|e| VelcruxError::Protocol(ProtocolError::InvalidManifest(e.to_string())))
    }

    /// Write this envelope to a file on disk atomically.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Load and deserialize an attestation envelope from a file on disk.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            VelcruxError::Config(format!(
                "failed to read signature file {}: {e}",
                path.display()
            ))
        })?;
        Self::from_json(&content)
    }
}

// ---------------------------------------------------------------------------
// Attestation Key (Ed25519 Secret Wrapper)
// ---------------------------------------------------------------------------

/// An Ed25519 signing keypair with private key material protected by [`Secret<T>`].
pub struct AttestationKey {
    keypair: signature::Ed25519KeyPair,
    pkcs8_secret: Secret<Vec<u8>>,
    public_key: [u8; 32],
}

impl AttestationKey {
    /// Generate a fresh random Ed25519 attestation keypair using the system CSPRNG.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8_doc = signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| {
            VelcruxError::Internal("failed to generate random Ed25519 keypair".into())
        })?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        Self::from_pkcs8(&pkcs8_bytes)
    }

    /// Load an attestation key from PKCS#8 DER bytes.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self> {
        let keypair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
            .map_err(|e| VelcruxError::Config(format!("invalid Ed25519 PKCS#8 key bytes: {e}")))?;
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(keypair.public_key().as_ref());
        Ok(Self {
            keypair,
            pkcs8_secret: Secret::new(pkcs8_bytes.to_vec()),
            public_key,
        })
    }

    /// Parse an attestation key from PKCS#8 PEM string format.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let mut in_block = false;
        let mut b64_lines = String::new();

        for line in pem.lines() {
            let trimmed = line.trim();
            if trimmed == "-----BEGIN PRIVATE KEY-----" {
                in_block = true;
                continue;
            }
            if trimmed == "-----END PRIVATE KEY-----" {
                break;
            }
            if in_block {
                b64_lines.push_str(trimmed);
            }
        }

        if b64_lines.is_empty() {
            // Check if raw hex string was passed
            if let Ok(raw) = decode_hex(pem.trim()) {
                if let Ok(key) = Self::from_pkcs8(&raw) {
                    return Ok(key);
                }
            }
            return Err(VelcruxError::Config(
                "no -----BEGIN PRIVATE KEY----- PEM block found in key".into(),
            ));
        }

        let der = decode_base64(&b64_lines)?;
        Self::from_pkcs8(&der)
    }

    /// Load an attestation key from a file path (supports PEM or DER).
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(|e| {
            VelcruxError::Config(format!("failed to open key file {}: {e}", path.display()))
        })?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        if let Ok(s) = std::str::from_utf8(&buf) {
            if s.contains("-----BEGIN PRIVATE KEY-----") {
                return Self::from_pem(s);
            }
        }

        // Try raw PKCS#8 DER
        Self::from_pkcs8(&buf)
    }

    /// Save the private key to a file in PEM format with restrictive permissions.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let b64 = encode_base64(self.pkcs8_secret.expose());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(path)?;
        file.write_all(pem.as_bytes())?;
        file.sync_all()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Return the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Return the public key formatted as a 64-character lowercase hex string.
    pub fn public_key_hex(&self) -> String {
        encode_hex(&self.public_key)
    }

    /// Format the public key in OpenSSH `ssh-ed25519` authorized_keys format.
    pub fn public_key_openssh(&self, comment: &str) -> String {
        // OpenSSH ed25519 wire format:
        // uint32 len(11) + "ssh-ed25519" + uint32 len(32) + 32-byte pubkey
        let mut wire = Vec::with_capacity(4 + 11 + 4 + 32);
        wire.extend_from_slice(&(11u32).to_be_bytes());
        wire.extend_from_slice(b"ssh-ed25519");
        wire.extend_from_slice(&(32u32).to_be_bytes());
        wire.extend_from_slice(&self.public_key);

        let b64 = encode_base64(&wire);
        if comment.is_empty() {
            format!("ssh-ed25519 {b64}")
        } else {
            format!("ssh-ed25519 {b64} {comment}")
        }
    }

    /// Sign an attestation payload, returning the complete detached [`AttestationEnvelope`].
    pub fn sign(&self, payload: &AttestationPayload) -> AttestationEnvelope {
        let preimage = payload.canonical_bytes();
        let sig = self.keypair.sign(&preimage);
        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(sig.as_ref());

        AttestationEnvelope {
            payload: payload.clone(),
            public_key: self.public_key,
            signature: signature_bytes,
        }
    }
}

impl fmt::Debug for AttestationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationKey")
            .field("public_key", &encode_hex(&self.public_key))
            .field("private_key", &self.pkcs8_secret) // prints [redacted]
            .finish()
    }
}

impl fmt::Display for AttestationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttestationKey(pubkey={}, secret=[redacted])",
            encode_hex(&self.public_key)
        )
    }
}

// ---------------------------------------------------------------------------
// Attestation Verifier & Status
// ---------------------------------------------------------------------------

/// Outcome status of an attestation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationStatus {
    /// Cryptographic signature and all metadata checks succeeded.
    Valid,
    /// Cryptographic Ed25519 signature check failed against public key.
    SignatureInvalid,
    /// The attestation timestamp exceeds the declared expiration deadline.
    Expired,
    /// The attestation creation timestamp lies in the future beyond allowed clock skew.
    FutureTimestamp,
    /// Signer public key is not trusted under the verifier's keyring policy.
    UntrustedSigner,
    /// Signer issuer identity does not match the expected required identity.
    IssuerMismatch,
    /// Manifest root BLAKE3 hash does not match the actual target data on disk.
    HashMismatch,
    /// File count does not match the actual target on disk.
    FileCountMismatch,
    /// Total byte length does not match the actual target on disk.
    TotalBytesMismatch,
    /// Target path does not exist or could not be read.
    TargetNotFound,
    /// Generic I/O or scanner error during disk evaluation.
    IoError,
}

impl fmt::Display for AttestationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "VALID"),
            Self::SignatureInvalid => write!(f, "SIGNATURE_INVALID"),
            Self::Expired => write!(f, "EXPIRED"),
            Self::FutureTimestamp => write!(f, "FUTURE_TIMESTAMP"),
            Self::UntrustedSigner => write!(f, "UNTRUSTED_SIGNER"),
            Self::IssuerMismatch => write!(f, "ISSUER_MISMATCH"),
            Self::HashMismatch => write!(f, "HASH_MISMATCH"),
            Self::FileCountMismatch => write!(f, "FILE_COUNT_MISMATCH"),
            Self::TotalBytesMismatch => write!(f, "TOTAL_BYTES_MISMATCH"),
            Self::TargetNotFound => write!(f, "TARGET_NOT_FOUND"),
            Self::IoError => write!(f, "IO_ERROR"),
        }
    }
}

/// Errors occurring during attestation envelope verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("signature verification failed: invalid Ed25519 signature")]
    InvalidSignature,
    #[error("attestation expired at {expires_at} (current time {current_time})")]
    Expired { expires_at: u64, current_time: u64 },
    #[error("attestation created in the future at {created_at} (current time {current_time})")]
    FutureTimestamp { created_at: u64, current_time: u64 },
    #[error("signer public key {0} is not present in the trusted signers keyring")]
    UntrustedSigner(String),
    #[error("issuer mismatch: expected '{expected}', got '{actual}'")]
    IssuerMismatch { expected: String, actual: String },
    #[error("manifest hash mismatch: signed {signed}, computed {computed}")]
    HashMismatch { signed: Hash, computed: Hash },
    #[error("file count mismatch: signed {signed}, computed {computed}")]
    FileCountMismatch { signed: u64, computed: u64 },
    #[error("total bytes mismatch: signed {signed}, computed {computed}")]
    TotalBytesMismatch { signed: u64, computed: u64 },
    #[error("I/O error during verification: {0}")]
    Io(String),
}

/// Successfully verified attestation claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// Resolved identity name or issuer string of the signer.
    pub signer_identity: String,
    /// 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// Attested claims payload.
    pub payload: AttestationPayload,
}

/// Verifies attestation envelopes against trusted signers and cryptographic policies.
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    trusted_keys: HashMap<[u8; 32], String>,
    require_trusted: bool,
    max_clock_skew_secs: u64,
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationVerifier {
    /// Create a new verifier with default 5-minute clock skew tolerance.
    pub fn new() -> Self {
        Self {
            trusted_keys: HashMap::new(),
            require_trusted: false,
            max_clock_skew_secs: 300,
        }
    }

    /// Require that any verified attestation must be signed by a key in the trusted keyring.
    pub fn with_require_trusted(mut self, require: bool) -> Self {
        self.require_trusted = require;
        self
    }

    /// Set maximum allowed future clock skew tolerance in seconds.
    pub fn with_max_clock_skew(mut self, skew_secs: u64) -> Self {
        self.max_clock_skew_secs = skew_secs;
        self
    }

    /// Add a trusted 32-byte Ed25519 public key with an associated identity name.
    pub fn add_trusted_key(&mut self, pubkey: [u8; 32], identity: impl Into<String>) {
        self.trusted_keys.insert(pubkey, identity.into());
    }

    /// Returns the number of trusted public keys loaded.
    pub fn trusted_key_count(&self) -> usize {
        self.trusted_keys.len()
    }

    /// Load trusted signers from an `authorized_signers` or `authorized_keys` formatted file.
    /// Supports:
    /// - `<hex_pubkey> <identity>`
    /// - `ssh-ed25519 <base64_pubkey> <identity>`
    pub fn load_trusted_keys_file(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            VelcruxError::Config(format!(
                "failed to read trusted keys file {}: {e}",
                path.display()
            ))
        })?;
        let count_before = self.trusted_keys.len();

        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            if parts[0] == "ssh-ed25519" {
                if parts.len() < 2 {
                    return Err(VelcruxError::Config(format!(
                        "line {}: invalid ssh-ed25519 key line",
                        line_no + 1
                    )));
                }
                let raw = decode_base64(parts[1])?;
                let identity = if parts.len() >= 3 {
                    parts[2..].join(" ")
                } else {
                    format!("signer-{}", line_no + 1)
                };

                let pubkey = if raw.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&raw);
                    k
                } else if raw.len() >= 4 + 11 + 4 + 32 {
                    let mut k = [0u8; 32];
                    let offset = 4 + 11 + 4;
                    k.copy_from_slice(&raw[offset..offset + 32]);
                    k
                } else {
                    return Err(VelcruxError::Config(format!(
                        "line {}: invalid length for ssh-ed25519 key",
                        line_no + 1
                    )));
                };
                self.add_trusted_key(pubkey, identity);
            } else {
                // Hex format: <hex_pubkey> [identity]
                let raw = decode_hex(parts[0])?;
                if raw.len() != 32 {
                    return Err(VelcruxError::Config(format!(
                        "line {}: expected 32-byte hex public key",
                        line_no + 1
                    )));
                }
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&raw);
                let identity = if parts.len() >= 2 {
                    parts[1..].join(" ")
                } else {
                    encode_hex(&pubkey)
                };
                self.add_trusted_key(pubkey, identity);
            }
        }

        Ok(self.trusted_keys.len() - count_before)
    }

    /// Cryptographically verify an attestation envelope.
    pub fn verify(
        &self,
        envelope: &AttestationEnvelope,
        now: u64,
    ) -> std::result::Result<VerifiedAttestation, AttestationError> {
        // 1. Verify Ed25519 signature
        let peer_pk = signature::UnparsedPublicKey::new(&signature::ED25519, &envelope.public_key);
        let preimage = envelope.payload.canonical_bytes();
        peer_pk
            .verify(&preimage, &envelope.signature)
            .map_err(|_| AttestationError::InvalidSignature)?;

        // 2. Check expiration
        if let Some(exp) = envelope.payload.expires_at {
            if now > exp {
                return Err(AttestationError::Expired {
                    expires_at: exp,
                    current_time: now,
                });
            }
        }

        // 3. Check future clock skew
        if envelope.payload.created_at > now.saturating_add(self.max_clock_skew_secs) {
            return Err(AttestationError::FutureTimestamp {
                created_at: envelope.payload.created_at,
                current_time: now,
            });
        }

        // 4. Check trusted keyring
        let trusted_id = self.trusted_keys.get(&envelope.public_key).cloned();
        if self.require_trusted && trusted_id.is_none() {
            return Err(AttestationError::UntrustedSigner(encode_hex(
                &envelope.public_key,
            )));
        }

        let signer_identity = trusted_id.unwrap_or_else(|| envelope.payload.issuer.clone());
        Ok(VerifiedAttestation {
            signer_identity,
            public_key: envelope.public_key,
            payload: envelope.payload.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// High-Level Target Manifest Attestation (Sign & Verify End-to-End)
// ---------------------------------------------------------------------------

/// Detailed verification report comparing signed attestation claims with local filesystem reality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Overall boolean validity flag.
    pub is_valid: bool,
    /// Detailed status enum.
    pub status: AttestationStatus,
    /// Resolved identity of the signer.
    pub signer_identity: String,
    /// Hex-encoded public key of the signer.
    pub signer_public_key: String,
    /// Timestamp when attestation was minted.
    pub created_at: u64,
    /// Optional expiration timestamp.
    pub expires_at: Option<u64>,
    /// Signed manifest BLAKE3 root hash.
    pub signed_manifest_hash: Hash,
    /// Recomputed BLAKE3 root hash of the target on disk.
    pub computed_manifest_hash: Hash,
    /// Signed file count.
    pub signed_file_count: u64,
    /// Actual file count found on disk.
    pub computed_file_count: u64,
    /// Signed total bytes.
    pub signed_total_bytes: u64,
    /// Actual total bytes found on disk.
    pub computed_total_bytes: u64,
    /// Target path evaluated.
    pub target_path: String,
    /// Human-readable explanation if verification failed.
    pub error_message: Option<String>,
}

/// Scan a local target path (file or directory tree) and mint a signed attestation envelope.
pub fn generate_target_attestation(
    target_path: &Path,
    key: &AttestationKey,
    issuer: &str,
    expires_in_secs: Option<u64>,
    metadata: BTreeMap<String, String>,
) -> Result<(AttestationEnvelope, ManifestBegin)> {
    if !target_path.exists() {
        return Err(VelcruxError::Protocol(ProtocolError::InvalidPath));
    }

    let temp_dir = std::env::temp_dir();
    let spill_path = temp_dir.join(format!(
        ".velcrux-attest-spill-{}.bin",
        ulid::Ulid::new().to_string()
    ));

    let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default())?;

    let is_dir = target_path.is_dir();
    if is_dir {
        scan_directory_tree(target_path, &mut writer)?;
    } else {
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        let filename = target_path
            .file_name()
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::InvalidPath))?;
        scan_single_file(parent, filename, &mut writer)?;
    }

    let (begin, _end, spill_file) = writer.finish()?;
    let _ = std::fs::remove_file(spill_file);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let expires_at = expires_in_secs.map(|dur| now.saturating_add(dur));

    let payload = AttestationPayload {
        version: ATTESTATION_VERSION_1,
        manifest_hash: begin.manifest_hash,
        file_count: begin.file_count,
        total_bytes: begin.total_bytes,
        issuer: issuer.to_string(),
        created_at: now,
        expires_at,
        metadata,
    };

    let envelope = key.sign(&payload);
    Ok((envelope, begin))
}

/// Verify a target file or directory tree against a detached attestation envelope.
pub fn verify_target_attestation(
    target_path: &Path,
    envelope: &AttestationEnvelope,
    verifier: &AttestationVerifier,
    expected_issuer: Option<&str>,
    now: u64,
) -> Result<AttestationReport> {
    let mut report = AttestationReport {
        is_valid: false,
        status: AttestationStatus::Valid,
        signer_identity: envelope.payload.issuer.clone(),
        signer_public_key: encode_hex(&envelope.public_key),
        created_at: envelope.payload.created_at,
        expires_at: envelope.payload.expires_at,
        signed_manifest_hash: envelope.payload.manifest_hash,
        computed_manifest_hash: Hash::ZERO,
        signed_file_count: envelope.payload.file_count,
        computed_file_count: 0,
        signed_total_bytes: envelope.payload.total_bytes,
        computed_total_bytes: 0,
        target_path: target_path.display().to_string(),
        error_message: None,
    };

    // 1. Verify cryptographic signature & validity
    let verified = match verifier.verify(envelope, now) {
        Ok(v) => v,
        Err(e) => {
            let status = match e {
                AttestationError::InvalidSignature => AttestationStatus::SignatureInvalid,
                AttestationError::Expired { .. } => AttestationStatus::Expired,
                AttestationError::FutureTimestamp { .. } => AttestationStatus::FutureTimestamp,
                AttestationError::UntrustedSigner(_) => AttestationStatus::UntrustedSigner,
                _ => AttestationStatus::SignatureInvalid,
            };
            report.status = status;
            report.error_message = Some(e.to_string());
            return Ok(report);
        }
    };
    report.signer_identity = verified.signer_identity;

    // 2. Issuer check
    if let Some(expected) = expected_issuer {
        if envelope.payload.issuer != expected {
            report.status = AttestationStatus::IssuerMismatch;
            report.error_message = Some(format!(
                "issuer mismatch: expected '{expected}', got '{}'",
                envelope.payload.issuer
            ));
            return Ok(report);
        }
    }

    // 3. Target existence
    if !target_path.exists() {
        report.status = AttestationStatus::TargetNotFound;
        report.error_message = Some(format!(
            "target path '{}' does not exist",
            target_path.display()
        ));
        return Ok(report);
    }

    // 4. Scan disk to compute actual manifest BLAKE3 root hash
    let temp_dir = std::env::temp_dir();
    let spill_path = temp_dir.join(format!(
        ".velcrux-verify-spill-{}.bin",
        ulid::Ulid::new().to_string()
    ));

    let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default())?;
    let scan_res = if target_path.is_dir() {
        scan_directory_tree(target_path, &mut writer)
    } else {
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        let filename = target_path
            .file_name()
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::InvalidPath))?;
        scan_single_file(parent, filename, &mut writer)
    };

    if let Err(e) = scan_res {
        let _ = std::fs::remove_file(&spill_path);
        report.status = AttestationStatus::IoError;
        report.error_message = Some(format!("scanning target on disk failed: {e}"));
        return Ok(report);
    }

    let (begin, _end, spill_file) = writer.finish()?;
    let _ = std::fs::remove_file(spill_file);

    report.computed_manifest_hash = begin.manifest_hash;
    report.computed_file_count = begin.file_count;
    report.computed_total_bytes = begin.total_bytes;

    // 5. Compare claims against disk reality
    if report.computed_manifest_hash != envelope.payload.manifest_hash {
        report.status = AttestationStatus::HashMismatch;
        report.error_message = Some(format!(
            "manifest BLAKE3 root digest mismatch: signed {}, computed {}",
            envelope.payload.manifest_hash, report.computed_manifest_hash
        ));
        return Ok(report);
    }

    if report.computed_file_count != envelope.payload.file_count {
        report.status = AttestationStatus::FileCountMismatch;
        report.error_message = Some(format!(
            "file count mismatch: signed {}, computed {}",
            envelope.payload.file_count, report.computed_file_count
        ));
        return Ok(report);
    }

    if report.computed_total_bytes != envelope.payload.total_bytes {
        report.status = AttestationStatus::TotalBytesMismatch;
        report.error_message = Some(format!(
            "total byte length mismatch: signed {}, computed {}",
            envelope.payload.total_bytes, report.computed_total_bytes
        ));
        return Ok(report);
    }

    report.is_valid = true;
    report.status = AttestationStatus::Valid;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_key_generation_and_debug_redaction() {
        let key = AttestationKey::generate().expect("key generation");
        let debug_str = format!("{key:?}");
        let display_str = format!("{key}");

        // Must redact private key material per SECURITY.md §7
        assert!(debug_str.contains("[redacted]"));
        assert!(display_str.contains("[redacted]"));
        assert_eq!(key.public_key().len(), 32);

        let openssh = key.public_key_openssh("release@velcrux.internal");
        assert!(openssh.starts_with("ssh-ed25519 "));
        assert!(openssh.ends_with(" release@velcrux.internal"));
    }

    #[test]
    fn test_pem_save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("attest.pem");

        let key1 = AttestationKey::generate().unwrap();
        key1.save_to_file(&key_path).unwrap();

        let key2 = AttestationKey::load_from_file(&key_path).unwrap();
        assert_eq!(key1.public_key(), key2.public_key());
    }

    #[test]
    fn test_attestation_signature_verification_and_tamper_detection() {
        let key = AttestationKey::generate().unwrap();
        let now = 1_700_000_000u64;

        let mut metadata = BTreeMap::new();
        metadata.insert("repo".into(), "velcrux".into());
        metadata.insert("commit".into(), "abcdef123".into());

        let payload = AttestationPayload {
            version: ATTESTATION_VERSION_1,
            manifest_hash: Hash::from_bytes(&[0x11; 32]).unwrap(),
            file_count: 42,
            total_bytes: 1_048_576,
            issuer: "spiffe://velcrux.internal/ci-runner".into(),
            created_at: now,
            expires_at: Some(now + 3600),
            metadata,
        };

        let envelope = key.sign(&payload);
        assert_eq!(envelope.public_key, key.public_key());

        let mut verifier = AttestationVerifier::new().with_require_trusted(true);
        verifier.add_trusted_key(key.public_key(), "ci-runner");

        // 1. Valid verification
        let verified = verifier.verify(&envelope, now + 100).expect("valid");
        assert_eq!(verified.signer_identity, "ci-runner");
        assert_eq!(verified.payload.file_count, 42);

        // 2. Tampered manifest hash
        let mut tampered = envelope.clone();
        tampered.payload.manifest_hash = Hash::from_bytes(&[0x22; 32]).unwrap();
        assert_eq!(
            verifier.verify(&tampered, now + 100).unwrap_err(),
            AttestationError::InvalidSignature
        );

        // 3. Tampered signature byte
        let mut bad_sig = envelope.clone();
        bad_sig.signature[10] ^= 0xFF;
        assert_eq!(
            verifier.verify(&bad_sig, now + 100).unwrap_err(),
            AttestationError::InvalidSignature
        );

        // 4. Expired attestation
        assert!(matches!(
            verifier.verify(&envelope, now + 3601).unwrap_err(),
            AttestationError::Expired { .. }
        ));

        // 5. Untrusted signer
        let mut untrusted_verifier = AttestationVerifier::new().with_require_trusted(true);
        untrusted_verifier.add_trusted_key([0x99; 32], "other-agent");
        assert!(matches!(
            untrusted_verifier.verify(&envelope, now + 100).unwrap_err(),
            AttestationError::UntrustedSigner(_)
        ));
    }

    #[test]
    fn test_end_to_end_directory_attestation_lifecycle() {
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("payload");
        std::fs::create_dir_all(&target_dir).unwrap();

        let f1 = target_dir.join("a.txt");
        let f2 = target_dir.join("b.bin");
        std::fs::write(&f1, b"hello world").unwrap();
        std::fs::write(&f2, vec![0xAB; 2048]).unwrap();

        let key = AttestationKey::generate().unwrap();
        let mut meta = BTreeMap::new();
        meta.insert("build".into(), "v1.2.0".into());

        // Generate attestation
        let (envelope, begin) =
            generate_target_attestation(&target_dir, &key, "release-authority", Some(86400), meta)
                .unwrap();

        assert_eq!(begin.file_count, 2);
        assert_eq!(begin.total_bytes, 11 + 2048);

        // Save detached signature into the directory itself
        let sig_path = target_dir.join(".velcrux-manifest.sig");
        envelope.save_to_file(&sig_path).unwrap();

        let loaded_envelope = AttestationEnvelope::load_from_file(&sig_path).unwrap();
        assert_eq!(loaded_envelope, envelope);

        let mut verifier = AttestationVerifier::new().with_require_trusted(true);
        verifier.add_trusted_key(key.public_key(), "release-authority");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Verification must succeed even with .velcrux-manifest.sig residing in target_dir
        let report = verify_target_attestation(
            &target_dir,
            &loaded_envelope,
            &verifier,
            Some("release-authority"),
            now,
        )
        .unwrap();

        assert!(report.is_valid);
        assert_eq!(report.status, AttestationStatus::Valid);
        assert_eq!(report.computed_file_count, 2);

        // Mutate a file -> verification must fail with HashMismatch
        std::fs::write(&f1, b"hello corrupted world").unwrap();
        let report_bad = verify_target_attestation(
            &target_dir,
            &loaded_envelope,
            &verifier,
            Some("release-authority"),
            now,
        )
        .unwrap();

        assert!(!report_bad.is_valid);
        assert_eq!(report_bad.status, AttestationStatus::HashMismatch);
    }
}
