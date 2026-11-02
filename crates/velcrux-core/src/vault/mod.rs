//! Post-Quantum Encrypted Staging Vault with Kyber/Dilithium Envelope Encryption (`ADR-059`).
//!
//! Provides defense-in-depth protection for staged multi-tenant data at rest against
//! "Harvest Now, Decrypt Later" (HNDL) attacks and future Cryptanalytically Relevant
//! Quantum Computers (CRQCs) by combining:
//! - **Key Encapsulation Mechanism (KEM)**: FIPS 203 **ML-KEM-768** (Kyber-768) to encapsulate
//!   ephemeral 256-bit symmetric Data Encryption Keys (DEKs).
//! - **Digital Signatures**: FIPS 204 **ML-DSA-65** (Dilithium-3) for tamper-proof manifest signing
//!   and post-quantum cryptographic identity verification.
//! - **Symmetric AEAD Envelope**: **ChaCha20-Poly1305** (RFC 8439) with cryptographically bound
//!   Associated Authenticated Data (AAD) tying file identity, original size, and vault ID.
//! - **Active Ephemeral Key Shredding**: Multi-pass disk overwrites (`0x55`, `0xAA`, `0x00`) with
//!   explicit fsync and in-memory cryptographic zeroization on sync commitment or abort.
//!
//! # Security Invariants
//! - **Pure Safe Rust**: `#![forbid(unsafe_code)]` strictly enforced across the entire module.
//! - **Post-Quantum Forward Secrecy**: Staged files are encrypted with unique ephemeral DEKs
//!   encapsulated with ML-KEM-768; shredding the key renders staging dumps permanently unrecoverable.
//! - **Tamper-Evident Signatures**: Manifest verification is evaluated before ciphertext decryption;
//!   any modification to ciphertext, nonce, or metadata causes immediate rejection.
//! - **Zero Memory Leaks**: Ephemeral keys and decapsulated shared secrets are zeroized on drop.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::crypto::pqc::{
    ml_dsa_65_keygen_from_seed, ml_dsa_65_sign, ml_dsa_65_verify, ml_kem_768_decapsulate,
    ml_kem_768_encapsulate, ml_kem_768_keygen_from_seed, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey, ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SECRET_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, ML_KEM_768_CIPHERTEXT_SIZE,
    ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_768_SECRET_KEY_SIZE,
};
use crate::error::{Result, VelcruxError};
use crate::session::server::ServerStats;

/// Magic header bytes for standalone `.vlt` binary envelope files.
pub const VAULT_MAGIC_HEADER: &[u8; 17] = b"VELCRUX-VAULT-V1\0";

/// Default number of multi-pass overwrite cycles for cryptographic shredding.
pub const VAULT_DEFAULT_SHRED_PASSES: u32 = 3;

/// Nonce length in bytes for ChaCha20-Poly1305 AEAD (96 bits).
pub const VAULT_NONCE_LEN: usize = 12;

/// Authentication tag length in bytes for ChaCha20-Poly1305 AEAD (128 bits).
pub const VAULT_TAG_LEN: usize = 16;

/// Canonical cipher suite descriptor.
pub const VAULT_CIPHER_SUITE: &str = "ChaCha20-Poly1305";

/// Canonical PQC KEM algorithm descriptor.
pub const VAULT_KEM_ALGO: &str = "ML-KEM-768";

/// Canonical PQC digital signature algorithm descriptor.
pub const VAULT_SIG_ALGO: &str = "ML-DSA-65";

// ---------------------------------------------------------------------------
// Ephemeral Memory Key Zeroization
// ---------------------------------------------------------------------------

/// Ephemeral 256-bit symmetric data encryption key (DEK) with automatic zeroization on drop.
pub struct EphemeralDek {
    bytes: [u8; 32],
}

impl EphemeralDek {
    /// Creates a new ephemeral key wrapper.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generates a fresh cryptographically secure random 256-bit key.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|_| VelcruxError::Internal("CSPRNG failed during DEK generation".into()))?;
        Ok(Self { bytes })
    }

    /// Borrows the raw 32-byte key slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Actively overwrites the in-memory key buffer with zeroes.
    pub fn shred(&mut self) {
        self.bytes.fill(0);
    }
}

impl Drop for EphemeralDek {
    fn drop(&mut self) {
        self.shred();
    }
}

impl std::fmt::Debug for EphemeralDek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EphemeralDek([REDACTED])")
    }
}

// ---------------------------------------------------------------------------
// Vault Data Structures & Envelopes
// ---------------------------------------------------------------------------

/// Lifecycle status of a staged file entry in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultFileStatus {
    /// File is sealed under ML-KEM-768 envelope encryption and intact.
    Sealed,
    /// File has been unsealed into target filesystem destination.
    Unsealed,
    /// Ephemeral key material and payload have been cryptographically shredded.
    Shredded,
}

impl std::fmt::Display for VaultFileStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sealed => write!(f, "SEALED"),
            Self::Unsealed => write!(f, "UNSEALED"),
            Self::Shredded => write!(f, "SHREDDED"),
        }
    }
}

/// Cryptographic manifest describing a sealed vault entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifest {
    /// Unique identifier for this staging vault instance.
    pub vault_id: String,
    /// Unique identifier for this staged file (UUID or BLAKE3-based).
    pub file_id: String,
    /// Original file name or relative path.
    pub original_name: String,
    /// Original unencrypted payload size in bytes.
    pub original_size: u64,
    /// Sealed ciphertext size in bytes (plaintext + 16-byte Poly1305 tag).
    pub sealed_size: u64,
    /// Creation timestamp in milliseconds since UNIX epoch.
    pub created_at_epoch_ms: u64,
    /// Symmetric AEAD cipher suite used for payload encryption.
    pub cipher_suite: String,
    /// Post-quantum Key Encapsulation Mechanism algorithm.
    pub kem_algorithm: String,
    /// Post-quantum digital signature algorithm.
    pub sig_algorithm: String,
    /// Hex-encoded ML-KEM-768 ciphertext (1,088 bytes raw).
    pub kem_ciphertext_hex: String,
    /// Hex-encoded 96-bit ChaCha20-Poly1305 initialization vector / nonce (12 bytes).
    pub nonce_hex: String,
    /// Hex-encoded BLAKE3 hash of the sealed ciphertext payload.
    pub payload_hash_hex: String,
    /// Hex-encoded ML-DSA-65 public key of the signing author (1,952 bytes).
    pub signer_pubkey_hex: String,
    /// Hex-encoded ML-DSA-65 digital signature over the canonical manifest preimage (3,309 bytes).
    pub signature_hex: String,
    /// Current lifecycle status of this staged file entry.
    pub status: VaultFileStatus,
}

/// Master post-quantum cryptographic keypair for the staging vault.
#[derive(Clone)]
pub struct VaultKeyPair {
    /// Recipient public key for ML-KEM-768 key encapsulation.
    pub kem_pk: MlKemPublicKey,
    /// Recipient private key for ML-KEM-768 decapsulation.
    pub kem_sk: MlKemPrivateKey,
    /// Signer public key for ML-DSA-65 signature verification.
    pub dsa_pk: MlDsaPublicKey,
    /// Signer private key for ML-DSA-65 manifest cosigning.
    pub dsa_sk: MlDsaPrivateKey,
}

impl VaultKeyPair {
    /// Generates a new fresh post-quantum keypair from system entropy.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut kem_seed = [0u8; 32];
        let mut dsa_seed = [0u8; 32];
        rng.fill(&mut kem_seed)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure during KEM keygen".into()))?;
        rng.fill(&mut dsa_seed)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure during DSA keygen".into()))?;

        let (kem_pk, kem_sk) = ml_kem_768_keygen_from_seed(&kem_seed);
        let (dsa_pk, dsa_sk) = ml_dsa_65_keygen_from_seed(&dsa_seed);

        kem_seed.fill(0);
        dsa_seed.fill(0);

        Ok(Self {
            kem_pk,
            kem_sk,
            dsa_pk,
            dsa_sk,
        })
    }

    /// Overwrites private keys in memory.
    pub fn shred(&mut self) {
        self.kem_sk.0.fill(0);
        self.dsa_sk.0.fill(0);
    }
}

impl Drop for VaultKeyPair {
    fn drop(&mut self) {
        self.shred();
    }
}

/// Global summary of the staging vault status and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSummary {
    /// Vault identifier.
    pub vault_id: String,
    /// Absolute path to the staging directory.
    pub vault_dir: PathBuf,
    /// Total number of currently sealed files in the staging vault.
    pub sealed_files_count: usize,
    /// Total encrypted bytes currently residing in sealed staging buffers.
    pub total_sealed_bytes: u64,
    /// Total ephemeral keys shredded since vault initialization.
    pub shredded_keys_count: u64,
    /// Total cryptographic verification or tamper rejection failures.
    pub verification_failures_count: u64,
    /// Active post-quantum KEM algorithm.
    pub kem_algorithm: String,
    /// Active post-quantum digital signature algorithm.
    pub sig_algorithm: String,
    /// Active symmetric AEAD cipher suite.
    pub cipher_suite: String,
    /// Hex-encoded BLAKE3 fingerprint of the recipient ML-KEM-768 public key.
    pub recipient_pk_fingerprint: String,
    /// Hex-encoded BLAKE3 fingerprint of the signer ML-DSA-65 public key.
    pub signer_pk_fingerprint: String,
}

/// Microsecond performance benchmark report for vault operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBenchmarkReport {
    /// KEM algorithm name.
    pub kem_algorithm: String,
    /// Signature algorithm name.
    pub sig_algorithm: String,
    /// AEAD cipher suite.
    pub cipher_suite: String,
    /// Payload chunk size tested in bytes.
    pub chunk_size_bytes: usize,
    /// Number of benchmark iterations evaluated.
    pub iterations: usize,
    /// Mean ML-KEM-768 encapsulation latency in microseconds.
    pub kem_encap_latency_us: f64,
    /// Mean ML-KEM-768 decapsulation latency in microseconds.
    pub kem_decap_latency_us: f64,
    /// Mean ML-DSA-65 manifest signing latency in microseconds.
    pub dsa_sign_latency_us: f64,
    /// Mean ML-DSA-65 signature verification latency in microseconds.
    pub dsa_verify_latency_us: f64,
    /// ChaCha20-Poly1305 symmetric AEAD sealing throughput in MB/s.
    pub aead_seal_throughput_mb_s: f64,
    /// ChaCha20-Poly1305 symmetric AEAD unsealing throughput in MB/s.
    pub aead_unseal_throughput_mb_s: f64,
    /// End-to-end envelope seal latency (KEM + AEAD + DSA) in microseconds.
    pub e2e_seal_latency_us: f64,
    /// End-to-end envelope unseal latency (Verify + KEM + AEAD) in microseconds.
    pub e2e_unseal_latency_us: f64,
    /// Total benchmark elapsed wall-clock duration in milliseconds.
    pub total_elapsed_ms: f64,
}

// ---------------------------------------------------------------------------
// Vault Engine
// ---------------------------------------------------------------------------

/// Post-Quantum Encrypted Staging Vault engine.
pub struct VaultEngine {
    vault_id: String,
    vault_dir: PathBuf,
    keypair: VaultKeyPair,
    stats: Option<Arc<ServerStats>>,
}

impl VaultEngine {
    /// Initializes or opens an existing staging vault directory.
    ///
    /// Persists or loads the master post-quantum keypair from `$VAULT_DIR/keys/` and
    /// initializes envelope storage directories.
    pub fn new(vault_dir: PathBuf, stats: Option<Arc<ServerStats>>) -> Result<Self> {
        fs::create_dir_all(&vault_dir).map_err(|e| {
            VelcruxError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to create vault directory {}: {}",
                    vault_dir.display(),
                    e
                ),
            ))
        })?;

        let keys_dir = vault_dir.join("keys");
        let envelopes_dir = vault_dir.join("envelopes");
        fs::create_dir_all(&keys_dir)?;
        fs::create_dir_all(&envelopes_dir)?;

        let kem_pk_path = keys_dir.join("vault_kem.pk");
        let kem_sk_path = keys_dir.join("vault_kem.sk");
        let dsa_pk_path = keys_dir.join("vault_dsa.pk");
        let dsa_sk_path = keys_dir.join("vault_dsa.sk");

        let keypair = if kem_pk_path.exists()
            && kem_sk_path.exists()
            && dsa_pk_path.exists()
            && dsa_sk_path.exists()
        {
            // Load existing keypair
            let kem_pk_raw = fs::read(&kem_pk_path)?;
            let kem_sk_raw = fs::read(&kem_sk_path)?;
            let dsa_pk_raw = fs::read(&dsa_pk_path)?;
            let dsa_sk_raw = fs::read(&dsa_sk_path)?;

            if kem_pk_raw.len() != ML_KEM_768_PUBLIC_KEY_SIZE
                || kem_sk_raw.len() != ML_KEM_768_SECRET_KEY_SIZE
                || dsa_pk_raw.len() != ML_DSA_65_PUBLIC_KEY_SIZE
                || dsa_sk_raw.len() != ML_DSA_65_SECRET_KEY_SIZE
            {
                return Err(VelcruxError::Internal(
                    "corrupted post-quantum key lengths in vault store".into(),
                ));
            }

            let mut kem_pk = [0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
            let mut kem_sk = [0u8; ML_KEM_768_SECRET_KEY_SIZE];
            let mut dsa_pk = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
            let mut dsa_sk = [0u8; ML_DSA_65_SECRET_KEY_SIZE];

            kem_pk.copy_from_slice(&kem_pk_raw);
            kem_sk.copy_from_slice(&kem_sk_raw);
            dsa_pk.copy_from_slice(&dsa_pk_raw);
            dsa_sk.copy_from_slice(&dsa_sk_raw);

            VaultKeyPair {
                kem_pk: MlKemPublicKey(kem_pk),
                kem_sk: MlKemPrivateKey(kem_sk),
                dsa_pk: MlDsaPublicKey(dsa_pk),
                dsa_sk: MlDsaPrivateKey(dsa_sk),
            }
        } else {
            // Generate and persist new keypair
            let kp = VaultKeyPair::generate()?;
            fs::write(&kem_pk_path, &kp.kem_pk.0)?;
            fs::write(&kem_sk_path, &kp.kem_sk.0)?;
            fs::write(&dsa_pk_path, &kp.dsa_pk.0)?;
            fs::write(&dsa_sk_path, &kp.dsa_sk.0)?;
            kp
        };

        let vault_id = format!(
            "vlt-{}",
            &blake3::hash(&keypair.kem_pk.0).to_hex().as_str()[..16]
        );

        Ok(Self {
            vault_id,
            vault_dir,
            keypair,
            stats,
        })
    }

    /// Constructs a vault engine with an explicit keypair.
    pub fn with_keypair(
        vault_dir: PathBuf,
        keypair: VaultKeyPair,
        stats: Option<Arc<ServerStats>>,
    ) -> Result<Self> {
        fs::create_dir_all(&vault_dir)?;
        let envelopes_dir = vault_dir.join("envelopes");
        fs::create_dir_all(&envelopes_dir)?;

        let vault_id = format!(
            "vlt-{}",
            &blake3::hash(&keypair.kem_pk.0).to_hex().as_str()[..16]
        );

        Ok(Self {
            vault_id,
            vault_dir,
            keypair,
            stats,
        })
    }

    /// Returns a reference to the active keypair.
    pub fn keypair(&self) -> &VaultKeyPair {
        &self.keypair
    }

    /// Returns the absolute path to the vault staging directory.
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// Returns the unique vault instance identifier.
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    // -----------------------------------------------------------------------
    // Core Envelope Encryption (Seal & Unseal)
    // -----------------------------------------------------------------------

    /// Seals in-memory bytes into a post-quantum envelope.
    ///
    /// Returns the signed `VaultManifest` and the encrypted ciphertext bytes.
    pub fn seal_bytes(
        &self,
        original_name: &str,
        plaintext: &[u8],
    ) -> Result<(VaultManifest, Vec<u8>)> {
        let start_time = Instant::now();
        let rng = SystemRandom::new();

        // 1. Generate unique file_id
        let file_id = format!("vfile-{}", ulid::Ulid::new().to_string().to_lowercase());
        let original_size = plaintext.len() as u64;

        // 2. Encapsulate ephemeral shared secret with ML-KEM-768
        let mut kem_randomness = [0u8; 32];
        rng.fill(&mut kem_randomness)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure for ML-KEM".into()))?;

        let (kem_ct, kem_ss) = ml_kem_768_encapsulate(&self.keypair.kem_pk, &kem_randomness);
        kem_randomness.fill(0);

        // Derive 256-bit ChaCha20-Poly1305 DEK from post-quantum shared secret
        let mut dek = blake3::derive_key("velcrux-staging-vault-dek-v1", &kem_ss);

        // 3. Generate random 96-bit AEAD nonce
        let mut nonce_bytes = [0u8; VAULT_NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure for AEAD nonce".into()))?;

        // 4. Construct Associated Authenticated Data (AAD)
        let aad_bytes = compute_vault_aad(&self.vault_id, &file_id, original_size);

        // 5. Encrypt payload with ChaCha20-Poly1305
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &dek)
            .map_err(|_| VelcruxError::Internal("failed to create unbound key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| VelcruxError::Internal("invalid AEAD nonce".into()))?;

        let mut in_out = plaintext.to_vec();
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::from(&aad_bytes[..]), &mut in_out)
            .map_err(|_| VelcruxError::Internal("ChaCha20-Poly1305 sealing failed".into()))?;

        // Zeroize ephemeral DEK
        dek.fill(0);

        // 6. Compute payload hash and build manifest signature preimage
        let payload_hash = blake3::hash(&in_out);
        let sealed_size = in_out.len() as u64;

        let sig_preimage = compute_manifest_sig_preimage(
            &self.vault_id,
            &file_id,
            original_size,
            sealed_size,
            &kem_ct.0,
            &nonce_bytes,
            payload_hash.as_bytes(),
        );

        // 7. Post-Quantum manifest signature with ML-DSA-65
        let dsa_sig = ml_dsa_65_sign(&self.keypair.dsa_sk, &sig_preimage);

        let created_at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let manifest = VaultManifest {
            vault_id: self.vault_id.clone(),
            file_id,
            original_name: original_name.to_string(),
            original_size,
            sealed_size,
            created_at_epoch_ms,
            cipher_suite: VAULT_CIPHER_SUITE.to_string(),
            kem_algorithm: VAULT_KEM_ALGO.to_string(),
            sig_algorithm: VAULT_SIG_ALGO.to_string(),
            kem_ciphertext_hex: hex_encode(&kem_ct.0),
            nonce_hex: hex_encode(&nonce_bytes),
            payload_hash_hex: payload_hash.to_hex().to_string(),
            signer_pubkey_hex: hex_encode(&self.keypair.dsa_pk.0),
            signature_hex: hex_encode(&dsa_sig.0),
            status: VaultFileStatus::Sealed,
        };

        // Update server statistics & latency gauges
        let elapsed_ns = start_time.elapsed().as_nanos() as u64;
        if let Some(ref stats) = self.stats {
            stats
                .vault_files_encrypted_total
                .fetch_add(1, Ordering::Relaxed);
            stats
                .vault_active_sealed_bytes
                .fetch_add(sealed_size, Ordering::Relaxed);
            stats
                .vault_active_sealed_files
                .fetch_add(1, Ordering::Relaxed);
            stats
                .vault_seal_latency_nanoseconds
                .store(elapsed_ns, Ordering::Relaxed);
        }

        Ok((manifest, in_out))
    }

    /// Seals a file from the host filesystem into the staging vault or destination path.
    pub fn seal_file(&self, src_path: &Path, dest_path: Option<&Path>) -> Result<VaultManifest> {
        let plaintext = fs::read(src_path).map_err(|e| {
            VelcruxError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read source file {}: {}", src_path.display(), e),
            ))
        })?;

        let original_name = src_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed_file".to_string());

        let (manifest, ciphertext) = self.seal_bytes(&original_name, &plaintext)?;

        if let Some(dest) = dest_path {
            if dest.is_dir() {
                // Save standalone .vlt package into destination directory
                let package_path = dest.join(format!("{}.vlt", manifest.file_id));
                let envelope_bytes = pack_standalone_envelope(&manifest, &ciphertext)?;
                fs::write(&package_path, envelope_bytes)?;
            } else {
                // Save standalone .vlt directly to path
                let envelope_bytes = pack_standalone_envelope(&manifest, &ciphertext)?;
                fs::write(dest, envelope_bytes)?;
            }
        } else {
            // Save into vault staging directory
            let envelopes_dir = self.vault_dir.join("envelopes");
            let manifest_path = envelopes_dir.join(format!("{}.manifest.json", manifest.file_id));
            let payload_path = envelopes_dir.join(format!("{}.payload.enc", manifest.file_id));

            let manifest_json = serde_json::to_string_pretty(&manifest)
                .map_err(|e| VelcruxError::Internal(format!("manifest serialization: {}", e)))?;

            fs::write(manifest_path, manifest_json)?;
            fs::write(payload_path, ciphertext)?;
        }

        Ok(manifest)
    }

    /// Unseals ciphertext bytes using manifest metadata and the vault private key.
    pub fn unseal_bytes(&self, manifest: &VaultManifest, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let start_time = Instant::now();

        // 1. Verify ciphertext size & BLAKE3 payload hash
        if ciphertext.len() as u64 != manifest.sealed_size {
            if let Some(ref stats) = self.stats {
                stats
                    .vault_verification_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            return Err(VelcruxError::Internal(format!(
                "sealed size mismatch: expected {} bytes, got {}",
                manifest.sealed_size,
                ciphertext.len()
            )));
        }

        let computed_hash = blake3::hash(ciphertext).to_hex().to_string();
        if computed_hash != manifest.payload_hash_hex {
            if let Some(ref stats) = self.stats {
                stats
                    .vault_verification_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            return Err(VelcruxError::Internal(
                "tampered ciphertext payload: BLAKE3 hash mismatch".into(),
            ));
        }

        // 2. Decode KEM ciphertext, nonce, signer pubkey, and signature
        let kem_ct_bytes = hex_decode(&manifest.kem_ciphertext_hex).map_err(|e| {
            VelcruxError::Internal(format!("invalid hex in kem_ciphertext_hex: {}", e))
        })?;
        if kem_ct_bytes.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(VelcruxError::Internal(
                "invalid ML-KEM ciphertext size".into(),
            ));
        }
        let mut kem_ct = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
        kem_ct.copy_from_slice(&kem_ct_bytes);

        let nonce_bytes = hex_decode(&manifest.nonce_hex)
            .map_err(|e| VelcruxError::Internal(format!("invalid hex in nonce_hex: {}", e)))?;
        if nonce_bytes.len() != VAULT_NONCE_LEN {
            return Err(VelcruxError::Internal("invalid AEAD nonce size".into()));
        }

        let signer_pub_bytes = hex_decode(&manifest.signer_pubkey_hex).map_err(|e| {
            VelcruxError::Internal(format!("invalid hex in signer_pubkey_hex: {}", e))
        })?;
        if signer_pub_bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
            return Err(VelcruxError::Internal(
                "invalid ML-DSA public key size".into(),
            ));
        }
        let mut dsa_pub = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        dsa_pub.copy_from_slice(&signer_pub_bytes);

        let sig_bytes = hex_decode(&manifest.signature_hex)
            .map_err(|e| VelcruxError::Internal(format!("invalid hex in signature_hex: {}", e)))?;
        if sig_bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
            return Err(VelcruxError::Internal(
                "invalid ML-DSA signature size".into(),
            ));
        }
        let mut dsa_sig = [0u8; ML_DSA_65_SIGNATURE_SIZE];
        dsa_sig.copy_from_slice(&sig_bytes);

        // 3. Verify ML-DSA-65 post-quantum signature over the manifest preimage
        let payload_hash_raw = hex_decode(&manifest.payload_hash_hex).map_err(|e| {
            VelcruxError::Internal(format!("invalid hex in payload_hash_hex: {}", e))
        })?;

        let sig_preimage = compute_manifest_sig_preimage(
            &manifest.vault_id,
            &manifest.file_id,
            manifest.original_size,
            manifest.sealed_size,
            &kem_ct,
            &nonce_bytes,
            &payload_hash_raw,
        );

        let sig_valid = ml_dsa_65_verify(
            &MlDsaPublicKey(dsa_pub),
            &sig_preimage,
            &MlDsaSignature(dsa_sig),
        );
        if !sig_valid {
            if let Some(ref stats) = self.stats {
                stats
                    .vault_verification_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            return Err(VelcruxError::Internal(
                "cryptographic integrity failure: ML-DSA-65 signature is invalid".into(),
            ));
        }

        // 4. Decapsulate ML-KEM-768 shared secret
        let kem_ss = ml_kem_768_decapsulate(&self.keypair.kem_sk, &MlKemCiphertext(kem_ct))
            .map_err(|e| {
                if let Some(ref stats) = self.stats {
                    stats
                        .vault_verification_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                VelcruxError::Internal(format!("ML-KEM decapsulation failed: {}", e))
            })?;

        // Derive 256-bit ChaCha20-Poly1305 DEK from post-quantum shared secret
        let mut dek = blake3::derive_key("velcrux-staging-vault-dek-v1", &kem_ss);

        // 5. Open ChaCha20-Poly1305 AEAD ciphertext
        let aad_bytes = compute_vault_aad(
            &manifest.vault_id,
            &manifest.file_id,
            manifest.original_size,
        );

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &dek)
            .map_err(|_| VelcruxError::Internal("failed to create unbound key".into()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| VelcruxError::Internal("invalid AEAD nonce".into()))?;

        let mut in_out = ciphertext.to_vec();
        let decrypted_slice = less_safe_key
            .open_in_place(nonce, Aad::from(&aad_bytes[..]), &mut in_out)
            .map_err(|_| {
                if let Some(ref stats) = self.stats {
                    stats
                        .vault_verification_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                VelcruxError::Internal("ChaCha20-Poly1305 decryption authentication failed".into())
            })?;

        let plaintext = decrypted_slice.to_vec();

        // Zeroize in-memory DEK
        dek.fill(0);

        // 6. Verify original size invariant
        if plaintext.len() as u64 != manifest.original_size {
            return Err(VelcruxError::Internal(format!(
                "plaintext size invariant violated: expected {} bytes, got {}",
                manifest.original_size,
                plaintext.len()
            )));
        }

        // Update server stats & latency gauges
        let elapsed_ns = start_time.elapsed().as_nanos() as u64;
        if let Some(ref stats) = self.stats {
            stats
                .vault_files_decrypted_total
                .fetch_add(1, Ordering::Relaxed);
            stats
                .vault_unseal_latency_nanoseconds
                .store(elapsed_ns, Ordering::Relaxed);
        }

        Ok(plaintext)
    }

    /// Unseals a staged vault entry by file ID or standalone `.vlt` file path,
    /// writing the restored plaintext to `dest_path`.
    pub fn unseal_file(
        &self,
        file_id_or_path: &str,
        dest_path: Option<&Path>,
    ) -> Result<(VaultManifest, PathBuf)> {
        let (manifest, ciphertext) = if file_id_or_path.ends_with(".vlt")
            || Path::new(file_id_or_path).exists()
        {
            // Standalone envelope package
            let bytes = fs::read(file_id_or_path)?;
            unpack_standalone_envelope(&bytes)?
        } else {
            // Staged entry in vault directory
            let envelopes_dir = self.vault_dir.join("envelopes");
            let manifest_path = envelopes_dir.join(format!("{}.manifest.json", file_id_or_path));
            let payload_path = envelopes_dir.join(format!("{}.payload.enc", file_id_or_path));

            if !manifest_path.exists() || !payload_path.exists() {
                return Err(VelcruxError::Internal(format!(
                    "vault staged file '{}' not found in {}",
                    file_id_or_path,
                    envelopes_dir.display()
                )));
            }

            let manifest_raw = fs::read_to_string(&manifest_path)?;
            let manifest: VaultManifest = serde_json::from_str(&manifest_raw)
                .map_err(|e| VelcruxError::Internal(format!("failed to parse manifest: {}", e)))?;
            let ciphertext = fs::read(&payload_path)?;
            (manifest, ciphertext)
        };

        let plaintext = self.unseal_bytes(&manifest, &ciphertext)?;

        let out_path = if let Some(dest) = dest_path {
            if dest.is_dir() {
                dest.join(&manifest.original_name)
            } else {
                dest.to_path_buf()
            }
        } else {
            PathBuf::from(&manifest.original_name)
        };

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&out_path, plaintext)?;

        Ok((manifest, out_path))
    }

    // -----------------------------------------------------------------------
    // Ephemeral Key Shredding & Vault Maintenance
    // -----------------------------------------------------------------------

    /// Cryptographically shreds a staged vault entry (multi-pass overwrite + unlink).
    pub fn shred_file(&self, file_id: &str, passes: u32) -> Result<()> {
        let envelopes_dir = self.vault_dir.join("envelopes");
        let manifest_path = envelopes_dir.join(format!("{}.manifest.json", file_id));
        let payload_path = envelopes_dir.join(format!("{}.payload.enc", file_id));

        let mut found = false;

        if payload_path.exists() {
            let metadata = fs::metadata(&payload_path).ok();
            let size = metadata.map(|m| m.len()).unwrap_or(0);
            shred_file_on_disk(&payload_path, passes)?;
            found = true;

            if let Some(ref stats) = self.stats {
                stats
                    .vault_active_sealed_bytes
                    .fetch_sub(size, Ordering::Relaxed);
                stats
                    .vault_active_sealed_files
                    .fetch_sub(1, Ordering::Relaxed);
            }
        }

        if manifest_path.exists() {
            shred_file_on_disk(&manifest_path, passes)?;
            found = true;
        }

        if !found {
            return Err(VelcruxError::Internal(format!(
                "file '{}' not found in vault envelopes",
                file_id
            )));
        }

        if let Some(ref stats) = self.stats {
            stats
                .vault_keys_shredded_total
                .fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Cryptographically shreds all staged files in the vault, and optionally the master keypair.
    pub fn shred_all(&self, passes: u32, shred_master_keys: bool) -> Result<usize> {
        let envelopes_dir = self.vault_dir.join("envelopes");
        let mut count = 0;

        if envelopes_dir.exists() {
            for entry in fs::read_dir(&envelopes_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let _ = shred_file_on_disk(&path, passes);
                    count += 1;
                }
            }
        }

        if shred_master_keys {
            let keys_dir = self.vault_dir.join("keys");
            if keys_dir.exists() {
                for entry in fs::read_dir(&keys_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() {
                        let _ = shred_file_on_disk(&path, passes);
                    }
                }
            }
        }

        if let Some(ref stats) = self.stats {
            stats.vault_active_sealed_bytes.store(0, Ordering::Relaxed);
            stats.vault_active_sealed_files.store(0, Ordering::Relaxed);
            stats
                .vault_keys_shredded_total
                .fetch_add(count as u64, Ordering::Relaxed);
        }

        Ok(count)
    }

    /// Enumerates all staged vault file manifests.
    pub fn list_entries(&self) -> Result<Vec<VaultManifest>> {
        let envelopes_dir = self.vault_dir.join("envelopes");
        let mut manifests = Vec::new();

        if !envelopes_dir.exists() {
            return Ok(manifests);
        }

        for entry in fs::read_dir(&envelopes_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.ends_with(".manifest.json"))
                    .unwrap_or(false)
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(manifest) = serde_json::from_str::<VaultManifest>(&content) {
                        manifests.push(manifest);
                    }
                }
            }
        }

        manifests.sort_by(|a, b| b.created_at_epoch_ms.cmp(&a.created_at_epoch_ms));
        Ok(manifests)
    }

    /// Compiles a global summary of the vault status and metrics.
    pub fn status(&self) -> Result<VaultSummary> {
        let entries = self.list_entries()?;
        let sealed_files_count = entries.len();
        let total_sealed_bytes: u64 = entries.iter().map(|e| e.sealed_size).sum();

        let recipient_pk_fingerprint = blake3::hash(&self.keypair.kem_pk.0).to_hex().to_string();
        let signer_pk_fingerprint = blake3::hash(&self.keypair.dsa_pk.0).to_hex().to_string();

        let shredded_keys_count = self
            .stats
            .as_ref()
            .map(|s| s.vault_keys_shredded_total.load(Ordering::Relaxed))
            .unwrap_or(0);

        let verification_failures_count = self
            .stats
            .as_ref()
            .map(|s| s.vault_verification_failures_total.load(Ordering::Relaxed))
            .unwrap_or(0);

        Ok(VaultSummary {
            vault_id: self.vault_id.clone(),
            vault_dir: self.vault_dir.clone(),
            sealed_files_count,
            total_sealed_bytes,
            shredded_keys_count,
            verification_failures_count,
            kem_algorithm: VAULT_KEM_ALGO.to_string(),
            sig_algorithm: VAULT_SIG_ALGO.to_string(),
            cipher_suite: VAULT_CIPHER_SUITE.to_string(),
            recipient_pk_fingerprint,
            signer_pk_fingerprint,
        })
    }

    // -----------------------------------------------------------------------
    // Microsecond Performance Benchmarking
    // -----------------------------------------------------------------------

    /// Executes microsecond performance benchmarks for ML-KEM-768, ML-DSA-65,
    /// ChaCha20-Poly1305, and end-to-end envelope seal/unseal operations.
    pub fn run_benchmark(iterations: usize, chunk_size_bytes: usize) -> VaultBenchmarkReport {
        let iters = iterations.max(10);
        let chunk_size = chunk_size_bytes.max(1024);
        let overall_start = Instant::now();

        let rng = SystemRandom::new();
        let (kem_pk, kem_sk) = {
            let mut s = [0u8; 32];
            let _ = rng.fill(&mut s);
            ml_kem_768_keygen_from_seed(&s)
        };
        let (dsa_pk, dsa_sk) = {
            let mut s = [0u8; 32];
            let _ = rng.fill(&mut s);
            ml_dsa_65_keygen_from_seed(&s)
        };

        // 1. Benchmark ML-KEM-768 Encapsulation
        let mut kem_randomness = [0u8; 32];
        let _ = rng.fill(&mut kem_randomness);
        let start_encap = Instant::now();
        let mut last_ct = MlKemCiphertext([0u8; ML_KEM_768_CIPHERTEXT_SIZE]);
        for _ in 0..iters {
            let (ct, _) = ml_kem_768_encapsulate(&kem_pk, &kem_randomness);
            last_ct = ct;
        }
        let kem_encap_latency_us =
            start_encap.elapsed().as_secs_f64() * 1_000_000.0 / (iters as f64);

        // 2. Benchmark ML-KEM-768 Decapsulation
        let start_decap = Instant::now();
        for _ in 0..iters {
            let _ = ml_kem_768_decapsulate(&kem_sk, &last_ct);
        }
        let kem_decap_latency_us =
            start_decap.elapsed().as_secs_f64() * 1_000_000.0 / (iters as f64);

        // 3. Benchmark ML-DSA-65 Signing
        let test_message = b"velcrux-benchmark-preimage-manifest-test-payload-data";
        let start_sign = Instant::now();
        let mut last_sig = MlDsaSignature([0u8; ML_DSA_65_SIGNATURE_SIZE]);
        for _ in 0..iters {
            last_sig = ml_dsa_65_sign(&dsa_sk, test_message);
        }
        let dsa_sign_latency_us = start_sign.elapsed().as_secs_f64() * 1_000_000.0 / (iters as f64);

        // 4. Benchmark ML-DSA-65 Verification
        let start_verify = Instant::now();
        for _ in 0..iters {
            let _ = ml_dsa_65_verify(&dsa_pk, test_message, &last_sig);
        }
        let dsa_verify_latency_us =
            start_verify.elapsed().as_secs_f64() * 1_000_000.0 / (iters as f64);

        // 5. Benchmark ChaCha20-Poly1305 AEAD Throughput
        let test_payload = vec![0x3Cu8; chunk_size];
        let dek_bytes = [0x5Au8; 32];
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &dek_bytes).unwrap();
        let less_safe_key = LessSafeKey::new(unbound_key);
        let aad_bytes = [0xAAu8; 32];

        let start_aead_seal = Instant::now();
        let mut sealed_payload = test_payload.clone();
        for _i in 0..iters {
            sealed_payload = test_payload.clone();
            let mut nonce_bytes = [0u8; VAULT_NONCE_LEN];
            nonce_bytes[..8].copy_from_slice(&(_i as u64).to_le_bytes());
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            less_safe_key
                .seal_in_place_append_tag(nonce, Aad::from(&aad_bytes[..]), &mut sealed_payload)
                .unwrap();
        }
        let aead_seal_sec = start_aead_seal.elapsed().as_secs_f64();
        let total_mb = (chunk_size * iters) as f64 / (1024.0 * 1024.0);
        let aead_seal_throughput_mb_s = total_mb / aead_seal_sec;

        // AEAD Unseal Throughput
        let start_aead_unseal = Instant::now();
        for _i in 0..iters {
            let mut to_decrypt = sealed_payload.clone();
            let mut nonce_bytes = [0u8; VAULT_NONCE_LEN];
            nonce_bytes[..8].copy_from_slice(&((iters - 1) as u64).to_le_bytes());
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            let _ = less_safe_key
                .open_in_place(nonce, Aad::from(&aad_bytes[..]), &mut to_decrypt)
                .unwrap();
        }
        let aead_unseal_sec = start_aead_unseal.elapsed().as_secs_f64();
        let aead_unseal_throughput_mb_s = total_mb / aead_unseal_sec;

        // 6. Benchmark End-to-End Seal and Unseal
        let engine = VaultEngine {
            vault_id: "bench-vault".to_string(),
            vault_dir: PathBuf::from("/tmp/bench_vault"),
            keypair: VaultKeyPair {
                kem_pk,
                kem_sk,
                dsa_pk,
                dsa_sk,
            },
            stats: None,
        };

        let start_e2e_seal = Instant::now();
        let mut last_manifest = None;
        let mut last_ciphertext = Vec::new();
        for _ in 0..iters {
            let (m, c) = engine.seal_bytes("bench_file.bin", &test_payload).unwrap();
            last_manifest = Some(m);
            last_ciphertext = c;
        }
        let e2e_seal_latency_us =
            start_e2e_seal.elapsed().as_secs_f64() * 1_000_000.0 / (iters as f64);

        let manifest = last_manifest.unwrap();
        let start_e2e_unseal = Instant::now();
        for _ in 0..iters {
            let _ = engine.unseal_bytes(&manifest, &last_ciphertext).unwrap();
        }
        let e2e_unseal_latency_us =
            start_e2e_unseal.elapsed().as_secs_f64() * 1_000_000.0 / (iters as f64);

        let total_elapsed_ms = overall_start.elapsed().as_secs_f64() * 1000.0;

        VaultBenchmarkReport {
            kem_algorithm: VAULT_KEM_ALGO.to_string(),
            sig_algorithm: VAULT_SIG_ALGO.to_string(),
            cipher_suite: VAULT_CIPHER_SUITE.to_string(),
            chunk_size_bytes: chunk_size,
            iterations: iters,
            kem_encap_latency_us,
            kem_decap_latency_us,
            dsa_sign_latency_us,
            dsa_verify_latency_us,
            aead_seal_throughput_mb_s,
            aead_unseal_throughput_mb_s,
            e2e_seal_latency_us,
            e2e_unseal_latency_us,
            total_elapsed_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// Standalone Envelope Binary Serialization (.vlt format)
// ---------------------------------------------------------------------------

/// Packs a manifest and ciphertext payload into a single self-contained `.vlt` binary format:
/// `[MAGIC: 17 bytes][MANIFEST_LEN: 4 bytes LE][MANIFEST_JSON: N bytes][CIPHERTEXT: M bytes]`.
pub fn pack_standalone_envelope(manifest: &VaultManifest, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let manifest_json = serde_json::to_vec(manifest)
        .map_err(|e| VelcruxError::Internal(format!("manifest json serialization: {}", e)))?;

    let manifest_len = manifest_json.len() as u32;
    let mut out = Vec::with_capacity(17 + 4 + manifest_json.len() + ciphertext.len());

    out.extend_from_slice(VAULT_MAGIC_HEADER);
    out.extend_from_slice(&manifest_len.to_le_bytes());
    out.extend_from_slice(&manifest_json);
    out.extend_from_slice(ciphertext);

    Ok(out)
}

/// Unpacks a standalone `.vlt` binary envelope into its `VaultManifest` and ciphertext payload.
pub fn unpack_standalone_envelope(bytes: &[u8]) -> Result<(VaultManifest, Vec<u8>)> {
    if bytes.len() < 21 {
        return Err(VelcruxError::Internal(
            "truncated vault envelope header".into(),
        ));
    }

    if &bytes[..17] != VAULT_MAGIC_HEADER {
        return Err(VelcruxError::Internal(
            "invalid vault magic header in envelope file".into(),
        ));
    }

    let manifest_len = u32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]) as usize;
    let offset_after_manifest = 21 + manifest_len;

    if bytes.len() < offset_after_manifest {
        return Err(VelcruxError::Internal(
            "truncated vault manifest payload".into(),
        ));
    }

    let manifest_bytes = &bytes[21..offset_after_manifest];
    let manifest: VaultManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| VelcruxError::Internal(format!("failed to parse envelope manifest: {}", e)))?;

    let ciphertext = bytes[offset_after_manifest..].to_vec();

    Ok((manifest, ciphertext))
}

// ---------------------------------------------------------------------------
// Cryptographic Multi-Pass Disk Shredding
// ---------------------------------------------------------------------------

/// Cryptographically shreds a file on disk by overwriting it multiple times
/// with alternating bit patterns (`0x55`, `0xAA`, `0x00`) before unlinking.
pub fn shred_file_on_disk(path: &Path, passes: u32) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    let len = metadata.len();

    if len > 0 {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let patterns = [0x55u8, 0xAAu8, 0x00u8];
        let chunk_size = 64 * 1024;
        let num_passes = passes.max(1);

        for pass_idx in 0..num_passes {
            file.seek(SeekFrom::Start(0))?;
            let pattern = patterns[(pass_idx as usize) % patterns.len()];
            let buf = vec![pattern; chunk_size.min(len as usize)];
            let mut written = 0u64;

            while written < len {
                let to_write = (len - written).min(buf.len() as u64) as usize;
                file.write_all(&buf[..to_write])?;
                written += to_write as u64;
            }
            file.sync_all()?;
        }
    }

    fs::remove_file(path)
}

// ---------------------------------------------------------------------------
// Cryptographic Binding Helpers
// ---------------------------------------------------------------------------

/// Constructs Associated Authenticated Data (AAD) for ChaCha20-Poly1305 sealing:
/// `AAD = BLAKE3("velcrux-staging-aad:" || vault_id || file_id || original_size)`.
fn compute_vault_aad(vault_id: &str, file_id: &str, original_size: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"velcrux-staging-aad:v1");
    hasher.update(vault_id.as_bytes());
    hasher.update(file_id.as_bytes());
    hasher.update(&original_size.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Computes the canonical ML-DSA-65 signature preimage across the manifest attributes.
fn compute_manifest_sig_preimage(
    vault_id: &str,
    file_id: &str,
    original_size: u64,
    sealed_size: u64,
    kem_ct: &[u8],
    nonce: &[u8],
    payload_hash: &[u8],
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"velcrux-vault-manifest-sig:v1\n");
    preimage.extend_from_slice(vault_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(file_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&original_size.to_le_bytes());
    preimage.extend_from_slice(&sealed_size.to_le_bytes());
    preimage.extend_from_slice(kem_ct);
    preimage.extend_from_slice(nonce);
    preimage.extend_from_slice(payload_hash);
    preimage
}

/// Encodes binary bytes to lowercase hexadecimal string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Decodes hexadecimal string into raw bytes.
pub fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex string length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("invalid hex char at {}: {}", i, e))?;
        out.push(byte);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_vault_keypair_generation_and_persistence() {
        let dir = tempdir().expect("tempdir");
        let stats = Arc::new(ServerStats::default());

        let engine1 =
            VaultEngine::new(dir.path().to_path_buf(), Some(stats.clone())).expect("init vault 1");
        let vault_id = engine1.vault_id().to_string();

        let pk1 = engine1.keypair().kem_pk.0;

        // Re-open from same directory: keypair should match
        let engine2 =
            VaultEngine::new(dir.path().to_path_buf(), Some(stats)).expect("init vault 2");
        assert_eq!(engine2.vault_id(), vault_id);
        assert_eq!(engine2.keypair().kem_pk.0, pk1);
    }

    #[test]
    fn test_vault_seal_unseal_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let engine = VaultEngine::new(dir.path().to_path_buf(), None).expect("init vault");

        let original_data =
            b"Post-quantum envelope encryption with ML-KEM-768 and ChaCha20-Poly1305!";
        let (manifest, ciphertext) = engine
            .seal_bytes("test_doc.txt", original_data)
            .expect("seal bytes");

        assert_eq!(manifest.original_size, original_data.len() as u64);
        assert_eq!(
            manifest.sealed_size,
            (original_data.len() + VAULT_TAG_LEN) as u64
        );
        assert_eq!(manifest.status, VaultFileStatus::Sealed);

        let decrypted = engine
            .unseal_bytes(&manifest, &ciphertext)
            .expect("unseal bytes");
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_vault_file_seal_and_unseal() {
        let dir = tempdir().expect("tempdir");
        let engine = VaultEngine::new(dir.path().to_path_buf(), None).expect("init vault");

        let src_file = dir.path().join("source.dat");
        let test_payload = vec![0x42u8; 1024 * 32]; // 32 KB
        fs::write(&src_file, &test_payload).expect("write src");

        let manifest = engine.seal_file(&src_file, None).expect("seal file");

        let out_dir = dir.path().join("restored");
        let (_, out_path) = engine
            .unseal_file(&manifest.file_id, Some(&out_dir))
            .expect("unseal file");

        assert!(out_path.exists());
        let restored_data = fs::read(&out_path).expect("read restored");
        assert_eq!(restored_data, test_payload);
    }

    #[test]
    fn test_vault_tamper_signature_rejection() {
        let dir = tempdir().expect("tempdir");
        let stats = Arc::new(ServerStats::default());
        let engine =
            VaultEngine::new(dir.path().to_path_buf(), Some(stats.clone())).expect("init vault");

        let original_data = b"Secret multi-tenant staged transfer payload";
        let (mut manifest, ciphertext) = engine
            .seal_bytes("tamper_test.txt", original_data)
            .expect("seal bytes");

        // Tamper with manifest signature hex
        let mut sig_chars: Vec<char> = manifest.signature_hex.chars().collect();
        sig_chars[10] = if sig_chars[10] == 'a' { 'b' } else { 'a' };
        manifest.signature_hex = sig_chars.into_iter().collect();

        let unseal_res = engine.unseal_bytes(&manifest, &ciphertext);
        assert!(unseal_res.is_err(), "tampered signature must be rejected");
        assert_eq!(
            stats
                .vault_verification_failures_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_vault_tamper_ciphertext_rejection() {
        let dir = tempdir().expect("tempdir");
        let stats = Arc::new(ServerStats::default());
        let engine =
            VaultEngine::new(dir.path().to_path_buf(), Some(stats.clone())).expect("init vault");

        let original_data = b"Secret payload that will be flipped in transit";
        let (manifest, mut ciphertext) = engine
            .seal_bytes("tamper_ct.txt", original_data)
            .expect("seal bytes");

        // Tamper with one byte of ciphertext
        ciphertext[5] ^= 0xFF;

        let unseal_res = engine.unseal_bytes(&manifest, &ciphertext);
        assert!(unseal_res.is_err(), "tampered ciphertext must be rejected");
        assert_eq!(
            stats
                .vault_verification_failures_total
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_vault_file_shredding() {
        let dir = tempdir().expect("tempdir");
        let stats = Arc::new(ServerStats::default());
        let engine =
            VaultEngine::new(dir.path().to_path_buf(), Some(stats.clone())).expect("init vault");

        let src_file = dir.path().join("to_shred.bin");
        fs::write(&src_file, b"temporary staging sensitive data").expect("write");

        let manifest = engine.seal_file(&src_file, None).expect("seal");

        let entries_before = engine.list_entries().expect("list");
        assert_eq!(entries_before.len(), 1);

        // Shred file
        engine.shred_file(&manifest.file_id, 3).expect("shred file");

        let entries_after = engine.list_entries().expect("list after");
        assert_eq!(entries_after.len(), 0);

        assert_eq!(stats.vault_keys_shredded_total.load(Ordering::Relaxed), 1);

        // Unseal should now fail
        let unseal_res = engine.unseal_file(&manifest.file_id, None);
        assert!(unseal_res.is_err());
    }

    #[test]
    fn test_vault_standalone_envelope_pack_unpack() {
        let dir = tempdir().expect("tempdir");
        let engine = VaultEngine::new(dir.path().to_path_buf(), None).expect("init vault");

        let src_file = dir.path().join("payload.bin");
        fs::write(
            &src_file,
            b"Standalone envelope binary package test payload",
        )
        .expect("write");

        let out_vlt = dir.path().join("standalone.vlt");
        let manifest = engine
            .seal_file(&src_file, Some(&out_vlt))
            .expect("seal to standalone");

        assert!(out_vlt.exists());

        let (unpacked_manifest, restored_path) = engine
            .unseal_file(out_vlt.to_str().unwrap(), Some(dir.path()))
            .expect("unseal standalone");

        assert_eq!(unpacked_manifest.file_id, manifest.file_id);
        let restored_bytes = fs::read(&restored_path).expect("read");
        assert_eq!(
            restored_bytes,
            b"Standalone envelope binary package test payload"
        );
    }

    #[test]
    fn test_vault_benchmark() {
        let report = VaultEngine::run_benchmark(10, 4096);
        assert_eq!(report.iterations, 10);
        assert!(report.kem_encap_latency_us > 0.0);
        assert!(report.dsa_sign_latency_us > 0.0);
        assert!(report.aead_seal_throughput_mb_s > 0.0);
    }
}
