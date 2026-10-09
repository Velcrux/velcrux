//! Zero-Knowledge Authenticated AEAD Chunk Encryption & Tamper-Proof Storage.
//!
//! (`PROTOCOL.md` §3, §4; `REQUIREMENTS.md` §37, §65; `SECURITY.md` §2, §3, §8).
//!
//! Implements client-side chunk encryption before leaving the host:
//! - Multi-cipher support: ChaCha20-Poly1305 (RFC 8439) and AES-256-GCM (NIST SP 800-38D).
//! - Cryptographic binding via Associated Authenticated Data (AAD):
//!   `AAD = [transfer_id: 16 bytes][chunk_offset: 8 bytes][chunk_index: 4 bytes]`.
//!   Guarantees chunks cannot be swapped, reordered, or spliced across transfers.
//! - Nonce isolation: 96-bit (12-byte) cryptographically secure random nonces per chunk.
//! - Wire overhead: Exactly 28 bytes per chunk (12-byte nonce + 16-byte auth tag).

#![forbid(unsafe_code)]

use std::fmt;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

use crate::util::TransferId;

/// Fixed length of AEAD nonce in bytes (96 bits).
pub const NONCE_LEN: usize = 12;

/// Fixed length of AEAD authentication tag in bytes (128 bits).
pub const TAG_LEN: usize = 16;

/// Total encryption overhead per chunk (nonce + auth tag = 28 bytes).
pub const ENVELOPE_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Cryptographic errors during AEAD sealing or opening.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("cryptographic authentication failed / chunk payload tampered")]
    AuthenticationFailed,
    #[error("truncated ciphertext: expected at least {expected} bytes, got {actual}")]
    TruncatedCiphertext { expected: usize, actual: usize },
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("cryptographic failure: {0}")]
    Unspecified(String),
}

/// Supported authenticated symmetric ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 (RFC 8439). 256-bit key, constant-time software execution.
    ChaCha20Poly1305 = 1,
    /// AES-256-GCM (NIST SP 800-38D). 256-bit key, hardware accelerated where available.
    Aes256Gcm = 2,
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::ChaCha20Poly1305
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

/// A 256-bit cryptographic transfer key.
#[derive(Clone)]
pub struct TransferKey {
    key_bytes: [u8; 32],
}

impl TransferKey {
    /// Create a transfer key from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key_bytes: bytes }
    }

    /// Access the underlying key slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key_bytes
    }
}

impl Drop for TransferKey {
    fn drop(&mut self) {
        // Zeroize memory on drop
        self.key_bytes.fill(0);
    }
}

impl fmt::Debug for TransferKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransferKey([REDACTED])")
    }
}

/// Derive a unique 256-bit transfer key from a master key and TransferId using BLAKE3 KDF.
pub fn derive_transfer_key(master_key: &[u8], transfer_id: &TransferId) -> TransferKey {
    let mut material = Vec::with_capacity(master_key.len() + 16);
    material.extend_from_slice(master_key);
    material.extend_from_slice(transfer_id.as_bytes());

    let derived = blake3::derive_key("velcrux-zero-knowledge-transfer-v1", &material);
    TransferKey::from_bytes(derived)
}

/// Derive a 256-bit master key from a user passphrase and salt using PBKDF2-HMAC-SHA256.
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        salt,
        passphrase.as_bytes(),
        &mut out,
    );
    out
}

/// Constructs the Associated Authenticated Data (AAD) for a chunk.
///
/// Cryptographically binds:
/// - `transfer_id`: 16 bytes
/// - `chunk_offset`: 8 bytes LE
/// - `chunk_index`: 4 bytes LE
/// Total AAD length: 28 bytes.
pub fn build_chunk_aad(transfer_id: &TransferId, chunk_offset: u64, chunk_index: u32) -> [u8; 28] {
    let mut aad = [0u8; 28];
    aad[..16].copy_from_slice(transfer_id.as_bytes());
    aad[16..24].copy_from_slice(&chunk_offset.to_le_bytes());
    aad[24..28].copy_from_slice(&chunk_index.to_le_bytes());
    aad
}

/// Client-side AEAD chunk encryptor.
pub struct ChunkEncryptor {
    suite: CipherSuite,
    key: LessSafeKey,
    rng: SystemRandom,
}

impl ChunkEncryptor {
    /// Construct a new `ChunkEncryptor` for the specified cipher suite and transfer key.
    pub fn new(suite: CipherSuite, key: &TransferKey) -> Result<Self, CryptoError> {
        let algo = match suite {
            CipherSuite::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            CipherSuite::Aes256Gcm => &AES_256_GCM,
        };
        let unbound = UnboundKey::new(algo, key.as_bytes()).map_err(|_| {
            CryptoError::Unspecified("failed to initialize unbound key".to_string())
        })?;
        let less_safe = LessSafeKey::new(unbound);
        Ok(Self {
            suite,
            key: less_safe,
            rng: SystemRandom::new(),
        })
    }

    /// Return the cipher suite configured for this encryptor.
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Encrypt a chunk payload into a self-contained ciphertext envelope:
    /// `[nonce: 12 bytes][ciphertext: N bytes][tag: 16 bytes]`.
    pub fn encrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_offset: u64,
        chunk_index: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::Unspecified("failed to generate random nonce".to_string()))?;

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::Unspecified("invalid nonce bytes for key".to_string()))?;

        let aad_bytes = build_chunk_aad(transfer_id, chunk_offset, chunk_index);
        let aad = Aad::from(&aad_bytes[..]);

        let mut in_out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
        in_out.extend_from_slice(&nonce_bytes);
        in_out.extend_from_slice(plaintext);

        // Seal chunk in place on the plaintext slice and append the tag
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, &mut in_out[NONCE_LEN..])
            .map_err(|_| CryptoError::Unspecified("sealing failed".to_string()))?;

        in_out.extend_from_slice(tag.as_ref());

        Ok(in_out)
    }
}

/// Client or server AEAD chunk decryptor.
pub struct ChunkDecryptor {
    suite: CipherSuite,
    key: LessSafeKey,
}

impl ChunkDecryptor {
    /// Construct a new `ChunkDecryptor` for the specified cipher suite and transfer key.
    pub fn new(suite: CipherSuite, key: &TransferKey) -> Result<Self, CryptoError> {
        let algo = match suite {
            CipherSuite::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            CipherSuite::Aes256Gcm => &AES_256_GCM,
        };
        let unbound = UnboundKey::new(algo, key.as_bytes()).map_err(|_| {
            CryptoError::Unspecified("failed to initialize unbound key".to_string())
        })?;
        let less_safe = LessSafeKey::new(unbound);
        Ok(Self {
            suite,
            key: less_safe,
        })
    }

    /// Return the cipher suite configured for this decryptor.
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Decrypt a chunk envelope, validating the AEAD tag and Associated Authenticated Data (AAD):
    /// Returns the verified plain chunk bytes.
    pub fn decrypt_chunk(
        &self,
        transfer_id: &TransferId,
        chunk_offset: u64,
        chunk_index: u32,
        envelope: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if envelope.len() < ENVELOPE_OVERHEAD {
            return Err(CryptoError::TruncatedCiphertext {
                expected: ENVELOPE_OVERHEAD,
                actual: envelope.len(),
            });
        }

        let nonce_bytes = &envelope[..NONCE_LEN];
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| CryptoError::Unspecified("invalid nonce bytes for key".to_string()))?;

        let aad_bytes = build_chunk_aad(transfer_id, chunk_offset, chunk_index);
        let aad = Aad::from(&aad_bytes[..]);

        let mut in_out = envelope[NONCE_LEN..].to_vec();

        let plain_slice = self
            .key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(plain_slice.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key_bytes = [0x5Au8; 32];
        let key = TransferKey::from_bytes(key_bytes);
        let encryptor = ChunkEncryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();
        let decryptor = ChunkDecryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();

        let transfer_id = TransferId::from_bytes(&[0x11; 16]).unwrap();
        let plaintext = b"Confidential dataset payload transferred across untrusted network";

        let envelope = encryptor
            .encrypt_chunk(&transfer_id, 1024, 1, plaintext)
            .expect("encrypt");

        assert_eq!(envelope.len(), plaintext.len() + ENVELOPE_OVERHEAD);

        let decrypted = decryptor
            .decrypt_chunk(&transfer_id, 1024, 1, &envelope)
            .expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key_bytes = [0x7Eu8; 32];
        let key = TransferKey::from_bytes(key_bytes);
        let encryptor = ChunkEncryptor::new(CipherSuite::Aes256Gcm, &key).unwrap();
        let decryptor = ChunkDecryptor::new(CipherSuite::Aes256Gcm, &key).unwrap();

        let transfer_id = TransferId::from_bytes(&[0x22; 16]).unwrap();
        let plaintext = b"High-throughput enterprise payload with hardware-accelerated AES-GCM";

        let envelope = encryptor
            .encrypt_chunk(&transfer_id, 4096, 4, plaintext)
            .expect("encrypt");

        let decrypted = decryptor
            .decrypt_chunk(&transfer_id, 4096, 4, &envelope)
            .expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tamper_detection_in_ciphertext() {
        let key = TransferKey::from_bytes([0x42u8; 32]);
        let encryptor = ChunkEncryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();
        let decryptor = ChunkDecryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();

        let transfer_id = TransferId::from_bytes(&[0x33; 16]).unwrap();
        let plaintext = b"Tamper-proof payload verified by Poly1305 authentication tag";

        let mut envelope = encryptor
            .encrypt_chunk(&transfer_id, 0, 0, plaintext)
            .expect("encrypt");

        // Flip a single bit in the ciphertext portion
        envelope[NONCE_LEN + 5] ^= 0x01;

        let res = decryptor.decrypt_chunk(&transfer_id, 0, 0, &envelope);
        assert_eq!(res, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_tamper_detection_in_nonce() {
        let key = TransferKey::from_bytes([0x42u8; 32]);
        let encryptor = ChunkEncryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();
        let decryptor = ChunkDecryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();

        let transfer_id = TransferId::from_bytes(&[0x33; 16]).unwrap();
        let plaintext = b"Tamper-proof payload verified by Poly1305 authentication tag";

        let mut envelope = encryptor
            .encrypt_chunk(&transfer_id, 0, 0, plaintext)
            .expect("encrypt");

        // Flip a bit in the nonce
        envelope[0] ^= 0x01;

        let res = decryptor.decrypt_chunk(&transfer_id, 0, 0, &envelope);
        assert_eq!(res, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_tamper_detection_aad_mismatch_rejection() {
        let key = TransferKey::from_bytes([0x42u8; 32]);
        let encryptor = ChunkEncryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();
        let decryptor = ChunkDecryptor::new(CipherSuite::ChaCha20Poly1305, &key).unwrap();

        let transfer_id_a = TransferId::from_bytes(&[0xAA; 16]).unwrap();
        let transfer_id_b = TransferId::from_bytes(&[0xBB; 16]).unwrap();
        let plaintext = b"Bound payload to specific transfer and chunk indices";

        let envelope = encryptor
            .encrypt_chunk(&transfer_id_a, 1000, 5, plaintext)
            .expect("encrypt");

        // 1. Mismatched TransferId
        let res_tx = decryptor.decrypt_chunk(&transfer_id_b, 1000, 5, &envelope);
        assert_eq!(res_tx, Err(CryptoError::AuthenticationFailed));

        // 2. Mismatched Chunk Offset
        let res_off = decryptor.decrypt_chunk(&transfer_id_a, 2000, 5, &envelope);
        assert_eq!(res_off, Err(CryptoError::AuthenticationFailed));

        // 3. Mismatched Chunk Index
        let res_idx = decryptor.decrypt_chunk(&transfer_id_a, 1000, 6, &envelope);
        assert_eq!(res_idx, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_key_derivation_from_passphrase() {
        let passphrase = "correct horse battery staple";
        let salt = b"velcrux-org-salt-1234";

        let key1 = derive_key_from_passphrase(passphrase, salt);
        let key2 = derive_key_from_passphrase(passphrase, salt);
        assert_eq!(key1, key2);

        let key3 = derive_key_from_passphrase("wrong password", salt);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_derive_transfer_key() {
        let master = [0x99u8; 32];
        let id1 = TransferId::from_bytes(&[0x01; 16]).unwrap();
        let id2 = TransferId::from_bytes(&[0x02; 16]).unwrap();

        let k1 = derive_transfer_key(&master, &id1);
        let k2 = derive_transfer_key(&master, &id2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
