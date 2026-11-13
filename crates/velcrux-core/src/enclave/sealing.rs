//! Hardware Enclave Data Sealing & Secret Protection Engine.
//!
//! Provides cryptographic sealing derived from hardware chip keys and enclave measurements
//! (MRENCLAVE or MRSIGNER policies), ensuring persisted secrets can only be unsealed
//! by authorized, un-tampered enclaves.

#![forbid(unsafe_code)]

use super::types::EnclaveMeasurement;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};

/// Policy governing the derivation of hardware sealing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SealingPolicy {
    /// Sealing key derived from MRENCLAVE (exact enclave binary measurement).
    /// Only the identical binary code instance can unseal the payload.
    MrEnclave,
    /// Sealing key derived from MRSIGNER (author signing authority & product ID).
    /// Enclaves signed by the same author key can unseal the payload across upgrades.
    MrSigner,
}

impl SealingPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MrEnclave => "MRENCLAVE",
            Self::MrSigner => "MRSIGNER",
        }
    }
}

/// Sealed payload envelope storing ciphertext, nonce, and authenticated measurement metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnclavePayload {
    pub policy: SealingPolicy,
    pub measurement_digest: Vec<u8>,
    #[serde(with = "hex_12")]
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    #[serde(with = "hex_32")]
    pub auth_tag: [u8; 32],
}

/// Hardware Enclave Sealing Engine.
#[derive(Debug, Clone)]
pub struct EnclaveSealingEngine {
    chip_id: [u8; 32],
}

impl EnclaveSealingEngine {
    pub fn new(chip_id: [u8; 32]) -> Self {
        Self { chip_id }
    }

    /// Derives the 256-bit symmetric sealing key based on chosen policy and measurement.
    pub fn derive_sealing_key(
        &self,
        policy: SealingPolicy,
        measurement: &EnclaveMeasurement,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("velcrux-enclave-sealing-key:v1");
        hasher.update(&self.chip_id);
        hasher.update(policy.as_str().as_bytes());

        match policy {
            SealingPolicy::MrEnclave => {
                if let Some(ref mr_e) = measurement.mr_enclave {
                    hasher.update(mr_e);
                } else {
                    hasher.update(&measurement.launch_digest);
                }
            }
            SealingPolicy::MrSigner => {
                if let Some(ref mr_s) = measurement.mr_signer {
                    hasher.update(mr_s);
                } else {
                    hasher.update(&measurement.launch_digest);
                }
                hasher.update(&measurement.isv_prod_id.to_be_bytes());
            }
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(hasher.finalize().as_bytes());
        key
    }

    /// Seals plaintext data under the specified policy, measurement, and additional authenticated data (AAD).
    pub fn seal(
        &self,
        plaintext: &[u8],
        policy: SealingPolicy,
        measurement: &EnclaveMeasurement,
        aad: &[u8],
    ) -> SealedEnclavePayload {
        let key = self.derive_sealing_key(policy, measurement);

        // Generate pseudorandom 96-bit nonce
        let mut nonce = [0u8; 12];
        let mut nonce_hasher = blake3::Hasher::new();
        nonce_hasher.update(b"velcrux-sealing-nonce:v1:");
        nonce_hasher.update(&self.chip_id);
        nonce_hasher.update(&(plaintext.len() as u64).to_be_bytes());
        nonce_hasher.update(aad);
        nonce.copy_from_slice(&nonce_hasher.finalize().as_bytes()[0..12]);

        // Keystream generation using BLAKE3 XOF
        let mut cipher_hasher = blake3::Hasher::new_keyed(&key);
        cipher_hasher.update(&nonce);
        cipher_hasher.update(b"payload-keystream");
        let mut xof = cipher_hasher.finalize_xof();

        let mut keystream = vec![0u8; plaintext.len()];
        xof.fill(&mut keystream);

        let mut ciphertext = vec![0u8; plaintext.len()];
        for i in 0..plaintext.len() {
            ciphertext[i] = plaintext[i] ^ keystream[i];
        }

        // Authenticated Tag generation
        let mut mac_hasher = blake3::Hasher::new_keyed(&key);
        mac_hasher.update(&nonce);
        mac_hasher.update(&(aad.len() as u64).to_be_bytes());
        mac_hasher.update(aad);
        mac_hasher.update(&(ciphertext.len() as u64).to_be_bytes());
        mac_hasher.update(&ciphertext);
        let mut auth_tag = [0u8; 32];
        auth_tag.copy_from_slice(mac_hasher.finalize().as_bytes());

        let measurement_digest = match policy {
            SealingPolicy::MrEnclave => measurement
                .mr_enclave
                .map(|e| e.to_vec())
                .unwrap_or_else(|| measurement.launch_digest.clone()),
            SealingPolicy::MrSigner => measurement
                .mr_signer
                .map(|s| s.to_vec())
                .unwrap_or_else(|| measurement.launch_digest.clone()),
        };

        SealedEnclavePayload {
            policy,
            measurement_digest,
            nonce,
            ciphertext,
            auth_tag,
        }
    }

    /// Unseals a sealed payload, verifying authentication tag and measurement policy.
    pub fn unseal(
        &self,
        sealed: &SealedEnclavePayload,
        measurement: &EnclaveMeasurement,
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.derive_sealing_key(sealed.policy, measurement);

        // Verify measurement matching
        let expected_digest = match sealed.policy {
            SealingPolicy::MrEnclave => measurement
                .mr_enclave
                .map(|e| e.to_vec())
                .unwrap_or_else(|| measurement.launch_digest.clone()),
            SealingPolicy::MrSigner => measurement
                .mr_signer
                .map(|s| s.to_vec())
                .unwrap_or_else(|| measurement.launch_digest.clone()),
        };

        if sealed.measurement_digest != expected_digest {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "sealing measurement mismatch; enclave binary is unauthorized to unseal this payload",
            )));
        }

        // Verify MAC tag
        let mut mac_hasher = blake3::Hasher::new_keyed(&key);
        mac_hasher.update(&sealed.nonce);
        mac_hasher.update(&(aad.len() as u64).to_be_bytes());
        mac_hasher.update(aad);
        mac_hasher.update(&(sealed.ciphertext.len() as u64).to_be_bytes());
        mac_hasher.update(&sealed.ciphertext);
        let expected_tag = mac_hasher.finalize();

        let mut diff = 0u8;
        for (a, b) in sealed.auth_tag.iter().zip(expected_tag.as_bytes().iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "sealing authentication tag verification failed; corrupted or forged ciphertext",
            )));
        }

        // Decrypt ciphertext
        let mut cipher_hasher = blake3::Hasher::new_keyed(&key);
        cipher_hasher.update(&sealed.nonce);
        cipher_hasher.update(b"payload-keystream");
        let mut xof = cipher_hasher.finalize_xof();

        let mut keystream = vec![0u8; sealed.ciphertext.len()];
        xof.fill(&mut keystream);

        let mut plaintext = vec![0u8; sealed.ciphertext.len()];
        for i in 0..sealed.ciphertext.len() {
            plaintext[i] = sealed.ciphertext[i] ^ keystream[i];
        }

        Ok(plaintext)
    }
}

mod hex_12 {
    use super::super::types::{hex_decode, hex_encode};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 12], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
        if vec.len() != 12 {
            return Err(serde::de::Error::custom(format!(
                "expected 12 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 12];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

mod hex_32 {
    use super::super::types::{hex_decode, hex_encode};
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
        let vec = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                vec.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sealing_and_unsealing_roundtrip() {
        let chip_id = [0x77u8; 32];
        let engine = EnclaveSealingEngine::new(chip_id);
        let measurement = EnclaveMeasurement::simulated("velcrux-kms-service");

        let secret = b"super-sensitive-cluster-master-encryption-key-0123456789";
        let aad = b"tenant-finance-aad-context";

        let sealed = engine.seal(secret, SealingPolicy::MrEnclave, &measurement, aad);
        assert_ne!(sealed.ciphertext, secret);

        let unsealed = engine
            .unseal(&sealed, &measurement, aad)
            .expect("unseal success");
        assert_eq!(unsealed, secret);
    }

    #[test]
    fn test_sealing_unauthorized_measurement_rejected() {
        let chip_id = [0x77u8; 32];
        let engine = EnclaveSealingEngine::new(chip_id);
        let measurement_valid = EnclaveMeasurement::simulated("velcrux-kms-service");
        let measurement_attacker = EnclaveMeasurement::simulated("malicious-injected-binary");

        let secret = b"confidential-data";
        let sealed = engine.seal(secret, SealingPolicy::MrEnclave, &measurement_valid, b"");

        let res = engine.unseal(&sealed, &measurement_attacker, b"");
        assert!(res.is_err());
    }
}
