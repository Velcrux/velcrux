//! Cryptographic engines and envelope encryption.
//!
//! (`PROTOCOL.md` §3, §4; `REQUIREMENTS.md` §37, §65; `SECURITY.md` §2, §3, §8).

pub mod chunk_aead;
pub mod pqc;

pub use chunk_aead::{
    build_chunk_aad, derive_key_from_passphrase, derive_transfer_key, ChunkDecryptor,
    ChunkEncryptor, CipherSuite, CryptoError, TransferKey, ENVELOPE_OVERHEAD, NONCE_LEN, TAG_LEN,
};
pub use pqc::{
    ml_dsa_65_keygen_from_seed, ml_dsa_65_sign, ml_dsa_65_verify, ml_kem_768_decapsulate,
    ml_kem_768_encapsulate, ml_kem_768_keygen_from_seed, run_pqc_benchmark, HybridCiphertext,
    HybridKemEngine, HybridKemKeyPair, HybridKemPrivateKey, HybridKemPublicKey, HybridSharedSecret,
    HybridSignature, HybridSignatureEngine, HybridSigningPrivateKey, HybridSigningPublicKey,
    MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature, MlKemCiphertext, MlKemPrivateKey,
    MlKemPublicKey, PqcAlgorithm, PqcBenchmarkReport, PqcStatusReport,
};
