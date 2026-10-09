//! Cryptographic engines and envelope encryption.
//!
//! (`PROTOCOL.md` §3, §4; `REQUIREMENTS.md` §37, §65; `SECURITY.md` §2, §3, §8).

pub mod chunk_aead;

pub use chunk_aead::{
    build_chunk_aad, derive_key_from_passphrase, derive_transfer_key, ChunkDecryptor,
    ChunkEncryptor, CipherSuite, CryptoError, TransferKey, ENVELOPE_OVERHEAD, NONCE_LEN, TAG_LEN,
};
