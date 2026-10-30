//! Zero-Trust Decentralized Identity (DID) & Verifiable Credential Attestation Mesh (Option CG, ADR-049).

pub mod did;

pub use did::{
    base58_decode, base58_encode, did_from_ed25519_pubkey, generate_ed25519_keypair, hex_decode,
    parse_ed25519_keypair, resolve_did, CredentialProof, DidAttestationEngine, DidBenchmarkReport,
    DidDocument, DidMethod, TransferCapabilitySubject, VerifiableCredential, VerificationMethod,
    VerificationReport,
};
