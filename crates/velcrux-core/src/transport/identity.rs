//! Peer identity derived from the QUIC/TLS handshake certificate.
//!
//! Per `SECURITY.md` §2:
//!   1. `subjectAltName` of type URI matching `velcrux://identity/<name>`, if
//!      present.
//!   2. Otherwise the Common Name.
//!
//! The `Identity` also carries the SHA-256 of the issuer and the SHA-256 of
//! the leaf certificate, for grant matching and revocation lists. We use
//! SHA-256 for the *fingerprint* (a small, fixed-length identifier) even
//! though chunk and file integrity use BLAKE3 — fingerprints are not file
//! content.

use std::fmt;

/// Peer identity, derived from the mTLS certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    /// `velcrux://identity/<name>` from SAN, or the CN as a fallback.
    pub name: String,
    /// SHA-256 of the issuer certificate, hex-encoded.
    pub issuer_fingerprint: String,
    /// SHA-256 of the leaf certificate, hex-encoded.
    pub cert_fingerprint: String,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Log the name; do not log full fingerprints at info level (they
        // are sensitive enough to identify a key). The DEBUG/Display
        // formats differ.
        f.debug_struct("Identity")
            .field("name", &self.name)
            .field("issuer_fingerprint", &"<redacted>")
            .field("cert_fingerprint", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Identity {
    /// Construct from a name and two pre-computed fingerprints. Used by
    /// the mTLS code path; tests construct directly.
    pub fn new(
        name: impl Into<String>,
        issuer_fingerprint: impl Into<String>,
        cert_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            issuer_fingerprint: issuer_fingerprint.into(),
            cert_fingerprint: cert_fingerprint.into(),
        }
    }
}
