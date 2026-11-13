//! Cryptographic TLS 1.3 Channel Binding Engine (RFC 9266 / RFC 5929).
//!
//! Cryptographically binds hardware enclave quotes to the active transport connection,
//! preventing untrusted hypervisors or host OS relays from performing Man-In-The-Middle (MITM) attacks.

#![forbid(unsafe_code)]

use crate::error::{ProtocolError, Result, VelcruxError};

/// Context domain for TLS 1.3 channel binding derivation.
const TLS_EXPORTER_CONTEXT_DOMAIN: &[u8] = b"velcrux-tls13-channel-binding-v1:";

/// Generates a 64-byte `REPORTDATA` payload by binding the TLS 1.3 exporter master secret
/// and bidirectional session nonces.
pub fn generate_channel_binding_report_data(
    tls_exporter_secret: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    additional_context: &[u8],
) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TLS_EXPORTER_CONTEXT_DOMAIN);
    hasher.update(tls_exporter_secret);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    hasher.update(&(additional_context.len() as u64).to_be_bytes());
    hasher.update(additional_context);

    // Expand to 64 bytes using XOF (Extended Output Function)
    let mut xof = hasher.finalize_xof();
    let mut report_data = [0u8; 64];
    xof.fill(&mut report_data);
    report_data
}

/// Verifies that an enclave quote's `report_data` matches the derived TLS 1.3 channel binding.
pub fn verify_channel_binding(
    quote_report_data: &[u8; 64],
    tls_exporter_secret: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    additional_context: &[u8],
) -> Result<()> {
    let expected = generate_channel_binding_report_data(
        tls_exporter_secret,
        client_nonce,
        server_nonce,
        additional_context,
    );

    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in quote_report_data.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }

    if diff == 0 {
        Ok(())
    } else {
        Err(VelcruxError::Protocol(ProtocolError::Malformed(
            "enclave quote report_data does not match TLS 1.3 channel binding; possible MITM relay attack",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_binding_derivation_and_verification() {
        let exporter_secret = [0x42u8; 32];
        let client_nonce = [0x11u8; 32];
        let server_nonce = [0x22u8; 32];
        let context = b"session-stream-99";

        let report_data = generate_channel_binding_report_data(
            &exporter_secret,
            &client_nonce,
            &server_nonce,
            context,
        );

        // Verification passes with identical parameters
        let res = verify_channel_binding(
            &report_data,
            &exporter_secret,
            &client_nonce,
            &server_nonce,
            context,
        );
        assert!(res.is_ok());

        // Verification fails if any parameter is tampered with
        let tampered_secret = [0x43u8; 32];
        let res_tampered = verify_channel_binding(
            &report_data,
            &tampered_secret,
            &client_nonce,
            &server_nonce,
            context,
        );
        assert!(res_tampered.is_err());
    }
}
