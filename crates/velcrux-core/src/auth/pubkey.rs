#![forbid(unsafe_code)]

//! SSH-Style Public-Key (Ed25519) Channel-Bound Authentication (`SECURITY.md` §2).
//!
//! For deployments without a PKI, an `authorized_keys`-style file maps Ed25519 public
//! keys to identities. The `AUTH` message carries a signature over
//! `"velcrux-auth-v1" || exporter_secret`, where `exporter_secret` is a 32-byte value
//! from the TLS keying material exporter (RFC 8446 §7.5) for this connection.
//!
//! Binding the signature to the TLS exporter channel-binds the proof to this specific
//! connection, preventing replay attacks.

use std::collections::HashMap;
use std::path::Path;

use ring::signature::{self, KeyPair};

use crate::error::{ProtocolError, Result, VelcruxError};
use crate::transport::identity::Identity;

/// Label used with RFC 8446 §7.5 TLS Keying Material Exporter.
pub const AUTH_EXPORTER_LABEL: &[u8] = b"velcrux-auth-v1";

/// Exporter secret size in bytes.
pub const EXPORTER_SECRET_LEN: usize = 32;

/// Prefix prepended to the exporter secret before signing:
/// `payload = b"velcrux-auth-v1" || exporter_secret`
pub const AUTH_SIGNATURE_PREFIX: &[u8] = b"velcrux-auth-v1";

/// Size of an Ed25519 public key in bytes.
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Size of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Total wire token size for `AUTH_MECHANISM_SSH_PUBKEY`:
/// 32 bytes (pubkey) + 64 bytes (signature) = 96 bytes.
pub const SSH_PUBKEY_TOKEN_LEN: usize = ED25519_PUBKEY_LEN + ED25519_SIGNATURE_LEN;

/// Construct the signed payload for channel-bound authentication:
/// `"velcrux-auth-v1" || exporter_secret`
pub fn compute_signed_payload(exporter_secret: &[u8; EXPORTER_SECRET_LEN]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(AUTH_SIGNATURE_PREFIX.len() + EXPORTER_SECRET_LEN);
    payload.extend_from_slice(AUTH_SIGNATURE_PREFIX);
    payload.extend_from_slice(exporter_secret);
    payload
}

/// Create an `AUTH` message token for `AUTH_MECHANISM_SSH_PUBKEY`:
/// signs `"velcrux-auth-v1" || exporter_secret` and packs `[pubkey (32) || signature (64)]`.
pub fn create_pubkey_auth_token(
    keypair: &signature::Ed25519KeyPair,
    exporter_secret: &[u8; EXPORTER_SECRET_LEN],
) -> Vec<u8> {
    let payload = compute_signed_payload(exporter_secret);
    let sig = keypair.sign(&payload);

    let mut token = Vec::with_capacity(SSH_PUBKEY_TOKEN_LEN);
    token.extend_from_slice(keypair.public_key().as_ref());
    token.extend_from_slice(sig.as_ref());
    token
}

/// Verify an `AUTH` token for `AUTH_MECHANISM_SSH_PUBKEY`.
///
/// Returns the verified 32-byte Ed25519 public key on success.
pub fn verify_pubkey_auth_token(
    token: &[u8],
    exporter_secret: &[u8; EXPORTER_SECRET_LEN],
) -> Result<[u8; ED25519_PUBKEY_LEN]> {
    if token.len() != SSH_PUBKEY_TOKEN_LEN {
        return Err(
            ProtocolError::Malformed("AUTH token invalid length for SSH pubkey mechanism").into(),
        );
    }

    let pubkey_bytes: [u8; ED25519_PUBKEY_LEN] = token[..ED25519_PUBKEY_LEN]
        .try_into()
        .map_err(|_| ProtocolError::Malformed("invalid pubkey bytes"))?;
    let sig_bytes = &token[ED25519_PUBKEY_LEN..];

    let payload = compute_signed_payload(exporter_secret);

    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &pubkey_bytes[..]);
    peer_public_key.verify(&payload, sig_bytes).map_err(|_| {
        VelcruxError::Protocol(ProtocolError::InvalidIdentity(
            "channel-bound pubkey signature verification failed",
        ))
    })?;

    Ok(pubkey_bytes)
}

/// Stores authorized public keys and maps them to identity names.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedKeys {
    /// Map of 32-byte Ed25519 public key to identity name.
    keys: HashMap<[u8; ED25519_PUBKEY_LEN], String>,
}

impl AuthorizedKeys {
    /// Create a new empty authorized keys set.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add an authorized Ed25519 public key for an identity.
    pub fn add_key(&mut self, pubkey: [u8; ED25519_PUBKEY_LEN], identity: String) {
        self.keys.insert(pubkey, identity);
    }

    /// Look up the identity name for an Ed25519 public key.
    pub fn lookup(&self, pubkey: &[u8; ED25519_PUBKEY_LEN]) -> Option<&str> {
        self.keys.get(pubkey).map(|s| s.as_str())
    }

    /// Parse an `authorized_keys` file content.
    /// Supports:
    /// 1. `<hex_pubkey> <identity>`
    /// 2. `ssh-ed25519 <base64_pubkey> <identity>`
    pub fn parse(content: &str) -> Result<Self> {
        let mut set = Self::new();
        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                return Err(VelcruxError::Config(format!(
                    "line {}: invalid authorized_keys entry: {}",
                    line_no + 1,
                    trimmed
                )));
            }

            if parts[0] == "ssh-ed25519" {
                // OpenSSH format: ssh-ed25519 <base64> <identity>
                let b64 = parts[1];
                let identity = if parts.len() >= 3 {
                    parts[2..].join(" ")
                } else {
                    format!("key-{}", line_no + 1)
                };

                let raw = decode_base64(b64).map_err(|e| {
                    VelcruxError::Config(format!(
                        "line {}: invalid base64 in ssh-ed25519 key: {e}",
                        line_no + 1
                    ))
                })?;

                // OpenSSH ed25519 wire format:
                // string "ssh-ed25519" (4-byte len prefix 11 + 11 bytes "ssh-ed25519")
                // string key (4-byte len prefix 32 + 32 bytes raw key)
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
                        "line {}: unexpected length {} for ssh-ed25519 key",
                        line_no + 1,
                        raw.len()
                    )));
                };

                set.add_key(pubkey, identity);
            } else {
                // Raw hex format: <hex_pubkey> <identity>
                let hex_str = parts[0];
                let identity = parts[1..].join(" ");
                let raw = decode_hex(hex_str).map_err(|e| {
                    VelcruxError::Config(format!(
                        "line {}: invalid hex in authorized key: {e}",
                        line_no + 1
                    ))
                })?;

                if raw.len() != ED25519_PUBKEY_LEN {
                    return Err(VelcruxError::Config(format!(
                        "line {}: ed25519 pubkey must be 32 bytes (got {})",
                        line_no + 1,
                        raw.len()
                    )));
                }

                let mut k = [0u8; 32];
                k.copy_from_slice(&raw);
                set.add_key(k, identity);
            }
        }
        Ok(set)
    }

    /// Load from a file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| VelcruxError::Config(format!("read authorized_keys: {e}")))?;
        Self::parse(&content)
    }

    /// Authenticate a peer's signed `AUTH` token using the connection's exporter secret.
    pub fn authenticate(
        &self,
        token: &[u8],
        exporter_secret: &[u8; EXPORTER_SECRET_LEN],
    ) -> Result<Identity> {
        let pubkey = verify_pubkey_auth_token(token, exporter_secret)?;
        let name = self.lookup(&pubkey).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::InvalidIdentity(
                "public key not in authorized_keys",
            ))
        })?;

        let hex_fp = encode_hex(&pubkey);
        Ok(Identity::new(
            name.to_string(),
            "ssh-pubkey".to_string(),
            hex_fp,
        ))
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers (pure Rust, `#![forbid(unsafe_code)]`)
// ---------------------------------------------------------------------------

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(VelcruxError::Config("hex string odd length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| VelcruxError::Config(format!("invalid hex: {e}")))?;
        out.push(byte);
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_bound_auth_token_roundtrip() {
        // Generate a random Ed25519 keypair using ring
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes =
            signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate keypair");
        let keypair =
            signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("parse keypair");

        let exporter_secret = [0x42u8; EXPORTER_SECRET_LEN];
        let token = create_pubkey_auth_token(&keypair, &exporter_secret);
        assert_eq!(token.len(), SSH_PUBKEY_TOKEN_LEN);

        // Verify with matching exporter secret
        let verified_pubkey =
            verify_pubkey_auth_token(&token, &exporter_secret).expect("token verification");
        assert_eq!(verified_pubkey, keypair.public_key().as_ref());

        // Verify with mismatched exporter secret (channel mismatch / replay attack)
        let other_secret = [0x99u8; EXPORTER_SECRET_LEN];
        assert!(verify_pubkey_auth_token(&token, &other_secret).is_err());

        // Corrupted token
        let mut corrupted_token = token.clone();
        corrupted_token[50] ^= 0xFF;
        assert!(verify_pubkey_auth_token(&corrupted_token, &exporter_secret).is_err());
    }

    #[test]
    fn test_authorized_keys_parsing_and_authentication() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes =
            signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate keypair");
        let keypair =
            signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("parse keypair");

        let pubkey_bytes: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
        let hex_pubkey = encode_hex(&pubkey_bytes);

        let file_content = format!(
            "# Authorized keys\n\
             {} backup-agent\n",
            hex_pubkey
        );

        let auth_keys = AuthorizedKeys::parse(&file_content).expect("parse authorized keys");
        assert_eq!(auth_keys.lookup(&pubkey_bytes), Some("backup-agent"));

        let exporter_secret = [0x77u8; EXPORTER_SECRET_LEN];
        let token = create_pubkey_auth_token(&keypair, &exporter_secret);

        let identity = auth_keys
            .authenticate(&token, &exporter_secret)
            .expect("authenticate peer");
        assert_eq!(identity.name, "backup-agent");
        assert_eq!(identity.issuer_fingerprint, "ssh-pubkey");
        assert_eq!(identity.cert_fingerprint, hex_pubkey);
    }
}
