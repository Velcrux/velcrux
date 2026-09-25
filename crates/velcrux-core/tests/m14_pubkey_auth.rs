#![forbid(unsafe_code)]

//! Integration tests for Milestone 14 (Option L):
//! SSH-Style Public-Key Channel-Bound Authentication (`SECURITY.md` §2).

use ring::signature::{self, KeyPair};
use velcrux_core::auth::{
    create_pubkey_auth_token, verify_pubkey_auth_token, Authenticator, AuthorizedKeys,
    HybridAuthenticator, EXPORTER_SECRET_LEN, SSH_PUBKEY_TOKEN_LEN,
};
use velcrux_core::protocol::message::AUTH_MECHANISM_SSH_PUBKEY;
use velcrux_core::transport::Identity;

fn generate_ed25519_keypair() -> signature::Ed25519KeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519");
    signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("parse Ed25519 keypair")
}

#[test]
fn test_authorized_keys_parsing_hex_and_openssh() {
    let kp = generate_ed25519_keypair();
    let pubkey_bytes: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();

    let hex_pubkey = pubkey_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let content = format!(
        "# Authorized Keys for Velcrux\n\
         \n\
         {} dev-backup-agent\n",
        hex_pubkey
    );

    let auth_keys = AuthorizedKeys::parse(&content).expect("parse valid authorized_keys");
    assert_eq!(auth_keys.lookup(&pubkey_bytes), Some("dev-backup-agent"));

    // Unknown key lookup returns None
    let unknown_key = [0x55u8; 32];
    assert_eq!(auth_keys.lookup(&unknown_key), None);
}

#[test]
fn test_channel_bound_signature_verification() {
    let kp = generate_ed25519_keypair();
    let pubkey_bytes: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();

    let mut auth_keys = AuthorizedKeys::new();
    auth_keys.add_key(pubkey_bytes, "operator-alice".to_string());

    let exporter_secret = [0xABu8; EXPORTER_SECRET_LEN];

    // Client creates channel-bound token
    let token = create_pubkey_auth_token(&kp, &exporter_secret);
    assert_eq!(token.len(), SSH_PUBKEY_TOKEN_LEN);

    // Verify token alone
    let verified_pubkey =
        verify_pubkey_auth_token(&token, &exporter_secret).expect("token verifies");
    assert_eq!(verified_pubkey, pubkey_bytes);

    // Authenticate through AuthorizedKeys
    let identity = auth_keys
        .authenticate(&token, &exporter_secret)
        .expect("authenticate succeeds");

    assert_eq!(identity.name, "operator-alice");
    assert_eq!(identity.issuer_fingerprint, "ssh-pubkey");
    assert_eq!(identity.cert_fingerprint.len(), 64);
}

#[test]
fn test_replay_attack_prevention() {
    let kp = generate_ed25519_keypair();
    let pubkey_bytes: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();

    let mut auth_keys = AuthorizedKeys::new();
    auth_keys.add_key(pubkey_bytes, "victim-client".to_string());

    let conn1_secret = [0x11u8; EXPORTER_SECRET_LEN];
    let conn2_secret = [0x22u8; EXPORTER_SECRET_LEN];

    // Legitimate token on Connection 1
    let token_conn1 = create_pubkey_auth_token(&kp, &conn1_secret);

    // Succeeds on Connection 1
    assert!(auth_keys.authenticate(&token_conn1, &conn1_secret).is_ok());

    // Attacker eavesdrops and attempts to replay token_conn1 on Connection 2:
    // MUST FAIL because connection 2 has a different exporter secret (RFC 8446 channel binding)
    let replay_result = auth_keys.authenticate(&token_conn1, &conn2_secret);
    assert!(replay_result.is_err());
}

#[test]
fn test_corrupted_token_and_unauthorized_key() {
    let kp = generate_ed25519_keypair();
    let exporter_secret = [0x33u8; EXPORTER_SECRET_LEN];

    let mut token = create_pubkey_auth_token(&kp, &exporter_secret);

    // 1. Corrupted signature bit
    token[70] ^= 0x01;
    assert!(verify_pubkey_auth_token(&token, &exporter_secret).is_err());

    // 2. Valid signature, but key not authorized in AuthorizedKeys
    let uncorrupted = create_pubkey_auth_token(&kp, &exporter_secret);
    let empty_keys = AuthorizedKeys::new();
    assert!(empty_keys
        .authenticate(&uncorrupted, &exporter_secret)
        .is_err());
}

#[test]
fn test_hybrid_authenticator_dispatch() {
    let kp = generate_ed25519_keypair();
    let pubkey_bytes: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();

    let mut auth_keys = AuthorizedKeys::new();
    auth_keys.add_key(pubkey_bytes, "hybrid-user".to_string());

    let hybrid = HybridAuthenticator::new(Some(auth_keys));

    // 1. mTLS authentication path
    let mtls_id = Identity::new("mtls-user", "test-ca", "cert-fp");
    let verified_mtls = hybrid.authenticate(&mtls_id).expect("mTLS auth");
    assert_eq!(verified_mtls.name, "mtls-user");

    // 2. SSH Pubkey authentication path
    let exporter_secret = [0x55u8; EXPORTER_SECRET_LEN];
    let token = create_pubkey_auth_token(&kp, &exporter_secret);

    let verified_pubkey = hybrid
        .authenticate_token(AUTH_MECHANISM_SSH_PUBKEY, &token, &exporter_secret)
        .expect("SSH pubkey auth");
    assert_eq!(verified_pubkey.name, "hybrid-user");
    assert_eq!(verified_pubkey.issuer_fingerprint, "ssh-pubkey");

    // 3. Unsupported mechanism fails closed
    assert!(hybrid
        .authenticate_token(999, &token, &exporter_secret)
        .is_err());
}
