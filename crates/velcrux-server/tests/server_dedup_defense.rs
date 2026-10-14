//! Server integration tests for Multi-Tenant Deduplication Poisoning Defense & Namespacing
//! (Option BJ, `CLAUDE.md` §4 Open Questions #3 & #4, `SECURITY.md` §8 & §9, `ADR-026`).

#![forbid(unsafe_code)]

use std::str::FromStr;
use tempfile::tempdir;
use velcrux_core::storage::{DedupNamespacePolicy, NamespacedChunkStore};
use velcrux_core::util::Hash;
use velcrux_server::config::ServerConfig;

#[test]
fn test_server_config_dedup_policy_parsing() {
    let toml_data = r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "cert.pem"
private_key = "key.pem"
client_ca = "ca.pem"

[storage]
root = "/tmp"
staging = "/tmp"
chunk_store = "/tmp/chunks"
dedup_policy = "proof-of-ownership"
dedup_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#;

    let cfg: ServerConfig = toml::from_str(toml_data).expect("parse config TOML");
    assert_eq!(
        cfg.storage.dedup_policy.as_deref(),
        Some("proof-of-ownership")
    );
    assert_eq!(
        cfg.storage.dedup_secret.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );

    let parsed_policy =
        DedupNamespacePolicy::from_str(cfg.storage.dedup_policy.as_deref().unwrap())
            .expect("valid policy");
    assert_eq!(parsed_policy, DedupNamespacePolicy::ProofOfOwnership);
}

#[test]
fn test_server_config_invalid_dedup_policy_validation() {
    let toml_data = r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "cert.pem"
private_key = "key.pem"
client_ca = "ca.pem"

[storage]
root = "/tmp"
staging = "/tmp"
dedup_policy = "unsupported-mode"
"#;

    let cfg: ServerConfig = toml::from_str(toml_data).expect("parse config TOML");
    let err = cfg.validate().unwrap_err();
    assert!(
        err.to_string().contains("invalid storage.dedup_policy"),
        "error must mention dedup_policy validation failure: {err}"
    );
}

#[tokio::test]
async fn test_namespaced_chunk_store_isolated_mode() {
    let dir = tempdir().expect("tempdir");
    let store = NamespacedChunkStore::new(dir.path(), DedupNamespacePolicy::Isolated, None)
        .await
        .expect("init store");

    assert_eq!(store.policy(), DedupNamespacePolicy::Isolated);

    let data_a = b"tenant-alpha confidential dataset block";
    let hash_a = Hash::of(data_a);

    // Tenant Alpha stores chunk
    store
        .put_for_tenant("tenant-alpha", &hash_a, data_a)
        .await
        .expect("put tenant-alpha");

    // Tenant Alpha should have it
    assert!(store.contains_for_tenant("tenant-alpha", &hash_a));

    // Tenant Beta must NOT see it (no cross-tenant leakage or existence oracle)
    assert!(!store.contains_for_tenant("tenant-beta", &hash_a));

    // Probes for non-existent chunk in Beta are blocked
    assert_eq!(store.oracle_probes_blocked(), 1);

    // Physical files must be segregated in `<root>/tenants/tenant-alpha/chunks/`
    let tenant_alpha_dir = dir
        .path()
        .join("tenants")
        .join("tenant-alpha")
        .join("chunks");
    assert!(
        tenant_alpha_dir.exists(),
        "tenant alpha chunk directory must exist"
    );
    let tenant_beta_dir = dir
        .path()
        .join("tenants")
        .join("tenant-beta")
        .join("chunks");
    assert!(
        !tenant_beta_dir.exists(),
        "tenant beta chunk directory must not exist yet"
    );
}

#[tokio::test]
async fn test_namespaced_chunk_store_proof_of_ownership_mode() {
    let dir = tempdir().expect("tempdir");
    let secret = [0x42u8; 32];
    let store = NamespacedChunkStore::new(
        dir.path(),
        DedupNamespacePolicy::ProofOfOwnership,
        Some(secret),
    )
    .await
    .expect("init store");

    assert_eq!(store.policy(), DedupNamespacePolicy::ProofOfOwnership);

    let data = b"shared dedup payload verified via proof of ownership";
    let hash = Hash::of(data);

    // Tenant A uploads data
    store
        .put_for_tenant("tenant-a", &hash, data)
        .await
        .expect("put tenant-a");

    // Tenant A is in ACL
    assert!(store.contains_for_tenant("tenant-a", &hash));

    // Tenant B is NOT in ACL yet; cannot see or probe chunk
    assert!(!store.contains_for_tenant("tenant-b", &hash));

    // Tenant B generates valid Proof of Ownership token
    let valid_token = store.pow_engine().compute_token(&hash, data);
    let auth_ok = store.authorize_tenant_with_pow("tenant-b", &hash, &valid_token);
    assert!(auth_ok, "valid PoW token must authorize tenant-b");

    // Now Tenant B is authorized to reuse chunk without re-uploading
    assert!(store.contains_for_tenant("tenant-b", &hash));

    // Invalid PoW token is rejected
    let bad_token = [0x99u8; 32];
    let auth_fail = store.authorize_tenant_with_pow("tenant-c", &hash, &bad_token);
    assert!(!auth_fail, "forged PoW token must be rejected");
    assert!(!store.contains_for_tenant("tenant-c", &hash));
}

#[tokio::test]
async fn test_chunk_quarantine_poisoning_defense() {
    let dir = tempdir().expect("tempdir");
    let store = NamespacedChunkStore::new(dir.path(), DedupNamespacePolicy::Isolated, None)
        .await
        .expect("init store");

    let valid_data = b"clean unpoisoned chunk payload";
    let valid_hash = Hash::of(valid_data);

    store
        .put_for_tenant("tenant-secure", &valid_hash, valid_data)
        .await
        .expect("put clean chunk");

    // Simulate bit-rot or deliberate chunk store poisoning by corrupting the chunk file on disk
    let chunk_path = store
        .get_tenant_store("tenant-secure")
        .await
        .unwrap()
        .chunk_path(&valid_hash);
    assert!(chunk_path.exists());
    std::fs::write(&chunk_path, b"POISONED_CORRUPTED_BYTES")
        .expect("overwrite with corrupted data");

    // Attempting to copy or read the corrupted chunk triggers in-flight BLAKE3 verification
    let mut dest_file = tempfile::tempfile().expect("temp destination file");
    let copy_result = store.copy_chunk_for_tenant("tenant-secure", &valid_hash, &mut dest_file, 0);

    assert!(
        copy_result.is_err(),
        "corrupted chunk must fail verification and return error"
    );

    // Poison attempt metric is incremented
    assert_eq!(store.poison_attempts(), 1);

    // Corrupted chunk was automatically removed from chunk store and quarantined
    assert!(
        !chunk_path.exists(),
        "corrupted chunk file must be removed from live chunk store"
    );

    let quarantined = store.quarantine().list();
    assert_eq!(
        quarantined.len(),
        1,
        "exactly one chunk must be quarantined"
    );
    assert_eq!(quarantined[0].hash, valid_hash);
    assert!(quarantined[0].reason.contains("blake3_checksum_mismatch"));
    assert!(quarantined[0].quarantine_path.exists());
}
