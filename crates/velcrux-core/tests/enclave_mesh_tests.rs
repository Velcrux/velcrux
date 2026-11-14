//! Integration test suite for Option DI: Confidential Enclave Attestation & Remote Hardware Root-of-Trust Mesh (`ADR-077`).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use velcrux_core::enclave::{
    generate_channel_binding_report_data, verify_channel_binding, EnclaveAttestationEngine,
    EnclaveAttestationEvidence, EnclaveMeasurement, EnclaveMeshEngine, EnclavePlatform,
    EnclavePolicy, EnclaveSealingEngine, SealingPolicy, TcbVersion,
};

#[test]
fn test_amd_sev_snp_quote_and_channel_binding_verification() {
    let engine = EnclaveAttestationEngine::new(EnclavePlatform::AmdSevSnp);
    let measurement = EnclaveMeasurement::simulated("velcrux-storage-gateway-v2");

    let tls_exporter_secret = [0x5Au8; 32];
    let client_nonce = [0x12u8; 32];
    let server_nonce = [0x34u8; 32];
    let session_context = b"velcrux-quic-stream-100";

    // 1. Enclave binds TLS 1.3 channel to 64-byte REPORTDATA
    let report_data = generate_channel_binding_report_data(
        &tls_exporter_secret,
        &client_nonce,
        &server_nonce,
        session_context,
    );

    let tcb = TcbVersion::production_baseline();
    let quote = engine.generate_quote(measurement, report_data, tcb, false);
    assert_eq!(quote.platform, EnclavePlatform::AmdSevSnp);

    // 2. Verifier checks quote and channel binding
    let policy = EnclavePolicy::default();
    let report = engine
        .verify_quote(&quote, Some(&report_data), &policy)
        .expect("quote verification must pass");

    assert!(report.is_valid);
    assert!(report.channel_binding_verified);
    assert!(report.tcb_compliant);
    assert!(report.non_debug_compliant);
    assert!(report.signature_valid);

    // 3. Verify channel binding function directly
    assert!(verify_channel_binding(
        &quote.report_data,
        &tls_exporter_secret,
        &client_nonce,
        &server_nonce,
        session_context
    )
    .is_ok());

    // 4. Tamper with report_data: must fail immediately
    let mut tampered_report_data = report_data;
    tampered_report_data[0] ^= 0x01;
    let tamper_err = engine.verify_quote(&quote, Some(&tampered_report_data), &policy);
    assert!(tamper_err.is_err());
}

#[test]
fn test_intel_sgx_mrenclave_and_mrsigner_policy_enforcement() {
    let engine = EnclaveAttestationEngine::new(EnclavePlatform::IntelSgx);
    let measurement = EnclaveMeasurement::simulated("velcrux-kms-enclave-v1");
    let report_data = [0x07u8; 64];
    let tcb = TcbVersion::production_baseline();

    let quote = engine.generate_quote(measurement.clone(), report_data, tcb, false);

    // 1. Policy requiring exact MRENCLAVE matches
    let mut strict_policy = EnclavePolicy::default();
    strict_policy.expected_mr_enclave = measurement.mr_enclave.map(|m| m.to_vec());
    let rep = engine.verify_quote(&quote, Some(&report_data), &strict_policy);
    assert!(rep.is_ok());

    // 2. Policy requiring different MRENCLAVE must fail
    let mut wrong_policy = EnclavePolicy::default();
    wrong_policy.expected_mr_enclave = Some(vec![0xFFu8; 32]);
    let err = engine.verify_quote(&quote, Some(&report_data), &wrong_policy);
    assert!(err.is_err());

    // 3. Policy requiring MRSIGNER matches
    let mut signer_policy = EnclavePolicy::default();
    signer_policy.expected_mr_signer = measurement.mr_signer.map(|s| s.to_vec());
    let rep_signer = engine.verify_quote(&quote, Some(&report_data), &signer_policy);
    assert!(rep_signer.is_ok());
}

#[test]
fn test_enclave_data_sealing_under_mrenclave_and_mrsigner() {
    let chip_id = [0xEEu8; 32];
    let sealing_engine = EnclaveSealingEngine::new(chip_id);

    let measurement_v1 = EnclaveMeasurement::simulated("app-binary-v1");
    let secret = b"sensitive-customer-root-encryption-key-42";
    let aad = b"tenant-fintech-scope";

    // 1. MRENCLAVE sealing
    let sealed_mrenclave =
        sealing_engine.seal(secret, SealingPolicy::MrEnclave, &measurement_v1, aad);
    let unsealed_exact = sealing_engine
        .unseal(&sealed_mrenclave, &measurement_v1, aad)
        .expect("unseal success");
    assert_eq!(unsealed_exact, secret);

    // MRENCLAVE unseal fails with upgraded binary
    let measurement_v2 = EnclaveMeasurement::simulated("app-binary-v2-upgraded");
    assert!(sealing_engine
        .unseal(&sealed_mrenclave, &measurement_v2, aad)
        .is_err());

    // 2. MRSIGNER sealing: Same author key can unseal across versions!
    // Construct measurement_v2_same_signer: different launch_digest/mr_enclave, identical mr_signer
    let mut measurement_v2_same_signer = measurement_v2.clone();
    measurement_v2_same_signer.mr_signer = measurement_v1.mr_signer;
    measurement_v2_same_signer.isv_prod_id = measurement_v1.isv_prod_id;

    let sealed_mrsigner =
        sealing_engine.seal(secret, SealingPolicy::MrSigner, &measurement_v1, aad);
    let unsealed_upgraded = sealing_engine
        .unseal(&sealed_mrsigner, &measurement_v2_same_signer, aad)
        .expect("MRSIGNER unseal succeeds on upgraded binary by same author");
    assert_eq!(unsealed_upgraded, secret);
}

#[test]
fn test_mutual_enclave_attestation_mesh_lifecycle() {
    let mut mesh = EnclaveMeshEngine::new("gateway-us-east-1", EnclavePlatform::Simulated);

    let peer1_id = "storage-enclave-node-01";
    let peer1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 100, 1, 10)), 7443);
    let peer2_id = "storage-enclave-node-02";
    let peer2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 100, 1, 11)), 7443);

    let exporter_secret = [0xABu8; 32];
    let client_nonce = [0x01u8; 32];
    let server_nonce = [0x02u8; 32];

    let engine = EnclaveAttestationEngine::new(EnclavePlatform::AmdSevSnp);
    let measurement = EnclaveMeasurement::simulated("velcrux-secure-storage-worker");
    let tcb = TcbVersion::production_baseline();

    // Register Peer 1
    let rd1 = generate_channel_binding_report_data(
        &exporter_secret,
        &client_nonce,
        &server_nonce,
        peer1_id.as_bytes(),
    );
    let q1 = engine.generate_quote(measurement.clone(), rd1, tcb, false);
    let ev1 = EnclaveAttestationEvidence {
        quote: q1,
        client_channel_nonce: client_nonce,
        server_channel_nonce: server_nonce,
        tls_exporter_secret_hash: *blake3::hash(&exporter_secret).as_bytes(),
    };
    mesh.verify_and_register_peer(peer1_id, peer1_addr, &ev1, &exporter_secret)
        .expect("peer 1 registered");

    // Register Peer 2
    let rd2 = generate_channel_binding_report_data(
        &exporter_secret,
        &client_nonce,
        &server_nonce,
        peer2_id.as_bytes(),
    );
    let q2 = engine.generate_quote(measurement, rd2, tcb, false);
    let ev2 = EnclaveAttestationEvidence {
        quote: q2,
        client_channel_nonce: client_nonce,
        server_channel_nonce: server_nonce,
        tls_exporter_secret_hash: *blake3::hash(&exporter_secret).as_bytes(),
    };
    mesh.verify_and_register_peer(peer2_id, peer2_addr, &ev2, &exporter_secret)
        .expect("peer 2 registered");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    assert_eq!(mesh.trusted_peer_count(now), 2);
    assert!(mesh.is_peer_trusted(peer1_id, now));
    assert!(mesh.is_peer_trusted(peer2_id, now));

    // Revoke Peer 1
    assert!(mesh.revoke_peer(peer1_id));
    assert!(!mesh.is_peer_trusted(peer1_id, now));
    assert!(mesh.is_peer_trusted(peer2_id, now));
    assert_eq!(mesh.trusted_peer_count(now), 1);
}

#[test]
fn test_mitm_hypervisor_relay_attack_detection() {
    let engine = EnclaveAttestationEngine::new(EnclavePlatform::AmdSevSnp);
    let measurement = EnclaveMeasurement::simulated("velcrux-enclave-target");
    let tcb = TcbVersion::production_baseline();

    let legitimate_exporter = [0x33u8; 32];
    let client_nonce = [0xAAu8; 32];
    let server_nonce = [0xBBu8; 32];

    // Quote generated for legitimate connection
    let legitimate_rd = generate_channel_binding_report_data(
        &legitimate_exporter,
        &client_nonce,
        &server_nonce,
        b"legitimate-peer",
    );
    let quote = engine.generate_quote(measurement, legitimate_rd, tcb, false);

    // Attacker hypervisor relays quote to an eavesdropped connection with different exporter secret
    let intercepted_exporter = [0x99u8; 32];
    let policy = EnclavePolicy::default();

    // Verifier checks with the intercepted session's parameters
    let expected_rd_intercepted = generate_channel_binding_report_data(
        &intercepted_exporter,
        &client_nonce,
        &server_nonce,
        b"legitimate-peer",
    );

    let verify_res = engine.verify_quote(&quote, Some(&expected_rd_intercepted), &policy);
    assert!(
        verify_res.is_err(),
        "Relayed quote on different TLS session MUST be rejected"
    );
}
