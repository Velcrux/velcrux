#![forbid(unsafe_code)]

//! Integration tests for Quantum Key Distribution (QKD) Optical Fiber & Satellite Entanglement Key Exchange.

use velcrux_core::qkd::{
    Bb84Engine, E91Engine, QkdKey, QkdKeyStatus, QkdKeyStore, QkdProtocolType, QkdReplenisher,
    QuantumChannel, BB84_QBER_ABORT_THRESHOLD, CHSH_CLASSICAL_LIMIT,
};

#[test]
fn test_optical_fiber_attenuation_and_satellite_loss() {
    let fiber_short = QuantumChannel::terrestrial_fiber(10.0);
    assert!((fiber_short.total_loss_db() - 2.0).abs() < 1e-4);
    assert!(fiber_short.channel_transmittance() > 0.60);

    let fiber_long = QuantumChannel::terrestrial_fiber(50.0);
    assert!((fiber_long.total_loss_db() - 10.0).abs() < 1e-4);
    assert!(fiber_long.channel_transmittance() < 0.15);

    let sat_zenith = QuantumChannel::satellite_downlink(500.0, 0.0);
    let sat_slant = QuantumChannel::satellite_downlink(500.0, 60.0);
    assert!(sat_slant.total_loss_db() > sat_zenith.total_loss_db());
}

#[test]
fn test_bb84_decoy_protocol_secure_exchange() {
    let channel = QuantumChannel::terrestrial_fiber(15.0);
    let engine = Bb84Engine::new(channel);

    // Clean exchange without eavesdropper
    let report = engine.execute_exchange(8000, 0.0).expect("bb84 exchange");
    assert!(report.is_secure);
    assert!(!report.eavesdropping_detected);
    assert!(report.qber < BB84_QBER_ABORT_THRESHOLD);
    assert!(report.sifted_bits_count > 0);
    assert_eq!(report.final_key_hex.len(), 64); // 256 bits = 32 bytes = 64 hex chars
    assert!(report.reconciled_bits_count > 0);
}

#[test]
fn test_bb84_decoy_protocol_eavesdropper_abort() {
    let channel = QuantumChannel::terrestrial_fiber(15.0);
    let engine = Bb84Engine::new(channel);

    // 80% eavesdropper presence must trigger Shor-Preskill abort
    let report = engine
        .execute_exchange(8000, 0.8)
        .expect("bb84 intercepted");
    assert!(!report.is_secure);
    assert!(report.eavesdropping_detected);
    assert!(report.qber >= BB84_QBER_ABORT_THRESHOLD);
    assert_eq!(report.final_key_hex.len(), 0);
}

#[test]
fn test_e91_bell_inequality_violation_and_key_distillation() {
    let channel = QuantumChannel::terrestrial_fiber(8.0);
    let engine = E91Engine::new(channel);

    let report = engine.execute_exchange(10000, 0.0).expect("e91 exchange");
    assert!(report.bell_inequality_violated);
    assert!(report.is_entanglement_verified);
    assert!(report.chsh_s_value > CHSH_CLASSICAL_LIMIT);
    assert!(report.chsh_s_value <= 3.5);
    assert_eq!(report.final_key_hex.len(), 64);
}

#[test]
fn test_e91_decoherence_eavesdropper_abort() {
    let channel = QuantumChannel::terrestrial_fiber(8.0);
    let engine = E91Engine::new(channel);

    // 100% decoherence / eavesdropping destroys entanglement
    let report = engine.execute_exchange(4000, 1.0).expect("e91 intercepted");
    assert!(!report.bell_inequality_violated);
    assert!(!report.is_entanglement_verified);
    assert!(report.chsh_s_value <= CHSH_CLASSICAL_LIMIT + 0.1);
    assert_eq!(report.final_key_hex.len(), 0);
}

#[test]
fn test_etsi_014_key_store_lifecycle() {
    let mut store = QkdKeyStore::new("sae-dc1", "sae-dc2");
    let key1 = QkdKey {
        key_id: "qkd-key-001".to_string(),
        key_bytes: vec![0xABu8; 32],
        protocol: QkdProtocolType::Bb84,
        status: QkdKeyStatus::Available,
        created_at_epoch_sec: 1731150000,
        ttl_secs: 86400,
    };
    let key2 = QkdKey {
        key_id: "qkd-key-002".to_string(),
        key_bytes: vec![0xCDu8; 32],
        protocol: QkdProtocolType::E91,
        status: QkdKeyStatus::Available,
        created_at_epoch_sec: 1731150100,
        ttl_secs: 86400,
    };

    store.insert_key(key1);
    store.insert_key(key2);

    assert_eq!(store.available_keys_count(), 2);
    assert_eq!(store.total_keys_generated, 2);

    // Consume key
    let consumed_bytes = store.consume_key("qkd-key-001").expect("consume 1");
    assert_eq!(consumed_bytes, vec![0xABu8; 32]);
    assert_eq!(store.available_keys_count(), 1);
    assert_eq!(store.total_keys_consumed, 1);

    // Attempting to consume consumed key fails
    assert!(store.consume_key("qkd-key-001").is_err());
}

#[test]
fn test_key_replenisher_and_hybrid_pqc_binding() {
    let mut store = QkdKeyStore::new("sae-alpha", "sae-beta");
    let channel = QuantumChannel::terrestrial_fiber(5.0);
    let replenisher = QkdReplenisher::new(3);

    let generated = replenisher
        .replenish(&mut store, &channel, QkdProtocolType::Bb84)
        .expect("replenish");

    assert_eq!(generated, 3);
    assert_eq!(store.available_keys_count(), 3);

    // Verify hybrid KDF derivation binding
    let raw_qkd = vec![0x55u8; 32];
    let kem_shared_secret = vec![0x33u8; 32];
    let hybrid_key = QkdKeyStore::derive_hybrid_session_key(&raw_qkd, &kem_shared_secret);
    assert_eq!(hybrid_key.len(), 32);
    assert_ne!(hybrid_key.to_vec(), raw_qkd);
}
