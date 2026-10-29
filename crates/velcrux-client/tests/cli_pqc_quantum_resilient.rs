//! Integration tests for Option CD: Quantum-Resilient Post-Quantum
//! Hybrid Cryptography (ML-KEM-768 & ML-DSA-65) (`ADR-046`).

#![forbid(unsafe_code)]

use std::process::Command;
use tempfile::tempdir;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_pqc_status_text_and_json() {
    // 1. Human-readable text output
    let output = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("status")
        .output()
        .expect("execute pqc status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Quantum-Resilient Post-Quantum Hybrid Cryptography ==="));
    assert!(stdout.contains("KEM Algorithm:          Hybrid X25519 + ML-KEM-768"));
    assert!(stdout.contains("Signature Algorithm:    Hybrid Ed25519 + ML-DSA-65"));
    assert!(stdout.contains("Post-Quantum KEM:       ML-KEM-768 (FIPS 203 / Kyber768)"));
    assert!(stdout.contains("Post-Quantum Signature: ML-DSA-65 (FIPS 204 / Dilithium3)"));
    assert!(stdout.contains("NIST Security Level:    Level 3"));
    assert!(stdout.contains("Dual Security Enforced: true"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute pqc status json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).expect("parse status json");
    assert_eq!(v["kem_algorithm"], "Hybrid X25519 + ML-KEM-768");
    assert_eq!(v["signature_algorithm"], "Hybrid Ed25519 + ML-DSA-65");
    assert_eq!(v["quantum_security_level"], 3);
    assert_eq!(v["hybrid_dual_security_enforced"], true);
}

#[test]
fn test_cli_pqc_keygen_and_out_dir() {
    let tmp = tempdir().expect("create tempdir");
    let out_dir = tmp.path().join("keys");

    let output = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("keygen")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--json")
        .output()
        .expect("execute pqc keygen");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse keygen json");
    assert_eq!(v["mode"], "hybrid");
    assert!(!v["kem_public_key_hex"].as_str().unwrap().is_empty());
    assert!(!v["kem_private_key_hex"].as_str().unwrap().is_empty());
    assert!(!v["sig_public_key_hex"].as_str().unwrap().is_empty());
    assert!(!v["sig_private_key_hex"].as_str().unwrap().is_empty());

    // Verify key files written to out_dir
    assert!(out_dir.join("pqc_kem.pub").exists());
    assert!(out_dir.join("pqc_kem.key").exists());
    assert!(out_dir.join("pqc_sig.pub").exists());
    assert!(out_dir.join("pqc_sig.key").exists());

    let kem_pub_file = std::fs::read_to_string(out_dir.join("pqc_kem.pub")).unwrap();
    assert_eq!(
        kem_pub_file.trim(),
        v["kem_public_key_hex"].as_str().unwrap()
    );
}

#[test]
fn test_cli_pqc_encap_and_decap() {
    // 1. Generate keypair
    let keygen_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("keygen")
        .arg("--json")
        .output()
        .expect("keygen");

    assert!(keygen_out.status.success());
    let keys: serde_json::Value = serde_json::from_slice(&keygen_out.stdout).unwrap();
    let kem_pk_hex = keys["kem_public_key_hex"].as_str().unwrap();
    let kem_sk_hex = keys["kem_private_key_hex"].as_str().unwrap();

    // 2. Encapsulate
    let encap_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("encap")
        .arg(kem_pk_hex)
        .arg("--json")
        .output()
        .expect("encap");

    assert!(
        encap_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&encap_out.stderr)
    );

    let encap_val: serde_json::Value = serde_json::from_slice(&encap_out.stdout).unwrap();
    let ct_hex = encap_val["ciphertext_hex"].as_str().unwrap();
    let ss_encap_hex = encap_val["shared_secret_hex"].as_str().unwrap();
    assert_eq!(ss_encap_hex.len(), 64); // 32 bytes hex = 64 characters

    // 3. Decapsulate
    let decap_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("decap")
        .arg(kem_sk_hex)
        .arg(ct_hex)
        .arg("--json")
        .output()
        .expect("decap");

    assert!(
        decap_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&decap_out.stderr)
    );

    let decap_val: serde_json::Value = serde_json::from_slice(&decap_out.stdout).unwrap();
    let ss_decap_hex = decap_val["shared_secret_hex"].as_str().unwrap();

    // Both shared secrets must match exactly
    assert_eq!(ss_encap_hex, ss_decap_hex);
}

#[test]
fn test_cli_pqc_sign_and_verify() {
    let tmp = tempdir().expect("create tempdir");
    let payload_file = tmp.path().join("payload.dat");
    std::fs::write(
        &payload_file,
        b"velcrux-mission-critical-bulk-transfer-data",
    )
    .unwrap();

    // 1. Generate keypair
    let keygen_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("keygen")
        .arg("--json")
        .output()
        .expect("keygen");

    assert!(keygen_out.status.success());
    let keys: serde_json::Value = serde_json::from_slice(&keygen_out.stdout).unwrap();
    let sig_pk_hex = keys["sig_public_key_hex"].as_str().unwrap();
    let sig_sk_hex = keys["sig_private_key_hex"].as_str().unwrap();

    // 2. Sign file
    let sign_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("sign")
        .arg(&payload_file)
        .arg(sig_sk_hex)
        .arg("--json")
        .output()
        .expect("sign");

    assert!(
        sign_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&sign_out.stderr)
    );

    let sign_val: serde_json::Value = serde_json::from_slice(&sign_out.stdout).unwrap();
    let sig_hex = sign_val["signature_hex"].as_str().unwrap();

    // 3. Verify signature
    let verify_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("verify")
        .arg(&payload_file)
        .arg(sig_pk_hex)
        .arg(sig_hex)
        .arg("--json")
        .output()
        .expect("verify");

    assert!(
        verify_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&verify_out.stderr)
    );

    let verify_val: serde_json::Value = serde_json::from_slice(&verify_out.stdout).unwrap();
    assert_eq!(verify_val["valid"], true);
    assert_eq!(verify_val["ed25519_verified"], true);
    assert_eq!(verify_val["ml_dsa_65_verified"], true);

    // 4. Verify tampering detection: alter payload file
    std::fs::write(&payload_file, b"velcrux-mission-critical-TAMPERED-payload").unwrap();

    let fail_verify_out = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("verify")
        .arg(&payload_file)
        .arg(sig_pk_hex)
        .arg(sig_hex)
        .arg("--json")
        .output()
        .expect("verify tampered");

    assert!(
        !fail_verify_out.status.success(),
        "verification of tampered payload must fail"
    );
}

#[test]
fn test_cli_pqc_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("pqc")
        .arg("benchmark")
        .arg("--iterations")
        .arg("5")
        .arg("--json")
        .output()
        .expect("execute pqc benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse benchmark json");
    assert_eq!(v["iterations"], 5);
    assert_eq!(v["all_operations_verified"], true);
    assert!(v["ml_kem_encaps_latency_us"].as_f64().unwrap() > 0.0);
    assert!(v["ml_dsa_sign_latency_us"].as_f64().unwrap() > 0.0);
    assert!(v["kem_ops_per_second"].as_f64().unwrap() > 0.0);
    assert!(v["sig_ops_per_second"].as_f64().unwrap() > 0.0);
}
