//! Integration tests for Option DA: Zero-Knowledge Multi-Party Computation (MPC)
//! Distributed Threshold Key Signing (`ADR-069`).

#![forbid(unsafe_code)]

use std::process::Command;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_mpc_init_text_and_json() {
    // 1. Human-readable text format
    let output = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("init")
        .arg("--threshold")
        .arg("3")
        .arg("--signers")
        .arg("5")
        .output()
        .expect("execute mpc init");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Zero-Knowledge MPC Distributed Threshold Group Initialized ==="));
    assert!(stdout.contains("Configuration:          3-of-5 Threshold Quorum"));
    assert!(stdout.contains("Group Master Pubkey:"));
    assert!(stdout.contains("Feldman VSS Commitments:3 Order-Group Points"));
    assert!(stdout.contains("DKG ZKP Dlog Proofs:    5 Validated"));
    assert!(stdout.contains("Participant Public Verification Keys:"));
    assert!(stdout.contains("Signer 01:"));
    assert!(stdout.contains("Signer 05:"));

    // 2. Structured JSON format
    let json_out = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("init")
        .arg("--threshold")
        .arg("2")
        .arg("--signers")
        .arg("4")
        .arg("--json")
        .output()
        .expect("execute mpc init json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse mpc init json");
    assert_eq!(val["threshold"], 2);
    assert_eq!(val["signers"], 4);
    assert_eq!(val["status"], "INITIALIZED");
    assert_eq!(val["zkp_proofs_verified"], 4);
    assert_eq!(val["feldman_commitments"], 2);
    assert!(val["group_public_key"].as_str().is_some());
    assert!(val["participant_public_keys"]["1"].as_str().is_some());
}

#[test]
fn test_cli_mpc_sign_text_and_json() {
    // 1. Text format
    let output = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("sign")
        .arg("--message")
        .arg("Test Cluster Attestation Payload")
        .arg("--threshold")
        .arg("3")
        .arg("--quorum")
        .arg("1,2,4")
        .output()
        .expect("execute mpc sign");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Distributed Threshold MPC Signing Round Completed ==="));
    assert!(stdout.contains("Threshold Scheme:       3-of-4 Quorum"));
    assert!(stdout.contains("Participating Signers:  [1, 2, 4]"));
    assert!(stdout.contains("Payload Message:        Test Cluster Attestation Payload"));
    assert!(stdout.contains("Threshold Signature:"));
    assert!(stdout.contains("Wire Size:              64 Bytes (Compact RFC 8032 standard)"));
    assert!(stdout.contains("Cryptographic Status:   VERIFIED (Valid Against Master Key)"));

    // 2. JSON format
    let json_out = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("sign")
        .arg("--message")
        .arg("Machine JSON Attestation")
        .arg("--threshold")
        .arg("2")
        .arg("--quorum")
        .arg("1,3")
        .arg("--json")
        .output()
        .expect("execute mpc sign json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse mpc sign json");
    assert_eq!(val["threshold"], 2);
    assert_eq!(val["quorum"], serde_json::json!([1, 3]));
    assert_eq!(val["wire_format_bytes"], 64);
    assert_eq!(val["verified"], true);
    assert!(val["signature_hex"].as_str().is_some());
    assert!(val["group_public_key"].as_str().is_some());
}

#[test]
fn test_cli_mpc_verify_text_and_json() {
    // Sign first to get valid signature and pubkey
    let sign_out = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("sign")
        .arg("--message")
        .arg("VerificationTargetMessage")
        .arg("--threshold")
        .arg("2")
        .arg("--quorum")
        .arg("1,2")
        .arg("--json")
        .output()
        .expect("execute sign for verify");

    assert!(sign_out.status.success());
    let sign_json: serde_json::Value = serde_json::from_slice(&sign_out.stdout).unwrap();
    let sig_hex = sign_json["signature_hex"].as_str().unwrap();
    let pubkey_hex = sign_json["group_public_key"].as_str().unwrap();

    // 1. Text verify - Valid
    let verify_out = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("verify")
        .arg("--message")
        .arg("VerificationTargetMessage")
        .arg("--signature")
        .arg(sig_hex)
        .arg("--pubkey")
        .arg(pubkey_hex)
        .output()
        .expect("execute mpc verify");

    assert!(verify_out.status.success());
    let stdout = String::from_utf8_lossy(&verify_out.stdout);
    assert!(stdout.contains("=== Distributed Threshold MPC Signature Verification ==="));
    assert!(stdout.contains("Payload Message:        VerificationTargetMessage"));
    assert!(stdout.contains("Verification Result:    VALID (Cryptographically Proven)"));

    // 2. Text verify - Corrupted Message
    let invalid_out = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("verify")
        .arg("--message")
        .arg("CorruptedTamperedMessage")
        .arg("--signature")
        .arg(sig_hex)
        .arg("--pubkey")
        .arg(pubkey_hex)
        .output()
        .expect("execute mpc verify invalid");

    assert!(invalid_out.status.success());
    let invalid_stdout = String::from_utf8_lossy(&invalid_out.stdout);
    assert!(invalid_stdout.contains("INVALID (Signature Mismatch or Corrupted Payload)"));

    // 3. JSON verify
    let json_out = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("verify")
        .arg("--message")
        .arg("VerificationTargetMessage")
        .arg("--signature")
        .arg(sig_hex)
        .arg("--pubkey")
        .arg(pubkey_hex)
        .arg("--json")
        .output()
        .expect("execute mpc verify json");

    assert!(json_out.status.success());
    let json_val: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(json_val["valid"], true);
    assert_eq!(json_val["status"], "VERIFIED");
}

#[test]
fn test_cli_mpc_audit_text_and_json() {
    // 1. Text audit
    let output = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("audit")
        .output()
        .expect("execute mpc audit");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Distributed MPC Threshold Cluster Audit Trail ==="));
    assert!(stdout.contains("Threshold Scheme:       3-of-5 Quorum"));
    assert!(stdout.contains("DKG ZKP Dlog Proofs:    5 Active & Verified"));
    assert!(stdout.contains("Logged Sessions:        2"));
    assert!(stdout.contains("Operation:            issue_root_token"));
    assert!(stdout.contains("Operation:            attest_storage_manifest"));
    assert!(stdout.contains("Success:              YES"));

    // 2. JSON audit
    let json_out = Command::new(velcrux_bin())
        .arg("mpc")
        .arg("audit")
        .arg("--json")
        .output()
        .expect("execute mpc audit json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse mpc audit json");
    assert_eq!(val["threshold"], 3);
    assert_eq!(val["total_signers"], 5);
    assert_eq!(val["zkp_proofs_verified"], 5);
    assert_eq!(val["audit_records"].as_array().unwrap().len(), 2);
}
