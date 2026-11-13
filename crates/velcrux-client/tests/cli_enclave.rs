//! Integration tests for Option DI: Confidential Enclave Attestation & Remote Hardware Root-of-Trust Mesh (`ADR-077`).

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
fn test_cli_enclave_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("status")
        .output()
        .expect("execute enclave status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CONFIDENTIAL ENCLAVE ATTESTATION & REMOTE HARDWARE ROOT-OF-TRUST STATUS")
    );
    assert!(stdout.contains("Local Enclave Node:     gateway-us-east-1"));
    assert!(stdout.contains("Hardware Platform:      amd_sev_snp (Active Enclave)"));
    assert!(stdout.contains("TCB Baseline SVN:"));
    assert!(stdout.contains("Launch Measurement:"));
    assert!(stdout.contains("Debug Mode Policy:      DISALLOWED"));
    assert!(stdout.contains("storage-node-us-east-01"));
    assert!(stdout.contains("storage-node-eu-west-01"));
    assert!(stdout.contains("TRUSTED"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute enclave status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse enclave status json");
    assert_eq!(val["local_node_id"].as_str().unwrap(), "gateway-us-east-1");
    assert_eq!(val["hardware_platform"].as_str().unwrap(), "amd_sev_snp");
    assert!(val["is_confidential_enclave_active"].as_bool().unwrap());
    assert!(!val["policy_debug_allowed"].as_bool().unwrap());
    assert_eq!(val["total_mesh_peers"].as_u64().unwrap(), 2);
    assert_eq!(val["trusted_mesh_peers"].as_u64().unwrap(), 2);

    let peers = val["peers"].as_array().expect("peers array");
    assert_eq!(peers.len(), 2);
}

#[test]
fn test_cli_enclave_quote_text_and_json() {
    // 1. Text output - AMD SEV-SNP
    let output = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("quote")
        .arg("--platform")
        .arg("amd_sev_snp")
        .output()
        .expect("execute enclave quote");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CONFIDENTIAL HARDWARE ENCLAVE ATTESTATION QUOTE GENERATION"));
    assert!(stdout.contains("Hardware Platform:      amd_sev_snp"));
    assert!(stdout.contains("REPORTDATA (64 Bytes):"));
    assert!(stdout.contains("TCB SVN Levels:"));
    assert!(stdout.contains("Debug Flag:             false"));
    assert!(stdout.contains("Signature Length:       64 bytes"));

    // 2. JSON output - Intel SGX
    let json_out = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("quote")
        .arg("--platform")
        .arg("intel_sgx")
        .arg("--json")
        .output()
        .expect("execute enclave quote json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse enclave quote json");
    assert_eq!(val["platform"].as_str().unwrap(), "intel_sgx");
    assert_eq!(val["is_debug"].as_bool().unwrap(), false);
    assert_eq!(val["report_data_hex"].as_str().unwrap().len(), 128);
    assert_eq!(val["signature_hex"].as_str().unwrap().len(), 128);
    assert!(val["mr_enclave_hex"].as_str().is_some());
    assert!(val["mr_signer_hex"].as_str().is_some());
}

#[test]
fn test_cli_enclave_verify_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("verify")
        .arg("--platform")
        .arg("amd_sev_snp")
        .output()
        .expect("execute enclave verify");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CONFIDENTIAL ENCLAVE ATTESTATION QUOTE VERIFICATION REPORT"));
    assert!(stdout.contains("Verification Status:    PASS (VERIFIED)"));
    assert!(stdout.contains("Hardware Platform:      amd_sev_snp"));
    assert!(stdout.contains("Signature Integrity:    VALID (Platform Root Signed)"));
    assert!(stdout.contains("Non-Debug Policy:       ENFORCED (Compliant: true)"));
    assert!(stdout.contains("TLS 1.3 Channel Bind:   VERIFIED (MITM Relay Protected)"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("verify")
        .arg("--platform")
        .arg("amd_sev_snp")
        .arg("--json")
        .output()
        .expect("execute enclave verify json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse enclave verify json");
    assert!(val["is_valid"].as_bool().unwrap());
    assert_eq!(val["platform"].as_str().unwrap(), "amd_sev_snp");
    assert!(val["signature_valid"].as_bool().unwrap());
    assert!(val["tcb_compliant"].as_bool().unwrap());
    assert!(val["non_debug_compliant"].as_bool().unwrap());
    assert!(val["channel_binding_verified"].as_bool().unwrap());
}

#[test]
fn test_cli_enclave_benchmark_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .output()
        .expect("execute enclave benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CONFIDENTIAL ENCLAVE HARDWARE ATTESTATION MICROSECOND BENCHMARK"));
    assert!(stdout.contains("Iterations:             20"));
    assert!(stdout.contains("Hardware Platform:      amd_sev_snp"));
    assert!(stdout.contains("TLS 1.3 Channel Bind:"));
    assert!(stdout.contains("Quote Generation:"));
    assert!(stdout.contains("Quote Verification:"));
    assert!(stdout.contains("Hardware Data Sealing:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("enclave")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .arg("--json")
        .output()
        .expect("execute enclave benchmark json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse enclave benchmark json");
    assert_eq!(val["iterations"].as_u64().unwrap(), 20);
    assert_eq!(val["platform"].as_str().unwrap(), "amd_sev_snp");
    assert!(val["tls_channel_binding_avg_us"].as_f64().unwrap() > 0.0);
    assert!(val["quote_generation_avg_us"].as_f64().unwrap() > 0.0);
    assert!(val["quote_verification_avg_us"].as_f64().unwrap() > 0.0);
    assert!(val["data_sealing_roundtrip_avg_us"].as_f64().unwrap() > 0.0);
    assert!(val["total_ops_per_second"].as_f64().unwrap() > 100.0);
}
