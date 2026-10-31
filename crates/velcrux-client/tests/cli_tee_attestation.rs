//! Integration tests for Option CH: Confidential Computing & Hardware
//! TEE Remote Attestation (`ADR-050`).

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn velcrux_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_tee_status_text_and_json() {
    // 1. Human-readable text output
    let output = Command::new(velcrux_bin())
        .arg("tee")
        .arg("status")
        .output()
        .expect("execute tee status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Confidential Computing & Hardware TEE Attestation Status ==="));
    assert!(stdout.contains("Supported Platforms:"));
    assert!(stdout.contains("amd_sev_snp"));
    assert!(stdout.contains("intel_sgx"));
    assert!(stdout.contains("aws_nitro"));
    assert!(stdout.contains("TEE Attestations:"));
    assert!(stdout.contains("Attestation Successes:"));
    assert!(stdout.contains("Attestation Failures:"));
    assert!(stdout.contains("Active Enclaves:"));
    assert!(stdout.contains("Last Latency:"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute tee status json");

    assert!(json_out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json_out.stdout).expect("parse status json");
    assert!(v.get("tee_attestations_total").is_some());
    assert!(v.get("tee_attestation_successes_total").is_some());
    assert!(v.get("tee_attestation_failures_total").is_some());
    assert!(v.get("tee_verification_latency_nanoseconds").is_some());
    assert!(v.get("tee_active_enclaves").is_some());
    assert!(v["supported_platforms"].is_array());
}

#[test]
fn test_cli_tee_measure() {
    let mut tmp = NamedTempFile::new().expect("create tempfile");
    tmp.write_all(b"VELCRUX_ENCLAVE_IMAGE_SAMPLE_PAYLOAD_TEST")
        .expect("write payload");
    let path_str = tmp.path().to_str().unwrap();

    // 1. Measure AMD SEV-SNP (SHA-384 / 96 chars)
    let sev_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("measure")
        .arg("--binary")
        .arg(path_str)
        .arg("--platform")
        .arg("amd_sev_snp")
        .arg("--json")
        .output()
        .expect("measure amd sev");

    assert!(sev_out.status.success());
    let sev_v: serde_json::Value =
        serde_json::from_slice(&sev_out.stdout).expect("parse measure json");
    let m_sev = sev_v["launch_measurement"].as_str().unwrap();
    assert_eq!(m_sev.len(), 96);
    assert_eq!(sev_v["platform"], "amd_sev_snp");

    // 2. Measure Intel SGX (SHA-256 / 64 chars)
    let sgx_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("measure")
        .arg("--binary")
        .arg(path_str)
        .arg("--platform")
        .arg("intel_sgx")
        .arg("--json")
        .output()
        .expect("measure intel sgx");

    assert!(sgx_out.status.success());
    let sgx_v: serde_json::Value =
        serde_json::from_slice(&sgx_out.stdout).expect("parse sgx measure json");
    let m_sgx = sgx_v["launch_measurement"].as_str().unwrap();
    assert_eq!(m_sgx.len(), 64);
    assert_eq!(sgx_v["platform"], "intel_sgx");
}

#[test]
fn test_cli_tee_quote_generation_and_verification() {
    // 1. Generate an AMD SEV-SNP quote bound to a challenge nonce
    let quote_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("quote")
        .arg("--platform")
        .arg("amd_sev_snp")
        .arg("--report-data")
        .arg("session_challenge_nonce_0123456789")
        .arg("--security-version")
        .arg("2")
        .arg("--json")
        .output()
        .expect("generate quote");

    assert!(
        quote_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&quote_out.stderr)
    );
    let quote_str = String::from_utf8_lossy(&quote_out.stdout)
        .trim()
        .to_string();
    let q_v: serde_json::Value = serde_json::from_str(&quote_str).expect("parse quote json");
    assert_eq!(q_v["platform"], "amd_sev_snp");
    assert_eq!(q_v["security_version"], 2);
    assert_eq!(q_v["debug_enabled"], false);
    assert!(!q_v["signature"].as_str().unwrap().is_empty());

    // 2. Verify quote with matching challenge nonce
    let verify_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("verify")
        .arg("--quote")
        .arg(&quote_str)
        .arg("--nonce")
        .arg("session_challenge_nonce_0123456789")
        .arg("--json")
        .output()
        .expect("verify quote");

    assert!(
        verify_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let rep_v: serde_json::Value =
        serde_json::from_slice(&verify_out.stdout).expect("parse verify json");
    assert_eq!(rep_v["is_valid"], true);
    assert_eq!(rep_v["platform"], "amd_sev_snp");
    assert_eq!(rep_v["nonce_matched"], true);
    assert_eq!(rep_v["security_version"], 2);
    assert_eq!(rep_v["debug_enabled"], false);
}

#[test]
fn test_cli_tee_policy_enforcement_and_rejection() {
    // 1. Generate debug-enabled quote
    let debug_quote_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("quote")
        .arg("--platform")
        .arg("amd_sev_snp")
        .arg("--debug-mode")
        .arg("--json")
        .output()
        .expect("generate debug quote");
    assert!(debug_quote_out.status.success());
    let debug_quote_str = String::from_utf8_lossy(&debug_quote_out.stdout)
        .trim()
        .to_string();

    // Verify debug quote fails under standard policy
    let verify_debug = Command::new(velcrux_bin())
        .arg("tee")
        .arg("verify")
        .arg("--quote")
        .arg(&debug_quote_str)
        .output()
        .expect("verify debug quote");
    assert!(!verify_debug.status.success());
    let err_str = String::from_utf8_lossy(&verify_debug.stderr);
    assert!(err_str.contains("hardware debugging enabled"));

    // 2. Nonce mismatch rejection
    let valid_quote_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("quote")
        .arg("--platform")
        .arg("intel_sgx")
        .arg("--report-data")
        .arg("valid_nonce_abc")
        .arg("--json")
        .output()
        .expect("generate valid quote");
    assert!(valid_quote_out.status.success());
    let valid_quote_str = String::from_utf8_lossy(&valid_quote_out.stdout)
        .trim()
        .to_string();

    let verify_wrong_nonce = Command::new(velcrux_bin())
        .arg("tee")
        .arg("verify")
        .arg("--quote")
        .arg(&valid_quote_str)
        .arg("--nonce")
        .arg("attacker_forged_nonce")
        .output()
        .expect("verify wrong nonce");
    assert!(!verify_wrong_nonce.status.success());
    let nonce_err = String::from_utf8_lossy(&verify_wrong_nonce.stderr);
    assert!(nonce_err.contains("Challenge nonce mismatch"));

    // 3. Measurement whitelist rejection via custom policy
    let policy_json = r#"{"allowed_platforms":["intel_sgx"],"allowed_measurements":["0000000000000000000000000000000000000000000000000000000000000000"],"min_security_version":1,"enforce_hardware_debug_disabled":true,"max_quote_age_seconds":3600,"require_nonce_binding":false}"#;

    let verify_bad_measurement = Command::new(velcrux_bin())
        .arg("tee")
        .arg("verify")
        .arg("--quote")
        .arg(&valid_quote_str)
        .arg("--policy")
        .arg(policy_json)
        .output()
        .expect("verify bad measurement");
    assert!(!verify_bad_measurement.status.success());
    let m_err = String::from_utf8_lossy(&verify_bad_measurement.stderr);
    assert!(m_err.contains("not in allowed measurements list"));
}

#[test]
fn test_cli_tee_benchmark() {
    // 1. Text benchmark
    let output = Command::new(velcrux_bin())
        .arg("tee")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .output()
        .expect("run tee benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Hardware TEE Remote Attestation Benchmark (20 iters) ==="));
    assert!(stdout.contains("Quote Generation Latency:"));
    assert!(stdout.contains("Quote Verification Latency:"));
    assert!(stdout.contains("Session Key Derivation:"));

    // 2. JSON benchmark
    let json_out = Command::new(velcrux_bin())
        .arg("tee")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .arg("--json")
        .output()
        .expect("run tee benchmark json");

    assert!(json_out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse benchmark json");
    assert_eq!(v["iterations"], 20);
    assert!(v["quote_generation_latency_nanoseconds"].as_f64().unwrap() > 0.0);
    assert!(
        v["quote_verification_latency_nanoseconds"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    assert!(v["key_derivation_latency_nanoseconds"].as_f64().unwrap() > 0.0);
    assert!(v["quote_generation_ops_per_second"].as_f64().unwrap() > 0.0);
    assert!(v["quote_verification_ops_per_second"].as_f64().unwrap() > 0.0);
    assert!(v["key_derivation_ops_per_second"].as_f64().unwrap() > 0.0);
}
