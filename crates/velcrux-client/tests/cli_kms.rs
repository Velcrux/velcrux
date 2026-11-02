//! Integration tests for Option CS: Hardware Security Module (HSM) PKCS#11 & Cloud KMS
//! Key Orchestration Bridge (`ADR-061`).

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
fn test_cli_kms_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("status")
        .output()
        .expect("execute velcrux kms status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("HSM / Cloud KMS Key Orchestration Bridge Status"));
    assert!(stdout.contains("Master Key ID:"));
    assert!(stdout.contains("velcrux-root-kek-v1"));
    assert!(stdout.contains("Active Provider:"));
    assert!(stdout.contains("Active Key Version:"));
}

#[test]
fn test_cli_kms_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute velcrux kms status --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse status JSON output");

    assert_eq!(v["master_key_id"], "velcrux-root-kek-v1");
    assert_eq!(v["active_key_version"], 1);
    assert!(v["master_key_fingerprint"].is_string());
}

#[test]
fn test_cli_kms_wrap_unwrap() {
    let dir = tempdir().expect("create tempdir");
    let plaintext_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let wrap_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("wrap")
        .arg("--plaintext")
        .arg(plaintext_hex)
        .arg("--context")
        .arg("tenant_id=tenant-alpha,env=prod")
        .arg("--json")
        .output()
        .expect("execute velcrux kms wrap");

    assert!(
        wrap_output.status.success(),
        "wrap stderr: {:?}",
        String::from_utf8_lossy(&wrap_output.stderr)
    );
    let envelope_json = String::from_utf8_lossy(&wrap_output.stdout);

    // Unwrap envelope with exact matching context
    let unwrap_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("unwrap")
        .arg("--envelope")
        .arg(envelope_json.trim())
        .arg("--context")
        .arg("tenant_id=tenant-alpha,env=prod")
        .arg("--json")
        .output()
        .expect("execute velcrux kms unwrap");

    assert!(
        unwrap_output.status.success(),
        "unwrap stderr: {:?}",
        String::from_utf8_lossy(&unwrap_output.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&unwrap_output.stdout).expect("parse unwrap JSON");
    assert_eq!(v["status"], "unwrapped");
    assert_eq!(v["unwrapped_key_hex"], plaintext_hex);
}

#[test]
fn test_cli_kms_context_tamper_rejection() {
    let dir = tempdir().expect("create tempdir");
    let plaintext_hex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    let wrap_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("wrap")
        .arg("--plaintext")
        .arg(plaintext_hex)
        .arg("--context")
        .arg("tenant_id=tenant-alpha,env=prod")
        .arg("--json")
        .output()
        .expect("execute velcrux kms wrap");

    assert!(wrap_output.status.success());
    let envelope_json = String::from_utf8_lossy(&wrap_output.stdout);

    // Attempt unwrap with forged tenant context
    let unwrap_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("unwrap")
        .arg("--envelope")
        .arg(envelope_json.trim())
        .arg("--context")
        .arg("tenant_id=tenant-hacker,env=prod")
        .arg("--json")
        .output()
        .expect("execute velcrux kms unwrap with forged context");

    assert!(
        !unwrap_output.status.success(),
        "Unwrap must fail when context is tampered"
    );
}

#[test]
fn test_cli_kms_sign_verify() {
    let dir = tempdir().expect("create tempdir");
    let payload = "velcrux-manifest-integrity-token-2026";

    let sign_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("sign")
        .arg("--data")
        .arg(payload)
        .arg("--json")
        .output()
        .expect("execute velcrux kms sign");

    assert!(
        sign_output.status.success(),
        "sign stderr: {:?}",
        String::from_utf8_lossy(&sign_output.stderr)
    );
    let sig_json: serde_json::Value =
        serde_json::from_slice(&sign_output.stdout).expect("parse sign JSON");
    let sig_hex = sig_json["signature_hex"]
        .as_str()
        .expect("signature_hex string");

    // Verify valid signature
    let verify_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("verify")
        .arg("--data")
        .arg(payload)
        .arg("--signature")
        .arg(sig_hex)
        .arg("--json")
        .output()
        .expect("execute velcrux kms verify");

    assert!(verify_output.status.success());
    let v_res: serde_json::Value =
        serde_json::from_slice(&verify_output.stdout).expect("parse verify JSON");
    assert_eq!(v_res["verified"], true);

    // Verify tampered data
    let verify_tampered = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("verify")
        .arg("--data")
        .arg("corrupted-payload-data")
        .arg("--signature")
        .arg(sig_hex)
        .arg("--json")
        .output()
        .expect("execute velcrux kms verify tampered");

    assert!(verify_tampered.status.success());
    let v_tampered: serde_json::Value =
        serde_json::from_slice(&verify_tampered.stdout).expect("parse verify tampered JSON");
    assert_eq!(v_tampered["verified"], false);
}

#[test]
fn test_cli_kms_rotate() {
    let dir = tempdir().expect("create tempdir");

    let rotate_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("rotate")
        .arg("--json")
        .output()
        .expect("execute velcrux kms rotate");

    assert!(
        rotate_output.status.success(),
        "rotate stderr: {:?}",
        String::from_utf8_lossy(&rotate_output.stderr)
    );
    let rot_json: serde_json::Value =
        serde_json::from_slice(&rotate_output.stdout).expect("parse rotate JSON");
    assert_eq!(rot_json["previous_version"], 1);
    assert_eq!(rot_json["new_version"], 2);

    // Check status reflects version 2
    let status_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute velcrux kms status");

    assert!(status_output.status.success());
    let status_json: serde_json::Value =
        serde_json::from_slice(&status_output.stdout).expect("parse status JSON");
    assert_eq!(status_json["active_key_version"], 2);
}

#[test]
fn test_cli_kms_benchmark() {
    let dir = tempdir().expect("create tempdir");

    let bench_output = Command::new(velcrux_bin())
        .env("VELCRUX_KMS_DIR", dir.path())
        .arg("kms")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .arg("--json")
        .output()
        .expect("execute velcrux kms benchmark");

    assert!(
        bench_output.status.success(),
        "benchmark stderr: {:?}",
        String::from_utf8_lossy(&bench_output.stderr)
    );
    let bench_json: serde_json::Value =
        serde_json::from_slice(&bench_output.stdout).expect("parse benchmark JSON");
    assert_eq!(bench_json["iterations"], 20);
    assert!(bench_json["key_wrap_latency_us"].as_f64().unwrap() >= 0.0);
    assert!(bench_json["key_unwrap_latency_us"].as_f64().unwrap() >= 0.0);
}
