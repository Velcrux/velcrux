//! Integration tests for Option CN: Zero-Knowledge Range & Membership Proofs
//! for Blinded Multi-Tenant Quota Auditing (`ADR-056`).

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
fn test_cli_zkquota_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("zkquota")
        .arg("status")
        .output()
        .expect("execute velcrux zkquota status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Zero-Knowledge Blinded Quota Auditing Engine Status"));
    assert!(stdout.contains("Registered Tenants:"));
    assert!(stdout.contains("Compliant Tenants:"));
    assert!(stdout.contains("Proofs Generated:"));
    assert!(stdout.contains("Authorized Merkle Root:"));
}

#[test]
fn test_cli_zkquota_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("--json")
        .arg("zkquota")
        .arg("status")
        .output()
        .expect("execute velcrux --json zkquota status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("parse json output from velcrux zkquota status");

    assert!(json_val.get("total_registered_tenants").is_some());
    assert!(json_val.get("compliant_tenants").is_some());
    assert!(json_val.get("proofs_generated_total").is_some());
    assert!(json_val.get("authorized_set_root").is_some());
}

#[test]
fn test_cli_zkquota_prove_compliant() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("zkquota")
        .arg("prove")
        .arg("--tenant")
        .arg("tenant-alpha")
        .arg("--usage-bytes")
        .arg("104857600") // 100 MiB
        .arg("--quota-bytes")
        .arg("524288000") // 500 MiB
        .arg("--save")
        .output()
        .expect("execute velcrux zkquota prove");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Zero-Knowledge Blinded Quota Proof Generated"));
    assert!(stdout.contains("COMPLIANT"));
    assert!(stdout.contains("Blinded Identity:"));
    assert!(stdout.contains("Usage Commitment:"));
}

#[test]
fn test_cli_zkquota_prove_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("--json")
        .arg("zkquota")
        .arg("prove")
        .arg("--tenant")
        .arg("tenant-beta")
        .arg("--usage-bytes")
        .arg("50000000")
        .arg("--quota-bytes")
        .arg("100000000")
        .arg("--save")
        .output()
        .expect("execute velcrux --json zkquota prove");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("parse json output from velcrux zkquota prove");

    assert_eq!(json_val["is_compliant"].as_bool(), Some(true));
    assert!(json_val.get("usage_commitment").is_some());
    assert!(json_val.get("range_proof").is_some());
    assert!(json_val.get("membership_proof").is_some());
}

#[test]
fn test_cli_zkquota_verify() {
    let dir = tempdir().expect("create tempdir");

    // 1. Generate proof
    let _ = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("zkquota")
        .arg("prove")
        .arg("--tenant")
        .arg("tenant-gamma")
        .arg("--usage-bytes")
        .arg("20000000")
        .arg("--quota-bytes")
        .arg("80000000")
        .arg("--save")
        .output()
        .expect("generate proof");

    // 2. Verify proof
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("zkquota")
        .arg("verify")
        .arg("--tenant")
        .arg("tenant-gamma")
        .output()
        .expect("execute velcrux zkquota verify");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Zero-Knowledge Quota Proof Verification"));
    assert!(stdout.contains("VALID"));
    assert!(stdout.contains("COMPLIANT"));
}

#[test]
fn test_cli_zkquota_audit() {
    let dir = tempdir().expect("create tempdir");

    let output = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("zkquota")
        .arg("audit")
        .output()
        .expect("execute velcrux zkquota audit");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Cluster-Wide Zero-Knowledge Quota Audit Report"));
    assert!(stdout.contains("All Proofs Valid:       true"));
    assert!(stdout.contains("Balance Accumulator:    true"));
}

#[test]
fn test_cli_zkquota_benchmark() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_ZKQUOTA_DIR", dir.path())
        .arg("zkquota")
        .arg("benchmark")
        .arg("--iterations")
        .arg("20")
        .output()
        .expect("execute velcrux zkquota benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Zero-Knowledge Quota Benchmark (20 iterations)"));
    assert!(stdout.contains("Pedersen Commitment:"));
    assert!(stdout.contains("Range Proof Generation:"));
    assert!(stdout.contains("Range Proof Verif:"));
    assert!(stdout.contains("Cluster Audit Sweep:"));
}
