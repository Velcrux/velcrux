//! Integration tests for Option CK: Zero-Trust Cryptographic Content Provenance
//! & Tamper-Evident Merkle-DAG Audit Log (`ADR-053`).

#![forbid(unsafe_code)]

use std::fs;
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
fn test_cli_provenance_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("status")
        .output()
        .expect("execute velcrux provenance status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Merkle-DAG Provenance Audit Log Status"));
    assert!(stdout.contains("Total Nodes:"));
    assert!(stdout.contains("DAG Heads / Tips:"));
    assert!(stdout.contains("DAG Depth:"));
    assert!(stdout.contains("Merkle Root:"));
    assert!(stdout.contains("Integrity Valid:        true"));
}

#[test]
fn test_cli_provenance_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("--json")
        .arg("provenance")
        .arg("status")
        .output()
        .expect("execute velcrux --json provenance status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("valid JSON expected from --json provenance status");

    assert!(json_val["total_nodes"].is_number());
    assert!(json_val["total_heads"].is_number());
    assert!(json_val["dag_depth"].is_number());
    assert!(json_val["merkle_root"].is_string());
    assert_eq!(json_val["is_valid"], true);
}

#[test]
fn test_cli_provenance_record_and_verify() {
    let dir = tempdir().expect("create tempdir");

    // 1. Record an event
    let record_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("record")
        .arg("--actor")
        .arg("spiffe://velcrux/client/test-agent")
        .arg("--action")
        .arg("cas_chunk_ingest")
        .arg("--resource")
        .arg("cas:test-chunk-abc123")
        .arg("--data")
        .arg("payload-sample-data")
        .arg("--json")
        .output()
        .expect("execute provenance record");

    assert!(
        record_output.status.success(),
        "record stderr: {:?}",
        String::from_utf8_lossy(&record_output.stderr)
    );

    let json_rec: serde_json::Value =
        serde_json::from_slice(&record_output.stdout).expect("valid JSON expected from record");

    assert_eq!(json_rec["actor"], "spiffe://velcrux/client/test-agent");
    assert_eq!(json_rec["action"], "cas_chunk_ingest");
    assert_eq!(json_rec["resource_id"], "cas:test-chunk-abc123");
    let node_hash = json_rec["node_hash"].as_str().expect("node_hash string");
    assert_eq!(node_hash.len(), 64);

    // 2. Verify DAG integrity
    let verify_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("verify")
        .arg("--json")
        .output()
        .expect("execute provenance verify");

    assert!(
        verify_output.status.success(),
        "verify stderr: {:?}",
        String::from_utf8_lossy(&verify_output.stderr)
    );

    let json_ver: serde_json::Value =
        serde_json::from_slice(&verify_output.stdout).expect("valid JSON expected from verify");

    assert_eq!(json_ver["is_valid"], true);
    assert_eq!(json_ver["total_nodes"], 1);
    assert_eq!(json_ver["dag_depth"], 1);
}

#[test]
fn test_cli_provenance_prove_inclusion() {
    let dir = tempdir().expect("create tempdir");

    // 1. Record an event
    let record_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("record")
        .arg("--actor")
        .arg("spiffe://velcrux/client/prover")
        .arg("--action")
        .arg("file_mutation")
        .arg("--resource")
        .arg("vpath:/etc/velcrux.conf")
        .arg("--data")
        .arg("port=9000")
        .arg("--json")
        .output()
        .expect("execute provenance record");

    assert!(record_output.status.success());
    let json_rec: serde_json::Value = serde_json::from_slice(&record_output.stdout).unwrap();
    let node_hash = json_rec["node_hash"].as_str().unwrap();

    // 2. Generate and verify inclusion proof
    let prove_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("prove")
        .arg("--node-hash")
        .arg(node_hash)
        .arg("--json")
        .output()
        .expect("execute provenance prove");

    assert!(
        prove_output.status.success(),
        "prove stderr: {:?}",
        String::from_utf8_lossy(&prove_output.stderr)
    );

    let json_proof: serde_json::Value = serde_json::from_slice(&prove_output.stdout).unwrap();
    assert_eq!(json_proof["target_node_hash"], node_hash);
    assert_eq!(json_proof["verified"], true);
    assert!(json_proof["path_length"].as_u64().unwrap() >= 1);
}

#[test]
fn test_cli_provenance_witness_cosign() {
    let dir = tempdir().expect("create tempdir");

    // 1. Record an event
    let record_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("record")
        .arg("--actor")
        .arg("spiffe://velcrux/server/authority")
        .arg("--action")
        .arg("access_grant")
        .arg("--resource")
        .arg("tenant:corporate-backup")
        .arg("--json")
        .output()
        .expect("execute provenance record");

    assert!(record_output.status.success());
    let json_rec: serde_json::Value = serde_json::from_slice(&record_output.stdout).unwrap();
    let node_hash = json_rec["node_hash"].as_str().unwrap();

    // 2. Attach witness cosignature
    let witness_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("witness")
        .arg("--node-hash")
        .arg(node_hash)
        .arg("--witness-id")
        .arg("witness-zurich-ch-01")
        .arg("--json")
        .output()
        .expect("execute provenance witness");

    assert!(
        witness_output.status.success(),
        "witness stderr: {:?}",
        String::from_utf8_lossy(&witness_output.stderr)
    );

    let json_wit: serde_json::Value = serde_json::from_slice(&witness_output.stdout).unwrap();
    assert_eq!(json_wit["witness_id"], "witness-zurich-ch-01");
    assert_eq!(json_wit["public_key_hex"].as_str().unwrap().len(), 64);
    assert_eq!(json_wit["signature_hex"].as_str().unwrap().len(), 64);
}

#[test]
fn test_cli_provenance_export() {
    let dir = tempdir().expect("create tempdir");
    let export_path = dir.path().join("audit_ledger.json");

    let export_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("export")
        .arg("--out")
        .arg(&export_path)
        .output()
        .expect("execute provenance export");

    assert!(
        export_output.status.success(),
        "export stderr: {:?}",
        String::from_utf8_lossy(&export_output.stderr)
    );

    assert!(export_path.exists());
    let contents = fs::read_to_string(&export_path).unwrap();
    let json_val: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert!(json_val.is_array());
}

#[test]
fn test_cli_provenance_benchmark() {
    let dir = tempdir().expect("create tempdir");
    let bench_output = Command::new(velcrux_bin())
        .env("VELCRUX_PROVENANCE_DIR", dir.path())
        .arg("provenance")
        .arg("benchmark")
        .arg("--iterations")
        .arg("25")
        .output()
        .expect("execute provenance benchmark");

    assert!(
        bench_output.status.success(),
        "bench stderr: {:?}",
        String::from_utf8_lossy(&bench_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&bench_output.stdout);
    assert!(stdout.contains("Merkle-DAG Provenance Benchmark"));
    assert!(stdout.contains("Node Append:"));
    assert!(stdout.contains("DAG Verification:"));
    assert!(stdout.contains("Inclusion Proof:"));
    assert!(stdout.contains("Witness Cosigning:"));
}
