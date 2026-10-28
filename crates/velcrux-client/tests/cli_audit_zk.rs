//! Integration tests for Option CA: Cryptographic Zero-Knowledge Transfer Audit Proofs
//! and Merkle Tree Accumulator (`ADR-043`).

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
fn test_cli_audit_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("audit")
        .arg("status")
        .arg("--epoch")
        .arg("1")
        .output()
        .expect("execute audit status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Audit Merkle Accumulator Status (Epoch 1)"));
    assert!(stdout.contains("Root Hash:"));
    assert!(stdout.contains("Record Count:"));
    assert!(stdout.contains("Tree Height:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("status")
        .arg("--epoch")
        .arg("1")
        .arg("--json")
        .output()
        .expect("execute audit status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse audit status json");
    assert_eq!(val["epoch"].as_u64().unwrap(), 1);
    assert!(val["total_records"].as_u64().unwrap() > 0);
    assert_eq!(val["root_hex"].as_str().unwrap().len(), 64);
}

#[test]
fn test_cli_audit_export_root() {
    let output = Command::new(velcrux_bin())
        .arg("audit")
        .arg("export-root")
        .arg("--epoch")
        .arg("42")
        .output()
        .expect("execute audit export-root");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Authoritative Root (Epoch 42):"));

    let json_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("export-root")
        .arg("--epoch")
        .arg("42")
        .arg("--json")
        .output()
        .expect("execute audit export-root json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse export-root json");
    assert_eq!(val["epoch"].as_u64().unwrap(), 42);
    assert_eq!(val["root_hex"].as_str().unwrap().len(), 64);
}

#[test]
fn test_cli_audit_generate_and_verify_proof() {
    let tmp = tempdir().unwrap();
    let proof_file = tmp.path().join("audit_proof.json");

    // 1. Generate inclusion proof
    let gen_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("generate-proof")
        .arg("01J00000000000000000012345")
        .arg("--tenant")
        .arg("tenant-finance")
        .arg("--bytes")
        .arg("5242880")
        .arg("--out")
        .arg(&proof_file)
        .output()
        .expect("generate proof");

    assert!(
        gen_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&gen_out.stderr)
    );
    assert!(proof_file.exists());

    let proof_raw = fs::read_to_string(&proof_file).expect("read proof file");
    let proof_val: serde_json::Value = serde_json::from_str(&proof_raw).expect("parse proof json");
    let leaf_hex = proof_val["leaf_hash"].as_str().unwrap();
    let root_hex = proof_val["expected_root"].as_str().unwrap();
    assert_eq!(leaf_hex.len(), 64);
    assert_eq!(root_hex.len(), 64);

    // 2. Verify proof with correct root and leaf
    let verify_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("verify-proof")
        .arg("--root")
        .arg(root_hex)
        .arg("--leaf")
        .arg(leaf_hex)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("verify proof");

    assert!(
        verify_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let verify_stdout = String::from_utf8_lossy(&verify_out.stdout);
    assert!(verify_stdout.contains("Valid:          YES"));
    assert!(verify_stdout.contains("Root Matches:   YES"));
    assert!(verify_stdout.contains("Leaf Matches:   YES"));

    // 3. Verify proof in JSON format
    let verify_json_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("verify-proof")
        .arg("--root")
        .arg(root_hex)
        .arg("--leaf")
        .arg(leaf_hex)
        .arg("--proof-file")
        .arg(&proof_file)
        .arg("--json")
        .output()
        .expect("verify proof json");

    assert!(verify_json_out.status.success());
    let v_val: serde_json::Value = serde_json::from_slice(&verify_json_out.stdout).unwrap();
    assert_eq!(v_val["valid"].as_bool().unwrap(), true);
    assert_eq!(v_val["matches_root"].as_bool().unwrap(), true);
    assert_eq!(v_val["matches_leaf"].as_bool().unwrap(), true);

    // 4. Verify proof inline JSON string option
    let verify_inline_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("verify-proof")
        .arg("--root")
        .arg(root_hex)
        .arg("--leaf")
        .arg(leaf_hex)
        .arg("--proof-json")
        .arg(&proof_raw)
        .output()
        .expect("verify inline proof");

    assert!(verify_inline_out.status.success());

    // 5. Tampered leaf rejection
    let tampered_leaf = format!("ff{}", &leaf_hex[2..]);
    let fail_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("verify-proof")
        .arg("--root")
        .arg(root_hex)
        .arg("--leaf")
        .arg(&tampered_leaf)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("verify tampered leaf");

    assert!(!fail_out.status.success(), "tampered leaf must be rejected");

    // 6. Tampered root rejection
    let tampered_root = format!("00{}", &root_hex[2..]);
    let fail_root_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("verify-proof")
        .arg("--root")
        .arg(&tampered_root)
        .arg("--leaf")
        .arg(leaf_hex)
        .arg("--proof-file")
        .arg(&proof_file)
        .output()
        .expect("verify tampered root");

    assert!(
        !fail_root_out.status.success(),
        "tampered root must be rejected"
    );
}

#[test]
fn test_cli_audit_benchmark() {
    let output = Command::new(velcrux_bin())
        .arg("audit")
        .arg("benchmark")
        .arg("--records")
        .arg("20")
        .arg("--samples")
        .arg("5")
        .output()
        .expect("execute audit benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Cryptographic Audit Accumulator Benchmark"));
    assert!(stdout.contains("Total Records:          20"));
    assert!(stdout.contains("Proof Samples:          5"));
    assert!(stdout.contains("All Proofs Verified:    YES"));

    let json_out = Command::new(velcrux_bin())
        .arg("audit")
        .arg("benchmark")
        .arg("--records")
        .arg("10")
        .arg("--samples")
        .arg("3")
        .arg("--json")
        .output()
        .expect("execute audit benchmark json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse benchmark json");
    assert_eq!(val["total_records"].as_u64().unwrap(), 10);
    assert_eq!(val["proof_samples"].as_u64().unwrap(), 3);
    assert_eq!(val["all_proofs_verified"].as_bool().unwrap(), true);
}
