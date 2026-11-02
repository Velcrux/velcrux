//! Integration tests for Option CQ: Post-Quantum Encrypted Staging Vault
//! with Kyber/Dilithium Envelope Encryption (`ADR-059`).

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
fn test_cli_vault_status_human() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", dir.path())
        .arg("vault")
        .arg("status")
        .output()
        .expect("execute velcrux vault status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Post-Quantum Encrypted Staging Vault Status"));
    assert!(stdout.contains("Vault ID:"));
    assert!(stdout.contains("ML-KEM-768"));
    assert!(stdout.contains("ML-DSA-65"));
    assert!(stdout.contains("ChaCha20-Poly1305"));
}

#[test]
fn test_cli_vault_status_json() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", dir.path())
        .arg("vault")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute velcrux vault status --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse vault status JSON");

    assert_eq!(json["kem_algorithm"], "ML-KEM-768");
    assert_eq!(json["sig_algorithm"], "ML-DSA-65");
    assert_eq!(json["cipher_suite"], "ChaCha20-Poly1305");
    assert_eq!(json["sealed_files_count"], 0);
}

#[test]
fn test_cli_vault_seal() {
    let dir = tempdir().expect("create tempdir");
    let src_file = dir.path().join("customer_record.csv");
    fs::write(
        &src_file,
        b"tenant_id,balance,secret_token\nalpha,1000000,super_secret_pqc\n",
    )
    .expect("write src");

    let output = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", dir.path().join("staging"))
        .arg("vault")
        .arg("seal")
        .arg(&src_file)
        .arg("--json")
        .output()
        .expect("execute velcrux vault seal --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse seal JSON");

    assert!(json["file_id"].as_str().unwrap().starts_with("vfile-"));
    assert_eq!(json["original_name"], "customer_record.csv");
    assert_eq!(json["status"], "sealed");
    assert_eq!(json["kem_algorithm"], "ML-KEM-768");
    assert_eq!(json["sig_algorithm"], "ML-DSA-65");
    assert!(json["sealed_size"].as_u64().unwrap() > json["original_size"].as_u64().unwrap());
}

#[test]
fn test_cli_vault_unseal() {
    let dir = tempdir().expect("create tempdir");
    let vault_dir = dir.path().join("staging");
    let src_file = dir.path().join("confidential_memo.txt");
    let original_bytes = b"CONFIDENTIAL: Post-Quantum Vault Envelope Testing 2026";
    fs::write(&src_file, original_bytes).expect("write src");

    // 1. Seal
    let seal_out = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("seal")
        .arg(&src_file)
        .arg("--json")
        .output()
        .expect("execute velcrux vault seal");
    assert!(seal_out.status.success());

    let seal_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&seal_out.stdout)).expect("parse seal json");
    let file_id = seal_json["file_id"].as_str().unwrap();

    // 2. Unseal to target directory
    let restore_dir = dir.path().join("restored");
    fs::create_dir_all(&restore_dir).expect("create restore dir");

    let unseal_out = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("unseal")
        .arg(file_id)
        .arg("--dest")
        .arg(&restore_dir)
        .arg("--json")
        .output()
        .expect("execute velcrux vault unseal");

    assert!(
        unseal_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&unseal_out.stderr)
    );

    let restored_file = restore_dir.join("confidential_memo.txt");
    assert!(restored_file.exists());
    let restored_bytes = fs::read(&restored_file).expect("read restored");
    assert_eq!(restored_bytes, original_bytes);
}

#[test]
fn test_cli_vault_seal_unseal_standalone_vlt() {
    let dir = tempdir().expect("create tempdir");
    let vault_dir = dir.path().join("staging");
    let src_file = dir.path().join("audit_evidence.tar");
    let original_bytes = vec![0x99u8; 16384]; // 16 KB
    fs::write(&src_file, &original_bytes).expect("write src");

    let vlt_package = dir.path().join("exported_vault_package.vlt");

    // 1. Seal directly to standalone .vlt package
    let seal_out = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("seal")
        .arg(&src_file)
        .arg("--dest")
        .arg(&vlt_package)
        .output()
        .expect("execute velcrux vault seal --dest standalone");

    assert!(seal_out.status.success());
    assert!(vlt_package.exists());

    // 2. Unseal standalone package
    let restored_file = dir.path().join("restored_evidence.tar");
    let unseal_out = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("unseal")
        .arg(vlt_package.to_str().unwrap())
        .arg("--dest")
        .arg(&restored_file)
        .output()
        .expect("execute velcrux vault unseal standalone");

    assert!(
        unseal_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&unseal_out.stderr)
    );
    assert!(restored_file.exists());
    let restored_bytes = fs::read(&restored_file).expect("read restored");
    assert_eq!(restored_bytes, original_bytes);
}

#[test]
fn test_cli_vault_shred() {
    let dir = tempdir().expect("create tempdir");
    let vault_dir = dir.path().join("staging");
    let src_file = dir.path().join("secret_to_shred.bin");
    fs::write(
        &src_file,
        b"Highly confidential payload destined for shredding",
    )
    .expect("write src");

    // 1. Seal file
    let seal_out = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("seal")
        .arg(&src_file)
        .arg("--json")
        .output()
        .expect("execute seal");
    assert!(seal_out.status.success());

    let seal_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&seal_out.stdout)).expect("parse JSON");
    let file_id = seal_json["file_id"].as_str().unwrap();

    // 2. List entries: count is 1
    let list_out = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("list")
        .arg("--json")
        .output()
        .expect("execute list");
    assert!(list_out.status.success());
    let list_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&list_out.stdout)).expect("parse list JSON");
    assert_eq!(list_json.as_array().unwrap().len(), 1);

    // 3. Shred file
    let shred_out = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("shred")
        .arg("--file-id")
        .arg(file_id)
        .arg("--passes")
        .arg("3")
        .arg("--json")
        .output()
        .expect("execute shred");
    assert!(shred_out.status.success());

    // 4. Verify unseal fails
    let unseal_fail = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("unseal")
        .arg(file_id)
        .output()
        .expect("execute unseal after shred");
    assert!(
        !unseal_fail.status.success(),
        "unseal must fail after shredding"
    );

    // 5. List entries: count is 0
    let list_after = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", &vault_dir)
        .arg("vault")
        .arg("list")
        .arg("--json")
        .output()
        .expect("execute list after");
    assert!(list_after.status.success());
    let list_after_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&list_after.stdout))
            .expect("parse list JSON");
    assert_eq!(list_after_json.as_array().unwrap().len(), 0);
}

#[test]
fn test_cli_vault_benchmark() {
    let dir = tempdir().expect("create tempdir");
    let output = Command::new(velcrux_bin())
        .env("VELCRUX_VAULT_DIR", dir.path())
        .arg("vault")
        .arg("benchmark")
        .arg("--iterations")
        .arg("10")
        .arg("--chunk-size")
        .arg("4096")
        .arg("--json")
        .output()
        .expect("execute velcrux vault benchmark --json");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("parse benchmark JSON");

    assert_eq!(json["iterations"], 10);
    assert_eq!(json["chunk_size_bytes"], 4096);
    assert_eq!(json["kem_algorithm"], "ML-KEM-768");
    assert_eq!(json["sig_algorithm"], "ML-DSA-65");
    assert!(json["kem_encap_latency_us"].as_f64().unwrap() > 0.0);
    assert!(json["kem_decap_latency_us"].as_f64().unwrap() > 0.0);
    assert!(json["dsa_sign_latency_us"].as_f64().unwrap() > 0.0);
    assert!(json["dsa_verify_latency_us"].as_f64().unwrap() > 0.0);
    assert!(json["aead_seal_throughput_mb_s"].as_f64().unwrap() > 0.0);
    assert!(json["aead_unseal_throughput_mb_s"].as_f64().unwrap() > 0.0);
}
