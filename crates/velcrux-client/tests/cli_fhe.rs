//! CLI Integration tests for Option DP: Distributed Homomorphic Encrypted
//! Query & Search Engine over Sharded Storage (ADR-084).

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
fn test_cli_fhe_status_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("status")
        .arg("--degree")
        .arg("1024")
        .output()
        .expect("execute fhe status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Distributed FHE Query & Search Engine Status (ADR-084)"));
    assert!(stdout.contains("Polynomial Degree N:    1024"));
    assert!(stdout.contains("Plain Modulus t:        65537"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute fhe status --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON status");
    assert_eq!(parsed["poly_degree"], 1024);
    assert_eq!(parsed["plain_modulus"], 65537);
}

#[test]
fn test_cli_fhe_keygen_and_file_export() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let key_file = temp_dir.path().join("fhe_keypair.json");

    // 1. Keygen with output file
    let output = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("keygen")
        .arg("--degree")
        .arg("256")
        .arg("--plaintext-modulus")
        .arg("65537")
        .arg("--output")
        .arg(&key_file)
        .output()
        .expect("execute fhe keygen");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BFV Homomorphic Encryption Keypair Generated"));
    assert!(stdout.contains("Polynomial Degree N:    256"));
    assert!(key_file.exists());

    // 2. Keygen with JSON output
    let output_json = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("keygen")
        .arg("--degree")
        .arg("128")
        .arg("--json")
        .output()
        .expect("execute fhe keygen --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON keypair");
    assert_eq!(parsed["params"]["poly_degree"], 128);
    assert!(parsed.get("secret_key").is_some());
    assert!(parsed.get("public_key").is_some());
    assert!(parsed.get("relin_key").is_some());
}

#[test]
fn test_cli_fhe_query_execution_text_and_json() {
    // 1. Text mode query
    let output = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("query")
        .arg("--query")
        .arg("size=42")
        .arg("--tenant-id")
        .arg("tenant-cli-test")
        .output()
        .expect("execute fhe query");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Encrypted Query Search Results"));
    assert!(stdout.contains("Predicate:              size=42"));
    assert!(stdout.contains("Target Tenant:          tenant-cli-test"));
    assert!(stdout.contains("Records Scanned:        5 records"));

    // 2. JSON mode query
    let output_json = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("query")
        .arg("--query")
        .arg("42")
        .arg("--json")
        .output()
        .expect("execute fhe query --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON query result");
    assert_eq!(parsed["total_records_scanned"], 5);
    assert!(parsed.get("matching_chunk_ids").is_some());
}

#[test]
fn test_cli_fhe_benchmark_accuracy_and_metrics() {
    // 1. Benchmark text mode
    let output = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("benchmark")
        .arg("--degree")
        .arg("128")
        .arg("--records")
        .arg("12")
        .output()
        .expect("execute fhe benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Distributed FHE & Encrypted Search Benchmark (ADR-084)"));
    assert!(stdout.contains("Quotient Ring Degree N: 128"));
    assert!(stdout.contains("Evaluated Records:      12 records"));
    assert!(stdout.contains("Decryption Accuracy:    100.0%"));

    // 2. Benchmark JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("fhe")
        .arg("benchmark")
        .arg("--degree")
        .arg("128")
        .arg("--records")
        .arg("10")
        .arg("--json")
        .output()
        .expect("execute fhe benchmark --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid JSON benchmark report");
    assert_eq!(parsed["poly_degree"], 128);
    assert_eq!(parsed["records_evaluated"], 10);
    assert_eq!(parsed["decryption_accuracy_percent"], 100.0);
}
