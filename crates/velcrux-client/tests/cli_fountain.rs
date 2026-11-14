//! CLI Integration tests for Option DN: Dynamic Rateless Fountain Coding
//! & Loss-Resilient Erasure Streaming Engine (`ADR-082`).

#![forbid(unsafe_code)]

use std::fs;
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
fn test_cli_fountain_status_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("status")
        .output()
        .expect("execute fountain status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX RATELESS FOUNTAIN & ERASURE STREAMING ENGINE"));
    assert!(stdout.contains("ACTIVE (Pure Safe Rust Rateless Luby / Soliton Fountain)"));
    assert!(stdout.contains("Robust Soliton CDF"));
    assert!(stdout.contains("Linear Peeling Solver"));
    assert!(stdout.contains("Gaussian Elimination Over GF(2)"));
    assert!(stdout.contains("VFT1"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute fountain status --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert!(parsed["engine_status"].as_str().unwrap().contains("ACTIVE"));
    assert_eq!(parsed["default_symbol_size_bytes"], 1024);
    assert_eq!(
        parsed["container_format_version"],
        "VFT1 (Velcrux Fountain Container v1)"
    );
}

#[test]
fn test_cli_fountain_encode_and_decode_cycle() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("source.dat");
    let container_path = temp_dir.path().join("source.vft");
    let restored_path = temp_dir.path().join("restored.dat");

    // Create 32 KiB test pattern
    let mut test_data = Vec::with_capacity(32 * 1024);
    for i in 0..(32 * 1024) {
        test_data.push((i * 17 % 251) as u8);
    }
    fs::write(&input_path, &test_data).expect("write test input");

    // 1. Encode with CLI
    let encode_out = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("encode")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&container_path)
        .arg("--symbol-size")
        .arg("512")
        .output()
        .expect("execute fountain encode");

    assert!(
        encode_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&encode_out.stderr)
    );

    let stdout_enc = String::from_utf8_lossy(&encode_out.stdout);
    assert!(stdout_enc.contains("FOUNTAIN ENCODING & CONTAINER PACKAGING COMPLETED"));
    assert!(stdout_enc.contains("Source Symbols (K):     64 blocks"));
    assert!(container_path.exists());

    // 2. Decode with CLI
    let decode_out = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("decode")
        .arg("--input")
        .arg(&container_path)
        .arg("--output")
        .arg(&restored_path)
        .output()
        .expect("execute fountain decode");

    assert!(
        decode_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&decode_out.stderr)
    );

    let stdout_dec = String::from_utf8_lossy(&decode_out.stdout);
    assert!(stdout_dec.contains("FOUNTAIN STREAMING RECONSTRUCTION COMPLETED"));
    assert!(stdout_dec.contains("VALIDATED (BLAKE3 OK)"));

    let restored_data = fs::read(&restored_path).expect("read restored data");
    assert_eq!(restored_data, test_data);
}

#[test]
fn test_cli_fountain_loss_sim_resilience() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("loss_test.bin");
    let container_path = temp_dir.path().join("loss_test.vft");
    let output_path = temp_dir.path().join("loss_recovered.bin");

    // Create 16 KiB random payload
    let mut payload = Vec::with_capacity(16 * 1024);
    for i in 0..(16 * 1024) {
        payload.push(((i ^ 0xaa) * 31 % 256) as u8);
    }
    fs::write(&input_path, &payload).expect("write payload");

    // Encode with 25% simulated packet loss and 1.8 repair multiplier
    let encode_out = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("encode")
        .arg("--input")
        .arg(&input_path)
        .arg("--output")
        .arg(&container_path)
        .arg("--symbol-size")
        .arg("256")
        .arg("--loss-sim")
        .arg("0.25")
        .arg("--repair-overhead")
        .arg("1.80")
        .arg("--json")
        .output()
        .expect("execute fountain encode with loss-sim");

    assert!(
        encode_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&encode_out.stderr)
    );

    let enc_json: serde_json::Value =
        serde_json::from_slice(&encode_out.stdout).expect("parse encode json");
    assert_eq!(enc_json["simulated_loss_rate"], 0.25);
    assert!(enc_json["surviving_symbols"].as_u64().unwrap() >= 64);

    // Decode recovered container
    let decode_out = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("decode")
        .arg("--input")
        .arg(&container_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--json")
        .output()
        .expect("execute fountain decode");

    assert!(
        decode_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&decode_out.stderr)
    );

    let dec_json: serde_json::Value =
        serde_json::from_slice(&decode_out.stdout).expect("parse decode json");
    assert_eq!(dec_json["blake3_verified"], true);
    assert_eq!(dec_json["reconstructed_bytes"], 16 * 1024);

    let restored = fs::read(&output_path).expect("read output file");
    assert_eq!(restored, payload);
}

#[test]
fn test_cli_fountain_benchmark_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("benchmark")
        .arg("--symbols")
        .arg("30")
        .arg("--symbol-size")
        .arg("256")
        .arg("--loss-rate")
        .arg("0.20")
        .output()
        .expect("execute fountain benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FOUNTAIN CODEC & ERASURE RECOVERY PERFORMANCE BENCHMARK"));
    assert!(stdout.contains("Source Symbols (K):     30 symbols"));
    assert!(stdout.contains("Simulated Loss Rate:    20.0%"));
    assert!(stdout.contains("BLAKE3 Integrity:       VALIDATED"));
    assert!(stdout.contains("Erasure Recovery:       SUCCESSFUL"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("fountain")
        .arg("benchmark")
        .arg("--symbols")
        .arg("25")
        .arg("--symbol-size")
        .arg("128")
        .arg("--loss-rate")
        .arg("0.15")
        .arg("--json")
        .output()
        .expect("execute fountain benchmark --json");

    assert!(
        output_json.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output_json.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("parse json benchmark");
    assert_eq!(parsed["k_source_symbols"], 25);
    assert_eq!(parsed["symbol_size_bytes"], 128);
    assert_eq!(parsed["blake3_match"], true);
    assert!(parsed["encode_throughput_mb_s"].as_f64().unwrap() > 0.0);
    assert!(parsed["decode_throughput_mb_s"].as_f64().unwrap() > 0.0);
}
