//! Integration tests for Option CI: Self-Healing Distributed Erasure Coding
//! and Autonomous Shard Scrub Mesh (`ADR-051`).

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
fn test_cli_ec_status_human() {
    let output = Command::new(velcrux_bin())
        .arg("ec")
        .arg("status")
        .output()
        .expect("execute velcrux ec status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("=== Distributed Erasure Coding & Shard Scrub Mesh Status ==="));
    assert!(stdout.contains("Default Schema:         4+2 (K=4 data, M=2 parity)"));
    assert!(
        stdout.contains("Finite Field / Matrix:  Galois Field GF(2^8) with Cauchy MDS Generator")
    );
    assert!(stdout.contains("Encoded Shards:"));
    assert!(stdout.contains("Repaired Shards:"));
    assert!(stdout.contains("Scrubbed Shards:"));
    assert!(stdout.contains("Corrupted Shards:"));
    assert!(stdout.contains("Degraded Objects:"));
}

#[test]
fn test_cli_ec_status_json() {
    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("ec")
        .arg("status")
        .output()
        .expect("execute velcrux --json ec status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON expected from --json ec status");

    assert!(json_val["default_schema"].as_str().unwrap().contains("4+2"));
    assert!(json_val["supported_finite_field"]
        .as_str()
        .unwrap()
        .contains("GF(2^8)"));
    assert!(json_val["ec_encoded_shards_total"].is_number());
    assert!(json_val["ec_repaired_shards_total"].is_number());
}

#[test]
fn test_cli_ec_encode_and_decode_roundtrip() {
    let dir = tempdir().expect("create temp dir");
    let input_file = dir.path().join("original.dat");
    let shards_dir = dir.path().join("shards");
    let output_file = dir.path().join("restored.dat");

    let test_data =
        b"Distributed Self-Healing Erasure Coding Test Payload with Velcrux VEC1 Envelopes!";
    fs::write(&input_file, test_data).expect("write original file");

    // 1. Encode into 4+2 shards
    let encode_output = Command::new(velcrux_bin())
        .arg("ec")
        .arg("encode")
        .arg("--input")
        .arg(&input_file)
        .arg("--out-dir")
        .arg(&shards_dir)
        .arg("-k")
        .arg("4")
        .arg("-m")
        .arg("2")
        .arg("--object-id")
        .arg("obj-test-roundtrip")
        .output()
        .expect("execute ec encode");

    assert!(
        encode_output.status.success(),
        "encode failed: {:?}",
        String::from_utf8_lossy(&encode_output.stderr)
    );

    // Verify 6 shards were produced
    let shard_files: Vec<_> = fs::read_dir(&shards_dir)
        .expect("read shards dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(shard_files.len(), 6);

    // 2. Decode back to restored.dat
    let decode_output = Command::new(velcrux_bin())
        .arg("ec")
        .arg("decode")
        .arg("--shards-dir")
        .arg(&shards_dir)
        .arg("--output")
        .arg(&output_file)
        .output()
        .expect("execute ec decode");

    assert!(
        decode_output.status.success(),
        "decode failed: {:?}",
        String::from_utf8_lossy(&decode_output.stderr)
    );

    let restored_data = fs::read(&output_file).expect("read restored file");
    assert_eq!(restored_data, test_data);
}

#[test]
fn test_cli_ec_decode_with_missing_data_shards() {
    let dir = tempdir().expect("create temp dir");
    let input_file = dir.path().join("mission_critical.bin");
    let shards_dir = dir.path().join("shards");
    let output_file = dir.path().join("reconstructed.bin");

    let mut sample_payload = Vec::new();
    for i in 0..16384 {
        sample_payload.push((i % 251) as u8);
    }
    fs::write(&input_file, &sample_payload).expect("write mission critical file");

    // Encode 4+2
    let encode_res = Command::new(velcrux_bin())
        .arg("ec")
        .arg("encode")
        .arg("--input")
        .arg(&input_file)
        .arg("--out-dir")
        .arg(&shards_dir)
        .arg("-k")
        .arg("4")
        .arg("-m")
        .arg("2")
        .arg("--object-id")
        .arg("obj-mission-critical")
        .output()
        .expect("encode");
    assert!(encode_res.status.success());

    // Delete 2 data shards: shard 0 and shard 1
    let shard0 = shards_dir.join("obj-mission-critical.shard.0");
    let shard1 = shards_dir.join("obj-mission-critical.shard.1");
    fs::remove_file(shard0).expect("remove shard 0");
    fs::remove_file(shard1).expect("remove shard 1");

    // Decode: should use shards 2, 3 (data) and 4, 5 (parity) to reconstruct via Cauchy matrix inversion
    let decode_res = Command::new(velcrux_bin())
        .arg("ec")
        .arg("decode")
        .arg("--shards-dir")
        .arg(&shards_dir)
        .arg("--output")
        .arg(&output_file)
        .output()
        .expect("decode");

    assert!(
        decode_res.status.success(),
        "decode failed: {:?}",
        String::from_utf8_lossy(&decode_res.stderr)
    );

    let reconstructed = fs::read(&output_file).expect("read reconstructed file");
    assert_eq!(reconstructed, sample_payload);
}

#[test]
fn test_cli_ec_scrub_detect_and_auto_repair() {
    let dir = tempdir().expect("create temp dir");
    let input_file = dir.path().join("vault.db");
    let shards_dir = dir.path().join("shards");

    let payload = b"Deep secure storage payload requiring scrubbing and self-repairing mesh";
    fs::write(&input_file, payload).expect("write vault.db");

    // Encode 4+2
    let enc = Command::new(velcrux_bin())
        .arg("ec")
        .arg("encode")
        .arg("--input")
        .arg(&input_file)
        .arg("--out-dir")
        .arg(&shards_dir)
        .arg("-k")
        .arg("4")
        .arg("-m")
        .arg("2")
        .arg("--object-id")
        .arg("obj-scrub-vault")
        .output()
        .expect("encode");
    assert!(enc.status.success());

    // Corrupt shard 1 by flipping bytes at payload offset
    let s1_path = shards_dir.join("obj-scrub-vault.shard.1");
    let mut s1_bytes = fs::read(&s1_path).expect("read shard 1");
    let last = s1_bytes.len() - 1;
    s1_bytes[last] ^= 0xff;
    fs::write(&s1_path, s1_bytes).expect("write corrupted shard 1");

    // Delete shard 5 (parity shard)
    let s5_path = shards_dir.join("obj-scrub-vault.shard.5");
    fs::remove_file(&s5_path).expect("delete shard 5");

    // Run scrub in scan-only mode
    let scrub_scan = Command::new(velcrux_bin())
        .arg("ec")
        .arg("scrub")
        .arg("--shards-dir")
        .arg(&shards_dir)
        .output()
        .expect("scrub scan");

    assert!(scrub_scan.status.success());
    let scan_out = String::from_utf8_lossy(&scrub_scan.stdout);
    assert!(scan_out.contains("Critical Objects:       1"));
    assert!(scan_out.contains("Corrupted Shards:       1"));

    // Run scrub with --auto-repair
    let scrub_repair = Command::new(velcrux_bin())
        .arg("ec")
        .arg("scrub")
        .arg("--shards-dir")
        .arg(&shards_dir)
        .arg("--auto-repair")
        .output()
        .expect("scrub auto repair");

    assert!(
        scrub_repair.status.success(),
        "repair failed: {:?}",
        String::from_utf8_lossy(&scrub_repair.stderr)
    );
    let repair_out = String::from_utf8_lossy(&scrub_repair.stdout);
    assert!(repair_out.contains("=== Erasure Coding Autonomous Shard Scrub & Repair ==="));
    assert!(repair_out.contains("Shards Reconstructed:   2"));

    // Run scrub again: should now be 100% healthy
    let scrub_verify = Command::new(velcrux_bin())
        .arg("--json")
        .arg("ec")
        .arg("scrub")
        .arg("--shards-dir")
        .arg(&shards_dir)
        .output()
        .expect("scrub verify");

    assert!(scrub_verify.status.success());
    let verify_val: serde_json::Value =
        serde_json::from_slice(&scrub_verify.stdout).expect("valid json scrub report");
    assert_eq!(verify_val["healthy_objects"], 1);
    assert_eq!(verify_val["degraded_objects"], 0);
    assert_eq!(verify_val["corrupted_shards"], 0);

    // Verify decode succeeds cleanly after repair
    let out_file = dir.path().join("vault_restored.db");
    let decode_after = Command::new(velcrux_bin())
        .arg("ec")
        .arg("decode")
        .arg("--shards-dir")
        .arg(&shards_dir)
        .arg("--output")
        .arg(&out_file)
        .output()
        .expect("decode after repair");
    assert!(decode_after.status.success());
    assert_eq!(fs::read(out_file).unwrap(), payload);
}

#[test]
fn test_cli_ec_scrub_unrecoverable() {
    let dir = tempdir().expect("create temp dir");
    let input_file = dir.path().join("unrecoverable.bin");
    let shards_dir = dir.path().join("shards");

    fs::write(&input_file, b"Unrecoverable test data payload").expect("write input");

    // Encode 4+2
    let enc = Command::new(velcrux_bin())
        .arg("ec")
        .arg("encode")
        .arg("--input")
        .arg(&input_file)
        .arg("--out-dir")
        .arg(&shards_dir)
        .arg("-k")
        .arg("4")
        .arg("-m")
        .arg("2")
        .arg("--object-id")
        .arg("obj-unrecoverable")
        .output()
        .expect("encode");
    assert!(enc.status.success());

    // Delete 3 shards (exceeding M=2)
    fs::remove_file(shards_dir.join("obj-unrecoverable.shard.0")).unwrap();
    fs::remove_file(shards_dir.join("obj-unrecoverable.shard.1")).unwrap();
    fs::remove_file(shards_dir.join("obj-unrecoverable.shard.2")).unwrap();

    // Run scrub
    let scrub_res = Command::new(velcrux_bin())
        .arg("--json")
        .arg("ec")
        .arg("scrub")
        .arg("--shards-dir")
        .arg(&shards_dir)
        .output()
        .expect("scrub");

    assert!(scrub_res.status.success());
    let val: serde_json::Value = serde_json::from_slice(&scrub_res.stdout).unwrap();
    assert_eq!(val["unrecoverable_objects"], 1);
}

#[test]
fn test_cli_ec_benchmark_human_and_json() {
    let output = Command::new(velcrux_bin())
        .arg("ec")
        .arg("benchmark")
        .arg("--size")
        .arg("65536")
        .arg("--iterations")
        .arg("10")
        .output()
        .expect("benchmark human");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Erasure Coding & Self-Healing Benchmark"));
    assert!(stdout.contains("Encoding Latency:"));
    assert!(stdout.contains("Decoding Latency:"));
    assert!(stdout.contains("Single-Shard Repair:"));

    let json_output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("ec")
        .arg("benchmark")
        .arg("--size")
        .arg("32768")
        .arg("--iterations")
        .arg("10")
        .output()
        .expect("benchmark json");

    assert!(
        json_output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let json_val: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(json_val["schema"]["data_shards"], 4);
    assert_eq!(json_val["schema"]["parity_shards"], 2);
    assert!(
        json_val["encode_throughput_bytes_per_sec"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    assert!(
        json_val["decode_throughput_bytes_per_sec"]
            .as_f64()
            .unwrap()
            > 0.0
    );
}
