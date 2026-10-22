//! Integration tests for Option BS: Zero-Copy Kernel Direct I/O (`O_DIRECT` / `F_NOCACHE`)
//! Ring-Buffer Pipeline (`ADR-035`).

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
fn test_cli_direct_io_inspect_text_and_json() {
    let temp = tempdir().unwrap();
    let test_file = temp.path().join("sample_direct.bin");
    fs::write(&test_file, vec![0xABu8; 1024 * 1024]).expect("write sample file");

    // 1. Text output without path
    let output = Command::new(velcrux_bin())
        .arg("direct-io")
        .arg("inspect")
        .output()
        .expect("execute direct-io inspect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Direct I/O Ring-Buffer Pipeline Configuration ==="));
    assert!(stdout.contains("Execution Mode:          auto"));
    assert!(stdout.contains("Ring Buffer Slots:       4"));
    assert!(stdout.contains("Physical Sector Size:    4096 bytes"));

    // 2. JSON output with path
    let json_out = Command::new(velcrux_bin())
        .arg("direct-io")
        .arg("inspect")
        .arg("--path")
        .arg(test_file.to_str().unwrap())
        .arg("--json")
        .output()
        .expect("execute direct-io inspect json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse direct-io inspect json");
    assert_eq!(val["direct_io_mode"].as_str().unwrap(), "auto");
    assert_eq!(val["ring_slots"].as_u64().unwrap(), 4);
    assert_eq!(val["sector_size_bytes"].as_u64().unwrap(), 4096);
    assert!(val["file_exists"].as_bool().unwrap());
    assert_eq!(val["file_size_bytes"].as_u64().unwrap(), 1024 * 1024);
}

#[test]
fn test_cli_direct_io_benchmark_roundtrip() {
    let temp = tempdir().unwrap();
    let test_file = temp.path().join("bench_roundtrip.bin");

    let test_size: u64 = 8 * 1024 * 1024; // 8 MiB

    let json_out = Command::new(velcrux_bin())
        .arg("direct-io")
        .arg("benchmark")
        .arg("--path")
        .arg(test_file.to_str().unwrap())
        .arg("--size")
        .arg(test_size.to_string())
        .arg("--json")
        .output()
        .expect("execute direct-io benchmark json");

    assert!(
        json_out.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&json_out.stderr)
    );

    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse benchmark json");
    assert_eq!(val["total_bytes"].as_u64().unwrap(), test_size);
    assert_eq!(val["ring_slots"].as_u64().unwrap(), 4);
    assert!(val["data_integrity_verified"].as_bool().unwrap());
    assert!(!val["checksum_blake3"].as_str().unwrap().is_empty());
    assert!(val["write_throughput_mb_s"].as_f64().unwrap() > 0.0);
    assert!(val["read_throughput_mb_s"].as_f64().unwrap() > 0.0);
}

#[test]
fn test_cli_direct_io_custom_ring_slots_and_sizes() {
    let temp = tempdir().unwrap();
    let test_file = temp.path().join("bench_custom.bin");

    let test_size: u64 = 4 * 1024 * 1024; // 4 MiB

    let output = Command::new(velcrux_bin())
        .arg("direct-io")
        .arg("benchmark")
        .arg("--path")
        .arg(test_file.to_str().unwrap())
        .arg("--size")
        .arg(test_size.to_string())
        .arg("--slots")
        .arg("6")
        .arg("--slot-size")
        .arg("1048576")
        .output()
        .expect("execute direct-io benchmark custom");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Direct I/O Ring-Buffer Pipeline Benchmark ==="));
    assert!(stdout.contains("6 slots × 1048576 (1.00 MB)"));
    assert!(stdout.contains("PASS (BLAKE3 exact match)"));
}

#[test]
fn test_cli_direct_io_unaligned_tail_truncation_benchmark() {
    let temp = tempdir().unwrap();
    let test_file = temp.path().join("bench_unaligned.bin");

    // Unaligned size with fractional tail
    let unaligned_size: u64 = 3_141_592;

    let json_out = Command::new(velcrux_bin())
        .arg("direct-io")
        .arg("benchmark")
        .arg("--path")
        .arg(test_file.to_str().unwrap())
        .arg("--size")
        .arg(unaligned_size.to_string())
        .arg("--json")
        .output()
        .expect("execute direct-io benchmark unaligned");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse benchmark json");
    assert_eq!(val["total_bytes"].as_u64().unwrap(), unaligned_size);
    assert!(val["data_integrity_verified"].as_bool().unwrap());

    // Verify physical file length exactly matches unaligned_size
    let meta = fs::metadata(&test_file).expect("file metadata");
    assert_eq!(meta.len(), unaligned_size);
}
