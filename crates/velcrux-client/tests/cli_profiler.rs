#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn velcrux_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // exit test exe
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_profile_help() {
    let output = Command::new(velcrux_bin())
        .arg("profile")
        .arg("--help")
        .output()
        .expect("should run velcrux profile --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("profile") || stdout.contains("bottlenecks"),
        "help text should describe profiling"
    );
    assert!(
        stdout.contains("--chunk-mode"),
        "help text should document --chunk-mode"
    );
}

#[test]
fn test_cli_profile_execution_ascii() {
    let temp_dir = tempdir().unwrap();
    let sample_file = temp_dir.path().join("profile_data.bin");
    {
        let mut f = File::create(&sample_file).unwrap();
        // Write 1 MB of test data
        let buf = [0x5au8; 1024];
        for _ in 0..1024 {
            f.write_all(&buf).unwrap();
        }
    }

    let output = Command::new(velcrux_bin())
        .arg("profile")
        .arg(&sample_file)
        .output()
        .expect("should execute velcrux profile");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX EMPIRICAL PERFORMANCE PROFILE REPORT"));
    assert!(stdout.contains("Storage Read I/O"));
    assert!(stdout.contains("Chunking"));
    assert!(stdout.contains("Cryptographic Hashing"));
    assert!(stdout.contains("Zero-Knowledge Encryption"));
    assert!(stdout.contains("BOTTLENECK DIAGNOSIS"));
}

#[test]
fn test_cli_profile_execution_json() {
    let temp_dir = tempdir().unwrap();
    let sample_file = temp_dir.path().join("profile_json_data.bin");
    {
        let mut f = File::create(&sample_file).unwrap();
        let buf = [0xa5u8; 1024];
        for _ in 0..512 {
            f.write_all(&buf).unwrap();
        }
    }

    let output = Command::new(velcrux_bin())
        .arg("--json")
        .arg("profile")
        .arg(&sample_file)
        .output()
        .expect("should execute velcrux --json profile");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert!(parsed.get("components").is_some());
    assert!(parsed.get("diagnosis").is_some());
    assert!(parsed.get("total_wall_clock_ms").is_some());
    assert!(parsed.get("memory").is_some());
}

#[test]
fn test_cli_profile_fixed_chunk_mode() {
    let temp_dir = tempdir().unwrap();
    let sample_file = temp_dir.path().join("profile_fixed.bin");
    {
        let mut f = File::create(&sample_file).unwrap();
        let buf = [0x7eu8; 1024];
        for _ in 0..256 {
            f.write_all(&buf).unwrap();
        }
    }

    let output = Command::new(velcrux_bin())
        .arg("profile")
        .arg("--chunk-mode")
        .arg("fixed")
        .arg(&sample_file)
        .output()
        .expect("should execute velcrux profile with fixed chunks");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX EMPIRICAL PERFORMANCE PROFILE REPORT"));
}
