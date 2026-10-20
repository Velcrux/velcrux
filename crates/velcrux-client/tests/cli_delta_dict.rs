//! Integration tests for Option BQ: Content-Aware Delta Compression Engine
//! with Zstd Dictionary Training & CDC Slicing (`ADR-033`).

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
fn test_cli_delta_slice_test_command() {
    let tmp = tempdir().unwrap();
    let baseline_path = tmp.path().join("baseline.log");
    let source_path = tmp.path().join("target.log");

    // Create realistic structured log data
    let base_content = "2026-10-20T10:00:00.000Z [INFO] request_id=req_1001 user=alice status=200 duration_ms=42\n".repeat(400);
    let target_content =
        "2026-10-20T10:00:00.000Z [INFO] request_id=req_1002 user=bob status=200 duration_ms=45\n"
            .repeat(400);

    fs::write(&baseline_path, &base_content).unwrap();
    fs::write(&source_path, &target_content).unwrap();

    // 1. Text table output
    let output = Command::new(velcrux_bin())
        .arg("delta-slice")
        .arg("test")
        .arg(&source_path)
        .arg(&baseline_path)
        .arg("--chunk-size")
        .arg("4096")
        .arg("--policy")
        .arg("auto")
        .arg("--threshold")
        .arg("10")
        .output()
        .expect("execute delta-slice test");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Delta Slice Evaluation Report ==="));
    assert!(stdout.contains("Source File:"));
    assert!(stdout.contains("Baseline File:"));
    assert!(stdout.contains("Chunk Slicing Size:      4096 bytes"));
    assert!(stdout.contains("Delta Policy:            auto"));
    assert!(stdout.contains("Compression Ratio:"));
    assert!(stdout.contains("Dict Compressed Chunks:"));

    // 2. JSON output
    let json_output = Command::new(velcrux_bin())
        .arg("delta-slice")
        .arg("test")
        .arg(&source_path)
        .arg(&baseline_path)
        .arg("--chunk-size")
        .arg("4096")
        .arg("--json")
        .output()
        .expect("execute delta-slice test json");

    assert!(json_output.status.success());
    let json_val: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("valid json");
    assert!(json_val["bytes_saved"].as_u64().unwrap() > 0);
    assert!(json_val["compression_ratio"].as_f64().unwrap() > 1.5);
    assert!(json_val["dict_compressed_chunks"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_sync_delta_dict_compression() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    // Baseline file with 256 KiB of repeated code/config
    let file_src = src.join("app_config.json");
    let line = "{\"service\":\"auth\",\"endpoint\":\"/api/v1/tokens\",\"timeout_ms\":5000,\"retries\":3}\n";
    let base_text = line.repeat(3000);
    fs::write(&file_src, &base_text).unwrap();

    // Initial sync to establish baseline on destination
    let initial_sync = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .output()
        .expect("initial sync");
    assert!(initial_sync.status.success());

    // Modify file with small local edits across chunks
    let modified_line = "{\"service\":\"auth\",\"endpoint\":\"/api/v2/tokens\",\"timeout_ms\":6000,\"retries\":5}\n";
    let mut modified_text = line.repeat(1500);
    modified_text.push_str(&modified_line.repeat(500));
    modified_text.push_str(&line.repeat(1000));
    fs::write(&file_src, &modified_text).unwrap();

    // Run sync with --delta-dict auto
    let delta_sync = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .arg("--delta-dict")
        .arg("auto")
        .arg("--delta-dict-threshold")
        .arg("10")
        .output()
        .expect("delta sync");

    assert!(
        delta_sync.status.success(),
        "sync failed: {:?}",
        String::from_utf8_lossy(&delta_sync.stderr)
    );

    // Verify bit-exact fidelity of reconstructed file
    let dst_file = dst.join("app_config.json");
    assert!(dst_file.exists());
    let dst_content = fs::read(&dst_file).unwrap();
    assert_eq!(dst_content, modified_text.as_bytes());
}

#[test]
fn test_cli_sync_delta_dict_off() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    let file_src = src.join("data.txt");
    fs::write(&file_src, b"hello baseline world").unwrap();

    let sync_off = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .arg("--delta-dict")
        .arg("off")
        .output()
        .expect("sync with delta-dict off");

    assert!(sync_off.status.success());
    let dst_file = dst.join("data.txt");
    assert_eq!(fs::read(&dst_file).unwrap(), b"hello baseline world");
}

#[test]
fn test_cli_sync_delta_dict_aggressive() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    let file_src = src.join("code.rs");
    let text = "pub fn execute_operation() -> Result<(), Error> {\n    Ok(())\n}\n".repeat(500);
    fs::write(&file_src, &text).unwrap();

    let sync1 = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .output()
        .expect("sync1");
    assert!(sync1.status.success());

    // Small modification
    let mod_text = "pub fn execute_operation() -> Result<(), Error> {\n    println!(\"debug\");\n    Ok(())\n}\n".repeat(500);
    fs::write(&file_src, &mod_text).unwrap();

    let sync2 = Command::new(velcrux_bin())
        .arg("sync")
        .arg(&src)
        .arg(&dst)
        .arg("--delta-dict")
        .arg("aggressive")
        .arg("--delta-dict-threshold")
        .arg("5")
        .output()
        .expect("sync2");
    assert!(sync2.status.success());

    let dst_file = dst.join("code.rs");
    assert_eq!(fs::read(&dst_file).unwrap(), mod_text.as_bytes());
}
