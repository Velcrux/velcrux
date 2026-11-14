//! CLI Integration tests for Option DJ: Autonomous Zero-Copy User-Space Storage Engine via `io_uring` Kernel Ring Buffers (`ADR-078`).

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
fn test_cli_ioring_status_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("ioring")
        .arg("status")
        .output()
        .expect("execute ioring status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX IO_URING AUTONOMOUS ZERO-COPY STORAGE ENGINE STATUS"));
    assert!(stdout.contains("Submission Queue (SQ):"));
    assert!(stdout.contains("Capacity:             256 entries"));
    assert!(stdout.contains("Completion Queue (CQ):"));
    assert!(stdout.contains("Capacity:             512 entries"));
    assert!(stdout.contains("Kernel SQPOLL Worker Mode:"));
    assert!(stdout.contains("Enabled:              true"));
    assert!(stdout.contains("Worker State:         polling"));
    assert!(stdout.contains("Fixed Buffer Registry (IORING_REGISTER_BUFFERS):"));
    assert!(stdout.contains("Registered Buffers:   3"));
    assert!(stdout.contains("Direct Zero-Copy Splice Pipelining (IORING_OP_SPLICE / TEE):"));
    assert!(stdout.contains("Active Pipe Channels: 2"));

    // 2. JSON mode
    let json_out = Command::new(velcrux_bin())
        .arg("ioring")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute ioring status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse ioring status json");
    assert!(val["engine_initialized"].as_bool().unwrap());
    assert_eq!(val["sq_capacity"].as_u64().unwrap(), 256);
    assert_eq!(val["cq_capacity"].as_u64().unwrap(), 512);
    assert!(val["sqpoll_enabled"].as_bool().unwrap());
    assert_eq!(val["registered_buffers_count"].as_u64().unwrap(), 3);
    assert_eq!(val["active_splice_channels"].as_u64().unwrap(), 2);
    assert_eq!(val["buffers"].as_array().unwrap().len(), 3);
    assert_eq!(val["splice_channels"].as_array().unwrap().len(), 2);
}

#[test]
fn test_cli_ioring_probe_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("ioring")
        .arg("probe")
        .output()
        .expect("execute ioring probe");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX IO_URING KERNEL SUBSYSTEM CAPABILITY & FEATURE PROBE"));
    assert!(stdout.contains("Host Kernel Target:     Linux 6.8.0-velcrux-iouring"));
    assert!(stdout.contains("Supported Opcodes:      49 / 49 probed standard opcodes"));
    assert!(stdout.contains("IORING_FEAT_SINGLE_MMAP"));
    assert!(stdout.contains("IORING_FEAT_NODROP"));
    assert!(stdout.contains("IORING_FEAT_FAST_POLL"));
    assert!(stdout.contains("IORING_FEAT_SQPOLL_NONFIXED"));
    assert!(stdout.contains("Kernel Pipe Direct Splicing (IORING_OP_SPLICE)"));
    assert!(stdout.contains("Pre-Registered Page-Locked Buffers (IORING_REGISTER_BUFFERS)"));

    // 2. JSON mode
    let json_out = Command::new(velcrux_bin())
        .arg("ioring")
        .arg("probe")
        .arg("--json")
        .output()
        .expect("execute ioring probe json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse ioring probe json");
    assert_eq!(
        val["kernel_version"].as_str().unwrap(),
        "Linux 6.8.0-velcrux-iouring"
    );
    assert_eq!(val["supported_opcodes_count"].as_u64().unwrap(), 49);
    assert!(val["active_features"].as_array().unwrap().len() >= 6);
    assert_eq!(val["zero_copy_capabilities"].as_array().unwrap().len(), 5);
}

#[test]
fn test_cli_ioring_benchmark_text_and_json() {
    // 1. Text mode standard
    let output = Command::new(velcrux_bin())
        .arg("ioring")
        .arg("benchmark")
        .arg("--entries")
        .arg("128")
        .arg("--ops")
        .arg("200")
        .output()
        .expect("execute ioring benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX IO_URING ZERO-COPY STORAGE ENGINE BENCHMARK"));
    assert!(stdout.contains("Ring Entry Capacity:    128 SQEs"));
    assert!(stdout.contains("Operations Executed:    200 ops"));
    assert!(stdout.contains("Kernel SQPOLL Mode:     false"));
    assert!(stdout.contains("I/O Operations / Sec:"));

    // 2. JSON mode with SQPOLL enabled
    let json_out = Command::new(velcrux_bin())
        .arg("ioring")
        .arg("benchmark")
        .arg("--entries")
        .arg("256")
        .arg("--ops")
        .arg("300")
        .arg("--sqpoll")
        .arg("--json")
        .output()
        .expect("execute ioring benchmark json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse ioring benchmark json");
    assert_eq!(val["entries"].as_u64().unwrap(), 256);
    assert_eq!(val["operations"].as_u64().unwrap(), 300);
    assert!(val["sqpoll"].as_bool().unwrap());
    assert!(val["iops"].as_f64().unwrap() > 0.0);
    assert!(val["throughput_mb_s"].as_f64().unwrap() > 0.0);
}
