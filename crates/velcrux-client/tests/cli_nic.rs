//! CLI Integration tests for Option DO: Autonomous Zero-Copy QUIC Kernel-Bypass
//! Direct NIC Memory Fabric (AF_XDP / UMEM) (ADR-083).

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
fn test_cli_nic_status_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("nic")
        .arg("status")
        .arg("--interface")
        .arg("eth0")
        .output()
        .expect("execute nic status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VELCRUX ZERO-COPY QUIC KERNEL-BYPASS DIRECT NIC MEMORY FABRIC"));
    assert!(stdout.contains("Interface:              eth0"));
    assert!(stdout.contains("ZeroCopyDriver"));
    assert!(stdout.contains("ACTIVE (DMA Direct into UMEM)"));
    assert!(stdout.contains("UMEM Memory Pool:       4096 frames"));

    // 2. Hardware offload mode
    let output_hw = Command::new(velcrux_bin())
        .arg("nic")
        .arg("status")
        .arg("--mode")
        .arg("hardware")
        .output()
        .expect("execute nic status --mode hardware");

    assert!(output_hw.status.success());
    let stdout_hw = String::from_utf8_lossy(&output_hw.stdout);
    assert!(stdout_hw.contains("HardwareOffloadAsic"));

    // 3. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("nic")
        .arg("status")
        .arg("--interface")
        .arg("eth0")
        .arg("--json")
        .output()
        .expect("execute nic status --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["interface_name"], "eth0");
    assert_eq!(parsed["driver_mode"], "ZeroCopyDriver");
    assert_eq!(parsed["zero_copy_active"], true);
    assert_eq!(parsed["umem_total_frames"], 4096);
}

#[test]
fn test_cli_nic_pools_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("nic")
        .arg("pools")
        .arg("--interface")
        .arg("vlx-nic0")
        .output()
        .expect("execute nic pools");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("UMEM USER-SPACE CONTIGUOUS MEMORY POOL CONFIGURATION"));
    assert!(stdout.contains("Interface:              vlx-nic0"));
    assert!(stdout.contains("Total Sliced Frames:    4096 frames"));
    assert!(stdout.contains("Frame Buffer Size:      2048 bytes"));
    assert!(stdout.contains("Headroom Prefix:        256 bytes (XDP_HEADROOM)"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("nic")
        .arg("pools")
        .arg("--json")
        .output()
        .expect("execute nic pools --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["total_frames"], 4096);
    assert_eq!(parsed["frame_size_bytes"], 2048);
    assert_eq!(parsed["headroom_bytes"], 256);
}

#[test]
fn test_cli_nic_rings_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("nic")
        .arg("rings")
        .output()
        .expect("execute nic rings");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AF_XDP SPSC LOCKLESS CIRCULAR DESCRIPTOR RINGS"));
    assert!(stdout.contains("fill_ring"));
    assert!(stdout.contains("rx_ring"));
    assert!(stdout.contains("tx_ring"));
    assert!(stdout.contains("completion_ring"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("nic")
        .arg("rings")
        .arg("--json")
        .output()
        .expect("execute nic rings --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    let rings = parsed.as_array().expect("array of rings");
    assert_eq!(rings.len(), 4);
    assert_eq!(rings[0]["ring_name"], "fill_ring");
    assert_eq!(rings[0]["capacity"], 1024);
}

#[test]
fn test_cli_nic_benchmark_text_and_json() {
    // 1. Text mode
    let output = Command::new(velcrux_bin())
        .arg("nic")
        .arg("benchmark")
        .arg("--frames")
        .arg("256")
        .arg("--frame-size")
        .arg("2048")
        .arg("--iterations")
        .arg("25")
        .output()
        .expect("execute nic benchmark");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("NIC ZERO-COPY KERNEL-BYPASS LINE-RATE PERFORMANCE BENCHMARK"));
    assert!(stdout.contains("Target Interface:       vlx-nic0"));
    assert!(stdout.contains("ZeroCopyDriver"));
    assert!(stdout.contains("Total Packets Cycled:   800 packets")); // 25 * 32 = 800
    assert!(stdout.contains("Zero-Copy Efficiency:   100.0%"));

    // 2. JSON mode
    let output_json = Command::new(velcrux_bin())
        .arg("nic")
        .arg("benchmark")
        .arg("--frames")
        .arg("128")
        .arg("--iterations")
        .arg("10")
        .arg("--json")
        .output()
        .expect("execute nic benchmark --json");

    assert!(output_json.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output_json.stdout).expect("valid json output");
    assert_eq!(parsed["packets_processed"], 320); // 10 * 32 = 320
    assert!(parsed["throughput_mpps"].as_f64().unwrap() > 0.0);
    assert!(parsed["throughput_gbps"].as_f64().unwrap() > 0.0);
    assert_eq!(parsed["zero_copy_efficiency_percent"], 100.0);
    assert_eq!(parsed["frame_reuse_ratio"], 1.0);
}
