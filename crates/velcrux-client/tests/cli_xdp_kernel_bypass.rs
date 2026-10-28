//! Integration tests for Option CC: Hardware-Accelerated FPGA/eBPF
//! Kernel XDP Packet Bypassing & UMEM Zero-Copy Rings (`ADR-045`).

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
fn test_cli_xdp_status_text_and_json() {
    // 1. Human-readable text output
    let output = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("status")
        .arg("--interface")
        .arg("eth0")
        .output()
        .expect("execute xdp status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Hardware-Accelerated eBPF/XDP Kernel Bypass Status ==="));
    assert!(stdout.contains("Interface:              eth0"));
    assert!(stdout.contains("Driver Mode:            NativeDriver"));
    assert!(stdout.contains("UMEM Total Frames:      4096"));
    assert!(stdout.contains("UMEM Frame Size:        2048 bytes"));

    // 2. Hardware offload flag
    let hw_out = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("status")
        .arg("--mode")
        .arg("hardware")
        .output()
        .expect("execute xdp status hardware");

    assert!(hw_out.status.success());
    let hw_stdout = String::from_utf8_lossy(&hw_out.stdout);
    assert!(hw_stdout.contains("Hardware Offload:       ACTIVE (FPGA / SmartNIC)"));

    // 3. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute xdp status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse xdp status json");
    assert_eq!(val["interface"].as_str().unwrap(), "eth0");
    assert_eq!(val["umem_frame_count"].as_u64().unwrap(), 4096);
    assert_eq!(val["umem_frame_size"].as_u64().unwrap(), 2048);
}

#[test]
fn test_cli_xdp_inspect_text_and_json() {
    let packet_hex = "00112233445566778899aabb08004500002e12344000401100007f0000017f00000112341d13001a0000c000000001080102030405060708040a0b0c0d";

    // 1. Human-readable text output
    let output = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("inspect")
        .arg(packet_hex)
        .output()
        .expect("execute xdp inspect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== XDP Wire-Speed Packet Header Inspection ==="));
    assert!(stdout.contains("Ethernet EtherType:     0x0800"));
    assert!(stdout.contains("Source Port:            4660"));
    assert!(stdout.contains("Destination Port:       7443"));
    assert!(stdout.contains("QUIC Connection ID:     0x0102030405060708"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("inspect")
        .arg(packet_hex)
        .arg("--json")
        .output()
        .expect("execute xdp inspect json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse xdp inspect json");
    assert_eq!(val["eth_proto"].as_u64().unwrap(), 0x0800);
    assert_eq!(val["src_port"].as_u64().unwrap(), 4660);
    assert_eq!(val["dst_port"].as_u64().unwrap(), 7443);
    assert_eq!(
        val["quic_connection_id"].as_str().unwrap(),
        "0102030405060708"
    );
}

#[test]
fn test_cli_xdp_rings_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("rings")
        .output()
        .expect("execute xdp rings");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== AF_XDP Zero-Copy UMEM Descriptor Rings ==="));
    assert!(stdout.contains("Total UMEM Frames:      4096"));
    assert!(stdout.contains("Fill Ring Capacity:     1024 entries"));
    assert!(stdout.contains("RX Ring Capacity:       1024 entries"));
    assert!(stdout.contains("Zero-Copy Ready:        YES"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("rings")
        .arg("--json")
        .output()
        .expect("execute xdp rings json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse xdp rings json");
    assert_eq!(val["umem_frames"].as_u64().unwrap(), 4096);
    assert_eq!(val["fill_ring_capacity"].as_u64().unwrap(), 1024);
    assert_eq!(val["rx_ring_capacity"].as_u64().unwrap(), 1024);
    assert!(val["zero_copy_ready"].as_bool().unwrap());
}

#[test]
fn test_cli_xdp_filter_evaluation_text_and_json() {
    // 1. Redirect filter on port 7443
    let output = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("filter")
        .arg("--port")
        .arg("7443")
        .arg("--action")
        .arg("redirect")
        .output()
        .expect("execute xdp filter redirect");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== eBPF/XDP Packet Filter Rule Evaluation ==="));
    assert!(stdout.contains("Target Port:            7443"));
    assert!(stdout.contains("Rule Match Status:      MATCHED"));
    assert!(stdout.contains("Target Action:          Redirect"));
    assert!(stdout.contains("Evaluated Action:       Redirect"));

    // 2. Drop filter evaluation with JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("filter")
        .arg("--port")
        .arg("9999")
        .arg("--action")
        .arg("drop")
        .arg("--json")
        .output()
        .expect("execute xdp filter drop json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse xdp filter json");
    assert_eq!(val["rule"]["dst_port"].as_u64().unwrap(), 9999);
    assert_eq!(val["rule"]["action"].as_str().unwrap(), "Drop");
    assert_eq!(val["evaluated_action"].as_str().unwrap(), "Drop");
    assert!(val["matched"].as_bool().unwrap());
}

#[test]
fn test_cli_xdp_benchmark_text_and_json() {
    // 1. Text output benchmark run
    let output = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("benchmark")
        .arg("--packets")
        .arg("500")
        .arg("--batch-size")
        .arg("16")
        .output()
        .expect("execute xdp benchmark");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Hardware-Accelerated eBPF/XDP Bypass Benchmark ==="));
    assert!(stdout.contains("Packets Evaluated:      500"));
    assert!(stdout.contains("Batch Size:             16"));
    assert!(stdout.contains("Throughput:"));
    assert!(stdout.contains("Bandwidth:"));

    // 2. JSON output benchmark run
    let json_out = Command::new(velcrux_bin())
        .arg("xdp")
        .arg("benchmark")
        .arg("--packets")
        .arg("200")
        .arg("--json")
        .output()
        .expect("execute xdp benchmark json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse xdp benchmark json");
    assert_eq!(val["packet_count"].as_u64().unwrap(), 200);
    assert_eq!(val["batch_size"].as_u64().unwrap(), 32);
    assert!(val["throughput_mpps"].as_f64().unwrap() > 0.0);
    assert!(val["throughput_gbps"].as_f64().unwrap() > 0.0);
    assert!(val["packets_redirected"].as_u64().unwrap() >= 192);
}
