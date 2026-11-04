//! Integration tests for Option CY: Hardware-Accelerated RDMA (RoCEv2 / InfiniBand)
//! Direct Memory Pacing & Verbs Architecture (`ADR-067`).

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
fn test_cli_rdma_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("status")
        .output()
        .expect("execute rdma status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== Hardware-Accelerated RDMA (RoCEv2 / InfiniBand) HCA Status ==="));
    assert!(stdout.contains("Device Name:            mlx5_0"));
    assert!(stdout.contains("Vendor ID:              0x15b3 (Mellanox Technologies)"));
    assert!(stdout.contains("Link Layer:             RoCEv2"));
    assert!(stdout.contains("Active Speed:           100 Gbps (4X EDR/HDR)"));
    assert!(stdout.contains("Active MTU:             4096 bytes"));
    assert!(stdout.contains("Max Queue Pairs:        65536"));
    assert!(stdout.contains("Max Memory Regions:     131072"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("status")
        .arg("--device")
        .arg("mlx5_1")
        .arg("--json")
        .output()
        .expect("execute rdma status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse rdma status json");
    assert_eq!(val["device_name"].as_str().unwrap(), "mlx5_1");
    assert_eq!(val["vendor_id"].as_u64().unwrap(), 0x15b3);
    assert_eq!(val["link_layer"].as_str().unwrap(), "RoCEv2");
    assert_eq!(val["active_mtu"].as_u64().unwrap(), 4096);
    assert_eq!(val["max_qp"].as_u64().unwrap(), 65536);
}

#[test]
fn test_cli_rdma_bench_text_and_json() {
    // 1. Text output benchmark run
    let output = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("bench")
        .arg("--chunks")
        .arg("32")
        .arg("--chunk-size")
        .arg("2048")
        .arg("--inject-cnp")
        .output()
        .expect("execute rdma bench");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== RDMA Hardware Bypass Zero-Copy Transfer Benchmark ==="));
    assert!(stdout.contains("Device:                 mlx5_0"));
    assert!(stdout.contains("Queue Pair Type:        ReliableConnected (RC)"));
    assert!(stdout.contains("Chunks Transferred:     32"));
    assert!(stdout.contains("Chunk Size:             2048 bytes"));
    assert!(stdout.contains("Total Transferred:      65536 bytes"));
    assert!(stdout.contains("Zero-Copy Verified:     YES (bit-for-bit matched remote memory)"));
    assert!(stdout.contains("DCQCN Congestion Marks: 1"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("bench")
        .arg("--chunks")
        .arg("16")
        .arg("--chunk-size")
        .arg("1024")
        .arg("--json")
        .output()
        .expect("execute rdma bench json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse rdma bench json");
    assert_eq!(val["num_chunks"].as_u64().unwrap(), 16);
    assert_eq!(val["chunk_size_bytes"].as_u64().unwrap(), 1024);
    assert_eq!(val["total_bytes"].as_u64().unwrap(), 16384);
    assert_eq!(val["zero_copy_verified"].as_bool().unwrap(), true);
    assert!(val["throughput_gbps"].as_f64().unwrap() > 0.0);
}

#[test]
fn test_cli_rdma_trace_text_and_json() {
    // 1. Text output: sample RoCEv2 frame dissection
    let output = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("trace")
        .output()
        .expect("execute rdma trace");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== RoCEv2 Wire-Speed Packet Frame Inspection ==="));
    assert!(stdout.contains("Transport Opcode:       RcRdmaWriteOnlyWithImm"));
    assert!(stdout.contains("Destination QP:         0x123456"));
    assert!(stdout.contains("Packet Sequence Num:    0x654321"));
    assert!(stdout.contains("Solicited Event:        true"));
    assert!(stdout.contains("Remote Virtual Addr:    0x00007fff12345678"));
    assert!(stdout.contains("Remote Key (rkey):      0xaabbccdd"));
    assert!(stdout.contains("DMA Transfer Length:    2048 bytes"));
    assert!(stdout.contains("Immediate Data:         0xcafebabe"));
    assert!(stdout.contains("Invariant CRC (ICRC):"));
    assert!(stdout.contains("(VERIFIED)"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("trace")
        .arg("--json")
        .output()
        .expect("execute rdma trace json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse rdma trace json");
    assert_eq!(val["opcode"].as_str().unwrap(), "RcRdmaWriteOnlyWithImm");
    assert_eq!(val["dest_qp"].as_u64().unwrap(), 0x123456);
    assert_eq!(val["psn"].as_u64().unwrap(), 0x654321);
    assert_eq!(val["reth"]["dma_len"].as_u64().unwrap(), 2048);
    assert_eq!(val["imm_data"].as_str().unwrap(), "0xcafebabe");
    assert_eq!(val["icrc_valid"].as_bool().unwrap(), true);
}

#[test]
fn test_cli_rdma_pacing_text_and_json() {
    // 1. Text output: DCQCN congestion pacing
    let output = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("pacing")
        .arg("--cnp-count")
        .arg("4")
        .arg("--pfc-pauses")
        .arg("3")
        .arg("--bytes-mb")
        .arg("15")
        .output()
        .expect("execute rdma pacing");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== DCQCN Congestion Control & Flow Pacing Telemetry ==="));
    assert!(stdout.contains("Line Rate Capacity:     100.00 Gbps"));
    assert!(stdout.contains("CNP Notifications:      4"));
    assert!(stdout.contains("PFC Pause Events:       3"));
    assert!(stdout.contains("Total Data Paced:       15.00 MB"));

    // 2. Machine-readable JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("rdma")
        .arg("pacing")
        .arg("--cnp-count")
        .arg("2")
        .arg("--pfc-pauses")
        .arg("1")
        .arg("--bytes-mb")
        .arg("10")
        .arg("--json")
        .output()
        .expect("execute rdma pacing json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse rdma pacing json");
    assert_eq!(val["cnp_count"].as_u64().unwrap(), 2);
    assert_eq!(val["pfc_pause_count"].as_u64().unwrap(), 1);
    assert!(val["alpha"].as_f64().unwrap() > 0.0);
}
