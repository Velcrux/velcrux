//! Integration tests for Option DC: SmartNIC / DPU Offloaded Direct-to-NVMe Storage Fabric (`ADR-071`).

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
fn test_cli_nvme_status_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("status")
        .output()
        .expect("execute nvme status");

    assert!(
        output.status.success(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== SmartNIC / DPU NVMe-oF Storage Fabric Status ==="));
    assert!(stdout.contains("Subsystem NQN:"));
    assert!(stdout.contains("DPU Device:"));
    assert!(stdout.contains("PCIe Interconnect:"));
    assert!(stdout.contains("Direct DMA Transfers:"));
    assert!(stdout.contains("Host CPU Cycles Saved:"));
    assert!(stdout.contains("P2P DMA Efficiency:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("status")
        .arg("--json")
        .output()
        .expect("execute nvme status json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse nvme status json");
    assert!(val["subsystem_nqn"].as_str().is_some());
    assert!(val["dpu_device"].as_str().is_some());
    assert!(val["pcie_gen"].as_u64().is_some());
    assert!(val["total_dma_transfers"].as_u64().is_some());
    assert!(val["host_cpu_cycles_saved"].as_u64().is_some());
    assert!(val["p2p_dma_efficiency_pct"].as_f64().is_some());
}

#[test]
fn test_cli_nvme_namespaces_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("namespaces")
        .output()
        .expect("execute nvme namespaces");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== NVMe Logical Block Addressing (LBA) Namespaces ==="));
    assert!(stdout.contains("[Namespace #1]"));
    assert!(stdout.contains("LBA Block Size: 4096 bytes"));
    assert!(stdout.contains("CRC32 Checksum:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("namespaces")
        .arg("--json")
        .output()
        .expect("execute nvme namespaces json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse namespaces json");
    let arr = val.as_array().expect("array of namespaces");
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["nsid"].as_u64().unwrap(), 1);
    assert!(arr[0]["capacity_mb"].as_f64().is_some());
    assert_eq!(arr[0]["block_size"].as_u64().unwrap(), 4096);
}

#[test]
fn test_cli_nvme_bench_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("bench")
        .arg("--iterations")
        .arg("20")
        .arg("--block-size")
        .arg("4096")
        .output()
        .expect("execute nvme bench");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== SmartNIC Direct-to-NVMe DMA Benchmark Report ==="));
    assert!(stdout.contains("Iterations:               20"));
    assert!(stdout.contains("Sector Size:              4096 bytes"));
    assert!(stdout.contains("DMA Line-Rate Throughput:"));
    assert!(stdout.contains("Direct IOPS:"));
    assert!(stdout.contains("Host CPU Cycles Saved:"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("bench")
        .arg("--iterations")
        .arg("10")
        .arg("--json")
        .output()
        .expect("execute nvme bench json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse bench json");
    assert_eq!(val["iterations"].as_u64().unwrap(), 10);
    assert_eq!(val["block_size_bytes"].as_u64().unwrap(), 4096);
    assert!(val["throughput_mb_s"].as_f64().unwrap() > 0.0);
    assert!(val["iops"].as_f64().unwrap() > 0.0);
    assert!(val["host_cpu_cycles_saved"].as_u64().unwrap() > 0);
}

#[test]
fn test_cli_nvme_connect_text_and_json() {
    // 1. Text output
    let output = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("connect")
        .arg("--subsystem")
        .arg("nqn.2026-11.io.velcrux:subsys.nvme01")
        .arg("--host-nqn")
        .arg("nqn.2026-11.io.velcrux:host.node01")
        .arg("--controller-id")
        .arg("1")
        .output()
        .expect("execute nvme connect");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("=== NVMe-oF Fabric Connect Session ==="));
    assert!(stdout.contains("Subsystem NQN:  nqn.2026-11.io.velcrux:subsys.nvme01"));
    assert!(stdout.contains("Host NQN:       nqn.2026-11.io.velcrux:host.node01"));
    assert!(stdout.contains("Controller ID:  1"));
    assert!(stdout.contains("CONNECTED (SUCCESS)"));

    // 2. JSON output
    let json_out = Command::new(velcrux_bin())
        .arg("nvme")
        .arg("connect")
        .arg("--json")
        .output()
        .expect("execute nvme connect json");

    assert!(json_out.status.success());
    let val: serde_json::Value =
        serde_json::from_slice(&json_out.stdout).expect("parse connect json");
    assert!(val["connected"].as_bool().unwrap());
    assert_eq!(val["controller_id"].as_u64().unwrap(), 1);
}
