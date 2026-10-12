//! Integration tests for Option AU: Empirical Performance Profiler, Live Diagnostic Telemetry & Bottleneck Analyzer
//!
//! (`REQUIREMENTS.md` §72, §38, §36, §46; `OPERATIONS.md` §29; `ADR-011`).
//!
//! Verifies:
//! 1. Granular stage-by-stage pipeline timing tracking (Read, Chunking, Hashing, Crypto, Write, Network).
//! 2. Accurate empirical bottleneck diagnosis (`NetworkBound`, `DiskIoReadBound`, `DiskIoWriteBound`, `CpuHashingBound`, `CryptoBound`, `BalancedOptimized`).
//! 3. Diagnostic confidence scoring and automated tuning recommendations.
//! 4. Process RSS and buffer pool memory tracking.
//! 5. Structured ASCII and machine-readable JSON report formatting.

#![forbid(unsafe_code)]

use std::time::Duration;
use velcrux_core::{BottleneckKind, ComponentKind, NetworkMetrics, TransferProfiler};

#[test]
fn test_server_profiler_end_to_end_pipeline() {
    let profiler = TransferProfiler::new();
    let payload_size = 50 * 1024 * 1024; // 50 MiB

    // Emulate realistic balanced transfer stages
    profiler.record_timing(
        ComponentKind::DiskIoRead,
        Duration::from_millis(40),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::Chunking,
        Duration::from_millis(30),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::Hashing,
        Duration::from_millis(25),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::Encryption,
        Duration::from_millis(35),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::NetworkQuic,
        Duration::from_millis(50),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::DiskIoWrite,
        Duration::from_millis(45),
        payload_size,
    );

    profiler.record_buffer_pool_allocated(8 * 1024 * 1024);
    profiler.sample_memory();
    profiler.set_bytes_transferred(payload_size);

    let report = profiler.finish();

    assert_eq!(report.total_bytes, payload_size);
    assert_eq!(report.components.len(), 6);
    assert!(report.effective_goodput_mbps > 0.0);
    assert!(report.memory.buffer_pool_peak_bytes >= 8 * 1024 * 1024);

    // Balanced transfer should detect BalancedOptimized
    assert_eq!(report.diagnosis.kind, BottleneckKind::BalancedOptimized);
    assert!(report.diagnosis.confidence > 0.5);
    assert!(!report.diagnosis.recommendations.is_empty());
}

#[test]
fn test_server_profiler_cpu_hashing_bottleneck() {
    let profiler = TransferProfiler::new();
    let payload_size = 20 * 1024 * 1024;

    // Simulate high CPU hashing load (e.g. single-threaded or unvectorized)
    profiler.record_timing(
        ComponentKind::DiskIoRead,
        Duration::from_millis(15),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::Chunking,
        Duration::from_millis(10),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::Hashing,
        Duration::from_millis(500), // Dominated by hashing
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::NetworkQuic,
        Duration::from_millis(20),
        payload_size,
    );

    profiler.set_bytes_transferred(payload_size);
    let report = profiler.finish();

    assert_eq!(report.diagnosis.kind, BottleneckKind::CpuHashingBound);
    assert!(report.diagnosis.primary_component_pct >= 80.0);

    // Verify recommendations suggest parallel hashing / hardware SIMD
    let rec_text = report.diagnosis.recommendations.join(" ");
    assert!(
        rec_text.contains("SIMD")
            || rec_text.contains("hashing")
            || rec_text.contains("concurrency"),
        "Recommendations should suggest SIMD or concurrency: {}",
        rec_text
    );
}

#[test]
fn test_server_profiler_disk_write_bottleneck() {
    let profiler = TransferProfiler::new();
    let payload_size = 100 * 1024 * 1024;

    profiler.record_timing(
        ComponentKind::DiskIoRead,
        Duration::from_millis(50),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::NetworkQuic,
        Duration::from_millis(60),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::DiskIoWrite,
        Duration::from_millis(1200), // Severely bottlenecked by destination disk write / fsync
        payload_size,
    );

    profiler.set_bytes_transferred(payload_size);
    let report = profiler.finish();

    assert_eq!(report.diagnosis.kind, BottleneckKind::DiskIoWriteBound);
    let rec_text = report.diagnosis.recommendations.join(" ");
    assert!(
        rec_text.contains("fsync")
            || rec_text.contains("storage")
            || rec_text.contains("direct I/O"),
        "Recommendations should mention fsync or storage: {}",
        rec_text
    );
}

#[test]
fn test_server_profiler_network_wan_bottleneck() {
    let profiler = TransferProfiler::new();
    let payload_size = 10 * 1024 * 1024;

    profiler.record_timing(
        ComponentKind::DiskIoRead,
        Duration::from_millis(10),
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::NetworkQuic,
        Duration::from_millis(950), // Severely bottlenecked by WAN transport
        payload_size,
    );
    profiler.record_timing(
        ComponentKind::DiskIoWrite,
        Duration::from_millis(15),
        payload_size,
    );

    profiler.set_network_metrics(NetworkMetrics {
        rtt_us: 120_000, // 120ms WAN RTT
        packet_loss_rate: 0.05,
        retransmits: 42,
        cwnd_bytes: 256 * 1024,
        wire_bytes: 12 * 1024 * 1024,
    });

    profiler.set_bytes_transferred(payload_size);
    let report = profiler.finish();

    assert_eq!(report.diagnosis.kind, BottleneckKind::NetworkBound);
    assert!(report.network.is_some());
    let net = report.network.as_ref().unwrap();
    assert_eq!(net.rtt_us, 120_000);
    assert_eq!(net.retransmits, 42);

    let rec_text = report.diagnosis.recommendations.join(" ");
    assert!(
        rec_text.contains("window") || rec_text.contains("BDP") || rec_text.contains("network"),
        "Recommendations should mention network tuning: {}",
        rec_text
    );
}

#[test]
fn test_server_profiler_json_and_ascii_formatting() {
    let profiler = TransferProfiler::new();
    profiler.record_timing(
        ComponentKind::Encryption,
        Duration::from_millis(300),
        1024 * 1024,
    );
    profiler.record_timing(
        ComponentKind::Serialization,
        Duration::from_millis(20),
        1024 * 1024,
    );
    profiler.set_bytes_transferred(1024 * 1024);

    let report = profiler.finish();

    // ASCII formatting
    let ascii = report.format_ascii_table();
    assert!(ascii.contains("VELCRUX EMPIRICAL PERFORMANCE PROFILE REPORT"));
    assert!(ascii.contains("Zero-Knowledge Encryption"));
    assert!(ascii.contains("Frame Serialization"));

    // JSON formatting
    let json_val = report.to_json_value();
    let json_str = serde_json::to_string(&json_val).unwrap();
    assert!(json_str.contains("\"encryption\""));
    assert!(json_str.contains("\"serialization\""));
    assert!(json_str.contains("\"diagnosis\""));
}
