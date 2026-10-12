#![forbid(unsafe_code)]

use std::time::Duration;
use velcrux_core::{BottleneckKind, ComponentKind, NetworkMetrics, TransferProfiler};

#[test]
fn test_transfer_profiler_stage_breakdown() {
    let profiler = TransferProfiler::new();

    // Record various component timings
    profiler.record_timing(
        ComponentKind::DiskIoRead,
        Duration::from_millis(50),
        10 * 1024 * 1024,
    );
    profiler.record_timing(
        ComponentKind::Chunking,
        Duration::from_millis(30),
        10 * 1024 * 1024,
    );
    profiler.record_timing(
        ComponentKind::Hashing,
        Duration::from_millis(20),
        10 * 1024 * 1024,
    );
    profiler.record_timing(
        ComponentKind::NetworkQuic,
        Duration::from_millis(400),
        10 * 1024 * 1024,
    );
    profiler.record_timing(
        ComponentKind::DiskIoWrite,
        Duration::from_millis(60),
        10 * 1024 * 1024,
    );

    profiler.sample_memory();
    profiler.set_bytes_transferred(10 * 1024 * 1024);

    profiler.set_network_metrics(NetworkMetrics {
        rtt_us: 15_000,
        packet_loss_rate: 0.02,
        retransmits: 4,
        cwnd_bytes: 128 * 1024,
        wire_bytes: 10 * 1024 * 1024,
    });

    let report = profiler.finish();

    // Check report structure
    assert!(report.components.len() >= 5);
    assert_eq!(report.diagnosis.kind, BottleneckKind::NetworkBound);
    assert!(report.diagnosis.primary_component_pct > 50.0);

    // Verify ASCII table generation
    let table = report.format_ascii_table();
    assert!(table.contains("VELCRUX EMPIRICAL PERFORMANCE PROFILE REPORT"));
    assert!(table.contains("Storage Read I/O"));
    assert!(table.contains("QUIC Network Transport"));
    assert!(table.contains("Primary Bottleneck: Network Bound"));

    // Verify JSON value output
    let json_val = report.to_json_value();
    assert!(json_val.get("components").is_some());
    assert!(json_val.get("diagnosis").is_some());
    assert!(json_val.get("network").is_some());
}

#[test]
fn test_timing_guard_measurement() {
    let profiler = TransferProfiler::new();

    {
        let _guard = profiler.start_timer(ComponentKind::Encryption, 1024 * 1024);
        std::thread::sleep(Duration::from_millis(15));
    }

    let report = profiler.finish();
    let comp_timing = report
        .components
        .get(&ComponentKind::Encryption)
        .expect("should find Encryption timing");

    assert!(comp_timing.total_ms() >= 10.0);
    assert_eq!(comp_timing.bytes_processed, 1024 * 1024);
    assert_eq!(comp_timing.invocations, 1);
}

#[test]
fn test_disk_bottleneck_detection() {
    let profiler = TransferProfiler::new();

    // Emulate slow disk read
    profiler.record_timing(
        ComponentKind::DiskIoRead,
        Duration::from_millis(800),
        5 * 1024 * 1024,
    );
    profiler.record_timing(
        ComponentKind::NetworkQuic,
        Duration::from_millis(100),
        5 * 1024 * 1024,
    );

    let report = profiler.finish();
    assert_eq!(report.diagnosis.kind, BottleneckKind::DiskIoReadBound);
}

#[test]
fn test_empty_profiler() {
    let profiler = TransferProfiler::new();
    let report = profiler.finish();
    assert!(report.components.is_empty());
    assert_eq!(report.diagnosis.kind, BottleneckKind::BalancedOptimized);

    let table = report.format_ascii_table();
    assert!(table.contains("Balanced Pipeline"));
}
