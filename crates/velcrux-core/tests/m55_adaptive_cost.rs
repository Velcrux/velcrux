//! Integration tests for Option AD: Adaptive Cost Estimator & Network-Aware Automatic Mode Selection (`REQUIREMENTS.md` §55, §88).
//!
//! Tests:
//! 1. Identical file matches (100% similarity) recommend `TransferMode::Skip`.
//! 2. Files below the minimum delta threshold recommend `TransferMode::DirectStream`.
//! 3. Low-similarity files below the minimum savings ratio recommend `TransferMode::DirectStream`.
//! 4. High-bandwidth LAN environments favor DirectStream for modest file sizes due to disk/hash bottlenecks.
//! 5. High-latency / low-bandwidth WAN environments favor DeltaCDC when data reuse is significant.
//! 6. Dynamic derivation of `NetworkProfile` from QUIC `TransportStats`.
//! 7. Local directory sync execution under `TransferMode::DirectStream` and `TransferMode::Auto`.

use std::fs;
use std::time::Duration;
use tempfile::tempdir;

use velcrux_core::sync::{
    execute_directory_sync, plan_directory_sync, AdaptiveCostEstimator, DeviceProfile,
    DirectorySyncOptions, NetworkProfile, TransferMode,
};
use velcrux_core::transport::stats::TransportStats;

#[test]
fn test_identical_file_recommends_skip() {
    let estimator = AdaptiveCostEstimator::default();
    let net = NetworkProfile::wan_fast();
    let dev = DeviceProfile::nvme();

    let decision = estimator.evaluate(10_000_000, 1.0, true, &net, &dev);
    assert_eq!(decision.recommended_mode, TransferMode::Skip);
    assert!(!decision.is_delta_worthwhile);
    assert_eq!(decision.estimated_duration_secs, 0.0);
    assert_eq!(decision.breakdown.estimated_reused_bytes, 10_000_000);
}

#[test]
fn test_small_file_recommends_direct_stream() {
    let estimator = AdaptiveCostEstimator::new(64 * 1024, 0.08); // 64 KiB threshold
    let net = NetworkProfile::wan_satellite();
    let dev = DeviceProfile::ssd();

    // 16 KiB file with 90% potential reuse: still direct stream because file is below threshold
    let decision = estimator.evaluate(16 * 1024, 0.90, false, &net, &dev);
    assert_eq!(decision.recommended_mode, TransferMode::DirectStream);
    assert!(!decision.is_delta_worthwhile);
    assert!(decision.reason.contains("below delta threshold"));
}

#[test]
fn test_low_similarity_recommends_direct_stream() {
    let estimator = AdaptiveCostEstimator::new(64 * 1024, 0.10); // 10% min reuse
    let net = NetworkProfile::wan_fast();
    let dev = DeviceProfile::nvme();

    // 50 MiB file with only 2% reuse: not worth scanning and negotiating
    let decision = estimator.evaluate(50 * 1024 * 1024, 0.02, false, &net, &dev);
    assert_eq!(decision.recommended_mode, TransferMode::DirectStream);
    assert!(!decision.is_delta_worthwhile);
    assert!(decision.reason.contains("below minimum savings"));
}

#[test]
fn test_lan_high_bandwidth_prefers_direct_stream() {
    let estimator = AdaptiveCostEstimator::default();
    // 10 Gbps LAN, 0.5ms RTT
    let net = NetworkProfile::lan();
    // Spinning HDD with slow read/write (120 MB/s)
    let dev = DeviceProfile::hdd();

    // 20 MiB file with 25% reuse: On 10 Gbps LAN (1.25 GB/s wire speed),
    // transferring 20 MiB over the wire takes ~0.016s.
    // Reading 20 MiB from HDD takes ~0.15s! Direct stream is much faster!
    let decision = estimator.evaluate(20 * 1024 * 1024, 0.25, false, &net, &dev);
    assert_eq!(decision.recommended_mode, TransferMode::DirectStream);
    assert!(!decision.is_delta_worthwhile);
    assert!(decision.reason.contains("Direct stream is faster"));
}

#[test]
fn test_wan_high_rtt_prefers_delta_cdc() {
    let estimator = AdaptiveCostEstimator::default();
    // 15 Mbps Satellite WAN, 250ms RTT
    let net = NetworkProfile::wan_satellite();
    let dev = DeviceProfile::nvme();

    // 100 MiB file with 90% reuse:
    // Full transfer of 100 MiB over 15 Mbps takes ~55 seconds!
    // Delta transfer of 10 MiB takes ~5.5s + local NVMe scan of 0.05s = ~6s.
    let decision = estimator.evaluate(100 * 1024 * 1024, 0.90, false, &net, &dev);
    assert_eq!(decision.recommended_mode, TransferMode::DeltaCDC);
    assert!(decision.is_delta_worthwhile);
    assert!(decision.breakdown.time_savings_secs > 30.0);
    assert!(decision.reason.contains("Delta sync saves"));
}

#[test]
fn test_network_profile_from_transport_stats() {
    let stats = TransportStats {
        rtt: Some(Duration::from_millis(50)), // 50ms RTT
        rtt_var: Some(Duration::from_millis(5)),
        bytes_in_flight: 64 * 1024,
        cwnd: 500_000, // 500 KB cwnd
        loss_events: 2,
        retransmits: 100,
    };

    let profile = NetworkProfile::from_transport_stats(&stats, 1_000_000);
    assert_eq!(profile.rtt, Duration::from_millis(50));
    // Derived BW = 500,000 / 0.05 = 10,000,000 B/s (10 MB/s = 80 Mbps)
    assert_eq!(profile.bandwidth_bytes_per_sec, 10_000_000);
    assert!(profile.packet_loss_rate > 0.0);
}

#[test]
fn test_bloom_match_preliminary_evaluation() {
    let estimator = AdaptiveCostEstimator::default();
    let net = NetworkProfile::wan_fast();
    let dev = DeviceProfile::nvme();

    // 200 chunks total, 180 matched in Bloom filter = 90% similarity
    let decision = estimator.evaluate_from_bloom_match(50 * 1024 * 1024, 180, 200, &net, &dev);
    assert_eq!(decision.recommended_mode, TransferMode::DeltaCDC);
    assert!(decision.is_delta_worthwhile);
}

#[test]
fn test_directory_sync_with_direct_stream_mode() {
    let src_dir = tempdir().expect("src dir");
    let dst_dir = tempdir().expect("dst dir");

    let src_path = src_dir.path();
    let dst_path = dst_dir.path();

    // Create 3 files in source
    fs::write(
        src_path.join("file1.txt"),
        b"file1 content for direct stream",
    )
    .expect("write f1");
    fs::write(
        src_path.join("file2.txt"),
        b"file2 content for direct stream",
    )
    .expect("write f2");
    fs::write(
        src_path.join("file3.txt"),
        b"file3 content for direct stream",
    )
    .expect("write f3");

    // Force TransferMode::DirectStream
    let options = DirectorySyncOptions::default().with_transfer_mode(TransferMode::DirectStream);

    let plan = plan_directory_sync(src_path, dst_path, &options, None).expect("plan sync");
    assert_eq!(plan.actions.len(), 3);
    assert_eq!(plan.summary.files_added, 3);

    let result = execute_directory_sync(src_path, dst_path, &options, None, None)
        .expect("execute direct sync");

    assert_eq!(result.files_transferred, 3);
    assert_eq!(result.files_committed, 3);
    assert_eq!(
        fs::read(dst_path.join("file1.txt")).unwrap(),
        b"file1 content for direct stream"
    );
    assert_eq!(
        fs::read(dst_path.join("file2.txt")).unwrap(),
        b"file2 content for direct stream"
    );
    assert_eq!(
        fs::read(dst_path.join("file3.txt")).unwrap(),
        b"file3 content for direct stream"
    );
}

#[test]
fn test_directory_sync_auto_mode_small_files_fast_path() {
    let src_dir = tempdir().expect("src dir");
    let dst_dir = tempdir().expect("dst dir");

    let src_path = src_dir.path();
    let dst_path = dst_dir.path();

    // 10 small files (1 KB each) - below 64 KiB min_delta_size
    for i in 0..10 {
        let content = vec![i as u8; 1024];
        fs::write(src_path.join(format!("small_{i}.dat")), &content).unwrap();
    }

    let options = DirectorySyncOptions::default()
        .with_transfer_mode(TransferMode::Auto)
        .with_min_delta_size(64 * 1024);

    let result = execute_directory_sync(src_path, dst_path, &options, None, None)
        .expect("execute auto sync");

    assert_eq!(result.files_transferred, 10);
    assert_eq!(result.files_committed, 10);
    assert_eq!(result.local_bytes_reused, 0); // Directly transferred without delta overhead
    assert_eq!(result.wire_bytes_transferred, 10 * 1024);
}
