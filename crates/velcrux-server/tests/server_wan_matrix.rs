//! Integration tests for Option AK: WAN Impairment Simulation & Multi-Protocol Comparative Benchmarking Suite
//! (`docs/REQUIREMENTS.md` §45, §46, §47, §48, §91, §92; `docs/PERFORMANCE.md` §7, §9).
//!
//! Validates:
//! 1. WAN RTT latency sweep across 1ms, 20ms, 50ms, 100ms, 150ms, 200ms, and 300ms.
//! 2. WAN loss resilience sweep across 0%, 0.1%, 0.5%, 1.0%, 2.0%, and 5.0% loss.
//! 3. Bandwidth scaling across 100 Mbps, 1 Gbps, and 10 Gbps.
//! 4. Flagship §48 example benchmark (150ms RTT, 0.5% loss, 10 Gbps, 99% delta reuse vs full transfer).
//! 5. Head-to-head comparison against legacy TCP un-chunked baseline, verifying >10× speedup on high-BDP WAN.
//! 6. Automated Markdown comparison table and JSON report emission in `benches/results/`.
//! 7. In-process impaired channel delivery and token-bucket bandwidth pacing.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use tempfile::tempdir;

use velcrux_core::transport::benchmarks::{
    BaselineComparator, BenchmarkScenario, WanMatrixReport, WanMatrixRunner,
};
use velcrux_core::transport::impairment::{ImpairedChannel, ImpairmentProfile, TokenBucket};

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn test_wan_latency_sweep_and_bdp_window_scaling() {
    let rtts = [
        Duration::from_millis(1),
        Duration::from_millis(20),
        Duration::from_millis(50),
        Duration::from_millis(100),
        Duration::from_millis(150),
        Duration::from_millis(200),
        Duration::from_millis(300),
    ];

    let bw_10g = 10_000_000_000u64; // 10 Gbps = 1.25 GB/s

    for rtt in rtts {
        let profile =
            ImpairmentProfile::new(format!("RTT-{}ms", rtt.as_millis()), rtt, 0.0, bw_10g);
        let bdp = profile.bdp_bytes();
        let expected_bdp = (1_250_000_000f64 * rtt.as_secs_f64()).round() as u64;
        assert_eq!(bdp, expected_bdp);

        let win = profile.recommended_receive_window();
        // Clamped between 16 MiB min and 1 GiB max
        assert!(win >= 16 * 1024 * 1024);
        assert!(win <= 1024 * 1024 * 1024);

        if rtt.as_millis() >= 150 {
            // High BDP links must have scaled windows > 300 MiB
            assert!(win >= 300 * 1024 * 1024);
        }
    }
}

#[test]
fn test_wan_loss_resilience_sweep() {
    let loss_rates = [0.0, 0.001, 0.005, 0.010, 0.020, 0.050]; // 0% to 5% (§45)
    let profile_100ms = ImpairmentProfile::new(
        "Loss Sweep 100ms",
        Duration::from_millis(100),
        0.0,
        1_000_000_000,
    );

    let file_size = 100 * 1024 * 1024; // 100 MB

    let mut prev_goodput = f64::MAX;
    for &loss in &loss_rates {
        let mut p = profile_100ms.clone();
        p.loss_rate = loss;

        let m = BaselineComparator::evaluate(&BenchmarkScenario::FullTransfer, &p, file_size);
        assert_eq!(m.loss_pct, loss * 100.0);
        assert!(m.goodput_mbps > 0.0);
        // Loss should monotonically decrease or maintain throughput
        assert!(m.goodput_mbps <= prev_goodput + 0.1);
        prev_goodput = m.goodput_mbps;

        // Peak RSS bounded to < 64 MB (CLAUDE.md §1 #3)
        assert!(m.peak_rss_bytes < 64 * 1024 * 1024);
    }
}

#[test]
fn test_scenario_48_flagship_wan_benchmark() {
    // §48 specification:
    // File size = 1 TB, RTT = 150 ms, bandwidth = 10 Gbps, loss = 0.5%
    // Compare full transfer vs delta transfer where 990 GB is already present (99% match).
    let one_tb = 1_000_000_000_000u64;

    let full_m = BaselineComparator::evaluate(
        &BenchmarkScenario::FullTransfer,
        &ImpairmentProfile::cross_pacific(),
        one_tb,
    );

    let delta_m = BaselineComparator::evaluate_scenario_48(one_tb);

    // Assert delta transfer avoids ~99% of data
    assert!(delta_m.avoided_bytes >= 990_000_000_000);
    assert_eq!(delta_m.efficiency_pct, 99.0);

    // Assert wire bytes is ~10 GB rather than 1 TB
    let ten_gb = 10_000_000_000u64;
    assert!(delta_m.wire_bytes < 12_000_000_000);
    assert!(delta_m.wire_bytes >= ten_gb);

    // Assert delta transfer is drastically faster than full transfer
    assert!(delta_m.duration_secs < full_m.duration_secs / 10.0);

    // Assert speedup over un-chunked TCP baseline exceeds 50×
    assert!(delta_m.speedup_vs_baseline > 50.0);
}

#[test]
fn test_wan_matrix_json_and_markdown_report_emission() {
    let runner = WanMatrixRunner::default();
    let report = runner.run(1_000_000_000); // 1 GB benchmark run

    assert_eq!(report.dataset_size_bytes, 1_000_000_000);
    assert!(!report.results.is_empty());

    // Markdown table formatting
    let md = report.format_markdown_table();
    assert!(md.contains("| Scenario | Link Profile | RTT | Loss |"));
    assert!(md.contains("CDC Delta Sync"));
    assert!(md.contains("Cross-Pacific 10G"));
    assert!(md.contains("Satellite Link"));

    // Save to results directory
    let temp = tempdir().unwrap();
    let (json_p, md_p) = report.save_to_dir(temp.path(), "wan_benchmark").unwrap();

    assert!(json_p.exists());
    assert!(md_p.exists());

    let json_content = fs::read_to_string(&json_p).unwrap();
    let deserialized: WanMatrixReport = serde_json::from_str(&json_content).unwrap();
    assert_eq!(deserialized.results.len(), report.results.len());

    // Also verify saving to repository benches/results directory
    let repo_results = repo_root().join("benches").join("results");
    let (repo_json, repo_md) = report
        .save_to_dir(&repo_results, "wan_matrix_latest")
        .unwrap();
    assert!(repo_json.exists());
    assert!(repo_md.exists());
}

#[tokio::test]
async fn test_impaired_channel_high_loss_and_recovery() {
    let profile = ImpairmentProfile::new(
        "Hostile Link",
        Duration::from_millis(5),
        0.05, // 5% loss (§45)
        100_000_000,
    );

    let channel = ImpairedChannel::<Vec<u8>>::new(profile, 99999);
    let total_packets = 500;
    let packet_size = 1024;

    let mut accepted = 0;
    for i in 0..total_packets {
        let payload = vec![(i % 256) as u8; packet_size];
        if channel.send(payload, packet_size).await {
            accepted += 1;
        }
    }

    let stats = channel.stats().snapshot();
    assert_eq!(stats.packets_sent, total_packets);
    // Observed loss should be close to 5% (~25 dropped packets)
    assert!(stats.packets_dropped > 5 && stats.packets_dropped < 60);
    assert_eq!(stats.packets_sent - stats.packets_dropped, accepted);

    // Drain channel
    let mut received = 0;
    for _ in 0..accepted {
        if channel.recv().await.is_some() {
            received += 1;
        }
    }
    assert_eq!(received, accepted);
}

#[test]
fn test_token_bucket_pacing_invariants() {
    let mut tb = TokenBucket::new(10_000_000); // 10 Mbps = 1.25 MB/s
                                               // Initial consume should be non-blocking
    assert_eq!(tb.consume(1024), Duration::ZERO);

    // Large burst triggers positive pacing delay
    let wait = tb.consume(5_000_000);
    assert!(wait > Duration::from_millis(100));
}
