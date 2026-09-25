#![forbid(unsafe_code)]

//! Integration tests for Milestone 12 (Option I):
//! Transport flow control, BDP window auto-tuning, and dynamic pipeline scaling.

use std::time::Duration;
use velcrux_core::transport::{
    AdaptiveFlowController, BdpEstimator, PacingController, TransportConfigTunables,
    TransportStats, MAX_RECEIVE_WINDOW, MIN_RECEIVE_WINDOW,
};

#[test]
fn test_bdp_window_sizing_lan_vs_wan() {
    let estimator = BdpEstimator::default();

    // 1. LAN: 10 Gbps (1,250,000,000 B/s), 1 ms RTT
    let lan_bw = 1_250_000_000u64;
    let lan_rtt = Duration::from_millis(1);
    let lan_bdp = BdpEstimator::calculate_bdp(lan_bw, lan_rtt);
    assert_eq!(lan_bdp, 1_250_000); // 1.25 MB

    // Window clamped to MIN_RECEIVE_WINDOW (16 MiB)
    let lan_win = estimator.optimal_receive_window(lan_bw, lan_rtt);
    assert_eq!(lan_win, MIN_RECEIVE_WINDOW);

    // 2. WAN: 10 Gbps (1,250,000,000 B/s), 150 ms RTT
    let wan_bw = 1_250_000_000u64;
    let wan_rtt = Duration::from_millis(150);
    let wan_bdp = BdpEstimator::calculate_bdp(wan_bw, wan_rtt);
    assert_eq!(wan_bdp, 187_500_000); // 187.5 MB

    // 2 × BDP = 375 MB ≈ 384 MiB
    let wan_win = estimator.optimal_receive_window(wan_bw, wan_rtt);
    assert_eq!(wan_win, 375_000_000);
    assert!(wan_win >= MIN_RECEIVE_WINDOW && wan_win <= MAX_RECEIVE_WINDOW);

    // 3. Ultra WAN: 100 Gbps (12.5 GB/s), 200 ms RTT -> BDP = 2.5 GB, 2x = 5.0 GB -> Clamped to 1 GiB
    let ultra_bw = 12_500_000_000u64;
    let ultra_rtt = Duration::from_millis(200);
    let ultra_win = estimator.optimal_receive_window(ultra_bw, ultra_rtt);
    assert_eq!(ultra_win, MAX_RECEIVE_WINDOW);
}

#[test]
fn test_transport_config_tunables_from_link_and_str() {
    let rtt = Duration::from_millis(150);
    let tunables =
        TransportConfigTunables::from_bandwidth_str("1G", rtt).expect("valid bandwidth string");

    assert_eq!(tunables.initial_rtt, rtt);
    assert!(tunables.receive_window >= MIN_RECEIVE_WINDOW);
    assert!(tunables.max_concurrent_streams >= 1);

    // Build quinn config to ensure no invalid settings or panics
    let quinn_config = tunables.build_quinn();
    drop(quinn_config);

    // Test with human byte format "100MB/s"
    let tunables_mb =
        TransportConfigTunables::from_bandwidth_str("100MB/s", Duration::from_millis(50))
            .expect("valid 100MB/s");
    assert_eq!(tunables_mb.initial_rtt, Duration::from_millis(50));
    assert!(tunables_mb.receive_window >= MIN_RECEIVE_WINDOW);

    // Test invalid bandwidth string
    assert!(TransportConfigTunables::from_bandwidth_str("invalid_rate", rtt).is_err());
}

#[test]
fn test_adaptive_flow_controller_rtt_loss_and_gating() {
    let mut controller = AdaptiveFlowController::new(100_000_000, Duration::from_millis(50));

    // Initially window allows dispatching within target inflight window
    let win = controller.target_inflight_window();
    assert!(win >= MIN_RECEIVE_WINDOW);
    assert!(controller.can_dispatch(0, 1_000_000));
    assert!(!controller.can_dispatch(win, 1024));

    // Update transport stats with loss
    let loss_stats = TransportStats {
        rtt: Some(Duration::from_millis(70)),
        loss_events: 10,
        ..TransportStats::default()
    };
    controller.update_transport_stats(&loss_stats);
    assert!(controller.rtt() > Duration::from_millis(50));

    // Record high throughput sample
    controller.record_transfer_sample(10_000_000, Duration::from_millis(50));
    assert!(controller.measured_throughput() > 0);

    // Concurrency calculation
    let concurrency = controller.optimal_concurrency(1024 * 1024, 32);
    assert!((1..=32).contains(&concurrency));
}

#[test]
fn test_pacing_controller_burst_regulation() {
    // 100 MB/s rate limit, 1 MB burst allowance
    let mut pacer = PacingController::new(100_000_000, 1_000_000);

    // Small request within burst allowance: no delay
    let d1 = pacer.calculate_pacing_delay(500_000);
    assert_eq!(d1, Duration::ZERO);

    // Large burst exceeding burst allowance: requires pacing delay
    let d2 = pacer.calculate_pacing_delay(10_000_000);
    assert!(d2 > Duration::ZERO);

    // Disabled pacer (0 rate) never delays
    let mut unpaced = PacingController::new(0, 0);
    assert_eq!(
        unpaced.calculate_pacing_delay(1_000_000_000),
        Duration::ZERO
    );
}
