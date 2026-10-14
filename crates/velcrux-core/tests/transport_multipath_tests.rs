use std::net::SocketAddr;
use std::time::Duration;
use velcrux_core::transport::multipath::{
    MultipathConfig, MultipathCoordinator, MultipathSchedulerPolicy, PathState,
};

fn socket(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

#[test]
fn test_multipath_auto_discovery_and_binding() {
    let mut cfg = MultipathConfig::default();
    cfg.enabled = true;
    let coord = MultipathCoordinator::new(cfg);

    let target = socket(7443);
    let bound = coord.auto_discover_and_bind(target).unwrap();
    assert!(bound >= 1, "at least one subflow path must be bound");
    assert_eq!(coord.path_count(), bound);
    assert!(coord.routable_path_count() >= 1);

    let report = coord.generate_report();
    assert_eq!(report.total_paths, bound);
    assert!(report.aggregate_bandwidth_mbps > 0.0);
}

#[test]
fn test_multipath_weighted_bandwidth_proportional_distribution() {
    let mut cfg = MultipathConfig::default();
    cfg.policy = MultipathSchedulerPolicy::WeightedBandwidth;
    let coord = MultipathCoordinator::new(cfg);

    let p10g = coord.add_subflow_path("eth0_10g".into(), socket(1001), socket(7443), 1, true);
    let p1g = coord.add_subflow_path("eth1_1g".into(), socket(1002), socket(7443), 1, false);

    // 10G path: 10 Gbps capacity (10,000 Mbps)
    coord.record_path_sample(p10g, Duration::from_millis(2), 0.0, 10_000_000, 0);
    // 1G path: 1 Gbps capacity (1,000 Mbps)
    coord.record_path_sample(p1g, Duration::from_millis(2), 0.0, 1_000_000, 0);

    let mut count_10g = 0;
    let mut count_1g = 0;

    for _ in 0..110 {
        let chosen = coord.select_path_for_chunk(65536, false);
        if chosen == vec![p10g] {
            count_10g += 1;
        } else if chosen == vec![p1g] {
            count_1g += 1;
        }
    }

    // Proportional ratio should strongly favour the 10G path (~10:1 ratio)
    assert!(
        count_10g > count_1g * 5,
        "10G path ({}) must handle significantly more chunks than 1G path ({})",
        count_10g,
        count_1g
    );
}

#[test]
fn test_multipath_degraded_path_handling() {
    let mut cfg = MultipathConfig::default();
    cfg.rtt_degraded_threshold_ms = 100.0;
    cfg.loss_degraded_threshold = 0.10;
    let coord = MultipathCoordinator::new(cfg);

    let p1 = coord.add_subflow_path("eth0".into(), socket(1001), socket(7443), 1, true);

    // Initial normal sample
    coord.record_path_sample(p1, Duration::from_millis(20), 0.01, 1_000_000, 0);
    let rep = coord.generate_report();
    assert_eq!(rep.paths[0].state, PathState::Active);

    // High loss sample -> Degraded
    coord.record_path_sample(p1, Duration::from_millis(20), 0.25, 1_000_000, 0);
    let rep_deg = coord.generate_report();
    assert_eq!(rep_deg.paths[0].state, PathState::Degraded);

    // Recovery sample -> Active
    coord.record_path_sample(p1, Duration::from_millis(20), 0.01, 1_000_000, 0);
    let rep_rec = coord.generate_report();
    assert_eq!(rep_rec.paths[0].state, PathState::Active);
}

#[test]
fn test_multipath_redundant_metadata_duplication() {
    let mut cfg = MultipathConfig::default();
    cfg.policy = MultipathSchedulerPolicy::WeightedBandwidth;
    cfg.duplicate_metadata = true;
    let coord = MultipathCoordinator::new(cfg);

    let p1 = coord.add_subflow_path("eth0".into(), socket(1001), socket(7443), 1, true);
    let p2 = coord.add_subflow_path("wlan0".into(), socket(1002), socket(7443), 1, false);

    // Regular chunk routes to single path
    let data_paths = coord.select_path_for_chunk(65536, false);
    assert_eq!(data_paths.len(), 1);

    // Metadata frame duplicates across all active paths
    let meta_paths = coord.select_path_for_chunk(1024, true);
    assert_eq!(meta_paths, vec![p1, p2]);
}
