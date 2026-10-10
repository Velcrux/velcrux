//! Integration tests for Option AT: Network Path MTU Discovery (PMTU / DPLPMTUD RFC 8899),
//! Blackhole Detection, and NAT Firewall Traversal Coordinator.
//!
//! (`REQUIREMENTS.md` §75; RFC 8899; RFC 9000; `OPERATIONS.md` §28).
//!
//! Verifies:
//! 1. DPLPMTUD step search through candidate MTU sizes up to Jumbo frame (9000).
//! 2. Path MTU blackhole detection and emergency fallback to safe baseline (1200).
//! 3. Stateful NAT keepalive adaptation across NAT rebinding events.
//! 4. Comprehensive firewall diagnostics generation and recommendations.
//! 5. QUIC transport configuration compatibility.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::Duration;

use velcrux_core::transport::{
    NatBindingStatus, NatTraversalCoordinator, PmtuConfig, PmtuCoordinator, PmtuState, BASE_PLPMTU,
    DEFAULT_PMTU_CANDIDATES, JUMBO_FRAME_MTU, STANDARD_ETHERNET_MTU,
};

#[test]
fn test_server_pmtu_step_search_jumbo_frame() {
    let config = PmtuConfig {
        max_mtu: JUMBO_FRAME_MTU,
        ..Default::default()
    };
    let mut coordinator = PmtuCoordinator::new(config);

    assert_eq!(coordinator.current_mtu(), BASE_PLPMTU);
    assert_eq!(coordinator.state(), PmtuState::Base);

    // Step through each candidate size up to 9000
    for &candidate in &DEFAULT_PMTU_CANDIDATES[1..] {
        let probe = coordinator.next_probe_size();
        assert_eq!(
            probe,
            Some(candidate),
            "Expected candidate probe size {}",
            candidate
        );
        assert_eq!(coordinator.state(), PmtuState::Searching);

        // Remote peer acknowledges probe
        coordinator.on_probe_ack(candidate);
        assert_eq!(coordinator.current_mtu(), candidate);
    }

    // After all candidates acknowledged, search completes at Jumbo frame (9000)
    assert_eq!(coordinator.state(), PmtuState::SearchComplete);
    assert_eq!(coordinator.current_mtu(), JUMBO_FRAME_MTU);
    assert_eq!(coordinator.next_probe_size(), None);

    let stats = coordinator.stats();
    assert_eq!(stats.current_mtu, 9000);
    assert_eq!(stats.probes_sent, 6);
    assert_eq!(stats.probes_acked, 6);
    assert_eq!(stats.probes_lost, 0);
    assert_eq!(stats.blackhole_events, 0);
}

#[test]
fn test_server_pmtu_blackhole_recovery_under_wan_drop() {
    let config = PmtuConfig::default();
    let mut coordinator = PmtuCoordinator::new(config);

    // Fast-forward to 1500 Standard Ethernet MTU
    for &candidate in &[1280, 1420, 1500] {
        coordinator.next_probe_size();
        coordinator.on_probe_ack(candidate);
    }
    assert_eq!(coordinator.current_mtu(), STANDARD_ETHERNET_MTU);

    // Simulate upstream path drop: packets larger than 1200 bytes are silently discarded
    assert!(!coordinator.on_data_loss());
    assert!(!coordinator.on_data_loss());
    assert!(!coordinator.on_data_loss());

    // 4th loss triggers blackhole recovery
    let blackhole_detected = coordinator.on_data_loss();
    assert!(
        blackhole_detected,
        "Expected blackhole to trigger on 4th consecutive drop"
    );

    // Immediate downshift to 1200 baseline without dropping session
    assert_eq!(coordinator.current_mtu(), BASE_PLPMTU);
    assert_eq!(coordinator.state(), PmtuState::BlackholeRecovery);

    let stats = coordinator.stats();
    assert_eq!(stats.blackhole_events, 1);
    assert_eq!(stats.current_mtu, 1200);

    // Standard traffic succeeds at 1200 bytes -> transition back to search/normal
    coordinator.on_data_ack();
    assert_eq!(coordinator.state(), PmtuState::Searching);
}

#[test]
fn test_server_nat_traversal_keepalive_scaling() {
    let mut nat_coord = NatTraversalCoordinator::new(Duration::from_secs(15));
    assert_eq!(nat_coord.active_keepalive(), Duration::from_secs(15));

    // Initially direct
    let pmtu = PmtuCoordinator::new(PmtuConfig::default());
    let bind_addr: SocketAddr = "127.0.0.1:7443".parse().unwrap();
    let initial_report = nat_coord.diagnostics_report(bind_addr, &pmtu);
    assert_eq!(initial_report.binding_status, NatBindingStatus::Direct);

    // Detect NAT rebinding event (e.g. mobile cellular roaming or aggressive firewall reap)
    nat_coord.on_rebind_detected();
    assert_eq!(nat_coord.active_keepalive(), Duration::from_secs(10));

    // Detect 2nd rebinding event -> clamps to 5s minimum keepalive
    nat_coord.on_rebind_detected();
    assert_eq!(nat_coord.active_keepalive(), Duration::from_secs(5));

    // 3rd event retains minimum floor
    nat_coord.on_rebind_detected();
    assert_eq!(nat_coord.active_keepalive(), Duration::from_secs(5));

    let updated_report = nat_coord.diagnostics_report(bind_addr, &pmtu);
    assert_eq!(
        updated_report.binding_status,
        NatBindingStatus::RebindingDetected
    );
    assert_eq!(updated_report.active_keepalive_secs, 5);
    assert_eq!(updated_report.rebinding_events, 3);
}

#[test]
fn test_server_nat_diagnostics_report_generation() {
    let mut pmtu = PmtuCoordinator::new(PmtuConfig::default());
    // Advance MTU to 1420
    pmtu.next_probe_size();
    pmtu.on_probe_ack(1280);
    pmtu.next_probe_size();
    pmtu.on_probe_ack(1420);

    let mut nat = NatTraversalCoordinator::default();
    nat.mark_natted();

    let bind_addr: SocketAddr = "0.0.0.0:7443".parse().unwrap();
    let report = nat.diagnostics_report(bind_addr, &pmtu);

    // Verify report fields
    assert_eq!(report.local_bind_addr, "0.0.0.0:7443");
    assert_eq!(report.binding_status, NatBindingStatus::Natted);
    assert_eq!(report.current_path_mtu, 1420);
    assert_eq!(report.active_keepalive_secs, 15);
    assert!(report.recommendations.iter().any(|r| r.contains("7443")));
    assert!(report
        .recommendations
        .iter()
        .any(|r| r.contains("ICMP Type 3 Code 4")));

    // Verify JSON serialization
    let json = serde_json::to_string(&report).expect("report serializes to JSON");
    assert!(json.contains("\"current_path_mtu\":1420"));
    assert!(json.contains("\"active_keepalive_secs\":15"));
}
