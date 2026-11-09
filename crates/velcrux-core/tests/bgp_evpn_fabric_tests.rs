#![forbid(unsafe_code)]

//! Integration Test Suite for BGP-4, MP-BGP EVPN, VXLAN, and Anycast Orchestrator.
//!
//! Validates:
//! - BGP-4 protocol message framing (OPEN, UPDATE, KEEPALIVE, NOTIFICATION).
//! - EVPN Route Types (Type 2 MAC/IP, Type 5 IP Prefix), Route Distinguishers, and Route Targets.
//! - VXLAN 8-byte header encapsulation/decapsulation over UDP 4789 and VTEP FDB learning.
//! - BGP Finite State Machine (FSM) session negotiation and timer handling.
//! - Multi-VRF table isolation and BGP best-path decision algorithm.
//! - Autonomous Anycast Orchestrator health scoring, AS-path prepending, and sub-second withdrawal.

use std::net::Ipv4Addr;
use velcrux_core::bgp::{
    AnycastAction, AnycastOrchestrator, AnycastVip, AsPathSegment, BgpEvent, BgpFsmState,
    BgpMessage, BgpPathAttributes, BgpPeer, BgpPrefix, EthernetSegmentId, EvpnRoute, MacAddress,
    PopHealthStatus, RouteDistinguisher, RouteTarget, VrfTable, VtepEngine,
};

#[test]
fn test_bgp_message_framing_and_capabilities() {
    let open = BgpMessage::Open {
        version: 4,
        asn: 65001,
        hold_time: 90,
        router_id: Ipv4Addr::new(10, 0, 0, 1),
        capabilities: vec![1, 2, 3],
    };

    let raw = open.to_bytes();
    assert!(raw.len() >= 19);
    assert_eq!(&raw[..16], &[0xFF; 16]);

    let parsed = BgpMessage::from_bytes(&raw).expect("parse open");
    if let BgpMessage::Open {
        version,
        asn,
        hold_time,
        router_id,
        capabilities,
    } = parsed
    {
        assert_eq!(version, 4);
        assert_eq!(asn, 65001);
        assert_eq!(hold_time, 90);
        assert_eq!(router_id, Ipv4Addr::new(10, 0, 0, 1));
        assert!(capabilities.contains(&1));
    } else {
        panic!("expected Open message");
    }
}

#[test]
fn test_evpn_routes_and_target_filtering() {
    let rd = RouteDistinguisher::parse("65001:500").unwrap();
    let rt_import = RouteTarget::parse("target:65001:500").unwrap();
    let rt_other = RouteTarget::parse("target:65001:999").unwrap();

    let mac = MacAddress::parse("00:50:56:AA:BB:CC").unwrap();
    let route_type2 = EvpnRoute::MacIpAdvertisement {
        rd,
        esi: EthernetSegmentId::zero(),
        ethernet_tag_id: 0,
        mac,
        ip: Some(Ipv4Addr::new(192, 168, 100, 50)),
        vni: 10500,
    };

    // Serialize and deserialize EVPN Type 2
    let raw = route_type2.to_bytes();
    let (parsed, len) = EvpnRoute::from_bytes(&raw).expect("parse type 2");
    assert_eq!(len, raw.len());
    assert_eq!(route_type2, parsed);

    // VRF Route Target filtering
    let mut vrf = VrfTable::new("tenant-500", 10500, rd, vec![rt_import], vec![rt_import]);

    // Import matching route target succeeds
    let accepted = vrf.import_evpn_route(route_type2.clone(), &[rt_import]);
    assert!(accepted);
    assert_eq!(vrf.evpn_routes.len(), 1);

    // Import non-matching route target is rejected
    let rejected = vrf.import_evpn_route(route_type2, &[rt_other]);
    assert!(!rejected);
    assert_eq!(vrf.evpn_routes.len(), 1);
}

#[test]
fn test_vxlan_encapsulation_and_vtep_learning() {
    let local_vtep = Ipv4Addr::new(10, 20, 0, 1);
    let remote_vtep = Ipv4Addr::new(10, 20, 0, 2);
    let mut vtep = VtepEngine::new(local_vtep);

    let mac = MacAddress::parse("52:54:00:12:34:56").unwrap();
    vtep.learn_fdb(50000, mac, remote_vtep);
    assert_eq!(vtep.lookup_fdb(50000, &mac), Some(remote_vtep));

    let frame = vec![0x08, 0x00, 0x45, 0x00, 0x00, 0x28];
    let encap = vtep.encapsulate(50000, frame.clone()).unwrap();

    // Verify VXLAN header
    let (vni, inner) = vtep.decapsulate(&encap).unwrap();
    assert_eq!(vni, 50000);
    assert_eq!(inner, frame);
    assert_eq!(vtep.packets_encapsulated, 1);
    assert_eq!(vtep.packets_decapsulated, 1);
}

#[test]
fn test_bgp_fsm_complete_lifecycle() {
    let mut peer = BgpPeer::new(
        65002,
        65001,
        Ipv4Addr::new(172, 16, 1, 2),
        Ipv4Addr::new(172, 16, 1, 1),
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    );

    // 1. Start session
    peer.process_event(BgpEvent::ManualStart).unwrap();
    assert_eq!(peer.state, BgpFsmState::Connect);

    // 2. TCP Confirmed -> OpenSent
    let msg_open = peer
        .process_event(BgpEvent::TcpConnectionConfirmed)
        .unwrap();
    assert_eq!(peer.state, BgpFsmState::OpenSent);
    assert!(matches!(msg_open, Some(BgpMessage::Open { .. })));

    // 3. Receive Peer OPEN -> OpenConfirm
    let peer_open = BgpMessage::Open {
        version: 4,
        asn: 65002,
        hold_time: 90,
        router_id: Ipv4Addr::new(2, 2, 2, 2),
        capabilities: Vec::new(),
    };
    let msg_ka = peer
        .process_event(BgpEvent::ReceiveOpen(Box::new(peer_open)))
        .unwrap();
    assert_eq!(peer.state, BgpFsmState::OpenConfirm);
    assert_eq!(msg_ka, Some(BgpMessage::Keepalive));

    // 4. Receive Peer KEEPALIVE -> Established
    peer.process_event(BgpEvent::ReceiveKeepalive).unwrap();
    assert_eq!(peer.state, BgpFsmState::Established);

    // 5. Hold Timer Expiration -> Notification & Idle
    let notif = peer.process_event(BgpEvent::HoldTimerExpired).unwrap();
    assert_eq!(peer.state, BgpFsmState::Idle);
    assert!(matches!(
        notif,
        Some(BgpMessage::Notification { error_code: 4, .. })
    ));
}

#[test]
fn test_bgp_best_path_decision_criteria() {
    let pfx = BgpPrefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut vrf = VrfTable::new(
        "default",
        0,
        RouteDistinguisher::parse("65001:1").unwrap(),
        vec![],
        vec![],
    );

    // Path 1: LocalPref 100, AS Path [65002]
    let mut attr1 = BgpPathAttributes::default();
    attr1.local_pref = Some(100);
    attr1.as_path = vec![AsPathSegment::sequence(vec![65002])];
    attr1.next_hop = Ipv4Addr::new(10, 0, 1, 1);

    // Path 2: LocalPref 150, AS Path [65003, 65004]
    let mut attr2 = BgpPathAttributes::default();
    attr2.local_pref = Some(150);
    attr2.as_path = vec![AsPathSegment::sequence(vec![65003, 65004])];
    attr2.next_hop = Ipv4Addr::new(10, 0, 2, 1);

    vrf.insert_prefix_route(pfx, attr1, 65002, Ipv4Addr::new(10, 0, 1, 1), 65001);
    vrf.insert_prefix_route(pfx, attr2, 65003, Ipv4Addr::new(10, 0, 2, 1), 65001);

    // Path 2 must win due to higher LocalPref (150 > 100)
    let best = vrf.get_best_route(&pfx).expect("has best route");
    assert_eq!(best.peer_asn, 65003);
    assert_eq!(best.attributes.local_pref, Some(150));

    // Withdraw Path 2 -> Path 1 becomes best route
    vrf.withdraw_prefix_route(&pfx, Ipv4Addr::new(10, 0, 2, 1), 65001);
    let best2 = vrf.get_best_route(&pfx).expect("has best route");
    assert_eq!(best2.peer_asn, 65002);
    assert_eq!(best2.attributes.local_pref, Some(100));
}

#[test]
fn test_anycast_orchestrator_autonomous_traffic_engineering() {
    let mut orch = AnycastOrchestrator::new(65001);
    let pfx = BgpPrefix::new(Ipv4Addr::new(203, 0, 113, 1), 32);
    let vip = AnycastVip::new(pfx, "fra-edge-01", 65001, Ipv4Addr::new(10, 0, 0, 1));
    orch.register_vip(vip);

    // Scenario 1: Optimal health -> Announce with 0 prepends
    let (act1, msg1) = orch.evaluate_pop_health(&pfx, 15.0, 0.0, 0).unwrap();
    assert_eq!(act1, AnycastAction::AnnounceNormal { as_prepends: 0 });
    assert!(msg1.is_some());
    assert_eq!(
        orch.vips.get(&pfx).unwrap().health_status,
        PopHealthStatus::Optimal
    );

    // Scenario 2: High latency and minor packet loss -> Soft deflect with AS prepends
    let (act2, msg2) = orch.evaluate_pop_health(&pfx, 260.0, 0.04, 1).unwrap();
    assert!(matches!(act2, AnycastAction::SoftDeflectPrepend { as_prepends } if as_prepends >= 2));
    assert!(msg2.is_some());
    assert_eq!(
        orch.vips.get(&pfx).unwrap().health_status,
        PopHealthStatus::Congested
    );

    // Scenario 3: Severe outage -> Immediate prefix withdrawal
    let (act3, msg3) = orch.evaluate_pop_health(&pfx, 600.0, 0.25, 5).unwrap();
    assert_eq!(act3, AnycastAction::InstantWithdraw);
    assert_eq!(
        orch.vips.get(&pfx).unwrap().health_status,
        PopHealthStatus::Critical
    );

    if let Some(BgpMessage::Update {
        withdrawn_routes, ..
    }) = msg3
    {
        assert_eq!(withdrawn_routes, vec![pfx]);
    } else {
        panic!("expected withdrawal update");
    }
}
