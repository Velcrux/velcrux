//! Integration test suite for Option DH: Autonomous L4/L7 Hardware Load Balancer & Maglev Consistent Hashing Multiplexing Engine (`ADR-076`).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use velcrux_core::lb::{
    BackendNode, BackendPool, FiveTuple, L4Protocol, L7Context, L7RouteRule, LoadBalancerDirector,
    MaglevTable, NodeStatus, DEFAULT_MAGLEV_M,
};

fn generate_nodes(count: usize) -> Vec<BackendNode> {
    (0..count)
        .map(|i| {
            let id = format!("storage-srv-{:02}", i + 1);
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 1, (10 + i) as u8)), 7443);
            BackendNode::new(id, addr, 100)
        })
        .collect()
}

#[test]
fn test_maglev_consistent_hashing_slot_filling_and_uniformity() {
    let nodes = generate_nodes(8);
    let table = MaglevTable::build(&nodes, 1);

    // Default capacity is Fermat prime 65537
    assert_eq!(table.table_size, DEFAULT_MAGLEV_M);
    assert_eq!(table.lookup.len(), DEFAULT_MAGLEV_M);
    assert_eq!(table.active_nodes.len(), 8);

    // Verify all slots are assigned to a valid node
    for id in &table.lookup {
        assert!(!id.is_empty());
        assert!(nodes.iter().any(|n| &n.id == id));
    }

    // Verify uniform distribution: each of the 8 nodes gets ~12.5% of slots
    let expected_share = DEFAULT_MAGLEV_M as f64 / 8.0; // ~8192 slots
    for node in &nodes {
        let count = *table
            .slot_counts
            .get(&node.id)
            .expect("node in slot counts");
        let deviation = (count as f64 - expected_share).abs();
        let relative_deviation = deviation / expected_share;
        assert!(
            relative_deviation < 0.15,
            "Node {} has skewed allocation: {} slots (expected {:.0}, rel dev {:.2}%)",
            node.id,
            count,
            expected_share,
            relative_deviation * 100.0
        );
    }
}

#[test]
fn test_maglev_minimal_disruption_migration_bound() {
    // 10 nodes initial cluster
    let initial_nodes = generate_nodes(10);
    let table_initial = MaglevTable::build(&initial_nodes, 1);

    // Add 1 node -> 11 nodes
    let expanded_nodes = generate_nodes(11);
    let table_expanded = MaglevTable::build(&expanded_nodes, 2);

    let churn = table_initial.compute_churn_percentage(&table_expanded);

    // In consistent hashing, adding 1 node to N nodes reassigns ~ 1/(N+1) of the keys
    // For 10 -> 11, theoretical is 1/11 = 9.09%
    // Maglev permutation allocation maintains this with slight variance: ~8% to 14%
    assert!(
        churn >= 7.0 && churn <= 15.0,
        "Churn percentage {churn:.2}% is outside expected minimal disruption bound (7% - 15%)"
    );

    // Verify that at least 85% of existing keys remain mapped to the exact same backend
    let mut stable_keys = 0;
    for i in 0..10_000 {
        let tuple = FiveTuple::mock_quic((10_000 + i) as u16);
        let orig = table_initial.lookup_tuple(&tuple).unwrap();
        let new_dest = table_expanded.lookup_tuple(&tuple).unwrap();
        if orig == new_dest {
            stable_keys += 1;
        }
    }
    let stability_pct = (stable_keys as f64 / 10_000.0) * 100.0;
    assert!(
        stability_pct >= 85.0,
        "Key stability {stability_pct:.2}% was lower than 85%"
    );
}

#[test]
fn test_conntrack_flow_stickiness_during_churn() {
    let mut director = LoadBalancerDirector::new("primary-storage");

    for node in generate_nodes(6) {
        director.add_node("primary-storage", node).unwrap();
    }

    // 1. Establish 200 concurrent flows
    let mut flows = Vec::with_capacity(200);
    for i in 0..200 {
        let tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 5, (i % 250) as u8 + 1)),
            (20000 + i) as u16,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            7443,
            L4Protocol::Quic,
        );
        let decision = director.route_packet(&tuple, None, 1400, 10_000).unwrap();
        assert!(!decision.was_sticky);
        flows.push((tuple, decision.backend_node_id));
    }

    assert_eq!(director.conntrack.active_flow_count(), 200);

    // 2. Add 2 new nodes to the cluster, inducing table rebalance
    let extra_node1 = BackendNode::new(
        "storage-extra-01",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 98)), 7443),
        100,
    );
    let extra_node2 = BackendNode::new(
        "storage-extra-02",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 99)), 7443),
        100,
    );
    let churn1 = director.add_node("primary-storage", extra_node1).unwrap();
    let churn2 = director.add_node("primary-storage", extra_node2).unwrap();
    assert!(churn1 > 0.0);
    assert!(churn2 > 0.0);

    // 3. Re-route the same 200 flows
    for (tuple, original_node) in &flows {
        let decision = director.route_packet(tuple, None, 1400, 12_000).unwrap();
        // Conntrack stickiness MUST pin every existing flow to its original backend!
        assert!(
            decision.was_sticky,
            "Flow {} should have been sticky",
            tuple
        );
        assert_eq!(
            &decision.backend_node_id, original_node,
            "Flow {} was remapped despite being active in conntrack!",
            tuple
        );
    }
}

#[test]
fn test_zero_downtime_graceful_draining_and_offline_failover() {
    let mut director = LoadBalancerDirector::new("main-pool");
    for node in generate_nodes(4) {
        director.add_node("main-pool", node).unwrap();
    }

    let tuple_pinned = FiveTuple::mock_quic(40001);
    let decision1 = director
        .route_packet(&tuple_pinned, None, 1024, 10_000)
        .unwrap();
    let draining_node = decision1.backend_node_id.clone();

    // 1. Drain the target node
    let churn = director.drain_node("main-pool", &draining_node).unwrap();
    assert!(churn > 0.0);

    // 2. Existing active flow remains pinned to draining node with is_draining flag
    let decision2 = director
        .route_packet(&tuple_pinned, None, 1024, 11_000)
        .unwrap();
    assert!(decision2.was_sticky);
    assert_eq!(decision2.backend_node_id, draining_node);
    assert!(decision2.is_draining);

    // 3. New flow MUST NOT be assigned to the draining node
    for port in 40002..40100 {
        let tuple_new = FiveTuple::mock_quic(port);
        let dec = director
            .route_packet(&tuple_new, None, 512, 11_500)
            .unwrap();
        assert_ne!(
            dec.backend_node_id, draining_node,
            "New flow was routed to a draining node!"
        );
    }

    // 4. Node is finally taken Offline
    director
        .set_node_status("main-pool", &draining_node, NodeStatus::Offline)
        .unwrap();

    // 5. Subsequent packet for pinned flow detects Offline node and safely fails over
    let decision3 = director
        .route_packet(&tuple_pinned, None, 1024, 15_000)
        .unwrap();
    assert!(!decision3.was_sticky);
    assert_ne!(decision3.backend_node_id, draining_node);
    assert!(!decision3.is_draining);
}

#[test]
fn test_l7_content_based_routing_with_priority_rules() {
    let mut director = LoadBalancerDirector::new("default-storage");
    for node in generate_nodes(3) {
        director.add_node("default-storage", node).unwrap();
    }

    // Provision dedicated pools
    director.pools.insert(
        "tenant-finance-pool".into(),
        BackendPool::new("tenant-finance-pool"),
    );
    director
        .add_node(
            "tenant-finance-pool",
            BackendNode::new(
                "finance-node-01",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 1, 1)), 7443),
                100,
            ),
        )
        .unwrap();

    director.pools.insert(
        "video-transcode-pool".into(),
        BackendPool::new("video-transcode-pool"),
    );
    director
        .add_node(
            "video-transcode-pool",
            BackendNode::new(
                "gpu-worker-01",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 30, 1, 1)), 7443),
                100,
            ),
        )
        .unwrap();

    // Register L7 rules
    director.add_l7_rule(L7RouteRule {
        rule_id: "rule-finance".into(),
        tenant_prefix: Some("tenant-fin".into()),
        path_prefix: None,
        target_pool: "tenant-finance-pool".into(),
        priority: 50,
    });

    director.add_l7_rule(L7RouteRule {
        rule_id: "rule-video".into(),
        tenant_prefix: None,
        path_prefix: Some("/media/hls".into()),
        target_pool: "video-transcode-pool".into(),
        priority: 20,
    });

    // Test 1: Finance tenant traffic
    let t1 = FiveTuple::mock_quic(50001);
    let l7_fin = L7Context::new().with_tenant("tenant-fin-sec-corp");
    let d1 = director
        .route_packet(&t1, Some(&l7_fin), 4096, 10_000)
        .unwrap();
    assert_eq!(d1.pool_name, "tenant-finance-pool");
    assert_eq!(d1.backend_node_id, "finance-node-01");

    // Test 2: Video path traffic
    let t2 = FiveTuple::mock_quic(50002);
    let l7_vid = L7Context::new().with_path("/media/hls/live/segment01.ts");
    let d2 = director
        .route_packet(&t2, Some(&l7_vid), 8192, 10_000)
        .unwrap();
    assert_eq!(d2.pool_name, "video-transcode-pool");
    assert_eq!(d2.backend_node_id, "gpu-worker-01");

    // Test 3: Unmatched default traffic
    let t3 = FiveTuple::mock_quic(50003);
    let l7_other = L7Context::new().with_tenant("tenant-general");
    let d3 = director
        .route_packet(&t3, Some(&l7_other), 1024, 10_000)
        .unwrap();
    assert_eq!(d3.pool_name, "default-storage");
}
