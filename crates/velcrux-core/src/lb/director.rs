//! Autonomous L4/L7 Load Balancer Director & Multiplexer.
//!
//! Orchestrates Maglev consistent hashing pools, L7 content-based routing rules,
//! and L4 connection tracking with zero-downtime node draining and failover.

#![forbid(unsafe_code)]

use super::conntrack::ConnectionTracker;
use super::maglev::MaglevTable;
use super::types::{BackendNode, FiveTuple, L7Context, NodeId, NodeStatus};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Routing decision output produced for an incoming packet or flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbRouteDecision {
    pub pool_name: String,
    pub backend_node_id: NodeId,
    pub backend_address: SocketAddr,
    pub was_sticky: bool,
    pub is_draining: bool,
    pub table_slot: usize,
}

/// Layer-7 Routing Rule mapping tenant or path criteria to a backend pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7RouteRule {
    pub rule_id: String,
    pub tenant_prefix: Option<String>,
    pub path_prefix: Option<String>,
    pub target_pool: String,
    pub priority: u8,
}

/// A named backend cluster pool backed by an active Maglev consistent hashing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendPool {
    pub name: String,
    pub nodes: HashMap<NodeId, BackendNode>,
    pub table: MaglevTable,
    pub epoch: u64,
}

impl BackendPool {
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        Self {
            name: name_str,
            nodes: HashMap::new(),
            table: MaglevTable::build(&[], 0),
            epoch: 0,
        }
    }

    /// Rebuilds the Maglev lookup table from current nodes, returning the churn percentage.
    pub fn rebuild_table(&mut self) -> f64 {
        self.epoch = self.epoch.saturating_add(1);
        let node_list: Vec<BackendNode> = self.nodes.values().cloned().collect();
        let new_table = MaglevTable::build(&node_list, self.epoch);
        let churn = self.table.compute_churn_percentage(&new_table);
        self.table = new_table;
        churn
    }
}

/// Primary Autonomous Load Balancer Director.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerDirector {
    pub default_pool: String,
    pub pools: HashMap<String, BackendPool>,
    pub l7_rules: Vec<L7RouteRule>,
    pub conntrack: ConnectionTracker,
    pub total_routed_packets: u64,
    pub total_sticky_hits: u64,
    pub total_maglev_lookups: u64,
}

impl LoadBalancerDirector {
    /// Instantiates a director with a designated default backend pool.
    pub fn new(default_pool_name: impl Into<String>) -> Self {
        let def_name = default_pool_name.into();
        let mut pools = HashMap::new();
        pools.insert(def_name.clone(), BackendPool::new(&def_name));

        Self {
            default_pool: def_name,
            pools,
            l7_rules: Vec::new(),
            conntrack: ConnectionTracker::new(),
            total_routed_packets: 0,
            total_sticky_hits: 0,
            total_maglev_lookups: 0,
        }
    }

    /// Adds or updates an L7 routing rule.
    pub fn add_l7_rule(&mut self, rule: L7RouteRule) {
        self.l7_rules.retain(|r| r.rule_id != rule.rule_id);
        self.l7_rules.push(rule);
        // Higher priority rules evaluated first
        self.l7_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Adds a backend node to a designated pool, recalculating the Maglev table.
    ///
    /// Returns the percentage of slots remapped (churn).
    pub fn add_node(&mut self, pool_name: &str, node: BackendNode) -> Result<f64> {
        let pool = self
            .pools
            .entry(pool_name.to_string())
            .or_insert_with(|| BackendPool::new(pool_name));
        pool.nodes.insert(node.id.clone(), node);
        let churn = pool.rebuild_table();
        Ok(churn)
    }

    /// Removes a backend node from a pool, recalculating the Maglev table.
    ///
    /// Returns the percentage of slots remapped (churn).
    pub fn remove_node(&mut self, pool_name: &str, node_id: &str) -> Result<f64> {
        let pool = self
            .pools
            .get_mut(pool_name)
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::Malformed("pool not found")))?;

        pool.nodes.remove(node_id);
        let churn = pool.rebuild_table();
        Ok(churn)
    }

    /// Transitions a node into `Draining` state for graceful termination.
    ///
    /// Draining nodes are excluded from new Maglev table slots, but established
    /// flows in conntrack remain routed to them until connection termination.
    pub fn drain_node(&mut self, pool_name: &str, node_id: &str) -> Result<f64> {
        self.set_node_status(pool_name, node_id, NodeStatus::Draining)
    }

    /// Sets the operational status of a node in a designated pool.
    pub fn set_node_status(
        &mut self,
        pool_name: &str,
        node_id: &str,
        status: NodeStatus,
    ) -> Result<f64> {
        let pool = self
            .pools
            .get_mut(pool_name)
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::Malformed("pool not found")))?;

        let node = pool.nodes.get_mut(node_id).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("backend node not found in pool"))
        })?;

        node.status = status;
        let churn = pool.rebuild_table();
        Ok(churn)
    }

    /// Resolves target pool name based on L7 application context or defaults.
    pub fn select_pool(&self, l7: Option<&L7Context>) -> &str {
        if let Some(ctx) = l7 {
            for rule in &self.l7_rules {
                let tenant_match = match (&rule.tenant_prefix, &ctx.tenant_id) {
                    (Some(prefix), Some(tenant)) => tenant.starts_with(prefix),
                    (None, _) => true,
                    _ => false,
                };
                let path_match = match (&rule.path_prefix, &ctx.path_prefix) {
                    (Some(prefix), Some(path)) => path.starts_with(prefix),
                    (None, _) => true,
                    _ => false,
                };

                if tenant_match && path_match && self.pools.contains_key(&rule.target_pool) {
                    return &rule.target_pool;
                }
            }
        }
        &self.default_pool
    }

    /// Primary packet/flow routing ingress.
    ///
    /// Evaluates connection stickiness, L7 rules, and Maglev consistent hashing.
    pub fn route_packet(
        &mut self,
        tuple: &FiveTuple,
        l7: Option<&L7Context>,
        payload_bytes: u64,
        now_micros: u64,
    ) -> Result<LbRouteDecision> {
        self.total_routed_packets = self.total_routed_packets.saturating_add(1);

        // 1. Check existing flow in conntrack for stickiness
        if let Some(existing) = self.conntrack.get_flow(tuple) {
            let assigned_id = existing.backend_node_id.clone();
            // Verify if the node is still routable (not Offline)
            for pool in self.pools.values() {
                if let Some(node) = pool.nodes.get(&assigned_id) {
                    if node.status != NodeStatus::Offline {
                        self.total_sticky_hits = self.total_sticky_hits.saturating_add(1);
                        let is_draining = node.status == NodeStatus::Draining;
                        let addr = node.address;

                        // Touch conntrack flow
                        self.conntrack.process_packet(
                            *tuple,
                            assigned_id.clone(),
                            now_micros,
                            payload_bytes,
                            l7.and_then(|c| c.tenant_id.clone()),
                            l7.and_then(|c| c.path_prefix.clone()),
                        );

                        return Ok(LbRouteDecision {
                            pool_name: pool.name.clone(),
                            backend_node_id: assigned_id,
                            backend_address: addr,
                            was_sticky: true,
                            is_draining,
                            table_slot: 0,
                        });
                    }
                }
            }
        }

        // 2. Select target pool (L7 or default)
        let target_pool_name = self.select_pool(l7).to_string();
        let pool = self.pools.get_mut(&target_pool_name).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("target backend pool unavailable"))
        })?;

        // 3. Maglev consistent hashing lookup
        self.total_maglev_lookups = self.total_maglev_lookups.saturating_add(1);
        let hash = tuple.flow_hash();
        let slot = (hash % (pool.table.table_size as u64)) as usize;

        let node_id = pool.table.lookup_hash(hash).cloned().ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("no routable backends in pool"))
        })?;

        let node = pool.nodes.get_mut(&node_id).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("assigned node missing from pool"))
        })?;

        let addr = node.address;
        let is_draining = node.status == NodeStatus::Draining;
        node.active_flows = node.active_flows.saturating_add(1);
        node.total_flows_served = node.total_flows_served.saturating_add(1);
        node.total_bytes_transferred = node.total_bytes_transferred.saturating_add(payload_bytes);

        // 4. Pin new flow into conntrack
        self.conntrack.process_packet(
            *tuple,
            node_id.clone(),
            now_micros,
            payload_bytes,
            l7.and_then(|c| c.tenant_id.clone()),
            l7.and_then(|c| c.path_prefix.clone()),
        );

        Ok(LbRouteDecision {
            pool_name: target_pool_name,
            backend_node_id: node_id,
            backend_address: addr,
            was_sticky: false,
            is_draining,
            table_slot: slot,
        })
    }

    /// Purges expired flows from the connection tracking table.
    pub fn purge_expired_flows(&mut self, now_micros: u64) -> usize {
        self.conntrack.purge_expired(now_micros)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_test_director() -> LoadBalancerDirector {
        let mut director = LoadBalancerDirector::new("default-pool");

        for i in 1..=3 {
            let id = format!("backend-{:02}", i);
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 10 + i as u8)), 7443);
            director
                .add_node("default-pool", BackendNode::new(id, addr, 100))
                .unwrap();
        }

        director
    }

    #[test]
    fn test_director_routing_and_conntrack_stickiness() {
        let mut director = make_test_director();
        let tuple = FiveTuple::mock_quic(30001);

        // 1. Initial routing: Maglev lookup
        let decision1 = director.route_packet(&tuple, None, 1400, 10_000).unwrap();
        assert!(!decision1.was_sticky);
        assert_eq!(director.total_maglev_lookups, 1);
        assert_eq!(director.total_sticky_hits, 0);

        // 2. Second packet for same 5-tuple: Conntrack sticky hit
        let decision2 = director.route_packet(&tuple, None, 1400, 10_500).unwrap();
        assert!(decision2.was_sticky);
        assert_eq!(decision2.backend_node_id, decision1.backend_node_id);
        assert_eq!(director.total_sticky_hits, 1);
    }

    #[test]
    fn test_director_zero_downtime_draining() {
        let mut director = make_test_director();
        let tuple = FiveTuple::mock_quic(30002);

        // Route flow to a node
        let decision1 = director.route_packet(&tuple, None, 1400, 10_000).unwrap();
        let target_node = decision1.backend_node_id.clone();

        // Drain the target node
        director.drain_node("default-pool", &target_node).unwrap();

        // Existing flow should still stick to draining node
        let decision2 = director.route_packet(&tuple, None, 1400, 11_000).unwrap();
        assert!(decision2.was_sticky);
        assert_eq!(decision2.backend_node_id, target_node);
        assert!(decision2.is_draining);

        // But Maglev table must not have any slots assigned to the draining node
        let pool = director.pools.get("default-pool").unwrap();
        for slot_id in &pool.table.lookup {
            assert_ne!(
                slot_id, &target_node,
                "Draining node should not occupy Maglev slots"
            );
        }
    }

    #[test]
    fn test_director_l7_content_routing() {
        let mut director = make_test_director();
        // Add a specialized edge pool
        director.pools.insert(
            "edge-cache-pool".into(),
            BackendPool::new("edge-cache-pool"),
        );
        director
            .add_node(
                "edge-cache-pool",
                BackendNode::new(
                    "edge-01",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)), 7443),
                    100,
                ),
            )
            .unwrap();

        // Add L7 rule: tenant "tenant-media" routes to "edge-cache-pool"
        director.add_l7_rule(L7RouteRule {
            rule_id: "rule-media".into(),
            tenant_prefix: Some("tenant-media".into()),
            path_prefix: None,
            target_pool: "edge-cache-pool".into(),
            priority: 10,
        });

        let tuple = FiveTuple::mock_quic(30003);
        let l7 = L7Context::new().with_tenant("tenant-media-streaming");

        let decision = director
            .route_packet(&tuple, Some(&l7), 2048, 10_000)
            .unwrap();
        assert_eq!(decision.pool_name, "edge-cache-pool");
        assert_eq!(decision.backend_node_id, "edge-01");
    }
}
