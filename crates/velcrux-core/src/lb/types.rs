//! Core data types and structures for the Autonomous L4/L7 Maglev Load Balancer.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Unique identifier for a backend storage or transport node.
pub type NodeId = String;

/// Operational health and routing lifecycle status of a backend node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is healthy and actively receiving new and existing flows.
    Healthy,
    /// Node is operational but reporting degraded metrics; may receive reduced weight.
    Degraded,
    /// Node is undergoing graceful draining; accepts existing established flows only.
    Draining,
    /// Node is unreachable or decommissioned; excluded from lookup table.
    Offline,
}

impl NodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Degraded => "DEGRADED",
            Self::Draining => "DRAINING",
            Self::Offline => "OFFLINE",
        }
    }

    pub fn is_routable_for_new_flows(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    pub fn is_active_for_lookup_table(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Representation of a backend destination node within a load-balanced pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendNode {
    pub id: NodeId,
    pub address: SocketAddr,
    pub weight: u32,
    pub status: NodeStatus,
    pub active_flows: u64,
    pub total_flows_served: u64,
    pub total_bytes_transferred: u64,
}

impl BackendNode {
    pub fn new(id: impl Into<String>, address: SocketAddr, weight: u32) -> Self {
        Self {
            id: id.into(),
            address,
            weight: weight.max(1),
            status: NodeStatus::Healthy,
            active_flows: 0,
            total_flows_served: 0,
            total_bytes_transferred: 0,
        }
    }

    pub fn with_status(mut self, status: NodeStatus) -> Self {
        self.status = status;
        self
    }
}

/// Supported L4 Transport Protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum L4Protocol {
    Tcp,
    Udp,
    Quic,
}

impl L4Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Quic => "QUIC",
        }
    }
}

impl fmt::Display for L4Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Standard 5-Tuple representation for flow identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: L4Protocol,
}

impl FiveTuple {
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: L4Protocol,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        }
    }

    pub fn mock_quic(src_port: u16) -> Self {
        Self {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            src_port,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_port: 7443,
            protocol: L4Protocol::Quic,
        }
    }

    /// Computes a high-entropy 64-bit flow hash for Maglev table lookup.
    pub fn flow_hash(&self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        match self.src_ip {
            IpAddr::V4(v4) => hasher.update(&v4.octets()),
            IpAddr::V6(v6) => hasher.update(&v6.octets()),
        };
        hasher.update(&self.src_port.to_be_bytes());
        match self.dst_ip {
            IpAddr::V4(v4) => hasher.update(&v4.octets()),
            IpAddr::V6(v6) => hasher.update(&v6.octets()),
        };
        hasher.update(&self.dst_port.to_be_bytes());
        match self.protocol {
            L4Protocol::Tcp => hasher.update(&[0x06]),
            L4Protocol::Udp => hasher.update(&[0x11]),
            L4Protocol::Quic => hasher.update(&[0x51]), // 'Q'
        };
        let hash_bytes = hasher.finalize();
        u64::from_le_bytes(hash_bytes.as_bytes()[0..8].try_into().unwrap())
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

/// L4 Connection Tracking Lifecycle State.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Established,
    Closing,
    Closed,
}

impl ConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "NEW",
            Self::Established => "ESTABLISHED",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
        }
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Active connection tracking record pinned to a backend node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    pub tuple: FiveTuple,
    pub backend_node_id: NodeId,
    pub state: ConnectionState,
    pub created_at_micros: u64,
    pub last_seen_micros: u64,
    pub packets: u64,
    pub bytes: u64,
    pub l7_tenant: Option<String>,
    pub l7_path: Option<String>,
}

impl FlowRecord {
    pub fn new(
        tuple: FiveTuple,
        backend_node_id: NodeId,
        now_micros: u64,
        l7_tenant: Option<String>,
        l7_path: Option<String>,
    ) -> Self {
        Self {
            tuple,
            backend_node_id,
            state: ConnectionState::New,
            created_at_micros: now_micros,
            last_seen_micros: now_micros,
            packets: 1,
            bytes: 0,
            l7_tenant,
            l7_path,
        }
    }

    pub fn touch(&mut self, bytes: u64, now_micros: u64) {
        self.last_seen_micros = now_micros;
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.state == ConnectionState::New {
            self.state = ConnectionState::Established;
        }
    }
}

/// Layer-7 application metadata used for content-based flow routing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7Context {
    pub tenant_id: Option<String>,
    pub path_prefix: Option<String>,
    pub quic_connection_id: Option<String>,
    pub priority: u8,
}

impl L7Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant.into());
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path_prefix = Some(path.into());
        self
    }

    pub fn with_quic_cid(mut self, cid: impl Into<String>) -> Self {
        self.quic_connection_id = Some(cid.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_five_tuple_hash_stability_and_entropy() {
        let t1 = FiveTuple::mock_quic(10001);
        let t2 = FiveTuple::mock_quic(10002);
        assert_eq!(t1.flow_hash(), t1.flow_hash());
        assert_ne!(t1.flow_hash(), t2.flow_hash());
    }

    #[test]
    fn test_node_status_routing_predicates() {
        assert!(NodeStatus::Healthy.is_routable_for_new_flows());
        assert!(NodeStatus::Degraded.is_routable_for_new_flows());
        assert!(!NodeStatus::Draining.is_routable_for_new_flows());
        assert!(!NodeStatus::Offline.is_routable_for_new_flows());
    }
}
