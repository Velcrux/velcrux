//! Autonomous L4/L7 Hardware Load Balancer & Maglev Consistent Hashing Multiplexing Engine (`ADR-076`).
//!
//! Features:
//! - Google Maglev consistent hashing algorithm ($M$-entry prime lookup tables).
//! - Minimal disruption guarantee ($\approx 1/N$ remapped slots upon cluster membership change).
//! - High-throughput L4 connection tracking with microsecond state recycling.
//! - Session stickiness and zero-downtime node draining.
//! - Layer-7 content-based routing (QUIC Connection ID, tenant ID, and path prefix).

#![forbid(unsafe_code)]

pub mod conntrack;
pub mod director;
pub mod maglev;
pub mod types;

pub use conntrack::{ConnectionTracker, ConntrackTimeouts};
pub use director::{BackendPool, L7RouteRule, LbRouteDecision, LoadBalancerDirector};
pub use maglev::{MaglevTable, DEFAULT_MAGLEV_M, SMALL_MAGLEV_M};
pub use types::{
    BackendNode, ConnectionState, FiveTuple, FlowRecord, L4Protocol, L7Context, NodeId, NodeStatus,
};
