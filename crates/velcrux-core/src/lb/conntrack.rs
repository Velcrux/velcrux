//! High-Throughput L4 Connection Tracking (conntrack) and State Machine.
//!
//! Tracks active flows, provides session stickiness, and enforces microsecond timeout
//! pruning for idle or terminated connections.

#![forbid(unsafe_code)]

use super::types::{ConnectionState, FiveTuple, FlowRecord, L4Protocol, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configurable connection timeout thresholds in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConntrackTimeouts {
    /// Timeout for active established TCP connections (default: 300 seconds = 300,000,000 µs).
    pub tcp_established_micros: u64,
    /// Timeout for active UDP/QUIC streams (default: 60 seconds = 60,000,000 µs).
    pub quic_established_micros: u64,
    /// Timeout for connections transitioning through closing states (default: 10 seconds = 10,000,000 µs).
    pub closing_micros: u64,
    /// Timeout for unconfirmed/new connections (default: 5 seconds = 5,000,000 µs).
    pub new_flow_micros: u64,
}

impl Default for ConntrackTimeouts {
    fn default() -> Self {
        Self {
            tcp_established_micros: 300_000_000,
            quic_established_micros: 60_000_000,
            closing_micros: 10_000_000,
            new_flow_micros: 5_000_000,
        }
    }
}

/// In-memory L4 Connection Tracking Table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionTracker {
    /// Active flow mapping: FiveTuple -> FlowRecord.
    pub flows: HashMap<FiveTuple, FlowRecord>,
    /// Configured timeout intervals.
    pub timeouts: ConntrackTimeouts,
    /// Telemetry: Total flows instantiated since startup.
    pub total_flows_created: u64,
    /// Telemetry: Total flows purged via timeout expiration.
    pub total_flows_expired: u64,
    /// Telemetry: Total packets processed across all tracked flows.
    pub total_packets_processed: u64,
    /// Telemetry: Total payload bytes processed across all tracked flows.
    pub total_bytes_processed: u64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeouts(timeouts: ConntrackTimeouts) -> Self {
        Self {
            flows: HashMap::new(),
            timeouts,
            total_flows_created: 0,
            total_flows_expired: 0,
            total_packets_processed: 0,
            total_bytes_processed: 0,
        }
    }

    /// Retrieves an existing flow record if currently active and tracked.
    pub fn get_flow(&self, tuple: &FiveTuple) -> Option<&FlowRecord> {
        self.flows.get(tuple)
    }

    /// Tracks a packet for a given 5-tuple: updates an existing flow or instantiates a new one.
    pub fn process_packet(
        &mut self,
        tuple: FiveTuple,
        assigned_node_id: NodeId,
        now_micros: u64,
        payload_bytes: u64,
        l7_tenant: Option<String>,
        l7_path: Option<String>,
    ) -> &FlowRecord {
        self.total_packets_processed = self.total_packets_processed.saturating_add(1);
        self.total_bytes_processed = self.total_bytes_processed.saturating_add(payload_bytes);

        if self.flows.contains_key(&tuple) {
            let record = self.flows.get_mut(&tuple).unwrap();
            record.touch(payload_bytes, now_micros);
            record
        } else {
            self.total_flows_created = self.total_flows_created.saturating_add(1);
            let mut record =
                FlowRecord::new(tuple, assigned_node_id, now_micros, l7_tenant, l7_path);
            record.bytes = payload_bytes;
            self.flows.insert(tuple, record);
            self.flows.get(&tuple).unwrap()
        }
    }

    /// Transitions a flow's connection state (e.g. closing or established).
    pub fn update_state(
        &mut self,
        tuple: &FiveTuple,
        new_state: ConnectionState,
        now_micros: u64,
    ) -> bool {
        if let Some(record) = self.flows.get_mut(tuple) {
            record.state = new_state;
            record.last_seen_micros = now_micros;
            true
        } else {
            false
        }
    }

    /// Purges expired connection tracking entries based on protocol and state timeouts.
    ///
    /// Returns the number of expired flows reclaimed in this pass.
    pub fn purge_expired(&mut self, now_micros: u64) -> usize {
        let timeouts = self.timeouts;
        let mut expired_keys = Vec::new();

        for (tuple, record) in &self.flows {
            let elapsed = now_micros.saturating_sub(record.last_seen_micros);
            let timeout_limit = match record.state {
                ConnectionState::New => timeouts.new_flow_micros,
                ConnectionState::Closing | ConnectionState::Closed => timeouts.closing_micros,
                ConnectionState::Established => match tuple.protocol {
                    L4Protocol::Tcp => timeouts.tcp_established_micros,
                    L4Protocol::Udp | L4Protocol::Quic => timeouts.quic_established_micros,
                },
            };

            if elapsed > timeout_limit {
                expired_keys.push(*tuple);
            }
        }

        let expired_count = expired_keys.len();
        for key in expired_keys {
            self.flows.remove(&key);
        }

        self.total_flows_expired = self
            .total_flows_expired
            .saturating_add(expired_count as u64);
        expired_count
    }

    /// Active tracked flow count.
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conntrack_lifecycle_and_timeout_expiration() {
        let mut timeouts = ConntrackTimeouts::default();
        timeouts.new_flow_micros = 1000;
        timeouts.quic_established_micros = 5000;

        let mut tracker = ConnectionTracker::with_timeouts(timeouts);
        let tuple = FiveTuple::mock_quic(20001);

        // Packet 1: Instantiates flow
        let rec = tracker.process_packet(tuple, "node-01".into(), 10_000, 1024, None, None);
        assert_eq!(rec.state, ConnectionState::New);
        assert_eq!(tracker.active_flow_count(), 1);

        // Packet 2: Touches flow, moves to Established
        let rec2 = tracker.process_packet(tuple, "node-01".into(), 10_500, 2048, None, None);
        assert_eq!(rec2.state, ConnectionState::Established);
        assert_eq!(rec2.bytes, 3072);

        // Check at t=12_000: elapsed = 1500 < 5000 -> not expired
        let purged = tracker.purge_expired(12_000);
        assert_eq!(purged, 0);
        assert_eq!(tracker.active_flow_count(), 1);

        // Check at t=16_000: elapsed = 5500 > 5000 -> expired!
        let purged = tracker.purge_expired(16_000);
        assert_eq!(purged, 1);
        assert_eq!(tracker.active_flow_count(), 0);
        assert_eq!(tracker.total_flows_expired, 1);
    }
}
