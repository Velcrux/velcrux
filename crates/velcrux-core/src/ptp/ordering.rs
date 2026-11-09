#![forbid(unsafe_code)]

//! Bounded-Skew Multi-Region Transfer Ordering Mesh & TrueTime-Style Bounded Uncertainty.
//!
//! Provides globally consistent causal commit ordering across geo-distributed regions
//! by modeling clock uncertainty intervals $[t - \epsilon, t + \epsilon]$ derived from
//! PTP nanosecond synchronization bounds.

use super::servo::ClockServo;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Bounded Timestamp Interval representing $[t - \epsilon, t + \epsilon]$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedTimestamp {
    pub center_nanos: u64,
    pub uncertainty_epsilon_nanos: u64,
}

impl BoundedTimestamp {
    pub fn new(center_nanos: u64, epsilon_nanos: u64) -> Self {
        Self {
            center_nanos,
            uncertainty_epsilon_nanos: epsilon_nanos,
        }
    }

    pub fn earliest_nanos(&self) -> u64 {
        self.center_nanos
            .saturating_sub(self.uncertainty_epsilon_nanos)
    }

    pub fn latest_nanos(&self) -> u64 {
        self.center_nanos
            .saturating_add(self.uncertainty_epsilon_nanos)
    }

    /// Evaluates definitive causal ordering between two bounded timestamps:
    /// - `Some(Ordering::Less)` if `self` strictly preceded `other` ($t_{self}^{latest} < t_{other}^{earliest}$)
    /// - `Some(Ordering::Greater)` if `other` strictly preceded `self` ($t_{other}^{latest} < t_{self}^{earliest}$)
    /// - `None` if uncertainty intervals overlap (concurrent or unorderable without wait).
    pub fn causal_order(&self, other: &Self) -> Option<Ordering> {
        if self.latest_nanos() < other.earliest_nanos() {
            Some(Ordering::Less)
        } else if other.latest_nanos() < self.earliest_nanos() {
            Some(Ordering::Greater)
        } else {
            None // Overlapping uncertainty interval
        }
    }
}

/// Commit ordering record assigned to a multi-region data transfer or transactional update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderedTransferCommit {
    pub transfer_id: String,
    pub region_id: String,
    pub timestamp: BoundedTimestamp,
    pub required_wait_nanos: u64,
}

/// Bounded Transfer Ordering Mesh Coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedOrderMesh {
    pub local_region_id: String,
    pub max_expected_network_jitter_nanos: u64,
}

impl BoundedOrderMesh {
    pub fn new(region_id: impl Into<String>, network_jitter_nanos: u64) -> Self {
        Self {
            local_region_id: region_id.into(),
            max_expected_network_jitter_nanos: network_jitter_nanos,
        }
    }

    /// Computes current bounded timestamp derived from the active PTP clock servo state.
    pub fn current_bounded_timestamp(
        &self,
        servo: &ClockServo,
        raw_local_nanos: u64,
    ) -> BoundedTimestamp {
        let sync_ts = servo.get_synchronized_time(raw_local_nanos);
        let center = sync_ts.to_nanos_total();

        // Epsilon is derived from servo jitter RMS + current offset magnitude + path jitter
        let servo_uncertainty = (servo.current_offset_nanos.unsigned_abs())
            .saturating_add(servo.jitter_rms_nanos.round() as u64);
        let total_epsilon =
            servo_uncertainty.saturating_add(self.max_expected_network_jitter_nanos);

        BoundedTimestamp::new(center, total_epsilon.max(10))
    }

    /// Allocates an ordered commit timestamp for a transfer, computing the wait-until-safe window ($2\epsilon$).
    pub fn allocate_commit(
        &self,
        transfer_id: impl Into<String>,
        servo: &ClockServo,
        raw_local_nanos: u64,
    ) -> OrderedTransferCommit {
        let bts = self.current_bounded_timestamp(servo, raw_local_nanos);
        let wait_nanos = bts.uncertainty_epsilon_nanos * 2;

        OrderedTransferCommit {
            transfer_id: transfer_id.into(),
            region_id: self.local_region_id.clone(),
            timestamp: bts,
            required_wait_nanos: wait_nanos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_timestamp_causal_ordering() {
        // Event A: center = 1000, eps = 50 -> [950, 1050]
        let ev_a = BoundedTimestamp::new(1000, 50);

        // Event B: center = 1200, eps = 50 -> [1150, 1250]
        // Since 1050 < 1150, Event A strictly precedes Event B
        let ev_b = BoundedTimestamp::new(1200, 50);
        assert_eq!(ev_a.causal_order(&ev_b), Some(Ordering::Less));
        assert_eq!(ev_b.causal_order(&ev_a), Some(Ordering::Greater));

        // Event C: center = 1080, eps = 50 -> [1030, 1130]
        // Overlaps with Event A [950, 1050]
        let ev_c = BoundedTimestamp::new(1080, 50);
        assert_eq!(ev_a.causal_order(&ev_c), None);
    }

    #[test]
    fn test_order_mesh_allocation_and_wait_window() {
        let mesh = BoundedOrderMesh::new("us-east-1", 100);
        let servo = ClockServo::default();

        let commit = mesh.allocate_commit("xfer-9001", &servo, 1_000_000_000);
        assert_eq!(commit.transfer_id, "xfer-9001");
        assert_eq!(commit.region_id, "us-east-1");
        assert!(commit.required_wait_nanos >= 200);
    }
}
