//! Vector Clocks and Hybrid Logical Clocks (HLC) for Causality Tracking.
//!
//! Provides mathematically sound causality ordering across distributed clusters,
//! supporting partial ordering, concurrency detection, and clock skew bounding.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Causality comparison relation between two vector clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalOrder {
    /// Clock A strictly happened before Clock B.
    Before,
    /// Clock A strictly happened after Clock B.
    After,
    /// Clock A and Clock B are identical.
    Equal,
    /// Clock A and Clock B are concurrent (causally independent conflict).
    Concurrent,
}

/// Vector Clock tracking logical causality across distributed cluster nodes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct VectorClock {
    /// Mapping of node/region identifier to logical sequence counter.
    pub entries: BTreeMap<String, u64>,
}

impl VectorClock {
    /// Create a new, empty Vector Clock.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Increment logical counter for a given node.
    pub fn tick(&mut self, node: &str) -> u64 {
        let entry = self.entries.entry(node.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Update logical counter for a given node to at least the given timestamp.
    pub fn update(&mut self, node: &str, timestamp: u64) {
        let entry = self.entries.entry(node.to_string()).or_insert(0);
        *entry = (*entry).max(timestamp);
    }

    /// Get current timestamp for a node, or 0 if unrecorded.
    pub fn get(&self, node: &str) -> u64 {
        self.entries.get(node).copied().unwrap_or(0)
    }

    /// Merge another vector clock into this one by taking component-wise maximums.
    pub fn merge(&mut self, other: &VectorClock) {
        for (node, &val) in &other.entries {
            let entry = self.entries.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(val);
        }
    }

    /// Returns a merged copy without mutating the original.
    pub fn merged(&self, other: &VectorClock) -> VectorClock {
        let mut res = self.clone();
        res.merge(other);
        res
    }

    /// Compare causal relationship against another vector clock.
    pub fn compare(&self, other: &VectorClock) -> CausalOrder {
        let mut self_greater = false;
        let mut other_greater = false;

        let mut all_keys = self
            .entries
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        for k in other.entries.keys() {
            all_keys.insert(k);
        }

        for &k in &all_keys {
            let v1 = self.get(k);
            let v2 = other.get(k);

            if v1 > v2 {
                self_greater = true;
            } else if v1 < v2 {
                other_greater = true;
            }
        }

        match (self_greater, other_greater) {
            (false, false) => CausalOrder::Equal,
            (true, false) => CausalOrder::After,
            (false, true) => CausalOrder::Before,
            (true, true) => CausalOrder::Concurrent,
        }
    }

    /// Returns true if this clock strictly happened before `other`.
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        self.compare(other) == CausalOrder::Before
    }

    /// Returns true if this clock is concurrent with `other`.
    pub fn is_concurrent_with(&self, other: &VectorClock) -> bool {
        self.compare(other) == CausalOrder::Concurrent
    }

    /// Returns true if this clock dominates (is greater than or equal to) `other`.
    pub fn dominates(&self, other: &VectorClock) -> bool {
        matches!(self.compare(other), CausalOrder::After | CausalOrder::Equal)
    }
}

/// Hybrid Logical Clock (HLC) combining physical wall time and logical sequence.
///
/// Ensures monotonic progress, causal ordering, and bounded drift against physical clocks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Hlc {
    /// Physical timestamp in milliseconds since Unix Epoch.
    pub physical_ms: u64,
    /// Logical counter for sub-millisecond events or clock skew catch-up.
    pub logical: u32,
    /// Node or region identifier used for deterministic tie-breaking.
    pub node_id: String,
}

impl Hlc {
    /// Initialize a new HLC for a specific node at current system time.
    pub fn new(node_id: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            physical_ms: now,
            logical: 0,
            node_id: node_id.into(),
        }
    }

    /// Construct with explicit physical and logical components.
    pub fn with_values(node_id: impl Into<String>, physical_ms: u64, logical: u32) -> Self {
        Self {
            physical_ms,
            logical,
            node_id: node_id.into(),
        }
    }

    /// Update HLC on a local send event or state mutation.
    pub fn on_send(&mut self) -> Hlc {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if now > self.physical_ms {
            self.physical_ms = now;
            self.logical = 0;
        } else {
            self.logical += 1;
        }

        self.clone()
    }

    /// Update HLC on receiving a remote message from a peer.
    pub fn on_recv(&mut self, remote: &Hlc) -> Hlc {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let max_phys = self.physical_ms.max(remote.physical_ms).max(now);

        if max_phys == self.physical_ms && max_phys == remote.physical_ms {
            self.logical = self.logical.max(remote.logical) + 1;
        } else if max_phys == self.physical_ms {
            self.logical += 1;
        } else if max_phys == remote.physical_ms {
            self.logical = remote.logical + 1;
        } else {
            self.logical = 0;
        }

        self.physical_ms = max_phys;
        self.clone()
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.physical_ms
            .cmp(&other.physical_ms)
            .then_with(|| self.logical.cmp(&other.logical))
            .then_with(|| self.node_id.cmp(&other.node_id))
    }
}
