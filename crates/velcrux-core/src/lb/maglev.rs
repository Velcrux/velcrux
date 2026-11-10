//! Google Maglev Consistent Hashing Algorithm Implementation.
//!
//! Provides lookup table construction over a prime modulus $M$, generating pseudo-random
//! permutations for each backend node to ensure minimal disruption during membership changes.

#![forbid(unsafe_code)]

use super::types::{BackendNode, FiveTuple, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default Maglev lookup table size: Fermat prime $2^{16} + 1 = 65537$.
pub const DEFAULT_MAGLEV_M: usize = 65537;

/// Smaller prime for lightweight testing or constrained memory footprints.
pub const SMALL_MAGLEV_M: usize = 10007;

/// Maglev Consistent Hashing Lookup Table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaglevTable {
    /// Prime table capacity $M$.
    pub table_size: usize,
    /// Direct index-to-NodeId lookup table array of length $M$.
    pub lookup: Vec<NodeId>,
    /// Active backend node list used to construct the table.
    pub active_nodes: Vec<BackendNode>,
    /// Slot allocation distribution count per node ID.
    pub slot_counts: HashMap<NodeId, usize>,
    /// Generation / epoch counter for cache invalidation.
    pub epoch: u64,
}

impl MaglevTable {
    /// Constructs a Maglev table with default prime size (65537).
    pub fn build(nodes: &[BackendNode], epoch: u64) -> Self {
        Self::build_with_capacity(nodes, DEFAULT_MAGLEV_M, epoch)
    }

    /// Constructs a Maglev table with custom prime size $M$.
    pub fn build_with_capacity(nodes: &[BackendNode], table_size: usize, epoch: u64) -> Self {
        let routable: Vec<BackendNode> = nodes
            .iter()
            .filter(|n| n.status.is_active_for_lookup_table())
            .cloned()
            .collect();

        if routable.is_empty() {
            return Self {
                table_size,
                lookup: vec![String::new(); table_size],
                active_nodes: Vec::new(),
                slot_counts: HashMap::new(),
                epoch,
            };
        }

        let n = routable.len();
        let m = table_size;

        // Precompute (offset, skip) for each active backend node
        // offset = Hash1(node_id) mod M
        // skip = (Hash2(node_id) mod (M - 1)) + 1
        let mut offsets = Vec::with_capacity(n);
        let mut skips = Vec::with_capacity(n);

        for node in &routable {
            let (off, sk) = compute_offset_and_skip(&node.id, m);
            offsets.push(off);
            skips.push(sk);
        }

        // Table array initialized to empty (-1 sentinel)
        let mut table: Vec<Option<usize>> = vec![None; m];
        let mut next_pos: Vec<usize> = vec![0; n];
        let mut slots_filled = 0;

        // Populate table: nodes take turns filling empty slots in weighted rounds
        while slots_filled < m {
            let mut made_progress = false;

            for i in 0..n {
                let weight = routable[i].weight.max(1) as usize;
                let mut claims_this_turn = 0;

                while claims_this_turn < weight && slots_filled < m {
                    // Compute candidate slot: (offset + next * skip) % M
                    let c = (offsets[i] + next_pos[i] * skips[i]) % m;
                    next_pos[i] += 1;

                    if table[c].is_none() {
                        table[c] = Some(i);
                        slots_filled += 1;
                        claims_this_turn += 1;
                        made_progress = true;
                    }

                    // Guard against cycling through all M permutations
                    if next_pos[i] >= m * 2 {
                        break;
                    }
                }
            }

            if !made_progress && slots_filled < m {
                // In the rare event of empty slots remaining due to weight discrepancies,
                // fill any remaining gaps with round-robin among active nodes.
                for (idx, slot) in table.iter_mut().enumerate() {
                    if slot.is_none() {
                        *slot = Some(idx % n);
                        slots_filled += 1;
                    }
                }
                break;
            }
        }

        // Materialize lookup table with NodeId strings
        let mut lookup = Vec::with_capacity(m);
        let mut slot_counts: HashMap<NodeId, usize> = HashMap::new();

        for slot_opt in table {
            let node_idx = slot_opt.unwrap_or(0);
            let node_id = routable[node_idx].id.clone();
            *slot_counts.entry(node_id.clone()).or_insert(0) += 1;
            lookup.push(node_id);
        }

        Self {
            table_size: m,
            lookup,
            active_nodes: routable,
            slot_counts,
            epoch,
        }
    }

    /// Looks up the designated backend node ID for a given 5-tuple flow.
    pub fn lookup_tuple(&self, tuple: &FiveTuple) -> Option<&NodeId> {
        if self.lookup.is_empty() || self.active_nodes.is_empty() {
            return None;
        }
        let hash = tuple.flow_hash();
        let slot = (hash % (self.table_size as u64)) as usize;
        let id = &self.lookup[slot];
        if id.is_empty() {
            None
        } else {
            Some(id)
        }
    }

    /// Looks up the designated backend node ID from a raw 64-bit flow hash.
    pub fn lookup_hash(&self, hash: u64) -> Option<&NodeId> {
        if self.lookup.is_empty() || self.active_nodes.is_empty() {
            return None;
        }
        let slot = (hash % (self.table_size as u64)) as usize;
        let id = &self.lookup[slot];
        if id.is_empty() {
            None
        } else {
            Some(id)
        }
    }

    /// Computes the exact churn / disruption percentage between this table and another.
    ///
    /// Minimal disruption guarantee: adding or removing a node from an $N$-node cluster
    /// results in remapping approximately $1/N$ fraction of the table slots.
    pub fn compute_churn_percentage(&self, other: &MaglevTable) -> f64 {
        if self.table_size == 0 || other.table_size == 0 || self.table_size != other.table_size {
            return 100.0;
        }

        let mut diff_count = 0;
        for i in 0..self.table_size {
            if self.lookup[i] != other.lookup[i] {
                diff_count += 1;
            }
        }

        (diff_count as f64 / self.table_size as f64) * 100.0
    }
}

/// Computes deterministic `offset` and `skip` values from a node ID and table size $M$.
///
/// Ensures $offset \in [0, M-1]$ and $skip \in [1, M-1]$.
fn compute_offset_and_skip(node_id: &str, m: usize) -> (usize, usize) {
    // Hash 1: Offset
    let mut h1 = blake3::Hasher::new();
    h1.update(b"velcrux_maglev_offset_v1:");
    h1.update(node_id.as_bytes());
    let b1 = h1.finalize();
    let val1 = u64::from_le_bytes(b1.as_bytes()[0..8].try_into().unwrap());
    let offset = (val1 % (m as u64)) as usize;

    // Hash 2: Skip
    let mut h2 = blake3::Hasher::new();
    h2.update(b"velcrux_maglev_skip_v1:");
    h2.update(node_id.as_bytes());
    let b2 = h2.finalize();
    let val2 = u64::from_le_bytes(b2.as_bytes()[0..8].try_into().unwrap());
    // skip must be in 1..(M - 1), and since M is prime, gcd(skip, M) == 1
    let m_minus_1 = if m > 1 { m - 1 } else { 1 };
    let skip = ((val2 % (m_minus_1 as u64)) as usize) + 1;

    (offset, skip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_test_nodes(count: usize) -> Vec<BackendNode> {
        (0..count)
            .map(|i| {
                let id = format!("storage-node-{:02}", i + 1);
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 10 + i as u8)), 7443);
                BackendNode::new(id, addr, 100)
            })
            .collect()
    }

    #[test]
    fn test_maglev_table_build_and_lookup_distribution() {
        let nodes = make_test_nodes(5);
        let table = MaglevTable::build_with_capacity(&nodes, SMALL_MAGLEV_M, 1);

        assert_eq!(table.lookup.len(), SMALL_MAGLEV_M);
        assert_eq!(table.active_nodes.len(), 5);

        // Verify each node receives approximately equal share (~20% +/- 5%)
        let expected_per_node = SMALL_MAGLEV_M / 5;
        for node in &nodes {
            let count = table.slot_counts.get(&node.id).copied().unwrap_or(0);
            let diff = (count as i64 - expected_per_node as i64).abs();
            assert!(
                diff < (expected_per_node as i64 / 4),
                "Node {} has uneven distribution: count={count}, expected={expected_per_node}",
                node.id
            );
        }
    }

    #[test]
    fn test_maglev_minimal_disruption_on_node_addition() {
        let nodes_4 = make_test_nodes(4);
        let table_4 = MaglevTable::build_with_capacity(&nodes_4, SMALL_MAGLEV_M, 1);

        let nodes_5 = make_test_nodes(5);
        let table_5 = MaglevTable::build_with_capacity(&nodes_5, SMALL_MAGLEV_M, 2);

        let churn = table_4.compute_churn_percentage(&table_5);
        // Adding 1 node to 4 should cause ~ 20% to 25% churn (1/5th to 1/4th)
        assert!(
            churn >= 15.0 && churn <= 35.0,
            "Churn was {churn}%, expected around ~20-25%"
        );
    }

    #[test]
    fn test_maglev_weighted_slot_allocation() {
        let mut nodes = make_test_nodes(2);
        nodes[0].weight = 300; // 3x weight
        nodes[1].weight = 100;

        let table = MaglevTable::build_with_capacity(&nodes, SMALL_MAGLEV_M, 1);
        let c0 = table.slot_counts.get(&nodes[0].id).copied().unwrap_or(0);
        let c1 = table.slot_counts.get(&nodes[1].id).copied().unwrap_or(0);

        let ratio = c0 as f64 / c1 as f64;
        assert!(
            (ratio - 3.0).abs() < 0.5,
            "Expected 3:1 weight ratio, got {ratio:.2} ({c0} vs {c1})"
        );
    }
}
