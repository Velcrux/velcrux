//! Anti-Entropy Gossip Synchronization Protocol & Delta-State Exchange.
//!
//! Minimizes cross-region WAN bandwidth consumption by exchanging delta mutations
//! scoped to vector clock causal horizons.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use crate::crdt::clock::{Hlc, VectorClock};
use crate::crdt::tree::{FsMergeReport, FsNode, ReplicatedFsTree};

/// Delta state payload containing only nodes modified since a vector clock watermark.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrdtDelta {
    pub origin_region: String,
    pub vclock: VectorClock,
    pub hlc: Hlc,
    pub mutated_nodes: Vec<FsNode>,
}

/// Digest summary representing the causal epoch and content hash of a replica.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DigestSummary {
    pub region_id: String,
    pub state_digest: String,
    pub vclock: VectorClock,
    pub active_nodes: usize,
}

/// Telemetry metrics for an anti-entropy synchronization exchange.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AntiEntropyReport {
    pub region_a: String,
    pub region_b: String,
    pub delta_a_to_b_nodes: usize,
    pub delta_b_to_a_nodes: usize,
    pub merge_report_a: FsMergeReport,
    pub merge_report_b: FsMergeReport,
    pub state_divergent_before: bool,
    pub state_converged_after: bool,
    pub final_state_digest: String,
}

/// Anti-Entropy Gossip Synchronization Engine.
pub struct AntiEntropyEngine;

impl AntiEntropyEngine {
    /// Compute a delta of nodes in `tree` that are newer than `peer_watermark`.
    pub fn compute_delta(tree: &ReplicatedFsTree, peer_watermark: &VectorClock) -> CrdtDelta {
        let mut mutated = Vec::new();

        for node in tree.nodes.values() {
            let node_region = &node.hlc.node_id;
            let peer_counter = peer_watermark.get(node_region);

            // If the node's HLC indicates mutation past the peer's observed counter, include it
            if node.hlc.logical as u64 >= peer_counter
                || tree.vclock.get(node_region) > peer_counter
            {
                mutated.push(node.clone());
            }
        }

        CrdtDelta {
            origin_region: tree.region_id.clone(),
            vclock: tree.vclock.clone(),
            hlc: tree.hlc.clone(),
            mutated_nodes: mutated,
        }
    }

    /// Apply a received delta into a local tree replica.
    pub fn apply_delta(tree: &mut ReplicatedFsTree, delta: &CrdtDelta) -> FsMergeReport {
        let mut report = FsMergeReport::default();

        tree.vclock.merge(&delta.vclock);
        tree.hlc.on_recv(&delta.hlc);

        for node in &delta.mutated_nodes {
            match tree.nodes.get(&node.path).cloned() {
                Some(local_node) => {
                    if local_node == *node {
                        report.identical_nodes += 1;
                    } else {
                        report.conflicts_resolved += 1;
                        if node.hlc > local_node.hlc {
                            if node.is_deleted && !local_node.is_deleted {
                                report.nodes_deleted += 1;
                            } else {
                                report.nodes_updated += 1;
                            }
                            tree.nodes.insert(node.path.clone(), node.clone());
                        }
                    }
                }
                None => {
                    report.nodes_added += 1;
                    tree.nodes.insert(node.path.clone(), node.clone());
                }
            }
        }

        report
    }

    /// Perform a full bidirectional anti-entropy exchange between two replicas.
    pub fn exchange(
        tree_a: &mut ReplicatedFsTree,
        tree_b: &mut ReplicatedFsTree,
    ) -> AntiEntropyReport {
        let digest_a_before = tree_a.state_digest();
        let digest_b_before = tree_b.state_digest();
        let divergent_before = digest_a_before != digest_b_before;

        // 1. Compute delta from A to B
        let delta_a = Self::compute_delta(tree_a, &tree_b.vclock);
        let count_a_to_b = delta_a.mutated_nodes.len();

        // 2. Compute delta from B to A
        let delta_b = Self::compute_delta(tree_b, &tree_a.vclock);
        let count_b_to_a = delta_b.mutated_nodes.len();

        // 3. Apply deltas
        let merge_b = Self::apply_delta(tree_b, &delta_a);
        let merge_a = Self::apply_delta(tree_a, &delta_b);

        let digest_a_after = tree_a.state_digest();
        let digest_b_after = tree_b.state_digest();
        let converged = digest_a_after == digest_b_after;

        AntiEntropyReport {
            region_a: tree_a.region_id.clone(),
            region_b: tree_b.region_id.clone(),
            delta_a_to_b_nodes: count_a_to_b,
            delta_b_to_a_nodes: count_b_to_a,
            merge_report_a: merge_a,
            merge_report_b: merge_b,
            state_divergent_before: divergent_before,
            state_converged_after: converged,
            final_state_digest: digest_a_after,
        }
    }

    /// Summarize current state of a tree into a `DigestSummary`.
    pub fn summarize(tree: &ReplicatedFsTree) -> DigestSummary {
        DigestSummary {
            region_id: tree.region_id.clone(),
            state_digest: tree.state_digest(),
            vclock: tree.vclock.clone(),
            active_nodes: tree.nodes.values().filter(|n| !n.is_deleted).count(),
        }
    }
}
