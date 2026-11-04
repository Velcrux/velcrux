//! Multi-Region Geo-Replication Topology & Convergence Mesh.
//!
//! Orchestrates active-active multi-datacenter clusters, models network partitions,
//! and runs gossip anti-entropy reconciliation across global topologies.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use crate::crdt::sync::{AntiEntropyEngine, AntiEntropyReport, DigestSummary};
use crate::crdt::tree::ReplicatedFsTree;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

/// Status and connection attributes for a regional cluster.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegionInfo {
    pub region_id: String,
    pub name: String,
    pub endpoint: String,
    pub rtt_ms: u64,
    pub is_partitioned: bool,
}

/// Structured benchmark and convergence report for multi-region geo-replication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoBenchmarkReport {
    pub num_regions: usize,
    pub total_mutations: usize,
    pub partition_simulated: bool,
    pub sync_cycles: usize,
    pub duration_millis: f64,
    pub fully_converged: bool,
    pub final_digest: String,
    pub total_conflicts_resolved: usize,
}

/// Global Multi-Cluster Geo-Replication Mesh.
pub struct GeoMesh {
    /// Replicated trees for each region.
    pub trees: BTreeMap<String, ReplicatedFsTree>,
    /// Metadata for each region.
    pub regions: BTreeMap<String, RegionInfo>,
    /// Set of partitioned bidirectional link pairs: (RegionA, RegionB).
    pub partitioned_links: BTreeSet<(String, String)>,
}

impl GeoMesh {
    /// Initialize an empty Geo-Replication Mesh.
    pub fn new() -> Self {
        Self {
            trees: BTreeMap::new(),
            regions: BTreeMap::new(),
            partitioned_links: BTreeSet::new(),
        }
    }

    /// Register a regional cluster in the global mesh.
    pub fn add_region(&mut self, region_id: &str, name: &str, endpoint: &str, rtt_ms: u64) {
        let tree = ReplicatedFsTree::new(region_id);
        let info = RegionInfo {
            region_id: region_id.to_string(),
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            rtt_ms,
            is_partitioned: false,
        };

        self.trees.insert(region_id.to_string(), tree);
        self.regions.insert(region_id.to_string(), info);
    }

    /// Isolate or reconnect a bidirectional network link between two regions.
    pub fn set_partition(&mut self, region_a: &str, region_b: &str, partitioned: bool) {
        let pair1 = (region_a.to_string(), region_b.to_string());
        let pair2 = (region_b.to_string(), region_a.to_string());

        if partitioned {
            self.partitioned_links.insert(pair1);
            self.partitioned_links.insert(pair2);
            if let Some(r) = self.regions.get_mut(region_a) {
                r.is_partitioned = true;
            }
            if let Some(r) = self.regions.get_mut(region_b) {
                r.is_partitioned = true;
            }
        } else {
            self.partitioned_links.remove(&pair1);
            self.partitioned_links.remove(&pair2);
            if let Some(r) = self.regions.get_mut(region_a) {
                r.is_partitioned = false;
            }
            if let Some(r) = self.regions.get_mut(region_b) {
                r.is_partitioned = false;
            }
        }
    }

    /// Check if a network link between two regions is partitioned.
    pub fn is_link_partitioned(&self, region_a: &str, region_b: &str) -> bool {
        self.partitioned_links
            .contains(&(region_a.to_string(), region_b.to_string()))
    }

    /// Execute a file creation mutation on a specific regional replica.
    pub fn create_file(
        &mut self,
        region_id: &str,
        path: &str,
        size_bytes: u64,
        blake3_hash: Option<String>,
        chunk_count: u32,
    ) -> Result<(), &'static str> {
        let tree = self
            .trees
            .get_mut(region_id)
            .ok_or("Region not found in mesh")?;
        tree.create_file(path, size_bytes, blake3_hash, chunk_count);
        Ok(())
    }

    /// Execute a file or directory deletion on a specific regional replica.
    pub fn delete_node(
        &mut self,
        region_id: &str,
        path: &str,
    ) -> Result<Vec<String>, &'static str> {
        let tree = self
            .trees
            .get_mut(region_id)
            .ok_or("Region not found in mesh")?;
        Ok(tree.delete(path))
    }

    /// Trigger a full round of anti-entropy gossip synchronization across all non-partitioned links.
    pub fn sync_all(&mut self) -> Vec<AntiEntropyReport> {
        let region_ids: Vec<String> = self.trees.keys().cloned().collect();
        let mut reports = Vec::new();

        for i in 0..region_ids.len() {
            for j in (i + 1)..region_ids.len() {
                let ra = &region_ids[i];
                let rb = &region_ids[j];

                if !self.is_link_partitioned(ra, rb) {
                    // Extract tree_a and tree_b mutably
                    if let (Some(mut tree_a), Some(mut tree_b)) =
                        (self.trees.remove(ra), self.trees.remove(rb))
                    {
                        let report = AntiEntropyEngine::exchange(&mut tree_a, &mut tree_b);
                        reports.push(report);
                        self.trees.insert(ra.clone(), tree_a);
                        self.trees.insert(rb.clone(), tree_b);
                    }
                }
            }
        }

        reports
    }

    /// Verify whether all non-partitioned regions have converged to the identical state digest.
    pub fn verify_convergence(&self) -> bool {
        let mut digests = BTreeSet::new();
        for tree in self.trees.values() {
            digests.insert(tree.state_digest());
        }
        digests.len() <= 1
    }

    /// Retrieve state digest summaries for all regions in the mesh.
    pub fn summaries(&self) -> Vec<DigestSummary> {
        self.trees
            .values()
            .map(AntiEntropyEngine::summarize)
            .collect()
    }

    /// Run an automated multi-region geo-replication benchmark.
    pub fn run_benchmark(
        num_regions: usize,
        files_per_region: usize,
        simulate_partition: bool,
    ) -> GeoBenchmarkReport {
        let start = Instant::now();
        let mut mesh = GeoMesh::new();

        // Standard regional topology
        let standard_regions = [
            ("us-east", "US East (N. Virginia)", "10.0.1.1:7443", 25),
            ("eu-west", "EU West (Frankfurt)", "10.0.2.1:7443", 95),
            ("ap-se", "AP Southeast (Singapore)", "10.0.3.1:7443", 180),
            ("sa-east", "SA East (São Paulo)", "10.0.4.1:7443", 130),
        ];

        let count = num_regions.min(standard_regions.len());
        for (id, name, ep, rtt) in standard_regions.iter().take(count) {
            mesh.add_region(id, name, ep, *rtt);
        }

        // Simulate network partition if enabled
        if simulate_partition && count >= 2 {
            mesh.set_partition("us-east", "eu-west", true);
        }

        // Concurrent independent file mutations across regions
        let mut total_mutations = 0;
        let region_keys: Vec<String> = mesh.trees.keys().cloned().collect();

        for (idx, r) in region_keys.iter().enumerate() {
            for f in 0..files_per_region {
                let path = format!("/datasets/region-{}/model-{}.bin", r, f);
                let size = (1024 * 1024 * (f + 1)) as u64;
                let hash = format!("blake3-digest-{}-{}", idx, f);
                let _ = mesh.create_file(r, &path, size, Some(hash), 64);
                total_mutations += 1;
            }
        }

        // If partitioned, heal the partition to test convergence
        if simulate_partition && count >= 2 {
            mesh.set_partition("us-east", "eu-west", false);
        }

        // Run anti-entropy gossip cycles until convergence or max cycles
        let mut sync_cycles = 0;
        let mut total_conflicts_resolved = 0;

        for _ in 0..5 {
            sync_cycles += 1;
            let reports = mesh.sync_all();
            for rep in reports {
                total_conflicts_resolved +=
                    rep.merge_report_a.conflicts_resolved + rep.merge_report_b.conflicts_resolved;
            }
            if mesh.verify_convergence() {
                break;
            }
        }

        let converged = mesh.verify_convergence();
        let final_digest = mesh
            .trees
            .values()
            .next()
            .map(|t| t.state_digest())
            .unwrap_or_default();

        let elapsed = start.elapsed();

        GeoBenchmarkReport {
            num_regions: count,
            total_mutations,
            partition_simulated: simulate_partition,
            sync_cycles,
            duration_millis: elapsed.as_secs_f64() * 1000.0,
            fully_converged: converged,
            final_digest,
            total_conflicts_resolved,
        }
    }
}

impl Default for GeoMesh {
    fn default() -> Self {
        Self::new()
    }
}
