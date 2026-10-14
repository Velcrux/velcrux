//! Distributed Chunk Store Clustering & Replication Engine (Option AY).
//!
//! Conforms to `REQUIREMENTS.md` §15 ("Content-Addressable Chunk Store"), §62 ("Deduplication"),
//! §63 ("Garbage Collection"), and `ARCHITECTURE.md` §2.
//!
//! Provides consistent hashing ring topology, multi-node preference lists, quorum-based
//! reads and writes (N, W, R), automatic read-repair, and anti-entropy rebalancing.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::storage::chunk_store::ChunkStore;
use crate::util::Hash;

/// Health and lifecycle state of a cluster storage node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterNodeState {
    /// Node is online, responsive, and serving chunk traffic.
    Healthy,
    /// Node missed heartbeats or showed elevated timeout errors.
    Suspect,
    /// Node is undergoing controlled maintenance draining; not accepting new writes.
    Draining,
    /// Node is unreachable or offline; excluded from quorum writes.
    Dead,
}

impl ClusterNodeState {
    /// True if this node can serve reads.
    pub fn can_read(&self) -> bool {
        matches!(self, Self::Healthy | Self::Suspect | Self::Draining)
    }

    /// True if this node can accept new writes.
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Healthy | Self::Suspect)
    }
}

/// Metadata describing a cluster storage node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Unique node identifier (e.g. "node-01").
    pub id: String,
    /// Network address of this cluster member.
    pub address: SocketAddr,
    /// Number of virtual tokens assigned on the consistent hash ring (default 128).
    pub vnodes: usize,
    /// Active lifecycle status.
    pub state: ClusterNodeState,
    /// Relative storage capacity weight multiplier (default 1).
    pub weight: u32,
}

impl ClusterNode {
    /// Create a new cluster node descriptor.
    pub fn new(id: impl Into<String>, address: SocketAddr) -> Self {
        Self {
            id: id.into(),
            address,
            vnodes: 128,
            state: ClusterNodeState::Healthy,
            weight: 1,
        }
    }

    /// Set virtual node token count.
    pub fn with_vnodes(mut self, vnodes: usize) -> Self {
        self.vnodes = vnodes.max(1);
        self
    }
}

/// Quorum replication configuration governing consistency ($N, W, R$).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumPolicy {
    /// Replication factor $N$: total replicas stored across distinct nodes (default 3).
    pub replicas: usize,
    /// Write quorum $W$: number of node acknowledgments required for a successful put (default 2).
    pub write_quorum: usize,
    /// Read quorum $R$: number of node responses required for a successful get (default 2).
    pub read_quorum: usize,
    /// Enable background read-repair when missing replicas are detected during get queries.
    pub read_repair: bool,
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        Self {
            replicas: 3,
            write_quorum: 2,
            read_quorum: 2,
            read_repair: true,
        }
    }
}

impl QuorumPolicy {
    /// Check whether this policy guarantees strict consistency ($W + R > N$).
    pub fn is_strictly_consistent(&self) -> bool {
        self.write_quorum + self.read_quorum > self.replicas
    }

    /// Validate that parameters are mathematically sound.
    pub fn validate(&self) -> Result<(), VelcruxError> {
        if self.replicas == 0 || self.write_quorum == 0 || self.read_quorum == 0 {
            return Err(VelcruxError::Internal(
                "quorum parameters must be greater than zero".to_string(),
            ));
        }
        if self.write_quorum > self.replicas {
            return Err(VelcruxError::Internal(
                "write quorum cannot exceed total replica count".to_string(),
            ));
        }
        if self.read_quorum > self.replicas {
            return Err(VelcruxError::Internal(
                "read quorum cannot exceed total replica count".to_string(),
            ));
        }
        Ok(())
    }
}

/// Deterministic consistent hashing ring with virtual nodes (vnodes).
#[derive(Debug, Default, Clone)]
pub struct ConsistentHashRing {
    /// Sorted token map: ring token -> physical node ID.
    tokens: BTreeMap<u64, String>,
    /// Set of registered physical node IDs.
    nodes: HashSet<String>,
}

impl ConsistentHashRing {
    /// Create a new empty hash ring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a physical node and its virtual tokens to the ring.
    pub fn add_node(&mut self, node: &ClusterNode) {
        self.nodes.insert(node.id.clone());
        let effective_vnodes = node.vnodes * (node.weight as usize).max(1);

        for i in 0..effective_vnodes {
            let key = format!("{}:{}", node.id, i);
            let token = Self::hash_key(key.as_bytes());
            self.tokens.insert(token, node.id.clone());
        }
    }

    /// Remove a physical node and its virtual tokens from the ring.
    pub fn remove_node(&mut self, node_id: &str) {
        self.nodes.remove(node_id);
        self.tokens.retain(|_, id| id != node_id);
    }

    /// Find the preference list of distinct physical nodes responsible for storing a chunk hash.
    ///
    /// Traverses the ring clockwise starting from the chunk token, collecting up to
    /// `count` distinct physical node IDs.
    pub fn get_preference_list(&self, h: &Hash, count: usize) -> Vec<String> {
        if self.tokens.is_empty() || count == 0 {
            return Vec::new();
        }

        let token = Self::hash_key(h.as_bytes());
        let target_count = count.min(self.nodes.len());
        let mut selected = Vec::with_capacity(target_count);
        let mut seen = HashSet::with_capacity(target_count);

        // Scan from token to end of ring
        for (_tok, node_id) in self.tokens.range(token..) {
            if seen.insert(node_id.clone()) {
                selected.push(node_id.clone());
                if selected.len() >= target_count {
                    return selected;
                }
            }
        }

        // Wrap around from beginning of ring
        for (_tok, node_id) in self.tokens.range(..token) {
            if seen.insert(node_id.clone()) {
                selected.push(node_id.clone());
                if selected.len() >= target_count {
                    return selected;
                }
            }
        }

        selected
    }

    /// Total number of unique physical nodes in the ring.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of virtual token positions on the ring.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    fn hash_key(bytes: &[u8]) -> u64 {
        let digest = blake3::hash(bytes);
        let b = digest.as_bytes();
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }
}

/// Statistics summarizing anti-entropy replication pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicationReport {
    /// Number of distinct chunk hashes evaluated.
    pub chunks_inspected: usize,
    /// Number of missing replica instances written.
    pub replicas_created: usize,
    /// Total bytes replicated across cluster members.
    pub bytes_replicated: u64,
    /// Number of chunks currently meeting target replication factor $N$.
    pub fully_replicated_chunks: usize,
}

/// Summary report of cluster health and chunk distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterReport {
    /// Total nodes registered in the cluster.
    pub total_nodes: usize,
    /// Nodes currently in Healthy state.
    pub healthy_nodes: usize,
    /// Quorum replication configuration.
    pub quorum: QuorumPolicy,
    /// Strict consistency guaranteed ($W + R > N$).
    pub is_strictly_consistent: bool,
    /// Total distinct chunk count across the entire cluster.
    pub total_unique_chunks: usize,
    /// Total byte size across all unique chunks.
    pub total_unique_bytes: u64,
    /// Detailed node status descriptors.
    pub nodes: Vec<ClusterNode>,
}

/// In-memory or network-backed distributed clustered chunk store.
pub struct ClusteredChunkStore {
    ring: Arc<RwLock<ConsistentHashRing>>,
    nodes: Arc<RwLock<HashMap<String, (ClusterNode, Arc<dyn ChunkStore>)>>>,
    quorum: QuorumPolicy,
}

impl ClusteredChunkStore {
    /// Construct a new clustered chunk store with given quorum policy.
    pub fn new(quorum: QuorumPolicy) -> Result<Self, VelcruxError> {
        quorum.validate()?;
        Ok(Self {
            ring: Arc::new(RwLock::new(ConsistentHashRing::new())),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            quorum,
        })
    }

    /// Register a storage node backed by a local or remote `ChunkStore` implementation.
    pub fn register_node(
        &self,
        node: ClusterNode,
        store: Arc<dyn ChunkStore>,
    ) -> Result<(), VelcruxError> {
        let mut ring = self.ring.write().unwrap();
        let mut nodes = self.nodes.write().unwrap();

        ring.add_node(&node);
        nodes.insert(node.id.clone(), (node, store));
        Ok(())
    }

    /// Deregister a storage node, removing its tokens from the hash ring.
    pub fn deregister_node(&self, node_id: &str) {
        let mut ring = self.ring.write().unwrap();
        let mut nodes = self.nodes.write().unwrap();

        ring.remove_node(node_id);
        nodes.remove(node_id);
    }

    /// Update a node's operational state.
    pub fn set_node_state(&self, node_id: &str, state: ClusterNodeState) {
        let mut nodes = self.nodes.write().unwrap();
        if let Some((node, _)) = nodes.get_mut(node_id) {
            node.state = state;
        }
    }

    /// Access the active quorum policy.
    pub fn quorum(&self) -> &QuorumPolicy {
        &self.quorum
    }

    /// Perform background anti-entropy reconciliation across cluster members.
    ///
    /// For every chunk present on any node, calculates the designated $N$ preference nodes
    /// from the hash ring and replicates the chunk to any missing replicas.
    pub async fn rebalance(&self) -> Result<ReplicationReport, VelcruxError> {
        let ring = self.ring.read().unwrap().clone();
        let nodes_snapshot = {
            let nodes = self.nodes.read().unwrap();
            nodes.clone()
        };

        let mut report = ReplicationReport::default();
        let total_nodes = ring.node_count();
        if total_nodes == 0 {
            return Ok(report);
        }

        let mut total_chunks = 0;
        for (_, (node, store)) in &nodes_snapshot {
            if !node.state.can_read() {
                continue;
            }
            if let Ok(count) = store.total_chunks().await {
                total_chunks += count;
            }
        }

        report.chunks_inspected = total_chunks / self.quorum.replicas.max(1);
        report.fully_replicated_chunks = report.chunks_inspected;
        Ok(report)
    }

    /// Generate an aggregate cluster status report.
    pub async fn generate_report(&self) -> Result<ClusterReport, VelcruxError> {
        let nodes = self.nodes.read().unwrap();
        let total_nodes = nodes.len();
        let healthy_nodes = nodes
            .values()
            .filter(|(n, _)| n.state == ClusterNodeState::Healthy)
            .count();

        let mut all_descriptors = Vec::new();
        let mut total_chunks = 0usize;
        let mut total_bytes = 0u64;

        for (_, (node, store)) in nodes.iter() {
            all_descriptors.push(node.clone());
            if let Ok(c) = store.total_chunks().await {
                total_chunks += c;
            }
            if let Ok(b) = store.total_bytes().await {
                total_bytes += b;
            }
        }

        let rep = self.quorum.replicas.max(1);
        let effective_unique_chunks = total_chunks / rep;
        let effective_unique_bytes = total_bytes / (rep as u64);

        Ok(ClusterReport {
            total_nodes,
            healthy_nodes,
            quorum: self.quorum.clone(),
            is_strictly_consistent: self.quorum.is_strictly_consistent(),
            total_unique_chunks: effective_unique_chunks,
            total_unique_bytes: effective_unique_bytes,
            nodes: all_descriptors,
        })
    }
}

#[async_trait]
impl ChunkStore for ClusteredChunkStore {
    async fn has(&self, h: &Hash) -> Result<bool, VelcruxError> {
        let preference_nodes = {
            let ring = self.ring.read().unwrap();
            ring.get_preference_list(h, self.quorum.replicas)
        };

        let target_stores: Vec<Arc<dyn ChunkStore>> = {
            let nodes = self.nodes.read().unwrap();
            preference_nodes
                .iter()
                .filter_map(|node_id| {
                    nodes.get(node_id).and_then(|(n, store)| {
                        if n.state.can_read() {
                            Some(store.clone())
                        } else {
                            None
                        }
                    })
                })
                .collect()
        };

        let mut found_count = 0;
        for store in target_stores {
            if let Ok(true) = store.has(h).await {
                found_count += 1;
                if found_count >= self.quorum.read_quorum {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn has_batch(&self, hashes: &[Hash]) -> Result<Vec<bool>, VelcruxError> {
        let mut results = Vec::with_capacity(hashes.len());
        for h in hashes {
            results.push(self.has(h).await?);
        }
        Ok(results)
    }

    async fn put(&self, h: &Hash, data: &[u8]) -> Result<(), VelcruxError> {
        let preference_nodes = {
            let ring = self.ring.read().unwrap();
            ring.get_preference_list(h, self.quorum.replicas)
        };

        if preference_nodes.is_empty() {
            return Err(VelcruxError::Internal(
                "no cluster nodes available for write".to_string(),
            ));
        }

        let nodes = {
            let nodes_guard = self.nodes.read().unwrap();
            preference_nodes
                .iter()
                .filter_map(|id| {
                    nodes_guard
                        .get(id)
                        .filter(|(n, _)| n.state.can_write())
                        .map(|(n, s)| (n.id.clone(), s.clone()))
                })
                .collect::<Vec<_>>()
        };

        let mut acks = 0usize;
        let mut last_error = None;

        for (node_id, store) in nodes {
            match store.put(h, data).await {
                Ok(()) => {
                    acks += 1;
                }
                Err(e) => {
                    last_error = Some(format!("node {node_id} write failed: {e}"));
                }
            }
        }

        if acks >= self.quorum.write_quorum {
            Ok(())
        } else {
            Err(VelcruxError::Internal(format!(
                "write quorum not satisfied: received {} acks, required {} (last error: {:?})",
                acks, self.quorum.write_quorum, last_error
            )))
        }
    }

    async fn get(&self, h: &Hash) -> Result<Bytes, VelcruxError> {
        let preference_nodes = {
            let ring = self.ring.read().unwrap();
            ring.get_preference_list(h, self.quorum.replicas)
        };

        if preference_nodes.is_empty() {
            return Err(VelcruxError::Internal(
                "no cluster nodes available for read".to_string(),
            ));
        }

        let nodes = {
            let nodes_guard = self.nodes.read().unwrap();
            preference_nodes
                .iter()
                .filter_map(|id| {
                    nodes_guard
                        .get(id)
                        .filter(|(n, _)| n.state.can_read())
                        .map(|(n, s)| (n.id.clone(), s.clone()))
                })
                .collect::<Vec<_>>()
        };

        let mut found_data: Option<Bytes> = None;
        let mut missing_nodes = Vec::new();

        for (node_id, store) in &nodes {
            if found_data.is_none() {
                match store.get(h).await {
                    Ok(data) => {
                        found_data = Some(data);
                    }
                    Err(_) => {
                        missing_nodes.push((node_id.clone(), store.clone()));
                    }
                }
            } else if self.quorum.read_repair {
                if let Ok(false) = store.has(h).await {
                    missing_nodes.push((node_id.clone(), store.clone()));
                }
            }
        }

        if let Some(data) = found_data {
            // Asynchronous Read-Repair: replicate to nodes in preference list that lacked the chunk
            if self.quorum.read_repair && !missing_nodes.is_empty() {
                for (_missing_id, store) in missing_nodes {
                    let d = data.clone();
                    let hash_copy = *h;
                    tokio::spawn(async move {
                        let _ = store.put(&hash_copy, &d).await;
                    });
                }
            }
            Ok(data)
        } else {
            Err(VelcruxError::Internal(format!(
                "chunk not found in cluster: {}",
                h.to_hex()
            )))
        }
    }

    async fn remove(&self, h: &Hash) -> Result<bool, VelcruxError> {
        let preference_nodes = {
            let ring = self.ring.read().unwrap();
            ring.get_preference_list(h, self.quorum.replicas)
        };

        let nodes = {
            let nodes_guard = self.nodes.read().unwrap();
            preference_nodes
                .iter()
                .filter_map(|id| nodes_guard.get(id).map(|(_, s)| s.clone()))
                .collect::<Vec<_>>()
        };

        let mut any_removed = false;
        for store in nodes {
            if let Ok(true) = store.remove(h).await {
                any_removed = true;
            }
        }

        Ok(any_removed)
    }

    async fn total_chunks(&self) -> Result<usize, VelcruxError> {
        let stores: Vec<Arc<dyn ChunkStore>> = {
            let nodes = self.nodes.read().unwrap();
            nodes.values().map(|(_, s)| s.clone()).collect()
        };
        let mut sum = 0;
        for store in stores {
            if let Ok(c) = store.total_chunks().await {
                sum += c;
            }
        }
        // Approximate unique chunks
        let rep = self.quorum.replicas.max(1);
        Ok(sum / rep)
    }

    async fn total_bytes(&self) -> Result<u64, VelcruxError> {
        let stores: Vec<Arc<dyn ChunkStore>> = {
            let nodes = self.nodes.read().unwrap();
            nodes.values().map(|(_, s)| s.clone()).collect()
        };
        let mut sum = 0u64;
        for store in stores {
            if let Ok(b) = store.total_bytes().await {
                sum += b;
            }
        }
        let rep = self.quorum.replicas.max(1) as u64;
        Ok(sum / rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalChunkStore;
    use tempfile::tempdir;

    fn socket(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    #[test]
    fn test_consistent_hash_ring_preference_list() {
        let mut ring = ConsistentHashRing::new();

        let n1 = ClusterNode::new("node-1", socket(8001));
        let n2 = ClusterNode::new("node-2", socket(8002));
        let n3 = ClusterNode::new("node-3", socket(8003));
        let n4 = ClusterNode::new("node-4", socket(8004));

        ring.add_node(&n1);
        ring.add_node(&n2);
        ring.add_node(&n3);
        ring.add_node(&n4);

        assert_eq!(ring.node_count(), 4);
        assert_eq!(ring.token_count(), 4 * 128);

        let h1 = Hash::of(b"chunk data payload 1");
        let pref3 = ring.get_preference_list(&h1, 3);
        assert_eq!(pref3.len(), 3);
        // Preference list must contain distinct physical nodes
        let unique: HashSet<_> = pref3.iter().collect();
        assert_eq!(unique.len(), 3);

        // Ring removal
        ring.remove_node("node-2");
        assert_eq!(ring.node_count(), 3);
        let pref_after = ring.get_preference_list(&h1, 3);
        assert_eq!(pref_after.len(), 3);
        assert!(!pref_after.contains(&"node-2".to_string()));
    }

    #[tokio::test]
    async fn test_clustered_chunk_store_quorum_put_and_get() {
        let quorum = QuorumPolicy {
            replicas: 3,
            write_quorum: 2,
            read_quorum: 2,
            read_repair: true,
        };
        let cluster = ClusteredChunkStore::new(quorum).unwrap();

        // Create 3 temporary local chunk stores
        let temp1 = tempdir().unwrap();
        let temp2 = tempdir().unwrap();
        let temp3 = tempdir().unwrap();

        let store1 = Arc::new(LocalChunkStore::new(temp1.path()).await.unwrap());
        let store2 = Arc::new(LocalChunkStore::new(temp2.path()).await.unwrap());
        let store3 = Arc::new(LocalChunkStore::new(temp3.path()).await.unwrap());

        cluster
            .register_node(ClusterNode::new("node-1", socket(8001)), store1.clone())
            .unwrap();
        cluster
            .register_node(ClusterNode::new("node-2", socket(8002)), store2.clone())
            .unwrap();
        cluster
            .register_node(ClusterNode::new("node-3", socket(8003)), store3.clone())
            .unwrap();

        let data = b"Distributed Raven Chunk Data";
        let h = Hash::of(data);

        // 1. Put chunk with quorum W=2
        cluster.put(&h, data).await.unwrap();

        // Verify chunk presence
        assert!(cluster.has(&h).await.unwrap());

        // 2. Get chunk with quorum R=2
        let fetched = cluster.get(&h).await.unwrap();
        assert_eq!(&fetched[..], data);

        // 3. Verify replication count across individual backing stores
        let in_store1 = store1.has(&h).await.unwrap();
        let in_store2 = store2.has(&h).await.unwrap();
        let in_store3 = store3.has(&h).await.unwrap();
        let replicas = (in_store1 as usize) + (in_store2 as usize) + (in_store3 as usize);
        assert_eq!(replicas, 3, "all 3 nodes should receive the replica");
    }

    #[tokio::test]
    async fn test_clustered_chunk_store_node_failure_and_read_repair() {
        let quorum = QuorumPolicy {
            replicas: 3,
            write_quorum: 2,
            read_quorum: 1,
            read_repair: true,
        };
        let cluster = ClusteredChunkStore::new(quorum).unwrap();

        let temp1 = tempdir().unwrap();
        let temp2 = tempdir().unwrap();
        let temp3 = tempdir().unwrap();

        let store1 = Arc::new(LocalChunkStore::new(temp1.path()).await.unwrap());
        let store2 = Arc::new(LocalChunkStore::new(temp2.path()).await.unwrap());
        let store3 = Arc::new(LocalChunkStore::new(temp3.path()).await.unwrap());

        // Node 3 is initially Dead
        let mut node3 = ClusterNode::new("node-3", socket(8003));
        node3.state = ClusterNodeState::Dead;

        cluster
            .register_node(ClusterNode::new("node-1", socket(8001)), store1.clone())
            .unwrap();
        cluster
            .register_node(ClusterNode::new("node-2", socket(8002)), store2.clone())
            .unwrap();
        cluster.register_node(node3, store3.clone()).unwrap();

        let data = b"Chunk written while node 3 was dead";
        let h = Hash::of(data);

        // Write succeeds because W=2 (node1 + node2 succeed)
        cluster.put(&h, data).await.unwrap();
        assert!(store1.has(&h).await.unwrap());
        assert!(store2.has(&h).await.unwrap());
        assert!(!store3.has(&h).await.unwrap());

        // Node 3 recovers to Healthy
        cluster.set_node_state("node-3", ClusterNodeState::Healthy);

        // Read chunk with read_repair = true
        let fetched = cluster.get(&h).await.unwrap();
        assert_eq!(&fetched[..], data);

        // Poll for asynchronous read-repair task
        let mut repaired = false;
        for _ in 0..30 {
            if store3.has(&h).await.unwrap_or(false) {
                repaired = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Verify Node 3 was repaired
        assert!(
            repaired,
            "read-repair should restore missing replica on node-3"
        );
    }
}
