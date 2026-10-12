//! Integration tests for Distributed Chunk Store Clustering & Replication (Option AY).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::tempdir;

use velcrux_core::error::VelcruxError;
use velcrux_core::storage::{
    ChunkStore, ClusteredChunkStore, ClusterNode, ClusterNodeState,
    ConsistentHashRing, LocalChunkStore, QuorumPolicy,
};
use velcrux_core::util::Hash;

fn socket(port: u16) -> SocketAddr {
    format!("127.0.0.1:{}", port).parse().unwrap()
}

#[tokio::test]
async fn test_cluster_hash_ring_distribution() {
    let mut ring = ConsistentHashRing::new();

    let n1 = ClusterNode::new("storage-node-1", socket(9001));
    let n2 = ClusterNode::new("storage-node-2", socket(9002));
    let n3 = ClusterNode::new("storage-node-3", socket(9003));
    let n4 = ClusterNode::new("storage-node-4", socket(9004));

    ring.add_node(&n1);
    ring.add_node(&n2);
    ring.add_node(&n3);
    ring.add_node(&n4);

    assert_eq!(ring.node_count(), 4);
    assert_eq!(ring.token_count(), 4 * 128);

    // Verify key distribution across nodes for 100 random keys
    let mut node_hits = std::collections::HashMap::new();
    for i in 0..100 {
        let chunk_data = format!("synthetic-chunk-data-payload-{}", i);
        let h = Hash::of(chunk_data.as_bytes());
        let pref = ring.get_preference_list(&h, 3);
        assert_eq!(pref.len(), 3);
        let distinct: HashSet<_> = pref.iter().collect();
        assert_eq!(distinct.len(), 3, "preference list must have distinct nodes");

        for n in pref {
            *node_hits.entry(n).or_insert(0) += 1;
        }
    }

    // Every node should be assigned chunks
    assert_eq!(node_hits.len(), 4);
    for (_node, count) in &node_hits {
        assert!(*count > 20, "each node should receive a fair share of tokens");
    }
}

#[tokio::test]
async fn test_cluster_strict_consistency_and_quorum_failure() {
    let quorum = QuorumPolicy {
        replicas: 3,
        write_quorum: 2,
        read_quorum: 2,
        read_repair: true,
    };
    assert!(quorum.is_strictly_consistent());

    let cluster = ClusteredChunkStore::new(quorum).unwrap();

    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();
    let dir3 = tempdir().unwrap();

    let s1 = Arc::new(LocalChunkStore::new(dir1.path()).await.unwrap());
    let s2 = Arc::new(LocalChunkStore::new(dir2.path()).await.unwrap());
    let s3 = Arc::new(LocalChunkStore::new(dir3.path()).await.unwrap());

    cluster.register_node(ClusterNode::new("node-a", socket(9101)), s1.clone()).unwrap();
    cluster.register_node(ClusterNode::new("node-b", socket(9102)), s2.clone()).unwrap();
    cluster.register_node(ClusterNode::new("node-c", socket(9103)), s3.clone()).unwrap();

    let data = b"strict-consistency-quorum-payload";
    let hash = Hash::of(data);

    // Put chunk with quorum W=2
    cluster.put(&hash, data).await.unwrap();
    assert!(cluster.has(&hash).await.unwrap());

    // Mark 2 nodes as Dead (only 1 node alive: node-a)
    cluster.set_node_state("node-b", ClusterNodeState::Dead);
    cluster.set_node_state("node-c", ClusterNodeState::Dead);

    // Write should now FAIL because write quorum W=2 cannot be satisfied
    let data2 = b"should-fail-due-to-insufficient-write-quorum";
    let hash2 = Hash::of(data2);
    let write_err = cluster.put(&hash2, data2).await;
    assert!(write_err.is_err());
    if let Err(VelcruxError::Internal(msg)) = write_err {
        assert!(msg.contains("write quorum not satisfied"));
    }

    // Read should also FAIL because read quorum R=2 cannot be satisfied
    let read_err = cluster.has(&hash).await;
    assert!(matches!(read_err, Ok(false)));

    // Recover node-b back to Healthy
    cluster.set_node_state("node-b", ClusterNodeState::Healthy);

    // Now read succeeds with R=2
    let retrieved = cluster.get(&hash).await.unwrap();
    assert_eq!(&retrieved[..], data);
}

#[tokio::test]
async fn test_cluster_rebalance_and_report() {
    let quorum = QuorumPolicy {
        replicas: 3,
        write_quorum: 2,
        read_quorum: 2,
        read_repair: true,
    };
    let cluster = ClusteredChunkStore::new(quorum).unwrap();

    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();
    let dir3 = tempdir().unwrap();

    let s1 = Arc::new(LocalChunkStore::new(dir1.path()).await.unwrap());
    let s2 = Arc::new(LocalChunkStore::new(dir2.path()).await.unwrap());
    let s3 = Arc::new(LocalChunkStore::new(dir3.path()).await.unwrap());

    cluster.register_node(ClusterNode::new("n1", socket(9201)), s1.clone()).unwrap();
    cluster.register_node(ClusterNode::new("n2", socket(9202)), s2.clone()).unwrap();
    cluster.register_node(ClusterNode::new("n3", socket(9203)), s3.clone()).unwrap();

    for i in 0..10 {
        let chunk = format!("cluster-rebalance-test-chunk-{}", i);
        let h = Hash::of(chunk.as_bytes());
        cluster.put(&h, chunk.as_bytes()).await.unwrap();
    }

    let report = cluster.generate_report().await.unwrap();
    assert_eq!(report.total_nodes, 3);
    assert_eq!(report.healthy_nodes, 3);
    assert!(report.is_strictly_consistent);
    assert_eq!(report.total_unique_chunks, 10);

    let rebal = cluster.rebalance().await.unwrap();
    assert_eq!(rebal.chunks_inspected, 10);
    assert_eq!(rebal.fully_replicated_chunks, 10);
}
