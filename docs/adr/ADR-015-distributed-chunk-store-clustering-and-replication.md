# ADR-015: Distributed Chunk Store Clustering & Quorum Replication

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §15 ("Storage Backend & Local Chunk Store"), §62 ("Scale Targets: 100M Chunks & Multi-PB Datasets"), and §63 ("High Availability & Fault Tolerance"), petascale data synchronization workloads introduce critical challenges for standalone local storage:
1. **Single Point of Failure (SPOF)**: A drive or host failure on a standalone chunk store causes permanent data loss or renders the sync cluster unavailable.
2. **Storage Capacity Limits**: Individual host storage limits (e.g. 100TB NVMe arrays) cannot accommodate multi-petabyte deduplication repositories.
3. **Write/Read Throughput Saturation**: A single node's I/O bus and network interfaces become the bottleneck when dozens of client transfer sessions write chunks concurrently.
4. **Maintenance Disruption**: Draining, replacing, or upgrading storage hosts without taking the deduplication cluster offline requires live rebalancing and fault tolerance.

## Options Considered

1. **Centralized Master-Worker Architecture (GFS / HDFS pattern)**:
   - A single primary coordinator node tracks chunk locations and delegates chunk I/O to chunk daemons.
   - *Rejected*: The central master becomes a performance bottleneck for billions of chunk lookups and requires complex multi-raft consensus leader failover.
2. **Static Hash Modulo Sharding (`hash % N`)**:
   - Assign chunks to nodes by hashing chunk keys modulo the number of nodes $N$.
   - *Rejected*: Adding or removing a single node forces reshuffling almost 100% of the entire chunk corpus, causing massive network traffic spikes.
3. **Decentralized Consistent Hashing Ring with Virtual Nodes & Tunable Quorum ($N, W, R$)**:
   - Dynamo-style ring architecture with deterministic BLAKE3 token hashing.
   - Each physical node is assigned virtual tokens (vnodes) to achieve uniform load distribution.
   - Preference lists determine the designated replica nodes for any chunk key.
   - Tunable consistency levels ($N, W, R$) permitting strict consistency ($W + R > N$) or eventual consistency for maximum write throughput.
   - Asynchronous read-repair during chunk fetches and background anti-entropy rebalancing.

## Decision

Option 3. Velcrux implements native distributed chunk store clustering and quorum replication with `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Consistent Hash Ring with Virtual Nodes

The cluster maintains a `ConsistentHashRing` mapping 64-bit BLAKE3 token hashes to physical nodes:
```text
                       Node-A (vnode 0)
                            [Token 0x1200]
                                 ▲
                                 │
           Node-C (vnode 127)    │    Node-B (vnode 42)
             [Token 0xE500]      │      [Token 0x3F00]
                    \            │            /
                     \           │           /
                      \          │          /
                       \         │         /
                                 ◯
                          Consistent Ring
                                 │
                      /          │          \
                     /           │           \
                    /            │            \
             [Token 0xA100]      │      [Token 0x7800]
           Node-A (vnode 64)     │    Node-C (vnode 0)
                                 ▼
                       Node-B (vnode 88)
```
- **Virtual Nodes (vnodes)**: By default, 128 virtual tokens per physical node prevent hotspots and ensure uniform data distribution across heterogeneous drives.
- **Preference List**: For any chunk hash, the coordinator traverses the ring clockwise to collect $N$ distinct physical storage nodes responsible for holding replicas.
- **Minimal Migration**: Adding or removing a node only impacts $\frac{1}{M}$ of total chunks, eliminating full-cluster re-sharding.

### 2. Quorum Policy & Consistency Semantics ($N, W, R$)

Consistency is governed by `QuorumPolicy`:
- **$N$ (Replicas)**: Total number of distinct nodes that hold copies of each chunk (default 3).
- **$W$ (Write Quorum)**: Number of node acknowledgments required for a chunk `put` to succeed (default 2).
- **$R$ (Read Quorum)**: Number of node confirmations required for a chunk `get` or `has` to succeed (default 2).
- **Strict Consistency ($W + R > N$)**: Guarantees read and write quorums overlap by at least one node, ensuring no stale or missed chunks can be observed.
- **Fault Tolerance**: The cluster survives up to $N - W$ node failures for writes, and $N - R$ node failures for reads without service disruption.

### 3. Node State Machine & Failover

Nodes transition through 4 lifecycle states:
- **`Healthy`**: Fully operational; accepts reads and writes.
- **`Suspect`**: Missed heartbeats or elevated errors; accepts reads and writes under observation.
- **`Draining`**: Controlled maintenance mode; accepts reads but rejects new writes while transferring data off the node.
- **`Dead`**: Offline or unreachable; excluded from quorum calculations.

### 4. Asynchronous Read-Repair & Anti-Entropy

- **Read-Repair**: When a read query fetches a chunk from a subset of preference nodes, any live preference node that lacked the chunk is asynchronously repaired via background `tokio::spawn` replication tasks.
- **Anti-Entropy Rebalancing**: The `rebalance()` routine inspects all nodes, compares replica distributions against current ring preference lists, and backfills missing replicas across cluster members.

### 5. CLI Administration

Administrative commands provide cluster inspection and reconciliation:
```bash
# Display cluster topology, node health, and consistency level
velcrux cluster status --nodes 10.0.1.1:8001,10.0.1.2:8001,10.0.1.3:8001 --replicas 3 --write-quorum 2 --read-quorum 2

# Output machine-readable JSON for monitoring and alerting
velcrux --json cluster status

# Run background anti-entropy reconciliation across cluster nodes
velcrux cluster rebalance --replicas 3
```

## Consequences

- **Positive**: Multi-PB scalability, zero-SPOF fault tolerance, and hot node replacement without downtime.
- **Positive**: Strict consistency guarantees prevent split-brain and missing chunk errors.
- **Neutral**: Small network overhead for replica propagation across nodes, mitigated by async read-repair and parallel quorum writes.
