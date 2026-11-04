# ADR-068: Distributed Global Multi-Cluster Geo-Replication & Conflict-Free Replicated Data Types (CRDTs)

- **Status**: Accepted
- **Date**: 2026-11-04
- **Deciders**: Velcrux Core Distributed Systems, Storage Architecture, Multi-Region Networking, and Geo-Replication Teams
- **Consulted**: Platform Operations, Global Edge Computing, DevOps, and Reliability Engineering Teams

---

## 1. Context and Problem Statement

Global enterprise deployments require data storage and transfer operations to execute seamlessly across multi-continent datacenter fabrics (e.g. `us-east`, `eu-west`, `ap-southeast`). Enforcing synchronous consensus (such as Raft or Multi-Paxos) across wide-area networks introduces severe architectural challenges:
1. **Trans-Oceanic Latency Tax**: Every file creation, directory mutation, or commit requires multi-roundtrip quorum consensus across intercontinental links, incurring 100–300 ms of latency per operation and destroying interactive throughput.
2. **Network Partitions & Submarine Cable Severance**: Trans-oceanic and trans-continental fiber cuts inevitably cause temporary network partitions. Synchronous CP systems stall writes entirely in minority partitions, causing enterprise workflow outages.
3. **Ghost Resurrections in Active-Active Deployments**: Naive timestamp-based replication causes deleted files to be resurrected if concurrent edits occur on remote replicas without proper tombstone causal tracking.
4. **Directory Tree Cycles during Concurrent Renames**: When Region A moves `/docs` into `/archive/docs` while Region B concurrently moves `/archive` into `/docs/archive`, naive replication creates isolated directory cycles or corrupts filesystem trees.

---

## 2. Decision Drivers

- **Active-Active Multi-Region Zero-Lock Mutability**: Enable local read and write operations to commit locally with sub-millisecond latencies across any regional cluster, without waiting for cross-oceanic consensus rounds.
- **Strong Eventual Consistency (SEC)**: Ensure that all cluster replicas receiving the identical set of mutations—regardless of message delivery order, reordering, or network delays—converge to mathematically identical filesystem tree states.
- **Causality & Clock Skew Tracking**: Implement Vector Clocks ([`VectorClock`]) for causal relationship tracking (`happens_before`, `dominates`, `concurrent_with`) and Hybrid Logical Clocks ([`Hlc`]) combining physical wall-clock timestamps with monotonic logical counters for bounded drift and deterministic tie-breaking.
- **Cycle-Safe Replicated Directory Tree (`ReplicatedFsTree`)**: Provide an active-active hierarchical directory and file tree CRDT supporting concurrent creations, modifications, deletions, and moves with cycle detection (preventing directory loops).
- **Delta-State Anti-Entropy Gossip (`AntiEntropyEngine`)**: Minimize cross-region WAN bandwidth consumption by computing and exchanging state deltas scoped to remote vector clock watermarks rather than transferring entire tree states.
- **Zero Unsafe Code**: 100% pure safe Rust (`#![forbid(unsafe_code)]`) with zero external C dependencies.

---

## 3. Considered Options

- **Option 1: Global Synchronous Raft Consensus Across WAN**:
  - *Cons*: Prohibitive 100–300 ms write latencies; total write unavailability during network partitions.
- **Option 2: Asynchronous Primary-Backup Replication with Central Leader**:
  - *Cons*: Single point of failure; failover incurs data loss or split-brain inconsistencies; remote regions cannot accept writes if disconnected from primary.
- **Option 3 (Chosen): Native CRDT Filesystem & Delta Anti-Entropy Geo-Replication (`Option CZ`)**:
  - Active-active multi-master topology where all regions accept concurrent mutations.
  - Join-semilattice mathematically provable convergence via LWW-Register, OR-Set, and ReplicatedFsTree.
  - Cycle detection prevents cyclic directory dependencies during concurrent moves.
  - Delta anti-entropy gossip minimizes WAN egress bandwidth.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│             VELCRUX DISTRIBUTED MULTI-CLUSTER GEO-REPLICATION (CRDT)                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        ▼                                   ▼                                   ▼
┌──────────────────────┐           ┌──────────────────────┐           ┌──────────────────────┐
│  Region: us-east-1   │           │  Region: eu-west-1   │           │  Region: ap-se-1     │
├──────────────────────┤           ├──────────────────────┤           ├──────────────────────┤
│ • ReplicatedFsTree   │           │ • ReplicatedFsTree   │           │ • ReplicatedFsTree   │
│ • Local HLC & VClock │           │ • Local HLC & VClock │           │ • Local HLC & VClock │
│ • State Digest: D_1  │           │ • State Digest: D_2  │           │ • State Digest: D_3  │
└──────────┬───────────┘           └──────────┬───────────┘           └──────────┬───────────┘
           │                                  │                                  │
           │           Anti-Entropy Gossip    │          Anti-Entropy Gossip     │
           │◄────────────────────────────────►│◄────────────────────────────────►│
           │       • Watermark Delta Sync     │      • Watermark Delta Sync      │
           │       • Vector Clock Exchange    │      • Vector Clock Exchange     │
           │       • Join-Semilattice Merge   │      • Join-Semilattice Merge    │
           │                                  │                                  │
           └──────────────────────────────────┴──────────────────────────────────┘
                                            │
                                            ▼
                          [ Network Partition Healing Event ]
                                            │
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │      Deterministic Conflict Resolution        │
                    │   • Concurrent File Edits: Higher HLC Wins    │
                    │   • Concurrent Deletions: Tombstone Dominance │
                    │   • Concurrent Moves: Cycle-Safe Rejection    │
                    └───────────────────────┬───────────────────────┘
                                            │
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │         Global Convergence Verified           │
                    │      State Digest: D_1 == D_2 == D_3          │
                    └───────────────────────────────────────────────┘
```

---

## 5. Subsystem Components

### 5.1. Causality & Clocks (`crdt/clock.rs`)
- **Vector Clock (`VectorClock`)**: Maps regional node IDs to sequence counters. Implements component-wise comparison returning `Before`, `After`, `Equal`, or `Concurrent`, and `dominates` checks.
- **Hybrid Logical Clock (`Hlc`)**: Combines physical wall-clock time in milliseconds with logical event counters. On local mutations, advances monotonic physical/logical components via `on_send`. On remote message reception, synchronizes against peer clock via `on_recv`, ensuring strict ordering with node ID tie-breaking.

### 5.2. Primitive CRDT Structures (`crdt/types.rs`)
- **LWW-Register (`LwwRegister<T>`)**: Last-Write-Wins register resolving concurrent mutations via HLC timestamp comparison.
- **OR-Set (`OrSet<T>`)**: Observed-Removed (Add-Wins) Set tracking element birth tags and tombstones. Concurrent addition and deletion operations resolve in favor of the addition because newly generated tags were not yet observed by the deleting replica.
- **MV-Register (`MvRegister<T>`)**: Multi-Value register retaining concurrent conflicting values under vector clock concurrency until explicitly pruned by dominant clocks.

### 5.3. Replicated Filesystem Directory Tree (`crdt/tree.rs`)
- **Node Model (`FsNode`)**: Models files and directories with canonical normalized paths, file sizes, chunk counts, BLAKE3 content digests, HLC timestamps, and deletion tombstones.
- **Cycle-Safe Directory Moves (`rename_or_move`)**: Detects and rejects circular dependency attempts (e.g. moving `/a` into `/a/b/c`), preserving valid directory acyclic DAG structures.
- **Join-Semilattice Merge (`merge`)**: Merges two filesystem trees deterministically, updating vector clocks and adopting nodes with higher HLC timestamps.
- **State Digest (`state_digest`)**: Computes a deterministic BLAKE3 digest across active tree nodes, allowing instant verification of cross-region convergence.

### 5.4. Anti-Entropy Gossip Synchronization (`crdt/sync.rs`)
- **Watermark Delta Extraction (`compute_delta`)**: Extracts only nodes mutated past a peer's observed vector clock watermark.
- **Delta Application (`apply_delta`)**: Merges deltas directly into local replicas, updating vector clocks and resolving conflicts.
- **Bidirectional Exchange (`exchange`)**: Orchestrates mutual exchange between two replicas, returning detailed convergence metrics (`AntiEntropyReport`).

### 5.5. Geo-Replication Mesh (`crdt/mesh.rs`)
- **Topology Modeling (`GeoMesh`)**: Maintains cluster topology across multiple regions, tracks RTT latencies, models simulated trans-oceanic network partitions, and verifies global convergence post-healing.
- **Benchmark Suite (`run_benchmark`)**: Executes concurrent multi-region mutations under simulated partitions and reports sync cycles, conflict counts, and convergence state.

---

## 6. CLI Integration & Operator Ergonomics

The `velcrux crdt` command suite exposes comprehensive status inspection, tree browsing, and gossip synchronization:
- **Mesh Status & Convergence**:
  ```bash
  velcrux crdt status
  velcrux crdt status --json
  ```
- **Replicated Tree Inspection**:
  ```bash
  velcrux crdt tree --region us-east --prefix /datasets
  velcrux crdt tree --region eu-west --json
  ```
- **Anti-Entropy Gossip Synchronization**:
  ```bash
  velcrux crdt sync --region-a us-east --region-b eu-west
  velcrux crdt sync --region-a us-east --region-b ap-se --json
  ```
- **Multi-Region Benchmark & Partition Healing**:
  ```bash
  velcrux crdt bench --regions 3 --files 10 --simulate-partition
  velcrux crdt bench --regions 2 --files 5 --json
  ```

---

## 7. Consequences & Guarantees

- **Guarantees**:
  - **Local Write Latency**: Reads and writes commit locally with sub-millisecond latencies, independent of cross-continental network latency.
  - **Partition Resilience**: Regional clusters continue serving local read/write traffic during WAN partitions, automatically reconciling and converging upon link restoration.
  - **Conflict Freedom**: Concurrency is mathematically resolved through join-semilattices, preventing silent overwrite, data loss, or tree cycle corruptions.
- **Trade-offs**:
  - Eventual consistency implies that transient cross-region reads during active WAN partitions reflect the local partition's causal history until anti-entropy gossip propagates updates.
