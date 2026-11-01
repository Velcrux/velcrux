# ADR-057: Distributed Global Snapshot Isolation & Transactional Multi-File Checkpoint Mesh

- **Status**: Accepted
- **Date**: 2026-11-01
- **Deciders**: Velcrux Core Architecture & Distributed Storage Working Group
- **Consulted**: High-Performance Data Systems Team, Site Reliability Engineering, Cryptographic Systems Group

---

## 1. Context and Problem Statement

Velcrux clusters deploy across distributed multi-region edge topologies where concurrent writers synchronize directory trees containing tens of thousands of heterogeneous files. In high-concurrency environments without distributed transactional boundaries, concurrent sync operations and network perturbations expose severe consistency anomalies:

1. **Phantom Reads & Inconsistent Multi-File Views**: When a reader scans a directory being concurrently updated, it observes half-written states (e.g. newly written configuration files referring to binaries that haven't been staged yet, or updated database indices pointing to uncommitted data blocks).
2. **Lost Updates & Write Conflicts**: Concurrent writers modifying overlapping file paths overwrite changes without causal synchronization, leading to silent data corruption and split-brain states.
3. **Torn Directory Trees on Abort**: If a sync session aborts mid-transfer due to connection drops, power loss, or policy violations, partial files remain in the active directory tree, leaving the filesystem corrupted without an atomic all-or-nothing rollback mechanism.
4. **Lack of Linearizable Point-in-Time Reads**: Remote nodes lack the ability to query immutable historical snapshots of complete directory hierarchies at a specific logical vector clock timestamp.

---

## 2. Decision Drivers

- **Linearizable Multi-Version Snapshot Isolation (MVCC)**: Every read transaction must observe a causally consistent point-in-time directory state, completely isolated from concurrent uncommitted or subsequent writes.
- **Strict Atomicity via Two-Phase Commit (2PC)**: Multi-file directory syncs across distributed nodes must commit on all participating nodes simultaneously or abort with zero side-effects.
- **Optimistic Concurrency Control (OCC)**: Detect concurrent file modifications using expected base revision tracking, guaranteeing first-committer-wins semantics without distributed write-locks.
- **Atomic All-or-Nothing Directory Rollback**: Ability to revert an entire filesystem tree to any prior committed snapshot tag or epoch with full BLAKE3 cryptographic integrity verification and automatic pruning of orphaned files.
- **Strict Safe Rust Invariant**: Pure safe Rust (`#![forbid(unsafe_code)]`) with zero external C/OS bignum or kernel dependencies.
- **Predictable Sub-Millisecond Latency**: 2PC prepare, commit, MVCC read, and rollback operations must execute with sub-millisecond latencies for production workloads.

---

## 3. Considered Options

- **Option 1: Two-Phase Locking (2PL) with Distributed Deadlock Detection**: Traditional distributed locking across all files during staging.
  - *Cons*: Prone to distributed deadlocks, high latency under wide-area networks, reader-writer blocking.
- **Option 2: Centralized Metadata Master**: Funneling all snapshot commits through a single Raft metadata coordinator.
  - *Cons*: Bottleneck for multi-region edge sync; single point of failure under network partitions.
- **Option 3 (Chosen): Distributed MVCC Snapshot Isolation with Vector Clocks, OCC, and 2PC Checkpoint Manifest Mesh**:
  - Each node maintains a logical vector clock $\vec{V} = \{ \text{node}_i \mapsto c_i \}$.
  - Staged file operations compute deterministic BLAKE3 Merkle roots and validate base revision preconditions (OCC).
  - Two-Phase Commit (2PC) ensures unanimous agreement before promoting staged files to content-addressed immutable versions (`.versions/<hash>`).
  - Read transactions access immutable historical snapshots indexed by Merkle roots and vector clocks.
  - Zero unsafe code; fully crash-consistent disk staging.

---

## 4. Technical Architecture & Invariants

```
                                      CLIENT / OPERATOR
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │  velcrux txsnapshot {begin, stage, ...}   │
                       └─────────────────────┬─────────────────────┘
                                             │
                                   ┌─────────▼─────────┐
                                   │ TxSnapshotEngine  │
                                   └─────────┬─────────┘
                                             │
           ┌─────────────────────────────────┼─────────────────────────────────┐
           │                                 │                                 │
┌──────────▼──────────┐           ┌──────────▼──────────┐           ┌──────────▼──────────┐
│   Vector Clocks     │           │   Two-Phase Commit   │           │    MVCC & OCC       │
│  $\vec{V} = [n \to c]$  │           │      (2PC Mesh)     │           │  Base Rev Check     │
│  Causality / Order  │           │  Prepare -> Commit  │           │  Read Isolation     │
└─────────────────────┘           └──────────┬──────────┘           └─────────────────────┘
                                             │
                                   ┌─────────▼─────────┐
                                   │ Storage Hierarchy │
                                   └─────────┬─────────┘
                                             │
             ┌───────────────────────────────┼───────────────────────────────┐
             │                               │                               │
  ┌──────────▼──────────┐         ┌──────────▼──────────┐         ┌──────────▼──────────┐
  │  staged/<tx_id>/    │         │  versions/<hash>    │         │ snapshots/<id>.json │
  │  Isolated buffers   │         │  Content-Addressed  │         │ Manifest & Merkle   │
  └─────────────────────┘         └─────────────────────┘         └─────────────────────┘
```

### 4.1. Logical Vector Clocks
A distributed vector clock $\vec{V}$ tracks logical timestamps:
- Increment: $V_{\text{local}}[node] \leftarrow V_{\text{local}}[node] + 1$.
- Causality: $\vec{V}_a < \vec{V}_b \iff (\forall k: V_a[k] \le V_b[k]) \land (\exists k: V_a[k] < V_b[k])$.
- Concurrency: $\vec{V}_a \parallel \vec{V}_b \iff \neg(\vec{V}_a \le \vec{V}_b) \land \neg(\vec{V}_b \le \vec{V}_a)$.

### 4.2. Optimistic Concurrency Control (OCC)
When staging file updates, the client specifies an optional `expected_base_version`. During Phase 1 `prepare_2pc`, the engine checks whether a newer revision has committed. If $\text{latest\_revision} > \text{expected\_base\_version}$, the transaction is rejected with an OCC conflict, preventing lost updates without holding write locks.

### 4.3. Two-Phase Commit (2PC) Lifecycle
1. **Begin**: Generates unique `tx_id` (`tx-<timestamp>-<hash>`), initializes isolated `.staged/<tx_id>/` directory, and captures read vector clock.
2. **Stage**: Writes staged file buffers and computes per-file BLAKE3 hashes.
3. **Phase 1 (Prepare)**: Calculates cryptographic staging Merkle root over sorted operations and verifies OCC preconditions. Generates `TwoPhasePrepare`.
4. **Vote**: Participants verify Merkle root and local locks, returning `VoteKind::Commit` or `VoteKind::Abort { reason }`.
5. **Phase 2 (Commit / Abort)**: Unanimous commit promotes staged files to immutable content-addressed storage `.versions/<hash>` and publishes an immutable `GlobalSnapshotManifest`. Any abort vote triggers immediate cleanup of staged data.

### 4.4. Atomic Multi-File Rollback
To restore a snapshot:
1. Verifies existence and BLAKE3 hash integrity of all snapshot file versions.
2. Stages target directory files in a temporary shadow tree.
3. Deletes extraneous files not present in the historical snapshot.
4. Atomically swaps or syncs restored files into the active worktree.

---

## 5. Security & Safety Implications

- **Memory Safety**: Pure `#![forbid(unsafe_code)]` with zero exceptions.
- **Content Integrity**: All version objects and snapshot manifests are cryptographically verified via BLAKE3 hashes and Merkle trees.
- **Process Isolation**: Multi-process storage isolation via atomic rename semantics and isolated staging paths (`VELCRUX_TXSNAPSHOT_DIR`).

---

## 6. Verification & Operational Metrics

- **CLI Operations**: `velcrux txsnapshot [status|begin|stage|prepare|commit|abort|read|list|rollback|benchmark]`.
- **Prometheus Metrics**:
  - `velcrux_txsnapshot_transactions_begun_total`
  - `velcrux_txsnapshot_transactions_committed_total`
  - `velcrux_txsnapshot_transactions_aborted_total`
  - `velcrux_txsnapshot_active_transactions`
  - `velcrux_txsnapshot_snapshots_total`
  - `velcrux_txsnapshot_rollbacks_total`
  - `velcrux_txsnapshot_conflicts_total`
  - `velcrux_txsnapshot_commit_latency_nanoseconds`
