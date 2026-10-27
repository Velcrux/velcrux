# ADR-042: Distributed Raft Consensus & High-Availability Cluster Metadata Coordinator

Status: Accepted · Date: 2026-10-28

## Context

Velcrux enterprise clusters require continuous high availability, automated failover, and strict consistency across multi-node topologies (`ARCHITECTURE.md` §2, §7; `SECURITY.md` §8, §9). While chunk payloads are content-addressed and horizontally partitioned across storage nodes (Option AY), distributed cluster coordination—including transfer state synchronization, active cluster node membership, configuration propagation, and mutual-exclusion file leases—requires a strongly consistent consensus coordinator with strict linearizability.

Key operational and architectural requirements:
1. **Strong Consistency & Quorum Invariants**:
   - Cluster metadata state must satisfy the state machine safety invariant: at most one leader per term, log matching, and committed entries must survive arbitrary node crashes or minority network partitions.
2. **Automated Leader Election & Sub-Second Failover**:
   - When the leader node fails or is partitioned, followers must detect heartbeat timeouts and trigger candidate elections. Majority quorum votes (`V > N / 2`) elect a new leader without human intervention or split-brain risk.
3. **Log Replication & State Machine Progression**:
   - Log entries with monotonically increasing indices and terms are replicated via `AppendEntries` RPCs. Entries are committed once acknowledged by a quorum majority and applied sequentially to the state machine.
4. **Distributed Leases with Monotonic Epoch Fencing**:
   - Granular distributed resource leases (e.g., active transfer sessions, namespace ownership, mutation locks) must prevent stale or partitioned former leaders from executing "zombie" writes. Monotonic lease epochs and fencing tokens ensure that writes with stale epochs are rejected.
5. **Dynamic Membership Management**:
   - Seamless addition (`Join`) and graceful decommissioning (`Leave`) of cluster nodes via consensus log entries without service downtime.
6. **Telemetry & Operability**:
   - Export Prometheus metrics (`velcrux_raft_term`, `velcrux_raft_is_leader`, `velcrux_raft_commit_index`, `velcrux_raft_leader_elections_total`, `velcrux_raft_active_leases`, `velcrux_raft_rpc_messages_total`) and CLI subcommands (`velcrux cluster [status|join|leave|elect|lease|benchmark]`).
7. **Invariants**:
   - 100% Safe Rust (`#![forbid(unsafe_code)]` with zero exceptions across all crates).
   - Strict bounded memory streaming: log replication and RPC payloads are bounded, preventing buffer exhaustion.

---

## Options Considered

1. **Option 1: External ZooKeeper or etcd Dependency**:
   - Delegate cluster coordination to an external etcd or ZooKeeper cluster.
   - *Rejected*: Violates Velcrux's self-contained single-binary architecture; introduces external operational overhead, deployment friction, and network protocol impedance mismatches.
2. **Option 2: Gossip / Dynamo Eventual Consistency for Metadata**:
   - Replicate metadata using gossip protocols with vector clocks.
   - *Rejected*: Inadequate for strict mutual-exclusion locks, transfer leases, and linearizable metadata; susceptible to split-brain and concurrent conflicting mutations during network partitions.
3. **Option 3: Embedded Distributed Raft Consensus Engine (`ADR-042`)**:
   - Native Safe Rust implementation of the Raft consensus algorithm integrated directly into `velcrux-core`.
   - In-memory state machine with monotonic log index and term progression.
   - Epoch-fenced distributed resource leasing preventing zombie mutations.
   - Built-in multi-node simulation benchmark verifying sub-millisecond election failover and network partition recovery.

---

## Decision

Adopt Option 3.

---

## Architecture & Implementation

### 1. Core Raft State & Roles (`crates/velcrux-core/src/consensus/mod.rs`)

Each cluster coordinator operates in one of three mutually exclusive roles:
- **`Follower`**: Responds to incoming vote requests and append heartbeats. Resets election timer upon receiving valid leader messages.
- **`Candidate`**: Increments term, votes for self, and broadcasts `RequestVoteRequest` RPCs to achieve majority quorum.
- **`Leader`**: Establishes leadership upon receiving majority votes, sends periodic heartbeat `AppendEntriesRequest` RPCs, coordinates log replication, and advances the commit index.

```rust
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

pub enum RaftCommand {
    SetMetadata { key: String, value: String, version: u64 },
    DeleteMetadata { key: String },
    AcquireLease { resource: String, holder: String, ttl_secs: u64 },
    ReleaseLease { resource: String, holder: String },
    RegisterNode { node_id: String, address: String, role: String },
    DecommissionNode { node_id: String },
    FenceEpoch { node_id: String, min_valid_epoch: u64 },
}
```

### 2. Distributed Resource Leases & Epoch Fencing

To guard against network partitions where an isolated former leader continues attempting mutations, leases utilize monotonic epochs:
- When a lease is granted or renewed, its `epoch` is incremented.
- Followers and storage nodes track `min_valid_epoch`. Any RPC or write containing `epoch < min_valid_epoch` is rejected with `InvalidEpoch`.

```rust
pub struct ClusterLease {
    pub resource: String,
    pub holder: String,
    pub epoch: u64,
    pub granted_at_secs: u64,
    pub expires_at_secs: u64,
}
```

### 3. State Machine & Monotonic Index Progression

The `ClusterMetadataStateMachine` applies committed commands deterministically:
- `apply(&mut self, command: &RaftCommand, now_secs: u64)`: Executes key-value updates, lease acquisitions/releases, and node membership tracking.
- State machine entries are applied strictly in log order after receiving acknowledgments from `(N / 2) + 1` nodes.

### 4. Telemetry & CLI Observability

- **Metrics**: Exported under `/metrics` via Prometheus (`velcrux_raft_*`).
- **CLI Subcommands**:
  - `velcrux cluster status --raft`: Displays current term, role, leader ID, commit index, peer count, and active leases.
  - `velcrux cluster join <node-id> --address <addr>`: Dynamically registers a new cluster peer.
  - `velcrux cluster leave <node-id>`: Decommissions a cluster node.
  - `velcrux cluster elect --candidate <node-id>`: Triggers on-demand election round and reports quorum status.
  - `velcrux cluster lease [acquire|release|list]`: Manages distributed leases with epoch fencing.
  - `velcrux cluster benchmark --nodes <N> --rounds <M>`: Runs multi-node simulation with automated network partition and failover verification.

---

## Consequences & Guarantees

1. **Zero External Dependencies**: Raft consensus is fully native and self-contained within Velcrux.
2. **Strict Quorum Consistency**: `W + R > N` linearizability for all cluster coordinator actions.
3. **Partition Resilience**: Majority partition continues processing commits; minority partition halts progression until reconnected, then catches up via log reconciliation.
4. **Safety Compliance**: `#![forbid(unsafe_code)]` with zero exceptions.
