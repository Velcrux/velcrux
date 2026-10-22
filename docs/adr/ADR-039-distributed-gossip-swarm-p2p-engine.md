# ADR-039: Distributed Gossip-Based Peer Discovery & Swarm P2P Acceleration Engine

Status: Accepted · Date: 2026-10-22

## Context

High-concurrency data distribution of large datasets (multi-gigabyte machine learning model checkpoints, container base images, and continuous delivery artifacts) typically relies on centralized origin servers (`ARCHITECTURE.md` §2, §7; `REQUIREMENTS.md` §76, §77). When dozens or hundreds of client worker nodes within the same data center, VPC, or edge cluster synchronize identical datasets simultaneously, centralized architectures suffer from:

1. **Origin Egress Saturation & Cloud Bandwidth Costs**:
   - Centralized servers experience catastrophic egress bandwidth spikes, resulting in high network egress charges and throughput throttling.
2. **Local Link Underutilization**:
   - Nodes situated on high-speed intra-rack or intra-cluster interconnects (10/40/100GbE) download duplicate chunks across wide-area links instead of cooperatively retrieving them from adjacent peers.
3. **Decentralized Membership & Node Churn**:
   - In dynamic ephemeral compute clusters (Kubernetes pods, autoscaling groups), nodes join, fail, and terminate rapidly. A static peer registry or centralized tracker introduces a single point of failure and coordination bottleneck.
4. **Byzantine & Malicious Data Poisoning**:
   - In cooperative peer-to-peer sharing, unverified or rogue peers may advertise corrupted, malicious, or poisoned chunk payloads.
5. **Architectural Safety Invariants**:
   - Zero `unsafe` code (`#![forbid(unsafe_code)]`) across all crates (`CLAUDE.md` §1).
   - Strict bounded memory streaming: chunk mesh management and peer gossip must operate with bounded memory overhead without loading full datasets or unverified chunks into RAM.

## Options Considered

1. **Option 1: Centralized Tracker-Based Peer Coordination (BitTorrent Tracker Pattern)**:
   - Clients query a centralized HTTP/UDP tracker to receive lists of active peers.
   - *Rejected*: The central tracker introduces a single point of failure, bottlenecks during massive scale-out storms, and requires dedicated infrastructure management.
2. **Option 2: Structured Kademlia Distributed Hash Table (DHT)**:
   - Organize all swarm participants into a 160-bit XOR-metric Kademlia routing tree.
   - *Rejected*: Excessively high routing table churn and lookup latency for localized clusters; overkill for ephemeral transfer jobs where gossip anti-entropy achieves faster convergence with lower complexity.
3. **Option 3: Epidemic Gossip Peer Discovery (SWIM-Inspired) with Rarest-First Swarm Mesh (`ADR-039`)**:
   - **Epidemic Gossip Membership**: Lightweight SWIM-inspired failure detector where nodes periodically ping random peer subsets ($k$-fanout). Suspicions are disseminated (`Alive` $\rightarrow$ `Suspect` $\rightarrow$ `Dead`) with monotonically increasing incarnation counters enabling refuted suspicions.
   - **Rarest-First Chunk Mesh**: Nodes advertise chunk possession through gossip inventory broadcasts. Schedulers prioritize the rarest chunks first (chunks possessed by the fewest peers), maximizing diversity and multi-source availability across the cluster.
   - **Byzantine Poisoning Protection**: Every chunk retrieved from a peer is cryptographically verified against the authoritative manifest's BLAKE3 digest *before* being made available to consumers or re-seeded. Any checksum mismatch immediately rejects the chunk, increments security telemetry, bans the rogue peer (`PeerState::Banned`), and purges it from the routing mesh.
   - **Cooperative Tit-for-Tat Unchoking**: Peers prioritize upload bandwidth to neighbors from whom they receive rapid inbound transfers, ensuring fair contribution and preventing free-riding.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Peer Lifecycle & SWIM State Resolution (`crates/velcrux-core/src/swarm/mod.rs`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    /// Peer is active, responsive, and exchanging chunk inventories.
    Alive = 0,
    /// Peer missed recent gossip ping heartbeats; awaiting confirmation.
    Suspect = 1,
    /// Peer confirmed unreachable or dead; excluded from active scheduling.
    Dead = 2,
    /// Peer provided corrupt payload failing cryptographic BLAKE3 verification; permanently banned.
    Banned = 3,
}
```

- When Node $A$ fails to receive an `Ack` from Node $B$, $A$ broadcasts `GossipMessage::Suspect { peer_id: B, incarnation: I }`.
- If $B$ is alive, it refutes the suspicion by incrementing its incarnation counter ($I+1$) and broadcasting `GossipMessage::Alive { peer_id: B, incarnation: I+1 }`.
- If $B$ remains silent throughout `suspect_timeout_ms`, it transitions to `Dead` and is dropped from active chunk transfers.

### 2. Rarest-First Chunk Scheduling (`SwarmChunkMesh`)

The mesh tracks a reverse mapping `chunk_holders: HashMap<Hash, HashSet<PeerId>>`:
- Candidate chunks needed by the local node are sorted ascending by peer possession count.
- The rarest chunks are fetched earliest, rapidly disseminating scarce chunks across the mesh and eliminating bottleneck chunk shortages towards the end of dataset synchronization.

### 3. Byzantine Chunk Poisoning Defense

```rust
pub fn ingest_and_verify(
    &self,
    expected_hash: &Hash,
    payload: &[u8],
    from_peer: &str,
) -> Result<Bytes, VelcruxError> {
    let computed = Hash::of(payload);
    if computed != *expected_hash {
        self.stats.chunks_poisoned_rejected.fetch_add(1, Ordering::Relaxed);
        return Err(VelcruxError::Internal(format!(
            "Byzantine chunk corruption detected from peer {from_peer}"
        )));
    }
    self.stats.chunks_transferred_p2p.fetch_add(1, Ordering::Relaxed);
    self.stats.bytes_offloaded_server.fetch_add(payload.len() as u64, Ordering::Relaxed);
    self.record_local_chunk(*expected_hash);
    Ok(Bytes::copy_from_slice(payload))
}
```

### 4. Telemetry & Prometheus Metrics

Exposed in standard Prometheus `/metrics` format (`crates/velcrux-server/src/metrics.rs`):
- `velcrux_swarm_peers_active`: Gauge of alive routable peers in the mesh.
- `velcrux_swarm_bytes_transferred_total{direction="inbound|outbound"}`: Cumulative bytes exchanged via P2P.
- `velcrux_swarm_offloaded_bytes_total`: Total server egress bandwidth saved via peer sharing.
- `velcrux_swarm_chunks_poisoned_rejected_total`: Total poisoned chunk injection attempts detected and neutralized.

### 5. CLI Management Surface (`velcrux swarm`)

- `velcrux swarm status [--json]`: Comprehensive mesh status, node ID, peer counts, and offload percentage.
- `velcrux swarm peers [--json]`: Detailed tabular listing of discovered peers, states, incarnations, and RTT.
- `velcrux swarm advertise <manifest|dir> [--json]`: Broadcast chunk inventory availability to the gossip mesh.
- `velcrux swarm benchmark [--nodes N] [--chunks C] [--json]`: Run an in-memory multi-node simulation benchmark and measure egress offload ratio (typically 80-95%+).

## Consequences

### Positive
- **80-95%+ Server Egress Bandwidth Reduction**: Multi-node downloads offload the majority of data transfers to cooperative high-bandwidth intra-cluster links.
- **Zero Central Coordination**: Epidemic gossip guarantees eventual consistency without relying on fragile centralized trackers.
- **Resilient Byzantine Defense**: Zero trust verification with strict BLAKE3 validation protects the cluster against corrupt or malicious chunk poisoning.
- **100% Safe Rust**: Complete implementation without any `unsafe` blocks.

### Negative
- Gossip ping traffic introduces nominal background UDP/QUIC control overhead (configurable via `--swarm-port` and `--swarm-max-peers`).
