# ADR-017: Cross-Cluster WAN Geo-Replication & Conflict Resolution Engine

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §50–§55 ("Cross-Cluster WAN Replication & Multi-Datacenter Distribution") and §63 ("Disaster Recovery & High Availability"), modern enterprise storage architectures span multiple disparate geographical locations (e.g. North America `us-east-1`, Europe `eu-central-1`, Asia-Pacific `ap-tokyo-1`):
1. **High WAN Latencies & Link Flapping**: Inter-datacenter RTTs frequently exceed 100ms–250ms with non-zero packet loss. Synchronous replication protocols (such as Raft or synchronous quorum writes $W=N$) introduce unacceptable write latency and stall entire clusters during transoceanic link cuts.
2. **Concurrent Multi-Master Edits (Split-Brain Risks)**: When users or automated data pipelines in different regions concurrently modify or delete the same file path while partitions exist, naive replication results in silent data overwrites or conflicting states.
3. **Resurrected Files (Deletion Races)**: Without durable tombstone tracking, an older delayed replication stream from a partitioned datacenter can re-create a file that was intentionally deleted in another datacenter.

## Options Considered

1. **Synchronous Two-Phase Commit / Global Consensus (Multi-Raft / Spanner pattern)**:
   - Synchronous consensus across all geographic regions on every write.
   - *Rejected*: Every write incurs multiple cross-continent RTT round-trips (>300ms) and becomes completely unavailable during any cross-region fiber cut.
2. **Centralized Active-Passive Hub-and-Spoke**:
   - Single designated primary datacenter; all other regions operate as read-only replicas.
   - *Rejected*: Single point of failure (SPOF) for ingestion, high write latency for distant branch offices, and manual failover complexity.
3. **Asynchronous Multi-Master Geo-Replication with Vector Clocks & Tunable Conflict Policies**:
   - Local writes commit immediately with sub-millisecond latency.
   - Mutations are captured and buffered into asynchronous outbound replication queues (`GeoReplicationQueue`).
   - Causality is mathematically tracked using `VectorClock` (mapping `RegionId -> sequence`).
   - Concurrent branching is detected (`ClockOrdering::Concurrent`) and deterministically resolved via configurable policies (`LastWriteWins`, `PrimaryAuthority`, `KeepBoth`, `RejectConcurrent`).
   - Deletions create timestamped `Tombstone` entries with configurable TTL to prevent stale resurrection.

## Decision

Option 3. Velcrux implements native asynchronous cross-cluster WAN geo-replication with vector clock causality tracking and configurable conflict resolution with `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Vector Clock Causality Tracking

Every file mutation maintains a `VectorClock`:
```text
  Region A (us-east)                Region B (eu-central)
  ──────────────────                ─────────────────────
  [v1] Write doc.txt
       VC = {us: 1}  ─────────────► [v1] Replicated
                                         VC = {us: 1}
  [v2] Modify doc.txt                    [v2'] Concurrently Modify
       VC = {us: 2}                      VC = {us: 1, eu: 1}
            │                                  │
            └───────────────┬──────────────────┘
                            ▼
               Concurrent Conflict Detected!
                  {us: 2} vs {us: 1, eu: 1}
```
- **Dominance (`Greater`/`Less`)**: If one vector clock strictly dominates another, the newer version is accepted without conflict.
- **Concurrent Conflict (`Concurrent`)**: If neither vector clock dominates, a concurrent modification conflict is flagged.

### 2. Configurable Conflict Resolution Policies

Operators configure conflict handling via `--conflict-policy`:
1. **`LastWriteWins` (LWW, Default)**: Compares physical wall-clock timestamps (Unix epoch milliseconds). Ties are broken deterministically by region identifier lexicographical ordering.
2. **`PrimaryAuthority`**: A designated primary region (e.g. `--primary-region us-east-1`) always overrides non-primary changes.
3. **`KeepBoth`**: Preserves both concurrent versions by creating a non-destructive sidecar file (e.g. `doc.txt.conflict-eu-central-1-1710000000.txt`).
4. **`RejectConcurrent`**: Rejects the incoming concurrent change and alerts operators for manual intervention.

### 3. Tombstones & Anti-Entropy Synchronization

- **Tombstones**: Deletions create a tombstone entry recording the deletion vector clock and timestamp. Stale remote mutations with older vector clocks are rejected, preventing file resurrection.
- **Tombstone Pruning**: Background routine prunes tombstones older than `tombstone_ttl_secs` (default: 7 days / 604,800s).
- **Anti-Entropy**: Background sweeps sync delta states and balance vector clocks across regional endpoints.

### 4. CLI Administration

```bash
# Inspect cross-region replication status, vector clocks, and WAN lag
velcrux geo status --local-region us-east-1

# Inspect with custom remote endpoints and Primary-Authority conflict policy
velcrux geo status \
  --local-region ap-tokyo-1 \
  --regions "eu-west-1=10.1.0.1:7443,us-east-1=10.2.0.1:7443" \
  --conflict-policy primary --primary-region us-east-1

# Trigger anti-entropy sync between two regional endpoints
velcrux geo sync --source-region us-east-1 --target-region eu-central-1

# Machine-readable JSON output for orchestration
velcrux --json geo status
```

## Consequences

- **Positive**: Low-latency local writes, zero downtime during WAN network cuts, and mathematical convergence across global sites.
- **Positive**: Eliminates file resurrection bugs via vector-clock-anchored tombstones.
- **Neutral**: Eventual consistency model requires awareness that concurrent edits resolve according to the configured conflict policy.
