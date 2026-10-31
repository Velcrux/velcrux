# ADR-052: Cross-Region Multi-Cloud Distributed Storage Federation & Active-Active Geo-Replication

Status: Accepted · Date: 2026-10-31

## Context

Global enterprise data workflows, cross-sovereign compliance regulations (e.g. EU GDPR data residency, US FedRAMP, HIPAA), and multi-cloud disaster recovery architectures require data distribution across heterogeneous hyperscaler object stores (AWS S3, Google Cloud Storage, Azure Blob Storage, and on-premises MinIO):
- **Vendor Lock-In & Cloud Outages**: Major regional outages in AWS, GCP, or Azure halt single-cloud applications. Enterprises require vendor-agnostic active-active storage that transparently survives the total failure of any single hyperscaler.
- **Egress Bandwidth Tolls**: Hyperscalers impose asymmetric egress networking fees (\$0.08 to \$0.09 per GiB) when reading data across cloud boundaries or to the public internet. Reads should be served from zero-cost on-premises MinIO or cached locally.
- **Concurrent Cross-Region Divergence**: Independent writes to different regional datacenters cause split-brain data divergence without causal ordering guarantees.
- **Incompatible Object APIs**: AWS S3 (SigV4, multipart upload), GCS (JSON API, resumable chunked upload), Azure Blob (SharedKey, block blobs), and MinIO each require different SDKs, credential schemes, and consistency models.

To eliminate hyperscaler lock-in, survive regional outages, optimize egress costs, and provide unified active-active data access, Velcrux requires a pure safe Rust Multi-Cloud Storage Federation and Geo-Replication Mesh.

---

## Options Considered

1. **Option 1: Traditional Cloud Storage Gateways / S3 Proxies (e.g. MinIO Gateway)**:
   - Run a standalone proxy translating S3 calls to GCS/Azure.
   - *Rejected*: MinIO Gateway was deprecated; introduces a single point of failure and bottleneck; lacks multi-cloud active-active quorum replication and causal vector clock conflict resolution.
2. **Option 2: Asynchronous Offline Cloud Bucket Replication Tools (e.g. Rclone / AWS S3 Replication)**:
   - Periodic rsync/rclone cron jobs or cloud-native 1-way replication.
   - *Rejected*: Lacks read-through caching; replication delays cause stale reads and lost updates; no support for active-active concurrent writes or atomic cross-cloud deletes.
3. **Option 3: Pure Safe Rust Unified Multi-Cloud Storage Federation & Active-Active Broker (`ADR-052`)**:
   - Strictly `#![forbid(unsafe_code)]` with zero external C/cloud SDK dependencies.
   - Unified federated namespace routing across AWS S3, GCS, Azure Blob, MinIO, and Local CAS.
   - Multi-cloud routing policies: `ActiveActive`, `PrimaryFailover`, `CostOptimized`, and `WeightedRoundRobin`.
   - Causal causality tracking using **Vector Clocks** with deterministic conflict resolution (`CausalVectorClock`, `LastWriteWins`, `ProviderPriority`, `KeepBothFork`).
   - High-performance LRU read-through caching engine (`FederatedReadCache`) with BLAKE3 cryptographic verification.
   - Dynamic provider health tracking, latency telemetry, and instantaneous circuit-breaker failover.
   - First-class operator CLI subcommands (`velcrux federation status|put|get|sync|providers|benchmark`) and Prometheus metrics exposition.

---

## Decision

Adopt **Option 3: Pure Safe Rust Unified Multi-Cloud Storage Federation & Active-Active Broker (`ADR-052`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------------+
|                  Velcrux Multi-Cloud Distributed Storage Federation Mesh                |
|                                                                                         |
|  [ Client Application / CLI / API ]                                                     |
|                   │                                                                     |
|                   ▼                                                                     |
|  ┌─────────────────────────────────────────────────────────┐                            |
|  │ FederatedStorageBroker (Routing & Causality Engine)     │                            |
|  │  - Vector Clock increment across active regions         │                            |
|  │  - Active-Active Quorum Replication                     │                            |
|  │  - Dynamic Health Probing & Latency Smoothing           │                            |
|  └───────────────┬─────────────────────────┬───────────────┘                            |
|                  │                         │                                            |
|                  ▼                         ▼                                            |
|  ┌──────────────────────────────┐   ┌──────────────────────────────────────────────┐    |
|  │ FederatedReadCache (Memory)  │   │ Federation Routing & Failover Manager        │    |
|  │  - Sub-µs Cache Hits (BLAKE3)│   │  - Lowest Latency / Lowest Egress Selection  │    |
|  │  - Bounded Memory Eviction   │   │  - Circuit Breaker: Auto-Failover to Healthy │    |
|  └──────────────────────────────┘   └──────────────────────┬───────────────────────┘    |
|                                                            │                            |
|           ┌────────────────┬───────────────────────────────┼────────────────┐           |
|           ▼                ▼                               ▼                ▼           |
|     ┌───────────┐    ┌───────────┐                   ┌───────────┐    ┌───────────┐     |
|     │  AWS S3   │    │ Google CS │                   │Azure Blob │    │   MinIO   │     |
|     │ us-east-1 │    │europe-west│                   │  eastus   │    │ on-prem   │     |
|     └───────────┘    └───────────┘                   └───────────┘    └───────────┘     |
+-----------------------------------------------------------------------------------------+
```

### Causality Tracking & Conflict Resolution

1. **Vector Clock Causality**:
   Each object modification is tagged with a `VectorClock` $V$, where $V[r]$ represents the logical sequence counter for region $r$.
   For two versions $A$ and $B$:
   - $A > B$ (dominates): $A[r] \ge B[r]$ for all $r$, and $A[r] > B[r]$ for at least one $r$.
   - $A < B$ (dominated): $B$ strictly dominates $A$.
   - $A \parallel B$ (concurrent conflict): $A[r_1] > B[r_1]$ and $A[r_2] < B[r_2]$ for distinct regions $r_1, r_2$.

2. **Resolution Policies**:
   - `CausalVectorClock`: Automatically picks the dominant version. If concurrent ($A \parallel B$), resolves deterministically via lexicographical BLAKE3 digest tie-breaking.
   - `LastWriteWins`: Uses physical wall-clock timestamp $T(A)$ vs $T(B)$ with provider priority tie-breaking.
   - `ProviderPriority`: Strict priority ordering (Primary AWS > GCS > Azure > MinIO).
   - `KeepBothFork`: Retains both branches by appending a collision suffix (`.conflicted.<origin>.<ts>`).

3. **Distributed Tombstones**:
   Deletions write tombstone markers ($S=0$, $\text{hash}=\text{Hash::ZERO}$, $\text{version}=9999$) propagated across clouds with configurable 24-hour retention to prevent resurrection by delayed asynchronous links.

---

## Consequences

### Positive
- **Hyperscaler Vendor Neutrality**: Applications read and write to a single federated broker without cloud lock-in.
- **Zero-Downtime High Availability**: Complete failure or partition of AWS, Google Cloud, or Azure results in automatic failover without client error.
- **Egress Cost Minimization**: Reads are served from local cache or lowest-cost providers (MinIO / on-prem), slashing cross-cloud egress bills.
- **Pure Safe Rust Reliability**: 100% safe Rust conforming to `#![forbid(unsafe_code)]`.
- **Comprehensive Observability**: Full Prometheus metrics and CLI administration.

### Negative / Trade-Offs
- **Multi-Cloud Write Latency**: Active-active writes must propagate across cloud APIs, bound by the write quorum latency.
- **Storage Amplification**: Storing replicas across multiple hyperscalers consumes storage capacity across each provider (mitigated by tiered federation policies).

