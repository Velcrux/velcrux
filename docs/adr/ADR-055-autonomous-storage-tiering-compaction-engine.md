# ADR-055: Autonomous Self-Tuning Storage Tiering & Compaction Engine

Status: Accepted · Date: 2026-11-01

## Context

Enterprise Content-Addressable Storage (CAS) architectures ingest millions to billions of content-addressed chunk blobs indexed by cryptographic BLAKE3 hashes. In production synchronization and replication environments:
- **Skewed Access Distribution**: Over 85% of transfer read requests target a small working set ($\le 15\%$) of recently synced files and metadata indexes.
- **Capacity Cost vs Performance Bottleneck**: Hosting entire multi-terabyte chunk repositories on high-speed NVMe/PCIe Gen5 storage is cost-prohibitive. Conversely, storing frequently accessed chunks on secondary SSD pools, erasure-coded distributed meshes, or cloud object archives introduces severe latency penalties (50µs vs 5ms vs 500ms).
- **Storage Fragmentation & Orphan Accumulation**: Repeated file edits, interrupted transfers, deleted snapshots, and garbage collection tombstones generate storage fragmentation and orphaned chunk blobs. Left uncompacted, fragmented CAS shards exhaust storage margins and degrade IOPS.
- **SLO Degradation from Heavy Compaction Sweeps**: Traditional background garbage collectors run large synchronous sweeps that spike disk I/O queue depths, creating severe read/write latency jitter that violates transfer Service Level Objectives (SLOs).

To resolve these challenges, Velcrux requires an **Autonomous Self-Tuning Storage Tiering & Compaction Engine** that monitors chunk access patterns in real time, computes mathematical heat-map temperatures using exponential decay, autonomously migrates data across physical tiers based on capacity watermarks, and executes rate-limited zero-copy compaction within strict SLO execution bounds.

---

## Options Considered

1. **Option 1: Static Time-Based Crontab Sweeps**:
   - Run daily or weekly cron scripts checking file mtime/atime to relocate files across directories.
   - *Rejected*: Lacks real-time access frequency visibility; coarse filesystem atime updates degrade filesystem performance; cannot respond autonomously to sudden capacity surges or watermark breaches.
2. **Option 2: Kernel-Level In-Band Tiering (bcache / dm-cache / ZFS L2ARC)**:
   - Rely on host operating system block-level caching or tiered file systems.
   - *Rejected*: Violates Velcrux's strict cross-platform, kernel-agnostic, and `#![forbid(unsafe_code)]` invariants; cannot inspect application-level chunk references, manifest provenance, or CAS tombstones.
3. **Option 3: Pure Safe Rust Autonomous Self-Tuning Storage Tiering & Zero-Copy Compaction Engine (`ADR-055`)**:
   - Strictly `#![forbid(unsafe_code)]` with zero external C/OS-kernel dependencies.
   - Continuous real-time heat-map generation (`ChunkAccessHeatmap`) tracking chunk frequency and exponential recency decay.
   - Multi-tier classification:
     - `Hot`: High-speed local NVMe/SSD, sub-millisecond retrieval ($T \ge 75.0$).
     - `Warm`: Secondary bulk local SSD or network staging ($35.0 \le T < 75.0$).
     - `Cold`: High-density erasure-coded distributed mesh ($10.0 \le T < 35.0$).
     - `FrozenGlacier`: Ultra-cold cloud archive ($T < 10.0$).
   - Autonomous watermark-driven migration policies (High/Low watermarks on Hot/Warm tiers) with automatic read-promotion.
   - Zero-copy compaction, orphan reclamation, and tombstone purging bounded by strict SLO execution duration budgets and throughput rate limits.
   - Multi-process atomic persistence (`VELCRUX_COMPACTION_DIR`).
   - Microsecond performance benchmark (`velcrux compaction benchmark`) and Prometheus metrics exposition.

---

## Decision

Adopt **Option 3: Pure Safe Rust Autonomous Self-Tuning Storage Tiering & Zero-Copy Compaction Engine (`ADR-055`)**.

### Architectural Design

```
+-------------------------------------------------------------------------------------------------+
|               Velcrux Autonomous Storage Tiering & Compaction Engine Architecture               |
|                                                                                                 |
|   [ CAS Chunk Ingestion / Transfers / Client Reads ]                                            |
|                              │                                                                  |
|                              ▼                                                                  |
|   ┌────────────────────────────────────────────────────────────────────────────────────────┐    |
|   │ Real-Time Chunk Access Heatmap (`ChunkAccessHeatmap`)                                  │    |
|   │  • Access Count (N)  • Last Access Epoch (t_last)  • Size (bytes)                      │    |
|   │  • Exponential Decay: R(t) = 2^(-Δt / t_1/2)                                           │    |
|   │  • Temperature Score: T = 0.60 * R(t) + 0.40 * min(1.0, N / N_cap)                    │    |
|   └──────────────────────────┬─────────────────────────────────────────────────────────────┘    |
|                              │                                                                  |
|         ┌────────────────────┴────────────────────┐                                             |
|         ▼                                         ▼                                             |
|   ┌───────────────────────────────┐         ┌──────────────────────────────────────────────┐    |
|   │ Autonomous Watermark Planner  │         │ Zero-Copy Compaction & Reclamation Daemon    │    |
|   │  • Hot Tier High WM (> 85%)   │         │  • Expired Tombstone Purging (> 7 days)      │    |
|   │    Demote coldest to Warm     │         │  • Unreferenced Orphan Reclamation (> 24h)   │    |
|   │  • Warm Tier High WM (> 85%)  │         │  • Rate Limiting (e.g. 100 MB/s cap)         │    |
|   │    Demote coldest to Cold     │         │  • Strict SLO Budget Guardrails (<= 100ms)   │    |
|   │  • Cold Tier High WM (> 90%)  │         └──────────────────────┬───────────────────────┘    |
|   │    Demote to Glacier Archive  │                                │                            |
|   │  • Read Access Auto-Promotion │                                │                            |
|   │    Promote to Hot Tier        │                                │                            |
|   └──────────────┬────────────────┘                                │                            |
|                  │                                                 │                            |
|                  ▼                                                 ▼                            |
|   ┌────────────────────────────────────────────────────────────────────────────────────────┐    |
|   │ Storage Tiers & Execution Fabric                                                       │    |
|   │  • [Hot Tier]: NVMe / SSD ($O(1)$ raw access)                                          │    |
|   │  • [Warm Tier]: Secondary Bulk SSD / Staging                                           │    |
|   │  • [Cold Tier]: Erasure-Coded Distributed Mesh                                         │    |
|   │  • [Glacier Tier]: High-Density Cloud Archive                                          │    |
|   └────────────────────────────────────────────────────────────────────────────────────────┘    |
+-------------------------------------------------------------------------------------------------+
```

---

## Mathematical Formulation

### 1. Exponential Recency Decay & Heat Temperature Scoring

For each chunk $c \in \text{CAS}$ with access count $N_c$ and time since last access $\Delta t = \max(0, t_{\text{now}} - t_{\text{last}})$:

1. **Recency Factor**:
   $$R(t) = 2^{-\frac{\Delta t}{t_{1/2}}}$$
   where $t_{1/2}$ is the configurable half-life (default: $3600\,\text{s} = 1\,\text{hour}$).
   $$\text{Score}_{\text{recency}} = 100.0 \times R(t)$$

2. **Frequency Factor**:
   $$F(N) = \min\left(1.0, \frac{N_c}{N_{\text{cap}}}\right)$$
   where $N_{\text{cap}}$ is the frequency normalization ceiling (default: $100$).
   $$\text{Score}_{\text{frequency}} = 100.0 \times F(N)$$

3. **Composite Temperature Score**:
   $$T(c) = 0.60 \times \text{Score}_{\text{recency}} + 0.40 \times \text{Score}_{\text{frequency}}$$
   $$T(c) \in [0.0, 100.0]$$

### 2. Tier Placement Classification

$$\text{Tier}(c) = \begin{cases}
\text{Hot} & \text{if } T(c) \ge 75.0 \\
\text{Warm} & \text{if } 35.0 \le T(c) < 75.0 \\
\text{Cold} & \text{if } 10.0 \le T(c) < 35.0 \\
\text{FrozenGlacier} & \text{if } T(c) < 10.0
\end{cases}$$

### 3. Watermarked Capacity Demotion Algorithm

Let $B_{\text{tier}}$ be the aggregate bytes currently stored in a given tier.
- If $B_{\text{tier}} > \text{Capacity}_{\text{tier}} \times \text{HighWatermark\%}$:
  Sort chunks in ascending order of temperature score $T(c)$ (coldest chunks first).
  Demote coldest chunks to the adjacent lower tier until:
  $$B_{\text{tier}} \le \text{Capacity}_{\text{tier}} \times \text{LowWatermark\%}$$

---

## Consequences

### Positive
- **Guaranteed NVMe Working Set Availability**: Autonomous demotion maintains Hot tier utilization below the high watermark (85%), preventing disk-full write rejections during high-volume ingress.
- **Zero Latency Regression on Working Data**: Frequently referenced and recently accessed chunks remain pinned in Hot tier or get promoted on first read.
- **Predictable Compaction Without SLO Violations**: Compaction cycles enforce a strict execution time budget ($\le 100\,\text{ms}$) and rate limiting, eliminating IOPS spikes and tail-latency jitter.
- **Safe Crash-Resilient Persistence**: State serialization uses atomic write and rename (`.compaction_state.tmp.*` $\to$ `compaction_state.json`), ensuring crash resilience across process restarts and CLI calls.
- **100% Safe Rust**: Implemented under `#![forbid(unsafe_code)]` with zero external C dependencies.

### Negative / Trade-Offs
- **Demotion / Promotion I/O Overhead**: Moving chunks between physical tiers consumes background storage bandwidth (mitigated by rate limiting and low watermark hysteresis).
- **In-Memory Heatmap Footprint**: Tracking metadata records for millions of chunks consumes approximately 80 bytes per chunk in memory (mitigated by compact struct layout and pruning).
