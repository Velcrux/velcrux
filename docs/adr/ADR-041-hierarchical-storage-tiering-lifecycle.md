# ADR-041: Multi-Tenant Hierarchical Storage Tiering & Hybrid Lifecycle Engine

Status: Accepted · Date: 2026-10-25

## Context

Enterprise data synchronization across multi-tenant environments (`ARCHITECTURE.md` §2, §7; `SECURITY.md` §8, §9) generates petabytes of content-addressable storage (CAS) chunks. Without lifecycle management, all chunks reside indefinitely on high-performance primary storage (NVMe SSDs), resulting in unsustainable infrastructure costs.

Key operational and architectural requirements:
1. **Access Skew & Cold Data Proliferation**:
   - Transfer data exhibits strong access locality: ~80% of chunks are unreferenced after 14 days of transfer completion. Storing dormant chunks on NVMe drives causes capacity exhaustion.
2. **Multi-Tier Latency & Cost Optimization**:
   - **Hot Tier**: Uncompressed raw storage on local NVMe/SSDs for active ingest, sub-millisecond retrieval, and zero-latency delta diffing.
   - **Warm Tier**: Secondary bulk volumes or local staging disks for infrequently accessed active datasets with high sequential throughput.
   - **Cold Tier**: High-density Zstandard-compressed archive storage (default level 9) with cryptographic integrity verification to minimize physical disk footprint by 40–70%.
3. **Multi-Tenant Policy Isolation**:
   - Distinct tenants (e.g., engineering teams, backup systems, ephemeral dev environments) require granular retention policies (`hot_to_warm_days`, `warm_to_cold_days`, `cold_retention_days`, `max_hot_bytes`).
4. **Transparent Retrieval & Auto-Promotion**:
   - Transfers and reads must never fail if a chunk has been demoted to Cold or Warm. The storage engine must stream-decompress chunks on demand, verify BLAKE3 integrity, and promote chunks to Hot when requested.
5. **Background Cryptographic Scrubbing**:
   - Long-term Cold tier archives must be continuously scrubbed to detect and report bit-rot early before data loss occurs.
6. **Invariants**:
   - 100% Safe Rust (`#![forbid(unsafe_code)]` with zero exceptions).
   - Strict bounded memory streaming: decompression and compression buffers are bounded, preventing multi-gigabyte memory spikes.

## Options Considered

1. **Option 1: Rely on OS-Level Filesystem Compression (ZFS / Btrfs)**:
   - Mount ZFS or Btrfs partitions with transparent compression.
   - *Rejected*: Incompatible with ext4, XFS, and macOS APFS; lacks multi-tenant policy granularity; cannot distinguish Hot active ingress from Cold archive chunks.
2. **Option 2: Offline External Archival Scripts**:
   - Cron jobs compressing chunks and archiving them to external tar archives.
   - *Rejected*: Breaks deduplication index; causes transfer read misses and race conditions during concurrent synchronization.
3. **Option 3: Embedded Multi-Tenant Hierarchical Storage Tiering & Hybrid Lifecycle Manager (`ADR-041`)**:
   - **Three-Tier Architecture**: Physical separation of chunk paths (`hot/chunks/`, `warm/chunks/`, `cold/chunks/`) with crash-resilient metadata index persistence.
   - **On-the-Fly Stream Decompression**: Reads from Cold tier automatically decompress with bounded memory buffers while verifying BLAKE3 cryptographic hashes.
   - **Automated Lifecycle Sweeps**: Automated evaluation of age and capacity quotas with configurable LRU demotion.
   - **Cold Archive Bit-Rot Scrubbing**: Dedicated scrub routines detecting silent bit degradation.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Storage Tiers & Policy Model (`crates/velcrux-core/src/storage/tiering.rs`)

```rust
pub enum StorageTier {
    Hot = 0,
    Warm = 1,
    Cold = 2,
}

pub struct TenantTierPolicy {
    pub tenant_id: String,
    pub hot_to_warm_days: u32,
    pub warm_to_cold_days: u32,
    pub cold_retention_days: Option<u32>,
    pub max_hot_bytes: Option<u64>,
    pub auto_promote_on_read: bool,
    pub cold_compression_level: i32,
}
```

### 2. Directory Layout & Persistence

```
<chunk_store>/
├── tier_index.json
├── policies/
│   ├── default.json
│   └── tenant_alpha.json
├── hot/
│   └── chunks/<shard>/<hash>
├── warm/
│   └── chunks/<shard>/<hash>
└── cold/
    └── chunks/<shard>/<hash>.zst
```

- Ingestion writes raw bytes to `hot/chunks/<shard>/<hash>`.
- Demotion to `cold/` compresses payload with Zstandard (level 9 default) into `<hash>.zst`, atomic fsync + rename, and deletes the uncompressed chunk.
- Transparent retrieval reads directly or decompresses on-the-fly, auto-promoting to Hot tier when `auto_promote_on_read` is enabled.

### 3. Operational CLI Management

- `velcrux tier status [--tenant <ID>] [--json]`
- `velcrux tier policy set [--tenant <ID>] [--hot-days <N>] [--warm-days <N>] [--cold-retention-days <N>] [--max-hot-bytes <B>]`
- `velcrux tier policy get [--tenant <ID>]`
- `velcrux tier policy list`
- `velcrux tier migrate --hash <HEX> --target <hot|warm|cold>`
- `velcrux tier sweep [--tenant <ID>] [--dry-run]`
- `velcrux tier scrub [--tenant <ID>]`

### 4. Telemetry & Prometheus Observability

Exposed under `/metrics`:
- `velcrux_storage_tier_bytes{tier="hot|warm|cold"}`
- `velcrux_storage_tier_promotions_total`
- `velcrux_storage_tier_demotions_total`
- `velcrux_storage_tier_retrievals_total`

## Consequences

- **Positive**:
  - Dramatic reduction in NVMe SSD storage costs (40–70% space savings for cold datasets).
  - Multi-tenant isolation with customized retention policies.
  - Zero-downtime transparent reads: clients and transfers never fail due to chunk demotion.
  - Continuous bit-rot protection through Cold tier scrubbing.
- **Negative / Trade-offs**:
  - Cold tier reads incur small CPU decompression overhead (~0.5 ms per 1 MiB chunk).
