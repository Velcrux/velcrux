# ADR-038: CAS Generational Garbage Collection, Tombstoning & Compaction Daemon

Status: Accepted · Date: 2026-10-22

## Context

Content-Addressable Storage (CAS) chunk deduplication is foundational for high-throughput dataset synchronization across wide-area networks (`ARCHITECTURE.md` §2, §7; `ADR-006`). By referencing chunks by their cryptographic digest (`BLAKE3`), redundant network transmissions and duplicate storage blocks are eliminated across files, versions, and snapshots.

However, content-addressed stores introduce subtle and critical garbage collection challenges:

1. **Race Conditions During Concurrent Ingestion & Sweep**:
   - In active multi-stream pipelines, chunks are written to the CAS store *before* the manifest is committed or the file tree is atomically renamed.
   - If a naive mark-and-sweep garbage collector runs concurrently, newly written chunks not yet referenced in committed file manifests would be swept, causing subsequent transfers or commits to fail with missing chunk errors.
2. **Immediate Unlinking Risks**:
   - Deleting unreferenced chunks immediately upon reference loss prevents recovery if an interrupted transfer, rollback journal, or subsequent delta transfer needed to reuse that chunk.
3. **Storage Compaction & Empty Shard Bloat**:
   - As chunks are deleted from two-level hex fanout directories (`chunks/ab/cd/`), hundreds of empty subdirectories remain, polluting inode tables and degrading directory lookups.
4. **Architectural Safety & Invariants**:
   - Strict adherence to `#![forbid(unsafe_code)]` with zero exceptions across all crates (`CLAUDE.md` §1).
   - Strict bounded memory streaming: generational mark-and-sweep and reference collection must never load entire chunk stores or multi-gigabyte files into memory.

## Options Considered

1. **Option 1: Manual Mark-and-Sweep Without Generational Lease**:
   - Walk files, gather references, and delete unreferenced chunks immediately.
   - *Rejected*: Suffers from severe race conditions with in-flight transfers and lacks safety margins for accidental deletions.
2. **Option 2: Strict Reference Counting in Database**:
   - Maintain a synchronous reference count on every chunk in SQLite.
   - *Rejected*: Incurs immense write amplification and database locking during high-concurrency 10Gbps+ transfers.
3. **Option 3: Generational GC with Tombstoning & Compaction Daemon (`ADR-038`)**:
   - Partition chunk lifecycles into 3 discrete generations:
     - `Nursery` (Gen 0): In-flight / recently ingested chunks within a configurable grace window (default: 1 hour). Immune from tombstoning.
     - `Tenured` (Gen 1): Verified referenced chunks in active files, manifests, and snapshots.
     - `Tombstoned` (Gen 2): Unreferenced chunks marked with durable tombstone metadata files (`<hex>.tombstone`).
   - Support instantaneous resurrection: If an active transfer references a tombstoned chunk before TTL expiry, the tombstone is removed, returning it to Tenured.
   - Background compaction daemon (`CasCompactionDaemon`) that sweeps expired tombstones past TTL, unlinks files, reclaims disk space, and prunes empty shard directories.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Generational Lifecycle Classification (`crates/velcrux-core/src/storage/cas_gc.rs`)

```rust
pub enum CasGeneration {
    /// Gen 0: Young chunks within nursery grace period. Immune to tombstoning.
    Nursery = 0,
    /// Gen 1: Chunks with verified active references.
    Tenured = 1,
    /// Gen 2: Unreferenced chunks marked with active tombstone files.
    Tombstoned = 2,
}
```

### 2. Durable Tombstone Markers (`CasTombstone`)

When an unreferenced chunk is swept, rather than immediate deletion, a companion JSON metadata file (`chunks/ab/cd/<hex>.tombstone`) is atomically created:

```rust
pub struct CasTombstone {
    pub hash: Hash,
    pub tombstoned_at_secs: u64,
    pub size: u64,
    pub generation: u32,
    pub reason: String,
    pub tenant: Option<String>,
}
```

- **Resurrection**: Calling `resurrect(&hash)` deletes `<hex>.tombstone` while retaining the data chunk on disk.
- **Hard Purge**: When `now - tombstoned_at_secs >= tombstone_ttl_secs`, both `<hex>.chunk` and `<hex>.tombstone` are deleted, and parent shard directories are pruned if empty.

### 3. Generational Compaction Daemon (`CasCompactionDaemon`)

Coordinates periodic background sweeps:
- Evaluates active reference sets across storage trees and snapshots.
- Protects nursery chunks within `nursery_grace_secs` (default: 3600s).
- Compacts expired tombstones older than `tombstone_ttl_secs` (default: 86400s).
- Rebuilds Bloom filter index and tracks Prometheus telemetry.

### 4. CLI Subcommand Reference (`crates/velcrux-client/src/main.rs`)

- Global flags:
  - `--cas-tombstone-ttl <seconds>`: Tombstone retention window before permanent purge (default: 86400).
  - `--cas-nursery-grace <seconds>`: In-flight nursery protection lease (default: 3600).
- Subcommands:
  - `velcrux cas status [--chunk-store <dir>] [--json]`: Displays generational inventory breakdown.
  - `velcrux cas gc [--chunk-store <dir>] [--nursery-grace <secs>] [--purge-expired] [--dry-run] [--json]`: Executes mark-and-sweep.
  - `velcrux cas resurrect --hash <hex> [--chunk-store <dir>] [--json]`: Un-tombstones a chunk.
  - `velcrux cas purge [--chunk-store <dir>] [--older-than-secs <secs>] [--dry-run] [--json]`: Hard purges expired tombstones.

### 5. Prometheus Observability (`crates/velcrux-server/src/metrics.rs`)

- `velcrux_cas_gc_runs_total`: Total compaction passes executed.
- `velcrux_cas_chunks_tombstoned_total`: Cumulative chunks transitioned to tombstone status.
- `velcrux_cas_chunks_resurrected_total`: Cumulative chunks resurrected.
- `velcrux_cas_chunks_purged_total`: Total physical chunks deleted.
- `velcrux_cas_bytes_reclaimed_total`: Total physical disk bytes freed.

## Consequences

### Positive
- Zero race conditions: in-flight uploads within the nursery grace period are never tombstoned.
- Safety net: unreferenced chunks survive for 24h as tombstones and can be resurrected instantly without re-upload.
- Automatic disk reclamation and empty shard pruning prevent inode exhaustion.
- Full observability through Prometheus counters and CLI diagnostics.

### Negative / Trade-offs
- Writing `.tombstone` files creates small metadata disk overhead until purge occurs.
- Compaction sweeps require scanning chunk directory trees.
