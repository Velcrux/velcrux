# ADR-065: Distributed Object Storage Sharding & Multi-Bucket Tiering

- **Status**: Accepted
- **Date**: 2026-11-04
- **Deciders**: Velcrux Core Storage, Distributed Systems, Multi-Cloud Gateway, and High-Throughput I/O Teams
- **Consulted**: Platform Engineering, DevOps, Cloud Architecture, and Performance Engineering Teams

---

## 1. Context and Problem Statement

Cloud object stores such as Amazon S3, MinIO, Google Cloud Storage, and Azure Blob Storage enforce fundamental architectural partition bounds:
1. **Per-Prefix IOPS Ceiling**: Standard S3 partitions scale up to 3,500 PUT/POST/DELETE requests/second and 5,500 GET/HEAD requests/second per prefix partition. Large-scale content-addressed bulk transfers with millions of chunks sharing a flat key prefix (e.g. `chunks/<hash>`) rapidly throttle with HTTP `503 SlowDown` errors.
2. **Single-Bucket Throughput & Capacity Bottlenecks**: High-throughput distributed ingestion workloads exceeding 100 Gbps easily saturate single-bucket API rate limits and region bandwidth gateways.
3. **Cold Archive Restoration Latency**: Archiving infrequently accessed historical chunks to cold tiers (e.g. `GLACIER`, `DEEP_ARCHIVE`) is economically essential, but REST reads on unrestored objects fail with HTTP `403 InvalidObjectState`. Applications require an asynchronous restore coordinator that manages `POST ?restore` request lifecycles, parses `x-amz-restore` headers, and coordinates transparent range reads once restored.
4. **Lifecycle Tiering Complexity**: Automated rule-based migration from hot (`STANDARD`) to warm (`STANDARD_IA`) and cold (`GLACIER`, `DEEP_ARCHIVE`) tiers must evaluate object age and size thresholds without blocking active I/O.

---

## 2. Decision Drivers

- **High-IOPS Horizontal Sharding**: Distribute chunk placement across $N$ bucket shards using a consistent hash ring with virtual nodes (vnodes) to achieve balanced load distribution and minimize chunk migration during topology resizing.
- **Prefix Fanout Scaling**: Implement configurable prefix partitioning strategies—specifically two-level hex prefix partitioning (`HexTwoLevel` -> `chunks/aa/bb/<hash>`), distributing chunks across 65,536 distinct S3 partitions and scaling theoretical throughput to > 229,000,000 PUTs/sec.
- **Unified Cloud Storage Classes**: Explicit modeling of storage classes (`Standard`, `StandardIa`, `OneZoneIa`, `IntelligentTiering`, `GlacierInstantRetrieval`, `GlacierFlexibleRetrieval`, `GlacierDeepArchive`).
- **Cold Archive Restoration State Machine**: Fully automated `GlacierRestoreCoordinator` managing asynchronous `POST /{bucket}/{key}?restore` lifecycles, tracking `ongoing-request="true"` polling, and transitioning to `Restored` upon readiness.
- **Automated Lifecycle Auto-Tiering Engine**: `ShardedLifecycleEngine` evaluating rule-based age and size thresholds across multi-bucket shards, generating comprehensive `ShardedLifecycleReport` metrics.
- **Distributed Content-Addressed Chunk Store**: `ShardedChunkStore` implementing the `ChunkStore` trait across the multi-bucket topology with batch existence queries (`has_batch`), parallel reads, and bit-for-bit whole-file reconstruction.
- **Zero Unsafe Code**: 100% pure safe Rust (`#![forbid(unsafe_code)]`) with zero external C dependencies.

---

## 3. Considered Options

- **Option 1: Flat Prefix on a Single S3 Bucket**:
  - *Cons*: Throttles at 3,500 PUT req/s and 5,500 GET req/s; cannot leverage multi-bucket or multi-region bandwidth.
- **Option 2: External Proxy / Gateway Routing (e.g. NGINX / Envoy)**:
  - *Cons*: Adds complex operational dependencies, additional network hops, latency overhead, and single points of failure.
- **Option 3 (Chosen): Native Distributed Object Storage Sharding & Multi-Bucket Tiering (`Option CW`)**:
  - Built-in consistent hash ring (`ShardRouter`) with virtual nodes and Shannon entropy verification.
  - Multi-level prefix strategies (`Flat`, `HexTwoLevel`, `HexThreeLevel`, `ShardPrefixed`).
  - Native cold tier restore coordinator (`GlacierRestoreCoordinator`) and state machine (`ObjectRestoreState`).
  - Sharded lifecycle engine (`ShardedLifecycleEngine`) evaluating age and size thresholds.
  - Distributed `ShardedChunkStore` exposing a unified content-addressed `ChunkStore` interface.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│             VELCRUX DISTRIBUTED OBJECT STORAGE SHARDING & MULTI-BUCKET TIERING         │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
                                            ▼
                                   ┌─────────────────┐
                                   │   Chunk Hash    │ (BLAKE3)
                                   └────────┬────────┘
                                            │
                                            ▼
                                   ┌─────────────────┐
                                   │   ShardRouter   │
                                   ├─────────────────┤
                                   │ Consistent Ring │
                                   │ Virtual Nodes   │
                                   │ Prefix Strategy │
                                   └────────┬────────┘
                                            │
                  ┌─────────────────────────┼─────────────────────────┐
                  ▼                         ▼                         ▼
         ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
         │ Bucket Shard 0  │       │ BucketShard 1   │       │ Bucket Shard 2  │
         │ (Hot: STANDARD) │       │ (Warm: STD_IA)  │       │ (Cold: GLACIER) │
         ├─────────────────┤       ├─────────────────┤       ├─────────────────┤
         │ chunks/0a/1b/.. │       │ chunks/4c/2d/.. │       │ chunks/9e/8f/.. │
         └────────┬────────┘       └────────┬────────┘       └────────┬────────┘
                  │                         │                         │
                  └─────────────────────────┼─────────────────────────┘
                                            ▼
                               ┌─────────────────────────┐
                               │ GlacierRestoreCoord     │
                               ├─────────────────────────┤
                               │ • POST ?restore         │
                               │ • x-amz-restore polling │
                               │ • Restored Read-Through │
                               └─────────────────────────┘
```

### 4.1 Prefix Partition Strategies

| Strategy | Path Pattern | Partitions | Max Theory PUTs/sec |
|---|---|---|---|
| `Flat` | `chunks/<hash>` | 1 | 3,500 |
| `HexTwoLevel` | `chunks/aa/bb/<hash>` | 65,536 | 229,376,000 |
| `HexThreeLevel` | `chunks/aa/bb/cc/<hash>` | 16,777,216 | 58,720,256,000 |
| `ShardPrefixed` | `<shard_id>/chunks/aa/bb/<hash>` | 65,536 per shard | $N \times 229,376,000$ |

### 4.2 Cold Archive Restoration State Machine

```
              ┌────────────────────────┐
              │  ArchivedNotRestored   │
              └───────────┬────────────┘
                          │ POST ?restore (Days, Tier)
                          ▼
              ┌────────────────────────┐
              │       Restoring        │ (ongoing-request="true")
              └───────────┬────────────┘
                          │ Polling / Completion
                          ▼
              ┌────────────────────────┐
              │        Restored        │ (ongoing-request="false", expiry-date)
              └────────────────────────┘
```

---

## 5. Implementation Summary

1. **`crates/velcrux-core/src/storage/sharding.rs`**:
   - `S3StorageClass`: Full storage class taxonomy with `is_cold_archive()` and `requires_restore()` predicates.
   - `BucketShard`: Multi-bucket shard metadata descriptor with region, endpoint, prefix, and default storage class.
   - `PrefixPartitionStrategy`: Configurable prefix fanout strategies (`HexTwoLevel` with 65,536 partitions).
   - `ShardRouter`: Consistent hash ring with virtual nodes (vnodes), key formatting, and Shannon entropy analysis.
   - `GlacierRestoreCoordinator`: Orchestrator managing `POST ?restore` request construction and `x-amz-restore` header tracking.
   - `ShardedLifecycleEngine` & `ShardedLifecycleRule`: Rule evaluation engine for automated age- and size-based tier migrations.
   - `ShardedChunkStore`: Distributed implementation of `ChunkStore` across multi-bucket topologies.
2. **`crates/velcrux-core/src/storage/s3.rs`**:
   - Added `put_object_with_storage_class` supporting `x-amz-storage-class`.
   - Added `restore_object` executing signed `POST ?restore` requests.
   - Added `x-amz-restore` and `x-amz-storage-class` header parsing to `head_object`.
   - Added `InvalidObjectState` (403) handling to `get_object` for unrestored cold objects.
3. **`crates/velcrux-core/src/storage/cloud_wire_mock.rs`**:
   - Added storage class tracking and `POST ?restore` handling to the live TCP wire mock server.
   - Verified that cold archive objects reject unrestored GETs with HTTP 403 `InvalidObjectState`.
4. **`crates/velcrux-client/src/main.rs`**:
   - Added `velcrux s3 restore <url> [--days <N>] [--tier <tier>]` CLI command.
   - Added storage class and restore status inspection to `velcrux s3 stat`.
5. **`crates/velcrux-core/tests/storage_sharding_tests.rs`**:
   - 5 comprehensive integration tests covering consistent hash routing, hex prefix fanout, live multi-bucket TCP wire storage, Glacier restore state machine, and lifecycle engine sweeps.

---

## 6. Consequences and Validation

### Positive
- Horizontal throughput scales linearly with the number of bucket shards.
- S3 per-prefix partition limits (3,500 PUT/s) are bypassed via 65,536 prefix fanouts (`HexTwoLevel`).
- Cold compliance data can be archived to Glacier Deep Archive with automated restore orchestration.
- 100% pure safe Rust with zero external C dependencies.

### Negative
- Multi-bucket topology requires careful configuration of bucket names and endpoints in the router.
- Consistent hashing ring migration requires a small fraction ($1/N$) of chunk movement when adding shards.

### Validation
- `cargo test --test storage_sharding_tests`: 5/5 integration tests passing.
- `cargo test -p velcrux-core storage`: 85/85 tests passing.
- `cargo clippy --workspace --all-targets -- -D clippy::correctness`: Clean exit code 0.
- `cargo fmt --all -- --check`: Clean formatting across the entire workspace.
