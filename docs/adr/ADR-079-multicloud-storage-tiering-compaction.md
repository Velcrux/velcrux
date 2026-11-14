# ADR-079: Autonomous Multi-Cloud Object Storage Tiering & Lifecycle Compaction Engine

- **Status**: Accepted
- **Date**: 2026-11-14
- **Deciders**: Velcrux Distributed Systems, Cloud Architecture, Storage Systems, and FinOps Engineering Teams
- **Consulted**: High-Performance Storage, SRE, Network Protocols, and Security Teams

---

## 1. Context and Problem Statement

When deploying large-scale bulk data transfer, content-defined deduplication (FastCDC), and backup synchronization across multi-cloud environments (Amazon S3, Google Cloud Storage, Microsoft Azure Blob Storage, and on-premise NVMe caches), systems face severe cost and architectural challenges:

1. **The Small-Object API Cost Multiplier**:
   Content-defined chunking splits files into fine-grained variable chunks (~64 KiB) for deduplication. Uploading billions of individual 64 KiB chunks directly to cloud object storage incurs staggering API costs. In AWS S3, `PUT` requests cost \$0.005 per 1,000 requests (\$5,000 per 1 billion chunks). Furthermore, cloud providers enforce minimum billable object sizes in archival tiers (e.g., 128 KiB in S3 Standard-IA / Glacier, 64 KiB in Azure Cool), inflating storage costs by 200–400% for small chunks.
2. **Metadata & Listing Bottlenecks**:
   Storing individual chunks directly creates billions of cloud objects, leading to slow pagination, rate-limiting (`429 Too Many Requests`), and high request latency when traversing remote datasets.
3. **Fragmented Cloud Storage Classes**:
   Each hyperscaler implements distinct storage classes with different latency characteristics, minimum retention policies, and retrieval pricing models:
   - AWS S3: `STANDARD`, `STANDARD_IA`, `GLACIER_FLEXIBLE`, `DEEP_ARCHIVE`.
   - Google Cloud Storage: `STANDARD`, `NEARLINE`, `COLDLINE`, `ARCHIVE`.
   - Azure Blob: `Hot`, `Cool`, `Cold`, `Archive`.
   Synchronizing data without a unified tiering abstraction requires brittle, cloud-specific scripts.
4. **Asynchronous Archive Retrieval (Hydration)**:
   Accessing cold and deep archive objects requires asynchronous restoration workflows (e.g., S3 `RestoreObject`, Azure `SetBlobTier(Hot)`). A naive storage layer blocks on archival reads, causing client connection timeouts and application stalls.
5. **Garbage Collection & Tombstone Re-packing**:
   When files are updated or superseded, individual chunks become obsolete. Without container-level compaction, cloud storage accumulates dead space that continues to accrue monthly storage fees.

To solve these challenges, Velcrux implements the **Autonomous Multi-Cloud Object Storage Tiering & Lifecycle Compaction Engine** in 100% pure safe Rust.

---

## 2. Decision Drivers

- **Compacted Cloud Container Architecture (`VLXT`)**:
  - Aggregates thousands of small FastCDC chunks into large, contiguous, 64–128 MiB cloud-optimized containers.
  - Reduces cloud `PUT` request costs by up to $1000\times$.
  - Binary container layout:
    - 4 KiB fixed Header prefix (`VLXT` magic `0x564C5854`, version, container ID, provider, tier, compression codec).
    - Concatenated chunk payloads (Zstandard or raw).
    - Serialized Chunk Index Table mapping 32-byte BLAKE3 hashes to payload offsets, compressed lengths, uncompressed sizes, and CRC32C checksums.
    - 16-byte Container Trailer.
- **Transparent Random-Access Byte-Range Reads (`Range: bytes=start-end`)**:
  - Allows immediate retrieval of individual 64 KiB chunks from 64 MiB containers without downloading the full container.
  - Calculates exact byte ranges and verifies CRC32C and BLAKE3 hashes on every read.
- **Declarative Lifecycle Policy Automation (`CloudLifecycleRule`)**:
  - Evaluates container age and heat-map metrics.
  - Automatically transitions containers across tiers:
    $$\text{Hot (Standard)} \xrightarrow{30\text{ days}} \text{Cool (Infrequent)} \xrightarrow{90\text{ days}} \text{Cold (Glacier)} \xrightarrow{365\text{ days}} \text{DeepArchive} \xrightarrow{730\text{ days}} \text{Expire}$$
  - Tenant and prefix filtering (`logs/`, `backups/`, `tenant-fin`).
- **Tombstone Garbage Collection & Auto-Compaction**:
  - Tracks container fragmentation ratio $\frac{\text{tombstoned\_bytes}}{\text{total\_bytes}}$.
  - When dead space exceeds threshold (default: 30%), triggers `compact_and_repack`, uploading a clean, densely packed container and deleting the fragmented container.
- **Asynchronous Cloud Archive Hydration Pipeline (`CloudHydrationPipeline`)**:
  - Non-blocking restoration workflow for Cold and DeepArchive tiers.
  - Supports `Expedited` (1–5 min), `Standard` (3–5 hours), and `Bulk` (12–48 hours) retrieval priorities.
  - Temporary 7-day hot cache with auto-expiry.
- **Unified Multi-Cloud Addressing**:
  - Universal URI scheme: `s3://bucket/key`, `gcs://bucket/key`, `azblob://container/blob`, `file:///path`.
- **Zero Unsafe Code**: 100% `#![forbid(unsafe_code)]` compliance with zero external C dependencies.

---

## 3. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              VELCRUX CLUSTER INGESTION                                 │
│                                                                                        │
│   FastCDC Streaming Chunker (64 KiB Variable Chunks)                                   │
│   BLAKE3 Content-Addressing -> Unique Hashes (H1, H2, H3, ... Hn)                      │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                   STAGE CONTAINER ACCUMULATOR (Target: 64 MiB)                         │
│                                                                                        │
│   [Chunk 1] [Chunk 2] [Chunk 3] ... [Chunk N]  ->  Compress (Zstandard Level 3)        │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Container Flush & Seal
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│             COMPACTED CONTAINER FILE FORMAT (VLXT - 0x564C5854)                        │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │ 0x0000: Container Header (4096-byte Padded: ID, Magic, Tier, Codec, Blake3)    │   │
│   ├────────────────────────────────────────────────────────────────────────────────┤   │
│   │ 0x1000: Concatenated Chunk Payloads [Chunk 0][Chunk 1][Chunk 2]...[Chunk N]    │   │
│   ├────────────────────────────────────────────────────────────────────────────────┤   │
│   │ Index Offset: Index Table JSON ([Hash, Offset, CompLen, OrigLen, CRC32C])      │   │
│   ├────────────────────────────────────────────────────────────────────────────────┤   │
│   │ Trailer (16 Bytes): [Index Start: u64, Index Len: u32, Magic: 0x564C5854]      │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Single S3/GCS/Azure PUT Request
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          MULTI-CLOUD STORAGE ENDPOINTS                                 │
│                                                                                        │
│     Amazon S3 Bucket             Google Cloud Storage           Azure Blob Storage     │
│   ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐   │
│   │ Standard (Hot)   │           │ Standard (Hot)   │           │ Hot              │   │
│   │ Standard-IA(Cool)│           │ Nearline (Cool)  │           │ Cool             │   │
│   │ Glacier (Cold)   │           │ Coldline (Cold)  │           │ Cold             │   │
│   │ Deep Archive     │           │ Archive          │           │ Archive          │   │
│   └──────────────────┘           └──────────────────┘           └──────────────────┘   │
└───────────────────────┬──────────────────────────────────────┬─────────────────────────┘
                        │                                      │
        Random-Access Range GET                                Cold Tier Hydration
        (Range: bytes=4096..69632)                             (S3 RestoreObject / Expedited)
                        │                                      │
                        ▼                                      ▼
┌──────────────────────────────────────────────────┐ ┌───────────────────────────────────┐
│     DIRECT BYTE-RANGE RETRIEVAL (< 20 ms)        │ │  ASYNC HYDRATION PIPELINE CACHE   │
│     - Decompress slice                           │ │  - Expedited / Standard / Bulk    │
│     - Validate CRC32C + BLAKE3                   │ │  - 7-Day Temporary Hot Cache      │
└──────────────────────────────────────────────────┘ └───────────────────────────────────┘
```

---

## 4. Operator CLI Suite

The engine provides operator CLI tooling under `velcrux cloud-tier`:

```bash
# 1. Inspect multi-cloud storage tiering state, endpoints, containers, and costs
velcrux cloud-tier status
velcrux cloud-tier status --json

# 2. Flush staging container and trigger compaction / repacking
velcrux cloud-tier compact --target-tier cool --container-size-mb 64
velcrux cloud-tier compact --target-tier hot --json

# 3. Transparently read a chunk across the multi-cloud mesh
velcrux cloud-tier read --chunk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
velcrux cloud-tier read --chunk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --json

# 4. Initiate or check asynchronous cloud archive restoration
velcrux cloud-tier hydrate --chunk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --retrieval-tier expedited
velcrux cloud-tier hydrate --chunk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --retrieval-tier expedited --json

# 5. Benchmark container compaction, compression, and range-read IOPS
velcrux cloud-tier benchmark --chunks 200
velcrux cloud-tier benchmark --chunks 500 --json
```

---

## 5. Verification and Test Matrix

The engine is validated with unit and integration test suites:

1. **Unit Tests** (`crates/velcrux-core/src/cloud_tier/`):
   - `test_cloud_provider_and_tier_string_mappings`: Validates provider and storage class translations.
   - `test_crc32c_deterministic`: Verifies standard IEEE 802.3 CRC32C checksum vector.
   - `test_lifecycle_rule_transitions`: Validates age triggers, prefix filters, and fragmentation thresholds.
   - `test_cloud_storage_uri_parsing`: Validates `s3://`, `gcs://`, `azblob://`, and `file://` schemes.
   - `test_endpoint_range_get_and_metrics`: Verifies byte-range slicing and cost modeling.
   - `test_hydration_pipeline_lifecycle`: Tests `Pending` -> `Hydrating` -> `Hydrated` -> `Expired` transitions.
   - `test_container_pack_read_and_serialize_roundtrip`: Verifies 4 KiB padded header, payload, index, and trailer serialization.
   - `test_container_range_calculation_and_tombstone_repack`: Tests tombstoning, dead space reclamation, and repacking.
   - `test_engine_ingest_flush_and_transparent_read`: Verifies end-to-end ingest -> flush -> range read -> hydration -> cache.
2. **Core Integration Tests** (`crates/velcrux-core/tests/tiering_lifecycle_tests.rs`):
   - `test_multi_cloud_container_compaction_and_range_reads`: 50 chunks packed and random-accessed.
   - `test_autonomous_lifecycle_tiering_transitions`: Simulates 45d, 120d, 400d, and 800d transitions.
   - `test_tombstone_garbage_collection_compaction`: Verifies 40% fragmentation triggers repacking.
   - `test_cold_archive_async_hydration_workflow`: Expedited hydration lifecycle validation.
   - `test_cloud_cost_and_metrics_accounting`: Cost and transfer volume tracking.
3. **CLI Integration Tests** (`crates/velcrux-client/tests/cli_cloud_tier.rs`):
   - `test_cli_cloud_tier_status_text_and_json`
   - `test_cli_cloud_tier_compact_text_and_json`
   - `test_cli_cloud_tier_read_and_hydrate`
   - `test_cli_cloud_tier_benchmark_text_and_json`

---

## 6. Consequences & Operational Benefits

### Positive
- **1000x Reduction in S3 PUT API Requests**: Aggregating chunks into 64 MiB containers saves up to \$5,000 per petabyte ingested.
- **Fast Random-Access Retrieval**: Byte-range GETs allow fetching single 64 KiB chunks with low network overhead.
- **Automated Lifecycle Cost Optimization**: Seamless migration down to Deep Archive reduces long-term storage fees by up to 95%.
- **Zero Double-Buffering**: Pure safe Rust Zstandard and CRC32C streaming pipeline.
- **Resilient Cold Hydration**: Prevents client read timeouts on cold archive storage.
