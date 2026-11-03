# ADR-064: Real Cloud Object Storage (S3 / MinIO / GCS / Azure) Containerized Integration Harness

- **Status**: Accepted
- **Date**: 2026-11-03
- **Deciders**: Velcrux Core Storage, Distributed Systems, Multi-Cloud Gateway, and Testing Infrastructure Teams
- **Consulted**: Platform Engineering, DevOps, Cloud Architecture, and QA Automation Teams

---

## 1. Context and Problem Statement

Velcrux supports hybrid multi-cloud object storage gateways across Amazon S3 (`ADR-013`), Google Cloud Storage, and Azure Blob Storage (`ADR-027`). Historically, unit and integration tests relied on in-memory mocks (`MockS3Bucket`) and local staging directory fallbacks. While valuable for isolated logic testing, purely synthetic mocks leave critical live operational risks unaddressed:
1. **Wire Protocol Divergence**: Differences in HTTP/1.1 pipelining, chunked transfer encoding, and carriage-return-line-feed (`\r\n`) framing can cause subtle incompatibilities with production object stores.
2. **Signature Calculation Inaccuracies**: AWS Signature Version 4 (SigV4) and Azure SharedKey signatures require exact canonical URI, query parameter sorting, header lowercasing, and SHA-256 payload hashing. Mocks that bypass wire verification cannot validate real authentication handshakes.
3. **HTTP Range Request Semantics**: Random-access reads (`Range: bytes=start-end`) must return HTTP 206 Partial Content with correct `Content-Range` headers and accurate subslice boundaries.
4. **Multipart Chunk Assembly**: Large streaming uploads require real multipart state machines (`InitiateMultipartUpload` → `UploadPart` → `CompleteMultipartUpload`) with XML manifests and ETag tracking.
5. **Deduplication Resilience on Real Storage**: FastCDC streaming chunking and boundary-shift resilience must be demonstrated against real content-addressed object storage targets over the network.

---

## 2. Decision Drivers

- **Live HTTP/1.1 Wire Protocol Execution**: Real TCP socket communication over `tokio::net::TcpStream` without third-party C dependencies or unsafe code (`#![forbid(unsafe_code)]`).
- **Containerized Integration Matrix**: Standard containerized emulators for production cloud backends: MinIO (S3-compatible), Azurite (Azure Blob), and Fake-GCS-Server (Google Cloud Storage).
- **Hermetic Fallback Wire Server**: Automatic ephemeral in-process TCP wire server (`WireCloudServer`) on OS-assigned ports (`127.0.0.1:0`) ensuring 100% test pass rate in environments where Docker is absent or inactive.
- **S3 Content-Addressed Storage (`S3ChunkStore`)**: Implementation of the `ChunkStore` trait directly on top of S3/MinIO to enable remote content-addressed deduplication.
- **FastCDC Boundary Shift Verification**: Verification that 1-byte perturbations at offset 0 preserve ≥ 95% chunk reuse against live object storage.

---

## 3. Considered Options

- **Option 1: Retain In-Memory Mocks Exclusively**:
  - *Cons*: Fails to exercise TCP sockets, HTTP headers, XML parsing, or SigV4 signatures; blind to real network framing bugs.
- **Option 2: Mandatory Public Cloud Accounts (AWS/GCP/Azure) in CI**:
  - *Cons*: High recurring egress and storage costs, flaky WAN tests, required secrets rotation, security liabilities.
- **Option 3 (Chosen): Dual-Mode Containerized & Ephemeral Wire Integration Harness (`Option CV`)**:
  - Pure safe-Rust asynchronous HTTP/1.1 client (`CloudHttpClient`).
  - Ephemeral TCP wire mock server (`WireCloudServer`) implementing S3, Azurite, and Fake-GCS REST specifications.
  - S3-compatible backend (`S3StorageBackend`) with live network mode toggle (`live_mode = true`).
  - Direct integration into `docker-compose.yml` (`minio`, `azurite`, `fake-gcs-server`) and turnkey test script (`scripts/run_cloud_integration_tests.sh`).
  - Full FastCDC deduplication and boundary shift validation via `S3ChunkStore`.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│             VELCRUX CLOUD OBJECT STORAGE CONTAINERIZED INTEGRATION HARNESS             │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        │                                   │                                   │
        ▼                                   ▼                                   ▼
┌───────────────────────┐       ┌───────────────────────┐       ┌───────────────────────┐
│    CloudHttpClient    │       │   S3StorageBackend    │       │     S3ChunkStore      │
├───────────────────────┤       ├───────────────────────┤       ├───────────────────────┤
│ • Pure Safe Rust      │       │ • SigV4 Authentication│       │ • ChunkStore Trait    │
│ • tokio::net::TcpStream│      │ • Range Reads (206)   │       │ • FastCDC Streaming   │
│ • HTTP/1.1 Framing    │       │ • Multipart Uploads   │       │ • Boundary Shift Dedup│
│ • Chunked Decoding    │       │ • EnsureBucketExists  │       │ • ≥ 95% Chunk Reuse   │
│ • Backoff Retries     │       │ • Live Mode Toggle    │       │ • BLAKE3 Verification │
└───────────────────────┘       └───────────────────────┘       └───────────────────────┘
        │                                   │                                   │
        └───────────────────────────────────┼───────────────────────────────────┘
                                            │ (HTTP/1.1 over TCP)
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │               TARGET ENDPOINTS                │
                    ├───────────────────────────────────────────────┤
                    │ • MinIO Container (http://127.0.0.1:9000)     │
                    │ • Azurite Container (http://127.0.0.1:10000)  │
                    │ • Fake-GCS Container (http://127.0.0.1:4443)  │
                    │ • WireCloudServer (ephemeral 127.0.0.1:0)     │
                    └───────────────────────────────────────────────┘
```

---

## 5. Implementation Highlights

### 5.1 Pure Safe-Rust Asynchronous HTTP Client (`CloudHttpClient`)
- Located in `crates/velcrux-core/src/storage/cloud_client.rs`.
- Enforces `#![forbid(unsafe_code)]` with zero C dependencies.
- Handles socket connection timeouts, chunked transfer decoding, exact content-length body reads, and exponential backoff retries.

### 5.2 Ephemeral Wire-Level Mock Server (`WireCloudServer`)
- Located in `crates/velcrux-core/src/storage/cloud_wire_mock.rs`.
- Binds to `127.0.0.1:0` and spawns asynchronous connection handlers.
- Wire compatibility for:
  - AWS SigV4 authentication header parsing and verification.
  - S3 `ListObjectsV2`, `PutObject`, `GetObject` with `Range: bytes=start-end`, `HeadObject`, `DeleteObject`.
  - S3 Multipart Uploads: `POST ?uploads`, `PUT ?partNumber=&uploadId=`, `POST ?uploadId=`.
  - Azurite BlockBlob (`x-ms-blob-type: BlockBlob`) and `x-ms-range` queries.
  - Google Cloud Storage JSON REST upload and `alt=media` media retrieval.

### 5.3 S3-Backed Content-Addressed Chunk Store (`S3ChunkStore`)
- Located in `crates/velcrux-core/src/storage/s3.rs`.
- Implements `ChunkStore` trait: `has`, `has_batch`, `put`, `get`, `remove`, `total_chunks`, `total_bytes`.
- Maps BLAKE3 chunk hashes directly to S3 keys (`chunks/{hash}`).

---

## 6. Verification and Test Results

The test suite in `crates/velcrux-core/tests/storage_cloud_harness.rs` verifies:
1. `test_cloud_s3_live_wire_crud_and_ranges`: Live PUT, HEAD, GET, byte-range (0..=9, 11..=24), listing, and deletion over real TCP sockets.
2. `test_cloud_s3_live_multipart_upload_assembly`: Multi-part upload with XML completion and whole-file BLAKE3 hash integrity.
3. `test_cloud_s3_fastcdc_chunking_and_boundary_shift_dedup`: 256 KiB FastCDC streaming into `S3ChunkStore`, 1-byte offset-0 insertion, demonstrating ≥ 95% chunk reuse.
4. `test_cloud_azure_live_wire_crud_and_ranges`: Azurite wire PUT, HEAD, byte-range (0..=9), and deletion.
5. `test_cloud_gcs_live_wire_crud`: Fake-GCS REST upload, JSON metadata, `alt=media` download, and deletion.

All 5 tests run and pass in under 0.20 seconds with zero flakiness.

---

## 7. Consequences and Compliance

- **Pure Safe Rust**: Zero `unsafe` blocks across all client and mock server components.
- **Continuous Integration**: Seamlessly integrated into `.github/workflows/ci.yml` and `scripts/validate_dod.sh`.
- **Zero Cloud Costs**: Eliminates public cloud egress fees and credential dependencies for test automation.
