# ADR-027: Native Multi-Cloud Object Storage Backends: Google Cloud Storage (GCS) and Azure Blob Storage

Status: Accepted · Date: 2026-10-14

## Context

Following the implementation of S3-compatible cloud storage gateways (`ADR-013`), production enterprise deployments frequently require native multi-cloud synchronization across Google Cloud Platform (Google Cloud Storage) and Microsoft Azure (Azure Blob Storage).

Key requirements:
1. **Multi-Cloud URL Abstraction**: Seamless support for `gs://<bucket>/<key>`, `az://<container>/<blob>`, and `azure://<container>/<blob>` URLs alongside existing `s3://` and `velcrux://` endpoints.
2. **Zero-SDK & Pure-Rust Architecture**: Avoid heavy vendor cloud SDKs (`google-cloud-storage`, `azure_storage_blobs`), C-bindings, or external CLI tools (`gsutil`, `azcopy`). Maintain strict `#![forbid(unsafe_code)]` compliance across all crates.
3. **Resumable & Chunked Upload Semantics**: Support GCS Resumable Upload sessions (`initiate_resumable_upload` -> `upload_resumable_chunk`) and Azure Block Blob staging (`Put Block` -> `Put Block List`).
4. **BLAKE3 Cryptographic Metadata**: Retain custom BLAKE3 object checksums (`x-goog-meta-blake3` and `x-ms-meta-blake3`), permissions (`x-*-meta-mode`), and modification times (`x-*-meta-mtime`).
5. **Streaming Range Reads**: Provide byte-range random access (`Range: bytes=start-end` and `x-ms-range: bytes=start-end`) for random-read engines and delta reconstructions.
6. **Hermetic CI Mock Engines**: Deterministic, credential-free testing in unit and integration test pipelines without external cloud credentials.

## Options Considered

1. **Vendor Official SDKs (`google-cloud-storage` & `azure_storage_blobs`)**:
   - Integrate vendor Rust SDKs.
   - *Rejected*: Adds hundreds of transitive dependencies, compiles with unbounded dependencies, increases build times drastically, and introduces potential unsafe blocks that violate workspace `#![forbid(unsafe_code)]`.
2. **External Tool Execution (`gsutil` / `azcopy` / `rclone`)**:
   - Shell out to host-installed CLI utilities.
   - *Rejected*: Host dependencies cannot be assumed in minimal containers or embedded devices, and external processes cannot implement `StorageBackend` trait in `velcrux-core`.
3. **Native Pure-Rust GCS and Azure Gateway Engines**:
   - Implement `GcsStorageBackend` and `AzureBlobStorageBackend` natively inside `velcrux-core::storage`.
   - Implement `AzureSharedKeySigner` using `ring::hmac` and pure-Rust Base64 encoding.
   - Expose dedicated CLI subcommands (`velcrux gcs` and `velcrux azure`) with automatic routing in `velcrux upload`, `velcrux download`, and `velcrux sync`.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Google Cloud Storage Engine (`crates/velcrux-core/src/storage/gcs.rs`)
- **Configuration (`GcsConfig`)**: Environment variable detection (`GOOGLE_APPLICATION_CREDENTIALS`, `STORAGE_EMULATOR_HOST`, `GCS_ENDPOINT`, `GCS_ACCESS_TOKEN`), configurable endpoints, chunk sizes, and prefix routing.
- **URL Handling**: Parses `gs://<bucket>/<object_path>` into bucket and key prefixes.
- **Resumable Sessions**: Implements chunked session uploads with generation tracking and byte offset verification.
- **Range Queries**: Supports streaming HTTP range queries for arbitrary offset reading.
- **Directory Sync**: Implements `sync_from_local` and `sync_to_local` with bidirectional BLAKE3 hash validation.

### 2. Azure Blob Storage Engine (`crates/velcrux-core/src/storage/azure.rs`)
- **Configuration (`AzureBlobConfig`)**: Resolves account name, key, container, and SAS tokens from environment (`AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_KEY`, `AZURE_STORAGE_SAS_TOKEN`, `AZURE_STORAGE_ENDPOINT`).
- **URL Handling**: Parses `az://<container>/<blob>`, `azure://<container>/<blob>`, and Azure Blob HTTPS URLs.
- **SharedKey Authentication (`AzureSharedKeySigner`)**: Signs CanonicalizedHeaders and CanonicalizedResource using pure-Rust HMAC-SHA256 and base64.
- **Block Blob Staging**: Multi-block chunking via `Put Block` and transactional commit via `Put Block List`.
- **Directory Sync**: Implements `sync_from_local` and `sync_to_local` with bidirectional BLAKE3 verification.

### 3. Trait Unification (`StorageBackend`)
Both `GcsStorageBackend` and `AzureBlobStorageBackend` implement the core `StorageBackend` trait:
- `stat` -> maps object metadata to `FileMeta`.
- `open_read` -> provides `Box<dyn AsyncRandomRead>` over byte ranges.
- `open_staging` & `commit` -> stages partial files and commits to cloud storage.
- `list_dir` -> navigates hierarchical prefixes using `/` delimiters.

### 4. CLI Subcommands & Pipeline Routing (`velcrux-client`)
- `velcrux gcs <ls|stat|put|get|delete|sync>`
- `velcrux azure <ls|stat|put|get|delete|sync>`
- Transparent pipeline routing: `velcrux upload`, `velcrux download`, and `velcrux sync` automatically detect `gs://`, `az://`, or `azure://` URLs and execute the appropriate multi-cloud handler.

## Consequences

- **Positive**: Complete multi-cloud parity across AWS S3, Google Cloud Storage, and Microsoft Azure Blob Storage without external tools or cloud SDKs.
- **Positive**: 100% `#![forbid(unsafe_code)]` compliance preserved across the entire workspace.
- **Positive**: Deterministic hermetic mock testing in local and CI environments.
