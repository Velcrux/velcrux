# ADR-013: S3-Compatible Cloud Object Storage Gateway Backend

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §42 ("S3 Compatibility") and §43 ("Object Storage Gateway"), modern enterprise data transfer workflows frequently require bridging local NVMe filesystems and on-premises storage clusters with cloud object storage (AWS S3, MinIO, Cloudflare R2, Ceph, Wasabi).

Core challenges include:
1. **Hierarchical vs Flat Namespaces**: Local filesystems rely on nested POSIX directories, symlinks, and permissions, whereas S3 provides flat key-value object namespaces where "directories" are prefix conventions.
2. **Authentication Security & Dependency Footprint**: AWS Signature Version 4 (SigV4) HMAC-SHA256 request signing is mandatory across all S3-compatible providers. However, pulling in official cloud SDKs introduces hundreds of transitive crates, lengthy build times, and potential unsafe code.
3. **Large Object Handling**: Objects exceeding standard HTTP payload sizes must be uploaded in streaming multipart parts (5 MiB to 5 GiB per part).
4. **Content-Addressing Integrity**: S3 ETags typically reflect MD5 checksums or multipart hashes, while Velcrux standardizes on BLAKE3 hashes. The gateway must record and preserve BLAKE3 integrity metadata across cloud transfers.
5. **Bi-directional Synchronization**: Operators need seamless sync between local directories and cloud prefixes without data corruption or redundant transfers.

## Options Considered

1. **Full AWS SDK Integration (`aws-sdk-s3`)**:
   - Integrate the official AWS Rust SDK.
   - *Rejected*: Adds dozens of crates (`aws-config`, `aws-types`, `hyper`, `aws-smithy-*`), drastically increasing compile times and binary sizes while conflicting with Velcrux's `#![forbid(unsafe_code)]` zero-dependency philosophy.
2. **External CLI Delegation (`aws-cli` / `rclone`)**:
   - Shell out to external binaries installed on the host.
   - *Rejected*: Unreliable in containerized, minimal Alpine/Debian, or embedded environments; cannot be embedded in `velcrux-core` as a reusable library backend.
3. **Pure-Rust S3 Gateway Engine using Workspace Cryptography**:
   - Implement pure-Rust AWS SigV4 signing using workspace crates (`ring::hmac` and `sha2::Sha256`).
   - Implement `S3StorageBackend` fulfilling the `StorageBackend` trait (`AsyncRandomRead`, CRUD, directory scanning, and byte-range queries).
   - Integrate multipart upload chunking, BLAKE3 metadata tracking, and bi-directional directory sync (`sync_from_local`, `sync_to_local`).
   - Expose dedicated CLI subcommands (`velcrux s3 <ls|stat|put|get|delete|sync>`) with automatic top-level `velcrux sync` delegation when `s3://` URLs are detected.

## Decision

Option 3. Velcrux implements a native, pure-Rust S3-compatible storage backend and CLI gateway with `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. URL Resolution & Configuration (`S3Config`)
- Standard URLs of the form `s3://bucket/key/path` or `s3://bucket/prefix/` are validated and parsed.
- Credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), region (`AWS_REGION`), and custom endpoints (`AWS_ENDPOINT_URL_S3` / `AWS_ENDPOINT_URL`) are resolved with fallbacks.
- Path-style (`https://endpoint/bucket/key`) and virtual-hosted addressing (`https://bucket.endpoint/key`) are configurable.

### 2. Pure-Rust SigV4 Signer (`SigV4Signer`)
- Computes canonical request strings:
  ```text
  CanonicalRequest =
    HTTPRequestMethod + '\n' +
    CanonicalURI + '\n' +
    CanonicalQueryString + '\n' +
    CanonicalHeaders + '\n' +
    SignedHeaders + '\n' +
    HashedPayload
  ```
- Generates the date-scoped HMAC-SHA256 signing key chain:
  `kSecret` → `kDate` → `kRegion` → `kService` → `kSigning`.
- Formats canonical `Authorization` header without third-party dependencies.

### 3. S3 Storage Backend (`S3StorageBackend`)
- **CRUD Operations**: `put_object`, `get_object`, `head_object`, `delete_object`.
- **Random Range Reads**: Implements `get_object_range` supporting `Range: bytes=start-end` for delta synchronizations and chunk extractions.
- **Multipart Upload Pipeline**: `initiate_multipart_upload`, `upload_part`, `complete_multipart_upload`, and `abort_multipart_upload`. Objects exceeding `part_size_bytes` (default: 8 MiB) are chunked and assembled into a combined ETag.
- **BLAKE3 Metadata**: Automatically persists BLAKE3 hashes in object metadata, facilitating instantaneous cache invalidation and change detection.
- **Bi-directional Sync**:
  - `sync_from_local(path, prefix)`: Scans local directory, uploads changed or new files, reusing objects whose size and BLAKE3 hash match.
  - `sync_to_local(prefix, path)`: Lists cloud prefix objects and downloads changed or missing files to local filesystem.

### 4. CLI Ergonomics
- Top-level `velcrux s3`:
  - `velcrux s3 ls s3://bucket/prefix/ [--delimiter /]`
  - `velcrux s3 stat s3://bucket/key`
  - `velcrux s3 put local_file s3://bucket/key [--multipart-size <bytes>]`
  - `velcrux s3 get s3://bucket/key local_file [--range-start <N>] [--range-end <M>]`
  - `velcrux s3 delete s3://bucket/key`
  - `velcrux s3 sync <source> <destination>`
- Seamless integration with top-level `velcrux sync`:
  - Passing `velcrux sync ./data s3://bucket/data` or `velcrux sync s3://bucket/data ./data` automatically delegates to the S3 gateway.

## Consequences

- **Positive**:
  - 100% pure Rust without external C dependencies or bulky SDKs.
  - Full compatibility with AWS S3, MinIO, Cloudflare R2, Ceph, and Wasabi.
  - Hermetic testing and offline staging resilience.
  - Direct integration into Velcrux's streaming and delta-sync pipelines.
- **Negative**:
  - Advanced proprietary AWS-only features (e.g. S3 Object Lambda, KMS client-side envelope decryption) must be handled through standard server-side headers.
