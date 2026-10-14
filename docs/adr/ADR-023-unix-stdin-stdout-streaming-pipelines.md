# ADR-023: Unix Stdin/Stdout Streaming Pipelines

Status: Accepted · Date: 2026-10-13

## Problem

In UNIX-centric production deployments, cloud environments, and CI/CD pipelines, high-throughput workflows frequently process dynamic data generated on-the-fly rather than reading and writing static files from disk:
1. **Intermediate Disk Bottlenecks**: Commands such as `tar cf - /var/log | velcrux upload - ...` or `mysqldump ... | velcrux upload - ...` generate continuous data streams that should be transmitted over the network immediately without forcing multi-gigabyte or multi-terabyte files to be staged on local disk before transmission.
2. **Pipelines to Downstream Consumers**: On the receiving side, downloading archives or disk images (`velcrux download ... - | tar xf -` or `velcrux download ... - | dd of=/dev/nvme0n1 ...`) requires pure binary streaming to standard output without corrupting stdout with status logs, metrics, or ANSI terminal sequences.
3. **Unknown Input Length & Hash Sentinel**: Standard Velcrux upload negotiations require declaring `file_size` and `file_hash` upfront in `TransferCreate` for chunk planning, quota checking, and deduplication. However, pipes and `stdin` have an indeterminate length and an unknown whole-stream BLAKE3 hash until `EOF` is reached.
4. **End-to-End Cryptographic Integrity**: Streaming pipelines must preserve Velcrux's core invariant: 100% cryptographic data integrity. Per-chunk integrity must be maintained on the wire, and whole-stream BLAKE3 verification must occur before any file is atomically committed or finalized.
5. **Log Hygiene & Separation**: All diagnostic, tracing, progress indicators, and audit logging must route strictly to standard error (`stderr`), ensuring standard output (`stdout`) remains 100% byte-pure for Unix pipe chaining.

## Options Considered

1. **Temporary File Spooling**:
   - The CLI spools all `stdin` input to a temporary scratch file in `/tmp`, hashes it, and then invokes standard upload.
   - *Rejected*: Incurs massive write amplification, saturates local SSD/disk I/O, doubles transfer latency, and fails if `/tmp` lacks disk space for massive datasets.
2. **Unchecked Raw TCP/QUIC Streaming Without Integrity Verification**:
   - Stream raw bytes over QUIC without framing, chunk hashing, or verification.
   - *Rejected*: Violates core architectural invariants in `REQUIREMENTS.md` §18 and `SECURITY.md` §2. Truncation or bit errors would go undetected.
3. **Native Unix Stdin/Stdout Streaming Protocol Pipelines (Option BG)**:
   - Streaming sentinel protocol extension: Client transmits `file_size: 0` and `file_hash: Hash::ZERO` in `TransferCreate`.
   - The server recognizes the sentinel, bypasses static FastCDC/Bloom delta calculation, and accepts streaming data frames over a unidirectional QUIC stream.
   - Continuous BLAKE3 incremental hashing: Client and server calculate rolling BLAKE3 digests concurrently as chunks are read and written.
   - Upon `EOF`, client issues `Verify { expected_hash }` on the bidirectional control stream with the computed whole-stream digest.
   - The server verifies `computed == verify.expected_hash` and commits the staged file atomically.
   - On download (`velcrux download <url> -`), server streams frames to client; client validates per-chunk hashes, streams bytes directly to `stdout`, computes rolling BLAKE3, and verifies against server's `VerifyResult`.
   - Strict log hygiene: `tracing_subscriber` and user progress output are routed strictly to `stderr`.
   - Ergonomic CLI support: `-` path argument in `upload` and `download`, plus dedicated aliases `velcrux stream send` and `velcrux stream recv`.

## Decision

Option 3. Velcrux implements native Unix Stdin/Stdout Streaming Pipelines under `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Sentinel Negotiation Pattern

When streaming from an async reader or pipe where total size and hash are unknown:
```
Client                                                 Server
  |                                                      |
  |--- TRANSFER_CREATE(src: "-", dst: "p",               |
  |                    size: 0, hash: Hash::ZERO) ------>|
  |<-- TRANSFER_CREATED(transfer_id: TID) ---------------|
  |<-- TRANSFER_PLAN(bytes_to_transfer: 0) --------------|
  |                                                      |
  |--- TRANSFER_BEGIN(transfer_id: TID, streams: 1) ---->|
  |                                                      |
  |=== (Uni-stream: DATA_PREAMBLE + DATA_FRAMES) =======>|  [Server writes staged file]
  |    Chunks read from stdin, rolling BLAKE3 computed   |  [Calculates rolling hash]
  |    Stream finished with FIN                          |
  |                                                      |
  |--- VERIFY(transfer_id: TID, final_blake3_hash) ----->|
  |<-- VERIFY_RESULT(transfer_id: TID, ok: true, ...) ---|
  |--- COMMIT(transfer_id: TID) ------------------------>|
  |<-- COMMITTED(transfer_id: TID, files: 1) ------------|
```

### 2. Stream Ingest & Download Engine

In `crates/velcrux-core/src/transfer/engine.rs`:
- `client_upload_stdin_stream<R>`: Asynchronously reads chunks up to `chunk_size` (bounded between 4 KiB and 1 MiB) from any `AsyncRead` implementation. Frames are framed with `DATA_FRAME_HEADER`, compressed adaptively if enabled, and transmitted. Computes rolling BLAKE3 hash using `blake3::Hasher`. Upon reader `EOF`, transmits `FIN`, sends `VerifyMsg`, awaits `VerifyResultMsg`, and issues `CommitMsg`.
- `client_download_stdout_stream<W>`: Accepts unidirectional data stream from server, parses preambles and frames, verifies chunk hashes on arrival, decompresses payloads, writes directly to `AsyncWrite` (`stdout`), updates rolling hash, and asserts against server's authoritative `VerifyResult`.
- `server_upload_session_with_limits`: Recognizes `expected_hash == Hash::ZERO`, accepts sequential streaming chunks without skipping, computes staging hash upon data stream completion, verifies against `verify.expected_hash`, updates `FileMeta` with actual on-disk length, and atomically commits the file.

### 3. CLI Integration & Log Hygiene

In `crates/velcrux-client`:
- `upload - <url>` / `download <url> -`: Seamlessly detects `-` as the source or destination path and activates streaming pipeline mode.
- `stream send <url>` / `stream recv <url>`: Dedicated subcommands for pipeline scripting:
  ```bash
  # Send stream
  tar czf - /data | velcrux stream send velcrux://server:4433/backups/data.tar.gz

  # Receive stream
  velcrux stream recv velcrux://server:4433/backups/data.tar.gz | tar xzf - -C /restore
  ```
- All diagnostic and informational output is directed strictly to `stderr`:
  - `eprintln!("transfer_id: {}", id)`
  - `eprintln!("stream download: received {} bytes, hash verified: {}", bytes, hash)`
  - `stdout` carries solely raw binary payload bytes during download, enabling seamless piping into downstream UNIX utilities (`tar`, `gzip`, `dd`, `gpg`, `sqlite3`).

### 4. Verification & Testing

- `crates/velcrux-server/tests/server_streaming_pipelines.rs`: Live QUIC integration test verifying upload from async cursor, download into buffer, and byte-for-byte roundtrip identity against BLAKE3 hashes.
- `crates/velcrux-client/tests/cli_stream.rs`: End-to-end CLI integration test validating piped stdin child process execution, binary stdout purity, and `stream send` / `stream recv` aliases.

## Consequences

- **Positive**:
  - Zero disk write amplification on client machines during streaming uploads.
  - Zero stdout pollution for clean integration into UNIX pipelines and container workflows.
  - End-to-end cryptographic integrity guarantees preserved using rolling BLAKE3 digests and EOF verification commits.
  - 100% compliant with `#![forbid(unsafe_code)]`.
- **Negative / Trade-offs**:
  - Streaming uploads cannot leverage deduplication or delta transfers on the client side since chunk hashes are not known upfront; however, the server can still index the resulting file for future delta downloads.
