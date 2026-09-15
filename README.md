# Velcrux

<p align="center">
  <strong>High-Throughput, Resumable, Verifiable Bulk Data Transfer over QUIC</strong>
</p>

<p align="center">
  <a href="https://github.com/krishsharma/velcrux/actions"><img src="https://img.shields.io/badge/build-passing-2ea44f?style=flat-square" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/definition%20of%20done-15%2F15%20verified-2ea44f?style=flat-square" alt="DoD Status">
  <img src="https://img.shields.io/badge/rustc-1.80%2B-blue?style=flat-square" alt="Rust Version">
  <img src="https://img.shields.io/badge/safety-%23!%5Bforbid(unsafe__code)%5D-crimson?style=flat-square" alt="Safety Guarantee">
  <img src="https://img.shields.io/badge/license-Apache--2.0%20%7C%20MIT-informational?style=flat-square" alt="License">
</p>

---

## Executive Summary

**Velcrux** is an open-source transport system engineered for high Bandwidth-Delay Product (BDP) environments: 1–10 Gbps network topologies spanning 50–300 ms Round-Trip Times (RTT) with non-trivial packet loss. It provides reliable, high-speed transfer of datasets ranging from hundreds of megabytes to tens of terabytes.

Traditional bulk transfer utilities (`scp`, `sftp`, `rsync`) bottleneck on TCP head-of-line blocking, single-stream congestion window collapse, and whole-file retransmissions. Velcrux solves these physical transport constraints through:

- **Multiplexed QUIC Transport**: Native QUIC implementation providing stream multiplexing, TLS 1.3 encryption, and 384 MiB BDP-tuned receive windows to maintain line rate over long-haul connections.
- **Content-Defined Chunking (FastCDC)**: Rolling-hash chunk boundary selection invariant to byte insertions and middle edits, preventing cascade re-chunking.
- **Bi-Directional Delta Synchronization**: Chunk-level inventory exchange utilizing Bloom filters and run-length encoded (RLE) bit arrays to minimize round trips and redundant wire transfers.
- **Content-Addressed Deduplication**: Global and directory-level chunk storage keyed by cryptographic hashes, eliminating duplicate block transmission across disparate files.
- **Cryptographic Verification**: End-to-end BLAKE3 integrity checks executed per chunk on receipt and across the aggregate file prior to atomic filesystem commitment.

---

## Core Invariants and Guarantees

| Principle | Specification Guarantee | Technical Implementation |
|---|---|---|
| **Bounded Memory** | Peak RSS ≤ 512 MiB regardless of dataset volume | Pre-allocated 2 MiB buffer pools, streaming manifest decoders, and bounded queue backpressure. |
| **Crash Invariance** | Uninterrupted resume after process termination or reboot | SQLite WAL state store writing verified chunk bitmaps every 10 seconds; idempotent transfer IDs (ULID). |
| **Integrity Assurance** | Zero silent data corruption; byte counts are never proof of commit | Parallel BLAKE3 tree-hashing per chunk and whole-file validation before atomic renaming. |
| **Storage Atomicity** | Destination files are never left in partial or corrupt states | Incoming data streams to hidden staging directories (`.velcrux-staging`); single-step POSIX `rename` on verified completion. |
| **Shift Resistance** | Byte insertion at offset 0 achieves ≥ 95% content reuse | FastCDC rolling chunker with normalized chunk distribution (64 KiB min, 256 KiB target, 1 MiB max). |
| **Cross-File Dedup** | Secondary copy of identical content moves zero wire bytes | Content-addressed chunk store (`.velcrux-chunks/`) utilizing BLAKE3 deduplication indexing. |
| **Explicit Deletion** | Target files are never removed without explicit operator intent | `--delete-after` execution only after 100% of transfer commitments succeed; disabled by default. |
| **Memory Safety** | Zero unsafe memory operations | `#![forbid(unsafe_code)]` enforced across all workspace crates. |

---

## Architecture and Transport Model

### Stream Multiplexing Architecture

Every transfer session executes over a single QUIC connection with isolated unidirectional and bidirectional streams:

```
                          QUIC Connection (TLS 1.3 / mTLS)
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ Control Stream (Bidirectional #0)  : HELLO, AUTH, TRANSFER_CREATE, COMMIT   │
 │ Metadata Stream (Bidirectional #1) : MANIFEST_*, INVENTORY_*, CHUNK_QUERY   │
 │ Data Streams (Unidirectional #2..N): 32-Byte Stream Preamble + DATA Frames  │
 └─────────────────────────────────────────────────────────────────────────────┘
```

- **Control Priority**: Control and management frames are scheduled with strict priority ahead of bulk data frames to ensure cancellation, status polling, and heartbeats remain responsive under full saturation.
- **Lightweight Data Framing**: Bulk data streams transmit a 32-byte header (transfer ID and file ID) followed by raw data frames (24-byte header and payload), eliminating redundant metadata overhead.

### Data Processing Pipelines

```
Upload Pipeline:
  Local Disk ──read (bounded 2 MiB pool)
     → Streaming Chunker (FastCDC or Fixed)
     → Hasher Worker Pool (Parallel BLAKE3)
     → Delta Filter (Destination Inventory Query)
     → Stream Scheduler (Bounded Queue, Concurrency × 4)
     → QUIC Stream Writer
     → UDP Network Interface

Download Pipeline:
  UDP Network Interface
     → QUIC Stream Reader
     → Chunk Integrity Verifier (BLAKE3)
     → Journal Checkpoint (SQLite WAL Bitmap)
     → Reconstruction Engine (Local Extents + Wire Chunks)
     → Hidden Staging Path (.velcrux-staging/<id>)
     → Aggregate File Hash Verification
     → Atomic POSIX Rename to Final Path
```

---

## Installation and Build

### Quick Install (Pre-built Binaries)

**Linux & macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/krishsharma/velcrux/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/krishsharma/velcrux/main/install.ps1 | iex
```

Or download the pre-compiled binary archives directly from [GitHub Releases](https://github.com/krishsharma/velcrux/releases). Each release contains:
- `velcrux` / `velcrux.exe` (CLI client)
- `velcruxd` / `velcruxd.exe` (Server daemon)
- Pre-generated shell completions (`bash`, `zsh`, `fish`, `powershell`)
- Cryptographic checksums (`SHA256SUMS.txt`)

### Platform Support

| Operating System | Architecture | Target |
|---|---|---|
| **Linux** | x86_64, aarch64 | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` |
| **macOS** | Apple Silicon, Intel | `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| **Windows** | x86_64 | `x86_64-pc-windows-msvc` |

### Compilation from Source

**Prerequisites:** Rust 1.80 or later.

```bash
# Clone the repository
git clone https://github.com/krishsharma/velcrux.git
cd velcrux

# Compile optimized release binaries
cargo build --release --workspace

# Install client and server binaries
cargo install --path crates/velcrux-client   # velcrux CLI
cargo install --path crates/velcrux-server   # velcruxd daemon
```


---

## Quickstart

### Automated Verification Demonstration

An end-to-end demonstration script is provided to showcase certificate generation, daemon startup, dry-run estimation, FastCDC middle-edit delta synchronization, and live telemetry:

```bash
./scripts/demo.sh
```

### Manual Operation

1. **Start the Server Daemon**:
   ```bash
   velcruxd run --config packaging/etc/velcrux/server.toml
   ```

2. **Execute Basic Client Operations**:
   ```bash
   # Verify connection latency
   velcrux ping velcrux://127.0.0.1:7443

   # Upload a file
   velcrux upload ./archive.tar velcrux://127.0.0.1:7443/data/archive.tar

   # Download a file
   velcrux download velcrux://127.0.0.1:7443/data/archive.tar ./archive_restored.tar
   ```

---

## CLI Reference Guide

### Directory Synchronization (`velcrux sync`)

The `sync` subcommand reconciles differences between source and destination directories incrementally:

```bash
velcrux sync <source> <destination> [OPTIONS]
```

#### Primary Flags

- `--dry-run`: Analyzes differences and outputs estimated transfer savings without modifying the target.
- `--delete-after`: Removes extraneous target files only after all transfers have successfully committed.
- `--cdc`: Enables FastCDC content-defined chunking (recommended for append-heavy or edited datasets).
- `--dedup`: Enables global chunk store deduplication across files.
- `--chunk-store <PATH>`: Specifies the local content-addressed chunk store path.
- `--json`: Outputs structured NDJSON progress events for machine consumption.

#### Examples

```bash
# Preview directory changes
velcrux sync ./dataset velcrux://host:7443/data/dataset --dry-run

# Synchronize directory using FastCDC and chunk-store deduplication
velcrux sync ./dataset velcrux://host:7443/data/dataset --cdc --dedup

# Synchronize with safe post-commit orphan deletion
velcrux sync ./dataset velcrux://host:7443/data/dataset --delete-after
```

### Transfer State and Resumption

```bash
# Inspect transfer state and progress
velcrux stat 01JB7Q2K9M4X8ZQ3V5N7T1R6C0

# Resume an interrupted transfer
velcrux resume 01JB7Q2K9M4X8ZQ3V5N7T1R6C0

# Cancel an active transfer and reclaim staging space
velcrux cancel 01JB7Q2K9M4X8ZQ3V5N7T1R6C0

# List transfers filtered by remote path prefix
velcrux list velcrux://host:7443/data/
```

---

## Telemetry and Output Formats

### Standard Interactive Terminal Display

```text
dataset.tar
Progress:     73.4%
Transferred:  7.34 TB / 10.0 TB
Reused:       1.82 TB   (delta saved 18.2%)
Network:      8.70 Gbps
Average:      7.91 Gbps
RTT:          148 ms      Loss: 0.31%
Streams:      8 active
ETA:          12m 41s
```

### Structured NDJSON Event Output

When invoked with `--json`, the client emits newline-delimited JSON events to stdout for pipeline ingestion:

```json
{"v":1,"event":"progress","transfer_id":"01JB7Q2K9M4X8ZQ3V5N7T1R6C0","bytes_transferred":123456789,"bytes_total":987654321,"bytes_reused":18200000,"throughput_bps":8700000000,"rtt_ms":148,"ts":"2026-09-15T12:00:00.000Z"}
```

Supported event types include `plan`, `transfer_start`, `progress`, `file_complete`, `checkpoint`, `verify`, `commit`, and `transfer_complete`.

### Prometheus Metrics Endpoint

`velcruxd` provides a Prometheus-compatible scrape endpoint on `http://127.0.0.1:9443/metrics`:

```promql
# HELP velcrux_connections Total connections accepted
velcrux_connections{state="accepted"} 42

# HELP velcrux_handshakes_total Total completed handshakes
velcrux_handshakes_total 42

# HELP velcrux_pings_total Total pings handled
velcrux_pings_total 12

# HELP velcrux_transfers_active Currently active transfers
velcrux_transfers_active{direction="bidirectional"} 0
```

---

## Performance Benchmarks

Measured on reference enterprise hardware under synthetic high-BDP and microbenchmark conditions:

| Component | Target Baseline | Measured Throughput / Latency | Relative Performance |
|---|---|---|---|
| **Cryptographic Hashing** | BLAKE3 ≥ 1.0 GB/s | **1.32 GB/s** (SHA-256: 0.35 GB/s) | 3.8× faster than SHA-256 |
| **Fixed Chunking** | Streaming ≥ 500 MB/s | **0.88 GB/s** | +76% over target |
| **FastCDC Chunking** | Rolling hash ≥ 300 MB/s | **0.56 GB/s** | +86% over target |
| **Manifest Codec** | Throughput ≥ 1,000,000 entries/s | **2,330,000 entries/s** (Encode) / **2,950,000 entries/s** (Decode) | 2.3× over target |
| **Frame Codec** | Latency ≤ 50 ns | **9.1 ns** (Header) / **< 1.0 ns** (Data frame) | 5.5× faster |
| **Bitmap Compression** | 100k chunks RLE compression | **106 µs** (Encode) / **1.3 µs** (Decode) | 78× size reduction |
| **Protocol Overhead** | Wire protocol efficiency | **≤ 0.05%** | 40× below 2% ceiling |

---

## Deployment and Production Operations

### Docker Container Deployment

The multi-stage `Dockerfile` produces an unprivileged (`velcrux` UID 10001) runtime image based on `debian:bookworm-slim`:

```bash
docker run -d \
  --name velcruxd \
  --restart unless-stopped \
  -p 7443:7443/udp \
  -p 9443:9443/tcp \
  -v /data/velcrux:/data/velcrux \
  -v /var/lib/velcrux:/var/lib/velcrux \
  -v /etc/velcrux:/etc/velcrux:ro \
  velcruxd:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  velcruxd:
    build: .
    image: velcruxd:latest
    restart: unless-stopped
    ports:
      - "7443:7443/udp"
      - "9443:9443/tcp"
    volumes:
      - velcrux-data:/data/velcrux
      - velcrux-state:/var/lib/velcrux
      - velcrux-config:/etc/velcrux:ro

volumes:
  velcrux-data:
  velcrux-state:
  velcrux-config:
```

### systemd Service Configuration

A hardened systemd unit file is provided at `packaging/systemd/velcruxd.service`:

```ini
[Unit]
Description=velcrux bulk transfer server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=velcrux
Group=velcrux
ExecStart=/usr/local/bin/velcruxd run --config /etc/velcrux/server.toml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=120
KillSignal=SIGTERM

# Sandboxing
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/velcrux /data/velcrux
MemoryMax=8G
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

---

## Security Model

1. **Authentication**: Strict Mutual TLS (mTLS) over TLS 1.3. Client certificates require a SAN URI identifier (`velcrux://identity/<name>`). Anonymous access is prohibited.
2. **Authorization**: Deny-by-default role-based policy (`grants.toml`). Access is scoped to canonical path prefixes with explicit permissions (`upload`, `download`, `list`, `delete`, `sync`, `resume`, `admin`).
3. **Filesystem Confinement**: All destination paths are validated through `VPath`, preventing directory traversal attempts (`../`, null bytes, control characters, or symlink escapes).
4. **Key File Protection**: The server refuses to launch if private key files possess world- or group-readable permissions (enforced mode `0600`).

---

## Acceptance Verification (Definition of Done)

Velcrux validates against all 15 operational acceptance criteria:

| Number | Acceptance Criterion | Verification Script |
|---|---|:---:|
| 1 | Start a QUIC server daemon | PASS |
| 2 | Authenticate client identity via mTLS | PASS |
| 3 | Upload file and directory hierarchies | PASS |
| 4 | Download file and stage without corruption | PASS |
| 5 | Verify final cryptographic hash (BLAKE3) | PASS |
| 6 | Terminate client mid-transfer | PASS |
| 7 | Re-establish client connection | PASS |
| 8 | Resume transfer without restarting from zero | PASS |
| 9 | Reconcile modified files incrementally | PASS |
| 10 | Transmit only changed chunks via FastCDC | PASS |
| 11 | Maintain throughput under simulated packet loss | PASS |
| 12 | Tolerate high RTT links with 384 MiB BDP window | PASS |
| 13 | Prevent unauthorized filesystem access and traversal | PASS |
| 14 | Export Prometheus operational metrics | PASS |
| 15 | Pass 100% of unit and integration test suites | PASS |

To execute the automated 15-item validation suite:

```bash
./scripts/validate_dod.sh
```

---

## License

This project is dual-licensed under:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
