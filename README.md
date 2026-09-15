# Velcrux

<p align="center">
  <strong>High-throughput, resumable, verifiable bulk dataset transfer over QUIC.</strong>
</p>

<p align="center">
  <a href="https://github.com/krishsharma/velcrux/actions"><img src="https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square" alt="CI Status"></a>
  <a href="docs/REQUIREMENTS.md#83-definition-of-done-for-mvp"><img src="https://img.shields.io/badge/DoD%20Acceptance-15%2F15%20Passed-brightgreen?style=flat-square" alt="DoD Status"></a>
  <img src="https://img.shields.io/badge/rust-1.80%2B-blue?style=flat-square" alt="Rust Version">
  <img src="https://img.shields.io/badge/unsafe%20code-forbidden-red?style=flat-square" alt="Unsafe Forbidden">
  <img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue?style=flat-square" alt="License">
</p>

---

## ⚡ Overview

`velcrux` is purpose-built for the reality where network links are fast but distant: **1–10 Gbps pipes with 50–300 ms RTT and non-trivial packet loss**, transferring objects from hundreds of megabytes to tens of terabytes.

Unlike legacy tools (`scp`, `sftp`, `rsync`) that bottleneck on TCP head-of-line blocking or high BDP window collapse, Velcrux combines:
- A **native QUIC multi-stream transport** with 384 MiB BDP receive windows and independent flow control.
- **Content-Defined Chunking (FastCDC)** to make transfers invariant to boundary shifts and byte insertions.
- **Bi-directional delta synchronization** with bloom filters and run-length encoded (RLE) bitmaps.
- **Content-addressed chunk store deduplication**, ensuring duplicate blocks across files and transfers cross the wire exactly once.
- **Cryptographic verification** via BLAKE3 per-chunk and whole-file checks, paired with two-phase atomic filesystem commits.

> *"Designed for high bandwidth-delay-product bulk transfer, and minimizes bytes on the wire through incremental synchronization."*

---

## 🛡️ Core Guarantees

| Property | Guarantee | Implementation |
|---|---|---|
| **Bounded Memory** | Peak RSS ≤ 512 MiB regardless of file size (10 GB or 100 TB) | Bounded buffer pools (2 MiB), streaming manifests, and backpressured channel queues. |
| **Crash Resilience** | Process kill / reboot resumes without restarting from zero | SQLite WAL persistent state store checkpointing verified chunk bitmaps every 10 s. |
| **Integrity Verification** | Byte count is never proof of success; zero silent corruption | BLAKE3 chunk verification on receipt + whole-file verification before atomic rename. |
| **Safe Atomicity** | Destination files are never left corrupted or half-written | Writes stage to hidden sibling directories; atomic POSIX `rename` on verified commit. |
| **Boundary Shift Immunity** | Adding bytes at offset 0 preserves ≥95% of subsequent chunks | FastCDC rolling hashing with normalized chunk boundaries (64 KiB – 1 MiB). |
| **Cross-File Dedup** | Second copy of an identical file moves 0 wire bytes | Content-addressed chunk store (`.velcrux-chunks/`) keyed by BLAKE3 hashes. |
| **Safe Deletion** | Extraneous destination files are never deleted by default | Strict `--delete-after` opt-in; deletions execute only after all file commits succeed. |
| **Zero Unsafe Code** | Memory safety strictly enforced by compiler | `#![forbid(unsafe_code)]` declared and enforced across all crates. |

---

## 🚀 Quickstart

### 1. Installation

```bash
# Clone repository
git clone https://github.com/krishsharma/velcrux.git
cd velcrux

# Build and install binaries
cargo install --path crates/velcrux-client   # velcrux (CLI)
cargo install --path crates/velcrux-server   # velcruxd (Daemon)
```

### 2. Interactive 60-Second Showcase Demo

Run the automated self-contained showcase to see mTLS provisioning, `--dry-run` estimation, FastCDC middle-edit delta sync, and live Prometheus metrics in action:

```bash
./scripts/demo.sh
```

---

## 💻 CLI Usage Guide

### Basic File Operations

```bash
# 1. Upload a single file
velcrux upload ./ubuntu.iso velcrux://host:7443/data/ubuntu.iso

# 2. Download a file
velcrux download velcrux://host:7443/data/ubuntu.iso ./ubuntu.iso

# 3. Ping server over mTLS
velcrux ping velcrux://host:7443
```

### Incremental Directory Synchronization (`velcrux sync`)

```bash
# Preview differences without modifying destination (dry-run)
velcrux sync ./dataset velcrux://host:7443/data/dataset --dry-run

# Synchronize directory tree incrementally
velcrux sync ./dataset velcrux://host:7443/data/dataset

# Enable Content-Defined Chunking (FastCDC) for boundary-shift resistance
velcrux sync ./dataset velcrux://host:7443/data/dataset --cdc

# Enable chunk-store deduplication across files
velcrux sync ./dataset velcrux://host:7443/data/dataset --cdc --dedup

# Safely delete destination files that no longer exist on source (after commits succeed)
velcrux sync ./dataset velcrux://host:7443/data/dataset --delete-after
```

### Transfer Management & Resumption

```bash
# Inspect state of an active or interrupted transfer
velcrux stat 01JB7Q2K9M4X8ZQ3V5N7T1R6C0

# Resume an interrupted transfer from its last checkpoint
velcrux resume 01JB7Q2K9M4X8ZQ3V5N7T1R6C0

# Cancel an in-flight transfer and clean up remote staging
velcrux cancel 01JB7Q2K9M4X8ZQ3V5N7T1R6C0

# List transfers under a path prefix
velcrux list velcrux://host:7443/data/
```

---

## 📊 Live Progress & Machine-Readable Output

### Interactive TTY Display

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

### JSON Event Stream (`--json`)

Pass `--json` for automation, dashboards, and programmatic ingestion. Events are newline-delimited JSON (NDJSON):

```json
{"v":1,"event":"progress","transfer_id":"01JB7Q...","bytes_transferred":123456789,"bytes_total":987654321,"bytes_reused":18200000,"throughput_bps":8700000000,"rtt_ms":148,"ts":"2026-09-02T11:14:03.221Z"}
```

---

## 🏗️ Architecture & Protocol

### Control Plane vs Data Plane

A single QUIC connection multiplexes control, metadata, and bulk data across distinct streams:

```
                      QUIC Connection (TLS 1.3 / mTLS)
 ┌────────────────────────────────────────────────────────────────────────────┐
 │ Control Stream (bidi #0)   : HELLO, AUTH, TRANSFER_CREATE, COMMIT, PING    │
 │ Metadata Stream (bidi #1)  : MANIFEST_*, INVENTORY_*, CHUNK_QUERY/RESP    │
 │ Data Streams (uni #2..#N)  : 32-byte Preamble + DATA Frames (raw chunks)   │
 └────────────────────────────────────────────────────────────────────────────┘
```

- **Control** is small and prioritised ahead of bulk data — a 10 TB file transfer never delays a `PING` or `CANCEL`.
- **Data streams** carry a 32-byte preamble followed by raw chunk frames. No JSON, no per-chunk handshake, no protocol overhead.

### Data Pipelines

```
Upload Pipeline:
  Disk ──read (bounded 2 MiB pool)
     → Chunker (FastCDC / Fixed, streaming zero-copy)
     → Hasher Pool (BLAKE3 parallel workers)
     → Delta Filter (Inventory query, drops existing chunks)
     → Scheduler (Bounded queue, depth = concurrency × 4)
     → QUIC Stream Writer
     → UDP

Download Pipeline:
  UDP
     → QUIC Stream Reader
     → Chunk Hash Verifier (BLAKE3)
     → Checkpoint Journal (SQLite WAL chunk bitmap)
     → Reconstructor (Hybrid wire chunks + local inventory copy)
     → Staging File (.velcrux-staging/<id>)
     → Whole-File Hash Check (BLAKE3)
     → Atomic POSIX Rename to Destination
```

---

## 📈 Measured Performance Benchmarks

Measured on reference hardware (`Apple M-series / Linux x86_64`) per `docs/PERFORMANCE.md` §12:

| Component | Target Metric | Measured Result | Margin |
|---|---|---|---|
| **Cryptographic Hash** | BLAKE3 throughput ≥ 1.0 GB/s | **1.32 GB/s** (vs SHA-256: 0.35 GB/s) | **3.8× faster** |
| **Content Chunking** | Fixed chunking ≥ 500 MB/s | **0.88 GB/s** | **+76%** |
| **FastCDC Chunking** | CDC rolling hash ≥ 300 MB/s | **0.56 GB/s** | **+86%** |
| **Manifest Streaming** | Encode/Decode ≥ 1,000,000 entries/s | **2,330,000 entries/s** encode / **2,950,000 entries/s** decode | **2.3× faster** |
| **Frame Codec** | Serialization latency ≤ 50 ns | **9.1 ns** / header; **< 1.0 ns** / data frame | **5.5× faster** |
| **Bitmap Compression**| 100k chunk set (RLE) | **106 µs** encode; **1.3 µs** decode | **78× size reduction** |
| **Delta Overhead** | Wire protocol overhead | **≤ 0.05%** | **40× under 2% cap** |

---

## 🐳 Containerization & Deployment

### Run via Docker

```bash
docker run -d --name velcruxd --restart unless-stopped \
  -p 7443:7443/udp \
  -p 9443:9443/tcp \
  -v velcrux-data:/data/velcrux \
  -v velcrux-state:/var/lib/velcrux \
  -v velcrux-config:/etc/velcrux \
  velcruxd:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  velcruxd:
    image: velcruxd:latest
    ports:
      - "7443:7443/udp"   # QUIC Bulk Data
      - "9443:9443/tcp"   # Prometheus /metrics
    volumes:
      - velcrux-data:/data/velcrux
      - velcrux-state:/var/lib/velcrux
      - velcrux-config:/etc/velcrux
    restart: unless-stopped
```

```bash
docker compose up -d
```

### systemd Service

```bash
cp packaging/systemd/velcruxd.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now velcruxd
```

---

## 📡 Prometheus Telemetry (`/metrics`)

`velcruxd` exposes Prometheus metrics on `telemetry.metrics_listen` (default: `http://127.0.0.1:9443/metrics`):

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

## ✅ Definition of Done (DoD §83)

The MVP fulfills all 15 acceptance criteria defined in `docs/REQUIREMENTS.md` §83:

| # | Acceptance Criterion | Verification Method | Status |
|---|---|---|:---:|
| 1 | Start a QUIC server | `scripts/validate_dod.sh` | **PASS** |
| 2 | Authenticate a client via mTLS | SAN URI identity handshake | **PASS** |
| 3 | Upload file / dataset | Streaming upload & verification | **PASS** |
| 4 | Download file / dataset | Two-phase staging download | **PASS** |
| 5 | Verify final cryptographic hash | BLAKE3 whole-file verification | **PASS** |
| 6 | Kill client halfway through | Process termination simulation | **PASS** |
| 7 | Restart client | Session reconnection | **PASS** |
| 8 | Resume without restarting from zero | SQLite WAL chunk bitmap checkpoint | **PASS** |
| 9 | Synchronize a modified file | Inventory exchange & delta reconstruct | **PASS** |
| 10 | Transfer only changed chunks | FastCDC rolling hash (≥95% reuse) | **PASS** |
| 11 | Survive simulated packet loss | Loss recovery & congestion window | **PASS** |
| 12 | Survive simulated high RTT | 384 MiB BDP receive window tuning | **PASS** |
| 13 | Prevent unauthorized filesystem access | Strict VPath & grant prefix containment | **PASS** |
| 14 | Produce useful metrics | Prometheus HTTP `/metrics` endpoint | **PASS** |
| 15 | Pass automated tests | 100% test pass rate across all suites | **PASS** |

Run the full validation suite locally:
```bash
./scripts/validate_dod.sh
```

---

## 📚 Documentation Index

| Document | Description |
|---|---|
| [`docs/ARCHITECTURE.md`](file:///Users/krishsharma/Downloads/velcrux/docs/ARCHITECTURE.md) | Architectural layers, pipelines, state machines, and concurrency models |
| [`docs/PROTOCOL.md`](file:///Users/krishsharma/Downloads/velcrux/docs/PROTOCOL.md) | Wire protocol specification, binary framing, message serialization |
| [`docs/SECURITY.md`](file:///Users/krishsharma/Downloads/velcrux/docs/SECURITY.md) | Threat model, mTLS authentication, path-scoped authorization, limits |
| [`docs/PERFORMANCE.md`](file:///Users/krishsharma/Downloads/velcrux/docs/PERFORMANCE.md) | Target metrics, BDP calculation, benchmark suite, and tuning |
| [`docs/OPERATIONS.md`](file:///Users/krishsharma/Downloads/velcrux/docs/OPERATIONS.md) | Deployment topologies, systemd configuration, runbooks, metrics |
| [`docs/DEVELOPMENT.md`](file:///Users/krishsharma/Downloads/velcrux/docs/DEVELOPMENT.md) | Local development setup, fuzzing, testing, network simulation |
| [`docs/adr/`](file:///Users/krishsharma/Downloads/velcrux/docs/adr/) | Architecture Decision Records (ADRs 001–006) |

---

## 📄 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
