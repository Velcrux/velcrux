# ADR-011: Empirical Performance Profiling & Bottleneck Analysis

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §72 ("Performance Profiling"), §38 ("Observability"), §36 ("Machine-Readable Output"), and §46 ("Benchmark Suite"), operators and automated tooling need granular, empirical visibility into where time and compute cycles are spent during bulk data transfers.

High-throughput transfers over QUIC involve multiple interconnected pipeline stages:
1. Disk read I/O
2. Chunking (rolling FastCDC vs fixed boundaries)
3. Cryptographic hashing (BLAKE3 single-chunk and SIMD tree hashing)
4. Zero-knowledge AEAD chunk encryption / decryption
5. QUIC network transport (stream pacing, congestion control, packet loss recovery)
6. Disk write / staging and filesystem commit (`fsync` / `rename`)
7. Frame serialization and protocol state evaluation

When transfers fall short of line-rate speed (e.g. 10 Gbps / 40 Gbps), operators need to know **immediately** whether the limiting factor is WAN bandwidth/latency, NVMe/disk I/O, CPU cryptographic throughput, or suboptimal chunk boundaries.

## Options

1. **External OS-Level Profiling Only**: Rely exclusively on external tools (`perf`, `flamegraph`, `iostat`, `tcpdump`).
2. **Coarse Overall Timers**: Record only total transfer elapsed duration and calculate aggregate Megabytes per second.
3. **Integrated Empirical Subsystem Profiling with Automated Bottleneck Diagnosis**: Instrument each pipeline stage with sub-microsecond non-blocking timing guards (`TransferProfiler`, `ComponentTiming`), capture network metrics (RTT, loss rate, cwnd) and memory usage (RSS, buffer pool), and apply deterministic empirical classification rules (`BottleneckDiagnosis`) with actionable remediation guidance.

## Decision

Option 3. Velcrux provides integrated empirical performance profiling and automated bottleneck diagnosis natively across `velcrux-core` and the `velcrux profile` CLI command.

Option 1 is rejected as a primary solution because external OS profilers require elevated root/sudo privileges, cannot correlate protocol-level state (e.g. QUIC cwnd or chunk boundaries), and cannot be queried by automated scripting or CI pipelines.
Option 2 is rejected because gross transfer throughput provides zero insight into which specific subsystem is bottlenecked.

## Architecture & Diagnosis Engine

The profiling engine measures per-component timings and classifies the primary constraint:
- `NetworkBound`: QUIC transmission latency, low cwnd, or high packet loss rate dominates pipeline time ($>50\%$). Suggests BDP tuning, UDP buffer expansion, or PMTU inspection.
- `DiskIoReadBound`: Storage read I/O dominates. Suggests NVMe striped arrays, direct I/O, or OS readahead adjustment.
- `DiskIoWriteBound`: Staging write or fsync commit dominates. Suggests writeback caching, separate staging disks, or relaxed sync policies.
- `CpuHashingBound`: BLAKE3 chunk hashing dominates. Suggests hardware SIMD vectorization (AVX-512/NEON) and thread concurrency scaling.
- `CryptoBound`: Zero-knowledge AEAD encryption dominates. Suggests hardware AES-NI or ChaCha20 vector acceleration.
- `BalancedOptimized`: Pipeline stages are evenly distributed without dominant stalling.

## Machine-Readable & Human-Readable Output

Per §36 and §38:
- Standard CLI invocation (`velcrux profile <file>`) renders an ASCII breakdown table with invocations, milliseconds, percentage contribution, and MB/s goodput.
- `--json` invocation outputs a structured JSON schema suitable for Prometheus/Grafana export, OpenTelemetry ingestion, or automated CI/CD performance regression gates.

## Consequences

- Zero performance degradation when disabled (zero-allocation overhead).
- Operates under `#![forbid(unsafe_code)]`.
- Documented in `docs/OPERATIONS.md` §29.
