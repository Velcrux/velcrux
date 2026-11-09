# ADR-074: Confidential Multi-Tenant eBPF Sandboxed Streaming Compute & In-Flight WASM Payload Transformation (WASI 0.2)

- **Status**: Accepted
- **Date**: 2026-11-09
- **Deciders**: Velcrux Architecture, Confidential Computing, Network Protocols, and Security Engineering Teams
- **Consulted**: Distributed Storage, Cloud-Native Compute, and Site Reliability Engineering Teams

---

## 1. Context and Problem Statement

High-throughput bulk data transfers across multi-tenant distributed cloud and edge fabrics often require dynamic on-the-wire payload processing:
1. **Confidentiality & In-Memory Transmutation**: Writing raw, unmasked, or unencrypted sensitive customer records (e.g. personally identifiable information, payment credentials, telemetry) to physical disks before transformation introduces compliance hazards (GDPR, PCI-DSS, HIPAA) and storage I/O latency bottlenecks.
2. **Dynamic Schema Transcoding**: Inter-service bulk transfers frequently require format conversions (e.g. streaming line-delimited JSON or CSV into compact columnar binary formats like Arrow/Parquet or FlatBuffers) without round-tripping through temporary files.
3. **Multi-Tenant Sandboxing & CPU Governance**: Executing arbitrary user or tenant transformation logic over raw transport streams requires strict isolation: untrusted code must be memory-isolated (preventing pointer escaping), capability-constrained (no unauthorized filesystem or raw network socket access), and gas/fuel-metered to guarantee termination and eliminate denial-of-service vulnerabilities.
4. **Line-Rate Fastpath Filtering**: Processing gigabytes-per-second of data requires an early eBPF classification stage capable of zero-copy bypassing pre-compressed or non-sensitive chunks without paying unnecessary execution costs.

To solve these challenges, Velcrux requires a **Confidential Multi-Tenant eBPF Sandboxed Streaming Compute & In-Flight WASM Payload Transformation Engine** implementing the WebAssembly Component Model (WASI 0.2) in 100% pure safe Rust.

---

## 2. Decision Drivers

- **Pure Safe Rust WebAssembly Runtime**:
  - Full W3C WebAssembly 1.0/2.0 binary module decoder: magic header (`\0asm`), section parsing (Type, Function, Memory, Export, Code), LEB128 variable-length integer parsing, and opcode disassembler.
  - Linear memory arena with strict bounds checking and 64 KiB page granularity (`WasmMemory`).
  - Stack-based instruction execution engine with deterministic step-by-step gas/fuel metering (`GasMeter`), halting execution with `OutOfGas` traps if resource budgets are exceeded.
- **WASI 0.2 Component Model & Capability-Based Sandboxing**:
  - Fine-grained capability grants: `allow_random`, `allow_clocks`, `allow_env`, `allow_logging`.
  - Strict host sandboxing: default denial of host filesystem (`DisallowFilesystem`) and arbitrary host network socket operations (`DisallowNetwork`).
  - Virtual stream I/O interfaces (`wasi:io/streams::read`, `wasi:io/streams::write`) operating entirely in memory.
- **In-Flight Streaming Transformation Filters**:
  - **PII Redaction Stage**: Real-time streaming masking of credit card numbers (`XXXX-XXXX-XXXX-XXXX`), US Social Security Numbers (`XXX-XX-XXXX`), and bearer credentials.
  - **Schema Transcoding Stage**: Real-time conversion between JSON/text and compact Velcrux Binary Columnar (`VXBC`) representations.
  - **Stream Masking & Authenticated Checksum Stamping**: In-place keystream masking and trailing BLAKE3 authenticated checksum trailers.
  - **Pipeline Composition**: Sequential chaining of multiple transformation stages with per-stage gas budgets and end-to-end BLAKE3 verification.
- **eBPF-Style Streaming Fastpath Classifier**:
  - Line-rate packet and chunk inspection evaluating magic byte signatures, tenant IDs, and payload metadata.
  - Fastpath zero-copy bypass for pre-compressed streams (Zstandard, Gzip) or binary opaque blobs, reserving WASM computation exclusively for candidate payloads.
- **Confidential Multi-Tenant Sandbox Governance**:
  - Independent tenant sandboxes (`TenantSandbox`) preventing cross-tenant state leakage.
  - Hard memory page quotas (e.g. 16 MiB max per sandbox) and concurrent pipeline constraints.
- **Zero Unsafe Code**: 100% `#![forbid(unsafe_code)]` compliance with zero external C dependencies.

---

## 3. Technical Architecture

```
                  Incoming In-Flight Transport Stream (QUIC / RDMA)
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │      eBPF Line-Rate Fast-Path Classifier     │
                  │  - Magic Prefix Matching (Zstd, Media, etc.) │
                  │  - Content-Type / Payload Structure Analysis │
                  └──────────────┬───────────────────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
         [Bypass Match]                  [Transform Match]
                 │                               │
                 ▼                               ▼
       ┌──────────────────┐            ┌────────────────────────────────────────┐
       │ Zero-Copy Direct │            │ Confidential Multi-Tenant WASM Sandbox │
       │ Streaming Target │            │                                        │
       └──────────────────┘            │  [WASI 0.2 Capability Layer]           │
                                       │  - wasi:io/streams Virtual Buffers     │
                                       │  - wasi:random, wasi:clocks            │
                                       │  - Blocked: Host Disk & Network        │
                                       │                                        │
                                       │  [Deterministic Gas / Fuel Meter]      │
                                       │  - Max Budget per Chunk                │
                                       │  - Traps on OutOfGas                   │
                                       │                                        │
                                       │  [Chained In-Flight Pipeline Stages]   │
                                       │  Stage 1: PII Masking / Redaction      │
                                       │  Stage 2: Columnar Schema Transcoding  │
                                       │  Stage 3: BLAKE3 Checksum Stamping     │
                                       └──────────────────┬─────────────────────┘
                                                          │
                                                          ▼
                                            Transformed Outgoing Stream
```

---

## 4. Security Considerations

1. **Memory Isolation**: All guest memory allocations are constrained within `WasmMemory` instances. Offsets are validated before any memory access, mathematically precluding buffer overflows or arbitrary host pointer dereferencing.
2. **Capability Containment**: Guests operate strictly within a WASI 0.2 sandbox lacking host OS file descriptors or sockets, ensuring complete confidentiality.
3. **Denial-of-Service Defense**: Gas metering decrements fuel on every instruction. Infinite loops, recursive calls, or pathological inputs terminate predictably with an `OutOfGas` error without starving CPU threads.
4. **Tenant Segregation**: `TenantSandboxManager` maintains isolated pipeline registries and memory budgets, guaranteeing zero cross-tenant contamination.

---

## 5. Consequences

### Positive
- Direct-to-memory in-flight payload transmutation eliminates intermediate disk I/O latency.
- Comprehensive privacy compliance via streaming PII masking before data reaches storage.
- High-performance schema transcoding without external runtimes or heavy C dependencies.
- Zero-copy eBPF fastpath prevents compute bottlenecks on pre-compressed data streams.

### Negative
- Compute-intensive transformation stages introduce CPU overhead proportional to payload volume; mitigated by eBPF fastpath filtering and gas budget caps.
