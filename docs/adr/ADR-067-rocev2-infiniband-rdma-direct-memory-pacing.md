# ADR-067: RoCEv2 & InfiniBand RDMA Direct Memory Pacing

- **Status**: Accepted
- **Date**: 2026-11-04
- **Deciders**: Velcrux Core Networking, Transport, High-Performance Datacenter I/O, and Systems Architecture Teams
- **Consulted**: AI/ML Infrastructure, HPC Storage, Linux Kernel Performance, and DevOps Teams

---

## 1. Context and Problem Statement

Modern hyperscale AI/ML training clusters and high-performance datacenter fabrics operate at line rates of 100 Gbps, 200 Gbps, and 400 Gbps. At these extreme bandwidths, conventional socket-based transport stacks (even when accelerated by kernel-bypass eBPF/XDP) encounter fundamental hardware host bottlenecks:
1. **Host CPU Saturation**: Transferring data across standard kernel or userspace network sockets requires CPU cores to mediate memory buffers, compute checksums, and service interrupts, consuming up to 100% of multi-core CPU capacity simply moving bytes.
2. **Memory Bus Contention & Cache Pollution**: Copying bulk chunk data into intermediate OS buffers thrashes CPU L1/L2/L3 caches and saturates host memory bus bandwidth.
3. **Pipelining Latency for Content-Addressed Chunks**: Waiting for synchronous receiver socket processing before acknowledging chunks limits pipelining depth on high-bandwidth, low-latency datacenter backbones.
4. **Congestion Collapse in Lossless Fabrics**: RoCEv2 operates over Converged Ethernet fabrics where Priority Flow Control (PFC) prevents packet loss, but unmanaged buffer pressure can lead to PFC pause frame propagation, head-of-line blocking, and credit deadlocks without intelligent end-to-end congestion control (DCQCN).

---

## 2. Decision Drivers

- **Zero-Copy, Zero-CPU Remote Direct Memory Access**: Bypass host CPU cores during active bulk chunk transfers by streaming bytes directly between the local Host Channel Adapter (HCA) and remote host registered memory regions.
- **RoCEv2 Wire Protocol Compliance**: Encapsulate InfiniBand transport headers (BTH, RETH, AETH, ImmDt, IETH) over standard UDP port 4791 with 32-bit Invariant CRC (ICRC) validation.
- **Verbs Architecture & Queue Pairs**: Implement Reliable Connected (`RC`) Queue Pairs (`QueuePair`), Scatter/Gather Elements (`Sge`), Work Requests (`SendWr`), Work Completions (`WorkCompletion`), and Completion Queues (`CompletionQueue`).
- **Memory Protection Domains & Key Validation**: Provide secure Memory Region (`MemoryRegion`) registration scoped to Protection Domains (`ProtectionDomain`), issuing and verifying cryptographically distinct local keys (`lkey`) and remote access keys (`rkey`).
- **Hardware-Assisted Flow Pacing & Congestion Control**: Implement Data Center Quantized Congestion Notification (DCQCN) with moving average congestion estimation ($\alpha$), multiplicative rate decrease upon Congestion Notification Packets (CNP), additive/hyper-increase recovery stages, and 802.1Qbb Priority Flow Control (PFC) pause tracking.
- **Zero Unsafe Code**: 100% pure safe Rust (`#![forbid(unsafe_code)]`) with zero external C dependencies or platform-specific FFI bindings.

---

## 3. Considered Options

- **Option 1: Standard TCP / QUIC with OS Kernel Network Stack**:
  - *Cons*: High CPU utilization, excessive context switches, memory copying, and incapable of scaling to > 40 Gbps without consuming dozens of CPU cores.
- **Option 2: Native C `libibverbs` / `librdmacm` via FFI**:
  - *Cons*: Introduces complex C runtime dependencies, platform-specific shared libraries, and pervasive unsafe pointers violating memory safety guarantees.
- **Option 3 (Chosen): Native Safe-Rust RoCEv2 / InfiniBand RDMA Subsystem (`Option CY`)**:
  - Pure safe-Rust verbs runtime, HCA emulation, wire framer, memory registration engine, and DCQCN flow pacer.
  - Zero external C dependencies under `#![forbid(unsafe_code)]`.
  - Enables direct RDMA Write with Immediate data for zero-copy chunk delivery and immediate notification.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│               VELCRUX HARDWARE-ACCELERATED RDMA DIRECT MEMORY PACING                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
               [ Client Host ]              │              [ Server Host ]
      ┌───────────────────────────────┐     │     ┌───────────────────────────────┐
      │   Client Registered Memory    │     │     │   Server Registered Memory    │
      │   (MemoryRegion: addr, lkey)  │     │     │   (MemoryRegion: addr, rkey)  │
      └──────────────┬────────────────┘     │     └───────────────▲───────────────┘
                     │                      │                     │
               [ DMA Read ]                 │               [ Direct DMA ]
                     │                      │                     │
                     ▼                      │                     │
      ┌───────────────────────────────┐     │     ┌───────────────┴───────────────┐
      │    Send Queue Pair (QPN_c)    │     │     │   Recv Queue Pair (QPN_s)     │
      │  • SendWr (RdmaWriteWithImm)  │     │     │  • Recv Completion Queue     │
      │  • SGE (Local Memory Buffer)  │     │     │  • Immediate Data (Chunk ID)  │
      └──────────────┬────────────────┘     │     └───────────────▲───────────────┘
                     │                      │                     │
                     ▼                      │                     │
      ┌───────────────────────────────┐     │     ┌───────────────┴───────────────┐
      │     RoCEv2 Wire Framer        │     │     │    RoCEv2 Wire Dissector      │
      │  • UDP 4791 + BTH + RETH      │     │     │  • BTH Opcode & PSN Verify    │
      │  • Immediate Data + ICRC      │     │     │  • RETH Bounds & RKey Check   │
      └──────────────┬────────────────┘     │     └───────────────▲───────────────┘
                     │                      │                     │
                     ▼                      │                     │
      ┌───────────────────────────────┐     │     ┌───────────────┴───────────────┐
      │      DCQCN Flow Pacer         │     │     │   Congestion Detection (ECN)  │
      │  • Line Rate (100 Gbps)       │     │     │  • ECN Marking Detection      │
      │  • Rate Limiter (Rc / Rt)     │◄────┼─────┤  • CNP Feedback Generation    │
      │  • Multiplicative Decrease    │ CNP │     │  • 802.1Qbb PFC Pause Frames  │
      └──────────────┬────────────────┘     │     └───────────────────────────────┘
                     │                      │
                     └──────────────────────┴─────────────────────►
                               [ 100G / 200G RoCEv2 Fabric ]
```

---

## 5. Subsystem Components

### 5.1. RoCEv2 / InfiniBand Wire Framing (`rdma/frame.rs`)
- **Base Transport Header (`Bth`)**: 12-byte InfiniBand transport header carrying opcode (`RcRdmaWriteOnlyWithImm`, `RcRdmaReadRequest`, `RcAck`, `Cnp`), destination QP (24-bit), packet sequence number (PSN, 24-bit), partition key (`pkey`), and flags (`solicited`, `ack_req`, `pad_count`).
- **Extended Transport Headers**:
  - `Reth` (16 bytes): Remote Virtual Address (64-bit), Remote Key `rkey` (32-bit), and DMA Length (32-bit).
  - `Aeth` (4 bytes): Syndrome code (ACK with credit count, or Receiver Not Ready RNR delay) and Message Sequence Number (`msn`).
  - `ImmDt` (4 bytes): 32-bit immediate data payload in network byte order.
- **Invariant CRC (`calculate_icrc`)**: 32-bit CRC computed across invariant packet fields as specified in InfiniBand Architecture Specification Vol 1, Section 7.8.

### 5.2. Memory Registration & Protection Domains (`rdma/mr.rs`)
- **Protection Domain (`ProtectionDomain`)**: Security boundary isolating memory regions and queue pairs from unauthorized cross-domain access.
- **Memory Region (`MemoryRegion`)**: Registers host memory buffers, assigns simulated 64-bit virtual addresses, generates unique `lkey` and `rkey` tokens, and enforces granular access permissions (`LOCAL_WRITE`, `REMOTE_WRITE`, `REMOTE_READ`, `REMOTE_ATOMIC`).
- **Key Validation**: Validates rkey authorization, offset bounds, and permissions before permitting remote DMA read/write operations.

### 5.3. Verbs Architecture & Queue Pairs (`rdma/verbs.rs`)
- **Queue Pair Lifecycle**: Enforces strict state transitions (`Reset` $\to$ `Init` $\to$ `ReadyToReceive` $\to$ `ReadyToSend`).
- **Pipelined Operations**:
  - `execute_rdma_write`: Gathers bytes from local SGEs and performs direct DMA write into remote memory. When immediate data is present, delivers immediate completion notification to the remote peer's receive CQ.
  - `execute_rdma_read`: Scatters bytes directly from remote memory into local memory buffers without remote CPU intervention.
- **Completion Queue (`CompletionQueue`)**: Thread-safe completion queue providing asynchronous polling (`poll`) and completion posting for send and receive events.

### 5.4. DCQCN Flow Pacing & PFC Control (`rdma/pacing.rs`)
- **Data Center Quantized Congestion Notification (`DcqcnPacer`)**:
  - Tracks congestion estimator $\alpha \in [0.0, 1.0]$.
  - Multiplicative decrease: On CNP receipt, current rate drops according to $R_c = R_c \times (1 - \alpha/2)$ and $\alpha = (1 - g)\alpha + g$.
  - Multi-stage recovery: Advances through Fast Recovery, Additive Increase (AI), and Hyper-Increase (HI) stages based on byte transmission thresholds.
- **Priority Flow Control (PFC)**: Tracks 802.1Qbb priority pause events and pause duration counters.

### 5.5. Transfer Engine & HCA Emulation (`rdma/engine.rs`)
- **HCA Attributes (`HcaDeviceAttributes`)**: Reports 100 Gbps line rate, 4096-byte MTU, 65,536 QPs, and 1 TiB maximum MR size.
- **Benchmark Orchestrator**: Executes pipelined zero-copy transfers across simulated client and server QPs with bit-for-bit memory verification and line-rate telemetry.

---

## 6. CLI Integration & Operator Ergonomics

The `velcrux rdma` CLI command suite provides operators with comprehensive inspection, benchmarking, and tracing capabilities:
- **HCA Device Status**:
  ```bash
  velcrux rdma status --device mlx5_0
  velcrux rdma status --json
  ```
- **Zero-Copy RDMA Benchmark**:
  ```bash
  velcrux rdma bench --chunks 64 --chunk-size 4096 --inject-cnp
  velcrux rdma bench --chunks 128 --chunk-size 8192 --json
  ```
- **RoCEv2 Wire Frame Dissection**:
  ```bash
  velcrux rdma trace
  velcrux rdma trace --json
  ```
- **DCQCN Congestion Pacing Inspection**:
  ```bash
  velcrux rdma pacing --cnp-count 4 --pfc-pauses 2 --bytes-mb 20
  velcrux rdma pacing --json
  ```

---

## 7. Consequences & Guarantees

- **Guarantees**:
  - **Zero-Copy Data Transfer**: Remote memory is populated directly without intermediate host buffer copying or CPU-mediated receiver reads.
  - **Memory Safety**: 100% pure `#![forbid(unsafe_code)]` compliance across all wire dissection, memory registration, queue pairs, and pacing algorithms.
  - **Lossless Fabric Stability**: DCQCN pacing mitigates congestion before switch ingress queues trigger PFC pause storms or buffer overflows.
- **Trade-offs**:
  - True hardware RoCEv2 NIC offload requires hardware HCA support (e.g. Mellanox ConnectX-5/6/7). In virtualized or containerized environments without SR-IOV / PCIe passthrough, the safe-Rust verbs runtime provides seamless emulation with identical API and telemetry.
