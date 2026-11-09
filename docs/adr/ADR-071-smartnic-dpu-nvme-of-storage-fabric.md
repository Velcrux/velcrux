# ADR-071: SmartNIC / DPU Offloaded Direct-to-NVMe Storage Fabric (NVMe-oF over RDMA)

- **Status**: Accepted
- **Date**: 2026-11-09
- **Deciders**: Velcrux Storage, High-Performance Systems, Hardware Acceleration, and Networking Engineering Teams
- **Consulted**: Infrastructure Platform, Kernel Systems, and Enterprise Reliability Engineering Teams

---

## 1. Context and Problem Statement

High-throughput bulk data transfers (100 Gbps to 400 Gbps line rates) traversing modern hyperscale data centers face severe host CPU and memory bottlenecks when writing to or reading from local persistent storage:
1. **Host CPU Overhead & Memory Bus Contention**: Traditional software storage stacks (kernel block layers, TCP sockets, POSIX file systems) consume ~2.5 to 3.0 CPU clock cycles per byte transferred. At 100 Gbps line rate (12.5 GB/s), this consumes $>37.5\text{ GHz}$ of compute (10 to 16 host CPU cores) strictly copying payloads through socket buffers and page caches.
2. **Memory Bandwidth Bottleneck**: Double or triple bounce buffering through host DRAM chokes the CPU memory subsystem, degrading co-located compute, database, and analytics workloads.
3. **Storage Latency Jitter**: Interrupt handling, kernel context switching, and lock contention in the block I/O layer add 25–100 µs of latency per transaction, preventing true microsecond-level NVMe flash saturation.
4. **Fabric Multipath Availability**: Data center leaf-spine topologies and dual-ported SmartNIC / NVMe enclosures require sub-millisecond failover across Asymmetric Namespace Access (ANA) paths to prevent transfer stalls during cable pulls, firmware updates, or PCIe switch flaps.

To resolve these bottlenecks, Velcrux requires a **SmartNIC / DPU Offloaded Direct-to-NVMe Storage Fabric** implementing **NVMe-oF 1.1 over RoCEv2 RDMA** in 100% pure safe Rust.

---

## 2. Decision Drivers

- **Zero-Copy Host CPU Bypass**: Bridge incoming RoCEv2 RDMA memory keys (`rkey`) directly into NVMe controller PCIe DMA rings via Peer-to-Peer (P2P) DMA, completely bypassing host DRAM and host CPU cycles.
- **Strict NVMe-oF 1.1 Protocol Adherence**:
  - 64-byte Submission Queue Entry (SQE) Command Capsules.
  - 16-byte Completion Queue Entry (CQE) Response Capsules.
  - 16-byte Keyed Scatter-Gather List (SGL) Data Block Descriptors.
  - 1024-byte Fabric Connect data payloads with 64-bit NVMe Qualified Names (NQNs).
- **Logical Block Addressing (LBA) Namespaces**: Provision sector-aligned storage namespaces supporting 512-byte and 4096-byte LBA formats, sparse block allocation, CRC32 integrity tracking, and TRIM/deallocate operations.
- **Asymmetric Namespace Access (ANA) & Virtual Subsystem**: Support multi-controller topologies reporting `Optimized`, `NonOptimized`, `Inaccessible`, `PersistentLoss`, and `Change` states.
- **Sub-Millisecond Multipath Failover**: Provide an asynchronous multipath router supporting active-passive and round-robin load distribution with automatic path failover upon controller degradation.
- **Host CPU Cycle Accounting**: Quantify exact host CPU cycles saved per I/O transaction ($3\text{ cycles/byte} + 4,000\text{ cycles/op}$), direct-to-NVMe line-rate throughput, IOPS, and P2P DMA efficiency ($>99\%$).
- **Zero Unsafe Code**: 100% `#![forbid(unsafe_code)]` compliance across all crates.

---

## 3. Considered Options

- **Option 1: Traditional Kernel Block Layer (Linux NVMe-oF Target & Initiator)**:
  - *Cons*: Heavy reliance on kernel modules (`nvmet`, `nvme-rdma`), root privileges, C codebases, and significant host CPU utilization.
- **Option 2: Userspace SPDK (Storage Performance Development Kit in C)**:
  - *Cons*: Massive C dependency footprint, complex C FFI bindings, unsafe pointer manipulation, and memory safety hazards.
- **Option 3 (Chosen): Pure Safe-Rust SmartNIC DPU Direct-to-NVMe Fabric (`Option DC`)**:
  - Pure safe Rust implementation with zero external C dependencies.
  - Memory-safe capsule serialization/deserialization.
  - SmartNIC DPU offload engine simulating P2P PCIe DMA direct transfers between RoCEv2 RDMA buffers and NVMe namespaces.
  - Transparent multipath failover with real-time CPU cycle savings telemetry.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│             SMARTNIC / DPU DIRECT-TO-NVME FABRIC (NVMe-oF OVER RDMA)                   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   Incoming RoCEv2 RDMA Packets (BTH/RETH/AETH)                                         │
│   [rkey: 0xDEADBEEF, Remote Address: 0x7FFF_8000_1000, Length: 64 KB]                  │
│                             │                                                          │
│                             ▼                                                          │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ SmartNIC / DPU Offload Engine (DpuOffloadEngine)  │                                │
│   │ ─ Keyed SGL Validation & P2P DMA Orchestration    │                                │
│   │ ─ Bypasses Host DRAM & Host CPU Execution Cores   │                                │
│   │ ─ Calculates CPU Cycles Saved (3 cyc/B + 4K/op)   │                                │
│   └─────────────────────────┬─────────────────────────┘                                │
│                             │                                                          │
│              Peer-to-Peer   │ Direct PCIe DMA Ring                                     │
│              (Zero-Copy)    ▼                                                          │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ NVMe Multipath Router (NvmeMultipathRouter)       │                                │
│   │ ─ Path Selection: LowestLatency / RoundRobin / AP │                                │
│   │ ─ ANA Status Tracker: Optimized vs Inaccessible   │                                │
│   │ ─ Sub-Millisecond Automatic Path Failover         │                                │
│   └───────────────┬───────────────────┬───────────────┘                                │
│                   │                   │                                                │
│         Path A (Optimized)   Path B (Standby/Failover)                                 │
│                   ▼                   ▼                                                │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ NVMe Subsystem & Controllers (NvmeSubsystem)      │                                │
│   │ ─ Admin Queue Pair (ASQ/ACQ)                      │                                │
│   │ ─ I/O Queue Pairs (IOSQ/IOCQ)                     │                                │
│   │ ─ Fabric Connect / Disconnect Handshakes          │                                │
│   └─────────────────────────┬─────────────────────────┘                                │
│                             │                                                          │
│                             ▼                                                          │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ NVMe LBA Namespaces (NvmeNamespace)               │                                │
│   │ ─ 512B / 4096B Sector-Aligned Buffer Management   │                                │
│   │ ─ Sparse Sector Allocation (BTreeMap<u64, Vec>)   │                                │
│   │ ─ Read / Write / Flush / TRIM / CRC32 Checksums   │                                │
│   └───────────────────────────────────────────────────┘                                │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1. NVMe-oF 1.1 Wire Protocol Capsules

1. **Submission Queue Entry (SQE)**: Standard 64-byte command containing opcode, command ID, target NSID, CDW2/CDW3 parameters, starting LBA (`slba`), block count (`nlb`), and a 16-byte Scatter-Gather List (`NvmeSglDescriptor`).
2. **Completion Queue Entry (CQE)**: Standard 16-byte response containing command-specific result, SQ head pointer, SQ ID, command ID, and status code (including phase tag bit).
3. **Keyed SGL Data Block Descriptor**: Encodes 64-bit remote RDMA memory address, 32-bit transfer length, and 32-bit `rkey` authorization token.
4. **Fabric Connect Capsule**: 1024-byte payload carrying Host UUID, target Subsystem NQN, and Host NQN.

### 4.2. SmartNIC DPU Direct-to-NVMe Offload Pipeline

The DPU offload engine inspects incoming SQE commands with Keyed SGL descriptors and directly connects the RoCEv2 RDMA memory keys to NVMe block operations:
- Host memory is never allocated or touched during I/O.
- CPU cycles saved is computed deterministically:
  $$\text{Cycles Saved} = (\text{Bytes Transferred} \times 3) + 4000$$
- DMA efficiency is monitored against PCIe Gen5 x16 link capabilities ($>99.4\%$).

### 4.3. Multipath Topology & Automatic Failover

`NvmeMultipathRouter` maintains health state and latency for multiple physical/virtual controller paths. When a primary controller transitions to `AnaState::Inaccessible` or returns `NVME_STATUS_NAMESPACE_NOT_READY`, the router immediately flags the path unhealthy, increments the failover metric, and reroutes the I/O to a secondary healthy controller.

---

## 5. Consequences

### Positive
- **Dramatic Host CPU Savings**: Eliminates $>90\%$ of host CPU utilization during line-rate bulk storage transfers, freeing compute cores for tenant applications.
- **Sub-Millisecond Flash Latency**: Eliminates kernel context switching and memory bus contention, reducing tail latency down to single-digit microseconds.
- **Enterprise High Availability**: Multi-controller Asymmetric Namespace Access (ANA) and automatic multipath failover ensure continuous data streaming across path failures.
- **Pure Memory Safety**: Fully compliant with safe Rust (`#![forbid(unsafe_code)]`), avoiding vulnerabilities typical of C/C++ storage drivers.

### Negative / Trade-offs
- **Hardware Requirement for P2P DMA**: Achieving physical P2P DMA in deployment requires PCIe Gen4/Gen5 switches supporting Peer-to-Peer transactions between SmartNIC DPUs and NVMe SSDs.
- **Memory Consumption in Emulated Mode**: In software simulation, sparse block allocation stores dirty blocks in userspace memory tables before persistence.

---

## 6. References

- NVM Express over Fabrics Revision 1.1 Specification.
- NVM Express Base Specification Revision 2.0.
- ADR-067: Enterprise Hardware RDMA RoCEv2 Verbs Acceleration Engine.
- ADR-070: Autonomous AI/ML Transfer Anomaly Detection & Self-Healing Traffic Shaper.
