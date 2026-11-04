# ADR-066: eBPF / XDP Kernel Bypass Acceleration & AF_XDP Multi-Queue Flow Steering

- **Status**: Accepted
- **Date**: 2026-11-04
- **Deciders**: Velcrux Core Networking, Transport, Systems Architecture, and High-Performance I/O Teams
- **Consulted**: Platform Engineering, Linux Kernel Performance, DevOps, and Site Reliability Teams

---

## 1. Context and Problem Statement

High-throughput peer-to-peer transport protocols operating over QUIC (RFC 9000) at 40 Gbps to 100 Gbps line rates encounter severe bottlenecks when mediated through standard Linux kernel network stacks:
1. **Per-Packet Allocation Overhead**: The kernel `sk_buff` allocation, metadata tagging, netfilter/iptables traversal, and socket buffer queuing introduce significant latency and CPU overhead, capping standard UDP socket performance to approximately 1.5–2.5 Mpps per core.
2. **Context Switch and Syscall Overhead**: `recvmsg` and `sendmsg` system calls incur costly user-kernel privilege transitions, TLB flushes, and memory copy operations between kernel buffers and user space.
3. **Multi-Core Lock Contention and Cache-Line Bouncing**: Directing high-rate UDP streams to shared multi-threaded sockets incurs severe locking overhead. Packets belonging to the same QUIC connection processed across varying CPU cores induce L1/L2/L3 cache misses, out-of-order packet arrival, and cryptographic replay window churn.
4. **Hardware Offload and SmartNIC Portability**: Modern SmartNICs and DPUs (e.g., Mellanox ConnectX, Intel E810, AMD Pensando) support programmable eBPF execution directly in network interface card hardware pipelines (XDP_OFFLOAD), but require verifiable canonical eBPF bytecode without unsafe memory dereferences or unbounded loops.

---

## 2. Decision Drivers

- **Zero-Copy Line-Rate Kernel Bypass**: Deliver ultra-high packet processing throughput (> 40 Gbps line rate, tens of millions of packets per second) via Linux eBPF/XDP and AF_XDP (`XSK`) memory-mapped UMEM descriptor rings.
- **Canonical 64-Bit eBPF Virtual Machine & Verifier**: Implement a pure safe-Rust 64-bit eBPF instruction set (`EbpfInsn`), assembler (`QuicFilterAssembler`), disassembler, static verifier (`EbpfVerifier`), and in-memory execution engine (`EbpfVm`).
- **Wire-Speed Dual-Stack Packet Dissection**: Support line-rate parsing of Ethernet II frames, single/double 802.1Q/QinQ VLAN tags, IPv4, IPv6 with extension header traversal, UDP, and RFC 9000 QUIC Long and Short (1-RTT) headers with variable-length Destination Connection IDs (DCID).
- **Lock-Free AF_XDP Multi-Queue Ring Pairs**: Provide power-of-two circular lock-free ring pairs (`Fill`, `RX`, `TX`, `Completion`) for zero-copy memory transfers between the NIC driver and application user space.
- **Connection-Affinity Multi-Queue Flow Steering**: Implement `XskMap` and `XdpSocketRouter` enabling QUIC Connection ID hash steering (`SteeringPolicy::CidHash`), symmetric 4-tuple RSS steering, and round-robin distribution to pin active connections to designated CPU worker threads without cross-core lock contention.
- **Zero Unsafe Code**: 100% pure safe Rust (`#![forbid(unsafe_code)]`) with zero external C dependencies, FFI bindings, or platform-unsafe transmutes.

---

## 3. Considered Options

- **Option 1: Standard Linux Kernel UDP Sockets (`recvmsg` / `recvmmsg`)**:
  - *Cons*: High syscall overhead, per-packet memory allocation, kernel netfilter traversal, and poor multi-core scaling at > 10 Gbps line rates.
- **Option 2: DPDK (Data Plane Development Kit)**:
  - *Cons*: Requires massive proprietary C runtime dependencies, complex hugepage memory configuration, exclusive hardware NIC takeover (disabling standard OS networking), and extensive unsafe memory operations incompatible with strict memory safety guarantees.
- **Option 3 (Chosen): Native eBPF / XDP Kernel Bypass & AF_XDP Multi-Queue Steering (`Option CX`)**:
  - Direct integration into native Linux XDP hook points and AF_XDP zero-copy socket architectures.
  - Complete safe-Rust eBPF verifier ensuring DAG termination, bounded instruction counts, register safety, and jump bounds.
  - QUIC Destination Connection ID (DCID) flow steering guaranteeing single-core connection affinity and eliminating cache thrashing.
  - Zero external C dependencies under `#![forbid(unsafe_code)]`.

---

## 4. Technical Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    VELCRUX eBPF/XDP KERNEL BYPASS ARCHITECTURE                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                       │
                         [ 40G / 100G NIC Ingress Wire ]
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │       XDP Driver Hook Point         │
                    │   (Native / Hardware Offloaded)     │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │      Wire-Speed Frame Parser        │
                    │  (Ethernet II / VLAN / IPv4 / IPv6) │
                    └──────────────────┬──────────────────┘
                                       │
                         [ Match QUIC UDP Target Port ]
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │          eBPF Program / VM          │
                    │    Verified 64-Bit Bytecode Engine  │
                    │  (XDP_DROP / XDP_PASS / XDP_REDIR)  │
                    └──────────────────┬──────────────────┘
                                       │
                              [ XDP_REDIRECT ]
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │   XSKMAP Flow Steering Router       │
                    │   • QUIC DCID Hash Affinity         │
                    │   • Symmetric 4-Tuple RSS           │
                    └──────────┬───────────────┬──────────┘
                               │               │
                     Queue 0   │               │   Queue N-1
                               ▼               ▼
                    ┌────────────────┐   ┌────────────────┐
                    │ AF_XDP Ring 0  │   │ AF_XDP Ring N  │
                    │  • Fill Ring   │   │  • Fill Ring   │
                    │  • RX Ring     │   │  • RX Ring     │
                    │  • TX Ring     │   │  • TX Ring     │
                    │  • Compl Ring  │   │  • Compl Ring  │
                    └───────┬────────┘   └───────┬────────┘
                            │                    │
                            ▼                    ▼
                    ┌────────────────┐   ┌────────────────┐
                    │ Worker Core 0  │   │ Worker Core N  │
                    │  Zero-Copy I/O │   │  Zero-Copy I/O │
                    └────────────────┘   └────────────────┘
```

---

## 5. Subsystem Components

### 5.1. Verified 64-Bit eBPF Virtual Machine (`xdp/bpf.rs`)
- **Instruction Taxonomy**: Canonical 64-bit eBPF encoding (`EbpfInsn`) supporting ALU operations (`Add`, `Sub`, `Mul`, `And`, `Or`, `Xor`, `Lsh`, `Rsh`), conditional jumps (`Jeq`, `Jne`, `Jgt`, `Jge`, `Jset`), memory loads/stores (`Ldxw`, `Ldxh`, `Ldxb`, `Stxdw`, `Stxw`), and program termination (`Exit`).
- **Kernel-Grade Static Verifier**: `EbpfVerifier` analyzes program DAG reachability, instruction count bounds (<= 4096), jump destination validity, divide-by-zero prevention, read-only `R10` frame pointer preservation, and terminal `Exit` verification.
- **Pure Safe VM**: `EbpfVm` executes verified programs against memory-mapped packet metadata (`XdpMd`), returning verdicts (`XDP_PASS`, `XDP_DROP`, `XDP_TX`, `XDP_REDIRECT`).
- **Dynamic Assembler & Disassembler**: `QuicFilterAssembler` generates verified bytecode filters matching target UDP destination ports with disassembler output formatted for operator inspection.

### 5.2. Wire-Speed Dual-Stack Frame Parser (`xdp/parser.rs`)
- **Zero-Allocation Dissection**: Fast cursor-based parser dissecting L2 (Ethernet II), 802.1Q Single VLAN, and 802.1ad QinQ nested tags.
- **Dual-Stack L3 Traversal**: IPv4 header validation (IHL and options) and IPv6 extension header chaining (`HopByHop`, `Routing`, `Fragment`).
- **RFC 9000 QUIC Inspection**: Accurately extracts QUIC Long Header versions and Destination Connection IDs (DCID) up to 20 bytes, as well as Short Header (1-RTT) 8-byte connection identifiers for flow steering.

### 5.3. AF_XDP Zero-Copy Multi-Queue Ring Pairs (`xdp/ring.rs`)
- **Lock-Free Ring Queues**: Circular lock-free `XskRing<T>` structures configured with power-of-two capacities, supporting batched producer and consumer operations (`produce_batch`, `consume_batch`).
- **Hardware NIC Queue Pairs**: `XskQueuePair` aggregates `FillRing`, `RxRing`, `TxRing`, and `CompletionRing` per hardware RX/TX queue, instrumented with atomic packet, byte, and drop telemetry.

### 5.4. Flow Steering Router & XSKMAP (`xdp/steering.rs`)
- **Steering Policies**:
  - `CidHash`: QUIC Connection ID hash affinity distributing packets across queues while guaranteeing all packets for a connection land on the identical CPU core.
  - `Symmetric4Tuple`: Bidirectional flow affinity using commutative XOR hashing of source/destination IPs and ports.
  - `RoundRobin`: Equalized packet distribution across all available queues.
  - `PinToQueue`: Explicit queue pinning for high-priority streams.
- **UMEM Frame Allocation**: `XdpSocketRouter` allocates zero-copy descriptor frames directly into target RX rings, updating real-time queue distribution telemetry (`SteeringReport`).

---

## 6. CLI Integration & Operator Ergonomics

The `velcrux xdp` command suite exposes kernel bypass inspection and steering telemetry:
- **Bytecode Disassembly**:
  ```bash
  velcrux xdp dump-bpf --port 7443
  velcrux xdp dump-bpf --port 7443 --json
  ```
- **Multi-Queue Steering Telemetry**:
  ```bash
  velcrux xdp steering --queues 8 --policy cid --packets 1000
  velcrux xdp steering --queues 8 --policy cid --packets 1000 --json
  ```

---

## 7. Consequences & Guarantees

- **Guarantees**:
  - **Memory Safety**: 100% pure `#![forbid(unsafe_code)]` compliance across all parsing, verifier, VM, ring, and steering modules.
  - **Line-Rate Scaling**: Single-core QUIC packet steering eliminates cross-core lock contention and maintains warm CPU L1/L2 data caches.
  - **Verified Security**: In-memory static verifier rejects invalid jump offsets, uninitialized register writes, and divide-by-zero edge cases prior to execution.
- **Trade-offs**:
  - In non-root or unprivileged environments, simulated in-memory AF_XDP rings and fallback VM execution provide deterministic behavior for testing and staging without requiring kernel `CAP_NET_ADMIN` privileges.
