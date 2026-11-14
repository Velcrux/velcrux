# ADR-083: Autonomous Zero-Copy QUIC Kernel-Bypass Direct NIC Memory Fabric (AF_XDP / UMEM)

- **Status**: Accepted
- **Date**: 2026-11-14
- **Deciders**: Velcrux Distributed Systems, High-Performance Networking, Kernel Systems, SRE, and Protocol Architecture Teams
- **Consulted**: SmartNIC Hardware Engineering, 100GbE Infrastructure, and Edge Datacenter Teams

---

## 1. Context and Problem Statement

At line rates of 25GbE, 40GbE, and 100GbE, conventional Linux network stack processing encounters severe CPU bottlenecks:

1. **Kernel SKB Allocation & Deallocation Overhead**:
   Allocating and freeing `sk_buff` structures per packet incurs high memory allocator contention, CPU cacheline bouncing, and TLB invalidations. At 14.88 Mpps (64-byte wire speed on 10GbE) or 148.8 Mpps (100GbE), standard kernel networking consumes 100% of available CPU cores solely handling per-packet overhead.
2. **User-Kernel Memory Copying**:
   Traditional `recvmsg`/`sendmsg` system calls copy packet payloads across user-space and kernel memory boundaries twice, burning memory bandwidth and polluting L1/L2/L3 CPU caches.
3. **Context Switching Interrupt Latency**:
   Servicing hardware network interrupts (IRQs) and transitioning through kernel-user context switches introduces microsecond-scale jitter, directly harming low-latency QUIC tail times.
4. **Fragile C Bindings & Unsafe Code**:
   Traditional DPDK or libbpf solutions require vast C codebases, root privileges, dedicated kernel modules, and unsafe pointer arithmetic susceptible to memory safety bugs.

To eliminate these bottlenecks permanently, Velcrux implements the **Autonomous Zero-Copy QUIC Kernel-Bypass Direct NIC Memory Fabric (AF_XDP / UMEM)** in 100% pure safe Rust (`#![forbid(unsafe_code)]`).

---

## 2. Decision Drivers

- **Pre-Registered User-Space Memory Pool (`NicUmemPool`)**:
  - Pre-allocates a contiguous memory region sliced into power-of-two frame buffers (default: 2048 or 4096 bytes).
  - Reserves standard 256-byte `XDP_HEADROOM` prefixes for packet metadata and driver headers.
  - Slices memory directly into DMA-accessible pages, eliminating all dynamic heap allocations on the packet hot path.
- **AF_XDP Lock-Free Circular SPSC Ring Pairs (`NicCircularRing`, `NicRingSet`)**:
  - Implements the 4 canonical AF_XDP rings with power-of-two mask modulo indexing (`idx & (cap - 1)`):
    1. **Fill Ring** (Userspace $\to$ NIC DMA): Hands empty UMEM frame addresses to the NIC.
    2. **Rx Ring** (NIC DMA $\to$ Userspace): Delivers received packet descriptors (`addr`, `len`, `flags`) without payload copying.
    3. **Tx Ring** (Userspace $\to$ NIC DMA): Submits packet descriptors directly out of UMEM for wire transmission.
    4. **Completion Ring** (NIC DMA $\to$ Userspace): Reclaims transmitted frame addresses back into the UMEM free pool.
- **Wire-Speed Zero-Copy Packet Demuxer (`NicPacketDemuxer`, `NicQuicPacketView`)**:
  - Dissects Ethernet (DIX II, 802.1Q VLAN, QinQ), IPv4/IPv6, UDP, and QUIC (RFC 9000) directly inside UMEM frame buffers.
  - Classifies QUIC Long Headers (Initial, 0-RTT, Handshake, Retry) and Short Headers (1-RTT data, spin bit, key phase).
  - Extracts Destination Connection ID (DCID) and Source Connection ID (SCID) with zero memory bouncing.
- **Cross-Platform Emulated & Driver Fallback Modes (`NicDriverMode`)**:
  - `ZeroCopyDriver`: Direct hardware DMA into UMEM (`XDP_ZEROCOPY`).
  - `CopySkbGeneric`: Fallback SKB copy mode for non-XDP-native NIC drivers.
  - `HardwareOffloadAsic`: SmartNIC FPGA on-chip packet handling.
  - `EmulatedUserSpace`: Cross-platform testing and development mode running seamlessly on macOS, BSD, and Windows.
- **Operator CLI Suite (`velcrux nic`)**:
  - `velcrux nic status [--interface <IFACE>] [--mode <MODE>] [--json]`
  - `velcrux nic pools [--interface <IFACE>] [--json]`
  - `velcrux nic rings [--interface <IFACE>] [--json]`
  - `velcrux nic benchmark [--frames <N>] [--frame-size <BYTES>] [--iterations <N>] [--json]`

---

## 3. Architecture & Key Mechanisms

```
+-----------------------------------------------------------------------------------+
|               VELCRUX DIRECT NIC MEMORY FABRIC ARCHITECTURE (ADR-083)             |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |             CONTIGUOUS UMEM MEMORY POOL (User-Space Memory)                 |  |
|  |  +----------------+  +----------------+         +-------------------------+ |  |
|  |  | Frame 0 (2048B)|  | Frame 1 (2048B)|  . . .  | Frame N-1 (2048B)       | |  |
|  |  | [Headroom][Pkt]|  | [Headroom][Pkt]|         | [Headroom][Pkt]         | |  |
|  |  +-------^--------+  +-------+--------+         +------------+------------+ |  |
|  +----------|-------------------|-------------------------------|--------------+  |
|             | Free Addrs        | Received Descs                | Transmit Descs  |
|             |                   v                               v                 |
|     +-------+-------+   +-------+-------+               +-------+-------+         |
|     |   FILL RING   |   |    RX RING    |               |    TX RING    |         |
|     |  (User -> NIC)|   |  (NIC -> User)|               |  (User -> NIC)|         |
|     +-------+-------+   +-------+-------+               +-------+-------+         |
|             |                   ^                               |                 |
|             | Hardware DMA      | Zero-Copy DMA                 | Wire Egress     |
|             v                   |                               v                 |
|  +-----------------------------------------------------------------------------+  |
|  |                 100GbE NETWORK INTERFACE CONTROLLER (NIC)                   |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                 |                 |
|                                         Transmitted Addrs       v                 |
|                                                         +-------+-------+         |
|                                                         |COMPLETION RING|         |
|                                                         |  (NIC -> User)|         |
|                                                         +-------+-------+         |
|                                                                 |                 |
|                                                                 v                 |
|                                                         [Reclaim to UMEM]         |
+-----------------------------------------------------------------------------------+
```

### Zero-Copy Packet Lifecycle

1. **Ring Priming**:
   The fabric allocates a batch of free frame indices from `NicUmemPool` and enqueues their physical UMEM byte addresses (`base_addr + headroom`) into the `FillRing`.
2. **Hardware DMA Ingress**:
   Incoming network packets are written by the NIC DMA directly into the physical UMEM frame without passing through kernel socket buffers. The NIC posts a descriptor (`addr`, `len`) to the `RxRing`.
3. **Wire-Speed Demux & Fast-Path Dispatch**:
   Userspace dequeues descriptors from the `RxRing`. `NicPacketDemuxer` inspects the frame slice, classifies L2-L4 headers and L7 QUIC Connection IDs (DCID), and hands the zero-copy frame view directly to the active QUIC connection engine.
4. **Zero-Copy Egress**:
   Outgoing QUIC packets are written directly into an allocated UMEM frame at `headroom` offset. A descriptor is posted to the `TxRing`.
5. **Reclaim & Recycle**:
   Upon hardware wire completion, the NIC posts the frame address to the `CompletionRing`. The fabric pops the address and returns the frame index back to the `NicUmemPool` free-list stack. Zero heap allocations occur throughout the entire lifecycle.

---

## 4. Consequences

### Positive

- **True Zero-Copy Line-Rate Throughput**: Avoids all memory copies between kernel and userspace, enabling multi-gigabit line-rate packet processing with sub-microsecond cycle latency.
- **Zero Heap Allocations on Hot Path**: Pre-registered UMEM pool eliminates memory allocator locks, fragmentation, and garbage collection pauses.
- **100% Pure Safe Rust**: Strictly `#![forbid(unsafe_code)]` with zero external C dependencies, ensuring memory safety, thread safety, and cross-platform compilation.
- **Deterministic Cross-Platform Emulation**: Runs natively with hardware zero-copy bypass on Linux AF_XDP and provides emulated zero-copy testing harnesses on macOS, BSD, and Windows.

### Neutral / Trade-offs

- **Pre-Allocated Memory Footprint**: UMEM pool requires contiguous virtual memory (e.g. 8–64 MiB). This memory is pinned during transfer execution.
- **Fixed Frame Granularity**: Frames are fixed at power-of-two sizes (e.g. 2048 or 4096 bytes). Packets smaller than the frame size do not share frames, trading a small amount of memory overhead for zero-fragmentation constant-time indexing.

---

## 5. Verification

1. **Unit Tests**:
   - `crates/velcrux-core/src/nic/mod.rs`: UMEM pool allocation and bounds, circular ring power-of-two rollover, QUIC Long/Short header demuxing, replenish/reclaim lifecycle, end-to-end loopback, and benchmark runner (6 unit tests).
2. **Core Integration Tests**:
   - `crates/velcrux-core/tests/nic_memory_fabric_tests.rs`:
     - `test_nic_umem_pool_multiframe_concurrency_and_exhaustion`
     - `test_nic_ring_pairs_power_of_two_rollover_under_saturation`
     - `test_nic_quic_packet_demux_vlan_qinq_and_short_headers`
     - `test_nic_fabric_line_rate_burst_loopback_and_zero_copy`
     - `test_nic_driver_modes_and_hardware_offload_profile`
     - `test_nic_benchmark_simulation_throughput_and_reuse`
3. **CLI Integration Tests**:
   - `crates/velcrux-client/tests/cli_nic.rs`:
     - `test_cli_nic_status_text_and_json`
     - `test_cli_nic_pools_text_and_json`
     - `test_cli_nic_rings_text_and_json`
     - `test_cli_nic_benchmark_text_and_json`
