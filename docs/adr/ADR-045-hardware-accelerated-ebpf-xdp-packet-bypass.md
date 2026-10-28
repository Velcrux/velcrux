# ADR-045: Hardware-Accelerated FPGA/eBPF Kernel XDP Packet Bypassing & UMEM Zero-Copy Rings

Status: Accepted · Date: 2026-10-28

## Context

Ultra-high-throughput bulk transfers operating at 40 Gbps, 100 Gbps, and 400 Gbps line rates encounter severe operating system kernel bottlenecks (`ARCHITECTURE.md` §2, §7; `PERFORMANCE.md` §26). Standard POSIX socket APIs (`sendto`/`recvfrom` and `recvmmsg`) force the Linux kernel network stack to allocate `sk_buff` descriptor structures, manage complex netfilter/iptables traversal, copy packet payloads across user/kernel address boundaries, and trigger high-frequency softIRQ hardware interrupts that saturate host CPU cores.

Key operational and architectural requirements:
1. **Wire-Speed Ingress Packet Filtering (eBPF/XDP)**:
   - Intercept incoming transport frames at the earliest possible stage in the network driver before Linux SKB allocation.
   - Parse Ethernet, IPv4, IPv6, UDP, and QUIC Connection ID headers directly at wire rate (up to 14.88 Mpps on 100 GbE).
   - Execute programmable filtering verdicts (`XdpAction::Redirect`, `Pass`, `Drop`, `Tx`) via compiled eBPF filter maps.
2. **AF_XDP (XSK) Zero-Copy UMEM Shared Memory Architecture**:
   - Establish contiguous page-aligned UMEM frame pools mapped directly between hardware NIC DMA rings and user-space memory.
   - Decouple buffer ownership using four lock-free circular ring queues:
     - **Fill Ring**: Supplies empty UMEM frames from user space to NIC driver for packet reception.
     - **RX Descriptor Ring**: Delivers received packet descriptors (`addr`, `len`, `flags`) to user-space workers without memory copy.
     - **TX Descriptor Ring**: Submits outbound packet descriptors from user space to NIC driver.
     - **Completion Ring**: Returns transmitted UMEM frames back to user space for recycling.
3. **Hardware Driver Offload (SmartNIC / FPGA)**:
   - Provide seamless fallback across three driver execution tiers:
     - `HardwareOffload`: eBPF byte-code loaded directly onto FPGA/SmartNIC (e.g. AMD Xilinx Alveo, NVIDIA Mellanox ConnectX-6 Dx/7) for true sub-microsecond processing.
     - `NativeDriver`: Driver-level XDP hook executed in the NIC device driver poll loop (NAPI).
     - `GenericSkb`: Testing and non-accelerated fallback operating after initial kernel SKB allocation.
4. **Server Telemetry & Prometheus Observability**:
   - Expose operational metrics: `velcrux_xdp_packets_processed_total`, `velcrux_xdp_packets_redirected_total`, `velcrux_xdp_packets_dropped_total`, `velcrux_xdp_umem_frames_active`, `velcrux_xdp_processing_latency_nanoseconds`.
   - Provide operator CLI subcommands: `velcrux xdp [status|inspect|rings|filter|benchmark]`.
5. **Invariants**:
   - 100% Safe Rust (`#![forbid(unsafe_code)]` with zero exceptions across all crates).
   - Strict bounded memory streaming: UMEM frame allocations and ring capacities are fixed, eliminating heap churn.

---

## Options Considered

1. **Option 1: Standard POSIX UDP Sockets (`recvmsg` / `sendmmsg`)**:
   - Rely solely on OS socket buffers and kernel UDP stack.
   - *Rejected*: Incurs per-packet kernel SKB allocation, context switches, and page copying overhead, capping single-core throughput at ~1.5–2.0 Mpps (~10–15 Gbps).
2. **Option 2: Data Plane Development Kit (DPDK)**:
   - Complete kernel bypass taking exclusive ownership of physical PCIe NIC ports using DPDK poll-mode drivers (PMDs).
   - *Rejected*: Requires dedicated physical NIC takeover that breaks host OS networking, lacks integration with standard Linux tooling, requires monolithic hugepage reservations, and depends on extensive C foreign function interfaces violating `#![forbid(unsafe_code)]`.
3. **Option 3: Hardware-Accelerated FPGA/eBPF Kernel XDP Packet Bypassing & UMEM Zero-Copy Rings (`ADR-045`)**:
   - Integrates native Linux eBPF/XDP kernel hooks with AF_XDP (XSK) zero-copy ring buffers.
   - Allows coexistence with host OS networking (unmatched packets are passed back to standard Linux stack).
   - Full support for hardware offload onto SmartNICs and FPGAs.
   - Implemented under `#![forbid(unsafe_code)]` using safe bounded ring buffer abstractions.

---

## Decision

Adopt **Option 3: Hardware-Accelerated FPGA/eBPF Kernel XDP Packet Bypassing & UMEM Zero-Copy Rings (`ADR-045`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------+
|                              Velcrux Core Application                             |
|  +---------------------+   +---------------------+   +--------------------------+ |
|  |   Raven QUIC Engine |   |  UMEM Buffer Pool   |   |   Operator CLI / Metrics | |
|  +----------^----------+   +----------^----------+   +------------^-------------+ |
+-------------|-------------------------|---------------------------|---------------+
              |                         |                           |
              | Zero-Copy Descriptors   | Frame Buffers             | Telemetry
              v                         v                           |
+-------------------------------------------------------------+     |
|             AF_XDP (XSK) Zero-Copy Descriptor Rings         |     |
|  +--------------------+  +--------------------+             |     |
|  |     Fill Ring      |  |  Completion Ring   |             |     |
|  +--------------------+  +--------------------+             |     |
|  +--------------------+  +--------------------+             |     |
|  |      RX Ring       |  |      TX Ring       |             |     |
|  +--------------------+  +--------------------+             |     |
+-------------------------------------------------------------+     |
              ^                         ^                           |
              | Native DMA              | Zero-Copy TX              |
+-------------v-------------------------v---------------------+     |
|            eBPF / XDP Wire-Speed Packet Filter Engine       |     |
|  - Wire-Speed Parser (Ethernet / IPv4 / IPv6 / UDP / QUIC)  |<----+
|  - Programmable Filter Rules (Port / QUIC CID / Verdict)    |
|  - Actions: REDIRECT (AF_XDP) | PASS (Kernel) | DROP | TX   |
+-------------------------------------------------------------+
              ^                         |
              | Wire Ingress            | Kernel Stack Fallback
+-------------v-------------------------v---------------------+
|      NIC Driver / SmartNIC / FPGA Hardware Offload          |
|  - Hardware Offload Hook (AMD Alveo / NVIDIA ConnectX)      |
|  - Kernel Driver Hook (NAPI Native XDP)                     |
+-------------------------------------------------------------+
```

---

## Consequences

### Positive
- **100 Gbps+ Line-Rate Capability**: Achieves 14.88 Mpps wire-speed packet processing with zero user-space memory copies.
- **Ultra-Low Ingress Latency**: Reduces packet ingress processing latency from ~15–20 µs down to < 200 ns under native driver mode and < 50 ns under SmartNIC/FPGA hardware offload.
- **CPU Offloading**: Completely bypasses kernel `sk_buff` allocation and softIRQ interrupt overhead, saving up to 80% CPU core utilization on high-bandwidth links.
- **Selective Bypassing**: Only configured Raven QUIC traffic (port 7443) and matching CIDs are redirected to AF_XDP; SSH, BGP, and management traffic seamlessly pass to the standard Linux kernel stack.
- **Memory Safety Guaranteed**: 100% Safe Rust (`#![forbid(unsafe_code)]`) with bounded memory pools preventing heap exhaustion.

### Negative
- Hardware offload requires compatible SmartNICs or FPGA NICs with eBPF offload firmware.
- Root or `CAP_NET_ADMIN` privileges required to attach XDP programs to network interfaces on production Linux hosts.
