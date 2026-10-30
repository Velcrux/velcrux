# ADR-048: Autonomous Multi-Path WAN Slicing & Sub-Millisecond Dynamic Interface Bonding

Status: Accepted · Date: 2026-10-30

## Context

High-throughput distributed storage replication and multi-datacenter synchronization frequently operate across heterogeneous, asymmetric WAN uplinks concurrently available on physical host machines:
- **Primary Terrestrial Fiber**: Ultra-high bandwidth ($100\,\text{Gbps}$), low latency ($1\text{--}5\,\text{ms}$ RTT), negligible packet loss.
- **Secondary Enterprise Ethernet**: Moderate bandwidth ($10\,\text{Gbps}$), standard latency ($5\text{--}15\,\text{ms}$ RTT).
- **Satellite (LEO / Starlink)**: Variable bandwidth ($100\text{--}300\,\text{Mbps}$), higher latency ($25\text{--}45\,\text{ms}$ RTT), orbital handoff jitter ($5\text{--}15\,\text{ms}$), and periodic micro-fades.
- **Cellular (5G / NR)**: Burst bandwidth ($500\text{--}1000\,\text{Mbps}$), radio contention latency ($15\text{--}30\,\text{ms}$ RTT).

Prior multi-interface bonding mechanisms (such as Linux LACP / 802.3ad or static round-robin packet bonding) fail over WAN networks with asymmetric latencies:
1. **Severe Out-of-Order Head-of-Line (HOL) Blocking**: Packets routed over slower satellite links arrive tens of milliseconds after packets sent over fiber. In single-stream transport or rigid reassembly buffers, the receiving pipeline stalls completely waiting for lagging packets, collapsing effective throughput to the slowest link.
2. **Bufferbloat & Delay Inversion**: Without continuous sub-millisecond quality probing (OWD, SRTT, jitter, ECN marks), schedulers pump data blindly into lossy, congested cellular or satellite links, inducing bufferbloat and packet drop spikes.
3. **Monolithic Chunk Bottlenecks**: Distributing entire multi-megabyte chunks as indivisible units over disparate paths results in link underutilization when large chunks block on slow interfaces while fast fiber links idle.

To maximize throughput across heterogeneous uplinks and eliminate Head-of-Line blocking, Velcrux requires an autonomous chunk-level WAN slicing engine (`WanSlicer`) and dynamic interface bonding aggregator with zero-HOL reassembly.

---

## Options Considered

1. **Option 1: Kernel LACP / 802.3ad Bonding**:
   - Rely on OS-level Ethernet trunking or hash-based bonding (`balance-rr` or `layer3+4`).
   - *Rejected*: Inapplicable across distinct IP subnets and heterogeneous uplinks. Round-robin bonding across links with unequal latencies produces massive packet reordering, destroying TCP/QUIC congestion control.
2. **Option 2: Course-Grained Whole-Chunk Round-Robin**:
   - Assign complete chunks ($1\,\text{MiB}\text{--}4\,\text{MiB}$) to different interfaces in round-robin fashion.
   - *Rejected*: Slower satellite/cellular links take tens of times longer to complete chunk delivery, delaying final manifest reconciliation and starving downstream consumers.
3. **Option 3: Autonomous Multi-Path WAN Slicing & Dynamic Interface Bonding (`ADR-048`)**:
   - Slices chunks into bounded MTU-aligned frames ($16\,\text{KiB}\text{--}64\,\text{KiB}$).
   - Dispatches slices using Deficit Weighted Round Robin (DWRR) proportional to each path's dynamic capacity score:
     $$\text{CapacityEff}_i = \frac{\text{CapacityMbps}_i}{\max(1, \text{SRTT\_ms}_i)} \times \text{LossFactor}_i \times \text{EcnFactor}_i$$
   - Executes sub-millisecond path quality probes (OWD, SRTT, jitter, ECN-CE, and loss ratio) to continuously tune interface weights and trigger automatic degradation gating.
   - Employs a Zero-HOL Reassembly engine (`WanReassembler`) where independent chunks reassemble completely independently without blocking each other.

---

## Decision

Adopt **Option 3: Autonomous Multi-Path WAN Slicing & Dynamic Interface Bonding (`ADR-048`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------------+
|                  Velcrux Autonomous Multi-Path WAN Slicing & Bonding Engine             |
|                                                                                         |
|  [ Ingress Chunk Payload (e.g. 1 MiB) ]                                                 |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐                            |
|   │ Dynamic WAN Slicer: Bounded Slice Frames (32 KiB)      │                            |
|   └────────────────────────────────────────────────────────┘                            |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐   ┌──────────────────────┐ |
|   │ Dynamic Capacity & Quality Scoring:                    │◄──┤ Sub-Millisecond      │ |
|   │   Score = (Capacity / SRTT) * (1-Loss) * (1-ECN)       │   │ Quality Probes       │ |
|   └────────────────────────────────────────────────────────┘   │ (OWD, RTT, Jitter)   │ |
|             │                                                  └──────────────────────┘ |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐                            |
|   │ Deficit Weighted Round-Robin (DWRR) Schedule           │                            |
|   └────────────────────────────────────────────────────────┘                            |
|        │                    │                   │                     │                 |
|        ▼ (98% Slices)       ▼ (2% Slices)       ▼ (<1% Slices)        ▼ (<1% Slices)    |
|   [wan0-fiber100g]    [wan1-eth10g]       [wan2-starlink]       [wan3-cellular5g]       |
|   100 Gbps, 2ms RTT   10 Gbps, 10ms RTT   250 Mbps, 32ms RTT    750 Mbps, 22ms RTT      |
|        │                    │                   │                     │                 |
|        └────────────────────┴─────────┬─────────┴─────────────────────┘                 |
|                                       │ Heterogeneous WAN Links                         |
|                                       ▼                                                 |
|   ┌──────────────────────────────────────────────────────────────────────────────────┐  |
|   │ Zero-HOL Reassembler: Independent Chunk Sliding Buffer                           │  |
|   │   - Tracks per-chunk slice indices (0..total_slices)                             │  |
|   │   - Independent chunks emit immediately upon full arrival                        │  |
|   │   - Missing slice gap timeout triggers fast-retransmit alert                     │  |
|   │   - BLAKE3 verification on reassembled payload                                   │  |
|   └──────────────────────────────────────────────────────────────────────────────────┘  |
+-----------------------------------------------------------------------------------------+
```

### Path Capacity Scoring Formulation

For each bonded interface $i$:
$$\text{CapacityEff}_i = \frac{\text{CapacityMbps}_i}{\max(1, \text{SRTT\_ms}_i)}$$
$$\text{LossFactor}_i = \max\left(0.05, 1.0 - \frac{\text{LossBasisPoints}_i}{1000.0}\right)$$
$$\text{EcnFactor}_i = \max\left(0.10, 1.0 - \frac{\text{EcnBasisPoints}_i}{2000.0}\right)$$
$$\text{DynamicWeight}_i = \text{Norm}\Big(\text{CapacityEff}_i \times \text{LossFactor}_i \times \text{EcnFactor}_i\Big)$$

When link quality degrades (e.g. packet loss $> 5\%$ or RTT inflates by $4\times$), the interface automatically transitions to `Degraded` mode, throttling its scheduled slice quota until probe measurements recover.

---

## Consequences

### Positive
- **True Uplink Aggregation**: Seamlessly bonds high-speed fiber with backup Ethernet, Starlink, or 5G without link starvation or latency penalties.
- **Zero Head-of-Line Blocking**: Chunk-level reassembly ensures faster chunks are committed immediately; slow slices only defer their parent chunk.
- **Sub-Millisecond Probe Adaptability**: High-frequency telemetry updates interface weights in real time as satellite and cellular links fluctuate.
- **Safe Memory Utilization**: In-flight reassembly buffers allocate strictly for active chunk frames and free immediately upon BLAKE3 verification.

### Negative / Trade-offs
- **Reordering Header Overhead**: Slices prepend small frame headers (sequence, offset, total slices, chunk hash), consuming $< 0.1\%$ wire overhead on 32 KiB slices.
- **Reassembly Buffer Memory**: Reordering buffers temporarily hold out-of-order slices until missing slices arrive.
