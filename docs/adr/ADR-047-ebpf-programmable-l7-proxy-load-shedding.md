# ADR-047: eBPF-Driven Programmable L7 Proxying & Dynamic Layer-7 Load Shedding

Status: Accepted · Date: 2026-10-30

## Context

Velcrux clusters multiplex diverse QUIC stream types over shared network connections: latency-critical session heartbeats (`PING`, `HELLO`, `AUTH`), transfer cancellation signals (`CANCEL`), manifest metadata exchanges, high-volume bulk chunk streaming, and background maintenance tasks (gossip sync, storage scrubbing).

Under severe infrastructure resource saturation—such as CPU exhaustion, memory pressure, internal socket queue buildup, or WAN RTT inflation—naive Layer-4 queueing or indiscriminate packet drops lead to catastrophic cluster degradation:
1. **Cascading Control Dropouts**: When control frames (heartbeats, authentication handshakes, cancellation notices) share buffer queues with multi-gigabyte bulk streams, queue overflow drops control packets indiscriminately, causing false-positive peer timeouts, failed re-elections, and cluster reconnection storms.
2. **Bufferbloat & Tail Latency Collapse**: Unregulated bulk streaming under high load inflates end-to-end RTT, starving interactive client requests and manifest synchronizations.
3. **Lack of Tenant-Aware Enforcement**: Unprivileged or rogue tenants streaming heavy workloads can monopolize buffer capacity, degrading SLA guarantees for higher-tier production tenants.

To guarantee zero control-plane dropouts and preserve high throughput during resource spikes, Velcrux requires an eBPF-driven programmable Layer-7 proxying engine with dynamic, multi-tier load shedding.

---

## Options Considered

1. **Option 1: Static Layer-4 OS / iptables / eBPF TC Dropping**:
   - Apply standard Linux Traffic Control (`tc`) or iptables rules to drop UDP datagrams when interface queues fill.
   - *Rejected*: Layer-4 packet filters are blind to QUIC stream frames. They cannot distinguish a critical `CANCEL` or `AUTH` stream frame from a background chunk payload inside an encrypted QUIC packet, causing control connection collapse.
2. **Option 2: Uncoordinated Application-Level Backpressure**:
   - Allow individual session endpoints to apply ad-hoc flow-control backpressure when buffers fill.
   - *Rejected*: Lacks unified cluster-wide pressure awareness, cannot enforce tenant rate-policing across streams, and responds too slowly to sudden CPU or memory spikes.
3. **Option 3: eBPF-Driven Programmable L7 Proxying & Dynamic Layer-7 Load Shedding (`ADR-047`)**:
   - Implement a pure safe Rust programmable Layer-7 proxy and shedding cascade that classifies streams into 5 distinct priority tiers.
   - Enforce the non-negotiable invariant that **Control streams (`HELLO`, `AUTH`, `CANCEL`, `PING`, `ERROR`) are strictly non-sheddable** under 100% load.
   - Compute a composite Pressure Score ($0\text{--}100\%$) based on CPU, memory, queue depth, and RTT inflation.
   - Apply a dynamic load shedding cascade: shed `Background` and `BulkLow` tiers first, throttle `BulkHigh`, while admitting `Interactive` and `Control` traffic.
   - Support programmable tenant/path rules, token bucket rate policing, Prometheus telemetry, and microsecond-level dispatch latency.

---

## Decision

Adopt **Option 3: eBPF-Driven Programmable L7 Proxying & Dynamic Layer-7 Load Shedding (`ADR-047`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------------+
|                    Velcrux eBPF Programmable L7 Proxy & Shedding Engine                 |
|                                                                                         |
|  [ Ingress QUIC Stream / Datagram ]                                                     |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐                            |
|   │ Control Flow Check (Stream ID 0 / Control Stream Type) │ ──(Strict Invariant)──┐    |
|   └────────────────────────────────────────────────────────┘                       │    |
|             │ (Non-control)                                                        │    |
|             ▼                                                                      │    |
|   ┌────────────────────────────────────────────────────────┐                       │    |
|   │ 5-Tier Classification: Control, Interactive,           │                       │    |
|   │                        BulkHigh, BulkLow, Background   │                       │    |
|   └────────────────────────────────────────────────────────┘                       │    |
|             │                                                                      │    |
|             ▼                                                                      │    |
|   ┌────────────────────────────────────────────────────────┐                       │    |
|   │ Dynamic Composite Pressure Sensor (0 - 100%)           │                       │    |
|   │   0.35*CPU + 0.25*Mem + 0.25*Queue + 0.15*RTT          │                       │    |
|   └────────────────────────────────────────────────────────┘                       │    |
|             │                                                                      │    |
|             ▼                                                                      │    |
|   ┌────────────────────────────────────────────────────────┐                       │    |
|   │ Programmable L7 Rules Engine (Tenant, Path, Precedence)│                       │    |
|   └────────────────────────────────────────────────────────┘                       │    |
|             │                                                                      │    |
|             ▼                                                                      │    |
|   ┌────────────────────────────────────────────────────────┐                       │    |
|   │ Dynamic Load Shedding Cascade:                         │                       │    |
|   │   Pressure >= 90%: Shed Background, BulkLow; Throttle  │                       │    |
|   │   Pressure >= 75%: Shed Background; Throttle BulkLow   │                       │    |
|   │   Pressure >= 50%: Throttle Background                 │                       │    |
|   │   Pressure <  50%: Admit All Flow Tiers                │                       │    |
|   └────────────────────────────────────────────────────────┘                       │    |
|             │                                                                      │    |
|             ▼                                                                      ▼    |
|   ┌──────────────────────────────────────────────────────────────────────────────────┐  |
|   │ Verdict Dispatch: [ Admit ]  /  [ Throttle ]  /  [ Shed ]  /  [ Reroute ]        │  |
|   └──────────────────────────────────────────────────────────────────────────────────┘  |
+-----------------------------------------------------------------------------------------+
```

### Flow Classification Tiers

| Tier | Name | Target Traffic Types | Load Shedding Invariant |
| :--- | :--- | :--- | :--- |
| **0** | `Control` | `HELLO`, `AUTH`, `CANCEL`, `PING`, `ERROR` | **Strictly Non-Sheddable** (100% admitted under all pressure) |
| **1** | `Interactive` | Manifest catalog queries, metadata reconciliation, user status | Admitted except under manual operator override |
| **2** | `BulkHigh` | Transactional payload chunks, primary tenant replications | Throttled under critical pressure ($\ge 90\%$) |
| **3** | `BulkLow` | Routine multi-gigabyte sync, warm tier transfers | Shed at $\ge 90\%$; Throttled at $\ge 75\%$ |
| **4** | `Background` | Storage scrub sweeps, epidemic gossip, speculative prefetch | Shed at $\ge 75\%$; Throttled at $\ge 50\%$ |

### Dynamic Composite Pressure Formulation

System pressure is evaluated dynamically using real-time telemetry inputs:
$$\text{Pressure} = 0.35 \cdot \text{CPU} + 0.25 \cdot \text{Memory} + 0.25 \cdot \text{QueueOccupancy} + 0.15 \cdot \text{RTTInflation}$$

When $\text{Pressure} \ge 90\%$, the engine transitions to Emergency Shedding mode, protecting system survival by dropping lower-priority payload transfers while servicing control-plane heartbeats and interactive queries with sub-microsecond evaluation latency.

---

## Consequences

### Positive
- **Guaranteed Cluster Stability**: Control streams are never dropped under high system stress, eliminating cascade disconnections and false failovers.
- **Microsecond Decision Path**: Safe Rust L7 rule engine evaluates classification and shedding verdicts in $< 1\,\mu\text{s}$ per stream.
- **Tenant Isolation**: Tenant-specific rate policing and prefix-based routing ensure misbehaving tenants do not degrade shared infrastructure.
- **Full Operational Observability**: Real-time Prometheus counters and histograms track routed, shed, throttled, and active flows alongside composite pressure.

### Negative / Trade-offs
- **Lower Priority Transfer Delays**: Heavy background and bulk transfers experience intentional shedding or throttling when pressure exceeds configured thresholds, requiring client retry logic.
- **Telemetry Overhead**: Regular sampling of host CPU, memory, socket queues, and RTT adds minimal CPU consumption ($< 0.1\%$).
