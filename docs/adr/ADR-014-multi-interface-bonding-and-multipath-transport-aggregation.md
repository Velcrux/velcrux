# ADR-014: Multi-Interface Bonding & Multi-Path QUIC Transport Aggregation

Status: Accepted · Date: 2026-10-12

## Problem

Per `REQUIREMENTS.md` §74 ("Multi-Path Future") and §75 ("NAT and Firewall Considerations"), enterprise workstations, storage nodes, and cloud instances frequently operate in multi-homed network topologies with multiple physical or virtual network interfaces:
- Dual or quad 10GbE / 25GbE / 100GbE data-center NICs.
- Heterogeneous links: 10GbE primary fiber bonded with 1GbE backup or Wi-Fi 6 / 5G.
- Multi-homed dual-stack IPv4 and IPv6 routing paths.

A single-path transport connection can only saturate the single interface to which its socket is bound. If a host possesses two 10Gbps links, single-path transport maxes out at 10Gbps while leaving the secondary 10Gbps link completely idle. Furthermore, unexpected physical link cuts or router failures on the active interface cause connection stalls or aborts unless alternate subflows are pre-warmed and immediately available.

## Options Considered

1. **OS-Level Link Aggregation (LACP / 802.3ad / Bonding)**:
   - Rely on OS bonding drivers (`bond0`).
   - *Rejected*: Requires compatible upstream switch support (LACP), works strictly within identical layer-2 broadcast domains, and cannot bond heterogeneous paths (e.g. Wi-Fi + Ethernet or public internet + VPN).
2. **Independent Parallel Client Invocations**:
   - Spawn multiple client processes transferring separate partitions of a dataset over distinct interfaces.
   - *Rejected*: Fragments transfer manifests, multiplies CPU/memory overhead, lacks coordinated bandwidth pacing, and cannot reassemble single multi-terabyte files in flight.
3. **Native Transport-Layer Multi-Path QUIC Bonding Coordinator**:
   - Implement `MultipathCoordinator` in `velcrux-core` managing bonded subflow paths across discovered or configured local network interfaces.
   - Implement continuous path quality probing (smoothed RTT, loss rate, congestion window headroom, and bandwidth estimation).
   - Provide 5 dynamic scheduling policies (`WeightedBandwidth`, `LowestLatencyFirst`, `RoundRobin`, `Redundant`, `PrimaryBackup`).
   - Provide subflow degradation detection, zero-loss hot failover, and automatic path restoration.

## Decision

Option 3. Velcrux implements native multi-interface bonding and multi-path QUIC transport aggregation with `#![forbid(unsafe_code)]`.

## Architecture & Implementation

### 1. Subflow Path Model & State Machine

Each bonded subflow path is modeled with distinct local/remote socket endpoints, link metrics, and lifecycle states:
```text
               ┌───────────────┐
               │    Active     │
               └──────┬──▲─────┘
        Elevated RTT /│  │ Normal RTT & Loss
        Loss Threshold│  │
               ┌──────▼──┴─────┐
               │   Degraded    │
               └──────┬──▲─────┘
     Consecutive      │  │ Healthy Probe
     Failures >= Limit│  │ Response
               ┌──────▼──┴─────┐
               │     Dead      │
               └───────────────┘
```
- **Active**: Healthy, responsive, actively selected for chunk transmissions.
- **Degraded**: Experiencing elevated latency ($>\text{threshold}$) or packet loss ($>\text{threshold}$); throttled to avoid head-of-line blocking.
- **Dead**: Unresponsive or link administratively down; removed from payload routing and placed in background probing state.

### 2. Multi-Path Scheduling Strategies

Velcrux provides 5 scheduling strategies configurable via `--multipath-scheduler`:

1. **`WeightedBandwidth` (Default)**:
   - Distributes chunks proportionally based on measured path bandwidth and BDP:
     $$\text{Weight}_i = \text{ConfigWeight}_i \times \frac{\text{cwnd}_i}{\text{SRTT}_i}$$
   - Maximizes aggregate multi-interface throughput across heterogeneous links (e.g. 10GbE + 1GbE).
2. **`LowestLatencyFirst` (`min-rtt`)**:
   - Routes chunks to the subflow with the lowest smoothed RTT as long as congestion window headroom is available, overflowing to secondary paths when the fast path is saturated.
3. **`RoundRobin`**:
   - Interleaves chunks sequentially across all active subflows.
4. **`Redundant` (`duplication`)**:
   - Duplicates chunks across all active subflows simultaneously. Ideal for high-loss or mission-critical channels (e.g. satellite or cellular telemetry).
5. **`PrimaryBackup` (`failover`)**:
   - Directs 100% of traffic through the designated primary interface (`--primary-interface`). Instantly shifts traffic to backup subflows if the primary link becomes degraded or dead.

### 3. Redundant Metadata Pipeline

Control and manifest frames can optionally be duplicated across all active bonded paths (`--redundant-metadata`), ensuring session negotiations and chunk completion ACKs never suffer packet loss jitter.

### 4. CLI Ergonomics

- `velcrux multipath [--target <url>] [--multipath-scheduler <policy>]` displays bonded interfaces, path IDs, RTTs, and aggregate bandwidth in tabular or JSON format.
- `velcrux upload` / `velcrux download` / `velcrux sync` accept `--multipath`, `--multipath-scheduler`, `--interfaces`, and `--primary-interface` flags.

## Consequences

- **Positive**:
  - Full bandwidth aggregation across multiple physical interfaces without requiring switch-side LACP.
  - Sub-millisecond failover resilience during physical cable disconnects or Wi-Fi roaming.
  - Fine-grained traffic steering tailored to network cost, latency, or reliability goals.
  - 100% memory-safe pure Rust implementation.
- **Negative**:
  - Out-of-order chunk arrival across divergent latency paths requires destination reordering buffers. Handled gracefully by Velcrux's chunk-addressed reassembly engine.
