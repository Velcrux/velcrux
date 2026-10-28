# ADR-044: Distributed Dynamic Content Router & Anycast Session Migration

Status: Accepted · Date: 2026-10-28

## Context

Globally distributed enterprise architectures require multi-region bulk data ingestion and distribution with low round-trip latency, high link utilization, and resilient failover (`ARCHITECTURE.md` §2, §7; `SECURITY.md` §8). Connecting remote edge clients directly to a single central origin cluster induces excessive WAN latency, packet loss penalties on flow control windows, and single-point-of-failure exposure.

Key operational and architectural requirements:
1. **Dynamic Content Routing & Edge PoP Topology**:
   - Maintain a dynamic, globally coordinated registry of edge Points-of-Presence (PoPs) across diverse cloud providers and on-premise data centers.
   - Routinely evaluate edge health telemetry: round-trip time (RTT), jitter, packet loss ratio, CPU utilization, and available bandwidth headroom.
2. **Latency-Aware & Load-Dampened Anycast Steering**:
   - Resolve client transfer requests to the optimal edge PoP utilizing a composite scoring model:
     $$\text{Score} = \left(\text{Distance} \times 0.05 + \text{RTT} + \text{LossPenalty} + \text{LoadPenalty} + \text{StatusPenalty}\right) \times \text{CostMultiplier}$$
   - Prevent "thundering herd" oscillations by applying non-linear load dampening as PoP capacity approaches saturation.
3. **Graceful PoP Draining & Automated Failover**:
   - Edge PoPs undergoing planned maintenance or encountering upstream ISP link failures transition seamlessly to `Draining` or `Degraded`.
   - Anycast routing tables immediately redirect new requests to healthy adjacent nodes within sub-second convergence windows.
4. **Live QUIC Session Migration & Handover Tickets**:
   - Active bulk transfers must be migratable across edge PoPs or between edge and origin clusters without restarting from byte zero.
   - Cryptographically signed handover tickets ($C = \text{BLAKE3\_KEYED}(\text{"velcrux-migration-ticket:v1"} \parallel \text{fields})$) allow the target PoP to authenticate and assume session ownership at the exact chunk offset.
5. **Telemetry & Observability**:
   - Export Prometheus metrics (`velcrux_router_pops_active`, `velcrux_router_routes_computed_total`, `velcrux_router_session_migrations_total`, `velcrux_router_session_migration_failures_total`, `velcrux_router_handover_latency_microseconds`) and CLI commands (`velcrux router [status|pops|route|migrate|benchmark]`).
6. **Invariants**:
   - 100% Safe Rust (`#![forbid(unsafe_code)]` with zero exceptions across all crates).
   - Strict bounded memory streaming: routing tables and migration tickets are bounded, avoiding buffer exhaustion.

---

## Options Considered

1. **Option 1: Static DNS Geo-Resolution (GeoDNS)**:
   - Route clients via static DNS latency records (e.g. AWS Route 53 or Cloudflare GeoDNS).
   - *Rejected*: DNS TTL caching delays failover by minutes; cannot account for instantaneous PoP egress load, packet loss spikes, or live session handover.
2. **Option 2: Pure BGP Anycast without Session Migration**:
   - Announce identical IP prefixes over BGP from all edge data centers.
   - *Rejected*: Internet BGP routing flaps cause TCP/QUIC connection resets; lacks application-level load awareness and cannot transfer in-flight chunk state between nodes.
3. **Option 3: Distributed Dynamic Content Router & Cryptographic Session Migration (`ADR-044`)**:
   - Edge PoP topology registry evaluating real-time RTT, loss, and capacity.
   - Fine-grained composite routing algorithm with load-dampened steering.
   - Keyed BLAKE3 migration tickets providing tamper-evident, authenticated transfer resumption.
   - Built-in simulation benchmark verifying sub-millisecond failover convergence.

---

## Decision

Adopt Option 3.

---

## Architecture & Implementation

### 1. PoP Node Descriptor & Health Telemetry (`crates/velcrux-core/src/router/mod.rs`)

Each PoP node publishes its status and network quality metrics:
```rust
pub struct PopNode {
    pub id: String,
    pub name: String,
    pub region: String,
    pub latitude: f64,
    pub longitude: f64,
    pub address: SocketAddr,
    pub status: PopStatus,
    pub capacity_bps: u64,
    pub current_load_bps: u64,
    pub metrics: PopHealthMetrics,
    pub cost_multiplier: f64,
}

pub enum PopStatus {
    Healthy,
    Degraded,
    Draining,
    Offline,
}
```

### 2. Composite Routing Resolution & Great-Circle Distance

Distance is computed via the Haversine formula in pure Safe Rust. The composite routing cost penalizes RTT, packet loss, and capacity saturation:
$$\text{LoadRatio} = \frac{\text{CurrentLoad}}{\text{Capacity}}$$
$$\text{LoadPenalty} = \left(\frac{\text{LoadRatio}}{1.0 - \text{LoadRatio}}\right) \times 10.0$$

### 3. Cryptographic Session Migration Ticket

When migrating an active transfer between PoPs:
1. Source PoP pauses chunk streaming and captures current `bytes_committed` and `chunk_offset`.
2. Router issues a signed `MigrationTicket` containing session metadata, target address, expiration TTL, and a keyed BLAKE3 MAC:
   $$\text{MAC} = \text{BLAKE3\_KEYED}_{K}\left(\text{"velcrux-migration-ticket:v1"} \parallel \text{ticket\_id} \parallel \text{session\_id} \parallel \text{transfer\_id} \parallel \dots \parallel \text{expires\_at}\right)$$
3. Target PoP verifies the ticket's signature and expiration timestamp, initializes transfer state from `chunk_offset`, and resumes data streaming.

### 4. Telemetry & Metrics (`crates/velcrux-server/src/metrics.rs`)

Prometheus gauges and counters exposed under `/metrics`:
- `velcrux_router_pops_active`: Active healthy edge PoP count.
- `velcrux_router_routes_computed_total`: Total anycast routing decisions computed.
- `velcrux_router_session_migrations_total`: Cumulative count of committed session migrations.
- `velcrux_router_session_migration_failures_total`: Total failed or rejected migration handovers.
- `velcrux_router_handover_latency_microseconds`: Observed latency of session handover processing.

### 5. CLI Operations (`crates/velcrux-client/src/main.rs`)

```bash
# Inspect router health and PoP distribution
velcrux router status

# List registered edge PoPs and real-time load
velcrux router pops

# Resolve optimal route for a client location
velcrux router route client-01 --lat 38.9072 --lon -77.0369 --bandwidth 50000000

# Execute live session migration between PoPs
velcrux router migrate sess-100 --source pop-iad --target pop-sfo --offset 5242880 --total 10485760

# Execute high-throughput routing and migration benchmark
velcrux router benchmark --pops 5 --iterations 50
```

---

## Consequences

### Positive
- **Global Ingestion Velocity**: Remote clients connect to the lowest-latency edge PoP, minimizing RTT and optimizing QUIC congestion windows.
- **Zero-Loss Failover**: Inflight transfers migrate seamlessly across edge nodes without restarting from scratch.
- **Cryptographic Security**: Keyed BLAKE3 tickets prevent unauthorized session hijacking or replay attacks across cluster boundaries.
- **Zero Unsafe Rust**: 100% `#![forbid(unsafe_code)]` compliance.

### Negative
- **Topology Coordination**: Edge nodes must continuously stream telemetry heartbeats to the central routing coordinator.
