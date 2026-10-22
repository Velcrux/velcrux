# ADR-037: Hierarchical Token-Bucket Quality of Service (QoS) & Flow Priority Multiplexer

Status: Accepted · Date: 2026-10-22

## Context

In multi-tenant, high-throughput storage networks and WAN sync operations, diverse workloads contend for shared network bandwidth:
1. **Interactive Control & Metadata**: Latency-sensitive directory indexing, session pings, small metadata updates, and checksum verifications require immediate transmission without head-of-line blocking behind multi-gigabyte bulk payloads.
2. **High-SLA Mission-Critical Streams**: Streaming database transaction logs, financial replication, and critical telemetry require guaranteed throughput minimums (Committed Information Rate - CIR) regardless of background load.
3. **Standard Bulk Data Sync**: Regular dataset synchronization needs proportional bandwidth sharing.
4. **Low-Priority Archival & Scrubbing**: Background bit-rot scrubbing and archival transfers must consume idle capacity without starving primary transfers.

Without dynamic Quality of Service (QoS) scheduling and fair-queue flow multiplexing, uncontrolled burst transfers monopolize link capacity, leading to latency spikes, starvation of control flows, and SLA violations.

### Key Invariants & Requirements

1. **Dual CIR / PIR Capacity Management**:
   - Provide Committed Information Rate (CIR) bandwidth guarantees per priority tier and tenant.
   - Support Peak Information Rate (PIR) ceilings allowing idle spare link capacity to be borrowed dynamically across tiers (`REQUIREMENTS.md` §28, §29).
2. **Deterministic Priority Queueing & Deficit Round-Robin Multiplexing**:
   - Four distinct priority tiers: `Realtime` (preemptive drain), `Critical` (weight 4), `Default` (weight 2), and `Background` (weight 1).
   - Realtime flows must be drained to exhaustion before bulk traffic, while non-realtime flows must interleave according to Deficit Round-Robin / Weighted Fair Queueing (4:2:1 ratio) to guarantee starvation prevention.
3. **Architectural Safety & Invariants**:
   - Strict adherence to `#![forbid(unsafe_code)]` with zero exceptions across all crates (`CLAUDE.md` §1).
   - Strict bounded memory streaming: multiplexing and rate limiting must operate on chunk / frame handles without full-file buffer allocations.

## Options Considered

1. **Option 1: Static Coarse Rate Limiting (Single Flat Token Bucket)**:
   - A single global rate limiter throttling all connections uniformly.
   - *Rejected*: Inflexible. Cannot guarantee SLA reservations (CIR) for critical streams and causes severe latency degradation for interactive metadata.
2. **Option 2: Strict Priority Queueing Without Capacity Sharing**:
   - Static prioritization where higher tiers completely preempt lower tiers without sharing spare capacity or burst ceilings.
   - *Rejected*: Can lead to starvation of background jobs even when higher tiers are idle.
3. **Option 3: Hierarchical Token-Bucket (HTB) with Dual-Rate CIR/PIR & Flow Priority Multiplexer (`ADR-037`)**:
   - Hierarchical dual-rate token buckets tracking guaranteed rates (CIR) and peak capacity ceilings (PIR).
   - Dynamically reallocates idle parent bandwidth to saturated child classes.
   - Multiplexes flows using strict preemptive priority for `Realtime` and 4:2:1 Deficit Round-Robin for `Critical`, `Default`, and `Background`.
   - Exposes CLI subcommands (`velcrux qos [inspect|benchmark|status]`) and Prometheus metrics.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Hierarchical Dual-Rate Token Bucket (`crates/velcrux-core/src/scheduler/qos.rs`)

`HtbTokenBucket` provides dual-rate token accounting:
- **CIR Token Pool**: Accrues tokens at the guaranteed bandwidth floor rate.
- **PIR Token Pool**: Accrues tokens up to the maximum peak link capacity.
- **Dynamic Borrowing**: When an admission request exceeds the local CIR balance, the bucket borrows idle tokens from the parent link pool up to the PIR ceiling without incurring sleep delays.

```rust
pub struct HtbTokenBucket {
    cir_rate_bps: u64,
    pir_rate_bps: u64,
    cir_capacity: f64,
    pir_capacity: f64,
    cir_tokens: f64,
    pir_tokens: f64,
    last_update: Instant,
}
```

### 2. Traffic Classes & Bandwidth Allocation

Four discrete QoS priority tiers are defined:
- `Realtime` (weight 8, CIR 40%): Latency-sensitive control, session pings, small metadata chunks.
- `Critical` (weight 4, CIR 35%): High-SLA mission-critical datasets, streaming database logs.
- `Default` (weight 2, CIR 20%): Standard interactive bulk transfers.
- `Background` (weight 1, CIR 5%): Low-priority background sync, archival, bit-rot scrubbing.

### 3. Deficit Round-Robin Flow Priority Multiplexer (`QosFlowMultiplexer<T>`)

The multiplexer manages 4 concurrent queues:
1. `Realtime` queue is drained to exhaustion first to minimize packet latency.
2. Remaining queues are multiplexed using a 7-step cyclic Weighted Round-Robin pattern:
   `[Critical, Critical, Critical, Critical, Default, Default, Background]`
   This enforces an exact 4:2:1 ratio among contending non-realtime flows while preventing starvation.

### 4. CLI Inspection & Diagnostic Subcommands (`crates/velcrux-client/src/main.rs`)

Global options:
- `--qos-priority <realtime|critical|default|background>`: Configures client transfer priority.
- `--qos-bandwidth <rate>`: Configures root link bandwidth ceiling (e.g. `1Gbps`, `100Mbps`).

Subcommands:
- `velcrux qos inspect [--bandwidth <rate>] [--json]`: Displays class weights, CIR fractions, guaranteed rates, and PIR ceilings.
- `velcrux qos benchmark [--bandwidth <rate>] [--packets <N>] [--json]`: Simulates high-contention traffic across tiers, verifying CIR isolation and dynamic PIR capacity borrowing.
- `velcrux qos status [--json]`: Displays active client QoS configuration and scheduling properties.

### 5. Prometheus Observability (`crates/velcrux-server/src/metrics.rs`)

Exported metrics:
- `velcrux_qos_tokens_consumed_total`: Cumulative bytes admitted across all classes.
- `velcrux_qos_tokens_borrowed_total`: Cumulative tokens borrowed from idle spare capacity.
- `velcrux_qos_delays_total`: Cumulative rate-throttling delay events.
- `velcrux_qos_class_bytes_total{class="realtime|critical|default|background"}`: Bytes transferred per QoS tier.

## Consequences

### Positive
- Strict CIR bandwidth guarantees prevent noisy neighbors from degrading mission-critical transfers.
- Dynamic PIR capacity borrowing ensures 100% link utilization when higher tiers are idle.
- Sub-millisecond dispatch for realtime control and metadata frames.
- Full observability through Prometheus telemetry and CLI diagnostics.

### Negative / Trade-offs
- Slight mutex synchronization overhead when multiple concurrent flows enqueue and dequeue items.
- Dual-rate token bucket calculations require microsecond-resolution clock reads.
