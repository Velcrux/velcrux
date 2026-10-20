# ADR-034: Adaptive Bandwidth Delay Product (BDP) Auto-Tuning Engine & QUIC Flow Control

Status: Accepted · Date: 2026-10-20

## Context

In high-speed, long-distance distributed transfers across the Internet (e.g. transatlantic, intercontinental, and low-earth-orbit satellite links), standard transport configurations suffer from throughput collapse due to inadequate flow control window sizing.

1. **Bandwidth-Delay Product (BDP) Impedance**:
   - The theoretical data volume required to keep a network pipe fully utilized without starvation is given by:
     $$\text{BDP} = \text{Bandwidth} \times \text{RTT}$$
   - On a 10 Gbps transatlantic link with 150 ms round-trip time:
     $$\text{BDP} = 1.25\text{ GB/s} \times 0.15\text{ s} = 187.5\text{ MB}$$
   - To buffer smoothly through transmission jitter and ACK delays without bubbling, the connection flow control window must be sized to at least $2 \times \text{BDP}$ (~375 MB).
   - If the flow control window is capped at standard OS or QUIC defaults (e.g. 16 MiB or 32 MiB), throughput collapses to:
     $$\text{Throughput} \le \frac{\text{Window}}{\text{RTT}} = \frac{16\text{ MB}}{0.15\text{ s}} \approx 106\text{ MB/s} \approx 850\text{ Mbps}$$
     representing a >90% loss of link capacity.
2. **Bufferbloat & Queueing Delay Risks**:
   - Conversely, assigning static 1 GiB windows indiscriminately on local networks (LAN) or shared enterprise links wastes socket memory and can cause catastrophic bufferbloat when bottleneck routers buffer excess inflight packets instead of signaling congestion.
3. **Dynamic Path Variations**:
   - Modern networks experience path changes (e.g., connection migration between Wi-Fi and 5G, satellite constellation handovers, temporary routing reroutes). A static window cannot adapt to dynamically shifting BDP profiles.

## Options Considered

1. **Option 1: Static Profile Flags Only (`--network-profile lan|wan|satellite`)**:
   - Rely solely on operator-selected static profile constants.
   - *Rejected*: Inflexible; operators rarely know the exact real-time RTT and available capacity; cannot adapt during a long-running multi-terabyte transfer if network conditions evolve.
2. **Option 2: Kernel Socket Buffer Tuning (`SO_RCVBUF` / `SO_SNDBUF`)**:
   - Modify host kernel sysctls and socket options directly.
   - *Rejected*: Requires root / `CAP_NET_ADMIN` privileges; platform-dependent; violates container isolation boundaries.
3. **Option 3: Adaptive BDP Auto-Tuning Feedback Loop (`ADR-034`)**:
   - Build a pure-Rust, user-space feedback controller (`BdpAutoTuner`) that integrates directly with QUIC transport telemetry.
   - Continuously estimate path propagation delay ($\text{min RTT}$) and smoothed RTT (SRTT).
   - Detect bufferbloat queueing delay spikes when $\text{SRTT} / \text{min RTT} \ge 1.5$ and gently decay the window.
   - Expand the window smoothly on high-capacity paths up to a configurable ceiling (512 MiB / 1 GiB).
   - Provide configurable policies (`Auto`, `Fixed`, `Aggressive`, `Conservative`), CLI management tools, and Prometheus telemetry.

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. BDP Auto-Tuner (`crates/velcrux-core/src/transport/bdp.rs`)

The `BdpAutoTuner` maintains real-time link statistics and auto-tunes the flow control window:

```rust
pub struct BdpAutoTuner {
    config: BdpWindowConfig,
    current_window: u64,
    smoothed_rtt: Duration,
    min_rtt: Duration,
    estimated_bandwidth_bytes_per_sec: u64,
    loss_events_total: u64,
    last_loss_count: u64,
    expansions_total: u64,
    decays_total: u64,
    holds_total: u64,
    last_direction: BdpTuningDirection,
    bufferbloat_detected: bool,
}
```

### 2. Tuning Policies & Delay Tiers

- **Tuning Policies**:
  - `Auto` (default): Dynamic feedback auto-tuning with 2.0× BDP multiplier and 1.5× queue delay threshold.
  - `Fixed`: Static flow control window without dynamic resizing.
  - `Aggressive`: 3.0× BDP multiplier with lower decay sensitivity (for dedicated WAN / high-loss satellite).
  - `Conservative`: 1.4× BDP multiplier with 1.3× bufferbloat sensitivity and rapid decay (for shared LAN).
- **Delay Tiers**:
  - `Lan`: RTT $\le$ 5 ms
  - `Metro`: 5 ms $<$ RTT $\le$ 30 ms
  - `Wan`: 30 ms $<$ RTT $\le$ 100 ms
  - `Transatlantic`: 100 ms $<$ RTT $\le$ 200 ms
  - `Satellite`: RTT $>$ 200 ms

### 3. Bufferbloat Guard Logic

When bottleneck router queues inflate, smoothed RTT increases relative to the physical minimum RTT:
$$\text{QueueRatio} = \frac{\text{SRTT}}{\text{min RTT}}$$
If $\text{QueueRatio} \ge 1.5$, `bufferbloat_detected` becomes true and the window decays by 10%–30% to drain the bottleneck queue before packet drops occur.

### 4. Telemetry & Metrics

Exported via Prometheus `/metrics`:
- `velcrux_bdp_current_window_bytes`: Active receive and flow control window size in bytes.
- `velcrux_bdp_estimated_bps`: Real-time path bandwidth estimation in bits/sec.
- `velcrux_bdp_tuning_adjustments_total{direction="expand|decay|hold"}`: Counters tracking feedback adjustments.

### 5. CLI Interface

- `velcrux sync <src> <dst> --bdp-tuning <auto|fixed|aggressive|conservative> --max-bdp-window <bytes> --min-bdp-window <bytes>`
- `velcrux bdp inspect [--json]`
- `velcrux bdp simulate --bandwidth <str> --rtt-ms <ms> [--loss-pct <pct>] [--policy <policy>] [--json]`

## Consequences

- **Performance**: Sustains line-rate 10 Gbps throughput on 150 ms transatlantic paths without manual tuning.
- **Queueing Delay**: Prevents bufferbloat and latency spikes on shared networks.
- **Safety**: Pure safe Rust under `#![forbid(unsafe_code)]`.
