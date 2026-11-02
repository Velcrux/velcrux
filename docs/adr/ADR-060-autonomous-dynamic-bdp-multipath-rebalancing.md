# ADR-060: Autonomous Dynamic BDP Multi-Path Re-balancing with Real-Time Loss Feedback

- **Status**: Accepted
- **Date**: 2026-11-02
- **Deciders**: Velcrux Core Architecture, Transport, and SRE Working Group
- **Consulted**: Distributed Networking, Performance Engineering, Site Reliability Engineering

---

## 1. Context and Problem Statement

Velcrux multi-path WAN transfer pipelines bond heterogeneous network links (such as 100GbE terrestrial fiber, 10GbE enterprise backhaul, Starlink LEO satellite constellations, and 5G cellular uplinks) to maximize aggregate throughput and provide link resilience (`ADR-048`).

However, operating across links with vastly disparate latency and stochastic loss profiles introduces severe transport pathologies under dynamic network conditions:
1. **Head-of-Line (HOL) Blocking**: In conventional multi-path bonding, slices sent across high-latency or degraded links (e.g., Starlink under rain fade or 5G during cell tower handovers) suffer delayed arrivals or burst losses. The receiving reassembly engine stalls waiting for missing slices before delivering chunks to storage, bottlenecking the entire transfer even when high-speed fiber links are pristine.
2. **Static BDP Window Failure**: Static flow-control windows (e.g. 64 MiB) allocate excessive buffer depth to impaired or lossy links, causing severe bufferbloat and latency inflation, while starving high-bandwidth links.
3. **Lack of Proactive Deflection**: When a path transitions into a high-loss Gilbert-Elliott state, packets continue to queue on the degraded link rather than being proactively deflected to healthy fast paths.

---

## 2. Decision Drivers

- **Autonomous Closed-Loop Feedback**: Continuously ingest subflow round-trip times ($RTT$), minimum physical RTT ($RTT_{\min}$), delivery rates, and loss ratios (in PPM).
- **Dynamic Bandwidth-Delay Product (BDP) Sizing**: Auto-tune each subflow's allocated send window based on instantaneous physical capacity: $\text{BDP}_i = \text{DeliveryRate}_i \times RTT_{\min, i}$.
- **Exponential Loss Penalty & Throttling**: Apply penalty $(1 - L_i)^\gamma$ to de-weight lossy subflows and prevent excessive in-flight packets on degrading paths.
- **Dynamic Deficit Weighted Round-Robin (D-DWRR)**: Re-distribute slice scheduler weights in real-time proportional to effective goodput capacity.
- **Proactive Traffic Deflection**: When a subflow crosses loss threshold $\tau_{\text{deflect}}$ or experiences RTT inflation $> 2.5\times RTT_{\min}$, immediately deflect pending slices to healthy terrestrial paths and clamp the degraded window to probe floor ($64\text{ KiB}$).
- **Anti-Flapping Hysteresis**: Prevent route flapping and oscillating allocations with EMA smoothing and minimum dwell intervals ($200\text{ ms}$).
- **Pure Safe Rust**: Strict `#![forbid(unsafe_code)]` compliance.

---

## 3. Considered Options

- **Option 1: Static Proportional Splitting Based on Nominal Link Capacity**:
  - *Cons*: Ignored dynamic path degradation; caused catastrophic HOL stalls when satellite links suffered weather fades.
- **Option 2: Per-Subflow Independent BBRv3 Instances Without Inter-Path Coordination**:
  - *Cons*: Each subflow throttles independently without deflecting traffic to alternate paths; does not solve slice reassembly HOL blocking.
- **Option 3 (Chosen): Autonomous Dynamic BDP Multi-Path Re-balancing Engine (`BdpRebalanceEngine`)**:
  - Cross-path coordination feedback controller with D-DWRR scheduling.
  - Proactive deflection of in-flight traffic upon loss detection.
  - Sub-microsecond evaluation and atomic metrics integration.
  - Staged atomic multi-process persistence (`VELCRUX_BDP_REBALANCE_DIR`).

---

## 4. Technical Architecture

```
                    TRANSPORT SUBFLOW TELEMETRY
          (RTT, MinRTT, DeliveryRate, LossRatio PPM, ECN)
                                │
                  ┌─────────────▼─────────────┐
                  │    EMA Smoothing Filter   │
                  │   (Hysteresis Dwell Gate) │
                  └─────────────┬─────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │                                               │
┌───────▼────────────────┐                     ┌────────▼──────────────┐
│  BDP Window Sizer      │                     │ Loss & Delay Monitor  │
│  BDP_i = BW_i * RTT_i  │                     │ Loss >= DeflectThresh │
│  Clamped [64KB, 256MB] │                     │ or RTT >= 2.5x MinRTT │
└───────┬────────────────┘                     └────────┬──────────────┘
        │                                               │
        └───────────────────────┬───────────────────────┘
                                │
                  ┌─────────────▼─────────────┐
                  │  Capacity Penalty Filter  │
                  │  Cap_i = BDP_i * (1-L)^γ  │
                  └─────────────┬─────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │ Nominal / Impaired                            │ Deflecting Triggered
┌───────▼────────────────┐                     ┌────────▼──────────────┐
│  D-DWRR Weight Alloc   │                     │ Proactive Deflection  │
│  W_i = Cap_i / Σ Cap_j │                     │ - Clamp Window to 64KB│
│  (1 to 100 Quantum)    │                     │ - Reroute to Fiber    │
└───────┬────────────────┘                     └────────┬──────────────┘
        │                                               │
        └───────────────────────┬───────────────────────┘
                                │
                  ┌─────────────▼─────────────┐
                  │  WAN Multi-Path Slicer    │
                  │  Zero-HOL Slice Dispatch  │
                  └───────────────────────────┘
```

---

## 5. Mathematical Formulation

1. **Subflow BDP Window Calculation**:
   $$\text{RawBDP}_i = \frac{\text{DeliveryRate}_i (\text{bps}) \times RTT_{\min, i} (\mu\text{s})}{8 \times 10^6}$$
   $$\text{AllocatedBDP}_i = \text{clamp}(\text{RawBDP}_i, \text{BDP}_{\min}, \text{BDP}_{\max})$$

2. **Exponential Loss Penalty Factor**:
   $$\text{Penalty}_i = \left(1.0 - \min(1.0, L_i)\right)^\gamma, \quad \gamma = 1.5$$

3. **Effective Goodput Capacity**:
   $$\text{Cap}_i = \text{AllocatedBDP}_i \times \text{Penalty}_i$$

4. **Dynamic Deficit Weighted Round-Robin (D-DWRR) Weight**:
   $$W_i = \max\left(1, \left\lfloor \frac{\text{Cap}_i}{\sum_j \text{Cap}_j} \times W_{\text{total}} \right\rfloor\right), \quad W_{\text{total}} = 100$$

---

## 6. Observability & Operational Metrics

- Prometheus metrics exposed under `/metrics`:
  - `velcrux_bdp_rebalance_cycles_total`
  - `velcrux_bdp_rebalance_subflow_deflections_total`
  - `velcrux_bdp_rebalance_active_subflows`
  - `velcrux_bdp_rebalance_aggregate_bdp_bytes`
  - `velcrux_bdp_rebalance_fast_link_utilization_ratio`
  - `velcrux_bdp_rebalance_loss_triggered_throttles_total`
  - `velcrux_bdp_rebalance_rebalance_latency_nanoseconds`
  - `velcrux_bdp_rebalance_hol_prevention_events_total`

