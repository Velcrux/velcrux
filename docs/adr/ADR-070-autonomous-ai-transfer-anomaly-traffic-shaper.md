# ADR-070: Autonomous AI/ML Transfer Anomaly Detection & Self-Healing Traffic Shaper

- **Status**: Accepted
- **Date**: 2026-11-09
- **Deciders**: Velcrux Networking, Distributed Transport, Telemetry, and Reliability Engineering Teams
- **Consulted**: Security Operations, Infrastructure Platform, and Edge Computing Teams

---

## 1. Context and Problem Statement

High-throughput bulk data transfers operating across enterprise WANs, hybrid-cloud fabrics, and satellite/5G links encounter severe dynamic impairments:
1. **Bufferbloat & Queuing Latency Tax**: Intermediate edge routers and broadband access nodes buffer excessive packets, inflating RTT by 300–800% without triggering loss-based congestion signals, destroying interactive responsiveness.
2. **Physical & Wireless Link Degradation**: Fiber degradation, LEO satellite beam handoffs, and cellular interference induce bursts of non-congestive packet loss ($>5\%$), tricking naive congestion control algorithms into collapsing transmission rates.
3. **Microburst Ingress Congestion**: Concurrent bursty workloads saturate switch buffers on sub-10ms timescales, causing packet drop storms before traditional feedback loops react.
4. **Route Flaps & Path Asymmetry Blackholes**: Dynamic BGP rerouting or submarine link failovers abruptly change path latencies or drop ACK returns, causing severe transfer stalls.
5. **Cross-Traffic Contention**: Uncoordinated competing bulk transfers (e.g. aggressive Cubic flows) induce severe rate oscillations.

Traditional reactive congestion control algorithms adjust sending windows strictly after packet drops or latency inflation occur, lacking multidimensional anomaly classification and autonomous multi-tier mitigation (e.g., dynamic FEC redundancy scaling, subflow rerouting, selective flow shedding, and fine-grained pacing).

To solve this, Velcrux requires an **Autonomous AI/ML Transfer Anomaly Detection & Self-Healing Traffic Shaper**.

---

## 2. Decision Drivers

- **Real-Time Streaming Anomaly Scoring**: Evaluate multi-dimensional telemetry (RTT z-score, queuing gradient, loss rate, throughput drop, jitter variance, and in-flight BDP ratio) with sub-millisecond evaluation latency.
- **Pure Safe-Rust Machine Learning Ensemble**: Implement a constant-memory, streaming partition Isolation Forest (`StreamingIsolationForest`) paired with two-sided Cumulative Sum (`CusumDetector`) drift detection in 100% safe Rust without external C/Python runtimes.
- **Multidimensional Anomaly Taxonomy**: Classify anomalies into explicit root-cause profiles: `Bufferbloat`, `LinkDegradation`, `MicroburstCongestion`, `RouteFlapBlackhole`, `CrossTrafficContention`, and `AsymmetricBdpShift`.
- **Closed-Loop Autonomous Actuation**: Execute decisive self-healing traffic shaping actions:
  - *Bufferbloat*: Dynamically throttle token bucket pacing rates by 30% and drain intermediate queues.
  - *Link Degradation*: Dynamically scale Reed-Solomon / RaptorQ erasure code parity overhead up to 35% to shield against loss spikes without stalling goodput.
  - *Microburst Congestion*: Apply token bucket inter-packet smoothing and burst-limit clamping.
  - *Route Blackholes*: Autonomously reroute bulk data traffic to secondary multipath subflows and trigger PMTU probing.
- **Post-Mortem Audit & Prometheus Exposition**: Preserve structured incident post-mortem ledgers with recovery latency and throughput delta tracking, while exposing native Prometheus gauges and counters.
- **Zero Unsafe Code**: 100% pure `#![forbid(unsafe_code)]` compliance.

---

## 3. Considered Options

- **Option 1: Static Heuristics & Hardcoded Thresholds**:
  - *Cons*: Highly fragile across diverse network topologies (e.g. 100Gbps datacenter vs 20Mbps Starlink); frequent false positives or delayed reactions.
- **Option 2: Heavyweight Deep Learning Runtime (Torch/ONNX C++ bindings)**:
  - *Cons*: Massive binary bloat ($>100\text{ MB}$), unsafe FFI, significant CPU/memory overhead, and non-deterministic inference latencies.
- **Option 3 (Chosen): Streaming Isolation Forest + CUSUM Drift + Closed-Loop Actuator (`Option DB`)**:
  - Lightweight, memory-bounded, safe-Rust ensemble Isolation Trees.
  - Normalized path-length anomaly scoring: $s(x, n) = 2^{-\frac{\mathbb{E}[h(x)]}{c(n)}}$.
  - Two-sided CUSUM drift detection for rapid change-point identification.
  - Multi-action self-healing shaper with cooldown hysteresis and gradual rate recovery.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│           AUTONOMOUS AI/ML ANOMALY DETECTION & SELF-HEALING SHAPER                     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  [Transport Telemetry Pipeline]                                                        │
│  RTT (ms), RTT Var, Loss Rate, Jitter, Throughput (bps), Bytes In-Flight, ECN Marks    │
│                                │                                                       │
│                                ▼                                                       │
│  [Rolling Window Feature Normalization]                                                │
│  - 50-sample circular buffer, EWMA smoothing (alpha = 0.15)                            │
│  - Standardized FeatureVector x in R^7:                                                │
│    [RTT_z, LossRate, ThroughputDrop, QueueDelayRatio, RTTVarRatio, Jitter_z, BDP_ratio]│
│                                │                                                       │
│                                ▼                                                       │
│  [Dual AI/ML Detection Engine]                                                         │
│  ┌───────────────────────────────────┐       ┌──────────────────────────────────────┐  │
│  │ Streaming Isolation Forest        │       │ Two-Sided CUSUM Drift Detector       │  │
│  │ - 25 randomized partition trees   │       │ - S+ = max(0, S+ + (x - mu - k))     │  │
│  │ - Score: s = 2^(-E[h(x)] / c(n))  │       │ - S- = max(0, S- - (x - mu + k))     │  │
│  └─────────────────┬─────────────────┘       └──────────────────┬───────────────────┘  │
│                    │                                            │                      │
│                    └─────────────────┬──────────────────────────┘                      │
│                                      ▼                                                 │
│                        [Composite Anomaly Evaluator]                                   │
│                        Anomaly Confirmed? (Score >= 0.65 || Drift)                     │
│                                      │                                                 │
│                        ┌─────────────┴─────────────┐                                   │
│                   Yes  ▼                           ▼  No                               │
│  [Multidimensional Classifier]             [Gradual Recovery]                          │
│  - Bufferbloat                             - Step up pacing (+5%)                      │
│  - Link Degradation                        - Restore nominal FEC (5%)                  │
│  - Microburst Congestion                   - Hold steady baseline                      │
│  - Route Flap / Blackhole                                                              │
│  - Cross-Traffic Contention                                                            │
│                        │                                                               │
│                        ▼                                                               │
│  [Closed-Loop Autonomous Actuation (Self-Healing Shaper)]                              │
│  - AdjustPacingRate (-30% throttle)                                                    │
│  - ScaleFecRedundancy (boost to 25% parity)                                            │
│  - DrainQueue (150ms token bucket drain)                                               │
│  - RerouteSubflow (switch to healthy multipath link)                                   │
│  - TriggerPmtuProbe (renegotiate path MTU)                                             │
│                        │                                                               │
│                        ▼                                                               │
│  [Audit Ledger & Prometheus Telemetry]                                                 │
│  - IncidentPostMortem (UUID, latency, delta throughput, resolution status)             │
│  - velcrux_traffic_anomaly_score, velcrux_traffic_pacing_rate_bps                      │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Mathematical Formulations

### 5.1 Average Path Length Normalization
The average path length of an unsuccessful search in a Binary Search Tree (BST) over $n$ samples is:
$$c(n) = 2 \left( \ln(n - 1) + 0.5772156649 \right) - \frac{2(n - 1)}{n}$$
The normalized anomaly score for observation vector $\mathbf{x}$ across an ensemble of $T$ isolation trees is:
$$s(\mathbf{x}, n) = 2^{-\frac{\mathbb{E}[h(\mathbf{x})]}{c(n)}} \quad \text{where } \mathbb{E}[h(\mathbf{x})] = \frac{1}{T} \sum_{t=1}^T h_t(\mathbf{x})$$
- When $\mathbb{E}[h(\mathbf{x})] \to 0 \implies s \to 1.0$ (strong anomaly).
- When $\mathbb{E}[h(\mathbf{x})] \to c(n) \implies s \to 0.5$ (nominal behavior).
- When $\mathbb{E}[h(\mathbf{x})] \to n - 1 \implies s \to 0.0$ (hyper-clustered normal).

### 5.2 Two-Sided CUSUM Change-Point Detector
Tracks cumulative deviations from baseline mean $\mu_0$ with slack $k$ and alert threshold $h$:
$$S_i^+ = \max(0, S_{i-1}^+ + (x_i - \mu_0 - k))$$
$$S_i^- = \max(0, S_{i-1}^- - (x_i - \mu_0 + k))$$
An alert triggers whenever $S_i^+ > h$ or $S_i^- > h$.

### 5.3 Bufferbloat Queuing Gradient
$$Q_d = \frac{\text{RTT}_{\text{sample}} - \text{minRTT}}{\max(1.0, \text{minRTT})}$$
When $Q_d > 1.5$ and loss rate $< 2\%$, the anomaly is uniquely diagnosed as Bufferbloat.

---

## 6. CLI Command Suite

```bash
# Inspect real-time streaming traffic status, anomaly score, and pacing rates
velcrux traffic status

# Inspect status formatted as machine-readable JSON
velcrux traffic status --json

# Inspect historical anomaly incident post-mortems and mitigation outcomes
velcrux traffic incidents --limit 10

# Execute synthetic streaming anomaly injection and self-healing benchmark
velcrux traffic bench --samples 100 --inject bufferbloat

# Dynamically tune anomaly detection sensitivity threshold
velcrux traffic tune --sensitivity 0.70

# Export Prometheus metrics exposition text
velcrux traffic prometheus
```

---

## 7. Consequences and Status

- **Positive**:
  - Eliminates transfer stalls caused by bufferbloat and transient link degradation.
  - Sub-millisecond streaming anomaly scoring without external dependencies or heavy ML runtimes.
  - Transparent post-mortem auditability with exact recovery latencies and throughput recovery deltas.
  - Native Prometheus integration for production Grafana dashboards.
- **Negative / Trade-offs**:
  - Pacing throttling reduces instantaneous throughput temporarily to drain queues (trade-off for latency collapse).

