//! Deterministic Network Emulation & Jitter Harness for Chaos Sync Verification (`ADR-058`, Option CP).
//!
//! Provides pure safe Rust userspace packet scheduling, deterministic loss/jitter/reorder/duplication
//! emulation, and chaos sync verification wrapped around the transport layer without requiring OS root privileges.
//!
//! Features:
//! 1. Deterministic PRNG Seeding:
//!    - 64-bit seedable PRNG (SplitMix64) producing 100% reproducible chaos experiments across CI and dev machines.
//! 2. Advanced Delay & Jitter Distributions:
//!    - Uniform, Normal (Box-Muller transform), and Pareto (heavy-tailed bufferbloat queuing).
//!    - Autoregressive delay correlation: $d_i = \rho \cdot d_{i-1} + (1 - \rho) \cdot \delta_i$.
//! 3. Gilbert-Elliott 2-State Markov Burst Loss Model:
//!    - Simulates correlated multi-packet loss bursts characteristic of wireless and satellite channels.
//! 4. Natural Packet Reordering:
//!    - Min-heap priority queue releases packets by virtual arrival deadlines ($t_{\text{arrival}} + d_i$),
//!      causing faster packets to overtake delayed ones realistically.
//! 5. Packet Duplication & Payload Corruption:
//!    - Simulates spurious link layer duplicate deliveries and single/multi-bit flips to verify BLAKE3 integrity.
//! 6. Pre-Configured WAN Link Presets:
//!    - `StarlinkSatellite`, `TransatlanticWan`, `RuralCellular5G`, `BufferbloatAdverse`, and `PristineLan`.
//! 7. Virtual Traffic Simulator & Microsecond Benchmark:
//!    - In-memory simulation harness computing packet delivery ratio, out-of-order rate, RTT percentiles, and throughput.
//! 8. 100% Safe Rust (`#![forbid(unsafe_code)]`) with zero external C/OS dependencies.

#![forbid(unsafe_code)]

use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;

/// Returns current Unix epoch timestamp in nanoseconds.
fn current_epoch_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Deterministic, fast 64-bit SplitMix64 pseudo-random generator for 100% reproducible network emulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetemPrng {
    state: u64,
}

impl NetemPrng {
    /// Initializes the PRNG with a specific 64-bit seed.
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E3779B97F4A7C15 } else { seed },
        }
    }

    /// Generates next 64-bit pseudo-random integer.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Generates pseudo-random float in $[0.0, 1.0)$.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }

    /// Generates standard normal (Gaussian) sample $\mathcal{N}(0, 1)$ via Box-Muller transform.
    pub fn next_gaussian(&mut self) -> f64 {
        let u1 = self.next_f64().max(1e-12);
        let u2 = self.next_f64();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }

    /// Generates a Pareto distributed sample with minimum scale $x_m$ and shape parameter $\alpha$.
    pub fn next_pareto(&mut self, scale: f64, alpha: f64) -> f64 {
        let u = self.next_f64().min(0.999999);
        scale / (1.0 - u).powf(1.0 / alpha.max(0.1))
    }
}

impl Default for NetemPrng {
    fn default() -> Self {
        Self::new(0xDEADBEEFCAFE)
    }
}

/// Jitter statistical distribution kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JitterDistribution {
    /// Uniform distribution within $[\mu - \sigma, \mu + \sigma]$.
    Uniform,
    /// Gaussian (Normal) distribution with mean $\mu$ and standard deviation $\sigma$.
    Normal,
    /// Pareto heavy-tailed distribution modeling queue bufferbloat spikes.
    Pareto,
}

impl fmt::Display for JitterDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JitterDistribution::Uniform => write!(f, "uniform"),
            JitterDistribution::Normal => write!(f, "normal"),
            JitterDistribution::Pareto => write!(f, "pareto"),
        }
    }
}

impl std::str::FromStr for JitterDistribution {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "uniform" => Ok(JitterDistribution::Uniform),
            "normal" => Ok(JitterDistribution::Normal),
            "pareto" => Ok(JitterDistribution::Pareto),
            other => Err(VelcruxError::Internal(format!(
                "unknown jitter distribution: '{}' (expected uniform, normal, pareto)",
                other
            ))),
        }
    }
}

/// State of the 2-state Gilbert-Elliott Markov chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkovState {
    /// Low-loss normal transmission state.
    Good = 0,
    /// High-loss burst state.
    Bad = 1,
}

/// Gilbert-Elliott 2-state Markov burst loss model configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GilbertElliottLossConfig {
    /// Probability of transitioning from Good to Bad state: $P(G \to B)$.
    pub p: f64,
    /// Probability of transitioning from Bad to Good state: $P(B \to G)$.
    pub r: f64,
    /// Loss probability in Good state (typically 0.001 or 0.0).
    pub loss_good: f64,
    /// Loss probability in Bad state (typically 0.8 to 1.0).
    pub loss_bad: f64,
}

impl Default for GilbertElliottLossConfig {
    fn default() -> Self {
        Self {
            p: 0.01,
            r: 0.20, // average burst length = 1/0.2 = 5 packets
            loss_good: 0.001,
            loss_bad: 0.95,
        }
    }
}

/// Pre-configured real-world network link emulation profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetemProfilePreset {
    /// Starlink low-Earth-orbit satellite (high jitter, wireless loss, 60ms base RTT).
    StarlinkSatellite,
    /// Inter-continental fiber WAN (90ms base RTT, tight normal jitter, low loss).
    TransatlanticWan,
    /// Rural 5G mobile link (fluctuating latency, Markov burst loss, 35ms base RTT).
    RuralCellular5G,
    /// Bufferbloat adverse link (20ms base, Pareto heavy-tail queuing delay spikes).
    BufferbloatAdverse,
    /// Pristine Gigabit LAN link (0.2ms delay, negligible jitter, 0% loss).
    PristineLan,
}

impl fmt::Display for NetemProfilePreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetemProfilePreset::StarlinkSatellite => write!(f, "starlink-satellite"),
            NetemProfilePreset::TransatlanticWan => write!(f, "transatlantic-wan"),
            NetemProfilePreset::RuralCellular5G => write!(f, "rural-cellular-5g"),
            NetemProfilePreset::BufferbloatAdverse => write!(f, "bufferbloat-adverse"),
            NetemProfilePreset::PristineLan => write!(f, "pristine-lan"),
        }
    }
}

impl std::str::FromStr for NetemProfilePreset {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "starlink-satellite" | "starlink" => Ok(NetemProfilePreset::StarlinkSatellite),
            "transatlantic-wan" | "wan" => Ok(NetemProfilePreset::TransatlanticWan),
            "rural-cellular-5g" | "5g" | "cellular" => Ok(NetemProfilePreset::RuralCellular5G),
            "bufferbloat-adverse" | "bufferbloat" => Ok(NetemProfilePreset::BufferbloatAdverse),
            "pristine-lan" | "lan" => Ok(NetemProfilePreset::PristineLan),
            other => Err(VelcruxError::Internal(format!(
                "unknown netem preset: '{}' (expected starlink-satellite, transatlantic-wan, rural-cellular-5g, bufferbloat-adverse, pristine-lan)",
                other
            ))),
        }
    }
}

/// Network emulation profile configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetemConfig {
    /// Whether network emulation is actively enabled.
    pub enabled: bool,
    /// Optional preset profile name.
    pub preset_name: Option<String>,
    /// Base propagation delay in milliseconds.
    pub delay_ms: f64,
    /// Delay jitter in milliseconds.
    pub jitter_ms: f64,
    /// Jitter distribution shape.
    pub jitter_dist: JitterDistribution,
    /// Delay correlation coefficient $\rho \in [0.0, 1.0)$.
    pub delay_correlation: f64,
    /// Pareto shape parameter $\alpha$ (used if `jitter_dist` is Pareto).
    pub pareto_shape: f64,
    /// Independent packet loss ratio in percent (0.0 to 100.0).
    pub loss_percent: f64,
    /// Optional Gilbert-Elliott burst loss model.
    pub markov_loss: Option<GilbertElliottLossConfig>,
    /// Packet reorder probability in percent (0.0 to 100.0).
    pub reorder_percent: f64,
    /// Packet duplicate probability in percent (0.0 to 100.0).
    pub duplicate_percent: f64,
    /// Packet payload bit-flip corruption probability in percent (0.0 to 100.0).
    pub corrupt_percent: f64,
    /// Ingress bandwidth limit in Megabits per second (0.0 for unlimited).
    pub bandwidth_mbps: f64,
    /// Deterministic seed for reproducible PRNG.
    pub prng_seed: u64,
}

impl Default for NetemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            preset_name: None,
            delay_ms: 0.0,
            jitter_ms: 0.0,
            jitter_dist: JitterDistribution::Normal,
            delay_correlation: 0.0,
            pareto_shape: 1.5,
            loss_percent: 0.0,
            markov_loss: None,
            reorder_percent: 0.0,
            duplicate_percent: 0.0,
            corrupt_percent: 0.0,
            bandwidth_mbps: 0.0,
            prng_seed: 1337,
        }
    }
}

impl NetemConfig {
    /// Constructs a NetemConfig from a preset.
    pub fn from_preset(preset: NetemProfilePreset, seed: Option<u64>) -> Self {
        let prng_seed = seed.unwrap_or(1337);
        match preset {
            NetemProfilePreset::StarlinkSatellite => Self {
                enabled: true,
                preset_name: Some(preset.to_string()),
                delay_ms: 30.0,
                jitter_ms: 12.0,
                jitter_dist: JitterDistribution::Pareto,
                delay_correlation: 0.35,
                pareto_shape: 1.4,
                loss_percent: 1.2,
                markov_loss: Some(GilbertElliottLossConfig {
                    p: 0.02,
                    r: 0.15,
                    loss_good: 0.002,
                    loss_bad: 0.90,
                }),
                reorder_percent: 2.0,
                duplicate_percent: 0.5,
                corrupt_percent: 0.05,
                bandwidth_mbps: 120.0,
                prng_seed,
            },
            NetemProfilePreset::TransatlanticWan => Self {
                enabled: true,
                preset_name: Some(preset.to_string()),
                delay_ms: 45.0,
                jitter_ms: 3.5,
                jitter_dist: JitterDistribution::Normal,
                delay_correlation: 0.20,
                pareto_shape: 1.5,
                loss_percent: 0.2,
                markov_loss: None,
                reorder_percent: 0.5,
                duplicate_percent: 0.1,
                corrupt_percent: 0.01,
                bandwidth_mbps: 1000.0,
                prng_seed,
            },
            NetemProfilePreset::RuralCellular5G => Self {
                enabled: true,
                preset_name: Some(preset.to_string()),
                delay_ms: 22.0,
                jitter_ms: 15.0,
                jitter_dist: JitterDistribution::Normal,
                delay_correlation: 0.40,
                pareto_shape: 1.5,
                loss_percent: 0.8,
                markov_loss: Some(GilbertElliottLossConfig {
                    p: 0.03,
                    r: 0.25,
                    loss_good: 0.001,
                    loss_bad: 0.85,
                }),
                reorder_percent: 1.5,
                duplicate_percent: 0.8,
                corrupt_percent: 0.08,
                bandwidth_mbps: 45.0,
                prng_seed,
            },
            NetemProfilePreset::BufferbloatAdverse => Self {
                enabled: true,
                preset_name: Some(preset.to_string()),
                delay_ms: 15.0,
                jitter_ms: 60.0,
                jitter_dist: JitterDistribution::Pareto,
                delay_correlation: 0.65,
                pareto_shape: 1.2,
                loss_percent: 0.5,
                markov_loss: None,
                reorder_percent: 3.0,
                duplicate_percent: 0.2,
                corrupt_percent: 0.02,
                bandwidth_mbps: 80.0,
                prng_seed,
            },
            NetemProfilePreset::PristineLan => Self {
                enabled: true,
                preset_name: Some(preset.to_string()),
                delay_ms: 0.2,
                jitter_ms: 0.05,
                jitter_dist: JitterDistribution::Normal,
                delay_correlation: 0.0,
                pareto_shape: 1.5,
                loss_percent: 0.0,
                markov_loss: None,
                reorder_percent: 0.0,
                duplicate_percent: 0.0,
                corrupt_percent: 0.0,
                bandwidth_mbps: 10000.0,
                prng_seed,
            },
        }
    }
}

/// Action decision outcome for an emulated packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketAction {
    /// Packet scheduled for delivery after calculated delay.
    Deliver {
        /// Total calculated delay in nanoseconds.
        delay_nanos: u64,
        /// Whether packet delivery is out-of-order relative to sequence.
        is_reordered: bool,
    },
    /// Packet dropped due to loss modeling.
    Drop {
        /// Reason for packet drop.
        reason: String,
    },
    /// Packet duplicated; primary delivered and clone delivered with offset.
    Duplicate {
        /// Delay for original packet.
        original_delay_nanos: u64,
        /// Delay for duplicated packet.
        duplicate_delay_nanos: u64,
    },
    /// Packet payload corrupted with bit flips before delivery.
    Corrupt {
        /// Delay before corrupted delivery.
        delay_nanos: u64,
        /// Count of flipped bits.
        flipped_bits: usize,
    },
}

/// An emulated packet scheduled in the priority queue.
#[derive(Debug, Clone)]
struct ScheduledPacket {
    packet_id: u64,
    release_nanos: u128,
    action: PacketAction,
    payload: Vec<u8>,
}

impl PartialEq for ScheduledPacket {
    fn eq(&self, other: &Self) -> bool {
        self.release_nanos == other.release_nanos && self.packet_id == other.packet_id
    }
}

impl Eq for ScheduledPacket {}

impl PartialOrd for ScheduledPacket {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledPacket {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse ordering so BinaryHeap acts as a min-heap by release_nanos
        other.release_nanos.cmp(&self.release_nanos)
    }
}

/// Telemetry metrics for network emulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetemMetricsSnapshot {
    /// Total packets processed.
    pub packets_processed: u64,
    /// Packets delivered successfully.
    pub packets_delivered: u64,
    /// Packets dropped due to loss.
    pub packets_dropped: u64,
    /// Packets delivered out-of-order.
    pub packets_reordered: u64,
    /// Packets duplicated.
    pub packets_duplicated: u64,
    /// Packets with bit-flip corruption.
    pub packets_corrupted: u64,
    /// Current simulated RTT in nanoseconds.
    pub latest_rtt_nanos: u64,
    /// Current queue length.
    pub queue_depth: usize,
}

/// Simulation report generated by running virtual traffic through netem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetemSimulationReport {
    /// Total simulated packets.
    pub total_packets: usize,
    /// Packets successfully delivered.
    pub delivered: usize,
    /// Packets dropped.
    pub dropped: usize,
    /// Packet delivery ratio percentage.
    pub delivery_ratio: f64,
    /// Packets delivered out of sequence.
    pub reordered: usize,
    /// Packets duplicated.
    pub duplicated: usize,
    /// Packets corrupted.
    pub corrupted: usize,
    /// Minimum observed RTT in milliseconds.
    pub min_rtt_ms: f64,
    /// Maximum observed RTT in milliseconds.
    pub max_rtt_ms: f64,
    /// Median (p50) RTT in milliseconds.
    pub p50_rtt_ms: f64,
    /// 95th percentile RTT in milliseconds.
    pub p95_rtt_ms: f64,
    /// 99th percentile RTT in milliseconds.
    pub p99_rtt_ms: f64,
    /// Effective throughput in Megabits per second.
    pub throughput_mbps: f64,
    /// Config snapshot used.
    pub config: NetemConfig,
}

/// Microsecond performance benchmark results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetemBenchmarkReport {
    /// Iterations executed.
    pub iterations: usize,
    /// Average latency to calculate jitter delay (nanoseconds).
    pub jitter_calc_nanos: f64,
    /// Average latency to evaluate Markov loss decision (nanoseconds).
    pub markov_eval_nanos: f64,
    /// Average latency to schedule packet into priority queue (nanoseconds).
    pub packet_enqueue_nanos: f64,
    /// Average latency to dequeue and emit packet from min-heap (nanoseconds).
    pub packet_dequeue_nanos: f64,
    /// Overall throughput in packets per second.
    pub throughput_pps: f64,
}

/// State of active network emulation engine.
pub struct NetemEngine {
    state_dir: PathBuf,
    config: NetemConfig,
    prng: NetemPrng,
    markov_state: MarkovState,
    last_delay_nanos: f64,
    last_emitted_id: u64,
    queue: BinaryHeap<ScheduledPacket>,
    // Metrics
    packets_processed: AtomicU64,
    packets_delivered: AtomicU64,
    packets_dropped: AtomicU64,
    packets_reordered: AtomicU64,
    packets_duplicated: AtomicU64,
    packets_corrupted: AtomicU64,
    latest_rtt_ns: AtomicU64,
    scheduler_latency_ns: AtomicU64,
}

impl NetemEngine {
    /// Initializes or loads the network emulation engine with storage at `state_dir`.
    pub fn new(state_dir: PathBuf, config: Option<NetemConfig>) -> Result<Self, VelcruxError> {
        fs::create_dir_all(&state_dir)?;
        let cfg_path = state_dir.join("netem_config.json");

        let active_cfg = if let Some(c) = config {
            let json = serde_json::to_vec_pretty(&c)
                .map_err(|e| VelcruxError::Internal(format!("serialize netem config: {}", e)))?;
            fs::write(&cfg_path, json)?;
            c
        } else if cfg_path.exists() {
            let data = fs::read(&cfg_path)?;
            serde_json::from_slice(&data)
                .map_err(|e| VelcruxError::Internal(format!("corrupt netem config: {}", e)))?
        } else {
            let def = NetemConfig::default();
            let json = serde_json::to_vec_pretty(&def).map_err(|e| {
                VelcruxError::Internal(format!("serialize default netem config: {}", e))
            })?;
            fs::write(&cfg_path, json)?;
            def
        };

        let seed = active_cfg.prng_seed;

        Ok(Self {
            state_dir,
            config: active_cfg,
            prng: NetemPrng::new(seed),
            markov_state: MarkovState::Good,
            last_delay_nanos: 0.0,
            last_emitted_id: 0,
            queue: BinaryHeap::new(),
            packets_processed: AtomicU64::new(0),
            packets_delivered: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_reordered: AtomicU64::new(0),
            packets_duplicated: AtomicU64::new(0),
            packets_corrupted: AtomicU64::new(0),
            latest_rtt_ns: AtomicU64::new(0),
            scheduler_latency_ns: AtomicU64::new(0),
        })
    }

    /// Update configuration and persist to disk.
    pub fn update_config(&mut self, config: NetemConfig) -> Result<(), VelcruxError> {
        let cfg_path = self.state_dir.join("netem_config.json");
        let json = serde_json::to_vec_pretty(&config)
            .map_err(|e| VelcruxError::Internal(format!("serialize netem config: {}", e)))?;
        fs::write(&cfg_path, json)?;
        self.prng = NetemPrng::new(config.prng_seed);
        self.config = config;
        Ok(())
    }

    /// Read active configuration.
    pub fn config(&self) -> &NetemConfig {
        &self.config
    }

    /// Compute simulated one-way delay with jitter and correlation.
    fn calculate_delay_nanos(&mut self) -> u64 {
        let base_delay_ns = (self.config.delay_ms * 1_000_000.0).max(0.0);
        let jitter_ns = (self.config.jitter_ms * 1_000_000.0).max(0.0);

        if jitter_ns <= 0.0 {
            return base_delay_ns as u64;
        }

        // Generate raw deviation delta
        let delta = match self.config.jitter_dist {
            JitterDistribution::Uniform => (self.prng.next_f64() * 2.0 - 1.0) * jitter_ns,
            JitterDistribution::Normal => self.prng.next_gaussian() * jitter_ns,
            JitterDistribution::Pareto => {
                let pareto = self.prng.next_pareto(1.0, self.config.pareto_shape);
                (pareto - 1.0) * jitter_ns
            }
        };

        // Apply autoregressive correlation: d = rho * last + (1 - rho) * delta
        let rho = self.config.delay_correlation.clamp(0.0, 0.999);
        let correlated_delta = rho * self.last_delay_nanos + (1.0 - rho) * delta;
        self.last_delay_nanos = correlated_delta;

        (base_delay_ns + correlated_delta).max(10_000.0) as u64 // Minimum 10 microseconds
    }

    /// Evaluate loss model (uniform loss and Gilbert-Elliott Markov burst loss).
    fn evaluate_loss(&mut self) -> bool {
        // 1. Check independent random loss
        if self.config.loss_percent > 0.0 {
            let roll = self.prng.next_f64() * 100.0;
            if roll < self.config.loss_percent {
                return true;
            }
        }

        // 2. Check Gilbert-Elliott Markov chain loss
        if let Some(markov) = &self.config.markov_loss {
            // State transition
            match self.markov_state {
                MarkovState::Good => {
                    if self.prng.next_f64() < markov.p {
                        self.markov_state = MarkovState::Bad;
                    }
                }
                MarkovState::Bad => {
                    if self.prng.next_f64() < markov.r {
                        self.markov_state = MarkovState::Good;
                    }
                }
            }

            // Packet loss decision based on current state
            let loss_prob = match self.markov_state {
                MarkovState::Good => markov.loss_good,
                MarkovState::Bad => markov.loss_bad,
            };

            if self.prng.next_f64() < loss_prob {
                return true;
            }
        }

        false
    }

    /// Process an inbound packet through the network emulation pipeline.
    pub fn process_packet(
        &mut self,
        packet_id: u64,
        payload: &[u8],
        now_nanos: u128,
    ) -> PacketAction {
        let start_time = Instant::now();
        self.packets_processed.fetch_add(1, Ordering::Relaxed);

        if !self.config.enabled {
            self.packets_delivered.fetch_add(1, Ordering::Relaxed);
            return PacketAction::Deliver {
                delay_nanos: 0,
                is_reordered: false,
            };
        }

        // 1. Check Loss
        if self.evaluate_loss() {
            self.packets_dropped.fetch_add(1, Ordering::Relaxed);
            return PacketAction::Drop {
                reason: "loss model rejection".to_string(),
            };
        }

        // 2. Calculate delay
        let delay_ns = self.calculate_delay_nanos();
        self.latest_rtt_ns.store(delay_ns * 2, Ordering::Relaxed);

        // 3. Check Corruption (bit flips)
        if self.config.corrupt_percent > 0.0 {
            let roll = self.prng.next_f64() * 100.0;
            if roll < self.config.corrupt_percent {
                self.packets_corrupted.fetch_add(1, Ordering::Relaxed);
                let mut corrupted_payload = payload.to_vec();
                let flipped_bits = if !corrupted_payload.is_empty() {
                    let byte_idx = (self.prng.next_u64() as usize) % corrupted_payload.len();
                    let bit_idx = (self.prng.next_u64() % 8) as u8;
                    corrupted_payload[byte_idx] ^= 1 << bit_idx;
                    1
                } else {
                    0
                };

                let sched = ScheduledPacket {
                    packet_id,
                    release_nanos: now_nanos + delay_ns as u128,
                    action: PacketAction::Corrupt {
                        delay_nanos: delay_ns,
                        flipped_bits,
                    },
                    payload: corrupted_payload,
                };
                self.queue.push(sched);

                return PacketAction::Corrupt {
                    delay_nanos: delay_ns,
                    flipped_bits,
                };
            }
        }

        // 4. Check Duplication
        if self.config.duplicate_percent > 0.0 {
            let roll = self.prng.next_f64() * 100.0;
            if roll < self.config.duplicate_percent {
                self.packets_duplicated.fetch_add(1, Ordering::Relaxed);
                let dup_delay = delay_ns + (self.calculate_delay_nanos() / 2).max(500_000);

                let sched_orig = ScheduledPacket {
                    packet_id,
                    release_nanos: now_nanos + delay_ns as u128,
                    action: PacketAction::Deliver {
                        delay_nanos: delay_ns,
                        is_reordered: false,
                    },
                    payload: payload.to_vec(),
                };
                let sched_dup = ScheduledPacket {
                    packet_id,
                    release_nanos: now_nanos + dup_delay as u128,
                    action: PacketAction::Duplicate {
                        original_delay_nanos: delay_ns,
                        duplicate_delay_nanos: dup_delay,
                    },
                    payload: payload.to_vec(),
                };
                self.queue.push(sched_orig);
                self.queue.push(sched_dup);

                return PacketAction::Duplicate {
                    original_delay_nanos: delay_ns,
                    duplicate_delay_nanos: dup_delay,
                };
            }
        }

        // 5. Standard Deliver with natural priority-queue reordering
        let is_reordered = if self.config.reorder_percent > 0.0 {
            let roll = self.prng.next_f64() * 100.0;
            roll < self.config.reorder_percent
        } else {
            false
        };

        let effective_delay = if is_reordered {
            // Apply delay gap to induce reordering overtake
            delay_ns + (self.calculate_delay_nanos() * 2)
        } else {
            delay_ns
        };

        if is_reordered {
            self.packets_reordered.fetch_add(1, Ordering::Relaxed);
        }
        self.packets_delivered.fetch_add(1, Ordering::Relaxed);

        let sched = ScheduledPacket {
            packet_id,
            release_nanos: now_nanos + effective_delay as u128,
            action: PacketAction::Deliver {
                delay_nanos: effective_delay,
                is_reordered,
            },
            payload: payload.to_vec(),
        };
        self.queue.push(sched);

        let sched_elapsed = start_time.elapsed().as_nanos() as u64;
        self.scheduler_latency_ns
            .store(sched_elapsed, Ordering::Relaxed);

        PacketAction::Deliver {
            delay_nanos: effective_delay,
            is_reordered,
        }
    }

    /// Emits all packets whose scheduled release deadline has arrived.
    pub fn poll_ready(&mut self, current_time_nanos: u128) -> Vec<(u64, PacketAction, Vec<u8>)> {
        let mut ready = Vec::new();
        while let Some(top) = self.queue.peek() {
            if top.release_nanos <= current_time_nanos {
                let packet = self.queue.pop().unwrap();
                let is_out_of_order = packet.packet_id < self.last_emitted_id;
                self.last_emitted_id = self.last_emitted_id.max(packet.packet_id);

                let action = match packet.action {
                    PacketAction::Deliver { delay_nanos, .. } => PacketAction::Deliver {
                        delay_nanos,
                        is_reordered: is_out_of_order,
                    },
                    other => other,
                };

                ready.push((packet.packet_id, action, packet.payload));
            } else {
                break;
            }
        }
        ready
    }

    /// Returns telemetry metrics snapshot.
    pub fn metrics_snapshot(&self) -> NetemMetricsSnapshot {
        NetemMetricsSnapshot {
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            packets_delivered: self.packets_delivered.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_reordered: self.packets_reordered.load(Ordering::Relaxed),
            packets_duplicated: self.packets_duplicated.load(Ordering::Relaxed),
            packets_corrupted: self.packets_corrupted.load(Ordering::Relaxed),
            latest_rtt_nanos: self.latest_rtt_ns.load(Ordering::Relaxed),
            queue_depth: self.queue.len(),
        }
    }

    /// Simulates virtual traffic stream across the active netem profile.
    pub fn simulate_traffic(
        &mut self,
        packet_count: usize,
        packet_size: usize,
    ) -> NetemSimulationReport {
        let count = packet_count.max(1);
        let dummy_payload = vec![0xABu8; packet_size.max(64)];

        let mut delivered = 0usize;
        let mut dropped = 0usize;
        let mut reordered = 0usize;
        let mut duplicated = 0usize;
        let mut corrupted = 0usize;
        let mut rtts_ms = Vec::with_capacity(count);

        let mut sim_clock_nanos: u128 = 1_000_000_000; // start at 1 second
        let packet_interval_nanos: u128 = 1_000_000_000 / 1000; // 1 ms pacing = 1,000 pps

        for i in 1..=count {
            let action = self.process_packet(i as u64, &dummy_payload, sim_clock_nanos);
            match action {
                PacketAction::Deliver {
                    delay_nanos,
                    is_reordered,
                } => {
                    delivered += 1;
                    if is_reordered {
                        reordered += 1;
                    }
                    rtts_ms.push((delay_nanos * 2) as f64 / 1_000_000.0);
                }
                PacketAction::Drop { .. } => {
                    dropped += 1;
                }
                PacketAction::Duplicate {
                    original_delay_nanos,
                    ..
                } => {
                    delivered += 1;
                    duplicated += 1;
                    rtts_ms.push((original_delay_nanos * 2) as f64 / 1_000_000.0);
                }
                PacketAction::Corrupt { delay_nanos, .. } => {
                    delivered += 1;
                    corrupted += 1;
                    rtts_ms.push((delay_nanos * 2) as f64 / 1_000_000.0);
                }
            }
            sim_clock_nanos += packet_interval_nanos;
        }

        // Drain remaining queue
        sim_clock_nanos += 5_000_000_000; // advance 5 seconds to drain all
        let _ = self.poll_ready(sim_clock_nanos);

        rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(CmpOrdering::Equal));

        let min_rtt_ms = rtts_ms.first().copied().unwrap_or(0.0);
        let max_rtt_ms = rtts_ms.last().copied().unwrap_or(0.0);
        let p50_rtt_ms = if !rtts_ms.is_empty() {
            rtts_ms[rtts_ms.len() * 50 / 100]
        } else {
            0.0
        };
        let p95_rtt_ms = if !rtts_ms.is_empty() {
            rtts_ms[rtts_ms.len() * 95 / 100]
        } else {
            0.0
        };
        let p99_rtt_ms = if !rtts_ms.is_empty() {
            rtts_ms[rtts_ms.len() * 99 / 100]
        } else {
            0.0
        };

        let delivery_ratio = (delivered as f64 / count as f64) * 100.0;
        let total_bytes = (delivered * packet_size) as f64;
        let total_time_sec = (count as f64 * packet_interval_nanos as f64) / 1_000_000_000.0;
        let throughput_mbps = (total_bytes * 8.0) / (total_time_sec * 1_000_000.0);

        NetemSimulationReport {
            total_packets: count,
            delivered,
            dropped,
            delivery_ratio,
            reordered,
            duplicated,
            corrupted,
            min_rtt_ms,
            max_rtt_ms,
            p50_rtt_ms,
            p95_rtt_ms,
            p99_rtt_ms,
            throughput_mbps,
            config: self.config.clone(),
        }
    }

    /// Runs microsecond performance benchmark measuring netem scheduler primitives.
    pub fn run_benchmark(iterations: usize) -> Result<NetemBenchmarkReport, VelcruxError> {
        let iters = iterations.max(10);
        let bench_dir =
            std::env::temp_dir().join(format!("velcrux_netem_bench_{}", current_epoch_nanos()));
        fs::create_dir_all(&bench_dir)?;

        let mut engine = NetemEngine::new(
            bench_dir.clone(),
            Some(NetemConfig::from_preset(
                NetemProfilePreset::StarlinkSatellite,
                Some(42),
            )),
        )?;

        // 1. Benchmark Jitter Calculation
        let start = Instant::now();
        for _ in 0..iters {
            let _ = engine.calculate_delay_nanos();
        }
        let jitter_calc_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 2. Benchmark Markov Loss Evaluation
        let start = Instant::now();
        for _ in 0..iters {
            let _ = engine.evaluate_loss();
        }
        let markov_eval_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 3. Benchmark Packet Enqueue (process_packet)
        let dummy = [0x55u8; 1200];
        let start = Instant::now();
        let base_time: u128 = 1_000_000_000;
        for i in 0..iters {
            let _ = engine.process_packet(i as u64, &dummy, base_time + (i as u128 * 1_000_000));
        }
        let packet_enqueue_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 4. Benchmark Packet Dequeue (poll_ready)
        let drain_time: u128 = base_time + 100_000_000_000;
        let start = Instant::now();
        let emitted = engine.poll_ready(drain_time);
        let packet_dequeue_nanos =
            start.elapsed().as_nanos() as f64 / (emitted.len().max(1)) as f64;

        let throughput_pps =
            1_000_000_000.0 / (packet_enqueue_nanos + packet_dequeue_nanos).max(1.0);

        let _ = fs::remove_dir_all(&bench_dir);

        Ok(NetemBenchmarkReport {
            iterations: iters,
            jitter_calc_nanos,
            markov_eval_nanos,
            packet_enqueue_nanos,
            packet_dequeue_nanos,
            throughput_pps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_engine(test_name: &str) -> (NetemEngine, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "velcrux_netem_test_{}_{}",
            test_name,
            current_epoch_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        let engine = NetemEngine::new(dir.clone(), None).unwrap();
        (engine, dir)
    }

    #[test]
    fn test_netem_prng_determinism() {
        let mut prng1 = NetemPrng::new(0x12345678);
        let mut prng2 = NetemPrng::new(0x12345678);

        for _ in 0..100 {
            assert_eq!(prng1.next_u64(), prng2.next_u64());
            assert_eq!(prng1.next_f64(), prng2.next_f64());
            assert_eq!(prng1.next_gaussian(), prng2.next_gaussian());
        }
    }

    #[test]
    fn test_netem_preset_configurations() {
        let presets = [
            NetemProfilePreset::StarlinkSatellite,
            NetemProfilePreset::TransatlanticWan,
            NetemProfilePreset::RuralCellular5G,
            NetemProfilePreset::BufferbloatAdverse,
            NetemProfilePreset::PristineLan,
        ];

        for preset in presets {
            let config = NetemConfig::from_preset(preset, Some(100));
            assert!(config.enabled);
            assert_eq!(config.prng_seed, 100);
            assert!(config.delay_ms >= 0.0);
            assert!(config.jitter_ms >= 0.0);
        }
    }

    #[test]
    fn test_netem_traffic_simulation_starlink() {
        let (mut engine, dir) = create_test_engine("sim_starlink");
        let starlink_cfg =
            NetemConfig::from_preset(NetemProfilePreset::StarlinkSatellite, Some(999));
        engine.update_config(starlink_cfg).unwrap();

        let report = engine.simulate_traffic(200, 1024);
        assert_eq!(report.total_packets, 200);
        assert!(
            report.delivered >= 140,
            "Expected majority of packets delivered: {}",
            report.delivered
        );
        assert!(
            report.dropped > 0,
            "Expected some packets dropped: {}",
            report.dropped
        );
        assert!(
            report.p50_rtt_ms > 40.0,
            "Expected Starlink RTT > 40ms: {}",
            report.p50_rtt_ms
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_netem_traffic_simulation_pristine_lan() {
        let (mut engine, dir) = create_test_engine("sim_lan");
        let lan_cfg = NetemConfig::from_preset(NetemProfilePreset::PristineLan, Some(42));
        engine.update_config(lan_cfg).unwrap();

        let report = engine.simulate_traffic(100, 1024);
        assert_eq!(report.delivered, 100);
        assert_eq!(report.dropped, 0);
        assert!(report.p50_rtt_ms < 1.0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_netem_payload_corruption_bit_flip() {
        let (mut engine, dir) = create_test_engine("corruption");
        let mut cfg = NetemConfig::default();
        cfg.enabled = true;
        cfg.corrupt_percent = 100.0; // Corrupt every packet
        engine.update_config(cfg).unwrap();

        let original = vec![0xFFu8; 32];
        let action = engine.process_packet(1, &original, 1_000_000);
        match action {
            PacketAction::Corrupt { flipped_bits, .. } => {
                assert_eq!(flipped_bits, 1);
            }
            other => panic!("expected PacketAction::Corrupt, got {:?}", other),
        }

        let ready = engine.poll_ready(100_000_000);
        assert_eq!(ready.len(), 1);
        let (_, _, corrupted_payload) = &ready[0];
        assert_ne!(corrupted_payload, &original);
        assert_eq!(corrupted_payload.len(), 32);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_netem_benchmark() {
        let bench = NetemEngine::run_benchmark(50).unwrap();
        assert_eq!(bench.iterations, 50);
        assert!(bench.jitter_calc_nanos > 0.0);
        assert!(bench.packet_enqueue_nanos > 0.0);
        assert!(bench.throughput_pps > 0.0);
    }
}
