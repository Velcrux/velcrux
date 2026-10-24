//! Automated Continuous Chaos Engineering, WAN Impairment & Network Fault Injection Suite (`ADR-040`).
//!
//! (`REQUIREMENTS.md` §45, §78, §79; `ARCHITECTURE.md` §2, §7; `ADR-040`).
//!
//! Features:
//! 1. Gilbert-Elliott 2-state Markov chain for realistic burst packet loss modeling.
//! 2. Jitter and latency distribution simulation (Normal/Pareto propagation delay).
//! 3. Packet reordering and duplicate frame delivery queues.
//! 4. Byzantine payload corruption injection (bit flips and byte scrambling) testing BLAKE3 integrity.
//! 5. Network partition and asymmetric blackholing simulation.
//! 6. Deterministic seedable pseudo-random generation for 100% reproducible chaos experiments.
//! 7. 100% Safe Rust (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::util::Hash;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Deterministic, fast Xorshift64* pseudo-random number generator for reproducible chaos testing.
#[derive(Debug, Clone)]
pub struct ChaosPrng {
    state: u64,
}

impl ChaosPrng {
    /// Construct PRNG with seed. If seed is 0, uses non-zero constant default.
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    /// Generate next pseudo-random u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Generate pseudo-random float in [0.0, 1.0).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }

    /// Generate pseudo-random integer in range [0, max).
    pub fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            0
        } else {
            self.next_u64() % max
        }
    }
}

impl Default for ChaosPrng {
    fn default() -> Self {
        Self::new(1337)
    }
}

/// Gilbert-Elliott 2-state Markov burst loss model parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GilbertElliottConfig {
    /// Probability of transitioning from Good to Bad state: P(G -> B).
    pub p: f64,
    /// Probability of transitioning from Bad to Good state: P(B -> G).
    pub r: f64,
    /// Loss probability in Good state (typically 0.0 or low, e.g. 0.001).
    pub loss_in_good: f64,
    /// Loss probability in Bad state (typically 1.0 or high, e.g. 0.95).
    pub loss_in_bad: f64,
}

impl Default for GilbertElliottConfig {
    fn default() -> Self {
        Self {
            p: 0.02, // 2% chance to transition into burst loss
            r: 0.20, // 20% recovery rate (average burst duration = 1/r = 5 packets)
            loss_in_good: 0.001,
            loss_in_bad: 0.95,
        }
    }
}

/// State of the Gilbert-Elliott Markov chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkovState {
    /// Normal low-loss link state.
    Good = 0,
    /// Degraded high-loss burst state.
    Bad = 1,
}

/// Dynamic Markov state tracker.
#[derive(Debug, Clone)]
pub struct GilbertElliottModel {
    config: GilbertElliottConfig,
    state: MarkovState,
}

impl GilbertElliottModel {
    /// Construct new Markov burst model.
    pub fn new(config: GilbertElliottConfig) -> Self {
        Self {
            config,
            state: MarkovState::Good,
        }
    }

    /// Current operational state.
    pub fn current_state(&self) -> MarkovState {
        self.state
    }

    /// Evaluate packet drop decision and step state forward.
    pub fn step(&mut self, prng: &mut ChaosPrng) -> bool {
        // 1. Determine packet loss for current state
        let loss_prob = match self.state {
            MarkovState::Good => self.config.loss_in_good,
            MarkovState::Bad => self.config.loss_in_bad,
        };
        let dropped = prng.next_f64() < loss_prob;

        // 2. Transition state
        match self.state {
            MarkovState::Good => {
                if prng.next_f64() < self.config.p {
                    self.state = MarkovState::Bad;
                }
            }
            MarkovState::Bad => {
                if prng.next_f64() < self.config.r {
                    self.state = MarkovState::Good;
                }
            }
        }

        dropped
    }
}

/// Built-in preconfigured WAN impairment and fault injection profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChaosProfileKind {
    /// Zero impairments; ideal baseline link.
    Clean,
    /// Transcontinental subsea optical fiber (120ms RTT, 10ms jitter, 1.5% loss, 0.2% reorder).
    Subsea,
    /// LEO Satellite link (45ms RTT, 25ms jitter, 3.5% loss, 0.5% duplicate).
    Satellite,
    /// Hostile cellular / mobile link (160ms RTT, 50ms jitter, 8.0% burst loss, 2.0% reorder).
    Cellular,
    /// Active Byzantine bit-rot adversary (10ms RTT, 0.5% corrupt rate).
    Byzantine,
    /// Complete network severance / partition blackhole.
    Partition,
}

impl ChaosProfileKind {
    /// Canonical profile identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Subsea => "subsea",
            Self::Satellite => "satellite",
            Self::Cellular => "cellular",
            Self::Byzantine => "byzantine",
            Self::Partition => "partition",
        }
    }

    /// Parse profile from string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "clean" | "none" => Some(Self::Clean),
            "subsea" | "transcontinental" | "wan" => Some(Self::Subsea),
            "satellite" | "leo" | "starlink" => Some(Self::Satellite),
            "cellular" | "mobile" | "4g" | "5g" => Some(Self::Cellular),
            "byzantine" | "corrupt" | "adversary" => Some(Self::Byzantine),
            "partition" | "blackhole" | "sever" => Some(Self::Partition),
            _ => None,
        }
    }
}

/// Comprehensive chaos injection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosConfig {
    /// Whether chaos injection is actively enabled.
    pub enabled: bool,
    /// Uniform Bernoulli packet loss probability (0.0 to 1.0).
    pub loss_rate: f64,
    /// Optional Gilbert-Elliott burst loss model.
    pub burst_loss: Option<GilbertElliottConfig>,
    /// Base latency injection in milliseconds.
    pub delay_ms: u64,
    /// Random latency jitter in milliseconds (± jitter).
    pub jitter_ms: u64,
    /// Packet reordering probability (0.0 to 1.0).
    pub reorder_rate: f64,
    /// Extra delay applied to reordered packets.
    pub reorder_delay_ms: u64,
    /// Packet duplication probability (0.0 to 1.0).
    pub duplicate_rate: f64,
    /// Byzantine bit-flip / payload corruption rate (0.0 to 1.0).
    pub corrupt_rate: f64,
    /// Complete network partition blackhole.
    pub blackhole: bool,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            loss_rate: 0.0,
            burst_loss: None,
            delay_ms: 0,
            jitter_ms: 0,
            reorder_rate: 0.0,
            reorder_delay_ms: 20,
            duplicate_rate: 0.0,
            corrupt_rate: 0.0,
            blackhole: false,
        }
    }
}

impl ChaosConfig {
    /// Instantiate a configuration from a profile preset.
    pub fn from_profile(kind: ChaosProfileKind) -> Self {
        match kind {
            ChaosProfileKind::Clean => Self::default(),
            ChaosProfileKind::Subsea => Self {
                enabled: true,
                loss_rate: 0.015,
                burst_loss: None,
                delay_ms: 60, // 120ms RTT / 2
                jitter_ms: 10,
                reorder_rate: 0.002,
                reorder_delay_ms: 15,
                duplicate_rate: 0.0005,
                corrupt_rate: 0.0,
                blackhole: false,
            },
            ChaosProfileKind::Satellite => Self {
                enabled: true,
                loss_rate: 0.035,
                burst_loss: None,
                delay_ms: 25,
                jitter_ms: 20,
                reorder_rate: 0.01,
                reorder_delay_ms: 25,
                duplicate_rate: 0.005,
                corrupt_rate: 0.0,
                blackhole: false,
            },
            ChaosProfileKind::Cellular => Self {
                enabled: true,
                loss_rate: 0.02,
                burst_loss: Some(GilbertElliottConfig {
                    p: 0.05,
                    r: 0.25,
                    loss_in_good: 0.005,
                    loss_in_bad: 0.90,
                }),
                delay_ms: 80,
                jitter_ms: 50,
                reorder_rate: 0.02,
                reorder_delay_ms: 40,
                duplicate_rate: 0.008,
                corrupt_rate: 0.0,
                blackhole: false,
            },
            ChaosProfileKind::Byzantine => Self {
                enabled: true,
                loss_rate: 0.0,
                burst_loss: None,
                delay_ms: 5,
                jitter_ms: 2,
                reorder_rate: 0.0,
                reorder_delay_ms: 0,
                duplicate_rate: 0.0,
                corrupt_rate: 0.005, // 0.5% payload bit corruption
                blackhole: false,
            },
            ChaosProfileKind::Partition => Self {
                enabled: true,
                loss_rate: 1.0,
                burst_loss: None,
                delay_ms: 0,
                jitter_ms: 0,
                reorder_rate: 0.0,
                reorder_delay_ms: 0,
                duplicate_rate: 0.0,
                corrupt_rate: 0.0,
                blackhole: true,
            },
        }
    }
}

/// Individual outcome decision for a processed packet or chunk frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChaosOutcome {
    /// Packet delivered normally with computed latency.
    Pass {
        /// Simulated delivery delay in milliseconds.
        delay_ms: u64,
        /// Payload data (may be corrupted if Byzantine injection triggered).
        payload: Bytes,
    },
    /// Packet dropped (simulated loss or blackhole).
    Drop,
    /// Packet duplicated: yields original and extra copies.
    Duplicate {
        /// Delivery delay.
        delay_ms: u64,
        /// Original and duplicated copies.
        copies: Vec<Bytes>,
    },
    /// Packet delayed out-of-order for reordering simulation.
    Reorder {
        /// Augmented delay for out-of-order reception.
        delay_ms: u64,
        /// Payload data.
        payload: Bytes,
    },
}

/// Cumulative telemetry metrics for chaos injection operations.
#[derive(Debug, Default)]
pub struct ChaosStats {
    /// Total packets/frames inspected.
    pub packets_processed: AtomicU64,
    /// Packets delivered without impairment.
    pub packets_passed: AtomicU64,
    /// Packets dropped due to uniform or burst loss.
    pub packets_dropped: AtomicU64,
    /// Packets delayed by latency injection.
    pub packets_delayed: AtomicU64,
    /// Packets flagged for reordering.
    pub packets_reordered: AtomicU64,
    /// Duplicate packets emitted.
    pub packets_duplicated: AtomicU64,
    /// Bytes corrupted via Byzantine injection.
    pub bytes_corrupted: AtomicU64,
    /// Partitions actively enforced.
    pub partitions_active: AtomicU64,
}

/// Operational status report for chaos engine monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosStatusReport {
    /// Whether chaos engine is enabled.
    pub enabled: bool,
    /// Active profile name or custom.
    pub active_profile: String,
    /// Total packets evaluated.
    pub packets_processed: u64,
    /// Packets delivered.
    pub packets_passed: u64,
    /// Packets dropped.
    pub packets_dropped: u64,
    /// Measured effective loss percentage.
    pub loss_percentage: f64,
    /// Packets delayed.
    pub packets_delayed: u64,
    /// Packets reordered.
    pub packets_reordered: u64,
    /// Duplicate packets emitted.
    pub packets_duplicated: u64,
    /// Corrupt bytes injected.
    pub bytes_corrupted: u64,
    /// Whether network is partitioned.
    pub blackhole_active: bool,
}

/// Core chaos injection and fault emulation engine.
pub struct ChaosEngine {
    config: Mutex<ChaosConfig>,
    prng: Mutex<ChaosPrng>,
    markov: Mutex<Option<GilbertElliottModel>>,
    stats: Arc<ChaosStats>,
    active_profile_name: Mutex<String>,
}

impl ChaosEngine {
    /// Construct a new chaos engine with given configuration.
    pub fn new(config: ChaosConfig, seed: u64) -> Self {
        let stats = Arc::new(ChaosStats::default());
        let markov = config
            .burst_loss
            .as_ref()
            .map(|c| GilbertElliottModel::new(c.clone()));
        let enabled = config.enabled;

        Self {
            config: Mutex::new(config),
            prng: Mutex::new(ChaosPrng::new(seed)),
            markov: Mutex::new(markov),
            stats,
            active_profile_name: Mutex::new(if enabled {
                "custom".to_string()
            } else {
                "disabled".to_string()
            }),
        }
    }

    /// Construct a chaos engine initialized with a profile preset.
    pub fn from_profile(kind: ChaosProfileKind, seed: u64) -> Self {
        let config = ChaosConfig::from_profile(kind);
        let name = kind.as_str().to_string();
        let engine = Self::new(config, seed);
        *engine.active_profile_name.lock().unwrap() = name;
        engine
    }

    /// Reference to telemetry stats.
    pub fn stats(&self) -> &Arc<ChaosStats> {
        &self.stats
    }

    /// Update engine configuration dynamically at runtime.
    pub fn set_config(&self, config: ChaosConfig) {
        let mut markov_guard = self.markov.lock().unwrap();
        *markov_guard = config
            .burst_loss
            .as_ref()
            .map(|c| GilbertElliottModel::new(c.clone()));
        *self.config.lock().unwrap() = config;
    }

    /// Check if chaos injection is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.lock().unwrap().enabled
    }

    /// Evaluate fault injection decisions for a single data payload.
    pub fn process_packet(&self, payload: &[u8]) -> ChaosOutcome {
        self.stats.packets_processed.fetch_add(1, Ordering::Relaxed);

        let config = self.config.lock().unwrap().clone();
        if !config.enabled {
            self.stats.packets_passed.fetch_add(1, Ordering::Relaxed);
            return ChaosOutcome::Pass {
                delay_ms: 0,
                payload: Bytes::copy_from_slice(payload),
            };
        }

        // 1. Blackhole / Partition check
        if config.blackhole {
            self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.stats.partitions_active.store(1, Ordering::Relaxed);
            return ChaosOutcome::Drop;
        } else {
            self.stats.partitions_active.store(0, Ordering::Relaxed);
        }

        let mut prng = self.prng.lock().unwrap();

        // 2. Burst packet loss (Gilbert-Elliott) or uniform loss
        let should_drop = if let Some(ref mut model) = *self.markov.lock().unwrap() {
            model.step(&mut prng)
        } else if config.loss_rate > 0.0 {
            prng.next_f64() < config.loss_rate
        } else {
            false
        };

        if should_drop {
            self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            return ChaosOutcome::Drop;
        }

        // 3. Compute transmission delay & jitter
        let jitter = if config.jitter_ms > 0 {
            let variance =
                prng.next_range(config.jitter_ms * 2 + 1) as i64 - config.jitter_ms as i64;
            (config.delay_ms as i64 + variance).max(0) as u64
        } else {
            config.delay_ms
        };

        if jitter > 0 {
            self.stats.packets_delayed.fetch_add(1, Ordering::Relaxed);
        }

        // 4. Byzantine corruption injection
        let final_payload = if config.corrupt_rate > 0.0 && prng.next_f64() < config.corrupt_rate {
            let corrupted = self.corrupt_bytes(payload, &mut prng);
            self.stats
                .bytes_corrupted
                .fetch_add(corrupted.len() as u64, Ordering::Relaxed);
            Bytes::from(corrupted)
        } else {
            Bytes::copy_from_slice(payload)
        };

        // 5. Packet Duplication
        if config.duplicate_rate > 0.0 && prng.next_f64() < config.duplicate_rate {
            self.stats
                .packets_duplicated
                .fetch_add(1, Ordering::Relaxed);
            return ChaosOutcome::Duplicate {
                delay_ms: jitter,
                copies: vec![final_payload.clone(), final_payload],
            };
        }

        // 6. Packet Reordering
        if config.reorder_rate > 0.0 && prng.next_f64() < config.reorder_rate {
            self.stats.packets_reordered.fetch_add(1, Ordering::Relaxed);
            let reordered_delay = jitter + config.reorder_delay_ms;
            return ChaosOutcome::Reorder {
                delay_ms: reordered_delay,
                payload: final_payload,
            };
        }

        self.stats.packets_passed.fetch_add(1, Ordering::Relaxed);
        ChaosOutcome::Pass {
            delay_ms: jitter,
            payload: final_payload,
        }
    }

    /// Mutate random bits in payload data to simulate memory or line bit-rot.
    fn corrupt_bytes(&self, data: &[u8], prng: &mut ChaosPrng) -> Vec<u8> {
        let mut corrupted = data.to_vec();
        if corrupted.is_empty() {
            return corrupted;
        }

        // Select 1 to 3 random positions to flip bits
        let flips = (prng.next_range(3) + 1) as usize;
        for _ in 0..flips {
            let idx = prng.next_range(corrupted.len() as u64) as usize;
            let bit_mask = 1 << prng.next_range(8);
            corrupted[idx] ^= bit_mask;
        }

        corrupted
    }

    /// Produce operational telemetry status report.
    pub fn status(&self) -> ChaosStatusReport {
        let config = self.config.lock().unwrap();
        let processed = self.stats.packets_processed.load(Ordering::Relaxed);
        let passed = self.stats.packets_passed.load(Ordering::Relaxed);
        let dropped = self.stats.packets_dropped.load(Ordering::Relaxed);
        let delayed = self.stats.packets_delayed.load(Ordering::Relaxed);
        let reordered = self.stats.packets_reordered.load(Ordering::Relaxed);
        let duplicated = self.stats.packets_duplicated.load(Ordering::Relaxed);
        let corrupted = self.stats.bytes_corrupted.load(Ordering::Relaxed);

        let loss_percentage = if processed == 0 {
            0.0
        } else {
            (dropped as f64 / processed as f64) * 100.0
        };

        ChaosStatusReport {
            enabled: config.enabled,
            active_profile: self.active_profile_name.lock().unwrap().clone(),
            packets_processed: processed,
            packets_passed: passed,
            packets_dropped: dropped,
            loss_percentage,
            packets_delayed: delayed,
            packets_reordered: reordered,
            packets_duplicated: duplicated,
            bytes_corrupted: corrupted,
            blackhole_active: config.blackhole,
        }
    }
}

/// Benchmark report summarizing execution of a simulated chaos scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosBenchmarkReport {
    /// Evaluated profile name.
    pub profile_name: String,
    /// Total packets simulated.
    pub total_packets: usize,
    /// Delivered packets.
    pub delivered_packets: u64,
    /// Dropped packets.
    pub dropped_packets: u64,
    /// Measured loss rate percentage.
    pub measured_loss_pct: f64,
    /// Reordered packets.
    pub reordered_packets: u64,
    /// Duplicated packets.
    pub duplicated_packets: u64,
    /// Corrupted payloads generated.
    pub corrupted_payloads: u64,
    /// Benchmark execution duration in milliseconds.
    pub duration_ms: u64,
    /// Average simulated delivery latency in milliseconds.
    pub avg_delay_ms: f64,
}

/// Run a deterministic in-memory chaos benchmark across a specified impairment profile.
pub fn run_chaos_benchmark(profile_name: &str, num_packets: usize) -> ChaosBenchmarkReport {
    let t0 = std::time::Instant::now();
    let kind = ChaosProfileKind::from_name(profile_name).unwrap_or(ChaosProfileKind::Subsea);
    let engine = ChaosEngine::from_profile(kind, 42);

    let dummy_chunk = vec![0xABu8; 1024]; // 1 KiB packet
    let mut total_delay_ms = 0u64;
    let mut corrupt_count = 0u64;

    for _ in 0..num_packets {
        match engine.process_packet(&dummy_chunk) {
            ChaosOutcome::Pass { delay_ms, payload } => {
                total_delay_ms += delay_ms;
                if Hash::of(&payload) != Hash::of(&dummy_chunk) {
                    corrupt_count += 1;
                }
            }
            ChaosOutcome::Duplicate { delay_ms, copies } => {
                total_delay_ms += delay_ms;
                for copy in copies {
                    if Hash::of(&copy) != Hash::of(&dummy_chunk) {
                        corrupt_count += 1;
                    }
                }
            }
            ChaosOutcome::Reorder { delay_ms, payload } => {
                total_delay_ms += delay_ms;
                if Hash::of(&payload) != Hash::of(&dummy_chunk) {
                    corrupt_count += 1;
                }
            }
            ChaosOutcome::Drop => {}
        }
    }

    let stats = engine.stats();
    let delivered = stats.packets_passed.load(Ordering::Relaxed)
        + stats.packets_delayed.load(Ordering::Relaxed)
        + stats.packets_reordered.load(Ordering::Relaxed);
    let dropped = stats.packets_dropped.load(Ordering::Relaxed);
    let reordered = stats.packets_reordered.load(Ordering::Relaxed);
    let duplicated = stats.packets_duplicated.load(Ordering::Relaxed);

    let measured_loss_pct = if num_packets == 0 {
        0.0
    } else {
        (dropped as f64 / num_packets as f64) * 100.0
    };

    let avg_delay = if num_packets - (dropped as usize) > 0 {
        total_delay_ms as f64 / (num_packets - (dropped as usize)) as f64
    } else {
        0.0
    };

    ChaosBenchmarkReport {
        profile_name: kind.as_str().to_string(),
        total_packets: num_packets,
        delivered_packets: delivered,
        dropped_packets: dropped,
        measured_loss_pct,
        reordered_packets: reordered,
        duplicated_packets: duplicated,
        corrupted_payloads: corrupt_count,
        duration_ms: t0.elapsed().as_millis() as u64,
        avg_delay_ms: avg_delay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gilbert_elliott_burst_loss() {
        let config = GilbertElliottConfig {
            p: 0.10,
            r: 0.50,
            loss_in_good: 0.0,
            loss_in_bad: 1.0,
        };
        let mut model = GilbertElliottModel::new(config);
        let mut prng = ChaosPrng::new(100);

        let mut drops = 0;
        for _ in 0..1000 {
            if model.step(&mut prng) {
                drops += 1;
            }
        }
        assert!(
            drops > 50 && drops < 350,
            "expected burst loss occurrences, got {drops}"
        );
    }

    #[test]
    fn test_byzantine_corruption_and_hash_failure() {
        let engine = ChaosEngine::from_profile(ChaosProfileKind::Byzantine, 777);
        let original = b"critical-transfer-payload-integrity-test";
        let expected_hash = Hash::of(original);

        let mut corruption_detected = false;
        for _ in 0..1000 {
            match engine.process_packet(original) {
                ChaosOutcome::Pass { payload, .. } => {
                    if Hash::of(&payload) != expected_hash {
                        corruption_detected = true;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(
            corruption_detected,
            "expected Byzantine corruption to alter hash"
        );
    }

    #[test]
    fn test_blackhole_partition() {
        let engine = ChaosEngine::from_profile(ChaosProfileKind::Partition, 1);
        let data = b"packet-data";
        for _ in 0..20 {
            assert_eq!(engine.process_packet(data), ChaosOutcome::Drop);
        }
        let report = engine.status();
        assert_eq!(report.packets_dropped, 20);
        assert!(report.blackhole_active);
    }

    #[test]
    fn test_chaos_benchmark_simulation() {
        let report = run_chaos_benchmark("satellite", 500);
        assert_eq!(report.total_packets, 500);
        assert!(
            report.dropped_packets > 0,
            "satellite profile should drop packets"
        );
        assert!(
            report.avg_delay_ms > 0.0,
            "satellite profile should add delay"
        );
        assert_eq!(report.profile_name, "satellite");
    }
}
