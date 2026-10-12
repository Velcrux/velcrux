//! Empirical performance profiler, live diagnostic telemetry, and bottleneck analyzer.
//!
//! Complies with `docs/REQUIREMENTS.md` §72 ("Performance Profiling"), §38 ("Observability"),
//! §36 ("Machine-Readable Output"), and §46 ("Benchmark Suite").
//!
//! Provides granular per-component elapsed time profiling across:
//! - Chunking (FastCDC rolling hashing vs fixed boundaries)
//! - Cryptographic hashing (BLAKE3 chunk & tree calculation)
//! - Zero-knowledge chunk encryption (AEAD encryption/decryption)
//! - Disk I/O (buffered vs direct I/O read/write)
//! - QUIC transport (stream transmission, pacing, flight latency)
//! - Frame serialization and protocol state processing
//! - Deduplication and chunk inventory lookups
//!
//! Automatically diagnoses pipeline bottlenecks and produces actionable tuning recommendations.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// High-level transfer pipeline components instrumented for empirical performance profiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    /// Rolling boundary chunking (FastCDC / fixed chunking).
    Chunking,
    /// Cryptographic hashing (BLAKE3 single-chunk or SIMD tree hashing).
    Hashing,
    /// AEAD encryption or decryption of chunk payloads.
    Encryption,
    /// Reading data from source storage / filesystem.
    DiskIoRead,
    /// Writing or staging data to destination filesystem / chunk store.
    DiskIoWrite,
    /// Network transmission, QUIC stream pacing, and flight latency.
    NetworkQuic,
    /// Protobuf / frame serialization and state machine handling.
    Serialization,
    /// Chunk store inventory querying and deduplication lookup.
    Deduplication,
}

impl ComponentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Chunking => "chunking",
            Self::Hashing => "hashing",
            Self::Encryption => "encryption",
            Self::DiskIoRead => "disk_io_read",
            Self::DiskIoWrite => "disk_io_write",
            Self::NetworkQuic => "network_quic",
            Self::Serialization => "serialization",
            Self::Deduplication => "deduplication",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Chunking => "Chunking (FastCDC/Fixed)",
            Self::Hashing => "Cryptographic Hashing (BLAKE3)",
            Self::Encryption => "Zero-Knowledge Encryption",
            Self::DiskIoRead => "Storage Read I/O",
            Self::DiskIoWrite => "Storage Write / Commit I/O",
            Self::NetworkQuic => "QUIC Network Transport",
            Self::Serialization => "Frame Serialization / Protocol",
            Self::Deduplication => "Deduplication & Inventory Diff",
        }
    }
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Aggregated timing statistics for an individual pipeline component.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ComponentTiming {
    /// Total number of recorded execution segments.
    pub invocations: u64,
    /// Cumulative duration spent inside this component in nanoseconds.
    pub total_nanos: u64,
    /// Cumulative bytes processed by this component during tracked intervals.
    pub bytes_processed: u64,
    /// Shortest recorded invocation duration in nanoseconds.
    pub min_nanos: u64,
    /// Longest recorded invocation duration in nanoseconds.
    pub max_nanos: u64,
}

impl ComponentTiming {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, duration_nanos: u64, bytes: u64) {
        self.invocations = self.invocations.saturating_add(1);
        self.total_nanos = self.total_nanos.saturating_add(duration_nanos);
        self.bytes_processed = self.bytes_processed.saturating_add(bytes);

        if self.invocations == 1 || duration_nanos < self.min_nanos {
            self.min_nanos = duration_nanos;
        }
        if duration_nanos > self.max_nanos {
            self.max_nanos = duration_nanos;
        }
    }

    pub fn total_ms(&self) -> f64 {
        self.total_nanos as f64 / 1_000_000.0
    }

    pub fn avg_ms(&self) -> f64 {
        if self.invocations == 0 {
            0.0
        } else {
            (self.total_nanos as f64 / self.invocations as f64) / 1_000_000.0
        }
    }

    pub fn throughput_mbps(&self) -> f64 {
        if self.total_nanos == 0 || self.bytes_processed == 0 {
            0.0
        } else {
            let seconds = self.total_nanos as f64 / 1_000_000_000.0;
            let mbits = (self.bytes_processed as f64 * 8.0) / 1_000_000.0;
            mbits / seconds
        }
    }
}

/// Process and buffer memory utilization metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryStats {
    /// Peak resident set size (RSS) in bytes observed during profiling.
    pub peak_rss_bytes: u64,
    /// Peak allocated bytes in the zero-copy buffer pool.
    pub buffer_pool_peak_bytes: u64,
}

/// Live transport network telemetry captured during profiled transfer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetworkMetrics {
    /// Smoothed round-trip time in microseconds.
    pub rtt_us: u64,
    /// Observed packet loss rate as a fractional value between 0.0 and 1.0.
    pub packet_loss_rate: f64,
    /// Cumulative retransmission events.
    pub retransmits: u64,
    /// Congestion window in bytes at the time of report generation.
    pub cwnd_bytes: u64,
    /// Total wire bytes transferred including headers and retransmissions.
    pub wire_bytes: u64,
}

/// Classification of the dominant transfer pipeline bottleneck.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BottleneckKind {
    /// Transfer speed is bounded by physical or congestion-controlled network bandwidth / latency.
    NetworkBound,
    /// Transfer speed is bounded by storage disk read throughput or seek latency.
    DiskIoReadBound,
    /// Transfer speed is bounded by destination disk write staging or fsync commit latency.
    DiskIoWriteBound,
    /// Transfer speed is bounded by CPU core capacity performing chunk scanning or BLAKE3 hashing.
    CpuHashingBound,
    /// Transfer speed is bounded by CPU capacity executing AEAD cryptography.
    CryptoBound,
    /// Pipeline stages are balanced; execution approaches theoretical device limits without severe stalls.
    BalancedOptimized,
}

impl BottleneckKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NetworkBound => "network_bound",
            Self::DiskIoReadBound => "disk_io_read_bound",
            Self::DiskIoWriteBound => "disk_io_write_bound",
            Self::CpuHashingBound => "cpu_hashing_bound",
            Self::CryptoBound => "crypto_bound",
            Self::BalancedOptimized => "balanced_optimized",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::NetworkBound => "Network Bound (WAN Bandwidth / Latency / Loss)",
            Self::DiskIoReadBound => "Storage Bound (Source Disk Read I/O)",
            Self::DiskIoWriteBound => "Storage Bound (Destination Disk Write / Commit I/O)",
            Self::CpuHashingBound => "CPU Bound (BLAKE3 Hashing / Chunking)",
            Self::CryptoBound => "CPU Bound (AEAD Cryptography)",
            Self::BalancedOptimized => "Balanced Pipeline (Optimal Utilization)",
        }
    }
}

impl fmt::Display for BottleneckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Automated bottleneck diagnosis and actionable tuning recommendations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BottleneckDiagnosis {
    /// Dominant bottleneck classification.
    pub kind: BottleneckKind,
    /// Diagnostic confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Percentage of total pipeline time consumed by the primary limiting stage.
    pub primary_component_pct: f64,
    /// Summary explanation of the bottleneck cause.
    pub summary: String,
    /// Actionable operator and configuration tuning suggestions.
    pub recommendations: Vec<String>,
}

/// Complete performance profiling report with component breakdowns and diagnosis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileReport {
    /// Total wall clock duration of the profiled transfer in milliseconds.
    pub total_wall_clock_ms: f64,
    /// Total logical bytes transferred.
    pub total_bytes: u64,
    /// Effective goodput in Megabits per second (Mbps).
    pub effective_goodput_mbps: f64,
    /// Per-component execution metrics.
    pub components: BTreeMap<ComponentKind, ComponentTiming>,
    /// Memory metrics sampled during profiling.
    pub memory: MemoryStats,
    /// Transport network telemetry if profiling a network transfer.
    pub network: Option<NetworkMetrics>,
    /// Automated empirical bottleneck diagnosis.
    pub diagnosis: BottleneckDiagnosis,
}

impl ProfileReport {
    /// Format a human-readable ASCII performance breakdown table and waterfall summary.
    pub fn format_ascii_table(&self) -> String {
        let mut out = String::new();
        out.push_str("========================================================================================\n");
        out.push_str("                        VELCRUX EMPIRICAL PERFORMANCE PROFILE REPORT                   \n");
        out.push_str("                             (docs/REQUIREMENTS.md §72, §38)                            \n");
        out.push_str("========================================================================================\n\n");

        out.push_str(&format!(
            "Total Transfer Size   : {:.2} MB ({} bytes)\n",
            self.total_bytes as f64 / (1024.0 * 1024.0),
            self.total_bytes
        ));
        out.push_str(&format!(
            "Total Wall Clock Time : {:.2} ms ({:.3} s)\n",
            self.total_wall_clock_ms,
            self.total_wall_clock_ms / 1000.0
        ));
        out.push_str(&format!(
            "Effective Goodput     : {:.2} Mbps ({:.2} MB/s)\n",
            self.effective_goodput_mbps,
            self.effective_goodput_mbps / 8.0
        ));
        out.push_str(&format!(
            "Peak Resident Memory  : {:.2} MB ({} bytes)\n",
            self.memory.peak_rss_bytes as f64 / (1024.0 * 1024.0),
            self.memory.peak_rss_bytes
        ));

        if let Some(ref net) = self.network {
            out.push_str(&format!(
                "Network RTT / Loss    : {:.2} ms / {:.2}% loss ({} retransmits, cwnd: {:.1} MB)\n",
                net.rtt_us as f64 / 1000.0,
                net.packet_loss_rate * 100.0,
                net.retransmits,
                net.cwnd_bytes as f64 / (1024.0 * 1024.0)
            ));
        }

        out.push_str("\n----------------------------------------------------------------------------------------\n");
        out.push_str(
            "Component                        Invocations  Time (ms)    Time (%)   Throughput (MB/s)\n",
        );
        out.push_str("----------------------------------------------------------------------------------------\n");

        let sum_component_ms: f64 = self.components.values().map(|c| c.total_ms()).sum();
        let base_ms = if sum_component_ms > 0.0 {
            sum_component_ms
        } else {
            self.total_wall_clock_ms.max(0.001)
        };

        for (kind, timing) in &self.components {
            let pct = (timing.total_ms() / base_ms) * 100.0;
            let mb_s = timing.throughput_mbps() / 8.0;
            out.push_str(&format!(
                "{:<32} {:>11} {:>10.2} {:>10.1}% {:>18.2}\n",
                kind.display_name(),
                timing.invocations,
                timing.total_ms(),
                pct,
                mb_s
            ));
        }

        out.push_str("----------------------------------------------------------------------------------------\n\n");
        out.push_str("BOTTLENECK DIAGNOSIS & ACTIONABLE TUNING RECOMMENDATIONS:\n");
        out.push_str(&format!(
            "  Primary Bottleneck: {}\n",
            self.diagnosis.kind.display_name()
        ));
        out.push_str(&format!(
            "  Confidence Score  : {:.1}% (Primary Component: {:.1}% of tracked pipeline)\n",
            self.diagnosis.confidence * 100.0,
            self.diagnosis.primary_component_pct
        ));
        out.push_str(&format!(
            "  Summary           : {}\n\n",
            self.diagnosis.summary
        ));
        out.push_str("  Recommended Actions:\n");
        for (idx, rec) in self.diagnosis.recommendations.iter().enumerate() {
            out.push_str(&format!("    {}. {}\n", idx + 1, rec));
        }
        out.push_str("========================================================================================\n");
        out
    }

    /// Convert report into a structured JSON value matching machine-readable API requirements (§36).
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Guard structure that records elapsed time upon drop.
pub struct TimingGuard {
    component: ComponentKind,
    bytes: u64,
    start: Instant,
    profiler: Arc<TransferProfilerInner>,
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        let elapsed_nanos = self.start.elapsed().as_nanos() as u64;
        self.profiler
            .record(self.component, elapsed_nanos, self.bytes);
    }
}

#[derive(Default)]
struct TransferProfilerInner {
    timings: Mutex<BTreeMap<ComponentKind, ComponentTiming>>,
    peak_rss: AtomicU64,
    buffer_pool_peak: AtomicU64,
}

impl TransferProfilerInner {
    fn record(&self, component: ComponentKind, duration_nanos: u64, bytes: u64) {
        if let Ok(mut lock) = self.timings.lock() {
            lock.entry(component)
                .or_default()
                .record(duration_nanos, bytes);
        }
    }
}

/// Active performance profiling session for an end-to-end or subsystem transfer.
pub struct TransferProfiler {
    inner: Arc<TransferProfilerInner>,
    start_time: Instant,
    total_bytes: AtomicU64,
    network_metrics: Mutex<Option<NetworkMetrics>>,
}

impl Default for TransferProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferProfiler {
    /// Initialize a new performance profiler.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TransferProfilerInner::default()),
            start_time: Instant::now(),
            total_bytes: AtomicU64::new(0),
            network_metrics: Mutex::new(None),
        }
    }

    /// Sample current process resident set size (RSS).
    pub fn sample_memory(&self) {
        let rss = sample_current_process_rss();
        let prev = self.inner.peak_rss.load(Ordering::Relaxed);
        if rss > prev {
            self.inner.peak_rss.store(rss, Ordering::Relaxed);
        }
    }

    /// Record peak allocated bytes in the buffer pool.
    pub fn record_buffer_pool_allocated(&self, bytes: u64) {
        let prev = self.inner.buffer_pool_peak.load(Ordering::Relaxed);
        if bytes > prev {
            self.inner.buffer_pool_peak.store(bytes, Ordering::Relaxed);
        }
    }

    /// Record a component execution interval directly.
    pub fn record_timing(&self, component: ComponentKind, duration: Duration, bytes: u64) {
        self.inner
            .record(component, duration.as_nanos() as u64, bytes);
    }

    /// Start a timing guard that records duration automatically on drop.
    pub fn start_timer(&self, component: ComponentKind, bytes_hint: u64) -> TimingGuard {
        TimingGuard {
            component,
            bytes: bytes_hint,
            start: Instant::now(),
            profiler: Arc::clone(&self.inner),
        }
    }

    /// Set total logical bytes transferred.
    pub fn set_bytes_transferred(&self, bytes: u64) {
        self.total_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Attach network transport telemetry metrics.
    pub fn set_network_metrics(&self, metrics: NetworkMetrics) {
        if let Ok(mut lock) = self.network_metrics.lock() {
            *lock = Some(metrics);
        }
    }

    /// Finalize profiling and synthesize the comprehensive performance report and diagnosis.
    pub fn finish(&self) -> ProfileReport {
        let elapsed = self.start_time.elapsed();
        let wall_clock_ms = elapsed.as_secs_f64() * 1000.0;
        let total_bytes = self.total_bytes.load(Ordering::Relaxed);

        let goodput_mbps = if elapsed.as_secs_f64() > 0.0 && total_bytes > 0 {
            (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0)
        } else {
            0.0
        };

        let timings = self
            .inner
            .timings
            .lock()
            .map(|t| t.clone())
            .unwrap_or_default();

        let memory = MemoryStats {
            peak_rss_bytes: self.inner.peak_rss.load(Ordering::Relaxed),
            buffer_pool_peak_bytes: self.inner.buffer_pool_peak.load(Ordering::Relaxed),
        };

        let network = self.network_metrics.lock().ok().and_then(|n| n.clone());

        let diagnosis = Self::diagnose_bottleneck(&timings, wall_clock_ms, network.as_ref());

        ProfileReport {
            total_wall_clock_ms: wall_clock_ms,
            total_bytes,
            effective_goodput_mbps: goodput_mbps,
            components: timings,
            memory,
            network,
            diagnosis,
        }
    }

    /// Empirically analyze timing distributions and network characteristics to isolate bottlenecks.
    pub fn diagnose_bottleneck(
        timings: &BTreeMap<ComponentKind, ComponentTiming>,
        wall_clock_ms: f64,
        network: Option<&NetworkMetrics>,
    ) -> BottleneckDiagnosis {
        let total_component_ms: f64 = timings.values().map(|t| t.total_ms()).sum();
        let reference_ms = if total_component_ms > 0.0 {
            total_component_ms
        } else {
            wall_clock_ms.max(0.001)
        };

        // Determine dominant component
        let mut max_component = None;
        let mut max_ms = 0.0;

        for (kind, timing) in timings {
            if timing.total_ms() > max_ms {
                max_ms = timing.total_ms();
                max_component = Some(*kind);
            }
        }

        let max_pct = (max_ms / reference_ms) * 100.0;

        // Check network characteristics if available
        let high_loss = network.map(|n| n.packet_loss_rate >= 0.01).unwrap_or(false);
        let high_rtt = network.map(|n| n.rtt_us >= 100_000).unwrap_or(false);

        if let Some(ComponentKind::DiskIoRead) = max_component {
            if max_pct >= 40.0 {
                return BottleneckDiagnosis {
                    kind: BottleneckKind::DiskIoReadBound,
                    confidence: (max_pct / 100.0).min(0.98),
                    primary_component_pct: max_pct,
                    summary: format!(
                        "Source storage read latency accounts for {:.1}% of total pipeline time.",
                        max_pct
                    ),
                    recommendations: vec![
                        "Enable kernel page-cache bypass and Direct I/O via `--direct-io always`."
                            .to_string(),
                        "Ensure source file resides on NVMe or stripe array storage with high sequential read capability.".to_string(),
                        "Increase read buffer size or concurrency using `--concurrency 8`.".to_string(),
                    ],
                };
            }
        }

        if let Some(ComponentKind::DiskIoWrite) = max_component {
            if max_pct >= 40.0 {
                return BottleneckDiagnosis {
                    kind: BottleneckKind::DiskIoWriteBound,
                    confidence: (max_pct / 100.0).min(0.98),
                    primary_component_pct: max_pct,
                    summary: format!(
                        "Destination storage write/fsync latency accounts for {:.1}% of pipeline execution.",
                        max_pct
                    ),
                    recommendations: vec![
                        "Increase checkpoint interval (--checkpoint-threshold-bytes) to amortize fsync latency.".to_string(),
                        "Utilize Direct I/O destination staging on NVMe or unbuffered fast storage.".to_string(),
                        "Confirm destination storage root and staging root reside on the same physical filesystem to enable O(1) atomic renames.".to_string(),
                    ],
                };
            }
        }

        if let Some(ComponentKind::Hashing) = max_component {
            if max_pct >= 40.0 {
                return BottleneckDiagnosis {
                    kind: BottleneckKind::CpuHashingBound,
                    confidence: (max_pct / 100.0).min(0.95),
                    primary_component_pct: max_pct,
                    summary: format!(
                        "BLAKE3 chunk hashing accounts for {:.1}% of execution time, indicating CPU-bound hashing.",
                        max_pct
                    ),
                    recommendations: vec![
                        "Verify host AVX-512 / AVX2 / ARM Neon hardware vector acceleration is active (`velcrux hardware`).".to_string(),
                        "Increase chunk size parameters (e.g. 4 MiB chunks) to reduce per-chunk boundary hash overhead.".to_string(),
                        "Enable multi-threaded parallel chunk hashing across available CPU cores.".to_string(),
                    ],
                };
            }
        }

        if let Some(ComponentKind::Encryption) = max_component {
            if max_pct >= 40.0 {
                return BottleneckDiagnosis {
                    kind: BottleneckKind::CryptoBound,
                    confidence: (max_pct / 100.0).min(0.95),
                    primary_component_pct: max_pct,
                    summary: format!(
                        "Zero-knowledge AEAD encryption/decryption accounts for {:.1}% of processing.",
                        max_pct
                    ),
                    recommendations: vec![
                        "Verify AES-NI hardware instruction acceleration is enabled on the CPU host architecture.".to_string(),
                        "Consider ChaCha20-Poly1305 algorithm on processors lacking hardware AES-NI instructions.".to_string(),
                        "Scale parallel crypto workers proportionally to the core count.".to_string(),
                    ],
                };
            }
        }

        if let Some(ComponentKind::NetworkQuic) = max_component {
            if max_pct >= 40.0 || high_loss || high_rtt {
                let mut recs = vec![
                    "Increase QUIC receive window buffer and BDP allocation (`--network-profile wan_fast`).".to_string(),
                    "Enable Path MTU Discovery (DPLPMTUD) or Jumbo Frames (9000 bytes) to reduce UDP packetization overhead.".to_string(),
                ];
                if high_loss {
                    recs.push(
                        "Elevated packet loss detected; increase stream concurrency to maximize recovery throughput.".to_string(),
                    );
                }
                return BottleneckDiagnosis {
                    kind: BottleneckKind::NetworkBound,
                    confidence: 0.90,
                    primary_component_pct: max_pct,
                    summary: format!(
                        "Network transport time ({:.1}% of pipeline) dominates due to WAN latency or bandwidth saturation.",
                        max_pct
                    ),
                    recommendations: recs,
                };
            }
        }

        // Default: balanced pipeline
        BottleneckDiagnosis {
            kind: BottleneckKind::BalancedOptimized,
            confidence: 0.85,
            primary_component_pct: max_pct,
            summary: "Pipeline components are well-balanced; no single stage creates excessive backpressure stalls.".to_string(),
            recommendations: vec![
                "Current settings are optimal for current hardware and network topology.".to_string(),
                "For further throughput gains, scale both network interface bandwidth and NVMe disk concurrency concurrently.".to_string(),
            ],
        }
    }
}

/// Safely sample process resident memory (RSS) without requiring unsafe code.
pub fn sample_current_process_rss() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let fields: Vec<&str> = statm.split_whitespace().collect();
            if fields.len() > 1 {
                let pages: u64 = fields[1].parse().unwrap_or(0);
                return pages.saturating_mul(4096);
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_timing_aggregation() {
        let mut timing = ComponentTiming::new();
        assert_eq!(timing.invocations, 0);

        timing.record(1_000_000, 1024); // 1 ms, 1 KB
        timing.record(3_000_000, 2048); // 3 ms, 2 KB

        assert_eq!(timing.invocations, 2);
        assert_eq!(timing.total_nanos, 4_000_000);
        assert_eq!(timing.bytes_processed, 3072);
        assert_eq!(timing.min_nanos, 1_000_000);
        assert_eq!(timing.max_nanos, 3_000_000);
        assert!((timing.total_ms() - 4.0).abs() < 1e-6);
        assert!((timing.avg_ms() - 2.0).abs() < 1e-6);
        assert!(timing.throughput_mbps() > 0.0);
    }

    #[test]
    fn test_profiler_timing_guard() {
        let profiler = TransferProfiler::new();
        {
            let _guard = profiler.start_timer(ComponentKind::Hashing, 1024 * 1024);
            std::thread::sleep(Duration::from_millis(5));
        }
        profiler.set_bytes_transferred(1024 * 1024);
        let report = profiler.finish();

        assert!(report.components.contains_key(&ComponentKind::Hashing));
        let hashing = &report.components[&ComponentKind::Hashing];
        assert_eq!(hashing.invocations, 1);
        assert_eq!(hashing.bytes_processed, 1024 * 1024);
        assert!(hashing.total_ms() >= 4.0);
    }

    #[test]
    fn test_bottleneck_diagnosis_classification() {
        let mut timings = BTreeMap::new();

        // 1. Disk read bound
        let mut read_timing = ComponentTiming::new();
        read_timing.record(80_000_000, 10 * 1024 * 1024); // 80ms
        timings.insert(ComponentKind::DiskIoRead, read_timing);

        let mut hash_timing = ComponentTiming::new();
        hash_timing.record(10_000_000, 10 * 1024 * 1024); // 10ms
        timings.insert(ComponentKind::Hashing, hash_timing);

        let diag = TransferProfiler::diagnose_bottleneck(&timings, 100.0, None);
        assert_eq!(diag.kind, BottleneckKind::DiskIoReadBound);
        assert!(!diag.recommendations.is_empty());
        assert!(diag.recommendations[0].contains("Direct I/O"));

        // 2. CPU hashing bound
        timings.clear();
        let mut hash_heavy = ComponentTiming::new();
        hash_heavy.record(90_000_000, 10 * 1024 * 1024);
        timings.insert(ComponentKind::Hashing, hash_heavy);
        let mut write_light = ComponentTiming::new();
        write_light.record(5_000_000, 10 * 1024 * 1024);
        timings.insert(ComponentKind::DiskIoWrite, write_light);

        let diag_cpu = TransferProfiler::diagnose_bottleneck(&timings, 100.0, None);
        assert_eq!(diag_cpu.kind, BottleneckKind::CpuHashingBound);
        assert!(diag_cpu.recommendations[0].contains("vector acceleration"));

        // 3. Network bound with loss
        timings.clear();
        let mut net_timing = ComponentTiming::new();
        net_timing.record(70_000_000, 10 * 1024 * 1024);
        timings.insert(ComponentKind::NetworkQuic, net_timing);
        let net_metrics = NetworkMetrics {
            rtt_us: 150_000,
            packet_loss_rate: 0.02,
            retransmits: 15,
            cwnd_bytes: 4 * 1024 * 1024,
            wire_bytes: 12 * 1024 * 1024,
        };
        let diag_net = TransferProfiler::diagnose_bottleneck(&timings, 100.0, Some(&net_metrics));
        assert_eq!(diag_net.kind, BottleneckKind::NetworkBound);
    }

    #[test]
    fn test_report_formatting_and_json() {
        let profiler = TransferProfiler::new();
        profiler.record_timing(
            ComponentKind::DiskIoRead,
            Duration::from_millis(10),
            1048576,
        );
        profiler.record_timing(ComponentKind::Hashing, Duration::from_millis(5), 1048576);
        profiler.record_timing(
            ComponentKind::NetworkQuic,
            Duration::from_millis(20),
            1048576,
        );
        profiler.set_bytes_transferred(1048576);
        profiler.set_network_metrics(NetworkMetrics {
            rtt_us: 20000,
            packet_loss_rate: 0.001,
            retransmits: 1,
            cwnd_bytes: 8 * 1024 * 1024,
            wire_bytes: 1050000,
        });

        let report = profiler.finish();
        let table = report.format_ascii_table();
        assert!(table.contains("VELCRUX EMPIRICAL PERFORMANCE PROFILE REPORT"));
        assert!(table.contains("Storage Read I/O"));
        assert!(table.contains("Cryptographic Hashing (BLAKE3)"));
        assert!(table.contains("QUIC Network Transport"));

        let json = report.to_json_value();
        assert_eq!(json["total_bytes"], 1048576);
        assert!(json["components"]["disk_io_read"].is_object());
        assert!(json["diagnosis"]["kind"].is_string());
    }
}
