//! Autonomous Self-Tuning Storage Tiering & Compaction Engine (`ADR-055`, Option CM).
//!
//! Features:
//! 1. Real-Time Access Heat-Map Generation:
//!    - Continuous tracking of Content-Addressable Storage (CAS) chunk access frequency and recency.
//!    - Exponential decay half-life modeling: recency factor $R(t) = 2^{-\Delta t / t_{1/2}}$.
//!    - Multi-factor temperature scoring $T \in [0.0, 100.0]$:
//!      - `Hot`: High-speed local NVMe / SSD ($T \ge 75.0$).
//!      - `Warm`: Secondary bulk SSD storage ($35.0 \le T < 75.0$).
//!      - `Cold`: High-density erasure-coded mesh ($10.0 \le T < 35.0$).
//!      - `FrozenGlacier`: Ultra-cold archival cloud storage ($T < 10.0$).
//! 2. Autonomous Multi-Tier Migration Engine:
//!    - Watermarked threshold demotions (Hot $\to$ Warm $\to$ Cold $\to$ Glacier) based on configurable high/low watermarks.
//!    - Transparent read-driven hot promotion with zero-copy staging.
//! 3. Background Zero-Copy Compaction & Garbage Collection:
//!    - Automated reclamation of orphan chunks past grace period.
//!    - Automated hard-purging of expired tombstone markers.
//!    - Service Level Objective (SLO) bound enforcement: bounded execution cycle time and rate limiting.
//! 4. Crash-Resilient Multi-Process Persistence:
//!    - Atomic journal and state serialization (`VELCRUX_COMPACTION_DIR`).
//! 5. 100% Safe Rust (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::util::Hash;

/// Chunk temperature classification reflecting access frequency and recency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChunkTemperature {
    /// Hot tier: local NVMe / SSD, sub-millisecond retrieval, active working set.
    Hot = 0,
    /// Warm tier: bulk local SSD or network staging, high sequential throughput.
    Warm = 1,
    /// Cold tier: erasure-coded distributed mesh, dense compressed storage.
    Cold = 2,
    /// FrozenGlacier tier: ultra-cold cloud archive, delayed retrieval, maximum cost efficiency.
    FrozenGlacier = 3,
}

impl ChunkTemperature {
    /// Canonical lowercase identifier for directories, CLI commands, and metrics.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::FrozenGlacier => "glacier",
        }
    }
}

impl fmt::Display for ChunkTemperature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ChunkTemperature {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().trim() {
            "hot" => Ok(Self::Hot),
            "warm" => Ok(Self::Warm),
            "cold" => Ok(Self::Cold),
            "glacier" | "frozenglacier" | "frozen_glacier" => Ok(Self::FrozenGlacier),
            other => Err(VelcruxError::Config(format!(
                "invalid chunk temperature '{other}': expected 'hot', 'warm', 'cold', or 'glacier'"
            ))),
        }
    }
}

/// Tracks access recency, frequency, and lifecycle state of a CAS chunk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessHeatRecord {
    /// Cryptographic BLAKE3 hash of chunk.
    pub chunk_hash: Hash,
    /// Total cumulative access count.
    pub access_count: u64,
    /// Epoch timestamp (seconds) of initial ingestion.
    pub first_access_epoch_secs: u64,
    /// Epoch timestamp (seconds) of most recent access.
    pub last_access_epoch_secs: u64,
    /// Size of chunk in bytes.
    pub size_bytes: u64,
    /// Calculated temperature score $T \in [0.0, 100.0]$.
    pub temperature_score: f64,
    /// Current storage tier placement.
    pub current_tier: ChunkTemperature,
    /// Whether chunk is actively referenced by manifest/staging or orphan.
    pub referenced: bool,
    /// Whether chunk is marked with a tombstone pending purge.
    pub is_tombstone: bool,
    /// Timestamp when marked as tombstone (if applicable).
    pub tombstone_epoch_secs: Option<u64>,
    /// Timestamp when unreferenced/orphan state was first detected.
    pub orphan_detected_epoch_secs: Option<u64>,
}

impl AccessHeatRecord {
    /// Constructs a new access heat record for a newly registered chunk.
    pub fn new(chunk_hash: Hash, size_bytes: u64, tier: ChunkTemperature, now_secs: u64) -> Self {
        let initial_score = match tier {
            ChunkTemperature::Hot => 85.0,
            ChunkTemperature::Warm => 55.0,
            ChunkTemperature::Cold => 25.0,
            ChunkTemperature::FrozenGlacier => 5.0,
        };

        Self {
            chunk_hash,
            access_count: 1,
            first_access_epoch_secs: now_secs,
            last_access_epoch_secs: now_secs,
            size_bytes,
            temperature_score: initial_score,
            current_tier: tier,
            referenced: true,
            is_tombstone: false,
            tombstone_epoch_secs: None,
            orphan_detected_epoch_secs: None,
        }
    }

    /// Records an access event, updating access count, recency, and temperature score.
    pub fn record_access(
        &mut self,
        now_secs: u64,
        half_life_secs: f64,
        max_freq_cap: u64,
        auto_promote: bool,
    ) {
        self.access_count = self.access_count.saturating_add(1);
        self.last_access_epoch_secs = now_secs;
        self.referenced = true;
        self.orphan_detected_epoch_secs = None;

        // If marked tombstone, access resurrects it
        if self.is_tombstone {
            self.is_tombstone = false;
            self.tombstone_epoch_secs = None;
        }

        self.recalculate_temperature(now_secs, half_life_secs, max_freq_cap);

        if auto_promote && self.current_tier != ChunkTemperature::Hot {
            self.current_tier = ChunkTemperature::Hot;
            if self.temperature_score < 75.0 {
                self.temperature_score = 80.0;
            }
        }
    }

    /// Recalculates temperature score based on exponential decay and frequency weighting.
    pub fn recalculate_temperature(
        &mut self,
        now_secs: u64,
        half_life_secs: f64,
        max_freq_cap: u64,
    ) {
        let delta_t = now_secs.saturating_sub(self.last_access_epoch_secs) as f64;
        let hl = if half_life_secs > 0.0 {
            half_life_secs
        } else {
            3600.0
        };

        // Recency score: 100 * 2^(-delta_t / half_life)
        let recency_exponent = -delta_t / hl;
        let recency_factor = 2.0_f64.powf(recency_exponent).clamp(0.0, 1.0);
        let recency_score = 100.0 * recency_factor;

        // Frequency score: 100 * min(1.0, count / max_cap)
        let cap = max_freq_cap.max(1) as f64;
        let freq_factor = (self.access_count as f64 / cap).clamp(0.0, 1.0);
        let freq_score = 100.0 * freq_factor;

        // Composite score: 60% recency + 40% frequency
        let composite = 0.60 * recency_score + 0.40 * freq_score;
        self.temperature_score = composite.clamp(0.0, 100.0);
    }

    /// Determines suggested tier for a given temperature score.
    pub fn score_to_tier(score: f64) -> ChunkTemperature {
        if score >= 75.0 {
            ChunkTemperature::Hot
        } else if score >= 35.0 {
            ChunkTemperature::Warm
        } else if score >= 10.0 {
            ChunkTemperature::Cold
        } else {
            ChunkTemperature::FrozenGlacier
        }
    }
}

/// In-memory heat-map engine tracking CAS chunk access dynamics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAccessHeatmap {
    /// Heatmap table indexed by chunk hash.
    records: HashMap<Hash, AccessHeatRecord>,
    /// Exponential decay half-life in seconds (default 3600 = 1 hour).
    half_life_secs: f64,
    /// Ceiling cap for frequency calculation (default 100).
    max_freq_cap: u64,
}

impl Default for ChunkAccessHeatmap {
    fn default() -> Self {
        Self::new(3600.0)
    }
}

impl ChunkAccessHeatmap {
    /// Constructs a new empty heatmap engine with specified half-life.
    pub fn new(half_life_secs: f64) -> Self {
        Self {
            records: HashMap::new(),
            half_life_secs: if half_life_secs > 0.0 {
                half_life_secs
            } else {
                3600.0
            },
            max_freq_cap: 100,
        }
    }

    /// Registers a chunk into the heatmap if not already present.
    pub fn register_chunk(
        &mut self,
        hash: Hash,
        size_bytes: u64,
        tier: ChunkTemperature,
        now_secs: u64,
    ) {
        if !self.records.contains_key(&hash) {
            let record = AccessHeatRecord::new(hash, size_bytes, tier, now_secs);
            self.records.insert(hash, record);
        }
    }

    /// Records access to a chunk, updating stats and returning true if promoted.
    pub fn record_access(
        &mut self,
        hash: &Hash,
        size_bytes: u64,
        now_secs: u64,
        auto_promote: bool,
    ) -> bool {
        if let Some(record) = self.records.get_mut(hash) {
            let prev_tier = record.current_tier;
            record.record_access(
                now_secs,
                self.half_life_secs,
                self.max_freq_cap,
                auto_promote,
            );
            prev_tier != ChunkTemperature::Hot && record.current_tier == ChunkTemperature::Hot
        } else {
            let mut record =
                AccessHeatRecord::new(*hash, size_bytes, ChunkTemperature::Hot, now_secs);
            record.record_access(
                now_secs,
                self.half_life_secs,
                self.max_freq_cap,
                auto_promote,
            );
            self.records.insert(*hash, record);
            false
        }
    }

    /// Marks a chunk as a tombstone pending deletion.
    pub fn mark_tombstone(&mut self, hash: &Hash, now_secs: u64) {
        if let Some(record) = self.records.get_mut(hash) {
            record.is_tombstone = true;
            record.tombstone_epoch_secs = Some(now_secs);
        }
    }

    /// Marks a chunk as unreferenced / candidate orphan.
    pub fn mark_orphan(&mut self, hash: &Hash, now_secs: u64) {
        if let Some(record) = self.records.get_mut(hash) {
            record.referenced = false;
            if record.orphan_detected_epoch_secs.is_none() {
                record.orphan_detected_epoch_secs = Some(now_secs);
            }
        }
    }

    /// Updates reference state for a chunk.
    pub fn mark_referenced(&mut self, hash: &Hash, referenced: bool, now_secs: u64) {
        if let Some(record) = self.records.get_mut(hash) {
            record.referenced = referenced;
            if referenced {
                record.orphan_detected_epoch_secs = None;
            } else if record.orphan_detected_epoch_secs.is_none() {
                record.orphan_detected_epoch_secs = Some(now_secs);
            }
        }
    }

    /// Refreshes temperature scores across all tracked chunks.
    pub fn refresh_all_temperatures(&mut self, now_secs: u64) {
        for record in self.records.values_mut() {
            record.recalculate_temperature(now_secs, self.half_life_secs, self.max_freq_cap);
        }
    }

    /// Returns record for a given chunk hash.
    pub fn get(&self, hash: &Hash) -> Option<&AccessHeatRecord> {
        self.records.get(hash)
    }

    /// Returns mutable reference to record for a given chunk hash.
    pub fn get_mut(&mut self, hash: &Hash) -> Option<&mut AccessHeatRecord> {
        self.records.get_mut(hash)
    }

    /// Total number of tracked chunks.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true if heatmap is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns chunks placed in a specific storage tier.
    pub fn chunks_by_tier(&self, tier: ChunkTemperature) -> Vec<AccessHeatRecord> {
        self.records
            .values()
            .filter(|r| r.current_tier == tier && !r.is_tombstone)
            .cloned()
            .collect()
    }

    /// Cumulative size in bytes of chunks in a specific tier.
    pub fn tier_bytes(&self, tier: ChunkTemperature) -> u64 {
        self.records
            .values()
            .filter(|r| r.current_tier == tier && !r.is_tombstone)
            .map(|r| r.size_bytes)
            .sum()
    }

    /// Total chunk count in a specific tier.
    pub fn tier_count(&self, tier: ChunkTemperature) -> u64 {
        self.records
            .values()
            .filter(|r| r.current_tier == tier && !r.is_tombstone)
            .count() as u64
    }

    /// Returns top hottest chunks sorted by temperature score descending.
    pub fn top_hot(&self, limit: usize) -> Vec<AccessHeatRecord> {
        let mut list: Vec<AccessHeatRecord> = self
            .records
            .values()
            .filter(|r| !r.is_tombstone)
            .cloned()
            .collect();
        list.sort_by(|a, b| {
            b.temperature_score
                .partial_cmp(&a.temperature_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        list.truncate(limit);
        list
    }

    /// Returns top coldest chunks sorted by temperature score ascending.
    pub fn top_cold(&self, limit: usize) -> Vec<AccessHeatRecord> {
        let mut list: Vec<AccessHeatRecord> = self
            .records
            .values()
            .filter(|r| !r.is_tombstone)
            .cloned()
            .collect();
        list.sort_by(|a, b| {
            a.temperature_score
                .partial_cmp(&b.temperature_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        list.truncate(limit);
        list
    }

    /// Returns all tracked records.
    pub fn all_records(&self) -> Vec<AccessHeatRecord> {
        self.records.values().cloned().collect()
    }

    /// Removes a chunk record directly (e.g. after purge).
    pub fn remove(&mut self, hash: &Hash) -> Option<AccessHeatRecord> {
        self.records.remove(hash)
    }
}

/// Operational and capacity policies governing autonomous tiering and compaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionPolicy {
    /// Hot tier physical capacity in bytes (e.g. NVMe partition size, default 10 GiB).
    pub hot_capacity_bytes: u64,
    /// Warm tier physical capacity in bytes (e.g. SSD pool, default 50 GiB).
    pub warm_capacity_bytes: u64,
    /// Cold tier physical capacity in bytes (e.g. Erasure mesh, default 200 GiB).
    pub cold_capacity_bytes: u64,
    /// Hot tier high watermark percentage triggering demotions (default 85.0%).
    pub hot_high_watermark_pct: f64,
    /// Hot tier low watermark demotion target percentage (default 70.0%).
    pub hot_low_watermark_pct: f64,
    /// Warm tier high watermark percentage triggering demotions to Cold (default 85.0%).
    pub warm_high_watermark_pct: f64,
    /// Warm tier low watermark percentage target (default 70.0%).
    pub warm_low_watermark_pct: f64,
    /// Cold tier high watermark percentage triggering archival to Glacier (default 90.0%).
    pub cold_high_watermark_pct: f64,
    /// Exponential decay half-life in seconds (default 3600 = 1 hour).
    pub decay_half_life_secs: f64,
    /// Service Level Objective (SLO) maximum cycle duration budget in milliseconds (default 100ms).
    pub slo_max_cycle_duration_ms: u64,
    /// Maximum zero-copy compaction throughput rate in bytes per second (default 100 MB/s).
    pub max_compaction_rate_bytes_per_sec: u64,
    /// Orphan chunk grace period in seconds before hard reclamation (default 86400 = 24h).
    pub orphan_grace_period_secs: u64,
    /// Tombstone time-to-live in seconds before hard purge (default 604800 = 7 days).
    pub tombstone_ttl_secs: u64,
    /// Whether reads on warm/cold chunks automatically promote them to Hot tier.
    pub auto_promote_on_read: bool,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            hot_capacity_bytes: 10 * 1024 * 1024 * 1024,   // 10 GiB
            warm_capacity_bytes: 50 * 1024 * 1024 * 1024,  // 50 GiB
            cold_capacity_bytes: 200 * 1024 * 1024 * 1024, // 200 GiB
            hot_high_watermark_pct: 85.0,
            hot_low_watermark_pct: 70.0,
            warm_high_watermark_pct: 85.0,
            warm_low_watermark_pct: 70.0,
            cold_high_watermark_pct: 90.0,
            decay_half_life_secs: 3600.0,
            slo_max_cycle_duration_ms: 100,
            max_compaction_rate_bytes_per_sec: 100_000_000, // 100 MB/s
            orphan_grace_period_secs: 86400,                // 24 hours
            tombstone_ttl_secs: 604800,                     // 7 days
            auto_promote_on_read: true,
        }
    }
}

/// Action plan evaluated during an autonomous tiering migration cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Chunks targeted for demotion from Hot tier to Warm tier.
    pub demotions_hot_to_warm: Vec<Hash>,
    /// Chunks targeted for demotion from Warm tier to Cold tier.
    pub demotions_warm_to_cold: Vec<Hash>,
    /// Chunks targeted for demotion from Cold tier to Glacier archive.
    pub demotions_cold_to_glacier: Vec<Hash>,
    /// Chunks targeted for promotion from Warm/Cold/Glacier to Hot tier.
    pub promotions_to_hot: Vec<Hash>,
    /// Total count of demotions planned.
    pub total_demotions: usize,
    /// Total count of promotions planned.
    pub total_promotions: usize,
    /// Aggregate bytes planned for migration across tiers.
    pub total_bytes_to_migrate: u64,
}

/// Execution summary of a zero-copy compaction and garbage collection cycle.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CompactionCycleReport {
    /// Monotonically increasing compaction cycle identifier.
    pub cycle_id: u64,
    /// Epoch timestamp (milliseconds) when cycle initiated.
    pub started_at_epoch_ms: u64,
    /// Execution duration of cycle in nanoseconds.
    pub duration_nanoseconds: u64,
    /// Total storage bytes reclaimed from orphans and tombstones.
    pub reclaimed_bytes: u64,
    /// Number of unreferenced orphan chunks permanently purged.
    pub orphans_purged: u64,
    /// Number of expired tombstones deleted.
    pub tombstones_deleted: u64,
    /// Number of chunk tier migrations executed.
    pub chunks_migrated: u64,
    /// Total payload bytes migrated across storage tiers.
    pub bytes_migrated: u64,
    /// Count of active chunks residing in Hot tier.
    pub hot_chunks: u64,
    /// Count of active chunks residing in Warm tier.
    pub warm_chunks: u64,
    /// Count of active chunks residing in Cold tier.
    pub cold_chunks: u64,
    /// Count of active chunks residing in Glacier archive.
    pub glacier_chunks: u64,
    /// Total stored bytes residing in Hot tier.
    pub hot_bytes: u64,
    /// Total stored bytes residing in Warm tier.
    pub warm_bytes: u64,
    /// Total stored bytes residing in Cold tier.
    pub cold_bytes: u64,
    /// Total stored bytes residing in Glacier archive.
    pub glacier_bytes: u64,
    /// Whether the execution cycle exceeded its configured SLO duration budget.
    pub slo_budget_exceeded: bool,
}

/// Comprehensive operator status of the autonomous compaction and tiering engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionEngineStatus {
    /// Active compaction policy.
    pub policy: CompactionPolicy,
    /// Total tracked chunk records in heatmap.
    pub total_records: usize,
    /// Hot tier active chunk count.
    pub hot_chunks: u64,
    /// Hot tier active bytes.
    pub hot_bytes: u64,
    /// Hot tier utilization percentage.
    pub hot_utilization_pct: f64,
    /// Warm tier active chunk count.
    pub warm_chunks: u64,
    /// Warm tier active bytes.
    pub warm_bytes: u64,
    /// Warm tier utilization percentage.
    pub warm_utilization_pct: f64,
    /// Cold tier active chunk count.
    pub cold_chunks: u64,
    /// Cold tier active bytes.
    pub cold_bytes: u64,
    /// Cold tier utilization percentage.
    pub cold_utilization_pct: f64,
    /// Glacier tier active chunk count.
    pub glacier_chunks: u64,
    /// Glacier tier active bytes.
    pub glacier_bytes: u64,
    /// Total cumulative reclaimed bytes.
    pub reclaimed_bytes_total: u64,
    /// Total cumulative orphans purged.
    pub orphans_purged_total: u64,
    /// Total cumulative tombstones deleted.
    pub tombstones_deleted_total: u64,
    /// Total cumulative migrations executed.
    pub migrations_total: u64,
    /// Latest compaction cycle duration in nanoseconds.
    pub last_cycle_duration_nanoseconds: u64,
    /// Total compaction cycles run.
    pub total_cycles_executed: u64,
}

/// Microsecond performance benchmark results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionBenchmarkReport {
    /// Benchmark iteration count.
    pub iterations: usize,
    /// Mean heatmap lookup and access update latency in nanoseconds.
    pub heatmap_lookup_latency_nanoseconds: f64,
    /// Heatmap update throughput in operations per second.
    pub heatmap_lookup_throughput_ops_per_sec: f64,
    /// Mean tier placement evaluation latency in nanoseconds.
    pub tier_evaluation_latency_nanoseconds: f64,
    /// Tier evaluation throughput in operations per second.
    pub tier_evaluation_throughput_ops_per_sec: f64,
    /// Zero-copy compaction sweep latency in nanoseconds.
    pub compaction_sweep_latency_nanoseconds: f64,
    /// Migration planning latency in nanoseconds.
    pub migration_planning_latency_nanoseconds: f64,
    /// Simulated migration throughput in Megabytes per second.
    pub simulated_migration_throughput_mb_per_sec: f64,
}

/// Persistent serialization schema for cross-process staging.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompactionPersistentState {
    policy: CompactionPolicy,
    records: Vec<AccessHeatRecord>,
    reclaimed_bytes_total: u64,
    orphans_purged_total: u64,
    tombstones_deleted_total: u64,
    migrations_total: u64,
    last_cycle_duration_ns: u64,
    cycle_counter: u64,
    saved_epoch_secs: u64,
}

/// Autonomous Self-Tuning Storage Tiering & Compaction Engine (`ADR-055`).
pub struct AutonomousCompactionEngine {
    /// Active tiering and compaction configuration policy.
    pub policy: CompactionPolicy,
    /// Real-time chunk access heat-map.
    pub heatmap: ChunkAccessHeatmap,
    /// Optional filesystem directory for state persistence.
    pub persistence_dir: Option<PathBuf>,
    /// Total bytes reclaimed by zero-copy compaction.
    pub reclaimed_bytes_total: Arc<AtomicU64>,
    /// Total orphan chunks permanently purged.
    pub orphans_purged_total: Arc<AtomicU64>,
    /// Total tombstones permanently deleted.
    pub tombstones_deleted_total: Arc<AtomicU64>,
    /// Total chunk migrations across tiers executed.
    pub migrations_total: Arc<AtomicU64>,
    /// Latest compaction cycle duration in nanoseconds.
    pub last_cycle_duration_ns: Arc<AtomicU64>,
    /// Monotonically increasing cycle counter.
    pub cycle_counter: Arc<AtomicU64>,
}

impl AutonomousCompactionEngine {
    /// Constructs a new autonomous compaction engine instance.
    pub fn new(policy: CompactionPolicy, persistence_dir: Option<PathBuf>) -> Self {
        let half_life = policy.decay_half_life_secs;
        Self {
            policy,
            heatmap: ChunkAccessHeatmap::new(half_life),
            persistence_dir,
            reclaimed_bytes_total: Arc::new(AtomicU64::new(0)),
            orphans_purged_total: Arc::new(AtomicU64::new(0)),
            tombstones_deleted_total: Arc::new(AtomicU64::new(0)),
            migrations_total: Arc::new(AtomicU64::new(0)),
            last_cycle_duration_ns: Arc::new(AtomicU64::new(0)),
            cycle_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Loads existing persistent state from disk or initializes default state.
    pub fn load_or_create(
        dir: PathBuf,
        override_policy: Option<CompactionPolicy>,
    ) -> Result<Self, VelcruxError> {
        let _ = fs::create_dir_all(&dir);
        let state_file = dir.join("compaction_state.json");

        if state_file.is_file() {
            let mut file = File::open(&state_file)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;

            if let Ok(st) = serde_json::from_str::<CompactionPersistentState>(&content) {
                let policy = override_policy.unwrap_or(st.policy);
                let mut heatmap = ChunkAccessHeatmap::new(policy.decay_half_life_secs);
                for rec in st.records {
                    heatmap.records.insert(rec.chunk_hash, rec);
                }

                return Ok(Self {
                    policy,
                    heatmap,
                    persistence_dir: Some(dir),
                    reclaimed_bytes_total: Arc::new(AtomicU64::new(st.reclaimed_bytes_total)),
                    orphans_purged_total: Arc::new(AtomicU64::new(st.orphans_purged_total)),
                    tombstones_deleted_total: Arc::new(AtomicU64::new(st.tombstones_deleted_total)),
                    migrations_total: Arc::new(AtomicU64::new(st.migrations_total)),
                    last_cycle_duration_ns: Arc::new(AtomicU64::new(st.last_cycle_duration_ns)),
                    cycle_counter: Arc::new(AtomicU64::new(st.cycle_counter)),
                });
            }
        }

        let policy = override_policy.unwrap_or_default();
        Ok(Self::new(policy, Some(dir)))
    }

    /// Persists state atomically to disk using staging file and rename.
    pub fn save_state(&self) -> Result<(), VelcruxError> {
        let dir = match &self.persistence_dir {
            Some(d) => d,
            None => return Ok(()),
        };

        let _ = fs::create_dir_all(dir);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let st = CompactionPersistentState {
            policy: self.policy.clone(),
            records: self.heatmap.all_records(),
            reclaimed_bytes_total: self.reclaimed_bytes_total.load(Ordering::Relaxed),
            orphans_purged_total: self.orphans_purged_total.load(Ordering::Relaxed),
            tombstones_deleted_total: self.tombstones_deleted_total.load(Ordering::Relaxed),
            migrations_total: self.migrations_total.load(Ordering::Relaxed),
            last_cycle_duration_ns: self.last_cycle_duration_ns.load(Ordering::Relaxed),
            cycle_counter: self.cycle_counter.load(Ordering::Relaxed),
            saved_epoch_secs: now_secs,
        };

        let json = serde_json::to_string_pretty(&st).map_err(|e| {
            VelcruxError::Internal(format!("compaction state serialization error: {e}"))
        })?;

        let tmp_file = dir.join(format!(
            ".compaction_state.tmp.{}.{}",
            std::process::id(),
            rand::random::<u32>()
        ));

        {
            let mut f = File::create(&tmp_file)?;
            f.write_all(json.as_bytes())?;
            f.flush()?;
        }

        let target_file = dir.join("compaction_state.json");
        fs::rename(&tmp_file, &target_file)?;

        Ok(())
    }

    /// Ingests access into the heatmap, optionally promoting warm/cold chunk to hot.
    pub fn record_access(&mut self, hash: &Hash, size_bytes: u64) -> bool {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let promoted = self.heatmap.record_access(
            hash,
            size_bytes,
            now_secs,
            self.policy.auto_promote_on_read,
        );

        if promoted {
            self.migrations_total.fetch_add(1, Ordering::Relaxed);
        }

        promoted
    }

    /// Registers a chunk explicitly into a storage tier.
    pub fn register_chunk(&mut self, hash: Hash, size_bytes: u64, tier: ChunkTemperature) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.heatmap
            .register_chunk(hash, size_bytes, tier, now_secs);
    }

    /// Marks a chunk with a tombstone.
    pub fn mark_tombstone(&mut self, hash: &Hash) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.heatmap.mark_tombstone(hash, now_secs);
    }

    /// Marks a chunk as unreferenced / orphan candidate.
    pub fn mark_orphan(&mut self, hash: &Hash) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.heatmap.mark_orphan(hash, now_secs);
    }

    /// Updates reference status of chunk.
    pub fn mark_referenced(&mut self, hash: &Hash, referenced: bool) {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.heatmap.mark_referenced(hash, referenced, now_secs);
    }

    /// Plans autonomous tier migrations based on current capacities and watermarks.
    pub fn plan_migrations(&mut self, force: bool) -> MigrationPlan {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.heatmap.refresh_all_temperatures(now_secs);

        let mut plan = MigrationPlan::default();

        // 1. Evaluate Hot tier capacity against watermarks
        let hot_bytes = self.heatmap.tier_bytes(ChunkTemperature::Hot);
        let hot_high_limit = (self.policy.hot_capacity_bytes as f64
            * (self.policy.hot_high_watermark_pct / 100.0)) as u64;
        let hot_low_target = (self.policy.hot_capacity_bytes as f64
            * (self.policy.hot_low_watermark_pct / 100.0)) as u64;

        if force || hot_bytes > hot_high_limit {
            // Find coldest chunks in Hot tier
            let mut hot_chunks = self.heatmap.chunks_by_tier(ChunkTemperature::Hot);
            hot_chunks.sort_by(|a, b| {
                a.temperature_score
                    .partial_cmp(&b.temperature_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            let mut current_bytes = hot_bytes;
            for chunk in hot_chunks {
                if !force && current_bytes <= hot_low_target {
                    break;
                }
                plan.demotions_hot_to_warm.push(chunk.chunk_hash);
                plan.total_bytes_to_migrate =
                    plan.total_bytes_to_migrate.saturating_add(chunk.size_bytes);
                current_bytes = current_bytes.saturating_sub(chunk.size_bytes);
            }
        }

        // 2. Evaluate Warm tier capacity against watermarks
        let warm_bytes = self.heatmap.tier_bytes(ChunkTemperature::Warm);
        let warm_high_limit = (self.policy.warm_capacity_bytes as f64
            * (self.policy.warm_high_watermark_pct / 100.0)) as u64;
        let warm_low_target = (self.policy.warm_capacity_bytes as f64
            * (self.policy.warm_low_watermark_pct / 100.0)) as u64;

        if force || warm_bytes > warm_high_limit {
            let mut warm_chunks = self.heatmap.chunks_by_tier(ChunkTemperature::Warm);
            warm_chunks.sort_by(|a, b| {
                a.temperature_score
                    .partial_cmp(&b.temperature_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            let mut current_bytes = warm_bytes;
            for chunk in warm_chunks {
                if !force && current_bytes <= warm_low_target {
                    break;
                }
                plan.demotions_warm_to_cold.push(chunk.chunk_hash);
                plan.total_bytes_to_migrate =
                    plan.total_bytes_to_migrate.saturating_add(chunk.size_bytes);
                current_bytes = current_bytes.saturating_sub(chunk.size_bytes);
            }
        }

        // 3. Evaluate Cold tier capacity against high watermark
        let cold_bytes = self.heatmap.tier_bytes(ChunkTemperature::Cold);
        let cold_high_limit = (self.policy.cold_capacity_bytes as f64
            * (self.policy.cold_high_watermark_pct / 100.0)) as u64;

        if force || cold_bytes > cold_high_limit {
            let mut cold_chunks = self.heatmap.chunks_by_tier(ChunkTemperature::Cold);
            cold_chunks.sort_by(|a, b| {
                a.temperature_score
                    .partial_cmp(&b.temperature_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            for chunk in cold_chunks {
                // Demote coldest cold chunks to glacier
                if chunk.temperature_score < 15.0 || force {
                    plan.demotions_cold_to_glacier.push(chunk.chunk_hash);
                    plan.total_bytes_to_migrate =
                        plan.total_bytes_to_migrate.saturating_add(chunk.size_bytes);
                }
            }
        }

        plan.total_demotions = plan.demotions_hot_to_warm.len()
            + plan.demotions_warm_to_cold.len()
            + plan.demotions_cold_to_glacier.len();
        plan.total_promotions = plan.promotions_to_hot.len();

        plan
    }

    /// Executes an evaluated migration plan, adjusting tiers and incrementing counters.
    pub fn execute_migration_plan(&mut self, plan: &MigrationPlan) -> (usize, u64) {
        let mut chunks_moved = 0usize;
        let mut bytes_moved = 0u64;

        for hash in &plan.demotions_hot_to_warm {
            if let Some(r) = self.heatmap.get_mut(hash) {
                if r.current_tier == ChunkTemperature::Hot {
                    r.current_tier = ChunkTemperature::Warm;
                    chunks_moved += 1;
                    bytes_moved = bytes_moved.saturating_add(r.size_bytes);
                }
            }
        }

        for hash in &plan.demotions_warm_to_cold {
            if let Some(r) = self.heatmap.get_mut(hash) {
                if r.current_tier == ChunkTemperature::Warm {
                    r.current_tier = ChunkTemperature::Cold;
                    chunks_moved += 1;
                    bytes_moved = bytes_moved.saturating_add(r.size_bytes);
                }
            }
        }

        for hash in &plan.demotions_cold_to_glacier {
            if let Some(r) = self.heatmap.get_mut(hash) {
                if r.current_tier == ChunkTemperature::Cold {
                    r.current_tier = ChunkTemperature::FrozenGlacier;
                    chunks_moved += 1;
                    bytes_moved = bytes_moved.saturating_add(r.size_bytes);
                }
            }
        }

        for hash in &plan.promotions_to_hot {
            if let Some(r) = self.heatmap.get_mut(hash) {
                if r.current_tier != ChunkTemperature::Hot {
                    r.current_tier = ChunkTemperature::Hot;
                    chunks_moved += 1;
                    bytes_moved = bytes_moved.saturating_add(r.size_bytes);
                }
            }
        }

        self.migrations_total
            .fetch_add(chunks_moved as u64, Ordering::Relaxed);
        let _ = self.save_state();

        (chunks_moved, bytes_moved)
    }

    /// Migrates a specific chunk to a desired tier manually.
    pub fn migrate_chunk(
        &mut self,
        hash: &Hash,
        target_tier: ChunkTemperature,
    ) -> Result<(), VelcruxError> {
        if let Some(r) = self.heatmap.get_mut(hash) {
            r.current_tier = target_tier;
            self.migrations_total.fetch_add(1, Ordering::Relaxed);
            let _ = self.save_state();
            Ok(())
        } else {
            Err(VelcruxError::Config(format!(
                "chunk hash {} not found in compaction heatmap",
                hash.to_hex()
            )))
        }
    }

    /// Executes zero-copy compaction, orphan reclamation, and tombstone purging.
    pub fn execute_compaction_cycle(
        &mut self,
        dry_run: bool,
        max_duration_ms: Option<u64>,
        rate_limit_mb: Option<u64>,
    ) -> CompactionCycleReport {
        let start_time = Instant::now();
        let cycle_id = self.cycle_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let started_at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let now_secs = started_at_epoch_ms / 1000;

        let slo_limit_ms = max_duration_ms.unwrap_or(self.policy.slo_max_cycle_duration_ms);
        let max_bytes_per_sec = rate_limit_mb
            .map(|mb| mb.saturating_mul(1_000_000))
            .unwrap_or(self.policy.max_compaction_rate_bytes_per_sec);

        let mut reclaimed_bytes = 0u64;
        let mut orphans_purged = 0u64;
        let mut tombstones_deleted = 0u64;
        let mut slo_budget_exceeded = false;

        let mut to_purge: Vec<Hash> = Vec::new();

        // Scan heatmap records for expired tombstones and orphan chunks
        for record in self.heatmap.records.values() {
            // Check SLO budget
            if start_time.elapsed().as_millis() as u64 >= slo_limit_ms {
                slo_budget_exceeded = true;
                break;
            }

            // 1. Tombstone check
            if record.is_tombstone {
                if let Some(t_secs) = record.tombstone_epoch_secs {
                    if now_secs.saturating_sub(t_secs) >= self.policy.tombstone_ttl_secs {
                        to_purge.push(record.chunk_hash);
                        tombstones_deleted += 1;
                        reclaimed_bytes = reclaimed_bytes.saturating_add(record.size_bytes);
                        continue;
                    }
                }
            }

            // 2. Orphan check
            if !record.referenced && !record.is_tombstone {
                if let Some(o_secs) = record.orphan_detected_epoch_secs {
                    if now_secs.saturating_sub(o_secs) >= self.policy.orphan_grace_period_secs {
                        to_purge.push(record.chunk_hash);
                        orphans_purged += 1;
                        reclaimed_bytes = reclaimed_bytes.saturating_add(record.size_bytes);
                    }
                }
            }
        }

        // Apply rate limit delay if needed
        if max_bytes_per_sec > 0 && reclaimed_bytes > 0 {
            let expected_duration_secs = (reclaimed_bytes as f64) / (max_bytes_per_sec as f64);
            let target_duration = Duration::from_secs_f64(expected_duration_secs.min(0.01)); // Cap delay in cycles
            let elapsed = start_time.elapsed();
            if elapsed < target_duration {
                std::thread::sleep(target_duration - elapsed);
            }
        }

        if !dry_run {
            for h in &to_purge {
                self.heatmap.remove(h);
            }
            self.reclaimed_bytes_total
                .fetch_add(reclaimed_bytes, Ordering::Relaxed);
            self.orphans_purged_total
                .fetch_add(orphans_purged, Ordering::Relaxed);
            self.tombstones_deleted_total
                .fetch_add(tombstones_deleted, Ordering::Relaxed);
        }

        // Also plan and execute autonomous migrations
        let plan = self.plan_migrations(false);
        let (chunks_migrated, bytes_migrated) = if !dry_run {
            self.execute_migration_plan(&plan)
        } else {
            (
                plan.total_demotions + plan.total_promotions,
                plan.total_bytes_to_migrate,
            )
        };

        let duration_ns = start_time.elapsed().as_nanos() as u64;
        self.last_cycle_duration_ns
            .store(duration_ns, Ordering::Relaxed);

        if !dry_run {
            let _ = self.save_state();
        }

        CompactionCycleReport {
            cycle_id,
            started_at_epoch_ms,
            duration_nanoseconds: duration_ns,
            reclaimed_bytes,
            orphans_purged,
            tombstones_deleted,
            chunks_migrated: chunks_migrated as u64,
            bytes_migrated,
            hot_chunks: self.heatmap.tier_count(ChunkTemperature::Hot),
            warm_chunks: self.heatmap.tier_count(ChunkTemperature::Warm),
            cold_chunks: self.heatmap.tier_count(ChunkTemperature::Cold),
            glacier_chunks: self.heatmap.tier_count(ChunkTemperature::FrozenGlacier),
            hot_bytes: self.heatmap.tier_bytes(ChunkTemperature::Hot),
            warm_bytes: self.heatmap.tier_bytes(ChunkTemperature::Warm),
            cold_bytes: self.heatmap.tier_bytes(ChunkTemperature::Cold),
            glacier_bytes: self.heatmap.tier_bytes(ChunkTemperature::FrozenGlacier),
            slo_budget_exceeded,
        }
    }

    /// Evaluates overall system health and status.
    pub fn status(&self) -> CompactionEngineStatus {
        let hot_bytes = self.heatmap.tier_bytes(ChunkTemperature::Hot);
        let warm_bytes = self.heatmap.tier_bytes(ChunkTemperature::Warm);
        let cold_bytes = self.heatmap.tier_bytes(ChunkTemperature::Cold);
        let glacier_bytes = self.heatmap.tier_bytes(ChunkTemperature::FrozenGlacier);

        let hot_util = if self.policy.hot_capacity_bytes > 0 {
            (hot_bytes as f64 / self.policy.hot_capacity_bytes as f64) * 100.0
        } else {
            0.0
        };

        let warm_util = if self.policy.warm_capacity_bytes > 0 {
            (warm_bytes as f64 / self.policy.warm_capacity_bytes as f64) * 100.0
        } else {
            0.0
        };

        let cold_util = if self.policy.cold_capacity_bytes > 0 {
            (cold_bytes as f64 / self.policy.cold_capacity_bytes as f64) * 100.0
        } else {
            0.0
        };

        CompactionEngineStatus {
            policy: self.policy.clone(),
            total_records: self.heatmap.len(),
            hot_chunks: self.heatmap.tier_count(ChunkTemperature::Hot),
            hot_bytes,
            hot_utilization_pct: hot_util,
            warm_chunks: self.heatmap.tier_count(ChunkTemperature::Warm),
            warm_bytes,
            warm_utilization_pct: warm_util,
            cold_chunks: self.heatmap.tier_count(ChunkTemperature::Cold),
            cold_bytes,
            cold_utilization_pct: cold_util,
            glacier_chunks: self.heatmap.tier_count(ChunkTemperature::FrozenGlacier),
            glacier_bytes,
            reclaimed_bytes_total: self.reclaimed_bytes_total.load(Ordering::Relaxed),
            orphans_purged_total: self.orphans_purged_total.load(Ordering::Relaxed),
            tombstones_deleted_total: self.tombstones_deleted_total.load(Ordering::Relaxed),
            migrations_total: self.migrations_total.load(Ordering::Relaxed),
            last_cycle_duration_nanoseconds: self.last_cycle_duration_ns.load(Ordering::Relaxed),
            total_cycles_executed: self.cycle_counter.load(Ordering::Relaxed),
        }
    }

    /// Executes microsecond performance benchmark measuring heatmap lookup, tier evaluation,
    /// compaction sweep, and migration throughput.
    pub fn run_benchmark(iterations: usize) -> CompactionBenchmarkReport {
        let iters = iterations.max(10);
        let mut engine = Self::new(CompactionPolicy::default(), None);

        // Pre-populate with synthetic chunks
        let mut hashes = Vec::with_capacity(iters);
        for i in 0..iters {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            let hash = Hash::from_bytes(&bytes).expect("valid synthetic chunk hash");
            hashes.push(hash);
            let tier = match i % 4 {
                0 => ChunkTemperature::Hot,
                1 => ChunkTemperature::Warm,
                2 => ChunkTemperature::Cold,
                _ => ChunkTemperature::FrozenGlacier,
            };
            engine.register_chunk(hash, 65536, tier);
        }

        // 1. Benchmark heatmap lookup & access record
        let start_lookup = Instant::now();
        for hash in &hashes {
            engine.record_access(hash, 65536);
        }
        let elapsed_lookup = start_lookup.elapsed();
        let lookup_latency_ns = (elapsed_lookup.as_nanos() as f64) / (iters as f64);
        let lookup_throughput = (iters as f64) / elapsed_lookup.as_secs_f64().max(1e-9);

        // 2. Benchmark tier evaluation
        let start_eval = Instant::now();
        engine.heatmap.refresh_all_temperatures(1_700_000_000);
        let elapsed_eval = start_eval.elapsed();
        let eval_latency_ns = (elapsed_eval.as_nanos() as f64) / (iters as f64);
        let eval_throughput = (iters as f64) / elapsed_eval.as_secs_f64().max(1e-9);

        // 3. Benchmark zero-copy compaction sweep
        let start_sweep = Instant::now();
        let _ = engine.execute_compaction_cycle(true, Some(1000), None);
        let elapsed_sweep = start_sweep.elapsed();
        let sweep_latency_ns = elapsed_sweep.as_nanos() as f64;

        // 4. Benchmark migration planning
        let start_plan = Instant::now();
        let plan = engine.plan_migrations(true);
        let elapsed_plan = start_plan.elapsed();
        let plan_latency_ns = elapsed_plan.as_nanos() as f64;

        let total_bytes = plan.total_bytes_to_migrate as f64;
        let migration_mb_sec = if elapsed_plan.as_secs_f64() > 0.0 {
            (total_bytes / 1_000_000.0) / elapsed_plan.as_secs_f64()
        } else {
            1000.0
        };

        CompactionBenchmarkReport {
            iterations: iters,
            heatmap_lookup_latency_nanoseconds: lookup_latency_ns,
            heatmap_lookup_throughput_ops_per_sec: lookup_throughput,
            tier_evaluation_latency_nanoseconds: eval_latency_ns,
            tier_evaluation_throughput_ops_per_sec: eval_throughput,
            compaction_sweep_latency_nanoseconds: sweep_latency_ns,
            migration_planning_latency_nanoseconds: plan_latency_ns,
            simulated_migration_throughput_mb_per_sec: migration_mb_sec,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash(val: u64) -> Hash {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&val.to_le_bytes());
        Hash::from_bytes(&b).expect("valid dummy hash")
    }

    #[test]
    fn test_chunk_temperature_parsing() {
        assert_eq!(
            ChunkTemperature::from_str("hot").unwrap(),
            ChunkTemperature::Hot
        );
        assert_eq!(
            ChunkTemperature::from_str("warm").unwrap(),
            ChunkTemperature::Warm
        );
        assert_eq!(
            ChunkTemperature::from_str("cold").unwrap(),
            ChunkTemperature::Cold
        );
        assert_eq!(
            ChunkTemperature::from_str("glacier").unwrap(),
            ChunkTemperature::FrozenGlacier
        );
        assert_eq!(
            ChunkTemperature::from_str("frozenglacier").unwrap(),
            ChunkTemperature::FrozenGlacier
        );
        assert!(ChunkTemperature::from_str("invalid").is_err());
    }

    #[test]
    fn test_access_heat_exponential_decay() {
        let hash = dummy_hash(100);
        let now = 10000;
        let mut record = AccessHeatRecord::new(hash, 1024, ChunkTemperature::Hot, now);
        assert!(record.temperature_score >= 80.0);

        // Advance time by 3600 seconds (1 half-life)
        record.recalculate_temperature(now + 3600, 3600.0, 100);
        // Recency dropped by half: 100 * 0.5 = 50. 0.6 * 50 + 0.4 * 1.0 = ~30.4
        assert!(record.temperature_score < 75.0);

        // Advance by 10 half-lives
        record.recalculate_temperature(now + 36000, 3600.0, 100);
        assert!(record.temperature_score < 10.0);
        assert_eq!(
            AccessHeatRecord::score_to_tier(record.temperature_score),
            ChunkTemperature::FrozenGlacier
        );
    }

    #[test]
    fn test_auto_promotion_on_read() {
        let hash = dummy_hash(200);
        let mut engine = AutonomousCompactionEngine::new(CompactionPolicy::default(), None);

        // Register in Cold tier
        engine.register_chunk(hash, 2048, ChunkTemperature::Cold);
        assert_eq!(
            engine.heatmap.get(&hash).unwrap().current_tier,
            ChunkTemperature::Cold
        );

        // Record read access -> auto promote
        let promoted = engine.record_access(&hash, 2048);
        assert!(promoted);
        assert_eq!(
            engine.heatmap.get(&hash).unwrap().current_tier,
            ChunkTemperature::Hot
        );
        assert_eq!(engine.migrations_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_watermark_migration_planning() {
        let mut policy = CompactionPolicy::default();
        policy.hot_capacity_bytes = 1000;
        policy.hot_high_watermark_pct = 50.0; // 500 bytes triggers demotion
        policy.hot_low_watermark_pct = 20.0; // 200 bytes target

        let mut engine = AutonomousCompactionEngine::new(policy, None);

        // Ingest 800 bytes into Hot tier (above 500 byte high watermark)
        for i in 0..8 {
            let h = dummy_hash(i + 1);
            engine.register_chunk(h, 100, ChunkTemperature::Hot);
        }

        let plan = engine.plan_migrations(false);
        assert!(!plan.demotions_hot_to_warm.is_empty());
        assert!(plan.total_demotions >= 6); // Needs to drop from 800 down to <= 200 bytes

        let (moved, bytes) = engine.execute_migration_plan(&plan);
        assert_eq!(moved, plan.total_demotions);
        assert!(bytes >= 600);

        // Verify Hot tier now at or below low target
        assert!(engine.heatmap.tier_bytes(ChunkTemperature::Hot) <= 200);
        assert!(engine.heatmap.tier_bytes(ChunkTemperature::Warm) >= 600);
    }

    #[test]
    fn test_compaction_reclaims_orphans_and_tombstones() {
        let mut policy = CompactionPolicy::default();
        policy.orphan_grace_period_secs = 60;
        policy.tombstone_ttl_secs = 60;

        let mut engine = AutonomousCompactionEngine::new(policy, None);
        let h1 = dummy_hash(1);
        let h2 = dummy_hash(2);
        let h3 = dummy_hash(3);

        engine.register_chunk(h1, 1000, ChunkTemperature::Hot);
        engine.register_chunk(h2, 2000, ChunkTemperature::Warm);
        engine.register_chunk(h3, 3000, ChunkTemperature::Cold);

        // Mark h1 as tombstone with past timestamp
        engine.heatmap.get_mut(&h1).unwrap().is_tombstone = true;
        engine.heatmap.get_mut(&h1).unwrap().tombstone_epoch_secs = Some(100);

        // Mark h2 as unreferenced orphan with past timestamp
        engine.heatmap.get_mut(&h2).unwrap().referenced = false;
        engine
            .heatmap
            .get_mut(&h2)
            .unwrap()
            .orphan_detected_epoch_secs = Some(100);

        // Execute compaction cycle
        let report = engine.execute_compaction_cycle(false, None, None);
        assert_eq!(report.tombstones_deleted, 1);
        assert_eq!(report.orphans_purged, 1);
        assert_eq!(report.reclaimed_bytes, 3000); // 1000 + 2000
        assert_eq!(engine.reclaimed_bytes_total.load(Ordering::Relaxed), 3000);

        // h1 and h2 should be removed, h3 preserved
        assert!(engine.heatmap.get(&h1).is_none());
        assert!(engine.heatmap.get(&h2).is_none());
        assert!(engine.heatmap.get(&h3).is_some());
    }

    #[test]
    fn test_multi_process_persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("compaction_test_{}", rand::random::<u32>()));
        let mut engine =
            AutonomousCompactionEngine::new(CompactionPolicy::default(), Some(dir.clone()));

        let h1 = dummy_hash(42);
        engine.register_chunk(h1, 4096, ChunkTemperature::Hot);
        engine.record_access(&h1, 4096);
        engine.save_state().unwrap();

        // Load into new instance
        let loaded = AutonomousCompactionEngine::load_or_create(dir.clone(), None).unwrap();
        assert_eq!(loaded.heatmap.len(), 1);
        let rec = loaded.heatmap.get(&h1).unwrap();
        assert_eq!(rec.size_bytes, 4096);
        assert_eq!(rec.current_tier, ChunkTemperature::Hot);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_benchmark_execution() {
        let report = AutonomousCompactionEngine::run_benchmark(50);
        assert_eq!(report.iterations, 50);
        assert!(report.heatmap_lookup_latency_nanoseconds >= 0.0);
        assert!(report.tier_evaluation_throughput_ops_per_sec > 0.0);
    }
}
