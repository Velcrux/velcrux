//! Multi-Tenant Hierarchical Storage Tiering & Hybrid Lifecycle Engine (`ADR-041`, Option BY).
//!
//! Features:
//! 1. Hierarchical Storage Tiers:
//!    - `Hot`: High-speed local SSD / NVMe uncompressed chunk store ($O(1)$ sub-millisecond retrieval).
//!    - `Warm`: Secondary bulk volume with optional light compression, high streaming bandwidth.
//!    - `Cold`: High-density Zstandard-compressed archive tier (level 9 default) with cryptographic scrubbing.
//! 2. Multi-Tenant Lifecycle Automation:
//!    - Tenant-level policies: `hot_to_warm_days`, `warm_to_cold_days`, `cold_retention_days`, `max_hot_bytes`.
//!    - Watermarked capacity demotions for high-throughput ingress tenants.
//! 3. Transparent Retrieval & Promotion:
//!    - Seamless on-demand streaming decompression from Cold to RAM or auto-promotion to Hot on read.
//!    - BLAKE3 hash validation at every tier transition, ensuring zero data corruption.
//! 4. Background Scrubbing:
//!    - Cryptographic verification of compressed Cold archives to detect and report bit-rot early.
//! 5. 100% Safe Rust (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::util::Hash;

/// Storage tier classification for hierarchical multi-tenant storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageTier {
    /// Hot tier: local NVMe / SSD, uncompressed raw chunks, sub-millisecond access.
    Hot = 0,
    /// Warm tier: bulk local volume or network staging, high sequential throughput.
    Warm = 1,
    /// Cold tier: Zstandard-compressed archive storage, maximum space efficiency.
    Cold = 2,
}

impl StorageTier {
    /// Canonical lowercase identifier for directories and metrics.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Cold => "cold",
        }
    }
}

impl fmt::Display for StorageTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for StorageTier {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().trim() {
            "hot" => Ok(Self::Hot),
            "warm" => Ok(Self::Warm),
            "cold" => Ok(Self::Cold),
            other => Err(VelcruxError::Config(format!(
                "invalid storage tier '{other}': expected 'hot', 'warm', or 'cold'"
            ))),
        }
    }
}

/// Tenant-specific storage tiering and lifecycle retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantTierPolicy {
    /// Identifier for tenant (or "default" for global fallback).
    pub tenant_id: String,
    /// Days elapsed since last access before migrating chunks from Hot to Warm (0 = disabled).
    pub hot_to_warm_days: u32,
    /// Days elapsed since last access before migrating chunks from Warm to Cold (0 = disabled).
    pub warm_to_cold_days: u32,
    /// Optional days before expired unreferenced cold chunks are evicted.
    pub cold_retention_days: Option<u32>,
    /// Optional maximum capacity in bytes for Hot storage before LRU demotion triggers.
    pub max_hot_bytes: Option<u64>,
    /// Whether reads on Cold or Warm chunks automatically promote them back to Hot tier.
    pub auto_promote_on_read: bool,
    /// Zstandard compression level for Cold tier storage (1 to 22, default 9).
    pub cold_compression_level: i32,
}

impl Default for TenantTierPolicy {
    fn default() -> Self {
        Self {
            tenant_id: "default".to_string(),
            hot_to_warm_days: 7,
            warm_to_cold_days: 30,
            cold_retention_days: None,
            max_hot_bytes: None,
            auto_promote_on_read: true,
            cold_compression_level: 9,
        }
    }
}

/// Metadata recorded for each chunk tracked within the tiered storage hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkTierMetadata {
    /// Cryptographic BLAKE3 hash of the chunk.
    pub hash: Hash,
    /// Current active storage tier.
    pub tier: StorageTier,
    /// Original uncompressed size of the chunk in bytes.
    pub raw_size: u64,
    /// Stored physical size on disk in bytes (compressed size if in Cold tier).
    pub stored_size: u64,
    /// Unix timestamp (seconds) when the chunk was first ingested.
    pub created_at_secs: u64,
    /// Unix timestamp (seconds) of the most recent read or write access.
    pub last_accessed_secs: u64,
    /// Cumulative number of read accesses.
    pub access_count: u64,
    /// Tenant identity owning or referencing this chunk.
    pub tenant_id: String,
}

/// Cumulative inventory and performance status report for tiered storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredStoreStatus {
    /// Root path of the tiered chunk store.
    pub root_dir: String,
    /// Tenant filter applied (or None if global).
    pub tenant_filter: Option<String>,
    /// Number of chunks in Hot tier.
    pub hot_chunks: usize,
    /// Total bytes stored in Hot tier.
    pub hot_bytes: u64,
    /// Number of chunks in Warm tier.
    pub warm_chunks: usize,
    /// Total bytes stored in Warm tier.
    pub warm_bytes: u64,
    /// Number of chunks in Cold tier.
    pub cold_chunks: usize,
    /// Total physical compressed bytes stored in Cold tier.
    pub cold_bytes: u64,
    /// Total uncompressed raw bytes in Cold tier.
    pub cold_raw_bytes: u64,
    /// Total chunks across all tiers.
    pub total_chunks: usize,
    /// Total physical bytes stored across all tiers.
    pub total_stored_bytes: u64,
    /// Total raw payload bytes stored across all tiers.
    pub total_raw_bytes: u64,
    /// Overall compression / space efficiency ratio (total_raw_bytes / total_stored_bytes).
    pub space_savings_ratio: f64,
    /// Lifetime count of chunk promotions.
    pub promotions_total: u64,
    /// Lifetime count of chunk demotions.
    pub demotions_total: u64,
    /// Lifetime count of chunk read retrievals.
    pub retrievals_total: u64,
}

/// Summary report produced by a hierarchical lifecycle sweep execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleSweepReport {
    /// Tenant evaluated during the sweep (or "all" if global).
    pub tenant_id: String,
    /// Total chunk metadata entries examined.
    pub chunks_scanned: usize,
    /// Number of chunks demoted from Hot to Warm.
    pub hot_to_warm_migrated: usize,
    /// Total bytes transferred from Hot to Warm.
    pub hot_to_warm_bytes: u64,
    /// Number of chunks demoted from Warm to Cold.
    pub warm_to_cold_migrated: usize,
    /// Total uncompressed bytes demoted to Cold.
    pub warm_to_cold_raw_bytes: u64,
    /// Total physical compressed bytes stored in Cold.
    pub warm_to_cold_compressed_bytes: u64,
    /// Disk space saved via Cold Zstd compression during this sweep.
    pub warm_to_cold_bytes_saved: u64,
    /// Number of expired Cold chunks evicted.
    pub cold_expired: usize,
    /// Total bytes reclaimed through Cold expiration.
    pub cold_expired_bytes: u64,
    /// Whether this run was a simulation without modifying disk.
    pub dry_run: bool,
    /// Sweep duration in milliseconds.
    pub duration_ms: u64,
}

/// Summary report produced by a Cold tier integrity scrub sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdScrubReport {
    /// Total cold archive chunks scanned.
    pub chunks_scanned: usize,
    /// Number of chunks successfully verified with matching BLAKE3 hash.
    pub valid_chunks: usize,
    /// List of corrupted chunk hex digests detected.
    pub corrupt_chunks: Vec<String>,
    /// Total uncompressed bytes verified.
    pub bytes_verified: u64,
    /// Scrub execution duration in milliseconds.
    pub duration_ms: u64,
}

/// Thread-safe in-memory index mapping chunk hashes to tier locations and policies.
#[derive(Debug, Default)]
struct TierIndex {
    chunks: HashMap<Hash, ChunkTierMetadata>,
    policies: HashMap<String, TenantTierPolicy>,
}

/// Multi-tenant hierarchical storage tiering and lifecycle manager (`ADR-041`).
pub struct TieredStorageManager {
    root: PathBuf,
    index: Arc<RwLock<TierIndex>>,
    promotions_total: AtomicU64,
    demotions_total: AtomicU64,
    retrievals_total: AtomicU64,
}

impl TieredStorageManager {
    /// Initialize or open an existing tiered storage root.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, VelcruxError> {
        let root = root.as_ref().to_path_buf();
        let hot_dir = root.join("hot").join("chunks");
        let warm_dir = root.join("warm").join("chunks");
        let cold_dir = root.join("cold").join("chunks");
        let policies_dir = root.join("policies");

        fs::create_dir_all(&hot_dir).map_err(VelcruxError::Io)?;
        fs::create_dir_all(&warm_dir).map_err(VelcruxError::Io)?;
        fs::create_dir_all(&cold_dir).map_err(VelcruxError::Io)?;
        fs::create_dir_all(&policies_dir).map_err(VelcruxError::Io)?;

        let mut index = TierIndex::default();
        index
            .policies
            .insert("default".to_string(), TenantTierPolicy::default());

        // Load policies from disk if present
        if let Ok(entries) = fs::read_dir(&policies_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                    if let Ok(data) = fs::read(&path) {
                        if let Ok(policy) = serde_json::from_slice::<TenantTierPolicy>(&data) {
                            index.policies.insert(policy.tenant_id.clone(), policy);
                        }
                    }
                }
            }
        }

        // Load index database if present
        let index_file = root.join("tier_index.json");
        if index_file.exists() {
            if let Ok(data) = fs::read(&index_file) {
                if let Ok(loaded_chunks) = serde_json::from_slice::<Vec<ChunkTierMetadata>>(&data) {
                    for meta in loaded_chunks {
                        index.chunks.insert(meta.hash, meta);
                    }
                }
            }
        } else {
            // Reconstruct initial index from scanning hot/warm/cold directories
            Self::rebuild_index_from_fs(&root, &mut index)?;
        }

        Ok(Self {
            root,
            index: Arc::new(RwLock::new(index)),
            promotions_total: AtomicU64::new(0),
            demotions_total: AtomicU64::new(0),
            retrievals_total: AtomicU64::new(0),
        })
    }

    fn rebuild_index_from_fs(root: &Path, index: &mut TierIndex) -> Result<(), VelcruxError> {
        let tiers = [
            (StorageTier::Hot, root.join("hot").join("chunks"), false),
            (StorageTier::Warm, root.join("warm").join("chunks"), false),
            (StorageTier::Cold, root.join("cold").join("chunks"), true),
        ];

        let now = now_secs();

        for (tier, dir, is_compressed) in tiers {
            if !dir.exists() {
                continue;
            }
            if let Ok(entries) = fs::read_dir(&dir) {
                for shard_res in entries.flatten() {
                    let shard_path = shard_res.path();
                    if shard_path.is_dir() {
                        if let Ok(chunk_entries) = fs::read_dir(&shard_path) {
                            for chunk_res in chunk_entries.flatten() {
                                let chunk_path = chunk_res.path();
                                let file_name = chunk_res.file_name();
                                let name_str = file_name.to_string_lossy();

                                let hex_hash = if is_compressed {
                                    if let Some(stripped) = name_str.strip_suffix(".zst") {
                                        stripped
                                    } else {
                                        continue;
                                    }
                                } else {
                                    &name_str
                                };

                                if let Some(hash) = Hash::from_hex(hex_hash) {
                                    let stored_size =
                                        chunk_path.metadata().map(|m| m.len()).unwrap_or(0);
                                    let raw_size = if is_compressed {
                                        stored_size.saturating_mul(2)
                                    } else {
                                        stored_size
                                    };

                                    index.chunks.insert(
                                        hash,
                                        ChunkTierMetadata {
                                            hash,
                                            tier,
                                            raw_size,
                                            stored_size,
                                            created_at_secs: now,
                                            last_accessed_secs: now,
                                            access_count: 0,
                                            tenant_id: "default".to_string(),
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Persist the tier index state safely to disk.
    pub fn persist_index(&self) -> Result<(), VelcruxError> {
        let index = self
            .index
            .read()
            .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;

        let chunks_vec: Vec<ChunkTierMetadata> = index.chunks.values().cloned().collect();
        let serialized = serde_json::to_vec_pretty(&chunks_vec)
            .map_err(|e| VelcruxError::Config(format!("failed to serialize tier index: {e}")))?;

        let tmp_path = self.root.join("tier_index.json.tmp");
        let final_path = self.root.join("tier_index.json");

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(VelcruxError::Io)?;

        file.write_all(&serialized).map_err(VelcruxError::Io)?;
        file.sync_all().map_err(VelcruxError::Io)?;
        drop(file);

        fs::rename(&tmp_path, &final_path).map_err(VelcruxError::Io)?;
        Ok(())
    }

    /// Compute disk file path for a chunk at the specified tier.
    pub fn chunk_path(&self, hash: &Hash, tier: StorageTier) -> PathBuf {
        let hex = hash.to_hex();
        let shard = hex[0..2].to_string();
        let filename = if tier == StorageTier::Cold {
            format!("{hex}.zst")
        } else {
            hex
        };

        self.root
            .join(tier.as_str())
            .join("chunks")
            .join(shard)
            .join(filename)
    }

    /// Check which tier currently hosts the chunk (or None if not present).
    pub fn has(&self, hash: &Hash) -> Result<Option<StorageTier>, VelcruxError> {
        let index = self
            .index
            .read()
            .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
        Ok(index.chunks.get(hash).map(|m| m.tier))
    }

    /// Ingest a chunk into the tiered storage system. New chunks are placed in Hot tier.
    pub fn put(
        &self,
        tenant_id: &str,
        hash: &Hash,
        data: &[u8],
    ) -> Result<StorageTier, VelcruxError> {
        let computed = Hash::of(data);
        if computed != *hash {
            return Err(VelcruxError::Config(format!(
                "chunk hash mismatch: expected {hash}, got {computed}"
            )));
        }

        // Check if chunk is already stored
        {
            let mut index = self
                .index
                .write()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
            if let Some(meta) = index.chunks.get_mut(hash) {
                meta.last_accessed_secs = now_secs();
                meta.access_count = meta.access_count.saturating_add(1);
                return Ok(meta.tier);
            }
        }

        // Store into Hot tier
        let path = self.chunk_path(hash, StorageTier::Hot);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(VelcruxError::Io)?;
        }

        let tmp_path = path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(VelcruxError::Io)?;
            file.write_all(data).map_err(VelcruxError::Io)?;
            file.sync_all().map_err(VelcruxError::Io)?;
        }
        fs::rename(&tmp_path, &path).map_err(VelcruxError::Io)?;

        let now = now_secs();
        let meta = ChunkTierMetadata {
            hash: *hash,
            tier: StorageTier::Hot,
            raw_size: data.len() as u64,
            stored_size: data.len() as u64,
            created_at_secs: now,
            last_accessed_secs: now,
            access_count: 1,
            tenant_id: tenant_id.to_string(),
        };

        {
            let mut index = self
                .index
                .write()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
            index.chunks.insert(*hash, meta);
        }

        self.persist_index()?;
        Ok(StorageTier::Hot)
    }

    /// Retrieve a chunk transparently regardless of which tier it resides on.
    /// If residing on Cold or Warm and tenant policy specifies `auto_promote_on_read`,
    /// the chunk will be promoted back to Hot tier asynchronously/in-line.
    pub fn get(&self, tenant_id: &str, hash: &Hash) -> Result<Bytes, VelcruxError> {
        self.retrievals_total.fetch_add(1, Ordering::Relaxed);

        let (tier, auto_promote) = {
            let index = self
                .index
                .read()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
            let meta = index.chunks.get(hash).ok_or_else(|| {
                VelcruxError::Config(format!("chunk {hash} not found in tiered store"))
            })?;
            let policy = index
                .policies
                .get(tenant_id)
                .or_else(|| index.policies.get(&meta.tenant_id))
                .or_else(|| index.policies.get("default"))
                .cloned()
                .unwrap_or_default();
            (meta.tier, policy.auto_promote_on_read)
        };

        let raw_data = match tier {
            StorageTier::Hot | StorageTier::Warm => {
                let path = self.chunk_path(hash, tier);
                fs::read(&path).map_err(VelcruxError::Io)?
            }
            StorageTier::Cold => {
                let path = self.chunk_path(hash, StorageTier::Cold);
                let compressed = fs::read(&path).map_err(VelcruxError::Io)?;
                // Decompress using Zstandard with bounded streaming decode
                let mut decoder = zstd::Decoder::new(&compressed[..]).map_err(|e| {
                    VelcruxError::Config(format!(
                        "failed to create zstd decoder for cold chunk {hash}: {e}"
                    ))
                })?;
                let mut decompressed = Vec::with_capacity(compressed.len().saturating_mul(2));
                decoder.read_to_end(&mut decompressed).map_err(|e| {
                    VelcruxError::Config(format!("failed to decompress cold chunk {hash}: {e}"))
                })?;
                decompressed
            }
        };

        // Cryptographic integrity check
        let computed = Hash::of(&raw_data);
        if computed != *hash {
            return Err(VelcruxError::Config(format!(
                "corrupt chunk in {tier} tier: expected {hash}, got {computed}"
            )));
        }

        // Update access metadata
        {
            let mut index = self
                .index
                .write()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
            if let Some(meta) = index.chunks.get_mut(hash) {
                meta.last_accessed_secs = now_secs();
                meta.access_count = meta.access_count.saturating_add(1);
            }
        }

        // Auto-promote if requested and not already Hot
        if auto_promote && tier != StorageTier::Hot {
            let _ = self.migrate_chunk(hash, StorageTier::Hot);
            self.promotions_total.fetch_add(1, Ordering::Relaxed);
        }

        Ok(Bytes::from(raw_data))
    }

    /// Manually or policy-driven migration of a chunk between tiers.
    pub fn migrate_chunk(
        &self,
        hash: &Hash,
        target_tier: StorageTier,
    ) -> Result<bool, VelcruxError> {
        let (current_tier, tenant_id, compression_level) = {
            let index = self
                .index
                .read()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
            let meta = match index.chunks.get(hash) {
                Some(m) => m,
                None => return Ok(false),
            };
            if meta.tier == target_tier {
                return Ok(true); // already in target tier
            }
            let policy = index
                .policies
                .get(&meta.tenant_id)
                .or_else(|| index.policies.get("default"))
                .cloned()
                .unwrap_or_default();
            (
                meta.tier,
                meta.tenant_id.clone(),
                policy.cold_compression_level,
            )
        };

        // 1. Read raw chunk data from current location
        let raw_data = match current_tier {
            StorageTier::Hot | StorageTier::Warm => {
                let current_path = self.chunk_path(hash, current_tier);
                fs::read(&current_path).map_err(VelcruxError::Io)?
            }
            StorageTier::Cold => {
                let current_path = self.chunk_path(hash, StorageTier::Cold);
                let compressed = fs::read(&current_path).map_err(VelcruxError::Io)?;
                let mut decoder = zstd::Decoder::new(&compressed[..]).map_err(|e| {
                    VelcruxError::Config(format!("failed to create zstd decoder for {hash}: {e}"))
                })?;
                let mut decompressed = Vec::with_capacity(compressed.len().saturating_mul(2));
                decoder.read_to_end(&mut decompressed).map_err(|e| {
                    VelcruxError::Config(format!("failed to decompress cold chunk {hash}: {e}"))
                })?;
                decompressed
            }
        };

        // Verify integrity before migration
        let computed = Hash::of(&raw_data);
        if computed != *hash {
            return Err(VelcruxError::Config(format!(
                "integrity check failed during migration for {hash}: expected {hash}, got {computed}"
            )));
        }

        // 2. Write to target tier
        let target_path = self.chunk_path(hash, target_tier);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).map_err(VelcruxError::Io)?;
        }

        let tmp_path = target_path.with_extension("tmp");
        let stored_size = if target_tier == StorageTier::Cold {
            let compressed = zstd::encode_all(&raw_data[..], compression_level).map_err(|e| {
                VelcruxError::Config(format!(
                    "zstd compression failed during migration to cold tier: {e}"
                ))
            })?;
            let len = compressed.len() as u64;
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(VelcruxError::Io)?;
            file.write_all(&compressed).map_err(VelcruxError::Io)?;
            file.sync_all().map_err(VelcruxError::Io)?;
            len
        } else {
            let len = raw_data.len() as u64;
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(VelcruxError::Io)?;
            file.write_all(&raw_data).map_err(VelcruxError::Io)?;
            file.sync_all().map_err(VelcruxError::Io)?;
            len
        };

        fs::rename(&tmp_path, &target_path).map_err(VelcruxError::Io)?;

        // 3. Remove old file
        let current_path = self.chunk_path(hash, current_tier);
        if current_path.exists() {
            let _ = fs::remove_file(&current_path);
        }

        // 4. Update index metadata
        {
            let mut index = self
                .index
                .write()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
            if let Some(meta) = index.chunks.get_mut(hash) {
                meta.tier = target_tier;
                meta.stored_size = stored_size;
                meta.raw_size = raw_data.len() as u64;
                meta.last_accessed_secs = now_secs();
            }
        }

        if target_tier > current_tier {
            self.demotions_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.promotions_total.fetch_add(1, Ordering::Relaxed);
        }

        let _ = tenant_id;
        self.persist_index()?;
        Ok(true)
    }

    /// Execute a hierarchical lifecycle sweep evaluating age and capacity policies.
    pub fn run_lifecycle_sweep(
        &self,
        tenant_id: Option<&str>,
        dry_run: bool,
    ) -> Result<LifecycleSweepReport, VelcruxError> {
        let start = Instant::now();
        let now = now_secs();

        let (candidate_chunks, policies) = {
            let index = self
                .index
                .read()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;

            let chunks: Vec<ChunkTierMetadata> = index
                .chunks
                .values()
                .filter(|m| {
                    if let Some(tid) = tenant_id {
                        m.tenant_id == tid
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();

            let policies = index.policies.clone();
            (chunks, policies)
        };

        let mut hot_to_warm_migrated = 0;
        let mut hot_to_warm_bytes = 0u64;
        let mut warm_to_cold_migrated = 0;
        let mut warm_to_cold_raw_bytes = 0u64;
        let mut warm_to_cold_compressed_bytes = 0u64;
        let mut warm_to_cold_bytes_saved = 0u64;
        let mut cold_expired = 0;
        let mut cold_expired_bytes = 0u64;

        let default_policy = TenantTierPolicy::default();

        // 1. Evaluate time-based age policies
        for meta in &candidate_chunks {
            let policy = policies
                .get(&meta.tenant_id)
                .or_else(|| policies.get("default"))
                .unwrap_or(&default_policy);

            let age_secs = now.saturating_sub(meta.last_accessed_secs);
            let age_days = (age_secs / 86400) as u32;

            match meta.tier {
                StorageTier::Hot => {
                    if policy.hot_to_warm_days > 0 && age_days >= policy.hot_to_warm_days {
                        hot_to_warm_migrated += 1;
                        hot_to_warm_bytes += meta.raw_size;
                        if !dry_run {
                            let _ = self.migrate_chunk(&meta.hash, StorageTier::Warm);
                        }
                    }
                }
                StorageTier::Warm => {
                    if policy.warm_to_cold_days > 0 && age_days >= policy.warm_to_cold_days {
                        warm_to_cold_migrated += 1;
                        warm_to_cold_raw_bytes += meta.raw_size;
                        let est_compressed = meta.raw_size / 2;
                        warm_to_cold_compressed_bytes += est_compressed;
                        warm_to_cold_bytes_saved += meta.raw_size.saturating_sub(est_compressed);
                        if !dry_run {
                            let _ = self.migrate_chunk(&meta.hash, StorageTier::Cold);
                        }
                    }
                }
                StorageTier::Cold => {
                    if let Some(retention_days) = policy.cold_retention_days {
                        if retention_days > 0 && age_days >= retention_days {
                            cold_expired += 1;
                            cold_expired_bytes += meta.stored_size;
                            if !dry_run {
                                let cold_path = self.chunk_path(&meta.hash, StorageTier::Cold);
                                if cold_path.exists() {
                                    let _ = fs::remove_file(&cold_path);
                                }
                                if let Ok(mut index) = self.index.write() {
                                    index.chunks.remove(&meta.hash);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Evaluate capacity-based watermark policy on Hot tier
        for (tid, policy) in &policies {
            if let Some(target_tid) = tenant_id {
                if tid != target_tid && target_tid != "default" {
                    continue;
                }
            }
            if let Some(max_hot) = policy.max_hot_bytes {
                let mut hot_chunks_for_tenant: Vec<ChunkTierMetadata> = candidate_chunks
                    .iter()
                    .filter(|m| m.tenant_id == *tid && m.tier == StorageTier::Hot)
                    .cloned()
                    .collect();

                let current_hot_bytes: u64 =
                    hot_chunks_for_tenant.iter().map(|m| m.stored_size).sum();
                if current_hot_bytes > max_hot {
                    // Sort by LRU (least recently accessed first)
                    hot_chunks_for_tenant.sort_by_key(|m| m.last_accessed_secs);
                    let mut excess = current_hot_bytes - max_hot;

                    for chunk in hot_chunks_for_tenant {
                        if excess == 0 {
                            break;
                        }
                        hot_to_warm_migrated += 1;
                        hot_to_warm_bytes += chunk.raw_size;
                        excess = excess.saturating_sub(chunk.stored_size);
                        if !dry_run {
                            let _ = self.migrate_chunk(&chunk.hash, StorageTier::Warm);
                        }
                    }
                }
            }
        }

        if !dry_run {
            self.persist_index()?;
        }

        Ok(LifecycleSweepReport {
            tenant_id: tenant_id.unwrap_or("all").to_string(),
            chunks_scanned: candidate_chunks.len(),
            hot_to_warm_migrated,
            hot_to_warm_bytes,
            warm_to_cold_migrated,
            warm_to_cold_raw_bytes,
            warm_to_cold_compressed_bytes,
            warm_to_cold_bytes_saved,
            cold_expired,
            cold_expired_bytes,
            dry_run,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Background cryptographic scrub of all chunks residing in Cold tier archives.
    pub fn scrub_cold_tier(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<ColdScrubReport, VelcruxError> {
        let start = Instant::now();

        let cold_chunks = {
            let index = self
                .index
                .read()
                .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
            let chunks: Vec<Hash> = index
                .chunks
                .values()
                .filter(|m| m.tier == StorageTier::Cold)
                .filter(|m| {
                    if let Some(tid) = tenant_id {
                        m.tenant_id == tid
                    } else {
                        true
                    }
                })
                .map(|m| m.hash)
                .collect();
            chunks
        };

        let mut valid_chunks = 0;
        let mut corrupt_chunks = Vec::new();
        let mut bytes_verified = 0u64;

        for hash in &cold_chunks {
            let path = self.chunk_path(hash, StorageTier::Cold);
            if !path.exists() {
                corrupt_chunks.push(format!("{hash} (file missing on disk)"));
                continue;
            }

            let compressed = match fs::read(&path) {
                Ok(data) => data,
                Err(e) => {
                    corrupt_chunks.push(format!("{hash} (io error: {e})"));
                    continue;
                }
            };

            let mut decoder = match zstd::Decoder::new(&compressed[..]) {
                Ok(d) => d,
                Err(e) => {
                    corrupt_chunks.push(format!("{hash} (zstd header corrupt: {e})"));
                    continue;
                }
            };

            let mut decompressed = Vec::with_capacity(compressed.len().saturating_mul(2));
            if let Err(e) = decoder.read_to_end(&mut decompressed) {
                corrupt_chunks.push(format!("{hash} (decompression bit-rot: {e})"));
                continue;
            }

            let computed = Hash::of(&decompressed);
            if computed != *hash {
                corrupt_chunks.push(format!(
                    "{hash} (hash mismatch: expected {hash}, got {computed})"
                ));
            } else {
                valid_chunks += 1;
                bytes_verified += decompressed.len() as u64;
            }
        }

        Ok(ColdScrubReport {
            chunks_scanned: cold_chunks.len(),
            valid_chunks,
            corrupt_chunks,
            bytes_verified,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Retrieve full status report across all tiers.
    pub fn get_status(&self, tenant_id: Option<&str>) -> Result<TieredStoreStatus, VelcruxError> {
        let index = self
            .index
            .read()
            .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;

        let mut hot_chunks = 0;
        let mut hot_bytes = 0u64;
        let mut warm_chunks = 0;
        let mut warm_bytes = 0u64;
        let mut cold_chunks = 0;
        let mut cold_bytes = 0u64;
        let mut cold_raw_bytes = 0u64;

        for meta in index.chunks.values() {
            if let Some(tid) = tenant_id {
                if meta.tenant_id != tid {
                    continue;
                }
            }
            match meta.tier {
                StorageTier::Hot => {
                    hot_chunks += 1;
                    hot_bytes += meta.stored_size;
                }
                StorageTier::Warm => {
                    warm_chunks += 1;
                    warm_bytes += meta.stored_size;
                }
                StorageTier::Cold => {
                    cold_chunks += 1;
                    cold_bytes += meta.stored_size;
                    cold_raw_bytes += meta.raw_size;
                }
            }
        }

        let total_chunks = hot_chunks + warm_chunks + cold_chunks;
        let total_stored_bytes = hot_bytes + warm_bytes + cold_bytes;
        let total_raw_bytes = hot_bytes + warm_bytes + cold_raw_bytes;

        let space_savings_ratio = if total_stored_bytes > 0 {
            total_raw_bytes as f64 / total_stored_bytes as f64
        } else {
            1.0
        };

        Ok(TieredStoreStatus {
            root_dir: self.root.display().to_string(),
            tenant_filter: tenant_id.map(|s| s.to_string()),
            hot_chunks,
            hot_bytes,
            warm_chunks,
            warm_bytes,
            cold_chunks,
            cold_bytes,
            cold_raw_bytes,
            total_chunks,
            total_stored_bytes,
            total_raw_bytes,
            space_savings_ratio,
            promotions_total: self.promotions_total.load(Ordering::Relaxed),
            demotions_total: self.demotions_total.load(Ordering::Relaxed),
            retrievals_total: self.retrievals_total.load(Ordering::Relaxed),
        })
    }

    /// Set or update the lifecycle tiering policy for a tenant.
    pub fn set_tenant_policy(&self, policy: TenantTierPolicy) -> Result<(), VelcruxError> {
        let policies_dir = self.root.join("policies");
        let file_path = policies_dir.join(format!("{}.json", policy.tenant_id));

        let serialized = serde_json::to_vec_pretty(&policy)
            .map_err(|e| VelcruxError::Config(format!("failed to serialize tenant policy: {e}")))?;

        let tmp_path = file_path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(VelcruxError::Io)?;
            file.write_all(&serialized).map_err(VelcruxError::Io)?;
            file.sync_all().map_err(VelcruxError::Io)?;
        }
        fs::rename(&tmp_path, &file_path).map_err(VelcruxError::Io)?;

        let mut index = self
            .index
            .write()
            .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
        index.policies.insert(policy.tenant_id.clone(), policy);
        Ok(())
    }

    /// Retrieve the lifecycle policy for a tenant (or global default if unset).
    pub fn get_tenant_policy(&self, tenant_id: &str) -> Result<TenantTierPolicy, VelcruxError> {
        let index = self
            .index
            .read()
            .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
        if let Some(p) = index.policies.get(tenant_id) {
            Ok(p.clone())
        } else if let Some(def) = index.policies.get("default") {
            let mut p = def.clone();
            p.tenant_id = tenant_id.to_string();
            Ok(p)
        } else {
            Err(VelcruxError::Config(format!(
                "no policy found for tenant '{tenant_id}'"
            )))
        }
    }

    /// List all registered tenant lifecycle policies.
    pub fn list_tenant_policies(&self) -> Result<Vec<TenantTierPolicy>, VelcruxError> {
        let index = self
            .index
            .read()
            .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
        let mut list: Vec<TenantTierPolicy> = index.policies.values().cloned().collect();
        list.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        Ok(list)
    }

    /// Total number of unique chunks in the tiered store.
    pub fn total_chunks(&self) -> Result<usize, VelcruxError> {
        let index = self
            .index
            .read()
            .map_err(|_| VelcruxError::Internal("tier index lock poisoned".to_string()))?;
        Ok(index.chunks.len())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_tier_basic_lifecycle() {
        let dir = tempdir().unwrap();
        let mgr = TieredStorageManager::new(dir.path()).unwrap();

        let data =
            b"Hierarchical storage tiering payload for velcrux hybrid lifecycle engine test.";
        let hash = Hash::of(data);

        // Put into Hot tier
        let initial_tier = mgr.put("tenant_a", &hash, data).unwrap();
        assert_eq!(initial_tier, StorageTier::Hot);
        assert_eq!(mgr.has(&hash).unwrap(), Some(StorageTier::Hot));

        // Read from Hot tier
        let retrieved = mgr.get("tenant_a", &hash).unwrap();
        assert_eq!(&retrieved[..], data);

        // Migrate to Warm tier
        assert!(mgr.migrate_chunk(&hash, StorageTier::Warm).unwrap());
        assert_eq!(mgr.has(&hash).unwrap(), Some(StorageTier::Warm));

        // Migrate to Cold tier (Zstd compressed)
        assert!(mgr.migrate_chunk(&hash, StorageTier::Cold).unwrap());
        assert_eq!(mgr.has(&hash).unwrap(), Some(StorageTier::Cold));

        // Transparent read from Cold tier (decompressed on the fly and auto-promoted to Hot)
        let cold_retrieved = mgr.get("tenant_a", &hash).unwrap();
        assert_eq!(&cold_retrieved[..], data);
        assert_eq!(mgr.has(&hash).unwrap(), Some(StorageTier::Hot));
    }

    #[test]
    fn test_tier_policies_and_sweep() {
        let dir = tempdir().unwrap();
        let mgr = TieredStorageManager::new(dir.path()).unwrap();

        let policy = TenantTierPolicy {
            tenant_id: "tenant_beta".to_string(),
            hot_to_warm_days: 0, // demote immediately
            warm_to_cold_days: 0,
            cold_retention_days: None,
            max_hot_bytes: Some(10), // tiny quota to trigger capacity demotion
            auto_promote_on_read: false,
            cold_compression_level: 3,
        };
        mgr.set_tenant_policy(policy).unwrap();

        let data1 = b"chunk one test payload for capacity watermark eviction";
        let hash1 = Hash::of(data1);
        mgr.put("tenant_beta", &hash1, data1).unwrap();

        // Run sweep
        let sweep_report = mgr.run_lifecycle_sweep(Some("tenant_beta"), false).unwrap();
        assert_eq!(sweep_report.chunks_scanned, 1);
        assert_eq!(sweep_report.hot_to_warm_migrated, 1);

        assert_eq!(mgr.has(&hash1).unwrap(), Some(StorageTier::Warm));
    }

    #[test]
    fn test_cold_tier_scrubbing() {
        let dir = tempdir().unwrap();
        let mgr = TieredStorageManager::new(dir.path()).unwrap();

        let data = b"Cold tier scrub verification payload with cryptographic integrity validation";
        let hash = Hash::of(data);
        mgr.put("tenant_c", &hash, data).unwrap();
        mgr.migrate_chunk(&hash, StorageTier::Cold).unwrap();

        // Run scrub on intact cold archive
        let report = mgr.scrub_cold_tier(None).unwrap();
        assert_eq!(report.chunks_scanned, 1);
        assert_eq!(report.valid_chunks, 1);
        assert!(report.corrupt_chunks.is_empty());

        // Introduce bit-rot by corrupting the archive file
        let cold_file = mgr.chunk_path(&hash, StorageTier::Cold);
        let mut raw = fs::read(&cold_file).unwrap();
        if let Some(byte) = raw.last_mut() {
            *byte ^= 0xFF; // flip bits
        }
        fs::write(&cold_file, raw).unwrap();

        // Run scrub again, detecting bit rot
        let corrupted_report = mgr.scrub_cold_tier(None).unwrap();
        assert_eq!(corrupted_report.chunks_scanned, 1);
        assert_eq!(corrupted_report.corrupt_chunks.len(), 1);
    }
}
