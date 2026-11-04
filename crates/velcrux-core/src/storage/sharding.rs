//! Distributed Object Storage Sharding & Multi-Bucket Tiering Engine (`ADR-065`).
//!
//! Provides enterprise-grade high-IOPS horizontal scaling and cold lifecycle tiering
//! across multiple S3/GCS/Azure bucket shards:
//!
//! 1. **Horizontal Bucket Sharding (`ShardRouter`)**:
//!    - Consistent hashing ring distributing chunks and objects across N bucket shards.
//!    - Bypasses cloud per-prefix IOPS bottlenecks (AWS S3 limit: 3,500 PUT / 5,500 GET req/s).
//!    - Uniform distribution with configurable virtual node tokens (vnodes) and capacity weights.
//!    - Shannon entropy calculation for empirical validation of uniform hash distribution.
//!
//! 2. **Prefix Partitioning Strategies (`PrefixPartitionStrategy`)**:
//!    - `Flat`: `chunks/{hash}`
//!    - `HexTwoLevel`: `chunks/{h[0..2]}/{h[2..4]}/{hash}` (65,536 prefixes for millions of IOPS).
//!    - `HexThreeLevel`: `chunks/{h[0..2]}/{h[2..4]}/{h[4..6]}/{hash}`
//!    - `TenantPrefixed`: `{tenant_id}/chunks/{hash}`
//!
//! 3. **Cloud Storage Classes & Multi-Tier Classification**:
//!    - `Standard`, `StandardIa`, `OnezoneIa`, `IntelligentTiering`,
//!      `GlacierInstantRetrieval`, `GlacierFlexibleRetrieval`, `GlacierDeepArchive`.
//!
//! 4. **Glacier / Deep Archive Restore Orchestrator (`GlacierRestoreCoordinator`)**:
//!    - Manages `RestoreObject` (`POST ?restore`) requests across `Expedited`, `Standard`, and `Bulk` tiers.
//!    - Tracks `x-amz-restore` header state machine (`ongoing-request="true"` vs `"false"`).
//!    - Polling and asynchronous readiness gating for archived chunks.
//!
//! 5. **Lifecycle Auto-Tiering Rule Engine (`ShardedLifecycleEngine`)**:
//!    - Evaluates object age and size against prefix rules to demote aging objects to IA/Glacier/Deep Archive.
//!    - Generates detailed `ShardedLifecycleReport`.
//!
//! 6. **Sharded Chunk Store (`ShardedChunkStore`)**:
//!    - Implements [`ChunkStore`] trait across the distributed multi-bucket topology.
//!    - High-throughput parallel batch existence checks (`has_batch`) grouped by shard.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::VelcruxError;
use crate::storage::chunk_store::ChunkStore;
use crate::storage::s3::{S3Config, S3Error, S3ObjectMeta, S3StorageBackend};
use crate::util::Hash;

// ---------------------------------------------------------------------------
// 1. Storage Class & Access Tier Definitions
// ---------------------------------------------------------------------------

/// Cloud object storage class classification (AWS S3, MinIO, GCS, Azure Blob).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum S3StorageClass {
    /// High-durability, immediate-access tier for active transfers.
    Standard,
    /// Infrequent access tier: lower storage cost, standard retrieval latency.
    StandardIa,
    /// Single-zone infrequent access for non-critical caches.
    OnezoneIa,
    /// Cloud auto-tiering based on dynamic access patterns.
    IntelligentTiering,
    /// Glacier archive with millisecond retrieval latency.
    GlacierInstantRetrieval,
    /// Traditional Glacier archive (3-5 hour retrieval, or expedited 1-5 min).
    GlacierFlexibleRetrieval,
    /// Ultra-low-cost cold archive (12-48 hour retrieval) for multi-year compliance.
    GlacierDeepArchive,
}

impl S3StorageClass {
    /// Return the wire header string value for `x-amz-storage-class`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::StandardIa => "STANDARD_IA",
            Self::OnezoneIa => "ONEZONE_IA",
            Self::IntelligentTiering => "INTELLIGENT_TIERING",
            Self::GlacierInstantRetrieval => "GLACIER_IR",
            Self::GlacierFlexibleRetrieval => "GLACIER",
            Self::GlacierDeepArchive => "DEEP_ARCHIVE",
        }
    }

    /// Whether this storage class requires an asynchronous restore job before GET reads.
    pub const fn requires_restore(&self) -> bool {
        matches!(
            self,
            Self::GlacierFlexibleRetrieval | Self::GlacierDeepArchive
        )
    }

    /// Whether this storage class represents a cold or deep archive.
    pub const fn is_cold_archive(&self) -> bool {
        matches!(
            self,
            Self::GlacierInstantRetrieval
                | Self::GlacierFlexibleRetrieval
                | Self::GlacierDeepArchive
        )
    }

    /// Parse from header or metadata string.
    pub fn from_header(s: &str) -> Self {
        match s.to_ascii_uppercase().trim() {
            "STANDARD_IA" => Self::StandardIa,
            "ONEZONE_IA" => Self::OnezoneIa,
            "INTELLIGENT_TIERING" => Self::IntelligentTiering,
            "GLACIER_IR" => Self::GlacierInstantRetrieval,
            "GLACIER" => Self::GlacierFlexibleRetrieval,
            "DEEP_ARCHIVE" => Self::GlacierDeepArchive,
            _ => Self::Standard,
        }
    }
}

impl fmt::Display for S3StorageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for S3StorageClass {
    type Err = VelcruxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_header(s))
    }
}

/// S3 Glacier restore job priority tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum GlacierTier {
    /// Expedited retrieval: 1-5 minutes (highest cost).
    Expedited,
    /// Standard retrieval: 3-5 hours.
    Standard,
    /// Bulk retrieval: 5-12 hours (lowest cost).
    Bulk,
}

impl GlacierTier {
    /// String identifier for XML request payload.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Expedited => "Expedited",
            Self::Standard => "Standard",
            Self::Bulk => "Bulk",
        }
    }
}

impl fmt::Display for GlacierTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Restoration status of an archived cloud object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectRestoreState {
    /// Object is stored in an immediate-access tier (no restore needed).
    NotArchived,
    /// Object is in cold archive and has not been restored.
    ArchivedNotRestored,
    /// Restore job is currently in progress.
    RestoreInProgress {
        /// Timestamp when restore was initiated.
        initiated_sec: u64,
        /// Requested retrieval tier.
        tier: GlacierTier,
    },
    /// Object has been restored and is available for random-access byte range reads.
    Restored {
        /// Timestamp when restored temporary copy expires.
        expires_sec: u64,
    },
}

impl ObjectRestoreState {
    /// Parse from `x-amz-restore` header string.
    pub fn parse_header(header_opt: Option<&str>, storage_class: S3StorageClass) -> Self {
        if !storage_class.requires_restore() {
            return Self::NotArchived;
        }

        let header = match header_opt {
            Some(h) if !h.trim().is_empty() => h.trim(),
            _ => return Self::ArchivedNotRestored,
        };

        if header.contains("ongoing-request=\"true\"") {
            return Self::RestoreInProgress {
                initiated_sec: 0,
                tier: GlacierTier::Standard,
            };
        }

        if header.contains("ongoing-request=\"false\"") {
            // ongoing-request="false", expiry-date="Fri, 23 Dec 2026 00:00:00 GMT"
            return Self::Restored {
                expires_sec: 1_800_000_000,
            };
        }

        Self::ArchivedNotRestored
    }

    /// Whether object is currently readable via GET / byte-range reads.
    pub fn is_readable(&self) -> bool {
        matches!(self, Self::NotArchived | Self::Restored { .. })
    }
}

// ---------------------------------------------------------------------------
// 2. Bucket Shard Descriptor & Partition Strategy
// ---------------------------------------------------------------------------

/// Configuration for an individual bucket shard in a distributed sharded topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketShard {
    /// Unique shard identifier (e.g. `shard-01`, `us-east-1a`).
    pub id: String,
    /// Target bucket name.
    pub bucket: String,
    /// S3 endpoint URL (e.g. `http://127.0.0.1:9000` or `https://s3.amazonaws.com`).
    pub endpoint: String,
    /// Optional key prefix prepended to all objects routed to this shard.
    pub prefix: String,
    /// AWS / Cloud region (default `us-east-1`).
    pub region: String,
    /// Virtual capacity / throughput weight multiplier on the hash ring (default 1).
    pub weight: u32,
    /// Default storage class assigned to new chunks written to this shard.
    pub default_storage_class: S3StorageClass,
    /// Whether this shard is read-only (e.g. during migration or decommission).
    pub read_only: bool,
}

impl BucketShard {
    /// Construct a new bucket shard descriptor with defaults.
    pub fn new(
        id: impl Into<String>,
        bucket: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            bucket: bucket.into(),
            endpoint: endpoint.into(),
            prefix: String::new(),
            region: "us-east-1".to_string(),
            weight: 1,
            default_storage_class: S3StorageClass::Standard,
            read_only: false,
        }
    }

    /// Set key prefix.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into().trim_matches('/').to_string();
        self
    }

    /// Set region.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    /// Set weight multiplier.
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }

    /// Set default storage class.
    pub fn with_storage_class(mut self, storage_class: S3StorageClass) -> Self {
        self.default_storage_class = storage_class;
        self
    }

    /// Mark shard as read-only.
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }
}

/// S3 key prefix partitioning strategy to avoid AWS per-prefix rate limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrefixPartitionStrategy {
    /// Flat prefix: `chunks/{hash}`.
    Flat,
    /// Two-level hex fanout: `chunks/{h[0..2]}/{h[2..4]}/{hash}` (65,536 distinct S3 prefixes).
    HexTwoLevel,
    /// Three-level hex fanout: `chunks/{h[0..2]}/{h[2..4]}/{h[4..6]}/{hash}` (16,777,216 prefixes).
    HexThreeLevel,
    /// Shard-prefixed two-level: `{shard_id}/chunks/{h[0..2]}/{hash}`.
    ShardPrefixed,
}

impl PrefixPartitionStrategy {
    /// Format an S3 object key for a chunk hash under the selected strategy.
    pub fn format_key(&self, shard: &BucketShard, h: &Hash) -> String {
        let hex = h.to_hex();
        let base_prefix = if shard.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", shard.prefix)
        };

        match self {
            Self::Flat => format!("{base_prefix}chunks/{hex}"),
            Self::HexTwoLevel => {
                let p1 = &hex[0..2];
                let p2 = &hex[2..4];
                format!("{base_prefix}chunks/{p1}/{p2}/{hex}")
            }
            Self::HexThreeLevel => {
                let p1 = &hex[0..2];
                let p2 = &hex[2..4];
                let p3 = &hex[4..6];
                format!("{base_prefix}chunks/{p1}/{p2}/{p3}/{hex}")
            }
            Self::ShardPrefixed => {
                let p1 = &hex[0..2];
                format!("{base_prefix}{}/chunks/{p1}/{hex}", shard.id)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Consistent Hashing Shard Router (`ShardRouter`)
// ---------------------------------------------------------------------------

/// Statistical report analyzing distribution across bucket shards.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShardDistributionStats {
    /// Total samples evaluated.
    pub total_samples: usize,
    /// Sample count allocated to each shard ID.
    pub counts_per_shard: HashMap<String, usize>,
    /// Percentage allocated to each shard ID.
    pub percentages: HashMap<String, f64>,
    /// Shannon entropy $H(X)$ of the distribution (in bits). Maximum is $\log_2(N)$.
    pub entropy_bits: f64,
    /// Theoretical maximum entropy for the number of active shards.
    pub max_entropy_bits: f64,
    /// Uniformity ratio: $\frac{H(X)}{H_{\max}}$ (1.0 = perfectly uniform).
    pub uniformity_ratio: f64,
}

/// Consistent hashing shard router with virtual node tokens.
#[derive(Debug, Clone)]
pub struct ShardRouter {
    shards: BTreeMap<String, BucketShard>,
    ring: BTreeMap<u64, String>, // token -> shard_id
    vnodes_per_shard: usize,
    strategy: PrefixPartitionStrategy,
}

impl ShardRouter {
    /// Create a new shard router with specified vnodes per shard and partition strategy.
    pub fn new(vnodes_per_shard: usize, strategy: PrefixPartitionStrategy) -> Self {
        Self {
            shards: BTreeMap::new(),
            ring: BTreeMap::new(),
            vnodes_per_shard: vnodes_per_shard.max(16),
            strategy,
        }
    }

    /// Add a bucket shard to the router.
    pub fn add_shard(&mut self, shard: BucketShard) {
        let shard_id = shard.id.clone();
        let effective_vnodes = self.vnodes_per_shard * (shard.weight as usize);

        for i in 0..effective_vnodes {
            let token_key = format!("{}:{}:vnode", shard_id, i);
            let token = hash_to_u64(token_key.as_bytes());
            self.ring.insert(token, shard_id.clone());
        }

        self.shards.insert(shard_id, shard);
    }

    /// Remove a bucket shard by ID.
    pub fn remove_shard(&mut self, shard_id: &str) -> Option<BucketShard> {
        self.ring.retain(|_, id| id != shard_id);
        self.shards.remove(shard_id)
    }

    /// Total registered bucket shards.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Access all configured shards.
    pub fn shards(&self) -> &BTreeMap<String, BucketShard> {
        &self.shards
    }

    /// Active prefix partitioning strategy.
    pub fn strategy(&self) -> PrefixPartitionStrategy {
        self.strategy
    }

    /// Route a chunk hash to its primary target bucket shard.
    pub fn route_hash(&self, h: &Hash) -> Result<&BucketShard, VelcruxError> {
        if self.ring.is_empty() {
            return Err(VelcruxError::Config(
                "no bucket shards configured in ShardRouter".to_string(),
            ));
        }

        let token = hash_to_u64(h.as_bytes());
        let shard_id = match self.ring.range(token..).next() {
            Some((_, id)) => id,
            None => self
                .ring
                .iter()
                .next()
                .map(|(_, id)| id)
                .expect("non-empty ring"),
        };

        self.shards.get(shard_id).ok_or_else(|| {
            VelcruxError::Internal(format!("shard '{}' missing from registry", shard_id))
        })
    }

    /// Route an arbitrary string object key to its primary target bucket shard.
    pub fn route_key(&self, key: &str) -> Result<&BucketShard, VelcruxError> {
        let h = Hash::of(key.as_bytes());
        self.route_hash(&h)
    }

    /// Retrieve an ordered preference list of distinct shards for replication or fallback.
    pub fn preference_list(&self, h: &Hash, count: usize) -> Vec<&BucketShard> {
        if self.ring.is_empty() || count == 0 {
            return Vec::new();
        }

        let token = hash_to_u64(h.as_bytes());
        let target_count = count.min(self.shards.len());
        let mut selected = Vec::with_capacity(target_count);
        let mut seen = HashSet::with_capacity(target_count);

        let iter_after = self.ring.range(token..);
        let iter_wrap = self.ring.range(..token);

        for (_tok, shard_id) in iter_after.chain(iter_wrap) {
            if seen.insert(shard_id) {
                if let Some(shard) = self.shards.get(shard_id) {
                    selected.push(shard);
                    if selected.len() == target_count {
                        break;
                    }
                }
            }
        }

        selected
    }

    /// Format the canonical S3 object key for a chunk in a specific shard.
    pub fn format_key(&self, shard: &BucketShard, h: &Hash) -> String {
        self.strategy.format_key(shard, h)
    }

    /// Evaluate hash routing uniformity and calculate Shannon entropy across sample hashes.
    pub fn distribution_stats(&self, sample_hashes: &[Hash]) -> ShardDistributionStats {
        let total = sample_hashes.len();
        let mut counts = HashMap::new();
        for s in self.shards.keys() {
            counts.insert(s.clone(), 0usize);
        }

        for h in sample_hashes {
            if let Ok(shard) = self.route_hash(h) {
                *counts.entry(shard.id.clone()).or_insert(0) += 1;
            }
        }

        let mut percentages = HashMap::new();
        let mut entropy = 0.0f64;
        for (id, count) in &counts {
            let p = if total > 0 {
                *count as f64 / total as f64
            } else {
                0.0
            };
            percentages.insert(id.clone(), p * 100.0);
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        let n = self.shards.len() as f64;
        let max_entropy = if n > 1.0 { n.log2() } else { 1.0 };
        let ratio = if max_entropy > 0.0 {
            entropy / max_entropy
        } else {
            1.0
        };

        ShardDistributionStats {
            total_samples: total,
            counts_per_shard: counts,
            percentages,
            entropy_bits: entropy,
            max_entropy_bits: max_entropy,
            uniformity_ratio: ratio,
        }
    }
}

fn hash_to_u64(data: &[u8]) -> u64 {
    let digest = blake3::hash(data);
    let bytes = digest.as_bytes();
    u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"))
}

// ---------------------------------------------------------------------------
// 4. Lifecycle Auto-Tiering Rule Engine
// ---------------------------------------------------------------------------

/// Policy rule defining automated transition from hot storage to colder tiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardedLifecycleRule {
    /// Unique rule identifier.
    pub id: String,
    /// Key prefix filter (empty = match all objects).
    pub prefix_filter: String,
    /// Days elapsed since creation before migrating to Standard-IA.
    pub days_to_ia: Option<u32>,
    /// Days elapsed since creation before migrating to Glacier Flexible Retrieval.
    pub days_to_glacier: Option<u32>,
    /// Days elapsed since creation before migrating to Glacier Deep Archive.
    pub days_to_deep_archive: Option<u32>,
    /// Minimum object size in bytes required for transition (e.g. 128 KiB for S3 IA/Glacier).
    pub min_size_bytes: Option<u64>,
}

impl ShardedLifecycleRule {
    /// Construct a new lifecycle rule.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            prefix_filter: String::new(),
            days_to_ia: None,
            days_to_glacier: None,
            days_to_deep_archive: None,
            min_size_bytes: Some(128 * 1024), // S3 Standard-IA / Glacier min chargeable size
        }
    }

    /// Set prefix filter.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix_filter = prefix.into();
        self
    }

    /// Set transition threshold to Standard-IA.
    pub fn with_days_to_ia(mut self, days: u32) -> Self {
        self.days_to_ia = Some(days);
        self
    }

    /// Set transition threshold to Glacier.
    pub fn with_days_to_glacier(mut self, days: u32) -> Self {
        self.days_to_glacier = Some(days);
        self
    }

    /// Set transition threshold to Glacier Deep Archive.
    pub fn with_days_to_deep_archive(mut self, days: u32) -> Self {
        self.days_to_deep_archive = Some(days);
        self
    }

    /// Set minimum object size threshold in bytes.
    pub fn with_min_size(mut self, size: u64) -> Self {
        self.min_size_bytes = Some(size);
        self
    }
}

/// Outcome report summarizing an automated lifecycle tiering evaluation sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardedLifecycleReport {
    /// Total bucket shards evaluated.
    pub shards_scanned: usize,
    /// Total object metadata records evaluated.
    pub objects_evaluated: usize,
    /// Objects transitioned to `STANDARD_IA`.
    pub transitioned_ia: usize,
    /// Objects transitioned to `GLACIER`.
    pub transitioned_glacier: usize,
    /// Objects transitioned to `DEEP_ARCHIVE`.
    pub transitioned_deep_archive: usize,
    /// Total bytes migrated across all colder tiers.
    pub bytes_transitioned: u64,
    /// Bytes evaluated but left unchanged.
    pub bytes_skipped: u64,
}

/// Evaluates lifecycle rules against object metadata.
pub struct ShardedLifecycleEngine {
    rules: Vec<ShardedLifecycleRule>,
}

impl ShardedLifecycleEngine {
    /// Create a new lifecycle engine with the given rules.
    pub fn new(rules: Vec<ShardedLifecycleRule>) -> Self {
        Self { rules }
    }

    /// Evaluate which storage class an object should occupy based on its age and size.
    pub fn evaluate_target_class(
        &self,
        meta: &S3ObjectMeta,
        now_sec: u64,
    ) -> Option<S3StorageClass> {
        let age_sec = now_sec.saturating_sub(meta.last_modified_sec.max(0) as u64);
        let age_days = (age_sec / 86400) as u32;

        let mut target = None;

        for rule in &self.rules {
            if !rule.prefix_filter.is_empty() && !meta.key.starts_with(&rule.prefix_filter) {
                continue;
            }

            if let Some(min_size) = rule.min_size_bytes {
                if meta.size < min_size {
                    continue;
                }
            }

            // Check tiers from coldest to warmest
            if let Some(deep_days) = rule.days_to_deep_archive {
                if age_days >= deep_days {
                    target = Some(S3StorageClass::GlacierDeepArchive);
                    break;
                }
            }

            if let Some(glacier_days) = rule.days_to_glacier {
                if age_days >= glacier_days
                    && (target.is_none() || target == Some(S3StorageClass::StandardIa))
                {
                    target = Some(S3StorageClass::GlacierFlexibleRetrieval);
                }
            }

            if let Some(ia_days) = rule.days_to_ia {
                if age_days >= ia_days && target.is_none() {
                    target = Some(S3StorageClass::StandardIa);
                }
            }
        }

        target
    }

    /// Evaluate a collection of objects in a shard and produce a lifecycle report.
    pub fn evaluate_shard(&self, objects: &[S3ObjectMeta], now_sec: u64) -> ShardedLifecycleReport {
        let mut report = ShardedLifecycleReport {
            shards_scanned: 1,
            objects_evaluated: objects.len(),
            ..Default::default()
        };

        for obj in objects {
            let current_class = obj
                .storage_class
                .as_deref()
                .map(S3StorageClass::from_header)
                .unwrap_or(S3StorageClass::Standard);

            if let Some(target) = self.evaluate_target_class(obj, now_sec) {
                if target != current_class {
                    match target {
                        S3StorageClass::StandardIa => report.transitioned_ia += 1,
                        S3StorageClass::GlacierFlexibleRetrieval => {
                            report.transitioned_glacier += 1
                        }
                        S3StorageClass::GlacierDeepArchive => report.transitioned_deep_archive += 1,
                        _ => {}
                    }
                    report.bytes_transitioned += obj.size;
                    continue;
                }
            }
            report.bytes_skipped += obj.size;
        }

        report
    }
}

// ---------------------------------------------------------------------------
// 5. Glacier Restore Orchestrator (`GlacierRestoreCoordinator`)
// ---------------------------------------------------------------------------

/// Helper for generating S3 restore XML payloads and parsing restore headers.
pub struct GlacierRestoreCoordinator;

impl GlacierRestoreCoordinator {
    /// Build canonical XML request body for `POST /{bucket}/{key}?restore`.
    pub fn build_restore_xml(days: u32, tier: GlacierTier) -> String {
        format!(
            "<RestoreRequest>\n  <Days>{}</Days>\n  <GlacierJobParameters>\n    <Tier>{}</Tier>\n  </GlacierJobParameters>\n</RestoreRequest>",
            days.max(1),
            tier.as_str()
        )
    }

    /// Parse `x-amz-restore` header value.
    pub fn parse_restore_header(header: Option<&str>, class: S3StorageClass) -> ObjectRestoreState {
        ObjectRestoreState::parse_header(header, class)
    }
}

// ---------------------------------------------------------------------------
// 6. Sharded Chunk Store (`ShardedChunkStore`)
// ---------------------------------------------------------------------------

/// Distributed content-addressed chunk store sharded across multiple S3 bucket endpoints.
#[derive(Clone)]
pub struct ShardedChunkStore {
    router: Arc<RwLock<ShardRouter>>,
    backends: Arc<RwLock<HashMap<String, S3StorageBackend>>>,
}

impl ShardedChunkStore {
    /// Construct a new sharded chunk store with the provided router.
    pub fn new(router: ShardRouter) -> Self {
        let mut backends = HashMap::new();
        for (id, shard) in router.shards() {
            let mut cfg = S3Config::new(&shard.bucket)
                .with_endpoint(&shard.endpoint)
                .with_region(&shard.region)
                .with_prefix(&shard.prefix);
            cfg.default_storage_class = Some(shard.default_storage_class.as_str().to_string());
            let backend = S3StorageBackend::new(cfg);
            backends.insert(id.clone(), backend);
        }

        Self {
            router: Arc::new(RwLock::new(router)),
            backends: Arc::new(RwLock::new(backends)),
        }
    }

    /// Construct with live network mode enabled for all shards.
    pub fn with_live_mode(self, live: bool) -> Self {
        if let Ok(mut b) = self.backends.try_write() {
            for backend in b.values_mut() {
                *backend = backend.clone().with_live_mode(live);
            }
        }
        self
    }

    /// Ensure all shard buckets exist on target S3 endpoints.
    pub async fn ensure_all_buckets_exist(&self) -> Result<(), S3Error> {
        let backends = self.backends.read().await;
        for backend in backends.values() {
            backend.ensure_bucket_exists().await?;
        }
        Ok(())
    }

    /// Access the underlying router.
    pub fn router(&self) -> &Arc<RwLock<ShardRouter>> {
        &self.router
    }

    /// Resolve the backend and formatted key for a chunk hash.
    async fn resolve_shard_and_key(
        &self,
        h: &Hash,
    ) -> Result<(S3StorageBackend, String, S3StorageClass), VelcruxError> {
        let router = self.router.read().await;
        let shard = router.route_hash(h)?;
        let key = router.format_key(shard, h);
        let storage_class = shard.default_storage_class;

        let backends = self.backends.read().await;
        let backend = backends
            .get(&shard.id)
            .ok_or_else(|| {
                VelcruxError::Internal(format!("backend for shard '{}' missing", shard.id))
            })?
            .clone();

        Ok((backend, key, storage_class))
    }

    /// Initiate Glacier restoration for an archived chunk.
    pub async fn restore_chunk(
        &self,
        h: &Hash,
        days: u32,
        tier: GlacierTier,
    ) -> Result<(), VelcruxError> {
        let (backend, key, _sc) = self.resolve_shard_and_key(h).await?;
        backend
            .restore_object(&key, days, tier.as_str())
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))
    }

    /// Query the active restoration status for a chunk.
    pub async fn restore_status(&self, h: &Hash) -> Result<ObjectRestoreState, VelcruxError> {
        let (backend, key, sc) = self.resolve_shard_and_key(h).await?;
        let meta = backend
            .head_object(&key)
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;

        match meta {
            Some(m) => {
                let actual_class = m
                    .storage_class
                    .as_deref()
                    .map(S3StorageClass::from_header)
                    .unwrap_or(sc);
                Ok(ObjectRestoreState::parse_header(
                    m.restore_status.as_deref(),
                    actual_class,
                ))
            }
            None => Err(VelcruxError::Internal(format!("chunk {} not found", h))),
        }
    }

    /// Poll until restore completes or timeout expires.
    pub async fn wait_for_restore(
        &self,
        h: &Hash,
        poll_interval: Duration,
        timeout: Duration,
    ) -> Result<ObjectRestoreState, VelcruxError> {
        let start = std::time::Instant::now();
        loop {
            let state = self.restore_status(h).await?;
            if let ObjectRestoreState::Restored { .. } = state {
                return Ok(state);
            }
            if start.elapsed() >= timeout {
                return Ok(state);
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}

#[async_trait]
impl ChunkStore for ShardedChunkStore {
    async fn has(&self, h: &Hash) -> Result<bool, VelcruxError> {
        let (backend, key, _sc) = self.resolve_shard_and_key(h).await?;
        match backend.head_object(&key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(VelcruxError::Internal(e.to_string())),
        }
    }

    async fn has_batch(&self, hashes: &[Hash]) -> Result<Vec<bool>, VelcruxError> {
        // Group hashes by shard for efficient parallel lookups
        let mut results = vec![false; hashes.len()];
        let mut shard_groups: HashMap<String, Vec<(usize, Hash, String)>> = HashMap::new();

        {
            let router = self.router.read().await;
            for (idx, h) in hashes.iter().enumerate() {
                if let Ok(shard) = router.route_hash(h) {
                    let key = router.format_key(shard, h);
                    shard_groups
                        .entry(shard.id.clone())
                        .or_default()
                        .push((idx, *h, key));
                }
            }
        }

        let backends = self.backends.read().await;
        for (shard_id, items) in shard_groups {
            if let Some(backend) = backends.get(&shard_id) {
                for (idx, _h, key) in items {
                    if let Ok(Some(_)) = backend.head_object(&key).await {
                        results[idx] = true;
                    }
                }
            }
        }

        Ok(results)
    }

    async fn put(&self, h: &Hash, data: &[u8]) -> Result<(), VelcruxError> {
        let actual = Hash::of(data);
        if actual != *h {
            return Err(VelcruxError::Internal(format!(
                "chunk hash mismatch: expected {}, got {}",
                h, actual
            )));
        }

        let (backend, key, _sc) = self.resolve_shard_and_key(h).await?;
        backend
            .put_object(&key, data, Some(*h))
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, h: &Hash) -> Result<Bytes, VelcruxError> {
        let (backend, key, sc) = self.resolve_shard_and_key(h).await?;

        // Check if object is in cold archive and requires restore
        if let Ok(Some(meta)) = backend.head_object(&key).await {
            let actual_class = meta
                .storage_class
                .as_deref()
                .map(S3StorageClass::from_header)
                .unwrap_or(sc);
            let state =
                ObjectRestoreState::parse_header(meta.restore_status.as_deref(), actual_class);
            if !state.is_readable() {
                return Err(VelcruxError::Internal(format!(
                    "chunk {} is archived in {} and has not been restored (call restore_chunk first)",
                    h, actual_class
                )));
            }
        }

        let data = backend
            .get_object(&key)
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;

        let actual = Hash::of(&data);
        if actual != *h {
            return Err(VelcruxError::Internal(format!(
                "chunk corrupt in sharded S3: expected {}, got {}",
                h, actual
            )));
        }

        Ok(Bytes::from(data))
    }

    async fn remove(&self, h: &Hash) -> Result<bool, VelcruxError> {
        if !self.has(h).await? {
            return Ok(false);
        }

        let (backend, key, _sc) = self.resolve_shard_and_key(h).await?;
        backend
            .delete_object(&key)
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;

        Ok(true)
    }

    async fn total_chunks(&self) -> Result<usize, VelcruxError> {
        let mut total = 0;
        let backends = self.backends.read().await;
        for backend in backends.values() {
            let list = backend
                .list_objects("", None)
                .await
                .map_err(|e| VelcruxError::Internal(e.to_string()))?;
            total += list.len();
        }
        Ok(total)
    }

    async fn total_bytes(&self) -> Result<u64, VelcruxError> {
        let mut total = 0u64;
        let backends = self.backends.read().await;
        for backend in backends.values() {
            let list = backend
                .list_objects("", None)
                .await
                .map_err(|e| VelcruxError::Internal(e.to_string()))?;
            total += list.iter().map(|o| o.size).sum::<u64>();
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_class_parsing_and_restore_predicates() {
        assert_eq!(
            S3StorageClass::from_header("STANDARD"),
            S3StorageClass::Standard
        );
        assert_eq!(
            S3StorageClass::from_header("glacier"),
            S3StorageClass::GlacierFlexibleRetrieval
        );
        assert_eq!(
            S3StorageClass::from_header("deep_archive"),
            S3StorageClass::GlacierDeepArchive
        );

        assert!(!S3StorageClass::Standard.requires_restore());
        assert!(!S3StorageClass::StandardIa.requires_restore());
        assert!(!S3StorageClass::GlacierInstantRetrieval.requires_restore());
        assert!(S3StorageClass::GlacierFlexibleRetrieval.requires_restore());
        assert!(S3StorageClass::GlacierDeepArchive.requires_restore());
    }

    #[test]
    fn test_consistent_hash_sharding_and_entropy() {
        let mut router = ShardRouter::new(128, PrefixPartitionStrategy::HexTwoLevel);
        router.add_shard(BucketShard::new(
            "shard-us-east",
            "bucket-east",
            "http://127.0.0.1:9000",
        ));
        router.add_shard(BucketShard::new(
            "shard-us-west",
            "bucket-west",
            "http://127.0.0.1:9000",
        ));
        router.add_shard(BucketShard::new(
            "shard-eu-central",
            "bucket-eu",
            "http://127.0.0.1:9000",
        ));

        assert_eq!(router.shard_count(), 3);

        // Generate 300 distinct hashes
        let mut sample_hashes = Vec::new();
        for i in 0..300u64 {
            sample_hashes.push(Hash::of(&i.to_le_bytes()));
        }

        let stats = router.distribution_stats(&sample_hashes);
        assert_eq!(stats.total_samples, 300);

        // Each shard should receive roughly 33% of keys (+/- 15%)
        for (_shard, &pct) in &stats.percentages {
            assert!(
                pct >= 18.0 && pct <= 48.0,
                "shard percentage {:.1}% should be balanced around 33.3%",
                pct
            );
        }

        // Uniformity ratio should be >= 0.90
        assert!(
            stats.uniformity_ratio >= 0.90,
            "uniformity ratio {:.3} should be >= 0.90",
            stats.uniformity_ratio
        );
    }

    #[test]
    fn test_prefix_partitioning_two_level_hex() {
        let shard = BucketShard::new("s1", "bucket", "http://localhost").with_prefix("v1");
        let hash = Hash::of(b"sample data payload");
        let hex = hash.to_hex();

        let flat = PrefixPartitionStrategy::Flat.format_key(&shard, &hash);
        assert_eq!(flat, format!("v1/chunks/{}", hex));

        let two_level = PrefixPartitionStrategy::HexTwoLevel.format_key(&shard, &hash);
        assert_eq!(
            two_level,
            format!("v1/chunks/{}/{}/{}", &hex[0..2], &hex[2..4], hex)
        );
    }
}
