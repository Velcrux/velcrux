//! Cross-cluster WAN geo-replication and conflict-free resolution engine (Option BA).
//!
//! Implements `REQUIREMENTS.md` §50–§55, §62, §63 and `ARCHITECTURE.md` §9.
//! Provides asynchronous multi-region data replication across high-latency WAN links,
//! causality tracking with Vector Clocks, configurable conflict resolution policies
//! (LWW, Priority, KeepBoth), tombstone lifecycle tracking, and backpressure pacing.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::util::Hash;

/// Causal ordering relationship between two vector clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockOrdering {
    /// Both clocks are identical.
    Equal,
    /// First clock strictly dominates the second (first is newer).
    Greater,
    /// First clock is strictly dominated by the second (first is older).
    Less,
    /// Clocks have branched concurrently; concurrent conflict detected.
    Concurrent,
}

/// Vector clock tracking distributed causality across distinct regions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock {
    /// Map of Region ID -> logical sequence counter.
    pub clocks: BTreeMap<String, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a vector clock with an initial region tick.
    pub fn initial(region: &str) -> Self {
        let mut vc = Self::new();
        vc.increment(region);
        vc
    }

    /// Increment logical counter for a given region.
    pub fn increment(&mut self, region: &str) -> u64 {
        let counter = self.clocks.entry(region.to_string()).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Get logical counter for a specific region.
    pub fn get(&self, region: &str) -> u64 {
        self.clocks.get(region).copied().unwrap_or(0)
    }

    /// Merge another vector clock by taking pairwise maximums.
    pub fn merge(&mut self, other: &VectorClock) {
        for (region, &counter) in &other.clocks {
            let current = self.clocks.entry(region.clone()).or_insert(0);
            *current = (*current).max(counter);
        }
    }

    /// Compare causal ordering between self and other.
    pub fn compare(&self, other: &VectorClock) -> ClockOrdering {
        let mut has_greater = false;
        let mut has_less = false;

        let all_regions: std::collections::BTreeSet<_> =
            self.clocks.keys().chain(other.clocks.keys()).collect();

        for region in all_regions {
            let v_self = self.get(region);
            let v_other = other.get(region);

            if v_self > v_other {
                has_greater = true;
            } else if v_self < v_other {
                has_less = true;
            }
        }

        match (has_greater, has_less) {
            (false, false) => ClockOrdering::Equal,
            (true, false) => ClockOrdering::Greater,
            (false, true) => ClockOrdering::Less,
            (true, true) => ClockOrdering::Concurrent,
        }
    }
}

/// Strategy for resolving concurrent conflicts during cross-region replication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    /// Last-Write-Wins based on physical wall-clock timestamp; ties broken by region ID.
    LastWriteWins,
    /// Highest-priority region always takes precedence on concurrent conflicts.
    PrimaryAuthority {
        /// Primary authority region identifier.
        primary_region: String,
    },
    /// Preserve both concurrent versions by creating a conflict branch file.
    KeepBoth,
    /// Reject the incoming concurrent change and flag an error for manual operator review.
    RejectConcurrent,
}

impl Default for ConflictPolicy {
    fn default() -> Self {
        ConflictPolicy::LastWriteWins
    }
}

/// Operational state of a remote geo-replication target region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoRegionState {
    /// Region is online and actively receiving replication streams.
    Active,
    /// Elevated WAN latency or packet loss; replication throttled.
    Degraded,
    /// Replication stream administratively paused; changes accumulating in queue.
    Paused,
    /// Unreachable or offline.
    Offline,
}

/// Metadata and link status of a peer replication region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRegionDescriptor {
    /// Unique region identifier (e.g. "us-east-1", "eu-central-1").
    pub region_id: String,
    /// Gateway network address of this region.
    pub endpoint: SocketAddr,
    /// Relative priority weighting (1-100).
    pub priority: u32,
    /// Current operational status.
    pub state: GeoRegionState,
    /// Estimated replication lag in milliseconds.
    pub replication_lag_ms: u64,
    /// Number of outbound changes pending in queue for this region.
    pub pending_changes: usize,
}

impl GeoRegionDescriptor {
    /// Construct a new region descriptor.
    pub fn new(region_id: impl Into<String>, endpoint: SocketAddr) -> Self {
        Self {
            region_id: region_id.into(),
            endpoint,
            priority: 50,
            state: GeoRegionState::Active,
            replication_lag_ms: 0,
            pending_changes: 0,
        }
    }
}

/// Full metadata describing a replicated file item or tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoItemMetadata {
    /// Relative file path.
    pub rel_path: String,
    /// File size in bytes (0 if tombstone).
    pub size: u64,
    /// BLAKE3 checksum.
    pub hash: Hash,
    /// Vector clock causality tracker.
    pub vector_clock: VectorClock,
    /// Physical wall-clock timestamp (Unix epoch milliseconds).
    pub physical_time_ms: u64,
    /// Originating region where the modification occurred.
    pub origin_region: String,
    /// True if this item represents a deleted tombstone.
    pub is_tombstone: bool,
}

impl GeoItemMetadata {
    /// Construct metadata for an active file mutation.
    pub fn file(
        rel_path: impl Into<String>,
        size: u64,
        hash: Hash,
        vector_clock: VectorClock,
        origin_region: impl Into<String>,
    ) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            rel_path: rel_path.into(),
            size,
            hash,
            vector_clock,
            physical_time_ms: now_ms,
            origin_region: origin_region.into(),
            is_tombstone: false,
        }
    }

    /// Construct metadata for a deleted file tombstone.
    pub fn tombstone(
        rel_path: impl Into<String>,
        vector_clock: VectorClock,
        origin_region: impl Into<String>,
    ) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            rel_path: rel_path.into(),
            size: 0,
            hash: Hash::of(b""),
            vector_clock,
            physical_time_ms: now_ms,
            origin_region: origin_region.into(),
            is_tombstone: true,
        }
    }
}

/// An individual replication change packet streamed across WAN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationChange {
    /// Monotonically increasing regional change sequence number.
    pub sequence_id: u64,
    /// Replicated item metadata.
    pub metadata: GeoItemMetadata,
    /// Payload data bytes (None if tombstone or metadata-only pass).
    #[serde(skip)]
    pub payload: Option<Bytes>,
}

/// Action to take as the outcome of conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictAction {
    /// Apply the incoming remote change (remote wins or is strictly newer).
    ApplyRemote,
    /// Keep current local state intact (local wins or is strictly newer).
    KeepLocal,
    /// Concurrent conflict: create a branch sidecar file (e.g. `file.conflict-us-east.dat`).
    CreateBranch {
        /// Created conflict branch relative path.
        branch_path: String,
    },
    /// Reject the incoming remote change due to strict conflict policy.
    Rejected,
}

/// Outcome of conflict resolution evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictResolutionResult {
    /// Action taken.
    pub action: ConflictAction,
    /// Whether an actual concurrent conflict was detected.
    pub was_conflict: bool,
    /// Human-readable explanation.
    pub details: String,
}

/// Outbound queue buffering replication changes for peer regions.
#[derive(Debug, Default)]
pub struct GeoReplicationQueue {
    /// Outbound change buffer per destination region.
    outbound: HashMap<String, Vec<ReplicationChange>>,
    /// Next change sequence ID.
    next_seq: u64,
    /// Maximum pending queue size per region.
    max_queue_depth: usize,
}

impl GeoReplicationQueue {
    /// Create a new replication queue.
    pub fn new(max_depth: usize) -> Self {
        Self {
            outbound: HashMap::new(),
            next_seq: 1,
            max_queue_depth: max_depth.max(100),
        }
    }

    /// Enqueue a change to all active target regions.
    pub fn enqueue(
        &mut self,
        target_regions: &[String],
        metadata: GeoItemMetadata,
        payload: Option<Bytes>,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;

        let change = ReplicationChange {
            sequence_id: seq,
            metadata,
            payload,
        };

        for region in target_regions {
            let list = self.outbound.entry(region.clone()).or_default();
            if list.len() < self.max_queue_depth {
                list.push(change.clone());
            }
        }

        seq
    }

    /// Drain up to `batch_size` pending changes for a given region.
    pub fn drain_batch(&mut self, region: &str, batch_size: usize) -> Vec<ReplicationChange> {
        if let Some(list) = self.outbound.get_mut(region) {
            let count = list.len().min(batch_size);
            list.drain(0..count).collect()
        } else {
            Vec::new()
        }
    }

    /// Total count of pending changes across all regional queues.
    pub fn pending_count(&self, region: &str) -> usize {
        self.outbound.get(region).map(|l| l.len()).unwrap_or(0)
    }

    /// Total count of pending changes across all regional queues.
    pub fn total_pending(&self) -> usize {
        self.outbound.values().map(|l| l.len()).sum()
    }
}

/// Summary report of geo-replication cluster status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoStatusReport {
    /// Local region ID.
    pub local_region: String,
    /// Active conflict resolution policy.
    pub conflict_policy: String,
    /// Total registered remote regions.
    pub total_regions: usize,
    /// Number of active online regions.
    pub active_regions: usize,
    /// Total tracked files in local geo-ledger.
    pub tracked_files: usize,
    /// Active tombstone count.
    pub active_tombstones: usize,
    /// Total pending outbound changes across all queues.
    pub pending_outbound_changes: usize,
    /// Cumulative conflicts resolved since startup.
    pub total_conflicts_resolved: u64,
    /// Detailed list of peer regions.
    pub regions: Vec<GeoRegionDescriptor>,
}

/// Cross-cluster WAN geo-replication coordinator.
pub struct GeoReplicationCoordinator {
    /// Local region identifier.
    local_region: String,
    /// Active conflict resolution policy.
    policy: ConflictPolicy,
    /// Registered remote peer regions.
    regions: RwLock<BTreeMap<String, GeoRegionDescriptor>>,
    /// Active file state ledger: relative path -> item metadata.
    ledger: RwLock<BTreeMap<String, GeoItemMetadata>>,
    /// Tombstone ledger: relative path -> tombstone metadata.
    tombstones: RwLock<BTreeMap<String, GeoItemMetadata>>,
    /// Outbound replication queue.
    queue: RwLock<GeoReplicationQueue>,
    /// Conflict counter.
    conflict_count: RwLock<u64>,
}

impl GeoReplicationCoordinator {
    /// Create a new geo-replication coordinator for the local region.
    pub fn new(local_region: impl Into<String>, policy: ConflictPolicy) -> Self {
        Self {
            local_region: local_region.into(),
            policy,
            regions: RwLock::new(BTreeMap::new()),
            ledger: RwLock::new(BTreeMap::new()),
            tombstones: RwLock::new(BTreeMap::new()),
            queue: RwLock::new(GeoReplicationQueue::new(10_000)),
            conflict_count: RwLock::new(0),
        }
    }

    /// Register a remote peer region.
    pub fn register_region(&self, descriptor: GeoRegionDescriptor) {
        let mut regions = self.regions.write().unwrap();
        regions.insert(descriptor.region_id.clone(), descriptor);
    }

    /// Record a local file mutation (creation or modification), updating the local vector clock
    /// and enqueuing the change for outbound WAN replication.
    pub fn record_local_mutation(
        &self,
        rel_path: &str,
        size: u64,
        hash: Hash,
        payload: Option<Bytes>,
    ) -> ReplicationChange {
        let mut ledger = self.ledger.write().unwrap();
        let mut tombstones = self.tombstones.write().unwrap();

        // Remove from tombstones if previously deleted
        tombstones.remove(rel_path);

        // Get existing vector clock or create new
        let mut vc = ledger
            .get(rel_path)
            .map(|existing| existing.vector_clock.clone())
            .unwrap_or_default();

        vc.increment(&self.local_region);

        let metadata = GeoItemMetadata::file(rel_path, size, hash, vc, &self.local_region);
        ledger.insert(rel_path.to_string(), metadata.clone());

        // Enqueue to all active remote regions
        let target_regions: Vec<String> = {
            let regions = self.regions.read().unwrap();
            regions.keys().cloned().collect()
        };

        let mut queue = self.queue.write().unwrap();
        let seq = queue.enqueue(&target_regions, metadata.clone(), payload.clone());

        ReplicationChange {
            sequence_id: seq,
            metadata,
            payload,
        }
    }

    /// Record a local file deletion, creating a tombstone with incremented vector clock
    /// and enqueuing the tombstone for outbound WAN replication.
    pub fn record_local_deletion(&self, rel_path: &str) -> Option<ReplicationChange> {
        let mut ledger = self.ledger.write().unwrap();
        let mut tombstones = self.tombstones.write().unwrap();

        let mut vc = if let Some(existing) = ledger.remove(rel_path) {
            existing.vector_clock
        } else {
            tombstones
                .get(rel_path)
                .map(|t| t.vector_clock.clone())
                .unwrap_or_default()
        };

        vc.increment(&self.local_region);

        let tombstone = GeoItemMetadata::tombstone(rel_path, vc, &self.local_region);
        tombstones.insert(rel_path.to_string(), tombstone.clone());

        let target_regions: Vec<String> = {
            let regions = self.regions.read().unwrap();
            regions.keys().cloned().collect()
        };

        let mut queue = self.queue.write().unwrap();
        let seq = queue.enqueue(&target_regions, tombstone.clone(), None);

        Some(ReplicationChange {
            sequence_id: seq,
            metadata: tombstone,
            payload: None,
        })
    }

    /// Evaluate an incoming remote change against current local state, applying conflict
    /// resolution policy and updating vector clocks.
    pub fn apply_remote_change(
        &self,
        change: &ReplicationChange,
    ) -> Result<ConflictResolutionResult, VelcruxError> {
        let rel_path = &change.metadata.rel_path;
        let mut ledger = self.ledger.write().unwrap();
        let mut tombstones = self.tombstones.write().unwrap();

        // Find current local state (either in ledger or tombstones)
        let local_meta = ledger
            .get(rel_path)
            .or_else(|| tombstones.get(rel_path))
            .cloned();

        let resolution = match local_meta {
            None => {
                // No local copy exists: remote change is unconditionally accepted
                ConflictResolutionResult {
                    action: ConflictAction::ApplyRemote,
                    was_conflict: false,
                    details: "First-time replication of new item".to_string(),
                }
            }
            Some(ref local) => {
                // Compare vector clocks
                match local.vector_clock.compare(&change.metadata.vector_clock) {
                    ClockOrdering::Less => {
                        // Remote strictly dominates local: remote is newer
                        ConflictResolutionResult {
                            action: ConflictAction::ApplyRemote,
                            was_conflict: false,
                            details: "Remote vector clock strictly dominates local".to_string(),
                        }
                    }
                    ClockOrdering::Greater | ClockOrdering::Equal => {
                        // Local strictly dominates or is identical to remote: ignore older remote
                        ConflictResolutionResult {
                            action: ConflictAction::KeepLocal,
                            was_conflict: false,
                            details: "Local vector clock is current or strictly dominates remote"
                                .to_string(),
                        }
                    }
                    ClockOrdering::Concurrent => {
                        // Concurrent conflict detected!
                        *self.conflict_count.write().unwrap() += 1;
                        self.resolve_concurrent_conflict(local, &change.metadata)
                    }
                }
            }
        };

        // Apply action to internal ledgers
        match &resolution.action {
            ConflictAction::ApplyRemote => {
                if change.metadata.is_tombstone {
                    ledger.remove(rel_path);
                    tombstones.insert(rel_path.to_string(), change.metadata.clone());
                } else {
                    tombstones.remove(rel_path);
                    ledger.insert(rel_path.to_string(), change.metadata.clone());
                }
            }
            ConflictAction::CreateBranch { branch_path } => {
                // Store branch file in ledger with merged vector clock
                let mut branch_meta = change.metadata.clone();
                branch_meta.rel_path = branch_path.clone();
                ledger.insert(branch_path.clone(), branch_meta);

                // Merge clocks into original item
                if let Some(orig) = ledger.get_mut(rel_path) {
                    orig.vector_clock.merge(&change.metadata.vector_clock);
                }
            }
            ConflictAction::KeepLocal | ConflictAction::Rejected => {
                // Merge vector clocks so both sites acknowledge mutual knowledge
                if let Some(orig) = ledger.get_mut(rel_path) {
                    orig.vector_clock.merge(&change.metadata.vector_clock);
                } else if let Some(t) = tombstones.get_mut(rel_path) {
                    t.vector_clock.merge(&change.metadata.vector_clock);
                }
            }
        }

        Ok(resolution)
    }

    /// Resolve a concurrent conflict according to the active `ConflictPolicy`.
    fn resolve_concurrent_conflict(
        &self,
        local: &GeoItemMetadata,
        remote: &GeoItemMetadata,
    ) -> ConflictResolutionResult {
        match &self.policy {
            ConflictPolicy::LastWriteWins => {
                // Compare wall-clock timestamps
                if remote.physical_time_ms > local.physical_time_ms {
                    ConflictResolutionResult {
                        action: ConflictAction::ApplyRemote,
                        was_conflict: true,
                        details: format!(
                            "Conflict resolved via LWW: Remote ({}) newer than Local ({})",
                            remote.physical_time_ms, local.physical_time_ms
                        ),
                    }
                } else if remote.physical_time_ms < local.physical_time_ms {
                    ConflictResolutionResult {
                        action: ConflictAction::KeepLocal,
                        was_conflict: true,
                        details: format!(
                            "Conflict resolved via LWW: Local ({}) newer than Remote ({})",
                            local.physical_time_ms, remote.physical_time_ms
                        ),
                    }
                } else {
                    // Tie-breaker: lexicographical region comparison
                    if remote.origin_region > local.origin_region {
                        ConflictResolutionResult {
                            action: ConflictAction::ApplyRemote,
                            was_conflict: true,
                            details: "Conflict resolved via LWW tie-breaker: Remote region won"
                                .to_string(),
                        }
                    } else {
                        ConflictResolutionResult {
                            action: ConflictAction::KeepLocal,
                            was_conflict: true,
                            details: "Conflict resolved via LWW tie-breaker: Local region won"
                                .to_string(),
                        }
                    }
                }
            }
            ConflictPolicy::PrimaryAuthority { primary_region } => {
                if remote.origin_region == *primary_region {
                    ConflictResolutionResult {
                        action: ConflictAction::ApplyRemote,
                        was_conflict: true,
                        details: format!(
                            "Conflict resolved via PrimaryAuthority: Remote is primary ({})",
                            primary_region
                        ),
                    }
                } else {
                    ConflictResolutionResult {
                        action: ConflictAction::KeepLocal,
                        was_conflict: true,
                        details: format!(
                            "Conflict resolved via PrimaryAuthority: Local kept over non-primary ({})",
                            remote.origin_region
                        ),
                    }
                }
            }
            ConflictPolicy::KeepBoth => {
                let branch = format!(
                    "{}.conflict-{}-{}",
                    local.rel_path, remote.origin_region, remote.physical_time_ms
                );
                ConflictResolutionResult {
                    action: ConflictAction::CreateBranch {
                        branch_path: branch,
                    },
                    was_conflict: true,
                    details: "Conflict resolved via KeepBoth: remote saved as conflict branch"
                        .to_string(),
                }
            }
            ConflictPolicy::RejectConcurrent => ConflictResolutionResult {
                action: ConflictAction::Rejected,
                was_conflict: true,
                details: "Concurrent modification rejected by policy".to_string(),
            },
        }
    }

    /// Prune tombstones that have exceeded their maximum time-to-live (`ttl_secs`).
    pub fn prune_tombstones(&self, ttl_secs: u64, now_secs: u64) -> usize {
        let mut tombstones = self.tombstones.write().unwrap();
        let before_count = tombstones.len();

        tombstones.retain(|_, meta| {
            let item_secs = meta.physical_time_ms / 1000;
            now_secs.saturating_sub(item_secs) < ttl_secs
        });

        before_count - tombstones.len()
    }

    /// Generate an aggregate status report of the geo-replication cluster.
    pub fn generate_status_report(&self) -> GeoStatusReport {
        let regions_guard = self.regions.read().unwrap();
        let queue_guard = self.queue.read().unwrap();

        let mut regions_list = Vec::new();
        let mut active_count = 0;

        for r in regions_guard.values() {
            let mut desc = r.clone();
            desc.pending_changes = queue_guard.pending_count(&desc.region_id);
            if desc.state == GeoRegionState::Active {
                active_count += 1;
            }
            regions_list.push(desc);
        }

        let policy_str = match &self.policy {
            ConflictPolicy::LastWriteWins => "Last-Write-Wins (LWW)".to_string(),
            ConflictPolicy::PrimaryAuthority { primary_region } => {
                format!("Primary-Authority ({primary_region})")
            }
            ConflictPolicy::KeepBoth => "Keep-Both-Branches".to_string(),
            ConflictPolicy::RejectConcurrent => "Reject-Concurrent".to_string(),
        };

        GeoStatusReport {
            local_region: self.local_region.clone(),
            conflict_policy: policy_str,
            total_regions: regions_guard.len(),
            active_regions: active_count,
            tracked_files: self.ledger.read().unwrap().len(),
            active_tombstones: self.tombstones.read().unwrap().len(),
            pending_outbound_changes: queue_guard.total_pending(),
            total_conflicts_resolved: *self.conflict_count.read().unwrap(),
            regions: regions_list,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_causality_and_concurrency() {
        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();

        vc1.increment("us-east");
        vc2.increment("us-east");
        assert_eq!(vc1.compare(&vc2), ClockOrdering::Equal);

        // vc1 ticks again -> vc1 > vc2
        vc1.increment("us-east");
        assert_eq!(vc1.compare(&vc2), ClockOrdering::Greater);
        assert_eq!(vc2.compare(&vc1), ClockOrdering::Less);

        // vc2 ticks eu-west concurrently -> Concurrent
        vc2.increment("eu-west");
        assert_eq!(vc1.compare(&vc2), ClockOrdering::Concurrent);
        assert_eq!(vc2.compare(&vc1), ClockOrdering::Concurrent);

        // Merge vc1 into vc2 -> vc2 dominates
        vc2.merge(&vc1);
        assert_eq!(vc2.compare(&vc1), ClockOrdering::Greater);
    }

    #[test]
    fn test_geo_coordinator_lww_conflict_resolution() {
        let coord = GeoReplicationCoordinator::new("us-east", ConflictPolicy::LastWriteWins);

        // Local mutation: doc.txt
        let hash1 = Hash::of(b"version 1");
        coord.record_local_mutation("doc.txt", 100, hash1, None);

        // Concurrent remote change from eu-central with older timestamp
        let mut remote_vc = VectorClock::new();
        remote_vc.increment("eu-central");

        let mut remote_meta = GeoItemMetadata::file(
            "doc.txt",
            120,
            Hash::of(b"version 2"),
            remote_vc,
            "eu-central",
        );
        remote_meta.physical_time_ms = 1_000_000; // deliberately older

        let change = ReplicationChange {
            sequence_id: 1,
            metadata: remote_meta,
            payload: None,
        };

        let res = coord.apply_remote_change(&change).unwrap();
        assert!(res.was_conflict);
        assert_eq!(res.action, ConflictAction::KeepLocal);
    }

    #[test]
    fn test_geo_coordinator_keep_both_branches() {
        let coord = GeoReplicationCoordinator::new("us-east", ConflictPolicy::KeepBoth);

        let hash1 = Hash::of(b"branch 1");
        coord.record_local_mutation("config.toml", 50, hash1, None);

        let mut remote_vc = VectorClock::new();
        remote_vc.increment("ap-tokyo");

        let remote_meta = GeoItemMetadata::file(
            "config.toml",
            60,
            Hash::of(b"branch 2"),
            remote_vc,
            "ap-tokyo",
        );

        let change = ReplicationChange {
            sequence_id: 2,
            metadata: remote_meta,
            payload: None,
        };

        let res = coord.apply_remote_change(&change).unwrap();
        assert!(res.was_conflict);
        if let ConflictAction::CreateBranch { branch_path } = res.action {
            assert!(branch_path.starts_with("config.toml.conflict-ap-tokyo-"));
        } else {
            panic!("expected CreateBranch action");
        }
    }

    #[test]
    fn test_geo_coordinator_tombstone_lifecycle() {
        let coord = GeoReplicationCoordinator::new("us-east", ConflictPolicy::LastWriteWins);

        coord.record_local_mutation("obsolete.log", 200, Hash::of(b"log data"), None);
        assert_eq!(coord.generate_status_report().tracked_files, 1);
        assert_eq!(coord.generate_status_report().active_tombstones, 0);

        coord.record_local_deletion("obsolete.log");
        assert_eq!(coord.generate_status_report().tracked_files, 0);
        assert_eq!(coord.generate_status_report().active_tombstones, 1);

        // Pruning with 0 TTL removes it
        let pruned = coord.prune_tombstones(0, 999_999_999_999);
        assert_eq!(pruned, 1);
        assert_eq!(coord.generate_status_report().active_tombstones, 0);
    }
}
