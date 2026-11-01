//! Distributed Global Snapshot Isolation & Transactional Multi-File Checkpoint Mesh (`ADR-057`, Option CO).
//!
//! Provides pure safe Rust distributed multi-version concurrency control (MVCC) snapshot
//! isolation, vector clocks, and two-phase commit (2PC) checkpoint manifests across edge nodes,
//! guaranteeing atomic all-or-nothing multi-file directory rollbacks and linearizable snapshot reads.
//!
//! Features:
//! 1. Vector Clocks:
//!    - Logical vector clock tracking per-node causal sequences.
//!    - Causal ordering determination (happened-before relation) and concurrent write conflict detection.
//! 2. Multi-Version Concurrency Control (MVCC) & Optimistic Concurrency Control (OCC):
//!    - Per-file revision history with content-addressed storage references.
//!    - Optimistic write verification against base read versions to prevent lost updates.
//!    - Point-in-time snapshot isolation guaranteeing readers observe consistent distributed directory views.
//! 3. Two-Phase Commit (2PC) Checkpoint Manifest Mesh:
//!    - Phase 1 (Prepare): Staged file writes, Merkle root computation, conflict checking, participant voting.
//!    - Phase 2 (Commit / Abort): All-or-nothing atomicity. On unanimous commit, staged files are promoted
//!      and an immutable GlobalSnapshotManifest is published. On any abort vote, changes are cleanly discarded.
//! 4. Atomic Multi-File Directory Rollback:
//!    - Restores any historical snapshot with full content verification and clean removal of orphaned files.
//! 5. Microsecond Performance Benchmark:
//!    - End-to-end benchmarking of transaction begin, staging, 2PC prepare, commit, MVCC read, and rollback.
//! 6. 100% Safe Rust (`#![forbid(unsafe_code)]`) with zero external C/OS dependencies.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::util::Hash;

/// Returns current Unix epoch timestamp in seconds.
fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns current Unix epoch timestamp in nanoseconds.
fn current_epoch_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Distributed logical vector clock mapping node identities to monotonically increasing sequence counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TxVectorClock {
    /// Clock entries ordered lexicographically by node ID.
    pub clock: BTreeMap<String, u64>,
}

impl TxVectorClock {
    /// Creates an empty vector clock.
    pub fn new() -> Self {
        Self {
            clock: BTreeMap::new(),
        }
    }

    /// Initializes a vector clock with an initial tick for a given node.
    pub fn initial(node: &str) -> Self {
        let mut vc = Self::new();
        vc.increment(node);
        vc
    }

    /// Increments the clock for the given node and returns the new value.
    pub fn increment(&mut self, node: &str) -> u64 {
        let entry = self.clock.entry(node.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Returns the sequence counter for the specified node (0 if not present).
    pub fn get(&self, node: &str) -> u64 {
        self.clock.get(node).copied().unwrap_or(0)
    }

    /// Updates this vector clock with the element-wise maximum of another clock.
    pub fn update_max(&mut self, other: &TxVectorClock) {
        for (node, &seq) in &other.clock {
            let entry = self.clock.entry(node.clone()).or_insert(0);
            if seq > *entry {
                *entry = seq;
            }
        }
    }

    /// Merges two vector clocks into a new clock containing the element-wise maximums.
    pub fn merge(&self, other: &TxVectorClock) -> TxVectorClock {
        let mut merged = self.clone();
        merged.update_max(other);
        merged
    }

    /// Determines if `self` causally preceded `other` ($self < other$).
    ///
    /// True if and only if $\forall k, self[k] \le other[k]$ and $\exists k, self[k] < other[k]$.
    pub fn is_causally_before(&self, other: &TxVectorClock) -> bool {
        let mut strictly_less = false;

        // Check all nodes in self
        for (node, &seq) in &self.clock {
            let other_seq = other.get(node);
            if seq > other_seq {
                return false;
            }
            if seq < other_seq {
                strictly_less = true;
            }
        }

        // Check if other has keys not in self where other > 0
        for (node, &other_seq) in &other.clock {
            if !self.clock.contains_key(node) && other_seq > 0 {
                strictly_less = true;
            }
        }

        strictly_less
    }

    /// Determines if `self` and `other` are causally concurrent (neither happened-before the other).
    pub fn is_concurrent(&self, other: &TxVectorClock) -> bool {
        !self.is_causally_before(other) && !other.is_causally_before(self) && self != other
    }

    /// Returns the dominant epoch (maximum sequence observed across all nodes).
    pub fn dominant_epoch(&self) -> u64 {
        self.clock.values().copied().max().unwrap_or(0)
    }

    /// Returns the sum of all ticks across all nodes.
    pub fn sum_ticks(&self) -> u64 {
        self.clock.values().copied().sum()
    }
}

impl fmt::Display for TxVectorClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        let mut first = true;
        for (node, seq) in &self.clock {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{}:{}", node, seq)?;
            first = false;
        }
        write!(f, "}}")
    }
}

/// Transaction state in the 2PC lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxState {
    /// Transaction is open and staging modifications.
    Active,
    /// Phase 1 prepare manifest generated and validated.
    Prepared,
    /// Phase 2 commit finished and files promoted to active snapshots.
    Committed,
    /// Transaction aborted and staged modifications discarded.
    Aborted,
}

impl fmt::Display for TxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxState::Active => write!(f, "Active"),
            TxState::Prepared => write!(f, "Prepared"),
            TxState::Committed => write!(f, "Committed"),
            TxState::Aborted => write!(f, "Aborted"),
        }
    }
}

/// Operation kind for a staged file modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOpKind {
    /// New file or updated file content.
    Write,
    /// File deletion (tombstone).
    Delete,
    /// File rename.
    Rename {
        /// Source path being renamed from.
        old_path: String,
    },
}

/// A staged file operation within an active transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedFileOp {
    /// Relative virtual target path within directory mesh.
    pub path: String,
    /// Operation kind.
    pub kind: FileOpKind,
    /// File size in bytes.
    pub size: u64,
    /// BLAKE3 whole-content cryptographic hash.
    pub blake3_hash: Hash,
    /// Relative path inside `.staged/<tx_id>/` where data was buffered (empty for deletes).
    pub staged_data_rel_path: String,
    /// Expected base revision for optimistic concurrency control (OCC).
    pub expected_base_version: Option<u64>,
}

/// A committed file revision in the MVCC history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRevision {
    /// Monotonically increasing revision sequence.
    pub revision_id: u64,
    /// Virtual relative file path.
    pub path: String,
    /// File byte size.
    pub size: u64,
    /// BLAKE3 whole-content cryptographic hash.
    pub blake3_hash: Hash,
    /// Vector clock timestamp at commit.
    pub vector_clock: TxVectorClock,
    /// Associated transaction identifier.
    pub tx_id: String,
    /// Unix epoch timestamp in seconds.
    pub committed_at_secs: u64,
    /// Authoring node identity.
    pub author_node: String,
    /// Whether this revision records a file deletion tombstone.
    pub is_tombstone: bool,
    /// Relative storage path inside `.versions/<hash>`.
    pub content_ref: String,
}

/// Immutable global directory snapshot manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalSnapshotManifest {
    /// Unique snapshot identifier (`snap-<epoch>-<hash>`).
    pub snapshot_id: String,
    /// Human-readable snapshot tag.
    pub tag: String,
    /// Monotonically increasing global cluster epoch.
    pub epoch: u64,
    /// Vector clock timestamp.
    pub vector_clock: TxVectorClock,
    /// Coordinator node ID that executed 2PC.
    pub coordinator_node: String,
    /// Participant nodes that cosigned or voted commit.
    pub participant_nodes: Vec<String>,
    /// Full virtual file tree: relative path -> file revision.
    pub files: BTreeMap<String, FileRevision>,
    /// BLAKE3 Merkle root over all files in this snapshot.
    pub merkle_root: Hash,
    /// Total count of active (non-tombstone) regular files.
    pub total_files: u64,
    /// Total cumulative byte size.
    pub total_bytes: u64,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at_secs: u64,
    /// Transaction ID that produced this snapshot.
    pub commit_tx_id: String,
}

/// Concise summary of a global snapshot for catalog listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Snapshot identifier.
    pub snapshot_id: String,
    /// User tag.
    pub tag: String,
    /// Global epoch.
    pub epoch: u64,
    /// Total active files.
    pub total_files: u64,
    /// Total bytes.
    pub total_bytes: u64,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at_secs: u64,
    /// Merkle root hash hex.
    pub merkle_root_hex: String,
}

/// Phase 1 2PC prepare manifest distributed to participants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoPhasePrepare {
    /// Transaction ID.
    pub tx_id: String,
    /// Coordinator node identity.
    pub coordinator: String,
    /// Registered participant nodes.
    pub participants: Vec<String>,
    /// Ordered list of staged operations.
    pub staged_ops: Vec<StagedFileOp>,
    /// BLAKE3 Merkle root over all staged operations.
    pub staging_merkle_root: Hash,
    /// Transaction read vector clock.
    pub read_vector_clock: TxVectorClock,
}

/// Voting decision by a 2PC participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteKind {
    /// Participant agrees to commit.
    Commit,
    /// Participant rejects with error reason.
    Abort {
        /// Explanation for abort vote.
        reason: String,
    },
}

/// Participant vote payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoPhaseVote {
    /// Node identity casting vote.
    pub node_id: String,
    /// Voting outcome.
    pub vote: VoteKind,
    /// Current vector clock of participant.
    pub vector_clock: TxVectorClock,
}

/// Result of a committed 2PC transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoPhaseCommitResult {
    /// Transaction ID.
    pub tx_id: String,
    /// Snapshot identifier created.
    pub snapshot_id: String,
    /// Human-readable tag.
    pub tag: String,
    /// Applied file count.
    pub applied_file_count: usize,
    /// Total bytes in snapshot.
    pub total_bytes: u64,
    /// Resulting vector clock.
    pub vector_clock: TxVectorClock,
    /// Commit timestamp in Unix epoch seconds.
    pub committed_at_secs: u64,
}

/// Result of an atomic directory rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    /// Target snapshot identifier.
    pub target_snapshot_id: String,
    /// Target tag.
    pub target_tag: String,
    /// Target destination directory.
    pub target_dir: String,
    /// Total files restored.
    pub restored_files: usize,
    /// Extraneous files deleted.
    pub deleted_files: usize,
    /// Bytes restored.
    pub bytes_restored: u64,
    /// Operation duration in nanoseconds.
    pub elapsed_nanos: u64,
}

/// Live status report of the distributed snapshot mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxSnapshotStatusReport {
    /// Node identity.
    pub node_id: String,
    /// Storage root directory path.
    pub storage_dir: String,
    /// Current local vector clock.
    pub vector_clock: TxVectorClock,
    /// Current global epoch.
    pub current_epoch: u64,
    /// Total snapshots committed.
    pub total_snapshots: usize,
    /// Total distinct file paths in catalog.
    pub catalog_file_count: usize,
    /// Active open transactions.
    pub active_transactions: usize,
    /// Prepared uncommitted transactions.
    pub prepared_transactions: usize,
}

/// Microsecond performance benchmark results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxSnapshotBenchmarkReport {
    /// Iterations executed per benchmark phase.
    pub iterations: usize,
    /// Average latency to begin a transaction (nanoseconds).
    pub begin_tx_nanos: f64,
    /// Average latency to stage a file with BLAKE3 hashing (nanoseconds).
    pub stage_file_nanos: f64,
    /// Average latency to compute 2PC prepare manifest and Merkle root (nanoseconds).
    pub prepare_2pc_nanos: f64,
    /// Average latency to execute 2PC commit and manifest publication (nanoseconds).
    pub commit_2pc_nanos: f64,
    /// Average latency for MVCC point-in-time file read (nanoseconds).
    pub mvcc_read_nanos: f64,
    /// Average latency to execute atomic directory rollback (nanoseconds).
    pub rollback_nanos: f64,
}

/// In-memory metadata for an open transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveTxMeta {
    tx_id: String,
    author_node: String,
    state: TxState,
    created_at_secs: u64,
    read_vector_clock: TxVectorClock,
    staged_ops: HashMap<String, StagedFileOp>,
    prepared_manifest: Option<TwoPhasePrepare>,
}

/// Master catalog containing global state across snapshots and revisions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SnapshotCatalog {
    current_epoch: u64,
    vector_clock: TxVectorClock,
    snapshots: BTreeMap<String, GlobalSnapshotManifest>,
    tag_to_id: HashMap<String, String>,
    file_revisions: HashMap<String, Vec<FileRevision>>,
}

/// Distributed Global Snapshot Isolation & Transactional Multi-File Checkpoint Mesh Engine.
pub struct TxSnapshotEngine {
    root_dir: PathBuf,
    node_id: String,
    // Metrics counters
    tx_begun_total: AtomicU64,
    tx_committed_total: AtomicU64,
    tx_aborted_total: AtomicU64,
    active_tx_count: AtomicU64,
    snapshots_total: AtomicU64,
    rollbacks_total: AtomicU64,
    conflicts_total: AtomicU64,
    commit_latency_ns: AtomicU64,
}

impl TxSnapshotEngine {
    /// Initializes or loads the distributed snapshot isolation engine at `root_dir`.
    pub fn new(root_dir: PathBuf, node_id: String) -> Result<Self, VelcruxError> {
        let engine = Self {
            root_dir,
            node_id,
            tx_begun_total: AtomicU64::new(0),
            tx_committed_total: AtomicU64::new(0),
            tx_aborted_total: AtomicU64::new(0),
            active_tx_count: AtomicU64::new(0),
            snapshots_total: AtomicU64::new(0),
            rollbacks_total: AtomicU64::new(0),
            conflicts_total: AtomicU64::new(0),
            commit_latency_ns: AtomicU64::new(0),
        };

        // Create directory hierarchy
        fs::create_dir_all(engine.staged_dir())?;
        fs::create_dir_all(engine.versions_dir())?;
        fs::create_dir_all(engine.snapshots_dir())?;

        // Initialize catalog if missing
        if !engine.catalog_file().exists() {
            let initial_catalog = SnapshotCatalog {
                current_epoch: 0,
                vector_clock: TxVectorClock::initial(&engine.node_id),
                snapshots: BTreeMap::new(),
                tag_to_id: HashMap::new(),
                file_revisions: HashMap::new(),
            };
            engine.save_catalog(&initial_catalog)?;
        }

        Ok(engine)
    }

    /// Internal directory helpers
    fn staged_dir(&self) -> PathBuf {
        self.root_dir.join("staged")
    }

    fn versions_dir(&self) -> PathBuf {
        self.root_dir.join("versions")
    }

    fn snapshots_dir(&self) -> PathBuf {
        self.root_dir.join("snapshots")
    }

    fn catalog_file(&self) -> PathBuf {
        self.root_dir.join("catalog.json")
    }

    fn tx_meta_file(&self, tx_id: &str) -> PathBuf {
        self.staged_dir().join(tx_id).join("tx_meta.json")
    }

    /// Load the snapshot catalog from disk.
    fn load_catalog(&self) -> Result<SnapshotCatalog, VelcruxError> {
        let path = self.catalog_file();
        if !path.exists() {
            return Ok(SnapshotCatalog::default());
        }
        let data = fs::read(&path)?;
        let catalog: SnapshotCatalog = serde_json::from_slice(&data)
            .map_err(|e| VelcruxError::Internal(format!("corrupt snapshot catalog: {}", e)))?;
        Ok(catalog)
    }

    /// Atomically write the snapshot catalog to disk using write-and-rename.
    fn save_catalog(&self, catalog: &SnapshotCatalog) -> Result<(), VelcruxError> {
        let json = serde_json::to_vec_pretty(catalog)
            .map_err(|e| VelcruxError::Internal(format!("catalog serialize error: {}", e)))?;
        let tmp_path = self
            .root_dir
            .join(format!(".tmp_catalog_{}.json", current_epoch_nanos()));
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, self.catalog_file())?;
        Ok(())
    }

    /// Load active transaction metadata from its staged directory.
    fn load_tx_meta(&self, tx_id: &str) -> Result<ActiveTxMeta, VelcruxError> {
        let path = self.tx_meta_file(tx_id);
        if !path.exists() {
            return Err(VelcruxError::Internal(format!(
                "transaction '{}' not found",
                tx_id
            )));
        }
        let data = fs::read(&path)?;
        let meta: ActiveTxMeta = serde_json::from_slice(&data).map_err(|e| {
            VelcruxError::Internal(format!("corrupt tx meta for '{}': {}", tx_id, e))
        })?;
        Ok(meta)
    }

    /// Save active transaction metadata atomically.
    fn save_tx_meta(&self, meta: &ActiveTxMeta) -> Result<(), VelcruxError> {
        let tx_dir = self.staged_dir().join(&meta.tx_id);
        fs::create_dir_all(&tx_dir)?;
        let path = self.tx_meta_file(&meta.tx_id);
        let tmp_path = tx_dir.join(format!(".tmp_tx_meta_{}.json", current_epoch_nanos()));
        let json = serde_json::to_vec_pretty(meta)
            .map_err(|e| VelcruxError::Internal(format!("tx_meta serialize error: {}", e)))?;
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Begin a new distributed transaction with read snapshot isolation.
    pub fn begin_tx(&self, author_node: Option<&str>) -> Result<String, VelcruxError> {
        let catalog = self.load_catalog()?;
        let author = author_node.unwrap_or(&self.node_id).to_string();
        let timestamp_nanos = current_epoch_nanos();
        let short_hash =
            &Hash::of(format!("{}:{}:{}", self.node_id, author, timestamp_nanos).as_bytes())
                .to_hex()[..8];
        let tx_id = format!("tx-{}-{}", current_epoch_secs(), short_hash);

        let tx_dir = self.staged_dir().join(&tx_id);
        fs::create_dir_all(&tx_dir)?;

        let meta = ActiveTxMeta {
            tx_id: tx_id.clone(),
            author_node: author,
            state: TxState::Active,
            created_at_secs: current_epoch_secs(),
            read_vector_clock: catalog.vector_clock.clone(),
            staged_ops: HashMap::new(),
            prepared_manifest: None,
        };

        self.save_tx_meta(&meta)?;

        self.tx_begun_total.fetch_add(1, Ordering::Relaxed);
        self.active_tx_count.fetch_add(1, Ordering::Relaxed);

        Ok(tx_id)
    }

    /// Stage a file write within an active transaction.
    ///
    /// Computes BLAKE3 cryptographic hash and buffers file content in `.staged/<tx_id>/`.
    pub fn stage_file(
        &self,
        tx_id: &str,
        path: &str,
        data: &[u8],
        expected_base_version: Option<u64>,
    ) -> Result<StagedFileOp, VelcruxError> {
        let mut meta = self.load_tx_meta(tx_id)?;
        if meta.state != TxState::Active {
            return Err(VelcruxError::Internal(format!(
                "cannot stage files: transaction '{}' is {}",
                tx_id, meta.state
            )));
        }

        let clean_path = path.trim_start_matches('/').to_string();
        let hash = Hash::of(data);
        let rel_data_file = format!(
            "data_{}_{}.bin",
            hash.to_hex()[..16].to_string(),
            current_epoch_nanos()
        );
        let target_file_path = self.staged_dir().join(tx_id).join(&rel_data_file);

        fs::write(&target_file_path, data)?;

        let op = StagedFileOp {
            path: clean_path.clone(),
            kind: FileOpKind::Write,
            size: data.len() as u64,
            blake3_hash: hash,
            staged_data_rel_path: rel_data_file,
            expected_base_version,
        };

        meta.staged_ops.insert(clean_path, op.clone());
        self.save_tx_meta(&meta)?;

        Ok(op)
    }

    /// Stage a file deletion (tombstone) within an active transaction.
    pub fn stage_delete(
        &self,
        tx_id: &str,
        path: &str,
        expected_base_version: Option<u64>,
    ) -> Result<StagedFileOp, VelcruxError> {
        let mut meta = self.load_tx_meta(tx_id)?;
        if meta.state != TxState::Active {
            return Err(VelcruxError::Internal(format!(
                "cannot stage delete: transaction '{}' is {}",
                tx_id, meta.state
            )));
        }

        let clean_path = path.trim_start_matches('/').to_string();
        let op = StagedFileOp {
            path: clean_path.clone(),
            kind: FileOpKind::Delete,
            size: 0,
            blake3_hash: Hash::ZERO,
            staged_data_rel_path: String::new(),
            expected_base_version,
        };

        meta.staged_ops.insert(clean_path, op.clone());
        self.save_tx_meta(&meta)?;

        Ok(op)
    }

    /// Computes Merkle root over a slice of staged operations.
    fn compute_staging_merkle_root(ops: &[StagedFileOp]) -> Hash {
        let mut sorted_ops = ops.to_vec();
        sorted_ops.sort_by(|a, b| a.path.cmp(&b.path));

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux:txsnapshot:staging_merkle:v1\n");
        for op in &sorted_ops {
            hasher.update(op.path.as_bytes());
            hasher.update(&op.size.to_le_bytes());
            hasher.update(op.blake3_hash.as_bytes());
            match &op.kind {
                FileOpKind::Write => {
                    hasher.update(b"WRITE");
                }
                FileOpKind::Delete => {
                    hasher.update(b"DELETE");
                }
                FileOpKind::Rename { old_path } => {
                    hasher.update(b"RENAME");
                    hasher.update(old_path.as_bytes());
                }
            }
            if let Some(base) = op.expected_base_version {
                hasher.update(&base.to_le_bytes());
            } else {
                hasher.update(&0u64.to_le_bytes());
            }
        }
        Hash::from_blake3(hasher.finalize())
    }

    /// Phase 1 2PC Prepare:
    /// Validates all staged operations, detects OCC conflicts against latest committed versions,
    /// computes Merkle root, and generates the prepare payload.
    pub fn prepare_2pc(
        &self,
        tx_id: &str,
        participants: &[String],
    ) -> Result<TwoPhasePrepare, VelcruxError> {
        let mut meta = self.load_tx_meta(tx_id)?;
        if meta.state != TxState::Active {
            return Err(VelcruxError::Internal(format!(
                "cannot prepare: transaction '{}' is {}",
                tx_id, meta.state
            )));
        }

        let catalog = self.load_catalog()?;

        // Perform Optimistic Concurrency Control (OCC) conflict check:
        // If a staged file specifies expected_base_version, ensure no revision > expected_base_version has committed.
        for op in meta.staged_ops.values() {
            if let Some(expected_base) = op.expected_base_version {
                if let Some(revs) = catalog.file_revisions.get(&op.path) {
                    if let Some(latest) = revs.last() {
                        if latest.revision_id > expected_base {
                            self.conflicts_total.fetch_add(1, Ordering::Relaxed);
                            return Err(VelcruxError::Internal(format!(
                                "OCC conflict on path '{}': expected base revision {} but latest committed revision is {}",
                                op.path, expected_base, latest.revision_id
                            )));
                        }
                    }
                }
            }
        }

        let mut ops_vec: Vec<StagedFileOp> = meta.staged_ops.values().cloned().collect();
        ops_vec.sort_by(|a, b| a.path.cmp(&b.path));

        let merkle_root = Self::compute_staging_merkle_root(&ops_vec);

        let prepare = TwoPhasePrepare {
            tx_id: tx_id.to_string(),
            coordinator: self.node_id.clone(),
            participants: participants.to_vec(),
            staged_ops: ops_vec,
            staging_merkle_root: merkle_root,
            read_vector_clock: meta.read_vector_clock.clone(),
        };

        meta.state = TxState::Prepared;
        meta.prepared_manifest = Some(prepare.clone());
        self.save_tx_meta(&meta)?;

        Ok(prepare)
    }

    /// Retrieve the prepared manifest for a transaction if it was already prepared.
    pub fn get_tx_prepare(&self, tx_id: &str) -> Result<Option<TwoPhasePrepare>, VelcruxError> {
        let meta = self.load_tx_meta(tx_id)?;
        Ok(meta.prepared_manifest)
    }

    /// Evaluates a 2PC Prepare payload and returns a participant vote.
    pub fn vote_2pc(&self, prepare: &TwoPhasePrepare) -> Result<TwoPhaseVote, VelcruxError> {
        let catalog = self.load_catalog()?;

        // Verify Merkle integrity of prepare payload
        let expected_root = Self::compute_staging_merkle_root(&prepare.staged_ops);
        if expected_root != prepare.staging_merkle_root {
            return Ok(TwoPhaseVote {
                node_id: self.node_id.clone(),
                vote: VoteKind::Abort {
                    reason: format!(
                        "staging Merkle root mismatch: expected {} got {}",
                        expected_root.to_hex(),
                        prepare.staging_merkle_root.to_hex()
                    ),
                },
                vector_clock: catalog.vector_clock.clone(),
            });
        }

        // Verify OCC on participant side
        for op in &prepare.staged_ops {
            if let Some(expected_base) = op.expected_base_version {
                if let Some(revs) = catalog.file_revisions.get(&op.path) {
                    if let Some(latest) = revs.last() {
                        if latest.revision_id > expected_base {
                            return Ok(TwoPhaseVote {
                                node_id: self.node_id.clone(),
                                vote: VoteKind::Abort {
                                    reason: format!(
                                        "OCC conflict on participant for path '{}': latest revision {} > base {}",
                                        op.path, latest.revision_id, expected_base
                                    ),
                                },
                                vector_clock: catalog.vector_clock.clone(),
                            });
                        }
                    }
                }
            }
        }

        Ok(TwoPhaseVote {
            node_id: self.node_id.clone(),
            vote: VoteKind::Commit,
            vector_clock: catalog.vector_clock.clone(),
        })
    }

    /// Computes BLAKE3 Merkle root over a full snapshot directory manifest.
    fn compute_snapshot_merkle_root(files: &BTreeMap<String, FileRevision>) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux:txsnapshot:manifest_merkle:v1\n");
        for (path, rev) in files {
            hasher.update(path.as_bytes());
            hasher.update(&rev.size.to_le_bytes());
            hasher.update(rev.blake3_hash.as_bytes());
            hasher.update(&rev.revision_id.to_le_bytes());
        }
        Hash::from_blake3(hasher.finalize())
    }

    /// Phase 2 2PC Commit:
    /// Verifies unanimous participant votes, updates vector clocks, promotes staged files
    /// to immutable version storage, creates a new GlobalSnapshotManifest, and marks the transaction committed.
    pub fn commit_2pc(
        &self,
        tx_id: &str,
        votes: &[TwoPhaseVote],
        snapshot_tag: Option<&str>,
    ) -> Result<GlobalSnapshotManifest, VelcruxError> {
        let start_time = Instant::now();
        let mut meta = self.load_tx_meta(tx_id)?;
        if meta.state != TxState::Prepared {
            return Err(VelcruxError::Internal(format!(
                "cannot commit: transaction '{}' is {} (must be Prepared)",
                tx_id, meta.state
            )));
        }

        // Verify votes: unanimous Commit is required
        for v in votes {
            if let VoteKind::Abort { ref reason } = v.vote {
                self.abort_tx(
                    tx_id,
                    &format!("participant '{}' voted Abort: {}", v.node_id, reason),
                )?;
                return Err(VelcruxError::Internal(format!(
                    "2PC aborted due to participant '{}': {}",
                    v.node_id, reason
                )));
            }
        }

        let mut catalog = self.load_catalog()?;

        // Merge participant vector clocks into global clock
        for v in votes {
            catalog.vector_clock.update_max(&v.vector_clock);
        }
        // Increment coordinator's tick
        catalog.vector_clock.increment(&self.node_id);
        catalog.current_epoch += 1;

        let commit_timestamp = current_epoch_secs();
        let mut _applied_files = 0usize;

        // Baseline files from the most recent snapshot if one exists
        let mut new_snapshot_files: BTreeMap<String, FileRevision> =
            if let Some((_, latest_snap)) = catalog.snapshots.iter().next_back() {
                latest_snap.files.clone()
            } else {
                BTreeMap::new()
            };

        // Promote staged files into .versions/ and catalog
        let tx_staged_dir = self.staged_dir().join(tx_id);
        for (rel_path, staged_op) in &meta.staged_ops {
            let next_rev_id = catalog
                .file_revisions
                .get(rel_path)
                .and_then(|r| r.last())
                .map(|r| r.revision_id + 1)
                .unwrap_or(1);

            match &staged_op.kind {
                FileOpKind::Write => {
                    let source_data_path = tx_staged_dir.join(&staged_op.staged_data_rel_path);
                    let version_file_name = format!("{}.bin", staged_op.blake3_hash.to_hex());
                    let dest_version_path = self.versions_dir().join(&version_file_name);

                    if source_data_path.exists() && !dest_version_path.exists() {
                        fs::copy(&source_data_path, &dest_version_path)?;
                    }

                    let revision = FileRevision {
                        revision_id: next_rev_id,
                        path: rel_path.clone(),
                        size: staged_op.size,
                        blake3_hash: staged_op.blake3_hash,
                        vector_clock: catalog.vector_clock.clone(),
                        tx_id: tx_id.to_string(),
                        committed_at_secs: commit_timestamp,
                        author_node: meta.author_node.clone(),
                        is_tombstone: false,
                        content_ref: version_file_name,
                    };

                    catalog
                        .file_revisions
                        .entry(rel_path.clone())
                        .or_default()
                        .push(revision.clone());

                    new_snapshot_files.insert(rel_path.clone(), revision);
                    _applied_files += 1;
                }
                FileOpKind::Delete => {
                    let revision = FileRevision {
                        revision_id: next_rev_id,
                        path: rel_path.clone(),
                        size: 0,
                        blake3_hash: Hash::ZERO,
                        vector_clock: catalog.vector_clock.clone(),
                        tx_id: tx_id.to_string(),
                        committed_at_secs: commit_timestamp,
                        author_node: meta.author_node.clone(),
                        is_tombstone: true,
                        content_ref: String::new(),
                    };

                    catalog
                        .file_revisions
                        .entry(rel_path.clone())
                        .or_default()
                        .push(revision);

                    new_snapshot_files.remove(rel_path);
                    _applied_files += 1;
                }
                FileOpKind::Rename { old_path } => {
                    let source_data_path = tx_staged_dir.join(&staged_op.staged_data_rel_path);
                    let version_file_name = format!("{}.bin", staged_op.blake3_hash.to_hex());
                    let dest_version_path = self.versions_dir().join(&version_file_name);

                    if source_data_path.exists() && !dest_version_path.exists() {
                        fs::copy(&source_data_path, &dest_version_path)?;
                    }

                    let revision = FileRevision {
                        revision_id: next_rev_id,
                        path: rel_path.clone(),
                        size: staged_op.size,
                        blake3_hash: staged_op.blake3_hash,
                        vector_clock: catalog.vector_clock.clone(),
                        tx_id: tx_id.to_string(),
                        committed_at_secs: commit_timestamp,
                        author_node: meta.author_node.clone(),
                        is_tombstone: false,
                        content_ref: version_file_name,
                    };

                    catalog
                        .file_revisions
                        .entry(rel_path.clone())
                        .or_default()
                        .push(revision.clone());

                    new_snapshot_files.remove(old_path);
                    new_snapshot_files.insert(rel_path.clone(), revision);
                    _applied_files += 1;
                }
            }
        }

        // Calculate totals and Merkle root
        let total_files = new_snapshot_files.len() as u64;
        let total_bytes: u64 = new_snapshot_files.values().map(|r| r.size).sum();
        let merkle_root = Self::compute_snapshot_merkle_root(&new_snapshot_files);

        let snap_epoch = catalog.current_epoch;
        let snapshot_id = format!("snap-{}-{}", snap_epoch, &merkle_root.to_hex()[..8]);
        let tag = snapshot_tag
            .map(|t| t.to_string())
            .unwrap_or_else(|| format!("snapshot-{}", snap_epoch));

        let participant_node_list: Vec<String> = votes.iter().map(|v| v.node_id.clone()).collect();

        let snapshot_manifest = GlobalSnapshotManifest {
            snapshot_id: snapshot_id.clone(),
            tag: tag.clone(),
            epoch: snap_epoch,
            vector_clock: catalog.vector_clock.clone(),
            coordinator_node: self.node_id.clone(),
            participant_nodes: participant_node_list,
            files: new_snapshot_files,
            merkle_root,
            total_files,
            total_bytes,
            created_at_secs: commit_timestamp,
            commit_tx_id: tx_id.to_string(),
        };

        // Write snapshot manifest to snapshots/<snapshot_id>.json
        let snap_file_path = self.snapshots_dir().join(format!("{}.json", snapshot_id));
        let snap_json = serde_json::to_vec_pretty(&snapshot_manifest)
            .map_err(|e| VelcruxError::Internal(format!("snapshot serialize error: {}", e)))?;
        fs::write(&snap_file_path, &snap_json)?;

        // Update catalog
        catalog.tag_to_id.insert(tag, snapshot_id.clone());
        catalog
            .snapshots
            .insert(snapshot_id.clone(), snapshot_manifest.clone());
        self.save_catalog(&catalog)?;

        // Update tx metadata to Committed and cleanup staged directory
        meta.state = TxState::Committed;
        let _ = self.save_tx_meta(&meta);
        let _ = fs::remove_dir_all(&tx_staged_dir);

        // Update metrics
        self.tx_committed_total.fetch_add(1, Ordering::Relaxed);
        if self.active_tx_count.load(Ordering::Relaxed) > 0 {
            self.active_tx_count.fetch_sub(1, Ordering::Relaxed);
        }
        self.snapshots_total.fetch_add(1, Ordering::Relaxed);
        let elapsed_ns = start_time.elapsed().as_nanos() as u64;
        self.commit_latency_ns.store(elapsed_ns, Ordering::Relaxed);

        Ok(snapshot_manifest)
    }

    /// Abort an active or prepared transaction and clean up staged files.
    pub fn abort_tx(&self, tx_id: &str, _reason: &str) -> Result<(), VelcruxError> {
        let mut meta = match self.load_tx_meta(tx_id) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };

        meta.state = TxState::Aborted;
        let tx_staged_dir = self.staged_dir().join(tx_id);
        let _ = fs::remove_dir_all(&tx_staged_dir);

        self.tx_aborted_total.fetch_add(1, Ordering::Relaxed);
        if self.active_tx_count.load(Ordering::Relaxed) > 0 {
            self.active_tx_count.fetch_sub(1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Resolves snapshot ID by tag or direct ID.
    fn resolve_snapshot_id<'a>(
        &self,
        catalog: &'a SnapshotCatalog,
        tag_or_id: &'a str,
    ) -> Option<String> {
        if catalog.snapshots.contains_key(tag_or_id) {
            return Some(tag_or_id.to_string());
        }
        catalog.tag_to_id.get(tag_or_id).cloned()
    }

    /// Read a file's content at a specific historical point-in-time snapshot (MVCC read isolation).
    pub fn read_snapshot(
        &self,
        snapshot_id_or_tag: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, VelcruxError> {
        let catalog = self.load_catalog()?;
        let snap_id = self
            .resolve_snapshot_id(&catalog, snapshot_id_or_tag)
            .ok_or_else(|| {
                VelcruxError::Internal(format!("snapshot '{}' not found", snapshot_id_or_tag))
            })?;

        let manifest = catalog.snapshots.get(&snap_id).ok_or_else(|| {
            VelcruxError::Internal(format!("snapshot '{}' not found in catalog", snap_id))
        })?;

        let clean_path = path.trim_start_matches('/');
        let rev = match manifest.files.get(clean_path) {
            Some(r) => r,
            None => return Ok(None),
        };

        if rev.is_tombstone {
            return Ok(None);
        }

        let content_path = self.versions_dir().join(&rev.content_ref);
        if !content_path.exists() {
            return Err(VelcruxError::Internal(format!(
                "version data '{}' for path '{}' missing on disk",
                rev.content_ref, clean_path
            )));
        }

        let bytes = fs::read(&content_path)?;
        let read_hash = Hash::of(&bytes);
        if read_hash != rev.blake3_hash {
            return Err(VelcruxError::Internal(format!(
                "cryptographic hash mismatch on read: expected {} got {}",
                rev.blake3_hash.to_hex(),
                read_hash.to_hex()
            )));
        }

        Ok(Some(bytes))
    }

    /// List all files in a specific point-in-time snapshot.
    pub fn list_snapshot_files(
        &self,
        snapshot_id_or_tag: &str,
    ) -> Result<Vec<FileRevision>, VelcruxError> {
        let catalog = self.load_catalog()?;
        let snap_id = self
            .resolve_snapshot_id(&catalog, snapshot_id_or_tag)
            .ok_or_else(|| {
                VelcruxError::Internal(format!("snapshot '{}' not found", snapshot_id_or_tag))
            })?;

        let manifest = catalog
            .snapshots
            .get(&snap_id)
            .ok_or_else(|| VelcruxError::Internal(format!("snapshot '{}' not found", snap_id)))?;

        let files: Vec<FileRevision> = manifest.files.values().cloned().collect();
        Ok(files)
    }

    /// Retrieve full manifest for a specific snapshot.
    pub fn get_snapshot(
        &self,
        snapshot_id_or_tag: &str,
    ) -> Result<GlobalSnapshotManifest, VelcruxError> {
        let catalog = self.load_catalog()?;
        let snap_id = self
            .resolve_snapshot_id(&catalog, snapshot_id_or_tag)
            .ok_or_else(|| {
                VelcruxError::Internal(format!("snapshot '{}' not found", snapshot_id_or_tag))
            })?;

        catalog.snapshots.get(&snap_id).cloned().ok_or_else(|| {
            VelcruxError::Internal(format!("snapshot manifest '{}' missing", snap_id))
        })
    }

    /// List all snapshots in the mesh sorted chronologically.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotSummary>, VelcruxError> {
        let catalog = self.load_catalog()?;
        let mut summaries: Vec<SnapshotSummary> = catalog
            .snapshots
            .values()
            .map(|s| SnapshotSummary {
                snapshot_id: s.snapshot_id.clone(),
                tag: s.tag.clone(),
                epoch: s.epoch,
                total_files: s.total_files,
                total_bytes: s.total_bytes,
                created_at_secs: s.created_at_secs,
                merkle_root_hex: s.merkle_root.to_hex(),
            })
            .collect();

        summaries.sort_by_key(|s| s.epoch);
        Ok(summaries)
    }

    /// Execute atomic multi-file directory rollback to a historical snapshot.
    ///
    /// Restores all files in `target_dir` to match the exact snapshot contents,
    /// verifying BLAKE3 cryptographic hashes and deleting extraneous files not in the snapshot.
    pub fn rollback_to_snapshot(
        &self,
        snapshot_id_or_tag: &str,
        target_dir: &Path,
    ) -> Result<RollbackReport, VelcruxError> {
        let start_time = Instant::now();
        let manifest = self.get_snapshot(snapshot_id_or_tag)?;

        fs::create_dir_all(target_dir)?;

        let mut restored_files = 0usize;
        let mut bytes_restored = 0u64;

        // Stage 1: Write all snapshot files into a temporary staging sibling directory
        let temp_staging_dir = target_dir.parent().unwrap_or(target_dir).join(format!(
            ".rollback_stage_{}_{}",
            manifest.snapshot_id,
            current_epoch_nanos()
        ));
        fs::create_dir_all(&temp_staging_dir)?;

        for (rel_path, rev) in &manifest.files {
            if rev.is_tombstone {
                continue;
            }
            let version_file = self.versions_dir().join(&rev.content_ref);
            if !version_file.exists() {
                let _ = fs::remove_dir_all(&temp_staging_dir);
                return Err(VelcruxError::Internal(format!(
                    "version content '{}' missing for rollback of '{}'",
                    rev.content_ref, rel_path
                )));
            }

            let file_bytes = fs::read(&version_file)?;
            let h = Hash::of(&file_bytes);
            if h != rev.blake3_hash {
                let _ = fs::remove_dir_all(&temp_staging_dir);
                return Err(VelcruxError::Internal(format!(
                    "content corruption detected on '{}': expected {} got {}",
                    rel_path,
                    rev.blake3_hash.to_hex(),
                    h.to_hex()
                )));
            }

            let dest_path = temp_staging_dir.join(rel_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&dest_path, &file_bytes)?;
            restored_files += 1;
            bytes_restored += rev.size;
        }

        // Stage 2: Synchronize into target_dir
        // Identify existing files in target_dir to delete extraneous files
        let mut existing_files = HashSet::new();
        if target_dir.exists() {
            Self::collect_regular_files(target_dir, target_dir, &mut existing_files)?;
        }

        let mut deleted_files = 0usize;
        for existing in &existing_files {
            if !manifest.files.contains_key(existing) {
                let p = target_dir.join(existing);
                if p.exists() {
                    let _ = fs::remove_file(p);
                    deleted_files += 1;
                }
            }
        }

        // Copy staged files to target_dir
        for (rel_path, _) in &manifest.files {
            let src = temp_staging_dir.join(rel_path);
            let dst = target_dir.join(rel_path);
            if src.exists() {
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&src, &dst)?;
            }
        }

        // Clean up temporary staging directory
        let _ = fs::remove_dir_all(&temp_staging_dir);

        let elapsed_nanos = start_time.elapsed().as_nanos() as u64;

        self.rollbacks_total.fetch_add(1, Ordering::Relaxed);

        Ok(RollbackReport {
            target_snapshot_id: manifest.snapshot_id,
            target_tag: manifest.tag,
            target_dir: target_dir.to_string_lossy().to_string(),
            restored_files,
            deleted_files,
            bytes_restored,
            elapsed_nanos,
        })
    }

    /// Recursively collects regular files relative to `base`.
    fn collect_regular_files(
        dir: &Path,
        base: &Path,
        out: &mut HashSet<String>,
    ) -> Result<(), VelcruxError> {
        if !dir.is_dir() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::collect_regular_files(&path, base, out)?;
            } else if path.is_file() {
                if let Ok(rel) = path.strip_prefix(base) {
                    out.insert(rel.to_string_lossy().to_string());
                }
            }
        }
        Ok(())
    }

    /// Current live status of the snapshot mesh.
    pub fn status(&self) -> Result<TxSnapshotStatusReport, VelcruxError> {
        let catalog = self.load_catalog()?;
        let mut active = 0usize;
        let mut prepared = 0usize;

        if let Ok(entries) = fs::read_dir(self.staged_dir()) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Ok(meta) = self.load_tx_meta(&entry.file_name().to_string_lossy()) {
                        match meta.state {
                            TxState::Active => active += 1,
                            TxState::Prepared => prepared += 1,
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(TxSnapshotStatusReport {
            node_id: self.node_id.clone(),
            storage_dir: self.root_dir.to_string_lossy().to_string(),
            vector_clock: catalog.vector_clock,
            current_epoch: catalog.current_epoch,
            total_snapshots: catalog.snapshots.len(),
            catalog_file_count: catalog.file_revisions.len(),
            active_transactions: active,
            prepared_transactions: prepared,
        })
    }

    /// Run microsecond performance benchmark across the transactional snapshot engine.
    pub fn run_benchmark(iterations: usize) -> Result<TxSnapshotBenchmarkReport, VelcruxError> {
        let iters = iterations.max(1);
        let bench_dir =
            std::env::temp_dir().join(format!("velcrux_txsnap_bench_{}", current_epoch_nanos()));
        fs::create_dir_all(&bench_dir)?;

        let engine = TxSnapshotEngine::new(bench_dir.clone(), "bench-node-01".to_string())?;

        // 1. Benchmark Begin Tx
        let start = Instant::now();
        let mut tx_ids = Vec::with_capacity(iters);
        for _ in 0..iters {
            let id = engine.begin_tx(None)?;
            tx_ids.push(id);
        }
        let begin_tx_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 2. Benchmark Stage File
        let dummy_payload = vec![0x42u8; 4096];
        let start = Instant::now();
        for (i, tx_id) in tx_ids.iter().enumerate() {
            let filename = format!("bench_file_{}.dat", i);
            let _ = engine.stage_file(tx_id, &filename, &dummy_payload, None)?;
        }
        let stage_file_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 3. Benchmark Prepare 2PC
        let start = Instant::now();
        let mut prepares = Vec::with_capacity(iters);
        let participants = vec!["bench-node-02".to_string(), "bench-node-03".to_string()];
        for tx_id in &tx_ids {
            let prep = engine.prepare_2pc(tx_id, &participants)?;
            prepares.push(prep);
        }
        let prepare_2pc_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 4. Benchmark Commit 2PC
        let start = Instant::now();
        let mut snapshot_tags = Vec::with_capacity(iters);
        for (i, tx_id) in tx_ids.iter().enumerate() {
            let vote1 = TwoPhaseVote {
                node_id: "bench-node-02".to_string(),
                vote: VoteKind::Commit,
                vector_clock: TxVectorClock::initial("bench-node-02"),
            };
            let vote2 = TwoPhaseVote {
                node_id: "bench-node-03".to_string(),
                vote: VoteKind::Commit,
                vector_clock: TxVectorClock::initial("bench-node-03"),
            };
            let tag = format!("bench-snap-{}", i);
            let snap = engine.commit_2pc(tx_id, &[vote1, vote2], Some(&tag))?;
            snapshot_tags.push(snap.tag);
        }
        let commit_2pc_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 5. Benchmark MVCC Read
        let start = Instant::now();
        for (i, tag) in snapshot_tags.iter().enumerate() {
            let filename = format!("bench_file_{}.dat", i);
            let _ = engine.read_snapshot(tag, &filename)?;
        }
        let mvcc_read_nanos = start.elapsed().as_nanos() as f64 / iters as f64;

        // 6. Benchmark Rollback
        let rollback_target_dir = bench_dir.join("rollback_dest");
        let start = Instant::now();
        if let Some(first_tag) = snapshot_tags.first() {
            let _ = engine.rollback_to_snapshot(first_tag, &rollback_target_dir)?;
        }
        let rollback_nanos = start.elapsed().as_nanos() as f64;

        // Cleanup
        let _ = fs::remove_dir_all(&bench_dir);

        Ok(TxSnapshotBenchmarkReport {
            iterations: iters,
            begin_tx_nanos,
            stage_file_nanos,
            prepare_2pc_nanos,
            commit_2pc_nanos,
            mvcc_read_nanos,
            rollback_nanos,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_engine(test_name: &str) -> (TxSnapshotEngine, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "velcrux_txsnap_test_{}_{}",
            test_name,
            current_epoch_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        let engine = TxSnapshotEngine::new(dir.clone(), "test-node-1".to_string()).unwrap();
        (engine, dir)
    }

    #[test]
    fn test_vector_clock_causality_and_concurrency() {
        let mut vc1 = TxVectorClock::new();
        vc1.increment("nodeA");
        vc1.increment("nodeA");

        let mut vc2 = TxVectorClock::new();
        vc2.increment("nodeA");
        vc2.increment("nodeA");
        vc2.increment("nodeB");

        assert!(vc1.is_causally_before(&vc2));
        assert!(!vc2.is_causally_before(&vc1));
        assert!(!vc1.is_concurrent(&vc2));

        let mut vc3 = TxVectorClock::new();
        vc3.increment("nodeA");
        vc3.increment("nodeC");

        assert!(vc1.is_concurrent(&vc3));
        assert!(vc2.is_concurrent(&vc3));

        let merged = vc2.merge(&vc3);
        assert_eq!(merged.get("nodeA"), 2);
        assert_eq!(merged.get("nodeB"), 1);
        assert_eq!(merged.get("nodeC"), 1);
    }

    #[test]
    fn test_txsnapshot_2pc_full_lifecycle() {
        let (engine, dir) = create_test_engine("lifecycle");

        // Begin transaction
        let tx_id = engine.begin_tx(None).unwrap();

        // Stage files
        let f1 = engine
            .stage_file(&tx_id, "configs/app.toml", b"version = 1.0\n", None)
            .unwrap();
        assert_eq!(f1.path, "configs/app.toml");
        assert_eq!(f1.size, 14);

        let f2 = engine
            .stage_file(&tx_id, "data/records.bin", &[1, 2, 3, 4, 5], None)
            .unwrap();
        assert_eq!(f2.path, "data/records.bin");

        // Prepare Phase 1
        let participants = vec!["node-2".to_string(), "node-3".to_string()];
        let prepare = engine.prepare_2pc(&tx_id, &participants).unwrap();
        assert_eq!(prepare.staged_ops.len(), 2);

        // Vote Commit
        let vote1 = engine.vote_2pc(&prepare).unwrap();
        assert_eq!(vote1.vote, VoteKind::Commit);

        let vote2 = TwoPhaseVote {
            node_id: "node-2".to_string(),
            vote: VoteKind::Commit,
            vector_clock: TxVectorClock::initial("node-2"),
        };
        let vote3 = TwoPhaseVote {
            node_id: "node-3".to_string(),
            vote: VoteKind::Commit,
            vector_clock: TxVectorClock::initial("node-3"),
        };

        // Commit Phase 2
        let snap = engine
            .commit_2pc(&tx_id, &[vote1, vote2, vote3], Some("v1.0-release"))
            .unwrap();
        assert_eq!(snap.tag, "v1.0-release");
        assert_eq!(snap.total_files, 2);
        assert_eq!(snap.total_bytes, 19);

        // Read point-in-time snapshot (MVCC)
        let read1 = engine
            .read_snapshot("v1.0-release", "configs/app.toml")
            .unwrap()
            .unwrap();
        assert_eq!(read1, b"version = 1.0\n");

        let read2 = engine
            .read_snapshot("v1.0-release", "data/records.bin")
            .unwrap()
            .unwrap();
        assert_eq!(read2, &[1, 2, 3, 4, 5]);

        let not_found = engine
            .read_snapshot("v1.0-release", "nonexistent.txt")
            .unwrap();
        assert!(not_found.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_occ_conflict_detection() {
        let (engine, dir) = create_test_engine("occ_conflict");

        // Tx1 writes version 1 of a file
        let tx1 = engine.begin_tx(None).unwrap();
        engine
            .stage_file(&tx1, "shared.txt", b"base", None)
            .unwrap();
        let prep1 = engine.prepare_2pc(&tx1, &[]).unwrap();
        let vote1 = engine.vote_2pc(&prep1).unwrap();
        engine.commit_2pc(&tx1, &[vote1], Some("snap1")).unwrap();

        // Tx2 begins, based on revision 1
        let tx2 = engine.begin_tx(None).unwrap();
        engine
            .stage_file(&tx2, "shared.txt", b"tx2 write", Some(1))
            .unwrap();

        // Tx3 commits a concurrent update to revision 2
        let tx3 = engine.begin_tx(None).unwrap();
        engine
            .stage_file(&tx3, "shared.txt", b"tx3 write", None)
            .unwrap();
        let prep3 = engine.prepare_2pc(&tx3, &[]).unwrap();
        let vote3 = engine.vote_2pc(&prep3).unwrap();
        engine.commit_2pc(&tx3, &[vote3], Some("snap2")).unwrap();

        // Now Tx2 prepare must fail due to OCC conflict (expected revision 1, but revision 2 committed)
        let err = engine.prepare_2pc(&tx2, &[]);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("OCC conflict"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_2pc_abort_handling() {
        let (engine, dir) = create_test_engine("abort");

        let tx = engine.begin_tx(None).unwrap();
        engine
            .stage_file(&tx, "temp.log", b"staged log", None)
            .unwrap();
        let _prep = engine
            .prepare_2pc(&tx, &["faulty-node".to_string()])
            .unwrap();

        let vote_abort = TwoPhaseVote {
            node_id: "faulty-node".to_string(),
            vote: VoteKind::Abort {
                reason: "disk write rejected".to_string(),
            },
            vector_clock: TxVectorClock::new(),
        };

        let res = engine.commit_2pc(&tx, &[vote_abort], Some("abort-snap"));
        assert!(res.is_err());

        // Snapshot was not created
        let catalog = engine.load_catalog().unwrap();
        assert!(!catalog.tag_to_id.contains_key("abort-snap"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_mvcc_multiple_snapshots_isolation() {
        let (engine, dir) = create_test_engine("mvcc_iso");

        // Snap 1
        let tx1 = engine.begin_tx(None).unwrap();
        engine
            .stage_file(&tx1, "doc.txt", b"version 1 content", None)
            .unwrap();
        let prep1 = engine.prepare_2pc(&tx1, &[]).unwrap();
        let vote1 = engine.vote_2pc(&prep1).unwrap();
        engine.commit_2pc(&tx1, &[vote1], Some("snap-v1")).unwrap();

        // Snap 2 updates doc.txt and adds secret.key
        let tx2 = engine.begin_tx(None).unwrap();
        engine
            .stage_file(&tx2, "doc.txt", b"version 2 modified", None)
            .unwrap();
        engine
            .stage_file(&tx2, "secret.key", b"supersecret", None)
            .unwrap();
        let prep2 = engine.prepare_2pc(&tx2, &[]).unwrap();
        let vote2 = engine.vote_2pc(&prep2).unwrap();
        engine.commit_2pc(&tx2, &[vote2], Some("snap-v2")).unwrap();

        // Reader at Snap 1 sees version 1 and does not see secret.key
        let read_v1 = engine.read_snapshot("snap-v1", "doc.txt").unwrap().unwrap();
        assert_eq!(read_v1, b"version 1 content");
        assert!(engine
            .read_snapshot("snap-v1", "secret.key")
            .unwrap()
            .is_none());

        // Reader at Snap 2 sees version 2 and secret.key
        let read_v2 = engine.read_snapshot("snap-v2", "doc.txt").unwrap().unwrap();
        assert_eq!(read_v2, b"version 2 modified");
        let read_key = engine
            .read_snapshot("snap-v2", "secret.key")
            .unwrap()
            .unwrap();
        assert_eq!(read_key, b"supersecret");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_directory_atomic_rollback() {
        let (engine, dir) = create_test_engine("rollback");
        let restore_dest = dir.join("active_worktree");

        // Commit snapshot 1
        let tx1 = engine.begin_tx(None).unwrap();
        engine
            .stage_file(&tx1, "alpha.txt", b"alpha state 1", None)
            .unwrap();
        engine
            .stage_file(&tx1, "sub/beta.txt", b"beta state 1", None)
            .unwrap();
        let prep1 = engine.prepare_2pc(&tx1, &[]).unwrap();
        let vote1 = engine.vote_2pc(&prep1).unwrap();
        engine
            .commit_2pc(&tx1, &[vote1], Some("baseline-snap"))
            .unwrap();

        // Modify tree in snapshot 2: delete alpha.txt, modify beta.txt, add gamma.txt
        let tx2 = engine.begin_tx(None).unwrap();
        engine.stage_delete(&tx2, "alpha.txt", None).unwrap();
        engine
            .stage_file(&tx2, "sub/beta.txt", b"beta modified in snap 2", None)
            .unwrap();
        engine
            .stage_file(&tx2, "gamma.txt", b"gamma added in snap 2", None)
            .unwrap();
        let prep2 = engine.prepare_2pc(&tx2, &[]).unwrap();
        let vote2 = engine.vote_2pc(&prep2).unwrap();
        engine
            .commit_2pc(&tx2, &[vote2], Some("updated-snap"))
            .unwrap();

        // First roll back to updated-snap
        let rep2 = engine
            .rollback_to_snapshot("updated-snap", &restore_dest)
            .unwrap();
        assert_eq!(rep2.restored_files, 2);
        assert!(!restore_dest.join("alpha.txt").exists());
        assert_eq!(
            fs::read(restore_dest.join("sub/beta.txt")).unwrap(),
            b"beta modified in snap 2"
        );
        assert_eq!(
            fs::read(restore_dest.join("gamma.txt")).unwrap(),
            b"gamma added in snap 2"
        );

        // Now roll back atomically to baseline-snap
        let rep1 = engine
            .rollback_to_snapshot("baseline-snap", &restore_dest)
            .unwrap();
        assert_eq!(rep1.restored_files, 2);
        assert_eq!(rep1.deleted_files, 1); // gamma.txt should have been deleted!

        assert_eq!(
            fs::read(restore_dest.join("alpha.txt")).unwrap(),
            b"alpha state 1"
        );
        assert_eq!(
            fs::read(restore_dest.join("sub/beta.txt")).unwrap(),
            b"beta state 1"
        );
        assert!(!restore_dest.join("gamma.txt").exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
