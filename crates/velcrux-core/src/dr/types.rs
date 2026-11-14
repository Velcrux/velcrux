//! Types, records, and telemetry structures for Multi-Cluster Global Disaster Recovery
//! Failover and Split-Brain Fencing Coordinator (ADR-080).

use serde::{Deserialize, Serialize};

/// High-level topology role of a cluster region within the DR mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterRole {
    /// Active primary serving read and write traffic. Holds the current fencing lease.
    Primary,
    /// Warm or hot standby actively replicating storage and ready for failover.
    Standby,
    /// Stateless or lightweight tie-breaker witness participating in quorum fencing decisions.
    Witness,
}

impl std::fmt::Display for ClusterRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Primary => write!(f, "primary"),
            Self::Standby => write!(f, "standby"),
            Self::Witness => write!(f, "witness"),
        }
    }
}

impl std::str::FromStr for ClusterRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "primary" | "active" => Ok(Self::Primary),
            "standby" | "replica" | "secondary" => Ok(Self::Standby),
            "witness" | "arbiter" | "tiebreaker" => Ok(Self::Witness),
            other => Err(format!("Unknown cluster role: '{other}'")),
        }
    }
}

/// Disaster recovery state machine lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrState {
    /// Primary is healthy, serving I/O; standbys replicating smoothly.
    NormalActive,
    /// Heartbeat degradation, transient packet loss or elevated jitter detected. Quorum intact.
    Degraded,
    /// Primary declared unresponsive or dead; quorum consensus initiating failover.
    FailoverPending,
    /// Quorum witness lease approved; issuing fencing generation epoch and revoking old lease.
    FencingOldPrimary,
    /// Catching up replication backlog on standby and preparing promotion.
    PromotingSecondary,
    /// Failover completed; new primary active under incremented epoch.
    FailoverComplete,
    /// Operator requested return to original primary or old primary recovered.
    FailbackPending,
    /// Reconciling any log divergence before restoring original topology roles.
    ReconcilingDivergence,
}

impl std::fmt::Display for DrState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NormalActive => write!(f, "normal_active"),
            Self::Degraded => write!(f, "degraded"),
            Self::FailoverPending => write!(f, "failover_pending"),
            Self::FencingOldPrimary => write!(f, "fencing_old_primary"),
            Self::PromotingSecondary => write!(f, "promoting_secondary"),
            Self::FailoverComplete => write!(f, "failover_complete"),
            Self::FailbackPending => write!(f, "failback_pending"),
            Self::ReconcilingDivergence => write!(f, "reconciling_divergence"),
        }
    }
}

/// Metadata describing a cluster region in the DR deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRegion {
    /// Unique identifier for the cluster region (e.g. "us-east-1", "eu-central-1").
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Current assigned cluster role.
    pub role: ClusterRole,
    /// Network endpoint or gRPC/QUIC address for inter-region probing.
    pub endpoint: String,
    /// Quorum voting weight (normally 1 for standard nodes, 0 for observers).
    pub weight: u32,
    /// Datacenter or cloud zone tag.
    pub datacenter: String,
}

impl ClusterRegion {
    /// Create a new cluster region definition.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        role: ClusterRole,
        endpoint: impl Into<String>,
        weight: u32,
        datacenter: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            role,
            endpoint: endpoint.into(),
            weight,
            datacenter: datacenter.into(),
        }
    }
}

/// Cryptographically signed fencing token guaranteeing mutual exclusion of write-leader status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingToken {
    /// Monotonically increasing fencing generation number.
    pub epoch: u64,
    /// Identifier of the cluster authorized to hold the write lease.
    pub holder_cluster: String,
    /// Unix millisecond timestamp when the token was issued.
    pub issued_at_ms: u64,
    /// Validity lease duration in milliseconds.
    pub lease_duration_ms: u64,
    /// BLAKE3 keyed quorum witness signatures approving this lease.
    pub quorum_signatures: Vec<[u8; 32]>,
}

impl FencingToken {
    /// Creates a new unapproved fencing token candidate.
    #[must_use]
    pub fn new_candidate(
        epoch: u64,
        holder_cluster: impl Into<String>,
        issued_at_ms: u64,
        lease_duration_ms: u64,
    ) -> Self {
        Self {
            epoch,
            holder_cluster: holder_cluster.into(),
            issued_at_ms,
            lease_duration_ms,
            quorum_signatures: Vec::new(),
        }
    }

    /// Expiration timestamp in Unix milliseconds.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.issued_at_ms.saturating_add(self.lease_duration_ms)
    }

    /// Check if the lease is currently valid at `now_ms`.
    #[must_use]
    pub fn is_valid(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_at_ms && now_ms < self.expires_at_ms()
    }

    /// Check if the lease has expired at `now_ms`.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms()
    }

    /// Compute cryptographic witness signature hash over token payload.
    #[must_use]
    pub fn compute_signature(
        witness_secret: &[u8],
        epoch: u64,
        holder: &str,
        issued_at: u64,
    ) -> [u8; 32] {
        let key = derive_key(witness_secret);
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(holder.as_bytes());
        hasher.update(&issued_at.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Derive 32-byte key from arbitrary-length witness secret.
fn derive_key(secret: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let hash = blake3::hash(secret);
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Periodic heartbeat probe message sent between regions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatMsg {
    /// Sending cluster region identifier.
    pub sender_cluster: String,
    /// Current fencing generation epoch recognized by sender.
    pub epoch: u64,
    /// Timestamp when heartbeat was dispatched (ms).
    pub timestamp_ms: u64,
    /// Estimated replication lag (RPO metric) in milliseconds.
    pub rpo_lag_ms: u64,
    /// Current DR state reported by sender.
    pub state: DrState,
}

/// Failure detector configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrFailureDetectorConfig {
    /// Expected interval between heartbeats in milliseconds (default: 1000ms).
    pub heartbeat_interval_ms: u64,
    /// Acceptable network jitter threshold in milliseconds (default: 250ms).
    pub jitter_bound_ms: u64,
    /// Number of consecutive missed heartbeats before declaring failure (default: 3).
    pub consecutive_loss_threshold: u32,
    /// Maximum sliding window size of recorded heartbeat intervals (default: 64).
    pub history_window_size: usize,
    /// Suspicion score threshold (0.0 to 1.0) above which a node is marked Suspect (default: 0.70).
    pub suspicion_threshold: f64,
}

impl Default for DrFailureDetectorConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 1000,
            jitter_bound_ms: 250,
            consecutive_loss_threshold: 3,
            history_window_size: 64,
            suspicion_threshold: 0.70,
        }
    }
}

/// Health verdict for an individual cluster node or probe path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeHealthStatus {
    /// Node is actively responding within jitter bounds.
    Alive,
    /// Heartbeat delayed or jitter high, but not yet crossing failure threshold.
    Suspect,
    /// Consecutive missed threshold exceeded; declared unreachable.
    Dead,
}

impl std::fmt::Display for ProbeHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alive => write!(f, "alive"),
            Self::Suspect => write!(f, "suspect"),
            Self::Dead => write!(f, "dead"),
        }
    }
}

/// Detailed health telemetry report for a cluster region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionStatus {
    /// Cluster ID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Role.
    pub role: ClusterRole,
    /// Probe health status.
    pub health: ProbeHealthStatus,
    /// Last received heartbeat timestamp in ms.
    pub last_heartbeat_ms: u64,
    /// Replication lag in ms (RPO metric).
    pub rpo_lag_ms: u64,
    /// Average heartbeat interval in ms.
    pub avg_interval_ms: f64,
    /// Measured jitter in ms.
    pub jitter_ms: f64,
    /// Consecutive missed heartbeats count.
    pub consecutive_missed: u32,
    /// Suspicion score (0.0 = completely healthy, 1.0 = dead).
    pub suspicion_score: f64,
}

/// Failover trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverMode {
    /// Graceful operator-initiated maintenance switchover (zero data loss, RPO = 0).
    PlannedSwitchover,
    /// Emergency automated or operator failover due to primary failure/isolation.
    EmergencyFailover,
}

/// Result report from a failover or failback execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrFailoverReport {
    /// Mode of operation.
    pub mode: FailoverMode,
    /// Previous primary cluster ID.
    pub previous_primary: String,
    /// New promoted primary cluster ID.
    pub new_primary: String,
    /// New active fencing epoch.
    pub fencing_epoch: u64,
    /// Measured RPO lag in milliseconds at the time of handover.
    pub rpo_lag_ms: u64,
    /// Measured RTO duration in milliseconds (time to complete failover).
    pub rto_duration_ms: u64,
    /// List of quorum witnesses that approved the fencing epoch.
    pub quorum_witnesses: Vec<String>,
    /// Whether the failover was successful.
    pub success: bool,
    /// Operational details or diagnosis.
    pub notes: String,
}

/// Full status snapshot of the Disaster Recovery coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrStatusReport {
    /// Active fencing epoch.
    pub current_epoch: u64,
    /// Identifier of the currently recognized primary cluster.
    pub active_primary: String,
    /// Global coordinator lifecycle state.
    pub state: DrState,
    /// List of all managed cluster regions and their health.
    pub regions: Vec<RegionStatus>,
    /// Total number of witness nodes participating in quorum.
    pub witness_count: usize,
    /// Required quorum size for fencing decisions.
    pub quorum_size: usize,
    /// Active fencing token lease information.
    pub active_fencing_token: Option<FencingToken>,
    /// Global maximum observed RPO lag in milliseconds across warm standbys.
    pub overall_rpo_ms: u64,
}

/// Benchmark performance result for DR failover and split-brain fencing engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrBenchmarkReport {
    /// Total simulated iterations executed.
    pub iterations: u32,
    /// Average heartbeat processing latency in nanoseconds.
    pub avg_heartbeat_latency_ns: f64,
    /// Average quorum fencing consensus latency in microseconds.
    pub avg_fencing_consensus_us: f64,
    /// Average simulated failover RTO in microseconds.
    pub avg_failover_rto_us: f64,
    /// Storage write fencing throughput (validations/sec).
    pub write_fencing_ops_per_sec: f64,
    /// Split-brain rejection count (writes properly blocked by fencing barriers).
    pub split_brain_prevented_count: u64,
}

/// Domain errors encountered during disaster recovery and fencing operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum DrError {
    #[error("Cluster region not found: '{0}'")]
    ClusterNotFound(String),

    #[error("Cluster '{0}' is not in a valid state for failover: {1:?}")]
    InvalidClusterState(String, DrState),

    #[error(
        "Fencing barrier: obsolete epoch attempted {attempted}, current barrier epoch is {current}"
    )]
    FencedObsoleteEpoch { attempted: u64, current: u64 },

    #[error("Fencing barrier: write lease expired at {expired_at} ms, current time is {now} ms")]
    FencedExpiredLease { expired_at: u64, now: u64 },

    #[error(
        "Fencing barrier: unauthorized cluster '{cluster}', current lease holder is '{holder}'"
    )]
    UnauthorizedCluster { cluster: String, holder: String },

    #[error("Quorum not reached: required {required} approvals, acquired {acquired}")]
    QuorumNotReached { required: usize, acquired: usize },

    #[error("Target cluster '{0}' is dead or unreachable")]
    TargetClusterUnreachable(String),

    #[error("Target cluster '{0}' already holds the primary role")]
    AlreadyPrimary(String),

    #[error("Failover rejected: {0}")]
    FailoverRejected(String),

    #[error("Failback rejected: {0}")]
    FailbackRejected(String),
}

/// Result alias for DR operations.
pub type DrResult<T> = std::result::Result<T, DrError>;
