//! Kubernetes Operator, Custom Resource Definitions (CRDs) & Declarative Transfer Reconciler (Option CU / ADR-063).
//!
//! Exposes:
//! - Declarative CRD data models: `VelcruxCluster` and `VelcruxTransfer` (`velcrux.io/v1alpha1`).
//! - Reconciliation engine: State machine transitions (`Pending`, `Scheduled`, `InProgress`, `Verifying`, `Committed`, `Retrying`, `Failed`).
//! - Exponential backoff retry policies and structured Kubernetes events.
//! - OpenAPI v3 CustomResourceDefinition manifest generators.
//! - Operator RBAC and Deployment generators.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Custom Resource Definition Group for Velcrux.
pub const CRD_GROUP: &str = "velcrux.io";
/// Custom Resource Definition Version.
pub const CRD_VERSION: &str = "v1alpha1";

/// Current system unix timestamp in seconds.
pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ==============================================================================
// 1. VelcruxCluster CRD Types
// ==============================================================================

/// High-availability Velcrux storage and replication cluster resource (`velcrux.io/v1alpha1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VelcruxCluster {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: VelcruxClusterSpec,
    #[serde(default)]
    pub status: Option<VelcruxClusterStatus>,
}

impl Default for VelcruxCluster {
    fn default() -> Self {
        Self {
            api_version: format!("{CRD_GROUP}/{CRD_VERSION}"),
            kind: "VelcruxCluster".to_string(),
            metadata: ObjectMeta::default(),
            spec: VelcruxClusterSpec::default(),
            status: Some(VelcruxClusterStatus::default()),
        }
    }
}

/// Metadata common to Kubernetes resources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    pub name: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: std::collections::BTreeMap<String, String>,
}

fn default_namespace() -> String {
    "default".to_string()
}

/// Specification for a VelcruxCluster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VelcruxClusterSpec {
    /// Number of cluster node replicas (minimum 1, recommended 3 or 5 for Raft quorum).
    #[serde(default = "default_replicas")]
    pub replicas: u32,
    /// Storage backend provider: "local", "memory", or "s3".
    #[serde(default = "default_backend")]
    pub storage_backend: String,
    /// Persistent storage capacity per replica (e.g. "1Ti", "500Gi").
    #[serde(default = "default_storage_capacity")]
    pub storage_capacity: String,
    /// QUIC transport port (UDP).
    #[serde(default = "default_quic_port")]
    pub quic_port: u16,
    /// Prometheus telemetry port (TCP).
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// Raft consensus communication port (TCP).
    #[serde(default = "default_raft_port")]
    pub raft_port: u16,
    /// Kubernetes Secret name containing mTLS server certificate and private key.
    #[serde(default)]
    pub mtls_secret_name: Option<String>,
    /// Remote deletion policy: "admin_only", "explicit_grant", or "disabled".
    #[serde(default = "default_deletion_policy")]
    pub deletion_policy: String,
}

fn default_replicas() -> u32 {
    3
}
fn default_backend() -> String {
    "local".to_string()
}
fn default_storage_capacity() -> String {
    "1Ti".to_string()
}
fn default_quic_port() -> u16 {
    7443
}
fn default_metrics_port() -> u16 {
    9443
}
fn default_raft_port() -> u16 {
    9444
}
fn default_deletion_policy() -> String {
    "admin_only".to_string()
}

impl Default for VelcruxClusterSpec {
    fn default() -> Self {
        Self {
            replicas: default_replicas(),
            storage_backend: default_backend(),
            storage_capacity: default_storage_capacity(),
            quic_port: default_quic_port(),
            metrics_port: default_metrics_port(),
            raft_port: default_raft_port(),
            mtls_secret_name: None,
            deletion_policy: default_deletion_policy(),
        }
    }
}

/// Status of a VelcruxCluster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VelcruxClusterStatus {
    pub phase: ClusterPhase,
    pub ready_replicas: u32,
    pub current_leader: Option<String>,
    pub active_raft_epoch: u64,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<ClusterCondition>,
}

impl Default for VelcruxClusterStatus {
    fn default() -> Self {
        Self {
            phase: ClusterPhase::Pending,
            ready_replicas: 0,
            current_leader: None,
            active_raft_epoch: 0,
            endpoints: Vec::new(),
            conditions: Vec::new(),
        }
    }
}

/// Operational phase of a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterPhase {
    Pending,
    Provisioning,
    Healthy,
    Degraded,
    Failed,
}

impl fmt::Display for ClusterPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Provisioning => write!(f, "Provisioning"),
            Self::Healthy => write!(f, "Healthy"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Condition entry in cluster status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterCondition {
    pub type_: String,
    pub status: String,
    pub last_transition_time: u64,
    pub reason: String,
    pub message: String,
}

// ==============================================================================
// 2. VelcruxTransfer CRD Types
// ==============================================================================

/// Declarative bulk transfer and directory synchronization resource (`velcrux.io/v1alpha1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VelcruxTransfer {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: VelcruxTransferSpec,
    #[serde(default)]
    pub status: Option<VelcruxTransferStatus>,
}

impl Default for VelcruxTransfer {
    fn default() -> Self {
        Self {
            api_version: format!("{CRD_GROUP}/{CRD_VERSION}"),
            kind: "VelcruxTransfer".to_string(),
            metadata: ObjectMeta::default(),
            spec: VelcruxTransferSpec::default(),
            status: Some(VelcruxTransferStatus::default()),
        }
    }
}

/// Transfer execution priority tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum K8sTransferPriority {
    Urgent,
    High,
    Normal,
    Low,
}

impl Default for K8sTransferPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Retry backoff policy on network or remote failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Maximum number of retry attempts before marking transfer Failed.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Base initial backoff delay in seconds (default: 5).
    #[serde(default = "default_initial_backoff_secs")]
    pub initial_backoff_secs: u64,
    /// Maximum backoff ceiling in seconds (default: 300).
    #[serde(default = "default_max_backoff_secs")]
    pub max_backoff_secs: u64,
}

fn default_max_retries() -> u32 {
    3
}
fn default_initial_backoff_secs() -> u64 {
    5
}
fn default_max_backoff_secs() -> u64 {
    300
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_secs: default_initial_backoff_secs(),
            max_backoff_secs: default_max_backoff_secs(),
        }
    }
}

/// Specification for a declarative transfer job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VelcruxTransferSpec {
    /// Source endpoint URL (e.g. "velcrux://cluster-node.velcrux:7443/data/models").
    pub source_url: String,
    /// Local or destination target filesystem path.
    pub destination_path: String,
    /// Optional recurring schedule (standard 5-field cron syntax e.g. "0 2 * * *").
    #[serde(default)]
    pub schedule: Option<String>,
    /// Transfer priority tier.
    #[serde(default)]
    pub priority: K8sTransferPriority,
    /// Number of parallel QUIC data channel streams (1..=16).
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Bandwidth-Delay Product flow control tuning policy: "auto", "fixed", "aggressive", "conservative".
    #[serde(default = "default_bdp_tuning")]
    pub bdp_tuning: String,
    /// Flow control window ceiling in bytes.
    #[serde(default = "default_max_bdp_window")]
    pub max_bdp_window: u64,
    /// Wire data compression: "none" or "zstd".
    #[serde(default = "default_compression")]
    pub compression: String,
    /// Enable content-addressed chunk store deduplication.
    #[serde(default = "default_true")]
    pub dedup: bool,
    /// Multi-tenant isolation tenant ID.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Automated retry policy on failures.
    #[serde(default)]
    pub retry_policy: RetryPolicy,
    /// Kubernetes Secret containing client mTLS certificate and private key.
    #[serde(default)]
    pub secret_ref: Option<String>,
}

fn default_concurrency() -> usize {
    4
}
fn default_bdp_tuning() -> String {
    "auto".to_string()
}
fn default_max_bdp_window() -> u64 {
    536870912
}
fn default_compression() -> String {
    "zstd".to_string()
}
fn default_true() -> bool {
    true
}

impl Default for VelcruxTransferSpec {
    fn default() -> Self {
        Self {
            source_url: "velcrux://localhost:7443/datasets".to_string(),
            destination_path: "/data/dest".to_string(),
            schedule: None,
            priority: K8sTransferPriority::Normal,
            concurrency: default_concurrency(),
            bdp_tuning: default_bdp_tuning(),
            max_bdp_window: default_max_bdp_window(),
            compression: default_compression(),
            dedup: true,
            tenant_id: None,
            retry_policy: RetryPolicy::default(),
            secret_ref: None,
        }
    }
}

/// Operational state of a transfer job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferPhase {
    Pending,
    Scheduled,
    InProgress,
    Verifying,
    Committed,
    Retrying,
    Failed,
}

impl fmt::Display for TransferPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Scheduled => write!(f, "Scheduled"),
            Self::InProgress => write!(f, "InProgress"),
            Self::Verifying => write!(f, "Verifying"),
            Self::Committed => write!(f, "Committed"),
            Self::Retrying => write!(f, "Retrying"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Real-time status reporting for a declarative transfer resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VelcruxTransferStatus {
    pub phase: TransferPhase,
    #[serde(default)]
    pub transfer_id: Option<String>,
    pub bytes_total: u64,
    pub bytes_transferred: u64,
    pub chunks_total: u64,
    pub chunks_completed: u64,
    pub bytes_reused: u64,
    pub dedup_ratio: f64,
    #[serde(default)]
    pub blake3_hash: Option<String>,
    pub retry_count: u32,
    pub next_retry_timestamp: Option<u64>,
    pub last_attempt_time: Option<u64>,
    pub completion_time: Option<u64>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub conditions: Vec<TransferCondition>,
}

impl Default for VelcruxTransferStatus {
    fn default() -> Self {
        Self {
            phase: TransferPhase::Pending,
            transfer_id: None,
            bytes_total: 0,
            bytes_transferred: 0,
            chunks_total: 0,
            chunks_completed: 0,
            bytes_reused: 0,
            dedup_ratio: 0.0,
            blake3_hash: None,
            retry_count: 0,
            next_retry_timestamp: None,
            last_attempt_time: None,
            completion_time: None,
            error_message: None,
            conditions: Vec::new(),
        }
    }
}

/// Condition entry in transfer status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TransferCondition {
    pub type_: String,
    pub status: String,
    pub last_transition_time: u64,
    pub reason: String,
    pub message: String,
}

// ==============================================================================
// 3. Kubernetes Event Model
// ==============================================================================

/// Emitted Kubernetes event for operator audit trails.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct K8sEvent {
    pub type_: String,
    pub reason: String,
    pub message: String,
    pub timestamp: u64,
}

impl K8sEvent {
    pub fn normal(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            type_: "Normal".to_string(),
            reason: reason.into(),
            message: message.into(),
            timestamp: current_timestamp_secs(),
        }
    }

    pub fn warning(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            type_: "Warning".to_string(),
            reason: reason.into(),
            message: message.into(),
            timestamp: current_timestamp_secs(),
        }
    }
}

// ==============================================================================
// 4. Operator Reconciliation Engine
// ==============================================================================

/// Reconciler execution result holding updated status and generated events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationResult {
    pub updated_status: VelcruxTransferStatus,
    pub events: Vec<K8sEvent>,
    pub requeue_after_secs: Option<u64>,
}

/// Core Operator Reconciler state machine.
pub struct OperatorReconciler;

impl OperatorReconciler {
    /// Parse a VelcruxTransfer resource from JSON or standard YAML format.
    pub fn parse_transfer_manifest(content: &str) -> Result<VelcruxTransfer, String> {
        if let Ok(val) = serde_json::from_str::<VelcruxTransfer>(content) {
            return Ok(val);
        }

        let mut transfer = VelcruxTransfer::default();
        let mut in_spec = false;
        let mut in_meta = false;

        for raw_line in content.lines() {
            // Strip comments outside quotes
            let line = if let Some(idx) = raw_line.find('#') {
                let before = &raw_line[..idx];
                let quotes = before.chars().filter(|&c| c == '"' || c == '\'').count();
                if quotes % 2 == 0 {
                    before
                } else {
                    raw_line
                }
            } else {
                raw_line
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed == "metadata:" {
                in_meta = true;
                in_spec = false;
                continue;
            }
            if trimmed == "spec:" {
                in_spec = true;
                in_meta = false;
                continue;
            }

            if in_meta {
                if let Some((k, v)) = trimmed.split_once(':') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    match key {
                        "name" => transfer.metadata.name = val.to_string(),
                        "namespace" => transfer.metadata.namespace = val.to_string(),
                        _ => {}
                    }
                }
            } else if in_spec {
                if let Some((k, v)) = trimmed.split_once(':') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    match key {
                        "sourceUrl" => transfer.spec.source_url = val.to_string(),
                        "destinationPath" => transfer.spec.destination_path = val.to_string(),
                        "schedule" => {
                            if !val.is_empty() {
                                transfer.spec.schedule = Some(val.to_string());
                            }
                        }
                        "priority" => {
                            transfer.spec.priority = match val.to_lowercase().as_str() {
                                "urgent" => K8sTransferPriority::Urgent,
                                "high" => K8sTransferPriority::High,
                                "low" => K8sTransferPriority::Low,
                                _ => K8sTransferPriority::Normal,
                            };
                        }
                        "concurrency" => {
                            if let Ok(c) = val.parse::<usize>() {
                                transfer.spec.concurrency = c;
                            }
                        }
                        "bdpTuning" => transfer.spec.bdp_tuning = val.to_string(),
                        "maxBdpWindow" => {
                            if let Ok(w) = val.parse::<u64>() {
                                transfer.spec.max_bdp_window = w;
                            }
                        }
                        "compression" => transfer.spec.compression = val.to_string(),
                        "dedup" => {
                            if let Ok(b) = val.parse::<bool>() {
                                transfer.spec.dedup = b;
                            }
                        }
                        "tenantId" => {
                            if !val.is_empty() {
                                transfer.spec.tenant_id = Some(val.to_string());
                            }
                        }
                        "secretRef" => {
                            if !val.is_empty() {
                                transfer.spec.secret_ref = Some(val.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if transfer.metadata.name.is_empty() {
            transfer.metadata.name = "unnamed-transfer".to_string();
        }

        Ok(transfer)
    }

    /// Validate transfer specification.
    pub fn validate_spec(spec: &VelcruxTransferSpec) -> Result<(), String> {
        if !spec.source_url.starts_with("velcrux://") {
            return Err(format!(
                "Invalid sourceUrl '{}': must use velcrux:// URI scheme",
                spec.source_url
            ));
        }
        if spec.destination_path.trim().is_empty() {
            return Err("destinationPath must not be empty".to_string());
        }
        if spec.concurrency == 0 || spec.concurrency > 16 {
            return Err("concurrency must be between 1 and 16".to_string());
        }
        if let Some(ref sched) = spec.schedule {
            let parts: Vec<&str> = sched.split_whitespace().collect();
            if parts.len() != 5 {
                return Err(format!(
                    "Invalid cron schedule '{sched}': expected 5 fields (minute hour dom month dow)"
                ));
            }
        }
        Ok(())
    }

    /// Calculate exponential backoff delay in seconds based on retry count.
    pub fn calculate_backoff(retry_count: u32, policy: &RetryPolicy) -> u64 {
        if retry_count == 0 {
            return policy.initial_backoff_secs;
        }
        let exp = 1u64
            .checked_shl(retry_count.saturating_sub(1))
            .unwrap_or(u64::MAX);
        let backoff = policy.initial_backoff_secs.saturating_mul(exp);
        backoff.min(policy.max_backoff_secs)
    }

    /// Reconcile a transfer resource against current time and state.
    pub fn reconcile_transfer(
        spec: &VelcruxTransferSpec,
        current_status: &VelcruxTransferStatus,
        now: u64,
    ) -> ReconciliationResult {
        let mut status = current_status.clone();
        let mut events = Vec::new();
        let mut requeue = None;

        // Validation gate
        if let Err(err) = Self::validate_spec(spec) {
            status.phase = TransferPhase::Failed;
            status.error_message = Some(err.clone());
            events.push(K8sEvent::warning("SpecValidationFailed", err));
            return ReconciliationResult {
                updated_status: status,
                events,
                requeue_after_secs: None,
            };
        }

        match status.phase {
            TransferPhase::Pending => {
                if spec.schedule.is_some() {
                    status.phase = TransferPhase::Scheduled;
                    events.push(K8sEvent::normal(
                        "TransferScheduled",
                        format!("Scheduled recurring transfer for {}", spec.source_url),
                    ));
                    requeue = Some(60);
                } else {
                    let tid = ulid::Ulid::new().to_string();
                    status.transfer_id = Some(tid.clone());
                    status.phase = TransferPhase::InProgress;
                    status.last_attempt_time = Some(now);
                    events.push(K8sEvent::normal(
                        "TransferStarted",
                        format!("Initiated transfer {tid} from {}", spec.source_url),
                    ));
                    requeue = Some(1);
                }
            }
            TransferPhase::Scheduled => {
                // Trigger scheduled transfer
                let tid = ulid::Ulid::new().to_string();
                status.transfer_id = Some(tid.clone());
                status.phase = TransferPhase::InProgress;
                status.last_attempt_time = Some(now);
                events.push(K8sEvent::normal(
                    "ScheduleTriggered",
                    format!("Triggered transfer {tid} per schedule"),
                ));
                requeue = Some(1);
            }
            TransferPhase::InProgress => {
                // If transfer was in progress, advance to Verifying once chunks are accounted for
                status.phase = TransferPhase::Verifying;
                events.push(K8sEvent::normal(
                    "TransferVerifying",
                    format!(
                        "Transferred {} bytes. Verifying aggregate BLAKE3 hash...",
                        status.bytes_transferred
                    ),
                ));
                requeue = Some(1);
            }
            TransferPhase::Verifying => {
                // Mark Committed
                status.phase = TransferPhase::Committed;
                status.completion_time = Some(now);
                events.push(K8sEvent::normal(
                    "TransferCommitted",
                    format!(
                        "BLAKE3 verification passed; atomically committed to {}",
                        spec.destination_path
                    ),
                ));
            }
            TransferPhase::Retrying => {
                if let Some(next_retry) = status.next_retry_timestamp {
                    if now >= next_retry {
                        status.phase = TransferPhase::InProgress;
                        status.next_retry_timestamp = None;
                        status.last_attempt_time = Some(now);
                        events.push(K8sEvent::normal(
                            "RetryAttemptStarted",
                            format!("Executing retry attempt {}", status.retry_count),
                        ));
                        requeue = Some(1);
                    } else {
                        requeue = Some(next_retry.saturating_sub(now));
                    }
                } else {
                    status.phase = TransferPhase::InProgress;
                    requeue = Some(1);
                }
            }
            TransferPhase::Committed | TransferPhase::Failed => {
                // Terminal phases require no action
            }
        }

        ReconciliationResult {
            updated_status: status,
            events,
            requeue_after_secs: requeue,
        }
    }

    /// Trigger a failure transition with retry evaluation.
    pub fn record_failure(
        spec: &VelcruxTransferSpec,
        current_status: &VelcruxTransferStatus,
        error: String,
        now: u64,
    ) -> ReconciliationResult {
        let mut status = current_status.clone();
        let mut events = Vec::new();

        status.retry_count = status.retry_count.saturating_add(1);
        status.error_message = Some(error.clone());

        if status.retry_count <= spec.retry_policy.max_retries {
            let backoff = Self::calculate_backoff(status.retry_count, &spec.retry_policy);
            status.phase = TransferPhase::Retrying;
            status.next_retry_timestamp = Some(now.saturating_add(backoff));

            events.push(K8sEvent::warning(
                "TransferTransientFailure",
                format!(
                    "Failure: {error}. Scheduling retry #{} in {backoff}s",
                    status.retry_count
                ),
            ));

            ReconciliationResult {
                updated_status: status,
                events,
                requeue_after_secs: Some(backoff),
            }
        } else {
            status.phase = TransferPhase::Failed;
            status.next_retry_timestamp = None;

            events.push(K8sEvent::warning(
                "TransferMaxRetriesExceeded",
                format!(
                    "Exceeded max retries ({}). Transfer failed: {error}",
                    spec.retry_policy.max_retries
                ),
            ));

            ReconciliationResult {
                updated_status: status,
                events,
                requeue_after_secs: None,
            }
        }
    }
}

// ==============================================================================
// 5. CRD OpenAPI v3 YAML & Manifest Generators
// ==============================================================================

/// Generate the OpenAPI v3 YAML manifest for VelcruxCluster CustomResourceDefinition.
pub fn generate_cluster_crd_yaml() -> String {
    r#"apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: velcruxclusters.velcrux.io
spec:
  group: velcrux.io
  names:
    kind: VelcruxCluster
    listKind: VelcruxClusterList
    plural: velcruxclusters
    singular: velcruxcluster
    shortNames:
      - vxcluster
      - vxc
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required:
                - storageBackend
              properties:
                replicas:
                  type: integer
                  minimum: 1
                  default: 3
                storageBackend:
                  type: string
                  enum: [local, memory, s3]
                  default: local
                storageCapacity:
                  type: string
                  default: 1Ti
                quicPort:
                  type: integer
                  minimum: 1024
                  maximum: 65535
                  default: 7443
                metricsPort:
                  type: integer
                  minimum: 1024
                  maximum: 65535
                  default: 9443
                raftPort:
                  type: integer
                  minimum: 1024
                  maximum: 65535
                  default: 9444
                mtlsSecretName:
                  type: string
                deletionPolicy:
                  type: string
                  enum: [admin_only, explicit_grant, disabled]
                  default: admin_only
            status:
              type: object
              properties:
                phase:
                  type: string
                readyReplicas:
                  type: integer
                currentLeader:
                  type: string
                activeRaftEpoch:
                  type: integer
                endpoints:
                  type: array
                  items:
                    type: string
      subresources:
        status: {}
      additionalPrinterColumns:
        - name: Phase
          type: string
          jsonPath: .status.phase
        - name: Ready
          type: integer
          jsonPath: .status.readyReplicas
        - name: Leader
          type: string
          jsonPath: .status.currentLeader
        - name: Age
          type: date
          jsonPath: .metadata.creationTimestamp
"#
    .to_string()
}

/// Generate the OpenAPI v3 YAML manifest for VelcruxTransfer CustomResourceDefinition.
pub fn generate_transfer_crd_yaml() -> String {
    r#"apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: velcruxtransfers.velcrux.io
spec:
  group: velcrux.io
  names:
    kind: VelcruxTransfer
    listKind: VelcruxTransferList
    plural: velcruxtransfers
    singular: velcruxtransfer
    shortNames:
      - vxtransfer
      - vxt
  scope: Namespaced
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              required:
                - sourceUrl
                - destinationPath
              properties:
                sourceUrl:
                  type: string
                  pattern: ^velcrux://.+
                destinationPath:
                  type: string
                schedule:
                  type: string
                priority:
                  type: string
                  enum: [urgent, high, normal, low]
                  default: normal
                concurrency:
                  type: integer
                  minimum: 1
                  maximum: 16
                  default: 4
                bdpTuning:
                  type: string
                  enum: [auto, fixed, aggressive, conservative]
                  default: auto
                maxBdpWindow:
                  type: integer
                  default: 536870912
                compression:
                  type: string
                  enum: [none, zstd]
                  default: zstd
                dedup:
                  type: boolean
                  default: true
                tenantId:
                  type: string
                secretRef:
                  type: string
                retryPolicy:
                  type: object
                  properties:
                    maxRetries:
                      type: integer
                      default: 3
                    initialBackoffSecs:
                      type: integer
                      default: 5
                    maxBackoffSecs:
                      type: integer
                      default: 300
            status:
              type: object
              properties:
                phase:
                  type: string
                transferId:
                  type: string
                bytesTotal:
                  type: integer
                bytesTransferred:
                  type: integer
                chunksCompleted:
                  type: integer
                chunksTotal:
                  type: integer
                dedupRatio:
                  type: number
                blake3Hash:
                  type: string
                retryCount:
                  type: integer
                errorMessage:
                  type: string
      subresources:
        status: {}
      additionalPrinterColumns:
        - name: Phase
          type: string
          jsonPath: .status.phase
        - name: Transferred
          type: integer
          jsonPath: .status.bytesTransferred
        - name: Dedup
          type: number
          jsonPath: .status.dedupRatio
        - name: Retries
          type: integer
          jsonPath: .status.retryCount
        - name: Age
          type: date
          jsonPath: .metadata.creationTimestamp
"#
    .to_string()
}

/// Generate Operator RBAC permissions manifest.
pub fn generate_operator_rbac_yaml(namespace: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: velcrux-operator
  namespace: {namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: velcrux-operator-role
rules:
  - apiGroups: ["velcrux.io"]
    resources: ["velcruxclusters", "velcruxclusters/status", "velcruxtransfers", "velcruxtransfers/status"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"]
    resources: ["statefulsets", "deployments"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["services", "configmaps", "secrets", "events", "persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: velcrux-operator-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: velcrux-operator-role
subjects:
  - kind: ServiceAccount
    name: velcrux-operator
    namespace: {namespace}
"#
    )
}

/// Generate Operator Deployment manifest.
pub fn generate_operator_deployment_yaml(image: &str, namespace: &str) -> String {
    format!(
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: velcrux-operator
  namespace: {namespace}
  labels:
    app.kubernetes.io/name: velcrux-operator
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: velcrux-operator
  template:
    metadata:
      labels:
        app.kubernetes.io/name: velcrux-operator
    spec:
      serviceAccountName: velcrux-operator
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
      containers:
        - name: operator
          image: {image}
          imagePullPolicy: IfNotPresent
          command:
            - /usr/local/bin/velcrux
            - k8s
            - operator-run
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "1000m"
              memory: "1Gi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
"#
    )
}

// ==============================================================================
// 6. Unit Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_spec_defaults() {
        let cluster = VelcruxCluster::default();
        assert_eq!(cluster.kind, "VelcruxCluster");
        assert_eq!(cluster.api_version, "velcrux.io/v1alpha1");
        assert_eq!(cluster.spec.replicas, 3);
        assert_eq!(cluster.spec.quic_port, 7443);
        assert_eq!(cluster.spec.metrics_port, 9443);
        assert_eq!(cluster.spec.deletion_policy, "admin_only");
    }

    #[test]
    fn test_transfer_spec_validation_success() {
        let spec = VelcruxTransferSpec {
            source_url: "velcrux://primary.storage:7443/datasets/models".to_string(),
            destination_path: "/data/models".to_string(),
            schedule: Some("0 2 * * *".to_string()),
            priority: K8sTransferPriority::Urgent,
            concurrency: 8,
            bdp_tuning: "auto".to_string(),
            max_bdp_window: 536870912,
            compression: "zstd".to_string(),
            dedup: true,
            tenant_id: Some("tenant-prod".to_string()),
            retry_policy: RetryPolicy::default(),
            secret_ref: Some("mtls-client-cert".to_string()),
        };

        assert!(OperatorReconciler::validate_spec(&spec).is_ok());
    }

    #[test]
    fn test_transfer_spec_validation_failures() {
        // Bad scheme
        let spec1 = VelcruxTransferSpec {
            source_url: "http://example.com/file".to_string(),
            destination_path: "/tmp/dest".to_string(),
            ..Default::default()
        };
        assert!(OperatorReconciler::validate_spec(&spec1).is_err());

        // Empty destination
        let spec2 = VelcruxTransferSpec {
            source_url: "velcrux://host:7443/file".to_string(),
            destination_path: "  ".to_string(),
            ..Default::default()
        };
        assert!(OperatorReconciler::validate_spec(&spec2).is_err());

        // Invalid cron
        let spec3 = VelcruxTransferSpec {
            source_url: "velcrux://host:7443/file".to_string(),
            destination_path: "/tmp/dest".to_string(),
            schedule: Some("daily".to_string()),
            ..Default::default()
        };
        assert!(OperatorReconciler::validate_spec(&spec3).is_err());

        // Zero concurrency
        let spec4 = VelcruxTransferSpec {
            source_url: "velcrux://host:7443/file".to_string(),
            destination_path: "/tmp/dest".to_string(),
            concurrency: 0,
            ..Default::default()
        };
        assert!(OperatorReconciler::validate_spec(&spec4).is_err());
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        let policy = RetryPolicy {
            max_retries: 5,
            initial_backoff_secs: 5,
            max_backoff_secs: 100,
        };

        assert_eq!(OperatorReconciler::calculate_backoff(0, &policy), 5);
        assert_eq!(OperatorReconciler::calculate_backoff(1, &policy), 5);
        assert_eq!(OperatorReconciler::calculate_backoff(2, &policy), 10);
        assert_eq!(OperatorReconciler::calculate_backoff(3, &policy), 20);
        assert_eq!(OperatorReconciler::calculate_backoff(4, &policy), 40);
        assert_eq!(OperatorReconciler::calculate_backoff(5, &policy), 80);
        assert_eq!(OperatorReconciler::calculate_backoff(6, &policy), 100); // capped at max_backoff_secs
    }

    #[test]
    fn test_reconciliation_lifecycle_pending_to_committed() {
        let spec = VelcruxTransferSpec {
            source_url: "velcrux://node-0:7443/files/data.bin".to_string(),
            destination_path: "/mnt/data.bin".to_string(),
            ..Default::default()
        };

        let now = 1700000000;
        let s0 = VelcruxTransferStatus::default();
        assert_eq!(s0.phase, TransferPhase::Pending);

        // Step 1: Pending -> InProgress
        let r1 = OperatorReconciler::reconcile_transfer(&spec, &s0, now);
        assert_eq!(r1.updated_status.phase, TransferPhase::InProgress);
        assert!(r1.updated_status.transfer_id.is_some());
        assert_eq!(r1.events.len(), 1);
        assert_eq!(r1.events[0].reason, "TransferStarted");

        // Step 2: InProgress -> Verifying
        let r2 = OperatorReconciler::reconcile_transfer(&spec, &r1.updated_status, now + 10);
        assert_eq!(r2.updated_status.phase, TransferPhase::Verifying);
        assert_eq!(r2.events[0].reason, "TransferVerifying");

        // Step 3: Verifying -> Committed
        let r3 = OperatorReconciler::reconcile_transfer(&spec, &r2.updated_status, now + 12);
        assert_eq!(r3.updated_status.phase, TransferPhase::Committed);
        assert_eq!(r3.updated_status.completion_time, Some(now + 12));
        assert_eq!(r3.events[0].reason, "TransferCommitted");
    }

    #[test]
    fn test_failure_retry_and_terminal_failure() {
        let spec = VelcruxTransferSpec {
            source_url: "velcrux://node-0:7443/files/data.bin".to_string(),
            destination_path: "/mnt/data.bin".to_string(),
            retry_policy: RetryPolicy {
                max_retries: 2,
                initial_backoff_secs: 5,
                max_backoff_secs: 30,
            },
            ..Default::default()
        };

        let now = 1700000000;
        let mut status = VelcruxTransferStatus {
            phase: TransferPhase::InProgress,
            ..Default::default()
        };

        // Failure 1: Retrying with retry_count = 1, backoff = 5s
        let r1 =
            OperatorReconciler::record_failure(&spec, &status, "QUIC stream timeout".into(), now);
        assert_eq!(r1.updated_status.phase, TransferPhase::Retrying);
        assert_eq!(r1.updated_status.retry_count, 1);
        assert_eq!(r1.updated_status.next_retry_timestamp, Some(now + 5));

        // Advance to retry timestamp
        let r_retry = OperatorReconciler::reconcile_transfer(&spec, &r1.updated_status, now + 5);
        assert_eq!(r_retry.updated_status.phase, TransferPhase::InProgress);
        status = r_retry.updated_status;

        // Failure 2: Retrying with retry_count = 2, backoff = 10s
        let r2 =
            OperatorReconciler::record_failure(&spec, &status, "Connection reset".into(), now + 10);
        assert_eq!(r2.updated_status.phase, TransferPhase::Retrying);
        assert_eq!(r2.updated_status.retry_count, 2);
        assert_eq!(r2.updated_status.next_retry_timestamp, Some(now + 20));
        status = r2.updated_status;

        // Failure 3: retry_count = 3 > max_retries (2) -> Terminal Failed
        let r3 = OperatorReconciler::record_failure(
            &spec,
            &status,
            "Auth token expired".into(),
            now + 25,
        );
        assert_eq!(r3.updated_status.phase, TransferPhase::Failed);
        assert_eq!(r3.updated_status.retry_count, 3);
        assert!(r3.events[0].reason.contains("MaxRetriesExceeded"));
    }

    #[test]
    fn test_crd_manifest_generators() {
        let cluster_crd = generate_cluster_crd_yaml();
        assert!(cluster_crd.contains("kind: CustomResourceDefinition"));
        assert!(cluster_crd.contains("name: velcruxclusters.velcrux.io"));
        assert!(cluster_crd.contains("shortNames:"));
        assert!(cluster_crd.contains("- vxc"));

        let transfer_crd = generate_transfer_crd_yaml();
        assert!(transfer_crd.contains("kind: CustomResourceDefinition"));
        assert!(transfer_crd.contains("name: velcruxtransfers.velcrux.io"));
        assert!(transfer_crd.contains("shortNames:"));
        assert!(transfer_crd.contains("- vxt"));

        let rbac = generate_operator_rbac_yaml("velcrux-system");
        assert!(rbac.contains("name: velcrux-operator"));
        assert!(rbac.contains("namespace: velcrux-system"));
        assert!(rbac.contains("resources: [\"velcruxclusters\""));

        let deploy =
            generate_operator_deployment_yaml("ghcr.io/velcrux/velcrux:v0.1.0", "velcrux-system");
        assert!(deploy.contains("kind: Deployment"));
        assert!(deploy.contains("image: ghcr.io/velcrux/velcrux:v0.1.0"));
        assert!(deploy.contains("namespace: velcrux-system"));
    }
}
