//! Distributed Lock Manager (DLM) & Mutex Lease Coordinator (Option BD).
//!
//! Implements `REQUIREMENTS.md` §61 ("Transactional Synchronization"), §17 ("Crash Recovery"),
//! §20 ("Authorization"), and §31 ("Large Manifest Optimization").
//!
//! Provides distributed mutual exclusion leases, shared read locks, monotonic Lamport fencing
//! tokens for split-brain prevention, and automatic TTL expiration to prevent deadlocks on client crash.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;

/// Access mode for a requested distributed lock lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockMode {
    /// Exclusive write lock: only a single holder can hold this lock on a given resource.
    Exclusive,
    /// Shared read lock: multiple concurrent readers can hold this lock on a given resource.
    Shared,
}

impl std::fmt::Display for LockMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exclusive => write!(f, "EXCLUSIVE"),
            Self::Shared => write!(f, "SHARED"),
        }
    }
}

impl std::str::FromStr for LockMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "exclusive" | "write" | "ex" | "w" => Ok(Self::Exclusive),
            "shared" | "read" | "sh" | "r" => Ok(Self::Shared),
            other => Err(format!("unknown lock mode '{}': expected 'exclusive' or 'shared'", other)),
        }
    }
}

/// An active time-bounded lock lease issued to a client or worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseLock {
    /// Globally unique lock lease identifier.
    pub lock_id: String,
    /// Canonical resource path or namespace protected by the lock.
    pub resource: String,
    /// Client, session, or node identifier holding the lease.
    pub holder_id: String,
    /// Lock access mode (Exclusive or Shared).
    pub mode: LockMode,
    /// Monotonically increasing Lamport fencing token.
    pub fencing_token: u64,
    /// Unix timestamp (seconds) when lock was granted.
    pub granted_at_secs: u64,
    /// Unix timestamp (seconds) when lease will expire unless renewed.
    pub expires_at_secs: u64,
    /// Configured lease duration in seconds.
    pub ttl_secs: u64,
}

impl LeaseLock {
    /// Check whether this lease has expired relative to `now_secs`.
    #[inline]
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs >= self.expires_at_secs
    }

    /// Remaining time to live in seconds, or 0 if expired.
    #[inline]
    pub fn remaining_ttl_secs(&self, now_secs: u64) -> u64 {
        self.expires_at_secs.saturating_sub(now_secs)
    }
}

/// Errors returned during distributed lock operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockError {
    /// Target resource is currently locked by a conflicting leaseholder.
    ResourceBusy {
        resource: String,
        current_holder: String,
        mode: LockMode,
        expires_in_secs: u64,
    },
    /// Lock lease ID not found.
    LockNotFound { lock_id: String },
    /// Requesting client does not match the registered leaseholder.
    HolderMismatch {
        lock_id: String,
        expected_holder: String,
        actual_holder: String,
    },
    /// Lease has already expired and cannot be renewed or operated upon.
    LockExpired { lock_id: String },
    /// Invalid resource path or format.
    InvalidResource { reason: String },
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResourceBusy {
                resource,
                current_holder,
                mode,
                expires_in_secs,
            } => write!(
                f,
                "resource '{}' is busy (held by '{}' [{}] for {}s)",
                resource, current_holder, mode, expires_in_secs
            ),
            Self::LockNotFound { lock_id } => write!(f, "lock lease '{}' not found", lock_id),
            Self::HolderMismatch {
                lock_id,
                expected_holder,
                actual_holder,
            } => write!(
                f,
                "lock '{}' holder mismatch: registered to '{}', called by '{}'",
                lock_id, expected_holder, actual_holder
            ),
            Self::LockExpired { lock_id } => write!(f, "lock lease '{}' has expired", lock_id),
            Self::InvalidResource { reason } => write!(f, "invalid resource: {}", reason),
        }
    }
}

impl std::error::Error for LockError {}

/// Comprehensive operational status report of active distributed locks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockReport {
    /// Total count of active valid locks.
    pub total_active_locks: usize,
    /// Total count of exclusive write locks.
    pub total_exclusive_locks: usize,
    /// Total count of shared read locks.
    pub total_shared_locks: usize,
    /// Highest fencing token issued so far.
    pub highest_fencing_token: u64,
    /// List of all active lock leases.
    pub active_locks: Vec<LeaseLock>,
}

/// Central Distributed Lock Manager (DLM) and Lease Mutex Coordinator.
pub struct DistributedLockManager {
    /// Resource -> active leases map.
    locks: Arc<RwLock<HashMap<String, Vec<LeaseLock>>>>,
    /// Monotonically increasing Lamport fencing token counter.
    token_counter: Arc<AtomicU64>,
    /// Default TTL for leases in seconds if unspecified (default: 60s).
    default_ttl_secs: u64,
    /// Maximum allowable TTL for leases in seconds (default: 3600s / 1hr).
    max_ttl_secs: u64,
    /// Optional persistent JSON file path for surviving server restarts.
    persistence_path: Option<PathBuf>,
}

impl DistributedLockManager {
    /// Create a new in-memory Distributed Lock Manager with default settings (60s TTL).
    pub fn new() -> Self {
        Self {
            locks: Arc::new(RwLock::new(HashMap::new())),
            token_counter: Arc::new(AtomicU64::new(100)),
            default_ttl_secs: 60,
            max_ttl_secs: 3600,
            persistence_path: None,
        }
    }

    /// Configure custom default lease TTL and maximum TTL in seconds.
    pub fn with_ttl(mut self, default_ttl_secs: u64, max_ttl_secs: u64) -> Self {
        self.default_ttl_secs = default_ttl_secs.max(5);
        self.max_ttl_secs = max_ttl_secs.max(self.default_ttl_secs);
        self
    }

    /// Enable optional persistent state storage at `path`.
    pub fn with_persistence(mut self, path: impl Into<PathBuf>) -> Result<Self, VelcruxError> {
        let p = path.into();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        self.persistence_path = Some(p);
        self.load_from_persistence()?;
        Ok(self)
    }

    /// Canonicalize resource path string (normalize slashes).
    pub fn canonicalize_resource(resource: &str) -> Result<String, LockError> {
        let trimmed = resource.trim();
        if trimmed.is_empty() {
            return Err(LockError::InvalidResource {
                reason: "resource name cannot be empty".to_string(),
            });
        }
        let cleaned = trimmed
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();

        if cleaned.is_empty() {
            return Ok("/".to_string());
        }
        Ok(format!("/{}", cleaned))
    }

    /// Acquire a distributed lock lease on `resource`.
    pub fn acquire(
        &self,
        resource: &str,
        holder_id: &str,
        mode: LockMode,
        ttl_secs: Option<u64>,
        now_secs: u64,
    ) -> Result<LeaseLock, LockError> {
        let canon_resource = Self::canonicalize_resource(resource)?;
        if holder_id.trim().is_empty() {
            return Err(LockError::InvalidResource {
                reason: "holder_id cannot be empty".to_string(),
            });
        }

        let effective_ttl = ttl_secs
            .unwrap_or(self.default_ttl_secs)
            .clamp(5, self.max_ttl_secs);

        let mut lock_map = self.locks.write().unwrap();

        // 1. Purge expired leases on this resource first
        if let Some(leases) = lock_map.get_mut(&canon_resource) {
            leases.retain(|l| !l.is_expired(now_secs));
        }

        // 2. Conflict detection
        if let Some(leases) = lock_map.get(&canon_resource) {
            if !leases.is_empty() {
                match mode {
                    LockMode::Exclusive => {
                        // Any existing non-expired lease blocks an Exclusive lock
                        let existing = &leases[0];
                        return Err(LockError::ResourceBusy {
                            resource: canon_resource,
                            current_holder: existing.holder_id.clone(),
                            mode: existing.mode,
                            expires_in_secs: existing.remaining_ttl_secs(now_secs),
                        });
                    }
                    LockMode::Shared => {
                        // If an active Exclusive lease exists, Shared is blocked
                        if let Some(ex) = leases.iter().find(|l| l.mode == LockMode::Exclusive) {
                            return Err(LockError::ResourceBusy {
                                resource: canon_resource,
                                current_holder: ex.holder_id.clone(),
                                mode: LockMode::Exclusive,
                                expires_in_secs: ex.remaining_ttl_secs(now_secs),
                            });
                        }
                    }
                }
            }
        }

        // 3. Issue monotonically increasing Lamport fencing token
        let token = self.token_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let lock_id = format!("lck-{}-{}", token, rand::random::<u16>());

        let lease = LeaseLock {
            lock_id,
            resource: canon_resource.clone(),
            holder_id: holder_id.to_string(),
            mode,
            fencing_token: token,
            granted_at_secs: now_secs,
            expires_at_secs: now_secs + effective_ttl,
            ttl_secs: effective_ttl,
        };

        lock_map
            .entry(canon_resource)
            .or_default()
            .push(lease.clone());

        drop(lock_map);
        let _ = self.save_to_persistence();
        Ok(lease)
    }

    /// Renew / extend an active lease before it expires.
    pub fn renew(
        &self,
        lock_id: &str,
        holder_id: &str,
        extension_secs: Option<u64>,
        now_secs: u64,
    ) -> Result<LeaseLock, LockError> {
        let mut lock_map = self.locks.write().unwrap();

        for leases in lock_map.values_mut() {
            if let Some(lease) = leases.iter_mut().find(|l| l.lock_id == lock_id) {
                // Verify holder
                if lease.holder_id != holder_id {
                    return Err(LockError::HolderMismatch {
                        lock_id: lock_id.to_string(),
                        expected_holder: lease.holder_id.clone(),
                        actual_holder: holder_id.to_string(),
                    });
                }
                // Check if already expired
                if lease.is_expired(now_secs) {
                    return Err(LockError::LockExpired {
                        lock_id: lock_id.to_string(),
                    });
                }

                let ext = extension_secs.unwrap_or(lease.ttl_secs).clamp(5, self.max_ttl_secs);
                lease.expires_at_secs = now_secs + ext;
                lease.ttl_secs = ext;

                let updated = lease.clone();
                drop(lock_map);
                let _ = self.save_to_persistence();
                return Ok(updated);
            }
        }

        Err(LockError::LockNotFound {
            lock_id: lock_id.to_string(),
        })
    }

    /// Release an active lease. Returns `true` if released, or error if not found / holder mismatch.
    pub fn release(
        &self,
        lock_id: &str,
        holder_id: &str,
        _now_secs: u64,
    ) -> Result<bool, LockError> {
        let mut lock_map = self.locks.write().unwrap();
        let mut target_res = None;

        for (res, leases) in lock_map.iter() {
            if let Some(pos) = leases.iter().position(|l| l.lock_id == lock_id) {
                let lease = &leases[pos];
                if lease.holder_id != holder_id {
                    return Err(LockError::HolderMismatch {
                        lock_id: lock_id.to_string(),
                        expected_holder: lease.holder_id.clone(),
                        actual_holder: holder_id.to_string(),
                    });
                }
                target_res = Some((res.clone(), pos));
                break;
            }
        }

        if let Some((res, pos)) = target_res {
            if let Some(leases) = lock_map.get_mut(&res) {
                leases.remove(pos);
                if leases.is_empty() {
                    lock_map.remove(&res);
                }
            }
            drop(lock_map);
            let _ = self.save_to_persistence();
            return Ok(true);
        }

        Err(LockError::LockNotFound {
            lock_id: lock_id.to_string(),
        })
    }

    /// Inspect active leases on a given resource path.
    pub fn inspect(&self, resource: &str, now_secs: u64) -> Vec<LeaseLock> {
        let canon = match Self::canonicalize_resource(resource) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let lock_map = self.locks.read().unwrap();
        match lock_map.get(&canon) {
            Some(leases) => leases
                .iter()
                .filter(|l| !l.is_expired(now_secs))
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Verify whether a Lamport fencing token is active and valid for the specified resource.
    pub fn verify_fencing(&self, resource: &str, fencing_token: u64, now_secs: u64) -> bool {
        let canon = match Self::canonicalize_resource(resource) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let lock_map = self.locks.read().unwrap();
        if let Some(leases) = lock_map.get(&canon) {
            leases
                .iter()
                .any(|l| l.fencing_token == fencing_token && !l.is_expired(now_secs))
        } else {
            false
        }
    }

    /// Sweep and purge all expired leases across all registered resources. Returns count of purged leases.
    pub fn purge_expired(&self, now_secs: u64) -> usize {
        let mut lock_map = self.locks.write().unwrap();
        let mut purged = 0usize;

        lock_map.retain(|_res, leases| {
            let before = leases.len();
            leases.retain(|l| !l.is_expired(now_secs));
            purged += before - leases.len();
            !leases.is_empty()
        });

        if purged > 0 {
            drop(lock_map);
            let _ = self.save_to_persistence();
        }
        purged
    }

    /// Generate comprehensive lock status report.
    pub fn generate_report(&self, now_secs: u64) -> LockReport {
        let lock_map = self.locks.read().unwrap();
        let mut active = Vec::new();
        let mut exclusive_count = 0usize;
        let mut shared_count = 0usize;

        for leases in lock_map.values() {
            for l in leases {
                if !l.is_expired(now_secs) {
                    active.push(l.clone());
                    match l.mode {
                        LockMode::Exclusive => exclusive_count += 1,
                        LockMode::Shared => shared_count += 1,
                    }
                }
            }
        }

        active.sort_by_key(|l| l.fencing_token);
        LockReport {
            total_active_locks: active.len(),
            total_exclusive_locks: exclusive_count,
            total_shared_locks: shared_count,
            highest_fencing_token: self.token_counter.load(Ordering::SeqCst),
            active_locks: active,
        }
    }

    fn save_to_persistence(&self) -> Result<(), VelcruxError> {
        let path = match &self.persistence_path {
            Some(p) => p,
            None => return Ok(()),
        };

        let lock_map = self.locks.read().unwrap();
        let mut all_locks = Vec::new();
        let mut exclusive_count = 0usize;
        let mut shared_count = 0usize;

        for leases in lock_map.values() {
            for l in leases {
                all_locks.push(l.clone());
                match l.mode {
                    LockMode::Exclusive => exclusive_count += 1,
                    LockMode::Shared => shared_count += 1,
                }
            }
        }
        all_locks.sort_by_key(|l| l.fencing_token);

        let report = LockReport {
            total_active_locks: all_locks.len(),
            total_exclusive_locks: exclusive_count,
            total_shared_locks: shared_count,
            highest_fencing_token: self.token_counter.load(Ordering::SeqCst),
            active_locks: all_locks,
        };

        let tmp_path = path.with_extension(format!("tmp-{}", rand::random::<u64>()));
        let json_bytes = serde_json::to_vec_pretty(&report)
            .map_err(|e| VelcruxError::Internal(format!("failed to serialize lock state: {}", e)))?;

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            f.write_all(&json_bytes)?;
            f.sync_all()?;
        }

        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    fn load_from_persistence(&mut self) -> Result<(), VelcruxError> {
        let path = match &self.persistence_path {
            Some(p) => p,
            None => return Ok(()),
        };

        if !path.exists() {
            return Ok(());
        }

        let mut f = File::open(path)?;
        let mut content = Vec::new();
        f.read_to_end(&mut content)?;

        if let Ok(report) = serde_json::from_slice::<LockReport>(&content) {
            let mut map: HashMap<String, Vec<LeaseLock>> = HashMap::new();
            for l in report.active_locks {
                map.entry(l.resource.clone()).or_default().push(l);
            }
            self.token_counter
                .store(report.highest_fencing_token, Ordering::SeqCst);
            *self.locks.write().unwrap() = map;
        }

        Ok(())
    }
}

impl Default for DistributedLockManager {
    fn default() -> Self {
        Self::new()
    }
}
