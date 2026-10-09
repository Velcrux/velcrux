//! Transfer session idempotency ledger and request replay protection.
//!
//! Enforces `REQUIREMENTS.md` §67:
//! "Operations should be designed to be safely retried. For example: `TRANSFER_CREATE`
//! should use an idempotency key where appropriate. A network timeout must not cause
//! duplicate transfers or corrupted state."
//!
//! Enforces `CLAUDE.md` §1: 100% safe Rust (`#![forbid(unsafe_code)]`).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::state::{Role, StateStore, TransferStatus};
use crate::util::TransferId;

/// Action returned by [`IdempotencyLedger::evaluate_transfer_create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyAction {
    /// Brand new transfer request; caller should assign resources and execute.
    ProceedNew(TransferId),
    /// Request is already in-progress on another active stream/session; caller should attach.
    ReplayActive(TransferId),
    /// Transfer has already succeeded and committed; caller can immediately replay `COMMITTED`.
    ReplayCommitted { transfer_id: TransferId, files: u32 },
    /// Transfer was previously interrupted and is in `Resumable` state; caller can resume.
    ResumeExisting {
        transfer_id: TransferId,
        bytes_completed: u64,
    },
    /// The idempotency key matches an existing record but parameters (path, size) differ.
    Conflict(String),
}

/// Durable entry cached inside the in-memory ledger.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    /// Stable transfer identifier.
    pub transfer_id: TransferId,
    /// Associated role (Client or Server).
    pub role: Role,
    /// Caller-supplied unique idempotency key.
    pub idempotency_key: String,
    /// Destination remote path inside the storage root.
    pub remote_path: String,
    /// Expected total transfer size in bytes.
    pub expected_size: u64,
    /// Lifecycle state of the transfer.
    pub status: TransferStatus,
    /// Timestamp when entry was created.
    pub created_at: Instant,
    /// Timestamp when entry was last updated.
    pub updated_at: Instant,
    /// Number of committed files (if committed).
    pub committed_files: Option<u32>,
}

/// Thread-safe registry coordinating transfer idempotency and duplicate request suppression.
#[derive(Debug, Default)]
pub struct IdempotencyLedger {
    entries: RwLock<HashMap<(Role, String), LedgerEntry>>,
}

impl IdempotencyLedger {
    /// Create a new, empty idempotency ledger.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Evaluate an incoming `TRANSFER_CREATE` request against active in-memory transfers
    /// and fallback persistent state store.
    pub fn evaluate_transfer_create(
        &self,
        role: Role,
        idempotency_key: &str,
        remote_path: &str,
        expected_size: u64,
        store: Option<&dyn StateStore>,
    ) -> IdempotencyAction {
        let key = (role, idempotency_key.to_string());

        // 1. Check in-memory fast-path
        if let Ok(guard) = self.entries.read() {
            if let Some(entry) = guard.get(&key) {
                // Verify parameter consistency
                if entry.remote_path != remote_path {
                    return IdempotencyAction::Conflict(format!(
                        "idempotency key {:?} already used for path {:?}, received {:?}",
                        idempotency_key, entry.remote_path, remote_path
                    ));
                }
                if entry.expected_size != expected_size {
                    return IdempotencyAction::Conflict(format!(
                        "idempotency key {:?} already used for size {}, received {}",
                        idempotency_key, entry.expected_size, expected_size
                    ));
                }

                match entry.status {
                    TransferStatus::Active => {
                        return IdempotencyAction::ReplayActive(entry.transfer_id);
                    }
                    TransferStatus::Committed => {
                        return IdempotencyAction::ReplayCommitted {
                            transfer_id: entry.transfer_id,
                            files: entry.committed_files.unwrap_or(1),
                        };
                    }
                    TransferStatus::Resumable => {
                        return IdempotencyAction::ResumeExisting {
                            transfer_id: entry.transfer_id,
                            bytes_completed: 0,
                        };
                    }
                    TransferStatus::Cancelled => {
                        // Cancelled transfers cannot be blindly resumed
                        return IdempotencyAction::Conflict(format!(
                            "idempotency key {:?} was previously cancelled",
                            idempotency_key
                        ));
                    }
                }
            }
        }

        // 2. Check persistent StateStore fallback if provided
        if let Some(s) = store {
            if let Ok(record) = s.get_transfer_by_idempotency(role, idempotency_key) {
                // Verify parameter consistency against durable record
                if record.remote_path != remote_path {
                    return IdempotencyAction::Conflict(format!(
                        "idempotency key {:?} registered for path {:?}, received {:?}",
                        idempotency_key, record.remote_path, remote_path
                    ));
                }
                if record.file_size != expected_size {
                    return IdempotencyAction::Conflict(format!(
                        "idempotency key {:?} registered for size {}, received {}",
                        idempotency_key, record.file_size, expected_size
                    ));
                }

                let transfer_id = record.transfer_id;
                let status = record.status;
                let bytes_completed = record.bytes_completed;

                // Cache into in-memory ledger
                if let Ok(mut guard) = self.entries.write() {
                    let now = Instant::now();
                    guard.insert(
                        key,
                        LedgerEntry {
                            transfer_id,
                            role,
                            idempotency_key: idempotency_key.to_string(),
                            remote_path: remote_path.to_string(),
                            expected_size,
                            status,
                            created_at: now,
                            updated_at: now,
                            committed_files: if status == TransferStatus::Committed {
                                Some(1)
                            } else {
                                None
                            },
                        },
                    );
                }

                return match status {
                    TransferStatus::Active => IdempotencyAction::ReplayActive(transfer_id),
                    TransferStatus::Committed => IdempotencyAction::ReplayCommitted {
                        transfer_id,
                        files: 1,
                    },
                    TransferStatus::Resumable => IdempotencyAction::ResumeExisting {
                        transfer_id,
                        bytes_completed,
                    },
                    TransferStatus::Cancelled => IdempotencyAction::Conflict(format!(
                        "idempotency key {:?} was previously cancelled in state DB",
                        idempotency_key
                    )),
                };
            }
        }

        // 3. First-time seen: assign fresh TransferId and record as Active
        let new_id = TransferId::generate();
        if let Ok(mut guard) = self.entries.write() {
            let now = Instant::now();
            guard.insert(
                key,
                LedgerEntry {
                    transfer_id: new_id,
                    role,
                    idempotency_key: idempotency_key.to_string(),
                    remote_path: remote_path.to_string(),
                    expected_size,
                    status: TransferStatus::Active,
                    created_at: now,
                    updated_at: now,
                    committed_files: None,
                },
            );
        }

        IdempotencyAction::ProceedNew(new_id)
    }

    /// Mark an existing transfer as successfully committed.
    pub fn mark_committed(&self, role: Role, idempotency_key: &str, files: u32) {
        if let Ok(mut guard) = self.entries.write() {
            if let Some(entry) = guard.get_mut(&(role, idempotency_key.to_string())) {
                entry.status = TransferStatus::Committed;
                entry.committed_files = Some(files);
                entry.updated_at = Instant::now();
            }
        }
    }

    /// Mark an existing transfer as resumable (e.g. after graceful drain or client disconnect).
    pub fn mark_resumable(&self, role: Role, idempotency_key: &str) {
        if let Ok(mut guard) = self.entries.write() {
            if let Some(entry) = guard.get_mut(&(role, idempotency_key.to_string())) {
                entry.status = TransferStatus::Resumable;
                entry.updated_at = Instant::now();
            }
        }
    }

    /// Mark an existing transfer as cancelled.
    pub fn mark_cancelled(&self, role: Role, idempotency_key: &str) {
        if let Ok(mut guard) = self.entries.write() {
            if let Some(entry) = guard.get_mut(&(role, idempotency_key.to_string())) {
                entry.status = TransferStatus::Cancelled;
                entry.updated_at = Instant::now();
            }
        }
    }

    /// Return total active entries in the ledger.
    pub fn active_count(&self) -> usize {
        self.entries
            .read()
            .map(|g| {
                g.values()
                    .filter(|e| e.status == TransferStatus::Active)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Return total tracked entries (active, committed, resumable).
    pub fn total_count(&self) -> usize {
        self.entries.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Prune completed or cancelled entries older than `ttl`. Active transfers are never pruned.
    pub fn prune_older_than(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        if let Ok(mut guard) = self.entries.write() {
            let initial = guard.len();
            guard.retain(|_, entry| {
                if entry.status == TransferStatus::Active {
                    true
                } else {
                    now.duration_since(entry.updated_at) < ttl
                }
            });
            initial - guard.len()
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{MockStateStore, TransferRecord};

    #[test]
    fn test_idempotency_new_and_replay_active() {
        let ledger = IdempotencyLedger::new();
        let role = Role::Server;
        let key = "tx-1234";
        let path = "test/file.bin";
        let size = 1024 * 1024;

        // First attempt -> ProceedNew
        let action1 = ledger.evaluate_transfer_create(role, key, path, size, None);
        let id1 = match action1 {
            IdempotencyAction::ProceedNew(id) => id,
            other => panic!("expected ProceedNew, got: {other:?}"),
        };

        // Second attempt with same parameters -> ReplayActive(id1)
        let action2 = ledger.evaluate_transfer_create(role, key, path, size, None);
        assert_eq!(action2, IdempotencyAction::ReplayActive(id1));
        assert_eq!(ledger.active_count(), 1);
    }

    #[test]
    fn test_idempotency_committed_replay() {
        let ledger = IdempotencyLedger::new();
        let role = Role::Server;
        let key = "tx-commit";
        let path = "data/log.gz";
        let size = 5000;

        let action = ledger.evaluate_transfer_create(role, key, path, size, None);
        let id = match action {
            IdempotencyAction::ProceedNew(id) => id,
            other => panic!("expected ProceedNew, got: {other:?}"),
        };

        // Mark committed
        ledger.mark_committed(role, key, 1);

        // Subsequent retry -> ReplayCommitted
        let retry = ledger.evaluate_transfer_create(role, key, path, size, None);
        assert_eq!(
            retry,
            IdempotencyAction::ReplayCommitted {
                transfer_id: id,
                files: 1
            }
        );
    }

    #[test]
    fn test_idempotency_mismatched_parameters_conflict() {
        let ledger = IdempotencyLedger::new();
        let role = Role::Server;
        let key = "tx-conflict";

        let _ = ledger.evaluate_transfer_create(role, key, "path/a.bin", 1000, None);

        // Mismatched path
        let err_path = ledger.evaluate_transfer_create(role, key, "path/b.bin", 1000, None);
        assert!(matches!(err_path, IdempotencyAction::Conflict(_)));

        // Mismatched size
        let err_size = ledger.evaluate_transfer_create(role, key, "path/a.bin", 2000, None);
        assert!(matches!(err_size, IdempotencyAction::Conflict(_)));
    }

    #[test]
    fn test_fallback_to_persistent_state_store() {
        let mock_store = MockStateStore::new();
        let role = Role::Server;
        let key = "tx-db";
        let id = TransferId::generate();

        let rec = TransferRecord {
            transfer_id: id,
            idempotency_key: key.to_string(),
            role,
            direction: crate::state::Direction::Upload,
            status: TransferStatus::Resumable,
            remote_path: "persisted/file.txt".to_string(),
            local_path: String::new(),
            file_size: 4096,
            file_hash: crate::util::Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 2000,
            bytes_completed: 2048,
            staging_relpath: "staging/file.tmp".to_string(),
            created_ms: 1000,
            updated_ms: 2000,
        };
        mock_store.upsert_transfer(&rec).unwrap();

        let ledger = IdempotencyLedger::new();
        let action = ledger.evaluate_transfer_create(
            role,
            key,
            "persisted/file.txt",
            4096,
            Some(&mock_store),
        );

        assert_eq!(
            action,
            IdempotencyAction::ResumeExisting {
                transfer_id: id,
                bytes_completed: 2048,
            }
        );
    }
}
