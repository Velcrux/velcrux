//! In-memory `StateStore` for deterministic tests.
//!
//! `ADR-005` and the user-confirmed design call for SQLite as the
//! production backend; this implementation exists so unit tests can
//! exercise the engine's interaction with the state seam without
//! touching the filesystem. It is not a second backend.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::util::TransferId;

use super::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, JournalRecovery, Role, StateStore,
    StateStoreError, StateStoreResult, TransferRecord, TransferStatus, UpsertOutcome,
};

/// In-memory state store. All operations are serialized through a
/// `Mutex`; this is correct for the test usage we need (single-threaded
/// test bodies driving one transfer at a time) and avoids the test
/// flakiness of a real concurrent map.
pub struct MockStateStore {
    inner: Mutex<Inner>,
}

struct Inner {
    transfers_by_id: HashMap<TransferId, TransferRecord>,
    idem_index: HashMap<(Role, String), TransferId>,
    bitmaps: HashMap<TransferId, ChunkBitmap>,
    journal: HashMap<(TransferId, u64), CommitJournalEntry>,
}

impl MockStateStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                transfers_by_id: HashMap::new(),
                idem_index: HashMap::new(),
                bitmaps: HashMap::new(),
                journal: HashMap::new(),
            }),
        }
    }
}

impl Default for MockStateStore {
    fn default() -> Self {
        Self::new()
    }
}

fn verify_idempotency_compat(
    existing: &TransferRecord,
    request: &TransferRecord,
) -> StateStoreResult<()> {
    // Same key, same role: a retry must match the durable identity
    // fields. The implementation is intentionally strict — we do not
    // want a different file_size / hash / direction to be silently
    // accepted under the same idempotency key. This is a defence
    // against accidental key reuse.
    if existing.role != request.role
        || existing.direction != request.direction
        || existing.remote_path != request.remote_path
        || existing.local_path != request.local_path
        || existing.file_size != request.file_size
        || existing.file_hash != request.file_hash
    {
        return Err(StateStoreError::IdempotencyConflict(format!(
            "idempotency key '{}' already used by transfer {} with different parameters",
            request.idempotency_key, existing.transfer_id
        )));
    }
    Ok(())
}

impl StateStore for MockStateStore {
    fn upsert_transfer(&self, record: &TransferRecord) -> StateStoreResult<UpsertOutcome> {
        let mut g = self.inner.lock().unwrap();
        if let Some(existing_id) = g
            .idem_index
            .get(&(record.role, record.idempotency_key.clone()))
        {
            let existing = g.transfers_by_id.get(existing_id).cloned().ok_or_else(|| {
                StateStoreError::Corrupt("idempotency index points at missing transfer".into())
            })?;
            verify_idempotency_compat(&existing, record)?;
            return Ok(UpsertOutcome::Reused(existing));
        }
        g.transfers_by_id.insert(record.transfer_id, record.clone());
        g.idem_index.insert(
            (record.role, record.idempotency_key.clone()),
            record.transfer_id,
        );
        Ok(UpsertOutcome::Inserted)
    }

    fn update_transfer(&self, record: &TransferRecord) -> StateStoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        if !g.transfers_by_id.contains_key(&record.transfer_id) {
            return Err(StateStoreError::NotFound);
        }
        g.transfers_by_id.insert(record.transfer_id, record.clone());
        g.idem_index.insert(
            (record.role, record.idempotency_key.clone()),
            record.transfer_id,
        );
        Ok(())
    }

    fn get_transfer(&self, transfer_id: TransferId) -> StateStoreResult<TransferRecord> {
        let g = self.inner.lock().unwrap();
        g.transfers_by_id
            .get(&transfer_id)
            .cloned()
            .ok_or(StateStoreError::NotFound)
    }

    fn get_transfer_by_idempotency(
        &self,
        role: Role,
        idempotency_key: &str,
    ) -> StateStoreResult<TransferRecord> {
        let g = self.inner.lock().unwrap();
        let id = g
            .idem_index
            .get(&(role, idempotency_key.to_string()))
            .copied()
            .ok_or(StateStoreError::NotFound)?;
        g.transfers_by_id
            .get(&id)
            .cloned()
            .ok_or(StateStoreError::NotFound)
    }

    fn list_transfers_by_path(
        &self,
        role: Role,
        path_prefix: &str,
    ) -> StateStoreResult<Vec<TransferRecord>> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<TransferRecord> = g
            .transfers_by_id
            .values()
            .filter(|r| r.role == role && r.remote_path.starts_with(path_prefix))
            .cloned()
            .collect();
        out.sort_by_key(|r| r.created_ms);
        Ok(out)
    }

    fn write_bitmap(&self, transfer_id: TransferId, bitmap: &ChunkBitmap) -> StateStoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        if !g.transfers_by_id.contains_key(&transfer_id) {
            return Err(StateStoreError::NotFound);
        }
        g.bitmaps.insert(transfer_id, bitmap.clone());
        Ok(())
    }

    fn read_bitmap(&self, transfer_id: TransferId) -> StateStoreResult<ChunkBitmap> {
        let g = self.inner.lock().unwrap();
        if !g.transfers_by_id.contains_key(&transfer_id) {
            return Err(StateStoreError::NotFound);
        }
        g.bitmaps
            .get(&transfer_id)
            .cloned()
            .ok_or(StateStoreError::NotFound)
    }

    fn delete_bitmap(&self, transfer_id: TransferId) -> StateStoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        g.bitmaps.remove(&transfer_id);
        Ok(())
    }

    fn write_journal(&self, entry: &CommitJournalEntry) -> StateStoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        g.journal
            .insert((entry.transfer_id, entry.file_id), entry.clone());
        Ok(())
    }

    fn pending_journal(&self) -> StateStoreResult<Vec<CommitJournalEntry>> {
        let g = self.inner.lock().unwrap();
        Ok(g.journal
            .values()
            .filter(|e| e.status != CommitStatus::Committed)
            .cloned()
            .collect())
    }

    fn mark_journal_committed(
        &self,
        transfer_id: TransferId,
        file_id: u64,
    ) -> StateStoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        let entry = g
            .journal
            .get_mut(&(transfer_id, file_id))
            .ok_or(StateStoreError::NotFound)?;
        entry.status = CommitStatus::Committed;
        Ok(())
    }

    fn delete_transfer(&self, transfer_id: TransferId) -> StateStoreResult<()> {
        let mut g = self.inner.lock().unwrap();
        let record = g.transfers_by_id.remove(&transfer_id);
        if let Some(r) = record {
            g.idem_index.remove(&(r.role, r.idempotency_key));
        }
        g.bitmaps.remove(&transfer_id);
        let keys: Vec<_> = g
            .journal
            .keys()
            .copied()
            .filter(|(tid, _)| *tid == transfer_id)
            .collect();
        for k in keys {
            g.journal.remove(&k);
        }
        Ok(())
    }

    fn recover_commit_journal(&self) -> StateStoreResult<Vec<JournalRecovery>> {
        let g = self.inner.lock().unwrap();
        Ok(g.journal
            .values()
            .filter(|e| e.status != CommitStatus::Committed)
            .map(|e| match e.status {
                CommitStatus::Renamed => JournalRecovery::Finalize {
                    transfer_id: e.transfer_id,
                    file_id: e.file_id,
                },
                CommitStatus::Pending => JournalRecovery::LeavePending {
                    transfer_id: e.transfer_id,
                    file_id: e.file_id,
                },
                CommitStatus::Committed => unreachable!(),
            })
            .collect())
    }

    fn mark_active_transfers_resumable(&self) -> StateStoreResult<usize> {
        let mut g = self.inner.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut count = 0;
        for r in g.transfers_by_id.values_mut() {
            if r.status == TransferStatus::Active {
                r.status = TransferStatus::Resumable;
                r.updated_ms = now;
                count += 1;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Direction, TransferStatus};
    use crate::util::Hash;

    fn rec(idem: &str, tid: TransferId) -> TransferRecord {
        TransferRecord {
            transfer_id: tid,
            idempotency_key: idem.into(),
            role: Role::Client,
            direction: Direction::Upload,
            status: TransferStatus::Active,
            remote_path: "data/x.bin".into(),
            local_path: "/tmp/x.bin".into(),
            file_size: 10,
            file_hash: Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 0,
            bytes_completed: 0,
            staging_relpath: String::new(),
            created_ms: 0,
            updated_ms: 0,
        }
    }

    #[test]
    fn upsert_inserts_then_reuses() {
        let s = MockStateStore::new();
        let tid = TransferId::generate();
        let r = rec("k", tid);
        match s.upsert_transfer(&r).unwrap() {
            UpsertOutcome::Inserted => {}
            other => panic!("first call should insert, got {:?}", other),
        }
        match s.upsert_transfer(&r).unwrap() {
            UpsertOutcome::Reused(got) => assert_eq!(got.transfer_id, tid),
            other => panic!("second call should reuse, got {:?}", other),
        }
    }

    #[test]
    fn upsert_rejects_mismatched_retry() {
        let s = MockStateStore::new();
        let tid = TransferId::generate();
        let mut r = rec("k", tid);
        s.upsert_transfer(&r).unwrap();
        r.file_size = 99;
        assert!(matches!(
            s.upsert_transfer(&r).unwrap_err(),
            StateStoreError::IdempotencyConflict(_)
        ));
    }

    #[test]
    fn update_not_found() {
        let s = MockStateStore::new();
        let r = rec("k", TransferId::generate());
        assert!(matches!(
            s.update_transfer(&r).unwrap_err(),
            StateStoreError::NotFound
        ));
    }

    #[test]
    fn bitmap_roundtrip() {
        let s = MockStateStore::new();
        let tid = TransferId::generate();
        s.upsert_transfer(&rec("k", tid)).unwrap();
        let mut bm = ChunkBitmap::new();
        bm.mark_complete(0, 1024);
        bm.mark_complete(7, 4096);
        s.write_bitmap(tid, &bm).unwrap();
        let read = s.read_bitmap(tid).unwrap();
        assert_eq!(read, bm);
    }

    #[test]
    fn journal_recovery_split() {
        let s = MockStateStore::new();
        let t1 = TransferId::generate();
        let t2 = TransferId::generate();
        s.write_journal(&CommitJournalEntry {
            transfer_id: t1,
            file_id: 1,
            remote_path: "a".into(),
            status: CommitStatus::Renamed,
            updated_ms: 0,
        })
        .unwrap();
        s.write_journal(&CommitJournalEntry {
            transfer_id: t2,
            file_id: 1,
            remote_path: "b".into(),
            status: CommitStatus::Pending,
            updated_ms: 0,
        })
        .unwrap();
        s.write_journal(&CommitJournalEntry {
            transfer_id: TransferId::generate(),
            file_id: 1,
            remote_path: "c".into(),
            status: CommitStatus::Committed,
            updated_ms: 0,
        })
        .unwrap();
        let rec = s.recover_commit_journal().unwrap();
        assert_eq!(rec.len(), 2);
        assert!(rec.iter().any(
            |r| matches!(r, JournalRecovery::Finalize { transfer_id, .. } if *transfer_id == t1)
        ));
        assert!(rec.iter().any(
            |r| matches!(r, JournalRecovery::LeavePending { transfer_id, .. } if *transfer_id == t2)
        ));
    }

    #[test]
    fn delete_transfer_removes_everything() {
        let s = MockStateStore::new();
        let tid = TransferId::generate();
        s.upsert_transfer(&rec("k", tid)).unwrap();
        let mut bm = ChunkBitmap::new();
        bm.mark_complete(0, 1);
        s.write_bitmap(tid, &bm).unwrap();
        s.write_journal(&CommitJournalEntry {
            transfer_id: tid,
            file_id: 1,
            remote_path: "x".into(),
            status: CommitStatus::Pending,
            updated_ms: 0,
        })
        .unwrap();
        s.delete_transfer(tid).unwrap();
        assert!(s.read_bitmap(tid).is_err());
        assert!(s.get_transfer(tid).is_err());
        assert!(s.get_transfer_by_idempotency(Role::Client, "k").is_err());
        assert!(s.pending_journal().unwrap().is_empty());
    }
}
