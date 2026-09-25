//! M3 state-store unit tests at the integration level.
//!
//! These exercise the production SQLite implementation end-to-end
//! (migrations, WAL durability, cascade delete, etc.) and the
//! M3-specific commitment journal split. The transfer-engine
//! round-trip and SIGKILL-resume tests live in `m3_resume.rs`.
//!
//! Coverage list (from the user-specified M3 testing plan):
//! - StateStore behavior (insert/get/update/recover)
//! - Checkpoint persistence/recovery (bitmap round-trip survives drop)
//! - Idempotent TRANSFER_CREATE (UNIQUE on (role, idempotency_key))
//! - Commit-journal recovery (Finalize vs LeavePending)

#![allow(clippy::needless_range_loop)]

use velcrux_core::state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, JournalRecovery, MockStateStore,
    Role, SqliteStateStore, StateStore, TransferRecord, TransferStatus, UpsertOutcome,
};
use velcrux_core::util::TransferId;
use velcrux_core::Hash;

fn sample(idem: &str, tid: TransferId) -> TransferRecord {
    let now = 1_000_000u64;
    TransferRecord {
        transfer_id: tid,
        idempotency_key: idem.into(),
        role: Role::Client,
        direction: Direction::Upload,
        status: TransferStatus::Active,
        remote_path: "data/x.bin".into(),
        local_path: "/tmp/x.bin".into(),
        file_size: 10_000_000,
        file_hash: Hash::of(b"hello"),
        verified_up_to: 0,
        last_checkpoint_ms: now,
        bytes_completed: 0,
        staging_relpath: String::new(),
        created_ms: now,
        updated_ms: now,
    }
}

fn tmp_path(name: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("velcrux-state-it-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

// MockStateStore unit coverage (deterministic, in-memory).
// ---------------------------------------------------------------------------

#[test]
fn mock_upsert_then_reuse() {
    let s = MockStateStore::new();
    let tid = TransferId::generate();
    let r = sample("k", tid);
    assert!(matches!(
        s.upsert_transfer(&r).unwrap(),
        UpsertOutcome::Inserted
    ));
    match s.upsert_transfer(&r).unwrap() {
        UpsertOutcome::Reused(got) => assert_eq!(got.transfer_id, tid),
        other => panic!("expected Reused, got {:?}", other),
    }
}

#[test]
fn mock_rejects_mismatched_retry() {
    let s = MockStateStore::new();
    let tid = TransferId::generate();
    let mut r = sample("k", tid);
    s.upsert_transfer(&r).unwrap();
    r.file_size = 99;
    assert!(matches!(
        s.upsert_transfer(&r).unwrap_err(),
        velcrux_core::StateStoreError::IdempotencyConflict(_)
    ));
}

#[test]
fn mock_bitmap_roundtrip() {
    let s = MockStateStore::new();
    let tid = TransferId::generate();
    s.upsert_transfer(&sample("k", tid)).unwrap();
    let mut bm = ChunkBitmap::new();
    bm.mark_complete(0, 1024);
    bm.mark_complete(7, 4096);
    s.write_bitmap(tid, &bm).unwrap();
    let read = s.read_bitmap(tid).unwrap();
    assert_eq!(read, bm);
}

#[test]
fn mock_journal_recovery_split() {
    let s = MockStateStore::new();
    let t1 = TransferId::generate();
    let t2 = TransferId::generate();
    s.upsert_transfer(&sample("k1", t1)).unwrap();
    s.upsert_transfer(&sample("k2", t2)).unwrap();
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
    let rec = s.recover_commit_journal().unwrap();
    assert_eq!(rec.len(), 2);
    assert!(
        matches!(
            rec[0],
            JournalRecovery::Finalize { transfer_id, .. } if transfer_id == t1
        ) || matches!(
            rec[1],
            JournalRecovery::Finalize { transfer_id, .. } if transfer_id == t1
        )
    );
    assert!(
        matches!(
            rec[0],
            JournalRecovery::LeavePending { transfer_id, .. } if transfer_id == t2
        ) || matches!(
            rec[1],
            JournalRecovery::LeavePending { transfer_id, .. } if transfer_id == t2
        )
    );
}

// SqliteStateStore integration coverage (WAL, persistence, cascade).
// ---------------------------------------------------------------------------

#[test]
fn sqlite_state_db_rejects_relative_path() {
    let p = std::path::PathBuf::from("relative.db");
    match SqliteStateStore::new(&p) {
        Err(velcrux_core::StateStoreError::Database(_)) => {}
        Err(other) => panic!("expected Database error, got {:?}", other),
        Ok(_) => panic!("expected error for relative path"),
    }
}

#[test]
fn sqlite_state_db_creates_at_absolute_path() {
    let p = tmp_path("create.db");
    let _ = std::fs::remove_file(&p);
    let s = SqliteStateStore::new(&p).unwrap();
    assert!(p.exists());
    assert!(s.path().is_absolute());
}

#[test]
fn sqlite_idempotency_unique_constraint() {
    let p = tmp_path("idem.db");
    let s = SqliteStateStore::new(&p).unwrap();
    let tid = TransferId::generate();
    let r = sample("key-1", tid);
    assert!(matches!(
        s.upsert_transfer(&r).unwrap(),
        UpsertOutcome::Inserted
    ));
    let mut r2 = r.clone();
    r2.file_size = 999;
    assert!(matches!(
        s.upsert_transfer(&r2).unwrap_err(),
        velcrux_core::StateStoreError::IdempotencyConflict(_)
    ));
    let r3 = sample("key-1", tid);
    match s.upsert_transfer(&r3).unwrap() {
        UpsertOutcome::Reused(got) => assert_eq!(got.transfer_id, tid),
        other => panic!("expected Reused, got {:?}", other),
    }
}

#[test]
fn sqlite_bitmap_replace_is_total() {
    let p = tmp_path("bm.db");
    let s = SqliteStateStore::new(&p).unwrap();
    let tid = TransferId::generate();
    s.upsert_transfer(&sample("k", tid)).unwrap();
    let mut bm = ChunkBitmap::new();
    bm.mark_complete(0, 1);
    bm.mark_complete(1, 1);
    s.write_bitmap(tid, &bm).unwrap();
    let mut bm2 = ChunkBitmap::new();
    bm2.mark_complete(5, 1);
    s.write_bitmap(tid, &bm2).unwrap();
    let read = s.read_bitmap(tid).unwrap();
    assert!(!read.contains(0));
    assert!(!read.contains(1));
    assert!(read.contains(5));
}

#[test]
fn sqlite_state_survives_drop_and_reopen() {
    let p = tmp_path("persist.db");
    let tid = TransferId::generate();
    {
        let s = SqliteStateStore::new(&p).unwrap();
        s.upsert_transfer(&sample("k", tid)).unwrap();
        let mut bm = ChunkBitmap::new();
        bm.mark_complete(7, 4096);
        s.write_bitmap(tid, &bm).unwrap();
    }
    let s2 = SqliteStateStore::new(&p).unwrap();
    let r = s2.get_transfer(tid).unwrap();
    assert_eq!(r.transfer_id, tid);
    let bm = s2.read_bitmap(tid).unwrap();
    assert!(bm.contains(7));
    assert_eq!(bm.bytes_completed(), 4096);
}

#[test]
fn sqlite_delete_cascades_to_bitmap_and_journal() {
    let p = tmp_path("cascade.db");
    let s = SqliteStateStore::new(&p).unwrap();
    let tid = TransferId::generate();
    s.upsert_transfer(&sample("k", tid)).unwrap();
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
    assert!(s.get_transfer(tid).is_err());
    assert!(s.read_bitmap(tid).is_err());
    assert!(s.pending_journal().unwrap().is_empty());
}

#[test]
fn sqlite_list_by_path_filters_and_orders() {
    let p = tmp_path("list.db");
    let s = SqliteStateStore::new(&p).unwrap();
    for (idem, path, ms) in [
        ("a", "data/a.bin", 10u64),
        ("b", "data/b.bin", 20),
        ("c", "other/c.bin", 5),
    ] {
        let mut r = sample(idem, TransferId::generate());
        r.remote_path = path.into();
        r.created_ms = ms;
        s.upsert_transfer(&r).unwrap();
    }
    let got = s.list_transfers_by_path(Role::Client, "data/").unwrap();
    assert_eq!(got.len(), 2);
    assert!(got[0].created_ms <= got[1].created_ms);
}

#[test]
fn sqlite_journal_recovery_split() {
    let p = tmp_path("jr.db");
    let s = SqliteStateStore::new(&p).unwrap();
    let t1 = TransferId::generate();
    let t2 = TransferId::generate();
    let t3 = TransferId::generate();
    s.upsert_transfer(&sample("k1", t1)).unwrap();
    s.upsert_transfer(&sample("k2", t2)).unwrap();
    s.upsert_transfer(&sample("k3", t3)).unwrap();
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
        transfer_id: t3,
        file_id: 1,
        remote_path: "c".into(),
        status: CommitStatus::Committed,
        updated_ms: 0,
    })
    .unwrap();
    let rec = s.recover_commit_journal().unwrap();
    assert_eq!(rec.len(), 2);
    assert!(rec.iter().any(|r| matches!(r,
        JournalRecovery::Finalize { transfer_id, .. } if *transfer_id == t1)));
    assert!(rec.iter().any(|r| matches!(r,
        JournalRecovery::LeavePending { transfer_id, .. } if *transfer_id == t2)));
}

// Checkpoint cadence constants: 1 GiB / 10 s.
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_cadence_constants() {
    use velcrux_core::protocol::limits::{CHECKPOINT_BYTES_INTERVAL, CHECKPOINT_TIME_INTERVAL_MS};
    assert_eq!(CHECKPOINT_BYTES_INTERVAL, 1u64 << 30, "1 GiB");
    assert_eq!(CHECKPOINT_TIME_INTERVAL_MS, 10_000, "10 s");
}

#[test]
fn mock_mark_active_transfers_resumable() {
    let s = MockStateStore::new();
    let t1 = TransferId::generate();
    let t2 = TransferId::generate();
    let mut r1 = sample("idem1", t1);
    r1.status = TransferStatus::Active;
    let mut r2 = sample("idem2", t2);
    r2.status = TransferStatus::Committed;
    s.upsert_transfer(&r1).unwrap();
    s.upsert_transfer(&r2).unwrap();

    let count = s.mark_active_transfers_resumable().unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        s.get_transfer(t1).unwrap().status,
        TransferStatus::Resumable
    );
    assert_eq!(
        s.get_transfer(t2).unwrap().status,
        TransferStatus::Committed
    );
}

#[test]
fn sqlite_mark_active_transfers_resumable() {
    let p = tmp_path("active_resumable.db");
    let s = SqliteStateStore::new(&p).unwrap();
    let t1 = TransferId::generate();
    let t2 = TransferId::generate();
    let t3 = TransferId::generate();
    let mut r1 = sample("idem1", t1);
    r1.status = TransferStatus::Active;
    let mut r2 = sample("idem2", t2);
    r2.status = TransferStatus::Active;
    let mut r3 = sample("idem3", t3);
    r3.status = TransferStatus::Committed;

    s.upsert_transfer(&r1).unwrap();
    s.upsert_transfer(&r2).unwrap();
    s.upsert_transfer(&r3).unwrap();

    let count = s.mark_active_transfers_resumable().unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        s.get_transfer(t1).unwrap().status,
        TransferStatus::Resumable
    );
    assert_eq!(
        s.get_transfer(t2).unwrap().status,
        TransferStatus::Resumable
    );
    assert_eq!(
        s.get_transfer(t3).unwrap().status,
        TransferStatus::Committed
    );
}
