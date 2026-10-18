//! Integration tests for whole-directory transactional commit and rollback journaling (Option BM).

use std::fs;
use tempfile::tempdir;

use velcrux_core::sync::{
    execute_atomic_directory_sync, DeleteMode, DirectorySyncOptions, DirectoryTransaction,
    TransactionAction, TransactionItem, TransactionJournal, TransactionManager, TransactionState,
};
use velcrux_core::util::Hash;

#[test]
fn test_atomic_directory_sync_success_multi_file() {
    let src_dir = tempdir().unwrap();
    let dst_dir = tempdir().unwrap();

    let src = src_dir.path();
    let dst = dst_dir.path();

    // Baseline: dst has existing fileA.txt and old_delete.txt
    fs::write(dst.join("fileA.txt"), b"initial file A").unwrap();
    fs::write(dst.join("old_delete.txt"), b"to be deleted").unwrap();

    // Source has updated fileA.txt, brand new fileB.txt, and sub/fileC.txt
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("fileA.txt"), b"updated file A payload").unwrap();
    fs::write(src.join("fileB.txt"), b"new file B payload").unwrap();
    fs::write(src.join("sub/fileC.txt"), b"nested file C").unwrap();

    let options = DirectorySyncOptions::default()
        .with_delete_mode(DeleteMode::DeleteAfter)
        .with_atomic(true);

    let res = execute_atomic_directory_sync(src, dst, &options, None, None).unwrap();

    assert!(res.transaction_id.is_some());
    assert_eq!(res.files_committed, 3);
    assert_eq!(res.files_deleted, 1);

    // Verify destination contents
    assert_eq!(
        fs::read(dst.join("fileA.txt")).unwrap(),
        b"updated file A payload"
    );
    assert_eq!(
        fs::read(dst.join("fileB.txt")).unwrap(),
        b"new file B payload"
    );
    assert_eq!(
        fs::read(dst.join("sub/fileC.txt")).unwrap(),
        b"nested file C"
    );
    assert!(!dst.join("old_delete.txt").exists());

    // Verify shadow directory cleaned up
    let shadow_base = dst.join(".velcrux-shadow");
    if shadow_base.exists() {
        assert_eq!(fs::read_dir(shadow_base).unwrap().count(), 0);
    }

    // Verify transaction list contains committed record
    let tx_list = TransactionManager::list_transactions(dst).unwrap();
    assert_eq!(tx_list.len(), 1);
    assert_eq!(tx_list[0].state, TransactionState::Committed);
    assert_eq!(tx_list[0].file_count, 4); // 3 files + 1 deletion
}

#[test]
fn test_atomic_directory_sync_rollback_restores_baseline() {
    let src_dir = tempdir().unwrap();
    let dst_dir = tempdir().unwrap();

    let src = src_dir.path();
    let dst = dst_dir.path();

    // Baseline on destination
    fs::write(dst.join("original.txt"), b"original baseline data").unwrap();
    fs::write(dst.join("do_not_lose.dat"), b"critical production data").unwrap();

    // Source has updated original.txt and new extra.txt
    fs::write(src.join("original.txt"), b"modified content").unwrap();
    fs::write(src.join("extra.txt"), b"extra content").unwrap();

    let options = DirectorySyncOptions::default().with_atomic(true);
    let res = execute_atomic_directory_sync(src, dst, &options, None, None).unwrap();
    let tx_id = res.transaction_id.expect("tx_id present");

    // Live destination has new contents
    assert_eq!(
        fs::read(dst.join("original.txt")).unwrap(),
        b"modified content"
    );
    assert_eq!(fs::read(dst.join("extra.txt")).unwrap(), b"extra content");

    // Now roll back the transaction!
    let report = TransactionManager::rollback_transaction(dst, &tx_id).unwrap();
    assert_eq!(report.state, TransactionState::RolledBack);
    assert_eq!(report.files_rolled_back, 2);

    // Destination must be exactly restored to original baseline!
    assert_eq!(
        fs::read(dst.join("original.txt")).unwrap(),
        b"original baseline data"
    );
    assert_eq!(
        fs::read(dst.join("do_not_lose.dat")).unwrap(),
        b"critical production data"
    );
    assert!(!dst.join("extra.txt").exists());
}

#[test]
fn test_transaction_hash_verification_aborts_without_mutating_target() {
    let dir = tempdir().unwrap();
    let target = dir.path();

    fs::write(target.join("important.txt"), b"unmodified baseline").unwrap();

    let mut tx = DirectoryTransaction::begin(target).unwrap();

    // Stage a file with an expected hash that does not match corrupted data
    let wrong_hash = Hash::of(b"expected correct data");
    tx.stage_file_bytes("important.txt", b"corrupted payload", Some(wrong_hash))
        .unwrap();

    // Prepare phase should detect hash mismatch and fail
    let err = tx.prepare().unwrap_err();
    assert!(err.to_string().contains("checksum verification failed"));

    // Target directory must remain 100% untouched
    assert_eq!(
        fs::read(target.join("important.txt")).unwrap(),
        b"unmodified baseline"
    );
}

#[test]
fn test_transaction_manager_crash_recovery_of_committing_state() {
    let dir = tempdir().unwrap();
    let target = dir.path();

    // Original target state
    fs::write(target.join("config.json"), b"{\"version\": 1}").unwrap();

    let tx_id = "tx_crash_sim_100";
    let shadow_root = target.join(".velcrux-shadow").join(tx_id);
    let backup_root = target.join(".velcrux-backup").join(tx_id);
    let journal_dir = target.join(".velcrux-journal");
    fs::create_dir_all(&shadow_root).unwrap();
    fs::create_dir_all(&backup_root).unwrap();
    fs::create_dir_all(&journal_dir).unwrap();

    // Put original backup in place
    fs::write(backup_root.join("config.json"), b"{\"version\": 1}").unwrap();
    // Simulate crash where new file was half-renamed or updated
    fs::write(target.join("config.json"), b"{\"version\": 2_corrupted}").unwrap();
    fs::write(target.join("half_committed.dat"), b"should be removed").unwrap();

    let items = vec![
        TransactionItem {
            rel_path: "config.json".to_string(),
            action: TransactionAction::Update,
            shadow_path: Some(shadow_root.join("config.json")),
            backup_path: Some(backup_root.join("config.json")),
            dest_path: target.join("config.json"),
            expected_hash: None,
            original_hash: Some(Hash::of(b"{\"version\": 1}")),
            size: 14,
            applied: true,
        },
        TransactionItem {
            rel_path: "half_committed.dat".to_string(),
            action: TransactionAction::Create,
            shadow_path: Some(shadow_root.join("half_committed.dat")),
            backup_path: None,
            dest_path: target.join("half_committed.dat"),
            expected_hash: None,
            original_hash: None,
            size: 17,
            applied: true,
        },
    ];

    let journal = TransactionJournal {
        tx_id: tx_id.to_string(),
        target_dir: target.to_path_buf(),
        shadow_root: shadow_root.clone(),
        backup_root: backup_root.clone(),
        state: TransactionState::Committing, // Interrupted mid-commit!
        created_at_sec: 1700000000,
        updated_at_sec: 1700000005,
        items,
    };

    let journal_json = serde_json::to_string_pretty(&journal).unwrap();
    fs::write(journal_dir.join(format!("{}.json", tx_id)), journal_json).unwrap();

    // Run crash recovery
    let reports = TransactionManager::recover_pending_transactions(target).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].tx_id, tx_id);
    assert_eq!(reports[0].state, TransactionState::RolledBack);

    // Verify target is restored to baseline!
    assert_eq!(
        fs::read(target.join("config.json")).unwrap(),
        b"{\"version\": 1}"
    );
    assert!(!target.join("half_committed.dat").exists());
}
