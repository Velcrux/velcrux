use tempfile::tempdir;

use velcrux_core::chunking::{ChunkMode, ChunkParams};
use velcrux_core::state::{CommitJournalEntry, CommitStatus, SqliteStateStore, StateStore};
use velcrux_core::sync::{
    execute_directory_sync, plan_directory_sync, resume_interrupted_commit, DeleteMode,
    DirectorySyncOptions,
};
use velcrux_core::util::TransferId;

#[test]
fn test_commit_journal_resumes_interrupted_commit() {
    // Exit test for Milestone 9: "Commit journal resumes an interrupted COMMIT"
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("state.db");
    let state = SqliteStateStore::new(&db_path).unwrap();

    let dst_root = temp.path().join("destination");
    let staging_root = temp.path().join("staging");
    std::fs::create_dir_all(&dst_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let tid = TransferId::generate();
    state
        .upsert_transfer(&velcrux_core::state::TransferRecord {
            transfer_id: tid,
            idempotency_key: format!("test-{}", tid),
            role: velcrux_core::state::Role::Client,
            direction: velcrux_core::state::Direction::Upload,
            status: velcrux_core::state::TransferStatus::Active,
            remote_path: "destination".into(),
            local_path: "source".into(),
            file_size: 1000,
            file_hash: velcrux_core::util::Hash::ZERO,
            verified_up_to: 0,
            last_checkpoint_ms: 0,
            bytes_completed: 0,
            staging_relpath: "staging".into(),
            created_ms: 1000,
            updated_ms: 1000,
        })
        .unwrap();

    // Prepare 4 files:
    // File 0: Already Committed prior to interruption
    // File 1: Renamed (moved into destination, but journal row was Renamed)
    // File 2: Pending in staging (needs atomic rename to destination root)
    // File 3: Pending in staging in a nested directory (needs parent dir creation + rename)

    let content0 = b"file 0 - already committed";
    let content1 = b"file 1 - renamed before crash";
    let content2 = b"file 2 - pending in staging root";
    let content3 = b"file 3 - pending in nested staging directory";

    // Setup File 0: in dst_root, marked Committed
    std::fs::write(dst_root.join("f0.txt"), content0).unwrap();
    state
        .write_journal(&CommitJournalEntry {
            transfer_id: tid,
            file_id: 0,
            remote_path: "f0.txt".into(),
            status: CommitStatus::Committed,
            updated_ms: 1000,
        })
        .unwrap();

    // Setup File 1: in dst_root, marked Renamed (journal was behind when crash happened)
    std::fs::write(dst_root.join("f1.txt"), content1).unwrap();
    state
        .write_journal(&CommitJournalEntry {
            transfer_id: tid,
            file_id: 1,
            remote_path: "f1.txt".into(),
            status: CommitStatus::Renamed,
            updated_ms: 1001,
        })
        .unwrap();

    // Setup File 2: in staging_root, marked Pending
    std::fs::write(staging_root.join("f2.txt"), content2).unwrap();
    state
        .write_journal(&CommitJournalEntry {
            transfer_id: tid,
            file_id: 2,
            remote_path: "f2.txt".into(),
            status: CommitStatus::Pending,
            updated_ms: 1002,
        })
        .unwrap();

    // Setup File 3: in nested staging dir, marked Pending
    let staging_sub = staging_root.join("nested").join("deep");
    std::fs::create_dir_all(&staging_sub).unwrap();
    std::fs::write(staging_sub.join("f3.bin"), content3).unwrap();
    state
        .write_journal(&CommitJournalEntry {
            transfer_id: tid,
            file_id: 3,
            remote_path: "nested/deep/f3.bin".into(),
            status: CommitStatus::Pending,
            updated_ms: 1003,
        })
        .unwrap();

    // Verify initial pending journal state
    let pending_before = state.pending_journal().unwrap();
    assert_eq!(pending_before.len(), 3, "files 1, 2, and 3 are pending");

    // Perform recovery
    let resumed_count =
        resume_interrupted_commit(&state, &staging_root, &dst_root, Some(tid)).unwrap();
    assert_eq!(resumed_count, 3, "should have finalized 3 pending files");

    // Verify destination filesystem has all 4 files intact
    assert_eq!(std::fs::read(dst_root.join("f0.txt")).unwrap(), content0);
    assert_eq!(std::fs::read(dst_root.join("f1.txt")).unwrap(), content1);
    assert_eq!(std::fs::read(dst_root.join("f2.txt")).unwrap(), content2);
    assert_eq!(
        std::fs::read(dst_root.join("nested/deep/f3.bin")).unwrap(),
        content3
    );

    // Staged pending files should have been moved
    assert!(!staging_root.join("f2.txt").exists());
    assert!(!staging_sub.join("f3.bin").exists());

    // Verify state store has zero pending entries left
    let pending_after = state.pending_journal().unwrap();
    assert!(
        pending_after.is_empty(),
        "commit journal should have zero pending rows after resume"
    );
}

#[test]
fn test_directory_sync_dry_run_leaves_destination_untouched() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // 1. Unchanged file
    std::fs::write(src.join("unchanged.txt"), b"same content").unwrap();
    std::fs::write(dst.join("unchanged.txt"), b"same content").unwrap();

    // 2. Modified file
    std::fs::write(src.join("modified.txt"), b"new version of content").unwrap();
    std::fs::write(dst.join("modified.txt"), b"old version").unwrap();

    // 3. Added file
    std::fs::write(src.join("added.txt"), b"brand new file content").unwrap();

    // 4. Extraneous file on destination
    std::fs::write(dst.join("extraneous.txt"), b"should be deleted if delete-after").unwrap();

    let options = DirectorySyncOptions {
        mode: ChunkMode::Fixed,
        params: ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap(),
        delete_mode: DeleteMode::DeleteAfter,
        dry_run: true,
        read_buffer_size: 64 * 1024,
    };

    let result = execute_directory_sync(&src, &dst, &options, None, None).unwrap();

    let summary = &result.plan.summary;
    assert_eq!(summary.files_unchanged, 1);
    assert_eq!(summary.files_modified, 1);
    assert_eq!(summary.files_added, 1);
    assert_eq!(summary.files_deleted, 1);
    assert!(summary.data_present > 0);
    assert!(summary.data_to_transfer > 0);
    assert!(summary.estimated_reduction > 0.0);

    // Format output check
    let display = summary.format_display();
    assert!(display.contains("Files unchanged:"));
    assert!(display.contains("Files modified:"));
    assert!(display.contains("Files added:"));
    assert!(display.contains("Files deleted:"));

    // Verify destination was NOT modified at all
    assert!(!dst.join("added.txt").exists());
    assert_eq!(std::fs::read(dst.join("modified.txt")).unwrap(), b"old version");
    assert!(dst.join("extraneous.txt").exists());
    assert_eq!(result.files_committed, 0);
    assert_eq!(result.files_transferred, 0);
}

#[test]
fn test_directory_sync_delete_modes() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("live.txt"), b"live data").unwrap();
    std::fs::write(dst.join("orphan.txt"), b"orphan data").unwrap();

    // 1. Run with DeleteMode::None (default safe)
    let options_none = DirectorySyncOptions {
        mode: ChunkMode::Fixed,
        params: ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap(),
        delete_mode: DeleteMode::None,
        dry_run: false,
        read_buffer_size: 64 * 1024,
    };
    let res1 = execute_directory_sync(&src, &dst, &options_none, None, None).unwrap();
    assert_eq!(res1.files_committed, 1);
    assert_eq!(res1.files_deleted, 0);
    assert!(dst.join("live.txt").exists());
    assert!(dst.join("orphan.txt").exists(), "orphan must NOT be deleted under DeleteMode::None");

    // 2. Run with DeleteMode::DeleteAfter
    let options_delete = DirectorySyncOptions {
        mode: ChunkMode::Fixed,
        params: ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap(),
        delete_mode: DeleteMode::DeleteAfter,
        dry_run: false,
        read_buffer_size: 64 * 1024,
    };
    let res2 = execute_directory_sync(&src, &dst, &options_delete, None, None).unwrap();
    assert_eq!(res2.files_deleted, 1);
    assert!(dst.join("live.txt").exists());
    assert!(!dst.join("orphan.txt").exists(), "orphan MUST be deleted under DeleteMode::DeleteAfter");
}

#[test]
fn test_directory_sync_delta_reuse_and_sqlite_journal() {
    let temp = tempdir().unwrap();
    let db_path = temp.path().join("journal.db");
    let state = SqliteStateStore::new(&db_path).unwrap();

    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // Create a 1 MiB base file
    let chunk_size = 64 * 1024;
    let mut base_data = vec![0u8; 1024 * 1024];
    for (i, b) in base_data.iter_mut().enumerate() {
        *b = ((i / chunk_size) % 251) as u8;
    }
    std::fs::write(dst.join("data.bin"), &base_data).unwrap();

    // Modify only one chunk in source (e.g. chunk 3)
    let mut modified_data = base_data.clone();
    for i in (3 * chunk_size)..(4 * chunk_size) {
        modified_data[i] = 0xEE;
    }
    std::fs::write(src.join("data.bin"), &modified_data).unwrap();

    // Add a second new file
    std::fs::write(src.join("new.txt"), b"new item").unwrap();

    let options = DirectorySyncOptions {
        mode: ChunkMode::Fixed,
        params: ChunkParams::new(chunk_size as u64, chunk_size as u64, chunk_size as u64).unwrap(),
        delete_mode: DeleteMode::None,
        dry_run: false,
        read_buffer_size: 64 * 1024,
    };

    let result = execute_directory_sync(&src, &dst, &options, Some(&state), None).unwrap();

    assert_eq!(result.files_committed, 2);
    // Delta reuse should have reused 15 out of 16 chunks from the existing destination file
    assert!(result.local_bytes_reused >= 15 * chunk_size as u64);
    assert!(result.wire_bytes_transferred <= 2 * chunk_size as u64 + 100);

    // Verify content on destination matches source exactly
    assert_eq!(std::fs::read(dst.join("data.bin")).unwrap(), modified_data);
    assert_eq!(std::fs::read(dst.join("new.txt")).unwrap(), b"new item");

    // Verify commit journal rows were logged and all marked Committed
    assert!(state.pending_journal().unwrap().is_empty());
}

#[test]
fn test_stage_failure_leaves_destination_untouched() {
    // Requirements §61 & Architecture §9:
    // If transfer fails during STAGE or TRANSFER, the destination remains untouched.
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // Existing destination file
    let initial_content = b"original destination content that must not be altered";
    std::fs::write(dst.join("target.txt"), initial_content).unwrap();

    // Source has a file with different content
    std::fs::write(src.join("target.txt"), b"new source content").unwrap();

    // Also an added file on source
    std::fs::write(src.join("added.txt"), b"added content").unwrap();

    // Verify initial destination state
    assert_eq!(std::fs::read(dst.join("target.txt")).unwrap(), initial_content);
    assert!(!dst.join("added.txt").exists());

    // Compute plan
    let options = DirectorySyncOptions {
        mode: ChunkMode::Fixed,
        params: ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap(),
        delete_mode: DeleteMode::None,
        dry_run: false,
        read_buffer_size: 64 * 1024,
    };

    let plan = plan_directory_sync(&src, &dst, &options, None).unwrap();
    assert_eq!(plan.summary.files_modified, 1);
    assert_eq!(plan.summary.files_added, 1);

    // Now simulate failure during STAGE by making a file unreadable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            src.join("added.txt"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();

        // Execution should fail during stage/transfer
        let exec_res = execute_directory_sync(&src, &dst, &options, None, None);
        assert!(exec_res.is_err(), "must error when staging fails");

        // CRITICAL: Destination MUST remain completely untouched!
        assert_eq!(
            std::fs::read(dst.join("target.txt")).unwrap(),
            initial_content,
            "destination file must remain untouched after staging failure"
        );
        assert!(
            !dst.join("added.txt").exists(),
            "added file must not exist on destination after staging failure"
        );

        // Restore permissions for cleanup
        let _ = std::fs::set_permissions(
            src.join("added.txt"),
            std::fs::Permissions::from_mode(0o644),
        );
    }
}

