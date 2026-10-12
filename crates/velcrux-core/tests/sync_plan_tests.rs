//! Integration tests for TransferPlan, PathFilter, and safe delete semantics (Option AV / REQUIREMENTS.md §57–§61).

use std::fs;
use tempfile::tempdir;

use velcrux_core::sync::{
    execute_directory_sync, plan_directory_sync, DeleteGuardrails, DeleteMode, DeleteSafetyError,
    DirectorySyncOptions, PathFilter, TransferPlan,
};

#[test]
fn test_transfer_plan_format_and_json() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("unchanged.txt"), b"unchanged").unwrap();
    fs::write(dst.join("unchanged.txt"), b"unchanged").unwrap();

    fs::write(src.join("modified.txt"), b"new-version").unwrap();
    fs::write(dst.join("modified.txt"), b"old-version").unwrap();

    fs::write(src.join("added.txt"), b"added").unwrap();
    fs::write(dst.join("extraneous.txt"), b"extraneous").unwrap();

    let options = DirectorySyncOptions::default().with_delete_mode(DeleteMode::DeleteAfter);
    let plan = plan_directory_sync(&src, &dst, &options, None).unwrap();

    let guardrails = DeleteGuardrails::default();
    let transfer_plan = TransferPlan::from_directory_plan(
        &src,
        &dst,
        &plan,
        DeleteMode::DeleteAfter,
        guardrails,
        0,
        true,
    );

    assert_eq!(transfer_plan.files_unchanged, 1);
    assert_eq!(transfer_plan.files_modified, 1);
    assert_eq!(transfer_plan.files_added, 1);
    assert_eq!(transfer_plan.files_deleted, 1);
    assert!(transfer_plan.dry_run);

    let display = transfer_plan.format_display();
    assert!(display.contains("VELCRUX TRANSFER PLAN"));
    assert!(display.contains("Files unchanged:"));
    assert!(display.contains("Files modified:"));
    assert!(display.contains("Files added:"));
    assert!(display.contains("Files deleted:"));

    let json_val = transfer_plan.to_json_value();
    assert_eq!(json_val["event"], "transfer_plan");
    assert_eq!(json_val["delete_mode"], "delete-after");
    assert_eq!(json_val["summary"]["files_unchanged"], 1);
    assert_eq!(json_val["summary"]["files_deleted"], 1);
}

#[test]
fn test_dry_run_leaves_destination_unmutated() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("file1.bin"), b"source-data-1").unwrap();
    fs::write(src.join("file2.bin"), b"source-data-2").unwrap();
    fs::write(dst.join("orphan.bin"), b"orphan-must-survive").unwrap();

    let options = DirectorySyncOptions::default()
        .with_dry_run(true)
        .with_delete_mode(DeleteMode::DeleteAfter);

    let res = execute_directory_sync(&src, &dst, &options, None, None).unwrap();

    assert_eq!(res.files_transferred, 0);
    assert_eq!(res.files_committed, 0);
    assert_eq!(res.files_deleted, 0);

    // Destination must remain completely unmutated
    assert!(!dst.join("file1.bin").exists());
    assert!(!dst.join("file2.bin").exists());
    assert!(dst.join("orphan.bin").exists());
    assert_eq!(
        fs::read(dst.join("orphan.bin")).unwrap(),
        b"orphan-must-survive"
    );
}

#[test]
fn test_delete_before_mode() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("new_file.txt"), b"payload").unwrap();
    fs::write(dst.join("obsolete.txt"), b"old-payload").unwrap();

    let options = DirectorySyncOptions::default().with_delete_mode(DeleteMode::DeleteBefore);

    let res = execute_directory_sync(&src, &dst, &options, None, None).unwrap();

    assert_eq!(res.files_committed, 1);
    assert_eq!(res.files_deleted, 1);
    assert!(dst.join("new_file.txt").exists());
    assert!(!dst.join("obsolete.txt").exists());
}

#[test]
fn test_delete_excluded_mode() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    // Source files
    fs::write(src.join("app.rs"), b"main code").unwrap();
    fs::write(src.join("debug.log"), b"temporary log").unwrap();

    // Destination files
    fs::write(dst.join("app.rs"), b"main code").unwrap();
    fs::write(dst.join("debug.log"), b"old log on dest").unwrap();
    fs::write(dst.join("cache.tmp"), b"temp cache").unwrap();

    let mut filter = PathFilter::new();
    filter.add_exclude("*.log");
    filter.add_exclude("*.tmp");

    let options = DirectorySyncOptions::default()
        .with_delete_mode(DeleteMode::DeleteExcluded)
        .with_filter(filter);

    let res = execute_directory_sync(&src, &dst, &options, None, None).unwrap();

    // app.rs is unchanged
    assert!(dst.join("app.rs").exists());
    // debug.log and cache.tmp match exclusion filter and must be deleted under DeleteExcluded
    assert!(!dst.join("debug.log").exists());
    assert!(!dst.join("cache.tmp").exists());
    assert_eq!(res.files_deleted, 2);
}

#[test]
fn test_delete_guardrails_abort_excessive_deletions() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("file1.txt"), b"data1").unwrap();

    // Destination has 5 extraneous files
    for i in 1..=5 {
        fs::write(dst.join(format!("orphan_{i}.txt")), b"orphan").unwrap();
    }

    // Guardrail: max 2 deletions allowed
    let guardrails = DeleteGuardrails::default()
        .with_max_delete_files(Some(2))
        .with_force_delete(false);

    let options = DirectorySyncOptions::default()
        .with_delete_mode(DeleteMode::DeleteAfter)
        .with_delete_guardrails(guardrails);

    let err = execute_directory_sync(&src, &dst, &options, None, None).unwrap_err();

    match err {
        velcrux_core::sync::SyncError::DeleteSafety(DeleteSafetyError::MaxFilesExceeded {
            attempted,
            limit,
        }) => {
            assert_eq!(attempted, 5);
            assert_eq!(limit, 2);
        }
        other => panic!("expected MaxFilesExceeded error, got: {other:?}"),
    }

    // Destination must remain intact (none of the 5 files deleted)
    for i in 1..=5 {
        assert!(dst.join(format!("orphan_{i}.txt")).exists());
    }
}

#[test]
fn test_delete_guardrails_force_delete_override() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();

    fs::write(src.join("file1.txt"), b"data1").unwrap();

    for i in 1..=4 {
        fs::write(dst.join(format!("orphan_{i}.txt")), b"orphan").unwrap();
    }

    // Max 1 delete, but force_delete is true
    let guardrails = DeleteGuardrails::default()
        .with_max_delete_files(Some(1))
        .with_force_delete(true);

    let options = DirectorySyncOptions::default()
        .with_delete_mode(DeleteMode::DeleteAfter)
        .with_delete_guardrails(guardrails);

    let res = execute_directory_sync(&src, &dst, &options, None, None).unwrap();
    assert_eq!(res.files_deleted, 4);

    for i in 1..=4 {
        assert!(!dst.join(format!("orphan_{i}.txt")).exists());
    }
}

#[test]
fn test_path_filter_patterns() {
    let mut filter = PathFilter::new();
    filter.add_exclude("*.bak");
    filter.add_exclude("build/**");
    filter.add_exclude("node_modules/*");
    filter.add_include("build/critical.bin");

    assert!(filter.is_excluded("file.bak"));
    assert!(filter.is_excluded("deep/nested/file.bak"));
    assert!(filter.is_excluded("build/sub/artifact.o"));
    assert!(!filter.is_excluded("build/critical.bin"));
    assert!(filter.is_excluded("node_modules/lodash"));
    assert!(!filter.is_excluded("src/lib.rs"));
}
