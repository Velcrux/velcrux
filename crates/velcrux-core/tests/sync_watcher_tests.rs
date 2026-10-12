//! Integration tests for real-time continuous file watcher and synchronization engine (Option AZ).

use std::fs;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;

use velcrux_core::sync::{ContinuousSyncCoordinator, WatchConfig};

#[tokio::test]
async fn test_watcher_nested_directories_and_changes() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    // Create initial directory structure
    let sub = root.join("nested").join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join("base.txt"), b"initial baseline").unwrap();

    let config = WatchConfig::new()
        .with_debounce(Duration::from_millis(50))
        .with_poll_interval(Duration::from_millis(20))
        .with_exclude("*.ignored")
        .with_max_batches(1);

    let mut coordinator = ContinuousSyncCoordinator::new(root.clone(), config).unwrap();

    // Add a new file inside nested directory
    fs::write(sub.join("new_file.dat"), b"newly created payload").unwrap();
    // Add an ignored file which should not trigger an event
    fs::write(sub.join("test.ignored"), b"should be skipped").unwrap();

    let batches = Arc::new(Mutex::new(Vec::new()));
    let b_clone = batches.clone();

    let summary = coordinator
        .run_continuous(|batch| {
            let b = batch.clone();
            let list = b_clone.clone();
            let count = batch.total_changes;
            async move {
                list.lock().unwrap().push(b);
                Ok(count)
            }
        })
        .await
        .unwrap();

    assert_eq!(summary.total_batches, 1);
    let captured = batches.lock().unwrap();
    assert_eq!(captured.len(), 1);
    let b = &captured[0];
    assert_eq!(b.created, vec!["nested/sub/new_file.dat"]);
    assert!(b.modified.is_empty());
    assert!(b.deleted.is_empty());
}

#[tokio::test]
async fn test_watcher_rapid_coalescing_and_ephemeral_files() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let config = WatchConfig::new()
        .with_debounce(Duration::from_millis(150))
        .with_poll_interval(Duration::from_millis(20))
        .with_max_batches(1);

    let mut coordinator = ContinuousSyncCoordinator::new(root.clone(), config).unwrap();

    // Spawn background task simulating live rapid edits across polling sweeps
    let rapid_file = root.join("rapid.log");
    tokio::spawn(async move {
        // First write: detected on scan 1
        fs::write(&rapid_file, b"version 1").unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Second write: detected on scan 2, coalesced with first
        fs::write(&rapid_file, b"version 2 longer content").unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Third write: detected on scan 3, coalesced with earlier
        fs::write(&rapid_file, b"version 3 final content").unwrap();
    });

    let batches = Arc::new(Mutex::new(Vec::new()));
    let b_clone = batches.clone();

    let summary = coordinator
        .run_continuous(|batch| {
            let b = batch.clone();
            let list = b_clone.clone();
            let count = batch.total_changes;
            async move {
                list.lock().unwrap().push(b);
                Ok(count)
            }
        })
        .await
        .unwrap();

    assert_eq!(summary.total_batches, 1);
    let captured = batches.lock().unwrap();
    assert_eq!(captured.len(), 1);
    let b = &captured[0];
    assert_eq!(b.created, vec!["rapid.log"]);
    assert!(b.coalesced_count >= 1, "rapid edits should be coalesced");
}

#[tokio::test]
async fn test_watcher_cooperative_shutdown() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    let config = WatchConfig::new()
        .with_debounce(Duration::from_millis(50))
        .with_poll_interval(Duration::from_millis(20));

    let mut coordinator = ContinuousSyncCoordinator::new(root.clone(), config).unwrap();
    let shutdown_handle = coordinator.shutdown_handle();

    // Trigger shutdown after 50ms from background task
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown_handle.store(true, Ordering::Relaxed);
    });

    let summary = coordinator
        .run_continuous(|_batch| async move { Ok(0) })
        .await
        .unwrap();

    assert_eq!(summary.status, "Completed");
}
