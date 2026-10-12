//! Integration tests for point-in-time snapshot isolation, version history, and CAS restore (Option BC).

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use tempfile::tempdir;
use velcrux_core::storage::{
    gc_chunk_store_with_snapshots, LocalChunkStore, SnapshotManager,
};
use velcrux_core::util::Hash;

#[tokio::test]
async fn test_snapshot_create_list_and_get() {
    let tmp = tempdir().unwrap();
    let src_dir = tmp.path().join("source");
    let snap_dir = tmp.path().join("snapshots");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(src_dir.join("subdir")).unwrap();

    // Create test files
    let hello_bytes = b"Hello, Velcrux Point-in-Time Snapshot!";
    fs::write(src_dir.join("hello.txt"), hello_bytes).unwrap();
    fs::write(src_dir.join("subdir/nested.dat"), vec![0xAB; 2048]).unwrap();
    fs::write(src_dir.join("empty.log"), b"").unwrap();

    let manager = SnapshotManager::new(&snap_dir, None).unwrap();

    // 1. Tag validation checks
    assert!(SnapshotManager::validate_tag("").is_err());
    assert!(SnapshotManager::validate_tag("../traversal").is_err());
    assert!(SnapshotManager::validate_tag("slash/tag").is_err());
    assert!(SnapshotManager::validate_tag("valid-tag_v1.0").is_ok());

    // 2. Create snapshot v1.0
    let mut annotations = HashMap::new();
    annotations.insert("environment".to_string(), "staging".to_string());
    annotations.insert("author".to_string(), "ops-team".to_string());

    let snap = manager
        .create_snapshot("release-v1.0", &src_dir, Some(annotations))
        .expect("create snapshot");

    assert_eq!(snap.tag, "release-v1.0");
    assert_eq!(snap.file_count, 3);
    assert_eq!(snap.total_bytes, hello_bytes.len() as u64 + 2048);
    assert_eq!(snap.metadata.get("environment").unwrap(), "staging");
    assert!(snap.files.contains_key("hello.txt"));
    assert!(snap.files.contains_key("subdir/nested.dat"));
    assert!(snap.files.contains_key("empty.log"));

    // 3. Duplicate snapshot creation rejected
    assert!(manager.create_snapshot("release-v1.0", &src_dir, None).is_err());

    // 4. List snapshots
    let list = manager.list_snapshots().expect("list snapshots");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].tag, "release-v1.0");
    assert_eq!(list[0].file_count, 3);

    // 5. Get snapshot
    let retrieved = manager.get_snapshot("release-v1.0").expect("get snapshot");
    assert_eq!(retrieved.tag, snap.tag);
    assert_eq!(retrieved.files, snap.files);
}

#[tokio::test]
async fn test_snapshot_diff_detection() {
    let tmp = tempdir().unwrap();
    let src_dir = tmp.path().join("source");
    let snap_dir = tmp.path().join("snapshots");
    fs::create_dir_all(&src_dir).unwrap();

    let manager = SnapshotManager::new(&snap_dir, None).unwrap();

    // Initial state: doc.txt, base.bin, temp.log
    fs::write(src_dir.join("doc.txt"), b"Version 1 document content").unwrap();
    fs::write(src_dir.join("base.bin"), vec![0x11; 1024]).unwrap();
    fs::write(src_dir.join("temp.log"), b"temporary log data").unwrap();

    manager
        .create_snapshot("snap-baseline", &src_dir, None)
        .expect("create baseline");

    // Mutate state:
    // - modify doc.txt
    // - delete temp.log
    // - add new_feature.rs
    // - keep base.bin untouched
    fs::write(src_dir.join("doc.txt"), b"Version 2 updated document content with more text").unwrap();
    fs::remove_file(src_dir.join("temp.log")).unwrap();
    fs::write(src_dir.join("new_feature.rs"), b"fn main() { println!(\"new\"); }").unwrap();

    manager
        .create_snapshot("snap-updated", &src_dir, None)
        .expect("create updated");

    // Compute diff
    let diff = manager
        .diff_snapshots("snap-baseline", "snap-updated")
        .expect("diff snapshots");

    assert_eq!(diff.tag_a, "snap-baseline");
    assert_eq!(diff.tag_b, "snap-updated");
    assert_eq!(diff.added_files, vec!["new_feature.rs"]);
    assert_eq!(diff.removed_files, vec!["temp.log"]);
    assert_eq!(diff.modified_files, vec!["doc.txt"]);
    assert_eq!(diff.unchanged_files, 1); // base.bin
    assert!(diff.bytes_added > 0);
    assert!(diff.bytes_removed > 0);
}

#[tokio::test]
async fn test_snapshot_cas_chunk_store_and_restore() {
    let tmp = tempdir().unwrap();
    let src_dir = tmp.path().join("source");
    let snap_dir = tmp.path().join("snapshots");
    let cas_dir = tmp.path().join("cas");
    let restore_dir = tmp.path().join("restored");

    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(src_dir.join("logs")).unwrap();

    // Generate multi-chunk file (> 128 KiB to produce multiple chunks)
    let large_payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    fs::write(src_dir.join("large_dataset.bin"), &large_payload).unwrap();
    fs::write(src_dir.join("logs/server.log"), b"System startup complete 200 OK").unwrap();

    // Initialize LocalChunkStore
    let chunk_store = Arc::new(LocalChunkStore::new(&cas_dir).await.unwrap());
    let manager = SnapshotManager::new(&snap_dir, Some(chunk_store.clone())).unwrap();

    // Snapshot creation automatically pushes chunks into chunk_store
    let snap = manager
        .create_snapshot("backup-2026-10-12", &src_dir, None)
        .expect("create snapshot");

    assert_eq!(snap.file_count, 2);
    let large_meta = snap.files.get("large_dataset.bin").unwrap();
    assert!(large_meta.chunk_hashes.len() >= 3); // 200_000 / 65536 = 3+ chunks

    // Verify chunk store contains the hashes
    for chash in &large_meta.chunk_hashes {
        assert!(chunk_store.contains_sync(chash));
    }

    // Now restore into a completely fresh destination from CAS
    let report = manager
        .restore_snapshot("backup-2026-10-12", &restore_dir, None)
        .expect("restore snapshot");

    assert_eq!(report.tag, "backup-2026-10-12");
    assert_eq!(report.restored_files, 2);
    assert_eq!(report.restored_bytes, large_payload.len() as u64 + 30);

    // Verify restored file contents and BLAKE3 checksums
    let restored_large = fs::read(restore_dir.join("large_dataset.bin")).unwrap();
    assert_eq!(restored_large, large_payload);
    assert_eq!(Hash::of(&restored_large), large_meta.file_hash);

    let restored_log = fs::read(restore_dir.join("logs/server.log")).unwrap();
    assert_eq!(restored_log, b"System startup complete 200 OK");
}

#[tokio::test]
async fn test_snapshot_gc_protection_and_deletion() {
    let tmp = tempdir().unwrap();
    let src_dir = tmp.path().join("source");
    let snap_dir = tmp.path().join("snapshots");
    let cas_dir = tmp.path().join("cas");
    let empty_root = tmp.path().join("empty_storage_root");

    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&empty_root).unwrap();

    let chunk_store = Arc::new(LocalChunkStore::new(&cas_dir).await.unwrap());
    let manager = SnapshotManager::new(&snap_dir, Some(chunk_store.clone())).unwrap();

    // File in snapshot
    let snap_data = b"Critical snapshot data that must not be garbage collected";
    fs::write(src_dir.join("critical.dat"), snap_data).unwrap();

    manager
        .create_snapshot("protected-v1", &src_dir, None)
        .expect("create snapshot");

    // Also put an unreferenced orphan chunk in the chunk store
    let orphan_data = b"Transient temporary chunk never referenced by any snapshot or file";
    let orphan_hash = Hash::of(orphan_data);
    chunk_store.put_sync(&orphan_hash, orphan_data).unwrap();
    assert!(chunk_store.contains_sync(&orphan_hash));

    // Verify all_referenced_chunks sees the snapshot chunk
    let protected_chunks = manager.all_referenced_chunks().unwrap();
    let snap_chunk_hash = Hash::of(snap_data);
    assert!(protected_chunks.contains(&snap_chunk_hash));
    assert!(!protected_chunks.contains(&orphan_hash));

    // Run garbage collection with snapshot manager protection!
    // Notice empty_root has 0 files, so without snapshot protection, all chunks would be pruned.
    let gc_report = gc_chunk_store_with_snapshots(
        &chunk_store,
        &[&empty_root],
        Some(&manager),
        false, // live deletion
    )
    .expect("gc sweep");

    // The orphan was pruned, but the snapshot chunk was PROTECTED!
    assert_eq!(gc_report.unreferenced_deleted, 1);
    assert!(!chunk_store.contains_sync(&orphan_hash));
    assert!(chunk_store.contains_sync(&snap_chunk_hash));

    // Now test snapshot deletion
    assert!(manager.delete_snapshot("protected-v1").unwrap());
    assert!(!manager.delete_snapshot("protected-v1").unwrap()); // second delete returns false
    assert_eq!(manager.list_snapshots().unwrap().len(), 0);
}
