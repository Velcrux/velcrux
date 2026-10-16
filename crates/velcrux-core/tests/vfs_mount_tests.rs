//! Integration tests for Virtual Filesystem Mount Engine (Option BL).

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

use velcrux_core::storage::snapshot::SnapshotFileMeta;
use velcrux_core::storage::vfs::{
    MountConfig, MountManager, VfsFileType, VirtualMountEngine, VFS_ROOT_INODE,
};
use velcrux_core::storage::SnapshotEntry;
use velcrux_core::util::Hash;

#[tokio::test]
async fn test_vfs_mount_local_directory_hierarchy() {
    let tmp = tempdir().unwrap();
    let src_dir = tmp.path().join("local_source");
    fs::create_dir_all(src_dir.join("subfolder")).unwrap();

    let file_a_data = b"Alpha dataset content for VFS integration testing";
    let file_b_data = b"Beta dataset in nested subdirectory hierarchy";
    fs::write(src_dir.join("alpha.txt"), file_a_data).unwrap();
    fs::write(src_dir.join("subfolder/beta.dat"), file_b_data).unwrap();

    let config = MountConfig {
        source: src_dir.display().to_string(),
        mountpoint: PathBuf::from("/mnt/local_vfs"),
        read_only: true,
        ..Default::default()
    };
    let engine = VirtualMountEngine::new(config);
    engine.init_from_local(&src_dir).await.unwrap();

    // 1. Root readdir
    let root_entries = engine.readdir(VFS_ROOT_INODE).await.unwrap();
    assert!(root_entries.iter().any(|e| e.name == "."));
    assert!(root_entries.iter().any(|e| e.name == ".."));
    assert!(root_entries.iter().any(|e| e.name == "alpha.txt"));
    assert!(root_entries.iter().any(|e| e.name == "subfolder"));

    // 2. Lookup alpha.txt
    let alpha_attr = engine
        .lookup(VFS_ROOT_INODE, "alpha.txt")
        .await
        .unwrap()
        .expect("alpha.txt exists");
    assert_eq!(alpha_attr.kind, VfsFileType::Regular);
    assert_eq!(alpha_attr.size, file_a_data.len() as u64);

    // 3. Read alpha.txt at offsets
    let read_whole = engine
        .read_at(alpha_attr.ino, 0, file_a_data.len())
        .await
        .unwrap();
    assert_eq!(read_whole, file_a_data);

    let read_part = engine.read_at(alpha_attr.ino, 6, 7).await.unwrap();
    assert_eq!(read_part, b"dataset");

    let read_eof = engine.read_at(alpha_attr.ino, 500, 10).await.unwrap();
    assert!(read_eof.is_empty());

    // 4. Lookup subfolder and nested beta.dat
    let subfolder_attr = engine
        .lookup(VFS_ROOT_INODE, "subfolder")
        .await
        .unwrap()
        .expect("subfolder exists");
    assert_eq!(subfolder_attr.kind, VfsFileType::Directory);

    let sub_entries = engine.readdir(subfolder_attr.ino).await.unwrap();
    assert!(sub_entries.iter().any(|e| e.name == "beta.dat"));

    let beta_attr = engine
        .lookup(subfolder_attr.ino, "beta.dat")
        .await
        .unwrap()
        .expect("beta.dat exists");
    assert_eq!(beta_attr.size, file_b_data.len() as u64);

    let read_beta = engine
        .read_at(beta_attr.ino, 0, file_b_data.len())
        .await
        .unwrap();
    assert_eq!(read_beta, file_b_data);
}

#[tokio::test]
async fn test_vfs_rw_create_write_delete_and_symlink() {
    let config = MountConfig {
        source: "./dummy".to_string(),
        mountpoint: PathBuf::from("/mnt/rw_vfs"),
        read_only: false,
        ..Default::default()
    };
    let engine = VirtualMountEngine::new(config);

    // 1. Create a new file
    let file_attr = engine
        .create_file(VFS_ROOT_INODE, "mutable.txt", 0o644)
        .await
        .unwrap();
    assert_eq!(file_attr.size, 0);

    // 2. Write payload
    let payload = b"Velcrux pure-Rust virtual filesystem engine read-write verification";
    let written = engine.write_at(file_attr.ino, 0, payload).await.unwrap();
    assert_eq!(written, payload.len());

    let updated_attr = engine.getattr(file_attr.ino).await.unwrap().unwrap();
    assert_eq!(updated_attr.size, payload.len() as u64);
    assert!(updated_attr.file_hash.is_some());

    // 3. Read back
    let read_data = engine
        .read_at(file_attr.ino, 0, payload.len())
        .await
        .unwrap();
    assert_eq!(read_data, payload);

    // 4. Create symlink
    let sym_attr = engine
        .create_symlink(VFS_ROOT_INODE, "link_to_mutable", "mutable.txt")
        .await
        .unwrap();
    assert_eq!(sym_attr.kind, VfsFileType::Symlink);

    let target = engine.readlink(sym_attr.ino).await.unwrap();
    assert_eq!(target, "mutable.txt");

    // 5. Delete file and symlink
    engine
        .remove_entry(VFS_ROOT_INODE, "mutable.txt")
        .await
        .unwrap();
    assert!(engine
        .lookup(VFS_ROOT_INODE, "mutable.txt")
        .await
        .unwrap()
        .is_none());

    engine
        .remove_entry(VFS_ROOT_INODE, "link_to_mutable")
        .await
        .unwrap();
    assert!(engine
        .lookup(VFS_ROOT_INODE, "link_to_mutable")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_vfs_page_cache_lru_and_eviction() {
    // 128 KiB cache capacity
    let config = MountConfig {
        source: "./dummy".to_string(),
        mountpoint: PathBuf::from("/mnt/cache_vfs"),
        read_only: false,
        cache_capacity_bytes: 128 * 1024,
        cache_ttl_sec: 30,
        ..Default::default()
    };
    let engine = VirtualMountEngine::new(config);

    // Create 3 files of 64 KiB each
    let block = vec![0x55; 64 * 1024];
    let file1 = engine
        .create_file(VFS_ROOT_INODE, "f1.dat", 0o644)
        .await
        .unwrap();
    let file2 = engine
        .create_file(VFS_ROOT_INODE, "f2.dat", 0o644)
        .await
        .unwrap();
    let file3 = engine
        .create_file(VFS_ROOT_INODE, "f3.dat", 0o644)
        .await
        .unwrap();

    engine.write_at(file1.ino, 0, &block).await.unwrap();
    engine.write_at(file2.ino, 0, &block).await.unwrap();
    engine.write_at(file3.ino, 0, &block).await.unwrap();

    // Read file1 and file2 -> fills 128 KiB cache
    let _ = engine.read_at(file1.ino, 0, block.len()).await.unwrap();
    let _ = engine.read_at(file2.ino, 0, block.len()).await.unwrap();

    let stats_before = engine.cache_stats().await;
    assert_eq!(stats_before.misses, 2);
    assert_eq!(stats_before.hits, 0);

    // Read file3 -> triggers eviction of LRU entry (file1)
    let _ = engine.read_at(file3.ino, 0, block.len()).await.unwrap();
    let stats_after = engine.cache_stats().await;
    assert_eq!(stats_after.misses, 3);
    assert!(stats_after.evictions >= 1);

    // Hit file3
    let _ = engine.read_at(file3.ino, 0, 100).await.unwrap();
    let stats_hit = engine.cache_stats().await;
    assert_eq!(stats_hit.hits, 1);
}

#[tokio::test]
async fn test_vfs_mount_snapshot_and_cloud_sources() {
    // 1. Snapshot source mount
    let mut files = std::collections::HashMap::new();
    let snap_hash = Hash::of(b"snapshot file content");
    files.insert(
        "models/weights.bin".to_string(),
        SnapshotFileMeta {
            relative_path: "models/weights.bin".to_string(),
            size: 1048576,
            file_hash: snap_hash,
            chunk_hashes: vec![snap_hash],
            modified_at_secs: 1760000000,
            is_executable: false,
        },
    );

    let snapshot = SnapshotEntry {
        tag: "prod-snapshot-v1".to_string(),
        created_at_secs: 1760000000,
        root_path: "/data/models".to_string(),
        file_count: 1,
        total_bytes: 1048576,
        metadata: std::collections::HashMap::new(),
        files,
    };

    let snap_config = MountConfig {
        source: "snapshot://prod-snapshot-v1".to_string(),
        mountpoint: PathBuf::from("/mnt/snap"),
        read_only: true,
        ..Default::default()
    };
    let snap_engine = VirtualMountEngine::new(snap_config);
    snap_engine.init_from_snapshot(&snapshot).await.unwrap();

    let root_entries = snap_engine.readdir(VFS_ROOT_INODE).await.unwrap();
    assert!(root_entries.iter().any(|e| e.name == "models"));

    let models_dir = snap_engine
        .lookup(VFS_ROOT_INODE, "models")
        .await
        .unwrap()
        .expect("models dir");
    let model_files = snap_engine.readdir(models_dir.ino).await.unwrap();
    assert!(model_files.iter().any(|e| e.name == "weights.bin"));

    // 2. Cloud source mount
    let cloud_config = MountConfig {
        source: "s3://dataset-bucket/prefix/".to_string(),
        mountpoint: PathBuf::from("/mnt/cloud"),
        read_only: true,
        ..Default::default()
    };
    let cloud_engine = VirtualMountEngine::new(cloud_config);
    let cloud_entries = vec![
        ("train.parquet".to_string(), 500000, Some(Hash::ZERO)),
        ("test.parquet".to_string(), 100000, Some(Hash::ZERO)),
    ];
    cloud_engine
        .init_from_cloud_entries(cloud_entries)
        .await
        .unwrap();

    let cloud_root = cloud_engine.readdir(VFS_ROOT_INODE).await.unwrap();
    assert!(cloud_root.iter().any(|e| e.name == "train.parquet"));
    assert!(cloud_root.iter().any(|e| e.name == "test.parquet"));

    // StatFS
    let statfs = cloud_engine.statfs().await;
    assert!(statfs.blocks > 0);
    assert_eq!(statfs.bsize, 4096);
}

#[tokio::test]
async fn test_vfs_mount_manager_process_coordination() {
    let tmp = tempdir().unwrap();
    let mp1 = tmp.path().join("mnt_alpha");
    let mp2 = tmp.path().join("mnt_beta");

    let manager = MountManager::new();

    let cfg1 = MountConfig {
        source: "gs://ml-datasets/alpha".to_string(),
        mountpoint: mp1.clone(),
        read_only: true,
        ..Default::default()
    };
    let cfg2 = MountConfig {
        source: "az://storage-container/beta".to_string(),
        mountpoint: mp2.clone(),
        read_only: false,
        ..Default::default()
    };

    let engine1 = manager.mount(cfg1).await.unwrap();
    let engine2 = manager.mount(cfg2).await.unwrap();
    assert_eq!(engine1.config().read_only, true);
    assert_eq!(engine2.config().read_only, false);

    // List registered
    let list = manager.list_registered();
    assert!(list
        .iter()
        .any(|s| s.mountpoint == mp1.display().to_string()));
    assert!(list
        .iter()
        .any(|s| s.mountpoint == mp2.display().to_string()));

    // Lookup active engine
    let found = manager.get_engine(&mp1).await;
    assert!(found.is_some());

    // Unmount
    let unmounted1 = manager.unmount(&mp1).await.unwrap();
    assert!(unmounted1);
    let unmounted2 = manager.unmount(&mp2).await.unwrap();
    assert!(unmounted2);

    let remaining = manager.list_registered();
    assert!(!remaining
        .iter()
        .any(|s| s.mountpoint == mp1.display().to_string()));
    assert!(!remaining
        .iter()
        .any(|s| s.mountpoint == mp2.display().to_string()));
}
