//! Integration tests for Small File Batch Container Pipeline (Option AI / Milestone 10).
//!
//! Verifies:
//! 1. Packing and streaming extraction of 250+ small files into `VBATCH/1` container with 100% BLAKE3 fidelity.
//! 2. End-to-end `execute_directory_sync` with small file batching enabled vs disabled.
//! 3. Path traversal attack defense within batch containers (lexical boundary enforcement).
//! 4. Tamper detection and cryptographic hash mismatch rejection.
//! 5. Dry-run transfer planning and roundtrip savings estimation.

use tempfile::tempdir;

use velcrux_core::sync::batch::{BatchContainerReader, BatchContainerWriter, VBATCH_MAGIC};
use velcrux_core::sync::directory::{
    execute_directory_sync, DirectorySyncOptions, FileAction, FileActionType,
};
use velcrux_core::util::Hash;

#[test]
fn test_small_files_batch_pack_unpack_roundtrip() {
    let src_dir = tempdir().unwrap();
    let staging_dir = tempdir().unwrap();

    let mut actions = Vec::new();

    // Create 250 small files in various nested directories
    for i in 0..250 {
        let sub_dir = format!("sub_{}", i % 5);
        let dir_path = src_dir.path().join(&sub_dir);
        std::fs::create_dir_all(&dir_path).unwrap();

        let rel_path = format!("{}/file_{}.txt", sub_dir, i);
        let file_path = src_dir.path().join(&rel_path);

        // Content sizes: 0, 1, 17, 1024, 4096, 16384 bytes
        let size = match i % 6 {
            0 => 0,
            1 => 1,
            2 => 17,
            3 => 1024,
            4 => 4096,
            _ => 16384,
        };
        let content = vec![(i as u8).wrapping_add(1); size];
        std::fs::write(&file_path, &content).unwrap();

        let hash = Hash::of(&content);
        actions.push(FileAction {
            rel_path,
            action: FileActionType::Add,
            src_size: size as u64,
            dst_size: 0,
            src_hash: Some(hash),
            bytes_to_transfer: size as u64,
            bytes_reusable: 0,
        });
    }

    // Pack into memory buffer
    let mut container_bytes = Vec::new();
    let total_packed =
        BatchContainerWriter::pack(src_dir.path(), &actions, &mut container_bytes).unwrap();
    assert!(total_packed > 0);
    assert_eq!(&container_bytes[..7], VBATCH_MAGIC);

    // Unpack into staging directory
    let mut cursor = std::io::Cursor::new(&container_bytes);
    let report = BatchContainerReader::unpack(&mut cursor, staging_dir.path()).unwrap();
    assert_eq!(report.files_extracted, 250);
    assert_eq!(report.unpacked_paths.len(), 250);

    // Verify all 250 files byte-for-byte and BLAKE3 equality
    for action in &actions {
        let original_file = src_dir.path().join(&action.rel_path);
        let unpacked_file = staging_dir.path().join(&action.rel_path);

        assert!(
            unpacked_file.exists(),
            "file {} must exist",
            action.rel_path
        );
        let orig_content = std::fs::read(&original_file).unwrap();
        let unp_content = std::fs::read(&unpacked_file).unwrap();
        assert_eq!(orig_content, unp_content);
        assert_eq!(Hash::of(&unp_content), action.src_hash.unwrap());
    }
}

#[test]
fn test_directory_sync_with_batching_enabled() {
    let src_dir = tempdir().unwrap();
    let dst_dir = tempdir().unwrap();

    // Create 50 small files
    for i in 0..50 {
        let path = src_dir.path().join(format!("file_{}.dat", i));
        std::fs::write(&path, format!("small file payload {}", i)).unwrap();
    }
    // Create 1 large file (256 KiB) exceeding default threshold
    let large_path = src_dir.path().join("large_file.dat");
    std::fs::write(&large_path, vec![0xAB; 256 * 1024]).unwrap();

    // 1. Dry run verification
    let dry_run_opts = DirectorySyncOptions::default()
        .with_dry_run(true)
        .with_batch_small_files(true)
        .with_small_file_threshold(64 * 1024);
    let dry_res =
        execute_directory_sync(src_dir.path(), dst_dir.path(), &dry_run_opts, None, None).unwrap();
    assert_eq!(dry_res.small_files_batched, 50);
    assert_eq!(dry_res.batch_containers, 1);
    assert_eq!(dry_res.roundtrips_saved, 49);
    assert_eq!(dry_res.files_transferred, 0);

    // 2. Real execution with batching
    let sync_opts = DirectorySyncOptions::default()
        .with_batch_small_files(true)
        .with_small_file_threshold(64 * 1024);
    let res =
        execute_directory_sync(src_dir.path(), dst_dir.path(), &sync_opts, None, None).unwrap();
    assert_eq!(res.files_transferred, 51);
    assert_eq!(res.files_committed, 51);
    assert_eq!(res.small_files_batched, 50);
    assert_eq!(res.batch_containers, 1);
    assert_eq!(res.roundtrips_saved, 49);

    // Verify all files in dst_dir
    for i in 0..50 {
        let p = dst_dir.path().join(format!("file_{}.dat", i));
        assert!(p.exists());
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            format!("small file payload {}", i)
        );
    }
    assert_eq!(
        std::fs::read(dst_dir.path().join("large_file.dat"))
            .unwrap()
            .len(),
        256 * 1024
    );
}

#[test]
fn test_batch_path_traversal_rejection() {
    let staging_dir = tempdir().unwrap();

    // Manually craft a malicious container trying to escape root via `../escape.txt`
    let evil_entry = velcrux_core::sync::batch::BatchEntryMeta {
        rel_path: "../escape.txt".to_string(),
        size: 5,
        mode: 0o100644,
        mtime_ns: 0,
        file_hash: Hash::of(b"evil!").to_string(),
        xattrs: Vec::new(),
    };
    let index_json = serde_json::to_vec(&vec![evil_entry]).unwrap();

    let mut stream = Vec::new();
    stream.extend_from_slice(VBATCH_MAGIC);
    stream.push(0); // flags
    stream.extend_from_slice(&(1u32).to_be_bytes()); // 1 entry
    stream.extend_from_slice(&(index_json.len() as u32).to_be_bytes());
    stream.extend_from_slice(&(5u64).to_be_bytes()); // 5 bytes payload
    stream.extend_from_slice(&index_json);
    stream.extend_from_slice(b"evil!");
    let hash = blake3::hash(b"evil!");
    stream.extend_from_slice(hash.as_bytes());

    let mut cursor = std::io::Cursor::new(&stream);
    let err = BatchContainerReader::unpack(&mut cursor, staging_dir.path()).unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("traversal") || err_str.contains("rejected"),
        "error should reject path traversal: {err_str}"
    );

    // Verify file was NOT written
    assert!(!staging_dir.path().join("../escape.txt").exists());
}

#[test]
fn test_batch_payload_tamper_detection() {
    let src_dir = tempdir().unwrap();
    let staging_dir = tempdir().unwrap();

    let file_path = src_dir.path().join("secure.txt");
    std::fs::write(&file_path, b"genuine payload 12345").unwrap();

    let action = FileAction {
        rel_path: "secure.txt".to_string(),
        action: FileActionType::Add,
        src_size: 21,
        dst_size: 0,
        src_hash: Some(Hash::of(b"genuine payload 12345")),
        bytes_to_transfer: 21,
        bytes_reusable: 0,
    };

    let mut container = Vec::new();
    BatchContainerWriter::pack(src_dir.path(), &[action], &mut container).unwrap();

    // Corrupt a byte in the payload data
    let payload_offset = container.len() - 32 - 10;
    container[payload_offset] ^= 0xFF;

    let mut cursor = std::io::Cursor::new(&container);
    let err = BatchContainerReader::unpack(&mut cursor, staging_dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("Hash mismatch")
            || err.to_string().contains("trailer checksum mismatch"),
        "tamper must be rejected by hash verification: {}",
        err
    );

    // Corrupt file should be cleanly removed from staging
    assert!(!staging_dir.path().join("secure.txt").exists());
}
