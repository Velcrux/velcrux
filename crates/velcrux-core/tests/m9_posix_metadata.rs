//! Integration tests for Option AC: Advanced POSIX Metadata Synchronization (Milestone 9).
//!
//! Tests:
//! 1. Symlink replication without traversal containment leaks.
//! 2. In-place modification of symlink targets during directory reconciliation.
//! 3. Canonical extended attributes (`xattrs`) sidecar serialization and propagation.
//! 4. POSIX permission mode (`chmod`) preservation and change detection.
//! 5. Extraneous symlink and sidecar deletion under `DeleteMode::DeleteAfter`.
//! 6. Streaming manifest encoding/decoding roundtrip preserving mode, mtime, and xattrs.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tempfile::tempdir;
use velcrux_core::chunking::{ChunkMode, ChunkParams};
use velcrux_core::storage::{decode_xattrs_canonical, encode_xattrs_canonical, xattr_sidecar_path};
use velcrux_core::sync::{
    execute_directory_sync, scan_dir_entries, DeleteMode, DirectorySyncOptions,
};

#[test]
fn test_symlink_replication_and_modified_targets() {
    let src_dir = tempdir().expect("src dir");
    let dst_dir = tempdir().expect("dst dir");

    let src_path = src_dir.path();
    let dst_path = dst_dir.path();

    // 1. Create target files and symlinks in source
    let file1 = src_path.join("file1.txt");
    fs::write(&file1, b"original content for target 1").expect("write file1");

    let file2 = src_path.join("file2.txt");
    fs::write(&file2, b"second target content").expect("write file2");

    let sub_dir = src_path.join("subdir");
    fs::create_dir(&sub_dir).expect("create subdir");

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("file1.txt", src_path.join("link_root.txt"))
            .expect("symlink root");
        std::os::unix::fs::symlink("../file1.txt", sub_dir.join("link_sub.txt"))
            .expect("symlink sub");
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file("file1.txt", src_path.join("link_root.txt"))
            .expect("symlink root");
        std::os::windows::fs::symlink_file("../file1.txt", sub_dir.join("link_sub.txt"))
            .expect("symlink sub");
    }

    let options = DirectorySyncOptions {
        mode: ChunkMode::Fixed,
        params: ChunkParams::default(),
        delete_mode: DeleteMode::None,
        dry_run: false,
        read_buffer_size: 64 * 1024,
    };

    // Initial sync
    let result = execute_directory_sync(src_path, dst_path, &options, None, None)
        .expect("initial sync execution");
    assert!(result.files_committed >= 4);

    // Verify destination files and symlinks
    let dst_link_root = dst_path.join("link_root.txt");
    let dst_link_sub = dst_path.join("subdir/link_sub.txt");

    assert!(fs::symlink_metadata(&dst_link_root)
        .expect("meta")
        .file_type()
        .is_symlink());
    assert!(fs::symlink_metadata(&dst_link_sub)
        .expect("meta")
        .file_type()
        .is_symlink());

    assert_eq!(
        fs::read_link(&dst_link_root)
            .expect("read link")
            .to_string_lossy(),
        "file1.txt"
    );
    assert_eq!(
        fs::read_link(&dst_link_sub)
            .expect("read link")
            .to_string_lossy(),
        "../file1.txt"
    );

    // Reading through symlinks yields target file contents
    assert_eq!(
        fs::read_to_string(&dst_link_root).expect("read content"),
        "original content for target 1"
    );
    assert_eq!(
        fs::read_to_string(&dst_link_sub).expect("read content"),
        "original content for target 1"
    );

    // 2. Modify symlink target on source: link_root.txt now points to file2.txt
    let _ = fs::remove_file(src_path.join("link_root.txt"));
    #[cfg(unix)]
    std::os::unix::fs::symlink("file2.txt", src_path.join("link_root.txt")).expect("new symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("file2.txt", src_path.join("link_root.txt"))
        .expect("new symlink");

    // Second sync: should detect modified symlink and update destination atomically
    let result2 = execute_directory_sync(src_path, dst_path, &options, None, None)
        .expect("second sync execution");
    assert_eq!(result2.plan.summary.files_modified, 1);

    assert_eq!(
        fs::read_link(&dst_link_root)
            .expect("read link")
            .to_string_lossy(),
        "file2.txt"
    );
    assert_eq!(
        fs::read_to_string(&dst_link_root).expect("read content"),
        "second target content"
    );
}

#[test]
fn test_xattr_sidecar_synchronization() {
    let src_dir = tempdir().expect("src dir");
    let dst_dir = tempdir().expect("dst dir");

    let src_path = src_dir.path();
    let dst_path = dst_dir.path();

    let file_path = src_path.join("doc.txt");
    fs::write(&file_path, b"document body").expect("write doc");

    // Create xattrs on source
    let sidecar = xattr_sidecar_path(&file_path);
    let original_xattrs = vec![
        ("user.author".to_string(), b"Alice".to_vec()),
        ("user.mime_type".to_string(), b"text/plain".to_vec()),
    ];
    let encoded = encode_xattrs_canonical(&original_xattrs);
    fs::write(&sidecar, &encoded).expect("write sidecar");

    let options = DirectorySyncOptions::default();

    // Initial sync
    let result =
        execute_directory_sync(src_path, dst_path, &options, None, None).expect("sync execution");
    assert_eq!(result.files_committed, 1);

    // Destination sidecar must exist and decode identically
    let dst_sidecar = xattr_sidecar_path(&dst_path.join("doc.txt"));
    assert!(dst_sidecar.exists());
    let dst_raw = fs::read(&dst_sidecar).expect("read dst sidecar");
    let decoded = decode_xattrs_canonical(&dst_raw).expect("decode xattrs");
    assert_eq!(decoded, original_xattrs);

    // Update xattrs on source: verify plan detects Modify and updates destination
    let updated_xattrs = vec![
        ("user.author".to_string(), b"Alice".to_vec()),
        ("user.mime_type".to_string(), b"application/json".to_vec()),
        ("user.version".to_string(), b"2.0".to_vec()),
    ];
    let encoded_updated = encode_xattrs_canonical(&updated_xattrs);
    fs::write(&sidecar, &encoded_updated).expect("update sidecar");

    let result2 = execute_directory_sync(src_path, dst_path, &options, None, None)
        .expect("sync update execution");
    assert_eq!(result2.plan.summary.files_modified, 1);

    let dst_raw2 = fs::read(&dst_sidecar).expect("read updated dst sidecar");
    let decoded2 = decode_xattrs_canonical(&dst_raw2).expect("decode xattrs 2");
    assert_eq!(decoded2, updated_xattrs);
}

#[cfg(unix)]
#[test]
fn test_posix_permission_mode_preservation() {
    let src_dir = tempdir().expect("src dir");
    let dst_dir = tempdir().expect("dst dir");

    let src_path = src_dir.path();
    let dst_path = dst_dir.path();

    let script = src_path.join("script.sh");
    fs::write(&script, b"#!/bin/sh\necho hello\n").expect("write script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod 755");

    let secret = src_path.join("secret.key");
    fs::write(&secret, b"super-secret-key-material").expect("write secret");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("chmod 600");

    let options = DirectorySyncOptions::default();
    execute_directory_sync(src_path, dst_path, &options, None, None).expect("sync execution");

    let dst_script = dst_path.join("script.sh");
    let dst_secret = dst_path.join("secret.key");

    let script_mode = fs::metadata(&dst_script)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    let secret_mode = fs::metadata(&dst_secret)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(script_mode, 0o755);
    assert_eq!(secret_mode, 0o600);

    // Modify permission on script from 755 to 700
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod 700");

    let result2 = execute_directory_sync(src_path, dst_path, &options, None, None)
        .expect("sync update execution");
    assert_eq!(result2.plan.summary.files_modified, 1);

    let new_script_mode = fs::metadata(&dst_script)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(new_script_mode, 0o700);
}

#[test]
fn test_deletion_of_symlinks_and_sidecars() {
    let src_dir = tempdir().expect("src dir");
    let dst_dir = tempdir().expect("dst dir");

    let src_path = src_dir.path();
    let dst_path = dst_dir.path();

    // Destination has an extraneous broken symlink and sidecar
    let dst_broken_sym = dst_path.join("dangling_link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("nonexistent.txt", &dst_broken_sym).expect("symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("nonexistent.txt", &dst_broken_sym).expect("symlink");

    let dst_broken_sidecar = xattr_sidecar_path(&dst_broken_sym);
    fs::write(&dst_broken_sidecar, b"dummy-xattrs").expect("write sidecar");

    // Source only has one active file
    fs::write(src_path.join("active.txt"), b"active data").expect("write active");

    let options = DirectorySyncOptions {
        delete_mode: DeleteMode::DeleteAfter,
        ..Default::default()
    };

    let result =
        execute_directory_sync(src_path, dst_path, &options, None, None).expect("sync with delete");
    assert_eq!(result.files_deleted, 1);

    assert!(dst_broken_sym.symlink_metadata().is_err());
    assert!(!dst_broken_sidecar.exists());
    assert!(dst_path.join("active.txt").exists());
}

#[tokio::test]
async fn test_manifest_streaming_preserves_metadata() {
    let temp = tempdir().expect("tempdir");
    let p = temp.path();

    let file_path = p.join("sample.bin");
    fs::write(&file_path, b"manifest streaming metadata payload").expect("write");

    let sidecar = xattr_sidecar_path(&file_path);
    let xattrs = vec![("user.env".to_string(), b"production".to_vec())];
    fs::write(&sidecar, encode_xattrs_canonical(&xattrs)).expect("write sidecar");

    #[cfg(unix)]
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o750)).expect("chmod");

    let scanned = scan_dir_entries(p).expect("scan");
    assert_eq!(scanned.len(), 1);
    let entry = scanned.get("sample.bin").expect("sample.bin entry");
    assert_eq!(entry.xattrs, xattrs);
    #[cfg(unix)]
    assert_eq!(entry.mode & 0o777, 0o750);

    // Roundtrip through channel BiSendStream/BiRecvStream
    let (client_tx, server_rx) = tokio::io::duplex(64 * 1024);

    let scanned_clone = scanned.clone();
    let send_handle = tokio::spawn(async move {
        let mut send_stream = dummy_stream::MemSend(client_tx);
        velcrux_core::sync::send_directory_manifest(&mut send_stream, &scanned_clone).await
    });

    let recv_handle = tokio::spawn(async move {
        let mut recv_stream = dummy_stream::MemRecv(server_rx);
        velcrux_core::sync::recv_directory_manifest(&mut recv_stream).await
    });

    let (send_res, recv_res) = tokio::join!(send_handle, recv_handle);
    let _send_hash = send_res.unwrap().expect("send manifest");
    let received_entries = recv_res.unwrap().expect("recv manifest");

    assert_eq!(received_entries.len(), 1);
    let recv_entry = received_entries.get("sample.bin").expect("entry present");
    assert_eq!(recv_entry.xattrs, xattrs);
    #[cfg(unix)]
    assert_eq!(recv_entry.mode & 0o777, 0o750);
}

mod dummy_stream {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use velcrux_core::error::VelcruxError;

    pub struct MemSend(pub DuplexStream);
    pub struct MemRecv(pub DuplexStream);

    #[async_trait::async_trait]
    impl velcrux_core::transport::BiSendStream for MemSend {
        async fn write_all(&mut self, data: Bytes) -> Result<(), VelcruxError> {
            self.0.write_all(&data).await.map_err(VelcruxError::Io)
        }
        async fn finish(&mut self) -> Result<(), VelcruxError> {
            self.0.shutdown().await.map_err(VelcruxError::Io)
        }
    }

    #[async_trait::async_trait]
    impl velcrux_core::transport::BiRecvStream for MemRecv {
        async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>, VelcruxError> {
            let mut buf = vec![0u8; max];
            let n = self.0.read(&mut buf).await.map_err(VelcruxError::Io)?;
            if n == 0 {
                Ok(None)
            } else {
                buf.truncate(n);
                Ok(Some(Bytes::from(buf)))
            }
        }
        async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>, VelcruxError> {
            let mut buf = vec![0u8; n];
            match self.0.read_exact(&mut buf).await {
                Ok(_) => Ok(Some(Bytes::from(buf))),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
                Err(e) => Err(VelcruxError::Io(e)),
            }
        }
    }
}
