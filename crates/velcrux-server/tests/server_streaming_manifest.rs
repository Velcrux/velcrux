//! Integration tests for Option Y: Streaming Manifest Generation, Compressed Batch Pipeline &
//! Bounded Memory Large-Directory Synchronization (`REQUIREMENTS.md` §10, §31; `ARCHITECTURE.md` §5; `PROTOCOL.md` §4, §6).
//!
//! Verifies:
//! 1. Streaming manifest generation on a large directory tree without buffering all entries in memory.
//! 2. Live QUIC wire streaming of 4096-entry zstd-compressed windows (`MANIFEST_BATCH`) and cryptographic BLAKE3 verification.
//! 3. Incremental streaming set-difference / directory reconciliation with strictly bounded RSS (< 64 MiB).
//! 4. End-to-end directory sync execution with commit journaling and atomic commits.

#![forbid(unsafe_code)]

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use tempfile::tempdir;

use velcrux_core::chunking::ChunkParams;
use velcrux_core::manifest::{ChunkDesc, FileEntry, ManifestReader, ManifestWriter};
use velcrux_core::protocol::capabilities::Capabilities;
use velcrux_core::protocol::limits::MANIFEST_BATCH_SIZE;
use velcrux_core::protocol::message::{Hello, Message};
use velcrux_core::session::{read_frame, write_frame};
use velcrux_core::storage::VPath;
use velcrux_core::sync::{
    diff_manifest_spill_files, execute_directory_sync, plan_directory_sync,
    recv_streaming_manifest_to_spill, send_streaming_manifest_from_spill, DeleteMode,
    DirectorySyncOptions, FileActionType,
};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::Hash;

// ---------------------------------------------------------------------------
// PKI Helpers
// ---------------------------------------------------------------------------

struct DevCa {
    cert_pem: String,
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

fn build_dev_ca() -> DevCa {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "velcrux-manifest-ca");
    ca_params.distinguished_name = dn;
    let ca_key = KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");
    DevCa {
        cert_pem: ca_cert.pem(),
        ca_cert,
        ca_key,
    }
}

struct ServerCert {
    certs: Vec<Certificate>,
    key: PrivateKey,
}

fn build_server_cert(ca: &DevCa) -> ServerCert {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    let key = KeyPair::generate().expect("server key");
    let cert = params
        .signed_by(&key, &ca.ca_cert, &ca.ca_key)
        .expect("sign server");
    let certs_pem = cert.pem();
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut &certs_pem.as_bytes()[..])
        .expect("parse server cert")
        .into_iter()
        .map(Certificate)
        .collect();
    let key_der = key.serialize_der();
    ServerCert {
        certs,
        key: PrivateKey(key_der),
    }
}

fn build_client_identity(ca: &DevCa, name: &str) -> ClientIdentity {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = vec![SanType::URI(
        format!("velcrux://identity/{name}").try_into().unwrap(),
    )];
    let key = KeyPair::generate().expect("client key");
    let cert = params
        .signed_by(&key, &ca.ca_cert, &ca.ca_key)
        .expect("sign client");
    let certs_pem = cert.pem();
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut &certs_pem.as_bytes()[..])
        .expect("parse client cert")
        .into_iter()
        .map(Certificate)
        .collect();
    let key_der = key.serialize_der();
    ClientIdentity::from_der(certs, key_der)
}

fn get_current_rss_bytes() -> usize {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
        {
            if let Ok(s) = std::str::from_utf8(&output.stdout) {
                if let Ok(kb) = s.trim().parse::<usize>() {
                    return kb * 1024;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pages) = parts[1].parse::<usize>() {
                    return pages * 4096;
                }
            }
        }
    }

    0
}

// ---------------------------------------------------------------------------
// 1. Streaming Manifest Generation on Large Directory Hierarchy
// ---------------------------------------------------------------------------

#[test]
fn test_streaming_manifest_generation_large_directory() {
    let td = tempdir().unwrap();
    let root = td.path().join("dataset");
    fs::create_dir_all(&root).unwrap();

    let initial_rss = get_current_rss_bytes();

    // Create 6,000 files across 30 directories to ensure multi-batch spilling
    const NUM_DIRS: usize = 30;
    const FILES_PER_DIR: usize = 200;
    const TOTAL_FILES: usize = NUM_DIRS * FILES_PER_DIR;

    for d in 0..NUM_DIRS {
        let dir_path = root.join(format!("dir_{:02}", d));
        fs::create_dir_all(&dir_path).unwrap();
        for f in 0..FILES_PER_DIR {
            let file_path = dir_path.join(format!("file_{:04}.dat", f));
            let content = format!("Dir {} File {} payload data bytes.", d, f);
            fs::write(file_path, content.as_bytes()).unwrap();
        }
    }

    let spill_path = td.path().join("dataset.spill");
    let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default()).unwrap();

    // Scan directory tree into writer
    velcrux_core::manifest::scanner::scan_directory_tree(&root, &mut writer).unwrap();

    let (begin, end, path) = writer.finish().unwrap();

    // Check counts: 6000 regular files + 30 directories = 6030 entries
    assert_eq!(begin.file_count, (TOTAL_FILES + NUM_DIRS) as u64);
    assert_eq!(begin.manifest_hash, end.manifest_hash);

    let end_rss = get_current_rss_bytes();
    if initial_rss > 0 && end_rss > initial_rss {
        let growth = end_rss - initial_rss;
        assert!(
            growth < 64 * 1024 * 1024,
            "RSS memory growth during 6,000-file scan ({growth} bytes) must be bounded < 64 MiB"
        );
    }

    // Read back through ManifestReader
    let mut reader = ManifestReader::open(&path, begin.manifest_hash).unwrap();
    let mut read_entries = 0u64;
    while let Some(_entry) = reader.next_entry().unwrap() {
        read_entries += 1;
    }
    assert_eq!(read_entries, begin.file_count);
}

// ---------------------------------------------------------------------------
// 2. Live QUIC Wire Streaming of Compressed Manifest Batches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_manifest_live_quic_transfer() {
    let td = tempdir().unwrap();
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "manifest-client");

    let tunables = TransportConfigTunables {
        receive_window: 64 * 1024 * 1024,
        stream_receive_window: 16 * 1024 * 1024,
        max_concurrent_streams: 16,
        idle_timeout: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
        initial_rtt: Duration::from_millis(10),
    };

    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("server client CA")
        .with_tunables(tunables.clone())
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server bind");

    let server_addr = server_transport.local_addr().expect("local addr");
    let server_spill_path = td.path().join("server_received.spill");
    let s_spill_clone = server_spill_path.clone();

    let (server_done_tx, server_done_rx) = tokio::sync::oneshot::channel::<Hash>();

    // Spawn server accept task
    let server_task = tokio::spawn(async move {
        if let Ok(conn) = server_transport.accept().await {
            if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                // Handshake & Auth
                let frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
                let _hello = Hello::decode(frame.payload).unwrap();
                let ack = velcrux_core::protocol::message::HelloAck {
                    version: 1,
                    capabilities: Capabilities::EMPTY,
                    agent: "velcruxd-manifest".into(),
                    limits: velcrux_core::protocol::message::Limits {
                        max_message_size: velcrux_core::protocol::limits::MAX_MESSAGE_SIZE,
                        max_chunk_size: velcrux_core::protocol::limits::MAX_CHUNK_SIZE,
                        max_manifest_entries: velcrux_core::protocol::limits::MAX_MANIFEST_ENTRIES,
                        max_concurrent_streams: 32,
                    },
                };
                write_frame(send.as_mut(), &Message::HelloAck(ack), 1)
                    .await
                    .unwrap();

                let a_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
                let _auth = velcrux_core::protocol::message::Auth::decode(a_frame.payload).unwrap();
                let ack_auth = velcrux_core::protocol::message::AuthOk {
                    identity: "manifest-client".into(),
                    permissions: 0xFF,
                };
                write_frame(send.as_mut(), &Message::AuthOk(ack_auth), 2)
                    .await
                    .unwrap();

                // Receive streaming manifest
                let (begin, end) = recv_streaming_manifest_to_spill(recv.as_mut(), &s_spill_clone)
                    .await
                    .expect("recv streaming manifest");

                assert_eq!(begin.manifest_hash, end.manifest_hash);
                let _ = server_done_tx.send(end.manifest_hash);
            }
        }
    });

    // Create client manifest spill file with 5,000 entries (requiring 2 batches of 4096)
    let client_spill = td.path().join("client_generated.spill");
    let mut writer = ManifestWriter::new(&client_spill, ChunkParams::default()).unwrap();
    let num_entries = 5000usize;
    for i in 0..num_entries {
        let path = VPath::validate(&format!("items/item_{:05}.bin", i)).unwrap();
        let chunk = ChunkDesc::new(128, Hash::ZERO);
        let entry = FileEntry::regular(
            path,
            128,
            0o644,
            1000 + i as i64,
            0,
            Hash::ZERO,
            vec![chunk],
        );
        writer.add_entry(entry).unwrap();
    }
    let (client_begin, client_end, spill_out) = writer.finish().unwrap();
    assert_eq!(client_begin.file_count, num_entries as u64);

    // Verify batch threshold was crossed
    assert!(
        num_entries > MANIFEST_BATCH_SIZE,
        "Dataset must cross MANIFEST_BATCH_SIZE (4096) to exercise multi-batch framing"
    );

    // Connect client
    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .with_tunables(tunables)
            .build()
            .expect("client build"),
    );

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Client Handshake & Auth
    let hello = Hello::default_client();
    write_frame(send.as_mut(), &Message::Hello(hello), 1)
        .await
        .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let auth = velcrux_core::protocol::message::Auth::mtls();
    write_frame(send.as_mut(), &Message::Auth(auth), 2)
        .await
        .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    // Stream pre-compressed manifest batches over QUIC
    let end = send_streaming_manifest_from_spill(send.as_mut(), &spill_out, &client_begin)
        .await
        .expect("send streaming manifest");

    assert_eq!(end.manifest_hash, client_end.manifest_hash);

    let received_hash = server_done_rx
        .await
        .expect("server completed manifest recv");
    assert_eq!(received_hash, client_begin.manifest_hash);

    server_task.await.unwrap();

    // Verify server can read all 5,000 entries from its received spill file
    let mut s_reader = ManifestReader::open(&server_spill_path, received_hash).unwrap();
    let mut server_read_count = 0u64;
    while let Some(e) = s_reader.next_entry().unwrap() {
        assert_eq!(
            e.path.as_str(),
            format!("items/item_{:05}.bin", server_read_count)
        );
        server_read_count += 1;
    }
    assert_eq!(server_read_count, num_entries as u64);
}

// ---------------------------------------------------------------------------
// 3. Incremental Streaming Set-Difference & Bounded RSS Reconciliation
// ---------------------------------------------------------------------------

#[test]
fn test_streaming_manifest_incremental_reconciliation_bounded_rss() {
    let td = tempdir().unwrap();
    let src_spill = td.path().join("src_reconcile.spill");
    let dst_spill = td.path().join("dst_reconcile.spill");

    let initial_rss = get_current_rss_bytes();

    let mut src_writer = ManifestWriter::new(&src_spill, ChunkParams::default()).unwrap();
    let mut dst_writer = ManifestWriter::new(&dst_spill, ChunkParams::default()).unwrap();

    const NUM_COMMON: usize = 3000;
    const NUM_MODIFIED: usize = 2000;
    const NUM_SRC_ONLY: usize = 2500;
    const NUM_DST_ONLY: usize = 2500;

    let h_common = Hash::from_bytes(&[0x11; 32]).unwrap();
    let h_mod_src = Hash::from_bytes(&[0x22; 32]).unwrap();
    let h_mod_dst = Hash::from_bytes(&[0x33; 32]).unwrap();
    let h_src = Hash::from_bytes(&[0x44; 32]).unwrap();
    let h_dst = Hash::from_bytes(&[0x55; 32]).unwrap();

    // 1. Common unchanged entries: "common/file_XXXX.bin"
    for i in 0..NUM_COMMON {
        let path = VPath::validate(&format!("common/file_{:05}.bin", i)).unwrap();
        let chunk = ChunkDesc::new(512, h_common);
        let entry = FileEntry::regular(path, 512, 0o644, 1000, 0, h_common, vec![chunk]);
        src_writer.add_entry(entry.clone()).unwrap();
        dst_writer.add_entry(entry).unwrap();
    }

    // 2. Destination-only entries (to be deleted): "dst_extra/file_XXXX.bin"
    for i in 0..NUM_DST_ONLY {
        let path = VPath::validate(&format!("dst_extra/file_{:05}.bin", i)).unwrap();
        let chunk = ChunkDesc::new(1024, h_dst);
        let entry = FileEntry::regular(path, 1024, 0o644, 1000, 0, h_dst, vec![chunk]);
        dst_writer.add_entry(entry).unwrap();
    }

    // 3. Modified entries: "modified/file_XXXX.bin"
    for i in 0..NUM_MODIFIED {
        let path = VPath::validate(&format!("modified/file_{:05}.bin", i)).unwrap();
        let c_src = ChunkDesc::new(2048, h_mod_src);
        let e_src = FileEntry::regular(path.clone(), 2048, 0o644, 1000, 0, h_mod_src, vec![c_src]);
        let c_dst = ChunkDesc::new(2048, h_mod_dst);
        let e_dst = FileEntry::regular(path, 2048, 0o644, 1000, 0, h_mod_dst, vec![c_dst]);
        src_writer.add_entry(e_src).unwrap();
        dst_writer.add_entry(e_dst).unwrap();
    }

    // 4. Source-only entries (to be added): "src_extra/file_XXXX.bin"
    for i in 0..NUM_SRC_ONLY {
        let path = VPath::validate(&format!("src_extra/file_{:05}.bin", i)).unwrap();
        let chunk = ChunkDesc::new(4096, h_src);
        let entry = FileEntry::regular(path, 4096, 0o644, 1000, 0, h_src, vec![chunk]);
        src_writer.add_entry(entry).unwrap();
    }

    let (src_begin, _, src_path) = src_writer.finish().unwrap();
    let (dst_begin, _, dst_path) = dst_writer.finish().unwrap();

    let mut actions_seen = 0usize;
    let mut add_count = 0usize;
    let mut del_count = 0usize;
    let mut mod_count = 0usize;
    let mut unc_count = 0usize;

    // Stream-diff directly between the two spill files
    let summary = diff_manifest_spill_files(
        &src_path,
        src_begin.manifest_hash,
        &dst_path,
        dst_begin.manifest_hash,
        |action| {
            actions_seen += 1;
            match action.action {
                FileActionType::Unchanged => unc_count += 1,
                FileActionType::Modify => mod_count += 1,
                FileActionType::Add => add_count += 1,
                FileActionType::Delete => del_count += 1,
            }
        },
    )
    .unwrap();

    assert_eq!(summary.files_unchanged, NUM_COMMON);
    assert_eq!(summary.files_modified, NUM_MODIFIED);
    assert_eq!(summary.files_added, NUM_SRC_ONLY);
    assert_eq!(summary.files_deleted, NUM_DST_ONLY);

    assert_eq!(unc_count, NUM_COMMON);
    assert_eq!(mod_count, NUM_MODIFIED);
    assert_eq!(add_count, NUM_SRC_ONLY);
    assert_eq!(del_count, NUM_DST_ONLY);
    assert_eq!(
        actions_seen,
        NUM_COMMON + NUM_MODIFIED + NUM_SRC_ONLY + NUM_DST_ONLY
    );

    let expected_present = (NUM_COMMON as u64) * 512;
    let expected_to_transfer = (NUM_MODIFIED as u64 * 2048) + (NUM_SRC_ONLY as u64 * 4096);
    assert_eq!(summary.data_present, expected_present);
    assert_eq!(summary.data_to_transfer, expected_to_transfer);

    let final_rss = get_current_rss_bytes();
    if initial_rss > 0 && final_rss > initial_rss {
        let diff_rss_growth = final_rss - initial_rss;
        assert!(
            diff_rss_growth < 64 * 1024 * 1024,
            "Reconciling 10,000 files must remain strictly bounded under 64 MiB RSS (was {diff_rss_growth} bytes)"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Atomic Whole-Tree Commit & State Consistency
// ---------------------------------------------------------------------------

#[test]
fn test_streaming_manifest_directory_sync_atomic_commit() {
    let td = tempdir().unwrap();
    let src_dir = td.path().join("source_tree");
    let dst_dir = td.path().join("dest_tree");

    fs::create_dir_all(src_dir.join("sub1")).unwrap();
    fs::create_dir_all(src_dir.join("sub2")).unwrap();
    fs::create_dir_all(dst_dir.join("sub1")).unwrap();
    fs::create_dir_all(dst_dir.join("sub2")).unwrap();

    // Source files
    fs::write(src_dir.join("sub1/file1.txt"), b"File 1 content").unwrap();
    fs::write(src_dir.join("sub1/file2.txt"), b"File 2 brand new").unwrap();
    fs::write(src_dir.join("sub2/file3.txt"), b"File 3 data").unwrap();
    fs::write(
        src_dir.join("shared.txt"),
        b"Shared file NEW updated content",
    )
    .unwrap();

    // Destination files (prior state)
    fs::write(dst_dir.join("sub1/file1.txt"), b"File 1 content").unwrap(); // Unchanged
    fs::write(dst_dir.join("shared.txt"), b"Shared file OLD content").unwrap(); // Modify
    fs::write(dst_dir.join("extra_stale.txt"), b"Extraneous old file").unwrap(); // Delete

    let opts = DirectorySyncOptions {
        delete_mode: DeleteMode::DeleteAfter,
        ..Default::default()
    };

    // Plan directory synchronization
    let plan = plan_directory_sync(&src_dir, &dst_dir, &opts, None).unwrap();

    assert_eq!(plan.summary.files_unchanged, 1); // sub1/file1.txt
    assert_eq!(plan.summary.files_modified, 1); // shared.txt
    assert_eq!(plan.summary.files_added, 2); // sub1/file2.txt, sub2/file3.txt
    assert_eq!(plan.summary.files_deleted, 1); // extra_stale.txt

    // Execute atomic sync
    let sync_res = execute_directory_sync(&src_dir, &dst_dir, &opts, None, None).unwrap();

    assert_eq!(sync_res.files_committed, 3); // 2 added + 1 modified
    assert_eq!(sync_res.files_deleted, 1); // 1 deleted

    // Verify destination filesystem contents
    assert!(dst_dir.join("sub1/file1.txt").is_file());
    assert_eq!(
        fs::read(dst_dir.join("sub1/file1.txt")).unwrap(),
        b"File 1 content"
    );

    assert!(dst_dir.join("sub1/file2.txt").is_file());
    assert_eq!(
        fs::read(dst_dir.join("sub1/file2.txt")).unwrap(),
        b"File 2 brand new"
    );

    assert!(dst_dir.join("sub2/file3.txt").is_file());
    assert_eq!(
        fs::read(dst_dir.join("sub2/file3.txt")).unwrap(),
        b"File 3 data"
    );

    assert!(dst_dir.join("shared.txt").is_file());
    assert_eq!(
        fs::read(dst_dir.join("shared.txt")).unwrap(),
        b"Shared file NEW updated content"
    );

    // Extraneous file must have been deleted atomically
    assert!(!dst_dir.join("extra_stale.txt").exists());

    // Staging directory must be cleaned up
    assert!(
        !dst_dir.join(".velcrux-staging").exists()
            || fs::read_dir(dst_dir.join(".velcrux-staging"))
                .unwrap()
                .next()
                .is_none()
    );
}
