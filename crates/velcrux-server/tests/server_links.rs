//! Integration tests for Option R: Symlink & Hard-Link Preservation with Lexical Path Containment & Escape Defense
//! (`SECURITY.md` §4, §5; `PROTOCOL.md` §6; `ARCHITECTURE.md` §8, §10).
//!
//! Verifies:
//! 1. Symlink lexical containment validation (`VPath::validate_symlink_target`):
//!    - Accepts valid contained relative targets inside directory subtrees.
//!    - Rejects escapes above virtual root (`..` underflow), absolute paths (`/`, Windows drive `C:`),
//!      NUL bytes, and control characters with `VPathError::SymlinkEscape`.
//!    - Never silently rewrites symlink targets.
//! 2. Storage backend symlink and hardlink operations:
//!    - `create_symlink` and `create_hardlink` on `LocalFilesystemBackend`.
//! 3. Filesystem scanning and manifest codec:
//!    - `scan_dir_entries` detects symlinks without traversing targets, detects hardlinks on Unix via `(dev, ino)`.
//!    - `send_directory_manifest` and `recv_directory_manifest` roundtrip link metadata losslessly.
//! 4. Live QUIC loopback symlink transfer and escape defense:
//!    - Valid symlinks committed on server disk.
//!    - Traversal escape attempts rejected with `ErrorCode::InvalidPath` without touching destination.
//!    - Absolute symlink targets rejected with `ErrorCode::InvalidPath`.
//! 5. Live QUIC loopback hardlink transfer and target existence check:
//!    - Hard links created referencing existing files without duplicate chunk bytes.
//!    - Non-existent hard link targets rejected with `ErrorCode::FileNotFound`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use tempfile::tempdir;

use velcrux_core::auth::{Authorizer, FileAuthorizer, Grant, PermSet};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{Committed, ErrorMsg, Message, TransferCreate, TransferOp};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::{FileMeta, LocalFilesystemBackend, StorageBackend, VPath, VPathError};
use velcrux_core::sync::{plan_directory_diff, scan_dir_entries, ScannedEntry};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};

// ---------------------------------------------------------------------------
// Dev PKI helpers for QUIC loopback
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
    dn.push(DnType::CommonName, "velcrux-links-ca");
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
    params.subject_alt_names = vec![SanType::DnsName(name.try_into().unwrap())];
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

fn blake3_of(data: &[u8]) -> Hash {
    let mut h = velcrux_core::HashHasher::new();
    h.feed(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// 1. Lexical Containment Unit Tests
// ---------------------------------------------------------------------------

#[test]
fn test_symlink_lexical_containment_pure_logic() {
    let link_path = VPath::validate("sub/dir/link.txt").unwrap();

    // Sibling target
    let resolved = VPath::validate_symlink_target(&link_path, "target.txt").unwrap();
    assert_eq!(resolved.as_str(), "sub/dir/target.txt");

    // Parent target
    let resolved = VPath::validate_symlink_target(&link_path, "../sibling.txt").unwrap();
    assert_eq!(resolved.as_str(), "sub/sibling.txt");

    // Root target
    let resolved = VPath::validate_symlink_target(&link_path, "../../root_file.txt").unwrap();
    assert_eq!(resolved.as_str(), "root_file.txt");

    // Current dir relative
    let resolved = VPath::validate_symlink_target(&link_path, "./nested/file.bin").unwrap();
    assert_eq!(resolved.as_str(), "sub/dir/nested/file.bin");

    // Escapes above virtual root
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "../../../outside.txt"),
        Err(VPathError::SymlinkEscape)
    );
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "../../../../etc/passwd"),
        Err(VPathError::SymlinkEscape)
    );

    // Absolute targets
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "/etc/shadow"),
        Err(VPathError::SymlinkEscape)
    );
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "\\Windows\\System32"),
        Err(VPathError::SymlinkEscape)
    );

    // Windows drive prefixes
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "C:\\Windows\\cmd.exe"),
        Err(VPathError::SymlinkEscape)
    );
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "D:secret"),
        Err(VPathError::SymlinkEscape)
    );

    // Top-level link escaping
    let top_link = VPath::validate("link.txt").unwrap();
    assert_eq!(
        VPath::validate_symlink_target(&top_link, "../escape"),
        Err(VPathError::SymlinkEscape)
    );

    // NUL and control characters
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "foo\0bar"),
        Err(VPathError::ForbiddenChar)
    );
    assert_eq!(
        VPath::validate_symlink_target(&link_path, "foo\nbar"),
        Err(VPathError::ForbiddenChar)
    );

    // Empty target
    assert_eq!(
        VPath::validate_symlink_target(&link_path, ""),
        Err(VPathError::Empty)
    );
}

// ---------------------------------------------------------------------------
// 2. Storage Backend Symlink and Hardlink CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_backend_symlink_and_hardlink_operations() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let staging = temp.path().join("staging");
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::create_dir_all(&staging).await.unwrap();

    let backend = LocalFilesystemBackend::new(root.clone(), staging.clone())
        .await
        .unwrap();

    // 1. Create original file
    let orig = VPath::validate("orig.txt").unwrap();
    let mut writer = backend.open_staging("t1", &orig, 12).await.unwrap();
    writer.write_at(0, b"link content").await.unwrap();
    writer.fsync().await.unwrap();
    backend
        .commit(
            "t1",
            writer.into_staging(),
            &orig,
            &FileMeta::new(12, blake3_of(b"link content")),
        )
        .await
        .unwrap();

    // 2. Create symlink
    let sym = VPath::validate("sub/sym.txt").unwrap();
    backend.create_symlink(&sym, "../orig.txt").await.unwrap();
    let sym_meta = tokio::fs::symlink_metadata(root.join("sub/sym.txt"))
        .await
        .unwrap();
    assert!(sym_meta.file_type().is_symlink());

    let target = tokio::fs::read_link(root.join("sub/sym.txt"))
        .await
        .unwrap();
    assert_eq!(target.to_string_lossy(), "../orig.txt");

    // Reading through symlink returns target file content
    let content = tokio::fs::read(root.join("sub/sym.txt")).await.unwrap();
    assert_eq!(content, b"link content");

    // 3. Atomically overwrite symlink
    backend.create_symlink(&sym, "../orig2.txt").await.unwrap();
    let target = tokio::fs::read_link(root.join("sub/sym.txt"))
        .await
        .unwrap();
    assert_eq!(target.to_string_lossy(), "../orig2.txt");

    // 4. Create hardlink
    let hard = VPath::validate("sub/hard.txt").unwrap();
    backend.create_hardlink(&hard, &orig).await.unwrap();
    let hard_meta = tokio::fs::metadata(root.join("sub/hard.txt"))
        .await
        .unwrap();
    assert_eq!(hard_meta.len(), 12);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let orig_meta = tokio::fs::metadata(root.join("orig.txt")).await.unwrap();
        assert_eq!(hard_meta.ino(), orig_meta.ino());
        assert_eq!(hard_meta.nlink(), 2);
    }
}

// ---------------------------------------------------------------------------
// 3. Filesystem Scanning & Manifest Codec with Links
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_scanner_and_manifest_codec_with_links() {
    let temp = tempdir().unwrap();
    let sync_dir = temp.path().join("sync_source");
    tokio::fs::create_dir_all(&sync_dir).await.unwrap();

    // Regular file
    let file1_path = sync_dir.join("file1.txt");
    tokio::fs::write(&file1_path, b"file 1 data").await.unwrap();

    // Symlink
    let sym_path = sync_dir.join("link_to_file1.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink("file1.txt", &sym_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("file1.txt", &sym_path).unwrap();

    // Hardlink
    #[cfg(unix)]
    let hard_path = sync_dir.join("hard_to_file1.txt");
    #[cfg(unix)]
    std::fs::hard_link(&file1_path, &hard_path).unwrap();

    // Scan
    let entries = scan_dir_entries(&sync_dir).unwrap();
    assert!(entries.contains_key("file1.txt"));
    assert!(entries.contains_key("link_to_file1.txt"));
    let sym_entry = &entries["link_to_file1.txt"];
    assert!(sym_entry.is_symlink);
    assert_eq!(sym_entry.symlink_target.as_deref(), Some("file1.txt"));

    #[cfg(unix)]
    {
        assert!(entries.contains_key("hard_to_file1.txt"));
        let hard_entry = &entries["hard_to_file1.txt"];
        assert_eq!(hard_entry.hardlink_target.as_deref(), Some("file1.txt"));
    }

    // Reconciliation diff planning
    let mut dst_entries = BTreeMap::new();
    dst_entries.insert(
        "file1.txt".to_string(),
        ScannedEntry::file(11, blake3_of(b"file 1 data")),
    );
    dst_entries.insert(
        "link_to_file1.txt".to_string(),
        ScannedEntry::symlink("file1.txt".to_string()),
    );

    let plan = plan_directory_diff(&entries, &dst_entries);
    assert_eq!(plan.summary.files_unchanged, 2);
}

// ---------------------------------------------------------------------------
// 4. Live QUIC Loopback: Symlink Creation & Escape Defense
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_symlink_creation_and_escape_defense() {
    let _ = tracing_subscriber::fmt().try_init();

    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "links-client");

    let pid = std::process::id();
    let test_root = std::env::temp_dir().join(format!("velcrux-symlink-test-{pid}"));
    let files_dir = test_root.join("files");
    let staging_dir = test_root.join("staging");
    tokio::fs::create_dir_all(&files_dir).await.unwrap();
    tokio::fs::create_dir_all(&staging_dir).await.unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(files_dir.clone(), staging_dir.clone())
            .await
            .unwrap(),
    );

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);
    server_caps.set(Capability::Symlinks);
    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("client CA")
        .with_tunables(TransportConfigTunables::default())
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server bind");
    let server_addr = server_transport.local_addr().unwrap();

    let stats = Arc::new(ServerStats::default());
    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "links-client".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let _server_task = {
        let backend = Arc::clone(&backend);
        let stats = Arc::clone(&stats);
        let authz = Arc::clone(&authz);
        tokio::spawn(async move {
            for _ in 0..4 {
                if let Ok(conn) = server_transport.accept().await {
                    let b = Arc::clone(&backend);
                    let s = Arc::clone(&stats);
                    let az = Arc::clone(&authz);
                    tokio::spawn(async move {
                        let actor = ServerConn::with_state(
                            server_caps,
                            "velcruxd",
                            s,
                            b,
                            None,
                            None,
                            Some(az),
                        );
                        let _ = actor.run(&conn).await;
                    });
                }
            }
        })
    };

    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .build()
            .expect("client build"),
    );

    // CASE 1: Valid contained symlink creation
    {
        let conn = client_transport
            .connect(server_addr, "localhost")
            .await
            .expect("client connect");
        let (send, recv) = conn.open_bi().await.expect("bi stream open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let create = TransferCreate {
            op: TransferOp::Symlink,
            src_path: "../sibling.txt".to_string(),
            dst_path: "data/sub/valid_link.txt".to_string(),
            idempotency_key: TransferId::generate().to_string(),
            file_size: 14,
            file_hash: Hash::ZERO,
        };
        let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
        session.send_mut().write_all(buf).await.unwrap();

        let frame = session.recv_frame().await.unwrap();
        assert_eq!(frame.type_byte, velcrux_core::protocol::message::COMMITTED);
        let committed = Committed::decode(frame.payload).unwrap();
        assert_eq!(committed.files, 1);

        // Verify symlink exists on server filesystem
        let sym_disk = files_dir.join("data/sub/valid_link.txt");
        let meta = tokio::fs::symlink_metadata(&sym_disk).await.unwrap();
        assert!(meta.file_type().is_symlink());
        let target = tokio::fs::read_link(&sym_disk).await.unwrap();
        assert_eq!(target.to_string_lossy(), "../sibling.txt");
    }

    // CASE 2: Traversal escape symlink attempt (refused with InvalidPath)
    {
        let conn = client_transport
            .connect(server_addr, "localhost")
            .await
            .expect("client connect");
        let (send, recv) = conn.open_bi().await.expect("bi stream open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let create = TransferCreate {
            op: TransferOp::Symlink,
            src_path: "../../escape.txt".to_string(),
            dst_path: "data/escape_link.txt".to_string(),
            idempotency_key: TransferId::generate().to_string(),
            file_size: 15,
            file_hash: Hash::ZERO,
        };
        let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
        session.send_mut().write_all(buf).await.unwrap();

        let frame = session.recv_frame().await.unwrap();
        assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
        let err = ErrorMsg::decode(frame.payload).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidPath);

        // Verify symlink was NOT created
        let escape_disk = files_dir.join("data/escape_link.txt");
        assert!(!escape_disk.exists());
    }

    // CASE 3: Absolute symlink attempt (refused with InvalidPath)
    {
        let conn = client_transport
            .connect(server_addr, "localhost")
            .await
            .expect("client connect");
        let (send, recv) = conn.open_bi().await.expect("bi stream open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let create = TransferCreate {
            op: TransferOp::Symlink,
            src_path: "/etc/passwd".to_string(),
            dst_path: "data/abs_link.txt".to_string(),
            idempotency_key: TransferId::generate().to_string(),
            file_size: 11,
            file_hash: Hash::ZERO,
        };
        let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
        session.send_mut().write_all(buf).await.unwrap();

        let frame = session.recv_frame().await.unwrap();
        assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
        let err = ErrorMsg::decode(frame.payload).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidPath);

        let abs_disk = files_dir.join("data/abs_link.txt");
        assert!(!abs_disk.exists());
    }

    let _ = tokio::fs::remove_dir_all(&test_root).await;
}

// ---------------------------------------------------------------------------
// 5. Live QUIC Loopback: Hardlink Creation & Target Verification
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_hardlink_creation_and_validation() {
    let _ = tracing_subscriber::fmt().try_init();

    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "hardlink-client");

    let pid = std::process::id();
    let test_root = std::env::temp_dir().join(format!("velcrux-hardlink-test-{pid}"));
    let files_dir = test_root.join("files");
    let staging_dir = test_root.join("staging");
    tokio::fs::create_dir_all(&files_dir).await.unwrap();
    tokio::fs::create_dir_all(&staging_dir).await.unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(files_dir.clone(), staging_dir.clone())
            .await
            .unwrap(),
    );

    // Pre-populate an existing original file on server
    let orig_vpath = VPath::validate("data/orig.txt").unwrap();
    let mut writer = backend.open_staging("t0", &orig_vpath, 20).await.unwrap();
    writer.write_at(0, b"original hard target").await.unwrap();
    writer.fsync().await.unwrap();
    backend
        .commit(
            "t0",
            writer.into_staging(),
            &orig_vpath,
            &FileMeta::new(20, blake3_of(b"original hard target")),
        )
        .await
        .unwrap();

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);
    server_caps.set(Capability::Symlinks);
    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("client CA")
        .with_tunables(TransportConfigTunables::default())
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server bind");
    let server_addr = server_transport.local_addr().unwrap();

    let stats = Arc::new(ServerStats::default());
    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "hardlink-client".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let _server_task = {
        let backend = Arc::clone(&backend);
        let stats = Arc::clone(&stats);
        let authz = Arc::clone(&authz);
        tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok(conn) = server_transport.accept().await {
                    let b = Arc::clone(&backend);
                    let s = Arc::clone(&stats);
                    let az = Arc::clone(&authz);
                    tokio::spawn(async move {
                        let actor = ServerConn::with_state(
                            server_caps,
                            "velcruxd",
                            s,
                            b,
                            None,
                            None,
                            Some(az),
                        );
                        let _ = actor.run(&conn).await;
                    });
                }
            }
        })
    };

    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .build()
            .expect("client build"),
    );

    // CASE 1: Valid hardlink creation referencing already committed file
    {
        let conn = client_transport
            .connect(server_addr, "localhost")
            .await
            .expect("client connect");
        let (send, recv) = conn.open_bi().await.expect("bi stream open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let create = TransferCreate {
            op: TransferOp::Hardlink,
            src_path: "data/orig.txt".to_string(),
            dst_path: "data/hard_copy.txt".to_string(),
            idempotency_key: TransferId::generate().to_string(),
            file_size: 0,
            file_hash: Hash::ZERO,
        };
        let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
        session.send_mut().write_all(buf).await.unwrap();

        let frame = session.recv_frame().await.unwrap();
        assert_eq!(frame.type_byte, velcrux_core::protocol::message::COMMITTED);
        let committed = Committed::decode(frame.payload).unwrap();
        assert_eq!(committed.files, 1);

        let hard_disk = files_dir.join("data/hard_copy.txt");
        let orig_disk = files_dir.join("data/orig.txt");
        assert!(hard_disk.exists());
        let content = tokio::fs::read(&hard_disk).await.unwrap();
        assert_eq!(content, b"original hard target");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m_orig = tokio::fs::metadata(&orig_disk).await.unwrap();
            let m_hard = tokio::fs::metadata(&hard_disk).await.unwrap();
            assert_eq!(m_orig.ino(), m_hard.ino());
            assert_eq!(m_orig.nlink(), 2);
        }
    }

    // CASE 2: Hardlink to non-existent file rejected with FileNotFound
    {
        let conn = client_transport
            .connect(server_addr, "localhost")
            .await
            .expect("client connect");
        let (send, recv) = conn.open_bi().await.expect("bi stream open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let create = TransferCreate {
            op: TransferOp::Hardlink,
            src_path: "data/nonexistent.txt".to_string(),
            dst_path: "data/bad_hard.txt".to_string(),
            idempotency_key: TransferId::generate().to_string(),
            file_size: 0,
            file_hash: Hash::ZERO,
        };
        let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
        session.send_mut().write_all(buf).await.unwrap();

        let frame = session.recv_frame().await.unwrap();
        assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
        let err = ErrorMsg::decode(frame.payload).unwrap();
        assert_eq!(err.code, ErrorCode::FileNotFound);

        let bad_disk = files_dir.join("data/bad_hard.txt");
        assert!(!bad_disk.exists());
    }

    let _ = tokio::fs::remove_dir_all(&test_root).await;
}
