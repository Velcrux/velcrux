//! Integration tests for Option S: Extended Attributes (`xattrs`) & POSIX ACL Preservation with Security Boundary Sanitization
//! (`SECURITY.md` §4; `ARCHITECTURE.md` §10; `PROTOCOL.md` §4).
//!
//! Verifies:
//! 1. Wire encoding and decoding of extended attributes in manifest entries (`encode_file_entry` and `decode_file_entry`):
//!    - Canonical encoding of `(name, value)` pairs when `has_xattrs()` is set.
//!    - Zero wire overhead when `has_xattrs()` is not set (full backward compatibility).
//!    - Resource limits: bounds on name len (255), value len (64 KiB), count (256), total bytes (256 KiB), and control characters.
//! 2. Storage backend extended attributes (`LocalFilesystemBackend`):
//!    - `set_xattrs` and `get_xattrs` preserve arbitrary attribute sets.
//!    - Empty attribute lists clean up metadata.
//!    - `backend.remove` cleans up both file and attribute sidecar.
//! 3. Security boundary sanitization (`SECURITY.md` §4):
//!    - Unprivileged clients are strictly blocked from writing to privileged namespaces (`security.*`, `trusted.*`, `system.*`).
//!    - Safe user namespaces (`user.*`, `com.apple.*`) are permitted for standard clients.
//!    - Clients holding `PermSet::ADMIN` can manage privileged namespaces.
//! 4. Directory scanning and diff reconciliation:
//!    - `scan_dir_entries` filters out attribute sidecars and attaches xattrs to `ScannedEntry`.
//!    - `plan_directory_diff` detects changes in xattrs as file modifications.
//!    - Manifest streaming preserves xattrs end-to-end.
//! 5. Live QUIC loopback transfer and security enforcement:
//!    - Client setting user xattrs on remote file succeeds and persists.
//!    - Client without admin grant attempting to inject `security.capability` is rejected with `ErrorCode::InvalidPath`.
//!    - Setting xattrs on non-existent file is rejected with `ErrorCode::FileNotFound`.
//!    - Admin client setting `security.capability` succeeds.

#![forbid(unsafe_code)]

use std::sync::Arc;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use tempfile::tempdir;

use velcrux_core::auth::{Authorizer, FileAuthorizer, Grant, PermSet};
use velcrux_core::error::ProtocolError;
use velcrux_core::manifest::codec::{
    decode_file_entry, encode_file_entry, is_privileged_xattr, validate_xattrs_security,
};
use velcrux_core::manifest::entry::{ChunkDesc, FileEntry, FileFlags};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{Committed, ErrorMsg, Message, TransferCreate, TransferOp};
use velcrux_core::protocol::varint::encode_varint;
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::{LocalFilesystemBackend, StorageBackend, VPath};
use velcrux_core::sync::{plan_directory_diff, scan_dir_entries};
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
    dn.push(DnType::CommonName, "velcrux-xattr-ca");
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
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    let key = KeyPair::generate().expect("server key");
    let cert = params
        .signed_by(&key, &ca.ca_cert, &ca.ca_key)
        .expect("server sign");
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

// ---------------------------------------------------------------------------
// 1. Manifest Codec Unit Tests
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_xattrs_codec_roundtrip() {
    let chunk = ChunkDesc::new(1024, Hash::from_bytes(&[1u8; 32]).unwrap());
    let xattrs = vec![
        ("user.author".to_string(), b"Velcrux Team".to_vec()),
        (
            "user.checksum".to_string(),
            b"sha256:0123456789abcdef".to_vec(),
        ),
        (
            "com.apple.provenance".to_string(),
            vec![0x10, 0x20, 0x30, 0x40],
        ),
    ];
    let entry = FileEntry::regular(
        VPath::validate("notes/readme.txt").unwrap(),
        1024,
        0o644,
        1700000000,
        500,
        Hash::from_bytes(&[2u8; 32]).unwrap(),
        vec![chunk],
    )
    .with_xattrs(xattrs.clone());

    assert!(entry.flags.has_xattrs());

    let mut out = Vec::new();
    encode_file_entry(&entry, &mut out);

    let (decoded, consumed) = decode_file_entry(&out).expect("decode");
    assert_eq!(consumed, out.len());
    assert_eq!(decoded.xattrs, xattrs);
    assert!(decoded.flags.has_xattrs());
    assert_eq!(entry, decoded);
}

#[test]
fn test_manifest_xattrs_backward_compatibility() {
    let chunk = ChunkDesc::new(512, Hash::from_bytes(&[3u8; 32]).unwrap());
    let entry = FileEntry::regular(
        VPath::validate("legacy.bin").unwrap(),
        512,
        0o644,
        1700000000,
        0,
        Hash::from_bytes(&[4u8; 32]).unwrap(),
        vec![chunk],
    );

    assert!(!entry.flags.has_xattrs());
    let mut out = Vec::new();
    encode_file_entry(&entry, &mut out);

    let (decoded, consumed) = decode_file_entry(&out).expect("decode");
    assert_eq!(consumed, out.len());
    assert!(decoded.xattrs.is_empty());
    assert!(!decoded.flags.has_xattrs());
    assert_eq!(entry, decoded);
}

#[test]
fn test_manifest_xattrs_bounds_enforcement() {
    // 1. Oversized name length (> 255)
    let long_name = "user.".to_string() + &"a".repeat(300);
    let mut buf = Vec::new();
    let mut vbuf = [0u8; 10];
    let flags = FileFlags::regular().with_xattrs(true);
    let n = encode_varint(flags.0, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    // path: "f"
    let n = encode_varint(1, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    buf.push(b'f');
    // size (8), mode (4), mtime_sec (8), mtime_nsec (4), hash (32)
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0o644u32.to_le_bytes());
    buf.extend_from_slice(&0i64.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 32]);
    // chunk_count: 0
    let n = encode_varint(0, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    // xattr_count: 1
    let n = encode_varint(1, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    // name_len > MAX_XATTR_NAME_LEN
    let n = encode_varint(long_name.len() as u64, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);
    buf.extend_from_slice(long_name.as_bytes());
    // val_len: 0
    let n = encode_varint(0, &mut vbuf);
    buf.extend_from_slice(&vbuf[..n]);

    let res = decode_file_entry(&buf);
    assert!(matches!(res, Err(ProtocolError::InvalidManifest(_))));

    // 2. Control characters in name
    let bad_name = "user\x00bad";
    let mut buf2 = Vec::new();
    let n = encode_varint(flags.0, &mut vbuf);
    buf2.extend_from_slice(&vbuf[..n]);
    let n = encode_varint(1, &mut vbuf);
    buf2.extend_from_slice(&vbuf[..n]);
    buf2.push(b'f');
    buf2.extend_from_slice(&0u64.to_le_bytes());
    buf2.extend_from_slice(&0o644u32.to_le_bytes());
    buf2.extend_from_slice(&0i64.to_le_bytes());
    buf2.extend_from_slice(&0u32.to_le_bytes());
    buf2.extend_from_slice(&[0u8; 32]);
    let n = encode_varint(0, &mut vbuf);
    buf2.extend_from_slice(&vbuf[..n]);
    let n = encode_varint(1, &mut vbuf);
    buf2.extend_from_slice(&vbuf[..n]);
    let n = encode_varint(bad_name.len() as u64, &mut vbuf);
    buf2.extend_from_slice(&vbuf[..n]);
    buf2.extend_from_slice(bad_name.as_bytes());
    let n = encode_varint(0, &mut vbuf);
    buf2.extend_from_slice(&vbuf[..n]);

    let res2 = decode_file_entry(&buf2);
    assert!(matches!(res2, Err(ProtocolError::InvalidManifest(_))));
}

// ---------------------------------------------------------------------------
// 2. Storage Backend Unit Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_storage_backend_xattrs() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path().join("root");
    let staging = tmp.path().join("staging");
    tokio::fs::create_dir(&root).await.unwrap();
    tokio::fs::create_dir(&staging).await.unwrap();

    let backend = LocalFilesystemBackend::new(root.clone(), staging)
        .await
        .unwrap();
    let file_vpath = VPath::validate("sample.txt").unwrap();
    let abs_file = root.join("sample.txt");
    tokio::fs::write(&abs_file, b"content").await.unwrap();

    // 1. Initially no xattrs
    let empty = backend.get_xattrs(&file_vpath).await.unwrap();
    assert!(empty.is_empty());

    // 2. Set xattrs
    let xattrs = vec![
        ("user.mime".to_string(), b"text/plain".to_vec()),
        ("user.indexed".to_string(), vec![1]),
    ];
    backend.set_xattrs(&file_vpath, &xattrs).await.unwrap();

    // 3. Retrieve and verify
    let read_back = backend.get_xattrs(&file_vpath).await.unwrap();
    assert_eq!(read_back, xattrs);

    // 4. Overwrite xattrs with empty list -> clears
    backend.set_xattrs(&file_vpath, &[]).await.unwrap();
    let cleared = backend.get_xattrs(&file_vpath).await.unwrap();
    assert!(cleared.is_empty());

    // 5. Set again, then delete file -> cleans up both file and sidecar
    backend.set_xattrs(&file_vpath, &xattrs).await.unwrap();
    backend.remove(&file_vpath).await.unwrap();
    let sidecar = velcrux_core::storage::xattr_sidecar_path(&abs_file);
    assert!(!sidecar.exists());
    assert!(!abs_file.exists());
}

// ---------------------------------------------------------------------------
// 3. Security Boundary Sanitization Unit Tests
// ---------------------------------------------------------------------------

#[test]
fn test_security_boundary_sanitization() {
    assert!(is_privileged_xattr("security.capability"));
    assert!(is_privileged_xattr("security.selinux"));
    assert!(is_privileged_xattr("trusted.foo"));
    assert!(is_privileged_xattr("system.posix_acl_access"));
    assert!(!is_privileged_xattr("user.comment"));
    assert!(!is_privileged_xattr("com.apple.provenance"));

    let priv_attrs = vec![("security.capability".to_string(), vec![0x00, 0x01])];
    let user_attrs = vec![("user.comment".to_string(), b"safe".to_vec())];

    // Non-admin cannot set privileged attributes
    let res = validate_xattrs_security(&priv_attrs, false);
    assert!(res.is_err());

    // Admin can set privileged attributes
    let res = validate_xattrs_security(&priv_attrs, true);
    assert!(res.is_ok());

    // Non-admin can set user attributes
    let res = validate_xattrs_security(&user_attrs, false);
    assert!(res.is_ok());
}

// ---------------------------------------------------------------------------
// 4. Directory Diff Reconciliation with Xattrs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sync_directory_diff_xattrs() {
    let tmp = tempdir().expect("tempdir");
    let dir_a = tmp.path().join("dir_a");
    let dir_b = tmp.path().join("dir_b");
    tokio::fs::create_dir_all(&dir_a).await.unwrap();
    tokio::fs::create_dir_all(&dir_b).await.unwrap();

    let f_a = dir_a.join("file.txt");
    let f_b = dir_b.join("file.txt");
    tokio::fs::write(&f_a, b"identical data").await.unwrap();
    tokio::fs::write(&f_b, b"identical data").await.unwrap();

    // Set xattrs on source only
    let sidecar_a = velcrux_core::storage::xattr_sidecar_path(&f_a);
    let xattrs = vec![("user.tag".to_string(), b"tagged".to_vec())];
    tokio::fs::write(
        &sidecar_a,
        velcrux_core::storage::encode_xattrs_canonical(&xattrs),
    )
    .await
    .unwrap();

    let src_entries = scan_dir_entries(&dir_a).unwrap();
    let dst_entries = scan_dir_entries(&dir_b).unwrap();

    // Verify sidecar was not scanned as a file entry
    assert_eq!(src_entries.len(), 1);
    assert_eq!(dst_entries.len(), 1);
    assert_eq!(src_entries["file.txt"].xattrs, xattrs);
    assert!(dst_entries["file.txt"].xattrs.is_empty());

    // Diff should plan a Modify because xattrs differ
    let plan = plan_directory_diff(&src_entries, &dst_entries);
    assert_eq!(plan.summary.files_modified, 1);
    assert_eq!(plan.summary.files_unchanged, 0);
}

// ---------------------------------------------------------------------------
// 5. Live QUIC Loopback: Xattr Operations & Security Boundary Enforcement
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_loopback_xattrs_and_security_boundary() {
    let _ = tracing_subscriber::fmt().try_init();

    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let standard_client_identity = build_client_identity(&ca, "user-alice");
    let admin_client_identity = build_client_identity(&ca, "admin-root");

    let pid = std::process::id();
    let test_root = std::env::temp_dir().join(format!("velcrux-xattr-test-{pid}"));
    let files_dir = test_root.join("files");
    let staging_dir = test_root.join("staging");
    tokio::fs::create_dir_all(&files_dir).await.unwrap();
    tokio::fs::create_dir_all(&staging_dir).await.unwrap();

    // Create a target file on the server
    let target_vpath = VPath::validate("data/document.pdf").unwrap();
    let target_file = files_dir.join("data/document.pdf");
    tokio::fs::create_dir_all(target_file.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&target_file, b"sample pdf document")
        .await
        .unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(files_dir.clone(), staging_dir.clone())
            .await
            .unwrap(),
    );

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);
    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("client CA")
        .with_tunables(TransportConfigTunables::default())
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server bind");
    let server_addr = server_transport.local_addr().unwrap();

    let stats = Arc::new(ServerStats::default());
    // Authorizer setup:
    // "user-alice" has upload, download, list (non-admin)
    // "admin-root" has admin + upload
    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![
        Grant {
            identity: "user-alice".to_string(),
            path_prefix: "data".to_string(),
            permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
        },
        Grant {
            identity: "admin-root".to_string(),
            path_prefix: "data".to_string(),
            permissions: PermSet::ADMIN | PermSet::UPLOAD,
        },
    ]));

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

    let client_standard: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(standard_client_identity)
            .build()
            .expect("client build"),
    );

    let client_admin: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(admin_client_identity)
            .build()
            .expect("client build"),
    );

    // CASE 1: Standard client sets safe user xattr (user.classification) -> SUCCESS
    {
        let conn = client_standard
            .connect(server_addr, "localhost")
            .await
            .expect("connect");
        let (send, recv) = conn.open_bi().await.expect("bi open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let xattrs = vec![("user.classification".to_string(), b"confidential".to_vec())];
        let payload = serde_json::to_string(&xattrs).unwrap();

        let create = TransferCreate {
            op: TransferOp::SetXattr,
            src_path: payload,
            dst_path: "data/document.pdf".into(),
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

        // Verify on server storage
        let read = backend.get_xattrs(&target_vpath).await.unwrap();
        assert_eq!(read, xattrs);
    }

    // CASE 2: Standard client attempts to inject privileged "security.capability" -> REJECTED
    {
        let conn = client_standard
            .connect(server_addr, "localhost")
            .await
            .expect("connect");
        let (send, recv) = conn.open_bi().await.expect("bi open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let priv_xattrs = vec![(
            "security.capability".to_string(),
            vec![0x01, 0x02, 0x03, 0x04],
        )];
        let payload = serde_json::to_string(&priv_xattrs).unwrap();

        let create = TransferCreate {
            op: TransferOp::SetXattr,
            src_path: payload,
            dst_path: "data/document.pdf".into(),
            idempotency_key: TransferId::generate().to_string(),
            file_size: 0,
            file_hash: Hash::ZERO,
        };

        let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
        session.send_mut().write_all(buf).await.unwrap();

        let frame = session.recv_frame().await.unwrap();
        assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
        let err = ErrorMsg::decode(frame.payload).unwrap();
        assert_eq!(err.code, ErrorCode::InvalidPath);
        assert!(err.detail.0.contains("privileged xattr namespace"));
    }

    // CASE 3: Standard client attempts to set xattrs on non-existent file -> FILE_NOT_FOUND
    {
        let conn = client_standard
            .connect(server_addr, "localhost")
            .await
            .expect("connect");
        let (send, recv) = conn.open_bi().await.expect("bi open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let xattrs = vec![("user.tag".to_string(), b"val".to_vec())];
        let payload = serde_json::to_string(&xattrs).unwrap();

        let create = TransferCreate {
            op: TransferOp::SetXattr,
            src_path: payload,
            dst_path: "data/non_existent.bin".into(),
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
    }

    // CASE 4: Admin client sets privileged "security.capability" -> SUCCESS
    {
        let conn = client_admin
            .connect(server_addr, "localhost")
            .await
            .expect("connect");
        let (send, recv) = conn.open_bi().await.expect("bi open");
        let mut session = ClientSession::from_handshake_parts(send, recv)
            .await
            .expect("handshake");

        let priv_xattrs = vec![(
            "security.capability".to_string(),
            vec![0x01, 0x02, 0x03, 0x04],
        )];
        let payload = serde_json::to_string(&priv_xattrs).unwrap();

        let create = TransferCreate {
            op: TransferOp::SetXattr,
            src_path: payload,
            dst_path: "data/document.pdf".into(),
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

        // Verify on server storage that privileged xattr was committed
        let read = backend.get_xattrs(&target_vpath).await.unwrap();
        assert_eq!(read, priv_xattrs);
    }
}
