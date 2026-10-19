//! Integration tests for Option BN: Strict RBAC & Policy-Gated Remote Deletion Enforcement
//! (`CLAUDE.md` §4 Open Question #1; `SECURITY.md` §4; `OPERATIONS.md` §48).
//!
//! Validates:
//! 1. Default `AdminOnly` deletion policy strictly forbids remote file deletions for non-admin identities.
//! 2. Admin identities carrying `PermSet::ADMIN` and `PermSet::SYNC_DELETE` can execute remote deletions.
//! 3. `ExplicitGrant` deletion policy allows non-admin identities holding `PermSet::SYNC_DELETE` to delete during sync.
//! 4. `ExplicitGrant` deletion policy forbids non-admin identities lacking `PermSet::SYNC_DELETE` (even if holding `PermSet::DELETE`).
//! 5. `Disabled` deletion policy globally denies all remote file deletions across all identities including admin.
//! 6. `RateLimited` deletion policy caps rapid deletion bursts per identity with `ErrorCode::QuotaExceeded`.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};

use velcrux_core::auth::{
    Authorizer, DeletionLimiter, DeletionPolicy, FileAuthorizer, Grant, PermSet, Role,
};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{Committed, ErrorMsg, Message, TransferCreate, TransferOp};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::{LocalFilesystemBackend, StorageBackend, VPath};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};

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
    dn.push(DnType::CommonName, "velcrux-rbac-ca");
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

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct TestHarness {
    server_addr: std::net::SocketAddr,
    tunables: TransportConfigTunables,
    ca: DevCa,
    stats: Arc<ServerStats>,
    storage_root: std::path::PathBuf,
    backend: Arc<dyn StorageBackend>,
    _server_task: tokio::task::JoinHandle<()>,
}

async fn start_harness(
    policy: DeletionPolicy,
    limiter: Option<DeletionLimiter>,
    grants: Vec<Grant>,
) -> TestHarness {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);

    let pid = std::process::id();
    let nonce = TransferId::generate().to_string();
    let root_path = std::env::temp_dir().join(format!("velcrux-rbac-root-{pid}-{nonce}"));
    let staging_path = std::env::temp_dir().join(format!("velcrux-rbac-staging-{pid}-{nonce}"));
    tokio::fs::create_dir_all(&root_path).await.unwrap();
    tokio::fs::create_dir_all(&staging_path).await.unwrap();

    let backend: Arc<dyn StorageBackend> = Arc::new(
        LocalFilesystemBackend::new(root_path.clone(), staging_path)
            .await
            .unwrap(),
    );

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(grants));
    let stats = Arc::new(ServerStats::default());
    let limiter = limiter.unwrap_or_default();

    let tunables = TransportConfigTunables {
        receive_window: 4 * 1024 * 1024,
        stream_receive_window: 4 * 1024 * 1024,
        max_concurrent_streams: 16,
        idle_timeout: Duration::from_secs(10),
        keepalive: Duration::from_secs(2),
        initial_rtt: Duration::from_millis(50),
    };

    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("server client CA")
        .with_tunables(tunables.clone())
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server bind");

    let server_addr = server_transport.local_addr().expect("local addr");
    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::Blake3);

    let server_task = {
        let b = backend.clone();
        let s = stats.clone();
        let az = authz.clone();
        let pol = policy;
        let lim = limiter;
        tokio::spawn(async move {
            while let Ok(conn) = server_transport.accept().await {
                let b = b.clone();
                let s = s.clone();
                let az = az.clone();
                let pol = pol.clone();
                let lim = lim.clone();
                tokio::spawn(async move {
                    let actor =
                        ServerConn::with_state(server_caps, "velcruxd", s, b, None, None, Some(az))
                            .with_deletion_policy(pol)
                            .with_deletion_limiter(lim);
                    let _ = actor.run(&conn).await;
                });
            }
        })
    };

    TestHarness {
        server_addr,
        tunables,
        ca,
        stats,
        storage_root: root_path,
        backend,
        _server_task: server_task,
    }
}

async fn create_client_session(harness: &TestHarness, identity_name: &str) -> ClientSession {
    let client_identity = build_client_identity(&harness.ca, identity_name);
    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(harness.ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .with_tunables(harness.tunables.clone())
            .build()
            .expect("client transport"),
    );

    let conn = client_transport
        .connect(harness.server_addr, "localhost")
        .await
        .expect("client connect");

    let quic_conn: QuicConnection = conn;
    let (send, recv) = quic_conn.open_bi().await.expect("open bi stream");

    ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_admin_only_policy_rejects_non_admin_sync_delete() {
    let grants = vec![Grant {
        identity: "replica-bot".to_string(),
        path_prefix: "data".to_string(),
        // Client holds sync and sync_delete permissions on data/
        permissions: PermSet::SYNC | PermSet::SYNC_DELETE,
    }];

    let harness = start_harness(DeletionPolicy::AdminOnly, None, grants).await;

    // Create target file on server backend root
    let target_dir = harness.storage_root.join("data");
    tokio::fs::create_dir_all(&target_dir).await.unwrap();
    let abs_file = target_dir.join("old_file.txt");
    tokio::fs::write(&abs_file, b"data to delete")
        .await
        .unwrap();

    let vpath = VPath::validate("data/old_file.txt").unwrap();
    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());

    let mut session = create_client_session(&harness, "replica-bot").await;

    // Client requests TransferOp::SyncDelete
    let create = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "data/old_file.txt".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 1).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(err.detail.as_str().contains("requires admin role"));

    // File must NOT be deleted
    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());
    // Telemetry verifies rejection
    assert_eq!(
        harness
            .stats
            .deletions_attempted
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        harness
            .stats
            .deletions_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        harness
            .stats
            .deletions_executed
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_admin_only_policy_allows_admin_sync_delete() {
    let grants = vec![Grant {
        identity: "ops-admin".to_string(),
        path_prefix: "".to_string(),
        // Admin role holds ADMIN | ALL_TRANSFER | DELETE | SYNC_DELETE
        permissions: Role::Admin.permissions(),
    }];

    let harness = start_harness(DeletionPolicy::AdminOnly, None, grants).await;

    let target_dir = harness.storage_root.join("data");
    tokio::fs::create_dir_all(&target_dir).await.unwrap();
    let abs_file = target_dir.join("obsolete.log");
    tokio::fs::write(&abs_file, b"logs to prune").await.unwrap();

    let vpath = VPath::validate("data/obsolete.log").unwrap();
    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());

    let mut session = create_client_session(&harness, "ops-admin").await;

    let create = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "data/obsolete.log".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 1).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::COMMITTED);
    let committed = Committed::decode(frame.payload).unwrap();
    assert_eq!(committed.files, 1);

    // File MUST be removed
    assert!(harness.backend.stat(&vpath).await.unwrap().is_none());
    assert_eq!(
        harness
            .stats
            .deletions_executed
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        harness
            .stats
            .deletions_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_explicit_grant_policy_allows_non_admin_with_sync_delete() {
    let grants = vec![Grant {
        identity: "replica-node".to_string(),
        path_prefix: "data".to_string(),
        permissions: Role::SyncReplica.permissions(), // has SYNC_DELETE
    }];

    // Server configured with ExplicitGrant policy
    let harness = start_harness(DeletionPolicy::ExplicitGrant, None, grants).await;

    let target_dir = harness.storage_root.join("data");
    tokio::fs::create_dir_all(&target_dir).await.unwrap();
    let abs_file = target_dir.join("stale_cache.bin");
    tokio::fs::write(&abs_file, b"stale data").await.unwrap();

    let vpath = VPath::validate("data/stale_cache.bin").unwrap();
    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());

    let mut session = create_client_session(&harness, "replica-node").await;

    let create = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "data/stale_cache.bin".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 1).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::COMMITTED);

    assert!(harness.backend.stat(&vpath).await.unwrap().is_none());
    assert_eq!(
        harness
            .stats
            .deletions_executed
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_explicit_grant_policy_forbids_sync_writer_without_sync_delete() {
    let grants = vec![Grant {
        identity: "writer-node".to_string(),
        path_prefix: "data".to_string(),
        // Writer only has upload/download/sync/resume, NO sync_delete
        permissions: Role::SyncWriter.permissions(),
    }];

    let harness = start_harness(DeletionPolicy::ExplicitGrant, None, grants).await;

    let target_dir = harness.storage_root.join("data");
    tokio::fs::create_dir_all(&target_dir).await.unwrap();
    let abs_file = target_dir.join("important.bin");
    tokio::fs::write(&abs_file, b"precious data").await.unwrap();

    let vpath = VPath::validate("data/important.bin").unwrap();
    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());

    let mut session = create_client_session(&harness, "writer-node").await;

    let create = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "data/important.bin".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 1).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(err.code, ErrorCode::FileNotFound); // coarse authz collapse

    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());
    assert_eq!(
        harness
            .stats
            .deletions_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_disabled_policy_rejects_even_admin() {
    let grants = vec![Grant {
        identity: "super-admin".to_string(),
        path_prefix: "".to_string(),
        permissions: Role::Admin.permissions(),
    }];

    // Deletion globally disabled on server (immutable archive mode)
    let harness = start_harness(DeletionPolicy::Disabled, None, grants).await;

    let target_dir = harness.storage_root.join("archive");
    tokio::fs::create_dir_all(&target_dir).await.unwrap();
    let abs_file = target_dir.join("doc.pdf");
    tokio::fs::write(&abs_file, b"permanent archive")
        .await
        .unwrap();

    let vpath = VPath::validate("archive/doc.pdf").unwrap();
    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());

    let mut session = create_client_session(&harness, "super-admin").await;

    let create = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "archive/doc.pdf".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 1).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert!(err.detail.as_str().contains("disabled on this server"));

    assert!(harness.backend.stat(&vpath).await.unwrap().is_some());
    assert_eq!(
        harness
            .stats
            .deletions_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_rate_limited_policy_enforcement() {
    let grants = vec![Grant {
        identity: "replica".to_string(),
        path_prefix: "data".to_string(),
        permissions: Role::SyncReplica.permissions(),
    }];

    // Allow at most 2 deletions in a 60 second window
    let limiter = DeletionLimiter::new();
    let harness = start_harness(
        DeletionPolicy::RateLimited {
            max_deletions: 2,
            window_secs: 60,
        },
        Some(limiter),
        grants,
    )
    .await;

    let target_dir = harness.storage_root.join("data");
    tokio::fs::create_dir_all(&target_dir).await.unwrap();
    tokio::fs::write(target_dir.join("file1.tmp"), b"1")
        .await
        .unwrap();
    tokio::fs::write(target_dir.join("file2.tmp"), b"2")
        .await
        .unwrap();
    tokio::fs::write(target_dir.join("file3.tmp"), b"3")
        .await
        .unwrap();

    let p1 = VPath::validate("data/file1.tmp").unwrap();
    let p2 = VPath::validate("data/file2.tmp").unwrap();
    let p3 = VPath::validate("data/file3.tmp").unwrap();
    assert!(harness.backend.stat(&p1).await.unwrap().is_some());
    assert!(harness.backend.stat(&p2).await.unwrap().is_some());
    assert!(harness.backend.stat(&p3).await.unwrap().is_some());

    let mut session = create_client_session(&harness, "replica").await;

    // First deletion -> OK
    let c1 = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "data/file1.tmp".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    session
        .send_mut()
        .write_all(Bytes::from(
            encode_message(&Message::TransferCreate(c1), 1).unwrap(),
        ))
        .await
        .unwrap();
    let f1 = session.recv_frame().await.unwrap();
    assert_eq!(f1.type_byte, velcrux_core::protocol::message::COMMITTED);

    // Second deletion -> OK
    let c2 = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "data/file2.tmp".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    session
        .send_mut()
        .write_all(Bytes::from(
            encode_message(&Message::TransferCreate(c2), 2).unwrap(),
        ))
        .await
        .unwrap();
    let f2 = session.recv_frame().await.unwrap();
    assert_eq!(f2.type_byte, velcrux_core::protocol::message::COMMITTED);

    // Third deletion -> Rate limit exceeded!
    let c3 = TransferCreate {
        op: TransferOp::SyncDelete,
        src_path: "".into(),
        dst_path: "data/file3.tmp".into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    session
        .send_mut()
        .write_all(Bytes::from(
            encode_message(&Message::TransferCreate(c3), 3).unwrap(),
        ))
        .await
        .unwrap();
    let f3 = session.recv_frame().await.unwrap();
    assert_eq!(f3.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(f3.payload).unwrap();
    assert_eq!(err.code, ErrorCode::QuotaExceeded);
    assert!(err.detail.as_str().contains("rate limit exceeded"));

    // File 3 must still exist
    assert!(harness.backend.stat(&p3).await.unwrap().is_some());
    assert_eq!(
        harness
            .stats
            .deletions_executed
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(
        harness
            .stats
            .deletions_blocked
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}
