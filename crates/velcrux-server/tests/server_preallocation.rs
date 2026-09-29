//! Integration tests for Option T: Storage Preallocation (`fallocate`) & Free Disk Space Reservation
//! (`SECURITY.md` §6; `OPERATIONS.md` §4).
//!
//! Verifies:
//! 1. Live filesystem available space inspection (`backend.available_space()`).
//! 2. Staging file preallocation (`open_staging_resumable` with `size_hint` allocates physical blocks upfront).
//! 3. Disk space reservation margin enforcement (`min_free_space`):
//!    - Fails closed with `ErrorCode::DiskFull` (`4002`) before chunk writes when disk margin is exhausted.
//!    - Protects host against unbounded disk saturation without writing orphaned staging files.
//! 4. Live QUIC loopback upload rejection on disk exhaustion:
//!    - Connects via QUIC.
//!    - Sends `TransferCreate` exceeding disk margin reservation.
//!    - Server rejects transfer with `ErrorCode::DiskFull` (`4002`).
//!    - Increments Prometheus counter `velcrux_disk_full_total`.
//!    - Zero bytes committed to storage root.
//! 5. Live QUIC loopback normal upload acceptance:
//!    - Upload passes preallocation margin check.
//!    - Server accepts with `TRANSFER_CREATED`.
//! 6. Staging file resumption with preallocation:
//!    - Resuming an existing preallocated staging file does not truncate or corrupt data.
//! 7. Config validation and Prometheus metrics serialization for `velcrux_disk_full_total` and
//!    `velcrux_resource_limit_hits_total{limit="disk_full"}`.

#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use tempfile::tempdir;

use velcrux_core::auth::{Authorizer, FileAuthorizer, Grant, PermSet};
use velcrux_core::error::VelcruxError;
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{ErrorMsg, Message, TransferCreate, TransferOp};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::{FileMeta, LocalFilesystemBackend, StorageBackend, VPath};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};
use velcrux_server::config::ServerConfig;
use velcrux_server::metrics::format_prometheus_metrics;

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
    dn.push(DnType::CommonName, "velcrux-prealloc-ca");
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
// 1. Filesystem available space unit test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_filesystem_available_space_query() {
    let root_td = tempdir().unwrap();
    let staging_td = tempdir().unwrap();
    let backend = LocalFilesystemBackend::new(
        root_td.path().to_path_buf(),
        staging_td.path().to_path_buf(),
    )
    .await
    .expect("backend new")
    .with_preallocation(true, 1024 * 1024);

    let avail = backend
        .available_space()
        .await
        .expect("query available space");
    assert!(
        avail > 0,
        "available space on disk must be positive, got {}",
        avail
    );
    assert_eq!(backend.min_free_space(), 1024 * 1024);
    assert!(backend.preallocate_enabled());
}

// ---------------------------------------------------------------------------
// 2. Staging preallocation allocates physical file size upfront
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_staging_preallocation_allocates_disk() {
    let root_td = tempdir().unwrap();
    let staging_td = tempdir().unwrap();
    let backend = LocalFilesystemBackend::new(
        root_td.path().to_path_buf(),
        staging_td.path().to_path_buf(),
    )
    .await
    .expect("backend new")
    .with_preallocation(true, 0);

    let vpath = VPath::validate("sub/dir/prealloc_file.bin").unwrap();
    let target_size = 65536u64; // 64 KiB

    let mut writer = backend
        .open_staging_resumable("tid-prealloc-1", &vpath, target_size, false)
        .await
        .expect("open staging resumable");
    assert_eq!(
        writer.written(),
        0,
        "new staging file should have initial written 0"
    );

    // Write first 128 bytes
    let payload = vec![0xABu8; 128];
    writer
        .write_at(0, &payload)
        .await
        .expect("write payload at 0");
    writer.fsync().await.expect("fsync");

    // Metadata on the staging file should reflect preallocation (allocated to 65536)
    let meta = tokio::fs::metadata(writer.path())
        .await
        .expect("file metadata");
    assert!(
        meta.len() >= target_size,
        "staging file len {} should be at least target size {}",
        meta.len(),
        target_size
    );
}

// ---------------------------------------------------------------------------
// 3. Disk space reservation margin rejection (fail closed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_disk_reservation_margin_rejection() {
    let root_td = tempdir().unwrap();
    let staging_td = tempdir().unwrap();

    // Query real disk space
    let probe_backend = LocalFilesystemBackend::new(
        root_td.path().to_path_buf(),
        staging_td.path().to_path_buf(),
    )
    .await
    .unwrap();
    let real_avail = probe_backend.available_space().await.unwrap();

    // Set min_free_space so that (real_avail + 10_000_000) exceeds real_avail
    let impossible_margin = real_avail.saturating_add(10_000_000);
    let backend = LocalFilesystemBackend::new(
        root_td.path().to_path_buf(),
        staging_td.path().to_path_buf(),
    )
    .await
    .unwrap()
    .with_preallocation(true, impossible_margin);

    let vpath = VPath::validate("overflow.bin").unwrap();
    let res = backend
        .open_staging_resumable("tid-overflow", &vpath, 1024, false)
        .await;

    match res {
        Err(VelcruxError::Protocol(velcrux_core::error::ProtocolError::DiskFull(msg))) => {
            assert!(
                msg.contains("insufficient disk space"),
                "expected insufficient disk space message, got: {}",
                msg
            );
        }
        other => panic!("expected ProtocolError::DiskFull, got: {:?}", other),
    }

    // Verify no file was created in staging directory
    let mut entries = tokio::fs::read_dir(staging_td.path()).await.unwrap();
    let mut count = 0;
    while let Ok(Some(_)) = entries.next_entry().await {
        count += 1;
    }
    assert_eq!(
        count, 0,
        "staging directory must remain clean after rejection"
    );
}

// ---------------------------------------------------------------------------
// 4. Staging file resumption with preallocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_resumable_staging_preallocation() {
    let root_td = tempdir().unwrap();
    let staging_td = tempdir().unwrap();
    let backend = LocalFilesystemBackend::new(
        root_td.path().to_path_buf(),
        staging_td.path().to_path_buf(),
    )
    .await
    .unwrap()
    .with_preallocation(true, 0);

    let vpath = VPath::validate("resumable_test.bin").unwrap();
    let target_size = 100_000u64;
    let tid = "tid-resumable-1";

    // Step 1: Open and write first chunk (30,000 bytes)
    {
        let mut writer = backend
            .open_staging_resumable(tid, &vpath, target_size, false)
            .await
            .expect("first open");
        assert_eq!(writer.written(), 0);
        let chunk1 = vec![0x11u8; 30_000];
        writer.write_at(0, &chunk1).await.expect("write chunk 1");
        writer.fsync().await.expect("fsync 1");
    }

    // Step 2: Open again as resumable
    {
        let mut writer = backend
            .open_staging_resumable(tid, &vpath, target_size, true)
            .await
            .expect("resume open");

        let chunk2 = vec![0x22u8; 70_000];
        writer
            .write_at(30_000, &chunk2)
            .await
            .expect("write chunk 2");
        writer.fsync().await.expect("fsync 2");

        let staging = writer.into_staging();
        backend
            .commit(tid, staging, &vpath, &FileMeta::new(100_000, Hash::ZERO))
            .await
            .expect("commit file");
    }

    let dest = root_td.path().join("resumable_test.bin");
    let content = tokio::fs::read(&dest).await.expect("read committed file");
    assert_eq!(content.len(), 100_000);
    assert_eq!(&content[0..30_000], &[0x11u8; 30_000][..]);
    assert_eq!(&content[30_000..100_000], &[0x22u8; 70_000][..]);
}

// ---------------------------------------------------------------------------
// 5. Live QUIC loopback upload rejection on disk exhaustion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_quic_loopback_disk_exhaustion_rejection() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "operator");

    let files_dir = tempdir().unwrap();
    let staging_dir = tempdir().unwrap();

    // Configure backend with impossible margin to force DiskFull
    let probe = LocalFilesystemBackend::new(
        files_dir.path().to_path_buf(),
        staging_dir.path().to_path_buf(),
    )
    .await
    .unwrap();
    let real_avail = probe.available_space().await.unwrap();
    let backend = Arc::new(
        LocalFilesystemBackend::new(
            files_dir.path().to_path_buf(),
            staging_dir.path().to_path_buf(),
        )
        .await
        .unwrap()
        .with_preallocation(true, real_avail.saturating_add(50_000_000)),
    );

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "operator".to_string(),
        path_prefix: "uploads".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());

    let tunables = TransportConfigTunables {
        receive_window: 4 * 1024 * 1024,
        stream_receive_window: 4 * 1024 * 1024,
        max_concurrent_streams: 8,
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

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = {
        let b = backend.clone();
        let s = stats.clone();
        let az = authz.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    while let Ok(conn) = server_transport.accept().await {
                        let b = b.clone();
                        let s = s.clone();
                        let az = az.clone();
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
                } => {},
                _ = &mut shutdown_rx => {}
            }
        })
    };

    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .with_tunables(tunables)
            .build()
            .expect("client build"),
    );

    // Client connects and attempts upload
    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let (send, recv) = conn.open_bi().await.expect("bi stream open");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "local.bin".to_string(),
        dst_path: "uploads/exhaustion_test.bin".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 10_000,
        file_hash: blake3_of(b"dummy"),
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(
        err.code,
        ErrorCode::DiskFull,
        "server must reject with ErrorCode::DiskFull"
    );

    // Verify stats counter incremented
    assert!(
        stats.disk_full_errors.load(Ordering::Relaxed) >= 1,
        "disk_full_errors counter must be >= 1"
    );

    // Verify no file was created in destination
    let dest_file = files_dir.path().join("uploads/exhaustion_test.bin");
    assert!(!dest_file.exists(), "destination file must not exist");

    let _ = session.bye().await;
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_millis(500), server_task).await;
}

// ---------------------------------------------------------------------------
// 6. Live QUIC loopback normal upload acceptance with preallocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_quic_loopback_normal_upload_acceptance() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "operator");

    let files_dir = tempdir().unwrap();
    let staging_dir = tempdir().unwrap();

    // Sane margin: 1 MiB (normal upload easily passes)
    let backend = Arc::new(
        LocalFilesystemBackend::new(
            files_dir.path().to_path_buf(),
            staging_dir.path().to_path_buf(),
        )
        .await
        .unwrap()
        .with_preallocation(true, 1024 * 1024),
    );

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "operator".to_string(),
        path_prefix: "uploads".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());

    let tunables = TransportConfigTunables {
        receive_window: 4 * 1024 * 1024,
        stream_receive_window: 4 * 1024 * 1024,
        max_concurrent_streams: 8,
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

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = {
        let b = backend.clone();
        let s = stats.clone();
        let az = authz.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    while let Ok(conn) = server_transport.accept().await {
                        let b = b.clone();
                        let s = s.clone();
                        let az = az.clone();
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
                } => {},
                _ = &mut shutdown_rx => {}
            }
        })
    };

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
    let (send, recv) = conn.open_bi().await.expect("bi stream open");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    let test_data = b"Hello from preallocated storage transfer! Bounded and verified.";
    let file_hash = blake3_of(test_data);
    let tid = TransferId::generate();

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "local.txt".to_string(),
        dst_path: "uploads/hello.txt".to_string(),
        idempotency_key: tid.to_string(),
        file_size: test_data.len() as u64,
        file_hash,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED,
        "transfer must be accepted and created when disk margin is sufficient"
    );

    let _ = session.bye().await;
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_millis(500), server_task).await;
}

// ---------------------------------------------------------------------------
// 7. Config parsing and Prometheus metrics serialization
// ---------------------------------------------------------------------------

#[test]
fn test_config_parsing_and_metrics() {
    let toml_content = r#"
[network]
listen = "127.0.0.1:7443"
max_connections = 50

[security]
certificate = "server.crt"
private_key = "server.key"
client_ca = "ca.crt"
grants = "grants.toml"

[storage]
root = "/tmp/data"
staging = "/tmp/staging"
state_db = "/tmp/state.db"
min_free_space = "500MiB"
preallocate = true

[telemetry]
metrics_listen = "127.0.0.1:9443"
"#;

    let cfg: ServerConfig = toml::from_str(toml_content).expect("parse config");
    assert_eq!(cfg.storage.min_free_space.as_deref(), Some("500MiB"));
    assert_eq!(cfg.storage.preallocate, Some(true));

    // Test metrics formatting includes disk_full_total and resource_limit_hits_total
    let stats = ServerStats::default();
    stats.disk_full_errors.store(7, Ordering::Relaxed);

    let metrics_text = format_prometheus_metrics(&stats);
    assert!(
        metrics_text.contains("# TYPE velcrux_disk_full_total counter"),
        "metrics must contain velcrux_disk_full_total type declaration"
    );
    assert!(
        metrics_text.contains("velcrux_disk_full_total 7"),
        "metrics must contain velcrux_disk_full_total counter value"
    );
    assert!(
        metrics_text.contains("velcrux_resource_limit_hits_total{limit=\"disk_full\"} 7"),
        "metrics must contain velcrux_resource_limit_hits_total label for disk_full"
    );
}
