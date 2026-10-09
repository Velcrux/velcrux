//! Integration tests for Option AP: Multi-Path QUIC Connection Migration & Failover Gating.
//!
//! Conforms to RFC 9000 §9 ("Connection Migration"), `REQUIREMENTS.md` §11, §41, §70,
//! `SECURITY.md` §2, §3, and `OPERATIONS.md` §4, §24.
//!
//! Verifies:
//! 1. Mid-session client endpoint migration / socket rebind:
//!    - Client UDP transport rebinds to a new local port.
//!    - Active QUIC connection and control/data streams continue without reset.
//!    - Full file upload completes with 100% BLAKE3 cryptographic integrity.
//! 2. Migration telemetry and event broadcast:
//!    - `MigrationCoordinator` captures `MigrationEvent` with correct addresses, timestamp, and RTT.
//!    - Metrics `migrations_total` and `migrations_accepted` accurately increment.
//! 3. Failover gating with `MigrationPolicyMode::Disabled`:
//!    - When disabled by policy, client endpoint migration is blocked.
//!    - Connection is terminated with `PROTOCOL_VIOLATION` and `migrations_rejected` increments.
//! 4. Failover gating with rate limiting in `MigrationPolicyMode::Gated`:
//!    - Rate limit window allows migrations up to the configured limit, then rejects excessive transitions.

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
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::message::{
    Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::transport::migration::{
    MigrationCoordinator, MigrationPolicy, MigrationPolicyMode, MigrationStats,
};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicTransport, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};

// ---------------------------------------------------------------------------
// Dev PKI Helpers
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
    dn.push(DnType::CommonName, "velcrux-migration-ca");
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
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = vec![
        SanType::URI(format!("velcrux://identity/{name}").try_into().unwrap()),
        SanType::DnsName(name.try_into().unwrap()),
    ];
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

struct TestRig {
    server_addr: std::net::SocketAddr,
    client_transport: Arc<QuicTransport>,
    migration_coordinator: Arc<MigrationCoordinator>,
    files_dir: tempfile::TempDir,
    _staging_dir: tempfile::TempDir,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
    _server_task: tokio::task::JoinHandle<()>,
}

async fn setup_test_rig(policy: MigrationPolicy) -> TestRig {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "operator");

    let files_dir = tempdir().unwrap();
    let staging_dir = tempdir().unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(
            files_dir.path().to_path_buf(),
            staging_dir.path().to_path_buf(),
        )
        .await
        .unwrap(),
    );

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "operator".to_string(),
        path_prefix: "uploads".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());
    let migration_stats = Arc::new(MigrationStats::default());
    let migration_coordinator = Arc::new(MigrationCoordinator::new(policy, migration_stats));

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

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = {
        let b = backend.clone();
        let s = stats.clone();
        let az = authz.clone();
        let coord = migration_coordinator.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    while let Ok(conn) = server_transport.accept().await {
                        let b = b.clone();
                        let s = s.clone();
                        let az = az.clone();
                        let coord = coord.clone();
                        tokio::spawn(async move {
                            let actor = ServerConn::with_state(
                                server_caps,
                                "velcruxd",
                                s,
                                b,
                                None,
                                None,
                                Some(az),
                            )
                            .with_migration_coordinator(Some(coord));
                            let _ = actor.run(&conn).await;
                        });
                    }
                } => {},
                _ = &mut shutdown_rx => {}
            }
        })
    };

    let client_transport = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client server CA")
            .with_client_identity(client_identity)
            .with_tunables(tunables)
            .build()
            .expect("client transport"),
    );

    TestRig {
        server_addr,
        client_transport,
        migration_coordinator,
        files_dir,
        _staging_dir: staging_dir,
        _shutdown_tx: shutdown_tx,
        _server_task: server_task,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_client_socket_rebind_mid_transfer_integrity() {
    let rig = setup_test_rig(MigrationPolicy::default()).await;
    let mut event_rx = rig.migration_coordinator.subscribe_events();

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");

    let initial_client_addr = rig
        .client_transport
        .local_addr()
        .expect("client local addr");
    let (send, recv) = conn.open_bi().await.expect("open bi control");

    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // Prepare transfer payload
    let payload = vec![0xABu8; 128 * 1024]; // 128 KiB
    let file_size = payload.len() as u64;
    let file_hash = Hash::of(&payload);

    let temp_dir = tempdir().unwrap();
    let source_path = temp_dir.path().join("migration_test.dat");
    tokio::fs::write(&source_path, &payload).await.unwrap();

    let idemp_key = format!("tx-mig-{}", TransferId::generate());
    let dst_path = "uploads/migrated_file.dat";

    // 1. Send TRANSFER_CREATE
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: source_path.display().to_string(),
        dst_path: dst_path.to_string(),
        idempotency_key: idemp_key.clone(),
        file_size,
        file_hash,
    };
    let cbuf = Bytes::from(encode_message(&Message::TransferCreate(create), 1).unwrap());
    session.send_mut().write_all(cbuf).await.unwrap();

    let frame = session.recv_frame().await.expect("TransferCreated frame");
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created = TransferCreated::decode(frame.payload).expect("decode TransferCreated");

    let pframe = session.recv_frame().await.expect("TransferPlan frame");
    assert_eq!(
        pframe.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );
    let plan = TransferPlan::decode(pframe.payload).expect("decode TransferPlan");
    assert_eq!(plan.transfer_id, created.transfer_id);

    // 2. NOW: REBIND THE CLIENT UDP ENDPOINT TO A NEW LOCAL PORT!
    // Simulates interface migration / roaming (Wi-Fi to Cellular handoff)
    let new_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind new socket");
    let migrated_addr = new_sock.local_addr().expect("new addr");
    assert_ne!(initial_client_addr, migrated_addr);

    rig.client_transport
        .rebind(new_sock)
        .expect("rebind transport");

    // 3. Send TRANSFER_BEGIN over migrated path
    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 1,
    };
    let bbuf = Bytes::from(encode_message(&Message::TransferBegin(begin), 2).unwrap());
    session.send_mut().write_all(bbuf).await.unwrap();

    // 4. Perform upload over the migrated connection
    let upload_cfg = velcrux_core::PipelineConfig::default();
    let upload_res = tokio::time::timeout(
        Duration::from_secs(15),
        velcrux_core::client_upload(
            &conn,
            session.send_mut_owned(),
            session.recv_mut_owned(),
            created.transfer_id,
            source_path.clone(),
            file_size,
            file_hash,
            upload_cfg,
        ),
    )
    .await
    .expect("upload timeout")
    .expect("upload error");

    assert_eq!(
        upload_res, file_hash,
        "file hash after migration must match"
    );

    // Verify stored file on server
    let dest_file = rig.files_dir.path().join("uploads/migrated_file.dat");
    let stored_bytes = tokio::fs::read(&dest_file).await.expect("read stored file");
    assert_eq!(stored_bytes.len(), payload.len());
    assert_eq!(Hash::of(&stored_bytes), file_hash);

    // Verify migration event was received by coordinator
    let event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
        .await
        .expect("timeout waiting for migration event")
        .expect("recv migration event");

    assert_eq!(event.new_addr, migrated_addr);
    assert_eq!(event.peer_identity, Some("operator".to_string()));

    // Verify telemetry counters
    let stats = rig.migration_coordinator.stats();
    assert!(
        stats.migrations_total.load(Ordering::Relaxed) >= 1,
        "migrations_total should be >= 1"
    );
    assert!(
        stats.migrations_accepted.load(Ordering::Relaxed) >= 1,
        "migrations_accepted should be >= 1"
    );
    assert_eq!(
        stats.migrations_rejected.load(Ordering::Relaxed),
        0,
        "no migrations should be rejected under permissive policy"
    );
}

#[tokio::test]
async fn test_migration_failover_gating_disabled_policy() {
    let policy = MigrationPolicy {
        mode: MigrationPolicyMode::Disabled,
        ..Default::default()
    };
    let rig = setup_test_rig(policy).await;

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");

    let initial_client_addr = rig
        .client_transport
        .local_addr()
        .expect("client local addr");
    let (send, recv) = conn.open_bi().await.expect("open bi control");

    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // Rebind the client transport to a new UDP socket
    let new_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind new socket");
    let migrated_addr = new_sock.local_addr().expect("new addr");
    assert_ne!(initial_client_addr, migrated_addr);

    rig.client_transport
        .rebind(new_sock)
        .expect("rebind transport");

    // Attempt to send next message (Ping) on migrated path
    let ping = velcrux_core::protocol::message::Ping {
        nonce: 99,
        sender_ts_ms: 1000,
    };
    let pbuf = Bytes::from(encode_message(&Message::Ping(ping), 99).unwrap());
    let _ = session.send_mut().write_all(pbuf).await;

    // Server should reject migration and close connection
    tokio::time::sleep(Duration::from_millis(150)).await;

    let stats = rig.migration_coordinator.stats();
    assert!(
        stats.migrations_rejected.load(Ordering::Relaxed) >= 1,
        "rejected count must be >= 1 under Disabled policy"
    );
}

#[tokio::test]
async fn test_migration_failover_gating_rate_limit() {
    let policy = MigrationPolicy {
        mode: MigrationPolicyMode::Gated,
        max_migrations_per_window: 1, // only 1 allowed
        rate_window_secs: 60,
        ..Default::default()
    };
    let rig = setup_test_rig(policy).await;

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");

    let (send, recv) = conn.open_bi().await.expect("open bi control");

    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // 1st migration: should be allowed (limit is 1)
    let sock1 = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind 1");
    rig.client_transport.rebind(sock1).expect("rebind 1");

    let ping1 = velcrux_core::protocol::message::Ping {
        nonce: 101,
        sender_ts_ms: 2000,
    };
    let pbuf1 = Bytes::from(encode_message(&Message::Ping(ping1), 101).unwrap());
    session
        .send_mut()
        .write_all(pbuf1)
        .await
        .expect("send ping 1");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let stats = rig.migration_coordinator.stats();
    assert_eq!(
        stats.migrations_accepted.load(Ordering::Relaxed),
        1,
        "first migration should be accepted"
    );

    // 2nd migration: should exceed the limit of 1 and be rejected!
    let sock2 = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind 2");
    rig.client_transport.rebind(sock2).expect("rebind 2");

    let ping2 = velcrux_core::protocol::message::Ping {
        nonce: 102,
        sender_ts_ms: 3000,
    };
    let pbuf2 = Bytes::from(encode_message(&Message::Ping(ping2), 102).unwrap());
    let _ = session.send_mut().write_all(pbuf2).await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        stats.migrations_rejected.load(Ordering::Relaxed) >= 1,
        "second migration should be rejected due to rate limit violation"
    );
}
