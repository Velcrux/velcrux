//! Integration tests for Option AN: Idempotent Transfer Session Replay & Checkpoint Coordinator
//! (`REQUIREMENTS.md` §67, §68, §69, §70; `OPERATIONS.md` §22).
//!
//! Validates:
//! 1. In-flight duplicate `TRANSFER_CREATE` replay:
//!    - Network reconnects and retried `TRANSFER_CREATE` frames rejoin the active session.
//! 2. Committed transfer replay:
//!    - Post-commit duplicate `TRANSFER_CREATE` with the same idempotency key immediately
//!      returns `COMMITTED` without redundant chunk transfer or duplicate storage I/O.
//! 3. Fail-closed parameter conflict rejection:
//!    - A retried `TRANSFER_CREATE` reusing an existing key with altered parameters (different
//!      destination path or file size) is rejected with `ErrorCode::ProtocolViolation`.
//! 4. Checkpoint coordination & durable recovery:
//!    - Active transfers balance byte milestones and staging syncs, reliably committing progress
//!      to the `StateStore` and enabling seamless resumption.

#![forbid(unsafe_code)]

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
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{
    Committed, ErrorMsg, Message, TransferCreate, TransferCreated, TransferOp,
};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::state::{
    ChunkBitmap, IdempotencyAction, IdempotencyLedger, MockStateStore, Role, StateStore,
    TransferRecord, TransferStatus,
};
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::transfer::{CheckpointCoordinator, CheckpointPolicy, CheckpointStats};
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
    dn.push(DnType::CommonName, "velcrux-idempotency-ca");
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

struct TestRig {
    server_addr: std::net::SocketAddr,
    client_transport: Arc<dyn Transport<Conn = QuicConnection>>,
    idempotency_ledger: Arc<IdempotencyLedger>,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
    _server_task: tokio::task::JoinHandle<()>,
}

async fn setup_test_rig() -> TestRig {
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
    let ledger = Arc::new(IdempotencyLedger::new());

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
        let led = ledger.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    while let Ok(conn) = server_transport.accept().await {
                        let b = b.clone();
                        let s = s.clone();
                        let az = az.clone();
                        let led = led.clone();
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
                            .with_idempotency_ledger(Some(led));
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
        idempotency_ledger: ledger,
        _shutdown_tx: shutdown_tx,
        _server_task: server_task,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_idempotent_transfer_replay_active_and_committed() {
    let rig = setup_test_rig().await;
    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();

    // 1. Initial Handshake & Auth via ClientSession
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // 2. Pre-mark an idempotency key as committed
    let idemp_key = "tx-idemp-001";
    let target_path = "uploads/committed_file.dat";
    let file_size = 1024 * 1024; // 1 MiB

    // Evaluate in ledger -> generates new TransferId
    let action = rig.idempotency_ledger.evaluate_transfer_create(
        Role::Server,
        idemp_key,
        target_path,
        file_size,
        None,
    );
    let tid = match action {
        IdempotencyAction::ProceedNew(id) => id,
        _ => panic!("expected ProceedNew"),
    };

    // Mark as committed
    rig.idempotency_ledger
        .mark_committed(Role::Server, idemp_key, 1);

    // 3. Now send TRANSFER_CREATE with the same key
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "file.dat".to_string(),
        dst_path: target_path.to_string(),
        idempotency_key: idemp_key.to_string(),
        file_size,
        file_hash: Hash::ZERO,
    };
    let cbuf = Bytes::from(encode_message(&Message::TransferCreate(create), 10).unwrap());
    session.send_mut().write_all(cbuf).await.unwrap();

    // The server MUST immediately return COMMITTED without demanding any chunk stream!
    let frame = session.recv_frame().await.expect("Committed frame");
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::COMMITTED,
        "Server must immediately replay COMMITTED for previously committed key"
    );
    let committed = Committed::decode(frame.payload).expect("decode Committed");
    assert_eq!(committed.transfer_id, tid);
    assert_eq!(committed.files, 1);
}

#[tokio::test]
async fn test_idempotent_transfer_parameter_conflict_rejection() {
    let rig = setup_test_rig().await;
    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();

    // 1. Initial Handshake & Auth via ClientSession
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // 2. Pre-register key with path "uploads/alpha.bin" and size 2048
    let key = "tx-conflict-999";
    let _ = rig.idempotency_ledger.evaluate_transfer_create(
        Role::Server,
        key,
        "uploads/alpha.bin",
        2048,
        None,
    );

    // 3. Client sends TRANSFER_CREATE with altered path "uploads/beta.bin"
    let conflicted_create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "file.bin".to_string(),
        dst_path: "uploads/beta.bin".to_string(),
        idempotency_key: key.to_string(),
        file_size: 2048,
        file_hash: Hash::ZERO,
    };
    let cbuf =
        Bytes::from(encode_message(&Message::TransferCreate(conflicted_create), 10).unwrap());
    session.send_mut().write_all(cbuf).await.unwrap();

    // The server MUST fail-closed and return ProtocolViolation error
    let frame = session.recv_frame().await.expect("Error frame");
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).expect("decode Error");
    assert_eq!(err.code, ErrorCode::ProtocolViolation);
    assert!(
        err.detail.0.contains("idempotency conflict"),
        "error message must describe parameter conflict: {}",
        err.detail.0
    );
}

#[tokio::test]
async fn test_checkpoint_coordinator_evaluation_and_flush() {
    let stats = Arc::new(CheckpointStats::default());
    let policy = CheckpointPolicy {
        bytes_threshold: 1024 * 1024, // 1 MiB
        time_interval: Duration::from_secs(60),
        chunk_threshold: 4,
        fsync_staging: true,
    };

    let mut coord = CheckpointCoordinator::new(policy, stats.clone());
    let store = Arc::new(MockStateStore::new());
    let tid = TransferId::generate();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let rec = TransferRecord {
        transfer_id: tid,
        idempotency_key: "tx-cp-test".to_string(),
        role: Role::Server,
        direction: velcrux_core::state::Direction::Upload,
        status: TransferStatus::Active,
        remote_path: "uploads/data.bin".to_string(),
        local_path: "".to_string(),
        file_size: 10 * 1024 * 1024,
        file_hash: Hash::of(b"dummy"),
        verified_up_to: 0,
        last_checkpoint_ms: now,
        bytes_completed: 0,
        staging_relpath: "staging/data.bin".to_string(),
        created_ms: now,
        updated_ms: now,
    };
    store.upsert_transfer(&rec).unwrap();

    // 1. Observe 3 small chunks (below chunk threshold 4 and below 1 MiB)
    assert!(!coord.observe_chunk(64 * 1024));
    assert!(!coord.observe_chunk(64 * 1024));
    assert!(!coord.observe_chunk(64 * 1024));

    // 2. 4th chunk hits chunk_threshold -> triggers checkpoint
    assert!(coord.observe_chunk(64 * 1024));

    // 3. Commit checkpoint
    let mut bitmap = ChunkBitmap::new();
    bitmap.mark_complete(0, 64 * 1024);
    bitmap.mark_complete(1, 64 * 1024);
    bitmap.mark_complete(2, 64 * 1024);
    bitmap.mark_complete(3, 64 * 1024);
    coord
        .commit_checkpoint(tid, 256 * 1024, &bitmap, store.as_ref())
        .unwrap();

    // Verify stats and store record
    assert_eq!(
        stats
            .checkpoints_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let updated = store.get_transfer(tid).unwrap();
    assert_eq!(updated.bytes_completed, 256 * 1024);
    assert_eq!(updated.status, TransferStatus::Active);

    // Verify stored bitmap
    let loaded_bm = store.read_bitmap(tid).unwrap();
    assert_eq!(loaded_bm.bytes_completed(), 256 * 1024);
}

#[tokio::test]
async fn test_idempotent_transfer_replay_active_in_flight() {
    let rig = setup_test_rig().await;
    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();

    // 1. Initial Handshake & Auth via ClientSession
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // 2. Register an in-flight active transfer in the ledger
    let idemp_key = "tx-inflight-042";
    let target_path = "uploads/active_stream.dat";
    let file_size = 5 * 1024 * 1024; // 5 MiB

    let initial_action = rig.idempotency_ledger.evaluate_transfer_create(
        Role::Server,
        idemp_key,
        target_path,
        file_size,
        None,
    );
    let expected_tid = match initial_action {
        IdempotencyAction::ProceedNew(id) => id,
        _ => panic!("expected ProceedNew"),
    };

    // 3. Client retries the identical TRANSFER_CREATE
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "stream.dat".to_string(),
        dst_path: target_path.to_string(),
        idempotency_key: idemp_key.to_string(),
        file_size,
        file_hash: Hash::ZERO,
    };
    let cbuf = Bytes::from(encode_message(&Message::TransferCreate(create), 10).unwrap());
    session.send_mut().write_all(cbuf).await.unwrap();

    // 4. Server recognizes active in-flight transfer and responds with TransferCreated (resumed = true)
    let frame = session.recv_frame().await.expect("TransferCreated frame");
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED,
        "Server must reply with TRANSFER_CREATED rejoining active transfer"
    );
    let created = TransferCreated::decode(frame.payload).expect("decode TransferCreated");
    assert_eq!(created.transfer_id, expected_tid);
    assert!(
        created.resumed,
        "Transfer must be marked as resumed when replaying active session"
    );
}
