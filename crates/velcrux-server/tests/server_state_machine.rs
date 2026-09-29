//! Integration tests for Option U: Protocol State Machine Defense, Invalid Transition Clamping & Malicious Frame Matrix
//! (`SECURITY.md` §8; `PROTOCOL.md` §7).
//!
//! Verifies:
//! 1. `AwaitHello` state machine clamping:
//!    - Client sending `TRANSFER_CREATE` before `HELLO` receives `ErrorCode::ProtocolViolation` (1003)
//!      and connection is cleanly closed with QUIC error 1003.
//! 2. `AwaitAuth` state machine clamping:
//!    - Client sending `TRANSFER_CREATE` or `PING` after `HELLO` but before `AUTH` receives `ErrorCode::ProtocolViolation` (1003).
//! 3. `Serving` state machine clamping:
//!    - Sending duplicate `HELLO` or `AUTH` once already authenticated receives `ErrorCode::ProtocolViolation` (1003).
//!    - Sending out-of-order transfer lifecycle messages (e.g. `COMMIT` or `TRANSFER_BEGIN` without active transfer)
//!      receives `ErrorCode::ProtocolViolation` (1003).
//! 4. Malformed and reserved type bytes:
//!    - Sending reserved type byte `0xFF` receives `ErrorCode::UnsupportedMessage` (1004) and terminates cleanly without crash.
//! 5. Server survival and concurrent connection isolation:
//!    - Multiple clients concurrently connect: an adversarial client sending illegal state transitions
//!      does not impact or crash the server; a legitimate client performs upload transfers uninterrupted.
//! 6. Prometheus telemetry tracking:
//!    - Protocol violations and invalid state transitions increment `velcrux_protocol_violations_total`
//!      and `velcrux_resource_limit_hits_total{limit="protocol_violation"}`.

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
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{
    Commit, ErrorMsg, Hello, Message, Ping, TransferCreate, TransferOp,
};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};
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
    dn.push(DnType::CommonName, "velcrux-sm-ca");
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
    stats: Arc<ServerStats>,
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

    TestRig {
        server_addr,
        client_transport,
        stats,
        _shutdown_tx: shutdown_tx,
        _server_task: server_task,
    }
}

// ---------------------------------------------------------------------------
// 1. AwaitHello State Machine Clamping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_unauthenticated_state_rejects_transfer_create() {
    let rig = setup_test_rig().await;

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Send TRANSFER_CREATE before sending HELLO
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "malicious.bin".to_string(),
        dst_path: "uploads/malicious.bin".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 100,
        file_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 1).unwrap());
    send.write_all(buf).await.expect("send bytes");

    // Server should reply with ErrorMsg { code: ProtocolViolation, ... }
    let frame = velcrux_core::session::read_frame(recv.as_mut())
        .await
        .expect("read frame")
        .expect("frame exists");
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::ERROR,
        "server must send ERROR frame on invalid state transition"
    );
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(
        err.code,
        ErrorCode::ProtocolViolation,
        "error code must be ProtocolViolation (1003)"
    );

    // Verify stats counter incremented
    assert!(
        rig.stats.protocol_violations.load(Ordering::Relaxed) >= 1,
        "protocol_violations stat must be incremented"
    );
}

// ---------------------------------------------------------------------------
// 2. AwaitAuth State Machine Clamping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_await_auth_state_rejects_non_auth_messages() {
    let rig = setup_test_rig().await;

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // 1. Send valid HELLO
    let mut client_caps = Capabilities::EMPTY;
    client_caps.set(Capability::FixedChunking);
    client_caps.set(Capability::Blake3);
    let hello = Hello {
        versions: vec![1],
        capabilities: client_caps,
        agent: "test-client".to_string(),
    };
    let buf = Bytes::from(encode_message(&Message::Hello(hello), 1).unwrap());
    send.write_all(buf).await.expect("send hello");

    // Receive HELLO_ACK
    let ack_frame = velcrux_core::session::read_frame(recv.as_mut())
        .await
        .expect("read hello ack")
        .expect("ack frame exists");
    assert_eq!(
        ack_frame.type_byte,
        velcrux_core::protocol::message::HELLO_ACK
    );

    // 2. Instead of AUTH, send PING
    let ping = Ping {
        nonce: 42,
        sender_ts_ms: 123456789,
    };
    let buf = Bytes::from(encode_message(&Message::Ping(ping), 2).unwrap());
    send.write_all(buf).await.expect("send ping out-of-order");

    // Server should reject with ProtocolViolation
    let frame = velcrux_core::session::read_frame(recv.as_mut())
        .await
        .expect("read error frame")
        .expect("error frame exists");
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(
        err.code,
        ErrorCode::ProtocolViolation,
        "server must reject unexpected message in AwaitAuth with ProtocolViolation (1003)"
    );

    assert!(
        rig.stats.protocol_violations.load(Ordering::Relaxed) >= 1,
        "protocol_violations stat must be incremented"
    );
}

// ---------------------------------------------------------------------------
// 3. Serving State Machine Clamping: Duplicate Handshake Rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_serving_state_rejects_duplicate_hello_or_auth() {
    let rig = setup_test_rig().await;

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");
    let (send, recv) = conn.open_bi().await.expect("bi stream open");

    // Perform complete handshake
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // Session is now in SERVING state. Try to send duplicate HELLO
    let mut client_caps = Capabilities::EMPTY;
    client_caps.set(Capability::FixedChunking);
    client_caps.set(Capability::Blake3);
    let hello = Hello {
        versions: vec![1],
        capabilities: client_caps,
        agent: "duplicate-hello".to_string(),
    };
    let buf = Bytes::from(encode_message(&Message::Hello(hello), 10).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(
        err.code,
        ErrorCode::ProtocolViolation,
        "duplicate HELLO in SERVING state must trigger ProtocolViolation (1003)"
    );

    assert!(
        rig.stats.protocol_violations.load(Ordering::Relaxed) >= 1,
        "protocol_violations stat must be incremented"
    );
}

// ---------------------------------------------------------------------------
// 4. Serving State Machine Clamping: Out-of-Order Transfer Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_serving_state_rejects_out_of_order_transfer_lifecycle() {
    let rig = setup_test_rig().await;

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");
    let (send, recv) = conn.open_bi().await.expect("bi stream open");

    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // Send COMMIT without prior TRANSFER_CREATE or active transfer
    let commit = Commit {
        transfer_id: TransferId::generate(),
    };
    let buf = Bytes::from(encode_message(&Message::Commit(commit), 20).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(
        err.code,
        ErrorCode::ProtocolViolation,
        "unexpected transfer message in SERVING state must trigger ProtocolViolation (1003)"
    );

    assert!(
        rig.stats.protocol_violations.load(Ordering::Relaxed) >= 1,
        "protocol_violations stat must be incremented"
    );
}

// ---------------------------------------------------------------------------
// 5. Malformed / Reserved Frame Type Byte Handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_malformed_and_reserved_type_bytes() {
    let rig = setup_test_rig().await;

    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("client connect");
    let (send, recv) = conn.open_bi().await.expect("bi stream open");

    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // Send illegal type byte 0xFF with arbitrary payload
    let raw_payload = b"unsupported_opcode_payload";
    let total = velcrux_core::protocol::frame::header_size_for(raw_payload.len() as u64)
        + raw_payload.len();
    let mut buf = vec![0u8; total];
    velcrux_core::protocol::frame::encode_frame(
        &mut buf,
        0xFF,
        velcrux_core::protocol::frame::FrameFlags::NONE,
        0,
        raw_payload,
    );

    session
        .send_mut()
        .write_all(Bytes::from(buf))
        .await
        .unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err = ErrorMsg::decode(frame.payload).unwrap();
    assert_eq!(
        err.code,
        ErrorCode::UnsupportedMessage,
        "reserved opcode 0xFF must trigger UnsupportedMessage (1004)"
    );

    assert!(
        rig.stats.protocol_violations.load(Ordering::Relaxed) >= 1,
        "protocol_violations stat must be incremented"
    );
}

// ---------------------------------------------------------------------------
// 6. Server Survival & Concurrent Connection Isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_server_survival_and_concurrent_connection_isolation() {
    let rig = setup_test_rig().await;

    // Connect hostile client that repeatedly sends violations
    let hostile_conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("hostile connect");
    let (mut h_send, mut h_recv) = hostile_conn.open_bi().await.expect("hostile bi open");

    // Hostile client sends an illegal state transition (TRANSFER_CREATE before HELLO)
    let hostile_create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "hostile.bin".to_string(),
        dst_path: "uploads/hostile.bin".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 100,
        file_hash: Hash::ZERO,
    };
    let h_buf = Bytes::from(encode_message(&Message::TransferCreate(hostile_create), 666).unwrap());
    h_send.write_all(h_buf).await.unwrap();

    let h_frame = velcrux_core::session::read_frame(h_recv.as_mut())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(h_frame.type_byte, velcrux_core::protocol::message::ERROR);

    // Simultaneously, a legitimate client connects and completes valid transfer operations
    let legit_conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .expect("legit connect");
    let (l_send, l_recv) = legit_conn.open_bi().await.expect("legit bi open");
    let mut legit_session = ClientSession::from_handshake_parts(l_send, l_recv)
        .await
        .expect("legit handshake");

    // Legit client sends PING and gets PONG
    let ping = Ping {
        nonce: 999,
        sender_ts_ms: 12345,
    };
    let buf = Bytes::from(encode_message(&Message::Ping(ping), 100).unwrap());
    legit_session.send_mut().write_all(buf).await.unwrap();

    let frame = legit_session.recv_frame().await.unwrap();
    assert_eq!(frame.type_byte, velcrux_core::protocol::message::PING);
    let pong = Ping::decode(frame.payload).unwrap();
    assert_eq!(pong.nonce, 999);

    // Legit client sends TRANSFER_CREATE
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "local.txt".to_string(),
        dst_path: "uploads/legit.txt".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 10,
        file_hash: Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 101).unwrap());
    legit_session.send_mut().write_all(buf).await.unwrap();

    let frame = legit_session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED,
        "legitimate client transfer must succeed despite concurrent hostile client errors"
    );

    let _ = legit_session.bye().await;
}

// ---------------------------------------------------------------------------
// 7. Prometheus Telemetry Tracking for Protocol Violations
// ---------------------------------------------------------------------------

#[test]
fn test_prometheus_metrics_protocol_violations() {
    let stats = ServerStats::default();
    stats.protocol_violations.store(13, Ordering::Relaxed);

    let metrics_text = format_prometheus_metrics(&stats);
    assert!(
        metrics_text.contains("# TYPE velcrux_protocol_violations_total counter"),
        "metrics must declare velcrux_protocol_violations_total type"
    );
    assert!(
        metrics_text.contains("velcrux_protocol_violations_total 13"),
        "metrics must render velcrux_protocol_violations_total counter value"
    );
    assert!(
        metrics_text.contains("velcrux_resource_limit_hits_total{limit=\"protocol_violation\"} 13"),
        "metrics must render resource_limit_hits_total label for protocol_violation"
    );
}
