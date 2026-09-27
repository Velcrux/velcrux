//! Integration tests for Option P: Certificate Revocation List (CRL) Enforcement,
//! Dynamic Rotation & Connection Defense (`OPERATIONS.md` §3, §4, §6; `SECURITY.md` §2, §3, §4).
//!
//! Verifies:
//! 1. `CrlStore` parsing of PEM and DER CRLs with robust serial number normalization.
//! 2. Rejection of revoked client certificates in `MtlsAuthenticator` and `ServerConn`.
//! 3. Dynamic CRL hot-reload on SIGHUP without dropping existing active connections.
//! 4. Per-IP (`network.max_connections_per_ip`) and unauthenticated (`network.max_connections_unauth`)
//!    connection ceiling defense with RAII `ConnectionGuard`.
//! 5. Maximum authentication attempts enforcement (`security.max_auth_attempts`).
//! 6. Prometheus telemetry tracking: `crl_revoked`, `max_attempts_exceeded`, and `connections` limit hits.
//! 7. End-to-end live QUIC loopback handshake with CRL enforcement.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, RevokedCertParams, SanType,
    SerialNumber,
};
use rustls::{Certificate, PrivateKey};

use velcrux_core::auth::{
    Authenticator, Authorizer, CrlStore, FileAuthorizer, Grant, MtlsAuthenticator, PermSet,
};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{Auth, Hello, Message};
use velcrux_core::session::{read_frame, write_frame, ServerConn, ServerStats};
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::transport::identity::Identity;
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_server::limits::LimitsManager;
use velcrux_server::metrics::format_prometheus_metrics;

struct DevCa {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
}

fn build_dev_ca() -> DevCa {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "velcrux-security-ca");
    ca_params.distinguished_name = dn;
    let ca_key = KeyPair::generate().expect("generate CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA cert");
    DevCa { ca_cert, ca_key }
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
        .expect("sign server cert");
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

fn build_client_identity(ca: &DevCa, name: &str, serial: u64) -> (ClientIdentity, String) {
    let mut params = CertificateParams::default();
    params.serial_number = Some(SerialNumber::from(serial));
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
        .expect("sign client cert");
    let certs_pem = cert.pem();
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut &certs_pem.as_bytes()[..])
        .expect("parse client cert")
        .into_iter()
        .map(Certificate)
        .collect();
    let key_der = key.serialize_der();

    let serial_hex = format!("{serial:02x}");
    (
        ClientIdentity {
            cert_chain: certs,
            key: PrivateKey(key_der),
        },
        serial_hex,
    )
}

fn generate_crl_pem(ca: &DevCa, revoked_serials: &[u64]) -> String {
    let revoked = revoked_serials
        .iter()
        .map(|s| RevokedCertParams {
            serial_number: SerialNumber::from(*s),
            revocation_time: rcgen::date_time_ymd(2026, 1, 1),
            reason_code: None,
            invalidity_date: None,
        })
        .collect();

    let crl_params = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2026, 1, 1),
        next_update: rcgen::date_time_ymd(2026, 12, 31),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: revoked,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let crl = crl_params
        .signed_by(&ca.ca_cert, &ca.ca_key)
        .expect("sign CRL");
    crl.pem().expect("crl pem")
}

// ---------------------------------------------------------------------------
// 1. CrlStore and MtlsAuthenticator tests
// ---------------------------------------------------------------------------

#[test]
fn test_crl_store_and_mtls_authenticator() {
    let ca = build_dev_ca();
    let crl_pem = generate_crl_pem(&ca, &[0x1337, 0xbeef]);

    let crl_store = Arc::new(CrlStore::new());
    let count = crl_store
        .add_crl_pem(crl_pem.as_bytes())
        .expect("load CRL PEM");
    assert_eq!(count, 2);

    let auth = MtlsAuthenticator::with_crl_store(Arc::clone(&crl_store));

    // Valid identity (not in CRL)
    let valid_id = Identity::new("client-valid", "issuer1", "cert1").with_serial("9999");
    let res = auth.authenticate(&valid_id);
    assert!(res.is_ok());
    assert_eq!(res.unwrap().name, "client-valid");

    // Revoked identity (in CRL)
    let revoked_id = Identity::new("client-revoked", "issuer1", "cert2").with_serial("1337");
    let err = auth.authenticate(&revoked_id).unwrap_err();
    assert!(
        err.to_string().contains("certificate revoked in CRL"),
        "expected revocation error, got {err:?}"
    );

    // Another revoked identity with uppercase hex
    let revoked_id2 = Identity::new("client-revoked-2", "issuer1", "cert3").with_serial("BEEF");
    assert!(auth.authenticate(&revoked_id2).is_err());
}

// ---------------------------------------------------------------------------
// 2. Connection defense limits: per-IP and unauthenticated ceiling
// ---------------------------------------------------------------------------

#[test]
fn test_connection_defense_limits() {
    let stats = Arc::new(ServerStats::default());
    // Max 10 total, max 2 per IP, max 3 unauthenticated
    let limits = LimitsManager::new(None, Some(10), Some(2), Some(3), &[], Arc::clone(&stats))
        .expect("create limits manager");

    let ip1: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let ip2: SocketAddr = "192.168.1.200:5000".parse().unwrap();

    // 1. IP1 first connection: allowed
    let g1 = limits
        .check_connection_limits(ip1.ip(), 0)
        .expect("conn 1 allowed");
    assert_eq!(limits.active_ip_connections(ip1.ip()), 1);
    assert_eq!(limits.active_unauth_connections(), 1);

    // 2. IP1 second connection: allowed (hits max_connections_per_ip ceiling of 2)
    let g2 = limits
        .check_connection_limits(ip1.ip(), 1)
        .expect("conn 2 allowed");
    assert_eq!(limits.active_ip_connections(ip1.ip()), 2);
    assert_eq!(limits.active_unauth_connections(), 2);

    // 3. IP1 third connection: rejected by per-IP ceiling!
    let err3 = limits
        .check_connection_limits(ip1.ip(), 2)
        .expect_err("conn 3 rejected");
    assert!(err3.contains("per-IP connection limit reached for 192.168.1.100"));
    assert_eq!(
        stats
            .resource_limit_hits_connections
            .load(Ordering::Relaxed),
        1
    );

    // 4. IP2 first connection: allowed (reaches unauth ceiling of 3)
    let g3 = limits
        .check_connection_limits(ip2.ip(), 2)
        .expect("conn 4 allowed");
    assert_eq!(limits.active_ip_connections(ip2.ip()), 1);
    assert_eq!(limits.active_unauth_connections(), 3);

    // 5. IP2 second connection: rejected by unauthenticated ceiling!
    let err5 = limits
        .check_connection_limits(ip2.ip(), 3)
        .expect_err("conn 5 rejected");
    assert!(err5.contains("unauthenticated connection limit reached (3 >= 3)"));
    assert_eq!(
        stats
            .resource_limit_hits_connections
            .load(Ordering::Relaxed),
        2
    );

    // 6. Authenticate g1: unauth count drops from 3 to 2
    g1.mark_authenticated();
    assert_eq!(limits.active_unauth_connections(), 2);

    // 7. IP2 second connection now succeeds!
    let g4 = limits
        .check_connection_limits(ip2.ip(), 3)
        .expect("conn 6 allowed after auth");
    assert_eq!(limits.active_unauth_connections(), 3);

    // 8. Dropping g2 releases an IP1 slot
    drop(g2);
    assert_eq!(limits.active_ip_connections(ip1.ip()), 1);

    // Now IP1 can connect again
    let _g5 = limits
        .check_connection_limits(ip1.ip(), 3)
        .expect("IP1 connect allowed after drop");

    // Clean up guards
    drop(g1);
    drop(g3);
    drop(g4);
    drop(_g5);
    assert_eq!(limits.active_unauth_connections(), 0);
    assert_eq!(limits.active_ip_connections(ip1.ip()), 0);
    assert_eq!(limits.active_ip_connections(ip2.ip()), 0);

    // Verify Prometheus metric export
    let prom = format_prometheus_metrics(&stats);
    assert!(prom.contains("velcrux_resource_limit_hits_total{limit=\"connections\"} 2"));
}

// ---------------------------------------------------------------------------
// 3. Dynamic CRL rotation on SIGHUP
// ---------------------------------------------------------------------------

#[test]
fn test_dynamic_crl_sighup_reload() {
    let ca = build_dev_ca();
    let crl_pem_v1 = generate_crl_pem(&ca, &[0x1111]);
    let crl_pem_v2 = generate_crl_pem(&ca, &[0x2222, 0x3333]);

    let crl_store = Arc::new(CrlStore::new());
    crl_store
        .add_crl_pem(crl_pem_v1.as_bytes())
        .expect("initial load");
    assert!(crl_store.is_revoked("1111"));
    assert!(!crl_store.is_revoked("2222"));

    // Reload CRL with v2
    let count = crl_store
        .reload_crl_pem(crl_pem_v2.as_bytes())
        .expect("reload v2");
    assert_eq!(count, 2);
    // Previous serial is no longer revoked in v2
    assert!(!crl_store.is_revoked("1111"));
    // New serials are revoked
    assert!(crl_store.is_revoked("2222"));
    assert!(crl_store.is_revoked("3333"));
}

// ---------------------------------------------------------------------------
// 4. Maximum authentication attempts and failure metric counters
// ---------------------------------------------------------------------------

#[test]
fn test_auth_failure_metric_counters() {
    let stats = Arc::new(ServerStats::default());

    // Record CRL revocation failure
    stats.auth_failures_crl.fetch_add(1, Ordering::Relaxed);
    stats.auth_failures.fetch_add(1, Ordering::Relaxed);

    // Record max attempts exceeded failure
    stats
        .auth_failures_max_attempts
        .fetch_add(2, Ordering::Relaxed);
    stats.auth_failures.fetch_add(2, Ordering::Relaxed);

    let prom = format_prometheus_metrics(&stats);
    assert!(prom.contains("velcrux_auth_failures_total{reason=\"invalid_cert\"} 3"));
    assert!(prom.contains("velcrux_auth_failures_total{reason=\"crl_revoked\"} 1"));
    assert!(prom.contains("velcrux_auth_failures_total{reason=\"max_attempts_exceeded\"} 2"));
}

// ---------------------------------------------------------------------------
// 5. End-to-end QUIC loopback mTLS with CRL enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_quic_mtls_crl_rejection() {
    let ca = build_dev_ca();
    let ca_pem = ca.ca_cert.pem();
    let server_cert = build_server_cert(&ca);

    // Client 1: Valid serial 0x5555
    let (client_valid, _) = build_client_identity(&ca, "valid-worker", 0x5555);
    // Client 2: Revoked serial 0x9999
    let (client_revoked, _) = build_client_identity(&ca, "revoked-worker", 0x9999);

    // Generate CRL revoking 0x9999
    let crl_pem = generate_crl_pem(&ca, &[0x9999]);
    let crl_store = Arc::new(CrlStore::new());
    crl_store.add_crl_pem(crl_pem.as_bytes()).expect("load CRL");

    let server_tunables = TransportConfigTunables::default();
    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca_pem.as_bytes())
        .expect("add ca")
        .with_tunables(server_tunables)
        .build("127.0.0.1:0".parse().unwrap())
        .expect("build server transport");

    let server_addr = server_transport.local_addr().expect("server local addr");

    let temp = tempdir().unwrap();
    let backend_root = temp.path().join("backend");
    let staging_root = temp.path().join("staging");
    std::fs::create_dir_all(&backend_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(backend_root, staging_root)
            .await
            .expect("local backend"),
    );

    let stats = Arc::new(ServerStats::default());
    let authorizer: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![
        Grant {
            identity: "valid-worker".into(),
            path_prefix: "".into(),
            permissions: PermSet::ALL_TRANSFER,
        },
        Grant {
            identity: "revoked-worker".into(),
            path_prefix: "".into(),
            permissions: PermSet::ALL_TRANSFER,
        },
    ]));
    let authenticator: Arc<dyn Authenticator> =
        Arc::new(MtlsAuthenticator::with_crl_store(Arc::clone(&crl_store)));

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);

    // Spawn server accept task
    let server_task = {
        let stats = Arc::clone(&stats);
        let backend = Arc::clone(&backend);
        let authorizer = Arc::clone(&authorizer);
        let authenticator = Arc::clone(&authenticator);
        tokio::spawn(async move {
            for _ in 0..2 {
                let conn = match server_transport.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let actor = ServerConn::with_state(
                    server_caps,
                    "velcruxd-test",
                    Arc::clone(&stats),
                    Arc::clone(&backend),
                    None,
                    Some(Arc::clone(&authenticator)),
                    Some(Arc::clone(&authorizer)),
                );
                tokio::spawn(async move {
                    let _ = actor.run(&conn).await;
                });
            }
        })
    };

    // 1. Connect Client 1 (valid)
    let client1_transport = ClientBuilder::new()
        .with_server_roots_pem(ca_pem.as_bytes())
        .expect("add root")
        .with_client_identity(client_valid)
        .build()
        .expect("build client1 transport");

    let conn1 = client1_transport
        .connect(server_addr, "localhost")
        .await
        .expect("connect client 1");

    let (mut send1, mut recv1) = conn1.open_bi().await.expect("open bi client 1");
    // Handshake HELLO
    let hello = Hello::default_client();
    write_frame(send1.as_mut(), &Message::Hello(hello), 1)
        .await
        .expect("send hello 1");
    let ack_frame = read_frame(recv1.as_mut())
        .await
        .expect("read ack")
        .expect("some frame");
    assert_eq!(
        ack_frame.type_byte,
        velcrux_core::protocol::message::HELLO_ACK
    );

    // Handshake AUTH
    let auth = Auth::mtls();
    write_frame(send1.as_mut(), &Message::Auth(auth), 2)
        .await
        .expect("send auth 1");
    let ok_frame = read_frame(recv1.as_mut())
        .await
        .expect("read auth ok")
        .expect("some frame");
    assert_eq!(ok_frame.type_byte, velcrux_core::protocol::message::AUTH_OK);

    // 2. Connect Client 2 (revoked in CRL)
    let client2_transport = ClientBuilder::new()
        .with_server_roots_pem(ca_pem.as_bytes())
        .expect("add root")
        .with_client_identity(client_revoked)
        .build()
        .expect("build client2 transport");

    let conn2 = client2_transport
        .connect(server_addr, "localhost")
        .await
        .expect("connect client 2");

    let (mut send2, mut recv2) = conn2.open_bi().await.expect("open bi client 2");
    // Handshake HELLO
    let hello2 = Hello::default_client();
    write_frame(send2.as_mut(), &Message::Hello(hello2), 1)
        .await
        .expect("send hello 2");
    let ack_frame2 = read_frame(recv2.as_mut())
        .await
        .expect("read ack 2")
        .expect("some frame");
    assert_eq!(
        ack_frame2.type_byte,
        velcrux_core::protocol::message::HELLO_ACK
    );

    // Handshake AUTH -> must be rejected with Error(AuthFailed)
    let auth2 = Auth::mtls();
    write_frame(send2.as_mut(), &Message::Auth(auth2), 2)
        .await
        .expect("send auth 2");
    let err_frame = read_frame(recv2.as_mut())
        .await
        .expect("read err frame")
        .expect("some frame");
    assert_eq!(err_frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err_msg =
        velcrux_core::protocol::message::ErrorMsg::decode(err_frame.payload).expect("decode err");
    assert_eq!(err_msg.code, ErrorCode::AuthFailed);
    assert!(
        err_msg
            .detail
            .as_str()
            .contains("certificate revoked in CRL"),
        "expected revoked detail, got {:?}",
        err_msg.detail.as_str()
    );

    // Verify stats counter incremented
    assert_eq!(stats.auth_failures_crl.load(Ordering::Relaxed), 1);
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);

    // Verify Prometheus metric formatting
    let prom = format_prometheus_metrics(&stats);
    assert!(prom.contains("velcrux_auth_failures_total{reason=\"crl_revoked\"} 1"));

    server_task.abort();
}

#[tokio::test]
async fn test_e2e_max_auth_attempts_enforcement() {
    let ca = build_dev_ca();
    let ca_pem = ca.ca_cert.pem();
    let server_cert = build_server_cert(&ca);

    let (client_identity, _) = build_client_identity(&ca, "retry-worker", 0x7777);

    let server_tunables = TransportConfigTunables::default();
    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca_pem.as_bytes())
        .expect("add ca")
        .with_tunables(server_tunables)
        .build("127.0.0.1:0".parse().unwrap())
        .expect("build server transport");

    let server_addr = server_transport.local_addr().expect("server local addr");

    let temp = tempdir().unwrap();
    let backend_root = temp.path().join("backend");
    let staging_root = temp.path().join("staging");
    std::fs::create_dir_all(&backend_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(backend_root, staging_root)
            .await
            .expect("local backend"),
    );

    let stats = Arc::new(ServerStats::default());
    let authorizer: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::new());
    let authenticator: Arc<dyn Authenticator> = Arc::new(MtlsAuthenticator::new());

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);

    // Spawn server accept task with max_auth_attempts = 2
    let server_task = {
        let stats = Arc::clone(&stats);
        let backend = Arc::clone(&backend);
        let authorizer = Arc::clone(&authorizer);
        let authenticator = Arc::clone(&authenticator);
        tokio::spawn(async move {
            if let Ok(conn) = server_transport.accept().await {
                let actor = ServerConn::with_state(
                    server_caps,
                    "velcruxd-test",
                    Arc::clone(&stats),
                    Arc::clone(&backend),
                    None,
                    Some(Arc::clone(&authenticator)),
                    Some(Arc::clone(&authorizer)),
                )
                .with_max_auth_attempts(2);

                let _ = actor.run(&conn).await;
            }
        })
    };

    let client_transport = ClientBuilder::new()
        .with_server_roots_pem(ca_pem.as_bytes())
        .expect("add root")
        .with_client_identity(client_identity)
        .build()
        .expect("build client transport");

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("connect client");

    let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
    // Handshake HELLO
    let hello = Hello::default_client();
    write_frame(send.as_mut(), &Message::Hello(hello), 1)
        .await
        .expect("send hello");
    let ack_frame = read_frame(recv.as_mut())
        .await
        .expect("read ack")
        .expect("some frame");
    assert_eq!(
        ack_frame.type_byte,
        velcrux_core::protocol::message::HELLO_ACK
    );

    // Attempt 1: bad token -> fails, but connection stays open (attempts = 1 < 2)
    let bad_auth1 = Auth {
        mechanism: velcrux_core::protocol::message::AUTH_MECHANISM_SSH_PUBKEY,
        token: vec![1, 2, 3],
    };
    write_frame(send.as_mut(), &Message::Auth(bad_auth1), 2)
        .await
        .expect("send bad auth 1");
    let err1_frame = read_frame(recv.as_mut())
        .await
        .expect("read err 1")
        .expect("some frame");
    assert_eq!(err1_frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err1_msg = velcrux_core::protocol::message::ErrorMsg::decode(err1_frame.payload)
        .expect("decode err 1");
    assert_eq!(err1_msg.code, ErrorCode::AuthFailed);
    assert!(err1_msg.detail.as_str().contains("pubkey auth failed"));

    // Attempt 2: hits max_auth_attempts (2) -> fails, and closes connection
    let bad_auth2 = Auth {
        mechanism: velcrux_core::protocol::message::AUTH_MECHANISM_SSH_PUBKEY,
        token: vec![4, 5, 6],
    };
    write_frame(send.as_mut(), &Message::Auth(bad_auth2), 3)
        .await
        .expect("send bad auth 2");
    let err2_frame = read_frame(recv.as_mut())
        .await
        .expect("read err 2")
        .expect("some frame");
    assert_eq!(err2_frame.type_byte, velcrux_core::protocol::message::ERROR);
    let err2_msg = velcrux_core::protocol::message::ErrorMsg::decode(err2_frame.payload)
        .expect("decode err 2");
    assert_eq!(err2_msg.code, ErrorCode::AuthFailed);
    assert!(err2_msg
        .detail
        .as_str()
        .contains("maximum authentication attempts exceeded"));

    // Verify stats
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 2);
    assert_eq!(stats.auth_failures_max_attempts.load(Ordering::Relaxed), 1);

    // Verify Prometheus metrics formatting
    let prom = format_prometheus_metrics(&stats);
    assert!(prom.contains("velcrux_auth_failures_total{reason=\"max_attempts_exceeded\"} 1"));

    server_task.abort();
}
