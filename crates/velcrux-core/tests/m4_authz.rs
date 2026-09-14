//! M4 end-to-end authorization test (`docs/ARCHITECTURE.md` §12).
//!
//! **Exit criterion (M4):** *"Traversal and cross-tenant tests all denied."*
//!
//! This drives real QUIC + mTLS on loopback with **two distinct client
//! identities** — `tenant-a-user` and `tenant-b-user` — each presenting a
//! client certificate whose SAN URI is `velcrux://identity/<name>`. The
//! server extracts that identity from the verified certificate chain and
//! authorizes every operation against a strict, tenant-isolated grant set:
//! each identity may only touch its own `data/tenant{A,B}` prefix, and
//! nothing else (deny-by-default, `SECURITY.md` §4).
//!
//! The five sequential connections exercise both directions of the
//! criterion:
//!
//!   1. `tenant-b-user` uploads `data/tenantB/secret.bin`  → SUCCESS
//!      (positive control; also seeds a *real* file on disk).
//!   2. `tenant-a-user` downloads `data/tenantB/secret.bin` → DENIED.
//!      This is the crown-jewel cross-tenant read: the file physically
//!      EXISTS, yet the authorizer denies *before* any filesystem access,
//!      so tenant A receives the exact same uniform `FILE_NOT_FOUND` /
//!      "not found" it would get for a path that does not exist. Existence
//!      of another tenant's data must never leak (`PROTOCOL.md` §10).
//!   3. `tenant-a-user` uploads `data/tenantA/ok.bin`      → SUCCESS
//!      (positive control; authorization must not over-block).
//!   4. `tenant-a-user` uploads `data/tenantB/evil.bin`    → DENIED
//!      (cross-tenant *write*).
//!   5. `tenant-a-user` uploads `../../../../etc/passwd`   → DENIED
//!      (path traversal, rejected at `VPath` validation, which the
//!      authorizer runs before grant lookup).
//!
//! Every denial is asserted to produce the *identical* wire reply — a single
//! `ERROR` frame carrying `FILE_NOT_FOUND` with detail "not found" — so the
//! four distinct denial reasons (no grant, wrong tenant, missing perm,
//! malformed path) are indistinguishable on the wire. Finally, the test
//! asserts the denied write created NOTHING on disk (not even a staged
//! `.velcrux-partial`), proving the server returns before touching storage.
//!
//! Test data is 256 KiB of deterministic pseudo-random bytes (fixed seed),
//! enough to span multiple CDC chunks and run the streaming pipeline end to
//! end while staying fast for CI.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use velcrux_core::auth::{Authorizer, FileAuthorizer, Grant, PermSet};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::error::ErrorCode;
use velcrux_core::protocol::message::{
    ErrorMsg, Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::{LocalFilesystemBackend, StorageBackend, VPath};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::TransferId;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile;
use tokio::time::timeout;
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------------
// Dev PKI helpers (mirrors tests/m2_roundtrip.rs)
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
    dn.push(DnType::CommonName, "velcrux-test-ca");
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

/// Build a client identity whose SAN URI is `velcrux://identity/<name>`, so
/// the server derives exactly `name` from the verified certificate chain.
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

// ---------------------------------------------------------------------------
// Deterministic test data
// ---------------------------------------------------------------------------

const TEST_FILE_LEN: usize = 256 * 1024; // 256 KiB; >= default chunk min

fn pseudo_random(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for _ in 0..8 {
            if out.len() >= len {
                break;
            }
            out.push(state as u8);
        }
    }
    out
}

fn blake3_of(data: &[u8]) -> velcrux_core::Hash {
    use velcrux_core::HashHasher;
    let mut h = HashHasher::new();
    h.feed(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Client scenario helpers
// ---------------------------------------------------------------------------

/// Drive a full, authorized single-file upload on a fresh connection and
/// assert the server accepts it and returns the matching whole-file BLAKE3
/// hash. Used as a positive control and to seed real files on disk.
async fn upload_ok(
    client_transport: &Arc<dyn Transport<Conn = QuicConnection>>,
    server_addr: SocketAddr,
    source_path: &Path,
    file_size: u64,
    source_hash: velcrux_core::Hash,
    dst_path: &str,
) {
    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect (upload)");
    let (send, recv) = conn.open_bi().await.expect("control stream open (upload)");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("HELLO/HELLO_ACK/AUTH_OK (upload)");

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: source_path.display().to_string(),
        dst_path: dst_path.into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size,
        file_hash: source_hash,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED,
        "upload {dst_path:?}: expected TRANSFER_CREATED, got 0x{:02x}",
        frame.type_byte
    );
    let created = TransferCreated::decode(&frame.payload).unwrap();
    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN,
        "upload {dst_path:?}: expected TRANSFER_PLAN, got 0x{:02x}",
        frame.type_byte
    );
    let _plan = TransferPlan::decode(&frame.payload).unwrap();
    let begin = TransferBegin {
        transfer_id: created.transfer_id,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let cfg = velcrux_core::PipelineConfig::default();
    let upload_hash = timeout(
        Duration::from_secs(15),
        velcrux_core::client_upload(
            &conn,
            session.send_mut_owned(),
            session.recv_mut_owned(),
            created.transfer_id,
            source_path.to_path_buf(),
            file_size,
            source_hash,
            cfg,
        ),
    )
    .await
    .expect("upload did not finish in time")
    .expect("upload failed");
    assert_eq!(
        upload_hash, source_hash,
        "upload {dst_path:?}: server whole-file hash mismatch"
    );
    drop(conn);
}

/// Attempt a `TRANSFER_CREATE` for `op`/`dst_path` on a fresh connection and
/// assert the server DENIES it with the uniform wire reply mandated by
/// `PROTOCOL.md` §10: a single `ERROR` frame carrying `FILE_NOT_FOUND` with
/// detail "not found". Because the server authorizes before any filesystem
/// access, this ERROR is the *first* frame — no `TRANSFER_CREATED` precedes
/// it — and it is byte-identical regardless of *why* access was denied or
/// whether the target file exists.
async fn expect_denied(
    client_transport: &Arc<dyn Transport<Conn = QuicConnection>>,
    server_addr: SocketAddr,
    op: TransferOp,
    dst_path: &str,
) {
    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect (denied case)");
    let (send, recv) = conn
        .open_bi()
        .await
        .expect("control stream open (denied case)");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("HELLO/HELLO_ACK/AUTH_OK (denied case)");

    let create = TransferCreate {
        op,
        src_path: "".into(),
        dst_path: dst_path.into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    // The FIRST frame must be ERROR: the server authorizes before doing any
    // filesystem work, so an unauthorized request never yields TRANSFER_CREATED.
    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::ERROR,
        "op={op:?} path={dst_path:?}: expected ERROR (0x7F) as the first frame, got 0x{:02x}",
        frame.type_byte
    );
    let err = ErrorMsg::decode(&frame.payload).expect("decode ERROR frame");
    assert_eq!(
        err.code,
        ErrorCode::FileNotFound,
        "op={op:?} path={dst_path:?}: denial must collapse to the uniform FILE_NOT_FOUND \
         (PROTOCOL.md §10), got {:?}",
        err.code
    );
    assert_eq!(
        err.detail.as_str(),
        "not found",
        "op={op:?} path={dst_path:?}: denial detail must be the uniform \"not found\""
    );
    drop(conn);
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m4_cross_tenant_and_traversal_denied() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();

    // 1. Dev PKI: one CA, one server cert, and TWO client identities mapping
    //    to two tenants via their SAN URI `velcrux://identity/<name>`.
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let id_a = build_client_identity(&ca, "tenant-a-user");
    let id_b = build_client_identity(&ca, "tenant-b-user");

    // 2. Storage roots (under the OS temp dir; cleaned up at the end).
    let pid = std::process::id();
    let test_root = std::env::temp_dir().join(format!("velcrux-m4-{pid}"));
    let root = test_root.join("root");
    let staging = test_root.join("staging");
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::create_dir_all(&staging).await.unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(root.clone(), staging.clone())
            .await
            .expect("backend"),
    );

    // 3. Server transport (mandatory client certs via the CA roots).
    let server_caps = {
        let mut c = Capabilities::EMPTY;
        c.set(Capability::FixedChunking);
        c.set(Capability::CdcChunking);
        c.set(Capability::Blake3);
        c
    };
    let server_addr: SocketAddr = "127.0.0.1:17652".parse().unwrap();
    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("client CA roots")
        .with_tunables(TransportConfigTunables {
            receive_window: 4 * 1024 * 1024,
            stream_receive_window: 4 * 1024 * 1024,
            max_concurrent_streams: 4,
            idle_timeout: Duration::from_secs(10),
            keepalive: Duration::from_secs(2),
            initial_rtt: Duration::from_millis(50),
        })
        .build(server_addr)
        .expect("server build");

    // 4. Deterministic test payload (seeded into tenant B's namespace below).
    let source_data = pseudo_random(0x0BAD_F00D_D15E_A5ED, TEST_FILE_LEN);
    let source_hash = blake3_of(&source_data);
    let source_path = test_root.join("source.bin");
    tokio::fs::write(&source_path, &source_data).await.unwrap();
    let file_size = source_data.len() as u64;

    // 5. Authorization: strict tenant isolation. Each identity may only touch
    //    its own tenant prefix; neither has any grant into the other's, and
    //    neither has a grant on the storage root. Everything else is denied
    //    by default (`SECURITY.md` §4).
    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![
        Grant {
            identity: "tenant-a-user".to_string(),
            path_prefix: "data/tenantA".to_string(),
            permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
        },
        Grant {
            identity: "tenant-b-user".to_string(),
            path_prefix: "data/tenantB".to_string(),
            permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
        },
    ]));

    // 6. Server accept loop: exactly N_CONNECTIONS, one per client scenario.
    //    `Capabilities` is `Copy`, so `server_caps` is reused per iteration.
    const N_CONNECTIONS: usize = 5;
    let stats = Arc::new(ServerStats::default());
    let server_task: tokio::task::JoinHandle<()> = {
        let backend = Arc::clone(&backend);
        let stats = Arc::clone(&stats);
        let authz = Arc::clone(&authz);
        tokio::spawn(async move {
            for n in 0..N_CONNECTIONS {
                let conn = server_transport.accept().await.expect("server accept");
                tracing::info!(n, "server: accepted connection");
                let b = Arc::clone(&backend);
                let s = Arc::clone(&stats);
                let az = Arc::clone(&authz);
                tokio::spawn(async move {
                    // authenticator = None → defaults to MtlsAuthenticator; the
                    // TLS handshake already validated the chain and the transport
                    // extracted the identity from it.
                    let actor =
                        ServerConn::with_state(server_caps, "velcruxd", s, b, None, None, Some(az));
                    let r = actor.run(&conn).await;
                    tracing::info!(n, ?r, "server: actor finished");
                    let _ = r;
                });
            }
        })
    };

    // 7. One client transport per identity.
    let client_a: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client A roots")
            .with_client_identity(id_a)
            .build()
            .expect("client A build"),
    );
    let client_b: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client B roots")
            .with_client_identity(id_b)
            .build()
            .expect("client B build"),
    );

    // --- Scenario 1 (conn 1): tenant B uploads into its OWN namespace.
    //     Positive control, and seeds a real file for the cross-tenant read. ---
    upload_ok(
        &client_b,
        server_addr,
        &source_path,
        file_size,
        source_hash,
        "data/tenantB/secret.bin",
    )
    .await;

    // --- Scenario 2 (conn 2): tenant A tries to DOWNLOAD tenant B's file,
    //     which now physically EXISTS. The authorizer denies before any
    //     filesystem access, so tenant A gets the same "not found" as for a
    //     path that does not exist. Cross-tenant read denied; existence of
    //     another tenant's data does not leak (`PROTOCOL.md` §10). ---
    expect_denied(
        &client_a,
        server_addr,
        TransferOp::Download,
        "data/tenantB/secret.bin",
    )
    .await;

    // --- Scenario 3 (conn 3): tenant A uploads into its OWN namespace.
    //     Positive control: authorization must not over-block. ---
    upload_ok(
        &client_a,
        server_addr,
        &source_path,
        file_size,
        source_hash,
        "data/tenantA/ok.bin",
    )
    .await;

    // --- Scenario 4 (conn 4): tenant A tries to WRITE into tenant B's
    //     namespace. Cross-tenant write denied. ---
    expect_denied(
        &client_a,
        server_addr,
        TransferOp::Upload,
        "data/tenantB/evil.bin",
    )
    .await;

    // --- Scenario 5 (conn 5): path traversal escape. Rejected at VPath
    //     validation (run before grant lookup) and collapsed to the same
    //     uniform "not found". ---
    expect_denied(
        &client_a,
        server_addr,
        TransferOp::Upload,
        "../../../../etc/passwd",
    )
    .await;

    // 8. Post-conditions on the real filesystem.
    //    (a) tenant A's authorized upload landed at the expected size.
    let ok_vpath = VPath::validate("data/tenantA/ok.bin").unwrap();
    let m = backend
        .stat(&ok_vpath)
        .await
        .unwrap()
        .expect("tenant A's authorized upload must exist");
    assert_eq!(m.size, file_size, "tenant A upload size");

    //    (b) tenant B's own upload exists.
    let secret_vpath = VPath::validate("data/tenantB/secret.bin").unwrap();
    assert!(
        backend.stat(&secret_vpath).await.unwrap().is_some(),
        "tenant B's own upload must exist"
    );

    //    (c) the DENIED cross-tenant write created NOTHING — the server
    //        returns before touching storage, so no destination file (empty,
    //        partial, or otherwise) may appear.
    let evil_vpath = VPath::validate("data/tenantB/evil.bin").unwrap();
    assert!(
        backend.stat(&evil_vpath).await.unwrap().is_none(),
        "denied cross-tenant write must not create a destination file"
    );

    //    (d) no `.velcrux-partial` staging file leaked from any transfer.
    let staging_dir = backend.staging_dir().to_path_buf();
    let mut entries = tokio::fs::read_dir(&staging_dir).await.unwrap();
    while let Some(e) = entries.next_entry().await.unwrap() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.contains("velcrux-partial"),
            "no `.velcrux-partial` should remain after commit/denial: {name}"
        );
    }

    // 9. The accept loop should have consumed exactly N_CONNECTIONS and
    //    returned.
    let _ = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server did not finish in time");

    // 10. Cleanup.
    let _ = tokio::fs::remove_dir_all(&test_root).await;
}
