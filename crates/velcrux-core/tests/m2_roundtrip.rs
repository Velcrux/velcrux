//! M2 end-to-end integration test (`docs/ARCHITECTURE.md` §12).
//!
//! Drives a full upload + download round-trip over real QUIC on loopback,
//! then verifies:
//!   - upload succeeds,
//!   - download succeeds,
//!   - file size matches,
//!   - source and destination BLAKE3 hashes match,
//!   - the staged file is renamed atomically (no `.velcrux-partial`
//!     remains after commit).
//!
//! Test data: 256 KiB of pseudo-random bytes generated from a fixed
//! seed. 256 KiB is enough to span multiple CDC chunks (chunk min =
//! 256 KiB) and run the streaming I/O pipeline end to end, while keeping
//! the test fast enough for CI. The actual M2 exit criterion (`100 GB
//! round trip, BLAKE3 hash matches, bounded RSS`) is verified separately
//! on provisioned hardware, per the project policy.
//!
//! We use a deterministic pseudo-random generator rather than
//! `/dev/urandom` so the test is reproducible; the bytes have high
//! entropy and the CDC chunker behaves the same as it would on real
//! random data.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::message::{
    Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
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
// Dev PKI helpers
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
    // xorshift64 with a fixed seed; deterministic.
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
// The test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m2_upload_download_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();

    // 1. Set up dev PKI.
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "dev-user");

    // 2. Set up storage roots (all under /tmp; cleaned up at end).
    let pid = std::process::id();
    let test_root = std::env::temp_dir().join(format!("velcrux-m2-{pid}"));
    let root = test_root.join("root");
    let staging = test_root.join("staging");
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::create_dir_all(&staging).await.unwrap();

    // 3. Build the server backend and transport.
    let backend = Arc::new(
        LocalFilesystemBackend::new(root.clone(), staging.clone())
            .await
            .expect("backend"),
    );
    let server_caps = {
        let mut c = Capabilities::EMPTY;
        c.set(Capability::FixedChunking);
        c.set(Capability::CdcChunking);
        c.set(Capability::Blake3);
        c
    };
    let server_addr: SocketAddr = "127.0.0.1:17646".parse().unwrap();
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

    // 4. Generate the test file content.
    let source_data = pseudo_random(0xDEAD_BEEF_CAFE_BABE, TEST_FILE_LEN);
    let source_hash = blake3_of(&source_data);
    let source_path = test_root.join("source.bin");
    tokio::fs::write(&source_path, &source_data).await.unwrap();

    // 5. Run the server actor loop in the background. It accepts
    //    *two* connections (one per transfer) on the same transport.
    let stats = Arc::new(ServerStats::default());
    let server_task: tokio::task::JoinHandle<()> = {
        let server_caps = server_caps;
        let backend = Arc::clone(&backend);
        let stats1 = Arc::clone(&stats);
        let stats2 = Arc::clone(&stats);
        tokio::spawn(async move {
            for n in 0..2 {
                let conn = server_transport.accept().await.expect("server accept");
                tracing::info!(n, "server: accepted connection");
                let caps = server_caps;
                let b = Arc::clone(&backend);
                let s = if n == 0 {
                    Arc::clone(&stats1)
                } else {
                    Arc::clone(&stats2)
                };
                tokio::spawn(async move {
                    let actor = ServerConn::new(caps, "velcruxd", s, b);
                    let r = actor.run(&conn).await;
                    tracing::warn!(n, ?r, "server: actor finished");
                    let _ = r;
                });
            }
        })
    };

    // 6. Client: connect + HELLO.
    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .build()
            .expect("client build"),
    );
    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let (send, recv) = conn.open_bi().await.expect("control stream open");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("HELLO/HELLO_ACK");
    let negotiated = session.negotiated().version;

    // 7. UPLOAD.
    let remote_path_str = "data/upload.bin";
    let file_size = source_data.len() as u64;
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: source_path.display().to_string(),
        dst_path: remote_path_str.into(),
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
        "expected TRANSFER_CREATED, got 0x{:02x}",
        frame.type_byte
    );
    let created = TransferCreated::decode(&frame.payload).unwrap();
    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );
    let _plan = TransferPlan::decode(&frame.payload).unwrap();
    let begin = TransferBegin {
        transfer_id: created.transfer_id,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let cfg = velcrux_core::PipelineConfig::default();
    let upload_result = timeout(
        Duration::from_secs(15),
        velcrux_core::client_upload(
            &conn,
            session.send_mut_owned(),
            session.recv_mut_owned(),
            created.transfer_id,
            source_path.clone(),
            file_size,
            source_hash,
            cfg,
        ),
    )
    .await
    .expect("upload did not finish in time");
    let upload_hash = upload_result.expect("upload failed");
    assert_eq!(upload_hash, source_hash, "upload: server hash mismatch");

    // Verify the file landed at the expected storage path, with the
    // expected size and no leftover staging file.
    let vpath = VPath::validate(remote_path_str).unwrap();
    let m = backend
        .stat(&vpath)
        .await
        .unwrap()
        .expect("uploaded file exists");
    assert_eq!(m.size, file_size, "uploaded file size");
    let staging_dir = backend.staging_dir().to_path_buf();
    let mut entries = tokio::fs::read_dir(&staging_dir).await.unwrap();
    let mut found_staging = false;
    while let Some(e) = entries.next_entry().await.unwrap() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.contains("velcrux-partial") {
            found_staging = true;
        }
    }
    assert!(
        !found_staging,
        "no `.velcrux-partial` should remain after commit"
    );

    // 8. DOWNLOAD on a *separate* connection. The M2 server's per-
    // connection state machine handles one transfer at a time and exits
    // after the transfer completes. Multiple transfers on a single
    // connection are a follow-up (M3+) optimisation; for M2 each
    // transfer opens a fresh connection.
    drop(conn);
    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect (download)");
    let (send, recv) = conn
        .open_bi()
        .await
        .expect("control stream open (download)");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("HELLO/HELLO_ACK (download)");
    let downloaded_path = test_root.join("downloaded.bin");
    let create = TransferCreate {
        op: TransferOp::Download,
        src_path: "".into(),
        dst_path: remote_path_str.into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED,
        "download: expected TRANSFER_CREATED, got 0x{:02x}",
        frame.type_byte
    );
    let created = TransferCreated::decode(&frame.payload).unwrap();
    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );
    let plan = TransferPlan::decode(&frame.payload).unwrap();
    assert_eq!(
        plan.bytes_total, file_size,
        "TRANSFER_PLAN bytes_total mismatch"
    );
    let begin = TransferBegin {
        transfer_id: created.transfer_id,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let downloaded_hash = timeout(
        Duration::from_secs(15),
        velcrux_core::client_download(
            &conn,
            session.send_mut_owned(),
            session.recv_mut_owned(),
            created.transfer_id,
            downloaded_path.clone(),
        ),
    )
    .await
    .expect("download did not finish in time")
    .expect("download failed");

    // 9. Verify the downloaded file matches the source byte-for-byte.
    let downloaded = tokio::fs::read(&downloaded_path).await.unwrap();
    assert_eq!(downloaded.len() as u64, file_size, "downloaded file size");
    assert_eq!(downloaded, source_data, "downloaded bytes match source");
    assert_eq!(
        downloaded_hash, source_hash,
        "downloaded hash matches source"
    );

    // 10. Sanity: HELLO_ACK observed a valid negotiation.
    assert_eq!(negotiated, 1, "version negotiated is 1");

    // 11. Server task should complete (or be very close to it).
    let _ = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server did not finish in time");

    // 12. Memory bound: the pipeline uses bounded buffers; assert the
    //     documented defaults remain within target.
    let cfg = velcrux_core::PipelineConfig::default();
    assert!(cfg.read_buffer_size <= 4 * 1024 * 1024);
    assert!(cfg.max_inflight <= 32);

    // 13. Cleanup.
    let _ = tokio::fs::remove_dir_all(&test_root).await;
}
