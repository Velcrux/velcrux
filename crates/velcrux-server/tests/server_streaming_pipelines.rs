//! Integration tests for Option BG: Unix Stdin/Stdout Streaming Pipelines.
//!
//! Verifies:
//! 1. Streaming upload over live QUIC from an asynchronous reader (stdin pipe emulation).
//!    - Streams data chunks with running BLAKE3 computation.
//!    - Whole-stream BLAKE3 verification on EOF and atomic server commitment.
//! 2. Streaming download over live QUIC to an asynchronous writer (stdout pipe emulation).
//!    - Chunks are written directly to the stream on the fly.
//!    - Running BLAKE3 hash is accumulated and verified against server's VERIFY_RESULT.
//! 3. Pipe-to-pipe roundtrip fidelity:
//!    - Uploads arbitrary binary payload from a stream, downloads it back into a stream.
//!    - Verifies 100% byte-for-byte identity.

#![forbid(unsafe_code)]

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use tempfile::tempdir;

use velcrux_core::auth::{Authorizer, FileAuthorizer, Grant, PermSet};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::message::{
    Auth, Hello, Message, TransferBegin, TransferCreate, TransferOp,
};
use velcrux_core::session::{read_frame, write_frame, ServerConn, ServerStats};
use velcrux_core::storage::LocalFilesystemBackend;
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
    dn.push(DnType::CommonName, "velcrux-stream-ca");
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

#[tokio::test]
async fn test_streaming_pipeline_upload_and_download() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "stream-user");

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
        identity: "stream-user".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());

    let tunables = TransportConfigTunables {
        receive_window: 64 * 1024 * 1024,
        stream_receive_window: 16 * 1024 * 1024,
        max_concurrent_streams: 16,
        idle_timeout: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
        initial_rtt: Duration::from_millis(10),
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
                                "velcruxd-stream",
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

    // Client connection
    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client CA")
            .with_client_identity(client_identity)
            .with_tunables(tunables)
            .build()
            .expect("client transport"),
    );

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("connect");

    let (mut send, mut recv) = conn.open_bi().await.expect("open control stream");

    // HELLO handshake
    let hello = Hello::default_client();
    let _ = write_frame(send.as_mut(), &Message::Hello(hello), 1).await;
    let f = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(f.type_byte, velcrux_core::protocol::message::HELLO_ACK);

    // AUTH
    let auth = Auth::mtls();
    let _ = write_frame(send.as_mut(), &Message::Auth(auth), 2).await;
    let f = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(f.type_byte, velcrux_core::protocol::message::AUTH_OK);

    // -----------------------------------------------------------------------
    // Part 1: Stream Upload (stdin pipe simulation)
    // -----------------------------------------------------------------------
    let test_data = {
        let mut d = Vec::with_capacity(768 * 1024);
        for i in 0..768 * 1024 {
            d.push((i % 251) as u8);
        }
        d
    };
    let expected_hash = Hash::of(&test_data);
    let remote_target = "data/piped_archive.tar";

    let tid = TransferId::generate();
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "-".into(),
        dst_path: remote_target.to_string(),
        idempotency_key: tid.to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    write_frame(send.as_mut(), &Message::TransferCreate(create), 3)
        .await
        .unwrap();

    let f = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        f.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created = velcrux_core::protocol::message::TransferCreated::decode(&f.payload).unwrap();
    let f = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(f.type_byte, velcrux_core::protocol::message::TRANSFER_PLAN);

    let begin = TransferBegin::new(created.transfer_id);
    write_frame(send.as_mut(), &Message::TransferBegin(begin), 4)
        .await
        .unwrap();

    let reader = tokio::io::BufReader::new(std::io::Cursor::new(test_data.clone()));
    let (uploaded_hash, bytes_uploaded) = velcrux_core::client_upload_stdin_stream(
        &conn,
        send.as_mut(),
        recv.as_mut(),
        created.transfer_id,
        reader,
        64 * 1024,
        false,
        None,
        None,
    )
    .await
    .expect("streaming upload must succeed");

    assert_eq!(bytes_uploaded, (768 * 1024) as u64);
    assert_eq!(uploaded_hash, expected_hash);

    // Verify committed file on server filesystem
    let committed_file = files_dir.path().join("data/piped_archive.tar");
    assert!(
        committed_file.exists(),
        "committed file must exist on server"
    );
    let on_disk_bytes = fs::read(&committed_file).expect("read server file");
    assert_eq!(on_disk_bytes.len(), test_data.len());
    assert_eq!(Hash::of(&on_disk_bytes), expected_hash);

    // -----------------------------------------------------------------------
    // Part 2: Stream Download (stdout pipe simulation)
    // -----------------------------------------------------------------------
    let tid_down = TransferId::generate();
    let create_down = TransferCreate {
        op: TransferOp::Download,
        src_path: "".into(),
        dst_path: remote_target.to_string(),
        idempotency_key: tid_down.to_string(),
        file_size: 0,
        file_hash: Hash::ZERO,
    };
    write_frame(send.as_mut(), &Message::TransferCreate(create_down), 5)
        .await
        .unwrap();

    let f = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        f.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created_down =
        velcrux_core::protocol::message::TransferCreated::decode(&f.payload).unwrap();
    let f = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(f.type_byte, velcrux_core::protocol::message::TRANSFER_PLAN);

    let begin_down = TransferBegin::new(created_down.transfer_id);
    write_frame(send.as_mut(), &Message::TransferBegin(begin_down), 6)
        .await
        .unwrap();

    let mut downloaded_buffer = Vec::new();
    let (downloaded_hash, bytes_downloaded) = velcrux_core::client_download_stdout_stream(
        &conn,
        send.as_mut(),
        recv.as_mut(),
        created_down.transfer_id,
        &mut downloaded_buffer,
        None,
        None,
    )
    .await
    .expect("streaming download must succeed");

    assert_eq!(bytes_downloaded, (768 * 1024) as u64);
    assert_eq!(downloaded_hash, expected_hash);
    assert_eq!(downloaded_buffer, test_data);

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}
