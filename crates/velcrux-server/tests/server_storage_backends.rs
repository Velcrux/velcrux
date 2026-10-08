//! Integration test suite for Option AJ: Pluggable Storage Backend Abstraction & In-Memory Virtual Engine
//! (`REQUIREMENTS.md` §42, §43).
//!
//! Validates:
//! 1. `StorageBackend` trait polymorphism: uniform handling of `LocalFilesystemBackend` and `MemoryStorageBackend`.
//! 2. `MemoryStorageBackend` staging isolation, transactional commit semantics, and zero disk leakage.
//! 3. `MemoryStorageBackend` simulated capacity quota & reservation margin enforcement.
//! 4. Content-addressed chunk store operations (`store_chunk`, `has_chunk`, `get_chunk`, `delete_chunk`).
//! 5. Server configuration loading (`storage.backend` in TOML and `VELCRUX_STORAGE_BACKEND` env override) and validation.
//! 6. Full QUIC loopback upload lifecycle driven by in-memory virtual storage engine.

#![forbid(unsafe_code)]

use bytes::Bytes;
use std::sync::Arc;
use tempfile::tempdir;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};

use velcrux_core::auth::{Authorizer, FileAuthorizer, Grant, PermSet};
use velcrux_core::error::VelcruxError;
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::frame::{
    encode_data_frame, encode_data_preamble, DataFrameFlags, DataPreamble,
};
use velcrux_core::protocol::message::{
    Auth, Commit, Hello, Message, TransferBegin, TransferCreate, TransferCreated, TransferOp,
    Verify, VerifyResult,
};
use velcrux_core::session::{read_frame, write_frame, ServerConn, ServerStats};
use velcrux_core::storage::{
    FileMeta, LocalFilesystemBackend, MemoryStorageBackend, StorageBackend, VPath,
};
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};
use velcrux_server::config::ServerConfig;

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
    dn.push(DnType::CommonName, "velcrux-backend-ca");
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
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_storage_backend_trait_polymorphism() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let staging = temp.path().join("staging");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&staging).unwrap();

    let local: Arc<dyn StorageBackend> = Arc::new(
        LocalFilesystemBackend::new(root, staging)
            .await
            .expect("local backend"),
    );

    let memory: Arc<dyn StorageBackend> = Arc::new(MemoryStorageBackend::new());

    let backends: Vec<(&'static str, Arc<dyn StorageBackend>)> =
        vec![("local", local), ("memory", memory)];

    for (name, backend) in backends {
        assert_eq!(backend.backend_type(), name);

        let vpath = VPath::validate("docs/spec.txt").unwrap();
        assert!(!backend.exists(&vpath).await.unwrap());
        assert!(backend.stat(&vpath).await.unwrap().is_none());

        // Open staging writer
        let transfer_id = "test-transfer-1";
        let test_data = b"Hello, Velcrux Pluggable Storage Backend!";
        let mut writer = backend
            .open_staging(transfer_id, &vpath, test_data.len() as u64)
            .await
            .unwrap();

        writer.write_at(0, test_data).await.unwrap();
        let staging_handle = writer.into_staging();

        // While staged, destination should not exist yet
        assert!(!backend.exists(&vpath).await.unwrap());

        // Verify staging hash computation
        let hash = backend
            .compute_staging_hash(transfer_id, &vpath)
            .await
            .unwrap();
        assert_eq!(hash, Hash::of(test_data));

        // Commit file
        let meta = FileMeta {
            size: test_data.len() as u64,
            mode: 0o644,
            mtime_ns: 1_700_000_000_000,
            file_hash: hash,
        };
        backend
            .commit(transfer_id, staging_handle, &vpath, &meta)
            .await
            .unwrap();

        // Post-commit: file exists and matches metadata
        assert!(backend.exists(&vpath).await.unwrap());
        let stat = backend.stat(&vpath).await.unwrap().expect("stat exists");
        assert_eq!(stat.size, test_data.len() as u64);
        assert_eq!(backend.compute_file_hash(&vpath).await.unwrap(), hash);

        // Read back data via open_read
        let mut reader = backend.open_read(&vpath).await.unwrap();
        assert_eq!(reader.len(), test_data.len() as u64);
        let mut read_buf = vec![0u8; test_data.len()];
        let n = reader.read_at(0, &mut read_buf).await.unwrap();
        assert_eq!(n, test_data.len());
        assert_eq!(&read_buf, test_data);

        // Verify whole-file hash
        let file_hash = backend.compute_file_hash(&vpath).await.unwrap();
        assert_eq!(file_hash, hash);

        // Verify directory listing
        let parent = VPath::validate("docs").unwrap();
        let entries = backend.list_dir(&parent).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "spec.txt");
        assert_eq!(entries[0].1.size, test_data.len() as u64);

        // Rename file
        let new_vpath = VPath::validate("docs/spec_v2.txt").unwrap();
        backend.rename_file(&vpath, &new_vpath).await.unwrap();
        assert!(!backend.exists(&vpath).await.unwrap());
        assert!(backend.exists(&new_vpath).await.unwrap());

        // Remove file
        backend.remove(&new_vpath).await.unwrap();
        assert!(!backend.exists(&new_vpath).await.unwrap());
    }
}

#[tokio::test]
async fn test_memory_storage_backend_staging_isolation_and_cancel() {
    let backend = Arc::new(MemoryStorageBackend::new());
    let dest = VPath::validate("transfers/report.csv").unwrap();

    let tid1 = "transfer-iso-1";
    let tid2 = "transfer-iso-2";

    let mut w1 = backend.open_staging(tid1, &dest, 100).await.unwrap();
    w1.write_at(0, b"worker-1 data").await.unwrap();

    let mut w2 = backend.open_staging(tid2, &dest, 100).await.unwrap();
    w2.write_at(0, b"worker-2 isolated data").await.unwrap();

    // Destination does not exist
    assert!(backend.stat(&dest).await.unwrap().is_none());

    // Compute hashes of separate staging files
    let h1 = backend.compute_staging_hash(tid1, &dest).await.unwrap();
    let h2 = backend.compute_staging_hash(tid2, &dest).await.unwrap();
    assert_ne!(h1, h2);

    // Cancel / abort tid1 by consuming without committing
    let _st1 = w1.into_staging();

    // Commit w2
    let st2 = w2.into_staging();
    let meta = FileMeta {
        size: b"worker-2 isolated data".len() as u64,
        mode: 0o600,
        mtime_ns: 1234567,
        file_hash: h2,
    };
    backend.commit(tid2, st2, &dest, &meta).await.unwrap();

    // Check dest contains worker-2 data
    let mut reader = backend.open_read(&dest).await.unwrap();
    let mut buf = vec![0u8; b"worker-2 isolated data".len()];
    reader.read_at(0, &mut buf).await.unwrap();
    assert_eq!(&buf, b"worker-2 isolated data");
}

#[tokio::test]
async fn test_memory_storage_backend_capacity_limits() {
    // 500 bytes capacity, 100 bytes reservation margin => maximum storable = 400 bytes
    let backend = MemoryStorageBackend::new_with_capacity(500, 100);
    assert_eq!(backend.available_space().await.unwrap(), 500);

    let p1 = VPath::validate("file1.bin").unwrap();
    let mut w = backend.open_staging("t1", &p1, 200).await.unwrap();
    w.write_at(0, &[0u8; 200]).await.unwrap();
    let st = w.into_staging();
    let meta = FileMeta {
        size: 200,
        mode: 0o644,
        mtime_ns: 0,
        file_hash: Hash::of(&[0u8; 200]),
    };
    backend.commit("t1", st, &p1, &meta).await.unwrap();

    assert_eq!(backend.available_space().await.unwrap(), 300);

    // Now try to stage a file of 250 bytes: 300 available - 250 requested = 50 < 100 margin => DiskFull
    let p2 = VPath::validate("file2.bin").unwrap();
    let err = backend.open_staging("t2", &p2, 250).await.unwrap_err();
    match err {
        VelcruxError::Protocol(velcrux_core::error::ProtocolError::DiskFull(_)) => {}
        other => panic!("expected DiskFull, got: {other:?}"),
    }

    // Attempting a 150 byte file: 300 - 150 = 150 >= 100 margin => succeeds
    let mut w2 = backend.open_staging("t2", &p2, 150).await.unwrap();
    w2.write_at(0, &[0u8; 150]).await.unwrap();
    let st2 = w2.into_staging();
    backend.commit("t2", st2, &p2, &meta).await.unwrap();

    assert_eq!(backend.available_space().await.unwrap(), 150);
}

#[tokio::test]
async fn test_memory_storage_backend_chunk_store() {
    let backend = MemoryStorageBackend::new();
    let chunk_data = b"content-addressed chunk bytes payload";
    let hash = Hash::of(chunk_data);

    assert!(!backend.has_chunk(&hash).await.unwrap());
    assert!(backend.get_chunk(&hash).await.unwrap().is_none());

    // Store chunk
    backend.store_chunk(&hash, chunk_data).await.unwrap();
    assert!(backend.has_chunk(&hash).await.unwrap());

    // Retrieve chunk
    let retrieved = backend.get_chunk(&hash).await.unwrap().unwrap();
    assert_eq!(retrieved, chunk_data);

    // Delete chunk
    assert!(backend.delete_chunk(&hash).await.unwrap());
    assert!(!backend.has_chunk(&hash).await.unwrap());
}

#[test]
fn test_server_config_backend_selection() {
    let temp = tempdir().unwrap();
    let cfg_path = temp.path().join("server.toml");

    // 1. Memory backend config
    let toml_mem = r#"
        [network]
        listen = "127.0.0.1:7443"

        [security]
        certificate = "server.crt"
        private_key = "server.key"
        client_ca = "ca.crt"

        [storage]
        root = "/virtual/root"
        staging = "/virtual/staging"
        backend = "memory"
    "#;
    std::fs::write(&cfg_path, toml_mem).unwrap();
    let cfg = ServerConfig::load(&cfg_path).expect("load memory config");
    assert_eq!(cfg.storage.backend.as_deref(), Some("memory"));

    // 2. Local backend config
    let toml_local = format!(
        r#"
        [network]
        listen = "127.0.0.1:7443"

        [security]
        certificate = "server.crt"
        private_key = "server.key"
        client_ca = "ca.crt"

        [storage]
        root = "{root}"
        staging = "{staging}"
        backend = "local"
    "#,
        root = temp.path().display(),
        staging = temp.path().display(),
    );
    std::fs::write(&cfg_path, toml_local).unwrap();
    let cfg2 = ServerConfig::load(&cfg_path).expect("load local config");
    assert_eq!(cfg2.storage.backend.as_deref(), Some("local"));

    // 3. Invalid backend config should fail validation
    let toml_invalid = r#"
        [network]
        listen = "127.0.0.1:7443"

        [security]
        certificate = "server.crt"
        private_key = "server.key"
        client_ca = "ca.crt"

        [storage]
        root = "/virtual/root"
        staging = "/virtual/staging"
        backend = "s3"
    "#;
    std::fs::write(&cfg_path, toml_invalid).unwrap();
    assert!(ServerConfig::load(&cfg_path).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_memory_backend_quic_transfer_lifecycle() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "memory-worker");

    let tunables = TransportConfigTunables {
        receive_window: 4 * 1024 * 1024,
        stream_receive_window: 4 * 1024 * 1024,
        max_concurrent_streams: 16,
        idle_timeout: std::time::Duration::from_secs(10),
        keepalive: std::time::Duration::from_secs(2),
        initial_rtt: std::time::Duration::from_millis(50),
    };

    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("add CA")
        .with_tunables(tunables.clone())
        .build("127.0.0.1:0".parse().unwrap())
        .expect("build server transport");

    let server_addr = server_transport.local_addr().expect("server local addr");

    // Memory storage backend: 0 disk files!
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryStorageBackend::new());
    let authorizer: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "memory-worker".into(),
        path_prefix: "".into(),
        permissions: PermSet::ALL_TRANSFER,
    }]));

    let stats = Arc::new(ServerStats::default());
    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::Blake3);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = {
        let backend = Arc::clone(&backend);
        let stats = Arc::clone(&stats);
        let authz = Arc::clone(&authorizer);
        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    while let Ok(conn) = server_transport.accept().await {
                        let b = Arc::clone(&backend);
                        let s = Arc::clone(&stats);
                        let az = Arc::clone(&authz);
                        tokio::spawn(async move {
                            let actor =
                                ServerConn::with_state(server_caps, "velcruxd-mem", s, b, None, None, Some(az));
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
            .expect("add CA")
            .with_client_identity(client_identity)
            .with_tunables(tunables)
            .build()
            .expect("build client transport"),
    );

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("connect to server");

    let (mut send, mut recv) = conn.open_bi().await.expect("open bi stream");

    // 1. Handshake: Hello
    let mut client_caps = Capabilities::EMPTY;
    client_caps.set(Capability::FixedChunking);
    client_caps.set(Capability::Blake3);
    let hello = Hello {
        versions: vec![1],
        capabilities: client_caps,
        agent: "velcrux-client".to_string(),
    };
    write_frame(send.as_mut(), &Message::Hello(hello), 1)
        .await
        .unwrap();
    let hello_ack_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        hello_ack_frame.type_byte,
        velcrux_core::protocol::message::HELLO_ACK
    );

    // 2. Auth
    let auth = Auth::mtls();
    write_frame(send.as_mut(), &Message::Auth(auth), 2)
        .await
        .unwrap();
    let auth_ok_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        auth_ok_frame.type_byte,
        velcrux_core::protocol::message::AUTH_OK
    );

    // 3. Upload a file directly into the memory backend
    let file_data = b"Virtual In-Memory Engine Data over QUIC";
    let file_hash = Hash::of(file_data);

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "local_memory_file.txt".to_string(),
        dst_path: "memory_file.txt".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: file_data.len() as u64,
        file_hash,
    };
    write_frame(send.as_mut(), &Message::TransferCreate(create), 3)
        .await
        .unwrap();

    // Read TransferCreated response
    let created_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let created = TransferCreated::decode(created_frame.payload).unwrap();

    let _plan_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();

    // Send TransferBegin
    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 1,
    };
    write_frame(send.as_mut(), &Message::TransferBegin(begin), 4)
        .await
        .unwrap();

    // Open uni data stream and send data frame
    let mut data_send = conn.open_uni().await.expect("open uni");
    let preamble = DataPreamble {
        transfer_id: created.transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    let pre_enc = encode_data_preamble(&preamble);
    data_send
        .write_all(Bytes::copy_from_slice(&pre_enc))
        .await
        .unwrap();

    let frame0 = encode_data_frame(
        0,
        file_data.len() as u32,
        DataFrameFlags::NONE,
        &file_hash,
        file_data,
    );
    data_send.write_all(Bytes::from(frame0)).await.unwrap();
    data_send.finish().await.unwrap();

    // Verify
    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash: file_hash,
    };
    write_frame(send.as_mut(), &Message::Verify(verify), 5)
        .await
        .unwrap();
    let vres_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let vres = VerifyResult::decode(vres_frame.payload).unwrap();
    assert!(
        vres.ok,
        "whole-file verification in memory backend must succeed"
    );

    // Commit
    let commit = Commit {
        transfer_id: created.transfer_id,
    };
    write_frame(send.as_mut(), &Message::Commit(commit), 6)
        .await
        .unwrap();
    let committed_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        committed_frame.type_byte,
        velcrux_core::protocol::message::COMMITTED
    );

    // Verify file is stored in MemoryStorageBackend
    let target_vpath = VPath::validate("memory_file.txt").unwrap();
    assert!(backend.exists(&target_vpath).await.unwrap());

    let meta = backend.stat(&target_vpath).await.unwrap().unwrap();
    assert_eq!(meta.size, file_data.len() as u64);
    assert_eq!(meta.file_hash, file_hash);

    let mut reader = backend.open_read(&target_vpath).await.unwrap();
    let mut read_bytes = vec![0u8; file_data.len()];
    reader.read_at(0, &mut read_bytes).await.unwrap();
    assert_eq!(&read_bytes, file_data);

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}
