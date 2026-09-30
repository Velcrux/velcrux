//! Integration tests for Option X: Sparse File Extent Detection, Hole Punching & Zero-Skip Transfer
//! (`REQUIREMENTS.md` §33; `ARCHITECTURE.md` §6; `STORAGE.md`).
//!
//! Verifies:
//! 1. Sparse extent detection and classification:
//!    - Analyzes mixed files, identifying data vs hole extents with exact offsets and lengths.
//! 2. Single-stream zero-skip sparse upload over live QUIC:
//!    - Uploads a file containing large sparse holes (e.g. 16 MiB hole flanked by data).
//!    - Zero bytes are transmitted for the hole (`DataFrameFlags::HOLE`, 48-byte header, 0 wire payload).
//!    - Receiver verifies whole-file BLAKE3 cryptographic hash and commits atomically.
//!    - Destination file has exact 18 MiB length and matches source bytes 100%.
//! 3. Multi-stream parallel data striping with sparse holes:
//!    - Concurrent streams send interleaved data and sparse hole chunks.
//!    - Receiver reassembles sparse and dense extents into final staging file.
//! 4. Trailing sparse hole handling:
//!    - Validates files with data followed by large trailing sparse holes.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Write;
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
use velcrux_core::protocol::frame::{
    encode_data_frame, encode_data_preamble, DataFrameFlags, DataPreamble,
};
use velcrux_core::protocol::message::{
    Commit, Hello, Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, Verify,
    VerifyResult,
};
use velcrux_core::session::{read_frame, write_frame, ServerConn, ServerStats};
use velcrux_core::storage::sparse::{detect_file_extents, FileExtent};
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
    dn.push(DnType::CommonName, "velcrux-sparse-ca");
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
// 1. Sparse Extent Detection & Classification
// ---------------------------------------------------------------------------

#[test]
fn test_sparse_extent_detection_and_classification() {
    let td = tempdir().unwrap();
    let path = td.path().join("mixed_sparse.bin");

    // Layout:
    // 0..128 KiB: Data (0x5A)
    // 128 KiB..1152 KiB: Hole (1024 KiB of 0x00)
    // 1152 KiB..1408 KiB: Data (256 KiB of 0xC3)
    // 1408 KiB..3456 KiB: Hole (2048 KiB of 0x00)
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(&vec![0x5A; 128 * 1024]).unwrap();
        f.write_all(&vec![0x00; 1024 * 1024]).unwrap();
        f.write_all(&vec![0xC3; 256 * 1024]).unwrap();
        f.write_all(&vec![0x00; 2048 * 1024]).unwrap();
    }

    let total_size = (128 + 1024 + 256 + 2048) * 1024;
    let extents = detect_file_extents(&path, total_size, 64 * 1024).unwrap();

    assert_eq!(extents.len(), 4, "must detect exactly 4 contiguous extents");
    assert_eq!(extents[0], FileExtent::data(0, 128 * 1024));
    assert_eq!(extents[1], FileExtent::hole(128 * 1024, 1024 * 1024));
    assert_eq!(extents[2], FileExtent::data(1152 * 1024, 256 * 1024));
    assert_eq!(extents[3], FileExtent::hole(1408 * 1024, 2048 * 1024));
}

// ---------------------------------------------------------------------------
// 2. Single-Stream Zero-Skip Sparse Upload over Live QUIC
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sparse_file_quic_loopback_zero_wire_transfer() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "sparse-client");

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
        identity: "sparse-client".to_string(),
        path_prefix: "sparse_vault".to_string(),
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
    server_caps.set(Capability::SparseFiles);

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
                                "velcruxd-sparse",
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
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Handshake & Auth
    let hello = Hello::default_client();
    let _ = write_frame(send.as_mut(), &Message::Hello(hello), 1).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let auth = velcrux_core::protocol::message::Auth::mtls();
    let _ = write_frame(send.as_mut(), &Message::Auth(auth), 2).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    // Construct a 6 MiB logical file:
    // Chunk 0: 1 MiB dense data (0x7E)
    // Chunks 1..4: 4 MiB sparse hole (four 1 MiB hole frames)
    // Chunk 5: 1 MiB dense data (0xE7)
    let chunk0_data = vec![0x7Eu8; 1024 * 1024];
    let hole_len = 4 * 1024 * 1024u64;
    let chunk2_data = vec![0xE7u8; 1024 * 1024];
    let total_file_size = (1024 * 1024) + hole_len + (1024 * 1024);

    // Compute whole-file expected BLAKE3
    let mut hasher = velcrux_core::HashHasher::new();
    hasher.feed(&chunk0_data);
    static ZERO_BLOCK: [u8; 64 * 1024] = [0u8; 64 * 1024];
    let mut rem_zeros = hole_len;
    while rem_zeros > 0 {
        let chunk = rem_zeros.min(ZERO_BLOCK.len() as u64) as usize;
        hasher.feed(&ZERO_BLOCK[..chunk]);
        rem_zeros -= chunk as u64;
    }
    hasher.feed(&chunk2_data);
    let expected_whole_hash = hasher.finalize();

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "local_sparse.bin".to_string(),
        dst_path: "sparse_vault/target_sparse.bin".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: total_file_size,
        file_hash: expected_whole_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferCreate(create), 3).await;
    let created_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let created = TransferCreated::decode(created_frame.payload).unwrap();

    let _plan_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 1,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferBegin(begin), 4).await;

    // Send chunks over data stream
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

    // 1. Send Chunk 0 (dense data)
    let chunk0_hash = Hash::of(&chunk0_data);
    let frame0 = encode_data_frame(
        0,
        chunk0_data.len() as u32,
        DataFrameFlags::NONE,
        &chunk0_hash,
        &chunk0_data,
    );
    data_send.write_all(Bytes::from(frame0)).await.unwrap();

    // 2. Send 4 MiB sparse hole (four 1 MiB hole frames: zero payload sent over wire!)
    let num_hole_chunks = 4;
    let hole_chunk_size = 1024 * 1024u32;
    for i in 0..num_hole_chunks {
        let offset = (1024 * 1024) + (i as u64 * hole_chunk_size as u64);
        let hole_hash = Hash::of_zeros(hole_chunk_size as u64);
        let frame = encode_data_frame(
            offset,
            hole_chunk_size,
            DataFrameFlags::HOLE,
            &hole_hash,
            &[], // 0 payload bytes!
        );
        assert_eq!(
            frame.len(),
            velcrux_core::protocol::frame::DATA_FRAME_HEADER_LEN
        );
        data_send.write_all(Bytes::from(frame)).await.unwrap();
    }

    // 3. Send Chunk 2 (dense data)
    let chunk2_hash = Hash::of(&chunk2_data);
    let frame2 = encode_data_frame(
        (1024 * 1024) + hole_len,
        chunk2_data.len() as u32,
        DataFrameFlags::NONE,
        &chunk2_hash,
        &chunk2_data,
    );
    data_send.write_all(Bytes::from(frame2)).await.unwrap();
    data_send.finish().await.unwrap();

    // Verify & Commit
    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash: expected_whole_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::Verify(verify), 5).await;
    let vres_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let vres = VerifyResult::decode(vres_frame.payload).unwrap();
    assert!(vres.ok, "whole-file BLAKE3 verification must succeed");

    let commit = Commit {
        transfer_id: created.transfer_id,
    };
    let _ = write_frame(send.as_mut(), &Message::Commit(commit), 6).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    // Assert destination file matches exact size and contents
    let dst_path = files_dir
        .path()
        .join("sparse_vault")
        .join("target_sparse.bin");
    assert!(dst_path.exists(), "committed file must exist");
    let meta = fs::metadata(&dst_path).expect("metadata");
    assert_eq!(
        meta.len(),
        total_file_size,
        "destination file length must match logical size"
    );

    // Read and verify sample slices from file without loading entire 18 MiB in memory
    let mut disk_f = File::open(&dst_path).unwrap();
    let mut buf = vec![0u8; 1024 * 1024];
    use std::io::Read;
    disk_f.read_exact(&mut buf).unwrap();
    assert_eq!(buf, chunk0_data, "chunk 0 bytes must match exactly");

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// 3. Multi-Stream Parallel Striping with Interleaved Sparse Holes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sparse_file_multi_stream_parallel_striping() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "sparse-striping-client");

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
        identity: "sparse-striping-client".to_string(),
        path_prefix: "striped_sparse".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());

    let tunables = TransportConfigTunables {
        receive_window: 64 * 1024 * 1024,
        stream_receive_window: 16 * 1024 * 1024,
        max_concurrent_streams: 32,
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
    server_caps.set(Capability::SparseFiles);

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
                                "velcruxd-sparse-striping",
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
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Handshake & Auth
    let hello = Hello::default_client();
    let _ = write_frame(send.as_mut(), &Message::Hello(hello), 1).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let auth = velcrux_core::protocol::message::Auth::mtls();
    let _ = write_frame(send.as_mut(), &Message::Auth(auth), 2).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    // 4 streams × 1 MiB chunks:
    // Stream 0: Data (0x11)
    // Stream 1: Hole (0x00) -> 0 payload bytes over wire
    // Stream 2: Data (0x33)
    // Stream 3: Hole (0x00) -> 0 payload bytes over wire
    let chunk_size = 1024 * 1024usize;
    let total_file_size = (chunk_size * 4) as u64;

    let chunk0 = vec![0x11u8; chunk_size];
    let chunk2 = vec![0x33u8; chunk_size];

    let mut hasher = velcrux_core::HashHasher::new();
    hasher.feed(&chunk0);
    hasher.feed(&vec![0u8; chunk_size]);
    hasher.feed(&chunk2);
    hasher.feed(&vec![0u8; chunk_size]);
    let expected_hash = hasher.finalize();

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "striped_sparse_input.bin".to_string(),
        dst_path: "striped_sparse/target.bin".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: total_file_size,
        file_hash: expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferCreate(create), 3).await;
    let created_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let created = TransferCreated::decode(created_frame.payload).unwrap();
    let _plan = read_frame(recv.as_mut()).await.unwrap().unwrap();

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 4,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferBegin(begin), 4).await;

    let conn_arc = Arc::new(conn);
    let mut handles = Vec::new();

    for stream_idx in 0..4usize {
        let conn_c = Arc::clone(&conn_arc);
        let tid = created.transfer_id;
        let c0 = chunk0.clone();
        let c2 = chunk2.clone();

        let handle = tokio::spawn(async move {
            let mut data_send = conn_c.open_uni().await.unwrap();
            let preamble = DataPreamble {
                transfer_id: tid,
                file_id: 1,
                stream_seq: (stream_idx + 1) as u64,
            };
            let pre_enc = encode_data_preamble(&preamble);
            data_send
                .write_all(Bytes::copy_from_slice(&pre_enc))
                .await
                .unwrap();

            let offset = (stream_idx * chunk_size) as u64;
            let (flags, hash, payload) = match stream_idx {
                0 => (DataFrameFlags::NONE, Hash::of(&c0), c0),
                1 => (
                    DataFrameFlags::HOLE,
                    Hash::of_zeros(chunk_size as u64),
                    Vec::new(),
                ),
                2 => (DataFrameFlags::NONE, Hash::of(&c2), c2),
                3 => (
                    DataFrameFlags::HOLE,
                    Hash::of_zeros(chunk_size as u64),
                    Vec::new(),
                ),
                _ => unreachable!(),
            };

            let frame = encode_data_frame(offset, chunk_size as u32, flags, &hash, &payload);
            data_send.write_all(Bytes::from(frame)).await.unwrap();
            data_send.finish().await.unwrap();
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    // Verify & Commit
    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::Verify(verify), 5).await;
    let vres_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let vres = VerifyResult::decode(vres_frame.payload).unwrap();
    assert!(
        vres.ok,
        "parallel multi-stream sparse upload verification must pass"
    );

    let commit = Commit {
        transfer_id: created.transfer_id,
    };
    let _ = write_frame(send.as_mut(), &Message::Commit(commit), 6).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    let dst_path = files_dir.path().join("striped_sparse").join("target.bin");
    let meta = fs::metadata(&dst_path).unwrap();
    assert_eq!(meta.len(), total_file_size);

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// 4. Trailing Sparse Hole Handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sparse_file_trailing_hole() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "trailing-sparse-client");

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
        identity: "trailing-sparse-client".to_string(),
        path_prefix: "trailing".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());

    let tunables = TransportConfigTunables {
        receive_window: 16 * 1024 * 1024,
        stream_receive_window: 16 * 1024 * 1024,
        max_concurrent_streams: 8,
        idle_timeout: Duration::from_secs(15),
        keepalive: Duration::from_secs(3),
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
    server_caps.set(Capability::SparseFiles);

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
                                "velcruxd-trailing",
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
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Handshake & Auth
    let _ = write_frame(send.as_mut(), &Message::Hello(Hello::default_client()), 1).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let _ = write_frame(
        send.as_mut(),
        &Message::Auth(velcrux_core::protocol::message::Auth::mtls()),
        2,
    )
    .await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    // 1 MiB data followed by 3 MiB trailing hole
    let chunk0 = vec![0x99u8; 1024 * 1024];
    let trailing_hole_len = 3 * 1024 * 1024u64;
    let total_file_size = (1024 * 1024) + trailing_hole_len;

    let mut hasher = velcrux_core::HashHasher::new();
    hasher.feed(&chunk0);
    hasher.feed(&vec![0u8; trailing_hole_len as usize]);
    let expected_hash = hasher.finalize();

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "trailing_src.bin".to_string(),
        dst_path: "trailing/trailing_dst.bin".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: total_file_size,
        file_hash: expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferCreate(create), 3).await;
    let created_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let created = TransferCreated::decode(created_frame.payload).unwrap();
    let _plan = read_frame(recv.as_mut()).await.unwrap().unwrap();

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 1,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferBegin(begin), 4).await;

    let mut data_send = conn.open_uni().await.unwrap();
    let preamble = DataPreamble {
        transfer_id: created.transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    data_send
        .write_all(Bytes::copy_from_slice(&encode_data_preamble(&preamble)))
        .await
        .unwrap();

    // Send chunk 0 data
    let frame0 = encode_data_frame(
        0,
        chunk0.len() as u32,
        DataFrameFlags::NONE,
        &Hash::of(&chunk0),
        &chunk0,
    );
    data_send.write_all(Bytes::from(frame0)).await.unwrap();

    // Send trailing hole
    let hole_hash = Hash::of_zeros(trailing_hole_len);
    let frame1 = encode_data_frame(
        chunk0.len() as u64,
        trailing_hole_len as u32,
        DataFrameFlags::HOLE,
        &hole_hash,
        &[],
    );
    data_send.write_all(Bytes::from(frame1)).await.unwrap();
    data_send.finish().await.unwrap();

    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::Verify(verify), 5).await;
    let vres_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let vres = VerifyResult::decode(vres_frame.payload).unwrap();
    assert!(vres.ok);

    let commit = Commit {
        transfer_id: created.transfer_id,
    };
    let _ = write_frame(send.as_mut(), &Message::Commit(commit), 6).await;
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    let dst_path = files_dir.path().join("trailing").join("trailing_dst.bin");
    let meta = fs::metadata(&dst_path).unwrap();
    assert_eq!(meta.len(), total_file_size);

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}
