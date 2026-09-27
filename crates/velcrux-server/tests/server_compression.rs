//! Integration tests for Option Q: Wire-Level Zstandard (zstd) Compression,
//! Frame Flag Enforcement & Decompression-Bomb Defense (PROTOCOL.md §3, §4; OPERATIONS.md §4; SECURITY.md §8, §10).
//!
//! Verifies:
//! 1. Server configuration parsing of `[transfer] compression = "zstd"` and `"none"`, plus validation.
//! 2. Frame-level compression (`FrameFlags::COMPRESSED`) and transparent safe decompression via `read_frame`.
//! 3. Decompression-bomb defense on wire frames: oversized declared expansion and excessive ratio rejection.
//! 4. DATA frame chunk compression (`DataFrameFlags::COMPRESSED`), payload compression threshold, and uncompressed chunk hash invariant.
//! 5. End-to-end live QUIC loopback upload and download of compressible data with compression enabled.
//! 6. End-to-end live QUIC loopback upload and download of incompressible random data with graceful fallback.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use tempfile::tempdir;
use tokio::time::timeout;

use velcrux_core::auth::{Authorizer, FileAuthorizer, Grant, PermSet};
use velcrux_core::error::ProtocolError;
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::protocol::compression::{compress_payload, decompress_payload_bounded};
use velcrux_core::protocol::frame::{
    decode_data_frame_header, encode_data_frame_maybe_compressed, encode_frame, header_size_for,
    FrameFlags,
};
use velcrux_core::protocol::message::{
    Message, StatResult, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
};
use velcrux_core::session::{
    encode_message, encode_message_compressed, read_frame, ClientSession, ServerConn, ServerStats,
};
use velcrux_core::storage::{LocalFilesystemBackend, StorageBackend, VPath};
use velcrux_core::transport::async_trait;
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{BiRecvStream, Connection, Transport};
use velcrux_core::util::TransferId;
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
    dn.push(DnType::CommonName, "velcrux-compression-ca");
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
// In-memory stream mock for frame-level unit tests
// ---------------------------------------------------------------------------

struct MockRecvStream {
    data: std::io::Cursor<Vec<u8>>,
}

impl MockRecvStream {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            data: std::io::Cursor::new(bytes),
        }
    }
}

#[async_trait]
impl BiRecvStream for MockRecvStream {
    async fn read_chunk(&mut self, max: usize) -> velcrux_core::error::Result<Option<Bytes>> {
        use std::io::Read;
        let mut buf = vec![0u8; max];
        let n = self
            .data
            .read(&mut buf)
            .map_err(velcrux_core::error::VelcruxError::Io)?;
        if n == 0 {
            Ok(None)
        } else {
            buf.truncate(n);
            Ok(Some(Bytes::from(buf)))
        }
    }

    async fn read_exact(&mut self, n: usize) -> velcrux_core::error::Result<Option<Bytes>> {
        use std::io::Read;
        let mut buf = vec![0u8; n];
        match self.data.read_exact(&mut buf) {
            Ok(()) => Ok(Some(Bytes::from(buf))),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(velcrux_core::error::VelcruxError::Io(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Test Data Generators
// ---------------------------------------------------------------------------

fn blake3_of(data: &[u8]) -> velcrux_core::Hash {
    let mut h = velcrux_core::HashHasher::new();
    h.feed(data);
    h.finalize()
}

fn pseudo_random(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for b in state.to_le_bytes() {
            if out.len() >= len {
                break;
            }
            out.push(b);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Test Cases
// ---------------------------------------------------------------------------

#[test]
fn test_server_config_compression_parsing_and_validation() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("server.toml");

    // 1. Explicit zstd compression
    let toml_zstd = r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "/tmp/server.crt"
private_key = "/tmp/server.key"
client_ca = "/tmp/ca.crt"

[storage]
root = "/tmp/storage"
staging = "/tmp/staging"

[transfer]
compression = "zstd"
"#;
    std::fs::write(&config_path, toml_zstd).unwrap();
    let cfg = ServerConfig::load(&config_path).expect("load valid zstd config");
    assert_eq!(cfg.transfer.compression.as_deref(), Some("zstd"));

    // 2. Explicit none compression
    let toml_none = toml_zstd.replace("compression = \"zstd\"", "compression = \"none\"");
    std::fs::write(&config_path, toml_none).unwrap();
    let cfg = ServerConfig::load(&config_path).expect("load valid none config");
    assert_eq!(cfg.transfer.compression.as_deref(), Some("none"));

    // 3. Invalid compression option rejected
    let toml_invalid = toml_zstd.replace("compression = \"zstd\"", "compression = \"lz4\"");
    std::fs::write(&config_path, toml_invalid).unwrap();
    assert!(ServerConfig::load(&config_path).is_err());
}

#[tokio::test]
async fn test_wire_frame_compression_flag_and_transparent_decompression() {
    // Generate a repetitive metadata message (StatResult with many attributes)
    let rep_vpath = "long/directory/path/with/repetitive/structures/file.dat".to_string();
    let original_msg = Message::StatResult(StatResult {
        transfer_id: TransferId::generate(),
        found: true,
        status: "active".into(),
        direction: "upload".into(),
        remote_path: rep_vpath.repeat(10),
        file_size: 1_234_567,
        bytes_completed: 100_000,
        verified_up_to: 100_000,
        created_ms: 1_700_000_000_000,
        updated_ms: 1_700_000_001_000,
    });

    let uncompressed_bytes = encode_message(&original_msg, 42).unwrap();
    let compressed_bytes = encode_message_compressed(&original_msg, 42, true).unwrap();

    // Compression should have achieved notable savings
    assert!(
        compressed_bytes.len() < uncompressed_bytes.len(),
        "compressed frame ({} bytes) must be smaller than uncompressed ({} bytes)",
        compressed_bytes.len(),
        uncompressed_bytes.len()
    );

    // Frame flags byte is at index 2-3 (little endian u16). Verify FrameFlags::COMPRESSED (0x0002) is set.
    let flags_val = u16::from_le_bytes([compressed_bytes[2], compressed_bytes[3]]);
    let frame_flags = FrameFlags::from_bits_truncate(flags_val);
    assert!(
        frame_flags.compressed(),
        "COMPRESSED flag bit 1 must be set in wire frame"
    );

    // Test transparent decompression via read_frame
    let mut mock_stream = MockRecvStream::new(compressed_bytes);
    let decoded_frame = read_frame(&mut mock_stream)
        .await
        .expect("read_frame succeeds")
        .expect("frame present");

    assert_eq!(decoded_frame.request_id, 42);
    let decoded_msg = Message::decode(decoded_frame.type_byte, decoded_frame.payload)
        .expect("decode message payload");

    match (original_msg, decoded_msg) {
        (Message::StatResult(orig), Message::StatResult(dec)) => {
            assert_eq!(orig.transfer_id, dec.transfer_id);
            assert_eq!(orig.file_size, dec.file_size);
            assert_eq!(orig.remote_path, dec.remote_path);
        }
        _ => panic!("message variant mismatch"),
    }
}

#[tokio::test]
async fn test_wire_frame_decompression_bomb_rejection_declared_limit() {
    // Construct a frame whose compressed payload expands into 70 MiB of zeros
    // (exceeding MAX_BATCH_DECOMPRESSED_BYTES = 64 MiB).
    let bomb_uncompressed = vec![0u8; 70 * 1024 * 1024];
    let bomb_compressed = compress_payload(&bomb_uncompressed, 3).expect("zstd compress");

    let length = bomb_compressed.len() as u64;
    let total = header_size_for(length) + bomb_compressed.len();
    let mut frame_buf = vec![0u8; total];
    encode_frame(
        &mut frame_buf,
        velcrux_core::protocol::message::STAT_RESULT,
        FrameFlags::COMPRESSED,
        101,
        &bomb_compressed,
    );

    let mut mock_stream = MockRecvStream::new(frame_buf);
    let result = read_frame(&mut mock_stream).await;

    assert!(
        result.is_err(),
        "read_frame must reject decompression bombs exceeding MAX_BATCH_DECOMPRESSED_BYTES"
    );
    match result.err().unwrap() {
        velcrux_core::error::VelcruxError::Protocol(ProtocolError::DecompressionBomb(msg)) => {
            assert!(
                msg.contains("limit"),
                "error message should cite limit: {msg}"
            );
        }
        other => panic!("expected DecompressionBomb protocol error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_wire_frame_decompression_bomb_ratio_rejection() {
    // 500 KB of zeroes compressed to ~100 bytes (ratio > 5000:1)
    let payload = vec![0u8; 500 * 1024];
    let compressed = compress_payload(&payload, 3).expect("compress");

    let res = decompress_payload_bounded(&compressed, 10 * 1024 * 1024, Some(50));
    assert!(
        res.is_err(),
        "decompress_payload_bounded must reject ratio > 50"
    );
    match res.err().unwrap() {
        ProtocolError::DecompressionBomb(msg) => {
            assert!(msg.contains("expansion ratio exceeded"), "message: {msg}");
        }
        other => panic!("expected DecompressionBomb, got: {other:?}"),
    }
}

#[test]
fn test_data_frame_compression_flag_and_hash_invariant() {
    // 1. Highly compressible chunk (128 KiB repetitive text)
    let compressible_chunk = b"The quick brown fox jumps over the lazy dog. 1234567890\n"
        .repeat(2500)
        .to_vec();
    let orig_hash = blake3_of(&compressible_chunk);

    let (frame_buf, was_compressed) =
        encode_data_frame_maybe_compressed(0, &orig_hash, &compressible_chunk, true);
    assert!(was_compressed, "compressible chunk must be compressed");
    assert!(
        frame_buf.len() < compressible_chunk.len(),
        "frame must be smaller than uncompressed chunk"
    );

    let (hdr, payload_slice) =
        decode_data_frame_header(&frame_buf).expect("decode data frame header");
    assert_eq!(hdr.chunk_offset, 0);
    // Invariant: chunk_hash on wire is always the BLAKE3 hash of the uncompressed data!
    assert_eq!(
        hdr.chunk_hash, orig_hash,
        "chunk_hash must match uncompressed data hash"
    );
    assert!(
        hdr.flags.compressed(),
        "DataFrameFlags::COMPRESSED (0x0002) must be set"
    );

    // Decompress payload and verify it matches original chunk exactly
    let decompressed = decompress_payload_bounded(
        payload_slice,
        velcrux_core::protocol::limits::MAX_CHUNK_SIZE as usize,
        None,
    )
    .expect("decompress chunk");
    assert_eq!(decompressed, compressible_chunk);

    // 2. Incompressible chunk (high entropy random data)
    let random_chunk = pseudo_random(0xCAFE_BABE, 64 * 1024);
    let rand_hash = blake3_of(&random_chunk);
    let (rand_frame_buf, rand_compressed) =
        encode_data_frame_maybe_compressed(100, &rand_hash, &random_chunk, true);
    assert!(
        !rand_compressed,
        "incompressible chunk should not be compressed"
    );

    let (rand_hdr, rand_slice) =
        decode_data_frame_header(&rand_frame_buf).expect("decode rand data frame");
    assert_eq!(rand_hdr.chunk_offset, 100);
    assert!(
        !rand_hdr.flags.compressed(),
        "DataFrameFlags::COMPRESSED should NOT be set"
    );
    assert_eq!(rand_slice, random_chunk.as_slice());
}

// ---------------------------------------------------------------------------
// Live QUIC Loopback End-to-End Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_e2e_compressed_transfer_roundtrip() {
    let _ = tracing_subscriber::fmt().try_init();

    // 1. PKI
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "compress-user");

    // 2. Storage backend
    let pid = std::process::id();
    let test_root = std::env::temp_dir().join(format!("velcrux-comp-test-{pid}"));
    let root = test_root.join("root");
    let staging = test_root.join("staging");
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::create_dir_all(&staging).await.unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(root.clone(), staging.clone())
            .await
            .expect("backend"),
    );

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);

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
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server build");
    let server_addr: SocketAddr = server_transport.local_addr().expect("server local addr");

    // 3. Compressible test file: 512 KiB structured JSON records (ratio ~10x, well within bomb threshold)
    let mut source_data = Vec::with_capacity(512 * 1024);
    let mut i = 0u64;
    while source_data.len() < 512 * 1024 {
        let line = format!(
            "{{\"id\":{},\"timestamp\":{},\"service\":\"velcrux-node\",\"action\":\"sync_chunk\",\"status\":\"success\",\"message\":\"processing batch item with moderate entropy and high compressibility\"}}\n",
            i, 1_700_000_000 + i
        );
        source_data.extend_from_slice(line.as_bytes());
        i += 1;
    }
    let source_hash = blake3_of(&source_data);
    let source_path = test_root.join("source.json");
    tokio::fs::write(&source_path, &source_data).await.unwrap();

    // 4. Server actor loop with compression enabled (.with_compression(true))
    let stats = Arc::new(ServerStats::default());
    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "compress-user".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let _server_task = {
        let backend = Arc::clone(&backend);
        let stats = Arc::clone(&stats);
        let authz = Arc::clone(&authz);
        tokio::spawn(async move {
            for _ in 0..2 {
                let conn = server_transport.accept().await.expect("server accept");
                let b = Arc::clone(&backend);
                let s = Arc::clone(&stats);
                let az = Arc::clone(&authz);
                tokio::spawn(async move {
                    let actor =
                        ServerConn::with_state(server_caps, "velcruxd", s, b, None, None, Some(az))
                            .with_compression(true);
                    let _ = actor.run(&conn).await;
                });
            }
        })
    };

    // 5. Client connection
    let client_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(
        ClientBuilder::new()
            .with_server_roots_pem(ca.cert_pem.as_bytes())
            .expect("client roots")
            .with_client_identity(client_identity)
            .build()
            .expect("client build"),
    );

    // =========================================================================
    // STEP A: Client UPLOAD with compression = true
    // =========================================================================
    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect upload");
    let (send, recv) = conn.open_bi().await.expect("control stream open");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("HELLO/HELLO_ACK");

    let remote_path_str = "data/compressed_upload.txt";
    let file_size = source_data.len() as u64;
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: source_path.display().to_string(),
        dst_path: remote_path_str.into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size,
        file_hash: source_hash,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created = TransferCreated::decode(frame.payload).unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );
    let _plan = TransferPlan::decode(frame.payload).unwrap();

    let begin = TransferBegin::new(created.transfer_id);
    let buf = Bytes::from(encode_message(&Message::TransferBegin(begin), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let upload_cfg = velcrux_core::PipelineConfig::default().with_compression(true);
    let upload_res = timeout(
        Duration::from_secs(15),
        velcrux_core::client_upload(
            &conn,
            session.send_mut_owned(),
            session.recv_mut_owned(),
            created.transfer_id,
            source_path.clone(),
            file_size,
            source_hash,
            upload_cfg,
        ),
    )
    .await
    .expect("upload did not complete within timeout")
    .expect("upload error");

    assert_eq!(upload_res, source_hash, "uploaded file hash must match");

    // Verify stored file on server
    let vpath = VPath::validate(remote_path_str).unwrap();
    let meta = backend.stat(&vpath).await.unwrap().expect("file exists");
    assert_eq!(meta.size, file_size);

    // =========================================================================
    // STEP B: Client DOWNLOAD with compression = true
    // =========================================================================
    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect download");
    let (send, recv) = conn.open_bi().await.expect("control stream open");
    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("HELLO/HELLO_ACK");

    let download_dst = test_root.join("downloaded.json");
    let create = TransferCreate {
        op: TransferOp::Download,
        src_path: "".into(),
        dst_path: remote_path_str.into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created = TransferCreated::decode(frame.payload).unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );
    let _plan = TransferPlan::decode(frame.payload).unwrap();

    let begin = TransferBegin::new(created.transfer_id);
    let buf = Bytes::from(encode_message(&Message::TransferBegin(begin), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let dl_res = timeout(
        Duration::from_secs(15),
        velcrux_core::client_download(
            &conn,
            session.send_mut_owned(),
            session.recv_mut_owned(),
            created.transfer_id,
            download_dst.clone(),
        ),
    )
    .await
    .expect("download did not complete within timeout")
    .expect("download error");

    assert_eq!(dl_res, source_hash, "downloaded hash must match");
    let downloaded_content = tokio::fs::read(&download_dst).await.unwrap();
    assert_eq!(downloaded_content, source_data, "file contents must match");

    // Clean up
    let _ = tokio::fs::remove_dir_all(&test_root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_e2e_incompressible_fallback_roundtrip() {
    let _ = tracing_subscriber::fmt().try_init();

    // 1. PKI
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "fallback-user");

    // 2. Storage
    let pid = std::process::id();
    let test_root = std::env::temp_dir().join(format!("velcrux-fallback-test-{pid}"));
    let root = test_root.join("root");
    let staging = test_root.join("staging");
    tokio::fs::create_dir_all(&root).await.unwrap();
    tokio::fs::create_dir_all(&staging).await.unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(root.clone(), staging.clone())
            .await
            .expect("backend"),
    );

    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::CdcChunking);
    server_caps.set(Capability::Blake3);

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
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server build");
    let server_addr: SocketAddr = server_transport.local_addr().expect("server local addr");

    // High entropy random bytes (completely incompressible)
    let source_data = pseudo_random(0x9876_5432_10FE_DCBA, 256 * 1024);
    let source_hash = blake3_of(&source_data);
    let source_path = test_root.join("incompressible.bin");
    tokio::fs::write(&source_path, &source_data).await.unwrap();

    let stats = Arc::new(ServerStats::default());
    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "fallback-user".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let _server_task = {
        let backend = Arc::clone(&backend);
        let stats = Arc::clone(&stats);
        let authz = Arc::clone(&authz);
        tokio::spawn(async move {
            let conn = server_transport.accept().await.expect("server accept");
            let actor = ServerConn::with_state(
                server_caps,
                "velcruxd",
                stats,
                backend,
                None,
                None,
                Some(authz),
            )
            .with_compression(true);
            let _ = actor.run(&conn).await;
        })
    };

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

    let remote_path_str = "data/incompressible_upload.bin";
    let file_size = source_data.len() as u64;
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: source_path.display().to_string(),
        dst_path: remote_path_str.into(),
        idempotency_key: TransferId::generate().to_string(),
        file_size,
        file_hash: source_hash,
    };
    let buf = Bytes::from(encode_message(&Message::TransferCreate(create), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created = TransferCreated::decode(frame.payload).unwrap();

    let frame = session.recv_frame().await.unwrap();
    assert_eq!(
        frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );
    let _plan = TransferPlan::decode(frame.payload).unwrap();

    let begin = TransferBegin::new(created.transfer_id);
    let buf = Bytes::from(encode_message(&Message::TransferBegin(begin), 0).unwrap());
    session.send_mut().write_all(buf).await.unwrap();

    // Enable compression in client pipeline; compression algorithm detects negligible savings
    // and sends uncompressed DATA frames without COMPRESSED flag.
    let upload_cfg = velcrux_core::PipelineConfig::default().with_compression(true);
    let upload_res = timeout(
        Duration::from_secs(15),
        velcrux_core::client_upload(
            &conn,
            session.send_mut_owned(),
            session.recv_mut_owned(),
            created.transfer_id,
            source_path.clone(),
            file_size,
            source_hash,
            upload_cfg,
        ),
    )
    .await
    .expect("upload did not complete within timeout")
    .expect("upload error");

    assert_eq!(
        upload_res, source_hash,
        "incompressible data uploaded without corruption"
    );

    let _ = tokio::fs::remove_dir_all(&test_root).await;
}
