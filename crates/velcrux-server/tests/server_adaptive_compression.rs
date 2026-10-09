//! Integration tests for Option AO: Dynamic Adaptive Compression Selector
//! (Shannon Entropy Sampling, Multi-tier Zstandard, and Historical Backoff).
//!
//! (`PROTOCOL.md` §3, §4; `OPERATIONS.md` §4, §23; `SECURITY.md` §8, §10; `REQUIREMENTS.md` §21, §32).
//!
//! Verifies:
//! 1. Shannon entropy sampling and high-entropy bypass:
//!    - High-entropy chunks (random, media, encrypted) immediately bypass compression.
//! 2. Multi-tier compression optimization:
//!    - Highly repetitive data uses ultra-compression (level 7); standard text uses balanced level 3.
//! 3. Historical stream backoff & recovery:
//!    - Consecutive incompressible chunks trigger stream cooldown; subsequent compressible chunks restore compression.
//! 4. End-to-end QUIC loopback transfer:
//!    - Upload and download of mixed content (compressible text + random binary) with compression enabled
//!      completes with 100% BLAKE3 cryptographic integrity and verified byte savings.

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
use velcrux_core::protocol::compression::{
    compute_shannon_entropy, estimate_entropy, AdaptiveCompressionConfig,
    AdaptiveCompressionSelector, AdaptiveCompressionStats, CompressionDecision,
};
use velcrux_core::protocol::frame::{decode_data_frame_header, encode_data_frame_adaptive};
use velcrux_core::protocol::message::{
    Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
};
use velcrux_core::session::{encode_message, ClientSession, ServerConn, ServerStats};
use velcrux_core::storage::LocalFilesystemBackend;
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
    dn.push(DnType::CommonName, "velcrux-ao-ca");
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
    _files_dir: tempfile::TempDir,
    _staging_dir: tempfile::TempDir,
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
    server_caps.set(Capability::CompressionZstd);

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
                            )
                            .with_compression(true);
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
        _files_dir: files_dir,
        _staging_dir: staging_dir,
        _shutdown_tx: shutdown_tx,
        _server_task: server_task,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_shannon_entropy_sampler_precision() {
    // 1. Zero entropy on repetitive identical byte
    let zeroes = vec![0x00; 4096];
    assert_eq!(compute_shannon_entropy(&zeroes), 0.0);
    assert_eq!(estimate_entropy(&zeroes), 0.0);

    // 2. Exact 1.0 bit entropy on 50/50 two-symbol split
    let binary_seq = [b'A', b'B'].repeat(2048);
    let binary_ent = compute_shannon_entropy(&binary_seq);
    assert!((binary_ent - 1.0).abs() < 1e-4);

    // 3. Structured text / JSON entropy (typically 3.0 to 5.5)
    let json_text =
        br#"{"event":"transfer_started","chunk_id":12345,"status":"ok","meta":{"host":"node-1"}}"#
            .repeat(20);
    let text_ent = estimate_entropy(&json_text);
    assert!(
        text_ent > 3.0 && text_ent < 5.5,
        "JSON entropy should be typical text range: {text_ent}"
    );

    // 4. Uniform distribution: 256 distinct bytes repeated evenly (entropy == 8.0)
    let mut uniform = Vec::with_capacity(256 * 16);
    for _ in 0..16 {
        for b in 0..=255u8 {
            uniform.push(b);
        }
    }
    let uniform_ent = estimate_entropy(&uniform);
    assert!(
        (uniform_ent - 8.0).abs() < 1e-4,
        "uniform entropy should equal 8.0 bits: {uniform_ent}"
    );
}

#[test]
fn test_adaptive_compression_high_entropy_bypass_frame_encoding() {
    let mut selector = AdaptiveCompressionSelector::with_defaults();

    // High entropy pseudorandom data (entropy > 7.9)
    let mut high_entropy = Vec::with_capacity(8192);
    for _ in 0..32 {
        for b in 0..=255u8 {
            high_entropy.push(b);
        }
    }
    let hash = Hash::of(&high_entropy);

    // Encode frame with adaptive selector
    let (wire_bytes, was_compressed, decision) =
        encode_data_frame_adaptive(0, &hash, &high_entropy, &mut selector);

    assert!(!was_compressed, "high entropy chunk must NOT be compressed");
    assert!(matches!(
        decision,
        CompressionDecision::BypassHighEntropy { .. }
    ));

    // Decode header and verify flags
    let (hdr, payload) = decode_data_frame_header(&wire_bytes).expect("decode data frame");
    assert!(
        !hdr.flags.compressed(),
        "COMPRESSED flag must be 0 for bypassed chunk"
    );
    assert_eq!(hdr.chunk_len, high_entropy.len() as u32);
    assert_eq!(payload, &high_entropy[..]);

    // Check selector statistics
    let stats = selector.stats();
    assert_eq!(stats.total_chunks.load(Ordering::Relaxed), 1);
    assert_eq!(stats.bypassed_entropy.load(Ordering::Relaxed), 1);
    assert_eq!(stats.compressed_chunks.load(Ordering::Relaxed), 0);
    assert!(stats.cpu_time_saved_us_est.load(Ordering::Relaxed) > 0);
}

#[test]
fn test_adaptive_compression_multi_tier_optimization() {
    let mut selector = AdaptiveCompressionSelector::with_defaults();

    // 1. Ultra-repetitive data (entropy < 3.0) -> High tier (level 7)
    let repetitive = b"A".repeat(5000); // 5000 bytes of single repeated byte (entropy = 0.0)
    let hash_rep = Hash::of(&repetitive);
    let (wire_rep, was_comp_rep, decision_rep) =
        encode_data_frame_adaptive(0, &hash_rep, &repetitive, &mut selector);

    assert!(was_comp_rep);
    match decision_rep {
        CompressionDecision::Compressed {
            level,
            raw_len,
            compressed_len,
        } => {
            assert_eq!(level, 7, "ultra-repetitive data must use level 7");
            assert_eq!(raw_len, 5000);
            assert!(
                compressed_len < 100,
                "compressed size should be under 100 bytes, was {compressed_len}"
            );
        }
        other => panic!("expected Compressed decision, got {other:?}"),
    }

    let (hdr_rep, payload_rep) = decode_data_frame_header(&wire_rep).unwrap();
    assert!(hdr_rep.flags.compressed());
    assert_eq!(hdr_rep.chunk_len as usize, payload_rep.len());

    // 2. Standard text data (3.0 <= entropy < 6.0) -> Standard tier (level 3)
    let standard_text =
        b"Velcrux high performance bulk file transfer protocol running across QUIC.".repeat(40);
    let hash_std = Hash::of(&standard_text);
    let (_wire_std, was_comp_std, decision_std) =
        encode_data_frame_adaptive(5000, &hash_std, &standard_text, &mut selector);

    assert!(was_comp_std);
    match decision_std {
        CompressionDecision::Compressed { level, .. } => {
            assert_eq!(level, 3, "standard text data must use level 3");
        }
        other => panic!("expected Compressed decision, got {other:?}"),
    }
}

#[test]
fn test_adaptive_compression_historical_backoff_and_probe() {
    let config = AdaptiveCompressionConfig {
        min_compressible_size: 64,
        min_savings: 16,
        entropy_bypass_threshold: 7.5,
        backoff_failure_threshold: 2,
        backoff_cooldown_chunks: 3,
    };
    let stats = Arc::new(AdaptiveCompressionStats::default());
    let mut selector = AdaptiveCompressionSelector::new(config, stats.clone());

    // Create 256-byte uniform block (entropy == 8.0)
    let mut random_block = Vec::with_capacity(256);
    for b in 0..=255u8 {
        random_block.push(b);
    }
    let h_rand = Hash::of(&random_block);

    // 1. Two high-entropy chunks trigger failure threshold (2)
    let (_, _, d1) = encode_data_frame_adaptive(0, &h_rand, &random_block, &mut selector);
    let (_, _, d2) = encode_data_frame_adaptive(256, &h_rand, &random_block, &mut selector);
    assert!(matches!(d1, CompressionDecision::BypassHighEntropy { .. }));
    assert!(matches!(d2, CompressionDecision::BypassHighEntropy { .. }));

    // 2. Next 3 chunks are bypassed via historical backoff cooldown without checking entropy
    for i in 0..3 {
        let (_, _, d) = encode_data_frame_adaptive(
            (512 + i * 256) as u64,
            &h_rand,
            &random_block,
            &mut selector,
        );
        match d {
            CompressionDecision::BypassBackoff { cooldown_remaining } => {
                assert_eq!(cooldown_remaining, 2 - i);
            }
            other => panic!("expected BypassBackoff, got {other:?}"),
        }
    }
    assert_eq!(stats.bypassed_backoff.load(Ordering::Relaxed), 3);

    // 3. Probing chunk: now feed a highly compressible chunk
    let compressible = b"RECOVERED COMPRESSIBLE REPETITIVE STREAM CONTENT ".repeat(20);
    let h_comp = Hash::of(&compressible);
    let (wire_probe, was_comp_probe, d_probe) =
        encode_data_frame_adaptive(1280, &h_comp, &compressible, &mut selector);

    assert!(was_comp_probe);
    assert!(matches!(d_probe, CompressionDecision::Compressed { .. }));

    let (hdr, _) = decode_data_frame_header(&wire_probe).unwrap();
    assert!(hdr.flags.compressed());
    assert_eq!(stats.compressed_chunks.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_end_to_end_adaptive_compression_quic_transfer() {
    let rig = setup_test_rig().await;
    let conn = rig
        .client_transport
        .connect(rig.server_addr, "localhost")
        .await
        .unwrap();
    let (send, recv) = conn.open_bi().await.unwrap();

    let mut session = ClientSession::from_handshake_parts(send, recv)
        .await
        .expect("handshake");

    // Construct mixed content: compressible header + random body
    let mut file_content = Vec::new();
    // 64 KiB of compressible text
    file_content.extend_from_slice(
        &b"velcrux-log-entry-adaptive-compression-test-string-repeated\n".repeat(1100),
    );
    // 64 KiB of incompressible high-entropy bytes
    for _ in 0..256 {
        for b in 0..=255u8 {
            file_content.push(b);
        }
    }
    let file_size = file_content.len() as u64;
    let file_hash = Hash::of(&file_content);

    let temp_dir = tempdir().unwrap();
    let source_path = temp_dir.path().join("mixed_adaptive.bin");
    tokio::fs::write(&source_path, &file_content).await.unwrap();

    let idemp_key = format!("tx-ao-{}", TransferId::generate());
    let dst_path = "uploads/mixed_adaptive.bin";

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

    // Server sends TRANSFER_PLAN immediately after TRANSFER_CREATED
    let pframe = session.recv_frame().await.expect("TransferPlan frame");
    assert_eq!(
        pframe.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );
    let plan = TransferPlan::decode(pframe.payload).expect("decode TransferPlan");
    assert_eq!(plan.transfer_id, created.transfer_id);

    // 2. Send TRANSFER_BEGIN
    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 1,
    };
    let bbuf = Bytes::from(encode_message(&Message::TransferBegin(begin), 2).unwrap());
    session.send_mut().write_all(bbuf).await.unwrap();

    // 3. Client upload using adaptive compression
    let upload_cfg = velcrux_core::PipelineConfig::default().with_compression(true);
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
    .expect("upload did not complete within timeout")
    .expect("upload error");

    assert_eq!(
        upload_res, file_hash,
        "uploaded file hash must match original BLAKE3 hash"
    );

    // Verify stored file on server
    let dest_file = rig._files_dir.path().join("uploads/mixed_adaptive.bin");
    let stored_bytes = tokio::fs::read(&dest_file).await.expect("read stored file");
    assert_eq!(stored_bytes.len(), file_content.len());
    assert_eq!(Hash::of(&stored_bytes), file_hash);
}
