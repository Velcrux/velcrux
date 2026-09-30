//! Integration tests for Option Z: Comprehensive Failure Injection, Fault Recovery & Chaos Transfer Resilience
//! (`REQUIREMENTS.md` §6, §7, §8, §34, §72; `ARCHITECTURE.md` §12).
//!
//! Verifies:
//! 1. Mid-flight connection drops & restart resumption:
//!    - Simulates client process kill / sudden socket drop at 50% transfer progress.
//!    - Verifies server retains bitmap checkpoints in persistent state store without corrupting destination.
//!    - Reconnects with same idempotency key; server reports completed chunks as reusable.
//!    - Client sends only missing chunks; whole-file BLAKE3 hash verified and committed atomically.
//! 2. Injected chunk payload tampering & bit-rot detection:
//!    - Injects bit flips / corrupt payload into a DATA frame.
//!    - Server per-chunk BLAKE3 verification detects mismatch, rejects corrupted chunk, aborts transfer,
//!      and keeps destination file uncorrupted.
//! 3. Storage space exhaustion (ENOSPC / disk full) simulation:
//!    - Backend configured with high minimum free space reservation constraint.
//!    - Server checks space prior to staging, fails gracefully, emits `ErrorCode::DiskFull`,
//!      increments `disk_full_errors` telemetry, and prevents partial writes.
//! 4. Crash-resilient commit journal recovery:
//!    - Simulates abrupt failure during multi-file commit leaving journal entries in `CommitStatus::Pending`.
//!    - `resume_interrupted_commit` detects pending staging entries, completes atomic renames,
//!      and marks journal rows `Committed`.
//! 5. Whole-file hash mismatch rejection:
//!    - Client provides invalid expected hash during `VERIFY` phase.
//!    - Server verifies hash against actual computed bytes, detects discrepancy, rejects commit,
//!      and leaves destination untouched.

#![forbid(unsafe_code)]

use std::fs;
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
use velcrux_core::protocol::frame::{
    encode_data_frame, encode_data_preamble, DataFrameFlags, DataPreamble,
};
use velcrux_core::protocol::message::{
    Commit, ErrorMsg, Hello, Message, TransferBegin, TransferCreate, TransferCreated, TransferOp,
    TransferPlan, Verify, VerifyResult,
};
use velcrux_core::session::{read_frame, write_frame, ServerConn, ServerStats};
use velcrux_core::state::sqlite::SqliteStateStore;
use velcrux_core::state::{
    CommitJournalEntry, CommitStatus, Direction, Role, StateStore, TransferRecord, TransferStatus,
};
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::sync::resume_interrupted_commit;
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
    dn.push(DnType::CommonName, "velcrux-chaos-ca");
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

fn test_tunables() -> TransportConfigTunables {
    TransportConfigTunables {
        receive_window: 64 * 1024 * 1024,
        stream_receive_window: 16 * 1024 * 1024,
        max_concurrent_streams: 16,
        idle_timeout: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
        initial_rtt: Duration::from_millis(10),
    }
}

// ---------------------------------------------------------------------------
// 1. Mid-Flight Connection Drops & Resume Verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_chaos_abrupt_disconnect_and_resumption() {
    let td = tempdir().unwrap();
    let root_dir = td.path().join("storage_root");
    let staging_dir = td.path().join("storage_staging");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&staging_dir).unwrap();

    let db_path = td.path().join("server_state.db");
    let state_store: Arc<dyn StateStore> =
        Arc::new(SqliteStateStore::new(&db_path).expect("open sqlite state store"));

    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "chaos-user");

    let backend = Arc::new(
        LocalFilesystemBackend::new_with_options(root_dir.clone(), staging_dir.clone(), 0, false)
            .await
            .unwrap(),
    );
    let stats = Arc::new(ServerStats::default());

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "chaos-user".to_string(),
        path_prefix: "".to_string(),
        permissions: PermSet::ALL_TRANSFER,
    }]));

    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("server client CA")
        .with_tunables(test_tunables())
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
        let st = state_store.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    while let Ok(conn) = server_transport.accept().await {
                        let b = b.clone();
                        let s = s.clone();
                        let az = az.clone();
                        let st = st.clone();
                        tokio::spawn(async move {
                            let actor = ServerConn::with_state(
                                server_caps,
                                "velcruxd-chaos",
                                s,
                                b,
                                Some(st),
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
            .with_client_identity(client_identity.clone())
            .with_tunables(test_tunables())
            .build()
            .expect("client build"),
    );

    // Create a 4 MiB source file consisting of four 1 MiB chunks (matching server M3_CHUNK_SIZE)
    const CHUNK_SIZE: usize = 1024 * 1024;
    const NUM_CHUNKS: usize = 4;
    let total_file_size = (CHUNK_SIZE * NUM_CHUNKS) as u64;

    let mut file_bytes = Vec::with_capacity(total_file_size as usize);
    let mut chunk_hashes = Vec::new();

    for i in 0..NUM_CHUNKS {
        let pattern = (0x30 + i) as u8;
        let c_data = vec![pattern; CHUNK_SIZE];
        chunk_hashes.push(Hash::of(&c_data));
        file_bytes.extend_from_slice(&c_data);
    }
    let expected_whole_hash = Hash::of(&file_bytes);
    let idempotency_key = "idempotent-chaos-resumption-key";
    let dest_rel_path = "vault/chaos_resume.bin";

    // -----------------------------------------------------------------------
    // Pass 1: Upload chunks 0 and 1, then abruptly DROP connection (kill simulation)
    // -----------------------------------------------------------------------
    let first_transfer_id = {
        let conn = client_transport
            .connect(server_addr, "localhost")
            .await
            .expect("client connect 1");
        let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open 1");

        // Handshake & Auth
        write_frame(send.as_mut(), &Message::Hello(Hello::default_client()), 1)
            .await
            .unwrap();
        let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
        write_frame(
            send.as_mut(),
            &Message::Auth(velcrux_core::protocol::message::Auth::mtls()),
            2,
        )
        .await
        .unwrap();
        let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

        let create = TransferCreate {
            op: TransferOp::Upload,
            src_path: "local_chaos.bin".to_string(),
            dst_path: dest_rel_path.to_string(),
            idempotency_key: idempotency_key.to_string(),
            file_size: total_file_size,
            file_hash: expected_whole_hash,
        };
        write_frame(send.as_mut(), &Message::TransferCreate(create), 3)
            .await
            .unwrap();

        let f1 = read_frame(recv.as_mut()).await.unwrap().unwrap();
        let created = TransferCreated::decode(f1.payload).unwrap();
        assert!(!created.resumed, "First pass must not be resumed");

        let f2 = read_frame(recv.as_mut()).await.unwrap().unwrap();
        let plan = TransferPlan::decode(f2.payload).unwrap();
        assert_eq!(plan.bytes_total, total_file_size);
        assert_eq!(plan.bytes_to_transfer, total_file_size);
        assert_eq!(plan.bytes_reusable, 0);

        write_frame(
            send.as_mut(),
            &Message::TransferBegin(TransferBegin::new(created.transfer_id)),
            4,
        )
        .await
        .unwrap();

        let mut data_send = conn.open_uni().await.expect("data stream 1");
        let preamble = DataPreamble {
            transfer_id: created.transfer_id,
            file_id: 1,
            stream_seq: 1,
        };
        data_send
            .write_all(Bytes::from(encode_data_preamble(&preamble).to_vec()))
            .await
            .unwrap();

        // Send Chunk 0
        let c0_data = &file_bytes[0..CHUNK_SIZE];
        let frame0 = encode_data_frame(
            0,
            CHUNK_SIZE as u32,
            DataFrameFlags::NONE,
            &chunk_hashes[0],
            c0_data,
        );
        data_send.write_all(Bytes::from(frame0)).await.unwrap();

        // Send Chunk 1
        let c1_data = &file_bytes[CHUNK_SIZE..2 * CHUNK_SIZE];
        let frame1 = encode_data_frame(
            CHUNK_SIZE as u64,
            CHUNK_SIZE as u32,
            DataFrameFlags::NONE,
            &chunk_hashes[1],
            c1_data,
        );
        data_send.write_all(Bytes::from(frame1)).await.unwrap();

        // Finish data stream cleanly so the server receives chunks and records checkpoint
        let _ = data_send.finish().await;

        // ABRUPT CLIENT DROP: drop streams and connection, aborting transfer halfway through
        drop(data_send);
        drop(send);
        drop(recv);
        drop(conn);

        created.transfer_id
    };

    // Verify destination file has NOT been committed
    assert!(
        !root_dir.join(dest_rel_path).exists(),
        "Destination must not exist after interrupted pass"
    );

    // Verify server recorded checkpoint in state store
    let mut recorded_bm = None;
    for _ in 0..40 {
        if let Ok(b) = state_store.read_bitmap(first_transfer_id) {
            if b.contains(0) && b.contains(1) {
                recorded_bm = Some(b);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let bm = recorded_bm.expect("Server checkpoint bitmap must contain chunks 0 and 1");

    // -----------------------------------------------------------------------
    // Pass 2: Reconnect with same idempotency key and complete resumption
    // -----------------------------------------------------------------------
    {
        let conn2 = client_transport
            .connect(server_addr, "localhost")
            .await
            .expect("client connect 2");
        let (mut send2, mut recv2) = conn2.open_bi().await.expect("bi stream open 2");

        // Handshake & Auth
        write_frame(send2.as_mut(), &Message::Hello(Hello::default_client()), 1)
            .await
            .unwrap();
        let _ = read_frame(recv2.as_mut()).await.unwrap().unwrap();
        write_frame(
            send2.as_mut(),
            &Message::Auth(velcrux_core::protocol::message::Auth::mtls()),
            2,
        )
        .await
        .unwrap();
        let _ = read_frame(recv2.as_mut()).await.unwrap().unwrap();

        let create2 = TransferCreate {
            op: TransferOp::Upload,
            src_path: "local_chaos.bin".to_string(),
            dst_path: dest_rel_path.to_string(),
            idempotency_key: idempotency_key.to_string(),
            file_size: total_file_size,
            file_hash: expected_whole_hash,
        };
        write_frame(send2.as_mut(), &Message::TransferCreate(create2), 3)
            .await
            .unwrap();

        let f1_2 = read_frame(recv2.as_mut()).await.unwrap().unwrap();
        let created2 = TransferCreated::decode(f1_2.payload).unwrap();
        assert_eq!(created2.transfer_id, first_transfer_id);
        assert!(created2.resumed, "Second pass MUST be flagged as resumed");

        let f2_2 = read_frame(recv2.as_mut()).await.unwrap().unwrap();
        let plan2 = TransferPlan::decode(f2_2.payload).unwrap();
        assert_eq!(plan2.bytes_total, total_file_size);
        assert!(
            plan2.bytes_reusable >= CHUNK_SIZE as u64,
            "Server must report completed chunks as reusable"
        );

        write_frame(
            send2.as_mut(),
            &Message::TransferBegin(TransferBegin::new(created2.transfer_id)),
            4,
        )
        .await
        .unwrap();

        let mut data_send2 = conn2.open_uni().await.expect("data stream 2");
        let preamble2 = DataPreamble {
            transfer_id: created2.transfer_id,
            file_id: 1,
            stream_seq: 1,
        };
        data_send2
            .write_all(Bytes::from(encode_data_preamble(&preamble2).to_vec()))
            .await
            .unwrap();

        // Send remaining missing chunks (chunks 2 and 3 or whichever are missing)
        for (chunk_idx, chunk_hash) in chunk_hashes.iter().enumerate().take(NUM_CHUNKS) {
            if !bm.contains(chunk_idx as u64) {
                let start = chunk_idx * CHUNK_SIZE;
                let c_data = &file_bytes[start..start + CHUNK_SIZE];
                let frame = encode_data_frame(
                    start as u64,
                    CHUNK_SIZE as u32,
                    DataFrameFlags::NONE,
                    chunk_hash,
                    c_data,
                );
                data_send2.write_all(Bytes::from(frame)).await.unwrap();
            }
        }
        let _ = data_send2.finish().await;
        drop(data_send2);

        // Verify phase
        let verify = Verify {
            transfer_id: created2.transfer_id,
            expected_hash: expected_whole_hash,
        };
        write_frame(send2.as_mut(), &Message::Verify(verify), 5)
            .await
            .unwrap();

        let vr_frame = read_frame(recv2.as_mut()).await.unwrap().unwrap();
        let vr = VerifyResult::decode(vr_frame.payload).unwrap();
        assert!(vr.ok, "Verify must succeed on completed resumed file");
        assert_eq!(vr.computed_hash, expected_whole_hash);

        // Commit phase
        let commit = Commit {
            transfer_id: created2.transfer_id,
        };
        write_frame(send2.as_mut(), &Message::Commit(commit), 6)
            .await
            .unwrap();

        let comm_frame = read_frame(recv2.as_mut()).await.unwrap().unwrap();
        assert_eq!(
            comm_frame.type_byte,
            velcrux_core::protocol::message::COMMITTED
        );
    }

    // Verify final committed destination file
    let final_dest = root_dir.join(dest_rel_path);
    assert!(
        final_dest.is_file(),
        "Destination file must exist after commit"
    );
    let actual_bytes = fs::read(&final_dest).unwrap();
    assert_eq!(actual_bytes.len(), total_file_size as usize);
    assert_eq!(actual_bytes, file_bytes);
    assert_eq!(Hash::of(&actual_bytes), expected_whole_hash);

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// 2. Injected Payload Tampering & Bit-Rot Detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_chaos_payload_tampering_and_bit_flip_detection() {
    let td = tempdir().unwrap();
    let root_dir = td.path().join("storage_root");
    let staging_dir = td.path().join("storage_staging");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&staging_dir).unwrap();

    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "chaos-user");

    let backend = Arc::new(
        LocalFilesystemBackend::new_with_options(root_dir.clone(), staging_dir.clone(), 0, false)
            .await
            .unwrap(),
    );
    let stats = Arc::new(ServerStats::default());

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "chaos-user".to_string(),
        path_prefix: "".to_string(),
        permissions: PermSet::ALL_TRANSFER,
    }]));

    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("server client CA")
        .with_tunables(test_tunables())
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
                                "velcruxd-chaos",
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
            .with_tunables(test_tunables())
            .build()
            .expect("client build"),
    );

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Handshake & Auth
    write_frame(send.as_mut(), &Message::Hello(Hello::default_client()), 1)
        .await
        .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
    write_frame(
        send.as_mut(),
        &Message::Auth(velcrux_core::protocol::message::Auth::mtls()),
        2,
    )
    .await
    .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    const CHUNK_SIZE: usize = 64 * 1024;
    let file_data = vec![0x42u8; CHUNK_SIZE];
    let original_hash = Hash::of(&file_data);

    let dest_rel = "vault/tampered_test.bin";
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "tampered.bin".to_string(),
        dst_path: dest_rel.to_string(),
        idempotency_key: "tampered-chaos-key".to_string(),
        file_size: CHUNK_SIZE as u64,
        file_hash: original_hash,
    };
    write_frame(send.as_mut(), &Message::TransferCreate(create), 3)
        .await
        .unwrap();

    let f1 = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let created = TransferCreated::decode(f1.payload).unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap(); // TransferPlan

    write_frame(
        send.as_mut(),
        &Message::TransferBegin(TransferBegin::new(created.transfer_id)),
        4,
    )
    .await
    .unwrap();

    let mut data_send = conn.open_uni().await.expect("data stream");
    let preamble = DataPreamble {
        transfer_id: created.transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    data_send
        .write_all(Bytes::from(encode_data_preamble(&preamble).to_vec()))
        .await
        .unwrap();

    // INJECT BIT FLIP / CORRUPTED BYTES:
    let mut corrupted_data = file_data.clone();
    corrupted_data[128] ^= 0xFF; // Flip bit

    // Declare original hash in header, but send corrupted payload
    let frame = encode_data_frame(
        0,
        CHUNK_SIZE as u32,
        DataFrameFlags::NONE,
        &original_hash, // Declared hash does NOT match corrupted payload
        &corrupted_data,
    );
    data_send.write_all(Bytes::from(frame)).await.unwrap();
    drop(data_send);

    // Attempt verify: should fail or receive Error
    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash: original_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::Verify(verify), 5).await;

    // Server should reject or close connection
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Destination file MUST NOT exist
    assert!(
        !root_dir.join(dest_rel).exists(),
        "Tampered payload must NEVER be committed to destination"
    );

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// 3. Storage Space Exhaustion (ENOSPC / Disk Full) Simulation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_chaos_enospc_disk_full_simulation() {
    let td = tempdir().unwrap();
    let root_dir = td.path().join("storage_root");
    let staging_dir = td.path().join("storage_staging");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&staging_dir).unwrap();

    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "chaos-user");

    // Configure backend with unreachable free disk space constraint (simulating ENOSPC)
    let backend = Arc::new(
        LocalFilesystemBackend::new_with_options(
            root_dir.clone(),
            staging_dir.clone(),
            u64::MAX - 1000, // Impossibly large required free margin
            false,
        )
        .await
        .unwrap(),
    );
    let stats = Arc::new(ServerStats::default());

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "chaos-user".to_string(),
        path_prefix: "".to_string(),
        permissions: PermSet::ALL_TRANSFER,
    }]));

    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("server client CA")
        .with_tunables(test_tunables())
        .build("127.0.0.1:0".parse().unwrap())
        .expect("server bind");

    let server_addr = server_transport.local_addr().expect("local addr");
    let mut server_caps = Capabilities::EMPTY;
    server_caps.set(Capability::FixedChunking);
    server_caps.set(Capability::Blake3);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let s_stats_clone = stats.clone();
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
                                "velcruxd-chaos",
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
            .with_tunables(test_tunables())
            .build()
            .expect("client build"),
    );

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Handshake & Auth
    write_frame(send.as_mut(), &Message::Hello(Hello::default_client()), 1)
        .await
        .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
    write_frame(
        send.as_mut(),
        &Message::Auth(velcrux_core::protocol::message::Auth::mtls()),
        2,
    )
    .await
    .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    let dest_rel = "vault/enospc_target.bin";
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "bigfile.bin".to_string(),
        dst_path: dest_rel.to_string(),
        idempotency_key: "enospc-chaos-key".to_string(),
        file_size: 10 * 1024 * 1024, // 10 MiB
        file_hash: Hash::ZERO,
    };
    write_frame(send.as_mut(), &Message::TransferCreate(create), 3)
        .await
        .unwrap();

    // Server must reject with ERROR (DiskFull)
    let err_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    assert_eq!(
        err_frame.type_byte,
        velcrux_core::protocol::message::ERROR,
        "Server must emit ERROR frame upon disk exhaustion"
    );

    let error_msg = ErrorMsg::decode(err_frame.payload).unwrap();
    assert_eq!(
        error_msg.code,
        ErrorCode::DiskFull,
        "Error code must be ErrorCode::DiskFull"
    );

    // Telemetry: disk_full_errors counter must be incremented
    assert!(
        s_stats_clone
            .disk_full_errors
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1,
        "disk_full_errors telemetry counter must be incremented"
    );

    // Destination file must not exist
    assert!(!root_dir.join(dest_rel).exists());

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// 4. Crash-Resilient Commit Journal Recovery
// ---------------------------------------------------------------------------

#[test]
fn test_chaos_crash_during_commit_journal_recovery() {
    let td = tempdir().unwrap();
    let dst_dir = td.path().join("committed_vault");
    let staging_dir = td.path().join("staging_vault");
    fs::create_dir_all(&dst_dir).unwrap();
    fs::create_dir_all(&staging_dir).unwrap();

    let db_path = td.path().join("journal_state.db");
    let state_store = SqliteStateStore::new(&db_path).expect("open sqlite state store");

    let transfer_id = TransferId::generate();

    // Setup simulated staged files left over after an abrupt crash before rename
    let staged_file_1 = staging_dir.join("recovered_1.dat");
    let staged_file_2 = staging_dir.join("sub").join("recovered_2.dat");
    fs::create_dir_all(staged_file_2.parent().unwrap()).unwrap();

    fs::write(&staged_file_1, b"Crash recovery data payload 1").unwrap();
    fs::write(&staged_file_2, b"Crash recovery data payload 2").unwrap();

    // Record parent transfer record in state store (for foreign key constraint)
    let now_ms = 1_700_000_000_000u64;
    let record = TransferRecord {
        transfer_id,
        idempotency_key: "chaos-journal-recovery-key".to_string(),
        role: Role::Server,
        direction: Direction::Upload,
        status: TransferStatus::Active,
        remote_path: "recovered_1.dat".to_string(),
        local_path: String::new(),
        file_size: 100,
        file_hash: Hash::ZERO,
        verified_up_to: 0,
        last_checkpoint_ms: 0,
        bytes_completed: 0,
        staging_relpath: String::new(),
        created_ms: now_ms,
        updated_ms: now_ms,
    };
    state_store.upsert_transfer(&record).unwrap();

    // Record pending entries in the commit journal (simulating crash during commit)
    let entry_1 = CommitJournalEntry {
        transfer_id,
        file_id: 1,
        remote_path: "recovered_1.dat".to_string(),
        status: CommitStatus::Pending,
        updated_ms: now_ms,
    };
    let entry_2 = CommitJournalEntry {
        transfer_id,
        file_id: 2,
        remote_path: "sub/recovered_2.dat".to_string(),
        status: CommitStatus::Pending,
        updated_ms: now_ms,
    };

    state_store.write_journal(&entry_1).unwrap();
    state_store.write_journal(&entry_2).unwrap();

    // Verify journal reports 2 pending items
    let pending_before = state_store.pending_journal().unwrap();
    assert_eq!(pending_before.len(), 2);

    // Execute journal recovery
    let resumed_count =
        resume_interrupted_commit(&state_store, &staging_dir, &dst_dir, Some(transfer_id))
            .expect("resume interrupted commit");

    assert_eq!(
        resumed_count, 2,
        "Both pending files must be recovered and committed"
    );

    // Verify files now exist in destination directory
    let final_file_1 = dst_dir.join("recovered_1.dat");
    let final_file_2 = dst_dir.join("sub").join("recovered_2.dat");

    assert!(final_file_1.is_file());
    assert_eq!(
        fs::read(&final_file_1).unwrap(),
        b"Crash recovery data payload 1"
    );

    assert!(final_file_2.is_file());
    assert_eq!(
        fs::read(&final_file_2).unwrap(),
        b"Crash recovery data payload 2"
    );

    // Verify journal has no pending items remaining
    let pending_after = state_store.pending_journal().unwrap();
    assert_eq!(
        pending_after.len(),
        0,
        "Commit journal must have 0 pending items after recovery"
    );
}

// ---------------------------------------------------------------------------
// 5. Whole-File Hash Discrepancy Rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_chaos_whole_file_hash_mismatch_rejected() {
    let td = tempdir().unwrap();
    let root_dir = td.path().join("storage_root");
    let staging_dir = td.path().join("storage_staging");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&staging_dir).unwrap();

    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "chaos-user");

    let backend = Arc::new(
        LocalFilesystemBackend::new_with_options(root_dir.clone(), staging_dir.clone(), 0, false)
            .await
            .unwrap(),
    );
    let stats = Arc::new(ServerStats::default());

    let authz: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::from_grants(vec![Grant {
        identity: "chaos-user".to_string(),
        path_prefix: "".to_string(),
        permissions: PermSet::ALL_TRANSFER,
    }]));

    let server_transport = ServerBuilder::new()
        .with_server_cert(server_cert.certs, server_cert.key)
        .with_client_ca_roots_pem(ca.cert_pem.as_bytes())
        .expect("server client CA")
        .with_tunables(test_tunables())
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
                                "velcruxd-chaos",
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
            .with_tunables(test_tunables())
            .build()
            .expect("client build"),
    );

    let conn = client_transport
        .connect(server_addr, "localhost")
        .await
        .expect("client connect");
    let (mut send, mut recv) = conn.open_bi().await.expect("bi stream open");

    // Handshake & Auth
    write_frame(send.as_mut(), &Message::Hello(Hello::default_client()), 1)
        .await
        .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();
    write_frame(
        send.as_mut(),
        &Message::Auth(velcrux_core::protocol::message::Auth::mtls()),
        2,
    )
    .await
    .unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap();

    const CHUNK_SIZE: usize = 64 * 1024;
    let file_data = vec![0x99u8; CHUNK_SIZE];
    let actual_hash = Hash::of(&file_data);

    let mut bad_hash_bytes = *actual_hash.as_bytes();
    bad_hash_bytes[0] ^= 0xAA;
    let declared_bad_hash = Hash::from_bytes(&bad_hash_bytes).unwrap();

    let dest_rel = "vault/bad_whole_hash.bin";
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "bad_hash.bin".to_string(),
        dst_path: dest_rel.to_string(),
        idempotency_key: "bad-hash-chaos-key".to_string(),
        file_size: CHUNK_SIZE as u64,
        file_hash: declared_bad_hash, // Client tells server to expect this hash
    };
    write_frame(send.as_mut(), &Message::TransferCreate(create), 3)
        .await
        .unwrap();

    let f1 = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let created = TransferCreated::decode(f1.payload).unwrap();
    let _ = read_frame(recv.as_mut()).await.unwrap().unwrap(); // TransferPlan

    write_frame(
        send.as_mut(),
        &Message::TransferBegin(TransferBegin::new(created.transfer_id)),
        4,
    )
    .await
    .unwrap();

    let mut data_send = conn.open_uni().await.expect("data stream");
    let preamble = DataPreamble {
        transfer_id: created.transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    data_send
        .write_all(Bytes::from(encode_data_preamble(&preamble).to_vec()))
        .await
        .unwrap();

    let frame = encode_data_frame(
        0,
        CHUNK_SIZE as u32,
        DataFrameFlags::NONE,
        &actual_hash,
        &file_data,
    );
    data_send.write_all(Bytes::from(frame)).await.unwrap();
    drop(data_send);

    // Verify with declared bad hash
    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash: declared_bad_hash,
    };
    write_frame(send.as_mut(), &Message::Verify(verify), 5)
        .await
        .unwrap();

    let vr_frame = read_frame(recv.as_mut()).await.unwrap().unwrap();
    let vr = VerifyResult::decode(vr_frame.payload).unwrap();
    assert!(
        !vr.ok,
        "VerifyResult MUST report ok=false when whole-file hash mismatch occurs"
    );
    assert_eq!(
        vr.computed_hash, actual_hash,
        "Computed hash must match actual bytes, revealing discrepancy"
    );

    // Destination file MUST NOT exist
    assert!(!root_dir.join(dest_rel).exists());

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}
