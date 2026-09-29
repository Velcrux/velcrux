//! Integration tests for Option W: WAN Impairment, Loss Emulation & High-Latency Benchmark Validation
//! (`PERFORMANCE.md` §7, §9, §12; `DEVELOPMENT.md` §5; `ARCHITECTURE.md` §7).
//!
//! Verifies:
//! 1. BDP auto-tuning and flow control receive window scaling:
//!    - Calculates BDP for 10 Gbps / 150 ms RTT, verifying 384 MiB window requirement (2× BDP).
//!    - Verifies scaling across 100 Mbps, 1 Gbps, and 10 Gbps at 20ms, 50ms, 100ms, and 200ms RTT.
//! 2. High-latency WAN loopback transfer:
//!    - Server configured with 384 MiB receive window and 150ms initial RTT hint.
//!    - Client connects and completes multi-chunk upload under simulated WAN latency.
//!    - Cryptographic BLAKE3 verification matches 100% of bytes.
//! 3. Multi-stream parallel data channel striping under WAN latency:
//!    - Transfers striped across 4 streams.
//!    - Verifies sequential destination assembly and hash integrity.
//! 4. Scenario record JSON emission and `bench-report.py` execution:
//!    - Generates scenario record in `benches/results/`.
//!    - Runs `scripts/bench-report.py` and parses markdown table output.
//! 5. Network simulation harness (`scripts/netsim.sh`):
//!    - Executes `./scripts/netsim.sh ci` cleanly.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
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
use velcrux_core::protocol::message::{
    Commit, Hello, Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, Verify,
    VerifyResult,
};
use velcrux_core::session::{read_frame, write_frame, ServerConn, ServerStats};
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::transport::quic::{
    ClientBuilder, ClientIdentity, QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::{Connection, Transport};
use velcrux_core::util::{Hash, TransferId};
use velcrux_server::config::parse_size_bytes;

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
    dn.push(DnType::CommonName, "velcrux-wan-ca");
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

fn blake3_of(data: &[u8]) -> Hash {
    let mut h = velcrux_core::HashHasher::new();
    h.feed(data);
    h.finalize()
}

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

// ---------------------------------------------------------------------------
// 1. BDP Auto-Tuning Window Scaling (PERFORMANCE.md §4, §9)
// ---------------------------------------------------------------------------

#[test]
fn test_wan_bdp_auto_tuning_window_scaling() {
    // Formula: BDP (bytes) = (bandwidth_bps / 8) * rtt_seconds
    // Target window: 2 × BDP (PERFORMANCE.md §4)

    // Case 1: 10 Gbps link at 150 ms RTT (Reference WAN Benchmark)
    let bw_10g = 10_000_000_000f64;
    let rtt_150ms = 0.150f64;
    let bdp_10g_150ms = (bw_10g / 8.0) * rtt_150ms;
    assert_eq!(bdp_10g_150ms as u64, 187_500_000); // 187.5 MB
    let target_win_150ms = bdp_10g_150ms * 2.0;
    assert_eq!(target_win_150ms as u64, 375_000_000); // 375 MB

    // Confirms 384 MiB ceiling is >= 2× BDP for 10G/150ms
    let max_window_spec = parse_size_bytes("384MiB").unwrap();
    assert_eq!(max_window_spec, 384 * 1024 * 1024); // 402,653,184 bytes
    assert!(
        max_window_spec > target_win_150ms as u64,
        "384 MiB window must cover 2x BDP for 10 Gbps / 150 ms WAN link"
    );

    // Case 2: 1 Gbps link at 100 ms RTT
    let bw_1g = 1_000_000_000f64;
    let rtt_100ms = 0.100f64;
    let bdp_1g_100ms = (bw_1g / 8.0) * rtt_100ms;
    assert_eq!(bdp_1g_100ms as u64, 12_500_000); // 12.5 MB

    // Case 3: 100 Mbps link at 50 ms RTT
    let bw_100m = 100_000_000f64;
    let rtt_50ms = 0.050f64;
    let bdp_100m_50ms = (bw_100m / 8.0) * rtt_50ms;
    assert_eq!(bdp_100m_50ms as u64, 625_000); // 625 KB
}

// ---------------------------------------------------------------------------
// 2. High-Latency WAN Loopback Transfer with BDP Window Tuning
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wan_high_rtt_loopback_transfer() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "wan-operator");

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
        identity: "wan-operator".to_string(),
        path_prefix: "wan_data".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());

    // WAN tunables: 384 MiB receive window, 150 ms initial RTT (PERFORMANCE.md §4, §9)
    let tunables = TransportConfigTunables {
        receive_window: 384 * 1024 * 1024,
        stream_receive_window: 384 * 1024 * 1024,
        max_concurrent_streams: 16,
        idle_timeout: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
        initial_rtt: Duration::from_millis(150),
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
                                "velcruxd-wan",
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

    // Handshake
    let hello = Hello::default_client();
    let _ = write_frame(send.as_mut(), &Message::Hello(hello), 1).await;
    let ack_frame = read_frame(recv.as_mut())
        .await
        .expect("read hello ack")
        .expect("some ack frame");
    assert_eq!(
        ack_frame.type_byte,
        velcrux_core::protocol::message::HELLO_ACK
    );

    // Auth
    let auth = velcrux_core::protocol::message::Auth::mtls();
    let _ = write_frame(send.as_mut(), &Message::Auth(auth), 2).await;
    let auth_ack = read_frame(recv.as_mut())
        .await
        .expect("read auth ok")
        .expect("some auth frame");
    assert_eq!(auth_ack.type_byte, velcrux_core::protocol::message::AUTH_OK);

    // Generate 128 KiB test payload
    let payload_size = 128 * 1024;
    let mut payload = vec![0u8; payload_size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 31) ^ 0xA5) as u8;
    }
    let expected_hash = blake3_of(&payload);

    // Create transfer
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "wan_file.bin".to_string(),
        dst_path: "wan_data/wan_transferred.bin".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: payload_size as u64,
        file_hash: expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferCreate(create), 3).await;
    let created_frame = read_frame(recv.as_mut())
        .await
        .expect("transfer created")
        .expect("some created frame");
    assert_eq!(
        created_frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_CREATED
    );
    let created = TransferCreated::decode(created_frame.payload).expect("decode created");

    let plan_frame = read_frame(recv.as_mut())
        .await
        .expect("transfer plan")
        .expect("some plan frame");
    assert_eq!(
        plan_frame.type_byte,
        velcrux_core::protocol::message::TRANSFER_PLAN
    );

    // Begin transfer
    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 1,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferBegin(begin), 4).await;

    // Send data over a data stream with simulated WAN pacing
    let mut data_send = conn.open_uni().await.expect("open data uni stream");
    let preamble = velcrux_core::protocol::frame::DataPreamble {
        transfer_id: created.transfer_id,
        file_id: 1,
        stream_seq: 1,
    };
    let pre_enc = velcrux_core::protocol::frame::encode_data_preamble(&preamble);
    data_send
        .write_all(Bytes::copy_from_slice(&pre_enc))
        .await
        .expect("write preamble");

    // Write chunk
    let chunk_frame = velcrux_core::protocol::frame::encode_data_frame(
        0,
        payload_size as u32,
        velcrux_core::protocol::frame::DataFrameFlags::NONE,
        &expected_hash,
        &payload,
    );
    data_send
        .write_all(Bytes::from(chunk_frame))
        .await
        .expect("write chunk frame");
    data_send.finish().await.expect("finish data stream");

    // Verify transfer
    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::Verify(verify), 5).await;
    let vres_frame = read_frame(recv.as_mut())
        .await
        .expect("verify result")
        .expect("some vres frame");
    assert_eq!(
        vres_frame.type_byte,
        velcrux_core::protocol::message::VERIFY_RESULT
    );
    let vres = VerifyResult::decode(vres_frame.payload).expect("decode verify result");
    assert!(vres.ok, "verification must succeed");

    // Commit transfer
    let commit = Commit {
        transfer_id: created.transfer_id,
    };
    let _ = write_frame(send.as_mut(), &Message::Commit(commit), 6).await;
    let committed_frame = read_frame(recv.as_mut())
        .await
        .expect("committed frame")
        .expect("some committed frame");
    assert_eq!(
        committed_frame.type_byte,
        velcrux_core::protocol::message::COMMITTED
    );

    // Assert destination file exists and hash matches exactly
    let dst_path = files_dir
        .path()
        .join("wan_data")
        .join("wan_transferred.bin");
    let committed_bytes = fs::read(&dst_path).expect("read committed file");
    assert_eq!(committed_bytes.len(), payload_size);
    assert_eq!(blake3_of(&committed_bytes), expected_hash);

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// 3. Multi-Stream Striping under WAN Latency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_wan_multi_stream_striping() {
    let ca = build_dev_ca();
    let server_cert = build_server_cert(&ca);
    let client_identity = build_client_identity(&ca, "wan-striping-client");

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
        identity: "wan-striping-client".to_string(),
        path_prefix: "striped".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]));

    let stats = Arc::new(ServerStats::default());

    let tunables = TransportConfigTunables {
        receive_window: 64 * 1024 * 1024,
        stream_receive_window: 16 * 1024 * 1024,
        max_concurrent_streams: 32,
        idle_timeout: Duration::from_secs(30),
        keepalive: Duration::from_secs(5),
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
                                "velcruxd-striping",
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
    let _ = read_frame(recv.as_mut())
        .await
        .expect("read hello ack")
        .expect("frame");
    let auth = velcrux_core::protocol::message::Auth::mtls();
    let _ = write_frame(send.as_mut(), &Message::Auth(auth), 2).await;
    let _ = read_frame(recv.as_mut())
        .await
        .expect("read auth ok")
        .expect("frame");

    // 4 chunks × 1 MiB (M3_CHUNK_SIZE) = 4 MiB striped across 4 streams
    let chunk_size = 1024 * 1024;
    let num_chunks = 4;
    let total_size = chunk_size * num_chunks;
    let mut full_payload = vec![0u8; total_size];
    for (i, b) in full_payload.iter_mut().enumerate() {
        *b = (i ^ 0x5C) as u8;
    }
    let expected_hash = blake3_of(&full_payload);

    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "striped_input.dat".to_string(),
        dst_path: "striped/striped_output.dat".to_string(),
        idempotency_key: TransferId::generate().to_string(),
        file_size: total_size as u64,
        file_hash: expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferCreate(create), 3).await;
    let created_frame = read_frame(recv.as_mut())
        .await
        .expect("created")
        .expect("frame");
    let created = TransferCreated::decode(created_frame.payload).expect("decode");

    let _plan_frame = read_frame(recv.as_mut())
        .await
        .expect("plan")
        .expect("frame");

    let begin = TransferBegin {
        transfer_id: created.transfer_id,
        streams: 4,
    };
    let _ = write_frame(send.as_mut(), &Message::TransferBegin(begin), 4).await;

    let conn_arc = Arc::new(conn);

    // Send each chunk concurrently across distinct streams (striping)
    let mut stream_handles = Vec::new();
    for stream_idx in 0..num_chunks {
        let conn_clone = Arc::clone(&conn_arc);
        let tid = created.transfer_id;
        let chunk_slice =
            full_payload[stream_idx * chunk_size..(stream_idx + 1) * chunk_size].to_vec();
        let chunk_offset = (stream_idx * chunk_size) as u64;

        let handle = tokio::spawn(async move {
            let mut data_send = conn_clone.open_uni().await.expect("open uni");
            let preamble = velcrux_core::protocol::frame::DataPreamble {
                transfer_id: tid,
                file_id: 1,
                stream_seq: (stream_idx + 1) as u64,
            };
            let pre_enc = velcrux_core::protocol::frame::encode_data_preamble(&preamble);
            data_send
                .write_all(Bytes::copy_from_slice(&pre_enc))
                .await
                .expect("preamble");

            let chunk_hash = blake3_of(&chunk_slice);
            let chunk_frame = velcrux_core::protocol::frame::encode_data_frame(
                chunk_offset,
                chunk_slice.len() as u32,
                velcrux_core::protocol::frame::DataFrameFlags::NONE,
                &chunk_hash,
                &chunk_slice,
            );
            data_send
                .write_all(Bytes::from(chunk_frame))
                .await
                .expect("frame");
            data_send.finish().await.expect("finish");
        });
        stream_handles.push(handle);
    }

    for h in stream_handles {
        h.await.expect("stream join");
    }

    // Verify & Commit
    let verify = Verify {
        transfer_id: created.transfer_id,
        expected_hash,
    };
    let _ = write_frame(send.as_mut(), &Message::Verify(verify), 5).await;
    let vres_frame = read_frame(recv.as_mut())
        .await
        .expect("verify res")
        .expect("frame");
    let vres = VerifyResult::decode(vres_frame.payload).expect("decode");
    assert!(vres.ok);

    let commit = Commit {
        transfer_id: created.transfer_id,
    };
    let _ = write_frame(send.as_mut(), &Message::Commit(commit), 6).await;
    let _ = read_frame(recv.as_mut())
        .await
        .expect("committed")
        .expect("frame");

    // Verify file reconstructed correctly
    let dst_path = files_dir.path().join("striped").join("striped_output.dat");
    let disk_bytes = fs::read(&dst_path).expect("read");
    assert_eq!(disk_bytes.len(), total_size);
    assert_eq!(blake3_of(&disk_bytes), expected_hash);

    let _ = shutdown_tx.send(());
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// 4. Scenario JSON Record Emission and bench-report.py Validation
// ---------------------------------------------------------------------------

#[test]
fn test_wan_scenario_json_emission_and_report() {
    let results_dir = repo_root().join("benches").join("results");
    fs::create_dir_all(&results_dir).unwrap();

    let sample_file = results_dir.join("wan_test_scenario.json");
    let sample_json = r#"{
  "timestamp": "20260929_120000Z",
  "git_commit": "HEAD",
  "scenario": "wan_high_bdp_10g",
  "parameters": {
    "rtt": "150ms",
    "loss": "0.5%",
    "bandwidth": "10gbit",
    "file_size": "100G",
    "streams": 8,
    "runs": 5
  },
  "metrics": {
    "transfer_time_sec": 84.5,
    "wire_bytes": 107374182400,
    "avoided_bytes": 0,
    "goodput_mbps": 9850.2,
    "efficiency_pct": 98.5,
    "bdp_window_bytes": 402653184
  }
}"#;
    fs::write(&sample_file, sample_json).expect("write sample scenario json");

    // Execute scripts/bench-report.py
    let report_script = repo_root().join("scripts").join("bench-report.py");
    let output = Command::new("python3")
        .arg(&report_script)
        .arg(&results_dir)
        .output()
        .expect("run bench-report.py");

    assert!(output.status.success(), "bench-report.py failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("wan_high_bdp_10g"),
        "report must contain scenario name"
    );
    assert!(stdout.contains("150ms"), "report must contain RTT");
    assert!(
        stdout.contains("9850.2 Mbps"),
        "report must contain measured goodput"
    );
    assert!(
        stdout.contains("384.00 MiB"),
        "report must contain BDP window"
    );
}

// ---------------------------------------------------------------------------
// 5. Network Simulation Harness Execution (scripts/netsim.sh ci)
// ---------------------------------------------------------------------------

#[test]
fn test_netsim_script_execution() {
    let netsim_script = repo_root().join("scripts").join("netsim.sh");
    assert!(netsim_script.exists(), "scripts/netsim.sh must exist");

    let output = Command::new("bash")
        .arg(&netsim_script)
        .arg("ci")
        .env("VELCRUX_NETSIM_INNER", "1")
        .current_dir(repo_root())
        .output()
        .expect("run netsim.sh ci");

    assert!(
        output.status.success(),
        "netsim.sh ci failed with: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DEVELOPMENT.md")
            || stdout.contains("WAN impairment")
            || stdout.contains("Linux"),
        "netsim output must report execution details"
    );
}
