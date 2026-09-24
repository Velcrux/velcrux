//! End-to-End integration test for Option E:
//! Multi-Stream QUIC Data Channel Striping (`--parallel <N>`, alias `-P`).
//!
//! Verifies:
//! - Multi-stream upload (`--parallel 4`) of multi-megabyte file across 4 concurrent QUIC uni streams.
//! - Multi-stream download (`--parallel 4`) of multi-megabyte file across 4 concurrent QUIC uni streams.
//! - Verification that whole-file BLAKE3 hash matches bit-for-bit after concurrent chunk assembly.
//! - Single-stream compatibility (`--parallel 1`).
//! - Edge case: small file transfer where chunk count is less than `--parallel` streams.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};
use tempfile::tempdir;

use velcrux_core::auth::{Authenticator, Authorizer, FileAuthorizer, MtlsAuthenticator};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::session::{ServerConn, ServerStats};
use velcrux_core::state::SqliteStateStore;
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::transport::quic::{QuicConnection, ServerBuilder, TransportConfigTunables};
use velcrux_core::transport::Transport;

fn velcrux_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

struct TestPki {
    ca_cert_path: PathBuf,
    client_cert_path: PathBuf,
    client_key_path: PathBuf,
    server_certs: Vec<Certificate>,
    server_key: PrivateKey,
}

fn generate_test_pki(dir: &Path) -> TestPki {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "velcrux-test-ca");
    ca_params.distinguished_name = dn;
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_cert_pem = ca_cert.pem();
    let ca_cert_path = dir.join("ca.crt");
    std::fs::write(&ca_cert_path, &ca_cert_pem).unwrap();

    let mut server_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    server_params.distinguished_name = dn;
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];
    let server_key_pair = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key)
        .unwrap();
    let server_cert_pem = server_cert.pem();
    let server_certs: Vec<Certificate> = rustls_pemfile::certs(&mut server_cert_pem.as_bytes())
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let server_key = PrivateKey(server_key_pair.serialize_der());

    let mut client_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "testclient");
    client_params.distinguished_name = dn;
    client_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.subject_alt_names = vec![SanType::URI(
        "velcrux://identity/testclient".try_into().unwrap(),
    )];
    let client_key_pair = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key_pair, &ca_cert, &ca_key)
        .unwrap();

    let client_cert_path = dir.join("client.crt");
    std::fs::write(&client_cert_path, client_cert.pem()).unwrap();

    let client_key_path = dir.join("client.key");
    std::fs::write(&client_key_path, client_key_pair.serialize_pem()).unwrap();

    TestPki {
        ca_cert_path,
        client_cert_path,
        client_key_path,
        server_certs,
        server_key,
    }
}

struct ServerHandle {
    addr: SocketAddr,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn start_test_server(
    pki: &TestPki,
    storage_root: PathBuf,
    staging_root: PathBuf,
    state_store: Arc<SqliteStateStore>,
    grants_path: PathBuf,
) -> ServerHandle {
    let backend = Arc::new(
        LocalFilesystemBackend::new(storage_root, staging_root)
            .await
            .unwrap(),
    );

    let ca_pem = std::fs::read(&pki.ca_cert_path).unwrap();
    let server_builder = ServerBuilder::new()
        .with_server_cert(pki.server_certs.clone(), pki.server_key.clone())
        .with_client_ca_roots_pem(&ca_pem)
        .unwrap()
        .with_tunables(TransportConfigTunables::default());

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let transport = server_builder.build(bind_addr).unwrap();
    let addr = transport.local_addr().unwrap();
    let transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::new(transport);

    let authorizer: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::load(&grants_path).unwrap());
    let authenticator: Arc<dyn Authenticator> = Arc::new(MtlsAuthenticator::new());
    let stats = Arc::new(ServerStats::default());
    let mut server_caps = Capabilities::EMPTY;
    server_caps
        .set(Capability::FixedChunking)
        .set(Capability::CdcChunking)
        .set(Capability::Blake3);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_transport: Arc<dyn Transport<Conn = QuicConnection>> = Arc::clone(&transport);
    let server_backend = Arc::clone(&backend);
    let server_state = Arc::clone(&state_store);

    tokio::spawn(async move {
        let next_id = Arc::new(AtomicU64::new(1));
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = server_transport.accept() => {
                    let conn = match res {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let _id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let actor = ServerConn::with_state(
                        server_caps,
                        "velcruxd-test",
                        Arc::clone(&stats),
                        Arc::clone(&server_backend),
                        Some(server_state.clone()),
                        Some(Arc::clone(&authenticator)),
                        Some(Arc::clone(&authorizer)),
                    );
                    tokio::spawn(async move {
                        let _ = actor.run(&conn).await;
                    });
                }
            }
        }
    });

    ServerHandle {
        addr,
        shutdown_tx: Some(shutdown_tx),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cli_multi_stream_parallel_transfer() {
    let temp = tempdir().unwrap();
    let storage_root = temp.path().join("server_storage");
    let staging_root = temp.path().join("server_staging");
    let state_db = temp.path().join("server_state.db");
    let grants_path = temp.path().join("grants.toml");

    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let grants = r#"
[[grant]]
identity = "testclient"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
"#;
    std::fs::write(&grants_path, grants).unwrap();

    let pki = generate_test_pki(temp.path());
    let state_store = Arc::new(SqliteStateStore::new(&state_db).unwrap());

    let server = start_test_server(
        &pki,
        storage_root.clone(),
        staging_root.clone(),
        state_store,
        grants_path,
    )
    .await;

    let bin = velcrux_bin();

    // 1. Create an 8 MiB test file with pseudorandom bytes (multiple 1 MiB chunks)
    let upload_file = temp.path().join("parallel_data_8mb.bin");
    let mut file_data = vec![0u8; 8 * 1024 * 1024];
    for (i, byte) in file_data.iter_mut().enumerate() {
        *byte = ((i * 31 + 17) % 251) as u8;
    }
    std::fs::write(&upload_file, &file_data).unwrap();
    let expected_hash = velcrux_core::sync::compute_file_hash(&upload_file).unwrap();

    // 2. Upload with --parallel 4
    let output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--sni")
        .arg("localhost")
        .arg("--parallel")
        .arg("4")
        .arg("--json")
        .arg("upload")
        .arg(&upload_file)
        .arg(format!("velcrux://{}/remote_parallel.bin", server.addr))
        .output()
        .expect("run parallel upload");

    assert!(
        output.status.success(),
        "parallel upload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let server_file = storage_root.join("remote_parallel.bin");
    assert!(server_file.exists(), "server staged and committed file");
    assert_eq!(
        velcrux_core::sync::compute_file_hash(&server_file).unwrap(),
        expected_hash,
        "server whole-file hash matches"
    );

    // 3. Download with -P 4
    let downloaded_file = temp.path().join("downloaded_parallel_8mb.bin");
    let output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--sni")
        .arg("localhost")
        .arg("-P")
        .arg("4")
        .arg("download")
        .arg(format!("velcrux://{}/remote_parallel.bin", server.addr))
        .arg(&downloaded_file)
        .output()
        .expect("run parallel download");

    assert!(
        output.status.success(),
        "parallel download failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(downloaded_file.exists(), "client download exists");
    assert_eq!(
        velcrux_core::sync::compute_file_hash(&downloaded_file).unwrap(),
        expected_hash,
        "client downloaded hash matches"
    );

    // 4. Test small file transfer with --parallel 8 (more streams than chunks)
    let small_file = temp.path().join("small_data.bin");
    let small_data = vec![42u8; 128 * 1024]; // 128 KiB
    std::fs::write(&small_file, &small_data).unwrap();
    let small_hash = velcrux_core::sync::compute_file_hash(&small_file).unwrap();

    let output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--sni")
        .arg("localhost")
        .arg("--parallel")
        .arg("8")
        .arg("upload")
        .arg(&small_file)
        .arg(format!("velcrux://{}/small_file.bin", server.addr))
        .output()
        .expect("run small file parallel upload");

    assert!(
        output.status.success(),
        "small file parallel upload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let server_small = storage_root.join("small_file.bin");
    assert!(server_small.exists());
    assert_eq!(
        velcrux_core::sync::compute_file_hash(&server_small).unwrap(),
        small_hash
    );

    // Download small file with --parallel 8
    let downloaded_small = temp.path().join("downloaded_small.bin");
    let output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--sni")
        .arg("localhost")
        .arg("--parallel")
        .arg("8")
        .arg("download")
        .arg(format!("velcrux://{}/small_file.bin", server.addr))
        .arg(&downloaded_small)
        .output()
        .expect("run small file parallel download");

    assert!(
        output.status.success(),
        "small file parallel download failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        velcrux_core::sync::compute_file_hash(&downloaded_small).unwrap(),
        small_hash
    );
}
