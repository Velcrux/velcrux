//! End-to-End integration test for Option F:
//! Bandwidth Throttle & Rate Limiting (`--rate-limit <rate>`, alias `-R`).
//!
//! Verifies:
//! - Throttled upload (`--rate-limit 500K` / `-R 500K`) enforces expected duration lower-bound.
//! - Throttled download (`--rate-limit 500K`) enforces expected duration lower-bound.
//! - Content integrity: BLAKE3 hash matches bit-for-bit after throttled transfer.
//! - Multi-stream concurrency striping combined with rate limiting (`-P 4 -R 1M`).
//! - Error handling on malformed rate limit inputs.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

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
use velcrux_core::Hash;

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
async fn test_cli_bandwidth_rate_limiting() {
    let bin = velcrux_bin();
    assert!(bin.exists(), "velcrux binary not found at {:?}", bin);

    let temp = tempdir().unwrap();
    let pki = generate_test_pki(temp.path());

    let storage_root = temp.path().join("server_storage");
    let staging_root = temp.path().join("server_staging");
    let server_db = temp.path().join("server_state.db");
    let client_db = temp.path().join("client_state.db");
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

    let state_store = Arc::new(SqliteStateStore::new(&server_db).unwrap());
    let server = start_test_server(
        &pki,
        storage_root.clone(),
        staging_root,
        state_store,
        grants_path,
    )
    .await;
    let server_addr = server.addr;

    // Create a 2 MiB test file with deterministic payload.
    let file_size: usize = 2 * 1024 * 1024;
    let mut src_bytes = Vec::with_capacity(file_size);
    for i in 0..file_size {
        src_bytes.push(((i * 31 + 17) & 0xFF) as u8);
    }
    let src_hash = Hash::of(&src_bytes);

    let client_data_dir = temp.path().join("client_data");
    std::fs::create_dir_all(&client_data_dir).unwrap();
    let upload_file = client_data_dir.join("throttled_upload.bin");
    std::fs::write(&upload_file, &src_bytes).unwrap();

    // 1. Throttled upload at 500 KB/s
    // Transfer of 2 MiB at 500 KB/s takes >= 1.5 seconds.
    let target_url = format!(
        "velcrux://{}:{}/throttled_upload.bin",
        server_addr.ip(),
        server_addr.port()
    );
    let t0 = Instant::now();
    let upload_out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("--rate-limit")
        .arg("500K")
        .arg("upload")
        .arg(&upload_file)
        .arg(&target_url)
        .output()
        .expect("failed to execute velcrux upload");

    let upload_elapsed = t0.elapsed();
    let stdout = String::from_utf8_lossy(&upload_out.stdout);
    let stderr = String::from_utf8_lossy(&upload_out.stderr);
    assert!(
        upload_out.status.success(),
        "Upload failed!\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        upload_elapsed >= std::time::Duration::from_millis(1500),
        "Upload completed too fast! Expected >= 1500ms, elapsed: {:?}",
        upload_elapsed
    );

    // Verify bit-for-bit server file match
    let uploaded_server_file = storage_root.join("throttled_upload.bin");
    assert!(uploaded_server_file.exists());
    let server_bytes = std::fs::read(&uploaded_server_file).unwrap();
    assert_eq!(server_bytes.len(), file_size);
    assert_eq!(Hash::of(&server_bytes), src_hash);

    // 2. Throttled download at 500 KB/s
    let download_file = client_data_dir.join("throttled_download.bin");
    let t1 = Instant::now();
    let download_out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("-R")
        .arg("500K")
        .arg("download")
        .arg(&target_url)
        .arg(&download_file)
        .output()
        .expect("failed to execute velcrux download");

    let download_elapsed = t1.elapsed();
    let dl_stdout = String::from_utf8_lossy(&download_out.stdout);
    let dl_stderr = String::from_utf8_lossy(&download_out.stderr);
    assert!(
        download_out.status.success(),
        "Download failed!\nstdout: {}\nstderr: {}",
        dl_stdout,
        dl_stderr
    );
    assert!(
        download_elapsed >= std::time::Duration::from_millis(1500),
        "Download completed too fast! Expected >= 1500ms, elapsed: {:?}",
        download_elapsed
    );

    let downloaded_bytes = std::fs::read(&download_file).unwrap();
    assert_eq!(downloaded_bytes.len(), file_size);
    assert_eq!(Hash::of(&downloaded_bytes), src_hash);

    // 3. Multi-stream combined with rate limiting (-P 4 -R 1M)
    let multi_url = format!(
        "velcrux://{}:{}/multi_throttled.bin",
        server_addr.ip(),
        server_addr.port()
    );
    let t2 = Instant::now();
    let multi_out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("-P")
        .arg("4")
        .arg("-R")
        .arg("1M")
        .arg("upload")
        .arg(&upload_file)
        .arg(&multi_url)
        .output()
        .expect("failed to execute multi-stream throttled upload");

    let multi_elapsed = t2.elapsed();
    assert!(multi_out.status.success());
    assert!(
        multi_elapsed >= std::time::Duration::from_millis(800),
        "Multi-stream throttled upload completed too fast! Expected >= 800ms, elapsed: {:?}",
        multi_elapsed
    );
    let multi_server_bytes = std::fs::read(storage_root.join("multi_throttled.bin")).unwrap();
    assert_eq!(Hash::of(&multi_server_bytes), src_hash);

    // 4. Invalid rate limit syntax rejection
    let invalid_out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--rate-limit")
        .arg("invalid_rate")
        .arg("upload")
        .arg(&upload_file)
        .arg(&target_url)
        .output()
        .expect("failed to execute invalid rate limit upload");

    assert!(!invalid_out.status.success());
    let invalid_err = String::from_utf8_lossy(&invalid_out.stderr);
    assert!(invalid_err.contains("invalid --rate-limit"));
}
