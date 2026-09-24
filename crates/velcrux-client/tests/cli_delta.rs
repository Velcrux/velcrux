//! Integration test for Wire-Level Remote Delta Transfers (Option B).
//!
//! Verifies:
//! - Delta upload of a modified file transfers only the modified chunks (< 10% wire transfer for 1% modification).
//! - Delta download of a modified file transfers only the modified chunks.
//! - Fast-skip on uploading identical files (0 bytes transferred).
//! - Fast-skip on downloading identical files (0 bytes transferred).

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
    dn.push(DnType::CommonName, "velcrux-delta-ca");
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
    let client_cert_pem = client_cert.pem();
    let client_key_pem = client_key_pair.serialize_pem();
    let client_cert_path = dir.join("client.crt");
    let client_key_path = dir.join("client.key");
    std::fs::write(&client_cert_path, &client_cert_pem).unwrap();
    std::fs::write(&client_key_path, &client_key_pem).unwrap();

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
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn start_server(
    pki: &TestPki,
    storage_root: PathBuf,
    staging_root: PathBuf,
    state_store: Arc<SqliteStateStore>,
    grants_path: PathBuf,
) -> (ServerHandle, Arc<LocalFilesystemBackend>) {
    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();
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

    (
        ServerHandle {
            addr,
            shutdown: Some(shutdown_tx),
        },
        backend,
    )
}

fn write_grants(path: &Path) {
    let grants = r#"
[[grant]]
identity = "testclient"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
"#;
    std::fs::write(path, grants).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_delta_upload_transfers_only_delta() {
    let temp = tempdir().unwrap();
    let pki_dir = temp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki = generate_test_pki(&pki_dir);

    let storage_root = temp.path().join("storage");
    let staging_root = temp.path().join("staging");
    let state_db = temp.path().join("server-state.db");
    let client_db = temp.path().join("client-state.db");
    let grants_path = temp.path().join("grants.toml");
    write_grants(&grants_path);

    let state_store = Arc::new(SqliteStateStore::new(&state_db).unwrap());
    let (server, _backend) = start_server(
        &pki,
        storage_root.clone(),
        staging_root,
        state_store,
        grants_path,
    )
    .await;

    // Create a 2 MiB file
    let total_size = 2 * 1024 * 1024;
    let mut initial_data = vec![0xABu8; total_size];
    // Fill with pattern
    for (i, b) in initial_data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let local_file = temp.path().join("local.bin");
    std::fs::write(&local_file, &initial_data).unwrap();

    let bin = velcrux_bin();

    // 1. Initial full upload
    let url = format!("velcrux://{}/file.bin", server.addr);
    let out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("--json")
        .arg("upload")
        .arg(&local_file)
        .arg(&url)
        .output()
        .expect("initial upload");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(val["status"], "committed");
    assert_eq!(val["file_size"], total_size);

    // Verify remote file matches
    let remote_path = storage_root.join("file.bin");
    let remote_data = std::fs::read(&remote_path).unwrap();
    assert_eq!(remote_data, initial_data);

    // 2. Modify 64 KiB at offset 512 KiB in local file
    let mut modified_data = initial_data.clone();
    for i in 512 * 1024..(512 + 64) * 1024 {
        modified_data[i] = 0xFE;
    }
    std::fs::write(&local_file, &modified_data).unwrap();

    // 3. Upload modified file (Delta Upload)
    let out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("--json")
        .arg("upload")
        .arg(&local_file)
        .arg(&url)
        .output()
        .expect("delta upload");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(val["status"], "committed");
    // Transferred bytes should be ~64 KiB (only modified chunk), not 2 MiB!
    let bytes_transferred = val["bytes_transferred"].as_u64().unwrap();
    assert!(
        bytes_transferred <= 128 * 1024,
        "Expected delta transfer of ~64 KiB, got {}",
        bytes_transferred
    );

    // Verify remote file now matches modified data exactly
    let remote_data = std::fs::read(&remote_path).unwrap();
    assert_eq!(remote_data, modified_data);

    // 4. Identical upload: should transfer 0 bytes (fast skip)
    let out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("--json")
        .arg("upload")
        .arg(&local_file)
        .arg(&url)
        .output()
        .expect("skip upload");

    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(val["status"], "committed");
    assert_eq!(val["bytes_transferred"], 0); // 0 bytes transferred!
}

#[tokio::test(flavor = "multi_thread")]
async fn test_delta_download_transfers_only_delta() {
    let temp = tempdir().unwrap();
    let pki_dir = temp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki = generate_test_pki(&pki_dir);

    let storage_root = temp.path().join("storage");
    let staging_root = temp.path().join("staging");
    let state_db = temp.path().join("server-state.db");
    let client_db = temp.path().join("client-state.db");
    let grants_path = temp.path().join("grants.toml");
    write_grants(&grants_path);

    let state_store = Arc::new(SqliteStateStore::new(&state_db).unwrap());
    let (server, _backend) = start_server(
        &pki,
        storage_root.clone(),
        staging_root,
        state_store,
        grants_path,
    )
    .await;

    // Create a 2 MiB file directly on server
    let total_size = 2 * 1024 * 1024;
    let mut server_data = vec![0x00u8; total_size];
    for (i, b) in server_data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let remote_file = storage_root.join("data.bin");
    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::write(&remote_file, &server_data).unwrap();

    // Prepare a local client file with 64 KiB difference at 256 KiB
    let mut local_data = server_data.clone();
    for i in 256 * 1024..(256 + 64) * 1024 {
        local_data[i] = 0x77;
    }
    let local_file = temp.path().join("downloaded.bin");
    std::fs::write(&local_file, &local_data).unwrap();

    let bin = velcrux_bin();
    let url = format!("velcrux://{}/data.bin", server.addr);

    // Delta download: client already has 31 out of 32 chunks matching!
    let out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("--json")
        .arg("download")
        .arg(&url)
        .arg(&local_file)
        .output()
        .expect("delta download");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(val["status"], "committed");
    let bytes_transferred = val["bytes_completed"].as_u64().unwrap();
    assert!(
        bytes_transferred <= 128 * 1024,
        "Expected delta transfer of ~64 KiB, got {}",
        bytes_transferred
    );

    // Verify local file now matches server file exactly
    let downloaded_data = std::fs::read(&local_file).unwrap();
    assert_eq!(downloaded_data, server_data);

    // Fast-skip download: file is now identical locally
    let out = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db)
        .arg("--json")
        .arg("download")
        .arg(&url)
        .arg(&local_file)
        .output()
        .expect("skip download");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(val["status"], "committed");
    assert_eq!(val["bytes_completed"], 0);
}
