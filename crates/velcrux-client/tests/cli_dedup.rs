//! End-to-End integration test for Option D:
//! Network Chunk Store Deduplication over QUIC (--dedup and .velcrux-chunks integration).

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
use velcrux_core::storage::{LocalChunkStore, LocalFilesystemBackend};
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

async fn start_test_server_with_chunk_store(
    pki: &TestPki,
    storage_root: PathBuf,
    staging_root: PathBuf,
    state_store: Arc<SqliteStateStore>,
    grants_path: PathBuf,
    chunk_store: Arc<LocalChunkStore>,
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
        .set(Capability::Blake3)
        .set(Capability::DedupChunkStore);

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
                    )
                    .with_chunk_store(Some(Arc::clone(&chunk_store)));
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
async fn test_network_chunk_store_deduplication() {
    let temp = tempdir().unwrap();
    let pki_dir = temp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki = generate_test_pki(&pki_dir);

    let storage_root = temp.path().join("server_storage");
    let staging_root = temp.path().join("server_staging");
    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let server_db_path = temp.path().join("server.db");
    let state_store = Arc::new(SqliteStateStore::new(&server_db_path).unwrap());

    let server_chunk_store_path = temp.path().join("server_chunks");
    let server_chunk_store = Arc::new(
        LocalChunkStore::new(&server_chunk_store_path)
            .await
            .unwrap(),
    );

    let grants_path = temp.path().join("grants.toml");
    let grants_content = r#"
[[grant]]
identity = "testclient"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
"#;
    std::fs::write(&grants_path, grants_content).unwrap();

    let server = start_test_server_with_chunk_store(
        &pki,
        storage_root.clone(),
        staging_root,
        state_store,
        grants_path,
        server_chunk_store,
    )
    .await;

    let bin = velcrux_bin();

    // 1. Create File A: 8 chunks of 64 KiB = 512 KiB total.
    let file_a_path = temp.path().join("file_a.bin");
    let mut file_a_data = vec![0u8; 512 * 1024];
    for (i, byte) in file_a_data.iter_mut().enumerate() {
        *byte = ((i / (64 * 1024)) as u8).wrapping_add(10);
    }
    std::fs::write(&file_a_path, &file_a_data).unwrap();
    let hash_a = velcrux_core::sync::compute_file_hash(&file_a_path).unwrap();

    // 2. Upload File A with --dedup
    let status = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--sni")
        .arg("localhost")
        .arg("--dedup")
        .arg("upload")
        .arg(&file_a_path)
        .arg(format!("velcrux://{}/file_a.bin", server.addr))
        .status()
        .expect("upload file A");
    assert!(status.success(), "upload file A with --dedup succeeded");

    let server_file_a = storage_root.join("file_a.bin");
    assert!(server_file_a.exists(), "server has file A");
    assert_eq!(
        velcrux_core::sync::compute_file_hash(&server_file_a).unwrap(),
        hash_a
    );

    // 3. Create File B: shares 6 out of 8 chunks (75%) with File A, modifying chunks 2 and 5.
    let file_b_path = temp.path().join("file_b.bin");
    let mut file_b_data = file_a_data.clone();
    file_b_data[2 * 64 * 1024..3 * 64 * 1024].fill(0xAA);
    file_b_data[5 * 64 * 1024..6 * 64 * 1024].fill(0xBB);
    std::fs::write(&file_b_path, &file_b_data).unwrap();
    let hash_b = velcrux_core::sync::compute_file_hash(&file_b_path).unwrap();

    // 4. Upload File B with --dedup and --json
    let output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--sni")
        .arg("localhost")
        .arg("--dedup")
        .arg("--json")
        .arg("upload")
        .arg(&file_b_path)
        .arg(format!("velcrux://{}/file_b.bin", server.addr))
        .output()
        .expect("upload file B");
    assert!(
        output.status.success(),
        "upload file B with --dedup succeeded"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "committed");
    assert_eq!(json["file_hash"], hash_b.to_string());
    // Only 2 chunks (128 KiB) transferred over wire; 6 chunks (384 KiB) reused from chunk store!
    let bytes_transferred = json["bytes_completed"].as_u64().unwrap();
    assert_eq!(
        bytes_transferred,
        128 * 1024,
        "only non-duplicate chunks transferred over wire"
    );

    let server_file_b = storage_root.join("file_b.bin");
    assert!(server_file_b.exists(), "server has file B");
    assert_eq!(
        velcrux_core::sync::compute_file_hash(&server_file_b).unwrap(),
        hash_b
    );

    // 5. Download File B into a new directory using client chunk store
    let client_chunk_store_path = temp.path().join("client_chunks");
    let client_download_path = temp.path().join("downloaded_file_b.bin");
    let status = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--sni")
        .arg("localhost")
        .arg("--dedup")
        .arg("--chunk-store")
        .arg(&client_chunk_store_path)
        .arg("download")
        .arg(format!("velcrux://{}/file_b.bin", server.addr))
        .arg(&client_download_path)
        .status()
        .expect("download file B");
    assert!(status.success(), "download file B succeeded");
    assert!(client_download_path.exists());
    assert_eq!(
        velcrux_core::sync::compute_file_hash(&client_download_path).unwrap(),
        hash_b
    );
}
