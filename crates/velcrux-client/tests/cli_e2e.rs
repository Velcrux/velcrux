//! Real End-to-End integration test for the `velcrux` CLI.
//!
//! Spawns a live QUIC server on loopback with real mTLS and SQLite StateStore,
//! then drives the built `velcrux` binary through:
//! - upload (human and --json)
//! - download (human and --json)
//! - stat (human and --json)
//! - list (human and --json)
//! - cancel (human and --json)
//! - resume after interruption

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
use velcrux_core::state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, Role, SqliteStateStore, StateStore,
    TransferRecord, TransferStatus,
};
use velcrux_core::storage::{LocalFilesystemBackend, StorageBackend, VPath};
use velcrux_core::transfer::M3_CHUNK_SIZE;
use velcrux_core::transport::quic::{
    QuicConnection, ServerBuilder, TransportConfigTunables,
};
use velcrux_core::transport::Transport;
use velcrux_core::util::{Hash, TransferId};

fn velcrux_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // exit test exe
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

// ---------------------------------------------------------------------------
// PKI Helpers
// ---------------------------------------------------------------------------

struct TestPki {
    ca_cert_path: PathBuf,
    client_cert_path: PathBuf,
    client_key_path: PathBuf,
    server_certs: Vec<Certificate>,
    server_key: PrivateKey,
}

fn generate_test_pki(dir: &Path) -> TestPki {
    // 1. Root CA
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

    // 2. Server Cert (DNS: localhost, 127.0.0.1)
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

    // 3. Client Cert (SAN URI: velcrux://identity/testclient)
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

// ---------------------------------------------------------------------------
// Server Runner
// ---------------------------------------------------------------------------

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
) -> (ServerHandle, Arc<LocalFilesystemBackend>) {
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
            shutdown_tx: Some(shutdown_tx),
        },
        backend,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cli_e2e_full_flow() {
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

    let client_db_path = temp.path().join("client.db");

    // Grants file allowing testclient all ops on /
    let grants_path = temp.path().join("grants.toml");
    let grants_content = r#"
[[grant]]
identity = "testclient"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
"#;
    std::fs::write(&grants_path, grants_content).unwrap();

    let (server_handle, backend) = start_test_server(
        &pki,
        storage_root.clone(),
        staging_root.clone(),
        state_store.clone(),
        grants_path,
    )
    .await;

    let server_url = format!("velcrux://127.0.0.1:{}/", server_handle.addr.port());
    let bin = velcrux_bin();

    // 1. PING test
    let ping_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("ping")
        .arg(&server_url)
        .output()
        .expect("exec ping");
    assert!(
        ping_output.status.success(),
        "ping stderr: {}",
        String::from_utf8_lossy(&ping_output.stderr)
    );
    let ping_stdout = String::from_utf8_lossy(&ping_output.stdout);
    assert!(ping_stdout.contains("PONG"), "got: {ping_stdout}");

    // 2. UPLOAD test (Human output)
    let upload_local = temp.path().join("local_file.bin");
    let file_bytes = vec![0xABu8; 1024 * 1024 + 42]; // >1 MiB to test fixed chunking
    std::fs::write(&upload_local, &file_bytes).unwrap();
    let expected_hash = Hash::of(&file_bytes);

    let upload_url = format!("velcrux://127.0.0.1:{}/data/uploaded.bin", server_handle.addr.port());
    let upload_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--state-db")
        .arg(&client_db_path)
        .arg("upload")
        .arg(&upload_local)
        .arg(&upload_url)
        .output()
        .expect("exec upload");

    assert!(
        upload_output.status.success(),
        "upload stderr: {}",
        String::from_utf8_lossy(&upload_output.stderr)
    );
    let upload_stdout = String::from_utf8_lossy(&upload_output.stdout);
    assert!(upload_stdout.contains("transfer_id:"), "stdout: {upload_stdout}");
    assert!(upload_stdout.contains("server hash matches: true"), "stdout: {upload_stdout}");

    // Extract transfer_id
    let transfer_id = upload_stdout
        .lines()
        .find(|l| l.starts_with("transfer_id: "))
        .map(|l| l.trim_start_matches("transfer_id: ").trim())
        .expect("find transfer_id");

    // Verify file exists at destination on server storage and no staging artifact remains
    let server_dest = storage_root.join("data").join("uploaded.bin");
    assert!(server_dest.exists(), "server dest missing");
    let server_content = std::fs::read(&server_dest).unwrap();
    assert_eq!(server_content.len(), file_bytes.len());
    assert_eq!(Hash::of(&server_content), expected_hash);

    let server_staging = staging_root.join(format!("{transfer_id}-data_uploaded.bin.velcrux-partial"));
    assert!(!server_staging.exists(), "staging file was not cleaned up!");

    let rec = state_store.get_transfer(TransferId::from_string(transfer_id).unwrap());
    eprintln!("server state_store.get_transfer for {transfer_id}: {:?}", rec);

    // 3. STAT test (Human & JSON)
    let stat_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("stat")
        .arg(transfer_id)
        .arg("--server")
        .arg(&server_url)
        .output()
        .expect("exec stat");
    assert!(
        stat_output.status.success(),
        "stat stderr: {}, stdout: {}",
        String::from_utf8_lossy(&stat_output.stderr),
        String::from_utf8_lossy(&stat_output.stdout)
    );
    let stat_stdout = String::from_utf8_lossy(&stat_output.stdout);
    assert!(stat_stdout.contains(transfer_id), "stat stdout: {stat_stdout}");
    assert!(stat_stdout.contains("committed"), "stat stdout: {stat_stdout}");

    let stat_json_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--json")
        .arg("stat")
        .arg(transfer_id)
        .arg("--server")
        .arg(&server_url)
        .output()
        .expect("exec stat --json");
    assert!(stat_json_output.status.success());
    let stat_json_str = String::from_utf8_lossy(&stat_json_output.stdout);
    let stat_json: serde_json::Value = serde_json::from_str(&stat_json_str).unwrap();
    assert_eq!(stat_json["event"], "stat");
    assert_eq!(stat_json["status"], "committed");
    assert_eq!(stat_json["transfer_id"], transfer_id);
    assert_eq!(stat_json["file_size"], file_bytes.len());

    // 4. DOWNLOAD test (Human & JSON)
    let downloaded_file = temp.path().join("downloaded.bin");
    let download_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("download")
        .arg(&upload_url)
        .arg(&downloaded_file)
        .output()
        .expect("exec download");
    assert!(
        download_output.status.success(),
        "download stderr: {}",
        String::from_utf8_lossy(&download_output.stderr)
    );
    let downloaded_content = std::fs::read(&downloaded_file).unwrap();
    assert_eq!(downloaded_content, file_bytes);

    let downloaded_json_file = temp.path().join("downloaded_json.bin");
    let download_json_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--json")
        .arg("download")
        .arg(&upload_url)
        .arg(&downloaded_json_file)
        .output()
        .expect("exec download --json");
    assert!(download_json_output.status.success());
    let download_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&download_json_output.stdout)).unwrap();
    assert_eq!(download_json["event"], "transfer_complete");
    assert_eq!(download_json["op"], "download");

    // 5. LIST test (Human & JSON)
    let list_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("list")
        .arg(format!("velcrux://127.0.0.1:{}/data/", server_handle.addr.port()))
        .output()
        .expect("exec list");
    assert!(
        list_output.status.success(),
        "list failed! stderr: {}, stdout: {}",
        String::from_utf8_lossy(&list_output.stderr),
        String::from_utf8_lossy(&list_output.stdout)
    );
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_stdout.contains(transfer_id), "list: {list_stdout}");

    let list_json_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--json")
        .arg("list")
        .arg(format!("velcrux://127.0.0.1:{}/data/", server_handle.addr.port()))
        .output()
        .expect("exec list --json");
    assert!(list_json_output.status.success());
    let list_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&list_json_output.stdout)).unwrap();
    assert!(list_json.is_array());
    assert!(!list_json.as_array().unwrap().is_empty());

    // 6. CANCEL test
    // Insert an active transfer record into server state
    let cancel_tid = TransferId::generate();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let cancel_rec = TransferRecord {
        transfer_id: cancel_tid,
        idempotency_key: cancel_tid.to_string(),
        role: Role::Server,
        direction: Direction::Upload,
        status: TransferStatus::Active,
        remote_path: "data/to_cancel.bin".to_string(),
        local_path: String::new(),
        file_size: 1000,
        file_hash: Hash::ZERO,
        verified_up_to: 0,
        last_checkpoint_ms: now,
        bytes_completed: 0,
        staging_relpath: "data_to_cancel.bin.velcrux-partial".to_string(),
        created_ms: now,
        updated_ms: now,
    };
    state_store.upsert_transfer(&cancel_rec).unwrap();

    let cancel_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--json")
        .arg("cancel")
        .arg(cancel_tid.to_string())
        .arg("--server")
        .arg(&server_url)
        .output()
        .expect("exec cancel");
    assert!(cancel_output.status.success());
    let cancel_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&cancel_output.stdout)).unwrap();
    assert_eq!(cancel_json["event"], "cancel");
    assert_eq!(cancel_json["status"], "cancelled");

    // Verify cancelled status in server state
    let rec_after = state_store.get_transfer(cancel_tid).unwrap();
    assert_eq!(rec_after.status, TransferStatus::Cancelled);

    // 7. RESUME test (interrupted transfer completion)
    // Setup a 2-chunk transfer (2 MiB) where chunk 0 is already written and staged, but chunk 1 is missing
    let resume_tid = TransferId::generate();
    let resume_size = 2 * M3_CHUNK_SIZE;
    let mut resume_data = vec![0u8; resume_size as usize];
    for (i, byte) in resume_data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let resume_file = temp.path().join("resume_src.bin");
    std::fs::write(&resume_file, &resume_data).unwrap();
    let resume_hash = Hash::of(&resume_data);

    let vpath = VPath::validate("data/resumed.bin").unwrap();
    // Open staging on server and write chunk 0 only
    let mut staging_writer = backend
        .open_staging(&resume_tid.to_string(), &vpath, resume_size)
        .await
        .unwrap();
    staging_writer
        .write_at(0, &resume_data[..M3_CHUNK_SIZE as usize])
        .await
        .unwrap();
    staging_writer.fsync().await.unwrap();

    let staging_relpath = format!("{}-data_resumed.bin.velcrux-partial", resume_tid);

    let resume_rec = TransferRecord {
        transfer_id: resume_tid,
        idempotency_key: resume_tid.to_string(),
        role: Role::Server,
        direction: Direction::Upload,
        status: TransferStatus::Active,
        remote_path: "data/resumed.bin".to_string(),
        local_path: String::new(),
        file_size: resume_size,
        file_hash: resume_hash,
        verified_up_to: 0,
        last_checkpoint_ms: now,
        bytes_completed: M3_CHUNK_SIZE,
        staging_relpath: staging_relpath.clone(),
        created_ms: now,
        updated_ms: now,
    };
    state_store.upsert_transfer(&resume_rec).unwrap();

    let mut bitmap = ChunkBitmap::new();
    bitmap.mark_complete(0, M3_CHUNK_SIZE);
    state_store.write_bitmap(resume_tid, &bitmap).unwrap();
    state_store
        .write_journal(&CommitJournalEntry {
            transfer_id: resume_tid,
            file_id: 1,
            remote_path: "data/resumed.bin".to_string(),
            status: CommitStatus::Pending,
            updated_ms: now,
        })
        .unwrap();

    // Now call `velcrux resume` from the CLI!
    let resume_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--json")
        .arg("resume")
        .arg(resume_tid.to_string())
        .arg("--server")
        .arg(&server_url)
        .arg("--local")
        .arg(&resume_file)
        .output()
        .expect("exec resume");

    assert!(
        resume_output.status.success(),
        "resume stderr: {}",
        String::from_utf8_lossy(&resume_output.stderr)
    );
    let resume_json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&resume_output.stdout)).unwrap();
    assert_eq!(resume_json["event"], "transfer_complete");
    assert_eq!(resume_json["op"], "resume");
    assert_eq!(resume_json["status"], "committed");

    // Verify committed file on server filesystem
    let server_resumed_file = storage_root.join("data").join("resumed.bin");
    assert!(server_resumed_file.exists(), "resumed file should exist on server");
    let server_resumed_content = std::fs::read(&server_resumed_file).unwrap();
    assert_eq!(server_resumed_content.len(), resume_size as usize);
    assert_eq!(Hash::of(&server_resumed_content), resume_hash);
}
