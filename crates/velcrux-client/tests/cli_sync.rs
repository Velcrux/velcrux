//! Integration tests for `velcrux sync` CLI subcommand (`REQUIREMENTS.md` §58–§60).

use std::process::Command;
use tempfile::tempdir;

fn velcrux_bin() -> std::path::PathBuf {
    // Locate the built `velcrux` binary in target/debug
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // exit test exe
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_cli_sync_dry_run() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // 1. Unchanged file
    std::fs::write(src.join("unchanged.txt"), b"unchanged data").unwrap();
    std::fs::write(dst.join("unchanged.txt"), b"unchanged data").unwrap();

    // 2. Modified file
    std::fs::write(src.join("modified.txt"), b"new modified version").unwrap();
    std::fs::write(dst.join("modified.txt"), b"old version").unwrap();

    // 3. Added file
    std::fs::write(src.join("added.txt"), b"added content").unwrap();

    // 4. Extraneous file on destination
    std::fs::write(dst.join("orphan.txt"), b"orphan content").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--dry-run")
        .output()
        .expect("failed to execute velcrux sync --dry-run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("--- CLI Dry-Run Output ---\n{stdout}");

    // Verify format matches REQUIREMENTS.md §58
    assert!(stdout.contains("Files unchanged:"));
    assert!(stdout.contains("Files modified:"));
    assert!(stdout.contains("Files added:"));
    assert!(stdout.contains("Files deleted:"));
    assert!(stdout.contains("Data already present:"));
    assert!(stdout.contains("Data to transfer:"));
    assert!(stdout.contains("Estimated reduction:"));

    // Verify destination was NOT modified
    assert!(!dst.join("added.txt").exists());
    assert_eq!(
        std::fs::read(dst.join("modified.txt")).unwrap(),
        b"old version"
    );
    assert!(dst.join("orphan.txt").exists());
}

#[test]
fn test_cli_sync_full_execute_and_delete_modes() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("file1.txt"), b"file 1 content").unwrap();
    std::fs::write(src.join("file2.txt"), b"file 2 content").unwrap();
    std::fs::write(dst.join("orphan.txt"), b"orphan file").unwrap();

    // 1. Run default sync (no delete)
    let output1 = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux sync");

    assert!(output1.status.success());
    assert_eq!(
        std::fs::read(dst.join("file1.txt")).unwrap(),
        b"file 1 content"
    );
    assert_eq!(
        std::fs::read(dst.join("file2.txt")).unwrap(),
        b"file 2 content"
    );
    assert!(
        dst.join("orphan.txt").exists(),
        "orphan.txt must be preserved under default DeleteMode::None"
    );

    // 2. Run sync with --delete-after
    let output2 = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--delete-after")
        .output()
        .expect("failed to execute velcrux sync --delete-after");

    assert!(output2.status.success());
    assert_eq!(
        std::fs::read(dst.join("file1.txt")).unwrap(),
        b"file 1 content"
    );
    assert_eq!(
        std::fs::read(dst.join("file2.txt")).unwrap(),
        b"file 2 content"
    );
    assert!(
        !dst.join("orphan.txt").exists(),
        "orphan.txt must be deleted under --delete-after"
    );
}

#[test]
fn test_cli_sync_cdc_and_dedup() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    let chunk_store = temp.path().join("chunk_store");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("payload.dat"), b"dedup test payload data").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--cdc")
        .arg("--dedup")
        .arg("--chunk-store")
        .arg(chunk_store.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux sync --cdc --dedup");

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dst.join("payload.dat")).unwrap(),
        b"dedup test payload data"
    );
}

// ---------------------------------------------------------------------------
// Network Directory Sync Tests (Option A)
// ---------------------------------------------------------------------------

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{Certificate, PrivateKey};

use velcrux_core::auth::{Authenticator, Authorizer, FileAuthorizer, MtlsAuthenticator};
use velcrux_core::protocol::capabilities::{Capabilities, Capability};
use velcrux_core::session::{ServerConn, ServerStats};
use velcrux_core::state::SqliteStateStore;
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_core::transport::quic::{QuicConnection, ServerBuilder, TransportConfigTunables};
use velcrux_core::transport::Transport;

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
async fn test_cli_network_sync_dry_run_and_upload() {
    let temp = tempdir().unwrap();
    let pki_dir = temp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki = generate_test_pki(&pki_dir);

    let storage_root = temp.path().join("server_storage");
    let staging_root = temp.path().join("server_staging");
    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let server_db = temp.path().join("server.db");
    let server_state = Arc::new(SqliteStateStore::new(&server_db).unwrap());

    let grants_path = temp.path().join("grants.toml");
    let grants_content = r#"
[[grant]]
identity = "testclient"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
"#;
    std::fs::write(&grants_path, grants_content).unwrap();

    let (server_handle, _backend) = start_test_server(
        &pki,
        storage_root.clone(),
        staging_root.clone(),
        server_state,
        grants_path,
    )
    .await;

    // Remote destination directory on server
    let remote_dir = storage_root.join("syncdir");
    std::fs::create_dir_all(&remote_dir).unwrap();
    std::fs::write(remote_dir.join("unchanged.txt"), b"unchanged content").unwrap();
    std::fs::write(remote_dir.join("modified.txt"), b"old server content").unwrap();
    std::fs::write(remote_dir.join("orphan.txt"), b"orphan file content").unwrap();

    // Local source directory
    let local_src = temp.path().join("local_src");
    std::fs::create_dir_all(&local_src).unwrap();
    std::fs::write(local_src.join("unchanged.txt"), b"unchanged content").unwrap();
    std::fs::write(local_src.join("modified.txt"), b"new local content").unwrap();
    std::fs::write(local_src.join("added.txt"), b"new added content").unwrap();

    let remote_url = format!("velcrux://127.0.0.1:{}/syncdir", server_handle.addr.port());

    // 1. Dry run
    let dry_run_output = Command::new(velcrux_bin())
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("sync")
        .arg(local_src.to_str().unwrap())
        .arg(&remote_url)
        .arg("--dry-run")
        .output()
        .expect("exec network sync --dry-run");

    assert!(
        dry_run_output.status.success(),
        "dry-run failed: stderr: {}",
        String::from_utf8_lossy(&dry_run_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&dry_run_output.stdout);
    assert!(stdout.contains("Files unchanged:"));
    assert!(stdout.contains("Files modified:"));
    assert!(stdout.contains("Files added:"));
    assert!(stdout.contains("Files deleted:"));

    // Verify remote destination was NOT modified during dry run
    assert!(!remote_dir.join("added.txt").exists());
    assert_eq!(
        std::fs::read(remote_dir.join("modified.txt")).unwrap(),
        b"old server content"
    );
    assert!(remote_dir.join("orphan.txt").exists());

    // 2. Full network upload sync (no delete)
    let sync_output = Command::new(velcrux_bin())
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("sync")
        .arg(local_src.to_str().unwrap())
        .arg(&remote_url)
        .output()
        .expect("exec network sync");

    assert!(
        sync_output.status.success(),
        "network sync failed: stderr: {}",
        String::from_utf8_lossy(&sync_output.stderr)
    );

    // Verify files on remote destination
    assert_eq!(
        std::fs::read(remote_dir.join("unchanged.txt")).unwrap(),
        b"unchanged content"
    );
    assert_eq!(
        std::fs::read(remote_dir.join("modified.txt")).unwrap(),
        b"new local content"
    );
    assert_eq!(
        std::fs::read(remote_dir.join("added.txt")).unwrap(),
        b"new added content"
    );
    assert!(
        remote_dir.join("orphan.txt").exists(),
        "orphan.txt must be preserved when --delete-after is omitted"
    );

    // 3. Network sync with --delete-after
    let delete_output = Command::new(velcrux_bin())
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("sync")
        .arg(local_src.to_str().unwrap())
        .arg(&remote_url)
        .arg("--delete-after")
        .output()
        .expect("exec network sync --delete-after");

    assert!(
        delete_output.status.success(),
        "network sync with delete failed: stderr: {}",
        String::from_utf8_lossy(&delete_output.stderr)
    );

    assert!(
        !remote_dir.join("orphan.txt").exists(),
        "orphan.txt must be deleted when --delete-after is specified"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cli_network_sync_download_and_json() {
    let temp = tempdir().unwrap();
    let pki_dir = temp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki = generate_test_pki(&pki_dir);

    let storage_root = temp.path().join("server_storage");
    let staging_root = temp.path().join("server_staging");
    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let server_db = temp.path().join("server.db");
    let server_state = Arc::new(SqliteStateStore::new(&server_db).unwrap());

    let grants_path = temp.path().join("grants.toml");
    let grants_content = r#"
[[grant]]
identity = "testclient"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
"#;
    std::fs::write(&grants_path, grants_content).unwrap();

    let (server_handle, _backend) = start_test_server(
        &pki,
        storage_root.clone(),
        staging_root.clone(),
        server_state,
        grants_path,
    )
    .await;

    // Seed server with directory tree
    let server_dir = storage_root.join("data_tree");
    std::fs::create_dir_all(server_dir.join("nested")).unwrap();
    std::fs::write(server_dir.join("root.txt"), b"root content").unwrap();
    std::fs::write(server_dir.join("nested/child.txt"), b"child content").unwrap();

    let local_dst = temp.path().join("download_dst");
    let remote_url = format!(
        "velcrux://127.0.0.1:{}/data_tree",
        server_handle.addr.port()
    );

    // 1. Download sync with --json and --dry-run
    let dry_run_json = Command::new(velcrux_bin())
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("--json")
        .arg("sync")
        .arg(&remote_url)
        .arg(local_dst.to_str().unwrap())
        .arg("--dry-run")
        .output()
        .expect("exec network sync json dry-run");

    assert!(dry_run_json.status.success());
    let stdout = String::from_utf8_lossy(&dry_run_json.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid json output");
    assert_eq!(parsed["event"], "sync_summary");
    assert_eq!(parsed["dry_run"], true);
    assert_eq!(parsed["files_added"], 2);

    // Verify local_dst is empty after dry-run
    assert!(!local_dst.join("root.txt").exists());

    // 2. Download sync execution
    let download_output = Command::new(velcrux_bin())
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("sync")
        .arg(&remote_url)
        .arg(local_dst.to_str().unwrap())
        .output()
        .expect("exec network sync download");

    assert!(download_output.status.success());
    assert_eq!(
        std::fs::read(local_dst.join("root.txt")).unwrap(),
        b"root content"
    );
    assert_eq!(
        std::fs::read(local_dst.join("nested/child.txt")).unwrap(),
        b"child content"
    );
}

#[test]
fn test_cli_sync_posix_metadata_and_symlinks() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("source");
    let dst = temp.path().join("destination");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    let target_file = src.join("data.txt");
    std::fs::write(&target_file, b"data content").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("data.txt", src.join("data_link.txt")).unwrap();
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file("data.txt", src.join("data_link.txt")).unwrap();
    }

    let sidecar = velcrux_core::storage::xattr_sidecar_path(&target_file);
    let xattrs = vec![("user.tag".to_string(), b"verified".to_vec())];
    std::fs::write(
        &sidecar,
        velcrux_core::storage::encode_xattrs_canonical(&xattrs),
    )
    .unwrap();

    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux sync");

    assert!(output.status.success());

    // Verify destination file, symlink, and xattr sidecar
    let dst_target = dst.join("data.txt");
    let dst_link = dst.join("data_link.txt");
    let dst_sidecar = velcrux_core::storage::xattr_sidecar_path(&dst_target);

    assert!(dst_target.exists());
    assert!(dst_link
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read_link(&dst_link).unwrap().to_string_lossy(),
        "data.txt"
    );

    assert!(dst_sidecar.exists());
    let raw = std::fs::read(&dst_sidecar).unwrap();
    let decoded = velcrux_core::storage::decode_xattrs_canonical(&raw).unwrap();
    assert_eq!(decoded, xattrs);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dst_target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
}

#[test]
fn test_cli_sync_mode_flags() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("sample.txt"), b"sample payload for direct mode").unwrap();

    let output = Command::new(velcrux_bin())
        .arg("--mode")
        .arg("direct")
        .arg("--network-profile")
        .arg("lan")
        .arg("--min-delta-size")
        .arg("32768")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux sync --mode direct");

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dst.join("sample.txt")).unwrap(),
        b"sample payload for direct mode"
    );
}

#[test]
fn test_cli_bind_flags() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("sample.txt"), b"bind test payload").unwrap();

    // Verify global bind flags are accepted during sync execution
    let output = Command::new(velcrux_bin())
        .arg("--bind-ip")
        .arg("127.0.0.1")
        .arg("--bind-port")
        .arg("0")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux with bind flags");

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dst.join("sample.txt")).unwrap(),
        b"bind test payload"
    );

    // Verify --help documents all Option AE bind flags
    let help_output = Command::new(velcrux_bin())
        .arg("--help")
        .output()
        .expect("failed to run velcrux --help");

    assert!(help_output.status.success());
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_text.contains("--bind-ip"));
    assert!(help_text.contains("--bind-interface"));
    assert!(help_text.contains("--bind-port"));
}

#[test]
fn test_cli_priority_and_concurrency_flags() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("sample.txt"), b"priority test payload").unwrap();

    // Verify valid priority and concurrency flags succeed during sync execution
    let output = Command::new(velcrux_bin())
        .arg("--priority")
        .arg("urgent")
        .arg("--concurrency")
        .arg("8")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux with priority and concurrency flags");

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dst.join("sample.txt")).unwrap(),
        b"priority test payload"
    );

    // Verify invalid priority fails
    let bad_prio = Command::new(velcrux_bin())
        .arg("--priority")
        .arg("superfast")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to run with invalid priority");
    assert!(!bad_prio.status.success());
    let stderr = String::from_utf8_lossy(&bad_prio.stderr);
    assert!(stderr.contains("invalid transfer priority"));

    // Verify zero concurrency fails
    let zero_conc = Command::new(velcrux_bin())
        .arg("--concurrency")
        .arg("0")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to run with zero concurrency");
    assert!(!zero_conc.status.success());
    let stderr_conc = String::from_utf8_lossy(&zero_conc.stderr);
    assert!(stderr_conc.contains("concurrency must be greater than 0"));

    // Verify --help documents --priority and --concurrency
    let help_output = Command::new(velcrux_bin())
        .arg("--help")
        .output()
        .expect("failed to run velcrux --help");
    assert!(help_output.status.success());
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_text.contains("--priority"));
    assert!(help_text.contains("--concurrency"));
}

#[test]
fn test_cli_direct_io_flags() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    let dst = temp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("sample.txt"), b"direct-io test payload").unwrap();

    // 1. Verify valid --direct-io flag succeeds during sync
    let output = Command::new(velcrux_bin())
        .arg("--direct-io")
        .arg("auto")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux with --direct-io auto");

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(dst.join("sample.txt")).unwrap(),
        b"direct-io test payload"
    );

    // 2. Verify --direct-io disabled succeeds
    let output_dis = Command::new(velcrux_bin())
        .arg("--direct-io")
        .arg("disabled")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to execute velcrux with --direct-io disabled");
    assert!(output_dis.status.success());

    // 3. Verify invalid --direct-io mode fails
    let bad_dio = Command::new(velcrux_bin())
        .arg("--direct-io")
        .arg("turbo_boost")
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .output()
        .expect("failed to run with invalid direct-io");
    assert!(!bad_dio.status.success());
    let stderr = String::from_utf8_lossy(&bad_dio.stderr);
    assert!(stderr.contains("invalid direct_io mode"));

    // 4. Verify --help documents --direct-io
    let help_output = Command::new(velcrux_bin())
        .arg("--help")
        .output()
        .expect("failed to run velcrux --help");
    assert!(help_output.status.success());
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_text.contains("--direct-io"));
}

#[test]
fn test_cli_batch_small_files_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src_batch");
    let dst = tmp.path().join("dst_batch");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // Create 10 small files
    for i in 0..10 {
        std::fs::write(
            src.join(format!("file_{}.txt", i)),
            format!("small test payload {}", i),
        )
        .unwrap();
    }

    // 1. Verify --batch-small-files sync succeeds with batch reporting
    let output = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .arg("--batch-small-files")
        .arg("--small-file-threshold")
        .arg("65536")
        .output()
        .expect("failed to execute velcrux sync with --batch-small-files");

    assert!(output.status.success(), "sync with batching must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Batched: 10 small files"));
    for i in 0..10 {
        assert_eq!(
            std::fs::read_to_string(dst.join(format!("file_{}.txt", i))).unwrap(),
            format!("small test payload {}", i)
        );
    }

    // 2. Verify --no-batch-small-files flag works
    let dst2 = tmp.path().join("dst_nobatch");
    std::fs::create_dir_all(&dst2).unwrap();
    let output_nobatch = Command::new(velcrux_bin())
        .arg("sync")
        .arg(src.to_str().unwrap())
        .arg(dst2.to_str().unwrap())
        .arg("--no-batch-small-files")
        .output()
        .expect("failed to execute velcrux sync with --no-batch-small-files");

    assert!(output_nobatch.status.success());
    for i in 0..10 {
        assert!(dst2.join(format!("file_{}.txt", i)).exists());
    }

    // 3. Verify --help documents batch options
    let help_output = Command::new(velcrux_bin())
        .arg("sync")
        .arg("--help")
        .output()
        .expect("failed to run velcrux sync --help");
    assert!(help_output.status.success());
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_text.contains("--batch-small-files"));
    assert!(help_text.contains("--no-batch-small-files"));
    assert!(help_text.contains("--small-file-threshold"));
    assert!(help_text.contains("--batch-max-bytes"));
}
