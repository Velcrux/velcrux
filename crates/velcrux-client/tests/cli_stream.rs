//! End-to-End CLI integration tests for Option BG: Unix Stdin/Stdout Streaming Pipelines.
//!
//! Validates:
//! 1. `velcrux upload - <url>` reads piped stdin stream and uploads to server.
//! 2. `velcrux download <url> -` streams remote file to stdout without stdout log pollution.
//! 3. `velcrux stream send <url>` dedicated alias for stdin streaming pipelines.
//! 4. `velcrux stream recv <url>` dedicated alias for stdout streaming pipelines.
//! 5. Full round-trip unix pipeline fidelity and byte-for-byte consistency.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
use velcrux_core::storage::{LocalFilesystemBackend, StorageBackend};
use velcrux_core::transport::quic::{ServerBuilder, TransportConfigTunables};
use velcrux_core::transport::Transport;
use velcrux_core::util::Hash;

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
    dn.push(DnType::CommonName, "velcrux-stream-test-ca");
    ca_params.distinguished_name = dn;
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let ca_cert_path = dir.join("ca.crt");
    std::fs::write(&ca_cert_path, ca_cert.pem()).unwrap();

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
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    let server_key_pair = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key)
        .unwrap();

    let server_certs = rustls_pemfile::certs(&mut server_cert.pem().as_bytes())
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let server_key = PrivateKey(server_key_pair.serialize_der());

    let mut client_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "streamclient");
    client_params.distinguished_name = dn;
    client_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.subject_alt_names = vec![SanType::URI(
        "velcrux://identity/streamclient".try_into().unwrap(),
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

async fn start_test_server(
    pki: &TestPki,
    storage_root: PathBuf,
    staging_root: PathBuf,
    grants_path: PathBuf,
) -> (ServerHandle, Arc<dyn StorageBackend>) {
    let tunables = TransportConfigTunables::default();
    let ca_pem = std::fs::read(&pki.ca_cert_path).unwrap();

    let transport = ServerBuilder::new()
        .with_server_cert(pki.server_certs.clone(), pki.server_key.clone())
        .with_client_ca_roots_pem(&ca_pem)
        .unwrap()
        .with_tunables(tunables)
        .build("127.0.0.1:0".parse().unwrap())
        .unwrap();

    let addr = transport.local_addr().unwrap();
    let backend: Arc<dyn StorageBackend> = Arc::new(
        LocalFilesystemBackend::new(storage_root, staging_root)
            .await
            .unwrap(),
    );

    let authenticator: Arc<dyn Authenticator> = Arc::new(MtlsAuthenticator::new());
    let authorizer: Arc<dyn Authorizer> = Arc::new(FileAuthorizer::load(&grants_path).unwrap());

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let stats = Arc::new(ServerStats::default());
    let server_backend = Arc::clone(&backend);

    tokio::spawn(async move {
        let mut server_caps = Capabilities::EMPTY;
        server_caps.set(Capability::FixedChunking);
        server_caps.set(Capability::Blake3);

        let next_id = Arc::new(AtomicU64::new(1));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                conn_res = transport.accept() => {
                    let conn = match conn_res {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let _id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let actor = ServerConn::with_state(
                        server_caps,
                        "velcruxd-stream-test",
                        Arc::clone(&stats),
                        Arc::clone(&server_backend),
                        None,
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
async fn test_cli_streaming_pipelines_roundtrip() {
    let temp = tempdir().unwrap();
    let pki_dir = temp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki = generate_test_pki(&pki_dir);

    let storage_root = temp.path().join("server_storage");
    let staging_root = temp.path().join("server_staging");
    std::fs::create_dir_all(&storage_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let grants_path = temp.path().join("grants.toml");
    let grants_content = r#"
[[grant]]
identity = "streamclient"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
"#;
    std::fs::write(&grants_path, grants_content).unwrap();

    let (mut server_handle, _backend) = start_test_server(
        &pki,
        storage_root.clone(),
        staging_root.clone(),
        grants_path,
    )
    .await;

    let bin = velcrux_bin();

    // Generate arbitrary 512 KiB binary payload
    let test_bytes: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    let expected_hash = Hash::of(&test_bytes);

    let remote_upload_url = format!(
        "velcrux://127.0.0.1:{}/streams/archive.tar",
        server_handle.addr.port()
    );

    // -----------------------------------------------------------------------
    // Test 1: `velcrux upload - <url>` via stdin pipe
    // -----------------------------------------------------------------------
    let mut child = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("upload")
        .arg("-")
        .arg(&remote_upload_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn upload -");

    {
        let mut stdin = child.stdin.take().expect("open stdin");
        stdin.write_all(&test_bytes).expect("write to stdin");
        stdin.flush().expect("flush stdin");
    }

    let output = child.wait_with_output().expect("wait on upload -");
    assert!(
        output.status.success(),
        "upload - stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let upload_err = String::from_utf8_lossy(&output.stderr);
    assert!(
        upload_err.contains("transfer_id:"),
        "upload output missing transfer_id: {upload_err}"
    );

    // Verify committed file on server storage
    let on_disk_server = storage_root.join("streams/archive.tar");
    assert!(
        on_disk_server.exists(),
        "staged/committed file must exist on server"
    );
    let server_content = std::fs::read(&on_disk_server).expect("read server file");
    assert_eq!(server_content.len(), test_bytes.len());
    assert_eq!(Hash::of(&server_content), expected_hash);

    // -----------------------------------------------------------------------
    // Test 2: `velcrux download <url> -` via stdout pipe
    // (Must be completely byte-pure on stdout without log pollution)
    // -----------------------------------------------------------------------
    let download_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("download")
        .arg(&remote_upload_url)
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("exec download -");

    assert!(
        download_output.status.success(),
        "download - stderr: {}",
        String::from_utf8_lossy(&download_output.stderr)
    );

    // Stdout must match EXACT bytes (not text, no progress bars)
    assert_eq!(
        download_output.stdout.len(),
        test_bytes.len(),
        "downloaded stdout length mismatch"
    );
    assert_eq!(
        Hash::of(&download_output.stdout),
        expected_hash,
        "downloaded stdout hash mismatch"
    );

    // Stderr should contain streaming progress or verify hash
    let download_err = String::from_utf8_lossy(&download_output.stderr);
    assert!(
        download_err.contains("hash verified:"),
        "download stderr should report hash verified: {download_err}"
    );

    // -----------------------------------------------------------------------
    // Test 3: `velcrux stream send <url>` dedicated alias
    // -----------------------------------------------------------------------
    let stream_alias_url = format!(
        "velcrux://127.0.0.1:{}/streams/alias.tar",
        server_handle.addr.port()
    );

    let mut send_child = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("stream")
        .arg("send")
        .arg(&stream_alias_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stream send");

    {
        let mut stdin = send_child.stdin.take().expect("open stdin");
        stdin.write_all(&test_bytes).expect("write to stdin");
        stdin.flush().expect("flush stdin");
    }

    let send_output = send_child.wait_with_output().expect("wait stream send");
    assert!(
        send_output.status.success(),
        "stream send stderr: {}",
        String::from_utf8_lossy(&send_output.stderr)
    );

    // -----------------------------------------------------------------------
    // Test 4: `velcrux stream recv <url>` dedicated alias
    // -----------------------------------------------------------------------
    let recv_output = Command::new(&bin)
        .arg("--ca")
        .arg(&pki.ca_cert_path)
        .arg("--cert")
        .arg(&pki.client_cert_path)
        .arg("--key")
        .arg(&pki.client_key_path)
        .arg("stream")
        .arg("recv")
        .arg(&stream_alias_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("exec stream recv");

    assert!(
        recv_output.status.success(),
        "stream recv stderr: {}",
        String::from_utf8_lossy(&recv_output.stderr)
    );

    assert_eq!(
        Hash::of(&recv_output.stdout),
        expected_hash,
        "stream recv stdout hash mismatch"
    );

    // Graceful shutdown
    if let Some(tx) = server_handle.shutdown_tx.take() {
        let _ = tx.send(());
    }
}
