//! Integration tests for Option N: Operational Session Management & Revocation Termination CLI (`OPERATIONS.md` §6, `SECURITY.md` §2).
//!
//! Verifies:
//! 1. `SessionRegistry` concurrent session tracking, lookups, and identity mapping.
//! 2. Admin HTTP endpoints `/admin/sessions` and `/admin/kill-session`.
//! 3. CLI commands `velcruxd sessions` (table and JSON formats) and `velcruxd kill-session`.
//! 4. Live connection actor termination upon operator kill signal.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

use velcrux_core::protocol::capabilities::Capabilities;
use velcrux_core::session::{ServerConn, ServerStats};
use velcrux_core::storage::LocalFilesystemBackend;
use velcrux_server::metrics::start_metrics_server_with_registry;
use velcrux_server::sessions::{SessionInfo, SessionRegistry};

fn velcruxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_velcruxd"))
}

async fn http_request(addr: SocketAddr, method: &str, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect to admin");
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write req");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read resp");
    let resp_str = String::from_utf8_lossy(&buf).to_string();

    let status_line = resp_str.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    (status_code, resp_str)
}

#[tokio::test]
async fn test_session_registry_lifecycle() {
    let registry = SessionRegistry::new();

    let addr1: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:10002".parse().unwrap();
    let addr3: SocketAddr = "127.0.0.1:10003".parse().unwrap();

    let rx1 = registry.register(1, addr1).await;
    let rx2 = registry.register(2, addr2).await;
    let rx3 = registry.register(3, addr3).await;

    assert!(!*rx1.borrow());
    assert!(!*rx2.borrow());
    assert!(!*rx3.borrow());

    let list = registry.list_sessions().await;
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].conn_id, 1);
    assert_eq!(list[0].identity, None);
    assert_eq!(list[0].remote_addr, "127.0.0.1:10001");

    // Authenticate sessions
    registry.set_identity(1, "svc-replica").await;
    registry.set_identity(2, "backup-worker").await;
    registry.set_identity(3, "svc-replica").await;

    let list = registry.list_sessions().await;
    assert_eq!(list[0].identity.as_deref(), Some("svc-replica"));
    assert_eq!(list[1].identity.as_deref(), Some("backup-worker"));
    assert_eq!(list[2].identity.as_deref(), Some("svc-replica"));

    // Kill by identity: terminates both conn 1 and conn 3
    let killed = registry.kill_by_identity("svc-replica").await;
    assert_eq!(killed, 2);
    assert!(*rx1.borrow());
    assert!(!*rx2.borrow());
    assert!(*rx3.borrow());

    // Kill by conn_id
    assert!(registry.kill_by_conn_id(2).await);
    assert!(*rx2.borrow());
    assert!(!registry.kill_by_conn_id(999).await);

    // Unregister
    registry.unregister(1).await;
    let list = registry.list_sessions().await;
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].conn_id, 2);
    assert_eq!(list[1].conn_id, 3);
}

#[tokio::test]
async fn test_admin_http_endpoints() {
    let registry = SessionRegistry::new();
    let stats = Arc::new(ServerStats::default());

    let (admin_addr, shutdown_tx) =
        start_metrics_server_with_registry("127.0.0.1:0", stats, Some(Arc::clone(&registry)))
            .await
            .expect("start admin server");

    let addr1: SocketAddr = "127.0.0.1:20001".parse().unwrap();
    let rx1 = registry.register(10, addr1).await;
    registry.set_identity(10, "revoked-client").await;

    // Test GET /admin/sessions
    let (status, body) = http_request(admin_addr, "GET", "/admin/sessions").await;
    assert_eq!(status, 200);
    assert!(body.contains("\"conn_id\": 10"));
    assert!(body.contains("\"identity\": \"revoked-client\""));

    // Test POST /admin/kill-session?identity=revoked-client
    assert!(!*rx1.borrow());
    let (status, body) = http_request(
        admin_addr,
        "POST",
        "/admin/kill-session?identity=revoked-client",
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("{\"killed\":1}"));
    assert!(*rx1.borrow());

    // Register second session and kill by conn_id
    let rx2 = registry.register(20, addr1).await;
    assert!(!*rx2.borrow());
    let (status, body) = http_request(admin_addr, "POST", "/admin/kill-session?conn_id=20").await;
    assert_eq!(status, 200);
    assert!(body.contains("{\"killed\":1}"));
    assert!(*rx2.borrow());

    let _ = shutdown_tx.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_sessions_and_kill_session() {
    let registry = SessionRegistry::new();
    let stats = Arc::new(ServerStats::default());

    let (admin_addr, shutdown_tx) =
        start_metrics_server_with_registry("127.0.0.1:0", stats, Some(Arc::clone(&registry)))
            .await
            .expect("start admin server");

    let temp = tempdir().unwrap();
    let config_path = temp.path().join("server.toml");
    let state_db = temp.path().join("state.db");
    let storage_dir = temp.path().join("data");
    let staging_dir = temp.path().join("staging");
    std::fs::create_dir_all(&storage_dir).unwrap();
    std::fs::create_dir_all(&staging_dir).unwrap();

    let toml = format!(
        r#"
[network]
listen = "127.0.0.1:7443"

[security]
client_ca = "/tmp/ca.crt"
certificate = "/tmp/server.crt"
private_key = "/tmp/server.key"

[storage]
root = "{}"
staging = "{}"
state_db = "{}"

[telemetry]
metrics_listen = "{}"
"#,
        storage_dir.display(),
        staging_dir.display(),
        state_db.display(),
        admin_addr
    );
    std::fs::write(&config_path, toml).unwrap();

    // 1. Initially no sessions
    let out = Command::new(velcruxd_bin())
        .args(["sessions", "--config", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("run velcruxd sessions");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No active sessions."));

    // 2. Format JSON initially empty array
    let out = Command::new(velcruxd_bin())
        .args([
            "sessions",
            "--config",
            config_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .await
        .expect("run velcruxd sessions --format json");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<SessionInfo> = serde_json::from_str(stdout.trim()).expect("parse empty json");
    assert!(parsed.is_empty());

    // 3. Register active session
    let addr: SocketAddr = "127.0.0.1:30001".parse().unwrap();
    let rx = registry.register(42, addr).await;
    registry.set_identity(42, "prod-worker-01").await;

    // 4. Test table output
    let out = Command::new(velcruxd_bin())
        .args(["sessions", "--config", config_path.to_str().unwrap()])
        .output()
        .await
        .expect("run velcruxd sessions");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CONN ID"));
    assert!(stdout.contains("IDENTITY"));
    assert!(stdout.contains("42"));
    assert!(stdout.contains("prod-worker-01"));

    // 5. Test JSON output
    let out = Command::new(velcruxd_bin())
        .args([
            "sessions",
            "--config",
            config_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .await
        .expect("run velcruxd sessions json");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<SessionInfo> = serde_json::from_str(stdout.trim()).expect("parse active json");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].conn_id, 42);
    assert_eq!(parsed[0].identity.as_deref(), Some("prod-worker-01"));

    // 6. Kill session via CLI
    let out = Command::new(velcruxd_bin())
        .args([
            "kill-session",
            "--config",
            config_path.to_str().unwrap(),
            "--identity",
            "prod-worker-01",
        ])
        .output()
        .await
        .expect("run velcruxd kill-session");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Successfully terminated 1 active session(s)."));
    assert!(*rx.borrow());

    // 7. Kill session when non-matching
    let out = Command::new(velcruxd_bin())
        .args([
            "kill-session",
            "--config",
            config_path.to_str().unwrap(),
            "--identity",
            "non-existent",
        ])
        .output()
        .await
        .expect("run velcruxd kill-session nonexistent");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No matching active sessions found."));

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_server_conn_operator_kill_signal_termination() {
    let temp = tempdir().unwrap();
    let backend_root = temp.path().join("backend");
    let staging_root = temp.path().join("staging");
    std::fs::create_dir_all(&backend_root).unwrap();
    std::fs::create_dir_all(&staging_root).unwrap();

    let backend = Arc::new(
        LocalFilesystemBackend::new(backend_root, staging_root)
            .await
            .expect("local backend"),
    );
    let stats = Arc::new(ServerStats::default());
    let registry = SessionRegistry::new();

    let addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let kill_rx = registry.register(1, addr).await;

    let actor = ServerConn::with_state(
        Capabilities::from_wire(0),
        "velcruxd-test",
        stats,
        backend,
        None,
        None,
        None,
    )
    .with_conn_id(1)
    .with_kill_signal(Some(kill_rx));

    // Signal termination immediately
    let killed = registry.kill_by_conn_id(1).await;
    assert!(killed);

    // Verify actor detects termination
    assert!(actor.is_killed());
}
