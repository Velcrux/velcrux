//! Integration tests for Option C: Production Operations & Daemon Polish.
//!
//! Verifies:
//! - Server TOML configuration loading and environment variable overrides (`VELCRUX_*`).
//! - Validation rules (e.g. absolute state_db path, valid listen addr).
//! - Prometheus text format metrics formatting and HTTP `/metrics` & `/healthz` endpoints.
//! - Dynamic authorization hot-reloading (SIGHUP behavior).
//! - Client `--config` file support.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use velcrux_core::auth::{Authorizer, FileAuthorizer, Op};
use velcrux_core::session::ServerStats;
use velcrux_core::transport::identity::Identity;
use velcrux_server::config::{parse_size_bytes, ServerConfig};
use velcrux_server::metrics::{format_prometheus_metrics, start_metrics_server};
use velcrux_server::server::ReloadableAuthorizer;

fn velcrux_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("velcrux")
}

#[test]
fn test_parse_size_bytes() {
    assert_eq!(parse_size_bytes("256KiB").unwrap(), 256 * 1024);
    assert_eq!(parse_size_bytes("384MiB").unwrap(), 384 * 1024 * 1024);
    assert_eq!(parse_size_bytes("1GiB").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(
        parse_size_bytes("2TiB").unwrap(),
        2 * 1024 * 1024 * 1024 * 1024
    );
    assert_eq!(parse_size_bytes("1024").unwrap(), 1024);
}

#[test]
fn test_server_config_and_env_overrides() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("server.toml");
    let state_db = temp.path().join("state.db");

    let toml_content = format!(
        r#"
[network]
listen = "127.0.0.1:7443"
idle_timeout = "45s"
keepalive = "10s"

[security]
certificate = "/tmp/server.crt"
private_key = "/tmp/server.key"
client_ca = "/tmp/ca.crt"

[storage]
root = "/tmp/storage"
staging = "/tmp/staging"
state_db = "{}"
"#,
        state_db.display()
    );
    std::fs::write(&config_path, &toml_content).unwrap();

    // 1. Initial load
    let cfg = ServerConfig::load(&config_path).expect("load config");
    assert_eq!(cfg.network.listen, "127.0.0.1:7443");
    assert_eq!(cfg.network.idle_timeout, "45s");
    assert_eq!(cfg.network.keepalive, "10s");
    assert_eq!(
        cfg.storage.state_db,
        Some(state_db.to_str().unwrap().to_string())
    );

    // 2. Environment variable overrides
    std::env::set_var("VELCRUX_NETWORK_LISTEN", "127.0.0.1:18443");
    std::env::set_var("VELCRUX_STORAGE_ROOT", "/tmp/overridden_storage");
    std::env::set_var("VELCRUX_TELEMETRY_METRICS_LISTEN", "127.0.0.1:9999");

    let cfg_overridden = ServerConfig::load(&config_path).expect("load with env overrides");
    assert_eq!(cfg_overridden.network.listen, "127.0.0.1:18443");
    assert_eq!(cfg_overridden.storage.root, "/tmp/overridden_storage");
    assert_eq!(
        cfg_overridden.telemetry.metrics_listen,
        Some("127.0.0.1:9999".into())
    );

    // Clean up env
    std::env::remove_var("VELCRUX_NETWORK_LISTEN");
    std::env::remove_var("VELCRUX_STORAGE_ROOT");
    std::env::remove_var("VELCRUX_TELEMETRY_METRICS_LISTEN");

    // 3. Validation failure on relative state_db path (ADR-005)
    let bad_toml = r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "/tmp/server.crt"
private_key = "/tmp/server.key"
client_ca = "/tmp/ca.crt"

[storage]
root = "/tmp/storage"
staging = "/tmp/staging"
state_db = "relative/path/state.db"
"#;
    let bad_config_path = temp.path().join("bad.toml");
    std::fs::write(&bad_config_path, bad_toml).unwrap();
    assert!(ServerConfig::load(&bad_config_path).is_err());
}

#[test]
fn test_prometheus_metrics_formatting() {
    let stats = ServerStats::default();
    stats.connections.store(15, Ordering::Relaxed);
    stats.handshakes.store(14, Ordering::Relaxed);
    stats.pings.store(8, Ordering::Relaxed);
    stats.transfers_active.store(2, Ordering::Relaxed);
    stats.transfers_total_upload.store(5, Ordering::Relaxed);
    stats.transfers_total_download.store(3, Ordering::Relaxed);
    stats
        .bytes_transferred_upload
        .store(1048576, Ordering::Relaxed);
    stats
        .bytes_transferred_download
        .store(524288, Ordering::Relaxed);
    stats.bytes_reused.store(2097152, Ordering::Relaxed);
    stats.authz_denials.store(1, Ordering::Relaxed);
    stats.checksum_mismatches.store(0, Ordering::Relaxed);

    let output = format_prometheus_metrics(&stats);
    assert!(output.contains("velcrux_connections{state=\"accepted\"} 15"));
    assert!(output.contains("velcrux_handshakes_total 14"));
    assert!(output.contains("velcrux_pings_total 8"));
    assert!(output.contains("velcrux_transfers_active{direction=\"bidirectional\"} 2"));
    assert!(output.contains("velcrux_transfers_total{direction=\"upload\",status=\"committed\"} 5"));
    assert!(
        output.contains("velcrux_transfers_total{direction=\"download\",status=\"committed\"} 3")
    );
    assert!(output.contains("velcrux_bytes_transferred_total{direction=\"upload\"} 1048576"));
    assert!(output.contains("velcrux_bytes_transferred_total{direction=\"download\"} 524288"));
    assert!(output.contains("velcrux_bytes_reused_total 2097152"));
    assert!(output.contains("velcrux_authz_denials_total{op=\"all\"} 1"));
    assert!(output.contains("velcrux_checksum_mismatch_total{side=\"server\"} 0"));
}

#[tokio::test]
async fn test_prometheus_http_server_endpoints() {
    let stats = Arc::new(ServerStats::default());
    stats.connections.store(42, Ordering::Relaxed);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let listen_str = addr.to_string();
    let shutdown_tx = start_metrics_server(&listen_str, Arc::clone(&stats))
        .await
        .expect("start metrics server");

    // 1. Query /healthz
    let mut stream = TcpStream::connect(addr).await.expect("connect to healthz");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.contains("200 OK"));
    assert!(response.contains("healthy"));

    // 2. Query /metrics
    let mut stream = TcpStream::connect(addr).await.expect("connect to metrics");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.contains("200 OK"));
    assert!(response.contains("velcrux_connections{state=\"accepted\"} 42"));

    // 3. Graceful shutdown
    let _ = shutdown_tx.send(());
}

#[test]
fn test_reloadable_authorizer_sighup() {
    let temp = tempdir().unwrap();
    let grants_path = temp.path().join("grants.toml");

    // Initial grants: only alice has access
    std::fs::write(
        &grants_path,
        r#"
[[grant]]
identity = "alice"
path = "/data"
permissions = ["upload", "download"]
"#,
    )
    .unwrap();

    let initial = Arc::new(FileAuthorizer::load(&grants_path).unwrap());
    let reloadable = ReloadableAuthorizer::new(initial);

    let alice = Identity::new("alice", "", "");
    let bob = Identity::new("bob", "", "");

    assert!(reloadable
        .check(&alice, Op::Upload, "/data/test.bin")
        .is_ok());
    assert!(reloadable
        .check(&bob, Op::Upload, "/data/test.bin")
        .is_err());

    // Update grants file on disk (simulate SIGHUP reload)
    std::fs::write(
        &grants_path,
        r#"
[[grant]]
identity = "alice"
path = "/data"
permissions = ["upload", "download"]

[[grant]]
identity = "bob"
path = "/data"
permissions = ["upload", "download"]
"#,
    )
    .unwrap();

    let reloaded = Arc::new(FileAuthorizer::load(&grants_path).unwrap());
    reloadable.reload(reloaded);

    // Now bob has access immediately without restarting or dropping sessions!
    assert!(reloadable
        .check(&alice, Op::Upload, "/data/test.bin")
        .is_ok());
    assert!(reloadable.check(&bob, Op::Upload, "/data/test.bin").is_ok());
}

#[test]
fn test_client_config_file_cli() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("client-config.toml");
    std::fs::write(
        &config_path,
        r#"
sni = "custom.domain.internal"
log_format = "json"
json = true
"#,
    )
    .unwrap();

    let bin = velcrux_bin();
    let out = Command::new(&bin)
        .arg("--config")
        .arg(&config_path)
        .arg("completions")
        .arg("zsh")
        .output()
        .expect("run client with config");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("velcrux"));
}
