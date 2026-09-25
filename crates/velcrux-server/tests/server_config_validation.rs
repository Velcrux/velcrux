#![forbid(unsafe_code)]

//! Integration tests for Milestone 13 (Option J):
//! Server Configuration Parser, Startup Validation & Environment Overrides (`OPERATIONS.md` §2, §4).

use std::fs;
use std::path::PathBuf;
use velcrux_core::auth::Op;
use velcrux_core::transport::Identity;
use velcrux_server::config::{parse_size_bytes, ServerConfig};

fn setup_temp_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("velcrux_cfg_test_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create temp dir");
    p
}

#[test]
fn test_full_server_config_parsing_from_spec() {
    let tmp = setup_temp_dir("full_spec");
    let root = tmp.join("files");
    let staging = tmp.join("files/.velcrux-staging");
    let cert = tmp.join("server.crt");
    let key = tmp.join("server.key");
    let ca = tmp.join("clients-ca.crt");
    let state_db = tmp.join("state.db");

    fs::create_dir_all(&staging).unwrap();
    fs::write(&cert, "dummy-cert").unwrap();
    fs::write(&key, "dummy-key").unwrap();
    fs::write(&ca, "dummy-ca").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let toml_content = format!(
        r#"
[network]
listen           = "127.0.0.1:7443"
max_bandwidth    = "10Gbps"
max_connections  = 100
max_connections_per_ip = 10
max_connections_unauth = 20
idle_timeout     = "60s"
keepalive        = "15s"

[quic]
receive_window        = "384MiB"
stream_receive_window = "384MiB"
max_concurrent_streams = 32
initial_rtt           = "150ms"
gso                   = true

[transfer]
chunking          = "cdc"
chunk_min         = "256KiB"
chunk_target      = "1MiB"
chunk_max         = "4MiB"
parallelism       = 8
resume            = true
compression       = "none"
checkpoint_bytes  = "1GiB"
checkpoint_secs   = 10
read_buffer       = "2MiB"
max_file_size     = "64TiB"
max_manifest_entries = 50000000

[hash]
algorithm = "blake3"
workers   = 4

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"
crl         = "/etc/velcrux/clients.crl"
max_auth_attempts = 3

[storage]
root        = "{}"
staging     = "{}"
state_db    = "{}"

[telemetry]
metrics_listen = "127.0.0.1:9443"
log_format     = "json"
log_level      = "info"

[[grant]]
identity    = "svc-replica"
path        = "/customerA"
permissions = ["upload", "download", "list", "sync", "resume"]

[[limits]]
identity    = "svc-replica"
max_bandwidth = "2Gbps"
quota_bytes   = "50TiB"
"#,
        cert.display(),
        key.display(),
        ca.display(),
        root.display(),
        staging.display(),
        state_db.display()
    );

    let config_path = tmp.join("server.toml");
    fs::write(&config_path, &toml_content).unwrap();

    let cfg = ServerConfig::load(&config_path).expect("valid configuration load");

    // Network assertions
    assert_eq!(cfg.network.listen, "127.0.0.1:7443");
    assert_eq!(cfg.network.max_bandwidth.as_deref(), Some("10Gbps"));
    assert_eq!(cfg.network.max_connections, Some(100));
    assert_eq!(cfg.network.max_connections_per_ip, Some(10));
    assert_eq!(cfg.network.max_connections_unauth, Some(20));

    // Quic assertions
    assert_eq!(cfg.quic.receive_window, "384MiB");
    assert_eq!(cfg.quic.max_concurrent_streams, 32);
    assert_eq!(cfg.quic.initial_rtt, "150ms");
    assert!(cfg.quic.gso);

    // Transfer assertions
    assert_eq!(cfg.transfer.chunking.as_deref(), Some("cdc"));
    assert_eq!(cfg.transfer.parallelism, Some(8));
    assert_eq!(cfg.transfer.max_manifest_entries, Some(50_000_000));

    // Grants and limits assertions
    assert_eq!(cfg.grants.len(), 1);
    assert_eq!(cfg.grants[0].identity, "svc-replica");
    assert_eq!(cfg.grants[0].path, "/customerA");
    assert_eq!(
        cfg.grants[0].permissions,
        vec!["upload", "download", "list", "sync", "resume"]
    );

    assert_eq!(cfg.limits.len(), 1);
    assert_eq!(cfg.limits[0].identity, "svc-replica");
    assert_eq!(cfg.limits[0].max_bandwidth.as_deref(), Some("2Gbps"));
    assert_eq!(cfg.limits[0].quota_bytes.as_deref(), Some("50TiB"));

    // Authorizer checking
    let authorizer = cfg.build_authorizer().expect("build authorizer");
    let id = Identity {
        name: "svc-replica".into(),
        issuer_fingerprint: "0123456789abcdef".into(),
        cert_fingerprint: "fedcba9876543210".into(),
    };

    // Allowed operations on customerA
    assert!(authorizer
        .check(&id, Op::Upload, "customerA/data.bin")
        .is_ok());
    assert!(authorizer
        .check(&id, Op::Download, "customerA/data.bin")
        .is_ok());
    assert!(authorizer
        .check(&id, Op::Sync, "customerA/data.bin")
        .is_ok());

    // Disallowed: delete is not granted to svc-replica
    assert!(authorizer
        .check(&id, Op::Delete, "customerA/data.bin")
        .is_err());

    // Disallowed: different path prefix
    assert!(authorizer
        .check(&id, Op::Upload, "customerB/data.bin")
        .is_err());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_env_var_overrides() {
    let tmp = setup_temp_dir("env_overrides");
    let root = tmp.join("files");
    let staging = tmp.join("files/.velcrux-staging");
    let cert = tmp.join("server.crt");
    let key = tmp.join("server.key");
    let ca = tmp.join("clients-ca.crt");
    let state_db = tmp.join("state.db");

    fs::create_dir_all(&staging).unwrap();
    fs::write(&cert, "dummy-cert").unwrap();
    fs::write(&key, "dummy-key").unwrap();
    fs::write(&ca, "dummy-ca").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let toml_content = format!(
        r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"

[storage]
root    = "{}"
staging = "{}"
state_db = "{}"
"#,
        cert.display(),
        key.display(),
        ca.display(),
        root.display(),
        staging.display(),
        state_db.display()
    );

    let config_path = tmp.join("server.toml");
    fs::write(&config_path, &toml_content).unwrap();

    // Set overrides
    std::env::set_var("VELCRUX_NETWORK_LISTEN", "127.0.0.1:8443");
    std::env::set_var("VELCRUX_NETWORK_MAX_BANDWIDTH", "5Gbps");
    std::env::set_var("VELCRUX_TRANSFER_PARALLELISM", "16");
    std::env::set_var("VELCRUX_QUIC_RECEIVE_WINDOW", "512MiB");

    let cfg = ServerConfig::load(&config_path).expect("valid configuration load");

    assert_eq!(cfg.network.listen, "127.0.0.1:8443");
    assert_eq!(cfg.network.max_bandwidth.as_deref(), Some("5Gbps"));
    assert_eq!(cfg.transfer.parallelism, Some(16));
    assert_eq!(cfg.quic.receive_window, "512MiB");

    // Clean up env
    std::env::remove_var("VELCRUX_NETWORK_LISTEN");
    std::env::remove_var("VELCRUX_NETWORK_MAX_BANDWIDTH");
    std::env::remove_var("VELCRUX_TRANSFER_PARALLELISM");
    std::env::remove_var("VELCRUX_QUIC_RECEIVE_WINDOW");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_fail_closed_validations() {
    let tmp = setup_temp_dir("fail_closed");
    let cert = tmp.join("server.crt");
    let key = tmp.join("server.key");
    let ca = tmp.join("clients-ca.crt");
    fs::write(&cert, "dummy-cert").unwrap();
    fs::write(&key, "dummy-key").unwrap();
    fs::write(&ca, "dummy-ca").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Insecure permissions: 0644 (world readable)
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let toml_insecure_key = format!(
        r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"

[storage]
root    = "{}"
staging = "{}"
"#,
        cert.display(),
        key.display(),
        ca.display(),
        tmp.display(),
        tmp.display()
    );

    let config_path = tmp.join("insecure_key.toml");
    fs::write(&config_path, &toml_insecure_key).unwrap();

    #[cfg(unix)]
    {
        let res = ServerConfig::load(&config_path);
        assert!(res.is_err());
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("group/world readable"));
    }

    // Fix key permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Invalid permission string in grant
    let toml_bad_perm = format!(
        r#"
[network]
listen = "127.0.0.1:7443"

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"

[storage]
root    = "{}"
staging = "{}"

[[grant]]
identity    = "user1"
path        = "/data"
permissions = ["upload", "superuser_all"]
"#,
        cert.display(),
        key.display(),
        ca.display(),
        tmp.display(),
        tmp.display()
    );

    let bad_perm_path = tmp.join("bad_perm.toml");
    fs::write(&bad_perm_path, &toml_bad_perm).unwrap();
    let res = ServerConfig::load(&bad_perm_path);
    assert!(res.is_err());
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("unknown permission"));

    // Invalid listen address
    let toml_bad_addr = format!(
        r#"
[network]
listen = "not_an_ip_or_port"

[security]
certificate = "{}"
private_key = "{}"
client_ca   = "{}"

[storage]
root    = "{}"
staging = "{}"
"#,
        cert.display(),
        key.display(),
        ca.display(),
        tmp.display(),
        tmp.display()
    );

    let bad_addr_path = tmp.join("bad_addr.toml");
    fs::write(&bad_addr_path, &toml_bad_addr).unwrap();
    let res = ServerConfig::load(&bad_addr_path);
    assert!(res.is_err());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_parse_size_bytes_utility() {
    assert_eq!(parse_size_bytes("256KiB").unwrap(), 256 * 1024);
    assert_eq!(parse_size_bytes("1MiB").unwrap(), 1024 * 1024);
    assert_eq!(parse_size_bytes("384MiB").unwrap(), 384 * 1024 * 1024);
    assert_eq!(parse_size_bytes("1GiB").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(
        parse_size_bytes("64TiB").unwrap(),
        64 * 1024 * 1024 * 1024 * 1024
    );
    assert_eq!(parse_size_bytes("1048576").unwrap(), 1048576);
}
