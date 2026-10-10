//! Integration tests for Option AR: Architecture Decision Records & Production Deployment Packaging
//!
//! (`REQUIREMENTS.md` §76, §77, §78, §80; `OPERATIONS.md` §2, §9, §26).
//!
//! Verifies:
//! 1. Linux systemd service unit generator for server daemon and client worker.
//! 2. macOS launchd daemon property list generator.
//! 3. Kubernetes production StatefulSet & Service manifest generator.
//! 4. Multi-stage hardened Dockerfile generator.
//! 5. Direct file output writing and directory creation.

#![forbid(unsafe_code)]

use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_systemd_server_unit_structure() {
    let unit = velcrux_client::package::generate_systemd_unit(
        true,
        Path::new("/usr/local/bin/velcruxd"),
        Path::new("/etc/velcrux/server.toml"),
        "velcrux",
        "16G",
        131072,
    );

    assert!(unit.contains("[Unit]"));
    assert!(unit.contains("Description=velcrux transfer server daemon"));
    assert!(unit.contains("[Service]"));
    assert!(unit.contains("User=velcrux"));
    assert!(unit.contains("Group=velcrux"));
    assert!(
        unit.contains("ExecStart=/usr/local/bin/velcruxd run --config /etc/velcrux/server.toml")
    );
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("KillSignal=SIGTERM"));
    assert!(unit.contains("NoNewPrivileges=true"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("ReadWritePaths=/var/lib/velcrux /data/velcrux"));
    assert!(unit.contains("MemoryMax=16G"));
    assert!(unit.contains("LimitNOFILE=131072"));
    assert!(unit.contains("[Install]"));
    assert!(unit.contains("WantedBy=multi-user.target"));
}

#[test]
fn test_systemd_client_worker_unit_structure() {
    let unit = velcrux_client::package::generate_systemd_unit(
        false,
        Path::new("/opt/bin/velcrux"),
        Path::new("/etc/velcrux/client.toml"),
        "transferuser",
        "4G",
        65536,
    );

    assert!(unit.contains("Description=velcrux transfer client worker"));
    assert!(unit.contains("User=transferuser"));
    assert!(unit.contains("ExecStart=/opt/bin/velcrux sync --config /etc/velcrux/client.toml"));
    assert!(unit.contains("ReadWritePaths=/var/lib/velcrux"));
    assert!(unit.contains("MemoryMax=4G"));
    assert!(unit.contains("LimitNOFILE=65536"));
}

#[test]
fn test_launchd_plist_structure() {
    let plist = velcrux_client::package::generate_launchd_plist(
        Path::new("/usr/local/bin/velcruxd"),
        Path::new("/etc/velcrux/server.toml"),
        Path::new("/var/log/velcrux/velcruxd.log"),
    );

    assert!(plist.contains("com.velcrux.velcruxd"));
    assert!(plist.contains("<key>RunAtLoad</key>"));
    assert!(plist.contains("<true/>"));
    assert!(plist.contains("<key>KeepAlive</key>"));
    assert!(plist.contains("<string>/var/log/velcrux/velcruxd.log</string>"));
    assert!(plist.contains("<string>/var/log/velcrux/velcruxd.err</string>"));
    assert!(plist.contains("<integer>65536</integer>"));
}

#[test]
fn test_kubernetes_manifest_structure() {
    let k8s =
        velcrux_client::package::generate_k8s_manifest("ghcr.io/org/velcrux:v1.2.3", 7443, 9443);

    assert!(k8s.contains("kind: Service"));
    assert!(k8s.contains("name: velcruxd"));
    assert!(k8s.contains("port: 7443"));
    assert!(k8s.contains("port: 9443"));
    assert!(k8s.contains("kind: StatefulSet"));
    assert!(k8s.contains("image: ghcr.io/org/velcrux:v1.2.3"));
    assert!(k8s.contains("runAsNonRoot: true"));
    assert!(k8s.contains("readOnlyRootFilesystem: true"));
    assert!(k8s.contains("drop:"));
    assert!(k8s.contains("- ALL"));
    assert!(k8s.contains("path: /metrics"));
}

#[test]
fn test_dockerfile_structure() {
    let dockerfile = velcrux_client::package::generate_dockerfile();

    assert!(dockerfile.contains("FROM rust:1.80-slim-bookworm AS builder"));
    assert!(dockerfile.contains("cargo build --release"));
    assert!(dockerfile.contains("FROM debian:bookworm-slim"));
    assert!(dockerfile.contains("groupadd -g 10001 velcrux"));
    assert!(dockerfile.contains("USER velcrux:velcrux"));
    assert!(dockerfile.contains("EXPOSE 7443/udp 9443/tcp"));
}

#[test]
fn test_execute_package_target_writes_file() {
    let temp_dir = tempdir().unwrap();
    let dest_file = temp_dir.path().join("sub/velcruxd.service");

    let target = velcrux_client::package::PackageTarget::Systemd {
        server: true,
        binary: "/usr/local/bin/velcruxd".into(),
        config: "/etc/velcrux/server.toml".into(),
        user: "velcrux".into(),
        memory_max: "8G".into(),
        nofile: 65536,
        output: Some(dest_file.clone()),
    };

    let res = velcrux_client::package::execute_package_target(target, false);
    assert!(res.is_ok());

    assert!(dest_file.exists());
    let content = std::fs::read_to_string(&dest_file).unwrap();
    assert!(content.contains("[Service]"));
    assert!(content.contains("velcruxd run"));
}
