//! Production deployment packaging and service unit generator (Option AR).
//!
//! (`REQUIREMENTS.md` §76, §77, §78, §80; `OPERATIONS.md` §2, §9, §26).
//!
//! Generates production-ready, security-hardened service configurations:
//! - Linux systemd units (`velcruxd.service` / `velcrux.service`) with sandboxing.
//! - macOS launchd property lists (`com.velcrux.velcruxd.plist`).
//! - Kubernetes manifests (StatefulSet + LoadBalancer Service with hardened securityContext).
//! - Multi-stage hardened Dockerfile.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;

#[derive(Subcommand, Debug, Clone)]
pub enum PackageTarget {
    /// Generate Linux systemd service unit (.service).
    Systemd {
        /// Generate server daemon unit (velcruxd.service) instead of client worker unit.
        #[arg(long)]
        server: bool,
        /// Path to binary.
        #[arg(long, default_value = "/usr/local/bin/velcruxd")]
        binary: PathBuf,
        /// Path to configuration file.
        #[arg(long, default_value = "/etc/velcrux/server.toml")]
        config: PathBuf,
        /// System user to execute service as.
        #[arg(long, default_value = "velcrux")]
        user: String,
        /// MemoryMax ceiling (e.g. 8G, 16G).
        #[arg(long, default_value = "8G")]
        memory_max: String,
        /// LimitNOFILE open file descriptor ceiling.
        #[arg(long, default_value = "65536")]
        nofile: u64,
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate macOS launchd daemon property list (.plist).
    Launchd {
        /// Path to velcruxd binary.
        #[arg(long, default_value = "/usr/local/bin/velcruxd")]
        binary: PathBuf,
        /// Path to configuration file.
        #[arg(long, default_value = "/etc/velcrux/server.toml")]
        config: PathBuf,
        /// Path to log output file.
        #[arg(long, default_value = "/var/log/velcrux/velcruxd.log")]
        log_path: PathBuf,
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate Kubernetes production StatefulSet & Service manifest (.yaml).
    K8s {
        /// Container image reference.
        #[arg(long, default_value = "ghcr.io/velcrux/velcrux:v0.1.0")]
        image: String,
        /// QUIC UDP port.
        #[arg(long, default_value = "7443")]
        quic_port: u16,
        /// Prometheus telemetry TCP port.
        #[arg(long, default_value = "9443")]
        metrics_port: u16,
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate production hardened multi-stage Dockerfile.
    Docker {
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

/// Generate a production-hardened systemd service unit.
pub fn generate_systemd_unit(
    server: bool,
    binary: &Path,
    config: &Path,
    user: &str,
    memory_max: &str,
    nofile: u64,
) -> String {
    let desc = if server {
        "velcrux transfer server daemon"
    } else {
        "velcrux transfer client worker"
    };

    let read_write_paths = if server {
        "/var/lib/velcrux /data/velcrux"
    } else {
        "/var/lib/velcrux"
    };

    let command_args = if server {
        format!("{} run --config {}", binary.display(), config.display())
    } else {
        format!("{} sync --config {}", binary.display(), config.display())
    };

    format!(
        r#"[Unit]
Description={desc}
Documentation=https://github.com/Velcrux/velcrux
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
EnvironmentFile=-/etc/velcrux/velcruxd.env
ExecStart={command_args}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=120

# Graceful drain: stop accepting, flush checkpoints, close sessions
KillSignal=SIGTERM

# Linux security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={read_write_paths}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
MemoryMax={memory_max}
LimitNOFILE={nofile}

[Install]
WantedBy=multi-user.target
"#
    )
}

/// Generate macOS launchd daemon property list (.plist).
pub fn generate_launchd_plist(binary: &Path, config: &Path, log_path: &Path) -> String {
    let err_path = log_path.with_extension("err");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.velcrux.velcruxd</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>run</string>
        <string>--config</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>HardResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
</dict>
</plist>
"#,
        binary.display(),
        config.display(),
        log_path.display(),
        err_path.display(),
    )
}

/// Generate a production Kubernetes StatefulSet & Service manifest.
pub fn generate_k8s_manifest(image: &str, quic_port: u16, metrics_port: u16) -> String {
    format!(
        r#"apiVersion: v1
kind: Service
metadata:
  name: velcruxd
  labels:
    app.kubernetes.io/name: velcruxd
spec:
  type: LoadBalancer
  ports:
    - name: quic
      port: {quic_port}
      protocol: UDP
      targetPort: {quic_port}
    - name: metrics
      port: {metrics_port}
      protocol: TCP
      targetPort: {metrics_port}
  selector:
    app.kubernetes.io/name: velcruxd
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: velcruxd
  labels:
    app.kubernetes.io/name: velcruxd
spec:
  serviceName: velcruxd
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: velcruxd
  template:
    metadata:
      labels:
        app.kubernetes.io/name: velcruxd
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
      containers:
        - name: velcruxd
          image: {image}
          imagePullPolicy: IfNotPresent
          command:
            - /usr/local/bin/velcruxd
            - run
            - --config
            - /etc/velcrux/server.toml
          ports:
            - name: quic
              containerPort: {quic_port}
              protocol: UDP
            - name: metrics
              containerPort: {metrics_port}
              protocol: TCP
          envFrom:
            - configMapRef:
                name: velcrux-config
                optional: true
            - secretRef:
                name: velcrux-secrets
                optional: true
          resources:
            requests:
              cpu: "1000m"
              memory: "2Gi"
            limits:
              cpu: "8000m"
              memory: "8Gi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          readinessProbe:
            httpGet:
              path: /metrics
              port: {metrics_port}
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /metrics
              port: {metrics_port}
            initialDelaySeconds: 15
            periodSeconds: 20
          volumeMounts:
            - name: storage
              mountPath: /data/velcrux
            - name: state
              mountPath: /var/lib/velcrux
            - name: config
              mountPath: /etc/velcrux
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: config
          configMap:
            name: velcrux-server-config
        - name: tmp
          emptyDir: {{}}
  volumeClaimTemplates:
    - metadata:
        name: storage
      spec:
        accessModes: [ "ReadWriteOnce" ]
        resources:
          requests:
            storage: 1Ti
    - metadata:
        name: state
      spec:
        accessModes: [ "ReadWriteOnce" ]
        resources:
          requests:
            storage: 50Gi
"#
    )
}

/// Generate production hardened multi-stage Dockerfile.
pub fn generate_dockerfile() -> String {
    r#"# Multi-Stage Production Dockerfile (docs/REQUIREMENTS.md §77)
FROM rust:1.80-slim-bookworm AS builder
WORKDIR /usr/src/velcrux
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config build-essential && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY deploy ./deploy
RUN cargo build --release -p velcrux-server -p velcrux-client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10001 velcrux && useradd -u 10001 -g velcrux -m -s /bin/bash velcrux
RUN mkdir -p /etc/velcrux /var/lib/velcrux /data/velcrux/files/.velcrux-staging /data/velcrux/chunks && chown -R velcrux:velcrux /etc/velcrux /var/lib/velcrux /data/velcrux
COPY --from=builder /usr/src/velcrux/target/release/velcruxd /usr/local/bin/velcruxd
COPY --from=builder /usr/src/velcrux/target/release/velcrux /usr/local/bin/velcrux
EXPOSE 7443/udp 9443/tcp
USER velcrux:velcrux
WORKDIR /var/lib/velcrux
VOLUME ["/data/velcrux", "/var/lib/velcrux", "/etc/velcrux"]
ENTRYPOINT ["/usr/local/bin/velcruxd"]
CMD ["run", "--config", "/etc/velcrux/server.toml"]
"#
    .to_string()
}

/// Execute packaging target.
pub fn execute_package_target(target: PackageTarget, json: bool) -> Result<()> {
    let (rendered, output_path, target_name) = match target {
        PackageTarget::Systemd {
            server,
            binary,
            config,
            user,
            memory_max,
            nofile,
            output,
        } => (
            generate_systemd_unit(server, &binary, &config, &user, &memory_max, nofile),
            output,
            "systemd",
        ),
        PackageTarget::Launchd {
            binary,
            config,
            log_path,
            output,
        } => (
            generate_launchd_plist(&binary, &config, &log_path),
            output,
            "launchd",
        ),
        PackageTarget::K8s {
            image,
            quic_port,
            metrics_port,
            output,
        } => (
            generate_k8s_manifest(&image, quic_port, metrics_port),
            output,
            "k8s",
        ),
        PackageTarget::Docker { output } => (generate_dockerfile(), output, "docker"),
    };

    if let Some(dest) = output_path {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
        fs::write(&dest, &rendered)
            .with_context(|| format!("writing manifest to {}", dest.display()))?;
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "success",
                    "target": target_name,
                    "output_file": dest.display().to_string(),
                })
            );
        } else {
            eprintln!("Wrote {} configuration to {}", target_name, dest.display());
        }
    } else if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "success",
                "target": target_name,
                "content": rendered,
            })
        );
    } else {
        print!("{rendered}");
    }

    Ok(())
}
