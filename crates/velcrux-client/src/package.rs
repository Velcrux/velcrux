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
    /// Generate Kubernetes Helm chart values.yaml.
    Helm {
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate macOS/Linux Homebrew formula (velcrux.rb).
    Homebrew {
        /// Version string (default: 0.1.0).
        #[arg(long, default_value = "0.1.0")]
        version: String,
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate Debian/Ubuntu packaging control file.
    Debian {
        /// Version string (default: 0.1.0).
        #[arg(long, default_value = "0.1.0")]
        version: String,
        /// Architecture (default: amd64).
        #[arg(long, default_value = "amd64")]
        arch: String,
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate RPM spec file (velcrux.spec).
    Rpm {
        /// Version string (default: 0.1.0).
        #[arg(long, default_value = "0.1.0")]
        version: String,
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate Windows Scoop bucket manifest (velcrux.json).
    Scoop {
        /// Version string (default: 0.1.0).
        #[arg(long, default_value = "0.1.0")]
        version: String,
        /// Write directly to destination file instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate Windows Package Manager (Winget) manifest.
    Winget {
        /// Version string (default: 0.1.0).
        #[arg(long, default_value = "0.1.0")]
        version: String,
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

/// Generate Kubernetes Helm chart values.yaml.
pub fn generate_helm_values() -> String {
    r#"# Default values for Velcrux server deployment.
replicaCount: 1

image:
  repository: ghcr.io/velcrux/velcrux
  pullPolicy: IfNotPresent
  tag: "v0.1.0"

service:
  type: LoadBalancer
  quicPort: 7443
  metricsPort: 9443

resources:
  limits:
    cpu: 8000m
    memory: 8Gi
  requests:
    cpu: 1000m
    memory: 2Gi

persistence:
  enabled: true
  accessMode: ReadWriteOnce
  dataSize: 1Ti
  stateSize: 50Gi

server:
  logLevel: "info,velcrux_server=debug,velcrux_core=debug"
  quic:
    maxBdpWindow: 536870912
    maxConcurrentStreams: 128
    idleTimeoutMs: 30000
  storage:
    backend: "local"
    dataDir: "/data/velcrux/files"
    stagingDir: "/data/velcrux/files/.velcrux-staging"
    chunkStoreDir: "/data/velcrux/chunks"
    stateDb: "/var/lib/velcrux/state.db"
    preallocate: true
    minFreeBytes: 10737418240
"#
    .to_string()
}

/// Generate macOS / Linux Homebrew formula (velcrux.rb).
pub fn generate_homebrew_formula(version: &str) -> String {
    format!(
        r##"class Velcrux < Formula
  desc "High-throughput, resumable, verifiable bulk data transfer over QUIC"
  homepage "https://github.com/Velcrux/velcrux"
  version "{version}"
  license "Apache-2.0 OR MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Velcrux/velcrux/releases/download/v#{{version}}/velcrux-v#{{version}}-darwin-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/Velcrux/velcrux/releases/download/v#{{version}}/velcrux-v#{{version}}-darwin-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Velcrux/velcrux/releases/download/v#{{version}}/velcrux-v#{{version}}-linux-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/Velcrux/velcrux/releases/download/v#{{version}}/velcrux-v#{{version}}-linux-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "velcrux"
    bin.install "velcruxd"

    if File.directory?("completions")
      bash_completion.install "completions/velcrux.bash" => "velcrux" if File.exist?("completions/velcrux.bash")
      zsh_completion.install "completions/_velcrux" => "_velcrux" if File.exist?("completions/_velcrux")
      fish_completion.install "completions/velcrux.fish" => "velcrux.fish" if File.exist?("completions/velcrux.fish")
    end

    (etc/"velcrux").mkpath
    (var/"lib/velcrux").mkpath
    (var/"log/velcrux").mkpath
  end

  service do
    run [opt_bin/"velcruxd", "run", "--config", etc/"velcrux/server.toml"]
    keep_alive true
    working_dir var/"lib/velcrux"
    log_path var/"log/velcrux/velcruxd.log"
    error_log_path var/"log/velcrux/velcruxd.err"
  end

  test do
    assert_match "velcrux client CLI", shell_output("#{{bin}}/velcrux --help")
  end
end
"##
    )
}

/// Generate Debian/Ubuntu packaging control file.
pub fn generate_debian_control(version: &str, arch: &str) -> String {
    format!(
        r#"Package: velcrux
Version: {version}
Section: utils
Priority: optional
Architecture: {arch}
Maintainer: Velcrux Core Team <maintainers@velcrux.io>
Depends: ca-certificates
Homepage: https://github.com/Velcrux/velcrux
Description: High-Throughput, Resumable, Verifiable Bulk Data Transfer over QUIC
 Velcrux is a high-performance transport system engineered for high
 Bandwidth-Delay Product (BDP) environments (1-10 Gbps, 50-300ms RTT) over QUIC
 with TLS 1.3 mTLS, FastCDC content-defined chunking, and BLAKE3 verification.
"#
    )
}

/// Generate RPM spec file.
pub fn generate_rpm_spec(version: &str) -> String {
    format!(
        r#"Name:           velcrux
Version:        {version}
Release:        1%{{?dist}}
Summary:        High-Throughput, Resumable, Verifiable Bulk Data Transfer over QUIC

License:        Apache-2.0 OR MIT
URL:            https://github.com/Velcrux/velcrux
Source0:        velcrux-%{{version}}.tar.gz

BuildRequires:  systemd-rpm-macros
Requires:       ca-certificates

%description
Velcrux is an open-source bulk data transfer system engineered for high
Bandwidth-Delay Product (BDP) environments over QUIC with TLS 1.3 mTLS,
FastCDC content-defined chunking, and whole-file BLAKE3 verification.

%install
rm -rf %{{buildroot}}
mkdir -p %{{buildroot}}%{{_bindir}}
mkdir -p %{{buildroot}}%{{_unitdir}}
mkdir -p %{{buildroot}}%{{_sysconfdir}}/velcrux

install -m 0755 velcrux %{{buildroot}}%{{_bindir}}/velcrux
install -m 0755 velcruxd %{{buildroot}}%{{_bindir}}/velcruxd

%files
%license LICENSE-APACHE LICENSE-MIT
%doc README.md
%{{_bindir}}/velcrux
%{{_bindir}}/velcruxd
"#
    )
}

/// Generate Windows Scoop manifest.
pub fn generate_scoop_manifest(version: &str) -> String {
    format!(
        r#"{{
    "version": "{version}",
    "description": "High-Throughput, Resumable, Verifiable Bulk Data Transfer over QUIC",
    "homepage": "https://github.com/Velcrux/velcrux",
    "license": {{
        "identifier": "Apache-2.0 OR MIT",
        "url": "https://github.com/Velcrux/velcrux/blob/main/LICENSE-APACHE"
    }},
    "architecture": {{
        "64bit": {{
            "url": "https://github.com/Velcrux/velcrux/releases/download/v{version}/velcrux-v{version}-windows-amd64.zip",
            "hash": "0000000000000000000000000000000000000000000000000000000000000000"
        }}
    }},
    "bin": [
        "velcrux.exe",
        "velcruxd.exe"
    ],
    "persist": "data",
    "checkver": "github",
    "autoupdate": {{
        "architecture": {{
            "64bit": {{
                "url": "https://github.com/Velcrux/velcrux/releases/download/v$version/velcrux-v$version-windows-amd64.zip"
            }}
        }}
    }}
}}
"#
    )
}

/// Generate Windows Winget manifest.
pub fn generate_winget_manifest(version: &str) -> String {
    format!(
        r#"PackageIdentifier: Velcrux.Velcrux
PackageVersion: {version}
PackageName: Velcrux
Publisher: Velcrux Core Team
License: Apache-2.0 OR MIT
ShortDescription: High-Throughput, Resumable, Verifiable Bulk Data Transfer over QUIC
PackageUrl: https://github.com/Velcrux/velcrux
Installers:
  - Architecture: x64
    InstallerType: zip
    InstallerUrl: https://github.com/Velcrux/velcrux/releases/download/v{version}/velcrux-v{version}-windows-amd64.zip
    InstallerSha256: 0000000000000000000000000000000000000000000000000000000000000000
    NestedInstallerType: portable
    NestedInstallerFiles:
      - RelativeFilePath: velcrux.exe
        PortableCommandAlias: velcrux
      - RelativeFilePath: velcruxd.exe
        PortableCommandAlias: velcruxd
ManifestType: singleton
ManifestVersion: 1.6.0
"#
    )
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
        PackageTarget::Helm { output } => (generate_helm_values(), output, "helm"),
        PackageTarget::Homebrew { version, output } => {
            (generate_homebrew_formula(&version), output, "homebrew")
        }
        PackageTarget::Debian {
            version,
            arch,
            output,
        } => (generate_debian_control(&version, &arch), output, "debian"),
        PackageTarget::Rpm { version, output } => (generate_rpm_spec(&version), output, "rpm"),
        PackageTarget::Scoop { version, output } => {
            (generate_scoop_manifest(&version), output, "scoop")
        }
        PackageTarget::Winget { version, output } => {
            (generate_winget_manifest(&version), output, "winget")
        }
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
