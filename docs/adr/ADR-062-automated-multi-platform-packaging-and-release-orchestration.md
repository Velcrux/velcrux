# ADR-062: Automated Multi-Platform Packaging, Distribution & Release Orchestration

- **Status**: Accepted
- **Date**: 2026-11-02
- **Deciders**: Velcrux Core Architecture, DevOps, Platform Engineering, and SRE Working Group
- **Consulted**: SRE, Security, Systems Architecture, and Release Engineering

---

## 1. Context and Problem Statement

Velcrux is an enterprise-grade high-throughput bulk transfer engine designed for heterogeneous production environments spanning Linux (cloud instances, high-performance edge compute, bare-metal servers), macOS (workstations, dev laptops), and Windows (enterprise servers). 

While the core Raven Protocol over QUIC, mTLS, SQLite WAL persistence, FastCDC, and enterprise features (ADRs 001–061) are fully implemented and verified in code, production adoption requires turnkey, reproducible, and verifiable delivery channels. Distributing bare raw binaries or requiring manual compilation from source introduces operational friction, non-standard system service configurations, unvetted update mechanisms, and security verification gaps.

Specifically, production operators require:
1. **Native OS Package Management**: Installation via standard tools (`brew install velcrux`, `apt install velcrux`, `dnf install velcrux`, `scoop install velcrux`, `winget install velcrux`).
2. **Cloud-Native Kubernetes Deployment**: A production-ready Helm chart (`packaging/helm/velcrux/`) configuring StatefulSets, dual-port UDP/TCP services, Persistent Volume Claims (PVCs), and Prometheus Operator ServiceMonitors.
3. **Multi-Architecture Static & Dynamic Binaries**: Linux glibc and musl (x86_64, aarch64), macOS (Intel and Apple Silicon), and Windows x64.
4. **Dual Cryptographic Checksums**: First-class **BLAKE3SUMS.txt** integrity alongside backward-compatible **SHA256SUMS.txt**.
5. **Multi-Arch OCI Container Images**: Automated container builds and publishing to GitHub Container Registry (`ghcr.io/velcrux/velcrux`).
6. **Programmatic Generator CLI**: Ability to generate all deployment manifests directly via `velcrux package` subcommands.

---

## 2. Decision Drivers

- **Zero-Friction Operator Experience**: Installation should take a single command across macOS, Ubuntu/Debian, Fedora/RHEL, Arch Linux, Windows, and Kubernetes.
- **Reproducible & Verifiable Delivery**: Cryptographic checksum manifests (BLAKE3 and SHA-256) generated deterministically in CI.
- **Strict Security Defaults**: Default systemd and Kubernetes manifests enforce least privilege (`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `drop: [ALL]`, unprivileged `velcrux:velcrux` user/group).
- **Pure Safe Rust Generator Integration**: Manifest generators embedded within `velcrux-client` via `velcrux package` obeying `#![forbid(unsafe_code)]`.
- **Cloud-Native Observability Out of the Box**: Standardized Prometheus telemetry endpoints (`/metrics` on TCP 9443) wired into Kubernetes readiness/liveness probes and ServiceMonitors.

---

## 3. Considered Options

- **Option 1: Ad-hoc Manual Release Builds & Static GitHub Assets**:
  - *Cons*: High human error, missing package managers, non-standard systemd service placement, manual container builds.
- **Option 2: Third-Party Complex External Packaging Frameworks (e.g. Goreleaser / Cargo-Dist only)**:
  - *Cons*: Introduces complex external DSLs and heavy dependencies; lacks direct CLI generation for air-gapped environments.
- **Option 3 (Chosen): Multi-Platform Packaging Matrix & Integrated CLI Generator Pipeline (`Option CT`)**:
  - First-class native package specifications in `packaging/`:
    - Kubernetes Helm Chart (`packaging/helm/velcrux/`)
    - macOS & Linux Homebrew Formula (`packaging/homebrew/velcrux.rb`)
    - Debian / Ubuntu `.deb` control scripts (`packaging/debian/`) and builder (`packaging/build-deb.sh`)
    - Red Hat / Fedora RPM Spec (`packaging/rpm/velcrux.spec`)
    - Arch Linux PKGBUILD (`packaging/arch/PKGBUILD`)
    - Windows Scoop (`packaging/scoop/velcrux.json`) and Winget (`packaging/winget/velcrux.yaml`)
  - Direct operator CLI generator via `velcrux package [systemd|launchd|k8s|docker|helm|homebrew|debian|rpm|scoop|winget]`.
  - Automated GitHub Actions release pipeline (`.github/workflows/release.yml`) cross-compiling 7 targets, building `.deb` packages, generating multi-arch container images on GHCR, and publishing releases with `BLAKE3SUMS.txt` and `SHA256SUMS.txt`.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        VELCRUX PACKAGING & RELEASE PIPELINE                            │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
         ┌──────────────────────────────────┼──────────────────────────────────┐
         │                                  │                                  │
         ▼                                  ▼                                  ▼
┌───────────────────┐             ┌───────────────────┐              ┌───────────────────┐
│ OS Package Mgrs   │             │ Cloud-Native OCI  │              │ Operator CLI Gen  │
├───────────────────┤             ├───────────────────┤              ├───────────────────┤
│ • Homebrew Formula│             │ • Multi-Arch OCI  │              │ `velcrux package`:│
│ • Debian (.deb)   │             │   (linux/amd64,   │              │ • systemd         │
│ • Red Hat (.rpm)  │             │    linux/arm64)   │              │ • launchd         │
│ • Arch PKGBUILD   │             │ • GHCR registry   │              │ • k8s & helm      │
│ • Windows Scoop   │             │ • Helm Chart v2   │              │ • homebrew        │
│ • Windows Winget  │             │   (StatefulSet +  │              │ • debian & rpm    │
│ • Shell Comp      │             │    ServiceMonitor)│              │ • scoop & winget  │
└───────────────────┘             └───────────────────┘              └───────────────────┘
```

---

## 5. Verification & Testing

1. **Unit & Integration Tests**:
   - `crates/velcrux-client/tests/cli_deployment_packaging.rs` executes 13 automated tests verifying:
     - Helm values structure and parameter propagation.
     - Homebrew Ruby formula syntax and architecture branching.
     - Debian control format and dependencies.
     - RPM spec macros and systemd scriptlets.
     - Scoop and Winget manifests.
     - Direct file generation and directory creation across all targets.
2. **Acceptance Criteria**:
   - Definition of Done Acceptance Criteria 1–15 pass 100%.

