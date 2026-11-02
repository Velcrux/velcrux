# ADR-063: Kubernetes Operator & Declarative Custom Resource Definitions (CRDs)

- **Status**: Accepted
- **Date**: 2026-11-02
- **Deciders**: Velcrux Core Architecture, Cloud-Native, DevOps, and Platform Engineering Working Group
- **Consulted**: SRE, Distributed Systems, Storage Infrastructure, and Kubernetes Platform Teams

---

## 1. Context and Problem Statement

As Velcrux is deployed in modern cloud-native environments (AWS EKS, GCP GKE, Azure AKS, and on-premise bare-metal Kubernetes clusters), managing high-throughput data replication pipelines through imperative CLI commands or ad-hoc cron jobs introduces major operational liabilities:
1. **Lack of Declarative Infrastructure**: Transfers, synchronization schedules, and multi-node clusters cannot be version-controlled, reviewed via GitOps (ArgoCD/Flux), or managed declaratively alongside application workloads.
2. **Missing Failure Reconciliation**: Transient network partitions, QUIC stream resets, or node restarts require manual intervention or custom wrapper scripts rather than self-healing Kubernetes reconciliation loops with exponential backoff.
3. **Cluster Topology Management**: Setting up 3-node or 5-node Raft consensus clusters (`ADR-042`) requires orchestrating headless peer discovery services, volume claim templates, and mTLS secret mounts manually.
4. **Status & Observability Gaps**: Platform engineers lack native Kubernetes visibility (`kubectl get vxt`, `kubectl describe vxcluster`) into transfer progress, chunk deduplication savings, and active BLAKE3 hash verification states.

---

## 2. Decision Drivers

- **Kubernetes-Native Declarative Control**: Full GitOps compatibility using standard Kubernetes Custom Resource Definitions (CRDs).
- **Automated Self-Healing Reconciliation**: The controller must automatically reconcile desired state against observed state, transitioning resources through well-defined phases (`Pending`, `Scheduled`, `InProgress`, `Verifying`, `Committed`, `Retrying`, `Failed`).
- **Resilient Exponential Backoff**: Transient errors (e.g. network timeouts, link flap) trigger bounded exponential backoff retries without human intervention.
- **Pure Safe Rust Engine**: Core CRD data structures, OpenAPI v3 manifest generation, YAML/JSON parsing, and reconciliation logic implemented strictly in safe Rust (`#![forbid(unsafe_code)]`).
- **Operator CLI Ergonomics**: Operators can generate CRD schemas, RBAC manifests, validate manifests, and execute dry-run reconciliation passes directly using `velcrux k8s`.

---

## 3. Considered Options

- **Option 1: Rely solely on standard Kubernetes CronJobs and Pods**:
  - *Cons*: No state tracking, no deduplication ratio status, no exponential backoff or dynamic requeue, no CRD status subresources, verbose pod specifications for every transfer.
- **Option 2: External Go-based Kubebuilder / Operator-SDK Controller**:
  - *Cons*: Creates a bifurcated codebase with separate language toolchains (Go vs Rust); duplicates transfer domain logic and limits compatibility.
- **Option 3 (Chosen): Pure Safe Rust Kubernetes Operator & Declarative CRDs (`Option CU`)**:
  - Native CRDs registered under `velcrux.io/v1alpha1`:
    - `VelcruxCluster`: Manages multi-node Raft storage clusters, volume claim templates, and mTLS secrets.
    - `VelcruxTransfer`: Manages declarative bulk transfers, cron scheduling, BDP auto-tuning, deduplication, and retry policies.
  - Built-in `OperatorReconciler` state machine executing validation, phase transitions, backoff calculation, and Kubernetes Event emission.
  - Manifest generators producing OpenAPI v3 YAML (`velcrux k8s crd`) and Operator RBAC/Deployment manifests (`velcrux k8s operator-manifest`).
  - Integrated into the Helm chart under `packaging/helm/velcrux/crds/`.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        KUBERNETES OPERATOR RECONCILIATION LOOP                         │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                            │
        ┌───────────────────────────────────┼───────────────────────────────────┐
        │                                   │                                   │
        ▼                                   ▼                                   ▼
┌───────────────────────┐       ┌───────────────────────┐       ┌───────────────────────┐
│     VelcruxCluster    │       │    VelcruxTransfer    │       │   OperatorReconciler  │
├───────────────────────┤       ├───────────────────────┤       ├───────────────────────┤
│ • Replicas: 3 / 5     │       │ • Source URL          │       │ • Phase Transitions:  │
│ • Storage: local/s3   │       │ • Destination Path    │       │   Pending -> Sched -> │
│ • Capacity: 1Ti PVC   │       │ • Cron Schedule       │       │   InProgress ->       │
│ • Ports: 7443 UDP,    │       │ • Priority: Urgent    │       │   Verifying -> Commit │
│   9443 TCP, 9444 Raft │       │ • Concurrency: 1..16  │       │ • Exponential Backoff:│
│ • DeletionPolicy:     │       │ • BDP: auto (512 MiB) │       │   Retrying (5s..300s) │
│   admin_only          │       │ • RetryPolicy         │       │ • K8s Event Emission  │
└───────────────────────┘       └───────────────────────┘       └───────────────────────┘
```

---

## 5. Verification & Testing

- **Core Module Tests**: 7 unit tests in `crates/velcrux-core/src/k8s/mod.rs` verifying specification validation, defaults, exponential backoff progression, lifecycle phases, and error handling.
- **CLI Integration Tests**: 8 end-to-end integration tests in `crates/velcrux-client/tests/cli_k8s.rs` verifying:
  - `velcrux k8s crd --kind cluster`
  - `velcrux k8s crd --kind transfer`
  - `velcrux k8s crd --output <file>`
  - `velcrux k8s operator-manifest --image <img --namespace <ns>`
  - `velcrux k8s validate --file <manifest> --json`
  - `velcrux k8s reconcile --file <manifest> --json`
  - `velcrux k8s reconcile --simulate-failure <err> --json`

