# ADR-061: Hardware Security Module (HSM) PKCS#11 & Cloud KMS Key Orchestration Bridge

- **Status**: Accepted
- **Date**: 2026-11-02
- **Deciders**: Velcrux Core Architecture, Security, Cryptography, and SRE Working Group
- **Consulted**: Enterprise Security Architecture, Cryptographic Engineering, Compliance & SRE

---

## 1. Context and Problem Statement

Velcrux clusters orchestrate multi-tenant, zero-trust transfer pipelines handling mission-critical, regulated enterprise payloads. With the integration of Post-Quantum Cryptography (`ADR-046`), Encrypted Staging Vaults (`ADR-059`), and Merkle DAG Provenance Logs (`ADR-053`), storage nodes require cryptographic root keys to:
1. Wrap and unwrap Staging Vault Data Encryption Keys (DEKs).
2. Protect recipient post-quantum key encapsulation keypairs (ML-KEM-768 / Kyber).
3. Produce tamper-proof digital signatures over chunk manifests and provenance inclusion proofs (ML-DSA-65 / Dilithium / HMAC-BLAKE3).

However, storing plaintext root Key Encryption Keys (KEKs) in server local configuration files or on local NVMe disks introduces severe security risks:
- **Disk Compromise & Exfiltration Risk**: Node disk theft, unauthorized snapshot clones, or hypervisor memory breaches expose root master keys, enabling bulk retrospective decryption across all historical staging vaults.
- **Cross-Tenant Ciphertext Replay**: An attacker who intercepts a wrapped key envelope from Tenant A could attempt to unwrap it in Tenant B's staging vault unless cryptographically bound to operational context.
- **Enterprise Regulatory Non-Compliance**: Regulated deployments (FIPS 140-3 Level 3, PCI-DSS v4.0, HIPAA, FedRAMP High, Common Criteria EAL4+) mandate that root keys never leave certified Hardware Security Module boundaries in plaintext.
- **Multi-Cloud Key Governance Fragmentation**: Enterprise nodes run across heterogeneous cloud and bare-metal environments (AWS, GCP, Azure, on-premise HSM appliances, and Nitro Enclaves), requiring a unified abstraction layer.

---

## 2. Decision Drivers

- **Zero Plaintext Root Keys on Node Disk**: Root master Key Encryption Keys (KEKs) must remain strictly confined within hardware HSM boundaries or Cloud KMS endpoints. Nodes only ever persist authenticated ciphertext envelopes (`WrappedKeyEnvelope`).
- **Cryptographic Encryption Context Binding**: Master key wrapping must bind operational metadata (tenant ID, key ID, version, and purpose) directly into ChaCha20-Poly1305 / AES-256-KW Associated Authenticated Data (AAD). Any modification to context immediately rejects unwrapping.
- **Multi-Provider Enterprise Pluggability**: Standardized abstraction supporting OASIS PKCS#11 v2.40/v3.0 tokens alongside AWS KMS, GCP Cloud KMS, Azure Key Vault / Managed HSM, HashiCorp Vault Transit Engine, and AWS Nitro Enclaves NSM attestation.
- **Pure Safe Rust Implementation**: Complete elimination of undefined behavior, memory corruption vulnerabilities, and buffer overflows via `#![forbid(unsafe_code)]` with zero external C/kernel FFI dependencies.
- **Master Key Versioning & Zero-Downtime Rotation**: Ability to rotate master keys to new cryptographic generations with monotonic version tracking, generating cryptographic fingerprints and audit trail entries without invalidating historical wrapped envelopes.
- **Sub-Microsecond Operational Performance**: In-memory caching, optimized symmetric key wrapping, and high-performance HMAC-BLAKE3 signing with microsecond benchmark validation.

---

## 3. Considered Options

- **Option 1: Node-Local Encrypted Master Key Files with Passphrase/Env Secrets**:
  - *Cons*: Fails FIPS 140-3 compliance; vulnerable to process memory dumping; no centralized audit logging or multi-cloud key rotation.
- **Option 2: Direct Vendor C FFI Bindings (`libcrypto.so`, `libpkcs11.so`, `aws-sdk-cpp`)**:
  - *Cons*: Violates `#![forbid(unsafe_code)]`; introduces heavy native dynamic linker dependencies, memory safety vulnerabilities, and portability issues across macOS and Linux.
- **Option 3 (Chosen): Hardware Security Module (HSM) PKCS#11 & Cloud KMS Key Orchestration Bridge (`HsmKmsBridge`)**:
  - Pure safe Rust root-of-trust orchestration engine with full software token emulation of OASIS PKCS#11.
  - Multi-provider abstraction for AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault Transit, and AWS Nitro Enclaves.
  - Cryptographic context binding via ChaCha20-Poly1305 AEAD and BLAKE3 context canonicalization.
  - Operator CLI subcommands (`velcrux kms [status|wrap|unwrap|sign|verify|rotate|benchmark]`).
  - Prometheus metrics instrumentation (`velcrux_hsm_kms_*`).

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      VELCRUX HSM / CLOUD KMS ORCHESTRATION BRIDGE                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         │                                 │                                 │
         ▼                                 ▼                                 ▼
┌──────────────────┐             ┌──────────────────┐             ┌──────────────────┐
│  Staging Vault   │             │   PQC Recipient  │             │ Manifest Signing │
│   Master Keys    │             │     Keypairs     │             │   Credentials    │
│    (ADR-059)     │             │    (ADR-046)     │             │    (ADR-053)     │
└────────┬─────────┘             └────────┬─────────┘             └────────┬─────────┘
         │                                │                                │
         └────────────────────────────────┼────────────────────────────────┘
                                          │
                        ┌─────────────────▼─────────────────┐
                        │   HsmKmsBridge Engine (Pure Rust) │
                        │   #![forbid(unsafe_code)]         │
                        └─────────────────┬─────────────────┘
                                          │
       ┌──────────────────────────────────┴──────────────────────────────────┐
       │                                                                     │
       ▼                                                                     ▼
┌──────────────────────────────┐                       ┌──────────────────────────────┐
│  Authenticated Key Wrapping  │                       │  Hardware Digital Signing    │
│  - ChaCha20-Poly1305 AEAD    │                       │  - HMAC-BLAKE3 Keyed Digester│
│  - 96-bit CSPRNG Nonce       │                       │  - Versioned Key Binding     │
│  - Context Hash in AAD       │                       │  - Monotonic Timestamping    │
└──────────────┬───────────────┘                       └──────────────┬───────────────┘
               │                                                      │
               └──────────────────────┬───────────────────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │    Provider Abstraction Interface       │
                 └────────────────────┬────────────────────┘
                                      │
    ┌──────────────┬──────────────┬───┴──────────┬──────────────┬──────────────┐
    │              │              │              │              │              │
    ▼              ▼              ▼              ▼              ▼              ▼
┌────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│PKCS#11 │    │ AWS KMS │    │ GCP KMS │    │  Azure  │    │HashiCorp│    │ Nitro   │
│Token   │    │Envelope │    │ Cloud   │    │Key Vault│    │ Vault   │    │ Enclaves│
│(v2.40/ │    │Encrypt/ │    │ KeyRing/│    │ Managed │    │ Transit │    │ Attested│
│ v3.0)  │    │ Decrypt │    │ Crypto  │    │   HSM   │    │ Engine  │    │ KMS     │
└────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────┘
```

---

## 5. Detailed Design & Security Invariants

### 5.1 Canonical Encryption Context Binding (AAD)

Every key wrapping operation takes an optional key-value dictionary of contextual metadata (such as `tenant_id`, `environment`, `purpose`, and `region`). 

The bridge computes a deterministic, canonical context hash:
1. Sort key-value pairs lexicographically by key string.
2. Hash into BLAKE3 keyed digest: $\text{Hash} = \text{BLAKE3}("velcrux-kms-context-v1:" \parallel \text{key\_id} \parallel \sum (k_i \parallel "=" \parallel v_i \parallel ";"))$.
3. Prepend `key_id`, `key_version`, and context hash into the Associated Authenticated Data (AAD) block:
$$\text{AAD} = \text{key\_id} \parallel ":" \parallel \text{version} \parallel ":" \parallel \text{context\_hash\_hex}$$
4. Encrypt the plaintext secret with ChaCha20-Poly1305 under the active KEK:
$$\text{Ciphertext} \parallel \text{Tag} = \text{ChaCha20Poly1305}_{\text{KEK}}(\text{Nonce}, \text{AAD}, \text{Secret})$$

If any context key or value is modified, reordered, or forged upon unwrapping, the ChaCha20-Poly1305 authentication tag check fails immediately, completely barring unauthorized key exposure.

### 5.2 Key Rotation Lifecycle

The bridge maintains monotonic key versions ($v_1, v_2, \dots, v_n$). When `rotate_key` is triggered:
1. A fresh cryptographically secure 256-bit entropy buffer is generated using system CSPRNG (`ring::rand::SystemRandom`).
2. A new master key fingerprint is calculated: $\text{Fingerprint} = \text{BLAKE3}(\text{KEK}_{\text{new}})$.
3. The key version increments monotonically: $v_{\text{new}} = v_{\text{prev}} + 1$.
4. The key catalog and token state are atomically committed to disk (`VELCRUX_KMS_DIR/tokens/<key_id>.kek` and `<key_id>.meta.json`).
5. Historical envelopes created under $v_{\text{prev}}$ remain un-wrappable using version-indexed key entries or archived key rings, enabling non-disruptive key rotation.

---

## 6. Observability & Operational Tooling

### 6.1 Prometheus Metrics

| Metric Name | Type | Description |
|---|---|---|
| `velcrux_hsm_kms_operations_total` | Counter | Total cryptographic operations processed by HSM / Cloud KMS |
| `velcrux_hsm_kms_operation_failures_total` | Counter | Total HSM / Cloud KMS operation failures or tamper alerts |
| `velcrux_hsm_kms_keys_wrapped_total` | Counter | Total Key Encryption Keys wrapped via HSM / Cloud KMS |
| `velcrux_hsm_kms_keys_unwrapped_total` | Counter | Total Key Encryption Keys unwrapped via HSM / Cloud KMS |
| `velcrux_hsm_kms_signatures_generated_total` | Counter | Total digital signatures produced by HSM / Cloud KMS |
| `velcrux_hsm_kms_active_provider_id` | Gauge | Active KMS provider code (0=SoftwareHsm, 1=AwsKms, 2=GcpKms, 3=Azure, 4=Vault, 5=Nitro) |
| `velcrux_hsm_kms_operation_latency_nanoseconds` | Gauge | Latest observed HSM / Cloud KMS operation latency in nanoseconds |
| `velcrux_hsm_kms_key_rotations_total` | Counter | Total master key rotation cycles executed |

### 6.2 Operator CLI

Operators interact with the bridge via `velcrux kms`:
- `velcrux kms status [--json]`: Inspect bridge state, active provider, key version, and metrics.
- `velcrux kms wrap --plaintext <hex> --context <k=v,...> [--json]`: Wrap a raw secret key into an authenticated envelope.
- `velcrux kms unwrap --envelope <json|path> --context <k=v,...> [--json]`: Unwrap an envelope and verify context integrity.
- `velcrux kms sign --data <str> [--json]`: Produce a digital signature over payload data.
- `velcrux kms verify --data <str> --signature <sig_hex|path> [--json]`: Verify signature validity against payload.
- `velcrux kms rotate [--key-id <id>] [--json]`: Rotate master key to a new cryptographic generation.
- `velcrux kms benchmark [--iterations <n>] [--json]`: Run microsecond latency and throughput benchmark.

---

## 7. Consequences & Trade-offs

### Positive
- **FIPS 140-3 Compliance**: Enables zero-trust root-of-trust key segregation required for federal, healthcare, and enterprise banking deployments.
- **Cross-Tenant Replay Immunity**: Authenticated encryption context binding completely prevents stolen envelopes from being decrypted by unauthorized tenants.
- **Memory Safety & Zero C Dependencies**: Pure safe Rust (`#![forbid(unsafe_code)]`) eliminates C FFI memory vulnerabilities.

### Negative / Mitigations
- **Network Latency for Remote Cloud KMS**: Remote HTTP round-trips to AWS/GCP/Azure KMS can add 15-45 ms during cold key unwrap.
  *Mitigation*: Node in-memory session key caching keeps hot path latency under 1 µs; remote KMS is only consulted once per staging vault session initialization.
