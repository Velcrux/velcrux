# ADR-077: Confidential Enclave Attestation & Remote Hardware Root-of-Trust Mesh (AMD SEV-SNP / Intel SGX/TDX)

- **Status**: Accepted
- **Date**: 2026-11-13
- **Deciders**: Velcrux Distributed Systems, Confidential Computing, Hardware Security, and Infrastructure Engineering Teams
- **Consulted**: Security Architecture, Site Reliability Engineering, and Cryptography Teams

---

## 1. Context and Problem Statement

When deploying Velcrux bulk data transfer gateways, distributed object storage clusters, and streaming compute components in untrusted public cloud and edge environments, security cannot rely on host OS hypervisor guarantees:
1. **Host Hypervisor Compromise & Snooping**: Unencrypted memory and host administrator access expose in-flight decryption keys, tenant secrets, and customer payloads to hypervisor inspection, memory dumping, or DMA scraping.
2. **Attestation Relay & Man-In-The-Middle (MITM) Attacks**: Naive remote attestation protocols allow a malicious hypervisor or proxy to request a legitimate attestation quote from a local enclave and relay it over an eavesdropped TLS connection to an external party. Attestation must be cryptographically bound to the specific transport session (RFC 9266 / RFC 5929 channel binding).
3. **Hardware TCB & Firmware Downgrade Hazards**: Enclaves running on outdated microcode or unpatched hypervisor firmware (low TCB SVN) remain vulnerable to known speculative execution exploits (e.g., Spectre, Meltdown, Foreshadow, Downfall). The attestation engine must enforce strict TCB baseline minimums.
4. **Persistent Secret Protection Across Upgrades**: Enclaves require hardware-bound data sealing (`EGETKEY`) to persist cluster keys across reboots. Code updates must choose between strict identity-bound sealing (`MRENCLAVE`) or vendor-authority-bound sealing (`MRSIGNER`) allowing seamless authorized upgrades.
5. **Distributed Multi-Node Enclave Mesh**: In a geo-distributed replication fabric, nodes must establish mutual enclave-to-enclave trust without central single-point-of-failure attestation servers.

To solve these challenges, Velcrux implements a **Confidential Enclave Attestation & Remote Hardware Root-of-Trust Mesh** supporting AMD SEV-SNP, Intel SGX/TDX, AWS Nitro, and simulated hardware in 100% pure safe Rust.

---

## 2. Decision Drivers

- **Multi-Architecture Hardware Enclave Support**:
  - AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP).
  - Intel Software Guard Extensions (SGX) and Trust Domain Extensions (TDX).
  - AWS Nitro Enclaves.
  - Cryptographically equivalent simulated hardware environment for local verification and automated testing.
- **Cryptographic Measurement & Identity Governance**:
  - `launch_digest`: SHA-384 / SHA-256 launch measurement verifying initial memory contents and vCPU register state.
  - `mr_enclave`: 256-bit measurement hash of enclave code and data pages.
  - `mr_signer`: 256-bit measurement hash of the enclave author's public signing key.
  - `isv_prod_id` & `isv_svn`: Product identification and security version numbers.
- **Strict Non-Debug & TCB Policy Enforcement**:
  - Default rejection of any enclave with the debug bit set (`allow_debug: false`), preventing external debugger inspection of enclave registers.
  - Multi-tier TCB SVN baseline checks (`bootloader_svn`, `tee_svn`, `snp_or_cpusvn`, `microcode_svn`), immediately failing out-of-date platforms.
- **TLS 1.3 Channel Binding via 64-Byte `REPORTDATA` (RFC 9266 / RFC 5929)**:
  - Computes $\text{REPORTDATA} = \text{BLAKE3\_DERIVE\_KEY}(\text{"velcrux-tls13-channel-binding-v1"}, \text{exporter\_secret} \parallel \text{client\_nonce} \parallel \text{server\_nonce})$.
  - Embedded directly into the hardware-signed quote payload, making hypervisor relay attacks mathematically impossible.
- **Hardware Data Sealing (`MRENCLAVE` vs `MRSIGNER`)**:
  - Key derivation using BLAKE3 KDF over hardware chip keys and measurement structures.
  - Authenticated encryption with associated data (AEAD) sealing sensitive keys and configuration on local disk.
- **Autonomous Root-of-Trust Mesh Engine**:
  - Continuous mutual peer verification with validity epochs (`max_quote_age_seconds: 3600`).
  - Active peer trust tracking and instantaneous revocation.
- **Zero Unsafe Code**: 100% `#![forbid(unsafe_code)]` compliance with zero external native C dependencies.

---

## 3. Technical Architecture

```
                 Remote Client / Peer Storage Enclave Node
                                    │
                  TLS 1.3 Handshake (mTLS Transport)
                  - Exporter Secret Generated
                  - Client Nonce || Server Nonce
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │   TLS 1.3 Channel Binding Generator (RFC 9266 / 5929)   │
       │   REPORTDATA = BLAKE3(tls_exporter, nonces, context)   │
       └────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │        Hardware Confidential Enclave Boundary          │
       │     (AMD SEV-SNP / Intel SGX / TDX / AWS Nitro)        │
       │                                                        │
       │  [Enclave Hardware Attestation Engine]                 │
       │  - Embeds 64-Byte REPORTDATA into Hardware Report      │
       │  - Reads Hardware TCB SVNs (Bootloader, TEE, Microcode)│
       │  - Hardware Signs Quote via Platform Endorsement Key   │
       │                                                        │
       │  [Hardware Data Sealing Engine]                        │
       │  - Sealing Policy: MRENCLAVE (Exact Code)              │
       │  - Sealing Policy: MRSIGNER (Author Upgradable)        │
       │  - Authenticated Envelope Storage                      │
       └────────────────────────────┬───────────────────────────┘
                                    │ Signed Hardware Quote
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │        Distributed Enclave Mesh Engine                 │
       │  - Validates Cryptographic Platform Signature          │
       │  - Enforces Non-Debug Policy                           │
       │  - Enforces Minimum TCB Baseline                       │
       │  - Compares REPORTDATA against TLS 1.3 Channel Binding │
       │  - Registers Peer in Mutual Root-of-Trust Mesh         │
       └────────────────────────────────────────────────────────┘
```

---

## 4. Mathematical Foundations & Verification Hierarchy

### 4.1 Canonical Quote Digest & Endorsement Verification

The quote digest covers all security-sensitive metadata to prevent attribute substitution:
$$D_{\text{quote}} = \text{BLAKE3}(\text{DOMAIN} \parallel \text{platform} \parallel \text{launch\_digest} \parallel \text{mr\_enclave} \parallel \text{mr\_signer} \parallel \text{isv\_prod\_id} \parallel \text{isv\_svn} \parallel \text{report\_data} \parallel \text{tcb} \parallel \text{debug} \parallel \text{chip\_id} \parallel \text{timestamp})$$

The signature is verified against the platform endorsement public key:
$$\text{Verify}_{\text{Ed25519}}(\text{SignerPubKey}, D_{\text{quote}}, \text{Signature}) \stackrel{?}{=} \text{True}$$

### 4.2 TLS 1.3 Channel Binding Verification

The verifier independently computes:
$$\text{ExpectedReportData} = \text{BLAKE3}_{\text{KDF}}(\text{Secret}, \text{ClientNonce} \parallel \text{ServerNonce} \parallel \text{NodeID})$$
$$\text{Quote}.\text{report\_data} \stackrel{?}{=} \text{ExpectedReportData}$$

If an adversary attempts to relay a valid quote generated from an enclave to another network connection, the exporter secrets and session nonces will diverge, failing the constant-time equality check.

---

## 5. Consequences

### 5.1 Positive Consequences
- **True Confidentiality in Multi-Tenant Clouds**: Eliminates the hypervisor and cloud provider infrastructure from the Trusted Computing Base (TCB).
- **Immunity to Attestation Relays**: TLS 1.3 channel binding prevents hypervisors from eavesdropping on cleartext data streams or impersonating enclave nodes.
- **Hardware-Enforced TCB Integrity**: Blocks unpatched, vulnerable platforms from participating in cluster replication.
- **Safe State Sealing**: Enables zero-trust local storage of cluster master keys and transfer checkpoints.
- **100% Pure Safe Rust**: `#![forbid(unsafe_code)]` with zero external native C dependencies.

### 5.2 Negative Consequences / Tradeoffs
- **Quote Generation Latency**: Generating and verifying cryptographic quotes takes $\approx 100\text{ µs} - 300\text{ µs}$ per handshake, mitigated by caching verified mesh peer relationships within their validity epochs.

---

## 6. Implementation References

- Core Module: `crates/velcrux-core/src/enclave/`
  - `types.rs`: Platforms, measurements, TCB versions, policies, and hardware quote structures.
  - `binding.rs`: TLS 1.3 channel binding derivation and verification.
  - `attestation.rs`: Hardware quote generation, verification, and non-debug enforcement.
  - `sealing.rs`: Hardware-derived secret sealing (`MRENCLAVE` and `MRSIGNER`).
  - `mesh.rs`: Distributed root-of-trust mesh engine and peer lifecycle coordinator.
- Core Integration Tests: `crates/velcrux-core/tests/enclave_mesh_tests.rs`
- Operator CLI Suite: `crates/velcrux-client/src/main.rs` (`velcrux enclave status|quote|verify|benchmark`)
- CLI Integration Tests: `crates/velcrux-client/tests/cli_enclave.rs`

