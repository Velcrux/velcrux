# ADR-059: Post-Quantum Encrypted Staging Vault with Kyber/Dilithium Envelope Encryption

- **Status**: Accepted
- **Date**: 2026-11-02
- **Deciders**: Velcrux Core Architecture, Cryptography & Security Working Group
- **Consulted**: Security Engineering, Threat Modeling, Compliance & Cryptographic Standards

---

## 1. Context and Problem Statement

Velcrux multi-tenant directory synchronization pipelines stage incoming and outgoing chunks, delta slices, and serialized filesystem manifests in local staging directories (`VELCRUX_VAULT_DIR`) prior to distributed two-phase commit (2PC) or permanent object store persistence.

During multi-tenant transfers, staged data resides on disk in intermediate buffers. This introduces a critical vulnerability window:
1. **"Harvest Now, Decrypt Later" (HNDL) Attacks**: Sophisticated adversaries and nation-state actors record exfiltrated staging disk buffers or multi-tenant staging volumes, holding the ciphertext until Cryptanalytically Relevant Quantum Computers (CRQCs) arrive to break classical asymmetric cryptography (RSA, ECDH, X25519).
2. **Ephemeral Staging Data-at-Rest Exposure**: Staging directories in high-concurrency multi-tenant clusters are prone to residual forensic recovery if keys are not actively and provably shredded immediately upon transfer commitment or abort.
3. **Manifest Tampering**: Staged manifests could potentially be manipulated or injected if they lack post-quantum cryptographic identity verification.
4. **Platform & Kernel Independence**: The staging vault must operate in unprivileged user environments across Linux and macOS workstations without hardware security module (HSM) dependencies or unsafe code.

---

## 2. Decision Drivers

- **Post-Quantum Forward Secrecy**: Eliminate HNDL exposure at rest by utilizing NIST FIPS 203 **ML-KEM-768** (Kyber-768) key encapsulation for all staged files.
- **Quantum-Resilient Manifest Integrity**: Guarantee that staged files cannot be tampered with or substituted using NIST FIPS 204 **ML-DSA-65** (Dilithium-3) digital signatures.
- **High-Throughput Symmetric AEAD**: Encrypt file payloads with **ChaCha20-Poly1305** (RFC 8439) with cryptographically bound Associated Authenticated Data (AAD) tying file identity, original size, and vault ID.
- **Active Ephemeral Key Shredding**: Multi-pass disk overwrites (`0x55`, `0xAA`, `0x00`) with explicit fsync and in-memory cryptographic zeroization upon sync commitment or abort.
- **Pure Safe Rust**: Strict `#![forbid(unsafe_code)]` compliance across all cryptographic and disk operations.

---

## 3. Considered Options

- **Option 1: Standard Symmetric AES-GCM Staging with Static Local Master Key**:
  - *Cons*: Does not protect against insider threats or compromise of the host's long-lived key; does not provide post-quantum asymmetric encapsulation.
- **Option 2: Classical X25519 Envelope Encryption**:
  - *Cons*: Completely broken by Shor's algorithm on a quantum computer; vulnerable to HNDL collection.
- **Option 3 (Chosen): Post-Quantum Encrypted Staging Vault (`VaultEngine`) with ML-KEM-768 + ChaCha20-Poly1305 + ML-DSA-65**:
  - Ephemeral 256-bit symmetric DEK generated per file and encapsulated using ML-KEM-768.
  - Manifest cosigned with ML-DSA-65 prior to writing to disk.
  - Verification evaluated before decryption; zeroization on drop.
  - Multi-pass overwrite shredding permanently destroys ephemeral keys and ciphertext buffers.
  - Multi-process staged persistence via `VELCRUX_VAULT_DIR`.

---

## 4. Technical Architecture

```
                       PLAINTEXT FILE / STREAM
                                  │
                  ┌───────────────▼───────────────┐
                  │   Ephemeral DEK Generation   │
                  │   (256-bit CSPRNG Secret)     │
                  └───────────────┬───────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         │                                                 │
┌────────▼────────────────┐                     ┌──────────▼──────────────┐
│  ML-KEM-768 Encap       │                     │ ChaCha20-Poly1305 AEAD  │
│  (FIPS 203 Kyber)       │                     │ Bound with Vault AAD    │
│  Produces:              │                     │ Produces:               │
│  - 1,088-byte Ciphertext│                     │ - Ciphertext + 16B Tag  │
│  - 32-byte Shared Secret│                     │ - BLAKE3 Payload Hash   │
└────────┬────────────────┘                     └──────────┬──────────────┘
         │                                                 │
         └────────────────────────┬────────────────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │    Canonical Preimage Build   │
                  │ (VaultID, FileID, Sizes, Hashes)
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │     ML-DSA-65 Manifest Sign   │
                  │      (FIPS 204 Dilithium)     │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │     Vault Storage Engine      │
                  │ - <file_id>.manifest.json     │
                  │ - <file_id>.payload.enc       │
                  │ (or standalone .vlt package)  │
                  └───────────────┬───────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │  Active Ephemeral Shredding   │
                  │ (Pass 1: 0x55, 2: 0xAA, 3: 00)│
                  │ In-Memory Memory Zeroization  │
                  └───────────────────────────────┘
```

---

## 5. Security & Verification Invariants

1. **Tamper Rejection Before Decryption**: Unsealing verifies the BLAKE3 ciphertext hash and the ML-DSA-65 signature before invoking ML-KEM-768 decapsulation or ChaCha20-Poly1305 decryption.
2. **Context Binding via AAD**: Associated Authenticated Data is derived via `BLAKE3("velcrux-staging-aad:v1" || vault_id || file_id || original_size)`, preventing ciphertext transplant across vaults or files.
3. **In-Memory Zeroization**: The `EphemeralDek` struct automatically zeroes its buffer in its `Drop` implementation; intermediate KEM randomness buffers are zeroized explicitly.
4. **Physical Shredding**: Files and keys shredded with `shred_file` or `shred_all` undergo 3 full overwrite passes with fsync before unlinking.

---

## 6. Observability & Operational Metrics

- Prometheus metrics exposed under `/metrics`:
  - `velcrux_vault_files_encrypted_total`
  - `velcrux_vault_files_decrypted_total`
  - `velcrux_vault_active_sealed_bytes`
  - `velcrux_vault_active_sealed_files`
  - `velcrux_vault_keys_shredded_total`
  - `velcrux_vault_verification_failures_total`
  - `velcrux_vault_seal_latency_nanoseconds`
  - `velcrux_vault_unseal_latency_nanoseconds`

