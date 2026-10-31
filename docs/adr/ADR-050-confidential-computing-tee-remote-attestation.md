# ADR-050: Confidential Computing & Hardware TEE Remote Attestation

Status: Accepted · Date: 2026-10-30

## Context

Federated enterprise data movement, sovereign cloud storage, and privacy-preserving multi-party compute pipelines increasingly process regulated, sensitive data (e.g., biometric markers, healthcare records, financial ledgers, and proprietary AI model weights) across untrusted physical infrastructure:
- **Host Infrastructure Compromise**: Hypervisor administrators, rogue cloud operators, kernel rootkits, and cold-boot physical bus sniffers have direct physical access to system DRAM and PCIe buses.
- **Untrusted Edge Compute**: Field IoT gateways and regional nodes run outside hardened datacenters where physical tampering or malicious hypervisor instrumentation is possible.
- **Zero-Knowledge Key Delivery**: Senders must cryptographically verify that the receiving node is executing an authentic, unmodified Velcrux binary inside a genuine hardware-isolated enclave before releasing decryption keys or plaintext chunks.

Prior software-only security approaches have critical limitations:
1. **OS Kernel & Hypervisor Vulnerability**: Traditional OS-level access control and root user privilege boundaries are bypassed if the OS kernel or hypervisor is compromised.
2. **Key Material Exposure in RAM**: Plaintext AES/ChaCha20 keys residing in standard host memory are vulnerable to hypervisor memory dumps, DMA attacks, and rowhammer corruption.
3. **Unverifiable Runtime Integrity**: Traditional TLS/mTLS authenticates the network endpoint's certificate, but provides zero guarantee regarding the actual code, memory layout, or debugging state executing inside the remote process.

To eliminate hypervisor and physical operator trust assumptions, Velcrux requires Confidential Computing with Hardware Trusted Execution Environment (TEE) Remote Attestation.

---

## Options Considered

1. **Option 1: Traditional Host TPM 2.0 Measured Boot**:
   - Utilize local motherboard TPM 2.0 chips to verify OS boot chain PCRs.
   - *Rejected*: Measures host platform boot up to OS kernel, but does not provide hardware memory encryption or isolate application memory from compromised host hypervisors.
2. **Option 2: Single-Vendor Proprietary Enclave SDK (e.g. Intel SGX DCAP only)**:
   - Couple tightly to vendor-specific C/C++ libraries and daemons (`libsgx-dcap-ql`).
   - *Rejected*: Violates `#![forbid(unsafe_code)]` with heavy foreign C dependencies, introduces brittle platform lock-in, and fails in AMD SEV-SNP or AWS Nitro environments.
3. **Option 3: Multi-Architecture Pure Safe Rust Hardware TEE Attestation & Key Derivation (`ADR-050`)**:
   - Unified hardware attestation abstraction supporting AMD SEV-SNP, Intel SGX/TDX, AWS Nitro Enclaves, and simulated environments.
   - Computes deterministic launch measurements (`measure_binary`) for target architectures (SHA-384 for SEV-SNP/Nitro, SHA-256 for SGX/TDX).
   - Validates hardware root-of-trust signatures over canonical domain-separated BLAKE3 quote digests.
   - Enforces strict security policies: measurement whitelists, minimum TCB security versions (SVN), non-debug mode enforcement, and challenge nonce binding.
   - Derives ephemeral symmetric transfer session keys cryptographically bound to the verified enclave launch measurement.

---

## Decision

Adopt **Option 3: Multi-Architecture Pure Safe Rust Hardware TEE Attestation & Key Derivation (`ADR-050`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------------+
|                  Velcrux Hardware TEE Remote Attestation Engine                         |
|                                                                                         |
|  [ Enclave Binary Image ]                                                               |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐                            |
|   │ Deterministic Launch Measurement:                      │                            |
|   │ - AMD SEV-SNP: SHA-384 launch digest (96 hex chars)    │                            |
|   │ - Intel SGX/TDX: SHA-256 MRENCLAVE / MRTD (64 hex)     │                            |
|   │ - AWS Nitro: SHA-384 PCR0 image hash                   │                            |
|   │ - Simulated: BLAKE3 launch digest                      │                            |
|   └────────────────────────────────────────────────────────┘                            |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐   ┌──────────────────────┐ |
|   │ Hardware Attestation Quote Construction:               │   │ Hardware Platform    │ |
|   │ - Measurement: MRENCLAVE / LaunchDigest                │◄──┤ Root of Trust (RoT)  │ |
|   │ - Report Data: 64-byte challenge nonce binding         │   │ (VCEK / PCK / Nitro) │ |
|   │ - Security Version (TCB SVN)                           │   │ Quote Signature      │ |
|   │ - Flags: debug_enabled = false                         │   └──────────────────────┘ |
|   └────────────────────────────────────────────────────────┘                            |
|             │                                                                           |
|             ▼                                                                           |
|   ┌─────────────────────────────────────────────────────────────────────────────────┐   |
|   │ Zero-Trust Attestation Policy Verifier:                                         │   |
|   │ 1. Validate platform in allowed_platforms                                       │   |
|   │ 2. Validate quote freshness: age <= max_quote_age_seconds                       │   |
|   │ 3. Enforce debug mode disabled: quote.debug_enabled == false                    │   |
|   │ 4. Verify TCB security level: quote.security_version >= min_security_version    │   |
|   │ 5. Validate launch measurement against approved golden image whitelist         │   |
|   │ 6. Verify hardware cryptographic signature over canonical quote digest          │   |
|   │ 7. Verify report_data == BLAKE3(client_session_challenge_nonce)                 │   |
|   └─────────────────────────────────────────────────────────────────────────────────┘   |
|             │                                                                           |
|             ▼                                                                           |
|   ┌─────────────────────────────────────────────────────────────────────────────────┐   |
|   │ Hardware-Bound Ephemeral Session Key Derivation (KDF):                          │   |
|   │ K_session = BLAKE3("velcrux-tee-session-kdf:v1:" || platform || measurement ||  │   |
|   │                    report_data || shared_secret)                                │   |
|   └─────────────────────────────────────────────────────────────────────────────────┘   |
+-----------------------------------------------------------------------------------------+
```

### Challenge Nonce Binding

To eliminate replay attacks where an attacker intercepts a valid quote and replays it to impersonate an authentic enclave, the client transmits an ephemeral challenge nonce $N$ before the handshake. The enclave binds $N$ into the hardware quote's 64-byte `report_data` field:
$$\text{ReportData} = \text{BLAKE3}\left(\text{"velcrux-tee-report-data:v1:"} \parallel N\right)$$
The verifier recomputes this digest and requires an exact match before admitting the session.

### Hardware-Bound Ephemeral Session Key Derivation

Session encryption keys are derived directly from the verified enclave measurement:
$$K_{\text{session}} = \text{BLAKE3-KDF}\left(\text{Measurement} \parallel \text{ReportData} \parallel S_{\text{shared}}\right)$$
If an adversary runs a modified binary, the resulting launch measurement will differ, producing an entirely mismatched session key and rendering transferred ciphertexts undecryptable.

---

## Consequences

### Positive
- **Hardware-Enforced Zero Trust**: Protects data-in-use even if the hypervisor, host OS, or physical infrastructure is compromised.
- **Multi-Cloud Portability**: Unified interface across AMD SEV-SNP (GCP, Azure), AWS Nitro Enclaves, and Intel SGX/TDX bare metal.
- **Replay & Relay Immunity**: Hardware-bound challenge nonces guarantee that attestation quotes cannot be replayed or relayed across connections.
- **Zero External Dependencies**: Pure safe Rust (`#![forbid(unsafe_code)]`), eliminating brittle vendor C libraries.
- **Microsecond Verification Latency**: Quote verification executes in $< 100\,\mu\text{s}$ on standard hardware.

### Negative
- Initial enclave measurement calculation requires computing cryptographic hashes over the binary executable.
- Enclave execution incurs small hardware memory encryption overhead ($1\text{--}3\%$) at runtime.

