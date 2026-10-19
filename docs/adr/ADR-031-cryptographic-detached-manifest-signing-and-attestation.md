# ADR-031: Cryptographic Detached Manifest Signing & End-to-End Attestation (`SECURITY.md` §7, `velcrux attest`)

Status: Accepted · Date: 2026-10-19

## Context

In supply chain pipelines, compliance auditing, distributed multi-tenant environments, and air-gapped backups, data transfer integrity must be provable and verifiable out-of-band. While TLS 1.3 provides in-flight channel encryption and BLAKE3 provides content verification, neither mechanism provides **cryptographic non-repudiation** or provenance:
1. **Provenance & Non-Repudiation**: A recipient needs cryptographic proof that a specific authoritative identity (e.g. build system, release signer, compliance auditor) generated and signed this exact dataset manifest.
2. **Offline & Detached Attestation**: Consumers or cold storage systems must be able to audit files on disk at rest without re-running active network transfers.
3. **Replay & Expiration Defense**: Attestations must be bound to validity windows with optional expiration and future clock-skew rejection.
4. **Domain Separation**: Preimages signed with Ed25519 must be explicitly domain-separated (`ATTESTATION_DOMAIN_SEPARATOR = "VELCRUX-MANIFEST-ATTESTATION-V1\0"`) to prevent signatures from being replayed across other protocols (such as SSH pubkey authentication).
5. **Secret Redaction**: In strict accordance with `SECURITY.md` §7, private keys must be wrapped in `Secret<T>` and never printed in logs or debug strings.
6. **Pure Safe Rust**: Zero unsafe code (`#![forbid(unsafe_code)]`) across all signing and verification components.

## Options Considered

1. **Embedded In-Stream Manifest Signatures Only**:
   - Embed digital signatures inside the `MANIFEST_BEGIN` or `MANIFEST_END` wire frames.
   - *Rejected*: Incompatible with offline filesystem auditing or verification of directories already transferred to disk; tightly couples signature format to the network transport.
2. **PGP / GPG External Tool Invocation**:
   - Shell out to system `gpg` or `pgp` binaries to sign and verify files.
   - *Rejected*: Introduces external C dependencies, brittle subprocessing, system dependency bloat, and platform inconsistency; breaks reproducible builds and container portability.
3. **Pure-Rust Detached Attestation Envelopes (`AttestationEnvelope`) with Ed25519 and Domain Separation**:
   - Define a canonical, domain-separated binary serialization for manifest claims (manifest BLAKE3 root hash, file count, total bytes, issuer identity, timestamps, expiration, and arbitrary metadata tags).
   - Use pure-Rust `ring::signature::Ed25519KeyPair` and `UnparsedPublicKey` for high-throughput, constant-time signing and verification.
   - Emit detached signature files (`.velcrux-manifest.sig` or custom `.sig`).
   - Integrate with both the dedicated `velcrux attest` CLI subcommand and `velcrux sync` (`--sign-key`, `--verify-sig`, `--trusted-signers`).

## Decision

Adopt Option 3.

## Architecture & Implementation

### 1. Attestation Payload & Deterministic Canonical Preimage (`crates/velcrux-core/src/auth/attestation.rs`)

- **Domain Separation**:
  ```rust
  pub const ATTESTATION_DOMAIN_SEPARATOR: &[u8] = b"VELCRUX-MANIFEST-ATTESTATION-V1\0";
  ```
- **`AttestationPayload`**:
  - `version: u32` (always `1`)
  - `manifest_hash: Hash` (32-byte BLAKE3 root hash of the manifest)
  - `file_count: u64`
  - `total_bytes: u64`
  - `issuer: String` (canonical issuer identity)
  - `created_at: u64` (Unix epoch seconds)
  - `expires_at: Option<u64>` (optional expiration timestamp)
  - `metadata: BTreeMap<String, String>` (sorted key-value metadata tags)
- **`canonical_bytes(&self) -> Vec<u8>`**:
  - Encodes the domain separator, fixed-width little-endian numbers, length-prefixed strings, and sorted key-value pairs into a deterministic binary slice.

### 2. Secret Redaction & Key Management (`AttestationKey`)

- Wraps PKCS#8 private key bytes in `Secret<Vec<u8>>` from `crates/velcrux-core/src/util/redacted.rs`.
- `Debug` and `Display` output `[redacted]` for private key material, preventing inadvertent log leaks.
- Supports PEM and raw PKCS#8 DER formats, with POSIX `0o600` permissions on created key files.
- Generates OpenSSH-compatible public keys (`ssh-ed25519 <base64> <comment>`).

### 3. Policy Verifier (`AttestationVerifier`)

- Manages trusted signers loaded from `authorized_signers` / `authorized_keys` or hex strings.
- Enforces cryptographic validity, expiration bounds, future timestamp skew limit (default 300s), and issuer identity checks.
- Returns detailed structured reports (`AttestationReport` with `AttestationStatus`).

### 4. End-to-End Filesystem Verification

- `generate_target_attestation(path, key, issuer, expires_in, metadata)`:
  - Scans single file or directory tree with `scan_directory_tree` / `scan_single_file`.
  - Automatically excludes `.velcrux-manifest.sig` and temporary staging artifacts from hash computation.
  - Returns `AttestationEnvelope` and `ManifestBegin`.
- `verify_target_attestation(path, envelope, verifier, expected_issuer, now)`:
  - Verifies cryptographic signature.
  - Re-scans disk target to recompute actual BLAKE3 manifest hash, file count, and byte total.
  - Compares reality against signed claims and flags `HashMismatch`, `FileCountMismatch`, or `TotalBytesMismatch`.

### 5. CLI Surface (`crates/velcrux-client`)

- `velcrux attest keygen --out <key> [--pub-out <pub>] [--comment <str>]`: Generate fresh Ed25519 keypair.
- `velcrux attest sign <path> --key <key> [--out <sig>] [--issuer <id>] [--expires-in <secs>] [-m k=v...] [--json]`: Sign detached manifest attestation.
- `velcrux attest verify <path> --sig <sig> [--trusted-keys <keys>] [--require-issuer <id>] [--json]`: Cryptographically verify directory or file against attestation.
- `velcrux attest inspect <sig> [--json]`: Inspect envelope claims without disk scan.
- `velcrux sync <src> <dst> --sign-key <key>`: Automatically mint `.velcrux-manifest.sig` upon successful synchronization.
- `velcrux sync <src> <dst> --verify-sig <sig> [--trusted-signers <keys>]`: Validate destination attestation after synchronization.

### 6. Server Telemetry & Configuration (`crates/velcrux-server`)

- Added `[security] require_signed_manifests` and `[security] trusted_signers` in server configuration.
- Added `velcrux_attestations_total{outcome="verified|invalid|rejected"}` Prometheus counters in `metrics.rs`.

## Consequences

- **Authenticity & Integrity**: File sets can be certified by authorized keys at build/release time and verified offline or in staging pipelines without relying on active server sessions.
- **Tamper Evidence**: Any modification to a file, extra file added, or file deleted immediately produces a `HashMismatch` or `FileCountMismatch`.
- **Zero Unsafe Code**: 100% pure, memory-safe Rust with zero dependencies on external C cryptography libraries.
