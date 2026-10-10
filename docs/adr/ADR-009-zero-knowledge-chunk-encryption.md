# ADR-009: Zero-Knowledge Client-Side Chunk Encryption & AEAD Tamper-Proof Storage

Status: Accepted · Date: 2026-10-09

## Problem

Requirement §37 ("Chunk Encryption / Security"), §65 ("Encryption Ordering"), and `SECURITY.md` §2, §3, §8 define the security boundary for multi-tenant and untrusted cloud storage. While QUIC provides transport-layer TLS 1.3 encryption across the network wire against passive eavesdroppers and active on-path attackers, TLS 1.3 terminates at the QUIC endpoint.

In untrusted storage, multi-tenant colocation, or edge caching scenarios:
1. Storage intermediaries, relay proxies, and server administrators can inspect unencrypted chunks stored on disk.
2. In-flight corrupted or maliciously spliced chunks from compromised intermediaries can poison recipient datasets.
3. Chunks could be spliced or reordered across different files or transfers if not cryptographically bound to their exact identity and offset.

## Options

1. **Full Disk / Filesystem Encryption (FDE/LUKS)**: Encrypts the entire server disk underneath the filesystem.
2. **Whole-File PGP / Age Envelope Encryption**: Encrypts the file prior to chunking.
3. **Zero-Knowledge AEAD Chunk Envelope Encryption with Associated Data (AAD)**: Chunks are individually sealed at the client using authenticated ciphers (ChaCha20-Poly1305 or AES-256-GCM) with Associated Authenticated Data binding `(TransferId, chunk_offset, chunk_index)`.

## Decision

Option 3. Velcrux implements client-side authenticated AEAD chunk encryption using RFC 8439 ChaCha20-Poly1305 and NIST SP 800-38D AES-256-GCM.

The pipeline strictly enforces the ordering required by `REQUIREMENTS.md` §65:
```text
source file ──> FastCDC chunking ──> optional zstd compression ──> AEAD chunk encryption ──> QUIC TLS 1.3 ──> wire
```

Option 1 is rejected as it requires server-side trust and does not protect data in transit between intermediary application hops.
Option 2 is rejected because whole-file pre-encryption generates high-entropy ciphertext that destroys FastCDC chunk boundaries, deduplication, and delta synchronization.

## Trade-offs

- **Overhead**: Each chunk envelope incurs exactly 28 bytes of overhead (12-byte cryptographically secure random nonce + 16-byte Poly1305 or GHASH authentication tag). On 1 MiB chunks, this is less than 0.003% wire overhead.
- **Deduplication vs Privacy**: Zero-knowledge encryption with unique nonces prevents multi-tenant convergent deduplication across distinct users holding different keys. This is an intentional security design choice: cross-tenant deduplication leaks side-channel information regarding whether other tenants possess identical file blocks. Deduplication remains fully operational within a single tenant or transfer key scope.
- **CPU Throughput**: ChaCha20-Poly1305 guarantees constant-time software security across all CPU architectures, immune to cache-timing attacks, and achieves >2.5 GB/s per core. AES-256-GCM utilizes hardware AES-NI / ARMv8 crypto extensions reaching >5 GB/s per core.

## Cryptographic Binding via Associated Authenticated Data (AAD)

To completely eliminate chunk swapping, offset alteration, and cross-session injection attacks, every chunk envelope incorporates 28 bytes of immutable context into the AEAD authentication tag:

$$\text{AAD} = \text{TransferId (16 bytes)} \parallel \text{chunk\_offset (8 bytes LE)} \parallel \text{chunk\_index (4 bytes LE)}$$

Any modification of the chunk offset or index causes `open_in_place` to fail with `CryptoError::AuthenticationFailed`, preventing corrupt or poisoned data from ever being written to disk or memory.

## Key Derivation

- Master keys are derived from user passphrases using PBKDF2-HMAC-SHA256 with 100,000 iterations and salt.
- Transfer keys are derived using BLAKE3 KDF with domain separation string `"velcrux-zero-knowledge-transfer-v1"`.
- `TransferKey` implements explicit memory zeroization on drop.

## Consequences

- Wire flag `DataFrameFlags::ENCRYPTED = 0x0004` and capability bit `Capability::ChunkEncryption = 10` are established.
- Server staging directories can operate in zero-knowledge mode where chunks are stored verbatim as ciphertext.
- Tamper detection is fail-closed: single-bit corruptions immediately abort chunk acceptance.
- Documented in `docs/OPERATIONS.md` §25.
