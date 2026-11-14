# ADR-081: Autonomous Micro-Segmented Zero-Trust WireGuard / Noise Mesh Tunnel Fabric

- **Status**: Accepted
- **Date**: 2026-11-14
- **Deciders**: Velcrux Distributed Systems, Cryptography, Global Networking, SRE, and Security Engineering Teams
- **Consulted**: High-Performance Networking, Cloud Infrastructure, Compliance, and Edge Computing Teams

---

## 1. Context and Problem Statement

When deploying large-scale bulk data transfer, content-defined deduplication synchronization, and multi-region replication meshes across public untrusted Internet WANs, multi-cloud interconnects, and edge Points of Presence (PoPs), organizations face severe security and performance bottlenecks:

1. **Vulnerability of Perimeter-Based VPNs**:
   Legacy IPsec and OpenVPN architectures rely on bulky negotiation phases (IKEv2), complex X.509 certificate chains, hundreds of configuration options, and large codebases susceptible to memory safety vulnerabilities. Furthermore, perimeter VPNs grant broad subnet access rather than enforcing zero-trust micro-segmentation.
2. **Cryptographic Routing & IP Spoofing Risks**:
   Without cryptographic association between IP addresses and public keys, compromised nodes or malicious actors on the local network can inject packets claiming forged source IPs, enabling man-in-the-middle attacks and cross-tenant data leaks.
3. **NAT Traversal & Dynamic Roaming**:
   Edge nodes, remote replication targets, and cloud instances frequently sit behind carrier-grade NAT (CGNAT) or experience mobile roaming across dynamic IP addresses. Traditional tunnels break when endpoints change IP/port, requiring expensive reconnection overhead.
4. **Packet Replay Vulnerabilities**:
   Adversaries intercepting encrypted UDP packets on transit backbones can replay historical packets to disrupt synchronization or corrupt state machines unless strict, windowed anti-replay barriers are maintained at line rate.

To resolve these challenges, Velcrux implements the **Autonomous Micro-Segmented Zero-Trust WireGuard / Noise Mesh Tunnel Fabric** in 100% pure safe Rust (`#![forbid(unsafe_code)]`).

---

## 2. Decision Drivers

- **Noise Protocol Handshake & Modern Cryptography (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`)**:
  - Implements the canonical 1-RTT Noise IK handshake matching the WireGuard specification:
    - Curve25519 (RFC 7748 X25519) Diffie-Hellman key exchange.
    - ChaCha20-Poly1305 (RFC 8439) AEAD symmetric authenticated transport encryption.
    - BLAKE3 key derivation functions and MAC1/MAC2 DoS challenge protection.
    - Optional pre-shared key (PSK) post-quantum resistance.
- **WireGuard Wire Framing**:
  - Binary framing compatibility:
    - Type 1: Handshake Initiation (148 bytes: sender index, unencrypted ephemeral, encrypted static, encrypted timestamp, MAC1, MAC2).
    - Type 2: Handshake Response (92 bytes: sender index, receiver index, unencrypted ephemeral, encrypted empty payload, MAC1, MAC2).
    - Type 3: Cookie Reply (64 bytes).
    - Type 4: Transport Data (16-byte header + encrypted payload + 16-byte Poly1305 auth tag).
- **Cryptographic Routing & AllowedIPs Prefix Trie (`AllowedIpsTrie`)**:
  - Longest-prefix match trie supporting IPv4 and IPv6 CIDRs.
  - Bidirectional cryptographic routing:
    - Outbound: Destination IP lookup selects the target peer tunnel.
    - Inbound: Inner source IP must match the peer's configured `AllowedIPs`; non-matching packets are dropped immediately as spoofing attempts.
- **256-Bit Sliding Window Anti-Replay Barrier (`AntiReplayWindow`)**:
  - RFC 6479 compliant 256-bit sliding window bitmap.
  - Drops replayed, duplicated, or out-of-order packets older than 256 transmission counts.
- **Autonomous Endpoint Roaming**:
  - Automatically updates peer socket endpoint upon receipt of an authenticated packet originating from a new source IP or UDP port.
- **Operator CLI Suite (`velcrux mesh`)**:
  - `velcrux mesh status [--json]`
  - `velcrux mesh peers [--json]`
  - `velcrux mesh connect --peer <ID> --public-key <PUBKEY> [--endpoint <IP:PORT>] [--allowed-ips <CIDR>] [--json]`
  - `velcrux mesh disconnect --peer <ID> [--json]`
  - `velcrux mesh benchmark [--packets <N>] [--packet-size <BYTES>] [--json]`

---

## 3. Architecture & Key Mechanisms

```
+-----------------------------------------------------------------------------------+
|               VELCRUX ZERO-TRUST WIREGUARD / NOISE MESH FABRIC                    |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +--------------------+        WireGuard UDP Tunnel         +-------------------+ |
|  |     ROUTER A       | <=================================> |     ROUTER B      | |
|  |   (10.200.1.0/24)  |        1-RTT Noise_IKpsk2           |  (10.200.2.0/24)  | |
|  |  Static: X25519_A  | <----\                        /---> |  Static: X25519_B  | |
|  +--------------------+       \                      /      +-------------------+ |
|            |                   \                    /                 |           |
|            | AllowedIPs Trie    v                  v                  |           |
|            | Longest-Prefix    +--------------------+                 |           |
|            v Match             |    ROUTER C (PoP)  |                 v           |
|  +--------------------+        |   (10.200.3.0/24)  |       +-------------------+ |
|  | Anti-Replay Barrier|        |  Static: X25519_C  |       | Anti-Replay Barrier|
|  | (256-bit Window)   |        +--------------------+       | (256-bit Window)  | |
|  +--------------------+                                     +-------------------+ |
+-----------------------------------------------------------------------------------+
```

### 3.1 Handshake Initiation & Response (Noise_IK)
1. **Initiator $\to$ Responder**:
   $$\text{Initiation} = [T_1 \parallel \text{idx}_i \parallel e_i \parallel \text{AEAD}_{k_1}(\text{pub}_i) \parallel \text{AEAD}_{k_2}(\text{timestamp}) \parallel \text{mac}_1 \parallel \text{mac}_2]$$
2. **Responder $\to$ Initiator**:
   $$\text{Response} = [T_2 \parallel \text{idx}_r \parallel \text{idx}_i \parallel e_r \parallel \text{AEAD}_{k_3}(\emptyset) \parallel \text{mac}_1 \parallel \text{mac}_2]$$
3. **Transport Keys Derived**:
   $$\text{Split}(ck) \to (\text{key}_{\text{init}\to\text{resp}}, \text{key}_{\text{resp}\to\text{init}})$$

### 3.2 Anti-Spoofing Cryptographic Routing
When an encrypted TransportData packet arrives:
1. `receiver_index` looks up the sender's peer session.
2. Anti-replay sliding window verifies packet counter $C$.
3. ChaCha20-Poly1305 authenticates and decrypts the payload.
4. The inner packet's source IP is tested against `routing_trie.lookup(source_ip)`.
   If $\text{lookup}(\text{source\_ip}) \neq \text{peer\_id}$, the packet is dropped immediately with a `CryptographicRoutingViolation`.

---

## 4. Consequences and Verification

### Positive Consequences
- **Zero-Trust Network Architecture**: Eliminates vulnerable perimeter VPN models in favor of micro-segmented, cryptographically bound peer-to-peer tunnels.
- **Ultra-High Throughput**: ChaCha20-Poly1305 and X25519 operate at line rate ($> 500\,\text{MB/s}$ encryption/decryption throughput on modern CPUs).
- **Pure Safe Rust**: Zero `unsafe` code (`#![forbid(unsafe_code)]`), zero external C dependencies.
- **Cross-Platform**: Seamless operation on macOS and Linux without external kernel modules or root TUN/TAP permissions required for userspace framing.

### Verification Matrix
- **Unit Tests**: `crates/velcrux-core/src/mesh/mod.rs` (7/7 passing).
- **Core Integration Tests**: `crates/velcrux-core/tests/mesh_tunnel_tests.rs` (6/6 passing).
- **Client CLI Tests**: `crates/velcrux-client/tests/cli_mesh.rs` (4/4 passing).
