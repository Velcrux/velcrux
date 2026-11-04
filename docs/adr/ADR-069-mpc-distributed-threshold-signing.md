# ADR-069: Zero-Knowledge Multi-Party Computation (MPC) Distributed Threshold Key Signing

- **Status**: Accepted
- **Date**: 2026-11-04
- **Deciders**: Velcrux Cryptography, Distributed Systems, Security Architecture, and Platform Core Teams
- **Consulted**: Security Operations, Infrastructure Engineering, Compliance, and Cluster Operations Teams

---

## 1. Context and Problem Statement

In distributed storage and high-throughput transfer clusters, cryptographic authority traditionally hinges on centralized private keys (e.g., cluster root certificates, root authorization tokens, node membership credentials, storage manifest attestations, and firmware update signing keys). This introduces critical security and architectural failure modes:
1. **Single Point of Compromise (SPoC)**: If a single cluster controller or administrator machine holding the master private key is compromised, an attacker gains unrestricted authority to mint root bearer tokens, forge manifests, or tamper with cluster membership.
2. **Single Point of Failure (SPoF)**: If the private key or its underlying hardware security module (HSM) is destroyed or goes offline during an outage, all cluster-level cryptographic operations freeze.
3. **Key Exfiltration Vulnerability**: Replicating master private keys across multiple controllers multiplies the attack surface, creating multiple targets for side-channel extraction or memory dumping.
4. **Lack of Cryptographic Accountability & Blame**: When keys are shared or delegations occur, detecting which specific node acted maliciously or suffered bit-flips during signing is impossible without zero-knowledge verification.

To eliminate single points of key compromise without sacrificing wire compatibility or verification performance, Velcrux requires **Zero-Knowledge Multi-Party Computation (MPC) Distributed Threshold Key Signing**.

---

## 2. Decision Drivers

- **$t$-of-$n$ Threshold Quorum Security**: Any subset of $t$ signers out of $n$ designated nodes can collaboratively produce a valid signature, while any coalition of fewer than $t$ nodes gains zero mathematical knowledge of the master private key.
- **Keyless Operational Reality**: The master private key never exists in full memory on any single node after Distributed Key Generation (DKG) or verifiable secret sharing.
- **Standard Ed25519 / RFC 8032 Wire Compatibility**: Threshold signatures must produce standard 64-byte Ed25519 signatures verifiable against a 32-byte master public key using standard verifiers (such as `ring`, libsodium, OpenSSL) without requiring verifiers to know $t$, $n$, or the MPC protocol.
- **Zero-Knowledge Proofs (ZKP) & Feldman Verifiable Secret Sharing (VSS)**: Participants cryptographically verify their shares against public commitments ($C_k = a_k \cdot B$) and prove knowledge of their private shares using Schnorr Non-Interactive Zero-Knowledge Proofs (NIZK DLEQ), precluding rogue-key attacks and dealer equivocation.
- **FROST Protocol with Deterministic Blame Attribution**: Implement the Flexible Round-Optimized Schnorr Threshold (FROST) protocol with per-participant binding factors ($\rho_i$) preventing concurrency replay attacks, while mathematically pinpointing malicious or corrupted shares.
- **Zero Unsafe Code**: 100% safe Rust (`#![forbid(unsafe_code)]`) with zero external C dependencies.

---

## 3. Considered Options

- **Option 1: Centralized HSM / Hardware Security Module**:
  - *Cons*: High hardware procurement cost, cloud provider lock-in, latency bottlenecks, and vendor-specific APIs.
- **Option 2: Multi-Signature Schemes (Cosigning $t$ independent signatures)**:
  - *Cons*: Increases signature size linearly by $t \times 64$ bytes; exposes signer identities and threshold policy to external verifiers; incompatible with standard single-key Ed25519 interfaces.
- **Option 3 (Chosen): FROST Distributed Threshold Signing with Feldman VSS & ZKP (`Option DA`)**:
  - Constant 64-byte Ed25519 signature and 32-byte public key.
  - Provable resistance to forgery under chosen-message attacks.
  - Deterministic blame attribution pinpointing faulty nodes.
  - Zero knowledge leakage of secret shares.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│               VELCRUX DISTRIBUTED THRESHOLD MPC SIGNING (FROST)                        │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  [Phase 1: Verifiable Secret Sharing / DKG]                                           │
│  Polynomial f(x) = s + a1*x + ... + a_{t-1}*x^{t-1} mod l                              │
│  Feldman Public Commitments: C_k = a_k * B (where C_0 = Y = Master Public Key)         │
│  Secret Shares s_i = f(i) mod l  ──> Verified by s_i * B == sum(i^k * C_k)             │
│  Schnorr ZKP Proof of Discrete Log: zkp_i = (R_{zkp}, z_{zkp})                         │
│                                                                                        │
│  [Phase 2: Round 1 (Ephemeral Nonce Commitments)]                                      │
│  Signer 1: (d1, e1) ──> Commitments (D1 = d1*B, E1 = e1*B)                             │
│  Signer 2: (d2, e2) ──> Commitments (D2 = d2*B, E2 = e2*B)   ──> CommitmentPackage     │
│  Signer 3: (d3, e3) ──> Commitments (D3 = d3*B, E3 = e3*B)                             │
│                                                                                        │
│  [Phase 3: Round 2 (Partial Signing & Binding Factors)]                                │
│  Binding Factor: rho_i = H_bind(i, M, commitments)                                     │
│  Group Nonce:    R = sum_{j in S} (D_j + rho_j * E_j)                                  │
│  Challenge:      c = SHA-512(R || Y || M) mod l                                        │
│  Lagrange Coeff: lambda_i = prod_{j != i} j / (j - i) mod l                            │
│  Partial Share:  z_i = d_i + (e_i * rho_i) + (lambda_i * s_i * c) mod l               │
│                                                                                        │
│  [Phase 4: Blame Attribution & Aggregation]                                            │
│  Share Check:    z_i * B == D_i + rho_i*E_i + lambda_i*c*Y_i  (Blame if False)         │
│  Aggregate:      z = sum_{i in S} z_i mod l                                            │
│  Threshold Sig:  (R, z)  ──> 64-byte compact Ed25519 signature                         │
│                                                                                        │
│  [Phase 5: Standard Single-Key RFC 8032 Verification]                                  │
│  Any Verifier:   z * B == R + c * Y  (Identical to single-party Ed25519!)              │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Mathematical Formulations

### 5.1 Scalar Field $\mathbb{F}_\ell$ & Curve Arithmetic
- Base field: $p = 2^{255} - 19$. Fast reduction via $2^{255} \equiv 19 \pmod p$.
- Scalar order: $\ell = 2^{252} + 27742317777372353535851937790883648493$.
- Twisted Edwards extended projective coordinates $(X : Y : Z : T)$ with curve equation:
  $$-x^2 + y^2 = 1 + d x^2 y^2 \pmod p \quad \text{where } d = -121665 / 121666 \pmod p$$
- Multiplicative inverse in $\mathbb{F}_\ell$ via Fermat's Little Theorem:
  $$a^{-1} \equiv a^{\ell - 2} \pmod \ell$$

### 5.2 Feldman Verifiable Secret Sharing (VSS)
A dealer or DKG round samples secret $s \in \mathbb{F}_\ell$ and random coefficients $a_1, \dots, a_{t-1} \in \mathbb{F}_\ell$:
$$f(x) = s + \sum_{k=1}^{t-1} a_k x^k \pmod \ell$$
Public commitments:
$$C_k = a_k \cdot B \quad (0 \le k < t, \text{ with } C_0 = Y = s \cdot B)$$
Each participant $i$ verifies its secret share $s_i = f(i)$ without revealing $s_i$:
$$s_i \cdot B \stackrel{?}{=} \sum_{k=0}^{t-1} (i^k \pmod \ell) \cdot C_k$$

### 5.3 Lagrange Interpolation in Quorum $S$
For any quorum of signers $S \subseteq \{1..n\}$ with $|S| \ge t$, the Lagrange basis coefficient at $x = 0$ is:
$$\lambda_i = \prod_{j \in S, j \neq i} \frac{j}{j - i} \pmod \ell$$
Such that:
$$\sum_{i \in S} \lambda_i s_i \equiv s \pmod \ell \implies \sum_{i \in S} \lambda_i Y_i = Y$$

### 5.4 FROST Aggregate Verification Proof
Each partial signature share is:
$$z_i = d_i + e_i \rho_i + \lambda_i s_i c \pmod \ell$$
Summing across all $i \in S$:
$$z = \sum_{i \in S} z_i = \sum_{i \in S} (d_i + e_i \rho_i) + c \sum_{i \in S} \lambda_i s_i = \sum_{i \in S} (d_i + e_i \rho_i) + c \cdot s \pmod \ell$$
Multiplying by base generator point $B$:
$$z \cdot B = \left(\sum_{i \in S} (d_i + e_i \rho_i)\right) B + c \cdot (s B) = \sum_{i \in S} (D_i + \rho_i E_i) + c \cdot Y = R + c \cdot Y$$
Thus, $(R, z)$ is a mathematically valid standard Ed25519 signature over message $M$ for public key $Y$.

---

## 6. CLI Command Suite

```bash
# Initialize a 3-of-5 threshold group with Feldman VSS commitments and DKG ZKP proofs
velcrux mpc init --threshold 3 --signers 5

# Execute a distributed threshold signing round across quorum {1, 2, 4}
velcrux mpc sign --message "Cluster Root Rebalance Ticket" --threshold 3 --quorum 1,2,4

# Cryptographically verify the 64-byte signature against the master group key
velcrux mpc verify --message "Cluster Root Rebalance Ticket" --signature <HEX> --pubkey <HEX>

# Inspect audit trail, session latencies, and ZKP discrete log knowledge proofs
velcrux mpc audit
```

---

## 7. Consequences and Status

- **Positive**:
  - Eliminates single points of compromise for root authorization tokens, manifest attestations, and membership certificates.
  - Indistinguishable from standard Ed25519 signatures, enabling drop-in verification by standard RFC 8032 libraries.
  - Sub-millisecond signing latency with optimized prime field reduction ($2^{255} \equiv 19 \pmod p$).
  - Blame attribution guarantees instant detection and isolation of faulty or compromised nodes.
- **Negative / Trade-offs**:
  - Two-round communication overhead during signing (mitigated by batch nonce pre-generation).
