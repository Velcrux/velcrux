# ADR-049: Zero-Trust Decentralized Identity (DID) & Verifiable Credential Attestation Mesh

Status: Accepted · Date: 2026-10-30

## Context

Federated enterprise data movement, cross-tenant synchronization, and edge IoT mesh workloads require cryptographically provable authorization without relying on central Certificate Authorities (CAs), single-point-of-failure OAuth/OIDC token servers, or synchronous LDAP/Kerberos domain controllers:
- **Air-Gapped & Offline Edge Transfers**: Edge storage nodes, disconnected field sensors, and naval or aerospace deployments cannot query centralized PKI infrastructure or CRL/OCSP endpoints to validate peer authorization.
- **Microservice & Agent Delegation**: Autonomous sub-agents and transient pipeline processes require scoped, short-lived authority to transfer subsets of paths (e.g. `/finance/q3/*`) with restricted operations (`download` only) without exposing master signing keys.
- **Byzantine Multi-Cloud Environments**: Storage clusters spanning AWS, GCP, Azure, and on-premise locations must authenticate and authorize cross-cluster peer operations deterministically across untrusted intermediate networks.

Prior access control mechanisms in storage systems suffer from severe architectural limitations:
1. **Centralized CA / PKI Single Point of Failure**: Traditional X.509 mTLS hierarchies require central root CAs, intermediate CA key escrow, and brittle CRL/OCSP network revocation checks that fail during network partitions or offline edge operations.
2. **Coarse-Grained Static Access Tokens**: Static API bearer tokens or symmetric shared secrets lack cryptographically bound tenant isolation, granular path globs, rate limit ceilings, or ephemeral delegation depth constraints.
3. **Privilege Escalation in Chained Workflows**: In automated multi-step data pipelines, passing root credentials to downstream nodes creates massive vulnerability surfaces because delegated processes cannot be cryptographically constrained to subsets of the parent's permissions.

To provide zero-trust, cryptographically autonomous authorization for transfer operations, Velcrux requires an attestation mesh based on W3C Decentralized Identifiers (DIDs) and W3C Verifiable Credentials (VCs).

---

## Options Considered

1. **Option 1: Traditional X.509 Attribute Certificates**:
   - Issue ITU-T X.509 attribute certificates signed by an internal intermediate CA.
   - *Rejected*: Inflexible ASN.1 DER encodings, heavyweight validation overhead, tight coupling to centralized PKI infrastructure, and failure during disconnected edge operations.
2. **Option 2: Signed JSON Web Tokens (JWT / RFC 7519) with OAuth 2.0**:
   - Issue OAuth 2.0 bearer JWTs containing transfer scopes.
   - *Rejected*: Central token issuer / JWKS endpoint dependency, lack of native capability delegation chains, vulnerable to token replay when not bound to peer public keys, and lacks W3C DID cryptographic subject identity.
3. **Option 3: Pure Safe Rust W3C Decentralized Identity (`did:key`, `did:peer`) & Verifiable Credential Attestation Mesh (`ADR-049`)**:
   - Uses W3C `did:key` and `did:peer` methods: public keys are self-certifying identifiers deterministically derived from Ed25519 public keys using multicodec (`0xed01`) and Base58BTC multibase (`z`) encoding.
   - Resolves into complete W3C DID Documents (`verificationMethod`, `authentication`, `assertionMethod`, `capabilityDelegation`) locally in sub-microsecond time with zero network requests.
   - Issues W3C Verifiable Credentials (`VelcruxTransferCapabilityCredential`) cryptographically signed via `Ed25519Signature2020` over canonical BLAKE3 digests.
   - Supports cryptographically verifiable capability delegation chains with monotonic delegation depth decrement, expiration clamping, and strict path/operation subset containment.

---

## Decision

Adopt **Option 3: Zero-Trust Decentralized Identity (DID) & Verifiable Credential Attestation Mesh (`ADR-049`)**.

### Architectural Design

```
+-----------------------------------------------------------------------------------------+
|                  Velcrux Zero-Trust DID & Verifiable Credential Attestation Mesh        |
|                                                                                         |
|  [ Ed25519 Public Key (32 bytes) ]                                                      |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐                            |
|   │ W3C Multicodec Prefix (0xed01) + Base58BTC Encoding    │                            |
|   │ -> did:key:z6M... / did:peer:0z6M...                   │                            |
|   └────────────────────────────────────────────────────────┘                            |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐                            |
|   │ Deterministic DID Document Resolution                  │                            |
|   │ - verificationMethod: did:key:...#key-1 (Ed25519)      │                            |
|   │ - authentication, assertionMethod, capabilityDelegation│                            |
|   └────────────────────────────────────────────────────────┘                            |
|             │                                                                           |
|             ▼                                                                           |
|   ┌────────────────────────────────────────────────────────┐   ┌──────────────────────┐ |
|   │ TransferCapabilitySubject:                             │   │ W3C VC Signing       │ |
|   │ - tenantId: tenant-alpha                               │◄──┤ Canonical BLAKE3     │ |
|   │ - allowedPaths: ["/data/*"]                            │   │ Domain Separator:    │ |
|   │ - allowedOperations: ["upload", "download"]            │   │ velcrux-vc-attest:v1 │ |
|   │ - maxBandwidthBps / rateLimitBurst                     │   │ Proof:               │ |
|   │ - delegationDepth: N                                   │   │ Ed25519Signature2020 │ |
|   └────────────────────────────────────────────────────────┘   └──────────────────────┘ |
|             │                                                                           |
|             ▼                                                                           |
|   ┌─────────────────────────────────────────────────────────────────────────────────┐   |
|   │ Zero-Trust Attestation Engine & Ephemeral Delegation Validator:                 │   |
|   │ 1. Verify Ed25519 signature of issuer via self-contained DID public key         │   |
|   │ 2. Validate current timestamp against [issuanceDate, expirationDate]             │   |
|   │ 3. Match requested transfer path against allowedPaths globs                     │   |
|   │ 4. Match requested operation against allowedOperations                          │   |
|   │ 5. Recursively verify parent delegation chain:                                  │   |
|   │    - parent.subject == child.issuer                                             │   |
|   │    - child.delegationDepth < parent.delegationDepth                             │   |
|   │    - child.expiration <= parent.expiration                                     │   |
|   │    - child.paths ⊆ parent.paths && child.ops ⊆ parent.ops                       │   |
|   └─────────────────────────────────────────────────────────────────────────────────┘   |
+-----------------------------------------------------------------------------------------+
```

### Deterministic Identifier Format

1. **`did:key`**:
   - Multicodec header: `[0xed, 0x01]` (two-byte varint encoding of Ed25519 public key type).
   - Concatenate header + raw 32-byte Ed25519 public key (total 34 bytes).
   - Encode with Base58BTC and prepend multibase indicator `'z'`.
   - Result: `did:key:z6M...`.

2. **`did:peer` (Numalgo 0 - Inception Key)**:
   - Method name: `did:peer:0`.
   - Encodes inception verification key multibase: `did:peer:0z6M...`.
   - Resolves deterministically into identical Ed25519 public key and capability assertions.

### Canonical BLAKE3 Signing Digest

To prevent cross-protocol signature forgery and guarantee deterministic canonical representation across programming languages and JSON parsers, the signing digest is computed over a strict binary domain-separated payload:
$$\text{Digest} = \text{BLAKE3}\left(\text{"velcrux-vc-attestation:v1:"} \parallel \text{vc.id} \parallel \text{vc.issuer} \parallel \text{subject.id} \parallel \text{tenant\_id} \parallel \text{issuance\_date} \parallel \text{expiration\_date} \parallel \text{paths} \parallel \text{ops} \parallel \text{bandwidth} \parallel \text{delegation\_depth} \parallel \text{parent\_sig}\right)$$

---

## Consequences

### Positive
- **Zero Central CA Dependency**: Completely offline peer verification. Nodes resolve public keys directly from DIDs in nanoseconds without network round-trips.
- **Cryptographic Capability Delegation**: Allows parent workers to delegate scoped sub-permissions to ephemeral workers with provable non-escalation invariants.
- **Sub-Microsecond Resolution**: Pure safe Rust Base58BTC decoder and multicodec unpacker resolve DIDs in $< 100\,\text{ns}$.
- **W3C Standards Compliance**: Interoperable with W3C DID Core 1.0, W3C Verifiable Credentials Data Model v1.1/v2.0, and `Ed25519Signature2020`.
- **Absolute Memory Safety**: 100% `#![forbid(unsafe_code)]` with zero external C dependencies.

### Negative
- Key rotation requires issuing updated DIDs and refreshing active Verifiable Credentials.
- Credential size includes delegation chain metadata when multi-hop delegation is used.
