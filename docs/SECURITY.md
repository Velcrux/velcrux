# SECURITY

## 1. Design principles

1. **Never invent cryptography.** QUIC/TLS 1.3 via rustls for transport security;
   BLAKE3 for integrity. No custom ciphers, KDFs, MACs, or handshakes.
2. **Authentication and authorization are separate.** Authentication answers *who
   is this*. Authorization answers *what may they do, and where*. They are
   different traits, different code, different tests.
3. **The server assumes every client is hostile.** Every length, count, path,
   hash, and flag from the wire is validated before it influences an allocation,
   a filesystem call, or a state transition.
4. **Validation is enforced by types, not discipline.** The storage API accepts
   only `VPath`, which cannot be constructed except by the authorizer. There is no
   code path that reaches the filesystem with an unvalidated path.
5. **Fail closed.** Unknown state, unparseable input, or an internal error denies
   the operation and never falls through to a permissive default.
6. **No insecure default, ever.** Certificate validation cannot be disabled by
   configuration. See §3.

## 2. Authentication

### mTLS (MVP, default)

Both sides present certificates during the QUIC/TLS 1.3 handshake. The server
requires a client certificate; a handshake without one fails. The client verifies
the server certificate against a configured trust root and checks the hostname.

The client identity is derived from the certificate, in this order:
1. `subjectAltName` of type URI matching `velcrux://identity/<name>`, if present;
2. otherwise the Common Name.

The result is an `Identity { name, issuer_fingerprint, cert_fingerprint }`. Identity
is bound to the connection at handshake and is immutable for the connection's life
— there is no re-authentication or identity-switching message.

Requirements:
- TLS 1.3 only. TLS 1.2 and below are not offered.
- Ed25519 or ECDSA P-256 keys. RSA accepted at ≥ 3072 bits for interop.
- Certificate expiry, `notBefore`, key usage, and EKU are all checked.
- Revocation: CRL file reloaded on SIGHUP for the MVP. OCSP stapling is a
  post-MVP item; the limitation is documented rather than papered over.

### Public-key (SSH-style) — secondary

For deployments without a PKI, an `authorized_keys`-style file maps Ed25519 public
keys to identities. The `AUTH` message carries a signature over
`"velcrux-auth-v1" || exporter_secret`, where `exporter_secret` is a 32-byte value from
the **TLS keying material exporter** (RFC 8446 §7.5) for this connection.

Binding the signature to the TLS exporter is the important part: it channel-binds
the proof to this specific connection, so a captured `AUTH` message is useless
elsewhere and useless later. This is the replay defence, and it is why we do not
need a nonce round trip.

### Not supported, by design

Plaintext passwords are never sent, never accepted, and there is no mechanism id
reserved for them. Bearer tokens (JWT/OIDC/API keys) have a reserved mechanism id
and an `Authenticator` implementation shape, but no implementation in the MVP —
adding one must not require touching the protocol layer.

## 3. TLS configuration

| Setting                  | Development                       | Production                    |
|--------------------------|-----------------------------------|-------------------------------|
| Server cert              | `velcruxd gen-dev-cert` (self-signed, 24 h) | CA-issued or internal PKI |
| Client trust root        | Explicit path to the dev CA       | Org CA bundle                 |
| Hostname verification    | **On**                            | **On**                        |
| Cert validation bypass   | **Does not exist**                | **Does not exist**            |

There is deliberately no `--insecure`, no `--no-verify`, and no
`accept_invalid_certs` config key. Development uses a real (short-lived,
self-signed) CA that the client is explicitly pointed at. A validation-bypass flag
is the single most commonly shipped security hole in transfer tools; the way to not
ship it is to never implement it.

Cipher suites are rustls defaults (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305,
all AEAD, all with forward-secret key exchange). We do not expose a knob to widen
this.

Replay resistance: TLS 1.3 0-RTT is **disabled**. 0-RTT data is replayable by
design, and a replayed `TRANSFER_CREATE` or `CANCEL` is a real hazard. The saved
RTT is not worth it — our transfers last minutes to days.

## 4. Authorization

### Model

```
Identity → [Grant]
Grant { path_prefix: VPath, permissions: PermSet }
```

Permissions: `upload`, `download`, `list`, `delete`, `sync`, `resume`, `admin`.

Every operation resolves to `(Identity, Op, raw_path)` and is checked *before* any
filesystem call. Denied requests never touch the disk — otherwise timing and error
differences leak the existence of files outside the caller's scope.

```toml
[[grant]]
identity    = "svc-replica"
path        = "/data/customerA"
permissions = ["upload", "download", "list", "sync", "resume"]
# note: no "delete" — see CLAUDE.md §4 open question 1

[[grant]]
identity    = "ops-admin"
path        = "/"
permissions = ["admin"]
```

The longest matching prefix wins. No grant means deny. `admin` does not imply
`delete` on paths outside its own grant prefix.

### Path validation

`raw_path` from the wire is untrusted. The pipeline, in order — and order matters:

1. Reject if not valid UTF-8.
2. Reject NUL bytes and, on Windows targets, reject `:`, reserved device names
   (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), trailing dots and
   spaces, and any `\\?\` or `\\.\` prefix.
3. Reject absolute paths and drive-letter prefixes. Client paths are always
   relative to the grant root.
4. Split on `/`, reject any `..` component **lexically, before touching the
   filesystem**. We do not "resolve then check" — resolution can be raced.
5. Join to the grant root.
6. `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` on Linux ≥ 5.6. This is the
   real defence: it makes escape impossible at the syscall level rather than
   relying on our string logic being perfect. Where unavailable, fall back to
   `O_NOFOLLOW` on every component plus a post-open `fstat` device/inode check
   against the root.
7. Only now construct `VPath`.

Symlinks are **never followed** for resolution. A symlink in a manifest is recreated
as a symlink only if its target, resolved lexically, stays within the grant root;
otherwise the entry is refused with `INVALID_PATH`. We do not silently rewrite the
target — a silently-rewritten symlink is a correctness bug the user cannot see.

TOCTOU: the check-then-use window is closed by holding the `openat2` file
descriptor and doing all subsequent I/O against that fd, never re-resolving the
path by name.

## 5. Threat model

Assets: data confidentiality and integrity in transit; destination data integrity;
server availability; the storage root's confidentiality boundary between tenants.

| Threat                       | Defence                                                                 |
|------------------------------|-------------------------------------------------------------------------|
| Passive network observer     | QUIC/TLS 1.3, all payload and metadata encrypted                        |
| MITM                         | Mutual certificate validation; hostname verification; no bypass exists  |
| Replay of authentication     | Channel-bound to TLS exporter; 0-RTT disabled                           |
| Replay of transfer messages  | QUIC packet-level replay protection; idempotency keys make retries safe  |
| Credential theft             | Short-lived certs recommended; CRL; per-identity grants limit blast radius |
| Malicious client — traversal | §4 pipeline; `RESOLVE_BENEATH`; type-enforced `VPath`                   |
| Malicious client — symlink escape | Never follow; lexical target validation; refuse rather than rewrite |
| Malicious client — hard-link escape | Hard links only recreated within one transfer, target must already be a committed `VPath` |
| Malicious client — memory exhaustion | Every length checked against a limit before allocation (§6)      |
| Malicious client — CPU exhaustion | Auth deadline; bounded hashing pool; manifest entry cap; CDC has hard max chunk size |
| Malicious client — disk exhaustion | Per-identity quota checked before staging; `fallocate` reservation; `DISK_FULL` |
| Malicious client — connection exhaustion | Per-IP and global connection caps; unauthenticated conns capped separately and dropped first |
| Malicious client — stream exhaustion | QUIC `max_streams` set explicitly, not left to library defaults    |
| Malicious manifest           | Entry count, path, size, chunk count, and chunk length all bounded; total declared size checked against quota before any staging |
| Malicious chunk metadata     | Offset+length must lie within declared file size; overlapping ranges rejected; declared sum must equal declared file size |
| Oversized messages           | `max_message_size` checked pre-allocation                               |
| Decompression bomb           | Declared decompressed size checked against `max_chunk_size` before allocation; zstd window capped; ratio cap |
| Hash collision / bad chunk   | Chunk hash verified pre-write; whole-file hash verified pre-commit      |
| Malicious server (to client) | Client verifies server cert; client verifies whole-file hash it computed itself against the manifest it authored (upload) or the one it received and pinned (download) |
| Amplification / reflection   | QUIC address validation with retry tokens; server never sends more than 3× received bytes to an unvalidated address |
| Information leak via errors  | Uniform `PERMISSION_DENIED`/`FILE_NOT_FOUND` behaviour outside scope; no paths, no internals in `detail` |
| Silent corruption from Bloom filters | Probabilistic structures are pre-filters only; reuse decisions come from exact `CHUNK_RESPONSE` |

### Out of scope

- Compromised endpoint host, malicious root on either side.
- Traffic-analysis resistance. Transfer size and timing are observable.
- Rogue CA in the trust store.
- Physical access, side channels on the host.

## 6. Resource limits

Every one of these is enforced, has a config key, and has a test that trips it.

| Limit                        | Default   | Enforcement point                     |
|------------------------------|-----------|---------------------------------------|
| `max_connections`            | 100       | On accept                             |
| `max_connections_unauth`     | 20        | Separate pool, dropped first          |
| `max_connections_per_ip`     | 10        | On accept                             |
| `max_transfers_per_conn`     | 16        | `TRANSFER_CREATE`                     |
| `max_concurrent_streams`     | 32        | QUIC transport parameter              |
| `max_message_size`           | 1 MiB     | Frame decode, pre-allocation          |
| `max_chunk_size`             | 16 MiB    | Frame decode and manifest validation  |
| `max_manifest_entries`       | 50 M      | `MANIFEST_BEGIN`, pre-accept          |
| `max_manifest_bytes`         | 8 GiB     | Streamed to spill file, counted       |
| `max_file_size`              | 64 TiB    | `MANIFEST_BEGIN` and `TRANSFER_CREATE`|
| `max_path_len`               | 4096      | Path validation                       |
| `max_path_depth`             | 128       | Path validation                       |
| `max_auth_attempts`          | 3/conn    | Then close; per-IP backoff            |
| `max_memory_per_conn`        | 256 MiB   | Accounted, not estimated              |
| `quota_bytes_per_identity`   | unset     | Checked before staging reservation    |
| `min_free_space`             | 1 GiB     | Disk reservation margin, `TRANSFER_CREATE` |
| `decompress_ratio_cap`       | 64×       | Before zstd decode                    |

Queues: every channel that carries network- or disk-fed work is bounded. There is a
lint-enforced ban on `unbounded_channel` in `velcrux-core` and `velcrux-server`.

Memory accounting is real, not estimated: buffers come from a pool with a hard
capacity, and a connection that would exceed its share blocks on acquisition rather
than allocating.

## 7. Logging and secrets

Never logged, at any level: private keys, key file contents, authentication tokens,
signatures, TLS session secrets, TLS exporter output, full configuration dumps.

A `Secret<T>` newtype with a redacting `Debug`/`Display` wraps every such value, so
accidentally logging one prints `[redacted]` rather than the value. This is checked
by a test that formats a fully-populated config and greps the output.

Configuration may reference secrets by path or environment variable
(`private_key = "env:VELCRUX_KEY"` or a file path); inline secrets in a config file are
permitted but the file's permissions are checked at startup and the server refuses
to start on a world-readable key file.

Structured log fields: `ts`, `level`, `component`, `conn_id`, `transfer_id`,
`file_id`, `identity`, `msg`. Identities are logged; credentials are not.

## 8. Security testing

Required in CI, not optional:

- **Fuzzing & Parser Security Hardening** (`./scripts/fuzz.sh`, `cargo-fuzz`, ASan):
  * **In-process property-based protocol fuzzer** (`crates/velcrux-core/tests/protocol_fuzzing.rs`): 100,000+ random and mutated inputs executed deterministically across all 26+ message decoders, frame decoders, manifest codecs, varints, `RleBitmap`, `BloomFilter`, `VPath`, and `BatchContainerReader`.
  * **Live connection actor fuzzer** (`crates/velcrux-server/tests/server_fuzzing.rs`): adversarial streams, early EOF, boundary frame sizes (`1 << 62`, `u64::MAX`), and out-of-order state transitions against `ServerConn`.
  * **Coverage-guided libFuzzer targets** (`fuzz/`): `frame_decoder`, `manifest_decoder`, `path_validator`, `config_parser`, `cert_identity`, `vbatch_decoder`.
  * **Committed seed corpus boundary test matrix** (`crates/velcrux-server/tests/fuzz_corpus.rs`).
  * Targets verified: random bytes, truncated messages, oversized varints, non-canonical varints, length/actual mismatches, integer-overflow boundary values (`u64::MAX`, `u64::MAX - 1`, offsets summing past `u64::MAX`), invalid UTF-8, decompression bomb prevention, and bounded pre-allocations (`buffer.len() / min_elem_size`).
- **Path traversal corpus**: `../`, `..\\`, encoded variants, absolute paths, UNC
  and `\\?\` prefixes, deep `..` chains, `.` and empty components, Unicode
  normalization tricks, overlong paths, symlink chains, a symlink to `/`, a
  symlink loop, and a directory replaced by a symlink mid-transfer (TOCTOU race
  test with a hostile concurrent thread).
- **Resource exhaustion**: manifests declaring `u64::MAX` entries, frames
  declaring `u64::MAX` length, 10 000 concurrent connections, stream floods, a
  zstd bomb, an authentication flood.
- **Authorization matrix test**: every (identity, op, path) pair from a fixture,
  asserted against an expected allow/deny table — including cross-tenant reads,
  dedup-store reads for unauthorized content, and `delete` without the permission.
- **Invalid state transitions**: every message type sent in every state, asserting
  a clean `PROTOCOL_VIOLATION` close and, critically, that the server process
  survives and other connections are unaffected.

The bar: **a malformed or malicious client must never crash the server, exhaust its
memory, or reach a byte outside its grant root.** Any fuzz crash is a release
blocker. Zero panics on untrusted wire inputs is strictly guaranteed.

## 9. Known limitations

Stated plainly rather than left to be discovered:

- No OCSP stapling; revocation is CRL-file-based and only as fresh as the last
  SIGHUP.
- No xattr or ACL transfer in the MVP; a `sync` that encounters them warns.
- No traffic-analysis resistance.
- Whole-directory commit is not atomic (see `ARCHITECTURE.md` §9).
- `RESOLVE_BENEATH` requires Linux ≥ 5.6. The fallback path is sound but has more
  moving parts, and is the place to look first for a traversal bug.
- Multi-tenant dedup namespace design is unresolved (`CLAUDE.md` §4).

## 10. Reporting

Report vulnerabilities privately to the address in the repository's security
policy. Do not open public issues for exploitable findings.
