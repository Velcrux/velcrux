# CLAUDE.md — velcrux project invariants

This file is the canonical, authoritative context for the `velcrux` project. Read it first.
It is short on purpose. It points to the detailed docs and states the rules that must
never be silently broken.

## 0. Doc index — read these on demand

Load the doc that matches the task. Do not guess at content covered by a doc you
have not read.

| If the task touches...                                          | Read                     |
|-----------------------------------------------------------------|--------------------------|
| what the project is, CLI surface, quickstart                    | `README.md`              |
| module layout, data flow, pipelines, concurrency, backpressure  | `docs/ARCHITECTURE.md`   |
| wire format, message types, framing, state machines, versioning | `docs/PROTOCOL.md`       |
| auth, authz, TLS, path validation, threat model, limits         | `docs/SECURITY.md`       |
| benchmarks, tuning, chunk sizing, stream counts, targets        | `docs/PERFORMANCE.md`    |
| build, test, fuzz, netem harness, local dev certs               | `docs/DEVELOPMENT.md`    |
| deployment, systemd, config reference, metrics, runbooks        | `docs/OPERATIONS.md`     |
| why a decision was made / proposing to change one               | `docs/adr/`              |
| tracing *why* a requirement exists at all (origin spec)         | `docs/REQUIREMENTS.md`†  |

† `REQUIREMENTS.md` is the historical origin prompt, kept for provenance only.
It is **not authoritative** — this file and the seven docs above always win on
conflict. Do not derive message types, limits, or defaults from it directly;
`docs/PROTOCOL.md` §5 is the definitive list of where the design deviated from it.
Load it only when asked "why does X exist" or "did we cover requirement Y",
never as a default context file.

If a change contradicts one of these docs, update the doc in the same change.
If a change contradicts this file, stop and ask.

## 1. Hard invariants

1. **QUIC is the transport.** Never implement retransmission, ACKs, congestion
   control, packet numbering, or TLS by hand. Transport lives behind the
   `Transport` trait (`core/transport`).
2. **Never invent cryptography.** BLAKE3 and rustls/QUIC-TLS only. No custom
   ciphers, no custom KDFs, no custom MACs.
3. **Nothing is sized by the file.** No API may allocate proportional to file or
   dataset size. Bounded memory, streaming everywhere. A 10 TB file transfers in
   the same RSS envelope as a 10 GB file.
4. **All sizes, offsets, and counters are `u64`.** Never `u32`, never `usize` in
   a wire struct or a persisted struct.
5. **Client metadata is untrusted.** Every path, length, count, and hash from the
   wire is validated before it reaches storage or the allocator.
6. **A hash is never sufficient on its own.** Chunk hash verified on receipt,
   whole-file hash verified before commit. Byte count is never a success signal.
7. **No unbounded queues or channels** on any path fed by the network or the disk.
   Bounded capacity, and backpressure must propagate end to end.
8. **Never overwrite the destination in place.** Stage to `<name>.velcrux-partial`,
   verify, `fsync`, atomic `rename`.
9. **Deletion is never implicit.** `sync` never deletes. Only `--delete` /
   `--delete-after` do, and both are logged per-path.
10. **Measure before optimizing.** No `unsafe`, no platform-specific path, no
    io_uring, without a committed benchmark showing the win.

## 2. Locked decisions (see ADRs to change)

- Language: **Rust**, stable, cargo workspace. `#![forbid(unsafe_code)]` in every
  crate except an isolated, documented, fuzzed exception crate. — ADR-002
- QUIC: **quinn** + rustls. — ADR-001
- Hash: **BLAKE3-256** for chunk identity, file identity, manifest integrity.
  SHA-256 offered only as a negotiated interop/compliance mode. — ADR-003
- Chunking: **content-defined (gear rolling hash)** default; fixed-size available.
  Defaults min 256 KiB / target 1 MiB / max 4 MiB. — ADR-004
- Manifest: **streaming, framed binary, zstd-compressed on the wire**; never a
  `Vec<ChunkDesc>` over a whole dataset. — ADR-005
- Local metadata / transfer state: **SQLite in WAL mode**, one DB per role
  (client state DB, server state DB). — ADR-005
- Chunk store: content-addressed, optional, behind `ChunkStore` trait. — ADR-006
- Streams: **one QUIC stream per file** for MVP; multi-stream-per-file is a
  benchmark-gated follow-up, not an MVP feature. — ADR-007
- Protocol version starts at **1**; capability negotiation from day one. — ADR-008

## 3. Repo layout

```
velcrux/
├── CLAUDE.md
├── README.md
├── docs/{ARCHITECTURE,PROTOCOL,SECURITY,PERFORMANCE,DEVELOPMENT,OPERATIONS}.md
├── docs/adr/ADR-0NN-*.md
├── crates/
│   ├── velcrux-core/    protocol, transfer, sync, chunking, hashing,
│   │                    storage, auth, scheduler, telemetry
│   ├── velcrux-client/  CLI + client engine
│   └── velcrux-server/  daemon + authz + storage root
├── tests/              integration + failure injection
├── benches/            criterion + end-to-end harness
└── examples/
```

## 4. Open questions — do not decide unilaterally

1. Whether `sync --delete` should ever be allowed for a non-admin role.
2. Extended attribute / ACL fidelity: how much do we promise on Linux vs macOS?
3. Whether the server may serve chunks from the dedup store for files the caller
   is not authorized to read (it must not — but the enforcement design needs a
   second reviewer).
4. Multi-tenant chunk store: shared vs per-tenant namespace.

## 5. Working style

- Small, testable milestones. Implement → test → benchmark → document → continue.
- Diff-style edits for narrow changes; full-file regeneration only for broad ones.
- When a requirement is ambiguous, name the alternatives and pick a default with a
  written reason. Do not silently choose.
- When a requirement creates a security or correctness hazard, stop and say so.
