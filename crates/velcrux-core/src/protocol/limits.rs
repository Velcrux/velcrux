//! Named constants for every protocol limit. Every default the code uses is
//! defined here, with a comment naming the doc it came from, per
//! `DEVELOPMENT.md` §8 ("no magic numbers on the wire or in limits").
//!
//! All values are conservative; the negotiated limits in `HELLO_ACK` may
//! lower them per connection.

/// Protocol version (`PROTOCOL.md` header).
///
/// Versioning is from day one (ADR-008). The version is *not* frozen until
/// the MVP definition-of-done is met (`PROTOCOL.md` §9).
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum payload size of a control or metadata frame, in bytes
/// (`PROTOCOL.md` §3, default 1 MiB). This is the single most important
/// bound in the protocol; the frame decoder rejects oversized frames
/// *before* any allocation.
pub const MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

/// Maximum size of a single chunk, in bytes (`OPERATIONS.md` §4, default
/// 4 MiB). The hash manifest encodes chunks no larger than this.
pub const MAX_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Default chunk target size, in bytes (`OPERATIONS.md` §4, default 1 MiB).
pub const DEFAULT_CHUNK_TARGET: u64 = 1024 * 1024;

/// Default minimum chunk size, in bytes (`OPERATIONS.md` §4, default 256 KiB).
pub const DEFAULT_CHUNK_MIN: u64 = 256 * 1024;

/// Maximum entries per manifest. Default from `OPERATIONS.md` §4
/// (50_000_000). Manifests larger than this must be split.
pub const MAX_MANIFEST_ENTRIES: u64 = 50_000_000;

/// Maximum total size of a manifest on the wire or spilled to disk, in bytes
/// (`SECURITY.md` §10, default 8 GiB).
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Target number of manifest entries per `MANIFEST_BATCH` frame (`PROTOCOL.md` §4).
pub const MANIFEST_BATCH_SIZE: usize = 4096;

/// Maximum decompressed payload size of a single `MANIFEST_BATCH` frame,
/// in bytes (`SECURITY.md` §10 decompression-bomb defense).
pub const MAX_BATCH_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// Maximum size of a single path component, in bytes
/// (`SECURITY.md` §4, derived from common FS limits).
pub const MAX_PATH_COMPONENT: usize = 255;

/// Maximum total path length, in bytes (`SECURITY.md` §4).
pub const MAX_PATH_TOTAL: usize = 4096;

/// QUIC idle timeout, seconds (`PROTOCOL.md` §11, default 60).
pub const QUIC_IDLE_TIMEOUT_SECS: u64 = 60;

/// Keepalive interval, seconds (`PROTOCOL.md` §11, default 15).
pub const QUIC_KEEPALIVE_SECS: u64 = 15;

/// Maximum size of an `ERROR` detail string, in bytes. Per
/// `PROTOCOL.md` §10 the detail is short and non-sensitive; we cap it
/// to keep a misbehaving client from sending megabytes of "detail".
pub const MAX_ERROR_DETAIL: usize = 256;

/// Default agent string advertised in HELLO. Format: `name/version (target)`.
pub const AGENT_STRING: &str = concat!("velcrux/", env!("CARGO_PKG_VERSION"));

/// ALPN protocol identifier (`PROTOCOL.md` header). Negotiated during the
/// QUIC/TLS handshake.
pub const ALPN: &[u8] = b"VELCRUX/1";

/// M3 checkpoint cadence: 1 GiB (sender side; receiver persists every
/// chunk on receive, so the sender drives the wire-side CHECKPOINT
/// message frequency).
pub const CHECKPOINT_BYTES_INTERVAL: u64 = 1 << 30;

/// M3 checkpoint cadence: 10 seconds (sender side).
pub const CHECKPOINT_TIME_INTERVAL_MS: u64 = 10_000;

/// Maximum size of the opaque token carried in an `AUTH` message, in bytes
/// (`SECURITY.md` §2). mTLS sends an empty token; future mechanisms
/// (SSH-style public key) send a signature, which is far smaller. Bounded
/// so the decoder rejects oversized tokens before allocation.
pub const MAX_AUTH_TOKEN: usize = 4096;

/// Maximum length of an identity name (`SECURITY.md` §2: SAN URI or CN).
/// Bounded in the `AUTH_OK` decoder before allocation.
pub const MAX_IDENTITY_LEN: usize = 255;
