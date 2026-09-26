//! Top-level error type for `velcrux-core`.
//!
//! Per `DEVELOPMENT.md` §8: thiserror per module, one crate-level enum at the
//! boundary. Every wire-visible error maps to a code in `PROTOCOL.md` §10.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, VelcruxError>;

/// Errors that can surface from any layer of `velcrux-core`.
///
/// `Protocol` variants come from the protocol module; `Transport` from the
/// transport module; `Io` is reserved for actual disk/network I/O done in
/// higher-level helpers (none in M1).
#[derive(Debug, Error)]
pub enum VelcruxError {
    /// A protocol-level error. Most of these map to a wire error code in
    /// `protocol::error::ErrorCode`.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// A transport-level error. Wraps `quinn::ConnectionError` and friends.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// I/O error. We surface these verbatim from `std::io` so callers can
    /// pattern-match on `ErrorKind`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A configuration error (bad TOML, missing path, etc.).
    #[error("configuration error: {0}")]
    Config(String),

    /// Catch-all for invariant violations. These should never fire; if one
    /// does it is a bug in `velcrux-core`, not a user error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Protocol-level errors. These are produced by the pure decoder logic in
/// `protocol::*` and never touch I/O.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The input was empty when at least one byte was required.
    #[error("input is empty")]
    Empty,

    /// A varint was encoded with more bytes than its value required.
    /// Per `PROTOCOL.md` §1 decoders reject over-long encodings so two
    /// representations of the same value cannot be used to smuggle state.
    #[error("non-canonical varint encoding")]
    NonCanonicalVarint,

    /// A varint was longer than 10 bytes (LEB128 limit for u64).
    #[error("varint overflow (>10 bytes)")]
    VarintOverflow,

    /// A `length` field exceeded `max_message_size` (or another named limit).
    /// This is the single most important bound in the protocol; a frame whose
    /// declared length would not fit in memory is rejected **before** any
    /// allocation (`PROTOCOL.md` §3).
    #[error("frame length {declared} exceeds limit {limit}")]
    FrameTooLarge { declared: u64, limit: u64 },

    /// The wire version byte did not match the negotiated version.
    #[error("protocol version mismatch: got {got}, expected {expected}")]
    VersionMismatch { got: u8, expected: u8 },

    /// An unknown or unexpected message type was received in the current
    /// state. Per `PROTOCOL.md` §7 unknown types on the control stream are
    /// answered with `ERROR{UNSUPPORTED_MESSAGE}` and the connection
    /// continues; the server-side state machine enforces valid transitions.
    #[error("unsupported message type: 0x{0:02x}")]
    UnsupportedMessage(u8),

    /// An invalid state transition was attempted. This is a `PROTOCOL_VIOLATION`
    /// on the wire and closes the connection.
    #[error("invalid state transition: {0}")]
    InvalidStateTransition(&'static str),

    /// A required field was missing or malformed.
    #[error("malformed payload: {0}")]
    Malformed(&'static str),

    /// A path validation failure. The detail string is intentionally generic
    /// (`PROTOCOL.md` §10: `PERMISSION_DENIED` and `FILE_NOT_FOUND` are
    /// indistinguishable in timing and detail for paths outside scope).
    #[error("invalid path")]
    InvalidPath,

    /// A cryptographic identity could not be derived from the peer certificate.
    #[error("invalid identity: {0}")]
    InvalidIdentity(&'static str),

    /// The caller is authenticated but not authorized for this operation/path.
    #[error("permission denied")]
    PermissionDenied,

    /// A manifest failed validation (hash mismatch, bounds violation, bad format).
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    /// A resource limit (bandwidth, connections, memory) was hit.
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// The caller exceeded its quota.
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
}

/// Transport-level errors. These wrap the underlying QUIC errors and add
/// our own context where useful.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Underlying QUIC error. The source is preserved for logging.
    #[error("QUIC connection error: {0}")]
    Quinn(#[from] quinn::ConnectionError),

    /// QUIC write error.
    #[error("QUIC write error: {0}")]
    QuinnWrite(#[from] quinn::WriteError),

    /// QUIC read error (after the read future has resolved).
    #[error("QUIC read error: {0}")]
    ReadError(String),

    /// TLS configuration error (rustls).
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    /// The peer did not present a client certificate (mTLS required).
    #[error("peer did not present a client certificate")]
    NoClientCertificate,

    /// Endpoint configuration error.
    #[error("endpoint error: {0}")]
    Endpoint(String),

    /// Connection was closed cleanly with a code we care about.
    #[error("connection closed by peer: code={code} reason={reason}")]
    ClosedByPeer { code: u32, reason: String },
}

// `#[from]` on the `Protocol` variant above already provides
// `From<ProtocolError> for VelcruxError`.

// Bridge the `?` operator: `From<X> for TransportError` exists via
// `#[from]` on each variant, but the `?` operator needs
// `From<X> for VelcruxError` (the outer enum) too, so callers can write
// `conn.await?` inside a function returning `Result<T, VelcruxError>`.

impl From<quinn::ConnectionError> for VelcruxError {
    fn from(e: quinn::ConnectionError) -> Self {
        VelcruxError::Transport(TransportError::Quinn(e))
    }
}

impl From<quinn::WriteError> for VelcruxError {
    fn from(e: quinn::WriteError) -> Self {
        VelcruxError::Transport(TransportError::QuinnWrite(e))
    }
}

impl From<rustls::Error> for VelcruxError {
    fn from(e: rustls::Error) -> Self {
        VelcruxError::Transport(TransportError::Tls(e))
    }
}
