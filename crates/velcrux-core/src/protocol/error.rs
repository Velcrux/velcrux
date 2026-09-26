//! Wire error codes and the `ERROR` message type.
//!
//! Code values and retryability come from `PROTOCOL.md` §10. The detail
//! string is non-sensitive by contract; we cap its length with
//! `MAX_ERROR_DETAIL`.

use crate::error::ProtocolError;
use crate::protocol::limits::MAX_ERROR_DETAIL;

/// Wire error code (`PROTOCOL.md` §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    /// Authentication failed (e.g. bad signature, unknown identity).
    AuthFailed = 1000,
    /// The caller is authenticated but not authorized for this op/path.
    PermissionDenied = 1001,
    /// Protocol version unsupported (no version overlap or capability
    /// intersection that lacks a mandatory capability).
    ProtocolVersionUnsupported = 1002,
    /// Protocol violation (e.g. invalid state transition). The connection
    /// is closed.
    ProtocolViolation = 1003,
    /// An unknown message type was received.
    UnsupportedMessage = 1004,
    /// The named file does not exist.
    FileNotFound = 2000,
    /// The path failed validation (traversal, absolute, symlink escape).
    InvalidPath = 2001,
    /// The named transfer does not exist.
    TransferNotFound = 2002,
    /// A manifest failed validation.
    InvalidManifest = 2003,
    /// A chunk was requested that the server does not have. May be retryable
    /// after the chunk is uploaded.
    ChunkNotFound = 2004,
    /// A chunk hash did not match the manifest. Retryable after a re-fetch.
    ChecksumMismatch = 3000,
    /// A write was only partial. Retryable.
    PartialWrite = 3001,
    /// A resource limit (memory, connections, bandwidth) was hit. Retryable.
    ResourceLimit = 4000,
    /// The server is overloaded. Retryable.
    ServerBusy = 4001,
    /// The destination is out of disk space. Retryable after space is freed.
    DiskFull = 4002,
    /// The caller exceeded its quota. Not retryable without operator action.
    QuotaExceeded = 4003,
    /// Transfer was cancelled by the peer.
    TransferCancelled = 5000,
    /// Generic network error. Retryable.
    NetworkError = 5001,
    /// Catch-all internal error. Retryable at the operator's discretion.
    InternalError = 5002,
}

impl ErrorCode {
    /// True if the protocol considers this error retryable by the client.
    pub const fn retryable(self) -> bool {
        use ErrorCode::*;
        matches!(
            self,
            ChunkNotFound
                | ChecksumMismatch
                | PartialWrite
                | ResourceLimit
                | ServerBusy
                | DiskFull
                | NetworkError
                | InternalError
        )
    }

    /// Convert to its wire form (u32 LE on the wire).
    #[inline]
    pub const fn to_wire(self) -> u32 {
        self as u32
    }

    /// Convert from a wire value. Unknown codes map to
    /// [`ErrorCode::InternalError`] (fail closed).
    pub const fn from_wire(code: u32) -> Self {
        match code {
            1000 => Self::AuthFailed,
            1001 => Self::PermissionDenied,
            1002 => Self::ProtocolVersionUnsupported,
            1003 => Self::ProtocolViolation,
            1004 => Self::UnsupportedMessage,
            2000 => Self::FileNotFound,
            2001 => Self::InvalidPath,
            2002 => Self::TransferNotFound,
            2003 => Self::InvalidManifest,
            2004 => Self::ChunkNotFound,
            3000 => Self::ChecksumMismatch,
            3001 => Self::PartialWrite,
            4000 => Self::ResourceLimit,
            4001 => Self::ServerBusy,
            4002 => Self::DiskFull,
            4003 => Self::QuotaExceeded,
            5000 => Self::TransferCancelled,
            5001 => Self::NetworkError,
            5002 => Self::InternalError,
            _ => Self::InternalError,
        }
    }
}

/// Static table of `(code, name)` for diagnostics and tests.
pub const ERROR_CODE_NAMES: &[(u32, &str)] = &[
    (1000, "AUTH_FAILED"),
    (1001, "PERMISSION_DENIED"),
    (1002, "PROTOCOL_VERSION_UNSUPPORTED"),
    (1003, "PROTOCOL_VIOLATION"),
    (1004, "UNSUPPORTED_MESSAGE"),
    (2000, "FILE_NOT_FOUND"),
    (2001, "INVALID_PATH"),
    (2002, "TRANSFER_NOT_FOUND"),
    (2003, "INVALID_MANIFEST"),
    (2004, "CHUNK_NOT_FOUND"),
    (3000, "CHECKSUM_MISMATCH"),
    (3001, "PARTIAL_WRITE"),
    (4000, "RESOURCE_LIMIT"),
    (4001, "SERVER_BUSY"),
    (4002, "DISK_FULL"),
    (4003, "QUOTA_EXCEEDED"),
    (5000, "TRANSFER_CANCELLED"),
    (5001, "NETWORK_ERROR"),
    (5002, "INTERNAL_ERROR"),
];

/// Detail string for an `ERROR` message. The string is sanitised:
/// `PERMISSION_DENIED` and `FILE_NOT_FOUND` deliberately share the same
/// detail to avoid leaking existence information (`PROTOCOL.md` §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetail(pub String);

impl ErrorDetail {
    /// Construct from a string, truncating to `MAX_ERROR_DETAIL`.
    pub fn new(s: impl Into<String>) -> Self {
        let mut s: String = s.into();
        if s.len() > MAX_ERROR_DETAIL {
            s.truncate(MAX_ERROR_DETAIL);
        }
        Self(s)
    }

    /// Build a generic "no such file or path outside scope" detail used for
    /// both `FILE_NOT_FOUND` and `PERMISSION_DENIED`.
    pub fn not_found_or_denied() -> Self {
        Self::new("not found")
    }

    /// Borrow the detail string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<ProtocolError> for ErrorDetail {
    fn from(e: ProtocolError) -> Self {
        // We do NOT leak protocol-internal error text to peers; the detail
        // is a coarse category. SECURITY.md §7 forbids including internal
        // strings in logs at any level; the same rule applies to the wire.
        let s: &'static str = match e {
            ProtocolError::Empty => "empty frame",
            ProtocolError::NonCanonicalVarint => "non-canonical varint",
            ProtocolError::VarintOverflow => "varint overflow",
            ProtocolError::FrameTooLarge { .. } => "frame too large",
            ProtocolError::VersionMismatch { .. } => "version mismatch",
            ProtocolError::UnsupportedMessage(_) => "unsupported message",
            ProtocolError::InvalidStateTransition(_) => "invalid state transition",
            ProtocolError::Malformed(_) => "malformed payload",
            ProtocolError::InvalidPath => "not found",
            ProtocolError::InvalidIdentity(_) => "invalid identity",
            ProtocolError::PermissionDenied => "not found",
            ProtocolError::InvalidManifest(_) => "invalid manifest",
            ProtocolError::ResourceLimitExceeded(_) => "resource limit exceeded",
            ProtocolError::QuotaExceeded(_) => "quota exceeded",
        };
        Self::new(s)
    }
}

impl From<&str> for ErrorDetail {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for ErrorDetail {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryability_table() {
        assert!(!ErrorCode::AuthFailed.retryable());
        assert!(!ErrorCode::PermissionDenied.retryable());
        assert!(ErrorCode::ChecksumMismatch.retryable());
        assert!(ErrorCode::ServerBusy.retryable());
        assert!(!ErrorCode::TransferCancelled.retryable());
        assert!(!ErrorCode::QuotaExceeded.retryable());
    }

    #[test]
    fn roundtrip_codes() {
        for (code, _name) in ERROR_CODE_NAMES {
            let c = ErrorCode::from_wire(*code);
            assert_eq!(c.to_wire(), *code, "code {code} did not round-trip");
        }
    }

    #[test]
    fn unknown_code_falls_back() {
        assert_eq!(ErrorCode::from_wire(99999), ErrorCode::InternalError);
    }

    #[test]
    fn detail_is_truncated() {
        let s = "x".repeat(MAX_ERROR_DETAIL + 1000);
        let d = ErrorDetail::new(s);
        assert!(d.as_str().len() <= MAX_ERROR_DETAIL);
    }

    #[test]
    fn not_found_and_denied_share_detail() {
        assert_eq!(ErrorDetail::not_found_or_denied().0, "not found");
    }
}
