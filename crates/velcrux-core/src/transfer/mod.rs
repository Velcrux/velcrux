//! Transfer engine.
//!
//! `ARCHITECTURE.md` §1 + `PROTOCOL.md` §7: per-connection state machine on
//! top of the session layer. M2 surface: single-file upload + download with
//! streaming I/O, atomic commit, whole-file BLAKE3 verification, bounded
//! memory. Resume, dedup, manifests, and directory sync are milestones M3+
//! / M5+ / M8+ / M9+.
//!
//! Invariants (CLAUDE.md §1):
//!   - Bounded memory: peak RSS is a function of pipeline depth, not of file
//!     size. No allocation proportional to file or dataset size.
//!   - All sizes/offsets/counters are u64.
//!   - Hash verification on receipt (chunk) and before commit (whole file).
//!     Byte count is never a success signal.
//!   - Storage is staged, then atomically renamed into place.

pub mod engine;
pub mod engine_m3;

pub use engine::{
    client_download, client_download_stream, client_download_with_progress, client_upload,
    client_upload_stream, client_upload_with_state, server_download_session, server_staging_path,
    server_upload_session, server_upload_session_with_state, PipelineConfig,
};
pub use engine_m3::{
    build_resume_state, cancel_transfer as cancel_transfer_m3, client_upload as client_upload_m3,
    server_upload_session as server_upload_session_m3, M3_CHUNK_SIZE,
};

use crate::error::VelcruxError;
use crate::util::TransferId;

/// Which side of a transfer this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDir {
    /// Client → server: an upload.
    Upload,
    /// Server → client: a download.
    Download,
}

/// What kind of operation is being performed. M2 only ships the single-file
/// variants; sync/upload+download is M5/M9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    /// Single-file upload.
    UploadFile,
    /// Single-file download.
    DownloadFile,
}

/// A client request to start a transfer. The server maps this to a
/// `TRANSFER_CREATED` reply with the assigned transfer id.
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Kind of transfer (`PROTOCOL.md` §4 op field).
    pub kind: TransferKind,
    /// Destination path on the server (for uploads) or source path on the
    /// server (for downloads). Already validated as a `VPath` by the caller.
    pub remote_path: String,
    /// Client-side idempotency key. A retry with the same key on the same
    /// server returns the existing transfer.
    pub idempotency_key: String,
    /// Bandwidth cap in bytes/sec. `0` means no client-side cap.
    pub bandwidth_bps: u64,
}

impl TransferRequest {
    /// Build an upload request for the given remote path.
    pub fn upload(remote_path: impl Into<String>) -> Self {
        Self {
            kind: TransferKind::UploadFile,
            remote_path: remote_path.into(),
            idempotency_key: TransferId::generate().to_string(),
            bandwidth_bps: 0,
        }
    }

    /// Build a download request for the given remote path.
    pub fn download(remote_path: impl Into<String>) -> Self {
        Self {
            kind: TransferKind::DownloadFile,
            remote_path: remote_path.into(),
            idempotency_key: TransferId::generate().to_string(),
            bandwidth_bps: 0,
        }
    }
}

/// Internal helper: convert a `VelcruxError` to a `PROTOCOL_VIOLATION`
/// connection close. Used by the session state machines when a transfer
/// pipeline hits an unrecoverable protocol error.
pub fn protocol_violation(detail: &'static str) -> VelcruxError {
    use crate::error::ProtocolError;
    VelcruxError::Protocol(ProtocolError::InvalidStateTransition(detail))
}
