//! Persistent transfer state (`ADR-005`).
//!
//! This module is the seam between the transfer engine and the on-disk
//! state DB. The `StateStore` trait is the abstraction; `SqliteStateStore`
//! is the production implementation (one DB per role, absolute path, WAL
//! mode). A small `MockStateStore` exists for deterministic in-memory
//! tests, but no other backends are planned — `ADR-005` calls out that
//! we are explicitly not building a "backends" abstraction.
//!
//! ## Invariants
//!
//! - All sizes/offsets/counters are `u64`.
//! - `idempotency_key` is UNIQUE per (role, key) and is the durable
//!   handle to a transfer.
//! - The chunk bitmap is bounded-memory; the trait takes a
//!   `ChunkBitmap`, not a `Vec<bool>` proportional to the file.
//! - `commit_journal.status` advances `pending -> renamed -> committed`;
//!   `renamed` is the durable midpoint that lets recovery decide
//!   between "complete the commit" and "roll back" without exposing a
//!   half-renamed destination.

pub mod bitmap;
pub mod mock;
pub mod sqlite;

pub use bitmap::{ChunkBitmap, MAX_WIRE_CHUNKS};
pub use mock::MockStateStore;
pub use sqlite::SqliteStateStore;

use std::path::PathBuf;

use crate::util::{Hash, TransferId};

/// What side this `StateStore` is recording state for. Idempotency
/// keys are scoped to a role so the same key used by a client and a
/// server does not collide (they have separate DBs in any case, but
/// the role disambiguates diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The `velcrux` client.
    Client,
    /// The `velcruxd` server.
    Server,
}

/// Lifecycle of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferStatus {
    /// Bytes are still being moved.
    Active,
    /// User-initiated cancel; staging + state rows will be released.
    Cancelled,
    /// Transfer finished and the destination was atomically renamed in.
    Committed,
    /// Process exited cleanly or was killed; staging is preserved on
    /// disk and a subsequent resume reuses it.
    Resumable,
}

impl TransferStatus {
    /// Wire-stable string form used in CLI output and logs.
    pub const fn name(self) -> &'static str {
        match self {
            TransferStatus::Active => "active",
            TransferStatus::Cancelled => "cancelled",
            TransferStatus::Committed => "committed",
            TransferStatus::Resumable => "resumable",
        }
    }
}

/// Direction of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Client → server.
    Upload,
    /// Server → client.
    Download,
}

impl Direction {
    /// Wire-stable string form.
    pub const fn name(self) -> &'static str {
        match self {
            Direction::Upload => "upload",
            Direction::Download => "download",
        }
    }
}

/// A row in the `transfers` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRecord {
    /// Stable across resumes; assigned on first TRANSFER_CREATE.
    pub transfer_id: TransferId,
    /// Idempotency key. UNIQUE within `role`. A retry with the same
    /// key returns the same `transfer_id`.
    pub idempotency_key: String,
    /// Which side recorded this row.
    pub role: Role,
    /// Direction (only meaningful for the role that is *sending* data).
    pub direction: Direction,
    /// Status of this transfer.
    pub status: TransferStatus,
    /// The server-side destination path (for uploads) or the source
    /// path (for downloads). May be empty for the client row when the
    /// server is the source.
    pub remote_path: String,
    /// For an upload, the local file path the sender is reading.
    /// Empty for download. Absolute path. Not a `VPath` because it is
    /// on the *caller's* filesystem, not the storage root.
    pub local_path: String,
    /// Declared file size in bytes. `0` for the unknown-at-create side
    /// of a download.
    pub file_size: u64,
    /// Expected whole-file BLAKE3 hash. `Hash::ZERO` if unknown.
    pub file_hash: Hash,
    /// Highest contiguous offset verified on the receive side. `0`
    /// until VERIFY.
    pub verified_up_to: u64,
    /// Last checkpoint timestamp in ms since UNIX epoch. `0` if no
    /// checkpoint has been written.
    pub last_checkpoint_ms: u64,
    /// Total bytes persisted as complete in the chunk bitmap.
    pub bytes_completed: u64,
    /// Path to the staging file, relative to the staging root. Empty
    /// when there is no on-disk staging.
    pub staging_relpath: String,
    /// Wall-clock creation time in ms since UNIX epoch.
    pub created_ms: u64,
    /// Wall-clock last-update time in ms since UNIX epoch.
    pub updated_ms: u64,
}

/// A row in the `commit_journal` table. The status is the durable
/// midpoint of the commit protocol; recovery on startup replays from
/// here to either complete or roll back without ever exposing a
/// half-renamed destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitStatus {
    /// Staging is open; the commit protocol has not yet started.
    Pending,
    /// The atomic `rename` from staging to destination has completed;
    /// only the journal entry is still pending. Crash-safe: recovery
    /// finalises this to `Committed`.
    Renamed,
    /// Both rename and journal write have completed.
    Committed,
}

impl CommitStatus {
    /// Wire-stable string form.
    pub const fn name(self) -> &'static str {
        match self {
            CommitStatus::Pending => "pending",
            CommitStatus::Renamed => "renamed",
            CommitStatus::Committed => "committed",
        }
    }

    /// Parse from a stored string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "renamed" => Some(Self::Renamed),
            "committed" => Some(Self::Committed),
            _ => None,
        }
    }
}

/// A row in the `commit_journal` table.
#[derive(Debug, Clone)]
pub struct CommitJournalEntry {
    pub transfer_id: TransferId,
    /// Single-file M3 only. M9 will introduce a list.
    pub file_id: u64,
    /// Destination path inside the storage root.
    pub remote_path: String,
    pub status: CommitStatus,
    pub updated_ms: u64,
}

/// Errors produced by `StateStore` operations. Distinct from
/// `VelcruxError` so the trait does not pull in the protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum StateStoreError {
    /// The transfer id is not present in the DB.
    #[error("transfer not found")]
    NotFound,
    /// A row already exists with a different `idempotency_key`
    /// argument set; the conflict is not retryable as-is.
    #[error("idempotency key conflict: {0}")]
    IdempotencyConflict(String),
    /// The underlying DB driver returned an error.
    #[error("database error: {0}")]
    Database(String),
    /// The data on disk is internally inconsistent.
    #[error("corrupt state: {0}")]
    Corrupt(String),
}

/// Crate-wide alias for the `?` operator in `StateStore` implementors.
pub type StateStoreResult<T> = std::result::Result<T, StateStoreError>;

/// Recovery action returned by [`StateStore::recover_commit_journal`].
/// One per non-`committed` journal entry observed at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecovery {
    /// `Renamed` entry: the atomic rename already completed, so
    /// finalize the journal to `Committed` (the destination is already
    /// visible, the journal is just behind).
    Finalize {
        transfer_id: TransferId,
        file_id: u64,
    },
    /// `Pending` entry: the rename did not complete. Leave the row
    /// alone and let the next resume retry from the existing staging.
    LeavePending {
        transfer_id: TransferId,
        file_id: u64,
    },
}

/// Outcome of `upsert_transfer`. Distinguishes the first-time insert
/// from the idempotent retry path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// A brand-new row was inserted; the caller receives the same
    /// record it submitted.
    Inserted,
    /// A row with the same `idempotency_key` already existed; the
    /// existing record is returned and the requested row is discarded.
    /// The implementation has verified that the parameters are
    /// compatible.
    Reused(TransferRecord),
}

/// The persistence seam for transfer state. SQLite is the only
/// production implementation; `MockStateStore` exists for unit tests.
pub trait StateStore: Send + Sync {
    /// Insert a new transfer row. If `idempotency_key` already exists
    /// for this `role`, returns the existing record. The implementation
    /// must verify that a retry with the same key but different
    /// parameters is rejected (and not silently returned as if it were
    /// the same).
    fn upsert_transfer(&self, record: &TransferRecord) -> StateStoreResult<UpsertOutcome>;

    /// Update an existing transfer row. Returns `NotFound` if the id
    /// is not present.
    fn update_transfer(&self, record: &TransferRecord) -> StateStoreResult<()>;

    /// Fetch a transfer by id.
    fn get_transfer(&self, transfer_id: TransferId) -> StateStoreResult<TransferRecord>;

    /// Fetch a transfer by its idempotency key (scoped to the role
    /// that stored it).
    fn get_transfer_by_idempotency(
        &self,
        role: Role,
        idempotency_key: &str,
    ) -> StateStoreResult<TransferRecord>;

    /// List transfers whose `remote_path` begins with `path_prefix`.
    /// Sorted by `created_ms` ascending.
    fn list_transfers_by_path(
        &self,
        role: Role,
        path_prefix: &str,
    ) -> StateStoreResult<Vec<TransferRecord>>;

    /// Replace the chunk-completion bitmap for a transfer. Idempotent.
    fn write_bitmap(&self, transfer_id: TransferId, bitmap: &ChunkBitmap) -> StateStoreResult<()>;

    /// Read the chunk-completion bitmap for a transfer.
    fn read_bitmap(&self, transfer_id: TransferId) -> StateStoreResult<ChunkBitmap>;

    /// Delete the bitmap rows for a transfer. Called from the cancel
    /// path.
    fn delete_bitmap(&self, transfer_id: TransferId) -> StateStoreResult<()>;

    /// Write or update a `commit_journal` row.
    fn write_journal(&self, entry: &CommitJournalEntry) -> StateStoreResult<()>;

    /// Read all non-`committed` journal rows so the server can
    /// replay them at startup.
    fn pending_journal(&self) -> StateStoreResult<Vec<CommitJournalEntry>>;

    /// Mark a journal row as `Committed` (the atomic rename + fsync
    /// have both succeeded).
    fn mark_journal_committed(&self, transfer_id: TransferId, file_id: u64)
        -> StateStoreResult<()>;

    /// Delete all rows (transfer, bitmap, journal) for a transfer.
    /// Used by the cancel path.
    fn delete_transfer(&self, transfer_id: TransferId) -> StateStoreResult<()>;

    /// Iterate every non-committed journal row and return the
    /// recovery action the caller should take. Pure read: the rows
    /// are not modified; the caller calls `mark_journal_committed`
    /// after acting.
    fn recover_commit_journal(&self) -> StateStoreResult<Vec<JournalRecovery>>;
}

/// Convenience: a request from the engine to commit a transfer. The
/// `commit_journal` row is the midpoint marker.
#[derive(Debug, Clone)]
pub struct CommitRequest {
    pub transfer_id: TransferId,
    pub file_id: u64,
    pub remote_path: String,
    /// Absolute path to the staging file (server-side).
    pub staging_path: PathBuf,
    /// Destination path the file will be renamed to (server-side).
    pub final_path: PathBuf,
}

// Re-export `Result` so callers can `use state::Result;`.
pub use crate::error::Result;
