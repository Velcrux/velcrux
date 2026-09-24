//! velcrux-core
//!
//! Core types and behaviour for the `velcrux` bulk transfer protocol.
//!
//! Layering follows `docs/ARCHITECTURE.md` §1:
//!
//!   protocol  →  transport  →  session  →  (client/server in velcrux-{client,server})
//!
//! Each layer depends only on the one below it. There is no I/O in `protocol`:
//! every decoder is a pure function over `&[u8]` so it can be fuzzed in isolation
//! (DEVELOPMENT.md §6).
//!
//! Invariants from `CLAUDE.md` §1 enforced in this crate:
//!   - No `unsafe` (forbidden via lints).
//!   - No unbounded channels (lints + code review; CI to come).
//!   - All wire sizes/offsets/counters are `u64`; no `u32`/`usize` on the wire
//!     or in persisted structs.
//!   - Every decoder checks length against a named constant *before* allocation.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#[allow(missing_docs)]
pub mod auth;
pub mod chunking;
pub mod error;
pub mod manifest;
pub mod protocol;
pub mod session;
pub mod state;
pub mod storage;
pub mod sync;
pub mod transfer;
pub mod transport;
pub mod util;

pub use auth::{Authenticator, Authorizer, FileAuthorizer, Grant, MtlsAuthenticator, Op, PermSet};
pub use chunking::{
    create_chunker, CdcChunker, ChunkBoundary, ChunkEngine, ChunkMode, ChunkParams, Chunker,
    FixedChunker, ReuseStats, RollingChunker, CHUNK_DEFAULT_MAX, CHUNK_DEFAULT_MIN,
    CHUNK_DEFAULT_TARGET,
};
pub use error::{Result, VelcruxError};
pub use manifest::{
    ChunkDesc, ChunkFlags, FileEntry, FileFlags, FileType, ManifestBatchDecoder, ManifestReader,
    ManifestStore, ManifestWriter,
};
pub use state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, JournalRecovery, MockStateStore,
    Role, SqliteStateStore, StateStore, StateStoreError, StateStoreResult, TransferRecord,
    TransferStatus, UpsertOutcome, MAX_WIRE_CHUNKS,
};
pub use storage::{
    ChunkStore, FileMeta, LocalChunkStore, LocalFilesystemBackend, Staging, StorageBackend, VPath,
    VPathError,
};
pub use sync::{
    compute_file_hash, execute_dedup_sync, execute_delta_sync, execute_directory_sync,
    plan_directory_diff, plan_directory_sync, recv_directory_manifest, resume_interrupted_commit,
    scan_dir_entries, send_directory_manifest, BloomFilter, ChunkExtent, CostEstimator, DeleteMode,
    DeltaProgress, DeltaReconstructor, DeltaSyncReport, DirectoryDiffSummary, DirectoryPlan,
    DirectorySyncOptions, DirectorySyncResult, FileAction, FileActionType, LocalInventory,
    RleBitmap, RleRun, ScannedEntry, SyncDecision, SyncError, SyncPlan,
};
pub use transfer::{
    client_download, client_download_stream, client_download_stream_with_staging,
    client_download_with_progress, client_upload, client_upload_stream, client_upload_with_state,
    server_download_session, server_download_session_with_delta, server_staging_path,
    server_upload_session, server_upload_session_with_delta, server_upload_session_with_state,
    PipelineConfig, TransferDir, TransferKind, TransferRequest,
};
pub use transport::{Connection, SharedTransport};
pub use util::{Hash, HashAlgorithm, HashHasher};
