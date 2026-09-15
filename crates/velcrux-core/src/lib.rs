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
#![warn(missing_docs)]

pub mod auth;
pub mod chunking;
pub mod error;
pub mod manifest;
pub mod protocol;
pub mod session;
pub mod state;
pub mod storage;
pub mod transfer;
pub mod transport;
pub mod util;

pub use chunking::{
    create_chunker, CdcChunker, ChunkBoundary, ChunkEngine, ChunkMode, ChunkParams, Chunker,
    FixedChunker, ReuseStats, RollingChunker, CHUNK_DEFAULT_MAX, CHUNK_DEFAULT_MIN,
    CHUNK_DEFAULT_TARGET,
};
pub use error::{Result, VelcruxError};
pub use auth::{Authenticator, Authorizer, FileAuthorizer, Grant, MtlsAuthenticator, Op, PermSet};
pub use manifest::{
    ChunkDesc, ChunkFlags, FileEntry, FileFlags, FileType, ManifestBatchDecoder, ManifestReader,
    ManifestStore, ManifestWriter,
};
pub use state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, JournalRecovery, MockStateStore,
    Role, SqliteStateStore, StateStore, StateStoreError, StateStoreResult, TransferRecord,
    TransferStatus, UpsertOutcome, MAX_WIRE_CHUNKS,
};
pub use storage::{FileMeta, LocalFilesystemBackend, Staging, StorageBackend, VPath, VPathError};
pub use transfer::{
    client_download, client_upload, server_download_session, server_staging_path,
    server_upload_session, PipelineConfig, TransferDir, TransferKind, TransferRequest,
};
pub use transport::{Connection, SharedTransport};
pub use util::{Hash, HashAlgorithm, HashHasher};
