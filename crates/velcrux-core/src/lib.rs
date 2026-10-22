//! velcrux-core
//!
//! Core types and behaviour for the Raven bulk transfer protocol implemented by Velcrux.
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
pub mod crypto;
pub mod error;
pub mod manifest;
pub mod protocol;
pub mod scheduler;
pub mod session;
pub mod state;
pub mod storage;
pub mod sync;
pub mod telemetry;
pub mod transfer;
pub mod transport;
pub mod util;

pub use auth::{
    compute_signed_payload, create_pubkey_auth_token, generate_target_attestation,
    verify_pubkey_auth_token, verify_target_attestation, AttestationEnvelope, AttestationError,
    AttestationKey, AttestationPayload, AttestationReport, AttestationStatus, AttestationVerifier,
    Authenticator, AuthorizedKeys, Authorizer, CrlStore, FileAuthorizer, Grant,
    HybridAuthenticator, MtlsAuthenticator, Op, PermSet, PubkeyAuthenticator, VerifiedAttestation,
    ATTESTATION_DOMAIN_SEPARATOR, ATTESTATION_VERSION_1, DEFAULT_SIG_EXT,
};
pub use chunking::{
    create_chunker, is_all_zeros, CdcChunker, ChunkBoundary, ChunkEngine, ChunkMode, ChunkParams,
    Chunker, FastCdcChunker, FixedChunker, PipelinedChunk, PipelinedChunker, ReuseStats,
    RollingChunker, CHUNK_DEFAULT_MAX, CHUNK_DEFAULT_MIN, CHUNK_DEFAULT_TARGET,
};
pub use crypto::{
    build_chunk_aad, derive_key_from_passphrase, derive_transfer_key, ChunkDecryptor,
    ChunkEncryptor, CipherSuite, CryptoError, TransferKey, ENVELOPE_OVERHEAD, NONCE_LEN, TAG_LEN,
};

pub use error::{Result, VelcruxError};
pub use manifest::{
    ChunkDesc, ChunkFlags, FileEntry, FileFlags, FileType, ManifestBatchDecoder, ManifestReader,
    ManifestStore, ManifestWriter,
};
pub use protocol::{
    compress_with_dict, compute_shannon_entropy, decompress_with_dict_bounded, estimate_entropy,
    evaluate_dictionary_ratio, AdaptiveCompressionConfig, AdaptiveCompressionSelector,
    AdaptiveCompressionStats, CompressionDecision, CompressionRatioEvaluation, DictionaryCatalog,
    DictionaryMetadata, DictionaryTrainer, EntropyTier, ZstdDictionary,
};
pub use session::{LimitsProvider, ServerConn, ServerState, ServerStats};
pub use state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, IdempotencyAction, IdempotencyLedger,
    JournalRecovery, LedgerEntry, MockStateStore, Role, SqliteStateStore, StateStore,
    StateStoreError, StateStoreResult, TransferRecord, TransferStatus, UpsertOutcome,
    WalCheckpointMode, WalCheckpointReport, MAX_WIRE_CHUNKS,
};

pub use scheduler::{
    civil_time_from_timestamp, ActiveScheduleStatus, BandwidthRate, BandwidthSchedule,
    BandwidthScheduleRule, DayMatcher, DayOfWeek, FairnessScheduler,
    HierarchicalBandwidthAllocator, ParseBandwidthError, ParseScheduleError, PriorityClass,
    ScheduledBandwidthLimiter, ScheduledItem, TimeWindow,
};
pub use storage::{
    gc_chunk_store, gc_chunk_store_with_snapshots, gc_staging, AceFlags, AcePermissions,
    AcePrincipal, AceType, AclPolicy, AlignedSectorBuffer, AzureBlobConfig, AzureBlobMeta,
    AzureBlobStorageBackend, AzureBlobSyncReport, AzureError, AzureSharedKeySigner,
    BackgroundScrubDaemon, CanonicalAce, CanonicalAcl, ChunkAclEntry, ChunkIntegrityStatus,
    ChunkPoisonReport, ChunkQuarantineManager, ChunkStore, ChunkStoreGcReport, ClusterNode,
    ClusterNodeState, ClusterReport, ClusteredChunkStore, ConsistentHashRing, DataScrubber,
    DedupAuditReport, DedupNamespacePolicy, DirectFileReader, DirectFileWriter,
    DirectIoBenchmarkReport, DirectIoConfig, DirectIoMode, DirectIoPipelineReader,
    DirectIoPipelineStats, DirectIoPipelineWriter, DirectIoRingBuffer, DirectIoRingConfig,
    FileMeta, GcsConfig, GcsError, GcsObjectMeta, GcsStorageBackend, GcsSyncReport,
    LocalChunkStore, LocalFilesystemBackend, MemoryFile, MemoryStorageBackend, MountConfig,
    MountManager, MountSessionInfo, NamespacedChunkStore, PlatformOs, ProofOfOwnershipEngine,
    QuarantinedChunk, QuorumPolicy, ReplicationReport, S3Config, S3Error, S3ObjectMeta,
    S3StorageBackend, S3SyncReport, ScrubFinding, ScrubMode, ScrubOptions, ScrubReport,
    SigV4Signer, SnapshotDiff, Staging, StagingGcReport, StorageBackend, VPath, VPathError,
    VfsAttr, VfsCacheStats, VfsDirEntry, VfsError, VfsFileType, VfsStatFs, VirtualMountEngine,
    XattrPolicy, XattrTransmuter, SNAPSHOT_CHUNK_SIZE, VFS_ROOT_INODE,
};
pub use sync::{
    compute_file_hash, execute_atomic_directory_sync, execute_dedup_sync, execute_delta_sync,
    execute_directory_sync, matches_glob, plan_directory_diff, plan_directory_diff_with_options,
    plan_directory_sync, recv_directory_manifest, resume_interrupted_commit, scan_dir_entries,
    send_directory_manifest, xattrs_are_compatible, AdaptiveCostEstimator, BatchContainerReader,
    BatchContainerWriter, BatchEntryMeta, BatchedSyncPlan, BloomFilter, ChangeBatch, ChangeKind,
    ChunkExtent, ClockOrdering, ConflictAction, ConflictPolicy, ConflictResolutionResult,
    ContentDeltaEngine, ContinuousSyncCoordinator, CostBreakdown, CostDecision, CostEstimator,
    DebounceQueue, DeleteGuardrails, DeleteMode, DeleteSafetyError, DeltaCompressionKind,
    DeltaCompressionReport, DeltaDictPolicy, DeltaProgress, DeltaReconstructor, DeltaSlice,
    DeltaSliceHeader, DeltaSyncReport, DeviceProfile, DirectoryDiffSummary, DirectoryPlan,
    DirectoryScanner, DirectorySyncOptions, DirectorySyncResult, DirectoryTransaction,
    DistributedLockManager, FileAction, FileActionType, FileChangeEvent, GeoItemMetadata,
    GeoRegionDescriptor, GeoRegionState, GeoReplicationCoordinator, GeoReplicationQueue,
    GeoStatusReport, LeaseLock, LocalInventory, LockError, LockMode, LockReport, NetworkProfile,
    PathFilter, ReplicationChange, RleBitmap, RleRun, ScannedEntry, SmallFileBatch,
    SmallFileBatchConfig, SmallFileBatchPlanner, SyncDecision, SyncError, SyncPlan,
    TransactionAction, TransactionError, TransactionItem, TransactionJournal, TransactionManager,
    TransactionReport, TransactionState, TransactionSummary, TransferMode, TransferPlan,
    UnpackedBatchReport, VectorClock, WatchConfig, WatchMetrics, WatchSummary,
    DEFAULT_BATCH_MAX_BYTES, DEFAULT_BATCH_MAX_FILES, DEFAULT_SMALL_FILE_THRESHOLD, VBATCH_MAGIC,
};
pub use telemetry::{
    sample_current_process_rss, BottleneckDiagnosis, BottleneckKind, ComponentKind,
    ComponentTiming, DeadLetterEntry, DeliveryStatus, MemoryStats, MockWebhookSink, NetworkMetrics,
    ProfileReport, TimingGuard, TransferProfiler, WebhookDeadLetterQueue, WebhookDeliverySink,
    WebhookEventBus, WebhookEventType, WebhookMetrics, WebhookPayload, WebhookSigner,
    WebhookSubscription,
};
pub use transfer::{
    client_download, client_download_stdout_stream, client_download_stream,
    client_download_stream_with_staging, client_download_with_progress, client_upload,
    client_upload_stdin_stream, client_upload_stream, client_upload_with_state, parse_rate_limit,
    server_download_session, server_download_session_with_delta,
    server_download_session_with_limits, server_staging_path, server_upload_session,
    server_upload_session_with_delta, server_upload_session_with_limits,
    server_upload_session_with_state, CheckpointCoordinator, CheckpointDaemonConfig,
    CheckpointPolicy, CheckpointStats, ConcurrentTransferLimiter, PipelineConfig,
    PriorityScheduler, RateLimiter, RecoveredTransferSummary, ResumeRecoveryReport, ScheduledTask,
    TransferDir, TransferKind, TransferPermit, TransferPriority, TransferRequest,
    TransferResumeCoordinator,
};

pub use transport::{
    simulate_fec_recovery, AdaptiveFecController, AdaptiveFlowController, BaselineComparator,
    BdpAutoTuner, BdpEstimator, BdpTier, BdpTuningDirection, BdpTuningPolicy, BdpTuningReport,
    BdpWindowConfig, BenchmarkMetrics, BenchmarkScenario, Connection, FecBlockDecoder,
    FecBlockEncoder, FecBlockHeader, FecCodec, FecProfile, FecRecoveryReport, FecSimulationReport,
    FecStats, FecStatsSnapshot, FecSymbol, ImpairedChannel, ImpairmentProfile, ImpairmentStats,
    MigrationCoordinator, MigrationDecision, MigrationEvent, MigrationPolicy, MigrationPolicyMode,
    MigrationStats, MultipathConfig, MultipathCoordinator, MultipathSchedulerPolicy,
    MultipathSessionReport, NatBindingStatus, NatDiagnosticsReport, NatTraversalCoordinator,
    PacingController, PathState, PmtuConfig, PmtuCoordinator, PmtuState, PmtuStats,
    SharedTransport, SubflowPathDescriptor, SubflowQualityMetrics, TokenBucket,
    TransportConfigTunables, WanMatrixReport, WanMatrixRunner, ABSOLUTE_MAX_BDP_WINDOW,
    ABSOLUTE_MIN_BDP_WINDOW, BASE_PLPMTU, DEFAULT_INITIAL_BDP_WINDOW, DEFAULT_MAX_BDP_WINDOW,
    DEFAULT_MIN_BDP_WINDOW, DEFAULT_PMTU_CANDIDATES, IPV6_MIN_MTU, JUMBO_FRAME_MTU,
    STANDARD_ETHERNET_MTU,
};
pub use util::{
    Hash, HashAlgorithm, HashHasher, ParallelHasher, SimdFeatures, SimdTier, TransferId,
    VectorizedScanner,
};
