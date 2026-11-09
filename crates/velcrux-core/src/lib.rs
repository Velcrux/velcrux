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
pub mod audit;
pub mod auth;
pub mod bdp_rebalance;
pub mod bgp;
pub mod chaos;
pub mod chunking;
pub mod consensus;
pub mod crdt;
pub mod crypto;
pub mod did;
pub mod ec;
pub mod error;
pub mod k8s;
pub mod kms;
pub mod manifest;
pub mod mpc;
pub mod netem;
pub mod nvme;
pub mod protocol;
pub mod provenance;
pub mod proxy;
pub mod qkd;
pub mod rdma;
pub mod router;
pub mod scheduler;
pub mod session;
pub mod state;
pub mod storage;
pub mod swarm;
pub mod sync;
pub mod tee;
pub mod telemetry;
pub mod traffic;
pub mod transfer;
pub mod transport;
pub mod txsnapshot;
pub mod util;
pub mod vault;
pub mod wan;
pub mod xdp;
pub mod zkquota;

pub use audit::{
    combine_hashes, hex_decode_32, hex_encode, run_audit_benchmark, verify_exclusion_proof,
    verify_inclusion_proof, AuditBenchmarkReport, AuditExclusionProof, AuditInclusionProof,
    AuditProofDirection, AuditProofStep, AuditRecord, AuditTreeStatus, BlindedAuditLeaf,
    MerkleAuditTree, AUDIT_LEAF_DOMAIN_TAG, AUDIT_NODE_DOMAIN_TAG,
};
pub use auth::{
    compute_signed_payload, create_pubkey_auth_token, generate_target_attestation,
    verify_pubkey_auth_token, verify_target_attestation, AttestationEnvelope, AttestationError,
    AttestationKey, AttestationPayload, AttestationReport, AttestationStatus, AttestationVerifier,
    Authenticator, AuthorizedKeys, Authorizer, CrlStore, FileAuthorizer, Grant,
    HybridAuthenticator, MtlsAuthenticator, Op, PermSet, PubkeyAuthenticator, VerifiedAttestation,
    ATTESTATION_DOMAIN_SEPARATOR, ATTESTATION_VERSION_1, DEFAULT_SIG_EXT,
};
pub use bdp_rebalance::{
    compute_bdp_bytes, BdpRebalanceBenchmarkReport, BdpRebalanceConfig, BdpRebalanceEngine,
    BdpRebalanceStatusReport, RebalanceDecision, SubflowAllocation, SubflowCongestionState,
    SubflowFeedback, SubflowRebalanceState, SubflowType, DEFAULT_ANTI_FLAPPING_HYSTERESIS_MS,
    DEFAULT_LOSS_DEFLECT_PPM, DEFAULT_LOSS_PENALTY_GAMMA, DEFAULT_LOSS_THROTTLE_PPM,
    DEFAULT_REBALANCE_INTERVAL_MS, MAX_SUBFLOW_BDP_CEILING_BYTES, MIN_SUBFLOW_BDP_FLOOR_BYTES,
};
pub use bgp::{
    AnycastAction, AnycastOrchestrator, AnycastVip, AsPathSegment, AsPathSegmentType, BgpEvent,
    BgpFsmState, BgpMessage, BgpOrigin, BgpPathAttributes, BgpPeer, BgpPrefix, BgpRibEntry,
    BgpRibManager, EthernetSegmentId, EvpnRoute, FdbEntry, MacAddress, PopHealthStatus,
    RouteDistinguisher, RouteTarget, VrfTable, VtepEngine, VxlanDatagram, VxlanHeader, AFI_L2VPN,
    ATTR_AGGREGATOR, ATTR_AS_PATH, ATTR_COMMUNITIES, ATTR_EXTENDED_COMMUNITIES, ATTR_LOCAL_PREF,
    ATTR_MP_REACH_NLRI, ATTR_MP_UNREACH_NLRI, ATTR_MULTI_EXIT_DISC, ATTR_NEXT_HOP, ATTR_ORIGIN,
    BGP_HEADER_LEN, BGP_HEADER_MARKER, BGP_MSG_KEEPALIVE, BGP_MSG_NOTIFICATION, BGP_MSG_OPEN,
    BGP_MSG_ROUTE_REFRESH, BGP_MSG_UPDATE, BGP_TCP_PORT, COMMUNITY_BLACKHOLE,
    COMMUNITY_NO_ADVERTISE, COMMUNITY_NO_EXPORT, EVPN_TYPE_ETHERNET_AD, EVPN_TYPE_ETHERNET_SEGMENT,
    EVPN_TYPE_INCLUSIVE_MULTICAST, EVPN_TYPE_IP_PREFIX, EVPN_TYPE_MAC_IP_ADV, ORIGIN_EGP,
    ORIGIN_IGP, ORIGIN_INCOMPLETE, SAFI_EVPN, VXLAN_FLAGS_VALID_VNI, VXLAN_UDP_PORT,
};
pub use chaos::{
    run_chaos_benchmark, ChaosBenchmarkReport, ChaosConfig, ChaosEngine, ChaosOutcome, ChaosPrng,
    ChaosProfileKind, ChaosStats, ChaosStatusReport, GilbertElliottConfig, GilbertElliottModel,
    MarkovState,
};
pub use chunking::{
    create_chunker, is_all_zeros, CdcChunker, ChunkBoundary, ChunkEngine, ChunkMode, ChunkParams,
    Chunker, FastCdcChunker, FixedChunker, PipelinedChunk, PipelinedChunker, ReuseStats,
    RollingChunker, CHUNK_DEFAULT_MAX, CHUNK_DEFAULT_MIN, CHUNK_DEFAULT_TARGET,
};
pub use consensus::{
    run_raft_benchmark, AppendEntriesRequest, AppendEntriesResponse, ClusterLease,
    ClusterMetadataStateMachine, RaftBenchmarkReport, RaftClusterStatus, RaftCommand,
    RaftCoordinator, RaftLogEntry, RaftRole, RaftStats, RequestVoteRequest, RequestVoteResponse,
};
pub use crdt::{
    AntiEntropyEngine, AntiEntropyReport, CausalOrder, CrdtDelta, DigestSummary, FsMergeReport,
    FsNode, FsNodeKind, GeoBenchmarkReport, GeoMesh, Hlc, LwwRegister, MvRegister, OrSet,
    RegionInfo, ReplicatedFsTree, VectorClock as CrdtVectorClock,
};
pub use crypto::{
    build_chunk_aad, derive_key_from_passphrase, derive_transfer_key, ChunkDecryptor,
    ChunkEncryptor, CipherSuite, CryptoError, TransferKey, ENVELOPE_OVERHEAD, NONCE_LEN, TAG_LEN,
};

pub use did::{
    base58_decode, base58_encode, did_from_ed25519_pubkey, generate_ed25519_keypair, hex_decode,
    parse_ed25519_keypair, resolve_did, CredentialProof, DidAttestationEngine, DidBenchmarkReport,
    DidDocument, DidMethod, TransferCapabilitySubject, VerifiableCredential, VerificationMethod,
    VerificationReport,
};
pub use ec::{
    EcAutoRepairReport, EcBenchmarkReport, EcObjectScrubSummary, EcRepairReport, EcScrubReport,
    ErasureEngine, ErasureSchema, ObjectHealthState, ShardEnvelope, ShardScrubMesh, SHARD_MAGIC,
    SHARD_VERSION,
};
pub use error::{Result, VelcruxError};
pub use k8s::{
    generate_cluster_crd_yaml, generate_operator_deployment_yaml, generate_operator_rbac_yaml,
    generate_transfer_crd_yaml, ClusterCondition, ClusterPhase, K8sEvent, K8sTransferPriority,
    ObjectMeta, OperatorReconciler, ReconciliationResult, RetryPolicy, TransferCondition,
    TransferPhase, VelcruxCluster, VelcruxClusterSpec, VelcruxClusterStatus, VelcruxTransfer,
    VelcruxTransferSpec, VelcruxTransferStatus, CRD_GROUP, CRD_VERSION,
};
pub use kms::{
    hex_decode as kms_hex_decode, hex_encode as kms_hex_encode, HsmKmsBridge, KeyRotationReport,
    KmsBenchmarkReport, KmsBridgeConfig, KmsKeyMetadata, KmsKeyPurpose, KmsProviderType,
    KmsSignature, KmsStatusReport, WrappedKeyEnvelope, KMS_KEY_LEN, KMS_NONCE_LEN,
};
pub use manifest::{
    ChunkDesc, ChunkFlags, FileEntry, FileFlags, FileType, ManifestBatchDecoder, ManifestReader,
    ManifestStore, ManifestWriter,
};
pub use mpc::{
    aggregate_signature_shares, compute_lagrange_coefficient, reconstruct_secret,
    verify_signature_share, CommitmentPackage as MpcCommitmentPackage, FeldmanCommitmentPackage,
    FieldElement as MpcFieldElement, MpcClusterConfig, MpcClusterCoordinator,
    MpcManifestAttestation, MpcRootToken, MpcSessionAuditRecord, NonceCommitment,
    Point as MpcPoint, Polynomial as MpcPolynomial, Scalar as MpcScalar, SchnorrDlogProof,
    SecretShare as MpcSecretShare, SignatureShare as MpcSignatureShare, SigningNonces,
    ThresholdSignature, ThresholdSigner,
};
pub use nvme::{
    AnaState, ControllerPath, DpuBenchmarkSummary, DpuDmaExecutionResult, DpuHardwareProfile,
    DpuOffloadEngine, MultipathPolicy, NvmeCompletionQueueEntry, NvmeController,
    NvmeFabricConnectData, NvmeIdentifyController, NvmeIdentifyNamespace, NvmeMultipathRouter,
    NvmeNamespace, NvmeSglDescriptor, NvmeSubmissionQueueEntry, NvmeSubsystem, CPU_CYCLES_PER_BYTE,
    CPU_CYCLES_PER_IO_OVERHEAD, NVME_FABRIC_AUTH, NVME_FABRIC_CONNECT, NVME_FABRIC_DISCONNECT,
    NVME_OP_FABRIC, NVME_OP_FLUSH, NVME_OP_IDENTIFY, NVME_OP_READ, NVME_OP_WRITE,
    NVME_STATUS_CAPACITY_EXCEEDED, NVME_STATUS_FABRIC_CONNECT_REJECTED, NVME_STATUS_INVALID_FIELD,
    NVME_STATUS_INVALID_OPCODE, NVME_STATUS_LBA_OUT_OF_RANGE, NVME_STATUS_NAMESPACE_NOT_READY,
    NVME_STATUS_SUCCESS, SGL_TYPE_DATA_BLOCK, SGL_TYPE_KEYED_DATA_BLOCK,
    SGL_TYPE_TRANSPORT_DATA_BLOCK,
};
pub use protocol::{
    compress_with_dict, compute_shannon_entropy, decompress_with_dict_bounded, estimate_entropy,
    evaluate_dictionary_ratio, AdaptiveCompressionConfig, AdaptiveCompressionSelector,
    AdaptiveCompressionStats, CompressionDecision, CompressionRatioEvaluation, DictionaryCatalog,
    DictionaryMetadata, DictionaryTrainer, EntropyTier, ZstdDictionary,
};
pub use provenance::{
    hex_decode_32 as provenance_hex_decode_32, hex_encode_32 as provenance_hex_encode_32,
    MerkleDagAuditLog, ProvenanceAction, ProvenanceBenchmarkReport, ProvenanceConfig,
    ProvenanceInclusionProof, ProvenanceNode, ProvenanceVerificationReport, TimestampToken,
    WitnessCosignature, PROVENANCE_NODE_DOMAIN_TAG, PROVENANCE_ROOT_DOMAIN_TAG,
    PROVENANCE_TIMESTAMP_DOMAIN_TAG, PROVENANCE_WITNESS_DOMAIN_TAG,
};
pub use qkd::{
    AlicePulse, Bb84Engine, Bb84SessionReport, BobMeasurement, DecoyIntensity, E91Engine,
    E91SessionReport, MeasurementAngle, QkdKey, QkdKeyInfo, QkdKeyStatus, QkdKeyStore,
    QkdProtocolType, QkdReplenisher, QuantumChannel, QuantumChannelType, QubitBasis,
    BB84_QBER_ABORT_THRESHOLD, CHSH_CLASSICAL_LIMIT, CHSH_TSIRELSON_BOUND,
    DEFAULT_DARK_COUNT_PROBABILITY, DEFAULT_DETECTOR_EFFICIENCY, INTENSITY_DECOY_NU,
    INTENSITY_SIGNAL_MU, INTENSITY_VACUUM_OMEGA, SMF28_ATTENUATION_DB_PER_KM,
    SPEED_OF_LIGHT_IN_FIBER_KM_S,
};
pub use rdma::{
    calculate_icrc, AccessFlags, Aeth, Bth, BthOpcode, CompletionQueue, DcqcnConfig, DcqcnPacer,
    DcqcnReport, DcqcnStage, HcaDeviceAttributes, Ieth, ImmDt, MemoryRegion, ProtectionDomain,
    QpInitAttr, QpState, QpType, QueuePair, RdmaBenchmarkReport, RdmaTransferEngine, RecvWr, Reth,
    RocePacket, SendFlags, SendWr, Sge, WcOpcode, WcStatus, WorkCompletion, WrOpcode,
    IB_DEFAULT_PKEY, ROCEV2_UDP_PORT,
};
pub use session::{LimitsProvider, ServerConn, ServerState, ServerStats};
pub use state::{
    ChunkBitmap, CommitJournalEntry, CommitStatus, Direction, IdempotencyAction, IdempotencyLedger,
    JournalRecovery, LedgerEntry, MockStateStore, Role, SqliteStateStore, StateStore,
    StateStoreError, StateStoreResult, TransferRecord, TransferStatus, UpsertOutcome,
    WalCheckpointMode, WalCheckpointReport, MAX_WIRE_CHUNKS,
};

pub use router::{
    haversine_distance_km, run_router_benchmark, AnycastRouter, MigrationState, MigrationTicket,
    PopHealthMetrics, PopNode, PopStatus, RouteDecision, RouteRequest, RouterBenchmarkReport,
    RouterStatus, SessionMigrationRecord, MIGRATION_TICKET_DOMAIN_TAG,
};

pub use scheduler::{
    civil_time_from_timestamp, run_qos_benchmark, ActiveScheduleStatus, BandwidthRate,
    BandwidthSchedule, BandwidthScheduleRule, DayMatcher, DayOfWeek, FairnessScheduler,
    HierarchicalBandwidthAllocator, HierarchicalQosScheduler, HtbTokenBucket, ParseBandwidthError,
    ParseScheduleError, PriorityClass, QosAdmission, QosBand, QosBenchmarkReport, QosClass,
    QosFlowMultiplexer, QosScheduledItem, QosStats, ScheduledBandwidthLimiter, ScheduledItem,
    TimeWindow,
};
pub use storage::{
    gc_chunk_store, gc_chunk_store_with_snapshots, gc_staging, AccessHeatRecord, AceFlags,
    AcePermissions, AcePrincipal, AceType, AclPolicy, AlignedSectorBuffer,
    AutonomousCompactionEngine, AzureBlobConfig, AzureBlobMeta, AzureBlobStorageBackend,
    AzureBlobSyncReport, AzureError, AzureSharedKeySigner, BackgroundScrubDaemon, CanonicalAce,
    CanonicalAcl, CasChunkEntry, CasCompactionDaemon, CasCompactionDaemonConfig, CasGcPolicy,
    CasGeneration, CasGenerationalGcReport, CasStoreStatus, CasTombstone, ChunkAccessHeatmap,
    ChunkAclEntry, ChunkIntegrityStatus, ChunkPoisonReport, ChunkQuarantineManager, ChunkStore,
    ChunkStoreGcReport, ChunkTemperature, ChunkTierMetadata, CloudProviderType, ClusterNode,
    ClusterNodeState, ClusterReport, ClusteredChunkStore, ColdScrubReport,
    CompactionBenchmarkReport, CompactionCycleReport, CompactionEngineStatus, CompactionPolicy,
    ConflictResolutionPolicy, ConsistentHashRing, DataScrubber, DedupAuditReport,
    DedupNamespacePolicy, DirectFileReader, DirectFileWriter, DirectIoBenchmarkReport,
    DirectIoConfig, DirectIoMode, DirectIoPipelineReader, DirectIoPipelineStats,
    DirectIoPipelineWriter, DirectIoRingBuffer, DirectIoRingConfig, FederatedObjectMeta,
    FederatedProviderConfig, FederatedReadCache, FederatedStorageBroker, FederationBenchmarkReport,
    FederationConfig, FederationRoutingPolicy, FederationSyncReport, FileMeta, GcsConfig, GcsError,
    GcsObjectMeta, GcsStorageBackend, GcsSyncReport, GenerationalCasManager, LifecycleSweepReport,
    LocalChunkStore, LocalFilesystemBackend, MemoryFile, MemoryStorageBackend, MigrationPlan,
    MountConfig, MountManager, MountSessionInfo, NamespacedChunkStore, PlatformOs,
    ProofOfOwnershipEngine, ProviderHealthInfo, ProviderHealthStatus, ProviderSyncStats,
    QuarantinedChunk, QuorumPolicy, ReplicationReport, S3Config, S3Error, S3ObjectMeta,
    S3StorageBackend, S3SyncReport, ScrubFinding, ScrubMode, ScrubOptions, ScrubReport,
    SigV4Signer, SnapshotDiff, Staging, StagingGcReport, StorageBackend, StorageTier,
    TenantTierPolicy, TieredStorageManager, TieredStoreStatus, VPath, VPathError, VfsAttr,
    VfsCacheStats, VfsDirEntry, VfsError, VfsFileType, VfsStatFs, VirtualMountEngine, XattrPolicy,
    XattrTransmuter, SNAPSHOT_CHUNK_SIZE, VFS_ROOT_INODE,
};
pub use swarm::{
    run_swarm_benchmark, GossipDiscoveryEngine, GossipMessage, PeerState, SwarmBenchmarkReport,
    SwarmChunkMesh, SwarmConfig, SwarmPeer, SwarmStats, SwarmStatusReport,
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

pub use crypto::pqc::{
    ml_dsa_65_keygen_from_seed, ml_dsa_65_sign, ml_dsa_65_verify, ml_kem_768_decapsulate,
    ml_kem_768_encapsulate, ml_kem_768_keygen_from_seed, run_pqc_benchmark, HybridCiphertext,
    HybridKemEngine, HybridKemKeyPair, HybridKemPrivateKey, HybridKemPublicKey, HybridSharedSecret,
    HybridSignature, HybridSignatureEngine, HybridSigningPrivateKey, HybridSigningPublicKey,
    MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature, MlKemCiphertext, MlKemPrivateKey,
    MlKemPublicKey, PqcAlgorithm, PqcBenchmarkReport, PqcStatusReport,
};
pub use netem::{
    GilbertElliottLossConfig, JitterDistribution, NetemBenchmarkReport, NetemConfig, NetemEngine,
    NetemMetricsSnapshot, NetemPrng, NetemProfilePreset, NetemSimulationReport, PacketAction,
};
pub use proxy::{
    run_l7_benchmark, FlowTier, L7Action, L7BenchmarkReport, L7ProxyEngine, L7ProxyStatus,
    L7RequestInfo, L7Rule, L7StreamType, L7TokenBucket, PressureSensor,
};
pub use traffic::{
    format_prometheus_metrics as format_traffic_prometheus_metrics, AnomalyClassification,
    AnomalyDetectionResult, AnomalyIncident, AnomalyType, CompositeAnomalyDetector, CusumDetector,
    FeatureVector, IncidentLedger, MetricSample, RollingWindowStats, SelfHealingShaper,
    ShaperAction, StreamingIsolationForest, TrafficBenchmarkReport, TrafficEngine,
    TrafficStatusReport, FEATURE_DIMENSIONS as TRAFFIC_FEATURE_DIMENSIONS,
};
pub use transport::{
    simulate_fec_recovery, AdaptiveFecController, AdaptiveFlowController,
    AdaptivePredictiveCongestionController, BanditAction, BaselineComparator, BbrPhase,
    BdpAutoTuner, BdpEstimator, BdpTier, BdpTuningDirection, BdpTuningPolicy, BdpTuningReport,
    BdpWindowConfig, BenchmarkMetrics, BenchmarkScenario, CongestionBenchmarkReport,
    CongestionConfig, CongestionLinkProfile, CongestionMetricsSnapshot, CongestionSimulationReport,
    Connection, FecBlockDecoder, FecBlockEncoder, FecBlockHeader, FecCodec, FecProfile,
    FecRecoveryReport, FecSimulationReport, FecStats, FecStatsSnapshot, FecSymbol, ImpairedChannel,
    ImpairmentProfile, ImpairmentStats, MigrationCoordinator, MigrationDecision, MigrationEvent,
    MigrationPolicy, MigrationPolicyMode, MigrationStats, MultipathConfig, MultipathCoordinator,
    MultipathSchedulerPolicy, MultipathSessionReport, NatBindingStatus, NatDiagnosticsReport,
    NatTraversalCoordinator, PacingController, PathState, PmtuConfig, PmtuCoordinator, PmtuState,
    PmtuStats, ProbeBwCyclePhase, RlPacingOptimizer, SharedTransport, SubflowPathDescriptor,
    SubflowQualityMetrics, TokenBucket, TransportConfigTunables, WanMatrixReport, WanMatrixRunner,
    ABSOLUTE_MAX_BDP_WINDOW, ABSOLUTE_MIN_BDP_WINDOW, BASE_PLPMTU, DEFAULT_INITIAL_BDP_WINDOW,
    DEFAULT_MAX_BDP_WINDOW, DEFAULT_MIN_BDP_WINDOW, DEFAULT_PMTU_CANDIDATES, IPV6_MIN_MTU,
    JUMBO_FRAME_MTU, STANDARD_ETHERNET_MTU,
};
pub use txsnapshot::{
    FileOpKind, FileRevision, GlobalSnapshotManifest, RollbackReport, SnapshotSummary,
    StagedFileOp, TwoPhaseCommitResult, TwoPhasePrepare, TwoPhaseVote, TxSnapshotBenchmarkReport,
    TxSnapshotEngine, TxSnapshotStatusReport, TxState, TxVectorClock, VoteKind,
};
pub use util::{
    Hash, HashAlgorithm, HashHasher, ParallelHasher, SimdFeatures, SimdTier, TransferId,
    VectorizedScanner,
};
pub use vault::{
    pack_standalone_envelope, shred_file_on_disk, unpack_standalone_envelope, EphemeralDek,
    VaultBenchmarkReport, VaultEngine, VaultFileStatus, VaultKeyPair, VaultManifest, VaultSummary,
    VAULT_CIPHER_SUITE, VAULT_DEFAULT_SHRED_PASSES, VAULT_KEM_ALGO, VAULT_MAGIC_HEADER,
    VAULT_NONCE_LEN, VAULT_SIG_ALGO, VAULT_TAG_LEN,
};
pub use wan::{
    ReassembledChunk, WanBenchmarkResult, WanBondingEngine, WanInterface, WanInterfaceInfo,
    WanLinkType, WanPathState, WanSlice,
};
pub use xdp::{
    disassemble_quic_filter_bpf, dissect_packet, generate_quic_filter_bpf, parse_packet_headers,
    run_xdp_benchmark, DissectedPacket, EbpfInsn, EbpfProgram, EbpfVerifier, EbpfVm,
    PacketHeaderSummary, QuicFilterAssembler, QuicHeaderForm, SteeringPolicy, SteeringReport,
    UmemConfig, UmemPool, VerifierReport, XdpAction, XdpBenchmarkReport, XdpDescriptor,
    XdpDriverMode, XdpEngine, XdpFilterRule, XdpSocketRouter, XdpStatus, XskMap, XskQueuePair,
    XskQueueStats, XskRing,
};
pub use zkquota::{
    PedersenGenerators, Scalar256, TenantQuotaRecord, ZkBitProof, ZkClusterAuditReport,
    ZkMembershipProof, ZkQuotaAuditBundle, ZkQuotaBenchmarkReport, ZkQuotaEngine,
    ZkQuotaEngineStatus, ZkRangeProof, ZkTenantAuditSummary,
};
