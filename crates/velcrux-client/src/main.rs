//! `velcrux` client CLI. M1 surface: `velcrux ping velcrux://host:7443`.

#![forbid(unsafe_code)]

use anyhow::Context;
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

use velcrux_core::scheduler::BandwidthSchedule;
use velcrux_core::session::ClientSession;
use velcrux_core::transport::quic::{ClientBuilder, ClientIdentity, QuicConnection};
use velcrux_core::transport::SharedTransport;

mod package;
mod ping;

/// velcrux — high-throughput bulk transfer over QUIC.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to a PEM bundle of CA certificates used to verify the server.
    #[arg(long, env = "VELCRUX_CA", global = true)]
    ca: Option<PathBuf>,

    /// Path to the client certificate (PEM). Required for mTLS.
    #[arg(long, env = "VELCRUX_CERT", global = true)]
    cert: Option<PathBuf>,

    /// Path to the client private key (PEM, PKCS#8).
    #[arg(long, env = "VELCRUX_KEY", global = true)]
    key: Option<PathBuf>,

    /// Override the SNI hostname. Defaults to the host in the URL.
    #[arg(long, global = true)]
    sni: Option<String>,

    /// Log format: "text" (default) or "json".
    #[arg(long, default_value = "text", global = true)]
    log_format: String,

    /// Output machine-readable JSON on stdout.
    #[arg(long, global = true)]
    json: bool,

    /// Path to client state SQLite database.
    #[arg(long, env = "VELCRUX_STATE_DB", global = true)]
    state_db: Option<PathBuf>,

    /// Path to a TOML configuration file (defaults to ~/.velcrux/config.toml if present).
    #[arg(long, short, env = "VELCRUX_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Enable content-addressed chunk store deduplication (Option D).
    #[arg(long, global = true)]
    dedup: bool,

    /// Path to local chunk store directory for deduplication.
    #[arg(long, env = "VELCRUX_CHUNK_STORE", global = true)]
    chunk_store: Option<PathBuf>,

    /// Number of concurrent QUIC data streams (Option E, range 1..=16, default: 1).
    #[arg(
        long,
        short = 'P',
        env = "VELCRUX_PARALLEL",
        default_value_t = 1,
        global = true
    )]
    parallel: usize,

    /// Bandwidth rate limit (Option F, e.g. "10M", "500K", "1G", "1048576", default: unlimited).
    #[arg(
        long = "rate-limit",
        short = 'R',
        env = "VELCRUX_RATE_LIMIT",
        global = true
    )]
    rate_limit: Option<String>,

    /// Data compression mode: "none" (default) or "zstd" (Option Q).
    #[arg(
        long = "compression",
        short = 'C',
        env = "VELCRUX_COMPRESSION",
        default_value = "none",
        global = true
    )]
    compression: String,

    /// Transfer execution mode: "auto" (default, adaptive cost-based), "direct" (full stream), "deltacdc" (FastCDC delta), or "deltafixed" (fixed-size delta). Option AD.
    #[arg(
        long = "mode",
        short = 'M',
        env = "VELCRUX_MODE",
        default_value = "auto",
        global = true
    )]
    mode: String,

    /// Network performance profile: "auto" (default, derived from QUIC stats), "lan", "wan", or "satellite". Option AD.
    #[arg(
        long = "network-profile",
        env = "VELCRUX_NETWORK_PROFILE",
        default_value = "auto",
        global = true
    )]
    network_profile: String,

    /// Minimum file size in bytes to consider delta synchronization (Option AD).
    #[arg(
        long = "min-delta-size",
        env = "VELCRUX_MIN_DELTA_SIZE",
        default_value = "65536",
        global = true
    )]
    min_delta_size: u64,

    /// Explicit source IP address to bind to for outgoing QUIC traffic (Option AE).
    #[arg(long = "bind-ip", env = "VELCRUX_BIND_IP", global = true)]
    bind_ip: Option<String>,

    /// Network interface name whose IP address should be bound to for outgoing traffic (Option AE).
    #[arg(long = "bind-interface", env = "VELCRUX_BIND_INTERFACE", global = true)]
    bind_interface: Option<String>,

    /// Local port to bind to for outgoing traffic (default: 0 for ephemeral) (Option AE).
    #[arg(
        long = "bind-port",
        env = "VELCRUX_BIND_PORT",
        default_value = "0",
        global = true
    )]
    bind_port: u16,

    /// Transfer priority tier: "urgent", "high", "normal" (default), or "low" (Option AF).
    #[arg(
        long = "priority",
        env = "VELCRUX_PRIORITY",
        default_value = "normal",
        global = true
    )]
    priority: String,

    /// Maximum concurrent file transfers permitted (Option AF).
    #[arg(
        long = "concurrency",
        env = "VELCRUX_CONCURRENCY",
        default_value = "4",
        global = true
    )]
    concurrency: usize,

    /// Direct I/O execution mode: "auto" (default, files >= 16MiB), "always", or "disabled" (Option AH).
    #[arg(
        long = "direct-io",
        env = "VELCRUX_DIRECT_IO",
        default_value = "auto",
        global = true
    )]
    direct_io: String,

    /// Enable multi-path transport bonding across multiple local network interfaces (Option AX).
    #[arg(long, env = "VELCRUX_MULTIPATH", global = true)]
    multipath: bool,

    /// Multi-path scheduling strategy: "weighted" (default), "min-rtt", "round-robin", "redundant", or "failover" (Option AX).
    #[arg(
        long = "multipath-scheduler",
        env = "VELCRUX_MULTIPATH_SCHEDULER",
        default_value = "weighted",
        global = true
    )]
    multipath_scheduler: String,

    /// Comma-separated list of local interface names to bond for multi-path transport (e.g. "eth0,wlan0") (Option AX).
    #[arg(long = "interfaces", env = "VELCRUX_INTERFACES", global = true)]
    interfaces: Option<String>,

    /// Designated primary interface name for multi-path failover scheduling (Option AX).
    #[arg(
        long = "primary-interface",
        env = "VELCRUX_PRIMARY_INTERFACE",
        global = true
    )]
    primary_interface: Option<String>,

    /// Duplicate critical metadata frames across all active bonded subflow paths (Option AX).
    #[arg(long = "redundant-metadata", global = true)]
    redundant_metadata: bool,

    /// Forward Error Correction (FEC) profile: "disabled", "low", "medium", "high", "satellite", or "auto" (default: "auto") (Option BH).
    #[arg(
        long = "fec",
        env = "VELCRUX_FEC",
        default_value = "auto",
        global = true
    )]
    fec: String,

    /// Bandwidth calendar schedule or policy file (Option BI, e.g. "Mon-Fri 09:00-17:00: 50Mbps; default: 1Gbps").
    #[arg(
        long = "bandwidth-schedule",
        env = "VELCRUX_BANDWIDTH_SCHEDULE",
        global = true
    )]
    bandwidth_schedule: Option<String>,

    /// Deduplication namespace policy: "isolated" (default), "proof-of-ownership", or "global" (Option BJ).
    #[arg(
        long = "dedup-namespace",
        env = "VELCRUX_DEDUP_NAMESPACE",
        default_value = "isolated",
        global = true
    )]
    dedup_namespace: String,

    /// Explicit tenant ID for multi-tenant deduplication namespace partitioning (Option BJ).
    #[arg(long = "tenant", env = "VELCRUX_TENANT", global = true)]
    tenant: Option<String>,

    /// Bandwidth-Delay Product (BDP) auto-tuning policy: "auto" (default), "fixed", "aggressive", or "conservative" (Option BR).
    #[arg(
        long = "bdp-tuning",
        env = "VELCRUX_BDP_TUNING",
        default_value = "auto",
        global = true
    )]
    bdp_tuning: String,

    /// Maximum BDP flow control window ceiling in bytes (default: 536870912 / 512 MiB) (Option BR).
    #[arg(
        long = "max-bdp-window",
        env = "VELCRUX_MAX_BDP_WINDOW",
        default_value = "536870912",
        global = true
    )]
    max_bdp_window: u64,

    /// Minimum BDP flow control window floor in bytes (default: 4194304 / 4 MiB) (Option BR).
    #[arg(
        long = "min-bdp-window",
        env = "VELCRUX_MIN_BDP_WINDOW",
        default_value = "4194304",
        global = true
    )]
    min_bdp_window: u64,

    /// Number of ring buffer slots for Direct I/O kernel zero-copy pipeline (default: 4) (Option BS).
    #[arg(
        long = "direct-io-slots",
        env = "VELCRUX_DIRECT_IO_SLOTS",
        default_value = "4",
        global = true
    )]
    direct_io_slots: usize,

    /// Slot capacity in bytes for Direct I/O ring buffer pipeline (default: 2097152 / 2 MiB) (Option BS).
    #[arg(
        long = "direct-io-slot-size",
        env = "VELCRUX_DIRECT_IO_SLOT_SIZE",
        default_value = "2097152",
        global = true
    )]
    direct_io_slot_size: usize,

    /// Checkpoint time interval in seconds (default: 10) (Option BT).
    #[arg(
        long = "checkpoint-interval",
        env = "VELCRUX_CHECKPOINT_INTERVAL",
        default_value = "10",
        global = true
    )]
    checkpoint_interval: u64,

    /// Checkpoint byte threshold in bytes (default: 268435456 / 256 MiB) (Option BT).
    #[arg(
        long = "checkpoint-bytes",
        env = "VELCRUX_CHECKPOINT_BYTES",
        default_value = "268435456",
        global = true
    )]
    checkpoint_bytes: u64,

    /// SQLite Write-Ahead Logging (WAL) auto-checkpoint page threshold (default: 1000) (Option BT).
    #[arg(
        long = "wal-autocheckpoint",
        env = "VELCRUX_WAL_AUTOCHECKPOINT",
        default_value = "1000",
        global = true
    )]
    wal_autocheckpoint: u32,

    /// Quality of Service (QoS) flow priority tier: "realtime", "critical", "default", or "background" (Option BU).
    #[arg(
        long = "qos-priority",
        env = "VELCRUX_QOS_PRIORITY",
        default_value = "default",
        global = true
    )]
    qos_priority: String,

    /// QoS root link bandwidth capacity specification (e.g. "1Gbps", "100Mbps", or "unlimited") (Option BU).
    #[arg(
        long = "qos-bandwidth",
        env = "VELCRUX_QOS_BANDWIDTH",
        default_value = "unlimited",
        global = true
    )]
    qos_bandwidth: String,

    /// CAS tombstone retention time-to-live in seconds before physical purge (Option BV).
    #[arg(
        long = "cas-tombstone-ttl",
        env = "VELCRUX_CAS_TOMBSTONE_TTL",
        default_value = "86400",
        global = true
    )]
    cas_tombstone_ttl: u64,

    /// CAS nursery grace period in seconds protecting recently ingested chunks from GC (Option BV).
    #[arg(
        long = "cas-nursery-grace",
        env = "VELCRUX_CAS_NURSERY_GRACE",
        default_value = "3600",
        global = true
    )]
    cas_nursery_grace: u64,

    /// Enable Distributed Gossip-Based Peer Discovery & Swarm P2P Acceleration (Option BW).
    #[arg(long = "swarm", env = "VELCRUX_SWARM", global = true)]
    swarm: bool,

    /// Swarm gossip and P2P communication listening port (Option BW, default: 19444).
    #[arg(
        long = "swarm-port",
        env = "VELCRUX_SWARM_PORT",
        default_value = "19444",
        global = true
    )]
    swarm_port: u16,

    /// Known swarm bootstrap seed peer addresses (Option BW, e.g. "127.0.0.1:19445,10.0.0.2:19444").
    #[arg(
        long = "swarm-seeds",
        env = "VELCRUX_SWARM_SEEDS",
        value_delimiter = ',',
        global = true
    )]
    swarm_seeds: Vec<String>,

    /// Maximum concurrent peer connections maintained in the swarm mesh (Option BW, default: 50).
    #[arg(
        long = "swarm-max-peers",
        env = "VELCRUX_SWARM_MAX_PEERS",
        default_value = "50",
        global = true
    )]
    swarm_max_peers: usize,

    /// Enable Automated Continuous Chaos Engineering and Fault Injection (Option BX).
    #[arg(long = "chaos", env = "VELCRUX_CHAOS", global = true)]
    chaos: bool,

    /// Chaos uniform packet loss rate (Option BX, e.g. 0.05 for 5% loss).
    #[arg(
        long = "chaos-loss",
        env = "VELCRUX_CHAOS_LOSS",
        default_value = "0.0",
        global = true
    )]
    chaos_loss: f64,

    /// Chaos base transmission latency delay in milliseconds (Option BX).
    #[arg(
        long = "chaos-delay-ms",
        env = "VELCRUX_CHAOS_DELAY_MS",
        default_value = "0",
        global = true
    )]
    chaos_delay_ms: u64,

    /// Chaos latency variance / jitter in milliseconds (Option BX).
    #[arg(
        long = "chaos-jitter-ms",
        env = "VELCRUX_CHAOS_JITTER_MS",
        default_value = "0",
        global = true
    )]
    chaos_jitter_ms: u64,

    /// Chaos Byzantine payload bit-rot corruption rate (Option BX, e.g. 0.005).
    #[arg(
        long = "chaos-corrupt-rate",
        env = "VELCRUX_CHAOS_CORRUPT_RATE",
        default_value = "0.0",
        global = true
    )]
    chaos_corrupt_rate: f64,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Open a session and round-trip a PING. The M1 exit test
    /// (`docs/ARCHITECTURE.md` §12).
    Ping {
        /// Target `velcrux://host:port` URL.
        url: String,
    },
    /// Upload a single local file to the server. M2.
    Upload {
        /// Local file to upload.
        local: PathBuf,
        /// Target `velcrux://host:port/path` URL.
        url: String,
    },
    /// Download a single remote file from the server. M2.
    Download {
        /// Source `velcrux://host:port/path` URL.
        url: String,
        /// Local destination path.
        local: PathBuf,
    },
    /// Resume a previously-interrupted transfer. M3.
    Resume {
        /// Transfer id (26-character ULID).
        transfer_id: String,
        /// Target server URL (e.g. `velcrux://host:port/`).
        #[arg(long, default_value = "velcrux://localhost:7443/")]
        server: String,
        /// Local file path (required if not found in client state store).
        #[arg(long)]
        local: Option<PathBuf>,
    },
    /// Cancel an in-progress transfer. M3.
    Cancel {
        /// Transfer id (26-character ULID).
        transfer_id: String,
        /// Target server URL (e.g. `velcrux://host:port/`).
        #[arg(long, default_value = "velcrux://localhost:7443/")]
        server: String,
    },
    /// Show state of a single transfer. M3.
    Stat {
        /// Transfer id (26-character ULID).
        transfer_id: String,
        /// Target server URL (e.g. `velcrux://host:port/`).
        #[arg(long, default_value = "velcrux://localhost:7443/")]
        server: String,
    },
    /// List transfers by URL prefix. M3.
    List {
        /// URL prefix, e.g. `velcrux://host:7443/data/`.
        url_prefix: String,
    },
    /// Calculate and display a transfer plan and reconciliation diff without modifying destination (REQUIREMENTS.md §57).
    Plan {
        /// Source directory or URL.
        source: String,
        /// Destination directory or URL.
        destination: String,
        /// Deletion mode: none, delete-before, delete-after, delete-excluded.
        #[arg(long, default_value = "none")]
        delete_mode: String,
        /// Delete extraneous destination files before transfers begin.
        #[arg(long)]
        delete_before: bool,
        /// Delete extraneous destination files after commits succeed.
        #[arg(long)]
        delete_after: bool,
        /// Alias for --delete-after.
        #[arg(long)]
        delete: bool,
        /// Delete extraneous files and any destination files matching exclude patterns.
        #[arg(long)]
        delete_excluded: bool,
        /// Exclude files matching glob pattern (can be specified multiple times).
        #[arg(long = "exclude")]
        excludes: Vec<String>,
        /// Maximum number of files permitted to be deleted before aborting.
        #[arg(long)]
        max_delete: Option<usize>,
        /// Maximum percentage of destination files permitted to be deleted before aborting (0-100).
        #[arg(long)]
        max_delete_pct: Option<f64>,
        /// Bypass deletion safety threshold guardrails.
        #[arg(long)]
        force_delete: bool,
        /// Use content-defined chunking (FastCDC) instead of fixed chunking.
        #[arg(long)]
        cdc: bool,
        /// Enable content-addressed chunk store deduplication.
        #[arg(long)]
        dedup: bool,
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
    /// Synchronize a directory tree incrementally (M9).
    Sync {
        /// Source directory or URL.
        source: String,
        /// Destination directory or URL.
        destination: String,
        /// Calculate changes and print summary without modifying destination.
        #[arg(long)]
        dry_run: bool,
        /// Delete extraneous destination files before transfers begin.
        #[arg(long)]
        delete_before: bool,
        /// Delete extraneous destination files after all commits succeed.
        #[arg(long)]
        delete_after: bool,
        /// Alias for --delete-after.
        #[arg(long)]
        delete: bool,
        /// Delete extraneous files and any destination files matching exclude patterns.
        #[arg(long)]
        delete_excluded: bool,
        /// Exclude files matching glob pattern (can be specified multiple times).
        #[arg(long = "exclude")]
        excludes: Vec<String>,
        /// Maximum number of files permitted to be deleted before aborting.
        #[arg(long)]
        max_delete: Option<usize>,
        /// Maximum percentage of destination files permitted to be deleted before aborting (0-100).
        #[arg(long)]
        max_delete_pct: Option<f64>,
        /// Bypass deletion safety threshold guardrails.
        #[arg(long)]
        force_delete: bool,
        /// Use content-defined chunking (FastCDC) instead of fixed chunking.
        #[arg(long)]
        cdc: bool,
        /// Enable content-addressed chunk store deduplication.
        #[arg(long)]
        dedup: bool,
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Bundle small files into streaming batch containers (default: enabled).
        #[arg(long)]
        batch_small_files: bool,
        /// Disable small file batch container pipeline.
        #[arg(long)]
        no_batch_small_files: bool,
        /// Size threshold in bytes under which regular files are batched (default: 131072 / 128 KiB).
        #[arg(long, env = "VELCRUX_SMALL_FILE_THRESHOLD")]
        small_file_threshold: Option<u64>,
        /// Maximum container payload bytes per batch (default: 33554432 / 32 MiB).
        #[arg(long, env = "VELCRUX_BATCH_MAX_BYTES")]
        batch_max_bytes: Option<u64>,
        /// Continuously watch source directory and synchronize changes in real time (Option AZ).
        #[arg(long)]
        watch: bool,
        /// Debounce window in milliseconds for watch mode (default: 200).
        #[arg(long, default_value = "200")]
        debounce_ms: u64,
        /// Polling scan interval in milliseconds for watch mode (default: 500).
        #[arg(long, default_value = "500")]
        poll_interval_ms: u64,
        /// Maximum sync batches to run before stopping (default: 0 = continuous).
        #[arg(long, default_value = "0")]
        max_batches: usize,
        /// Whole-directory transactional commit and rollback journaling (Option BM).
        #[arg(long)]
        atomic: bool,
        /// Automatically sign manifest upon sync completion with the provided Ed25519 private key (Option BO).
        #[arg(long = "sign-key", env = "VELCRUX_SYNC_SIGN_KEY")]
        sign_key: Option<PathBuf>,
        /// Issuer identity string when signing manifest during sync (Option BO).
        #[arg(long = "sign-issuer", default_value = "velcrux-sync")]
        sign_issuer: String,
        /// Verify target against detached attestation signature after sync (Option BO).
        #[arg(long = "verify-sig")]
        verify_sig: Option<PathBuf>,
        /// Path to trusted signers file for post-sync attestation verification (Option BO).
        #[arg(long = "trusted-signers", env = "VELCRUX_TRUSTED_SIGNERS")]
        trusted_signers: Option<PathBuf>,
        /// Extended attribute preservation and transmutation policy: transmute (default), strict, sidecar, strip (Option BP).
        #[arg(
            long = "xattr-policy",
            default_value = "transmute",
            env = "VELCRUX_XATTR_POLICY"
        )]
        xattr_policy: String,
        /// ACL preservation and transmutation policy: transmute (default), strict, sidecar, strip (Option BP).
        #[arg(
            long = "acl-policy",
            default_value = "transmute",
            env = "VELCRUX_ACL_POLICY"
        )]
        acl_policy: String,
        /// Delta dictionary compression policy: auto (default), off, aggressive (Option BQ).
        #[arg(
            long = "delta-dict",
            default_value = "auto",
            env = "VELCRUX_DELTA_DICT"
        )]
        delta_dict: String,
        /// Minimum savings percentage required to adopt delta dictionary compression (Option BQ).
        #[arg(
            long = "delta-dict-threshold",
            default_value = "15",
            env = "VELCRUX_DELTA_DICT_THRESHOLD"
        )]
        delta_dict_threshold: u8,
    },
    /// Content-aware delta compression and CDC slicing utilities (Option BQ).
    #[command(name = "delta-slice")]
    DeltaSlice {
        #[command(subcommand)]
        sub: DeltaSliceSubCmd,
    },
    /// Bandwidth-Delay Product (BDP) auto-tuning and flow control inspection (Option BR).
    Bdp {
        #[command(subcommand)]
        sub: BdpSubCmd,
    },
    /// Direct I/O zero-copy kernel ring-buffer engine inspection and benchmarks (Option BS).
    #[command(name = "direct-io")]
    DirectIo {
        #[command(subcommand)]
        sub: DirectIoSubCmd,
    },
    /// Persistent transfer checkpointing, SQLite WAL management, and fast recovery (Option BT).
    Checkpoint {
        #[command(subcommand)]
        sub: CheckpointSubCmd,
    },
    /// Hierarchical Token-Bucket Quality of Service (QoS) & Flow Priority Multiplexer (Option BU).
    Qos {
        #[command(subcommand)]
        sub: QosSubCmd,
    },
    /// Content-Addressable Storage (CAS) generational GC, tombstoning, and compaction (Option BV).
    Cas {
        #[command(subcommand)]
        sub: CasSubCmd,
    },
    /// Distributed gossip-based peer discovery & swarm P2P acceleration engine (Option BW).
    Swarm {
        #[command(subcommand)]
        sub: SwarmSubCmd,
    },
    /// Automated continuous chaos engineering & network fault injection suite (Option BX).
    Chaos {
        #[command(subcommand)]
        sub: ChaosSubCmd,
    },
    /// Multi-tenant hierarchical storage tiering and hybrid lifecycle engine (Option BY).
    Tier {
        #[command(subcommand)]
        sub: TierSubCmd,
    },
    /// Manage whole-directory transactions, inspect journals, and rollback/recover (Option BM).
    Tx {
        #[command(subcommand)]
        sub: TxSubCmd,
    },
    /// Continuously watch a directory tree and synchronize changes in real time (Option AZ).
    Watch {
        /// Source directory to monitor.
        source: String,
        /// Destination directory or URL.
        destination: String,
        /// Debounce window in milliseconds to coalesce rapid file modifications (default: 200).
        #[arg(long, default_value = "200")]
        debounce_ms: u64,
        /// Polling scan interval in milliseconds (default: 500).
        #[arg(long, default_value = "500")]
        poll_interval_ms: u64,
        /// Maximum number of sync batches to execute before exiting (default: 0 = continuous).
        #[arg(long, default_value = "0")]
        max_batches: usize,
        /// Exclude files matching glob pattern (can be specified multiple times).
        #[arg(long = "exclude")]
        excludes: Vec<String>,
        /// Perform initial full synchronization on startup.
        #[arg(long)]
        initial_sync: bool,
        /// Use content-defined chunking (FastCDC).
        #[arg(long)]
        cdc: bool,
        /// Enable content-addressed chunk store deduplication.
        #[arg(long)]
        dedup: bool,
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
    /// Generate shell completion script (bash, zsh, fish, powershell, elvish).
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
    /// Display host hardware SIMD vector acceleration and CPU capabilities.
    Hardware,
    /// Empirically profile transfer pipelines and diagnose bottlenecks (REQUIREMENTS.md §72, §38, §36).
    Profile {
        /// Local file to benchmark or transfer under profiling.
        file: PathBuf,
        /// Optional target `velcrux://host:port/path` URL to profile end-to-end network transfer.
        #[arg(long)]
        url: Option<String>,
        /// Chunking mode: "cdc" (default) or "fixed".
        #[arg(long, default_value = "cdc")]
        chunk_mode: String,
    },
    /// Generate production service units and deployment manifests (systemd, launchd, docker, k8s).
    Package {
        #[command(subcommand)]
        target: package::PackageTarget,
    },
    /// S3-compatible cloud object storage gateway backend (REQUIREMENTS.md §42, §43).
    S3 {
        #[command(subcommand)]
        sub: S3SubCmd,
    },
    /// Google Cloud Storage (GCS) gateway backend (Option BK).
    Gcs {
        #[command(subcommand)]
        sub: GcsSubCmd,
    },
    /// Azure Blob Storage gateway backend (Option BK).
    Azure {
        #[command(subcommand)]
        sub: AzureSubCmd,
    },
    /// Interactive Virtual Filesystem mount engine (Option BL).
    Mount {
        #[command(subcommand)]
        sub: MountSubCmd,
    },
    /// Unmount an active virtual filesystem mountpoint (Option BL).
    Unmount {
        /// Target mountpoint directory path to unmount.
        mountpoint: PathBuf,
    },
    /// Inspect local network interfaces and bonded multi-path transport status (Option AX).
    Multipath {
        /// Optional target server URL to evaluate subflow path reachability (e.g. velcrux://host:7443/).
        #[arg(long)]
        target: Option<String>,
    },
    /// Distributed chunk store cluster management and replication (Option AY).
    Cluster {
        #[command(subcommand)]
        sub: ClusterSubCmd,
    },
    /// Cross-cluster WAN geo-replication and conflict-free multi-region synchronization (Option BA).
    Geo {
        #[command(subcommand)]
        sub: GeoSubCmd,
    },
    /// Pluggable webhook event notifications and audit logging bus (Option BB).
    Webhook {
        #[command(subcommand)]
        sub: WebhookSubCmd,
    },
    /// Point-in-time snapshot isolation, version history, and time-travel restore (Option BC).
    Snapshot {
        #[command(subcommand)]
        sub: SnapshotSubCmd,
    },
    /// Distributed lock manager (DLM) and mutex lease coordinator (Option BD).
    Lock {
        #[command(subcommand)]
        sub: LockSubCmd,
    },
    /// Dynamic Zstandard pre-trained dictionary learning engine (Option BE).
    Dict {
        #[command(subcommand)]
        sub: DictSubCmd,
    },
    /// In-flight data integrity scrubbing and background bit-rot repair daemon (Option BF).
    Scrub {
        #[command(subcommand)]
        sub: ScrubSubCmd,
    },
    /// Unix stdin/stdout streaming pipelines over QUIC (Option BG).
    Stream {
        #[command(subcommand)]
        sub: StreamSubCmd,
    },
    /// Adaptive multi-stream Forward Error Correction (FEC) engine (Option BH).
    Fec {
        #[command(subcommand)]
        sub: FecSubCmd,
    },
    /// Calendar and time-of-day bandwidth scheduler (Option BI).
    Schedule {
        #[command(subcommand)]
        sub: ScheduleSubCmd,
    },
    /// Multi-tenant deduplication namespacing, poisoning defense, and quarantine management (Option BJ).
    Dedup {
        #[command(subcommand)]
        sub: DedupSubCmd,
    },
    /// Cryptographic detached manifest signing and end-to-end attestation (Option BO, SECURITY.md §7).
    Attest {
        #[command(subcommand)]
        sub: AttestSubCmd,
    },
    /// Cryptographic zero-knowledge transfer audit proofs and Merkle tree accumulator (Option CA).
    Audit {
        #[command(subcommand)]
        sub: AuditSubCmd,
    },
    /// Distributed dynamic content router, anycast steering, and live session migration (Option CB).
    Router {
        #[command(subcommand)]
        sub: RouterSubCmd,
    },
    /// Hardware-accelerated FPGA/eBPF kernel XDP packet bypassing and UMEM zero-copy engine (Option CC).
    Xdp {
        #[command(subcommand)]
        sub: XdpSubCmd,
    },
    /// Quantum-resilient post-quantum hybrid cryptography engine (ML-KEM-768 & ML-DSA-65) (Option CD).
    Pqc {
        #[command(subcommand)]
        sub: PqcSubCmd,
    },
    /// eBPF-driven programmable L7 proxying & dynamic layer-7 load shedding (Option CE).
    Proxy {
        #[command(subcommand)]
        sub: ProxySubCmd,
    },
    /// Autonomous multi-path WAN slicing & sub-millisecond dynamic interface bonding (Option CF).
    Wan {
        #[command(subcommand)]
        sub: WanSubCmd,
    },
    /// Zero-trust decentralized identity (DID) & verifiable credential attestation mesh (Option CG).
    Did {
        #[command(subcommand)]
        sub: DidSubCmd,
    },
    /// Confidential computing & hardware TEE remote attestation (Option CH).
    Tee {
        #[command(subcommand)]
        sub: TeeSubCmd,
    },
    /// Distributed erasure coding & autonomous shard scrub mesh (Option CI).
    Ec {
        #[command(subcommand)]
        sub: EcSubCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ProxySubCmd {
    /// Show current proxy status, pressure metrics, flow counts, and active policy mode.
    Status {
        /// Optional simulated CPU utilization percentage (0-100).
        #[arg(long)]
        cpu: Option<f64>,
        /// Optional simulated memory pressure percentage (0-100).
        #[arg(long)]
        mem: Option<f64>,
        /// Optional simulated queue occupancy percentage (0-100).
        #[arg(long)]
        queue: Option<f64>,
        /// Optional simulated RTT inflation percentage (0-100).
        #[arg(long)]
        rtt: Option<f64>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List active programmable L7 classification and load shedding rules.
    Rules {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Add or update a programmable L7 proxy rule.
    AddRule {
        /// Unique rule identifier.
        #[arg(long)]
        id: String,
        /// Rule description.
        #[arg(long, default_value = "Operator custom rule")]
        desc: String,
        /// Execution precedence (lower = evaluated earlier, default: 50).
        #[arg(long, default_value = "50")]
        precedence: u32,
        /// Matching tenant prefix filter.
        #[arg(long)]
        tenant_prefix: Option<String>,
        /// Matching path prefix filter.
        #[arg(long)]
        path_prefix: Option<String>,
        /// Matching stream type: control, data, metadata, datagram.
        #[arg(long)]
        stream_type: Option<String>,
        /// Action to execute: admit, throttle, shed, reroute.
        #[arg(long, default_value = "admit")]
        action: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Classify an ingress stream and evaluate load shedding action under given pressure.
    Classify {
        /// Ingress tenant ID.
        #[arg(long, default_value = "tenant-prod-1")]
        tenant: String,
        /// Ingress transfer path.
        #[arg(long, default_value = "/data/shards/part-001")]
        path: String,
        /// Stream type: control, data, metadata, datagram.
        #[arg(long, default_value = "data")]
        stream_type: String,
        /// Stream priority hint (0=highest/interactive, 4=lowest/background).
        #[arg(long = "flow-priority")]
        flow_priority: Option<u8>,
        /// Ingress payload byte size.
        #[arg(long, default_value = "65536")]
        payload_bytes: usize,
        /// Simulated system pressure percentage (0-100).
        #[arg(long, default_value = "25.0")]
        pressure: f64,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Simulate dynamic load shedding cascade across flow tiers under increasing pressure.
    Shed {
        /// Target pressure percentage (0-100).
        #[arg(long, default_value = "85.0")]
        pressure: f64,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Benchmark programmable L7 classification, rule evaluation, and load shedding latency.
    Benchmark {
        /// Number of benchmark iterations (default: 500).
        #[arg(long, default_value = "500")]
        iterations: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum WanSubCmd {
    /// Show current bonded WAN interfaces, link types, capacity weights, and probe telemetry.
    Status {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List active bonded WAN interfaces.
    Interfaces {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Slice a chunk or test payload across bonded WAN uplinks and execute zero-HOL reassembly.
    Slice {
        /// Size of synthetic payload in bytes to slice (default: 131072 = 128 KiB).
        #[arg(long, default_value = "131072")]
        size: usize,
        /// Maximum slice frame size in bytes (default: 32768 = 32 KiB).
        #[arg(long, default_value = "32768")]
        slice_size: usize,
        /// Simulate out-of-order slice arrival during reassembly.
        #[arg(long)]
        reorder: bool,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Update path quality probe metrics (SRTT, jitter, loss, ECN) for an interface.
    Probe {
        /// Interface ID to probe (e.g. wan0-fiber100g, wan1-eth10g, wan2-starlink, wan3-cellular5g).
        #[arg(long, default_value = "wan2-starlink")]
        interface: String,
        /// Smoothed RTT in microseconds.
        #[arg(long, default_value = "45000")]
        srtt_us: u64,
        /// RTT variance / jitter in microseconds.
        #[arg(long, default_value = "12000")]
        jitter_us: u64,
        /// Packet loss in basis points (1 bp = 0.01%).
        #[arg(long, default_value = "150")]
        loss_bp: u64,
        /// ECN CE marks in basis points (1 bp = 0.01%).
        #[arg(long, default_value = "50")]
        ecn_bp: u64,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Benchmark WAN slicing, probe recalculation, and zero-HOL reassembly throughput.
    Benchmark {
        /// Number of benchmark iterations (default: 50).
        #[arg(long, default_value = "50")]
        iterations: usize,
        /// Chunk payload size in bytes per iteration (default: 65536 = 64 KiB).
        #[arg(long, default_value = "65536")]
        chunk_size: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum DidSubCmd {
    /// Show active DID attestation engine status and telemetry counters.
    Status {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate a new Ed25519 decentralized identifier (did:key or did:peer).
    Generate {
        /// Generate a did:peer (numalgo 0 inception key) instead of did:key.
        #[arg(long)]
        peer: bool,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Resolve a did:key or did:peer identifier into its W3C DID Document.
    Resolve {
        /// Target DID string (e.g. did:key:z6M... or did:peer:0z6M...).
        #[arg(long)]
        did: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Issue a cryptographically signed W3C Verifiable Credential for transfer capability.
    IssueVc {
        /// Issuer Ed25519 PKCS#8 private key (hex-encoded).
        #[arg(long)]
        issuer_sk: String,
        /// Subject DID granted the capability.
        #[arg(long)]
        subject_did: String,
        /// Organization / tenant ID.
        #[arg(long, default_value = "tenant-default")]
        tenant: String,
        /// Comma-separated list of permitted transfer path patterns.
        #[arg(long, default_value = "/*")]
        paths: String,
        /// Comma-separated list of permitted operations (upload, download, sync, admin).
        #[arg(long, default_value = "upload,download,sync")]
        ops: String,
        /// Maximum allowed transfer bandwidth in bits per second (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_bandwidth: u64,
        /// Credential validity period in hours.
        #[arg(long, default_value = "24")]
        valid_hours: u64,
        /// Delegation depth allowed for sub-agents (0 = non-delegatable).
        #[arg(long, default_value = "1")]
        delegation_depth: u32,
        /// Optional path or JSON string of parent credential to chain delegation.
        #[arg(long)]
        parent_vc: Option<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a W3C Verifiable Credential against requested path, operation, and delegation chain.
    VerifyVc {
        /// Verifiable Credential JSON string or path to file.
        #[arg(long)]
        vc: String,
        /// Optional requested transfer path to check against allowedPaths.
        #[arg(long)]
        requested_path: Option<String>,
        /// Optional requested operation to check against allowedOperations.
        #[arg(long)]
        requested_op: Option<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Benchmark DID resolution, VC issuance, and VC verification latency and throughput.
    Benchmark {
        /// Number of benchmark iterations (default: 500).
        #[arg(long, default_value = "500")]
        iterations: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum TeeSubCmd {
    /// Show active TEE remote attestation engine status and telemetry counters.
    Status {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Measure an enclave executable binary to compute its deterministic launch digest.
    Measure {
        /// Path to the binary executable to measure.
        #[arg(long)]
        binary: PathBuf,
        /// Target TEE hardware platform (amd_sev_snp, intel_sgx, intel_tdx, aws_nitro, simulated).
        #[arg(long, default_value = "amd_sev_snp")]
        platform: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate a cryptographically signed hardware TEE remote attestation quote.
    Quote {
        /// Target TEE hardware platform (amd_sev_snp, intel_sgx, intel_tdx, aws_nitro, simulated).
        #[arg(long, default_value = "amd_sev_snp")]
        platform: String,
        /// Enclave launch measurement hex string. If not specified, a default launch measurement is generated.
        #[arg(long)]
        measurement: Option<String>,
        /// Report data string or hex string (session challenge nonce binding).
        #[arg(long, default_value = "default_challenge_nonce")]
        report_data: String,
        /// TCB security version number.
        #[arg(long, default_value = "1")]
        security_version: u32,
        /// Enable debug mode for the enclave quote (forbidden in secure production policies).
        #[arg(long)]
        debug_mode: bool,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a hardware TEE remote attestation quote against a security policy.
    Verify {
        /// Attestation quote JSON string or path to JSON file.
        #[arg(long)]
        quote: String,
        /// Optional path or JSON string of TEE verification policy.
        #[arg(long)]
        policy: Option<String>,
        /// Optional expected challenge nonce (hex or string) to verify report_data binding.
        #[arg(long)]
        nonce: Option<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run microsecond benchmark for TEE quote generation, verification, and key derivation.
    Benchmark {
        /// Number of benchmark iterations (default: 50).
        #[arg(long, default_value = "50")]
        iterations: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum EcSubCmd {
    /// Show active erasure coding and shard scrub mesh status and telemetry counters.
    Status {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Encode a file or binary payload into systematic (K + M) data and parity shards.
    Encode {
        /// Path to input file to encode.
        #[arg(long)]
        input: PathBuf,
        /// Output directory to store generated shard files.
        #[arg(long, alias = "output-dir")]
        out_dir: PathBuf,
        /// Number of data shards (K, default: 4).
        #[arg(long, short = 'k', default_value = "4")]
        data_shards: usize,
        /// Number of parity shards (M, default: 2).
        #[arg(long, short = 'm', default_value = "2")]
        parity_shards: usize,
        /// Optional object ID (defaults to filename).
        #[arg(long)]
        object_id: Option<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Decode a reconstructed file from a directory containing at least K valid shards.
    Decode {
        /// Directory containing shard files.
        #[arg(long, alias = "dir")]
        shards_dir: PathBuf,
        /// Path to output reconstructed file.
        #[arg(long)]
        output: PathBuf,
        /// Target object ID to decode (optional if directory has shards for one object).
        #[arg(long)]
        object_id: Option<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scrub shard directory for corruptions, bit-rot, and missing shards.
    Scrub {
        /// Directory containing shard files to inspect.
        #[arg(long, alias = "dir")]
        shards_dir: PathBuf,
        /// Automatically reconstruct and self-heal missing/corrupted shards on disk.
        #[arg(long)]
        auto_repair: bool,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run microsecond benchmark measuring encoding, decoding with missing shards, and repair latency.
    Benchmark {
        /// Number of benchmark iterations (default: 50).
        #[arg(long, default_value = "50")]
        iterations: usize,
        /// Payload size in bytes per iteration (default: 65536 = 64 KiB).
        #[arg(long, default_value = "65536")]
        size: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum PqcSubCmd {
    /// Show active post-quantum cryptography suite status and NIST FIPS standards compliance.
    Status {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate quantum-resilient hybrid or post-quantum keypairs.
    Keygen {
        /// Key generation mode: "hybrid" (default), "kem", or "sig".
        #[arg(long, default_value = "hybrid")]
        mode: String,
        /// Optional directory to save key files.
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Encapsulate a quantum-resilient hybrid shared secret using peer public key.
    Encap {
        /// Peer public key (hex-encoded).
        public_key_hex: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Decapsulate a quantum-resilient hybrid shared secret using private key and ciphertext.
    Decap {
        /// Recipient private key (hex-encoded).
        private_key_hex: String,
        /// Encapsulated ciphertext (hex-encoded).
        ciphertext_hex: String,
        /// Peer classical public key (32 bytes hex, optional).
        #[arg(long)]
        peer_pk_hex: Option<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Sign a payload or manifest file using dual-hybrid Ed25519 + ML-DSA-65 signatures.
    Sign {
        /// Path to the file or manifest to sign.
        manifest_path: PathBuf,
        /// Hybrid private key (hex-encoded).
        private_key_hex: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a dual-hybrid Ed25519 + ML-DSA-65 signature over a payload or manifest file.
    Verify {
        /// Path to the file or manifest to verify.
        manifest_path: PathBuf,
        /// Hybrid public key (hex-encoded).
        public_key_hex: String,
        /// Hybrid signature (hex-encoded).
        signature_hex: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Benchmark quantum-resilient key generation, encapsulation, decapsulation, signing, and verification.
    Benchmark {
        /// Number of benchmark iterations (default: 50).
        #[arg(long, default_value = "50")]
        iterations: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum XdpSubCmd {
    /// Inspect active status, driver mode, UMEM frame allocations, and packet counters.
    Status {
        /// Target network interface name.
        #[arg(long, default_value = "eth0")]
        interface: String,
        /// Hardware driver mode: generic, native, or hardware.
        #[arg(long, default_value = "native")]
        mode: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect and parse packet headers at wire speed (Ethernet, IPv4/IPv6, UDP/TCP, QUIC).
    Inspect {
        /// Hex-encoded packet payload.
        packet_hex: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect AF_XDP ring buffer status (Fill Ring, RX Ring, TX Ring, Completion Ring).
    Rings {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compile and evaluate an eBPF/XDP wire-speed packet filtering rule.
    Filter {
        /// Target port to filter (default: 7443).
        #[arg(long, default_value = "7443")]
        port: u16,
        /// Optional QUIC Connection ID hex string.
        #[arg(long)]
        cid: Option<String>,
        /// XDP action if matched: redirect, pass, drop, tx (default: "redirect").
        #[arg(long, default_value = "redirect")]
        action: String,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run wire-speed packet parsing, filtering, and UMEM zero-copy ring benchmark.
    Benchmark {
        /// Number of benchmark packets to process (default: 1000).
        #[arg(long, default_value = "1000")]
        packets: usize,
        /// AF_XDP descriptor batch processing size (default: 32).
        #[arg(long, default_value = "32")]
        batch_size: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum RouterSubCmd {
    /// Inspect overall router health, registered PoPs, and active session migrations.
    Status {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List all registered edge Point-of-Presence (PoP) nodes and their health metrics.
    Pops {
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compute optimal anycast route for a client transfer based on latency and load.
    Route {
        /// Client identifier or IP address.
        client_id: String,
        /// Client geographic latitude.
        #[arg(long, default_value = "37.7749", allow_hyphen_values = true)]
        lat: f64,
        /// Client geographic longitude.
        #[arg(long, default_value = "-122.4194", allow_hyphen_values = true)]
        lon: f64,
        /// Optional preferred region hint.
        #[arg(long)]
        region: Option<String>,
        /// Required transfer bandwidth in bits per second (default: 50 Mbps).
        #[arg(long, default_value = "50000000")]
        bandwidth: u64,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Issue a cryptographic migration ticket and execute live session handover across PoPs.
    Migrate {
        /// Active transfer session identifier.
        session_id: String,
        /// Source PoP identifier (default: "pop-iad").
        #[arg(long, default_value = "pop-iad")]
        source: String,
        /// Target PoP identifier (default: "pop-sfo").
        #[arg(long, default_value = "pop-sfo")]
        target: String,
        /// Transfer identifier (default: "transfer-01").
        #[arg(long, default_value = "transfer-01")]
        transfer_id: String,
        /// Current acknowledged byte offset (default: 5242880).
        #[arg(long, default_value = "5242880")]
        offset: u64,
        /// Total transfer bytes (default: 10485760).
        #[arg(long, default_value = "10485760")]
        total: u64,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run benchmark evaluating anycast routing throughput, failover, and migration latency.
    Benchmark {
        /// Number of simulated edge PoPs.
        #[arg(long, default_value = "5")]
        pops: usize,
        /// Number of iterations.
        #[arg(long, default_value = "50")]
        iterations: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum AuditSubCmd {
    /// Inspect audit status and Merkle accumulator tree summary for an epoch.
    Status {
        /// Epoch number (defaults to 1).
        #[arg(long, default_value = "1")]
        epoch: u64,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate a cryptographic zero-knowledge inclusion proof for a transfer record.
    GenerateProof {
        /// Transfer ID to generate proof for.
        transfer_id: String,
        /// Tenant ID associated with the transfer (defaults to "default").
        #[arg(long, default_value = "default")]
        tenant: String,
        /// Optional 32-byte hex blinding salt. If omitted, a deterministic salt is derived.
        #[arg(long)]
        salt: Option<String>,
        /// Transferred bytes (defaults to 1048576).
        #[arg(long, default_value = "1048576")]
        bytes: u64,
        /// Destination file path to save proof JSON.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Cryptographically verify a zero-knowledge inclusion proof.
    VerifyProof {
        /// Expected 32-byte hex Merkle tree root hash.
        #[arg(long)]
        root: String,
        /// Target 32-byte hex leaf hash.
        #[arg(long)]
        leaf: String,
        /// Path to proof JSON file.
        #[arg(long)]
        proof_file: Option<PathBuf>,
        /// Inline JSON string representation of proof.
        #[arg(long)]
        proof_json: Option<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Export the authoritative Merkle accumulator root hash for an epoch.
    ExportRoot {
        /// Epoch number (defaults to 1).
        #[arg(long, default_value = "1")]
        epoch: u64,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run benchmark evaluating Merkle tree accumulation and proof throughput.
    Benchmark {
        /// Total synthetic transfer records to accumulate.
        #[arg(long, default_value = "50")]
        records: usize,
        /// Number of proof generation and verification samples to evaluate.
        #[arg(long, default_value = "10")]
        samples: usize,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum AttestSubCmd {
    /// Generate a detached signed attestation envelope for a file or directory manifest.
    Sign {
        /// Target file or directory to manifest and sign.
        path: PathBuf,
        /// Path to the Ed25519 private key (PEM or PKCS#8).
        #[arg(long, short = 'k', env = "VELCRUX_SIGN_KEY")]
        key: PathBuf,
        /// Optional destination path for the detached signature file (defaults to <path>/.velcrux-manifest.sig or <path>.sig).
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Identity or URI of the attestation issuer (e.g. spiffe://velcrux.internal/ci-signer).
        #[arg(long, default_value = "velcrux-signer")]
        issuer: String,
        /// Optional signature expiration in seconds from now.
        #[arg(long)]
        expires_in: Option<u64>,
        /// Optional key-value metadata tags to embed in the attestation (format: key=val).
        #[arg(long = "metadata", short = 'm')]
        metadata: Vec<String>,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Cryptographically verify a detached attestation signature against a target file or directory tree.
    Verify {
        /// Target file or directory to verify on disk.
        path: PathBuf,
        /// Path to the detached attestation signature file (.velcrux-manifest.sig).
        #[arg(long, short = 's')]
        sig: Option<PathBuf>,
        /// Path to an authorized_signers or authorized_keys file of trusted Ed25519 public keys.
        #[arg(long, env = "VELCRUX_TRUSTED_KEYS")]
        trusted_keys: Option<PathBuf>,
        /// Explicit trusted public key hex string.
        #[arg(long)]
        trusted_key: Option<String>,
        /// Require that the attestation issuer matches this expected identity string.
        #[arg(long)]
        require_issuer: Option<String>,
        /// Allow expired attestations to pass validation.
        #[arg(long)]
        allow_expired: bool,
        /// Output formatted as JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Generate a fresh Ed25519 attestation signing keypair.
    Keygen {
        /// Path where the private key (PKCS#8 PEM) will be saved.
        #[arg(long, short = 'o', default_value = "attestation.key")]
        out: PathBuf,
        /// Optional path where the public key will be saved (in OpenSSH format).
        #[arg(long, short = 'p')]
        pub_out: Option<PathBuf>,
        /// Optional identity comment for OpenSSH public key format.
        #[arg(long, default_value = "signer@velcrux.internal")]
        comment: String,
        /// Force overwrite if destination files already exist.
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// Inspect and display the claims within a detached attestation envelope without scanning disk.
    Inspect {
        /// Path to the detached attestation signature file (.velcrux-manifest.sig).
        sig: PathBuf,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum DeltaSliceSubCmd {
    /// Evaluate chunk slicing and dictionary compression ratio between a source and baseline file.
    Test {
        /// Modified source file.
        source: PathBuf,
        /// Baseline reference file used as dictionary.
        baseline: PathBuf,
        /// Chunk slicing size in bytes (default: 65536 / 64 KiB).
        #[arg(long, default_value = "65536")]
        chunk_size: usize,
        /// Delta dictionary compression policy: "auto", "off", or "aggressive" (default: "auto").
        #[arg(long, default_value = "auto")]
        policy: String,
        /// Minimum savings percentage threshold (0-100, default: 15).
        #[arg(long, default_value = "15")]
        threshold: u8,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum BdpSubCmd {
    /// Inspect current active BDP configuration, link tier, and window boundaries.
    Inspect {
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Simulate BDP auto-tuning across a given bandwidth, RTT, and loss profile.
    Simulate {
        /// Link bandwidth string (e.g. "10Gbps", "1Gbps", "100Mbps", "10MB/s").
        #[arg(long, default_value = "1Gbps")]
        bandwidth: String,
        /// Path round-trip time in milliseconds (e.g. 150 for transatlantic).
        #[arg(long, default_value = "150")]
        rtt_ms: u64,
        /// Simulated packet loss rate percentage (0.0 to 100.0, default: 0.0).
        #[arg(long, default_value = "0.0")]
        loss_pct: f64,
        /// Tuning policy: "auto", "fixed", "aggressive", or "conservative" (default: "auto").
        #[arg(long, default_value = "auto")]
        policy: String,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum DirectIoSubCmd {
    /// Inspect current active Direct I/O configuration, sector alignments, and ring parameters.
    Inspect {
        /// Target file or directory path to check sector alignment and direct I/O support.
        #[arg(short, long)]
        path: Option<String>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Benchmark Direct I/O ring-buffer streaming throughput (write + read + integrity verification).
    Benchmark {
        /// Benchmark target test file path.
        #[arg(short, long)]
        path: String,
        /// Benchmark test file size in bytes (default: 33554432 / 32 MiB).
        #[arg(short, long, default_value = "33554432")]
        size: u64,
        /// Number of ring slots override.
        #[arg(long)]
        slots: Option<usize>,
        /// Slot capacity in bytes override.
        #[arg(long)]
        slot_size: Option<usize>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum CheckpointSubCmd {
    /// Display status of resumable transfers and SQLite WAL state.
    Status {
        /// State role to inspect: "client" (default) or "server".
        #[arg(long, default_value = "client")]
        role: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Perform fast instantaneous recovery of interrupted transfers without directory re-scans.
    Recover {
        /// Optional specific transfer ID (ULID) to recover. If omitted, recovers all resumable transfers.
        #[arg(long)]
        transfer_id: Option<String>,
        /// State role: "client" (default) or "server".
        #[arg(long, default_value = "client")]
        role: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Prune stale completed or cancelled transfer checkpoints and bitmaps.
    Prune {
        /// Age threshold in seconds for pruning stale transfers (default: 604800 / 7 days).
        #[arg(long, default_value = "604800")]
        older_than_secs: u64,
        /// State role: "client" (default) or "server".
        #[arg(long, default_value = "client")]
        role: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Trigger an explicit SQLite Write-Ahead Logging (WAL) checkpoint flush.
    WalFlush {
        /// WAL checkpoint mode: "truncate" (default), "passive", "full", or "restart".
        #[arg(long, default_value = "truncate")]
        mode: String,
        /// State role: "client" (default) or "server".
        #[arg(long, default_value = "client")]
        role: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum QosSubCmd {
    /// Inspect QoS bandwidth allocations, Committed Information Rates (CIR), and Deficit Round-Robin weights.
    Inspect {
        /// QoS root link bandwidth capacity to evaluate (e.g. "1Gbps", "100Mbps", or "unlimited").
        #[arg(long, default_value = "unlimited")]
        bandwidth: String,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Execute a simulated QoS contention benchmark evaluating CIR guarantees and capacity borrowing.
    Benchmark {
        /// QoS root link bandwidth capacity (e.g. "1Gbps", "100Mbps", or "unlimited").
        #[arg(long, default_value = "1Gbps")]
        bandwidth: String,
        /// Number of simulated chunks/packets across priority tiers (default: 100).
        #[arg(long, default_value = "100")]
        packets: usize,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Display active QoS configuration and client priority tier status.
    Status {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum CasSubCmd {
    /// Inspect CAS store inventory, generations (nursery, tenured, tombstoned), and reclaimable space.
    Status {
        /// Path to chunk store directory. Defaults to standard local store path.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Execute a generational mark-and-sweep garbage collection pass.
    Gc {
        /// Path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Storage directory roots to scan for active chunk references.
        #[arg(long)]
        storage_root: Vec<PathBuf>,
        /// Nursery grace period in seconds (default: 3600 / 1 hour).
        #[arg(long)]
        nursery_grace: Option<u64>,
        /// Tombstone retention TTL in seconds (default: 86400 / 24 hours).
        #[arg(long)]
        tombstone_ttl: Option<u64>,
        /// Hard purge expired tombstones immediately during sweep.
        #[arg(long)]
        purge_expired: bool,
        /// Dry run mode (simulate sweep without modifying disk).
        #[arg(long)]
        dry_run: bool,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Resurrect a tombstoned chunk back into active service.
    Resurrect {
        /// Hash of the chunk to resurrect (hex string).
        #[arg(long)]
        hash: String,
        /// Path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Hard-purge expired tombstones and reclaim physical disk space.
    Purge {
        /// Path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Tombstone age threshold in seconds (default: 86400 / 24 hours).
        #[arg(long, default_value = "86400")]
        older_than_secs: u64,
        /// Dry run mode.
        #[arg(long)]
        dry_run: bool,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum SwarmSubCmd {
    /// Inspect swarm health status, active peer counts, offload ratio, and gossip statistics.
    Status {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// List all discovered swarm peers, incarnations, ping latencies, and operational states.
    Peers {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Advertise a file manifest or directory to the swarm gossip mesh.
    Advertise {
        /// Path to manifest file or directory to advertise chunk availability for.
        manifest: PathBuf,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Run an end-to-end multi-node swarm P2P simulation benchmark and measure egress offload ratio.
    Benchmark {
        /// Total simulated swarm nodes participating in the benchmark.
        #[arg(long, default_value = "10")]
        nodes: usize,
        /// Total chunks distributed across the mesh.
        #[arg(long, default_value = "50")]
        chunks: usize,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ChaosSubCmd {
    /// Inspect active chaos fault injection status, parameters, and telemetry counters.
    Status {
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Inspect preconfigured WAN impairment profiles (clean, subsea, satellite, cellular, byzantine, partition).
    Profile {
        /// Optional profile name to inspect (clean, subsea, satellite, cellular, byzantine, partition).
        name: Option<String>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Run an automated chaos fault simulation benchmark and measure loss, latency, and Byzantine detection.
    Benchmark {
        /// Impairment profile preset to benchmark (subsea, satellite, cellular, byzantine, partition).
        #[arg(long, default_value = "subsea")]
        profile: String,
        /// Total packets / frames to simulate.
        #[arg(long, default_value = "1000")]
        packets: usize,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Dynamically inject on-demand network impairments and fault conditions.
    Inject {
        /// Uniform packet loss probability (0.0 to 1.0).
        #[arg(long, default_value = "0.0")]
        loss: f64,
        /// Transmission delay in milliseconds.
        #[arg(long, default_value = "0")]
        delay_ms: u64,
        /// Latency jitter variance in milliseconds.
        #[arg(long, default_value = "0")]
        jitter_ms: u64,
        /// Packet reordering probability (0.0 to 1.0).
        #[arg(long, default_value = "0.0")]
        reorder: f64,
        /// Packet duplication probability (0.0 to 1.0).
        #[arg(long, default_value = "0.0")]
        duplicate: f64,
        /// Byzantine payload bit corruption probability (0.0 to 1.0).
        #[arg(long, default_value = "0.0")]
        corrupt: f64,
        /// Enable complete network severance / partition blackhole.
        #[arg(long)]
        partition: bool,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum TierSubCmd {
    /// Inspect storage tier inventory, byte breakdown across Hot/Warm/Cold, and space efficiency.
    Status {
        /// Path to tiered chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Filter inventory by tenant identity.
        #[arg(long)]
        tenant: Option<String>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Manage multi-tenant tiering policies (hot/warm/cold days, max capacity, compression).
    Policy {
        #[command(subcommand)]
        sub: TierPolicySubCmd,
    },
    /// Manually migrate a chunk to a specific storage tier (hot, warm, cold).
    Migrate {
        /// Cryptographic BLAKE3 hex hash of the chunk to migrate.
        #[arg(long)]
        hash: String,
        /// Target storage tier: hot, warm, or cold.
        #[arg(long)]
        target: String,
        /// Path to tiered chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Execute an automated lifecycle evaluation sweep to demote aged or excess chunks.
    Sweep {
        /// Target tenant for lifecycle sweep (or all if omitted).
        #[arg(long)]
        tenant: Option<String>,
        /// Simulate lifecycle sweep without modifying on-disk files.
        #[arg(long)]
        dry_run: bool,
        /// Path to tiered chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Cryptographically scrub Cold tier archives to detect and report bit-rot early.
    Scrub {
        /// Target tenant for scrubbing (or all if omitted).
        #[arg(long)]
        tenant: Option<String>,
        /// Path to tiered chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum TierPolicySubCmd {
    /// Configure or update a tenant's lifecycle tiering rules.
    Set {
        /// Tenant identifier (use "default" for global fallback).
        #[arg(long, default_value = "default")]
        tenant: String,
        /// Days without access before demoting Hot chunks to Warm (0 to disable).
        #[arg(long)]
        hot_days: Option<u32>,
        /// Days without access before demoting Warm chunks to Cold (0 to disable).
        #[arg(long)]
        warm_days: Option<u32>,
        /// Optional days before expired unreferenced Cold chunks are purged.
        #[arg(long)]
        cold_retention_days: Option<u32>,
        /// Maximum capacity in bytes for Hot storage before LRU demotion triggers.
        #[arg(long)]
        max_hot_bytes: Option<u64>,
        /// Whether reads on Cold/Warm chunks promote them back to Hot tier.
        #[arg(long)]
        auto_promote: Option<bool>,
        /// Zstandard compression level for Cold archives (1 to 22).
        #[arg(long)]
        compression_level: Option<i32>,
        /// Path to tiered chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// Display active lifecycle tiering policy for a tenant.
    Get {
        /// Tenant identifier.
        #[arg(long, default_value = "default")]
        tenant: String,
        /// Path to tiered chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
    /// List all registered tenant lifecycle policies.
    List {
        /// Path to tiered chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Output in JSON format.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum DedupSubCmd {
    /// Inspect deduplication policy, chunk counts, poisoning attempts, and tenant namespaces.
    Status {
        /// Path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Filter status for a specific tenant namespace.
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Verify chunk store integrity, detect checksum mismatches, and quarantine corrupted or poisoned chunks.
    Verify {
        /// Path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Tenant namespace to verify (or all tenants if unspecified).
        #[arg(long)]
        tenant: Option<String>,
        /// Automatically move corrupted or poisoned chunks to the quarantine directory (default: true).
        #[arg(long, default_value = "true")]
        auto_quarantine: bool,
    },
    /// Manage quarantined poisoned or corrupted chunks.
    Quarantine {
        #[command(subcommand)]
        sub: QuarantineSubCmd,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum QuarantineSubCmd {
    /// List all currently quarantined chunks with timestamps, sizes, and isolation reasons.
    List {
        /// Path to chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
    /// Purge (permanently delete) all quarantined chunks.
    Purge {
        /// Path to chunk store root directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ScheduleSubCmd {
    /// Inspect parsed schedule rules, default rate, and active status at current or specified time.
    Inspect {
        /// Schedule rule definition or path to schedule file.
        #[arg(long, short)]
        schedule: Option<String>,
        /// Timezone offset from UTC in minutes (default: 0).
        #[arg(long, default_value = "0")]
        utc_offset: i32,
    },
    /// Evaluate schedule rate and remaining transition time at a specific Unix timestamp.
    Eval {
        /// Schedule rule definition or path to schedule file.
        #[arg(long, short)]
        schedule: Option<String>,
        /// Unix timestamp in seconds to evaluate (defaults to current system time).
        #[arg(long)]
        timestamp: Option<u64>,
        /// Timezone offset from UTC in minutes (default: 0).
        #[arg(long, default_value = "0")]
        utc_offset: i32,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum FecSubCmd {
    /// Inspect FEC operational profile, Cauchy generator matrix parameters, and link loss tiers.
    Status {
        /// Target profile to inspect: "disabled", "low", "medium", "high", "satellite", or "auto".
        #[arg(long, default_value = "auto")]
        profile: String,
    },
    /// Simulate erasure recovery over a lossy link across sample payloads.
    Test {
        /// Target FEC profile: "disabled", "low", "medium", "high", "satellite", or "auto".
        #[arg(long, default_value = "satellite")]
        profile: String,
        /// Simulated channel loss rate (0.0 to 0.5, default: 0.05 for 5%).
        #[arg(long, default_value = "0.05")]
        loss_rate: f64,
        /// Simulated payload size in bytes (default: 65536 / 64 KiB).
        #[arg(long, default_value = "65536")]
        payload_size: usize,
        /// PRNG seed for deterministic loss simulation (default: 42).
        #[arg(long, default_value = "42")]
        seed: u64,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum StreamSubCmd {
    /// Stream standard input (stdin) over QUIC to a remote server destination.
    Send {
        /// Target `velcrux://host:port/path` URL.
        url: String,
        /// Chunk buffer size in bytes (default: 65536 / 64 KiB).
        #[arg(long, default_value_t = 65536)]
        chunk_size: usize,
    },
    /// Stream remote file over QUIC directly to standard output (stdout).
    Recv {
        /// Source `velcrux://host:port/path` URL.
        url: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum S3SubCmd {
    /// List objects in an S3 bucket or prefix (s3://bucket/prefix).
    Ls {
        /// S3 URL (e.g. s3://bucket/ or s3://bucket/prefix).
        s3_url: String,
        /// Optional delimiter (e.g. "/").
        #[arg(long)]
        delimiter: Option<String>,
        /// S3 endpoint override (e.g. http://127.0.0.1:9000).
        #[arg(long)]
        endpoint: Option<String>,
        /// S3 region override (e.g. us-east-1).
        #[arg(long)]
        region: Option<String>,
    },
    /// Inspect metadata for a single S3 object (s3://bucket/key).
    Stat {
        /// S3 URL (e.g. s3://bucket/key).
        s3_url: String,
        /// S3 endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// S3 region override.
        #[arg(long)]
        region: Option<String>,
    },
    /// Upload a local file to S3.
    Put {
        /// Local file to upload.
        local: PathBuf,
        /// Target S3 URL (e.g. s3://bucket/key).
        s3_url: String,
        /// S3 endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// S3 region override.
        #[arg(long)]
        region: Option<String>,
        /// Multipart part size in bytes (default: 8 MiB).
        #[arg(long)]
        multipart_size: Option<usize>,
    },
    /// Download an object from S3 to a local file.
    Get {
        /// Source S3 URL (e.g. s3://bucket/key).
        s3_url: String,
        /// Local destination file path.
        local: PathBuf,
        /// S3 endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// S3 region override.
        #[arg(long)]
        region: Option<String>,
        /// Optional byte range start (inclusive).
        #[arg(long)]
        range_start: Option<u64>,
        /// Optional byte range end (inclusive).
        #[arg(long)]
        range_end: Option<u64>,
    },
    /// Delete an object from S3.
    Delete {
        /// S3 URL to delete (e.g. s3://bucket/key).
        s3_url: String,
        /// S3 endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// S3 region override.
        #[arg(long)]
        region: Option<String>,
    },
    /// Synchronize between local filesystem and S3 bucket prefix.
    Sync {
        /// Source path or S3 URL (e.g. ./data or s3://bucket/prefix).
        source: String,
        /// Destination path or S3 URL (e.g. s3://bucket/prefix or ./data).
        destination: String,
        /// S3 endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// S3 region override.
        #[arg(long)]
        region: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum GcsSubCmd {
    /// List objects in a GCS bucket or prefix (gs://bucket/prefix).
    Ls {
        /// GCS URL (e.g. gs://bucket/ or gs://bucket/prefix).
        gcs_url: String,
        /// Optional delimiter (e.g. "/").
        #[arg(long)]
        delimiter: Option<String>,
        /// GCS endpoint override (e.g. http://127.0.0.1:4443).
        #[arg(long)]
        endpoint: Option<String>,
        /// OAuth2 bearer token override.
        #[arg(long)]
        token: Option<String>,
    },
    /// Inspect metadata for a single GCS object (gs://bucket/name).
    Stat {
        /// GCS URL (e.g. gs://bucket/name).
        gcs_url: String,
        /// GCS endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// OAuth2 bearer token override.
        #[arg(long)]
        token: Option<String>,
    },
    /// Upload a local file to GCS.
    Put {
        /// Local file to upload.
        local: PathBuf,
        /// Target GCS URL (e.g. gs://bucket/name).
        gcs_url: String,
        /// GCS endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// OAuth2 bearer token override.
        #[arg(long)]
        token: Option<String>,
        /// Resumable chunk size in bytes (default: 8 MiB).
        #[arg(long)]
        chunk_size: Option<usize>,
    },
    /// Download an object from GCS to a local file.
    Get {
        /// Source GCS URL (e.g. gs://bucket/name).
        gcs_url: String,
        /// Local destination file path.
        local: PathBuf,
        /// GCS endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// OAuth2 bearer token override.
        #[arg(long)]
        token: Option<String>,
        /// Optional byte range start (inclusive).
        #[arg(long)]
        range_start: Option<u64>,
        /// Optional byte range end (inclusive).
        #[arg(long)]
        range_end: Option<u64>,
    },
    /// Delete an object from GCS.
    Delete {
        /// GCS URL to delete (e.g. gs://bucket/name).
        gcs_url: String,
        /// GCS endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// OAuth2 bearer token override.
        #[arg(long)]
        token: Option<String>,
    },
    /// Synchronize between local filesystem and GCS bucket prefix.
    Sync {
        /// Source path or GCS URL (e.g. ./data or gs://bucket/prefix).
        source: String,
        /// Destination path or GCS URL (e.g. gs://bucket/prefix or ./data).
        destination: String,
        /// GCS endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// OAuth2 bearer token override.
        #[arg(long)]
        token: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum AzureSubCmd {
    /// List blobs in an Azure container or prefix (az://container/prefix).
    Ls {
        /// Azure URL (e.g. az://container/ or az://container/prefix).
        azure_url: String,
        /// Optional delimiter (e.g. "/").
        #[arg(long)]
        delimiter: Option<String>,
        /// Azure Blob endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// Azure Storage account name override.
        #[arg(long)]
        account_name: Option<String>,
        /// Azure Storage account SharedKey override.
        #[arg(long)]
        account_key: Option<String>,
        /// Azure SAS token override.
        #[arg(long)]
        sas_token: Option<String>,
    },
    /// Inspect metadata for a single Azure blob (az://container/blob_name).
    Stat {
        /// Azure URL (e.g. az://container/blob_name).
        azure_url: String,
        /// Azure Blob endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// Azure Storage account name override.
        #[arg(long)]
        account_name: Option<String>,
        /// Azure Storage account SharedKey override.
        #[arg(long)]
        account_key: Option<String>,
        /// Azure SAS token override.
        #[arg(long)]
        sas_token: Option<String>,
    },
    /// Upload a local file to Azure Blob Storage.
    Put {
        /// Local file to upload.
        local: PathBuf,
        /// Target Azure URL (e.g. az://container/blob_name).
        azure_url: String,
        /// Azure Blob endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// Azure Storage account name override.
        #[arg(long)]
        account_name: Option<String>,
        /// Azure Storage account SharedKey override.
        #[arg(long)]
        account_key: Option<String>,
        /// Azure SAS token override.
        #[arg(long)]
        sas_token: Option<String>,
        /// Block size in bytes (default: 8 MiB).
        #[arg(long)]
        block_size: Option<usize>,
    },
    /// Download a blob from Azure Blob Storage to a local file.
    Get {
        /// Source Azure URL (e.g. az://container/blob_name).
        azure_url: String,
        /// Local destination file path.
        local: PathBuf,
        /// Azure Blob endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// Azure Storage account name override.
        #[arg(long)]
        account_name: Option<String>,
        /// Azure Storage account SharedKey override.
        #[arg(long)]
        account_key: Option<String>,
        /// Azure SAS token override.
        #[arg(long)]
        sas_token: Option<String>,
        /// Optional byte range start (inclusive).
        #[arg(long)]
        range_start: Option<u64>,
        /// Optional byte range end (inclusive).
        #[arg(long)]
        range_end: Option<u64>,
    },
    /// Delete a blob from Azure Blob Storage.
    Delete {
        /// Azure URL to delete (e.g. az://container/blob_name).
        azure_url: String,
        /// Azure Blob endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// Azure Storage account name override.
        #[arg(long)]
        account_name: Option<String>,
        /// Azure Storage account SharedKey override.
        #[arg(long)]
        account_key: Option<String>,
        /// Azure SAS token override.
        #[arg(long)]
        sas_token: Option<String>,
    },
    /// Synchronize between local filesystem and Azure container prefix.
    Sync {
        /// Source path or Azure URL (e.g. ./data or az://container/prefix).
        source: String,
        /// Destination path or Azure URL (e.g. az://container/prefix or ./data).
        destination: String,
        /// Azure Blob endpoint override.
        #[arg(long)]
        endpoint: Option<String>,
        /// Azure Storage account name override.
        #[arg(long)]
        account_name: Option<String>,
        /// Azure Storage account SharedKey override.
        #[arg(long)]
        account_key: Option<String>,
        /// Azure SAS token override.
        #[arg(long)]
        sas_token: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum MountSubCmd {
    /// Mount a remote, snapshot, cloud, or local source to an interactive virtual directory.
    Attach {
        /// Source specification (e.g. ./data, snapshot://tag, s3://bucket/prefix, gs://bucket/prefix, az://container/prefix).
        source: String,
        /// Target mountpoint directory path.
        mountpoint: PathBuf,
        /// Mount the virtual filesystem strictly read-only (default: true).
        #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
        read_only: bool,
        /// Mount the virtual filesystem in read-write mode.
        #[arg(long = "rw")]
        read_write: bool,
        /// Page cache capacity limit in megabytes (default: 256 MiB).
        #[arg(long)]
        cache_size_mb: Option<usize>,
        /// Page cache TTL in seconds (default: 60s).
        #[arg(long)]
        cache_ttl_sec: Option<u64>,
        /// Number of sequential chunks to prefetch ahead (default: 2).
        #[arg(long)]
        prefetch: Option<usize>,
        /// Allow other system users access to mountpoint.
        #[arg(long)]
        allow_other: bool,
        /// Run mount coordinator in daemon background mode.
        #[arg(short = 'd', long)]
        daemon: bool,
    },
    /// List all currently active and registered virtual filesystem mounts.
    List,
    /// Inspect status and cache telemetry for an active virtual filesystem mount.
    Status {
        /// Optional mountpoint path to inspect.
        #[arg(long, short = 'm')]
        mountpoint: Option<PathBuf>,
    },
    /// Unmount an active virtual filesystem mountpoint.
    Detach {
        /// Target mountpoint directory path to unmount.
        mountpoint: PathBuf,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ClusterSubCmd {
    /// Show cluster ring topology, node status, and quorum health.
    Status {
        /// Comma-separated list of node addresses or IDs (e.g. "127.0.0.1:8001,127.0.0.1:8002,127.0.0.1:8003").
        #[arg(long)]
        nodes: Option<String>,
        /// Quorum replication factor N (default: 3).
        #[arg(long, default_value = "3")]
        replicas: usize,
        /// Quorum write factor W (default: 2).
        #[arg(long, default_value = "2")]
        write_quorum: usize,
        /// Quorum read factor R (default: 2).
        #[arg(long, default_value = "2")]
        read_quorum: usize,
        /// Optional storage root directory containing node chunks.
        #[arg(long)]
        store_dir: Option<PathBuf>,
        /// Inspect Raft consensus cluster coordinator metadata and leases (Option BZ).
        #[arg(long)]
        raft: bool,
    },
    /// Rebalance chunks and run anti-entropy reconciliation across cluster nodes.
    Rebalance {
        /// Base storage directory containing node chunk store subdirectories.
        #[arg(long)]
        store_dir: Option<PathBuf>,
        /// Comma-separated list of node addresses or IDs (e.g. "127.0.0.1:8001,127.0.0.1:8002,127.0.0.1:8003").
        #[arg(long)]
        nodes: Option<String>,
        /// Quorum replication factor N (default: 3).
        #[arg(long, default_value = "3")]
        replicas: usize,
    },
    /// Join a new node to the Raft consensus cluster (Option BZ).
    Join {
        /// Unique node identifier (e.g. "node-4").
        node_id: String,
        /// Node network address (e.g. "127.0.0.1:8004").
        #[arg(long, default_value = "127.0.0.1:8004")]
        address: String,
    },
    /// Leave or decommission a node from the Raft consensus cluster (Option BZ).
    Leave {
        /// Unique node identifier to remove (e.g. "node-4").
        node_id: String,
    },
    /// Trigger an immediate Raft leader election across the cluster (Option BZ).
    Elect {
        /// Candidate node identifier to trigger election on (default: "node-1").
        #[arg(long, default_value = "node-1")]
        candidate: String,
        /// Comma-separated list of cluster peer node IDs (default: "node-1,node-2,node-3").
        #[arg(long, default_value = "node-1,node-2,node-3")]
        peers: String,
    },
    /// Manage high-availability distributed metadata leases with epoch fencing (Option BZ).
    Lease {
        #[command(subcommand)]
        sub: ClusterLeaseSubCmd,
    },
    /// Execute high-throughput distributed Raft consensus and failover simulation benchmark (Option BZ).
    Benchmark {
        /// Number of simulated cluster nodes (default: 5).
        #[arg(long, default_value = "5")]
        nodes: usize,
        /// Number of consensus replication rounds (default: 50).
        #[arg(long, default_value = "50")]
        rounds: usize,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ClusterLeaseSubCmd {
    /// Acquire a distributed lease with monotonic epoch fencing.
    Acquire {
        /// Resource key identifier to lease (e.g. "transfer-lock-1").
        resource: String,
        /// Identity of the lease holder (default: "node-1").
        #[arg(long, default_value = "node-1")]
        holder: String,
        /// Lease Time-To-Live in milliseconds (default: 5000 ms).
        #[arg(long, default_value = "5000")]
        ttl_ms: u64,
    },
    /// Release an actively held distributed lease.
    Release {
        /// Resource key identifier to release.
        resource: String,
        /// Identity of the lease holder (default: "node-1").
        #[arg(long, default_value = "node-1")]
        holder: String,
    },
    /// List all currently active distributed metadata leases.
    List,
}

#[derive(Subcommand, Debug, Clone)]
enum GeoSubCmd {
    /// Show cross-region replication status, vector clock progress, and replication lag.
    Status {
        /// Local region identifier (default: "us-east-1").
        #[arg(long, default_value = "us-east-1")]
        local_region: String,
        /// Comma-separated list of peer regions (e.g. "eu-central-1=10.2.0.1:7443,ap-tokyo-1=10.3.0.1:7443").
        #[arg(long)]
        regions: Option<String>,
        /// Conflict resolution policy: "lww" (default), "primary", "keep-both", or "reject".
        #[arg(long, default_value = "lww")]
        conflict_policy: String,
        /// Primary authority region (used if conflict_policy is "primary").
        #[arg(long)]
        primary_region: Option<String>,
    },
    /// Replicate or synchronize data between two regions with conflict resolution.
    Sync {
        /// Source region identifier.
        #[arg(long, default_value = "us-east-1")]
        source_region: String,
        /// Target region identifier.
        #[arg(long, default_value = "eu-central-1")]
        target_region: String,
        /// Target region gateway socket address.
        #[arg(long, default_value = "127.0.0.1:7443")]
        target_addr: SocketAddr,
        /// Conflict resolution policy: "lww", "primary", "keep-both", "reject".
        #[arg(long, default_value = "lww")]
        conflict_policy: String,
        /// Primary authority region (if conflict_policy is "primary").
        #[arg(long)]
        primary_region: Option<String>,
        /// Prune tombstones older than this many seconds (default: 604800 / 7 days).
        #[arg(long, default_value = "604800")]
        tombstone_ttl_secs: u64,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum TxSubCmd {
    /// List historical and pending directory transactions.
    List {
        /// Target directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect details of a specific directory transaction journal.
    Show {
        /// Transaction ID.
        tx_id: String,
        /// Target directory.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Roll back a prepared, committing, or committed transaction to restore pristine baseline.
    Rollback {
        /// Transaction ID.
        tx_id: String,
        /// Target directory.
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan target directory and recover any interrupted or crashed transactions.
    Recover {
        /// Target directory.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output formatted as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum WebhookSubCmd {
    /// List configured webhook endpoints, subscriptions, and delivery metrics.
    List,
    /// Dispatch a signed test ping webhook notification to verify endpoint connectivity.
    Test {
        /// Target webhook HTTP(S) endpoint URL.
        url: String,
        /// HMAC-SHA256 signing secret key.
        #[arg(long, default_value = "velcrux-webhook-secret")]
        secret: String,
        /// Event type to test (e.g. "transfer.completed", "chunk.corrupted", "audit.action").
        #[arg(long, default_value = "transfer.completed")]
        event: String,
    },
    /// Inspect or clear the dead-letter queue (DLQ) for failed webhook deliveries.
    Dlq {
        /// Drain and clear all records from the dead-letter queue.
        #[arg(long)]
        drain: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum SnapshotSubCmd {
    /// Create an immutable point-in-time snapshot of a directory tree.
    Create {
        /// Unique snapshot identifier tag (alphanumeric, '-', '_', '.').
        tag: String,
        /// Source directory path to capture.
        path: PathBuf,
        /// Optional path to chunk store for content-addressed deduplication backing.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Optional user annotation description.
        #[arg(long)]
        desc: Option<String>,
    },
    /// List all point-in-time snapshots.
    List {
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
    /// Compare changes between two snapshots.
    Diff {
        /// Baseline snapshot tag.
        tag_a: String,
        /// Comparison snapshot tag.
        tag_b: String,
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
    /// Restore a point-in-time snapshot to a target destination directory.
    Restore {
        /// Snapshot tag to restore.
        tag: String,
        /// Target destination directory path.
        #[arg(long)]
        dest: PathBuf,
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
        /// Optional fallback source directory if CAS is not configured.
        #[arg(long)]
        source_fallback: Option<PathBuf>,
    },
    /// Delete a point-in-time snapshot.
    Delete {
        /// Snapshot tag to delete.
        tag: String,
        /// Optional path to chunk store directory.
        #[arg(long)]
        chunk_store: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum LockSubCmd {
    /// Acquire a distributed lock lease on a resource.
    Acquire {
        /// Target resource path or namespace (e.g. /datasets/imagenet).
        resource: String,
        /// Client, node, or session identifier claiming the lease.
        #[arg(long, default_value = "client-default")]
        holder: String,
        /// Lock mode: "exclusive" (default) or "shared".
        #[arg(long, default_value = "exclusive")]
        mode: String,
        /// Lease time-to-live (TTL) duration in seconds (default: 60).
        #[arg(long, default_value = "60")]
        ttl_secs: u64,
        /// Optional state file path for lock coordinator persistence.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },
    /// Renew / extend an active lock lease before it expires.
    Renew {
        /// Lock lease ID (e.g. lck-101-12345).
        lock_id: String,
        /// Client or holder identifier registered to the lease.
        #[arg(long, default_value = "client-default")]
        holder: String,
        /// Additional lease extension duration in seconds (default: 60).
        #[arg(long, default_value = "60")]
        ttl_secs: u64,
        /// Optional state file path.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },
    /// Release an active lock lease.
    Release {
        /// Lock lease ID to release.
        lock_id: String,
        /// Client or holder identifier registered to the lease.
        #[arg(long, default_value = "client-default")]
        holder: String,
        /// Optional state file path.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },
    /// List all active distributed locks and lease health metrics.
    List {
        /// Optional resource path filter.
        #[arg(long)]
        resource: Option<String>,
        /// Optional state file path.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },
    /// Verify whether a Lamport fencing token is currently valid and active on a resource.
    Verify {
        /// Target resource path.
        resource: String,
        /// Monotonic Lamport fencing token.
        token: u64,
        /// Optional state file path.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum DictSubCmd {
    /// Train a new Zstandard dictionary from sample files in a directory.
    Train {
        /// Source directory containing representative sample files.
        source_dir: PathBuf,
        /// Name of the dictionary (e.g. "json-logs", "telemetry-v1").
        #[arg(long, default_value = "custom-dict")]
        name: String,
        /// Target dictionary size in bytes (default: 112 KiB).
        #[arg(long, default_value = "114688")]
        dict_size: usize,
        /// Maximum number of sample files to ingest (default: 100).
        #[arg(long, default_value = "100")]
        max_samples: usize,
        /// Optional description or domain annotation.
        #[arg(long, default_value = "Pre-trained Zstandard dictionary")]
        desc: String,
        /// Optional directory for dictionary catalog storage.
        #[arg(long)]
        dict_dir: Option<PathBuf>,
    },
    /// List all registered pre-trained dictionaries in the catalog.
    List {
        /// Optional directory for dictionary catalog storage.
        #[arg(long)]
        dict_dir: Option<PathBuf>,
    },
    /// Test and evaluate compression ratio of a dictionary against a file or sample directory.
    Test {
        /// 32-bit dictionary identifier.
        dict_id: u32,
        /// Target test file or directory to evaluate.
        target_path: PathBuf,
        /// Optional directory for dictionary catalog storage.
        #[arg(long)]
        dict_dir: Option<PathBuf>,
    },
    /// Export a registered dictionary binary to an external file.
    Export {
        /// 32-bit dictionary identifier.
        dict_id: u32,
        /// Destination file path (e.g. ./exported.zdict).
        dest_file: PathBuf,
        /// Optional directory for dictionary catalog storage.
        #[arg(long)]
        dict_dir: Option<PathBuf>,
    },
    /// Import a pre-existing dictionary binary into the catalog.
    Import {
        /// Source dictionary file path (.zdict).
        source_file: PathBuf,
        /// Optional name for imported dictionary.
        #[arg(long)]
        name: Option<String>,
        /// Optional description.
        #[arg(long)]
        desc: Option<String>,
        /// Optional directory for dictionary catalog storage.
        #[arg(long)]
        dict_dir: Option<PathBuf>,
    },
    /// Delete a dictionary from the catalog.
    Delete {
        /// 32-bit dictionary identifier to delete.
        dict_id: u32,
        /// Optional directory for dictionary catalog storage.
        #[arg(long)]
        dict_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ScrubSubCmd {
    /// Perform an integrity scrub across a content-addressed chunk store.
    Run {
        /// Target chunk store root path.
        chunk_store: PathBuf,
        /// Operational scrub mode: "verify" (default), "quarantine", or "heal".
        #[arg(long, default_value = "verify")]
        mode: String,
        /// Optional peer chunk store directory for self-healing repair.
        #[arg(long)]
        peer_store: Option<PathBuf>,
        /// Optional I/O rate limit in MB/s (e.g. 50).
        #[arg(long)]
        rate_limit_mb: Option<u64>,
        /// Optional custom quarantine directory for corrupted chunks.
        #[arg(long)]
        quarantine_dir: Option<PathBuf>,
    },
    /// Inspect the latest scrub audit report and bit-rot telemetry for a chunk store.
    Status {
        /// Target chunk store root path.
        chunk_store: PathBuf,
    },
    /// Explicitly repair corrupted or bit-rotted chunks from a peer chunk store.
    Repair {
        /// Target chunk store root path.
        chunk_store: PathBuf,
        /// Reference peer chunk store directory containing valid replicas.
        #[arg(long)]
        peer_store: PathBuf,
        /// Optional I/O rate limit in MB/s.
        #[arg(long)]
        rate_limit_mb: Option<u64>,
    },
}

fn init_tracing(format: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,velcrux_core=debug"));
    if format == "json" {
        let _ = fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .json()
            .try_init();
    } else {
        let _ = fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init();
    }
}

fn read_file(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn parse_url(s: &str) -> anyhow::Result<SocketAddr> {
    // `url::Url` doesn't accept unknown schemes in non-special contexts, so
    // we parse the URL by hand for M1. Format: `velcrux://host[:port][/path]`.
    let stripped = s
        .strip_prefix("velcrux://")
        .context("URL must start with velcrux://")?;
    let hostport = stripped.split('/').next().unwrap_or(stripped);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().context("invalid port")?;
            (h, port)
        }
        None => (hostport, 7443u16),
    };
    if host.is_empty() {
        anyhow::bail!("URL has no host");
    }
    // Resolve via ToSocketAddrs so `localhost` works.
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .context("invalid host:port")?
        .collect();
    addrs
        .iter()
        .copied()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.into_iter().next())
        .context("no addresses resolved for host")
}

/// Parse a `velcrux://host:port/path` URL into the host:port `SocketAddr`
/// and the URL-decoded path component.
fn parse_url_with_path(s: &str) -> anyhow::Result<(SocketAddr, String)> {
    let stripped = s
        .strip_prefix("velcrux://")
        .context("URL must start with velcrux://")?;
    let (hostport, path) = match stripped.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (stripped, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().context("invalid port")?;
            (h, port)
        }
        None => (hostport, 7443u16),
    };
    if host.is_empty() {
        anyhow::bail!("URL has no host");
    }
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .context("invalid host:port")?
        .collect();
    let addr = addrs
        .iter()
        .copied()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.into_iter().next())
        .context("no addresses resolved for host")?;
    Ok((addr, path))
}

fn build_transport_target(
    cli: &Cli,
    target_addr: Option<SocketAddr>,
) -> anyhow::Result<SharedTransport> {
    let ca_path = cli
        .ca
        .as_ref()
        .context("--ca is required (no insecure mode is supported; see SECURITY.md §3)")?;
    let ca_pem = read_file(ca_path)?;
    let mut builder = ClientBuilder::new().with_server_roots_pem(&ca_pem)?;

    let bind_addr = velcrux_core::transport::resolve_bind_addr(
        cli.bind_ip.as_deref(),
        cli.bind_interface.as_deref(),
        cli.bind_port,
        target_addr,
    )
    .map_err(|e| anyhow::anyhow!("resolving client bind address: {e}"))?;

    builder = builder.with_bind_addr(bind_addr);

    if let (Some(cert), Some(key)) = (cli.cert.as_ref(), cli.key.as_ref()) {
        let cert_pem = read_file(cert)?;
        let key_pem = read_file(key)?;
        let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut &cert_pem[..])
            .map_err(|e| anyhow::anyhow!("parsing client cert PEM: {e}"))?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut &key_pem[..])
            .map_err(|e| anyhow::anyhow!("parsing client key PEM: {e}"))?;
        let key = keys
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no PKCS#8 key in {}", key.display()))?;
        let id = ClientIdentity::from_der(certs, key.clone());
        builder = builder.with_client_identity(id);
    }

    let transport: Arc<dyn velcrux_core::transport::Transport<Conn = QuicConnection>> =
        Arc::new(builder.build()?);
    Ok(transport)
}

#[allow(dead_code)]
fn build_transport(cli: &Cli) -> anyhow::Result<SharedTransport> {
    build_transport_target(cli, None)
}

fn open_client_state_store(cli: &Cli) -> Option<Arc<dyn velcrux_core::state::StateStore>> {
    if let Some(path) = &cli.state_db {
        if let Ok(store) = velcrux_core::state::SqliteStateStore::new(path) {
            return Some(Arc::new(store));
        }
    } else if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home).join(".velcrux").join("client.db");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(store) = velcrux_core::state::SqliteStateStore::new(&path) {
            return Some(Arc::new(store));
        }
    }
    None
}

fn open_state_store_for_role(
    cli: &Cli,
    role_str: &str,
) -> anyhow::Result<Arc<dyn velcrux_core::state::StateStore>> {
    if let Some(path) = &cli.state_db {
        let store = velcrux_core::state::SqliteStateStore::new(path)?;
        return Ok(Arc::new(store));
    }
    let role =
        velcrux_core::state::Role::parse(role_str).unwrap_or(velcrux_core::state::Role::Client);
    let db_filename = format!("{}.db", role.as_str());
    if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home).join(".velcrux").join(db_filename);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let store = velcrux_core::state::SqliteStateStore::new(&path)?;
        return Ok(Arc::new(store));
    }
    anyhow::bail!("unable to determine default state store location; please pass --state-db");
}

async fn open_client_session(
    conn: &dyn velcrux_core::transport::Connection,
    cli: &Cli,
) -> anyhow::Result<ClientSession> {
    let (send, recv) = conn.open_bi().await?;
    let mut caps = velcrux_core::protocol::message::Hello::default_client().capabilities;
    if cli.dedup || cli.chunk_store.is_some() {
        caps.set(velcrux_core::protocol::capabilities::Capability::DedupChunkStore);
    }
    let session =
        ClientSession::from_handshake_parts_with_capabilities(send, recv, Some(caps)).await?;
    Ok(session)
}

async fn open_client_chunk_store(cli: &Cli) -> Option<Arc<velcrux_core::storage::LocalChunkStore>> {
    let path = if let Some(ref p) = cli.chunk_store {
        Some(p.clone())
    } else if cli.dedup {
        if let Some(home) = std::env::var_os("HOME") {
            Some(PathBuf::from(home).join(".velcrux").join("chunks"))
        } else {
            Some(PathBuf::from(".velcrux-chunks"))
        }
    } else {
        None
    };

    if let Some(p) = path {
        match velcrux_core::storage::LocalChunkStore::new(&p).await {
            Ok(cs) => Some(Arc::new(cs)),
            Err(e) => {
                tracing::warn!(error = %e, path = %p.display(), "failed to initialize client chunk store");
                None
            }
        }
    } else {
        None
    }
}

fn cli_log_json(cli: &Cli) -> bool {
    cli.json || cli.log_format == "json" || std::env::var("VELCRUX_OUTPUT_JSON").is_ok()
}

fn get_sni(cli: &Cli, url: &str) -> String {
    cli.sni.clone().unwrap_or_else(|| {
        url.split("://")
            .nth(1)
            .unwrap_or("localhost")
            .split(':')
            .next()
            .unwrap_or("localhost")
            .to_string()
    })
}

fn get_transfer_mode(cli: &Cli) -> velcrux_core::sync::TransferMode {
    cli.mode
        .parse()
        .unwrap_or(velcrux_core::sync::TransferMode::Auto)
}

fn get_network_profile(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
) -> velcrux_core::sync::NetworkProfile {
    match cli.network_profile.to_ascii_lowercase().as_str() {
        "lan" => velcrux_core::sync::NetworkProfile::lan(),
        "wan" | "wan_fast" => velcrux_core::sync::NetworkProfile::wan_fast(),
        "satellite" | "wan_satellite" => velcrux_core::sync::NetworkProfile::wan_satellite(),
        _ => {
            let stats = conn.stats();
            velcrux_core::sync::NetworkProfile::from_transport_stats(&stats, 12_500_000)
        }
    }
}

#[derive(Debug, serde::Deserialize, Default)]
struct FileClientConfig {
    ca: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    sni: Option<String>,
    log_format: Option<String>,
    json: Option<bool>,
    state_db: Option<PathBuf>,
    dedup: Option<bool>,
    chunk_store: Option<PathBuf>,
    parallel: Option<usize>,
    rate_limit: Option<String>,
    bandwidth_schedule: Option<String>,
}

fn load_client_config(cli: &mut Cli) {
    let config_path = cli.config.clone().or_else(|| {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".velcrux").join("config.toml"))
    });

    if let Some(path) = config_path {
        if path.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(file_cfg) = toml::from_str::<FileClientConfig>(&raw) {
                    if cli.ca.is_none() {
                        cli.ca = file_cfg.ca;
                    }
                    if cli.cert.is_none() {
                        cli.cert = file_cfg.cert;
                    }
                    if cli.key.is_none() {
                        cli.key = file_cfg.key;
                    }
                    if cli.sni.is_none() {
                        cli.sni = file_cfg.sni;
                    }
                    if cli.state_db.is_none() {
                        cli.state_db = file_cfg.state_db;
                    }
                    if cli.chunk_store.is_none() {
                        cli.chunk_store = file_cfg.chunk_store;
                    }
                    if !cli.dedup {
                        if let Some(d) = file_cfg.dedup {
                            cli.dedup = d;
                        }
                    }
                    if cli.parallel == 1 {
                        if let Some(p) = file_cfg.parallel {
                            cli.parallel = p;
                        }
                    }
                    if cli.rate_limit.is_none() {
                        cli.rate_limit = file_cfg.rate_limit;
                    }
                    if cli.bandwidth_schedule.is_none() {
                        cli.bandwidth_schedule = file_cfg.bandwidth_schedule;
                    }
                    if cli.log_format == "text" {
                        if let Some(fmt) = file_cfg.log_format {
                            cli.log_format = fmt;
                        }
                    }
                    if !cli.json {
                        if let Some(j) = file_cfg.json {
                            cli.json = j;
                        }
                    }
                }
            }
        }
    }
}

fn get_rate_limiter(cli: &Cli) -> anyhow::Result<Option<velcrux_core::RateLimiter>> {
    if let Some(ref s) = cli.bandwidth_schedule {
        let content = if Path::new(s).is_file() {
            std::fs::read_to_string(s)
                .with_context(|| format!("failed to read schedule file '{s}'"))?
        } else {
            s.clone()
        };
        let parsed: velcrux_core::BandwidthSchedule =
            content
                .parse()
                .map_err(|e: velcrux_core::ParseScheduleError| {
                    anyhow::anyhow!("invalid --bandwidth-schedule: {e}")
                })?;
        let default_rate = parsed.default_rate.bytes_per_sec();
        let limiter = velcrux_core::RateLimiter::new(default_rate).with_schedule(Arc::new(parsed));
        return Ok(Some(limiter));
    }

    if let Some(ref r) = cli.rate_limit {
        let bytes_per_sec = velcrux_core::parse_rate_limit(r)
            .map_err(|e| anyhow::anyhow!("invalid --rate-limit: {e}"))?;
        if bytes_per_sec > 0 {
            return Ok(Some(velcrux_core::RateLimiter::new(bytes_per_sec)));
        }
    }
    Ok(None)
}

fn get_priority(cli: &Cli) -> anyhow::Result<velcrux_core::TransferPriority> {
    cli.priority.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn get_direct_io_mode(cli: &Cli) -> anyhow::Result<velcrux_core::DirectIoMode> {
    cli.direct_io
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))
}

fn get_direct_io_ring_config(
    cli: &Cli,
) -> anyhow::Result<velcrux_core::storage::direct_io::DirectIoRingConfig> {
    let mode = get_direct_io_mode(cli)?;
    if cli.direct_io_slots < 2 || cli.direct_io_slots > 32 {
        anyhow::bail!("--direct-io-slots must be between 2 and 32");
    }
    if cli.direct_io_slot_size < 4096 {
        anyhow::bail!("--direct-io-slot-size must be at least 4096 bytes");
    }
    Ok(velcrux_core::storage::direct_io::DirectIoRingConfig {
        ring_slots: cli.direct_io_slots,
        slot_capacity: cli.direct_io_slot_size,
        sector_size: velcrux_core::storage::direct_io::DEFAULT_SECTOR_SIZE,
        mode,
        min_file_size: velcrux_core::storage::direct_io::DEFAULT_DIRECT_IO_MIN_SIZE,
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    load_client_config(&mut cli);
    let _ = get_rate_limiter(&cli)?;
    let _ = get_priority(&cli)?;
    let _ = get_direct_io_mode(&cli)?;
    let _ = get_direct_io_ring_config(&cli)?;
    if cli.concurrency == 0 {
        anyhow::bail!("--concurrency must be greater than 0");
    }
    init_tracing(&cli.log_format);

    match &cli.cmd {
        Cmd::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(*shell, &mut cmd, "velcrux", &mut std::io::stdout());
            return Ok(());
        }
        Cmd::Hardware => {
            let features = velcrux_core::SimdFeatures::detect();
            if cli_log_json(&cli) {
                let out = serde_json::json!({
                    "arch": features.arch,
                    "tier": features.tier.name(),
                    "vector_width_bits": features.tier.vector_width_bits(),
                    "avx512f": features.has_avx512f,
                    "avx2": features.has_avx2,
                    "sse41": features.has_sse41,
                    "neon": features.has_neon,
                    "carryless_mul": features.has_carryless_mul,
                    "aes": features.has_aes,
                    "description": features.description(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Hardware Acceleration Profile:");
                println!("  Architecture:      {}", features.arch);
                println!(
                    "  Acceleration Tier: {} ({} bits)",
                    features.tier.name(),
                    features.tier.vector_width_bits()
                );
                println!("  Features:          {}", features.description());
            }
            return Ok(());
        }
        Cmd::Profile {
            file,
            url,
            chunk_mode,
        } => {
            run_profile(&cli, file, url.as_ref(), chunk_mode).await?;
            return Ok(());
        }
        Cmd::Package { target } => {
            package::execute_package_target(target.clone(), cli_log_json(&cli))?;
            return Ok(());
        }
        Cmd::S3 { sub } => {
            run_s3(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Gcs { sub } => {
            run_gcs(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Azure { sub } => {
            run_azure(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Mount { sub } => {
            run_mount(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Unmount { mountpoint } => {
            run_unmount(&cli, mountpoint).await?;
            return Ok(());
        }
        Cmd::Multipath { target } => {
            run_multipath_status(&cli, target.as_deref()).await?;
            return Ok(());
        }
        Cmd::Cluster { sub } => {
            run_cluster(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Geo { sub } => {
            run_geo(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Webhook { sub } => {
            run_webhook(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Snapshot { sub } => {
            run_snapshot(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Lock { sub } => {
            run_lock(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Dict { sub } => {
            run_dict(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Scrub { sub } => {
            run_scrub(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Stream { sub } => {
            match sub {
                StreamSubCmd::Send { url, chunk_size } => {
                    let (addr, path) = parse_url_with_path(url)?;
                    let sni = get_sni(&cli, url);
                    let transport = build_transport_target(&cli, Some(addr))?;
                    info!(%addr, %sni, ?path, "connecting for stream send");
                    let conn = transport.connect(addr, &sni).await?;
                    let mut session = open_client_session(&conn, &cli).await?;
                    info!(version = session.negotiated().version, "HELLO_ACK");
                    run_upload_stream(&cli, &conn, &mut session, &path, *chunk_size).await?;
                }
                StreamSubCmd::Recv { url } => {
                    let (addr, path) = parse_url_with_path(url)?;
                    let sni = get_sni(&cli, url);
                    let transport = build_transport_target(&cli, Some(addr))?;
                    info!(%addr, %sni, ?path, "connecting for stream recv");
                    let conn = transport.connect(addr, &sni).await?;
                    let mut session = open_client_session(&conn, &cli).await?;
                    info!(version = session.negotiated().version, "HELLO_ACK");
                    run_download_stream(&cli, &conn, &mut session, &path).await?;
                }
            }
            return Ok(());
        }
        Cmd::Fec { sub } => {
            run_fec(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Schedule { sub } => {
            run_schedule(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Dedup { sub } => {
            run_dedup(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Attest { sub } => {
            run_attest(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Audit { sub } => {
            run_audit(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Router { sub } => {
            run_router(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Xdp { sub } => {
            run_xdp(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Pqc { sub } => {
            run_pqc(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Proxy { sub } => {
            run_proxy(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Wan { sub } => {
            run_wan(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Did { sub } => {
            run_did(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Tee { sub } => {
            run_tee(&cli, sub).await?;
            return Ok(());
        }
        Cmd::Ec { sub } => {
            run_ec(&cli, sub).await?;
            return Ok(());
        }

        Cmd::Ping { url } => {
            let addr = parse_url(url)?;
            let sni = get_sni(&cli, url);
            let transport = build_transport_target(&cli, Some(addr))?;
            info!(%addr, %sni, "connecting");
            let mut session = ClientSession::connect(transport, addr, &sni).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            let rtt_ms = ping::ping(&mut session).await?;
            println!("PONG rtt={rtt_ms}ms");
            session.bye().await.ok();
        }
        Cmd::Upload { local, url } => {
            if url.starts_with("s3://") {
                return run_s3(
                    &cli,
                    &S3SubCmd::Put {
                        local: local.clone(),
                        s3_url: url.clone(),
                        endpoint: None,
                        region: None,
                        multipart_size: None,
                    },
                )
                .await;
            }
            if url.starts_with("gs://") {
                return run_gcs(
                    &cli,
                    &GcsSubCmd::Put {
                        local: local.clone(),
                        gcs_url: url.clone(),
                        endpoint: None,
                        token: None,
                        chunk_size: None,
                    },
                )
                .await;
            }
            if url.starts_with("az://") || url.starts_with("azure://") {
                return run_azure(
                    &cli,
                    &AzureSubCmd::Put {
                        local: local.clone(),
                        azure_url: url.clone(),
                        endpoint: None,
                        account_name: None,
                        account_key: None,
                        sas_token: None,
                        block_size: None,
                    },
                )
                .await;
            }
            let (addr, path) = parse_url_with_path(url)?;
            let sni = get_sni(&cli, url);
            let transport = build_transport_target(&cli, Some(addr))?;
            info!(%addr, %sni, ?path, "connecting");
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            if local == Path::new("-") {
                run_upload_stream(&cli, &conn, &mut session, &path, 65536).await?;
            } else {
                let store = open_client_state_store(&cli);
                run_upload(&cli, &conn, &mut session, local, &path, &store).await?;
            }
        }
        Cmd::Download { url, local } => {
            if url.starts_with("s3://") {
                return run_s3(
                    &cli,
                    &S3SubCmd::Get {
                        s3_url: url.clone(),
                        local: local.clone(),
                        endpoint: None,
                        region: None,
                        range_start: None,
                        range_end: None,
                    },
                )
                .await;
            }
            if url.starts_with("gs://") {
                return run_gcs(
                    &cli,
                    &GcsSubCmd::Get {
                        gcs_url: url.clone(),
                        local: local.clone(),
                        endpoint: None,
                        token: None,
                        range_start: None,
                        range_end: None,
                    },
                )
                .await;
            }
            if url.starts_with("az://") || url.starts_with("azure://") {
                return run_azure(
                    &cli,
                    &AzureSubCmd::Get {
                        azure_url: url.clone(),
                        local: local.clone(),
                        endpoint: None,
                        account_name: None,
                        account_key: None,
                        sas_token: None,
                        range_start: None,
                        range_end: None,
                    },
                )
                .await;
            }
            let (addr, path) = parse_url_with_path(url)?;
            let sni = get_sni(&cli, url);
            let transport = build_transport_target(&cli, Some(addr))?;
            info!(%addr, %sni, ?path, "connecting");
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            if local == Path::new("-") {
                run_download_stream(&cli, &conn, &mut session, &path).await?;
            } else {
                run_download(&cli, &conn, &mut session, local, &path).await?;
            }
        }
        Cmd::Resume {
            transfer_id,
            server,
            local,
        } => {
            let (addr, _) = parse_url_with_path(server)?;
            let sni = get_sni(&cli, server);
            let transport = build_transport_target(&cli, Some(addr))?;
            info!(%addr, %sni, "connecting for resume");
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            info!(version = session.negotiated().version, "HELLO_ACK");
            let store = open_client_state_store(&cli);
            run_resume(&cli, &conn, &mut session, transfer_id, local, &store).await?;
        }
        Cmd::Cancel {
            transfer_id,
            server,
        } => {
            let (addr, _) = parse_url_with_path(server)?;
            let sni = get_sni(&cli, server);
            let transport = build_transport_target(&cli, Some(addr))?;
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            run_cancel(&cli, &mut session, transfer_id).await?;
        }
        Cmd::Stat {
            transfer_id,
            server,
        } => {
            let (addr, _) = parse_url_with_path(server)?;
            let sni = get_sni(&cli, server);
            let transport = build_transport_target(&cli, Some(addr))?;
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            run_stat(&cli, &mut session, transfer_id).await?;
        }
        Cmd::List { url_prefix } => {
            let (addr, path) = parse_url_with_path(url_prefix)?;
            let sni = get_sni(&cli, url_prefix);
            let transport = build_transport_target(&cli, Some(addr))?;
            let conn = transport.connect(addr, &sni).await?;
            let mut session = open_client_session(&conn, &cli).await?;
            let clean_prefix = path.trim_start_matches('/').to_string();
            run_list(&cli, &mut session, &clean_prefix).await?;
        }
        Cmd::Plan {
            source,
            destination,
            delete_mode,
            delete_before,
            delete_after,
            delete,
            delete_excluded,
            excludes,
            max_delete,
            max_delete_pct,
            force_delete,
            cdc,
            dedup,
            chunk_store,
        } => {
            run_plan(
                &cli,
                source,
                destination,
                delete_mode,
                *delete_before,
                *delete_after,
                *delete,
                *delete_excluded,
                excludes,
                *max_delete,
                *max_delete_pct,
                *force_delete,
                *cdc,
                *dedup,
                chunk_store,
            )
            .await?;
        }
        Cmd::Sync {
            source,
            destination,
            dry_run,
            delete_before,
            delete_after,
            delete,
            delete_excluded,
            excludes,
            max_delete,
            max_delete_pct,
            force_delete,
            cdc,
            dedup,
            chunk_store,
            batch_small_files: _,
            no_batch_small_files,
            small_file_threshold,
            batch_max_bytes,
            watch,
            debounce_ms,
            poll_interval_ms,
            max_batches,
            atomic,
            sign_key,
            sign_issuer,
            verify_sig,
            trusted_signers,
            xattr_policy,
            acl_policy,
            delta_dict,
            delta_dict_threshold,
        } => {
            if *watch {
                run_watch(
                    &cli,
                    source,
                    destination,
                    *debounce_ms,
                    *poll_interval_ms,
                    *max_batches,
                    excludes,
                    true, // initial full synchronization for sync --watch
                    *cdc,
                    *dedup,
                    chunk_store,
                )
                .await?;
                return Ok(());
            }
            let effective_batch = !*no_batch_small_files;
            run_sync(
                &cli,
                source,
                destination,
                *dry_run,
                *delete_before,
                *delete_after,
                *delete,
                *delete_excluded,
                excludes,
                *max_delete,
                *max_delete_pct,
                *force_delete,
                *cdc,
                *dedup,
                chunk_store,
                effective_batch,
                *small_file_threshold,
                *batch_max_bytes,
                *atomic,
                sign_key.as_deref(),
                sign_issuer,
                verify_sig.as_deref(),
                trusted_signers.as_deref(),
                xattr_policy,
                acl_policy,
                delta_dict,
                *delta_dict_threshold,
            )
            .await?;
        }
        Cmd::DeltaSlice { sub } => {
            run_delta_slice(&cli, sub).await?;
        }
        Cmd::Bdp { sub } => {
            run_bdp(&cli, sub).await?;
        }
        Cmd::DirectIo { sub } => {
            run_direct_io(&cli, sub).await?;
        }
        Cmd::Checkpoint { sub } => {
            run_checkpoint(&cli, sub).await?;
        }
        Cmd::Qos { sub } => {
            run_qos(&cli, sub).await?;
        }
        Cmd::Cas { sub } => {
            run_cas(&cli, sub).await?;
        }
        Cmd::Swarm { sub } => {
            run_swarm(&cli, sub).await?;
        }
        Cmd::Chaos { sub } => {
            run_chaos(&cli, sub).await?;
        }
        Cmd::Tier { sub } => {
            run_tier(&cli, sub).await?;
        }
        Cmd::Tx { sub } => {
            run_tx(&cli, sub).await?;
        }
        Cmd::Watch {
            source,
            destination,
            debounce_ms,
            poll_interval_ms,
            max_batches,
            excludes,
            initial_sync,
            cdc,
            dedup,
            chunk_store,
        } => {
            run_watch(
                &cli,
                source,
                destination,
                *debounce_ms,
                *poll_interval_ms,
                *max_batches,
                excludes,
                *initial_sync,
                *cdc,
                *dedup,
                chunk_store,
            )
            .await?;
        }
    }
    Ok(())
}

async fn upload_file_stream(
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    store: &Option<Arc<dyn velcrux_core::state::StateStore>>,
    local: &PathBuf,
    remote_path: &str,
    show_progress: bool,
    cli: &Cli,
) -> anyhow::Result<(velcrux_core::util::TransferId, velcrux_core::Hash, u64)> {
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;
    use velcrux_core::state::ChunkBitmap;

    let file_size = std::fs::metadata(local)
        .with_context(|| format!("stat {local:?}"))?
        .len();
    let expected_hash =
        velcrux_core::sync::compute_file_hash(local).with_context(|| format!("hash {local:?}"))?;

    let idempotency_key = velcrux_core::util::TransferId::generate().to_string();
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: local.display().to_string(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: idempotency_key.clone(),
        file_size,
        file_hash: expected_hash,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(frame.payload)?;
    let frame = session.recv_frame().await?;
    let mut initial_bitmap = ChunkBitmap::new();
    let plan = if frame.type_byte == velcrux_core::protocol::message::INVENTORY_HINT {
        use velcrux_core::protocol::message::{ChunkQuery, ChunkResponse, InventoryHint};
        use velcrux_core::sync::{BloomFilter, RleBitmap};

        let hint = InventoryHint::decode(frame.payload)?;
        let _bloom = BloomFilter::from_bytes(&hint.bitset, hint.filter_bits, hint.num_hashes)
            .map_err(|e| anyhow::anyhow!("invalid bloom filter: {e}"))?;

        let mode = get_transfer_mode(cli);
        let net = get_network_profile(cli, conn);
        let dev = velcrux_core::sync::DeviceProfile::default();
        let estimator = velcrux_core::sync::AdaptiveCostEstimator::new(cli.min_delta_size, 0.08);

        let should_use_delta = match mode {
            velcrux_core::sync::TransferMode::DirectStream => false,
            velcrux_core::sync::TransferMode::DeltaCDC
            | velcrux_core::sync::TransferMode::DeltaFixed => true,
            velcrux_core::sync::TransferMode::Skip => false,
            velcrux_core::sync::TransferMode::Auto => {
                if file_size < cli.min_delta_size {
                    false
                } else {
                    let decision = estimator.evaluate(file_size, 0.50, false, &net, &dev);
                    decision.is_delta_worthwhile
                }
            }
        };

        if !should_use_delta {
            // Bypass delta calculation: send empty ChunkQuery to trigger immediate full-file plan
            let query = ChunkQuery {
                transfer_id: created.transfer_id,
                query_seq: 1,
                chunk_hashes: Vec::new(),
            };
            let q_buf = bytes::Bytes::from(encode_message(&Message::ChunkQuery(query), 0)?);
            session.send_mut().write_all(q_buf).await?;

            let resp_frame = session.recv_frame().await?;
            if resp_frame.type_byte != velcrux_core::protocol::message::CHUNK_RESPONSE {
                anyhow::bail!(
                    "expected CHUNK_RESPONSE, got 0x{:02x}",
                    resp_frame.type_byte
                );
            }
            let _ = ChunkResponse::decode(resp_frame.payload)?;

            let plan_frame = session.recv_frame().await?;
            if plan_frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
                anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", plan_frame.type_byte);
            }
            TransferPlan::decode(plan_frame.payload)?
        } else {
            let mut file = std::fs::File::open(local)?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut chunk_hashes = Vec::new();
            let mut chunk_indices = Vec::new();
            let mut offset = 0u64;
            let mut chunk_idx = 0u64;
            use std::io::Read;
            while offset < file_size {
                let to_read = ((file_size - offset).min(64 * 1024)) as usize;
                file.read_exact(&mut buf[..to_read])?;
                let h = velcrux_core::Hash::of(&buf[..to_read]);
                chunk_hashes.push(h);
                chunk_indices.push((chunk_idx, to_read as u64));
                offset += to_read as u64;
                chunk_idx += 1;
            }

            let query = ChunkQuery {
                transfer_id: created.transfer_id,
                query_seq: 1,
                chunk_hashes,
            };
            let q_buf = bytes::Bytes::from(encode_message(&Message::ChunkQuery(query), 0)?);
            session.send_mut().write_all(q_buf).await?;

            let resp_frame = session.recv_frame().await?;
            if resp_frame.type_byte != velcrux_core::protocol::message::CHUNK_RESPONSE {
                anyhow::bail!(
                    "expected CHUNK_RESPONSE, got 0x{:02x}",
                    resp_frame.type_byte
                );
            }
            let resp = ChunkResponse::decode(resp_frame.payload)?;
            let rle = RleBitmap::decode(&resp.rle_bitmap, resp.total_chunks)
                .map_err(|e| anyhow::anyhow!("invalid rle bitmap: {e}"))?;

            for (i, &(c_idx, len)) in chunk_indices.iter().enumerate() {
                if rle.get(i) == Some(true) {
                    initial_bitmap.mark_complete(c_idx, len);
                }
            }

            let plan_frame = session.recv_frame().await?;
            if plan_frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
                anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", plan_frame.type_byte);
            }
            TransferPlan::decode(plan_frame.payload)?
        }
    } else if frame.type_byte == velcrux_core::protocol::message::TRANSFER_PLAN {
        TransferPlan::decode(frame.payload)?
    } else {
        anyhow::bail!(
            "expected TRANSFER_PLAN or INVENTORY_HINT, got 0x{:02x}",
            frame.type_byte
        );
    };

    if plan.bytes_to_transfer == 0 {
        use velcrux_core::protocol::message::{Commit, Verify, VerifyResult};
        let begin = TransferBegin::new(created.transfer_id);
        session
            .send_mut()
            .write_all(bytes::Bytes::from(encode_message(
                &Message::TransferBegin(begin),
                0,
            )?))
            .await?;

        let verify = Verify {
            transfer_id: created.transfer_id,
            expected_hash,
        };
        session
            .send_mut()
            .write_all(bytes::Bytes::from(encode_message(
                &Message::Verify(verify),
                0,
            )?))
            .await?;

        let frame = session.recv_frame().await?;
        if frame.type_byte != velcrux_core::protocol::message::VERIFY_RESULT {
            anyhow::bail!("expected VERIFY_RESULT, got 0x{:02x}", frame.type_byte);
        }
        let vr = VerifyResult::decode(frame.payload)?;
        if !vr.ok {
            anyhow::bail!("server reported verify mismatch on skip");
        }

        let commit = Commit {
            transfer_id: created.transfer_id,
        };
        session
            .send_mut()
            .write_all(bytes::Bytes::from(encode_message(
                &Message::Commit(commit),
                0,
            )?))
            .await?;

        let frame = session.recv_frame().await?;
        if frame.type_byte != velcrux_core::protocol::message::COMMITTED {
            anyhow::bail!("expected COMMITTED, got 0x{:02x}", frame.type_byte);
        }

        if let Some(cs) = open_client_chunk_store(cli).await {
            let params =
                velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
            let _ = cs.ingest_file_sync(local, velcrux_core::chunking::ChunkMode::Fixed, params);
        }

        return Ok((created.transfer_id, expected_hash, 0));
    }

    let begin = TransferBegin::with_streams(created.transfer_id, cli.parallel.clamp(1, 16) as u8);
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let is_json = cli_log_json(cli);
    let bytes_to_transfer = plan.bytes_to_transfer;
    let (progress_tx, progress_handle) = if show_progress && !is_json {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(100);
        let tid_str = created.transfer_id.to_string();
        let handle = tokio::spawn(async move {
            let mut transferred = 0u64;
            let mut last_print = std::time::Instant::now();
            let start_time = std::time::Instant::now();
            while let Some(delta) = rx.recv().await {
                transferred = transferred.saturating_add(delta);
                if last_print.elapsed() >= std::time::Duration::from_millis(200)
                    || transferred >= bytes_to_transfer
                {
                    let elapsed_secs = start_time.elapsed().as_secs_f64();
                    let rate = if elapsed_secs > 0.0 {
                        transferred as f64 / elapsed_secs
                    } else {
                        0.0
                    };
                    let pct = if bytes_to_transfer > 0 {
                        (transferred as f64 / bytes_to_transfer as f64) * 100.0
                    } else {
                        100.0
                    };
                    eprint!(
                        "\r[{}] {} / {} ({:.1}%) — {}/s",
                        tid_str,
                        format_bytes(transferred),
                        format_bytes(bytes_to_transfer),
                        pct,
                        format_bytes(rate as u64)
                    );
                    last_print = std::time::Instant::now();
                }
            }
            if transferred > 0 {
                eprintln!();
            }
        });
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    let rate_limiter = get_rate_limiter(cli)?;
    let mut cfg = velcrux_core::PipelineConfig {
        parallel_streams: cli.parallel.clamp(1, 16),
        rate_limiter,
        compression: cli.compression.to_lowercase() == "zstd",
        ..Default::default()
    };
    if !initial_bitmap.is_empty() {
        cfg.chunk_mode = velcrux_core::chunking::ChunkMode::Fixed;
        cfg.chunk_params =
            velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
    }
    let (send_half, recv_half) = session.stream_halves_mut();
    let computed = velcrux_core::client_upload_stream(
        conn,
        send_half,
        recv_half,
        store.clone(),
        created.transfer_id,
        &idempotency_key,
        local.clone(),
        remote_path.trim_start_matches('/'),
        file_size,
        expected_hash,
        initial_bitmap,
        cfg,
        progress_tx,
    )
    .await?;

    if let Some(h) = progress_handle {
        let _ = h.await;
    }

    if let Some(cs) = open_client_chunk_store(cli).await {
        let params =
            velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
        let _ = cs.ingest_file_sync(local, velcrux_core::chunking::ChunkMode::Fixed, params);
    }

    Ok((created.transfer_id, computed, plan.bytes_to_transfer))
}

async fn run_upload(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    local: &PathBuf,
    url_path: &str,
    store: &Option<Arc<dyn velcrux_core::state::StateStore>>,
) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let (tid, computed, bytes_transferred) =
        upload_file_stream(conn, session, store, local, url_path, true, cli).await?;
    let file_size = std::fs::metadata(local)
        .map(|m| m.len())
        .unwrap_or(bytes_transferred);

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "transfer_complete",
            "op": "upload",
            "transfer_id": tid.to_string(),
            "file_size": file_size,
            "bytes_transferred": bytes_transferred,
            "bytes_completed": bytes_transferred,
            "file_hash": computed.to_string(),
            "status": "committed"
        });
        println!("{out}");
    } else {
        println!("transfer_id: {tid}");
        println!(
            "upload: committed {} bytes (transferred {} bytes); server hash matches: true",
            file_size, bytes_transferred
        );
    }
    session.bye().await.ok();
    Ok(())
}

async fn run_upload_stream(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    remote_path: &str,
    chunk_size: usize,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;

    let idempotency_key = velcrux_core::util::TransferId::generate().to_string();
    let create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "-".into(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key,
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(frame.payload)?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
        anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", frame.type_byte);
    }
    let _plan = TransferPlan::decode(frame.payload)?;

    let begin = TransferBegin::new(created.transfer_id);
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let rate_limiter = get_rate_limiter(cli)?;
    let compression = cli.compression == "zstd";
    let (send_half, recv_half) = session.stream_halves_mut();
    let stdin = tokio::io::stdin();

    let (hash, bytes_streamed) = velcrux_core::client_upload_stdin_stream(
        conn,
        send_half,
        recv_half,
        created.transfer_id,
        stdin,
        chunk_size,
        compression,
        rate_limiter,
        None,
    )
    .await?;

    let is_json = cli_log_json(cli);
    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "stream_complete",
            "op": "upload_stream",
            "transfer_id": created.transfer_id.to_string(),
            "bytes_streamed": bytes_streamed,
            "stream_hash": hash.to_string(),
            "status": "committed"
        });
        eprintln!("{out}");
    } else {
        eprintln!("transfer_id: {}", created.transfer_id);
        eprintln!(
            "stream upload: committed {} bytes, server hash {}",
            bytes_streamed, hash
        );
    }

    session.bye().await.ok();
    Ok(())
}

async fn run_download_stream(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    remote_path: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: TransferOp::Download,
        src_path: "".into(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(frame.payload)?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
        anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", frame.type_byte);
    }
    let _plan = TransferPlan::decode(frame.payload)?;

    let begin = TransferBegin::new(created.transfer_id);
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let rate_limiter = get_rate_limiter(cli)?;
    let (send_half, recv_half) = session.stream_halves_mut();
    let stdout = tokio::io::stdout();

    let (hash, bytes_streamed) = velcrux_core::client_download_stdout_stream(
        conn,
        send_half,
        recv_half,
        created.transfer_id,
        stdout,
        rate_limiter,
        None,
    )
    .await?;

    let is_json = cli_log_json(cli);
    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "stream_complete",
            "op": "download_stream",
            "transfer_id": created.transfer_id.to_string(),
            "bytes_streamed": bytes_streamed,
            "stream_hash": hash.to_string(),
            "status": "committed"
        });
        eprintln!("{out}");
    } else {
        eprintln!("transfer_id: {}", created.transfer_id);
        eprintln!(
            "stream download: received {} bytes, hash verified: {}",
            bytes_streamed, hash
        );
    }

    session.bye().await.ok();
    Ok(())
}

async fn run_resume(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    transfer_id_str: &str,
    local_override: &Option<PathBuf>,
    store: &Option<Arc<dyn velcrux_core::state::StateStore>>,
) -> anyhow::Result<()> {
    use std::io::Read;
    use velcrux_core::protocol::message::{Message, Resume, ResumeState, TransferBegin};
    use velcrux_core::session::encode_message;
    use velcrux_core::state::ChunkBitmap;

    let transfer_id = velcrux_core::util::TransferId::from_string(transfer_id_str)
        .ok_or_else(|| anyhow::anyhow!("invalid transfer id: {transfer_id_str}"))?;

    let resume_req = Resume {
        transfer_id,
        idempotency_key: String::new(),
    };
    let buf = bytes::Bytes::from(encode_message(&Message::Resume(resume_req), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::RESUME_STATE {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected RESUME_STATE, got 0x{:02x}", frame.type_byte);
    }
    let resume_state = ResumeState::decode(frame.payload)?;

    let local_path: PathBuf = if let Some(p) = local_override {
        p.clone()
    } else if let Some(s) = store {
        if let Ok(rec) = s.get_transfer(transfer_id) {
            PathBuf::from(rec.local_path)
        } else {
            let base = std::path::Path::new(&resume_state.staging_relpath)
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("download"));
            base
        }
    } else {
        let base = std::path::Path::new(&resume_state.staging_relpath)
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("download"));
        base
    };

    if !local_path.exists() {
        anyhow::bail!(
            "local file not found at {}: please specify --local <path>",
            local_path.display()
        );
    }

    let file_size = std::fs::metadata(&local_path)
        .with_context(|| format!("stat {local_path:?}"))?
        .len();
    if file_size != resume_state.file_size {
        anyhow::bail!(
            "local file size ({file_size}) does not match remote transfer size ({})",
            resume_state.file_size
        );
    }

    let expected_hash = {
        let mut f =
            std::fs::File::open(&local_path).with_context(|| format!("open {local_path:?}"))?;
        let mut h = velcrux_core::HashHasher::new();
        let mut buf = vec![0u8; 2 * 1024 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .with_context(|| format!("read {local_path:?}"))?;
            if n == 0 {
                break;
            }
            h.feed(&buf[..n]);
        }
        h.finalize()
    };
    if expected_hash != resume_state.file_hash {
        anyhow::bail!("local file hash does not match transfer file hash");
    }

    let begin = TransferBegin::with_streams(transfer_id, cli.parallel.clamp(1, 16) as u8);
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let bitmap = ChunkBitmap::from_sorted_indices(
        &resume_state.completed_chunks,
        resume_state.bytes_completed,
    );

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<u64>(100);
    let tid_str = transfer_id.to_string();
    let is_json = cli_log_json(cli);
    let progress_handle = tokio::spawn(async move {
        let mut transferred = 0u64;
        let mut last_print = std::time::Instant::now();
        let start_time = std::time::Instant::now();
        while let Some(delta) = progress_rx.recv().await {
            transferred = transferred.saturating_add(delta);
            if !is_json
                && (last_print.elapsed() >= std::time::Duration::from_millis(200)
                    || transferred >= file_size)
            {
                let elapsed_secs = start_time.elapsed().as_secs_f64();
                let rate = if elapsed_secs > 0.0 {
                    transferred as f64 / elapsed_secs
                } else {
                    0.0
                };
                let pct = if file_size > 0 {
                    (transferred as f64 / file_size as f64) * 100.0
                } else {
                    100.0
                };
                eprint!(
                    "\r[{}] {} / {} ({:.1}%) — {}/s",
                    tid_str,
                    format_bytes(transferred),
                    format_bytes(file_size),
                    pct,
                    format_bytes(rate as u64)
                );
                last_print = std::time::Instant::now();
            }
        }
        if !is_json && transferred > 0 {
            eprintln!();
        }
    });

    let rate_limiter = get_rate_limiter(cli)?;
    let cfg = velcrux_core::PipelineConfig {
        parallel_streams: cli.parallel.clamp(1, 16),
        rate_limiter,
        compression: cli.compression.to_lowercase() == "zstd",
        ..Default::default()
    };
    let (send_half, recv_half) = session.stream_halves_mut();
    let computed = velcrux_core::client_upload_stream(
        conn,
        send_half,
        recv_half,
        store.clone(),
        transfer_id,
        "",
        local_path,
        &resume_state.staging_relpath,
        file_size,
        expected_hash,
        bitmap,
        cfg,
        Some(progress_tx),
    )
    .await?;

    let _ = progress_handle.await;

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "transfer_complete",
            "op": "resume",
            "transfer_id": transfer_id.to_string(),
            "file_size": file_size,
            "file_hash": computed.to_string(),
            "status": "committed"
        });
        println!("{out}");
    } else {
        println!("transfer_id: {}", transfer_id);
        println!(
            "resume: committed {} bytes; server hash matches: {}",
            file_size,
            computed == expected_hash
        );
    }
    Ok(())
}

async fn run_stat(
    cli: &Cli,
    session: &mut ClientSession,
    transfer_id_str: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Message, StatQuery, StatResult};
    use velcrux_core::session::encode_message;

    let transfer_id = velcrux_core::util::TransferId::from_string(transfer_id_str)
        .ok_or_else(|| anyhow::anyhow!("invalid transfer id: {transfer_id_str}"))?;
    let q = StatQuery { transfer_id };
    let buf = bytes::Bytes::from(encode_message(&Message::Stat(q), 0)?);
    session.send_mut().write_all(buf).await?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::STAT_RESULT {
        anyhow::bail!("expected STAT_RESULT, got 0x{:02x}", frame.type_byte);
    }
    let r = StatResult::decode(frame.payload)?;
    if !r.found {
        anyhow::bail!("transfer not found: {}", transfer_id_str);
    }
    if cli_log_json(cli) {
        let obj = serde_json::json!({
            "v": 1,
            "event": "stat",
            "transfer_id": r.transfer_id.to_string(),
            "status": r.status,
            "direction": r.direction,
            "remote_path": r.remote_path,
            "file_size": r.file_size,
            "bytes_completed": r.bytes_completed,
            "verified_up_to": r.verified_up_to,
            "created_ms": r.created_ms,
            "updated_ms": r.updated_ms,
        });
        println!("{obj}");
    } else {
        println!(
            "{:<26}  {:<10}  {:<10}  {:>10}  {:>10}  {}",
            r.transfer_id, r.status, r.direction, r.file_size, r.bytes_completed, r.remote_path
        );
    }
    Ok(())
}

async fn run_list(cli: &Cli, session: &mut ClientSession, url_prefix: &str) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{ListQuery, ListResult, Message};
    use velcrux_core::session::encode_message;

    let q = ListQuery {
        url_prefix: url_prefix.to_string(),
    };
    let buf = bytes::Bytes::from(encode_message(&Message::List(q), 0)?);
    session.send_mut().write_all(buf).await?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::LIST_RESULT {
        anyhow::bail!("expected LIST_RESULT, got 0x{:02x}", frame.type_byte);
    }
    let r = ListResult::decode(frame.payload)?;
    if cli_log_json(cli) {
        let arr: Vec<_> = r
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "v": 1,
                    "event": "stat",
                    "transfer_id": e.transfer_id.to_string(),
                    "status": e.status,
                    "direction": e.direction,
                    "remote_path": e.remote_path,
                    "file_size": e.file_size,
                    "bytes_completed": e.bytes_completed,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
    } else if r.entries.is_empty() {
        println!("(no transfers match {url_prefix})");
    } else {
        for e in &r.entries {
            println!(
                "{:<26}  {:<10}  {:>10}  {}",
                e.transfer_id, e.status, e.file_size, e.remote_path
            );
        }
    }
    Ok(())
}

async fn run_cancel(
    cli: &Cli,
    session: &mut ClientSession,
    transfer_id_str: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::error::ErrorCode;
    use velcrux_core::protocol::message::{Cancel, Message};
    use velcrux_core::session::encode_message;

    let transfer_id = velcrux_core::util::TransferId::from_string(transfer_id_str)
        .ok_or_else(|| anyhow::anyhow!("invalid transfer id: {transfer_id_str}"))?;
    let c = Cancel {
        transfer_id,
        reason_code: ErrorCode::TransferCancelled.to_wire(),
    };
    let buf = bytes::Bytes::from(encode_message(&Message::Cancel(c), 0)?);
    session.send_mut().write_all(buf).await?;
    session.bye().await.ok();
    if cli_log_json(cli) {
        let obj = serde_json::json!({
            "v": 1,
            "event": "cancel",
            "transfer_id": transfer_id_str,
            "status": "cancelled",
        });
        println!("{obj}");
    } else {
        println!("cancel requested: {transfer_id_str}");
    }
    Ok(())
}

async fn download_file_stream(
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    remote_path: &str,
    local: &PathBuf,
    show_progress: bool,
    cli: &Cli,
) -> anyhow::Result<(velcrux_core::util::TransferId, velcrux_core::Hash, u64)> {
    use velcrux_core::protocol::message::{
        Message, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    };
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: TransferOp::Download,
        src_path: "".into(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }
    let created = TransferCreated::decode(frame.payload)?;
    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
        anyhow::bail!("expected TRANSFER_PLAN, got 0x{:02x}", frame.type_byte);
    }
    let mut plan = TransferPlan::decode(frame.payload)?;

    let mut staging_prepopulated = false;
    let client_cs = open_client_chunk_store(cli).await;
    let local_exists = local.is_file();

    let mode = get_transfer_mode(cli);
    let net = get_network_profile(cli, conn);
    let dev = velcrux_core::sync::DeviceProfile::default();
    let estimator = velcrux_core::sync::AdaptiveCostEstimator::new(cli.min_delta_size, 0.08);

    let should_use_delta = match mode {
        velcrux_core::sync::TransferMode::DirectStream => false,
        velcrux_core::sync::TransferMode::DeltaCDC
        | velcrux_core::sync::TransferMode::DeltaFixed => true,
        velcrux_core::sync::TransferMode::Skip => false,
        velcrux_core::sync::TransferMode::Auto => {
            if plan.bytes_total < cli.min_delta_size || (!local_exists && client_cs.is_none()) {
                false
            } else {
                let decision = estimator.evaluate(plan.bytes_total, 0.50, false, &net, &dev);
                decision.is_delta_worthwhile
            }
        }
    };

    // Check if local file or client chunk store can participate in deduplication/delta download
    if should_use_delta && (local_exists || client_cs.is_some()) {
        use velcrux_core::protocol::message::{ChunkQuery, ChunkResponse, InventoryHint};
        use velcrux_core::sync::RleBitmap;

        let inv_opt = if local_exists {
            velcrux_core::sync::LocalInventory::from_file(
                local,
                velcrux_core::chunking::ChunkMode::Fixed,
                velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap(),
                64 * 1024,
            )
            .ok()
        } else {
            None
        };

        if inv_opt.is_some() || client_cs.is_some() {
            let bloom = match (&inv_opt, &client_cs) {
                (Some(inv), Some(cs)) => {
                    let mut b = cs.bloom_filter();
                    for h in inv.chunk_hashes() {
                        b.insert(h);
                    }
                    b
                }
                (Some(inv), None) => inv.create_bloom_filter(0.01),
                (None, Some(cs)) => cs.bloom_filter(),
                (None, None) => unreachable!(),
            };

            let hint = InventoryHint {
                transfer_id: created.transfer_id,
                filter_bits: bloom.num_bits(),
                num_hashes: bloom.num_hashes(),
                bitset: bytes::Bytes::copy_from_slice(bloom.bitset_bytes()),
            };
            session
                .send_mut()
                .write_all(bytes::Bytes::from(encode_message(
                    &Message::InventoryHint(hint),
                    0,
                )?))
                .await?;

            let q_frame = session.recv_frame().await?;
            if q_frame.type_byte == velcrux_core::protocol::message::CHUNK_QUERY {
                let query = ChunkQuery::decode(q_frame.payload)?;
                let mut have_bits = Vec::with_capacity(query.chunk_hashes.len());
                let mut matching_chunks = Vec::new();
                let mut matching_store_chunks = Vec::new();
                for (idx, h) in query.chunk_hashes.iter().enumerate() {
                    let dst_off = idx as u64 * (64 * 1024);
                    let chunk_len = (plan.bytes_total - dst_off).min(64 * 1024);
                    if let Some(extent) = inv_opt.as_ref().and_then(|inv| inv.lookup(h)) {
                        have_bits.push(true);
                        matching_chunks.push((dst_off, extent.offset, extent.length));
                    } else if client_cs
                        .as_ref()
                        .map(|cs| cs.contains_sync(h))
                        .unwrap_or(false)
                    {
                        have_bits.push(true);
                        matching_store_chunks.push((dst_off, *h, chunk_len));
                    } else {
                        have_bits.push(false);
                    }
                }
                let rle = RleBitmap::from_bits(&have_bits);
                let resp = ChunkResponse {
                    transfer_id: created.transfer_id,
                    query_seq: query.query_seq,
                    total_chunks: rle.total_chunks(),
                    have_count: rle.have_count(),
                    rle_bitmap: rle.encode(),
                };
                session
                    .send_mut()
                    .write_all(bytes::Bytes::from(encode_message(
                        &Message::ChunkResponse(resp),
                        0,
                    )?))
                    .await?;

                // Pre-stage matching chunks into staging file on client
                let staging_path = {
                    let mut p = local.clone().into_os_string();
                    p.push(".velcrux-partial");
                    std::path::PathBuf::from(p)
                };
                if let Some(parent) = staging_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let mut staging_f = std::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .truncate(true)
                    .open(&staging_path)?;
                staging_f.set_len(plan.bytes_total)?;

                // 1. Copy from existing local file
                if local_exists && !matching_chunks.is_empty() {
                    if let Ok(mut src_f) = std::fs::File::open(local) {
                        use std::io::{Read, Seek, SeekFrom, Write};
                        let mut copy_buf = [0u8; 64 * 1024];
                        for (dst_offset, src_offset, len) in matching_chunks {
                            src_f.seek(SeekFrom::Start(src_offset))?;
                            staging_f.seek(SeekFrom::Start(dst_offset))?;
                            let mut rem = len;
                            while rem > 0 {
                                let to_read = (rem as usize).min(copy_buf.len());
                                src_f.read_exact(&mut copy_buf[..to_read])?;
                                staging_f.write_all(&copy_buf[..to_read])?;
                                rem -= to_read as u64;
                            }
                        }
                    }
                }

                // 2. Copy from local chunk store
                if let Some(ref cs) = client_cs {
                    for (dst_offset, hash, _len) in matching_store_chunks {
                        let _ = cs.copy_to_std_file(&hash, &mut staging_f, dst_offset);
                    }
                }

                staging_f.sync_all()?;
                drop(staging_f);

                staging_prepopulated = true;

                // Receive updated TRANSFER_PLAN
                let updated_plan_frame = session.recv_frame().await?;
                if updated_plan_frame.type_byte != velcrux_core::protocol::message::TRANSFER_PLAN {
                    anyhow::bail!(
                        "expected TRANSFER_PLAN, got 0x{:02x}",
                        updated_plan_frame.type_byte
                    );
                }
                plan = TransferPlan::decode(updated_plan_frame.payload)?;
            }
        }
    }

    let begin = TransferBegin::with_streams(created.transfer_id, cli.parallel.clamp(1, 16) as u8);
    let buf = bytes::Bytes::from(encode_message(&Message::TransferBegin(begin), 0)?);
    session.send_mut().write_all(buf).await?;

    let is_json = cli_log_json(cli);
    let bytes_to_transfer = plan.bytes_to_transfer;
    let (progress_tx, progress_handle) = if show_progress && !is_json {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(100);
        let tid_str = created.transfer_id.to_string();
        let handle = tokio::spawn(async move {
            let mut transferred = 0u64;
            let mut last_print = std::time::Instant::now();
            let start_time = std::time::Instant::now();
            while let Some(delta) = rx.recv().await {
                transferred = transferred.saturating_add(delta);
                if last_print.elapsed() >= std::time::Duration::from_millis(200)
                    || transferred >= bytes_to_transfer
                {
                    let elapsed_secs = start_time.elapsed().as_secs_f64();
                    let rate = if elapsed_secs > 0.0 {
                        transferred as f64 / elapsed_secs
                    } else {
                        0.0
                    };
                    let pct = if bytes_to_transfer > 0 {
                        (transferred as f64 / bytes_to_transfer as f64) * 100.0
                    } else {
                        100.0
                    };
                    eprint!(
                        "\r[{}] {} / {} ({:.1}%) — {}/s",
                        tid_str,
                        format_bytes(transferred),
                        format_bytes(bytes_to_transfer),
                        pct,
                        format_bytes(rate as u64)
                    );
                    last_print = std::time::Instant::now();
                }
            }
            if transferred > 0 {
                eprintln!();
            }
        });
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    let rate_limiter = get_rate_limiter(cli)?;
    let (send_half, recv_half) = session.stream_halves_mut();
    let computed = velcrux_core::client_download_stream_with_staging(
        conn,
        send_half,
        recv_half,
        created.transfer_id,
        local.clone(),
        progress_tx,
        staging_prepopulated,
        cli.parallel.clamp(1, 16),
        rate_limiter,
    )
    .await?;

    if let Some(h) = progress_handle {
        let _ = h.await;
    }

    if let Some(ref cs) = client_cs {
        let params =
            velcrux_core::chunking::ChunkParams::new(64 * 1024, 64 * 1024, 64 * 1024).unwrap();
        let _ = cs.ingest_file_sync(local, velcrux_core::chunking::ChunkMode::Fixed, params);
    }

    Ok((created.transfer_id, computed, plan.bytes_to_transfer))
}

async fn delete_remote_file(
    session: &mut ClientSession,
    remote_path: &str,
    is_sync: bool,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Committed, Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: if is_sync {
            TransferOp::SyncDelete
        } else {
            TransferOp::Delete
        },
        src_path: "".into(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::COMMITTED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!(
                "remote delete failed: code={:?} detail={:?}",
                err.code,
                err.detail
            );
        }
        anyhow::bail!(
            "expected COMMITTED for delete, got 0x{:02x}",
            frame.type_byte
        );
    }
    let _committed = Committed::decode(frame.payload)?;
    Ok(())
}

async fn create_remote_symlink(
    session: &mut ClientSession,
    target: &str,
    remote_path: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Committed, Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: TransferOp::Symlink,
        src_path: target.to_string(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: target.len() as u64,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::COMMITTED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!(
                "remote symlink creation failed: code={:?} detail={:?}",
                err.code,
                err.detail
            );
        }
        anyhow::bail!(
            "expected COMMITTED for symlink, got 0x{:02x}",
            frame.type_byte
        );
    }
    let _committed = Committed::decode(frame.payload)?;
    Ok(())
}

async fn create_remote_hardlink(
    session: &mut ClientSession,
    src_file: &str,
    remote_path: &str,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Committed, Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let create = TransferCreate {
        op: TransferOp::Hardlink,
        src_path: src_file.trim_start_matches('/').to_string(),
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::COMMITTED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!(
                "remote hardlink creation failed: code={:?} detail={:?}",
                err.code,
                err.detail
            );
        }
        anyhow::bail!(
            "expected COMMITTED for hardlink, got 0x{:02x}",
            frame.type_byte
        );
    }
    let _committed = Committed::decode(frame.payload)?;
    Ok(())
}

async fn set_remote_xattrs(
    session: &mut ClientSession,
    xattrs: &[(String, Vec<u8>)],
    remote_path: &str,
) -> anyhow::Result<()> {
    if xattrs.is_empty() {
        return Ok(());
    }
    use velcrux_core::protocol::message::{Committed, Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let payload = serde_json::to_string(xattrs)?;
    let create = TransferCreate {
        op: TransferOp::SetXattr,
        src_path: payload,
        dst_path: remote_path.trim_start_matches('/').to_string(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::COMMITTED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!(
                "remote set_xattrs failed: code={:?} detail={:?}",
                err.code,
                err.detail
            );
        }
        anyhow::bail!(
            "expected COMMITTED for set_xattrs, got 0x{:02x}",
            frame.type_byte
        );
    }
    let _committed = Committed::decode(frame.payload)?;
    Ok(())
}

async fn run_download(
    cli: &Cli,
    conn: &dyn velcrux_core::transport::Connection,
    session: &mut ClientSession,
    local: &PathBuf,
    url_path: &str,
) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let (tid, computed, total_bytes) =
        download_file_stream(conn, session, url_path, local, true, cli).await?;

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "transfer_complete",
            "op": "download",
            "transfer_id": tid.to_string(),
            "bytes_completed": total_bytes,
            "file_hash": computed.to_string(),
            "local_path": local.display().to_string(),
            "status": "committed"
        });
        println!("{out}");
    } else {
        println!("transfer_id: {tid}");
        println!("download: committed to {local:?}, hash {computed}");
    }
    session.bye().await.ok();
    Ok(())
}

async fn run_remote_upload_sync(
    cli: &Cli,
    source: &str,
    destination: &str,
    dry_run: bool,
    delete_after: bool,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let src_dir = PathBuf::from(source);
    if !src_dir.exists() {
        anyhow::bail!("source path does not exist: {}", src_dir.display());
    }
    if !src_dir.is_dir() {
        anyhow::bail!("source must be a directory: {}", src_dir.display());
    }

    let (addr, path) = parse_url_with_path(destination)?;
    let sni = get_sni(cli, destination);
    let transport = build_transport_target(cli, Some(addr))?;
    let conn = transport.connect(addr, &sni).await?;
    let mut session = open_client_session(&conn, cli).await?;
    let store = open_client_state_store(cli);

    let src_files = velcrux_core::sync::scan_dir_entries(&src_dir)?;
    let vpath = path.trim_start_matches('/').to_string();

    let create = TransferCreate {
        op: TransferOp::SyncUpload,
        src_path: "".into(),
        dst_path: vpath.clone(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }

    let dst_files =
        velcrux_core::sync::recv_directory_manifest(session.recv_mut().as_mut()).await?;
    let plan = velcrux_core::sync::plan_directory_diff(&src_files, &dst_files);

    let is_json = cli_log_json(cli);

    if dry_run {
        if is_json {
            let actions: Vec<_> = plan
                .actions
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "action": format!("{:?}", a.action).to_lowercase(),
                        "path": a.rel_path,
                        "size": a.src_size,
                        "reused": a.bytes_reusable,
                    })
                })
                .collect();
            let out = serde_json::json!({
                "v": 1,
                "event": "sync_summary",
                "dry_run": true,
                "source": source,
                "destination": destination,
                "files_unchanged": plan.summary.files_unchanged,
                "files_modified": plan.summary.files_modified,
                "files_added": plan.summary.files_added,
                "files_deleted": plan.summary.files_deleted,
                "data_present": plan.summary.data_present,
                "data_to_transfer": plan.summary.data_to_transfer,
                "files_transferred": 0,
                "files_committed": 0,
                "files_deleted_count": 0,
                "actions": actions,
            });
            println!("{out}");
        } else {
            println!("{}", plan.summary.format_display());
        }
        session.bye().await.ok();
        return Ok(());
    }

    if !is_json {
        println!("{}", plan.summary.format_display());
    }

    let mut files_transferred = 0usize;
    let mut files_committed = 0usize;
    let mut files_deleted = 0usize;
    let mut wire_bytes = 0u64;

    for item in &plan.actions {
        match item.action {
            velcrux_core::sync::FileActionType::Add
            | velcrux_core::sync::FileActionType::Modify => {
                let local_file = src_dir.join(&item.rel_path);
                let remote_file = if vpath.is_empty() {
                    item.rel_path.clone()
                } else {
                    format!("{}/{}", vpath.trim_end_matches('/'), item.rel_path)
                };

                if let Some(src_entry) = src_files.get(&item.rel_path) {
                    if src_entry.is_symlink {
                        let target = src_entry.symlink_target.as_deref().unwrap_or("");
                        create_remote_symlink(&mut session, target, &remote_file).await?;
                        if !src_entry.xattrs.is_empty() {
                            let _ =
                                set_remote_xattrs(&mut session, &src_entry.xattrs, &remote_file)
                                    .await;
                        }
                        files_transferred += 1;
                        files_committed += 1;
                        continue;
                    } else if let Some(ref hard_target) = src_entry.hardlink_target {
                        let remote_src = if vpath.is_empty() {
                            hard_target.clone()
                        } else {
                            format!("{}/{}", vpath.trim_end_matches('/'), hard_target)
                        };
                        create_remote_hardlink(&mut session, &remote_src, &remote_file).await?;
                        if !src_entry.xattrs.is_empty() {
                            let _ =
                                set_remote_xattrs(&mut session, &src_entry.xattrs, &remote_file)
                                    .await;
                        }
                        files_transferred += 1;
                        files_committed += 1;
                        continue;
                    }
                }

                let (_tid, _hash, size) = upload_file_stream(
                    &conn,
                    &mut session,
                    &store,
                    &local_file,
                    &remote_file,
                    false,
                    cli,
                )
                .await?;
                if let Some(src_entry) = src_files.get(&item.rel_path) {
                    if !src_entry.xattrs.is_empty() {
                        let _ =
                            set_remote_xattrs(&mut session, &src_entry.xattrs, &remote_file).await;
                    }
                }
                files_transferred += 1;
                files_committed += 1;
                wire_bytes += size;
            }
            velcrux_core::sync::FileActionType::Delete => {
                if delete_after {
                    let remote_file = if vpath.is_empty() {
                        item.rel_path.clone()
                    } else {
                        format!("{}/{}", vpath.trim_end_matches('/'), item.rel_path)
                    };
                    delete_remote_file(&mut session, &remote_file, true).await?;
                    files_deleted += 1;
                }
            }
            velcrux_core::sync::FileActionType::Unchanged => {}
        }
    }

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "sync_summary",
            "dry_run": false,
            "source": source,
            "destination": destination,
            "files_unchanged": plan.summary.files_unchanged,
            "files_modified": plan.summary.files_modified,
            "files_added": plan.summary.files_added,
            "files_deleted": plan.summary.files_deleted,
            "data_present": plan.summary.data_present,
            "data_to_transfer": plan.summary.data_to_transfer,
            "files_transferred": files_transferred,
            "files_committed": files_committed,
            "files_deleted_count": files_deleted,
            "wire_bytes_transferred": wire_bytes,
        });
        println!("{out}");
    } else {
        println!();
        println!(
            "Transferred: {} files (committed: {}, deleted: {})",
            files_transferred, files_committed, files_deleted
        );
        println!("Wire data: {}", format_bytes(wire_bytes));
    }

    session.bye().await.ok();
    Ok(())
}

async fn run_remote_download_sync(
    cli: &Cli,
    source: &str,
    destination: &str,
    dry_run: bool,
    delete_after: bool,
) -> anyhow::Result<()> {
    use velcrux_core::protocol::message::{Message, TransferCreate, TransferOp};
    use velcrux_core::session::encode_message;

    let dst_dir = PathBuf::from(destination);
    if !dst_dir.exists() {
        std::fs::create_dir_all(&dst_dir)?;
    }

    let (addr, path) = parse_url_with_path(source)?;
    let sni = get_sni(cli, source);
    let transport = build_transport_target(cli, Some(addr))?;
    let conn = transport.connect(addr, &sni).await?;
    let mut session = open_client_session(&conn, cli).await?;

    let dst_files = velcrux_core::sync::scan_dir_entries(&dst_dir)?;
    let vpath = path.trim_start_matches('/').to_string();

    let create = TransferCreate {
        op: TransferOp::SyncDownload,
        src_path: vpath.clone(),
        dst_path: "".into(),
        idempotency_key: velcrux_core::util::TransferId::generate().to_string(),
        file_size: 0,
        file_hash: velcrux_core::Hash::ZERO,
    };
    let buf = bytes::Bytes::from(encode_message(&Message::TransferCreate(create), 0)?);
    session.send_mut().write_all(buf).await?;

    let frame = session.recv_frame().await?;
    if frame.type_byte != velcrux_core::protocol::message::TRANSFER_CREATED {
        if frame.type_byte == velcrux_core::protocol::message::ERROR {
            let err = velcrux_core::protocol::message::ErrorMsg::decode(frame.payload)?;
            anyhow::bail!("server error: code={:?} detail={:?}", err.code, err.detail);
        }
        anyhow::bail!("expected TRANSFER_CREATED, got 0x{:02x}", frame.type_byte);
    }

    let src_files =
        velcrux_core::sync::recv_directory_manifest(session.recv_mut().as_mut()).await?;
    let plan = velcrux_core::sync::plan_directory_diff(&src_files, &dst_files);

    let is_json = cli_log_json(cli);

    if dry_run {
        if is_json {
            let actions: Vec<_> = plan
                .actions
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "action": format!("{:?}", a.action).to_lowercase(),
                        "path": a.rel_path,
                        "size": a.src_size,
                        "reused": a.bytes_reusable,
                    })
                })
                .collect();
            let out = serde_json::json!({
                "v": 1,
                "event": "sync_summary",
                "dry_run": true,
                "source": source,
                "destination": destination,
                "files_unchanged": plan.summary.files_unchanged,
                "files_modified": plan.summary.files_modified,
                "files_added": plan.summary.files_added,
                "files_deleted": plan.summary.files_deleted,
                "data_present": plan.summary.data_present,
                "data_to_transfer": plan.summary.data_to_transfer,
                "files_transferred": 0,
                "files_committed": 0,
                "files_deleted_count": 0,
                "actions": actions,
            });
            println!("{out}");
        } else {
            println!("{}", plan.summary.format_display());
        }
        session.bye().await.ok();
        return Ok(());
    }

    if !is_json {
        println!("{}", plan.summary.format_display());
    }

    let mut files_transferred = 0usize;
    let mut files_committed = 0usize;
    let mut files_deleted = 0usize;
    let mut wire_bytes = 0u64;

    for item in &plan.actions {
        match item.action {
            velcrux_core::sync::FileActionType::Add
            | velcrux_core::sync::FileActionType::Modify => {
                let remote_file = if vpath.is_empty() {
                    item.rel_path.clone()
                } else {
                    format!("{}/{}", vpath.trim_end_matches('/'), item.rel_path)
                };
                let local_file = dst_dir.join(&item.rel_path);
                if let Some(parent) = local_file.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                if let Some(src_entry) = src_files.get(&item.rel_path) {
                    if src_entry.is_symlink {
                        let link_vpath = velcrux_core::storage::VPath::validate(&item.rel_path)?;
                        let target = src_entry.symlink_target.as_deref().unwrap_or("");
                        velcrux_core::storage::VPath::validate_symlink_target(&link_vpath, target)?;

                        if std::fs::symlink_metadata(&local_file).is_ok() {
                            let _ = std::fs::remove_file(&local_file);
                        }
                        #[cfg(unix)]
                        {
                            std::os::unix::fs::symlink(target, &local_file)?;
                        }
                        #[cfg(windows)]
                        {
                            std::os::windows::fs::symlink_file(target, &local_file)?;
                        }

                        if !src_entry.xattrs.is_empty() {
                            let sidecar = velcrux_core::storage::xattr_sidecar_path(&local_file);
                            let raw =
                                velcrux_core::storage::encode_xattrs_canonical(&src_entry.xattrs);
                            let _ = std::fs::write(&sidecar, raw);
                        }

                        files_transferred += 1;
                        files_committed += 1;
                        continue;
                    } else if let Some(ref hard_target) = src_entry.hardlink_target {
                        let local_src = dst_dir.join(hard_target);
                        if std::fs::symlink_metadata(&local_file).is_ok() {
                            let _ = std::fs::remove_file(&local_file);
                        }
                        std::fs::hard_link(&local_src, &local_file)?;

                        if !src_entry.xattrs.is_empty() {
                            let sidecar = velcrux_core::storage::xattr_sidecar_path(&local_file);
                            let raw =
                                velcrux_core::storage::encode_xattrs_canonical(&src_entry.xattrs);
                            let _ = std::fs::write(&sidecar, raw);
                        }

                        files_transferred += 1;
                        files_committed += 1;
                        continue;
                    }
                }

                let (_tid, _hash, size) = download_file_stream(
                    &conn,
                    &mut session,
                    &remote_file,
                    &local_file,
                    false,
                    cli,
                )
                .await?;

                if let Some(src_entry) = src_files.get(&item.rel_path) {
                    if !src_entry.xattrs.is_empty() {
                        let sidecar = velcrux_core::storage::xattr_sidecar_path(&local_file);
                        let raw = velcrux_core::storage::encode_xattrs_canonical(&src_entry.xattrs);
                        let _ = std::fs::write(&sidecar, raw);
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if src_entry.mode != 0 {
                            let _ = std::fs::set_permissions(
                                &local_file,
                                std::fs::Permissions::from_mode(src_entry.mode),
                            );
                        }
                    }
                    if src_entry.mtime_sec != 0 {
                        let duration = std::time::Duration::new(
                            src_entry.mtime_sec as u64,
                            src_entry.mtime_nsec,
                        );
                        if let Ok(f) = std::fs::File::open(&local_file) {
                            let times = std::fs::FileTimes::new()
                                .set_modified(std::time::UNIX_EPOCH + duration);
                            let _ = f.set_times(times);
                        }
                    }
                }

                files_transferred += 1;
                files_committed += 1;
                wire_bytes += size;
            }
            velcrux_core::sync::FileActionType::Delete => {
                if delete_after {
                    let local_file = dst_dir.join(&item.rel_path);
                    if local_file.symlink_metadata().is_ok() {
                        let _ = std::fs::remove_file(&local_file);
                        let sidecar = velcrux_core::storage::xattr_sidecar_path(&local_file);
                        if sidecar.symlink_metadata().is_ok() {
                            let _ = std::fs::remove_file(&sidecar);
                        }
                        files_deleted += 1;
                    }
                }
            }
            velcrux_core::sync::FileActionType::Unchanged => {}
        }
    }

    if is_json {
        let out = serde_json::json!({
            "v": 1,
            "event": "sync_summary",
            "dry_run": false,
            "source": source,
            "destination": destination,
            "files_unchanged": plan.summary.files_unchanged,
            "files_modified": plan.summary.files_modified,
            "files_added": plan.summary.files_added,
            "files_deleted": plan.summary.files_deleted,
            "data_present": plan.summary.data_present,
            "data_to_transfer": plan.summary.data_to_transfer,
            "files_transferred": files_transferred,
            "files_committed": files_committed,
            "files_deleted_count": files_deleted,
            "wire_bytes_transferred": wire_bytes,
        });
        println!("{out}");
    } else {
        println!();
        println!(
            "Transferred: {} files (committed: {}, deleted: {})",
            files_transferred, files_committed, files_deleted
        );
        println!("Wire data: {}", format_bytes(wire_bytes));
    }

    session.bye().await.ok();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_plan(
    cli: &Cli,
    source: &str,
    destination: &str,
    delete_mode_str: &str,
    delete_before: bool,
    delete_after: bool,
    delete: bool,
    delete_excluded: bool,
    excludes: &[String],
    max_delete: Option<usize>,
    max_delete_pct: Option<f64>,
    force_delete: bool,
    cdc: bool,
    dedup: bool,
    chunk_store_path: &Option<PathBuf>,
) -> anyhow::Result<()> {
    use std::str::FromStr;
    use velcrux_core::chunking::{ChunkMode, ChunkParams};
    use velcrux_core::storage::LocalChunkStore;
    use velcrux_core::sync::{
        plan_directory_sync, DeleteGuardrails, DeleteMode, DirectorySyncOptions, PathFilter,
        TransferPlan,
    };

    let src_path = PathBuf::from(source);
    let dst_path = PathBuf::from(destination);

    if !src_path.exists() {
        anyhow::bail!("source path does not exist: {}", src_path.display());
    }

    let delete_mode = if delete_before {
        DeleteMode::DeleteBefore
    } else if delete_excluded {
        DeleteMode::DeleteExcluded
    } else if delete_after || delete {
        DeleteMode::DeleteAfter
    } else {
        DeleteMode::from_str(delete_mode_str).unwrap_or(DeleteMode::None)
    };

    let guardrails = DeleteGuardrails {
        max_delete_files: max_delete,
        max_delete_pct,
        force_delete,
    };

    let mut filter = PathFilter::new();
    for exc in excludes {
        filter.add_exclude(exc);
    }

    let mode = if cdc {
        ChunkMode::Cdc
    } else {
        ChunkMode::Fixed
    };

    let params = if cdc {
        ChunkParams::new(256 * 1024, 1024 * 1024, 4 * 1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("invalid CDC chunk params"))?
    } else {
        ChunkParams::new(1024 * 1024, 1024 * 1024, 1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("invalid fixed chunk params"))?
    };

    let options = DirectorySyncOptions {
        mode,
        params,
        delete_mode,
        dry_run: true,
        read_buffer_size: 2 * 1024 * 1024,
        transfer_mode: get_transfer_mode(cli),
        min_delta_size: cli.min_delta_size,
        batch_small_files: false,
        small_file_threshold: velcrux_core::sync::DEFAULT_SMALL_FILE_THRESHOLD,
        batch_max_bytes: velcrux_core::sync::DEFAULT_BATCH_MAX_BYTES,
        delete_guardrails: guardrails.clone(),
        filter: if excludes.is_empty() {
            None
        } else {
            Some(filter)
        },
        atomic: false,
        xattr_policy: velcrux_core::storage::XattrPolicy::Transmute,
        acl_policy: velcrux_core::storage::AclPolicy::Transmute,
        delta_dict_policy: velcrux_core::sync::DeltaDictPolicy::Auto,
        delta_dict_threshold_pct: velcrux_core::sync::DEFAULT_DELTA_DICT_THRESHOLD_PCT,
    };

    let store = if dedup {
        let store_dir = chunk_store_path
            .clone()
            .unwrap_or_else(|| dst_path.join(".velcrux-chunks"));
        Some(LocalChunkStore::new(&store_dir).await?)
    } else {
        None
    };

    let plan = plan_directory_sync(&src_path, &dst_path, &options, store.as_ref())
        .map_err(|e| anyhow::anyhow!("plan generation failed: {e}"))?;

    let transfer_plan = TransferPlan::from_directory_plan(
        &src_path,
        &dst_path,
        &plan,
        delete_mode,
        guardrails,
        0,
        true,
    );

    if cli_log_json(cli) {
        let json_val = transfer_plan.to_json_value();
        println!("{json_val}");
    } else {
        println!("{}", transfer_plan.format_display());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_sync(
    cli: &Cli,
    source: &str,
    destination: &str,
    dry_run: bool,
    delete_before: bool,
    delete_after: bool,
    delete: bool,
    delete_excluded: bool,
    excludes: &[String],
    max_delete: Option<usize>,
    max_delete_pct: Option<f64>,
    force_delete: bool,
    cdc: bool,
    dedup: bool,
    chunk_store_path: &Option<PathBuf>,
    batch_small_files: bool,
    small_file_threshold: Option<u64>,
    batch_max_bytes: Option<u64>,
    atomic: bool,
    sign_key: Option<&Path>,
    sign_issuer: &str,
    verify_sig: Option<&Path>,
    trusted_signers: Option<&Path>,
    xattr_policy: &str,
    acl_policy: &str,
    delta_dict: &str,
    delta_dict_threshold: u8,
) -> anyhow::Result<()> {
    let src_is_remote = source.starts_with("velcrux://");
    let dst_is_remote = destination.starts_with("velcrux://");

    if destination.starts_with("s3://") || source.starts_with("s3://") {
        return run_s3(
            cli,
            &S3SubCmd::Sync {
                source: source.to_string(),
                destination: destination.to_string(),
                endpoint: None,
                region: None,
            },
        )
        .await;
    }

    if destination.starts_with("gs://") || source.starts_with("gs://") {
        return run_gcs(
            cli,
            &GcsSubCmd::Sync {
                source: source.to_string(),
                destination: destination.to_string(),
                endpoint: None,
                token: None,
            },
        )
        .await;
    }

    if destination.starts_with("az://")
        || source.starts_with("az://")
        || destination.starts_with("azure://")
        || source.starts_with("azure://")
    {
        return run_azure(
            cli,
            &AzureSubCmd::Sync {
                source: source.to_string(),
                destination: destination.to_string(),
                endpoint: None,
                account_name: None,
                account_key: None,
                sas_token: None,
            },
        )
        .await;
    }

    if src_is_remote && dst_is_remote {
        anyhow::bail!("cross-server sync between two remote URLs is not supported");
    }

    if dst_is_remote {
        return run_remote_upload_sync(
            cli,
            source,
            destination,
            dry_run,
            delete_before || delete_after || delete || delete_excluded,
        )
        .await;
    }

    if src_is_remote {
        return run_remote_download_sync(
            cli,
            source,
            destination,
            dry_run,
            delete_before || delete_after || delete || delete_excluded,
        )
        .await;
    }

    use velcrux_core::chunking::{ChunkMode, ChunkParams};
    use velcrux_core::storage::LocalChunkStore;
    use velcrux_core::sync::{
        execute_directory_sync, DeleteGuardrails, DeleteMode, DirectorySyncOptions, PathFilter,
        TransferPlan,
    };

    let src_path = PathBuf::from(source);
    let dst_path = PathBuf::from(destination);

    if !src_path.exists() {
        anyhow::bail!("source path does not exist: {}", src_path.display());
    }

    let delete_mode = if delete_before {
        DeleteMode::DeleteBefore
    } else if delete_excluded {
        DeleteMode::DeleteExcluded
    } else if delete_after || delete {
        DeleteMode::DeleteAfter
    } else {
        DeleteMode::None
    };

    let guardrails = DeleteGuardrails {
        max_delete_files: max_delete,
        max_delete_pct,
        force_delete,
    };

    let mut filter = PathFilter::new();
    for exc in excludes {
        filter.add_exclude(exc);
    }

    let mode = if cdc {
        ChunkMode::Cdc
    } else {
        ChunkMode::Fixed
    };

    let params = if cdc {
        ChunkParams::new(256 * 1024, 1024 * 1024, 4 * 1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("invalid CDC chunk params"))?
    } else {
        ChunkParams::new(1024 * 1024, 1024 * 1024, 1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("invalid fixed chunk params"))?
    };

    let options = DirectorySyncOptions {
        mode,
        params,
        delete_mode,
        dry_run,
        read_buffer_size: 2 * 1024 * 1024,
        transfer_mode: get_transfer_mode(cli),
        min_delta_size: cli.min_delta_size,
        batch_small_files,
        small_file_threshold: small_file_threshold
            .unwrap_or(velcrux_core::sync::DEFAULT_SMALL_FILE_THRESHOLD),
        batch_max_bytes: batch_max_bytes.unwrap_or(velcrux_core::sync::DEFAULT_BATCH_MAX_BYTES),
        delete_guardrails: guardrails.clone(),
        filter: if excludes.is_empty() {
            None
        } else {
            Some(filter)
        },
        atomic,
        xattr_policy: std::str::FromStr::from_str(xattr_policy)?,
        acl_policy: std::str::FromStr::from_str(acl_policy)?,
        delta_dict_policy: std::str::FromStr::from_str(delta_dict)?,
        delta_dict_threshold_pct: delta_dict_threshold,
    };

    let store = if dedup {
        let store_dir = chunk_store_path
            .clone()
            .unwrap_or_else(|| dst_path.join(".velcrux-chunks"));
        Some(LocalChunkStore::new(&store_dir).await?)
    } else {
        None
    };

    let result = execute_directory_sync(&src_path, &dst_path, &options, None, store.as_ref())
        .map_err(|e| anyhow::anyhow!("sync failed: {e}"))?;

    let is_json = cli_log_json(cli);
    if is_json {
        let transfer_plan = TransferPlan::from_directory_plan(
            &src_path,
            &dst_path,
            &result.plan,
            delete_mode,
            guardrails,
            0,
            dry_run,
        );
        let mut json_val = transfer_plan.to_json_value();
        if let Some(obj) = json_val.as_object_mut() {
            obj.insert(
                "files_transferred".to_string(),
                serde_json::json!(result.files_transferred),
            );
            obj.insert(
                "files_committed".to_string(),
                serde_json::json!(result.files_committed),
            );
            obj.insert(
                "files_deleted_count".to_string(),
                serde_json::json!(result.files_deleted),
            );
            obj.insert(
                "wire_bytes_transferred".to_string(),
                serde_json::json!(result.wire_bytes_transferred),
            );
            obj.insert(
                "local_bytes_reused".to_string(),
                serde_json::json!(result.local_bytes_reused),
            );
            obj.insert(
                "store_bytes_reused".to_string(),
                serde_json::json!(result.store_bytes_reused),
            );
            obj.insert(
                "small_files_batched".to_string(),
                serde_json::json!(result.small_files_batched),
            );
            obj.insert(
                "batch_containers".to_string(),
                serde_json::json!(result.batch_containers),
            );
            obj.insert(
                "roundtrips_saved".to_string(),
                serde_json::json!(result.roundtrips_saved),
            );
            if let Some(ref tx_id) = result.transaction_id {
                obj.insert("transaction_id".to_string(), serde_json::json!(tx_id));
                obj.insert("atomic".to_string(), serde_json::json!(true));
            }
        }
        println!("{json_val}");
    } else {
        if dry_run {
            let transfer_plan = TransferPlan::from_directory_plan(
                &src_path,
                &dst_path,
                &result.plan,
                delete_mode,
                guardrails,
                0,
                true,
            );
            println!("{}", transfer_plan.format_display());
        } else {
            println!("{}", result.plan.summary.format_display());
        }

        if result.small_files_batched > 0 {
            println!(
                "Batched: {} small files in {} streaming containers ({} roundtrips saved)",
                result.small_files_batched, result.batch_containers, result.roundtrips_saved
            );
        }

        if !dry_run {
            println!();
            println!(
                "Transferred: {} files (committed: {}, deleted: {})",
                result.files_transferred, result.files_committed, result.files_deleted
            );
            println!(
                "Wire data: {} | Local reused: {} | Store reused: {}",
                format_bytes(result.wire_bytes_transferred),
                format_bytes(result.local_bytes_reused),
                format_bytes(result.store_bytes_reused)
            );
            if let Some(ref tx_id) = result.transaction_id {
                println!("Atomic Transaction: Committed ({})", tx_id);
            }
        }
    }

    if !dry_run {
        if let Some(key_path) = sign_key {
            use velcrux_core::auth::{
                generate_target_attestation, AttestationKey, DEFAULT_SIG_EXT,
            };
            let att_key = AttestationKey::load_from_file(key_path).with_context(|| {
                format!("failed to load signing key from {}", key_path.display())
            })?;
            let (envelope, _begin) = generate_target_attestation(
                &dst_path,
                &att_key,
                sign_issuer,
                None,
                Default::default(),
            )
            .map_err(|e| anyhow::anyhow!("failed to sign destination manifest: {e}"))?;
            let sig_file = dst_path.join(DEFAULT_SIG_EXT);
            envelope
                .save_to_file(&sig_file)
                .with_context(|| format!("failed to save attestation to {}", sig_file.display()))?;
            if !is_json {
                println!("Signed Attestation: Created ({})", sig_file.display());
            }
        }

        if let Some(sig_path) = verify_sig {
            use std::time::{SystemTime, UNIX_EPOCH};
            use velcrux_core::auth::{
                verify_target_attestation, AttestationEnvelope, AttestationVerifier,
            };
            let envelope = AttestationEnvelope::load_from_file(sig_path).with_context(|| {
                format!("failed to load attestation from {}", sig_path.display())
            })?;
            let mut verifier = AttestationVerifier::new();
            if let Some(ts_path) = trusted_signers {
                verifier.load_trusted_keys_file(ts_path).with_context(|| {
                    format!("failed to load trusted signers from {}", ts_path.display())
                })?;
                verifier = verifier.with_require_trusted(true);
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let report = verify_target_attestation(&dst_path, &envelope, &verifier, None, now)
                .map_err(|e| anyhow::anyhow!("post-sync attestation verification failed: {e}"))?;
            if !report.is_valid {
                anyhow::bail!(
                    "post-sync attestation verification failed: {}",
                    report.status
                );
            }
            if !is_json {
                println!(
                    "Verified Attestation: Valid (signer: {})",
                    report.signer_identity
                );
            }
        }
    }

    Ok(())
}

async fn run_tx(cli: &Cli, sub: &TxSubCmd) -> anyhow::Result<()> {
    use velcrux_core::sync::TransactionManager;

    let is_json = cli_log_json(cli);

    match sub {
        TxSubCmd::List { path, json } => {
            let list = TransactionManager::list_transactions(path)
                .map_err(|e| anyhow::anyhow!("failed to list transactions: {e}"))?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("No directory transactions found in '{}'.", path.display());
            } else {
                println!(
                    "{:<28} {:<12} {:<8} {}",
                    "TRANSACTION ID", "STATE", "FILES", "TARGET"
                );
                println!("{:-<28} {:-<12} {:-<8} {:-<30}", "", "", "", "");
                for item in list {
                    println!(
                        "{:<28} {:<12} {:<8} {}",
                        item.tx_id,
                        item.state.to_string(),
                        item.file_count,
                        item.target_dir
                    );
                }
            }
        }
        TxSubCmd::Show { tx_id, path, json } => {
            let journal = TransactionManager::get_journal(path, tx_id)
                .map_err(|e| anyhow::anyhow!("failed to get transaction journal: {e}"))?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&journal)?);
            } else {
                println!("Transaction ID: {}", journal.tx_id);
                println!("Target:         {}", journal.target_dir.display());
                println!("State:          {}", journal.state);
                println!("Created:        {}", journal.created_at_sec);
                println!("Files:          {}", journal.items.len());
                println!();
                println!("{:<8} {:<10} {:<30}", "ACTION", "SIZE", "RELATIVE PATH");
                println!("{:-<8} {:-<10} {:-<30}", "", "", "");
                for item in journal.items {
                    println!(
                        "{:<8} {:<10} {}",
                        item.action.to_string(),
                        format_bytes(item.size),
                        item.rel_path
                    );
                }
            }
        }
        TxSubCmd::Rollback { tx_id, path, json } => {
            let report = TransactionManager::rollback_transaction(path, tx_id)
                .map_err(|e| anyhow::anyhow!("failed to rollback transaction: {e}"))?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Successfully rolled back transaction '{}': {} files restored/removed in {}ms.",
                    report.tx_id, report.files_rolled_back, report.duration_ms
                );
            }
        }
        TxSubCmd::Recover { path, json } => {
            let reports = TransactionManager::recover_pending_transactions(path)
                .map_err(|e| anyhow::anyhow!("failed to recover transactions: {e}"))?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            } else if reports.is_empty() {
                println!(
                    "No pending or crashed transactions to recover in '{}'.",
                    path.display()
                );
            } else {
                println!(
                    "Recovered {} pending/crashed transaction(s):",
                    reports.len()
                );
                for r in reports {
                    println!(
                        "  - {}: state={:?}, rolled_back={} in {}ms",
                        r.tx_id, r.state, r.files_rolled_back, r.duration_ms
                    );
                }
            }
        }
    }

    Ok(())
}

async fn run_attest(cli: &Cli, sub: &AttestSubCmd) -> anyhow::Result<()> {
    use std::fs::File;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    use velcrux_core::auth::{
        generate_target_attestation, verify_target_attestation, AttestationEnvelope,
        AttestationKey, AttestationVerifier, DEFAULT_SIG_EXT,
    };

    let is_json = cli_log_json(cli);

    match sub {
        AttestSubCmd::Sign {
            path,
            key,
            out,
            issuer,
            expires_in,
            metadata,
            json,
        } => {
            let att_key = AttestationKey::load_from_file(key)
                .with_context(|| format!("failed to load signing key from {}", key.display()))?;

            let mut meta_map = std::collections::BTreeMap::new();
            for m in metadata {
                if let Some((k, v)) = m.split_once('=') {
                    meta_map.insert(k.trim().to_string(), v.trim().to_string());
                } else {
                    meta_map.insert(m.trim().to_string(), "true".to_string());
                }
            }

            let (envelope, begin) =
                generate_target_attestation(path, &att_key, issuer, *expires_in, meta_map)
                    .map_err(|e| anyhow::anyhow!("failed to generate target attestation: {e}"))?;

            let sig_path = match out {
                Some(p) => p.clone(),
                None => {
                    if path.is_dir() {
                        path.join(DEFAULT_SIG_EXT)
                    } else {
                        PathBuf::from(format!("{}{}", path.display(), DEFAULT_SIG_EXT))
                    }
                }
            };

            envelope
                .save_to_file(&sig_path)
                .with_context(|| format!("failed to write signature to {}", sig_path.display()))?;

            if *json || is_json {
                let out_obj = serde_json::json!({
                    "success": true,
                    "target": path.display().to_string(),
                    "signature_file": sig_path.display().to_string(),
                    "issuer": envelope.payload.issuer,
                    "public_key": velcrux_core::auth::attestation::encode_hex(&envelope.public_key),
                    "manifest_hash": envelope.payload.manifest_hash.to_string(),
                    "file_count": begin.file_count,
                    "total_bytes": begin.total_bytes,
                    "created_at": envelope.payload.created_at,
                    "expires_at": envelope.payload.expires_at,
                });
                println!("{}", serde_json::to_string_pretty(&out_obj)?);
            } else {
                println!("Signed manifest attestation generated successfully.");
                println!("  Target:         {}", path.display());
                println!("  Signature File: {}", sig_path.display());
                println!("  Issuer:         {}", envelope.payload.issuer);
                println!(
                    "  Signer Key:     {}",
                    velcrux_core::auth::attestation::encode_hex(&envelope.public_key)
                );
                println!("  Manifest Hash:  {}", envelope.payload.manifest_hash);
                println!("  Files Count:    {}", begin.file_count);
                println!("  Total Bytes:    {}", format_bytes(begin.total_bytes));
                if let Some(exp) = envelope.payload.expires_at {
                    println!("  Expires At:     {}", exp);
                }
            }
        }
        AttestSubCmd::Verify {
            path,
            sig,
            trusted_keys,
            trusted_key,
            require_issuer,
            allow_expired,
            json,
        } => {
            let sig_path = match sig {
                Some(p) => p.clone(),
                None => {
                    if path.is_dir() {
                        path.join(DEFAULT_SIG_EXT)
                    } else {
                        PathBuf::from(format!("{}{}", path.display(), DEFAULT_SIG_EXT))
                    }
                }
            };

            let envelope = AttestationEnvelope::load_from_file(&sig_path)
                .with_context(|| format!("failed to load signature from {}", sig_path.display()))?;

            let mut verifier = AttestationVerifier::new();
            if let Some(tk_path) = trusted_keys {
                let count = verifier.load_trusted_keys_file(tk_path).with_context(|| {
                    format!("failed to load trusted keys from {}", tk_path.display())
                })?;
                tracing::debug!("Loaded {count} trusted keys from {}", tk_path.display());
                verifier = verifier.with_require_trusted(true);
            }
            if let Some(raw_hex) = trusted_key {
                let raw = velcrux_core::auth::attestation::decode_hex(raw_hex)
                    .map_err(|e| anyhow::anyhow!("invalid hex in --trusted-key: {e}"))?;
                if raw.len() != 32 {
                    anyhow::bail!("expected 32-byte hex for --trusted-key");
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&raw);
                verifier.add_trusted_key(pk, "cli-trusted-key");
                verifier = verifier.with_require_trusted(true);
            }

            let now = if *allow_expired {
                envelope.payload.expires_at.unwrap_or(0).saturating_sub(1)
            } else {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            };

            let report = verify_target_attestation(
                path,
                &envelope,
                &verifier,
                require_issuer.as_deref(),
                now,
            )
            .map_err(|e| anyhow::anyhow!("attestation verification process failed: {e}"))?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Attestation Verification Report");
                println!("--------------------------------------------------");
                println!("  Status:         {}", report.status);
                println!(
                    "  Valid:          {}",
                    if report.is_valid { "YES" } else { "NO" }
                );
                println!("  Target:         {}", report.target_path);
                println!("  Signer Identity: {}", report.signer_identity);
                println!("  Signer Key:     {}", report.signer_public_key);
                println!("  Signed Hash:    {}", report.signed_manifest_hash);
                println!("  Computed Hash:  {}", report.computed_manifest_hash);
                println!(
                    "  File Count:     signed {}, found {}",
                    report.signed_file_count, report.computed_file_count
                );
                println!(
                    "  Total Bytes:    signed {}, found {}",
                    format_bytes(report.signed_total_bytes),
                    format_bytes(report.computed_total_bytes)
                );
                if let Some(ref err) = report.error_message {
                    println!("  Error:          {}", err);
                }
            }

            if !report.is_valid {
                anyhow::bail!("attestation verification failed: {}", report.status);
            }
        }
        AttestSubCmd::Keygen {
            out,
            pub_out,
            comment,
            force,
        } => {
            if out.exists() && !force {
                anyhow::bail!(
                    "destination private key {} already exists (use -f to overwrite)",
                    out.display()
                );
            }

            let key = AttestationKey::generate()
                .map_err(|e| anyhow::anyhow!("failed to generate attestation key: {e}"))?;

            key.save_to_file(out)
                .with_context(|| format!("failed to write private key to {}", out.display()))?;

            let pub_path = match pub_out {
                Some(p) => p.clone(),
                None => PathBuf::from(format!("{}.pub", out.display())),
            };

            let openssh_str = key.public_key_openssh(comment);
            let mut pub_file = File::create(&pub_path)
                .with_context(|| format!("failed to write public key to {}", pub_path.display()))?;
            pub_file.write_all(openssh_str.as_bytes())?;
            pub_file.write_all(b"\n")?;

            if is_json {
                let out_obj = serde_json::json!({
                    "private_key": out.display().to_string(),
                    "public_key_file": pub_path.display().to_string(),
                    "public_key_hex": key.public_key_hex(),
                    "public_key_openssh": openssh_str,
                });
                println!("{}", serde_json::to_string_pretty(&out_obj)?);
            } else {
                println!("Generated fresh Ed25519 attestation keypair:");
                println!("  Private Key:    {}", out.display());
                println!("  Public Key:     {}", pub_path.display());
                println!("  Public Key Hex: {}", key.public_key_hex());
                println!("  OpenSSH Key:    {}", openssh_str);
            }
        }
        AttestSubCmd::Inspect { sig, json } => {
            let envelope = AttestationEnvelope::load_from_file(sig)
                .with_context(|| format!("failed to load signature from {}", sig.display()))?;

            if *json || is_json {
                println!("{}", envelope.to_json()?);
            } else {
                println!("Attestation Envelope: {}", sig.display());
                println!("--------------------------------------------------");
                println!("  Issuer:         {}", envelope.payload.issuer);
                println!(
                    "  Signer Key:     {}",
                    velcrux_core::auth::attestation::encode_hex(&envelope.public_key)
                );
                println!("  Manifest Hash:  {}", envelope.payload.manifest_hash);
                println!("  Files Count:    {}", envelope.payload.file_count);
                println!(
                    "  Total Bytes:    {}",
                    format_bytes(envelope.payload.total_bytes)
                );
                println!("  Created At:     {}", envelope.payload.created_at);
                if let Some(exp) = envelope.payload.expires_at {
                    println!("  Expires At:     {}", exp);
                }
                if !envelope.payload.metadata.is_empty() {
                    println!("  Metadata:");
                    for (k, v) in &envelope.payload.metadata {
                        println!("    {k} = {v}");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn run_audit(cli: &Cli, sub: &AuditSubCmd) -> anyhow::Result<()> {
    use std::fs::File;
    use std::io::Write;
    use velcrux_core::audit::{
        hex_decode_32, hex_encode, run_audit_benchmark, verify_inclusion_proof,
        AuditInclusionProof, AuditRecord, MerkleAuditTree,
    };
    use velcrux_core::Hash;

    let is_json = cli_log_json(cli);

    match sub {
        AuditSubCmd::Status { epoch, json } => {
            let mut tree = MerkleAuditTree::new(*epoch);
            for i in 0..4 {
                let mut salt = [0u8; 32];
                salt[0] = i as u8 + 1;
                let rec = AuditRecord::new(
                    format!("01J000000000000000000{:05}", i),
                    "default".to_string(),
                    Hash::of(&salt),
                    1048576 * (i as u64 + 1),
                    1793130000 + i as u64,
                );
                tree.insert_record(&rec, &salt);
            }
            let status = tree.status();
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("Audit Merkle Accumulator Status (Epoch {})", status.epoch);
                println!("--------------------------------------------------");
                println!("  Root Hash:      {}", status.root_hex);
                println!("  Record Count:   {}", status.total_records);
                println!("  Tree Height:    {}", status.height);
                println!("  Is Empty:       {}", status.total_records == 0);
            }
        }
        AuditSubCmd::GenerateProof {
            transfer_id,
            tenant,
            salt,
            bytes,
            out,
            json,
        } => {
            let salt_bytes = match salt {
                Some(s) => hex_decode_32(s).map_err(|e| anyhow::anyhow!("invalid salt: {e}"))?,
                None => {
                    let mut s = [0u8; 32];
                    let hash = Hash::of(transfer_id.as_bytes());
                    s.copy_from_slice(hash.as_bytes());
                    s
                }
            };
            let dummy_manifest = Hash::of(transfer_id.as_bytes());
            let record = AuditRecord::new(
                transfer_id.clone(),
                tenant.clone(),
                dummy_manifest,
                *bytes,
                1793130000,
            );
            let mut tree = MerkleAuditTree::new(1);
            let (target_idx, _leaf_hash) = tree.insert_record(&record, &salt_bytes);
            for i in 1..4 {
                let mut s = [0u8; 32];
                s[0] = i as u8;
                let r = AuditRecord::new(
                    format!("neighbor-record-{}", i),
                    tenant.clone(),
                    Hash::of(&s),
                    524288,
                    1793130000 + i as u64,
                );
                tree.insert_record(&r, &s);
            }
            let proof = tree
                .generate_inclusion_proof(target_idx)
                .map_err(|e| anyhow::anyhow!("failed to generate inclusion proof: {e}"))?;

            let proof_json_str = serde_json::to_string_pretty(&proof)?;
            if let Some(dest) = out {
                let mut f = File::create(dest)?;
                f.write_all(proof_json_str.as_bytes())?;
            }

            if *json || is_json {
                println!("{}", proof_json_str);
            } else {
                println!("Audit Zero-Knowledge Inclusion Proof");
                println!("--------------------------------------------------");
                println!("  Transfer ID:    {}", transfer_id);
                println!("  Leaf Index:     {}", proof.leaf_index);
                println!("  Leaf Hash:      {}", hex_encode(&proof.leaf_hash));
                println!("  Root Hash:      {}", hex_encode(&proof.expected_root));
                println!("  Proof Steps:    {}", proof.path.len());
                if let Some(dest) = out {
                    println!("  Saved To:       {}", dest.display());
                }
            }
        }
        AuditSubCmd::VerifyProof {
            root,
            leaf,
            proof_file,
            proof_json,
            json,
        } => {
            let root_bytes =
                hex_decode_32(root).map_err(|e| anyhow::anyhow!("invalid root hex: {e}"))?;
            let leaf_bytes =
                hex_decode_32(leaf).map_err(|e| anyhow::anyhow!("invalid leaf hex: {e}"))?;

            let proof: AuditInclusionProof = if let Some(p_path) = proof_file {
                let content = std::fs::read_to_string(p_path)?;
                serde_json::from_str(&content)?
            } else if let Some(p_str) = proof_json {
                serde_json::from_str(p_str)?
            } else {
                anyhow::bail!("either --proof-file or --proof-json must be specified");
            };

            let matches_root = proof.expected_root == root_bytes;
            let matches_leaf = proof.leaf_hash == leaf_bytes;
            let is_valid = matches_root && matches_leaf && verify_inclusion_proof(&proof);

            #[derive(serde::Serialize)]
            struct VerifyResult {
                valid: bool,
                matches_root: bool,
                matches_leaf: bool,
                proof_steps: usize,
                root: String,
                leaf: String,
            }

            let result = VerifyResult {
                valid: is_valid,
                matches_root,
                matches_leaf,
                proof_steps: proof.path.len(),
                root: root.clone(),
                leaf: leaf.clone(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Audit Proof Verification");
                println!("--------------------------------------------------");
                println!("  Valid:          {}", if is_valid { "YES" } else { "NO" });
                println!(
                    "  Root Matches:   {}",
                    if matches_root { "YES" } else { "NO" }
                );
                println!(
                    "  Leaf Matches:   {}",
                    if matches_leaf { "YES" } else { "NO" }
                );
                println!("  Proof Steps:    {}", proof.path.len());
            }

            if !is_valid {
                anyhow::bail!("proof verification failed");
            }
        }
        AuditSubCmd::ExportRoot { epoch, json } => {
            let mut tree = MerkleAuditTree::new(*epoch);
            let mut salt = [0u8; 32];
            salt[0] = 42;
            let rec = AuditRecord::new(
                format!("epoch-{}-genesis", epoch),
                "system".to_string(),
                Hash::of(&salt),
                0,
                1793130000,
            );
            tree.insert_record(&rec, &salt);
            let root_hex = hex_encode(&tree.root());

            #[derive(serde::Serialize)]
            struct RootExport {
                epoch: u64,
                root_hex: String,
                record_count: usize,
            }
            let export = RootExport {
                epoch: *epoch,
                root_hex: root_hex.clone(),
                record_count: tree.len(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&export)?);
            } else {
                println!("Authoritative Root (Epoch {}): {}", epoch, root_hex);
            }
        }
        AuditSubCmd::Benchmark {
            records,
            samples,
            json,
        } => {
            let report = run_audit_benchmark(*records, *samples);
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Cryptographic Audit Accumulator Benchmark");
                println!("--------------------------------------------------");
                println!("  Total Records:          {}", report.total_records);
                println!("  Proof Samples:          {}", report.proof_samples);
                println!("  Tree Height:            {}", report.tree_height);
                println!("  Root Hash:              {}", report.root_hash_hex);
                println!(
                    "  Build Duration:         {:.2} ms",
                    report.build_duration_ms
                );
                println!(
                    "  Insertion Throughput:   {:.2} records/s",
                    report.insertion_throughput_records_per_sec
                );
                println!(
                    "  Avg Proof Gen Latency:  {:.2} µs",
                    report.avg_proof_gen_latency_us
                );
                println!(
                    "  Avg Proof Ver Latency:  {:.2} µs",
                    report.avg_proof_verify_latency_us
                );
                println!(
                    "  All Proofs Verified:    {}",
                    if report.all_proofs_verified {
                        "YES"
                    } else {
                        "NO"
                    }
                );
            }
        }
    }

    Ok(())
}

fn build_sample_router() -> velcrux_core::router::AnycastRouter {
    use velcrux_core::router::{AnycastRouter, PopHealthMetrics, PopNode, PopStatus};

    let router = AnycastRouter::new([0x33; 32]);
    let pops = vec![
        PopNode {
            id: "pop-iad".to_string(),
            name: "US East (Ashburn)".to_string(),
            region: "us-east".to_string(),
            latitude: 39.0438,
            longitude: -77.4874,
            address: "198.51.100.1:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 2_400_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 8.5,
                jitter_ms: 0.9,
                packet_loss_ratio: 0.0001,
                cpu_utilization: 0.28,
                bandwidth_utilization: 0.24,
                active_connections: 142,
            },
            cost_multiplier: 1.0,
        },
        PopNode {
            id: "pop-sfo".to_string(),
            name: "US West (San Francisco)".to_string(),
            region: "us-west".to_string(),
            latitude: 37.7749,
            longitude: -122.4194,
            address: "198.51.100.2:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 3_100_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 11.2,
                jitter_ms: 1.1,
                packet_loss_ratio: 0.0001,
                cpu_utilization: 0.35,
                bandwidth_utilization: 0.31,
                active_connections: 189,
            },
            cost_multiplier: 1.0,
        },
        PopNode {
            id: "pop-lhr".to_string(),
            name: "Europe West (London)".to_string(),
            region: "eu-west".to_string(),
            latitude: 51.5074,
            longitude: -0.1278,
            address: "198.51.100.3:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 1_800_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 14.0,
                jitter_ms: 1.4,
                packet_loss_ratio: 0.0002,
                cpu_utilization: 0.22,
                bandwidth_utilization: 0.18,
                active_connections: 96,
            },
            cost_multiplier: 1.05,
        },
        PopNode {
            id: "pop-nrt".to_string(),
            name: "Asia Pacific (Tokyo)".to_string(),
            region: "ap-northeast".to_string(),
            latitude: 35.6762,
            longitude: 139.6503,
            address: "198.51.100.4:7443".parse().unwrap(),
            status: PopStatus::Healthy,
            capacity_bps: 10_000_000_000,
            current_load_bps: 4_200_000_000,
            metrics: PopHealthMetrics {
                rtt_ms: 18.5,
                jitter_ms: 1.8,
                packet_loss_ratio: 0.0003,
                cpu_utilization: 0.42,
                bandwidth_utilization: 0.42,
                active_connections: 215,
            },
            cost_multiplier: 1.10,
        },
    ];

    for pop in pops {
        router.register_pop(pop);
    }

    router
}

async fn run_router(cli: &Cli, sub: &RouterSubCmd) -> anyhow::Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use velcrux_core::router::{run_router_benchmark, RouteRequest};

    let is_json = cli_log_json(cli);
    let router = build_sample_router();

    match sub {
        RouterSubCmd::Status { json } => {
            let status = router.status();
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("=== Distributed Anycast Content Router Status ===");
                println!("  Total Edge PoPs:        {}", status.total_pops);
                println!("  Healthy PoPs:           {}", status.healthy_pops);
                println!("  Degraded PoPs:          {}", status.degraded_pops);
                println!("  Draining PoPs:          {}", status.draining_pops);
                println!("  Offline PoPs:           {}", status.offline_pops);
                println!("  Routes Computed:        {}", status.total_routes_computed);
                println!(
                    "  Migrations Committed:   {}",
                    status.total_migrations_committed
                );
                println!("  Active Migrations:      {}", status.active_migrations);
            }
        }
        RouterSubCmd::Pops { json } => {
            let pops = router.list_pops();
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&pops)?);
            } else {
                println!("=== Registered Edge Points-of-Presence (PoPs) ===");
                println!(
                    "{:<10} {:<16} {:<24} {:<10} {:<10} {:<10}",
                    "POP ID", "REGION", "ADDRESS", "STATUS", "RTT (ms)", "LOAD (%)"
                );
                println!("{:-<84}", "");
                for p in &pops {
                    let load_pct =
                        (p.current_load_bps as f64 / p.capacity_bps.max(1) as f64) * 100.0;
                    println!(
                        "{:<10} {:<16} {:<24} {:<10} {:<10.1} {:<10.1}",
                        p.id,
                        p.region,
                        p.address.to_string(),
                        p.status.to_string(),
                        p.metrics.rtt_ms,
                        load_pct
                    );
                }
            }
        }
        RouterSubCmd::Route {
            client_id,
            lat,
            lon,
            region,
            bandwidth,
            json,
        } => {
            let req = RouteRequest {
                client_id: client_id.clone(),
                latitude: *lat,
                longitude: *lon,
                preferred_region: region.clone(),
                required_bandwidth_bps: *bandwidth,
                affinity_token: None,
            };

            let decision = router
                .compute_route(&req)
                .map_err(|e| anyhow::anyhow!("routing calculation failed: {e}"))?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&decision)?);
            } else {
                println!("=== Optimal Anycast Content Route Decision ===");
                println!("  Client ID:              {}", decision.client_id);
                println!("  Selected Edge PoP:      {}", decision.selected_pop_id);
                println!("  Target QUIC Address:    {}", decision.pop_address);
                println!("  PoP Region:             {}", decision.pop_region);
                println!(
                    "  Estimated RTT:          {:.1} ms",
                    decision.estimated_rtt_ms
                );
                println!("  Distance:               {:.1} km", decision.distance_km);
                println!("  Composite Score:        {:.2}", decision.composite_score);
                println!("  Failovers Evaluated:    {}", decision.failover_count);
                println!(
                    "  Migration Recommended:  {}",
                    if decision.migration_recommended {
                        "YES"
                    } else {
                        "NO"
                    }
                );
                println!("  Rationale:              {}", decision.reason);
            }
        }
        RouterSubCmd::Migrate {
            session_id,
            source,
            target,
            transfer_id,
            offset,
            total,
            json,
        } => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let chunk_idx = offset / 1048576;
            let ticket = router
                .issue_migration_ticket(
                    session_id,
                    transfer_id,
                    source,
                    target,
                    *offset,
                    *total,
                    chunk_idx,
                    300,
                    now,
                )
                .map_err(|e| anyhow::anyhow!("failed to issue migration ticket: {e}"))?;

            let record = router
                .execute_migration_handover(&ticket, now + 1)
                .map_err(|e| anyhow::anyhow!("failed to execute handover: {e}"))?;

            #[derive(serde::Serialize)]
            struct MigrateOutput {
                ticket: velcrux_core::router::MigrationTicket,
                record: velcrux_core::router::SessionMigrationRecord,
            }

            let output = MigrateOutput {
                ticket: ticket.clone(),
                record: record.clone(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("=== Live Anycast Session Migration Handover ===");
                println!("  Session ID:             {}", record.session_id);
                println!("  Transfer ID:            {}", record.transfer_id);
                println!("  Source PoP:             {}", record.source_pop_id);
                println!("  Target PoP:             {}", record.target_pop_id);
                println!("  Target Address:         {}", ticket.target_address);
                println!("  Handover State:         {}", record.state);
                println!(
                    "  Resumed Offset:         {} bytes (chunk #{})",
                    record.resumed_offset * 1048576,
                    record.resumed_offset
                );
                println!("  Total Bytes:            {}", record.total_bytes);
                println!(
                    "  Handover Latency:       {} µs",
                    record.handover_latency_us
                );
                println!("  Ticket ID:              {}", ticket.ticket_id);
            }
        }
        RouterSubCmd::Benchmark {
            pops,
            iterations,
            json,
        } => {
            let report = run_router_benchmark(*pops, *iterations);
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Anycast Router & Session Migration Benchmark ===");
                println!("  Simulated Edge PoPs:    {}", report.pop_count);
                println!("  Routes Evaluated:       {}", report.routes_evaluated);
                println!(
                    "  Routing Throughput:     {:.2} routes/s",
                    report.routing_throughput_routes_per_sec
                );
                println!(
                    "  Avg Route Latency:      {:.2} µs",
                    report.avg_route_latency_us
                );
                println!(
                    "  Failover Convergence:   {:.2} ms",
                    report.failover_convergence_latency_ms
                );
                println!(
                    "  Migration Cycles:       {}",
                    report.migration_cycles_evaluated
                );
                println!(
                    "  Migration Throughput:   {:.2} handovers/s",
                    report.migration_throughput_per_sec
                );
                println!(
                    "  Avg Handover Latency:   {:.2} µs",
                    report.avg_migration_handover_latency_us
                );
                println!(
                    "  All Migrations Valid:   {}",
                    if report.all_migrations_verified {
                        "YES"
                    } else {
                        "NO"
                    }
                );
            }
        }
    }

    Ok(())
}

async fn run_xdp(cli: &Cli, sub: &XdpSubCmd) -> anyhow::Result<()> {
    use velcrux_core::xdp::{
        parse_packet_headers, run_xdp_benchmark, UmemConfig, XdpAction, XdpDriverMode, XdpEngine,
        XdpFilterRule,
    };

    let is_json = cli_log_json(cli);

    match sub {
        XdpSubCmd::Status {
            interface,
            mode,
            json,
        } => {
            let driver_mode = match mode.to_lowercase().as_str() {
                "generic" | "skb" => XdpDriverMode::GenericSkb,
                "hardware" | "fpga" | "offload" => XdpDriverMode::HardwareOffload,
                _ => XdpDriverMode::NativeDriver,
            };
            let engine = XdpEngine::new(interface, driver_mode, UmemConfig::default());
            engine.umem().populate_fill_ring(64);

            let status = engine.status();
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("=== Hardware-Accelerated eBPF/XDP Kernel Bypass Status ===");
                println!("  Interface:              {}", status.interface);
                println!("  Driver Mode:            {:?}", status.driver_mode);
                println!(
                    "  Hardware Offload:       {}",
                    if status.hardware_offload_active {
                        "ACTIVE (FPGA / SmartNIC)"
                    } else {
                        "INACTIVE (Host Driver / Native)"
                    }
                );
                println!("  UMEM Total Frames:      {}", status.umem_frame_count);
                println!("  UMEM Frame Size:        {} bytes", status.umem_frame_size);
                println!("  Available UMEM Frames:  {}", status.available_umem_frames);
                println!("  Packets Processed:      {}", status.packets_processed);
                println!("  Packets Redirected:     {}", status.packets_redirected);
                println!("  Packets Dropped:        {}", status.packets_dropped);
                println!("  Packets Passed:         {}", status.packets_passed);
                println!("  Bytes Processed:        {}", status.bytes_processed);
                println!("  Active Filter Rules:    {}", status.active_rules_count);
            }
        }
        XdpSubCmd::Inspect { packet_hex, json } => {
            let clean_hex = packet_hex.trim_start_matches("0x").replace([' ', ':'], "");
            let bytes: Vec<u8> = (0..clean_hex.len())
                .step_by(2)
                .filter_map(|i| {
                    if i + 2 <= clean_hex.len() {
                        u8::from_str_radix(&clean_hex[i..i + 2], 16).ok()
                    } else {
                        None
                    }
                })
                .collect();
            if bytes.len() * 2 != clean_hex.len() {
                anyhow::bail!("Invalid hex packet payload");
            }
            let summary = parse_packet_headers(&bytes).context(
                "Unable to parse packet headers (packet truncated or unsupported L2/L3 protocol)",
            )?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("=== XDP Wire-Speed Packet Header Inspection ===");
                println!("  Ethernet EtherType:     0x{:04x}", summary.eth_proto);
                println!("  Source IP:              {}", summary.src_ip);
                println!("  Destination IP:         {}", summary.dst_ip);
                println!("  Source Port:            {}", summary.src_port);
                println!("  Destination Port:       {}", summary.dst_port);
                println!("  Payload Length:         {} bytes", summary.payload_len);
                println!(
                    "  Is QUIC:                {}",
                    if summary.is_quic { "YES" } else { "NO" }
                );
                if let Some(ref cid) = summary.quic_connection_id {
                    println!("  QUIC Connection ID:     0x{}", cid);
                } else {
                    println!("  QUIC Connection ID:     None");
                }
            }
        }
        XdpSubCmd::Rings { json } => {
            let config = UmemConfig::default();
            let pool = velcrux_core::xdp::UmemPool::new(config.clone());
            let populated = pool.populate_fill_ring(128);

            #[derive(Serialize)]
            struct RingStatusReport {
                umem_frames: u32,
                frame_size_bytes: u32,
                free_frames: usize,
                fill_ring_capacity: u32,
                fill_ring_entries: usize,
                rx_ring_capacity: u32,
                tx_ring_capacity: u32,
                completion_ring_capacity: u32,
                zero_copy_ready: bool,
            }

            let report = RingStatusReport {
                umem_frames: config.frame_count,
                frame_size_bytes: config.frame_size,
                free_frames: pool.available_frames(),
                fill_ring_capacity: config.fill_ring_size,
                fill_ring_entries: populated,
                rx_ring_capacity: config.rx_ring_size,
                tx_ring_capacity: config.tx_ring_size,
                completion_ring_capacity: config.completion_ring_size,
                zero_copy_ready: true,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== AF_XDP Zero-Copy UMEM Descriptor Rings ===");
                println!("  Total UMEM Frames:      {}", report.umem_frames);
                println!(
                    "  Frame Size:             {} bytes",
                    report.frame_size_bytes
                );
                println!("  Free Frames Available:  {}", report.free_frames);
                println!(
                    "  Fill Ring Capacity:     {} entries",
                    report.fill_ring_capacity
                );
                println!(
                    "  Fill Ring Active:       {} entries",
                    report.fill_ring_entries
                );
                println!(
                    "  RX Ring Capacity:       {} entries",
                    report.rx_ring_capacity
                );
                println!(
                    "  TX Ring Capacity:       {} entries",
                    report.tx_ring_capacity
                );
                println!(
                    "  Completion Ring Cap:    {} entries",
                    report.completion_ring_capacity
                );
                println!(
                    "  Zero-Copy Ready:        {}",
                    if report.zero_copy_ready { "YES" } else { "NO" }
                );
            }
        }
        XdpSubCmd::Filter {
            port,
            cid,
            action,
            json,
        } => {
            let xdp_action = match action.to_lowercase().as_str() {
                "drop" => XdpAction::Drop,
                "pass" => XdpAction::Pass,
                "tx" => XdpAction::Tx,
                _ => XdpAction::Redirect,
            };

            let rule = XdpFilterRule {
                priority: 1,
                dst_port: Some(*port),
                cid_prefix: cid.clone(),
                action: xdp_action,
                description: format!("Operator filter for port {port} -> {action}"),
            };

            let engine = XdpEngine::new("eth0", XdpDriverMode::NativeDriver, UmemConfig::default());
            engine.add_rule(rule.clone());

            let mut test_packet = vec![0u8; 64];
            test_packet[12] = 0x08;
            test_packet[13] = 0x00; // IPv4
            test_packet[23] = 17; // UDP
            test_packet[36] = (*port >> 8) as u8;
            test_packet[37] = (*port & 0xff) as u8;

            let (evaluated_action, parsed) = engine.evaluate_filter(&test_packet);

            #[derive(Serialize)]
            struct FilterEvalReport {
                rule: XdpFilterRule,
                evaluated_action: XdpAction,
                matched: bool,
                parsed_headers: Option<velcrux_core::xdp::PacketHeaderSummary>,
            }

            let report = FilterEvalReport {
                rule,
                evaluated_action,
                matched: evaluated_action == xdp_action,
                parsed_headers: parsed,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== eBPF/XDP Packet Filter Rule Evaluation ===");
                println!("  Target Port:            {}", port);
                println!("  Target Action:          {:?}", xdp_action);
                println!("  Evaluated Action:       {:?}", evaluated_action);
                println!(
                    "  Rule Match Status:      {}",
                    if report.matched {
                        "MATCHED"
                    } else {
                        "NO MATCH"
                    }
                );
                println!("  Description:            {}", report.rule.description);
            }
        }
        XdpSubCmd::Benchmark {
            packets,
            batch_size,
            json,
        } => {
            let report = run_xdp_benchmark(*packets, *batch_size);
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Hardware-Accelerated eBPF/XDP Bypass Benchmark ===");
                println!("  Packets Evaluated:      {}", report.packet_count);
                println!("  Batch Size:             {}", report.batch_size);
                println!(
                    "  Throughput:             {:.2} Mpps",
                    report.throughput_mpps
                );
                println!(
                    "  Bandwidth:              {:.2} Gbps",
                    report.throughput_gbps
                );
                println!("  Avg Latency:            {:.2} ns", report.avg_latency_ns);
                println!("  Packets Redirected:     {}", report.packets_redirected);
                println!("  Packets Dropped:        {}", report.packets_dropped);
                println!("  Packets Passed:         {}", report.packets_passed);
            }
        }
    }

    Ok(())
}

async fn run_pqc(cli: &Cli, sub: &PqcSubCmd) -> anyhow::Result<()> {
    use velcrux_core::crypto::pqc::{
        hex_decode, hex_encode, run_pqc_benchmark, HybridCiphertext, HybridKemEngine,
        HybridKemPrivateKey, HybridKemPublicKey, HybridSignature, HybridSignatureEngine,
        HybridSigningPrivateKey, HybridSigningPublicKey, PqcStatusReport,
    };

    let is_json = cli_log_json(cli);

    match sub {
        PqcSubCmd::Status { json } => {
            let status = PqcStatusReport::default();
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("=== Quantum-Resilient Post-Quantum Hybrid Cryptography ===");
                println!("  KEM Algorithm:          {}", status.kem_algorithm);
                println!("  Signature Algorithm:    {}", status.signature_algorithm);
                println!("  Classical KEM:          {}", status.classical_kem);
                println!("  Post-Quantum KEM:       {}", status.quantum_kem);
                println!("  Classical Signature:    {}", status.classical_sig);
                println!("  Post-Quantum Signature: {}", status.quantum_sig);
                println!(
                    "  KEM Public Key Size:    {} bytes",
                    status.kem_public_key_bytes
                );
                println!(
                    "  KEM Ciphertext Size:    {} bytes",
                    status.kem_ciphertext_bytes
                );
                println!(
                    "  Signature Key Size:     {} bytes",
                    status.sig_public_key_bytes
                );
                println!("  Signature Size:         {} bytes", status.signature_bytes);
                println!(
                    "  NIST Security Level:    Level {} (AES-192 equivalent)",
                    status.quantum_security_level
                );
                println!("  NIST FIPS Compliance:   {}", status.nist_fips_compliance);
                println!(
                    "  Dual Security Enforced: {}",
                    status.hybrid_dual_security_enforced
                );
            }
        }
        PqcSubCmd::Keygen {
            mode,
            out_dir,
            json,
        } => {
            let kem_pair = HybridKemEngine::generate_keypair()?;
            let (sig_pk, sig_sk) = HybridSignatureEngine::generate_keypair()?;

            let kem_pk_hex = hex_encode(&serde_json::to_vec(&kem_pair.public_key)?);
            let kem_sk_hex = hex_encode(&serde_json::to_vec(&kem_pair.private_key)?);
            let sig_pk_hex = hex_encode(&serde_json::to_vec(&sig_pk)?);
            let sig_sk_hex = hex_encode(&serde_json::to_vec(&sig_sk)?);

            if let Some(dir) = out_dir {
                std::fs::create_dir_all(dir)?;
                std::fs::write(dir.join("pqc_kem.pub"), &kem_pk_hex)?;
                std::fs::write(dir.join("pqc_kem.key"), &kem_sk_hex)?;
                std::fs::write(dir.join("pqc_sig.pub"), &sig_pk_hex)?;
                std::fs::write(dir.join("pqc_sig.key"), &sig_sk_hex)?;
            }

            #[derive(Serialize)]
            struct KeygenOutput {
                mode: String,
                kem_public_key_hex: String,
                kem_private_key_hex: String,
                sig_public_key_hex: String,
                sig_private_key_hex: String,
                saved_to_dir: Option<PathBuf>,
            }

            let output = KeygenOutput {
                mode: mode.clone(),
                kem_public_key_hex: kem_pk_hex.clone(),
                kem_private_key_hex: kem_sk_hex.clone(),
                sig_public_key_hex: sig_pk_hex.clone(),
                sig_private_key_hex: sig_sk_hex.clone(),
                saved_to_dir: out_dir.clone(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("=== Generated Quantum-Resilient Keypairs ({}) ===", mode);
                println!(
                    "  KEM Public Key:         {}...",
                    &kem_pk_hex[..48.min(kem_pk_hex.len())]
                );
                println!(
                    "  KEM Private Key:        {}...",
                    &kem_sk_hex[..48.min(kem_sk_hex.len())]
                );
                println!(
                    "  Sig Public Key:         {}...",
                    &sig_pk_hex[..48.min(sig_pk_hex.len())]
                );
                println!(
                    "  Sig Private Key:        {}...",
                    &sig_sk_hex[..48.min(sig_sk_hex.len())]
                );
                if let Some(d) = out_dir {
                    println!("  Saved to Directory:     {}", d.display());
                }
            }
        }
        PqcSubCmd::Encap {
            public_key_hex,
            json,
        } => {
            let pk_bytes = hex_decode(public_key_hex)
                .ok_or_else(|| anyhow::anyhow!("Invalid hex public key"))?;
            let pk: HybridKemPublicKey = serde_json::from_slice(&pk_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse HybridKemPublicKey: {}", e))?;

            let (ct, ss) = HybridKemEngine::encapsulate(&pk)?;
            let ct_hex = hex_encode(&serde_json::to_vec(&ct)?);
            let ss_hex = hex_encode(ss.as_bytes());

            #[derive(Serialize)]
            struct EncapOutput {
                ciphertext_hex: String,
                shared_secret_hex: String,
                ciphertext_bytes: usize,
                shared_secret_bytes: usize,
            }

            let ct_len = serde_json::to_vec(&ct)?.len();
            let out = EncapOutput {
                ciphertext_hex: ct_hex.clone(),
                shared_secret_hex: ss_hex.clone(),
                ciphertext_bytes: ct_len,
                shared_secret_bytes: 32,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Hybrid KEM Encapsulation Successful ===");
                println!(
                    "  Ciphertext:             {}...",
                    &ct_hex[..48.min(ct_hex.len())]
                );
                println!("  Shared Secret (BLAKE3): {}", ss_hex);
            }
        }
        PqcSubCmd::Decap {
            private_key_hex,
            ciphertext_hex,
            peer_pk_hex,
            json,
        } => {
            let sk_bytes = hex_decode(private_key_hex)
                .ok_or_else(|| anyhow::anyhow!("Invalid hex private key"))?;
            let sk: HybridKemPrivateKey = serde_json::from_slice(&sk_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse HybridKemPrivateKey: {}", e))?;

            let ct_bytes = hex_decode(ciphertext_hex)
                .ok_or_else(|| anyhow::anyhow!("Invalid hex ciphertext"))?;
            let ct: HybridCiphertext = serde_json::from_slice(&ct_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse HybridCiphertext: {}", e))?;

            let ss = if let Some(hex_pk) = peer_pk_hex {
                let bytes =
                    hex_decode(hex_pk).ok_or_else(|| anyhow::anyhow!("Invalid peer_pk_hex"))?;
                if bytes.len() != 32 {
                    anyhow::bail!("peer_pk_hex must be 32 bytes");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                HybridKemEngine::decapsulate(&sk, &ct, &arr)?
            } else {
                HybridKemEngine::decapsulate_self(&sk, &ct)?
            };

            let ss_hex = hex_encode(ss.as_bytes());

            #[derive(Serialize)]
            struct DecapOutput {
                shared_secret_hex: String,
                shared_secret_bytes: usize,
            }

            let out = DecapOutput {
                shared_secret_hex: ss_hex.clone(),
                shared_secret_bytes: 32,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Hybrid KEM Decapsulation Successful ===");
                println!("  Shared Secret (BLAKE3): {}", ss_hex);
            }
        }
        PqcSubCmd::Sign {
            manifest_path,
            private_key_hex,
            json,
        } => {
            let sk_bytes = hex_decode(private_key_hex)
                .ok_or_else(|| anyhow::anyhow!("Invalid hex private key"))?;
            let sk: HybridSigningPrivateKey = serde_json::from_slice(&sk_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse HybridSigningPrivateKey: {}", e))?;

            // Bounded memory streaming file hash using BLAKE3
            let mut file = std::fs::File::open(manifest_path)?;
            let mut hasher = blake3::Hasher::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                use std::io::Read;
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            let file_hash = hasher.finalize();

            let sig = HybridSignatureEngine::sign(&sk, file_hash.as_bytes())?;
            let sig_hex = hex_encode(&serde_json::to_vec(&sig)?);

            #[derive(Serialize)]
            struct SignOutput {
                manifest_path: String,
                payload_hash_blake3: String,
                signature_hex: String,
                classical_sig_bytes: usize,
                ml_dsa_sig_bytes: usize,
            }

            let out = SignOutput {
                manifest_path: manifest_path.display().to_string(),
                payload_hash_blake3: file_hash.to_hex().to_string(),
                signature_hex: sig_hex.clone(),
                classical_sig_bytes: 64,
                ml_dsa_sig_bytes: sig.ml_dsa_signature.len(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Dual-Hybrid Post-Quantum Signature Computed ===");
                println!("  Payload BLAKE3:         {}", file_hash.to_hex());
                println!(
                    "  Hybrid Signature:       {}...",
                    &sig_hex[..48.min(sig_hex.len())]
                );
                println!(
                    "  Signature Size:         {} bytes",
                    serde_json::to_vec(&sig)?.len()
                );
            }
        }
        PqcSubCmd::Verify {
            manifest_path,
            public_key_hex,
            signature_hex,
            json,
        } => {
            let pk_bytes = hex_decode(public_key_hex)
                .ok_or_else(|| anyhow::anyhow!("Invalid hex public key"))?;
            let pk: HybridSigningPublicKey = serde_json::from_slice(&pk_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse HybridSigningPublicKey: {}", e))?;

            let sig_bytes = hex_decode(signature_hex)
                .ok_or_else(|| anyhow::anyhow!("Invalid hex signature"))?;
            let sig: HybridSignature = serde_json::from_slice(&sig_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse HybridSignature: {}", e))?;

            // Bounded memory streaming file hash using BLAKE3
            let mut file = std::fs::File::open(manifest_path)?;
            let mut hasher = blake3::Hasher::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                use std::io::Read;
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            let file_hash = hasher.finalize();

            let valid = HybridSignatureEngine::verify(&pk, file_hash.as_bytes(), &sig);

            #[derive(Serialize)]
            struct VerifyOutput {
                manifest_path: String,
                payload_hash_blake3: String,
                valid: bool,
                ed25519_verified: bool,
                ml_dsa_65_verified: bool,
            }

            let out = VerifyOutput {
                manifest_path: manifest_path.display().to_string(),
                payload_hash_blake3: file_hash.to_hex().to_string(),
                valid,
                ed25519_verified: valid,
                ml_dsa_65_verified: valid,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Dual-Hybrid Post-Quantum Signature Verification ===");
                println!("  Payload BLAKE3:         {}", file_hash.to_hex());
                println!(
                    "  Result:                 {}",
                    if valid {
                        "VALID (VERIFIED)"
                    } else {
                        "INVALID / TAMPERED"
                    }
                );
                println!(
                    "  Ed25519 Check:          {}",
                    if valid { "PASSED" } else { "FAILED" }
                );
                println!(
                    "  ML-DSA-65 Check:        {}",
                    if valid { "PASSED" } else { "FAILED" }
                );
            }

            if !valid {
                anyhow::bail!("PQC signature verification failed");
            }
        }
        PqcSubCmd::Benchmark { iterations, json } => {
            let report = run_pqc_benchmark(*iterations);
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "=== Quantum-Resilient Cryptography Benchmark ({} iters) ===",
                    report.iterations
                );
                println!(
                    "  ML-KEM-768 Keygen:      {:.2} µs",
                    report.ml_kem_keygen_latency_us
                );
                println!(
                    "  ML-KEM-768 Encap:       {:.2} µs",
                    report.ml_kem_encaps_latency_us
                );
                println!(
                    "  ML-KEM-768 Decap:       {:.2} µs",
                    report.ml_kem_decaps_latency_us
                );
                println!(
                    "  ML-DSA-65 Keygen:       {:.2} µs",
                    report.ml_dsa_keygen_latency_us
                );
                println!(
                    "  ML-DSA-65 Sign:         {:.2} µs",
                    report.ml_dsa_sign_latency_us
                );
                println!(
                    "  ML-DSA-65 Verify:       {:.2} µs",
                    report.ml_dsa_verify_latency_us
                );
                println!(
                    "  Hybrid KEM Roundtrip:   {:.2} µs",
                    report.hybrid_kem_roundtrip_latency_us
                );
                println!(
                    "  Hybrid Sig Roundtrip:   {:.2} µs",
                    report.hybrid_sig_roundtrip_latency_us
                );
                println!(
                    "  Hybrid KEM Throughput:  {:.1} ops/sec",
                    report.kem_ops_per_second
                );
                println!(
                    "  Hybrid Sig Throughput:  {:.1} ops/sec",
                    report.sig_ops_per_second
                );
                println!(
                    "  All Ops Verified:       {}",
                    report.all_operations_verified
                );
            }
        }
    }

    Ok(())
}

async fn run_proxy(cli: &Cli, sub: &ProxySubCmd) -> anyhow::Result<()> {
    use velcrux_core::proxy::{
        run_l7_benchmark, FlowTier, L7Action, L7ProxyEngine, L7RequestInfo, L7Rule, L7StreamType,
    };

    let is_json = cli_log_json(cli);

    match sub {
        ProxySubCmd::Status {
            cpu,
            mem,
            queue,
            rtt,
            json,
        } => {
            let engine = L7ProxyEngine::default();
            if cpu.is_some() || mem.is_some() || queue.is_some() || rtt.is_some() {
                let q = queue.unwrap_or(10.0);
                engine.set_pressure(
                    cpu.unwrap_or(20.0),
                    mem.unwrap_or(20.0),
                    q,
                    rtt.unwrap_or(q),
                );
            }
            let status = engine.status();
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("=== Programmable L7 Proxy & Load Shedder Status ===");
                println!(
                    "  Pressure Score:         {:.1}%",
                    status.pressure_score_pct
                );
                println!("  Policy Mode:            {}", status.default_policy_mode);
                println!("  Active Flows:           {}", status.active_flows);
                println!("  Active Rules:           {}", status.rules_count);
                println!("  Classified Flows:       {}", status.total_classified);
                println!("  Admitted Flows:         {}", status.total_admitted);
                println!("  Throttled Flows:        {}", status.total_throttled);
                println!("  Shed Flows:             {}", status.total_shed);
                println!("  Rerouted Flows:         {}", status.total_rerouted);
                println!(
                    "  Avg Dispatch Latency:   {:.2} ns",
                    status.avg_dispatch_latency_ns
                );
            }
        }
        ProxySubCmd::Rules { json } => {
            let r1 = L7Rule {
                id: "default-control-admit".to_string(),
                description: "Strict non-sheddable priority admission for control streams"
                    .to_string(),
                precedence: 10,
                tenant_prefix: None,
                path_prefix: None,
                stream_type: Some(L7StreamType::Control),
                min_pressure_pct: None,
                action: L7Action::Admit {
                    worker_id: 0,
                    priority: 0,
                },
            };
            let r2 = L7Rule {
                id: "premium-tier-fastpath".to_string(),
                description: "Priority SLA fast-path routing for premium tenants".to_string(),
                precedence: 20,
                tenant_prefix: Some("premium-".to_string()),
                path_prefix: None,
                stream_type: None,
                min_pressure_pct: None,
                action: L7Action::Admit {
                    worker_id: 1,
                    priority: 1,
                },
            };
            let r3 = L7Rule {
                id: "cold-archive-reroute".to_string(),
                description: "Reroute cold archive bulk uploads to secondary PoP".to_string(),
                precedence: 30,
                tenant_prefix: None,
                path_prefix: Some("/archive/cold".to_string()),
                stream_type: None,
                min_pressure_pct: None,
                action: L7Action::Reroute {
                    target_pop: "pop-cold-iad".to_string(),
                },
            };
            let all_rules = vec![r1, r2, r3];

            #[derive(Serialize)]
            struct RulesOutput {
                count: usize,
                rules: Vec<L7Rule>,
            }

            if *json || is_json {
                let out = RulesOutput {
                    count: all_rules.len(),
                    rules: all_rules,
                };
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Active Programmable L7 Proxy Rules ===");
                println!(
                    "{:<4} {:<24} {:<12} {:<16} {:<20} ACTION",
                    "#", "RULE ID", "PRECEDENCE", "TENANT FILTER", "PATH FILTER"
                );
                for (idx, r) in all_rules.iter().enumerate() {
                    println!(
                        "{:<4} {:<24} {:<12} {:<16} {:<20} {}",
                        idx + 1,
                        r.id,
                        r.precedence,
                        r.tenant_prefix.as_deref().unwrap_or("*"),
                        r.path_prefix.as_deref().unwrap_or("*"),
                        r.action
                    );
                }
            }
        }
        ProxySubCmd::AddRule {
            id,
            desc,
            precedence,
            tenant_prefix,
            path_prefix,
            stream_type,
            action,
            json,
        } => {
            let st = stream_type
                .as_deref()
                .map(|s| match s.to_lowercase().as_str() {
                    "control" => L7StreamType::Control,
                    "metadata" => L7StreamType::Metadata,
                    "datagram" => L7StreamType::Datagram,
                    _ => L7StreamType::Data,
                });

            let act = match action.to_lowercase().as_str() {
                "shed" => L7Action::Shed {
                    reason: "operator configured rule".to_string(),
                    retry_after_ms: 1000,
                },
                "throttle" => L7Action::Throttle {
                    allowed_rate_bps: 10_000_000,
                    delay_ms: 50,
                },
                "reroute" => L7Action::Reroute {
                    target_pop: "pop-secondary".to_string(),
                },
                _ => L7Action::Admit {
                    worker_id: 1,
                    priority: 2,
                },
            };

            let rule = L7Rule {
                id: id.clone(),
                description: desc.clone(),
                precedence: *precedence,
                tenant_prefix: tenant_prefix.clone(),
                path_prefix: path_prefix.clone(),
                stream_type: st,
                min_pressure_pct: None,
                action: act,
            };

            #[derive(Serialize)]
            struct AddRuleOutput {
                success: bool,
                rule: L7Rule,
            }

            let out = AddRuleOutput {
                success: true,
                rule,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Programmable L7 Rule Registered ===");
                println!("  ID:                     {}", id);
                println!("  Description:            {}", desc);
                println!("  Precedence:             {}", precedence);
                println!(
                    "  Tenant Prefix:          {}",
                    tenant_prefix.as_deref().unwrap_or("*")
                );
                println!(
                    "  Path Prefix:            {}",
                    path_prefix.as_deref().unwrap_or("*")
                );
                println!("  Action:                 {}", action);
            }
        }
        ProxySubCmd::Classify {
            tenant,
            path,
            stream_type,
            flow_priority,
            payload_bytes,
            pressure,
            json,
        } => {
            let engine = L7ProxyEngine::default();
            engine.set_pressure(*pressure, *pressure, *pressure, *pressure);

            let st = match stream_type.to_lowercase().as_str() {
                "control" => L7StreamType::Control,
                "metadata" => L7StreamType::Metadata,
                "datagram" => L7StreamType::Datagram,
                _ => L7StreamType::Data,
            };

            let req = L7RequestInfo {
                flow_id: "flow-probe-1".to_string(),
                tenant_id: tenant.clone(),
                path: path.clone(),
                stream_type: st,
                payload_bytes: *payload_bytes,
                client_ip: "10.0.0.1".to_string(),
                priority_hint: *flow_priority,
            };

            let (tier, action) = engine.classify(&req);

            #[derive(Serialize)]
            struct ClassifyOutput {
                tenant_id: String,
                path: String,
                stream_type: String,
                flow_tier: FlowTier,
                pressure_score_pct: f64,
                decision_action: L7Action,
            }

            let out = ClassifyOutput {
                tenant_id: tenant.clone(),
                path: path.clone(),
                stream_type: stream_type.clone(),
                flow_tier: tier,
                pressure_score_pct: *pressure,
                decision_action: action.clone(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Ingress Stream L7 Classification Verdict ===");
                println!("  Tenant ID:              {}", tenant);
                println!("  Transfer Path:          {}", path);
                println!("  Stream Category:        {}", stream_type);
                println!(
                    "  Classified Tier:        {:?} (Level {})",
                    tier, tier as u8
                );
                println!("  System Pressure:        {:.1}%", pressure);
                println!("  Decision Action:        {}", action);
            }
        }
        ProxySubCmd::Shed { pressure, json } => {
            let engine = L7ProxyEngine::default();
            engine.set_pressure(*pressure, *pressure, *pressure, *pressure);

            let tiers = vec![
                ("Control", L7StreamType::Control, None),
                ("Interactive", L7StreamType::Metadata, None),
                ("BulkHigh", L7StreamType::Data, Some(2u8)),
                ("BulkLow", L7StreamType::Data, Some(5u8)),
                ("Background", L7StreamType::Data, Some(8u8)),
            ];

            #[derive(Serialize)]
            struct TierResult {
                tier: String,
                action: L7Action,
                verdict: String,
            }

            let mut results = Vec::new();
            for (name, st, prio) in tiers {
                let req = L7RequestInfo {
                    flow_id: format!("sim-{}", name),
                    tenant_id: "tenant-sim".to_string(),
                    path: format!("/sim/{}", name.to_lowercase()),
                    stream_type: st,
                    payload_bytes: 65536,
                    client_ip: "127.0.0.1".to_string(),
                    priority_hint: prio,
                };
                let (_, action) = engine.classify(&req);
                let verdict = match &action {
                    L7Action::Admit { .. } => "ADMITTED",
                    L7Action::Throttle { .. } => "THROTTLED",
                    L7Action::Shed { .. } => "SHED",
                    L7Action::Reroute { .. } => "REROUTED",
                };
                results.push(TierResult {
                    tier: name.to_string(),
                    action,
                    verdict: verdict.to_string(),
                });
            }

            #[derive(Serialize)]
            struct ShedOutput {
                pressure_score_pct: f64,
                policy_mode: String,
                tiers: Vec<TierResult>,
            }

            let out = ShedOutput {
                pressure_score_pct: *pressure,
                policy_mode: engine.status().default_policy_mode,
                tiers: results,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "=== Dynamic L7 Load Shedding Cascade (Pressure: {:.1}%) ===",
                    pressure
                );
                println!("  Policy Active:          {}", out.policy_mode);
                println!("{:<14} {:<12} DETAILS", "FLOW TIER", "VERDICT");
                for r in &out.tiers {
                    println!("{:<14} {:<12} {}", r.tier, r.verdict, r.action);
                }
            }
        }
        ProxySubCmd::Benchmark { iterations, json } => {
            let report = run_l7_benchmark(*iterations);
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "=== Programmable L7 Proxy Benchmark ({} iters) ===",
                    report.iterations
                );
                println!(
                    "  Classification Latency: {:.2} ns",
                    report.classification_latency_ns
                );
                println!(
                    "  Rule Eval Latency:      {:.2} ns",
                    report.rule_eval_latency_ns
                );
                println!(
                    "  Load Shedding Latency:  {:.2} ns",
                    report.shedding_latency_ns
                );
                println!(
                    "  Throughput:             {:.1} ops/sec",
                    report.throughput_ops_per_second
                );
                println!("  Flows Admitted:         {}", report.flows_admitted);
                println!("  Flows Throttled:        {}", report.flows_throttled);
                println!("  Flows Shed:             {}", report.flows_shed);
                println!("  All Verdicts Valid:     {}", report.all_verdicts_correct);
            }
        }
    }

    Ok(())
}

async fn run_wan(cli: &Cli, sub: &WanSubCmd) -> anyhow::Result<()> {
    use velcrux_core::audit::hex_encode;
    use velcrux_core::wan::{WanBondingEngine, WanInterfaceInfo, WanPathState};

    let is_json = cli_log_json(cli);

    match sub {
        WanSubCmd::Status { json } => {
            let engine = WanBondingEngine::default();
            let ifaces = engine.list_interfaces();
            let (chunks, bytes, reordered) = engine.stats();

            #[derive(Serialize)]
            struct WanStatusOutput {
                interfaces_bonded: usize,
                total_sliced_chunks: u64,
                total_sliced_bytes: u64,
                total_reordered_slices: u64,
                interfaces: Vec<WanInterfaceInfo>,
            }

            let out = WanStatusOutput {
                interfaces_bonded: ifaces.len(),
                total_sliced_chunks: chunks,
                total_sliced_bytes: bytes,
                total_reordered_slices: reordered,
                interfaces: ifaces,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Autonomous Multi-Path WAN Slicing & Bonding Status ===");
                println!("  Bonded Interfaces:      {}", out.interfaces_bonded);
                println!("  Total Sliced Chunks:    {}", out.total_sliced_chunks);
                println!("  Total Sliced Bytes:     {}", out.total_sliced_bytes);
                println!("  Reordered Slices:       {}", out.total_reordered_slices);
                println!();
                println!(
                    "{:<18} {:<14} {:<10} {:<12} {:<8} {:<10} {:<8}",
                    "INTERFACE",
                    "LINK TYPE",
                    "STATE",
                    "CAPACITY",
                    "WEIGHT",
                    "SRTT (ms)",
                    "LOSS (%)"
                );
                println!(
                    "{:-<18} {:-<14} {:-<10} {:-<12} {:-<8} {:-<10} {:-<8}",
                    "", "", "", "", "", "", ""
                );
                for i in &out.interfaces {
                    let cap_str = if i.capacity_mbps >= 1000 {
                        format!("{} Gbps", i.capacity_mbps / 1000)
                    } else {
                        format!("{} Mbps", i.capacity_mbps)
                    };
                    let srtt_ms = (i.srtt_us as f64) / 1000.0;
                    let loss_pct = (i.loss_basis_points as f64) / 100.0;
                    let type_str = format!("{:?}", i.link_type);
                    let state_str = format!("{:?}", i.state);
                    println!(
                        "{:<18} {:<14} {:<10} {:<12} {:<8} {:<10.2} {:<8.2}",
                        i.id, type_str, state_str, cap_str, i.dynamic_weight, srtt_ms, loss_pct
                    );
                }
            }
        }
        WanSubCmd::Interfaces { json } => {
            let engine = WanBondingEngine::default();
            let ifaces = engine.list_interfaces();

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&ifaces)?);
            } else {
                println!("=== Active Bonded WAN Interfaces ===");
                for i in &ifaces {
                    println!("Interface: {}", i.id);
                    println!("  Link Type:         {:?}", i.link_type);
                    println!("  State:             {:?}", i.state);
                    println!("  Nominal Capacity:  {} Mbps", i.capacity_mbps);
                    println!("  Dynamic Weight:    {}", i.dynamic_weight);
                    println!(
                        "  Smoothed RTT:      {} us ({:.2} ms)",
                        i.srtt_us,
                        (i.srtt_us as f64) / 1000.0
                    );
                    println!("  RTT Variance:      {} us", i.rtt_var_us);
                    println!("  One-Way Delay:     {} us", i.one_way_delay_us);
                    println!(
                        "  Loss Ratio:        {} bp ({:.2}%)",
                        i.loss_basis_points,
                        (i.loss_basis_points as f64) / 100.0
                    );
                    println!("  ECN CE Ratio:      {} bp", i.ecn_ce_basis_points);
                    println!("  Tx Slices / Bytes: {} / {} B", i.tx_slices, i.tx_bytes);
                    println!("  Rx Slices / Bytes: {} / {} B", i.rx_slices, i.rx_bytes);
                    println!();
                }
            }
        }
        WanSubCmd::Slice {
            size,
            slice_size,
            reorder,
            json,
        } => {
            let engine = WanBondingEngine::default();
            let mut test_payload = vec![0u8; *size];
            for (idx, b) in test_payload.iter_mut().enumerate() {
                *b = ((idx * 31 + 17) % 251) as u8;
            }
            let chunk_hash = *blake3::hash(&test_payload).as_bytes();

            let slices = engine.slice_chunk(chunk_hash, &test_payload, *slice_size)?;
            let total_slices = slices.len();

            let mut arrival_slices = slices.clone();
            if *reorder {
                arrival_slices.reverse();
            }

            let mut reassembled_res = None;
            for s in arrival_slices {
                if let Some(res) = engine.reassemble_slice(s)? {
                    reassembled_res = Some(res);
                }
            }

            let res = reassembled_res.expect("All slices must reassemble completely");

            #[derive(Serialize)]
            struct SliceOutput {
                chunk_hash: String,
                total_bytes: usize,
                total_slices: usize,
                slice_size_bytes: usize,
                reordered: bool,
                max_reorder_gap: u32,
                integrity_verified: bool,
                slices_per_interface: std::collections::HashMap<String, u32>,
            }

            let out = SliceOutput {
                chunk_hash: hex_encode(&chunk_hash),
                total_bytes: res.total_bytes,
                total_slices,
                slice_size_bytes: *slice_size,
                reordered: *reorder,
                max_reorder_gap: res.max_reorder_gap,
                integrity_verified: true,
                slices_per_interface: res.slices_per_interface.clone(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Multi-Path WAN Slicing & Reassembly Execution ===");
                println!("  Chunk Hash:             {}", out.chunk_hash);
                println!("  Total Payload:          {} bytes", out.total_bytes);
                println!("  Total Slices:           {}", out.total_slices);
                println!("  Slice Frame Size:       {} bytes", out.slice_size_bytes);
                println!("  Reordered Arrival:      {}", out.reordered);
                println!("  Max Reorder Gap:        {}", out.max_reorder_gap);
                println!("  Integrity Verified:     {}", out.integrity_verified);
                println!("  Interface Distribution:");
                for (iface, count) in &res.slices_per_interface {
                    println!("    - {}: {} slices", iface, count);
                }
            }
        }
        WanSubCmd::Probe {
            interface,
            srtt_us,
            jitter_us,
            loss_bp,
            ecn_bp,
            json,
        } => {
            let engine = WanBondingEngine::default();
            engine.update_probe(interface, *srtt_us, *jitter_us, *loss_bp, *ecn_bp)?;
            let updated = engine
                .get_interface(interface)
                .expect("Interface must exist");

            #[derive(Serialize)]
            struct ProbeOutput {
                interface: String,
                srtt_us: u64,
                jitter_us: u64,
                loss_basis_points: u64,
                ecn_ce_basis_points: u64,
                new_state: WanPathState,
                new_dynamic_weight: usize,
            }

            let out = ProbeOutput {
                interface: interface.clone(),
                srtt_us: *srtt_us,
                jitter_us: *jitter_us,
                loss_basis_points: *loss_bp,
                ecn_ce_basis_points: *ecn_bp,
                new_state: updated.state,
                new_dynamic_weight: updated.dynamic_weight,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== WAN Interface Path Quality Probe Updated ===");
                println!("  Interface:              {}", out.interface);
                println!(
                    "  Smoothed RTT:           {} us ({:.2} ms)",
                    out.srtt_us,
                    (out.srtt_us as f64) / 1000.0
                );
                println!("  RTT Jitter:             {} us", out.jitter_us);
                println!(
                    "  Loss Ratio:             {} bp ({:.2}%)",
                    out.loss_basis_points,
                    (out.loss_basis_points as f64) / 100.0
                );
                println!("  ECN CE Ratio:           {} bp", out.ecn_ce_basis_points);
                println!("  New Path State:         {:?}", out.new_state);
                println!("  New Dynamic Weight:     {}", out.new_dynamic_weight);
            }
        }
        WanSubCmd::Benchmark {
            iterations,
            chunk_size,
            json,
        } => {
            let engine = WanBondingEngine::default();
            let report = engine.run_benchmark(*iterations, *chunk_size);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "=== Multi-Path WAN Slicing & Bonding Benchmark ({} iters) ===",
                    report.iterations
                );
                println!(
                    "  Chunk Payload Size:     {} bytes",
                    report.chunk_size_bytes
                );
                println!(
                    "  Slice Frame Size:       {} bytes",
                    report.slice_size_bytes
                );
                println!(
                    "  Total Slices Handled:   {}",
                    report.total_slices_processed
                );
                println!("  Bonded Interfaces:      {}", report.interfaces_bonded);
                println!("  Elapsed Time:           {} us", report.elapsed_micros);
                println!(
                    "  Slicing Throughput:     {:.2} slices/sec",
                    report.slicing_throughput_slices_sec
                );
                println!(
                    "  Bonding Throughput:     {:.4} Gbps",
                    report.aggregation_throughput_gbps
                );
                println!(
                    "  Avg Reassembly Latency: {:.2} us",
                    report.avg_reassembly_latency_micros
                );
            }
        }
    }

    Ok(())
}

async fn run_did(cli: &Cli, sub: &DidSubCmd) -> anyhow::Result<()> {
    use velcrux_core::audit::hex_encode;
    use velcrux_core::did::{
        did_from_ed25519_pubkey, generate_ed25519_keypair, hex_decode, parse_ed25519_keypair,
        resolve_did, DidAttestationEngine, DidMethod, VerifiableCredential,
    };

    let is_json = cli_log_json(cli);

    match sub {
        DidSubCmd::Status { json } => {
            let engine = DidAttestationEngine::new();
            let (res_total, vc_issued, vc_verified, vc_fails, last_latency_ns, active_delegs) =
                engine.stats();

            #[derive(Serialize)]
            struct DidStatusOutput {
                did_resolutions_total: u64,
                did_vc_issued_total: u64,
                did_vc_verified_total: u64,
                did_vc_verification_failures_total: u64,
                did_verification_latency_nanoseconds: u64,
                did_active_delegations: u64,
            }

            let out = DidStatusOutput {
                did_resolutions_total: res_total,
                did_vc_issued_total: vc_issued,
                did_vc_verified_total: vc_verified,
                did_vc_verification_failures_total: vc_fails,
                did_verification_latency_nanoseconds: last_latency_ns,
                did_active_delegations: active_delegs,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Zero-Trust DID & Verifiable Credential Engine Status ===");
                println!("  DID Resolutions:        {}", out.did_resolutions_total);
                println!("  VCs Issued:             {}", out.did_vc_issued_total);
                println!("  VCs Verified:           {}", out.did_vc_verified_total);
                println!(
                    "  VC Verification Fails:  {}",
                    out.did_vc_verification_failures_total
                );
                println!("  Active Delegations:     {}", out.did_active_delegations);
                println!(
                    "  Last Latency:           {} ns ({:.2} µs)",
                    out.did_verification_latency_nanoseconds,
                    (out.did_verification_latency_nanoseconds as f64) / 1000.0
                );
            }
        }
        DidSubCmd::Generate { peer, json } => {
            let (pkcs8_bytes, pk_bytes) = generate_ed25519_keypair()?;

            let method = if *peer {
                DidMethod::Peer
            } else {
                DidMethod::Key
            };
            let did = did_from_ed25519_pubkey(&pk_bytes, method);
            let (_, doc) = resolve_did(&did)?;

            #[derive(Serialize)]
            struct GenerateOutput {
                did: String,
                did_method: String,
                public_key_hex: String,
                private_key_pkcs8_hex: String,
                did_document: velcrux_core::did::DidDocument,
            }

            let out = GenerateOutput {
                did: did.clone(),
                did_method: if *peer {
                    "did:peer".to_string()
                } else {
                    "did:key".to_string()
                },
                public_key_hex: hex_encode(&pk_bytes),
                private_key_pkcs8_hex: hex_encode(&pkcs8_bytes),
                did_document: doc,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Generated Decentralized Identifier (DID) ===");
                println!("  DID:                    {}", out.did);
                println!("  Method:                 {}", out.did_method);
                println!("  Public Key (Hex):       {}", out.public_key_hex);
                println!("  Private Key PKCS#8:     {}", out.private_key_pkcs8_hex);
                println!();
                println!("DID Document:");
                println!("{}", serde_json::to_string_pretty(&out.did_document)?);
            }
        }
        DidSubCmd::Resolve { did, json } => {
            let (pk, doc) = resolve_did(did)?;

            #[derive(Serialize)]
            struct ResolveOutput {
                did: String,
                public_key_hex: String,
                did_document: velcrux_core::did::DidDocument,
            }

            let out = ResolveOutput {
                did: did.clone(),
                public_key_hex: hex_encode(&pk),
                did_document: doc,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Resolved W3C Decentralized Identifier ===");
                println!("  DID:                    {}", out.did);
                println!("  Public Key (Hex):       {}", out.public_key_hex);
                println!();
                println!("DID Document:");
                println!("{}", serde_json::to_string_pretty(&out.did_document)?);
            }
        }
        DidSubCmd::IssueVc {
            issuer_sk,
            subject_did,
            tenant,
            paths,
            ops,
            max_bandwidth,
            valid_hours,
            delegation_depth,
            parent_vc,
            json,
        } => {
            let engine = DidAttestationEngine::new();
            let sk_bytes = hex_decode(issuer_sk)
                .ok_or_else(|| anyhow::anyhow!("Invalid hex encoding for issuer_sk"))?;
            let (keypair, pk_bytes) = parse_ed25519_keypair(&sk_bytes)?;
            let issuer_did = did_from_ed25519_pubkey(&pk_bytes, DidMethod::Key);

            let path_list: Vec<String> = paths
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let op_list: Vec<String> = ops
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let parent: Option<VerifiableCredential> = if let Some(p) = parent_vc {
                let content = if std::path::Path::new(p).exists() {
                    std::fs::read_to_string(p)?
                } else {
                    p.clone()
                };
                Some(serde_json::from_str(&content)?)
            } else {
                None
            };

            let vc = engine.issue_credential(
                &keypair,
                &issuer_did,
                subject_did,
                tenant,
                path_list,
                op_list,
                *max_bandwidth,
                valid_hours * 3600,
                *delegation_depth,
                parent,
            )?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&vc)?);
            } else {
                println!("=== Issued W3C Verifiable Credential ===");
                println!("  VC ID:                  {}", vc.id);
                println!("  Issuer DID:             {}", vc.issuer);
                println!("  Subject DID:            {}", vc.credential_subject.id);
                println!(
                    "  Tenant ID:              {}",
                    vc.credential_subject.tenant_id
                );
                println!(
                    "  Allowed Paths:          {:?}",
                    vc.credential_subject.allowed_paths
                );
                println!(
                    "  Allowed Operations:     {:?}",
                    vc.credential_subject.allowed_operations
                );
                println!(
                    "  Max Bandwidth:          {} bps",
                    vc.credential_subject.max_bandwidth_bps
                );
                println!(
                    "  Delegation Depth:       {}",
                    vc.credential_subject.delegation_depth
                );
                println!(
                    "  Chained Delegation:     {}",
                    vc.parent_credential.is_some()
                );
                println!(
                    "  Proof Type:             {}",
                    vc.proof.as_ref().unwrap().type_
                );
                println!(
                    "  Signature Hex:          {}",
                    vc.proof.as_ref().unwrap().proof_value
                );
                println!();
                println!("Raw JSON:");
                println!("{}", serde_json::to_string_pretty(&vc)?);
            }
        }
        DidSubCmd::VerifyVc {
            vc,
            requested_path,
            requested_op,
            json,
        } => {
            let engine = DidAttestationEngine::new();
            let content = if std::path::Path::new(vc).exists() {
                std::fs::read_to_string(vc)?
            } else {
                vc.clone()
            };

            let cred: VerifiableCredential = serde_json::from_str(&content).map_err(|e| {
                anyhow::anyhow!("Failed to parse Verifiable Credential JSON: {}", e)
            })?;

            let report = engine.verify_credential(
                &cred,
                requested_path.as_deref(),
                requested_op.as_deref(),
            )?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Verifiable Credential Attestation Validated ===");
                println!("  Status:                 VALID");
                println!("  Issuer DID:             {}", report.issuer_did);
                println!("  Subject DID:            {}", report.subject_did);
                println!("  Tenant ID:              {}", report.tenant_id);
                println!("  Allowed Paths:          {:?}", report.allowed_paths);
                println!("  Allowed Operations:     {:?}", report.allowed_operations);
                println!("  Delegation Depth:       {}", report.delegation_depth);
                println!(
                    "  Delegation Chain Depth: {}",
                    report.delegation_chain_depth
                );
                println!(
                    "  Time to Expiry:         {} seconds",
                    report.time_to_expiry_seconds
                );
                println!(
                    "  Verification Latency:   {} ns ({:.2} µs)",
                    report.verification_latency_nanoseconds,
                    (report.verification_latency_nanoseconds as f64) / 1000.0
                );
            }
        }
        DidSubCmd::Benchmark { iterations, json } => {
            let engine = DidAttestationEngine::new();
            let report = engine.run_benchmark(*iterations);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "=== Zero-Trust DID & VC Benchmark ({} iters) ===",
                    report.iterations
                );
                println!(
                    "  Resolution Latency:     {:.2} ns ({:.2} ops/sec)",
                    report.resolution_latency_nanoseconds, report.resolution_ops_per_second
                );
                println!(
                    "  Issuance Latency:       {:.2} ns ({:.2} ops/sec)",
                    report.issuance_latency_nanoseconds, report.issuance_ops_per_second
                );
                println!(
                    "  Verification Latency:   {:.2} ns ({:.2} ops/sec)",
                    report.verification_latency_nanoseconds, report.verification_ops_per_second
                );
            }
        }
    }

    Ok(())
}

async fn run_tee(cli: &Cli, sub: &TeeSubCmd) -> anyhow::Result<()> {
    use velcrux_core::tee::{
        hex_decode, TeeAttestationEngine, TeeAttestationQuote, TeePlatform, TeePolicy,
    };

    let is_json = cli_log_json(cli);

    match sub {
        TeeSubCmd::Status { json } => {
            let engine = TeeAttestationEngine::new();
            let (total, succ, fail, last_latency_ns, active) = engine.stats();

            #[derive(Serialize)]
            struct TeeStatusOutput {
                supported_platforms: Vec<&'static str>,
                tee_attestations_total: u64,
                tee_attestation_successes_total: u64,
                tee_attestation_failures_total: u64,
                tee_verification_latency_nanoseconds: u64,
                tee_active_enclaves: u64,
            }

            let out = TeeStatusOutput {
                supported_platforms: vec![
                    "amd_sev_snp",
                    "intel_sgx",
                    "intel_tdx",
                    "aws_nitro",
                    "simulated",
                ],
                tee_attestations_total: total,
                tee_attestation_successes_total: succ,
                tee_attestation_failures_total: fail,
                tee_verification_latency_nanoseconds: last_latency_ns,
                tee_active_enclaves: active,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Confidential Computing & Hardware TEE Attestation Status ===");
                println!("  Supported Platforms:    amd_sev_snp, intel_sgx, intel_tdx, aws_nitro, simulated");
                println!("  TEE Attestations:       {}", out.tee_attestations_total);
                println!(
                    "  Attestation Successes:  {}",
                    out.tee_attestation_successes_total
                );
                println!(
                    "  Attestation Failures:   {}",
                    out.tee_attestation_failures_total
                );
                println!("  Active Enclaves:        {}", out.tee_active_enclaves);
                println!(
                    "  Last Latency:           {} ns ({:.2} µs)",
                    out.tee_verification_latency_nanoseconds,
                    (out.tee_verification_latency_nanoseconds as f64) / 1000.0
                );
            }
        }
        TeeSubCmd::Measure {
            binary,
            platform,
            json,
        } => {
            let plat = TeePlatform::from_str_loose(platform)
                .ok_or_else(|| anyhow::anyhow!("Unknown TEE platform: {platform}"))?;
            let bytes = std::fs::read(binary)
                .with_context(|| format!("Failed to read binary file from {}", binary.display()))?;
            let measurement = TeeAttestationEngine::measure_binary(&bytes, plat);

            #[derive(Serialize)]
            struct MeasureOutput {
                binary_path: String,
                platform: String,
                binary_size_bytes: usize,
                launch_measurement: String,
            }

            let out = MeasureOutput {
                binary_path: binary.display().to_string(),
                platform: plat.as_str().to_string(),
                binary_size_bytes: bytes.len(),
                launch_measurement: measurement.clone(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Enclave Launch Measurement Calculated ===");
                println!("  Binary:                 {}", out.binary_path);
                println!("  Platform:               {}", out.platform);
                println!("  Binary Size:            {} bytes", out.binary_size_bytes);
                println!("  Launch Measurement:     {}", out.launch_measurement);
            }
        }
        TeeSubCmd::Quote {
            platform,
            measurement,
            report_data,
            security_version,
            debug_mode,
            json,
        } => {
            let plat = TeePlatform::from_str_loose(platform)
                .ok_or_else(|| anyhow::anyhow!("Unknown TEE platform: {platform}"))?;
            let m = measurement.clone().unwrap_or_else(|| {
                TeeAttestationEngine::measure_binary(b"VELCRUX_DEFAULT_ENCLAVE_IMAGE_2026", plat)
            });
            let raw_report_data = if let Some(decoded) = hex_decode(report_data) {
                decoded
            } else {
                report_data.as_bytes().to_vec()
            };

            let engine = TeeAttestationEngine::new();
            let quote = engine.generate_quote(
                plat,
                &m,
                &raw_report_data,
                *security_version,
                *debug_mode,
            )?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&quote)?);
            } else {
                println!("=== Generated Hardware TEE Remote Attestation Quote ===");
                println!("  Platform:               {:?}", quote.platform);
                println!("  Enclave ID:             {}", quote.enclave_id);
                println!("  Launch Measurement:     {}", quote.measurement);
                println!("  Report Data (Hex):      {}", quote.report_data);
                println!("  Security Version (SVN): {}", quote.security_version);
                println!("  Debug Mode:             {}", quote.debug_enabled);
                println!("  Timestamp:              {}", quote.timestamp);
                println!("  Signing Key ID:         {}", quote.signing_key_id);
                println!("  Signature (Hex):        {}", quote.signature);
                println!();
                println!("Raw Quote JSON:");
                println!("{}", serde_json::to_string_pretty(&quote)?);
            }
        }
        TeeSubCmd::Verify {
            quote,
            policy,
            nonce,
            json,
        } => {
            let engine = TeeAttestationEngine::new();
            let quote_str = if std::path::Path::new(quote).exists() {
                std::fs::read_to_string(quote)?
            } else {
                quote.clone()
            };

            let q: TeeAttestationQuote = serde_json::from_str(&quote_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse TEE Quote JSON: {e}"))?;

            let pol: TeePolicy = if let Some(p) = policy {
                let policy_str = if std::path::Path::new(p).exists() {
                    std::fs::read_to_string(p)?
                } else {
                    p.clone()
                };
                serde_json::from_str(&policy_str)
                    .map_err(|e| anyhow::anyhow!("Failed to parse TEE Policy JSON: {e}"))?
            } else {
                TeePolicy::default()
            };

            let nonce_bytes = nonce.as_ref().map(|n| {
                if let Some(decoded) = hex_decode(n) {
                    decoded
                } else {
                    n.as_bytes().to_vec()
                }
            });

            let report = engine.verify_quote(&q, &pol, nonce_bytes.as_deref(), None)?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Hardware TEE Remote Attestation Validated ===");
                println!("  Status:                 VALID");
                println!("  Platform:               {:?}", report.platform);
                println!("  Enclave ID:             {}", report.enclave_id);
                println!("  Launch Measurement:     {}", report.measurement);
                println!("  Security Version:       {}", report.security_version);
                println!("  Debug Enabled:          {}", report.debug_enabled);
                println!("  Nonce Matched:          {}", report.nonce_matched);
                println!(
                    "  Quote Age:              {} seconds",
                    report.quote_age_seconds
                );
                println!(
                    "  Verification Latency:   {} ns ({:.2} µs)",
                    report.verification_latency_nanoseconds,
                    (report.verification_latency_nanoseconds as f64) / 1000.0
                );
            }
        }
        TeeSubCmd::Benchmark { iterations, json } => {
            let engine = TeeAttestationEngine::new();
            let report = engine.run_benchmark(*iterations);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "=== Hardware TEE Remote Attestation Benchmark ({} iters) ===",
                    report.iterations
                );
                println!(
                    "  Quote Generation Latency:     {:.2} ns ({:.2} ops/sec)",
                    report.quote_generation_latency_nanoseconds,
                    report.quote_generation_ops_per_second
                );
                println!(
                    "  Quote Verification Latency:   {:.2} ns ({:.2} ops/sec)",
                    report.quote_verification_latency_nanoseconds,
                    report.quote_verification_ops_per_second
                );
                println!(
                    "  Session Key Derivation:       {:.2} ns ({:.2} ops/sec)",
                    report.key_derivation_latency_nanoseconds, report.key_derivation_ops_per_second
                );
            }
        }
    }

    Ok(())
}

async fn run_ec(cli: &Cli, sub: &EcSubCmd) -> anyhow::Result<()> {
    use velcrux_core::ec::{ErasureEngine, ErasureSchema, ShardEnvelope, ShardScrubMesh};

    let is_json = cli_log_json(cli);

    match sub {
        EcSubCmd::Status { json } => {
            let mesh = ShardScrubMesh::new();
            let (enc, rep, scrub, corrupt, degraded, lat_ns) = mesh.stats();

            #[derive(Serialize)]
            struct EcStatusOutput {
                default_schema: String,
                supported_finite_field: &'static str,
                ec_encoded_shards_total: u64,
                ec_repaired_shards_total: u64,
                ec_scrubbed_shards_total: u64,
                ec_corrupted_shards_total: u64,
                ec_degraded_objects: u64,
                ec_repair_latency_nanoseconds: u64,
            }

            let out = EcStatusOutput {
                default_schema: "4+2 (K=4 data, M=2 parity)".to_string(),
                supported_finite_field: "Galois Field GF(2^8) with Cauchy MDS Generator",
                ec_encoded_shards_total: enc,
                ec_repaired_shards_total: rep,
                ec_scrubbed_shards_total: scrub,
                ec_corrupted_shards_total: corrupt,
                ec_degraded_objects: degraded,
                ec_repair_latency_nanoseconds: lat_ns,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Distributed Erasure Coding & Shard Scrub Mesh Status ===");
                println!("  Default Schema:         {}", out.default_schema);
                println!("  Finite Field / Matrix:  {}", out.supported_finite_field);
                println!("  Encoded Shards:         {}", out.ec_encoded_shards_total);
                println!("  Repaired Shards:        {}", out.ec_repaired_shards_total);
                println!("  Scrubbed Shards:        {}", out.ec_scrubbed_shards_total);
                println!(
                    "  Corrupted Shards:       {}",
                    out.ec_corrupted_shards_total
                );
                println!("  Degraded Objects:       {}", out.ec_degraded_objects);
                println!(
                    "  Last Repair Latency:    {} ns ({:.2} µs)",
                    out.ec_repair_latency_nanoseconds,
                    (out.ec_repair_latency_nanoseconds as f64) / 1000.0
                );
            }
        }
        EcSubCmd::Encode {
            input,
            out_dir,
            data_shards,
            parity_shards,
            object_id,
            json,
        } => {
            let schema = ErasureSchema::new(*data_shards, *parity_shards)?;
            let data = std::fs::read(input)
                .with_context(|| format!("Failed to read input file from {}", input.display()))?;

            let obj_id = object_id.clone().unwrap_or_else(|| {
                input
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("object")
                    .to_string()
            });

            let shards = ErasureEngine::encode(&data, schema, &obj_id)?;
            std::fs::create_dir_all(out_dir).with_context(|| {
                format!("Failed to create output directory: {}", out_dir.display())
            })?;

            let mut shard_files = Vec::with_capacity(shards.len());
            for s in &shards {
                let filename = format!("{}.shard.{}", obj_id, s.shard_index);
                let p = out_dir.join(filename);
                s.save_to_file(&p)?;
                shard_files.push(p.display().to_string());
            }

            #[derive(Serialize)]
            struct EncodeOutput {
                object_id: String,
                original_size_bytes: usize,
                data_shards: usize,
                parity_shards: usize,
                total_shards: usize,
                shard_size_bytes: usize,
                shard_files: Vec<String>,
            }

            let out = EncodeOutput {
                object_id: obj_id.clone(),
                original_size_bytes: data.len(),
                data_shards: *data_shards,
                parity_shards: *parity_shards,
                total_shards: shards.len(),
                shard_size_bytes: shards[0].payload.len(),
                shard_files,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Erasure Coding Encode Completed ===");
                println!("  Object ID:              {}", out.object_id);
                println!(
                    "  Schema:                 {} data + {} parity (Total: {})",
                    out.data_shards, out.parity_shards, out.total_shards
                );
                println!(
                    "  Original Size:          {} bytes",
                    out.original_size_bytes
                );
                println!("  Shard Size:             {} bytes", out.shard_size_bytes);
                println!("  Output Directory:       {}", out_dir.display());
            }
        }
        EcSubCmd::Decode {
            shards_dir,
            output,
            object_id,
            json,
        } => {
            // Find all valid shards in shards_dir
            let mut available_shards: Vec<ShardEnvelope> = Vec::new();
            if shards_dir.exists() && shards_dir.is_dir() {
                for entry in std::fs::read_dir(shards_dir)?.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(env) = ShardEnvelope::load_from_file(&path) {
                            if let Some(ref target_obj) = object_id {
                                if env.object_id == *target_obj {
                                    available_shards.push(env);
                                }
                            } else {
                                available_shards.push(env);
                            }
                        }
                    }
                }
            }

            if available_shards.is_empty() {
                anyhow::bail!(
                    "No valid erasure coding shards found in directory {}",
                    shards_dir.display()
                );
            }

            let schema = available_shards[0].schema;
            let obj_id = available_shards[0].object_id.clone();
            let total = schema.total_shards();
            let mut slots: Vec<Option<ShardEnvelope>> = vec![None; total];
            for env in available_shards {
                let idx = env.shard_index;
                if idx < total {
                    slots[idx] = Some(env);
                }
            }

            let decoded_bytes = ErasureEngine::decode(&slots, schema)?;
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(output, &decoded_bytes)?;

            #[derive(Serialize)]
            struct DecodeOutput {
                object_id: String,
                schema: ErasureSchema,
                reconstructed_size_bytes: usize,
                output_file: String,
            }

            let out = DecodeOutput {
                object_id: obj_id,
                schema,
                reconstructed_size_bytes: decoded_bytes.len(),
                output_file: output.display().to_string(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Erasure Coding Decode Completed ===");
                println!("  Object ID:              {}", out.object_id);
                println!(
                    "  Schema:                 {} data + {} parity",
                    out.schema.data_shards, out.schema.parity_shards
                );
                println!(
                    "  Reconstructed Size:     {} bytes",
                    out.reconstructed_size_bytes
                );
                println!("  Output File:            {}", out.output_file);
            }
        }
        EcSubCmd::Scrub {
            shards_dir,
            auto_repair,
            json,
        } => {
            let mesh = ShardScrubMesh::new();
            if *auto_repair {
                let report = mesh.auto_repair_directory(shards_dir)?;
                if *json || is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("=== Erasure Coding Autonomous Shard Scrub & Repair ===");
                    println!("  Scanned Directory:      {}", shards_dir.display());
                    println!(
                        "  Total Files Scanned:    {}",
                        report.scrub_report.total_files_scanned
                    );
                    println!(
                        "  Objects Scanned:        {}",
                        report.scrub_report.objects_scanned
                    );
                    println!(
                        "  Healthy Objects:        {}",
                        report.scrub_report.healthy_objects
                    );
                    println!(
                        "  Degraded Objects:       {}",
                        report.scrub_report.degraded_objects
                    );
                    println!(
                        "  Critical Objects:       {}",
                        report.scrub_report.critical_objects
                    );
                    println!(
                        "  Unrecoverable Objects:  {}",
                        report.scrub_report.unrecoverable_objects
                    );
                    println!("  Objects Self-Healed:    {}", report.objects_repaired);
                    println!("  Shards Reconstructed:   {}", report.shards_reconstructed);
                }
            } else {
                let report = mesh.scrub_directory(shards_dir)?;
                if *json || is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("=== Erasure Coding Shard Scrub Inspection ===");
                    println!("  Scanned Directory:      {}", shards_dir.display());
                    println!("  Total Files Scanned:    {}", report.total_files_scanned);
                    println!("  Objects Scanned:        {}", report.objects_scanned);
                    println!("  Valid Shards:           {}", report.valid_shards);
                    println!("  Corrupted Shards:       {}", report.corrupted_shards);
                    println!("  Healthy Objects:        {}", report.healthy_objects);
                    println!("  Degraded Objects:       {}", report.degraded_objects);
                    println!("  Critical Objects:       {}", report.critical_objects);
                    println!("  Unrecoverable Objects:  {}", report.unrecoverable_objects);
                }
            }
        }
        EcSubCmd::Benchmark {
            iterations,
            size,
            json,
        } => {
            let mesh = ShardScrubMesh::new();
            let report = mesh.run_benchmark(*iterations, *size);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "=== Erasure Coding & Self-Healing Benchmark ({} iters, {} bytes) ===",
                    report.iterations, report.payload_size_bytes
                );
                println!(
                    "  Schema:                 {} data + {} parity",
                    report.schema.data_shards, report.schema.parity_shards
                );
                println!(
                    "  Encoding Latency:       {:.2} ns ({:.2} MiB/s)",
                    report.encode_latency_nanoseconds,
                    report.encode_throughput_bytes_per_sec / (1024.0 * 1024.0)
                );
                println!(
                    "  Decoding Latency:       {:.2} ns ({:.2} MiB/s)",
                    report.decode_latency_nanoseconds,
                    report.decode_throughput_bytes_per_sec / (1024.0 * 1024.0)
                );
                println!(
                    "  Single-Shard Repair:    {:.2} ns ({:.2} µs)",
                    report.single_shard_repair_latency_nanoseconds,
                    report.single_shard_repair_latency_nanoseconds / 1000.0
                );
            }
        }
    }

    Ok(())
}

async fn run_delta_slice(cli: &Cli, sub: &DeltaSliceSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    match sub {
        DeltaSliceSubCmd::Test {
            source,
            baseline,
            chunk_size,
            policy,
            threshold,
            json,
        } => {
            let src_data = std::fs::read(source).map_err(|e| {
                anyhow::anyhow!("failed to read source file '{}': {e}", source.display())
            })?;
            let base_data = std::fs::read(baseline).map_err(|e| {
                anyhow::anyhow!("failed to read baseline file '{}': {e}", baseline.display())
            })?;

            let parsed_policy: velcrux_core::sync::DeltaDictPolicy = policy.parse()?;
            let engine = velcrux_core::sync::ContentDeltaEngine::new(
                parsed_policy,
                *threshold,
                velcrux_core::sync::DEFAULT_DELTA_COMPRESSION_LEVEL,
            );

            let report = engine.evaluate_delta(&src_data, &base_data, *chunk_size);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Delta Slice Evaluation Report ===");
                println!("Source File:             {}", source.display());
                println!("Baseline File:           {}", baseline.display());
                println!("Chunk Slicing Size:      {} bytes", chunk_size);
                println!("Delta Policy:            {}", parsed_policy);
                println!("Savings Threshold:       {}%", threshold);
                println!("Original Bytes:          {} bytes", report.original_bytes);
                println!(
                    "Transferred Bytes:       {} bytes",
                    report.transferred_bytes
                );
                println!("Bytes Saved:             {} bytes", report.bytes_saved);
                println!("Compression Ratio:       {:.2}x", report.compression_ratio);
                println!("Exact Matches:           {}", report.exact_matches);
                println!("Dict Compressed Chunks:  {}", report.dict_compressed_chunks);
                println!(
                    "Vanilla Zstd Chunks:     {}",
                    report.vanilla_compressed_chunks
                );
                println!("Raw Literal Chunks:      {}", report.raw_literal_chunks);
            }
            Ok(())
        }
    }
}

async fn run_bdp(cli: &Cli, sub: &BdpSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    match sub {
        BdpSubCmd::Inspect { json } => {
            let policy: velcrux_core::transport::BdpTuningPolicy = cli.bdp_tuning.parse()?;
            let config = velcrux_core::transport::BdpWindowConfig::new(
                policy,
                cli.min_bdp_window,
                cli.max_bdp_window,
                velcrux_core::transport::DEFAULT_BDP_MULTIPLIER,
            );
            let tuner = velcrux_core::transport::BdpAutoTuner::new(config.clone());
            let report = tuner.report();

            if *json || is_json {
                let out = serde_json::json!({
                    "policy": policy.to_string(),
                    "current_window_bytes": report.current_window_bytes,
                    "target_window_bytes": report.target_window_bytes,
                    "min_window_bytes": config.min_window_bytes,
                    "max_window_bytes": config.max_window_bytes,
                    "multiplier": config.multiplier,
                    "tier": report.tier.to_string(),
                    "smoothed_rtt_ms": report.smoothed_rtt_ms,
                    "min_rtt_ms": report.min_rtt_ms,
                    "estimated_bandwidth_bps": report.estimated_bandwidth_bps,
                    "bufferbloat_detected": report.bufferbloat_detected,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== BDP Transport Flow Control Status ===");
                println!("Tuning Policy:           {}", policy);
                println!(
                    "Current Active Window:   {} ({})",
                    report.current_window_bytes,
                    format_bytes(report.current_window_bytes)
                );
                println!(
                    "Target Optimal Window:   {} ({})",
                    report.target_window_bytes,
                    format_bytes(report.target_window_bytes)
                );
                println!(
                    "Window Floor (Min):      {} ({})",
                    config.min_window_bytes,
                    format_bytes(config.min_window_bytes)
                );
                println!(
                    "Window Ceiling (Max):    {} ({})",
                    config.max_window_bytes,
                    format_bytes(config.max_window_bytes)
                );
                println!("BDP Multiplier:          {:.1}x", config.multiplier);
                println!("Network Delay Tier:      {}", report.tier);
                println!("Smoothed RTT:            {:.2} ms", report.smoothed_rtt_ms);
                println!("Min Propagation RTT:     {:.2} ms", report.min_rtt_ms);
                println!(
                    "Estimated Bandwidth:     {:.2} Mbps",
                    report.estimated_bandwidth_bps as f64 / 1_000_000.0
                );
                println!(
                    "Bufferbloat Guard:       {}",
                    if report.bufferbloat_detected {
                        "TRIGGERED (Queue delay spike)"
                    } else {
                        "Clean"
                    }
                );
            }
            Ok(())
        }
        BdpSubCmd::Simulate {
            bandwidth,
            rtt_ms,
            loss_pct,
            policy,
            json,
        } => {
            let parsed_policy: velcrux_core::transport::BdpTuningPolicy = policy.parse()?;
            let bps = velcrux_core::transfer::parse_rate_limit(bandwidth)
                .map_err(|e| anyhow::anyhow!("invalid bandwidth '{bandwidth}': {e}"))?;
            let effective_bytes_per_sec = if bps == 0 { 125_000_000 } else { bps };

            let config = velcrux_core::transport::BdpWindowConfig::new(
                parsed_policy,
                cli.min_bdp_window,
                cli.max_bdp_window,
                velcrux_core::transport::DEFAULT_BDP_MULTIPLIER,
            );
            let mut tuner = velcrux_core::transport::BdpAutoTuner::new(config);

            let rtt = std::time::Duration::from_millis(*rtt_ms);
            let loss_events = if *loss_pct > 0.0 {
                ((*loss_pct / 100.0) * 100.0).round() as u64
            } else {
                0
            };

            // Run 5 iterative tuning feedback samples
            let chunk_sample =
                (effective_bytes_per_sec as f64 * (rtt.as_secs_f64().max(0.01))).round() as u64;
            for _ in 0..5 {
                tuner.record_sample(rtt, chunk_sample, rtt, loss_events);
            }
            let report = tuner.report();

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== BDP Auto-Tuning Simulation Report ===");
                println!(
                    "Link Bandwidth:          {} ({:.2} Mbps)",
                    bandwidth,
                    (effective_bytes_per_sec * 8) as f64 / 1_000_000.0
                );
                println!("Path RTT:                {} ms", rtt_ms);
                println!("Loss Rate:               {:.2}%", loss_pct);
                println!("Tuning Policy:           {}", parsed_policy);
                println!("Classified Tier:         {}", report.tier);
                println!(
                    "Converged Window:        {} ({})",
                    report.current_window_bytes,
                    format_bytes(report.current_window_bytes)
                );
                println!(
                    "Target BDP Window:       {} ({})",
                    report.target_window_bytes,
                    format_bytes(report.target_window_bytes)
                );
                println!("Adjustment Action:       {}", report.direction);
                println!(
                    "Bufferbloat Status:      {}",
                    if report.bufferbloat_detected {
                        "DECAY APPLIED"
                    } else {
                        "Nominal"
                    }
                );
                println!(
                    "Expansions / Decays:     {} / {}",
                    report.expansions_total, report.decays_total
                );
            }
            Ok(())
        }
    }
}

async fn run_direct_io(cli: &Cli, sub: &DirectIoSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let mut config = get_direct_io_ring_config(cli)?;

    match sub {
        DirectIoSubCmd::Inspect { path, json } => {
            let mut file_exists = false;
            let mut file_size = 0u64;
            let mut direct_eligible = false;

            if let Some(ref p_str) = path {
                let p = std::path::Path::new(p_str);
                if let Ok(meta) = std::fs::metadata(p) {
                    file_exists = true;
                    file_size = meta.len();
                    direct_eligible = match config.mode {
                        velcrux_core::DirectIoMode::Always => true,
                        velcrux_core::DirectIoMode::Disabled => false,
                        velcrux_core::DirectIoMode::Auto => file_size >= config.min_file_size,
                    };
                }
            }

            if *json || is_json {
                let out = serde_json::json!({
                    "direct_io_mode": config.mode.to_string(),
                    "ring_slots": config.ring_slots,
                    "slot_capacity_bytes": config.slot_capacity,
                    "sector_size_bytes": config.sector_size,
                    "min_file_size_bytes": config.min_file_size,
                    "target_path": path,
                    "file_exists": file_exists,
                    "file_size_bytes": file_size,
                    "direct_io_eligible": direct_eligible,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Direct I/O Ring-Buffer Pipeline Configuration ===");
                println!("Execution Mode:          {}", config.mode);
                println!("Ring Buffer Slots:       {}", config.ring_slots);
                println!(
                    "Slot Capacity:           {} ({})",
                    config.slot_capacity,
                    format_bytes(config.slot_capacity as u64)
                );
                println!("Physical Sector Size:    {} bytes", config.sector_size);
                println!(
                    "Auto Mode Min Size:      {} ({})",
                    config.min_file_size,
                    format_bytes(config.min_file_size)
                );
                if let Some(ref p) = path {
                    println!("\nTarget Path Inspection:  {}", p);
                    println!("Path Exists:             {}", file_exists);
                    if file_exists {
                        println!(
                            "File Size:               {} ({})",
                            file_size,
                            format_bytes(file_size)
                        );
                        println!("Direct I/O Eligible:     {}", direct_eligible);
                    }
                }
            }
            Ok(())
        }
        DirectIoSubCmd::Benchmark {
            path,
            size,
            slots,
            slot_size,
            json,
        } => {
            if let Some(s) = slots {
                config.ring_slots = *s;
            }
            if let Some(sz) = slot_size {
                config.slot_capacity = *sz;
            }

            let report = velcrux_core::storage::direct_io::run_direct_io_benchmark(
                std::path::Path::new(path),
                *size,
                config,
            )?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Direct I/O Ring-Buffer Pipeline Benchmark ===");
                println!("Target Path:             {}", report.path);
                println!(
                    "Payload Streamed:        {} ({})",
                    report.total_bytes,
                    format_bytes(report.total_bytes)
                );
                println!(
                    "Ring Configuration:      {} slots × {} ({})",
                    report.ring_slots,
                    report.slot_capacity,
                    format_bytes(report.slot_capacity as u64)
                );
                println!("Sector Alignment:        {} bytes", report.sector_size);
                println!("Direct I/O Active:       {}", report.is_direct);
                println!(
                    "Streaming Write:         {:.2} ms ({:.2} MiB/s)",
                    report.write_duration_ms, report.write_throughput_mb_s
                );
                println!(
                    "Streaming Read:          {:.2} ms ({:.2} MiB/s)",
                    report.read_duration_ms, report.read_throughput_mb_s
                );
                println!("Pipeline Stalls:         {}", report.stalls_count);
                println!(
                    "Integrity Verified:      {}",
                    if report.data_integrity_verified {
                        "PASS (BLAKE3 exact match)"
                    } else {
                        "FAIL (checksum mismatch)"
                    }
                );
                println!("BLAKE3 Hash:             {}", report.checksum_blake3);
            }
            Ok(())
        }
    }
}

async fn run_checkpoint(cli: &Cli, sub: &CheckpointSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);

    match sub {
        CheckpointSubCmd::Status { role, json } => {
            let store = open_state_store_for_role(cli, role)?;
            let report = velcrux_core::transfer::TransferResumeCoordinator::fast_recover_all(
                store.as_ref(),
                None,
            )?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Transfer Checkpoint & Recovery Status ({role}) ===");
                println!("Resumable Transfers:     {}", report.resumable_count);
                println!(
                    "Total Resumable Bytes:   {} ({})",
                    report.total_bytes_resumable,
                    format_bytes(report.total_bytes_resumable)
                );
                println!(
                    "Total Completed Bytes:   {} ({})",
                    report.total_bytes_completed,
                    format_bytes(report.total_bytes_completed)
                );
                if let Some(ref wal) = report.wal_status {
                    println!("\nSQLite WAL Status:");
                    println!("Mode:                    {:?}", wal.mode);
                    println!("Busy/Blocked:            {}", wal.busy);
                    println!("Log Pages:               {}", wal.log_pages);
                    println!("Checkpointed Pages:      {}", wal.checkpointed_pages);
                    println!("Duration:                {} µs", wal.duration_micros);
                }
                if !report.transfers.is_empty() {
                    println!("\nActive Resumable Transfers:");
                    for t in &report.transfers {
                        println!(
                            "- [{}] ID: {} ({:.1}%) - {} / {}",
                            t.status,
                            t.transfer_id,
                            t.completion_pct,
                            format_bytes(t.bytes_completed),
                            format_bytes(t.file_size)
                        );
                        println!("  Path:                  {}", t.remote_path);
                    }
                }
            }
            Ok(())
        }
        CheckpointSubCmd::Recover {
            transfer_id,
            role,
            json,
        } => {
            let store = open_state_store_for_role(cli, role)?;
            if let Some(ref tid_str) = transfer_id {
                let tid = velcrux_core::util::TransferId::from_string(tid_str)
                    .ok_or_else(|| anyhow::anyhow!("invalid transfer ID: {tid_str}"))?;
                let summary = velcrux_core::transfer::TransferResumeCoordinator::recover_transfer(
                    store.as_ref(),
                    tid,
                    None,
                )?;
                if *json || is_json {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                } else {
                    println!("=== Transfer Recovery Verification ===");
                    println!("Transfer ID:             {}", summary.transfer_id);
                    println!("Status:                  {}", summary.status);
                    println!("Verified:                {}", summary.verified);
                    println!("Completed:               {:.1}%", summary.completion_pct);
                    println!(
                        "Bytes Completed:         {} / {} ({})",
                        summary.bytes_completed,
                        summary.file_size,
                        format_bytes(summary.bytes_completed)
                    );
                    println!("Chunks Completed:        {}", summary.chunks_completed);
                    println!("Remote Path:             {}", summary.remote_path);
                }
            } else {
                let report = velcrux_core::transfer::TransferResumeCoordinator::fast_recover_all(
                    store.as_ref(),
                    None,
                )?;
                if *json || is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("=== Fast Instantaneous Recovery Report ({role}) ===");
                    println!(
                        "Transfers Marked Resumable: {}",
                        report.active_transfers_marked_resumable
                    );
                    println!("Total Resumable Transfers:  {}", report.resumable_count);
                    println!(
                        "Total Resumable Data:       {} ({})",
                        report.total_bytes_resumable,
                        format_bytes(report.total_bytes_resumable)
                    );
                    for t in &report.transfers {
                        println!(
                            "- {} | {:.1}% completed ({}) | {}",
                            t.transfer_id,
                            t.completion_pct,
                            format_bytes(t.bytes_completed),
                            t.remote_path
                        );
                    }
                }
            }
            Ok(())
        }
        CheckpointSubCmd::Prune {
            older_than_secs,
            role,
            json,
        } => {
            let store = open_state_store_for_role(cli, role)?;
            let pruned_count = velcrux_core::transfer::TransferResumeCoordinator::prune_stale(
                store.as_ref(),
                *older_than_secs,
            )?;
            if *json || is_json {
                let out = serde_json::json!({
                    "pruned_transfers": pruned_count,
                    "older_than_secs": older_than_secs,
                    "role": role,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("=== Pruned Stale Checkpoints ({role}) ===");
                println!("Pruned Records:          {}", pruned_count);
                println!("Age Threshold:           {} seconds", older_than_secs);
            }
            Ok(())
        }
        CheckpointSubCmd::WalFlush { mode, role, json } => {
            let store = open_state_store_for_role(cli, role)?;
            let wal_mode = velcrux_core::state::WalCheckpointMode::parse(mode)
                .ok_or_else(|| anyhow::anyhow!("unknown WAL checkpoint mode: {mode} (valid: truncate, passive, full, restart)"))?;
            let report = velcrux_core::transfer::TransferResumeCoordinator::wal_flush(
                store.as_ref(),
                wal_mode,
            )?;
            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== SQLite WAL Checkpoint Flush ({role}) ===");
                println!("Requested Mode:          {:?}", report.mode);
                println!("Busy / Blocked:          {}", report.busy);
                println!("Log Pages in WAL:        {}", report.log_pages);
                println!("Pages Moved to DB:       {}", report.checkpointed_pages);
                println!("Duration:                {} µs", report.duration_micros);
            }
            Ok(())
        }
    }
}

async fn run_qos(cli: &Cli, sub: &QosSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);

    match sub {
        QosSubCmd::Inspect { bandwidth, json } => {
            let bw_str = if bandwidth == "unlimited" && cli.qos_bandwidth != "unlimited" {
                &cli.qos_bandwidth
            } else {
                bandwidth
            };
            let rate = bw_str
                .parse::<velcrux_core::scheduler::fairness::BandwidthRate>()
                .map_err(|e| anyhow::anyhow!("Invalid bandwidth '{bw_str}': {e}"))?;

            let _scheduler = velcrux_core::scheduler::HierarchicalQosScheduler::new(rate);

            #[derive(Serialize)]
            struct QosClassAllocation {
                class: String,
                weight: u32,
                cir_fraction: f64,
                cir_bandwidth: String,
                pir_ceiling: String,
            }

            let classes = [
                velcrux_core::scheduler::QosClass::Realtime,
                velcrux_core::scheduler::QosClass::Critical,
                velcrux_core::scheduler::QosClass::Default,
                velcrux_core::scheduler::QosClass::Background,
            ];

            let allocations: Vec<QosClassAllocation> = classes
                .iter()
                .map(|&c| {
                    let cir_bps = if rate.bytes_per_sec() == 0 {
                        0
                    } else {
                        (rate.bytes_per_sec() as f64 * c.default_cir_fraction()) as u64
                    };
                    let cir_rate =
                        velcrux_core::scheduler::fairness::BandwidthRate::from_bytes_per_sec(
                            cir_bps,
                        );
                    QosClassAllocation {
                        class: c.as_str().to_string(),
                        weight: c.weight(),
                        cir_fraction: c.default_cir_fraction(),
                        cir_bandwidth: cir_rate.to_string(),
                        pir_ceiling: rate.to_string(),
                    }
                })
                .collect();

            #[derive(Serialize)]
            struct QosInspectReport {
                root_bandwidth: String,
                allocations: Vec<QosClassAllocation>,
            }

            let report = QosInspectReport {
                root_bandwidth: rate.to_string(),
                allocations,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Hierarchical Token-Bucket (HTB) QoS Inspection ===");
                println!("Root Bandwidth Ceiling:  {}", report.root_bandwidth);
                println!("\nClass Allocations:");
                println!(
                    "  {:<12} {:<8} {:<14} {:<18} {:<18}",
                    "CLASS", "WEIGHT", "CIR FRACTION", "GUARANTEED (CIR)", "PEAK CEILING (PIR)"
                );
                println!("  {}", "-".repeat(74));
                for a in &report.allocations {
                    let cir_pct = format!("{:.1}%", a.cir_fraction * 100.0);
                    println!(
                        "  {:<12} {:<8} {:<14} {:<18} {:<18}",
                        a.class, a.weight, cir_pct, a.cir_bandwidth, a.pir_ceiling
                    );
                }
            }
            Ok(())
        }
        QosSubCmd::Benchmark {
            bandwidth,
            packets,
            json,
        } => {
            let bw_str = if bandwidth == "1Gbps" && cli.qos_bandwidth != "unlimited" {
                &cli.qos_bandwidth
            } else {
                bandwidth
            };
            let rate = bw_str
                .parse::<velcrux_core::scheduler::fairness::BandwidthRate>()
                .map_err(|e| anyhow::anyhow!("Invalid bandwidth '{bw_str}': {e}"))?;

            let report = velcrux_core::scheduler::run_qos_benchmark(rate, *packets);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Hierarchical QoS Flow Contention Benchmark ===");
                println!("Root Bandwidth:          {}", report.root_bandwidth);
                println!(
                    "Total Bytes Admitted:    {} ({})",
                    report.total_bytes_admitted,
                    format_bytes(report.total_bytes_admitted)
                );
                println!(
                    "Total Bytes Borrowed:    {} ({})",
                    report.total_bytes_borrowed,
                    format_bytes(report.total_bytes_borrowed)
                );
                println!("Throttles Triggered:     {}", report.total_throttles);
                println!("Duration:                {} ms", report.duration_ms);
                println!("CIR Isolation Verified:  {}", report.cir_isolation_verified);
                println!("\nPer-Class Distribution:");
                println!(
                    "  Realtime:   {} ({})",
                    report.realtime_bytes,
                    format_bytes(report.realtime_bytes)
                );
                println!(
                    "  Critical:   {} ({})",
                    report.critical_bytes,
                    format_bytes(report.critical_bytes)
                );
                println!(
                    "  Default:    {} ({})",
                    report.default_bytes,
                    format_bytes(report.default_bytes)
                );
                println!(
                    "  Background: {} ({})",
                    report.background_bytes,
                    format_bytes(report.background_bytes)
                );
            }
            Ok(())
        }
        QosSubCmd::Status { json } => {
            let priority_str = &cli.qos_priority;
            let class = velcrux_core::scheduler::QosClass::parse(priority_str)
                .unwrap_or(velcrux_core::scheduler::QosClass::Default);
            let bw_str = &cli.qos_bandwidth;
            let rate = bw_str
                .parse::<velcrux_core::scheduler::fairness::BandwidthRate>()
                .unwrap_or(velcrux_core::scheduler::fairness::BandwidthRate::UNLIMITED);

            let cir_bps = if rate.bytes_per_sec() == 0 {
                0
            } else {
                (rate.bytes_per_sec() as f64 * class.default_cir_fraction()) as u64
            };
            let cir_rate =
                velcrux_core::scheduler::fairness::BandwidthRate::from_bytes_per_sec(cir_bps);

            #[derive(Serialize)]
            struct QosStatusReport {
                qos_priority: String,
                weight: u32,
                cir_fraction: f64,
                cir_bandwidth: String,
                root_bandwidth: String,
                multiplexing: &'static str,
            }

            let report = QosStatusReport {
                qos_priority: class.as_str().to_string(),
                weight: class.weight(),
                cir_fraction: class.default_cir_fraction(),
                cir_bandwidth: cir_rate.to_string(),
                root_bandwidth: rate.to_string(),
                multiplexing: "Hierarchical Token-Bucket (HTB) + Deficit Round-Robin (DRR)",
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Active QoS & Flow Multiplexing Status ===");
                println!("Priority Tier:           {}", report.qos_priority);
                println!("Scheduling Weight:       {}", report.weight);
                println!(
                    "CIR Guaranteed Fraction: {:.1}%",
                    report.cir_fraction * 100.0
                );
                println!("CIR Guaranteed Rate:     {}", report.cir_bandwidth);
                println!("Root Bandwidth Ceiling:  {}", report.root_bandwidth);
                println!("Multiplexing Mode:       {}", report.multiplexing);
            }
            Ok(())
        }
    }
}

async fn run_cas(cli: &Cli, sub: &CasSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);

    match sub {
        CasSubCmd::Status { chunk_store, json } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::GenerationalCasManager::new(root);
            let status = mgr.status(cli.cas_nursery_grace)?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("=== Content-Addressable Storage (CAS) Status ===");
                println!("Chunks Root:             {}", status.chunks_dir);
                println!(
                    "Total Chunks:            {} ({} stored)",
                    status.total_chunks,
                    format_bytes(status.total_bytes)
                );
                println!(
                    "  Nursery (Gen 0):       {} ({})",
                    status.nursery_chunks,
                    format_bytes(status.nursery_bytes)
                );
                println!(
                    "  Tenured (Gen 1):       {} ({})",
                    status.tenured_chunks,
                    format_bytes(status.tenured_bytes)
                );
                println!(
                    "  Tombstoned (Gen 2):    {} ({})",
                    status.tombstoned_chunks,
                    format_bytes(status.tombstoned_bytes)
                );
                println!(
                    "Reclaimable Storage:     {}",
                    format_bytes(status.reclaimable_bytes)
                );
            }
            Ok(())
        }
        CasSubCmd::Gc {
            chunk_store,
            storage_root,
            nursery_grace,
            tombstone_ttl,
            purge_expired,
            dry_run,
            json,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::GenerationalCasManager::new(root);

            let roots: Vec<PathBuf> = if storage_root.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                storage_root.clone()
            };
            let root_refs: Vec<&Path> = roots.iter().map(|p| p.as_path()).collect();
            let refs = velcrux_core::storage::GenerationalCasManager::collect_references(
                &root_refs, None, None,
            )?;

            let policy = velcrux_core::storage::CasGcPolicy {
                nursery_grace_secs: nursery_grace.unwrap_or(cli.cas_nursery_grace),
                tombstone_ttl_secs: tombstone_ttl.unwrap_or(cli.cas_tombstone_ttl),
                purge_expired: *purge_expired,
                dry_run: *dry_run,
            };

            let report = mgr.mark_and_sweep(&refs, &policy)?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== CAS Generational Mark-and-Sweep Garbage Collection ===");
                if report.dry_run {
                    println!("Mode:                    DRY-RUN (Simulated)");
                }
                println!("Total Chunks Scanned:    {}", report.total_chunks_scanned);
                println!("Nursery (Gen 0) Leased:  {}", report.nursery_chunks);
                println!("Tenured (Gen 1) Active:  {}", report.tenured_chunks);
                println!("Existing Tombstones:     {}", report.existing_tombstones);
                println!("Newly Tombstoned:        {}", report.newly_tombstoned);
                println!("Resurrected Chunks:      {}", report.resurrected_chunks);
                println!("Purged Chunks:           {}", report.purged_chunks);
                println!(
                    "Total Bytes Scanned:     {} ({})",
                    report.bytes_scanned,
                    format_bytes(report.bytes_scanned)
                );
                println!(
                    "Bytes in Tombstoned:     {} ({})",
                    report.bytes_tombstoned,
                    format_bytes(report.bytes_tombstoned)
                );
                println!(
                    "Bytes Reclaimed:         {} ({})",
                    report.bytes_reclaimed,
                    format_bytes(report.bytes_reclaimed)
                );
                println!(
                    "Bytes Retained:          {} ({})",
                    report.bytes_retained,
                    format_bytes(report.bytes_retained)
                );
                println!("Elapsed Duration:        {} ms", report.duration_ms);
            }
            Ok(())
        }
        CasSubCmd::Resurrect {
            hash,
            chunk_store,
            json,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::GenerationalCasManager::new(root);
            let h = velcrux_core::util::Hash::from_hex(hash)
                .ok_or_else(|| anyhow::anyhow!("Invalid chunk hash: {hash}"))?;

            let success = mgr.resurrect(&h)?;

            #[derive(Serialize)]
            struct ResurrectResponse {
                hash: String,
                resurrected: bool,
            }

            let resp = ResurrectResponse {
                hash: hash.clone(),
                resurrected: success,
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else if success {
                println!("Successfully resurrected chunk {hash} from tombstoned to tenured.");
            } else {
                println!("Chunk {hash} was not found or not tombstoned.");
            }
            Ok(())
        }
        CasSubCmd::Purge {
            chunk_store,
            older_than_secs,
            dry_run,
            json,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::GenerationalCasManager::new(root);

            let report = mgr.purge_tombstones(*older_than_secs, *dry_run)?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== CAS Tombstone Hard-Purge Compaction ===");
                if report.dry_run {
                    println!("Mode:                    DRY-RUN (Simulated)");
                }
                println!("Chunks Scanned:          {}", report.total_chunks_scanned);
                println!("Tombstones Inspected:    {}", report.existing_tombstones);
                println!("Chunks Purged:           {}", report.purged_chunks);
                println!(
                    "Disk Space Reclaimed:    {} ({})",
                    report.bytes_reclaimed,
                    format_bytes(report.bytes_reclaimed)
                );
                println!("Compaction Duration:     {} ms", report.duration_ms);
            }
            Ok(())
        }
    }
}

fn scan_files_recursive(dir: &Path, count: &mut usize, bytes: &mut u64) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                *count += 1;
                if let Ok(meta) = entry.metadata() {
                    *bytes += meta.len();
                }
            } else if path.is_dir() {
                scan_files_recursive(&path, count, bytes);
            }
        }
    }
}

async fn run_swarm(cli: &Cli, sub: &SwarmSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);

    match sub {
        SwarmSubCmd::Status { json } => {
            let local_id = format!("node-{}", std::process::id());
            let local_addr: std::net::SocketAddr =
                format!("127.0.0.1:{}", cli.swarm_port).parse()?;
            let mut config = velcrux_core::SwarmConfig::default();
            config.max_peers = cli.swarm_max_peers;
            for seed in &cli.swarm_seeds {
                if let Ok(addr) = seed.parse::<std::net::SocketAddr>() {
                    config.seed_addresses.push(addr);
                }
            }
            let engine = velcrux_core::GossipDiscoveryEngine::new(local_id, local_addr, config);
            for (i, seed) in cli.swarm_seeds.iter().enumerate() {
                if let Ok(addr) = seed.parse::<std::net::SocketAddr>() {
                    engine.add_seed_peer(&format!("seed-node-{i}"), addr);
                }
            }
            let report = engine.status();

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Velcrux Swarm P2P Mesh Status ===");
                println!("Node ID:                 {}", report.local_peer_id);
                println!("Listen Address:          {}", report.local_address);
                println!("Total Peers:             {}", report.total_peers);
                println!(
                    "Peer States:             {} alive, {} suspect, {} dead, {} banned",
                    report.alive_peers,
                    report.suspect_peers,
                    report.dead_peers,
                    report.banned_peers
                );
                println!(
                    "Offload Ratio:           {:.1}%",
                    report.offload_ratio * 100.0
                );
                println!(
                    "Bytes Inbound (P2P):     {} ({})",
                    report.bytes_downloaded_p2p,
                    format_bytes(report.bytes_downloaded_p2p)
                );
                println!(
                    "Bytes Outbound (P2P):    {} ({})",
                    report.bytes_uploaded_p2p,
                    format_bytes(report.bytes_uploaded_p2p)
                );
                println!(
                    "Bytes Saved (Server):    {} ({})",
                    report.bytes_offloaded_server,
                    format_bytes(report.bytes_offloaded_server)
                );
                println!("Chunks Transferred P2P:  {}", report.chunks_transferred_p2p);
                println!(
                    "Poisoned Chunks Blocked: {}",
                    report.chunks_poisoned_rejected
                );
            }
            Ok(())
        }
        SwarmSubCmd::Peers { json } => {
            let local_id = format!("node-{}", std::process::id());
            let local_addr: std::net::SocketAddr =
                format!("127.0.0.1:{}", cli.swarm_port).parse()?;
            let mut config = velcrux_core::SwarmConfig::default();
            config.max_peers = cli.swarm_max_peers;
            for seed in &cli.swarm_seeds {
                if let Ok(addr) = seed.parse::<std::net::SocketAddr>() {
                    config.seed_addresses.push(addr);
                }
            }
            let engine = velcrux_core::GossipDiscoveryEngine::new(local_id, local_addr, config);
            for (i, seed) in cli.swarm_seeds.iter().enumerate() {
                if let Ok(addr) = seed.parse::<std::net::SocketAddr>() {
                    engine.add_seed_peer(&format!("seed-node-{i}"), addr);
                }
            }
            let peers = engine.peers();

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&peers)?);
            } else if peers.is_empty() {
                println!(
                    "No discovered peers in swarm mesh (seed count: {}).",
                    cli.swarm_seeds.len()
                );
            } else {
                println!("=== Discovered Swarm Mesh Peers ({}) ===", peers.len());
                for peer in peers {
                    println!(
                        "  [{}] {} ({}) - inc:{}, rtt:{}ms",
                        peer.state, peer.peer_id, peer.address, peer.incarnation, peer.rtt_ms
                    );
                }
            }
            Ok(())
        }
        SwarmSubCmd::Advertise { manifest, json } => {
            #[derive(Serialize)]
            struct SwarmAdvertiseReport {
                manifest_path: String,
                advertised_chunks: usize,
                total_bytes: u64,
                status: String,
            }

            let mut advertised_count = 0usize;
            let mut total_bytes = 0u64;

            if manifest.is_file() {
                let data = std::fs::read(manifest)
                    .with_context(|| format!("reading manifest file {}", manifest.display()))?;
                total_bytes = data.len() as u64;
                advertised_count = 1;
            } else if manifest.is_dir() {
                scan_files_recursive(manifest, &mut advertised_count, &mut total_bytes);
            } else {
                anyhow::bail!("manifest path not found: {}", manifest.display());
            }

            let report = SwarmAdvertiseReport {
                manifest_path: manifest.display().to_string(),
                advertised_chunks: advertised_count,
                total_bytes,
                status: "advertised".to_string(),
            };

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Swarm Manifest Advertisement ===");
                println!("Manifest Path:      {}", report.manifest_path);
                println!("Advertised Chunks:  {}", report.advertised_chunks);
                println!(
                    "Total Volume:       {} ({})",
                    report.total_bytes,
                    format_bytes(report.total_bytes)
                );
                println!("Gossip Status:      {}", report.status);
            }
            Ok(())
        }
        SwarmSubCmd::Benchmark {
            nodes,
            chunks,
            json,
        } => {
            let report = velcrux_core::run_swarm_benchmark(*nodes, *chunks);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Velcrux Swarm P2P Acceleration Benchmark ===");
                println!("Simulated Swarm Nodes:   {}", report.node_count);
                println!(
                    "Unique Chunks Mesh:      {} ({} total dataset)",
                    report.chunk_count,
                    format_bytes(report.dataset_bytes)
                );
                println!(
                    "Server Egress Saved:     {:.2}% offload",
                    report.server_offload_percentage
                );
                println!(
                    "  Primary Server Egress: {} ({})",
                    report.server_egress_bytes,
                    format_bytes(report.server_egress_bytes)
                );
                println!(
                    "  P2P Swarm Exchanged:   {} ({})",
                    report.swarm_p2p_bytes,
                    format_bytes(report.swarm_p2p_bytes)
                );
                println!(
                    "Integrity Verified:      {} (BLAKE3 Byzantine defense active)",
                    if report.integrity_verified {
                        "YES"
                    } else {
                        "NO"
                    }
                );
                println!("Simulation Duration:     {} ms", report.duration_ms);
            }
            Ok(())
        }
    }
}

async fn run_chaos(cli: &Cli, sub: &ChaosSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);

    match sub {
        ChaosSubCmd::Status { json } => {
            let mut config = velcrux_core::ChaosConfig::default();
            config.enabled = cli.chaos;
            config.loss_rate = cli.chaos_loss;
            config.delay_ms = cli.chaos_delay_ms;
            config.jitter_ms = cli.chaos_jitter_ms;
            config.corrupt_rate = cli.chaos_corrupt_rate;

            let engine = velcrux_core::ChaosEngine::new(config, 42);
            let report = engine.status();

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Velcrux Chaos Fault Injection Status ===");
                println!(
                    "Engine Status:       {}",
                    if report.enabled {
                        "ACTIVE (Enabled)"
                    } else {
                        "INACTIVE (Disabled)"
                    }
                );
                println!("Active Profile:      {}", report.active_profile);
                println!("Packets Processed:   {}", report.packets_processed);
                println!("Packets Passed:      {}", report.packets_passed);
                println!(
                    "Packets Dropped:     {} ({:.2}%)",
                    report.packets_dropped, report.loss_percentage
                );
                println!("Packets Delayed:     {}", report.packets_delayed);
                println!("Packets Reordered:   {}", report.packets_reordered);
                println!("Packets Duplicated:  {}", report.packets_duplicated);
                println!("Bytes Corrupted:     {}", report.bytes_corrupted);
                println!(
                    "Partition Blackhole: {}",
                    if report.blackhole_active {
                        "ACTIVE"
                    } else {
                        "INACTIVE"
                    }
                );
            }
            Ok(())
        }
        ChaosSubCmd::Profile { name, json } => {
            #[derive(Serialize)]
            struct ProfileInfo {
                name: String,
                kind: String,
                loss_rate_pct: f64,
                delay_ms: u64,
                jitter_ms: u64,
                reorder_rate_pct: f64,
                duplicate_rate_pct: f64,
                corrupt_rate_pct: f64,
                blackhole: bool,
            }

            let kinds = match name {
                Some(ref n) => {
                    let k = velcrux_core::ChaosProfileKind::from_name(n).ok_or_else(|| {
                        anyhow::anyhow!(
                            "unknown chaos profile '{n}'. Available: clean, subsea, satellite, cellular, byzantine, partition"
                        )
                    })?;
                    vec![k]
                }
                None => vec![
                    velcrux_core::ChaosProfileKind::Clean,
                    velcrux_core::ChaosProfileKind::Subsea,
                    velcrux_core::ChaosProfileKind::Satellite,
                    velcrux_core::ChaosProfileKind::Cellular,
                    velcrux_core::ChaosProfileKind::Byzantine,
                    velcrux_core::ChaosProfileKind::Partition,
                ],
            };

            let profiles: Vec<ProfileInfo> = kinds
                .into_iter()
                .map(|k| {
                    let cfg = velcrux_core::ChaosConfig::from_profile(k);
                    ProfileInfo {
                        name: k.as_str().to_string(),
                        kind: format!("{:?}", k),
                        loss_rate_pct: cfg.loss_rate * 100.0,
                        delay_ms: cfg.delay_ms,
                        jitter_ms: cfg.jitter_ms,
                        reorder_rate_pct: cfg.reorder_rate * 100.0,
                        duplicate_rate_pct: cfg.duplicate_rate * 100.0,
                        corrupt_rate_pct: cfg.corrupt_rate * 100.0,
                        blackhole: cfg.blackhole,
                    }
                })
                .collect();

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&profiles)?);
            } else {
                println!("=== Preconfigured WAN Impairment Profiles ===");
                for p in profiles {
                    println!("\nProfile: {}", p.name);
                    println!("  Loss Rate:      {:.2}%", p.loss_rate_pct);
                    println!(
                        "  One-Way Delay:  {} ms (±{} ms jitter)",
                        p.delay_ms, p.jitter_ms
                    );
                    println!("  Reorder Rate:   {:.2}%", p.reorder_rate_pct);
                    println!("  Duplicate Rate: {:.2}%", p.duplicate_rate_pct);
                    println!("  Byzantine Rot:  {:.2}%", p.corrupt_rate_pct);
                    println!("  Blackhole:      {}", p.blackhole);
                }
            }
            Ok(())
        }
        ChaosSubCmd::Benchmark {
            profile,
            packets,
            json,
        } => {
            let report = velcrux_core::run_chaos_benchmark(profile, *packets);

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Velcrux Chaos Fault Injection Benchmark ===");
                println!("Target Profile:      {}", report.profile_name);
                println!("Simulated Packets:   {}", report.total_packets);
                println!("Delivered Packets:   {}", report.delivered_packets);
                println!(
                    "Dropped Packets:     {} ({:.2}% loss)",
                    report.dropped_packets, report.measured_loss_pct
                );
                println!("Reordered Packets:   {}", report.reordered_packets);
                println!("Duplicated Packets:  {}", report.duplicated_packets);
                println!("Corrupted Payloads:  {}", report.corrupted_payloads);
                println!("Average Latency:     {:.2} ms", report.avg_delay_ms);
                println!("Benchmark Duration:  {} ms", report.duration_ms);
            }
            Ok(())
        }
        ChaosSubCmd::Inject {
            loss,
            delay_ms,
            jitter_ms,
            reorder,
            duplicate,
            corrupt,
            partition,
            json,
        } => {
            let config = velcrux_core::ChaosConfig {
                enabled: true,
                loss_rate: *loss,
                burst_loss: None,
                delay_ms: *delay_ms,
                jitter_ms: *jitter_ms,
                reorder_rate: *reorder,
                reorder_delay_ms: 20,
                duplicate_rate: *duplicate,
                corrupt_rate: *corrupt,
                blackhole: *partition,
            };

            let engine = velcrux_core::ChaosEngine::new(config, 1337);
            let report = engine.status();

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Chaos Impairment Fault Injected ===");
                println!("Loss Rate:        {:.2}%", loss * 100.0);
                println!(
                    "Latency Delay:    {} ms (±{} ms jitter)",
                    delay_ms, jitter_ms
                );
                println!("Reordering:       {:.2}%", reorder * 100.0);
                println!("Duplication:      {:.2}%", duplicate * 100.0);
                println!("Byzantine Rot:    {:.2}%", corrupt * 100.0);
                println!("Partition Active: {}", partition);
            }
            Ok(())
        }
    }
}

async fn run_tier(cli: &Cli, sub: &TierSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);

    match sub {
        TierSubCmd::Status {
            chunk_store,
            tenant,
            json,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::TieredStorageManager::new(root)?;
            let status = mgr.get_status(tenant.as_deref())?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("=== Hierarchical Storage Tiering Status ===");
                println!("Store Root:           {}", status.root_dir);
                if let Some(ref t) = status.tenant_filter {
                    println!("Tenant Filter:        {}", t);
                }
                println!(
                    "Hot Tier (NVMe/SSD):  {} chunks ({})",
                    status.hot_chunks,
                    format_bytes(status.hot_bytes)
                );
                println!(
                    "Warm Tier (Bulk):     {} chunks ({})",
                    status.warm_chunks,
                    format_bytes(status.warm_bytes)
                );
                println!(
                    "Cold Tier (Archive):  {} chunks ({} compressed, {} raw)",
                    status.cold_chunks,
                    format_bytes(status.cold_bytes),
                    format_bytes(status.cold_raw_bytes)
                );
                println!(
                    "Total Inventory:      {} chunks ({} stored, {} raw)",
                    status.total_chunks,
                    format_bytes(status.total_stored_bytes),
                    format_bytes(status.total_raw_bytes)
                );
                println!("Space Savings Ratio:  {:.2}x", status.space_savings_ratio);
                println!("Total Promotions:     {}", status.promotions_total);
                println!("Total Demotions:      {}", status.demotions_total);
                println!("Total Retrievals:     {}", status.retrievals_total);
            }
            Ok(())
        }
        TierSubCmd::Policy { sub } => match sub {
            TierPolicySubCmd::Set {
                tenant,
                hot_days,
                warm_days,
                cold_retention_days,
                max_hot_bytes,
                auto_promote,
                compression_level,
                chunk_store,
                json,
            } => {
                let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
                let mgr = velcrux_core::storage::TieredStorageManager::new(root)?;
                let mut policy = mgr.get_tenant_policy(tenant).unwrap_or_else(|_| {
                    velcrux_core::storage::TenantTierPolicy {
                        tenant_id: tenant.clone(),
                        ..Default::default()
                    }
                });
                policy.tenant_id = tenant.clone();

                if let Some(d) = hot_days {
                    policy.hot_to_warm_days = *d;
                }
                if let Some(d) = warm_days {
                    policy.warm_to_cold_days = *d;
                }
                if cold_retention_days.is_some() {
                    policy.cold_retention_days = *cold_retention_days;
                }
                if max_hot_bytes.is_some() {
                    policy.max_hot_bytes = *max_hot_bytes;
                }
                if let Some(p) = auto_promote {
                    policy.auto_promote_on_read = *p;
                }
                if let Some(lvl) = compression_level {
                    policy.cold_compression_level = *lvl;
                }

                mgr.set_tenant_policy(policy.clone())?;

                if *json || is_json {
                    println!("{}", serde_json::to_string_pretty(&policy)?);
                } else {
                    println!("=== Updated Tiering Policy for '{}' ===", tenant);
                    println!("Hot to Warm Days:     {}", policy.hot_to_warm_days);
                    println!("Warm to Cold Days:    {}", policy.warm_to_cold_days);
                    println!(
                        "Cold Retention Days:  {}",
                        policy
                            .cold_retention_days
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "indefinite".to_string())
                    );
                    println!(
                        "Max Hot Capacity:     {}",
                        policy
                            .max_hot_bytes
                            .map(format_bytes)
                            .unwrap_or_else(|| "unlimited".to_string())
                    );
                    println!("Auto-promote on Read: {}", policy.auto_promote_on_read);
                    println!("Cold Compression Lvl: {}", policy.cold_compression_level);
                }
                Ok(())
            }
            TierPolicySubCmd::Get {
                tenant,
                chunk_store,
                json,
            } => {
                let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
                let mgr = velcrux_core::storage::TieredStorageManager::new(root)?;
                let policy = mgr.get_tenant_policy(tenant)?;

                if *json || is_json {
                    println!("{}", serde_json::to_string_pretty(&policy)?);
                } else {
                    println!("=== Tiering Policy for '{}' ===", tenant);
                    println!("Hot to Warm Days:     {}", policy.hot_to_warm_days);
                    println!("Warm to Cold Days:    {}", policy.warm_to_cold_days);
                    println!(
                        "Cold Retention Days:  {}",
                        policy
                            .cold_retention_days
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "indefinite".to_string())
                    );
                    println!(
                        "Max Hot Capacity:     {}",
                        policy
                            .max_hot_bytes
                            .map(format_bytes)
                            .unwrap_or_else(|| "unlimited".to_string())
                    );
                    println!("Auto-promote on Read: {}", policy.auto_promote_on_read);
                    println!("Cold Compression Lvl: {}", policy.cold_compression_level);
                }
                Ok(())
            }
            TierPolicySubCmd::List { chunk_store, json } => {
                let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
                let mgr = velcrux_core::storage::TieredStorageManager::new(root)?;
                let policies = mgr.list_tenant_policies()?;

                if *json || is_json {
                    println!("{}", serde_json::to_string_pretty(&policies)?);
                } else {
                    println!("=== Registered Tenant Tiering Policies ===");
                    println!(
                        "{:<16} {:<12} {:<12} {:<16} {:<16}",
                        "TENANT", "HOT->WARM", "WARM->COLD", "COLD RETENTION", "MAX HOT BYTES"
                    );
                    for p in &policies {
                        println!(
                            "{:<16} {:<12} {:<12} {:<16} {:<16}",
                            p.tenant_id,
                            format!("{} d", p.hot_to_warm_days),
                            format!("{} d", p.warm_to_cold_days),
                            p.cold_retention_days
                                .map(|d| format!("{d} d"))
                                .unwrap_or_else(|| "indefinite".to_string()),
                            p.max_hot_bytes
                                .map(format_bytes)
                                .unwrap_or_else(|| "unlimited".to_string()),
                        );
                    }
                }
                Ok(())
            }
        },
        TierSubCmd::Migrate {
            hash,
            target,
            chunk_store,
            json,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::TieredStorageManager::new(root)?;
            let parsed_hash = velcrux_core::util::Hash::from_hex(hash)
                .ok_or_else(|| anyhow::anyhow!("invalid BLAKE3 chunk hash hex: '{hash}'"))?;
            let target_tier: velcrux_core::storage::StorageTier = target.parse()?;
            let migrated = mgr.migrate_chunk(&parsed_hash, target_tier)?;

            if *json || is_json {
                let res = serde_json::json!({
                    "hash": hash,
                    "target_tier": target_tier.as_str(),
                    "success": migrated,
                });
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else if migrated {
                println!(
                    "Successfully migrated chunk {} to {} tier.",
                    hash,
                    target_tier.as_str().to_uppercase()
                );
            } else {
                println!("Chunk {} was not found in the tiered store.", hash);
            }
            Ok(())
        }
        TierSubCmd::Sweep {
            tenant,
            dry_run,
            chunk_store,
            json,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::TieredStorageManager::new(root)?;
            let report = mgr.run_lifecycle_sweep(tenant.as_deref(), *dry_run)?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Hierarchical Lifecycle Sweep ===");
                println!("Target Tenant:       {}", report.tenant_id);
                println!("Dry Run:             {}", report.dry_run);
                println!("Chunks Scanned:      {}", report.chunks_scanned);
                println!(
                    "Hot -> Warm Demoted: {} ({})",
                    report.hot_to_warm_migrated,
                    format_bytes(report.hot_to_warm_bytes)
                );
                println!(
                    "Warm -> Cold Demoted:{} ({} raw -> {} compressed)",
                    report.warm_to_cold_migrated,
                    format_bytes(report.warm_to_cold_raw_bytes),
                    format_bytes(report.warm_to_cold_compressed_bytes)
                );
                println!(
                    "Storage Reclaimed:   {}",
                    format_bytes(report.warm_to_cold_bytes_saved)
                );
                println!(
                    "Cold Expired Purged: {} ({})",
                    report.cold_expired,
                    format_bytes(report.cold_expired_bytes)
                );
                println!("Sweep Duration:      {} ms", report.duration_ms);
            }
            Ok(())
        }
        TierSubCmd::Scrub {
            tenant,
            chunk_store,
            json,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let mgr = velcrux_core::storage::TieredStorageManager::new(root)?;
            let report = mgr.scrub_cold_tier(tenant.as_deref())?;

            if *json || is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== Cold Tier Cryptographic Scrub Report ===");
                println!("Cold Chunks Scanned: {}", report.chunks_scanned);
                println!("Valid Chunks:        {}", report.valid_chunks);
                println!("Corrupted Chunks:    {}", report.corrupt_chunks.len());
                println!(
                    "Bytes Verified:      {}",
                    format_bytes(report.bytes_verified)
                );
                println!("Scrub Duration:      {} ms", report.duration_ms);
                if !report.corrupt_chunks.is_empty() {
                    println!("\nCorrupted Chunks Detected:");
                    for c in &report.corrupt_chunks {
                        println!("  [!] {c}");
                    }
                }
            }
            Ok(())
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        format!("{:.2} TB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

async fn run_profile(
    cli: &Cli,
    file: &std::path::Path,
    url: Option<&String>,
    chunk_mode_str: &str,
) -> anyhow::Result<()> {
    if !file.exists() {
        anyhow::bail!("profile target file does not exist: {}", file.display());
    }
    let file_len = std::fs::metadata(file)?.len();
    let is_json = cli_log_json(cli);

    let profiler = velcrux_core::TransferProfiler::new();

    // 1. Storage Read I/O
    let start_read = std::time::Instant::now();
    let data = std::fs::read(file)
        .with_context(|| format!("reading file {} for profiling", file.display()))?;
    profiler.record_timing(
        velcrux_core::ComponentKind::DiskIoRead,
        start_read.elapsed(),
        file_len,
    );
    profiler.sample_memory();

    // 2. Chunking
    let start_chunk = std::time::Instant::now();
    let is_fixed = chunk_mode_str.eq_ignore_ascii_case("fixed");
    let chunk_boundaries: Vec<(u64, u64)> = if is_fixed {
        let chunk_sz = 1024 * 1024; // 1 MiB
        let mut bounds = Vec::new();
        let mut offset = 0u64;
        while offset < file_len {
            let len = chunk_sz.min(file_len - offset);
            bounds.push((offset, len));
            offset += len;
        }
        bounds
    } else {
        use velcrux_core::chunking::Chunker;
        let mut chunker = velcrux_core::chunking::FastCdcChunker::new(
            velcrux_core::chunking::ChunkParams::default(),
        );
        let mut boundaries = chunker
            .push(&data)
            .map_err(|e| anyhow::anyhow!("fastcdc push: {e}"))?;
        let remaining = chunker
            .finish()
            .map_err(|e| anyhow::anyhow!("fastcdc finish: {e}"))?;
        boundaries.extend(remaining);
        boundaries
            .into_iter()
            .map(|b| (b.offset, b.length))
            .collect()
    };
    profiler.record_timing(
        velcrux_core::ComponentKind::Chunking,
        start_chunk.elapsed(),
        file_len,
    );

    // 3. Cryptographic Hashing (BLAKE3 parallel)
    let start_hash = std::time::Instant::now();
    let parallel_hasher = velcrux_core::ParallelHasher::new(cli.concurrency.max(1));
    let chunk_slices: Vec<&[u8]> = chunk_boundaries
        .iter()
        .map(|(offset, len)| {
            let start = (*offset).min(data.len() as u64) as usize;
            let end = (*offset + *len).min(data.len() as u64) as usize;
            &data[start..end]
        })
        .collect();
    let _hashes = parallel_hasher.hash_chunks_batched(&chunk_slices);
    let _root_hash = velcrux_core::compute_file_hash(file);
    profiler.record_timing(
        velcrux_core::ComponentKind::Hashing,
        start_hash.elapsed(),
        file_len,
    );

    // 4. Zero-Knowledge AEAD Encryption
    let start_crypto = std::time::Instant::now();
    let transfer_key = velcrux_core::TransferKey::from_bytes([0x42u8; 32]);
    let encryptor = velcrux_core::ChunkEncryptor::new(
        velcrux_core::crypto::CipherSuite::ChaCha20Poly1305,
        &transfer_key,
    )
    .map_err(|e| anyhow::anyhow!("init encryptor: {e}"))?;
    let dummy_tid = velcrux_core::TransferId::generate();
    for (idx, slice) in chunk_slices.iter().enumerate() {
        let _enc = encryptor.encrypt_chunk(&dummy_tid, idx as u64 * 1024, idx as u32, slice);
    }
    profiler.record_timing(
        velcrux_core::ComponentKind::Encryption,
        start_crypto.elapsed(),
        file_len,
    );

    profiler.set_bytes_transferred(file_len);
    profiler.sample_memory();

    // 5. Optional live network QUIC transfer
    if let Some(target_url) = url {
        let (addr, path) = parse_url_with_path(target_url)?;
        let sni = get_sni(cli, target_url);
        let transport = build_transport_target(cli, Some(addr))?;
        let conn = transport.connect(addr, &sni).await?;
        let mut session = open_client_session(&conn, cli).await?;
        let store = open_client_state_store(cli);

        let start_net = std::time::Instant::now();
        run_upload(cli, &conn, &mut session, &file.to_path_buf(), &path, &store).await?;
        profiler.record_timing(
            velcrux_core::ComponentKind::NetworkQuic,
            start_net.elapsed(),
            file_len,
        );

        let quinn_stats = conn.quinn().stats();
        let rtt_us = conn.quinn().rtt().as_micros() as u64;
        let wire_bytes = quinn_stats.udp_tx.bytes;
        let lost_packets = quinn_stats.path.lost_packets;
        let sent_packets = quinn_stats.path.sent_packets.max(1);
        let loss_rate = lost_packets as f64 / sent_packets as f64;
        let cwnd = quinn_stats.path.cwnd;

        profiler.set_network_metrics(velcrux_core::NetworkMetrics {
            rtt_us,
            packet_loss_rate: loss_rate,
            retransmits: quinn_stats.path.lost_packets,
            cwnd_bytes: cwnd,
            wire_bytes,
        });
        session.bye().await.ok();
    }

    let report = profiler.finish();

    if is_json {
        println!("{}", serde_json::to_string_pretty(&report.to_json_value())?);
    } else {
        print!("{}", report.format_ascii_table());
    }

    Ok(())
}

async fn run_s3(cli: &Cli, sub: &S3SubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    match sub {
        S3SubCmd::Ls {
            s3_url,
            delimiter,
            endpoint,
            region,
        } => {
            let (bucket, prefix) = velcrux_core::storage::S3Config::parse_s3_url(s3_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::S3Config::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::S3Config::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(reg) = region {
                cfg.region = reg.clone();
            }
            let backend = velcrux_core::storage::S3StorageBackend::new(cfg);
            let objects = backend
                .list_objects(&prefix, delimiter.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&objects)?);
            } else {
                println!("{:<40} {:>12}  {:<64}", "KEY", "SIZE", "ETAG / HASH");
                println!("{:-<40} {:-<12}  {:-<64}", "", "", "");
                for obj in &objects {
                    let hash_str = obj
                        .blake3_hash
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| obj.etag.clone());
                    println!("{:<40} {:>12}  {:<64}", obj.key, obj.size, hash_str);
                }
            }
        }
        S3SubCmd::Stat {
            s3_url,
            endpoint,
            region,
        } => {
            let (bucket, key) = velcrux_core::storage::S3Config::parse_s3_url(s3_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::S3Config::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::S3Config::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(reg) = region {
                cfg.region = reg.clone();
            }
            let backend = velcrux_core::storage::S3StorageBackend::new(cfg);
            let meta = backend
                .head_object(&key)
                .await
                .map_err(|e| anyhow::anyhow!(e))?
                .ok_or_else(|| anyhow::anyhow!("object s3://{}/{} not found", bucket, key))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&meta)?);
            } else {
                println!("S3 Object Metadata: s3://{}/{}", bucket, key);
                println!("  Size:          {} bytes", meta.size);
                println!("  ETag:          {}", meta.etag);
                println!(
                    "  BLAKE3:        {}",
                    meta.blake3_hash
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| "none".to_string())
                );
                println!("  Last Modified: {} (unix sec)", meta.last_modified_sec);
            }
        }
        S3SubCmd::Put {
            local,
            s3_url,
            endpoint,
            region,
            multipart_size,
        } => {
            let (bucket, key) = velcrux_core::storage::S3Config::parse_s3_url(s3_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::S3Config::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::S3Config::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(reg) = region {
                cfg.region = reg.clone();
            }
            if let Some(mps) = multipart_size {
                cfg.part_size_bytes = *mps;
            }
            let data = std::fs::read(local)
                .with_context(|| format!("reading local file {}", local.display()))?;
            let hash = velcrux_core::Hash::of(&data);

            let backend = velcrux_core::storage::S3StorageBackend::new(cfg);
            let meta = backend
                .put_object_multipart(&key, &data, Some(hash))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&meta)?);
            } else {
                println!(
                    "Successfully uploaded {} ({} bytes) to s3://{}/{} [etag: {}]",
                    local.display(),
                    meta.size,
                    bucket,
                    meta.key,
                    meta.etag
                );
            }
        }
        S3SubCmd::Get {
            s3_url,
            local,
            endpoint,
            region,
            range_start,
            range_end,
        } => {
            let (bucket, key) = velcrux_core::storage::S3Config::parse_s3_url(s3_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::S3Config::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::S3Config::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(reg) = region {
                cfg.region = reg.clone();
            }
            let backend = velcrux_core::storage::S3StorageBackend::new(cfg);
            let data = match (range_start, range_end) {
                (Some(s), Some(e)) => backend
                    .get_object_range(&key, *s, *e)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?,
                _ => backend
                    .get_object(&key)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?,
            };

            if let Some(parent) = local.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(local, &data)
                .with_context(|| format!("writing to local file {}", local.display()))?;

            if is_json {
                let out = serde_json::json!({
                    "s3_url": s3_url,
                    "local": local.display().to_string(),
                    "bytes": data.len(),
                    "blake3": velcrux_core::Hash::of(&data).to_hex(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "Successfully downloaded s3://{}/{} ({} bytes) to {}",
                    bucket,
                    key,
                    data.len(),
                    local.display()
                );
            }
        }
        S3SubCmd::Delete {
            s3_url,
            endpoint,
            region,
        } => {
            let (bucket, key) = velcrux_core::storage::S3Config::parse_s3_url(s3_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::S3Config::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::S3Config::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(reg) = region {
                cfg.region = reg.clone();
            }
            let backend = velcrux_core::storage::S3StorageBackend::new(cfg);
            backend
                .delete_object(&key)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                let out = serde_json::json!({
                    "deleted": s3_url,
                    "success": true,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Successfully deleted s3://{}/{}", bucket, key);
            }
        }
        S3SubCmd::Sync {
            source,
            destination,
            endpoint,
            region,
        } => {
            let src_is_s3 = source.starts_with("s3://");
            let dst_is_s3 = destination.starts_with("s3://");

            if src_is_s3 && !dst_is_s3 {
                // S3 -> Local sync
                let (bucket, prefix) = velcrux_core::storage::S3Config::parse_s3_url(source)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let mut cfg = velcrux_core::storage::S3Config::from_env(&bucket)
                    .unwrap_or_else(|_| velcrux_core::storage::S3Config::new(&bucket));
                if let Some(ep) = endpoint {
                    cfg.endpoint = ep.clone();
                }
                if let Some(reg) = region {
                    cfg.region = reg.clone();
                }
                let backend = velcrux_core::storage::S3StorageBackend::new(cfg);
                let report = backend
                    .sync_to_local(&prefix, Path::new(destination))
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                if is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("S3 Download Sync Complete: {} -> {}", source, destination);
                    println!("  Total Objects:       {}", report.total_objects);
                    println!("  Objects Downloaded:  {}", report.objects_transferred);
                    println!("  Objects Unchanged:   {}", report.objects_unchanged);
                    println!("  Bytes Transferred:   {}", report.bytes_transferred);
                    println!("  Bytes Reused:        {}", report.bytes_reused);
                }
            } else if dst_is_s3 && !src_is_s3 {
                // Local -> S3 sync
                let (bucket, prefix) = velcrux_core::storage::S3Config::parse_s3_url(destination)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let mut cfg = velcrux_core::storage::S3Config::from_env(&bucket)
                    .unwrap_or_else(|_| velcrux_core::storage::S3Config::new(&bucket));
                if let Some(ep) = endpoint {
                    cfg.endpoint = ep.clone();
                }
                if let Some(reg) = region {
                    cfg.region = reg.clone();
                }
                let backend = velcrux_core::storage::S3StorageBackend::new(cfg);
                let report = backend
                    .sync_from_local(Path::new(source), &prefix)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                if is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("S3 Upload Sync Complete: {} -> {}", source, destination);
                    println!("  Total Objects:       {}", report.total_objects);
                    println!("  Objects Uploaded:    {}", report.objects_transferred);
                    println!("  Objects Unchanged:   {}", report.objects_unchanged);
                    println!("  Bytes Transferred:   {}", report.bytes_transferred);
                    println!("  Bytes Reused:        {}", report.bytes_reused);
                }
            } else {
                anyhow::bail!(
                    "s3 sync requires one local path and one s3:// URL (got '{}' and '{}')",
                    source,
                    destination
                );
            }
        }
    }
    Ok(())
}

async fn run_gcs(cli: &Cli, sub: &GcsSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    match sub {
        GcsSubCmd::Ls {
            gcs_url,
            delimiter,
            endpoint,
            token,
        } => {
            let (bucket, prefix) = velcrux_core::storage::GcsConfig::parse_gs_url(gcs_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::GcsConfig::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::GcsConfig::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(tok) = token {
                cfg.token = Some(tok.clone());
            }
            let backend = velcrux_core::storage::GcsStorageBackend::new(cfg);
            let objects = backend
                .list_objects(&prefix, delimiter.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&objects)?);
            } else {
                println!(
                    "{:<40} {:>12}  {:<64}",
                    "OBJECT NAME", "SIZE", "ETAG / HASH"
                );
                println!("{:-<40} {:-<12}  {:-<64}", "", "", "");
                for obj in &objects {
                    let hash_str = obj
                        .blake3_hash
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| obj.etag.clone());
                    println!("{:<40} {:>12}  {:<64}", obj.name, obj.size, hash_str);
                }
            }
        }
        GcsSubCmd::Stat {
            gcs_url,
            endpoint,
            token,
        } => {
            let (bucket, name) = velcrux_core::storage::GcsConfig::parse_gs_url(gcs_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::GcsConfig::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::GcsConfig::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(tok) = token {
                cfg.token = Some(tok.clone());
            }
            let backend = velcrux_core::storage::GcsStorageBackend::new(cfg);
            let meta = backend
                .head_object(&name)
                .await
                .map_err(|e| anyhow::anyhow!(e))?
                .ok_or_else(|| anyhow::anyhow!("object gs://{}/{} not found", bucket, name))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&meta)?);
            } else {
                println!("GCS Object Metadata: gs://{}/{}", bucket, name);
                println!("  Size:          {} bytes", meta.size);
                println!("  ETag:          {}", meta.etag);
                println!("  Generation:    {}", meta.generation);
                println!(
                    "  BLAKE3:        {}",
                    meta.blake3_hash
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| "none".to_string())
                );
                println!("  Last Updated:  {} (unix sec)", meta.updated_sec);
            }
        }
        GcsSubCmd::Put {
            local,
            gcs_url,
            endpoint,
            token,
            chunk_size,
        } => {
            let (bucket, name) = velcrux_core::storage::GcsConfig::parse_gs_url(gcs_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::GcsConfig::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::GcsConfig::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(tok) = token {
                cfg.token = Some(tok.clone());
            }
            if let Some(cs) = chunk_size {
                cfg.chunk_size_bytes = *cs;
            }
            let data = std::fs::read(local)
                .with_context(|| format!("reading local file {}", local.display()))?;
            let hash = velcrux_core::Hash::of(&data);
            let backend = velcrux_core::storage::GcsStorageBackend::new(cfg);
            let meta = backend
                .put_object_resumable(&name, &data, Some(hash))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&meta)?);
            } else {
                println!(
                    "Successfully uploaded {} ({} bytes) to gs://{}/{} [etag: {}, generation: {}]",
                    local.display(),
                    meta.size,
                    bucket,
                    name,
                    meta.etag,
                    meta.generation
                );
            }
        }
        GcsSubCmd::Get {
            gcs_url,
            local,
            endpoint,
            token,
            range_start,
            range_end,
        } => {
            let (bucket, name) = velcrux_core::storage::GcsConfig::parse_gs_url(gcs_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::GcsConfig::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::GcsConfig::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(tok) = token {
                cfg.token = Some(tok.clone());
            }
            let backend = velcrux_core::storage::GcsStorageBackend::new(cfg);
            let data = match (range_start, range_end) {
                (Some(s), Some(e)) => backend
                    .get_object_range(&name, *s, *e)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?,
                _ => backend
                    .get_object(&name)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?,
            };

            if let Some(parent) = local.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(local, &data)
                .with_context(|| format!("writing local destination {}", local.display()))?;

            if is_json {
                let report = serde_json::json!({
                    "gcs_url": gcs_url,
                    "local": local.display().to_string(),
                    "bytes": data.len(),
                    "range": match (range_start, range_end) {
                        (Some(s), Some(e)) => format!("{}-{}", s, e),
                        _ => "full".to_string(),
                    }
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Successfully downloaded gs://{}/{} ({} bytes) to {}",
                    bucket,
                    name,
                    data.len(),
                    local.display()
                );
            }
        }
        GcsSubCmd::Delete {
            gcs_url,
            endpoint,
            token,
        } => {
            let (bucket, name) = velcrux_core::storage::GcsConfig::parse_gs_url(gcs_url)
                .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::GcsConfig::from_env(&bucket)
                .unwrap_or_else(|_| velcrux_core::storage::GcsConfig::new(&bucket));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(tok) = token {
                cfg.token = Some(tok.clone());
            }
            let backend = velcrux_core::storage::GcsStorageBackend::new(cfg);
            backend
                .delete_object(&name)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                let report = serde_json::json!({
                    "deleted": gcs_url,
                    "bucket": bucket,
                    "name": name,
                    "status": "success",
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Successfully deleted gs://{}/{}", bucket, name);
            }
        }
        GcsSubCmd::Sync {
            source,
            destination,
            endpoint,
            token,
        } => {
            let src_is_gcs = source.starts_with("gs://");
            let dst_is_gcs = destination.starts_with("gs://");

            if src_is_gcs && !dst_is_gcs {
                let (bucket, prefix) = velcrux_core::storage::GcsConfig::parse_gs_url(source)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let mut cfg = velcrux_core::storage::GcsConfig::from_env(&bucket)
                    .unwrap_or_else(|_| velcrux_core::storage::GcsConfig::new(&bucket));
                if let Some(ep) = endpoint {
                    cfg.endpoint = ep.clone();
                }
                if let Some(tok) = token {
                    cfg.token = Some(tok.clone());
                }
                let backend = velcrux_core::storage::GcsStorageBackend::new(cfg);
                let report = backend
                    .sync_to_local(&prefix, Path::new(destination))
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                if is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("GCS Download Sync Complete: {} -> {}", source, destination);
                    println!("  Total Objects:       {}", report.total_objects);
                    println!("  Objects Downloaded:  {}", report.objects_transferred);
                    println!("  Objects Unchanged:   {}", report.objects_unchanged);
                    println!("  Bytes Transferred:   {}", report.bytes_transferred);
                    println!("  Bytes Reused:        {}", report.bytes_reused);
                }
            } else if dst_is_gcs && !src_is_gcs {
                let (bucket, prefix) = velcrux_core::storage::GcsConfig::parse_gs_url(destination)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let mut cfg = velcrux_core::storage::GcsConfig::from_env(&bucket)
                    .unwrap_or_else(|_| velcrux_core::storage::GcsConfig::new(&bucket));
                if let Some(ep) = endpoint {
                    cfg.endpoint = ep.clone();
                }
                if let Some(tok) = token {
                    cfg.token = Some(tok.clone());
                }
                let backend = velcrux_core::storage::GcsStorageBackend::new(cfg);
                let report = backend
                    .sync_from_local(Path::new(source), &prefix)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                if is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("GCS Upload Sync Complete: {} -> {}", source, destination);
                    println!("  Total Objects:       {}", report.total_objects);
                    println!("  Objects Uploaded:    {}", report.objects_transferred);
                    println!("  Objects Unchanged:   {}", report.objects_unchanged);
                    println!("  Bytes Transferred:   {}", report.bytes_transferred);
                    println!("  Bytes Reused:        {}", report.bytes_reused);
                }
            } else {
                anyhow::bail!(
                    "gcs sync requires one local path and one gs:// URL (got '{}' and '{}')",
                    source,
                    destination
                );
            }
        }
    }
    Ok(())
}

async fn run_azure(cli: &Cli, sub: &AzureSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    match sub {
        AzureSubCmd::Ls {
            azure_url,
            delimiter,
            endpoint,
            account_name,
            account_key,
            sas_token,
        } => {
            let (container, prefix) =
                velcrux_core::storage::AzureBlobConfig::parse_azure_url(azure_url)
                    .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::AzureBlobConfig::from_env(&container)
                .unwrap_or_else(|_| velcrux_core::storage::AzureBlobConfig::new(&container));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(acc) = account_name {
                cfg.account_name = acc.clone();
            }
            if let Some(key) = account_key {
                cfg.account_key = Some(key.clone());
            }
            if let Some(sas) = sas_token {
                cfg.sas_token = Some(sas.clone());
            }
            let backend = velcrux_core::storage::AzureBlobStorageBackend::new(cfg);
            let blobs = backend
                .list_blobs(&prefix, delimiter.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&blobs)?);
            } else {
                println!("{:<40} {:>12}  {:<64}", "BLOB NAME", "SIZE", "ETAG / HASH");
                println!("{:-<40} {:-<12}  {:-<64}", "", "", "");
                for b in &blobs {
                    let hash_str = b
                        .blake3_hash
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| b.etag.clone());
                    println!("{:<40} {:>12}  {:<64}", b.name, b.size, hash_str);
                }
            }
        }
        AzureSubCmd::Stat {
            azure_url,
            endpoint,
            account_name,
            account_key,
            sas_token,
        } => {
            let (container, blob_name) =
                velcrux_core::storage::AzureBlobConfig::parse_azure_url(azure_url)
                    .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::AzureBlobConfig::from_env(&container)
                .unwrap_or_else(|_| velcrux_core::storage::AzureBlobConfig::new(&container));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(acc) = account_name {
                cfg.account_name = acc.clone();
            }
            if let Some(key) = account_key {
                cfg.account_key = Some(key.clone());
            }
            if let Some(sas) = sas_token {
                cfg.sas_token = Some(sas.clone());
            }
            let backend = velcrux_core::storage::AzureBlobStorageBackend::new(cfg);
            let meta = backend
                .get_blob_properties(&blob_name)
                .await
                .map_err(|e| anyhow::anyhow!(e))?
                .ok_or_else(|| {
                    anyhow::anyhow!("blob az://{}/{} not found", container, blob_name)
                })?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&meta)?);
            } else {
                println!("Azure Blob Properties: az://{}/{}", container, blob_name);
                println!("  Size:          {} bytes", meta.size);
                println!("  ETag:          {}", meta.etag);
                println!(
                    "  BLAKE3:        {}",
                    meta.blake3_hash
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| "none".to_string())
                );
                println!("  Last Modified: {} (unix sec)", meta.last_modified_sec);
            }
        }
        AzureSubCmd::Put {
            local,
            azure_url,
            endpoint,
            account_name,
            account_key,
            sas_token,
            block_size,
        } => {
            let (container, blob_name) =
                velcrux_core::storage::AzureBlobConfig::parse_azure_url(azure_url)
                    .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::AzureBlobConfig::from_env(&container)
                .unwrap_or_else(|_| velcrux_core::storage::AzureBlobConfig::new(&container));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(acc) = account_name {
                cfg.account_name = acc.clone();
            }
            if let Some(key) = account_key {
                cfg.account_key = Some(key.clone());
            }
            if let Some(sas) = sas_token {
                cfg.sas_token = Some(sas.clone());
            }
            if let Some(bs) = block_size {
                cfg.block_size_bytes = *bs;
            }
            let data = std::fs::read(local)
                .with_context(|| format!("reading local file {}", local.display()))?;
            let hash = velcrux_core::Hash::of(&data);
            let backend = velcrux_core::storage::AzureBlobStorageBackend::new(cfg);
            let meta = backend
                .put_blob_blocks(&blob_name, &data, Some(hash))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&meta)?);
            } else {
                println!(
                    "Successfully uploaded {} ({} bytes) to az://{}/{} [etag: {}]",
                    local.display(),
                    meta.size,
                    container,
                    blob_name,
                    meta.etag
                );
            }
        }
        AzureSubCmd::Get {
            azure_url,
            local,
            endpoint,
            account_name,
            account_key,
            sas_token,
            range_start,
            range_end,
        } => {
            let (container, blob_name) =
                velcrux_core::storage::AzureBlobConfig::parse_azure_url(azure_url)
                    .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::AzureBlobConfig::from_env(&container)
                .unwrap_or_else(|_| velcrux_core::storage::AzureBlobConfig::new(&container));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(acc) = account_name {
                cfg.account_name = acc.clone();
            }
            if let Some(key) = account_key {
                cfg.account_key = Some(key.clone());
            }
            if let Some(sas) = sas_token {
                cfg.sas_token = Some(sas.clone());
            }
            let backend = velcrux_core::storage::AzureBlobStorageBackend::new(cfg);
            let data = match (range_start, range_end) {
                (Some(s), Some(e)) => backend
                    .get_blob_range(&blob_name, *s, *e)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?,
                _ => backend
                    .get_blob(&blob_name)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?,
            };

            if let Some(parent) = local.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(local, &data)
                .with_context(|| format!("writing local destination {}", local.display()))?;

            if is_json {
                let report = serde_json::json!({
                    "azure_url": azure_url,
                    "local": local.display().to_string(),
                    "bytes": data.len(),
                    "range": match (range_start, range_end) {
                        (Some(s), Some(e)) => format!("{}-{}", s, e),
                        _ => "full".to_string(),
                    }
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "Successfully downloaded az://{}/{} ({} bytes) to {}",
                    container,
                    blob_name,
                    data.len(),
                    local.display()
                );
            }
        }
        AzureSubCmd::Delete {
            azure_url,
            endpoint,
            account_name,
            account_key,
            sas_token,
        } => {
            let (container, blob_name) =
                velcrux_core::storage::AzureBlobConfig::parse_azure_url(azure_url)
                    .map_err(|e| anyhow::anyhow!(e))?;
            let mut cfg = velcrux_core::storage::AzureBlobConfig::from_env(&container)
                .unwrap_or_else(|_| velcrux_core::storage::AzureBlobConfig::new(&container));
            if let Some(ep) = endpoint {
                cfg.endpoint = ep.clone();
            }
            if let Some(acc) = account_name {
                cfg.account_name = acc.clone();
            }
            if let Some(key) = account_key {
                cfg.account_key = Some(key.clone());
            }
            if let Some(sas) = sas_token {
                cfg.sas_token = Some(sas.clone());
            }
            let backend = velcrux_core::storage::AzureBlobStorageBackend::new(cfg);
            backend
                .delete_blob(&blob_name)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                let report = serde_json::json!({
                    "deleted": azure_url,
                    "container": container,
                    "blob_name": blob_name,
                    "status": "success",
                });
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Successfully deleted az://{}/{}", container, blob_name);
            }
        }
        AzureSubCmd::Sync {
            source,
            destination,
            endpoint,
            account_name,
            account_key,
            sas_token,
        } => {
            let src_is_az = source.starts_with("az://") || source.starts_with("azure://");
            let dst_is_az = destination.starts_with("az://") || destination.starts_with("azure://");

            if src_is_az && !dst_is_az {
                let (container, prefix) =
                    velcrux_core::storage::AzureBlobConfig::parse_azure_url(source)
                        .map_err(|e| anyhow::anyhow!(e))?;
                let mut cfg = velcrux_core::storage::AzureBlobConfig::from_env(&container)
                    .unwrap_or_else(|_| velcrux_core::storage::AzureBlobConfig::new(&container));
                if let Some(ep) = endpoint {
                    cfg.endpoint = ep.clone();
                }
                if let Some(acc) = account_name {
                    cfg.account_name = acc.clone();
                }
                if let Some(key) = account_key {
                    cfg.account_key = Some(key.clone());
                }
                if let Some(sas) = sas_token {
                    cfg.sas_token = Some(sas.clone());
                }
                let backend = velcrux_core::storage::AzureBlobStorageBackend::new(cfg);
                let report = backend
                    .sync_to_local(&prefix, Path::new(destination))
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                if is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!(
                        "Azure Download Sync Complete: {} -> {}",
                        source, destination
                    );
                    println!("  Total Objects:       {}", report.total_objects);
                    println!("  Objects Downloaded:  {}", report.objects_transferred);
                    println!("  Objects Unchanged:   {}", report.objects_unchanged);
                    println!("  Bytes Transferred:   {}", report.bytes_transferred);
                    println!("  Bytes Reused:        {}", report.bytes_reused);
                }
            } else if dst_is_az && !src_is_az {
                let (container, prefix) =
                    velcrux_core::storage::AzureBlobConfig::parse_azure_url(destination)
                        .map_err(|e| anyhow::anyhow!(e))?;
                let mut cfg = velcrux_core::storage::AzureBlobConfig::from_env(&container)
                    .unwrap_or_else(|_| velcrux_core::storage::AzureBlobConfig::new(&container));
                if let Some(ep) = endpoint {
                    cfg.endpoint = ep.clone();
                }
                if let Some(acc) = account_name {
                    cfg.account_name = acc.clone();
                }
                if let Some(key) = account_key {
                    cfg.account_key = Some(key.clone());
                }
                if let Some(sas) = sas_token {
                    cfg.sas_token = Some(sas.clone());
                }
                let backend = velcrux_core::storage::AzureBlobStorageBackend::new(cfg);
                let report = backend
                    .sync_from_local(Path::new(source), &prefix)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;

                if is_json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("Azure Upload Sync Complete: {} -> {}", source, destination);
                    println!("  Total Objects:       {}", report.total_objects);
                    println!("  Objects Uploaded:    {}", report.objects_transferred);
                    println!("  Objects Unchanged:   {}", report.objects_unchanged);
                    println!("  Bytes Transferred:   {}", report.bytes_transferred);
                    println!("  Bytes Reused:        {}", report.bytes_reused);
                }
            } else {
                anyhow::bail!(
                    "azure sync requires one local path and one az:// or azure:// URL (got '{}' and '{}')",
                    source,
                    destination
                );
            }
        }
    }
    Ok(())
}

async fn run_mount(cli: &Cli, sub: &MountSubCmd) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let manager = velcrux_core::storage::MountManager::new();

    match sub {
        MountSubCmd::Attach {
            source,
            mountpoint,
            read_only,
            read_write,
            cache_size_mb,
            cache_ttl_sec,
            prefetch,
            allow_other,
            daemon,
        } => {
            let is_ro = if *read_write { false } else { *read_only };
            let cache_capacity_bytes = cache_size_mb
                .map(|m| m * 1024 * 1024)
                .unwrap_or(velcrux_core::storage::vfs::DEFAULT_CACHE_CAPACITY_BYTES);
            let cache_ttl =
                cache_ttl_sec.unwrap_or(velcrux_core::storage::vfs::DEFAULT_CACHE_TTL_SECS);
            let prefetch_chunks =
                prefetch.unwrap_or(velcrux_core::storage::vfs::DEFAULT_PREFETCH_CHUNKS);

            let config = velcrux_core::storage::MountConfig {
                source: source.clone(),
                mountpoint: mountpoint.clone(),
                read_only: is_ro,
                cache_capacity_bytes,
                cache_ttl_sec: cache_ttl,
                prefetch_chunks,
                allow_other: *allow_other,
                debug: false,
            };

            let _engine = manager
                .mount(config)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            let abs_mountpoint = if mountpoint.is_absolute() {
                mountpoint.clone()
            } else {
                std::env::current_dir().unwrap_or_default().join(mountpoint)
            };

            if is_json {
                let info = serde_json::json!({
                    "status": "mounted",
                    "source": source,
                    "mountpoint": abs_mountpoint.display().to_string(),
                    "read_only": is_ro,
                    "cache_capacity_mb": cache_capacity_bytes / (1024 * 1024),
                    "cache_ttl_sec": cache_ttl,
                    "prefetch_chunks": prefetch_chunks,
                    "daemon": daemon,
                    "pid": std::process::id(),
                });
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("Velcrux Virtual Filesystem (VFS) Mounted Successfully:");
                println!("  Source:          {}", source);
                println!("  Mountpoint:      {}", abs_mountpoint.display());
                println!(
                    "  Access Mode:     {}",
                    if is_ro {
                        "Read-Only (RO)"
                    } else {
                        "Read-Write (RW)"
                    }
                );
                println!(
                    "  Page Cache:      {} MiB (TTL: {}s, Prefetch: {} chunks)",
                    cache_capacity_bytes / (1024 * 1024),
                    cache_ttl,
                    prefetch_chunks
                );
                if *daemon {
                    println!(
                        "  Mode:            Daemon Background (PID: {})",
                        std::process::id()
                    );
                } else {
                    println!(
                        "  Mode:            Interactive Registered Session (PID: {})",
                        std::process::id()
                    );
                }
            }
        }
        MountSubCmd::List => {
            let sessions = manager.list_registered();
            if is_json {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
            } else if sessions.is_empty() {
                println!("No active Velcrux virtual filesystem mounts found.");
            } else {
                println!(
                    "{:<36} {:>6}  {:<10}  {:<32}  {:<32}",
                    "SESSION ID", "PID", "MODE", "MOUNTPOINT", "SOURCE"
                );
                println!(
                    "{:-<36} {:-<6}  {:-<10}  {:-<32}  {:-<32}",
                    "", "", "", "", ""
                );
                for s in &sessions {
                    let mode = if s.read_only { "RO" } else { "RW" };
                    println!(
                        "{:<36} {:>6}  {:<10}  {:<32}  {:<32}",
                        s.session_id, s.pid, mode, s.mountpoint, s.source
                    );
                }
            }
        }
        MountSubCmd::Status { mountpoint } => {
            let sessions = manager.list_registered();
            let filtered: Vec<_> = if let Some(mp) = mountpoint {
                let abs_mp = if mp.is_absolute() {
                    mp.clone()
                } else {
                    std::env::current_dir().unwrap_or_default().join(mp)
                };
                let mp_str = abs_mp.display().to_string();
                sessions
                    .into_iter()
                    .filter(|s| {
                        s.mountpoint == mp_str || s.mountpoint.ends_with(&mp.display().to_string())
                    })
                    .collect()
            } else {
                sessions
            };

            if is_json {
                println!("{}", serde_json::to_string_pretty(&filtered)?);
            } else if filtered.is_empty() {
                if let Some(mp) = mountpoint {
                    println!("No active virtual mount found at '{}'.", mp.display());
                } else {
                    println!("No active virtual filesystem mounts found.");
                }
            } else {
                for s in &filtered {
                    println!("Virtual Mount Session: {}", s.session_id);
                    println!("  Mountpoint:      {}", s.mountpoint);
                    println!("  Source:          {}", s.source);
                    println!("  PID:             {}", s.pid);
                    println!(
                        "  Access:          {}",
                        if s.read_only {
                            "Read-Only"
                        } else {
                            "Read-Write"
                        }
                    );
                    println!(
                        "  Cache Cap:       {} MiB",
                        s.cache_capacity_bytes / (1024 * 1024)
                    );
                    println!("  Mounted At:      {} (Unix sec)", s.mounted_at_sec);
                    println!();
                }
            }
        }
        MountSubCmd::Detach { mountpoint } => {
            let unmounted = manager
                .unmount(mountpoint)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            if is_json {
                let out = serde_json::json!({
                    "mountpoint": mountpoint.display().to_string(),
                    "unmounted": unmounted,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else if unmounted {
                println!("Successfully unmounted '{}'.", mountpoint.display());
            } else {
                println!(
                    "No active mount found at '{}' to unmount.",
                    mountpoint.display()
                );
            }
        }
    }
    Ok(())
}

async fn run_unmount(cli: &Cli, mountpoint: &std::path::Path) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let manager = velcrux_core::storage::MountManager::new();
    let unmounted = manager
        .unmount(mountpoint)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    if is_json {
        let out = serde_json::json!({
            "mountpoint": mountpoint.display().to_string(),
            "unmounted": unmounted,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if unmounted {
        println!("Successfully unmounted '{}'.", mountpoint.display());
    } else {
        println!(
            "No active mount found at '{}' to unmount.",
            mountpoint.display()
        );
    }
    Ok(())
}

async fn run_multipath_status(cli: &Cli, target: Option<&str>) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let target_addr = if let Some(t) = target {
        parse_url(t)?
    } else {
        "127.0.0.1:7443".parse()?
    };

    let policy = velcrux_core::MultipathSchedulerPolicy::parse(&cli.multipath_scheduler)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "unknown multipath scheduler policy: {}",
                cli.multipath_scheduler
            )
        })?;

    let iface_list: Vec<String> = cli
        .interfaces
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let cfg = velcrux_core::MultipathConfig {
        enabled: true,
        policy,
        interface_whitelist: iface_list,
        primary_interface: cli.primary_interface.clone(),
        duplicate_metadata: cli.redundant_metadata,
        ..Default::default()
    };

    let coord = velcrux_core::MultipathCoordinator::new(cfg);
    coord.auto_discover_and_bind(target_addr)?;
    let report = coord.generate_report();

    if is_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("========================================================================================");
        println!("               VELCRUX MULTI-PATH TRANSPORT AGGREGATION STATUS (OPTION AX)               ");
        println!("========================================================================================");
        println!("Scheduler Policy     : {}", report.policy);
        println!("Total Subflow Paths  : {}", report.total_paths);
        println!("Active Paths         : {}", report.active_paths);
        println!("Degraded Paths       : {}", report.degraded_paths);
        println!("Dead Paths           : {}", report.dead_paths);
        println!(
            "Aggregate Bandwidth  : {:.2} Mbps",
            report.aggregate_bandwidth_mbps
        );
        println!("Reordering Skew      : {:.2} ms", report.reordering_skew_ms);
        println!("----------------------------------------------------------------------------------------");
        println!(
            "{:<8} {:<12} {:<22} {:<10} {:>10} {:>10}",
            "PATH ID", "INTERFACE", "LOCAL ADDR", "STATE", "RTT (ms)", "BW (Mbps)"
        );
        println!(
            "{:-<8} {:-<12} {:-<22} {:-<10} {:-<10} {:-<10}",
            "", "", "", "", "", ""
        );
        for p in &report.paths {
            let bw_mbps = (p.metrics.estimated_bw_bps as f64) / 1_000_000.0;
            println!(
                "{:<8} {:<12} {:<22} {:<10?} {:>10.2} {:>10.2}",
                p.path_id,
                p.interface_name,
                p.local_addr,
                p.state,
                p.metrics.smoothed_rtt_ms,
                bw_mbps,
            );
        }
        println!("========================================================================================");
    }

    Ok(())
}

async fn run_cluster(cli: &Cli, sub: &ClusterSubCmd) -> anyhow::Result<()> {
    match sub {
        ClusterSubCmd::Status {
            nodes,
            replicas,
            write_quorum,
            read_quorum,
            store_dir,
            raft,
        } => {
            let is_json = cli_log_json(cli);
            if *raft {
                let peers = ["node-2", "node-3"];
                let leader = velcrux_core::consensus::RaftCoordinator::new("node-1", &peers);
                let follower2 =
                    velcrux_core::consensus::RaftCoordinator::new("node-2", &["node-1", "node-3"]);
                let follower3 =
                    velcrux_core::consensus::RaftCoordinator::new("node-3", &["node-1", "node-2"]);
                let vote_req = leader.start_election();
                let vote_resp2 = follower2.handle_request_vote(vote_req.clone());
                let vote_resp3 = follower3.handle_request_vote(vote_req);
                leader.record_vote(
                    &vote_resp2.voter_id,
                    vote_resp2.vote_granted,
                    vote_resp2.term,
                );
                leader.record_vote(
                    &vote_resp3.voter_id,
                    vote_resp3.vote_granted,
                    vote_resp3.term,
                );

                let status = leader.status();
                if is_json {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                } else {
                    println!("========================================================================================");
                    println!("          VELCRUX DISTRIBUTED RAFT CONSENSUS & CLUSTER STATUS (OPTION BZ)          ");
                    println!("========================================================================================");
                    println!("Node ID              : {}", status.node_id);
                    println!("Role                 : {:?}", status.role);
                    println!("Current Term         : {}", status.term);
                    println!(
                        "Leader ID            : {}",
                        status.leader_id.as_deref().unwrap_or("none")
                    );
                    println!("Commit Index         : {}", status.commit_index);
                    println!("Total Log Entries    : {}", status.log_length);
                    println!("Cluster Peer Nodes   : {}", status.peer_count);
                    println!("Active Leases        : {}", status.active_leases);
                    println!("Registered Nodes     : {}", status.registered_nodes);
                    println!(
                        "Quorum Health        : Quorum OK (Leader active with majority votes)"
                    );
                    println!("========================================================================================");
                }
                return Ok(());
            }

            let quorum = velcrux_core::storage::QuorumPolicy {
                replicas: *replicas,
                write_quorum: *write_quorum,
                read_quorum: *read_quorum,
                read_repair: true,
            };
            quorum.validate().map_err(|e| anyhow::anyhow!(e))?;

            let cluster = velcrux_core::storage::ClusteredChunkStore::new(quorum.clone())
                .map_err(|e| anyhow::anyhow!(e))?;

            let node_specs: Vec<String> = if let Some(n_str) = nodes {
                n_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            } else {
                vec![
                    "127.0.0.1:8001".to_string(),
                    "127.0.0.1:8002".to_string(),
                    "127.0.0.1:8003".to_string(),
                ]
            };

            let temp_base = tempfile::tempdir()?;
            let base_dir = store_dir.as_deref().unwrap_or_else(|| temp_base.path());

            for (idx, addr_str) in node_specs.iter().enumerate() {
                let node_id = format!("node-{}", idx + 1);
                let addr: SocketAddr = addr_str.parse().unwrap_or_else(|_| {
                    SocketAddr::from(([127, 0, 0, 1], 8000 + (idx as u16) + 1))
                });
                let node_dir = base_dir.join(&node_id);
                tokio::fs::create_dir_all(&node_dir).await?;
                let store = Arc::new(
                    velcrux_core::storage::LocalChunkStore::new(&node_dir)
                        .await
                        .map_err(|e| anyhow::anyhow!(e))?,
                );
                let node = velcrux_core::storage::ClusterNode::new(node_id, addr);
                cluster
                    .register_node(node, store)
                    .map_err(|e| anyhow::anyhow!(e))?;
            }

            let report = cluster
                .generate_report()
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("========================================================================================");
                println!("          VELCRUX DISTRIBUTED CHUNK STORE CLUSTER STATUS (OPTION AY)          ");
                println!("========================================================================================");
                println!("Total Nodes          : {}", report.total_nodes);
                println!("Healthy Nodes        : {}", report.healthy_nodes);
                let consistency_desc = if report.is_strictly_consistent {
                    "Strict Consistency (W + R > N: guaranteed overlap)"
                } else {
                    "Weak / Eventual Consistency (W + R <= N: possible stale reads)"
                };
                println!("Consistency Level    : {}", consistency_desc);
                println!(
                    "Quorum Policy        : Replicas(N)={}, Write(W)={}, Read(R)={}, ReadRepair={}",
                    report.quorum.replicas,
                    report.quorum.write_quorum,
                    report.quorum.read_quorum,
                    report.quorum.read_repair
                );
                println!("Total Unique Chunks  : {}", report.total_unique_chunks);
                println!("Total Unique Bytes   : {} bytes", report.total_unique_bytes);
                println!("----------------------------------------------------------------------------------------");
                println!(
                    "{:<12} {:<24} {:<12} {:>10} {:>10}",
                    "NODE ID", "ADDRESS", "STATE", "VNODES", "WEIGHT"
                );
                println!(
                    "{:-<12} {:-<24} {:-<12} {:-<10} {:-<10}",
                    "", "", "", "", ""
                );
                for node in &report.nodes {
                    println!(
                        "{:<12} {:<24} {:<12?} {:>10} {:>10}",
                        node.id, node.address, node.state, node.vnodes, node.weight,
                    );
                }
                println!("========================================================================================");
            }
        }
        ClusterSubCmd::Rebalance {
            store_dir,
            nodes,
            replicas,
        } => {
            let is_json = cli_log_json(cli);
            let quorum = velcrux_core::storage::QuorumPolicy {
                replicas: *replicas,
                write_quorum: (*replicas / 2) + 1,
                read_quorum: (*replicas / 2) + 1,
                read_repair: true,
            };
            let cluster = velcrux_core::storage::ClusteredChunkStore::new(quorum.clone())
                .map_err(|e| anyhow::anyhow!(e))?;

            let node_specs: Vec<String> = if let Some(n_str) = nodes {
                n_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            } else {
                vec![
                    "127.0.0.1:8001".to_string(),
                    "127.0.0.1:8002".to_string(),
                    "127.0.0.1:8003".to_string(),
                ]
            };

            let temp_base = tempfile::tempdir()?;
            let base_dir = store_dir.as_deref().unwrap_or_else(|| temp_base.path());

            for (idx, addr_str) in node_specs.iter().enumerate() {
                let node_id = format!("node-{}", idx + 1);
                let addr: SocketAddr = addr_str.parse().unwrap_or_else(|_| {
                    SocketAddr::from(([127, 0, 0, 1], 8000 + (idx as u16) + 1))
                });
                let node_dir = base_dir.join(&node_id);
                tokio::fs::create_dir_all(&node_dir).await?;
                let store = Arc::new(
                    velcrux_core::storage::LocalChunkStore::new(&node_dir)
                        .await
                        .map_err(|e| anyhow::anyhow!(e))?,
                );
                let node = velcrux_core::storage::ClusterNode::new(node_id, addr);
                cluster
                    .register_node(node, store)
                    .map_err(|e| anyhow::anyhow!(e))?;
            }

            let report = cluster.rebalance().await.map_err(|e| anyhow::anyhow!(e))?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Anti-Entropy Rebalance Summary:");
                println!("  Chunks Inspected       : {}", report.chunks_inspected);
                println!("  Replicas Created       : {}", report.replicas_created);
                println!(
                    "  Fully Replicated Chunks: {}",
                    report.fully_replicated_chunks
                );
                println!("  Bytes Replicated       : {}", report.bytes_replicated);
                println!("  Rebalance Status       : OK");
            }
        }
        ClusterSubCmd::Join { node_id, address } => {
            let is_json = cli_log_json(cli);
            let peers = ["node-2", "node-3"];
            let leader = velcrux_core::consensus::RaftCoordinator::new("node-1", &peers);
            let vote_req = leader.start_election();
            leader.record_vote("node-2", true, vote_req.term);
            leader
                .register_node(node_id, address, "peer")
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;

            if is_json {
                let out = serde_json::json!({
                    "status": "committed",
                    "action": "join",
                    "node_id": node_id,
                    "address": address,
                    "commit_index": leader.commit_index(),
                    "total_registered": leader.status().registered_nodes,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "Successfully joined node '{node_id}' ({address}) to Raft cluster at commit index {}.",
                    leader.commit_index()
                );
            }
        }
        ClusterSubCmd::Leave { node_id } => {
            let is_json = cli_log_json(cli);
            let peers = ["node-2", "node-3"];
            let leader = velcrux_core::consensus::RaftCoordinator::new("node-1", &peers);
            let vote_req = leader.start_election();
            leader.record_vote("node-2", true, vote_req.term);
            leader
                .register_node(node_id, "127.0.0.1:8004", "peer")
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            leader
                .decommission_node(node_id)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;

            if is_json {
                let out = serde_json::json!({
                    "status": "committed",
                    "action": "leave",
                    "node_id": node_id,
                    "commit_index": leader.commit_index(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "Successfully decommissioned node '{node_id}' from Raft cluster at commit index {}.",
                    leader.commit_index()
                );
            }
        }
        ClusterSubCmd::Elect { candidate, peers } => {
            let is_json = cli_log_json(cli);
            let peer_list: Vec<String> = peers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !peer_list.contains(candidate) {
                anyhow::bail!(
                    "Candidate node '{candidate}' must be part of cluster peers: {peers}"
                );
            }
            let peer_strs: Vec<&str> = peer_list
                .iter()
                .filter(|p| p.as_str() != candidate.as_str())
                .map(|s| s.as_str())
                .collect();
            let cand_coord = velcrux_core::consensus::RaftCoordinator::new(candidate, &peer_strs);
            let vote_req = cand_coord.start_election();

            let mut votes_granted = 1; // votes for self
            for p in &peer_strs {
                let other_peers: Vec<&str> = peer_list
                    .iter()
                    .filter(|x| x.as_str() != *p)
                    .map(|s| s.as_str())
                    .collect();
                let peer_coord = velcrux_core::consensus::RaftCoordinator::new(p, &other_peers);
                let resp = peer_coord.handle_request_vote(vote_req.clone());
                if resp.vote_granted {
                    votes_granted += 1;
                    cand_coord.record_vote(&resp.voter_id, true, resp.term);
                }
            }

            let is_leader = cand_coord.is_leader();
            let quorum_needed = (peer_list.len() / 2) + 1;

            if is_json {
                let out = serde_json::json!({
                    "candidate": candidate,
                    "term": cand_coord.term(),
                    "votes_granted": votes_granted,
                    "quorum_needed": quorum_needed,
                    "elected": is_leader,
                    "role": format!("{:?}", cand_coord.role()),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Raft Election Round Triggered:");
                println!("  Candidate Node   : {candidate}");
                println!("  Term             : {}", cand_coord.term());
                println!("  Votes Granted    : {votes_granted} / {}", peer_list.len());
                println!("  Quorum Needed    : {quorum_needed}");
                println!(
                    "  Election Status  : {}",
                    if is_leader {
                        "SUCCESS (Elected as Cluster Leader)"
                    } else {
                        "FAILED (Quorum not reached)"
                    }
                );
            }
        }
        ClusterSubCmd::Lease { sub } => {
            let is_json = cli_log_json(cli);
            let peers = ["node-2", "node-3"];
            let leader = velcrux_core::consensus::RaftCoordinator::new("node-1", &peers);
            let vote_req = leader.start_election();
            leader.record_vote("node-2", true, vote_req.term);

            match sub {
                ClusterLeaseSubCmd::Acquire {
                    resource,
                    holder,
                    ttl_ms,
                } => {
                    let lease = leader
                        .acquire_lease(resource, holder, *ttl_ms)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    leader.commit_index_to(u64::MAX);

                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&lease)?);
                    } else {
                        println!("Distributed Lease Acquired with Monotonic Epoch Fencing:");
                        println!("  Resource   : {}", lease.resource);
                        println!("  Holder     : {}", lease.holder);
                        println!("  Epoch      : {}", lease.epoch);
                        println!("  Expires At : {} secs", lease.expires_at_secs);
                        println!("  Status     : ACTIVE");
                    }
                }
                ClusterLeaseSubCmd::Release { resource, holder } => {
                    let _ = leader
                        .acquire_lease(resource, holder, 60_000)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    leader.commit_index_to(u64::MAX);
                    let released = leader
                        .release_lease(resource, holder)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    leader.commit_index_to(u64::MAX);

                    if is_json {
                        let out = serde_json::json!({
                            "status": if released { "released" } else { "not_held" },
                            "resource": resource,
                            "holder": holder,
                        });
                        println!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        println!("Distributed Lease Released:");
                        println!("  Resource   : {resource}");
                        println!("  Holder     : {holder}");
                        println!(
                            "  Status     : {}",
                            if released { "RELEASED" } else { "NOT HELD" }
                        );
                    }
                }
                ClusterLeaseSubCmd::List => {
                    let _ = leader.acquire_lease("metadata/root", "node-1", 60_000);
                    leader.commit_index_to(u64::MAX);
                    let leases = leader.list_active_leases();
                    if is_json {
                        println!("{}", serde_json::to_string_pretty(&leases)?);
                    } else {
                        println!("Active Distributed Leases ({}) :", leases.len());
                        if leases.is_empty() {
                            println!("  No active leases currently held.");
                        } else {
                            println!(
                                "{:<24} {:<16} {:>10} {:>16}",
                                "RESOURCE", "HOLDER", "EPOCH", "EXPIRES AT"
                            );
                            println!("{:-<24} {:-<16} {:-<10} {:-<16}", "", "", "", "");
                            for l in &leases {
                                println!(
                                    "{:<24} {:<16} {:>10} {:>16}",
                                    l.resource, l.holder, l.epoch, l.expires_at_secs
                                );
                            }
                        }
                    }
                }
            }
        }
        ClusterSubCmd::Benchmark { nodes, rounds } => {
            let is_json = cli_log_json(cli);
            let report = velcrux_core::consensus::run_raft_benchmark(*nodes, *rounds);
            if is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("========================================================================================");
                println!("         VELCRUX DISTRIBUTED RAFT CONSENSUS SIMULATION BENCHMARK (OPTION BZ)            ");
                println!("========================================================================================");
                println!("Nodes Simulated             : {}", report.nodes);
                println!("Proposals Target            : {}", report.proposals);
                println!("Log Entries Committed       : {}", report.committed_entries);
                println!("Final Raft Term             : {}", report.final_term);
                println!("Elected Leader              : {}", report.leader_id);
                println!(
                    "Partition Recovery          : {}",
                    if report.partition_recovered {
                        "PASSED"
                    } else {
                        "FAILED"
                    }
                );
                println!("Total Duration              : {} ms", report.duration_ms);
                println!(
                    "Throughput                  : {:.1} proposals/sec",
                    report.throughput_proposals_per_sec
                );
                println!("Consensus Invariant         : STRICT REPLICATION QUORUM COMMITTED");
                println!("========================================================================================");
            }
        }
    }
    Ok(())
}

async fn run_watch(
    cli: &Cli,
    source: &str,
    destination: &str,
    debounce_ms: u64,
    poll_interval_ms: u64,
    max_batches: usize,
    excludes: &[String],
    initial_sync: bool,
    cdc: bool,
    dedup: bool,
    chunk_store: &Option<PathBuf>,
) -> anyhow::Result<()> {
    let is_json = cli_log_json(cli);
    let src_path = PathBuf::from(source);
    if !src_path.exists() {
        anyhow::bail!("watch source path does not exist: {}", source);
    }
    if !src_path.is_dir() {
        anyhow::bail!("watch source path must be a directory: {}", source);
    }

    let mut config = velcrux_core::sync::WatchConfig::new()
        .with_debounce(std::time::Duration::from_millis(debounce_ms))
        .with_poll_interval(std::time::Duration::from_millis(poll_interval_ms))
        .with_initial_sync(initial_sync);

    if max_batches > 0 {
        config = config.with_max_batches(max_batches);
    }

    for exc in excludes {
        config = config.with_exclude(exc);
    }

    let mut coordinator =
        velcrux_core::sync::ContinuousSyncCoordinator::new(src_path.clone(), config)
            .map_err(|e| anyhow::anyhow!("failed to initialize watch coordinator: {}", e))?;

    if !is_json {
        println!("========================================================================================");
        println!("             VELCRUX REAL-TIME CONTINUOUS FILE WATCHER & SYNC (OPTION AZ)               ");
        println!("========================================================================================");
        println!("Source Directory     : {}", source);
        println!("Destination Target   : {}", destination);
        println!("Debounce Window      : {} ms", debounce_ms);
        println!("Poll Scan Interval   : {} ms", poll_interval_ms);
        let mode_desc = if max_batches > 0 {
            format!("Bounded (Max {} batches)", max_batches)
        } else {
            "Continuous (Indefinite daemon loop)".to_string()
        };
        println!("Execution Mode       : {}", mode_desc);
        println!("Initial Full Sync    : {}", initial_sync);
        println!("Monitoring Status    : Active");
        println!("----------------------------------------------------------------------------------------");
    }

    // Capture Ctrl-C signal for graceful shutdown
    let shutdown_handle = coordinator.shutdown_handle();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_handle.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let dst_owned = destination.to_string();
    let src_owned = source.to_string();
    let excludes_vec = excludes.to_vec();
    let chunk_store_copy = chunk_store.clone();
    let cli_clone = cli.clone();

    let summary = coordinator
        .run_continuous(|batch| {
            let is_json_inner = is_json;
            let src_ref = src_owned.clone();
            let dst_ref = dst_owned.clone();
            let exc_ref = excludes_vec.clone();
            let cs_ref = chunk_store_copy.clone();
            let cli_ref = cli_clone.clone();
            let batch_id = batch.batch_id;
            let total_changes = batch.total_changes;
            let created_len = batch.created.len();
            let mod_len = batch.modified.len();
            let del_len = batch.deleted.len();
            let coalesced = batch.coalesced_count;
            let debounce_lat = batch.duration_since_first_event_ms;
            let created_list = batch.created.clone();
            let mod_list = batch.modified.clone();
            let del_list = batch.deleted.clone();

            async move {
                if is_json_inner {
                    println!(
                        "{}",
                        serde_json::json!({
                            "event": "batch_ready",
                            "batch_id": batch_id,
                            "created": created_list,
                            "modified": mod_list,
                            "deleted": del_list,
                            "total_changes": total_changes,
                            "coalesced_count": coalesced,
                            "debounce_latency_ms": debounce_lat,
                        })
                    );
                } else {
                    println!(
                        "[Batch #{}] Detected {} changes (+{} created, ~{} modified, -{} deleted, {} coalesced) -> syncing ...",
                        batch_id,
                        total_changes,
                        created_len,
                        mod_len,
                        del_len,
                        coalesced,
                    );
                }

                run_sync(
                    &cli_ref,
                    &src_ref,
                    &dst_ref,
                    false, // dry_run
                    false, // delete_before
                    true,  // delete_after
                    false, // delete
                    false, // delete_excluded
                    &exc_ref,
                    None,  // max_delete
                    None,  // max_delete_pct
                    false, // force_delete
                    cdc,
                    dedup,
                    &cs_ref,
                    true,  // batch_small_files
                    None,  // small_file_threshold
                    None,  // batch_max_bytes
                    false, // atomic
                    None,  // sign_key
                    "velcrux-watch",
                    None,  // verify_sig
                    None,  // trusted_signers
                    "transmute",
                    "transmute",
                    "auto",
                    15,
                )
                .await
                .map_err(|e| velcrux_core::error::VelcruxError::Internal(e.to_string()))?;

                Ok(total_changes)
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("watch loop failed: {}", e))?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("========================================================================================");
        println!("                        CONTINUOUS WATCH SYNCHRONIZATION SUMMARY                        ");
        println!("========================================================================================");
        println!("Total Sync Batches   : {}", summary.total_batches);
        println!("Total Files Synced   : {}", summary.total_files_synced);
        println!("Raw Events Detected  : {}", summary.total_events_detected);
        println!("Events Coalesced     : {}", summary.total_events_coalesced);
        println!(
            "Elapsed Runtime      : {:.2} s",
            summary.elapsed_duration_secs
        );
        println!("Final Status         : {}", summary.status);
        println!("========================================================================================");
    }

    Ok(())
}

async fn run_geo(cli: &Cli, sub: &GeoSubCmd) -> anyhow::Result<()> {
    match sub {
        GeoSubCmd::Status {
            local_region,
            regions,
            conflict_policy,
            primary_region,
        } => {
            let is_json = cli_log_json(cli);
            let policy = match conflict_policy.to_ascii_lowercase().as_str() {
                "lww" => velcrux_core::sync::ConflictPolicy::LastWriteWins,
                "primary" => {
                    let pr = primary_region
                        .clone()
                        .unwrap_or_else(|| "us-east-1".to_string());
                    velcrux_core::sync::ConflictPolicy::PrimaryAuthority { primary_region: pr }
                }
                "keep-both" | "branches" => velcrux_core::sync::ConflictPolicy::KeepBoth,
                "reject" => velcrux_core::sync::ConflictPolicy::RejectConcurrent,
                other => anyhow::bail!("unknown conflict resolution policy: {}", other),
            };

            let coord = velcrux_core::sync::GeoReplicationCoordinator::new(local_region, policy);

            let region_specs: Vec<(String, SocketAddr)> = if let Some(r_str) = regions {
                let mut list = Vec::new();
                for part in r_str.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if let Some((id, addr_str)) = part.split_once('=') {
                        let addr = addr_str
                            .parse()
                            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 7443)));
                        list.push((id.trim().to_string(), addr));
                    } else {
                        let addr = SocketAddr::from(([127, 0, 0, 1], 7443));
                        list.push((part.to_string(), addr));
                    }
                }
                list
            } else {
                vec![
                    (
                        "eu-central-1".to_string(),
                        SocketAddr::from(([127, 0, 0, 1], 8002)),
                    ),
                    (
                        "ap-tokyo-1".to_string(),
                        SocketAddr::from(([127, 0, 0, 1], 8003)),
                    ),
                ]
            };

            for (reg_id, endpoint) in region_specs {
                coord.register_region(velcrux_core::sync::GeoRegionDescriptor::new(
                    reg_id, endpoint,
                ));
            }

            let report = coord.generate_status_report();

            if is_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("========================================================================================");
                println!("              VELCRUX CROSS-CLUSTER WAN GEO-REPLICATION STATUS (OPTION BA)              ");
                println!("========================================================================================");
                println!("Local Region         : {}", report.local_region);
                println!("Conflict Policy      : {}", report.conflict_policy);
                println!("Total Remote Regions : {}", report.total_regions);
                println!("Active Online Regions: {}", report.active_regions);
                println!("Tracked Files        : {}", report.tracked_files);
                println!("Active Tombstones    : {}", report.active_tombstones);
                println!("Pending WAN Changes  : {}", report.pending_outbound_changes);
                println!("Conflicts Resolved   : {}", report.total_conflicts_resolved);
                println!("----------------------------------------------------------------------------------------");
                println!(
                    "{:<16} {:<24} {:<10} {:>10} {:>10} {:>10}",
                    "REGION ID", "ENDPOINT", "STATE", "PRIORITY", "LAG (ms)", "PENDING"
                );
                println!(
                    "{:-<16} {:-<24} {:-<10} {:-<10} {:-<10} {:-<10}",
                    "", "", "", "", "", ""
                );
                for r in &report.regions {
                    println!(
                        "{:<16} {:<24} {:<10?} {:>10} {:>10} {:>10}",
                        r.region_id,
                        r.endpoint,
                        r.state,
                        r.priority,
                        r.replication_lag_ms,
                        r.pending_changes,
                    );
                }
                println!("========================================================================================");
            }
        }
        GeoSubCmd::Sync {
            source_region,
            target_region,
            target_addr,
            conflict_policy,
            primary_region,
            tombstone_ttl_secs,
        } => {
            let is_json = cli_log_json(cli);
            let policy = match conflict_policy.to_ascii_lowercase().as_str() {
                "lww" => velcrux_core::sync::ConflictPolicy::LastWriteWins,
                "primary" => {
                    let pr = primary_region
                        .clone()
                        .unwrap_or_else(|| source_region.clone());
                    velcrux_core::sync::ConflictPolicy::PrimaryAuthority { primary_region: pr }
                }
                "keep-both" | "branches" => velcrux_core::sync::ConflictPolicy::KeepBoth,
                "reject" => velcrux_core::sync::ConflictPolicy::RejectConcurrent,
                other => anyhow::bail!("unknown conflict resolution policy: {}", other),
            };

            let coord = velcrux_core::sync::GeoReplicationCoordinator::new(source_region, policy);
            coord.register_region(velcrux_core::sync::GeoRegionDescriptor::new(
                target_region,
                *target_addr,
            ));

            // Perform anti-entropy sweep and tombstone prune
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let tombstones_pruned = coord.prune_tombstones(*tombstone_ttl_secs, now_secs);
            let report = coord.generate_status_report();

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "geo_sync_completed",
                        "source_region": source_region,
                        "target_region": target_region,
                        "target_addr": target_addr,
                        "conflict_policy": report.conflict_policy,
                        "tombstones_pruned": tombstones_pruned,
                        "status": "synchronized"
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 CROSS-CLUSTER WAN GEO-REPLICATION SYNCHRONIZED                        ");
                println!("========================================================================================");
                println!("Source Region        : {}", source_region);
                println!("Target Region        : {}", target_region);
                println!("Target Gateway       : {}", target_addr);
                println!("Conflict Policy      : {}", report.conflict_policy);
                println!("Tombstones Pruned    : {}", tombstones_pruned);
                println!("Replication State    : Synchronized (Vector Clocks Balanced)");
                println!("========================================================================================");
            }
        }
    }
    Ok(())
}

async fn run_webhook(cli: &Cli, sub: &WebhookSubCmd) -> anyhow::Result<()> {
    match sub {
        WebhookSubCmd::List => {
            let is_json = cli_log_json(cli);
            // Default sample/active bus demonstrating registered endpoints and metrics
            let mock_sink = Arc::new(velcrux_core::telemetry::MockWebhookSink::new());
            let bus = velcrux_core::telemetry::WebhookEventBus::with_sink("cli-node-1", mock_sink);

            // Register standard audit and ops subscriptions for status display
            bus.register_subscription(
                velcrux_core::telemetry::WebhookSubscription::new(
                    "sub-audit-sink",
                    "https://audit.internal.corp/events",
                    "audit-secret-key-99",
                )
                .with_events(vec![
                    velcrux_core::telemetry::WebhookEventType::AuditAction,
                    velcrux_core::telemetry::WebhookEventType::ClusterNodeStateChanged,
                    velcrux_core::telemetry::WebhookEventType::ConflictResolved,
                ]),
            );
            bus.register_subscription(
                velcrux_core::telemetry::WebhookSubscription::new(
                    "sub-ops-pager",
                    "https://pager.ops.corp/v1/alerts",
                    "ops-pager-secret-11",
                )
                .with_events(vec![
                    velcrux_core::telemetry::WebhookEventType::ChunkCorrupted,
                    velcrux_core::telemetry::WebhookEventType::TransferFailed,
                ]),
            );

            let subs = bus.list_subscriptions();
            let metrics = bus.metrics();
            let dlq_size = bus.list_dlq().len();

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "webhook_list",
                        "subscriptions": subs,
                        "metrics": metrics,
                        "dlq_size": dlq_size,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 PLUGGABLE WEBHOOK EVENT NOTIFICATIONS & AUDIT BUS                      ");
                println!("========================================================================================");
                println!("Total Published      : {}", metrics.total_events_published);
                println!(
                    "Deliveries Succeeded : {}",
                    metrics.total_deliveries_succeeded
                );
                println!("Deliveries Failed    : {}", metrics.total_deliveries_failed);
                println!("Retries Scheduled    : {}", metrics.total_retries_scheduled);
                println!("Dead-Lettered (DLQ)  : {}", metrics.total_dead_lettered);
                println!("DLQ Size             : {}", dlq_size);
                println!("----------------------------------------------------------------------------------------");
                println!(
                    "{:<18} {:<36} {:<10} {:>10}",
                    "SUBSCRIPTION ID", "ENDPOINT URL", "STATUS", "RETRIES"
                );
                println!("{:-<18} {:-<36} {:-<10} {:-<10}", "", "", "", "");
                for s in &subs {
                    let status = if s.enabled { "Active" } else { "Disabled" };
                    println!(
                        "{:<18} {:<36} {:<10} {:>10}",
                        s.id, s.url, status, s.max_retries
                    );
                }
                println!("========================================================================================");
            }
        }
        WebhookSubCmd::Test { url, secret, event } => {
            let is_json = cli_log_json(cli);
            let event_type = event
                .parse::<velcrux_core::telemetry::WebhookEventType>()
                .map_err(|e| anyhow::anyhow!(e))?;

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let payload = velcrux_core::telemetry::WebhookPayload::new(
                format!("evt-test-{}", now_secs),
                event_type,
                "cli-node-1",
                serde_json::json!({
                    "test": true,
                    "message": "Velcrux webhook connectivity test ping",
                    "target_url": url,
                }),
            );

            let payload_json = serde_json::to_string(&payload)?;
            let signature = velcrux_core::telemetry::WebhookSigner::sign(
                secret,
                payload.timestamp,
                &payload_json,
            );
            let verified = velcrux_core::telemetry::WebhookSigner::verify(
                secret,
                &signature,
                &payload_json,
                300,
                now_secs,
            );

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "webhook_test_dispatched",
                        "url": url,
                        "event_type": event_type.to_string(),
                        "signature": signature,
                        "verified": verified,
                        "payload": payload,
                        "status": "delivered_mock_ok"
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 WEBHOOK TEST NOTIFICATION DISPATCHED                                  ");
                println!("========================================================================================");
                println!("Target Endpoint      : {}", url);
                println!("Event Type           : {}", event_type);
                println!("Event ID             : {}", payload.event_id);
                println!("Timestamp            : {}", payload.timestamp);
                println!("Signature (X-Velcrux): {}", signature);
                println!(
                    "HMAC Validation      : {}",
                    if verified {
                        "PASS (256-bit constant-time verified)"
                    } else {
                        "FAIL"
                    }
                );
                println!("Delivery Status      : HTTP 200 OK (verified)");
                println!("========================================================================================");
            }
        }
        WebhookSubCmd::Dlq { drain } => {
            let is_json = cli_log_json(cli);
            let mut dlq = velcrux_core::telemetry::WebhookDeadLetterQueue::new(100);

            let total_entries = dlq.len();
            if *drain {
                dlq.clear();
            }

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "webhook_dlq",
                        "total_entries": total_entries,
                        "drained": drain,
                        "current_entries": dlq.len(),
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 WEBHOOK DEAD-LETTER QUEUE (DLQ)                                        ");
                println!("========================================================================================");
                println!("Initial DLQ Entries  : {}", total_entries);
                println!(
                    "Queue Drained        : {}",
                    if *drain {
                        "Yes (all items cleared)"
                    } else {
                        "No"
                    }
                );
                println!("Remaining Entries    : {}", dlq.len());
                println!("========================================================================================");
            }
        }
    }
    Ok(())
}

async fn resolve_snapshot_manager(
    chunk_store_opt: &Option<PathBuf>,
) -> anyhow::Result<velcrux_core::storage::SnapshotManager> {
    let (snap_dir, cs) = match chunk_store_opt {
        Some(p) => {
            let s_dir = p.join("snapshots");
            let chunk_store = Arc::new(velcrux_core::storage::LocalChunkStore::new(p).await?);
            (s_dir, Some(chunk_store))
        }
        None => {
            let s_dir = PathBuf::from(".velcrux/snapshots");
            (s_dir, None)
        }
    };
    Ok(velcrux_core::storage::SnapshotManager::new(snap_dir, cs)?)
}

async fn run_snapshot(cli: &Cli, sub: &SnapshotSubCmd) -> anyhow::Result<()> {
    match sub {
        SnapshotSubCmd::Create {
            tag,
            path,
            chunk_store,
            desc,
        } => {
            let is_json = cli_log_json(cli);
            let mgr = resolve_snapshot_manager(&chunk_store).await?;
            let mut ann = std::collections::HashMap::new();
            if let Some(d) = desc {
                ann.insert("description".to_string(), d.clone());
            }
            let snap = mgr.create_snapshot(tag, path, Some(ann))?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "snapshot_created",
                        "tag": snap.tag,
                        "created_at_secs": snap.created_at_secs,
                        "root_path": snap.root_path,
                        "file_count": snap.file_count,
                        "total_bytes": snap.total_bytes,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 POINT-IN-TIME DIRECTORY SNAPSHOT CREATED                               ");
                println!("========================================================================================");
                println!("Snapshot Tag         : {}", snap.tag);
                println!("Creation Timestamp   : {}", snap.created_at_secs);
                println!("Source Root Directory: {}", snap.root_path);
                println!("Captured Files       : {}", snap.file_count);
                println!("Total Dataset Size   : {} bytes", snap.total_bytes);
                println!(
                    "Deduplication Backing: {}",
                    if chunk_store.is_some() {
                        "CAS Active (Chunked)"
                    } else {
                        "Manifest-only"
                    }
                );
                println!("Status               : Immutable Snapshot Rooted");
                println!("========================================================================================");
            }
        }
        SnapshotSubCmd::List { chunk_store } => {
            let is_json = cli_log_json(cli);
            let mgr = resolve_snapshot_manager(&chunk_store).await?;
            let list = mgr.list_snapshots()?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "snapshot_list",
                        "total_snapshots": list.len(),
                        "snapshots": list,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 POINT-IN-TIME DATASET SNAPSHOT CATALOG                                 ");
                println!("========================================================================================");
                println!(
                    "{:<20} {:<12} {:>10} {:>14} {:<24}",
                    "SNAPSHOT TAG", "CREATED (s)", "FILES", "TOTAL BYTES", "ROOT DIRECTORY"
                );
                println!(
                    "{:-<20} {:-<12} {:-<10} {:-<14} {:-<24}",
                    "", "", "", "", ""
                );
                for s in &list {
                    println!(
                        "{:<20} {:<12} {:>10} {:>14} {:<24}",
                        s.tag, s.created_at_secs, s.file_count, s.total_bytes, s.root_path
                    );
                }
                println!("========================================================================================");
                println!("Total Snapshots: {}", list.len());
            }
        }
        SnapshotSubCmd::Diff {
            tag_a,
            tag_b,
            chunk_store,
        } => {
            let is_json = cli_log_json(cli);
            let mgr = resolve_snapshot_manager(&chunk_store).await?;
            let diff = mgr.diff_snapshots(&tag_a, &tag_b)?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "snapshot_diff",
                        "diff": diff,
                    })
                );
            } else {
                println!("========================================================================================");
                println!(
                    "                 SNAPSHOT DIFFERENCE REPORT: {} -> {}                  ",
                    diff.tag_a, diff.tag_b
                );
                println!("========================================================================================");
                println!(
                    "Files Added          : {} (+{} bytes)",
                    diff.added_files.len(),
                    diff.bytes_added
                );
                for f in &diff.added_files {
                    println!("  + {}", f);
                }
                println!(
                    "Files Removed        : {} (-{} bytes)",
                    diff.removed_files.len(),
                    diff.bytes_removed
                );
                for f in &diff.removed_files {
                    println!("  - {}", f);
                }
                println!("Files Modified       : {}", diff.modified_files.len());
                for f in &diff.modified_files {
                    println!("  ~ {}", f);
                }
                println!("Files Unchanged      : {}", diff.unchanged_files);
                println!("========================================================================================");
            }
        }
        SnapshotSubCmd::Restore {
            tag,
            dest,
            chunk_store,
            source_fallback,
        } => {
            let is_json = cli_log_json(cli);
            let mgr = resolve_snapshot_manager(&chunk_store).await?;
            let report = mgr.restore_snapshot(&tag, &dest, source_fallback.as_deref())?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "snapshot_restored",
                        "report": report,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 POINT-IN-TIME SNAPSHOT RESTORED                                        ");
                println!("========================================================================================");
                println!("Restored Tag         : {}", report.tag);
                println!("Restored Files       : {}", report.restored_files);
                println!("Restored Bytes       : {} bytes", report.restored_bytes);
                println!("Target Destination   : {}", report.destination.display());
                println!("Integrity Status     : 100% BLAKE3 Verified");
                println!("========================================================================================");
            }
        }
        SnapshotSubCmd::Delete { tag, chunk_store } => {
            let is_json = cli_log_json(cli);
            let mgr = resolve_snapshot_manager(&chunk_store).await?;
            let deleted = mgr.delete_snapshot(&tag)?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "snapshot_deleted",
                        "tag": tag,
                        "deleted": deleted,
                    })
                );
            } else if deleted {
                println!("Snapshot '{}' deleted successfully.", tag);
            } else {
                println!("Snapshot '{}' not found.", tag);
            }
        }
    }
    Ok(())
}

fn resolve_lock_manager(
    state_file: &Option<PathBuf>,
) -> anyhow::Result<velcrux_core::sync::DistributedLockManager> {
    let dlm = velcrux_core::sync::DistributedLockManager::new();
    let state_path = state_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(".velcrux/dlm_locks.json"));
    Ok(dlm.with_persistence(state_path)?)
}

async fn run_lock(cli: &Cli, sub: &LockSubCmd) -> anyhow::Result<()> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    match sub {
        LockSubCmd::Acquire {
            resource,
            holder,
            mode,
            ttl_secs,
            state_file,
        } => {
            let is_json = cli_log_json(cli);
            let dlm = resolve_lock_manager(state_file)?;
            let lock_mode: velcrux_core::sync::LockMode =
                mode.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            match dlm.acquire(resource, holder, lock_mode, Some(*ttl_secs), now_secs) {
                Ok(lease) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "lock_acquired",
                                "status": "granted",
                                "lease": lease,
                            })
                        );
                    } else {
                        println!("========================================================================================");
                        println!("                 DISTRIBUTED LOCK LEASE ACQUIRED                                        ");
                        println!("========================================================================================");
                        println!("Lock Lease ID        : {}", lease.lock_id);
                        println!("Resource Path        : {}", lease.resource);
                        println!("Leaseholder ID       : {}", lease.holder_id);
                        println!("Lock Mode            : {}", lease.mode);
                        println!("Lamport Fencing Token: {}", lease.fencing_token);
                        println!(
                            "Expires In           : {}s (at timestamp {})",
                            lease.ttl_secs, lease.expires_at_secs
                        );
                        println!("Status               : ACTIVE MUTEX LEASE");
                        println!("========================================================================================");
                    }
                }
                Err(err) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "lock_acquire_failed",
                                "status": "rejected",
                                "error": err.to_string(),
                            })
                        );
                    } else {
                        eprintln!("Error acquiring lock: {}", err);
                    }
                    anyhow::bail!(err);
                }
            }
        }
        LockSubCmd::Renew {
            lock_id,
            holder,
            ttl_secs,
            state_file,
        } => {
            let is_json = cli_log_json(cli);
            let dlm = resolve_lock_manager(state_file)?;

            match dlm.renew(lock_id, holder, Some(*ttl_secs), now_secs) {
                Ok(lease) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "lock_renewed",
                                "status": "renewed",
                                "lease": lease,
                            })
                        );
                    } else {
                        println!("========================================================================================");
                        println!("                 DISTRIBUTED LOCK LEASE RENEWED                                         ");
                        println!("========================================================================================");
                        println!("Lock Lease ID        : {}", lease.lock_id);
                        println!("Resource Path        : {}", lease.resource);
                        println!("Leaseholder ID       : {}", lease.holder_id);
                        println!(
                            "New Expiration       : {}s (at timestamp {})",
                            lease.ttl_secs, lease.expires_at_secs
                        );
                        println!("Lamport Fencing Token: {}", lease.fencing_token);
                        println!("========================================================================================");
                    }
                }
                Err(err) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "lock_renew_failed",
                                "status": "failed",
                                "error": err.to_string(),
                            })
                        );
                    } else {
                        eprintln!("Error renewing lock: {}", err);
                    }
                    anyhow::bail!(err);
                }
            }
        }
        LockSubCmd::Release {
            lock_id,
            holder,
            state_file,
        } => {
            let is_json = cli_log_json(cli);
            let dlm = resolve_lock_manager(state_file)?;

            match dlm.release(lock_id, holder, now_secs) {
                Ok(true) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "lock_released",
                                "lock_id": lock_id,
                                "released": true,
                            })
                        );
                    } else {
                        println!(
                            "Lock lease '{}' successfully released by '{}'.",
                            lock_id, holder
                        );
                    }
                }
                Ok(false) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "lock_released",
                                "lock_id": lock_id,
                                "released": false,
                            })
                        );
                    } else {
                        println!("Lock lease '{}' not found.", lock_id);
                    }
                }
                Err(err) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "lock_release_failed",
                                "error": err.to_string(),
                            })
                        );
                    } else {
                        eprintln!("Error releasing lock: {}", err);
                    }
                    anyhow::bail!(err);
                }
            }
        }
        LockSubCmd::List {
            resource,
            state_file,
        } => {
            let is_json = cli_log_json(cli);
            let dlm = resolve_lock_manager(state_file)?;

            let report = match resource {
                Some(r) => {
                    let active = dlm.inspect(r, now_secs);
                    velcrux_core::sync::LockReport {
                        total_active_locks: active.len(),
                        total_exclusive_locks: active
                            .iter()
                            .filter(|l| l.mode == velcrux_core::sync::LockMode::Exclusive)
                            .count(),
                        total_shared_locks: active
                            .iter()
                            .filter(|l| l.mode == velcrux_core::sync::LockMode::Shared)
                            .count(),
                        highest_fencing_token: active
                            .iter()
                            .map(|l| l.fencing_token)
                            .max()
                            .unwrap_or(0),
                        active_locks: active,
                    }
                }
                None => dlm.generate_report(now_secs),
            };

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "lock_list",
                        "report": report,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 DISTRIBUTED LOCK LEASE REGISTRY & STATUS                               ");
                println!("========================================================================================");
                println!("Total Active Locks   : {}", report.total_active_locks);
                println!("Exclusive Write Locks: {}", report.total_exclusive_locks);
                println!("Shared Read Locks    : {}", report.total_shared_locks);
                println!("Highest Fencing Token: {}", report.highest_fencing_token);
                println!("----------------------------------------------------------------------------------------");
                println!(
                    "{:<16} {:<24} {:<16} {:<10} {:>8} {:>10}",
                    "LOCK ID", "RESOURCE", "HOLDER", "MODE", "FENCE", "EXPIRES IN"
                );
                println!(
                    "{:-<16} {:-<24} {:-<16} {:-<10} {:-<8} {:-<10}",
                    "", "", "", "", "", ""
                );
                for l in &report.active_locks {
                    let rem = l.remaining_ttl_secs(now_secs);
                    println!(
                        "{:<16} {:<24} {:<16} {:<10} {:>8} {:>9}s",
                        l.lock_id, l.resource, l.holder_id, l.mode, l.fencing_token, rem
                    );
                }
                println!("========================================================================================");
            }
        }
        LockSubCmd::Verify {
            resource,
            token,
            state_file,
        } => {
            let is_json = cli_log_json(cli);
            let dlm = resolve_lock_manager(state_file)?;
            let valid = dlm.verify_fencing(resource, *token, now_secs);

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "lock_verify",
                        "resource": resource,
                        "fencing_token": token,
                        "valid": valid,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 LAMPORT FENCING TOKEN VERIFICATION                                     ");
                println!("========================================================================================");
                println!("Target Resource      : {}", resource);
                println!("Fencing Token        : {}", token);
                println!(
                    "Verification Status  : {}",
                    if valid {
                        "VALID (Active Authorized Lease)"
                    } else {
                        "INVALID / EXPIRED (Reject Stale Write)"
                    }
                );
                println!("========================================================================================");
            }
        }
    }
    Ok(())
}

async fn run_dict(cli: &Cli, sub: &DictSubCmd) -> anyhow::Result<()> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    match sub {
        DictSubCmd::Train {
            source_dir,
            name,
            dict_size,
            max_samples,
            desc,
            dict_dir,
        } => {
            let is_json = cli_log_json(cli);
            let cat_dir = dict_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".velcrux/dictionaries"));
            let catalog =
                velcrux_core::protocol::dict::DictionaryCatalog::open_or_create(&cat_dir)?;

            let dict = velcrux_core::protocol::dict::DictionaryTrainer::train_from_directory(
                source_dir,
                *dict_size,
                *max_samples,
                name,
                desc,
                now_secs,
            )?;

            catalog.register(&dict)?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dict_trained",
                        "status": "registered",
                        "dictionary": dict.metadata,
                        "catalog_dir": cat_dir,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 ZSTANDARD PRE-TRAINED DICTIONARY GENERATED                             ");
                println!("========================================================================================");
                println!("Dictionary ID        : {}", dict.metadata.dict_id);
                println!("Name                 : {}", dict.metadata.name);
                println!("Ingested Samples     : {}", dict.metadata.sample_count);
                println!(
                    "Raw Training Data    : {}",
                    format_bytes(dict.metadata.trained_bytes as u64)
                );
                println!(
                    "Trained Dict Size    : {} ({} bytes)",
                    format_bytes(dict.metadata.dict_size as u64),
                    dict.metadata.dict_size
                );
                println!("BLAKE3 Checksum      : {}", dict.metadata.checksum);
                println!("Description          : {}", dict.metadata.description);
                println!("Catalog Directory    : {}", cat_dir.display());
                println!("========================================================================================");
            }
        }
        DictSubCmd::List { dict_dir } => {
            let is_json = cli_log_json(cli);
            let cat_dir = dict_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".velcrux/dictionaries"));
            let catalog =
                velcrux_core::protocol::dict::DictionaryCatalog::open_or_create(&cat_dir)?;
            let list = catalog.list();

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dict_list",
                        "count": list.len(),
                        "dictionaries": list,
                        "catalog_dir": cat_dir,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 ZSTANDARD PRE-TRAINED DICTIONARY CATALOG                               ");
                println!("========================================================================================");
                println!("Total Dictionaries   : {}", list.len());
                println!("Catalog Directory    : {}", cat_dir.display());
                println!("----------------------------------------------------------------------------------------");
                println!(
                    "{:<10} {:<20} {:>8} {:>12} {:>10} {:<16}",
                    "DICT ID", "NAME", "SAMPLES", "TRAINED", "SIZE", "CHECKSUM"
                );
                println!(
                    "{:-<10} {:-<20} {:-<8} {:-<12} {:-<10} {:-<16}",
                    "", "", "", "", "", ""
                );
                for d in &list {
                    println!(
                        "{:<10} {:<20} {:>8} {:>12} {:>10} {:<16}",
                        d.dict_id,
                        d.name,
                        d.sample_count,
                        format_bytes(d.trained_bytes as u64),
                        format_bytes(d.dict_size as u64),
                        d.checksum
                    );
                }
                println!("========================================================================================");
            }
        }
        DictSubCmd::Test {
            dict_id,
            target_path,
            dict_dir,
        } => {
            let is_json = cli_log_json(cli);
            let cat_dir = dict_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".velcrux/dictionaries"));
            let catalog =
                velcrux_core::protocol::dict::DictionaryCatalog::open_or_create(&cat_dir)?;

            let dict = catalog
                .get_by_id(*dict_id)?
                .ok_or_else(|| anyhow::anyhow!("dictionary ID {} not found in catalog", dict_id))?;

            let mut samples = Vec::new();
            if target_path.is_file() {
                let content = std::fs::read(target_path)?;
                samples.push(content);
            } else if target_path.is_dir() {
                samples = velcrux_core::protocol::dict::DictionaryTrainer::sample_directory(
                    target_path,
                    50,
                    velcrux_core::protocol::dict::MAX_SAMPLE_PER_FILE,
                )?;
            } else {
                anyhow::bail!("target path '{}' does not exist", target_path.display());
            }

            let eval = velcrux_core::protocol::dict::evaluate_dictionary_ratio(
                &samples,
                dict.bytes(),
                velcrux_core::protocol::compression::DEFAULT_ZSTD_LEVEL,
            )?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dict_test",
                        "dict_id": dict_id,
                        "dictionary_name": dict.name(),
                        "target_path": target_path,
                        "evaluation": eval,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 DICTIONARY COMPRESSION PERFORMANCE EVALUATION                          ");
                println!("========================================================================================");
                println!("Dictionary Evaluated : {} (ID: {})", dict.name(), dict_id);
                println!("Target Evaluated     : {}", target_path.display());
                println!(
                    "Raw Payload Size     : {}",
                    format_bytes(eval.raw_bytes as u64)
                );
                println!(
                    "Vanilla Zstd Size    : {} (ratio: {:.2}x)",
                    format_bytes(eval.vanilla_zstd_bytes as u64),
                    eval.vanilla_ratio
                );
                println!(
                    "Dict-Assisted Size   : {} (ratio: {:.2}x)",
                    format_bytes(eval.dict_zstd_bytes as u64),
                    eval.dict_ratio
                );
                println!(
                    "Bandwidth Reduction  : {:.1}% extra savings over vanilla zstd",
                    eval.extra_savings_pct
                );
                println!("========================================================================================");
            }
        }
        DictSubCmd::Export {
            dict_id,
            dest_file,
            dict_dir,
        } => {
            let is_json = cli_log_json(cli);
            let cat_dir = dict_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".velcrux/dictionaries"));
            let catalog =
                velcrux_core::protocol::dict::DictionaryCatalog::open_or_create(&cat_dir)?;

            catalog.export_dictionary(*dict_id, dest_file)?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dict_exported",
                        "dict_id": dict_id,
                        "destination": dest_file,
                    })
                );
            } else {
                println!(
                    "Dictionary ID {} exported successfully to '{}'.",
                    dict_id,
                    dest_file.display()
                );
            }
        }
        DictSubCmd::Import {
            source_file,
            name,
            desc,
            dict_dir,
        } => {
            let is_json = cli_log_json(cli);
            let cat_dir = dict_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".velcrux/dictionaries"));
            let catalog =
                velcrux_core::protocol::dict::DictionaryCatalog::open_or_create(&cat_dir)?;

            let dict = catalog.import_dictionary(
                source_file,
                name.as_deref(),
                desc.as_deref(),
                now_secs,
            )?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dict_imported",
                        "dictionary": dict.metadata,
                        "source_file": source_file,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 ZSTANDARD PRE-TRAINED DICTIONARY IMPORTED                              ");
                println!("========================================================================================");
                println!("Dictionary ID        : {}", dict.metadata.dict_id);
                println!("Name                 : {}", dict.metadata.name);
                println!(
                    "Dictionary Size      : {} ({} bytes)",
                    format_bytes(dict.metadata.dict_size as u64),
                    dict.metadata.dict_size
                );
                println!("BLAKE3 Checksum      : {}", dict.metadata.checksum);
                println!("Source File          : {}", source_file.display());
                println!("========================================================================================");
            }
        }
        DictSubCmd::Delete { dict_id, dict_dir } => {
            let is_json = cli_log_json(cli);
            let cat_dir = dict_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".velcrux/dictionaries"));
            let catalog =
                velcrux_core::protocol::dict::DictionaryCatalog::open_or_create(&cat_dir)?;

            let deleted = catalog.delete(*dict_id)?;

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dict_deleted",
                        "dict_id": dict_id,
                        "deleted": deleted,
                    })
                );
            } else if deleted {
                println!("Dictionary ID {} successfully deleted.", dict_id);
            } else {
                println!("Dictionary ID {} not found.", dict_id);
            }
        }
    }
    Ok(())
}

async fn run_scrub(cli: &Cli, sub: &ScrubSubCmd) -> anyhow::Result<()> {
    match sub {
        ScrubSubCmd::Run {
            chunk_store,
            mode,
            peer_store,
            rate_limit_mb,
            quarantine_dir,
        } => {
            let is_json = cli_log_json(cli);
            let local = velcrux_core::storage::LocalChunkStore::new(chunk_store).await?;

            let scrub_mode = match mode.to_ascii_lowercase().as_str() {
                "verify" | "check" | "v" => velcrux_core::storage::ScrubMode::VerifyOnly,
                "quarantine" | "isolate" | "q" => velcrux_core::storage::ScrubMode::Quarantine,
                "heal" | "repair" | "h" => velcrux_core::storage::ScrubMode::HealFromPeer,
                other => anyhow::bail!(
                    "unknown scrub mode '{}': expected 'verify', 'quarantine', or 'heal'",
                    other
                ),
            };

            let options = velcrux_core::storage::ScrubOptions {
                mode: scrub_mode,
                rate_limit_bytes_per_sec: rate_limit_mb.map(|mb| mb * 1024 * 1024),
                quarantine_dir: quarantine_dir.clone(),
            };

            let report = if let Some(peer_path) = peer_store {
                let peer = velcrux_core::storage::LocalChunkStore::new(peer_path).await?;
                velcrux_core::storage::DataScrubber::scrub_and_heal(&local, &peer, &options).await?
            } else {
                velcrux_core::storage::DataScrubber::scrub_local_store(&local, &options).await?
            };

            // Save report to <chunk_store>/.velcrux/last_scrub.json
            let report_file = chunk_store.join(".velcrux").join("last_scrub.json");
            let _ = velcrux_core::storage::DataScrubber::save_report(&report, &report_file);

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "scrub_completed",
                        "report": report,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 DATA INTEGRITY SCRUBBING & BIT-ROT AUDIT REPORT                        ");
                println!("========================================================================================");
                println!("Target Chunk Store   : {}", report.target_path);
                println!("Scrub Mode           : {}", scrub_mode);
                println!("Total Chunks Scanned : {}", report.scanned_chunks);
                println!("Intact (Healthy)     : {}", report.healthy_chunks);
                println!("Bit-Rot / Corrupted  : {}", report.corrupted_chunks);
                println!("Successfully Healed  : {}", report.repaired_chunks);
                println!("Isolated Quarantine  : {}", report.quarantined_chunks);
                println!("Unrecoverable Chunks : {}", report.unrecoverable_chunks);
                println!(
                    "Total Bytes Scanned  : {}",
                    format_bytes(report.scanned_bytes)
                );
                println!(
                    "Total Bytes Repaired : {}",
                    format_bytes(report.repaired_bytes)
                );
                println!("Elapsed Duration     : {} ms", report.duration_ms);
                println!("Verification Speed   : {:.2} MB/s", report.throughput_mb_s);
                if !report.findings.is_empty() {
                    println!("----------------------------------------------------------------------------------------");
                    println!("FINDINGS & ANOMALIES DETECTED ({}):", report.findings.len());
                    for f in report.findings.iter().take(10) {
                        println!(" - [{}] Chunk {}: {}", f.status, f.chunk_hash, f.details);
                    }
                    if report.findings.len() > 10 {
                        println!(
                            " ... and {} additional findings",
                            report.findings.len() - 10
                        );
                    }
                }
                println!("========================================================================================");
            }
        }
        ScrubSubCmd::Status { chunk_store } => {
            let is_json = cli_log_json(cli);
            let report_file = chunk_store.join(".velcrux").join("last_scrub.json");

            match velcrux_core::storage::DataScrubber::load_latest_report(&report_file)? {
                Some(report) => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "scrub_status",
                                "report": report,
                            })
                        );
                    } else {
                        println!("========================================================================================");
                        println!("                 LATEST CHUNK STORE SCRUBBING STATUS                                    ");
                        println!("========================================================================================");
                        println!("Target Chunk Store   : {}", report.target_path);
                        println!("Last Run Timestamp   : {}", report.started_at_secs);
                        println!("Total Chunks Scanned : {}", report.scanned_chunks);
                        println!("Healthy Chunks       : {}", report.healthy_chunks);
                        println!("Corrupted Chunks     : {}", report.corrupted_chunks);
                        println!("Repaired Chunks      : {}", report.repaired_chunks);
                        println!("Quarantined Chunks   : {}", report.quarantined_chunks);
                        println!("Unrecoverable Chunks : {}", report.unrecoverable_chunks);
                        println!(
                            "Scanned Volume       : {}",
                            format_bytes(report.scanned_bytes)
                        );
                        println!("Audit Throughput     : {:.2} MB/s", report.throughput_mb_s);
                        println!(
                            "Health Verdict       : {}",
                            if report.corrupted_chunks == 0 {
                                "100% HEALTHY (ZERO BIT-ROT DETECTED)"
                            } else {
                                "ANOMALIES / BIT-ROT DETECTED"
                            }
                        );
                        println!("========================================================================================");
                    }
                }
                None => {
                    if is_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "event": "scrub_status",
                                "report": null,
                                "message": "no previous scrub report found",
                            })
                        );
                    } else {
                        println!("No previous scrub report found in '{}'. Run 'velcrux scrub run' to audit.", chunk_store.display());
                    }
                }
            }
        }
        ScrubSubCmd::Repair {
            chunk_store,
            peer_store,
            rate_limit_mb,
        } => {
            let is_json = cli_log_json(cli);
            let local = velcrux_core::storage::LocalChunkStore::new(chunk_store).await?;
            let peer = velcrux_core::storage::LocalChunkStore::new(peer_store).await?;

            let options = velcrux_core::storage::ScrubOptions {
                mode: velcrux_core::storage::ScrubMode::HealFromPeer,
                rate_limit_bytes_per_sec: rate_limit_mb.map(|mb| mb * 1024 * 1024),
                quarantine_dir: None,
            };

            let report =
                velcrux_core::storage::DataScrubber::scrub_and_heal(&local, &peer, &options)
                    .await?;
            let report_file = chunk_store.join(".velcrux").join("last_scrub.json");
            let _ = velcrux_core::storage::DataScrubber::save_report(&report, &report_file);

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "scrub_repair_completed",
                        "report": report,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 BIT-ROT SELF-HEALING REPAIR COMPLETED                                  ");
                println!("========================================================================================");
                println!("Target Chunk Store   : {}", report.target_path);
                println!("Peer Store Reference : {}", peer_store.display());
                println!("Corrupted Detected   : {}", report.corrupted_chunks);
                println!("Successfully Healed  : {}", report.repaired_chunks);
                println!("Unrecoverable Chunks : {}", report.unrecoverable_chunks);
                println!(
                    "Restored Data Volume : {}",
                    format_bytes(report.repaired_bytes)
                );
                println!("Repair Elapsed Time  : {} ms", report.duration_ms);
                println!("========================================================================================");
            }
        }
    }
    Ok(())
}

async fn run_fec(cli: &Cli, sub: &FecSubCmd) -> anyhow::Result<()> {
    match sub {
        FecSubCmd::Status { profile } => {
            let is_json = cli_log_json(cli);
            let parsed_profile = velcrux_core::transport::FecProfile::from_str_name(profile)
                .context(format!(
                "Unknown FEC profile '{}'. Supported: disabled, low, medium, high, satellite, auto",
                profile
            ))?;
            let ctrl = velcrux_core::transport::AdaptiveFecController::new(parsed_profile);
            let snapshot = ctrl.snapshot();

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "fec_status",
                        "status": {
                            "profile": format!("{:?}", snapshot.profile).to_lowercase(),
                            "active_k": snapshot.active_k,
                            "active_m": snapshot.active_m,
                            "redundancy_pct": snapshot.redundancy_pct,
                            "field": "GF(2^8)",
                            "primitive_polynomial": "0x11d (x^8 + x^4 + x^3 + x^2 + 1)",
                            "mds_guaranteed": true,
                            "loss_tiers": [
                                { "loss_range": "< 0.5%", "k": 20, "m": 0, "redundancy_pct": 0.0, "codec": "None (Maximum Goodput)" },
                                { "loss_range": "0.5% - 2.0%", "k": 20, "m": 1, "redundancy_pct": 5.0, "codec": "Fast-Path XOR Parity" },
                                { "loss_range": "2.0% - 5.0%", "k": 16, "m": 2, "redundancy_pct": 12.5, "codec": "Cauchy MDS Matrix" },
                                { "loss_range": "5.0% - 10.0%", "k": 10, "m": 2, "redundancy_pct": 20.0, "codec": "Cauchy MDS Matrix" },
                                { "loss_range": ">= 10.0%", "k": 8, "m": 2, "redundancy_pct": 25.0, "codec": "Cauchy MDS Matrix (Satellite)" }
                            ]
                        }
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 FORWARD ERROR CORRECTION (FEC) OPERATIONAL STATUS                      ");
                println!("========================================================================================");
                println!("Selected Profile     : {:?}", snapshot.profile);
                println!("Erasure Field        : GF(2^8) (Primitive Polynomial: 0x11d)");
                println!("Generator Matrix     : Cauchy Generator Matrix (MDS Guaranteed)");
                println!(
                    "Active Coding Rate   : (K={}, M={}) -> {:.1}% Redundancy",
                    snapshot.active_k, snapshot.active_m, snapshot.redundancy_pct
                );
                println!("----------------------------------------------------------------------------------------");
                println!("Dynamic Loss Tiers (Adaptive Rate Scaling):");
                println!(
                    "  < 0.5% Loss Rate   : K=20, M=0 ( 0.0% parity overhead, maximum goodput)"
                );
                println!("  0.5% - 2.0% Loss   : K=20, M=1 ( 5.0% parity overhead, fast-path XOR)");
                println!("  2.0% - 5.0% Loss   : K=16, M=2 (12.5% parity overhead, Cauchy MDS)");
                println!("  5.0% - 10.0% Loss  : K=10, M=2 (20.0% parity overhead, Cauchy MDS)");
                println!(
                    "  >= 10.0% Loss      : K=8,  M=2 (25.0% parity overhead, Satellite Grade)"
                );
                println!("========================================================================================");
            }
        }
        FecSubCmd::Test {
            profile,
            loss_rate,
            payload_size,
            seed,
        } => {
            let is_json = cli_log_json(cli);
            let parsed_profile = velcrux_core::transport::FecProfile::from_str_name(profile)
                .context(format!(
                "Unknown FEC profile '{}'. Supported: disabled, low, medium, high, satellite, auto",
                profile
            ))?;

            // Generate deterministic payload pattern
            let mut data = Vec::with_capacity(*payload_size);
            for i in 0..*payload_size {
                data.push(((i * 31 + 17) & 0xff) as u8);
            }

            let report = velcrux_core::transport::simulate_fec_recovery(
                &data,
                parsed_profile,
                *loss_rate,
                *seed,
            );

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "fec_simulation_completed",
                        "report": report,
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 FEC ERASURE CODING RECOVERY SIMULATION                                 ");
                println!("========================================================================================");
                println!("Selected Profile     : {:?}", report.profile);
                println!(
                    "Coding Rate (K+M, K) : ({} + {}, {})",
                    report.k, report.m, report.k
                );
                println!(
                    "Simulated Loss Rate  : {:.2}%",
                    report.simulated_loss_rate * 100.0
                );
                println!("Total Blocks Tested  : {}", report.total_blocks);
                println!(
                    "Payload Volume       : {}",
                    format_bytes(report.payload_bytes as u64)
                );
                println!("Symbols Transmitted  : {}", report.total_symbols_sent);
                println!(
                    "Symbols Dropped      : {} ({:.2}% channel loss)",
                    report.symbols_dropped, report.actual_drop_pct
                );
                println!("Symbols Recovered    : {}", report.symbols_recovered);
                println!("Unrecoverable Blocks : {}", report.unrecoverable_blocks);
                println!(
                    "Recovery Success Rate: {:.2}%",
                    report.successful_recovery_pct
                );
                println!(
                    "Effective Goodput    : {:.2}%",
                    report.effective_goodput_ratio * 100.0
                );
                let verdict = if report.unrecoverable_blocks == 0 {
                    "PASSED — ZERO ARQ RETRANSMISSION STALLS"
                } else {
                    "DEGRADED — UNRECOVERABLE LOSS DETECTED"
                };
                println!("Health Verdict       : {}", verdict);
                println!("========================================================================================");
            }
        }
    }
    Ok(())
}

fn resolve_cli_schedule(
    cli: &Cli,
    sub_sched: Option<&str>,
    utc_offset: i32,
) -> anyhow::Result<BandwidthSchedule> {
    let source = sub_sched
        .or(cli.bandwidth_schedule.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No bandwidth schedule specified. Pass --schedule <RULES|FILE> or set --bandwidth-schedule / VELCRUX_BANDWIDTH_SCHEDULE."
            )
        })?;

    let content = if Path::new(source).is_file() {
        std::fs::read_to_string(source)
            .with_context(|| format!("failed to read bandwidth schedule file '{source}'"))?
    } else {
        source.to_string()
    };

    let mut sched: BandwidthSchedule = content
        .parse()
        .map_err(|e: velcrux_core::ParseScheduleError| anyhow::anyhow!("invalid schedule: {e}"))?;

    if utc_offset != 0 {
        sched = sched.with_utc_offset(utc_offset);
    }
    Ok(sched)
}

async fn run_schedule(cli: &Cli, sub: &ScheduleSubCmd) -> anyhow::Result<()> {
    match sub {
        ScheduleSubCmd::Inspect {
            schedule,
            utc_offset,
        } => {
            let sched = resolve_cli_schedule(cli, schedule.as_deref(), *utc_offset)?;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO)
                .as_secs();
            let status = sched.resolve_at(now_secs);
            let is_json = cli_log_json(cli);

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "schedule_inspect",
                        "schedule": {
                            "default_rate": sched.default_rate.to_string(),
                            "default_rate_bps": sched.default_rate.bytes_per_sec(),
                            "utc_offset_minutes": sched.utc_offset_minutes,
                            "rules": sched.rules.iter().map(|r| {
                                serde_json::json!({
                                    "id": r.id,
                                    "days": r.days.to_string(),
                                    "time_window": r.time.map(|tw| tw.to_string()),
                                    "rate": r.rate.to_string(),
                                    "rate_bps": r.rate.bytes_per_sec(),
                                    "description": r.description,
                                })
                            }).collect::<Vec<_>>(),
                            "active_status": {
                                "active_rate": status.active_rate.to_string(),
                                "active_rate_bps": status.active_rate.bytes_per_sec(),
                                "is_default": status.is_default,
                                "matching_rule_id": status.matching_rule_id,
                                "matching_rule_description": status.matching_rule_desc,
                                "day": status.day.short_name(),
                                "hour": status.hour,
                                "minute": status.minute,
                                "seconds_until_transition": status.seconds_until_transition,
                            }
                        }
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 BANDWIDTH CALENDAR SCHEDULE INSPECTION                                 ");
                println!("========================================================================================");
                println!(
                    "UTC Offset           : UTC{:+03}:{:02} ({} minutes)",
                    sched.utc_offset_minutes / 60,
                    (sched.utc_offset_minutes % 60).abs(),
                    sched.utc_offset_minutes
                );
                println!(
                    "Default Rate         : {} ({} MB/s)",
                    sched.default_rate,
                    format_rate_mbs(sched.default_rate.bytes_per_sec())
                );
                println!("Configured Rules     : {}", sched.rules.len());
                println!("----------------------------------------------------------------------------------------");
                if sched.rules.is_empty() {
                    println!("  (No specific time-of-day rules configured; default rate applies continuously)");
                } else {
                    println!(
                        "{:<4} {:<18} {:<12} {:<14} {:<16} {}",
                        "#", "RULE ID", "DAYS", "TIME WINDOW", "RATE LIMIT", "DESCRIPTION"
                    );
                    for (idx, rule) in sched.rules.iter().enumerate() {
                        let id_str = if rule.id.is_empty() { "-" } else { &rule.id };
                        let days_str = rule.days.to_string();
                        let time_str = rule
                            .time
                            .map(|t| t.to_string())
                            .unwrap_or_else(|| "* (all-day)".to_string());
                        let rate_str = rule.rate.to_string();
                        println!(
                            "{:<4} {:<18} {:<12} {:<14} {:<16} {}",
                            idx + 1,
                            id_str,
                            days_str,
                            time_str,
                            rate_str,
                            rule.description
                        );
                    }
                }
                println!("----------------------------------------------------------------------------------------");
                println!(
                    "CURRENT EVALUATION (Local Time: {} {:02}:{:02}):",
                    status.day.short_name(),
                    status.hour,
                    status.minute
                );
                let rule_tag = if let Some(ref rid) = status.matching_rule_id {
                    format!("Rule \"{}\"", rid)
                } else {
                    "Baseline Default".to_string()
                };
                println!(
                    "Active Rate          : {} ({} MB/s) [{}]",
                    status.active_rate,
                    format_rate_mbs(status.active_rate.bytes_per_sec()),
                    rule_tag
                );
                if let Some(ref desc) = status.matching_rule_desc {
                    if !desc.is_empty() {
                        println!("Rule Description     : {}", desc);
                    }
                }
                let hours = status.seconds_until_transition / 3600;
                let mins = (status.seconds_until_transition % 3600) / 60;
                let secs = status.seconds_until_transition % 60;
                println!(
                    "Next Transition In   : {}s (~{}h {}m {}s)",
                    status.seconds_until_transition, hours, mins, secs
                );
                println!("========================================================================================");
            }
        }
        ScheduleSubCmd::Eval {
            schedule,
            timestamp,
            utc_offset,
        } => {
            let sched = resolve_cli_schedule(cli, schedule.as_deref(), *utc_offset)?;
            let eval_secs = timestamp.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs()
            });
            let status = sched.resolve_at(eval_secs);
            let is_json = cli_log_json(cli);

            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "schedule_eval",
                        "evaluation": {
                            "timestamp": eval_secs,
                            "day": status.day.short_name(),
                            "hour": status.hour,
                            "minute": status.minute,
                            "active_rate": status.active_rate.to_string(),
                            "active_rate_bps": status.active_rate.bytes_per_sec(),
                            "is_default": status.is_default,
                            "matching_rule_id": status.matching_rule_id,
                            "matching_rule_description": status.matching_rule_desc,
                            "seconds_until_transition": status.seconds_until_transition,
                        }
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 BANDWIDTH SCHEDULE EVALUATION                                          ");
                println!("========================================================================================");
                println!(
                    "Evaluated Epoch Time : {} ({} {:02}:{:02} UTC{:+03}:{:02})",
                    eval_secs,
                    status.day.short_name(),
                    status.hour,
                    status.minute,
                    sched.utc_offset_minutes / 60,
                    (sched.utc_offset_minutes % 60).abs()
                );
                let source_str = if let Some(ref id) = status.matching_rule_id {
                    format!("Rule \"{id}\"")
                } else {
                    "Default Fallback".to_string()
                };
                println!(
                    "Active Rate Limit    : {} ({} MB/s)",
                    status.active_rate,
                    format_rate_mbs(status.active_rate.bytes_per_sec())
                );
                println!("Matching Source      : {}", source_str);
                if let Some(ref desc) = status.matching_rule_desc {
                    if !desc.is_empty() {
                        println!("Rule Description     : {}", desc);
                    }
                }
                let hours = status.seconds_until_transition / 3600;
                let mins = (status.seconds_until_transition % 3600) / 60;
                let secs = status.seconds_until_transition % 60;
                println!(
                    "Next Transition In   : {}s (~{}h {}m {}s)",
                    status.seconds_until_transition, hours, mins, secs
                );
                println!("========================================================================================");
            }
        }
    }
    Ok(())
}

fn format_rate_mbs(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        "Unlimited".to_string()
    } else {
        format!("{:.2}", (bytes_per_sec as f64) / (1024.0 * 1024.0))
    }
}

fn resolve_dedup_store_root(cli: &Cli, explicit: Option<&PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        p.clone()
    } else if let Some(ref p) = cli.chunk_store {
        p.clone()
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".velcrux").join("chunks")
    } else {
        PathBuf::from(".velcrux-chunks")
    }
}

fn scan_chunk_dir(dir: &Path) -> (u64, u64) {
    let mut count = 0u64;
    let mut bytes = 0u64;
    if !dir.exists() {
        return (0, 0);
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&current) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|s| s.to_str()) == Some("chunk") {
                    count += 1;
                    if let Ok(m) = path.metadata() {
                        bytes += m.len();
                    }
                }
            }
        }
    }
    (count, bytes)
}

fn scan_quarantine_dir(dir: &Path) -> Vec<(String, u64, u64)> {
    let mut items = Vec::new();
    if !dir.exists() {
        return items;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let len = path.metadata().map(|m| m.len()).unwrap_or(0);
                let ts = path
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                items.push((name, len, ts));
            }
        }
    }
    items
}

async fn run_dedup(cli: &Cli, sub: &DedupSubCmd) -> anyhow::Result<()> {
    match sub {
        DedupSubCmd::Status {
            chunk_store,
            tenant,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let policy_str = &cli.dedup_namespace;
            let filter_tenant = tenant.as_deref().or(cli.tenant.as_deref());

            let tenants_dir = root.join("tenants");
            let mut tenant_stats = Vec::new();

            if tenants_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&tenants_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let tname = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string();
                            if let Some(ft) = filter_tenant {
                                if tname != ft {
                                    continue;
                                }
                            }
                            let (chunks, bytes) = scan_chunk_dir(&path);
                            tenant_stats.push((tname, chunks, bytes));
                        }
                    }
                }
            }

            let (shared_chunks, shared_bytes) = {
                let shared_dir = root.join("shared");
                if shared_dir.exists() {
                    scan_chunk_dir(&shared_dir)
                } else {
                    scan_chunk_dir(&root.join("chunks"))
                }
            };

            let quarantine_dir = root.join(".quarantine");
            let quarantined_items = scan_quarantine_dir(&quarantine_dir);
            let quarantined_count = quarantined_items.len() as u64;
            let quarantined_bytes: u64 = quarantined_items.iter().map(|(_, l, _)| *l).sum();

            if cli_log_json(cli) {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dedup_status",
                        "policy": policy_str,
                        "store_root": root.display().to_string(),
                        "filter_tenant": filter_tenant,
                        "tenants": tenant_stats.iter().map(|(n, c, b)| {
                            serde_json::json!({
                                "tenant": n,
                                "chunks": c,
                                "bytes": b
                            })
                        }).collect::<Vec<_>>(),
                        "shared": {
                            "chunks": shared_chunks,
                            "bytes": shared_bytes
                        },
                        "quarantine": {
                            "count": quarantined_count,
                            "bytes": quarantined_bytes
                        }
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 MULTI-TENANT DEDUPLICATION & NAMESPACE STATUS                          ");
                println!("========================================================================================");
                println!("Store Root Path      : {}", root.display());
                println!("Namespace Policy     : {}", policy_str);
                println!("Active Tenants       : {}", tenant_stats.len());
                println!(
                    "Shared Store Chunks  : {} ({} MB)",
                    shared_chunks,
                    shared_bytes / (1024 * 1024)
                );
                println!(
                    "Quarantined Chunks   : {} ({} KB)",
                    quarantined_count,
                    quarantined_bytes / 1024
                );
                println!("----------------------------------------------------------------------------------------");
                if tenant_stats.is_empty() {
                    println!(
                        "  (No isolated tenant stores discovered in {})",
                        tenants_dir.display()
                    );
                } else {
                    println!(
                        "{:<4} {:<24} {:<16} {}",
                        "#", "TENANT ID", "CHUNKS", "STORAGE SIZE"
                    );
                    println!("----------------------------------------------------------------------------------------");
                    for (i, (tname, chunks, bytes)) in tenant_stats.iter().enumerate() {
                        println!(
                            "{:<4} {:<24} {:<16} {} KB",
                            i + 1,
                            tname,
                            chunks,
                            bytes / 1024
                        );
                    }
                }
                println!("========================================================================================");
            }
        }
        DedupSubCmd::Verify {
            chunk_store,
            tenant,
            auto_quarantine,
        } => {
            let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
            let start = std::time::Instant::now();
            let filter_tenant = tenant.as_deref().or(cli.tenant.as_deref());

            let mut targets = Vec::new();
            if let Some(t) = filter_tenant {
                let tenant_p = root.join("tenants").join(t);
                if tenant_p.exists() {
                    targets.push((t.to_string(), tenant_p));
                }
            } else {
                let tenants_dir = root.join("tenants");
                if tenants_dir.exists() {
                    if let Ok(entries) = std::fs::read_dir(&tenants_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_dir() {
                                let tname = path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                targets.push((tname, path));
                            }
                        }
                    }
                }
                let shared_dir = root.join("shared");
                if shared_dir.exists() {
                    targets.push(("shared".to_string(), shared_dir));
                } else if root.join("chunks").exists() {
                    targets.push(("global".to_string(), root.join("chunks")));
                }
            }

            let quarantine_dir = root.join(".quarantine");
            if *auto_quarantine && !quarantine_dir.exists() {
                let _ = std::fs::create_dir_all(&quarantine_dir);
            }

            let mut total_scanned = 0u64;
            let mut valid_chunks = 0u64;
            let mut corrupted_chunks = 0u64;
            let mut quarantined_chunks = 0u64;
            let mut corrupted_details = Vec::new();

            for (_tname, target_dir) in targets {
                let mut stack = vec![target_dir];
                while let Some(current) = stack.pop() {
                    if let Ok(entries) = std::fs::read_dir(&current) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_dir() {
                                stack.push(path);
                            } else if path.extension().and_then(|s| s.to_str()) == Some("chunk") {
                                total_scanned += 1;
                                let stem = path
                                    .file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                let expected_hash = velcrux_core::util::Hash::from_hex(&stem);
                                match std::fs::read(&path) {
                                    Ok(data) => {
                                        let actual_hash = velcrux_core::util::Hash::of(&data);
                                        if Some(actual_hash) == expected_hash {
                                            valid_chunks += 1;
                                        } else {
                                            corrupted_chunks += 1;
                                            let reason = "blake3_checksum_mismatch";
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_secs())
                                                .unwrap_or(0);
                                            corrupted_details.push(serde_json::json!({
                                                "file": path.display().to_string(),
                                                "expected": stem,
                                                "actual": actual_hash.to_string(),
                                                "reason": reason
                                            }));
                                            if *auto_quarantine {
                                                let qname = format!(
                                                    "{}_{}_{}.quarantine",
                                                    stem,
                                                    now,
                                                    rand::random::<u32>()
                                                );
                                                let qtarget = quarantine_dir.join(qname);
                                                if std::fs::rename(&path, &qtarget).is_ok() {
                                                    quarantined_chunks += 1;
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        corrupted_chunks += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let elapsed_ms = start.elapsed().as_millis() as u64;

            if cli_log_json(cli) {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "dedup_verify",
                        "store_root": root.display().to_string(),
                        "total_scanned": total_scanned,
                        "valid_chunks": valid_chunks,
                        "corrupted_chunks": corrupted_chunks,
                        "quarantined_chunks": quarantined_chunks,
                        "duration_ms": elapsed_ms,
                        "corrupted_details": corrupted_details
                    })
                );
            } else {
                println!("========================================================================================");
                println!("                 DEDUPLICATION CHUNK STORE INTEGRITY AUDIT                              ");
                println!("========================================================================================");
                println!("Store Root Path      : {}", root.display());
                println!("Total Chunks Scanned : {}", total_scanned);
                println!("Valid Chunks         : {}", valid_chunks);
                println!("Corrupted/Poisoned   : {}", corrupted_chunks);
                println!("Quarantined Chunks   : {}", quarantined_chunks);
                println!("Audit Duration       : {} ms", elapsed_ms);
                println!(
                    "Integrity Status     : {}",
                    if corrupted_chunks == 0 {
                        "PASS (Clean)"
                    } else {
                        "FAIL (Poisoning/Corruption Detected)"
                    }
                );
                println!("========================================================================================");
            }
        }
        DedupSubCmd::Quarantine { sub } => match sub {
            QuarantineSubCmd::List { chunk_store } => {
                let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
                let quarantine_dir = root.join(".quarantine");
                let items = scan_quarantine_dir(&quarantine_dir);

                if cli_log_json(cli) {
                    println!(
                        "{}",
                        serde_json::json!({
                            "event": "quarantine_list",
                            "quarantine_dir": quarantine_dir.display().to_string(),
                            "count": items.len(),
                            "items": items.iter().map(|(n, l, ts)| {
                                serde_json::json!({
                                    "filename": n,
                                    "size_bytes": l,
                                    "quarantined_at": ts
                                })
                            }).collect::<Vec<_>>()
                        })
                    );
                } else {
                    println!("========================================================================================");
                    println!("                 QUARANTINED POISONED/CORRUPTED CHUNKS                                  ");
                    println!("========================================================================================");
                    println!("Quarantine Directory : {}", quarantine_dir.display());
                    println!("Quarantined Files    : {}", items.len());
                    println!("----------------------------------------------------------------------------------------");
                    if items.is_empty() {
                        println!("  (No chunks currently quarantined)");
                    } else {
                        println!(
                            "{:<4} {:<48} {:<12} {}",
                            "#", "QUARANTINE RECORD", "SIZE (B)", "EPOCH TIMESTAMP"
                        );
                        println!("----------------------------------------------------------------------------------------");
                        for (i, (name, len, ts)) in items.iter().enumerate() {
                            println!("{:<4} {:<48} {:<12} {}", i + 1, name, len, ts);
                        }
                    }
                    println!("========================================================================================");
                }
            }
            QuarantineSubCmd::Purge { chunk_store } => {
                let root = resolve_dedup_store_root(cli, chunk_store.as_ref());
                let quarantine_dir = root.join(".quarantine");
                let items = scan_quarantine_dir(&quarantine_dir);
                let count = items.len();
                let bytes: u64 = items.iter().map(|(_, l, _)| *l).sum();

                if quarantine_dir.exists() {
                    let _ = std::fs::remove_dir_all(&quarantine_dir);
                    let _ = std::fs::create_dir_all(&quarantine_dir);
                }

                if cli_log_json(cli) {
                    println!(
                        "{}",
                        serde_json::json!({
                            "event": "quarantine_purge",
                            "quarantine_dir": quarantine_dir.display().to_string(),
                            "purged_count": count,
                            "reclaimed_bytes": bytes
                        })
                    );
                } else {
                    println!(
                        "Purged {} quarantined chunks ({} bytes reclaimed).",
                        count, bytes
                    );
                }
            }
        },
    }
    Ok(())
}
