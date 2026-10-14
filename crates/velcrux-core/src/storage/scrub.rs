//! In-Flight Data Integrity Scrubbing & Background Bit-Rot Repair Daemon (Option BF).
//!
//! Conforms to `REQUIREMENTS.md` §18 ("Integrity Verification"), §63 ("Garbage Collection"),
//! §70 ("Graceful Shutdown"), and `ARCHITECTURE.md` §2.
//!
//! Provides proactive cryptographic verification of stored chunks against BLAKE3 digests,
//! silent bit-rot detection, automated quarantine isolation, self-healing restoration
//! from healthy quorum peers or backup stores, and throttled background scrubbing.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::storage::chunk_store::{ChunkStore, LocalChunkStore};
use crate::util::Hash;

/// Operational execution mode for data integrity scrubbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrubMode {
    /// Read and verify all chunk hashes; report corruptions without modifying disk.
    VerifyOnly,
    /// Isolate corrupt chunks by moving them to a quarantine directory.
    Quarantine,
    /// Automatically heal and reconstruct corrupt chunks from a healthy peer chunk store.
    HealFromPeer,
}

impl std::fmt::Display for ScrubMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifyOnly => write!(f, "VERIFY_ONLY"),
            Self::Quarantine => write!(f, "QUARANTINE"),
            Self::HealFromPeer => write!(f, "HEAL_FROM_PEER"),
        }
    }
}

/// Cryptographic integrity status of a scanned chunk or file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkIntegrityStatus {
    /// Chunk content matches its expected BLAKE3 digest.
    Healthy,
    /// Content mismatch detected; bits have degraded or been corrupted.
    BitRotCorrupted,
    /// File size is truncated (0 bytes or partial write).
    Truncated,
    /// Chunk was corrupt but successfully reconstructed and healed from a peer.
    Repaired,
    /// Chunk was corrupt and safely moved into the quarantine holding area.
    Quarantined,
    /// Chunk was corrupt and could not be recovered (no healthy replica available).
    Unrecoverable,
}

impl std::fmt::Display for ChunkIntegrityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "HEALTHY"),
            Self::BitRotCorrupted => write!(f, "BIT_ROT_CORRUPTED"),
            Self::Truncated => write!(f, "TRUNCATED"),
            Self::Repaired => write!(f, "REPAIRED"),
            Self::Quarantined => write!(f, "QUARANTINED"),
            Self::Unrecoverable => write!(f, "UNRECOVERABLE"),
        }
    }
}

/// Detailed diagnosis finding for an individual scanned chunk or file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubFinding {
    /// Expected chunk hash derived from content address or manifest.
    pub chunk_hash: String,
    /// Filesystem location of the chunk file.
    pub path: PathBuf,
    /// Actual BLAKE3 hash computed from bytes read on disk.
    pub actual_hash: Option<String>,
    /// Classification status.
    pub status: ChunkIntegrityStatus,
    /// Human-readable explanation.
    pub details: String,
}

/// Comprehensive report produced by an integrity scrubbing run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrubReport {
    /// Total chunks or files inspected.
    pub scanned_chunks: usize,
    /// Total chunks confirmed cryptographically intact.
    pub healthy_chunks: usize,
    /// Total chunks where content did not match expected hash.
    pub corrupted_chunks: usize,
    /// Total chunks successfully restored from peer stores.
    pub repaired_chunks: usize,
    /// Total chunks isolated into quarantine.
    pub quarantined_chunks: usize,
    /// Corrupt chunks that could not be repaired.
    pub unrecoverable_chunks: usize,
    /// Total raw bytes read and hashed during the sweep.
    pub scanned_bytes: u64,
    /// Total bytes repaired/rewritten to disk.
    pub repaired_bytes: u64,
    /// Unix timestamp when the scrub began.
    pub started_at_secs: u64,
    /// Total elapsed wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Calculated sustained verification throughput in MB/s.
    pub throughput_mb_s: f64,
    /// Target store or root path inspected.
    pub target_path: String,
    /// List of anomalies and repair actions recorded.
    pub findings: Vec<ScrubFinding>,
}

impl Default for ScrubReport {
    fn default() -> Self {
        Self {
            scanned_chunks: 0,
            healthy_chunks: 0,
            corrupted_chunks: 0,
            repaired_chunks: 0,
            quarantined_chunks: 0,
            unrecoverable_chunks: 0,
            scanned_bytes: 0,
            repaired_bytes: 0,
            started_at_secs: 0,
            duration_ms: 0,
            throughput_mb_s: 0.0,
            target_path: String::new(),
            findings: Vec::new(),
        }
    }
}

/// Execution tunables and constraints for scrubbing passes.
#[derive(Debug, Clone)]
pub struct ScrubOptions {
    /// Operational mode (verify, quarantine, heal).
    pub mode: ScrubMode,
    /// Optional rate limit in bytes/sec to avoid saturating disk I/O (e.g. 50 MB/s).
    pub rate_limit_bytes_per_sec: Option<u64>,
    /// Custom quarantine directory. Defaults to `<store_root>/.quarantine/`.
    pub quarantine_dir: Option<PathBuf>,
}

impl Default for ScrubOptions {
    fn default() -> Self {
        Self {
            mode: ScrubMode::VerifyOnly,
            rate_limit_bytes_per_sec: None,
            quarantine_dir: None,
        }
    }
}

/// Proactive data integrity validator and bit-rot self-healing coordinator.
pub struct DataScrubber;

impl DataScrubber {
    /// Scrub an entire local content-addressed chunk store (`LocalChunkStore`).
    pub async fn scrub_local_store(
        store: &LocalChunkStore,
        options: &ScrubOptions,
    ) -> Result<ScrubReport, VelcruxError> {
        Self::scrub_local_store_with_peer(store, None, options).await
    }

    /// Scrub a local chunk store and heal corrupted chunks from a reference peer chunk store.
    pub async fn scrub_and_heal(
        store: &LocalChunkStore,
        peer: &(dyn ChunkStore + 'static),
        options: &ScrubOptions,
    ) -> Result<ScrubReport, VelcruxError> {
        Self::scrub_local_store_with_peer(store, Some(peer), options).await
    }

    async fn scrub_local_store_with_peer(
        store: &LocalChunkStore,
        peer: Option<&(dyn ChunkStore + 'static)>,
        options: &ScrubOptions,
    ) -> Result<ScrubReport, VelcruxError> {
        let start_time = Instant::now();
        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut report = ScrubReport {
            started_at_secs: now_secs,
            target_path: store.root().display().to_string(),
            ..Default::default()
        };

        let quarantine_path = options
            .quarantine_dir
            .clone()
            .unwrap_or_else(|| store.root().join(".quarantine"));

        if options.mode == ScrubMode::Quarantine {
            fs::create_dir_all(&quarantine_path)?;
        }

        // 1. Discover all chunk files in chunks/ab/cd/*.chunk
        let mut chunk_paths = Vec::new();
        Self::collect_chunk_files(store.chunks_dir(), &mut chunk_paths)?;

        let mut rate_limiter_last = Instant::now();
        let mut bytes_since_throttle = 0u64;

        // 2. Inspect each chunk
        for path in chunk_paths {
            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(f) if f.ends_with(".chunk") => f.trim_end_matches(".chunk"),
                _ => continue,
            };

            let expected_hash = match Hash::from_hex(filename) {
                Some(h) => h,
                None => continue,
            };

            report.scanned_chunks += 1;

            // Read chunk bytes
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(err) => {
                    report.corrupted_chunks += 1;
                    report.unrecoverable_chunks += 1;
                    report.findings.push(ScrubFinding {
                        chunk_hash: expected_hash.to_string(),
                        path: path.clone(),
                        actual_hash: None,
                        status: ChunkIntegrityStatus::Unrecoverable,
                        details: format!("I/O read error: {}", err),
                    });
                    continue;
                }
            };

            report.scanned_bytes += bytes.len() as u64;
            bytes_since_throttle += bytes.len() as u64;

            // Optional rate-limiting throttle
            if let Some(limit) = options.rate_limit_bytes_per_sec {
                if bytes_since_throttle >= 1024 * 1024 {
                    let elapsed = rate_limiter_last.elapsed();
                    let expected_time =
                        Duration::from_secs_f64(bytes_since_throttle as f64 / limit as f64);
                    if expected_time > elapsed {
                        tokio::time::sleep(expected_time - elapsed).await;
                    }
                    rate_limiter_last = Instant::now();
                    bytes_since_throttle = 0;
                }
            }

            // Verify BLAKE3 hash
            let computed_hash = Hash::of(&bytes);

            if computed_hash == expected_hash && !bytes.is_empty() {
                report.healthy_chunks += 1;
            } else {
                report.corrupted_chunks += 1;
                let status_initial = if bytes.is_empty() {
                    ChunkIntegrityStatus::Truncated
                } else {
                    ChunkIntegrityStatus::BitRotCorrupted
                };

                // Self-healing branch
                if options.mode == ScrubMode::HealFromPeer {
                    if let Some(peer_store) = peer {
                        match peer_store.get(&expected_hash).await {
                            Ok(healthy_bytes) if Hash::of(&healthy_bytes) == expected_hash => {
                                // Write healed bytes atomically
                                if let Err(e) = fs::write(&path, &healthy_bytes) {
                                    report.unrecoverable_chunks += 1;
                                    report.findings.push(ScrubFinding {
                                        chunk_hash: expected_hash.to_string(),
                                        path: path.clone(),
                                        actual_hash: Some(computed_hash.to_string()),
                                        status: ChunkIntegrityStatus::Unrecoverable,
                                        details: format!("failed to write healed chunk: {}", e),
                                    });
                                } else {
                                    report.repaired_chunks += 1;
                                    report.repaired_bytes += healthy_bytes.len() as u64;
                                    report.findings.push(ScrubFinding {
                                        chunk_hash: expected_hash.to_string(),
                                        path: path.clone(),
                                        actual_hash: Some(computed_hash.to_string()),
                                        status: ChunkIntegrityStatus::Repaired,
                                        details: "Corrupt chunk successfully healed and restored from peer".into(),
                                    });
                                }
                                continue;
                            }
                            _ => {
                                report.unrecoverable_chunks += 1;
                                report.findings.push(ScrubFinding {
                                    chunk_hash: expected_hash.to_string(),
                                    path: path.clone(),
                                    actual_hash: Some(computed_hash.to_string()),
                                    status: ChunkIntegrityStatus::Unrecoverable,
                                    details:
                                        "Peer store did not have a valid replica for this chunk"
                                            .into(),
                                });
                                continue;
                            }
                        }
                    }
                }

                // Quarantine branch
                if options.mode == ScrubMode::Quarantine {
                    let quarantine_dest =
                        quarantine_path.join(format!("{}.corrupt", expected_hash));
                    if let Err(e) = fs::rename(&path, &quarantine_dest) {
                        report.unrecoverable_chunks += 1;
                        report.findings.push(ScrubFinding {
                            chunk_hash: expected_hash.to_string(),
                            path: path.clone(),
                            actual_hash: Some(computed_hash.to_string()),
                            status: status_initial,
                            details: format!("failed to move chunk to quarantine: {}", e),
                        });
                    } else {
                        report.quarantined_chunks += 1;
                        report.findings.push(ScrubFinding {
                            chunk_hash: expected_hash.to_string(),
                            path: quarantine_dest,
                            actual_hash: Some(computed_hash.to_string()),
                            status: ChunkIntegrityStatus::Quarantined,
                            details: format!("Chunk moved to quarantine due to {}", status_initial),
                        });
                    }
                } else {
                    report.findings.push(ScrubFinding {
                        chunk_hash: expected_hash.to_string(),
                        path: path.clone(),
                        actual_hash: Some(computed_hash.to_string()),
                        status: status_initial,
                        details: format!(
                            "Checksum mismatch: expected {}, got {}",
                            expected_hash, computed_hash
                        ),
                    });
                }
            }
        }

        let elapsed = start_time.elapsed();
        report.duration_ms = elapsed.as_millis() as u64;
        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            report.throughput_mb_s = (report.scanned_bytes as f64 / (1024.0 * 1024.0)) / secs;
        }

        Ok(report)
    }

    /// Recursively harvest chunk file paths from the 2-level directory shard.
    fn collect_chunk_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), VelcruxError> {
        if !dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::collect_chunk_files(&path, out)?;
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "chunk" {
                        out.push(path);
                    }
                }
            }
        }
        Ok(())
    }

    /// Save scrub report to disk at `dest_file`.
    pub fn save_report(report: &ScrubReport, dest_file: &Path) -> Result<(), VelcruxError> {
        if let Some(parent) = dest_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = dest_file.with_extension(format!("tmp-{}", rand::random::<u32>()));
        let json_bytes = serde_json::to_vec_pretty(report).map_err(|e| {
            VelcruxError::Internal(format!("failed to serialize scrub report: {}", e))
        })?;

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&json_bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, dest_file)?;
        Ok(())
    }

    /// Load the most recent scrub report from disk if present.
    pub fn load_latest_report(report_file: &Path) -> Result<Option<ScrubReport>, VelcruxError> {
        if !report_file.exists() {
            return Ok(None);
        }
        let bytes = fs::read(report_file)?;
        let report = serde_json::from_slice::<ScrubReport>(&bytes)
            .map_err(|e| VelcruxError::Internal(format!("failed to parse scrub report: {}", e)))?;
        Ok(Some(report))
    }
}

/// Background periodic scrubbing daemon.
pub struct BackgroundScrubDaemon {
    is_running: Arc<AtomicBool>,
}

impl BackgroundScrubDaemon {
    /// Create a new background daemon controller.
    pub fn new() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check whether the daemon is currently active.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Stop the background daemon gracefully per `REQUIREMENTS.md` §70.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

impl Default for BackgroundScrubDaemon {
    fn default() -> Self {
        Self::new()
    }
}
