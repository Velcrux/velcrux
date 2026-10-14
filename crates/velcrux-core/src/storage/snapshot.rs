//! Point-in-time snapshot isolation, file version history, and time-travel restore engine (Option BC).
//!
//! Implements `REQUIREMENTS.md` §34 ("Atomicity"), §61 ("Transactional Synchronization"),
//! §63 ("Garbage Collection"), and §94 ("Deliverables").
//!
//! Provides zero-duplication directory snapshot creation backed by content-addressed
//! chunk storage (CAS), snapshot manifest difference analysis, atomic point-in-time
//! restoration, and garbage collection pinning for active snapshot references.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::storage::chunk_store::LocalChunkStore;
use crate::util::Hash;

/// Fixed default chunk size (64 KiB) for snapshot chunk indexing.
pub const SNAPSHOT_CHUNK_SIZE: usize = 64 * 1024;

/// Metadata for a single file captured in a point-in-time snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFileMeta {
    /// Relative path within the snapshot root.
    pub relative_path: String,
    /// Exact byte size.
    pub size: u64,
    /// BLAKE3 whole-file cryptographic hash.
    pub file_hash: Hash,
    /// Ordered list of content chunk hashes comprising the file.
    pub chunk_hashes: Vec<Hash>,
    /// Last modification timestamp in seconds since Unix epoch.
    pub modified_at_secs: u64,
    /// Whether file has executable POSIX permissions.
    pub is_executable: bool,
}

/// Point-in-time directory snapshot entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Unique snapshot identifier tag.
    pub tag: String,
    /// Timestamp when snapshot was recorded (Unix epoch seconds).
    pub created_at_secs: u64,
    /// Canonical source path where snapshot originated.
    pub root_path: String,
    /// Total number of regular files captured.
    pub file_count: usize,
    /// Cumulative byte size of all files in the snapshot.
    pub total_bytes: u64,
    /// Relative file path -> file metadata map.
    pub files: HashMap<String, SnapshotFileMeta>,
    /// Optional user or system annotations (e.g. commit hash, build ID).
    pub metadata: HashMap<String, String>,
}

/// Concise summary of a snapshot for fast catalog enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Unique snapshot tag.
    pub tag: String,
    /// Creation timestamp (seconds since Unix epoch).
    pub created_at_secs: u64,
    /// Source root directory.
    pub root_path: String,
    /// Total file count.
    pub file_count: usize,
    /// Total bytes.
    pub total_bytes: u64,
}

/// Structural difference report between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDiff {
    /// Baseline snapshot tag.
    pub tag_a: String,
    /// Comparison snapshot tag.
    pub tag_b: String,
    /// Files present in `tag_b` but absent in `tag_a`.
    pub added_files: Vec<String>,
    /// Files present in `tag_a` but deleted in `tag_b`.
    pub removed_files: Vec<String>,
    /// Files present in both snapshots whose cryptographic hash changed.
    pub modified_files: Vec<String>,
    /// Files identical in path, size, and hash across both snapshots.
    pub unchanged_files: usize,
    /// Net added bytes in `tag_b`.
    pub bytes_added: u64,
    /// Net removed bytes in `tag_b`.
    pub bytes_removed: u64,
}

/// Execution outcome report for snapshot restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRestoreReport {
    /// Restored snapshot tag.
    pub tag: String,
    /// Number of files successfully restored and verified.
    pub restored_files: usize,
    /// Total bytes written to destination.
    pub restored_bytes: u64,
    /// Destination directory path.
    pub destination: PathBuf,
}

/// Central snapshot management and point-in-time isolation coordinator.
#[derive(Clone)]
pub struct SnapshotManager {
    snapshot_dir: PathBuf,
    chunk_store: Option<Arc<LocalChunkStore>>,
}

impl SnapshotManager {
    /// Initialize a snapshot manager rooted at `snapshot_dir` with optional CAS integration.
    pub fn new(
        snapshot_dir: impl Into<PathBuf>,
        chunk_store: Option<Arc<LocalChunkStore>>,
    ) -> Result<Self, VelcruxError> {
        let snapshot_dir = snapshot_dir.into();
        fs::create_dir_all(&snapshot_dir)?;
        Ok(Self {
            snapshot_dir,
            chunk_store,
        })
    }

    /// Snapshot storage directory.
    pub fn snapshot_dir(&self) -> &Path {
        &self.snapshot_dir
    }

    /// Validate snapshot tag against directory traversal or invalid syntax.
    pub fn validate_tag(tag: &str) -> Result<(), VelcruxError> {
        if tag.is_empty() {
            return Err(VelcruxError::Config(
                "snapshot tag cannot be empty".to_string(),
            ));
        }
        if tag.contains('/') || tag.contains('\\') || tag.contains("..") {
            return Err(VelcruxError::Config(format!(
                "invalid snapshot tag '{}': must not contain path delimiters or '..'",
                tag
            )));
        }
        if !tag
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(VelcruxError::Config(format!(
                "invalid snapshot tag '{}': characters must be alphanumeric, '-', '_', or '.'",
                tag
            )));
        }
        Ok(())
    }

    fn snapshot_file_path(&self, tag: &str) -> PathBuf {
        self.snapshot_dir.join(format!("{}.json", tag))
    }

    /// Create an immutable point-in-time snapshot of the given `root_path`.
    pub fn create_snapshot(
        &self,
        tag: &str,
        root_path: &Path,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<SnapshotEntry, VelcruxError> {
        Self::validate_tag(tag)?;

        if !root_path.exists() {
            return Err(VelcruxError::Config(format!(
                "source directory '{}' does not exist",
                root_path.display()
            )));
        }

        let snap_file = self.snapshot_file_path(tag);
        if snap_file.exists() {
            return Err(VelcruxError::Config(format!(
                "snapshot '{}' already exists at {}",
                tag,
                snap_file.display()
            )));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut files = HashMap::new();
        let mut total_bytes = 0u64;

        // Collect all file paths recursively
        let mut file_paths = Vec::new();
        Self::collect_files(root_path, &mut file_paths)?;
        file_paths.sort();

        for abs_path in file_paths {
            let rel_path = match abs_path.strip_prefix(root_path) {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            // Read file content
            let mut f = File::open(&abs_path)?;
            let meta = f.metadata()?;
            let size = meta.len();
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(now_secs);

            #[cfg(unix)]
            let is_executable = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let is_executable = false;

            let mut content = Vec::with_capacity(size as usize);
            f.read_to_end(&mut content)?;

            let file_hash = Hash::of(&content);
            let mut chunk_hashes = Vec::new();

            // Chunk the file into 64 KiB segments
            if content.is_empty() {
                // Empty file has 0 chunks
            } else {
                for chunk in content.chunks(SNAPSHOT_CHUNK_SIZE) {
                    let chash = Hash::of(chunk);
                    chunk_hashes.push(chash);

                    // Persist to CAS if chunk store is active
                    if let Some(cs) = &self.chunk_store {
                        cs.put_sync(&chash, chunk)?;
                    }
                }
            }

            total_bytes += size;
            files.insert(
                rel_path.clone(),
                SnapshotFileMeta {
                    relative_path: rel_path,
                    size,
                    file_hash,
                    chunk_hashes,
                    modified_at_secs: modified,
                    is_executable,
                },
            );
        }

        let entry = SnapshotEntry {
            tag: tag.to_string(),
            created_at_secs: now_secs,
            root_path: root_path
                .canonicalize()
                .unwrap_or_else(|_| root_path.to_path_buf())
                .to_string_lossy()
                .to_string(),
            file_count: files.len(),
            total_bytes,
            files,
            metadata: annotations.unwrap_or_default(),
        };

        // Write snapshot atomically
        let temp_path =
            self.snapshot_dir
                .join(format!("{}.json.tmp-{}", tag, rand::random::<u64>()));
        let json_bytes = serde_json::to_vec_pretty(&entry)
            .map_err(|e| VelcruxError::Internal(format!("failed to serialize snapshot: {}", e)))?;

        {
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            tmp_file.write_all(&json_bytes)?;
            tmp_file.sync_all()?;
        }

        fs::rename(&temp_path, &snap_file)?;
        Ok(entry)
    }

    fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), VelcruxError> {
        if !dir.is_dir() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.starts_with('.')
                && (file_name.ends_with(".tmp") || file_name.ends_with(".partial"))
            {
                continue;
            }
            if path.is_dir() {
                Self::collect_files(&path, out)?;
            } else if path.is_file() {
                out.push(path);
            }
        }
        Ok(())
    }

    /// List all registered snapshots sorted chronologically.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotSummary>, VelcruxError> {
        let mut summaries = Vec::new();
        if !self.snapshot_dir.exists() {
            return Ok(summaries);
        }

        for entry in fs::read_dir(&self.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = fs::read(&path) {
                    if let Ok(snap) = serde_json::from_slice::<SnapshotEntry>(&content) {
                        summaries.push(SnapshotSummary {
                            tag: snap.tag,
                            created_at_secs: snap.created_at_secs,
                            root_path: snap.root_path,
                            file_count: snap.file_count,
                            total_bytes: snap.total_bytes,
                        });
                    }
                }
            }
        }

        summaries.sort_by_key(|s| s.created_at_secs);
        Ok(summaries)
    }

    /// Retrieve full snapshot record by tag.
    pub fn get_snapshot(&self, tag: &str) -> Result<SnapshotEntry, VelcruxError> {
        Self::validate_tag(tag)?;
        let snap_file = self.snapshot_file_path(tag);
        if !snap_file.exists() {
            return Err(VelcruxError::Config(format!(
                "snapshot '{}' not found at {}",
                tag,
                snap_file.display()
            )));
        }

        let content = fs::read(&snap_file)?;
        let entry: SnapshotEntry = serde_json::from_slice(&content)
            .map_err(|e| VelcruxError::Internal(format!("corrupt snapshot json: {}", e)))?;
        Ok(entry)
    }

    /// Delete a snapshot manifest.
    pub fn delete_snapshot(&self, tag: &str) -> Result<bool, VelcruxError> {
        Self::validate_tag(tag)?;
        let snap_file = self.snapshot_file_path(tag);
        if snap_file.exists() {
            fs::remove_file(snap_file)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Compute differences between two snapshots `tag_a` (base) and `tag_b` (target).
    pub fn diff_snapshots(&self, tag_a: &str, tag_b: &str) -> Result<SnapshotDiff, VelcruxError> {
        let a = self.get_snapshot(tag_a)?;
        let b = self.get_snapshot(tag_b)?;

        let mut added_files = Vec::new();
        let mut removed_files = Vec::new();
        let mut modified_files = Vec::new();
        let mut unchanged_files = 0usize;
        let mut bytes_added = 0u64;
        let mut bytes_removed = 0u64;

        // Inspect files in B
        for (rel_path, meta_b) in &b.files {
            match a.files.get(rel_path) {
                Some(meta_a) => {
                    if meta_a.file_hash == meta_b.file_hash {
                        unchanged_files += 1;
                    } else {
                        modified_files.push(rel_path.clone());
                        bytes_added += meta_b.size;
                        bytes_removed += meta_a.size;
                    }
                }
                None => {
                    added_files.push(rel_path.clone());
                    bytes_added += meta_b.size;
                }
            }
        }

        // Inspect files deleted in B
        for (rel_path, meta_a) in &a.files {
            if !b.files.contains_key(rel_path) {
                removed_files.push(rel_path.clone());
                bytes_removed += meta_a.size;
            }
        }

        added_files.sort();
        removed_files.sort();
        modified_files.sort();

        Ok(SnapshotDiff {
            tag_a: tag_a.to_string(),
            tag_b: tag_b.to_string(),
            added_files,
            removed_files,
            modified_files,
            unchanged_files,
            bytes_added,
            bytes_removed,
        })
    }

    /// Restore a point-in-time snapshot to `destination` directory.
    pub fn restore_snapshot(
        &self,
        tag: &str,
        destination: &Path,
        source_fallback: Option<&Path>,
    ) -> Result<SnapshotRestoreReport, VelcruxError> {
        let snap = self.get_snapshot(tag)?;
        fs::create_dir_all(destination)?;

        let mut restored_files = 0usize;
        let mut restored_bytes = 0u64;

        for (rel_path, meta) in &snap.files {
            let target_path = destination.join(rel_path);
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut assembled = Vec::with_capacity(meta.size as usize);

            // 1. Reconstruct from ChunkStore if present
            let mut chunks_available = false;
            if let Some(cs) = &self.chunk_store {
                let mut all_found = true;
                for chash in &meta.chunk_hashes {
                    if !cs.contains_sync(chash) {
                        all_found = false;
                        break;
                    }
                }
                if all_found {
                    chunks_available = true;
                    for chash in &meta.chunk_hashes {
                        let chunk_bytes = cs.get_sync(chash)?;
                        assembled.extend_from_slice(&chunk_bytes);
                    }
                }
            }

            // 2. Fallback to source directory if CAS chunks missing
            if !chunks_available {
                let mut read_fallback = false;
                if let Some(src) = source_fallback {
                    let src_file = src.join(rel_path);
                    if src_file.exists() {
                        let mut f = File::open(&src_file)?;
                        assembled.clear();
                        f.read_to_end(&mut assembled)?;
                        if Hash::of(&assembled) == meta.file_hash {
                            read_fallback = true;
                        }
                    }
                }
                if !read_fallback && !meta.chunk_hashes.is_empty() {
                    return Err(VelcruxError::Internal(format!(
                        "failed to restore '{}': chunks missing from CAS and no source fallback available",
                        rel_path
                    )));
                }
            }

            // Verify integrity
            let computed = Hash::of(&assembled);
            if computed != meta.file_hash {
                return Err(VelcruxError::Protocol(
                    crate::error::ProtocolError::Malformed(
                        "restored file cryptographic checksum mismatch",
                    ),
                ));
            }

            // Atomically write file
            let temp_dest = target_path.with_extension(format!("tmp-{}", rand::random::<u64>()));
            {
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temp_dest)?;
                out.write_all(&assembled)?;
                out.sync_all()?;
            }

            #[cfg(unix)]
            if meta.is_executable {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&temp_dest, fs::Permissions::from_mode(0o755));
            }

            fs::rename(&temp_dest, &target_path)?;

            restored_files += 1;
            restored_bytes += meta.size;
        }

        Ok(SnapshotRestoreReport {
            tag: tag.to_string(),
            restored_files,
            restored_bytes,
            destination: destination.to_path_buf(),
        })
    }

    /// Collect all chunk hashes across all active snapshots for Garbage Collection protection.
    pub fn all_referenced_chunks(&self) -> Result<HashSet<Hash>, VelcruxError> {
        let mut pinned = HashSet::new();
        if !self.snapshot_dir.exists() {
            return Ok(pinned);
        }

        for entry in fs::read_dir(&self.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = fs::read(&path) {
                    if let Ok(snap) = serde_json::from_slice::<SnapshotEntry>(&content) {
                        for meta in snap.files.values() {
                            for chash in &meta.chunk_hashes {
                                pinned.insert(*chash);
                            }
                        }
                    }
                }
            }
        }

        Ok(pinned)
    }
}
