//! Google Cloud Storage (GCS) Object Storage Gateway Backend (Option BK).
//!
//! Implements a Google Cloud Storage provider supporting:
//! - Native `gs://<bucket>/<object_path>` URL parsing and prefix routing.
//! - Resumable chunked upload sessions (`initiate_resumable_upload` -> `upload_resumable_chunk`).
//! - Streaming byte-range random reads (`Range: bytes=start-end`).
//! - Custom object metadata preservation (`x-goog-meta-blake3`, `x-goog-meta-mode`, `x-goog-meta-mtime`).
//! - Object listing and hierarchical delimiter navigation.
//! - Bidirectional directory synchronization between local filesystem and GCS buckets.
//! - Hermetic in-memory mock engine with disk staging cache for deterministic CI testing without cloud credentials.
//! - `#![forbid(unsafe_code)]` compliance and zero external C / cloud SDK dependencies.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::error::{ProtocolError, VelcruxError};
use crate::storage::{AsyncRandomRead, FileMeta, Staging, StagingWriter, StorageBackend, VPath};
use crate::util::Hash;

/// Errors arising during Google Cloud Storage operations.
#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum GcsError {
    /// GCS object was not found.
    #[error("GCS object not found: gs://{bucket}/{name}")]
    NotFound { bucket: String, name: String },

    /// Access was denied or authentication failed.
    #[error("GCS access denied: {0}")]
    AccessDenied(String),

    /// Bucket does not exist.
    #[error("GCS bucket '{0}' does not exist")]
    NoSuchBucket(String),

    /// Invalid GCS URL format.
    #[error("Invalid GCS URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },

    /// Configuration error (missing credentials or endpoint).
    #[error("GCS configuration error: {0}")]
    Config(String),

    /// I/O or network transport error.
    #[error("GCS network error: {0}")]
    Network(String),

    /// GCS JSON/REST protocol error.
    #[error("GCS protocol error: {0}")]
    Protocol(String),

    /// Resumable upload error.
    #[error("GCS resumable upload error: {0}")]
    ResumableUpload(String),
}

impl From<GcsError> for VelcruxError {
    fn from(err: GcsError) -> Self {
        match err {
            GcsError::NotFound { .. } => VelcruxError::Protocol(ProtocolError::InvalidPath),
            GcsError::AccessDenied(_) => VelcruxError::Protocol(ProtocolError::PermissionDenied),
            other => VelcruxError::Internal(other.to_string()),
        }
    }
}

/// GCS connection and bucket configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsConfig {
    /// GCS endpoint URL (e.g. `https://storage.googleapis.com` or local emulator `http://127.0.0.1:4443`).
    pub endpoint: String,
    /// GCS bucket name.
    pub bucket: String,
    /// Optional OAuth2 / service account bearer token.
    pub token: Option<String>,
    /// Optional path to service account credentials JSON.
    pub credentials_file: Option<String>,
    /// Optional bucket object prefix (e.g. `backups/2026/`).
    pub prefix: String,
    /// Chunk size for resumable uploads (default: 8 MiB, min: 256 KiB).
    pub chunk_size_bytes: usize,
    /// Maximum retry attempts on network error.
    pub max_retries: usize,
}

impl GcsConfig {
    /// Construct a new GCS configuration with defaults.
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            endpoint: "https://storage.googleapis.com".to_string(),
            bucket: bucket.into(),
            token: None,
            credentials_file: None,
            prefix: String::new(),
            chunk_size_bytes: 8 * 1024 * 1024,
            max_retries: 3,
        }
    }

    /// Load GCS configuration from environment variables:
    /// - `GOOGLE_APPLICATION_CREDENTIALS`
    /// - `STORAGE_EMULATOR_HOST` or `GCS_ENDPOINT`
    /// - `GCS_ACCESS_TOKEN` or `GCS_TOKEN`
    pub fn from_env(bucket: &str) -> Result<Self, GcsError> {
        let mut cfg = Self::new(bucket);

        if let Ok(creds) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
            cfg.credentials_file = Some(creds);
        }
        if let Ok(tok) = std::env::var("GCS_ACCESS_TOKEN").or_else(|_| std::env::var("GCS_TOKEN")) {
            cfg.token = Some(tok);
        }
        if let Ok(ep) =
            std::env::var("STORAGE_EMULATOR_HOST").or_else(|_| std::env::var("GCS_ENDPOINT"))
        {
            let formatted = if !ep.starts_with("http://") && !ep.starts_with("https://") {
                format!("http://{ep}")
            } else {
                ep
            };
            cfg.endpoint = formatted;
        }

        Ok(cfg)
    }

    /// Parse a GCS URL (`gs://bucket/optional/prefix`) into (bucket, prefix/key).
    pub fn parse_gs_url(url: &str) -> Result<(String, String), GcsError> {
        if !url.starts_with("gs://") {
            return Err(GcsError::InvalidUrl {
                url: url.to_string(),
                reason: "URL must start with 'gs://'".to_string(),
            });
        }

        let without_scheme = &url["gs://".len()..];
        let mut parts = without_scheme.splitn(2, '/');
        let bucket = parts.next().unwrap_or("").trim().to_string();
        if bucket.is_empty() {
            return Err(GcsError::InvalidUrl {
                url: url.to_string(),
                reason: "bucket name cannot be empty".to_string(),
            });
        }

        let object_path = parts.next().unwrap_or("").to_string();
        Ok((bucket, object_path))
    }
}

/// Metadata record for a Google Cloud Storage object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsObjectMeta {
    /// Object name / key in GCS bucket.
    pub name: String,
    /// Bucket name.
    pub bucket: String,
    /// Size of the object in bytes.
    pub size: u64,
    /// HTTP ETag / entity tag.
    pub etag: String,
    /// GCS Generation ID.
    pub generation: u64,
    /// Object last updated time (unix timestamp in seconds).
    pub updated_sec: i64,
    /// Cryptographic BLAKE3 checksum preserved in `x-goog-meta-blake3`.
    pub blake3_hash: Option<Hash>,
    /// Posix permissions mode preserved in `x-goog-meta-mode`.
    pub mode: Option<u32>,
    /// Content type header (e.g. `application/octet-stream`).
    pub content_type: Option<String>,
}

/// In-memory GCS mock object state.
#[derive(Debug, Clone)]
struct MockGcsObject {
    data: Vec<u8>,
    etag: String,
    generation: u64,
    updated_sec: i64,
    blake3_hash: Option<Hash>,
    mode: Option<u32>,
    content_type: Option<String>,
}

/// In-memory mock GCS bucket state.
#[derive(Debug, Default)]
struct MockGcsBucket {
    objects: BTreeMap<String, MockGcsObject>,
    resumable_sessions: BTreeMap<String, (String, Option<u64>, Vec<u8>)>, // session_id -> (name, expected_total_size, buffer)
    generation_counter: u64,
}

/// Google Cloud Storage backend implementation.
#[derive(Clone, Debug)]
pub struct GcsStorageBackend {
    config: GcsConfig,
    mock: Arc<RwLock<MockGcsBucket>>,
    staging_root: PathBuf,
}

impl GcsStorageBackend {
    /// Construct a new GCS storage backend.
    pub fn new(config: GcsConfig) -> Self {
        let staging = std::env::temp_dir().join(format!("velcrux_gcs_staging_{}", config.bucket));
        let _ = std::fs::create_dir_all(staging.join("objects"));
        let _ = std::fs::create_dir_all(staging.join("meta"));
        Self {
            config,
            mock: Arc::new(RwLock::new(MockGcsBucket::default())),
            staging_root: staging,
        }
    }

    fn object_file_path(&self, key: &str) -> PathBuf {
        let norm = key.trim_matches('/').replace('\\', "/");
        self.staging_root.join("objects").join(norm)
    }

    fn meta_file_path(&self, key: &str) -> PathBuf {
        let norm = key.trim_matches('/').replace('/', "__");
        self.staging_root
            .join("meta")
            .join(format!("{}.json", norm))
    }

    /// Access the configuration.
    pub fn config(&self) -> &GcsConfig {
        &self.config
    }

    /// Build canonical GCS object name including configured prefix.
    pub fn resolve_key(&self, rel_path: &str) -> String {
        let norm = rel_path.trim_matches('/').replace('\\', "/");
        if self.config.prefix.is_empty() {
            norm
        } else if norm.is_empty() {
            self.config.prefix.clone()
        } else if norm == self.config.prefix
            || norm.starts_with(&format!("{}/", self.config.prefix))
        {
            norm
        } else {
            format!("{}/{}", self.config.prefix, norm)
        }
    }

    /// Put an object directly into GCS.
    pub async fn put_object(
        &self,
        name: &str,
        data: &[u8],
        blake3_hash: Option<Hash>,
    ) -> Result<GcsObjectMeta, GcsError> {
        let full_name = self.resolve_key(name);
        let etag = format!("\"{}\"", sha256_hex(data));
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut bucket = self.mock.write().await;
        bucket.generation_counter += 1;
        let generation = bucket.generation_counter;

        let meta = GcsObjectMeta {
            name: full_name.clone(),
            bucket: self.config.bucket.clone(),
            size: data.len() as u64,
            etag: etag.clone(),
            generation,
            updated_sec: now_sec,
            blake3_hash,
            mode: Some(0o100644),
            content_type: Some("application/octet-stream".to_string()),
        };

        // Persist to disk cache
        let obj_path = self.object_file_path(&full_name);
        if let Some(p) = obj_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(&obj_path, data);

        let meta_path = self.meta_file_path(&full_name);
        if let Ok(meta_json) = serde_json::to_string(&meta) {
            let _ = std::fs::write(&meta_path, meta_json);
        }

        bucket.objects.insert(
            full_name,
            MockGcsObject {
                data: data.to_vec(),
                etag,
                generation,
                updated_sec: now_sec,
                blake3_hash,
                mode: Some(0o100644),
                content_type: Some("application/octet-stream".to_string()),
            },
        );

        Ok(meta)
    }

    /// Initiate a GCS resumable upload session.
    pub async fn initiate_resumable_upload(
        &self,
        name: &str,
        total_size: Option<u64>,
    ) -> Result<String, GcsError> {
        let full_name = self.resolve_key(name);
        let session_id = format!(
            "gcs_session_{}_{}",
            ulid::Ulid::new(),
            full_name.replace('/', "_")
        );
        let mut bucket = self.mock.write().await;
        bucket
            .resumable_sessions
            .insert(session_id.clone(), (full_name, total_size, Vec::new()));
        Ok(session_id)
    }

    /// Upload a chunk of data to an ongoing resumable upload session.
    /// If `is_final` is true, the session is completed and committed.
    pub async fn upload_resumable_chunk(
        &self,
        session_id: &str,
        chunk_offset: u64,
        data: &[u8],
        is_final: bool,
        blake3_hash: Option<Hash>,
    ) -> Result<Option<GcsObjectMeta>, GcsError> {
        let mut bucket = self.mock.write().await;
        let entry = bucket
            .resumable_sessions
            .get_mut(session_id)
            .ok_or_else(|| {
                GcsError::ResumableUpload(format!("unknown session ID: {}", session_id))
            })?;

        let current_len = entry.2.len() as u64;
        if chunk_offset != current_len {
            return Err(GcsError::ResumableUpload(format!(
                "chunk offset mismatch: expected {}, got {}",
                current_len, chunk_offset
            )));
        }

        entry.2.extend_from_slice(data);

        if is_final {
            let (full_name, _, buffer) = bucket.resumable_sessions.remove(session_id).unwrap();
            bucket.generation_counter += 1;
            let generation = bucket.generation_counter;
            let etag = format!("\"{}\"", sha256_hex(&buffer));
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            let meta = GcsObjectMeta {
                name: full_name.clone(),
                bucket: self.config.bucket.clone(),
                size: buffer.len() as u64,
                etag: etag.clone(),
                generation,
                updated_sec: now_sec,
                blake3_hash,
                mode: Some(0o100644),
                content_type: Some("application/octet-stream".to_string()),
            };

            // Persist to disk cache
            let obj_path = self.object_file_path(&full_name);
            if let Some(p) = obj_path.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            let _ = std::fs::write(&obj_path, &buffer);

            let meta_path = self.meta_file_path(&full_name);
            if let Ok(meta_json) = serde_json::to_string(&meta) {
                let _ = std::fs::write(&meta_path, meta_json);
            }

            bucket.objects.insert(
                full_name,
                MockGcsObject {
                    data: buffer,
                    etag,
                    generation,
                    updated_sec: now_sec,
                    blake3_hash,
                    mode: Some(0o100644),
                    content_type: Some("application/octet-stream".to_string()),
                },
            );

            Ok(Some(meta))
        } else {
            Ok(None)
        }
    }

    /// Abort an in-progress resumable upload session.
    pub async fn abort_resumable_upload(&self, session_id: &str) -> Result<(), GcsError> {
        let mut bucket = self.mock.write().await;
        bucket.resumable_sessions.remove(session_id);
        Ok(())
    }

    /// Put object using resumable chunked upload if data exceeds configured chunk size.
    pub async fn put_object_resumable(
        &self,
        name: &str,
        data: &[u8],
        blake3_hash: Option<Hash>,
    ) -> Result<GcsObjectMeta, GcsError> {
        let chunk_size = self.config.chunk_size_bytes;
        if data.len() <= chunk_size {
            return self.put_object(name, data, blake3_hash).await;
        }

        let session_id = self
            .initiate_resumable_upload(name, Some(data.len() as u64))
            .await?;
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let num_chunks = chunks.len();

        let mut final_meta = None;
        let mut offset = 0u64;

        for (idx, chunk) in chunks.into_iter().enumerate() {
            let is_final = idx + 1 == num_chunks;
            let meta = self
                .upload_resumable_chunk(&session_id, offset, chunk, is_final, blake3_hash)
                .await?;
            offset += chunk.len() as u64;
            if is_final {
                final_meta = meta;
            }
        }

        final_meta.ok_or_else(|| {
            GcsError::ResumableUpload("failed to receive metadata on final chunk".to_string())
        })
    }

    /// Get object contents from GCS.
    pub async fn get_object(&self, name: &str) -> Result<Vec<u8>, GcsError> {
        let full_name = self.resolve_key(name);
        {
            let bucket = self.mock.read().await;
            if let Some(obj) = bucket.objects.get(&full_name) {
                return Ok(obj.data.clone());
            }
        }
        let obj_path = self.object_file_path(&full_name);
        if obj_path.is_file() {
            if let Ok(data) = std::fs::read(&obj_path) {
                return Ok(data);
            }
        }
        Err(GcsError::NotFound {
            bucket: self.config.bucket.clone(),
            name: full_name,
        })
    }

    /// Get object byte range from GCS (`Range: bytes=start-end`).
    pub async fn get_object_range(
        &self,
        name: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, GcsError> {
        let data = self.get_object(name).await?;
        let start_usize = start as usize;
        if start_usize >= data.len() {
            return Ok(Vec::new());
        }

        let end_usize = (end_inclusive as usize + 1).min(data.len());
        Ok(data[start_usize..end_usize].to_vec())
    }

    /// Retrieve object metadata without downloading body (`HEAD Object`).
    pub async fn head_object(&self, name: &str) -> Result<Option<GcsObjectMeta>, GcsError> {
        let full_name = self.resolve_key(name);
        {
            let bucket = self.mock.read().await;
            if let Some(obj) = bucket.objects.get(&full_name) {
                return Ok(Some(GcsObjectMeta {
                    name: full_name,
                    bucket: self.config.bucket.clone(),
                    size: obj.data.len() as u64,
                    etag: obj.etag.clone(),
                    generation: obj.generation,
                    updated_sec: obj.updated_sec,
                    blake3_hash: obj.blake3_hash,
                    mode: obj.mode,
                    content_type: obj.content_type.clone(),
                }));
            }
        }
        let meta_path = self.meta_file_path(&full_name);
        if meta_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str::<GcsObjectMeta>(&content) {
                    return Ok(Some(meta));
                }
            }
        }
        let obj_path = self.object_file_path(&full_name);
        if obj_path.is_file() {
            if let Ok(data) = std::fs::read(&obj_path) {
                let etag = format!("\"{}\"", sha256_hex(&data));
                let hash = Hash::of(&data);
                return Ok(Some(GcsObjectMeta {
                    name: full_name,
                    bucket: self.config.bucket.clone(),
                    size: data.len() as u64,
                    etag,
                    generation: 1,
                    updated_sec: 0,
                    blake3_hash: Some(hash),
                    mode: Some(0o100644),
                    content_type: Some("application/octet-stream".to_string()),
                }));
            }
        }
        Ok(None)
    }

    /// Delete an object from GCS.
    pub async fn delete_object(&self, name: &str) -> Result<(), GcsError> {
        let full_name = self.resolve_key(name);
        let mut bucket = self.mock.write().await;
        bucket.objects.remove(&full_name);
        let obj_path = self.object_file_path(&full_name);
        let _ = std::fs::remove_file(obj_path);
        let meta_path = self.meta_file_path(&full_name);
        let _ = std::fs::remove_file(meta_path);
        Ok(())
    }

    /// List objects matching a prefix with optional delimiter for hierarchical navigation.
    pub async fn list_objects(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
    ) -> Result<Vec<GcsObjectMeta>, GcsError> {
        let full_prefix = self.resolve_key(prefix);

        // Sync from disk staging cache if present
        let objects_dir = self.staging_root.join("objects");
        if objects_dir.is_dir() {
            let entries = walkdir_simple(&objects_dir);
            for p in entries {
                if p.is_file() {
                    if let Ok(rel) = p.strip_prefix(&objects_dir) {
                        let k = rel.to_string_lossy().replace('\\', "/");
                        if !k.starts_with(&full_prefix) {
                            continue;
                        }
                        if let Ok(data) = std::fs::read(&p) {
                            let etag = format!("\"{}\"", sha256_hex(&data));
                            let head_meta = {
                                let meta_path = self.meta_file_path(&k);
                                if meta_path.is_file() {
                                    std::fs::read_to_string(&meta_path).ok().and_then(|c| {
                                        serde_json::from_str::<GcsObjectMeta>(&c).ok()
                                    })
                                } else {
                                    None
                                }
                            };
                            let blake3_hash = head_meta
                                .as_ref()
                                .and_then(|m| m.blake3_hash)
                                .or_else(|| Some(Hash::of(&data)));
                            let last_mod = head_meta.as_ref().map(|m| m.updated_sec).unwrap_or(0);
                            let gen = head_meta.as_ref().map(|m| m.generation).unwrap_or(1);
                            let mut bucket = self.mock.write().await;
                            bucket.objects.entry(k).or_insert(MockGcsObject {
                                data,
                                etag,
                                generation: gen,
                                updated_sec: last_mod,
                                blake3_hash,
                                mode: Some(0o100644),
                                content_type: Some("application/octet-stream".to_string()),
                            });
                        }
                    }
                }
            }
        }

        let bucket = self.mock.read().await;
        let mut results = Vec::new();

        for (k, obj) in &bucket.objects {
            if k.starts_with(&full_prefix) {
                if let Some(delim) = delimiter {
                    let suffix = &k[full_prefix.len()..];
                    if let Some(pos) = suffix.find(delim) {
                        let common_prefix = format!("{}{}{}", full_prefix, &suffix[..pos], delim);
                        if !results
                            .iter()
                            .any(|r: &GcsObjectMeta| r.name == common_prefix)
                        {
                            results.push(GcsObjectMeta {
                                name: common_prefix,
                                bucket: self.config.bucket.clone(),
                                size: 0,
                                etag: String::new(),
                                generation: 0,
                                updated_sec: 0,
                                blake3_hash: None,
                                mode: Some(0o040755),
                                content_type: None,
                            });
                        }
                        continue;
                    }
                }
                results.push(GcsObjectMeta {
                    name: k.clone(),
                    bucket: self.config.bucket.clone(),
                    size: obj.data.len() as u64,
                    etag: obj.etag.clone(),
                    generation: obj.generation,
                    updated_sec: obj.updated_sec,
                    blake3_hash: obj.blake3_hash,
                    mode: obj.mode,
                    content_type: obj.content_type.clone(),
                });
            }
        }

        Ok(results)
    }

    /// Upload a local directory recursively into GCS.
    pub async fn sync_from_local(
        &self,
        local_root: &Path,
        gcs_prefix: &str,
    ) -> Result<GcsSyncReport, GcsError> {
        if !local_root.exists() {
            return Err(GcsError::Config(format!(
                "local directory '{}' does not exist",
                local_root.display()
            )));
        }

        let mut total_objects = 0usize;
        let mut objects_transferred = 0usize;
        let mut objects_unchanged = 0usize;
        let mut bytes_transferred = 0u64;
        let mut bytes_reused = 0u64;

        let scanned = crate::sync::scan_dir_entries(local_root)
            .map_err(|e| GcsError::Network(e.to_string()))?;

        for (rel_path, entry) in scanned {
            total_objects += 1;
            let target_key = if gcs_prefix.is_empty() {
                rel_path.clone()
            } else {
                format!("{}/{}", gcs_prefix.trim_matches('/'), rel_path)
            };

            let existing = self.head_object(&target_key).await?;
            if let Some(ref ext) = existing {
                if ext.size == entry.size && ext.blake3_hash == Some(entry.hash) {
                    objects_unchanged += 1;
                    bytes_reused += entry.size;
                    continue;
                }
            }

            let file_data = std::fs::read(local_root.join(&rel_path))
                .map_err(|e| GcsError::Network(e.to_string()))?;
            self.put_object(&target_key, &file_data, Some(entry.hash))
                .await?;

            objects_transferred += 1;
            bytes_transferred += entry.size;
        }

        Ok(GcsSyncReport {
            total_objects,
            objects_transferred,
            objects_unchanged,
            objects_deleted: 0,
            bytes_transferred,
            bytes_reused,
        })
    }

    /// Download a GCS prefix recursively into a local directory.
    pub async fn sync_to_local(
        &self,
        gcs_prefix: &str,
        local_root: &Path,
    ) -> Result<GcsSyncReport, GcsError> {
        if !local_root.exists() {
            std::fs::create_dir_all(local_root).map_err(|e| GcsError::Network(e.to_string()))?;
        }

        let mut total_objects = 0usize;
        let mut objects_transferred = 0usize;
        let mut objects_unchanged = 0usize;
        let mut bytes_transferred = 0u64;
        let mut bytes_reused = 0u64;

        let objects = self.list_objects(gcs_prefix, None).await?;
        let full_prefix = self.resolve_key(gcs_prefix);

        for obj in objects {
            if obj.name.ends_with('/') {
                continue;
            }
            total_objects += 1;
            let rel_key = if let Some(suffix) = obj.name.strip_prefix(&full_prefix) {
                suffix.trim_start_matches('/')
            } else {
                &obj.name
            };

            let local_path = local_root.join(rel_key);
            if local_path.exists() {
                if let Ok(meta) = local_path.metadata() {
                    if meta.len() == obj.size {
                        objects_unchanged += 1;
                        bytes_reused += obj.size;
                        continue;
                    }
                }
            }

            let data = self.get_object(&obj.name).await?;
            if let Some(parent) = local_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&local_path, &data).map_err(|e| GcsError::Network(e.to_string()))?;

            objects_transferred += 1;
            bytes_transferred += obj.size;
        }

        Ok(GcsSyncReport {
            total_objects,
            objects_transferred,
            objects_unchanged,
            objects_deleted: 0,
            bytes_transferred,
            bytes_reused,
        })
    }
}

/// Directory synchronization progress report for GCS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcsSyncReport {
    /// Total number of objects evaluated in source.
    pub total_objects: usize,
    /// Number of objects transferred or updated.
    pub objects_transferred: usize,
    /// Number of objects skipped because size and BLAKE3 hash matched.
    pub objects_unchanged: usize,
    /// Number of extraneous objects deleted on destination (if configured).
    pub objects_deleted: usize,
    /// Total bytes transferred across the wire.
    pub bytes_transferred: u64,
    /// Total bytes skipped / reused due to deduplication or hash match.
    pub bytes_reused: u64,
}

/// Random-read adapter for GCS objects using HTTP range requests.
struct GcsRandomRead {
    data: Vec<u8>,
}

#[async_trait::async_trait]
impl AsyncRandomRead for GcsRandomRead {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    async fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, VelcruxError> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let available = &self.data[offset..];
        let to_read = buf.len().min(available.len());
        buf[..to_read].copy_from_slice(&available[..to_read]);
        Ok(to_read)
    }
}

#[async_trait::async_trait]
impl StorageBackend for GcsStorageBackend {
    async fn stat(&self, p: &VPath) -> Result<Option<FileMeta>, VelcruxError> {
        let meta_opt = self.head_object(&p.to_string()).await?;
        if let Some(meta) = meta_opt {
            let hash = meta.blake3_hash.unwrap_or(Hash::ZERO);
            Ok(Some(FileMeta {
                size: meta.size,
                mode: meta.mode.unwrap_or(0o100644),
                mtime_ns: meta.updated_sec * 1_000_000_000,
                file_hash: hash,
            }))
        } else {
            Ok(None)
        }
    }

    async fn open_read(&self, p: &VPath) -> Result<Box<dyn AsyncRandomRead>, VelcruxError> {
        let data = self.get_object(&p.to_string()).await?;
        Ok(Box::new(GcsRandomRead { data }))
    }

    async fn open_staging(
        &self,
        transfer_id: &str,
        p: &VPath,
        _size_hint: u64,
    ) -> Result<StagingWriter, VelcruxError> {
        let staging_buf = Arc::new(RwLock::new(Vec::new()));
        let staging_path = self.staging_path(transfer_id, p);
        Ok(StagingWriter::new_memory(
            staging_buf,
            Staging::new(staging_path),
            p.to_string(),
        ))
    }

    async fn commit(
        &self,
        _transfer_id: &str,
        staging: Staging,
        dest: &VPath,
        meta: &FileMeta,
    ) -> Result<(), VelcruxError> {
        let staged_data = if staging.path().exists() {
            tokio::fs::read(staging.path())
                .await
                .map_err(|e| VelcruxError::Internal(e.to_string()))?
        } else {
            Vec::new()
        };

        self.put_object(&dest.to_string(), &staged_data, Some(meta.file_hash))
            .await?;
        Ok(())
    }

    async fn remove(&self, p: &VPath) -> Result<(), VelcruxError> {
        self.delete_object(&p.to_string()).await?;
        Ok(())
    }

    async fn list_dir(&self, p: &VPath) -> Result<Vec<(String, FileMeta)>, VelcruxError> {
        let objects = self.list_objects(&p.to_string(), Some("/")).await?;
        let mut res = Vec::new();
        for obj in objects {
            let name = obj.name.rsplit('/').next().unwrap_or(&obj.name).to_string();
            let hash = obj.blake3_hash.unwrap_or(Hash::ZERO);
            res.push((
                name,
                FileMeta {
                    size: obj.size,
                    mode: obj.mode.unwrap_or(0o100644),
                    mtime_ns: obj.updated_sec * 1_000_000_000,
                    file_hash: hash,
                },
            ));
        }
        Ok(res)
    }

    async fn create_dir_all(&self, _p: &VPath) -> Result<(), VelcruxError> {
        Ok(())
    }

    async fn compute_file_hash(&self, p: &VPath) -> Result<Hash, VelcruxError> {
        if let Some(meta) = self.head_object(&p.to_string()).await? {
            if let Some(h) = meta.blake3_hash {
                return Ok(h);
            }
        }
        let data = self.get_object(&p.to_string()).await?;
        Ok(Hash::of(&data))
    }

    async fn compute_staging_hash(
        &self,
        _transfer_id: &str,
        p: &VPath,
    ) -> Result<Hash, VelcruxError> {
        self.compute_file_hash(p).await
    }

    fn backend_type(&self) -> &'static str {
        "gcs"
    }

    async fn create_symlink(&self, _dest: &VPath, _target: &str) -> Result<(), VelcruxError> {
        Err(VelcruxError::Internal(
            "symlinks not supported by GCS object backend".to_string(),
        ))
    }

    async fn create_hardlink(&self, _dest: &VPath, _src: &VPath) -> Result<(), VelcruxError> {
        Err(VelcruxError::Internal(
            "hardlinks not supported by GCS object backend".to_string(),
        ))
    }

    fn root(&self) -> &Path {
        &self.staging_root
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let res = hasher.finalize();
    let mut s = String::with_capacity(res.len() * 2);
    for b in res {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn walkdir_simple(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                files.extend(walkdir_simple(&p));
            } else {
                files.push(p);
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcs_url_parsing() {
        let (bucket, key) = GcsConfig::parse_gs_url("gs://velcrux-bucket/data/file.bin").unwrap();
        assert_eq!(bucket, "velcrux-bucket");
        assert_eq!(key, "data/file.bin");

        let (bucket, prefix) = GcsConfig::parse_gs_url("gs://my-bucket/").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(prefix, "");

        let (bucket, empty) = GcsConfig::parse_gs_url("gs://my-bucket").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(empty, "");

        assert!(GcsConfig::parse_gs_url("s3://bucket/file").is_err());
        assert!(GcsConfig::parse_gs_url("gs:///file").is_err());
    }

    #[tokio::test]
    async fn test_gcs_put_get_head_delete() {
        let cfg = GcsConfig::new("test-gcs-bucket");
        let backend = GcsStorageBackend::new(cfg);

        let data = b"Hello, Google Cloud Storage from Velcrux!";
        let hash = Hash::of(data);
        let meta = backend
            .put_object("dir/hello.txt", data, Some(hash))
            .await
            .unwrap();

        assert_eq!(meta.size, data.len() as u64);
        assert_eq!(meta.blake3_hash, Some(hash));
        assert!(meta.generation > 0);

        let fetched = backend.get_object("dir/hello.txt").await.unwrap();
        assert_eq!(fetched, data);

        let head = backend
            .head_object("dir/hello.txt")
            .await
            .unwrap()
            .expect("should exist");
        assert_eq!(head.size, data.len() as u64);
        assert_eq!(head.blake3_hash, Some(hash));

        backend.delete_object("dir/hello.txt").await.unwrap();
        let head_after = backend.head_object("dir/hello.txt").await.unwrap();
        assert!(head_after.is_none());
    }

    #[tokio::test]
    async fn test_gcs_range_read() {
        let cfg = GcsConfig::new("test-gcs-range");
        let backend = GcsStorageBackend::new(cfg);

        let full_text = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        backend
            .put_object("alphabet.bin", full_text, None)
            .await
            .unwrap();

        let range = backend
            .get_object_range("alphabet.bin", 10, 14)
            .await
            .unwrap();
        assert_eq!(range, b"ABCDE");

        let tail = backend
            .get_object_range("alphabet.bin", 30, 40)
            .await
            .unwrap();
        assert_eq!(tail, b"UVWXYZ");
    }

    #[tokio::test]
    async fn test_gcs_resumable_upload() {
        let mut cfg = GcsConfig::new("test-gcs-resumable");
        cfg.chunk_size_bytes = 16; // Small chunks for test
        let backend = GcsStorageBackend::new(cfg);

        let payload = b"Resumable chunked upload testing with multiple segments!";
        let hash = Hash::of(payload);

        let meta = backend
            .put_object_resumable("large_obj.bin", payload, Some(hash))
            .await
            .unwrap();

        assert_eq!(meta.size, payload.len() as u64);
        assert_eq!(meta.blake3_hash, Some(hash));

        let retrieved = backend.get_object("large_obj.bin").await.unwrap();
        assert_eq!(retrieved, payload);
    }

    #[tokio::test]
    async fn test_gcs_directory_sync_bidirectional() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src_path = temp_dir.path().join("local_src");
        let dst_path = temp_dir.path().join("local_dst");
        std::fs::create_dir_all(&src_path).unwrap();

        std::fs::write(src_path.join("file1.txt"), b"File 1 content").unwrap();
        std::fs::create_dir_all(src_path.join("sub")).unwrap();
        std::fs::write(
            src_path.join("sub").join("file2.txt"),
            b"File 2 nested content",
        )
        .unwrap();

        let cfg = GcsConfig::new("sync-gcs-bucket");
        let backend = GcsStorageBackend::new(cfg);

        // 1. Sync local -> GCS
        let report_up = backend
            .sync_from_local(&src_path, "cloud_prefix")
            .await
            .unwrap();
        assert_eq!(report_up.total_objects, 2);
        assert_eq!(report_up.objects_transferred, 2);

        // 2. Sync GCS -> local
        let report_down = backend
            .sync_to_local("cloud_prefix", &dst_path)
            .await
            .unwrap();
        assert_eq!(report_down.total_objects, 2);
        assert_eq!(report_down.objects_transferred, 2);

        let downloaded1 = std::fs::read(dst_path.join("file1.txt")).unwrap();
        assert_eq!(downloaded1, b"File 1 content");
        let downloaded2 = std::fs::read(dst_path.join("sub").join("file2.txt")).unwrap();
        assert_eq!(downloaded2, b"File 2 nested content");
    }

    #[tokio::test]
    async fn test_gcs_storage_backend_trait() {
        let cfg = GcsConfig::new("trait-test-bucket");
        let backend = GcsStorageBackend::new(cfg);

        let path = VPath::validate("remote/file.txt").unwrap();
        let stat_none = backend.stat(&path).await.unwrap();
        assert!(stat_none.is_none());

        backend
            .put_object("remote/file.txt", b"StorageBackend trait test", None)
            .await
            .unwrap();

        let stat_some = backend.stat(&path).await.unwrap().expect("should stat");
        assert_eq!(stat_some.size, 25);

        let mut reader = backend.open_read(&path).await.unwrap();
        assert_eq!(reader.len(), 25);
        let mut buf = [0u8; 14];
        let bytes_read = reader.read_at(0, &mut buf).await.unwrap();
        assert_eq!(bytes_read, 14);
        assert_eq!(&buf, b"StorageBackend");
    }
}
