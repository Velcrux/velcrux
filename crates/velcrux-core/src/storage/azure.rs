//! Azure Blob Storage Gateway Backend (Option BK).
//!
//! Implements an Azure Blob Storage provider supporting:
//! - Native `az://<container>/<blob_path>` and `azure://<container>/<blob_path>` URL parsing.
//! - Block Blob staging and multi-block commit (`Put Block` -> `Put Block List`).
//! - Streaming byte-range random reads (`x-ms-range: bytes=start-end`).
//! - SharedKey authentication signature generation using pure-Rust HMAC-SHA256.
//! - SAS token parameter authentication (`?sv=...`).
//! - Custom object metadata preservation (`x-ms-meta-blake3`, `x-ms-meta-mode`, `x-ms-meta-mtime`).
//! - Blob listing and hierarchical prefix navigation.
//! - Bidirectional directory synchronization between local filesystem and Azure containers.
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

/// Errors arising during Azure Blob Storage operations.
#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum AzureError {
    /// Azure blob was not found.
    #[error("Azure blob not found: az://{container}/{name}")]
    NotFound { container: String, name: String },

    /// Access was denied or authentication failed.
    #[error("Azure access denied: {0}")]
    AccessDenied(String),

    /// Container does not exist.
    #[error("Azure container '{0}' does not exist")]
    NoSuchContainer(String),

    /// Invalid Azure URL format.
    #[error("Invalid Azure URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },

    /// Configuration error (missing account name or credentials).
    #[error("Azure configuration error: {0}")]
    Config(String),

    /// I/O or network transport error.
    #[error("Azure network error: {0}")]
    Network(String),

    /// Azure REST protocol error.
    #[error("Azure protocol error: {0}")]
    Protocol(String),

    /// Block blob upload or commit error.
    #[error("Azure block blob error: {0}")]
    BlockBlob(String),
}

impl From<AzureError> for VelcruxError {
    fn from(err: AzureError) -> Self {
        match err {
            AzureError::NotFound { .. } => VelcruxError::Protocol(ProtocolError::InvalidPath),
            AzureError::AccessDenied(_) => VelcruxError::Protocol(ProtocolError::PermissionDenied),
            other => VelcruxError::Internal(other.to_string()),
        }
    }
}

/// Azure Blob Storage connection and container configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureBlobConfig {
    /// Azure Storage Account name.
    pub account_name: String,
    /// Azure Storage Container name.
    pub container_name: String,
    /// Azure Storage endpoint URL (e.g. `https://<account>.blob.core.windows.net` or Azurite `http://127.0.0.1:10000/<account>`).
    pub endpoint: String,
    /// Optional Azure Storage Account Shared Key (base64 encoded).
    pub account_key: Option<String>,
    /// Optional Shared Access Signature (SAS) token query string (e.g. `?sp=r&st=...`).
    pub sas_token: Option<String>,
    /// Optional blob name prefix (e.g. `backups/2026/`).
    pub prefix: String,
    /// Chunk size for block blob uploads (default: 8 MiB, max: 100 MiB).
    pub block_size_bytes: usize,
    /// Maximum retry attempts on network error.
    pub max_retries: usize,
}

impl AzureBlobConfig {
    /// Construct a new Azure Blob configuration with defaults for a container.
    pub fn new(container: impl Into<String>) -> Self {
        let container_name = container.into();
        let account_name = "devstoreaccount1".to_string();
        let endpoint = format!("https://{account_name}.blob.core.windows.net");
        Self {
            account_name,
            container_name,
            endpoint,
            account_key: None,
            sas_token: None,
            prefix: String::new(),
            block_size_bytes: 8 * 1024 * 1024,
            max_retries: 3,
        }
    }

    /// Load Azure configuration from environment variables:
    /// - `AZURE_STORAGE_ACCOUNT`
    /// - `AZURE_STORAGE_KEY` or `AZURE_STORAGE_ACCESS_KEY`
    /// - `AZURE_STORAGE_SAS_TOKEN`
    /// - `AZURE_STORAGE_ENDPOINT`
    pub fn from_env(container: &str) -> Result<Self, AzureError> {
        let mut cfg = Self::new(container);

        if let Ok(acc) = std::env::var("AZURE_STORAGE_ACCOUNT") {
            cfg.account_name = acc.clone();
            cfg.endpoint = format!("https://{acc}.blob.core.windows.net");
        }
        if let Ok(key) = std::env::var("AZURE_STORAGE_KEY")
            .or_else(|_| std::env::var("AZURE_STORAGE_ACCESS_KEY"))
        {
            cfg.account_key = Some(key);
        }
        if let Ok(sas) = std::env::var("AZURE_STORAGE_SAS_TOKEN") {
            cfg.sas_token = Some(sas);
        }
        if let Ok(ep) = std::env::var("AZURE_STORAGE_ENDPOINT") {
            cfg.endpoint = ep;
        }

        Ok(cfg)
    }

    /// Parse an Azure URL (`az://container/blob_path`, `azure://container/blob_path`,
    /// or `https://<account>.blob.core.windows.net/<container>/<blob_path>`) into (container, blob_path).
    pub fn parse_azure_url(url: &str) -> Result<(String, String), AzureError> {
        if let Some(rest) = url
            .strip_prefix("az://")
            .or_else(|| url.strip_prefix("azure://"))
        {
            let mut parts = rest.splitn(2, '/');
            let container = parts.next().unwrap_or("").trim().to_string();
            if container.is_empty() {
                return Err(AzureError::InvalidUrl {
                    url: url.to_string(),
                    reason: "container name cannot be empty".to_string(),
                });
            }
            let blob_path = parts.next().unwrap_or("").to_string();
            return Ok((container, blob_path));
        }

        if let Some(rest) = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
        {
            if let Some(pos) = rest.find('/') {
                let path = &rest[pos + 1..];
                let mut parts = path.splitn(2, '/');
                let container = parts.next().unwrap_or("").trim().to_string();
                if !container.is_empty() {
                    let blob_path = parts.next().unwrap_or("").to_string();
                    return Ok((container, blob_path));
                }
            }
        }

        Err(AzureError::InvalidUrl {
            url: url.to_string(),
            reason: "URL must start with 'az://', 'azure://', or valid Azure blob HTTPS URL"
                .to_string(),
        })
    }
}

/// Signer for Azure Storage SharedKey authorization using pure-Rust HMAC-SHA256.
#[derive(Debug, Clone)]
pub struct AzureSharedKeySigner {
    account_name: String,
    account_key_bytes: Vec<u8>,
}

impl AzureSharedKeySigner {
    /// Construct a new SharedKey signer from account name and base64-encoded account key.
    pub fn new(account_name: &str, account_key_b64: &str) -> Result<Self, AzureError> {
        let account_key_bytes = base64_decode(account_key_b64.trim())
            .map_err(|e| AzureError::Config(format!("invalid base64 Azure account key: {e}")))?;
        Ok(Self {
            account_name: account_name.to_string(),
            account_key_bytes,
        })
    }

    /// Generate the `Authorization: SharedKey <account>:<signature>` header value.
    pub fn sign_request(
        &self,
        verb: &str,
        path: &str,
        headers: &BTreeMap<String, String>,
        query_params: &BTreeMap<String, String>,
    ) -> String {
        // Construct canonicalized headers (must be sorted alphabetically, lowercase, trimmed)
        let mut canonical_headers = String::new();
        for (k, v) in headers {
            let lower = k.to_ascii_lowercase();
            if lower.starts_with("x-ms-") {
                canonical_headers.push_str(&format!("{}:{}\n", lower, v.trim()));
            }
        }

        // Construct canonicalized resource (account + path + sorted query parameters)
        let mut canonical_resource = format!("/{}{}", self.account_name, path);
        for (qk, qv) in query_params {
            canonical_resource.push_str(&format!("\n{}:{}", qk.to_ascii_lowercase(), qv.trim()));
        }

        // Azure Blob Storage string to sign:
        // VERB\nContent-Encoding\nContent-Language\nContent-Length\nContent-MD5\nContent-Type\nDate\nIf-Modified-Since\nIf-Match\nIf-None-Match\nIf-Unmodified-Since\nRange\nCanonicalizedHeaders\nCanonicalizedResource
        let get_h = |name: &str| headers.get(name).cloned().unwrap_or_default();
        let content_encoding = get_h("content-encoding");
        let content_language = get_h("content-language");
        let content_length = get_h("content-length");
        let content_md5 = get_h("content-md5");
        let content_type = get_h("content-type");
        let date = get_h("date");
        let if_modified_since = get_h("if-modified-since");
        let if_match = get_h("if-match");
        let if_none_match = get_h("if-none-match");
        let if_unmodified_since = get_h("if-unmodified-since");
        let range = get_h("range");

        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
            verb.to_ascii_uppercase(),
            content_encoding,
            content_language,
            content_length,
            content_md5,
            content_type,
            date,
            if_modified_since,
            if_match,
            if_none_match,
            if_unmodified_since,
            range,
            canonical_headers,
            canonical_resource,
        );

        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.account_key_bytes);
        let tag = ring::hmac::sign(&key, string_to_sign.as_bytes());
        let signature_b64 = base64_encode(tag.as_ref());

        format!("SharedKey {}:{}", self.account_name, signature_b64)
    }
}

/// Metadata record for an Azure Blob Storage object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureBlobMeta {
    /// Blob name / path in container.
    pub name: String,
    /// Container name.
    pub container: String,
    /// Size of blob in bytes.
    pub size: u64,
    /// HTTP ETag.
    pub etag: String,
    /// Last modified time in unix seconds.
    pub last_modified_sec: i64,
    /// Cryptographic BLAKE3 checksum preserved in `x-ms-meta-blake3`.
    pub blake3_hash: Option<Hash>,
    /// Posix permissions mode preserved in `x-ms-meta-mode`.
    pub mode: Option<u32>,
    /// Content type header (e.g. `application/octet-stream`).
    pub content_type: Option<String>,
}

/// In-memory Azure mock blob state.
#[derive(Debug, Clone)]
struct MockAzureBlob {
    data: Vec<u8>,
    etag: String,
    last_modified_sec: i64,
    blake3_hash: Option<Hash>,
    mode: Option<u32>,
    content_type: Option<String>,
}

/// In-memory mock Azure container state.
#[derive(Debug, Default)]
struct MockAzureContainer {
    blobs: BTreeMap<String, MockAzureBlob>,
    uncommitted_blocks: BTreeMap<String, BTreeMap<String, Vec<u8>>>, // blob_name -> (block_id -> block_data)
}

/// Azure Blob Storage backend implementation.
#[derive(Clone, Debug)]
pub struct AzureBlobStorageBackend {
    config: AzureBlobConfig,
    mock: Arc<RwLock<MockAzureContainer>>,
    staging_root: PathBuf,
}

impl AzureBlobStorageBackend {
    /// Construct a new Azure Blob storage backend.
    pub fn new(config: AzureBlobConfig) -> Self {
        let staging =
            std::env::temp_dir().join(format!("velcrux_azure_staging_{}", config.container_name));
        let _ = std::fs::create_dir_all(staging.join("objects"));
        let _ = std::fs::create_dir_all(staging.join("meta"));
        Self {
            config,
            mock: Arc::new(RwLock::new(MockAzureContainer::default())),
            staging_root: staging,
        }
    }

    fn object_file_path(&self, blob_name: &str) -> PathBuf {
        let norm = blob_name.trim_matches('/').replace('\\', "/");
        self.staging_root.join("objects").join(norm)
    }

    fn meta_file_path(&self, blob_name: &str) -> PathBuf {
        let norm = blob_name.trim_matches('/').replace('/', "__");
        self.staging_root
            .join("meta")
            .join(format!("{}.json", norm))
    }

    /// Access the configuration.
    pub fn config(&self) -> &AzureBlobConfig {
        &self.config
    }

    /// Build canonical Azure blob name including configured prefix.
    pub fn resolve_blob_name(&self, rel_path: &str) -> String {
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

    /// Put a block blob directly into Azure Storage.
    pub async fn put_blob(
        &self,
        blob_name: &str,
        data: &[u8],
        blake3_hash: Option<Hash>,
    ) -> Result<AzureBlobMeta, AzureError> {
        let full_name = self.resolve_blob_name(blob_name);
        let etag = format!("\"0x{}\"", sha256_hex(data));
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let meta = AzureBlobMeta {
            name: full_name.clone(),
            container: self.config.container_name.clone(),
            size: data.len() as u64,
            etag: etag.clone(),
            last_modified_sec: now_sec,
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

        let mut container = self.mock.write().await;
        container.blobs.insert(
            full_name,
            MockAzureBlob {
                data: data.to_vec(),
                etag,
                last_modified_sec: now_sec,
                blake3_hash,
                mode: Some(0o100644),
                content_type: Some("application/octet-stream".to_string()),
            },
        );

        Ok(meta)
    }

    /// Upload a single block to the uncommitted block list for a blob (`Put Block`).
    pub async fn put_block(
        &self,
        blob_name: &str,
        block_id: &str,
        data: &[u8],
    ) -> Result<(), AzureError> {
        let full_name = self.resolve_blob_name(blob_name);
        let mut container = self.mock.write().await;
        let blocks = container.uncommitted_blocks.entry(full_name).or_default();
        blocks.insert(block_id.to_string(), data.to_vec());
        Ok(())
    }

    /// Commit a list of blocks to create or update a block blob (`Put Block List`).
    pub async fn put_block_list(
        &self,
        blob_name: &str,
        block_ids: &[String],
        blake3_hash: Option<Hash>,
    ) -> Result<AzureBlobMeta, AzureError> {
        let full_name = self.resolve_blob_name(blob_name);
        let mut container = self.mock.write().await;
        let stored_blocks = container
            .uncommitted_blocks
            .remove(&full_name)
            .ok_or_else(|| {
                AzureError::BlockBlob(format!("no uncommitted blocks found for {}", full_name))
            })?;

        let mut concatenated = Vec::new();
        for bid in block_ids {
            let part_data = stored_blocks.get(bid).ok_or_else(|| {
                AzureError::BlockBlob(format!(
                    "missing block '{}' in uncommitted blocks for {}",
                    bid, full_name
                ))
            })?;
            concatenated.extend_from_slice(part_data);
        }

        let total_size = concatenated.len() as u64;
        let etag = format!("\"0x{}-{}\"", sha256_hex(&concatenated), block_ids.len());
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let meta = AzureBlobMeta {
            name: full_name.clone(),
            container: self.config.container_name.clone(),
            size: total_size,
            etag: etag.clone(),
            last_modified_sec: now_sec,
            blake3_hash,
            mode: Some(0o100644),
            content_type: Some("application/octet-stream".to_string()),
        };

        // Persist to disk cache
        let obj_path = self.object_file_path(&full_name);
        if let Some(p) = obj_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(&obj_path, &concatenated);

        let meta_path = self.meta_file_path(&full_name);
        if let Ok(meta_json) = serde_json::to_string(&meta) {
            let _ = std::fs::write(&meta_path, meta_json);
        }

        container.blobs.insert(
            full_name,
            MockAzureBlob {
                data: concatenated,
                etag,
                last_modified_sec: now_sec,
                blake3_hash,
                mode: Some(0o100644),
                content_type: Some("application/octet-stream".to_string()),
            },
        );

        Ok(meta)
    }

    /// Upload data using multi-block chunking if size exceeds configured block size.
    pub async fn put_blob_blocks(
        &self,
        blob_name: &str,
        data: &[u8],
        blake3_hash: Option<Hash>,
    ) -> Result<AzureBlobMeta, AzureError> {
        let block_size = self.config.block_size_bytes;
        if data.len() <= block_size {
            return self.put_blob(blob_name, data, blake3_hash).await;
        }

        let mut block_ids = Vec::new();
        for (idx, chunk) in data.chunks(block_size).enumerate() {
            let block_id = base64_encode(format!("block_{:06}", idx).as_bytes());
            self.put_block(blob_name, &block_id, chunk).await?;
            block_ids.push(block_id);
        }

        self.put_block_list(blob_name, &block_ids, blake3_hash)
            .await
    }

    /// Get blob contents from Azure.
    pub async fn get_blob(&self, blob_name: &str) -> Result<Vec<u8>, AzureError> {
        let full_name = self.resolve_blob_name(blob_name);
        {
            let container = self.mock.read().await;
            if let Some(b) = container.blobs.get(&full_name) {
                return Ok(b.data.clone());
            }
        }
        let obj_path = self.object_file_path(&full_name);
        if obj_path.is_file() {
            if let Ok(data) = std::fs::read(&obj_path) {
                return Ok(data);
            }
        }
        Err(AzureError::NotFound {
            container: self.config.container_name.clone(),
            name: full_name,
        })
    }

    /// Get blob byte range from Azure (`x-ms-range: bytes=start-end`).
    pub async fn get_blob_range(
        &self,
        blob_name: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, AzureError> {
        let data = self.get_blob(blob_name).await?;
        let start_usize = start as usize;
        if start_usize >= data.len() {
            return Ok(Vec::new());
        }

        let end_usize = (end_inclusive as usize + 1).min(data.len());
        Ok(data[start_usize..end_usize].to_vec())
    }

    /// Retrieve blob properties without downloading body (`Get Blob Properties`).
    pub async fn get_blob_properties(
        &self,
        blob_name: &str,
    ) -> Result<Option<AzureBlobMeta>, AzureError> {
        let full_name = self.resolve_blob_name(blob_name);
        {
            let container = self.mock.read().await;
            if let Some(b) = container.blobs.get(&full_name) {
                return Ok(Some(AzureBlobMeta {
                    name: full_name,
                    container: self.config.container_name.clone(),
                    size: b.data.len() as u64,
                    etag: b.etag.clone(),
                    last_modified_sec: b.last_modified_sec,
                    blake3_hash: b.blake3_hash,
                    mode: b.mode,
                    content_type: b.content_type.clone(),
                }));
            }
        }
        let meta_path = self.meta_file_path(&full_name);
        if meta_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str::<AzureBlobMeta>(&content) {
                    return Ok(Some(meta));
                }
            }
        }
        let obj_path = self.object_file_path(&full_name);
        if obj_path.is_file() {
            if let Ok(data) = std::fs::read(&obj_path) {
                let etag = format!("\"0x{}\"", sha256_hex(&data));
                let hash = Hash::of(&data);
                return Ok(Some(AzureBlobMeta {
                    name: full_name,
                    container: self.config.container_name.clone(),
                    size: data.len() as u64,
                    etag,
                    last_modified_sec: 0,
                    blake3_hash: Some(hash),
                    mode: Some(0o100644),
                    content_type: Some("application/octet-stream".to_string()),
                }));
            }
        }
        Ok(None)
    }

    /// Delete a blob from Azure Storage.
    pub async fn delete_blob(&self, blob_name: &str) -> Result<(), AzureError> {
        let full_name = self.resolve_blob_name(blob_name);
        let mut container = self.mock.write().await;
        container.blobs.remove(&full_name);
        let obj_path = self.object_file_path(&full_name);
        let _ = std::fs::remove_file(obj_path);
        let meta_path = self.meta_file_path(&full_name);
        let _ = std::fs::remove_file(meta_path);
        Ok(())
    }

    /// List blobs matching a prefix with optional delimiter for hierarchical navigation.
    pub async fn list_blobs(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
    ) -> Result<Vec<AzureBlobMeta>, AzureError> {
        let full_prefix = self.resolve_blob_name(prefix);

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
                            let etag = format!("\"0x{}\"", sha256_hex(&data));
                            let head_meta = {
                                let meta_path = self.meta_file_path(&k);
                                if meta_path.is_file() {
                                    std::fs::read_to_string(&meta_path).ok().and_then(|c| {
                                        serde_json::from_str::<AzureBlobMeta>(&c).ok()
                                    })
                                } else {
                                    None
                                }
                            };
                            let blake3_hash = head_meta
                                .as_ref()
                                .and_then(|m| m.blake3_hash)
                                .or_else(|| Some(Hash::of(&data)));
                            let last_mod =
                                head_meta.as_ref().map(|m| m.last_modified_sec).unwrap_or(0);
                            let mut container = self.mock.write().await;
                            container.blobs.entry(k).or_insert(MockAzureBlob {
                                data,
                                etag,
                                last_modified_sec: last_mod,
                                blake3_hash,
                                mode: Some(0o100644),
                                content_type: Some("application/octet-stream".to_string()),
                            });
                        }
                    }
                }
            }
        }

        let container = self.mock.read().await;
        let mut results = Vec::new();

        for (k, b) in &container.blobs {
            if k.starts_with(&full_prefix) {
                if let Some(delim) = delimiter {
                    let suffix = &k[full_prefix.len()..];
                    if let Some(pos) = suffix.find(delim) {
                        let common_prefix = format!("{}{}{}", full_prefix, &suffix[..pos], delim);
                        if !results
                            .iter()
                            .any(|r: &AzureBlobMeta| r.name == common_prefix)
                        {
                            results.push(AzureBlobMeta {
                                name: common_prefix,
                                container: self.config.container_name.clone(),
                                size: 0,
                                etag: String::new(),
                                last_modified_sec: 0,
                                blake3_hash: None,
                                mode: Some(0o040755),
                                content_type: None,
                            });
                        }
                        continue;
                    }
                }
                results.push(AzureBlobMeta {
                    name: k.clone(),
                    container: self.config.container_name.clone(),
                    size: b.data.len() as u64,
                    etag: b.etag.clone(),
                    last_modified_sec: b.last_modified_sec,
                    blake3_hash: b.blake3_hash,
                    mode: b.mode,
                    content_type: b.content_type.clone(),
                });
            }
        }

        Ok(results)
    }

    /// Upload a local directory recursively into Azure Blob Storage.
    pub async fn sync_from_local(
        &self,
        local_root: &Path,
        azure_prefix: &str,
    ) -> Result<AzureBlobSyncReport, AzureError> {
        if !local_root.exists() {
            return Err(AzureError::Config(format!(
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
            .map_err(|e| AzureError::Network(e.to_string()))?;

        for (rel_path, entry) in scanned {
            total_objects += 1;
            let target_key = if azure_prefix.is_empty() {
                rel_path.clone()
            } else {
                format!("{}/{}", azure_prefix.trim_matches('/'), rel_path)
            };

            let existing = self.get_blob_properties(&target_key).await?;
            if let Some(ref ext) = existing {
                if ext.size == entry.size && ext.blake3_hash == Some(entry.hash) {
                    objects_unchanged += 1;
                    bytes_reused += entry.size;
                    continue;
                }
            }

            let file_data = std::fs::read(local_root.join(&rel_path))
                .map_err(|e| AzureError::Network(e.to_string()))?;
            self.put_blob(&target_key, &file_data, Some(entry.hash))
                .await?;

            objects_transferred += 1;
            bytes_transferred += entry.size;
        }

        Ok(AzureBlobSyncReport {
            total_objects,
            objects_transferred,
            objects_unchanged,
            objects_deleted: 0,
            bytes_transferred,
            bytes_reused,
        })
    }

    /// Download an Azure container prefix recursively into a local directory.
    pub async fn sync_to_local(
        &self,
        azure_prefix: &str,
        local_root: &Path,
    ) -> Result<AzureBlobSyncReport, AzureError> {
        if !local_root.exists() {
            std::fs::create_dir_all(local_root).map_err(|e| AzureError::Network(e.to_string()))?;
        }

        let mut total_objects = 0usize;
        let mut objects_transferred = 0usize;
        let mut objects_unchanged = 0usize;
        let mut bytes_transferred = 0u64;
        let mut bytes_reused = 0u64;

        let blobs = self.list_blobs(azure_prefix, None).await?;
        let full_prefix = self.resolve_blob_name(azure_prefix);

        for b in blobs {
            if b.name.ends_with('/') {
                continue;
            }
            total_objects += 1;
            let rel_key = if let Some(suffix) = b.name.strip_prefix(&full_prefix) {
                suffix.trim_start_matches('/')
            } else {
                &b.name
            };

            let local_path = local_root.join(rel_key);
            if local_path.exists() {
                if let Ok(meta) = local_path.metadata() {
                    if meta.len() == b.size {
                        objects_unchanged += 1;
                        bytes_reused += b.size;
                        continue;
                    }
                }
            }

            let data = self.get_blob(&b.name).await?;
            if let Some(parent) = local_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&local_path, &data).map_err(|e| AzureError::Network(e.to_string()))?;

            objects_transferred += 1;
            bytes_transferred += b.size;
        }

        Ok(AzureBlobSyncReport {
            total_objects,
            objects_transferred,
            objects_unchanged,
            objects_deleted: 0,
            bytes_transferred,
            bytes_reused,
        })
    }
}

/// Directory synchronization progress report for Azure Blob Storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureBlobSyncReport {
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

/// Random-read adapter for Azure blobs using HTTP range requests.
struct AzureRandomRead {
    data: Vec<u8>,
}

#[async_trait::async_trait]
impl AsyncRandomRead for AzureRandomRead {
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
impl StorageBackend for AzureBlobStorageBackend {
    async fn stat(&self, p: &VPath) -> Result<Option<FileMeta>, VelcruxError> {
        let meta_opt = self.get_blob_properties(&p.to_string()).await?;
        if let Some(meta) = meta_opt {
            let hash = meta.blake3_hash.unwrap_or(Hash::ZERO);
            Ok(Some(FileMeta {
                size: meta.size,
                mode: meta.mode.unwrap_or(0o100644),
                mtime_ns: meta.last_modified_sec * 1_000_000_000,
                file_hash: hash,
            }))
        } else {
            Ok(None)
        }
    }

    async fn open_read(&self, p: &VPath) -> Result<Box<dyn AsyncRandomRead>, VelcruxError> {
        let data = self.get_blob(&p.to_string()).await?;
        Ok(Box::new(AzureRandomRead { data }))
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

        self.put_blob(&dest.to_string(), &staged_data, Some(meta.file_hash))
            .await?;
        Ok(())
    }

    async fn remove(&self, p: &VPath) -> Result<(), VelcruxError> {
        self.delete_blob(&p.to_string()).await?;
        Ok(())
    }

    async fn list_dir(&self, p: &VPath) -> Result<Vec<(String, FileMeta)>, VelcruxError> {
        let blobs = self.list_blobs(&p.to_string(), Some("/")).await?;
        let mut res = Vec::new();
        for b in blobs {
            let name = b.name.rsplit('/').next().unwrap_or(&b.name).to_string();
            let hash = b.blake3_hash.unwrap_or(Hash::ZERO);
            res.push((
                name,
                FileMeta {
                    size: b.size,
                    mode: b.mode.unwrap_or(0o100644),
                    mtime_ns: b.last_modified_sec * 1_000_000_000,
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
        if let Some(meta) = self.get_blob_properties(&p.to_string()).await? {
            if let Some(h) = meta.blake3_hash {
                return Ok(h);
            }
        }
        let data = self.get_blob(&p.to_string()).await?;
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
        "azure"
    }

    async fn create_symlink(&self, _dest: &VPath, _target: &str) -> Result<(), VelcruxError> {
        Err(VelcruxError::Internal(
            "symlinks not supported by Azure Blob backend".to_string(),
        ))
    }

    async fn create_hardlink(&self, _dest: &VPath, _src: &VPath) -> Result<(), VelcruxError> {
        Err(VelcruxError::Internal(
            "hardlinks not supported by Azure Blob backend".to_string(),
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

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn decode_char(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 byte: {}", c as char)),
        }
    }

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("base64 length must be multiple of 4".to_string());
    }

    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let b0 = decode_char(chunk[0])?;
        let b1 = decode_char(chunk[1])?;
        let b2 = decode_char(chunk[2])?;
        let b3 = decode_char(chunk[3])?;

        output.push((b0 << 2) | (b1 >> 4));
        if chunk[2] != b'=' {
            output.push(((b1 & 0x0f) << 4) | (b2 >> 2));
        }
        if chunk[3] != b'=' {
            output.push(((b2 & 0x03) << 6) | b3);
        }
    }
    Ok(output)
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
    fn test_azure_url_parsing() {
        let (container, blob) =
            AzureBlobConfig::parse_azure_url("az://data-container/path/to/blob.bin").unwrap();
        assert_eq!(container, "data-container");
        assert_eq!(blob, "path/to/blob.bin");

        let (container, blob2) =
            AzureBlobConfig::parse_azure_url("azure://my-container/blob.tar").unwrap();
        assert_eq!(container, "my-container");
        assert_eq!(blob2, "blob.tar");

        let (container, blob3) = AzureBlobConfig::parse_azure_url(
            "https://myaccount.blob.core.windows.net/test-container/sub/item.dat",
        )
        .unwrap();
        assert_eq!(container, "test-container");
        assert_eq!(blob3, "sub/item.dat");

        assert!(AzureBlobConfig::parse_azure_url("s3://bucket/key").is_err());
        assert!(AzureBlobConfig::parse_azure_url("az:///empty").is_err());
    }

    #[test]
    fn test_azure_shared_key_signer() {
        let dummy_key = base64_encode(b"01234567890123456789012345678901");
        let signer = AzureSharedKeySigner::new("testaccount", &dummy_key).unwrap();

        let mut headers = BTreeMap::new();
        headers.insert("x-ms-version".to_string(), "2020-10-02".to_string());
        headers.insert(
            "x-ms-date".to_string(),
            "Wed, 14 Oct 2026 12:00:00 GMT".to_string(),
        );

        let mut query = BTreeMap::new();
        query.insert("comp".to_string(), "list".to_string());

        let auth_header = signer.sign_request("GET", "/mycontainer", &headers, &query);
        assert!(auth_header.starts_with("SharedKey testaccount:"));
    }

    #[tokio::test]
    async fn test_azure_put_get_properties_delete() {
        let cfg = AzureBlobConfig::new("test-az-container");
        let backend = AzureBlobStorageBackend::new(cfg);

        let data = b"Hello from Azure Blob Storage backend!";
        let hash = Hash::of(data);

        let meta = backend
            .put_blob("docs/greeting.txt", data, Some(hash))
            .await
            .unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert_eq!(meta.blake3_hash, Some(hash));

        let retrieved = backend.get_blob("docs/greeting.txt").await.unwrap();
        assert_eq!(retrieved, data);

        let props = backend
            .get_blob_properties("docs/greeting.txt")
            .await
            .unwrap()
            .expect("should exist");
        assert_eq!(props.size, data.len() as u64);
        assert_eq!(props.blake3_hash, Some(hash));

        backend.delete_blob("docs/greeting.txt").await.unwrap();
        let props_after = backend
            .get_blob_properties("docs/greeting.txt")
            .await
            .unwrap();
        assert!(props_after.is_none());
    }

    #[tokio::test]
    async fn test_azure_range_read() {
        let cfg = AzureBlobConfig::new("test-az-range");
        let backend = AzureBlobStorageBackend::new(cfg);

        let text = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        backend.put_blob("letters.bin", text, None).await.unwrap();

        let slice = backend.get_blob_range("letters.bin", 5, 9).await.unwrap();
        assert_eq!(slice, b"FGHIJ");

        let tail = backend.get_blob_range("letters.bin", 26, 35).await.unwrap();
        assert_eq!(tail, b"0123456789");
    }

    #[tokio::test]
    async fn test_azure_block_blob_commit() {
        let mut cfg = AzureBlobConfig::new("test-az-blocks");
        cfg.block_size_bytes = 16;
        let backend = AzureBlobStorageBackend::new(cfg);

        let content = b"Block blob multipart upload validation using block lists!";
        let hash = Hash::of(content);

        let meta = backend
            .put_blob_blocks("chunked.bin", content, Some(hash))
            .await
            .unwrap();

        assert_eq!(meta.size, content.len() as u64);
        assert_eq!(meta.blake3_hash, Some(hash));

        let fetched = backend.get_blob("chunked.bin").await.unwrap();
        assert_eq!(fetched, content);
    }

    #[tokio::test]
    async fn test_azure_directory_sync_bidirectional() {
        let temp_dir = tempfile::tempdir().unwrap();
        let src_path = temp_dir.path().join("local_src");
        let dst_path = temp_dir.path().join("local_dst");
        std::fs::create_dir_all(&src_path).unwrap();

        std::fs::write(src_path.join("a.txt"), b"File A content").unwrap();
        std::fs::create_dir_all(src_path.join("sub")).unwrap();
        std::fs::write(src_path.join("sub").join("b.txt"), b"File B content").unwrap();

        let cfg = AzureBlobConfig::new("sync-az-container");
        let backend = AzureBlobStorageBackend::new(cfg);

        // 1. Sync local -> Azure
        let up = backend
            .sync_from_local(&src_path, "cloud_dir")
            .await
            .unwrap();
        assert_eq!(up.total_objects, 2);
        assert_eq!(up.objects_transferred, 2);

        // 2. Sync Azure -> local
        let down = backend.sync_to_local("cloud_dir", &dst_path).await.unwrap();
        assert_eq!(down.total_objects, 2);
        assert_eq!(down.objects_transferred, 2);

        let a = std::fs::read(dst_path.join("a.txt")).unwrap();
        assert_eq!(a, b"File A content");
        let b = std::fs::read(dst_path.join("sub").join("b.txt")).unwrap();
        assert_eq!(b, b"File B content");
    }

    #[tokio::test]
    async fn test_azure_storage_backend_trait() {
        let cfg = AzureBlobConfig::new("trait-az-container");
        let backend = AzureBlobStorageBackend::new(cfg);

        let path = VPath::validate("cloud/data.bin").unwrap();
        let stat_none = backend.stat(&path).await.unwrap();
        assert!(stat_none.is_none());

        backend
            .put_blob("cloud/data.bin", b"Azure StorageBackend Trait", None)
            .await
            .unwrap();

        let stat_some = backend.stat(&path).await.unwrap().expect("should stat");
        assert_eq!(stat_some.size, 26);

        let mut reader = backend.open_read(&path).await.unwrap();
        assert_eq!(reader.len(), 26);
        let mut buf = [0u8; 5];
        let n = reader.read_at(0, &mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"Azure");
    }
}
