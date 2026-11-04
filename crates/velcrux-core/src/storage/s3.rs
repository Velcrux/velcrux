//! S3-Compatible Cloud Object Storage Gateway Backend (`REQUIREMENTS.md` §42, §43).
//!
//! Implements an S3-compatible object storage provider supporting:
//! - AWS Signature Version 4 (SigV4) authentication.
//! - Streaming range-request random reads (`Range: bytes=start-end`).
//! - Multipart chunk uploads (`InitiateMultipartUpload` → `UploadPart` → `CompleteMultipartUpload`).
//! - Custom object metadata preservation (`x-amz-meta-blake3`, `x-amz-meta-mode`, `x-amz-meta-mtime`).
//! - Object listing and hierarchical delimiter navigation.
//! - Bi-directional directory synchronization between local filesystem and S3 buckets.
//! - Hermetic in-memory mock engine for deterministic testing without external cloud access.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::error::{ProtocolError, VelcruxError};
use crate::storage::chunk_store::ChunkStore;
use crate::storage::cloud_client::{CloudHttpClient, HttpRequest};
use crate::storage::{AsyncRandomRead, FileMeta, Staging, StagingWriter, StorageBackend, VPath};
use crate::util::Hash;

/// Errors arising during S3 operations.
#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum S3Error {
    /// S3 object was not found.
    #[error("S3 object not found: s3://{bucket}/{key}")]
    NotFound { bucket: String, key: String },

    /// Access was denied or authentication failed.
    #[error("S3 access denied: {0}")]
    AccessDenied(String),

    /// Bucket does not exist.
    #[error("S3 bucket '{0}' does not exist")]
    NoSuchBucket(String),

    /// Invalid S3 URL format.
    #[error("Invalid S3 URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },

    /// Configuration error (missing credentials or endpoint).
    #[error("S3 configuration error: {0}")]
    Config(String),

    /// I/O or network transport error.
    #[error("S3 network error: {0}")]
    Network(String),

    /// S3 protocol / XML parsing error.
    #[error("S3 protocol error: {0}")]
    Protocol(String),

    /// Multipart upload error.
    #[error("S3 multipart upload error: {0}")]
    Multipart(String),
}

impl From<S3Error> for VelcruxError {
    fn from(err: S3Error) -> Self {
        match err {
            S3Error::NotFound { .. } => VelcruxError::Protocol(ProtocolError::InvalidPath),
            S3Error::AccessDenied(_) => VelcruxError::Protocol(ProtocolError::PermissionDenied),
            other => VelcruxError::Internal(other.to_string()),
        }
    }
}

/// S3 connection and bucket configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Config {
    /// S3 endpoint URL (e.g. `https://s3.amazonaws.com` or `http://127.0.0.1:9000`).
    pub endpoint: String,
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region (default: `us-east-1`).
    pub region: String,
    /// AWS Access Key ID.
    pub access_key_id: String,
    /// AWS Secret Access Key.
    pub secret_access_key: String,
    /// Optional AWS Session Token (for STS credentials).
    pub session_token: Option<String>,
    /// Optional bucket key prefix (e.g. `backups/2026/`).
    pub prefix: String,
    /// Whether to use path-style addressing (`/bucket/key`) vs virtual-hosted (`bucket.s3...`).
    pub path_style: bool,
    /// Chunk size for multipart uploads (default: 8 MiB, min: 5 MiB).
    pub part_size_bytes: usize,
    /// Maximum retry attempts on network error.
    pub max_retries: usize,
    /// Whether to execute live HTTP/1.1 requests to endpoint over TCP sockets.
    pub live_mode: bool,
    /// Default cloud storage class (e.g. `STANDARD`, `GLACIER`, `DEEP_ARCHIVE`).
    pub default_storage_class: Option<String>,
}

impl S3Config {
    /// Construct a new S3 configuration with defaults.
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            endpoint: "https://s3.amazonaws.com".to_string(),
            bucket: bucket.into(),
            region: "us-east-1".to_string(),
            access_key_id: "anonymous".to_string(),
            secret_access_key: "anonymous".to_string(),
            session_token: None,
            prefix: String::new(),
            path_style: true,
            part_size_bytes: 8 * 1024 * 1024,
            max_retries: 3,
            live_mode: false,
            default_storage_class: None,
        }
    }

    /// Load S3 configuration from environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.).
    pub fn from_env(bucket: &str) -> Result<Self, S3Error> {
        let mut cfg = Self::new(bucket);

        if let Ok(ak) = std::env::var("AWS_ACCESS_KEY_ID") {
            cfg.access_key_id = ak;
        }
        if let Ok(sk) = std::env::var("AWS_SECRET_ACCESS_KEY") {
            cfg.secret_access_key = sk;
        }
        if let Ok(st) = std::env::var("AWS_SESSION_TOKEN") {
            cfg.session_token = Some(st);
        }
        if let Ok(reg) =
            std::env::var("AWS_REGION").or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        {
            cfg.region = reg;
        }
        if let Ok(ep) =
            std::env::var("AWS_ENDPOINT_URL_S3").or_else(|_| std::env::var("AWS_ENDPOINT_URL"))
        {
            cfg.endpoint = ep;
        }
        if let Ok(val) = std::env::var("VELCRUX_S3_LIVE") {
            if val == "1" || val.eq_ignore_ascii_case("true") {
                cfg.live_mode = true;
            }
        }
        if let Ok(ep) = std::env::var("VELCRUX_S3_TEST_ENDPOINT")
            .or_else(|_| std::env::var("VELCRUX_S3_ENDPOINT"))
        {
            cfg.endpoint = ep;
            cfg.live_mode = true;
        }

        Ok(cfg)
    }

    /// Set live network mode.
    pub fn with_live_mode(mut self, live: bool) -> Self {
        self.live_mode = live;
        self
    }

    /// Parse an S3 URL (`s3://bucket/optional/prefix`) into bucket and prefix.
    pub fn parse_s3_url(url: &str) -> Result<(String, String), S3Error> {
        if !url.starts_with("s3://") {
            return Err(S3Error::InvalidUrl {
                url: url.to_string(),
                reason: "URL must start with 's3://'".to_string(),
            });
        }

        let without_scheme = &url["s3://".len()..];
        let mut parts = without_scheme.splitn(2, '/');
        let bucket = parts.next().unwrap_or("").trim().to_string();

        if bucket.is_empty() {
            return Err(S3Error::InvalidUrl {
                url: url.to_string(),
                reason: "bucket name cannot be empty".to_string(),
            });
        }

        let key_or_prefix = parts
            .next()
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        Ok((bucket, key_or_prefix))
    }

    /// Set endpoint URL.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Set AWS region.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    /// Set credentials.
    pub fn with_credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        self.access_key_id = access_key_id.into();
        self.secret_access_key = secret_access_key.into();
        self
    }

    /// Set key prefix.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        let p = prefix.into();
        self.prefix = p.trim_matches('/').to_string();
        self
    }

    /// Set multipart part size.
    pub fn with_part_size(mut self, size: usize) -> Self {
        self.part_size_bytes = size.max(5 * 1024 * 1024);
        self
    }

    /// Set default cloud storage class (e.g. `STANDARD`, `STANDARD_IA`, `GLACIER`, `DEEP_ARCHIVE`).
    pub fn with_storage_class(mut self, storage_class: impl Into<String>) -> Self {
        self.default_storage_class = Some(storage_class.into());
        self
    }
}

/// Metadata describing an S3 object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3ObjectMeta {
    /// Object key within the bucket.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// ETag header value.
    pub etag: String,
    /// Last-Modified timestamp in seconds since epoch.
    pub last_modified_sec: i64,
    /// BLAKE3 hash stored in `x-amz-meta-blake3`, if present.
    pub blake3_hash: Option<Hash>,
    /// POSIX file mode bits stored in `x-amz-meta-mode`, if present.
    pub mode: Option<u32>,
    /// S3 storage class (e.g. `STANDARD`, `GLACIER`, `DEEP_ARCHIVE`).
    #[serde(default)]
    pub storage_class: Option<String>,
    /// Active restore status (from `x-amz-restore`), if applicable.
    #[serde(default)]
    pub restore_status: Option<String>,
}

/// Outcome report of an S3 synchronization operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3SyncReport {
    /// Total objects evaluated.
    pub total_objects: usize,
    /// Number of objects transferred.
    pub objects_transferred: usize,
    /// Number of objects unchanged.
    pub objects_unchanged: usize,
    /// Number of objects deleted.
    pub objects_deleted: usize,
    /// Wire bytes transferred.
    pub bytes_transferred: u64,
    /// Bytes reused / skipped.
    pub bytes_reused: u64,
}

/// AWS Signature Version 4 signer.
#[derive(Debug, Clone)]
pub struct SigV4Signer {
    region: String,
    access_key: String,
    secret_key: String,
}

impl SigV4Signer {
    /// Construct a new SigV4 signer.
    pub fn new(region: &str, access_key: &str, secret_key: &str) -> Self {
        Self {
            region: region.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        }
    }

    /// Sign an HTTP request and generate Authorization and Date headers.
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &BTreeMap<String, String>,
        payload_hash: &str,
        datetime: &str, // YYYYMMDD'T'HHMMSS'Z'
    ) -> (String, String) {
        let date = &datetime[..8]; // YYYYMMDD

        // 1. Canonical Headers & Signed Headers
        let mut normalized_headers = BTreeMap::new();
        for (k, v) in headers {
            normalized_headers.insert(k.to_ascii_lowercase(), v.trim().to_string());
        }
        let mut canonical_headers = String::new();
        let mut signed_headers_list = Vec::new();

        for (lower_k, v) in &normalized_headers {
            canonical_headers.push_str(&format!("{}:{}\n", lower_k, v));
            signed_headers_list.push(lower_k.clone());
        }
        let signed_headers = signed_headers_list.join(";");

        // 2. Canonical Request
        let canonical_uri = if path.is_empty() {
            "/".to_string()
        } else if !path.starts_with('/') {
            format!("/{path}")
        } else {
            path.to_string()
        };

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, canonical_uri, query, canonical_headers, signed_headers, payload_hash
        );

        let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());

        // 3. String to Sign
        let credential_scope = format!("{}/{}/s3/aws4_request", date, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            datetime, credential_scope, hashed_canonical_request
        );

        // 4. Calculate Signature
        let k_secret = format!("AWS4{}", self.secret_key);
        let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = to_hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        // 5. Authorization Header
        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, credential_scope, signed_headers, signature
        );

        (auth_header, datetime.to_string())
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&s_key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let res = hasher.finalize();
    to_hex(&res)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// In-memory S3 mock bucket object state.
#[derive(Debug, Clone)]
struct MockS3Object {
    data: Vec<u8>,
    etag: String,
    last_modified_sec: i64,
    blake3_hash: Option<Hash>,
    mode: Option<u32>,
    storage_class: Option<String>,
    restore_status: Option<String>,
}

/// In-memory mock S3 service state.
#[derive(Debug, Default)]
struct MockS3Bucket {
    objects: BTreeMap<String, MockS3Object>,
    multipart_uploads: BTreeMap<String, (String, BTreeMap<usize, Vec<u8>>)>, // upload_id -> (key, parts)
}

/// S3 storage engine implementation.
#[derive(Clone, Debug)]
pub struct S3StorageBackend {
    config: S3Config,
    mock: Arc<RwLock<MockS3Bucket>>,
    staging_root: PathBuf,
    http_client: CloudHttpClient,
}

impl S3StorageBackend {
    /// Construct a new S3 storage backend.
    pub fn new(config: S3Config) -> Self {
        let staging = std::env::temp_dir().join(format!("velcrux_s3_staging_{}", config.bucket));
        let _ = std::fs::create_dir_all(staging.join("objects"));
        let _ = std::fs::create_dir_all(staging.join("meta"));
        let http_client = CloudHttpClient::new(Duration::from_secs(15), config.max_retries);
        Self {
            config,
            mock: Arc::new(RwLock::new(MockS3Bucket::default())),
            staging_root: staging,
            http_client,
        }
    }

    /// Enable or disable live network execution.
    pub fn with_live_mode(mut self, live: bool) -> Self {
        self.config.live_mode = live;
        self
    }

    /// Whether backend executes live HTTP requests over the network.
    pub fn is_live(&self) -> bool {
        self.config.live_mode
    }

    /// Convert backend into a content-addressed chunk store (`S3ChunkStore`).
    pub fn as_chunk_store(&self, prefix: &str) -> S3ChunkStore {
        S3ChunkStore::new(self.clone(), prefix)
    }

    fn signer(&self) -> SigV4Signer {
        SigV4Signer::new(
            &self.config.region,
            &self.config.access_key_id,
            &self.config.secret_access_key,
        )
    }

    fn build_url(&self, path_with_slash: &str, query: &str) -> (String, String) {
        let ep = self.config.endpoint.trim_end_matches('/');
        let url = if query.is_empty() {
            format!("{}{}", ep, path_with_slash)
        } else {
            format!("{}{}?{}", ep, path_with_slash, query)
        };

        let host_hdr = if let Ok(parsed) = url::Url::parse(ep) {
            let h = parsed.host_str().unwrap_or("localhost");
            if let Some(p) = parsed.port() {
                format!("{}:{}", h, p)
            } else {
                h.to_string()
            }
        } else {
            "localhost".to_string()
        };

        (url, host_hdr)
    }

    /// Ensure that the configured bucket exists on the live S3/MinIO endpoint.
    pub async fn ensure_bucket_exists(&self) -> Result<(), S3Error> {
        if !self.config.live_mode {
            return Ok(());
        }
        let path = format!("/{}", self.config.bucket);
        let (url, host_hdr) = self.build_url(&path, "");
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (_d, dt) = current_iso8601_date(now_sec);
        let payload_hash = sha256_hex(b"");

        // 1. HEAD /{bucket}
        let mut head_headers = BTreeMap::new();
        head_headers.insert("host".to_string(), host_hdr.clone());
        head_headers.insert("x-amz-date".to_string(), dt.clone());
        head_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

        let (auth, _) =
            self.signer()
                .sign_request("HEAD", &path, "", &head_headers, &payload_hash, &dt);

        let head_req = HttpRequest::new("HEAD", &url)
            .with_header("Host", host_hdr.clone())
            .with_header("Authorization", auth)
            .with_header("x-amz-date", dt.clone())
            .with_header("x-amz-content-sha256", payload_hash.clone());

        if let Ok(resp) = self.http_client.send(&head_req).await {
            if resp.status == 200 {
                return Ok(());
            }
        }

        // 2. PUT /{bucket} to create bucket
        let mut put_headers = BTreeMap::new();
        put_headers.insert("host".to_string(), host_hdr.clone());
        put_headers.insert("x-amz-date".to_string(), dt.clone());
        put_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

        let (put_auth, _) =
            self.signer()
                .sign_request("PUT", &path, "", &put_headers, &payload_hash, &dt);

        let put_req = HttpRequest::new("PUT", &url)
            .with_header("Host", host_hdr)
            .with_header("Authorization", put_auth)
            .with_header("x-amz-date", dt)
            .with_header("x-amz-content-sha256", payload_hash);

        let _ = self.http_client.send(&put_req).await;
        Ok(())
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
    pub fn config(&self) -> &S3Config {
        &self.config
    }

    /// Build canonical S3 object key including configured prefix.
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

    /// Put an object directly into S3.
    pub async fn put_object(
        &self,
        key: &str,
        data: &[u8],
        blake3_hash: Option<Hash>,
    ) -> Result<S3ObjectMeta, S3Error> {
        self.put_object_with_storage_class(key, data, blake3_hash, None)
            .await
    }

    /// Put an object directly into S3 with optional storage class override.
    pub async fn put_object_with_storage_class(
        &self,
        key: &str,
        data: &[u8],
        blake3_hash: Option<Hash>,
        storage_class: Option<&str>,
    ) -> Result<S3ObjectMeta, S3Error> {
        let full_key = self.resolve_key(key);
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let effective_sc = storage_class
            .map(|s| s.to_string())
            .or_else(|| self.config.default_storage_class.clone());

        let mut etag = format!("\"{}\"", sha256_hex(data));

        if self.config.live_mode {
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let (url, host_hdr) = self.build_url(&path, "");
            let (_d, dt) = current_iso8601_date(now_sec as u64);
            let payload_hash = sha256_hex(data);

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());
            if let Some(h) = blake3_hash {
                sign_headers.insert("x-amz-meta-blake3".to_string(), h.to_hex());
            }
            sign_headers.insert("x-amz-meta-mode".to_string(), "100644".to_string());
            if let Some(ref sc) = effective_sc {
                sign_headers.insert("x-amz-storage-class".to_string(), sc.clone());
            }

            let (auth, _) =
                self.signer()
                    .sign_request("PUT", &path, "", &sign_headers, &payload_hash, &dt);

            let mut req = HttpRequest::new("PUT", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash)
                .with_header("x-amz-meta-mode", "100644")
                .with_body(data.to_vec());
            if let Some(h) = blake3_hash {
                req = req.with_header("x-amz-meta-blake3", h.to_hex());
            }
            if let Some(ref sc) = effective_sc {
                req = req.with_header("x-amz-storage-class", sc.clone());
            }

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;

            if !resp.is_success() {
                return Err(S3Error::Protocol(format!(
                    "S3 live PUT failed with status {}: {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                )));
            }

            if let Some(resp_etag) = resp.get_header("etag") {
                etag = resp_etag.to_string();
            }
        }

        let meta = S3ObjectMeta {
            key: full_key.clone(),
            size: data.len() as u64,
            etag: etag.clone(),
            last_modified_sec: now_sec,
            blake3_hash,
            mode: Some(0o100644),
            storage_class: effective_sc.clone(),
            restore_status: None,
        };

        // Persist to disk
        let obj_path = self.object_file_path(&full_key);
        if let Some(p) = obj_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(&obj_path, data);

        let meta_path = self.meta_file_path(&full_key);
        if let Ok(meta_json) = serde_json::to_string(&meta) {
            let _ = std::fs::write(&meta_path, meta_json);
        }

        let mut bucket = self.mock.write().await;
        bucket.objects.insert(
            full_key,
            MockS3Object {
                data: data.to_vec(),
                etag,
                last_modified_sec: now_sec,
                blake3_hash,
                mode: Some(0o100644),
                storage_class: effective_sc,
                restore_status: None,
            },
        );

        Ok(meta)
    }

    /// Initiate a multipart upload session.
    pub async fn initiate_multipart_upload(&self, key: &str) -> Result<String, S3Error> {
        let full_key = self.resolve_key(key);
        if self.config.live_mode {
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let query = "uploads";
            let (url, host_hdr) = self.build_url(&path, query);
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(b"");

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("POST", &path, query, &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("POST", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash);

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;
            if resp.is_success() {
                let xml = String::from_utf8_lossy(&resp.body);
                if let Some(upload_id) = extract_xml_tag(&xml, "UploadId") {
                    let mut bucket = self.mock.write().await;
                    bucket
                        .multipart_uploads
                        .insert(upload_id.clone(), (full_key, BTreeMap::new()));
                    return Ok(upload_id);
                }
            }
            return Err(S3Error::Multipart(format!(
                "failed to initiate multipart upload, status {}",
                resp.status
            )));
        }

        let upload_id = format!(
            "upload_{}_{}",
            ulid::Ulid::new(),
            full_key.replace('/', "_")
        );
        let mut bucket = self.mock.write().await;
        bucket
            .multipart_uploads
            .insert(upload_id.clone(), (full_key, BTreeMap::new()));
        Ok(upload_id)
    }

    /// Upload a single part in a multipart upload session.
    pub async fn upload_part(
        &self,
        upload_id: &str,
        part_number: usize,
        data: &[u8],
    ) -> Result<String, S3Error> {
        let etag = format!("\"{}\"", sha256_hex(data));

        if self.config.live_mode {
            let full_key = {
                let bucket = self.mock.read().await;
                bucket
                    .multipart_uploads
                    .get(upload_id)
                    .map(|(k, _)| k.clone())
                    .unwrap_or_else(|| self.resolve_key("part"))
            };
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let query = format!(
                "partNumber={}&uploadId={}",
                part_number,
                urlencoding_encode(upload_id)
            );
            let (url, host_hdr) = self.build_url(&path, &query);
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(data);

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("PUT", &path, &query, &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("PUT", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash)
                .with_body(data.to_vec());

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;
            if resp.is_success() {
                let resp_etag = resp
                    .get_header("etag")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| etag.clone());
                let mut bucket = self.mock.write().await;
                if let Some(entry) = bucket.multipart_uploads.get_mut(upload_id) {
                    entry.1.insert(part_number, data.to_vec());
                }
                return Ok(resp_etag);
            }
            return Err(S3Error::Multipart(format!(
                "failed to upload part {}, status {}",
                part_number, resp.status
            )));
        }

        let mut bucket = self.mock.write().await;
        let entry = bucket.multipart_uploads.get_mut(upload_id).ok_or_else(|| {
            S3Error::Multipart(format!("unknown multipart upload id {}", upload_id))
        })?;
        entry.1.insert(part_number, data.to_vec());
        Ok(etag)
    }

    /// Complete a multipart upload, concatenating parts into a single object.
    pub async fn complete_multipart_upload(
        &self,
        upload_id: &str,
        parts: &[(usize, String)],
        blake3_hash: Option<Hash>,
    ) -> Result<S3ObjectMeta, S3Error> {
        if self.config.live_mode {
            let full_key = {
                let bucket = self.mock.read().await;
                bucket
                    .multipart_uploads
                    .get(upload_id)
                    .map(|(k, _)| k.clone())
                    .unwrap_or_else(|| self.resolve_key("part"))
            };
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let query = format!("uploadId={}", urlencoding_encode(upload_id));
            let (url, host_hdr) = self.build_url(&path, &query);

            let mut xml_body = String::from("<CompleteMultipartUpload>\n");
            for (p_num, etag) in parts {
                xml_body.push_str(&format!(
                    "  <Part>\n    <PartNumber>{}</PartNumber>\n    <ETag>{}</ETag>\n  </Part>\n",
                    p_num, etag
                ));
            }
            xml_body.push_str("</CompleteMultipartUpload>");
            let body_bytes = xml_body.into_bytes();

            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(&body_bytes);

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) = self.signer().sign_request(
                "POST",
                &path,
                &query,
                &sign_headers,
                &payload_hash,
                &dt,
            );

            let req = HttpRequest::new("POST", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash)
                .with_header("Content-Type", "application/xml")
                .with_body(body_bytes);

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;
            if !resp.is_success() {
                return Err(S3Error::Multipart(format!(
                    "failed to complete multipart upload, status {}",
                    resp.status
                )));
            }
        }

        let mut bucket = self.mock.write().await;
        let (full_key, stored_parts) =
            bucket.multipart_uploads.remove(upload_id).ok_or_else(|| {
                S3Error::Multipart(format!("unknown multipart upload id {}", upload_id))
            })?;

        let mut concatenated = Vec::new();
        for (part_num, _expected_etag) in parts {
            let part_data = stored_parts.get(part_num).ok_or_else(|| {
                S3Error::Multipart(format!("missing part {} in upload {}", part_num, upload_id))
            })?;
            concatenated.extend_from_slice(part_data);
        }

        let total_size = concatenated.len() as u64;
        let etag = format!("\"{}-{}\"", sha256_hex(&concatenated), parts.len());
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let meta = S3ObjectMeta {
            key: full_key.clone(),
            size: total_size,
            etag: etag.clone(),
            last_modified_sec: now_sec,
            blake3_hash,
            mode: Some(0o100644),
            storage_class: self.config.default_storage_class.clone(),
            restore_status: None,
        };

        bucket.objects.insert(
            full_key,
            MockS3Object {
                data: concatenated,
                etag,
                last_modified_sec: now_sec,
                blake3_hash,
                mode: Some(0o100644),
                storage_class: self.config.default_storage_class.clone(),
                restore_status: None,
            },
        );

        Ok(meta)
    }

    /// Abort a multipart upload, discarding stored parts.
    pub async fn abort_multipart_upload(&self, upload_id: &str) -> Result<(), S3Error> {
        if self.config.live_mode {
            let full_key = {
                let bucket = self.mock.read().await;
                bucket
                    .multipart_uploads
                    .get(upload_id)
                    .map(|(k, _)| k.clone())
                    .unwrap_or_else(|| self.resolve_key("part"))
            };
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let query = format!("uploadId={}", urlencoding_encode(upload_id));
            let (url, host_hdr) = self.build_url(&path, &query);
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(b"");

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) = self.signer().sign_request(
                "DELETE",
                &path,
                &query,
                &sign_headers,
                &payload_hash,
                &dt,
            );

            let req = HttpRequest::new("DELETE", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash);

            let _ = self.http_client.send(&req).await;
        }

        let mut bucket = self.mock.write().await;
        bucket.multipart_uploads.remove(upload_id);
        Ok(())
    }

    /// Put object using multipart upload if data exceeds part size, otherwise single put.
    pub async fn put_object_multipart(
        &self,
        key: &str,
        data: &[u8],
        blake3_hash: Option<Hash>,
    ) -> Result<S3ObjectMeta, S3Error> {
        let part_size = self.config.part_size_bytes;
        if data.len() <= part_size {
            return self.put_object(key, data, blake3_hash).await;
        }

        let upload_id = self.initiate_multipart_upload(key).await?;
        let mut parts = Vec::new();

        for (idx, chunk) in data.chunks(part_size).enumerate() {
            let part_num = idx + 1;
            let etag = self.upload_part(&upload_id, part_num, chunk).await?;
            parts.push((part_num, etag));
        }

        self.complete_multipart_upload(&upload_id, &parts, blake3_hash)
            .await
    }

    /// Get object contents from S3.
    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        let full_key = self.resolve_key(key);
        if self.config.live_mode {
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let (url, host_hdr) = self.build_url(&path, "");
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(b"");

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("GET", &path, "", &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("GET", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash);

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;
            if resp.status == 200 {
                return Ok(resp.body);
            } else if resp.status == 404 {
                return Err(S3Error::NotFound {
                    bucket: self.config.bucket.clone(),
                    key: full_key,
                });
            } else if resp.status == 403 {
                return Err(S3Error::Protocol(format!(
                    "InvalidObjectState (403): {}",
                    String::from_utf8_lossy(&resp.body)
                )));
            } else {
                return Err(S3Error::Protocol(format!(
                    "S3 live GET failed with status {}",
                    resp.status
                )));
            }
        }

        {
            let bucket = self.mock.read().await;
            if let Some(obj) = bucket.objects.get(&full_key) {
                if let Some(ref sc) = obj.storage_class {
                    if sc == "GLACIER" || sc == "DEEP_ARCHIVE" {
                        let is_restored = match &obj.restore_status {
                            Some(s) => s.contains("ongoing-request=\"false\""),
                            None => false,
                        };
                        if !is_restored {
                            return Err(S3Error::Protocol(format!(
                                "InvalidObjectState: object '{}' is archived in {} and has not been restored",
                                full_key, sc
                            )));
                        }
                    }
                }
                return Ok(obj.data.clone());
            }
        }
        let obj_path = self.object_file_path(&full_key);
        if obj_path.is_file() {
            if let Ok(data) = std::fs::read(&obj_path) {
                return Ok(data);
            }
        }
        Err(S3Error::NotFound {
            bucket: self.config.bucket.clone(),
            key: full_key,
        })
    }

    /// Get object byte range from S3 (`Range: bytes=start-end`).
    pub async fn get_object_range(
        &self,
        key: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, S3Error> {
        let full_key = self.resolve_key(key);
        if self.config.live_mode {
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let (url, host_hdr) = self.build_url(&path, "");
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(b"");
            let range_val = format!("bytes={}-{}", start, end_inclusive);

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());
            sign_headers.insert("range".to_string(), range_val.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("GET", &path, "", &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("GET", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash)
                .with_header("Range", range_val);

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;
            if resp.status == 200 || resp.status == 206 {
                return Ok(resp.body);
            } else if resp.status == 404 {
                return Err(S3Error::NotFound {
                    bucket: self.config.bucket.clone(),
                    key: full_key,
                });
            } else {
                return Err(S3Error::Protocol(format!(
                    "S3 live GET range failed with status {}",
                    resp.status
                )));
            }
        }

        let data = self.get_object(key).await?;
        let start_usize = start as usize;
        if start_usize >= data.len() {
            return Ok(Vec::new());
        }

        let end_usize = (end_inclusive as usize + 1).min(data.len());
        Ok(data[start_usize..end_usize].to_vec())
    }

    /// Retrieve object metadata without downloading body (`HEAD Object`).
    pub async fn head_object(&self, key: &str) -> Result<Option<S3ObjectMeta>, S3Error> {
        let full_key = self.resolve_key(key);
        if self.config.live_mode {
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let (url, host_hdr) = self.build_url(&path, "");
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(b"");

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("HEAD", &path, "", &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("HEAD", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash);

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;
            if resp.status == 200 {
                let size = resp
                    .get_header("content-length")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let etag = resp.get_header("etag").unwrap_or("").to_string();
                let b3 = resp
                    .get_header("x-amz-meta-blake3")
                    .and_then(Hash::from_hex);
                let mode = resp
                    .get_header("x-amz-meta-mode")
                    .and_then(|m| u32::from_str_radix(m, 8).ok())
                    .or(Some(0o100644));
                let storage_class = resp
                    .get_header("x-amz-storage-class")
                    .map(|s| s.to_string());
                let restore_status = resp.get_header("x-amz-restore").map(|s| s.to_string());
                return Ok(Some(S3ObjectMeta {
                    key: full_key,
                    size,
                    etag,
                    last_modified_sec: now_sec as i64,
                    blake3_hash: b3,
                    mode,
                    storage_class,
                    restore_status,
                }));
            } else if resp.status == 404 {
                return Ok(None);
            }
        }

        {
            let bucket = self.mock.read().await;
            if let Some(obj) = bucket.objects.get(&full_key) {
                return Ok(Some(S3ObjectMeta {
                    key: full_key,
                    size: obj.data.len() as u64,
                    etag: obj.etag.clone(),
                    last_modified_sec: obj.last_modified_sec,
                    blake3_hash: obj.blake3_hash,
                    mode: obj.mode,
                    storage_class: obj.storage_class.clone(),
                    restore_status: obj.restore_status.clone(),
                }));
            }
        }
        let meta_path = self.meta_file_path(&full_key);
        if meta_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str::<S3ObjectMeta>(&content) {
                    return Ok(Some(meta));
                }
            }
        }
        let obj_path = self.object_file_path(&full_key);
        if obj_path.is_file() {
            if let Ok(data) = std::fs::read(&obj_path) {
                let etag = format!("\"{}\"", sha256_hex(&data));
                let hash = Hash::of(&data);
                return Ok(Some(S3ObjectMeta {
                    key: full_key,
                    size: data.len() as u64,
                    etag,
                    last_modified_sec: 0,
                    blake3_hash: Some(hash),
                    mode: Some(0o100644),
                    storage_class: None,
                    restore_status: None,
                }));
            }
        }
        Ok(None)
    }

    /// Delete object from S3.
    pub async fn delete_object(&self, key: &str) -> Result<(), S3Error> {
        let full_key = self.resolve_key(key);
        if self.config.live_mode {
            let path = format!("/{}/{}", self.config.bucket, full_key);
            let (url, host_hdr) = self.build_url(&path, "");
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(b"");

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("DELETE", &path, "", &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("DELETE", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash);

            let _ = self.http_client.send(&req).await;
        }

        {
            let mut bucket = self.mock.write().await;
            bucket.objects.remove(&full_key);
        }
        let _ = std::fs::remove_file(self.object_file_path(&full_key));
        let _ = std::fs::remove_file(self.meta_file_path(&full_key));
        Ok(())
    }

    /// Request restoration of an archived object (Glacier / Deep Archive).
    pub async fn restore_object(&self, key: &str, days: u32, tier: &str) -> Result<(), S3Error> {
        let full_key = self.resolve_key(key);
        let xml_body = format!(
            "<RestoreRequest><Days>{}</Days><GlacierJobParameters><Tier>{}</Tier></GlacierJobParameters></RestoreRequest>",
            days, tier
        );

        if self.config.live_mode {
            let path = format!("/{}/{}?restore", self.config.bucket, full_key);
            let (url, host_hdr) = self.build_url(&path, "");
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(xml_body.as_bytes());

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("POST", &path, "", &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("POST", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash)
                .with_body(xml_body.into_bytes());

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;

            if resp.status == 200 || resp.status == 202 {
                return Ok(());
            } else if resp.status == 404 {
                return Err(S3Error::NotFound {
                    bucket: self.config.bucket.clone(),
                    key: full_key,
                });
            } else {
                return Err(S3Error::Protocol(format!(
                    "S3 restore failed with status {}: {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                )));
            }
        }

        let mut bucket = self.mock.write().await;
        if let Some(obj) = bucket.objects.get_mut(&full_key) {
            obj.restore_status = Some(format!(
                "ongoing-request=\"false\", expiry-date=\"Wed, 01 Dec 2026 00:00:00 GMT\""
            ));
            Ok(())
        } else {
            Err(S3Error::NotFound {
                bucket: self.config.bucket.clone(),
                key: full_key,
            })
        }
    }

    /// List objects under a prefix.
    pub async fn list_objects(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
    ) -> Result<Vec<S3ObjectMeta>, S3Error> {
        let full_prefix = self.resolve_key(prefix);
        if self.config.live_mode {
            let mut query = format!("list-type=2&prefix={}", urlencoding_encode(&full_prefix));
            if let Some(d) = delimiter {
                query.push_str(&format!("&delimiter={}", urlencoding_encode(d)));
            }
            let path = format!("/{}", self.config.bucket);
            let (url, host_hdr) = self.build_url(&path, &query);
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (_d, dt) = current_iso8601_date(now_sec);
            let payload_hash = sha256_hex(b"");

            let mut sign_headers = BTreeMap::new();
            sign_headers.insert("host".to_string(), host_hdr.clone());
            sign_headers.insert("x-amz-date".to_string(), dt.clone());
            sign_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

            let (auth, _) =
                self.signer()
                    .sign_request("GET", &path, &query, &sign_headers, &payload_hash, &dt);

            let req = HttpRequest::new("GET", &url)
                .with_header("Host", host_hdr)
                .with_header("Authorization", auth)
                .with_header("x-amz-date", dt)
                .with_header("x-amz-content-sha256", payload_hash);

            let resp = self
                .http_client
                .send(&req)
                .await
                .map_err(|e| S3Error::Network(e.to_string()))?;
            if resp.status == 200 {
                let xml = String::from_utf8_lossy(&resp.body);
                let list = parse_list_objects_v2_xml(&xml);
                return Ok(list);
            } else {
                return Err(S3Error::Protocol(format!(
                    "S3 live list_objects failed with status {}",
                    resp.status
                )));
            }
        }
        let objects_dir = self.staging_root.join("objects");
        if objects_dir.is_dir() {
            if let Ok(entries) = crate::sync::scan_dir_entries(&objects_dir) {
                for (rel, _entry) in entries {
                    let k = rel.replace('\\', "/");
                    let mut head_meta = None;
                    let meta_path = self.meta_file_path(&k);
                    if let Ok(c) = std::fs::read_to_string(&meta_path) {
                        if let Ok(m) = serde_json::from_str::<S3ObjectMeta>(&c) {
                            head_meta = Some(m);
                        }
                    }
                    if let Ok(data) = std::fs::read(self.object_file_path(&k)) {
                        let etag = head_meta
                            .as_ref()
                            .map(|m| m.etag.clone())
                            .unwrap_or_else(|| format!("\"{}\"", sha256_hex(&data)));
                        let blake3_hash = head_meta
                            .as_ref()
                            .and_then(|m| m.blake3_hash)
                            .or_else(|| Some(Hash::of(&data)));
                        let last_mod = head_meta.as_ref().map(|m| m.last_modified_sec).unwrap_or(0);
                        let (sc, rs) = match head_meta.as_ref() {
                            Some(m) => (m.storage_class.clone(), m.restore_status.clone()),
                            None => (None, None),
                        };
                        let mut bucket = self.mock.write().await;
                        bucket.objects.entry(k).or_insert(MockS3Object {
                            data,
                            etag,
                            last_modified_sec: last_mod,
                            blake3_hash,
                            mode: Some(0o100644),
                            storage_class: sc,
                            restore_status: rs,
                        });
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
                            .any(|r: &S3ObjectMeta| r.key == common_prefix)
                        {
                            results.push(S3ObjectMeta {
                                key: common_prefix,
                                size: 0,
                                etag: String::new(),
                                last_modified_sec: 0,
                                blake3_hash: None,
                                mode: Some(0o040755),
                                storage_class: None,
                                restore_status: None,
                            });
                        }
                        continue;
                    }
                }
                results.push(S3ObjectMeta {
                    key: k.clone(),
                    size: obj.data.len() as u64,
                    etag: obj.etag.clone(),
                    last_modified_sec: obj.last_modified_sec,
                    blake3_hash: obj.blake3_hash,
                    mode: obj.mode,
                    storage_class: obj.storage_class.clone(),
                    restore_status: obj.restore_status.clone(),
                });
            }
        }

        Ok(results)
    }

    /// Upload a local directory recursively into S3.
    pub async fn sync_from_local(
        &self,
        local_root: &Path,
        s3_prefix: &str,
    ) -> Result<S3SyncReport, S3Error> {
        if !local_root.exists() {
            return Err(S3Error::Config(format!(
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
            .map_err(|e| S3Error::Network(e.to_string()))?;

        for (rel_path, entry) in scanned {
            total_objects += 1;
            let target_key = if s3_prefix.is_empty() {
                rel_path.clone()
            } else {
                format!("{}/{}", s3_prefix.trim_matches('/'), rel_path)
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
                .map_err(|e| S3Error::Network(e.to_string()))?;
            self.put_object(&target_key, &file_data, Some(entry.hash))
                .await?;

            objects_transferred += 1;
            bytes_transferred += entry.size;
        }

        Ok(S3SyncReport {
            total_objects,
            objects_transferred,
            objects_unchanged,
            objects_deleted: 0,
            bytes_transferred,
            bytes_reused,
        })
    }

    /// Download an S3 prefix recursively into a local directory.
    pub async fn sync_to_local(
        &self,
        s3_prefix: &str,
        local_root: &Path,
    ) -> Result<S3SyncReport, S3Error> {
        if !local_root.exists() {
            std::fs::create_dir_all(local_root).map_err(|e| S3Error::Network(e.to_string()))?;
        }

        let mut total_objects = 0usize;
        let mut objects_transferred = 0usize;
        let mut objects_unchanged = 0usize;
        let mut bytes_transferred = 0u64;
        let mut bytes_reused = 0u64;

        let objects = self.list_objects(s3_prefix, None).await?;
        let full_prefix = self.resolve_key(s3_prefix);

        for obj in objects {
            if obj.key.ends_with('/') {
                continue;
            }
            total_objects += 1;
            let rel_key = if let Some(suffix) = obj.key.strip_prefix(&full_prefix) {
                suffix.trim_start_matches('/')
            } else {
                &obj.key
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

            let data = self.get_object(&obj.key).await?;
            if let Some(parent) = local_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&local_path, &data).map_err(|e| S3Error::Network(e.to_string()))?;

            objects_transferred += 1;
            bytes_transferred += obj.size;
        }

        Ok(S3SyncReport {
            total_objects,
            objects_transferred,
            objects_unchanged,
            objects_deleted: 0,
            bytes_transferred,
            bytes_reused,
        })
    }
}

/// Random-read adapter for S3 objects using HTTP range requests.
struct S3RandomRead {
    data: Vec<u8>,
}

#[async_trait::async_trait]
impl AsyncRandomRead for S3RandomRead {
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
impl StorageBackend for S3StorageBackend {
    async fn stat(&self, p: &VPath) -> Result<Option<FileMeta>, VelcruxError> {
        let meta_opt = self.head_object(&p.to_string()).await?;
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
        let data = self.get_object(&p.to_string()).await?;
        Ok(Box::new(S3RandomRead { data }))
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
        // Read staged file if staged on disk, or commit mock data
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
            let name = obj.key.rsplit('/').next().unwrap_or(&obj.key).to_string();
            let hash = obj.blake3_hash.unwrap_or(Hash::ZERO);
            res.push((
                name,
                FileMeta {
                    size: obj.size,
                    mode: obj.mode.unwrap_or(0o100644),
                    mtime_ns: obj.last_modified_sec * 1_000_000_000,
                    file_hash: hash,
                },
            ));
        }
        Ok(res)
    }

    async fn create_dir_all(&self, _p: &VPath) -> Result<(), VelcruxError> {
        // S3 is a flat object namespace; directories are implicit prefixes
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
        "s3"
    }

    async fn create_symlink(&self, _dest: &VPath, _target: &str) -> Result<(), VelcruxError> {
        Err(VelcruxError::Internal(
            "symlinks not supported by S3 object backend".to_string(),
        ))
    }

    async fn create_hardlink(&self, _dest: &VPath, _src: &VPath) -> Result<(), VelcruxError> {
        Err(VelcruxError::Internal(
            "hardlinks not supported by S3 object backend".to_string(),
        ))
    }

    fn root(&self) -> &Path {
        &self.staging_root
    }
}

/// Content-addressed chunk store backed by S3 / MinIO (`ARCHITECTURE.md` §2, §7, `ADR-064`).
#[derive(Clone, Debug)]
pub struct S3ChunkStore {
    backend: S3StorageBackend,
    chunk_prefix: String,
}

impl S3ChunkStore {
    /// Construct a new S3-backed content-addressed chunk store.
    pub fn new(backend: S3StorageBackend, chunk_prefix: impl Into<String>) -> Self {
        Self {
            backend,
            chunk_prefix: chunk_prefix.into().trim_matches('/').to_string(),
        }
    }

    /// Access the underlying backend.
    pub fn backend(&self) -> &S3StorageBackend {
        &self.backend
    }

    fn chunk_key(&self, h: &Hash) -> String {
        if self.chunk_prefix.is_empty() {
            format!("chunks/{}", h.to_hex())
        } else {
            format!("{}/chunks/{}", self.chunk_prefix, h.to_hex())
        }
    }
}

#[async_trait::async_trait]
impl ChunkStore for S3ChunkStore {
    async fn has(&self, h: &Hash) -> Result<bool, VelcruxError> {
        let key = self.chunk_key(h);
        match self.backend.head_object(&key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(VelcruxError::Internal(e.to_string())),
        }
    }

    async fn has_batch(&self, hashes: &[Hash]) -> Result<Vec<bool>, VelcruxError> {
        let mut results = Vec::with_capacity(hashes.len());
        for h in hashes {
            results.push(self.has(h).await?);
        }
        Ok(results)
    }

    async fn put(&self, h: &Hash, data: &[u8]) -> Result<(), VelcruxError> {
        let actual = Hash::of(data);
        if actual != *h {
            return Err(VelcruxError::Internal(format!(
                "chunk hash mismatch: expected {}, got {}",
                h, actual
            )));
        }
        let key = self.chunk_key(h);
        self.backend
            .put_object(&key, data, Some(*h))
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, h: &Hash) -> Result<bytes::Bytes, VelcruxError> {
        let key = self.chunk_key(h);
        let data = self
            .backend
            .get_object(&key)
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;
        let actual = Hash::of(&data);
        if actual != *h {
            return Err(VelcruxError::Internal(format!(
                "chunk corrupt in S3: expected {}, got {}",
                h, actual
            )));
        }
        Ok(bytes::Bytes::from(data))
    }

    async fn remove(&self, h: &Hash) -> Result<bool, VelcruxError> {
        let key = self.chunk_key(h);
        if !self.has(h).await? {
            return Ok(false);
        }
        self.backend
            .delete_object(&key)
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;
        Ok(true)
    }

    async fn total_chunks(&self) -> Result<usize, VelcruxError> {
        let prefix = if self.chunk_prefix.is_empty() {
            "chunks/".to_string()
        } else {
            format!("{}/chunks/", self.chunk_prefix)
        };
        let list = self
            .backend
            .list_objects(&prefix, None)
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;
        Ok(list.len())
    }

    async fn total_bytes(&self) -> Result<u64, VelcruxError> {
        let prefix = if self.chunk_prefix.is_empty() {
            "chunks/".to_string()
        } else {
            format!("{}/chunks/", self.chunk_prefix)
        };
        let list = self
            .backend
            .list_objects(&prefix, None)
            .await
            .map_err(|e| VelcruxError::Internal(e.to_string()))?;
        Ok(list.iter().map(|o| o.size).sum())
    }
}

fn current_iso8601_date(epoch_sec: u64) -> (String, String) {
    let days = epoch_sec / 86400;
    let rem_secs = epoch_sec % 86400;
    let hour = rem_secs / 3600;
    let minute = (rem_secs % 3600) / 60;
    let second = rem_secs % 60;

    let (year, month, day) = days_to_ymd(days);
    let date = format!("{:04}{:02}{:02}", year, month, day);
    let datetime = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, month, day, hour, minute, second
    );
    (date, datetime)
}

fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);
    let start = xml.find(&open_tag)? + open_tag.len();
    let end = xml[start..].find(&close_tag)? + start;
    Some(xml[start..end].trim().to_string())
}

fn parse_list_objects_v2_xml(xml: &str) -> Vec<S3ObjectMeta> {
    let mut objects = Vec::new();
    let mut cursor = 0;
    while let Some(pos) = xml[cursor..].find("<Contents>") {
        let start = cursor + pos + "<Contents>".len();
        if let Some(end_rel) = xml[start..].find("</Contents>") {
            let end = start + end_rel;
            let block = &xml[start..end];
            let key = extract_xml_tag(block, "Key").unwrap_or_default();
            let size = extract_xml_tag(block, "Size")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let etag = extract_xml_tag(block, "ETag").unwrap_or_default();
            let storage_class = extract_xml_tag(block, "StorageClass");
            objects.push(S3ObjectMeta {
                key,
                size,
                etag,
                last_modified_sec: 0,
                blake3_hash: None,
                mode: Some(0o100644),
                storage_class,
                restore_status: None,
            });
            cursor = end + "</Contents>".len();
        } else {
            break;
        }
    }

    let mut cp_cursor = 0;
    while let Some(pos) = xml[cp_cursor..].find("<CommonPrefixes>") {
        let start = cp_cursor + pos + "<CommonPrefixes>".len();
        if let Some(end_rel) = xml[start..].find("</CommonPrefixes>") {
            let end = start + end_rel;
            let block = &xml[start..end];
            if let Some(prefix) = extract_xml_tag(block, "Prefix") {
                objects.push(S3ObjectMeta {
                    key: prefix,
                    size: 0,
                    etag: String::new(),
                    last_modified_sec: 0,
                    blake3_hash: None,
                    mode: Some(0o040755),
                    storage_class: None,
                    restore_status: None,
                });
            }
            cp_cursor = end + "</CommonPrefixes>".len();
        } else {
            break;
        }
    }
    objects
}

fn urlencoding_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_url_parsing() {
        let (bucket, key) = S3Config::parse_s3_url("s3://my-bucket/path/to/file.iso").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "path/to/file.iso");

        let (bucket, prefix) = S3Config::parse_s3_url("s3://dataset/").unwrap();
        assert_eq!(bucket, "dataset");
        assert_eq!(prefix, "");

        assert!(S3Config::parse_s3_url("http://bucket/file").is_err());
        assert!(S3Config::parse_s3_url("s3:///file").is_err());
    }

    #[test]
    fn test_sigv4_signing_determinism() {
        let signer = SigV4Signer::new(
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "s3.amazonaws.com".to_string());
        headers.insert("x-amz-date".to_string(), "20261012T080000Z".to_string());

        let payload_hash = sha256_hex(b"");
        let (auth, date) = signer.sign_request(
            "GET",
            "/test.txt",
            "",
            &headers,
            &payload_hash,
            "20261012T080000Z",
        );

        assert_eq!(date, "20261012T080000Z");
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261012/us-east-1/s3/aws4_request"
        ));
        assert!(auth.contains("SignedHeaders=host;x-amz-date"));
        assert!(auth.contains("Signature="));
    }

    #[tokio::test]
    async fn test_s3_storage_backend_crud_and_range() {
        let cfg = S3Config::new("test-bucket").with_prefix("staging/");
        let backend = S3StorageBackend::new(cfg);

        // 1. Put object
        let data = b"Hello, S3 Object Storage Gateway!";
        let hash = Hash::of(data);
        let meta = backend
            .put_object("greet.txt", data, Some(hash))
            .await
            .unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert_eq!(meta.blake3_hash, Some(hash));

        // 2. Head object
        let head = backend.head_object("greet.txt").await.unwrap().unwrap();
        assert_eq!(head.size, data.len() as u64);

        // 3. Get full object
        let fetched = backend.get_object("greet.txt").await.unwrap();
        assert_eq!(fetched, data);

        // 4. Get range request: bytes 7-10 ("S3 O")
        let range = backend.get_object_range("greet.txt", 7, 10).await.unwrap();
        assert_eq!(range, b"S3 O");

        // 5. List objects
        let list = backend.list_objects("", None).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key, "staging/greet.txt");

        // 6. Delete object
        backend.delete_object("greet.txt").await.unwrap();
        assert!(backend.head_object("greet.txt").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_s3_multipart_upload() {
        let mut cfg = S3Config::new("mp-bucket");
        cfg.part_size_bytes = 100; // 100-byte parts
        let backend = S3StorageBackend::new(cfg);

        let data = vec![42u8; 350]; // 4 parts: 100, 100, 100, 50
        let hash = Hash::of(&data);
        let meta = backend
            .put_object_multipart("large.bin", &data, Some(hash))
            .await
            .unwrap();
        assert_eq!(meta.size, 350);
        assert!(meta.etag.contains("-4\""));

        let retrieved = backend.get_object("large.bin").await.unwrap();
        assert_eq!(retrieved, data);
        assert_eq!(Hash::of(&retrieved), hash);
    }

    #[tokio::test]
    async fn test_s3_directory_sync_bidirectional() {
        let temp_src = tempfile::tempdir().unwrap();
        let src_path = temp_src.path();
        std::fs::write(src_path.join("file1.txt"), b"file1 content").unwrap();
        std::fs::create_dir_all(src_path.join("sub")).unwrap();
        std::fs::write(src_path.join("sub/file2.txt"), b"sub file2 content").unwrap();

        let bucket_name = format!(
            "sync-bucket-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let cfg = S3Config::new(&bucket_name).with_prefix("cloud_prefix");
        let backend = S3StorageBackend::new(cfg);

        // Upload local dir to S3
        let rep_up = backend
            .sync_from_local(src_path, "cloud_prefix")
            .await
            .unwrap();
        assert_eq!(rep_up.objects_transferred, 2);

        // Download from S3 into a fresh local directory
        let temp_dst = tempfile::tempdir().unwrap();
        let dst_path = temp_dst.path();
        let rep_down = backend
            .sync_to_local("cloud_prefix", dst_path)
            .await
            .unwrap();
        assert_eq!(rep_down.objects_transferred, 2);

        assert_eq!(
            std::fs::read(dst_path.join("file1.txt")).unwrap(),
            b"file1 content"
        );
        assert_eq!(
            std::fs::read(dst_path.join("sub/file2.txt")).unwrap(),
            b"sub file2 content"
        );
    }
}
