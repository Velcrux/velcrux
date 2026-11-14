//! Type Definitions for Multi-Cloud Object Storage Tiering & Compaction (`ADR-079`).

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Result, VelcruxError};

/// Magic header bytes for Velcrux Tiered Container files (`b"VLXT"` = 0x564C5854).
pub const VLXT_CONTAINER_MAGIC: [u8; 4] = [0x56, 0x4C, 0x58, 0x54];

/// Current container format version.
pub const VLXT_CONTAINER_VERSION: u16 = 1;

/// Target container size in bytes (default: 64 MiB).
pub const DEFAULT_TARGET_CONTAINER_BYTES: u64 = 64 * 1024 * 1024;

/// Target container size in bytes (minimum: 1 MiB).
pub const MIN_CONTAINER_BYTES: u64 = 1024 * 1024;

/// Deletion / tombstone fragmentation threshold for compaction triggering (30%).
pub const DEFAULT_COMPACTION_FRAGMENTATION_THRESHOLD: f64 = 0.30;

/// Supported Cloud Object Storage Providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProviderKind {
    /// Amazon Simple Storage Service (AWS S3) or S3-compatible (MinIO, Ceph).
    AwsS3,
    /// Google Cloud Storage (GCS).
    GoogleGcs,
    /// Microsoft Azure Blob Storage.
    AzureBlob,
    /// Local NVMe / POSIX block cache tier.
    LocalPosix,
}

impl CloudProviderKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AwsS3 => "s3",
            Self::GoogleGcs => "gcs",
            Self::AzureBlob => "azure",
            Self::LocalPosix => "local",
        }
    }

    pub const fn scheme(&self) -> &'static str {
        match self {
            Self::AwsS3 => "s3://",
            Self::GoogleGcs => "gcs://",
            Self::AzureBlob => "azblob://",
            Self::LocalPosix => "file://",
        }
    }

    /// Translates a canonical tier to the provider's specific cloud storage class.
    pub fn cloud_storage_class(&self, tier: CloudTierClass) -> &'static str {
        match (self, tier) {
            (Self::AwsS3, CloudTierClass::Hot) => "STANDARD",
            (Self::AwsS3, CloudTierClass::Cool) => "STANDARD_IA",
            (Self::AwsS3, CloudTierClass::Cold) => "GLACIER",
            (Self::AwsS3, CloudTierClass::DeepArchive) => "DEEP_ARCHIVE",

            (Self::GoogleGcs, CloudTierClass::Hot) => "STANDARD",
            (Self::GoogleGcs, CloudTierClass::Cool) => "NEARLINE",
            (Self::GoogleGcs, CloudTierClass::Cold) => "COLDLINE",
            (Self::GoogleGcs, CloudTierClass::DeepArchive) => "ARCHIVE",

            (Self::AzureBlob, CloudTierClass::Hot) => "Hot",
            (Self::AzureBlob, CloudTierClass::Cool) => "Cool",
            (Self::AzureBlob, CloudTierClass::Cold) => "Cold",
            (Self::AzureBlob, CloudTierClass::DeepArchive) => "Archive",

            (Self::LocalPosix, CloudTierClass::Hot) => "nvme-hot",
            (Self::LocalPosix, CloudTierClass::Cool) => "ssd-warm",
            (Self::LocalPosix, CloudTierClass::Cold) => "hdd-cold",
            (Self::LocalPosix, CloudTierClass::DeepArchive) => "tape-archive",
        }
    }
}

impl fmt::Display for CloudProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for CloudProviderKind {
    type Err = VelcruxError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "s3" | "aws" | "aws_s3" | "minio" => Ok(Self::AwsS3),
            "gcs" | "google" | "google_gcs" => Ok(Self::GoogleGcs),
            "azure" | "azblob" | "azure_blob" => Ok(Self::AzureBlob),
            "local" | "posix" | "file" => Ok(Self::LocalPosix),
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unsupported cloud storage provider",
            ))),
        }
    }
}

/// Cloud Storage Tier Class representing price, performance, and retrieval latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudTierClass {
    /// Hot: Millisecond latency, active working set, highest storage cost, zero retrieval cost.
    Hot = 0,
    /// Cool / Infrequent: Low latency, 30-day minimum, lower storage cost, low retrieval fee.
    Cool = 1,
    /// Cold / Archive: 90-day minimum, very low storage cost, asynchronous retrieval (minutes to hours).
    Cold = 2,
    /// Deep Archive / Glacier: 180-day minimum, ultra-low storage cost, long retrieval delay (12-48 hours).
    DeepArchive = 3,
}

impl CloudTierClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Cool => "cool",
            Self::Cold => "cold",
            Self::DeepArchive => "deep_archive",
        }
    }

    /// Whether this tier requires asynchronous hydration (e.g. S3 RestoreObject) before reading.
    pub const fn requires_hydration(&self) -> bool {
        matches!(self, Self::Cold | Self::DeepArchive)
    }

    /// Typical retrieval latency in seconds.
    pub const fn typical_latency_secs(&self) -> u64 {
        match self {
            Self::Hot => 0,                 // < 20 ms
            Self::Cool => 0,                // < 50 ms
            Self::Cold => 3600 * 3,         // 3-5 hours standard
            Self::DeepArchive => 3600 * 12, // 12 hours standard
        }
    }

    /// Relative storage cost per GB-month normalized to Hot = 1.0.
    pub const fn relative_storage_cost(&self) -> f64 {
        match self {
            Self::Hot => 1.0,           // ~$0.023 / GB
            Self::Cool => 0.54,         // ~$0.0125 / GB
            Self::Cold => 0.17,         // ~$0.004 / GB
            Self::DeepArchive => 0.043, // ~$0.00099 / GB
        }
    }
}

impl fmt::Display for CloudTierClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for CloudTierClass {
    type Err = VelcruxError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hot" | "standard" => Ok(Self::Hot),
            "cool" | "warm" | "infrequent" | "ia" | "nearline" => Ok(Self::Cool),
            "cold" | "archive" | "glacier" | "coldline" => Ok(Self::Cold),
            "deep_archive" | "deeparchive" | "deep" | "frozen" => Ok(Self::DeepArchive),
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown cloud tier class",
            ))),
        }
    }
}

/// Universal Cloud Storage URI (`s3://bucket/key`, `gcs://bucket/key`, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudStorageUri {
    pub provider: CloudProviderKind,
    pub bucket_or_container: String,
    pub key: String,
}

impl CloudStorageUri {
    pub fn new(
        provider: CloudProviderKind,
        bucket_or_container: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            bucket_or_container: bucket_or_container.into(),
            key: key.into(),
        }
    }

    pub fn to_uri_string(&self) -> String {
        format!(
            "{}{}/{}",
            self.provider.scheme(),
            self.bucket_or_container,
            self.key.trim_start_matches('/')
        )
    }
}

impl fmt::Display for CloudStorageUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri_string())
    }
}

impl FromStr for CloudStorageUri {
    type Err = VelcruxError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (provider, rest) = if let Some(stripped) = s.strip_prefix("s3://") {
            (CloudProviderKind::AwsS3, stripped)
        } else if let Some(stripped) = s.strip_prefix("gcs://") {
            (CloudProviderKind::GoogleGcs, stripped)
        } else if let Some(stripped) = s.strip_prefix("azblob://") {
            (CloudProviderKind::AzureBlob, stripped)
        } else if let Some(stripped) = s.strip_prefix("file://") {
            (CloudProviderKind::LocalPosix, stripped)
        } else {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid cloud storage URI scheme; expected s3://, gcs://, azblob://, or file://",
            )));
        };

        let mut parts = rest.splitn(2, '/');
        let bucket = parts.next().unwrap_or("").to_string();
        let key = parts.next().unwrap_or("").to_string();

        if bucket.is_empty() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "cloud storage URI missing bucket or container name",
            )));
        }

        Ok(Self {
            provider,
            bucket_or_container: bucket,
            key,
        })
    }
}

/// Compression codec for compacted cloud containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionCodec {
    None = 0,
    Zstd = 1,
}

impl CompressionCodec {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
        }
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::None => Ok(data.to_vec()),
            Self::Zstd => zstd::encode_all(data, 3).map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("zstd compression failure"))
            }),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::None => Ok(data.to_vec()),
            Self::Zstd => zstd::decode_all(data).map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("zstd decompression failure"))
            }),
        }
    }
}

/// Metadata descriptor for a single FastCDC chunk inside a compacted cloud container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkDescriptor {
    /// 32-byte BLAKE3 content-addressed hash of the raw uncompressed chunk.
    pub chunk_hash: [u8; 32],
    /// Absolute byte offset where the chunk payload begins inside the container.
    pub offset_in_container: u64,
    /// Compressed length stored in the container payload.
    pub compressed_len: u32,
    /// Original uncompressed size of the chunk.
    pub uncompressed_len: u32,
    /// CRC32C checksum of the compressed chunk payload.
    pub checksum_crc32c: u32,
    /// Whether this chunk has been tombstoned / marked deleted by garbage collection.
    pub tombstoned: bool,
    /// Unix timestamp when the chunk was added to the container.
    pub added_at: u64,
    /// Read access frequency counter for temperature scoring.
    pub access_count: u32,
    /// Unix timestamp of the most recent read access.
    pub last_accessed_at: u64,
}

impl ChunkDescriptor {
    pub fn new(
        chunk_hash: [u8; 32],
        offset_in_container: u64,
        compressed_len: u32,
        uncompressed_len: u32,
        checksum_crc32c: u32,
        timestamp: u64,
    ) -> Self {
        Self {
            chunk_hash,
            offset_in_container,
            compressed_len,
            uncompressed_len,
            checksum_crc32c,
            tombstoned: false,
            added_at: timestamp,
            access_count: 0,
            last_accessed_at: timestamp,
        }
    }

    pub fn chunk_hash_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for &b in &self.chunk_hash {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
}

/// Binary header prefix for compacted container files (`VLXT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub container_id: String,
    pub provider: CloudProviderKind,
    pub tier: CloudTierClass,
    pub codec: CompressionCodec,
    pub chunk_count: u32,
    pub total_uncompressed_bytes: u64,
    pub total_compressed_bytes: u64,
    pub index_offset: u64,
    pub index_length: u32,
    pub payload_blake3: [u8; 32],
}

/// Asynchronous archive retrieval priority class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HydrationPriority {
    /// 1-5 minutes retrieval (e.g. S3 Glacier Expedited).
    Expedited = 0,
    /// 3-5 hours retrieval (e.g. S3 Glacier Standard, Azure Standard).
    Standard = 1,
    /// 12-48 hours retrieval (e.g. S3 Glacier Bulk, Deep Archive Bulk).
    Bulk = 2,
}

impl HydrationPriority {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Expedited => "expedited",
            Self::Standard => "standard",
            Self::Bulk => "bulk",
        }
    }

    pub const fn simulated_duration_secs(&self) -> u64 {
        match self {
            Self::Expedited => 60,      // 1 min
            Self::Standard => 3600 * 3, // 3 hours
            Self::Bulk => 3600 * 12,    // 12 hours
        }
    }
}

impl fmt::Display for HydrationPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for HydrationPriority {
    type Err = VelcruxError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "expedited" | "fast" => Ok(Self::Expedited),
            "standard" | "default" => Ok(Self::Standard),
            "bulk" | "slow" | "batch" => Ok(Self::Bulk),
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown hydration priority",
            ))),
        }
    }
}

/// Lifecycle status of an asynchronous cloud archive hydration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HydrationStatus {
    Pending = 0,
    Hydrating = 1,
    Hydrated = 2,
    Expired = 3,
}

impl HydrationStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Hydrating => "hydrating",
            Self::Hydrated => "hydrated",
            Self::Expired => "expired",
        }
    }

    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Hydrated)
    }
}

/// Asynchronous cloud hydration request record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationRequest {
    pub request_id: String,
    pub container_id: String,
    pub chunk_hash: [u8; 32],
    pub source_tier: CloudTierClass,
    pub priority: HydrationPriority,
    pub status: HydrationStatus,
    pub requested_at: u64,
    pub completed_at: Option<u64>,
    pub expires_at: Option<u64>,
}

/// Pure Safe Rust IEEE 802.3 CRC-32 / CRC-32C calculation.
pub fn compute_crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask); // Castagnoli polynomial
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider_and_tier_string_mappings() {
        assert_eq!(CloudProviderKind::AwsS3.as_str(), "s3");
        assert_eq!(
            CloudProviderKind::AwsS3.cloud_storage_class(CloudTierClass::DeepArchive),
            "DEEP_ARCHIVE"
        );
        assert_eq!(
            CloudProviderKind::GoogleGcs.cloud_storage_class(CloudTierClass::Cold),
            "COLDLINE"
        );
        assert_eq!(
            CloudProviderKind::AzureBlob.cloud_storage_class(CloudTierClass::Cool),
            "Cool"
        );

        assert!(CloudTierClass::Cold.requires_hydration());
        assert!(!CloudTierClass::Hot.requires_hydration());
    }

    #[test]
    fn test_cloud_storage_uri_parsing() {
        let uri: CloudStorageUri = "s3://my-backup-bucket/daily/2026-11-14.vlxt"
            .parse()
            .unwrap();
        assert_eq!(uri.provider, CloudProviderKind::AwsS3);
        assert_eq!(uri.bucket_or_container, "my-backup-bucket");
        assert_eq!(uri.key, "daily/2026-11-14.vlxt");
        assert_eq!(
            uri.to_uri_string(),
            "s3://my-backup-bucket/daily/2026-11-14.vlxt"
        );

        let gcs_uri: CloudStorageUri = "gcs://europe-west-archive/containers/c1.vlxt"
            .parse()
            .unwrap();
        assert_eq!(gcs_uri.provider, CloudProviderKind::GoogleGcs);
    }

    #[test]
    fn test_crc32c_deterministic() {
        let data = b"123456789";
        let crc = compute_crc32c(data);
        assert_eq!(crc, 0xE3069283); // Standard CRC32C test vector for "123456789"
    }
}
