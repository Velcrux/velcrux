//! Dynamic Zstandard Pre-Trained Dictionary Learning Engine (Option BE).
//!
//! Provides pre-trained dictionary generation, persistent catalog management,
//! dictionary-accelerated compression, and bounded decompression defense
//! per `REQUIREMENTS.md` §89, §26 and `SECURITY.md` §8.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, VelcruxError};

/// Default maximum Zstandard dictionary size (112 KiB).
pub const DEFAULT_MAX_DICT_SIZE: usize = 112 * 1024;

/// Target maximum sample chunk size collected per file for dictionary training (32 KiB).
pub const MAX_SAMPLE_PER_FILE: usize = 32 * 1024;

/// Default minimum sample count required to build a viable dictionary.
pub const MIN_TRAINING_SAMPLES: usize = 5;

/// Common binary and compressed file extensions that should be skipped during sample gathering.
pub const DEFAULT_SKIPPED_EXTENSIONS: &[&str] = &[
    "gz", "zip", "zst", "tar", "tgz", "bz2", "xz", "7z", "rar", "png", "jpg", "jpeg", "gif",
    "webp", "mp4", "mov", "avi", "mkv", "mp3", "flac", "wav", "pdf", "iso", "bin",
];

/// Metadata header describing a stored pre-trained Zstandard dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DictionaryMetadata {
    /// 32-bit unique dictionary identifier.
    pub dict_id: u32,
    /// Human-readable dictionary name (e.g. "json-telemetry", "syslogs-v1").
    pub name: String,
    /// Unix timestamp when dictionary was trained.
    pub created_at_secs: u64,
    /// Total number of training samples ingested.
    pub sample_count: usize,
    /// Total raw bytes of training data ingested.
    pub trained_bytes: usize,
    /// Serialized dictionary size on disk in bytes.
    pub dict_size: usize,
    /// BLAKE3 64-bit hex checksum of dictionary payload.
    pub checksum: String,
    /// User description or domain tag.
    pub description: String,
}

/// A fully loaded pre-trained Zstandard dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZstdDictionary {
    pub metadata: DictionaryMetadata,
    #[serde(skip)]
    pub dict_bytes: Vec<u8>,
}

impl ZstdDictionary {
    /// Construct a dictionary from metadata and raw trained dictionary bytes.
    pub fn new(metadata: DictionaryMetadata, dict_bytes: Vec<u8>) -> Self {
        Self {
            metadata,
            dict_bytes,
        }
    }

    /// Access dictionary identifier.
    #[inline]
    pub fn dict_id(&self) -> u32 {
        self.metadata.dict_id
    }

    /// Access dictionary name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Access dictionary bytes.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.dict_bytes
    }
}

/// Comparison evaluation between vanilla zstd and dictionary-accelerated zstd.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompressionRatioEvaluation {
    /// Raw uncompressed bytes evaluated.
    pub raw_bytes: usize,
    /// Compressed bytes using standard Zstandard.
    pub vanilla_zstd_bytes: usize,
    /// Compressed bytes using trained dictionary Zstandard.
    pub dict_zstd_bytes: usize,
    /// Compression ratio for standard Zstandard (raw / vanilla).
    pub vanilla_ratio: f64,
    /// Compression ratio for dictionary Zstandard (raw / dict).
    pub dict_ratio: f64,
    /// Additional bandwidth savings achieved by dictionary over vanilla zstd (percentage).
    pub extra_savings_pct: f64,
}

// ---------------------------------------------------------------------------
// Compression & Decompression with Pre-Trained Dictionary
// ---------------------------------------------------------------------------

/// Compress `data` using Zstandard with a pre-trained dictionary at `level`.
pub fn compress_with_dict(
    data: &[u8],
    level: i32,
    dict_bytes: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if dict_bytes.is_empty() {
        return crate::protocol::compression::compress_payload(data, level);
    }

    let mut encoder = zstd::Encoder::with_dictionary(Vec::new(), level, dict_bytes)
        .map_err(|_| ProtocolError::Malformed("failed to initialize zstd dict encoder"))?;

    encoder
        .write_all(data)
        .map_err(|_| ProtocolError::Malformed("zstd dict write failed"))?;

    encoder
        .finish()
        .map_err(|_| ProtocolError::Malformed("zstd dict compression finish failed"))
}

/// Decompress `compressed` payload using a pre-trained dictionary with strict bounds.
///
/// Prevents decompression bombs per `SECURITY.md` §8.
pub fn decompress_with_dict_bounded(
    compressed: &[u8],
    dict_bytes: &[u8],
    max_bytes: usize,
    max_ratio: Option<usize>,
) -> Result<Vec<u8>, ProtocolError> {
    if compressed.is_empty() {
        return Err(ProtocolError::Malformed("empty compressed payload"));
    }

    if dict_bytes.is_empty() {
        return crate::protocol::compression::decompress_payload_bounded(
            compressed, max_bytes, max_ratio,
        );
    }

    let mut decoder = zstd::Decoder::with_dictionary(compressed, dict_bytes)
        .map_err(|_| ProtocolError::Malformed("invalid zstd dict decoder"))?;

    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|_| ProtocolError::Malformed("zstd dict decode error"))?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_bytes {
            return Err(ProtocolError::DecompressionBomb(format!(
                "decompressed size with dictionary exceeds limit of {max_bytes} bytes"
            )));
        }

        out.extend_from_slice(&buf[..n]);

        if let Some(ratio) = max_ratio {
            if out.len() > 64 * 1024 {
                let current_ratio = out.len() / compressed.len().max(1);
                if current_ratio > ratio {
                    return Err(ProtocolError::DecompressionBomb(format!(
                        "decompression expansion ratio {current_ratio}x exceeds maximum of {ratio}x"
                    )));
                }
            }
        }
    }

    Ok(out)
}

/// Evaluate and compare compression performance of raw vs vanilla vs dictionary-assisted zstd.
pub fn evaluate_dictionary_ratio<S: AsRef<[u8]>>(
    samples: &[S],
    dict_bytes: &[u8],
    level: i32,
) -> Result<CompressionRatioEvaluation, ProtocolError> {
    let mut total_raw = 0usize;
    let mut total_vanilla = 0usize;
    let mut total_dict = 0usize;

    for s in samples {
        let slice = s.as_ref();
        if slice.is_empty() {
            continue;
        }
        total_raw += slice.len();

        let vanilla = crate::protocol::compression::compress_payload(slice, level)?;
        total_vanilla += vanilla.len();

        let with_dict = compress_with_dict(slice, level, dict_bytes)?;
        total_dict += with_dict.len();
    }

    if total_raw == 0 {
        return Ok(CompressionRatioEvaluation {
            raw_bytes: 0,
            vanilla_zstd_bytes: 0,
            dict_zstd_bytes: 0,
            vanilla_ratio: 1.0,
            dict_ratio: 1.0,
            extra_savings_pct: 0.0,
        });
    }

    let vanilla_ratio = total_raw as f64 / total_vanilla.max(1) as f64;
    let dict_ratio = total_raw as f64 / total_dict.max(1) as f64;

    let extra_savings_pct = if total_vanilla > total_dict {
        ((total_vanilla - total_dict) as f64 / total_vanilla as f64) * 100.0
    } else {
        0.0
    };

    Ok(CompressionRatioEvaluation {
        raw_bytes: total_raw,
        vanilla_zstd_bytes: total_vanilla,
        dict_zstd_bytes: total_dict,
        vanilla_ratio,
        dict_ratio,
        extra_savings_pct,
    })
}

// ---------------------------------------------------------------------------
// Dictionary Trainer
// ---------------------------------------------------------------------------

/// Engine to harvest sample payloads and train optimized Zstandard dictionaries.
pub struct DictionaryTrainer;

impl DictionaryTrainer {
    /// Train a new Zstandard dictionary from in-memory sample slices.
    pub fn train_from_samples<S: AsRef<[u8]>>(
        samples: &[S],
        target_dict_size: usize,
        name: &str,
        description: &str,
        now_secs: u64,
    ) -> Result<ZstdDictionary, VelcruxError> {
        let valid_samples: Vec<&[u8]> = samples
            .iter()
            .map(|s| s.as_ref())
            .filter(|s| !s.is_empty())
            .collect();

        if valid_samples.len() < MIN_TRAINING_SAMPLES {
            return Err(VelcruxError::Config(format!(
                "insufficient training samples: provided {}, minimum required is {}",
                valid_samples.len(),
                MIN_TRAINING_SAMPLES
            )));
        }

        let dict_size = target_dict_size.clamp(1024, DEFAULT_MAX_DICT_SIZE);
        let trained_bytes = zstd::dict::from_samples(&valid_samples, dict_size).map_err(|e| {
            VelcruxError::Internal(format!("zstd dictionary training failed: {}", e))
        })?;

        let checksum_bytes = blake3::hash(&trained_bytes);
        let checksum = checksum_bytes.to_hex()[..16].to_string();

        // Compute stable 32-bit dict_id from first 4 bytes of BLAKE3 checksum
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&checksum_bytes.as_bytes()[..4]);
        let mut dict_id = u32::from_be_bytes(id_bytes);
        if dict_id == 0 {
            dict_id = 1;
        }

        let total_sample_bytes: usize = valid_samples.iter().map(|s| s.len()).sum();

        let metadata = DictionaryMetadata {
            dict_id,
            name: name.to_string(),
            created_at_secs: now_secs,
            sample_count: valid_samples.len(),
            trained_bytes: total_sample_bytes,
            dict_size: trained_bytes.len(),
            checksum,
            description: description.to_string(),
        };

        Ok(ZstdDictionary::new(metadata, trained_bytes))
    }

    /// Recursively harvest training samples from a directory tree.
    pub fn sample_directory(
        root: &Path,
        max_samples: usize,
        max_sample_len: usize,
    ) -> Result<Vec<Vec<u8>>, VelcruxError> {
        let mut samples = Vec::new();
        Self::collect_samples_recursive(root, max_samples, max_sample_len, &mut samples)?;
        Ok(samples)
    }

    fn collect_samples_recursive(
        dir: &Path,
        max_samples: usize,
        max_sample_len: usize,
        out: &mut Vec<Vec<u8>>,
    ) -> Result<(), VelcruxError> {
        if !dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(dir)?;
        for entry in entries.flatten() {
            if out.len() >= max_samples {
                break;
            }
            let path = entry.path();
            if path.is_dir() {
                Self::collect_samples_recursive(&path, max_samples, max_sample_len, out)?;
            } else if path.is_file() {
                // Check extension
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = ext.to_ascii_lowercase();
                    if DEFAULT_SKIPPED_EXTENSIONS.contains(&ext_lower.as_str()) {
                        continue;
                    }
                }

                if let Ok(mut f) = File::open(&path) {
                    let mut buf = vec![0u8; max_sample_len];
                    if let Ok(n) = f.read(&mut buf) {
                        if n >= 32 {
                            buf.truncate(n);
                            out.push(buf);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Harvest training samples from a directory and build a registered dictionary.
    pub fn train_from_directory(
        dir: &Path,
        target_dict_size: usize,
        max_samples: usize,
        name: &str,
        description: &str,
        now_secs: u64,
    ) -> Result<ZstdDictionary, VelcruxError> {
        let samples = Self::sample_directory(dir, max_samples, MAX_SAMPLE_PER_FILE)?;
        if samples.len() < MIN_TRAINING_SAMPLES {
            return Err(VelcruxError::Config(format!(
                "directory '{}' yielded {} samples; at least {} required",
                dir.display(),
                samples.len(),
                MIN_TRAINING_SAMPLES
            )));
        }

        Self::train_from_samples(&samples, target_dict_size, name, description, now_secs)
    }
}

// ---------------------------------------------------------------------------
// Dictionary Catalog (Persistent Registry)
// ---------------------------------------------------------------------------

/// Persistent catalog storing pre-trained Zstandard dictionaries.
#[derive(Debug)]
pub struct DictionaryCatalog {
    base_dir: PathBuf,
    catalog_file: PathBuf,
    metadata_map: RwLock<HashMap<u32, DictionaryMetadata>>,
}

impl DictionaryCatalog {
    /// Open or initialize a dictionary catalog at `base_dir`.
    pub fn open_or_create(base_dir: impl Into<PathBuf>) -> Result<Self, VelcruxError> {
        let dir = base_dir.into();
        fs::create_dir_all(&dir)?;
        let catalog_file = dir.join("catalog.json");

        let mut metadata_map = HashMap::new();
        if catalog_file.exists() {
            if let Ok(file_content) = fs::read(&catalog_file) {
                if let Ok(list) = serde_json::from_slice::<Vec<DictionaryMetadata>>(&file_content) {
                    for m in list {
                        metadata_map.insert(m.dict_id, m);
                    }
                }
            }
        }

        Ok(Self {
            base_dir: dir,
            catalog_file,
            metadata_map: RwLock::new(metadata_map),
        })
    }

    /// Register a newly trained or imported dictionary into the catalog.
    pub fn register(&self, dict: &ZstdDictionary) -> Result<(), VelcruxError> {
        let dict_file = self.dict_path(dict.dict_id());
        let tmp_file = dict_file.with_extension("tmp");

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_file)?;
            f.write_all(&dict.dict_bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_file, &dict_file)?;

        {
            let mut map = self.metadata_map.write().unwrap();
            map.insert(dict.dict_id(), dict.metadata.clone());
        }

        self.save_catalog_index()
    }

    /// Retrieve a dictionary by its numeric ID.
    pub fn get_by_id(&self, dict_id: u32) -> Result<Option<ZstdDictionary>, VelcruxError> {
        let meta = {
            let map = self.metadata_map.read().unwrap();
            map.get(&dict_id).cloned()
        };

        match meta {
            Some(metadata) => {
                let dict_file = self.dict_path(dict_id);
                if !dict_file.exists() {
                    return Ok(None);
                }
                let bytes = fs::read(&dict_file)?;
                Ok(Some(ZstdDictionary::new(metadata, bytes)))
            }
            None => Ok(None),
        }
    }

    /// Retrieve a dictionary by name.
    pub fn get_by_name(&self, name: &str) -> Result<Option<ZstdDictionary>, VelcruxError> {
        let id = {
            let map = self.metadata_map.read().unwrap();
            map.values()
                .find(|m| m.name.eq_ignore_ascii_case(name))
                .map(|m| m.dict_id)
        };

        match id {
            Some(dict_id) => self.get_by_id(dict_id),
            None => Ok(None),
        }
    }

    /// List all registered dictionary metadata records sorted by created timestamp.
    pub fn list(&self) -> Vec<DictionaryMetadata> {
        let map = self.metadata_map.read().unwrap();
        let mut list: Vec<DictionaryMetadata> = map.values().cloned().collect();
        list.sort_by_key(|m| m.created_at_secs);
        list
    }

    /// Delete a registered dictionary by ID.
    pub fn delete(&self, dict_id: u32) -> Result<bool, VelcruxError> {
        let removed = {
            let mut map = self.metadata_map.write().unwrap();
            map.remove(&dict_id).is_some()
        };

        if removed {
            let dict_file = self.dict_path(dict_id);
            if dict_file.exists() {
                let _ = fs::remove_file(dict_file);
            }
            self.save_catalog_index()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Export dictionary binary to an external file path.
    pub fn export_dictionary(&self, dict_id: u32, dest: &Path) -> Result<(), VelcruxError> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let dict = self
            .get_by_id(dict_id)?
            .ok_or_else(|| VelcruxError::Config(format!("dict ID {dict_id} not found")))?;
        fs::write(dest, &dict.dict_bytes)?;
        Ok(())
    }

    /// Import a pre-existing dictionary binary from an external file path.
    pub fn import_dictionary(
        &self,
        source: &Path,
        name: Option<&str>,
        description: Option<&str>,
        now_secs: u64,
    ) -> Result<ZstdDictionary, VelcruxError> {
        let bytes = fs::read(source)?;
        if bytes.is_empty() {
            return Err(VelcruxError::Config("empty dictionary file".into()));
        }

        let checksum_bytes = blake3::hash(&bytes);
        let checksum = checksum_bytes.to_hex()[..16].to_string();

        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&checksum_bytes.as_bytes()[..4]);
        let mut dict_id = u32::from_be_bytes(id_bytes);
        if dict_id == 0 {
            dict_id = 1;
        }

        let dict_name = name.map(|s| s.to_string()).unwrap_or_else(|| {
            source
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("imported-dict")
                .to_string()
        });

        let metadata = DictionaryMetadata {
            dict_id,
            name: dict_name,
            created_at_secs: now_secs,
            sample_count: 1,
            trained_bytes: bytes.len(),
            dict_size: bytes.len(),
            checksum,
            description: description.unwrap_or("Imported dictionary").to_string(),
        };

        let dict = ZstdDictionary::new(metadata, bytes);
        self.register(&dict)?;
        Ok(dict)
    }

    fn dict_path(&self, dict_id: u32) -> PathBuf {
        self.base_dir.join(format!("{}.zdict", dict_id))
    }

    fn save_catalog_index(&self) -> Result<(), VelcruxError> {
        let map = self.metadata_map.read().unwrap();
        let list: Vec<&DictionaryMetadata> = map.values().collect();
        let json_bytes = serde_json::to_vec_pretty(&list).map_err(|e| {
            VelcruxError::Internal(format!("failed to serialize catalog index: {}", e))
        })?;

        let tmp_file = self.catalog_file.with_extension("tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_file)?;
            f.write_all(&json_bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_file, &self.catalog_file)?;
        Ok(())
    }
}
