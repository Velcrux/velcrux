//! Content-addressed chunk store and deduplication engine (`ARCHITECTURE.md` §2, §7, §12).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use async_trait::async_trait;
use bytes::Bytes;

use crate::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use crate::error::{ProtocolError, VelcruxError};
use crate::sync::BloomFilter;
use crate::util::Hash;

/// Core interface for content-addressed chunk storage (`ARCHITECTURE.md` §2).
#[async_trait]
pub trait ChunkStore: Send + Sync {
    /// Check whether the store contains a chunk with hash `h`.
    async fn has(&self, h: &Hash) -> Result<bool, VelcruxError>;

    /// Check presence for a batch of chunk hashes.
    async fn has_batch(&self, h: &[Hash]) -> Result<Vec<bool>, VelcruxError>;

    /// Store a chunk, verifying that its BLAKE3 digest matches `h`.
    async fn put(&self, h: &Hash, data: &[u8]) -> Result<(), VelcruxError>;

    /// Retrieve a chunk, verifying its BLAKE3 digest matches `h`.
    async fn get(&self, h: &Hash) -> Result<Bytes, VelcruxError>;

    /// Delete a chunk from the store. Returns `true` if removed, `false` if not found.
    async fn remove(&self, h: &Hash) -> Result<bool, VelcruxError>;

    /// Total number of unique chunks in the store.
    async fn total_chunks(&self) -> Result<usize, VelcruxError>;

    /// Total stored byte size across all chunks.
    async fn total_bytes(&self) -> Result<u64, VelcruxError>;
}

/// Filesystem-backed content-addressed chunk store with two-level directory sharding.
///
/// Directory layout:
/// ```text
/// <root>/
///   chunks/
///     ab/
///       cd/
///         abcdef01...chunk
///   staging/
///     .partial_...
/// ```
pub struct LocalChunkStore {
    root: PathBuf,
    chunks_dir: PathBuf,
    staging_dir: PathBuf,
    bloom: RwLock<BloomFilter>,
}

impl LocalChunkStore {
    /// Initialize or open a local chunk store at `root`.
    pub async fn new<P: AsRef<Path>>(root: P) -> Result<Self, VelcruxError> {
        let root = root.as_ref().to_path_buf();
        let chunks_dir = root.join("chunks");
        let staging_dir = root.join("staging");

        tokio::fs::create_dir_all(&chunks_dir).await?;
        tokio::fs::create_dir_all(&staging_dir).await?;

        // Initialize in-memory Bloom filter for membership pre-filtering
        let bloom = RwLock::new(BloomFilter::new(50_000, 0.01));

        let store = Self {
            root,
            chunks_dir,
            staging_dir,
            bloom,
        };

        // Populate initial bloom filter from existing directory
        store.rebuild_bloom_sync()?;

        Ok(store)
    }

    /// Construct sharded path for a chunk: `chunks/ab/cd/<hex>.chunk`.
    pub fn chunk_path(&self, h: &Hash) -> PathBuf {
        let hex = h.to_string();
        self.chunks_dir
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{hex}.chunk"))
    }

    /// Root directory of this chunk store.
    #[inline]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Chunks directory.
    #[inline]
    pub fn chunks_dir(&self) -> &Path {
        &self.chunks_dir
    }

    /// Staging directory.
    #[inline]
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Export a clone of the internal BloomFilter for network negotiation.
    pub fn bloom_filter(&self) -> BloomFilter {
        self.bloom.read().unwrap().clone()
    }

    /// Synchronous membership check.
    pub fn contains_sync(&self, h: &Hash) -> bool {
        {
            let b = self.bloom.read().unwrap();
            if !b.contains(h) {
                return false;
            }
        }
        self.chunk_path(h).exists()
    }

    /// Synchronous retrieval with BLAKE3 verification.
    pub fn get_sync(&self, h: &Hash) -> Result<Bytes, VelcruxError> {
        let path = self.chunk_path(h);
        let mut file = File::open(&path)?;

        let meta = file.metadata()?;
        let mut buf = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut buf)?;

        let computed = Hash::of(&buf);
        if computed != *h {
            let _ = fs::remove_file(&path);
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "checksum mismatch",
            )));
        }

        Ok(Bytes::from(buf))
    }

    /// Synchronous put with BLAKE3 verification and atomic rename.
    pub fn put_sync(&self, h: &Hash, data: &[u8]) -> Result<(), VelcruxError> {
        let computed = Hash::of(data);
        if computed != *h {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "checksum mismatch",
            )));
        }

        let final_path = self.chunk_path(h);
        if final_path.exists() {
            return Ok(());
        }

        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temp_name = format!(".partial_{}_{}", h, rand::random::<u64>());
        let temp_path = self.staging_dir.join(temp_name);

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            f.write_all(data)?;
            f.sync_all()?;
        }

        fs::rename(&temp_path, &final_path)?;

        {
            let mut b = self.bloom.write().unwrap();
            b.insert(h);
        }

        Ok(())
    }

    /// Copy a chunk directly from the store into `dst_file` at `dst_offset`.
    pub fn copy_to_std_file(
        &self,
        h: &Hash,
        dst_file: &mut File,
        dst_offset: u64,
    ) -> Result<u64, VelcruxError> {
        let path = self.chunk_path(h);
        let mut chunk_file = File::open(&path)?;

        let chunk_len = chunk_file.metadata()?.len();
        dst_file.seek(SeekFrom::Start(dst_offset))?;

        let mut buf = [0u8; 64 * 1024];
        let mut remaining = chunk_len;
        let mut hasher = blake3::Hasher::new();

        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = chunk_file.read(&mut buf[..to_read])?;
            if n == 0 {
                return Err(VelcruxError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated chunk file in chunk store",
                )));
            }
            hasher.update(&buf[..n]);
            dst_file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }

        let computed = Hash::from_bytes(hasher.finalize().as_bytes()).unwrap();
        if computed != *h {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "checksum mismatch",
            )));
        }

        Ok(chunk_len)
    }

    /// Ingest all chunks of an existing file into the chunk store.
    pub fn ingest_file_sync<P: AsRef<Path>>(
        &self,
        path: P,
        mode: ChunkMode,
        params: ChunkParams,
    ) -> Result<usize, VelcruxError> {
        let file = File::open(path)?;
        let reader = std::io::BufReader::with_capacity(params.max.max(64 * 1024) as usize, file);

        let mut ingested_count = 0usize;
        ChunkEngine::chunk_reader(
            reader,
            mode,
            params,
            params.max as usize,
            |desc, payload| {
                if let Some(hash) = desc.hash {
                    self.put_sync(&hash, payload)?;
                    ingested_count += 1;
                }
                Ok(())
            },
        )?;

        Ok(ingested_count)
    }

    /// Scan directory and rebuild Bloom filter.
    pub fn rebuild_bloom_sync(&self) -> Result<(), VelcruxError> {
        if !self.chunks_dir.exists() {
            return Ok(());
        }

        let mut hashes = Vec::new();
        for d1 in fs::read_dir(&self.chunks_dir)? {
            let d1 = d1?;
            if d1.file_type()?.is_dir() {
                for d2 in fs::read_dir(d1.path())? {
                    let d2 = d2?;
                    if d2.file_type()?.is_dir() {
                        for f in fs::read_dir(d2.path())? {
                            let f = f?;
                            let name = f.file_name();
                            let s = name.to_string_lossy();
                            if let Some(hex) = s.strip_suffix(".chunk") {
                                if let Some(h) = Hash::from_hex(hex) {
                                    hashes.push(h);
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut b = BloomFilter::new(hashes.len().max(1000), 0.01);
        for h in &hashes {
            b.insert(h);
        }
        *self.bloom.write().unwrap() = b;

        Ok(())
    }
}

#[async_trait]
impl ChunkStore for LocalChunkStore {
    async fn has(&self, h: &Hash) -> Result<bool, VelcruxError> {
        {
            let b = self.bloom.read().unwrap();
            if !b.contains(h) {
                return Ok(false);
            }
        }
        let p = self.chunk_path(h);
        Ok(tokio::fs::try_exists(&p).await.unwrap_or(false))
    }

    async fn has_batch(&self, hashes: &[Hash]) -> Result<Vec<bool>, VelcruxError> {
        let mut results = Vec::with_capacity(hashes.len());
        for h in hashes {
            results.push(self.has(h).await?);
        }
        Ok(results)
    }

    async fn put(&self, h: &Hash, data: &[u8]) -> Result<(), VelcruxError> {
        let computed = Hash::of(data);
        if computed != *h {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "checksum mismatch",
            )));
        }

        let final_path = self.chunk_path(h);
        if tokio::fs::try_exists(&final_path).await.unwrap_or(false) {
            return Ok(());
        }

        if let Some(parent) = final_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let temp_name = format!(".partial_{}_{}", h, rand::random::<u64>());
        let temp_path = self.staging_dir.join(temp_name);

        use tokio::io::AsyncWriteExt;
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .await?;
        f.write_all(data).await?;
        f.sync_all().await?;
        drop(f);

        tokio::fs::rename(&temp_path, &final_path).await?;

        {
            let mut b = self.bloom.write().unwrap();
            b.insert(h);
        }

        Ok(())
    }

    async fn get(&self, h: &Hash) -> Result<Bytes, VelcruxError> {
        let path = self.chunk_path(h);
        let mut file = tokio::fs::File::open(&path).await?;

        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;

        let computed = Hash::of(&buf);
        if computed != *h {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "checksum mismatch",
            )));
        }

        Ok(Bytes::from(buf))
    }

    async fn remove(&self, h: &Hash) -> Result<bool, VelcruxError> {
        let path = self.chunk_path(h);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(VelcruxError::Io(e)),
        }
    }

    async fn total_chunks(&self) -> Result<usize, VelcruxError> {
        let mut count = 0usize;
        let mut entries = tokio::fs::read_dir(&self.chunks_dir).await?;
        while let Some(d1) = entries.next_entry().await? {
            if d1.file_type().await?.is_dir() {
                let mut d2_entries = tokio::fs::read_dir(d1.path()).await?;
                while let Some(d2) = d2_entries.next_entry().await? {
                    if d2.file_type().await?.is_dir() {
                        let mut files = tokio::fs::read_dir(d2.path()).await?;
                        while let Some(f) = files.next_entry().await? {
                            if f.file_name().to_string_lossy().ends_with(".chunk") {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    async fn total_bytes(&self) -> Result<u64, VelcruxError> {
        let mut bytes = 0u64;
        let mut entries = tokio::fs::read_dir(&self.chunks_dir).await?;
        while let Some(d1) = entries.next_entry().await? {
            if d1.file_type().await?.is_dir() {
                let mut d2_entries = tokio::fs::read_dir(d1.path()).await?;
                while let Some(d2) = d2_entries.next_entry().await? {
                    if d2.file_type().await?.is_dir() {
                        let mut files = tokio::fs::read_dir(d2.path()).await?;
                        while let Some(f) = files.next_entry().await? {
                            let meta = f.metadata().await?;
                            if f.file_name().to_string_lossy().ends_with(".chunk") {
                                bytes += meta.len();
                            }
                        }
                    }
                }
            }
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn chunk_store_put_get_has() {
        let dir = tempdir().unwrap();
        let store = LocalChunkStore::new(dir.path()).await.unwrap();

        let payload = b"hello chunk store deduplication!";
        let hash = Hash::of(payload);

        assert!(!store.has(&hash).await.unwrap());

        store.put(&hash, payload).await.unwrap();
        assert!(store.has(&hash).await.unwrap());

        let retrieved = store.get(&hash).await.unwrap();
        assert_eq!(retrieved.as_ref(), payload);

        let batch = store
            .has_batch(&[hash, Hash::of(b"missing")])
            .await
            .unwrap();
        assert_eq!(batch, vec![true, false]);

        assert_eq!(store.total_chunks().await.unwrap(), 1);
        assert_eq!(store.total_bytes().await.unwrap(), payload.len() as u64);
    }

    #[tokio::test]
    async fn chunk_store_rejects_checksum_mismatch() {
        let dir = tempdir().unwrap();
        let store = LocalChunkStore::new(dir.path()).await.unwrap();

        let payload = b"real data";
        let wrong_hash = Hash::of(b"wrong data");

        let err = store.put(&wrong_hash, payload).await.unwrap_err();
        assert!(matches!(
            err,
            VelcruxError::Protocol(ProtocolError::Malformed(_))
        ));
    }
}
