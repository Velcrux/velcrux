//! Receiver-side local chunk inventory (`ARCHITECTURE.md` §7).

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use super::bloom::BloomFilter;
use super::SyncError;
use crate::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use crate::util::Hash;

/// Byte extent of a chunk within a local source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkExtent {
    /// Byte offset within the local file.
    pub offset: u64,
    /// Length of the chunk in bytes.
    pub length: u64,
}

/// Inventory of local chunks available in an existing file for delta reuse.
#[derive(Debug, Clone, Default)]
pub struct LocalInventory {
    chunks: HashMap<Hash, ChunkExtent>,
    total_bytes: u64,
    total_chunks: usize,
    whole_hash: Option<Hash>,
}

impl LocalInventory {
    /// Create an inventory directly from a collection of chunk descriptors.
    pub fn from_extents(
        chunks: HashMap<Hash, ChunkExtent>,
        total_bytes: u64,
        total_chunks: usize,
        whole_hash: Option<Hash>,
    ) -> Self {
        Self {
            chunks,
            total_bytes,
            total_chunks,
            whole_hash,
        }
    }

    /// Scan an existing local file and build its chunk inventory using bounded memory streaming.
    pub fn from_file<P: AsRef<Path>>(
        path: P,
        mode: ChunkMode,
        params: ChunkParams,
        read_buf_size: usize,
    ) -> Result<Self, SyncError> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(read_buf_size.max(64 * 1024), file);

        let mut chunks = HashMap::new();
        let mut offset = 0u64;
        let mut total_chunks = 0usize;

        let (whole_hash, total_bytes) =
            ChunkEngine::chunk_reader(reader, mode, params, read_buf_size, |desc, _payload| {
                total_chunks += 1;
                if let Some(hash) = desc.hash {
                    chunks.entry(hash).or_insert(ChunkExtent {
                        offset,
                        length: desc.length,
                    });
                }
                offset += desc.length;
                Ok(())
            })
            .map_err(|e| {
                SyncError::Inventory(format!("failed to scan file {}: {e}", path.display()))
            })?;

        Ok(Self {
            chunks,
            total_bytes,
            total_chunks,
            whole_hash: Some(whole_hash),
        })
    }

    /// Check if a chunk hash is present in the local inventory.
    #[inline]
    pub fn contains(&self, hash: &Hash) -> bool {
        self.chunks.contains_key(hash)
    }

    /// Lookup extent for a chunk hash.
    #[inline]
    pub fn lookup(&self, hash: &Hash) -> Option<ChunkExtent> {
        self.chunks.get(hash).copied()
    }

    /// Iterator over all indexed chunk hashes.
    #[inline]
    pub fn chunk_hashes(&self) -> impl Iterator<Item = &Hash> {
        self.chunks.keys()
    }

    /// Total number of chunks scanned in the file.
    #[inline]
    pub fn total_chunks(&self) -> usize {
        self.total_chunks
    }

    /// Total number of unique chunk hashes indexed.
    #[inline]
    pub fn unique_chunks(&self) -> usize {
        self.chunks.len()
    }

    /// Total bytes indexed.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Whole-file BLAKE3 digest, if computed.
    #[inline]
    pub fn whole_hash(&self) -> Option<Hash> {
        self.whole_hash
    }

    /// Generate an [`INVENTORY_HINT`] Bloom filter covering all chunks in this inventory.
    pub fn create_bloom_filter(&self, fp_rate: f64) -> BloomFilter {
        let mut bloom = BloomFilter::new(self.chunks.len(), fp_rate);
        for hash in self.chunks.keys() {
            bloom.insert(hash);
        }
        bloom
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn inventory_from_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        let payload = vec![0x42u8; 128 * 1024];
        tmp.write_all(&payload).unwrap();
        tmp.flush().unwrap();

        let params = ChunkParams::new(16 * 1024, 32 * 1024, 64 * 1024).unwrap();
        let inv =
            LocalInventory::from_file(tmp.path(), ChunkMode::Fixed, params, 64 * 1024).unwrap();

        assert_eq!(inv.total_bytes(), 128 * 1024);
        assert_eq!(inv.whole_hash(), Some(Hash::of(&payload)));
        assert_eq!(inv.total_chunks(), 4);

        let bloom = inv.create_bloom_filter(0.01);
        for h in inv.chunks.keys() {
            assert!(bloom.contains(h));
        }
        assert!(!bloom.contains(&Hash::of(b"nonexistent")));
    }
}
