//! Compacted Cloud Storage Container (`VLXT`) Engine.
//!
//! Packs millions of small content-defined chunks (FastCDC ~64 KiB) into contiguous,
//! 64-128 MiB cloud-optimized containers with embedded index tables, CRC32C validation,
//! and transparent byte-range (`Range: bytes=X-Y`) extraction.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use super::types::{
    compute_crc32c, ChunkDescriptor, CloudProviderKind, CloudTierClass, CompressionCodec,
    ContainerHeader, VLXT_CONTAINER_MAGIC, VLXT_CONTAINER_VERSION,
};
use crate::error::{ProtocolError, Result, VelcruxError};

/// In-memory compacted container structure with chunk lookup index and raw payload.
#[derive(Debug, Clone)]
pub struct CompactedContainer {
    pub header: ContainerHeader,
    pub index: HashMap<[u8; 32], ChunkDescriptor>,
    pub payload: Vec<u8>,
}

impl CompactedContainer {
    /// Creates a new, empty compacted container for the target provider and tier.
    pub fn new(
        container_id: impl Into<String>,
        provider: CloudProviderKind,
        tier: CloudTierClass,
        codec: CompressionCodec,
    ) -> Self {
        let container_id = container_id.into();
        let header = ContainerHeader {
            magic: VLXT_CONTAINER_MAGIC,
            version: VLXT_CONTAINER_VERSION,
            container_id,
            provider,
            tier,
            codec,
            chunk_count: 0,
            total_uncompressed_bytes: 0,
            total_compressed_bytes: 0,
            index_offset: 0,
            index_length: 0,
            payload_blake3: [0u8; 32],
        };

        Self {
            header,
            index: HashMap::new(),
            payload: Vec::new(),
        }
    }

    /// Packs a single raw uncompressed chunk into this container.
    pub fn append_chunk(
        &mut self,
        chunk_hash: [u8; 32],
        raw_data: &[u8],
        timestamp: u64,
    ) -> Result<()> {
        if self.index.contains_key(&chunk_hash) {
            // Deduplication within the container: chunk already present
            return Ok(());
        }

        let uncompressed_len = raw_data.len() as u32;
        let compressed = self.header.codec.compress(raw_data)?;
        let compressed_len = compressed.len() as u32;
        let crc = compute_crc32c(&compressed);

        let offset = self.payload.len() as u64;
        self.payload.extend_from_slice(&compressed);

        let desc = ChunkDescriptor::new(
            chunk_hash,
            offset,
            compressed_len,
            uncompressed_len,
            crc,
            timestamp,
        );

        self.index.insert(chunk_hash, desc);
        self.header.chunk_count += 1;
        self.header.total_uncompressed_bytes += uncompressed_len as u64;
        self.header.total_compressed_bytes += compressed_len as u64;

        Ok(())
    }

    /// Finalizes the container by generating the index table, trailer, and BLAKE3 payload digest.
    pub fn finalize(&mut self) {
        self.header.payload_blake3 = *blake3::hash(&self.payload).as_bytes();
        self.header.index_offset = self.payload.len() as u64;

        // Serialize index table
        let mut index_vec: Vec<ChunkDescriptor> = self.index.values().cloned().collect();
        index_vec.sort_by_key(|d| d.offset_in_container);

        let serialized_index = serde_json::to_vec(&index_vec).unwrap_or_default();
        self.header.index_length = serialized_index.len() as u32;
    }

    /// Serializes the entire container into an on-wire or on-disk byte buffer:
    /// `[Header JSON (4096-byte padded)] [Payload Chunks] [Index JSON] [Trailer (16 bytes)]`
    pub fn serialize_to_bytes(&mut self) -> Result<Vec<u8>> {
        self.finalize();

        let header_json = serde_json::to_vec(&self.header).map_err(|_| {
            VelcruxError::Protocol(ProtocolError::Malformed("header serialization failed"))
        })?;

        // 4 KiB header block with padding
        let mut buf = Vec::with_capacity(
            4096 + self.payload.len() + (self.header.index_length as usize) + 16,
        );

        // 1. Header Magic & Length
        buf.extend_from_slice(&VLXT_CONTAINER_MAGIC);
        let header_len_u32 = header_json.len() as u32;
        buf.extend_from_slice(&header_len_u32.to_le_bytes());
        buf.extend_from_slice(&header_json);
        buf.resize(4096, 0u8);

        // 2. Payload Chunks
        buf.extend_from_slice(&self.payload);

        // 3. Index Table
        let mut index_vec: Vec<ChunkDescriptor> = self.index.values().cloned().collect();
        index_vec.sort_by_key(|d| d.offset_in_container);
        let index_json = serde_json::to_vec(&index_vec).map_err(|_| {
            VelcruxError::Protocol(ProtocolError::Malformed("index serialization failed"))
        })?;
        let index_start = buf.len() as u64;
        buf.extend_from_slice(&index_json);

        // 4. Trailer: [index_start: u64, index_len: u32, magic: 4 bytes]
        buf.extend_from_slice(&index_start.to_le_bytes());
        buf.extend_from_slice(&(index_json.len() as u32).to_le_bytes());
        buf.extend_from_slice(&VLXT_CONTAINER_MAGIC);

        Ok(buf)
    }

    /// Parses a serialized container buffer back into a `CompactedContainer`.
    pub fn deserialize_from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4096 + 16 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "container byte stream too small",
            )));
        }

        // Check header magic
        if &data[0..4] != &VLXT_CONTAINER_MAGIC {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid container magic header",
            )));
        }

        let header_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if 8 + header_len > 4096 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "corrupt container header length",
            )));
        }

        let header: ContainerHeader =
            serde_json::from_slice(&data[8..8 + header_len]).map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("invalid container header JSON"))
            })?;

        // Check footer magic
        let footer_magic = &data[data.len() - 4..];
        if footer_magic != &VLXT_CONTAINER_MAGIC {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid container footer magic",
            )));
        }

        let index_start = u64::from_le_bytes(
            data[data.len() - 16..data.len() - 8]
                .try_into()
                .map_err(|_| {
                    VelcruxError::Protocol(ProtocolError::Malformed("corrupt index start offset"))
                })?,
        ) as usize;

        let index_len = u32::from_le_bytes(
            data[data.len() - 8..data.len() - 4]
                .try_into()
                .map_err(|_| {
                    VelcruxError::Protocol(ProtocolError::Malformed("corrupt index length"))
                })?,
        ) as usize;

        if index_start + index_len > data.len() - 16 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "corrupt index range bounds",
            )));
        }

        let descriptors: Vec<ChunkDescriptor> =
            serde_json::from_slice(&data[index_start..index_start + index_len]).map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("invalid index table JSON"))
            })?;

        let mut index = HashMap::with_capacity(descriptors.len());
        for d in descriptors {
            index.insert(d.chunk_hash, d);
        }

        let payload = data[4096..index_start].to_vec();

        Ok(Self {
            header,
            index,
            payload,
        })
    }

    /// Calculates the exact byte-range `(start_byte, end_byte)` for an HTTP `Range: bytes=start-end` GET request.
    ///
    /// The offset returned is relative to the entire container file on remote cloud object storage.
    pub fn get_chunk_cloud_range(&self, chunk_hash: &[u8; 32]) -> Option<(u64, u64)> {
        let desc = self.index.get(chunk_hash)?;
        if desc.tombstoned {
            return None;
        }
        // Container payload starts at offset 4096 in the serialized object
        let start = 4096 + desc.offset_in_container;
        let end = start + (desc.compressed_len as u64) - 1;
        Some((start, end))
    }

    /// Reads and extracts a specific chunk directly from the container payload buffer.
    pub fn read_chunk(&mut self, chunk_hash: &[u8; 32], now: u64) -> Result<Vec<u8>> {
        let desc = self.index.get_mut(chunk_hash).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("chunk not found in container"))
        })?;

        if desc.tombstoned {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "chunk has been tombstoned / deleted",
            )));
        }

        desc.access_count = desc.access_count.saturating_add(1);
        desc.last_accessed_at = now;

        let start = desc.offset_in_container as usize;
        let end = start + (desc.compressed_len as usize);

        if end > self.payload.len() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "chunk bounds extend past container payload buffer",
            )));
        }

        let compressed_slice = &self.payload[start..end];

        // Check CRC32C
        let actual_crc = compute_crc32c(compressed_slice);
        if actual_crc != desc.checksum_crc32c {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "chunk checksum CRC32C mismatch: data corrupted",
            )));
        }

        let decompressed = self.header.codec.decompress(compressed_slice)?;

        // Verify BLAKE3 hash
        let actual_blake3 = *blake3::hash(&decompressed).as_bytes();
        if actual_blake3 != *chunk_hash {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "chunk BLAKE3 hash mismatch after decompression",
            )));
        }

        Ok(decompressed)
    }

    /// Marks a chunk as tombstoned / deleted within the container.
    pub fn tombstone_chunk(&mut self, chunk_hash: &[u8; 32]) -> bool {
        if let Some(desc) = self.index.get_mut(chunk_hash) {
            if !desc.tombstoned {
                desc.tombstoned = true;
                return true;
            }
        }
        false
    }

    /// Active (non-tombstoned) chunk count.
    pub fn active_chunk_count(&self) -> usize {
        self.index.values().filter(|d| !d.tombstoned).count()
    }

    /// Tombstoned / deleted chunk count.
    pub fn tombstoned_chunk_count(&self) -> usize {
        self.index.values().filter(|d| d.tombstoned).count()
    }

    /// Dead-space fragmentation ratio $\in [0.0, 1.0]$.
    pub fn fragmentation_ratio(&self) -> f64 {
        if self.index.is_empty() {
            return 0.0;
        }
        let tombstoned_bytes: u64 = self
            .index
            .values()
            .filter(|d| d.tombstoned)
            .map(|d| d.compressed_len as u64)
            .sum();

        let total_bytes: u64 = self.payload.len() as u64;
        if total_bytes == 0 {
            0.0
        } else {
            (tombstoned_bytes as f64) / (total_bytes as f64)
        }
    }

    /// Compacts and repacks active chunks into a newly compacted container, purging all tombstoned chunks.
    pub fn compact_and_repack(&self, new_container_id: impl Into<String>) -> Result<Self> {
        let mut new_container = Self::new(
            new_container_id,
            self.header.provider,
            self.header.tier,
            self.header.codec,
        );

        // Sort active descriptors by original offset to preserve sequential locality
        let mut active_descriptors: Vec<&ChunkDescriptor> =
            self.index.values().filter(|d| !d.tombstoned).collect();
        active_descriptors.sort_by_key(|d| d.offset_in_container);

        for desc in active_descriptors {
            let start = desc.offset_in_container as usize;
            let end = start + (desc.compressed_len as usize);
            let compressed_slice = &self.payload[start..end];

            let new_offset = new_container.payload.len() as u64;
            new_container.payload.extend_from_slice(compressed_slice);

            let mut new_desc = desc.clone();
            new_desc.offset_in_container = new_offset;
            new_desc.tombstoned = false;

            new_container.index.insert(desc.chunk_hash, new_desc);
            new_container.header.chunk_count += 1;
            new_container.header.total_uncompressed_bytes += desc.uncompressed_len as u64;
            new_container.header.total_compressed_bytes += desc.compressed_len as u64;
        }

        new_container.finalize();
        Ok(new_container)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_pack_read_and_serialize_roundtrip() {
        let mut container = CompactedContainer::new(
            "cont-2026-001",
            CloudProviderKind::AwsS3,
            CloudTierClass::Hot,
            CompressionCodec::Zstd,
        );

        let c1_data = b"velcrux-small-chunk-payload-01-testing-compression-and-indexing";
        let c1_hash = *blake3::hash(c1_data).as_bytes();

        let c2_data = b"velcrux-small-chunk-payload-02-another-fastcdc-variable-block";
        let c2_hash = *blake3::hash(c2_data).as_bytes();

        container.append_chunk(c1_hash, c1_data, 1000).unwrap();
        container.append_chunk(c2_hash, c2_data, 1000).unwrap();

        assert_eq!(container.active_chunk_count(), 2);
        assert_eq!(container.tombstoned_chunk_count(), 0);

        // Read chunk 1 directly
        let read1 = container.read_chunk(&c1_hash, 1001).unwrap();
        assert_eq!(read1, c1_data);

        // Serialize to bytes and deserialize
        let bytes = container.serialize_to_bytes().unwrap();
        let mut recovered = CompactedContainer::deserialize_from_bytes(&bytes).unwrap();

        assert_eq!(recovered.header.container_id, "cont-2026-001");
        assert_eq!(recovered.index.len(), 2);

        let read2 = recovered.read_chunk(&c2_hash, 1002).unwrap();
        assert_eq!(read2, c2_data);
    }

    #[test]
    fn test_container_range_calculation_and_tombstone_repack() {
        let mut container = CompactedContainer::new(
            "cont-repack-test",
            CloudProviderKind::GoogleGcs,
            CloudTierClass::Cool,
            CompressionCodec::None,
        );

        let chunk_a = vec![0x41u8; 1024];
        let chunk_b = vec![0x42u8; 2048];
        let hash_a = *blake3::hash(&chunk_a).as_bytes();
        let hash_b = *blake3::hash(&chunk_b).as_bytes();

        container.append_chunk(hash_a, &chunk_a, 2000).unwrap();
        container.append_chunk(hash_b, &chunk_b, 2000).unwrap();

        let range_a = container.get_chunk_cloud_range(&hash_a).unwrap();
        assert_eq!(range_a.0, 4096);
        assert_eq!(range_a.1, 4096 + 1024 - 1);

        // Tombstone Chunk A
        assert!(container.tombstone_chunk(&hash_a));
        assert_eq!(container.active_chunk_count(), 1);
        assert_eq!(container.tombstoned_chunk_count(), 1);
        assert!(container.fragmentation_ratio() > 0.0);

        // Repack
        let repacked = container.compact_and_repack("cont-repacked-002").unwrap();
        assert_eq!(repacked.active_chunk_count(), 1);
        assert_eq!(repacked.tombstoned_chunk_count(), 0);
        assert_eq!(repacked.fragmentation_ratio(), 0.0);
        assert!(repacked.index.contains_key(&hash_b));
        assert!(!repacked.index.contains_key(&hash_a));
    }
}
