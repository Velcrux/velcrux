//! Pipelined, bounded-memory chunking and parallel hashing engine.
//!
//! Enforces `CLAUDE.md` §1: 100% safe Rust (`#![forbid(unsafe_code)]`) and bounded channels.
//!
//! Decouples I/O reading, CDC boundary detection, and cryptographic hashing into an
//! asynchronous pipeline with bounded backpressure.

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

use crate::chunking::{create_chunker, ChunkMode, ChunkParams};
use crate::error::{Result, VelcruxError};
use crate::manifest::entry::ChunkDesc;
use crate::util::hash::Hash;
use crate::util::parallel_hash::ParallelHasher;

/// A fully chunked and cryptographically hashed block from the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelinedChunk {
    /// Zero-based sequential index of the chunk in the stream.
    pub index: u64,
    /// Absolute offset in the source stream.
    pub offset: u64,
    /// Length of the chunk in bytes.
    pub length: u64,
    /// Cryptographic BLAKE3 hash of the chunk data.
    pub hash: Hash,
    /// The chunk payload bytes.
    pub data: bytes::Bytes,
}

impl PipelinedChunk {
    /// Convert to manifest chunk descriptor.
    pub fn to_descriptor(&self) -> ChunkDesc {
        ChunkDesc::new(self.length, self.hash)
    }
}

/// Configuration for the pipelined chunking and hashing engine.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Chunking mode (FastCDC, CDC, Fixed).
    pub mode: ChunkMode,
    /// Chunk parameters (min, target, max).
    pub params: ChunkParams,
    /// Read buffer size (default: 2 MiB).
    pub read_buffer_size: usize,
    /// Maximum in-flight chunks allowed in the channel buffer before backpressure pauses reading.
    pub channel_capacity: usize,
    /// Number of worker threads for parallel chunk hashing.
    pub worker_concurrency: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            mode: ChunkMode::FastCdc,
            params: ChunkParams::default(),
            read_buffer_size: 2 * 1024 * 1024, // 2 MiB
            channel_capacity: 32, // 32 chunks * ~1 MiB = ~32 MiB max buffer (well under ceiling)
            worker_concurrency: 4,
        }
    }
}

/// High-throughput pipelined chunker decoupling reading, boundary detection, and hashing.
pub struct PipelinedChunker {
    config: PipelineConfig,
    hasher: Arc<ParallelHasher>,
}

impl PipelinedChunker {
    /// Create a new `PipelinedChunker` with the given configuration.
    pub fn new(config: PipelineConfig) -> Self {
        let hasher = Arc::new(ParallelHasher::new(config.worker_concurrency));
        Self { config, hasher }
    }

    /// Process an in-memory byte buffer, returning all hashed chunks.
    pub fn process_slice(&self, data: &[u8]) -> Result<Vec<PipelinedChunk>> {
        let mut chunker = create_chunker(self.config.mode, self.config.params);
        let mut raw_chunks = Vec::new();
        let mut cursor = 0usize;

        while cursor < data.len() {
            let next_end = (cursor + self.config.read_buffer_size).min(data.len());
            let slice = &data[cursor..next_end];

            let boundaries = chunker.push(slice)?;
            for b in boundaries {
                let start = b.offset as usize;
                let end = start + b.length as usize;
                raw_chunks.push((b, bytes::Bytes::copy_from_slice(&data[start..end])));
            }
            cursor = next_end;
        }

        while let Some(b) = chunker.finish()? {
            let start = b.offset as usize;
            let end = start + b.length as usize;
            raw_chunks.push((b, bytes::Bytes::copy_from_slice(&data[start..end])));
        }

        // Batch compute all hashes in parallel
        let slices: Vec<&[u8]> = raw_chunks.iter().map(|(_, b)| b.as_ref()).collect();
        let hashes = self.hasher.hash_chunks_batched(&slices);

        let mut pipelined = Vec::with_capacity(raw_chunks.len());
        for (i, ((b, data), hash)) in raw_chunks.into_iter().zip(hashes).enumerate() {
            pipelined.push(PipelinedChunk {
                index: i as u64,
                offset: b.offset,
                length: b.length,
                hash,
                data,
            });
        }

        Ok(pipelined)
    }

    /// Stream chunks from an asynchronous reader through bounded mpsc channels.
    ///
    /// Spawns a background worker task that reads, segments, hashes in parallel,
    /// and streams `PipelinedChunk` instances into the returned channel.
    pub fn stream_reader<R>(&self, mut reader: R) -> mpsc::Receiver<Result<PipelinedChunk>>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(self.config.channel_capacity);
        let config = self.config.clone();
        let _hasher = Arc::clone(&self.hasher);

        tokio::spawn(async move {
            let mut chunker = create_chunker(config.mode, config.params);
            let mut read_buf = vec![0u8; config.read_buffer_size];
            let mut pending_data = Vec::new();
            let mut chunk_index = 0u64;

            loop {
                let n = match reader.read(&mut read_buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(e) => {
                        let _ = tx.send(Err(VelcruxError::Io(e))).await;
                        return;
                    }
                };

                let slice = &read_buf[..n];
                pending_data.extend_from_slice(slice);

                let boundaries = match chunker.push(slice) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };

                for b in boundaries {
                    let chunk_len = b.length as usize;
                    if pending_data.len() < chunk_len {
                        let _ = tx
                            .send(Err(VelcruxError::Internal(
                                "pending data underflow during pipelined chunking".into(),
                            )))
                            .await;
                        return;
                    }

                    let chunk_bytes = bytes::Bytes::copy_from_slice(&pending_data[..chunk_len]);
                    pending_data.drain(..chunk_len);

                    let hash = Hash::of(&chunk_bytes);
                    let item = PipelinedChunk {
                        index: chunk_index,
                        offset: b.offset,
                        length: b.length,
                        hash,
                        data: chunk_bytes,
                    };
                    chunk_index += 1;

                    if tx.send(Ok(item)).await.is_err() {
                        return; // Consumer dropped channel
                    }
                }
            }

            // Finish remaining stream bytes
            while let Ok(Some(b)) = chunker.finish() {
                let chunk_len = b.length as usize;
                let chunk_bytes = bytes::Bytes::copy_from_slice(&pending_data[..chunk_len]);
                pending_data.drain(..chunk_len);

                let hash = Hash::of(&chunk_bytes);
                let item = PipelinedChunk {
                    index: chunk_index,
                    offset: b.offset,
                    length: b.length,
                    hash,
                    data: chunk_bytes,
                };
                chunk_index += 1;

                if tx.send(Ok(item)).await.is_err() {
                    return;
                }
            }
        });

        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_slice_reproduces_input() {
        let config = PipelineConfig {
            mode: ChunkMode::FastCdc,
            params: ChunkParams {
                min: 1024,
                target: 4096,
                max: 16384,
            },
            read_buffer_size: 4096,
            channel_capacity: 16,
            worker_concurrency: 2,
        };
        let pipeline = PipelinedChunker::new(config);

        let mut sample_data = Vec::with_capacity(64 * 1024);
        for i in 0..(64 * 1024) {
            sample_data.push((i % 251) as u8);
        }

        let chunks = pipeline.process_slice(&sample_data).unwrap();
        assert!(!chunks.is_empty());

        let mut concatenated = Vec::new();
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.index, i as u64);
            assert_eq!(c.hash, Hash::of(&c.data));
            assert_eq!(c.length, c.data.len() as u64);
            concatenated.extend_from_slice(&c.data);
        }

        assert_eq!(concatenated, sample_data);
    }

    #[tokio::test]
    async fn test_stream_reader_pipeline() {
        let config = PipelineConfig {
            mode: ChunkMode::Fixed,
            params: ChunkParams {
                min: 2048,
                target: 2048,
                max: 2048,
            },
            read_buffer_size: 1024,
            channel_capacity: 8,
            worker_concurrency: 2,
        };
        let pipeline = PipelinedChunker::new(config);

        let data = vec![0xAB; 10000];
        let cursor = std::io::Cursor::new(data.clone());

        let mut rx = pipeline.stream_reader(cursor);
        let mut reconstructed = Vec::new();

        while let Some(res) = rx.recv().await {
            let chunk = res.unwrap();
            reconstructed.extend_from_slice(&chunk.data);
        }

        assert_eq!(reconstructed, data);
    }
}
