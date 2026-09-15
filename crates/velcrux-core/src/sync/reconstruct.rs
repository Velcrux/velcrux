//! Streaming delta reconstructor and atomic staging commit (`ARCHITECTURE.md` §7, §12).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use super::SyncError;
use crate::storage::LocalChunkStore;
use crate::util::Hash;

/// Progress statistics during delta reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaProgress {
    /// Total chunks expected in the destination file.
    pub total_chunks: usize,
    /// Chunks copied locally from the existing file at target path.
    pub local_chunks_copied: usize,
    /// Chunks copied from the content-addressed chunk store.
    pub store_chunks_copied: usize,
    /// Chunks written from wire transfer.
    pub wire_chunks_written: usize,
    /// Total bytes written to staging so far.
    pub bytes_written: u64,
    /// Target file size in bytes.
    pub total_bytes: u64,
}

/// Delta reconstructor that writes wire chunks, local file chunks, and chunk store chunks into a staging file,
/// verifies the whole-file BLAKE3 digest, and commits atomically.
pub struct DeltaReconstructor {
    target_path: PathBuf,
    staging_path: PathBuf,
    staging_file: Option<File>,
    expected_hash: Hash,
    total_size: u64,
    total_chunks: usize,
    local_chunks_copied: usize,
    store_chunks_copied: usize,
    wire_chunks_written: usize,
    bytes_written: u64,
    committed: bool,
}

impl DeltaReconstructor {
    /// Initialize a new reconstructor, creating and pre-allocating the staging file.
    pub fn new(
        target_path: PathBuf,
        staging_path: PathBuf,
        expected_hash: Hash,
        total_size: u64,
        total_chunks: usize,
    ) -> Result<Self, SyncError> {
        if let Some(parent) = staging_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&staging_path)?;

        // Pre-allocate target length
        file.set_len(total_size)?;

        Ok(Self {
            target_path,
            staging_path,
            staging_file: Some(file),
            expected_hash,
            total_size,
            total_chunks,
            local_chunks_copied: 0,
            store_chunks_copied: 0,
            wire_chunks_written: 0,
            bytes_written: 0,
            committed: false,
        })
    }

    /// Copy a chunk from an existing local file into staging at `dst_offset`.
    ///
    /// Copies using a bounded 64 KiB memory buffer to ensure strictly bounded RSS.
    pub fn copy_local_chunk(
        &mut self,
        src_file: &mut File,
        src_offset: u64,
        dst_offset: u64,
        length: u64,
    ) -> Result<(), SyncError> {
        let staging = self.staging_file.as_mut().ok_or_else(|| {
            SyncError::Reconstruction("staging file is closed or committed".into())
        })?;

        src_file.seek(SeekFrom::Start(src_offset))?;
        staging.seek(SeekFrom::Start(dst_offset))?;

        let mut remaining = length;
        let mut buf = [0u8; 64 * 1024];

        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = src_file.read(&mut buf[..to_read])?;
            if n == 0 {
                return Err(SyncError::Reconstruction(format!(
                    "unexpected EOF while copying local chunk at offset {src_offset}"
                )));
            }
            staging.write_all(&buf[..n])?;
            remaining -= n as u64;
        }

        self.local_chunks_copied += 1;
        self.bytes_written += length;
        Ok(())
    }

    /// Copy a chunk from the content-addressed [`LocalChunkStore`] into staging at `dst_offset`.
    pub fn copy_chunk_from_store(
        &mut self,
        chunk_store: &LocalChunkStore,
        hash: &Hash,
        dst_offset: u64,
    ) -> Result<(), SyncError> {
        let staging = self.staging_file.as_mut().ok_or_else(|| {
            SyncError::Reconstruction("staging file is closed or committed".into())
        })?;

        let bytes_copied = chunk_store
            .copy_to_std_file(hash, staging, dst_offset)
            .map_err(|e| {
                SyncError::Reconstruction(format!("failed to copy chunk from store: {e}"))
            })?;

        self.store_chunks_copied += 1;
        self.bytes_written += bytes_copied;
        Ok(())
    }

    /// Write an incoming chunk received over the wire into staging at `dst_offset`.
    pub fn write_wire_chunk(&mut self, dst_offset: u64, payload: &[u8]) -> Result<(), SyncError> {
        let staging = self.staging_file.as_mut().ok_or_else(|| {
            SyncError::Reconstruction("staging file is closed or committed".into())
        })?;

        staging.seek(SeekFrom::Start(dst_offset))?;
        staging.write_all(payload)?;

        self.wire_chunks_written += 1;
        self.bytes_written += payload.len() as u64;
        Ok(())
    }

    /// Current reconstruction progress.
    pub fn progress(&self) -> DeltaProgress {
        DeltaProgress {
            total_chunks: self.total_chunks,
            local_chunks_copied: self.local_chunks_copied,
            store_chunks_copied: self.store_chunks_copied,
            wire_chunks_written: self.wire_chunks_written,
            bytes_written: self.bytes_written,
            total_bytes: self.total_size,
        }
    }

    /// Verify whole-file BLAKE3 hash and atomically commit to target path.
    ///
    /// If verification succeeds:
    ///   - Atomically renames `staging_path` to `target_path`.
    ///
    /// If verification fails:
    ///   - Removes staging file and returns [`SyncError::HashMismatch`].
    pub fn verify_and_commit(mut self) -> Result<(), SyncError> {
        let mut file = self
            .staging_file
            .take()
            .ok_or_else(|| SyncError::Reconstruction("staging file already closed".into()))?;

        file.flush()?;
        file.seek(SeekFrom::Start(0))?;

        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        let mut read_bytes = 0u64;

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            read_bytes += n as u64;
        }

        if read_bytes != self.total_size {
            let _ = fs::remove_file(&self.staging_path);
            return Err(SyncError::Reconstruction(format!(
                "reconstructed file size mismatch: expected {}, got {}",
                self.total_size, read_bytes
            )));
        }

        let computed_hash = Hash::from_bytes(hasher.finalize().as_bytes()).unwrap();
        if computed_hash != self.expected_hash {
            let _ = fs::remove_file(&self.staging_path);
            return Err(SyncError::HashMismatch {
                expected: self.expected_hash.to_string(),
                actual: computed_hash.to_string(),
            });
        }

        // Close file handle prior to rename for Windows/cross-platform compatibility
        drop(file);

        if let Some(parent) = self.target_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::rename(&self.staging_path, &self.target_path)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for DeltaReconstructor {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.staging_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn reconstruct_hybrid_local_and_wire() {
        let dir = tempdir().unwrap();
        let existing_path = dir.path().join("existing.bin");
        let target_path = dir.path().join("target.bin");
        let staging_path = dir.path().join("target.bin.velcrux-partial");

        // Existing file has 3 chunks: [A, B, C]
        // Target file has: [A, Modified_B, C]
        let chunk_a = vec![0x11u8; 32 * 1024];
        let chunk_b_old = vec![0x22u8; 32 * 1024];
        let chunk_c = vec![0x33u8; 32 * 1024];

        let mut existing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&existing_path)
            .unwrap();
        existing_file.write_all(&chunk_a).unwrap();
        existing_file.write_all(&chunk_b_old).unwrap();
        existing_file.write_all(&chunk_c).unwrap();
        existing_file.flush().unwrap();

        let chunk_b_new = vec![0x99u8; 32 * 1024];
        let mut target_expected = Vec::new();
        target_expected.extend_from_slice(&chunk_a);
        target_expected.extend_from_slice(&chunk_b_new);
        target_expected.extend_from_slice(&chunk_c);
        let expected_hash = Hash::of(&target_expected);

        let mut recon = DeltaReconstructor::new(
            target_path.clone(),
            staging_path.clone(),
            expected_hash,
            target_expected.len() as u64,
            3,
        )
        .unwrap();

        // Copy chunk A from existing file (offset 0 -> 0)
        recon
            .copy_local_chunk(&mut existing_file, 0, 0, 32 * 1024)
            .unwrap();

        // Wire chunk B_new directly (offset 32 KiB)
        recon.write_wire_chunk(32 * 1024, &chunk_b_new).unwrap();

        // Copy chunk C from existing file (offset 64 KiB -> 64 KiB)
        recon
            .copy_local_chunk(&mut existing_file, 64 * 1024, 64 * 1024, 32 * 1024)
            .unwrap();

        assert_eq!(recon.progress().local_chunks_copied, 2);
        assert_eq!(recon.progress().wire_chunks_written, 1);

        recon.verify_and_commit().unwrap();

        assert!(target_path.exists());
        assert!(!staging_path.exists());

        let target_content = fs::read(&target_path).unwrap();
        assert_eq!(target_content, target_expected);
    }

    #[test]
    fn reconstruct_corruption_aborts_and_cleans_up() {
        let dir = tempdir().unwrap();
        let target_path = dir.path().join("target_corrupt.bin");
        let staging_path = dir.path().join("target_corrupt.bin.velcrux-partial");

        let expected_hash = Hash::of(b"correct data");
        let mut recon = DeltaReconstructor::new(
            target_path.clone(),
            staging_path.clone(),
            expected_hash,
            12,
            1,
        )
        .unwrap();

        recon.write_wire_chunk(0, b"corrupt data").unwrap();
        let res = recon.verify_and_commit();

        assert!(matches!(res, Err(SyncError::HashMismatch { .. })));
        assert!(!target_path.exists());
        assert!(!staging_path.exists());
    }
}
