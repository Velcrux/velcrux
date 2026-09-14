//! Filesystem scanner and manifest generator (`ARCHITECTURE.md` §7).
//!
//! Scans local files and directories streaming: reads files with bounded buffers,
//! runs the CDC chunker, computes per-chunk BLAKE3 digests, computes the
//! whole-file BLAKE3 digest in the same streaming pass, and streams entries
//! directly into [`ManifestWriter`].

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::chunking::{ChunkParams, Chunker, RollingChunker};
use crate::error::{ProtocolError, Result, VelcruxError};
use crate::manifest::entry::{ChunkDesc, FileEntry};
use crate::manifest::writer::ManifestWriter;
use crate::storage::VPath;
use crate::util::Hash;

/// Default buffer size used for streaming file reads during manifest scanning (2 MiB).
pub const SCANNER_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Stream-scans a single file on disk and adds it to `writer`.
pub fn scan_single_file(
    root: impl AsRef<Path>,
    rel_path: impl AsRef<Path>,
    writer: &mut ManifestWriter,
) -> Result<()> {
    let full_path = root.as_ref().join(rel_path.as_ref());
    let metadata = std::fs::symlink_metadata(&full_path)?;

    let vpath_str = rel_path
        .as_ref()
        .to_str()
        .ok_or_else(|| VelcruxError::Protocol(ProtocolError::InvalidPath))?;
    let vpath = VPath::validate(vpath_str)
        .map_err(|e| VelcruxError::Protocol(ProtocolError::InvalidManifest(e.to_string())))?;

    if metadata.is_dir() {
        let entry = FileEntry::directory(vpath, 0o755, 0, 0);
        writer.add_entry(entry)?;
        return Ok(());
    }

    let file_size = metadata.len();
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::MetadataExt;
        metadata.mode()
    };
    #[cfg(not(unix))]
    let mode = 0o644;

    let (mtime_sec, mtime_nsec) = match metadata.modified() {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            Err(_) => (0, 0),
        },
        Err(_) => (0, 0),
    };

    let mut file = File::open(&full_path)?;
    let mut read_buf = vec![0u8; SCANNER_BUFFER_SIZE];
    let mut pending = Vec::new();
    let mut pending_offset: u64 = 0;
    let mut chunker = RollingChunker::new(ChunkParams::default());
    let mut whole_hasher = blake3::Hasher::new();
    let mut chunks = Vec::new();

    loop {
        let n = file.read(&mut read_buf)?;
        if n == 0 {
            break;
        }
        let slice = &read_buf[..n];
        whole_hasher.update(slice);
        pending.extend_from_slice(slice);

        let boundaries = chunker.push(slice)?;
        for b in &boundaries {
            let target = b.end() as usize;
            let need = target - pending_offset as usize;
            let hash_bytes = blake3::hash(&pending[..need]);
            let hash = Hash::from_bytes(hash_bytes.as_bytes()).unwrap();
            chunks.push(ChunkDesc::new(need as u64, hash));
            pending.drain(..need);
            pending_offset = b.end();
        }
    }

    if let Some(b) = chunker.finish()? {
        let target = b.end() as usize;
        let need = target - pending_offset as usize;
        let hash_bytes = blake3::hash(&pending[..need]);
        let hash = Hash::from_bytes(hash_bytes.as_bytes()).unwrap();
        chunks.push(ChunkDesc::new(need as u64, hash));
        pending.drain(..need);
    }

    let file_digest = whole_hasher.finalize();
    let file_hash = Hash::from_bytes(file_digest.as_bytes()).unwrap();

    let entry = FileEntry::regular(
        vpath,
        file_size,
        mode,
        mtime_sec,
        mtime_nsec,
        file_hash,
        chunks,
    );

    writer.add_entry(entry)?;
    Ok(())
}

/// Recursively scans a directory tree and populates `writer` streaming.
pub fn scan_directory_tree(
    root: impl AsRef<Path>,
    writer: &mut ManifestWriter,
) -> Result<()> {
    let root = root.as_ref();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .map_err(|_| VelcruxError::Protocol(ProtocolError::InvalidPath))?;

            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                let vpath_str = rel
                    .to_str()
                    .ok_or_else(|| VelcruxError::Protocol(ProtocolError::InvalidPath))?;
                let vpath = VPath::validate(vpath_str).map_err(|e| {
                    VelcruxError::Protocol(ProtocolError::InvalidManifest(e.to_string()))
                })?;
                writer.add_entry(FileEntry::directory(vpath, 0o755, 0, 0))?;
                stack.push(path);
            } else if file_type.is_file() {
                scan_single_file(root, rel, writer)?;
            }
        }
    }

    Ok(())
}
