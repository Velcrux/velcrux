//! Filesystem scanner and manifest generator (`ARCHITECTURE.md` §7).
//!
//! Scans local files and directories streaming: reads files with bounded buffers,
//! runs the CDC chunker, computes per-chunk BLAKE3 digests, computes the
//! whole-file BLAKE3 digest in the same streaming pass, and streams entries
//! directly into [`ManifestWriter`].

use std::fs::File;
use std::path::Path;

use crate::chunking::{ChunkEngine, ChunkMode, ChunkParams};
use crate::error::{ProtocolError, Result, VelcruxError};
use crate::manifest::entry::FileEntry;
use crate::manifest::writer::ManifestWriter;
use crate::storage::VPath;

/// Default buffer size used for streaming file reads during manifest scanning (2 MiB).
pub const SCANNER_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// Stream-scans a single file on disk and adds it to `writer` using default CDC chunking.
pub fn scan_single_file(
    root: impl AsRef<Path>,
    rel_path: impl AsRef<Path>,
    writer: &mut ManifestWriter,
) -> Result<()> {
    scan_single_file_with_mode(
        root,
        rel_path,
        writer,
        ChunkMode::Cdc,
        ChunkParams::default(),
    )
}

/// Stream-scans a single file on disk and adds it to `writer` using the specified chunk mode and parameters.
pub fn scan_single_file_with_mode(
    root: impl AsRef<Path>,
    rel_path: impl AsRef<Path>,
    writer: &mut ManifestWriter,
    chunk_mode: ChunkMode,
    params: ChunkParams,
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

    let file = File::open(&full_path)?;
    let mut chunks = Vec::new();
    let (file_hash, _) = ChunkEngine::chunk_reader(
        file,
        chunk_mode,
        params,
        SCANNER_BUFFER_SIZE,
        |desc, _bytes| {
            chunks.push(desc);
            Ok(())
        },
    )?;

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

/// Recursively scans a directory tree and populates `writer` streaming using default CDC chunking.
pub fn scan_directory_tree(
    root: impl AsRef<Path>,
    writer: &mut ManifestWriter,
) -> Result<()> {
    scan_directory_tree_with_mode(root, writer, ChunkMode::Cdc, ChunkParams::default())
}

/// Recursively scans a directory tree and populates `writer` streaming using the specified chunk mode and parameters.
pub fn scan_directory_tree_with_mode(
    root: impl AsRef<Path>,
    writer: &mut ManifestWriter,
    chunk_mode: ChunkMode,
    params: ChunkParams,
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
                scan_single_file_with_mode(root, rel, writer, chunk_mode, params)?;
            }
        }
    }

    Ok(())
}
