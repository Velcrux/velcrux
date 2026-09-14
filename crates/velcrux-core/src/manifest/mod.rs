//! Streaming framed manifests (`docs/ARCHITECTURE.md` §3, `PROTOCOL.md` §4, `ADR-005`).
//!
//! A manifest describes the complete directory structure, metadata, whole-file
//! hashes, and chunk descriptors for a transfer.
//!
//! Key invariants:
//! - Never allocated as `Vec<Everything>`. Memory is bounded to one batch of up to
//!   4096 entries (`MANIFEST_BATCH_SIZE`).
//! - Each batch is zstd-compressed on the wire.
//! - The manifest is content-addressed by the BLAKE3 digest of its canonical binary encoding.
//! - Receiver validates paths, bounds, and chunk hashes before staging or committing.

pub mod codec;
pub mod entry;
pub mod reader;
pub mod scanner;
pub mod store;
pub mod writer;

pub use codec::{decode_chunk_desc, decode_file_entry, encode_chunk_desc, encode_file_entry};
pub use entry::{
    ChunkDesc, ChunkFlags, FileEntry, FileFlags, FileType, CHUNK_FLAG_HOLE, FILE_FLAG_HAS_XATTRS,
    FILE_FLAG_SPARSE, FILE_TYPE_DIR, FILE_TYPE_REGULAR, FILE_TYPE_SYMLINK,
};
pub use reader::{decompress_batch, ManifestBatchDecoder, ManifestReader};
pub use scanner::{scan_directory_tree, scan_single_file, SCANNER_BUFFER_SIZE};
pub use store::ManifestStore;
pub use writer::{ManifestWriter, SPILL_MAGIC, SPILL_VERSION};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::ChunkParams;
    use crate::storage::VPath;
    use crate::util::Hash;
    use tempfile::tempdir;

    #[test]
    fn writer_reader_roundtrip() {
        let dir = tempdir().unwrap();
        let spill_path = dir.path().join("test.spill");

        let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default()).unwrap();

        let num_entries = 10_000;
        for i in 0..num_entries {
            let path = VPath::validate(&format!("dir_{}/file_{}.bin", i / 100, i)).unwrap();
            let chunk = ChunkDesc::new(1024, Hash::from_bytes(&[i as u8; 32]).unwrap());
            let entry = FileEntry::regular(
                path,
                1024,
                0o644,
                1700000000 + i as i64,
                0,
                Hash::from_bytes(&[(i % 256) as u8; 32]).unwrap(),
                vec![chunk],
            );
            writer.add_entry(entry).unwrap();
        }

        let (begin, end, path) = writer.finish().unwrap();
        assert_eq!(begin.file_count, num_entries);
        assert_eq!(begin.total_bytes, num_entries * 1024);
        assert_eq!(begin.manifest_hash, end.manifest_hash);

        // Read back using ManifestReader
        let mut reader = ManifestReader::open(&path, begin.manifest_hash).unwrap();
        let mut count = 0;
        while let Some(entry) = reader.next_entry().unwrap() {
            assert_eq!(
                entry.path.as_str(),
                format!("dir_{}/file_{}.bin", count / 100, count)
            );
            count += 1;
        }
        assert_eq!(count, num_entries);
    }

    #[test]
    fn batch_decoder_roundtrip() {
        let dir = tempdir().unwrap();
        let spill_path = dir.path().join("batch_test.spill");

        let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default()).unwrap();
        let path = VPath::validate("single/file.txt").unwrap();
        let chunk = ChunkDesc::new(100, Hash::ZERO);
        let entry = FileEntry::regular(path, 100, 0o644, 1000, 0, Hash::ZERO, vec![chunk]);
        writer.add_entry(entry.clone()).unwrap();

        let (begin, _, path) = writer.finish().unwrap();

        let mut reader = ManifestReader::open(&path, begin.manifest_hash).unwrap();
        let read_entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(read_entry, entry);
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn tampered_manifest_hash_is_rejected() {
        let dir = tempdir().unwrap();
        let spill_path = dir.path().join("tampered.spill");

        let mut writer = ManifestWriter::new(&spill_path, ChunkParams::default()).unwrap();
        let path = VPath::validate("file.txt").unwrap();
        let chunk = ChunkDesc::new(10, Hash::ZERO);
        writer
            .add_entry(FileEntry::regular(
                path,
                10,
                0o644,
                0,
                0,
                Hash::ZERO,
                vec![chunk],
            ))
            .unwrap();
        let (begin, _, path) = writer.finish().unwrap();

        // Tamper with expected hash
        let mut bad_hash_bytes = *begin.manifest_hash.as_bytes();
        bad_hash_bytes[0] ^= 0xFF;
        let bad_hash = Hash::from_bytes(&bad_hash_bytes).unwrap();

        let mut reader = ManifestReader::open(&path, bad_hash).unwrap();
        let _ = reader.next_entry().unwrap();
        // At EOF, reader verifies hash and fails
        let err = reader.next_entry().unwrap_err();
        assert!(matches!(
            err,
            crate::error::VelcruxError::Protocol(crate::error::ProtocolError::InvalidManifest(_))
        ));
    }
}
