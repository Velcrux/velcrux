//! Canonical binary codec for manifest entries (`PROTOCOL.md` §4).
//!
//! Pure functions over `&[u8]` and `&mut Vec<u8>`. No I/O.
//! Every length and count is validated against named protocol constants
//! before allocating.

use crate::error::ProtocolError;
use crate::manifest::entry::{ChunkDesc, ChunkFlags, FileEntry, FileFlags, FileType};
use crate::protocol::limits::{MAX_CHUNK_SIZE, MAX_PATH_TOTAL};
use crate::protocol::varint::{decode_varint, encode_varint};
use crate::storage::VPath;
use crate::util::Hash;

/// Encode a [`FileEntry`] in canonical binary format into `out`.
pub fn encode_file_entry(entry: &FileEntry, out: &mut Vec<u8>) {
    // 1. flags: varint
    let mut vbuf = [0u8; 10];
    let n = encode_varint(entry.flags.0, &mut vbuf);
    out.extend_from_slice(&vbuf[..n]);

    // 2. path_len: varint, then path bytes
    let path_bytes = entry.path.as_str().as_bytes();
    let n = encode_varint(path_bytes.len() as u64, &mut vbuf);
    out.extend_from_slice(&vbuf[..n]);
    out.extend_from_slice(path_bytes);

    // 3. size: 8 bytes LE
    out.extend_from_slice(&entry.size.to_le_bytes());

    // 4. mode: 4 bytes LE
    out.extend_from_slice(&entry.mode.to_le_bytes());

    // 5. mtime_sec: 8 bytes LE
    out.extend_from_slice(&entry.mtime_sec.to_le_bytes());

    // 6. mtime_nsec: 4 bytes LE
    out.extend_from_slice(&entry.mtime_nsec.to_le_bytes());

    // 7. file_hash: 32 bytes
    out.extend_from_slice(entry.file_hash.as_bytes());

    // 8. chunk_count: varint
    let n = encode_varint(entry.chunks.len() as u64, &mut vbuf);
    out.extend_from_slice(&vbuf[..n]);

    // 9. ChunkDesc sequence
    for chunk in &entry.chunks {
        encode_chunk_desc(chunk, out);
    }
}

/// Encode a single [`ChunkDesc`] into `out`.
pub fn encode_chunk_desc(chunk: &ChunkDesc, out: &mut Vec<u8>) {
    let mut vbuf = [0u8; 10];

    // flags: varint
    let n = encode_varint(chunk.flags.0, &mut vbuf);
    out.extend_from_slice(&vbuf[..n]);

    // length: varint
    let n = encode_varint(chunk.length, &mut vbuf);
    out.extend_from_slice(&vbuf[..n]);

    // hash: 32 bytes if not hole
    if !chunk.flags.is_hole() {
        if let Some(ref h) = chunk.hash {
            out.extend_from_slice(h.as_bytes());
        } else {
            out.extend_from_slice(Hash::ZERO.as_bytes());
        }
    }
}

/// Decode a [`FileEntry`] from `buf`. Returns `(FileEntry, bytes_consumed)`.
pub fn decode_file_entry(buf: &[u8]) -> Result<(FileEntry, usize), ProtocolError> {
    let mut offset = 0;

    // 1. flags: varint
    let (flags_val, c) = decode_varint(&buf[offset..])?;
    offset += c;
    let flags = FileFlags(flags_val);

    // 2. path_len: varint, then path bytes
    if offset >= buf.len() {
        return Err(ProtocolError::Malformed("FILE_ENTRY: truncated path length"));
    }
    let (path_len, c) = decode_varint(&buf[offset..])?;
    offset += c;
    if path_len as usize > MAX_PATH_TOTAL {
        return Err(ProtocolError::InvalidManifest(format!(
            "path length {path_len} exceeds MAX_PATH_TOTAL {MAX_PATH_TOTAL}"
        )));
    }
    let path_len_us = path_len as usize;
    if buf.len() < offset + path_len_us {
        return Err(ProtocolError::Malformed("FILE_ENTRY: truncated path bytes"));
    }
    let path_str = std::str::from_utf8(&buf[offset..offset + path_len_us])
        .map_err(|_| ProtocolError::Malformed("FILE_ENTRY: path is not valid UTF-8"))?;
    offset += path_len_us;

    // Receiver-side VPath validation (SECURITY.md §4)
    let path = VPath::validate(path_str).map_err(|e| {
        ProtocolError::InvalidManifest(format!("path validation failed for '{path_str}': {e}"))
    })?;

    // 3. Fixed size header: size (8), mode (4), mtime_sec (8), mtime_nsec (4), hash (32) = 56 bytes
    const FIXED_HDR_LEN: usize = 8 + 4 + 8 + 4 + 32;
    if buf.len() < offset + FIXED_HDR_LEN {
        return Err(ProtocolError::Malformed("FILE_ENTRY: truncated metadata fields"));
    }
    let size = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
    offset += 8;

    let mode = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let mtime_sec = i64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
    offset += 8;

    let mtime_nsec = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let file_hash = Hash::from_bytes(&buf[offset..offset + 32])
        .ok_or_else(|| ProtocolError::Malformed("FILE_ENTRY: invalid hash"))?;
    offset += 32;

    // 4. chunk_count: varint
    if offset >= buf.len() {
        return Err(ProtocolError::Malformed("FILE_ENTRY: truncated chunk count"));
    }
    let (chunk_count, c) = decode_varint(&buf[offset..])?;
    offset += c;

    // Limit chunk count check: 1M chunks per file max
    if chunk_count > crate::state::MAX_WIRE_CHUNKS {
        return Err(ProtocolError::InvalidManifest(format!(
            "chunk count {chunk_count} exceeds MAX_WIRE_CHUNKS"
        )));
    }

    let mut chunks = Vec::with_capacity(chunk_count as usize);
    let mut running_sum: u64 = 0;

    for _ in 0..chunk_count {
        let (chunk, consumed) = decode_chunk_desc(&buf[offset..])?;
        offset += consumed;
        if chunk.length > MAX_CHUNK_SIZE {
            return Err(ProtocolError::InvalidManifest(format!(
                "chunk length {} exceeds MAX_CHUNK_SIZE {MAX_CHUNK_SIZE}",
                chunk.length
            )));
        }
        running_sum = running_sum.checked_add(chunk.length).ok_or_else(|| {
            ProtocolError::InvalidManifest("chunk length overflow".into())
        })?;
        chunks.push(chunk);
    }

    // Consistency check: for regular files, sum of chunk lengths must equal size
    if flags.file_type() == FileType::Regular && running_sum != size {
        return Err(ProtocolError::InvalidManifest(format!(
            "declared size ({size}) does not match sum of chunk lengths ({running_sum}) for {}",
            path.as_str()
        )));
    }

    let entry = FileEntry {
        flags,
        path,
        size,
        mode,
        mtime_sec,
        mtime_nsec,
        file_hash,
        chunks,
    };

    Ok((entry, offset))
}

/// Decode a single [`ChunkDesc`] from `buf`. Returns `(ChunkDesc, bytes_consumed)`.
pub fn decode_chunk_desc(buf: &[u8]) -> Result<(ChunkDesc, usize), ProtocolError> {
    let mut offset = 0;

    // flags: varint
    let (flags_val, c) = decode_varint(&buf[offset..])?;
    offset += c;
    let flags = ChunkFlags(flags_val);

    // length: varint
    if offset >= buf.len() {
        return Err(ProtocolError::Malformed("CHUNK_DESC: truncated length"));
    }
    let (length, c) = decode_varint(&buf[offset..])?;
    offset += c;

    let hash = if flags.is_hole() {
        None
    } else {
        if buf.len() < offset + 32 {
            return Err(ProtocolError::Malformed("CHUNK_DESC: truncated hash"));
        }
        let h = Hash::from_bytes(&buf[offset..offset + 32])
            .ok_or_else(|| ProtocolError::Malformed("CHUNK_DESC: invalid hash"))?;
        offset += 32;
        Some(h)
    };

    Ok((ChunkDesc { flags, length, hash }, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_entry_roundtrip() {
        let chunk1 = ChunkDesc::new(1024, Hash::from_bytes(&[1u8; 32]).unwrap());
        let chunk2 = ChunkDesc::new(2048, Hash::from_bytes(&[2u8; 32]).unwrap());
        let chunk3 = ChunkDesc::hole(512);

        let entry = FileEntry {
            flags: FileFlags::regular().with_sparse(true),
            path: VPath::validate("documents/report.pdf").unwrap(),
            size: 3584,
            mode: 0o644,
            mtime_sec: 1700000000,
            mtime_nsec: 123456,
            file_hash: Hash::from_bytes(&[3u8; 32]).unwrap(),
            chunks: vec![chunk1, chunk2, chunk3],
        };

        let mut out = Vec::new();
        encode_file_entry(&entry, &mut out);

        let (decoded, consumed) = decode_file_entry(&out).unwrap();
        assert_eq!(consumed, out.len());
        assert_eq!(entry, decoded);
    }

    #[test]
    fn directory_entry_roundtrip() {
        let entry = FileEntry::directory(
            VPath::validate("documents/subdir").unwrap(),
            0o755,
            1700000000,
            0,
        );
        let mut out = Vec::new();
        encode_file_entry(&entry, &mut out);

        let (decoded, consumed) = decode_file_entry(&out).unwrap();
        assert_eq!(consumed, out.len());
        assert_eq!(entry, decoded);
    }

    #[test]
    fn reject_traversal_path() {
        let mut out = Vec::new();
        let flags_val = FileFlags::regular().0;
        let mut vbuf = [0u8; 10];
        let n = encode_varint(flags_val, &mut vbuf);
        out.extend_from_slice(&vbuf[..n]);

        let bad_path = b"../../etc/passwd";
        let n = encode_varint(bad_path.len() as u64, &mut vbuf);
        out.extend_from_slice(&vbuf[..n]);
        out.extend_from_slice(bad_path);

        out.extend_from_slice(&0u64.to_le_bytes()); // size
        out.extend_from_slice(&0o644u32.to_le_bytes()); // mode
        out.extend_from_slice(&0i64.to_le_bytes()); // mtime_sec
        out.extend_from_slice(&0u32.to_le_bytes()); // mtime_nsec
        out.extend_from_slice(Hash::ZERO.as_bytes()); // hash
        let n = encode_varint(0u64, &mut vbuf); // chunks
        out.extend_from_slice(&vbuf[..n]);

        let err = decode_file_entry(&out).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidManifest(_)));
    }
}
