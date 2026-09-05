//! Control and metadata frame header codec.
//!
//! Layout (`PROTOCOL.md` §3):
//!
//! ```text
//!  0        1        2        3        4
//! +--------+--------+--------+--------+-------------------------+
//! | ver(1) | type(1)|    flags (2)    |      length (varint)    |
//! +--------+--------+--------+--------+-------------------------+
//! |              request_id (u64, LE)                           |
//! +-------------------------------------------------------------+
//! |              payload (length bytes)                         |
//! +-------------------------------------------------------------+
//! ```
//!
//! The header is 12 bytes when `length` fits in a single varint byte (the
//! common case for small control frames). The `length` is a varint, so the
//! total header size varies between 12 and 21 bytes for any u64 length.

use crate::error::ProtocolError;
use crate::protocol::limits::{MAX_MESSAGE_SIZE, PROTOCOL_VERSION};
use crate::protocol::varint;

/// Length of the fixed prefix of a frame header: `ver | type | flags` plus
/// the 1-byte short varint. The full header is
/// `FRAME_HEADER_LEN + (varint_len(length) - 1) + 8` for `request_id`.
pub const FRAME_HEADER_LEN: usize = 4;

/// Bitflags in the 2-byte `flags` field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameFlags(pub u16);

impl FrameFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// `END_OF_SEQUENCE` (bit 0). Marks the last frame in a logical sequence
    /// (e.g. last `MANIFEST_BATCH`).
    pub const END_OF_SEQUENCE: Self = Self(0b0000_0001);
    /// `COMPRESSED` (bit 1). Payload is zstd-compressed.
    pub const COMPRESSED: Self = Self(0b0000_0010);

    /// Returns the raw 2-byte value.
    #[inline]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Constructs a `FrameFlags` from raw bits, masking to 16 bits.
    #[inline]
    pub const fn from_bits_truncate(bits: u16) -> Self {
        Self(bits & 0xFFFF)
    }

    /// True if the `END_OF_SEQUENCE` bit is set.
    #[inline]
    pub const fn end_of_sequence(self) -> bool {
        (self.0 & 0x0001) != 0
    }

    /// True if the `COMPRESSED` bit is set.
    #[inline]
    pub const fn compressed(self) -> bool {
        (self.0 & 0x0002) != 0
    }
}

impl std::ops::BitOr for FrameFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// A decoded frame header plus the full payload bytes.
///
/// The payload is borrowed from the input buffer; this struct does not copy.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// Wire version, must equal [`PROTOCOL_VERSION`].
    pub version: u8,
    /// Message type byte.
    pub type_byte: u8,
    /// Decoded flags.
    pub flags: FrameFlags,
    /// Payload byte count.
    pub length: u64,
    /// Echoed request id (zero for unsolicited messages).
    pub request_id: u64,
    /// Payload bytes (length `Frame::length`).
    pub payload: &'a [u8],
}

/// Compute the total number of header bytes for a frame with the given
/// `length` field.
#[inline]
pub fn header_size_for(length: u64) -> usize {
    // 4 fixed bytes (ver, type, flags) + varint_len(length) for the length
    // varint (written in full at offset 4) + 8 for request_id.
    4 + varint::varint_len(length) + 8
}

// ---------------------------------------------------------------------------
// DATA stream (unidirectional; sender → receiver)
// ---------------------------------------------------------------------------
//
// `PROTOCOL.md` §3:
//
// Data stream preamble (once per stream):
// +-------------------------+-------------------------+
// |  transfer_id (16 bytes) |    file_id (u64, LE)    |
// +-------------------------+-------------------------+
// |  stream_seq (u64, LE)   |                       0 |
// +-------------------------+-------------------------+
// | reserved (16 bytes, 0)                          |
// +-------------------------+-------------------------+
//
// DATA frame (one per chunk; no 12-byte frame header on data streams):
// +--------------+--------------+----------------------------+
// | chunk_off(u64)| chunk_len(u32)| flags(2)  | reserved(2)  |
// +--------------+--------------+----------------------------+
// | chunk_hash(32 bytes)                                      |
// +------------------------------------------------------------+
// | chunk_payload (chunk_len bytes)                           |
// +------------------------------------------------------------+
//
// `chunk_len` is u32 here so we have a hard cap of 4 GiB per frame,
// consistent with `MAX_CHUNK_SIZE` (4 MiB). `chunk_off` is u64 because
// it is an absolute byte offset within the file (CLAUDE.md §1 #4).

/// Total length of the data-stream preamble. 16 + 8 + 8 + 8 + 16 = 56 bytes.
pub const DATA_PREAMBLE_LEN: usize = 56;
/// Header length of a DATA frame (no payload): 8 + 4 + 2 + 2 + 32 = 48 bytes.
pub const DATA_FRAME_HEADER_LEN: usize = 48;
/// Maximum declared `chunk_len` on a DATA frame. M2 keeps this identical to
/// `MAX_CHUNK_SIZE` from `protocol/limits.rs`.
pub const DATA_MAX_CHUNK_LEN: u32 = 4 * 1024 * 1024;

/// Data-stream preamble (sent once at the start of every data stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPreamble {
    /// Transfer this stream belongs to.
    pub transfer_id: crate::util::TransferId,
    /// Logical file id within the transfer (always 1 in M2; reserved for M5).
    pub file_id: u64,
    /// Stream sequence number within the transfer (always 1 in M2; reserved
    /// for the multi-stream-per-file optimisation gated on benchmarks).
    pub stream_seq: u64,
}

/// Encode a [`DataPreamble`] into a 56-byte buffer.
pub fn encode_data_preamble(p: &DataPreamble) -> [u8; DATA_PREAMBLE_LEN] {
    let mut out = [0u8; DATA_PREAMBLE_LEN];
    out[..16].copy_from_slice(p.transfer_id.as_bytes());
    out[16..24].copy_from_slice(&p.file_id.to_le_bytes());
    out[24..32].copy_from_slice(&p.stream_seq.to_le_bytes());
    // Bytes 32..56 are reserved (must be zero on send).
    out
}

/// Decode a [`DataPreamble`] from a 56-byte buffer.
pub fn decode_data_preamble(buf: &[u8]) -> Result<DataPreamble, ProtocolError> {
    if buf.len() < DATA_PREAMBLE_LEN {
        return Err(ProtocolError::Malformed("data preamble: truncated"));
    }
    let transfer_id = crate::util::TransferId::from_bytes(&buf[..16])
        .ok_or_else(|| ProtocolError::Malformed("data preamble: bad transfer_id"))?;
    let file_id = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let stream_seq = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    Ok(DataPreamble { transfer_id, file_id, stream_seq })
}

/// Flags on a DATA frame. Currently none are defined; reserved bits must
/// be zero on send.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataFrameFlags(pub u16);

impl DataFrameFlags {
    pub const NONE: Self = Self(0);
    pub const fn bits(self) -> u16 {
        self.0
    }
    pub const fn from_bits_truncate(bits: u16) -> Self {
        Self(bits & 0xFFFF)
    }
}

/// Maximum permitted `length` for a frame. Reads use this as the bound
/// check; writes use it as a ceiling. Pulled from `MAX_MESSAGE_SIZE` so the
/// default is named (`PROTOCOL.md` §3).
#[inline]
pub fn max_message_size() -> u64 {
    MAX_MESSAGE_SIZE
}

/// Decode a frame from `buf`. The buffer must contain a complete frame
/// (header + payload); partial buffers return [`ProtocolError::Empty`]
/// (truncated) via the `varint` decoder.
///
/// This function **does not allocate** for the payload — the returned
/// `Frame::payload` is a borrow. The caller decides whether to copy.
pub fn decode_frame(buf: &[u8]) -> Result<Frame<'_>, ProtocolError> {
    if buf.len() < 4 {
        return Err(ProtocolError::Empty);
    }
    let version = buf[0];
    let type_byte = buf[1];
    let flags_raw = u16::from_le_bytes([buf[2], buf[3]]);
    let flags = FrameFlags::from_bits_truncate(flags_raw);

    // `length` varint starts at offset 4. The decoder's first read overlaps
    // the 4 fixed bytes (the 1-byte short varint form is *not* folded into
    // the 4 bytes here, by encoder design — see `encode_frame`).
    let (length, varint_consumed) = varint::decode_varint(&buf[4..])?;
    let header_len = 4 + varint_consumed + 8;
    if buf.len() < header_len {
        return Err(ProtocolError::Empty);
    }

    // The most important bound in the protocol: declared length must fit
    // both in `max_message_size` AND in the remaining bytes of `buf`. The
    // first check is the security boundary (rejects a malicious declaration
    // before any allocation); the second is a wire consistency check.
    let max = max_message_size();
    if length > max {
        return Err(ProtocolError::FrameTooLarge { declared: length, limit: max });
    }
    let payload_len: usize = length.try_into().map_err(|_| ProtocolError::FrameTooLarge {
        declared: length,
        limit: max,
    })?;
    if buf.len() < header_len + payload_len {
        return Err(ProtocolError::Empty);
    }

    let rid_off = 4 + varint_consumed;
    let request_id = u64::from_le_bytes([
        buf[rid_off],
        buf[rid_off + 1],
        buf[rid_off + 2],
        buf[rid_off + 3],
        buf[rid_off + 4],
        buf[rid_off + 5],
        buf[rid_off + 6],
        buf[rid_off + 7],
    ]);
    let payload = &buf[header_len..header_len + payload_len];

    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            got: version,
            expected: PROTOCOL_VERSION,
        });
    }

    Ok(Frame {
        version,
        type_byte,
        flags,
        length,
        request_id,
        payload,
    })
}

/// A DATA frame header parsed from the wire (no payload attached).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataFrameHeader {
    pub chunk_offset: u64,
    pub chunk_len: u32,
    pub flags: DataFrameFlags,
    pub chunk_hash: crate::util::Hash,
}

/// A DATA frame: header plus a borrowed payload.
///
/// `payload.len()` may be smaller than `chunk_len` if the read was
/// truncated; the caller must check before consuming.
#[derive(Debug, Clone, Copy)]
pub struct DataFrame<'a> {
    pub chunk_offset: u64,
    pub chunk_len: u32,
    pub flags: DataFrameFlags,
    pub chunk_hash: crate::util::Hash,
    pub payload: &'a [u8],
}

/// Encode a DATA frame header (48 bytes) into `out`.
pub fn encode_data_frame_header(
    out: &mut [u8],
    chunk_offset: u64,
    chunk_len: u32,
    flags: DataFrameFlags,
    chunk_hash: &crate::util::Hash,
) {
    debug_assert_eq!(out.len(), DATA_FRAME_HEADER_LEN, "encode_data_frame_header: bad out length");
    out[..8].copy_from_slice(&chunk_offset.to_le_bytes());
    out[8..12].copy_from_slice(&chunk_len.to_le_bytes());
    let fb = flags.bits().to_le_bytes();
    out[12..14].copy_from_slice(&fb);
    out[14..16].copy_from_slice(&[0u8; 2]); // reserved
    out[16..48].copy_from_slice(chunk_hash.as_bytes());
}

/// Decode a DATA frame header from `buf`. Returns the header and the
/// trailing payload bytes. The caller is responsible for verifying that
/// the trailing payload length matches `header.chunk_len` and that the
/// payload hashes to `header.chunk_hash`.
pub fn decode_data_frame_header(buf: &[u8]) -> Result<(DataFrameHeader, &[u8]), ProtocolError> {
    if buf.len() < DATA_FRAME_HEADER_LEN {
        return Err(ProtocolError::Malformed("data frame: truncated header"));
    }
    let chunk_offset = u64::from_le_bytes(buf[..8].try_into().unwrap());
    let chunk_len = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if chunk_len > DATA_MAX_CHUNK_LEN {
        return Err(ProtocolError::Malformed("data frame: chunk_len > max"));
    }
    let flags = DataFrameFlags::from_bits_truncate(u16::from_le_bytes(buf[12..14].try_into().unwrap()));
    let reserved = u16::from_le_bytes(buf[14..16].try_into().unwrap());
    if reserved != 0 {
        return Err(ProtocolError::Malformed("data frame: reserved bits set"));
    }
    let chunk_hash = crate::util::Hash::from_bytes(&buf[16..48])
        .ok_or_else(|| ProtocolError::Malformed("data frame: bad chunk hash"))?;
    let payload = &buf[DATA_FRAME_HEADER_LEN..];
    Ok((DataFrameHeader { chunk_offset, chunk_len, flags, chunk_hash }, payload))
}

/// Encode a full DATA frame (header + payload) into a fresh buffer.
/// Returns the buffer. The payload is appended verbatim; no compression.
pub fn encode_data_frame(
    chunk_offset: u64,
    chunk_len: u32,
    flags: DataFrameFlags,
    chunk_hash: &crate::util::Hash,
    payload: &[u8],
) -> Vec<u8> {
    debug_assert_eq!(payload.len() as u64, chunk_len as u64, "encode_data_frame: payload/chunk_len mismatch");
    let mut out = Vec::with_capacity(DATA_FRAME_HEADER_LEN + payload.len());
    out.resize(DATA_FRAME_HEADER_LEN, 0);
    encode_data_frame_header(&mut out, chunk_offset, chunk_len, flags, chunk_hash);
    out.extend_from_slice(payload);
    out
}

/// Encode a frame into `out`. Returns the number of bytes written.
///
/// `out` must be sized for the full frame: `header_size_for(length) + length`.
/// Callers should pre-size using [`header_size_for`] and `length`.
pub fn encode_frame(
    out: &mut [u8],
    type_byte: u8,
    flags: FrameFlags,
    request_id: u64,
    payload: &[u8],
) -> usize {
    let length = payload.len() as u64;
    let total = header_size_for(length) + payload.len();
    debug_assert!(out.len() >= total, "encode_frame: output buffer too small");

    out[0] = PROTOCOL_VERSION;
    out[1] = type_byte;
    let fb = flags.bits().to_le_bytes();
    out[2] = fb[0];
    out[3] = fb[1];

    let varint_len_bytes = varint::varint_len(length);
    varint::encode_varint(length, &mut out[4..4 + varint_len_bytes]);
    let rid_off = 4 + varint_len_bytes;
    out[rid_off..rid_off + 8].copy_from_slice(&request_id.to_le_bytes());
    let payload_off = rid_off + 8;
    out[payload_off..payload_off + payload.len()].copy_from_slice(payload);
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::limits::PROTOCOL_VERSION;

    fn roundtrip(type_byte: u8, flags: FrameFlags, request_id: u64, payload: &[u8]) {
        let length = payload.len() as u64;
        let total = header_size_for(length) + payload.len();
        let mut buf = vec![0u8; total];
        let n = encode_frame(&mut buf, type_byte, flags, request_id, payload);
        assert_eq!(n, total);

        let f = decode_frame(&buf).unwrap();
        assert_eq!(f.version, PROTOCOL_VERSION);
        assert_eq!(f.type_byte, type_byte);
        assert_eq!(f.flags, flags);
        assert_eq!(f.length, length);
        assert_eq!(f.request_id, request_id);
        assert_eq!(f.payload, payload);
    }

    #[test]
    fn empty_payload_roundtrip() {
        roundtrip(0x06, FrameFlags::NONE, 0, &[]);
    }

    #[test]
    fn small_payload_roundtrip() {
        roundtrip(0x06, FrameFlags::END_OF_SEQUENCE, 42, b"hello");
    }

    #[test]
    fn flags_roundtrip() {
        let f = FrameFlags::END_OF_SEQUENCE | FrameFlags::COMPRESSED;
        roundtrip(0x06, f, 1, b"x");
        assert!(f.end_of_sequence());
        assert!(f.compressed());
    }

    #[test]
    fn rejects_oversized_length() {
        // Header declares a length larger than max_message_size.
        let bad = MAX_MESSAGE_SIZE + 1;
        let mut buf = vec![0u8; 4 + varint::varint_len(bad) + 8];
        buf[0] = PROTOCOL_VERSION;
        buf[1] = 0x01;
        let v = varint::varint_len(bad);
        varint::encode_varint(bad, &mut buf[4..4 + v]);
        let e = decode_frame(&buf);
        assert!(matches!(e, Err(ProtocolError::FrameTooLarge { .. })));
    }

    #[test]
    fn rejects_version_mismatch() {
        let mut buf = vec![0u8; 4 + 1 + 8];
        buf[0] = PROTOCOL_VERSION.wrapping_add(1);
        buf[1] = 0x01;
        let e = decode_frame(&buf);
        assert!(matches!(e, Err(ProtocolError::VersionMismatch { .. })));
    }

    #[test]
    fn rejects_truncated_buffer() {
        let e = decode_frame(&[PROTOCOL_VERSION, 0x01, 0, 0]);
        assert!(matches!(e, Err(ProtocolError::Empty)));
    }

    #[test]
    fn data_preamble_roundtrip() {
        let tid = crate::util::TransferId::generate();
        let p = DataPreamble { transfer_id: tid, file_id: 1, stream_seq: 1 };
        let bytes = encode_data_preamble(&p);
        assert_eq!(bytes.len(), DATA_PREAMBLE_LEN);
        // Reserved 24 bytes must be zero on send.
        for &b in &bytes[32..] {
            assert_eq!(b, 0);
        }
        let p2 = decode_data_preamble(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn data_preamble_rejects_truncated() {
        let bytes = [0u8; 30];
        assert!(matches!(
            decode_data_preamble(&bytes),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn data_frame_roundtrip() {
        let h = crate::util::Hash::of(b"hello");
        let payload = b"hello";
        let buf = encode_data_frame(1024, 5, DataFrameFlags::NONE, &h, payload);
        let (hdr, payload_after) = decode_data_frame_header(&buf).unwrap();
        assert_eq!(hdr.chunk_offset, 1024);
        assert_eq!(hdr.chunk_len, 5);
        assert_eq!(hdr.chunk_hash, h);
        assert_eq!(payload_after, payload);
        // Verify the chunk hash matches the payload.
        let computed = crate::util::Hash::of(payload_after);
        assert_eq!(computed, h);
    }

    #[test]
    fn data_frame_rejects_oversized_chunk_len() {
        // Header claims chunk_len > MAX; decode rejects.
        let mut bad = vec![0u8; DATA_FRAME_HEADER_LEN];
        bad[..8].copy_from_slice(&0u64.to_le_bytes());
        bad[8..12].copy_from_slice(&(DATA_MAX_CHUNK_LEN + 1).to_le_bytes());
        assert!(matches!(
            decode_data_frame_header(&bad),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn data_frame_rejects_reserved_bits() {
        let mut bad = vec![0u8; DATA_FRAME_HEADER_LEN];
        bad[14] = 0x01; // reserved bits
        assert!(matches!(
            decode_data_frame_header(&bad),
            Err(ProtocolError::Malformed(_))
        ));
    }
}
