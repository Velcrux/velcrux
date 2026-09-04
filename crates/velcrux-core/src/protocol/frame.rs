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
}
