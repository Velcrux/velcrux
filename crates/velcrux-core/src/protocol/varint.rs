//! LEB128 varint codec.
//!
//! Rules (`PROTOCOL.md` §1):
//!   - Unsigned, little-endian, 1–10 bytes.
//!   - Decoders **reject over-long encodings** so the wire form is canonical
//!     and a value cannot be smuggled in two representations.

use crate::error::ProtocolError;

/// Maximum number of bytes a u64 varint can occupy. LEB128 is 1 bit of
/// payload per 7 bits of encoding, so ceil(64/7) = 10.
pub const MAX_VARINT_BYTES: usize = 10;

/// Number of bytes required to encode the given value.
#[inline]
pub const fn varint_len(value: u64) -> usize {
    match value {
        0..=0x7F => 1,
        0x80..=0x3FFF => 2,
        0x4000..=0x1F_FFFF => 3,
        0x20_0000..=0xFFF_FFFF => 4,
        0x1000_0000..=0x7_FFFF_FFFF => 5,
        0x8_0000_0000..=0x3FF_FFFF_FFFF => 6,
        0x400_0000_0000..=0x1_FFFF_FFFF_FFFF => 7,
        0x2_0000_0000_0000..=0xF_FFFF_FFFF_FFFF => 8,
        0x10_0000_0000_0000..=0x7FF_FFFF_FFFF_FFFF => 9,
        _ => 10,
    }
}

/// Encode a u64 as a LEB128 varint into `buf`. Returns the number of bytes
/// written.
///
/// # Panics
/// Panics if `buf.len() < varint_len(value)`. Callers should size `buf` with
/// [`varint_len`] first.
#[inline]
pub fn encode_varint(mut value: u64, buf: &mut [u8]) -> usize {
    let needed = varint_len(value);
    // Defensive: debug-only check. Production callers size buf up front.
    debug_assert!(buf.len() >= needed, "buf too small for varint");

    let mut i = 0;
    while value >= 0x80 {
        buf[i] = (value as u8 & 0x7F) | 0x80;
        value >>= 7;
        i += 1;
    }
    buf[i] = value as u8;
    needed
}

/// Decode a LEB128 varint from `buf`. Returns `(value, bytes_consumed)`.
///
/// Errors:
///   - [`ProtocolError::Empty`] if `buf` is empty.
///   - [`ProtocolError::VarintOverflow`] if the encoding is longer than 10
///     bytes (i.e. would not fit in a u64).
///   - [`ProtocolError::NonCanonicalVarint`] if the encoding uses more bytes
///     than the minimum needed for the value. This is the canonicality rule.
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), ProtocolError> {
    if buf.is_empty() {
        return Err(ProtocolError::Empty);
    }

    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;

    loop {
        if i >= buf.len() {
            return Err(ProtocolError::VarintOverflow);
        }
        let b = buf[i];
        i += 1;

        // Shift cap: i bytes of payload give us 7*i bits, which must fit in u64.
        if i > MAX_VARINT_BYTES {
            return Err(ProtocolError::VarintOverflow);
        }

        if shift < 64 {
            let low = (b & 0x7F) as u64;
            // Reject the case where setting `low` would push past 64 bits.
            // The `shift < 57` guard covers the high bits; LEB128 is invalid
            // when the value would overflow u64 regardless.
            if shift >= 57 && low.checked_shl(shift).is_none() {
                return Err(ProtocolError::VarintOverflow);
            }
            value |= low.checked_shl(shift).unwrap_or(0);
        } else if (b & 0x7F) != 0 {
            // Beyond 64 bits of value we still need the input to be all-zero
            // continuation bytes; otherwise the value is too large for u64.
            return Err(ProtocolError::VarintOverflow);
        }

        shift += 7;

        if b & 0x80 == 0 {
            break;
        }
    }

    // Canonicality: the last byte must not be 0x80..=0xFF with only zero
    // payload. Equivalently, the value must fit in (i-1)*7 bits if i is the
    // number of bytes consumed.
    let needed = varint_len(value);
    if needed != i {
        return Err(ProtocolError::NonCanonicalVarint);
    }

    Ok((value, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_roundtrip() {
        let mut buf = [0u8; 16];
        let n = encode_varint(0, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0);
        let (v, k) = decode_varint(&buf[..n]).unwrap();
        assert_eq!((v, k), (0, 1));
    }

    #[test]
    fn small_roundtrip() {
        for v in [1u64, 127, 128, 16_383, 16_384] {
            let mut buf = [0u8; 16];
            let n = encode_varint(v, &mut buf);
            let (out, k) = decode_varint(&buf[..n]).unwrap();
            assert_eq!((out, k), (v, n));
        }
    }

    #[test]
    fn max_u64_roundtrip() {
        let mut buf = [0u8; 16];
        let n = encode_varint(u64::MAX, &mut buf);
        assert_eq!(n, 10);
        let (out, k) = decode_varint(&buf[..n]).unwrap();
        assert_eq!((out, k), (u64::MAX, 10));
    }

    #[test]
    fn rejects_non_canonical() {
        // 0 encoded in 2 bytes (0x80 0x00) is non-canonical.
        assert!(matches!(
            decode_varint(&[0x80, 0x00]),
            Err(ProtocolError::NonCanonicalVarint)
        ));
        // 1 encoded in 2 bytes (0x81 0x00) is non-canonical.
        assert!(matches!(
            decode_varint(&[0x81, 0x00]),
            Err(ProtocolError::NonCanonicalVarint)
        ));
    }

    #[test]
    fn rejects_overflow() {
        // 11 continuation bytes.
        let buf = [0x80u8; 11];
        assert!(matches!(
            decode_varint(&buf),
            Err(ProtocolError::VarintOverflow)
        ));
    }

    #[test]
    fn rejects_truncated() {
        // 0x80 0x80 with no terminating byte — truncated.
        let buf = [0x80, 0x80];
        assert!(matches!(decode_varint(&buf), Err(ProtocolError::VarintOverflow)));
    }
}
