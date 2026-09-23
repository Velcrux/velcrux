//! Session layer: HELLO exchange, PING/PONG, and the per-connection state
//! machine.
//!
//! This sits between the transport and the (M2+) transfer engine. It owns
//! the control stream and the message dispatch loop. Every state
//! transition is an explicit `match` with no wildcard arm, per
//! `PROTOCOL.md` §7.
//!
//! M1 surface: HELLO/HELLO_ACK, PING/PONG, BYE. AUTH is wired in `M2`; the
//! server currently passes the connection through `AWAIT_AUTH` immediately
//! with a `// M2:` marker.

pub mod client;
pub mod server;

pub use client::ClientSession;
pub use server::{ServerConn, ServerState, ServerStats};

use crate::error::Result;
use crate::protocol::frame::{encode_frame, header_size_for, Frame, FrameFlags};
use crate::protocol::message::Message;
use crate::transport::{BiRecvStream, BiSendStream};

/// Encode `msg` as a single frame, allocating the output buffer.
///
/// `request_id` is zero for unsolicited server-to-client messages; the
/// client uses non-zero ids to correlate responses (M2+).
pub fn encode_message(msg: &Message, request_id: u64) -> Result<Vec<u8>> {
    let (type_byte, payload) = msg.encode()?;
    let length = payload.len() as u64;
    let total = header_size_for(length) + payload.len();
    let mut out = vec![0u8; total];
    let n = encode_frame(&mut out, type_byte, FrameFlags::NONE, request_id, &payload);
    debug_assert_eq!(n, total);
    Ok(out)
}

/// Read a single frame from `recv`. Returns `Ok(None)` on clean EOF.
///
/// The frame header is parsed first; if the declared `length` exceeds
/// `max_message_size` (the all-important bound from `PROTOCOL.md` §3) the
/// function returns `Err` **before** any payload allocation.
pub async fn read_frame(recv: &mut dyn BiRecvStream) -> Result<Option<Frame<'static>>> {
    // Read 5 bytes: the 4-byte fixed prefix (ver, type, flags_lo,
    // flags_hi) and the first byte of the `length` varint. The first
    // varint byte is at offset 4.
    let header_start = match recv.read_exact(5).await? {
        Some(b) => b,
        None => return Ok(None),
    };
    let mut buf = header_start.to_vec();
    let mut varint_len = 1usize;
    while (buf[buf.len() - 1] & 0x80) != 0 {
        let next = match recv.read_chunk(1).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        buf.extend_from_slice(&next);
        varint_len += 1;
        if varint_len > 10 {
            return Err(crate::error::ProtocolError::VarintOverflow.into());
        }
    }
    // We have the full varint; compute remaining header bytes.
    let (declared_length, _consumed) = crate::protocol::varint::decode_varint(&buf[4..])?;
    // request_id (8 bytes)
    let _request_id_off = 4 + varint_len;
    let rid = match recv.read_exact(8).await? {
        Some(b) => b,
        None => return Ok(None),
    };
    buf.extend_from_slice(&rid);

    // Bound check: declared length must fit in max_message_size. The
    // inner decoder will also check this; doing it here too gives us a
    // single, clear guard before any payload allocation.
    let max = crate::protocol::frame::max_message_size();
    if declared_length > max {
        return Err(crate::error::ProtocolError::FrameTooLarge {
            declared: declared_length,
            limit: max,
        }
        .into());
    }
    let payload_len = declared_length as usize;
    let payload = if payload_len == 0 {
        bytes::Bytes::new()
    } else {
        match recv.read_exact(payload_len).await? {
            Some(b) => b,
            None => return Ok(None),
        }
    };
    buf.extend_from_slice(&payload);

    // Now decode the fully-assembled frame. We use the inner decode; it
    // re-checks version, length, etc. — those checks are cheap and the
    // test in the frame module is the spec.
    let frame = crate::protocol::frame::decode_frame(&buf)?;
    // The decoder returns a `Frame<'_>` borrowing from `buf`; re-emit as
    // `Frame<'static>` by leaking the payload (it is small, bounded by
    // max_message_size, and the original buffer is dropped immediately).
    let payload_static: &'static [u8] = Box::leak(frame.payload.to_vec().into_boxed_slice());
    Ok(Some(Frame {
        version: frame.version,
        type_byte: frame.type_byte,
        flags: frame.flags,
        length: frame.length,
        request_id: frame.request_id,
        payload: payload_static,
    }))
}

/// Write a single frame to `send`. Backpressure-aware: the underlying quinn
/// call awaits the QUIC driver.
pub async fn write_frame(
    send: &mut dyn BiSendStream,
    msg: &Message,
    request_id: u64,
) -> Result<()> {
    let buf = encode_message(msg, request_id)?;
    send.write_all(bytes::Bytes::from(buf)).await?;
    Ok(())
}
