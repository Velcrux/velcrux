//! Client-side session.
//!
//! After `connect()` the client has a `ClientSession` that owns the
//! control stream and exposes `ping()`. The session is the boundary where
//! the wire protocol meets application code; higher layers (transfer
//! engine, etc.) talk to the session, not to quinn.

use std::time::Instant;

use rand::RngCore;

use crate::error::{Result, VelcruxError};
use crate::protocol::capabilities::Capabilities;
use crate::protocol::message::{Auth, AuthOk, Hello, HelloAck, Limits, Message, Ping};
use crate::transport::{BiRecvStream, BiSendStream, Connection, SharedTransport};

use super::{read_frame, write_frame};

/// Negotiated session state visible to the client.
#[derive(Debug, Clone)]
pub struct Negotiated {
    /// Server-chosen version.
    pub version: u8,
    /// Negotiated capability intersection.
    pub capabilities: Capabilities,
    /// Server-side limits.
    pub limits: Limits,
    /// Server agent string.
    pub server_agent: String,
}

/// A live client session. Owns both halves of the control stream.
pub struct ClientSession {
    /// The negotiated HELLO result.
    pub negotiated: Negotiated,
    /// Send half of the control stream.
    send: Box<dyn BiSendStream>,
    /// Recv half of the control stream.
    recv: Box<dyn BiRecvStream>,
}

impl ClientSession {
    /// Open a new connection, send HELLO, await HELLO_ACK.
    pub async fn connect(
        transport: SharedTransport,
        addr: std::net::SocketAddr,
        sni: &str,
    ) -> Result<Self> {
        let conn = transport.connect(addr, sni).await?;
        Self::handshake(&conn).await
    }

    /// Variant of [`connect`](Self::connect) that takes a borrowed
    /// `Connection`. Used by tests.
    pub async fn handshake(conn: &dyn Connection) -> Result<Self> {
        let (send, recv) = conn.open_bi().await?;
        Self::from_handshake_parts(send, recv).await
    }

    /// Lower-level constructor: the caller opened the bidi control
    /// stream and passes the two halves in. Returns a `ClientSession`
    /// once HELLO / HELLO_ACK have completed.
    ///
    /// This is the entry point used by `velcrux upload` / `velcrux
    /// download` so the caller can keep a handle to the underlying
    /// `Connection` for opening data streams alongside the control
    /// stream.
    pub async fn from_handshake_parts(
        mut send: Box<dyn BiSendStream>,
        mut recv: Box<dyn BiRecvStream>,
    ) -> Result<Self> {
        tracing::debug!("client: control stream opened");

        // 1. Send HELLO.
        let hello = Hello::default_client();
        write_frame(send.as_mut(), &Message::Hello(hello), 0).await?;
        tracing::debug!("client: HELLO sent");

        // 2. Await HELLO_ACK.
        let frame = read_frame(recv.as_mut())
            .await?
            .ok_or_else(|| VelcruxError::Internal("EOF awaiting HELLO_ACK".into()))?;
        tracing::debug!(type = frame.type_byte, "client: frame received");
        if frame.type_byte != crate::protocol::message::HELLO_ACK {
            return Err(VelcruxError::Internal(format!(
                "expected HELLO_ACK, got type 0x{:02x}",
                frame.type_byte
            )));
        }
        let ack = HelloAck::decode(&frame.payload)?;

        // 3. Validate the intersection.
        if let Err(s) = Capabilities::validate_intersection(ack.capabilities) {
            return Err(VelcruxError::Internal(format!(
                "invalid capability intersection: {s}"
            )));
        }

        // 4. Send AUTH (mTLS with empty token).
        let auth = Auth::mtls();
        write_frame(send.as_mut(), &Message::Auth(auth), 0).await?;
        tracing::debug!("client: AUTH sent");

        // 5. Await AUTH_OK.
        let frame = read_frame(recv.as_mut())
            .await?
            .ok_or_else(|| VelcruxError::Internal("EOF awaiting AUTH_OK".into()))?;
        tracing::debug!(type = frame.type_byte, "client: frame received");
        if frame.type_byte != crate::protocol::message::AUTH_OK {
            return Err(VelcruxError::Internal(format!(
                "expected AUTH_OK, got type 0x{:02x}",
                frame.type_byte
            )));
        }
        let auth_ok = AuthOk::decode(&frame.payload)?;
        tracing::debug!(identity = %auth_ok.identity, "client: AUTH_OK received");

        Ok(Self {
            negotiated: Negotiated {
                version: ack.version,
                capabilities: ack.capabilities,
                limits: ack.limits,
                server_agent: ack.agent,
            },
            send,
            recv,
        })
    }

    /// Send a PING and await the matching PONG. Returns round-trip
    /// time in milliseconds.
    pub async fn ping(&mut self) -> Result<u64> {
        let nonce = rand::thread_rng().next_u64();
        write_frame(
            self.send.as_mut(),
            &Message::Ping(Ping {
                nonce,
                sender_ts_ms: 0,
            }),
            0,
        )
        .await?;
        let started = Instant::now();
        let frame = read_frame(self.recv.as_mut())
            .await?
            .ok_or_else(|| VelcruxError::Internal("EOF awaiting PONG".into()))?;
        if frame.type_byte != crate::protocol::message::PING {
            return Err(VelcruxError::Internal(format!(
                "expected PONG (type 0x06), got 0x{:02x}",
                frame.type_byte
            )));
        }
        let pong = Ping::decode(&frame.payload)?;
        if pong.nonce != nonce {
            return Err(VelcruxError::Internal(format!(
                "PONG nonce mismatch: sent 0x{nonce:016x}, got 0x{:016x}",
                pong.nonce
            )));
        }
        Ok(started.elapsed().as_millis() as u64)
    }

    /// Send a BYE and close the control stream.
    pub async fn bye(&mut self) -> Result<()> {
        let bye = crate::protocol::message::Bye {
            code: crate::protocol::error::ErrorCode::TransferCancelled.to_wire(),
        };
        write_frame(self.send.as_mut(), &Message::Bye(bye), 0).await?;
        self.send.finish().await?;
        Ok(())
    }

    /// Borrow the negotiated HELLO_ACK result.
    pub fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// Mutable borrow of the send half of the control stream.
    pub fn send_mut(&mut self) -> &mut Box<dyn BiSendStream> {
        &mut self.send
    }

    /// Mutable borrow of the recv half of the control stream.
    pub fn recv_mut(&mut self) -> &mut Box<dyn BiRecvStream> {
        &mut self.recv
    }

    /// Mutable borrow of both control stream halves at once.
    pub fn stream_halves_mut(&mut self) -> (&mut dyn BiSendStream, &mut dyn BiRecvStream) {
        (self.send.as_mut(), self.recv.as_mut())
    }

    /// Move the send half out of the session. Used by M2 transfer
    /// pipelines that need to write/read the control stream directly.
    ///
    /// The session's send/recv Boxes are replaced with empty placeholders
    /// so this can be called twice only on different fields. After this
    /// call the session is no longer usable for control-stream reads
    /// through `self`; the caller owns the returned Box.
    pub fn send_mut_owned(&mut self) -> Box<dyn BiSendStream> {
        // Use a small `Noop` shim so we can `mem::replace` a Box<dyn>.
        // The shim implements the traits but returns errors on use; we
        // never use it after the replace.
        use crate::transport::NoopStream;
        std::mem::replace(&mut self.send, Box::new(NoopStream::bidir_send()))
    }

    /// Same as [`send_mut_owned`] for the recv half.
    pub fn recv_mut_owned(&mut self) -> Box<dyn BiRecvStream> {
        use crate::transport::NoopStream;
        std::mem::replace(&mut self.recv, Box::new(NoopStream::bidir_recv()))
    }

    /// Read a single control frame and return it.
    pub async fn recv_frame(&mut self) -> Result<crate::protocol::frame::Frame<'static>> {
        use crate::protocol::frame::Frame;
        // 5 bytes: 4-byte fixed prefix + 1-byte short varint.
        let header_start = self
            .recv
            .read_exact(5)
            .await?
            .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
        let mut buf = header_start.to_vec();
        let mut varint_len = 1usize;
        while (buf[buf.len() - 1] & 0x80) != 0 {
            let next = self
                .recv
                .read_exact(1)
                .await?
                .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
            buf.extend_from_slice(&next);
            varint_len += 1;
            if varint_len > 10 {
                return Err(VelcruxError::Protocol(
                    crate::error::ProtocolError::VarintOverflow,
                ));
            }
        }
        let (declared_length, _) = crate::protocol::varint::decode_varint(&buf[4..])?;
        let max = crate::protocol::frame::max_message_size();
        if declared_length > max {
            return Err(VelcruxError::Protocol(
                crate::error::ProtocolError::FrameTooLarge {
                    declared: declared_length,
                    limit: max,
                },
            ));
        }
        let rid = self
            .recv
            .read_exact(8)
            .await?
            .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?;
        buf.extend_from_slice(&rid);
        let payload = if declared_length == 0 {
            bytes::Bytes::new()
        } else {
            self.recv
                .read_exact(declared_length as usize)
                .await?
                .ok_or_else(|| VelcruxError::Protocol(crate::error::ProtocolError::Empty))?
        };
        buf.extend_from_slice(&payload);
        let frame = crate::protocol::frame::decode_frame(&buf)?;
        let payload_static: &'static [u8] = Box::leak(frame.payload.to_vec().into_boxed_slice());
        Ok(Frame {
            version: frame.version,
            type_byte: frame.type_byte,
            flags: frame.flags,
            length: frame.length,
            request_id: frame.request_id,
            payload: payload_static,
        })
    }
}
