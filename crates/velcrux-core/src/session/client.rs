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
use crate::protocol::message::{Hello, HelloAck, Limits, Message, Ping, BYE};
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
        let (mut send, mut recv) = conn.open_bi().await?;
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

        // 3. Validate the intersection. The server's HELLO_ACK already
        //    is the intersection; check that it is well-formed.
        if let Err(s) = Capabilities::validate_intersection(ack.capabilities) {
            return Err(VelcruxError::Internal(format!(
                "invalid capability intersection: {s}"
            )));
        }

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
}
