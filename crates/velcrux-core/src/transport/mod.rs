//! Transport trait and QUIC implementation.
//!
//! `CLAUDE.md` §1 invariant #1: QUIC is the transport. We never implement
//! retransmission, ACKs, congestion control, packet numbering, or TLS by
//! hand. Everything below the `Transport` trait is quinn + rustls.
//!
//! The trait surface mirrors `ARCHITECTURE.md` §2 so higher layers do not
//! depend on quinn types.

pub mod flow_control;
pub mod identity;
pub mod quic;
pub mod stats;

pub use flow_control::{
    AdaptiveFlowController, BdpEstimator, PacingController, DEFAULT_BDP_MULTIPLIER,
    MAX_RECEIVE_WINDOW, MIN_RECEIVE_WINDOW,
};
pub use identity::Identity;
pub use quic::{
    ClientBuilder, ClientIdentity, QuicConnection, QuicTransport, ServerBuilder,
    TransportConfigTunables,
};
pub use stats::TransportStats;

use crate::error::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;

/// Bidirectional stream send half.
pub type BiSend = Box<dyn BiSendStream>;
/// Bidirectional stream receive half.
pub type BiRecv = Box<dyn BiRecvStream>;
/// Unidirectional send half.
pub type UniSend = Box<dyn UniSendStream>;
/// Unidirectional receive half.
pub type UniRecv = Box<dyn UniRecvStream>;

/// A network connection.
///
/// One connection carries one velcrux session (`PROTOCOL.md` §2): a control
/// stream (always open), zero or more metadata streams, and zero or more
/// data streams. Implementations decide how to multiplex.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Open a new client-initiated bidirectional stream. Used for control
    /// and metadata streams.
    async fn open_bi(&self) -> Result<(BiSend, BiRecv)>;

    /// Accept the next incoming bidirectional stream opened by the peer.
    /// Used by the server to accept the control stream.
    async fn accept_bi(&self) -> Result<(BiSend, BiRecv)>;

    /// Open a new unidirectional stream. Used for data streams.
    async fn open_uni(&self) -> Result<UniSend>;

    /// Accept the next incoming unidirectional stream. The server uses this
    /// to receive data streams.
    async fn accept_uni(&self) -> Result<UniRecv>;

    /// Identity derived from the peer certificate during the QUIC handshake.
    /// `None` if the peer did not present a certificate (mTLS required by
    /// default; absence is an error rather than anonymity, per
    /// `SECURITY.md` §2).
    fn peer_identity(&self) -> Option<Identity>;

    /// Snapshot of transport-layer counters (RTT, cwnd, bytes in flight, loss).
    fn stats(&self) -> TransportStats;

    /// Close the connection with a wire error code and a non-sensitive
    /// reason. The connection is gracefully drained.
    fn close(&self, code: u32, reason: &[u8]);
}

/// The transport factory. One for clients, one for servers.
#[async_trait]
pub trait Transport: Send + Sync {
    /// The connection type produced.
    type Conn: Connection;

    /// Open a new client connection to `addr` with the given SNI hostname.
    async fn connect(&self, addr: SocketAddr, sni: &str) -> Result<Self::Conn>;

    /// Accept the next incoming server connection.
    async fn accept(&self) -> Result<Self::Conn>;
}

// ---------------------------------------------------------------------------
// Stream traits (object-safe). We keep the surface small; specific read/write
// helpers live in the quinn-backed implementation in `quic.rs`.
// ---------------------------------------------------------------------------

/// Bidirectional send half.
#[async_trait]
pub trait BiSendStream: Send {
    /// Write all bytes, waiting for them to be flushed to QUIC. This is
    /// backpressure-aware: it returns when the bytes have been handed to
    /// the QUIC driver.
    async fn write_all(&mut self, data: Bytes) -> Result<()>;
    /// Half-close the send side.
    async fn finish(&mut self) -> Result<()>;
}

/// Bidirectional recv half.
#[async_trait]
pub trait BiRecvStream: Send {
    /// Read up to `max` bytes; returns `Ok(None)` on clean EOF.
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>>;
    /// Read exactly `n` bytes; returns `Ok(None)` on clean EOF before all
    /// bytes arrived.
    async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>>;
}

/// Unidirectional send half.
#[async_trait]
pub trait UniSendStream: Send {
    async fn write_all(&mut self, data: Bytes) -> Result<()>;
    async fn finish(&mut self) -> Result<()>;
}

/// Unidirectional recv half.
#[async_trait]
pub trait UniRecvStream: Send {
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>>;
    async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>>;
}

/// Convenience: re-export the Arc'd transport type used by client/server.
pub type SharedTransport = Arc<dyn Transport<Conn = QuicConnection>>;

/// Sentinel stream used by [`crate::session::ClientSession`] to swap out
/// the owned control-stream Boxes when transferring ownership to a
/// per-transfer pipeline. Implements the stream traits but never used;
/// any read or write returns an error.
pub struct NoopStream;

impl NoopStream {
    /// Construct a no-op `BiSendStream`.
    pub fn bidir_send() -> impl BiSendStream {
        Self
    }
    /// Construct a no-op `BiRecvStream`.
    pub fn bidir_recv() -> impl BiRecvStream {
        Self
    }
}

#[async_trait::async_trait]
impl BiSendStream for NoopStream {
    async fn write_all(&mut self, _data: Bytes) -> Result<()> {
        Err(crate::error::VelcruxError::Internal(
            "NoopStream::write_all".into(),
        ))
    }
    async fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl BiRecvStream for NoopStream {
    async fn read_chunk(&mut self, _max: usize) -> Result<Option<Bytes>> {
        Err(crate::error::VelcruxError::Internal(
            "NoopStream::read_chunk".into(),
        ))
    }
    async fn read_exact(&mut self, _n: usize) -> Result<Option<Bytes>> {
        Err(crate::error::VelcruxError::Internal(
            "NoopStream::read_exact".into(),
        ))
    }
}
