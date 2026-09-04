//! Server-side per-connection state machine.
//!
//! Per `PROTOCOL.md` §7 the server-side state machine for one connection is
//!
//! ```text
//! ACCEPTED → TLS_HANDSHAKE → AWAIT_HELLO → AWAIT_AUTH → AUTHENTICATED
//!   → SERVING (0..N transfers) → DRAINING → CLOSED
//! ```
//!
//! `ServerConn` is the per-connection actor. It drives a single
//! `control_stream` task: receive one HELLO, reply HELLO_ACK, then loop
//! receiving PING/PONG and other control messages until the peer sends BYE
//! or the connection drops.
//!
//! AUTH is a no-op pass-through in M1; the `AWAIT_AUTH` transition
//! happens immediately. M2 will insert the real authenticator between
//! `AWAIT_HELLO` and `SERVING`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::{Result, VelcruxError};
use crate::protocol::capabilities::Capabilities;
use crate::protocol::message::{Hello, HelloAck, Message, Ping};
use crate::transport::Connection;

use super::{read_frame, write_frame};

/// Per-connection state. The match in [`ServerConn::run`] has no wildcard
/// arm, so unknown message types or invalid transitions are
/// `PROTOCOL_VIOLATION` rather than silent fall-through (`PROTOCOL.md` §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// TCP/QUIC accept completed, before the TLS handshake.
    Accepted,
    /// TLS handshake in progress.
    TlsHandshake,
    /// Awaiting HELLO from the client.
    AwaitHello,
    /// Awaiting AUTH (M2).
    AwaitAuth,
    /// Authenticated; serving transfers (M2+). M1 handles PING/PONG here.
    Serving,
    /// Draining in response to a graceful shutdown.
    Draining,
    /// Connection is closed.
    Closed,
}

impl ServerState {
    /// Static name for logs and error messages.
    pub fn name(self) -> &'static str {
        match self {
            ServerState::Accepted => "ACCEPTED",
            ServerState::TlsHandshake => "TLS_HANDSHAKE",
            ServerState::AwaitHello => "AWAIT_HELLO",
            ServerState::AwaitAuth => "AWAIT_AUTH",
            ServerState::Serving => "SERVING",
            ServerState::Draining => "DRAINING",
            ServerState::Closed => "CLOSED",
        }
    }
}

/// Server-wide counters, exported in `ServerStats` for tests and (later)
/// `/metrics`.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Total connections accepted.
    pub connections: AtomicU64,
    /// Connections that completed HELLO/HELLO_ACK.
    pub handshakes: AtomicU64,
    /// PINGs handled.
    pub pings: AtomicU64,
}

/// A per-connection actor. Constructed by `run`; runs to completion.
pub struct ServerConn {
    /// Server's full capabilities (used to compute the intersection).
    server_caps: Capabilities,
    /// Server's identity (name), for logs.
    server_name: String,
    /// Server-wide counters (Arc'd so a test can share them).
    stats: Arc<ServerStats>,
}

impl ServerConn {
    /// Construct a new connection actor.
    pub fn new(
        server_caps: Capabilities,
        server_name: impl Into<String>,
        stats: Arc<ServerStats>,
    ) -> Self {
        Self {
            server_caps,
            server_name: server_name.into(),
            stats,
        }
    }

    /// Drive the connection from `Accepted` through `Closed`. Returns the
    /// final state.
    pub async fn run(self, conn: &dyn Connection) -> Result<ServerState> {
        self.stats.connections.fetch_add(1, Ordering::Relaxed);
        let mut state = ServerState::AwaitHello;
        let (mut send, mut recv) = conn.accept_bi().await?;

        loop {
            match state {
                ServerState::AwaitHello => {
                    let frame = match read_frame(recv.as_mut()).await? {
                        Some(f) => f,
                        None => break,
                    };
                    match frame.type_byte {
                        x if x == crate::protocol::message::HELLO => {
                            let hello = Hello::decode(&frame.payload)?;
                            let intersection = hello.capabilities.intersect(self.server_caps);
                            if let Err(s) = Capabilities::validate_intersection(intersection) {
                                let err = crate::protocol::message::ErrorMsg::new(
                                    crate::protocol::error::ErrorCode::ProtocolVersionUnsupported,
                                    s,
                                );
                                let _ = write_frame(send.as_mut(), &Message::Error(err), frame.request_id).await;
                                conn.close(
                                    crate::protocol::error::ErrorCode::ProtocolVersionUnsupported.to_wire(),
                                    b"no capability intersection",
                                );
                                state = ServerState::Closed;
                                break;
                            }
                            let ack = HelloAck {
                                version: crate::protocol::limits::PROTOCOL_VERSION,
                                capabilities: intersection,
                                limits: crate::protocol::message::Limits::default(),
                                agent: format!("{}/{}", self.server_name, env!("CARGO_PKG_VERSION")),
                            };
                            write_frame(send.as_mut(), &Message::HelloAck(ack), frame.request_id).await?;
                            self.stats.handshakes.fetch_add(1, Ordering::Relaxed);
                            state = ServerState::Serving;
                        }
                        _other => {
                            return Err(VelcruxError::Protocol(
                                crate::error::ProtocolError::InvalidStateTransition("expected HELLO"),
                            ));
                        }
                    }
                }
                ServerState::Serving => {
                    let frame = match read_frame(recv.as_mut()).await? {
                        Some(f) => f,
                        None => break,
                    };
                    match frame.type_byte {
                        x if x == crate::protocol::message::PING => {
                            let ping = Ping::decode(&frame.payload)?;
                            let pong = Ping {
                                nonce: ping.nonce,
                                sender_ts_ms: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0),
                            };
                            write_frame(send.as_mut(), &Message::Pong(pong), frame.request_id).await?;
                            self.stats.pings.fetch_add(1, Ordering::Relaxed);
                        }
                        x if x == crate::protocol::message::BYE => {
                            send.finish().await.ok();
                            state = ServerState::Closed;
                            break;
                        }
                        other => {
                            let err = crate::protocol::message::ErrorMsg::new(
                                crate::protocol::error::ErrorCode::UnsupportedMessage,
                                "unsupported",
                            );
                            let _ = write_frame(send.as_mut(), &Message::Error(err), frame.request_id).await;
                            tracing::debug!(state = state.name(), "unsupported message 0x{other:02x}");
                        }
                    }
                }
                ServerState::Closed => break,
                ServerState::Accepted
                | ServerState::TlsHandshake
                | ServerState::AwaitAuth
                | ServerState::Draining => {
                    return Err(VelcruxError::Protocol(
                        crate::error::ProtocolError::InvalidStateTransition(state.name()),
                    ));
                }
            }
        }
        Ok(state)
    }
}

#[inline]
fn break_as_closed(state: &mut ServerState) {
    *state = ServerState::Closed;
}