#![forbid(unsafe_code)]

//! BGP Finite State Machine (FSM) & Peering Session Engine (RFC 4271 §8).
//!
//! Models standard BGP session states (Idle, Connect, Active, OpenSent, OpenConfirm, Established),
//! timer management (HoldTimer, KeepaliveTimer), event dispatching, and message generation.

use super::message::BgpMessage;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// BGP-4 Finite State Machine (FSM) States.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpFsmState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl BgpFsmState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connect => "Connect",
            Self::Active => "Active",
            Self::OpenSent => "OpenSent",
            Self::OpenConfirm => "OpenConfirm",
            Self::Established => "Established",
        }
    }
}

/// Events driving BGP Finite State Machine transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpEvent {
    ManualStart,
    ManualStop,
    TcpConnectionConfirmed,
    TcpConnectionFails,
    ReceiveOpen(Box<BgpMessage>),
    ReceiveKeepalive,
    ReceiveUpdate(Box<BgpMessage>),
    ReceiveNotification(u8, u8),
    HoldTimerExpired,
    KeepaliveTimerExpired,
}

/// BGP Peer Peering Session Instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpPeer {
    /// Remote Autonomous System Number (ASN).
    pub peer_asn: u32,
    /// Local Autonomous System Number (ASN).
    pub local_asn: u32,
    /// Remote peer IPv4 address.
    pub peer_ip: Ipv4Addr,
    /// Local router IPv4 address.
    pub local_ip: Ipv4Addr,
    /// Local BGP Router ID.
    pub local_router_id: Ipv4Addr,
    /// Remote BGP Router ID (learned during OPEN exchange).
    pub remote_router_id: Option<Ipv4Addr>,
    /// Configured hold time in seconds (default 90).
    pub configured_hold_time: u16,
    /// Negotiated hold time in seconds.
    pub negotiated_hold_time: u16,
    /// Keepalive interval in seconds (default hold_time / 3).
    pub keepalive_interval: u16,
    /// Current FSM state.
    pub state: BgpFsmState,
    /// Whether this is an external BGP (eBGP) session.
    pub is_ebgp: bool,
    /// Counters.
    pub messages_sent: u64,
    pub messages_received: u64,
    pub updates_received: u64,
    pub updates_sent: u64,
    pub session_uptime_secs: u64,
}

impl BgpPeer {
    /// Creates a new BGP peering session configuration.
    pub fn new(
        peer_asn: u32,
        local_asn: u32,
        peer_ip: Ipv4Addr,
        local_ip: Ipv4Addr,
        local_router_id: Ipv4Addr,
        hold_time: u16,
    ) -> Self {
        let is_ebgp = peer_asn != local_asn;
        Self {
            peer_asn,
            local_asn,
            peer_ip,
            local_ip,
            local_router_id,
            remote_router_id: None,
            configured_hold_time: hold_time,
            negotiated_hold_time: hold_time,
            keepalive_interval: hold_time / 3,
            state: BgpFsmState::Idle,
            is_ebgp,
            messages_sent: 0,
            messages_received: 0,
            updates_received: 0,
            updates_sent: 0,
            session_uptime_secs: 0,
        }
    }

    /// Processes an incoming FSM event and transitions state accordingly.
    /// Returns any outgoing message that must be sent immediately in response.
    pub fn process_event(&mut self, event: BgpEvent) -> Result<Option<BgpMessage>> {
        match (self.state, event) {
            (BgpFsmState::Idle, BgpEvent::ManualStart) => {
                self.state = BgpFsmState::Connect;
                Ok(None)
            }
            (BgpFsmState::Connect, BgpEvent::TcpConnectionConfirmed)
            | (BgpFsmState::Active, BgpEvent::TcpConnectionConfirmed) => {
                self.state = BgpFsmState::OpenSent;
                let open_msg = BgpMessage::Open {
                    version: 4,
                    asn: self.local_asn,
                    hold_time: self.configured_hold_time,
                    router_id: self.local_router_id,
                    capabilities: Vec::new(),
                };
                self.messages_sent += 1;
                Ok(Some(open_msg))
            }
            (BgpFsmState::Connect, BgpEvent::TcpConnectionFails) => {
                self.state = BgpFsmState::Active;
                Ok(None)
            }
            (BgpFsmState::Active, BgpEvent::TcpConnectionFails) => {
                self.state = BgpFsmState::Idle;
                Ok(None)
            }
            (BgpFsmState::OpenSent, BgpEvent::ReceiveOpen(msg)) => {
                self.messages_received += 1;
                if let BgpMessage::Open {
                    asn,
                    hold_time,
                    router_id,
                    ..
                } = *msg
                {
                    if asn != self.peer_asn {
                        self.state = BgpFsmState::Idle;
                        let notif = BgpMessage::Notification {
                            error_code: 2,    // OPEN message error
                            error_subcode: 2, // Bad Peer AS
                            data: Vec::new(),
                        };
                        self.messages_sent += 1;
                        return Ok(Some(notif));
                    }
                    self.remote_router_id = Some(router_id);
                    self.negotiated_hold_time = self.configured_hold_time.min(hold_time);
                    self.keepalive_interval = self.negotiated_hold_time / 3;
                    self.state = BgpFsmState::OpenConfirm;

                    // Send KEEPALIVE to confirm
                    self.messages_sent += 1;
                    Ok(Some(BgpMessage::Keepalive))
                } else {
                    self.state = BgpFsmState::Idle;
                    Ok(None)
                }
            }
            (BgpFsmState::OpenConfirm, BgpEvent::ReceiveKeepalive) => {
                self.messages_received += 1;
                self.state = BgpFsmState::Established;
                Ok(None)
            }
            (BgpFsmState::Established, BgpEvent::ReceiveKeepalive) => {
                self.messages_received += 1;
                Ok(None)
            }
            (BgpFsmState::Established, BgpEvent::KeepaliveTimerExpired) => {
                self.messages_sent += 1;
                Ok(Some(BgpMessage::Keepalive))
            }
            (BgpFsmState::Established, BgpEvent::ReceiveUpdate(_msg)) => {
                self.messages_received += 1;
                self.updates_received += 1;
                // Update processing handled by caller/RIB
                Ok(None)
            }
            (_, BgpEvent::ReceiveNotification(_code, _subcode)) => {
                self.messages_received += 1;
                self.state = BgpFsmState::Idle;
                Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "BGP peer sent NOTIFICATION message",
                )))
            }
            (_, BgpEvent::HoldTimerExpired) => {
                self.state = BgpFsmState::Idle;
                let notif = BgpMessage::Notification {
                    error_code: 4, // Hold Timer Expired
                    error_subcode: 0,
                    data: Vec::new(),
                };
                self.messages_sent += 1;
                Ok(Some(notif))
            }
            (_, BgpEvent::ManualStop) => {
                self.state = BgpFsmState::Idle;
                let notif = BgpMessage::Notification {
                    error_code: 6, // Cease
                    error_subcode: 0,
                    data: Vec::new(),
                };
                self.messages_sent += 1;
                Ok(Some(notif))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_fsm_handshake_to_established() {
        let mut peer = BgpPeer::new(
            65002,
            65001,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            90,
        );

        assert_eq!(peer.state, BgpFsmState::Idle);

        // 1. ManualStart -> Connect
        peer.process_event(BgpEvent::ManualStart).unwrap();
        assert_eq!(peer.state, BgpFsmState::Connect);

        // 2. TCP Confirmed -> OpenSent (emits OPEN)
        let out_open = peer
            .process_event(BgpEvent::TcpConnectionConfirmed)
            .unwrap();
        assert_eq!(peer.state, BgpFsmState::OpenSent);
        assert!(matches!(out_open, Some(BgpMessage::Open { .. })));

        // 3. Receive Peer OPEN -> OpenConfirm (emits KEEPALIVE)
        let peer_open = BgpMessage::Open {
            version: 4,
            asn: 65002,
            hold_time: 90,
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            capabilities: Vec::new(),
        };
        let out_ka = peer
            .process_event(BgpEvent::ReceiveOpen(Box::new(peer_open)))
            .unwrap();
        assert_eq!(peer.state, BgpFsmState::OpenConfirm);
        assert_eq!(out_ka, Some(BgpMessage::Keepalive));
        assert_eq!(peer.remote_router_id, Some(Ipv4Addr::new(2, 2, 2, 2)));

        // 4. Receive Peer KEEPALIVE -> Established
        peer.process_event(BgpEvent::ReceiveKeepalive).unwrap();
        assert_eq!(peer.state, BgpFsmState::Established);
    }

    #[test]
    fn test_bad_peer_asn_rejection() {
        let mut peer = BgpPeer::new(
            65002,
            65001,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            90,
        );

        peer.process_event(BgpEvent::ManualStart).unwrap();
        peer.process_event(BgpEvent::TcpConnectionConfirmed)
            .unwrap();

        // Mismatched ASN 65099 instead of 65002
        let peer_open = BgpMessage::Open {
            version: 4,
            asn: 65099,
            hold_time: 90,
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            capabilities: Vec::new(),
        };
        let out_notif = peer
            .process_event(BgpEvent::ReceiveOpen(Box::new(peer_open)))
            .unwrap();
        assert_eq!(peer.state, BgpFsmState::Idle);
        assert!(matches!(
            out_notif,
            Some(BgpMessage::Notification {
                error_code: 2,
                error_subcode: 2,
                ..
            })
        ));
    }
}
