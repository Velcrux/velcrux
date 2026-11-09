#![forbid(unsafe_code)]

//! Autonomous Global Anycast BGP Orchestrator & Traffic Engineering Engine.
//!
//! Manages global Anycast Virtual IPs (VIPs), automated health-based AS-path prepending,
//! BGP community tagging, sub-second route withdrawals, and transit ingress deflection.

use super::message::{AsPathSegment, BgpMessage, BgpOrigin, BgpPathAttributes, BgpPrefix};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Health status classification for an Anycast Edge POP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PopHealthStatus {
    /// Optimal performance: 0 prepends, full line-rate traffic ingestion.
    Optimal,
    /// Elevated latency or packet loss: apply AS-path prepends to soft-deflect transit traffic.
    Congested,
    /// Critical failure or high packet loss: immediately withdraw prefix from global BGP tables.
    Critical,
}

/// Dynamic action taken by the Anycast Orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnycastAction {
    AnnounceNormal { as_prepends: u8 },
    SoftDeflectPrepend { as_prepends: u8 },
    InstantWithdraw,
}

/// Global Anycast Virtual IP (VIP) Advertisement Record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnycastVip {
    pub prefix: BgpPrefix,
    pub pop_id: String,
    pub local_asn: u32,
    pub next_hop: Ipv4Addr,
    pub is_announced: bool,
    pub as_prepends: u8,
    pub med: u32,
    pub communities: Vec<u32>,
    pub health_score: f64,
    pub health_status: PopHealthStatus,
}

impl AnycastVip {
    pub fn new(
        prefix: BgpPrefix,
        pop_id: impl Into<String>,
        local_asn: u32,
        next_hop: Ipv4Addr,
    ) -> Self {
        Self {
            prefix,
            pop_id: pop_id.into(),
            local_asn,
            next_hop,
            is_announced: false,
            as_prepends: 0,
            med: 0,
            communities: Vec::new(),
            health_score: 1.0,
            health_status: PopHealthStatus::Optimal,
        }
    }

    /// Builds the BGP UPDATE announcement message according to current traffic engineering state.
    pub fn build_update_announcement(&self) -> BgpMessage {
        let mut asns = vec![self.local_asn];
        for _ in 0..self.as_prepends {
            asns.push(self.local_asn);
        }

        let mut attrs = BgpPathAttributes::default();
        attrs.origin = BgpOrigin::Igp;
        attrs.as_path = vec![AsPathSegment::sequence(asns)];
        attrs.next_hop = self.next_hop;
        attrs.med = Some(self.med);
        attrs.local_pref = Some(100);
        attrs.communities = self.communities.clone();

        BgpMessage::Update {
            withdrawn_routes: Vec::new(),
            path_attributes: attrs,
            nlri: vec![self.prefix],
        }
    }

    /// Builds the BGP UPDATE withdrawal message.
    pub fn build_update_withdrawal(&self) -> BgpMessage {
        BgpMessage::Update {
            withdrawn_routes: vec![self.prefix],
            path_attributes: BgpPathAttributes::default(),
            nlri: Vec::new(),
        }
    }
}

/// Autonomous Global Anycast Orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnycastOrchestrator {
    pub local_asn: u32,
    pub vips: HashMap<BgpPrefix, AnycastVip>,
    pub total_announcements: u64,
    pub total_withdrawals: u64,
    pub total_path_prepends: u64,
}

impl AnycastOrchestrator {
    /// Creates a new Anycast Orchestrator for the local ASN.
    pub fn new(local_asn: u32) -> Self {
        Self {
            local_asn,
            vips: HashMap::new(),
            total_announcements: 0,
            total_withdrawals: 0,
            total_path_prepends: 0,
        }
    }

    /// Registers an anycast VIP prefix for orchestration.
    pub fn register_vip(&mut self, vip: AnycastVip) {
        self.vips.insert(vip.prefix, vip);
    }

    /// Evaluates edge POP real-time telemetry (RTT, packet loss, BGP flaps) and adjusts BGP advertisements.
    pub fn evaluate_pop_health(
        &mut self,
        prefix: &BgpPrefix,
        rtt_ms: f64,
        loss_pct: f64,
        upstream_flaps: u32,
    ) -> Result<(AnycastAction, Option<BgpMessage>)> {
        let vip = self.vips.get_mut(prefix).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("VIP prefix not found"))
        })?;

        // Compute composite health score in [0.0, 1.0]
        let loss_penalty = (loss_pct * 10.0).min(1.0);
        let rtt_penalty = if rtt_ms > 150.0 {
            ((rtt_ms - 150.0) / 200.0).min(1.0)
        } else {
            0.0
        };
        let flap_penalty = (upstream_flaps as f64 * 0.25).min(1.0);

        let composite_score =
            (1.0 - (loss_penalty * 0.5 + rtt_penalty * 0.3 + flap_penalty * 0.2)).max(0.0);
        vip.health_score = composite_score;

        if composite_score >= 0.80 {
            vip.health_status = PopHealthStatus::Optimal;
            vip.as_prepends = 0;
            vip.is_announced = true;
            self.total_announcements += 1;
            let msg = vip.build_update_announcement();
            Ok((AnycastAction::AnnounceNormal { as_prepends: 0 }, Some(msg)))
        } else if composite_score >= 0.40 {
            // Apply AS Path Prepending (2 to 4 prepends) to softly shift transit traffic away
            let prepends = if composite_score >= 0.60 { 2 } else { 4 };
            vip.health_status = PopHealthStatus::Congested;
            vip.as_prepends = prepends;
            vip.is_announced = true;
            self.total_path_prepends += 1;
            let msg = vip.build_update_announcement();
            Ok((
                AnycastAction::SoftDeflectPrepend {
                    as_prepends: prepends,
                },
                Some(msg),
            ))
        } else {
            // Severe failure -> Instant Withdraw
            vip.health_status = PopHealthStatus::Critical;
            vip.is_announced = false;
            self.total_withdrawals += 1;
            let msg = vip.build_update_withdrawal();
            Ok((AnycastAction::InstantWithdraw, Some(msg)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anycast_orchestrator_autonomous_failover() {
        let mut orch = AnycastOrchestrator::new(65001);
        let pfx = BgpPrefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
        let vip = AnycastVip::new(pfx, "iad-edge-01", 65001, Ipv4Addr::new(10, 0, 0, 1));
        orch.register_vip(vip);

        // 1. Optimal telemetry -> Normal announcement (0 prepends)
        let (action1, msg1) = orch.evaluate_pop_health(&pfx, 25.0, 0.0, 0).unwrap();
        assert_eq!(action1, AnycastAction::AnnounceNormal { as_prepends: 0 });
        assert!(msg1.is_some());
        assert!(orch.vips.get(&pfx).unwrap().is_announced);

        // 2. High RTT and moderate packet loss -> Soft deflect with AS prepends
        let (action2, msg2) = orch.evaluate_pop_health(&pfx, 280.0, 0.05, 1).unwrap();
        assert!(matches!(action2, AnycastAction::SoftDeflectPrepend { .. }));
        assert!(msg2.is_some());
        assert!(orch.vips.get(&pfx).unwrap().as_prepends >= 2);

        // 3. Critical failure (high loss) -> Instant prefix withdrawal
        let (action3, msg3) = orch.evaluate_pop_health(&pfx, 500.0, 0.20, 4).unwrap();
        assert_eq!(action3, AnycastAction::InstantWithdraw);
        assert!(!orch.vips.get(&pfx).unwrap().is_announced);
        assert_eq!(orch.total_withdrawals, 1);

        if let Some(BgpMessage::Update {
            withdrawn_routes, ..
        }) = msg3
        {
            assert_eq!(withdrawn_routes.len(), 1);
            assert_eq!(withdrawn_routes[0], pfx);
        } else {
            panic!("expected Update withdrawal");
        }
    }
}
