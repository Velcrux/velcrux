#![forbid(unsafe_code)]

//! BGP Routing Information Base (RIB), VRF Tables & EVPN Best-Path Selection.
//!
//! Models Adj-RIB-In, Loc-RIB, Virtual Routing and Forwarding (VRF) domains,
//! EVPN Route Target import/export filtering, and deterministic BGP-4 best path decision criteria.

use super::evpn::{EvpnRoute, RouteDistinguisher, RouteTarget};
use super::message::{BgpPathAttributes, BgpPrefix};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A single route entry in the BGP Routing Information Base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpRibEntry {
    pub prefix: BgpPrefix,
    pub attributes: BgpPathAttributes,
    pub peer_asn: u32,
    pub peer_ip: Ipv4Addr,
    pub is_best_path: bool,
    pub learned_epoch_sec: u64,
}

impl BgpRibEntry {
    /// Compares two candidate BGP paths according to RFC 4271 §9.1.2.2 decision criteria:
    /// 1. Prefer highest Local Preference.
    /// 2. Prefer shortest AS Path.
    /// 3. Prefer lowest Origin (IGP < EGP < Incomplete).
    /// 4. Prefer lowest MED.
    /// 5. Prefer eBGP over iBGP.
    /// 6. Prefer lowest Peer IP.
    pub fn compare_candidates(&self, other: &Self, local_asn: u32) -> Ordering {
        // 1. Highest Local Preference
        let lp1 = self.attributes.local_pref.unwrap_or(100);
        let lp2 = other.attributes.local_pref.unwrap_or(100);
        if lp1 != lp2 {
            return lp1.cmp(&lp2); // greater is better
        }

        // 2. Shortest AS Path length
        let len1 = self.attributes.total_as_hops();
        let len2 = other.attributes.total_as_hops();
        if len1 != len2 {
            return len2.cmp(&len1); // smaller is better
        }

        // 3. Lowest Origin code (IGP=0 < EGP=1 < Incomplete=2)
        let o1 = self.attributes.origin.to_u8();
        let o2 = other.attributes.origin.to_u8();
        if o1 != o2 {
            return o2.cmp(&o1); // smaller is better
        }

        // 4. Lowest MED
        let med1 = self.attributes.med.unwrap_or(0);
        let med2 = other.attributes.med.unwrap_or(0);
        if med1 != med2 {
            return med2.cmp(&med1); // smaller is better
        }

        // 5. Prefer eBGP over iBGP
        let is_ebgp1 = self.peer_asn != local_asn;
        let is_ebgp2 = other.peer_asn != local_asn;
        if is_ebgp1 != is_ebgp2 {
            return is_ebgp1.cmp(&is_ebgp2);
        }

        // 6. Lowest Peer IP (tie-breaker)
        other.peer_ip.octets().cmp(&self.peer_ip.octets())
    }
}

/// Virtual Routing and Forwarding (VRF) Routing Table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfTable {
    /// Tenant or routing domain name.
    pub name: String,
    /// Associated 24-bit VXLAN VNI.
    pub vni: u32,
    /// VRF Route Distinguisher.
    pub rd: RouteDistinguisher,
    /// Route Targets imported by this VRF.
    pub import_targets: Vec<RouteTarget>,
    /// Route Targets exported by this VRF.
    pub export_targets: Vec<RouteTarget>,
    /// IPv4 IP Prefix RIB mapping: Prefix -> list of candidate paths.
    pub prefix_routes: HashMap<BgpPrefix, Vec<BgpRibEntry>>,
    /// EVPN Type 2 / Type 5 routes learned.
    pub evpn_routes: Vec<EvpnRoute>,
}

impl VrfTable {
    /// Creates a new VRF instance.
    pub fn new(
        name: impl Into<String>,
        vni: u32,
        rd: RouteDistinguisher,
        import_targets: Vec<RouteTarget>,
        export_targets: Vec<RouteTarget>,
    ) -> Self {
        Self {
            name: name.into(),
            vni,
            rd,
            import_targets,
            export_targets,
            prefix_routes: HashMap::new(),
            evpn_routes: Vec::new(),
        }
    }

    /// Injects or updates an IP prefix route into this VRF's RIB.
    pub fn insert_prefix_route(
        &mut self,
        prefix: BgpPrefix,
        attributes: BgpPathAttributes,
        peer_asn: u32,
        peer_ip: Ipv4Addr,
        local_asn: u32,
    ) {
        let entry = BgpRibEntry {
            prefix,
            attributes,
            peer_asn,
            peer_ip,
            is_best_path: false,
            learned_epoch_sec: 1731150000,
        };

        let candidates = self.prefix_routes.entry(prefix).or_default();
        // Remove existing candidate from same peer
        candidates.retain(|e| e.peer_ip != peer_ip);
        candidates.push(entry);

        // Recompute best path
        self.recompute_best_path(prefix, local_asn);
    }

    /// Withdraws an IP prefix route received from a specific peer.
    pub fn withdraw_prefix_route(&mut self, prefix: &BgpPrefix, peer_ip: Ipv4Addr, local_asn: u32) {
        if let Some(candidates) = self.prefix_routes.get_mut(prefix) {
            candidates.retain(|e| e.peer_ip != peer_ip);
            if candidates.is_empty() {
                self.prefix_routes.remove(prefix);
            } else {
                self.recompute_best_path(*prefix, local_asn);
            }
        }
    }

    /// Injects an EVPN route into this VRF if any of its export targets match this VRF's import targets.
    pub fn import_evpn_route(&mut self, route: EvpnRoute, route_targets: &[RouteTarget]) -> bool {
        let matches = route_targets
            .iter()
            .any(|rt| self.import_targets.contains(rt));
        if matches {
            self.evpn_routes.push(route);
            true
        } else {
            false
        }
    }

    /// Re-evaluates best path among all candidate routes for a given prefix.
    fn recompute_best_path(&mut self, prefix: BgpPrefix, local_asn: u32) {
        if let Some(candidates) = self.prefix_routes.get_mut(&prefix) {
            for c in candidates.iter_mut() {
                c.is_best_path = false;
            }

            if candidates.is_empty() {
                return;
            }

            let mut best_idx = 0;
            for i in 1..candidates.len() {
                if candidates[i].compare_candidates(&candidates[best_idx], local_asn)
                    == Ordering::Greater
                {
                    best_idx = i;
                }
            }

            candidates[best_idx].is_best_path = true;
        }
    }

    /// Returns the active best-path route for a prefix, if present.
    pub fn get_best_route(&self, prefix: &BgpPrefix) -> Option<&BgpRibEntry> {
        self.prefix_routes
            .get(prefix)
            .and_then(|candidates| candidates.iter().find(|e| e.is_best_path))
    }
}

/// Global Routing Information Base (RIB) Manager aggregating VRFs and global Loc-RIB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpRibManager {
    pub local_asn: u32,
    pub vrfs: HashMap<String, VrfTable>,
}

impl BgpRibManager {
    /// Creates a new RIB manager.
    pub fn new(local_asn: u32) -> Self {
        let mut mgr = Self {
            local_asn,
            vrfs: HashMap::new(),
        };
        // Initialize default global VRF
        let default_rd = RouteDistinguisher::Asn4 {
            asn: local_asn,
            assigned: 1,
        };
        let default_rt = RouteTarget::Asn4 {
            asn: local_asn,
            assigned: 1,
        };
        let default_vrf =
            VrfTable::new("default", 0, default_rd, vec![default_rt], vec![default_rt]);
        mgr.vrfs.insert("default".to_string(), default_vrf);
        mgr
    }

    /// Adds a custom VRF.
    pub fn add_vrf(&mut self, vrf: VrfTable) -> Result<()> {
        let name = vrf.name.clone();
        if self.vrfs.contains_key(&name) {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "VRF with this name already exists",
            )));
        }
        self.vrfs.insert(name, vrf);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::message::{AsPathSegment, BgpPathAttributes};
    use super::*;

    #[test]
    fn test_bgp_best_path_selection_local_pref() {
        let pfx = BgpPrefix::new(Ipv4Addr::new(10, 50, 0, 0), 16);
        let mut vrf = VrfTable::new(
            "test",
            100,
            RouteDistinguisher::parse("65001:100").unwrap(),
            vec![],
            vec![],
        );

        // Path A: LocalPref = 100
        let mut attr_a = BgpPathAttributes::default();
        attr_a.local_pref = Some(100);
        attr_a.as_path = vec![AsPathSegment::sequence(vec![65002])];

        // Path B: LocalPref = 200
        let mut attr_b = BgpPathAttributes::default();
        attr_b.local_pref = Some(200);
        attr_b.as_path = vec![AsPathSegment::sequence(vec![65003, 65004])];

        vrf.insert_prefix_route(pfx, attr_a, 65002, Ipv4Addr::new(10, 0, 0, 2), 65001);
        vrf.insert_prefix_route(pfx, attr_b, 65003, Ipv4Addr::new(10, 0, 0, 3), 65001);

        // Path B should win due to higher Local Preference (200 > 100) even though AS path is longer
        let best = vrf.get_best_route(&pfx).expect("has best route");
        assert_eq!(best.peer_asn, 65003);
        assert_eq!(best.attributes.local_pref, Some(200));
    }

    #[test]
    fn test_bgp_best_path_selection_as_path_length() {
        let pfx = BgpPrefix::new(Ipv4Addr::new(172, 16, 0, 0), 12);
        let mut vrf = VrfTable::new(
            "test",
            101,
            RouteDistinguisher::parse("65001:101").unwrap(),
            vec![],
            vec![],
        );

        // Path A: 3 AS hops
        let mut attr_a = BgpPathAttributes::default();
        attr_a.local_pref = Some(100);
        attr_a.as_path = vec![AsPathSegment::sequence(vec![65002, 65003, 65004])];

        // Path B: 1 AS hop
        let mut attr_b = BgpPathAttributes::default();
        attr_b.local_pref = Some(100);
        attr_b.as_path = vec![AsPathSegment::sequence(vec![65005])];

        vrf.insert_prefix_route(pfx, attr_a, 65002, Ipv4Addr::new(10, 0, 0, 2), 65001);
        vrf.insert_prefix_route(pfx, attr_b, 65005, Ipv4Addr::new(10, 0, 0, 5), 65001);

        // Path B should win due to shorter AS path (1 hop < 3 hops)
        let best = vrf.get_best_route(&pfx).expect("has best route");
        assert_eq!(best.peer_asn, 65005);
        assert_eq!(best.attributes.total_as_hops(), 1);
    }
}
