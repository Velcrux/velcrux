//! Cryptographic Routing & AllowedIPs Prefix Trie (ADR-081).
//!
//! Enforces WireGuard's cryptographic routing table:
//! - Outgoing packets: Looks up destination IP in AllowedIPs to select the target peer.
//! - Incoming packets: Verifies inner source IP belongs to the peer's configured AllowedIPs,
//!   dropping spoofed or misrouted packets immediately.

use std::net::IpAddr;

use super::types::{MeshError, MeshResult};

/// An IPv4 or IPv6 CIDR prefix rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrRule {
    pub network: IpAddr,
    pub prefix_len: u8,
    pub peer_id: String,
}

impl CidrRule {
    /// Parse a CIDR string (e.g. "10.0.0.0/24", "192.168.1.5/32", "fd00::/64").
    pub fn parse(cidr: &str, peer_id: impl Into<String>) -> Result<Self, MeshError> {
        let parts: Vec<&str> = cidr.trim().split('/').collect();
        if parts.is_empty() || parts.len() > 2 {
            return Err(MeshError::InvalidCidr(cidr.to_string()));
        }

        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|_| MeshError::InvalidCidr(cidr.to_string()))?;

        let prefix_len = if parts.len() == 2 {
            parts[1]
                .parse::<u8>()
                .map_err(|_| MeshError::InvalidCidr(cidr.to_string()))?
        } else {
            match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            }
        };

        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix_len > max_prefix {
            return Err(MeshError::InvalidCidr(format!(
                "Prefix length {} exceeds max {}",
                prefix_len, max_prefix
            )));
        }

        Ok(Self {
            network: ip,
            prefix_len,
            peer_id: peer_id.into(),
        })
    }

    /// Check if an IP address falls within this CIDR rule.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u32 = u32::from(net);
                let target_u32 = u32::from(target);
                let mask = !((1u32 << (32 - self.prefix_len)) - 1);
                (net_u32 & mask) == (target_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u128 = u128::from(net);
                let target_u128 = u128::from(target);
                let mask = !((1u128 << (128 - self.prefix_len)) - 1);
                (net_u128 & mask) == (target_u128 & mask)
            }
            _ => false,
        }
    }
}

/// Longest-prefix match cryptographic routing trie.
#[derive(Debug, Clone, Default)]
pub struct AllowedIpsTrie {
    rules: Vec<CidrRule>,
}

impl AllowedIpsTrie {
    /// Create a new empty AllowedIPs routing trie.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Insert a CIDR rule mapping an IP prefix to a mesh peer.
    pub fn insert(&mut self, cidr: &str, peer_id: &str) -> MeshResult<()> {
        let rule = CidrRule::parse(cidr, peer_id)?;
        self.rules.push(rule);
        // Sort descending by prefix length for longest-prefix matching
        self.rules.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        Ok(())
    }

    /// Remove all CIDR routes registered for a peer.
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.rules.retain(|r| r.peer_id != peer_id);
    }

    /// Lookup destination IP to determine which peer to route traffic to (Longest-Prefix Match).
    #[must_use]
    pub fn lookup(&self, destination_ip: IpAddr) -> Option<&str> {
        for rule in &self.rules {
            if rule.contains(destination_ip) {
                return Some(&rule.peer_id);
            }
        }
        None
    }

    /// Verify whether a source IP address is authorized for a specific incoming peer (Anti-Spoofing).
    ///
    /// Following the WireGuard specification: looks up the source IP using longest-prefix match;
    /// the source is only permitted if the matching route belongs to `peer_id`.
    #[must_use]
    pub fn check_allowed(&self, source_ip: IpAddr, peer_id: &str) -> bool {
        self.lookup(source_ip) == Some(peer_id)
    }

    /// Return all registered route entries as (CIDR, peer_id) tuples.
    #[must_use]
    pub fn all_routes(&self) -> Vec<(String, String)> {
        self.rules
            .iter()
            .map(|r| {
                let cidr = format!("{}/{}", r.network, r.prefix_len);
                (cidr, r.peer_id.clone())
            })
            .collect()
    }
}
