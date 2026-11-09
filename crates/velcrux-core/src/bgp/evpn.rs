#![forbid(unsafe_code)]

//! BGP EVPN (Ethernet VPN) NLRI, Route Distinguishers & Route Targets.
//!
//! Conforms to RFC 7432 (BGP MPLS-Based Ethernet VPN) and RFC 9136 (IP Prefix Advertisement).
//! Implements Route Distinguishers, Route Targets, and EVPN Route Types 1 through 5.

use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;

pub const AFI_L2VPN: u16 = 25;
pub const SAFI_EVPN: u8 = 70;

pub const EVPN_TYPE_ETHERNET_AD: u8 = 1;
pub const EVPN_TYPE_MAC_IP_ADV: u8 = 2;
pub const EVPN_TYPE_INCLUSIVE_MULTICAST: u8 = 3;
pub const EVPN_TYPE_ETHERNET_SEGMENT: u8 = 4;
pub const EVPN_TYPE_IP_PREFIX: u8 = 5;

/// BGP Route Distinguisher (RFC 4364 §4.2, 8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RouteDistinguisher {
    /// Type 0: 2-byte ASN, 4-byte Assigned Number.
    Asn2 { asn: u16, assigned: u32 },
    /// Type 1: 4-byte IPv4 Address, 2-byte Assigned Number.
    Ip { ip: Ipv4Addr, assigned: u16 },
    /// Type 2: 4-byte ASN, 2-byte Assigned Number.
    Asn4 { asn: u32, assigned: u16 },
}

impl RouteDistinguisher {
    /// Parses RD string (e.g. "65001:100" or "10.0.0.1:100").
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid Route Distinguisher format; expected 'ASN:num' or 'IP:num'",
            )));
        }

        if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
            let assigned = parts[1].parse::<u16>().map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed(
                    "invalid RD assigned number for IP",
                ))
            })?;
            Ok(Self::Ip { ip, assigned })
        } else if let Ok(asn) = parts[0].parse::<u32>() {
            if asn <= 65535 {
                let assigned = parts[1].parse::<u32>().map_err(|_| {
                    VelcruxError::Protocol(ProtocolError::Malformed("invalid RD assigned number"))
                })?;
                Ok(Self::Asn2 {
                    asn: asn as u16,
                    assigned,
                })
            } else {
                let assigned = parts[1].parse::<u16>().map_err(|_| {
                    VelcruxError::Protocol(ProtocolError::Malformed(
                        "invalid RD assigned number for 4-byte ASN",
                    ))
                })?;
                Ok(Self::Asn4 { asn, assigned })
            }
        } else {
            Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unrecognized Route Distinguisher prefix",
            )))
        }
    }

    /// Serializes RD into standard 8 bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        match self {
            Self::Asn2 { asn, assigned } => {
                out[0..2].copy_from_slice(&0u16.to_be_bytes());
                out[2..4].copy_from_slice(&asn.to_be_bytes());
                out[4..8].copy_from_slice(&assigned.to_be_bytes());
            }
            Self::Ip { ip, assigned } => {
                out[0..2].copy_from_slice(&1u16.to_be_bytes());
                out[2..6].copy_from_slice(&ip.octets());
                out[6..8].copy_from_slice(&assigned.to_be_bytes());
            }
            Self::Asn4 { asn, assigned } => {
                out[0..2].copy_from_slice(&2u16.to_be_bytes());
                out[2..6].copy_from_slice(&asn.to_be_bytes());
                out[6..8].copy_from_slice(&assigned.to_be_bytes());
            }
        }
        out
    }

    /// Deserializes RD from 8 bytes.
    pub fn from_bytes(bytes: &[u8; 8]) -> Result<Self> {
        let rd_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        match rd_type {
            0 => {
                let asn = u16::from_be_bytes([bytes[2], bytes[3]]);
                let assigned = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                Ok(Self::Asn2 { asn, assigned })
            }
            1 => {
                let ip = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
                let assigned = u16::from_be_bytes([bytes[6], bytes[7]]);
                Ok(Self::Ip { ip, assigned })
            }
            2 => {
                let asn = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                let assigned = u16::from_be_bytes([bytes[6], bytes[7]]);
                Ok(Self::Asn4 { asn, assigned })
            }
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown Route Distinguisher type",
            ))),
        }
    }
}

impl fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn2 { asn, assigned } => write!(f, "{}:{}", asn, assigned),
            Self::Ip { ip, assigned } => write!(f, "{}:{}", ip, assigned),
            Self::Asn4 { asn, assigned } => write!(f, "{}:{}", asn, assigned),
        }
    }
}

/// BGP Route Target Extended Community (RFC 4360, 8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RouteTarget {
    Asn2 { asn: u16, assigned: u32 },
    Ip { ip: Ipv4Addr, assigned: u16 },
    Asn4 { asn: u32, assigned: u16 },
}

impl RouteTarget {
    /// Parses Route Target string (e.g. "target:65001:100" or "target:10.0.0.1:100").
    pub fn parse(s: &str) -> Result<Self> {
        let raw = s.strip_prefix("target:").unwrap_or(s);
        let rd = RouteDistinguisher::parse(raw)?;
        match rd {
            RouteDistinguisher::Asn2 { asn, assigned } => Ok(Self::Asn2 { asn, assigned }),
            RouteDistinguisher::Ip { ip, assigned } => Ok(Self::Ip { ip, assigned }),
            RouteDistinguisher::Asn4 { asn, assigned } => Ok(Self::Asn4 { asn, assigned }),
        }
    }

    /// Serializes Route Target into standard 8-byte BGP Extended Community wire format.
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        match self {
            Self::Asn2 { asn, assigned } => {
                out[0] = 0x00; // Type: 2-byte ASN
                out[1] = 0x02; // Subtype: Route Target
                out[2..4].copy_from_slice(&asn.to_be_bytes());
                out[4..8].copy_from_slice(&assigned.to_be_bytes());
            }
            Self::Ip { ip, assigned } => {
                out[0] = 0x01; // Type: IPv4 Address
                out[1] = 0x02; // Subtype: Route Target
                out[2..6].copy_from_slice(&ip.octets());
                out[6..8].copy_from_slice(&assigned.to_be_bytes());
            }
            Self::Asn4 { asn, assigned } => {
                out[0] = 0x02; // Type: 4-byte ASN
                out[1] = 0x02; // Subtype: Route Target
                out[2..6].copy_from_slice(&asn.to_be_bytes());
                out[6..8].copy_from_slice(&assigned.to_be_bytes());
            }
        }
        out
    }

    /// Deserializes Route Target from 8 bytes.
    pub fn from_bytes(bytes: &[u8; 8]) -> Result<Self> {
        if bytes[1] != 0x02 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "extended community is not a Route Target (subtype != 0x02)",
            )));
        }
        match bytes[0] {
            0x00 => {
                let asn = u16::from_be_bytes([bytes[2], bytes[3]]);
                let assigned = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                Ok(Self::Asn2 { asn, assigned })
            }
            0x01 => {
                let ip = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
                let assigned = u16::from_be_bytes([bytes[6], bytes[7]]);
                Ok(Self::Ip { ip, assigned })
            }
            0x02 => {
                let asn = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                let assigned = u16::from_be_bytes([bytes[6], bytes[7]]);
                Ok(Self::Asn4 { asn, assigned })
            }
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown Route Target type code",
            ))),
        }
    }
}

impl fmt::Display for RouteTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn2 { asn, assigned } => write!(f, "target:{}:{}", asn, assigned),
            Self::Ip { ip, assigned } => write!(f, "target:{}:{}", ip, assigned),
            Self::Asn4 { asn, assigned } => write!(f, "target:{}:{}", asn, assigned),
        }
    }
}

/// 10-byte Ethernet Segment Identifier (ESI, RFC 7432 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EthernetSegmentId(pub [u8; 10]);

impl EthernetSegmentId {
    /// Zero ESI for single-homed endpoints.
    pub const fn zero() -> Self {
        Self([0u8; 10])
    }

    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Default for EthernetSegmentId {
    fn default() -> Self {
        Self::zero()
    }
}

/// 6-byte Ethernet MAC Address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn to_hex(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid MAC address format; expected 'XX:XX:XX:XX:XX:XX'",
            )));
        }
        let mut octets = [0u8; 6];
        for i in 0..6 {
            octets[i] = u8::from_str_radix(parts[i], 16).map_err(|_| {
                VelcruxError::Protocol(ProtocolError::Malformed("invalid MAC address hex"))
            })?;
        }
        Ok(Self(octets))
    }
}

/// EVPN Network Layer Reachability Information (NLRI) Route Types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvpnRoute {
    /// Route Type 1: Ethernet Auto-Discovery (A-D) Route.
    EthernetAutoDiscovery {
        rd: RouteDistinguisher,
        esi: EthernetSegmentId,
        ethernet_tag_id: u32,
        vni: u32,
    },
    /// Route Type 2: MAC/IP Advertisement Route (MAC + optional IP binding to VNI).
    MacIpAdvertisement {
        rd: RouteDistinguisher,
        esi: EthernetSegmentId,
        ethernet_tag_id: u32,
        mac: MacAddress,
        ip: Option<Ipv4Addr>,
        vni: u32,
    },
    /// Route Type 3: Inclusive Multicast Ethernet Tag (IMET) Route (for BUM replication).
    InclusiveMulticast {
        rd: RouteDistinguisher,
        ethernet_tag_id: u32,
        originating_router_ip: Ipv4Addr,
    },
    /// Route Type 4: Ethernet Segment Route (for multi-homing all-active ES).
    EthernetSegment {
        rd: RouteDistinguisher,
        esi: EthernetSegmentId,
        originating_router_ip: Ipv4Addr,
    },
    /// Route Type 5: IP Prefix Route (RFC 9136, inter-subnet routing).
    IpPrefix {
        rd: RouteDistinguisher,
        esi: EthernetSegmentId,
        ethernet_tag_id: u32,
        prefix_len: u8,
        prefix: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        vni: u32,
    },
}

impl EvpnRoute {
    /// Returns the Route Type code (1 to 5).
    pub fn route_type(&self) -> u8 {
        match self {
            Self::EthernetAutoDiscovery { .. } => EVPN_TYPE_ETHERNET_AD,
            Self::MacIpAdvertisement { .. } => EVPN_TYPE_MAC_IP_ADV,
            Self::InclusiveMulticast { .. } => EVPN_TYPE_INCLUSIVE_MULTICAST,
            Self::EthernetSegment { .. } => EVPN_TYPE_ETHERNET_SEGMENT,
            Self::IpPrefix { .. } => EVPN_TYPE_IP_PREFIX,
        }
    }

    /// Serializes EVPN NLRI into wire bytes (Type [1B] + Length [1B] + Value).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut val = Vec::new();

        match self {
            Self::EthernetAutoDiscovery {
                rd,
                esi,
                ethernet_tag_id,
                vni,
            } => {
                val.extend_from_slice(&rd.to_bytes());
                val.extend_from_slice(&esi.0);
                val.extend_from_slice(&ethernet_tag_id.to_be_bytes());
                // 24-bit MPLS/VNI label shifted by 4 (bottom 4 bits for flags/BoS)
                let label_bytes = (vni << 4).to_be_bytes();
                val.extend_from_slice(&label_bytes[1..4]);
            }
            Self::MacIpAdvertisement {
                rd,
                esi,
                ethernet_tag_id,
                mac,
                ip,
                vni,
            } => {
                val.extend_from_slice(&rd.to_bytes());
                val.extend_from_slice(&esi.0);
                val.extend_from_slice(&ethernet_tag_id.to_be_bytes());
                val.push(48); // MAC address length in bits
                val.extend_from_slice(&mac.0);
                if let Some(ipv4) = ip {
                    val.push(32); // IP address length in bits
                    val.extend_from_slice(&ipv4.octets());
                } else {
                    val.push(0); // No IP address present
                }
                let label_bytes = (vni << 4).to_be_bytes();
                val.extend_from_slice(&label_bytes[1..4]);
            }
            Self::InclusiveMulticast {
                rd,
                ethernet_tag_id,
                originating_router_ip,
            } => {
                val.extend_from_slice(&rd.to_bytes());
                val.extend_from_slice(&ethernet_tag_id.to_be_bytes());
                val.push(32); // IP length in bits
                val.extend_from_slice(&originating_router_ip.octets());
            }
            Self::EthernetSegment {
                rd,
                esi,
                originating_router_ip,
            } => {
                val.extend_from_slice(&rd.to_bytes());
                val.extend_from_slice(&esi.0);
                val.push(32);
                val.extend_from_slice(&originating_router_ip.octets());
            }
            Self::IpPrefix {
                rd,
                esi,
                ethernet_tag_id,
                prefix_len,
                prefix,
                gateway_ip,
                vni,
            } => {
                val.extend_from_slice(&rd.to_bytes());
                val.extend_from_slice(&esi.0);
                val.extend_from_slice(&ethernet_tag_id.to_be_bytes());
                val.push(*prefix_len);
                val.extend_from_slice(&prefix.octets());
                val.extend_from_slice(&gateway_ip.octets());
                let label_bytes = (vni << 4).to_be_bytes();
                val.extend_from_slice(&label_bytes[1..4]);
            }
        }

        let mut out = Vec::with_capacity(2 + val.len());
        out.push(self.route_type());
        out.push(val.len() as u8);
        out.extend_from_slice(&val);
        out
    }

    /// Deserializes EVPN NLRI from wire slice.
    pub fn from_bytes(slice: &[u8]) -> Result<(Self, usize)> {
        if slice.len() < 2 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "EVPN NLRI slice too short",
            )));
        }
        let r_type = slice[0];
        let r_len = slice[1] as usize;
        if slice.len() < 2 + r_len {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "truncated EVPN NLRI length",
            )));
        }
        let body = &slice[2..2 + r_len];

        let route = match r_type {
            EVPN_TYPE_ETHERNET_AD => {
                if body.len() < 25 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "EVPN Type 1 body too short",
                    )));
                }
                let mut rd_bytes = [0u8; 8];
                rd_bytes.copy_from_slice(&body[0..8]);
                let rd = RouteDistinguisher::from_bytes(&rd_bytes)?;

                let mut esi_bytes = [0u8; 10];
                esi_bytes.copy_from_slice(&body[8..18]);
                let esi = EthernetSegmentId(esi_bytes);

                let ethernet_tag_id = u32::from_be_bytes(body[18..22].try_into().unwrap());
                let vni = (u32::from_be_bytes([0, body[22], body[23], body[24]])) >> 4;

                Self::EthernetAutoDiscovery {
                    rd,
                    esi,
                    ethernet_tag_id,
                    vni,
                }
            }
            EVPN_TYPE_MAC_IP_ADV => {
                if body.len() < 33 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "EVPN Type 2 body too short",
                    )));
                }
                let mut rd_bytes = [0u8; 8];
                rd_bytes.copy_from_slice(&body[0..8]);
                let rd = RouteDistinguisher::from_bytes(&rd_bytes)?;

                let mut esi_bytes = [0u8; 10];
                esi_bytes.copy_from_slice(&body[8..18]);
                let esi = EthernetSegmentId(esi_bytes);

                let ethernet_tag_id = u32::from_be_bytes(body[18..22].try_into().unwrap());
                // body[22] is MAC length in bits (48)
                let mut mac_bytes = [0u8; 6];
                mac_bytes.copy_from_slice(&body[23..29]);
                let mac = MacAddress(mac_bytes);

                let ip_len_bits = body[29];
                let mut offset = 30;
                let ip = if ip_len_bits == 32 && body.len() >= offset + 4 {
                    let ipv4 = Ipv4Addr::new(
                        body[offset],
                        body[offset + 1],
                        body[offset + 2],
                        body[offset + 3],
                    );
                    offset += 4;
                    Some(ipv4)
                } else {
                    None
                };

                let vni = if body.len() >= offset + 3 {
                    (u32::from_be_bytes([0, body[offset], body[offset + 1], body[offset + 2]])) >> 4
                } else {
                    0
                };

                Self::MacIpAdvertisement {
                    rd,
                    esi,
                    ethernet_tag_id,
                    mac,
                    ip,
                    vni,
                }
            }
            EVPN_TYPE_INCLUSIVE_MULTICAST => {
                if body.len() < 17 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "EVPN Type 3 body too short",
                    )));
                }
                let mut rd_bytes = [0u8; 8];
                rd_bytes.copy_from_slice(&body[0..8]);
                let rd = RouteDistinguisher::from_bytes(&rd_bytes)?;
                let ethernet_tag_id = u32::from_be_bytes(body[8..12].try_into().unwrap());
                let originating_router_ip = Ipv4Addr::new(body[13], body[14], body[15], body[16]);

                Self::InclusiveMulticast {
                    rd,
                    ethernet_tag_id,
                    originating_router_ip,
                }
            }
            EVPN_TYPE_ETHERNET_SEGMENT => {
                if body.len() < 23 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "EVPN Type 4 body too short",
                    )));
                }
                let mut rd_bytes = [0u8; 8];
                rd_bytes.copy_from_slice(&body[0..8]);
                let rd = RouteDistinguisher::from_bytes(&rd_bytes)?;
                let mut esi_bytes = [0u8; 10];
                esi_bytes.copy_from_slice(&body[8..18]);
                let esi = EthernetSegmentId(esi_bytes);
                let originating_router_ip = Ipv4Addr::new(body[19], body[20], body[21], body[22]);

                Self::EthernetSegment {
                    rd,
                    esi,
                    originating_router_ip,
                }
            }
            EVPN_TYPE_IP_PREFIX => {
                if body.len() < 34 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "EVPN Type 5 body too short",
                    )));
                }
                let mut rd_bytes = [0u8; 8];
                rd_bytes.copy_from_slice(&body[0..8]);
                let rd = RouteDistinguisher::from_bytes(&rd_bytes)?;

                let mut esi_bytes = [0u8; 10];
                esi_bytes.copy_from_slice(&body[8..18]);
                let esi = EthernetSegmentId(esi_bytes);

                let ethernet_tag_id = u32::from_be_bytes(body[18..22].try_into().unwrap());
                let prefix_len = body[22];
                let prefix = Ipv4Addr::new(body[23], body[24], body[25], body[26]);
                let gateway_ip = Ipv4Addr::new(body[27], body[28], body[29], body[30]);
                let vni = (u32::from_be_bytes([0, body[31], body[32], body[33]])) >> 4;

                Self::IpPrefix {
                    rd,
                    esi,
                    ethernet_tag_id,
                    prefix_len,
                    prefix,
                    gateway_ip,
                    vni,
                }
            }
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown EVPN Route Type code",
            )))?,
        };

        Ok((route, 2 + r_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_distinguisher_and_target_parse() {
        let rd1 = RouteDistinguisher::parse("65001:100").unwrap();
        assert_eq!(rd1.to_string(), "65001:100");
        let bytes1 = rd1.to_bytes();
        assert_eq!(RouteDistinguisher::from_bytes(&bytes1).unwrap(), rd1);

        let rd2 = RouteDistinguisher::parse("10.0.0.1:500").unwrap();
        assert_eq!(rd2.to_string(), "10.0.0.1:500");
        let bytes2 = rd2.to_bytes();
        assert_eq!(RouteDistinguisher::from_bytes(&bytes2).unwrap(), rd2);

        let rt = RouteTarget::parse("target:65001:200").unwrap();
        assert_eq!(rt.to_string(), "target:65001:200");
        let rt_bytes = rt.to_bytes();
        assert_eq!(RouteTarget::from_bytes(&rt_bytes).unwrap(), rt);
    }

    #[test]
    fn test_evpn_type2_mac_ip_roundtrip() {
        let rd = RouteDistinguisher::parse("65001:1000").unwrap();
        let mac = MacAddress::parse("00:1A:2B:3C:4D:5E").unwrap();
        let ip = Some(Ipv4Addr::new(10, 10, 1, 42));

        let route = EvpnRoute::MacIpAdvertisement {
            rd,
            esi: EthernetSegmentId::zero(),
            ethernet_tag_id: 0,
            mac,
            ip,
            vni: 10001,
        };

        let raw = route.to_bytes();
        let (parsed, consumed) = EvpnRoute::from_bytes(&raw).expect("parse type 2");
        assert_eq!(consumed, raw.len());
        assert_eq!(route, parsed);
    }

    #[test]
    fn test_evpn_type5_ip_prefix_roundtrip() {
        let rd = RouteDistinguisher::parse("65001:2000").unwrap();
        let route = EvpnRoute::IpPrefix {
            rd,
            esi: EthernetSegmentId::zero(),
            ethernet_tag_id: 0,
            prefix_len: 24,
            prefix: Ipv4Addr::new(192, 168, 50, 0),
            gateway_ip: Ipv4Addr::new(10, 0, 0, 1),
            vni: 20002,
        };

        let raw = route.to_bytes();
        let (parsed, consumed) = EvpnRoute::from_bytes(&raw).expect("parse type 5");
        assert_eq!(consumed, raw.len());
        assert_eq!(route, parsed);
    }
}
