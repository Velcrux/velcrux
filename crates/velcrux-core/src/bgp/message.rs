#![forbid(unsafe_code)]

//! BGP-4 & Multiprotocol BGP (MP-BGP) Protocol Framing & Message Descriptors.
//!
//! Conforms to RFC 4271 (BGP-4), RFC 4760 (Multiprotocol Extensions), and RFC 6793 (4-byte ASNs).
//! Implements wire encoding and decoding for BGP OPEN, UPDATE, NOTIFICATION, KEEPALIVE, and ROUTE_REFRESH.

use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// 16-byte BGP message header marker (all bits set to 1 per RFC 4271).
pub const BGP_HEADER_MARKER: [u8; 16] = [0xFF; 16];

/// Standard BGP message header length (16-byte marker + 2-byte length + 1-byte type).
pub const BGP_HEADER_LEN: usize = 19;

/// Standard BGP TCP Port.
pub const BGP_TCP_PORT: u16 = 179;

// BGP Message Types
pub const BGP_MSG_OPEN: u8 = 1;
pub const BGP_MSG_UPDATE: u8 = 2;
pub const BGP_MSG_NOTIFICATION: u8 = 3;
pub const BGP_MSG_KEEPALIVE: u8 = 4;
pub const BGP_MSG_ROUTE_REFRESH: u8 = 5;

// Path Attribute Type Flags
pub const ATTR_FLAG_OPTIONAL: u8 = 0x80;
pub const ATTR_FLAG_TRANSITIVE: u8 = 0x40;
pub const ATTR_FLAG_PARTIAL: u8 = 0x20;
pub const ATTR_FLAG_EXTENDED_LEN: u8 = 0x10;

// Well-Known & Optional Path Attribute Type Codes
pub const ATTR_ORIGIN: u8 = 1;
pub const ATTR_AS_PATH: u8 = 2;
pub const ATTR_NEXT_HOP: u8 = 3;
pub const ATTR_MULTI_EXIT_DISC: u8 = 4;
pub const ATTR_LOCAL_PREF: u8 = 5;
pub const ATTR_ATOMIC_AGGREGATE: u8 = 6;
pub const ATTR_AGGREGATOR: u8 = 7;
pub const ATTR_COMMUNITIES: u8 = 8;
pub const ATTR_ORIGINATOR_ID: u8 = 9;
pub const ATTR_CLUSTER_LIST: u8 = 10;
pub const ATTR_MP_REACH_NLRI: u8 = 14;
pub const ATTR_MP_UNREACH_NLRI: u8 = 15;
pub const ATTR_EXTENDED_COMMUNITIES: u8 = 16;
pub const ATTR_AS4_PATH: u8 = 17;

// Origin Types
pub const ORIGIN_IGP: u8 = 0;
pub const ORIGIN_EGP: u8 = 1;
pub const ORIGIN_INCOMPLETE: u8 = 2;

// Standard Well-Known Communities (RFC 1997)
pub const COMMUNITY_NO_EXPORT: u32 = 0xFFFF_FF01;
pub const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFF_FF02;
pub const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;
pub const COMMUNITY_BLACKHOLE: u32 = 0xFFFF_029A; // RFC 7999

/// Represents a BGP Path Attribute Origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpOrigin {
    Igp,
    Egp,
    Incomplete,
}

impl BgpOrigin {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Igp => ORIGIN_IGP,
            Self::Egp => ORIGIN_EGP,
            Self::Incomplete => ORIGIN_INCOMPLETE,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            ORIGIN_IGP => Self::Igp,
            ORIGIN_EGP => Self::Egp,
            _ => Self::Incomplete,
        }
    }
}

/// AS Path Segment Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

/// AS Path Segment containing 32-bit ASNs (RFC 6793).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsPathSegment {
    pub segment_type: AsPathSegmentType,
    pub asns: Vec<u32>,
}

impl AsPathSegment {
    pub fn sequence(asns: Vec<u32>) -> Self {
        Self {
            segment_type: AsPathSegmentType::AsSequence,
            asns,
        }
    }
}

/// IP Prefix (IPv4 CIDR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BgpPrefix {
    pub prefix: Ipv4Addr,
    pub length: u8,
}

impl BgpPrefix {
    pub fn new(prefix: Ipv4Addr, length: u8) -> Self {
        Self { prefix, length }
    }

    /// Serializes BGP prefix according to RFC 4271 (1 byte length + ceil(length/8) prefix bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.length);
        let octets = self.prefix.octets();
        let bytes_needed = ((self.length as usize) + 7) / 8;
        out.extend_from_slice(&octets[..bytes_needed.min(4)]);
        out
    }

    /// Deserializes BGP prefix from byte slice, returning (Prefix, bytes_consumed).
    pub fn from_bytes(slice: &[u8]) -> Result<(Self, usize)> {
        if slice.is_empty() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "empty slice for BGP prefix",
            )));
        }
        let length = slice[0];
        if length > 32 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "IPv4 prefix length > 32",
            )));
        }
        let bytes_needed = ((length as usize) + 7) / 8;
        if slice.len() < 1 + bytes_needed {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "truncated BGP prefix bytes",
            )));
        }
        let mut octets = [0u8; 4];
        for i in 0..bytes_needed.min(4) {
            octets[i] = slice[1 + i];
        }
        Ok((
            Self {
                prefix: Ipv4Addr::from(octets),
                length,
            },
            1 + bytes_needed,
        ))
    }
}

/// BGP Path Attributes Collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpPathAttributes {
    pub origin: BgpOrigin,
    pub as_path: Vec<AsPathSegment>,
    pub next_hop: Ipv4Addr,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub atomic_aggregate: bool,
    pub aggregator_asn: Option<u32>,
    pub aggregator_ip: Option<Ipv4Addr>,
    pub communities: Vec<u32>,
    pub extended_communities: Vec<[u8; 8]>,
}

impl Default for BgpPathAttributes {
    fn default() -> Self {
        Self {
            origin: BgpOrigin::Igp,
            as_path: Vec::new(),
            next_hop: Ipv4Addr::new(127, 0, 0, 1),
            med: None,
            local_pref: Some(100),
            atomic_aggregate: false,
            aggregator_asn: None,
            aggregator_ip: None,
            communities: Vec::new(),
            extended_communities: Vec::new(),
        }
    }
}

impl BgpPathAttributes {
    /// Total AS hops along the AS path.
    pub fn total_as_hops(&self) -> usize {
        self.as_path.iter().map(|seg| seg.asns.len()).sum()
    }

    /// Serializes path attributes into raw wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // 1. ORIGIN (Transitive, Well-Known = 0x40)
        out.push(ATTR_FLAG_TRANSITIVE);
        out.push(ATTR_ORIGIN);
        out.push(1);
        out.push(self.origin.to_u8());

        // 2. AS_PATH (Transitive, Well-Known = 0x40)
        let mut as_path_buf = Vec::new();
        for seg in &self.as_path {
            as_path_buf.push(seg.segment_type as u8);
            as_path_buf.push(seg.asns.len() as u8);
            for &asn in &seg.asns {
                as_path_buf.extend_from_slice(&asn.to_be_bytes());
            }
        }
        out.push(ATTR_FLAG_TRANSITIVE);
        out.push(ATTR_AS_PATH);
        out.push(as_path_buf.len() as u8);
        out.extend_from_slice(&as_path_buf);

        // 3. NEXT_HOP (Transitive, Well-Known = 0x40)
        out.push(ATTR_FLAG_TRANSITIVE);
        out.push(ATTR_NEXT_HOP);
        out.push(4);
        out.extend_from_slice(&self.next_hop.octets());

        // 4. MED (Optional Non-Transitive = 0x80)
        if let Some(med) = self.med {
            out.push(ATTR_FLAG_OPTIONAL);
            out.push(ATTR_MULTI_EXIT_DISC);
            out.push(4);
            out.extend_from_slice(&med.to_be_bytes());
        }

        // 5. LOCAL_PREF (Transitive, Well-Known in iBGP = 0x40)
        if let Some(lp) = self.local_pref {
            out.push(ATTR_FLAG_TRANSITIVE);
            out.push(ATTR_LOCAL_PREF);
            out.push(4);
            out.extend_from_slice(&lp.to_be_bytes());
        }

        // 6. ATOMIC_AGGREGATE (Transitive, Well-Known = 0x40)
        if self.atomic_aggregate {
            out.push(ATTR_FLAG_TRANSITIVE);
            out.push(ATTR_ATOMIC_AGGREGATE);
            out.push(0);
        }

        // 7. COMMUNITIES (Optional Transitive = 0xC0)
        if !self.communities.is_empty() {
            out.push(ATTR_FLAG_OPTIONAL | ATTR_FLAG_TRANSITIVE);
            out.push(ATTR_COMMUNITIES);
            let len = (self.communities.len() * 4) as u8;
            out.push(len);
            for &c in &self.communities {
                out.extend_from_slice(&c.to_be_bytes());
            }
        }

        // 8. EXTENDED COMMUNITIES (Optional Transitive = 0xC0)
        if !self.extended_communities.is_empty() {
            out.push(ATTR_FLAG_OPTIONAL | ATTR_FLAG_TRANSITIVE);
            out.push(ATTR_EXTENDED_COMMUNITIES);
            let len = (self.extended_communities.len() * 8) as u8;
            out.push(len);
            for ext in &self.extended_communities {
                out.extend_from_slice(ext);
            }
        }

        out
    }

    /// Deserializes path attributes from wire bytes.
    pub fn from_bytes(slice: &[u8]) -> Result<Self> {
        let mut attrs = Self::default();
        let mut offset = 0;

        while offset < slice.len() {
            if offset + 2 > slice.len() {
                break;
            }
            let flags = slice[offset];
            let attr_code = slice[offset + 1];
            offset += 2;

            let length = if (flags & ATTR_FLAG_EXTENDED_LEN) != 0 {
                if offset + 2 > slice.len() {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "truncated extended attribute length",
                    )));
                }
                let l = u16::from_be_bytes([slice[offset], slice[offset + 1]]) as usize;
                offset += 2;
                l
            } else {
                if offset + 1 > slice.len() {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "truncated attribute length",
                    )));
                }
                let l = slice[offset] as usize;
                offset += 1;
                l
            };

            if offset + length > slice.len() {
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "attribute length exceeds buffer",
                )));
            }

            let val_slice = &slice[offset..offset + length];
            offset += length;

            match attr_code {
                ATTR_ORIGIN => {
                    if !val_slice.is_empty() {
                        attrs.origin = BgpOrigin::from_u8(val_slice[0]);
                    }
                }
                ATTR_AS_PATH => {
                    let mut seg_offset = 0;
                    attrs.as_path.clear();
                    while seg_offset + 2 <= val_slice.len() {
                        let seg_type = match val_slice[seg_offset] {
                            1 => AsPathSegmentType::AsSet,
                            _ => AsPathSegmentType::AsSequence,
                        };
                        let seg_len = val_slice[seg_offset + 1] as usize;
                        seg_offset += 2;
                        let mut asns = Vec::new();
                        // Support 4-byte ASNs
                        for _ in 0..seg_len {
                            if seg_offset + 4 <= val_slice.len() {
                                let asn = u32::from_be_bytes(
                                    val_slice[seg_offset..seg_offset + 4].try_into().unwrap(),
                                );
                                asns.push(asn);
                                seg_offset += 4;
                            } else if seg_offset + 2 <= val_slice.len() {
                                // 2-byte ASN fallback
                                let asn = u16::from_be_bytes(
                                    val_slice[seg_offset..seg_offset + 2].try_into().unwrap(),
                                ) as u32;
                                asns.push(asn);
                                seg_offset += 2;
                            }
                        }
                        attrs.as_path.push(AsPathSegment {
                            segment_type: seg_type,
                            asns,
                        });
                    }
                }
                ATTR_NEXT_HOP => {
                    if val_slice.len() >= 4 {
                        attrs.next_hop =
                            Ipv4Addr::new(val_slice[0], val_slice[1], val_slice[2], val_slice[3]);
                    }
                }
                ATTR_MULTI_EXIT_DISC => {
                    if val_slice.len() >= 4 {
                        attrs.med = Some(u32::from_be_bytes(val_slice[..4].try_into().unwrap()));
                    }
                }
                ATTR_LOCAL_PREF => {
                    if val_slice.len() >= 4 {
                        attrs.local_pref =
                            Some(u32::from_be_bytes(val_slice[..4].try_into().unwrap()));
                    }
                }
                ATTR_ATOMIC_AGGREGATE => {
                    attrs.atomic_aggregate = true;
                }
                ATTR_COMMUNITIES => {
                    let mut c_offset = 0;
                    attrs.communities.clear();
                    while c_offset + 4 <= val_slice.len() {
                        let comm = u32::from_be_bytes(
                            val_slice[c_offset..c_offset + 4].try_into().unwrap(),
                        );
                        attrs.communities.push(comm);
                        c_offset += 4;
                    }
                }
                ATTR_EXTENDED_COMMUNITIES => {
                    let mut ext_offset = 0;
                    attrs.extended_communities.clear();
                    while ext_offset + 8 <= val_slice.len() {
                        let mut ext = [0u8; 8];
                        ext.copy_from_slice(&val_slice[ext_offset..ext_offset + 8]);
                        attrs.extended_communities.push(ext);
                        ext_offset += 8;
                    }
                }
                _ => {}
            }
        }

        Ok(attrs)
    }
}

/// BGP Protocol Messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpMessage {
    /// BGP OPEN Message (Type 1).
    Open {
        version: u8,
        asn: u32,
        hold_time: u16,
        router_id: Ipv4Addr,
        capabilities: Vec<u8>,
    },
    /// BGP UPDATE Message (Type 2).
    Update {
        withdrawn_routes: Vec<BgpPrefix>,
        path_attributes: BgpPathAttributes,
        nlri: Vec<BgpPrefix>,
    },
    /// BGP NOTIFICATION Message (Type 3).
    Notification {
        error_code: u8,
        error_subcode: u8,
        data: Vec<u8>,
    },
    /// BGP KEEPALIVE Message (Type 4, exactly 19 bytes).
    Keepalive,
    /// BGP ROUTE_REFRESH Message (Type 5).
    RouteRefresh { afi: u16, safi: u8 },
}

impl BgpMessage {
    /// Serializes complete BGP message with standard 19-byte header framing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let msg_type = match self {
            Self::Open {
                version,
                asn,
                hold_time,
                router_id,
                capabilities,
            } => {
                body.push(*version);
                // 16-bit ASN in basic header; 0xFFFF / 23456 (AS_TRANS) if 32-bit > 65535
                let as16 = if *asn > 65535 { 23456u16 } else { *asn as u16 };
                body.extend_from_slice(&as16.to_be_bytes());
                body.extend_from_slice(&hold_time.to_be_bytes());
                body.extend_from_slice(&router_id.octets());

                // Optional parameters (Capabilities)
                let mut opt_params = Vec::new();
                // 4-byte ASN capability (Cap code 65, RFC 6793)
                opt_params.push(2); // Param type: Capability
                opt_params.push(6); // Param length: 6
                opt_params.push(65); // Cap code: 4-byte ASN
                opt_params.push(4); // Cap length: 4
                opt_params.extend_from_slice(&asn.to_be_bytes());

                // MP-BGP EVPN Capability (AFI 25 L2VPN, SAFI 70 EVPN, Cap code 1)
                opt_params.push(2);
                opt_params.push(6);
                opt_params.push(1); // Cap code: Multiprotocol Extensions
                opt_params.push(4);
                opt_params.extend_from_slice(&25u16.to_be_bytes()); // AFI 25
                opt_params.push(0); // Reserved
                opt_params.push(70); // SAFI 70 EVPN

                // Custom extra capabilities
                opt_params.extend_from_slice(capabilities);

                body.push(opt_params.len() as u8);
                body.extend_from_slice(&opt_params);
                BGP_MSG_OPEN
            }
            Self::Update {
                withdrawn_routes,
                path_attributes,
                nlri,
            } => {
                // Withdrawn routes length
                let mut withdrawn_bytes = Vec::new();
                for w in withdrawn_routes {
                    withdrawn_bytes.extend_from_slice(&w.to_bytes());
                }
                body.extend_from_slice(&(withdrawn_bytes.len() as u16).to_be_bytes());
                body.extend_from_slice(&withdrawn_bytes);

                // Path attributes
                let attr_bytes = path_attributes.to_bytes();
                body.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
                body.extend_from_slice(&attr_bytes);

                // NLRI
                for n in nlri {
                    body.extend_from_slice(&n.to_bytes());
                }
                BGP_MSG_UPDATE
            }
            Self::Notification {
                error_code,
                error_subcode,
                data,
            } => {
                body.push(*error_code);
                body.push(*error_subcode);
                body.extend_from_slice(data);
                BGP_MSG_NOTIFICATION
            }
            Self::Keepalive => BGP_MSG_KEEPALIVE,
            Self::RouteRefresh { afi, safi } => {
                body.extend_from_slice(&afi.to_be_bytes());
                body.push(0); // reserved
                body.push(*safi);
                BGP_MSG_ROUTE_REFRESH
            }
        };

        let total_length = (BGP_HEADER_LEN + body.len()) as u16;
        let mut msg = Vec::with_capacity(total_length as usize);
        msg.extend_from_slice(&BGP_HEADER_MARKER);
        msg.extend_from_slice(&total_length.to_be_bytes());
        msg.push(msg_type);
        msg.extend_from_slice(&body);
        msg
    }

    /// Deserializes a complete BGP message from a wire packet.
    pub fn from_bytes(slice: &[u8]) -> Result<Self> {
        if slice.len() < BGP_HEADER_LEN {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "slice is shorter than standard BGP 19-byte header",
            )));
        }

        // Verify 16-byte marker
        if slice[..16] != BGP_HEADER_MARKER {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid BGP header marker",
            )));
        }

        let length = u16::from_be_bytes([slice[16], slice[17]]) as usize;
        if slice.len() < length {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "incomplete BGP packet",
            )));
        }

        let msg_type = slice[18];
        let body = &slice[BGP_HEADER_LEN..length];

        match msg_type {
            BGP_MSG_OPEN => {
                if body.len() < 10 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "OPEN message body too short",
                    )));
                }
                let version = body[0];
                let asn16 = u16::from_be_bytes([body[1], body[2]]) as u32;
                let hold_time = u16::from_be_bytes([body[3], body[4]]);
                let router_id = Ipv4Addr::new(body[5], body[6], body[7], body[8]);
                let opt_len = body[9] as usize;

                let mut asn = asn16;
                let mut capabilities = Vec::new();

                if body.len() >= 10 + opt_len {
                    let opt_bytes = &body[10..10 + opt_len];
                    let mut pos = 0;
                    while pos + 2 <= opt_bytes.len() {
                        let p_type = opt_bytes[pos];
                        let p_len = opt_bytes[pos + 1] as usize;
                        pos += 2;
                        if pos + p_len <= opt_bytes.len() {
                            let p_val = &opt_bytes[pos..pos + p_len];
                            if p_type == 2 && p_val.len() >= 6 && p_val[0] == 65 {
                                // 4-byte ASN capability
                                asn = u32::from_be_bytes(p_val[2..6].try_into().unwrap());
                            }
                            capabilities.extend_from_slice(p_val);
                            pos += p_len;
                        }
                    }
                }

                Ok(Self::Open {
                    version,
                    asn,
                    hold_time,
                    router_id,
                    capabilities,
                })
            }
            BGP_MSG_UPDATE => {
                if body.len() < 4 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "UPDATE message body too short",
                    )));
                }
                let withdrawn_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                let mut offset = 2;

                if offset + withdrawn_len > body.len() {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "withdrawn routes length overflow",
                    )));
                }

                let mut withdrawn_routes = Vec::new();
                let withdrawn_slice = &body[offset..offset + withdrawn_len];
                let mut w_off = 0;
                while w_off < withdrawn_slice.len() {
                    let (pfx, consumed) = BgpPrefix::from_bytes(&withdrawn_slice[w_off..])?;
                    withdrawn_routes.push(pfx);
                    w_off += consumed;
                }
                offset += withdrawn_len;

                if offset + 2 > body.len() {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "truncated total attribute length",
                    )));
                }
                let total_attr_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
                offset += 2;

                if offset + total_attr_len > body.len() {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "attribute length overflow",
                    )));
                }

                let path_attributes =
                    BgpPathAttributes::from_bytes(&body[offset..offset + total_attr_len])?;
                offset += total_attr_len;

                let mut nlri = Vec::new();
                let nlri_slice = &body[offset..];
                let mut n_off = 0;
                while n_off < nlri_slice.len() {
                    let (pfx, consumed) = BgpPrefix::from_bytes(&nlri_slice[n_off..])?;
                    nlri.push(pfx);
                    n_off += consumed;
                }

                Ok(Self::Update {
                    withdrawn_routes,
                    path_attributes,
                    nlri,
                })
            }
            BGP_MSG_NOTIFICATION => {
                if body.len() < 2 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "NOTIFICATION body too short",
                    )));
                }
                let error_code = body[0];
                let error_subcode = body[1];
                let data = body[2..].to_vec();
                Ok(Self::Notification {
                    error_code,
                    error_subcode,
                    data,
                })
            }
            BGP_MSG_KEEPALIVE => Ok(Self::Keepalive),
            BGP_MSG_ROUTE_REFRESH => {
                if body.len() < 4 {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "ROUTE_REFRESH body too short",
                    )));
                }
                let afi = u16::from_be_bytes([body[0], body[1]]);
                let safi = body[3];
                Ok(Self::RouteRefresh { afi, safi })
            }
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown BGP message type",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_open_roundtrip() {
        let open = BgpMessage::Open {
            version: 4,
            asn: 65001,
            hold_time: 90,
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: Vec::new(),
        };

        let raw = open.to_bytes();
        assert!(raw.len() >= BGP_HEADER_LEN);
        let parsed = BgpMessage::from_bytes(&raw).expect("parse open");

        if let BgpMessage::Open {
            version,
            asn,
            hold_time,
            router_id,
            ..
        } = parsed
        {
            assert_eq!(version, 4);
            assert_eq!(asn, 65001);
            assert_eq!(hold_time, 90);
            assert_eq!(router_id, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("expected Open message");
        }
    }

    #[test]
    fn test_bgp_update_roundtrip() {
        let pfx1 = BgpPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let pfx2 = BgpPrefix::new(Ipv4Addr::new(10, 20, 0, 0), 16);

        let mut attrs = BgpPathAttributes::default();
        attrs.origin = BgpOrigin::Igp;
        attrs.as_path = vec![AsPathSegment::sequence(vec![65001, 65002])];
        attrs.next_hop = Ipv4Addr::new(10, 0, 0, 2);
        attrs.local_pref = Some(200);
        attrs.communities = vec![COMMUNITY_NO_EXPORT, 0xFD00_0001];

        let update = BgpMessage::Update {
            withdrawn_routes: vec![pfx2],
            path_attributes: attrs,
            nlri: vec![pfx1],
        };

        let raw = update.to_bytes();
        let parsed = BgpMessage::from_bytes(&raw).expect("parse update");

        if let BgpMessage::Update {
            withdrawn_routes,
            path_attributes,
            nlri,
        } = parsed
        {
            assert_eq!(withdrawn_routes.len(), 1);
            assert_eq!(withdrawn_routes[0], pfx2);
            assert_eq!(nlri.len(), 1);
            assert_eq!(nlri[0], pfx1);
            assert_eq!(path_attributes.origin, BgpOrigin::Igp);
            assert_eq!(path_attributes.total_as_hops(), 2);
            assert_eq!(path_attributes.next_hop, Ipv4Addr::new(10, 0, 0, 2));
            assert_eq!(path_attributes.local_pref, Some(200));
            assert_eq!(path_attributes.communities.len(), 2);
        } else {
            panic!("expected Update message");
        }
    }

    #[test]
    fn test_bgp_keepalive_roundtrip() {
        let ka = BgpMessage::Keepalive;
        let raw = ka.to_bytes();
        assert_eq!(raw.len(), 19);
        let parsed = BgpMessage::from_bytes(&raw).expect("parse keepalive");
        assert_eq!(parsed, BgpMessage::Keepalive);
    }
}
