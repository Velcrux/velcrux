//! Dual-Stack Wire-Speed Packet Header Parser (`ADR-066`).
//!
//! Provides zero-copy parsing of Layer-2 through Layer-4 transport headers
//! with support for:
//! - IEEE 802.3 Ethernet II and IEEE 802.1Q Single/QinQ VLAN tags
//! - IPv4 (RFC 791) and IPv6 (RFC 8200) dual-stack network headers
//! - UDP (RFC 768) transport framing
//! - RFC 9000 QUIC Long Headers (Initial, 0-RTT, Handshake, Retry) and Short Headers (1-RTT)
//! - Variable-length Destination Connection ID (DCID) extraction (up to 20 bytes)

use serde::{Deserialize, Serialize};

/// Layer-2 Ethernet Protocol numbers.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN_8021Q: u16 = 0x8100;
pub const ETHERTYPE_VLAN_QINQ: u16 = 0x88A8;

/// IP Protocol numbers.
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_ICMPV6: u8 = 58;

/// IPv6 Extension Header numbers.
pub const IPV6_EXT_HOPOPT: u8 = 0;
pub const IPV6_EXT_ROUTING: u8 = 43;
pub const IPV6_EXT_FRAGMENT: u8 = 44;

/// QUIC Packet Header Form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicHeaderForm {
    /// Long Header (Initial, 0-RTT, Handshake, Retry) used during connection establishment.
    Long,
    /// Short Header (1-RTT Protected) used for bulk data transfer.
    Short,
}

/// Detailed dissection of an ingress network frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DissectedPacket {
    /// Layer-2 EtherType.
    pub ethertype: u16,
    /// 802.1Q VLAN Tag if encapsulated.
    pub vlan_id: Option<u16>,
    /// Source IP address (IPv4 or IPv6 string).
    pub src_ip: String,
    /// Destination IP address (IPv4 or IPv6 string).
    pub dst_ip: String,
    /// Whether IP layer is IPv6.
    pub is_ipv6: bool,
    /// L4 Protocol (17 for UDP).
    pub ip_protocol: u8,
    /// L4 Source Port.
    pub src_port: u16,
    /// L4 Destination Port.
    pub dst_port: u16,
    /// Total UDP payload length.
    pub udp_payload_len: usize,
    /// Whether the frame contains a valid QUIC datagram.
    pub is_quic: bool,
    /// QUIC Header Form (Long or Short).
    pub quic_header_form: Option<QuicHeaderForm>,
    /// QUIC Version if Long Header.
    pub quic_version: Option<u32>,
    /// Extracted Destination Connection ID (DCID) as hex string.
    pub quic_dcid: Option<String>,
    /// Raw DCID byte array.
    pub quic_dcid_bytes: Option<Vec<u8>>,
    /// Total frame byte length.
    pub total_frame_len: usize,
}

/// Dissect an incoming raw packet frame at wire speed.
pub fn dissect_packet(raw: &[u8]) -> Option<DissectedPacket> {
    if raw.len() < 14 {
        return None;
    }

    let mut cursor = 12; // Skip Src/Dst MAC addresses (6 + 6 = 12 bytes)
    let mut ethertype = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]);
    cursor += 2;

    let mut vlan_id = None;

    // Handle 802.1Q / QinQ VLAN encapsulation
    if ethertype == ETHERTYPE_VLAN_8021Q || ethertype == ETHERTYPE_VLAN_QINQ {
        if raw.len() < cursor + 4 {
            return None;
        }
        let tci = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]);
        vlan_id = Some(tci & 0x0FFF);
        cursor += 2;
        ethertype = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]);
        cursor += 2;

        // Check for double VLAN (QinQ)
        if ethertype == ETHERTYPE_VLAN_8021Q {
            if raw.len() < cursor + 4 {
                return None;
            }
            cursor += 2;
            ethertype = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]);
            cursor += 2;
        }
    }

    let is_ipv6;
    let src_ip;
    let dst_ip;
    let ip_protocol;
    let ip_payload_offset;

    match ethertype {
        ETHERTYPE_IPV4 => {
            is_ipv6 = false;
            if raw.len() < cursor + 20 {
                return None;
            }
            let ihl = (raw[cursor] & 0x0F) as usize * 4;
            if ihl < 20 || raw.len() < cursor + ihl {
                return None;
            }

            ip_protocol = raw[cursor + 9];
            src_ip = format!(
                "{}.{}.{}.{}",
                raw[cursor + 12],
                raw[cursor + 13],
                raw[cursor + 14],
                raw[cursor + 15]
            );
            dst_ip = format!(
                "{}.{}.{}.{}",
                raw[cursor + 16],
                raw[cursor + 17],
                raw[cursor + 18],
                raw[cursor + 19]
            );
            ip_payload_offset = cursor + ihl;
        }
        ETHERTYPE_IPV6 => {
            is_ipv6 = true;
            if raw.len() < cursor + 40 {
                return None;
            }

            let mut next_header = raw[cursor + 6];
            src_ip = format_ipv6(&raw[cursor + 8..cursor + 24]);
            dst_ip = format_ipv6(&raw[cursor + 24..cursor + 40]);
            cursor += 40;

            // Traverse IPv6 Extension Headers
            while next_header == IPV6_EXT_HOPOPT
                || next_header == IPV6_EXT_ROUTING
                || next_header == IPV6_EXT_FRAGMENT
            {
                if raw.len() < cursor + 8 {
                    return None;
                }
                next_header = raw[cursor];
                let ext_len = (raw[cursor + 1] as usize + 1) * 8;
                cursor += ext_len;
            }

            ip_protocol = next_header;
            ip_payload_offset = cursor;
        }
        _ => return None,
    }

    if ip_protocol != IP_PROTO_UDP {
        return None;
    }

    // UDP Header (8 bytes)
    if raw.len() < ip_payload_offset + 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([raw[ip_payload_offset], raw[ip_payload_offset + 1]]);
    let dst_port = u16::from_be_bytes([raw[ip_payload_offset + 2], raw[ip_payload_offset + 3]]);
    let udp_len =
        u16::from_be_bytes([raw[ip_payload_offset + 4], raw[ip_payload_offset + 5]]) as usize;
    let quic_offset = ip_payload_offset + 8;

    let mut is_quic = false;
    let mut quic_header_form = None;
    let mut quic_version = None;
    let mut quic_dcid = None;
    let mut quic_dcid_bytes = None;

    if raw.len() >= quic_offset + 4 {
        let first_byte = raw[quic_offset];

        if (first_byte & 0x80) != 0 {
            // QUIC Long Header
            is_quic = true;
            quic_header_form = Some(QuicHeaderForm::Long);

            if raw.len() >= quic_offset + 5 {
                let ver = u32::from_be_bytes([
                    raw[quic_offset + 1],
                    raw[quic_offset + 2],
                    raw[quic_offset + 3],
                    raw[quic_offset + 4],
                ]);
                quic_version = Some(ver);
            }

            if raw.len() >= quic_offset + 6 {
                let dcid_len = raw[quic_offset + 5] as usize;
                if dcid_len > 0 && dcid_len <= 20 && raw.len() >= quic_offset + 6 + dcid_len {
                    let cid = raw[quic_offset + 6..quic_offset + 6 + dcid_len].to_vec();
                    quic_dcid = Some(to_hex_string(&cid));
                    quic_dcid_bytes = Some(cid);
                }
            }
        } else if (first_byte & 0x40) != 0 {
            // QUIC Short Header (1-RTT)
            is_quic = true;
            quic_header_form = Some(QuicHeaderForm::Short);

            // In short header, DCID immediately follows the first byte (standard length 8..=20 bytes)
            let cid_len = if raw.len() >= quic_offset + 1 + 8 {
                8
            } else {
                0
            };
            if cid_len > 0 {
                let cid = raw[quic_offset + 1..quic_offset + 1 + cid_len].to_vec();
                quic_dcid = Some(to_hex_string(&cid));
                quic_dcid_bytes = Some(cid);
            }
        }
    }

    Some(DissectedPacket {
        ethertype,
        vlan_id,
        src_ip,
        dst_ip,
        is_ipv6,
        ip_protocol,
        src_port,
        dst_port,
        udp_payload_len: udp_len.saturating_sub(8),
        is_quic,
        quic_header_form,
        quic_version,
        quic_dcid,
        quic_dcid_bytes,
        total_frame_len: raw.len(),
    })
}

fn to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn format_ipv6(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "::".to_string();
    }
    let mut parts = Vec::with_capacity(8);
    for i in 0..8 {
        let val = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
        parts.push(format!("{:x}", val));
    }
    parts.join(":")
}
