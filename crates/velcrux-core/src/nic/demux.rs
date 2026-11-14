//! Wire-Speed Packet Demuxer & QUIC Header Classification (ADR-083).
//!
//! Inspects L2 Ethernet, L3 IPv4/IPv6, L4 UDP, and L7 QUIC headers directly
//! inside UMEM frame buffers without copying packet payload.

#![forbid(unsafe_code)]

use super::types::{NicError, NicQuicHeaderForm, NicQuicPacketView, NicResult};

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_QINQ: u16 = 0x88A8;
pub const IP_PROTO_UDP: u8 = 17;

/// Zero-copy parser dissecting raw network frames into structured QUIC views.
pub struct NicPacketDemuxer;

impl NicPacketDemuxer {
    /// Dissect raw frame buffer into a `NicQuicPacketView`.
    pub fn parse_frame(frame_index: usize, data: &[u8]) -> NicResult<NicQuicPacketView> {
        if data.len() < 14 {
            return Err(NicError::ParseError(
                "Packet smaller than Ethernet header".to_string(),
            ));
        }

        let mut offset = 0;
        let eth_offset = 0;

        // 1. Parse Ethernet Header
        let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
        offset += 14;

        // Handle single 802.1Q VLAN tag
        if ethertype == ETH_P_8021Q && offset + 4 <= data.len() {
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        }

        // Handle double QinQ VLAN tag
        if ethertype == ETH_P_QINQ && offset + 4 <= data.len() {
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        }

        let ip_offset = offset;
        let (src_ip, dst_ip, l4_proto, ip_hdr_len) = match ethertype {
            ETH_P_IP => {
                if offset + 20 > data.len() {
                    return Err(NicError::ParseError("Truncated IPv4 header".to_string()));
                }
                let ihl = (data[offset] & 0x0F) as usize * 4;
                if ihl < 20 || offset + ihl > data.len() {
                    return Err(NicError::ParseError("Invalid IPv4 IHL".to_string()));
                }
                let proto = data[offset + 9];
                let src = format!(
                    "{}.{}.{}.{}",
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15]
                );
                let dst = format!(
                    "{}.{}.{}.{}",
                    data[offset + 16],
                    data[offset + 17],
                    data[offset + 18],
                    data[offset + 19]
                );
                (src, dst, proto, ihl)
            }
            ETH_P_IPV6 => {
                if offset + 40 > data.len() {
                    return Err(NicError::ParseError("Truncated IPv6 header".to_string()));
                }
                let proto = data[offset + 6];
                let src = Self::format_ipv6(&data[offset + 8..offset + 24]);
                let dst = Self::format_ipv6(&data[offset + 24..offset + 40]);
                (src, dst, proto, 40)
            }
            other => {
                return Err(NicError::ParseError(format!(
                    "Unsupported EtherType: 0x{:04x}",
                    other
                )));
            }
        };

        if l4_proto != IP_PROTO_UDP {
            return Err(NicError::ParseError(format!(
                "Non-UDP transport protocol: {}",
                l4_proto
            )));
        }

        offset += ip_hdr_len;
        let udp_offset = offset;

        // 2. Parse UDP Header (8 bytes)
        if offset + 8 > data.len() {
            return Err(NicError::ParseError("Truncated UDP header".to_string()));
        }

        let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let udp_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;
        offset += 8;

        let quic_offset = offset;
        let quic_len = if udp_len >= 8 && udp_offset + udp_len <= data.len() {
            udp_len - 8
        } else {
            data.len().saturating_sub(offset)
        };

        if quic_len < 1 {
            return Err(NicError::ParseError("Empty UDP/QUIC payload".to_string()));
        }

        // 3. Parse QUIC Wire Header (RFC 9000)
        let first_byte = data[quic_offset];
        let is_long_header = (first_byte & 0x80) != 0;

        let (header_form, dcid_hex, scid_hex) = if is_long_header {
            if quic_len < 7 {
                return Err(NicError::ParseError(
                    "Truncated QUIC Long Header".to_string(),
                ));
            }
            let version = u32::from_be_bytes([
                data[quic_offset + 1],
                data[quic_offset + 2],
                data[quic_offset + 3],
                data[quic_offset + 4],
            ]);
            let packet_type = (first_byte >> 4) & 0x03;

            let mut cur = quic_offset + 5;
            let dcid_len = data[cur] as usize;
            cur += 1;
            if cur + dcid_len > data.len() {
                return Err(NicError::ParseError(
                    "Truncated QUIC Long Header DCID".to_string(),
                ));
            }
            let dcid = hex_encode(&data[cur..cur + dcid_len]);
            cur += dcid_len;

            if cur >= data.len() {
                return Err(NicError::ParseError(
                    "Truncated QUIC Long Header SCID len".to_string(),
                ));
            }
            let scid_len = data[cur] as usize;
            cur += 1;
            if cur + scid_len > data.len() {
                return Err(NicError::ParseError(
                    "Truncated QUIC Long Header SCID".to_string(),
                ));
            }
            let scid = hex_encode(&data[cur..cur + scid_len]);

            (
                NicQuicHeaderForm::LongHeader {
                    packet_type,
                    version,
                },
                dcid,
                Some(scid),
            )
        } else {
            // Short Header: 1-RTT application data
            let spin_bit = (first_byte & 0x20) != 0;
            let key_phase = (first_byte & 0x04) != 0;

            // In short header, DCID length is agreed upon during handshake (standard default: 8 or 16 bytes).
            // We extract up to 8 bytes or available bytes.
            let dcid_bytes_to_read = 8.min(quic_len.saturating_sub(1));
            let dcid = hex_encode(&data[quic_offset + 1..quic_offset + 1 + dcid_bytes_to_read]);

            (
                NicQuicHeaderForm::ShortHeader {
                    spin_bit,
                    key_phase,
                },
                dcid,
                None,
            )
        };

        Ok(NicQuicPacketView {
            frame_index,
            eth_offset,
            ip_offset,
            udp_offset,
            quic_offset,
            quic_len,
            src_addr: format!("{}:{}", src_ip, src_port),
            dst_addr: format!("{}:{}", dst_ip, dst_port),
            dcid_hex,
            scid_hex,
            header_form,
        })
    }

    fn format_ipv6(bytes: &[u8]) -> String {
        let mut parts = Vec::with_capacity(8);
        for chunk in bytes.chunks_exact(2) {
            parts.push(format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])));
        }
        parts.join(":")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}
