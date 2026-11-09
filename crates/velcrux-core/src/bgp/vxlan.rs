#![forbid(unsafe_code)]

//! VXLAN (Virtual eXtensible Local Area Network) Overlay Encapsulation (RFC 7348).
//!
//! Implements pure safe-Rust 8-byte VXLAN header framing over UDP port 4789,
//! 24-bit VNI multi-tenant isolation (16.7M tenant segments), VTEP tunnel endpoint orchestration,
//! and Forwarding Database (FDB) MAC learning.

use super::evpn::MacAddress;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Standard IANA assigned UDP port for VXLAN.
pub const VXLAN_UDP_PORT: u16 = 4789;

/// Standard VXLAN header flags: I-flag (bit 3 = 0x08) indicating valid 24-bit VNI.
pub const VXLAN_FLAGS_VALID_VNI: u8 = 0x08;

/// Standard 8-byte VXLAN Header (RFC 7348 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VxlanHeader {
    /// Flags field (0x08 indicates VNI presence).
    pub flags: u8,
    /// 24-bit VXLAN Network Identifier (1..=16,777,215).
    pub vni: u32,
}

impl VxlanHeader {
    pub const SIZE_BYTES: usize = 8;

    /// Creates a standard VXLAN header for the given 24-bit VNI.
    pub fn new(vni: u32) -> Result<Self> {
        if vni > 0x00FF_FFFF {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "VNI exceeds 24-bit maximum (16,777,215)",
            )));
        }
        Ok(Self {
            flags: VXLAN_FLAGS_VALID_VNI,
            vni,
        })
    }

    /// Serializes VXLAN header to standard 8 bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE_BYTES] {
        let mut out = [0u8; Self::SIZE_BYTES];
        out[0] = self.flags;
        // out[1..4] reserved 24 bits = 0
        let vni_be = self.vni.to_be_bytes();
        out[4] = vni_be[1];
        out[5] = vni_be[2];
        out[6] = vni_be[3];
        // out[7] reserved 8 bits = 0
        out
    }

    /// Deserializes VXLAN header from 8 bytes.
    pub fn from_bytes(bytes: &[u8; Self::SIZE_BYTES]) -> Result<Self> {
        let flags = bytes[0];
        if (flags & VXLAN_FLAGS_VALID_VNI) == 0 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid VXLAN flags: I-flag bit 3 must be set",
            )));
        }
        let vni = u32::from_be_bytes([0, bytes[4], bytes[5], bytes[6]]);
        Ok(Self { flags, vni })
    }
}

/// Encapsulated VXLAN Datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VxlanDatagram {
    pub header: VxlanHeader,
    pub inner_payload: Vec<u8>,
}

impl VxlanDatagram {
    /// Encapsulates inner payload into a VXLAN packet.
    pub fn encapsulate(vni: u32, inner_payload: Vec<u8>) -> Result<Self> {
        let header = VxlanHeader::new(vni)?;
        Ok(Self {
            header,
            inner_payload,
        })
    }

    /// Serializes entire datagram (Header + Inner Payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VxlanHeader::SIZE_BYTES + self.inner_payload.len());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.inner_payload);
        out
    }

    /// Decapsulates raw datagram into header and inner payload.
    pub fn decapsulate(raw: &[u8]) -> Result<Self> {
        if raw.len() < VxlanHeader::SIZE_BYTES {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "datagram is shorter than 8-byte VXLAN header",
            )));
        }
        let mut hdr_bytes = [0u8; VxlanHeader::SIZE_BYTES];
        hdr_bytes.copy_from_slice(&raw[..VxlanHeader::SIZE_BYTES]);
        let header = VxlanHeader::from_bytes(&hdr_bytes)?;
        let inner_payload = raw[VxlanHeader::SIZE_BYTES..].to_vec();

        Ok(Self {
            header,
            inner_payload,
        })
    }
}

/// Forwarding Database (FDB) Entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdbEntry {
    pub vni: u32,
    pub mac: MacAddress,
    pub remote_vtep_ip: Ipv4Addr,
    pub last_seen_epoch_sec: u64,
}

/// VXLAN Tunnel Endpoint (VTEP) Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtepEngine {
    /// Local underlay IPv4 address of this VTEP.
    pub local_vtep_ip: Ipv4Addr,
    /// UDP listening port.
    pub udp_port: u16,
    /// Forwarding Database mapping (VNI, MAC) -> Remote VTEP IP.
    pub fdb: HashMap<(u32, MacAddress), FdbEntry>,
    /// Total packets encapsulated.
    pub packets_encapsulated: u64,
    /// Total packets decapsulated.
    pub packets_decapsulated: u64,
    /// Total bytes encapsulated.
    pub bytes_encapsulated: u64,
    /// Total bytes decapsulated.
    pub bytes_decapsulated: u64,
}

impl VtepEngine {
    /// Creates a new VTEP instance.
    pub fn new(local_vtep_ip: Ipv4Addr) -> Self {
        Self {
            local_vtep_ip,
            udp_port: VXLAN_UDP_PORT,
            fdb: HashMap::new(),
            packets_encapsulated: 0,
            packets_decapsulated: 0,
            bytes_encapsulated: 0,
            bytes_decapsulated: 0,
        }
    }

    /// Registers or statically programs an entry in the Forwarding Database (FDB).
    pub fn learn_fdb(&mut self, vni: u32, mac: MacAddress, remote_vtep: Ipv4Addr) {
        self.fdb.insert(
            (vni, mac),
            FdbEntry {
                vni,
                mac,
                remote_vtep_ip: remote_vtep,
                last_seen_epoch_sec: 1731150000,
            },
        );
    }

    /// Looks up destination VTEP IP for a given VNI and MAC.
    pub fn lookup_fdb(&self, vni: u32, mac: &MacAddress) -> Option<Ipv4Addr> {
        self.fdb.get(&(vni, *mac)).map(|e| e.remote_vtep_ip)
    }

    /// Encapsulates an inner Ethernet/IP frame for transmission to an overlay VNI.
    pub fn encapsulate(&mut self, vni: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        let datagram = VxlanDatagram::encapsulate(vni, payload)?;
        let raw = datagram.to_bytes();
        self.packets_encapsulated += 1;
        self.bytes_encapsulated += raw.len() as u64;
        Ok(raw)
    }

    /// Decapsulates an incoming VXLAN packet and returns (VNI, inner_payload).
    pub fn decapsulate(&mut self, raw: &[u8]) -> Result<(u32, Vec<u8>)> {
        let datagram = VxlanDatagram::decapsulate(raw)?;
        self.packets_decapsulated += 1;
        self.bytes_decapsulated += raw.len() as u64;
        Ok((datagram.header.vni, datagram.inner_payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vxlan_header_roundtrip() {
        let hdr = VxlanHeader::new(10050).unwrap();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], 0x08);

        let parsed = VxlanHeader::from_bytes(&bytes).expect("parse vxlan header");
        assert_eq!(hdr, parsed);
    }

    #[test]
    fn test_vxlan_datagram_encap_decap() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let mut vtep = VtepEngine::new(Ipv4Addr::new(192, 168, 10, 1));

        let encap = vtep.encapsulate(20001, payload.clone()).unwrap();
        assert_eq!(encap.len(), 8 + payload.len());

        let (vni, inner) = vtep.decapsulate(&encap).unwrap();
        assert_eq!(vni, 20001);
        assert_eq!(inner, payload);
    }

    #[test]
    fn test_fdb_mac_learning() {
        let mut vtep = VtepEngine::new(Ipv4Addr::new(10, 0, 0, 1));
        let mac = MacAddress::parse("02:00:00:AA:BB:CC").unwrap();
        let remote_ip = Ipv4Addr::new(10, 0, 0, 2);

        vtep.learn_fdb(5000, mac, remote_ip);
        assert_eq!(vtep.lookup_fdb(5000, &mac), Some(remote_ip));
        assert_eq!(vtep.lookup_fdb(5001, &mac), None);
    }
}
