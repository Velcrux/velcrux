//! RoCEv2 (RDMA over Converged Ethernet v2) & InfiniBand Wire Framing.
//!
//! Encapsulates InfiniBand Base Transport Headers (BTH), Extended Transport
//! Headers (RETH, AETH, ImmDt, IETH), and Invariant CRC (ICRC) over UDP port 4791.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use std::fmt;

/// Standard RoCEv2 UDP destination port assigned by IANA.
pub const ROCEV2_UDP_PORT: u16 = 4791;

/// Default InfiniBand Partition Key (P_Key) for default partition.
pub const IB_DEFAULT_PKEY: u16 = 0xFFFF;

/// InfiniBand Transport Header Version.
pub const IB_TVER: u8 = 0;

/// RoCEv2 / InfiniBand Base Transport Opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BthOpcode {
    // Reliable Connected (RC) Opcodes
    RcSendFirst = 0x00,
    RcSendMiddle = 0x01,
    RcSendLast = 0x02,
    RcSendLastWithImm = 0x03,
    RcSendOnly = 0x04,
    RcSendOnlyWithImm = 0x05,
    RcRdmaWriteFirst = 0x06,
    RcRdmaWriteMiddle = 0x07,
    RcRdmaWriteLast = 0x08,
    RcRdmaWriteLastWithImm = 0x09,
    RcRdmaWriteOnly = 0x0A,
    RcRdmaWriteOnlyWithImm = 0x0B,
    RcRdmaReadRequest = 0x0C,
    RcRdmaReadResponseFirst = 0x0D,
    RcRdmaReadResponseMiddle = 0x0E,
    RcRdmaReadResponseLast = 0x0F,
    RcRdmaReadResponseOnly = 0x10,
    RcAck = 0x11,
    RcAtomicAck = 0x12,
    RcCmpSwap = 0x13,
    RcFetchAdd = 0x14,

    // Unreliable Datagram (UD) Opcodes
    UdSendOnly = 0x64,
    UdSendOnlyWithImm = 0x65,

    // Congestion Notification Packet (CNP) for DCQCN
    Cnp = 0x81,

    // Unknown or vendor opcode
    Unknown = 0xFF,
}

impl From<u8> for BthOpcode {
    fn from(val: u8) -> Self {
        match val {
            0x00 => BthOpcode::RcSendFirst,
            0x01 => BthOpcode::RcSendMiddle,
            0x02 => BthOpcode::RcSendLast,
            0x03 => BthOpcode::RcSendLastWithImm,
            0x04 => BthOpcode::RcSendOnly,
            0x05 => BthOpcode::RcSendOnlyWithImm,
            0x06 => BthOpcode::RcRdmaWriteFirst,
            0x07 => BthOpcode::RcRdmaWriteMiddle,
            0x08 => BthOpcode::RcRdmaWriteLast,
            0x09 => BthOpcode::RcRdmaWriteLastWithImm,
            0x0A => BthOpcode::RcRdmaWriteOnly,
            0x0B => BthOpcode::RcRdmaWriteOnlyWithImm,
            0x0C => BthOpcode::RcRdmaReadRequest,
            0x0D => BthOpcode::RcRdmaReadResponseFirst,
            0x0E => BthOpcode::RcRdmaReadResponseMiddle,
            0x0F => BthOpcode::RcRdmaReadResponseLast,
            0x10 => BthOpcode::RcRdmaReadResponseOnly,
            0x11 => BthOpcode::RcAck,
            0x12 => BthOpcode::RcAtomicAck,
            0x13 => BthOpcode::RcCmpSwap,
            0x14 => BthOpcode::RcFetchAdd,
            0x64 => BthOpcode::UdSendOnly,
            0x65 => BthOpcode::UdSendOnlyWithImm,
            0x81 => BthOpcode::Cnp,
            _ => BthOpcode::Unknown,
        }
    }
}

impl BthOpcode {
    /// Returns true if this opcode carries immediate data (ImmDt).
    pub fn has_immediate(&self) -> bool {
        matches!(
            self,
            BthOpcode::RcSendLastWithImm
                | BthOpcode::RcSendOnlyWithImm
                | BthOpcode::RcRdmaWriteLastWithImm
                | BthOpcode::RcRdmaWriteOnlyWithImm
                | BthOpcode::UdSendOnlyWithImm
        )
    }

    /// Returns true if this opcode carries an RDMA Extended Transport Header (RETH).
    pub fn has_reth(&self) -> bool {
        matches!(
            self,
            BthOpcode::RcRdmaWriteFirst
                | BthOpcode::RcRdmaWriteOnly
                | BthOpcode::RcRdmaWriteOnlyWithImm
                | BthOpcode::RcRdmaReadRequest
        )
    }

    /// Returns true if this opcode is an ACK carrying an AETH.
    pub fn has_aeth(&self) -> bool {
        matches!(
            self,
            BthOpcode::RcAck
                | BthOpcode::RcRdmaReadResponseFirst
                | BthOpcode::RcRdmaReadResponseLast
                | BthOpcode::RcRdmaReadResponseOnly
                | BthOpcode::RcAtomicAck
        )
    }
}

/// InfiniBand Base Transport Header (BTH) - 12 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bth {
    /// Operation code.
    pub opcode: BthOpcode,
    /// Solicited Event flag: triggers completion notification on receiver.
    pub solicited: bool,
    /// Migration request bit for Alternate Path.
    pub mig_req: bool,
    /// Pad count (0..=3 bytes) added to end of payload.
    pub pad_count: u8,
    /// Transport Header Version (always 0).
    pub tver: u8,
    /// Partition Key.
    pub pkey: u16,
    /// Destination Queue Pair number (24 bits).
    pub dest_qp: u32,
    /// Acknowledge Request flag: prompts receiver to respond with ACK.
    pub ack_req: bool,
    /// Packet Sequence Number (24 bits).
    pub psn: u32,
}

impl Bth {
    pub const LEN: usize = 12;

    /// Parse BTH from a 12-byte slice.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }

        let opcode = BthOpcode::from(buf[0]);
        let solicited = (buf[1] & 0x80) != 0;
        let mig_req = (buf[1] & 0x40) != 0;
        let pad_count = (buf[1] >> 4) & 0x03;
        let tver = buf[1] & 0x0F;

        let pkey = u16::from_be_bytes([buf[2], buf[3]]);

        // Destination QP is 24 bits in buf[5..8]
        let dest_qp = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]);

        let ack_req = (buf[8] & 0x80) != 0;
        // PSN is 24 bits in buf[9..12]
        let psn = u32::from_be_bytes([0, buf[9], buf[10], buf[11]]);

        Some(Self {
            opcode,
            solicited,
            mig_req,
            pad_count,
            tver,
            pkey,
            dest_qp,
            ack_req,
            psn,
        })
    }

    /// Serialize BTH into a 12-byte vector.
    pub fn serialize(&self) -> [u8; Self::LEN] {
        let mut buf = [0u8; Self::LEN];
        buf[0] = self.opcode as u8;

        let mut b1 = self.tver & 0x0F;
        b1 |= (self.pad_count & 0x03) << 4;
        if self.mig_req {
            b1 |= 0x40;
        }
        if self.solicited {
            b1 |= 0x80;
        }
        buf[1] = b1;

        let pkey_bytes = self.pkey.to_be_bytes();
        buf[2] = pkey_bytes[0];
        buf[3] = pkey_bytes[1];

        // Reserved byte at index 4 (0x00)
        buf[4] = 0;

        // Destination QP (24 bits)
        let qp_bytes = self.dest_qp.to_be_bytes();
        buf[5] = qp_bytes[1];
        buf[6] = qp_bytes[2];
        buf[7] = qp_bytes[3];

        // Ack Request + reserved
        buf[8] = if self.ack_req { 0x80 } else { 0x00 };

        // PSN (24 bits)
        let psn_bytes = self.psn.to_be_bytes();
        buf[9] = psn_bytes[1];
        buf[10] = psn_bytes[2];
        buf[11] = psn_bytes[3];

        buf
    }
}

/// RDMA Extended Transport Header (RETH) - 16 bytes.
///
/// Used in RDMA Write and RDMA Read requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reth {
    /// Virtual address of remote target memory.
    pub va: u64,
    /// Remote Memory Key granting permission.
    pub rkey: u32,
    /// Total DMA length in bytes.
    pub dma_len: u32,
}

impl Reth {
    pub const LEN: usize = 16;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }

        let va = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let rkey = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let dma_len = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        Some(Self { va, rkey, dma_len })
    }

    pub fn serialize(&self) -> [u8; Self::LEN] {
        let mut buf = [0u8; Self::LEN];
        buf[0..8].copy_from_slice(&self.va.to_be_bytes());
        buf[8..12].copy_from_slice(&self.rkey.to_be_bytes());
        buf[12..16].copy_from_slice(&self.dma_len.to_be_bytes());
        buf
    }
}

/// ACK Extended Transport Header (AETH) - 4 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aeth {
    /// Syndrome code (ACK, RNR retry delay, or NAK).
    pub syndrome: u8,
    /// Message Sequence Number (24 bits).
    pub msn: u32,
}

impl Aeth {
    pub const LEN: usize = 4;

    /// Normal ACK syndrome (Credit count = 0x1F max).
    pub const SYNDROME_ACK: u8 = 0x00;
    /// Receiver Not Ready (RNR) syndrome prefix.
    pub const SYNDROME_RNR_MASK: u8 = 0x20;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }

        let syndrome = buf[0];
        let msn = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]);

        Some(Self { syndrome, msn })
    }

    pub fn serialize(&self) -> [u8; Self::LEN] {
        let mut buf = [0u8; Self::LEN];
        buf[0] = self.syndrome;
        let msn_bytes = self.msn.to_be_bytes();
        buf[1] = msn_bytes[1];
        buf[2] = msn_bytes[2];
        buf[3] = msn_bytes[3];
        buf
    }

    /// Returns true if this AETH indicates normal acknowledgment.
    pub fn is_ack(&self) -> bool {
        (self.syndrome & 0xE0) == 0x00
    }

    /// Returns true if this AETH indicates Receiver Not Ready (RNR).
    pub fn is_rnr(&self) -> bool {
        (self.syndrome & 0xE0) == Self::SYNDROME_RNR_MASK
    }
}

/// Immediate Data Header (ImmDt) - 4 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImmDt {
    /// 32-bit immediate data payload in network byte order.
    pub data: u32,
}

impl ImmDt {
    pub const LEN: usize = 4;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        let data = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Some(Self { data })
    }

    pub fn serialize(&self) -> [u8; Self::LEN] {
        self.data.to_be_bytes()
    }
}

/// Invalidate Extended Transport Header (IETH) - 4 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ieth {
    /// Remote key (`rkey`) to be invalidated.
    pub rkey: u32,
}

impl Ieth {
    pub const LEN: usize = 4;

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::LEN {
            return None;
        }
        let rkey = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Some(Self { rkey })
    }

    pub fn serialize(&self) -> [u8; Self::LEN] {
        self.rkey.to_be_bytes()
    }
}

/// Invariant CRC (ICRC) calculator.
///
/// Computes the 32-bit CRC over invariant packet fields per InfiniBand Architecture
/// Specification Vol 1, Section 7.8.
pub fn calculate_icrc(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            if (crc & 0x80000000) != 0 {
                crc = (crc << 1) ^ 0x04C11DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    !crc
}

/// Fully decoded RoCEv2 / InfiniBand Packet Frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RocePacket {
    /// Base Transport Header.
    pub bth: Bth,
    /// Optional RDMA Extended Transport Header.
    pub reth: Option<Reth>,
    /// Optional ACK Extended Transport Header.
    pub aeth: Option<Aeth>,
    /// Optional Immediate Data.
    pub imm: Option<ImmDt>,
    /// Optional Invalidation Header.
    pub ieth: Option<Ieth>,
    /// Application payload bytes.
    pub payload: Vec<u8>,
    /// Invariant CRC (32-bit).
    pub icrc: u32,
}

impl RocePacket {
    /// Dissect a raw RoCEv2 UDP payload (starting directly at the BTH).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Bth::LEN + 4 {
            // Must contain at least BTH (12) + ICRC (4)
            return None;
        }

        let bth = Bth::parse(&buf[0..Bth::LEN])?;
        let mut offset = Bth::LEN;

        let mut reth = None;
        let mut aeth = None;
        let mut imm = None;
        let ieth = None;

        if bth.opcode.has_reth() {
            if buf.len() < offset + Reth::LEN + 4 {
                return None;
            }
            reth = Reth::parse(&buf[offset..offset + Reth::LEN]);
            offset += Reth::LEN;
        }

        if bth.opcode.has_aeth() {
            if buf.len() < offset + Aeth::LEN + 4 {
                return None;
            }
            aeth = Aeth::parse(&buf[offset..offset + Aeth::LEN]);
            offset += Aeth::LEN;
        }

        if bth.opcode.has_immediate() {
            if buf.len() < offset + ImmDt::LEN + 4 {
                return None;
            }
            imm = ImmDt::parse(&buf[offset..offset + ImmDt::LEN]);
            offset += ImmDt::LEN;
        }

        if bth.opcode == BthOpcode::RcSendLastWithImm || bth.opcode == BthOpcode::RcSendOnlyWithImm
        {
            // If opcode is send with invalidate, ieth might follow, but immediate takes precedence
        }

        // The last 4 bytes are the ICRC
        let icrc_offset = buf.len() - 4;
        if offset > icrc_offset {
            return None;
        }

        let payload_len = icrc_offset - offset;
        let pad_len = bth.pad_count as usize;
        let actual_payload_len = payload_len.saturating_sub(pad_len);

        let payload = buf[offset..offset + actual_payload_len].to_vec();
        let icrc = u32::from_be_bytes([
            buf[icrc_offset],
            buf[icrc_offset + 1],
            buf[icrc_offset + 2],
            buf[icrc_offset + 3],
        ]);

        Some(Self {
            bth,
            reth,
            aeth,
            imm,
            ieth,
            payload,
            icrc,
        })
    }

    /// Serialize this RoCEv2 packet frame into wire format with ICRC appended.
    pub fn serialize(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(64 + self.payload.len());
        frame.extend_from_slice(&self.bth.serialize());

        if let Some(ref r) = self.reth {
            frame.extend_from_slice(&r.serialize());
        }
        if let Some(ref a) = self.aeth {
            frame.extend_from_slice(&a.serialize());
        }
        if let Some(ref im) = self.imm {
            frame.extend_from_slice(&im.serialize());
        }
        if let Some(ref ie) = self.ieth {
            frame.extend_from_slice(&ie.serialize());
        }

        frame.extend_from_slice(&self.payload);

        // Add padding bytes if requested
        for _ in 0..self.bth.pad_count {
            frame.push(0x00);
        }

        // Calculate and append ICRC
        let icrc = calculate_icrc(&frame);
        frame.extend_from_slice(&icrc.to_be_bytes());

        frame
    }
}

impl fmt::Display for RocePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RocePacket(Opcode={:?}, DestQP={}, PSN={}, Payload={}B, Imm={:?})",
            self.bth.opcode,
            self.bth.dest_qp,
            self.bth.psn,
            self.payload.len(),
            self.imm.map(|i| i.data)
        )
    }
}
