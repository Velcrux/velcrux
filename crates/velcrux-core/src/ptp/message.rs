#![forbid(unsafe_code)]

//! IEEE 1588v2 (PTP) Wire Message Framing, Encoding, and Decoding.
//!
//! Implements 34-byte common PTP header parsing and typed payloads for:
//! `Sync`, `DelayReq`, `FollowUp`, `DelayResp`, and `Announce`.

use super::types::{
    ClockIdentity, ClockQuality, CorrectionField, PortIdentity, PtpTimestamp, DEFAULT_PTP_DOMAIN,
    PTP_VERSION_2,
};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};

pub const PTP_COMMON_HEADER_LEN: usize = 34;
pub const PTP_FLAG_TWO_STEP: u16 = 0x0200;

/// Standard IEEE 1588v2 Message Types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtpMessageType {
    Sync = 0x0,
    DelayReq = 0x1,
    PdelayReq = 0x2,
    PdelayResp = 0x3,
    FollowUp = 0x8,
    DelayResp = 0x9,
    PdelayRespFollowUp = 0xA,
    Announce = 0xB,
    Signaling = 0xC,
    Management = 0xD,
}

impl PtpMessageType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v & 0x0F {
            0x0 => Ok(Self::Sync),
            0x1 => Ok(Self::DelayReq),
            0x2 => Ok(Self::PdelayReq),
            0x3 => Ok(Self::PdelayResp),
            0x8 => Ok(Self::FollowUp),
            0x9 => Ok(Self::DelayResp),
            0xA => Ok(Self::PdelayRespFollowUp),
            0xB => Ok(Self::Announce),
            0xC => Ok(Self::Signaling),
            0xD => Ok(Self::Management),
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown ptp message type",
            ))),
        }
    }
}

/// 34-byte IEEE 1588v2 Common Message Header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtpHeader {
    pub message_type: PtpMessageType,
    pub version: u8,
    pub message_length: u16,
    pub domain_number: u8,
    pub flag_field: u16,
    pub correction_field: CorrectionField,
    pub source_port_identity: PortIdentity,
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_interval: i8,
}

impl PtpHeader {
    pub fn new(
        message_type: PtpMessageType,
        message_length: u16,
        source_port: PortIdentity,
        sequence_id: u16,
    ) -> Self {
        Self {
            message_type,
            version: PTP_VERSION_2,
            message_length,
            domain_number: DEFAULT_PTP_DOMAIN,
            flag_field: PTP_FLAG_TWO_STEP,
            correction_field: CorrectionField(0),
            source_port_identity: source_port,
            sequence_id,
            control_field: match message_type {
                PtpMessageType::Sync => 0x00,
                PtpMessageType::DelayReq => 0x01,
                PtpMessageType::FollowUp => 0x02,
                PtpMessageType::DelayResp => 0x03,
                _ => 0x05,
            },
            log_message_interval: 0,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.message_type as u8 & 0x0F);
        buf.push(self.version & 0x0F);
        buf.extend_from_slice(&self.message_length.to_be_bytes());
        buf.push(self.domain_number);
        buf.push(0x00); // Reserved byte
        buf.extend_from_slice(&self.flag_field.to_be_bytes());
        buf.extend_from_slice(&self.correction_field.0.to_be_bytes());
        buf.extend_from_slice(&[0x00; 4]); // 4 reserved bytes
        buf.extend_from_slice(&self.source_port_identity.clock_identity.0);
        buf.extend_from_slice(&self.source_port_identity.port_number.to_be_bytes());
        buf.extend_from_slice(&self.sequence_id.to_be_bytes());
        buf.push(self.control_field);
        buf.push(self.log_message_interval as u8);
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < PTP_COMMON_HEADER_LEN {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "ptp frame too short for header",
            )));
        }

        let msg_type = PtpMessageType::from_u8(data[0])?;
        let version = data[1] & 0x0F;
        let message_length = u16::from_be_bytes([data[2], data[3]]);
        let domain_number = data[4];
        let flag_field = u16::from_be_bytes([data[6], data[7]]);
        let correction = i64::from_be_bytes(data[8..16].try_into().unwrap());

        let mut cid = [0u8; 8];
        cid.copy_from_slice(&data[20..28]);
        let port_number = u16::from_be_bytes([data[28], data[29]]);
        let sequence_id = u16::from_be_bytes([data[30], data[31]]);
        let control_field = data[32];
        let log_interval = data[33] as i8;

        Ok(Self {
            message_type: msg_type,
            version,
            message_length,
            domain_number,
            flag_field,
            correction_field: CorrectionField(correction),
            source_port_identity: PortIdentity::new(ClockIdentity::new(cid), port_number),
            sequence_id,
            control_field,
            log_message_interval: log_interval,
        })
    }
}

/// Announce Message Payload carrying Grandmaster Clock Quality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtpAnnounce {
    pub origin_timestamp: PtpTimestamp,
    pub current_utc_offset: i16,
    pub grandmaster_priority1: u8,
    pub grandmaster_clock_quality: ClockQuality,
    pub grandmaster_priority2: u8,
    pub grandmaster_identity: ClockIdentity,
    pub steps_removed: u16,
    pub time_source: u8,
}

impl PtpAnnounce {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encode_timestamp(&self.origin_timestamp, buf);
        buf.extend_from_slice(&self.current_utc_offset.to_be_bytes());
        buf.push(0x00); // Reserved byte
        buf.push(self.grandmaster_priority1);
        buf.push(self.grandmaster_clock_quality.clock_class);
        buf.push(self.grandmaster_clock_quality.clock_accuracy);
        buf.extend_from_slice(
            &self
                .grandmaster_clock_quality
                .offset_scaled_log_variance
                .to_be_bytes(),
        );
        buf.push(self.grandmaster_priority2);
        buf.extend_from_slice(&self.grandmaster_identity.0);
        buf.extend_from_slice(&self.steps_removed.to_be_bytes());
        buf.push(self.time_source);
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 30 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "ptp announce payload too short",
            )));
        }

        let origin_ts = decode_timestamp(&data[0..10])?;
        let utc_offset = i16::from_be_bytes([data[10], data[11]]);
        let p1 = data[13];
        let c_class = data[14];
        let c_acc = data[15];
        let variance = u16::from_be_bytes([data[16], data[17]]);
        let p2 = data[18];
        let mut gm_id = [0u8; 8];
        gm_id.copy_from_slice(&data[19..27]);
        let steps = u16::from_be_bytes([data[27], data[28]]);
        let time_source = data[29];

        Ok(Self {
            origin_timestamp: origin_ts,
            current_utc_offset: utc_offset,
            grandmaster_priority1: p1,
            grandmaster_clock_quality: ClockQuality {
                clock_class: c_class,
                clock_accuracy: c_acc,
                offset_scaled_log_variance: variance,
            },
            grandmaster_priority2: p2,
            grandmaster_identity: ClockIdentity::new(gm_id),
            steps_removed: steps,
            time_source,
        })
    }
}

/// Sync / Follow_Up / Delay_Req Timestamp Payload (10 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtpTimestampPayload {
    pub timestamp: PtpTimestamp,
}

impl PtpTimestampPayload {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encode_timestamp(&self.timestamp, buf);
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let ts = decode_timestamp(data)?;
        Ok(Self { timestamp: ts })
    }
}

/// Delay_Resp Payload (10-byte receive timestamp + 10-byte requesting port identity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtpDelayRespPayload {
    pub receive_timestamp: PtpTimestamp,
    pub requesting_port_identity: PortIdentity,
}

impl PtpDelayRespPayload {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        encode_timestamp(&self.receive_timestamp, buf);
        buf.extend_from_slice(&self.requesting_port_identity.clock_identity.0);
        buf.extend_from_slice(&self.requesting_port_identity.port_number.to_be_bytes());
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "ptp delay_resp payload too short",
            )));
        }
        let ts = decode_timestamp(&data[0..10])?;
        let mut cid = [0u8; 8];
        cid.copy_from_slice(&data[10..18]);
        let port_num = u16::from_be_bytes([data[18], data[19]]);
        Ok(Self {
            receive_timestamp: ts,
            requesting_port_identity: PortIdentity::new(ClockIdentity::new(cid), port_num),
        })
    }
}

/// Complete Typed PTP Message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtpMessage {
    Sync(PtpHeader, PtpTimestampPayload),
    DelayReq(PtpHeader, PtpTimestampPayload),
    FollowUp(PtpHeader, PtpTimestampPayload),
    DelayResp(PtpHeader, PtpDelayRespPayload),
    Announce(PtpHeader, PtpAnnounce),
}

impl PtpMessage {
    pub fn header(&self) -> &PtpHeader {
        match self {
            Self::Sync(h, _) => h,
            Self::DelayReq(h, _) => h,
            Self::FollowUp(h, _) => h,
            Self::DelayResp(h, _) => h,
            Self::Announce(h, _) => h,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Sync(h, p) => {
                h.encode(&mut buf);
                p.encode(&mut buf);
            }
            Self::DelayReq(h, p) => {
                h.encode(&mut buf);
                p.encode(&mut buf);
            }
            Self::FollowUp(h, p) => {
                h.encode(&mut buf);
                p.encode(&mut buf);
            }
            Self::DelayResp(h, p) => {
                h.encode(&mut buf);
                p.encode(&mut buf);
            }
            Self::Announce(h, p) => {
                h.encode(&mut buf);
                p.encode(&mut buf);
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = PtpHeader::decode(data)?;
        let payload_data = &data[PTP_COMMON_HEADER_LEN..];

        match header.message_type {
            PtpMessageType::Sync => {
                let payload = PtpTimestampPayload::decode(payload_data)?;
                Ok(Self::Sync(header, payload))
            }
            PtpMessageType::DelayReq => {
                let payload = PtpTimestampPayload::decode(payload_data)?;
                Ok(Self::DelayReq(header, payload))
            }
            PtpMessageType::FollowUp => {
                let payload = PtpTimestampPayload::decode(payload_data)?;
                Ok(Self::FollowUp(header, payload))
            }
            PtpMessageType::DelayResp => {
                let payload = PtpDelayRespPayload::decode(payload_data)?;
                Ok(Self::DelayResp(header, payload))
            }
            PtpMessageType::Announce => {
                let payload = PtpAnnounce::decode(payload_data)?;
                Ok(Self::Announce(header, payload))
            }
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unsupported ptp message type in decoder",
            ))),
        }
    }
}

// ---------------- Timestamp Encoding Helpers ----------------

fn encode_timestamp(ts: &PtpTimestamp, buf: &mut Vec<u8>) {
    // 48-bit seconds (6 bytes) + 32-bit nanoseconds (4 bytes)
    let s = ts.seconds;
    buf.push(((s >> 40) & 0xFF) as u8);
    buf.push(((s >> 32) & 0xFF) as u8);
    buf.push(((s >> 24) & 0xFF) as u8);
    buf.push(((s >> 16) & 0xFF) as u8);
    buf.push(((s >> 8) & 0xFF) as u8);
    buf.push((s & 0xFF) as u8);
    buf.extend_from_slice(&ts.nanoseconds.to_be_bytes());
}

fn decode_timestamp(data: &[u8]) -> Result<PtpTimestamp> {
    if data.len() < 10 {
        return Err(VelcruxError::Protocol(ProtocolError::Malformed(
            "ptp timestamp data too short (expected 10 bytes)",
        )));
    }
    let mut s = 0u64;
    for i in 0..6 {
        s = (s << 8) | (data[i] as u64);
    }
    let ns = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
    Ok(PtpTimestamp::new(s, ns))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_message_roundtrip() {
        let src = PortIdentity::new(ClockIdentity::new([1, 2, 3, 4, 5, 6, 7, 8]), 1);
        let header = PtpHeader::new(PtpMessageType::Sync, 44, src, 101);
        let payload = PtpTimestampPayload {
            timestamp: PtpTimestamp::new(1731150000, 42000),
        };
        let msg = PtpMessage::Sync(header, payload);

        let encoded = msg.encode();
        assert_eq!(encoded.len(), 44);

        let decoded = PtpMessage::decode(&encoded).expect("decode sync");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_announce_message_roundtrip() {
        let src = PortIdentity::new(ClockIdentity::new([0xAA; 8]), 2);
        let header = PtpHeader::new(PtpMessageType::Announce, 64, src, 55);
        let announce = PtpAnnounce {
            origin_timestamp: PtpTimestamp::new(1731150000, 0),
            current_utc_offset: 37,
            grandmaster_priority1: 128,
            grandmaster_clock_quality: ClockQuality::gnss_primary(),
            grandmaster_priority2: 128,
            grandmaster_identity: ClockIdentity::new([0x11; 8]),
            steps_removed: 1,
            time_source: 0x20, // GPS
        };
        let msg = PtpMessage::Announce(header, announce);

        let encoded = msg.encode();
        let decoded = PtpMessage::decode(&encoded).expect("decode announce");
        assert_eq!(decoded, msg);
    }
}
