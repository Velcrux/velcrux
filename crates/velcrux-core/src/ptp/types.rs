#![forbid(unsafe_code)]

//! Precision Time Protocol (IEEE 1588v2) Primitive Types & Clock State.
//!
//! Provides nanosecond timestamps, EUI-64 clock identities, clock quality specifications,
//! PTP port state machines, and clock topology definitions.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const PTP_VERSION_2: u8 = 0x02;
pub const PTP_EVENT_PORT: u16 = 319;
pub const PTP_GENERAL_PORT: u16 = 320;
pub const DEFAULT_PTP_DOMAIN: u8 = 0;

/// 8-byte Clock Identity derived from MAC-48 / EUI-64 identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClockIdentity(pub [u8; 8]);

impl ClockIdentity {
    pub fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub fn from_mac(mac: [u8; 6]) -> Self {
        // EUI-64 standard insertion of 0xFF, 0xFE in the middle
        Self([mac[0], mac[1], mac[2], 0xFF, 0xFE, mac[3], mac[4], mac[5]])
    }

    pub fn to_hex(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }
}

impl fmt::Display for ClockIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Port Identity identifying a specific physical or logical PTP port on a clock node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PortIdentity {
    pub clock_identity: ClockIdentity,
    pub port_number: u16,
}

impl PortIdentity {
    pub fn new(clock_identity: ClockIdentity, port_number: u16) -> Self {
        Self {
            clock_identity,
            port_number,
        }
    }
}

impl fmt::Display for PortIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.clock_identity, self.port_number)
    }
}

/// Nanosecond Precision PTP Timestamp (48-bit seconds + 32-bit nanoseconds).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct PtpTimestamp {
    pub seconds: u64, // Stored as 48-bit on wire (max 281 trillion seconds)
    pub nanoseconds: u32,
}

impl PtpTimestamp {
    pub fn new(seconds: u64, nanoseconds: u32) -> Self {
        Self {
            seconds: seconds + (nanoseconds as u64 / 1_000_000_000),
            nanoseconds: nanoseconds % 1_000_000_000,
        }
    }

    pub fn from_nanos_total(total_nanos: u64) -> Self {
        Self {
            seconds: total_nanos / 1_000_000_000,
            nanoseconds: (total_nanos % 1_000_000_000) as u32,
        }
    }

    pub fn to_nanos_total(&self) -> u64 {
        self.seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(self.nanoseconds as u64)
    }

    /// Calculates signed difference `self - other` in nanoseconds.
    pub fn diff_nanos(&self, other: &Self) -> i64 {
        let s_diff = (self.seconds as i64).saturating_sub(other.seconds as i64);
        let ns_diff = (self.nanoseconds as i64).saturating_sub(other.nanoseconds as i64);
        s_diff.saturating_mul(1_000_000_000).saturating_add(ns_diff)
    }

    pub fn add_nanos(&self, nanos: i64) -> Self {
        let total = self.to_nanos_total() as i128 + nanos as i128;
        let non_neg = total.max(0) as u64;
        Self::from_nanos_total(non_neg)
    }
}

impl fmt::Display for PtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}s", self.seconds, self.nanoseconds)
    }
}

/// Scaled Sub-Nanosecond Correction Field (nanoseconds multiplied by $2^{16}$).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CorrectionField(pub i64);

impl CorrectionField {
    pub fn from_nanos(nanos: f64) -> Self {
        Self((nanos * 65536.0) as i64)
    }

    pub fn to_nanos(&self) -> f64 {
        (self.0 as f64) / 65536.0
    }
}

/// Clock Quality attributes used by the Best Master Clock Algorithm (BMCA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ClockQuality {
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub offset_scaled_log_variance: u16,
}

impl Default for ClockQuality {
    fn default() -> Self {
        Self {
            clock_class: 248,     // Default slave-only / arbitrary clock
            clock_accuracy: 0xFE, // Unknown accuracy
            offset_scaled_log_variance: 0xFFFF,
        }
    }
}

impl ClockQuality {
    /// Quality parameters for a Primary Reference Clock (e.g. atomic clock / GNSS locked).
    pub fn gnss_primary() -> Self {
        Self {
            clock_class: 6,       // Synchronized to primary reference time source
            clock_accuracy: 0x21, // Accurate within 100 ns
            offset_scaled_log_variance: 0x4000,
        }
    }

    /// Quality parameters for an IEEE 1588 Telecom profile boundary clock.
    pub fn telecom_boundary() -> Self {
        Self {
            clock_class: 135,
            clock_accuracy: 0x22, // Accurate within 250 ns
            offset_scaled_log_variance: 0x4800,
        }
    }
}

/// IEEE 1588v2 PTP Port State Machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtpPortState {
    Initializing,
    Faulty,
    Disabled,
    Listening,
    PreMaster,
    Master,
    Passive,
    Uncalibrated,
    Slave,
}

impl PtpPortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initializing => "INITIALIZING",
            Self::Faulty => "FAULTY",
            Self::Disabled => "DISABLED",
            Self::Listening => "LISTENING",
            Self::PreMaster => "PRE_MASTER",
            Self::Master => "MASTER",
            Self::Passive => "PASSIVE",
            Self::Uncalibrated => "UNCALIBRATED",
            Self::Slave => "SLAVE",
        }
    }
}

/// PTP Clock Hardware & Architectural Roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PtpClockRole {
    OrdinaryClockMaster,
    OrdinaryClockSlave,
    BoundaryClock,
    TransparentClockE2E,
    TransparentClockP2P,
}

impl PtpClockRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OrdinaryClockMaster => "ORDINARY_CLOCK_MASTER",
            Self::OrdinaryClockSlave => "ORDINARY_CLOCK_SLAVE",
            Self::BoundaryClock => "BOUNDARY_CLOCK",
            Self::TransparentClockE2E => "TRANSPARENT_CLOCK_E2E",
            Self::TransparentClockP2P => "TRANSPARENT_CLOCK_P2P",
        }
    }
}

/// Phase / Frequency Synchronization Lock Status of the Clock Servo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServoLockStatus {
    Unlocked,
    Calibrating,
    LockedPhase,
    Holdover,
}

impl ServoLockStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unlocked => "UNLOCKED",
            Self::Calibrating => "CALIBRATING",
            Self::LockedPhase => "LOCKED_PHASE",
            Self::Holdover => "HOLDOVER",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_identity_eui64_from_mac() {
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let cid = ClockIdentity::from_mac(mac);
        assert_eq!(cid.0, [0x00, 0x1A, 0x2B, 0xFF, 0xFE, 0x3C, 0x4D, 0x5E]);
        assert_eq!(cid.to_hex(), "00:1A:2B:FF:FE:3C:4D:5E");
    }

    #[test]
    fn test_ptp_timestamp_math() {
        let t1 = PtpTimestamp::new(100, 500_000_000);
        let t2 = PtpTimestamp::new(101, 100_000_000);
        let diff = t2.diff_nanos(&t1);
        assert_eq!(diff, 600_000_000); // 0.6 seconds in nanos

        let added = t1.add_nanos(600_000_000);
        assert_eq!(added, t2);
    }

    #[test]
    fn test_correction_field_scaling() {
        let cf = CorrectionField::from_nanos(12.5);
        assert!((cf.to_nanos() - 12.5).abs() < 1e-4);
    }
}
