#![forbid(unsafe_code)]

//! Quantum Key Distribution (QKD) Optical Fiber & Satellite Entanglement Engine.
//!
//! Provides BB84 discrete-variable protocol with optical decoy-state estimation,
//! Ekert 1991 (E91) entangled photon Bell CHSH inequality testing, realistic optical fiber
//! and LEO satellite channel physics, and ETSI GS QKD 014 key management.

pub mod channel;
pub mod entanglement;
pub mod kms;
pub mod protocol;

pub use channel::{
    QuantumChannel, QuantumChannelType, DEFAULT_DARK_COUNT_PROBABILITY,
    DEFAULT_DETECTOR_EFFICIENCY, SMF28_ATTENUATION_DB_PER_KM, SPEED_OF_LIGHT_IN_FIBER_KM_S,
};

pub use protocol::{
    AlicePulse, Bb84Engine, Bb84SessionReport, BobMeasurement, DecoyIntensity, QubitBasis,
    BB84_QBER_ABORT_THRESHOLD, INTENSITY_DECOY_NU, INTENSITY_SIGNAL_MU, INTENSITY_VACUUM_OMEGA,
};

pub use entanglement::{
    E91Engine, E91SessionReport, MeasurementAngle, CHSH_CLASSICAL_LIMIT, CHSH_TSIRELSON_BOUND,
};

pub use kms::{QkdKey, QkdKeyInfo, QkdKeyStatus, QkdKeyStore, QkdProtocolType, QkdReplenisher};
