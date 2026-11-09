#![forbid(unsafe_code)]

//! Optical Fiber & Free-Space LEO Satellite Quantum Channel Physics.
//!
//! Models realistic quantum optics channel loss, photon attenuation, detector quantum efficiency,
//! dark count probabilities, and atmospheric beam divergence for both terrestrial fiber links
//! and satellite-to-ground downlinks.

use serde::{Deserialize, Serialize};

/// Standard single-mode fiber (SMF-28) attenuation at 1550 nm telecommunication C-band (dB/km).
pub const SMF28_ATTENUATION_DB_PER_KM: f64 = 0.20;

/// Standard InGaAs single-photon avalanche photodiode (SPAD) detector efficiency.
pub const DEFAULT_DETECTOR_EFFICIENCY: f64 = 0.85;

/// Standard detector dark count probability per gate window (~1 ns).
pub const DEFAULT_DARK_COUNT_PROBABILITY: f64 = 1.0e-6;

/// Speed of light in single-mode optical fiber core (km/s).
pub const SPEED_OF_LIGHT_IN_FIBER_KM_S: f64 = 204_000.0;

/// Type of optical quantum communication channel.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum QuantumChannelType {
    /// Terrestrial low-loss single-mode optical fiber.
    OpticalFiber { length_km: f64 },
    /// Low Earth Orbit (LEO) satellite-to-ground optical downlink.
    SatelliteDownlink {
        orbit_altitude_km: f64,
        zenith_angle_deg: f64,
    },
}

/// Optical Quantum Channel Parameters and Loss Model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumChannel {
    pub channel_type: QuantumChannelType,
    pub fiber_attenuation_db_km: f64,
    pub detector_efficiency: f64,
    pub dark_count_prob: f64,
    pub optical_error_rate: f64,
}

impl QuantumChannel {
    /// Creates a terrestrial optical fiber channel.
    pub fn terrestrial_fiber(length_km: f64) -> Self {
        Self {
            channel_type: QuantumChannelType::OpticalFiber { length_km },
            fiber_attenuation_db_km: SMF28_ATTENUATION_DB_PER_KM,
            detector_efficiency: DEFAULT_DETECTOR_EFFICIENCY,
            dark_count_prob: DEFAULT_DARK_COUNT_PROBABILITY,
            optical_error_rate: 0.015, // 1.5% optical baseline alignment error
        }
    }

    /// Creates a LEO satellite free-space optical downlink channel.
    pub fn satellite_downlink(orbit_altitude_km: f64, zenith_angle_deg: f64) -> Self {
        Self {
            channel_type: QuantumChannelType::SatelliteDownlink {
                orbit_altitude_km,
                zenith_angle_deg,
            },
            fiber_attenuation_db_km: 0.0,
            detector_efficiency: DEFAULT_DETECTOR_EFFICIENCY,
            dark_count_prob: DEFAULT_DARK_COUNT_PROBABILITY * 2.0, // background sky noise
            optical_error_rate: 0.025, // 2.5% atmospheric turbulence jitter
        }
    }

    /// Calculates total transmission loss in decibels (dB).
    pub fn total_loss_db(&self) -> f64 {
        match self.channel_type {
            QuantumChannelType::OpticalFiber { length_km } => {
                length_km * self.fiber_attenuation_db_km
            }
            QuantumChannelType::SatelliteDownlink {
                orbit_altitude_km,
                zenith_angle_deg,
            } => {
                // Free-space geometric diffraction loss + atmospheric extinction
                let zenith_rad = zenith_angle_deg.to_radians();
                let slant_distance_km = orbit_altitude_km / zenith_rad.cos().max(0.1);
                // Geometric beam divergence loss: ~30 dB at 500 km + 3 dB atmospheric attenuation
                let geo_loss = 25.0 + 10.0 * (slant_distance_km / 500.0).log10();
                geo_loss.max(20.0)
            }
        }
    }

    /// Computes channel transmittance $\eta_{channel} \in (0, 1]$.
    pub fn channel_transmittance(&self) -> f64 {
        let loss_db = self.total_loss_db();
        10.0f64.powf(-loss_db / 10.0)
    }

    /// Overall photon detection probability $\eta_{total} = \eta_{channel} \times \eta_{detector}$.
    pub fn total_detection_probability(&self) -> f64 {
        (self.channel_transmittance() * self.detector_efficiency).clamp(1.0e-7, 1.0)
    }

    /// Propagation latency in microseconds.
    pub fn propagation_delay_micros(&self) -> u64 {
        match self.channel_type {
            QuantumChannelType::OpticalFiber { length_km } => {
                let seconds = length_km / SPEED_OF_LIGHT_IN_FIBER_KM_S;
                (seconds * 1_000_000.0) as u64
            }
            QuantumChannelType::SatelliteDownlink {
                orbit_altitude_km,
                zenith_angle_deg,
            } => {
                let zenith_rad = zenith_angle_deg.to_radians();
                let slant_km = orbit_altitude_km / zenith_rad.cos().max(0.1);
                let seconds = slant_km / 300_000.0; // speed of light in vacuum
                (seconds * 1_000_000.0) as u64
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terrestrial_fiber_loss() {
        let channel = QuantumChannel::terrestrial_fiber(50.0);
        // 50 km * 0.20 dB/km = 10 dB loss
        let loss_db = channel.total_loss_db();
        assert!((loss_db - 10.0).abs() < 1e-4);

        // 10 dB loss means transmittance = 10^(-1) = 0.10
        let trans = channel.channel_transmittance();
        assert!((trans - 0.10).abs() < 1e-4);

        let delay = channel.propagation_delay_micros();
        assert!(delay > 200 && delay < 300);
    }

    #[test]
    fn test_satellite_downlink_loss() {
        let sat = QuantumChannel::satellite_downlink(500.0, 30.0);
        let loss = sat.total_loss_db();
        assert!(loss > 20.0 && loss < 40.0);
        assert!(sat.total_detection_probability() > 0.0);
    }
}

