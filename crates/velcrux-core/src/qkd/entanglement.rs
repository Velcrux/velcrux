#![forbid(unsafe_code)]

//! Ekert 1991 (E91) Entangled-Photon QKD Protocol Engine & Bell CHSH Verification.
//!
//! Implements Einstein-Podolsky-Rosen (EPR) entangled Bell state $|\Phi^+\rangle$ generation,
//! 3-angle basis selection for Alice ($a_1=0^\circ, a_2=45^\circ, a_3=90^\circ$) and Bob
//! ($b_1=45^\circ, b_2=90^\circ, b_3=135^\circ$), Clauser-Horne-Shimony-Holt (CHSH)
//! inequality evaluation ($S \le 2$ classical limit vs $S \le 2\sqrt{2}$ quantum limit),
//! and matching-angle key extraction.

use super::channel::QuantumChannel;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};

/// Classical Bell inequality limit (Local Hidden Variable limit).
pub const CHSH_CLASSICAL_LIMIT: f64 = 2.000;

/// Maximum quantum mechanical correlation limit (Tsirelson's bound: $2\sqrt{2} \approx 2.8284$).
pub const CHSH_TSIRELSON_BOUND: f64 = 2.8284;

/// Measurement basis angle in degrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeasurementAngle {
    Deg0,
    Deg22_5,
    Deg45,
    Deg67_5,
    Deg90,
}

impl MeasurementAngle {
    pub fn to_radians(self) -> f64 {
        match self {
            Self::Deg0 => 0.0,
            Self::Deg22_5 => std::f64::consts::FRAC_PI_8,
            Self::Deg45 => std::f64::consts::FRAC_PI_4,
            Self::Deg67_5 => 3.0 * std::f64::consts::FRAC_PI_8,
            Self::Deg90 => std::f64::consts::FRAC_PI_2,
        }
    }
}

/// Result report of an executed E91 Entangled-Photon session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E91SessionReport {
    pub total_bell_pairs: usize,
    pub detected_coincidences: usize,
    pub correlation_a1_b1: f64,
    pub correlation_a1_b3: f64,
    pub correlation_a3_b1: f64,
    pub correlation_a3_b3: f64,
    pub chsh_s_value: f64,
    pub chsh_classical_limit: f64,
    pub bell_inequality_violated: bool,
    pub is_entanglement_verified: bool,
    pub sifted_key_bits: usize,
    pub final_key_hex: String,
    pub channel_loss_db: f64,
}

/// E91 Entanglement-Based Protocol Engine.
#[derive(Debug, Clone)]
pub struct E91Engine {
    pub channel: QuantumChannel,
}

impl E91Engine {
    /// Creates a new E91 engine.
    pub fn new(channel: QuantumChannel) -> Self {
        Self { channel }
    }

    /// Executes an E91 entangled photon exchange.
    pub fn execute_exchange(
        &self,
        num_pairs: usize,
        eve_decoherence_prob: f64,
    ) -> Result<E91SessionReport> {
        if num_pairs < 200 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "num_pairs must be at least 200 for CHSH statistical significance",
            )));
        }

        let mut seed: u64 = 0xEE91_2026_CAFE_BABE ^ (num_pairs as u64);
        let mut next_rand = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            seed
        };

        let alice_angles = [
            MeasurementAngle::Deg0,
            MeasurementAngle::Deg45,
            MeasurementAngle::Deg90,
        ];
        let bob_angles = [
            MeasurementAngle::Deg22_5,
            MeasurementAngle::Deg45,
            MeasurementAngle::Deg67_5,
        ];

        let det_prob = self.channel.total_detection_probability();

        let mut a1_b1_matches = (0i64, 0usize);
        let mut a1_b3_matches = (0i64, 0usize);
        let mut a3_b1_matches = (0i64, 0usize);
        let mut a3_b3_matches = (0i64, 0usize);

        let mut raw_key_alice = Vec::new();
        let mut raw_key_bob = Vec::new();

        let mut total_coincidences = 0;

        for _ in 0..num_pairs {
            // Both photons must reach detectors (coincidence detection)
            let roll_click_a = (((next_rand() >> 32) % 1_000_000) as f64) / 1_000_000.0;
            let roll_click_b = (((next_rand() >> 32) % 1_000_000) as f64) / 1_000_000.0;
            if roll_click_a > det_prob || roll_click_b > det_prob {
                continue;
            }

            total_coincidences += 1;

            let a_idx = ((next_rand() >> 32) % 3) as usize;
            let b_idx = ((next_rand() >> 32) % 3) as usize;
            let angle_a = alice_angles[a_idx];
            let angle_b = bob_angles[b_idx];

            let eve_roll = (((next_rand() >> 32) % 10000) as f64) / 10000.0;
            let is_decohered = eve_roll < eve_decoherence_prob;

            // Quantum correlation expectation on Bell state |Phi+>:
            // E(theta_a, theta_b) = cos(2 * (theta_a - theta_b))
            let (bit_a, bit_b) = if is_decohered {
                // Completely disentangled (local hidden variable / classical noise)
                let bit = ((next_rand() >> 32) & 1) as u8;
                (bit, ((next_rand() >> 32) & 1) as u8)
            } else {
                let diff_rad = angle_a.to_radians() - angle_b.to_radians();
                let correlation = (2.0 * diff_rad).cos();
                let prob_same = (1.0 + correlation) / 2.0;

                let roll_same = (((next_rand() >> 32) % 1_000_000) as f64) / 1_000_000.0;
                let bit_alice = ((next_rand() >> 32) & 1) as u8;
                let bit_bob = if roll_same < prob_same {
                    bit_alice
                } else {
                    1 - bit_alice
                };
                (bit_alice, bit_bob)
            };

            let val = if bit_a == bit_b { 1i64 } else { -1i64 };

            // Categorize into CHSH correlation pairs
            match (angle_a, angle_b) {
                (MeasurementAngle::Deg0, MeasurementAngle::Deg22_5) => {
                    a1_b1_matches.0 += val;
                    a1_b1_matches.1 += 1;
                }
                (MeasurementAngle::Deg0, MeasurementAngle::Deg67_5) => {
                    a1_b3_matches.0 += val;
                    a1_b3_matches.1 += 1;
                }
                (MeasurementAngle::Deg90, MeasurementAngle::Deg22_5) => {
                    a3_b1_matches.0 += val;
                    a3_b1_matches.1 += 1;
                }
                (MeasurementAngle::Deg90, MeasurementAngle::Deg67_5) => {
                    a3_b3_matches.0 += val;
                    a3_b3_matches.1 += 1;
                }
                // Key generation matching angle: (45 deg, 45 deg)
                (MeasurementAngle::Deg45, MeasurementAngle::Deg45) => {
                    raw_key_alice.push(bit_a);
                    raw_key_bob.push(bit_b);
                }
                _ => {}
            }
        }

        let calc_e = |(sum, count): (i64, usize)| -> f64 {
            if count == 0 {
                0.0
            } else {
                (sum as f64) / (count as f64)
            }
        };

        let e_a1_b1 = calc_e(a1_b1_matches);
        let e_a1_b3 = calc_e(a1_b3_matches);
        let e_a3_b1 = calc_e(a3_b1_matches);
        let e_a3_b3 = calc_e(a3_b3_matches);

        // Standard CHSH parameter: S = |E(a1,b1) - E(a1,b3) + E(a3,b3) - E(a3,b1)|
        let chsh_s = (e_a1_b1 - e_a1_b3 + e_a3_b3 - e_a3_b1).abs();
        let bell_violated = chsh_s > CHSH_CLASSICAL_LIMIT;
        let is_verified = bell_violated && chsh_s >= 2.10;

        // Distill key if entanglement is verified
        let key_bytes_len = if is_verified {
            (raw_key_alice.len() / 8).min(32)
        } else {
            0
        };
        let mut final_key = vec![0u8; key_bytes_len];

        for i in 0..key_bytes_len {
            let mut byte = 0u8;
            for bit_pos in 0..8 {
                let bit = raw_key_alice[i * 8 + bit_pos];
                byte |= (bit & 1) << bit_pos;
            }
            final_key[i] = byte;
        }

        let final_key_hex = final_key
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        Ok(E91SessionReport {
            total_bell_pairs: num_pairs,
            detected_coincidences: total_coincidences,
            correlation_a1_b1: e_a1_b1,
            correlation_a1_b3: e_a1_b3,
            correlation_a3_b1: e_a3_b1,
            correlation_a3_b3: e_a3_b3,
            chsh_s_value: chsh_s,
            chsh_classical_limit: CHSH_CLASSICAL_LIMIT,
            bell_inequality_violated: bell_violated,
            is_entanglement_verified: is_verified,
            sifted_key_bits: raw_key_alice.len(),
            final_key_hex,
            channel_loss_db: self.channel.total_loss_db(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e91_bell_inequality_violation() {
        let channel = QuantumChannel::terrestrial_fiber(5.0);
        let engine = E91Engine::new(channel);

        // Clean quantum channel must violate classical Bell inequality (S > 2.0)
        let report = engine.execute_exchange(3000, 0.0).expect("e91 clean");
        assert!(report.bell_inequality_violated);
        assert!(report.is_entanglement_verified);
        assert!(report.chsh_s_value > 2.0);
        assert!(report.chsh_s_value <= 3.5);
        assert!(report.final_key_hex.len() > 0);
    }

    #[test]
    fn test_e91_decoherence_aborts() {
        let channel = QuantumChannel::terrestrial_fiber(5.0);
        let engine = E91Engine::new(channel);

        // 100% decoherence / classical eavesdropper enforces S <= 2.0
        let report = engine.execute_exchange(3000, 1.0).expect("e91 decohered");
        assert!(!report.is_entanglement_verified);
        assert!(report.chsh_s_value <= CHSH_CLASSICAL_LIMIT + 0.1);
        assert_eq!(report.final_key_hex.len(), 0);
    }
}
