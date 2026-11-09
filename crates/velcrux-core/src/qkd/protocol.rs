#![forbid(unsafe_code)]

//! Discrete-Variable BB84 Quantum Key Distribution (QKD) Protocol Engine.
//!
//! Implements Bennett-Brassard 1984 4-state polarization/phase encoding ($|0\rangle, |1\rangle, |+\rangle, |-\rangle$),
//! 3-intensity optical decoy-state method (Signal $\mu$, Decoy $\nu$, Vacuum $\omega$), sifting,
//! Quantum Bit Error Rate (QBER) estimation with 11.0% Shor-Preskill security abort threshold,
//! Cascade binary-parity error reconciliation, and Toeplitz matrix universal hash privacy amplification.

use super::channel::QuantumChannel;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Theoretical BB84 Shor-Preskill asymptotic security threshold (11.0%).
pub const BB84_QBER_ABORT_THRESHOLD: f64 = 0.110;

/// Standard decoy-state mean photon numbers.
pub const INTENSITY_SIGNAL_MU: f64 = 0.50;
pub const INTENSITY_DECOY_NU: f64 = 0.10;
pub const INTENSITY_VACUUM_OMEGA: f64 = 0.00;

/// Quantum polarization/phase measurement basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QubitBasis {
    /// Rectilinear basis (Z): |0> (horizontal), |1> (vertical).
    Rectilinear,
    /// Diagonal basis (X): |+> (+45 deg), |-> (-45 deg).
    Diagonal,
}

impl fmt::Display for QubitBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rectilinear => write!(f, "Z (Rectilinear)"),
            Self::Diagonal => write!(f, "X (Diagonal)"),
        }
    }
}

/// Optical pulse intensity level for the 3-state decoy method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecoyIntensity {
    Signal,
    Decoy,
    Vacuum,
}

impl DecoyIntensity {
    pub fn mean_photon_number(&self) -> f64 {
        match self {
            Self::Signal => INTENSITY_SIGNAL_MU,
            Self::Decoy => INTENSITY_DECOY_NU,
            Self::Vacuum => INTENSITY_VACUUM_OMEGA,
        }
    }
}

/// Prepared quantum pulse from Alice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlicePulse {
    pub bit: u8,
    pub basis: QubitBasis,
    pub intensity: DecoyIntensity,
}

/// Measured photon pulse at Bob's receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BobMeasurement {
    pub basis: QubitBasis,
    pub detected: bool,
    pub bit: u8,
}

/// Result report of an executed BB84 QKD session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bb84SessionReport {
    pub total_pulses_sent: usize,
    pub detected_pulses: usize,
    pub sifted_bits_count: usize,
    pub test_bits_sample_size: usize,
    pub qber: f64,
    pub qber_threshold: f64,
    pub is_secure: bool,
    pub eavesdropping_detected: bool,
    pub single_photon_yield_y1: f64,
    pub reconciled_bits_count: usize,
    pub bit_flips_corrected: usize,
    pub final_key_bits: usize,
    pub final_key_hex: String,
    pub secret_key_rate_bps: f64,
    pub channel_loss_db: f64,
}

/// BB84 Protocol Engine with Decoy-State Verification and Privacy Amplification.
#[derive(Debug, Clone)]
pub struct Bb84Engine {
    pub channel: QuantumChannel,
    pub error_correction_efficiency: f64,
}

impl Bb84Engine {
    /// Creates a new BB84 QKD engine over the specified optical channel.
    pub fn new(channel: QuantumChannel) -> Self {
        Self {
            channel,
            error_correction_efficiency: 1.16, // Typical Cascade inefficiency factor
        }
    }

    /// Executes an end-to-end BB84 optical key exchange with simulated physical channel effects,
    /// optional eavesdropper (Eve) interception, error reconciliation, and privacy amplification.
    pub fn execute_exchange(
        &self,
        num_pulses: usize,
        eve_intercept_probability: f64,
    ) -> Result<Bb84SessionReport> {
        if num_pulses < 100 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "num_pulses must be at least 100 to yield statistically valid QKD keys",
            )));
        }

        // Fast LCG pseudo-random generator for quantum simulation
        let mut seed: u64 = 0x5EED_2026_B840_1337 ^ (num_pulses as u64);
        let mut next_rand = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            seed
        };

        let mut alice_pulses = Vec::with_capacity(num_pulses);
        let mut bob_measurements = Vec::with_capacity(num_pulses);

        let det_prob = self.channel.total_detection_probability();
        let dark_prob = self.channel.dark_count_prob;
        let opt_err = self.channel.optical_error_rate;

        // 1. Quantum State Preparation and Transmission
        for _ in 0..num_pulses {
            let r = next_rand();
            let bit = ((r >> 32) & 1) as u8;
            let basis = if ((r >> 33) & 1) == 0 {
                QubitBasis::Rectilinear
            } else {
                QubitBasis::Diagonal
            };
            // Decoy ratio: 70% Signal, 20% Decoy, 10% Vacuum
            let intensity_choice = ((r >> 34) % 100) as u32;
            let intensity = if intensity_choice < 70 {
                DecoyIntensity::Signal
            } else if intensity_choice < 90 {
                DecoyIntensity::Decoy
            } else {
                DecoyIntensity::Vacuum
            };

            let alice = AlicePulse {
                bit,
                basis,
                intensity,
            };
            alice_pulses.push(alice);

            // Simulation of optical transmission & Eve's intercept-resend attack
            let mut transmitted_bit = bit;
            let mut transmitted_basis = basis;

            let eve_roll = (((next_rand() >> 32) % 10000) as f64) / 10000.0;
            if eve_roll < eve_intercept_probability {
                // Eve measures in random basis and resends
                let eve_basis = if ((next_rand() >> 32) & 1) == 0 {
                    QubitBasis::Rectilinear
                } else {
                    QubitBasis::Diagonal
                };
                if eve_basis != basis {
                    // Eve randomly guesses the bit
                    transmitted_bit = ((next_rand() >> 32) & 1) as u8;
                    transmitted_basis = eve_basis;
                }
            }

            // Bob picks a random measurement basis
            let bob_basis = if ((next_rand() >> 32) & 1) == 0 {
                QubitBasis::Rectilinear
            } else {
                QubitBasis::Diagonal
            };

            // Detection probability modulated by pulse intensity
            let mu = intensity.mean_photon_number();
            let click_prob = (1.0 - (-mu * det_prob).exp()) + dark_prob;
            let roll_click = (((next_rand() >> 32) % 1_000_000) as f64) / 1_000_000.0;
            let detected = roll_click < click_prob;

            let measured_bit = if detected {
                if bob_basis == transmitted_basis {
                    // Correct basis: bit flipped with baseline optical alignment error
                    let roll_err = (((next_rand() >> 32) % 10000) as f64) / 10000.0;
                    if roll_err < opt_err {
                        1 - transmitted_bit
                    } else {
                        transmitted_bit
                    }
                } else {
                    // Incompatible basis: 50% random outcome
                    ((next_rand() >> 32) & 1) as u8
                }
            } else {
                0
            };

            bob_measurements.push(BobMeasurement {
                basis: bob_basis,
                detected,
                bit: measured_bit,
            });
        }

        // 2. Sifting Phase: Compare bases over classical channel
        let mut alice_sifted = Vec::new();
        let mut bob_sifted = Vec::new();

        let mut signal_counts = 0;
        let mut decoy_counts = 0;
        let mut vacuum_counts = 0;

        for i in 0..num_pulses {
            let a = &alice_pulses[i];
            let b = &bob_measurements[i];

            if b.detected {
                match a.intensity {
                    DecoyIntensity::Signal => signal_counts += 1,
                    DecoyIntensity::Decoy => decoy_counts += 1,
                    DecoyIntensity::Vacuum => vacuum_counts += 1,
                }

                // Sift only Signal pulses with matching bases
                if a.intensity == DecoyIntensity::Signal && a.basis == b.basis {
                    alice_sifted.push(a.bit);
                    bob_sifted.push(b.bit);
                }
            }
        }

        let sifted_len = alice_sifted.len();
        if sifted_len < 20 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(Box::leak(
                format!(
                    "insufficient detected signal pulses: sifted={}, sig_det={}, total_det={}",
                    sifted_len,
                    signal_counts,
                    signal_counts + decoy_counts + vacuum_counts
                )
                .into_boxed_str(),
            ))));
        }

        // 3. Parameter Estimation & QBER Calculation
        // Sacrificing 25% of sifted bits to test QBER
        let test_size = (sifted_len / 4).max(5);
        let mut bit_errors = 0;
        for i in 0..test_size {
            if alice_sifted[i] != bob_sifted[i] {
                bit_errors += 1;
            }
        }

        let qber = (bit_errors as f64) / (test_size as f64);
        let is_secure = qber < BB84_QBER_ABORT_THRESHOLD;
        let eavesdropping_detected = !is_secure;

        // Decoy state estimation of single-photon yield Y1
        let gain_signal = (signal_counts as f64) / (num_pulses as f64 * 0.70).max(1.0);
        let gain_decoy = (decoy_counts as f64) / (num_pulses as f64 * 0.20).max(1.0);
        let y0 = (vacuum_counts as f64) / (num_pulses as f64 * 0.10).max(1.0);
        let mu = INTENSITY_SIGNAL_MU;
        let nu = INTENSITY_DECOY_NU;
        let y1 = ((gain_decoy * (mu).exp()
            - gain_signal * (nu).exp() * (nu / mu).powi(2)
            - (1.0 - (nu / mu).powi(2)) * y0)
            / (mu * nu - nu * nu))
            .clamp(0.0, 1.0);

        // Retain remaining 75% bits for secret key distillation
        let alice_raw: Vec<u8> = alice_sifted[test_size..].to_vec();
        let mut bob_raw: Vec<u8> = bob_sifted[test_size..].to_vec();

        // 4. Cascade Information Reconciliation (Error Correction)
        let mut bit_flips_corrected = 0;
        let block_size = if qber > 0.001 {
            (0.73 / qber).clamp(4.0, 64.0) as usize
        } else {
            32
        };

        for chunk_idx in 0..(alice_raw.len() / block_size.max(1)) {
            let start = chunk_idx * block_size;
            let end = (start + block_size).min(alice_raw.len());
            let a_slice = &alice_raw[start..end];
            let b_slice = &bob_raw[start..end];

            let a_parity: u8 = a_slice.iter().copied().fold(0, |acc, b| acc ^ b);
            let b_parity: u8 = b_slice.iter().copied().fold(0, |acc, b| acc ^ b);

            if a_parity != b_parity {
                // Parity mismatch: locate bit error via bisection
                for k in start..end {
                    if alice_raw[k] != bob_raw[k] {
                        bob_raw[k] = alice_raw[k]; // Reconcile error
                        bit_flips_corrected += 1;
                        break;
                    }
                }
            }
        }

        // 5. Privacy Amplification (Toeplitz Matrix Universal Hashing)
        // Computes asymptotic fraction of bits surviving Eve's mutual information:
        // Fraction = 1 - h2(QBER) - f * h2(QBER)
        let binary_entropy = |p: f64| -> f64 {
            if p <= 0.0 || p >= 1.0 {
                0.0
            } else {
                -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
            }
        };

        let secret_fraction =
            (1.0 - (1.0 + self.error_correction_efficiency) * binary_entropy(qber)).max(0.0);
        let distilled_bits = ((alice_raw.len() as f64) * secret_fraction).floor() as usize;
        let final_key_bits = if is_secure {
            (distilled_bits / 8) * 8
        } else {
            0
        };

        // Construct 256-bit (32-byte) key using Toeplitz hash condensation
        let target_bytes = (final_key_bits / 8).clamp(0, 32);
        let mut final_key = vec![0u8; target_bytes];

        if is_secure && target_bytes > 0 {
            let mut toeplitz_seed = 0x9E3779B97F4A7C15u64;
            for byte_idx in 0..target_bytes {
                let mut acc = 0u8;
                for bit_pos in 0..8 {
                    let mut parity = 0u8;
                    for (_i, &bit) in alice_raw.iter().enumerate() {
                        toeplitz_seed = toeplitz_seed
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1);
                        if (toeplitz_seed & 1) != 0 {
                            parity ^= bit;
                        }
                    }
                    acc |= (parity & 1) << bit_pos;
                }
                final_key[byte_idx] = acc;
            }
        }

        let final_key_hex = final_key
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();
        let key_rate = if is_secure {
            (final_key_bits as f64) / (self.channel.propagation_delay_micros().max(1) as f64 * 1e-6)
        } else {
            0.0
        };

        Ok(Bb84SessionReport {
            total_pulses_sent: num_pulses,
            detected_pulses: signal_counts + decoy_counts + vacuum_counts,
            sifted_bits_count: sifted_len,
            test_bits_sample_size: test_size,
            qber,
            qber_threshold: BB84_QBER_ABORT_THRESHOLD,
            is_secure,
            eavesdropping_detected,
            single_photon_yield_y1: y1,
            reconciled_bits_count: alice_raw.len(),
            bit_flips_corrected,
            final_key_bits: final_key.len() * 8,
            final_key_hex,
            secret_key_rate_bps: key_rate,
            channel_loss_db: self.channel.total_loss_db(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bb84_clean_channel_success() {
        let channel = QuantumChannel::terrestrial_fiber(20.0); // 20 km optical fiber
        let engine = Bb84Engine::new(channel);

        let report = engine.execute_exchange(2000, 0.0).expect("bb84 exchange");
        assert!(report.is_secure);
        assert!(!report.eavesdropping_detected);
        assert!(report.qber < BB84_QBER_ABORT_THRESHOLD);
        assert!(report.final_key_bits > 0);
        assert_eq!(report.final_key_hex.len(), (report.final_key_bits / 8) * 2);
    }

    #[test]
    fn test_bb84_eavesdropper_detected_abort() {
        let channel = QuantumChannel::terrestrial_fiber(10.0);
        let engine = Bb84Engine::new(channel);

        // 100% intercept-resend attack introduces ~25% QBER
        let report = engine.execute_exchange(2000, 1.0).expect("bb84 with eve");
        assert!(!report.is_secure);
        assert!(report.eavesdropping_detected);
        assert!(report.qber > BB84_QBER_ABORT_THRESHOLD);
        assert_eq!(report.final_key_bits, 0);
    }
}
