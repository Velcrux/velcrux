//! Robust Soliton Distribution & Deterministic Degree Sampling (ADR-082).
//!
//! Implements the Robust Soliton degree distribution $\Omega(d)$ for Luby Transform
//! (LT) codes, ensuring that:
//! 1. Degree-1 symbols arrive frequently enough to kickstart the peeling decoder.
//! 2. Degrees $2..K$ arrive with optimal frequencies to prevent the ripple from stalling
//!    before all $K$ source symbols are recovered.

use super::types::FountainConfig;

/// Deterministic SplitMix64 PRNG state.
#[derive(Debug, Clone, Copy)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator.
    #[must_use]
    pub fn seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate next 64-bit unsigned integer.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    /// Generate float in range [0.0, 1.0).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Generate uniform integer in range [0, max).
    pub fn next_range(&mut self, max: usize) -> usize {
        if max <= 1 {
            return 0;
        }
        (self.next_u64() % (max as u64)) as usize
    }
}

/// Precomputed Cumulative Distribution Function (CDF) for Robust Soliton.
#[derive(Debug, Clone)]
pub struct RobustSolitonCdf {
    k: usize,
    cdf: Vec<f64>,
}

impl RobustSolitonCdf {
    /// Compute the CDF table for a given block count K and configuration parameters.
    #[must_use]
    pub fn new(k: usize, c: f64, delta: f64) -> Self {
        if k <= 1 {
            return Self {
                k: 1,
                cdf: vec![1.0],
            };
        }

        let k_f = k as f64;
        let r = c * (k_f / delta).ln() * k_f.sqrt();
        let pivot = if r > 0.0 {
            ((k_f / r).floor() as usize).min(k)
        } else {
            k
        };

        let mut probabilities = Vec::with_capacity(k);

        // Compute unnormalized probabilities: rho(i) + tau(i)
        for i in 1..=k {
            let i_f = i as f64;
            // 1. Ideal Soliton rho(i)
            let rho = if i == 1 {
                1.0 / k_f
            } else {
                1.0 / (i_f * (i_f - 1.0))
            };

            // 2. Robust addition tau(i)
            let tau = if r > 0.0 {
                if i < pivot && pivot > 0 {
                    r / (i_f * k_f)
                } else if i == pivot {
                    (r * (r / delta).ln()) / k_f
                } else {
                    0.0
                }
            } else {
                0.0
            };

            probabilities.push(rho + tau);
        }

        // Sum for normalization: beta = sum(rho + tau)
        let beta: f64 = probabilities.iter().sum();
        let mut cdf = Vec::with_capacity(k);
        let mut accum = 0.0;

        for p in probabilities {
            accum += p / beta;
            cdf.push(accum.min(1.0));
        }

        if let Some(last) = cdf.last_mut() {
            *last = 1.0;
        }

        Self { k, cdf }
    }

    /// Sample degree from a uniform random float in [0.0, 1.0).
    #[must_use]
    pub fn sample_degree(&self, rand_val: f64) -> usize {
        if self.k <= 1 {
            return 1;
        }
        for (idx, &threshold) in self.cdf.iter().enumerate() {
            if rand_val <= threshold {
                return idx + 1;
            }
        }
        self.k
    }
}

/// Deterministically compute degree and neighbor set for an Encoding Symbol ID (ESI).
#[must_use]
pub fn sample_neighbors(esi: u32, k: usize, config: &FountainConfig) -> (usize, Vec<usize>) {
    if k <= 1 {
        return (1, vec![0]);
    }

    // Systematic fast-path: the first K symbols are identical to source blocks
    if config.systematic && (esi as usize) < k {
        return (1, vec![esi as usize]);
    }

    // Seed PRNG deterministically based on ESI and K
    let seed = ((esi as u64) << 32) ^ (k as u64) ^ 0x517cc1b727220a95;
    let mut rng = SplitMix64::seed(seed);

    let cdf = RobustSolitonCdf::new(k, config.robust_c, config.robust_delta);
    let raw_degree = cdf.sample_degree(rng.next_f64());
    let degree = raw_degree.clamp(1, k);

    // Sample 'degree' distinct indices from 0..K-1
    let mut neighbors = Vec::with_capacity(degree);
    let mut pool: Vec<usize> = (0..k).collect();

    for i in 0..degree {
        let pick_idx = i + rng.next_range(k - i);
        pool.swap(i, pick_idx);
        neighbors.push(pool[i]);
    }

    neighbors.sort_unstable();
    (degree, neighbors)
}
