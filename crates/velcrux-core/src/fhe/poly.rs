//! Cyclotomic Polynomial Ring Arithmetic over $R_q = \mathbb{Z}_q[X]/(X^N + 1)$ (ADR-084).
//!
//! Implements exact negacyclic polynomial convolution, modulo addition, subtraction,
//! and discrete Gaussian/ternary sampling under `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use super::types::{FheError, FheResult, Polynomial};

/// Negacyclic polynomial arithmetic engine over $\mathbb{Z}_q[X] / (X^N + 1)$.
pub struct PolyRing;

impl PolyRing {
    /// Add two polynomials coefficient-wise modulo $q$.
    pub fn add(a: &Polynomial, b: &Polynomial, q: u64) -> FheResult<Polynomial> {
        if a.degree() != b.degree() {
            return Err(FheError::DegreeMismatch {
                expected: a.degree(),
                actual: b.degree(),
            });
        }
        let n = a.degree();
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            coeffs.push(((a.coeffs[i] as u128 + b.coeffs[i] as u128) % q as u128) as u64);
        }
        Ok(Polynomial { coeffs })
    }

    /// Subtract polynomial $b$ from $a$ coefficient-wise modulo $q$.
    pub fn sub(a: &Polynomial, b: &Polynomial, q: u64) -> FheResult<Polynomial> {
        if a.degree() != b.degree() {
            return Err(FheError::DegreeMismatch {
                expected: a.degree(),
                actual: b.degree(),
            });
        }
        let n = a.degree();
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            let diff = if a.coeffs[i] >= b.coeffs[i] {
                a.coeffs[i] - b.coeffs[i]
            } else {
                q - (b.coeffs[i] - a.coeffs[i])
            };
            coeffs.push(diff % q);
        }
        Ok(Polynomial { coeffs })
    }

    /// Multiply a polynomial by a scalar modulo $q$.
    #[must_use]
    pub fn mul_scalar(a: &Polynomial, scalar: u64, q: u64) -> Polynomial {
        let n = a.degree();
        let mut coeffs = Vec::with_capacity(n);
        let s = scalar as u128;
        let q_u128 = q as u128;
        for &c in &a.coeffs {
            coeffs.push(((c as u128 * s) % q_u128) as u64);
        }
        Polynomial { coeffs }
    }

    /// Multiply two polynomials in the negacyclic quotient ring $R_q = \mathbb{Z}_q[X] / (X^N + 1)$.
    ///
    /// In this ring, $X^N \equiv -1$, so when indices $i + j \ge N$,
    /// the product $a[i] b[j] X^{i+j} = -a[i] b[j] X^{i+j-N}$.
    pub fn mul_negacyclic(a: &Polynomial, b: &Polynomial, q: u64) -> FheResult<Polynomial> {
        if a.degree() != b.degree() {
            return Err(FheError::DegreeMismatch {
                expected: a.degree(),
                actual: b.degree(),
            });
        }
        let n = a.degree();
        let mut acc = vec![0u128; n];
        let q_u128 = q as u128;

        for i in 0..n {
            let ai = a.coeffs[i] as u128;
            if ai == 0 {
                continue;
            }
            for j in 0..n {
                let bj = b.coeffs[j] as u128;
                if bj == 0 {
                    continue;
                }
                let prod = (ai * bj) % q_u128;
                let k = i + j;
                if k < n {
                    acc[k] = (acc[k] + prod) % q_u128;
                } else {
                    let k_wrap = k - n;
                    // Subtract prod modulo q
                    acc[k_wrap] = (acc[k_wrap] + q_u128 - prod) % q_u128;
                }
            }
        }

        let coeffs = acc.into_iter().map(|c| (c % q_u128) as u64).collect();
        Ok(Polynomial { coeffs })
    }

    /// Multiply two polynomials over the integer negacyclic ring $\mathbb{Z}[X]/(X^N + 1)$
    /// treating coefficients as positive integers in $[0, q-1]$ using 128-bit signed integer accumulators.
    pub fn mul_negacyclic_pos_i128(a: &Polynomial, b: &Polynomial) -> FheResult<Vec<i128>> {
        if a.degree() != b.degree() {
            return Err(FheError::DegreeMismatch {
                expected: a.degree(),
                actual: b.degree(),
            });
        }
        let n = a.degree();
        let mut acc = vec![0i128; n];
        for i in 0..n {
            let ai = a.coeffs[i] as i128;
            if ai == 0 {
                continue;
            }
            for j in 0..n {
                let bj = b.coeffs[j] as i128;
                if bj == 0 {
                    continue;
                }
                let prod = ai * bj;
                let k = i + j;
                if k < n {
                    acc[k] += prod;
                } else {
                    acc[k - n] -= prod;
                }
            }
        }
        Ok(acc)
    }

    /// Sample a uniform random polynomial with coefficients $\in [0, q-1]$.
    #[must_use]
    pub fn sample_uniform(degree: usize, q: u64, rng: &mut FastPrng) -> Polynomial {
        let mut coeffs = Vec::with_capacity(degree);
        for _ in 0..degree {
            coeffs.push(rng.next_u64() % q);
        }
        Polynomial { coeffs }
    }

    /// Sample a ternary polynomial with coefficients $\in \{-1, 0, 1\} \pmod q$.
    #[must_use]
    pub fn sample_ternary(degree: usize, q: u64, rng: &mut FastPrng) -> Polynomial {
        let mut coeffs = Vec::with_capacity(degree);
        for _ in 0..degree {
            let r = rng.next_u64() % 3;
            let val = match r {
                0 => 0u64,
                1 => 1u64,
                _ => q - 1, // -1 mod q
            };
            coeffs.push(val);
        }
        Polynomial { coeffs }
    }

    /// Sample a discrete Gaussian error polynomial bounded by $\pm 6\sigma \pmod q$.
    #[must_use]
    pub fn sample_gaussian(degree: usize, q: u64, std_dev: f64, rng: &mut FastPrng) -> Polynomial {
        let mut coeffs = Vec::with_capacity(degree);
        let max_val = (6.0 * std_dev).ceil() as i64;

        for _ in 0..degree {
            // Box-Muller transform for discrete Gaussian approximation
            let u1 = rng.next_f64().max(1e-10);
            let u2 = rng.next_f64();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            let val = (z * std_dev).round() as i64;
            let clamped = val.clamp(-max_val, max_val);

            let coeff = if clamped >= 0 {
                (clamped as u64) % q
            } else {
                (q - ((-clamped) as u64 % q)) % q
            };
            coeffs.push(coeff);
        }
        Polynomial { coeffs }
    }
}

/// Fast pseudo-random number generator (SplitMix64) for deterministic sampling.
pub struct FastPrng {
    state: u64,
}

impl FastPrng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E3779B97F4A7C15,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}
