//! Brakerski-Fan-Vercauteren (BFV) Leveled Homomorphic Encryption Scheme (ADR-084).
//!
//! Implements key generation, public key encryption, secret key decryption,
//! homomorphic addition, plaintext multiplication, and ciphertext evaluation
//! over cyclotomic polynomial rings under `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use super::poly::{FastPrng, PolyRing};
use super::types::{
    FheCiphertext, FheError, FheKeyPair, FheParams, FhePlaintext, FhePublicKey, FheRelinKey,
    FheResult, FheSecretKey, Polynomial,
};

/// Key generator for BFV public, secret, and relinearization keys.
pub struct FheKeyGenerator;

impl FheKeyGenerator {
    /// Generate a complete BFV keypair using the provided parameter set and seed.
    pub fn generate_keypair(params: &FheParams, seed: u64) -> FheResult<FheKeyPair> {
        let mut rng = FastPrng::new(seed);
        let n = params.poly_degree;
        let q = params.coeff_modulus;

        // 1. Secret Key s: ternary polynomial in {-1, 0, 1}
        let s = PolyRing::sample_ternary(n, q, &mut rng);

        // 2. Public Key (p0, p1): p1 = uniform random a, p0 = -(a * s + e) mod q
        let a = PolyRing::sample_uniform(n, q, &mut rng);
        let e = PolyRing::sample_gaussian(n, q, params.noise_std_dev, &mut rng);

        let as_prod = PolyRing::mul_negacyclic(&a, &s, q)?;
        let as_plus_e = PolyRing::add(&as_prod, &e, q)?;
        let p0 = PolyRing::sub(&Polynomial::zero(n), &as_plus_e, q)?;
        let p1 = a;

        // 3. Relinearization Key (r0, r1): r1 = uniform random a_relin, r0 = -(a_relin * s) + s^2 mod q
        let a_relin = PolyRing::sample_uniform(n, q, &mut rng);
        let s_squared = PolyRing::mul_negacyclic(&s, &s, q)?;
        let as_relin = PolyRing::mul_negacyclic(&a_relin, &s, q)?;
        let neg_as = PolyRing::sub(&Polynomial::zero(n), &as_relin, q)?;
        let r0 = PolyRing::add(&neg_as, &s_squared, q)?;
        let r1 = a_relin;

        Ok(FheKeyPair {
            params: params.clone(),
            secret_key: FheSecretKey { s },
            public_key: FhePublicKey { p0, p1 },
            relin_key: FheRelinKey { r0, r1 },
        })
    }
}

/// BFV Public-Key Encryptor.
pub struct FheEncryptor;

impl FheEncryptor {
    /// Encrypt a plaintext into a BFV ciphertext:
    /// $c_0 = (p_0 \cdot u + e_1 + \Delta \cdot m) \pmod q$
    /// $c_1 = (p_1 \cdot u + e_2) \pmod q$
    pub fn encrypt(
        pk: &FhePublicKey,
        pt: &FhePlaintext,
        params: &FheParams,
        seed: u64,
    ) -> FheResult<FheCiphertext> {
        let n = params.poly_degree;
        let q = params.coeff_modulus;

        if pt.poly.degree() != n {
            return Err(FheError::DegreeMismatch {
                expected: n,
                actual: pt.poly.degree(),
            });
        }

        let mut rng = FastPrng::new(seed);
        let u = PolyRing::sample_ternary(n, q, &mut rng);
        let e1 = PolyRing::sample_gaussian(n, q, params.noise_std_dev, &mut rng);
        let e2 = PolyRing::sample_gaussian(n, q, params.noise_std_dev, &mut rng);

        // Scale plaintext by Delta = floor(q / t)
        let scaled_m = PolyRing::mul_scalar(&pt.poly, params.delta, q);

        // c0 = p0 * u + e1 + Delta * m mod q
        let p0_u = PolyRing::mul_negacyclic(&pk.p0, &u, q)?;
        let p0_u_e1 = PolyRing::add(&p0_u, &e1, q)?;
        let c0 = PolyRing::add(&p0_u_e1, &scaled_m, q)?;

        // c1 = p1 * u + e2 mod q
        let p1_u = PolyRing::mul_negacyclic(&pk.p1, &u, q)?;
        let c1 = PolyRing::add(&p1_u, &e2, q)?;

        let initial_noise = params.initial_noise_budget_bits() as i64;

        Ok(FheCiphertext {
            c0,
            c1,
            noise_budget_bits: initial_noise,
        })
    }
}

/// BFV Secret-Key Decryptor.
pub struct FheDecryptor;

impl FheDecryptor {
    /// Decrypt a BFV ciphertext back to plaintext:
    /// Compute $v = (c_0 + c_1 \cdot s) \pmod q$.
    /// Round $\lfloor \frac{t \cdot v + q/2}{q} \rfloor \pmod t$.
    pub fn decrypt(
        sk: &FheSecretKey,
        ct: &FheCiphertext,
        params: &FheParams,
    ) -> FheResult<FhePlaintext> {
        let n = params.poly_degree;
        let q = params.coeff_modulus;
        let t = params.plain_modulus;

        if ct.c0.degree() != n || ct.c1.degree() != n {
            return Err(FheError::DegreeMismatch {
                expected: n,
                actual: ct.c0.degree(),
            });
        }

        // v = c0 + c1 * s mod q
        let c1_s = PolyRing::mul_negacyclic(&ct.c1, &sk.s, q)?;
        let v = PolyRing::add(&ct.c0, &c1_s, q)?;

        // Scale by t / q with rounding
        let mut pt_coeffs = Vec::with_capacity(n);
        let half_q = (q / 2) as u128;
        let t_u128 = t as u128;
        let q_u128 = q as u128;

        for &coeff in &v.coeffs {
            let num = (coeff as u128 * t_u128) + half_q;
            let res = (num / q_u128) % t_u128;
            pt_coeffs.push(res as u64);
        }

        Ok(FhePlaintext {
            poly: Polynomial { coeffs: pt_coeffs },
        })
    }
}

/// BFV Homomorphic Evaluator.
pub struct FheEvaluator;

impl FheEvaluator {
    /// Homomorphic addition of two ciphertexts: $(c_{1,0} + c_{2,0}, c_{1,1} + c_{2,1}) \pmod q$.
    pub fn add(
        c1: &FheCiphertext,
        c2: &FheCiphertext,
        params: &FheParams,
    ) -> FheResult<FheCiphertext> {
        let q = params.coeff_modulus;
        let c0 = PolyRing::add(&c1.c0, &c2.c0, q)?;
        let c1_poly = PolyRing::add(&c1.c1, &c2.c1, q)?;

        let noise_budget = c1.noise_budget_bits.min(c2.noise_budget_bits) - 1;
        if noise_budget <= 0 {
            return Err(FheError::NoiseBudgetExhausted { bits: noise_budget });
        }

        Ok(FheCiphertext {
            c0,
            c1: c1_poly,
            noise_budget_bits: noise_budget,
        })
    }

    /// Homomorphic subtraction of two ciphertexts: $(c_{1,0} - c_{2,0}, c_{1,1} - c_{2,1}) \pmod q$.
    pub fn sub(
        c1: &FheCiphertext,
        c2: &FheCiphertext,
        params: &FheParams,
    ) -> FheResult<FheCiphertext> {
        let q = params.coeff_modulus;
        let c0 = PolyRing::sub(&c1.c0, &c2.c0, q)?;
        let c1_poly = PolyRing::sub(&c1.c1, &c2.c1, q)?;

        let noise_budget = c1.noise_budget_bits.min(c2.noise_budget_bits) - 1;
        if noise_budget <= 0 {
            return Err(FheError::NoiseBudgetExhausted { bits: noise_budget });
        }

        Ok(FheCiphertext {
            c0,
            c1: c1_poly,
            noise_budget_bits: noise_budget,
        })
    }

    /// Homomorphic addition with a plaintext: $(c_0 + \Delta \cdot m, c_1) \pmod q$.
    pub fn add_plain(
        c: &FheCiphertext,
        pt: &FhePlaintext,
        params: &FheParams,
    ) -> FheResult<FheCiphertext> {
        let q = params.coeff_modulus;
        let scaled_m = PolyRing::mul_scalar(&pt.poly, params.delta, q);
        let c0 = PolyRing::add(&c.c0, &scaled_m, q)?;

        Ok(FheCiphertext {
            c0,
            c1: c.c1.clone(),
            noise_budget_bits: c.noise_budget_bits,
        })
    }

    /// Homomorphic scalar multiplication of a ciphertext by a plain scalar: $(k \cdot c_0, k \cdot c_1) \pmod q$.
    pub fn mul_scalar(
        c: &FheCiphertext,
        scalar: u64,
        params: &FheParams,
    ) -> FheResult<FheCiphertext> {
        let q = params.coeff_modulus;
        let c0 = PolyRing::mul_scalar(&c.c0, scalar, q);
        let c1 = PolyRing::mul_scalar(&c.c1, scalar, q);

        let scalar_bits = (scalar as f64).log2().ceil() as i64;
        let noise_budget = c.noise_budget_bits.saturating_sub(scalar_bits);
        if noise_budget <= 0 {
            return Err(FheError::NoiseBudgetExhausted { bits: noise_budget });
        }

        Ok(FheCiphertext {
            c0,
            c1,
            noise_budget_bits: noise_budget,
        })
    }

    /// Homomorphic plaintext multiplication: $(c_0 \cdot m, c_1 \cdot m) \pmod q$.
    pub fn mul_plain(
        c: &FheCiphertext,
        pt: &FhePlaintext,
        params: &FheParams,
    ) -> FheResult<FheCiphertext> {
        let q = params.coeff_modulus;
        let c0 = PolyRing::mul_negacyclic(&c.c0, &pt.poly, q)?;
        let c1 = PolyRing::mul_negacyclic(&c.c1, &pt.poly, q)?;

        // Plaintext multiplication degrades noise budget logarithmically based on max plaintext coeff
        let max_coeff = pt.poly.coeffs.iter().copied().max().unwrap_or(1).max(1);
        let pt_bits = (max_coeff as f64).log2().ceil() as i64 + 2;
        let noise_budget = c.noise_budget_bits.saturating_sub(pt_bits);

        if noise_budget <= 0 {
            return Err(FheError::NoiseBudgetExhausted { bits: noise_budget });
        }

        Ok(FheCiphertext {
            c0,
            c1,
            noise_budget_bits: noise_budget,
        })
    }

    /// Homomorphic ciphertext multiplication with relinearization:
    /// Computes tensor product $(c_{1,0} + c_{1,1}s)(c_{2,0} + c_{2,1}s) = d_0 + d_1 s + d_2 s^2$.
    /// Scales by $t / q$, then applies relinearization key $rk$ to map $d_2 s^2$ back to $(r_0, r_1)$.
    pub fn mul(
        c1: &FheCiphertext,
        c2: &FheCiphertext,
        rk: &FheRelinKey,
        params: &FheParams,
    ) -> FheResult<FheCiphertext> {
        let q = params.coeff_modulus;
        let t = params.plain_modulus;
        let n = params.poly_degree;

        if c1.c0.degree() != n || c1.c1.degree() != n || c2.c0.degree() != n || c2.c1.degree() != n
        {
            return Err(FheError::DegreeMismatch {
                expected: n,
                actual: c1.c0.degree(),
            });
        }

        // d0 = c1_0 * c2_0 in Z[X]/(X^N + 1)
        let d0_raw = PolyRing::mul_negacyclic_pos_i128(&c1.c0, &c2.c0)?;

        // d1 = c1_0 * c2_1 + c1_1 * c2_0 in Z[X]/(X^N + 1)
        let d1_a = PolyRing::mul_negacyclic_pos_i128(&c1.c0, &c2.c1)?;
        let d1_b = PolyRing::mul_negacyclic_pos_i128(&c1.c1, &c2.c0)?;
        let mut d1_raw = vec![0i128; n];
        for i in 0..n {
            d1_raw[i] = d1_a[i] + d1_b[i];
        }

        // d2 = c1_1 * c2_1 in Z[X]/(X^N + 1)
        let d2_raw = PolyRing::mul_negacyclic_pos_i128(&c1.c1, &c2.c1)?;

        let scale_coeff = |v: i128| -> u64 {
            let t_i128 = t as i128;
            let q_i128 = q as i128;
            let half_q = q_i128 / 2;
            let res = if v >= 0 {
                let k = v / q_i128;
                let r = v % q_i128;
                k * t_i128 + (r * t_i128 + half_q) / q_i128
            } else {
                let neg_v = -v;
                let k = neg_v / q_i128;
                let r = neg_v % q_i128;
                -(k * t_i128 + (r * t_i128 + half_q) / q_i128)
            };
            res.rem_euclid(q_i128) as u64
        };

        let d0 = Polynomial {
            coeffs: d0_raw.into_iter().map(scale_coeff).collect(),
        };
        let d1 = Polynomial {
            coeffs: d1_raw.into_iter().map(scale_coeff).collect(),
        };
        let d2 = Polynomial {
            coeffs: d2_raw.into_iter().map(scale_coeff).collect(),
        };

        // Relinearization: (c0', c1') = (d0 + d2 * r0, d1 + d2 * r1) mod q
        let d2_r0 = PolyRing::mul_negacyclic(&d2, &rk.r0, q)?;
        let d2_r1 = PolyRing::mul_negacyclic(&d2, &rk.r1, q)?;

        let c0_final = PolyRing::add(&d0, &d2_r0, q)?;
        let c1_final = PolyRing::add(&d1, &d2_r1, q)?;

        let consumed = 14; // Multiplicative depth cost in noise bits
        let noise_budget = c1
            .noise_budget_bits
            .min(c2.noise_budget_bits)
            .saturating_sub(consumed);

        if noise_budget <= 0 {
            return Err(FheError::NoiseBudgetExhausted { bits: noise_budget });
        }

        Ok(FheCiphertext {
            c0: c0_final,
            c1: c1_final,
            noise_budget_bits: noise_budget,
        })
    }
}
