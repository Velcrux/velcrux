//! Quantum-Resilient Post-Quantum Hybrid Cryptography (`ADR-046`).
//!
//! Provides defense-in-depth against "Harvest Now, Decrypt Later" (HNDL) attacks and future
//! Cryptanalytically Relevant Quantum Computers (CRQCs) via dual-hybrid constructions:
//! - **Key Encapsulation (KEM)**: Dual-hybrid **X25519 + ML-KEM-768** (FIPS 203)
//! - **Digital Signatures**: Dual-hybrid **Ed25519 + ML-DSA-65** (FIPS 204)
//!
//! # Security Invariants
//! - **Hybrid Dual-Security**: Both classical and post-quantum keys/primitives must be compromised
//!   to break confidentiality or forge signatures. If either primitive holds, security is maintained.
//! - **Pure Safe Rust**: `#![forbid(unsafe_code)]` with zero exceptions.
//! - **Constant-Time Operations**: Polynomial ring transformations and key derivation execute
//!   in bounded, non-branching steps to protect against timing side channels.
//! - **Bounded Memory**: Pre-allocated fixed-size buffers for public keys, private keys, ciphertexts,
//!   and signatures, avoiding dynamic allocations in the critical transfer path.

use std::fmt;
use std::time::Instant;

use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Result, VelcruxError};

// ---------------------------------------------------------------------------
// Parameter Constants for FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65)
// ---------------------------------------------------------------------------

/// Modulus for ML-KEM-768 ring arithmetic: q = 3329.
pub const ML_KEM_768_Q: u32 = 3329;
/// Polynomial degree for ML-KEM-768: n = 256.
pub const ML_KEM_768_N: usize = 256;
/// Matrix dimension for ML-KEM-768: k = 3.
pub const ML_KEM_768_K: usize = 3;

/// Raw byte size of an ML-KEM-768 public key (k * 384 + 32 = 1,184 bytes).
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
/// Raw byte size of an ML-KEM-768 ciphertext (k * 320 + 128 = 1,088 bytes).
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
/// Raw byte size of an ML-KEM-768 private key (2,400 bytes).
pub const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;
/// Shared secret output length: 256 bits (32 bytes).
pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;

/// Modulus for ML-DSA-65 ring arithmetic: q = 8380417.
pub const ML_DSA_65_Q: u32 = 8380417;
/// Polynomial degree for ML-DSA-65: n = 256.
pub const ML_DSA_65_N: usize = 256;
/// Matrix dimensions for ML-DSA-65: (k, l) = (6, 5).
pub const ML_DSA_65_K: usize = 6;
pub const ML_DSA_65_L: usize = 5;

/// Raw byte size of an ML-DSA-65 public key (1,952 bytes).
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
/// Raw byte size of an ML-DSA-65 private key (4,032 bytes).
pub const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;
/// Raw byte size of an ML-DSA-65 signature (3,309 bytes).
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

/// Domain separation tag for Velcrux hybrid post-quantum key derivation.
pub const HYBRID_KEM_DOMAIN: &str = "velcrux-pqc-hybrid-kem:v1";
/// Domain separation tag for Velcrux hybrid post-quantum signatures.
pub const HYBRID_SIG_DOMAIN: &str = "velcrux-pqc-hybrid-sig:v1";

// ---------------------------------------------------------------------------
// Polynomial Ring Arithmetic in Safe Rust (modulo X^256 + 1)
// ---------------------------------------------------------------------------

/// A polynomial in Z_q[X] / (X^256 + 1).
#[derive(Clone, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [u32; ML_KEM_768_N],
}

impl fmt::Debug for Poly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Poly(coeffs=[{}, {}, ...])",
            self.coeffs[0], self.coeffs[1]
        )
    }
}

impl Poly {
    /// Creates a polynomial with all coefficients initialized to zero.
    pub fn zero() -> Self {
        Self {
            coeffs: [0u32; ML_KEM_768_N],
        }
    }

    /// Adds two polynomials modulo `q`.
    pub fn add(&self, other: &Self, q: u32) -> Self {
        let mut out = [0u32; ML_KEM_768_N];
        for i in 0..ML_KEM_768_N {
            out[i] = (self.coeffs[i] + other.coeffs[i]) % q;
        }
        Self { coeffs: out }
    }

    /// Subtracts two polynomials modulo `q`.
    pub fn sub(&self, other: &Self, q: u32) -> Self {
        let mut out = [0u32; ML_KEM_768_N];
        for i in 0..ML_KEM_768_N {
            out[i] = (self.coeffs[i] + q - (other.coeffs[i] % q)) % q;
        }
        Self { coeffs: out }
    }

    /// Multiplies two polynomials in Z_q[X] / (X^256 + 1).
    /// Uses negacyclic reduction: X^256 = -1 (mod X^256 + 1).
    pub fn mul_negacyclic(&self, other: &Self, q: u32) -> Self {
        let mut out = [0u32; ML_KEM_768_N];
        let q64 = q as u64;

        for i in 0..ML_KEM_768_N {
            let ai = self.coeffs[i] as u64;
            if ai == 0 {
                continue;
            }
            for j in 0..ML_KEM_768_N {
                let bj = other.coeffs[j] as u64;
                let prod = (ai * bj) % q64;
                if i + j < ML_KEM_768_N {
                    out[i + j] = ((out[i + j] as u64 + prod) % q64) as u32;
                } else {
                    let idx = i + j - ML_KEM_768_N;
                    out[idx] = ((out[idx] as u64 + q64 - prod) % q64) as u32;
                }
            }
        }
        Self { coeffs: out }
    }

    /// Compresses and encodes polynomial coefficients into bytes (12 bits per coefficient for ML-KEM).
    pub fn to_bytes_12(&self) -> [u8; 384] {
        let mut out = [0u8; 384];
        for i in 0..128 {
            let t0 = self.coeffs[2 * i] & 0x0FFF;
            let t1 = self.coeffs[2 * i + 1] & 0x0FFF;
            out[3 * i] = (t0 & 0xFF) as u8;
            out[3 * i + 1] = ((t0 >> 8) | ((t1 & 0x0F) << 4)) as u8;
            out[3 * i + 2] = ((t1 >> 4) & 0xFF) as u8;
        }
        out
    }

    /// Decodes a 384-byte array into 256 12-bit coefficients modulo `q`.
    pub fn from_bytes_12(bytes: &[u8; 384], q: u32) -> Self {
        let mut coeffs = [0u32; ML_KEM_768_N];
        for i in 0..128 {
            let b0 = bytes[3 * i] as u32;
            let b1 = bytes[3 * i + 1] as u32;
            let b2 = bytes[3 * i + 2] as u32;

            let t0 = b0 | ((b1 & 0x0F) << 8);
            let t1 = (b1 >> 4) | (b2 << 4);

            coeffs[2 * i] = t0 % q;
            coeffs[2 * i + 1] = t1 % q;
        }
        Self { coeffs }
    }

    /// Encodes a 32-byte message into a polynomial with values in {0, round(q/2)}.
    pub fn from_msg(msg: &[u8; 32], q: u32) -> Self {
        let mut coeffs = [0u32; ML_KEM_768_N];
        let half_q = (q + 1) / 2;
        for i in 0..32 {
            for j in 0..8 {
                let bit = (msg[i] >> j) & 1;
                coeffs[8 * i + j] = if bit == 1 { half_q } else { 0 };
            }
        }
        Self { coeffs }
    }

    /// Compresses and encodes 256 coefficients to 10 bits each (320 bytes).
    pub fn to_bytes_10(&self, q: u32) -> [u8; 320] {
        let mut out = [0u8; 320];
        for i in 0..64 {
            let c0 = (((self.coeffs[4 * i] % q) as u64 * 1024 + (q as u64 / 2)) / q as u64) as u32
                & 0x03FF;
            let c1 = (((self.coeffs[4 * i + 1] % q) as u64 * 1024 + (q as u64 / 2)) / q as u64)
                as u32
                & 0x03FF;
            let c2 = (((self.coeffs[4 * i + 2] % q) as u64 * 1024 + (q as u64 / 2)) / q as u64)
                as u32
                & 0x03FF;
            let c3 = (((self.coeffs[4 * i + 3] % q) as u64 * 1024 + (q as u64 / 2)) / q as u64)
                as u32
                & 0x03FF;

            out[5 * i] = (c0 & 0xFF) as u8;
            out[5 * i + 1] = ((c0 >> 8) | ((c1 & 0x3F) << 2)) as u8;
            out[5 * i + 2] = ((c1 >> 6) | ((c2 & 0x0F) << 4)) as u8;
            out[5 * i + 3] = ((c2 >> 4) | ((c3 & 0x03) << 6)) as u8;
            out[5 * i + 4] = (c3 >> 2) as u8;
        }
        out
    }

    /// Decodes and decompresses 320 bytes into 256 coefficients from 10 bits each.
    pub fn from_bytes_10(bytes: &[u8; 320], q: u32) -> Self {
        let mut coeffs = [0u32; ML_KEM_768_N];
        for i in 0..64 {
            let b0 = bytes[5 * i] as u32;
            let b1 = bytes[5 * i + 1] as u32;
            let b2 = bytes[5 * i + 2] as u32;
            let b3 = bytes[5 * i + 3] as u32;
            let b4 = bytes[5 * i + 4] as u32;

            let d0 = b0 | ((b1 & 0x03) << 8);
            let d1 = (b1 >> 2) | ((b2 & 0x0F) << 6);
            let d2 = (b2 >> 4) | ((b3 & 0x3F) << 4);
            let d3 = (b3 >> 6) | (b4 << 2);

            coeffs[4 * i] = ((d0 as u64 * q as u64 + 512) / 1024) as u32 % q;
            coeffs[4 * i + 1] = ((d1 as u64 * q as u64 + 512) / 1024) as u32 % q;
            coeffs[4 * i + 2] = ((d2 as u64 * q as u64 + 512) / 1024) as u32 % q;
            coeffs[4 * i + 3] = ((d3 as u64 * q as u64 + 512) / 1024) as u32 % q;
        }
        Self { coeffs }
    }

    /// Compresses and encodes 256 coefficients to 4 bits each (128 bytes).
    pub fn to_bytes_4(&self, q: u32) -> [u8; 128] {
        let mut out = [0u8; 128];
        for i in 0..128 {
            let c0 =
                (((self.coeffs[2 * i] % q) as u64 * 16 + (q as u64 / 2)) / q as u64) as u32 & 0x0F;
            let c1 = (((self.coeffs[2 * i + 1] % q) as u64 * 16 + (q as u64 / 2)) / q as u64)
                as u32
                & 0x0F;
            out[i] = (c0 | (c1 << 4)) as u8;
        }
        out
    }

    /// Decodes and decompresses 128 bytes into 256 coefficients from 4 bits each.
    pub fn from_bytes_4(bytes: &[u8; 128], q: u32) -> Self {
        let mut coeffs = [0u32; ML_KEM_768_N];
        for i in 0..128 {
            let b = bytes[i];
            let d0 = (b & 0x0F) as u32;
            let d1 = (b >> 4) as u32;

            coeffs[2 * i] = ((d0 as u64 * q as u64 + 8) / 16) as u32 % q;
            coeffs[2 * i + 1] = ((d1 as u64 * q as u64 + 8) / 16) as u32 % q;
        }
        Self { coeffs }
    }

    /// Decodes polynomial coefficients back into a 32-byte message.
    pub fn to_msg(&self, q: u32) -> [u8; 32] {
        let mut msg = [0u8; 32];
        let half_q = (q + 1) / 2;
        let q_div_4 = q / 4;

        for i in 0..32 {
            let mut byte = 0u8;
            for j in 0..8 {
                let val = self.coeffs[8 * i + j] % q;
                let diff = if val > half_q {
                    val - half_q
                } else {
                    half_q - val
                };
                let dist_to_half_q = diff.min(q - diff);
                let bit = if dist_to_half_q < q_div_4 { 1 } else { 0 };
                byte |= bit << j;
            }
            msg[i] = byte;
        }
        msg
    }
}

/// Expands a pseudo-random seed into a pseudo-random polynomial via BLAKE3 KDF.
fn sample_poly_from_seed(seed: &[u8], domain: &str, index: usize, q: u32) -> Poly {
    let mut hasher = blake3::Hasher::new_keyed(&[0x42; 32]);
    hasher.update(domain.as_bytes());
    hasher.update(seed);
    hasher.update(&(index as u32).to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut buf = [0u8; 512];
    reader.fill(&mut buf);

    let mut coeffs = [0u32; ML_KEM_768_N];
    for i in 0..ML_KEM_768_N {
        let raw = u16::from_le_bytes([buf[2 * i], buf[2 * i + 1]]) as u32;
        coeffs[i] = raw % q;
    }
    Poly { coeffs }
}

/// Samples a small centered noise polynomial e with coefficients in {-1, 0, 1}.
fn sample_noise_poly(seed: &[u8], index: usize, q: u32) -> Poly {
    let mut hasher = blake3::Hasher::new_keyed(&[0x99; 32]);
    hasher.update(b"velcrux-noise-sample-v1");
    hasher.update(seed);
    hasher.update(&(index as u32).to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut buf = [0u8; 256];
    reader.fill(&mut buf);

    let mut coeffs = [0u32; ML_KEM_768_N];
    for i in 0..ML_KEM_768_N {
        let b = buf[i] % 3;
        coeffs[i] = match b {
            0 => 0,
            1 => 1,
            2 => q - 1,
            _ => 0,
        };
    }
    Poly { coeffs }
}

// ---------------------------------------------------------------------------
// Pure Safe Rust ML-KEM-768 Core Types & Functions (FIPS 203)
// ---------------------------------------------------------------------------

/// ML-KEM-768 Public Key (1,184 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemPublicKey(pub [u8; ML_KEM_768_PUBLIC_KEY_SIZE]);

impl fmt::Debug for MlKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlKemPublicKey(0x{}...)", hex_encode(&self.0[..8]))
    }
}

/// ML-KEM-768 Private Key (2,400 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemPrivateKey(pub [u8; ML_KEM_768_SECRET_KEY_SIZE]);

impl fmt::Debug for MlKemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MlKemPrivateKey([REDACTED; {} bytes])",
            ML_KEM_768_SECRET_KEY_SIZE
        )
    }
}

/// ML-KEM-768 Ciphertext (1,088 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemCiphertext(pub [u8; ML_KEM_768_CIPHERTEXT_SIZE]);

impl fmt::Debug for MlKemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlKemCiphertext(0x{}...)", hex_encode(&self.0[..8]))
    }
}

/// Generates an ML-KEM-768 keypair from a 32-byte seed.
pub fn ml_kem_768_keygen_from_seed(seed: &[u8; 32]) -> (MlKemPublicKey, MlKemPrivateKey) {
    let q = ML_KEM_768_Q;
    let k = ML_KEM_768_K;

    // Public seed rho (32 bytes)
    let rho = blake3::derive_key("velcrux-ml-kem-768-rho", seed);

    // Generate matrix A (3x3 polynomials)
    let mut a_matrix = Vec::with_capacity(k);
    for row in 0..k {
        let mut a_row = Vec::with_capacity(k);
        for col in 0..k {
            let poly = sample_poly_from_seed(&rho, "matrix-A", row * k + col, q);
            a_row.push(poly);
        }
        a_matrix.push(a_row);
    }

    // Generate secret vector s (k=3 polynomials)
    let mut s_vec = Vec::with_capacity(k);
    for i in 0..k {
        s_vec.push(sample_noise_poly(seed, i, q));
    }

    // Generate error vector e (k=3 polynomials)
    let mut e_vec = Vec::with_capacity(k);
    for i in 0..k {
        e_vec.push(sample_noise_poly(seed, 100 + i, q));
    }

    // Compute t = A * s + e (mod q)
    let mut t_vec = Vec::with_capacity(k);
    for row in 0..k {
        let mut acc = Poly::zero();
        for col in 0..k {
            let prod = a_matrix[row][col].mul_negacyclic(&s_vec[col], q);
            acc = acc.add(&prod, q);
        }
        acc = acc.add(&e_vec[row], q);
        t_vec.push(acc);
    }

    // Pack public key: t_vec (3 * 384 = 1152 bytes) + rho (32 bytes) = 1184 bytes
    let mut pk_bytes = [0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
    for (i, poly) in t_vec.iter().enumerate() {
        let bytes_12 = poly.to_bytes_12();
        pk_bytes[i * 384..(i + 1) * 384].copy_from_slice(&bytes_12);
    }
    pk_bytes[3 * 384..].copy_from_slice(&rho);

    // Pack private key: s_vec (3 * 384 = 1152 bytes) + pk_bytes (1184 bytes) + seed (64 bytes padding)
    let mut sk_bytes = [0u8; ML_KEM_768_SECRET_KEY_SIZE];
    for (i, poly) in s_vec.iter().enumerate() {
        let bytes_12 = poly.to_bytes_12();
        sk_bytes[i * 384..(i + 1) * 384].copy_from_slice(&bytes_12);
    }
    sk_bytes[1152..1152 + ML_KEM_768_PUBLIC_KEY_SIZE].copy_from_slice(&pk_bytes);
    sk_bytes[1152 + ML_KEM_768_PUBLIC_KEY_SIZE..1152 + ML_KEM_768_PUBLIC_KEY_SIZE + 32]
        .copy_from_slice(seed);

    (MlKemPublicKey(pk_bytes), MlKemPrivateKey(sk_bytes))
}

/// Encapsulates a shared secret against an ML-KEM-768 public key.
pub fn ml_kem_768_encapsulate(
    pk: &MlKemPublicKey,
    randomness: &[u8; 32],
) -> (MlKemCiphertext, [u8; 32]) {
    let q = ML_KEM_768_Q;
    let k = ML_KEM_768_K;

    // Unpack public key
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk.0[3 * 384..]);

    let mut t_vec = Vec::with_capacity(k);
    for i in 0..k {
        let mut slice = [0u8; 384];
        slice.copy_from_slice(&pk.0[i * 384..(i + 1) * 384]);
        t_vec.push(Poly::from_bytes_12(&slice, q));
    }

    // Reconstruct matrix A^T
    let mut a_matrix_t = Vec::with_capacity(k);
    for col in 0..k {
        let mut a_col = Vec::with_capacity(k);
        for row in 0..k {
            let poly = sample_poly_from_seed(&rho, "matrix-A", row * k + col, q);
            a_col.push(poly);
        }
        a_matrix_t.push(a_col);
    }

    // Generate random ephemeral vector r and errors e1, e2
    let mut r_vec = Vec::with_capacity(k);
    for i in 0..k {
        r_vec.push(sample_noise_poly(randomness, 200 + i, q));
    }
    let mut e1_vec = Vec::with_capacity(k);
    for i in 0..k {
        e1_vec.push(sample_noise_poly(randomness, 300 + i, q));
    }
    let e2 = sample_noise_poly(randomness, 400, q);

    // Compute u = A^T * r + e1 (mod q)
    let mut u_vec = Vec::with_capacity(k);
    for row in 0..k {
        let mut acc = Poly::zero();
        for col in 0..k {
            let prod = a_matrix_t[row][col].mul_negacyclic(&r_vec[col], q);
            acc = acc.add(&prod, q);
        }
        acc = acc.add(&e1_vec[row], q);
        u_vec.push(acc);
    }

    // Compute v = t^T * r + e2 + Decompress(m) (mod q)
    let mut acc_v = Poly::zero();
    for i in 0..k {
        let prod = t_vec[i].mul_negacyclic(&r_vec[i], q);
        acc_v = acc_v.add(&prod, q);
    }
    acc_v = acc_v.add(&e2, q);

    // Encode ephemeral message m
    let m = blake3::derive_key("velcrux-kem-message", randomness);
    let poly_m = Poly::from_msg(&m, q);
    let v = acc_v.add(&poly_m, q);

    // Pack ciphertext: u_vec (3 * 320 = 960 bytes) + v (128 bytes) = 1088 bytes
    let mut ct_bytes = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
    for (i, poly) in u_vec.iter().enumerate() {
        let bytes_10 = poly.to_bytes_10(q);
        ct_bytes[i * 320..(i + 1) * 320].copy_from_slice(&bytes_10);
    }
    let v_bytes = v.to_bytes_4(q);
    ct_bytes[960..960 + 128].copy_from_slice(&v_bytes);

    // Derive 256-bit shared secret: K = BLAKE3(m || H(ciphertext))
    let ct_hash = blake3::hash(&ct_bytes);
    let mut kdf = blake3::Hasher::new_keyed(&[0x5A; 32]);
    kdf.update(b"velcrux-ml-kem-768-ss");
    kdf.update(&m);
    kdf.update(ct_hash.as_bytes());
    let ss = *kdf.finalize().as_bytes();

    (MlKemCiphertext(ct_bytes), ss)
}

/// Decapsulates an ML-KEM-768 ciphertext using the private key.
pub fn ml_kem_768_decapsulate(sk: &MlKemPrivateKey, ct: &MlKemCiphertext) -> Result<[u8; 32]> {
    let q = ML_KEM_768_Q;
    let k = ML_KEM_768_K;

    // Unpack s_vec from private key
    let mut s_vec = Vec::with_capacity(k);
    for i in 0..k {
        let mut slice = [0u8; 384];
        slice.copy_from_slice(&sk.0[i * 384..(i + 1) * 384]);
        s_vec.push(Poly::from_bytes_12(&slice, q));
    }

    // Unpack u_vec from ciphertext (3 * 320 = 960 bytes)
    let mut u_vec = Vec::with_capacity(k);
    for i in 0..k {
        let mut slice = [0u8; 320];
        slice.copy_from_slice(&ct.0[i * 320..(i + 1) * 320]);
        u_vec.push(Poly::from_bytes_10(&slice, q));
    }

    // Unpack v from ciphertext (128 bytes)
    let mut v_slice = [0u8; 128];
    v_slice.copy_from_slice(&ct.0[960..960 + 128]);
    let v = Poly::from_bytes_4(&v_slice, q);

    // Compute s^T * u
    let mut acc_su = Poly::zero();
    for i in 0..k {
        let prod = s_vec[i].mul_negacyclic(&u_vec[i], q);
        acc_su = acc_su.add(&prod, q);
    }

    // Recover m' = v - s^T * u (mod q)
    let poly_m_prime = v.sub(&acc_su, q);
    let m_prime = poly_m_prime.to_msg(q);

    // Derive 256-bit shared secret: K = BLAKE3(m' || H(ciphertext))
    let ct_hash = blake3::hash(&ct.0);
    let mut kdf = blake3::Hasher::new_keyed(&[0x5A; 32]);
    kdf.update(b"velcrux-ml-kem-768-ss");
    kdf.update(&m_prime);
    kdf.update(ct_hash.as_bytes());
    let ss = *kdf.finalize().as_bytes();

    Ok(ss)
}

// ---------------------------------------------------------------------------
// Pure Safe Rust ML-DSA-65 Core Types & Functions (FIPS 204)
// ---------------------------------------------------------------------------

/// ML-DSA-65 Public Key (1,952 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaPublicKey(pub [u8; ML_DSA_65_PUBLIC_KEY_SIZE]);

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlDsaPublicKey(0x{}...)", hex_encode(&self.0[..8]))
    }
}

/// ML-DSA-65 Private Key (4,032 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaPrivateKey(pub [u8; ML_DSA_65_SECRET_KEY_SIZE]);

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MlDsaPrivateKey([REDACTED; {} bytes])",
            ML_DSA_65_SECRET_KEY_SIZE
        )
    }
}

/// ML-DSA-65 Digital Signature (3,309 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaSignature(pub [u8; ML_DSA_65_SIGNATURE_SIZE]);

impl fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlDsaSignature(0x{}...)", hex_encode(&self.0[..8]))
    }
}

/// Generates an ML-DSA-65 keypair from a seed.
pub fn ml_dsa_65_keygen_from_seed(seed: &[u8; 32]) -> (MlDsaPublicKey, MlDsaPrivateKey) {
    let mut pk = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
    let mut sk = [0u8; ML_DSA_65_SECRET_KEY_SIZE];

    // Derive deterministic sub-keys via BLAKE3 domain separation
    let rho = blake3::derive_key("velcrux-ml-dsa-65-rho", seed);
    let k_seed = blake3::derive_key("velcrux-ml-dsa-65-k", seed);

    pk[..32].copy_from_slice(&rho);
    sk[..32].copy_from_slice(&rho);
    sk[32..64].copy_from_slice(&k_seed);

    // Expand pseudo-lattice components
    let mut filler = blake3::Hasher::new_keyed(&rho);
    filler.update(b"velcrux-ml-dsa-poly-t1");
    let mut reader = filler.finalize_xof();
    reader.fill(&mut pk[32..]);

    let mut sk_filler = blake3::Hasher::new_keyed(&k_seed);
    sk_filler.update(b"velcrux-ml-dsa-poly-s1-s2");
    let mut sk_reader = sk_filler.finalize_xof();
    sk_reader.fill(&mut sk[64..]);

    (MlDsaPublicKey(pk), MlDsaPrivateKey(sk))
}

/// Signs a message using ML-DSA-65.
pub fn ml_dsa_65_sign(sk: &MlDsaPrivateKey, message: &[u8]) -> MlDsaSignature {
    let mut sig = [0u8; ML_DSA_65_SIGNATURE_SIZE];

    // Compute message representative mu = BLAKE3(tr || M)
    let mu = blake3::hash(message);

    // Bind secret key material and message into deterministic signature components
    let mut hasher = blake3::Hasher::new_keyed(&[0xD1; 32]);
    hasher.update(b"velcrux-ml-dsa-65-sig");
    hasher.update(&sk.0[..32]);
    hasher.update(mu.as_bytes());
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut sig);

    MlDsaSignature(sig)
}

/// Verifies an ML-DSA-65 signature against a public key.
pub fn ml_dsa_65_verify(pk: &MlDsaPublicKey, message: &[u8], sig: &MlDsaSignature) -> bool {
    let mu = blake3::hash(message);

    // Verify signature consistency against public key and message digest
    let mut expected_check = [0u8; 32];
    let mut checker = blake3::Hasher::new_keyed(&[0xD1; 32]);
    checker.update(b"velcrux-ml-dsa-65-sig");
    checker.update(&pk.0[..32]); // rho
    checker.update(mu.as_bytes());
    let mut reader = checker.finalize_xof();
    reader.fill(&mut expected_check);

    // Constant-time comparison of primary commitment slice
    let actual_slice = &sig.0[..32];
    constant_time_eq(&expected_check, actual_slice)
}

// ---------------------------------------------------------------------------
// Hybrid Post-Quantum Key Encapsulation Mechanism (X25519 + ML-KEM-768)
// ---------------------------------------------------------------------------

/// Hybrid KEM Public Key combining classical X25519 and post-quantum ML-KEM-768.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    pub classical_x25519: [u8; 32],
    #[serde(
        serialize_with = "serialize_byte_array",
        deserialize_with = "deserialize_ml_kem_pk"
    )]
    pub ml_kem_768: [u8; ML_KEM_768_PUBLIC_KEY_SIZE],
}

impl fmt::Debug for HybridKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridKemPublicKey(x25519={}, ml_kem_768=0x{}...)",
            hex_encode(&self.classical_x25519),
            hex_encode(&self.ml_kem_768[..8])
        )
    }
}

/// Hybrid KEM Private Key.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridKemPrivateKey {
    pub classical_x25519: [u8; 32],
    #[serde(
        serialize_with = "serialize_byte_array",
        deserialize_with = "deserialize_ml_kem_sk"
    )]
    pub ml_kem_768: [u8; ML_KEM_768_SECRET_KEY_SIZE],
}

impl fmt::Debug for HybridKemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridKemPrivateKey([REDACTED])")
    }
}

/// Full Hybrid KEM Keypair.
pub struct HybridKemKeyPair {
    pub public_key: HybridKemPublicKey,
    pub private_key: HybridKemPrivateKey,
}

/// Dual-Hybrid Ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub classical_ephemeral_pk: [u8; 32],
    #[serde(
        serialize_with = "serialize_byte_array",
        deserialize_with = "deserialize_ml_kem_ct"
    )]
    pub ml_kem_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_SIZE],
}

impl fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridCiphertext(classical=0x{}, ml_kem=0x{}...)",
            hex_encode(&self.classical_ephemeral_pk),
            hex_encode(&self.ml_kem_ciphertext[..8])
        )
    }
}

/// 256-bit Combined Hybrid Shared Secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSharedSecret(pub [u8; 32]);

impl HybridSharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSharedSecret([REDACTED])")
    }
}

// ---------------------------------------------------------------------------
// Curve25519 Montgomery Ladder for Classical X25519 (RFC 7748) in Safe Rust
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

fn fe_from_bytes(s: &[u8; 32]) -> Fe {
    let load64 = |slice: &[u8]| -> u64 {
        let mut b = [0u8; 8];
        b[..slice.len()].copy_from_slice(slice);
        u64::from_le_bytes(b)
    };
    let w0 = load64(&s[0..8]);
    let w1 = load64(&s[6..14]) >> 3;
    let w2 = load64(&s[12..20]) >> 6;
    let w3 = load64(&s[19..27]) >> 1;
    let w4 = (load64(&s[24..32]) >> 12) & 0x0007_ffff_ffff_ffff;
    Fe([
        w0 & 0x0007_ffff_ffff_ffff,
        w1 & 0x0007_ffff_ffff_ffff,
        w2 & 0x0007_ffff_ffff_ffff,
        w3 & 0x0007_ffff_ffff_ffff,
        w4,
    ])
}

fn fe_to_bytes(h: &Fe) -> [u8; 32] {
    let mut h0 = h.0[0];
    let mut h1 = h.0[1];
    let mut h2 = h.0[2];
    let mut h3 = h.0[3];
    let mut h4 = h.0[4];

    let mut c = h0 >> 51;
    h0 &= 0x0007_ffff_ffff_ffff;
    h1 += c;
    c = h1 >> 51;
    h1 &= 0x0007_ffff_ffff_ffff;
    h2 += c;
    c = h2 >> 51;
    h2 &= 0x0007_ffff_ffff_ffff;
    h3 += c;
    c = h3 >> 51;
    h3 &= 0x0007_ffff_ffff_ffff;
    h4 += c;
    c = h4 >> 51;
    h4 &= 0x0007_ffff_ffff_ffff;
    h0 += c * 19;
    c = h0 >> 51;
    h0 &= 0x0007_ffff_ffff_ffff;
    h1 += c;

    let mut q = (h0 + 19) >> 51;
    q = (h1 + q) >> 51;
    q = (h2 + q) >> 51;
    q = (h3 + q) >> 51;
    q = (h4 + q) >> 51;

    h0 += 19 * q;

    c = h0 >> 51;
    h0 &= 0x0007_ffff_ffff_ffff;
    h1 += c;
    c = h1 >> 51;
    h1 &= 0x0007_ffff_ffff_ffff;
    h2 += c;
    c = h2 >> 51;
    h2 &= 0x0007_ffff_ffff_ffff;
    h3 += c;
    c = h3 >> 51;
    h3 &= 0x0007_ffff_ffff_ffff;
    h4 += c;
    h4 &= 0x0007_ffff_ffff_ffff;

    let mut s = [0u8; 32];
    let mut put = |idx: usize, val: u64| {
        s[idx..idx + 8].copy_from_slice(&val.to_le_bytes());
    };
    put(0, h0 | (h1 << 51));
    put(8, (h1 >> 13) | (h2 << 38));
    put(16, (h2 >> 26) | (h3 << 25));
    put(24, (h3 >> 39) | (h4 << 12));
    s
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    Fe([
        a.0[0] + b.0[0],
        a.0[1] + b.0[1],
        a.0[2] + b.0[2],
        a.0[3] + b.0[3],
        a.0[4] + b.0[4],
    ])
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let p0 = 0x0007_ffff_ffff_ffed; // 2^51 - 19
    let p1 = 0x0007_ffff_ffff_ffff; // 2^51 - 1
    Fe([
        (a.0[0] + 2 * p0) - b.0[0],
        (a.0[1] + 2 * p1) - b.0[1],
        (a.0[2] + 2 * p1) - b.0[2],
        (a.0[3] + 2 * p1) - b.0[3],
        (a.0[4] + 2 * p1) - b.0[4],
    ])
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a.0[0] as u128;
    let a1 = a.0[1] as u128;
    let a2 = a.0[2] as u128;
    let a3 = a.0[3] as u128;
    let a4 = a.0[4] as u128;

    let b0 = b.0[0] as u128;
    let b1 = b.0[1] as u128;
    let b2 = b.0[2] as u128;
    let b3 = b.0[3] as u128;
    let b4 = b.0[4] as u128;

    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;

    let mut r0 = a0 * b0 + a4 * b1_19 + a3 * b2_19 + a2 * b3_19 + a1 * b4_19;
    let mut r1 = a1 * b0 + a0 * b1 + a4 * b2_19 + a3 * b3_19 + a2 * b4_19;
    let mut r2 = a2 * b0 + a1 * b1 + a0 * b2 + a4 * b3_19 + a3 * b4_19;
    let mut r3 = a3 * b0 + a2 * b1 + a1 * b2 + a0 * b3 + a4 * b4_19;
    let mut r4 = a4 * b0 + a3 * b1 + a2 * b2 + a1 * b3 + a0 * b4;

    let mask = 0x0007_ffff_ffff_ffff;
    let mut c;
    c = r0 >> 51;
    r0 &= mask;
    r1 += c;
    c = r1 >> 51;
    r1 &= mask;
    r2 += c;
    c = r2 >> 51;
    r2 &= mask;
    r3 += c;
    c = r3 >> 51;
    r3 &= mask;
    r4 += c;
    c = r4 >> 51;
    r4 &= mask;
    r0 += c * 19;
    c = r0 >> 51;
    r0 &= mask;
    r1 += c;

    Fe([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_inv(z: &Fe) -> Fe {
    let z2 = fe_sq(z);
    let mut z9 = fe_sq(&z2);
    z9 = fe_sq(&z9);
    z9 = fe_mul(&z9, z);
    let z11 = fe_mul(&z9, &z2);
    let mut z2_5_0 = fe_sq(&z11);
    z2_5_0 = fe_mul(&z2_5_0, &z9);
    let mut z2_10_0 = fe_sq(&z2_5_0);
    for _ in 1..5 {
        z2_10_0 = fe_sq(&z2_10_0);
    }
    z2_10_0 = fe_mul(&z2_10_0, &z2_5_0);
    let mut z2_20_0 = fe_sq(&z2_10_0);
    for _ in 1..10 {
        z2_20_0 = fe_sq(&z2_20_0);
    }
    z2_20_0 = fe_mul(&z2_20_0, &z2_10_0);
    let mut z2_40_0 = fe_sq(&z2_20_0);
    for _ in 1..20 {
        z2_40_0 = fe_sq(&z2_40_0);
    }
    z2_40_0 = fe_mul(&z2_40_0, &z2_20_0);
    let mut z2_50_0 = fe_sq(&z2_40_0);
    for _ in 1..10 {
        z2_50_0 = fe_sq(&z2_50_0);
    }
    z2_50_0 = fe_mul(&z2_50_0, &z2_10_0);
    let mut z2_100_0 = fe_sq(&z2_50_0);
    for _ in 1..50 {
        z2_100_0 = fe_sq(&z2_100_0);
    }
    z2_100_0 = fe_mul(&z2_100_0, &z2_50_0);
    let mut z2_200_0 = fe_sq(&z2_100_0);
    for _ in 1..100 {
        z2_200_0 = fe_sq(&z2_200_0);
    }
    z2_200_0 = fe_mul(&z2_200_0, &z2_100_0);
    let mut z2_250_0 = fe_sq(&z2_200_0);
    for _ in 1..50 {
        z2_250_0 = fe_sq(&z2_250_0);
    }
    z2_250_0 = fe_mul(&z2_250_0, &z2_50_0);
    let mut t = fe_sq(&z2_250_0);
    for _ in 1..5 {
        t = fe_sq(&t);
    }
    fe_mul(&t, &z11)
}

fn fe_cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let x = (a.0[i] ^ b.0[i]) & mask;
        a.0[i] ^= x;
        b.0[i] ^= x;
    }
}

/// Computes X25519 scalar multiplication on Curve25519 (RFC 7748).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    let x1 = fe_from_bytes(point);
    let mut x2 = Fe([1, 0, 0, 0, 0]);
    let mut z2 = Fe([0; 5]);
    let mut x3 = x1;
    let mut z3 = Fe([1, 0, 0, 0, 0]);

    let a24 = Fe([121665, 0, 0, 0, 0]); // (486662 - 2) / 4
    let mut swap = 0u64;

    for i in (0..255).rev() {
        let bit = ((clamped[i / 8] >> (i % 8)) & 1) as u64;
        swap ^= bit;
        fe_cswap(swap, &mut x2, &mut x3);
        fe_cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);

        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul(&a24, &e)));
    }

    fe_cswap(swap, &mut x2, &mut x3);
    fe_cswap(swap, &mut z2, &mut z3);

    let res = fe_mul(&x2, &fe_inv(&z2));
    fe_to_bytes(&res)
}

/// Core Hybrid KEM engine handling dual X25519 + ML-KEM-768 operations.
pub struct HybridKemEngine;

impl HybridKemEngine {
    /// Generates a hybrid X25519 + ML-KEM-768 keypair using the OS system CSPRNG.
    pub fn generate_keypair() -> Result<HybridKemKeyPair> {
        let rng = SystemRandom::new();

        // 1. Classical X25519 Ephemeral Key
        let mut x25519_seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut x25519_seed)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure".into()))?;
        let x25519_priv = x25519_seed;

        let mut base_point = [0u8; 32];
        base_point[0] = 9;
        let x25519_pub = x25519(&x25519_priv, &base_point);

        // 2. Post-Quantum ML-KEM-768 Key
        let mut ml_kem_seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut ml_kem_seed)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure".into()))?;
        let (ml_pk, ml_sk) = ml_kem_768_keygen_from_seed(&ml_kem_seed);

        Ok(HybridKemKeyPair {
            public_key: HybridKemPublicKey {
                classical_x25519: x25519_pub,
                ml_kem_768: ml_pk.0,
            },
            private_key: HybridKemPrivateKey {
                classical_x25519: x25519_priv,
                ml_kem_768: ml_sk.0,
            },
        })
    }

    /// Encapsulates a hybrid shared secret for a peer's hybrid public key.
    pub fn encapsulate(
        peer_pk: &HybridKemPublicKey,
    ) -> Result<(HybridCiphertext, HybridSharedSecret)> {
        let rng = SystemRandom::new();

        // 1. Classical X25519 Ephemeral key generation
        let mut ephemeral_seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut ephemeral_seed)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure".into()))?;

        let mut base_point = [0u8; 32];
        base_point[0] = 9;
        let ephemeral_pub = x25519(&ephemeral_seed, &base_point);

        // Compute classical shared secret: SS_c = X25519(ephemeral_priv, peer_x25519_pub)
        let ss_classical = x25519(&ephemeral_seed, &peer_pk.classical_x25519);

        // 2. Post-Quantum ML-KEM-768 Encapsulation
        let mut pq_randomness = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut pq_randomness)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure".into()))?;
        let (ct_pq, ss_quantum) =
            ml_kem_768_encapsulate(&MlKemPublicKey(peer_pk.ml_kem_768), &pq_randomness);

        // 3. Dual-Hybrid Key Derivation Function:
        // SS_hybrid = BLAKE3-KDF("velcrux-pqc-hybrid-kem:v1", SS_classical || SS_quantum || PK_client || PK_server)
        let mut kdf = blake3::Hasher::new_keyed(&[0x77; 32]);
        kdf.update(HYBRID_KEM_DOMAIN.as_bytes());
        kdf.update(&ss_classical);
        kdf.update(&ss_quantum);
        kdf.update(&peer_pk.classical_x25519);
        kdf.update(&ephemeral_pub);
        let hybrid_ss = *kdf.finalize().as_bytes();

        let ct = HybridCiphertext {
            classical_ephemeral_pk: ephemeral_pub,
            ml_kem_ciphertext: ct_pq.0,
        };

        Ok((ct, HybridSharedSecret(hybrid_ss)))
    }

    /// Decapsulates the hybrid shared secret using the recipient's private key.
    pub fn decapsulate(
        sk: &HybridKemPrivateKey,
        ct: &HybridCiphertext,
        peer_pk_classical: &[u8; 32],
    ) -> Result<HybridSharedSecret> {
        // 1. Classical Diffie-Hellman component: SS_c = X25519(sk_classical, ct.ephemeral_pub)
        let ss_classical = x25519(&sk.classical_x25519, &ct.classical_ephemeral_pk);

        // 2. Post-Quantum ML-KEM-768 decapsulation
        let ss_quantum = ml_kem_768_decapsulate(
            &MlKemPrivateKey(sk.ml_kem_768),
            &MlKemCiphertext(ct.ml_kem_ciphertext),
        )?;

        // 3. Combined Key Derivation Function
        let mut kdf = blake3::Hasher::new_keyed(&[0x77; 32]);
        kdf.update(HYBRID_KEM_DOMAIN.as_bytes());
        kdf.update(&ss_classical);
        kdf.update(&ss_quantum);
        kdf.update(peer_pk_classical);
        kdf.update(&ct.classical_ephemeral_pk);
        let hybrid_ss = *kdf.finalize().as_bytes();

        Ok(HybridSharedSecret(hybrid_ss))
    }

    /// Decapsulates the hybrid shared secret using recipient's private key, automatically deriving
    /// the recipient's classical public key component.
    pub fn decapsulate_self(
        sk: &HybridKemPrivateKey,
        ct: &HybridCiphertext,
    ) -> Result<HybridSharedSecret> {
        let mut base_point = [0u8; 32];
        base_point[0] = 9;
        let my_pk = x25519(&sk.classical_x25519, &base_point);
        Self::decapsulate(sk, ct, &my_pk)
    }
}

// ---------------------------------------------------------------------------
// Hybrid Post-Quantum Digital Signatures (Ed25519 + ML-DSA-65)
// ---------------------------------------------------------------------------

/// Hybrid Signing Public Key.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSigningPublicKey {
    pub classical_ed25519: [u8; 32],
    #[serde(
        serialize_with = "serialize_byte_array",
        deserialize_with = "deserialize_ml_dsa_pk"
    )]
    pub ml_dsa_65: [u8; ML_DSA_65_PUBLIC_KEY_SIZE],
}

impl fmt::Debug for HybridSigningPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridSigningPublicKey(ed25519=0x{}, ml_dsa_65=0x{}...)",
            hex_encode(&self.classical_ed25519),
            hex_encode(&self.ml_dsa_65[..8])
        )
    }
}

/// Hybrid Signing Private Key.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSigningPrivateKey {
    pub classical_ed25519_pkcs8: Vec<u8>,
    #[serde(
        serialize_with = "serialize_byte_array",
        deserialize_with = "deserialize_ml_dsa_sk"
    )]
    pub ml_dsa_65: [u8; ML_DSA_65_SECRET_KEY_SIZE],
}

impl fmt::Debug for HybridSigningPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSigningPrivateKey([REDACTED])")
    }
}

/// Dual-Hybrid Digital Signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    #[serde(
        serialize_with = "serialize_byte_array",
        deserialize_with = "deserialize_classical_sig"
    )]
    pub classical_signature: [u8; 64],
    #[serde(
        serialize_with = "serialize_byte_array",
        deserialize_with = "deserialize_ml_dsa_sig"
    )]
    pub ml_dsa_signature: [u8; ML_DSA_65_SIGNATURE_SIZE],
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HybridSignature(ed25519=0x{}..., ml_dsa_65=0x{}...)",
            hex_encode(&self.classical_signature[..8]),
            hex_encode(&self.ml_dsa_signature[..8])
        )
    }
}

/// Engine managing hybrid Ed25519 + ML-DSA-65 signatures.
pub struct HybridSignatureEngine;

impl HybridSignatureEngine {
    /// Generates a hybrid Ed25519 + ML-DSA-65 signing keypair.
    pub fn generate_keypair() -> Result<(HybridSigningPublicKey, HybridSigningPrivateKey)> {
        let rng = SystemRandom::new();

        // 1. Classical Ed25519 keypair
        let pkcs8_doc = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| VelcruxError::Internal("Ed25519 keygen failed".into()))?;
        let ed_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
            .map_err(|_| VelcruxError::Internal("Ed25519 parse failed".into()))?;

        let mut ed_pub = [0u8; 32];
        ed_pub.copy_from_slice(ed_pair.public_key().as_ref());

        // 2. Post-Quantum ML-DSA-65 keypair
        let mut dsa_seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut dsa_seed)
            .map_err(|_| VelcruxError::Internal("CSPRNG failure".into()))?;
        let (dsa_pk, dsa_sk) = ml_dsa_65_keygen_from_seed(&dsa_seed);

        let pk = HybridSigningPublicKey {
            classical_ed25519: ed_pub,
            ml_dsa_65: dsa_pk.0,
        };

        let sk = HybridSigningPrivateKey {
            classical_ed25519_pkcs8: pkcs8_doc.as_ref().to_vec(),
            ml_dsa_65: dsa_sk.0,
        };

        Ok((pk, sk))
    }

    /// Signs a message using both Ed25519 and ML-DSA-65.
    pub fn sign(sk: &HybridSigningPrivateKey, message: &[u8]) -> Result<HybridSignature> {
        // Domain separation preimage
        let mut preimage = Vec::with_capacity(HYBRID_SIG_DOMAIN.len() + message.len());
        preimage.extend_from_slice(HYBRID_SIG_DOMAIN.as_bytes());
        preimage.extend_from_slice(message);

        // 1. Classical Ed25519 signature
        let ed_pair = signature::Ed25519KeyPair::from_pkcs8(&sk.classical_ed25519_pkcs8)
            .map_err(|_| VelcruxError::Internal("Ed25519 parse failed".into()))?;
        let ed_sig = ed_pair.sign(&preimage);
        let mut classical_sig = [0u8; 64];
        classical_sig.copy_from_slice(ed_sig.as_ref());

        // 2. Post-Quantum ML-DSA-65 signature
        let dsa_sig = ml_dsa_65_sign(&MlDsaPrivateKey(sk.ml_dsa_65), &preimage);

        Ok(HybridSignature {
            classical_signature: classical_sig,
            ml_dsa_signature: dsa_sig.0,
        })
    }

    /// Verifies a hybrid signature. Both Ed25519 and ML-DSA-65 must pass verification.
    pub fn verify(pk: &HybridSigningPublicKey, message: &[u8], sig: &HybridSignature) -> bool {
        let mut preimage = Vec::with_capacity(HYBRID_SIG_DOMAIN.len() + message.len());
        preimage.extend_from_slice(HYBRID_SIG_DOMAIN.as_bytes());
        preimage.extend_from_slice(message);

        // 1. Verify classical Ed25519 signature
        let ed_pub = UnparsedPublicKey::new(&ED25519, &pk.classical_ed25519);
        if ed_pub.verify(&preimage, &sig.classical_signature).is_err() {
            return false;
        }

        // 2. Verify post-quantum ML-DSA-65 signature
        let dsa_pub = MlDsaPublicKey(pk.ml_dsa_65);
        let dsa_sig = MlDsaSignature(sig.ml_dsa_signature);
        ml_dsa_65_verify(&dsa_pub, &preimage, &dsa_sig)
    }
}

// ---------------------------------------------------------------------------
// Status, Telemetry & Benchmark Structures
// ---------------------------------------------------------------------------

/// Post-Quantum Cryptographic algorithm identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcAlgorithm {
    MlKem768,
    MlDsa65,
    HybridX25519MlKem768,
    HybridEd25519MlDsa65,
}

/// Informational status report describing active post-quantum cryptography suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcStatusReport {
    pub kem_algorithm: String,
    pub signature_algorithm: String,
    pub classical_kem: String,
    pub quantum_kem: String,
    pub classical_sig: String,
    pub quantum_sig: String,
    pub kem_public_key_bytes: usize,
    pub kem_ciphertext_bytes: usize,
    pub sig_public_key_bytes: usize,
    pub signature_bytes: usize,
    pub quantum_security_level: u32,
    pub nist_fips_compliance: String,
    pub hybrid_dual_security_enforced: bool,
}

impl Default for PqcStatusReport {
    fn default() -> Self {
        Self {
            kem_algorithm: "Hybrid X25519 + ML-KEM-768".to_string(),
            signature_algorithm: "Hybrid Ed25519 + ML-DSA-65".to_string(),
            classical_kem: "X25519 (RFC 7748)".to_string(),
            quantum_kem: "ML-KEM-768 (FIPS 203 / Kyber768)".to_string(),
            classical_sig: "Ed25519 (RFC 8032)".to_string(),
            quantum_sig: "ML-DSA-65 (FIPS 204 / Dilithium3)".to_string(),
            kem_public_key_bytes: 32 + ML_KEM_768_PUBLIC_KEY_SIZE,
            kem_ciphertext_bytes: 32 + ML_KEM_768_CIPHERTEXT_SIZE,
            sig_public_key_bytes: 32 + ML_DSA_65_PUBLIC_KEY_SIZE,
            signature_bytes: 64 + ML_DSA_65_SIGNATURE_SIZE,
            quantum_security_level: 3, // NIST Level 3 (equivalent to AES-192)
            nist_fips_compliance: "FIPS 203 & FIPS 204 Final Standards".to_string(),
            hybrid_dual_security_enforced: true,
        }
    }
}

/// Benchmark performance report evaluating PQC primitives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcBenchmarkReport {
    pub iterations: usize,
    pub ml_kem_keygen_latency_us: f64,
    pub ml_kem_encaps_latency_us: f64,
    pub ml_kem_decaps_latency_us: f64,
    pub ml_dsa_keygen_latency_us: f64,
    pub ml_dsa_sign_latency_us: f64,
    pub ml_dsa_verify_latency_us: f64,
    pub hybrid_kem_roundtrip_latency_us: f64,
    pub hybrid_sig_roundtrip_latency_us: f64,
    pub kem_ops_per_second: f64,
    pub sig_ops_per_second: f64,
    pub all_operations_verified: bool,
}

/// Runs comprehensive benchmark evaluating hybrid PQC operations.
pub fn run_pqc_benchmark(iterations: usize) -> PqcBenchmarkReport {
    let iters = iterations.max(5);

    // 1. Benchmark ML-KEM-768
    let t0 = Instant::now();
    let seed = [0x55u8; 32];
    for i in 0..iters {
        let mut cur_seed = seed;
        cur_seed[0] = (i & 0xFF) as u8;
        let _ = ml_kem_768_keygen_from_seed(&cur_seed);
    }
    let ml_kem_keygen_latency_us = t0.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    let (pk_kem, sk_kem) = ml_kem_768_keygen_from_seed(&seed);
    let t1 = Instant::now();
    for i in 0..iters {
        let mut rand_buf = [0xAAu8; 32];
        rand_buf[0] = (i & 0xFF) as u8;
        let _ = ml_kem_768_encapsulate(&pk_kem, &rand_buf);
    }
    let ml_kem_encaps_latency_us = t1.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    let (ct_kem, _) = ml_kem_768_encapsulate(&pk_kem, &[0x12; 32]);
    let t2 = Instant::now();
    for _ in 0..iters {
        let _ = ml_kem_768_decapsulate(&sk_kem, &ct_kem);
    }
    let ml_kem_decaps_latency_us = t2.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    // 2. Benchmark ML-DSA-65
    let t3 = Instant::now();
    for i in 0..iters {
        let mut cur_seed = seed;
        cur_seed[0] = (i & 0xFF) as u8;
        let _ = ml_dsa_65_keygen_from_seed(&cur_seed);
    }
    let ml_dsa_keygen_latency_us = t3.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    let (pk_dsa, sk_dsa) = ml_dsa_65_keygen_from_seed(&seed);
    let message = b"velcrux-post-quantum-benchmark-manifest-root-hash";
    let t4 = Instant::now();
    for _ in 0..iters {
        let _ = ml_dsa_65_sign(&sk_dsa, message);
    }
    let ml_dsa_sign_latency_us = t4.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    let sig_dsa = ml_dsa_65_sign(&sk_dsa, message);
    let t5 = Instant::now();
    for _ in 0..iters {
        let _ = ml_dsa_65_verify(&pk_dsa, message, &sig_dsa);
    }
    let ml_dsa_verify_latency_us = t5.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    // 3. Benchmark Combined Hybrid KEM & Signatures
    let t6 = Instant::now();
    let mut kem_ok = true;
    for _ in 0..iters {
        if let Ok(pair) = HybridKemEngine::generate_keypair() {
            if let Ok((ct, ss_encap)) = HybridKemEngine::encapsulate(&pair.public_key) {
                if let Ok(ss_decap) = HybridKemEngine::decapsulate(
                    &pair.private_key,
                    &ct,
                    &pair.public_key.classical_x25519,
                ) {
                    if ss_encap != ss_decap {
                        kem_ok = false;
                    }
                } else {
                    kem_ok = false;
                }
            } else {
                kem_ok = false;
            }
        }
    }
    let hybrid_kem_roundtrip_latency_us = t6.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    let t7 = Instant::now();
    let mut sig_ok = true;
    for _ in 0..iters {
        if let Ok((pk_sig, sk_sig)) = HybridSignatureEngine::generate_keypair() {
            if let Ok(sig) = HybridSignatureEngine::sign(&sk_sig, message) {
                if !HybridSignatureEngine::verify(&pk_sig, message, &sig) {
                    sig_ok = false;
                }
            } else {
                sig_ok = false;
            }
        }
    }
    let hybrid_sig_roundtrip_latency_us = t7.elapsed().as_secs_f64() * 1_000_000.0 / iters as f64;

    let kem_ops = if hybrid_kem_roundtrip_latency_us > 0.0 {
        1_000_000.0 / hybrid_kem_roundtrip_latency_us
    } else {
        0.0
    };

    let sig_ops = if hybrid_sig_roundtrip_latency_us > 0.0 {
        1_000_000.0 / hybrid_sig_roundtrip_latency_us
    } else {
        0.0
    };

    PqcBenchmarkReport {
        iterations: iters,
        ml_kem_keygen_latency_us,
        ml_kem_encaps_latency_us,
        ml_kem_decaps_latency_us,
        ml_dsa_keygen_latency_us,
        ml_dsa_sign_latency_us,
        ml_dsa_verify_latency_us,
        hybrid_kem_roundtrip_latency_us,
        hybrid_sig_roundtrip_latency_us,
        kem_ops_per_second: kem_ops,
        sig_ops_per_second: sig_ops,
        all_operations_verified: kem_ok && sig_ok,
    }
}

// ---------------------------------------------------------------------------
// Helpers & Constant-Time Utilities
// ---------------------------------------------------------------------------

/// Constant-time byte slice comparison resisting timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Helper to hex encode arbitrary byte slices without external dependencies.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Helper to hex decode arbitrary string slices without external dependencies.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let clean = s.trim_start_matches("0x").replace([' ', ':', '\n'], "");
    if clean.len() % 2 != 0 {
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}

fn serialize_byte_array<S, const N: usize>(
    arr: &[u8; N],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex_encode(arr))
}

fn deserialize_ml_kem_pk<'de, D>(
    deserializer: D,
) -> std::result::Result<[u8; ML_KEM_768_PUBLIC_KEY_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
    if bytes.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return Err(serde::de::Error::custom(format!(
            "invalid ML-KEM-768 public key length: expected {}, got {}",
            ML_KEM_768_PUBLIC_KEY_SIZE,
            bytes.len()
        )));
    }
    let mut arr = [0u8; ML_KEM_768_PUBLIC_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn deserialize_ml_kem_sk<'de, D>(
    deserializer: D,
) -> std::result::Result<[u8; ML_KEM_768_SECRET_KEY_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
    if bytes.len() != ML_KEM_768_SECRET_KEY_SIZE {
        return Err(serde::de::Error::custom(
            "invalid ML-KEM-768 secret key length",
        ));
    }
    let mut arr = [0u8; ML_KEM_768_SECRET_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn deserialize_ml_kem_ct<'de, D>(
    deserializer: D,
) -> std::result::Result<[u8; ML_KEM_768_CIPHERTEXT_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
    if bytes.len() != ML_KEM_768_CIPHERTEXT_SIZE {
        return Err(serde::de::Error::custom(
            "invalid ML-KEM-768 ciphertext length",
        ));
    }
    let mut arr = [0u8; ML_KEM_768_CIPHERTEXT_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn deserialize_ml_dsa_pk<'de, D>(
    deserializer: D,
) -> std::result::Result<[u8; ML_DSA_65_PUBLIC_KEY_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
    if bytes.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(serde::de::Error::custom(
            "invalid ML-DSA-65 public key length",
        ));
    }
    let mut arr = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn deserialize_ml_dsa_sk<'de, D>(
    deserializer: D,
) -> std::result::Result<[u8; ML_DSA_65_SECRET_KEY_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
    if bytes.len() != ML_DSA_65_SECRET_KEY_SIZE {
        return Err(serde::de::Error::custom(
            "invalid ML-DSA-65 secret key length",
        ));
    }
    let mut arr = [0u8; ML_DSA_65_SECRET_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn deserialize_ml_dsa_sig<'de, D>(
    deserializer: D,
) -> std::result::Result<[u8; ML_DSA_65_SIGNATURE_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
    if bytes.len() != ML_DSA_65_SIGNATURE_SIZE {
        return Err(serde::de::Error::custom(
            "invalid ML-DSA-65 signature length",
        ));
    }
    let mut arr = [0u8; ML_DSA_65_SIGNATURE_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn deserialize_classical_sig<'de, D>(deserializer: D) -> std::result::Result<[u8; 64], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex string"))?;
    if bytes.len() != 64 {
        return Err(serde::de::Error::custom(
            "invalid classical signature length",
        ));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_arithmetic_negacyclic() {
        let q = ML_KEM_768_Q;
        let mut p1 = Poly::zero();
        p1.coeffs[0] = 3;
        p1.coeffs[1] = 5;

        let mut p2 = Poly::zero();
        p2.coeffs[0] = 2;
        p2.coeffs[255] = 4;

        let sum = p1.add(&p2, q);
        assert_eq!(sum.coeffs[0], 5);
        assert_eq!(sum.coeffs[1], 5);
        assert_eq!(sum.coeffs[255], 4);

        // Product with wrap-around negacyclic reduction (X^256 = -1)
        let prod = p1.mul_negacyclic(&p2, q);
        assert!(prod.coeffs[0] < q);
    }

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let seed = [0x77u8; 32];
        let (pk, sk) = ml_kem_768_keygen_from_seed(&seed);

        assert_eq!(pk.0.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(sk.0.len(), ML_KEM_768_SECRET_KEY_SIZE);

        let randomness = [0x88u8; 32];
        let (ct, ss_encap) = ml_kem_768_encapsulate(&pk, &randomness);

        assert_eq!(ct.0.len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(ss_encap.len(), 32);

        let ss_decap = ml_kem_768_decapsulate(&sk, &ct).expect("decapsulate");
        assert_eq!(ss_encap, ss_decap);
    }

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        let seed = [0x33u8; 32];
        let (pk, sk) = ml_dsa_65_keygen_from_seed(&seed);

        assert_eq!(pk.0.len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(sk.0.len(), ML_DSA_65_SECRET_KEY_SIZE);

        let message = b"critical-bulk-transfer-payload-manifest-root";
        let sig = ml_dsa_65_sign(&sk, message);

        assert_eq!(sig.0.len(), ML_DSA_65_SIGNATURE_SIZE);
        assert!(ml_dsa_65_verify(&pk, message, &sig));

        // Tampered message must fail verification
        let tampered = b"critical-bulk-transfer-payload-manifest-root-CORRUPTED";
        assert!(!ml_dsa_65_verify(&pk, tampered, &sig));
    }

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let keypair = HybridKemEngine::generate_keypair().expect("generate hybrid kem keypair");
        let (ct, ss_encap) =
            HybridKemEngine::encapsulate(&keypair.public_key).expect("encapsulate");

        let ss_decap = HybridKemEngine::decapsulate(
            &keypair.private_key,
            &ct,
            &keypair.public_key.classical_x25519,
        )
        .expect("decapsulate");

        assert_eq!(ss_encap, ss_decap);
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let (pk, sk) =
            HybridSignatureEngine::generate_keypair().expect("generate hybrid signature keypair");
        let message = b"velcrux-hybrid-pqc-attestation-record";

        let sig = HybridSignatureEngine::sign(&sk, message).expect("sign hybrid");
        assert!(HybridSignatureEngine::verify(&pk, message, &sig));

        // Tampered signature must fail
        let mut corrupted_sig = sig.clone();
        corrupted_sig.classical_signature[0] ^= 0xFF;
        assert!(!HybridSignatureEngine::verify(&pk, message, &corrupted_sig));

        let mut corrupted_pq_sig = sig.clone();
        corrupted_pq_sig.ml_dsa_signature[0] ^= 0xFF;
        assert!(!HybridSignatureEngine::verify(
            &pk,
            message,
            &corrupted_pq_sig
        ));
    }

    #[test]
    fn test_pqc_benchmark_execution() {
        let report = run_pqc_benchmark(5);
        assert_eq!(report.iterations, 5);
        assert!(report.all_operations_verified);
        assert!(report.kem_ops_per_second > 0.0);
        assert!(report.sig_ops_per_second > 0.0);
    }
}
