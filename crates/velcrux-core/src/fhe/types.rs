//! Types, configurations, and cryptographic representations for Distributed
//! Homomorphic Encrypted Query & Search Engine over Sharded Storage (ADR-084).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Standard polynomial degree N for BFV ring R_q = Z_q[X]/(X^N + 1).
pub const FHE_DEFAULT_DEGREE: usize = 1024;
/// Default 50-bit prime coefficient modulus q: $2^{50} + 153369$, where $q \equiv 1 \pmod t$.
pub const FHE_DEFAULT_COEFF_MODULUS: u64 = 1125899908153369;
/// Default plaintext modulus t (e.g. 65537, standard Fermat prime).
pub const FHE_DEFAULT_PLAIN_MODULUS: u64 = 65537;
/// Default discrete Gaussian error standard deviation sigma.
pub const FHE_DEFAULT_NOISE_STD_DEV: f64 = 3.2;

/// Parameter set defining the leveled homomorphic encryption scheme (BFV).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FheParams {
    /// Degree N of cyclotomic polynomial quotient ring $X^N + 1$ (must be power of two).
    pub poly_degree: usize,
    /// Ciphertext coefficient modulus $q$.
    pub coeff_modulus: u64,
    /// Plaintext coefficient modulus $t$.
    pub plain_modulus: u64,
    /// Discrete Gaussian error standard deviation $\sigma$.
    pub noise_std_dev: f64,
    /// Scaling factor $\Delta = \lfloor q / t \rfloor$.
    pub delta: u64,
}

impl Default for FheParams {
    fn default() -> Self {
        let q = FHE_DEFAULT_COEFF_MODULUS;
        let t = FHE_DEFAULT_PLAIN_MODULUS;
        let delta = q / t;
        Self {
            poly_degree: FHE_DEFAULT_DEGREE,
            coeff_modulus: q,
            plain_modulus: t,
            noise_std_dev: FHE_DEFAULT_NOISE_STD_DEV,
            delta,
        }
    }
}

impl FheParams {
    /// Initialize with custom parameters and compute $\Delta$.
    pub fn new(
        poly_degree: usize,
        coeff_modulus: u64,
        plain_modulus: u64,
    ) -> Result<Self, FheError> {
        if !poly_degree.is_power_of_two() || poly_degree < 64 || poly_degree > 8192 {
            return Err(FheError::InvalidParams(format!(
                "poly_degree ({}) must be a power of two between 64 and 8192",
                poly_degree
            )));
        }
        if coeff_modulus <= plain_modulus {
            return Err(FheError::InvalidParams(format!(
                "coeff_modulus ({}) must be strictly greater than plain_modulus ({})",
                coeff_modulus, plain_modulus
            )));
        }
        if plain_modulus < 2 {
            return Err(FheError::InvalidParams(
                "plain_modulus must be at least 2".to_string(),
            ));
        }

        let delta = coeff_modulus / plain_modulus;
        Ok(Self {
            poly_degree,
            coeff_modulus,
            plain_modulus,
            noise_std_dev: FHE_DEFAULT_NOISE_STD_DEV,
            delta,
        })
    }

    /// Calculate initial noise budget in bits: $\approx \log_2(\Delta) - 3.2$.
    #[must_use]
    pub fn initial_noise_budget_bits(&self) -> f64 {
        (self.delta as f64).log2().max(0.0)
    }
}

/// A polynomial in the quotient ring $R_q = \mathbb{Z}_q[X] / (X^N + 1)$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Polynomial {
    /// Coefficients $a_0, a_1, \dots, a_{N-1}$ where $P(X) = \sum a_i X^i$.
    pub coeffs: Vec<u64>,
}

impl Polynomial {
    /// Create a zero polynomial of degree N.
    #[must_use]
    pub fn zero(degree: usize) -> Self {
        Self {
            coeffs: vec![0u64; degree],
        }
    }

    /// Degree of polynomial.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.coeffs.len()
    }
}

/// Secret key $s \in R_q$ with ternary coefficients $\in \{-1, 0, 1\}$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FheSecretKey {
    pub s: Polynomial,
}

/// Public key $(p_0, p_1) \in R_q^2$ where $p_0 = -(a \cdot s + e) \pmod q, p_1 = a$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FhePublicKey {
    pub p0: Polynomial,
    pub p1: Polynomial,
}

/// Relinearization key for reducing degree-2 ciphertexts back to degree-1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FheRelinKey {
    pub r0: Polynomial,
    pub r1: Polynomial,
}

/// Key pair bundling secret, public, and relinearization keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FheKeyPair {
    pub params: FheParams,
    pub secret_key: FheSecretKey,
    pub public_key: FhePublicKey,
    pub relin_key: FheRelinKey,
}

/// Plaintext polynomial $m(X) \in R_t = \mathbb{Z}_t[X] / (X^N + 1)$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FhePlaintext {
    pub poly: Polynomial,
}

impl FhePlaintext {
    /// Create a constant scalar plaintext: $m(X) = c$.
    #[must_use]
    pub fn from_scalar(value: u64, degree: usize, plain_modulus: u64) -> Self {
        let mut coeffs = vec![0u64; degree];
        coeffs[0] = value % plain_modulus;
        Self {
            poly: Polynomial { coeffs },
        }
    }

    /// Create a plaintext from a slice of values (SIMD batch packing into slots).
    #[must_use]
    pub fn from_values(values: &[u64], degree: usize, plain_modulus: u64) -> Self {
        let mut coeffs = vec![0u64; degree];
        for (i, &v) in values.iter().take(degree).enumerate() {
            coeffs[i] = v % plain_modulus;
        }
        Self {
            poly: Polynomial { coeffs },
        }
    }
}

/// BFV Ciphertext $(c_0, c_1) \in R_q^2$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FheCiphertext {
    pub c0: Polynomial,
    pub c1: Polynomial,
    /// Estimated remaining noise budget in bits.
    pub noise_budget_bits: i64,
}

/// Encrypted metadata record stored on untrusted storage nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheEncryptedRecord {
    /// Unique chunk or object identifier (e.g. BLAKE3 hash hex).
    pub chunk_id: String,
    /// Tenant or owner identifier.
    pub tenant_id: String,
    /// Storage tier code (0: Hot, 1: Warm, 2: Cold, 3: DeepArchive).
    pub tier_code: u8,
    /// Encrypted numerical attributes vector (e.g. [size_cat, access_freq, modified_epoch]).
    pub encrypted_attributes: FheCiphertext,
    /// Additional metadata tags.
    pub tags: Vec<String>,
}

/// An encrypted search query sent to untrusted storage nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheQuery {
    /// Query identifier.
    pub query_id: String,
    /// Encrypted attribute query vector.
    pub query_vector: FheCiphertext,
    /// Target tenant ID.
    pub tenant_id: String,
}

/// Result of evaluating an encrypted search query over storage records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheQueryResult {
    pub query_id: String,
    pub matching_chunk_ids: Vec<String>,
    pub total_records_scanned: usize,
    pub evaluation_time_us: u64,
    pub min_noise_budget_remaining_bits: i64,
}

/// Telemetry status of the FHE search engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheStatus {
    pub engine_status: String,
    pub poly_degree: usize,
    pub coeff_modulus: u64,
    pub plain_modulus: u64,
    pub scale_factor_delta: u64,
    pub initial_noise_budget_bits: f64,
    pub total_indexed_records: usize,
}

/// Benchmark performance metrics report for homomorphic operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheBenchmarkReport {
    pub poly_degree: usize,
    pub records_evaluated: usize,
    pub keygen_latency_us: f64,
    pub encryption_latency_us: f64,
    pub decryption_latency_us: f64,
    pub homomorphic_addition_latency_ns: f64,
    pub homomorphic_plain_mul_latency_us: f64,
    pub homomorphic_cipher_mul_latency_us: f64,
    pub query_scan_throughput_records_per_sec: f64,
    pub noise_budget_initial_bits: f64,
    pub noise_budget_consumed_bits: f64,
    pub decryption_accuracy_percent: f64,
}

/// Domain errors encountered during FHE operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum FheError {
    #[error("Invalid FHE parameters: {0}")]
    InvalidParams(String),

    #[error("Polynomial degree mismatch: expected {expected}, found {actual}")]
    DegreeMismatch { expected: usize, actual: usize },

    #[error("Noise budget exhausted: decryption error inevitable ({bits} bits remaining)")]
    NoiseBudgetExhausted { bits: i64 },

    #[error("Cryptographic verification failed: {0}")]
    VerificationFailed(String),

    #[error("Storage record not found: {0}")]
    RecordNotFound(String),
}

/// Result alias for FHE operations.
pub type FheResult<T> = Result<T, FheError>;
