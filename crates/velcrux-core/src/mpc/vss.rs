#![forbid(unsafe_code)]

//! Verifiable Secret Sharing (VSS) via Shamir's Secret Sharing and Feldman's Public Commitments.

use serde::{Deserialize, Serialize};

use super::curve::Point;
use super::scalar::Scalar;
use crate::error::{ProtocolError, Result, VelcruxError};

/// Secret share held by a participant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretShare {
    /// 1-based participant identifier ($1 \le i \le n$).
    pub participant_id: u32,
    /// Secret evaluation $s_i = f(i) \pmod \ell$.
    pub share: Scalar,
}

impl SecretShare {
    /// Secure zeroization on cleanup.
    pub fn zeroize(&mut self) {
        self.share.zeroize();
    }
}

impl Drop for SecretShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Feldman VSS public commitment package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeldmanCommitmentPackage {
    /// Polynomial degree threshold $t$.
    pub threshold: u32,
    /// Public commitments to polynomial coefficients: $C_k = a_k \cdot B$ for $0 \le k < t$.
    /// $C_0$ is the master group public key $Y = s \cdot B$.
    pub commitments: Vec<Point>,
}

impl FeldmanCommitmentPackage {
    /// Master public key $Y = C_0$.
    pub fn group_public_key(&self) -> Result<Point> {
        self.commitments
            .first()
            .copied()
            .ok_or_else(|| VelcruxError::Protocol(ProtocolError::Malformed("empty commitments")))
    }

    /// Verifies that participant $i$'s secret share $s_i$ is consistent with public commitments:
    /// $s_i \cdot B \stackrel{?}{=} \sum_{k=0}^{t-1} (i^k) \cdot C_k$.
    pub fn verify_share(&self, share: &SecretShare) -> bool {
        if self.commitments.len() < self.threshold as usize {
            return false;
        }

        let lhs = Point::generator().mul_scalar(&share.share);

        let mut rhs = Point::IDENTITY;
        let id_scalar = Scalar::from_u64(share.participant_id as u64);
        let mut id_pow = Scalar::ONE;

        for commitment in &self.commitments {
            let term = commitment.mul_scalar(&id_pow);
            rhs = rhs.add(&term);
            id_pow = id_pow.mul(&id_scalar);
        }

        lhs == rhs
    }
}

/// Polynomial over $\mathbb{F}_\ell$ of degree $t - 1$.
pub struct Polynomial {
    pub coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Generates a random polynomial $f(x) = s + a_1 x + \dots + a_{t-1} x^{t-1}$ with secret $s = f(0)$.
    pub fn random_with_secret(secret: &Scalar, threshold: u32) -> Self {
        let mut coefficients = Vec::with_capacity(threshold as usize);
        coefficients.push(*secret);
        for _ in 1..threshold {
            coefficients.push(Scalar::random_nonzero());
        }
        Self { coefficients }
    }

    /// Evaluates polynomial $f(x) \pmod \ell$ at $x$ using Horner's method.
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for coeff in self.coefficients.iter().rev() {
            acc = acc.mul(x).add(coeff);
        }
        acc
    }

    /// Generates Feldman public commitments $C_k = a_k \cdot B$.
    pub fn commitments(&self) -> FeldmanCommitmentPackage {
        let gen = Point::generator();
        let commitments = self
            .coefficients
            .iter()
            .map(|a| gen.mul_scalar(a))
            .collect();
        FeldmanCommitmentPackage {
            threshold: self.coefficients.len() as u32,
            commitments,
        }
    }

    /// Splits secret into $n$ verifiable shares for $t$-of-$n$ threshold scheme.
    pub fn generate_shares(&self, num_participants: u32) -> Vec<SecretShare> {
        let mut shares = Vec::with_capacity(num_participants as usize);
        for i in 1..=num_participants {
            let x = Scalar::from_u64(i as u64);
            let s_i = self.evaluate(&x);
            shares.push(SecretShare {
                participant_id: i,
                share: s_i,
            });
        }
        shares
    }
}

/// Computes Lagrange basis coefficient $\lambda_i(0)$ for participant $i$ within quorum $S$:
/// $\lambda_i(0) = \prod_{j \in S, j \neq i} \frac{j}{j - i} \pmod \ell$.
pub fn compute_lagrange_coefficient(participant_id: u32, quorum: &[u32]) -> Result<Scalar> {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &j in quorum {
        if j == participant_id {
            continue;
        }
        let j_scalar = Scalar::from_u64(j as u64);
        numerator = numerator.mul(&j_scalar);

        // diff = (j - i) mod l
        let diff = if j > participant_id {
            Scalar::from_u64((j - participant_id) as u64)
        } else {
            let pos_diff = Scalar::from_u64((participant_id - j) as u64);
            pos_diff.neg()
        };
        denominator = denominator.mul(&diff);
    }

    let den_inv = denominator.invert().ok_or_else(|| {
        VelcruxError::Protocol(ProtocolError::Malformed(
            "duplicate or invalid participant in quorum",
        ))
    })?;

    Ok(numerator.mul(&den_inv))
}

/// Reconstructs secret $s = f(0)$ from any quorum of $t$ valid shares:
/// $s = \sum_{i \in S} \lambda_i(0) \cdot s_i \pmod \ell$.
pub fn reconstruct_secret(shares: &[SecretShare]) -> Result<Scalar> {
    let quorum: Vec<u32> = shares.iter().map(|s| s.participant_id).collect();
    let mut secret = Scalar::ZERO;

    for share in shares {
        let lambda = compute_lagrange_coefficient(share.participant_id, &quorum)?;
        let term = lambda.mul(&share.share);
        secret = secret.add(&term);
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_and_feldman_vss_roundtrip() {
        let secret = Scalar::from_u64(4242424242);
        let threshold = 3;
        let total = 5;

        let poly = Polynomial::random_with_secret(&secret, threshold);
        let pkg = poly.commitments();
        let shares = poly.generate_shares(total);

        assert_eq!(shares.len(), 5);

        // Verify each share with Feldman commitments
        for s in &shares {
            assert!(pkg.verify_share(s));
        }

        // Test quorum of {1, 3, 5}
        let quorum_shares = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = reconstruct_secret(&quorum_shares).expect("reconstruct");
        assert_eq!(recovered, secret);

        // Test quorum of {2, 3, 4}
        let quorum_shares2 = vec![shares[1].clone(), shares[2].clone(), shares[3].clone()];
        let recovered2 = reconstruct_secret(&quorum_shares2).expect("reconstruct 2");
        assert_eq!(recovered2, secret);
    }
}
