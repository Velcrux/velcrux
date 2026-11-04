#![forbid(unsafe_code)]

//! Non-Interactive Zero-Knowledge Proofs (NIZK) of Discrete Logarithm Knowledge.
//!
//! Proves knowledge of secret share $s_i$ such that $Y_i = s_i \cdot B$ without revealing $s_i$,
//! preventing rogue-key and adversarial injection attacks during distributed key generation.

use serde::{Deserialize, Serialize};

use super::curve::Point;
use super::scalar::Scalar;

/// Zero-knowledge proof of discrete logarithm knowledge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrDlogProof {
    /// 1-based participant identifier.
    pub participant_id: u32,
    /// Verification public key $Y_i = s_i \cdot B$.
    pub public_key: Point,
    /// Ephemeral commitment $R_{zkp} = k \cdot B$.
    pub commitment: Point,
    /// Schnorr response $z_{zkp} = k + e \cdot s_i \pmod \ell$.
    pub response: Scalar,
}

impl SchnorrDlogProof {
    /// Computes Fiat-Shamir challenge $e = H(\text{domain} \,||\, i \,||\, Y_i \,||\, R_{zkp} \,||\, \text{context}) \pmod \ell$.
    pub fn compute_challenge(
        participant_id: u32,
        public_key: &Point,
        commitment: &Point,
        context: &[u8],
    ) -> Scalar {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-mpc-zkp-dleq:v1\n");
        hasher.update(&participant_id.to_le_bytes());
        hasher.update(&public_key.to_bytes());
        hasher.update(&commitment.to_bytes());
        hasher.update(context);

        let mut output = [0u8; 64];
        let mut xof = hasher.finalize_xof();
        xof.fill(&mut output);
        Scalar::from_bytes_mod_order_wide(&output)
    }

    /// Generates NIZK proof of knowledge for secret $s_i$.
    pub fn prove(participant_id: u32, secret: &Scalar, context: &[u8]) -> Self {
        let gen = Point::generator();
        let public_key = gen.mul_scalar(secret);

        let k = Scalar::random_nonzero();
        let commitment = gen.mul_scalar(&k);

        let challenge = Self::compute_challenge(participant_id, &public_key, &commitment, context);
        let response = k.add(&challenge.mul(secret));

        Self {
            participant_id,
            public_key,
            commitment,
            response,
        }
    }

    /// Verifies NIZK proof: $z_{zkp} \cdot B \stackrel{?}{=} R_{zkp} + e \cdot Y_i$.
    pub fn verify(&self, context: &[u8]) -> bool {
        let gen = Point::generator();
        let challenge = Self::compute_challenge(
            self.participant_id,
            &self.public_key,
            &self.commitment,
            context,
        );

        let lhs = gen.mul_scalar(&self.response);
        let rhs = self.commitment.add(&self.public_key.mul_scalar(&challenge));

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_prove_and_verify() {
        let secret = Scalar::from_u64(987654321);
        let context = b"cluster-session-001";

        let proof = SchnorrDlogProof::prove(1, &secret, context);
        assert!(proof.verify(context));

        // Tampering with response must fail verification
        let mut bad_proof = proof.clone();
        bad_proof.response = bad_proof.response.add(&Scalar::ONE);
        assert!(!bad_proof.verify(context));

        // Different context must fail verification
        assert!(!proof.verify(b"different-context"));
    }
}
