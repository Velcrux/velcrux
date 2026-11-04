#![forbid(unsafe_code)]

//! Prime field scalar arithmetic over the Curve25519 order field $\mathbb{F}_\ell$.
//!
//! $\ell = 2^{252} + 27742317777372353535851937790883648493$
//! Hex: `0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed`

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Modulus $\ell$ in little-endian 64-bit limbs.
pub const SCALAR_ORDER_LIMBS: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// 256-bit scalar integer in $\mathbb{F}_\ell$ with little-endian limbs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scalar(pub [u64; 4]);

impl Scalar {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Construct a scalar from a single u64 value.
    pub const fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }

    /// Check if scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Convert scalar to little-endian 32-byte array.
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        out
    }

    /// Convert scalar to 64-character lowercase hexadecimal string (big-endian display).
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes_le();
        let mut hex = String::with_capacity(64);
        for b in bytes.iter().rev() {
            hex.push_str(&format!("{:02x}", b));
        }
        hex
    }

    /// Parse scalar from 64-character lowercase hexadecimal string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let hex_idx = (31 - i) * 2;
            let byte_val = u8::from_str_radix(&clean[hex_idx..hex_idx + 2], 16).ok()?;
            bytes[i] = byte_val;
        }
        Some(Self::from_bytes_le(&bytes))
    }

    /// Parse scalar from 32 little-endian bytes and reduce modulo $\ell$.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(buf);
        }
        Self(limbs).reduce()
    }

    /// Parse scalar from arbitrary-length byte slice (up to 64 bytes) modulo $\ell$.
    pub fn from_bytes_mod_order_wide(bytes: &[u8]) -> Self {
        let mut acc = Self::ZERO;
        for &byte in bytes.iter().rev() {
            for _ in 0..8 {
                acc = acc.add(&acc);
            }
            acc = acc.add(&Self::from_u64(byte as u64));
        }
        acc
    }

    /// Hash domain and payload to scalar in $\mathbb{F}_\ell$ using BLAKE3.
    pub fn hash_to_scalar(domain: &[u8], payload: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"velcrux-mpc-scalar-v1\n");
        hasher.update(domain);
        hasher.update(b"\n");
        hasher.update(payload);
        let mut output = [0u8; 64];
        let mut xof = hasher.finalize_xof();
        xof.fill(&mut output);
        Self::from_bytes_mod_order_wide(&output)
    }

    /// Derive random non-zero scalar using system entropy.
    pub fn random_nonzero() -> Self {
        loop {
            let s = Self::random();
            if !s.is_zero() {
                return s;
            }
        }
    }

    /// Derive cryptographically strong random scalar in $\mathbb{F}_\ell$.
    pub fn random() -> Self {
        let mut bytes = [0u8; 64];
        for chunk in bytes.chunks_exact_mut(8) {
            let r = rand::random::<u64>();
            chunk.copy_from_slice(&r.to_le_bytes());
        }
        Self::from_bytes_mod_order_wide(&bytes)
    }

    /// True if limbs >= $\ell$.
    fn is_ge_order(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > SCALAR_ORDER_LIMBS[i] {
                return true;
            }
            if self.0[i] < SCALAR_ORDER_LIMBS[i] {
                return false;
            }
        }
        true
    }

    /// Reduce modulo $\ell$ if $\ge \ell$.
    pub fn reduce(mut self) -> Self {
        while self.is_ge_order() {
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = (self.0[i] as i128) - (SCALAR_ORDER_LIMBS[i] as i128) - borrow;
                if diff < 0 {
                    self.0[i] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    self.0[i] = diff as u64;
                    borrow = 0;
                }
            }
        }
        self
    }

    /// Addition $(a + b) \pmod \ell$.
    pub fn add(&self, other: &Self) -> Self {
        let mut carry = 0u128;
        let mut res = [0u64; 4];
        for i in 0..4 {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            res[i] = sum as u64;
            carry = sum >> 64;
        }

        let mut out = Self(res);
        if carry > 0 || out.is_ge_order() {
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = (out.0[i] as i128) - (SCALAR_ORDER_LIMBS[i] as i128) - borrow;
                if diff < 0 {
                    out.0[i] = (diff + (1i128 << 64)) as u64;
                    borrow = 1;
                } else {
                    out.0[i] = diff as u64;
                    borrow = 0;
                }
            }
        }
        out
    }

    /// Subtraction $(a - b) \pmod \ell$.
    pub fn sub(&self, other: &Self) -> Self {
        let mut borrow = 0i128;
        let mut res = [0u64; 4];
        for i in 0..4 {
            let diff = (self.0[i] as i128) - (other.0[i] as i128) - borrow;
            if diff < 0 {
                res[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                res[i] = diff as u64;
                borrow = 0;
            }
        }

        let mut out = Self(res);
        if borrow > 0 {
            let mut carry = 0u128;
            for i in 0..4 {
                let sum = (out.0[i] as u128) + (SCALAR_ORDER_LIMBS[i] as u128) + carry;
                out.0[i] = sum as u64;
                carry = sum >> 64;
            }
        }
        out
    }

    /// Negation $(-a) \pmod \ell$.
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            Self(SCALAR_ORDER_LIMBS).sub(self)
        }
    }

    /// Multiplication $(a \times b) \pmod \ell$.
    pub fn mul(&self, other: &Self) -> Self {
        let mut wide = [0u128; 8];
        for i in 0..4 {
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (other.0[j] as u128);
                let idx = i + j;
                let mut sum = wide[idx] + (prod & 0xFFFF_FFFF_FFFF_FFFF);
                wide[idx] = sum & 0xFFFF_FFFF_FFFF_FFFF;
                let mut carry = (prod >> 64) + (sum >> 64);
                let mut k = idx + 1;
                while carry > 0 && k < 8 {
                    sum = wide[k] + carry;
                    wide[k] = sum & 0xFFFF_FFFF_FFFF_FFFF;
                    carry = sum >> 64;
                    k += 1;
                }
            }
        }

        let mut acc = Self::ZERO;
        for i in (0..8).rev() {
            let limb = wide[i] as u64;
            for bit in (0..64).rev() {
                acc = acc.add(&acc);
                if (limb >> bit) & 1 == 1 {
                    acc = acc.add(&Self::ONE);
                }
            }
        }
        acc
    }

    /// Modular exponentiation $a^e \pmod \ell$ using square-and-multiply.
    pub fn pow(&self, exp: &Self) -> Self {
        let mut res = Self::ONE;
        let mut base = *self;

        for i in 0..4 {
            let mut limb = exp.0[i];
            for _ in 0..64 {
                if limb & 1 == 1 {
                    res = res.mul(&base);
                }
                base = base.mul(&base);
                limb >>= 1;
            }
        }
        res
    }

    /// Multiplicative inverse $a^{-1} \pmod \ell$ via Fermat's Little Theorem:
    /// $a^{-1} \equiv a^{\ell - 2} \pmod \ell$.
    ///
    /// Returns `None` if $a = 0$.
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        // Compute ell - 2
        let two = Self::from_u64(2);
        let ell_minus_two = Self(SCALAR_ORDER_LIMBS).sub(&two);
        Some(self.pow(&ell_minus_two))
    }

    /// Constant-time zeroing of sensitive memory.
    pub fn zeroize(&mut self) {
        self.0 = [0, 0, 0, 0];
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({})", self.to_hex())
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid scalar hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_add_sub_mul_identity() {
        let one = Scalar::ONE;
        let zero = Scalar::ZERO;

        assert_eq!(one.add(&zero), one);
        assert_eq!(one.sub(&zero), one);
        assert_eq!(one.mul(&one), one);
        assert_eq!(one.sub(&one), zero);
        assert_eq!(zero.neg(), zero);

        let two = one.add(&one);
        assert_eq!(two, Scalar::from_u64(2));
    }

    #[test]
    fn test_scalar_inversion_fermat() {
        let val = Scalar::from_u64(1234567);
        let inv = val.invert().expect("invert nonzero");
        let prod = val.mul(&inv);
        assert_eq!(prod, Scalar::ONE);

        assert_eq!(Scalar::ZERO.invert(), None);
    }

    #[test]
    fn test_scalar_serde_hex() {
        let s = Scalar::from_u64(987654321);
        let hex = s.to_hex();
        let parsed = Scalar::from_hex(&hex).expect("parse hex");
        assert_eq!(s, parsed);
    }
}
