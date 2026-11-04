#![forbid(unsafe_code)]

//! Twisted Edwards Curve25519 point arithmetic in extended projective coordinates $(X : Y : Z : T)$.
//!
//! Curve Equation: $-x^2 + y^2 = 1 + d x^2 y^2 \pmod p$
//! Base field: $p = 2^{255} - 19$
//! Group order: $\ell = 2^{252} + 27742317777372353535851937790883648493$

use super::scalar::Scalar;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Field modulus $p = 2^{255} - 19$ in little-endian 64-bit limbs.
pub const FIELD_MODULUS_LIMBS: [u64; 4] = [
    0xFFFFFFFFFFFFFFED,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
];

/// Element of prime field $\mathbb{F}_{2^{255}-19}$.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FieldElement(pub [u64; 4]);

impl FieldElement {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Square root of -1 in $\mathbb{F}_p$: $2^{(p-1)/4} \pmod p$.
    pub const SQRT_MINUS_ONE: Self = Self([
        0xC4EE1B274A0EA0B0,
        0x2F431806AD2FE478,
        0x2B4D00993DFBD7A7,
        0x2B8324804FC1DF0B,
    ]);

    /// Curve constant $d = -121665 / 121666 \pmod p$.
    pub const D: Self = Self([
        0x75EB4DCA135978A3,
        0x00700A4D4141D8AB,
        0x8CC740797779E898,
        0x52036CEE2B6FFE73,
    ]);

    /// Curve constant $2d \pmod p$.
    pub const TWO_D: Self = Self([
        0xEBD69B9426B2F159,
        0x00E0149A8283B156,
        0x198E80F2EEF3D130,
        0x2406D9DC56DFFCE7,
    ]);

    pub const fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }

    pub fn is_zero(&self) -> bool {
        let r = self.reduce();
        r.0 == [0, 0, 0, 0]
    }

    /// Check if field element is odd.
    pub fn is_odd(&self) -> bool {
        let r = self.reduce();
        (r.0[0] & 1) == 1
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let r = self.reduce();
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&r.0[i].to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(buf);
        }
        // clear highest bit (since p < 2^255)
        limbs[3] &= 0x7FFFFFFFFFFFFFFF;
        Self(limbs).reduce()
    }

    pub fn is_ge_modulus(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > FIELD_MODULUS_LIMBS[i] {
                return true;
            }
            if self.0[i] < FIELD_MODULUS_LIMBS[i] {
                return false;
            }
        }
        true
    }

    pub fn reduce(mut self) -> Self {
        while self.is_ge_modulus() {
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = (self.0[i] as i128) - (FIELD_MODULUS_LIMBS[i] as i128) - borrow;
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

    pub fn add(&self, other: &Self) -> Self {
        let mut carry = 0u128;
        let mut res = [0u64; 4];
        for i in 0..4 {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            res[i] = sum as u64;
            carry = sum >> 64;
        }

        let mut out = Self(res);
        if carry > 0 || out.is_ge_modulus() {
            let mut borrow = 0i128;
            for i in 0..4 {
                let diff = (out.0[i] as i128) - (FIELD_MODULUS_LIMBS[i] as i128) - borrow;
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
                let sum = (out.0[i] as u128) + (FIELD_MODULUS_LIMBS[i] as u128) + carry;
                out.0[i] = sum as u64;
                carry = sum >> 64;
            }
        }
        out
    }

    pub fn neg(&self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            Self(FIELD_MODULUS_LIMBS).sub(self)
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut wide = [0u128; 8];
        for i in 0..4 {
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (other.0[j] as u128);
                let idx = i + j;
                let sum = wide[idx] + (prod & 0xFFFF_FFFF_FFFF_FFFF);
                wide[idx] = sum & 0xFFFF_FFFF_FFFF_FFFF;
                let mut carry = (prod >> 64) + (sum >> 64);
                let mut k = idx + 1;
                while carry > 0 && k < 8 {
                    let s = wide[k] + carry;
                    wide[k] = s & 0xFFFF_FFFF_FFFF_FFFF;
                    carry = s >> 64;
                    k += 1;
                }
            }
        }

        let w = [
            wide[0] as u64,
            wide[1] as u64,
            wide[2] as u64,
            wide[3] as u64,
            wide[4] as u64,
            wide[5] as u64,
            wide[6] as u64,
            wide[7] as u64,
        ];

        let low = [w[0], w[1], w[2], w[3] & 0x7FFF_FFFF_FFFF_FFFF];
        let h = [
            (w[3] >> 63) | (w[4] << 1),
            (w[4] >> 63) | (w[5] << 1),
            (w[5] >> 63) | (w[6] << 1),
            (w[6] >> 63) | (w[7] << 1),
            w[7] >> 63,
        ];

        // Multiply h by 19 and add to low
        let mut carry = 0u128;
        let mut res = [0u64; 5];
        for i in 0..4 {
            let prod = (h[i] as u128) * 19 + (low[i] as u128) + carry;
            res[i] = prod as u64;
            carry = prod >> 64;
        }
        res[4] = ((h[4] as u128) * 19 + carry) as u64;

        let r_low = [res[0], res[1], res[2], res[3] & 0x7FFF_FFFF_FFFF_FFFF];
        let r_high = (res[3] >> 63) | (res[4] << 1);

        let mut carry2 = (r_high as u128) * 19;
        let mut final_limbs = [0u64; 4];
        for i in 0..4 {
            let s = (r_low[i] as u128) + carry2;
            final_limbs[i] = s as u64;
            carry2 = s >> 64;
        }

        if carry2 > 0 || (final_limbs[3] >> 63) > 0 {
            let top = (final_limbs[3] >> 63) | ((carry2 as u64) << 1);
            final_limbs[3] &= 0x7FFF_FFFF_FFFF_FFFF;
            let mut carry3 = (top as u128) * 19;
            for i in 0..4 {
                let s = (final_limbs[i] as u128) + carry3;
                final_limbs[i] = s as u64;
                carry3 = s >> 64;
            }
        }

        Self(final_limbs).reduce()
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Exponentiation $a^e \pmod p$.
    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut res = Self::ONE;
        let mut base = *self;
        for i in 0..4 {
            let mut limb = exp[i];
            for _ in 0..64 {
                if limb & 1 == 1 {
                    res = res.mul(&base);
                }
                base = base.square();
                limb >>= 1;
            }
        }
        res
    }

    /// Multiplicative inverse $a^{-1} \pmod p$ via Fermat's Little Theorem: $a^{p-2} \pmod p$.
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        // p - 2: [0xFFFFFFFFFFFFFFEB, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF]
        let p_minus_two = [
            0xFFFFFFFFFFFFFFEB,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ];
        Some(self.pow(&p_minus_two))
    }

    /// Square root in $\mathbb{F}_p$ for $p \equiv 5 \pmod 8$.
    /// Candidate $x = (u)^{(p+3)/8} \pmod p$. If $x^2 \neq u$, $x = x \cdot 2^{(p-1)/4}$.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::ZERO);
        }
        // (p + 3) / 8: 2^252 - 2
        // [0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0FFFFFFFFFFFFFFF]
        let exp = [
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x0FFFFFFFFFFFFFFF,
        ];
        let mut cand = self.pow(&exp);
        if cand.square().reduce() != self.reduce() {
            cand = cand.mul(&Self::SQRT_MINUS_ONE);
        }
        if cand.square().reduce() == self.reduce() {
            Some(cand)
        } else {
            None
        }
    }
}

/// Point on Twisted Edwards Curve25519 in extended coordinates $(X : Y : Z : T)$
/// where $x = X/Z, y = Y/Z, x \cdot y = T/Z$.
#[derive(Clone, Copy)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

impl Point {
    /// Identity point $(0, 1, 1, 0)$.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// Base generator point $B$ on Ed25519.
    pub fn generator() -> Self {
        // xB = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
        let x = FieldElement([
            0xC9562D608F25D51A,
            0x692CC7609525A7B2,
            0xC0A4E231FDD6DC5C,
            0x216936D3CD6E53FE,
        ]);
        // yB = 4/5 mod p = 0x6666666666666666666666666666666666666666666666666666666666666658
        let y = FieldElement([
            0x6666666666666658,
            0x6666666666666666,
            0x6666666666666666,
            0x6666666666666666,
        ]);
        let z = FieldElement::ONE;
        let t = x.mul(&y);
        Self { x, y, z, t }
    }

    /// Check if this point is the neutral identity element $\mathcal{O}$.
    pub fn is_identity(&self) -> bool {
        self.x.is_zero() && (self.y.reduce() == self.z.reduce())
    }

    /// Complete Edwards point addition (Hisil et al. 2008): $P_3 = P_1 + P_2$.
    pub fn add(&self, other: &Self) -> Self {
        let a = (self.y.sub(&self.x)).mul(&(other.y.sub(&other.x)));
        let b = (self.y.add(&self.x)).mul(&(other.y.add(&other.x)));
        let c = self.t.mul(&FieldElement::TWO_D).mul(&other.t);
        let d = self.z.mul(&FieldElement::from_u64(2)).mul(&other.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);

        let x3 = e.mul(&f);
        let y3 = g.mul(&h);
        let t3 = e.mul(&h);
        let z3 = f.mul(&g);

        Self {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// Point negation $-P = (-X, Y, Z, -T)$.
    pub fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Point subtraction $P_1 - P_2 = P_1 + (-P_2)$.
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Scalar multiplication $s \cdot P$ using double-and-add over little-endian limbs of $s$.
    pub fn mul_scalar(&self, scalar: &Scalar) -> Self {
        let mut r = Self::IDENTITY;
        let mut base = *self;

        for i in 0..4 {
            let mut limb = scalar.0[i];
            for _ in 0..64 {
                if limb & 1 == 1 {
                    r = r.add(&base);
                }
                base = base.add(&base);
                limb >>= 1;
            }
        }
        r
    }

    /// Compress point to 32 bytes (RFC 8032 Ed25519 standard format).
    pub fn to_bytes(&self) -> [u8; 32] {
        if self.z.is_zero() {
            let mut b = [0u8; 32];
            b[0] = 1;
            return b;
        }
        let z_inv = self.z.invert().unwrap_or(FieldElement::ONE);
        let x = self.x.mul(&z_inv).reduce();
        let y = self.y.mul(&z_inv).reduce();

        let mut out = y.to_bytes();
        if x.is_odd() {
            out[31] |= 0x80;
        }
        out
    }

    /// Decompress point from 32 bytes (RFC 8032 format).
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let sign_bit = (bytes[31] >> 7) & 1;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7F;

        let y = FieldElement::from_bytes(&y_bytes);
        let one = FieldElement::ONE;
        let y2 = y.square();

        // u = y^2 - 1
        let u = y2.sub(&one);
        // v = d * y^2 + 1
        let v = FieldElement::D.mul(&y2).add(&one);

        let v_inv = v.invert()?;
        let x2 = u.mul(&v_inv);
        let mut x = x2.sqrt()?;

        if (x.is_odd() as u8) != sign_bit {
            x = x.neg().reduce();
        }

        let z = FieldElement::ONE;
        let t = x.mul(&y);
        Some(Self { x, y, z, t })
    }

    /// Hexadecimal encoding (64 lowercase hex characters).
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Parse point from 64-character lowercase hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        if clean.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let byte_val = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
            bytes[i] = byte_val;
        }
        Self::from_bytes(&bytes)
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        // P1 == P2 iff X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
        let x1z2 = self.x.mul(&other.z).reduce();
        let x2z1 = other.x.mul(&self.z).reduce();
        let y1z2 = self.y.mul(&other.z).reduce();
        let y2z1 = other.y.mul(&self.z).reduce();

        x1z2 == x2z1 && y1z2 == y2z1
    }
}

impl Eq for Point {}

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Point({})", self.to_hex())
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Point {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid point hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_generator_and_order() {
        let g = Point::generator();
        assert!(!g.is_identity());

        // Check compression / decompression roundtrip
        let bytes = g.to_bytes();
        let decompressed = Point::from_bytes(&bytes).expect("decompress generator");
        assert_eq!(g, decompressed);

        // Check that ell * G == IDENTITY
        let ell = Scalar(super::super::scalar::SCALAR_ORDER_LIMBS);
        let identity = g.mul_scalar(&ell);
        assert!(identity.is_identity());
    }

    #[test]
    fn test_point_addition_associativity() {
        let g = Point::generator();
        let g2 = g.add(&g);
        let g3 = g2.add(&g);

        let g_mul3 = g.mul_scalar(&Scalar::from_u64(3));
        assert_eq!(g3, g_mul3);
    }
}
