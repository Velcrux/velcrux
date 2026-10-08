#![forbid(unsafe_code)]

//! In-process deterministic protocol fuzzing engine and parser security validator.
//!
//! Implements requirements from:
//! - `docs/REQUIREMENTS.md` §49 ("Security Testing")
//! - `docs/REQUIREMENTS.md` §50 ("Fuzzing")
//! - `docs/REQUIREMENTS.md` §22 ("Security Threat Model")
//! - `CLAUDE.md` §1 invariant #5 ("Client metadata is untrusted")
//!
//! Provides property-based mutation generation (bit flips, byte swaps, truncations,
//! oversized fields, invalid LEB128 varints, corrupted UTF-8) and asserts zero-panic,
//! fail-closed error handling across all binary decoders in 100% safe Rust.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Fast, deterministic pseudo-random mutation engine (xorshift64).
#[derive(Debug, Clone)]
pub struct FuzzMutator {
    state: u64,
}

impl FuzzMutator {
    /// Construct a new mutator with an initial seed.
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x517cc1b727220a95 } else { seed },
        }
    }

    /// Retrieve next pseudo-random 64-bit integer.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Retrieve next pseudo-random integer in range `[min, max)`.
    pub fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let diff = (max - min) as u64;
        let val = self.next_u64() % diff;
        min + val as usize
    }

    /// Flip a random bit in the slice.
    pub fn bit_flip(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let byte_idx = self.next_range(0, data.len());
        let bit_idx = (self.next_u64() % 8) as u8;
        data[byte_idx] ^= 1 << bit_idx;
    }

    /// Overwrite a random byte with random data.
    pub fn byte_flip(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let byte_idx = self.next_range(0, data.len());
        data[byte_idx] = (self.next_u64() & 0xFF) as u8;
    }

    /// Truncate a random slice of bytes from the end.
    pub fn truncate(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let new_len = self.next_range(0, data.len());
        data.truncate(new_len);
    }

    /// Insert random bytes at a random position.
    pub fn insert_bytes(&mut self, data: &mut Vec<u8>) {
        let pos = self.next_range(0, data.len() + 1);
        let count = self.next_range(1, 16);
        for _ in 0..count {
            let b = (self.next_u64() & 0xFF) as u8;
            data.insert(pos, b);
        }
    }

    /// Delete random bytes.
    pub fn delete_bytes(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let pos = self.next_range(0, data.len());
        let count = self.next_range(1, (data.len() - pos).min(16) + 1);
        data.drain(pos..pos + count);
    }

    /// Inject non-canonical or overflowing varint byte sequence (>10 bytes or MSB never cleared).
    pub fn inject_bad_varint(&mut self, data: &mut Vec<u8>) {
        let pos = self.next_range(0, data.len() + 1);
        // 11 consecutive bytes with high bit set triggers VarintOverflow (>10 bytes)
        let bad_varint = [0x80u8; 11];
        data.splice(pos..pos, bad_varint);
    }

    /// Inject invalid UTF-8 byte sequences.
    pub fn inject_bad_utf8(&mut self, data: &mut Vec<u8>) {
        let pos = self.next_range(0, data.len() + 1);
        // Invalid UTF-8: standalone continuation bytes or invalid lead byte (0xFF, 0xC0)
        let bad_utf8 = [0xFF, 0xC0, 0x80, 0xFE];
        data.splice(pos..pos, bad_utf8);
    }

    /// Inject boundary integers (0, 1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF).
    pub fn inject_boundary_ints(&mut self, data: &mut Vec<u8>) {
        let pos = self.next_range(0, data.len() + 1);
        let boundary = match self.next_u64() % 4 {
            0 => vec![0x00u8; 8],
            1 => vec![0xFFu8; 8],
            2 => vec![0x7Fu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
            _ => vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
        };
        data.splice(pos..pos, boundary);
    }

    /// Mutate an input buffer using a composition of mutation strategies.
    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.is_empty() {
            out.push((self.next_u64() & 0xFF) as u8);
            return out;
        }

        let mutations = self.next_range(1, 4);
        for _ in 0..mutations {
            match self.next_u64() % 8 {
                0 => self.bit_flip(&mut out),
                1 => self.byte_flip(&mut out),
                2 => self.truncate(&mut out),
                3 => self.insert_bytes(&mut out),
                4 => self.delete_bytes(&mut out),
                5 => self.inject_bad_varint(&mut out),
                6 => self.inject_bad_utf8(&mut out),
                _ => self.inject_boundary_ints(&mut out),
            }
        }
        out
    }

    /// Generate a pseudo-random buffer of `len` bytes.
    pub fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (self.next_u64() & 0xFF) as u8;
        }
        buf
    }
}

/// Asserts that a single invocation of `decode_fn` on `buf` does not panic.
pub fn assert_no_panic<F>(buf: &[u8], decode_fn: F)
where
    F: FnOnce(&[u8]),
{
    let res = catch_unwind(AssertUnwindSafe(|| {
        decode_fn(buf);
    }));
    assert!(
        res.is_ok(),
        "Decoder panicked on input len: {}, hex: {:02x?}",
        buf.len(),
        &buf[..buf.len().min(64)]
    );
}

/// Asserts that a binary decoder NEVER panics on any mutated or adversarial input.
///
/// Executes `iterations` mutations against `corpus`. If a decoder panics, the assertion
/// fails immediately with reproduction seed and input bytes.
pub fn assert_decoder_panic_free<F>(
    mutator: &mut FuzzMutator,
    corpus: &[Vec<u8>],
    iterations: usize,
    decode_fn: F,
) where
    F: Fn(&[u8]),
{
    // 1. First test empty input and single byte inputs
    let empty_res = catch_unwind(AssertUnwindSafe(|| {
        decode_fn(&[]);
    }));
    assert!(empty_res.is_ok(), "Decoder panicked on empty input buffer");

    for b in 0u8..=255 {
        let single_byte = [b];
        let res = catch_unwind(AssertUnwindSafe(|| {
            decode_fn(&single_byte);
        }));
        assert!(res.is_ok(), "Decoder panicked on single byte 0x{b:02x}");
    }

    // 2. Test base corpus
    for seed_input in corpus {
        let res = catch_unwind(AssertUnwindSafe(|| {
            decode_fn(seed_input);
        }));
        assert!(
            res.is_ok(),
            "Decoder panicked on seed corpus input (len {})",
            seed_input.len()
        );
    }

    // 3. Fuzz iterations with mutations
    for iter in 0..iterations {
        let base = if corpus.is_empty() {
            Vec::new()
        } else {
            let idx = mutator.next_range(0, corpus.len());
            corpus[idx].clone()
        };

        let mutated = mutator.mutate(&base);
        let res = catch_unwind(AssertUnwindSafe(|| {
            decode_fn(&mutated);
        }));

        if res.is_err() {
            panic!(
                "CRITICAL: Decoder panicked on iteration {iter}!\nInput len: {}\nInput hex: {:02x?}",
                mutated.len(),
                &mutated[..mutated.len().min(64)]
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutator_determinism_and_operations() {
        let mut m1 = FuzzMutator::new(42);
        let mut m2 = FuzzMutator::new(42);

        let input = b"Hello, Velcrux Fuzzer Invariants!";
        let out1 = m1.mutate(input);
        let out2 = m2.mutate(input);

        // Deterministic reproduction from same seed
        assert_eq!(out1, out2);
        // Mutation altered the input
        assert_ne!(out1, input.to_vec());
    }

    #[test]
    fn test_panic_free_assertion_with_safe_decoder() {
        let mut mutator = FuzzMutator::new(12345);
        let corpus = vec![b"test_payload_123".to_vec()];

        // Decoder that safely returns or fails without panic
        assert_decoder_panic_free(&mut mutator, &corpus, 1000, |data| {
            let _ = std::str::from_utf8(data);
        });
    }

    #[test]
    #[should_panic(expected = "Decoder panicked")]
    fn test_panic_free_assertion_catches_unsafe_decoder() {
        let mut mutator = FuzzMutator::new(999);
        let corpus = vec![vec![1, 2, 3, 4, 5]];

        // Intentionally buggy decoder that panics on byte 0xFF
        assert_decoder_panic_free(&mut mutator, &corpus, 500, |data| {
            if data.contains(&0xFF) {
                panic!("boom: unhandled byte 0xFF");
            }
        });
    }
}
