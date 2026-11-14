//! Anti-Replay Protection & Sliding Bitmask Engine (ADR-081).
//!
//! Implements a 256-bit sliding window anti-replay barrier following the WireGuard
//! and IPsec RFC 6479 specifications. Prevents replay attacks by tracking received
//! transport packet transmission counters.

use super::types::{MeshError, MeshResult};

/// Size of the anti-replay sliding window in bits (4 x 64-bit words = 256 packets).
pub const REPLAY_WINDOW_SIZE: u64 = 256;

/// Canonical anti-replay sliding window tracking received packet counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiReplayWindow {
    /// Highest packet transmission counter observed so far.
    highest: u64,
    /// 256-bit bitmap representation (index 0 is highest counter, index 255 is highest - 255).
    bitmap: [u64; 4],
    /// Total number of packets processed.
    packets_seen: u64,
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayWindow {
    /// Create a new, empty anti-replay window initialized at counter 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0u64; 4],
            packets_seen: 0,
        }
    }

    /// Highest counter received so far.
    #[must_use]
    pub fn highest_counter(&self) -> u64 {
        self.highest
    }

    /// Total valid packets accepted through the window.
    #[must_use]
    pub fn packets_seen(&self) -> u64 {
        self.packets_seen
    }

    /// Check if a packet counter is valid and update the sliding window.
    ///
    /// Returns `Ok(())` if the counter is accepted.
    /// Returns `Err(MeshError::ReplayAttackDetected)` if the packet is replayed or too old.
    pub fn check_and_update(&mut self, counter: u64) -> MeshResult<()> {
        if self.packets_seen == 0 {
            self.highest = counter;
            self.bitmap[0] = 1;
            self.packets_seen = 1;
            return Ok(());
        }

        if counter > self.highest {
            // New counter is greater than current highest
            let delta = counter - self.highest;
            if delta >= REPLAY_WINDOW_SIZE {
                // Large forward jump: clear bitmap completely
                self.bitmap = [0u64; 4];
                self.bitmap[0] = 1;
            } else {
                // Shift bitmap right by delta positions
                self.shift_bitmap(delta as usize);
                self.bitmap[0] |= 1;
            }
            self.highest = counter;
            self.packets_seen += 1;
            Ok(())
        } else {
            // Counter is less than or equal to highest
            let diff = self.highest - counter;
            if diff >= REPLAY_WINDOW_SIZE {
                return Err(MeshError::ReplayAttackDetected {
                    counter,
                    highest: self.highest,
                });
            }

            let word_idx = (diff / 64) as usize;
            let bit_idx = (diff % 64) as usize;
            let mask = 1u64 << bit_idx;

            if (self.bitmap[word_idx] & mask) != 0 {
                // Packet already observed -> Replay Attack!
                return Err(MeshError::ReplayAttackDetected {
                    counter,
                    highest: self.highest,
                });
            }

            // Mark counter as seen
            self.bitmap[word_idx] |= mask;
            self.packets_seen += 1;
            Ok(())
        }
    }

    /// Shift the 256-bit bitmap by `shift` positions.
    fn shift_bitmap(&mut self, shift: usize) {
        if shift >= 256 {
            self.bitmap = [0u64; 4];
            return;
        }

        let words_to_shift = shift / 64;
        let bits_to_shift = shift % 64;

        if words_to_shift > 0 {
            for i in (words_to_shift..4).rev() {
                self.bitmap[i] = self.bitmap[i - words_to_shift];
            }
            for i in 0..words_to_shift {
                self.bitmap[i] = 0;
            }
        }

        if bits_to_shift > 0 {
            let mut carry = 0u64;
            for i in 0..4 {
                let next_carry = self.bitmap[i] >> (64 - bits_to_shift);
                self.bitmap[i] = (self.bitmap[i] << bits_to_shift) | carry;
                carry = next_carry;
            }
        }
    }
}
