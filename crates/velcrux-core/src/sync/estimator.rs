//! Cost estimation for sync decision (FULL vs DELTA) (`ARCHITECTURE.md` §7).

/// Synchronization strategy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDecision {
    /// Target file exists and matches the source hash completely. No transfer required.
    Skip,
    /// Delta synchronization: only missing chunks are sent over the wire.
    Delta,
    /// Full file transfer: the entire file is transferred (insufficient reuse or delta overhead).
    Full,
}

/// Execution plan resulting from cost estimation.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncPlan {
    /// Selected decision.
    pub decision: SyncDecision,
    /// Total logical bytes of the file.
    pub total_bytes: u64,
    /// Estimated or actual wire bytes required.
    pub wire_bytes: u64,
    /// Reused bytes from existing local file.
    pub reused_bytes: u64,
    /// Total chunks in the file.
    pub total_chunks: usize,
    /// Chunks already available on receiver.
    pub have_chunks: usize,
    /// Chunks that must be sent over the wire.
    pub need_chunks: usize,
    /// Reuse ratio (0.0 to 1.0).
    pub reuse_ratio: f64,
}

/// Cost estimator comparing Full Transfer vs Delta Reconstruction.
#[derive(Debug, Clone)]
pub struct CostEstimator {
    /// Minimum file size in bytes to consider delta synchronization (below this, Full is preferred).
    pub min_file_size: u64,
    /// Minimum reuse ratio (0.0 to 1.0) to justify delta reconstruction overhead (default: 0.10 = 10%).
    pub min_savings_ratio: f64,
}

impl Default for CostEstimator {
    fn default() -> Self {
        Self {
            min_file_size: 64 * 1024, // 64 KiB
            min_savings_ratio: 0.05,  // 5% minimum savings
        }
    }
}

impl CostEstimator {
    /// Create a new estimator with custom parameters.
    pub fn new(min_file_size: u64, min_savings_ratio: f64) -> Self {
        Self {
            min_file_size,
            min_savings_ratio: min_savings_ratio.clamp(0.0, 1.0),
        }
    }

    /// Evaluate synchronization plan based on chunk counts and optional whole-file match.
    pub fn evaluate(
        &self,
        file_size: u64,
        total_chunks: usize,
        have_chunks: usize,
        target_matches: bool,
    ) -> SyncPlan {
        if target_matches {
            return SyncPlan {
                decision: SyncDecision::Skip,
                total_bytes: file_size,
                wire_bytes: 0,
                reused_bytes: file_size,
                total_chunks,
                have_chunks: total_chunks,
                need_chunks: 0,
                reuse_ratio: 1.0,
            };
        }

        let total_c = total_chunks.max(1);
        let have_c = have_chunks.min(total_c);
        let need_c = total_c - have_c;

        let reuse_ratio = have_c as f64 / total_c as f64;
        let estimated_reused_bytes = (file_size as f64 * reuse_ratio).round() as u64;
        let estimated_wire_bytes = file_size.saturating_sub(estimated_reused_bytes);

        let decision = if file_size < self.min_file_size {
            // Small files: full transfer is cheaper than chunk negotiation overhead
            SyncDecision::Full
        } else if have_c == 0 || reuse_ratio < self.min_savings_ratio {
            // No reuse or below threshold
            SyncDecision::Full
        } else {
            SyncDecision::Delta
        };

        let wire_bytes = match decision {
            SyncDecision::Skip => 0,
            SyncDecision::Full => file_size,
            SyncDecision::Delta => estimated_wire_bytes,
        };

        let reused_bytes = match decision {
            SyncDecision::Skip => file_size,
            SyncDecision::Full => 0,
            SyncDecision::Delta => estimated_reused_bytes,
        };

        SyncPlan {
            decision,
            total_bytes: file_size,
            wire_bytes,
            reused_bytes,
            total_chunks,
            have_chunks: have_c,
            need_chunks: need_c,
            reuse_ratio,
        }
    }

    /// Evaluate synchronization plan with exact byte counts.
    pub fn evaluate_with_bytes(
        &self,
        file_size: u64,
        reused_bytes: u64,
        total_chunks: usize,
        have_chunks: usize,
        target_matches: bool,
    ) -> SyncPlan {
        if target_matches {
            return SyncPlan {
                decision: SyncDecision::Skip,
                total_bytes: file_size,
                wire_bytes: 0,
                reused_bytes: file_size,
                total_chunks,
                have_chunks: total_chunks,
                need_chunks: 0,
                reuse_ratio: 1.0,
            };
        }

        let total_c = total_chunks.max(1);
        let have_c = have_chunks.min(total_c);
        let need_c = total_c - have_c;
        let reused_b = reused_bytes.min(file_size);
        let reuse_ratio = if file_size > 0 {
            reused_b as f64 / file_size as f64
        } else {
            1.0
        };

        let decision = if file_size < self.min_file_size {
            SyncDecision::Full
        } else if have_c == 0 || reuse_ratio < self.min_savings_ratio {
            SyncDecision::Full
        } else {
            SyncDecision::Delta
        };

        let wire_bytes = match decision {
            SyncDecision::Skip => 0,
            SyncDecision::Full => file_size,
            SyncDecision::Delta => file_size.saturating_sub(reused_b),
        };

        let final_reused_bytes = match decision {
            SyncDecision::Skip => file_size,
            SyncDecision::Full => 0,
            SyncDecision::Delta => reused_b,
        };

        SyncPlan {
            decision,
            total_bytes: file_size,
            wire_bytes,
            reused_bytes: final_reused_bytes,
            total_chunks,
            have_chunks: have_c,
            need_chunks: need_c,
            reuse_ratio,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimator_matches_skips() {
        let est = CostEstimator::default();
        let plan = est.evaluate(10_000_000, 20, 20, true);
        assert_eq!(plan.decision, SyncDecision::Skip);
        assert_eq!(plan.wire_bytes, 0);
        assert_eq!(plan.reused_bytes, 10_000_000);
    }

    #[test]
    fn estimator_small_file_prefers_full() {
        let est = CostEstimator::default();
        let plan = est.evaluate(1024, 2, 1, false);
        assert_eq!(plan.decision, SyncDecision::Full);
        assert_eq!(plan.wire_bytes, 1024);
    }

    #[test]
    fn estimator_high_reuse_selects_delta() {
        let est = CostEstimator::default();
        // 100 GB with 3 GB changed -> 97% reuse
        let total_size = 100_000_000_000u64;
        let total_chunks = 200_000;
        let have_chunks = 194_000; // 97% have
        let plan = est.evaluate(total_size, total_chunks, have_chunks, false);
        assert_eq!(plan.decision, SyncDecision::Delta);
        assert_eq!(plan.wire_bytes, 3_000_000_000);
        assert_eq!(plan.reused_bytes, 97_000_000_000);
    }
}
