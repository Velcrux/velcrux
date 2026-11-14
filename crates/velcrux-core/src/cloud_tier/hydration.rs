//! Asynchronous Cloud Archive Hydration Pipeline (`ADR-079`).
//!
//! Models asynchronous restoration of cold and deep-archive objects (e.g. S3 RestoreObject /
//! Azure SetBlobTier rehydration), priority tiers (`Expedited`, `Standard`, `Bulk`),
//! temporary hot cache promotion, and auto-expiry management.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use super::types::{CloudTierClass, HydrationPriority, HydrationRequest, HydrationStatus};
use crate::error::{ProtocolError, Result, VelcruxError};

/// Asynchronous hydration pipeline coordinator.
#[derive(Debug, Clone, Default)]
pub struct CloudHydrationPipeline {
    /// Active and completed requests indexed by request ID.
    pub requests: HashMap<String, HydrationRequest>,
    /// Chunk hash to active request ID mapping for request deduplication.
    pub chunk_to_request: HashMap<[u8; 32], String>,
    /// Temporary hydrated chunk payload cache (simulating restored data availability).
    pub hydrated_cache: HashMap<[u8; 32], (Vec<u8>, u64)>, // (payload, expires_at)
    /// Metrics counters.
    pub total_requested: u64,
    pub total_completed: u64,
    pub total_expired: u64,
    pub total_expedited: u64,
}

impl CloudHydrationPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submits a hydration request for a chunk located in a cold or deep archive container.
    pub fn request_hydration(
        &mut self,
        container_id: impl Into<String>,
        chunk_hash: [u8; 32],
        source_tier: CloudTierClass,
        priority: HydrationPriority,
        now: u64,
    ) -> Result<String> {
        if !source_tier.requires_hydration() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "tier does not require asynchronous hydration (hot/cool direct access)",
            )));
        }

        // Check if an existing pending or active request already exists for this chunk
        if let Some(existing_id) = self.chunk_to_request.get(&chunk_hash) {
            if let Some(req) = self.requests.get(existing_id) {
                if req.status != HydrationStatus::Expired {
                    return Ok(req.request_id.clone());
                }
            }
        }

        let request_id = format!(
            "hyd-{}-{:x}",
            self.total_requested,
            u32::from_be_bytes([chunk_hash[0], chunk_hash[1], chunk_hash[2], chunk_hash[3]])
        );

        let req = HydrationRequest {
            request_id: request_id.clone(),
            container_id: container_id.into(),
            chunk_hash,
            source_tier,
            priority,
            status: HydrationStatus::Pending,
            requested_at: now,
            completed_at: None,
            expires_at: None,
        };

        if priority == HydrationPriority::Expedited {
            self.total_expedited = self.total_expedited.saturating_add(1);
        }

        self.requests.insert(request_id.clone(), req);
        self.chunk_to_request.insert(chunk_hash, request_id.clone());
        self.total_requested = self.total_requested.saturating_add(1);

        Ok(request_id)
    }

    /// Polls and advances pending hydration requests based on the current wall-clock timestamp.
    ///
    /// Simulates cloud restoration duration based on `HydrationPriority`.
    pub fn poll_hydrations<F>(&mut self, now: u64, mut chunk_fetcher: F) -> usize
    where
        F: FnMut(&str, &[u8; 32]) -> Option<Vec<u8>>,
    {
        let mut completed_now = 0;

        for req in self.requests.values_mut() {
            if req.status == HydrationStatus::Pending {
                req.status = HydrationStatus::Hydrating;
            }

            match req.status {
                HydrationStatus::Hydrating => {
                    let elapsed = now.saturating_sub(req.requested_at);
                    let target_duration = req.priority.simulated_duration_secs();

                    if elapsed >= target_duration {
                        req.status = HydrationStatus::Hydrated;
                        req.completed_at = Some(now);
                        // Hydrated objects remain available for 7 days (604,800s)
                        let expires_at = now + 604_800;
                        req.expires_at = Some(expires_at);

                        if let Some(payload) = chunk_fetcher(&req.container_id, &req.chunk_hash) {
                            self.hydrated_cache
                                .insert(req.chunk_hash, (payload, expires_at));
                        }

                        self.total_completed = self.total_completed.saturating_add(1);
                        completed_now += 1;
                    }
                }
                HydrationStatus::Hydrated => {
                    if let Some(exp) = req.expires_at {
                        if now >= exp {
                            req.status = HydrationStatus::Expired;
                            self.hydrated_cache.remove(&req.chunk_hash);
                            self.total_expired = self.total_expired.saturating_add(1);
                        }
                    }
                }
                HydrationStatus::Pending => {}
                HydrationStatus::Expired => {}
            }
        }

        completed_now
    }

    /// Reads a previously hydrated chunk from the temporary restoration cache.
    pub fn read_hydrated_chunk(&self, chunk_hash: &[u8; 32], now: u64) -> Option<&[u8]> {
        if let Some((payload, expires_at)) = self.hydrated_cache.get(chunk_hash) {
            if now < *expires_at {
                return Some(payload);
            }
        }
        None
    }

    /// Status of a hydration request.
    pub fn get_status(&self, request_id: &str) -> Option<&HydrationRequest> {
        self.requests.get(request_id)
    }

    /// Count of active hydrations currently in progress.
    pub fn active_hydrations_count(&self) -> usize {
        self.requests
            .values()
            .filter(|r| {
                r.status == HydrationStatus::Pending || r.status == HydrationStatus::Hydrating
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hydration_pipeline_lifecycle() {
        let mut pipeline = CloudHydrationPipeline::new();

        let chunk_hash = [0x5Au8; 32];
        let req_id = pipeline
            .request_hydration(
                "cont-glacier-01",
                chunk_hash,
                CloudTierClass::Cold,
                HydrationPriority::Expedited,
                1000,
            )
            .unwrap();

        assert_eq!(pipeline.active_hydrations_count(), 1);
        let req = pipeline.get_status(&req_id).unwrap();
        assert_eq!(req.status, HydrationStatus::Pending);

        // Advance 1 second -> Hydrating
        pipeline.poll_hydrations(1001, |_cid, _ch| None);
        let req = pipeline.get_status(&req_id).unwrap();
        assert_eq!(req.status, HydrationStatus::Hydrating);

        // Advance past expedited duration (60s) -> Hydrated
        let sample_payload = b"hydrated-from-glacier-cold-storage".to_vec();
        pipeline.poll_hydrations(1070, |_cid, _ch| Some(sample_payload.clone()));

        let req = pipeline.get_status(&req_id).unwrap();
        assert_eq!(req.status, HydrationStatus::Hydrated);
        assert!(req.expires_at.is_some());

        // Read from cache
        let cached = pipeline.read_hydrated_chunk(&chunk_hash, 1075).unwrap();
        assert_eq!(cached, sample_payload.as_slice());

        // Fast forward past expiry
        pipeline.poll_hydrations(1070 + 700_000, |_cid, _ch| None);
        let req = pipeline.get_status(&req_id).unwrap();
        assert_eq!(req.status, HydrationStatus::Expired);
        assert!(pipeline
            .read_hydrated_chunk(&chunk_hash, 1070 + 700_000)
            .is_none());
    }
}
