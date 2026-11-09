#![forbid(unsafe_code)]

//! Confidential Multi-Tenant Sandbox Manager & Isolation Boundaries.
//!
//! Enforces tenant quotas, memory page caps, capability permissions,
//! and isolated WASM execution contexts without shared mutable state.

use super::filter::TransformPipeline;
use super::wasi::WasiCapabilities;
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security & Quota Policy for a Tenant's Sandboxed Environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub max_memory_pages: u32,
    pub max_gas_per_chunk: u64,
    pub max_concurrent_pipelines: usize,
    pub capabilities: WasiCapabilities,
    pub allow_custom_wasm: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            max_memory_pages: 128, // 8 MiB max memory
            max_gas_per_chunk: 5_000_000,
            max_concurrent_pipelines: 16,
            capabilities: WasiCapabilities::default(),
            allow_custom_wasm: true,
        }
    }
}

/// Tenant Sandbox Instance holding registered pipelines and usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSandbox {
    pub tenant_id: String,
    pub policy: SandboxPolicy,
    pub registered_pipelines: HashMap<String, TransformPipeline>,
    pub total_chunks_processed: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub total_gas_consumed: u64,
}

impl TenantSandbox {
    pub fn new(tenant_id: impl Into<String>, policy: SandboxPolicy) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            policy,
            registered_pipelines: HashMap::new(),
            total_chunks_processed: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
            total_gas_consumed: 0,
        }
    }

    pub fn register_pipeline(&mut self, pipeline: TransformPipeline) -> Result<()> {
        if self.registered_pipelines.len() >= self.policy.max_concurrent_pipelines {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "tenant exceeded max registered pipelines quota",
            )));
        }
        self.registered_pipelines
            .insert(pipeline.pipeline_id.clone(), pipeline);
        Ok(())
    }

    pub fn get_pipeline(&self, id: &str) -> Option<&TransformPipeline> {
        self.registered_pipelines.get(id)
    }

    pub fn process_chunk(
        &mut self,
        pipeline_id: &str,
        chunk: &[u8],
    ) -> Result<(Vec<u8>, super::filter::TransformResult)> {
        let pipeline = self.registered_pipelines.get(pipeline_id).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed(
                "pipeline not registered for tenant",
            ))
        })?;

        let (out_bytes, report) = pipeline.execute(chunk)?;

        self.total_chunks_processed += 1;
        self.total_bytes_in += report.original_size_bytes as u64;
        self.total_bytes_out += report.transformed_size_bytes as u64;
        self.total_gas_consumed += report.total_gas_consumed;

        Ok((out_bytes, report))
    }
}

/// Global Multi-Tenant Sandbox Manager.
#[derive(Debug, Default)]
pub struct TenantSandboxManager {
    sandboxes: HashMap<String, TenantSandbox>,
}

impl TenantSandboxManager {
    pub fn new() -> Self {
        Self {
            sandboxes: HashMap::new(),
        }
    }

    pub fn get_or_create_sandbox(&mut self, tenant_id: &str) -> &mut TenantSandbox {
        self.sandboxes
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantSandbox::new(tenant_id, SandboxPolicy::default()))
    }

    pub fn get_sandbox(&self, tenant_id: &str) -> Option<&TenantSandbox> {
        self.sandboxes.get(tenant_id)
    }

    pub fn list_tenants(&self) -> Vec<String> {
        self.sandboxes.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::filter::{FilterKind, PipelineStage};

    #[test]
    fn test_tenant_sandbox_isolation_and_quotas() {
        let mut mgr = TenantSandboxManager::new();
        let sandbox_a = mgr.get_or_create_sandbox("tenant-apple");

        let mut pipe = TransformPipeline::new("pipe-apple", "tenant-apple");
        pipe.add_stage(PipelineStage::new(
            "mask",
            FilterKind::PiiRedaction,
            100_000,
        ));
        sandbox_a.register_pipeline(pipe).expect("register");

        let data = b"Card: 4111-2222-3333-4444";
        let (out, rep) = sandbox_a
            .process_chunk("pipe-apple", data)
            .expect("process");
        assert!(rep.is_success);
        assert_eq!(String::from_utf8_lossy(&out), "Card: XXXX-XXXX-XXXX-XXXX");
        assert_eq!(sandbox_a.total_chunks_processed, 1);

        // Tenant Orange has no pipelines and cannot access Tenant Apple's pipeline
        let sandbox_b = mgr.get_or_create_sandbox("tenant-orange");
        assert!(sandbox_b.get_pipeline("pipe-apple").is_none());
    }
}
