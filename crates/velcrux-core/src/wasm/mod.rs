#![forbid(unsafe_code)]

//! Confidential Multi-Tenant eBPF Sandboxed Streaming Compute & In-Flight WASM Transformation (WASI 0.2).
//!
//! Provides WebAssembly 1.0/2.0 bytecode execution, deterministic gas metering,
//! memory-safe linear address arenas, WASI 0.2 capability-checked virtual I/O,
//! multi-stage in-flight transformation pipelines, and line-rate eBPF fastpath classification.

pub mod bytecode;
pub mod fastpath;
pub mod filter;
pub mod sandbox;
pub mod vm;
pub mod wasi;

pub use bytecode::{
    WasmExport, WasmExportDesc, WasmFuncBody, WasmFuncType, WasmImport, WasmMemLimits, WasmModule,
    WasmOp, WasmValType, WASM_MAGIC, WASM_VERSION,
};

pub use vm::{
    GasMeter, HostFunction, WasmInstance, WasmMemory, WasmValue, DEFAULT_GAS_LIMIT,
    DEFAULT_MAX_PAGES, WASM_PAGE_SIZE,
};

pub use wasi::{WasiCapabilities, WasiContext, WasiStreamBuffer};

pub use filter::{
    execute_binary_to_json_transcode, execute_checksum_stamping, execute_json_to_binary_transcode,
    execute_pii_redaction, execute_stream_masking, FilterKind, PipelineStage, TransformPipeline,
    TransformResult,
};

pub use sandbox::{SandboxPolicy, TenantSandbox, TenantSandboxManager};

pub use fastpath::{FastPathClassifier, FastPathDecision, FastPathRule};
