#![forbid(unsafe_code)]

//! Integration Tests for Confidential Multi-Tenant eBPF Sandboxed Streaming Compute & In-Flight WASM Payload Transformation (`ADR-074`).

use velcrux_core::wasm::{
    execute_binary_to_json_transcode, execute_json_to_binary_transcode, execute_pii_redaction,
    FastPathClassifier, FastPathDecision, FastPathRule, FilterKind, GasMeter, PipelineStage,
    TenantSandboxManager, TransformPipeline, WasiCapabilities, WasiContext, WasmInstance,
    WasmMemory, WasmModule, WasmValue, WASM_MAGIC, WASM_VERSION,
};

#[test]
fn test_wasm_binary_parsing_and_bytecode_disassembly() {
    let mut wasm_bytes = Vec::new();
    wasm_bytes.extend_from_slice(&WASM_MAGIC);
    wasm_bytes.extend_from_slice(&WASM_VERSION);

    // Section 1: Type section (1 function type: () -> i32)
    // 0x01 (section id), len=5, count=1, 0x60 (func), param_count=0, ret_count=1, 0x7F (i32)
    wasm_bytes.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);

    // Section 3: Function section (1 function pointing to type 0)
    // 0x03 (section id), len=2, count=1, type_idx=0
    wasm_bytes.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);

    // Section 5: Memory section (initial=1, max=2)
    // 0x05 (section id), len=4, count=1, flags=1, init=1, max=2
    wasm_bytes.extend_from_slice(&[0x05, 0x04, 0x01, 0x01, 0x01, 0x02]);

    // Section 7: Export section (1 export: "compute" -> func 0)
    // 0x07 (section id), len=11, count=1, len=7, "compute", kind=0 (func), idx=0
    wasm_bytes.extend_from_slice(&[
        0x07, 0x0B, 0x01, 0x07, b'c', b'o', b'm', b'p', b'u', b't', b'e', 0x00, 0x00,
    ]);

    // Section 10: Code section (1 function body: i32.const 42, return, end)
    // 0x0A (section id), len=6, count=1, body_len=4, local_count=0, 0x41, 42, 0x0B
    wasm_bytes.extend_from_slice(&[0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B]);

    let module = WasmModule::parse(&wasm_bytes).expect("parse wasm binary");
    assert_eq!(module.types.len(), 1);
    assert_eq!(module.functions.len(), 1);
    assert_eq!(module.memories.len(), 1);
    assert_eq!(module.exports.len(), 1);
    assert_eq!(module.code.len(), 1);

    assert_eq!(module.find_export_func("compute"), Some(0));

    // Execute in WasmInstance
    let mut instance = WasmInstance::new(module, 10_000);
    let res = instance.call_export("compute", &[]).expect("call compute");
    assert_eq!(res, Some(WasmValue::I32(42)));
    assert!(instance.gas_meter.gas_consumed > 0);
}

#[test]
fn test_pii_masking_streaming_filter() {
    let raw_payload = b"User: bob, CC: 4111-2222-3333-4444, SSN: 987-65-4321, Status: active";
    let mut gas = GasMeter::new(10_000);

    let redacted = execute_pii_redaction(raw_payload, &mut gas).expect("pii redact");
    let result = String::from_utf8_lossy(&redacted);

    assert_eq!(
        result,
        "User: bob, CC: XXXX-XXXX-XXXX-XXXX, SSN: XXX-XX-XXXX, Status: active"
    );
    assert!(!result.contains("4111-2222-3333-4444"));
    assert!(!result.contains("987-65-4321"));
    assert!(gas.gas_consumed > 0);
}

#[test]
fn test_schema_transcoding_json_columnar_roundtrip() {
    let json_input = b"{\"event\":\"file_transfer\",\"bytes\":1048576,\"tenant\":\"org-42\"}";
    let mut gas = GasMeter::new(10_000);

    // Transcode to binary format
    let binary = execute_json_to_binary_transcode(json_input, &mut gas).expect("json to binary");
    assert!(binary.starts_with(b"VXBC"));

    // Transcode back to json
    let restored = execute_binary_to_json_transcode(&binary, &mut gas).expect("binary to json");
    assert_eq!(&restored, json_input);
}

#[test]
fn test_multi_stage_transform_pipeline_execution() {
    let mut pipeline = TransformPipeline::new("pipeline-finance-01", "tenant-fintech");
    pipeline
        .add_stage(PipelineStage::new(
            "stage-1-pii",
            FilterKind::PiiRedaction,
            50_000,
        ))
        .add_stage(PipelineStage::new(
            "stage-2-compress",
            FilterKind::SchemaTranscodeJsonToBinary,
            50_000,
        ))
        .add_stage(PipelineStage::new(
            "stage-3-checksum",
            FilterKind::ChecksumStamping,
            50_000,
        ));

    let input_chunk = b"{\"account\": \"1001-2002-3003-4004\", \"balance\": 95000}";
    let (output_chunk, report) = pipeline.execute(input_chunk).expect("execute pipeline");

    assert!(report.is_success);
    assert_eq!(report.stages_executed, 3);
    assert_eq!(report.original_size_bytes, input_chunk.len());
    assert!(report.total_gas_consumed > 0);
    assert_ne!(report.input_blake3_hex, report.output_blake3_hex);
    assert!(output_chunk.ends_with(b"B3CK") || output_chunk.len() > input_chunk.len());
}

#[test]
fn test_tenant_sandbox_isolation_and_quotas() {
    let mut mgr = TenantSandboxManager::new();

    // Tenant A setup
    let sandbox_a = mgr.get_or_create_sandbox("tenant-alpha");
    let mut pipe_a = TransformPipeline::new("pipe-a", "tenant-alpha");
    pipe_a.add_stage(PipelineStage::new(
        "redact",
        FilterKind::PiiRedaction,
        20_000,
    ));
    sandbox_a
        .register_pipeline(pipe_a)
        .expect("register pipe a");

    let chunk_a = b"Sensitive Alpha: 1234-5678-9012-3456";
    let (out_a, _report_a) = sandbox_a
        .process_chunk("pipe-a", chunk_a)
        .expect("process a");
    assert_eq!(
        String::from_utf8_lossy(&out_a),
        "Sensitive Alpha: XXXX-XXXX-XXXX-XXXX"
    );
    assert_eq!(sandbox_a.total_chunks_processed, 1);

    // Tenant B setup
    let sandbox_b = mgr.get_or_create_sandbox("tenant-beta");
    assert_eq!(sandbox_b.total_chunks_processed, 0);
    assert!(sandbox_b.get_pipeline("pipe-a").is_none());
}

#[test]
fn test_ebpf_fastpath_classifier_routing() {
    let mut classifier = FastPathClassifier::new();
    classifier.add_rule(FastPathRule {
        rule_id: "media-bypass".to_string(),
        magic_prefix: Some(b"\xFF\xD8\xFF".to_vec()), // JPEG SOI
        min_size: 3,
        max_size: 10_000_000,
        target_pipeline: None, // Direct zero-copy bypass
    });
    classifier.add_rule(FastPathRule {
        rule_id: "customer-stream".to_string(),
        magic_prefix: Some(b"CUST:".to_vec()),
        min_size: 5,
        max_size: 1_000_000,
        target_pipeline: Some("cust-pii-pipeline".to_string()),
    });

    // 1. Pre-compressed Zstd bypasses
    let zstd_chunk = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x11, 0x22];
    assert!(matches!(
        classifier.classify(&zstd_chunk),
        FastPathDecision::Bypass { .. }
    ));

    // 2. JPEG matches media-bypass rule
    let jpeg_chunk = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    assert!(matches!(
        classifier.classify(&jpeg_chunk),
        FastPathDecision::Bypass { .. }
    ));

    // 3. Customer stream matches transform rule
    let cust_chunk = b"CUST:4111-2222-3333-4444:Bob";
    assert_eq!(
        classifier.classify(cust_chunk),
        FastPathDecision::Transform {
            pipeline_id: "cust-pii-pipeline".to_string()
        }
    );
}

#[test]
fn test_wasi_context_capabilities_and_streams() {
    let input = b"In-Flight Payload Stream".to_vec();
    let mut caps = WasiCapabilities::default();
    caps.allow_clocks = true;
    caps.allow_random = true;

    let mut ctx = WasiContext::new(input, caps);
    let mut mem = WasmMemory::new(1, Some(1));
    let mut gas = GasMeter::new(1000);

    let read_bytes = ctx
        .host_stream_read(&mut mem, &mut gas, 0, 9)
        .expect("read stream");
    assert_eq!(read_bytes, 9);
    assert_eq!(mem.read_bytes(0, 9).expect("read mem"), b"In-Flight");

    ctx.host_stream_write(&mem, &mut gas, 0, 9)
        .expect("write stream");
    assert_eq!(&ctx.stream.output_data, b"In-Flight");

    let now = ctx.host_clock_now(&mut gas).expect("clock now");
    assert!(now > 0);
}
