//! Integration tests for Option DJ: Autonomous Zero-Copy User-Space Storage Engine via `io_uring` Kernel Ring Buffers (`ADR-078`).

#![forbid(unsafe_code)]

use velcrux_core::ioring::{
    feature_flags, splice_flags, IoUringOp, IoUringProbe, IoUringSqe, IoUringStorageEngine,
    ZeroCopySplicePipeline,
};

#[test]
fn test_fixed_buffer_registration_and_vectored_transfers() {
    let mut engine = IoUringStorageEngine::with_capacity(128, false);

    // 1. Pre-register 4 x 64 KiB fixed buffers (256 KiB total)
    let buf0 = engine.buffers.register(65536).expect("register buf 0");
    let buf1 = engine.buffers.register(65536).expect("register buf 1");
    let buf2 = engine.buffers.register(65536).expect("register buf 2");
    let buf3 = engine.buffers.register(65536).expect("register buf 3");

    assert_eq!(engine.buffers.count(), 4);
    assert_eq!(engine.buffers.total_registered_bytes, 262_144);

    // 2. Write test payload into fixed buffer 1
    let payload = b"velcrux-fastcdc-chunk-payload-data-stream-4096-bytes";
    engine
        .buffers
        .write_slice(buf1, 0, payload)
        .expect("write slice");

    // 3. Enqueue 4 WriteFixed operations
    engine.write_chunk_fixed(10, buf0, 0, 65536, 1001).unwrap();
    engine
        .write_chunk_fixed(10, buf1, 65536, 65536, 1002)
        .unwrap();
    engine
        .write_chunk_fixed(10, buf2, 131072, 65536, 1003)
        .unwrap();
    engine
        .write_chunk_fixed(10, buf3, 196608, 65536, 1004)
        .unwrap();

    assert_eq!(engine.total_submitted, 4);
    assert_eq!(engine.in_flight_count(), 4);

    // 4. Process all submissions
    let processed = engine.process_submissions(10);
    assert_eq!(processed, 4);
    assert_eq!(engine.total_completed, 4);
    assert_eq!(engine.total_zero_copy_bytes, 262_144);

    // 5. Reap CQEs
    let cqes = engine.reap_completions(10);
    assert_eq!(cqes.len(), 4);
    for (i, cqe) in cqes.iter().enumerate() {
        assert_eq!(cqe.user_data, (1001 + i) as u64);
        assert!(cqe.is_success());
        assert_eq!(cqe.bytes_transferred(), Some(65536));
    }
}

#[test]
fn test_zero_copy_splice_pipeline_throughput() {
    let mut pipeline = ZeroCopySplicePipeline::new();

    // Allocate 2 distinct splice channels (e.g. Socket -> Pipe -> Target File)
    let chan_a = pipeline.allocate_channel(5, 6);
    let chan_b = pipeline.allocate_channel(7, 8);

    assert_eq!(pipeline.channels.len(), 2);

    // Splice 1 MiB on channel A
    let transferred_a = pipeline
        .execute_splice(chan_a, 1_048_576, splice_flags::SPLICE_F_MOVE)
        .expect("splice A");
    assert_eq!(transferred_a, 1_048_576);

    // Splice 2 MiB on channel B
    let transferred_b = pipeline
        .execute_splice(chan_b, 1_048_576, splice_flags::SPLICE_F_MOVE)
        .expect("splice B part 1");
    assert_eq!(transferred_b, 1_048_576);

    let transferred_b2 = pipeline
        .execute_splice(chan_b, 1_048_576, splice_flags::SPLICE_F_MOVE)
        .expect("splice B part 2");
    assert_eq!(transferred_b2, 1_048_576);

    assert_eq!(pipeline.total_splice_operations, 3);
    assert_eq!(pipeline.total_bytes_spliced, 3_145_728); // 3 MiB
    assert_eq!(pipeline.cpu_memory_copies_avoided, 6); // 2 copies avoided per splice
    assert_eq!(pipeline.zero_copy_efficiency_pct(), 100.0);
}

#[test]
fn test_sqpoll_kernel_polling_batch_submission() {
    // Engine instantiated with SQPOLL enabled
    let mut engine = IoUringStorageEngine::with_capacity(256, true);
    assert!(engine.params.is_sqpoll_enabled());

    let mut batch = Vec::with_capacity(128);
    for i in 0..128 {
        batch.push(IoUringSqe::write_fixed(
            3,
            0,
            (i * 4096) as u64,
            4096,
            (2000 + i) as u64,
        ));
    }

    let submitted = engine.submit_batch(&batch).expect("submit batch");
    assert_eq!(submitted, 128);
    assert_eq!(engine.syscalls_avoided_by_sqpoll, 128);

    // SQPOLL thread executes batch
    let processed = engine.process_submissions(256);
    assert_eq!(processed, 128);
    assert_eq!(engine.sqpoll_cycles, 1);
    assert_eq!(engine.in_flight_count(), 0);

    let cqes = engine.reap_completions(256);
    assert_eq!(cqes.len(), 128);
}

#[test]
fn test_io_uring_probe_kernel_features() {
    let probe = IoUringProbe::standard_linux_probe();

    // Verify all essential zero-copy and networking opcodes
    assert!(probe.is_opcode_supported(IoUringOp::ReadFixed));
    assert!(probe.is_opcode_supported(IoUringOp::WriteFixed));
    assert!(probe.is_opcode_supported(IoUringOp::Splice));
    assert!(probe.is_opcode_supported(IoUringOp::Tee));
    assert!(probe.is_opcode_supported(IoUringOp::SendZc));
    assert!(probe.is_opcode_supported(IoUringOp::SendmsgZc));

    // Verify feature flags
    assert!(probe.supports_feature(feature_flags::IORING_FEAT_FAST_POLL));
    assert!(probe.supports_feature(feature_flags::IORING_FEAT_CQE_SKIP));
    assert!(probe.supports_feature(feature_flags::IORING_FEAT_NODROP));
    assert!(probe.supports_sqpoll());
}

#[test]
fn test_backpressure_and_overflow_handling() {
    let mut engine = IoUringStorageEngine::with_capacity(16, false);
    let cap = engine.sq.capacity; // minimum 16

    // 1. Fill SQ to maximum capacity
    for i in 0..cap {
        engine
            .submit(IoUringSqe::new(IoUringOp::Nop, 1, i as u64))
            .expect("must fit");
    }
    assert!(engine.sq.is_full());

    // 2. Next submission should fail cleanly with backpressure error
    let overflow_err = engine.submit(IoUringSqe::new(IoUringOp::Nop, 1, 999));
    assert!(overflow_err.is_err());
    assert_eq!(engine.sq.dropped, 1);

    // 3. Process submissions to drain SQ
    let processed = engine.process_submissions(cap);
    assert_eq!(processed, cap);
    assert!(engine.sq.is_empty());

    // 4. Subsequent submission succeeds
    assert!(engine
        .submit(IoUringSqe::new(IoUringOp::Nop, 1, 1000))
        .is_ok());
}
