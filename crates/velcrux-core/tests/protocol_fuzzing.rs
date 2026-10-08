//! Property-based deterministic protocol fuzzing suite (Option AL / REQUIREMENTS.md §49, §50, §22).
//!
//! Validates that all Raven binary wire decoders, message decoders, frame parsers,
//! manifest decoders, and container extractors NEVER panic on malformed, truncated,
//! or adversarial input bytes.
//!
//! Enforces `#![forbid(unsafe_code)]` and `CLAUDE.md` §1 invariant #5.

use bytes::Bytes;
use std::io::Cursor;
use velcrux_core::manifest::codec::{
    decode_chunk_desc, decode_file_entry, encode_chunk_desc, encode_file_entry,
};
use velcrux_core::manifest::entry::{ChunkDesc, FileEntry, FileFlags};
use velcrux_core::manifest::reader::ManifestBatchDecoder;
use velcrux_core::protocol::capabilities::Capabilities;
use velcrux_core::protocol::frame::{
    decode_data_frame_header, decode_data_preamble, decode_frame, encode_data_frame_header,
    encode_data_preamble, encode_frame, header_size_for, DataFrameFlags, DataPreamble, FrameFlags,
    DATA_FRAME_HEADER_LEN, DATA_PREAMBLE_LEN,
};
use velcrux_core::protocol::fuzzing::{assert_decoder_panic_free, assert_no_panic, FuzzMutator};
use velcrux_core::protocol::limits::PROTOCOL_VERSION;
use velcrux_core::protocol::message::*;
use velcrux_core::protocol::varint::{decode_varint, encode_varint};
use velcrux_core::storage::VPath;
use velcrux_core::sync::batch::BatchContainerReader;
use velcrux_core::sync::bloom::BloomFilter;
use velcrux_core::sync::rle::RleBitmap;
use velcrux_core::util::{Hash, TransferId};

#[test]
fn test_fuzz_varint_decoder() {
    let mut mutator = FuzzMutator::new(0x1337_0001);

    // 1. Raw random buffers
    for _ in 0..15_000 {
        let len = (mutator.next_u64() % 32) as usize;
        let buf = mutator.random_bytes(len);
        assert_no_panic(&buf, |b| {
            let _ = decode_varint(b);
        });
    }

    // 2. Mutated valid varints
    let test_values = [
        0u64,
        1,
        127,
        128,
        255,
        256,
        16383,
        16384,
        65535,
        (1 << 21) - 1,
        (1 << 28) - 1,
        (1 << 35) - 1,
        (1 << 42) - 1,
        (1 << 49) - 1,
        (1 << 56) - 1,
        (1 << 62) - 1,
        u64::MAX,
    ];

    let mut tmp = [0u8; 10];
    for &val in &test_values {
        let n = encode_varint(val, &mut tmp);
        let valid = tmp[..n].to_vec();

        // Valid decodes correctly
        let (decoded, consumed) = decode_varint(&valid).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, n);

        // Mutate valid varint with assert_decoder_panic_free
        assert_decoder_panic_free(&mut mutator, &[valid], 100, |b| {
            let _ = decode_varint(b);
        });
    }

    // 3. Overflow and non-canonical boundary attempts
    let ten_bytes_all_msb = [0x80u8; 10];
    assert!(decode_varint(&ten_bytes_all_msb).is_err());
    let eleven_bytes = [0x80u8; 11];
    assert!(decode_varint(&eleven_bytes).is_err());
}

#[test]
fn test_fuzz_frame_decoders() {
    let mut mutator = FuzzMutator::new(0x1337_0002);

    // 1. decode_frame with 25,000 random slices
    for _ in 0..25_000 {
        let len = (mutator.next_u64() % 512) as usize;
        let buf = mutator.random_bytes(len);
        assert_no_panic(&buf, |b| {
            let _ = decode_frame(b);
        });
    }

    // 2. Valid frames mutated across all byte positions
    let hello = Hello::default_client();
    let payload = hello.encode().unwrap();
    let mut valid_frame = vec![0u8; header_size_for(payload.len() as u64) + payload.len()];
    let n = encode_frame(&mut valid_frame, HELLO, FrameFlags::NONE, 42, &payload);
    valid_frame.truncate(n);

    // Truncate to every possible length 0..=len
    for i in 0..=valid_frame.len() {
        assert_no_panic(&valid_frame[..i], |b| {
            let _ = decode_frame(b);
        });
    }

    // Mutate valid frame 1,000 times
    assert_decoder_panic_free(&mut mutator, &[valid_frame], 1_000, |b| {
        let _ = decode_frame(b);
    });

    // 3. decode_data_frame_header with 10,000 random slices
    for _ in 0..10_000 {
        let len = (mutator.next_u64() % (DATA_FRAME_HEADER_LEN as u64 + 32)) as usize;
        let buf = mutator.random_bytes(len);
        assert_no_panic(&buf, |b| {
            let _ = decode_data_frame_header(b);
        });
    }

    // Valid data frame header mutated
    let mut data_hdr = vec![0u8; DATA_FRAME_HEADER_LEN];
    encode_data_frame_header(&mut data_hdr, 1024, 4096, DataFrameFlags::NONE, &Hash::ZERO);
    for i in 0..=data_hdr.len() {
        assert_no_panic(&data_hdr[..i], |b| {
            let _ = decode_data_frame_header(b);
        });
    }
    assert_decoder_panic_free(&mut mutator, &[data_hdr], 500, |b| {
        let _ = decode_data_frame_header(b);
    });

    // 4. decode_data_preamble with 10,000 random slices
    for _ in 0..10_000 {
        let len = (mutator.next_u64() % (DATA_PREAMBLE_LEN as u64 + 32)) as usize;
        let buf = mutator.random_bytes(len);
        assert_no_panic(&buf, |b| {
            let _ = decode_data_preamble(b);
        });
    }

    // Valid preamble mutated
    let preamble = DataPreamble {
        transfer_id: TransferId::generate(),
        file_id: 1234,
        stream_seq: 5678,
    };
    let preamble_bytes = encode_data_preamble(&preamble);
    for i in 0..=preamble_bytes.len() {
        assert_no_panic(&preamble_bytes[..i], |b| {
            let _ = decode_data_preamble(b);
        });
    }
    assert_decoder_panic_free(&mut mutator, &[preamble_bytes.to_vec()], 500, |b| {
        let _ = decode_data_preamble(b);
    });
}

#[test]
fn test_fuzz_message_dispatch_random() {
    let mut mutator = FuzzMutator::new(0x1337_0003);

    // 25,000 iterations of Message::decode with random type bytes and payloads
    for _ in 0..25_000 {
        let type_byte = (mutator.next_u64() & 0xFF) as u8;
        let len = (mutator.next_u64() % 1024) as usize;
        let payload = mutator.random_bytes(len);

        assert_no_panic(&payload, |b| {
            let _ = Message::decode(type_byte, b);
        });
    }
}

#[test]
fn test_fuzz_all_26_message_decoders() {
    let mut mutator = FuzzMutator::new(0x1337_0004);

    let mut test_cases: Vec<(u8, Vec<u8>)> = Vec::new();

    // 1. Hello
    let hello = Hello::default_client();
    test_cases.push((HELLO, hello.encode().unwrap().to_vec()));

    // 2. HelloAck
    let ack = HelloAck {
        version: PROTOCOL_VERSION,
        capabilities: Capabilities::from_wire(0x03FF),
        limits: Limits::default(),
        agent: "fuzz_agent/1.0".into(),
    };
    test_cases.push((HELLO_ACK, ack.encode().unwrap().to_vec()));

    // 3. Auth
    let auth = Auth::mtls();
    test_cases.push((AUTH, auth.encode().unwrap().to_vec()));

    // 4. AuthOk
    let auth_ok = AuthOk {
        identity: "user@example.com".into(),
        permissions: 0xFF,
    };
    test_cases.push((AUTH_OK, auth_ok.encode().unwrap().to_vec()));

    // 5. SessionInit
    let session_init = SessionInit {
        bandwidth_bps: 1_000_000,
        priority: 1,
    };
    test_cases.push((SESSION_INIT, session_init.encode().to_vec()));

    // 6. TransferCreate
    let transfer_create = TransferCreate {
        op: TransferOp::Upload,
        src_path: "src.dat".into(),
        dst_path: "dst.dat".into(),
        idempotency_key: "idem_key_1".into(),
        file_size: 1000,
        file_hash: Hash::ZERO,
    };
    test_cases.push((TRANSFER_CREATE, transfer_create.encode().unwrap().to_vec()));

    // 7. TransferCreated
    let transfer_created = TransferCreated {
        transfer_id: TransferId::generate(),
        resumed: false,
        max_chunk_size: 65536,
    };
    test_cases.push((
        TRANSFER_CREATED,
        transfer_created.encode().unwrap().to_vec(),
    ));

    // 8. TransferBegin
    let transfer_begin = TransferBegin {
        transfer_id: TransferId::generate(),
        streams: 1,
    };
    test_cases.push((TRANSFER_BEGIN, transfer_begin.encode().unwrap().to_vec()));

    // 9. TransferPlan
    let transfer_plan = TransferPlan {
        transfer_id: TransferId::generate(),
        bytes_total: 1000,
        bytes_to_transfer: 1000,
        bytes_reusable: 0,
    };
    test_cases.push((TRANSFER_PLAN, transfer_plan.encode().unwrap().to_vec()));

    // 10. Checkpoint
    let checkpoint = Checkpoint {
        transfer_id: TransferId::generate(),
        bytes_transferred: 1000,
        verified_up_to: 1000,
        ts_ms: 1234567,
        completed_chunks: vec![0, 1, 2],
    };
    test_cases.push((CHECKPOINT, checkpoint.encode().unwrap().to_vec()));

    // 11. ManifestBegin
    let manifest_begin = ManifestBegin {
        file_count: 10,
        total_bytes: 10000,
        chunker_params: velcrux_core::chunking::ChunkParams::default(),
        manifest_hash: Hash::ZERO,
    };
    test_cases.push((MANIFEST_BEGIN, manifest_begin.encode().unwrap().to_vec()));

    // 12. ManifestBatch
    let manifest_batch = ManifestBatch {
        batch_index: 0,
        entry_count: 10,
        compressed_payload: Bytes::from_static(&[1, 2, 3, 4]),
    };
    test_cases.push((MANIFEST_BATCH, manifest_batch.encode().unwrap().to_vec()));

    // 13. ManifestEnd
    let manifest_end = ManifestEnd {
        manifest_hash: Hash::ZERO,
    };
    test_cases.push((MANIFEST_END, manifest_end.encode().unwrap().to_vec()));

    // 14. InventoryHint
    let inventory_hint = InventoryHint {
        transfer_id: TransferId::generate(),
        filter_bits: 64,
        num_hashes: 4,
        bitset: Bytes::from_static(&[0u8; 8]),
    };
    test_cases.push((INVENTORY_HINT, inventory_hint.encode().unwrap().to_vec()));

    // 15. ChunkQuery
    let chunk_query = ChunkQuery {
        transfer_id: TransferId::generate(),
        query_seq: 1,
        chunk_hashes: vec![Hash::ZERO, Hash::of(b"chunk1")],
    };
    test_cases.push((CHUNK_QUERY, chunk_query.encode().unwrap().to_vec()));

    // 16. ChunkResponse
    let chunk_response = ChunkResponse {
        transfer_id: TransferId::generate(),
        query_seq: 1,
        total_chunks: 10,
        have_count: 5,
        rle_bitmap: Bytes::from_static(b"\x01\x02"),
    };
    test_cases.push((CHUNK_RESPONSE, chunk_response.encode().unwrap().to_vec()));

    // 17. Commit
    let commit = Commit {
        transfer_id: TransferId::generate(),
    };
    test_cases.push((COMMIT, commit.encode().unwrap().to_vec()));

    // 18. Committed
    let committed = Committed {
        transfer_id: TransferId::generate(),
        files: 1,
    };
    test_cases.push((COMMITTED, committed.encode().unwrap().to_vec()));

    // 19. Verify
    let verify = Verify {
        transfer_id: TransferId::generate(),
        expected_hash: Hash::ZERO,
    };
    test_cases.push((VERIFY, verify.encode().unwrap().to_vec()));

    // 20. VerifyResult
    let verify_result = VerifyResult {
        transfer_id: TransferId::generate(),
        ok: true,
        computed_hash: Hash::ZERO,
    };
    test_cases.push((VERIFY_RESULT, verify_result.encode().unwrap().to_vec()));

    // 21. Cancel
    let cancel = Cancel {
        transfer_id: TransferId::generate(),
        reason_code: 1,
    };
    test_cases.push((CANCEL, cancel.encode().unwrap().to_vec()));

    // 22. Ping
    let ping = Ping {
        nonce: 99999,
        sender_ts_ms: 123456,
    };
    test_cases.push((PING, ping.encode().to_vec()));

    // 23. Pong
    let pong = Pong {
        nonce: 99999,
        sender_ts_ms: 123456,
    };
    test_cases.push((PONG, pong.encode().to_vec()));

    // 24. ErrorMsg
    let err = ErrorMsg::new(
        velcrux_core::protocol::error::ErrorCode::ProtocolViolation,
        "unexpected test error",
    );
    test_cases.push((ERROR, err.encode().unwrap().to_vec()));

    // 25. Bye
    let bye = Bye { code: 0 };
    test_cases.push((BYE, bye.encode().to_vec()));

    // 26. StatQuery
    let stat_query = StatQuery {
        transfer_id: TransferId::generate(),
    };
    test_cases.push((STAT, stat_query.encode().to_vec()));

    // 27. StatResult
    let stat_result = StatResult {
        transfer_id: TransferId::generate(),
        found: true,
        status: "COMPLETED".into(),
        direction: "PUSH".into(),
        remote_path: "data/file.txt".into(),
        file_size: 10000,
        bytes_completed: 10000,
        verified_up_to: 10000,
        created_ms: 1000,
        updated_ms: 2000,
    };
    test_cases.push((STAT_RESULT, stat_result.encode().unwrap().to_vec()));

    // 28. ListQuery
    let list_query = ListQuery {
        url_prefix: "data/".into(),
    };
    test_cases.push((LIST, list_query.encode().unwrap().to_vec()));

    // 29. ListResult
    let list_result = ListResult {
        entries: vec![stat_result],
    };
    test_cases.push((LIST_RESULT, list_result.encode().unwrap().to_vec()));

    // 30. Resume
    let resume = Resume {
        transfer_id: TransferId::generate(),
        idempotency_key: "idem_key_1".into(),
    };
    test_cases.push((RESUME, resume.encode().unwrap().to_vec()));

    // 31. ResumeState
    let resume_state = ResumeState {
        transfer_id: TransferId::generate(),
        staging_relpath: ".staging/t1".into(),
        file_size: 10000,
        bytes_completed: 10000,
        verified_up_to: 10000,
        file_hash: Hash::ZERO,
        completed_chunks: vec![0, 1],
    };
    test_cases.push((RESUME_STATE, resume_state.encode().unwrap().to_vec()));

    // For each message type:
    for (type_byte, encoded) in test_cases {
        // 1. Valid instance must decode via Message::decode
        let decoded = Message::decode(type_byte, &encoded);
        assert!(decoded.is_ok(), "Failed to decode type {type_byte}");

        // 2. Truncate to every length 0..=len
        for i in 0..=encoded.len() {
            assert_no_panic(&encoded[..i], |b| {
                let _ = Message::decode(type_byte, b);
            });
        }

        // 3. Mutate 150 times per message type
        assert_decoder_panic_free(&mut mutator, &[encoded], 150, |b| {
            let _ = Message::decode(type_byte, b);
        });
    }
}

#[test]
fn test_fuzz_manifest_decoders() {
    let mut mutator = FuzzMutator::new(0x1337_0005);

    // 1. FileEntry encoder / decoder fuzzing
    let entry = FileEntry {
        flags: FileFlags::regular(),
        path: VPath::validate("dir/nested/file.txt").unwrap(),
        size: 2048,
        mode: 0o644,
        mtime_sec: 1700000000,
        mtime_nsec: 123456,
        file_hash: Hash::of(b"sample_content"),
        chunks: vec![
            ChunkDesc::new(1024, Hash::of(b"chunk1")),
            ChunkDesc::new(1024, Hash::of(b"chunk2")),
        ],
        symlink_target: None,
        hardlink_target: None,
        xattrs: vec![
            ("user.tag".into(), b"production".to_vec()),
            ("user.checksum".into(), vec![0xDE, 0xAD]),
        ],
    };

    let mut valid_entry_bytes = Vec::new();
    encode_file_entry(&entry, &mut valid_entry_bytes);

    let (decoded, consumed) = decode_file_entry(&valid_entry_bytes).unwrap();
    assert_eq!(consumed, valid_entry_bytes.len());
    assert_eq!(decoded.size, 2048);

    // Truncate to every length 0..=len
    for i in 0..=valid_entry_bytes.len() {
        assert_no_panic(&valid_entry_bytes[..i], |b| {
            let _ = decode_file_entry(b);
        });
    }

    // Mutate 2,000 times
    assert_decoder_panic_free(&mut mutator, &[valid_entry_bytes], 2_000, |b| {
        let _ = decode_file_entry(b);
    });

    // 2. decode_chunk_desc fuzzing
    let chunk = ChunkDesc::new(4096, Hash::of(b"chunk_desc_test"));
    let mut chunk_bytes = Vec::new();
    encode_chunk_desc(&chunk, &mut chunk_bytes);

    for i in 0..=chunk_bytes.len() {
        assert_no_panic(&chunk_bytes[..i], |b| {
            let _ = decode_chunk_desc(b);
        });
    }

    assert_decoder_panic_free(&mut mutator, &[chunk_bytes], 1_000, |b| {
        let _ = decode_chunk_desc(b);
    });

    // 3. 10,000 raw random bytes to decode_file_entry
    for _ in 0..10_000 {
        let len = (mutator.next_u64() % 512) as usize;
        let buf = mutator.random_bytes(len);
        assert_no_panic(&buf, |b| {
            let _ = decode_file_entry(b);
        });
    }
}

#[test]
fn test_fuzz_manifest_batch_decoder() {
    let mut mutator = FuzzMutator::new(0x1337_0006);

    for _ in 0..1_000 {
        let len = (mutator.next_u64() % 256) as usize;
        let compressed = mutator.random_bytes(len);

        let batch = ManifestBatch {
            batch_index: 0,
            entry_count: (mutator.next_u64() % 5000) as u32,
            compressed_payload: Bytes::from(compressed),
        };

        let mut decoder = ManifestBatchDecoder::new(Hash::ZERO);
        let _ = decoder.decode_batch(&batch);
    }
}

#[test]
fn test_fuzz_sync_primitives() {
    let mut mutator = FuzzMutator::new(0x1337_0007);

    // 1. RleBitmap::decode
    for _ in 0..10_000 {
        let len = (mutator.next_u64() % 256) as usize;
        let buf = mutator.random_bytes(len);
        let expected = (mutator.next_u64() % 50_000) as u32;

        assert_no_panic(&buf, |b| {
            let _ = RleBitmap::decode(b, expected);
        });
    }

    // 2. BloomFilter::from_bytes
    for _ in 0..10_000 {
        let len = (mutator.next_u64() % 128) as usize;
        let buf = mutator.random_bytes(len);
        let num_bits = (mutator.next_u64() % 2000) as u32;
        let num_hashes = (mutator.next_u64() % 20) as u8;

        assert_no_panic(&buf, |b| {
            let _ = BloomFilter::from_bytes(b, num_bits, num_hashes);
        });
    }

    // 3. VPath::validate
    for _ in 0..10_000 {
        let len = (mutator.next_u64() % 256) as usize;
        let raw_bytes = mutator.random_bytes(len);
        if let Ok(s) = std::str::from_utf8(&raw_bytes) {
            let _ = VPath::validate(s);
        }
    }
}

#[test]
fn test_fuzz_vbatch_container_unpack() {
    let mut mutator = FuzzMutator::new(0x1337_0008);
    let temp_dir = tempfile::tempdir().unwrap();

    // 1. Random bytes fed to BatchContainerReader::unpack
    for _ in 0..1_000 {
        let len = (mutator.next_u64() % 1024) as usize;
        let buf = mutator.random_bytes(len);
        let mut cursor = Cursor::new(&buf);

        let res = BatchContainerReader::unpack(&mut cursor, temp_dir.path());
        assert!(res.is_err());
    }

    // 2. Malformed VBATCH/1 magic and header crafted inputs
    let mut valid_magic = b"VBATCH\x01\x00".to_vec();
    valid_magic.extend_from_slice(&(1u32).to_be_bytes()); // entry_count = 1
    valid_magic.extend_from_slice(&(20u32).to_be_bytes()); // index_len = 20
    valid_magic.extend_from_slice(&(0u64).to_be_bytes()); // total_bytes = 0
    valid_magic.extend_from_slice(b"{\"invalid\": \"json\"}");

    for _ in 0..500 {
        let corrupted = mutator.mutate(&valid_magic);
        let mut cursor = Cursor::new(&corrupted);
        let _ = BatchContainerReader::unpack(&mut cursor, temp_dir.path());
    }
}
