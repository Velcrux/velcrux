//! M6 end-to-end chunking test (`docs/ARCHITECTURE.md` §12).
//!
//! **Exit criterion (M6):** *"Insertion at offset 0 reuses ≥ 95% under CDC"*
//!
//! This integration test suite exercises:
//! 1. Exit criterion verification: Insertion of 1 byte, 37 bytes, and 1 MiB at offset 0
//!    achieves ≥ 95% reuse under CDC, while dropping reuse to 0% under Fixed chunking.
//! 2. Middle edit blast radius: Local modifications perturb only immediate neighboring chunks
//!    under CDC, preserving all preceding and subsequent chunks.
//! 3. Bit-for-bit concatenation reconstruction for both Fixed and CDC across empty, small,
//!    and multi-megabyte streams.
//! 4. Hard boundary clamps: Enforcement of `min` and `max` (4 MiB) clamps even on adversarial
//!    repeating patterns.
//! 5. Memory-bounded streaming chunking via `ChunkEngine::chunk_reader`.
//! 6. Manifest scanner integration supporting both Fixed and CDC modes.

use std::io::Cursor;
use tempfile::tempdir;

use velcrux_core::chunking::{
    ChunkEngine, ChunkMode, ChunkParams, ReuseStats,
};
use velcrux_core::manifest::entry::ChunkDesc;
use velcrux_core::manifest::scanner::{scan_single_file_with_mode, SCANNER_BUFFER_SIZE};
use velcrux_core::manifest::writer::ManifestWriter;
use velcrux_core::util::Hash;

/// Generates pseudorandom non-repeating byte content of `size` bytes.
fn generate_test_content(size: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut state = seed;
    for _ in 0..(size / 8) {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    let rem = size % 8;
    if rem > 0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes()[..rem]);
    }
    out
}

/// Helper to chunk an in-memory buffer and return the list of [`ChunkDesc`].
fn chunk_buffer(data: &[u8], mode: ChunkMode, params: ChunkParams) -> Vec<ChunkDesc> {
    let mut chunks = Vec::new();
    let reader = Cursor::new(data);
    let _ = ChunkEngine::chunk_reader(
        reader,
        mode,
        params,
        SCANNER_BUFFER_SIZE,
        |desc, _payload| {
            chunks.push(desc);
            Ok(())
        },
    )
    .unwrap();
    chunks
}

/// **Exit criterion (M6):** *"Insertion at offset 0 reuses ≥ 95% under CDC"*
///
/// Tests that inserting bytes at offset 0 of a 64 MiB file preserves ≥ 95%
/// byte reuse under CDC, while Fixed chunking collapses to 0% reuse on unaligned shifts.
#[test]
fn m6_exit_test_insertion_at_offset_0_reuses_95_percent_under_cdc() {
    let file_size = 64 * 1024 * 1024; // 64 MiB
    let original = generate_test_content(file_size, 0x9E3779B97F4A7C15);

    let cdc_params = ChunkParams::default(); // min 256 KiB, target 1 MiB, max 4 MiB
    let fixed_params = ChunkParams::fixed(1024 * 1024); // 1 MiB fixed

    let orig_cdc_chunks = chunk_buffer(&original, ChunkMode::Cdc, cdc_params);
    let orig_fixed_chunks = chunk_buffer(&original, ChunkMode::Fixed, fixed_params);

    assert!(
        orig_cdc_chunks.len() >= 40 && orig_cdc_chunks.len() <= 80,
        "CDC should produce approximately 64 chunks for 64 MiB at 1 MiB target, got {}",
        orig_cdc_chunks.len()
    );
    assert_eq!(
        orig_fixed_chunks.len(),
        64,
        "Fixed 1 MiB should produce exactly 64 chunks for 64 MiB"
    );

    // Test cases: 1-byte, 37-byte, and 1-MiB insertion at offset 0
    let insertions = vec![
        ("1-byte insertion", vec![0x42u8]),
        ("37-byte insertion", vec![0xAAu8; 37]),
        ("1-MiB insertion", vec![0x55u8; 1024 * 1024]),
    ];

    for (label, prefix) in insertions {
        let mut modified = Vec::with_capacity(prefix.len() + original.len());
        modified.extend_from_slice(&prefix);
        modified.extend_from_slice(&original);

        // 1. CDC chunking reuse check
        let mod_cdc_chunks = chunk_buffer(&modified, ChunkMode::Cdc, cdc_params);
        let cdc_stats = ReuseStats::compute(&orig_cdc_chunks, &mod_cdc_chunks);

        println!(
            "[{}] CDC: total={} bytes, reused={} bytes, ratio={:.4} ({:.2}%)",
            label,
            cdc_stats.total_bytes,
            cdc_stats.reused_bytes,
            cdc_stats.byte_reuse_ratio,
            cdc_stats.byte_reuse_ratio * 100.0
        );

        // Required exit criterion: ≥ 95% reuse under CDC
        assert!(
            cdc_stats.byte_reuse_ratio >= 0.95,
            "[{}] CDC reuse must be >= 0.95 (95%), got {:.4} ({:.2}%)",
            label,
            cdc_stats.byte_reuse_ratio,
            cdc_stats.byte_reuse_ratio * 100.0
        );

        // 2. Fixed chunking comparison check
        let mod_fixed_chunks = chunk_buffer(&modified, ChunkMode::Fixed, fixed_params);
        let fixed_stats = ReuseStats::compute(&orig_fixed_chunks, &mod_fixed_chunks);

        println!(
            "[{}] Fixed: total={} bytes, reused={} bytes, ratio={:.4} ({:.2}%)",
            label,
            fixed_stats.total_bytes,
            fixed_stats.reused_bytes,
            fixed_stats.byte_reuse_ratio,
            fixed_stats.byte_reuse_ratio * 100.0
        );

        // For unaligned insertions (1-byte, 37-byte), fixed chunking reuse drops to ~0%
        if prefix.len() % (1024 * 1024) != 0 {
            assert_eq!(
                fixed_stats.reused_chunks, 0,
                "[{}] Fixed chunking should have 0 matching chunks under unaligned shift, got {}",
                label, fixed_stats.reused_chunks
            );
            assert_eq!(
                fixed_stats.reused_bytes, 0,
                "[{}] Fixed chunking should have 0 reused bytes under unaligned shift",
                label
            );
        }
    }
}

/// Tests that a modification in the middle of a file only invalidates
/// the local chunk(s), while preserving the rest under CDC.
#[test]
fn m6_middle_edit_blast_radius() {
    let file_size = 32 * 1024 * 1024; // 32 MiB
    let original = generate_test_content(file_size, 0x123456789ABCDEF0);
    let cdc_params = ChunkParams::default();

    let orig_chunks = chunk_buffer(&original, ChunkMode::Cdc, cdc_params);

    // Insert 128 bytes right in the middle (at 16 MiB)
    let mid = 16 * 1024 * 1024;
    let mut modified = Vec::with_capacity(file_size + 128);
    modified.extend_from_slice(&original[..mid]);
    modified.extend_from_slice(&vec![0xEEu8; 128]);
    modified.extend_from_slice(&original[mid..]);

    let mod_chunks = chunk_buffer(&modified, ChunkMode::Cdc, cdc_params);
    let stats = ReuseStats::compute(&orig_chunks, &mod_chunks);

    println!(
        "[middle edit] CDC reuse: {:.4} ({:.2}%)",
        stats.byte_reuse_ratio,
        stats.byte_reuse_ratio * 100.0
    );

    // Blast radius of a single edit in a 32 MiB file is ~1-2 chunks, so reuse is > 95%
    assert!(
        stats.byte_reuse_ratio >= 0.95,
        "CDC reuse under middle edit should be >= 0.95, got {:.4}",
        stats.byte_reuse_ratio
    );
}

/// Tests that concatenating chunks reproduces the exact original stream
/// across empty files, sub-chunk files, and multi-megabyte streams.
#[test]
fn m6_exact_concatenation_reconstruction() {
    let test_sizes = [0, 1, 100, 4096, 256 * 1024, 1024 * 1024 + 500, 8 * 1024 * 1024];

    for &size in &test_sizes {
        let input = generate_test_content(size, 0xCAFEBABE);

        for mode in [ChunkMode::Fixed, ChunkMode::Cdc] {
            let params = match mode {
                ChunkMode::Fixed => ChunkParams::fixed(512 * 1024),
                ChunkMode::Cdc => ChunkParams::default(),
            };

            let mut reconstructed = Vec::with_capacity(size);
            let mut chunk_count = 0usize;

            let reader = Cursor::new(&input);
            let (whole_hash, total_bytes) = ChunkEngine::chunk_reader(
                reader,
                mode,
                params,
                64 * 1024,
                |desc, payload| {
                    assert_eq!(desc.length as usize, payload.len());
                    assert_eq!(desc.hash.unwrap(), Hash::of(payload));
                    reconstructed.extend_from_slice(payload);
                    chunk_count += 1;
                    Ok(())
                },
            )
            .unwrap();

            assert_eq!(total_bytes, size as u64);
            assert_eq!(reconstructed.len(), size);
            assert_eq!(reconstructed, input, "Payload mismatch for size {size}");
            assert_eq!(whole_hash, Hash::of(&input));

            if size == 0 {
                assert_eq!(chunk_count, 0);
            } else {
                assert!(chunk_count >= 1);
            }
        }
    }
}

/// Tests that hard boundary clamps (`min` and `max`) are strictly enforced,
/// even against adversarial repeating data (e.g. 16 MiB of identical bytes).
#[test]
fn m6_hard_boundary_clamps_adversarial() {
    let adversarial_data = vec![0x00u8; 16 * 1024 * 1024]; // 16 MiB of zeros
    let params = ChunkParams {
        min: 256 * 1024,
        target: 1024 * 1024,
        max: 4 * 1024 * 1024,
    };

    let mut chunk_lengths = Vec::new();
    let reader = Cursor::new(&adversarial_data);
    let _ = ChunkEngine::chunk_reader(
        reader,
        ChunkMode::Cdc,
        params,
        SCANNER_BUFFER_SIZE,
        |desc, _payload| {
            chunk_lengths.push(desc.length);
            Ok(())
        },
    )
    .unwrap();

    assert!(!chunk_lengths.is_empty());
    let total_chunks = chunk_lengths.len();

    for (idx, &len) in chunk_lengths.iter().enumerate() {
        // Hard max clamp check: strictly <= max (4 MiB)
        assert!(
            len <= params.max,
            "Chunk {} length {} exceeds max {}",
            idx,
            len,
            params.max
        );

        // Hard min clamp check: all non-final chunks must be >= min (256 KiB)
        if idx + 1 < total_chunks {
            assert!(
                len >= params.min,
                "Non-final chunk {} length {} is below min {}",
                idx,
                len,
                params.min
            );
        }
    }
}

/// Tests that directory scanning with `scan_single_file_with_mode` supports
/// both Fixed and CDC chunking and produces valid, verified manifests.
#[test]
fn m6_manifest_scanner_fixed_and_cdc_parity() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("dataset.bin");
    let content = generate_test_content(8 * 1024 * 1024, 0x5555AAAA);
    std::fs::write(&file_path, &content).unwrap();

    let spill_cdc = dir.path().join("spill_cdc.manifest");
    let spill_fixed = dir.path().join("spill_fixed.manifest");

    // 1. Scan with CDC
    let mut writer_cdc = ManifestWriter::new(&spill_cdc, ChunkParams::default()).unwrap();
    scan_single_file_with_mode(
        dir.path(),
        "dataset.bin",
        &mut writer_cdc,
        ChunkMode::Cdc,
        ChunkParams::default(),
    )
    .unwrap();
    let (cdc_begin, _cdc_end, _spill_cdc) = writer_cdc.finish().unwrap();

    // 2. Scan with Fixed
    let fixed_params = ChunkParams::fixed(1024 * 1024);
    let mut writer_fixed = ManifestWriter::new(&spill_fixed, fixed_params).unwrap();
    scan_single_file_with_mode(
        dir.path(),
        "dataset.bin",
        &mut writer_fixed,
        ChunkMode::Fixed,
        fixed_params,
    )
    .unwrap();
    let (fixed_begin, _fixed_end, _spill_fixed) = writer_fixed.finish().unwrap();

    assert_eq!(cdc_begin.file_count, 1);
    assert_eq!(fixed_begin.file_count, 1);
    assert_eq!(cdc_begin.total_bytes, 8 * 1024 * 1024);
    assert_eq!(fixed_begin.total_bytes, 8 * 1024 * 1024);

    // Both manifests are non-empty and have valid non-zero content digests
    assert!(!cdc_begin.manifest_hash.is_zero());
    assert!(!fixed_begin.manifest_hash.is_zero());
}
