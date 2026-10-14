//! Integration tests for Option BH: Adaptive Multi-Stream Forward Error Correction (FEC)
//! (`REQUIREMENTS.md` §13, §47, §88).
//!
//! Validates:
//! 1. Systematic Maximum Distance Separable (MDS) Cauchy erasure coding over GF(2^8).
//! 2. Arbitrary symbol loss recovery: any K received symbols from (K+M) reconstructs 100% original payload.
//! 3. Fast-path XOR parity single-loss recovery vs Cauchy linear equation solving.
//! 4. Real-time dynamic `AdaptiveFecController` gating loss tiers (0% to 25% redundancy).
//! 5. Simulated satellite / high-loss WAN channel erasure recovery across multi-block streams with BLAKE3 verification.

#![forbid(unsafe_code)]

use velcrux_core::transport::fec::{
    gf_add, gf_div, gf_inv, gf_mul, simulate_fec_recovery, AdaptiveFecController,
    FecBlockDecoder, FecBlockEncoder, FecCodec, FecProfile, FecSymbol, GfMatrix,
};
use velcrux_core::transport::impairment::DeterministicLossPrng;
use velcrux_core::util::Hash;

#[test]
fn test_galois_field_arithmetic_axioms() {
    // Identity: a ^ 0 = a
    assert_eq!(gf_add(0x42, 0), 0x42);
    // Inverse: a ^ a = 0
    assert_eq!(gf_add(0xab, 0xab), 0);
    // Multiplication identity: a * 1 = a
    assert_eq!(gf_mul(0x7f, 1), 0x7f);
    assert_eq!(gf_mul(1, 0x9c), 0x9c);
    // Multiplication by zero
    assert_eq!(gf_mul(0x55, 0), 0);
    assert_eq!(gf_mul(0, 0x55), 0);

    // Multiplicative inverse: a * inv(a) = 1 for all a in [1..255]
    for a in 1..=255u8 {
        let inv = gf_inv(a);
        assert_eq!(
            gf_mul(a, inv),
            1,
            "Multiplicative inverse failed for symbol 0x{:02x}",
            a
        );
    }

    // Division: a / b * b = a
    for a in 1..=10u8 {
        for b in 1..=10u8 {
            let div = gf_div(a, b);
            assert_eq!(gf_mul(div, b), a);
        }
    }
}

#[test]
fn test_cauchy_matrix_invertibility_and_mds_property() {
    // For Cauchy matrix C_{i, j} = 1 / (x_i ^ y_j) with disjoint x, y sets:
    // Every square submatrix is guaranteed non-singular (MDS property).
    for k in [4, 8, 12, 16] {
        let m = 2;
        let cauchy = GfMatrix::cauchy(m, k);
        assert_eq!(cauchy.rows, m);
        assert_eq!(cauchy.cols, k);

        // Test systematic augmented matrix where first row is parity row 0 and remaining are identity
        let mut sys = GfMatrix::zeros(k, k);
        for i in 0..k {
            if i == 0 {
                // Parity row replaces first source symbol
                for j in 0..k {
                    sys.set(i, j, cauchy.get(0, j));
                }
            } else {
                sys.set(i, i, 1);
            }
        }

        let inv = sys.invert();
        assert!(inv.is_some(), "Cauchy systematic submatrix must be invertible for K={}", k);
    }
}

#[test]
fn test_fec_codec_recovers_arbitrary_erasure_patterns() {
    let k = 8;
    let m = 2;
    let codec = FecCodec::new(k, m);

    let symbol_size = 128;
    let mut original_sources = Vec::with_capacity(k);
    for i in 0..k {
        let mut sym = vec![0u8; symbol_size];
        for b in 0..symbol_size {
            sym[b] = ((i * 37 + b * 13) & 0xff) as u8;
        }
        original_sources.push(sym);
    }

    let repair_symbols = codec.encode(&original_sources);
    assert_eq!(repair_symbols.len(), m);

    // Form complete pool of symbols
    let mut all_symbols = Vec::with_capacity(k + m);
    for (i, s) in original_sources.iter().enumerate() {
        all_symbols.push(FecSymbol {
            index: i,
            data: s.clone(),
        });
    }
    all_symbols.extend(repair_symbols);

    // Test dropping any combination of up to M=2 symbols
    for drop1 in 0..k {
        for drop2 in (drop1 + 1)..k {
            let mut received = Vec::new();
            for s in &all_symbols {
                if s.index != drop1 && s.index != drop2 {
                    received.push(s.clone());
                }
            }

            assert_eq!(received.len(), k);
            let recovered = codec.decode(&received).expect("decoding must succeed when K symbols are present");
            assert_eq!(recovered.len(), k);
            for i in 0..k {
                assert_eq!(
                    recovered[i], original_sources[i],
                    "Mismatch on source symbol {} after dropping {} and {}",
                    i, drop1, drop2
                );
            }
        }
    }
}

#[test]
fn test_fast_path_xor_parity_vs_cauchy_linear_solve() {
    let k = 10;
    let m = 1; // M=1 triggers fast-path XOR
    let codec = FecCodec::new(k, m);

    let symbol_size = 256;
    let mut sources = Vec::new();
    for i in 0..k {
        sources.push(vec![(i as u8) ^ 0xaa; symbol_size]);
    }

    let repair = codec.encode(&sources);
    assert_eq!(repair.len(), 1);
    assert_eq!(repair[0].index, k);

    // Verify XOR parity calculation
    let mut expected_xor = vec![0u8; symbol_size];
    for s in &sources {
        for b in 0..symbol_size {
            expected_xor[b] ^= s[b];
        }
    }
    assert_eq!(repair[0].data, expected_xor);

    // Drop source symbol 4 and recover
    let mut received = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        if i != 4 {
            received.push(FecSymbol {
                index: i,
                data: s.clone(),
            });
        }
    }
    received.push(repair[0].clone());

    let recovered = codec.decode(&received).expect("fast-path recovery");
    assert_eq!(recovered[4], sources[4]);
}

#[test]
fn test_adaptive_controller_telemetry_scaling() {
    let mut ctrl = AdaptiveFecController::new(FecProfile::Auto);

    // <0.5% loss -> disabled parity
    assert_eq!(ctrl.adapt_to_loss(0.001), (20, 0));
    assert_eq!(ctrl.snapshot().redundancy_pct, 0.0);

    // 0.5% - 2.0% loss -> 5% parity
    assert_eq!(ctrl.adapt_to_loss(0.015), (20, 1));
    assert_eq!(ctrl.snapshot().redundancy_pct, 5.0);

    // 2.0% - 5.0% loss -> 12.5% parity
    assert_eq!(ctrl.adapt_to_loss(0.035), (16, 2));
    assert_eq!(ctrl.snapshot().redundancy_pct, 12.5);

    // 5.0% - 10.0% loss -> 20% parity
    assert_eq!(ctrl.adapt_to_loss(0.075), (10, 2));
    assert_eq!(ctrl.snapshot().redundancy_pct, 20.0);

    // >= 10.0% loss -> 25% satellite-grade parity
    assert_eq!(ctrl.adapt_to_loss(0.12), (8, 2));
    assert_eq!(ctrl.snapshot().redundancy_pct, 25.0);
}

#[test]
fn test_high_loss_satellite_channel_block_recovery_and_blake3_integrity() {
    let payload_len = 256 * 1024; // 256 KiB
    let mut payload = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        payload.push(((i * 73 + 41) & 0xff) as u8);
    }

    let original_hash = Hash::of(&payload);

    // Satellite profile: K=8, M=2 (25% redundancy)
    let k = 8;
    let m = 2;
    let block_size = 64 * 1024; // 64 KiB per block -> 4 blocks

    let mut prng = DeterministicLossPrng::new(42);
    let loss_rate = 0.04; // 4% simulated channel loss

    let mut reconstructed_full = Vec::with_capacity(payload_len);
    let mut total_recovered_symbols = 0usize;

    for (chunk_idx, chunk) in payload.chunks(block_size).enumerate() {
        let (header, all_symbols) = FecBlockEncoder::encode_block(chunk_idx as u64, chunk, k, m);
        assert_eq!(all_symbols.len(), k + m);

        let mut received = Vec::new();
        for sym in all_symbols {
            if !prng.should_drop(loss_rate) {
                received.push(sym);
            }
        }

        // Must have received at least K=8 symbols out of 10
        assert!(
            received.len() >= k,
            "Block {} received {} symbols, expected at least {}",
            chunk_idx,
            received.len(),
            k
        );

        let (reconstructed, report) = FecBlockDecoder::decode_block(&header, &received);
        assert!(report.is_successful, "Block {} reconstruction failed", chunk_idx);
        let block_bytes = reconstructed.expect("reconstructed data");
        assert_eq!(&block_bytes, chunk, "Reconstructed block must match original");

        total_recovered_symbols += report.recovered_source_count;
        reconstructed_full.extend_from_slice(&block_bytes);
    }

    assert_eq!(reconstructed_full.len(), payload_len);
    let final_hash = Hash::of(&reconstructed_full);
    assert_eq!(
        original_hash, final_hash,
        "Cryptographic BLAKE3 hash must match original after channel loss recovery"
    );
    assert!(total_recovered_symbols > 0, "Loss simulation should have erased and recovered symbols");
}

#[test]
fn test_fec_simulation_harness_goodput_and_stats() {
    let mut data = vec![0u8; 128 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let report = simulate_fec_recovery(&data, FecProfile::Satellite, 0.04, 12345);
    assert_eq!(report.profile, FecProfile::Satellite);
    assert_eq!(report.k, 8);
    assert_eq!(report.m, 2);
    assert_eq!(report.unrecoverable_blocks, 0);
    assert_eq!(report.successful_recovery_pct, 100.0);
    assert!(report.symbols_recovered > 0);
    assert!(report.effective_goodput_ratio > 0.7);
}
