//! Integration tests for Option DN: Dynamic Rateless Fountain Coding
//! & Loss-Resilient Erasure Streaming Engine (`ADR-082`).

use velcrux_core::fountain::{
    run_fountain_benchmark, FountainConfig, FountainContainer, FountainDecoder, FountainEncoder,
    SplitMix64,
};

fn generate_sample_data(bytes: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(bytes);
    let mut rng = SplitMix64::seed(0xdeadbeefcafebabe);
    for _ in 0..(bytes / 8) {
        data.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    if data.len() < bytes {
        data.resize(bytes, 0x5a);
    }
    data
}

#[test]
fn test_fountain_end_to_end_zero_loss_fastpath() {
    let payload = generate_sample_data(64 * 1024); // 64 KiB
    let config = FountainConfig {
        symbol_size: 512,
        robust_c: 0.05,
        robust_delta: 0.05,
        systematic: true,
    };

    let encoder = FountainEncoder::new(&payload, config).unwrap();
    let k = encoder.k();
    assert_eq!(k, 128); // 64 KiB / 512 B = 128 symbols

    let mut decoder = FountainDecoder::new(*encoder.header(), config);

    // Deliver exact K systematic symbols
    for esi in 0..k as u32 {
        let sym = encoder.encode_symbol(esi);
        decoder.add_symbol(sym);
    }

    assert!(decoder.is_complete());
    assert_eq!(decoder.status().overhead_percentage, 0.0);

    let recovered = decoder.finish().unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fountain_resilience_under_severe_loss_30_percent() {
    let payload = generate_sample_data(32 * 1024); // 32 KiB
    let config = FountainConfig {
        symbol_size: 256,
        robust_c: 0.05,
        robust_delta: 0.05,
        systematic: true,
    };

    let encoder = FountainEncoder::new(&payload, config).unwrap();
    let _k = encoder.k();
    let mut decoder = FountainDecoder::new(*encoder.header(), config);

    let mut loss_rng = SplitMix64::seed(0x3030303030303030);
    let mut esi = 0u32;

    while !decoder.is_complete() {
        let sym = encoder.encode_symbol(esi);
        esi += 1;

        // 30% packet loss probability
        if loss_rng.next_f64() >= 0.30 {
            decoder.add_symbol(sym);
        }

        assert!(esi < 2000, "Too many symbols generated");
    }

    assert!(decoder.is_complete());
    let recovered = decoder.finish().unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fountain_resilience_under_catastrophic_loss_60_percent() {
    let payload = generate_sample_data(16 * 1024); // 16 KiB
    let config = FountainConfig {
        symbol_size: 128,
        robust_c: 0.05,
        robust_delta: 0.05,
        systematic: true,
    };

    let encoder = FountainEncoder::new(&payload, config).unwrap();
    let mut decoder = FountainDecoder::new(*encoder.header(), config);

    let mut loss_rng = SplitMix64::seed(0x6060606060606060);
    let mut esi = 0u32;

    while !decoder.is_complete() {
        let sym = encoder.encode_symbol(esi);
        esi += 1;

        // 60% catastrophic packet loss
        if loss_rng.next_f64() >= 0.60 {
            decoder.add_symbol(sym);
        }

        assert!(esi < 4000, "Too many symbols generated");
    }

    assert!(decoder.is_complete());
    let recovered = decoder.finish().unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fountain_out_of_order_and_duplicate_packet_immunity() {
    let payload = generate_sample_data(8 * 1024); // 8 KiB
    let config = FountainConfig {
        symbol_size: 128,
        robust_c: 0.05,
        robust_delta: 0.05,
        systematic: true,
    };

    let encoder = FountainEncoder::new(&payload, config).unwrap();
    let k = encoder.k();

    // Generate K + 10 symbols
    let mut symbols = encoder.encode_batch(0, k + 10);

    // Reverse order
    symbols.reverse();

    let mut decoder = FountainDecoder::new(*encoder.header(), config);

    // Feed in reverse order, injecting duplicates
    for sym in symbols {
        decoder.add_symbol(sym.clone());
        decoder.add_symbol(sym); // duplicate injection
    }

    assert!(decoder.is_complete());
    let recovered = decoder.finish().unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fountain_container_file_serialization_and_recovery() {
    let payload = generate_sample_data(12 * 1024); // 12 KiB
    let config = FountainConfig {
        symbol_size: 256,
        robust_c: 0.05,
        robust_delta: 0.05,
        systematic: true,
    };

    let encoder = FountainEncoder::new(&payload, config).unwrap();
    let symbols = encoder.encode_batch(0, encoder.k() + 15);

    let container = FountainContainer {
        header: *encoder.header(),
        symbols,
    };

    let wire_bytes = container.to_bytes();
    let restored_container = FountainContainer::from_bytes(&wire_bytes, &config).unwrap();

    let mut decoder = FountainDecoder::new(restored_container.header, config);
    for sym in restored_container.symbols {
        decoder.add_symbol(sym);
    }

    assert!(decoder.is_complete());
    let recovered = decoder.finish().unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn test_fountain_benchmark_simulation() {
    let report = run_fountain_benchmark(32, 256, 0.25);
    assert_eq!(report.k_source_symbols, 32);
    assert_eq!(report.symbol_size_bytes, 256);
    assert!(report.blake3_match);
    assert!(report.encode_throughput_mb_s > 0.0);
    assert!(report.decode_throughput_mb_s > 0.0);
    assert!(report.symbols_dropped > 0);
    assert!(report.symbols_received >= report.k_source_symbols);
}
