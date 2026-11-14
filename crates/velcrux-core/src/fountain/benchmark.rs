//! Fountain Benchmark & Loss Simulation Suite (ADR-082).

use super::decoder::FountainDecoder;
use super::distribution::SplitMix64;
use super::encoder::FountainEncoder;
use super::types::{FountainBenchmarkReport, FountainConfig};

/// Execute a full end-to-end benchmark of the Fountain codec with simulated channel loss.
#[must_use]
pub fn run_fountain_benchmark(
    k_symbols: usize,
    symbol_size: usize,
    simulated_loss_rate: f64,
) -> FountainBenchmarkReport {
    let k = k_symbols.clamp(4, 2048);
    let sym_size = symbol_size.clamp(64, 65536);
    let loss_rate = simulated_loss_rate.clamp(0.0, 0.90);

    // 1. Generate pseudo-random test payload
    let total_bytes = k * sym_size;
    let mut payload = Vec::with_capacity(total_bytes);
    let mut rng = SplitMix64::seed(0x123456789abcdef0);

    for _ in 0..(total_bytes / 8) {
        payload.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    if payload.len() < total_bytes {
        payload.resize(total_bytes, 0x42);
    }

    let config = FountainConfig {
        symbol_size: sym_size,
        robust_c: 0.05,
        robust_delta: 0.05,
        systematic: true,
    };

    // 2. Measure encoding throughput
    let enc_start = std::time::Instant::now();
    let encoder = FountainEncoder::new(&payload, config).expect("encoder created");

    // Generate initial batch of K symbols
    let initial_symbols = encoder.encode_batch(0, k);
    let enc_elapsed = enc_start.elapsed();
    let encode_throughput_mb_s =
        (total_bytes as f64 / (1024.0 * 1024.0)) / enc_elapsed.as_secs_f64().max(0.000001);

    // 3. Simulate lossy channel and measure decoding throughput
    let mut decoder = FountainDecoder::new(*encoder.header(), config);
    let mut loss_rng = SplitMix64::seed(0xfedcba9876543210);

    let mut transmitted = 0usize;
    let mut received = 0usize;
    let mut dropped = 0usize;

    let dec_start = std::time::Instant::now();

    // First feed initial symbols with loss simulation
    for sym in initial_symbols {
        transmitted += 1;
        if loss_rng.next_f64() < loss_rate {
            dropped += 1;
        } else {
            received += 1;
            decoder.add_symbol(sym);
        }
    }

    // If more symbols are needed, generate rateless repair symbols on the fly
    let mut esi = k as u32;
    while !decoder.is_complete() {
        transmitted += 1;
        let sym = encoder.encode_symbol(esi);
        esi = esi.saturating_add(1);

        if loss_rng.next_f64() < loss_rate {
            dropped += 1;
        } else {
            received += 1;
            decoder.add_symbol(sym);
        }

        // Safety break if loss is catastrophic
        if transmitted > k * 10 {
            break;
        }
    }

    let decoded_payload = decoder.finish().expect("payload decoded");
    let dec_elapsed = dec_start.elapsed();
    let decode_throughput_mb_s =
        (total_bytes as f64 / (1024.0 * 1024.0)) / dec_elapsed.as_secs_f64().max(0.000001);

    let blake3_match = decoded_payload == payload;
    let overhead_symbols = received.saturating_sub(k);
    let overhead_percentage = if k > 0 {
        (overhead_symbols as f64 / k as f64) * 100.0
    } else {
        0.0
    };

    FountainBenchmarkReport {
        k_source_symbols: k,
        symbol_size_bytes: sym_size,
        simulated_loss_rate: loss_rate,
        total_data_bytes: total_bytes,
        encode_throughput_mb_s,
        decode_throughput_mb_s,
        symbols_transmitted: transmitted,
        symbols_received: received,
        symbols_dropped: dropped,
        overhead_symbols,
        overhead_percentage,
        blake3_match,
    }
}
