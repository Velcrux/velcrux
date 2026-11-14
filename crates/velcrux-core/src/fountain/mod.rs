//! Dynamic Rateless Fountain Coding & Loss-Resilient Erasure Streaming Engine (ADR-082).
//!
//! Provides pure safe Rust rateless Fountain codes (Luby Transform / RaptorQ hybrid)
//! for infinite on-demand repair symbol generation across lossy networks.

pub mod benchmark;
pub mod decoder;
pub mod distribution;
pub mod encoder;
pub mod pacer;
pub mod types;

pub use benchmark::run_fountain_benchmark;
pub use decoder::FountainDecoder;
pub use distribution::{sample_neighbors, RobustSolitonCdf, SplitMix64};
pub use encoder::FountainEncoder;
pub use pacer::FountainRatePacer;
pub use types::{
    FountainBenchmarkReport, FountainConfig, FountainContainer, FountainDecoderStatus,
    FountainError, FountainHeader, FountainResult, FountainSymbol, FOUNTAIN_MAGIC,
    FOUNTAIN_VERSION,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soliton_distribution_cdf() {
        let cdf = RobustSolitonCdf::new(10, 0.05, 0.05);
        let deg1 = cdf.sample_degree(0.001);
        let deg_max = cdf.sample_degree(0.999);

        assert_eq!(deg1, 1);
        assert!(deg_max >= 1 && deg_max <= 10);
    }

    #[test]
    fn test_systematic_encoding_and_fast_path_recovery() {
        let raw_data =
            b"Hello, world! This is a systematic Fountain coding test across loss-free channel.";
        let config = FountainConfig {
            symbol_size: 16,
            robust_c: 0.05,
            robust_delta: 0.05,
            systematic: true,
        };

        let encoder = FountainEncoder::new(raw_data, config).unwrap();
        let k = encoder.k();
        assert!(k > 1);

        let mut decoder = FountainDecoder::new(*encoder.header(), config);

        // Feed exact K systematic symbols
        for esi in 0..k as u32 {
            let sym = encoder.encode_symbol(esi);
            assert_eq!(sym.degree, 1);
            decoder.add_symbol(sym);
        }

        assert!(decoder.is_complete());
        let recovered = decoder.finish().unwrap();
        assert_eq!(recovered, raw_data);
    }

    #[test]
    fn test_rateless_erasure_recovery_under_50_percent_loss() {
        let mut raw_data = Vec::with_capacity(2048);
        for i in 0..2048 {
            raw_data.push((i % 251) as u8);
        }

        let config = FountainConfig {
            symbol_size: 64,
            robust_c: 0.05,
            robust_delta: 0.05,
            systematic: true,
        };

        let encoder = FountainEncoder::new(&raw_data, config).unwrap();
        let _k = encoder.k();
        let mut decoder = FountainDecoder::new(*encoder.header(), config);

        // Transmit symbols with alternating 50% packet drop
        let mut esi = 0u32;
        while !decoder.is_complete() {
            let sym = encoder.encode_symbol(esi);
            if esi % 2 == 0 {
                // Keep even packets, drop odd packets
                decoder.add_symbol(sym);
            }
            esi += 1;
            assert!(esi < 1000, "Decoding took too many symbols");
        }

        assert!(decoder.is_complete());
        let recovered = decoder.finish().unwrap();
        assert_eq!(recovered, raw_data);
    }

    #[test]
    fn test_container_serialization_roundtrip() {
        let payload = b"Containerized Fountain Code Payload for Multi-Cloud Wire Transmission";
        let config = FountainConfig {
            symbol_size: 16,
            robust_c: 0.05,
            robust_delta: 0.05,
            systematic: true,
        };

        let encoder = FountainEncoder::new(payload, config).unwrap();
        let symbols = encoder.encode_batch(0, encoder.k() + 4);

        let container = FountainContainer {
            header: *encoder.header(),
            symbols,
        };

        let bytes = container.to_bytes();
        let parsed = FountainContainer::from_bytes(&bytes, &config).unwrap();

        assert_eq!(parsed.header, *encoder.header());
        assert_eq!(parsed.symbols.len(), container.symbols.len());

        let mut decoder = FountainDecoder::new(parsed.header, config);
        for sym in parsed.symbols {
            decoder.add_symbol(sym);
        }
        assert!(decoder.is_complete());
        assert_eq!(decoder.finish().unwrap(), payload);
    }

    #[test]
    fn test_gaussian_elimination_fallback_on_non_systematic_stream() {
        let payload = b"Testing pure non-systematic linear elimination over GF(2)";
        let config = FountainConfig {
            symbol_size: 16,
            robust_c: 0.1,
            robust_delta: 0.1,
            systematic: false, // Pure non-systematic symbols
        };

        let encoder = FountainEncoder::new(payload, config).unwrap();
        let k = encoder.k();
        let mut decoder = FountainDecoder::new(*encoder.header(), config);

        let mut esi = 0u32;
        while !decoder.is_complete() {
            let sym = encoder.encode_symbol(esi);
            decoder.add_symbol(sym);
            esi += 1;
            if esi > (k as u32 * 4) {
                break;
            }
        }

        assert!(decoder.is_complete());
        assert_eq!(decoder.finish().unwrap(), payload);
    }

    #[test]
    fn test_rate_pacer_multiplier_and_delay() {
        let mut pacer = FountainRatePacer::new(0.10);
        assert!(pacer.target_multiplier() >= 1.10);

        pacer.record_feedback(0.20, 30);
        assert!(pacer.loss_ratio > 0.0);

        let syms = pacer.target_symbols_to_transmit(100);
        assert!(syms > 100);

        let delay = pacer.pace_delay_us(50.0, 1024);
        assert!(delay > 0);
    }

    #[test]
    fn test_fountain_benchmark_runner() {
        let bench = run_fountain_benchmark(16, 128, 0.20);
        assert_eq!(bench.k_source_symbols, 16);
        assert!(bench.blake3_match);
        assert!(bench.encode_throughput_mb_s > 0.0);
        assert!(bench.decode_throughput_mb_s > 0.0);
        assert!(bench.symbols_dropped > 0);
    }
}
