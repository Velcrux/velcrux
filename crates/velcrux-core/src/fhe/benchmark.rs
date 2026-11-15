//! Homomorphic Encryption and Encrypted Search Benchmark Suite (ADR-084).

#![forbid(unsafe_code)]

use std::time::Instant;

use super::bfv::{FheDecryptor, FheEncryptor, FheEvaluator, FheKeyGenerator};
use super::index::FheSearchIndex;
use super::types::{FheBenchmarkReport, FheEncryptedRecord, FheParams, FhePlaintext, FheQuery};

/// Execute a microsecond-accurate benchmark evaluating BFV homomorphic operations and encrypted search.
#[must_use]
pub fn run_fhe_benchmark(poly_degree: usize, num_records: usize) -> FheBenchmarkReport {
    let degree = poly_degree.max(64).min(2048).next_power_of_two();
    let records_count = num_records.max(10);

    let params =
        FheParams::new(degree, 1125899908153369, 65537).expect("valid benchmark parameters");

    // 1. Key Generation Benchmark
    let keygen_start = Instant::now();
    let keypair =
        FheKeyGenerator::generate_keypair(&params, 0x12345678abcdef01).expect("keygen failed");
    let keygen_latency_us = keygen_start.elapsed().as_secs_f64() * 1_000_000.0;

    // 2. Encryption Benchmark
    let val_a = 42u64;
    let val_b = 13u64;
    let pt_a = FhePlaintext::from_scalar(val_a, degree, params.plain_modulus);
    let pt_b = FhePlaintext::from_scalar(val_b, degree, params.plain_modulus);

    let enc_start = Instant::now();
    let ct_a = FheEncryptor::encrypt(&keypair.public_key, &pt_a, &params, 0x1111222233334444)
        .expect("encrypt a failed");
    let enc_latency_us = enc_start.elapsed().as_secs_f64() * 1_000_000.0;

    let ct_b = FheEncryptor::encrypt(&keypair.public_key, &pt_b, &params, 0x5555666677778888)
        .expect("encrypt b failed");

    // 3. Decryption Benchmark
    let dec_start = Instant::now();
    let decrypted_a =
        FheDecryptor::decrypt(&keypair.secret_key, &ct_a, &params).expect("decrypt failed");
    let dec_latency_us = dec_start.elapsed().as_secs_f64() * 1_000_000.0;

    // 4. Homomorphic Addition Benchmark
    let add_start = Instant::now();
    let ct_sum = FheEvaluator::add(&ct_a, &ct_b, &params).expect("homomorphic add failed");
    let add_latency_ns = add_start.elapsed().as_secs_f64() * 1_000_000_000.0;

    // 5. Homomorphic Plaintext Multiplication Benchmark
    let plain_mul_start = Instant::now();
    let ct_plain_mul =
        FheEvaluator::mul_plain(&ct_a, &pt_b, &params).expect("homomorphic plain mul failed");
    let plain_mul_latency_us = plain_mul_start.elapsed().as_secs_f64() * 1_000_000.0;

    // 6. Homomorphic Ciphertext Multiplication Benchmark
    let cipher_mul_start = Instant::now();
    let ct_prod = FheEvaluator::mul(&ct_a, &ct_b, &keypair.relin_key, &params)
        .expect("homomorphic mul failed");
    let cipher_mul_latency_us = cipher_mul_start.elapsed().as_secs_f64() * 1_000_000.0;

    // 7. Verify Accuracy of Homomorphic Evaluations
    let dec_sum = FheDecryptor::decrypt(&keypair.secret_key, &ct_sum, &params).unwrap();
    let dec_plain_mul = FheDecryptor::decrypt(&keypair.secret_key, &ct_plain_mul, &params).unwrap();
    let dec_prod = FheDecryptor::decrypt(&keypair.secret_key, &ct_prod, &params).unwrap();

    let correct_sum = dec_sum.poly.coeffs[0] == ((val_a + val_b) % params.plain_modulus);
    let correct_plain_mul =
        dec_plain_mul.poly.coeffs[0] == ((val_a * val_b) % params.plain_modulus);
    let correct_prod = dec_prod.poly.coeffs[0] == ((val_a * val_b) % params.plain_modulus);
    let correct_dec_a = decrypted_a.poly.coeffs[0] == val_a;

    let all_correct = correct_sum && correct_plain_mul && correct_prod && correct_dec_a;
    let accuracy_percent = if all_correct { 100.0 } else { 0.0 };

    // 8. Encrypted Search Index Benchmark
    let mut index = FheSearchIndex::new(params.clone());
    for i in 0..records_count {
        let rec_val = (i as u64 % 50) + 1;
        let rec_pt = FhePlaintext::from_scalar(rec_val, degree, params.plain_modulus);
        let rec_ct =
            FheEncryptor::encrypt(&keypair.public_key, &rec_pt, &params, 0x1000 + i as u64)
                .unwrap();

        index.insert_record(FheEncryptedRecord {
            chunk_id: format!("chunk_{:06x}", i),
            tenant_id: "tenant-enterprise-1".to_string(),
            tier_code: (i % 4) as u8,
            encrypted_attributes: rec_ct,
            tags: vec!["fhe".to_string(), "indexed".to_string()],
        });
    }

    let query_pt = FhePlaintext::from_scalar(25, degree, params.plain_modulus);
    let query_ct = FheEncryptor::encrypt(&keypair.public_key, &query_pt, &params, 0x9999).unwrap();
    let query = FheQuery {
        query_id: "bench_q01".to_string(),
        query_vector: query_ct,
        tenant_id: "tenant-enterprise-1".to_string(),
    };

    let search_start = Instant::now();
    let _res = index
        .execute_search(&query, Some(&keypair.secret_key))
        .expect("search failed");
    let search_elapsed = search_start.elapsed().as_secs_f64().max(0.000001);
    let search_throughput = (records_count as f64) / search_elapsed;

    let initial_noise = params.initial_noise_budget_bits();
    let remaining_noise = ct_prod.noise_budget_bits as f64;
    let noise_consumed = initial_noise - remaining_noise;

    FheBenchmarkReport {
        poly_degree: degree,
        records_evaluated: records_count,
        keygen_latency_us,
        encryption_latency_us: enc_latency_us,
        decryption_latency_us: dec_latency_us,
        homomorphic_addition_latency_ns: add_latency_ns,
        homomorphic_plain_mul_latency_us: plain_mul_latency_us,
        homomorphic_cipher_mul_latency_us: cipher_mul_latency_us,
        query_scan_throughput_records_per_sec: search_throughput,
        noise_budget_initial_bits: initial_noise,
        noise_budget_consumed_bits: noise_consumed,
        decryption_accuracy_percent: accuracy_percent,
    }
}
