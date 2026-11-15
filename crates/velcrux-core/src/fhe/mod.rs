//! Distributed Homomorphic Encrypted Query & Search Engine over Sharded Storage (ADR-084).
//!
//! Provides privacy-preserving search over encrypted chunk metadata and index catalogs
//! without decrypting storage contents, leveraging the Brakerski-Fan-Vercauteren (BFV)
//! leveled homomorphic encryption scheme over cyclotomic polynomial rings.

#![forbid(unsafe_code)]

pub mod benchmark;
pub mod bfv;
pub mod index;
pub mod poly;
pub mod types;

pub use benchmark::run_fhe_benchmark;
pub use bfv::{FheDecryptor, FheEncryptor, FheEvaluator, FheKeyGenerator};
pub use index::FheSearchIndex;
pub use poly::{FastPrng, PolyRing};
pub use types::{
    FheBenchmarkReport, FheCiphertext, FheEncryptedRecord, FheError, FheKeyPair, FheParams,
    FhePlaintext, FhePublicKey, FheQuery, FheQueryResult, FheRelinKey, FheResult, FheSecretKey,
    FheStatus, Polynomial, FHE_DEFAULT_COEFF_MODULUS, FHE_DEFAULT_DEGREE,
    FHE_DEFAULT_NOISE_STD_DEV, FHE_DEFAULT_PLAIN_MODULUS,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_ring_negacyclic_multiplication_properties() {
        let _n = 4;
        let q = 97;

        // a(X) = 1 + 2X, b(X) = 3 + 4X
        // In R_q = Z_q[X] / (X^4 + 1):
        // a * b = 3 + 4X + 6X + 8X^2 = 3 + 10X + 8X^2
        let a = Polynomial {
            coeffs: vec![1, 2, 0, 0],
        };
        let b = Polynomial {
            coeffs: vec![3, 4, 0, 0],
        };

        let prod = PolyRing::mul_negacyclic(&a, &b, q).unwrap();
        assert_eq!(prod.coeffs, vec![3, 10, 8, 0]);

        // Wrap around test: X^3 * X = X^4 = -1 = 96 mod 97
        let x3 = Polynomial {
            coeffs: vec![0, 0, 0, 1],
        };
        let x1 = Polynomial {
            coeffs: vec![0, 1, 0, 0],
        };
        let prod_wrap = PolyRing::mul_negacyclic(&x3, &x1, q).unwrap();
        assert_eq!(prod_wrap.coeffs, vec![96, 0, 0, 0]);
    }

    #[test]
    fn test_bfv_keygen_encryption_decryption_correctness() {
        let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, 65537).unwrap();
        let keypair = FheKeyGenerator::generate_keypair(&params, 0xcafe1234).unwrap();

        let original_val = 1337u64;
        let pt = FhePlaintext::from_scalar(original_val, 256, params.plain_modulus);

        let ct = FheEncryptor::encrypt(&keypair.public_key, &pt, &params, 0x5678).unwrap();
        assert!(ct.noise_budget_bits > 20);

        let decrypted = FheDecryptor::decrypt(&keypair.secret_key, &ct, &params).unwrap();
        assert_eq!(decrypted.poly.coeffs[0], original_val);
    }

    #[test]
    fn test_bfv_homomorphic_addition_and_subtraction() {
        let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, 65537).unwrap();
        let keypair = FheKeyGenerator::generate_keypair(&params, 0x98765432).unwrap();

        let val1 = 100u64;
        let val2 = 35u64;
        let pt1 = FhePlaintext::from_scalar(val1, 256, params.plain_modulus);
        let pt2 = FhePlaintext::from_scalar(val2, 256, params.plain_modulus);

        let ct1 = FheEncryptor::encrypt(&keypair.public_key, &pt1, &params, 0x111).unwrap();
        let ct2 = FheEncryptor::encrypt(&keypair.public_key, &pt2, &params, 0x222).unwrap();

        // 1. Homomorphic Addition: 100 + 35 = 135
        let ct_add = FheEvaluator::add(&ct1, &ct2, &params).unwrap();
        let dec_add = FheDecryptor::decrypt(&keypair.secret_key, &ct_add, &params).unwrap();
        assert_eq!(dec_add.poly.coeffs[0], 135);

        // 2. Homomorphic Subtraction: 100 - 35 = 65
        let ct_sub = FheEvaluator::sub(&ct1, &ct2, &params).unwrap();
        let dec_sub = FheDecryptor::decrypt(&keypair.secret_key, &ct_sub, &params).unwrap();
        assert_eq!(dec_sub.poly.coeffs[0], 65);
    }

    #[test]
    fn test_bfv_homomorphic_plaintext_and_scalar_multiplication() {
        let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, 65537).unwrap();
        let keypair = FheKeyGenerator::generate_keypair(&params, 0xaabbccdd).unwrap();

        let val = 12u64;
        let pt = FhePlaintext::from_scalar(val, 256, params.plain_modulus);
        let ct = FheEncryptor::encrypt(&keypair.public_key, &pt, &params, 0x333).unwrap();

        // 1. Scalar multiplication by 7: 12 * 7 = 84
        let ct_scalar = FheEvaluator::mul_scalar(&ct, 7, &params).unwrap();
        let dec_scalar = FheDecryptor::decrypt(&keypair.secret_key, &ct_scalar, &params).unwrap();
        assert_eq!(dec_scalar.poly.coeffs[0], 84);

        // 2. Plaintext polynomial multiplication by 5: 12 * 5 = 60
        let pt_mult = FhePlaintext::from_scalar(5, 256, params.plain_modulus);
        let ct_plain = FheEvaluator::mul_plain(&ct, &pt_mult, &params).unwrap();
        let dec_plain = FheDecryptor::decrypt(&keypair.secret_key, &ct_plain, &params).unwrap();
        assert_eq!(dec_plain.poly.coeffs[0], 60);
    }

    #[test]
    fn test_bfv_homomorphic_ciphertext_multiplication_with_relinearization() {
        let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, 65537).unwrap();
        let keypair = FheKeyGenerator::generate_keypair(&params, 0x112233445566).unwrap();

        let val1 = 15u64;
        let val2 = 6u64;
        let pt1 = FhePlaintext::from_scalar(val1, 256, params.plain_modulus);
        let pt2 = FhePlaintext::from_scalar(val2, 256, params.plain_modulus);

        let ct1 = FheEncryptor::encrypt(&keypair.public_key, &pt1, &params, 0x444).unwrap();
        let ct2 = FheEncryptor::encrypt(&keypair.public_key, &pt2, &params, 0x555).unwrap();

        // Ciphertext-Ciphertext Multiplication: 15 * 6 = 90
        let ct_prod = FheEvaluator::mul(&ct1, &ct2, &keypair.relin_key, &params).unwrap();
        let dec_prod = FheDecryptor::decrypt(&keypair.secret_key, &ct_prod, &params).unwrap();
        assert_eq!(dec_prod.poly.coeffs[0], 90);
    }

    #[test]
    fn test_fhe_search_index_exact_match_query() {
        let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, 65537).unwrap();
        let keypair = FheKeyGenerator::generate_keypair(&params, 0x99887766).unwrap();

        let mut index = FheSearchIndex::new(params.clone());

        // Insert 5 encrypted metadata records with different attribute values
        for i in 1..=5 {
            let pt = FhePlaintext::from_scalar(i * 10, 256, params.plain_modulus);
            let ct = FheEncryptor::encrypt(&keypair.public_key, &pt, &params, 0x100 + i).unwrap();

            index.insert_record(FheEncryptedRecord {
                chunk_id: format!("chunk_id_{}", i),
                tenant_id: "tenant-a".to_string(),
                tier_code: 1,
                encrypted_attributes: ct,
                tags: vec!["test".to_string()],
            });
        }

        assert_eq!(index.len(), 5);

        // Search for record with attribute value = 30 (should match chunk_id_3)
        let query_pt = FhePlaintext::from_scalar(30, 256, params.plain_modulus);
        let query_ct =
            FheEncryptor::encrypt(&keypair.public_key, &query_pt, &params, 0x777).unwrap();

        let query = FheQuery {
            query_id: "q_test_1".to_string(),
            query_vector: query_ct,
            tenant_id: "tenant-a".to_string(),
        };

        let result = index
            .execute_search(&query, Some(&keypair.secret_key))
            .unwrap();
        assert_eq!(result.total_records_scanned, 5);
        assert_eq!(result.matching_chunk_ids, vec!["chunk_id_3"]);
    }

    #[test]
    fn test_fhe_benchmark_accuracy_and_metrics() {
        let report = run_fhe_benchmark(128, 15);
        assert_eq!(report.poly_degree, 128);
        assert_eq!(report.records_evaluated, 15);
        assert_eq!(report.decryption_accuracy_percent, 100.0);
        assert!(report.keygen_latency_us > 0.0);
        assert!(report.encryption_latency_us > 0.0);
        assert!(report.decryption_latency_us > 0.0);
        assert!(report.homomorphic_addition_latency_ns > 0.0);
        assert!(report.homomorphic_plain_mul_latency_us > 0.0);
        assert!(report.query_scan_throughput_records_per_sec > 0.0);
    }
}
