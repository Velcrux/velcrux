//! Integration tests for Distributed Homomorphic Encrypted Query & Search Engine over Sharded Storage (ADR-084).

#![forbid(unsafe_code)]

use velcrux_core::fhe::{
    FheDecryptor, FheEncryptedRecord, FheEncryptor, FheEvaluator, FheKeyGenerator, FheParams,
    FhePlaintext, FheQuery, FheSearchIndex, PolyRing, Polynomial, FHE_DEFAULT_COEFF_MODULUS,
    FHE_DEFAULT_PLAIN_MODULUS,
};

#[test]
fn test_fhe_ring_negacyclic_arithmetic_associativity_and_distributivity() {
    let q = FHE_DEFAULT_COEFF_MODULUS;

    // Polynomials in Z_q[X] / (X^4 + 1)
    let a = Polynomial {
        coeffs: vec![12, 34, 56, 78],
    };
    let b = Polynomial {
        coeffs: vec![90, 23, 45, 67],
    };
    let c = Polynomial {
        coeffs: vec![89, 10, 11, 12],
    };

    // Distributivity: a * (b + c) == a * b + a * c (mod q)
    let b_plus_c = PolyRing::add(&b, &c, q).unwrap();
    let a_times_b_plus_c = PolyRing::mul_negacyclic(&a, &b_plus_c, q).unwrap();

    let a_times_b = PolyRing::mul_negacyclic(&a, &b, q).unwrap();
    let a_times_c = PolyRing::mul_negacyclic(&a, &c, q).unwrap();
    let sum_of_prods = PolyRing::add(&a_times_b, &a_times_c, q).unwrap();

    assert_eq!(a_times_b_plus_c.coeffs, sum_of_prods.coeffs);

    // Associativity: (a * b) * c == a * (b * c) (mod q)
    let ab_c = PolyRing::mul_negacyclic(&a_times_b, &c, q).unwrap();
    let bc = PolyRing::mul_negacyclic(&b, &c, q).unwrap();
    let a_bc = PolyRing::mul_negacyclic(&a, &bc, q).unwrap();

    assert_eq!(ab_c.coeffs, a_bc.coeffs);
}

#[test]
fn test_fhe_bfv_keygen_and_codec_roundtrip() {
    let params = FheParams::new(128, FHE_DEFAULT_COEFF_MODULUS, FHE_DEFAULT_PLAIN_MODULUS).unwrap();
    let keypair = FheKeyGenerator::generate_keypair(&params, 0x8877665544332211).unwrap();

    // Verify parameter serialization
    let params_json = serde_json::to_string(&params).expect("serialize params");
    let deser_params: FheParams = serde_json::from_str(&params_json).expect("deser params");
    assert_eq!(params, deser_params);

    // Verify keypair serialization
    let kp_json = serde_json::to_string(&keypair).expect("serialize keypair");
    let deser_kp: velcrux_core::fhe::FheKeyPair =
        serde_json::from_str(&kp_json).expect("deser keypair");
    assert_eq!(keypair.params, deser_kp.params);
    assert_eq!(keypair.secret_key.s.coeffs, deser_kp.secret_key.s.coeffs);

    // Encrypt and serialize ciphertext
    let pt = FhePlaintext::from_scalar(420, 128, params.plain_modulus);
    let ct = FheEncryptor::encrypt(&keypair.public_key, &pt, &params, 0x12345).unwrap();

    let ct_json = serde_json::to_string(&ct).expect("serialize ct");
    let deser_ct: velcrux_core::fhe::FheCiphertext =
        serde_json::from_str(&ct_json).expect("deser ct");

    let dec = FheDecryptor::decrypt(&deser_kp.secret_key, &deser_ct, &deser_params).unwrap();
    assert_eq!(dec.poly.coeffs[0], 420);
}

#[test]
fn test_fhe_bfv_homomorphic_linear_operations() {
    let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, FHE_DEFAULT_PLAIN_MODULUS).unwrap();
    let keypair = FheKeyGenerator::generate_keypair(&params, 0x5544332211).unwrap();

    let pt1 = FhePlaintext::from_scalar(500, 256, params.plain_modulus);
    let pt2 = FhePlaintext::from_scalar(175, 256, params.plain_modulus);

    let ct1 = FheEncryptor::encrypt(&keypair.public_key, &pt1, &params, 0x101).unwrap();
    let ct2 = FheEncryptor::encrypt(&keypair.public_key, &pt2, &params, 0x202).unwrap();

    // 1. Homomorphic Addition: 500 + 175 = 675
    let ct_sum = FheEvaluator::add(&ct1, &ct2, &params).unwrap();
    let dec_sum = FheDecryptor::decrypt(&keypair.secret_key, &ct_sum, &params).unwrap();
    assert_eq!(dec_sum.poly.coeffs[0], 675);

    // 2. Homomorphic Subtraction: 500 - 175 = 325
    let ct_diff = FheEvaluator::sub(&ct1, &ct2, &params).unwrap();
    let dec_diff = FheDecryptor::decrypt(&keypair.secret_key, &ct_diff, &params).unwrap();
    assert_eq!(dec_diff.poly.coeffs[0], 325);

    // 3. Scalar multiplication: 500 * 4 = 2000
    let ct_scaled = FheEvaluator::mul_scalar(&ct1, 4, &params).unwrap();
    let dec_scaled = FheDecryptor::decrypt(&keypair.secret_key, &ct_scaled, &params).unwrap();
    assert_eq!(dec_scaled.poly.coeffs[0], 2000);

    // 4. Plaintext polynomial multiplication: 175 * 10 = 1750
    let pt_mul = FhePlaintext::from_scalar(10, 256, params.plain_modulus);
    let ct_plain_mul = FheEvaluator::mul_plain(&ct2, &pt_mul, &params).unwrap();
    let dec_plain_mul = FheDecryptor::decrypt(&keypair.secret_key, &ct_plain_mul, &params).unwrap();
    assert_eq!(dec_plain_mul.poly.coeffs[0], 1750);
}

#[test]
fn test_fhe_bfv_homomorphic_ciphertext_multiplication() {
    let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, FHE_DEFAULT_PLAIN_MODULUS).unwrap();
    let keypair = FheKeyGenerator::generate_keypair(&params, 0xabcdef012345).unwrap();

    let val1 = 25u64;
    let val2 = 14u64;
    let pt1 = FhePlaintext::from_scalar(val1, 256, params.plain_modulus);
    let pt2 = FhePlaintext::from_scalar(val2, 256, params.plain_modulus);

    let ct1 = FheEncryptor::encrypt(&keypair.public_key, &pt1, &params, 0x301).unwrap();
    let ct2 = FheEncryptor::encrypt(&keypair.public_key, &pt2, &params, 0x302).unwrap();

    // Homomorphic Multiplication: 25 * 14 = 350
    let ct_prod = FheEvaluator::mul(&ct1, &ct2, &keypair.relin_key, &params).unwrap();
    assert!(ct_prod.noise_budget_bits > 0);

    let dec_prod = FheDecryptor::decrypt(&keypair.secret_key, &ct_prod, &params).unwrap();
    assert_eq!(dec_prod.poly.coeffs[0], 350);
}

#[test]
fn test_fhe_search_index_multi_tenant_sharded_queries() {
    let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, FHE_DEFAULT_PLAIN_MODULUS).unwrap();
    let keypair = FheKeyGenerator::generate_keypair(&params, 0xdeadbeef1122).unwrap();

    let mut index = FheSearchIndex::new(params.clone());

    // Insert records for tenant-alpha
    for i in 1..=10 {
        let val = i * 15;
        let pt = FhePlaintext::from_scalar(val, 256, params.plain_modulus);
        let ct = FheEncryptor::encrypt(&keypair.public_key, &pt, &params, 0x1000 + i).unwrap();

        index.insert_record(FheEncryptedRecord {
            chunk_id: format!("chunk_alpha_{:03}", i),
            tenant_id: "tenant-alpha".to_string(),
            tier_code: 0,
            encrypted_attributes: ct,
            tags: vec!["alpha".to_string()],
        });
    }

    // Insert records for tenant-beta
    for i in 1..=5 {
        let val = i * 15;
        let pt = FhePlaintext::from_scalar(val, 256, params.plain_modulus);
        let ct = FheEncryptor::encrypt(&keypair.public_key, &pt, &params, 0x2000 + i).unwrap();

        index.insert_record(FheEncryptedRecord {
            chunk_id: format!("chunk_beta_{:03}", i),
            tenant_id: "tenant-beta".to_string(),
            tier_code: 1,
            encrypted_attributes: ct,
            tags: vec!["beta".to_string()],
        });
    }

    assert_eq!(index.len(), 15);

    // Query for value = 45 on tenant-alpha (corresponds to i=3, chunk_alpha_003)
    let q_pt = FhePlaintext::from_scalar(45, 256, params.plain_modulus);
    let q_ct = FheEncryptor::encrypt(&keypair.public_key, &q_pt, &params, 0x7777).unwrap();

    let query_alpha = FheQuery {
        query_id: "q_alpha_01".to_string(),
        query_vector: q_ct.clone(),
        tenant_id: "tenant-alpha".to_string(),
    };

    let res_alpha = index
        .execute_search(&query_alpha, Some(&keypair.secret_key))
        .unwrap();
    assert_eq!(res_alpha.total_records_scanned, 10);
    assert_eq!(res_alpha.matching_chunk_ids, vec!["chunk_alpha_003"]);

    // Query for value = 45 on tenant-beta (corresponds to i=3, chunk_beta_003)
    let query_beta = FheQuery {
        query_id: "q_beta_01".to_string(),
        query_vector: q_ct,
        tenant_id: "tenant-beta".to_string(),
    };

    let res_beta = index
        .execute_search(&query_beta, Some(&keypair.secret_key))
        .unwrap();
    assert_eq!(res_beta.total_records_scanned, 5);
    assert_eq!(res_beta.matching_chunk_ids, vec!["chunk_beta_003"]);

    // Query for value not present: 999
    let q_pt_none = FhePlaintext::from_scalar(999, 256, params.plain_modulus);
    let q_ct_none =
        FheEncryptor::encrypt(&keypair.public_key, &q_pt_none, &params, 0x8888).unwrap();
    let query_none = FheQuery {
        query_id: "q_none".to_string(),
        query_vector: q_ct_none,
        tenant_id: "tenant-alpha".to_string(),
    };

    let res_none = index
        .execute_search(&query_none, Some(&keypair.secret_key))
        .unwrap();
    assert_eq!(res_none.total_records_scanned, 10);
    assert!(res_none.matching_chunk_ids.is_empty());
}

#[test]
fn test_fhe_search_index_weighted_relevance_scoring() {
    let params = FheParams::new(256, FHE_DEFAULT_COEFF_MODULUS, FHE_DEFAULT_PLAIN_MODULUS).unwrap();
    let keypair = FheKeyGenerator::generate_keypair(&params, 0x11223344).unwrap();

    let index = FheSearchIndex::new(params.clone());

    // Record with attribute vector = [10, 20, 30]
    let attrs = vec![10u64, 20, 30];
    let pt = FhePlaintext::from_values(&attrs, 256, params.plain_modulus);
    let ct = FheEncryptor::encrypt(&keypair.public_key, &pt, &params, 0x5555).unwrap();

    let record = FheEncryptedRecord {
        chunk_id: "chunk_weighted_1".to_string(),
        tenant_id: "tenant-w".to_string(),
        tier_code: 0,
        encrypted_attributes: ct,
        tags: vec!["weighted".to_string()],
    };

    // Weight vector = [3, 2, 1]
    // Expected homomorphic product polynomial:
    // a(X) = 10 + 20X + 30X^2, w(X) = 3 + 2X + 1X^2
    // Decrypt and verify
    let weights = vec![3u64, 2, 1];
    let scored_ct = index.evaluate_weighted_score(&record, &weights).unwrap();
    let dec_score = FheDecryptor::decrypt(&keypair.secret_key, &scored_ct, &params).unwrap();

    // Constant term of product: 10*3 = 30
    assert_eq!(dec_score.poly.coeffs[0], 30);
    // Linear term: 10*2 + 20*3 = 80
    assert_eq!(dec_score.poly.coeffs[1], 80);
    // Quadratic term: 10*1 + 20*2 + 30*3 = 140
    assert_eq!(dec_score.poly.coeffs[2], 140);
}
