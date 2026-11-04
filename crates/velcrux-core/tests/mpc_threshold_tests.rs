#![forbid(unsafe_code)]

//! Comprehensive Integration Tests for Zero-Knowledge MPC Distributed Threshold Signing (`ADR-069`, Option DA).

use std::time::{SystemTime, UNIX_EPOCH};

use ring::signature::{self, UnparsedPublicKey};
use velcrux_core::mpc::{
    aggregate_signature_shares, reconstruct_secret, verify_signature_share, CommitmentPackage,
    MpcClusterCoordinator, Point, Polynomial, Scalar, SchnorrDlogProof, ThresholdSigner,
};

#[test]
fn test_scalar_arithmetic_inversion_and_negation() {
    let a = Scalar::from_u64(123456789);
    let b = Scalar::from_u64(987654321);

    let sum = a.add(&b);
    let diff = sum.sub(&b);
    assert_eq!(diff, a);

    let inv_a = a.invert().expect("invert a");
    let prod = a.mul(&inv_a);
    assert_eq!(prod, Scalar::ONE);

    let neg_a = a.neg();
    let zero = a.add(&neg_a);
    assert_eq!(zero, Scalar::ZERO);
}

#[test]
fn test_edwards_curve_complete_addition_and_scalar_mul() {
    let gen = Point::generator();
    assert!(!gen.is_identity());

    // Identity element properties
    let id = Point::IDENTITY;
    assert_eq!(gen.add(&id), gen);
    assert_eq!(id.add(&gen), gen);

    // Order ell: ell * B == IDENTITY
    let ell = Scalar(velcrux_core::mpc::scalar::SCALAR_ORDER_LIMBS);
    let order_point = gen.mul_scalar(&ell);
    assert!(order_point.is_identity());

    // Associativity
    let p2 = gen.add(&gen);
    let p3 = p2.add(&gen);
    let p3_mul = gen.mul_scalar(&Scalar::from_u64(3));
    assert_eq!(p3, p3_mul);
}

#[test]
fn test_shamir_secret_sharing_arbitrary_quorums() {
    let master_secret = Scalar::from_u64(0xDEADBEEFCAFE);
    let threshold = 3;
    let total = 5;

    let poly = Polynomial::random_with_secret(&master_secret, threshold);
    let shares = poly.generate_shares(total);

    // Any 3 shares out of 5 must successfully reconstruct the secret
    let quorums = vec![
        vec![shares[0].clone(), shares[1].clone(), shares[2].clone()], // {1, 2, 3}
        vec![shares[1].clone(), shares[3].clone(), shares[4].clone()], // {2, 4, 5}
        vec![shares[0].clone(), shares[2].clone(), shares[4].clone()], // {1, 3, 5}
        vec![shares[2].clone(), shares[3].clone(), shares[4].clone()], // {3, 4, 5}
    ];

    for quorum in quorums {
        let reconstructed = reconstruct_secret(&quorum).expect("reconstruct quorum");
        assert_eq!(reconstructed, master_secret);
    }
}

#[test]
fn test_feldman_vss_commitments_and_corruption_detection() {
    let secret = Scalar::from_u64(777888999);
    let poly = Polynomial::random_with_secret(&secret, 3);
    let feldman_pkg = poly.commitments();
    let shares = poly.generate_shares(5);

    // Valid shares pass Feldman verification
    for share in &shares {
        assert!(feldman_pkg.verify_share(share));
    }

    // Corrupted share must fail verification
    let mut bad_share = shares[0].clone();
    bad_share.share = bad_share.share.add(&Scalar::ONE);
    assert!(!feldman_pkg.verify_share(&bad_share));
}

#[test]
fn test_schnorr_zkp_discrete_log_knowledge() {
    let secret_share = Scalar::from_u64(555444333);
    let context = b"velcrux-dkg-phase1-audit";

    let proof = SchnorrDlogProof::prove(1, &secret_share, context);
    assert!(proof.verify(context));

    // Wrong context fails
    assert!(!proof.verify(b"different-context-string"));

    // Mutated response fails
    let mut bad_proof = proof.clone();
    bad_proof.response = bad_proof.response.add(&Scalar::ONE);
    assert!(!bad_proof.verify(context));
}

#[test]
fn test_frost_two_round_distributed_threshold_signing() {
    let master_secret = Scalar::from_u64(9876543210);
    let threshold = 3;
    let total = 5;

    let poly = Polynomial::random_with_secret(&master_secret, threshold);
    let pkg = poly.commitments();
    let group_pubkey = pkg.group_public_key().expect("group pubkey");
    let shares = poly.generate_shares(total);

    let signers: Vec<ThresholdSigner> = shares
        .into_iter()
        .map(|s| ThresholdSigner::new(s, group_pubkey))
        .collect();

    let message = b"CRITICAL TRANSACTION: Cluster Rebalance Authorize";

    // Select quorum {1, 3, 5}
    let quorum_indices = vec![0, 2, 4];
    let mut nonces = Vec::new();
    let mut commitments = Vec::new();

    // Round 1
    for &idx in &quorum_indices {
        let (n, c) = signers[idx].round1_commit();
        nonces.push(n);
        commitments.push(c);
    }

    let commit_pkg = CommitmentPackage { commitments };

    // Round 2
    let mut sig_shares = Vec::new();
    for (i, &idx) in quorum_indices.iter().enumerate() {
        let share = signers[idx]
            .round2_sign(&nonces[i], &commit_pkg, message)
            .expect("sign share");

        // Verify partial share
        verify_signature_share(
            &share,
            &commit_pkg.commitments[i],
            &signers[idx].public_key,
            &group_pubkey,
            &commit_pkg,
            message,
        )
        .expect("verify partial share");

        sig_shares.push(share);
    }

    // Aggregation
    let threshold_sig =
        aggregate_signature_shares(&commit_pkg, &sig_shares, &group_pubkey, message)
            .expect("aggregate signature");

    // Group verification
    assert!(threshold_sig.verify(&group_pubkey, message));

    // Verification must fail on altered message
    assert!(!threshold_sig.verify(&group_pubkey, b"TAMPERED MESSAGE PAYLOAD"));
}

#[test]
fn test_malicious_share_detection_and_blame_attribution() {
    let master_secret = Scalar::from_u64(1122334455);
    let poly = Polynomial::random_with_secret(&master_secret, 2);
    let pkg = poly.commitments();
    let group_pubkey = pkg.group_public_key().expect("pubkey");
    let shares = poly.generate_shares(3);

    let signer1 = ThresholdSigner::new(shares[0].clone(), group_pubkey);
    let signer2 = ThresholdSigner::new(shares[1].clone(), group_pubkey);

    let msg = b"Transaction Approval";

    let (nonces1, comm1) = signer1.round1_commit();
    let (nonces2, comm2) = signer2.round1_commit();

    let commit_pkg = CommitmentPackage {
        commitments: vec![comm1, comm2],
    };

    let share1 = signer1.round2_sign(&nonces1, &commit_pkg, msg).unwrap();
    let mut share2 = signer2.round2_sign(&nonces2, &commit_pkg, msg).unwrap();

    // Malicious node 2 alters its share
    share2.share = share2.share.add(&Scalar::ONE);

    // Share 1 verifies cleanly
    assert!(verify_signature_share(
        &share1,
        &comm1,
        &signer1.public_key,
        &group_pubkey,
        &commit_pkg,
        msg
    )
    .is_ok());

    // Share 2 is caught with blame attributed
    let err = verify_signature_share(
        &share2,
        &comm2,
        &signer2.public_key,
        &group_pubkey,
        &commit_pkg,
        msg,
    );
    assert!(err.is_err());
}

#[tokio::test]
async fn test_mpc_cluster_root_token_minting_and_expiration() {
    let coordinator = MpcClusterCoordinator::initialize(3, 5).expect("init coordinator");
    let quorum = vec![1, 2, 4];

    let token = coordinator
        .issue_root_token("vault-admin-node", "superadmin", 2, &quorum)
        .await
        .expect("mint root token");

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Immediately valid
    assert!(token.verify(now_ms));

    // Expired in 3 seconds
    assert!(!token.verify(now_ms + 3_000));
}

#[tokio::test]
async fn test_mpc_storage_manifest_attestation_and_audit_history() {
    let coordinator = MpcClusterCoordinator::initialize(2, 4).expect("init coordinator");
    let quorum = vec![2, 3];

    let manifest_digest = [0xabu8; 32];
    let epoch = 42;

    let attestation = coordinator
        .attest_storage_manifest(&manifest_digest, epoch, &quorum)
        .await
        .expect("attest manifest");

    assert!(attestation.verify());

    let audits = coordinator.get_audit_records().await;
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].operation, "attest_storage_manifest");
    assert_eq!(audits[0].quorum, vec![2, 3]);
    assert!(audits[0].success);
    assert!(audits[0].blame_node.is_none());
}

#[test]
fn test_cross_verification_with_ring_ed25519() {
    // Generate a threshold key and threshold signature
    let master_secret = Scalar::from_u64(0xCAFEBABE1234);
    let poly = Polynomial::random_with_secret(&master_secret, 2);
    let pkg = poly.commitments();
    let group_pubkey = pkg.group_public_key().expect("pubkey");
    let shares = poly.generate_shares(3);

    let signer1 = ThresholdSigner::new(shares[0].clone(), group_pubkey);
    let signer2 = ThresholdSigner::new(shares[1].clone(), group_pubkey);

    let message = b"RFC 8032 Compliant Cross-Verification Test Payload";

    let (nonces1, comm1) = signer1.round1_commit();
    let (nonces2, comm2) = signer2.round1_commit();

    let commit_pkg = CommitmentPackage {
        commitments: vec![comm1, comm2],
    };

    let share1 = signer1.round2_sign(&nonces1, &commit_pkg, message).unwrap();
    let share2 = signer2.round2_sign(&nonces2, &commit_pkg, message).unwrap();

    let sig =
        aggregate_signature_shares(&commit_pkg, &[share1, share2], &group_pubkey, message).unwrap();

    // 1. Internal verification
    assert!(sig.verify(&group_pubkey, message));

    // 2. Standard 64-byte Ed25519 signature wire format
    let sig_bytes = sig.to_bytes();
    assert_eq!(sig_bytes.len(), 64);

    let pubkey_bytes = group_pubkey.to_bytes();
    assert_eq!(pubkey_bytes.len(), 32);

    // 3. Verify with ring's standard Ed25519 verifier!
    let ring_verifier = UnparsedPublicKey::new(&signature::ED25519, &pubkey_bytes);
    let ring_result = ring_verifier.verify(message, &sig_bytes);
    assert!(
        ring_result.is_ok(),
        "ring ed25519 verifier accepted FROST threshold signature"
    );
}
