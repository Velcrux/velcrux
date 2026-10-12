//! Integration tests for Distributed Lock Manager (DLM) & Mutex Lease Coordinator (Option BD).

use tempfile::tempdir;
use velcrux_core::sync::{DistributedLockManager, LockError, LockMode};

#[test]
fn test_dlm_exclusive_lock_mutual_exclusion() {
    let dlm = DistributedLockManager::new();
    let resource = "/datasets/genome.tar";
    let now = 1000u64;

    // 1. Client A acquires exclusive write lease
    let lease_a = dlm
        .acquire(resource, "client-node-a", LockMode::Exclusive, Some(60), now)
        .expect("acquire lease A");

    assert_eq!(lease_a.resource, resource);
    assert_eq!(lease_a.holder_id, "client-node-a");
    assert_eq!(lease_a.mode, LockMode::Exclusive);
    assert_eq!(lease_a.fencing_token, 101);
    assert_eq!(lease_a.expires_at_secs, 1060);
    assert!(!lease_a.is_expired(now));

    // 2. Client B attempts exclusive acquisition -> Rejected (ResourceBusy)
    let err_b = dlm
        .acquire(resource, "client-node-b", LockMode::Exclusive, Some(60), now)
        .unwrap_err();

    match err_b {
        LockError::ResourceBusy {
            current_holder,
            mode,
            expires_in_secs,
            ..
        } => {
            assert_eq!(current_holder, "client-node-a");
            assert_eq!(mode, LockMode::Exclusive);
            assert_eq!(expires_in_secs, 60);
        }
        other => panic!("unexpected error: {:?}", other),
    }

    // 3. Client C attempts shared read acquisition -> Rejected (ResourceBusy)
    let err_c = dlm
        .acquire(resource, "client-node-c", LockMode::Shared, Some(60), now)
        .unwrap_err();
    assert!(matches!(err_c, LockError::ResourceBusy { .. }));

    // 4. Unauthorized release attempt by wrong holder -> HolderMismatch
    let err_release = dlm
        .release(&lease_a.lock_id, "rogue-client", now)
        .unwrap_err();
    assert!(matches!(err_release, LockError::HolderMismatch { .. }));

    // 5. Authorized release by Client A -> Success
    assert!(dlm.release(&lease_a.lock_id, "client-node-a", now).unwrap());

    // 6. Client B can now acquire exclusive lease with higher fencing token
    let lease_b = dlm
        .acquire(resource, "client-node-b", LockMode::Exclusive, Some(60), now)
        .expect("acquire lease B");
    assert_eq!(lease_b.fencing_token, 102);
    assert_eq!(lease_b.holder_id, "client-node-b");
}

#[test]
fn test_dlm_shared_read_locks() {
    let dlm = DistributedLockManager::new();
    let resource = "/reports/annual.pdf";
    let now = 2000u64;

    // 1. Client 1 acquires shared read lock
    let lease_1 = dlm
        .acquire(resource, "reader-1", LockMode::Shared, Some(30), now)
        .expect("reader 1");

    // 2. Client 2 acquires shared read lock concurrently -> Succeeds
    let lease_2 = dlm
        .acquire(resource, "reader-2", LockMode::Shared, Some(30), now)
        .expect("reader 2");

    assert_eq!(lease_1.mode, LockMode::Shared);
    assert_eq!(lease_2.mode, LockMode::Shared);

    // 3. Writer attempts exclusive lock -> Rejected
    let err_writer = dlm
        .acquire(resource, "writer-1", LockMode::Exclusive, Some(30), now)
        .unwrap_err();
    assert!(matches!(err_writer, LockError::ResourceBusy { .. }));

    // 4. Inspect resource shows 2 active shared leases
    let active = dlm.inspect(resource, now);
    assert_eq!(active.len(), 2);

    // 5. Both readers release
    assert!(dlm.release(&lease_1.lock_id, "reader-1", now).unwrap());
    assert!(dlm.release(&lease_2.lock_id, "reader-2", now).unwrap());

    // 6. Writer can now acquire exclusive lock
    let lease_w = dlm
        .acquire(resource, "writer-1", LockMode::Exclusive, Some(30), now)
        .expect("writer 1");
    assert_eq!(lease_w.mode, LockMode::Exclusive);
}

#[test]
fn test_dlm_lease_ttl_expiry_and_deadlock_prevention() {
    let dlm = DistributedLockManager::new();
    let resource = "/backups/database.dump";
    let t_start = 5000u64;

    // 1. Client A acquires lock with 10s TTL
    let lease_a = dlm
        .acquire(resource, "worker-alpha", LockMode::Exclusive, Some(10), t_start)
        .expect("acquire alpha");
    assert_eq!(lease_a.expires_at_secs, 5010);

    // 2. Worker crashes! Halfway through (t = 5005), lock is still active
    assert!(dlm.acquire(resource, "worker-beta", LockMode::Exclusive, Some(10), 5005).is_err());

    // 3. After TTL expiry (t = 5011), Worker Beta attempts acquisition
    // DLM automatically purges expired lease and grants new lock to Beta
    let lease_b = dlm
        .acquire(resource, "worker-beta", LockMode::Exclusive, Some(10), 5011)
        .expect("acquire beta");

    assert_eq!(lease_b.holder_id, "worker-beta");
    assert!(lease_b.fencing_token > lease_a.fencing_token);

    // 4. Alpha wakes up delayed and tries to release or renew -> Fails
    assert!(matches!(
        dlm.renew(&lease_a.lock_id, "worker-alpha", Some(10), 5012),
        Err(LockError::LockNotFound { .. })
    ));
}

#[test]
fn test_dlm_lease_heartbeat_renewal() {
    let dlm = DistributedLockManager::new();
    let resource = "/pipeline/stream.dat";
    let now = 1000u64;

    let lease = dlm
        .acquire(resource, "stream-writer", LockMode::Exclusive, Some(30), now)
        .expect("acquire");
    assert_eq!(lease.expires_at_secs, 1030);

    // Renew at t = 1020 for another 30 seconds -> expires at 1050
    let renewed = dlm
        .renew(&lease.lock_id, "stream-writer", Some(30), 1020)
        .expect("renew");
    assert_eq!(renewed.expires_at_secs, 1050);
    assert_eq!(renewed.fencing_token, lease.fencing_token);

    // Attempt renewal by wrong holder -> HolderMismatch
    assert!(matches!(
        dlm.renew(&lease.lock_id, "wrong-holder", Some(30), 1025),
        Err(LockError::HolderMismatch { .. })
    ));
}

#[test]
fn test_dlm_fencing_token_and_report() {
    let dlm = DistributedLockManager::new();
    let resource = "/shared/config.json";
    let now = 3000u64;

    let lease = dlm
        .acquire(resource, "deployer", LockMode::Exclusive, Some(60), now)
        .expect("acquire");

    // Fencing token verification
    assert!(dlm.verify_fencing(resource, lease.fencing_token, now));
    assert!(!dlm.verify_fencing(resource, lease.fencing_token + 999, now));
    assert!(!dlm.verify_fencing("/other/resource", lease.fencing_token, now));

    // Report generation
    let report = dlm.generate_report(now);
    assert_eq!(report.total_active_locks, 1);
    assert_eq!(report.total_exclusive_locks, 1);
    assert_eq!(report.total_shared_locks, 0);
    assert!(report.highest_fencing_token >= lease.fencing_token);

    // After release, fencing token is no longer valid
    dlm.release(&lease.lock_id, "deployer", now).unwrap();
    assert!(!dlm.verify_fencing(resource, lease.fencing_token, now));
}

#[test]
fn test_dlm_persistence_recovery() {
    let tmp = tempdir().unwrap();
    let state_file = tmp.path().join("dlm_state.json");
    let now = 8000u64;

    // 1. Instance 1 acquires locks and saves state
    {
        let dlm1 = DistributedLockManager::new()
            .with_persistence(&state_file)
            .expect("init dlm1");

        dlm1.acquire("/sync/a", "node-1", LockMode::Exclusive, Some(120), now)
            .expect("lock a");
        dlm1.acquire("/sync/b", "node-2", LockMode::Shared, Some(120), now)
            .expect("lock b");
    }

    // 2. Instance 2 recovers state from file
    let dlm2 = DistributedLockManager::new()
        .with_persistence(&state_file)
        .expect("init dlm2");

    let report = dlm2.generate_report(now);
    assert_eq!(report.total_active_locks, 2);
    assert_eq!(report.total_exclusive_locks, 1);
    assert_eq!(report.total_shared_locks, 1);

    // Verify lock on /sync/a is still busy
    assert!(dlm2.acquire("/sync/a", "node-3", LockMode::Exclusive, Some(60), now).is_err());
}
