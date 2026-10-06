//! Integration tests for Transfer Priority Scheduler and Concurrent Transfer Limiter
//! (`REQUIREMENTS.md` §24, §25, §29).

use std::sync::Arc;
use std::time::Duration;
use velcrux_core::transfer::scheduler::{
    ConcurrentTransferLimiter, PriorityScheduler, TransferPriority,
};

#[test]
fn test_transfer_priority_weights_and_parsing() {
    assert_eq!(TransferPriority::Urgent.weight(), 8);
    assert_eq!(TransferPriority::High.weight(), 4);
    assert_eq!(TransferPriority::Normal.weight(), 2);
    assert_eq!(TransferPriority::Low.weight(), 1);

    assert_eq!(TransferPriority::default(), TransferPriority::Normal);

    let base = 1024;
    assert_eq!(TransferPriority::Urgent.quantum_bytes(base), 8192);
    assert_eq!(TransferPriority::High.quantum_bytes(base), 4096);
    assert_eq!(TransferPriority::Normal.quantum_bytes(base), 2048);
    assert_eq!(TransferPriority::Low.quantum_bytes(base), 1024);

    // Parsing
    assert_eq!(
        "urgent".parse::<TransferPriority>().unwrap(),
        TransferPriority::Urgent
    );
    assert_eq!(
        "URGENT".parse::<TransferPriority>().unwrap(),
        TransferPriority::Urgent
    );
    assert_eq!(
        "high".parse::<TransferPriority>().unwrap(),
        TransferPriority::High
    );
    assert_eq!(
        "Normal".parse::<TransferPriority>().unwrap(),
        TransferPriority::Normal
    );
    assert_eq!(
        "low".parse::<TransferPriority>().unwrap(),
        TransferPriority::Low
    );
    assert_eq!(
        "background".parse::<TransferPriority>().unwrap(),
        TransferPriority::Low
    );
    assert!("invalid_prio".parse::<TransferPriority>().is_err());

    // Display
    assert_eq!(TransferPriority::Urgent.to_string(), "urgent");
    assert_eq!(TransferPriority::High.to_string(), "high");
    assert_eq!(TransferPriority::Normal.to_string(), "normal");
    assert_eq!(TransferPriority::Low.to_string(), "low");

    // Serde roundtrip
    let serialized = serde_json::to_string(&TransferPriority::High).unwrap();
    let deserialized: TransferPriority = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, TransferPriority::High);
}

#[test]
fn test_priority_scheduler_push_and_cancel() {
    let mut scheduler: PriorityScheduler<&'static str> = PriorityScheduler::new(1000);
    assert!(scheduler.is_empty());
    assert_eq!(scheduler.len(), 0);

    let id1 = scheduler.push("task-normal", TransferPriority::Normal, 500);
    let id2 = scheduler.push("task-high", TransferPriority::High, 500);
    let id3 = scheduler.push("task-low", TransferPriority::Low, 500);

    assert_eq!(scheduler.len(), 3);
    assert_eq!(scheduler.count_for_priority(TransferPriority::Normal), 1);
    assert_eq!(scheduler.count_for_priority(TransferPriority::High), 1);
    assert_eq!(scheduler.count_for_priority(TransferPriority::Low), 1);
    assert_eq!(scheduler.count_for_priority(TransferPriority::Urgent), 0);

    // Cancel id2
    let cancelled = scheduler.cancel(id2);
    assert_eq!(cancelled, Some("task-high"));
    assert_eq!(scheduler.len(), 2);
    assert_eq!(scheduler.count_for_priority(TransferPriority::High), 0);

    // Cancel non-existent
    assert_eq!(scheduler.cancel(99999), None);
    assert_eq!(scheduler.cancel(id2), None);

    // Cancel id1
    assert_eq!(scheduler.cancel(id1), Some("task-normal"));
    assert_eq!(scheduler.len(), 1);

    // Pop remaining task
    let popped = scheduler.pop_next().unwrap();
    assert_eq!(popped.id, id3);
    assert_eq!(popped.payload, "task-low");
    assert!(scheduler.is_empty());
}

#[test]
fn test_priority_scheduler_drr_fairness_and_starvation_prevention() {
    // Base quantum = 100 units
    // Urgent gets 800 units/round
    // High gets 400 units/round
    // Normal gets 200 units/round
    // Low gets 100 units/round
    let mut scheduler = PriorityScheduler::new(100);

    // Enqueue 8 tasks per priority, each costing 100 units
    for i in 0..8 {
        scheduler.push(format!("urgent-{i}"), TransferPriority::Urgent, 100);
        scheduler.push(format!("high-{i}"), TransferPriority::High, 100);
        scheduler.push(format!("normal-{i}"), TransferPriority::Normal, 100);
        scheduler.push(format!("low-{i}"), TransferPriority::Low, 100);
    }

    assert_eq!(scheduler.len(), 32);

    let mut served_urgent = 0;
    let mut served_high = 0;
    let mut served_normal = 0;
    let mut served_low = 0;

    // Pop until empty, tracking that all tiers get served and no starvation occurs
    while let Some(task) = scheduler.pop_next() {
        match task.priority {
            TransferPriority::Urgent => served_urgent += 1,
            TransferPriority::High => served_high += 1,
            TransferPriority::Normal => served_normal += 1,
            TransferPriority::Low => served_low += 1,
        }
    }

    assert_eq!(served_urgent, 8);
    assert_eq!(served_high, 8);
    assert_eq!(served_normal, 8);
    assert_eq!(served_low, 8);
    assert!(scheduler.is_empty());
}

#[test]
fn test_priority_scheduler_urgent_preemptive() {
    let mut scheduler = PriorityScheduler::new(1000);

    scheduler.push("normal-1", TransferPriority::Normal, 100);
    scheduler.push("high-1", TransferPriority::High, 100);
    scheduler.push("urgent-1", TransferPriority::Urgent, 100);
    scheduler.push("low-1", TransferPriority::Low, 100);

    // Preemptive pop should immediately yield the Urgent task
    let t1 = scheduler.pop_next_urgent_preemptive().unwrap();
    assert_eq!(t1.priority, TransferPriority::Urgent);
    assert_eq!(t1.payload, "urgent-1");

    // Enqueue another urgent task
    scheduler.push("urgent-2", TransferPriority::Urgent, 100);
    let t2 = scheduler.pop_next_urgent_preemptive().unwrap();
    assert_eq!(t2.priority, TransferPriority::Urgent);
    assert_eq!(t2.payload, "urgent-2");

    // When urgent is empty, next pop falls back to DRR
    let t3 = scheduler.pop_next_urgent_preemptive().unwrap();
    assert_ne!(t3.priority, TransferPriority::Urgent);
}

#[tokio::test]
async fn test_concurrent_transfer_limiter_capacity() {
    let limiter = ConcurrentTransferLimiter::new(2);
    assert_eq!(limiter.max_concurrency().await, 2);
    assert_eq!(limiter.active_transfers().await, 0);
    assert_eq!(limiter.waiting_transfers().await, 0);

    // Acquire slot 1
    let permit1 = limiter.acquire(TransferPriority::Normal).await;
    assert_eq!(limiter.active_transfers().await, 1);
    assert_eq!(limiter.waiting_transfers().await, 0);

    // Acquire slot 2
    let permit2 = limiter.acquire(TransferPriority::Normal).await;
    assert_eq!(limiter.active_transfers().await, 2);
    assert_eq!(limiter.waiting_transfers().await, 0);

    // Drop permit1 -> slot should free up
    drop(permit1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(limiter.active_transfers().await, 1);

    // Drop permit2
    drop(permit2);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(limiter.active_transfers().await, 0);
}

#[tokio::test]
async fn test_concurrent_transfer_limiter_priority_waking() {
    let limiter = ConcurrentTransferLimiter::new(1);

    // Hold the single available permit
    let permit0 = limiter.acquire(TransferPriority::Normal).await;
    assert_eq!(limiter.active_transfers().await, 1);

    // Launch background waiters in reverse priority order: Low, then Normal, then Urgent
    let execution_order = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let limiter_low = limiter.clone();
    let order_low = Arc::clone(&execution_order);
    tokio::spawn(async move {
        let _permit = limiter_low.acquire(TransferPriority::Low).await;
        order_low.lock().await.push("low");
    });

    let limiter_norm = limiter.clone();
    let order_norm = Arc::clone(&execution_order);
    tokio::spawn(async move {
        let _permit = limiter_norm.acquire(TransferPriority::Normal).await;
        order_norm.lock().await.push("normal");
    });

    let limiter_urg = limiter.clone();
    let order_urg = Arc::clone(&execution_order);
    tokio::spawn(async move {
        let _permit = limiter_urg.acquire(TransferPriority::Urgent).await;
        order_urg.lock().await.push("urgent");
    });

    // Give time for waiters to register
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(limiter.waiting_transfers().await, 3);

    // Release permit0: Urgent should be woken first despite arriving last
    drop(permit0);

    // Allow the waking chain to process
    tokio::time::sleep(Duration::from_millis(150)).await;

    let order = execution_order.lock().await.clone();
    // Urgent must have woken up first!
    assert!(!order.is_empty());
    assert_eq!(
        order[0], "urgent",
        "Urgent must be woken before Normal and Low"
    );
}
