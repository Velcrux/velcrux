//! Integration tests for Option AS: Dynamic Multi-Tenant Bandwidth Allocator & Fairness Scheduler
//!
//! (`REQUIREMENTS.md` §28, §29; `ARCHITECTURE.md` §5; `OPERATIONS.md` §27).
//!
//! Verifies:
//! 1. Multi-tier hierarchical bandwidth limit composition: `min(per_transfer, per_user, global)`.
//! 2. Strict priority queue draining (`High` priority drained to exhaustion first).
//! 3. 4:1 Weighted Round-Robin (WRR) fairness interleaving between `Normal` and `Low`.
//! 4. Multi-tenant thread-safe concurrent scheduling with zero item loss.
//! 5. Async token bucket pacing with deficit recovery.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use velcrux_core::scheduler::{
    BandwidthRate, FairnessScheduler, HierarchicalBandwidthAllocator, PriorityClass,
};
use velcrux_core::util::TransferId;

#[test]
fn test_server_scheduler_hierarchical_limit_composition() {
    let global_rate = BandwidthRate::from_bytes_per_sec(20_000_000); // 20 MB/s
    let user_rate = BandwidthRate::from_bytes_per_sec(10_000_000); // 10 MB/s
    let transfer_rate = BandwidthRate::from_bytes_per_sec(5_000_000); // 5 MB/s

    let allocator = HierarchicalBandwidthAllocator::new(global_rate);
    let tid = TransferId::from_bytes(&[1u8; 16]).unwrap();

    allocator.set_user_rate("tenant-alpha", user_rate);
    allocator.set_transfer_rate(&tid, transfer_rate);

    // Consume 15 MB in one burst -> exceeds all burst capacities
    let delay = allocator.consume("tenant-alpha", &tid, 15_000_000);
    assert!(delay > Duration::ZERO);

    // At 5 MB/s (transfer limit is the lowest), 15 MB takes roughly 2.5 - 3.0 seconds
    assert!(
        delay >= Duration::from_millis(2000),
        "Expected delay throttled to 5MB/s transfer limit, got {:?}",
        delay
    );

    // Remove transfer limit: now throttled to user limit (10 MB/s)
    allocator.remove_transfer(&tid);
    let tid2 = TransferId::from_bytes(&[2u8; 16]).unwrap();
    let delay_user = allocator.consume("tenant-alpha", &tid2, 15_000_000);
    assert!(delay_user > Duration::ZERO);
    // At 10 MB/s, 15 MB takes ~1.0 - 1.5 seconds (less than 2s)
    assert!(
        delay_user < delay,
        "User ceiling (10 MB/s) should result in lower delay than 5 MB/s"
    );
}

#[test]
fn test_server_scheduler_strict_priority_drain() {
    let allocator = Arc::new(HierarchicalBandwidthAllocator::default());
    let scheduler: FairnessScheduler<usize> = FairnessScheduler::new(allocator);
    let tid = TransferId::from_bytes(&[3u8; 16]).unwrap();

    // Interleave High, Normal, and Low items
    scheduler.enqueue(100, PriorityClass::Normal, "userA", tid);
    scheduler.enqueue(200, PriorityClass::Low, "userA", tid);
    scheduler.enqueue(1, PriorityClass::High, "userA", tid);
    scheduler.enqueue(101, PriorityClass::Normal, "userA", tid);
    scheduler.enqueue(2, PriorityClass::High, "userA", tid);
    scheduler.enqueue(201, PriorityClass::Low, "userA", tid);
    scheduler.enqueue(3, PriorityClass::High, "userA", tid);

    // Assert that ALL High items (1, 2, 3) are dequeued before ANY Normal or Low items
    assert_eq!(scheduler.dequeue().unwrap().item, 1);
    assert_eq!(scheduler.dequeue().unwrap().item, 2);
    assert_eq!(scheduler.dequeue().unwrap().item, 3);

    // After High queue is drained, Normal and Low are dequeued following 4:1 WRR
    let next = scheduler.dequeue().unwrap();
    assert_eq!(next.priority, PriorityClass::Normal);
    assert_eq!(next.item, 100);
}

#[test]
fn test_server_scheduler_4_to_1_wrr_fairness_interleave() {
    let allocator = Arc::new(HierarchicalBandwidthAllocator::default());
    let scheduler: FairnessScheduler<String> = FairnessScheduler::new(allocator);
    let tid = TransferId::from_bytes(&[4u8; 16]).unwrap();

    // Enqueue 12 Normal and 6 Low items
    for i in 1..=12 {
        scheduler.enqueue(format!("N{}", i), PriorityClass::Normal, "tenant-1", tid);
    }
    for i in 1..=6 {
        scheduler.enqueue(format!("L{}", i), PriorityClass::Low, "tenant-1", tid);
    }

    // Verify Cycle 1: 4 Normal followed by 1 Low
    assert_eq!(scheduler.dequeue().unwrap().item, "N1");
    assert_eq!(scheduler.dequeue().unwrap().item, "N2");
    assert_eq!(scheduler.dequeue().unwrap().item, "N3");
    assert_eq!(scheduler.dequeue().unwrap().item, "N4");
    assert_eq!(scheduler.dequeue().unwrap().item, "L1");

    // Verify Cycle 2: 4 Normal followed by 1 Low
    assert_eq!(scheduler.dequeue().unwrap().item, "N5");
    assert_eq!(scheduler.dequeue().unwrap().item, "N6");
    assert_eq!(scheduler.dequeue().unwrap().item, "N7");
    assert_eq!(scheduler.dequeue().unwrap().item, "N8");
    assert_eq!(scheduler.dequeue().unwrap().item, "L2");

    // Verify Cycle 3: 4 Normal followed by 1 Low
    assert_eq!(scheduler.dequeue().unwrap().item, "N9");
    assert_eq!(scheduler.dequeue().unwrap().item, "N10");
    assert_eq!(scheduler.dequeue().unwrap().item, "N11");
    assert_eq!(scheduler.dequeue().unwrap().item, "N12");
    assert_eq!(scheduler.dequeue().unwrap().item, "L3");

    // Normal queue is now empty. Remaining Low items (L4, L5, L6) must still drain without stalling
    assert_eq!(scheduler.dequeue().unwrap().item, "L4");
    assert_eq!(scheduler.dequeue().unwrap().item, "L5");
    assert_eq!(scheduler.dequeue().unwrap().item, "L6");
    assert!(scheduler.is_empty());
}

#[test]
fn test_server_scheduler_zero_loss_concurrency() {
    let allocator = Arc::new(HierarchicalBandwidthAllocator::default());
    let scheduler = Arc::new(FairnessScheduler::new(allocator));
    let tid = TransferId::from_bytes(&[5u8; 16]).unwrap();

    let items_per_thread = 500;
    let num_producers = 4;
    let mut handles = Vec::new();

    // Spawn 4 producer threads enqueuing mixed priorities
    for p in 0..num_producers {
        let s = Arc::clone(&scheduler);
        handles.push(std::thread::spawn(move || {
            for i in 0..items_per_thread {
                let priority = match (p + i) % 3 {
                    0 => PriorityClass::High,
                    1 => PriorityClass::Normal,
                    _ => PriorityClass::Low,
                };
                s.enqueue(p * 10_000 + i, priority, format!("user-{}", p), tid);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(scheduler.len(), num_producers * items_per_thread);

    // Consume all items across 4 consumer threads
    let consumed_count = Arc::new(AtomicUsize::new(0));
    let mut consumer_handles = Vec::new();

    for _ in 0..4 {
        let s = Arc::clone(&scheduler);
        let count = Arc::clone(&consumed_count);
        consumer_handles.push(std::thread::spawn(move || {
            while let Some(_item) = s.dequeue() {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in consumer_handles {
        h.join().unwrap();
    }

    assert_eq!(
        consumed_count.load(Ordering::Relaxed),
        num_producers * items_per_thread
    );
    assert!(scheduler.is_empty());
}

#[tokio::test]
async fn test_async_token_bucket_pacing_accuracy() {
    // 500 KB/s rate limit
    let rate = BandwidthRate::from_bytes_per_sec(500_000);
    let allocator = HierarchicalBandwidthAllocator::new(rate);
    let tid = TransferId::from_bytes(&[6u8; 16]).unwrap();

    // Consume initial burst
    allocator.consume("alice", &tid, 100_000);

    // Acquire 250 KB asynchronously: at 500 KB/s, 250 KB takes ~500ms
    let start = Instant::now();
    let delay = allocator.acquire("alice", &tid, 250_000).await;
    let elapsed = start.elapsed();

    assert!(delay > Duration::ZERO);
    assert!(
        elapsed >= Duration::from_millis(400),
        "Expected elapsed >= 400ms for 250KB at 500KB/s, got {:?}",
        elapsed
    );
}
