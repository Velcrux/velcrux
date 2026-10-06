//! Transfer priority scheduler and concurrent transfer limiter (`REQUIREMENTS.md` §24, §25, §29).
//!
//! Provides:
//! - Priority-weighted Deficit Round-Robin (DRR) scheduling across `Urgent`, `High`, `Normal`, and `Low` priority tiers.
//! - Starvation prevention: lower priority tasks steadily accumulate deficits and receive guaranteed bandwidth quanta.
//! - Bounded concurrency limiter (`ConcurrentTransferLimiter`) enforcing maximum active parallel transfers with priority-ordered queueing.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

/// Priority tier assigned to a transfer, stream, or chunk (`REQUIREMENTS.md` §24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransferPriority {
    /// Urgent priority (quantum weight 8, priority tier 0).
    /// Used for small metadata, PING, control frames, or interactive commands.
    Urgent = 0,
    /// High priority (quantum weight 4, priority tier 1).
    /// Used for expedited transfers.
    High = 1,
    /// Normal priority (quantum weight 2, priority tier 2).
    /// Default for standard bulk file transfers.
    Normal = 2,
    /// Low / Background priority (quantum weight 1, priority tier 3).
    /// Used for bulk background synchronization.
    Low = 3,
}

impl Default for TransferPriority {
    fn default() -> Self {
        Self::Normal
    }
}

impl TransferPriority {
    /// Relative quantum weight for Deficit Round-Robin scheduling.
    pub fn weight(&self) -> u64 {
        match self {
            Self::Urgent => 8,
            Self::High => 4,
            Self::Normal => 2,
            Self::Low => 1,
        }
    }

    /// Quantum byte allocation per round for this priority tier based on base quantum.
    pub fn quantum_bytes(&self, base_quantum: u64) -> u64 {
        base_quantum.saturating_mul(self.weight())
    }

    /// All priority tiers in descending order of priority.
    pub fn all() -> &'static [TransferPriority] {
        &[
            TransferPriority::Urgent,
            TransferPriority::High,
            TransferPriority::Normal,
            TransferPriority::Low,
        ]
    }
}

impl std::str::FromStr for TransferPriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "urgent" => Ok(Self::Urgent),
            "high" => Ok(Self::High),
            "normal" => Ok(Self::Normal),
            "low" | "background" => Ok(Self::Low),
            other => Err(format!(
                "invalid transfer priority: '{other}' (expected 'urgent', 'high', 'normal', or 'low')"
            )),
        }
    }
}

impl std::fmt::Display for TransferPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Urgent => write!(f, "urgent"),
            Self::High => write!(f, "high"),
            Self::Normal => write!(f, "normal"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// A scheduled item wrapped with its metadata and size cost.
#[derive(Debug, Clone)]
pub struct ScheduledTask<T> {
    /// Unique identifier for this task.
    pub id: u64,
    /// Priority tier of this task.
    pub priority: TransferPriority,
    /// Cost in bytes or abstract work units (must be >= 1).
    pub cost: u64,
    /// Enqueued payload.
    pub payload: T,
}

/// Deficit Round-Robin (DRR) priority scheduler (`REQUIREMENTS.md` §24, §29).
///
/// Prevents starvation of lower priority tiers while ensuring higher priority
/// traffic receives proportionally larger quanta of bandwidth and dispatch slots.
#[derive(Debug)]
pub struct PriorityScheduler<T> {
    base_quantum: u64,
    next_id: AtomicU64,
    queues: BTreeMap<TransferPriority, (VecDeque<ScheduledTask<T>>, u64)>,
    round_robin_index: usize,
}

impl<T> PriorityScheduler<T> {
    /// Default base quantum size (64 KiB).
    pub const DEFAULT_BASE_QUANTUM: u64 = 64 * 1024;

    /// Create a new priority scheduler with the specified base quantum in bytes.
    pub fn new(base_quantum: u64) -> Self {
        let base_quantum = if base_quantum == 0 {
            Self::DEFAULT_BASE_QUANTUM
        } else {
            base_quantum
        };

        let mut queues = BTreeMap::new();
        for &p in TransferPriority::all() {
            queues.insert(p, (VecDeque::new(), 0));
        }

        Self {
            base_quantum,
            next_id: AtomicU64::new(1),
            queues,
            round_robin_index: 0,
        }
    }

    /// Push an item into the scheduler queue. Returns the assigned task ID.
    pub fn push(&mut self, payload: T, priority: TransferPriority, cost: u64) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cost = cost.max(1);
        let task = ScheduledTask {
            id,
            priority,
            cost,
            payload,
        };

        if let Some((q, _)) = self.queues.get_mut(&priority) {
            q.push_back(task);
        }
        id
    }

    /// Total number of pending tasks across all priority tiers.
    pub fn len(&self) -> usize {
        self.queues.values().map(|(q, _)| q.len()).sum()
    }

    /// Whether there are any pending tasks.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of tasks pending for a specific priority tier.
    pub fn count_for_priority(&self, priority: TransferPriority) -> usize {
        self.queues
            .get(&priority)
            .map(|(q, _)| q.len())
            .unwrap_or(0)
    }

    /// Pop the next task using strict Deficit Round-Robin fairness.
    ///
    /// Starvation prevention is mathematically guaranteed: all active queues receive
    /// incremental credits in proportion to their weight. If a queue becomes empty,
    /// its deficit is reset to 0 to prevent hoarding.
    pub fn pop_next(&mut self) -> Option<ScheduledTask<T>> {
        if self.is_empty() {
            return None;
        }

        let priorities = TransferPriority::all();
        let num_priorities = priorities.len();

        for _ in 0..(num_priorities * 2) {
            let p = priorities[self.round_robin_index % num_priorities];
            self.round_robin_index = (self.round_robin_index + 1) % num_priorities;

            if let Some((q, deficit)) = self.queues.get_mut(&p) {
                if q.is_empty() {
                    *deficit = 0;
                    continue;
                }

                // Add priority-weighted quantum to deficit
                *deficit = deficit.saturating_add(p.quantum_bytes(self.base_quantum));

                if let Some(front) = q.front() {
                    if *deficit >= front.cost {
                        let task = q.pop_front().unwrap();
                        *deficit = deficit.saturating_sub(task.cost);
                        if q.is_empty() {
                            *deficit = 0;
                        }
                        return Some(task);
                    }
                }
            }
        }

        // Fallback: pop from highest priority non-empty queue if all costs exceed quanta
        for &p in priorities {
            if let Some((q, deficit)) = self.queues.get_mut(&p) {
                if let Some(task) = q.pop_front() {
                    *deficit = 0;
                    return Some(task);
                }
            }
        }

        None
    }

    /// Pop the next task, strictly giving Urgent priority immediate preemption
    /// before applying Deficit Round-Robin to other tiers.
    pub fn pop_next_urgent_preemptive(&mut self) -> Option<ScheduledTask<T>> {
        // 1. If Urgent queue has any items, serve immediately
        if let Some((urgent_q, _)) = self.queues.get_mut(&TransferPriority::Urgent) {
            if let Some(task) = urgent_q.pop_front() {
                return Some(task);
            }
        }
        // 2. Otherwise serve using DRR
        self.pop_next()
    }

    /// Cancel a task by its ID, returning its payload if it was still in the queue.
    pub fn cancel(&mut self, task_id: u64) -> Option<T> {
        for (q, _) in self.queues.values_mut() {
            if let Some(pos) = q.iter().position(|t| t.id == task_id) {
                let task = q.remove(pos).unwrap();
                return Some(task.payload);
            }
        }
        None
    }
}

impl<T> Default for PriorityScheduler<T> {
    fn default() -> Self {
        Self::new(Self::DEFAULT_BASE_QUANTUM)
    }
}

// ---------------------------------------------------------------------------
// ConcurrentTransferLimiter (Bounded Concurrency with Priority Acquisition)
// ---------------------------------------------------------------------------

struct LimiterState {
    max_concurrency: usize,
    active_count: usize,
    waiters: BTreeMap<TransferPriority, VecDeque<oneshot::Sender<()>>>,
}

/// A concurrency limiter that regulates simultaneous active file transfers
/// with priority-ordered queueing (`REQUIREMENTS.md` §25).
#[derive(Clone)]
pub struct ConcurrentTransferLimiter {
    state: Arc<Mutex<LimiterState>>,
}

impl std::fmt::Debug for ConcurrentTransferLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrentTransferLimiter")
            .finish_non_exhaustive()
    }
}

impl ConcurrentTransferLimiter {
    /// Default maximum parallel transfers per session/connection.
    pub const DEFAULT_MAX_CONCURRENT: usize = 4;

    /// Create a new concurrent transfer limiter with the specified maximum active transfers.
    pub fn new(max_concurrency: usize) -> Self {
        let max_concurrency = max_concurrency.max(1);
        let mut waiters = BTreeMap::new();
        for &p in TransferPriority::all() {
            waiters.insert(p, VecDeque::new());
        }

        Self {
            state: Arc::new(Mutex::new(LimiterState {
                max_concurrency,
                active_count: 0,
                waiters,
            })),
        }
    }

    /// Maximum concurrency allowed.
    pub async fn max_concurrency(&self) -> usize {
        self.state.lock().await.max_concurrency
    }

    /// Number of transfers currently holding active execution slots.
    pub async fn active_transfers(&self) -> usize {
        self.state.lock().await.active_count
    }

    /// Total number of transfers waiting for an available slot.
    pub async fn waiting_transfers(&self) -> usize {
        self.state
            .lock()
            .await
            .waiters
            .values()
            .map(|q| q.len())
            .sum()
    }

    /// Acquire an execution slot.
    ///
    /// If all slots are occupied, the caller is enqueued in its respective priority
    /// tier (Urgent > High > Normal > Low) and waits asynchronously until a slot frees up.
    pub async fn acquire(&self, priority: TransferPriority) -> TransferPermit {
        let rx = {
            let mut state = self.state.lock().await;
            if state.active_count < state.max_concurrency {
                state.active_count += 1;
                return TransferPermit {
                    limiter: Arc::clone(&self.state),
                };
            }

            // Enqueue waiter into priority tier
            let (tx, rx) = oneshot::channel();
            state
                .waiters
                .entry(priority)
                .or_insert_with(VecDeque::new)
                .push_back(tx);
            rx
        };

        // Wait until notified
        let _ = rx.await;
        TransferPermit {
            limiter: Arc::clone(&self.state),
        }
    }
}

/// An active transfer lease. When dropped, the slot is automatically yielded
/// to the highest priority waiting task.
pub struct TransferPermit {
    limiter: Arc<Mutex<LimiterState>>,
}

impl std::fmt::Debug for TransferPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferPermit").finish()
    }
}

impl Drop for TransferPermit {
    fn drop(&mut self) {
        let limiter = Arc::clone(&self.limiter);
        tokio::spawn(async move {
            let mut state = limiter.lock().await;
            // Find highest priority waiter
            for &p in TransferPriority::all() {
                if let Some(waiters) = state.waiters.get_mut(&p) {
                    while let Some(tx) = waiters.pop_front() {
                        if tx.send(()).is_ok() {
                            return;
                        }
                        // If waiter receiver was dropped, continue to next
                    }
                }
            }

            // No active waiters, decrement active count
            if state.active_count > 0 {
                state.active_count -= 1;
            }
        });
    }
}
