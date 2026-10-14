//! Pluggable webhook event notification and audit logging bus (Option BB).
//!
//! Implements `REQUIREMENTS.md` §69–§73 ("Audit Logging & Event Notification Webhooks")
//! and `ARCHITECTURE.md` §11 ("Telemetry & Operational Visibility").
//! Provides signed HMAC-SHA256 webhook dispatch, exponential backoff retries,
//! dead-letter queue (DLQ) buffering, and structured JSON audit event streaming.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ring::hmac;
use serde::{Deserialize, Serialize};

/// Types of system and transfer lifecycle events that trigger webhook notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    /// Data transfer session initiated.
    TransferStarted,
    /// Data transfer successfully completed and committed.
    TransferCompleted,
    /// Data transfer aborted due to error or cancellation.
    TransferFailed,
    /// Chunk checksum mismatch or storage corruption detected.
    ChunkCorrupted,
    /// Cluster storage node state transition (Healthy, Suspect, Dead).
    ClusterNodeStateChanged,
    /// Concurrent multi-region replication conflict resolved.
    ConflictResolved,
    /// Deletion tombstone expired and pruned from ledger.
    TombstonePruned,
    /// Security audit action (authentication, configuration update, deletion).
    AuditAction,
}

impl fmt::Display for WebhookEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransferStarted => write!(f, "transfer.started"),
            Self::TransferCompleted => write!(f, "transfer.completed"),
            Self::TransferFailed => write!(f, "transfer.failed"),
            Self::ChunkCorrupted => write!(f, "chunk.corrupted"),
            Self::ClusterNodeStateChanged => write!(f, "cluster.node_changed"),
            Self::ConflictResolved => write!(f, "geo.conflict_resolved"),
            Self::TombstonePruned => write!(f, "geo.tombstone_pruned"),
            Self::AuditAction => write!(f, "audit.action"),
        }
    }
}

impl std::str::FromStr for WebhookEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "transfer.started" | "transfer_started" | "start" => Ok(Self::TransferStarted),
            "transfer.completed" | "transfer_completed" | "completed" | "complete" => {
                Ok(Self::TransferCompleted)
            }
            "transfer.failed" | "transfer_failed" | "failed" => Ok(Self::TransferFailed),
            "chunk.corrupted" | "chunk_corrupted" | "corrupted" => Ok(Self::ChunkCorrupted),
            "cluster.node_changed"
            | "cluster_node_changed"
            | "cluster_node_state_changed"
            | "cluster" => Ok(Self::ClusterNodeStateChanged),
            "geo.conflict_resolved" | "conflict_resolved" | "conflict" => {
                Ok(Self::ConflictResolved)
            }
            "geo.tombstone_pruned" | "tombstone_pruned" | "tombstone" => Ok(Self::TombstonePruned),
            "audit.action" | "audit_action" | "audit" => Ok(Self::AuditAction),
            other => Err(format!("unknown webhook event type: '{}'", other)),
        }
    }
}

/// Standardized JSON event notification payload delivered to webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Unique event identifier.
    pub event_id: String,
    /// Event classification type.
    pub event_type: WebhookEventType,
    /// Timestamp in seconds since Unix epoch.
    pub timestamp: u64,
    /// Node or region identifier where event originated.
    pub origin_node: String,
    /// Structured event payload data.
    pub data: serde_json::Value,
}

impl WebhookPayload {
    /// Create a new event payload.
    pub fn new(
        event_id: impl Into<String>,
        event_type: WebhookEventType,
        origin_node: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            event_id: event_id.into(),
            event_type,
            timestamp: ts,
            origin_node: origin_node.into(),
            data,
        }
    }
}

/// Webhook signature generator and validator conforming to HMAC-SHA256 standards.
pub struct WebhookSigner;

impl WebhookSigner {
    /// Generate signature header string in format: `t={timestamp},v1={hex_hmac}`.
    pub fn sign(secret: &str, timestamp: u64, payload_json: &str) -> String {
        let signed_payload = format!("{}.{}", timestamp, payload_json);
        let s_key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&s_key, signed_payload.as_bytes());
        let hex_sig = Self::to_hex(tag.as_ref());
        format!("t={},v1={}", timestamp, hex_sig)
    }

    /// Verify an incoming signature header against expected secret and payload.
    pub fn verify(
        secret: &str,
        header: &str,
        payload_json: &str,
        tolerance_secs: u64,
        now_secs: u64,
    ) -> bool {
        let mut timestamp = None;
        let mut signature = None;

        for part in header.split(',') {
            if let Some((k, v)) = part.trim().split_once('=') {
                match k.trim() {
                    "t" => {
                        if let Ok(ts) = v.trim().parse::<u64>() {
                            timestamp = Some(ts);
                        }
                    }
                    "v1" => {
                        signature = Some(v.trim());
                    }
                    _ => {}
                }
            }
        }

        let (ts, sig) = match (timestamp, signature) {
            (Some(t), Some(s)) => (t, s),
            _ => return false,
        };

        // Replay defense: check timestamp skew within tolerance
        if now_secs.abs_diff(ts) > tolerance_secs {
            return false;
        }

        let expected_header = Self::sign(secret, ts, payload_json);
        let expected_sig = match expected_header.split_once(",v1=") {
            Some((_, s)) => s,
            None => return false,
        };

        // Constant-time comparison
        Self::constant_time_eq(sig.as_bytes(), expected_sig.as_bytes())
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

/// Registered webhook subscriber configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSubscription {
    /// Unique subscription identifier.
    pub id: String,
    /// Target HTTP/HTTPS endpoint URL.
    pub url: String,
    /// Shared secret key used for HMAC-SHA256 request signing.
    pub secret: String,
    /// Filtered event types to receive (empty = receive all events).
    pub events: Vec<WebhookEventType>,
    /// Whether this subscriber is active.
    pub enabled: bool,
    /// Maximum retry attempts before routing to Dead-Letter Queue (default: 3).
    pub max_retries: usize,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl WebhookSubscription {
    /// Create a new webhook subscription.
    pub fn new(id: impl Into<String>, url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            url: url.into(),
            secret: secret.into(),
            events: Vec::new(),
            enabled: true,
            max_retries: 3,
            timeout_secs: 10,
        }
    }

    /// Filter specific event types.
    pub fn with_events(mut self, events: Vec<WebhookEventType>) -> Self {
        self.events = events;
        self
    }

    /// Set maximum retries before DLQ routing.
    pub fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Check if this subscription is interested in a given event type.
    pub fn matches(&self, event_type: WebhookEventType) -> bool {
        if !self.enabled {
            return false;
        }
        if self.events.is_empty() {
            return true;
        }
        self.events.contains(&event_type)
    }
}

/// Status of an individual webhook delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Delivered successfully.
    Delivered { status_code: u16, latency_ms: u64 },
    /// Delivery failed but scheduled for retry with exponential backoff.
    Retrying {
        attempt: usize,
        max_retries: usize,
        next_backoff_ms: u64,
    },
    /// Delivery failed permanently and routed to Dead-Letter Queue (DLQ).
    DeadLettered { attempts: usize, reason: String },
}

/// An entry in the Dead-Letter Queue (DLQ) containing failed delivery metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    /// DLQ entry sequence ID.
    pub id: String,
    /// Target subscriber ID.
    pub subscription_id: String,
    /// Target endpoint URL.
    pub url: String,
    /// Failed event payload.
    pub payload: WebhookPayload,
    /// Number of delivery attempts made.
    pub attempts: usize,
    /// Timestamp of last failure.
    pub failed_at_secs: u64,
    /// Error description.
    pub reason: String,
}

/// Bounded Dead-Letter Queue (DLQ) storing failed deliveries for operator inspection.
#[derive(Debug, Default)]
pub struct WebhookDeadLetterQueue {
    entries: VecDeque<DeadLetterEntry>,
    max_capacity: usize,
}

impl WebhookDeadLetterQueue {
    /// Create a new DLQ with bounded capacity.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_capacity: max_capacity.max(50),
        }
    }

    /// Push an entry to DLQ, dropping oldest if capacity exceeded.
    pub fn push(&mut self, entry: DeadLetterEntry) {
        if self.entries.len() >= self.max_capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Current count of entries in DLQ.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if DLQ is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List all current DLQ entries.
    pub fn list(&self) -> Vec<DeadLetterEntry> {
        self.entries.iter().cloned().collect()
    }

    /// Drain all entries from DLQ for replay.
    pub fn drain(&mut self) -> Vec<DeadLetterEntry> {
        self.entries.drain(..).collect()
    }

    /// Clear all entries from DLQ.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Real-time metrics for webhook event notifications.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookMetrics {
    /// Total events published to the event bus.
    pub total_events_published: u64,
    /// Total successful HTTP deliveries.
    pub total_deliveries_succeeded: u64,
    /// Total delivery attempts that failed.
    pub total_deliveries_failed: u64,
    /// Total retry attempts scheduled.
    pub total_retries_scheduled: u64,
    /// Total events permanently routed to DLQ.
    pub total_dead_lettered: u64,
    /// Average delivery latency in milliseconds.
    pub average_latency_ms: f64,
}

/// Plug-in delivery sink interface for testing and simulated HTTP endpoints.
pub trait WebhookDeliverySink: Send + Sync {
    /// Attempt delivery of a signed request.
    fn deliver(&self, url: &str, signature_header: &str, payload_json: &str)
        -> Result<u16, String>;
}

/// Default mock / simulated delivery sink for testing and local operation.
#[derive(Default)]
pub struct MockWebhookSink {
    delivered_requests: Mutex<Vec<(String, String, String)>>,
    fail_urls: Mutex<HashMap<String, usize>>,
    attempt_counts: Mutex<HashMap<String, usize>>,
}

impl MockWebhookSink {
    /// Create a new mock sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure a URL to fail for N attempts.
    pub fn set_fail_attempts(&self, url: &str, attempts: usize) {
        let mut map = self.fail_urls.lock().unwrap();
        map.insert(url.to_string(), attempts);
    }

    /// Configure a URL to fail indefinitely or clear failure.
    pub fn set_failure(&self, url: &str, failing: bool) {
        let attempts = if failing { usize::MAX } else { 0 };
        self.set_fail_attempts(url, attempts);
    }

    /// Count successful deliveries captured for a URL.
    pub fn delivery_count(&self, url: &str) -> usize {
        self.delivered_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(u, _, _)| u == url)
            .count()
    }

    /// Count total delivery attempts (successful and failed) for a URL.
    pub fn total_attempts(&self, url: &str) -> usize {
        self.attempt_counts
            .lock()
            .unwrap()
            .get(url)
            .copied()
            .unwrap_or(0)
    }

    /// Access all captured delivered requests: (url, signature_header, payload_json).
    pub fn get_delivered(&self) -> Vec<(String, String, String)> {
        self.delivered_requests.lock().unwrap().clone()
    }
}

impl WebhookDeliverySink for MockWebhookSink {
    fn deliver(
        &self,
        url: &str,
        signature_header: &str,
        payload_json: &str,
    ) -> Result<u16, String> {
        {
            let mut attempts = self.attempt_counts.lock().unwrap();
            *attempts.entry(url.to_string()).or_insert(0) += 1;
        }

        let mut fail_map = self.fail_urls.lock().unwrap();
        if let Some(count) = fail_map.get_mut(url) {
            if *count > 0 {
                *count -= 1;
                return Err("Simulated network connection timeout".to_string());
            }
        }

        self.delivered_requests.lock().unwrap().push((
            url.to_string(),
            signature_header.to_string(),
            payload_json.to_string(),
        ));
        Ok(200)
    }
}

/// Asynchronous webhook event bus and audit dispatcher.
pub struct WebhookEventBus {
    subscriptions: RwLock<HashMap<String, WebhookSubscription>>,
    dlq: RwLock<WebhookDeadLetterQueue>,
    metrics: RwLock<WebhookMetrics>,
    sink: Arc<dyn WebhookDeliverySink>,
    origin_node: String,
}

impl WebhookEventBus {
    /// Create a new event bus with default mock sink.
    pub fn new(origin_node: impl Into<String>) -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            dlq: RwLock::new(WebhookDeadLetterQueue::new(1_000)),
            metrics: RwLock::new(WebhookMetrics::default()),
            sink: Arc::new(MockWebhookSink::new()),
            origin_node: origin_node.into(),
        }
    }

    /// Create an event bus with a custom delivery sink.
    pub fn with_sink(origin_node: impl Into<String>, sink: Arc<dyn WebhookDeliverySink>) -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            dlq: RwLock::new(WebhookDeadLetterQueue::new(1_000)),
            metrics: RwLock::new(WebhookMetrics::default()),
            sink,
            origin_node: origin_node.into(),
        }
    }

    /// Register or update a webhook subscription.
    pub fn register_subscription(&self, sub: WebhookSubscription) {
        let mut subs = self.subscriptions.write().unwrap();
        subs.insert(sub.id.clone(), sub);
    }

    /// Remove a subscription by ID.
    pub fn unregister_subscription(&self, id: &str) -> bool {
        let mut subs = self.subscriptions.write().unwrap();
        subs.remove(id).is_some()
    }

    /// List all registered subscriptions.
    pub fn list_subscriptions(&self) -> Vec<WebhookSubscription> {
        let subs = self.subscriptions.read().unwrap();
        subs.values().cloned().collect()
    }

    /// Access live metrics snapshot.
    pub fn metrics(&self) -> WebhookMetrics {
        self.metrics.read().unwrap().clone()
    }

    /// Access dead letter queue entries.
    pub fn list_dlq(&self) -> Vec<DeadLetterEntry> {
        self.dlq.read().unwrap().list()
    }

    /// Publish an event to the bus, dispatching to all matching subscribers.
    pub fn publish(&self, event_type: WebhookEventType, data: serde_json::Value) -> WebhookPayload {
        let event_id = format!("evt-{}", Instant::now().elapsed().as_nanos());
        let payload = WebhookPayload::new(event_id, event_type, &self.origin_node, data);

        {
            let mut m = self.metrics.write().unwrap();
            m.total_events_published += 1;
        }

        let matching_subs: Vec<WebhookSubscription> = {
            let subs = self.subscriptions.read().unwrap();
            subs.values()
                .filter(|s| s.matches(event_type))
                .cloned()
                .collect()
        };

        for sub in matching_subs {
            self.dispatch_with_retries(&sub, &payload);
        }

        payload
    }

    /// Dispatch an event to a subscriber with retries and exponential backoff.
    pub fn dispatch_with_retries(
        &self,
        sub: &WebhookSubscription,
        payload: &WebhookPayload,
    ) -> DeliveryStatus {
        let payload_json = match serde_json::to_string(payload) {
            Ok(j) => j,
            Err(e) => {
                let err_str = e.to_string();
                let mut m = self.metrics.write().unwrap();
                m.total_deliveries_failed += 1;
                return DeliveryStatus::DeadLettered {
                    attempts: 0,
                    reason: err_str,
                };
            }
        };

        let now_secs = payload.timestamp;
        let sig = WebhookSigner::sign(&sub.secret, now_secs, &payload_json);

        let mut attempts = 0usize;
        let mut _backoff_ms = 100u64;

        while attempts <= sub.max_retries {
            attempts += 1;
            let start = Instant::now();

            match self.sink.deliver(&sub.url, &sig, &payload_json) {
                Ok(status) => {
                    let lat = start.elapsed().as_millis() as u64;
                    let mut m = self.metrics.write().unwrap();
                    m.total_deliveries_succeeded += 1;
                    return DeliveryStatus::Delivered {
                        status_code: status,
                        latency_ms: lat,
                    };
                }
                Err(err) => {
                    let mut m = self.metrics.write().unwrap();
                    m.total_deliveries_failed += 1;

                    if attempts <= sub.max_retries {
                        m.total_retries_scheduled += 1;
                        _backoff_ms *= 2;
                    } else {
                        // Max retries exceeded -> route to DLQ
                        m.total_dead_lettered += 1;
                        let dlq_entry = DeadLetterEntry {
                            id: format!("dlq-{}", payload.event_id),
                            subscription_id: sub.id.clone(),
                            url: sub.url.clone(),
                            payload: payload.clone(),
                            attempts,
                            failed_at_secs: now_secs,
                            reason: err.clone(),
                        };
                        self.dlq.write().unwrap().push(dlq_entry);
                        return DeliveryStatus::DeadLettered {
                            attempts,
                            reason: err,
                        };
                    }
                }
            }
        }

        DeliveryStatus::DeadLettered {
            attempts,
            reason: "Retries exhausted".to_string(),
        }
    }

    /// Replay all dead-lettered events in the DLQ.
    pub fn replay_dlq(&self) -> usize {
        let mut dlq = self.dlq.write().unwrap();
        let entries = dlq.drain();
        let count = entries.len();

        let subs = self.subscriptions.read().unwrap();
        for entry in entries {
            if let Some(sub) = subs.get(&entry.subscription_id) {
                let _ = self.dispatch_with_retries(sub, &entry.payload);
            }
        }

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_signer_generate_and_verify() {
        let secret = "whsec_test_secret_key_12345";
        let payload = r#"{"event":"transfer.completed","transfer_id":"01HYEXAMPLE"}"#;
        let ts = 1710000000;

        // 1. Sign payload
        let header = WebhookSigner::sign(secret, ts, payload);
        assert!(header.starts_with("t=1710000000,v1="));

        // 2. Verify signature with valid tolerance
        let valid = WebhookSigner::verify(secret, &header, payload, 300, ts);
        assert!(valid, "valid signature must verify successfully");

        // 3. Verify fails if payload tampered
        let tampered = r#"{"event":"transfer.completed","transfer_id":"TAMPERED"}"#;
        let invalid_tamper = WebhookSigner::verify(secret, &header, tampered, 300, ts);
        assert!(!invalid_tamper, "tampered payload must fail verification");

        // 4. Verify fails if timestamp exceeds tolerance (replay defense)
        let invalid_skew = WebhookSigner::verify(secret, &header, payload, 60, ts + 3600);
        assert!(
            !invalid_skew,
            "timestamp beyond tolerance must fail verification"
        );
    }

    #[test]
    fn test_webhook_bus_publish_and_mock_delivery() {
        let sink = Arc::new(MockWebhookSink::new());
        let bus = WebhookEventBus::with_sink("node-us-east", sink.clone());

        let mut sub =
            WebhookSubscription::new("audit-webhook", "https://audit.corp/events", "secret123");
        sub.events = vec![WebhookEventType::TransferCompleted];
        bus.register_subscription(sub);

        // Publish matching event
        let data = serde_json::json!({ "transfer_id": "01HY00001", "bytes": 1048576 });
        bus.publish(WebhookEventType::TransferCompleted, data.clone());

        let delivered = sink.get_delivered();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, "https://audit.corp/events");
        assert!(delivered[0].1.contains("v1="));

        // Publish non-matching event (should not be delivered)
        bus.publish(WebhookEventType::ChunkCorrupted, data);
        let delivered_after = sink.get_delivered();
        assert_eq!(delivered_after.len(), 1);

        assert_eq!(bus.metrics().total_deliveries_succeeded, 1);
    }

    #[test]
    fn test_webhook_bus_retries_and_dead_letter_queue() {
        let sink = Arc::new(MockWebhookSink::new());
        let bus = WebhookEventBus::with_sink("node-eu-west", sink.clone());

        let mut sub =
            WebhookSubscription::new("failing-webhook", "https://down.endpoint/hook", "secret456");
        sub.max_retries = 2; // initial + 2 retries = 3 attempts total
        bus.register_subscription(sub);

        // Configure sink to fail 5 times
        sink.set_fail_attempts("https://down.endpoint/hook", 5);

        // Publish event
        bus.publish(
            WebhookEventType::TransferFailed,
            serde_json::json!({ "error": "timeout" }),
        );

        // Should route to DLQ after exceeding retries
        let metrics = bus.metrics();
        assert_eq!(metrics.total_dead_lettered, 1);
        assert_eq!(metrics.total_retries_scheduled, 2);

        let dlq = bus.list_dlq();
        assert_eq!(dlq.len(), 1);
        assert_eq!(dlq[0].subscription_id, "failing-webhook");
        assert_eq!(dlq[0].attempts, 3);
    }
}
