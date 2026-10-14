//! Integration tests for pluggable webhook event notifications and audit logging bus (Option BB).

use std::sync::Arc;

use velcrux_core::telemetry::{
    MockWebhookSink, WebhookDeadLetterQueue, WebhookEventBus, WebhookEventType, WebhookSigner,
    WebhookSubscription,
};

#[test]
fn test_webhook_bus_multi_subscriber_fanout() {
    let mock_sink = Arc::new(MockWebhookSink::new());
    let bus = WebhookEventBus::with_sink("cluster-node-alpha", mock_sink.clone());

    // 1. Subscription A: Receives all events
    let sub_all =
        WebhookSubscription::new("sub-all", "https://sink.all.corp/events", "secret-all-123");
    bus.register_subscription(sub_all);

    // 2. Subscription B: Only receives TransferCompleted
    let sub_transfers = WebhookSubscription::new(
        "sub-transfers",
        "https://sink.transfers.corp/events",
        "secret-transfer-456",
    )
    .with_events(vec![WebhookEventType::TransferCompleted]);
    bus.register_subscription(sub_transfers);

    // 3. Subscription C: Only receives AuditAction
    let sub_audit = WebhookSubscription::new(
        "sub-audit",
        "https://sink.audit.corp/events",
        "secret-audit-789",
    )
    .with_events(vec![WebhookEventType::AuditAction]);
    bus.register_subscription(sub_audit);

    // Publish TransferCompleted
    let p1 = bus.publish(
        WebhookEventType::TransferCompleted,
        serde_json::json!({ "transfer_id": "tx-100", "bytes": 1048576 }),
    );
    assert_eq!(p1.event_type, WebhookEventType::TransferCompleted);

    // Sub A and Sub B received it; Sub C did not
    assert_eq!(mock_sink.delivery_count("https://sink.all.corp/events"), 1);
    assert_eq!(
        mock_sink.delivery_count("https://sink.transfers.corp/events"),
        1
    );
    assert_eq!(
        mock_sink.delivery_count("https://sink.audit.corp/events"),
        0
    );

    // Publish AuditAction
    let p2 = bus.publish(
        WebhookEventType::AuditAction,
        serde_json::json!({ "actor": "admin", "action": "prune_tombstones" }),
    );
    assert_eq!(p2.event_type, WebhookEventType::AuditAction);

    // Sub A and Sub C received it; Sub B did not
    assert_eq!(mock_sink.delivery_count("https://sink.all.corp/events"), 2);
    assert_eq!(
        mock_sink.delivery_count("https://sink.transfers.corp/events"),
        1
    );
    assert_eq!(
        mock_sink.delivery_count("https://sink.audit.corp/events"),
        1
    );

    // Verify aggregate bus metrics
    let metrics = bus.metrics();
    assert_eq!(metrics.total_events_published, 2);
    assert_eq!(metrics.total_deliveries_succeeded, 4);
    assert_eq!(metrics.total_deliveries_failed, 0);
    assert_eq!(metrics.total_dead_lettered, 0);
}

#[test]
fn test_webhook_signer_tamper_and_replay_detection() {
    let secret = "production-hmac-secret-k99";
    let now_secs = 1700000000u64;
    let payload_json = r#"{"event_id":"evt-1","event_type":"transfer.completed","bytes":4096}"#;

    // Generate valid signature
    let signature = WebhookSigner::sign(secret, now_secs, payload_json);
    assert!(signature.starts_with("t=1700000000,v1="));

    // 1. Valid signature within tolerance window (5 seconds later)
    assert!(WebhookSigner::verify(
        secret,
        &signature,
        payload_json,
        300,
        now_secs + 5
    ));

    // 2. Tampered secret -> verification fails
    assert!(!WebhookSigner::verify(
        "wrong-secret",
        &signature,
        payload_json,
        300,
        now_secs + 5
    ));

    // 3. Tampered payload JSON -> verification fails
    let tampered_json = r#"{"event_id":"evt-1","event_type":"transfer.completed","bytes":8192}"#;
    assert!(!WebhookSigner::verify(
        secret,
        &signature,
        tampered_json,
        300,
        now_secs + 5
    ));

    // 4. Replay attack: timestamp expired beyond tolerance window (301 seconds later)
    assert!(!WebhookSigner::verify(
        secret,
        &signature,
        payload_json,
        300,
        now_secs + 301
    ));

    // 5. Future timestamp drift beyond tolerance window
    assert!(!WebhookSigner::verify(
        secret,
        &signature,
        payload_json,
        300,
        now_secs - 301
    ));
}

#[test]
fn test_webhook_retry_backoff_and_dlq_lifecycle() {
    let mock_sink = Arc::new(MockWebhookSink::new());
    let failing_url = "https://unreachable.endpoint.corp/webhook";
    mock_sink.set_failure(failing_url, true);

    let bus = WebhookEventBus::with_sink("node-beta", mock_sink.clone());

    let sub =
        WebhookSubscription::new("sub-failing", failing_url, "secret-xyz").with_max_retries(2);
    bus.register_subscription(sub);

    // Publish event
    bus.publish(
        WebhookEventType::ChunkCorrupted,
        serde_json::json!({ "chunk_hash": "abcd1234", "offset": 65536 }),
    );

    // Initial attempt (1) + 2 retries = 3 attempts total, 0 successful deliveries
    assert_eq!(mock_sink.total_attempts(failing_url), 3);
    assert_eq!(mock_sink.delivery_count(failing_url), 0);

    // Bus metrics should record 3 failures, 2 retries, and 1 dead letter
    let metrics = bus.metrics();
    assert_eq!(metrics.total_events_published, 1);
    assert_eq!(metrics.total_deliveries_succeeded, 0);
    assert_eq!(metrics.total_deliveries_failed, 3);
    assert_eq!(metrics.total_retries_scheduled, 2);
    assert_eq!(metrics.total_dead_lettered, 1);

    // Inspect DLQ
    let dlq_entries = bus.list_dlq();
    assert_eq!(dlq_entries.len(), 1);
    let entry = &dlq_entries[0];
    assert_eq!(entry.subscription_id, "sub-failing");
    assert_eq!(entry.url, failing_url);
    assert_eq!(entry.attempts, 3);
    assert_eq!(entry.payload.event_type, WebhookEventType::ChunkCorrupted);

    // Test standalone DLQ drain and clear operations
    let mut standalone_dlq = WebhookDeadLetterQueue::new(10);
    standalone_dlq.push(entry.clone());
    assert_eq!(standalone_dlq.len(), 1);
    assert!(!standalone_dlq.is_empty());

    let drained = standalone_dlq.drain();
    assert_eq!(drained.len(), 1);
    assert_eq!(standalone_dlq.len(), 0);
    assert!(standalone_dlq.is_empty());

    standalone_dlq.push(entry.clone());
    standalone_dlq.clear();
    assert_eq!(standalone_dlq.len(), 0);
}

#[test]
fn test_webhook_subscription_disable_and_event_type_parsing() {
    use std::str::FromStr;

    // Test string parsing
    assert_eq!(
        WebhookEventType::from_str("transfer.started").unwrap(),
        WebhookEventType::TransferStarted
    );
    assert_eq!(
        WebhookEventType::from_str("transfer_completed").unwrap(),
        WebhookEventType::TransferCompleted
    );
    assert_eq!(
        WebhookEventType::from_str("chunk.corrupted").unwrap(),
        WebhookEventType::ChunkCorrupted
    );
    assert_eq!(
        WebhookEventType::from_str("cluster.node_changed").unwrap(),
        WebhookEventType::ClusterNodeStateChanged
    );
    assert_eq!(
        WebhookEventType::from_str("geo.conflict_resolved").unwrap(),
        WebhookEventType::ConflictResolved
    );
    assert_eq!(
        WebhookEventType::from_str("geo.tombstone_pruned").unwrap(),
        WebhookEventType::TombstonePruned
    );
    assert_eq!(
        WebhookEventType::from_str("audit.action").unwrap(),
        WebhookEventType::AuditAction
    );
    assert!(WebhookEventType::from_str("unknown_nonsense").is_err());

    // Test disabled subscription
    let mut sub = WebhookSubscription::new(
        "sub-disabled",
        "https://sink.disabled.corp/events",
        "secret",
    );
    assert!(sub.matches(WebhookEventType::TransferCompleted));

    sub.enabled = false;
    assert!(!sub.matches(WebhookEventType::TransferCompleted));
}
