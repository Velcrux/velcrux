//! Telemetry, live profiling, and empirical performance diagnostics.
//!
//! Complies with `docs/REQUIREMENTS.md` §72 ("Performance Profiling"), §38 ("Observability"),
//! and §36 ("Machine-Readable Output").

pub mod profiler;
pub mod webhook;

pub use profiler::{
    sample_current_process_rss, BottleneckDiagnosis, BottleneckKind, ComponentKind,
    ComponentTiming, MemoryStats, NetworkMetrics, ProfileReport, TimingGuard, TransferProfiler,
};
pub use webhook::{
    DeadLetterEntry, DeliveryStatus, MockWebhookSink, WebhookDeadLetterQueue, WebhookDeliverySink,
    WebhookEventBus, WebhookEventType, WebhookMetrics, WebhookPayload, WebhookSigner,
    WebhookSubscription,
};
