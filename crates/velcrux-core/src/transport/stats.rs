//! Transport-layer statistics. Fed from QUIC's own counters (we never
//! re-implement them, per `CLAUDE.md` §1).
//!
//! M1 exposes a small set: enough to log RTT and bytes-in-flight. The
//! remaining counters (cwnd, loss, retransmits) come from quinn in M2 when
//! the scheduler consumes them.

use std::time::Duration;

/// Snapshot of transport counters at a moment in time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats {
    /// Smoothed round-trip time (QUIC's min RTT estimator). `None` if no
    /// samples have been collected yet.
    pub rtt: Option<Duration>,
    /// Smoothed RTT variance (RFC 9002 §5.3).
    pub rtt_var: Option<Duration>,
    /// Bytes currently in flight (sent but not yet acknowledged).
    pub bytes_in_flight: u64,
    /// Congestion window in bytes.
    pub cwnd: u64,
    /// Cumulative packet loss events.
    pub loss_events: u64,
    /// Cumulative retransmits.
    pub retransmits: u64,
}
