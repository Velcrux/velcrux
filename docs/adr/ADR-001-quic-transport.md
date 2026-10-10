# ADR-001: QUIC as the transport layer

Status: Accepted · Date: 2026-09-02

## Problem

We need a reliable, encrypted, congestion-controlled transport for bulk data over
high-BDP, lossy WAN links. The obvious temptation, and the thing products in this
space historically did, is to build a custom reliable-UDP protocol.

## Options

1. **Custom reliable UDP.** Full control over congestion control, ACK strategy,
   and pacing. This is what the proprietary systems in this space did, and it is
   why they can claim numbers TCP cannot reach.
2. **TCP.** Universally supported, mature stacks, kernel-optimized. But a single
   flow on a high-BDP lossy link is exactly where TCP's loss response hurts, and
   we would need application-level encryption on top.
3. **QUIC (RFC 9000) over UDP.** Reliability, ordering, flow control, congestion
   control, TLS 1.3, packet authentication, and connection migration, all
   standardized and already implemented by mature libraries.

## Decision

QUIC, via `quinn`. No custom transport in v1.

## Trade-offs

Building a custom transport means writing and getting right: retransmission,
ACK generation and processing, RTT estimation, congestion control, loss detection,
pacing, packet numbering, anti-amplification, and a full AEAD record layer with
key rotation. Each of those has a decade of subtle bugs behind it in every stack
that has attempted it. It is the highest-risk, lowest-differentiation work in the
project — and getting congestion control wrong does not produce a slow system, it
produces a system that damages the network it runs on.

QUIC gives all of it, standardized and interoperable. What we give up is the
ability to be deliberately more aggressive than a standard congestion controller.
We consider that a feature: §29 of the requirements asks us not to be a UDP
flooder, and respecting QUIC's congestion control is how that is achieved by
construction rather than by promise.

The honest cost is that QUIC is userspace, so there is more per-packet CPU than
kernel TCP. UDP GSO and hardware AES bring this within budget (`PERFORMANCE.md`
§10), and it is measurable rather than speculative.

Our differentiation is not the transport. It is moving fewer bytes (delta + dedup),
recovering without redoing work (resume), and verifying everything.

## Consequences

- A `Transport` trait isolates QUIC so a future transport is possible without
  rewriting the transfer engine. This is the escape hatch, and it is cheap.
- We consume QUIC's congestion signals (RTT, cwnd, bytes in flight, loss) for
  application-level scheduling. We never override them.
- Flow-control window sizing becomes a first-class tuning concern, because it is
  now the thing that caps high-BDP throughput.
