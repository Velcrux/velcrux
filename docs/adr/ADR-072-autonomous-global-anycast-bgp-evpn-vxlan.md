# ADR-072: Autonomous Global Anycast BGP Peering & EVPN-VXLAN Edge Transit Fabric Engine

- **Status**: Accepted
- **Date**: 2026-11-09
- **Deciders**: Velcrux Networking, Edge Infrastructure, Routing Protocols, and Site Reliability Engineering Teams
- **Consulted**: Distributed Transport, Security Operations, and Enterprise Cloud Platform Teams

---

## 1. Context and Problem Statement

Global enterprise deployments of Velcrux require distributed Points of Presence (POPs) operating across multiple cloud providers, internet exchange points (IXPs), and bare-metal edge facilities:
1. **Anycast Ingress Traffic Imbalances & Suboptimal Routing**: Traditional static BGP Anycast announcements often lead to severe transit traffic skew, where users in Asia or Europe get routed to transatlantic POPs due to asymmetric transit AS paths.
2. **Edge POP Congestion & Failover Latency Tax**: When an edge POP experiences fiber cuts, localized DDoS spikes, or upstream carrier degradation, static BGP routes continue attracting traffic into network blackholes until manual route changes or DNS TTLs expire.
3. **Multi-Tenant Network Isolation Limit**: Classical IEEE 802.1Q VLANs are strictly capped at 4,096 VLAN IDs, severely limiting multi-tenant network partitioning across large-scale distributed clusters.
4. **Data Center Interconnect (DCI) Complexity**: Bridging layer-2 broadcast domains and layer-3 VRF routing between heterogeneous cloud environments (AWS, GCP, Azure, on-premises) requires an open standard control plane (EVPN) and data plane (VXLAN).

To solve these challenges, Velcrux requires an **Autonomous Global Anycast BGP Peering & EVPN-VXLAN Edge Transit Fabric Engine** implemented in 100% pure safe Rust.

---

## 2. Decision Drivers

- **BGP-4 & Multiprotocol BGP (MP-BGP) Protocol Engine**:
  - Full RFC 4271 message framing: 16-byte marker, OPEN, UPDATE, NOTIFICATION, KEEPALIVE, and ROUTE_REFRESH.
  - RFC 6793 4-byte ASN support and RFC 4760 Multiprotocol Extensions.
  - Standard BGP Finite State Machine (FSM): `Idle`, `Connect`, `Active`, `OpenSent`, `OpenConfirm`, `Established`.
- **Ethernet VPN (EVPN) Overlay Control Plane (RFC 7432 / RFC 9136)**:
  - Address Family Identifier (AFI 25 L2VPN) and Subsequent AFI (SAFI 70 EVPN).
  - 8-byte Route Distinguishers (RD Type 0, Type 1, Type 2).
  - 8-byte Route Target (RT) Extended Communities for multi-tenant VRF import/export policy matching.
  - EVPN Route Types 1 through 5 (including Type 2 MAC/IP Advertisements and Type 5 IP Prefix Routes).
- **VXLAN Overlay Encapsulation (RFC 7348)**:
  - Standard 8-byte VXLAN header framing over UDP port 4789.
  - 24-bit VXLAN Network Identifier (VNI) enabling up to 16.7 million isolated tenant segments.
  - VTEP (VXLAN Tunnel Endpoint) Forwarding Database (FDB) MAC learning and encapsulation/decapsulation.
- **Autonomous Global Anycast Traffic Engineering**:
  - Continuous POP telemetry monitoring (RTT z-scores, loss ratios, upstream carrier BGP flaps).
  - Automated AS-path prepending (1 to 5 hops) to gracefully soft-deflect transit traffic away from congested POPs.
  - Sub-second instant prefix withdrawal (`BGP UPDATE Withdrawn Routes`) upon critical node failure, causing global internet routers to converge immediately to the nearest healthy POP.
- **Zero Unsafe Code**: Pure `#![forbid(unsafe_code)]` compliance with zero external C dependencies.

---

## 3. Considered Options

- **Option 1: Rely on Host OS BGP Daemons (FRRouting / BIRD / Quagga)**:
  - *Cons*: Heavy external C dependencies, complex Linux system configuration, root daemon privileges, and lack of programmatic tight integration with Velcrux transfer pacing.
- **Option 2: DNS-Based Geo-Steering (GeoDNS)**:
  - *Cons*: Subject to aggressive client DNS caching, ISP recursive resolver aggregation, and high failover convergence times (tens of seconds to minutes).
- **Option 3 (Chosen): Pure Safe-Rust BGP Peering, EVPN-VXLAN & Anycast Orchestrator (`Option DD`)**:
  - Native, memory-safe Rust implementation of BGP-4 and EVPN wire protocols.
  - Embedded VXLAN encapsulation engine for multi-tenant tenant isolation.
  - Closed-loop autonomous traffic engineering with dynamic AS prepending and sub-second failover.

---

## 4. Technical Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│             AUTONOMOUS GLOBAL ANYCAST BGP & EVPN-VXLAN EDGE TRANSIT FABRIC             │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   Upstream Transit Providers & Edge IXPs (eBGP AS174, AS13335, AS65002)                │
│                                  │                                                     │
│                                  ▼                                                     │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ BGP-4 & MP-BGP Protocol Engine (BgpPeer)          │                                │
│   │ ─ Standard 19-byte Header & Wire Protocol Framing │                                │
│   │ ─ FSM: Idle ➔ Connect ➔ OpenSent ➔ Established    │                                │
│   │ ─ Negotiated HoldTimer & Keepalive Management     │                                │
│   └─────────────────────────┬─────────────────────────┘                                │
│                             │                                                          │
│                             ▼                                                          │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ Global Anycast Orchestrator (AnycastOrchestrator) │                                │
│   │ ─ Telemetry: Real-Time RTT, Loss %, Upstream Flap │                                │
│   │ ─ Status: Optimal (0 Prepend) vs Congested (2-4)  │                                │
│   │ ─ Critical: Sub-Second Instant Route Withdrawal   │                                │
│   └─────────────────────────┬─────────────────────────┘                                │
│                             │                                                          │
│                             ▼                                                          │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ Routing Information Base (Loc-RIB & VRF Tables)   │                                │
│   │ ─ Multi-Tenant VRF Isolation via RD & Route Target│                                │
│   │ ─ BGP Best Path Selection (LocalPref > AS > MED)  │                                │
│   │ ─ EVPN Route Types 2 (MAC/IP) & 5 (IP Prefix)     │                                │
│   └─────────────────────────┬─────────────────────────┘                                │
│                             │                                                          │
│                             ▼                                                          │
│   ┌───────────────────────────────────────────────────┐                                │
│   │ VXLAN Overlay Encapsulation Engine (VtepEngine)   │                                │
│   │ ─ 8-Byte VXLAN Header (I-Flag, 24-bit VNI)        │                                │
│   │ ─ Underlay UDP 4789 Tunnel Encapsulation / Decap  │                                │
│   │ ─ Forwarding Database (FDB) MAC Address Learning  │                                │
│   └───────────────────────────────────────────────────┘                                │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1. BGP-4 Wire Framing & State Machine

1. **Header**: 16 bytes of `0xFF` marker, 2 bytes total packet length, 1 byte message type code.
2. **FSM States**: Strictly enforces RFC 4271 state progression (`Idle` $\to$ `Connect` $\to$ `OpenSent` $\to$ `OpenConfirm` $\to$ `Established`). Mismatched ASNs or malformed messages elicit BGP NOTIFICATION capsules and gracefully reset to `Idle`.
3. **Path Attributes**: ORIGIN, AS_PATH (4-byte ASNs), NEXT_HOP, MULTI_EXIT_DISC (MED), LOCAL_PREF, ATOMIC_AGGREGATE, and BGP Communities (`NO_EXPORT`, `BLACKHOLE`).

### 4.2. EVPN & VXLAN Multi-Tenant Data Plane

- **Route Distinguisher (RD)**: 8 bytes (`Type:ASN:num` or `Type:IP:num`) ensuring uniqueness across overlapping tenant subnets.
- **Route Target (RT)**: Extended community controlling cross-VRF route distribution.
- **VXLAN Overlay (RFC 7348)**: Wraps inner Ethernet frames into UDP datagrams with 24-bit VNI, allowing 16,777,215 tenant overlays with zero VLAN ID collisions.

### 4.3. Autonomous Anycast Traffic Engineering

The orchestrator dynamically monitors POP operational health:
- $\text{Health Score} \ge 0.80$: Normal announcement with 0 AS-path prepends.
- $0.40 \le \text{Health Score} < 0.80$: Congested state; prepends local ASN 2 to 4 times to lengthen the AS path, prompting upstream transit BGP routers to shift traffic away.
- $\text{Health Score} < 0.40$: Critical failure; immediately sends BGP UPDATE with withdrawn routes, triggering sub-second internet traffic convergence to alternate edge nodes.

---

## 5. Consequences

### Positive
- **Deterministic Anycast Control**: Eliminates traffic skew by dynamically shaping transit ingress using AS prepends and communities.
- **Zero-Downtime POP Failover**: Sub-second route withdrawal reroutes global internet traffic without waiting for DNS TTL expirations.
- **Massive Multi-Tenancy**: VXLAN 24-bit VNIs expand network segmentation from 4,096 VLANs to 16.7M tenant networks.
- **Memory Safety**: 100% pure `#![forbid(unsafe_code)]` compliance.

### Negative / Trade-offs
- **BGP Propagation Latency**: While route withdrawal is generated in sub-milliseconds, global internet routing convergence across Tier-1 carriers typically takes 500ms to 2s.

---

## 6. References

- RFC 4271: A Border Gateway Protocol 4 (BGP-4).
- RFC 4760: Multiprotocol Extensions for BGP-4.
- RFC 6793: BGP Support for Four-Octet AS Numbers.
- RFC 7348: Virtual eXtensible Local Area Network (VXLAN).
- RFC 7432: BGP MPLS-Based Ethernet VPN (EVPN).
- RFC 9136: IP Prefix Advertisement in BGP EVPN.
- ADR-071: SmartNIC / DPU Offloaded Direct-to-NVMe Storage Fabric.
